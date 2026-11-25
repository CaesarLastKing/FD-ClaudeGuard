//! 7 类 HTTP 403 与风控日志精准消歧引擎（纯函数，不读磁盘、不发网）。
//!
//! 严格遵循 `docs/research/01-local-config-audit-and-403-disambiguation.md` 第二节与第五节第 5 条契约：
//! - 结合账号套餐事实（`AccountFacts`）与数据来源标签（`DataSource`）联合判定；
//! - 绝不把 `Unknown` 误判为“无害降噪”。

use serde::{Deserialize, Serialize};

/// 事实数据来源标签（用于严格遵守状态诚实原则）
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataSource {
    LocalConfig,
    OfficialProbe,
    OfflineJsonl,
    #[default]
    Unknown,
}

/// 供 403 消歧纯函数使用的账号事实摘要
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountFacts {
    pub plan: Option<String>,
    pub plan_source: DataSource,
    pub kyc_status: Option<String>,
    pub kyc_source: DataSource,
    pub is_banned: Option<bool>,
}

impl Default for AccountFacts {
    fn default() -> Self {
        Self {
            plan: None,
            plan_source: DataSource::Unknown,
            kyc_status: None,
            kyc_source: DataSource::Unknown,
            is_banned: None,
        }
    }
}

/// 7 类 403 / 鉴权报错精准分类枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Http403Category {
    /// 1. 未登录态 403（credential: none）
    Unauthenticated403,
    /// 2. 套餐权限边界背景 OAuth 403（len=164/156 或 Missing permissions）
    PlanBoundaryOAuth403,
    /// 3. Cloudflare 节点弹盾 403（网络出口 IP 问题，非封号）
    CloudflareShield403,
    /// 4. 会话过期 / 登出失效 403/401（非 account_banned）
    SessionExpired403,
    /// 5. 退出回传 / 带 Cookie 403（len=182/270 或 onQuitCleanup 断连泄露前兆）
    QuitCookieLeak403,
    /// 6. 官方门户验证受限（portal.anthropic.com/verify / withpersona.com / KYC 阻塞态）
    PortalVerifyRestricted,
    /// 7. 官方实锤封号（account_banned / len=130/123 强吊）
    AccountBannedConfirmed,
    /// 非 403 / 无法归入上述 7 类的常规条目
    Other,
}

/// 消歧后的风险级别
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisambiguatedRiskLevel {
    Benign,
    Low,
    Warn,
    High,
    Critical,
}

/// 单条日志或响应的 403 消歧输入
#[derive(Debug, Clone)]
pub struct Log403Input<'a> {
    pub raw_line: &'a str,
    pub status_code: Option<u16>,
    pub cf_mitigated: Option<&'a str>,
    pub error_code: Option<&'a str>,
}

/// 403 消歧输出结论
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisambiguatedRisk {
    pub category: Http403Category,
    pub risk_level: DisambiguatedRiskLevel,
    /// 是否默认自动静默降噪（不弹红黄提醒，但仍可在日志流勾选“显示已降噪”复查）
    pub denoised: bool,
    pub chip_label: String,
    pub title: String,
    pub explanation: String,
    pub basis_source: DataSource,
}

fn is_kyc_blocked(status: Option<&str>) -> bool {
    matches!(
        status.map(|s| s.trim().to_ascii_lowercase()).as_deref(),
        Some(
            "created"
                | "pending"
                | "needs_review"
                | "marked_for_review"
                | "expired"
                | "denied"
                | "declined"
                | "failed"
                | "required"
        )
    )
}

/// 纯函数：执行 7 类 403 精准消歧（绝不读磁盘、绝不发网、绝不把 unknown 误判为无害）
pub fn disambiguate_403(input: &Log403Input<'_>, facts: &AccountFacts) -> DisambiguatedRisk {
    let lower = input.raw_line.to_ascii_lowercase();
    let err_code_lower = input
        .error_code
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();

    // 7. 官方实锤封号（最高优先级）
    let confirmed_ban = err_code_lower == "account_banned"
        || lower.contains("account_banned")
        || lower.contains("account_suspended")
        || lower.contains("organization_disabled")
        || lower.contains("ban_evasion")
        || (lower.contains("permission_error")
            && (lower.contains("len=130") || lower.contains("len=123")));
    if confirmed_ban {
        return DisambiguatedRisk {
            category: Http403Category::AccountBannedConfirmed,
            risk_level: DisambiguatedRiskLevel::Critical,
            denoised: false,
            chip_label: "403 消歧 · 实锤封号".into(),
            title: "官方返回账号封禁或强制吊销（account_banned）".into(),
            explanation: "命中官方实锤封禁特征，强烈建议在彻底备份清理本机桌面端与 CLI 目录前不要同机切换备用号。".into(),
            basis_source: if facts.is_banned == Some(true) {
                DataSource::OfficialProbe
            } else {
                DataSource::LocalConfig
            },
        };
    }

    // 6. 官方门户验证受限（待核验，与永久封号严格区分）
    let portal_verify = lower.contains("portal.anthropic.com/verify")
        || lower.contains("withpersona.com")
        || lower.contains("can't receive replies from claude");
    if portal_verify {
        return DisambiguatedRisk {
            category: Http403Category::PortalVerifyRestricted,
            risk_level: DisambiguatedRiskLevel::High,
            denoised: false,
            chip_label: "403 消歧 · 门户待验".into(),
            title: "触发官方验证门户或实名核验（待核验，非永久封号）".into(),
            explanation: "账号处于高危待核验态而非确认永封；建议保持单一干净节点完成官方验证，不要直接同机切备用号。".into(),
            basis_source: facts.kyc_source,
        };
    }

    // 5. 退出回传 / 带 Cookie 403（高危泄露前兆）
    let quit_cookie_403 = lower.contains("credentialed upload refused")
        || (lower.contains("403")
            && lower.contains("credential: cookie")
            && (lower.contains("withheld")
                || lower.contains("len=182")
                || lower.contains("182 chars")
                || lower.contains("len=270")
                || lower.contains("270 chars")))
        || (lower.contains("onquitcleanup") && lower.contains("403"));
    if quit_cookie_403 && !lower.contains("credential: none") {
        return DisambiguatedRisk {
            category: Http403Category::QuitCookieLeak403,
            risk_level: DisambiguatedRiskLevel::High,
            denoised: false,
            chip_label: "403 消歧 · 断连回传".into(),
            title: "捕获退出回传 / 带 Cookie 403（断连裸连高危前兆）".into(),
            explanation: "高度吻合代理断连或切直连瞬间携带登录态回传请求被拒，建议切换代理前先开启 45s 防复活盯防。".into(),
            basis_source: DataSource::LocalConfig,
        };
    }

    // 3. Cloudflare 节点弹盾 403（网络出口问题，非封号）
    let cf_challenge = input
        .cf_mitigated
        .map(|v| v.to_ascii_lowercase().contains("challenge"))
        .unwrap_or(false)
        || lower.contains("navigation to https://claude.ai/ failed with status code 403")
        || lower.contains("cf-mitigated: challenge")
        || lower.contains("cf-browser-verification")
        || lower.contains("challenge-platform");
    if cf_challenge {
        return DisambiguatedRisk {
            category: Http403Category::CloudflareShield403,
            risk_level: DisambiguatedRiskLevel::Warn,
            denoised: false,
            chip_label: "403 消歧 · CF 入口盾".into(),
            title: "Cloudflare 网页拦截盾（出口节点 IP 问题，非账号封禁）".into(),
            explanation: "出口节点 IP 被 Cloudflare 拦截，账号本身未必异常；建议前往「节点流量」切换干净同区节点。".into(),
            basis_source: DataSource::LocalConfig,
        };
    }

    // 1. 未登录态 403（credential: none）
    if lower.contains("403") && lower.contains("credential: none") {
        return DisambiguatedRisk {
            category: Http403Category::Unauthenticated403,
            risk_level: DisambiguatedRiskLevel::Benign,
            denoised: true,
            chip_label: "已自动降噪 · 未登录 403".into(),
            title: "未登录态后台接口返回 403（credential: none）".into(),
            explanation: "登出状态下不携带凭证的常规轮询，属于无害行为，已自动静默归档。".into(),
            basis_source: DataSource::LocalConfig,
        };
    }

    // 2. 套餐权限边界背景 OAuth 403（len=164/156 或 Missing permissions）
    let oauth_perm_403 = ((lower.contains("authorize returned 403")
        || lower.contains("oauth failed"))
        && lower.contains("permission_error"))
        || (lower.contains("permission_error")
            && (lower.contains("len=164") || lower.contains("len=156")))
        || (lower.contains("subscription_details") && lower.contains("missing permissions"));
    if oauth_perm_403 {
        let plan_known = facts.plan_source != DataSource::Unknown
            && facts
                .plan
                .as_deref()
                .map(|p| !p.trim().is_empty() && p != "未知")
                .unwrap_or(false);
        let kyc_blocked = is_kyc_blocked(facts.kyc_status.as_deref());
        let banned_known = facts.is_banned == Some(true);

        // 严格遵守状态诚实原则：仅当已知真实套餐事实、且未命中 KYC 阻塞与封号时才自动降噪
        if plan_known && !kyc_blocked && !banned_known {
            let plan_name = facts.plan.as_deref().unwrap_or("当前");
            return DisambiguatedRisk {
                category: Http403Category::PlanBoundaryOAuth403,
                risk_level: DisambiguatedRiskLevel::Benign,
                denoised: true,
                chip_label: "已自动降噪 · 背景 OAuth 403".into(),
                title: "客户端背景轮询未开通特性接口返回 OAuth 403 (permission_error)".into(),
                explanation: format!(
                    "结合当前 {plan_name} 套餐事实已归类为正常特性权限边界（非 KYC、非封号），默认静默降噪。"
                ),
                basis_source: facts.plan_source,
            };
        }

        // 若套餐未知（Unknown）或云端明确处于 KYC 待验态，绝不误判为无害！
        return DisambiguatedRisk {
            category: Http403Category::PlanBoundaryOAuth403,
            risk_level: if kyc_blocked {
                DisambiguatedRiskLevel::High
            } else {
                DisambiguatedRiskLevel::Warn
            },
            denoised: false,
            chip_label: if kyc_blocked {
                "403 消歧 · 待 KYC 验证".into()
            } else {
                "403 消歧 · 权限/KYC 待核".into()
            },
            title: if kyc_blocked {
                "OAuth 403 叠加云端 KYC 待核验状态".into()
            } else {
                "OAuth 403 权限被拒（当前套餐未知，保守保留提醒）".into()
            },
            explanation: if kyc_blocked {
                "云端核验显示账号处于实名核验待完成状态，建议在固定干净节点下完成官方 KYC。".into()
            } else {
                "暂未读取到明确套餐配置（unknown），无法排除 KYC 或权限受限可能，保守不自动降噪。".into()
            },
            basis_source: if kyc_blocked {
                facts.kyc_source
            } else {
                DataSource::Unknown
            },
        };
    }

    // 4. 会话过期 / 登出失效 403/401（非 account_banned）
    let session_expired = matches!(input.status_code, Some(401) | Some(403))
        || lower.contains("invalid authorization")
        || lower.contains("authentication_error")
        || lower.contains("session_stale_relogin")
        || lower.contains("no sessionkey cookie found");
    if session_expired {
        return DisambiguatedRisk {
            category: Http403Category::SessionExpired403,
            risk_level: DisambiguatedRiskLevel::Low,
            denoised: false,
            chip_label: "403 消歧 · 会话过期".into(),
            title: "会话凭据过期或已登出（非封号）".into(),
            explanation: "当前会话凭据失效且未命中 account_banned，重新登录即可，未必代表账号被封。".into(),
            basis_source: DataSource::LocalConfig,
        };
    }

    DisambiguatedRisk {
        category: Http403Category::Other,
        risk_level: DisambiguatedRiskLevel::Benign,
        denoised: false,
        chip_label: "常规日志".into(),
        title: "非 403 类别日志条目".into(),
        explanation: "未命中 7 类 403 特征。".into(),
        basis_source: DataSource::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seven_403_categories_disambiguated_accurately() {
        let pro_facts = AccountFacts {
            plan: Some("Pro".into()),
            plan_source: DataSource::LocalConfig,
            kyc_status: Some("verified".into()),
            kyc_source: DataSource::OfficialProbe,
            is_banned: Some(false),
        };

        // 1. 未登录态 403 -> 自动降噪
        let r1 = disambiguate_403(
            &Log403Input {
                raw_line: "GET /api/my-access returned 403 (credential: none)",
                status_code: Some(403),
                cf_mitigated: None,
                error_code: None,
            },
            &pro_facts,
        );
        assert_eq!(r1.category, Http403Category::Unauthenticated403);
        assert!(r1.denoised);

        // 2A. 已知套餐背景 OAuth 403 -> 自动降噪
        let r2a = disambiguate_403(
            &Log403Input {
                raw_line: "authorize returned 403 permission_error (len=164)",
                status_code: Some(403),
                cf_mitigated: None,
                error_code: None,
            },
            &pro_facts,
        );
        assert_eq!(r2a.category, Http403Category::PlanBoundaryOAuth403);
        assert!(r2a.denoised);
        assert_eq!(r2a.risk_level, DisambiguatedRiskLevel::Benign);

        // 2B. 未知套餐(unknown)绝不误判为无害降噪
        let r2b = disambiguate_403(
            &Log403Input {
                raw_line: "authorize returned 403 permission_error (len=164)",
                status_code: Some(403),
                cf_mitigated: None,
                error_code: None,
            },
            &AccountFacts::default(),
        );
        assert_eq!(r2b.category, Http403Category::PlanBoundaryOAuth403);
        assert!(!r2b.denoised);
        assert_eq!(r2b.risk_level, DisambiguatedRiskLevel::Warn);

        // 3. Cloudflare 节点弹盾 403
        let r3 = disambiguate_403(
            &Log403Input {
                raw_line: "navigation to https://claude.ai/ failed with status code 403",
                status_code: Some(403),
                cf_mitigated: Some("challenge"),
                error_code: None,
            },
            &pro_facts,
        );
        assert_eq!(r3.category, Http403Category::CloudflareShield403);
        assert!(!r3.denoised);
        assert_eq!(r3.risk_level, DisambiguatedRiskLevel::Warn);

        // 4. 会话过期 401/403
        let r4 = disambiguate_403(
            &Log403Input {
                raw_line: "Invalid authorization header",
                status_code: Some(401),
                cf_mitigated: None,
                error_code: Some("authentication_error"),
            },
            &pro_facts,
        );
        assert_eq!(r4.category, Http403Category::SessionExpired403);
        assert_eq!(r4.risk_level, DisambiguatedRiskLevel::Low);

        // 5. 退出回传 Cookie 403
        let r5 = disambiguate_403(
            &Log403Input {
                raw_line: "POST /api/event returned 403 credential: cookie withheld (182 chars)",
                status_code: Some(403),
                cf_mitigated: None,
                error_code: None,
            },
            &pro_facts,
        );
        assert_eq!(r5.category, Http403Category::QuitCookieLeak403);
        assert_eq!(r5.risk_level, DisambiguatedRiskLevel::High);

        // 6. 官方验证门户受限
        let r6 = disambiguate_403(
            &Log403Input {
                raw_line: "redirected to https://portal.anthropic.com/verify",
                status_code: Some(403),
                cf_mitigated: None,
                error_code: None,
            },
            &pro_facts,
        );
        assert_eq!(r6.category, Http403Category::PortalVerifyRestricted);
        assert_eq!(r6.risk_level, DisambiguatedRiskLevel::High);

        // 7. 官方实锤封号
        let r7 = disambiguate_403(
            &Log403Input {
                raw_line: r#"{"error":{"details":{"error_code":"account_banned"}}}"#,
                status_code: Some(403),
                cf_mitigated: None,
                error_code: Some("account_banned"),
            },
            &pro_facts,
        );
        assert_eq!(r7.category, Http403Category::AccountBannedConfirmed);
        assert_eq!(r7.risk_level, DisambiguatedRiskLevel::Critical);
    }
}
