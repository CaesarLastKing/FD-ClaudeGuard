//! 100 分制纯函数安全评分引擎（无状态、零 I/O、桌面端与外部 `POST /v1/audit/check-sk` 共用）。
//!
//! 严格权重总和（8 项总分 = 100 分）：
//! 1. 归属地 × 出口 IP 一致性：24 分
//! 2. 官方 API 端点纯净度（防反代）：16 分
//! 3. 多号隔离与设备指纹防连坐：16 分
//! 4. 官方警告与静默监控标：12 分
//! 5. 高敏观察窗（新号/支付/过 KYC）：10 分
//! 6. 人机节律与 429 并发安全：10 分
//! 7. Clash 断连回传 Cookie 403 防护：8 分
//! 8. 本机隐私遥测与待传缓存：4 分
//! 合计 = 24 + 16 + 16 + 12 + 10 + 10 + 8 + 4 = 100 分。
//!
//! 附加规则：
//! - 致命熔断：`account_banned` 或 `portal_hold` → 总分直接锁死 `<= 15`；
//! - 实名护城河：`persona_kyc_verified_over_72h` → `+5`（总分封顶 100，熔断态不加分）；
//! - 信息盲区诚实封顶：`LocalOnly`（未核验 `sk` 或超 7 天衰减）→ 上限封顶 `85`。

use serde::{Deserialize, Serialize};

pub const WEIGHT_GEO: i32 = 24;
pub const WEIGHT_ENDPOINT: i32 = 16;
pub const WEIGHT_MULTI_ACCT: i32 = 16;
pub const WEIGHT_CLOUD_WARN: i32 = 12;
pub const WEIGHT_HIGH_RISK_WINDOW: i32 = 10;
pub const WEIGHT_RHYTHM_429: i32 = 10;
pub const WEIGHT_DISCONNECT_403: i32 = 8;
pub const WEIGHT_PRIVACY_TELEMETRY: i32 = 4;
pub const KYC_BUFFER_BONUS: i32 = 5;
pub const LOCAL_BLIND_SPOT_CAP: i32 = 85;
pub const FATAL_MELTDOWN_CAP: i32 = 15;

/// 评估置信度模式（桌面端本地估 / 桌面端云端超 7 天衰减 / 桌面端完整综合 / 外部纯云端 API）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScoreConfidenceMode {
    LocalOnly,
    Stale7d,
    FullCombined,
    CloudOnly,
}

/// 评分纯函数输入信号（全部由上游扫描或云端探针构造，零 I/O）
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RiskScoreInput {
    pub confidence_mode: Option<ScoreConfidenceMode>,
    pub stale_days: Option<u64>,

    // 致命熔断信号
    pub account_banned: bool,
    pub portal_hold: bool,

    // 维度 1（24 分）：归属地 × 出口 IP 一致性
    pub geo_cross_continent_mismatch: bool,
    pub geo_mismatch_detail: Option<String>,
    pub datacenter_or_frequent_hop: bool,
    pub datacenter_or_hop_detail: Option<String>,

    // 维度 2（16 分）：官方 API 端点纯净度
    pub non_official_endpoint: bool,
    pub non_official_endpoint_detail: Option<String>,

    // 维度 3（16 分）：多号隔离与设备指纹防连坐
    pub ban_residue_or_cross_org_404: bool,
    pub cross_client_or_multi_org_mix: bool,
    /// 单端存在失效凭据 / 同文件跨号交叉污染 / 旧号会话目录残留（轻度预警 -6 分，绝不假绿）
    #[serde(default)]
    pub stale_or_polluted_cli_residue: bool,
    pub multi_acct_detail: Option<String>,

    // 维度 4（12 分）：官方警告与静默监控标
    pub cloud_warning_active: bool,
    pub cloud_warning_detail: Option<String>,

    // 维度 5（10 分）：高敏观察窗
    pub in_high_risk_window: bool,
    pub high_risk_window_detail: Option<String>,

    // 维度 6（10 分）：人机节律与 429 并发安全
    pub severe_automation_or_429: bool,
    pub mild_rate_limit_429: bool,
    #[serde(default)]
    pub mild_scheduled_tasks: bool,
    pub rhythm_detail: Option<String>,

    // 维度 7（8 分）：Clash 断连回传 Cookie 403 防护
    pub quit_cookie_403_hit: bool,
    pub proxy_or_hold_unready: bool,
    pub disconnect_detail: Option<String>,

    // 维度 8（4 分）：本机隐私遥测与待传缓存
    pub telemetry_env_missing_count: usize,
    pub telemetry_dir_bytes: u64,

    // 实名护城河缓冲（+5 分）
    pub persona_kyc_verified_over_72h: bool,
}

/// 单条扣分 / 加分 / 封顶明细
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScoreDeductionItem {
    pub id: String,
    pub weight_max: i32,
    pub delta: i32,
    /// 前端展示文案标签（例如 "-24" / "+5" / "封顶 85" / "锁死 ≤15"）
    pub delta_label: String,
    /// "danger" | "warn" | "muted" | "ok"
    pub tone: String,
    pub title: String,
    pub desc: String,
}

/// 100 分制评分结果（桌面端与外部 `POST /v1/audit/check-sk` 100% 共享同一 DTO）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScoreResult {
    pub score: i32,
    pub max_score: i32,
    /// "safe" | "watch" | "mid_high" | "critical"
    pub level: String,
    pub level_label: String,
    /// "green" | "amber" | "orange" | "red"
    pub color_token: String,
    /// "local_only" | "stale_7d" | "full_combined" | "cloud_only"
    pub confidence: String,
    pub confidence_label: String,
    pub disclaimer: String,
    pub blind_spot_note: Option<String>,
    pub deductions: Vec<ScoreDeductionItem>,
}

/// 校验 8 项总权重严格为 100 分
pub const fn total_dimension_weight() -> i32 {
    WEIGHT_GEO
        + WEIGHT_ENDPOINT
        + WEIGHT_MULTI_ACCT
        + WEIGHT_CLOUD_WARN
        + WEIGHT_HIGH_RISK_WINDOW
        + WEIGHT_RHYTHM_429
        + WEIGHT_DISCONNECT_403
        + WEIGHT_PRIVACY_TELEMETRY
}

/// 纯函数：计算 100 分制防御参考分
pub fn compute_risk_score(input: &RiskScoreInput) -> ScoreResult {
    let mode = input.confidence_mode.unwrap_or(ScoreConfidenceMode::LocalOnly);
    let is_cloud_only = mode == ScoreConfidenceMode::CloudOnly;

    let mut score: i32 = 100;
    let mut deductions: Vec<ScoreDeductionItem> = Vec::new();

    // 1. 归属地 × 出口 IP 一致性（24 分）
    if input.geo_cross_continent_mismatch {
        score -= WEIGHT_GEO;
        deductions.push(ScoreDeductionItem {
            id: "geo_mismatch".into(),
            weight_max: WEIGHT_GEO,
            delta: -WEIGHT_GEO,
            delta_label: format!("-{WEIGHT_GEO}"),
            tone: "danger".into(),
            title: "归属地与出口跨洲错配（权重 24 分）".into(),
            desc: input.geo_mismatch_detail.clone().unwrap_or_else(|| {
                "账号属地与当前代理出口跨洲，强烈建议切回同区稳定节点".into()
            }),
        });
    } else if input.datacenter_or_frequent_hop {
        score -= 8;
        deductions.push(ScoreDeductionItem {
            id: "geo_ip_hop".into(),
            weight_max: WEIGHT_GEO,
            delta: -8,
            delta_label: "-8".into(),
            tone: "warn".into(),
            title: "出口机房段或高频跨区跳变（权重 24 分）".into(),
            desc: input.datacenter_or_hop_detail.clone().unwrap_or_else(|| {
                "近期存在出口跳区或机房 IP 风险，建议锁死单一稳定节点".into()
            }),
        });
    }

    // 2. 官方 API 端点纯净度（16 分，仅桌面端评估）
    if !is_cloud_only && input.non_official_endpoint {
        score -= WEIGHT_ENDPOINT;
        deductions.push(ScoreDeductionItem {
            id: "non_official_endpoint".into(),
            weight_max: WEIGHT_ENDPOINT,
            delta: -WEIGHT_ENDPOINT,
            delta_label: format!("-{WEIGHT_ENDPOINT}"),
            tone: "danger".into(),
            title: "检出非官方 API 端点反代改写（权重 16 分）".into(),
            desc: input.non_official_endpoint_detail.clone().unwrap_or_else(|| {
                "消费级订阅叠加第三方共享反代易引发连坐，强烈建议还原官方原生端点".into()
            }),
        });
    }

    // 3. 多号隔离与设备指纹防连坐（16 分，仅桌面端评估）
    if !is_cloud_only {
        if input.ban_residue_or_cross_org_404 {
            score -= WEIGHT_MULTI_ACCT;
            deductions.push(ScoreDeductionItem {
                id: "ban_residue_or_cross_org".into(),
                weight_max: WEIGHT_MULTI_ACCT,
                delta: -WEIGHT_MULTI_ACCT,
                delta_label: format!("-{WEIGHT_MULTI_ACCT}"),
                tone: "danger".into(),
                title: "存在封禁残留或跨组织 404 竞态（权重 16 分）".into(),
                desc: input.multi_acct_detail.clone().unwrap_or_else(|| {
                    "本机残留旧号封禁或跨组织竞态记录，建议先原子备份并彻底清理残留".into()
                }),
            });
        } else if input.cross_client_or_multi_org_mix {
            score -= 10;
            deductions.push(ScoreDeductionItem {
                id: "multi_account_mix".into(),
                weight_max: WEIGHT_MULTI_ACCT,
                delta: -10,
                delta_label: "-10".into(),
                tone: "warn".into(),
                title: "CLI 与桌面端混登不同组织（权重 16 分）".into(),
                desc: input.multi_acct_detail.clone().unwrap_or_else(|| {
                    "本机检测到多个不同组织记录，存在跨端残留连坐风险".into()
                }),
            });
        } else if input.stale_or_polluted_cli_residue {
            score -= 6;
            deductions.push(ScoreDeductionItem {
                id: "cli_stale_or_cross_residue".into(),
                weight_max: WEIGHT_MULTI_ACCT,
                delta: -6,
                delta_label: "-6".into(),
                tone: "warn".into(),
                title: "CLI 残留失效凭据或跨号缓存（权重 16 分）".into(),
                desc: input.multi_acct_detail.clone().unwrap_or_else(|| {
                    "检测到 CLI 旧号失效凭据或文件内双账号交叉缓存，登录新号前建议一键备份清理防连坐"
                        .into()
                }),
            });
        }
    }

    // 4. 官方警告与静默监控标（12 分）
    if input.cloud_warning_active {
        score -= WEIGHT_CLOUD_WARN;
        deductions.push(ScoreDeductionItem {
            id: "monitoring_notice".into(),
            weight_max: WEIGHT_CLOUD_WARN,
            delta: -WEIGHT_CLOUD_WARN,
            delta_label: format!("-{WEIGHT_CLOUD_WARN}"),
            tone: "warn".into(),
            title: "云端命中后台观察标或账单警告（权重 12 分）".into(),
            desc: input.cloud_warning_detail.clone().unwrap_or_else(|| {
                "对话仍可用，但账号已进观察队列，容错率下降".into()
            }),
        });
    }

    // 5. 高敏观察窗（10 分）
    if input.in_high_risk_window {
        score -= WEIGHT_HIGH_RISK_WINDOW;
        deductions.push(ScoreDeductionItem {
            id: "high_risk_window".into(),
            weight_max: WEIGHT_HIGH_RISK_WINDOW,
            delta: -WEIGHT_HIGH_RISK_WINDOW,
            delta_label: format!("-{WEIGHT_HIGH_RISK_WINDOW}"),
            tone: "warn".into(),
            title: "处于高敏观察窗（权重 10 分）".into(),
            desc: input.high_risk_window_detail.clone().unwrap_or_else(|| {
                "新号(<7天)、支付/升级(<=24h)或过 KYC 前 72h 容错率偏低，建议稳健低频使用".into()
            }),
        });
    }

    // 6. 人机节律与 429 并发安全（10 分，仅桌面端评估）
    if !is_cloud_only {
        if input.severe_automation_or_429 {
            score -= WEIGHT_RHYTHM_429;
            deductions.push(ScoreDeductionItem {
                id: "automation_rhythm".into(),
                weight_max: WEIGHT_RHYTHM_429,
                delta: -WEIGHT_RHYTHM_429,
                delta_label: format!("-{WEIGHT_RHYTHM_429}"),
                tone: "danger".into(),
                title: "自动化脚本机刷或高频 429 限流（权重 10 分）".into(),
                desc: input.rhythm_detail.clone().unwrap_or_else(|| {
                    "检测到定时脚本、跨夜连续循环或高频 429 并发，建议恢复常规人工节奏".into()
                }),
            });
        } else if input.mild_rate_limit_429 || input.mild_scheduled_tasks {
            score -= 5;
            let (id, title, default_desc) = if input.mild_rate_limit_429 && input.mild_scheduled_tasks {
                (
                    "mild_rhythm_and_tasks",
                    "近期偶发 429 且活跃定时任务较多（权重 10 分）",
                    "日志存在偶发 429 限流且活跃定时任务达 6 个及以上，建议适当错峰并降低并发",
                )
            } else if input.mild_scheduled_tasks {
                (
                    "mild_scheduled_tasks",
                    "活跃定时任务偏多（≥6 个 · 轻微提醒，权重 10 分）",
                    "检测到较多近期活跃定时任务，建议控制执行频率与并发，避免压线触发限流",
                )
            } else {
                (
                    "mild_429",
                    "近期偶发 429 限流提醒（权重 10 分）",
                    "近期日志捕获偶发 429 限流，建议适当降低并发会话数",
                )
            };
            deductions.push(ScoreDeductionItem {
                id: id.into(),
                weight_max: WEIGHT_RHYTHM_429,
                delta: -5,
                delta_label: "-5".into(),
                tone: "warn".into(),
                title: title.into(),
                desc: input
                    .rhythm_detail
                    .clone()
                    .unwrap_or_else(|| default_desc.into()),
            });
        }
    }

    // 7. Clash 断连回传 Cookie 403 防护（8 分，仅桌面端评估）
    if !is_cloud_only {
        if input.quit_cookie_403_hit {
            score -= WEIGHT_DISCONNECT_403;
            deductions.push(ScoreDeductionItem {
                id: "disconnect_cookie_403".into(),
                weight_max: WEIGHT_DISCONNECT_403,
                delta: -WEIGHT_DISCONNECT_403,
                delta_label: format!("-{WEIGHT_DISCONNECT_403}"),
                tone: "danger".into(),
                title: "断连退出回传 Cookie 403 风险（权重 8 分）".into(),
                desc: input.disconnect_detail.clone().unwrap_or_else(|| {
                    "日志命中退出回传 Cookie 403 前兆，切代理前建议先开启 45s 防复活盯防".into()
                }),
            });
        } else if input.proxy_or_hold_unready {
            score -= 5;
            deductions.push(ScoreDeductionItem {
                id: "disconnect_guard_unready".into(),
                weight_max: WEIGHT_DISCONNECT_403,
                delta: -5,
                delta_label: "-5".into(),
                tone: "warn".into(),
                title: "断连防漏链保护存在缺口（权重 8 分）".into(),
                desc: input.disconnect_detail.clone().unwrap_or_else(|| {
                    "TUN 代理、规则锁死、Fake-IP DNS 或运行中自动热熔断未完整就绪，存在断连回传隐患".into()
                }),
            });
        }
    }

    // 8. 本机隐私遥测与待传缓存（4 分，仅桌面端评估）
    if !is_cloud_only {
        if input.telemetry_env_missing_count > 0 {
            score -= 3;
            deductions.push(ScoreDeductionItem {
                id: "telemetry_env_missing".into(),
                weight_max: WEIGHT_PRIVACY_TELEMETRY,
                delta: -3,
                delta_label: "-3".into(),
                tone: "muted".into(),
                title: "隐私遥测降噪开关未补齐（权重 4 分）".into(),
                desc: format!(
                    "settings.json 缺少 {} 项降噪变量，可一键补齐并支持撤回",
                    input.telemetry_env_missing_count
                ),
            });
        }
        if input.telemetry_dir_bytes > 0 {
            score -= 1;
            deductions.push(ScoreDeductionItem {
                id: "telemetry_dir_nonempty".into(),
                weight_max: WEIGHT_PRIVACY_TELEMETRY,
                delta: -1,
                delta_label: "-1".into(),
                tone: "muted".into(),
                title: "待传遥测目录有残留（权重 4 分）".into(),
                desc: format!(
                    "telemetry 目录含 {} B 待传文件，可一键清空",
                    input.telemetry_dir_bytes
                ),
            });
        }
    }

    // 致命熔断检查（一票触底 <= 15）
    let fatal = input.account_banned || input.portal_hold;
    if fatal {
        score = score.min(FATAL_MELTDOWN_CAP);
        deductions.insert(
            0,
            ScoreDeductionItem {
                id: if input.account_banned {
                    "fatal_account_banned".into()
                } else {
                    "fatal_portal_hold".into()
                },
                weight_max: 100,
                delta: -(100 - score),
                delta_label: "锁死 ≤15".into(),
                tone: "danger".into(),
                title: if input.account_banned {
                    "致命熔断：官方实锤封号 (account_banned)".into()
                } else {
                    "致命熔断：Portal 风控门户挂起 (hold_notice)".into()
                },
                desc: "触发高危红线一票触底，强烈建议彻底备份并清理本机残留前勿同机切换备用号"
                    .into(),
            },
        );
    } else if input.persona_kyc_verified_over_72h {
        // Persona 实名护城河缓冲（+5 分，总分封顶 100）
        score = (score + KYC_BUFFER_BONUS).min(100);
        deductions.push(ScoreDeductionItem {
            id: "persona_kyc_buffer".into(),
            weight_max: KYC_BUFFER_BONUS,
            delta: KYC_BUFFER_BONUS,
            delta_label: "+5".into(),
            tone: "ok".into(),
            title: "已通过 Persona 实名认证（护城河缓冲）".into(),
            desc: "已过 72h 稳定期，账号抗误杀能力显著高于白号".into(),
        });
    }

    // 信息盲区诚实封顶（未核验 sk 或超 7 天衰减，上限 85）
    let mut blind_spot_note = None;
    if !fatal {
        match mode {
            ScoreConfidenceMode::LocalOnly => {
                if score > LOCAL_BLIND_SPOT_CAP {
                    score = LOCAL_BLIND_SPOT_CAP;
                }
                let note = "当前仅基于本地数据评估（封顶 85）；云端核验后可补全官方警告、KYC 与真实属地，评分更真实完整".to_string();
                blind_spot_note = Some(note);
                deductions.push(ScoreDeductionItem {
                    id: "local_blind_spot_cap".into(),
                    weight_max: LOCAL_BLIND_SPOT_CAP,
                    delta: 0,
                    delta_label: "封顶 85".into(),
                    tone: "muted".into(),
                    title: "尚未完成云端核验（存在云端盲区）".into(),
                    desc: "暂无法读取官方静默标、KYC 与隐藏属地，本地评估上限封顶 85 分".into(),
                });
            }
            ScoreConfidenceMode::Stale7d => {
                if score > LOCAL_BLIND_SPOT_CAP {
                    score = LOCAL_BLIND_SPOT_CAP;
                }
                let days = input.stale_days.unwrap_or(8);
                let note = format!(
                    "上次云端核验已超过 7 天（{days} 天前）；重新核验可刷新实时状态，评分更准确"
                );
                blind_spot_note = Some(note);
                deductions.push(ScoreDeductionItem {
                    id: "stale_cloud_cap".into(),
                    weight_max: LOCAL_BLIND_SPOT_CAP,
                    delta: 0,
                    delta_label: "封顶 85".into(),
                    tone: "muted".into(),
                    title: "云端核验已超 7 天时效".into(),
                    desc: format!(
                        "属地绑定永久有效，但云端状态为 {days} 天前旧快照，建议重验刷新"
                    ),
                });
            }
            ScoreConfidenceMode::FullCombined | ScoreConfidenceMode::CloudOnly => {}
        }
    }

    score = score.clamp(0, 100);

    let (level, level_label, color_token) = if score < 45 {
        ("critical", "高危警报", "red")
    } else if score < 70 {
        ("mid_high", "中高风险", "orange")
    } else if score < 85 {
        ("watch", "建议优化", "amber")
    } else {
        ("safe", "低危稳健", "green")
    };

    let (confidence, confidence_label, disclaimer) = match mode {
        ScoreConfidenceMode::LocalOnly => (
            "local_only",
            "本地评估",
            "防御参考分（非 Anthropic 官方黑盒风控分）；仅基于本地环境评估，补验云端后更完整。",
        ),
        ScoreConfidenceMode::Stale7d => (
            "stale_7d",
            "超 7 天衰减",
            "防御参考分（非 Anthropic 官方黑盒风控分）；云端核验已超 7 天，建议重验刷新。",
        ),
        ScoreConfidenceMode::FullCombined => (
            "full_combined",
            "本地+云端综合",
            "防御参考分（非 Anthropic 官方黑盒风控分）；高分不承诺永不封号，低分代表存在可优化隐患。",
        ),
        ScoreConfidenceMode::CloudOnly => (
            "cloud_only",
            "云端评估（不含本机混登/日志项）",
            "防御参考分（非 Anthropic 官方黑盒风控分）；外部 API 仅评估云端维度，不含本机环境审计。",
        ),
    };

    ScoreResult {
        score,
        max_score: 100,
        level: level.into(),
        level_label: level_label.into(),
        color_token: color_token.into(),
        confidence: confidence.into(),
        confidence_label: confidence_label.into(),
        disclaimer: disclaimer.into(),
        blind_spot_note,
        deductions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dimension_weights_strictly_sum_to_100() {
        assert_eq!(total_dimension_weight(), 100);
    }

    #[test]
    fn local_only_caps_at_85_and_applies_local_deductions() {
        // 纯净本地环境：满分 100 但受云端盲区诚实封顶 85
        let clean_local = compute_risk_score(&RiskScoreInput {
            confidence_mode: Some(ScoreConfidenceMode::LocalOnly),
            ..Default::default()
        });
        assert_eq!(clean_local.score, 85);
        assert_eq!(clean_local.level, "safe");

        // 本机实测态：跨端混登(-10) + 缺 2 项降噪(-3) = 87 -> 封顶 85
        let real_local = compute_risk_score(&RiskScoreInput {
            confidence_mode: Some(ScoreConfidenceMode::LocalOnly),
            cross_client_or_multi_org_mix: true,
            telemetry_env_missing_count: 2,
            ..Default::default()
        });
        assert_eq!(real_local.score, 85);
        assert!(real_local.blind_spot_note.is_some());
    }

    #[test]
    fn cloud_only_matches_handoff_contract_example() {
        // 对齐 docs/handoff-v030-account-audit.md 5.3 节示例：100 - 24 - 12 + 5 = 69 (mid_high / orange)
        let res = compute_risk_score(&RiskScoreInput {
            confidence_mode: Some(ScoreConfidenceMode::CloudOnly),
            geo_cross_continent_mismatch: true,
            cloud_warning_active: true,
            persona_kyc_verified_over_72h: true,
            // 外部 API 不扣本地项
            cross_client_or_multi_org_mix: true,
            telemetry_env_missing_count: 4,
            ..Default::default()
        });
        assert_eq!(res.score, 69);
        assert_eq!(res.level, "mid_high");
        assert_eq!(res.level_label, "中高风险");
        assert_eq!(res.color_token, "orange");
        assert_eq!(res.confidence, "cloud_only");
    }

    #[test]
    fn fatal_meltdown_locks_score_at_or_below_15() {
        let banned = compute_risk_score(&RiskScoreInput {
            confidence_mode: Some(ScoreConfidenceMode::FullCombined),
            account_banned: true,
            persona_kyc_verified_over_72h: true,
            ..Default::default()
        });
        assert!(banned.score <= 15);
        assert_eq!(banned.level, "critical");
        assert_eq!(banned.color_token, "red");

        let portal = compute_risk_score(&RiskScoreInput {
            confidence_mode: Some(ScoreConfidenceMode::FullCombined),
            portal_hold: true,
            ..Default::default()
        });
        assert!(portal.score <= 15);
        assert_eq!(portal.level, "critical");
    }

    #[test]
    fn stale_7d_caps_score_at_85() {
        let res = compute_risk_score(&RiskScoreInput {
            confidence_mode: Some(ScoreConfidenceMode::Stale7d),
            stale_days: Some(12),
            persona_kyc_verified_over_72h: true,
            ..Default::default()
        });
        assert_eq!(res.score, 85);
        assert_eq!(res.confidence, "stale_7d");
        assert!(res.blind_spot_note.unwrap().contains("12 天前"));
    }
}
