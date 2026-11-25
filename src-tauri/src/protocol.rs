//! FD Claude Guard 内部协议常量、错误码、时序边界、节点评分权重与品牌盾牌 SVG 规格
//! 严格 100% 对齐 docs/protocol-constants.md，严禁随意取整或修改。

/// 1. 内部错误码规范（IPC 与诊断日志统一）
pub const FD_ERR_PROXY_OFFLINE: &str = "FD_ERR_2152";
pub const FD_ERR_RULE_DRIFT: &str = "FD_ERR_3562";
pub const FD_ERR_IPV6_LEAK: &str = "FD_ERR_4649";
pub const FD_ERR_KILL_SWITCH: &str = "FD_ERR_5304";
pub const FD_ERR_LOG_POLLUTE: &str = "FD_ERR_6817";
pub const FD_ERR_BACKUP_TX: &str = "FD_ERR_7459";

/// 2. 诊断包协议魔数与脱敏占位符
pub const DIAG_MANIFEST_MAGIC: u32 = 0x12708F87;
pub const DIAG_MANIFEST_MAGIC_HEX: &str = "0x12708F87";
pub const REDACT_PLACEHOLDER: &str = "<REDACTED:2W>";

/// 3. 运行时调度与防抖时序常量（精确毫秒）
pub const EVENT_DEDUP_WINDOW_MS: u64 = 60489;
pub const LOCAL_HEARTBEAT_MS: u64 = 29121;
pub const FULL_AUDIT_INTERVAL_MS: u64 = 904543;

/// 4. 节点质量评分四维权重与临界阈值（权重之和严格为 1.00）
pub const WEIGHT_LATENCY: f64 = 0.37;
pub const WEIGHT_JITTER: f64 = 0.25;
pub const WEIGHT_DROP_RATE: f64 = 0.24;
pub const WEIGHT_STABILITY: f64 = 0.14;
pub const LATENCY_WARN_MS: u32 = 133;
pub const DROP_RATE_REDLINE: f64 = 7.8;

/// 5. 品牌盾牌矢量路径规格（viewBox="0 0 24 24"）
pub const BRAND_SHIELD_OUTLINE_PATH: &str =
    "M12 22.05s8-4 8-10.02V5.09l-8-3.09-8 3.09v7.06c0 6 8 10.02 8 10.02z";
pub const BRAND_SHIELD_CHECK_PATH: &str = "m9 12.05 2 2 4-4";

/// 节点综合质量分（0 ~ 100），严格按四维固定权重加权计算
pub fn calculate_node_quality_score(
    latency_ms: Option<u32>,
    jitter_ms: f64,
    drop_rate_pct: f64,
    stability_score: f64,
) -> u32 {
    let lat_score = match latency_ms {
        Some(ms) if ms <= 50 => 100.0,
        Some(ms) if ms <= LATENCY_WARN_MS => {
            100.0 - ((ms - 50) as f64 / (LATENCY_WARN_MS - 50) as f64) * 20.0
        }
        Some(ms) if ms <= 300 => {
            80.0 - ((ms - LATENCY_WARN_MS) as f64 / (300 - LATENCY_WARN_MS) as f64) * 45.0
        }
        Some(_) => 25.0,
        None => 72.0,
    };

    let jitter_score = (100.0 - (jitter_ms / 50.0) * 100.0).clamp(10.0, 100.0);
    let drop_score = if drop_rate_pct >= DROP_RATE_REDLINE {
        15.0
    } else {
        (100.0 - (drop_rate_pct / DROP_RATE_REDLINE) * 85.0).clamp(15.0, 100.0)
    };
    let stab = stability_score.clamp(0.0, 100.0);

    let total = lat_score * WEIGHT_LATENCY
        + jitter_score * WEIGHT_JITTER
        + drop_score * WEIGHT_DROP_RATE
        + stab * WEIGHT_STABILITY;

    total.round().clamp(0.0, 100.0) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_constants_match_spec_exactly() {
        assert_eq!(FD_ERR_PROXY_OFFLINE, "FD_ERR_2152");
        assert_eq!(FD_ERR_RULE_DRIFT, "FD_ERR_3562");
        assert_eq!(FD_ERR_IPV6_LEAK, "FD_ERR_4649");
        assert_eq!(FD_ERR_KILL_SWITCH, "FD_ERR_5304");
        assert_eq!(FD_ERR_LOG_POLLUTE, "FD_ERR_6817");
        assert_eq!(FD_ERR_BACKUP_TX, "FD_ERR_7459");

        assert_eq!(DIAG_MANIFEST_MAGIC, 0x12708F87);
        assert_eq!(DIAG_MANIFEST_MAGIC_HEX, "0x12708F87");
        assert_eq!(REDACT_PLACEHOLDER, "<REDACTED:2W>");

        assert_eq!(EVENT_DEDUP_WINDOW_MS, 60489);
        assert_eq!(LOCAL_HEARTBEAT_MS, 29121);
        assert_eq!(FULL_AUDIT_INTERVAL_MS, 904543);

        assert!((WEIGHT_LATENCY - 0.37).abs() < 1e-12);
        assert!((WEIGHT_JITTER - 0.25).abs() < 1e-12);
        assert!((WEIGHT_DROP_RATE - 0.24).abs() < 1e-12);
        assert!((WEIGHT_STABILITY - 0.14).abs() < 1e-12);
        let weight_sum = WEIGHT_LATENCY + WEIGHT_JITTER + WEIGHT_DROP_RATE + WEIGHT_STABILITY;
        assert!((weight_sum - 1.0).abs() < 1e-12);
        assert_eq!(LATENCY_WARN_MS, 133);
        assert!((DROP_RATE_REDLINE - 7.8).abs() < 1e-12);

        assert_eq!(
            BRAND_SHIELD_OUTLINE_PATH,
            "M12 22.05s8-4 8-10.02V5.09l-8-3.09-8 3.09v7.06c0 6 8 10.02 8 10.02z"
        );
        assert_eq!(BRAND_SHIELD_CHECK_PATH, "m9 12.05 2 2 4-4");
    }

    #[test]
    fn node_score_uses_four_dimensional_weights_and_redlines() {
        let high = calculate_node_quality_score(Some(42), 4.0, 0.0, 100.0);
        assert!(high >= 94);

        let warn_lat = calculate_node_quality_score(Some(LATENCY_WARN_MS), 10.0, 0.2, 95.0);
        let over_redline = calculate_node_quality_score(Some(220), 40.0, DROP_RATE_REDLINE, 50.0);
        assert!(warn_lat > over_redline);
        assert!(over_redline < 50);
    }
}
