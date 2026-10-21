//! A Kubernetes quantity (`2Gi`, `500M`, `1.5Gi`) in bytes: what a
//! `quota` becomes before it is compared with `quotas.maxDiskQuota`.

/// Why a quantity was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QuantityError {
    #[error("{quantity:?}: unknown unit {unit:?}")]
    UnknownUnit { quantity: String, unit: String },
    #[error("{0:?} is not a quantity (e.g. 2Gi, 500M)")]
    Invalid(String),
    #[error("{0:?} is too large")]
    TooLarge(String),
}

/// The bytes `quantity` stands for, rounded up to a whole byte. Binary
/// (`Ki` … `Ei`) and decimal (`k` … `E`) suffixes, a plain number, a
/// decimal fraction; no exponent nor negative value.
pub fn bytes(quantity: &str) -> Result<u64, QuantityError> {
    let q = quantity.trim();
    let split = q
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(q.len());
    let (number, suffix) = q.split_at(split);
    let multiplier: u128 = match suffix {
        "" => 1,
        "Ki" => 1 << 10,
        "Mi" => 1 << 20,
        "Gi" => 1 << 30,
        "Ti" => 1 << 40,
        "Pi" => 1 << 50,
        "Ei" => 1 << 60,
        "k" => 1_000,
        "M" => 1_000_000,
        "G" => 1_000_000_000,
        "T" => 1_000_000_000_000,
        "P" => 1_000_000_000_000_000,
        "E" => 1_000_000_000_000_000_000,
        _ => {
            return Err(QuantityError::UnknownUnit {
                quantity: quantity.to_string(),
                unit: suffix.to_string(),
            });
        }
    };
    let invalid = || QuantityError::Invalid(quantity.to_string());
    let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
    if whole.is_empty() && fraction.is_empty() || fraction.contains('.') || fraction.len() > 18 {
        return Err(invalid());
    }
    let whole: u128 = if whole.is_empty() {
        0
    } else {
        whole.parse().map_err(|_| invalid())?
    };
    let scale = 10u128.pow(fraction.len() as u32);
    let fraction: u128 = if fraction.is_empty() {
        0
    } else {
        fraction.parse().map_err(|_| invalid())?
    };
    let total = whole
        .checked_mul(multiplier)
        .and_then(|w| w.checked_add((fraction * multiplier).div_ceil(scale)))
        .ok_or_else(invalid)?;
    u64::try_from(total).map_err(|_| QuantityError::TooLarge(quantity.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units_are_converted_to_bytes() {
        for (q, b) in [
            ("2Gi", 2_147_483_648),
            ("1.5Gi", 1_610_612_736),
            ("500M", 500_000_000),
            ("1k", 1_000),
            ("1024", 1_024),
            ("0.5Ki", 512),
            ("1.0001", 2),
            (" 3Ti ", 3 * (1u64 << 40)),
        ] {
            assert_eq!(bytes(q), Ok(b), "{q}");
        }
    }

    #[test]
    fn garbage_is_refused() {
        for q in ["", "Gi", "2GB", "-1Gi", "1e9", "1.2.3", "99999Ei"] {
            assert!(bytes(q).is_err(), "{q}");
        }
    }
}
