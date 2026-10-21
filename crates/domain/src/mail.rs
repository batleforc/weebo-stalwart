//! Pure rules on mail names: the form Stalwart stores (lowercased domain
//! names, local-parts and addresses), and the syntax checked before any
//! call — what the server would refuse anyway, refused earlier with a
//! message naming the field.
//!
//! Stalwart validates more than the syntax: v0.16.27 refuses a domain whose
//! top-level label it doesn't know (`weebo.abcd`), while it accepts the
//! special-use ones (`.internal`, `.lan`, `.home.arpa`, `.test`). That
//! list is the server's: a name passing [`check_domain_name`] may still be
//! refused at creation (`InvalidSpec`, with Stalwart's message).

/// A DNS name as Stalwart stores it: lowercased, without the root's
/// trailing dot.
pub fn normalize_domain(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// A local-part as Stalwart stores it (account and alias names are
/// lowercased).
pub fn normalize_local_part(name: &str) -> String {
    name.trim().to_ascii_lowercase()
}

/// `local@domain`, both normalized.
pub fn address(local_part: &str, domain: &str) -> String {
    format!(
        "{}@{}",
        normalize_local_part(local_part),
        normalize_domain(domain)
    )
}

/// Why a name was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NameError {
    #[error("{0:?} is not a domain name (1 to 253 characters)")]
    DomainLength(String),
    #[error("{0:?} is not a fully qualified domain name")]
    NotQualified(String),
    #[error("{name:?}: label {label:?} is not a hostname label")]
    Label { name: String, label: String },
    #[error("{0:?} is not a local-part (letters, digits, '.', '_', '-'; 64 characters at most)")]
    LocalPart(String),
}

/// LDH labels (letters, digits, inner hyphens) of 1–63 bytes, at least two
/// of them, 253 bytes at most: a hostname, as a mail domain must be.
pub fn check_domain_name(name: &str) -> Result<(), NameError> {
    let name = normalize_domain(name);
    if name.is_empty() || name.len() > 253 {
        return Err(NameError::DomainLength(name));
    }
    let labels: Vec<&str> = name.split('.').collect();
    if labels.len() < 2 {
        return Err(NameError::NotQualified(name));
    }
    for label in labels {
        let ldh = label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if label.is_empty()
            || label.len() > 63
            || !ldh
            || label.starts_with('-')
            || label.ends_with('-')
        {
            return Err(NameError::Label {
                label: label.to_string(),
                name,
            });
        }
    }
    Ok(())
}

/// The local-parts the operator creates: lowercase letters, digits, `.`,
/// `_` and `-`, 64 bytes at most, no leading, trailing or doubled `.`. No
/// `+`: it is Stalwart's sub-addressing separator.
pub fn check_local_part(name: &str) -> Result<(), NameError> {
    let name = normalize_local_part(name);
    let allowed = name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'));
    if name.is_empty()
        || name.len() > 64
        || !allowed
        || name.starts_with('.')
        || name.ends_with('.')
        || name.contains("..")
    {
        return Err(NameError::LocalPart(name));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_take_the_stored_form() {
        assert_eq!(normalize_domain(" Weebo.POC. "), "weebo.poc");
        assert_eq!(
            address("NoReply", "Weebo.Internal"),
            "noreply@weebo.internal"
        );
    }

    #[test]
    fn domain_names_are_hostnames() {
        for ok in ["weebo.internal", "a-b.example.com", "x1.lan", "WEEBO.Test"] {
            assert_eq!(check_domain_name(ok), Ok(()), "{ok}");
        }
        for bad in [
            "",
            "localhost",
            "-a.example",
            "a_b.example",
            "a..example",
            "é.example",
        ] {
            assert!(check_domain_name(bad).is_err(), "{bad}");
        }
        assert!(check_domain_name(&format!("{}.example", "a".repeat(64))).is_err());
    }

    #[test]
    fn local_parts_leave_out_the_sub_address_separator() {
        for ok in ["forgejo", "no-reply", "first.last", "a_1"] {
            assert_eq!(check_local_part(ok), Ok(()), "{ok}");
        }
        for bad in ["", "a+b", ".a", "a.", "a..b", "a b", "a@b"] {
            assert!(check_local_part(bad).is_err(), "{bad}");
        }
    }
}
