//! Acceptable weaker modes and the two literal package-policy lowering forms.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    NoArtifactPin,
    NoBrief,
}

impl Mode {
    pub fn label(self) -> &'static str {
        match self {
            Self::NoArtifactPin => "An installation with no artifact pin",
            Self::NoBrief => "Acting on a goal with no brief",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acceptance {
    pub session: String,
    pub mode: Mode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lowering {
    SignatureLevelNever,
    UntrustedRepository,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureRefusal {
    pub machine: String,
    pub form: Lowering,
}

/// Case-sensitive ASCII tokens in raw bytes, not a shell parser. Comment lines are inert.
pub fn lowering(command: &[u8]) -> Option<Lowering> {
    fn word(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'_'
    }
    for line in command.split(|b| *b == b'\n') {
        if line.iter().copied().find(|b| !b.is_ascii_whitespace()) == Some(b'#') {
            continue;
        }
        // Once a directive precedes an equals sign, every later word on this line
        // is a candidate. No punctuation or later directive closes that suffix.
        let mut directive = false;
        let mut value = false;
        let mut at = 0;
        while at < line.len() {
            if !word(line[at]) {
                if line[at] == b'=' && directive {
                    value = true;
                }
                at += 1;
                continue;
            }
            let start = at;
            while at < line.len() && word(line[at]) {
                at += 1;
            }
            let token = &line[start..at];
            if [
                b"SigLevel".as_slice(),
                b"LocalFileSigLevel",
                b"RemoteFileSigLevel",
            ]
            .contains(&token)
            {
                directive = true;
            }
            if value {
                if [b"Never".as_slice(), b"PackageNever", b"DatabaseNever"].contains(&token) {
                    return Some(Lowering::SignatureLevelNever);
                }
                if [
                    b"TrustAll".as_slice(),
                    b"PackageTrustAll",
                    b"DatabaseTrustAll",
                ]
                .contains(&token)
                {
                    return Some(Lowering::UntrustedRepository);
                }
            }
        }
    }
    None
}
