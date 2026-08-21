use serde::Serialize;

use crate::ApplicationInfo;

const LIBRARY_NAME: &str = "agentknock";
const LIBRARY_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Copy, Serialize)]
pub(crate) enum Method {
    SecretUse,
    PairingFinish,
    PairingRemove,
    SecretList,
    SecretUpload,
}

pub(crate) fn encode<T>(
    application_info: &ApplicationInfo,
    contents: &T,
) -> Result<Vec<u8>, serde_json::Error>
where
    T: Serialize,
{
    serde_json::to_vec(&Message {
        app_info: SoftwareInfo {
            name: application_info.name(),
            version: application_info.version(),
        },
        lib_info: SoftwareInfo {
            name: LIBRARY_NAME,
            version: LIBRARY_VERSION,
        },
        contents,
    })
}

#[derive(Serialize)]
struct Message<'a, T> {
    app_info: SoftwareInfo<'a>,
    lib_info: SoftwareInfo<'static>,
    #[serde(flatten)]
    contents: &'a T,
}

#[derive(Serialize)]
struct SoftwareInfo<'a> {
    name: &'a str,
    version: &'a str,
}

#[cfg(test)]
mod tests {
    use serde::Serialize;
    use serde_json::json;

    use super::encode;
    use crate::ApplicationInfo;

    #[derive(Serialize)]
    struct Contents {
        method: &'static str,
    }

    #[test]
    fn distinguishes_application_and_library_versions() {
        let encoded = encode(
            &ApplicationInfo::new("embedded-application", "2.3.4"),
            &Contents { method: "Example" },
        )
        .unwrap();

        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&encoded).unwrap(),
            json!({
                "app_info": {
                    "name": "embedded-application",
                    "version": "2.3.4",
                },
                "lib_info": {
                    "name": "agentknock",
                    "version": env!("CARGO_PKG_VERSION"),
                },
                "method": "Example",
            })
        );
    }
}
