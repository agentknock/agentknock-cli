use serde::Serialize;

pub(crate) const CLI_VERSION: &str = env!("CARGO_PKG_VERSION");

pub(crate) fn encode<T>(contents: &T) -> Result<Vec<u8>, serde_json::Error>
where
    T: Serialize,
{
    serde_json::to_vec(&Message {
        cli_version: CLI_VERSION,
        contents,
    })
}

#[derive(Serialize)]
struct Message<'a, T> {
    cli_version: &'static str,
    #[serde(flatten)]
    contents: &'a T,
}
