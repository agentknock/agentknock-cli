use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use agentknock::{GitSignChangeStatus, GitSignChangedPath, GitSignHead, GitSignRepository};
use serde::{Deserialize, Serialize};

const MAXIMUM_CHANGED_PATHS: usize = 50;

#[derive(Deserialize, Serialize)]
pub struct Repository {
    remote: Option<String>,
    worktree: Option<String>,
    head: Option<Head>,
    changed_path_count: Option<usize>,
    changed_paths: Option<Vec<ChangedPath>>,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
enum Head {
    Branch {
        name: String,
        upstream: Option<String>,
    },
    Detached,
}

#[derive(Deserialize, Serialize)]
struct ChangedPath {
    status: ChangeStatus,
    path: String,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ChangeStatus {
    Added,
    Deleted,
    Modified,
    TypeChanged,
}

impl Repository {
    pub fn collect(message: &[u8]) -> Option<Self> {
        let git = parent_git()?;
        let worktree = git_text(
            &git,
            ["rev-parse", "--path-format=absolute", "--show-toplevel"],
        );
        let head = git_head(&git);
        let remote = git_remote(&git, head.as_ref());
        let (changed_path_count, changed_paths) = changed_paths(&git, message)
            .map(|(count, paths)| (Some(count), paths))
            .unwrap_or((None, None));

        if remote.is_none() && worktree.is_none() && head.is_none() && changed_path_count.is_none()
        {
            return None;
        }
        Some(Self {
            remote,
            worktree,
            head,
            changed_path_count,
            changed_paths,
        })
    }
}

fn parent_git() -> Option<PathBuf> {
    // SAFETY: getppid has no preconditions.
    let parent = unsafe { libc::getppid() };
    let executable = crate::process_info::executable_path(parent).ok()?;
    (executable.file_name() == Some(OsStr::new("git"))).then_some(executable)
}

fn git_head(git: &Path) -> Option<Head> {
    if let Some(name) = git_text(git, ["symbolic-ref", "--quiet", "--short", "HEAD"]) {
        let upstream = git_text(
            git,
            [
                "rev-parse",
                "--abbrev-ref",
                "--symbolic-full-name",
                "@{upstream}",
            ],
        );
        return Some(Head::Branch { name, upstream });
    }
    git_output(git, ["rev-parse", "--verify", "HEAD"]).map(|_| Head::Detached)
}

fn git_remote(git: &Path, head: Option<&Head>) -> Option<String> {
    let upstream_remote = match head {
        Some(Head::Branch { name, .. }) => {
            let reference = format!("refs/heads/{name}");
            git_text(
                git,
                [
                    OsStr::new("for-each-ref"),
                    OsStr::new("--format=%(upstream:remotename)"),
                    OsStr::new(&reference),
                ],
            )
            .filter(|remote| remote != ".")
        }
        _ => None,
    };
    let remote = upstream_remote.or_else(|| git_text(git, ["remote"]))?;
    let url = git_text(
        git,
        [
            OsStr::new("remote"),
            OsStr::new("get-url"),
            OsStr::new("--"),
            OsStr::new(&remote),
        ],
    )?;
    sanitize_remote(&url)
}

fn sanitize_remote(url: &str) -> Option<String> {
    if unsafe_text(url) {
        return None;
    }
    if let Some((scheme, remainder)) = url.split_once("://") {
        if !matches!(scheme, "git" | "http" | "https" | "ssh") {
            return None;
        }
        let remainder = remainder.split(['?', '#']).next()?;
        let (authority, path) = remainder.split_once('/')?;
        let host = authority
            .rsplit_once('@')
            .map_or(authority, |(_, host)| host);
        return repository_identity(host, path);
    }

    let host_start = url.rsplit_once('@').map_or(0, |(user, _)| user.len() + 1);
    let host_and_path = &url[host_start..];
    let separator = if host_and_path.starts_with('[') {
        host_and_path.find("]:").map(|index| index + 1)?
    } else {
        host_and_path.find(':')?
    };
    if host_and_path.as_bytes().get(separator + 1) == Some(&b':') {
        return None;
    }
    repository_identity(&host_and_path[..separator], &host_and_path[separator + 1..])
}

fn repository_identity(host: &str, path: &str) -> Option<String> {
    let path = path.split(['?', '#']).next()?.trim_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path);
    if host.is_empty() || path.is_empty() || unsafe_text(host) || unsafe_text(path) {
        return None;
    }
    Some(format!("{host}/{path}"))
}

fn changed_paths(git: &Path, message: &[u8]) -> Option<(usize, Option<Vec<ChangedPath>>)> {
    let (tree, parent) = commit_tree_and_parent(message)?;
    let base = match parent {
        Some(parent) => parent.to_owned(),
        None => git_text(git, ["hash-object", "-t", "tree", "--stdin"])?,
    };
    let output = git_output(
        git,
        [
            OsStr::new("diff-tree"),
            OsStr::new("--no-commit-id"),
            OsStr::new("--name-status"),
            OsStr::new("-r"),
            OsStr::new("-z"),
            OsStr::new("--no-renames"),
            OsStr::new("--no-ext-diff"),
            OsStr::new("--no-textconv"),
            OsStr::new(&base),
            OsStr::new(tree),
        ],
    )?;
    parse_changed_paths(&output)
}

fn commit_tree_and_parent(message: &[u8]) -> Option<(&str, Option<&str>)> {
    let mut tree = None;
    let mut parent = None;
    for line in message.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            break;
        }
        if let Some(value) = line.strip_prefix(b"tree ") {
            if tree.is_some() {
                return None;
            }
            tree = git_object_id(value);
        } else if parent.is_none()
            && let Some(value) = line.strip_prefix(b"parent ")
        {
            parent = git_object_id(value);
        }
    }
    Some((tree?, parent))
}

fn git_object_id(value: &[u8]) -> Option<&str> {
    if !matches!(value.len(), 40 | 64) || !value.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    std::str::from_utf8(value).ok()
}

fn parse_changed_paths(output: &[u8]) -> Option<(usize, Option<Vec<ChangedPath>>)> {
    let mut fields = output.split(|byte| *byte == 0);
    let mut count = 0;
    let mut paths = Some(Vec::new());
    loop {
        let status = fields.next()?;
        if status.is_empty() {
            return fields.next().is_none().then_some((count, paths));
        }
        let path = fields.next()?;
        count += 1;
        if count > MAXIMUM_CHANGED_PATHS {
            paths = None;
            continue;
        }
        let Some(collected) = paths.as_mut() else {
            continue;
        };
        let status = match status {
            b"A" => ChangeStatus::Added,
            b"D" => ChangeStatus::Deleted,
            b"M" => ChangeStatus::Modified,
            b"T" => ChangeStatus::TypeChanged,
            _ => {
                paths = None;
                continue;
            }
        };
        let Ok(path) = std::str::from_utf8(path) else {
            paths = None;
            continue;
        };
        if unsafe_text(path) {
            paths = None;
            continue;
        }
        collected.push(ChangedPath {
            status,
            path: path.to_owned(),
        });
    }
}

fn git_text<I, S>(git: &Path, arguments: I) -> Option<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut output = git_output(git, arguments)?;
    while matches!(output.last(), Some(b'\n' | b'\r')) {
        output.pop();
    }
    let text = String::from_utf8(output).ok()?;
    (!text.is_empty() && !unsafe_text(&text)).then_some(text)
}

fn git_output<I, S>(git: &Path, arguments: I) -> Option<Vec<u8>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new(git)
        .args(arguments)
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    output.status.success().then_some(output.stdout)
}

fn unsafe_text(value: &str) -> bool {
    value.is_empty() || value.chars().any(char::is_control)
}

impl From<Repository> for GitSignRepository {
    fn from(repository: Repository) -> Self {
        Self {
            remote: repository.remote,
            worktree: repository.worktree,
            head: repository.head.map(GitSignHead::from),
            changed_path_count: repository.changed_path_count,
            changed_paths: repository
                .changed_paths
                .map(|paths| paths.into_iter().map(GitSignChangedPath::from).collect()),
        }
    }
}

impl From<Head> for GitSignHead {
    fn from(head: Head) -> Self {
        match head {
            Head::Branch { name, upstream } => Self::Branch { name, upstream },
            Head::Detached => Self::Detached,
        }
    }
}

impl From<ChangedPath> for GitSignChangedPath {
    fn from(path: ChangedPath) -> Self {
        Self {
            status: path.status.into(),
            path: path.path,
        }
    }
}

impl From<ChangeStatus> for GitSignChangeStatus {
    fn from(status: ChangeStatus) -> Self {
        match status {
            ChangeStatus::Added => Self::Added,
            ChangeStatus::Deleted => Self::Deleted,
            ChangeStatus::Modified => Self::Modified,
            ChangeStatus::TypeChanged => Self::TypeChanged,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_credentials_and_transport_details_from_remote_urls() {
        assert_eq!(
            sanitize_remote("https://user:token@example.com/owner/project.git?ignored=yes"),
            Some("example.com/owner/project".into())
        );
        assert_eq!(
            sanitize_remote("ssh://git@example.com:2222/owner/project.git"),
            Some("example.com:2222/owner/project".into())
        );
        assert_eq!(
            sanitize_remote("git@example.com:owner/project.git"),
            Some("example.com/owner/project".into())
        );
        assert_eq!(sanitize_remote("../project"), None);
        assert_eq!(sanitize_remote("file:///home/example/project"), None);
        assert_eq!(sanitize_remote("ext::command with a secret"), None);
    }

    #[test]
    fn reads_the_exact_tree_and_first_parent_from_a_commit() {
        let tree = "1111111111111111111111111111111111111111";
        let first_parent = "2222222222222222222222222222222222222222";
        let second_parent = "3333333333333333333333333333333333333333";
        let message = format!(
            "tree {tree}\nparent {first_parent}\nparent {second_parent}\nauthor A <a@example.com> 0 +0000\n\nMerge\n"
        );

        assert_eq!(
            commit_tree_and_parent(message.as_bytes()),
            Some((tree, Some(first_parent)))
        );
    }

    #[test]
    fn sends_only_complete_changed_path_lists() {
        let output = b"A\0added\0M\0modified\0T\0type-changed\0D\0deleted\0";
        let (count, paths) = parse_changed_paths(output).unwrap();
        let paths = paths.unwrap();
        assert_eq!(count, 4);
        assert_eq!(paths.len(), 4);
        assert!(matches!(paths[0].status, ChangeStatus::Added));
        assert_eq!(paths[0].path, "added");

        let mut output = Vec::new();
        for index in 0..=MAXIMUM_CHANGED_PATHS {
            output.extend_from_slice(format!("M\0path-{index}\0").as_bytes());
        }
        let (count, paths) = parse_changed_paths(&output).unwrap();
        assert_eq!(count, MAXIMUM_CHANGED_PATHS + 1);
        assert!(paths.is_none());
    }
}
