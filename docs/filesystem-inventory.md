# Filesystem metadata

`toolgate.executors.filesystem_inventory` lists names and kinds only. It never
opens file contents, resolves symlinks, reads credentials, writes, or deletes.
Operator `TOOLGATE_FILE_ROOTS` is a JSON object such as
`{"workspace":"/srv/conker/workspace"}`. No default root exists. Root IDs are
1–64 ASCII letters, digits, underscores or hyphens; at most 64 roots / 32 KiB
configuration. Root paths are absolute Linux paths without symlink components,
trailing separators, dot components or control characters. `/` is allowed only
if explicitly configured by the operator; narrow roots are preferable.

`roots()` returns configuration, not an existence check: `mode: configured`,
`roots: [{id,path}]`, and list/read/write capabilities true/false/false. Absolute
paths are owner-selected display metadata. This API still requires scoped
authorization at its caller; filenames themselves may be sensitive.

`list_directory(root_id, path='', limit=200)` returns `mode: observed`, `rootId`,
relative `path`, `entries: [{name,path,kind}]`, `truncated`, and ISO `sampledAt`.
Kinds are directory/file/symlink/other. Limit is an integer 1–200. The backend
examines at most 2,000 entries plus one lookahead and returns at most 200.
Unsafe/unrepresentable names are omitted and mark the listing truncated. Truncated listings are a bounded
sample, sorted directories first then name; there is no pagination or promise
that this is the alphabetically first page. Paths are at most 4,096 characters.

Native implementation requires Linux. It opens `/` then every configured and
requested component relative to an already-open directory descriptor, with
`O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`. Listing and non-following stat use that
descriptor. Symlink replacement cannot redirect traversal outside the held
directory. Renaming an already-open directory preserves its identity, not its
current pathname; results are not a transactional filesystem snapshot. If an
entry disappears before its metadata is read, the entire request fails as
unavailable and may be requested again. Mounts
and hard links remain within the operator's trust boundary. No syscall deadline
is guaranteed for stalled network filesystems; use local roots.

`FileError` exposes static `code`, `message`, `status`; OS paths/errors never
appear in error responses. Unsupported platforms fail explicitly without a
path-based fallback. Tests use a descriptor backend seam on Windows, plus a
Linux-only temporary-directory test for actual symlink/replacement rejection.
The latter is skipped on Windows; Windows test success alone does not verify
native Linux syscalls. No tests inspect production roots.
