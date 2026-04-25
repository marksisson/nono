//! Declarative install-time wiring for nono packs.
//!
//! Packs that need to place files in agent-specific locations (Claude
//! Code's marketplace dirs, Codex's config.toml entries, etc) declare
//! the operations as data in their `package.json::wiring` array. The
//! CLI executes that data via a closed vocabulary of directive types.
//!
//! Design rules:
//!   - The CLI knows nothing about specific agents. The directives
//!     are agent-agnostic file ops; the pack supplies the inputs.
//!   - The vocabulary is fixed and small (5 types). New directive
//!     types require a CLI release; new agents do not.
//!   - Every directive records what it did into a `WiringRecord`,
//!     stored in the lockfile. `nono remove` replays records in
//!     reverse — the install plan never has to be re-derived.
//!   - Variables expanded at execution time: `$PACK_DIR`, `$NS`
//!     (pack namespace), `$PLUGIN` (pack name, the second segment
//!     of `<ns>/<pack>`), `$HOME`, `$XDG_CONFIG_HOME`. No shell
//!     evaluation, no user-controlled inputs flow in.
//!   - Idempotent: re-running a directive with the same inputs is a
//!     no-op and reports `wiring_changed = false`.

use chrono::Utc;
use nono::{NonoError, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs as unix_fs;
use std::path::{Path, PathBuf};

/// A single declarative wiring step. Tagged by `type` so the manifest
/// JSON reads naturally — `{ "type": "symlink", ... }`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WiringDirective {
    /// Create a symlink at `link` pointing to `target`. Both fields
    /// are variable-expanded. If `link` already exists as a symlink
    /// pointing at the right `target`, no-op. If it points elsewhere,
    /// it's replaced. If a real file/dir occupies the path, refuse
    /// (records as conflict, no rewrite).
    Symlink { link: String, target: String },

    /// Copy a file from inside the pack to an absolute path. `source`
    /// is a pack-relative path (no `..`, no leading `/`); `dest` is
    /// the absolute destination, variable-expanded. Mode preserved.
    WriteFile { source: String, dest: String },

    /// Read a JSON document from a pack-relative `patch` file and
    /// merge it into the JSON file at `file`. Object keys are deep-
    /// merged (last writer wins); arrays are replaced wholesale (use
    /// `JsonArrayAppend` when you need to extend an array).
    JsonMerge { file: String, patch: String },

    /// Append entries to a JSON array at `path` inside `file`. Each
    /// entry from `patch_entries` (a JSON array file in the pack) is
    /// added unless an entry already exists with a matching value at
    /// the `key_field`. Idempotent.
    JsonArrayAppend {
        file: String,
        path: String,
        patch_entries: String,
        key_field: String,
    },

    /// Insert (or replace) a fenced text block in `file`, identified
    /// by `marker_id`. Markers are derived as
    /// `# >>> nono:<marker_id> >>>` and `# <<< nono:<marker_id> <<<`.
    /// `content` is a pack-relative file holding the block body.
    /// Re-running replaces just that block; lines outside the markers
    /// are never touched.
    TomlBlock {
        file: String,
        marker_id: String,
        content: String,
    },
}

/// What a single directive did, recorded into the lockfile so removal
/// can undo it without re-evaluating the original directive list (the
/// pack might have been updated or removed in the meantime).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WiringRecord {
    /// Symlink created (or repointed) at `link`.
    Symlink { link: String },
    /// File copied to `dest`.
    WriteFile { dest: String },
    /// JSON keys we set in `file`. On removal, those exact keys are
    /// stripped (other keys at the same paths are preserved).
    JsonMerge { file: String, keys: Vec<String> },
    /// Entries we appended to a JSON array at `path` inside `file`,
    /// matched by `key_field`. On removal, entries with those key
    /// values are filtered out; pre-existing entries are preserved.
    JsonArrayAppend {
        file: String,
        path: String,
        key_field: String,
        keys: Vec<String>,
    },
    /// TOML fenced block we wrote in `file` under `marker_id`.
    TomlBlock { file: String, marker_id: String },
}

/// Context for variable expansion — supplied by the caller, NOT by
/// pack content. Closed set, no shell evaluation.
#[derive(Debug)]
pub struct WiringContext {
    /// Absolute path of the pack inside the package store.
    pub pack_dir: PathBuf,
    /// Pack namespace (the `<ns>` in `<ns>/<pack>`).
    pub namespace: String,
    /// Pack name (the `<pack>` in `<ns>/<pack>`).
    pub pack_name: String,
}

/// Outcome of executing a directive list.
#[derive(Debug, Default)]
pub struct WiringReport {
    /// Records of every directive that ran successfully — go into
    /// the lockfile so `reverse()` knows what to undo.
    pub records: Vec<WiringRecord>,
    /// Conflicts encountered (path occupied, etc) that didn't abort
    /// but the user should know about.
    pub conflicts: Vec<String>,
    /// True if any directive actually changed disk state.
    pub changed: bool,
}

/// Execute a list of directives in order. Stops on hard errors; soft
/// conflicts (a real file where we'd symlink) are recorded and
/// execution continues with the next directive.
pub fn execute(directives: &[WiringDirective], ctx: &WiringContext) -> Result<WiringReport> {
    let mut report = WiringReport::default();
    for directive in directives {
        match execute_one(directive, ctx, &mut report) {
            Ok(()) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(report)
}

fn execute_one(
    directive: &WiringDirective,
    ctx: &WiringContext,
    report: &mut WiringReport,
) -> Result<()> {
    match directive {
        WiringDirective::Symlink { link, target } => {
            let link_path = expand_to_path(link, ctx)?;
            let target_path = expand_to_path(target, ctx)?;
            match ensure_symlink(&link_path, &target_path)? {
                SymlinkOutcome::Created | SymlinkOutcome::Repointed => {
                    report.changed = true;
                    report.records.push(WiringRecord::Symlink {
                        link: link_path.to_string_lossy().into_owned(),
                    });
                }
                SymlinkOutcome::AlreadyCorrect => {
                    // Still record so removal knows we own it.
                    report.records.push(WiringRecord::Symlink {
                        link: link_path.to_string_lossy().into_owned(),
                    });
                }
                SymlinkOutcome::Conflict(msg) => {
                    report.conflicts.push(msg);
                }
            }
        }
        WiringDirective::WriteFile { source, dest } => {
            let source_path = pack_relative(source, ctx)?;
            let dest_path = expand_to_path(dest, ctx)?;
            let changed = copy_file_atomic(&source_path, &dest_path)?;
            if changed {
                report.changed = true;
            }
            report.records.push(WiringRecord::WriteFile {
                dest: dest_path.to_string_lossy().into_owned(),
            });
        }
        WiringDirective::JsonMerge { file, patch } => {
            let file_path = expand_to_path(file, ctx)?;
            let patch_path = pack_relative(patch, ctx)?;
            let patch_value = read_pack_json(&patch_path, ctx)?;
            let keys = merge_json_into_file(&file_path, &patch_value)?;
            if !keys.is_empty() {
                report.changed = true;
            }
            report.records.push(WiringRecord::JsonMerge {
                file: file_path.to_string_lossy().into_owned(),
                keys,
            });
        }
        WiringDirective::JsonArrayAppend {
            file,
            path,
            patch_entries,
            key_field,
        } => {
            let file_path = expand_to_path(file, ctx)?;
            let entries_path = pack_relative(patch_entries, ctx)?;
            let entries_value = read_pack_json(&entries_path, ctx)?;
            let entries = entries_value.as_array().ok_or_else(|| {
                NonoError::PackageInstall(format!(
                    "json_array_append: {} must be a JSON array",
                    entries_path.display()
                ))
            })?;
            let outcome = append_json_entries(&file_path, path, entries, key_field)?;
            if outcome.mutated {
                report.changed = true;
            }
            report.records.push(WiringRecord::JsonArrayAppend {
                file: file_path.to_string_lossy().into_owned(),
                path: path.clone(),
                key_field: key_field.clone(),
                keys: outcome.keys,
            });
        }
        WiringDirective::TomlBlock {
            file,
            marker_id,
            content,
        } => {
            let file_path = expand_to_path(file, ctx)?;
            let content_path = pack_relative(content, ctx)?;
            let raw_body = fs::read_to_string(&content_path).map_err(NonoError::Io)?;
            // Expand `$VAR` placeholders inside the body so packs can
            // declare absolute paths (e.g. `source = "$HOME/.codex/..."`)
            // without committing user-specific paths to the registry.
            let body = expand_vars(&raw_body, ctx)?;
            let changed = upsert_toml_block(&file_path, marker_id, &body)?;
            if changed {
                report.changed = true;
            }
            report.records.push(WiringRecord::TomlBlock {
                file: file_path.to_string_lossy().into_owned(),
                marker_id: marker_id.clone(),
            });
        }
    }
    Ok(())
}

/// Replay a record list in reverse, undoing each. Best-effort: a
/// missing file or already-removed key is not an error.
pub fn reverse(records: &[WiringRecord]) -> Result<()> {
    for record in records.iter().rev() {
        let _ = reverse_one(record);
    }
    Ok(())
}

fn reverse_one(record: &WiringRecord) -> Result<()> {
    match record {
        WiringRecord::Symlink { link } => {
            let path = Path::new(link);
            if let Ok(meta) = path.symlink_metadata() {
                if meta.file_type().is_symlink() {
                    let _ = fs::remove_file(path);
                }
            }
        }
        WiringRecord::WriteFile { dest } => {
            let _ = fs::remove_file(dest);
        }
        WiringRecord::JsonMerge { file, keys } => {
            strip_json_keys(Path::new(file), keys)?;
        }
        WiringRecord::JsonArrayAppend {
            file,
            path,
            key_field,
            keys,
        } => {
            strip_json_array_entries(Path::new(file), path, key_field, keys)?;
        }
        WiringRecord::TomlBlock { file, marker_id } => {
            strip_toml_block(Path::new(file), marker_id)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Variable expansion + path validation
// ---------------------------------------------------------------------------

/// Expand `$VAR` placeholders in a string against the closed set of
/// allowed variables, then return as a path. Refuses unknown variables
/// and `..` traversal.
fn expand_to_path(template: &str, ctx: &WiringContext) -> Result<PathBuf> {
    let expanded = expand_vars(template, ctx)?;
    let path = PathBuf::from(&expanded);
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(NonoError::PackageInstall(format!(
            "wiring path contains '..': '{template}'"
        )));
    }
    Ok(path)
}

/// Resolve a pack-relative path safely (no escape via `..`, no
/// absolute paths).
fn pack_relative(rel: &str, ctx: &WiringContext) -> Result<PathBuf> {
    let p = Path::new(rel);
    if p.is_absolute() {
        return Err(NonoError::PackageInstall(format!(
            "wiring source must be pack-relative, got '{rel}'"
        )));
    }
    if p.components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(NonoError::PackageInstall(format!(
            "wiring source contains '..': '{rel}'"
        )));
    }
    Ok(ctx.pack_dir.join(p))
}

fn expand_vars(template: &str, ctx: &WiringContext) -> Result<String> {
    let home = xdg_home::home_dir()
        .ok_or_else(|| NonoError::PackageInstall("HOME not set".to_string()))?;
    let xdg_config_home = std::env::var("XDG_CONFIG_HOME")
        .ok()
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"));

    let pack_dir = ctx.pack_dir.to_string_lossy().into_owned();
    let home_str = home.to_string_lossy().into_owned();
    let xdg_str = xdg_config_home.to_string_lossy().into_owned();

    // `$` is a variable sigil only when followed by an ASCII uppercase
    // letter or underscore — i.e. the start of an identifier from the
    // closed set below. Any other `$` (regex end-anchor `$`, a literal
    // dollar sign in a comment, jq's `$var` lowercase) is passed
    // through untouched. This keeps pack content like
    // `"matcher": "^(Bash|apply_patch)$"` from needing a `$$` escape.
    let mut out = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '$' {
            out.push(c);
            continue;
        }
        match chars.peek() {
            Some(&p) if p.is_ascii_uppercase() || p == '_' => {}
            _ => {
                out.push('$');
                continue;
            }
        }
        let mut name = String::new();
        while let Some(&peek) = chars.peek() {
            if peek.is_ascii_alphanumeric() || peek == '_' {
                name.push(peek);
                chars.next();
            } else {
                break;
            }
        }
        let value = match name.as_str() {
            "PACK_DIR" => pack_dir.clone(),
            "NS" => ctx.namespace.clone(),
            "PLUGIN" => ctx.pack_name.clone(),
            "HOME" => home_str.clone(),
            "XDG_CONFIG_HOME" => xdg_str.clone(),
            // Install-time UTC timestamp (RFC3339, milliseconds), for
            // agents that require a `lastUpdated`-style field on their
            // config entries (Claude Code's marketplace registry being
            // the case that drove this in). Resolved per call so each
            // expansion within a single install carries the same
            // monotonic value.
            "NOW" => Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            other => {
                return Err(NonoError::PackageInstall(format!(
                    "wiring template references unknown variable '${other}' in '{template}'"
                )));
            }
        };
        out.push_str(&value);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Symlink primitive
// ---------------------------------------------------------------------------

enum SymlinkOutcome {
    Created,
    Repointed,
    AlreadyCorrect,
    Conflict(String),
}

fn ensure_symlink(link: &Path, target: &Path) -> Result<SymlinkOutcome> {
    if let Some(parent) = link.parent() {
        fs::create_dir_all(parent).map_err(NonoError::Io)?;
    }
    match link.symlink_metadata() {
        Ok(meta) => {
            if !meta.file_type().is_symlink() {
                return Ok(SymlinkOutcome::Conflict(format!(
                    "{} exists and is not a nono-managed symlink — leaving it alone",
                    link.display()
                )));
            }
            let current = fs::read_link(link).map_err(NonoError::Io)?;
            if current == target {
                return Ok(SymlinkOutcome::AlreadyCorrect);
            }
            fs::remove_file(link).map_err(NonoError::Io)?;
            unix_fs::symlink(target, link).map_err(NonoError::Io)?;
            Ok(SymlinkOutcome::Repointed)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            unix_fs::symlink(target, link).map_err(NonoError::Io)?;
            Ok(SymlinkOutcome::Created)
        }
        Err(e) => Err(NonoError::Io(e)),
    }
}

// ---------------------------------------------------------------------------
// File copy primitive
// ---------------------------------------------------------------------------

fn copy_file_atomic(source: &Path, dest: &Path) -> Result<bool> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(NonoError::Io)?;
    }
    // Skip-no-op only if existing content matches exactly.
    if let (Ok(a), Ok(b)) = (fs::read(source), fs::read(dest)) {
        if a == b {
            return Ok(false);
        }
    }
    let tmp = dest.with_extension("nono-tmp");
    fs::copy(source, &tmp).map_err(NonoError::Io)?;
    fs::rename(&tmp, dest).map_err(NonoError::Io)?;
    Ok(true)
}

// ---------------------------------------------------------------------------
// JSON merge / append primitives
// ---------------------------------------------------------------------------

fn read_json(path: &Path) -> Result<Value> {
    let content = fs::read_to_string(path).map_err(NonoError::Io)?;
    serde_json::from_str(&content)
        .map_err(|e| NonoError::PackageInstall(format!("invalid JSON in {}: {e}", path.display())))
}

/// Read a JSON file shipped inside the pack and expand `$VAR`
/// placeholders inside string values (recursively, including inside
/// arrays and nested objects). Used for `JsonMerge` and
/// `JsonArrayAppend` patch files so packs can declare paths like
/// `"$HOME/.claude/plugins/marketplaces/$NS"` inside the JSON
/// content. Object keys are NOT expanded — they're treated as
/// literal identifiers so a user-controlled value can't accidentally
/// rewrite a key path.
fn read_pack_json(path: &Path, ctx: &WiringContext) -> Result<Value> {
    let mut value = read_json(path)?;
    expand_json_strings(&mut value, ctx)?;
    Ok(value)
}

fn expand_json_strings(value: &mut Value, ctx: &WiringContext) -> Result<()> {
    match value {
        Value::String(s) => {
            if s.contains('$') {
                *s = expand_vars(s, ctx)?;
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                expand_json_strings(v, ctx)?;
            }
        }
        Value::Object(obj) => {
            for (_k, v) in obj.iter_mut() {
                expand_json_strings(v, ctx)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Deep-merge `patch` into the JSON document at `file`. Returns the
/// list of top-level patch keys actually applied (so removal knows
/// which to strip later). If the file doesn't exist, it's created.
fn merge_json_into_file(file: &Path, patch: &Value) -> Result<Vec<String>> {
    let mut existing = if file.exists() {
        read_json(file)?
    } else {
        Value::Object(serde_json::Map::new())
    };
    let mut applied = Vec::new();
    if let (Value::Object(dst), Value::Object(src)) = (&mut existing, patch) {
        for (k, v) in src {
            applied.push(k.clone());
            match dst.get_mut(k) {
                Some(existing_val) => deep_merge(existing_val, v),
                None => {
                    dst.insert(k.clone(), v.clone());
                }
            }
        }
    } else {
        return Err(NonoError::PackageInstall(format!(
            "json_merge: {} must be a JSON object at the root",
            file.display()
        )));
    }
    write_json(file, &existing)?;
    Ok(applied)
}

fn deep_merge(target: &mut Value, src: &Value) {
    match (target, src) {
        (Value::Object(a), Value::Object(b)) => {
            for (k, v) in b {
                match a.get_mut(k) {
                    Some(existing) => deep_merge(existing, v),
                    None => {
                        a.insert(k.clone(), v.clone());
                    }
                }
            }
        }
        (slot, src) => *slot = src.clone(),
    }
}

/// Append entries to the JSON array at `path` inside `file`. `path`
/// is dot-separated (e.g. `hooks.PostToolUse`). `key_field` is also
/// dot-separated; walking from each entry's root it should resolve to
/// a string used for dedup (e.g. `hooks.0.command` to dedup by the
/// first hook's command path). Returns the list of dedup keys actually
/// appended — paired with `key_field` and `path`, the inverse can
/// filter exactly those entries back out on removal.
/// Outcome of `append_json_entries`. `keys` is what landed on disk
/// (used by the lockfile so `nono remove` can strip those entries
/// back out). `mutated` is whether the file's contents actually
/// changed — false for a no-op idempotent re-run.
struct AppendOutcome {
    keys: Vec<String>,
    mutated: bool,
}

fn append_json_entries(
    file: &Path,
    path: &str,
    entries: &[Value],
    key_field: &str,
) -> Result<AppendOutcome> {
    let mut doc = if file.exists() {
        read_json(file)?
    } else {
        Value::Object(serde_json::Map::new())
    };
    let before = doc.clone();
    let array = ensure_array_at(&mut doc, path)?;
    let mut keys = Vec::new();
    for entry in entries {
        let Some(key) = extract_string_at(entry, key_field) else {
            return Err(NonoError::PackageInstall(format!(
                "json_array_append: entry has no string at key_field '{key_field}'"
            )));
        };
        let key_owned = key.to_string();
        // Replace-in-place if the dedup key already matches an entry —
        // pack re-publishes that add or change fields (e.g. flipping
        // `silent: true` on a hook) need the new shape to win, not the
        // pre-existing entry. Pure idempotency (identical re-run) is
        // preserved by the `mutated` check below: if the doc bytes are
        // unchanged we skip the write and report `changed = false`.
        let mut replaced = false;
        for existing in array.iter_mut() {
            if extract_string_at(existing, key_field) == Some(key) {
                *existing = entry.clone();
                replaced = true;
                break;
            }
        }
        if !replaced {
            array.push(entry.clone());
        }
        keys.push(key_owned);
    }
    let mutated = doc != before;
    if mutated {
        write_json(file, &doc)?;
    }
    Ok(AppendOutcome { keys, mutated })
}

/// Walk `value` along a dot-separated path. Numeric segments index
/// arrays. Returns `None` if any segment doesn't exist or the leaf
/// isn't a string.
fn extract_string_at<'a>(value: &'a Value, path: &str) -> Option<&'a str> {
    let mut cursor = value;
    for seg in path.split('.') {
        cursor = if let Ok(idx) = seg.parse::<usize>() {
            cursor.as_array().and_then(|arr| arr.get(idx))?
        } else {
            cursor.as_object().and_then(|obj| obj.get(seg))?
        };
    }
    cursor.as_str()
}

/// Walk `doc` along `path` (dot-separated), creating empty objects
/// along the way; ensure the leaf is a JSON array and return a
/// mutable reference to it.
fn ensure_array_at<'a>(doc: &'a mut Value, path: &str) -> Result<&'a mut Vec<Value>> {
    let segments: Vec<&str> = path.split('.').collect();
    let mut cursor = doc;
    for (i, seg) in segments.iter().enumerate() {
        let is_last = i == segments.len() - 1;
        let obj = cursor.as_object_mut().ok_or_else(|| {
            NonoError::PackageInstall(format!("json_array_append: '{path}' traverses non-object"))
        })?;
        if is_last {
            let entry = obj
                .entry(seg.to_string())
                .or_insert_with(|| Value::Array(Vec::new()));
            return entry.as_array_mut().ok_or_else(|| {
                NonoError::PackageInstall(format!("json_array_append: '{path}' is not an array"))
            });
        }
        cursor = obj
            .entry(seg.to_string())
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
    }
    unreachable!("segments has at least one element")
}

fn write_json(path: &Path, value: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(NonoError::Io)?;
    }
    let pretty = serde_json::to_string_pretty(value)
        .map_err(|e| NonoError::PackageInstall(format!("serialize {}: {e}", path.display())))?;
    let tmp = path.with_extension("json.nono-tmp");
    fs::write(&tmp, format!("{pretty}\n")).map_err(NonoError::Io)?;
    fs::rename(&tmp, path).map_err(NonoError::Io)?;
    Ok(())
}

/// Reverse of `merge_json_into_file`: strip the listed top-level keys.
fn strip_json_keys(file: &Path, keys: &[String]) -> Result<()> {
    if !file.exists() {
        return Ok(());
    }
    let mut doc = match read_json(file) {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };
    let Some(obj) = doc.as_object_mut() else {
        return Ok(());
    };
    let mut changed = false;
    for k in keys {
        if obj.remove(k).is_some() {
            changed = true;
        }
    }
    if changed {
        write_json(file, &doc)?;
    }
    Ok(())
}

/// Reverse of `append_json_entries`: walk to the array and filter
/// out entries whose `key_field` is in `keys`. Drop the array if it
/// becomes empty.
fn strip_json_array_entries(
    file: &Path,
    path: &str,
    key_field: &str,
    keys: &[String],
) -> Result<()> {
    if !file.exists() {
        return Ok(());
    }
    let mut doc = match read_json(file) {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };
    let Ok(array) = ensure_array_at(&mut doc, path) else {
        return Ok(());
    };
    let before = array.len();
    array.retain(|entry| {
        extract_string_at(entry, key_field)
            .map(|k| !keys.iter().any(|key| key == k))
            .unwrap_or(true)
    });
    if array.len() != before {
        write_json(file, &doc)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// TOML fenced block primitive
// ---------------------------------------------------------------------------

fn block_markers(marker_id: &str) -> (String, String) {
    (
        format!("# >>> nono:{marker_id} >>>"),
        format!("# <<< nono:{marker_id} <<<"),
    )
}

/// Insert or replace a fenced block in `file`. Pure text edit — no
/// TOML parser, since we own the markers exactly. Returns true if
/// disk content changed.
fn upsert_toml_block(file: &Path, marker_id: &str, body: &str) -> Result<bool> {
    let (begin, end) = block_markers(marker_id);
    let existing = fs::read_to_string(file).unwrap_or_default();
    let new_block = format!("{begin}\n{}{end}\n", ensure_trailing_newline(body));

    let updated = match find_block_bounds(&existing, &begin, &end) {
        Some((s, e)) => {
            let mut out = String::with_capacity(existing.len() + new_block.len());
            out.push_str(&existing[..s]);
            out.push_str(&new_block);
            out.push_str(&existing[e..]);
            out
        }
        None => {
            let mut out = existing.clone();
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            if !out.is_empty() && !out.ends_with("\n\n") {
                out.push('\n');
            }
            out.push_str(&new_block);
            out
        }
    };

    if updated == existing {
        return Ok(false);
    }
    if let Some(parent) = file.parent() {
        fs::create_dir_all(parent).map_err(NonoError::Io)?;
    }
    let tmp = file.with_extension("toml.nono-tmp");
    fs::write(&tmp, &updated).map_err(NonoError::Io)?;
    fs::rename(&tmp, file).map_err(NonoError::Io)?;
    Ok(true)
}

fn strip_toml_block(file: &Path, marker_id: &str) -> Result<()> {
    if !file.exists() {
        return Ok(());
    }
    let (begin, end) = block_markers(marker_id);
    let existing = fs::read_to_string(file).map_err(NonoError::Io)?;
    let Some((s, e)) = find_block_bounds(&existing, &begin, &end) else {
        return Ok(());
    };
    let mut out = String::with_capacity(existing.len());
    out.push_str(&existing[..s]);
    out.push_str(&existing[e..]);
    if out.ends_with("\n\n") {
        out.pop();
    }
    let tmp = file.with_extension("toml.nono-tmp");
    fs::write(&tmp, &out).map_err(NonoError::Io)?;
    fs::rename(&tmp, file).map_err(NonoError::Io)?;
    Ok(())
}

fn find_block_bounds(content: &str, begin: &str, end: &str) -> Option<(usize, usize)> {
    let s = content.find(begin)?;
    let end_marker_end = content[s..].find(end).map(|rel| s + rel + end.len())?;
    let after = if content[end_marker_end..].starts_with('\n') {
        end_marker_end + 1
    } else {
        end_marker_end
    };
    Some((s, after))
}

fn ensure_trailing_newline(s: &str) -> String {
    if s.ends_with('\n') {
        s.to_string()
    } else {
        format!("{s}\n")
    }
}

// Suppress unused-import warnings for items that are only used in
// callers we haven't wired up yet (lockfile schema additions land in
// a follow-up step). Forward-only — once `package.rs` references
// `WiringRecord`, this goes away.
#[allow(dead_code)]
fn _suppress_unused() {
    let _ = (Utc::now, BTreeMap::<String, String>::new);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env::{EnvVarGuard, ENV_LOCK};
    use tempfile::TempDir;

    fn ctx_in(home: &Path, pack_dir: PathBuf) -> WiringContext {
        let _ = home; // signature parity with test setup
        WiringContext {
            pack_dir,
            namespace: "always-further".to_string(),
            pack_name: "claude".to_string(),
        }
    }

    fn with_fake_home<F: FnOnce(&Path)>(f: F) {
        let _g = match ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let home = TempDir::new().expect("tempdir");
        let _env = EnvVarGuard::set_all(&[("HOME", home.path().to_str().expect("utf8"))]);
        f(home.path());
    }

    #[test]
    fn expand_vars_substitutes_known_set() {
        let pack_dir = PathBuf::from("/p");
        let ctx = WiringContext {
            pack_dir,
            namespace: "ns".to_string(),
            pack_name: "name".to_string(),
        };
        let _g = match ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let _env = EnvVarGuard::set_all(&[("HOME", "/h")]);
        assert_eq!(expand_vars("$PACK_DIR/x", &ctx).expect("expand"), "/p/x");
        assert_eq!(expand_vars("$NS/$PLUGIN", &ctx).expect("expand"), "ns/name");
        assert_eq!(
            expand_vars("$HOME/.config", &ctx).expect("expand"),
            "/h/.config"
        );
    }

    #[test]
    fn expand_vars_rejects_unknown() {
        let ctx = WiringContext {
            pack_dir: PathBuf::from("/p"),
            namespace: "n".to_string(),
            pack_name: "p".to_string(),
        };
        assert!(expand_vars("$BOGUS/x", &ctx).is_err());
        // Bare `$` not followed by an uppercase identifier passes through.
        // Lets pack content like regex end-anchors stay literal without
        // needing a `$$` escape.
        assert_eq!(
            expand_vars("trailing $", &ctx).expect("trailing"),
            "trailing $"
        );
        assert_eq!(
            expand_vars("^(Bash|apply_patch)$", &ctx).expect("regex"),
            "^(Bash|apply_patch)$"
        );
        assert_eq!(
            expand_vars("$lowercase", &ctx).expect("lower"),
            "$lowercase"
        );
    }

    #[test]
    fn symlink_directive_creates_records_and_reverses() {
        with_fake_home(|home| {
            let pack = home.join("pack");
            fs::create_dir_all(&pack).expect("mkdir pack");
            let ctx = ctx_in(home, pack.clone());
            let directives = vec![WiringDirective::Symlink {
                link: "$HOME/link".to_string(),
                target: "$PACK_DIR".to_string(),
            }];
            let report = execute(&directives, &ctx).expect("execute");
            assert!(report.changed);
            assert_eq!(report.records.len(), 1);
            let link = home.join("link");
            assert!(link
                .symlink_metadata()
                .expect("meta")
                .file_type()
                .is_symlink());
            assert_eq!(fs::read_link(&link).expect("readlink"), pack);

            reverse(&report.records).expect("reverse");
            assert!(link.symlink_metadata().is_err());
        });
    }

    #[test]
    fn symlink_directive_is_idempotent() {
        with_fake_home(|home| {
            let pack = home.join("pack");
            fs::create_dir_all(&pack).expect("mkdir pack");
            let ctx = ctx_in(home, pack);
            let directives = vec![WiringDirective::Symlink {
                link: "$HOME/link".to_string(),
                target: "$PACK_DIR".to_string(),
            }];
            let _ = execute(&directives, &ctx).expect("first");
            let r2 = execute(&directives, &ctx).expect("second");
            assert!(!r2.changed, "second run should be no-op");
        });
    }

    #[test]
    fn json_merge_and_strip_round_trip() {
        with_fake_home(|home| {
            let pack = home.join("pack");
            fs::create_dir_all(&pack).expect("mkdir pack");
            fs::write(
                pack.join("patch.json"),
                r#"{ "enabledPlugins": { "nono": true } }"#,
            )
            .expect("write patch");
            // Seed an existing file with unrelated keys.
            let target = home.join("settings.json");
            fs::write(&target, r#"{ "effortLevel": "xhigh" }"#).expect("seed target");

            let ctx = ctx_in(home, pack);
            let directives = vec![WiringDirective::JsonMerge {
                file: "$HOME/settings.json".to_string(),
                patch: "patch.json".to_string(),
            }];
            let report = execute(&directives, &ctx).expect("execute");
            let v: Value =
                serde_json::from_str(&fs::read_to_string(&target).expect("read")).expect("parse");
            assert_eq!(v["effortLevel"], "xhigh", "preserve unrelated keys");
            assert_eq!(v["enabledPlugins"]["nono"], true);

            reverse(&report.records).expect("reverse");
            let v2: Value =
                serde_json::from_str(&fs::read_to_string(&target).expect("read")).expect("parse");
            assert_eq!(v2["effortLevel"], "xhigh", "unrelated keys still present");
            assert!(v2.get("enabledPlugins").is_none(), "merged keys gone");
        });
    }

    #[test]
    fn json_array_append_dedups_by_key_field() {
        with_fake_home(|home| {
            let pack = home.join("pack");
            fs::create_dir_all(&pack).expect("mkdir pack");
            fs::write(
                pack.join("entries.json"),
                r#"[{ "name": "nono", "command": "x" }]"#,
            )
            .expect("write entries");

            let target = home.join("hooks.json");
            let ctx = ctx_in(home, pack);
            let directives = vec![WiringDirective::JsonArrayAppend {
                file: "$HOME/hooks.json".to_string(),
                path: "hooks.PostToolUse".to_string(),
                patch_entries: "entries.json".to_string(),
                key_field: "name".to_string(),
            }];
            let r1 = execute(&directives, &ctx).expect("first");
            assert!(r1.changed);
            let r2 = execute(&directives, &ctx).expect("second");
            assert!(!r2.changed, "dedup by key_field");

            let v: Value =
                serde_json::from_str(&fs::read_to_string(&target).expect("read")).expect("parse");
            assert_eq!(
                v["hooks"]["PostToolUse"].as_array().expect("array").len(),
                1
            );

            reverse(&r1.records).expect("reverse");
            let v2: Value =
                serde_json::from_str(&fs::read_to_string(&target).expect("read")).expect("parse");
            assert_eq!(
                v2["hooks"]["PostToolUse"].as_array().expect("array").len(),
                0
            );
        });
    }

    #[test]
    fn json_array_append_replaces_entry_when_shape_changes() {
        with_fake_home(|home| {
            let pack = home.join("pack");
            fs::create_dir_all(&pack).expect("mkdir pack");
            // First publish: just name + command.
            fs::write(
                pack.join("entries.json"),
                r#"[{ "name": "nono", "command": "x" }]"#,
            )
            .expect("write v1");

            let target = home.join("hooks.json");
            let ctx = ctx_in(home, pack.clone());
            let directives = vec![WiringDirective::JsonArrayAppend {
                file: "$HOME/hooks.json".to_string(),
                path: "hooks.PostToolUse".to_string(),
                patch_entries: "entries.json".to_string(),
                key_field: "name".to_string(),
            }];
            let r1 = execute(&directives, &ctx).expect("first install");
            assert!(r1.changed);

            // Second publish with new shape (added `silent: true`).
            fs::write(
                pack.join("entries.json"),
                r#"[{ "name": "nono", "command": "x", "silent": true }]"#,
            )
            .expect("write v2");

            let r2 = execute(&directives, &ctx).expect("re-install");
            assert!(r2.changed, "shape change must be applied, not skipped");

            let v: Value =
                serde_json::from_str(&fs::read_to_string(&target).expect("read")).expect("parse");
            let entries = v["hooks"]["PostToolUse"].as_array().expect("array present");
            assert_eq!(entries.len(), 1, "key dedup keeps a single entry");
            assert_eq!(
                entries[0].get("silent").and_then(|v| v.as_bool()),
                Some(true),
                "new shape (silent:true) replaces old shape"
            );

            // Re-running with the same v2 entries is a true no-op.
            let r3 = execute(&directives, &ctx).expect("third");
            assert!(!r3.changed, "identical re-run must report no change");
        });
    }

    #[test]
    fn toml_block_upsert_strip_round_trip() {
        with_fake_home(|home| {
            let pack = home.join("pack");
            fs::create_dir_all(&pack).expect("mkdir pack");
            fs::write(pack.join("block.toml"), "[plugins.test]\nenabled = true\n")
                .expect("write block");

            let target = home.join("config.toml");
            // Seed unrelated content.
            fs::write(&target, "[features]\ncodex_hooks = true\n").expect("seed");

            let ctx = ctx_in(home, pack);
            let directives = vec![WiringDirective::TomlBlock {
                file: "$HOME/config.toml".to_string(),
                marker_id: "test".to_string(),
                content: "block.toml".to_string(),
            }];
            let r = execute(&directives, &ctx).expect("execute");
            let after = fs::read_to_string(&target).expect("read");
            assert!(after.contains("# >>> nono:test >>>"));
            assert!(after.contains("[plugins.test]"));
            assert!(after.contains("[features]"), "unrelated section preserved");

            reverse(&r.records).expect("reverse");
            let after_strip = fs::read_to_string(&target).expect("read");
            assert!(!after_strip.contains("nono:test"));
            assert!(after_strip.contains("[features]"));
        });
    }

    #[test]
    fn write_file_atomic_skips_when_identical() {
        with_fake_home(|home| {
            let pack = home.join("pack");
            fs::create_dir_all(&pack).expect("mkdir pack");
            fs::write(pack.join("file"), "hello").expect("seed source");
            let ctx = ctx_in(home, pack);
            let directives = vec![WiringDirective::WriteFile {
                source: "file".to_string(),
                dest: "$HOME/dest".to_string(),
            }];
            let r1 = execute(&directives, &ctx).expect("first");
            assert!(r1.changed);
            let r2 = execute(&directives, &ctx).expect("second");
            assert!(!r2.changed, "identical content is no-op");

            reverse(&r1.records).expect("reverse");
            assert!(!home.join("dest").exists());
        });
    }
}
