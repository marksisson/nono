use nono::supervisor::{AuditEntry, UrlOpenRequest};
use nono::undo::{AuditIntegritySummary, ContentHash, NetworkAuditEvent};
use nono::{NonoError, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

const AUDIT_EVENTS_FILENAME: &str = "audit-events.ndjson";
const EVENT_DOMAIN: &[u8] = b"nono.audit.event.v1\n";
const CHAIN_DOMAIN: &[u8] = b"nono.audit.chain.v1\n";
const HASH_ALGORITHM: &str = "sha256";

#[derive(Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum AuditEventPayload {
    SessionStarted {
        started: String,
        command: Vec<String>,
    },
    SessionEnded {
        ended: String,
        exit_code: i32,
    },
    CapabilityDecision {
        entry: AuditEntry,
    },
    UrlOpen {
        request: UrlOpenRequest,
        success: bool,
        error: Option<String>,
    },
    Network {
        event: NetworkAuditEvent,
    },
}

#[derive(Serialize)]
struct AuditEventRecord {
    sequence: u64,
    prev_chain: Option<ContentHash>,
    leaf_hash: ContentHash,
    chain_hash: ContentHash,
    event: AuditEventPayload,
}

pub(crate) struct AuditRecorder {
    file: File,
    next_sequence: u64,
    previous_chain: Option<ContentHash>,
    leaf_hashes: Vec<ContentHash>,
}

impl AuditRecorder {
    pub(crate) fn new(session_dir: PathBuf) -> Result<Self> {
        let path = session_dir.join(AUDIT_EVENTS_FILENAME);
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| {
                NonoError::Snapshot(format!(
                    "Failed to open audit event log {}: {e}",
                    path.display()
                ))
            })?;
        Ok(Self {
            file,
            next_sequence: 0,
            previous_chain: None,
            leaf_hashes: Vec::new(),
        })
    }

    pub(crate) fn record_session_started(
        &mut self,
        started: String,
        command: Vec<String>,
    ) -> Result<()> {
        self.append_event(AuditEventPayload::SessionStarted { started, command })
    }

    pub(crate) fn record_session_ended(&mut self, ended: String, exit_code: i32) -> Result<()> {
        self.append_event(AuditEventPayload::SessionEnded { ended, exit_code })
    }

    pub(crate) fn record_capability_decision(&mut self, entry: AuditEntry) -> Result<()> {
        self.append_event(AuditEventPayload::CapabilityDecision { entry })
    }

    pub(crate) fn record_open_url(
        &mut self,
        request: UrlOpenRequest,
        success: bool,
        error: Option<String>,
    ) -> Result<()> {
        self.append_event(AuditEventPayload::UrlOpen {
            request,
            success,
            error,
        })
    }

    pub(crate) fn record_network_event(&mut self, event: NetworkAuditEvent) -> Result<()> {
        self.append_event(AuditEventPayload::Network { event })
    }

    pub(crate) fn event_count(&self) -> u64 {
        self.leaf_hashes.len() as u64
    }

    pub(crate) fn finalize(&self) -> Option<AuditIntegritySummary> {
        let chain_head = self.previous_chain?;
        let merkle_root = merkle_root(&self.leaf_hashes);
        Some(AuditIntegritySummary {
            hash_algorithm: HASH_ALGORITHM.to_string(),
            event_count: self.event_count(),
            chain_head,
            merkle_root,
        })
    }

    fn append_event(&mut self, event: AuditEventPayload) -> Result<()> {
        let event_bytes = serde_json::to_vec(&event)
            .map_err(|e| NonoError::Snapshot(format!("Failed to serialize audit event: {e}")))?;
        let leaf_hash = hash_event(&event_bytes);
        let chain_hash = hash_chain(self.previous_chain.as_ref(), &leaf_hash);
        let record = AuditEventRecord {
            sequence: self.next_sequence,
            prev_chain: self.previous_chain,
            leaf_hash,
            chain_hash,
            event,
        };
        let line = serde_json::to_vec(&record)
            .map_err(|e| NonoError::Snapshot(format!("Failed to serialize audit record: {e}")))?;
        self.file
            .write_all(&line)
            .and_then(|_| self.file.write_all(b"\n"))
            .and_then(|_| self.file.flush())
            .map_err(|e| NonoError::Snapshot(format!("Failed to append audit record: {e}")))?;
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.previous_chain = Some(chain_hash);
        self.leaf_hashes.push(leaf_hash);
        Ok(())
    }
}

fn hash_event(event_bytes: &[u8]) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(EVENT_DOMAIN);
    hasher.update(event_bytes);
    ContentHash::from_bytes(hasher.finalize().into())
}

fn hash_chain(previous: Option<&ContentHash>, leaf_hash: &ContentHash) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(CHAIN_DOMAIN);
    if let Some(prev) = previous {
        hasher.update(prev.as_bytes());
    } else {
        hasher.update([0u8; 32]);
    }
    hasher.update(leaf_hash.as_bytes());
    ContentHash::from_bytes(hasher.finalize().into())
}

fn merkle_root(leaves: &[ContentHash]) -> ContentHash {
    if leaves.is_empty() {
        return ContentHash::from_bytes(Sha256::digest(b"").into());
    }

    let mut level: Vec<[u8; 32]> = leaves.iter().map(|leaf| *leaf.as_bytes()).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let left = pair[0];
            let right = pair.get(1).copied().unwrap_or(left);
            let mut hasher = Sha256::new();
            hasher.update(left);
            hasher.update(right);
            next.push(hasher.finalize().into());
        }
        level = next;
    }
    ContentHash::from_bytes(level[0])
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn recorder_produces_integrity_summary() {
        let dir = tempfile::tempdir().unwrap();
        let mut recorder = AuditRecorder::new(dir.path().to_path_buf()).unwrap();
        recorder
            .record_session_started("2026-04-21T00:00:00Z".to_string(), vec!["pwd".to_string()])
            .unwrap();
        recorder
            .record_session_ended("2026-04-21T00:00:01Z".to_string(), 0)
            .unwrap();

        let summary = recorder.finalize().unwrap();
        assert_eq!(summary.event_count, 2);
        assert_eq!(summary.hash_algorithm, HASH_ALGORITHM);
    }

    #[test]
    fn recorder_tracks_event_count_without_needing_integrity_output() {
        let dir = tempfile::tempdir().unwrap();
        let mut recorder = AuditRecorder::new(dir.path().to_path_buf()).unwrap();
        recorder
            .record_session_started("2026-04-21T00:00:00Z".to_string(), vec!["pwd".to_string()])
            .unwrap();

        assert_eq!(recorder.event_count(), 1);
    }
}
