//! Local commit creation (PLAN.md §6, "Commit"): encrypt the staged working set under the
//! environment DEK, build and store the blob/tree/commit objects, and sign the commit with
//! the author's Ed25519 key. Entirely offline and client-side.

use wonton_crypto::{encrypt_value, sign, Dek, UnlockedIdentity};
use wonton_objects::{Blob, Commit, CommitFields, Hash, LocalObjectStore, Tree};

use crate::{author_id_from_identity, current_unix_seconds, VcsError, WorkingSet};

/// Create a signed, content-addressed commit from a staged [`WorkingSet`] and return its
/// [`Hash`].
///
/// Steps (PLAN.md §6):
/// 1. Encrypt every staged value under `dek` with a fresh random nonce ([`encrypt_value`]),
///    wrap each as a [`Blob`], hash it, and `put` it into `store`.
/// 2. Build a [`Tree`] mapping each (plaintext) key name to its blob hash; hash and `put` it.
/// 3. Build [`CommitFields`] — the new tree hash, `parent`'s hash as `parent_hashes` (`None`
///    ⇒ a 0-parent root commit), the author id derived from `identity`
///    ([`author_id_from_identity`] — a Phase-2 placeholder), the current unix timestamp, and
///    `message`.
/// 4. Sign `fields.signing_bytes()` with `identity`'s Ed25519 key, wrap into a [`Commit`],
///    hash and `put` it, and return the commit hash.
///
/// The DEK, identity, and plaintext never leave the client; only ciphertext objects are
/// stored (PLAN.md §2).
pub fn commit(
    store: &LocalObjectStore,
    dek: &Dek,
    identity: &UnlockedIdentity,
    parent: Option<Hash>,
    working_set: &WorkingSet,
    message: impl Into<String>,
) -> Result<Hash, VcsError> {
    // 1. Encrypt each staged value and store it as a blob; record key -> blob_hash.
    let mut tree = Tree::new();
    for (key, plaintext) in working_set.iter() {
        let encrypted = encrypt_value(dek, plaintext);
        // Bridge crypto's `EncryptedValue` to objects' structurally-identical `Blob`.
        let blob = Blob::new(encrypted.nonce, encrypted.ciphertext);
        let blob_bytes = blob.to_bytes()?;
        let blob_hash = Hash::of(&blob_bytes);
        store.put(&blob_hash, &blob_bytes)?;
        tree.insert(key.clone(), blob_hash);
    }

    // 2. Store the tree.
    let tree_bytes = tree.to_bytes()?;
    let tree_hash = Hash::of(&tree_bytes);
    store.put(&tree_hash, &tree_bytes)?;

    // 3. Assemble the signable fields. `parent` is 0-or-1 hashes in Phase 2 (root or linear);
    //    merge commits with 2+ parents are a Phase 5 concern.
    let fields = CommitFields {
        tree_hash,
        parent_hashes: parent.into_iter().collect(),
        author_id: author_id_from_identity(identity.public()),
        timestamp: current_unix_seconds(),
        message: message.into(),
    };

    // 4. Sign the canonical field bytes, wrap, store, return.
    let signature = sign(identity, &fields.signing_bytes()?);
    let commit = Commit {
        fields,
        signature: signature.to_vec(),
    };
    let commit_bytes = commit.to_bytes()?;
    let commit_hash = Hash::of(&commit_bytes);
    store.put(&commit_hash, &commit_bytes)?;
    Ok(commit_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{new_dek, new_identity, temp_store};
    use crate::{decrypt_blob, load_commit, load_tree_of_commit};

    #[test]
    fn root_commit_stores_all_objects_and_decrypts_back() {
        let (_dir, store) = temp_store();
        let identity = new_identity(b"pass");
        let dek = new_dek();

        let mut ws = WorkingSet::new();
        ws.set("DATABASE_URL", b"postgres://user:pw@host/db".to_vec());
        ws.set("API_KEY", b"sk-live-123".to_vec());

        let commit_hash = commit(&store, &dek, &identity, None, &ws, "initial").unwrap();

        // Commit object exists and is a 0-parent root pointing at a stored tree.
        let c = load_commit(&store, &commit_hash).unwrap();
        assert!(c.fields.parent_hashes.is_empty());
        assert_eq!(c.fields.message, "initial");
        assert_eq!(
            c.fields.author_id,
            author_id_from_identity(identity.public())
        );

        // The tree has both keys, and each blob decrypts back to the staged plaintext.
        let tree = load_tree_of_commit(&store, &commit_hash).unwrap();
        assert_eq!(tree.entries.len(), 2);
        let db = decrypt_blob(&store, &dek, tree.entries.get("DATABASE_URL").unwrap()).unwrap();
        assert_eq!(db, b"postgres://user:pw@host/db");
        let api = decrypt_blob(&store, &dek, tree.entries.get("API_KEY").unwrap()).unwrap();
        assert_eq!(api, b"sk-live-123");
    }

    #[test]
    fn empty_working_set_commits_an_empty_tree() {
        let (_dir, store) = temp_store();
        let identity = new_identity(b"pass");
        let dek = new_dek();

        let commit_hash = commit(&store, &dek, &identity, None, &WorkingSet::new(), "empty").unwrap();
        let tree = load_tree_of_commit(&store, &commit_hash).unwrap();
        assert!(tree.entries.is_empty());
    }

    #[test]
    fn second_commit_links_to_parent() {
        let (_dir, store) = temp_store();
        let identity = new_identity(b"pass");
        let dek = new_dek();

        let mut ws = WorkingSet::new();
        ws.set("K", b"v1".to_vec());
        let root = commit(&store, &dek, &identity, None, &ws, "root").unwrap();

        ws.set("K", b"v2".to_vec());
        let child = commit(&store, &dek, &identity, Some(root), &ws, "child").unwrap();

        let c = load_commit(&store, &child).unwrap();
        assert_eq!(c.fields.parent_hashes, vec![root]);
    }
}
