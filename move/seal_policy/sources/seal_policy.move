module seal_policy::policy {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    /// Error codes
    const ESessionMismatch: u64 = 0;

    /// Owned capability object - holder can decrypt the linked session bundle.
    /// This follows Seal's requirement that access control be enforced via
    /// object ownership rather than on-chain state mutations.
    public struct AccessCap has key, store {
        id: UID,
        /// Session ID that this capability grants access to
        session_id: vector<u8>,
        /// Optional label for the session (e.g., timestamp or description)
        label: vector<u8>,
    }

    /// Immutable receipt object that anchors the session data on-chain.
    /// Used for verifiable forensics and "judge-proof" accountability.
    public struct SessionReceipt has key, store {
        id: UID,
        session_id: vector<u8>,
        policy_sha256: vector<u8>,
        final_log_hash: vector<u8>,
        walrus_blob_id: vector<u8>,
        bundle_sha256: vector<u8>,
    }

    /// Create a new receipt and transfer it to the sender.
    /// This is an immutable record of the session upload.
    public entry fun create_receipt_to_sender(
        session_id: vector<u8>,
        policy_sha256: vector<u8>,
        final_log_hash: vector<u8>,
        walrus_blob_id: vector<u8>,
        bundle_sha256: vector<u8>,
        ctx: &mut TxContext
    ) {
        let receipt = SessionReceipt {
            id: object::new(ctx),
            session_id,
            policy_sha256,
            final_log_hash,
            walrus_blob_id,
            bundle_sha256,
        };
        transfer::transfer(receipt, tx_context::sender(ctx));
    }


    /// Mint an AccessCap for a specific session.
    /// This is a normal entry function with side effects (object creation).
    /// After minting, the recipient can use the cap to decrypt the session bundle.
    public entry fun mint_access_cap_to_sender(
        session_id: vector<u8>,
        label: vector<u8>,
        ctx: &mut TxContext
    ) {
        let cap = AccessCap {
            id: object::new(ctx),
            session_id,
            label,
        };
        transfer::transfer(cap, tx_context::sender(ctx));
    }

    /// The "Gate" function.
    /// Verifies that the sender owns an AccessCap matching the requested `id`.
    /// This function MUST be `public entry` to be called directly from a
    /// transaction block (as required by Seal's `seal_approve_access` pattern).
    /// It is side-effect free (read-only) but reverts if the check fails.
    public entry fun seal_approve_access(
        id: vector<u8>,
        cap: &AccessCap,
        _ctx: &TxContext
    ) {
        // Enforce that the provided id matches the capability's session_id.
        // In the demo, `id` corresponds to the encryption context (session ID).
        assert!(id == cap.session_id, ESessionMismatch);
    }

    #[test_only]
    public fun init_for_testing(ctx: &mut TxContext) {
        // No init logic needed for this module, but good for testing setup
    }
}
