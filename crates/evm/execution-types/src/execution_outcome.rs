use std::collections::HashMap;

use alloy_eips::eip7685::Requests;
use alloy_primitives::{Address, BlockNumber, Bloom, Log, B256, U256};
use reth_primitives::{logs_bloom, Account, Bytecode, Receipts, StorageEntry};
use reth_primitives_traits::{constants::ETHEREUM_CHAIN_ID, receipt::ReceiptExt, Receipt};
use reth_trie::HashedPostState;
use revm::{
    db::{states::BundleState, BundleAccount},
    primitives::{AccountInfo, ChainAddress},
};

use crate::BlockExecutionOutput;

/// Represents a changed account
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChangedAccount {
    /// The address of the account.
    pub address: Address,
    /// Account nonce.
    pub nonce: u64,
    /// Account balance.
    pub balance: U256,
}

impl ChangedAccount {
    /// Creates a new [`ChangedAccount`] with the given address and 0 balance and nonce.
    pub const fn empty(address: Address) -> Self {
        Self { address, nonce: 0, balance: U256::ZERO }
    }
}

/// Represents the outcome of block execution, including post-execution changes and reverts.
///
/// The `ExecutionOutcome` structure aggregates the state changes over an arbitrary number of
/// blocks, capturing the resulting state, receipts, and requests following the execution.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExecutionOutcome<T = reth_primitives::Receipt> {
    /// Chain id of this execution outcome.
    pub chain_id: u64,
    /// Bundle state with reverts.
    pub bundle: BundleState,
    // FIX(Cecilia): Add (chain_id, Reciepts)
    /// The collection of receipts.
    /// Outer vector stores receipts for each block sequentially.
    /// The inner vector stores receipts ordered by transaction number.
    ///
    /// If receipt is None it means it is pruned.
    pub receipts: Receipts<T>,
    /// First block of bundle state.
    pub first_block: BlockNumber,
    // FIX(Cecilia): Add (chain_id, Request)
    /// The collection of EIP-7685 requests.
    /// Outer vector stores requests for each block sequentially.
    /// The inner vector stores requests ordered by transaction number.
    ///
    /// A transaction may have zero or more requests, so the length of the inner vector is not
    /// guaranteed to be the same as the number of transactions.
    pub requests: Vec<Requests>,
}

/// Type used to initialize revms bundle state.
pub type BundleStateInit =
    HashMap<Address, (Option<Account>, Option<Account>, HashMap<B256, (U256, U256)>)>;

/// Types used inside `RevertsInit` to initialize revms reverts.
pub type AccountRevertInit = (Option<Option<Account>>, Vec<StorageEntry>);

/// Type used to initialize revms reverts.
pub type RevertsInit = HashMap<BlockNumber, HashMap<Address, AccountRevertInit>>;

impl<T: Clone> ExecutionOutcome<T> {
    /// Creates a new `ExecutionOutcome`.
    ///
    /// This constructor initializes a new `ExecutionOutcome` instance with the provided
    /// bundle state, receipts, first block number, and EIP-7685 requests.
    pub fn new(
        chain_id: u64,
        bundle: BundleState,
        receipts: Receipts<T>,
        first_block: BlockNumber,
        requests: Vec<Requests>,
    ) -> Self {
        Self { chain_id, bundle, receipts, first_block, requests }
    }

    /// Creates a new `ExecutionOutcome` from initialization parameters.
    ///
    /// This constructor initializes a new `ExecutionOutcome` instance using detailed
    /// initialization parameters.
    pub fn new_init(
        chain_id: u64,
        state_init: BundleStateInit,
        revert_init: RevertsInit,
        contracts_init: impl IntoIterator<Item = (B256, Bytecode)>,
        receipts: Receipts<T>,
        first_block: BlockNumber,
        requests: Vec<Requests>,
    ) -> Self {
        // sort reverts by block number
        let mut reverts = revert_init.into_iter().collect::<Vec<_>>();
        reverts.sort_unstable_by_key(|a| a.0);

        // initialize revm bundle
        let bundle = BundleState::new(
            state_init.into_iter().map(|(address, (original, present, storage))| {
                (
                    ChainAddress(chain_id, address),
                    original.map(Into::into),
                    present.map(Into::into),
                    storage.into_iter().map(|(k, s)| (k.into(), s)).collect(),
                )
            }),
            reverts.into_iter().map(|(_, reverts)| {
                // does not needs to be sorted, it is done when taking reverts.
                reverts.into_iter().map(|(address, (original, storage))| {
                    (
                        ChainAddress(chain_id, address),
                        original.map(|i| i.map(Into::into)),
                        storage.into_iter().map(|entry| (entry.key.into(), entry.value)),
                    )
                })
            }),
            contracts_init
                .into_iter()
                .map(|(code_hash, bytecode)| ((chain_id, code_hash), bytecode.0)),
        );

        Self { chain_id, bundle, receipts, first_block, requests }
    }

    /// Reture the `ExecutionOutcome` for a speicific chain.
    pub fn filter_chain(&self, chain_id: u64) -> Self {
        Self {
            chain_id,
            bundle: self.bundle.filter_for_chain(chain_id),
            // FIX(Cecilia): with (chain_id, Reciepts) & (chain_id, Requests)
            // we can filter out the right ones
            receipts: self.receipts.clone(),
            first_block: self.first_block,
            requests: self.requests.clone(),
        }
    }

    /// Filter the `ExecutionOutcome` for the current chain
    /// if `chain_id` is not set, default to Ethereum.
    pub fn filter_current_chain(&self) -> Self {
        Self {
            chain_id: self.chain_id,
            bundle: self.current_state(),
            // FIX(Cecilia): with (chain_id, Reciepts) & (chain_id, Requests)
            // we can filter out the right ones
            receipts: self.receipts.clone(),
            first_block: self.first_block,
            requests: self.requests.clone(),
        }
    }

    /// Return revm bundle state.
    pub const fn all_states(&self) -> &BundleState {
        &self.bundle
    }

    /// Returns mutable revm bundle state.
    pub fn all_states_mut(&mut self) -> &mut BundleState {
        &mut self.bundle
    }

    /// Reture states for a speicific chain.
    pub fn state(&self, chain_id: u64) -> BundleState {
        self.bundle.filter_for_chain(chain_id)
    }

    /// Reture states for a speicific chain.
    pub fn current_state(&self) -> BundleState {
        self.bundle.filter_for_chain(self.chain_id)
    }

    /// Set first block.
    pub fn set_first_block(&mut self, first_block: BlockNumber) {
        self.first_block = first_block;
    }

    /// Return iterator over all accounts
    pub fn accounts_iter(&self) -> impl Iterator<Item = (Address, Option<&AccountInfo>)> {
        self.bundle.state().iter().map(|(a, acc)| (a.1, acc.info.as_ref()))
    }

    /// Return iterator over all [`BundleAccount`]s in the bundle
    pub fn bundle_accounts_iter(&self) -> impl Iterator<Item = (Address, &BundleAccount)> {
        self.bundle.state().iter().map(|(a, acc)| (a.1, acc))
    }

    /// Get account if account is known.
    /// Only support the account of current chain, or default to Ethereum.
    pub fn account(&self, address: &Address) -> Option<Option<Account>> {
        self.bundle
            .account(&ChainAddress(self.chain_id, *address))
            .map(|a| a.info.clone().map(Into::into))
    }

    /// Get storage if value is known.
    ///
    /// This means that depending on status we can potentially return `U256::ZERO`.
    pub fn storage(&self, address: &Address, storage_key: U256) -> Option<U256> {
        self.bundle
            .account(&ChainAddress(self.chain_id, *address))
            .and_then(|a| a.storage_slot(storage_key))
    }

    /// Return bytecode if known.
    pub fn bytecode(&self, code_hash: &B256) -> Option<Bytecode> {
        self.bundle.bytecode(self.chain_id, code_hash).map(Bytecode)
    }

    /// Returns [`HashedPostState`] for this execution outcome.
    /// See [`HashedPostState::from_bundle_state`] for more info.
    pub fn hash_state_slow(&self) -> HashedPostState {
        HashedPostState::from_bundle_state(self.current_state().state())
    }

    /// Transform block number to the index of block.
    pub fn block_number_to_index(&self, block_number: BlockNumber) -> Option<usize> {
        if self.first_block > block_number {
            return None
        }
        let index = block_number - self.first_block;
        if index >= self.receipts.len() as u64 {
            return None
        }
        Some(index as usize)
    }

    /// Returns the receipt root for all recorded receipts.
    /// Note: this function calculated Bloom filters for every receipt and created merkle trees
    /// of receipt. This is a expensive operation.
    pub fn generic_receipts_root_slow(
        &self,
        block_number: BlockNumber,
        f: impl FnOnce(&[&T]) -> B256,
    ) -> Option<B256> {
        self.receipts.root_slow(self.block_number_to_index(block_number)?, f)
    }

    /// Returns reference to receipts.
    pub const fn receipts(&self) -> &Receipts<T> {
        &self.receipts
    }

    /// Returns mutable reference to receipts.
    pub fn receipts_mut(&mut self) -> &mut Receipts<T> {
        &mut self.receipts
    }

    /// Return all block receipts
    pub fn receipts_by_block(&self, block_number: BlockNumber) -> &[Option<T>] {
        let Some(index) = self.block_number_to_index(block_number) else { return &[] };
        &self.receipts[index]
    }

    /// Is execution outcome empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Number of blocks in the execution outcome.
    pub fn len(&self) -> usize {
        self.receipts.len()
    }

    /// Return first block of the execution outcome
    pub const fn first_block(&self) -> BlockNumber {
        self.first_block
    }

    /// Revert the state to the given block number.
    ///
    /// Returns false if the block number is not in the bundle state.
    ///
    /// # Note
    ///
    /// The provided block number will stay inside the bundle state.
    pub fn revert_to(&mut self, block_number: BlockNumber) -> bool {
        let Some(index) = self.block_number_to_index(block_number) else { return false };

        // +1 is for number of blocks that we have as index is included.
        let new_len = index + 1;
        let rm_trx: usize = self.len() - new_len;

        // remove receipts
        self.receipts.truncate(new_len);
        // remove requests
        self.requests.truncate(new_len);
        // Revert last n reverts.
        self.bundle.revert(rm_trx);

        true
    }

    /// Splits the block range state at a given block number.
    /// Returns two split states ([..at], [at..]).
    /// The plain state of the 2nd bundle state will contain extra changes
    /// that were made in state transitions belonging to the lower state.
    ///
    /// # Panics
    ///
    /// If the target block number is not included in the state block range.
    pub fn split_at(self, at: BlockNumber) -> (Option<Self>, Self)
    where
        T: Clone,
    {
        if at == self.first_block {
            return (None, self)
        }

        let (mut lower_state, mut higher_state) = (self.clone(), self);

        // Revert lower state to [..at].
        lower_state.revert_to(at.checked_sub(1).unwrap());

        // Truncate higher state to [at..].
        let at_idx = higher_state.block_number_to_index(at).unwrap();
        higher_state.receipts = higher_state.receipts.split_off(at_idx).into();
        // Ensure that there are enough requests to truncate.
        // Sometimes we just have receipts and no requests.
        if at_idx < higher_state.requests.len() {
            higher_state.requests = higher_state.requests.split_off(at_idx);
        }
        higher_state.bundle.take_n_reverts(at_idx);
        higher_state.first_block = at;

        (Some(lower_state), higher_state)
    }

    /// Extend one state from another
    ///
    /// For state this is very sensitive operation and should be used only when
    /// we know that other state was build on top of this one.
    /// In most cases this would be true.
    pub fn extend(&mut self, other: Self) {
        self.bundle.extend(other.bundle);
        self.receipts.extend(other.receipts.receipt_vec);
        self.requests.extend(other.requests);
    }

    /// Prepends present the state with the given `BundleState`.
    /// It adds changes from the given state but does not override any existing changes.
    ///
    /// Reverts  and receipts are not updated.
    pub fn prepend_state(&mut self, mut other: BundleState) {
        let other_len = other.reverts.len();
        // take this bundle
        let this_bundle = std::mem::take(&mut self.bundle);
        // extend other bundle with this
        other.extend(this_bundle);
        // discard other reverts
        other.take_n_reverts(other_len);
        // swap bundles
        std::mem::swap(&mut self.bundle, &mut other)
    }

    /// Create a new instance with updated receipts.
    pub fn with_receipts(mut self, receipts: Receipts<T>) -> Self {
        self.receipts = receipts;
        self
    }

    /// Create a new instance with updated requests.
    pub fn with_requests(mut self, requests: Vec<Requests>) -> Self {
        self.requests = requests;
        self
    }

    /// Returns an iterator over all changed accounts from the `ExecutionOutcome`.
    ///
    /// This method filters the accounts to return only those that have undergone changes
    /// and maps them into `ChangedAccount` instances, which include the address, nonce, and
    /// balance.
    pub fn changed_accounts(&self) -> impl Iterator<Item = ChangedAccount> + '_ {
        self.accounts_iter().filter_map(|(addr, acc)| acc.map(|acc| (addr, acc))).map(
            |(address, acc)| ChangedAccount { address, nonce: acc.nonce, balance: acc.balance },
        )
    }
}

impl<T: Receipt> ExecutionOutcome<T> {
    /// Returns an iterator over all block logs.
    pub fn logs(&self, block_number: BlockNumber) -> Option<impl Iterator<Item = &Log>> {
        let index = self.block_number_to_index(block_number)?;
        Some(self.receipts[index].iter().filter_map(|r| Some(r.as_ref()?.logs().iter())).flatten())
    }

    /// Return blocks logs bloom
    pub fn block_logs_bloom(&self, block_number: BlockNumber) -> Option<Bloom> {
        Some(logs_bloom(self.logs(block_number)?))
    }

    /// Returns the receipt root for all recorded receipts.
    /// Note: this function calculated Bloom filters for every receipt and created merkle trees
    /// of receipt. This is a expensive operation.
    pub fn receipts_root_slow(&self, _block_number: BlockNumber) -> Option<B256>
    where
        T: ReceiptExt,
    {
        #[cfg(feature = "optimism")]
        panic!("This should not be called in optimism mode. Use `optimism_receipts_root_slow` instead.");
        #[cfg(not(feature = "optimism"))]
        self.receipts.root_slow(self.block_number_to_index(_block_number)?, T::receipts_root)
    }
}

impl<T> From<(BlockExecutionOutput<T>, u64, BlockNumber)> for ExecutionOutcome<T> {
    fn from(value: (BlockExecutionOutput<T>, u64, BlockNumber)) -> Self {
        Self {
            chain_id: value.1,
            bundle: value.0.state,
            receipts: Receipts::from(value.0.receipts),
            first_block: value.2,
            requests: vec![value.0.requests],
        }
    }
}

impl<T> From<(BlockExecutionOutput<T>, BlockNumber)> for ExecutionOutcome<T> {
    fn from(value: (BlockExecutionOutput<T>, BlockNumber)) -> Self {
        Self {
            chain_id: ETHEREUM_CHAIN_ID,
            bundle: value.0.state,
            receipts: Receipts::from(value.0.receipts),
            first_block: value.1,
            requests: vec![value.0.requests],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(feature = "optimism"))]
    use alloy_primitives::bytes;
    use alloy_primitives::{Address, B256};
    use reth_primitives::Receipts;
    #[cfg(not(feature = "optimism"))]
    use reth_primitives::{LogData, TxType};

    const CHAIN_ID: u64 = 1u64;

    #[test]
    #[cfg(not(feature = "optimism"))]
    fn test_initialisation() {
        // Create a new BundleState object with initial data
        let bundle = BundleState::new(
            vec![(
                ChainAddress(CHAIN_ID, Address::new([2; 20])),
                None,
                Some(AccountInfo::default()),
                HashMap::default(),
            )],
            vec![vec![(ChainAddress(CHAIN_ID, Address::new([2; 20])), None, vec![])]],
            vec![],
        );

        // Create a Receipts object with a vector of receipt vectors
        let receipts = Receipts {
            receipt_vec: vec![vec![Some(reth_primitives::Receipt {
                tx_type: TxType::Legacy,
                cumulative_gas_used: 46913,
                logs: vec![],
                success: true,
            })]],
        };

        // Create a Requests object with a vector of requests
        let requests = vec![Requests::new(vec![bytes!("dead"), bytes!("beef"), bytes!("beebee")])];

        // Define the first block number
        let first_block = 123;

        // Create a ExecutionOutcome object with the created bundle, receipts, requests, and
        // first_block
        let exec_res = ExecutionOutcome {
            chain_id: CHAIN_ID,
            bundle: bundle.clone(),
            receipts: receipts.clone(),
            requests: requests.clone(),
            first_block,
        };

        // Assert that creating a new ExecutionOutcome using the constructor matches exec_res
        assert_eq!(
            ExecutionOutcome::new(
                CHAIN_ID,
                bundle,
                receipts.clone(),
                first_block,
                requests.clone()
            ),
            exec_res
        );

        // Create a BundleStateInit object and insert initial data
        let mut state_init: BundleStateInit = HashMap::default();
        state_init
            .insert(Address::new([2; 20]), (None, Some(Account::default()), HashMap::default()));

        // Create a HashMap for account reverts and insert initial data
        let mut revert_inner: HashMap<Address, AccountRevertInit> = HashMap::default();
        revert_inner.insert(Address::new([2; 20]), (None, vec![]));

        // Create a RevertsInit object and insert the revert_inner data
        let mut revert_init: RevertsInit = HashMap::default();
        revert_init.insert(123, revert_inner);

        // Assert that creating a new ExecutionOutcome using the new_init method matches
        // exec_res
        assert_eq!(
            ExecutionOutcome::new_init(
                CHAIN_ID,
                state_init,
                revert_init,
                vec![],
                receipts,
                first_block,
                requests,
            ),
            exec_res
        );
    }

    #[test]
    #[cfg(not(feature = "optimism"))]
    fn test_block_number_to_index() {
        // Create a Receipts object with a vector of receipt vectors
        let receipts = Receipts {
            receipt_vec: vec![vec![Some(reth_primitives::Receipt {
                tx_type: TxType::Legacy,
                cumulative_gas_used: 46913,
                logs: vec![],
                success: true,
            })]],
        };

        // Define the first block number
        let first_block = 123;

        // Create a ExecutionOutcome object with the created bundle, receipts, requests, and
        // first_block
        let exec_res = ExecutionOutcome {
            chain_id: CHAIN_ID,
            bundle: Default::default(),
            receipts,
            requests: vec![],
            first_block,
        };

        // Test before the first block
        assert_eq!(exec_res.block_number_to_index(12), None);

        // Test after after the first block but index larger than receipts length
        assert_eq!(exec_res.block_number_to_index(133), None);

        // Test after the first block
        assert_eq!(exec_res.block_number_to_index(123), Some(0));
    }

    #[test]
    #[cfg(not(feature = "optimism"))]
    fn test_get_logs() {
        // Create a Receipts object with a vector of receipt vectors
        let receipts = Receipts {
            receipt_vec: vec![vec![Some(reth_primitives::Receipt {
                tx_type: TxType::Legacy,
                cumulative_gas_used: 46913,
                logs: vec![Log::<LogData>::default()],
                success: true,
            })]],
        };

        // Define the first block number
        let first_block = 123;

        // Create a ExecutionOutcome object with the created bundle, receipts, requests, and
        // first_block
        let exec_res = ExecutionOutcome {
            chain_id: CHAIN_ID,
            bundle: Default::default(),
            receipts,
            requests: vec![],
            first_block,
        };

        // Get logs for block number 123
        let logs: Vec<&Log> = exec_res.logs(123).unwrap().collect();

        // Assert that the logs match the expected logs
        assert_eq!(logs, vec![&Log::<LogData>::default()]);
    }

    #[test]
    #[cfg(not(feature = "optimism"))]
    fn test_receipts_by_block() {
        // Create a Receipts object with a vector of receipt vectors
        let receipts = Receipts {
            receipt_vec: vec![vec![Some(reth_primitives::Receipt {
                tx_type: TxType::Legacy,
                cumulative_gas_used: 46913,
                logs: vec![Log::<LogData>::default()],
                success: true,
            })]],
        };

        // Define the first block number
        let first_block = 123;

        // Create a ExecutionOutcome object with the created bundle, receipts, requests, and
        // first_block
        let exec_res = ExecutionOutcome {
            chain_id: CHAIN_ID,
            bundle: Default::default(), // Default value for bundle
            receipts,                   // Include the created receipts
            requests: vec![],           // Empty vector for requests
            first_block,                // Set the first block number
        };

        // Get receipts for block number 123 and convert the result into a vector
        let receipts_by_block: Vec<_> = exec_res.receipts_by_block(123).iter().collect();

        // Assert that the receipts for block number 123 match the expected receipts
        assert_eq!(
            receipts_by_block,
            vec![&Some(reth_primitives::Receipt {
                tx_type: TxType::Legacy,
                cumulative_gas_used: 46913,
                logs: vec![Log::<LogData>::default()],
                success: true,
            })]
        );
    }

    #[test]
    #[cfg(not(feature = "optimism"))]
    fn test_receipts_len() {
        // Create a Receipts object with a vector of receipt vectors
        let receipts = Receipts {
            receipt_vec: vec![vec![Some(reth_primitives::Receipt {
                tx_type: TxType::Legacy,
                cumulative_gas_used: 46913,
                logs: vec![Log::<LogData>::default()],
                success: true,
            })]],
        };

        // Create an empty Receipts object
        let receipts_empty: Receipts = Receipts { receipt_vec: vec![] };

        // Define the first block number
        let first_block = 123;

        // Create a ExecutionOutcome object with the created bundle, receipts, requests, and
        // first_block
        let exec_res = ExecutionOutcome {
            chain_id: CHAIN_ID,
            bundle: Default::default(), // Default value for bundle
            receipts,                   // Include the created receipts
            requests: vec![],           // Empty vector for requests
            first_block,                // Set the first block number
        };

        // Assert that the length of receipts in exec_res is 1
        assert_eq!(exec_res.len(), 1);

        // Assert that exec_res is not empty
        assert!(!exec_res.is_empty());

        // Create a ExecutionOutcome object with an empty Receipts object
        let exec_res_empty_receipts = ExecutionOutcome {
            chain_id: CHAIN_ID,
            bundle: Default::default(), // Default value for bundle
            receipts: receipts_empty,   // Include the empty receipts
            requests: vec![],           // Empty vector for requests
            first_block,                // Set the first block number
        };

        // Assert that the length of receipts in exec_res_empty_receipts is 0
        assert_eq!(exec_res_empty_receipts.len(), 0);

        // Assert that exec_res_empty_receipts is empty
        assert!(exec_res_empty_receipts.is_empty());
    }

    #[test]
    #[cfg(not(feature = "optimism"))]
    fn test_revert_to() {
        // Create a random receipt object
        let receipt = reth_primitives::Receipt {
            tx_type: TxType::Legacy,
            cumulative_gas_used: 46913,
            logs: vec![],
            success: true,
        };

        // Create a Receipts object with a vector of receipt vectors
        let receipts = Receipts {
            receipt_vec: vec![vec![Some(receipt.clone())], vec![Some(receipt.clone())]],
        };

        // Define the first block number
        let first_block = 123;

        // Create a request.
        let request = bytes!("deadbeef");

        // Create a vector of Requests containing the request.
        let requests =
            vec![Requests::new(vec![request.clone()]), Requests::new(vec![request.clone()])];

        // Create a ExecutionOutcome object with the created bundle, receipts, requests, and
        // first_block
        let mut exec_res = ExecutionOutcome {
            chain_id: CHAIN_ID,
            bundle: Default::default(),
            receipts,
            requests,
            first_block,
        };

        // Assert that the revert_to method returns true when reverting to the initial block number.
        assert!(exec_res.revert_to(123));

        // Assert that the receipts are properly cut after reverting to the initial block number.
        assert_eq!(exec_res.receipts, Receipts { receipt_vec: vec![vec![Some(receipt)]] });

        // Assert that the requests are properly cut after reverting to the initial block number.
        assert_eq!(exec_res.requests, vec![Requests::new(vec![request])]);

        // Assert that the revert_to method returns false when attempting to revert to a block
        // number greater than the initial block number.
        assert!(!exec_res.revert_to(133));

        // Assert that the revert_to method returns false when attempting to revert to a block
        // number less than the initial block number.
        assert!(!exec_res.revert_to(10));
    }

    #[test]
    #[cfg(not(feature = "optimism"))]
    fn test_extend_execution_outcome() {
        // Create a Receipt object with specific attributes.
        let receipt = reth_primitives::Receipt {
            tx_type: TxType::Legacy,
            cumulative_gas_used: 46913,
            logs: vec![],
            success: true,
        };

        // Create a Receipts object containing the receipt.
        let receipts = Receipts { receipt_vec: vec![vec![Some(receipt.clone())]] };

        // Create a request.
        let request = bytes!("deadbeef");

        // Create a vector of Requests containing the request.
        let requests = vec![Requests::new(vec![request.clone()])];

        // Define the initial block number.
        let first_block = 123;

        // Create an ExecutionOutcome object.
        let mut exec_res = ExecutionOutcome {
            chain_id: CHAIN_ID,
            bundle: Default::default(),
            receipts,
            requests,
            first_block,
        };

        // Extend the ExecutionOutcome object by itself.
        exec_res.extend(exec_res.clone());

        // Assert the extended ExecutionOutcome matches the expected outcome.
        assert_eq!(
            exec_res,
            ExecutionOutcome {
                chain_id: CHAIN_ID,
                bundle: Default::default(),
                receipts: Receipts {
                    receipt_vec: vec![vec![Some(receipt.clone())], vec![Some(receipt)]]
                },
                requests: vec![Requests::new(vec![request.clone()]), Requests::new(vec![request])],
                first_block: 123,
            }
        );
    }

    #[test]
    #[cfg(not(feature = "optimism"))]
    fn test_split_at_execution_outcome() {
        // Create a random receipt object
        let receipt = reth_primitives::Receipt {
            tx_type: TxType::Legacy,
            cumulative_gas_used: 46913,
            logs: vec![],
            success: true,
        };

        // Create a Receipts object with a vector of receipt vectors
        let receipts = Receipts {
            receipt_vec: vec![
                vec![Some(receipt.clone())],
                vec![Some(receipt.clone())],
                vec![Some(receipt.clone())],
            ],
        };

        // Define the first block number
        let first_block = 123;

        // Create a request.
        let request = bytes!("deadbeef");

        // Create a vector of Requests containing the request.
        let requests = vec![
            Requests::new(vec![request.clone()]),
            Requests::new(vec![request.clone()]),
            Requests::new(vec![request.clone()]),
        ];

        // Create a ExecutionOutcome object with the created bundle, receipts, requests, and
        // first_block
        let exec_res = ExecutionOutcome {
            chain_id: CHAIN_ID,
            bundle: Default::default(),
            receipts,
            requests,
            first_block,
        };

        // Split the ExecutionOutcome at block number 124
        let result = exec_res.clone().split_at(124);

        // Define the expected lower ExecutionOutcome after splitting
        let lower_execution_outcome = ExecutionOutcome {
            chain_id: CHAIN_ID,
            bundle: Default::default(),
            receipts: Receipts { receipt_vec: vec![vec![Some(receipt.clone())]] },
            requests: vec![Requests::new(vec![request.clone()])],
            first_block,
        };

        // Define the expected higher ExecutionOutcome after splitting
        let higher_execution_outcome = ExecutionOutcome {
            chain_id: CHAIN_ID,
            bundle: Default::default(),
            receipts: Receipts {
                receipt_vec: vec![vec![Some(receipt.clone())], vec![Some(receipt)]],
            },
            requests: vec![Requests::new(vec![request.clone()]), Requests::new(vec![request])],
            first_block: 124,
        };

        // Assert that the split result matches the expected lower and higher outcomes
        assert_eq!(result.0, Some(lower_execution_outcome));
        assert_eq!(result.1, higher_execution_outcome);

        // Assert that splitting at the first block number returns None for the lower outcome
        assert_eq!(exec_res.clone().split_at(123), (None, exec_res));
    }

    #[test]
    fn test_changed_accounts() {
        // Set up some sample accounts
        let address1 = Address::random();
        let address2 = Address::random();
        let address3 = Address::random();

        // Set up account info with some changes
        let account_info1 =
            AccountInfo { nonce: 1, balance: U256::from(100), code_hash: B256::ZERO, code: None };
        let account_info2 =
            AccountInfo { nonce: 2, balance: U256::from(200), code_hash: B256::ZERO, code: None };

        // Set up the bundle state with these accounts
        let mut bundle_state = BundleState::default();
        bundle_state.state.insert(
            ChainAddress(CHAIN_ID, address1),
            BundleAccount {
                info: Some(account_info1),
                storage: Default::default(),
                original_info: Default::default(),
                status: Default::default(),
            },
        );
        bundle_state.state.insert(
            ChainAddress(CHAIN_ID, address2),
            BundleAccount {
                info: Some(account_info2),
                storage: Default::default(),
                original_info: Default::default(),
                status: Default::default(),
            },
        );

        // Unchanged account
        bundle_state.state.insert(
            ChainAddress(CHAIN_ID, address3),
            BundleAccount {
                info: None,
                storage: Default::default(),
                original_info: Default::default(),
                status: Default::default(),
            },
        );

        let execution_outcome: ExecutionOutcome = ExecutionOutcome {
            chain_id: CHAIN_ID,
            bundle: bundle_state,
            receipts: Receipts::default(),
            first_block: 0,
            requests: vec![],
        };

        // Get the changed accounts
        let changed_accounts: Vec<ChangedAccount> = execution_outcome.changed_accounts().collect();

        // Assert that the changed accounts match the expected ones
        assert_eq!(changed_accounts.len(), 2);

        assert!(changed_accounts.contains(&ChangedAccount {
            address: address1,
            nonce: 1,
            balance: U256::from(100)
        }));

        assert!(changed_accounts.contains(&ChangedAccount {
            address: address2,
            nonce: 2,
            balance: U256::from(200)
        }));
    }
}
