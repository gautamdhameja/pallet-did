#![cfg_attr(not(feature = "std"), no_std)]

/// Edit this file to define custom logic or remove it if it is not needed.
/// Learn more about FRAME and the core library of Substrate FRAME pallets:
/// <https://substrate.dev/docs/en/knowledgebase/runtime/frame>
pub use pallet::*;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[frame_support::pallet]
pub mod pallet {
    use codec::{Decode, Encode}; 
    use frame_support::pallet_prelude::IsType;
    use frame_support::pallet_prelude::OptionQuery;
    use frame_support::pallet_prelude::ValueQuery; 
    use frame_support::Blake2_128Concat;
    use frame_support::{
        dispatch::{DispatchResult, DispatchResultWithPostInfo},
        pallet_prelude::*,
    };
    use frame_system::pallet_prelude::OriginFor;
    use frame_system::pallet_prelude::*;
    use frame_system::{ ensure_signed};
    use sp_io::hashing::blake2_256;
    use sp_runtime::traits::{IdentifyAccount, Verify}; 
    use sp_std::{prelude::*, vec::Vec};
    /// Attributes or properties that make an identity.
    #[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Default, RuntimeDebug)]
    pub struct Attribute<BlockNumber, Moment> {
        pub name: Vec<u8>,
        pub value: Vec<u8>,
        pub validity: BlockNumber,
        pub creation: Moment,
        pub nonce: u64,
    }

    pub type AttributedId<BlockNumber, Moment> = (Attribute<BlockNumber, Moment>, [u8; 32]);

    /// Off-chain signed transaction.
    #[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Default, RuntimeDebug)]
    pub struct AttributeTransaction<Signature, AccountId> {
        pub signature: Signature,
        pub name: Vec<u8>,
        pub value: Vec<u8>,
        pub validity: u32,
        pub signer: AccountId,
        pub identity: AccountId,
    }

    /// Configure the pallet by specifying the parameters and types on which it depends.
    #[pallet::config]
    pub trait Config: frame_system::Config + pallet_timestamp::Config {
        /// Because this pallet emits events, it depends on the runtime's definition of an event.
        type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
        type Public: IdentifyAccount<AccountId = Self::AccountId>;
        type Signature: Verify<Signer = Self::Public> + Member + Decode + Encode;
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    pub struct Pallet<T>(_);

    #[pallet::storage]
    #[pallet::getter(fn delegate_of)]
    pub(super) type DelegateOf<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        (T::AccountId, Vec<u8>, T::AccountId),
        T::BlockNumber,
        OptionQuery,
    >;

    #[pallet::storage]
    #[pallet::getter(fn attribute_of)]
    pub(super) type AttributeOf<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        (T::AccountId, [u8; 32]),
        Attribute<T::BlockNumber, T::Moment>,
        ValueQuery,
    >;

    #[pallet::storage]
    #[pallet::getter(fn nonce_of)]
    pub(super) type AttributeNonce<T: Config> =
        StorageMap<_, Blake2_128Concat, (T::AccountId, Vec<u8>), u64, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn owner_of)]
    pub(super) type OwnerOf<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, T::AccountId, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn updated_by)]
    pub(super) type UpdatedBy<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        (T::AccountId, T::BlockNumber, T::Moment),
        ValueQuery,
    >;

    #[pallet::event]
    #[pallet::metadata(T::AccountId = "AccountId")]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Event documentation should end with an array that provides descriptive names for event
        /// parameters. [something, who]
        SomethingStored(u32, T::AccountId),
        OwnerChanged(T::AccountId, T::AccountId, T::AccountId, T::BlockNumber),
        DelegateAdded(T::AccountId, Vec<u8>, T::AccountId, Option<T::BlockNumber>),
        DelegateRevoked(T::AccountId, Vec<u8>, T::AccountId),
        AttributeAdded(T::AccountId, Vec<u8>, Option<T::BlockNumber>),
        AttributeRevoked(T::AccountId, Vec<u8>, T::BlockNumber),
        AttributeDeleted(T::AccountId, Vec<u8>, T::BlockNumber),
        AttributeTransactionExecuted(AttributeTransaction<T::Signature, T::AccountId>),
    }
   
    // Errors inform users that something went wrong.
    #[pallet::error]
    pub enum Error<T> {
        NoneValue,
        StorageOverflow,
        NotOwner,
        InvalidDelegate,
        BadSignature,
        AttributeCreationFailed,
        AttributeResetFailed,
        AttributeRemovalFailed,
        InvalidAttribute,
        Overflow,
        BadTransaction,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

    // Dispatchable functions allows users to interact with the pallet and invoke state changes.
    // These functions materialize as "extrinsics", which are often compared to transactions.
    // Dispatchable functions must be annotated with a weight and must return a DispatchResult.
    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::weight(10_000 + T::DbWeight::get().writes(1))]
        pub fn change_owner(
            origin: OriginFor<T>,
            identity: T::AccountId,
            new_owner: T::AccountId,
        ) -> DispatchResultWithPostInfo {
            let who = ensure_signed(origin)?;
            Self::is_owner(&identity, &who)?;

            let now_timestamp = <pallet_timestamp::Pallet<T>>::now();
            let now_block_number = <frame_system::Pallet<T>>::block_number();

            if <OwnerOf<T>>::contains_key(&identity) {
                // Update to new owner.
                <OwnerOf<T>>::mutate(&identity, |o| *o = Some(new_owner.clone()));
            } else {
                // Add to new owner.
                <OwnerOf<T>>::insert(&identity, &new_owner);
            }
            // Save the update time and block.
            <UpdatedBy<T>>::insert(&identity, (&who, &now_block_number, &now_timestamp));
            Self::deposit_event(Event::<T>::OwnerChanged(
                identity,
                who,
                new_owner,
                now_block_number,
            ));
            Ok(().into())
        }
		#[pallet::weight(0)]
		 pub fn add_delegate(
            origin:OriginFor<T>,
            identity: T::AccountId,
            delegate: T::AccountId,
            delegate_type: Vec<u8>,
            valid_for: Option<T::BlockNumber>,
        ) -> DispatchResultWithPostInfo {
            let who = ensure_signed(origin)?;
            ensure!(delegate_type.len() <= 64, Error::<T>::InvalidDelegate);

            Self::create_delegate( &who, &identity, &delegate, &delegate_type, valid_for)?;

            let now_timestamp = <pallet_timestamp::Pallet<T>>::now();
            let now_block_number = <frame_system::Pallet<T>>::block_number();
            <UpdatedBy<T>>::insert(&identity, (who, now_block_number, now_timestamp));

            Self::deposit_event(Event::DelegateAdded(
                identity,
                delegate_type,
                delegate,
                valid_for,
            ));
            Ok(().into())
        }

		#[pallet::weight(0)]
        pub fn revoke_delegate(
            origin: OriginFor<T>,
            identity: T::AccountId,
            delegate_type: Vec<u8>,
            delegate: T::AccountId,
        ) -> DispatchResultWithPostInfo {
            let who = ensure_signed(origin)?;
            Self::is_owner(&identity, &who)?;
            Self::valid_listed_delegate(&identity, &delegate_type, &delegate)?;
            ensure!(delegate_type.len() <= 64, Error::<T>::InvalidDelegate);

            let now_timestamp = <pallet_timestamp::Pallet<T>>::now();
            let now_block_number = <frame_system::Pallet<T>>::block_number();

            // Update only the validity period to revoke the delegate.
            <DelegateOf<T>>::mutate(
                (&identity, &delegate_type, &delegate), |b| *b = Some(now_block_number),
            );
            <UpdatedBy<T>>::insert(&identity, (who, now_block_number, now_timestamp));
            Self::deposit_event(Event::DelegateRevoked(identity, delegate_type, delegate));
            Ok(().into())
        }

        /// Creates a new attribute as part of an identity.
        /// Sets its expiration period.
        #[pallet::weight(0)]
        pub fn add_attribute(
            origin: OriginFor<T>,
            identity: T::AccountId,
            name: Vec<u8>,
            value: Vec<u8>,
            valid_for: Option<T::BlockNumber>,
        ) -> DispatchResultWithPostInfo {
            let who = ensure_signed(origin)?;
            ensure!(name.len() <= 64, Error::<T>::AttributeCreationFailed);

            Self::create_attribute(&who, &identity, &name, &value, valid_for)?;
            Self::deposit_event(Event::AttributeAdded(identity, name, valid_for));
            Ok(().into())
        }

        /// Revokes an attribute/property from an identity.
        /// Sets its expiration period to the actual block number.
        #[pallet::weight(0)]
        pub fn revoke_attribute(origin: OriginFor<T>, identity: T::AccountId, name: Vec<u8>) -> DispatchResultWithPostInfo {
            let who = ensure_signed(origin)?;
            ensure!(name.len() <= 64, Error::<T>::AttributeRemovalFailed);

            Self::reset_attribute(who, &identity, &name)?;
            Self::deposit_event(Event::AttributeRevoked(
                identity,
                name,
                <frame_system::Pallet<T>>::block_number(),
            ));
            Ok(().into())
        }

        /// Removes an attribute from an identity. This attribute/property becomes unavailable.
        #[pallet::weight(0)]
        pub fn delete_attribute(origin: OriginFor<T>, identity: T::AccountId, name: Vec<u8>) -> DispatchResultWithPostInfo {
            let who = ensure_signed(origin)?;
            Self::is_owner(&identity, &who)?;
            ensure!(name.len() <= 64, Error::<T>::AttributeRemovalFailed);

            let now_block_number = <frame_system::Pallet<T>>::block_number();
            let result = Self::attribute_and_id(&identity, &name);

            match result {
                Some((_, id)) => <AttributeOf<T>>::remove((&identity, &id)),
                None => return Err(Error::<T>::AttributeRemovalFailed.into()),
            }

            <UpdatedBy<T>>::insert(
                &identity,
                (&who, &now_block_number, <pallet_timestamp::Pallet<T>>::now()),
            );

            Self::deposit_event(Event::AttributeDeleted(identity, name, now_block_number));
            Ok(().into())
        }

        /// Executes off-chain signed transaction.
        #[pallet::weight(0)]
        pub fn execute(
            origin: OriginFor<T>,
            transaction: AttributeTransaction<T::Signature, T::AccountId>,
        ) -> DispatchResultWithPostInfo {
            let who = ensure_signed(origin)?;

            let mut encoded = transaction.name.encode();
            encoded.extend(transaction.value.encode());
            encoded.extend(transaction.validity.encode());
            encoded.extend(transaction.identity.encode());

            // Execute the storage update if the signer is valid.
            Self::signed_attribute(who, &encoded, &transaction)?;
            Self::deposit_event(Event::AttributeTransactionExecuted(transaction));
            Ok(().into())
        }
        /// An example dispatchable that may throw a custom error.
        #[pallet::weight(10_000 + T::DbWeight::get().reads_writes(1,1))]
        pub fn cause_error(origin: OriginFor<T>) -> DispatchResultWithPostInfo {
            let _who = ensure_signed(origin)?;

            Ok(().into())
        }
    }
    #[allow(dead_code)]
    impl<T: Config> Pallet<T> {
        pub fn is_owner(identity: &T::AccountId, actual_owner: &T::AccountId) -> DispatchResult {
            let owner = Self::identity_owner(identity);

            match owner == *actual_owner {
                true => Ok(()),
                false => Err(Error::<T>::NotOwner.into()),
            }
        }

        /// Get the identity owner if set.
        /// If never changed, returns the identity as its owner.
        pub fn identity_owner(identity: &T::AccountId) -> T::AccountId {
            match Self::owner_of(identity) {
                Some(id) => id,
                None => identity.clone(),
            }
        }

        /// Validates if a delegate belongs to an identity and it has not expired.
        pub fn valid_delegate(
            identity: &T::AccountId,
            delegate_type: &[u8],
            delegate: &T::AccountId,
        ) -> DispatchResult {
            ensure!(delegate_type.len() <= 64, Error::<T>::InvalidDelegate);
            ensure!(
                Self::valid_listed_delegate(identity, delegate_type, delegate).is_ok()
                    || Self::is_owner(identity, delegate).is_ok(),
                Error::<T>::InvalidDelegate
            );
            Ok(())
        }

        /// Validates that a delegate contains_key for specific purpose and remains valid at this block high.
        pub fn valid_listed_delegate(
            identity: &T::AccountId,
            delegate_type: &[u8],
            delegate: &T::AccountId,
        ) -> DispatchResult {
            ensure!(
                <DelegateOf<T>>::contains_key((&identity, delegate_type, &delegate)),
                Error::<T>::InvalidDelegate
            );

            let validity = Self::delegate_of((identity, delegate_type, delegate));
            match validity > Some(<frame_system::Pallet<T>>::block_number()) {
                true => Ok(()),
                false => Err(Error::<T>::InvalidDelegate.into()),
            }
        }

        // Creates a new delegete for an account.
        pub fn create_delegate(
            who: &T::AccountId,
            identity: &T::AccountId,
            delegate: &T::AccountId,
            delegate_type: &[u8],
            valid_for: Option<T::BlockNumber>,
        ) -> DispatchResult {
            Self::is_owner(&identity, who)?;
            ensure!(who != delegate, Error::<T>::InvalidDelegate);
            ensure!(
                !Self::valid_listed_delegate(identity, delegate_type, delegate).is_ok(),
                Error::<T>::InvalidDelegate
            );

            let now_block_number = <frame_system::Pallet<T>>::block_number();
            let validity: T::BlockNumber = match valid_for {
                Some(blocks) => now_block_number + blocks,
                None => u32::max_value().into(),
            };

            <DelegateOf<T>>::insert((&identity, delegate_type, delegate), &validity);
            Ok(())
        }

        /// Checks if a signature is valid. Used to validate off-chain transactions.
        pub fn check_signature(
            signature: &T::Signature,
            msg: &[u8],
            signer: &T::AccountId,
        ) -> DispatchResult {
            if signature.verify(msg, signer) {
                Ok(())
            } else {
                Err(Error::<T>::BadSignature.into())
            }
        }

        /// Checks if a signature is valid. Used to validate off-chain transactions.
        pub fn valid_signer(
            identity: &T::AccountId,
            signature: &T::Signature,
            msg: &[u8],
            signer: &T::AccountId,
        ) -> DispatchResult {
            // Owner or a delegate signer.
            Self::valid_delegate(&identity, b"x25519VerificationKey2018", &signer)?;
            Self::check_signature(&signature, &msg, &signer)
        }

        /// Adds a new attribute to an identity and colects the storage fee.
        pub fn create_attribute(
            who: &T::AccountId,
            identity: &T::AccountId,
            name: &[u8],
            value: &[u8],
            valid_for: Option<T::BlockNumber>,
        ) -> DispatchResult {
            Self::is_owner(&identity, &who)?;
            let now_timestamp = <pallet_timestamp::Pallet<T>>::now();
            let now_block_number = <frame_system::Pallet<T>>::block_number();
            let mut nonce = Self::nonce_of((&identity, name.to_vec()));

            let validity: T::BlockNumber = match valid_for {
                Some(blocks) => now_block_number + blocks,
                None => u32::max_value().into(),
            };

            // Used for first time attribute creation
            let lookup_nonce = match &nonce {
                0 => 0, // prevents intialization panic
                _ => &nonce - 1,
            };

            let id = (&identity, name, lookup_nonce).using_encoded(blake2_256);

            if <AttributeOf<T>>::contains_key((&identity, &id)) {
                Err(Error::<T>::AttributeCreationFailed.into())
            } else {
                let new_attribute = Attribute {
                    name: (&name).to_vec(),
                    value: (&value).to_vec(),
                    validity,
                    creation: now_timestamp,
                    nonce,
                };

                // Prevent panic overflow
                nonce = nonce.checked_add(1).ok_or(Error::<T>::Overflow)?;
                <AttributeOf<T>>::insert((&identity, &id), new_attribute);
                <AttributeNonce<T>>::mutate((&identity, name.to_vec()), |n| *n = nonce);
                <UpdatedBy<T>>::insert(
                    identity,
                    (
                        who,
                        <frame_system::Pallet<T>>::block_number(),
                        <pallet_timestamp::Pallet<T>>::now(),
                    ),
                );
                Ok(())
            }
        }

        /// Updates the attribute validity to make it expire and invalid.
        pub fn reset_attribute(
            who: T::AccountId,
            identity: &T::AccountId,
            name: &[u8],
        ) -> DispatchResult {
            Self::is_owner(&identity, &who)?;
            // If the attribute contains_key, the latest valid block is set to the current block.
            let result = Self::attribute_and_id(identity, name);
            match result {
                Some((mut attribute, id)) => {
                    attribute.validity = <frame_system::Pallet<T>>::block_number();
                    <AttributeOf<T>>::mutate((&identity, id), |a| *a = attribute);
                }
                None => return Err(Error::<T>::AttributeResetFailed.into()),
            }

            // Keep track of the updates.
            <UpdatedBy<T>>::insert(
                identity,
                (
                    who,
                    <frame_system::Pallet<T>>::block_number(),
                    <pallet_timestamp::Pallet<T>>::now(),
                ),
            );
            Ok(())
        }

        /// Validates if an attribute belongs to an identity and it has not expired.
        pub fn valid_attribute(
            identity: &T::AccountId,
            name: &[u8],
            value: &[u8],
        ) -> DispatchResult {
            ensure!(name.len() <= 64, Error::<T>::InvalidAttribute);
            let result = Self::attribute_and_id(identity, name);

            let (attr, _) = match result {
                Some((attr, id)) => (attr, id),
                None => return Err(Error::<T>::InvalidAttribute.into()),
            };

            if (attr.validity > (<frame_system::Pallet<T>>::block_number()))
                && (attr.value == value.to_vec())
            {
                Ok(())
            } else {
                Err(Error::<T>::InvalidAttribute.into())
            }
        }

        /// Returns the attribute and its hash identifier.
        /// Uses a nonce to keep track of identifiers making them unique after attributes deletion.
        pub fn attribute_and_id(
            identity: &T::AccountId,
            name: &[u8],
        ) -> Option<AttributedId<T::BlockNumber, T::Moment>> {
            let nonce = Self::nonce_of((&identity, name.to_vec()));

            // Used for first time attribute creation
            let lookup_nonce = match nonce {
                0u64 => 0, // prevents intialization panic
                _ => nonce - 1u64,
            };

            // Looks up for the existing attribute.
            // Needs to use actual attribute nonce -1.
            let id = (&identity, name, lookup_nonce).using_encoded(blake2_256);

            if <AttributeOf<T>>::contains_key((&identity, &id)) {
                Some((Self::attribute_of((identity, id)), id))
            } else {
                None
            }
        }

        /// Creates a new attribute from a off-chain transaction.
        fn signed_attribute(
            who: T::AccountId,
            encoded: &[u8],
            transaction: &AttributeTransaction<T::Signature, T::AccountId>,
        ) -> DispatchResult {
            // Verify that the Data was signed by the owner or a not expired signer delegate.
            Self::valid_signer(
                &transaction.identity,
                &transaction.signature,
                &encoded,
                &transaction.signer,
            )?;
            Self::is_owner(&transaction.identity, &transaction.signer)?;
            ensure!(transaction.name.len() <= 64, Error::<T>::BadTransaction);

            let now_block_number = <frame_system::Pallet<T>>::block_number();
            let validity = now_block_number + transaction.validity.into();

            // If validity was set to 0 in the transaction,
            // it will set the attribute latest valid block to the actual block.
            if validity > now_block_number {
                Self::create_attribute(
                    &who,
                    &transaction.identity,
                    &transaction.name,
                    &transaction.value,
                    Some(transaction.validity.into()),
                )?;
            } else {
                Self::reset_attribute(who, &transaction.identity, &transaction.name)?;
            }
            Ok(())
        }
    }
}
