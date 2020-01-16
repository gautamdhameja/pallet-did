// Copyright 2018-2020 Parity Technologies (UK) Ltd.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// This pallet is based on ERC-1056

//! # DID Pallet
//!
//! The DID pallet allows resolving and management for DIDs (Decentralized Identifiers).
//! DID compliant with: https://w3c-ccg.github.io/did-spec/
//!
//! ## Overview
//!
//! The DID pallet provides functionality for DIDs management.
//!
//! * Change Identity Owner
//! * Add Delegate
//! * Revoke Delegate
//! * Add Attribute
//! * Revoke Attribute
//! * Delete Attribute
//! * Off-Chain Attribute Management
//!
//! ### Terminology
//!
//! * **DID:** A Decentralized Identifiers/Identity compliant with the DID standard.
//!     The DID is an AccountId with associated attributes/properties.
//! * **Identity Ownership** By default an identity is owned by itself, meaning whoever controls the account with that key.
//!     The owner can be updated to a new key pair.
//! * **Delegate:** A Delegate recives delegated permissions from a DID for a specific purpose.
//! * **Attribute:** It is a feature that gives extra information of an identity.
//! * **Valid Delegate:** The action of obtaining the validity period of the delegate.
//! * **Valid Attribute:** The action of obtaining the validity period of an attribute.
//! * **Change Identity Owner:** The process of transferring ownership.
//! * **Add Delegate:** The process of adding delegate privileges to an identity.
//!     An identity can assign multiple delegates for specific purposes on its behalf.
//! * **Revoke Delegate:** The process of revoking delegate privileges from an identity.
//! * **Add Attribute:** The process of assigning a specific identity attribute or feature.
//! * **Revoke Attribute:** The process of revoking a specific identity attribute or feature.
//! * **Delete Attribute:** The process of deleting a specific identity attribute or feature.
//!
//! ### Goals
//!
//! The DID system in Substrate is designed to make the following possible:
//!
//! * A decentralized identity or self-sovereign identity is a new approach where no one but you owns or controls the state of your digital identity.
//! * It enables the possibility to create a portable, persistent,  privacy-protecting, and personal identity.
//!
//! ### Dispatchable Functions
//!
//! * `change_owner` - Transfers an `identity` represented as an `AccountId` from the owner account (`origin`) to a `target` account.
//! * `add_delegate` - Creates a new delegate with an expiration period and for a specific purpose.
//! * `revoke_delegate` - Revokes an identity's delegate by setting its expiration to the current block number.
//! * `add_attribute` - Creates a new attribute/property as part of an identity. Sets its expiration period.
//! * `revoke_attribute` - Revokes an attribute/property from an identity. Sets its expiration period to the actual block number.
//! * `delete_attribute` - Removes an attribute/property from an identity. This attribute/property becomes unavailable.
//! * `execute` - Executes off-chain signed transactions.
//!
//! ### Public Functions
//!
//! * `is_owner` - Returns a boolean value. `True` if the `account` owns the `identity`.
//! * `identity_owner` - Get the account owner of an `identity`.
//! * `valid_delegate` - Validates if a delegate belongs to an identity and it has not expired.
//!    The identity owner has all provileges and is considered as delegate with all permissions.
//! * `valid_listed_delegate` - Returns a boolean value. `True` if the `delegate` belongs the `identity` delegates list.
//! * `valid_attribute` - Validates if an attribute belongs to an identity and it has not expired.
//! * `attribute_and_id` - Get the `attribute` and its `hash` identifier.
//! * `check_signature` - Validates the signer from a signature.
//! * `valid_signer` - Validates a signature from a valid signer delegate or the owner of an identity.
//!
//! *

#![cfg_attr(not(feature = "std"), no_std)]
#![recursion_limit = "256"]

use codec::{Decode, Encode};
use frame_support::{
    decl_error, decl_event, decl_module, decl_storage,
    dispatch::DispatchResult,
    ensure, StorageMap,
};
use sp_runtime::traits::{Hash, IdentifyAccount, Member, Verify};
use sp_std::{prelude::*, vec::Vec};
use system::ensure_signed;

/// Attributes or properties that make up an identity.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Default)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct Attribute<BlockNumber, Moment> {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
    pub validity: BlockNumber,
    pub creation: Moment,
    pub nonce: u64,
}

/// Off-chain signed transaction.
#[derive(PartialEq, Eq, PartialOrd, Ord, Default, Clone, Encode, Decode, Hash)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct AttributeTransaction<Signature, AccountId> {
    pub signature: Signature,
    pub name: Vec<u8>,
    pub value: Vec<u8>,
    pub validity: u32,
    pub signer: AccountId,
    pub identity: AccountId,
}

pub trait Trait: system::Trait + timestamp::Trait {
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
    type Public: IdentifyAccount<AccountId = Self::AccountId> + Clone;
    type Signature: Verify<Signer = Self::Public> + Member + Decode + Encode;
}

decl_storage! {
    trait Store for Module<T: Trait> as DID {
        /// Identity delegates stored by type.
        /// Delegates are only valid for a specific period defined as blocks number.
        pub DelegateOf get(delegate_of): map (T::AccountId, Vec<u8>, T::AccountId) => Option<T::BlockNumber>;
        /// The attributes that belong to an identity.
        /// Attributes are only valid for a specific period defined as blocks number.
        pub AttributeOf get(attribute_of): map (T::AccountId, T::Hash) => Attribute<T::BlockNumber, T::Moment>;
        /// Attribute nonce used to generate a unique hash even if the attribute is deleted and recreated.
        pub AttributeNonce get(nonce_of): map (T::AccountId, Vec<u8>) => u64;
        /// Identity owner.
        pub OwnerOf get(owner_of): map T::AccountId => Option<T::AccountId>;
        /// Tracking the latest identity update.
        pub UpdatedBy get(updated_by): map T::AccountId => (T::AccountId, T::BlockNumber, T::Moment);
    }
}

decl_module! {
  pub struct Module<T: Trait> for enum Call where origin: T::Origin {
      type Error = Error<T>;

      fn deposit_event() = default;
        /// Transfers ownership of an identity.
        pub fn change_owner(
            origin,
            identity: T::AccountId,
            new_owner: T::AccountId,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Self::is_owner(&identity, &who)?;

            let now_timestamp = <timestamp::Module<T>>::now();
            let now_block_number = <system::Module<T>>::block_number();

            if <OwnerOf<T>>::exists(&identity) {
                // Update to new owner.
                <OwnerOf<T>>::mutate(&identity, |o| *o = Some(new_owner.clone()));
            } else {
                // Add to new owner.
                <OwnerOf<T>>::insert(&identity, &new_owner);
            }
            // Save the update time and block.
            <UpdatedBy<T>>::insert(
                &identity,
                (who.clone(), now_block_number.clone(), now_timestamp),
            );
            Self::deposit_event(RawEvent::OwnerChanged(
                identity,
                who,
                new_owner,
                now_block_number,
            ));

            Ok(())
        }

        /// Creates a new delegate with an expiration period and for a specific purpose.
        pub fn add_delegate(
            origin,
            identity: T::AccountId,
            delegate: T::AccountId,
            delegate_type: Vec<u8>,
            valid_for: T::BlockNumber,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Self::is_owner(&identity, &who)?;
            ensure!(&who != &delegate, Error::<T>::InvalidDelegate);
            ensure!(
                !Self::valid_listed_delegate(&identity, &delegate_type, &delegate).is_ok(),
                Error::<T>::InvalidDelegate
            );
            ensure!(delegate_type.len() <= 64, Error::<T>::InvalidDelegate);

            let now_timestamp = <timestamp::Module<T>>::now();
            let now_block_number = <system::Module<T>>::block_number();
            let validity = now_block_number.clone() + valid_for.clone();

            <DelegateOf<T>>::insert(
                (identity.clone(), delegate_type.clone(), delegate.clone()),
                validity.clone(),
            );
            <UpdatedBy<T>>::insert(&identity, (who, now_block_number, now_timestamp));
            Self::deposit_event(RawEvent::DelegateAdded(
                identity,
                delegate_type,
                delegate,
                validity,
                valid_for,
            ));

            Ok(())
        }

        /// Revokes an identity's delegate by setting its expiration to the current block number.
        pub fn revoke_delegate(
            origin,
            identity: T::AccountId,
            delegate_type: Vec<u8>,
            delegate: T::AccountId,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Self::is_owner(&identity, &who)?;
            Self::valid_listed_delegate(&identity, &delegate_type, &delegate)?;
            ensure!(delegate_type.len() <= 64, Error::<T>::InvalidDelegate);

            let now_timestamp = <timestamp::Module<T>>::now();
            let now_block_number = <system::Module<T>>::block_number();

            // Update only the validity period to revoke the delegate.
            <DelegateOf<T>>::mutate(
                (identity.clone(), delegate_type.clone(), delegate.clone()),
                |b| *b = Some(now_block_number.clone()),
            );
            <UpdatedBy<T>>::insert(&identity, (who, now_block_number, now_timestamp));
            Self::deposit_event(RawEvent::DelegateRevoked(identity, delegate_type, delegate));

            Ok(())
        }

        /// Creates a new attribute as part of an identity. 
        /// Sets its expiration period.
        pub fn add_attribute(
            origin,
            identity: T::AccountId,
            name: Vec<u8>,
            value: Vec<u8>,
            valid_for: T::BlockNumber,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Self::is_owner(&identity, &who)?;
            ensure!(name.len() <= 64, Error::<T>::AttributeCreationFailed);

            Self::create_attribute(who, &identity, &name, &value, &valid_for)?;
            Self::deposit_event(RawEvent::AttributeAdded(identity, name, valid_for));

            Ok(())
        }

        /// Revokes an attribute/property from an identity. 
        /// Sets its expiration period to the actual block number.
        pub fn revoke_attribute(origin, identity: T::AccountId, name: Vec<u8>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Self::is_owner(&identity, &who)?;
            ensure!(name.len() <= 64, Error::<T>::AttributeRemovalFailed);

            Self::reset_attribute(who, &identity, &name)?;
            Self::deposit_event(RawEvent::AttributeRevoked(
                identity,
                name,
                <system::Module<T>>::block_number(),
            ));

            Ok(())
        }

        /// Removes an attribute from an identity. This attribute/property becomes unavailable.
        pub fn delete_attribute(origin, identity: T::AccountId, name: Vec<u8>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            Self::is_owner(&identity, &who)?;
            ensure!(name.len() <= 64, Error::<T>::AttributeRemovalFailed);

            let now_block_number = <system::Module<T>>::block_number();
            let result = Self::attribute_and_id(&identity, &name);

            match result {
                Some((_, id)) => <AttributeOf<T>>::remove((identity.clone(), id)),
                None => return Err(Error::<T>::AttributeRemovalFailed.into()),
            }

            <UpdatedBy<T>>::insert(
                &identity,
                (who, now_block_number.clone(), <timestamp::Module<T>>::now()),
            );

            Self::deposit_event(RawEvent::AttributeDeleted(identity, name, now_block_number));

            Ok(())
        }

        /// Executes off-chain signed transaction.
        pub fn execute(
            origin,
            transaction: AttributeTransaction<T::Signature, T::AccountId>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let mut encoded = transaction.name.encode();
            encoded.extend(transaction.value.encode());
            encoded.extend(transaction.validity.encode());
            encoded.extend(transaction.identity.encode());

            // Execute the storage update if the signer is valid.
            Self::signed_attribute(who, &encoded, &transaction)?;
            Self::deposit_event(RawEvent::AttributeTransactionExecuted(transaction));
            Ok(())
        }
    }
}

decl_event!(
  pub enum Event<T> 
  where 
	<T as system::Trait>::AccountId,
  <T as system::Trait>::BlockNumber,
  <T as Trait>::Signature
  {
    OwnerChanged(AccountId, AccountId, AccountId, BlockNumber),
    DelegateAdded(AccountId, Vec<u8>, AccountId, BlockNumber, BlockNumber),
    DelegateRevoked(AccountId, Vec<u8>, AccountId),
    AttributeAdded(AccountId,Vec<u8>,BlockNumber),
    AttributeRevoked(AccountId,Vec<u8>,BlockNumber),
    AttributeDeleted(AccountId,Vec<u8>,BlockNumber),
    AttributeTransactionExecuted(AttributeTransaction<Signature,AccountId>),
  }
);

decl_error! {
    pub enum Error for Module<T: Trait> {
        NotOwner,
        InvalidDelegate,
        BadSignature,
        AttributeCreationFailed,
        AttributeResetFailed,
        AttributeRemovalFailed,
        Overflow,
        BadTransaction,
    }
}

impl<T: Trait> Module<T> {
    /// Validates if the AccountId 'actual_owner' owns the identity.
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
        let owner = match Self::owner_of(identity) {
            Some(id) => id,
            None => identity.clone(),
        };
        owner
    }

    /// Validates if a delegate belongs to an identity and it has not expired.
    pub fn valid_delegate(
        identity: &T::AccountId,
        delegate_type: &Vec<u8>,
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

    /// Validates that a delegate exists for specific purpose and remains valid at this block high.
    pub fn valid_listed_delegate(
        identity: &T::AccountId,
        delegate_type: &Vec<u8>,
        delegate: &T::AccountId,
    ) -> DispatchResult {
        ensure!(
            <DelegateOf<T>>::exists((identity.clone(), delegate_type.clone(), delegate.clone())),
            Error::<T>::InvalidDelegate
        );

        let validity =
            Self::delegate_of((identity.clone(), delegate_type.clone(), delegate.clone()));
        match validity > Some(<system::Module<T>>::block_number()) {
            true => Ok(()),
            false => Err(Error::<T>::InvalidDelegate.into()),
        }
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
        // Predefined signer delegate type: "Sr25519VerificationKey2018"
        let delegate_type: Vec<u8> = [
            83, 114, 50, 53, 53, 49, 57, 86, 101, 114, 105, 102, 105, 99, 97, 116, 105, 111, 110,
            75, 101, 121, 50, 48, 49, 56,
        ]
        .to_vec();

        // Owner or a delegate signer.
        Self::valid_delegate(&identity, &delegate_type, &signer)?;
        Self::check_signature(&signature, &msg, &signer)
    }

    /// Adds a new attribute to an identity and colects the storage fee.
    fn create_attribute(
        who: T::AccountId,
        identity: &T::AccountId,
        name: &Vec<u8>,
        value: &Vec<u8>,
        valid_for: &T::BlockNumber,
    ) -> DispatchResult {
        let now_timestamp = <timestamp::Module<T>>::now();
        let now_block_number = <system::Module<T>>::block_number();
        let mut nonce = Self::nonce_of((identity.clone(), name.clone()));
        let validity = now_block_number + *valid_for;

        // Used for first time attribute creation
        let lookup_nonce = match nonce.clone() {
            0u64 => 0, // prevents intialization panic
            _ => nonce.clone() - 1u64,
        };

        let id = (identity, name, lookup_nonce).using_encoded(<T as system::Trait>::Hashing::hash);

        if <AttributeOf<T>>::exists((identity.clone(), id.clone())) {
            Err(Error::<T>::AttributeCreationFailed.into())
        } else {
            let new_attribute = Attribute {
                name: name.clone(),
                value: value.clone(),
                validity,
                creation: now_timestamp,
                nonce: nonce.clone(),
            };

            nonce = nonce.checked_add(1).ok_or(Error::<T>::Overflow)?; // prevent overflow panic

            <AttributeOf<T>>::insert((identity.clone(), id), new_attribute);
            <AttributeNonce<T>>::mutate((identity.clone(), name.clone()), |n| *n = nonce);
            <UpdatedBy<T>>::insert(
                identity,
                (
                    who,
                    <system::Module<T>>::block_number(),
                    <timestamp::Module<T>>::now(),
                ),
            );
            Ok(())
        }
    }

    /// Updates the attribute validity to make it expire and invalid.
    fn reset_attribute(
        who: T::AccountId,
        identity: &T::AccountId,
        name: &Vec<u8>,
    ) -> DispatchResult {
        // If the attribute exists, the latest valid block is set to the current block.
        let result = Self::attribute_and_id(identity, name);
        match result {
            Some((mut attribute, id)) => {
                attribute.validity = <system::Module<T>>::block_number();
                <AttributeOf<T>>::mutate((identity.clone(), id), |a| *a = attribute);
            }
            None => return Err(Error::<T>::AttributeResetFailed.into()),
        }

        // Keep track of the updates.
        <UpdatedBy<T>>::insert(
            identity,
            (
                who,
                <system::Module<T>>::block_number(),
                <timestamp::Module<T>>::now(),
            ),
        );
        Ok(())
    }

    /// Returns the attribute and its hash identifier.
    /// Uses a nonce to keep track of identifiers making them unique after attributes deletion.
    pub fn attribute_and_id(
        identity: &T::AccountId,
        name: &Vec<u8>,
    ) -> Option<(Attribute<T::BlockNumber, T::Moment>, T::Hash)> {
        let nonce = Self::nonce_of((identity.clone(), name.clone()));

        // Used for first time attribute creation
        let lookup_nonce = match nonce.clone() {
            0u64 => 0, // prevents intialization panic
            _ => nonce - 1u64,
        };

        // Looks up for the existing attribute.
        // Needs to use actual attribute nonce -1.
        let id = (identity.clone(), name.clone(), lookup_nonce)
            .using_encoded(<T as system::Trait>::Hashing::hash);

        if <AttributeOf<T>>::exists((identity.clone(), id.clone())) {
            Some((
                Self::attribute_of((identity.clone(), id.clone())),
                id.clone(),
            ))
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
        ensure!(&transaction.name.len() <= &64, Error::<T>::BadTransaction);

        let now_block_number = <system::Module<T>>::block_number();
        let validity = now_block_number + transaction.validity.into();

        // If validity was set to 0 in the transaction,
        // it will set the attribute latest valid block to the actual block.
        if validity > now_block_number {
            Self::create_attribute(
                who,
                &transaction.identity,
                &transaction.name,
                &transaction.value,
                &transaction.validity.into(),
            )?;
        } else {
            Self::reset_attribute(who, &transaction.identity, &transaction.name)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frame_support::{
      assert_ok, assert_noop, impl_outer_origin, parameter_types, weights::Weight};
    use sp_core::{H256, sr25519, Pair};
    use sp_runtime::{
        testing::Header,
        traits::{BlakeTwo256, IdentityLookup},
        Perbill,
    };
    use std::string::String;

    impl_outer_origin! {
        pub enum Origin for Test {}
    }

    // For testing the pallet, we construct most of a mock runtime. This means
    // first constructing a configuration type (`Test`) which `impl`s each of the
    // configuration traits of modules we want to use.
    #[derive(Clone, Eq, PartialEq)]
    pub struct Test;
    parameter_types! {
        pub const BlockHashCount: u64 = 250;
        pub const MaximumBlockWeight: Weight = 1024;
        pub const MaximumBlockLength: u32 = 2 * 1024;
        pub const AvailableBlockRatio: Perbill = Perbill::from_percent(75);
    }
    impl system::Trait for Test {
        type Origin = Origin;
        type Call = ();
        type Index = u64;
        type BlockNumber = u64;
        type Hash = H256;
        type Hashing = BlakeTwo256;
        type AccountId = sr25519::Public;
        type Lookup = IdentityLookup<Self::AccountId>;
        type Header = Header;
        type Event = ();
        type BlockHashCount = BlockHashCount;
        type MaximumBlockWeight = MaximumBlockWeight;
        type MaximumBlockLength = MaximumBlockLength;
        type AvailableBlockRatio = AvailableBlockRatio;
        type Version = ();
        type ModuleToIndex = ();
    }

    impl timestamp::Trait for Test {
      type Moment = u64;
      type OnTimestampSet = ();
      type MinimumPeriod = ();
    }

    impl Trait for Test {
      type Event = ();
      type Public = sr25519::Public;
      type Signature = sr25519::Signature;
    }

    type DID = Module<Test>;

    // This function basically just builds a genesis storage key/value store according to
    // our desired mockup.
    fn new_test_ext() -> sp_io::TestExternalities {
        system::GenesisConfig::default()
            .build_storage::<Test>()
            .unwrap()
            .into()
    }

    pub fn account_pair(s: &str) -> sr25519::Pair {
        sr25519::Pair::from_string(&format!("//{}", s), None)
        .expect("static values are valid; qed")
    }

    pub fn account_key(s: &str) -> sr25519::Public {
        sr25519::Pair::from_string(&format!("//{}", s), None)
        .expect("static values are valid; qed")
        .public()
    }

    #[test]
    fn validate_claim() {
      new_test_ext().execute_with(|| {
        let value: Vec<u8> = String::from("I am Satoshi Nakamoto").into();

        // Create a new account pair and get the public key.
        let satoshi_pair = account_pair("Satoshi");
        let satoshi_public = satoshi_pair.public();

        // Encode and sign the claim message.
        let claim = value.encode();
        let satoshi_sig = satoshi_pair.sign(&claim);
        
        // Validate that "Satoshi" signed the message.
        assert_ok!(DID::valid_signer(&satoshi_public, &satoshi_sig, &claim, &satoshi_public));

        // Create a different public key to test the signature.
        let bobtc_public = account_key("Bob");
        
        // Fail to validate that Bob signed the message.
        assert_noop!(DID::check_signature(&satoshi_sig, &claim, &bobtc_public), Error::<Test>::BadSignature);
    });
  }
}
