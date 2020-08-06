// Copyright 2019-2020 Parity Technologies (UK) Ltd.
// You can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// You should have received a copy of the GNU General Public License
// along with Substrate.  If not, see <http://www.gnu.org/licenses/>.
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
	decl_error, decl_event, decl_module, decl_storage, dispatch::DispatchResult, ensure, StorageMap,
	Parameter
};
use frame_system::{self as system, ensure_signed};
use sp_runtime::traits::{MaybeSerializeDeserialize, IdentifyAccount, Member, Verify, MaybeDisplay,
	Saturating};
use sp_std::{prelude::*, fmt, fmt::Debug};

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

const DELEGATE_TYPE_MAX_LEN: usize = 64;
const ATTR_NAME_MAX_LEN: usize = 64;
pub const OFFCHAIN_TX_DELEGATE_TYPE: &[u8] = b"x25519VerificationKey2018";

/// Attributes or properties that make an identity.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Default, Debug)]
pub struct Attribute<BlockNumber> {
	pub name: Vec<u8>,
	pub value: Vec<u8>,
	pub valid_till: Option<BlockNumber>,
	pub nonce: u64,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Default)]
pub struct AttributeUpdateTx<T: Trait> {
	pub did: T::DId,
	pub name: Vec<u8>,
	pub value: Vec<u8>,
	pub valid_till: Option<T::BlockNumber>,
	pub signature: T::Signature,
}

impl<T: Trait> fmt::Debug for AttributeUpdateTx<T> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("AttributeUpdateTx<T>")
	}
}

pub trait Trait: frame_system::Trait + pallet_timestamp::Trait {
	type DId: Parameter + Member + MaybeSerializeDeserialize + Debug + MaybeDisplay + Ord
		+ Default + Encode + Decode;
	type Event: From<Event<Self>> + Into<<Self as frame_system::Trait>::Event>;
	type Public: IdentifyAccount<AccountId = Self::AccountId>;
	type Signature: Verify<Signer = Self::Public> + Member + Encode + Decode;
}

decl_event!(
	pub enum Event<T> where
		<T as frame_system::Trait>::AccountId,
		<T as frame_system::Trait>::BlockNumber,
		<T as Trait>::DId,
	{
		// params order: DId, the owner
		DIdRegistered(DId, AccountId),
		// params order: DId, the owner
		DIdOwnerChanged(DId, AccountId),
		// params order: DId, delegate type, target account, valid offset
		DelegateUpserted(DId, Vec<u8>, AccountId, Option<BlockNumber>),
		// params order: DId, delegate type, target account
		DelegateRevoked(DId, Vec<u8>, AccountId),

		AttributeUpserted(DId, Vec<u8>, Vec<u8>, Option<BlockNumber>),
		AttributeRevoked(DId, Vec<u8>),
		AttributeUpdateTxExecuted(AccountId, DId, Vec<u8>, Vec<u8>, Option<BlockNumber>),
	}
);

decl_error! {
	pub enum Error for Module<T: Trait> {
		AttrNameTooLong,
		DelegateTypeTooLong,
		DIdAlreadyExist,
		DIdNotExist,
		InvalidDelegate,
		InvalidSignature,
		NotOwner,
	}
}

decl_storage! {
	trait Store for Module<T: Trait> as DId {
		// Storing all the current registered DId
		pub DIdStore get(fn did_store): map hasher(blake2_128_concat) T::DId => bool;

		/// DId owner
		pub OwnerOf get(fn owner_of): map hasher(blake2_128_concat) T::DId => T::AccountId;

		/// The delegates of an identity. Only valid for a specific period as defined by block number.
		pub DelegateOf get(fn delegate_of): double_map hasher(blake2_128_concat) T::DId,
			hasher(blake2_128_concat) Vec<u8> => Vec<(T::AccountId, Option<T::BlockNumber>)>;

		/// The attributes that belong to a DId. Only valid for a specific period as defined by
		///   block number.
		pub AttributeOf get(fn attribute_of): double_map hasher(blake2_128_concat) T::DId,
			hasher(blake2_128_concat) Vec<u8> => Attribute<T::BlockNumber>;

		/// Attribute nonce used to generate a unique hash even if the attribute is deleted and recreated.
		pub AttributeNonceOf get(fn nonce_of): double_map hasher(blake2_128_concat) T::DId,
			hasher(blake2_128_concat) Vec<u8> => u64;
	}
}

decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		type Error = Error<T>;
		fn deposit_event() = default;

		/// This function registers a new DId. The DId must not existed before
		#[weight = 10000]
		pub fn register_did(origin, did: T::DId) -> DispatchResult {
			// check: this is a signed tx
			let who = ensure_signed(origin)?;
			// check: `did` doesn't exist in the store yet
			ensure!(!Self::did_store(&did), Error::<T>::DIdAlreadyExist);

			// writes
			<DIdStore<T>>::insert(&did, true);
			<OwnerOf<T>>::insert(&did, &who);

			// Emit event to notify DId is updated
			Self::deposit_event(RawEvent::DIdRegistered(did, who));
			Ok(())
		}

		/// This function registers a new DId. The DId must not existed before
		#[weight = 10000]
		pub fn change_owner(origin, did: T::DId, new_owner: T::AccountId) -> DispatchResult {
			// check: this is a signed tx
			let who = ensure_signed(origin)?;
			// check: `did` exists in the store
			ensure!(Self::did_store(&did), Error::<T>::DIdNotExist);
			// check: `who` is the owner of the DId
			ensure!(Self::owner_of(&did) == who, Error::<T>::NotOwner);

			// writes
			<OwnerOf<T>>::insert(&did, &new_owner);

			// Emit event to notify DId is updated
			Self::deposit_event(RawEvent::DIdOwnerChanged(did, new_owner));
			Ok(())
		}

		/// Upsert a delegate with an expiration period for a delegate_type.
		#[weight = 10000]
		pub fn upsert_delegate(origin, did: T::DId, delegate_type: Vec<u8>, delegate: T::AccountId,
			valid_for_offset: Option<T::BlockNumber>) -> DispatchResult
		{
			// check: this is a signed tx
			let who = ensure_signed(origin)?;
			// check: `did` exists in the store
			ensure!(Self::did_store(&did), Error::<T>::DIdNotExist);
			// check: the call is made by the DId owner
			ensure!(Self::owner_of(&did) == who, Error::<T>::NotOwner);
			// check: the `delegate_type` length is within the limit
			ensure!(delegate_type.len() <= DELEGATE_TYPE_MAX_LEN, Error::<T>::DelegateTypeTooLong);

			// writes
			Self::upsert_delegate_execute(&did, &delegate_type, &delegate, valid_for_offset);

			// emit successful event
			Self::deposit_event(RawEvent::DelegateUpserted(did, delegate_type, delegate, valid_for_offset));
			Ok(())
		}

		/// Revokes the delegate from the DId and delegation type
		#[weight = 10000]
		pub fn revoke_delegate(origin, did: T::DId, delegate_type: Vec<u8>, delegate: T::AccountId)
			-> DispatchResult
		{
			// check: this is a signed tx
			let who = ensure_signed(origin)?;
			// check: `did` exists in the store
			ensure!(Self::did_store(&did), Error::<T>::DIdNotExist);
			// check: `who` is the owner of the DId
			ensure!(Self::owner_of(&did) == who, Error::<T>::NotOwner);
			// check: the `delegate_type` length is within the limit
			ensure!(delegate_type.len() <= DELEGATE_TYPE_MAX_LEN, Error::<T>::DelegateTypeTooLong);

			// writes
			Self::revoke_delegate_execute(&did, &delegate_type, &delegate);

			// emit successful event
			Self::deposit_event(RawEvent::DelegateRevoked(did, delegate_type, delegate));
			Ok(())
		}

		/// Creates a new attribute as part of an identity.
		/// Sets its expiration period.
		#[weight = 10000]
		pub fn upsert_attribute(
			origin,
			did: T::DId,
			name: Vec<u8>,
			value: Vec<u8>,
			valid_for_offset: Option<T::BlockNumber>,
		) -> DispatchResult
		{
			// check: this is a signed tx
			let who = ensure_signed(origin)?;
			// check: `did` exists in the store
			ensure!(Self::did_store(&did), Error::<T>::DIdNotExist);
			// check: the call is made by the DId owner
			ensure!(Self::owner_of(&did) == who, Error::<T>::NotOwner);
			// check: the attribute name length is within the limit
			ensure!(name.len() <= ATTR_NAME_MAX_LEN, Error::<T>::AttrNameTooLong);

			// writes
			Self::upsert_attribute_execute(&did, &name, &value, valid_for_offset);

			Self::deposit_event(RawEvent::AttributeUpserted(did, name, value, valid_for_offset));
			Ok(())
		}

		/// Revokes an attribute/property from an identity.
		/// Sets its expiration period to the actual block number.
		#[weight = 10000]
		pub fn revoke_attribute(origin, did: T::DId, name: Vec<u8>) -> DispatchResult {
			// check: this is a signed tx
			let who = ensure_signed(origin)?;
			// check: `did` exists in the store
			ensure!(Self::did_store(&did), Error::<T>::DIdNotExist);
			// check: the call is made by the DId owner
			ensure!(Self::owner_of(&did) == who, Error::<T>::NotOwner);
			// check: the attribute name length is within the limit
			ensure!(name.len() <= ATTR_NAME_MAX_LEN, Error::<T>::AttrNameTooLong);

			// writes
			Self::revoke_attribute_execute(&did, &name);

			Self::deposit_event(RawEvent::AttributeRevoked(did, name));
			Ok(())
		}

		/// Upsert DId attribute value via off-chain signature.
		// The main difference of this function and `upsert_attribute` is that this function allows the DId
		//   owner or its delegate (with delegation_type OFFCHAIN_TX_DELEGATE_TYPE) to update the DId attribute.
		#[weight = 10000]
		pub fn execute(origin, tx: AttributeUpdateTx<T>) -> DispatchResult {
			// check: this is a signed tx
			let who = ensure_signed(origin)?;
			// check: if signer is a valid delegate of the DId with specific delegation type
			//   OFFCHAIN_TX_DELEGATE_TYPE
			ensure!(Self::valid_delegate(&tx.did, OFFCHAIN_TX_DELEGATE_TYPE, &who), Error::<T>::InvalidDelegate);
			// check: if the attribute name length is within the limit
			ensure!(tx.name.len() <= ATTR_NAME_MAX_LEN, Error::<T>::AttrNameTooLong);
			// check: verify the signature is signed by `who`
			ensure!(
				tx.signature.verify(&Self::encode_dnvv(&tx.did, &tx.name, &tx.value, tx.valid_till) as &[u8], &who),
				Error::<T>::InvalidSignature
			);

			// write: update the DId attribute
			Self::upsert_attribute_execute(&tx.did, &tx.name, &tx.value, tx.valid_till);

			Self::deposit_event(RawEvent::AttributeUpdateTxExecuted(who, tx.did, tx.name,
				tx.value, tx.valid_till));
			Ok(())
		}
	}
}

impl<T: Trait> Module<T> {
	/// Check if a delegate is valid for a (DId, delegate_type)
	// The DId owner is always a valid delegate for all delegate_type at all time
	pub fn valid_delegate(did: &T::DId, delegate_type: &[u8], delegate: &T::AccountId) -> bool {
		// DId does not exist
		if !Self::did_store(did) { return false }

		// `delegate` is the DId owner
		if Self::owner_of(did) == *delegate  { return true }

		let delegate_vec = Self::delegate_of(did, delegate_type);
		match delegate_vec.iter().find(|(acct, _)| acct == delegate) {
			Some((_, exp_opt)) => exp_opt.map_or(true, |e| e <= <frame_system::Module<T>>::block_number()),
			None => false,
		}
	}

	/// Check if a (name, value) attribute pair is valid for a DId
	pub fn valid_attribute(did: &T::DId, name: &[u8], value: &[u8]) -> bool {
		if name.len() > ATTR_NAME_MAX_LEN { return false }

		if !<AttributeOf<T>>::contains_key(did, name) { return false }

		let attr = Self::attribute_of(did, name);
		let current = <frame_system::Module<T>>::block_number();
		if attr.value != value || attr.valid_till.map_or(false, |bn| bn > current) { return false }

		true
	}

	pub fn encode_dnvv(did: &T::DId, name: &[u8], value: &[u8], valid_till: Option<T::BlockNumber>) -> Vec<u8> {
		let mut encoded = did.encode();
		encoded.extend(name.encode());
		encoded.extend(value.encode());
		encoded.extend(valid_till.encode());
		encoded
	}

	// Insert or update a delegete for a DId.
	fn upsert_delegate_execute(
		did: &T::DId,
		delegate_type: &Vec<u8>,
		delegate: &T::AccountId,
		valid_for_offset: Option<T::BlockNumber>,
	) {
		let new_exp_opt = valid_for_offset.map_or(None,
			|offset| Some(<frame_system::Module<T>>::block_number().saturating_add(offset))
		);

		let mut acct_exist = false;

		<DelegateOf<T>>::mutate(did, delegate_type, |vec| {
			// Check if there is existing acct, update that record
			*vec = vec.into_iter()
				.filter_map( |(acct, orig_exp_opt)| if acct == delegate {
					acct_exist = true;
					Some((acct.clone(), new_exp_opt))
				} else {
					Some((acct.clone(), *orig_exp_opt))
				})
				.collect::<Vec<_>>();

			// No existing acct found, so insert a record
			if !acct_exist {
				vec.push((delegate.clone(), new_exp_opt));
			}
		});
	}

	fn revoke_delegate_execute(did: &T::DId, delegate_type: &Vec<u8>, delegate: &T::AccountId) {
		<DelegateOf<T>>::mutate(did, delegate_type, |vec| {
			*vec = vec.into_iter()
				.filter_map( |(acct, exp_opt)| if acct == delegate {
					None
				} else {
					Some((acct.clone(), *exp_opt))
				})
				.collect::<Vec<_>>();
		});
	}

	/// Adds a new attribute to an identity and colects the storage fee.
	fn upsert_attribute_execute (
		did: &T::DId, name: &[u8], value: &[u8], valid_for_offset: Option<T::BlockNumber>
	) {
		let valid_till = valid_for_offset.map_or(None,
			|offset| Some(<frame_system::Module<T>>::block_number().saturating_add(offset))
		);

		let nonce = Self::nonce_of(did, name);

		let attr = Attribute {
			name: name.to_vec(),
			value: value.to_vec(),
			valid_till,
			nonce
		};

		//2 writes: 1) to AttributeOf, 2) to AttributeNonceOf
		<AttributeOf<T>>::insert(did.clone(), name.clone(), attr);
		<AttributeNonceOf<T>>::mutate(did, name, |n| *n += 1);
	}

	/// Revoke the attribute from DId
	// It removes both the 2nd key and the value from <AttributeOf<T>> double map
	fn revoke_attribute_execute (did: &T::DId, name: &[u8]) {
		<AttributeOf<T>>::remove(did, name);
	}
}
