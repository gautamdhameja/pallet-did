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
//! The DId (Decentralized ID) pallet provides functionality for DIds management.
//!
//! * Change the DId Owner
//! * Add Delegate
//! * Revoke Delegate
//! * Add Attribute
//! * Revoke Attribute
//! * DId attribute update from off-chain transaction signature
//!
//! By default, each DId belongs to itself, until a `change_owner` dispatchable function is called
//!   to pass the ownership to someone else.
//!
//! ### Terminology
//!
//! * **DId:** A Decentralized Identifiers/Identity compliant with the DID standard.
//!     The DId is an AccountId with associated attributes/properties.
//! * **DId Ownership** The owner of the DId. By default it belongs to itself until ownership is passed
//!     to others.
//! * **Delegate:** A Delegate receives delegated permissions from a DId for a specific purpose, represented
//!    as `delegate_type`. The delegation can be valid indefinitely or valid for a certain time period,
//!     represented by `BlockNumber`.
//! * **Attribute:** It is a feature that gives extra information of a DId. Each attribute is a key, value
//!     pair. The attribute can be valid indefinitely or valid for a certain time period, represented by
//!    `BlockNumber`.
//!
//! ### Goals
//!
//! The DID system in Substrate is designed to make the following possible:
//!
//! * A decentralized identity or self-sovereign identity is a new approach where no one but you owns
//    or controls the state of your claimed digital identity.
//! * It enables the possibility to create a portable, persistent,  privacy-protecting, and personal identity.
//!
//! ### Dispatchable Functions
//!
//! * `change_owner` - Transfer the DId ownership to another account.
//! * `upsert_delegate` - Create/update a new delegate with an expiration period for a specific purpose
//!   (`delegate_type`).
//! * `revoke_delegate` - Revoke a DId delegate for a specific purpose (`delegate_type`).
//! * `upsert_attribute` - Create/update a new attribute/property as part of an identity and its its expiration period.
//! * `revoke_attribute` - Revoke an attribute/property from an identity.
//! * `upsert_attribute_from_offchain_signature` - Execute off-chain signed transactions to upsert the attribute
//!   by the DId owner or delegate.
//!
//! ### Public Functions
//!
//! * `did_owned` - Check whether a DId is owned by the user. Return a `bool` value.
//! * `did_owner` - Retrieve the DId owner. Return a `T::AccounId` value.
//! * `valid_delegate` - Check if a user is a valid delegate for a `delegate_type`. The owner is
//!    always a valid delegate of its owned DId. Return `true` or `false`.
//! * `valid_attribute` - Check if an attribute/property is valid for the DId. The function return
//!    `true` only when both the key and value match, and the property is before its expiration period.
//! * `encode_dnvv` - This method encodes DId, attribute name, attribute value, and expiration period
//!    into a message to be signed. This method is used when in `upsert_attribute_from_offchain_signature`.

#![cfg_attr(not(feature = "std"), no_std)]
#![recursion_limit = "256"]

use codec::{Decode, Encode};
use frame_support::{
	decl_error, decl_event, decl_module, decl_storage, dispatch::DispatchResult, ensure,
	StorageMap, Parameter
};
use frame_system::{ensure_signed};
use sp_runtime::traits::{IdentifyAccount, Verify, Saturating};
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
	type DId: IdentifyAccount<AccountId = Self::AccountId> + Into<Self::AccountId> + Parameter;
	type Event: From<Event<Self>> + Into<<Self as frame_system::Trait>::Event>;
	type Signature: Verify<Signer = Self::DId> + Parameter;
}

decl_event!(
	pub enum Event<T> where
		<T as frame_system::Trait>::AccountId,
		<T as frame_system::Trait>::BlockNumber,
		<T as Trait>::DId,
	{
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
		InvalidDelegate,
		InvalidSignature,
		NotOwner,
	}
}

decl_storage! {
	trait Store for Module<T: Trait> as DId {
		/// DId owner
		pub OwnerOf get(fn owner_of): map hasher(blake2_128_concat) T::DId => Option<T::AccountId>;

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
		pub fn change_owner(origin, did: T::DId, new_owner: T::AccountId) -> DispatchResult {
			// check: this is a signed tx
			let who = ensure_signed(origin)?;
			// check: `who` is the owner of the DId
			if !Self::did_owned(&did, &who) { return Err(Error::<T>::NotOwner.into()) }

			// DB writes
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
			if !Self::did_owned(&did, &who) { return Err(Error::<T>::NotOwner.into()) }
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
			if !Self::did_owned(&did, &who) { return Err(Error::<T>::NotOwner.into()) }
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
			if !Self::did_owned(&did, &who) { return Err(Error::<T>::NotOwner.into()) }
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
			if !Self::did_owned(&did, &who) { return Err(Error::<T>::NotOwner.into()) }
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
		pub fn upsert_attribute_from_offchain_signature(origin, tx: AttributeUpdateTx<T>) -> DispatchResult {
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
	pub fn did_owned(did: &T::DId, check: &T::AccountId) -> bool {
		Self::did_owner(did) == *check
	}

	pub fn did_owner(did: &T::DId) -> T::AccountId {
		match Self::owner_of(did) {
			Some(owner) => owner,
			None => did.clone().into(),
		}
	}

	/// Check if a delegate is valid for a (DId, delegate_type)
	// The DId owner is always a valid delegate for all delegate_type at all time
	pub fn valid_delegate(did: &T::DId, delegate_type: &[u8], delegate: &T::AccountId) -> bool {
		// Check if it is DId owner
		if Self::did_owned(did, delegate) { return true }

		// Verified `delegate` is not DId owner here
		let delegate_vec = Self::delegate_of(did, delegate_type);
		match delegate_vec.iter().find(|(acct, _)| acct == delegate) {
			Some((_, exp_opt)) => exp_opt.map_or(true,
				|valid_till| valid_till >= <frame_system::Module<T>>::block_number()),
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
		delegate_type: &[u8],
		delegate: &T::AccountId,
		valid_for_offset: Option<T::BlockNumber>,
	) {
		let new_exp_opt = valid_for_offset.map(|offset|
			<frame_system::Module<T>>::block_number().saturating_add(offset)
		);

		let mut acct_exist = false;

		<DelegateOf<T>>::mutate(did, delegate_type, |vec| {
			// Check if there is existing acct, update that record
			*vec = vec.iter_mut().map(|(acct, orig_exp_opt)|
				if acct == delegate {
					acct_exist = true;
					(acct.clone(), new_exp_opt)
				} else {
					(acct.clone(), *orig_exp_opt)
				}).collect::<Vec<_>>();

			// No existing acct found, so insert a record
			if !acct_exist {
				vec.push((delegate.clone(), new_exp_opt));
			}
		});
	}

	fn revoke_delegate_execute(did: &T::DId, delegate_type: &[u8], delegate: &T::AccountId) {
		<DelegateOf<T>>::mutate(did, delegate_type, |vec| {
			*vec = vec.iter_mut().filter_map(|(acct, exp_opt)|
				if acct == delegate { None }
				else { Some((acct.clone(), *exp_opt)) }
			).collect::<Vec<_>>();
		});
	}

	/// Adds a new attribute to an identity and colects the storage fee.
	fn upsert_attribute_execute (
		did: &T::DId, name: &[u8], value: &[u8], valid_for_offset: Option<T::BlockNumber>
	) {
		let valid_till = valid_for_offset.map(|offset|
			<frame_system::Module<T>>::block_number().saturating_add(offset)
		);

		let nonce = Self::nonce_of(did, name);

		let attr = Attribute {
			name: name.to_vec(),
			value: value.to_vec(),
			valid_till,
			nonce
		};

		//2 writes: 1) to AttributeOf, 2) to AttributeNonceOf
		<AttributeOf<T>>::insert(did.clone(), name.to_vec(), attr);
		<AttributeNonceOf<T>>::mutate(did, name, |n| *n += 1);
	}

	/// Revoke the attribute from DId
	// It removes both the 2nd key and the value from <AttributeOf<T>> double map
	fn revoke_attribute_execute (did: &T::DId, name: &[u8]) {
		<AttributeOf<T>>::remove(did, name);
	}
}
