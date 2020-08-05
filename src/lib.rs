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
// use sp_core::RuntimeDebug;
// use sp_io::hashing::blake2_256;
use sp_runtime::traits::{MaybeSerializeDeserialize, IdentifyAccount, Member, Verify, MaybeDisplay,
	Saturating};
use sp_std::{prelude::*, vec::Vec, fmt::Debug};

// #[cfg(test)]
// mod mock;

// #[cfg(test)]
// mod tests;

const DELEGATE_TYPE_LEN: usize = 64;

/// Attributes or properties that make an identity.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Default)]
pub struct Attribute<BlockNumber> {
	pub name: Vec<u8>,
	pub value: Vec<u8>,
	pub created_at: BlockNumber,
	pub valid_for: BlockNumber,
	pub nonce: u64,
}

/// This is the attribute with a 32-char hash
pub type AttributedId<BlockNumber> = (Attribute<BlockNumber>, [u8; 32]);

/// Off-chain signed transaction.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Default)]
pub struct AttributeTransaction<Signature, AccountId> {
	pub signature: Signature,
	pub name: Vec<u8>,
	pub value: Vec<u8>,
	pub validity: u32,
	pub signer: AccountId,
	pub identity: AccountId,
}

pub trait Trait: frame_system::Trait + pallet_timestamp::Trait {

	type DId: Parameter + Member + MaybeSerializeDeserialize + Debug + MaybeDisplay + Ord
		+ Default;

	type Event: From<Event<Self>> + Into<<Self as frame_system::Trait>::Event>;
	type Public: IdentifyAccount<AccountId = Self::AccountId>;
	type Signature: Verify<Signer = Self::Public> + Member + Encode + Decode;
}

decl_event!(
	pub enum Event<T> where
		<T as frame_system::Trait>::AccountId,
		<T as frame_system::Trait>::BlockNumber,
		// <T as Trait>::Signature,
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

		// ---

		// AttributeAdded(AccountId,Vec<u8>, Option<BlockNumber>),
		// AttributeRevoked(AccountId,Vec<u8>,BlockNumber),
		// AttributeDeleted(AccountId,Vec<u8>,BlockNumber),
		// AttributeTransactionExecuted(AttributeTransaction<Signature,AccountId>),
	}
);

decl_error! {
	pub enum Error for Module<T: Trait> {
		DelegateTypeTooLong,
		DIdAlreadyExist,
		DIdNotExist,
		NotOwner,

		// ---

		// BadSignature,
		// AttributeCreationFailed,
		// AttributeResetFailed,
		// AttributeRemovalFailed,
		// InvalidAttribute,
		// Overflow,
		// BadTransaction,
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

		/// The attributes that belong to an identity. Only valid for a specific period as defined by
		///   block number.
		pub AttributeOf get(fn attribute_of): double_map hasher(blake2_128_concat) T::DId,
			hasher(identity) Vec<u8> => Attribute<T::BlockNumber>;

		/// Attribute nonce used to generate a unique hash even if the attribute is deleted and recreated.
		pub AttributeNonce get(fn nonce_of): map hasher(blake2_128_concat) (T::DId, Vec<u8>) => u64;
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

		/// Creates a new delegate with an expiration period and for a specific purpose.
		// Either the did itself or the owner can add_delegate
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
			ensure!(delegate_type.len() <= DELEGATE_TYPE_LEN, Error::<T>::DelegateTypeTooLong);

			// writes
			Self::upsert_delegate_execute(&did, &delegate_type, &delegate, valid_for_offset);

			// emit successful event
			Self::deposit_event(RawEvent::DelegateUpserted(did, delegate_type, delegate, valid_for_offset));
			Ok(())
		}

		/// Revokes an identity's delegate by setting its expiration to the current block number.
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
			ensure!(delegate_type.len() <= DELEGATE_TYPE_LEN, Error::<T>::DelegateTypeTooLong);

			// writes
			Self::revoke_delegate_execute(&did, &delegate_type, &delegate);

			// emit successful event
			Self::deposit_event(RawEvent::DelegateRevoked(did, delegate_type, delegate));
			Ok(())
		}

		// /// Creates a new attribute as part of an identity.
		// /// Sets its expiration period.
		// #[weight = 10000]
		// pub fn add_attribute(
		// 	origin,
		// 	identity: T::AccountId,
		// 	name: Vec<u8>,
		// 	value: Vec<u8>,
		// 	valid_for: Option<T::BlockNumber>,
		// ) -> DispatchResult {
		// 	let who = ensure_signed(origin)?;
		// 	ensure!(name.len() <= 64, Error::<T>::AttributeCreationFailed);

		// 	Self::create_attribute(who, &identity, &name, &value, valid_for)?;
		// 	Self::deposit_event(RawEvent::AttributeAdded(identity, name, valid_for));
		// 	Ok(())
		// }

		// /// Revokes an attribute/property from an identity.
		// /// Sets its expiration period to the actual block number.
		// #[weight = 10000]
		// pub fn revoke_attribute(origin, identity: T::AccountId, name: Vec<u8>) -> DispatchResult {
		// 	let who = ensure_signed(origin)?;
		// 	ensure!(name.len() <= 64, Error::<T>::AttributeRemovalFailed);

		// 	Self::reset_attribute(who, &identity, &name)?;
		// 	Self::deposit_event(RawEvent::AttributeRevoked(
		// 		identity,
		// 		name,
		// 		<frame_system::Module<T>>::block_number(),
		// 	));
		// 	Ok(())
		// }

		// /// Executes off-chain signed transaction.
		// #[weight = 10000]
		// pub fn execute(
		// 	origin,
		// 	transaction: AttributeTransaction<T::Signature, T::AccountId>,
		// ) -> DispatchResult {
		// 	let who = ensure_signed(origin)?;

		// 	let mut encoded = transaction.name.encode();
		// 	encoded.extend(transaction.value.encode());
		// 	encoded.extend(transaction.validity.encode());
		// 	encoded.extend(transaction.identity.encode());

		// 	// Execute the storage update if the signer is valid.
		// 	Self::signed_attribute(who, &encoded, &transaction)?;
		// 	Self::deposit_event(RawEvent::AttributeTransactionExecuted(transaction));
		// 	Ok(())
		// }
	}
}

impl<T: Trait> Module<T> {
	/// Check if a delegate is valid for a (DId, delegate_type)
	// the DId owner is always a valid delegate for all delegate_type at all time
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

	// Insert or update a delegete for a DId.
	pub fn upsert_delegate_execute(
		did: &T::DId,
		delegate_type: &Vec<u8>,
		delegate: &T::AccountId,
		valid_for_offset: Option<T::BlockNumber>,
	) {
		let new_exp_opt = valid_for_offset.map_or(None,
			|offset| Some(<frame_system::Module<T>>::block_number().saturating_add(offset)));

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

	pub fn revoke_delegate_execute(did: &T::DId, delegate_type: &Vec<u8>, delegate: &T::AccountId) {
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

	// /// Checks if a signature is valid. Used to validate off-chain transactions.
	// pub fn check_signature(
	// 	signature: &T::Signature,
	// 	msg: &[u8],
	// 	signer: &T::AccountId,
	// ) -> DispatchResult {
	// 	if signature.verify(msg, signer) {
	// 		Ok(())
	// 	} else {
	// 		Err(Error::<T>::BadSignature.into())
	// 	}
	// }

	// /// Checks if a signature is valid. Used to validate off-chain transactions.
	// pub fn valid_signer(
	// 	identity: &T::AccountId,
	// 	signature: &T::Signature,
	// 	msg: &[u8],
	// 	signer: &T::AccountId,
	// ) -> DispatchResult {
	// 	// Owner or a delegate signer.
	// 	Self::valid_delegate(&identity, b"x25519VerificationKey2018", &signer)?;
	// 	Self::check_signature(&signature, &msg, &signer)
	// }

	// /// Adds a new attribute to an identity and colects the storage fee.
	// pub fn create_attribute(
	// 	who: T::AccountId,
	// 	identity: &T::AccountId,
	// 	name: &[u8],
	// 	value: &[u8],
	// 	valid_for: Option<T::BlockNumber>,
	// ) -> DispatchResult {
	// 	Self::is_owner(&identity, &who)?;
	// 	let now_timestamp = <pallet_timestamp::Module<T>>::now();
	// 	let now_block_number = <frame_system::Module<T>>::block_number();
	// 	let mut nonce = Self::nonce_of((&identity, name.to_vec()));

	// 	let validity: T::BlockNumber = match valid_for {
	// 		Some(blocks) => now_block_number + blocks,
	// 		None => u32::max_value().into(),
	// 	};

	// 	// Used for first time attribute creation
	// 	let lookup_nonce = match &nonce {
	// 		0 => 0, // prevents intialization panic
	// 		_ => &nonce - 1,
	// 	};

	// 	let id = (&identity, name, lookup_nonce).using_encoded(blake2_256);

	// 	if <AttributeOf<T>>::contains_key((&identity, &id)) {
	// 		Err(Error::<T>::AttributeCreationFailed.into())
	// 	} else {
	// 		let new_attribute = Attribute {
	// 			name: (&name).to_vec(),
	// 			value: (&value).to_vec(),
	// 			validity,
	// 			creation: now_timestamp,
	// 			nonce,
	// 		};

	// 		// Prevent panic overflow
	// 		nonce = nonce.checked_add(1).ok_or(Error::<T>::Overflow)?;
	// 		<AttributeOf<T>>::insert((&identity, &id), new_attribute);
	// 		<AttributeNonce<T>>::mutate((&identity, name.to_vec()), |n| *n = nonce);
	// 		<UpdatedBy<T>>::insert(
	// 			identity,
	// 			(
	// 				who,
	// 				<frame_system::Module<T>>::block_number(),
	// 				<pallet_timestamp::Module<T>>::now(),
	// 			),
	// 		);
	// 		Ok(())
	// 	}
	// }

	// /// Updates the attribute validity to make it expire and invalid.
	// pub fn reset_attribute(who: T::AccountId, identity: &T::AccountId, name: &[u8]) -> DispatchResult {
	// 	Self::is_owner(&identity, &who)?;
	// 	// If the attribute contains_key, the latest valid block is set to the current block.
	// 	let result = Self::attribute_and_id(identity, name);
	// 	match result {
	// 		Some((mut attribute, id)) => {
	// 			attribute.validity = <frame_system::Module<T>>::block_number();
	// 			<AttributeOf<T>>::mutate((&identity, id), |a| *a = attribute);
	// 		}
	// 		None => return Err(Error::<T>::AttributeResetFailed.into()),
	// 	}

	// 	// Keep track of the updates.
	// 	<UpdatedBy<T>>::insert(
	// 		identity,
	// 		(
	// 			who,
	// 			<frame_system::Module<T>>::block_number(),
	// 			<pallet_timestamp::Module<T>>::now(),
	// 		),
	// 	);
	// 	Ok(())
	// }

	// /// Validates if an attribute belongs to an identity and it has not expired.
	// pub fn valid_attribute(identity: &T::AccountId, name: &[u8], value: &[u8]) -> DispatchResult {
	// 	ensure!(name.len() <= 64, Error::<T>::InvalidAttribute);
	// 	let result = Self::attribute_and_id(identity, name);

	// 	let (attr, _) = match result {
	// 		Some((attr, id)) => (attr, id),
	// 		None => return Err(Error::<T>::InvalidAttribute.into()),
	// 	};

	// 	if (attr.validity > (<frame_system::Module<T>>::block_number()))
	// 		&& (attr.value == value.to_vec())
	// 	{
	// 		Ok(())
	// 	} else {
	// 		Err(Error::<T>::InvalidAttribute.into())
	// 	}
	// }

	// /// Returns the attribute and its hash identifier.
	// /// Uses a nonce to keep track of identifiers making them unique after attributes deletion.
	// pub fn attribute_and_id(
	// 	identity: &T::AccountId,
	// 	name: &[u8],
	// ) -> Option<AttributedId<T::BlockNumber, T::Moment>> {
	// 	let nonce = Self::nonce_of((&identity, name.to_vec()));

	// 	// Used for first time attribute creation
	// 	let lookup_nonce = match nonce {
	// 		0u64 => 0, // prevents intialization panic
	// 		_ => nonce - 1u64,
	// 	};

	// 	// Looks up for the existing attribute.
	// 	// Needs to use actual attribute nonce -1.
	// 	let id = (&identity, name, lookup_nonce).using_encoded(blake2_256);

	// 	if <AttributeOf<T>>::contains_key((&identity, &id)) {
	// 		Some((Self::attribute_of((identity, id)), id))
	// 	} else {
	// 		None
	// 	}
	// }

	// /// Creates a new attribute from a off-chain transaction.
	// fn signed_attribute(
	// 	who: T::AccountId,
	// 	encoded: &[u8],
	// 	transaction: &AttributeTransaction<T::Signature, T::AccountId>,
	// ) -> DispatchResult {
	// 	// Verify that the Data was signed by the owner or a not expired signer delegate.
	// 	Self::valid_signer(
	// 		&transaction.identity,
	// 		&transaction.signature,
	// 		&encoded,
	// 		&transaction.signer,
	// 	)?;
	// 	Self::is_owner(&transaction.identity, &transaction.signer)?;
	// 	ensure!(transaction.name.len() <= 64, Error::<T>::BadTransaction);

	// 	let now_block_number = <frame_system::Module<T>>::block_number();
	// 	let validity = now_block_number + transaction.validity.into();

	// 	// If validity was set to 0 in the transaction,
	// 	// it will set the attribute latest valid block to the actual block.
	// 	if validity > now_block_number {
	// 		Self::create_attribute(
	// 			who,
	// 			&transaction.identity,
	// 			&transaction.name,
	// 			&transaction.value,
	// 			Some(transaction.validity.into()),
	// 		)?;
	// 	} else {
	// 		Self::reset_attribute(who, &transaction.identity, &transaction.name)?;
	// 	}
	// 	Ok(())
	// }
}
