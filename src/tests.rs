use crate::{mock::*, AttributeTransaction, Error};
use codec::Encode;
use frame_support::{assert_noop, assert_ok};
use sp_core::Pair;

#[test]
fn validate_owner_signature() {
	new_test_ext().execute_with(|| {
		// Create a DId account
		let (_, did_public) = account("My Organization");

		// Create a new account pair and public key
		let (satoshi_pair, satoshi_public) = account("Satoshi");

		// Test: Should be able to register a new DId
		assert_ok(!DID::register_did(Origin::signed(satoshi_public.clone()), did_public));

		// Encode and sign a message.
		let msg = "I am Satoshi Nakamoto".encode();
		let satoshi_sig = satoshi_pair.sign(&msg);

		// Test: Should accept DId's owner signature
		assert(DID::valid_signer_and_signature(&did_public, &satoshi_sig, &msg, &satoshi_public));

		// Test: Should not accept someone masquerading as the owner, Satoshi
		let (bob_pair, _) = account("Bob");
		let bob_sig = bob_pair.sign(&msg);

		assert(!DID::valid_signer_and_signature(&did_public, &bob_sig, &msg, &satoshi_public));
	});
}

#[test]
fn validate_delegate_signature() {
	new_test_ext().execute_with(|| {
		System::set_block_number(1);

		// Create a DId account
		let (_, did_public) = account("My Organization");

		// Create a new account pair and public key
		let (satoshi_pair, satoshi_public) = account("Satoshi");
		let (bob_pair, bob_public) = account("Bob");

		assert_ok(!DID::register_did(Origin::signed(satoshi_public.clone()), did_public));

		let valid_block_offset = 5;

		// Test: Adding Bob as delegate should succeed
		assert_ok(!DID::upsert_delegate(Origin::signed(satoshi_public.clone()),
			did_public, crate::OFFCHAIN_TX_DELEGATE_TYPE, bob_public, Some(valid_block_offset)));

		let msg = "I am Satoshi Nakamoto".encode();
		let bob_sig = bob_pair.sign(&msg);

		System::set_block_number(valid_block_offset + 1);

		// Test: The delegate signature should be valid during the delegation period
		assert(DID::valid_signer_and_signature(&did_public, &bob_public, &msg, &bob_sig));

		System::set_block_number(valid_block_offset + 2);

		// Test: The delegate signature should fail after the delegation period
		assert(!DID::valid_signer_and_signature(&did_public, &bob_public, &msg, &bob_sig));
	});
}

// #[test]
// fn add_on_chain_and_revoke_off_chain_attribute() {
// 	new_test_ext().execute_with(|| {
// 		let name = b"MyAttribute".to_vec();
// 		let mut value = [1, 2, 3].to_vec();
// 		let mut validity: u32 = 1000;

// 		// Create a new account pair and get the public key.
// 		let alice_pair = account_pair("Alice");
// 		let alice_public = alice_pair.public();

// 		// Add a new attribute to an identity. Valid until block 1 + 1000.
// 		assert_ok!(DID::add_attribute(
// 			Origin::signed(alice_public.clone()),
// 			alice_public.clone(),
// 			name.clone(),
// 			value.clone(),
// 			Some(validity.clone().into())
// 		));

// 		// Validate that the attribute contains_key and has not expired.
// 		assert_ok!(DID::valid_attribute(&alice_public, &name, &value));

// 		// Revoke attribute off-chain
// 		// Set validity to 0 in order to revoke the attribute.
// 		validity = 0;
// 		value = [0].to_vec();
// 		let mut encoded = name.encode();
// 		encoded.extend(value.encode());
// 		encoded.extend(validity.encode());
// 		encoded.extend(alice_public.encode());

// 		let revoke_sig = alice_pair.sign(&encoded);

// 		let revoke_transaction = AttributeTransaction {
// 			signature: revoke_sig,
// 			name: name.clone(),
// 			value: value.clone(),
// 			validity,
// 			signer: alice_public.clone(),
// 			identity: alice_public.clone(),
// 		};

// 		// Revoke with off-chain signed transaction.
// 		assert_ok!(DID::execute(
// 			Origin::signed(alice_public.clone()),
// 			revoke_transaction
// 		));

// 		// Validate that the attribute was revoked.
// 		assert_noop!(
// 			DID::valid_attribute(&alice_public, &name, &[1, 2, 3].to_vec()),
// 			Error::<Test>::InvalidAttribute
// 		);
// 	});
// }
