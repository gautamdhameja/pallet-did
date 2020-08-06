use crate::{mock::*, AttributeUpdateTx, Error};
use frame_support::{assert_noop, assert_ok};
use sp_core::Pair;

#[test]
fn allows_owner_attr_update_tx() {
	new_test_ext().execute_with(|| {
		// Create a DId account
		let (_, did_public) = account("My Organization");

		// Create a new account pair and public key
		let (satoshi_pair, satoshi_public) = account("Satoshi");

		// Test: Should be able to register a new DId
		assert_ok!(DId::register_did(Origin::signed(satoshi_public.clone()), did_public));

		// Test: Should accept DId's owner signature
		let name = b"attribute name";
		let value = b"attribute value";
		let msg = DId::encode_dnvv(&did_public, name, value, None);
		let tx_satoshi = AttributeUpdateTx {
			did: did_public,
			name: name.to_vec(),
			value: value.to_vec(),
			valid_till: None,
			signature: satoshi_pair.sign(&msg)
		};
		assert_ok!(DId::execute(Origin::signed(satoshi_public.clone()), tx_satoshi));

		// Test: Should not accept other ppl to update
		let (bob_pair, bob_public) = account("Bob");
		let tx_bob = AttributeUpdateTx {
			did: did_public,
			name: name.to_vec(),
			value: value.to_vec(),
			valid_till: None,
			signature: bob_pair.sign(&msg)
		};
		assert_noop!(DId::execute(Origin::signed(bob_public.clone()), tx_bob),
			Error::<Test>::InvalidDelegate);
	});
}

#[test]
fn allows_delegate_attr_update_tx() {
	new_test_ext().execute_with(|| {
		System::set_block_number(1);

		// Create a DId account
		let (_, did_public) = account("My Organization");

		// Create a new account pair and public key
		let (_, satoshi_public) = account("Satoshi");
		let (bob_pair, bob_public) = account("Bob");

		assert_ok!(DId::register_did(Origin::signed(satoshi_public.clone()), did_public));

		let valid_block_offset = 5;

		// Test: Adding Bob as delegate should succeed
		assert_ok!(DId::upsert_delegate(
			Origin::signed(satoshi_public.clone()),
			did_public,
			crate::OFFCHAIN_TX_DELEGATE_TYPE.to_vec(),
			bob_public,
			Some(valid_block_offset)
		));

		System::set_block_number(1 + valid_block_offset);

		// Test: Bob now be able to send attr_update_tx
		let name = b"attribute name";
		let value = b"attribute value";
		let msg = DId::encode_dnvv(&did_public, name, value, None);
		let tx_bob = AttributeUpdateTx {
			did: did_public,
			name: name.to_vec(),
			value: value.to_vec(),
			valid_till: None,
			signature: bob_pair.sign(&msg)
		};
		assert_ok!(DId::execute(Origin::signed(bob_public.clone()), tx_bob.clone()));

		// Now, Bob valid period has passed
		System::set_block_number(2 + valid_block_offset);
		// Test: This tx should fail
		assert_noop!(DId::execute(Origin::signed(bob_public.clone()), tx_bob),
			Error::<Test>::InvalidDelegate);
	});
}
