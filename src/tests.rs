use crate::{mock::*, AttributeUpdateTx, Error};
use frame_support::{assert_noop, assert_ok};
use sp_core::Pair;

#[test]
fn allows_registering_did_with_valid_signature() {
	new_test_ext().execute_with(|| {
		let (did_pair, did_public) = account("My Organization");
		let (satoshi_pair, satoshi_public) = account("Satoshi");
		let reg_msg = b"did registration";

		// Test 1: Test with invalid signature - should fail. The signature should be from
		//   did private key, not Satoshi private key.
		assert_noop!(DId::register_did(
			Origin::signed(satoshi_public.clone()),
			did_public,
			reg_msg.to_vec(),
			satoshi_pair.sign(reg_msg)
		), Error::<Test>::InvalidSignature);

		// Test 2: Test with valid signature - should succeed
		assert_ok!(DId::register_did(
			Origin::signed(satoshi_public.clone()),
			did_public,
			reg_msg.to_vec(),
			did_pair.sign(reg_msg)
		));

		// Test 3: Test with DId registration the duplicate DId - should fail
		assert_noop!(DId::register_did(
			Origin::signed(satoshi_public.clone()),
			did_public,
			reg_msg.to_vec(),
			did_pair.sign(reg_msg)
		), Error::<Test>::DIdAlreadyExist);
	})
}

#[test]
fn change_did_owner() {
	new_test_ext().execute_with(|| {
		// Setup: Satoshi create a DId
		let (did_pair, did_public) = account("My Organization");
		let (_, satoshi_public) = account("Satoshi");
		let reg_msg = b"did registration";
		let del_type = b"del_type";

		assert_ok!(DId::register_did(
			Origin::signed(satoshi_public.clone()),
			did_public,
			reg_msg.to_vec(),
			did_pair.sign(reg_msg)
		));

		// Test 1: Bob try to upsert DId delegate for Charles. This should fail
		let (_, bob_public) = account("Bob");
		let (_, charles_public) = account("Charles");

		assert_noop!(DId::upsert_delegate(
			Origin::signed(bob_public.clone()),
			did_public,
			del_type.to_vec(),
			charles_public,
			None
		), Error::<Test>::NotOwner);

		// Satoshi pass the DId ownership to Bob
		assert_ok!(DId::change_owner(
			Origin::signed(satoshi_public.clone()),
			did_public,
			bob_public,
		));

		// Test 2: Bob try to upsert DId delegate for Charles. This should succeed
		assert_ok!(DId::upsert_delegate(
			Origin::signed(bob_public.clone()),
			did_public,
			del_type.to_vec(),
			charles_public,
			None
		));

		// Test 3: Satoshi try to upsert DId delegate for Charles. This should fail, as he
		//   is no longer the DId owner
		assert_noop!(DId::upsert_delegate(
			Origin::signed(satoshi_public.clone()),
			did_public,
			del_type.to_vec(),
			charles_public,
			None
		), Error::<Test>::NotOwner);
	})
}

#[test]
fn accepts_owner_attr_update_tx() {
	new_test_ext().execute_with(|| {
		// Create a DId account
		let (did_pair, did_public) = account("My Organization");

		// Create a new account pair and public key
		let (satoshi_pair, satoshi_public) = account("Satoshi");

		let reg_msg = b"did registration";

		// Register a DId
		assert_ok!(DId::register_did(
			Origin::signed(satoshi_public.clone()),
			did_public,
			reg_msg.to_vec(),
			did_pair.sign(reg_msg)
		));

		// Test #1: Should accept DId's owner signature
		let name = b"attribute name";
		let value = b"attribute value";
		let dnvv_msg = DId::encode_dnvv(&did_public, name, value, None);
		let tx_satoshi = AttributeUpdateTx {
			did: did_public,
			name: name.to_vec(),
			value: value.to_vec(),
			valid_till: None,
			signature: satoshi_pair.sign(&dnvv_msg)
		};
		assert_ok!(DId::upsert_attribute_from_offchain_signature(
			Origin::signed(satoshi_public.clone()),
			tx_satoshi.clone()
		));

		// Test #2: Should not accept other ppl to update
		let (bob_pair, bob_public) = account("Bob");
		let tx_bob = AttributeUpdateTx {
			did: did_public,
			name: name.to_vec(),
			value: value.to_vec(),
			valid_till: None,
			signature: bob_pair.sign(&dnvv_msg)
		};
		assert_noop!(DId::upsert_attribute_from_offchain_signature(
			Origin::signed(bob_public.clone()),
			tx_bob
		), Error::<Test>::InvalidDelegate);

		// Test #3: Should not accept Bob masquerading as Satoshi.
		//   To test this, we need to give Bob upsert_attribute right first
		assert_ok!(DId::upsert_delegate(
			Origin::signed(satoshi_public.clone()),
			did_public,
			crate::OFFCHAIN_TX_DELEGATE_TYPE.to_vec(),
			bob_public,
			None
		));

		assert_noop!(DId::upsert_attribute_from_offchain_signature(
			Origin::signed(bob_public.clone()),
			tx_satoshi
		), Error::<Test>::InvalidSignature);
	});
}

#[test]
fn accepts_delegate_attr_update_tx() {
	new_test_ext().execute_with(|| {
		System::set_block_number(1);

		// Create a DId account
		let (did_pair, did_public) = account("My Organization");

		// Create a new account pair and public key
		let (_, satoshi_public) = account("Satoshi");
		let (bob_pair, bob_public) = account("Bob");
		let reg_msg = b"did registration";

		// Setup: Satoshi registers a DId
		assert_ok!(DId::register_did(
			Origin::signed(satoshi_public.clone()),
			did_public,
			reg_msg.to_vec(),
			did_pair.sign(reg_msg)
		));

		let valid_block_offset = 5;

		// Setup: Satoshi upsert Bob as DId delegate
		assert_ok!(DId::upsert_delegate(
			Origin::signed(satoshi_public.clone()),
			did_public,
			crate::OFFCHAIN_TX_DELEGATE_TYPE.to_vec(),
			bob_public,
			Some(valid_block_offset)
		));

		System::set_block_number(1 + valid_block_offset);

		// Test #1: Bob now should be able to send attr_update_tx
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
		assert_ok!(DId::upsert_attribute_from_offchain_signature(
			Origin::signed(bob_public.clone()),
			tx_bob.clone()
		));

		// Test #2: Bob valid period has passed. Now the transaction should fail.
		System::set_block_number(2 + valid_block_offset);
		assert_noop!(DId::upsert_attribute_from_offchain_signature(
			Origin::signed(bob_public.clone()),
			tx_bob
		), Error::<Test>::InvalidDelegate);
	});
}
