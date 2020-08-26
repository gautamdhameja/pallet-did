use crate::{mock::*, AttributeUpdateTx, Error};
use frame_support::{assert_noop, assert_ok};
use sp_core::Pair;

#[test]
fn change_did_owner() {
	new_test_ext().execute_with(|| {
		// Setup
		let del_type = b"del_type";
		let (_, did_public) = account("My Organization");
		let (_, bob_public) = account("Bob");
		let (_, charles_public) = account("Charles");

		// Test 1: Bob try to upsert DId delegate for Charles. This should fail as it is owned by DId now.
		assert_noop!(DId::upsert_delegate(
			Origin::signed(bob_public.clone()),
			did_public,
			del_type.to_vec(),
			charles_public,
			None
		), Error::<Test>::NotOwner);

		// DId itself pass the ownership to Bob
		assert_ok!(DId::change_owner(
			Origin::signed(did_public.clone()),
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

		// Test 3: DId now try to upsert DId delegate for Charles. This should fail, as he
		//   is no longer the DId owner
		assert_noop!(DId::upsert_delegate(
			Origin::signed(did_public.clone()),
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
		// Setup
		let (did_pair, did_public) = account("My Organization");
		let (bob_pair, bob_public) = account("Bob");
		let name = b"attribute name";
		let value = b"attribute value";
		let dnvv_msg = DId::encode_dnvv(&did_public, name, value, None);

		// Test #1: Should accept DId's owner signature
		let tx_did = AttributeUpdateTx {
			did: did_public,
			name: name.to_vec(),
			value: value.to_vec(),
			valid_till: None,
			signature: did_pair.sign(&dnvv_msg)
		};
		assert_ok!(DId::upsert_attribute_from_offchain_signature(
			Origin::signed(did_public.clone()),
			tx_did.clone()
		));

		// Test #2: Should not accept other ppl to update
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

		// Test #3: Should not accept Bob masquerading as DId.
		//   To test this, we need to first give Bob upsert_attribute right
		assert_ok!(DId::upsert_delegate(
			Origin::signed(did_public.clone()),
			did_public,
			crate::OFFCHAIN_TX_DELEGATE_TYPE.to_vec(),
			bob_public,
			None
		));

		assert_noop!(DId::upsert_attribute_from_offchain_signature(
			Origin::signed(bob_public.clone()),
			tx_did
		), Error::<Test>::InvalidSignature);
	});
}

#[test]
fn accepts_delegate_attr_update_tx() {
	new_test_ext().execute_with(|| {
		// Setup
		System::set_block_number(1);
		let (_, did_public) = account("My Organization");
		let (bob_pair, bob_public) = account("Bob");
		let valid_block_offset = 5;

		// Setup: DId upsert Bob as DId delegate
		assert_ok!(DId::upsert_delegate(
			Origin::signed(did_public.clone()),
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

		// Test #2: Bob delegate period has passed. Now the transaction should fail.
		System::set_block_number(2 + valid_block_offset);
		assert_noop!(DId::upsert_attribute_from_offchain_signature(
			Origin::signed(bob_public.clone()),
			tx_bob
		), Error::<Test>::InvalidDelegate);
	});
}
