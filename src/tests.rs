use crate::{mock::*, AttributeTransaction, Error};
use codec::Encode;
use frame_support::{assert_noop, assert_ok};
use sp_core::Pair;

#[test]
fn validate_claim() {
    new_test_ext().execute_with(|| {
        let value = b"I am Satoshi Nakamoto".to_vec();

        // Create a new account pair and get the public key.
        let satoshi_pair = account_pair("Satoshi");
        let satoshi_public = satoshi_pair.public();

        // Encode and sign the claim message.
        let claim = value.encode();
        let satoshi_sig = satoshi_pair.sign(&claim);

        // Validate that "Satoshi" signed the message.
        assert_ok!(DID::valid_signer(
            &satoshi_public,
            &satoshi_sig,
            &claim,
            &satoshi_public
        ));

        // Create a different public key to test the signature.
        let bobtc_public = account_key("Bob");

        // Fail to validate that Bob signed the message.
        assert_noop!(
            DID::check_signature(&satoshi_sig, &claim, &bobtc_public),
            Error::<Test>::BadSignature
        );
    });
}

#[test]
fn validate_delegated_claim() {
    new_test_ext().execute_with(|| {
        System::set_block_number(1);

        // Predefined delegate type: "Sr25519VerificationKey2018"
        let delegate_type = b"x25519VerificationKey2018".to_vec();
        let data = b"I am Satoshi Nakamoto".to_vec();

        let satoshi_public = account_key("Satoshi"); // Get Satoshi's public key.
        let nakamoto_pair = account_pair("Nakamoto"); // Create a new delegate account pair.
        let nakamoto_public = nakamoto_pair.public(); // Get delegate's public key.

        // Add signer delegate
        assert_ok!(
            DID::add_delegate(
                Origin::signed(satoshi_public.clone()),
                satoshi_public,  // owner
                nakamoto_public, // new signer delgate
                delegate_type,   // "Sr25519VerificationKey2018"
                Some(5)
            ) // valid for 5 blocks
        );

        let claim = data.encode();
        let satoshi_sig = nakamoto_pair.sign(&claim); // Sign the data with delegate private key.

        System::set_block_number(3);

        // Validate that satoshi's delegate signed the message.
        assert_ok!(DID::valid_signer(
            &satoshi_public,
            &satoshi_sig,
            &claim,
            &nakamoto_public
        ));

        System::set_block_number(6);

        // Delegate became invalid at block 6
        assert_noop!(
            DID::valid_signer(&satoshi_public, &satoshi_sig, &claim, &nakamoto_public),
            Error::<Test>::InvalidDelegate
        );
    });
}

#[test]
fn add_on_chain_and_revoke_off_chain_attribute() {
    new_test_ext().execute_with(|| {
        let name = b"MyAttribute".to_vec();
        let mut value = [1, 2, 3].to_vec();
        let mut validity: u32 = 1000;

        // Create a new account pair and get the public key.
        let alice_pair = account_pair("Alice");
        let alice_public = alice_pair.public();

        // Add a new attribute to an identity. Valid until block 1 + 1000.
        assert_ok!(DID::add_attribute(
            Origin::signed(alice_public),
            alice_public,
            name.clone(),
            value.clone(),
            Some(validity.clone().into())
        ));

        // Validate that the attribute contains_key and has not expired.
        assert_ok!(DID::valid_attribute(&alice_public, &name, &value));

        // Revoke attribute off-chain
        // Set validity to 0 in order to revoke the attribute.
        validity = 0;
        value = [0].to_vec();
        let mut encoded = name.encode();
        encoded.extend(value.encode());
        encoded.extend(validity.encode());
        encoded.extend(alice_public.encode());

        let revoke_sig = alice_pair.sign(&encoded);

        let revoke_transaction = AttributeTransaction {
            signature: revoke_sig,
            name: name.clone(),
            value,
            validity,
            signer: alice_public,
            identity: alice_public,
        };

        // Revoke with off-chain signed transaction.
        assert_ok!(DID::execute(
            Origin::signed(alice_public),
            revoke_transaction
        ));

        // Validate that the attribute was revoked.
        assert_noop!(
            DID::valid_attribute(&alice_public, &name, &[1, 2, 3].to_vec()),
            Error::<Test>::InvalidAttribute
        );
    });
}

#[test]
fn attacker_to_transfer_identity_should_fail() {
    new_test_ext().execute_with(|| {
        // Attacker is not the owner
        assert_eq!(
            DID::identity_owner(&account_key("Alice")),
            account_key("Alice")
        );

        // Transfer identity ownership to attacker
        assert_noop!(
            DID::change_owner(
                Origin::signed(account_key("BadBoy")),
                account_key("Alice"),
                account_key("BadBoy")
            ),
            Error::<Test>::NotOwner
        );

        // Attacker is not the owner
        assert_noop!(
            DID::is_owner(&account_key("Alice"), &account_key("BadBoy")),
            Error::<Test>::NotOwner
        );

        // Verify that the owner never changed
        assert_eq!(
            DID::identity_owner(&account_key("Alice")),
            account_key("Alice")
        );
    });
}

#[test]
fn attacker_add_new_delegate_should_fail() {
    new_test_ext().execute_with(|| {
        // BadBoy is an invalid delegate previous to attack.
        assert_noop!(
            DID::valid_delegate(&account_key("Alice"), &[7, 7, 7], &account_key("BadBoy")),
            Error::<Test>::InvalidDelegate
        );

        // Attacker should fail to add delegate.
        assert_noop!(
            DID::add_delegate(
                Origin::signed(account_key("BadBoy")),
                account_key("Alice"),
                account_key("BadBoy"),
                vec![7, 7, 7],
                Some(20)
            ),
            Error::<Test>::NotOwner
        );

        // BadBoy is an invalid delegate.
        assert_noop!(
            DID::valid_delegate(&account_key("Alice"), &[7, 7, 7], &account_key("BadBoy")),
            Error::<Test>::InvalidDelegate
        );
    });
}
