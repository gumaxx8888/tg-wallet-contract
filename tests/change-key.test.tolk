import "@acton/crypto"
import "@acton/emulation/network"
import "@acton/emulation/testing"
import "@acton/testing/expect"
import "@wrappers/WalletTrampoline.gen"
import "@wrappers/utils"
import "@contracts/WalletTg/errors"

/*
    This file checks public key rotation: external/internal success paths,
    repeated rotations, emitted external-out events, current-key signatures,
    new-key rotation proofs, and malformed encrypted-old-key cells.
*/

// Opaque test ciphertexts: the contract must forward all 256 bits unchanged.
const ENCRYPTED_OLD_PRIVATE_KEY = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".hexToSlice() as bits256
const SECOND_ENCRYPTED_OLD_PRIVATE_KEY = "ffeeddccbbaa99887766554433221100fedcba98765432100123456789abcdef".hexToSlice() as bits256

fun assertRawKeyRotationResult(isExternal: bool, encryptedOldPrivateKey: cell?, expectedExitCode: int): void {
    val oldKey = crypto.generateKeyPair();
    val newKey = crypto.generateKeyPair();
    val (wallet, deployer) = deployWalletWithKey(oldKey);

    // Build the request manually so the last ref can be malformed or absent.
    // Both signatures are valid and cover the exact request being sent.
    var request = beginCell()
        .storeUint(isExternal ? 0xFBBA99C8 : 0xFBBA99C7, 32)
        .storeAny(seqnoHeader(0))
        .storeUint(newKey.publicKey, 256)
        .storeRef(createKeyRotationProof(wallet.address, newKey).toCell());
    if (encryptedOldPrivateKey != null) {
        request.storeRef(encryptedOldPrivateKey);
    }
    val body = request.endCell();
    val signature = crypto.sign(oldKey.privateKey, body);
    val envelope = beginCell().storeSlice(signature).storeSlice(body.beginParse()).endCell();

    if (isExternal) {
        val balanceBefore = testing.getAccountBalance(wallet.address);
        val result = wallet.sendAnyExternal(envelope);
        if (expectedExitCode == 0) {
            expect(result).toBeAccepted();
            expect(result.unwrap()).toHaveSuccessfulTx();
            assertKeyChangedEvent(result.unwrap(), wallet.address, (encryptedOldPrivateKey! as Cell<bits256>).load());
        } else {
            expect(result).toBeNotAccepted();
            expect(result).toHaveExternalVmExitCode(expectedExitCode);
            expect(testing.getAccountBalance(wallet.address)).toEqual(balanceBefore);
        }
    } else {
        val result = wallet.sendAny(deployer.address, envelope, { value: ton("0.1") });
        expect(result).toHaveTx({
            from: deployer.address,
            to: wallet.address,
            success: expectedExitCode == 0,
            exitCode: expectedExitCode,
        });
        if (expectedExitCode == 0) {
            assertKeyChangedEvent(result, wallet.address, (encryptedOldPrivateKey! as Cell<bits256>).load());
        } else {
            expect(result.findExternalOutMessage()).toBeNull();
        }
    }
    expect(wallet.getPublicKey()).toEqual(expectedExitCode == 0 ? newKey.publicKey : oldKey.publicKey);
    expect(wallet.seqno()).toEqual(expectedExitCode == 0 ? 1 : 0);
}

get fun `test change-key: raw requests accept exactly 256 encrypted-old-key bits`() {
    val encryptedOldPrivateKey = ENCRYPTED_OLD_PRIVATE_KEY.toCell();
    assertRawKeyRotationResult(false, encryptedOldPrivateKey, 0);
    assertRawKeyRotationResult(true, encryptedOldPrivateKey, 0);
}

get fun `test change-key: rejects an empty encrypted-old-key cell`() {
    assertRawKeyRotationResult(false, createEmptyCell(), 9);
    assertRawKeyRotationResult(true, createEmptyCell(), 9);
}

get fun `test change-key: rejects 255 encrypted-old-key bits`() {
    val encryptedOldPrivateKey = beginCell().storeUint(0, 255).endCell();
    assertRawKeyRotationResult(false, encryptedOldPrivateKey, 9);
    assertRawKeyRotationResult(true, encryptedOldPrivateKey, 9);
}

get fun `test change-key: rejects 257 encrypted-old-key bits`() {
    val encryptedOldPrivateKey = beginCell().storeAny(ENCRYPTED_OLD_PRIVATE_KEY).storeUint(0, 1).endCell();
    assertRawKeyRotationResult(false, encryptedOldPrivateKey, 9);
    assertRawKeyRotationResult(true, encryptedOldPrivateKey, 9);
}

get fun `test change-key: rejects an extra ref in the encrypted-old-key cell`() {
    val encryptedOldPrivateKey = beginCell().storeAny(ENCRYPTED_OLD_PRIVATE_KEY).storeRef(createEmptyCell()).endCell();
    assertRawKeyRotationResult(false, encryptedOldPrivateKey, 9);
    assertRawKeyRotationResult(true, encryptedOldPrivateKey, 9);
}

get fun `test change-key: rejects a missing encrypted-old-key ref`() {
    assertRawKeyRotationResult(false, null, 9);
    assertRawKeyRotationResult(true, null, 9);
}

get fun `test change-key: rotates the key and the new key takes over`() {
    val oldKey = crypto.generateKeyPair();
    val newKey = crypto.generateKeyPair();
    val (wallet, _) = deployWalletWithKey(oldKey);

    val reqRotation = prepareChangePublicKeyE(
        oldKey,
        seqnoHeader(0),
        wallet.address,
        newKey,
        ENCRYPTED_OLD_PRIVATE_KEY,
    );
    val rotation = wallet.requestExternal(reqRotation);
    expect(rotation).toBeAccepted();
    expect(rotation.unwrap()).toHaveTx({ exitCode: 0 });
    assertKeyChangedEvent(rotation.unwrap(), wallet.address, ENCRYPTED_OLD_PRIVATE_KEY);
    expect(wallet.getPublicKey()).toEqual(newKey.publicKey);
    expect(wallet.seqno()).toEqual(1);

    val receiver = randomAddress("receiver");
    val forwardValue = ton("0.001");
    val messageToSend = makeTransferToSend(receiver, forwardValue);

    val reqStale = prepareSendMessagesE(
        oldKey,
        seqnoHeader(1),
        [messageToSend],
    );
    val stale = wallet.requestExternal(reqStale);
    expect(stale).toBeNotAccepted();
    expect(stale).toHaveExternalVmExitCode(Errors.InvalidSignature);
    expect(wallet.seqno()).toEqual(1);

    val reqTransfer = prepareSendMessagesE(
        newKey,
        seqnoHeader(1),
        [messageToSend],
    );
    val transfer = wallet.requestExternal(reqTransfer);
    expect(transfer).toBeAccepted();
    expect(transfer.unwrap()).toHaveTx({
        from: wallet.address,
        to: receiver,
        value: forwardValue,
    });
    expect(wallet.seqno()).toEqual(2);
}

get fun `test change-key: the key can be rotated repeatedly externally`() {
    val oldKey = crypto.generateKeyPair();
    val newKey = crypto.generateKeyPair();
    val thirdKey = crypto.generateKeyPair();
    val (wallet, _) = deployWalletWithKey(oldKey);

    val reqFirst = prepareChangePublicKeyE(
        oldKey,
        seqnoHeader(0),
        wallet.address,
        newKey,
        ENCRYPTED_OLD_PRIVATE_KEY,
    );
    val first = wallet.requestExternal(reqFirst);
    expect(first).toBeAccepted();
    expect(first.unwrap()).toHaveTx({ exitCode: 0 });
    assertKeyChangedEvent(first.unwrap(), wallet.address, ENCRYPTED_OLD_PRIVATE_KEY);
    expect(wallet.getPublicKey()).toEqual(newKey.publicKey);
    expect(wallet.seqno()).toEqual(1);

    val reqSecond = prepareChangePublicKeyE(
        newKey,
        seqnoHeader(1),
        wallet.address,
        thirdKey,
        SECOND_ENCRYPTED_OLD_PRIVATE_KEY,
    );
    val second = wallet.requestExternal(reqSecond);
    expect(second).toBeAccepted();
    expect(second.unwrap()).toHaveTx({ exitCode: 0 });
    assertKeyChangedEvent(second.unwrap(), wallet.address, SECOND_ENCRYPTED_OLD_PRIVATE_KEY);
    expect(wallet.getPublicKey()).toEqual(thirdKey.publicKey);
    expect(wallet.seqno()).toEqual(2);
}

get fun `test change-key: a refused rotation keeps the current key and can be retried`() {
    val oldKey = crypto.generateKeyPair();
    val newKey = crypto.generateKeyPair();
    val (wallet, _) = deployWalletWithKey(oldKey);
    val wrongProof = createKeyRotationProof(wallet.address, oldKey);

    val reqRefused = prepareChangePublicKeyWithProofE(
        oldKey,
        seqnoHeader(0),
        newKey.publicKey,
        wrongProof,
        ENCRYPTED_OLD_PRIVATE_KEY,
    );
    val refused = wallet.requestExternal(reqRefused);

    expect(refused).toBeNotAccepted();
    expect(refused).toHaveExternalVmExitCode(Errors.NewKeySignatureIsInvalid);
    expect(wallet.getPublicKey()).toEqual(oldKey.publicKey);
    expect(wallet.seqno()).toEqual(0);

    val receiver = randomAddress("receiver-after-refused-rotation");
    val paymentValue = ton("0.001");
    val messageToSend = makeTransferToSend(receiver, paymentValue);
    val reqStillCurrent = prepareSendMessagesE(
        oldKey,
        seqnoHeader(0),
        [messageToSend],
    );
    val stillCurrent = wallet.requestExternal(reqStillCurrent);
    expect(stillCurrent).toBeAccepted();
    expect(stillCurrent.unwrap()).toHaveTx({
        from: wallet.address,
        to: receiver,
        value: paymentValue,
    });
    expect(wallet.seqno()).toEqual(1);

    val reqRetry = prepareChangePublicKeyE(
        oldKey,
        seqnoHeader(1),
        wallet.address,
        newKey,
        ENCRYPTED_OLD_PRIVATE_KEY,
    );
    val retry = wallet.requestExternal(reqRetry);
    expect(retry).toBeAccepted();
    expect(retry.unwrap()).toHaveTx({ exitCode: 0 });
    assertKeyChangedEvent(retry.unwrap(), wallet.address, ENCRYPTED_OLD_PRIVATE_KEY);
    expect(wallet.getPublicKey()).toEqual(newKey.publicKey);
    expect(wallet.seqno()).toEqual(2);
}

get fun `test change-key: rotates through an internal signed request too`() {
    val oldKey = crypto.generateKeyPair();
    val newKey = crypto.generateKeyPair();
    val (wallet, deployer) = deployWalletWithKey(oldKey);

    val req = prepareChangePublicKeyI(
        oldKey,
        seqnoHeader(0),
        wallet.address,
        newKey,
        ENCRYPTED_OLD_PRIVATE_KEY,
    );
    val receipt = wallet.requestInternal(deployer.address, req, { value: ton("0.1") });

    expect(receipt).toHaveSuccessfulTx({ from: deployer.address, to: wallet.address });
    assertKeyChangedEvent(receipt, wallet.address, ENCRYPTED_OLD_PRIVATE_KEY);
    expect(wallet.getPublicKey()).toEqual(newKey.publicKey);
    expect(wallet.seqno()).toEqual(1);
}

get fun `test change-key: internal request rejects the same key`() {
    val keyPair = crypto.generateKeyPair();
    val (wallet, deployer) = deployWalletWithKey(keyPair);

    val req = prepareChangePublicKeyI(
        keyPair,
        seqnoHeader(0),
        wallet.address,
        keyPair,
        ENCRYPTED_OLD_PRIVATE_KEY,
    );
    val receipt = wallet.requestInternal(deployer.address, req, { value: ton("0.1") });

    expect(receipt).toHaveTx({ exitCode: Errors.NewKeyMustDiffer });
    expect(receipt.findExternalOutMessage()).toBeNull();
    expect(wallet.getPublicKey()).toEqual(keyPair.publicKey);
    expect(wallet.seqno()).toEqual(0);
}

get fun `test change-key: internal request can rotate the key repeatedly`() {
    val oldKey = crypto.generateKeyPair();
    val newKey = crypto.generateKeyPair();
    val thirdKey = crypto.generateKeyPair();
    val (wallet, deployer) = deployWalletWithKey(oldKey);

    val reqFirst = prepareChangePublicKeyI(
        oldKey,
        seqnoHeader(0),
        wallet.address,
        newKey,
        ENCRYPTED_OLD_PRIVATE_KEY,
    );
    val first = wallet.requestInternal(deployer.address, reqFirst, { value: ton("0.1") });
    expect(first).toHaveSuccessfulTx({ from: deployer.address, to: wallet.address });
    assertKeyChangedEvent(first, wallet.address, ENCRYPTED_OLD_PRIVATE_KEY);
    expect(wallet.getPublicKey()).toEqual(newKey.publicKey);
    expect(wallet.seqno()).toEqual(1);

    val reqSecond = prepareChangePublicKeyI(
        newKey,
        seqnoHeader(1),
        wallet.address,
        thirdKey,
        SECOND_ENCRYPTED_OLD_PRIVATE_KEY,
    );
    val second = wallet.requestInternal(deployer.address, reqSecond, { value: ton("0.1") });
    expect(second).toHaveSuccessfulTx({ from: deployer.address, to: wallet.address });
    assertKeyChangedEvent(second, wallet.address, SECOND_ENCRYPTED_OLD_PRIVATE_KEY);
    expect(wallet.getPublicKey()).toEqual(thirdKey.publicKey);
    expect(wallet.seqno()).toEqual(2);
}

get fun `test change-key: internal request rejects proof from the wrong key`() {
    val oldKey = crypto.generateKeyPair();
    val newKey = crypto.generateKeyPair();
    val (wallet, deployer) = deployWalletWithKey(oldKey);
    val wrongProof = createKeyRotationProof(wallet.address, oldKey);

    val req = prepareChangePublicKeyWithProofI(
        oldKey,
        seqnoHeader(0),
        newKey.publicKey,
        wrongProof,
        ENCRYPTED_OLD_PRIVATE_KEY,
    );
    val receipt = wallet.requestInternal(deployer.address, req, { value: ton("0.1") });

    expect(receipt).toHaveTx({ exitCode: Errors.NewKeySignatureIsInvalid });
    expect(receipt.findExternalOutMessage()).toBeNull();
    expect(wallet.getPublicKey()).toEqual(oldKey.publicKey);
    expect(wallet.seqno()).toEqual(0);
}

get fun `test change-key: a rotation the new key did not sign is rejected`() {
    val oldKey = crypto.generateKeyPair();
    val newKey = crypto.generateKeyPair();
    val (wallet, _) = deployWalletWithKey(oldKey);
    val wrongProof = createKeyRotationProof(wallet.address, oldKey);

    val req = prepareChangePublicKeyWithProofE(
        oldKey,
        seqnoHeader(0),
        newKey.publicKey,
        wrongProof,
        ENCRYPTED_OLD_PRIVATE_KEY,
    );
    val result = wallet.requestExternal(req);

    expect(result).toBeNotAccepted();
    expect(result).toHaveExternalVmExitCode(Errors.NewKeySignatureIsInvalid);
    expect(wallet.getPublicKey()).toEqual(oldKey.publicKey);
    expect(wallet.seqno()).toEqual(0);
}

get fun `test change-key: rotating to the same key is rejected`() {
    val keyPair = crypto.generateKeyPair();
    val (wallet, _) = deployWalletWithKey(keyPair);

    val req = prepareChangePublicKeyE(
        keyPair,
        seqnoHeader(0),
        wallet.address,
        keyPair,
        ENCRYPTED_OLD_PRIVATE_KEY,
    );
    val result = wallet.requestExternal(req);
    expect(result).toBeNotAccepted();
    expect(result).toHaveExternalVmExitCode(Errors.NewKeyMustDiffer);
    expect(wallet.getPublicKey()).toEqual(keyPair.publicKey);
    expect(wallet.seqno()).toEqual(0);
}

get fun `test change-key: a request the current key did not sign is rejected`() {
    val oldKey = crypto.generateKeyPair();
    val newKey = crypto.generateKeyPair();
    val attackerKey = crypto.generateKeyPair();
    val (wallet, _) = deployWalletWithKey(oldKey);

    val req = prepareChangePublicKeyE(
        attackerKey,
        seqnoHeader(0),
        wallet.address,
        newKey,
        ENCRYPTED_OLD_PRIVATE_KEY,
    );
    val forged = wallet.requestExternal(req);
    expect(forged).toBeNotAccepted();
    expect(forged).toHaveExternalVmExitCode(Errors.InvalidSignature);
    expect(wallet.getPublicKey()).toEqual(oldKey.publicKey);
    expect(wallet.seqno()).toEqual(0);
}

get fun `test change-key: a proof made for one wallet is rejected by another`() {
    val sharedKey = crypto.generateKeyPair();
    val newKey = crypto.generateKeyPair();
    val subwalletIdA: uint32 = DEFAULT_SUBWALLET_ID;
    val subwalletIdB: uint32 = DEFAULT_SUBWALLET_ID + 1;
    val (walletA, _) = deployWallet(makeStorage(sharedKey.publicKey, 0, subwalletIdA));
    val (walletB, _) = deployWallet(makeStorage(sharedKey.publicKey, 0, subwalletIdB));
    val proofForA = createKeyRotationProof(walletA.address, newKey);

    val reqB = prepareChangePublicKeyWithProofE(
        sharedKey,
        seqnoHeader(0, null, subwalletIdB),
        newKey.publicKey,
        proofForA,
        ENCRYPTED_OLD_PRIVATE_KEY,
    );
    val forB = walletB.requestExternal(reqB);
    expect(forB).toBeNotAccepted();
    expect(forB).toHaveExternalVmExitCode(Errors.NewKeySignatureIsInvalid);
    expect(walletB.getPublicKey()).toEqual(sharedKey.publicKey);
    expect(walletB.seqno()).toEqual(0);

    val reqA = prepareChangePublicKeyWithProofE(
        sharedKey,
        seqnoHeader(0, null, subwalletIdA),
        newKey.publicKey,
        proofForA,
        ENCRYPTED_OLD_PRIVATE_KEY,
    );
    val forA = walletA.requestExternal(reqA);
    expect(forA).toBeAccepted();
    expect(forA.unwrap()).toHaveTx({ exitCode: 0 });
    assertKeyChangedEvent(forA.unwrap(), walletA.address, ENCRYPTED_OLD_PRIVATE_KEY);
    expect(walletA.getPublicKey()).toEqual(newKey.publicKey);
    expect(walletA.seqno()).toEqual(1);
}
