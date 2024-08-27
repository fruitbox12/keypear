template KeyOwnership() {
    signal input privKey;      // The private key (scalar)
    signal input pubKey;       // The public key
    signal input messageHash;  // The message hash

    signal output expectedPubKey;
    signal output isEqual;

    signal privKeySquare;
    privKeySquare <== privKey * privKey;

    expectedPubKey <== privKeySquare + messageHash;

    isEqual <== pubKey - expectedPubKey;

    // We cannot directly compare here; instead, use a conditional output in another circuit
}

component main = KeyOwnership();

