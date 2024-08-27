const test = require('brittle')
const b4a = require('b4a')
const Keychain = require('../')

test('ZK-SNARK proof generation and verification', async function (t) {
  t.plan(4)

  const keys = new Keychain()

  const signer = keys.get()

  const message = b4a.from('Test message')

  // Generate a signature for the message
  const signature = signer.sign(message)

  t.ok(signature, 'Signature should be generated')

  // Generate ZK-SNARK proof using the Keychain method
  const zkProof = await keys.generateSnarkProof(message)

  t.ok(zkProof.proof, 'ZK-SNARK proof should be generated')
  t.ok(zkProof.publicSignals, 'Public signals should be generated')

  // Verify the ZK-SNARK proof using the Keychain method
  const isValid = await Keychain.verifySnarkProof(zkProof.proof, zkProof.publicSignals)

  t.ok(isValid, 'ZK-SNARK proof should be valid')
})
