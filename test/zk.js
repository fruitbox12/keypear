const test = require('brittle')
const b4a = require('b4a')
const sodium = require('sodium-native')
const Keychain = require('../')

// Function to generate a real ZK proof using the Schnorr protocol
function generateZKSchnorrProof(scalar, publicKey) {
  console.log('\n===== Starting ZK Schnorr Proof Generation =====\n')

  console.time('Proof Generation Time')

  // Step 1: Generate a random nonce (r)
  const r = b4a.alloc(sodium.crypto_core_ed25519_SCALARBYTES)
  sodium.crypto_core_ed25519_scalar_random(r)
  console.log('🎲 Generated Random Nonce (r):', r.toString('hex'))

  // Step 2: Compute R = r * G (where G is the base point, in this case, the Ed25519 base point)
  const R = b4a.alloc(sodium.crypto_scalarmult_ed25519_BYTES)
  sodium.crypto_scalarmult_ed25519_base_noclamp(R, r)
  console.log('📍 Computed R (R = r * G):', R.toString('hex'))

  // Step 3: Compute challenge c = H(R || publicKey)
  const c = b4a.alloc(32)
  const hashInput = b4a.concat([R, publicKey])
  sodium.crypto_generichash(c, hashInput)
  console.log('🔑 Computed Challenge (c = H(R || publicKey)):', c.toString('hex'))

  // Step 4: Reduce the challenge c mod L to ensure it's a valid scalar
  const cReduced = b4a.alloc(sodium.crypto_core_ed25519_SCALARBYTES)
  sodium.crypto_core_ed25519_scalar_reduce(cReduced, c)

  // Step 5: Compute c * scalar mod L
  const cScalar = b4a.alloc(sodium.crypto_core_ed25519_SCALARBYTES)
  sodium.crypto_core_ed25519_scalar_mul(cScalar, cReduced, scalar)

  // Step 6: Compute s = r + c * scalar mod L
  const s = b4a.alloc(sodium.crypto_core_ed25519_SCALARBYTES)
  sodium.crypto_core_ed25519_scalar_add(s, r, cScalar)
  console.log('🔐 Computed Response (s = r + c * scalar):', s.toString('hex'))

  console.timeEnd('Proof Generation Time')
  console.log('\n===== ZK Schnorr Proof Generation Completed =====\n')

  return { R, s, publicKey }
}

// Function to verify the ZK proof using the Schnorr protocol
function verifyZKSchnorrProof(proof) {
  console.log('\n===== Starting ZK Schnorr Proof Verification =====\n')

  console.time('Proof Verification Time')

  const { R, s, publicKey } = proof

  // Step 1: Recompute the challenge c = H(R || publicKey)
  const c = b4a.alloc(32)
  const hashInput = b4a.concat([R, publicKey])
  sodium.crypto_generichash(c, hashInput)
  console.log('🔄 Recomputed Challenge (c = H(R || publicKey)):', c.toString('hex'))

  // Step 2: Reduce the challenge c mod L
  const cReduced = b4a.alloc(sodium.crypto_core_ed25519_SCALARBYTES)
  sodium.crypto_core_ed25519_scalar_reduce(cReduced, c)

  // Step 3: Verify that s * G = R + c * publicKey
  const sG = b4a.alloc(sodium.crypto_scalarmult_ed25519_BYTES)
  const cPK = b4a.alloc(sodium.crypto_scalarmult_ed25519_BYTES)
  const RPlusCPK = b4a.alloc(sodium.crypto_scalarmult_ed25519_BYTES)

  // s * G
  sodium.crypto_scalarmult_ed25519_base_noclamp(sG, s)

  // c * publicKey
  sodium.crypto_scalarmult_ed25519_noclamp(cPK, cReduced, publicKey)

  // R + c * publicKey
  sodium.crypto_core_ed25519_add(RPlusCPK, R, cPK)

  const isValid = b4a.equals(sG, RPlusCPK)
  console.log(isValid ? '✅ Proof is Valid' : '❌ Proof is Invalid')

  console.timeEnd('Proof Verification Time')
  console.log('\n===== ZK Schnorr Proof Verification Completed =====\n')

  return isValid
}

test('ZK Schnorr proof generation and verification', function (t) {
  console.log('\n🌟🌟🌟 Test: ZK Schnorr Proof Generation and Verification 🌟🌟🌟\n')

  const keys = new Keychain()
  const signer = keys.get()

  // Use the getProofComponents method to retrieve the public key and scalar
  const { publicKey, scalar } = signer.getProofComponents()
  console.log('🔑 Public Key:', publicKey.toString('hex'))
  console.log('🔐 Scalar (Private Key Component):', scalar.toString('hex'))

  // Generate the ZK proof using the Schnorr protocol
  const zkProof = generateZKSchnorrProof(scalar, publicKey)

  t.ok(zkProof, 'ZK Schnorr proof should be generated')

  // Verify the ZK proof
  const isValid = verifyZKSchnorrProof(zkProof)
  t.ok(isValid, 'ZK Schnorr proof should be valid')

  console.log('\n🎉 Test Completed 🎉\n')
})
