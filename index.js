// Ensure no trailing spaces on the following lines

const storage = require('./storage')
const sodium = require('sodium-native')
const b4a = require('b4a')
const snarkjs = require('snarkjs')
const fs = require('fs')

class Keychain {
  constructor (home = Keychain.keyPair(), base = null, tweak = null) {
    this.home = toScalarKeyPair(fromKeyPair(home))
    this.base = base || this.home
    this.tweak = tweak
    this.head = tweak
      ? add(tweak, this.base, allocKeyPair(!!this.base.scalar))
      : this.base
  }

  get isKeychain () {
    return true
  }

  get publicKey () {
    return this.head.publicKey
  }

  get (name) {
    if (!name) return createSigner(this.head)

    const keyPair = allocKeyPair(!!this.head.scalar)

    add(this.head, this._getTweak(name), keyPair)

    return createSigner(keyPair)
  }

  sub (name) {
    const tweak = this._getTweak(name)
    if (this.tweak) add(tweak, this.tweak, tweak)

    return new Keychain(this.home, this.base, tweak)
  }

  checkout (keyPair) {
    return new Keychain(this.home, fromKeyPair(keyPair), null)
  }

  _getTweak (name) {
    if (typeof name === 'string') name = b4a.from(name)
    if (!b4a.isBuffer(name)) return name // keypair

    return tweakKeyPair(toBuffer(name), this.head.publicKey)
  }

  static async open (filename) {
    return new this(this.keyPair(await storage.open(filename)))
  }

  static openSync (filename) {
    return new this(this.keyPair(storage.openSync(filename)))
  }

  static from (k) {
    if (this.isKeychain(k)) { // future compat
      return k instanceof this ? k : new this(k.home, k.base, k.tweak)
    }
    return new this(k)
  }

  static verify (signable, signature, publicKey) {
    return sodium.crypto_sign_verify_detached(signature, signable, publicKey)
  }

  static isKeychain (k) {
    return !!(k && k.isKeychain)
  }

  static seed () {
    const buf = b4a.alloc(32)
    sodium.randombytes_buf(buf)
    return buf
  }

  static keyPair (seed) {
    const buf = b4a.alloc(96)
    const publicKey = buf.subarray(0, 32)
    const secretKey = buf.subarray(32, 96)
    const scalar = secretKey.subarray(0, 32)

    if (seed) sodium.crypto_sign_seed_keypair(publicKey, secretKey, seed)
    else sodium.crypto_sign_keypair(publicKey, secretKey)

    sodium.extension_tweak_ed25519_sk_to_scalar(scalar, secretKey)

    return {
      publicKey,
      scalar
    }
  }

  // Method to generate a zk-SNARK proof
  async generateSnarkProof (message) {
    const signer = createSigner(this.head)
    const { publicKey, scalar } = signer.getProofComponents()
  
    // Check scalar size and content
    if (scalar.length !== 32) {
      throw new Error(`Unexpected scalar size: ${scalar.length} bytes. Expected 32 bytes.`);
    }
  
    // Convert to hex and prepend '0x' to ensure proper BigInt conversion
    const input = {
      privKey: `0x${b4a.toString(scalar, 'hex')}`,
      pubKey: `0x${b4a.toString(publicKey, 'hex')}`,
      messageHash: `0x${b4a.toString(message, 'hex')}`
    }
  
    console.log('Input Scalar:', input.privKey);
    console.log('Input Public Key:', input.pubKey);
  
    // Load the circuit compiled files
    const wasmFile = './keyownership.wasm'
    const zkeyFile = './keyownership_final.zkey'
  
    // Generate the proof
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmFile, zkeyFile)
  
    return { proof, publicSignals }
}

  // Method to verify a zk-SNARK proof
  static async verifySnarkProof (proof, publicSignals) {
    const vkey = JSON.parse(fs.readFileSync('./verification_key.json'))

    const isValid = await snarkjs.groth16.verify(vkey, publicSignals, proof)
    return isValid
  }
}

module.exports = Keychain

function add (a, b, out) {
  sodium.extension_tweak_ed25519_pk_add(out.publicKey, a.publicKey, b.publicKey)
  if (a.scalar && b.scalar) {
    sodium.extension_tweak_ed25519_scalar_add(out.scalar, a.scalar, b.scalar)
  }
  return out
}

function fromKeyPair (keyPair) {
  if (b4a.isBuffer(keyPair)) return { publicKey: keyPair, scalar: null }
  return toScalarKeyPair(keyPair)
}

function allocKeyPair (signer) {
  const buf = b4a.alloc(signer ? 64 : 32)
  return {
    publicKey: buf.subarray(0, 32),
    scalar: signer ? buf.subarray(32, 64) : null
  }
}

function toScalarKeyPair (keyPair) {
  if (!keyPair.secretKey) return keyPair

  const scalar = b4a.alloc(32)
  sodium.extension_tweak_ed25519_sk_to_scalar(scalar, keyPair.secretKey)
  return { publicKey: keyPair.publicKey, scalar }
}

function tweakKeyPair (name, prev) {
  const keyPair = allocKeyPair(true)
  const seed = b4a.allocUnsafe(32)
  sodium.crypto_generichash_batch(seed, [prev, name])
  sodium.extension_tweak_ed25519_base(keyPair.scalar, keyPair.publicKey, seed)
  return keyPair
}

function createSigner (kp) {
  if (kp.scalar) {
    return {
      publicKey: kp.publicKey,
      scalar: kp.scalar,
      writable: true,
      dh (publicKey) {
        const output = b4a.alloc(sodium.crypto_scalarmult_ed25519_BYTES)

        sodium.crypto_scalarmult_ed25519_noclamp(
          output,
          kp.scalar,
          publicKey
        )

        return output
      },
      sign (signable) {
        const sig = b4a.alloc(sodium.crypto_sign_BYTES)
        sodium.extension_tweak_ed25519_sign_detached(sig, signable, kp.scalar)
        return sig
      },
      verify,
      // Expose components for manual ZK proof generation
      getProofComponents () {
        return {
          publicKey: kp.publicKey,
          scalar: kp.scalar
        }
      }
    }
  }

  return {
    publicKey: kp.publicKey,
    scalar: null,
    writable: false,
    dh: null,
    sign: null,
    verify
  }

  function verify (signable, signature) {
    return sodium.crypto_sign_verify_detached(signature, signable, kp.publicKey)
  }
}

function toBuffer (buf) {
  return typeof buf === 'string' ? b4a.from(buf) : buf
}
