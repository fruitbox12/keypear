const storage = require('./storage')
const sodium = require('sodium-native')
const b4a = require('b4a')

class Keychain {
  constructor(home = Keychain.keyPair(), base = null, tweak = null) {
    this.home = toScalarKeyPair(fromKeyPair(home))
    this.base = base || this.home
    this.tweak = tweak
    this.head = tweak
      ? add(this.tweak, this.base, allocKeyPair(!!this.base.scalar))
      : this.base
  }

  get isKeychain() {
    return true
  }

  get publicKey() {
    return this.head.publicKey
  }

  get(name) {
    if (!name) return createSigner(this.head)

    const keyPair = allocKeyPair(!!this.head.scalar)
    add(this.head, this._getTweak(name), keyPair)

    return createSigner(keyPair)
  }

  sub(name) {
    const tweak = this._getTweak(name)
    if (this.tweak) add(tweak, this.tweak, tweak)

    return new Keychain(this.home, this.base, tweak)
  }

  checkout(keyPair) {
    return new Keychain(this.home, fromKeyPair(keyPair), null)
  }

  _getTweak(name) {
    if (typeof name === 'string') name = b4a.from(name)
    if (!b4a.isBuffer(name)) return name // keypair

    return tweakKeyPair(toBuffer(name), this.head.publicKey)
  }

  static async open(filename) {
    const data = await storage.open(filename)
    return new this(this.keyPair(data))
  }

  static openSync(filename) {
    const data = storage.openSync(filename)
    return new this(this.keyPair(data))
  }

  static from(k) {
    if (this.isKeychain(k)) {
      return k instanceof this ? k : new this(k.home, k.base, k.tweak)
    }
    return new this(k)
  }

  static verify(signable, signature, publicKey) {
    return sodium.crypto_sign_verify_detached(signature, signable, publicKey)
  }

  static isKeychain(k) {
    return !!(k && k.isKeychain)
  }

  static seed() {
    const buf = b4a.alloc(32)
    sodium.randombytes_buf(buf)
    return buf
  }

  static keyPair(seed) {
    const buf = b4a.alloc(96)
    const publicKey = buf.subarray(0, 32)
    const secretKey = buf.subarray(32, 96)
    const scalar = secretKey.subarray(0, 32)

    if (seed) {
      sodium.crypto_sign_seed_keypair(publicKey, secretKey, seed)
    } else {
      sodium.crypto_sign_keypair(publicKey, secretKey)
    }

    sodium.crypto_core_ed25519_scalar_reduce(scalar, scalar)

    return {
      publicKey,
      scalar
    }
  }
}

module.exports = Keychain

function add(a, b, out) {
  sodium.crypto_core_ed25519_add(out.publicKey, a.publicKey, b.publicKey)
  if (a.scalar && b.scalar) {
    sodium.crypto_core_ed25519_scalar_add(out.scalar, a.scalar, b.scalar)
  }
  return out
}

function fromKeyPair(keyPair) {
  if (b4a.isBuffer(keyPair)) return { publicKey: keyPair, scalar: null }
  return toScalarKeyPair(keyPair)
}

function allocKeyPair(signer) {
  const buf = b4a.alloc(signer ? 64 : 32)
  return {
    publicKey: buf.subarray(0, 32),
    scalar: signer ? buf.subarray(32, 64) : null
  }
}

function toScalarKeyPair(keyPair) {
  if (!keyPair.secretKey) return keyPair

  const scalar = b4a.alloc(32)
  sodium.crypto_core_ed25519_scalar_reduce(scalar, keyPair.secretKey.subarray(0, 32))
  return { publicKey: keyPair.publicKey, scalar }
}

function tweakKeyPair(name, prev) {
  const keyPair = allocKeyPair(true)
  const seed = b4a.allocUnsafe(32)
  sodium.crypto_generichash_batch(seed, [prev, name])
  sodium.crypto_scalarmult_ed25519_base(keyPair.publicKey, seed)
  sodium.crypto_core_ed25519_scalar_reduce(keyPair.scalar, seed)
  return keyPair
}

function createSigner(kp) {
  if (kp.scalar) {
    return {
      publicKey: kp.publicKey,
      scalar: kp.scalar,
      writable: true,
      dh(publicKey) {
        const output = b4a.alloc(sodium.crypto_scalarmult_ed25519_BYTES)
        sodium.crypto_scalarmult_ed25519(output, kp.scalar, publicKey)
        return output
      },
      sign(signable) {
        const sig = b4a.alloc(sodium.crypto_sign_BYTES)
        sodium.crypto_sign_detached(sig, signable, kp.scalar)
        return sig
      },
      verify,
      getProofComponents() {
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

  function verify(signable, signature) {
    return sodium.crypto_sign_verify_detached(signature, signable, kp.publicKey)
  }
}

function toBuffer(buf) {
  return typeof buf === 'string' ? b4a.from(buf) : buf
}
