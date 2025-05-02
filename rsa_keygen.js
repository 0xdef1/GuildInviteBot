global.window = this

const JSEncrypt = require('jsencrypt')
const { createHash } = require("node:crypto")
const { BigInteger } = require('jsbn')

// New keys:
let jse = new JSEncrypt({'default_key_size': 256})
console.log("generating key")
console.log(jse.getKey().getPublicKey())
console.log(jse.getKey().getPrivateKey())
console.log(`shared: ${jse.getKey().n.toString()}`) // Decimal representation suitable for use in LUA
console.log(`public: ${jse.getKey().e.toString()}`)
console.log(`private: ${jse.getKey().d.toString()}`)

// Test with existing key instead:
// privateKey is PEM string i.e. starting with -----BEGIN RSA PRIVATE KEY-----
// jse.setKey(privateKey) 

console.log(jse.getKey().n.bitLength())
const maxLength = (jse.getKey().n.bitLength() + 7) >> 3;
console.log(maxLength)

let message = "This is an arbitrarily long message that is much longer than the key size asdf"

console.log(message.length)

let digest = function(msg) {
    let hash = createHash('sha256').update(msg).digest('hex')
    console.log(hash)
    return hash.substring(32)
}

console.log(digest(message))
console.log(digest(message).length)

let raw = new BigInteger(digest(message), 16)
console.log(raw.toString())
let sig = jse.getKey().doPrivate(raw)
console.log(sig.toString())
console.log(sig.toString(16))
let verify = jse.getKey().doPublic(sig)
console.log(verify.toString())
