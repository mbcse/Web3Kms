const { KMS } = require('aws-sdk')
const asn1 = require('asn1.js')
const { keccak256 } = require('js-sha3')
const { ecrecover, pubToAddress, bufferToHex, keccak } = require('ethereumjs-util')
const BN = require('bn.js')
const ethers = require('ethers')

const config = require('../config')
const logger = require('../utilities/logger')

const chainId = 97 // BSC Testnet

const kms = new KMS({
  accessKeyId: config.KMS.AWS_ACCESS_KEY_ID,
  secretAccessKey: config.KMS.AWS_SECRET_ACCESS_KEY,
  region: config.KMS.REGION,
  apiVersion: config.KMS.API_VERSION
})

const fetchSerializedTx = async (txHash, tx, key) => {
  // Get the ethereum address
  const ethAddr = await getEthereumAddress(key)

  // Calculating the Ethereum Signature - r and s
  const sig = await findEthereumSig(txHash, key)

  //  Finding the right v value
  const recoveredPubAddr = await findRightKey(txHash, sig.r, sig.s, ethAddr)

  tx.r = sig.r.toBuffer()
  tx.s = sig.s.toBuffer()
  const v = (recoveredPubAddr.v - 27) + chainId * 2 + 35
  tx.v = new BN(v).toBuffer()

  // console.log(tx)

  const serializedTx = tx.serialize().toString('hex')
  // logger.info(`0x${serializedTx}`);

  return '0x' + serializedTx
}

const fetchSignature = async (key) => {
  // Get the ethereum address
  const ethAddr = await getEthereumAddress(key)

  const ethAddrHash = keccak(Buffer.from(ethAddr))

  // Calculating the Ethereum Signature - r and s
  const sig = await findEthereumSig(ethAddrHash, key)

  //  Finding the right v value
  const recoveredPubAddr = await findRightKey(ethAddrHash, sig.r, sig.s, ethAddr)
  // logger.info('Admin :' + recoveredPubAddr.pubKey);
  const v = (recoveredPubAddr.v - 27) + chainId * 2 + 35

  const obj = {
    r: sig.r.toBuffer(),
    s: sig.s.toBuffer(),
    v: v
  }
  return obj
}

const getEthereumAddress = async (key) => {
  const publicKey = await kms
    .getPublicKey({
      KeyId: config.KMS.KEY_IDS[key]
    })
    .promise()

  const decoded = EcdsaPubKey.decode(publicKey.PublicKey, 'der')
  let pubKeyBuffer = decoded.pubKey.data

  pubKeyBuffer = pubKeyBuffer.slice(1, pubKeyBuffer.length)
  const address = keccak256(pubKeyBuffer) // keccak256 hash of publicKey
  const buf2 = Buffer.from(address, 'hex')
  const EthAddr = '0x' + buf2.slice(-20).toString('hex') // take last 20 bytes as ethereum adress
  // logger.info('Generated address: ' + EthAddr)
  return EthAddr
}

/*
        According to EIP-2, allowing transactions with any s value (from 0 to the max number on the secp256k1n curve),
        opens a transaction malleability concern. This is why a signature with a value of s > secp256k1n / 2 (greater than half of the curve) is invalid,
        i.e. it is a valid ECDSA signature but from an Ethereum perspective the signature is on the dark side of the curve.
    */

const findEthereumSig = async (plaintext, key) => {
  const signature = await sign(plaintext, key)
  if (signature.Signature == undefined) {
    throw new Error('UNKNOWN_SIGNATURE')
  }

  const decoded = EcdsaSigAsnParse.decode(signature.Signature, 'der')
  const r = decoded.r
  let s = decoded.s

  const secp256k1N = new BN('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 16) // max value on the curve
  const secp256k1halfN = secp256k1N.div(new BN(2)) // half of the curve
  // Because of EIP-2 not all elliptic curve signatures are accepted
  // the value of s needs to be SMALLER than half of the curve
  // i.e. we need to flip s if it's greater than half of the curve
  if (s.gt(secp256k1halfN)) {
    // According to EIP2 https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2.md
    // if s < half the curve we need to invert it
    // s = curve.n - s
    s = secp256k1N.sub(s)
    return { r, s }
  }
  // if s is less than half of the curve, we're on the "good" side of the curve, we can just return
  return { r, s }
}

const sign = async (msgHash, key) => {
  const params = {
    KeyId: config.KMS.KEY_IDS[key],
    Message: msgHash,
    SigningAlgorithm: 'ECDSA_SHA_256',
    MessageType: 'DIGEST'
  }
  const res = await kms.sign(params).promise()
  return res
}

const findRightKey = async (msg, r, s, expectedEthAddr) => {
  // This is the wrapper function to find the right v value
  // There are two matching signatues on the elliptic curve
  // we need to find the one that matches to our public key
  // it can be v = 27 or v = 28
  let v = 27
  let pubKey = recoverPubKeyFromSig(msg, r, s, v)
  if (pubKey != expectedEthAddr) {
    // if the pub key for v = 27 does not match
    // it has to be v = 28
    v = 28
    pubKey = recoverPubKeyFromSig(msg, r, s, v)
  }
  return { pubKey, v }
}

const recoverPubKeyFromSig = (msg, r, s, v) => {
  const rBuffer = r.toBuffer()
  const sBuffer = s.toBuffer()
  const pubKey = ecrecover(msg, v, rBuffer, sBuffer)
  const addrBuf = pubToAddress(pubKey)
  const RecoveredEthAddr = bufferToHex(addrBuf)
  return RecoveredEthAddr
}

const EcdsaPubKey = asn1.define('EcdsaPubKey', function () {
  this.seq().obj(
    this.key('algo').seq().obj(this.key('a').objid(), this.key('b').objid()),
    this.key('pubKey').bitstr()
  )
})

const EcdsaSigAsnParse = asn1.define('EcdsaSig', function () {
  this.seq().obj(this.key('r').int(), this.key('s').int())
})

const signDigest = async (digestString, key) => {
  const digestBuffer = Buffer.from(ethers.utils.arrayify(digestString))
  const sig = await findEthereumSig(digestBuffer, key)
  const ethAddr = await getEthereumAddress(key)
  const { v } = await findRightKey(digestBuffer, sig.r, sig.s, ethAddr)
  const vv = (v - 27) + chainId * 2 + 35

  return ethers.utils.joinSignature({
    v: vv,
    r: `0x${sig.r.toString('hex')}`,
    s: `0x${sig.s.toString('hex')}`
  })
}

const signTypedData = async (domain, types, value, key) => {
  const hash = ethers.utils._TypedDataEncoder.hash(domain, types, value)
  return signDigest(hash, key)
}

module.exports = {
  fetchSerializedTx,
  fetchSignature,
  getEthereumAddress,
  findEthereumSig,
  sign,
  findRightKey,
  recoverPubKeyFromSig,
  signTypedData
}

// getEthereumAddress('ADMIN').then((res) => {
//   console.log(res)
// }).catch((err) => {
//   console.log(err)
// })
