const Tx = require('ethereumjs-tx').Transaction
const { getAdminWallet } = require('../services/wallet-management/admin')
const web3 = require('./web3')
const { getNonce } = require('../utilities/nonceManager')
const config = require('../config')
const common = require('ethereumjs-common')
const KMSHelper = require('./kms')
const logger = require('../utilities/logger')

const chain = common.default.forCustomChain(
  'mainnet', {
    name: 'bnb',
    networkId: config.CHAIN_ID[config.BNB.NETWORK.CHAIN_NAME],
    chainId: config.CHAIN_ID[config.BNB.NETWORK.CHAIN_NAME]
  },
  'petersburg'
)

const createTxByKms = async (txObject) => {
  const KEY = config.KMS.TRANSACTION_KEY

  const adminAddress = await KMSHelper.getEthereumAddress(KEY)

  logger.debug('ADMIN BALANCE:', await web3.eth.getBalance(adminAddress))
  txObject.from = web3.utils.toChecksumAddress(adminAddress)

  const gasPrice = await web3.eth.getGasPrice()
  txObject.gasPrice = web3.utils.toHex(gasPrice)

  const nonceCount = await getNonce(adminAddress)
  txObject.nonce = web3.utils.toHex(nonceCount)

  txObject.gasLimit = await web3.eth.estimateGas({
    to: txObject.to,
    data: txObject.data,
    nonce: txObject.nonce,
    from: adminAddress
  })

  const chainId = await web3.eth.getChainId()
  txObject.chainId = chainId

  // KMS signing
  const fetchSign = await KMSHelper.fetchSignature(KEY)

  // Setting up r,s,v in rawTransaction
  txObject.r = fetchSign.r
  txObject.s = fetchSign.s
  txObject.v = fetchSign.v

  const tx = new Tx(txObject, { common: chain })
  // KMS signing
  const txHash = tx.hash(false)
  const serializedTx = await KMSHelper.fetchSerializedTx(txHash, tx, KEY)

  return serializedTx
}

module.exports = createTxByKms
