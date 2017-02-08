/* eslint-disable semi */

var Base58 = require('bs58')
var RNG = require('./rng')
var API = require('./api')
var Bitcoin = require('bitcoinjs-lib')
var Helpers = require('./helpers')
var ImportExport = require('./import-export')
var constants = require('./constants')
var assert = require('assert')
var { Record } = require('immutable')

const AddressRecord = Record({
  addr: null,
  priv: null,
  tag: 0,
  label: null,
  created_time: null,
  created_device_name: null,
  created_device_version: null
})

class Address extends AddressRecord {
  getAddress () {
    return this.get('addr')
  }

  getPrivateKey () {
    return this.get('priv')
  }

  isWatchOnly () {
    return this.getPrivateKey() === null
  }

  isEncrypted () {
    let priv = this.getPrivateKey()
    return Helpers.isBase64(priv) && !Helpers.isBase58Key(priv)
  }

  isUnEncrypted () {
    let priv = this.getPrivateKey()
    return Helpers.isBase58Key(priv)
  }

  getLabel () {
    return this.get('label')
  }

  static setLabel (address, label) {
    if (Helpers.isValidLabel(label) || label == null) {
      return address.set('label', label || null)
    } else {
      throw new Error('Address label must be an alphanumeric string')
    }
  }

  isActive () {
    return this.get('tag') === 0
  }

  isArchived () {
    return !this.isActive()
  }

  static setActive (address, active) {
    return address.set('tag', active ? 0 : 2)
  }

  signMessage (message, cipher) {
    assert(Helpers.isString(message), 'Expected message to be a string')
    assert(!this.isWatchOnly(), 'Private key needed for message signing')
    assert(this.isUnEncrypted() || cipher != null, 'Cipher needed to decrypt key')

    let address = this.isEncrypted() ? this.applyCipher(cipher) : this
    let priv = address.getPrivateKey()
    let keyPair = Helpers.privateKeyStringToKey(priv, 'base58')

    if (keyPair.getAddress() !== address.getAddress()) keyPair.compressed = false
    return Bitcoin.message.sign(keyPair, message, constants.getNetwork()).toString('base64')
  }

  applyCipher (cipher) {
    if (this.isWatchOnly()) return this
    let encryptedPriv = cipher(this.getPrivateKey())
    if (!encryptedPriv) throw new Error('Cipher failed')
    return this.set('privateKey', encryptedPriv)
  }

  toJSON () {
    return this.toJS()
  }

  static createNew (label) {
    let key = Bitcoin.ECPair.makeRandom({
      rng: RNG.run.bind(RNG),
      compressed: true,
      network: constants.getNetwork()
    })
    return Address.createFromKey(key, label)
  }

  static createFromObject (object) {
    return new Address().merge(object)
  }

  static createFromString (keyOrAddr, label, bipPass) {
    if (Helpers.isBitcoinAddress(keyOrAddr)) {
      return Promise.resolve(Address.createFromKey(keyOrAddr, label))
    } else {
      // Import private key
      var format = Helpers.detectPrivateKeyFormat(keyOrAddr)
      var okFormats = ['base58', 'base64', 'hex', 'mini', 'sipa', 'compsipa']
      if (format === 'bip38') {
        if (bipPass === undefined || bipPass === null || bipPass === '') {
          return Promise.reject('needsBip38')
        }

        var parseBIP38Wrapper = function (resolve, reject) {
          ImportExport.parseBIP38toECPair(keyOrAddr, bipPass,
            function (key) { resolve(Address.createFromKey(key, label)) },
            function () { reject('wrongBipPass') },
            function () { reject('importError') }
          )
        }
        return new Promise(parseBIP38Wrapper)
      } else if (format === 'mini' || format === 'base58') {
        try {
          var myk = Helpers.privateKeyStringToKey(keyOrAddr, format)
        } catch (e) {
          return Promise.reject(e)
        }
        myk.compressed = true
        var cad = myk.getAddress()
        myk.compressed = false
        var uad = myk.getAddress()
        return API.getBalances([cad, uad]).then(
          function (o) {
            var compBalance = o[cad].final_balance
            var ucompBalance = o[uad].final_balance
            if (compBalance === 0 && ucompBalance > 0) {
              myk.compressed = false
            } else {
              myk.compressed = true
            }
            return Address.createFromKey(myk, label)
          }
        ).catch(
          function (e) {
            myk.compressed = true
            return Promise.resolve(Address.createFromKey(myk, label))
          }
        )
      } else if (okFormats.indexOf(format) > -1) {
        var k = Helpers.privateKeyStringToKey(keyOrAddr, format)
        return Promise.resolve(Address.createFromKey(k, label))
      } else {
        return Promise.reject('unknown key format')
      }
    }
  }

  static createFromKey (key, label) {
    let object = {
      label,
      created_time: Date.now(),
      created_device_name: constants.APP_NAME,
      created_device_version: constants.APP_VERSION
    }

    switch (true) {
      case Helpers.isBitcoinAddress(key):
        object.addr = key
        object.priv = null
        break
      case Helpers.isKey(key):
        object.addr = key.getAddress()
        object.priv = Base58.encode(key.d.toBuffer(32))
        break
      case Helpers.isBitcoinPrivateKey(key):
        key = Bitcoin.ECPair.fromWIF(key, constants.getNetwork())
        object.addr = key.getAddress()
        object.priv = Base58.encode(key.d.toBuffer(32))
        break
      default:
        throw new Error('address import format not supported')
    }

    return new Address().createFromObject(object)
  }
}

module.exports = Address
