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

/*
  NOTE: Even though Address inherits the Immutable API, it is considered
    best practice to not use it externally.
*/

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

  static setActive (address) {
    return address.set('tag', 0)
  }

  isArchived () {
    return !this.isActive()
  }

  static setArchived (address) {
    return address.set('tag', 2)
  }

  signMessage (message) {
    assert(Helpers.isString(message), 'Expected message to be a string')
    assert(!this.isWatchOnly(), 'Private key needed for message signing')
    assert(this.isUnEncrypted(), 'Cannot sign with an encrypted private key')

    let priv = this.getPrivateKey()
    let keyPair = Helpers.privateKeyStringToKey(priv, 'base58')

    keyPair.compressed = keyPair.getAddress() === this.getAddress();
    return Bitcoin.message.sign(keyPair, message, constants.getNetwork()).toString('base64')
  }

  encrypt (cipher) {
    if (this.isEncrypted()) throw new Error('Private key is already encrypted')
    return this.applyCipher(cipher)
  }

  decrypt (cipher) {
    if (this.isUnEncrypted()) throw new Error('Private key is not encrypted')
    return this.applyCipher(cipher)
  }

  applyCipher (cipher) {
    if (cipher == null || this.isWatchOnly()) return this
    let encryptedPriv = cipher(this.getPrivateKey())
    if (!encryptedPriv) throw new Error('Cipher failed')
    return this.set('priv', encryptedPriv)
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
    return Address.import(key, label)
  }

  static fromString (keyOrAddr, label, bipPass) {
    if (Helpers.isBitcoinAddress(keyOrAddr)) {
      return Promise.resolve(Address.import(keyOrAddr, label))
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
            function (key) { resolve(Address.import(key, label)) },
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
            return Address.import(myk, label)
          }
        ).catch(
          function (e) {
            myk.compressed = true
            return Promise.resolve(Address.import(myk, label))
          }
        )
      } else if (okFormats.indexOf(format) > -1) {
        var k = Helpers.privateKeyStringToKey(keyOrAddr, format)
        return Promise.resolve(Address.import(k, label))
      } else {
        return Promise.reject('unknown key format')
      }
    }
  }

  static import (key, label) {
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

    return new Address(object)
  }
}

module.exports = Address
