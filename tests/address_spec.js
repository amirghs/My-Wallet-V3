let Bitcoin = require('bitcoinjs-lib');

let proxyquire = require('proxyquireify')(require);

let MyWallet = {
  wallet: {
    sharedKey: 'shared_key',
    pbkdf2_iterations: 5000,
    getHistory: function () {},
    syncWallet: function () {}
  }
};

Bitcoin = {
  ECPair: {
    makeRandom: function (options) {
      let pk;
      pk = options.rng(32);
      return {
        getAddress: function () {
          return 'random_address';
        },
        pub: {},
        d: {
          toBuffer: function () {
            return pk;
          }
        }
      };
    },
    fromWIF: function (wif) {
      return {
        getAddress: function () {
          return `pub_key_for_${wif}`;
        },
        d: {
          toBuffer: function () {
            return `${wif}_private_key_buffer`;
          }
        }
      };
    }
  },
  message: {
    sign: function (keyPair, message) {
      return `${message}_signed`;
    }
  }
};

let Base58 = {
  encode: function (v) {
    return v;
  }
};

let API = {
  getBalances: function (l) {
    let ad1;
    let ad2;
    let o;
    ad1 = l[0];
    ad2 = l[1];
    o = {};
    if (ad1 === 'mini_2') {
      o[ad1] = {
        final_balance: 0
      };
      o[ad2] = {
        final_balance: 10
      };
    } else {
      o[ad1] = {
        final_balance: 10
      };
      o[ad2] = {
        final_balance: 0
      };
    }
    return Promise.resolve(o);
  }
};

let Helpers = {
  isBitcoinAddress: function () {
    return false;
  },
  isKey: function () {
    return true;
  },
  isBitcoinPrivateKey: function () {
    return false;
  },
  privateKeyStringToKey: function (priv, format) {
    return {
      priv,
      getAddress: function () {
        return '1HaxXWGa5cZBUKNLzSWWtyDyRiYLWff8FN';
      }
    };
  }
};

let RNG = {
  run: function (input) {
    if (RNG.shouldThrow) {
      throw new Error('Connection failed');
    }
    return '1111111111111111111111111111111H';
  }
};

let ImportExport = {
  parseBIP38toECPair: function (b58, pass, succ, wrong, error) {
    if (pass === 'correct') {
      return succ('5KUwyCzLyDjAvNGN4qmasFqnSimHzEYVTuHLNyME63JKfVU4wiU');
    } else if (pass === 'wrong') {
      return wrong();
    } else if (pass === 'fail') {
      return error();
    }
  }
};

let WalletCrypto = {
  decryptSecretWithSecondPassword: function (data, pw) {
    return `${data}_decrypted_with_${pw}`;
  }
};

let stubs = {
  './wallet': MyWallet,
  './rng': RNG,
  './api': API,
  './import-export': ImportExport,
  './wallet-crypto': WalletCrypto,
  './helpers': Helpers,
  'bitcoinjs-lib': Bitcoin,
  'bs58': Base58
};

let Address = proxyquire('../src/address', stubs);

fdescribe('Address', () => {
  let object = {
    'addr': '1HaxXWGa5cZBUKNLzSWWtyDyRiYLWff8FN',
    'priv': 'GFZrKdb4tGWBWrvkjwRymnhGX8rfrWAGYadfHSJz36dF',
    'label': 'my label',
    'tag': 0,
    'created_time': 0,
    'created_device_name': 'javascript-web',
    'created_device_version': '1.0'
  };

  beforeEach(() => {
    spyOn(MyWallet, 'syncWallet');
    spyOn(MyWallet.wallet, 'getHistory');
  });

  describe('class', () => {
    describe('new Address()', () => {
      it('should create an empty Address with default options', () => {
        let a = new Address();
        // expect(a.balance).toEqual(null);
        expect(a.isActive()).toBeTruthy();
        expect(a.isArchived()).not.toBeTruthy();
        expect(a.isWatchOnly()).toBeTruthy();
      });

      it('should transform an Object to an Address', () => {
        let a = new Address(object);
        expect(a.addr).toEqual(object.addr);
        expect(a.priv).toEqual(object.priv);
        expect(a.label).toEqual(object.label);
        expect(a.created_time).toEqual(object.created_time);
        expect(a.created_device_name).toEqual(object.created_device_name);
        expect(a.created_device_version).toEqual(object.created_device_version);
        expect(a.isActive()).toBeTruthy();
        expect(a.isArchived()).not.toBeTruthy();
        expect(a.isWatchOnly()).not.toBeTruthy();
      });
    });

    describe('Address.createNew()', () => {
      beforeEach(() => {
        spyOn(Bitcoin.ECPair, 'makeRandom').and.callThrough();
        spyOn(RNG, 'run').and.callThrough();
        Helpers.isBitcoinAddress = () => false;
        Helpers.isKey = () => true;
        Helpers.isBitcoinPrivateKey = () => false;
      });

      it('should return an address', () => {
        let a = Address.createNew('My New Address');
        expect(a.label).toEqual('My New Address');
      });

      it('should generate a random private key', () => {
        let a = Address.createNew('My New Address');
        expect(a.priv).toBe('1111111111111111111111111111111H');
      });

      it('should generate a random address', () => {
        let a = Address.createNew('My New Address');
        expect(a.addr).toBe('random_address');
      });

      it('should call Bitcoin.ECPair.makeRandom with our RNG', () => {
        Address.createNew('My New Address');
        expect(Bitcoin.ECPair.makeRandom).toHaveBeenCalled();
        expect(RNG.run).toHaveBeenCalled();
      });

      it('should throw if RNG throws', () => {
        RNG.shouldThrow = true;
        expect(() => Address.createNew('My New Address')).toThrow(Error('Connection failed'));
      });
    });

    describe('static', () => {
      let a;
      beforeEach(() => { a = new Address(object); });

      describe('Address.setLabel()', () => {
        it('label should set a new label', () => {
          let next = Address.setLabel(a, 'my new label');
          expect(next.label).toEqual('my new label');
        });

        it('label should be alphanumerical', () => {
          let invalid = () => { Address.setLabel(a, 1); };
          expect(invalid).toThrow();
        });

        it('label should be null if set to empty string', () => {
          let next = Address.setLabel(a, '');
          expect(next.label).toEqual(null);
        });
      });

      describe('Address.setActive()', () => {
        it('should make the address active', () => {
          let next = Address.setActive(a);
          expect(next.isActive()).toBeTruthy();
        });
      });

      describe('Address.setArchived()', () => {
        it('should return an archived address', () => {
          let next = Address.setArchived(a);
          expect(next.isArchived()).toBeTruthy();
        });

        it('should archive a list of addresses', () => {
          let addresses = [a, a, a];
          let allArchived = addresses.map(Address.setArchived);
          expect(addresses.every(a => a.isActive())).toEqual(true);
          expect(allArchived.every(a => a.isArchived())).toEqual(true);
        });
      });
    });
  });

  describe('instance', () => {
    let a;

    beforeEach(() => {
      a = new Address(object);
    });

    describe('immutable', () => {
      it('should have an immutable private key', () => {
        expect(() => { a.priv = 'not allowed'; }).toThrow();
        expect(a.priv).toEqual('GFZrKdb4tGWBWrvkjwRymnhGX8rfrWAGYadfHSJz36dF');
      });

      it('address is read only', () => {
        expect(() => { a.addr = 'not allowed'; }).toThrow();
        expect(a.addr).toEqual('1HaxXWGa5cZBUKNLzSWWtyDyRiYLWff8FN');
      });
    });

    // TODO: figure out what to do about ephemeral properties like `balance`
    xdescribe('Setter', () => {
      it('balance should be set and not sync wallet', () => {
        a.balance = 100;
        expect(a.balance).toEqual(100);
        expect(MyWallet.syncWallet).not.toHaveBeenCalled();
      });

      it('balance should throw exception if is non-Number set', () => {
        let wrongSet;
        wrongSet = () => { a.balance = 'failure'; };
        expect(wrongSet).toThrow();
      });

      it('totalSent must be a number', () => {
        let invalid = () => { a.totalSent = '1'; };
        let valid = () => { a.totalSent = 1; };
        expect(invalid).toThrow();
        expect(a.totalSent).toEqual(null);
        expect(valid).not.toThrow();
        expect(a.totalSent).toEqual(1);
      });

      it('totalReceived must be a number', () => {
        let invalid = () => { a.totalReceived = '1'; };
        let valid = () => { a.totalReceived = 1; };
        expect(invalid).toThrow();
        expect(a.totalReceived).toEqual(null);
        expect(valid).not.toThrow();
        expect(a.totalReceived).toEqual(1);
      });
    });

    describe('.signMessage()', () => {
      it('should sign a message', () => {
        expect(a.signMessage('message')).toEqual('message_signed');
      });

      it('should decrypt and sign a message', () => {
        let enc = a.set('priv', 'encrypted_key');
        let signedMessage = enc.decrypt(() => a.priv).signMessage('message');
        expect(signedMessage).toEqual('message_signed');
      });

      it('should fail when not passed a bad message', () => {
        expect(a.signMessage.bind(a)).toThrow(Error('Expected message to be a string'));
      });

      it('should fail when encrypted', () => {
        let enc = a.set('priv', 'encpriv');
        expect(enc.signMessage.bind(enc, 'message')).toThrow(Error('Cannot sign with an encrypted private key'));
      });

      it('should fail when called on a watch only address', () => {
        let watchOnly = a.set('priv', null);
        expect(watchOnly.signMessage.bind(watchOnly, 'message')).toThrow(Error('Private key needed for message signing'));
      });

      it('should convert to base64', () => {
        let spy = jasmine.createSpy('toString');
        spyOn(Bitcoin.message, 'sign').and.returnValue({ toString: spy });
        a.signMessage('message');
        expect(spy).toHaveBeenCalledWith('base64');
      });

      it('should try compressed format if the address does not match', () => {
        let keyPair = {
          getAddress () { return 'uncomp_address'; },
          compressed: true
        };
        spyOn(Helpers, 'privateKeyStringToKey').and.returnValue(keyPair);
        a.signMessage('message');
        expect(keyPair.compressed).toEqual(false);
      });
    });

    describe('.encrypt', () => {
      it('should fail when encryption fails', () => {
        let wrongEnc = () => a.encrypt(() => null);
        expect(wrongEnc).toThrow();
      });

      it('should encrypt the private key', () => {
        let enc = a.encrypt(() => 'encrypted_key');
        expect(enc.priv).toEqual('encrypted_key');
      });

      it('should do nothing if watch only address', () => {
        let watchOnly = a.set('priv', null);
        let enc = watchOnly.encrypt(() => 'encrypted_key');
        expect(enc.priv).toEqual(null);
      });

      it('should do nothing if no cipher provided', () => {
        let enc = a.encrypt(void 0);
        expect(enc.priv).toEqual(a.priv);
      });
    });

    describe('.decrypt', () => {
      let enc;
      beforeEach(() => { enc = a.set('priv', 'encrypted_key'); });

      it('should fail when decryption fails', () => {
        let wrongEnc = () => enc.decrypt(() => null);
        expect(wrongEnc).toThrow();
      });

      it('should write in a temporary field and let the original key intact', () => {
        let dec = enc.decrypt(() => 'decrypted_key');
        expect(dec.priv).toEqual('decrypted_key');
      });

      it('should do nothing if watch only address', () => {
        let watchOnly = enc.set('priv', null);
        let dec = watchOnly.decrypt(() => 'decrypted_key');
        expect(dec.priv).toEqual(null);
      });

      it('should do nothing if no cipher provided', () => {
        let dec = enc.decrypt(void 0);
        expect(dec.priv).toEqual(enc.priv);
      });
    });

    describe('JSON serializer', () => {
      let parse = (json) => JSON.parse(json);
      let stringify = (o) => JSON.stringify(o, null, 2);

      it('should hold: fromJSON . toJSON = id', () => {
        let b = parse(stringify(a));
        expect(a.toJSON()).toEqual(b);
      });

      it('should hold: fromJSON . toJSON = id for watchOnly addresses', () => {
        let withoutPriv = a.set('priv', null);
        let b = parse(stringify(withoutPriv));
        expect(withoutPriv.toJSON()).toEqual(b);
      });

      it('should not serialize non-expected fields', () => {
        a.rarefield = 'I am an intruder';
        let b = JSON.parse(stringify(a));
        expect(b.addr).toBeDefined();
        expect(b.priv).toBeDefined();
        expect(b.tag).toBeDefined();
        expect(b.label).toBeDefined();
        expect(b.created_time).toBeDefined();
        expect(b.created_device_name).toBeDefined();
        expect(b.created_device_version).toBeDefined();
        expect(b.rarefield).not.toBeDefined();
        expect(b._temporary_priv).not.toBeDefined();
      });

      it('should not deserialize non-expected fields', () => {
        let b = JSON.parse(stringify(a));
        b.rarefield = 'I am an intruder';
        let bb = new Address(b);
        expect(bb.toJSON()).toEqual(a.toJSON());
      });
    });

    describe('.fromString()', () => {
      beforeEach(() => {
        Helpers.isBitcoinAddress = candidate => {
          return candidate === 'address';
        };

        Helpers.detectPrivateKeyFormat = candidate => {
          if (candidate === 'unknown_format') {
            return null;
          }
          if (candidate === 'bip_38') {
            return 'bip38';
          }
          if (candidate.indexOf('mini_') === 0) {
            return 'mini';
          }
          return 'sipa';
        };

        let miniAddress = {
          getAddress: function () {
            return this.compressed
              ? 'mini_address'
              : 'mini_address_uncompressed';
          },
          compressed: true
        };

        let miniInvalid = {
          getAddress: function () {
            return 'mini_address';
          },
          compressed: true
        };

        let mini2 = {
          getAddress: function () {
            return this.compressed
              ? 'mini_2'
              : 'mini_2_uncompressed';
          },
          compressed: true
        };

        let validAddress = {
          getAddress: function () {
            return 'address';
          },
          compressed: true
        };

        Helpers.privateKeyStringToKey = (address, format) => {
          if (address === 'mini_address') {
            return miniAddress;
          }
          if (address === 'mini_2') {
            return mini2;
          }
          if (address === 'address') {
            return validAddress;
          }
          if (address === 'mini_invalid') {
            throw miniInvalid;
          }
        };

        spyOn(Address, 'import').and.callFake(address => {
          if (Helpers.isString(address)) {
            return { addr: address };
          }
          if (address) {
            return { addr: address.getAddress() };
          }
          if (!address) {
            return { addr: address };
          }
        });
      });

      it('should not import unknown formats', done => {
        let promise = Address.fromString('unknown_format', null, null);
        expect(promise).toBeRejectedWith('unknown key format', done);
      });

      it('should not import BIP-38 format without a password', done => {
        let promise = Address.fromString('bip_38', null, null, done);
        expect(promise).toBeRejectedWith('needsBip38', done);
      });

      it('should not import BIP-38 format with an empty password', done => {
        let promise = Address.fromString('bip_38', null, '', done);
        expect(promise).toBeRejectedWith('needsBip38', done);
      });

      it('should not import BIP-38 format with a bad password', done => {
        let promise = Address.fromString('bip_38', null, 'wrong', done);
        expect(promise).toBeRejectedWith('wrongBipPass', done);
      });

      it('should not import BIP-38 format if the decryption fails', done => {
        let promise = Address.fromString('bip_38', null, 'fail', done);
        expect(promise).toBeRejectedWith('importError', done);
      });

      it('should import BIP-38 format with a correct password', done => {
        let promise = Address.fromString('bip_38', null, 'correct', done);
        expect(promise).toBeResolved(done);
      });

      it('should import valid addresses string', done => {
        let promise = Address.fromString('address', null, null);
        let match = jasmine.objectContaining({ addr: 'address' });
        expect(promise).toBeResolvedWith(match, done);
      });

      it('should import private keys using mini format string', done => {
        let promise = Address.fromString('mini_address', null, null);
        let match = jasmine.objectContaining({ addr: 'mini_address' });
        expect(promise).toBeResolvedWith(match, done);
      });

      it('should import uncompressed private keys using mini format string', done => {
        let promise = Address.fromString('mini_2', null, null);
        let match = jasmine.objectContaining({ addr: 'mini_2_uncompressed' });
        expect(promise).toBeResolvedWith(match, done);
      });

      it('should not import private keys using an invalid mini format string', done => {
        let promise = Address.fromString('mini_invalid', null, null);
        expect(promise).toBeRejected(done);
      });
    });

    describe('Address.import()', () => {
      beforeEach(() => {
        Helpers.isKey = () => false;
        Helpers.isBitcoinAddress = () => true;
      });

      it('should not import unknown formats', () => {
        Helpers.isBitcoinAddress = () => false;
        expect(() => Address.import('abcd', null)).toThrow();
      });

      it('should not import invalid addresses', () => {
        Helpers.isBitcoinAddress = () => false;
        expect(() => Address.import('19p7ktDbdJnmV4YLC7zQ37RsYczMZJmd66', null)).toThrow();
      });

      it('should import WIF keys', () => {
        Helpers.isBitcoinAddress = () => false;
        Helpers.isBitcoinPrivateKey = () => true;
        let addr = Address.import('5KUwyCzLyDjAvNGN4qmasFqnSimHzEYVTuHLNyME63JKfVU4wiU', null);
        expect(addr.addr).toEqual('pub_key_for_5KUwyCzLyDjAvNGN4qmasFqnSimHzEYVTuHLNyME63JKfVU4wiU');
      });

      it('should import valid addresses', () => {
        let addr = Address.import('19p7ktDbdJnmV4YLC7zQ37RsYczMZJmd6q', null);
        expect(addr.addr).toEqual('19p7ktDbdJnmV4YLC7zQ37RsYczMZJmd6q');
      });
    });

    describe('isEncrypted', () => {
      it('should be true if the address has been encrypted', () => {
        expect(a.isEncrypted()).toBeFalsy();
        let enc = a.encrypt(() => 'ZW5jcnlwdGVk');
        expect(enc.isEncrypted()).toBeTruthy();
      });
    });

    describe('isUnEncrypted', () => {
      it('should be true if the address has been decrypted', () => {
        expect(a.isEncrypted()).toBeFalsy();
        let enc = a.encrypt(() => 'ZW5jcnlwdGVk');
        expect(enc.isUnEncrypted()).toBeFalsy();
        let dec = enc.decrypt(() => 'GFZrKdb4tGWBWrvkjwRymnhGX8rfrWAGYadfHSJz36dF');
        expect(dec.isEncrypted()).toBeFalsy();
      });
    });
  });
});
