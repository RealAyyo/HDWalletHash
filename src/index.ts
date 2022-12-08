import * as bip39 from 'bip39';
import * as ecc from 'tiny-secp256k1';
import { BIP32Factory } from 'bip32';
import * as crypto from 'crypto';
import EthCrypto from 'eth-crypto';
import * as ScryptAsync from 'scrypt-async';
import * as Nacl from "tweetnacl";
import * as NaclUtil from 'tweetnacl-util';

const BitCore = require('bitcore-lib');
const Mnemonic = require('bitcore-mnemonic');

const bip32 = BIP32Factory(ecc);

class HashStore {
  salt: string = 't&#3bq73Nd?2P%raGjHB?bR';
  hdPathString: string = `m/44'/195'/0/0/`;
  encSeed: { encStr: any; nonce: any; } | undefined;
  encHdRootPriv: { encStr: any; nonce: any; } | undefined;
  addresses: any[] = [];
  encPrivKeys: any = {};
  version = 1;
  hdIndex = 0;

  init(mnemonic: string, pwDerivedKey: any, salt: string) {
    const words = mnemonic.split(' ');

    const paddedSeed = this.leftPadString(mnemonic, ' ', 120);
    this.encSeed = this.encryptString(paddedSeed, pwDerivedKey);

    const hdRoot = new Mnemonic(mnemonic).toHDPrivateKey().xprivkey;
    const hdRootKey = new BitCore.HDPrivateKey(hdRoot);
    const hdPathKey = hdRootKey.derive(0).xprivkey;
    // const hdPathKey = hdRootKey.derive(this.hdPathString).xprivkey;
    this.encHdRootPriv = this.encryptString(hdPathKey, pwDerivedKey);
  }

  createVault(options: { salt?: string; password: string; seedPhrase: string }, cb: any) {
    if (!options.salt) {
      options.salt = 't&#3bq73Nd?2P%raGjHB?bR';
    }
    const { seedPhrase, password, salt } = options;

    this.deriveKeyFromPasswordAndSalt(password, salt, (err: any, pwDerivedKey: any) => {
      const ks = new HashStore()
      ks.init(seedPhrase, pwDerivedKey, salt);

      cb(null, ks);
    });
  }

  keyFromPassword(password: string, callback: any) {
    this.deriveKeyFromPasswordAndSalt(password, this.salt, callback);
  };

  async generateNewAddress(pwDerivedKey: string, n: any) {
    this.isDerivedKeyCorrect(pwDerivedKey)
    if (!this.encSeed) {
      throw new Error('KeyStore.generateNewAddress: No seed set');
    }

    n = n || 1;


    const keys = await this.generatePrivateKey(pwDerivedKey, n);


    for (let i = 0; i < n; i++) {
      const keyObj = keys[i];

      const address= await this.generateAddressFromPublicKey(keyObj.privKey);

      this.encPrivKeys[address] = keyObj.encPrivKey;
      this.addresses.push(address);


    }
  };

  isDerivedKeyCorrect(pwDerivedKey: any) {
    const paddedSeed = this.decryptString(this.encSeed, pwDerivedKey);

    const result = paddedSeed && paddedSeed.length > 0;

    if(!result){
      throw new Error('Incorrect derived key!');
    }

  };

  deriveKeyFromPasswordAndSalt(password: string, salt: string, callback: (err: any, ui8arr: any) => void) {
    const logN = 14;
    const r = 8;
    const dkLen = 32;
    const interruptStep = 200;

    const cb = function (derKey: any) {
      let err = null;
      let ui8arr = null;

      try {
        ui8arr = new Uint8Array(derKey);
      } catch (e) {
        err = e;
      }

      callback(err, ui8arr);
    };

    // @ts-ignore
    ScryptAsync(password, salt, logN, r, dkLen, interruptStep, cb, null);
  }

  async generatePrivateKey(pwDerivedKey: any, n: any) {
    this.isDerivedKeyCorrect(pwDerivedKey)
    const hdRoot = this.decryptString(this.encHdRootPriv, pwDerivedKey);

    if (!hdRoot || hdRoot.length === 0) {
      throw new Error('Provided password derived key is wrong');
    }

    const keys = [];

    let len=this.addresses.length+n

    for (let i=this.addresses.length; i < len; i++) {

      let mnemonic = await this.getSeed(pwDerivedKey);

      const seed = await bip39.mnemonicToSeed(mnemonic);
      const node = await bip32.fromSeed(seed);
      const child = await node.derivePath(`m/44'/195'/${i}'/0/0`);
      const privateKey = await child.privateKey as any;
      const privateKeyBuf = Buffer.from(privateKey);
      let privateKeyHex = privateKeyBuf.toString('hex');

      if (privateKeyBuf.length < 16) {
        // Way too small key, something must have gone wrong
        // Halt and catch fire
        throw new Error('Private key suspiciously small: < 16 bytes. Aborting!');
      } else if (privateKeyBuf.length > 32) {
        throw new Error('Private key larger than 32 bytes. Aborting!');
      } else if (privateKeyBuf.length < 32) {
        // Pad private key if too short
        // bitcore has a bug where it sometimes returns
        // truncated keys
        privateKeyHex = this.leftPadString(privateKeyBuf.toString('hex'), '0', 64);
      }

      const encPrivateKey = this.encryptKey(privateKeyHex, pwDerivedKey);

      keys.push({
        privKey: privateKeyHex,
        encPrivKey: encPrivateKey
      })
    }
    return keys;
  }

  encryptKey (privateKey: string, pwDerivedKey: Uint8Array) {
    const nonce = Nacl.randomBytes(Nacl.secretbox.nonceLength);
    const privateKeyArray = this.decodeHex(privateKey);
    const encKey = Nacl.secretbox(privateKeyArray, nonce, pwDerivedKey);

    return {
      key: NaclUtil.encodeBase64(encKey),
      nonce: NaclUtil.encodeBase64(nonce),
    };
  };

  decodeHex(msgHex: any) {
    // @ts-ignore
    const msgBase64 = (new Buffer.from(msgHex, 'hex')).toString('base64');

    return NaclUtil.decodeBase64(msgBase64);
  }

  getSeed(pwDerivedKey: any){
    this.isDerivedKeyCorrect(pwDerivedKey)

    const paddedSeed = this.decryptString(this.encSeed, pwDerivedKey);

    if (!paddedSeed || paddedSeed.length === 0) {
      throw new Error('Provided password derived key is wrong');
    }

    return paddedSeed.trim();
  };

  exportPrivateKey(address:string, pwDerivedKey: any) {

    this.isDerivedKeyCorrect(pwDerivedKey)

    if (this.encPrivKeys[address] === undefined) {
      throw new Error('KeyStore.exportPrivateKey: Address not found in KeyStore');
    }

    const encPrivateKey = this.encPrivKeys[address];


    return this.decryptKey(encPrivateKey, pwDerivedKey);
  };

  decryptKey(encryptedKey: any, pwDerivedKey: any) {
    const decKey = NaclUtil.decodeBase64(encryptedKey.key);
    const nonce = NaclUtil.decodeBase64(encryptedKey.nonce);
    const decryptedKey = Nacl.secretbox.open(decKey, nonce, pwDerivedKey);

    if (decryptedKey === null) {
      throw new Error('Decryption failed!');
    }

    return this.encodeHex(decryptedKey);
  };

  encodeHex(msgUInt8Arr: any) {
    const msgBase64 = NaclUtil.encodeBase64(msgUInt8Arr);

    // @ts-ignore
    return (new Buffer.from(msgBase64, 'base64')).toString('hex');
  }
  async generateAddressFromPublicKey(privateKey: string) {
    let publicKey: string  = EthCrypto.publicKeyByPrivateKey(privateKey)
    let address: string  = EthCrypto.publicKey.toAddress(publicKey);

    address = '41' + address.substring(2, address.length);

    const doubleSha256 = this.sha256(this.sha256(address));
    const checkSum = doubleSha256.substring(0, 8);

    const bufferAddress = Buffer.from(address + checkSum, 'hex')
    return this.encode58(bufferAddress);
  }

  leftPadString(stringToPad: string, padChar: string, length: number) {
    let repeatedPadChar = '';

    for (let i = 0; i < length; i++) {
      repeatedPadChar += padChar;
    }

    return (repeatedPadChar + stringToPad).slice(-length);
  }

  encryptString = function (string: string, pwDerivedKey: any) {
    const nonce = Nacl.randomBytes(Nacl.secretbox.nonceLength);
    const encStr = Nacl.secretbox(NaclUtil.decodeUTF8(string), nonce, pwDerivedKey);

    return {
      encStr: NaclUtil.encodeBase64(encStr),
      nonce: NaclUtil.encodeBase64(nonce)
    };
  };

  decryptString(encryptedStr: any, pwDerivedKey: Uint8Array) {
    const decStr = NaclUtil.decodeBase64(encryptedStr.encStr);
    const nonce = NaclUtil.decodeBase64(encryptedStr.nonce);

    const decryptedStr = Nacl.secretbox.open(decStr, nonce, pwDerivedKey);

    if (decryptedStr === null) {
      return false;
    }

    return NaclUtil.encodeUTF8(decryptedStr);
  };

  sha256(msg: string) {
    return crypto.createHash('sha256').update(Buffer.from(msg, 'hex')).digest('hex');
  }

  encode58(buffer: string | any[] | Buffer) {
    const BASE = 58;
    const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

    if (buffer.length === 0) return '';

    const digits = [0];

    for (let i = 0; i < buffer.length; i++) {
      for (let j = 0; j < digits.length; j++) digits[j] <<= 8;

      digits[0] += buffer[i];
      let carry = 0;

      for (let j = 0; j < digits.length; ++j) {
        digits[j] += carry;
        carry = (digits[j] / BASE) | 0;
        digits[j] %= BASE;
      }

      while (carry) {
        digits.push(carry % BASE);
        carry = (carry / BASE) | 0;
      }
    }

    for (let i = 0; buffer[i] === 0 && i < buffer.length - 1; i++) digits.push(0);

    return digits
      .reverse()
      .map((digit) => ALPHABET[digit])
      .join('');
  };
}

module.exports = HashStore