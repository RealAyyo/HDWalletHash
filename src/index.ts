import * as bip39 from 'bip39';
import * as ecc from 'tiny-secp256k1';
import { BIP32Factory } from 'bip32';
import * as crypto from 'crypto';
import EthCrypto from 'eth-crypto';
import ScryptAsync from 'scrypt-async';
import * as Nacl from 'tweetnacl';
import * as NaclUtil from 'tweetnacl-util';
const BitCore = require('bitcore-lib');
const Mnemonic = require('bitcore-mnemonic');

const bip32 = BIP32Factory(ecc);

export default class HashStore {
  salt: string;
  hdPathString: string;
  encSeed = undefined;
  encHdRootPriv = undefined;

  constructor(hdPathString: string = `m/44'/195'/0'/0/`) {
    this.salt = 't&#3bq73Nd?2P%raGjHB?bR';
    this.hdPathString = hdPathString;
  }

  init(mnemonic, pwDerivedKey, salt) {
    const words = mnemonic.split(' ');

    const paddedSeed = this.leftPadString(mnemonic, ' ', 120);
    this.encSeed = this.encryptString(paddedSeed, pwDerivedKey);

    const hdRoot = new Mnemonic(mnemonic).toHDPrivateKey().xprivkey;
    const hdRootKey = new BitCore.HDPrivateKey(hdRoot);
    const hdPathKey = hdRootKey.derive(this.hdPathString).xprivkey;
    this.encHdRootPriv = this.encryptString(hdPathKey, pwDerivedKey);
  }

  createVault(options: { salt?: string; password: string; seedPhrase: string }, cb) {
    if (!options.salt) {
      options.salt = 't&#3bq73Nd?2P%raGjHB?bR';
    }
    const { seedPhrase, password, salt } = options;

    this.deriveKeyFromPasswordAndSalt(password, salt, (err, pwDerivedKey) => {
      this.init(seedPhrase, pwDerivedKey, salt);
      cb(null, {
        salt: this.salt,
        hdPathString: this.hdPathString,
        encSeed: this.encSeed,
        encHdRootPriv: this.encHdRootPriv
      });
    });
  }

  deriveKeyFromPasswordAndSalt(password, salt, callback) {
    const logN = 14;
    const r = 8;
    const dkLen = 32;
    const interruptStep = 200;

    const cb = function (derKey) {
      let err = null;
      let ui8arr = null;

      try {
        ui8arr = new Uint8Array(derKey);
      } catch (e) {
        err = e;
      }

      callback(err, ui8arr);
    };

    ScryptAsync(password, salt, logN, r, dkLen, interruptStep, cb, null);
  }

  async generatePrivateKey(mnemonic, index): Promise<Record<string, string>> {
    try {
      const seed = await bip39.mnemonicToSeed(mnemonic);
      const node = await bip32.fromSeed(seed);
      const child = await node.derivePath(this.hdPathString + index);

      const privateKey = await child.privateKey;
      const publicKey = child.publicKey;

      const privateKeyBuf = Buffer.from(privateKey);
      const publicKeyBuf = Buffer.from(publicKey);

      const PrivKey = privateKeyBuf.toString('hex');
      const PubKey = publicKeyBuf.toString('hex');

      return {
        PrivKey,
        PubKey
      };
    } catch (e) {
      throw new Error(e);
    }
  }

  async generateAddressFromPublicKey(publicKey) {
    let address: Buffer | string = EthCrypto.publicKey.toAddress(publicKey);
    address = '41' + address.substring(2, address.length);

    const doubleSha256 = this.sha256(this.sha256(address));
    const checkSum = doubleSha256.substring(0, 8);
    address = Buffer.from(address + checkSum, 'hex');
    return this.encode58(address);
  }

  leftPadString(stringToPad, padChar, length) {
    let repeatedPadChar = '';

    for (let i = 0; i < length; i++) {
      repeatedPadChar += padChar;
    }

    return (repeatedPadChar + stringToPad).slice(-length);
  }

  encryptString = function (string, pwDerivedKey) {
    const nonce = Nacl.randomBytes(Nacl.secretbox.nonceLength);
    const encStr = Nacl.secretbox(NaclUtil.decodeUTF8(string), nonce, pwDerivedKey);

    return {
      encStr: NaclUtil.encodeBase64(encStr),
      nonce: NaclUtil.encodeBase64(nonce)
    };
  };

  sha256(msg) {
    return crypto.createHash('sha256').update(Buffer.from(msg, 'hex')).digest('hex');
  }

  encode58(buffer) {
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
