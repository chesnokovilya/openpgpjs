// OpenPGP.js - An OpenPGP implementation in javascript
// Copyright (C) 2015-2016 Decentral
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

/**
 * @fileoverview Implementation of ECDSA following RFC6637 for Openpgpjs
 * @requires bn.js
 * @requires web-stream-tools
 * @requires enums
 * @requires util
 * @requires crypto/public_key/elliptic/curves
 * @module crypto/public_key/elliptic/ecdsa
 */

import BN from 'bn.js';
import stream from 'web-stream-tools';
import enums from '../../../enums';
import util from '../../../util';
import Curve, { webCurves, privateToJwk, rawPublicToJwk } from './curves';
import KeyPair from './indutnyKey';

const webCrypto = util.getWebCrypto();
const nodeCrypto = util.getNodeCrypto();

/**
 * Sign a message using the provided key
 * @param  {module:type/oid}   oid          Elliptic curve object identifier
 * @param  {module:enums.hash} hash_algo    Hash algorithm used to sign
 * @param  {Uint8Array}        message      Message to sign
 * @param  {Uint8Array}        publicKey    Public key
 * @param  {Uint8Array}        privateKey   Private key used to sign the message
 * @param  {Uint8Array}        hashed       The hashed message
 * @returns {{r: Uint8Array,
 *            s: Uint8Array}}               Signature of the message
 * @async
 */
async function sign(oid, hash_algo, message, publicKey, privateKey, hashed) {
  const curve = new Curve(oid);
  let signature;
  if (message && !message.locked) {
    message = await stream.readToEnd(message);
    const keyPair = {
      getPublic: () => publicKey,
      getPrivate: () => privateKey
    };
    switch (curve.type) {
      case 'web': {
        // If browser doesn't support a curve, we'll catch it
        try {
          // need to await to make sure browser succeeds
          const signature = await webSign(curve, hash_algo, message, keyPair);
          return signature;
        } catch (err) {
          util.print_debug("Browser did not support signing: " + err.message);
        }
        break;
      }
      case 'node': {
        signature = await nodeSign(curve, hash_algo, message, keyPair);
        return {
          r: signature.r.toArrayLike(Uint8Array),
          s: signature.s.toArrayLike(Uint8Array)
        };
      }
    }
  }
  if(!signature && !util.getFullBuild()) {
    throw(new Error('This curve is supported only in the full build of OpenPGP.js'));
  }
  const key = new KeyPair(curve, { priv: privateKey });
  signature = key.keyPair.sign(hashed);
  return {
    r: signature.r.toArrayLike(Uint8Array),
    s: signature.s.toArrayLike(Uint8Array)
  };
}

/**
 * Verifies if a signature is valid for a message
 * @param  {module:type/oid}   oid       Elliptic curve object identifier
 * @param  {module:enums.hash} hash_algo Hash algorithm used in the signature
 * @param  {{r: Uint8Array,
             s: Uint8Array}}   signature Signature to verify
 * @param  {Uint8Array}        message   Message to verify
 * @param  {Uint8Array}        publicKey Public key used to verify the message
 * @param  {Uint8Array}        hashed    The hashed message
 * @returns {Boolean}
 * @async
 */
async function verify(oid, hash_algo, signature, message, publicKey, hashed) {
  const curve = new Curve(oid);
  if (message && !message.locked) {
    message = await stream.readToEnd(message);
    switch (curve.type) {
      case 'web': {
        try {
          // need to await to make sure browser succeeds
          const result = await webVerify(curve, hash_algo, signature, message, publicKey);
          return result;
        } catch (err) {
          util.print_debug("Browser did not support signing: " + err.message);
        }
        break;
      }
      case 'node': {
        return nodeVerify(curve, hash_algo, signature, message, publicKey);
      }
    }
  }
  if (!util.getFullBuild()) {
    throw(new Error('This curve is only supported in the full build of OpenPGP.js'));
  }
  //elliptic fallback
  const key = new KeyPair(curve, { pub: publicKey });
  const digest = (typeof hash_algo === 'undefined') ? message : hashed;
  return key.keyPair.verify(digest, signature);
}

export default { sign, verify };


//////////////////////////
//                      //
//   Helper functions   //
//                      //
//////////////////////////


async function webSign(curve, hash_algo, message, keyPair) {
  const len = curve.payloadSize;
  const jwk = privateToJwk(curve.payloadSize, webCurves[curve.name], keyPair.getPublic(), keyPair.getPrivate());
  const key = await webCrypto.importKey(
    "jwk",
    jwk,
    {
      "name": "ECDSA",
      "namedCurve": webCurves[curve.name],
      "hash": { name: enums.read(enums.webHash, curve.hash) }
    },
    false,
    ["sign"]
  );

  const signature = new Uint8Array(await webCrypto.sign(
    {
      "name": 'ECDSA',
      "namedCurve": webCurves[curve.name],
      "hash": { name: enums.read(enums.webHash, hash_algo) }
    },
    key,
    message
  ));

  return {
    r: signature.slice(0, len),
    s: signature.slice(len, len << 1)
  };
}

async function webVerify(curve, hash_algo, { r, s }, message, publicKey) {
  const len = curve.payloadSize;
  const jwk = rawPublicToJwk(curve.payloadSize, webCurves[curve.name], publicKey);
  const key = await webCrypto.importKey(
    "jwk",
    jwk,
    {
      "name": "ECDSA",
      "namedCurve": webCurves[curve.name],
      "hash": { name: enums.read(enums.webHash, curve.hash) }
    },
    false,
    ["verify"]
  );

  const signature = util.concatUint8Array([
    new Uint8Array(len - r.length), r,
    new Uint8Array(len - s.length), s
  ]).buffer;

  return webCrypto.verify(
    {
      "name": 'ECDSA',
      "namedCurve": webCurves[curve.name],
      "hash": { name: enums.read(enums.webHash, hash_algo) }
    },
    key,
    signature,
    message
  );
}

async function nodeSign(curve, hash_algo, message, keyPair) {
  const sign = nodeCrypto.createSign(enums.read(enums.hash, hash_algo));
  sign.write(message);
  sign.end();
  const key = ECPrivateKey.encode({
    version: 1,
    parameters: curve.oid,
    privateKey: Array.from(keyPair.getPrivate()),
    publicKey: { unused: 0, data: Array.from(keyPair.getPublic()) }
  }, 'pem', {
    label: 'EC PRIVATE KEY'
  });

  return ECDSASignature.decode(sign.sign(key), 'der');
}

async function nodeVerify(curve, hash_algo, { r, s }, message, publicKey) {
  const verify = nodeCrypto.createVerify(enums.read(enums.hash, hash_algo));
  verify.write(message);
  verify.end();
  const key = SubjectPublicKeyInfo.encode({
    algorithm: {
      algorithm: [1, 2, 840, 10045, 2, 1],
      parameters: curve.oid
    },
    subjectPublicKey: { unused: 0, data: Array.from(publicKey) }
  }, 'pem', {
    label: 'PUBLIC KEY'
  });
  const signature = ECDSASignature.encode({
    r: new BN(r), s: new BN(s)
  }, 'der');

  try {
    return verify.verify(key, signature);
  } catch (err) {
    return false;
  }
}

// Originally written by Owen Smith https://github.com/omsmith
// Adapted on Feb 2018 from https://github.com/Brightspace/node-jwk-to-pem/

/* eslint-disable no-invalid-this */

const asn1 = nodeCrypto ? require('asn1.js') : undefined;

const ECDSASignature = nodeCrypto ?
  asn1.define('ECDSASignature', function() {
    this.seq().obj(
      this.key('r').int(),
      this.key('s').int()
    );
  }) : undefined;

const ECPrivateKey = nodeCrypto ?
  asn1.define('ECPrivateKey', function() {
    this.seq().obj(
      this.key('version').int(),
      this.key('privateKey').octstr(),
      this.key('parameters').explicit(0).optional().any(),
      this.key('publicKey').explicit(1).optional().bitstr()
    );
  }) : undefined;

const AlgorithmIdentifier = nodeCrypto ?
  asn1.define('AlgorithmIdentifier', function() {
    this.seq().obj(
      this.key('algorithm').objid(),
      this.key('parameters').optional().any()
    );
  }) : undefined;

const SubjectPublicKeyInfo = nodeCrypto ?
  asn1.define('SubjectPublicKeyInfo', function() {
    this.seq().obj(
      this.key('algorithm').use(AlgorithmIdentifier),
      this.key('subjectPublicKey').bitstr()
    );
  }) : undefined;

//from mozilla polyfill https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/from#Polyfill

/* eslint-disable */
if (!Array.from) {
  Array.from = (function () {
    var toStr = Object.prototype.toString;
    var isCallable = function (fn) {
      return typeof fn === 'function' || toStr.call(fn) === '[object Function]';
    };
    var toInteger = function (value) {
      var number = Number(value);
      if (isNaN(number)) { return 0; }
      if (number === 0 || !isFinite(number)) { return number; }
      return (number > 0 ? 1 : -1) * Math.floor(Math.abs(number));
    };
    var maxSafeInteger = Math.pow(2, 53) - 1;
    var toLength = function (value) {
      var len = toInteger(value);
      return Math.min(Math.max(len, 0), maxSafeInteger);
    };

    // The length property of the from method is 1.
    return function from(arrayLike/*, mapFn, thisArg */) {
      // 1. Let C be the this value.
      var C = this;

      // 2. Let items be ToObject(arrayLike).
      var items = Object(arrayLike);

      // 3. ReturnIfAbrupt(items).
      if (arrayLike == null) {
        throw new TypeError("Array.from requires an array-like object - not null or undefined");
      }

      // 4. If mapfn is undefined, then let mapping be false.
      var mapFn = arguments.length > 1 ? arguments[1] : void undefined;
      var T;
      if (typeof mapFn !== 'undefined') {
        // 5. else
        // 5. a If IsCallable(mapfn) is false, throw a TypeError exception.
        if (!isCallable(mapFn)) {
          throw new TypeError('Array.from: when provided, the second argument must be a function');
        }

        // 5. b. If thisArg was supplied, let T be thisArg; else let T be undefined.
        if (arguments.length > 2) {
          T = arguments[2];
        }
      }

      // 10. Let lenValue be Get(items, "length").
      // 11. Let len be ToLength(lenValue).
      var len = toLength(items.length);

      // 13. If IsConstructor(C) is true, then
      // 13. a. Let A be the result of calling the [[Construct]] internal method of C with an argument list containing the single item len.
      // 14. a. Else, Let A be ArrayCreate(len).
      var A = isCallable(C) ? Object(new C(len)) : new Array(len);

      // 16. Let k be 0.
      var k = 0;
      // 17. Repeat, while k < len… (also steps a - h)
      var kValue;
      while (k < len) {
        kValue = items[k];
        if (mapFn) {
          A[k] = typeof T === 'undefined' ? mapFn(kValue, k) : mapFn.call(T, kValue, k);
        } else {
          A[k] = kValue;
        }
        k += 1;
      }
      // 18. Let putStatus be Put(A, "length", len, true).
      A.length = len;
      // 20. Return A.
      return A;
    };
  }());
}