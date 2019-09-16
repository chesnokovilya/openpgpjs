/**
 * @fileoverview functions dealing with openPGP key object
 * @see module:key/key
 * @module key
 */

import * as key from './key';
import * as factory from './factory';
import { getPreferredAlgo, isAeadSupported } from './helper';

const mod = {
  getPreferredAlgo: getPreferredAlgo,
  isAeadSupported: isAeadSupported
};

Object.assign(mod, key);
Object.assign(mod, factory);

export default mod;
