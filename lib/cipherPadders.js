/**
 * Supported cipher modes.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2010-2014 Digital Bazaar, Inc.
 */
var forge = require('./forge');
require('./util');

forge.cipher = forge.cipher || {};

// supported cipher modes
var padders = module.exports = forge.cipher.padders = forge.cipher.padders || {};

padders.pkcs_7 = function(message, options) {
  var options = options || {};

  if ( !options.decrypt ) {
    // add PKCS#7 padding to block (each pad byte is the
    // value of the number of pad bytes)
    var padding = (message.length() === this.blockSize ?
      this.blockSize : (this.blockSize - message.length()));

    message.fillWithByte(padding, padding);
  }
  else {
    // check for error: input data not a multiple of blockSize
    if(options.overflow > 0) {
      return false;
    }

    // ensure padding byte count is valid
    var len = message.length();
    var count = message.at(len - 1);
    if(count > (this.blockSize << 2)) {
      return false;
    }

    // trim off padding bytes
    message.truncate(count);
  }

  return true;
}

padders.nopad = function(message, options) {
  return true;
}
