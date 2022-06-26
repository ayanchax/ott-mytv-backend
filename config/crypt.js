const crypto = require("crypto");
const key = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);
var CryptoJS = require("crypto-js");
const { v1: uuidv1 } = require("uuid");

module.exports = {
  encrypt: function (obj) {
    const secret = this.getSecret();
    var ciphertext = CryptoJS.AES.encrypt(obj, secret).toString();
    return {
      iv: iv.toString("hex"),
      encryptedData: ciphertext,
      secret: secret,
    };
  },
  decrypt: function (obj) {
    let iv = Buffer.from(obj.iv, "hex");
    let encryptedText = Buffer.from(obj.encryptedData, "hex");
    let decipher = crypto.createDecipheriv("aes-256-cbc", Buffer.from(key), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
  },

  getSecret: function () {
    try {
      return crypto.randomUUID({ disableEntropyCache: true });
    } catch (error) {
      return uuidv1();
    }
  },
};
