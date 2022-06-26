const { REGEX } = require("../config/constants");

const isBoolean = (l) => {
  return Boolean(l) === false || Boolean(l) === true;
};

const addQuotes = (value) => {
  var quotedlet = "'" + value + "'";
  return quotedlet;
};

const format = (data) => {
  return data
    .replace("&quot;", "'")
    .replace("&amp;", "&")
    .replace("&#039;", "'");
};
const getUUID = () => {
  const { v4: uuidv4 } = require("uuid");
  return uuidv4();
};

const randomKeyWord = (keyword) => {
  if (keyword[Math.floor(Math.random() * keyword.length)] === undefined) {
    return keyword[0];
  }
  return keyword[Math.floor(Math.random() * keyword.length)];
};

const splitData = (str, delim) => {
  try {
    let _array = str.split(delim);
    let _returningArray = [];
    _array.forEach((obj) => {
      _returningArray.push({ name: obj });
    });
    return _returningArray;
  } catch (error) {
    _array.push({ name: str });
    return _array;
  }
};

const isValidEmail = (email) => {
  if (!email) return false;
  const re = REGEX.EMAIL;
  return re.test(email);
};

const isValidZIP = (zip) => {
  if (!zip) return false;
  if (isNaN(zip)) return false;
  if (zip.length === 6) return true;
  return false;
};

const isValidPhoneNumber = (phone) => {
  if (!phone) return false;
  if (isNaN(phone)) return false;
  if (phone.length === 10) return true;
  return false;
};
module.exports = {
  addQuotes,
  isBoolean,
  getUUID,
  isValidZIP,
  isValidPhoneNumber,
};
