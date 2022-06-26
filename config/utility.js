
const logFormatter=(source, host, module, message)=> {
  var obj = {
    ts: new Date().toISOString(),
    source: source,
    host: host,
    module: module,
    message: message,
  };
  return obj;
}
const getContentType = (filepath) => {
  const mime = require("mime-types");
  return mime.lookup(filepath);
};

const getFileExtension = (str, withDot) => {
  if (!str) return null;
  try {
    return withDot ? "." + str.split(".").pop() : str.split(".").pop();
  } catch (error) {
    return "";
  }
};

const dirCleanup = async (dir) => {
  const del = require("del");
  try {
    await del(dir);
  } catch (err) {}
};

const isEmptyObject = (object) => {
  return Object.keys(object).length === 0 && object.constructor === Object;
};

module.exports = {
  logFormatter,
  getContentType,
  getFileExtension,
  dirCleanup,
  isEmptyObject
};
