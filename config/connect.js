const MongoClient = require("mongodb").MongoClient;
const {
  APP_BACKEND_DB,
} = require("../config/constants");
const {
  CONNECTION_OK,
  CONNECTION_FAILED,
} = require("../routes/api/messages/api-messages");
const { logFormatter } = require("./utility");

const url = `mongodb://localhost:27017/`;
var _db;

module.exports = {
  connectToServer: function (callback) {
    MongoClient.connect(url, this.connectOpts(), function (err, client) {
      if (err) {
        console.log(CONNECTION_FAILED)
        return callback(err);
      }
      _db = client.db(APP_BACKEND_DB);
      console.log(CONNECTION_OK)
     
      return callback(err);
    });
  },
  get: function () {
    return _db;
  },
  connectOpts: function () {
    return { useNewUrlParser: true, useUnifiedTopology: true };
  },
};
