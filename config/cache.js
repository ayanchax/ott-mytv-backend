const NodeCache = require("node-cache");
const myCache = new NodeCache();

module.exports = {
    setCache: function (token, user) {
        return myCache.set(token, user, 10000);
    },

    getCache: function (key) {
        return myCache.get(key)
    },

    clearCache: function (key) {
        return myCache.del(key)
    }
};


