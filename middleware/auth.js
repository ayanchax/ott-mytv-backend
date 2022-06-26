const Strategy = require("passport-jwt").Strategy;
var constants = require("../config/constants");
var mongoUtil = require("../config/connect");
var myCache = require("../config/cache");
const {
  SECRET_KEY,
  TOKENS_COLLECTION,
  HTTP_CODES,
} = require("../config/constants");
var database = mongoUtil.get();
let requestedWithJWTString = null;
const jwtExtractor = (req) => {
  let token = null;
  if (req && req.headers && req.headers.authorization) {
    let tokenParts = req.headers.authorization.split(" ");
    // tokenParts tokenParts[0] is schema and tokenParts[1] is credentials
    // test matching schema
    if (/^Bearer$/i.test(tokenParts[0])) {
      token = tokenParts[1];
      requestedWithJWTString = token;
    }
  }
  return token;
};
module.exports = {
  applyJWTAuthenticationStrategy: function (passport) {
    const options = {};
    options.jwtFromRequest = jwtExtractor;
    options.secretOrKey = constants.SECRET_KEY;
    options.passReqToCallback = true;

    // initializing JWT strategy for all our sensitive routes/API authentication.
    passport.use(
      new Strategy(options, async (request, payload, done) => {
        // CHECK IF USER HAS LOGGED OUT FROM APPLICATION BY STEALING THE ACCESS TOKEN AND THEN TRYING TO ACCESS PRIVATE ROUTE FROM ANY OTHER HTTP-PLATFORM/TOOL.
        // IN SUCH CASES, CHECK IF USER HAS A VALID REFRESH TOKEN ASSOCIATED WITH THE STOLEN ACCESS TOKEN, IF NO REFRESH TOKEN IS FOUND THEN THE USER IS MOST PROBABLY A ATTACKER, BLOCK ACCESS IN SUCH CASES.
        // SINCE THE FOLLOWING CHECK DEALS WITH PREVENTING SESSION HIJACKING, IT IS DONE OUTSIDE OF CACHE.
        const platformSpecificValidRefreshToken = await database
          .collection(this.JWTConfig().collection)
          .find({
            userId: payload.user.id,
            tempAccessToken: requestedWithJWTString,
          })
          .toArray();

        if (
          !platformSpecificValidRefreshToken ||
          platformSpecificValidRefreshToken.length === 0
        ) {
          // clear cache.
          myCache.clearCache(payload.user.username);
          return done("Unauthorized", false, {
            info: "Access forbidden. Needs re-login to app.",
            code: HTTP_CODES._4XX.FORBIDDEN,
          });
        }
        if (
          myCache.getCache(payload.user.username) != undefined &&
          myCache.getCache(payload.user.username).iat === payload.iat
        ) {
          return done(null, myCache.getCache(payload.user.username));
        } else {
          // if cache is empty, rebuild cache with user information
          database
            .collection(constants.USERS_COLLECTION)
            .findOne({ phone: payload.user.phone }, (err, user) => {
              if (err) return done(err, false);
              if (user) {
                myCache.setCache(payload.user.phone, {
                  user_id: user.user_id,
                  service_provider_id: user.service_provider_id,
                  iat: payload.iat,
                  phone: user.phone,
                  deviceID: user.deviceID,
                });
                return done(null, {
                  user_id: user.user_id,
                  service_provider_id: user.service_provider_id,
                  iat: payload.iat,
                  phone: user.phone,
                  deviceID: user.deviceID,
                });
              }
              return done(null, false);
            });
        }
      })
    );
  },

  JWTConfig: function () {
    return {
      secret: SECRET_KEY, // 256 BIT SECRET KEY FOR SIGNING OUR JWT PAYLOAD USING HS256 ALGORITHM
      collection: TOKENS_COLLECTION, // Collection where we store user refresh tokens.
      jwtAccessTokenExpiration: "15m", // 15 minutes 15m
      jwtRefreshTokenExpiration: "1h", // 1 hour 1h
      jwtSetPasswordTokenExpiration: "15m", //15 minutes
      jwtUserDataTokenExpiration: "2m", // 2 minutes
      refreshTokenLimit: 5, // Refresh token limit per user, for enhanced security on authorization. Refer jwt.js getRefreshToken(payload) method for more detail. Only 5 active logins are allowed.
    };
  },
};
