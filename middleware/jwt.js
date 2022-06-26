/**
 * @description
 * MIDDLE WARE UTILITY FOR MANAGING JSON WEB TOKENS(RFC 7519 https://tools.ietf.org/html/rfc7519) WHICH INTERACTS WITH THE APPLICATION AUTHORIZATION MODULE
 * AND IS RESPONSIBLE FOR ENSURING APPLICATION SECURITY THROUGHOUT THE LIFECYCLE OF THE APPLICATION.
 * @author Swaroop Chakraborty
 * @created May 7 2022
 * @modified May 8 2022
 * @version 1.0
 * @note IMPORTANT : Do not change this file without consent from stakeholders and development lead.
 */
const jwt = require("jsonwebtoken");
const { v1: uuidv1 } = require("uuid");
const mongoUtil = require("../config/connect");
const { USERS_COLLECTION, HTTP_CODES } = require("../config/constants");
const { JWTConfig } = require("./auth");
const database = mongoUtil.get();
const jwtConfig = JWTConfig();
const util = require("util");
const jwtVerifyAsync = util.promisify(jwt.verify);

/**
 * @author: Swaroop Chakraborty
 * @description
 * Get short lived access token for a given payload.
 * @param {*} payload
 * @returns string
 */
function getAccessToken(payload) {
  return jwt.sign({ user: payload }, jwtConfig.secret, {
    expiresIn: jwtConfig.jwtAccessTokenExpiration,
  });
}

/**
 * @author: Swaroop Chakraborty
 * @description
 * Get short lived user data token for a given payload.
 * @param {*} payload
 * @returns string
 */
 function getUserDataToken(payload) {
  return jwt.sign({ user: payload }, jwtConfig.secret, {
    expiresIn: jwtConfig.jwtUserDataTokenExpiration,
  });
}

/**
 * @author: Swaroop Chakraborty
 * @description
 * Get short lived access token for a given payload for getting the set password link in user's registered email inbox.
 *
 * @notes
 * Set password link is sent to user's inbox in two events:
 * EV1. New user is added to system - Refer api.js endpoint /user/add
 * EV2. User requests for a forget password workflow - Refer api.js endpoint /user/forgotPassword
 *
 * @param {*} payload
 * @returns string
 */
function getPasswordAccessToken(payload) {
  return jwt.sign({ user: payload }, jwtConfig.secret, {
    expiresIn: jwtConfig.jwtSetPasswordTokenExpiration,
  });
}

/**
 * @author: Swaroop Chakraborty
 * @description
 * Get opaque(long-lived) refresh token for a given payload.
 * @param {*} payload
 * @notes
 * EXPLANATION:
 * Why are we having a limit on refresh tokens?
 * -----------------------------------------------
 * Before creating a new refresh token, we check how many refresh tokens the user has already had with the application.
 * But how is it possible that one user has multiple refresh tokens?
 * Nowadays, people can use more than one device—smartphones, laptops, and tablets.
 * That’s why we store all the refresh tokens for each user to use the authorization feature on more than one device.
 * During each login, a record is created in our database.
 * But, in that case, it’s worth taking care of security, that’s why we check the number of refresh tokens.
 * The maximum number of tokens is set to five. If there are more than five,
 * we have to delete all of them and keep only the new one.
 * In this way, we can avoid a situation when someone tries to do sketchy stuff.
 * @returns string
 */
function getRefreshToken(payload, accessToken) {
  return new Promise(async (resolve) => {
    // get all user's refresh tokens from DB
    const userRefreshTokens = await database
      .collection(jwtConfig.collection)
      .find({ userId: payload.id })
      .toArray();

    // check if there are 5 or more refresh tokens,
    // which have already been generated. In this case, we should
    // remove all this refresh tokens and leave only new one for security reason

    if (userRefreshTokens.length >= jwtConfig.refreshTokenLimit) {
      database
        .collection(jwtConfig.collection)
        .deleteMany({ userId: payload.id });
    }
    const refreshToken = jwt.sign({ user: payload }, jwtConfig.secret, {
      expiresIn: jwtConfig.jwtRefreshTokenExpiration,
    });
    await database.collection(jwtConfig.collection).insertOne(
      {
        id: uuidv1(),
        userId: payload.id,
        refreshToken: refreshToken,
        tempAccessToken: accessToken,
        created_ts: new Date(),
        modified_ts: new Date(),
      },
      (err, result) => {
        resolve(refreshToken);
      }
    );
  });
}
/***
 * @author: Swaroop Chakraborty
 * @description:
 * Updates the old refresh token with a new one considering that every refresh token is valid for 1h.
 * @notes
 * In case somebody steals the refresh token,
 * a hacker can also generate a new access token during these 1h while the old token expires.
 * To avoid this situation, and increase security, we are updating the refresh token
 * whenever we generate a new access token.
 * But if the user is offline for more than 1h or logs off the system manually from the front end, the user has to be authenticated again, because in each case, the refresh token will be not valid and would be removed from the database respectively.
 */
function refreshToken(token) {
  return new Promise(async (resolve, reject) => {
    try {
      await jwtVerifyAsync(token, jwtConfig.secret)
        .then(async (__jwt) => {
          // at this point we have a valid refresh token
          // find the user in the user table
          const user = await database
            .collection(USERS_COLLECTION)
            .findOne({ user_id: __jwt.user.id });
          if (!user) {
            reject({
              code: HTTP_CODES._4XX.UNAUTHORIZED[1],
              error: true,
              message: `Access is forbidden. User does not exist. Needs re-login.`,
            });
          } // get all user's refresh tokens from DB
          const allRefreshTokens = await database
            .collection(jwtConfig.collection)
            .find({ userId: user.user_id })
            .toArray();

          if (!allRefreshTokens || allRefreshTokens.length == 0) {
            reject({
              code: HTTP_CODES._4XX.UNAUTHORIZED[1],
              error: true,
              message: `Access is forbidden. There exists no refresh token for this user. Needs re-login.`,
            });
          }
          const currentRefreshToken = allRefreshTokens.find(
            (refreshToken) => refreshToken.refreshToken === token
          );
          if (!currentRefreshToken) {
            reject({
              code: HTTP_CODES._4XX.UNAUTHORIZED[1],
              error: true,
              message: `Access is forbidden. Invalid refresh token. Needs re-login.`,
            });
          }
          // user's data for new tokens
          const payload = {
            id: user.user_id,
            username: user.username,
          };
          // get new access and refresh token
          const newAccessToken = getAccessToken(payload);
          const newRefreshToken = getUpdatedRefreshToken(
            token,
            payload,
            newAccessToken,
            false
          );
          newRefreshToken
            .then((_newRefreshToken) => {
              resolve({
                accessToken: newAccessToken,
                refreshToken: _newRefreshToken,
              });
            })
            .catch(() => {
              reject({
                code: HTTP_CODES._4XX.UNAUTHORIZED[1],
                error: true,
                message: `Access is forbidden. Token could not be refreshed. Needs re-login.`,
              });
            });
        })
        .catch((err) => {
          // Manage different errors here (Expired, untrusted...)
          // refresh token has expired, delete the entry from database and reject promise
          _pruneToken(token);
          reject({
            code: HTTP_CODES._4XX.UNAUTHORIZED[1],
            error: true,
            message: `Access is forbidden. Refresh token expired. Needs re-login.`,
          });
        });
    } catch (err) {
      // Manage different errors here (Expired, untrusted...)
      // refresh token has expired, delete the entry from database and reject promise
      _pruneToken(token);
      reject({
        code: HTTP_CODES._4XX.UNAUTHORIZED[1],
        error: true,
        message: `Access is forbidden. Refresh token expired. Needs re-login.`,
      });
    }
  });
}
function _pruneToken(token) {
  if (token) {
    database
      .collection(jwtConfig.collection)
      .deleteOne({ refreshToken: token });
  }
}

/**
 * @author: Swaroop Chakraborty
 * @description
 * Updates the old refresh token with a new refresh token when assiging a new access token.
 * @param {*} oldRefreshToken
 * @param {*} payload
 * @returns
 */
function getUpdatedRefreshToken(oldRefreshToken, payload, newAccessToken, canUpdateRefreshToken) {
  return new Promise(async (resolve) => {
    // create new refresh token
    const newRefreshToken = canUpdateRefreshToken? jwt.sign({ user: payload }, jwtConfig.secret, {
      expiresIn: jwtConfig.jwtRefreshTokenExpiration,
    }):oldRefreshToken
    // replace current refresh token with new one
    await database.collection(jwtConfig.collection).updateMany(
      {
        userId: payload.id,
        refreshToken: { $eq: oldRefreshToken },
      },
      {
        $set: {
          refreshToken: newRefreshToken,
          tempAccessToken: newAccessToken,
          modified_ts: new Date()
        },
      },
      (error, result) => {
        if (error) {
          resolve(newRefreshToken);
        }
        resolve(newRefreshToken);
      }
    );
  });
}

/**
 * @author: Swaroop Chakraborty
 * @description
 * Deletes refresh token for a given user.
 * @param {*} user
 * @param {*} refreshToken
 * @returns
 */
function deleteRefreshToken(user, refreshToken) {
  return new Promise(async (resolve, reject) => {
    if (!refreshToken) {
      reject({
        code: HTTP_CODES._4XX.NOT_FOUND[0],
        error: true,
        message: `Token not found`,
      });
    }
    if (!user) {
      reject({
        code: HTTP_CODES._4XX.NOT_FOUND[0],
        error: true,
        message: `User not found`,
      });
    }

    const _user = await database
      .collection(USERS_COLLECTION)
      .findOne({ user_id: user.user_id });
    if (!_user) {
      reject({
        code: HTTP_CODES._4XX.NOT_FOUND[0],
        error: true,
        message: `User not found`,
      });
    }
    database
      .collection(jwtConfig.collection)
      .deleteOne(
        { userId: user.user_id, refreshToken: refreshToken },
        (err, result) => {
          if (result) {
            
            resolve({
              code: HTTP_CODES._2XX.OK[0],
              message: "Removed refresh token.",
            });
          }
          if (err) {
            reject({
              code: HTTP_CODES._4XX.NOT_FOUND[0],
              error: true,
              message: `Token not found`,
            });
          }
        }
      );
  });
}

/**
 * @author: Swaroop Chakraborty
 * @description
 * Verify JWT payload for a given token.
 * @param {*} token
 * @returns Promise
 */
function verifyJWT(token) {
  return new Promise((_resolve) => {
    const verifiedResponse = {
      valid: false,
      message: "Token is invalid",
      user:null
    };
    if (!token) {
      _resolve(verifiedResponse);
    }
    const verificationPromise = new Promise((resolve) => {
      jwt.verify(token, jwtConfig.secret, (err,_payload) => {
        if (err) {
          resolve(verifiedResponse);
        } else {
          verifiedResponse.valid = true;
          verifiedResponse.message = "Token is valid";
          verifiedResponse.user=_payload
          resolve(verifiedResponse);
        }
      });
    });
    verificationPromise
      .then((_verifiedResponse) => {
        if (_verifiedResponse) _resolve(_verifiedResponse);
        _resolve(verifiedResponse);
      })
      .catch((err) => {
        _resolve(verifiedResponse);
      });
  });
}

/**
 * @description
 * Returns if a jwt claim expiration time is expired or not.
 * The "exp" (expiration time) claim identifies the expiration time on
   or after which the JWT MUST NOT be accepted for processing.  The
   processing of the "exp" claim requires that the current date/time
   MUST be before the expiration date/time listed in the "exp" claim.
   https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
   This claim is formatted as a Unix Timestamp — the number of seconds elapsed since the beginning of January 1, 1970, UTC
 * @param {*} exp 
 * returns boolean
 */
const isExpiredToken = (exp) => {
  if (!exp) return true;
  return exp < new Date().getTime() / 1000;
};

module.exports = {
  getAccessToken,
  getRefreshToken,
  getUserDataToken,
  refreshToken,
  deleteRefreshToken,
  getPasswordAccessToken,
  verifyJWT,
};
