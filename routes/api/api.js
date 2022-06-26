const express = require("express");
const router = express.Router();
const BodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
var database = require("../config/connect");
const { v1: uuidv1 } = require("uuid");
const constants = require("../config/constants");
var cryptoLib = require("../config/crypt");
const nodemailer = require("nodemailer");
const logger = require("../config/log");
const utility = require("../config/utility");
const passport = require("passport");
const speakeasy = require("speakeasy");
const validator = require("validator");
const sgMail = require('@sendgrid/mail');

var myCache = require("../config/cache");
router.use(BodyParser.json());
router.use(BodyParser.urlencoded({ extended: true }));
const crypto = require("crypto");
const {
  getAccessToken,
  getRefreshToken,
  refreshToken,
  deleteRefreshToken,
  getPasswordAccessToken,
  verifyJWT,
} = require("../middleware/jwt");
const {
  ENTITY_LENGTH_CONFIGURATION,
  HTTP_CODES,
  REGEX,
} = require("../config/constants");
/**
 *@swagger
 * /login:
 *  post:
 *    tags:
 *      - api
 *    name: user login
 *    summary: user login
 *    parameters:
 *      - in: header 
 *        name: x-tfa
 *        type: Integer
 *        required: false
 *    produces:
 *       - application/json
 *    requestBody:
 *      content:
 *          application/json:
 *           schema:
 *               type: object
 *               properties:
 *                username:
 *                  type: string
 *                password:
 *                  type: string

 *    responses:
 *      206:
 *        description: OK.
 *      400:
 *        description: Failed Login Attempt.
 *      500:
 *        description: Failed Login Attempt.
 *
 */

router.post("/login", async (req, res) => {
  var username = req.body.username;
  var reqPassword = req.body.password;

  logger.info(
    utility.logFormatter(
      "das-backend",
      req.headers.host,
      "users",
      "Initiating API login.."
    )
  );
  if (!validator.isLength(username, 0, ENTITY_LENGTH_CONFIGURATION.USERNAME.maxLength)) {
    res
      .status(400)
      .send({ message: "Username length exceeds permisible characters." });
  }
  database
    .get()
    .collection(constants.USERS_COLLECTION)
    .findOne({ username: username, active: true }, async (error, _result) => {
      if (_result == null) {
        res.status(400).send({
          message: "Failed Login Attempt",
        });
        return true;
      }

      const stamp = await database
        .get()
        .collection("privacy_policy")
        .find({})
        .sort({ privacy_ts: -1 })
        .limit(1)
        .project({ privacy_ts: 1 })
        .toArray();
      const tos_stamp = stamp[0].privacy_ts.toISOString();
      if (error) {
        res.status(500).send({
          message: "Failed Login Attempt",
        });
        return true;
      } else {
        if (
          !_result.privacy_ts ||
          tos_stamp > _result.privacy_ts.toISOString()
        ) {
          res.json({
            message: "tos issue",
            user_id: _result.user_id,
            customer_id: _result.customer_id,
          });
          return true;
        }
        if (_result !== null) {
          let username = _result.username;
          let user_id = _result.user_id;
          let role = _result.user_role
          const payload = {
            id: user_id,
            username,
            jti:uuidv1(),
            aud:role
          };
          const user_roles = _result.user_role;
          let allowedPasswordMinLength = ENTITY_LENGTH_CONFIGURATION.PASSWORD.minLength.USER;

          if (user_roles.includes("admin"))
            allowedPasswordMinLength = ENTITY_LENGTH_CONFIGURATION.PASSWORD.minLength.ADMIN;

          if (_result.attempts < 3) {
            if (
              !validator.isLength(
                reqPassword,
                allowedPasswordMinLength,
                ENTITY_LENGTH_CONFIGURATION.PASSWORD.maxLength
              )
            ) {
              //add attempt
              database
                .get()
                .collection(constants.USERS_COLLECTION)
                .updateOne(
                  { username: username },
                  {
                    $set: {
                      attempts: _result.attempts + 1,
                      updated_ts: new Date(),
                    },
                  },
                  () => {
                    res.status(400).send({
                      message: "Password length does not comply with policy.",
                    });
                  }
                );
              return;
            }

            if (
              _result.auth_data === undefined ||
              _result.auth_data.secret === undefined ||
              _result.auth_data.secret === ""
            ) {
              bcrypt.compare(reqPassword, _result.password, (err, isMatch) => {
                if (err) {
                  return res.status(500).send(err);
                }
                if (isMatch) {
                  const accessToken = getAccessToken(payload);
                  const refreshToken = getRefreshToken(payload, accessToken);
                  refreshToken
                    .then((_refreshToken) => {
                      if (accessToken && _refreshToken) {
                        database
                          .get()
                          .collection(constants.USERS_COLLECTION)
                          .updateOne(
                            { username: username },
                            {
                              $set: {
                                attempts: 0,
                                locked: false,
                                updated_ts: new Date(),
                              },
                            },
                            () => {
                              if (err) {
                                return res.status(500).send(err);
                              }
                              const ud_payload = {
                                user_id: _result.user_id,
                                first_name: _result.first_name,
                                last_name: _result.last_name,
                                user_role: _result.user_role,
                                customer_id: _result.customer_id,
                                username: _result.username,
                                email: _result.email,
                              };
                              /**
                               * Encrypted user data
                               */
                              const encryptedData = cryptoLib.encrypt(
                                JSON.stringify(ud_payload)
                              );
                              const userData = {
                                e: encryptedData.encryptedData,
                                iv: encryptedData.iv,
                                s: encryptedData.secret,
                              };

                              res.json({
                                token: accessToken,
                                refreshToken: _refreshToken,
                                data: userData,
                              });
                            }
                          );
                      } else {
                        console.log(
                          `ERROR: Login unsuccesful. Tokens not generated`
                        );
                        return res.status(500).send({
                          message: "Login unsuccesful. Tokens not generated",
                        });
                      }
                    })
                    .catch(() => {
                      console.log(
                        `ERROR: Login unsuccesful. Tokens not generated`
                      );
                      return res.status(500).send({
                        message: "Login unsuccesful. Tokens not generated",
                      });
                    });
                } else {
                  ///add attempt
                  console.log(`ERROR: Login without TFA is not successful`);
                  database
                    .get()
                    .collection(constants.USERS_COLLECTION)
                    .updateOne(
                      { username: username },
                      {
                        $set: {
                          attempts: _result.attempts + 1,
                          updated_ts: new Date(),
                        },
                      },
                      () => {
                        res.status(400).send({
                          message: "Failed Login Attempt",
                        });
                      }
                    );
                }
              });
            } else {
              bcrypt.compare(reqPassword, _result.password, (err, isMatch) => {
                if (err) {
                  return res.status(500).send(err);
                }
                if (isMatch) {
                  // TwoFactorAuth Code start
                  if (!req.headers["x-tfa"]) {
                    return res.send({
                      status: 206,
                      message: "Please enter the Auth Code",
                    });
                  }

                  let isVerified = speakeasy.totp.verify({
                    secret: _result.auth_data.secret,
                    encoding: "base32",
                    token: req.headers["x-tfa"],
                    window: 600,
                  });
                  //TwoFactorAuth Code end

                  if (isVerified) {
                    const accessToken = getAccessToken(payload);
                    const refreshToken = getRefreshToken(payload, accessToken);
                    refreshToken
                      .then((_refreshToken) => {
                        if (accessToken && _refreshToken) {
                          database
                            .get()
                            .collection(constants.USERS_COLLECTION)
                            .updateOne(
                              { username: username },
                              {
                                $set: {
                                  attempts: 0,
                                  locked: false,
                                  updated_ts: new Date(),
                                },
                              },
                              () => {
                                if (err) {
                                  return res.status(500).send(err);
                                }
                                let customer_name = null;
                                getCustomerByID(_result.customer_id)
                                  .then((data) => {
                                    customer_name = data.customer_name;
                                  })
                                  .finally(() => {
                                    const ud_payload = {
                                      user_id: _result.user_id,
                                      first_name: _result.first_name,
                                      last_name: _result.last_name,
                                      user_role: _result.user_role,
                                      customer_id: _result.customer_id,
                                      customer_name: customer_name,
                                      username: _result.username,
                                      email: _result.email,
                                    };
                                    /**
                                     * Encrypted user data
                                     */
                                    const encryptedData = cryptoLib.encrypt(
                                      JSON.stringify(ud_payload)
                                    );

                                    const userData = {
                                      e: encryptedData.encryptedData,
                                      iv: encryptedData.iv,
                                      s: encryptedData.secret,
                                    };
                                    res.json({
                                      token: accessToken,
                                      refreshToken: _refreshToken,
                                      data: userData,
                                    });
                                  });
                              }
                            );
                        } else {
                          console.log(
                            `ERROR: Login unsuccesful. Tokens not generated`
                          );
                          return res.status(500).send({
                            message: "Login unsuccesful. Tokens not generated",
                          });
                        }
                      })
                      .catch(() => {
                        console.log(
                          `ERROR: Login unsuccesful. Tokens not generated`
                        );
                        return res.status(500).send({
                          message: "Login unsuccesful. Tokens not generated",
                        });
                      });
                  } else {
                    ///add attempt
                    database
                      .get()
                      .collection(constants.USERS_COLLECTION)
                      .updateOne(
                        { username: username },
                        {
                          $set: {
                            attempts: _result.attempts + 1,
                            updated_ts: new Date(),
                          },
                        },
                        () => {
                          res.status(400).send({
                            message: "Failed Login Attempt",
                          });
                        }
                      );
                  }
                } else {
                  ///add attempt
                  database
                    .get()
                    .collection(constants.USERS_COLLECTION)
                    .updateOne(
                      { username: username },
                      {
                        $set: {
                          attempts: _result.attempts + 1,
                          updated_ts: new Date(),
                        },
                      },
                      () => {
                        res.status(400).send({
                          message: "Failed Login Attempt",
                        });
                      }
                    );
                }
              });
            }
          } else {
            database
              .get()
              .collection(constants.USERS_COLLECTION)
              .updateOne(
                { username: username },
                { $set: { locked: true, updated_ts: new Date() } },
                () => {
                  res.status(400).send({
                    message: "Account Locked",
                  });
                }
              );
          }
        } else {
          res.status(400).send({
            message: "User not found for given username and password.",
          });
        }
      }
    });
});
/**
 * @swagger
 *  /logout/:
 *   post:
 *     tags:
 *       - api
 *     name:  User logout
 *     summary:  User logout
 *     security:
 *      - bearerAuth: []
 *     responses:
 *       200:
 *         description: logout sucessful.
 *       401:
 *         description: unexpected error.
 *       500:
 *         description: Failed Login Attempt.
 */
router.post(
  "/logout/",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    logger.info(
      utility.logFormatter(
        "das-backend",
        req.headers.host,
        "users",
        `Logout user`
      )
    );
    const loggedInUser = req.user;
    if (loggedInUser) {
      myCache.clearCache(loggedInUser.username);
      deleteRefreshToken(loggedInUser, req.body.refreshToken)
        .then((_res) => {
          res.status(_res.code).send({ message: "Logout done" });
        })
        .catch((_err) => {
          res
            .status(_err.code)
            .send({ message: "Logout done but with errors" });
        });
    } else
      res
        .status(HTTP_CODES._5XX.INTERNAL_ERROR[0])
        .send({ message: "Logout done but with errors" });
  }
);
/**
 * @swagger
 *  /loggedInStatus:
 *   get:
 *     tags:
 *       - api
 *     name:  User loggedIn Status
 *     summary:  User loggedIn Status
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: user logged in.
 */
router.get(
  "/loggedInStatus",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    logger.info(
      utility.logFormatter(
        "das-backend",
        req.headers.host,
        "users",
        "Fetch logging in status"
      )
    );

    res.status(200).send({ loggedIn: true });
  }
);
/**
 * @swagger
 *  /user/add:
 *   post:
 *     tags:
 *       - api
 *     summary: add user
 *     security:
 *       - bearerAuth: []
 *     produces:
 *      application/json:
 *     requestBody:
 *         content:
 *          application/json:
 *           schema:
 *               type: object
 *               properties:
 *                 username:
 *                   type: string
 *                 first_name:
 *                   type: string
 *                 last_name:
 *                   type: string
 *                 email:
 *                   type: string
 *                   example: aya@gmail.com
 *                 user_role:
 *                   type: string
 *                   example: customer
 *     responses:
 *       200:
 *         description: OK
 *       500:
 *         description: Error in creating user as access token could not be created.
 *       400:
 *         description: This username already exists.
 */

// TEST ME
router.post(
  "/user/add",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    logger.info(
      utility.logFormatter(
        "das-backend",
        req.headers.host,
        "users",
        "Fetch logging in status"
      )
    );

    let loggedInUser = req.user;
    let customer_id;

    let username = `^${req.body.username}$`;
    let first_name = req.body.first_name;
    let last_name = req.body.last_name;
    let email = req.body.email;
    let userrole = req.body.user_role ? req.body.user_role : ["customer"];

    // data sanity checks
    if (
      !validator.isEmail(email) ||
      !validator.isLength(email, ENTITY_LENGTH_CONFIGURATION.EMAIL.minLength, ENTITY_LENGTH_CONFIGURATION.EMAIL.maxLength) ||
      !validator.matches(email,REGEX.EMAIL.pattern) ||
      !validator.isAlphanumeric(req.body.username, "en-US", { ignore: "-." }) ||
      !validator.isLength(req.body.username, ENTITY_LENGTH_CONFIGURATION.USERNAME.minLength, ENTITY_LENGTH_CONFIGURATION.USERNAME.maxLength) ||
      !validator.isAlphanumeric(first_name, "en-US", { ignore: " " }) ||
      !validator.isLength(first_name, ENTITY_LENGTH_CONFIGURATION.PERSON_NAME.minLength, ENTITY_LENGTH_CONFIGURATION.PERSON_NAME.maxLength) ||
      !validator.isAlphanumeric(last_name, "en-US", { ignore: " " }) ||
      !validator.isLength(last_name, ENTITY_LENGTH_CONFIGURATION.PERSON_NAME.minLength, ENTITY_LENGTH_CONFIGURATION.PERSON_NAME.maxLength)
    ) {
      return res.status(400).send("One of the field is missing or invalid");
    }
    database
      .get()
      .collection(constants.USERS_COLLECTION)
      .findOne(
        { username: { $regex: new RegExp(username, "i") } },
        async (error, result) => {
          if (result) {
            return res.status(400).send("This username already exists.");
          } else {
            if (
              loggedInUser.user_role.includes("admin") &&
              loggedInUser.customer_id == constants.TCS_ID
            ) {
              customer_id = req.body.customer_id;
            } else {
              customer_id = loggedInUser.customer_id;
            }
            const user = {
              first_name: first_name,
              last_name: last_name,
              user_id: uuidv1(),
              user_role: userrole,
              email: email,
              customer_id: customer_id,
              updated_ts: new Date(),
              created_ts: new Date(),
              active: false,
              attempts: 0,
              locked: false,
              tos_ts: "",
              privacy_ts: "",
              tour_complete: false,
              verified: false,
              username: req.body.username,
            };

            let jwtTokenVerification;
            const payload = {
              username: req.body.username,
              jti:uuidv1(),
              aud:user.user_role
            };
            const accessToken = getPasswordAccessToken(payload);
            if (!accessToken) {
              return res.status(500).send({
                message:
                  "Error in creating set password link as access token could not be created.",
              });
            }
            jwtTokenVerification = accessToken;
            let link =
              constants.DAS_FRONTEND_URL + constants.RESET_PASSWORD_PATH +
              jwtTokenVerification;

            const email_properties = {
              email: email,
              username: req.body.username,
              subject: "Please Verify Email",
              text: "Click the link below to verify/reset your email",
              invalidemail_message: "Error in creating set password link as user email is not registered with system.",
              body: "Welcome to TCS Autoscape&trade; Data Annotation Studio.<br> Please Click on the link to verify your email.<br><a href=" +
              link +
              ">Click here to verify</a>",
            };

            sendEmail(email_properties, req, res);

            database
              .get()
              .collection(constants.USERS_COLLECTION)
              .insertOne(user, async (error, result) => {
                if (error) {
                  return res.status(500).send(error);
                }
                await utility.logAdminActivity(
                  user.user_id,
                  req.method,
                  req.url,
                  req.body
                );
                res.send(result);
              });
          }
        }
      );
  }
);
/**
 * @swagger
 *  /{user_id}/verify:
 *   get:
 *     tags:
 *       - api
 *     summary: verify user id
 *     parameters:
 *       - in: path
 *         name: user_id
 *         type: string
 *         required: true
 *     responses:
 *       200:
 *         description: Email is been Successfully verified
 *       500:
 *         description: Bad Request
 */
//NOT IN USE
router.get("/:user_id/verify", async function (req, res) {
  logger.info(
    utility.logFormatter(
      "das-backend",
      req.headers.host,
      "users",
      "Verify Email"
    )
  );

  let isVerified = false;
  const jwtVerifiedResponse = verifyJWT(req.query.id);
  jwtVerifiedResponse
    .then((_verifiedResponse) => {
      if (!_verifiedResponse.valid) {
        return res.json({
          success: isVerified,
          message: "Token is invalid",
        });
      }

      isVerified = true;

      if (true) {
        console.log("Domain is matched. Information is from Authentic email");
        if (isVerified) {
          database
            .get()
            .collection(constants.USERS_COLLECTION)
            .updateOne(
              { user_id: req.params.user_id },
              {
                $set: { active: true, verified: true, updated_ts: new Date() },
              },
              (error) => {
                if (error) {
                  return res.status(500).send(error);
                } else {
                  res.end("<h1>Email is been Successfully verified");
                }
              }
            );
        } else {
          res.end("<h1>Bad Request</h1>");
        }
      } else {
        res.end("<h1>Request is from unknown source");
      }
    })
    .catch(() => {
      return res.json({
        success: isVerified,
        message: "Token is invalid",
      });
    });
});

/**
 * @swagger
 *  /user/forgotPassword:
 *    post:
 *     tags:
 *       - api
 *     summary: forgot password
 *     produces:
 *      - application/json:
 *     requestBody:         
 *         content:
 *          application/json:
 *           schema:
 *               type: object
 *               properties:
 *                 username:
 *                   type: string
 *     responses:
 *       200:
 *         description: Email sent to reset password
 *       400:
 *         description: Username doesn't exists
 *       500:
 *         description: Error in creating set password link as user email is not registered with system.

 */
//TEST ME
router.post("/user/forgotPassword", (req, res) => {
  logger.info(
    utility.logFormatter(
      "das-backend",
      req.headers.host,
      "users",
      "Forgot Password"
    )
  );
  if (!validator.isLength(req.body.username, ENTITY_LENGTH_CONFIGURATION.USERNAME.minLength, ENTITY_LENGTH_CONFIGURATION.USERNAME.maxLength)) {
    return res
      .status(400)
      .send({ message: "Username exceeds permissible characters" });
  }
  database
    .get()
    .collection(constants.USERS_COLLECTION)
    .findOne({ username: req.body.username }, async (error, result) => {
      if (result) {
        let email = result.email;
        let role = result.user_role;
        let jwtTokenVerification;
        const payload = {
          username: req.body.username,
          jti:uuidv1(),
          aud:role
        };
        const accessToken = getPasswordAccessToken(payload);
        if (!accessToken) {
          return res.status(500).send({
            message:
              "Error in creating set password link as access token could not be created.",
          });
        }
        jwtTokenVerification = accessToken;
        let link =
          constants.DAS_FRONTEND_URL + constants.RESET_PASSWORD_PATH +
          jwtTokenVerification;

        const email_properties = {
          email: email,
          username: req.body.username,
          subject: "Reset Password",
          text: "Click the link below to reset your password",
          invalidemail_message: "Error in creating set password link as user email is not registered with system.",
          body: "Hello,<br> Please Click on the link to reset your password.<br><a href=" +
            link +
            ">Click here to reset password</a>", // html body
        };
        sendEmail(email_properties, req, res);

        res.status(200).send({ message: "Email sent to reset password" });
      } else {
        return res.status(400).send({ message: "Username doesn't exists" });
      }
    });
});

/**
 *@swagger
 * /user/resetPassword:
 *  post:
 *   tags:
 *    - api
 *   summary: reset password
 *   produces:
 *    - application/json:
 *   requestBody:
 *    content:
 *     application/json:
 *      schema:
 *       type: object
 *       properties:
 *        token:
 *         type: string
 *        newPW:
 *         type: string
 *        retypePW:
 *         type: string
 *   responses:
 *    200:
 *     description: Password updated.
 *    400:
 *     description: Password length does not comply with policy.
 *    500:
 *     description: token invalid.
 */
// TEST ME
router.post("/user/resetPassword", async function (req, res) {
  logger.info(
    utility.logFormatter(
      "das-backend",
      req.headers.host,
      "users",
      "Reset Password"
    )
  );

  let isVerified = false;
  let username = null;
  const jwtVerifiedResponse = verifyJWT(req.body.token);
  jwtVerifiedResponse
    .then(async (_verifiedResponse) => {
      if (!_verifiedResponse.valid) {
        return res.json({
          success: isVerified,
          message: "Token is invalid",
        });
      }
      isVerified = true;
      
      username = _verifiedResponse.user.user.username;
       

      let user_details = await database
        .get()
        .collection(constants.USERS_COLLECTION)
        .findOne({ username: username });
      const user_role = user_details.user_role;

      let allowedPasswordMinLength = ENTITY_LENGTH_CONFIGURATION.PASSWORD.minLength.USER;
      if (user_role.includes("admin")) {
        allowedPasswordMinLength = ENTITY_LENGTH_CONFIGURATION.PASSWORD.minLength.ADMIN;
      }
      if (isVerified && username) {
        console.log("Domain is matched. Information is from Authentic email");
        if (
          !validator.isLength(
            req.body.newPW,
            allowedPasswordMinLength,
            ENTITY_LENGTH_CONFIGURATION.PASSWORD.maxLength
          ) ||
          !validator.isLength(
            req.body.retypePW,
            allowedPasswordMinLength,
            ENTITY_LENGTH_CONFIGURATION.PASSWORD.maxLength
          )
        ) {
          return res
            .status(400)
            .send({ message: "Password length does not comply with policy." });
        }
        if (req.body.newPW !== req.body.retypePW) {
          return res.status(400).send({ message: "Passwords do not match." });
        }
        bcrypt.genSalt(10, (e, salt) => {
          bcrypt.hash(req.body.newPW, salt, (err, hash) => {
            if (err) throw err;

            req.body.newPW = hash;
            database
              .get()
              .collection(constants.USERS_COLLECTION)
              .updateOne(
                { username: username },
                {
                  $set: {
                    active: true,
                    password: req.body.newPW,
                    attempts: 0,
                    locked: false,
                    verified: true,
                    updated_ts: new Date(),
                    // update privacy policy timestamp while resetting password for user.
                    privacy_ts: new Date(),
                  },
                },
                (error) => {
                  if (error) {
                    return res.status(HTTP_CODES._5XX.INTERNAL_ERROR[0]).send({
                      success: false,
                      message: error,
                    });
                  }
                  res.status(200).send({
                    success: true,
                    message: "Password updated",
                  });
                }
              );
          });
        });
      } else {
        
        return res.status(HTTP_CODES._5XX.INTERNAL_ERROR[0]).json({
          success: isVerified,
          message: "Token is invalid",
        });
      }
    })
    .catch((err) => {
      
      return res.status(HTTP_CODES._5XX.INTERNAL_ERROR[0]).json({
        success: isVerified,
        message: "Token is invalid",
      });
    });
});
/**
 * @swagger
 *  /changepassword:
 *   post:
 *     tags:
 *       - api
 *     security:
 *      - bearerAuth: []
 *     summary: change password
 *     produces:
 *      - application/json
 *     requestBody:
 *         content:
 *          application/json:
 *           schema:
 *               type: object
 *               properties:
 *                 current_password:
 *                   type: string
 *                 new_password:
 *                   type: string
 *                 confirm_password:
 *                   type: string
 *     responses:
 *       200:
 *         description: Password changed successfully
 *       400:
 *         description: Password length does not comply with policy.
 *       500:
 *         description: Failed to update password.
 */

//Start: change password
router.post(
  "/changepassword",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    logger.info(
      utility.logFormatter(
        "das-backend",
        req.headers.host,
        "users",
        "Change Password"
      )
    );

    let current_password = req.body.current_password;
    let new_password = req.body.new_password;

    let confirm_password = req.body.confirm_password;
    const AuthHeader = req.header("Authorization").split(" ");
    let token = AuthHeader[1] || req.body.token;
    let username = null;
    let isVerified = false;
    const jwtVerifiedResponse = verifyJWT(token);

    jwtVerifiedResponse
      .then(async (_verifiedResponse) => {
        if (!_verifiedResponse.valid) {
          console.log(_verifiedResponse);
          return res.status(500).json({
            success: isVerified,
            message: "Failed to update password.",
          });
        }
        isVerified = true;

        username = _verifiedResponse.user.user.username;
        let allowedPasswordMinLength = ENTITY_LENGTH_CONFIGURATION.PASSWORD.minLength.USER;
        let user_details = await database
          .get()
          .collection(constants.USERS_COLLECTION)
          .findOne({ username: username });
        const user_role = user_details.user_role;
        if (user_role.includes("admin")) {
          allowedPasswordMinLength = ENTITY_LENGTH_CONFIGURATION.PASSWORD.minLength.ADMIN;
        }
        if (
          !validator.isLength(
            current_password,
            allowedPasswordMinLength,
            ENTITY_LENGTH_CONFIGURATION.PASSWORD.maxLength
          ) ||
          !validator.isLength(
            new_password,
            allowedPasswordMinLength,
            ENTITY_LENGTH_CONFIGURATION.PASSWORD.maxLength
          ) ||
          !validator.isLength(
            confirm_password,
            allowedPasswordMinLength,
            ENTITY_LENGTH_CONFIGURATION.PASSWORD.maxLength
          )
        ) {
          return res
            .status(400)
            .send({ message: "Password length does not comply with policy." });
        }

        if (isVerified && username) {
          database
            .get()
            .collection(constants.USERS_COLLECTION)
            .findOne({ username: username }, (error, result) => {
              if (error) {
                return res
                  .status(500)
                  .send({ message: "Failed to update password." });
              } else {
                if (result && result.password) {
                  bcrypt.compare(
                    current_password,
                    result.password,
                    (err, isMatch) => {
                      if (err) {
                        return res
                          .status(500)
                          .send({ message: "Failed to update password." });
                      }
                      if (isMatch) {
                        if (new_password === confirm_password) {
                          bcrypt.genSalt(10, (e, salt) => {
                            bcrypt.hash(
                              req.body.new_password,
                              salt,
                              (err, hash) => {
                                if (err) throw err;
                                req.body.new_password = hash;
                                database
                                  .get()
                                  .collection(constants.USERS_COLLECTION)
                                  .updateOne(
                                    { username: username },
                                    {
                                      $set: {
                                        password: req.body.new_password,
                                        updated_ts: new Date(),
                                      },
                                    },
                                    (error) => {
                                      if (error) {
                                        return res.status(500).send({
                                          message: "Failed to update password.",
                                        });
                                      }
                                      res.status(200).send({
                                        message:
                                          "Password changed successfully",
                                      });
                                    }
                                  );
                              }
                            );
                          });
                        } else {
                          res.status(400).send({
                            message: "Passwords do not match",
                          });
                        }
                      } else
                        res.status(400).send({
                          message: "Current password is invalid",
                        });
                    }
                  );
                } else {
                  res
                    .status(500)
                    .send({ message: "Failed to update password." });
                }
              }
            });
        } else {
          return res.status(500).json({
            success: isVerified,
            message: "Failed to update password.",
          });
        }
      })
      .catch((err) => {
        return res.status(500).json({
          success: false,
          message: "Failed to update password.",
        });
      });
  }
);

//End: change password

/**
 *@swagger
 * /users/{user_id}:
 *  get:
 *   tags:
 *    - api
 *   summary: get user by user id
 *   parameters:
 *    - name: user_id
 *      in: path
 *      type: string
 *   responses:
 *    500:
 *      description: error
 */
//Start: Get user details
router.get("/users/:user_id", (req, res) => {
  logger.info(
    utility.logFormatter(
      "das-backend",
      req.headers.host,
      "users",
      "Find a single user"
    )
  );

  database
    .get()
    .collection(constants.USERS_COLLECTION)
    .findOne({ user_id: req.params.user_id }, (error, result) => {
      if (error) {
        return res.status(500).send(error);
      }
      res.send(result);
    });
});

/**
 *@swagger
 * /users/byToken/{token}:
 *  get:
 *   tags:
 *    - api
 *   summary: get user by token
 *   parameters:
 *    - name: token
 *      in: path
 *      type: string
 *      required: true
 *   responses:
 *    500:
 *      description: invalid token
 */
router.get("/users/byToken/:token", (req, res) => {
  logger.info(
    utility.logFormatter(
      "das-backend",
      req.headers.host,
      "users",
      "Find a single user from a given token"
    )
  );
  const jwtVerifiedResponse = verifyJWT(req.params.token);
  jwtVerifiedResponse.then((verifiedResponse) => {
    if (
      verifiedResponse.valid &&
      verifiedResponse.user &&
      verifiedResponse.user.user.username
    ) {
      database
        .get()
        .collection(constants.USERS_COLLECTION)
        .findOne(
          { username: verifiedResponse.user.user.username },
          (error, result) => {
            if (error) {
              res.status(HTTP_CODES._5XX.INTERNAL_ERROR[0]).send(error);
            } else {
              const encryptedData = cryptoLib.encrypt(JSON.stringify(result));
              const userData = {
                e: encryptedData.encryptedData,
                iv: encryptedData.iv,
                s: encryptedData.secret,
              };

              res.status(HTTP_CODES._2XX.OK[0]).send(userData);
            }
          }
        );
    } else {
      res.status(HTTP_CODES._5XX.INTERNAL_ERROR[0]).json({
        success: false,
        message: "Token is invalid",
      });
    }
  });
});
/**
 *@swagger
 * /users:
 *   get:
 *     tags:
 *       - api
 *     name: List of Users
 *     summary: List of Users
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List if Users
 *       401:
 *         description: Authorization information is missing or invalid.
 *       500:
 *         description: Unexpected error.
 */
router.get(
  "/users",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    let loggedInUser = req.user;
    let query = {};
    if (
      loggedInUser.user_role.includes("admin") &&
      loggedInUser.customer_id == constants.TCS_ID
    ) {
    } else {
      query.customer_id = loggedInUser.customer_id;
    }
    database
      .get()
      .collection(constants.USERS_COLLECTION)
      .find(query)
      .project({
        username: 1,
        first_name: 1,
        last_name: 1,
        user_id: 1,
        user_role: 1,
        email: 1,
        customer_id: 1,
        updated_ts: 1,
        created_ts: 1,
        active: 1,
        locked: 1,
        tos_ts: 1,
        privacy_ts: 1,
        tour_complete: 1,
        verified: 1,
        username: 1,
        attempts: 1,
      })
      .toArray((error, result) => {
        if (error) {
          return res.status(500).send(error);
        }
        res.send(result);
      });
  }
);
//End: Get user details
/**
 *@swagger
 * /users/update:
 *   post:
 *     tags:
 *       - api
 *     summary: update user account status
 *     security:
 *      - bearerAuth: []
 *     produces:
 *      - application/json:
 *     requestBody:
 *         content:
 *          application/json:
 *           schema:
 *               type: object
 *               properties:
 *                 user_id:
 *                   type: string
 *                 attempt:
 *                   type: integer
 *                 locked:
 *                   type: string
 *                 active:
 *                   type: string
 *     responses:
 *       200:
 *         description: OK
 *       400:
 *         description: failed update Attempt.
 */
router.post(
  "/users/update",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    logger.info(
      utility.logFormatter(
        "das-backend",
        req.headers.host,
        "users",
        "Update user accout status"
      )
    );
    let attempt = 0;
    if (req.body.locked == true) {
      attempt = 3;
    }
    database
      .get()
      .collection(constants.USERS_COLLECTION)
      .updateOne(
        { user_id: req.body.user_id },
        {
          $set: {
            attempts: attempt,
            locked: req.body.locked,
            active: req.body.active,
            verified: req.body.verified,
            updated_ts: new Date(),
          },
        },
        async (error, result) => {
          if (error) {
            res.status(400).send({
              message: "Failed Update Attempt",
            });
          }
          await utility.logAdminActivity(
            req.user.user_id,
            req.method,
            req.url,
            req.body
          );
          res.send(result);
        }
      );
  }
);

/**
 *@swagger
 * /users/privacyUpdate/:
 *   post:
 *     tags:
 *       - api
 *     summary: update privacy policy
 *     produces:
 *      - application/json:
 *     requestBody:
 *         content:
 *          application/json:
 *           schema:
 *               type: object
 *               properties:
 *                 user_id:
 *                   type: string
 *     responses:
 *       200:
 *         description: privacy policy updated
 *       500:
 *         description: Bad Request
 */
router.post("/users/privacyUpdate/", (req, res) => {
  logger.info(
    utility.logFormatter(
      "das-backend",
      req.headers.host,
      "users",
      "Update privacy policy"
    )
  );

  database
    .get()
    .collection(constants.USERS_COLLECTION)
    .updateOne(
      { user_id: req.body.user_id },
      { $set: { privacy_ts: new Date(), updated_ts: new Date() } },
      (error, result) => {
        if (error) {
          res.send(error);
        }
        res.send(result);
      }
    );
});

/**
 *@swagger
 * /tos/:
 *   get:
 *     tags:
 *       - api
 *     summary: Retrieve Terms of Service policy
 *     responses:
 *      200:
 *       description:  Terms of Service policy
 */
router.get("/tos/", (req, res) => {
  logger.info(
    utility.logFormatter(
      "das-backend",
      req.headers.host,
      "users",
      "Update Terms of Service policy"
    )
  );

  database
    .get()
    .collection("system_configuration")
    .find({})
    .toArray((error, result) => {
      if (error) {
        res.send(error);
      }
      res.send(result);
    });
});

/**
 *@swagger
 * /privacy/:
 *   get:
 *    tags:
 *     - api
 *    summary: Retrieve customer Privacy policy 
 *    responses:
 *     200:
 *      description: Privacy policy
 *     500:
 *      description: Bad Request

 */
router.get("/privacy/", (req, res) => {
  logger.info(
    utility.logFormatter(
      "das-backend",
      req.headers.host,
      "users",
      "Retrieve Privacy policies by customer id"
    )
  );

  database
    .get()
    .collection("privacy_policy")
    .find({})
    .toArray((error, result) => {
      if (error) {
        res.send(error);
      }
      res.send(result);
    });
});

/**
 * @swagger
 *  /tos/add/:
 *   post:
 *    tags:
 *     - api
 *    summary: add terms of service for a customer
 *    security:
 *     - bearerAuth: []
 *    produces:
 *       - application/json
 *    requestBody:
 *         content:
 *          application/json:
 *           schema:
 *               type: object
 *               properties:
 *                 tos_html:
 *                   type: string
 *    responses:
 *     200:
 *      description: added terms of service for a customer
 *     500:
 *      description: Bad Request
 */
router.post(
  "/tos/add/",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    logger.info(
      utility.logFormatter(
        "das-backend",
        req.headers.host,
        "users",
        "add terms of service for a customer"
      )
    );

    console.log(req.body.tos_html);
    let obj = {
      tos_ts: new Date(),
      updated_ts: new Date(),
      tos_html: req.body.tos_html,
    };
    database
      .get()
      .collection("system_configuration")
      .insertOne(obj, async (error, result) => {
        if (error) {
          return res.status(500).send(error);
        }
        await utility.logAdminActivity(
          req.user.user_id,
          req.method,
          req.url,
          req.body
        );
        res.send(result);
      });
  }
);

/**
 * @swagger
 *  /tos/latest/:
 *   get:
 *     tags:
 *       - api
 *     summary: get latest terms of service for a customer
 *     responses:
 *      200:
 *        description: latest terms of service for a customer
 *      500:
 *        description: Bad Request
 */
router.get("/tos/latest/", (req, res) => {
  logger.info(
    utility.logFormatter(
      "das-backend",
      req.headers.host,
      "users",
      "get latest terms of service for a customer"
    )
  );

  database
    .get()
    .collection("system_configuration")
    .find({})
    .sort({ tos_ts: -1 })
    .limit(1)
    .project({ tos_ts: 1, tos_html: 1 })
    .toArray((error, result) => {
      if (error) {
        res.send(error);
      }
      res.send(result[0]);
    });
});

/**
 * @swagger
 *  /privacy/add:
 *   post:
 *     tags:
 *      - api
 *     summary: add privacy policy for a customer
 *     security:
 *      - bearerAuth: []
 *     produces:
 *       - application/json
 *     requestBody:
 *         content:
 *          application/json:
 *           schema:
 *               type: object
 *               properties:
 *                 privacy_html:
 *                   type: string
 *     responses:
 *       200:
 *         description:  privacy policy for a customer added
 *       500:
 *         description: Bad Request
 */
router.post(
  "/privacy/add",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    logger.info(
      utility.logFormatter(
        "das-backend",
        req.headers.host,
        "users",
        "add privacy policy for a customer"
      )
    );

    console.log(req.body.tos_html);
    let obj = {
      privacy_ts: new Date(),
      updated_ts: new Date(),
      privacy_html: req.body.privacy_html,
    };
    database
      .get()
      .collection("privacy_policy")
      .insertOne(obj, async (error, result) => {
        if (error) {
          return res.status(500).send(error);
        }
        await utility.logAdminActivity(
          req.user.user_id,
          req.method,
          req.url,
          req.body
        );
        res.send(result);
      });
  }
);
/**
 *@swagger
 * /privacy/latest/:
 *   get:
 *     tags:
 *       - api
 *     summary: get latest privacy policy for a customer
 *     responses:
 *       200:
 *         description: latest privacy policy for customer
 *       500:
 *         description: Bad Request
 */
router.get("/privacy/latest/", (req, res) => {
  logger.info(
    utility.logFormatter(
      "das-backend",
      req.headers.host,
      "users",
      "get latest privacy policy for a customer"
    )
  );

  database
    .get()
    .collection("privacy_policy")
    .find({})
    .sort({ privacy_ts: -1 })
    .limit(1)
    .project({ privacy_ts: 1, privacy_html: 1 })
    .toArray((error, result) => {
      if (error) {
        res.send(error);
      }
      res.send(result[0]);
    });
});

/**
 * @swagger
 *  /customer/add:
 *   post:
 *     tags:
 *      - api
 *     summary: Add new Customer
 *     security:
 *      - bearerAuth: []
 *     produces:
 *       - application/json
 *     requestBody:
 *      content:
 *       application/json:
 *        schema:
 *         type: object
 *         properties:
 *          customer_name:
 *           type: string
 *          customer_contact:
 *           type: string
 *     responses:
 *       200:
 *         description: customer added
 *       400:
 *         description: Customer name already exists
 *       500:
 *         description: Bad Request
 */
router.post(
  "/customer/add",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    logger.info(
      utility.logFormatter(
        "das-backend",
        req.headers.host,
        "customer",
        "Add new Customer"
      )
    );
    let doc = {
      customer_id: uuidv1(),
      customer_name: req.body.customer_name,
      customer_contact: req.body.customer_contact,
      created_ts: new Date(),
      updated_ts: new Date(),
      active: true,
    };
    database
      .get()
      .collection(constants.CUSTOMERS_COLLECTION)
      .distinct("customer_name", { active: true }, (error, result) => {
        if (error) {
          logger.error(
            utility.logFormatter(
              "das-backend",
              req.headers.host,
              "customer",
              `Error - ${error.message}, stack trace - ${error.stack}`
            )
          );
          res.send(error);
        }
        if (result) {
          for (const element of result) {
            console.log(element);
            if (element === req.body.customer_name) {
              return res
                .status(400)
                .send({ message: "Customer name already exists" });
            }
          }
          let doc = {
            customer_id: uuidv1(),
            customer_name: req.body.customer_name,
            customer_contact: req.body.customer_contact,
            created_ts: new Date(),
            updated_ts: new Date(),
            active: true,
          };
          database
            .get()
            .collection(constants.CUSTOMERS_COLLECTION)
            .insertOne(doc, async (error, result) => {
              if (error) {
                logger.error(
                  utility.logFormatter(
                    "das-backend",
                    req.headers.host,
                    "customer",
                    `Error - ${error.message}, stack trace - ${error.stack}`
                  )
                );
                res.send(error);
              }
              await addCustomerPrivacyPolicy(doc.customer_id);
              await utility.logAdminActivity(
                req.user.user_id,
                req.method,
                req.url,
                req.body
              );
              res.send(result);
            });
        }
      });
  }
);

/**
 *@swagger
 * /customers:
 *   get:
 *     tags:
 *      - api
 *     summary: get all active customers
 *     security:
 *      - bearerAuth: []
 *     responses:
 *       200:
 *         description: list of active customer
 *       500:
 *         description: Bad Request
 */
router.get(
  "/customers",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    logger.info(
      utility.logFormatter(
        "das-backend",
        req.headers.host,
        "customer",
        "get all active customers"
      )
    );

    database
      .get()
      .collection(constants.CUSTOMERS_COLLECTION)
      .find({ active: true })
      .toArray((error, result) => {
        if (error) {
          logger.error(
            utility.logFormatter(
              "das-backend",
              req.headers.host,
              "customer",
              `Error - ${error.message}, stack trace - ${error.stack}`
            )
          );
          return res.status(500).send(error);
        }
        res.send(result);
      });
  }
);

/**
 *@swagger
 * /user/reset-password/isValidToken/{token}:
 *  get:
 *   tags:
 *    - api
 *   summary: reset password token validation
 *   parameters:
 *    - name: token
 *      in: path
 *      type: string
 *      required: true
 *   responses:
 *    500:
 *      description: invalid token
 */
router.get(
  "/user/reset-password/isValidToken/:token",
  async function (req, res) {
    logger.info(
      utility.logFormatter(
        "das-backend",
        req.headers.host,
        "token",
        "Reset Password Token Validation"
      )
    );

    let isVerified = false;

    const jwtVerifiedResponse = verifyJWT(req.params.token);
    jwtVerifiedResponse.then((verifiedResponse) => {
      if (verifiedResponse.valid) {
        isVerified = true;
        return res.status(HTTP_CODES._2XX.OK[0]).json({
          success: isVerified,
          message: "Token is valid",
        });
      }
      return res.status(HTTP_CODES._5XX.INTERNAL_ERROR[0]).json({
        success: isVerified,
        message: "Token is invalid",
      });
    });
  }
);

router.get(
  "/heartbeat",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    logger.info(
      utility.logFormatter(
        "das-backend",
        req.headers.host,
        "jwt-api-heartbeat",
        "Get JWT API Token Heartbeat"
      )
    );

    res.send({ alive: true });
  }
);

router.post("/refresh-token", function (req, res) {
  const _refreshToken = req.body.refreshToken;
  if (!_refreshToken) {
    return res.status(HTTP_CODES._4XX.UNAUTHORIZED[1]).send({
      message: "Access is forbidden. No refresh token passed. Needs re-login.",
    });
  }
  try {
    const issueNewToken = refreshToken(_refreshToken, res);
    issueNewToken
      .then((_res) => {
        res.send(_res);
      })
      .catch((_rej) => {
        res.status(_rej.code).send(_rej.message);
      });
  } catch (err) {
    const message = {
      message: `Access is forbidden. ${(err && err.message) || err}`,
    };
    res.status(HTTP_CODES._4XX.UNAUTHORIZED[1]).send(message);
  }
});

router.post(
  "/sync-roles",
  passport.authenticate("jwt", { session: false }),
  function (req, res) {
    const roles = req.body;

    const loggedInUser = req.user;
    const user_id = loggedInUser.user_id;

    database
      .get()
      .collection(constants.USERS_COLLECTION)
      .findOne({ user_id: user_id }, (error, result) => {
        if (error) {
          return res
            .status(HTTP_CODES._4XX.UNAUTHORIZED[1])
            .send({ insync: false });
        }
        if (result && result.user_role) {
          if (JSON.stringify(roles) == JSON.stringify(result.user_role)) {
            return res.status(HTTP_CODES._2XX.OK[0]).send({ insync: true });
          }
          return res
            .status(HTTP_CODES._4XX.UNAUTHORIZED[0])
            .send({ insync: false });
        }
        return res
          .status(HTTP_CODES._4XX.UNAUTHORIZED[0])
          .send({ insync: false });
      });
  }
);

async function addCustomerPrivacyPolicy(customer_id) {
  let policy = await database
    .get()
    .collection("privacy_policy")
    .find({ customer_id: constants.TCS_ID })
    .sort({ privacy_ts: -1 })
    .limit(1)
    .project({ privacy_ts: 1, privacy_html: 1 })
    .toArray();

  let privacy_policy = {
    privacy_ts: new Date(),
    updated_ts: new Date(),
    privacy_html: policy[0].privacy_html,
    customer_id: customer_id,
  };
  return new Promise((resolve, reject) => {
    database
      .get()
      .collection(constants.PRIVACY_POLICY)
      .insertOne(privacy_policy, async (error, result) => {
        if (error) {
          logger.error(
            utility.logFormatter(
              "das-backend",
              host,
              "privacy_policy",
              `Error - ${error.message}, stack trace - ${error.stack}`
            )
          );
          reject(error);
        } else {
          resolve(result);
        }
      });
  });
}
function decryptUserData(email, fname, lname) {
  console.log(constants.INIT_VECTOR);
  console.log(constants.CRYPTO_KEY);
  let arr = [email, fname, lname];
  let ret_arr = [];
  for (const i of arr) {
    const decipher = crypto.createDecipheriv(
      constants.CRYPTO_ALGO,
      constants.CRYPTO_KEY,
      constants.INIT_VECTOR
    );
    let decryptedData = decipher.update(i, "hex", "utf-8");
    decryptedData += decipher.final("utf8");
    ret_arr.push(decryptedData);
  }
  return ret_arr;
}

function encryptUserData(email, fname, lname) {
  console.log(constants.INIT_VECTOR);
  console.log(constants.CRYPTO_KEY);
  let arr = [email, fname, lname];
  let ret_arr = [];
  for (const i of arr) {
    const cipher = crypto.createCipheriv(
      constants.CRYPTO_ALGO,
      constants.CRYPTO_KEY,
      constants.INIT_VECTOR
    );
    let encryptedData = cipher.update(i, "utf-8", "hex");
    encryptedData += cipher.final("hex");
    ret_arr.push(encryptedData);
  }
  return ret_arr;
}

/**
 * Send Email for Reset Password or while Adding user. Use nodemail to create SMTP email transfer using secured App
 *  
 * @param {*} emailDetails 
 * @param {*} req 
 * @returns 
 */
 function sendEmail(emailDetails, req, res) {
  return new Promise((resolve, reject) => {
    if (!emailDetails.email) {
      reject(emailDetails.invalidemail_message);
      return res.status(500).send({
        message: emailDetails.invalidemail_message,
      });
    }
    let mailOptions = {
      from: constants.EMAIL_CONFIG.FROM, // sender address
      to: emailDetails.email, // list of receivers
      subject: emailDetails.subject, // Subject line
      text: emailDetails.text, // plain text body
      html: emailDetails.body // html body
    };    
    if(constants.EMAIL_CONFIG.EMAIL_SENDGRID_API_KEY){      
      sgMail.setApiKey(constants.EMAIL_CONFIG.EMAIL_SENDGRID_API_KEY);

      sgMail.send(mailOptions)
      .then((response) => {
        logger.info(
          utility.logFormatter(
            "das-backend",
            req.headers.host,
            "sendMail",
            "Sending Email using sendgrid. StatusCode:"+response[0].statusCode+" Response Header:"+response[0].headers
          )
        );
        console.log(response[0].statusCode)
        console.log(response[0].headers)
      })
      .catch((error) => {
        reject(error);
        console.error(error)
        logger.error(
          utility.logFormatter(
            "das-backend",
            req.headers.host,
            "sendEmail",
            `Error - ${error.message}, stack trace - ${error.stack}`
          )
        );
      })
    }else{
      const transporter = nodemailer.createTransport({
        host: constants.EMAIL_CONFIG.HOST,
        port: constants.EMAIL_CONFIG.PORT,
        secure: constants.EMAIL_CONFIG.SECURE,      
        auth: {
          user: constants.EMAIL_CONFIG.USER,  
          pass: constants.EMAIL_CONFIG.PASSWORD // secured app  
        }
      });
  
      transporter.verify(function (error) {
        if (error) {
          reject(error);
          logger.error(
            utility.logFormatter(
              "das-backend",
              req.headers.host,
              "customer",
              `Error - ${error.message}, stack trace - ${error.stack}`
            )
          );
        } else {
          logger.info(
            utility.logFormatter(
              "das-backend",
              req.headers.host,
              "sendMail",
              "Server is ready to take messages"
            )
          );
          
          // Send the email
          transporter.sendMail(mailOptions, function (error, info) {
            if (error) {            
              logger.error(
                utility.logFormatter(
                  "das-backend",
                  req.headers.host,
                  "sendMail",
                  `Error - ${error.message}, stack trace - ${error.stack}`
                )
              );
              reject(error);
            } else {
              logger.info(
                utility.logFormatter(
                  "das-backend",
                  req.headers.host,
                  "sendMail",
                  "Email sent: " + info.response
                )
              );
              resolve(info.response);
            }
          })
        }
      });      
    }
    
    
  });
}

router.post(
  "/user/status/update",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    logger.info(
      utility.logFormatter(
        "das-backend",
        req.headers.host,
        "customer",
        "Update user status"
      )
    );

    console.log(req.body);

    let user_array = [];
    if (req.body.active === "true") {
      if (req.body.email.includes("@") && req.body.email.includes(".")) {
        user_array.push(req.body.email);
        user_array.push(req.body.first_name);
        user_array.push(req.body.last_name);
      } else {
        user_array = await decryptUserData(
          req.body.email,
          req.body.first_name,
          req.body.last_name
        );
      }
    } else {
      user_array = await encryptUserData(
        req.body.email,
        req.body.first_name,
        req.body.last_name
      );
    }

    req.body.email = user_array[0];
    req.body.first_name = user_array[1];
    req.body.last_name = user_array[2];
    database
      .get()
      .collection(constants.USERS_COLLECTION)
      .updateOne(
        { user_id: req.body.user_id },
        {
          $set: {
            active: req.body.active,
            email: req.body.email,
            first_name: req.body.first_name,
            last_name: req.body.last_name,
            updated_ts: new Date(),
          },
        },
        async (error, result) => {
          if (error) {
            res.status(400).send({
              message: "Failed Update Attempt",
            });
          }
          await utility.logAdminActivity(
            req.user.user_id,
            req.method,
            req.url,
            req.body
          );
          res.send(result);
        }
      );
  }
);

const getCustomerByID = (customer_id) => {
  return new Promise((resolve, reject) => {
    database
      .get()
      .collection(constants.CUSTOMERS_COLLECTION)
      .findOne({ customer_id: customer_id, active: true }, (err, data) => {
        if (err) {
          reject({ message: "No customer found" });
        } else {
          resolve(data);
        }
      });
  });
};

/**

* @swagger

* /file/download:
*   post:
*     tags:
*       - api
*     name: download after receiving url from file storage server.
*     summary: download after receiving url from file storage server.
*     security:
*       - bearerAuth: []
*     requestBody:
*      content:
*       application/json:
*        schema:
*         type: object
*         properties:
*          url:
*           type: string
*     responses:
*       200:
*         description: Ok
*       500:
*         description: Unexpected error
*       400:
*         description: Bad Request  
*/
router.post(
  "/file/download",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    logger.info(
      utility.logFormatter(
        "das-backend",
        req.headers.host,
        "Download",
        "download after receiving url from file storage server."
      )
    );
    const request = require("superagent");

    request.get(req.body.url).end((err, response) => {
      if (utility.isEmptyObject(response.body)) {
        res.send(response.text);
      } else res.send(response.body);
    });
  }
);

module.exports = router;
