const express = require("express");
const {
  HTTP_CODES,
  ENTITY_LENGTH_CONFIGURATION,
} = require("../../../../../../config/constants");
const api_messages = require("../../../../messages/api-messages");
const userManagementRouter = express.Router();
const { body, validationResult } = require("express-validator");
const User = require("../../../../../../models/user");
const { getUUID } = require("../../../../../../utils/helper");
const bcrypt = require("bcryptjs");

/** @swagger
 *  /api/v1/manage/user/add:
 *   post:
 *     tags:
 *       - Manage User
 *     security:
 *      - bearerAuth: []
 *     summary: Adds an user to the system.
 *     produces:
 *      - application/json
 *     requestBody:
 *         content:
 *          application/json:
 *           schema:
 *               type: object
 *               properties:
 *                 mobile:
 *                   type: string
 *                   required: true

 *                 password:
 *                   type: string
 *                   required: true

 *                 service_provider_id:
 *                   type: string
 *                   required: true
 
 *                 created_ts:
 *                   type: string
 *                 modified_ts:
 *                   type: string
 *                 isActive:
 *                   type: boolean
 *                 username:
 *                   type: string
 *                 deviceID:
 *                   type: string
 *                 name:
 *                   type: string
 *                 lastWatchedMovieID:
 *                   type: string
 *                 currentlyWatchingMovieID:
 *                   type: string
 *                 isLoggedIn:
 *                   type: boolean
 *                 created_by:
 *                   type: string
 *     responses:
 *       201:
 *         description: User created successfully.
 *       400:
 *         description: Bad Request encountered.
 *       500:
 *         description: An internal error occurred.
 */
userManagementRouter.post(
  "/add",
  body("mobile")
    .not()
    .isEmpty()
    .trim()
    .escape()
    .isMobilePhone()
    .withMessage("must be a valid mobile number of 10 digits."),
  body("service_provider_id")
    .not()
    .isEmpty()
    .trim()
    .escape()
    .withMessage("is required"),
  body("isActive").toBoolean(),
  body("password")
    .isLength({
      min: ENTITY_LENGTH_CONFIGURATION.PASSWORD.minLength,
      max: ENTITY_LENGTH_CONFIGURATION.PASSWORD.maxLength,
    })
    .withMessage(
      `must be atleast ${ENTITY_LENGTH_CONFIGURATION.PASSWORD.minLength} chars long`
    ),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(HTTP_CODES._4XX.BAD_REQUEST).json({
        error: api_messages.ERRORS.BAD_REQUEST.TITLE,
        code: HTTP_CODES._4XX.BAD_REQUEST,
        message: api_messages.ERRORS.BAD_REQUEST.DESCRIPTION,
        diagnostics: errors.array(),
      });
    }

    bcrypt.genSalt(
      10,
      (e, salt) => {
        bcrypt.hash(req.body.password, salt, (err, hash) => {
          if (err)
            return res.status(HTTP_CODES._5XX.INTERNAL_ERROR).json({
              error: api_messages.ERRORS.INTERNAL_ERROR.TITLE,
              code: HTTP_CODES._5XX.INTERNAL_ERROR,
              message: api_messages.ERRORS.INTERNAL_ERROR.DESCRIPTION,
              diagnostics: err.message,
            });
          req.body.password = hash;
          const user = new User({
            user_id: getUUID(),
            mobile: req.body.mobile,
            password: req.body.password,
            service_provider_id: req.body.service_provider_id,
            created_ts: new Date().toISOString(),
            modified_ts: new Date().toISOString(),
            isActive: req.body.isActive,
            username: req.body.username || null,
            deviceID: req.body.deviceID || null,
            name: req.body.name || null,
            lastWatchedMovieID: req.body.lastWatchedMovieID || null,
            currentlyWatchingMovieID: req.body.currentlyWatchingMovieID || null,
            isLoggedIn: req.body.isLoggedIn || false,
            created_by: req.body.created_by || "ANONYMOUS",
          });
          user
            .save()
            .then((val) => {
              res.status(HTTP_CODES._2XX.CREATED).json({
                message: api_messages.USER.created,
                code: HTTP_CODES._2XX.CREATED,
                data: val,
              });
            })
            .catch((err) => {
              res.status(HTTP_CODES._5XX.INTERNAL_ERROR).json({
                error: api_messages.ERRORS.INTERNAL_ERROR.TITLE,
                code: HTTP_CODES._5XX.INTERNAL_ERROR,
                message:
                  err.toString() ||
                  api_messages.ERRORS.INTERNAL_ERROR.DESCRIPTION,
                diagnostics: err,
              });
            });
        });
      },
      (error, result) => {
        return res.status(HTTP_CODES._5XX.INTERNAL_ERROR).json({
          error: api_messages.ERRORS.INTERNAL_ERROR.TITLE,
          code: HTTP_CODES._5XX.INTERNAL_ERROR,
          message: api_messages.ERRORS.INTERNAL_ERROR.DESCRIPTION,
          diagnostics: error,
        });
      }
    );
  }
);

module.exports = userManagementRouter;
