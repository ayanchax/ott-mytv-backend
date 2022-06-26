const express = require("express");
const { HTTP_CODES } = require("../../../../config/constants");
const api_messages = require("../../messages/api-messages");
const pingServerRouter = express.Router();

/**
 * @swagger
 * /:
 *   get:
 *     description:  Endpoint for pinging the back end service.
 */
pingServerRouter.get("/", (req, res, next) => {
  res.status(HTTP_CODES._2XX.OK).json({
    message: api_messages.PING_OK,
    code: HTTP_CODES._2XX.OK,
  });
});

module.exports = pingServerRouter;
