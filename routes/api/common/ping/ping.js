const express = require("express");
const { HTTP_CODES } = require("../../../../config/constants");
const api_messages = require("../../messages/api-messages");
const pingServerRouter = express.Router();

/** @swagger
 * /api/common/ping/:
 *  get:
 *    tags:
 *      - Ping
 *    name: Ping the back end server
 *    summary: Endpoint for pinging the back end service.
 
 *    produces:
 *       - application/json
 *    
 *    responses:
 *      200:
 *        description: You have succesfully pinged the mytv-ott-backend API service.
 *      500:
 *        description: The route you are trying to access is unavailable.
 *
 */
pingServerRouter.get("/", (req, res, next) => {
  res.status(HTTP_CODES._2XX.OK).json({
    message: api_messages.PING_OK,
    code: HTTP_CODES._2XX.OK,
  });
});

module.exports = pingServerRouter;
