const { HTTP_CODES } = require("../../../../config/constants");
function routeErrorHandler() {
  return function (err, res, next) {
    res
      .status(err.status || HTTP_CODES._5XX.INTERNAL_ERROR)
      .json({
        error: "Invalid route",
        status: err.status || HTTP_CODES._5XX.INTERNAL_ERROR,
        path:err.originalUrl,
        message:'The route you are trying to access is unavailable.',
      });
    
  };
}

// HANDLE OPERATIONAL/PROCESS ERRORS
// Simplifying the error handling with exact error message in the console in case of Unhandled Rejecttion of a any async task. This is experimental.
process.on("unhandledRejection", (error) => {
  console.log("unhandledRejection", error.message);
});

// Simplifying the error handling with exact error message in the console in case of Uncaught Exception. This is experimental.
process.on("uncaughtException", (err) => {
  console.error("There was an uncaught error", err);
  process.exit(1); //mandatory (as per the Node.js docs)
});

module.exports = {
  routeErrorHandler,
};
