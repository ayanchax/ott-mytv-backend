const winston = require('winston');
const { APPLICATION_BACKEND_NAME } = require('./constants');
const application_name = APPLICATION_BACKEND_NAME
var fluentTransport = require('fluent-logger').support.winstonTransport();
var fluent_config = {
  // host:'http://'+process.env.LOGGING_HOST,
  // port: 24224,
  // timeout: 3.0,
  // reconnectInterval: 1000,
  // requireAckResponse: false
};

var fluent = new fluentTransport(application_name, fluent_config);

var logger = winston.createLogger({
  format: winston.format.json(),
  format: winston.format.combine(
    winston.format.splat(),
    winston.format.json(),
    winston.format.errors({ stack: true }),
  ),
  transports: [fluent, new (winston.transports.Console)()]
});

logger.on('flush', () => {
  console.log("flush");
})

logger.on('finish', () => {
  console.log("finish");
  fluent.sender.end("end", {}, () => { })
});

module.exports = logger;