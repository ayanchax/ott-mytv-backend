const express = require("express");
const app = express();
var cors = require("cors");
const helmet = require("helmet");
var mongoUtil = require("./config/connect");
const passport = require("passport");
var constants = require("./config/constants");
const compression = require("compression");
require("dotenv").config();
const path = require("path");
const {
  routeErrorHandler,
} = require("./routes/api/common/route-errors/error-handler");
const { V1: API_VERSION } = require("./config/constants");
const pingServerRouter = require("./routes/api/common/ping/ping");
const {
  SERVER_STARTED,
  ROUTES_VERIFIED,
  SWAGGER_DOCUMENTATION_VERIFIED,
} = require("./routes/api/messages/api-messages");
// Our static file location are stored in public folder under root directory
app.use(express.static(path.join(__dirname, "public")));
//Cors Start
var corsOptions = {
  allowedHeaders: [
    "sessionId",
    "Content-Type",
    "authorization",
    "Cache-Control",
    "X-Content-Type-Options",
    "x-tfa",
  ],
  exposedHeaders: ["sessionId", "Content-Type", "authorization"],
  methods: ["OPTIONS, GET, POST, PUT, PATCH, DELETE"],
  origin: ["*"],
};
// Cors End

// SERVER OPTIONS -START
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));
app.use(cors(corsOptions));
app.use(helmet.noSniff());
app.use(helmet.hidePoweredBy());
app.use(helmet.xssFilter());
app.use(
  helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true })
);
app.use(helmet.frameguard());
app.use(helmet.contentSecurityPolicy());
const shouldCompress = (req, res) => {
  if (req.headers["x-no-compression"]) {
    // Will not compress responses, if this header is present
    return false;
  }
  // Resort to standard compression
  return compression.filter(req, res);
};
app.use(
  compression({
    // filter: Decide if the answer should be compressed or not,
    // depending on the 'shouldCompress' function above
    filter: shouldCompress,
    // threshold: It is the byte threshold for the response
    // body size before considering compression, the default is 1 kB
    threshold: 0,
  })
);
// SERVER OPTIONS -END

// START CACHE SETTING CONFIG
let setCache = function (req, res, next) {
  res.set("Cache-control", "no-store, private");
  res.set("X-XSS-Protection", "1; mode=block");
  next();
};
app.use(setCache);
// END CACHE SETTING CONFIG

//Start: Swagger configuration
const swaggerUi = require("swagger-ui-express");
const swaggerJsdoc = require("swagger-jsdoc");
const userManagementRouter = require("./routes/api/v1/data/management/private/userManagementRouter");

const options = {
  swaggerDefinition: {
    openapi: "3.0.0",
    info: {
      title: `${constants.APPLICATION_BACKEND_NAME} - API Documentation`,
      version: "1.0.0",
      description: `${constants.APPLICATION_BACKEND_NAME} - API Documentation`,
    },
    servers: [
      {
        url: constants.APP_BACKEND_URL,
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT",
        },
      },
    },
  },
  apis: [
    `./routes/api/common/ping/ping.js`,
    `./routes/api/${API_VERSION}/data/management/private/userManagementRouter.js`,
  ],
};
const oasDefinition = swaggerJsdoc(options);
const swaggerOptions = {
  customSiteTitle: `${constants.APPLICATION_BACKEND_NAME} - API Documentation`,
  customCss: ".topbar { display: none }",
};

app.use(
  "/api-docs",
  swaggerUi.serve,
  swaggerUi.setup(oasDefinition, swaggerOptions)
);
app.get(
  `/${constants.APPLICATION_BACKEND_NAME}/${constants.V1}/swagger`,
  function (req, res) {
    res.setHeader("Content-Type", "application/json");
    res.send(oasDefinition);
  }
);
console.log(`${SWAGGER_DOCUMENTATION_VERIFIED}`);
//End: Swagger configuration

//Connect to our database instance, activate all our application routes/endpoints, apply authentication strategy for sensitive/private routes, handle invalid routes & turn on the application server.
mongoUtil.connectToMongoose(function (err) {
  if (err) {
    return;
  }
  const authMiddleWare = require("./middleware/auth");
  // apply jwt authentication strategy routing to passport(which is our application's middleware to authenticate sensitive routes) throughout the lifecycle of the application server.
  authMiddleWare.applyJWTAuthenticationStrategy(passport);

  // common ping/health check router
  app.use(`/api/common/ping/`, pingServerRouter);

  //public user routers

  //private user routers

  // private user data management/administrative routers, as of now build these routers without passport strategy, when UI is build for administration, protect these routes with passport

  app.use(`/api/${API_VERSION}/manage/user/`, userManagementRouter);

  //  common route error handling router
  app.use(routeErrorHandler());
  //  common route error handling router

  console.log(`${ROUTES_VERIFIED}`);
  //Turn on server.
  const port = process.env.PORT || "3000";
  app.listen(port, () => {
    console.log(`${SERVER_STARTED}${port}`);
  });
});
