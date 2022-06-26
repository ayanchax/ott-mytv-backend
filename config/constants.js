module.exports = {
  APPLICATION_BACKEND_NAME: "mytv-ott-backend",
  APP_BACKEND_DB: "mytv-ott",
  API_VERSION: "v1",
  //256 BIT SECRET_KEY FOR SIGNING JWT USING HS256 ALGORITHM
  SECRET_KEY:
    "$2a10$8p7bTV41UhCHJGbbkMH7zC4pbdsrB5fNCNwFsoLZ6rlHnYmiXlbSa1drCGxFDBfri9eQd313EW9WvCv3GIdysP3Qq6TYJ3RfKBUWIcxRnuZG10aUUidr6Lj8QPU3zEH614RnR5OI8BZaZpinb2xYK0TokxebpluLDTAFwMvKcZr9pOb4tbI1tpfcIV5QVKD7s14EkoXSAudZcOYbYKWExAO4Qk6WYAjmtb1GdrT3I6eKtjA5Rnkra.3zsW.Gd8",
  APP_BACKEND_URL: process.env.APP_BACKEND_HOST || "http://localhost:3000",
  APP_FRONTEND_URL: process.env.APP_FRONTEND_URL || "http://localhost:4200",
  CRYPTO_ALGO: "aes-256-cbc",
  TOKENS_COLLECTION:"tokens",
  USERS_COLLECTION:'users',
  HTTP_CODES: {
    _4XX: {
      UNAUTHORIZED: 401,
      FORBIDDEN: 403,
      NOT_FOUND: 404,
    },
    _2XX: {
      OK: 200,
      NO_CONTENT: 204,
    },
    _5XX: {
      INTERNAL_ERROR: 500,
    },
  },
  ENTITY_LENGTH_CONFIGURATION: {
    USERNAME: {
      name: "USERNAME",
      maxLength: 10,
      minLength: 10,
    },
    PASSWORD: {
      name: "PASSWORD",
      maxLength: 32,
      minLength: 15,
    },
  },
};
