const { APPLICATION_BACKEND_NAME } = require("../../../config/constants");

const api_messages = {
  AMBIGIOUS: "User Input Blank or Null or ambigious.",
  SUPPLY_VALID_IDENTIFIER: "Supply a valid identifier.",
  NO_SEARCH_RESULTS: "No search results found.",
  ERROR: "Error occured.",
  SERVER_STARTED: "Server started successfully on port ",
  ROUTES_VERIFIED: "API routes verified successfully.",
  SWAGGER_DOCUMENTATION_VERIFIED: "Verified swagger API documentation.",
  OPERATION_FAILED:
    "Operation failed. Please try again or contact support if problem persists.",
  PING_OK: `You have succesfully pinged the ${APPLICATION_BACKEND_NAME} API service.`,
  CONNECTION_OK: `You have succesfully connected to the ${APPLICATION_BACKEND_NAME} API service database server.`,
  CONNECTION_FAILED: `Failed to connect to the ${APPLICATION_BACKEND_NAME} API service database server.`,
  USER: {
    created: "User created successfully.",
    updated: "User updated successfully.",
    deleted: "User deleted successfully.",
    already_verified: "User already verified",
    account_verified: "User account verified successfully.",
    already_activated: "User already activated",
    account_activated: "User account activated successfully.",
    already_deactivated: "User already Deactivated.",
    account_deactivated: "User account Deactivated successfully.",
    password_changed: "User password changed successfully.",
    old_password_incorrect: "Old password entered is incorrect.",
    password_change_error:
      "Password could not be changed. Possible reason could be either the user does not exist or is deactivated or the old password you entered is incorrect. Please contact support.",
    verification_link_generated:
      "User verification link generated successfully.",
    verification_link_exists: "User verification link already exists.",
    no_verification_link:
      "No user verification link generated. Please contact support for account verification link.",
    required_fields_error:
      "Required user fields missing. Requird fields are userid, password,name,st_address_ln1,city,pincode, state,country,mobile_number.",
    password_error:
      "Password must be min 8 letters, with at least a special symbol, upper and lower case letters and a number.",
    user_id_error: "User id must be a valid email address.",
    pincode_error: "Pincode must be a 6 digit number.",
    mobile_number_error: "Phone number must be a 10 digit number.",
    object_missing_update_error:
      "Provide a valid object identifier to update user details.",
    not_found_error: "No User found to update.",
    no_user_found: "No User found.",
    no_users_found: "No Users found.",
    no_user_found_to_delete: "No User found to delete.",
    no_active_users_found: "No Active Users found.",
    no_inactive_users_found: "No Inactive Users found.",
    user_not_active: "User is not active",
    user_not_inactive: "User is not inactive",
    cannot_delete_active_user:
      "User is active, you cannot delete it. To remove a user permanently, you need to deactivate the user first. For more information, please refer to API docs or contact support.",
    required_fields_for_password_change_error:
      "Required fields for password change missing. Requird fields are oldPassword,newPassword,confirmNewPassword.",
    password_mismatch_error:
      "New password does not match with the confirm password.",
    authentication_error: "Authentication error",
    authentication_error_message: "Incorrect email and/or password.",
    authentication_done: "User is authenticated successfully.",
    authorization_error: "Authorization error",
    authorization_done: "User is authorized successfully.",
    unauthorization_error: "Un-Authorization error",
    unauthorization_done: "User is unauthorized successfully.",
  },
  ERRORS: {
    INTERNAL_ERROR: {
      TITLE: "Internal Error",
      DESCRIPTION: "An internal error occurred.",
    },
    BAD_REQUEST: {
      TITLE: "Bad Request",
      DESCRIPTION: "Bad Request encountered.",
    },
  },
};
module.exports = api_messages;
