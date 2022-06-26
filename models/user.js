const mongoose = require("mongoose");
const userSchema = new mongoose.Schema({
  user_id: {
    type: String,
    required: true,
  },

  mobile: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true,
  },
  service_provider_id: {
    type: String,
    required: true,
  },
  created_ts: {
    type: String,
    required: true,
  },
  modified_ts: {
    type: String,
    required: true,
  },
  isActive: {
    type: Boolean,
    required: true,
  },
  username: {
    type: String,
    required: false,
  },
  deviceID: {
    type: String,
    required: false,
  },
  name: {
    type: String,
    required: false,
  },

  lastWatchedMovieID: {
    type: String,
    required: false,
  },

  currentlyWatchingMovieID: {
    type: String,
    required: false,
  },
  isLoggedIn: {
    type: Boolean,
    required: false,
  },
  created_by: {
    type: String,
    required: false,
  },
});
const User = mongoose.model("User", userSchema);
module.exports = User;
