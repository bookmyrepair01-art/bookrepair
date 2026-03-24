const mongoose = require("mongoose");

const ServiceSchema = new mongoose.Schema({

  image: {
    type: String
  },

  name: {
    type: String,
    required: true
  },

  subtitle: {
    type: String
  }

},{
  timestamps: true
});

module.exports = mongoose.model("Service", ServiceSchema);
