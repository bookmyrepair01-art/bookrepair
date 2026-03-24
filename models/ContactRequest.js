const mongoose = require("mongoose");

const contactSchema = new mongoose.Schema(
  {
    name: String,
    email: String,
    phone: String,
    address: String,
    brand: String,
    model: String,
    issue: String,
    message: String
  },
  { timestamps: true }
);

module.exports = mongoose.model("Contact", contactSchema);
