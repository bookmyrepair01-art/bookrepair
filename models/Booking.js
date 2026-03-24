const mongoose = require("mongoose");

const generateTrackingId = () => {
  const random = Math.random().toString(36).slice(2, 8).toUpperCase();
  return `SB-${Date.now().toString(36).toUpperCase()}-${random}`;
}

const bookingSchema = new mongoose.Schema(
  {
    trackingId: { type: String, unique: true, index: true, default: generateTrackingId },
    brand: { type: String, required: true, trim: true },
    model: { type: String, required: true, trim: true },
    service: { type: String, required: true, trim: true },
    selectedIssues: [{ type: String, trim: true }],
    issueOne: { type: String, trim: true },
    issueTwo: { type: String, trim: true },
    name: { type: String, required: true, trim: true },
    phone: { type: String, required: true, trim: true },
    email: { type: String, trim: true, lowercase: true },
    pickupOption: { type: String, trim: true, default: "Pickup & Drop" },
    address: { type: String, required: true, trim: true },
    pickupAddress: { type: String, trim: true, default: "" },
    pickupPhone: { type: String, trim: true, default: "" },
    pickupMapUrl: { type: String, trim: true, default: "" },
    location: {
      type: String,
      trim: true,
      default: function defaultLocation() {
        return this.address;
      },
    },
    status: { type: String, trim: true, default: "Pending" },

    technician: { type: String, trim: true, default: "" },
    technicianId: { type: mongoose.Schema.Types.ObjectId, ref: "Technician", default: null },
    technicianName: { type: String, trim: true, default: "" },
    technicianPhone: { type: String, trim: true, default: "" },

    technicianEmployeeId: { type: String, trim: true, default: "" },
    technicianPhoto: { type: String, trim: true, default: "" },
    technicianVerified: { type: Boolean, default: false },

    visitOtpHash: { type: String, select: false, default: "" },
    visitOtpSalt: { type: String, select: false, default: "" },
    visitOtpExpiresAt: { type: Date, default: null },
    visitOtpVerifiedAt: { type: Date, default: null },

    liveLocation: {
      lat: { type: Number, default: null },
      lng: { type: Number, default: null },
      updatedAt: { type: Date, default: null },
    },
    mapUrl: { type: String, trim: true, default: "" },
    adminNote: { type: String, trim: true, default: "" },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Booking", bookingSchema);
