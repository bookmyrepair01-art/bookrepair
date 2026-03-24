require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const crypto = require("crypto");
const multer = require("multer");
const fs = require("fs");
const path = require("path");

const Brand = require("./models/Brand");
const Model = require("./models/Model");
const Booking = require("./models/Booking");
const Admin = require("./models/Admin");
const Technician = require("./models/Technician");
const Service = require("./models/Service");
const ContactRequest = require("./models/ContactRequest");
const csv = require("csv-parser");
const { verifyTrackingToken } = require("./utils/trackingToken");

const {
  sendBookingEmail,
  sendBookingUpdateEmail,
  sendCustomerOtpEmail,
  sendTechnicianVisitOtpEmail
} = require("./services/bookingNotifications");

const app = express();
const PORT = process.env.PORT || 5000;
app.use(cors({
  origin: [
    "http://localhost:3000",
    "https://servizy.netlify.app"
  ],
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: [
    "Content-Type",
    "Authorization",
    "x-customer-auth"
  ],
  credentials: true,
}));
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));


/* ================= DATABASE ================= */
require("dotenv").config();

mongoose
  .connect(process.env.MONGO_URI, {
    dbName: "mybook"
  })
  .then(() => {
    console.log("✅ MongoDB Connected to mybook");
    app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
    });
  })
  .catch((err) => console.log("MongoDB error:", err));
/* ================= ROOT ================= */

app.get("/", (req, res) => {
  res.send("Server is running ✅");
});

/* ================= PASSWORD UTILS ================= */

const hashPassword = (password, salt) =>
  crypto.pbkdf2Sync(password, salt, 100000, 64, "sha512").toString("hex");

const generateToken = () => crypto.randomBytes(24).toString("hex");

/* ================= CUSTOMER AUTH UTILS ================= */
const CUSTOMER_OTP_TTL_MS = Math.max(
  60000,
  Number(process.env.CUSTOMER_OTP_TTL_MS || 10 * 60 * 1000)
);
const CUSTOMER_OTP_RESEND_INTERVAL_MS = Math.max(
  15000,
  Number(process.env.CUSTOMER_OTP_RESEND_INTERVAL_MS || 60 * 1000)
);
const CUSTOMER_OTP_MAX_VERIFY_ATTEMPTS = Math.max(
  3,
  Number(process.env.CUSTOMER_OTP_MAX_VERIFY_ATTEMPTS || 5)
);
const CUSTOMER_SESSION_TTL_MS = Math.max(
  300000,
  Number(process.env.CUSTOMER_SESSION_TTL_MS || 12 * 60 * 60 * 1000)
);
const VISIT_OTP_TTL_MS = Math.max(
  5 * 60 * 1000,
  Number(process.env.VISIT_OTP_TTL_MS || 4 * 60 * 60 * 1000)
);
const CUSTOMER_AUTH_SECRET = String(
  process.env.CUSTOMER_AUTH_SECRET || "bookmyrepair-dev-customer-secret"
).trim();

if (!process.env.CUSTOMER_AUTH_SECRET) {
  console.warn(
    "CUSTOMER_AUTH_SECRET is missing. Using fallback secret; set it in production."
  );
}

const customerOtpStore = new Map();

const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
const isValidIndianPhone = (phone) => /^[6-9]\d{9}$/.test(phone) && !/^(\d)\1{9}$/.test(phone);

const normalizeCustomerInput = (payload = {}) => ({
  name: String(payload.name || "").trim(),
  phone: String(payload.phone || "").trim(),
  email: String(payload.email || "").trim().toLowerCase()
});

const getCustomerIdentityError = ({ name, phone, email }) => {
  if (!name || !phone || !email) return "Name, mobile and email are required.";
  if (!isValidIndianPhone(phone)) return "Enter a valid 10-digit mobile number.";
  if (!isValidEmail(email)) return "Please enter a valid email address.";
  return "";
};

const generateOtpCode = () => String(Math.floor(100000 + Math.random() * 900000));

const hashOtp = (otp, salt) =>
  crypto.createHash("sha256").update(`${otp}.${salt}`).digest("hex");

const safeEqual = (valueA, valueB) => {
  const a = Buffer.from(String(valueA || ""));
  const b = Buffer.from(String(valueB || ""));

  if (a.length !== b.length) return false;

  return crypto.timingSafeEqual(a, b);
};

const createCustomerAuthSignature = (payloadB64) =>
  crypto
    .createHmac("sha256", CUSTOMER_AUTH_SECRET)
    .update(payloadB64)
    .digest("base64url");

const createCustomerSessionToken = (customer) => {
  const payload = {
    name: customer.name,
    phone: customer.phone,
    email: customer.email,
    exp: Date.now() + CUSTOMER_SESSION_TTL_MS
  };

  const payloadB64 = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const signature = createCustomerAuthSignature(payloadB64);

  return `${payloadB64}.${signature}`;
};

const verifyCustomerSessionToken = (token) => {
  const rawToken = String(token || "").trim();

  if (!rawToken || !rawToken.includes(".")) return null;

  const [payloadB64, signature = ""] = rawToken.split(".");
  const expectedSignature = createCustomerAuthSignature(payloadB64);

  if (!safeEqual(signature, expectedSignature)) return null;

  try {
    const decoded = JSON.parse(
      Buffer.from(payloadB64, "base64url").toString("utf8")
    );

    if (!decoded?.exp || Number(decoded.exp) < Date.now()) return null;

    const identity = normalizeCustomerInput(decoded);
    const error = getCustomerIdentityError(identity);

    if (error) return null;

    return identity;
  } catch (error) {
    return null;
  }
};

const getCustomerAuthTokenFromRequest = (req) => {
  const customHeader = req.headers["x-customer-auth"];
  if (customHeader) return String(customHeader).trim();

  const authHeader = String(req.headers.authorization || "").trim();
  if (authHeader.toLowerCase().startsWith("bearer ")) {
    return authHeader.slice(7).trim();
  }

  return "";
};

const requireCustomerAuth = (req, res, next) => {
  const token = getCustomerAuthTokenFromRequest(req);
  const session = verifyCustomerSessionToken(token);

  if (!session) {
    return res.status(401).json({
      error: "Session expired. Please login with OTP again."
    });
  }

  req.customerSession = session;
  return next();
};

const cleanOtpStore = () => {
  const now = Date.now();

  for (const [key, entry] of customerOtpStore.entries()) {
    if (!entry || now > entry.expiresAt + CUSTOMER_OTP_RESEND_INTERVAL_MS) {
      customerOtpStore.delete(key);
    }
  }
};

/* ================= IMAGE UPLOAD ================= */

const uploadPath = path.join(__dirname, "uploads");

if (!fs.existsSync(uploadPath)) {
  fs.mkdirSync(uploadPath, { recursive: true });
}

app.use("/uploads", express.static(uploadPath));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadPath),
  filename: (req, file, cb) =>
    cb(null, Date.now() + "-" + file.originalname)
});

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith("image/")) cb(null, true);
    else cb(new Error("Only images allowed"), false);
  }
});

/* ================= ADMIN ================= */

app.post("/api/admin/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const exist = await Admin.findOne({ email });
    if (exist) return res.status(400).json({ error: "Email exists" });

    const salt = crypto.randomBytes(16).toString("hex");
    const hash = hashPassword(password, salt);

    const admin = await Admin.create({
      name,
      email,
      passwordHash: hash,
      passwordSalt: salt
    });

    res.json(admin);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/admin/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const admin = await Admin.findOne({ email });
    if (!admin) return res.status(401).json({ error: "Invalid login" });

    const hash = hashPassword(password, admin.passwordSalt);

    if (hash !== admin.passwordHash)
      return res.status(401).json({ error: "Invalid login" });

    res.json({
      message: "Login success",
      token: generateToken(),
      admin
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ================= CUSTOMER OTP AUTH ================= */

app.post("/api/customer-auth/request-otp", async (req, res) => {
  try {
    cleanOtpStore();

    const customer = normalizeCustomerInput(req.body);
    const inputError = getCustomerIdentityError(customer);

    if (inputError) {
      return res.status(400).json({ error: inputError });
    }

    const customerKey = `${customer.email}::${customer.phone}`;
    const existingEntry = customerOtpStore.get(customerKey);
    const now = Date.now();

    if (existingEntry?.nextSendAllowedAt > now) {
      const retryAfterSeconds = Math.ceil(
        (existingEntry.nextSendAllowedAt - now) / 1000
      );

      return res.status(429).json({
        error: `Please wait ${retryAfterSeconds} seconds before requesting another OTP.`,
        retryAfterSeconds
      });
    }

    const otpCode = generateOtpCode();
    const otpSalt = crypto.randomBytes(16).toString("hex");

    customerOtpStore.set(customerKey, {
      ...customer,
      otpHash: hashOtp(otpCode, otpSalt),
      otpSalt,
      expiresAt: now + CUSTOMER_OTP_TTL_MS,
      nextSendAllowedAt: now + CUSTOMER_OTP_RESEND_INTERVAL_MS,
      remainingAttempts: CUSTOMER_OTP_MAX_VERIFY_ATTEMPTS
    });

    try {
      await sendCustomerOtpEmail({
        email: customer.email,
        name: customer.name,
        otpCode,
        expiresInMinutes: Math.ceil(CUSTOMER_OTP_TTL_MS / 60000)
      });
    } catch (emailError) {
      customerOtpStore.delete(customerKey);
      throw emailError;
    }

    return res.json({
      message: "OTP sent successfully.",
      expiresInSeconds: Math.floor(CUSTOMER_OTP_TTL_MS / 1000),
      resendInSeconds: Math.floor(CUSTOMER_OTP_RESEND_INTERVAL_MS / 1000)
    });
  } catch (error) {
    console.error("Customer OTP request error:", error);
    return res.status(500).json({
      error: "Unable to send OTP right now. Please try again."
    });
  }
});

app.post("/api/customer-auth/verify-otp", async (req, res) => {
  try {
    cleanOtpStore();

    const customer = normalizeCustomerInput(req.body);
    const inputError = getCustomerIdentityError(customer);

    if (inputError) {
      return res.status(400).json({ error: inputError });
    }

    const otpCode = String(req.body?.otp || "").trim().replace(/\D/g, "");
    if (!/^\d{6}$/.test(otpCode)) {
      return res.status(400).json({ error: "Enter a valid 6-digit OTP." });
    }

    const customerKey = `${customer.email}::${customer.phone}`;
    const otpEntry = customerOtpStore.get(customerKey);

    if (!otpEntry) {
      return res.status(400).json({
        error: "OTP not found or expired. Please request a new OTP."
      });
    }

    if (Date.now() > otpEntry.expiresAt) {
      customerOtpStore.delete(customerKey);
      return res.status(400).json({
        error: "OTP expired. Please request a new OTP."
      });
    }

    if (otpEntry.remainingAttempts <= 0) {
      customerOtpStore.delete(customerKey);
      return res.status(429).json({
        error: "Too many invalid attempts. Please request a new OTP."
      });
    }

    const incomingOtpHash = hashOtp(otpCode, otpEntry.otpSalt);
    const isOtpValid = safeEqual(incomingOtpHash, otpEntry.otpHash);

    if (!isOtpValid) {
      otpEntry.remainingAttempts -= 1;
      customerOtpStore.set(customerKey, otpEntry);

      if (otpEntry.remainingAttempts <= 0) {
        customerOtpStore.delete(customerKey);
        return res.status(429).json({
          error: "Too many invalid attempts. Please request a new OTP."
        });
      }

      return res.status(401).json({
        error: `Invalid OTP. ${otpEntry.remainingAttempts} attempts left.`
      });
    }

    customerOtpStore.delete(customerKey);

    const customerSession = {
      name: otpEntry.name,
      phone: otpEntry.phone,
      email: otpEntry.email
    };
    const token = createCustomerSessionToken(customerSession);

    return res.json({
      message: "OTP verified successfully.",
      token,
      customer: customerSession,
      expiresInSeconds: Math.floor(CUSTOMER_SESSION_TTL_MS / 1000)
    });
  } catch (error) {
    console.error("Customer OTP verify error:", error);
    return res.status(500).json({
      error: "Unable to verify OTP right now. Please try again."
    });
  }
});

/* ================= CONTACT REQUESTS ================= */

app.post("/api/contact", async (req, res) => {
  try {
    const payload = req.body || {};
    const name = String(payload.name || "").trim();
    const email = String(payload.email || "").trim().toLowerCase();
    const message = String(payload.message || "").trim();

    if (!name || !email || !message) {
      return res.status(400).json({
        error: "Name, email and message are required."
      });
    }

    const saved = await ContactRequest.create({
      name,
      email,
      phone: String(payload.phone || "").trim(),
      address: String(payload.address || "").trim(),
      brand: String(payload.brand || "").trim(),
      model: String(payload.model || "").trim(),
      issue: String(payload.issue || "").trim(),
      message
    });

    return res.json(saved);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.get("/api/contact", async (req, res) => {
  try {
    const items = await ContactRequest.find().sort({ createdAt: -1 });
    return res.json(items);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.delete("/api/contact/:id", async (req, res) => {
  try {
    await ContactRequest.findByIdAndDelete(req.params.id);
    return res.json({ message: "Contact deleted ✅" });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

/* ================= BRANDS ================= */

app.post("/api/brands", async (req, res) => {
  const brand = await Brand.create(req.body);
  res.json(brand);
});

app.get("/api/brands", async (req, res) => {
  const brands = await Brand.find().sort({ createdAt: -1 });
  res.json(brands);
});

app.put("/api/brands/:id", async (req, res) => {
  const brand = await Brand.findByIdAndUpdate(req.params.id, req.body, {
    new: true
  });
  res.json(brand);
});

app.delete("/api/brands/:id", async (req, res) => {
  await Model.deleteMany({ brandId: req.params.id });
  await Brand.findByIdAndDelete(req.params.id);
  res.json({ message: "Brand deleted" });
});

/* ================= MODELS ================= */

// ================= CSV UPLOAD =================
let csvData = [];

app.post("/api/models", async (req, res) => {
  const model = await Model.create(req.body);
  res.json(model);
});

app.get("/api/models", async (req, res) => {
  try {
    const data = await Model.find().populate("brandId");
    console.log("📦 Sending data:", data); // DEBUG
    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/models/:id", async (req, res) => {
  const model = await Model.findByIdAndUpdate(req.params.id, req.body, {
    new: true
  });
  res.json(model);
});

app.delete("/api/models/:id", async (req, res) => {
  await Model.findByIdAndDelete(req.params.id);
  res.json({ message: "Model deleted" });
});

const normalizeBulkCsvKey = (value) =>
  String(value || "")
    .replace(/\uFEFF/g, "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, "_");

const escapeRegex = (value) =>
  String(value || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const normalizeBulkModelRow = (row = {}) => {
  const normalized = {};

  for (const [key, value] of Object.entries(row || {})) {
    normalized[normalizeBulkCsvKey(key)] = String(value || "").trim();
  }

  const name = String(
    normalized.name ||
      normalized.model ||
      normalized.model_name ||
      normalized.modelname ||
      ""
  ).trim();
  const brand = String(
    normalized.brand ||
      normalized.brand_name ||
      normalized.brandname ||
      normalized.company ||
      ""
  ).trim();

  return { name, brand };
};

app.post("/api/models/bulk", async (req, res) => {
  try {
    const rows = req.body;

    if (!Array.isArray(rows)) {
      return res.status(400).json({ error: "Invalid data format" });
    }

    const createdModels = [];
    let skipped = 0;

    for (const item of rows) {
      const { name, brand } = normalizeBulkModelRow(item);

      if (!name || !brand) {
        skipped += 1;
        continue;
      }

      let brandDoc = await Brand.findOne({
        name: { $regex: `^${escapeRegex(brand)}$`, $options: "i" }
      });

      if (!brandDoc) {
        brandDoc = await Brand.create({ name: brand });
      }

      const existingModel = await Model.findOne({
        brandId: brandDoc._id,
        name: { $regex: `^${escapeRegex(name)}$`, $options: "i" }
      });

      if (existingModel) {
        skipped += 1;
        continue;
      }

      const model = await Model.create({
        name,
        brandId: brandDoc._id
      });

      createdModels.push(model);
    }

    res.json({
      message: "Upload processed",
      count: createdModels.length,
      skipped
    });

  } catch (err) {
    console.error("BULK IMPORT ERROR:", err);
    res.status(500).json({ error: err.message });
  }
});
/* ================= TECHNICIANS ================= */

app.post("/api/technicians", async (req, res) => {
  const tech = await Technician.create(req.body);
  res.json({ message: "Technician added", technician: tech });
});

app.get("/api/technicians", async (req, res) => {
  const techs = await Technician.find().sort({ createdAt: -1 });
  res.json(techs);
});

app.put("/api/technicians/:id", async (req, res) => {
  const tech = await Technician.findByIdAndUpdate(req.params.id, req.body, {
    new: true
  });
  res.json(tech);
});

app.post("/api/technicians/upload-photo", upload.single("image"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "Image file is required" });
    }

    const baseUrl = `${req.protocol}://${req.get("host")}`;
    res.json({
      message: "Image uploaded successfully",
      imageUrl: `${baseUrl}/uploads/${req.file.filename}`,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete("/api/technicians/:id", async (req, res) => {
  await Technician.findByIdAndDelete(req.params.id);
  res.json({ message: "Deleted" });
});

/* ================= BOOKINGS ================= */

app.post("/api/bookings", requireCustomerAuth, async (req, res) => {
  try {
    const requestCustomer = normalizeCustomerInput(req.body);
    const customerSession = req.customerSession;
    const customerMismatch =
      requestCustomer.email !== customerSession.email ||
      requestCustomer.phone !== customerSession.phone ||
      requestCustomer.name.toLowerCase() !== customerSession.name.toLowerCase();

    if (customerMismatch) {
      return res.status(401).json({
        error: "Customer verification failed. Please login again."
      });
    }

    const bookingPayload = {
      ...req.body,
      name: customerSession.name,
      phone: customerSession.phone,
      email: customerSession.email
    };

    const booking = await Booking.create(bookingPayload);

    // send response immediately
    res.json({
      trackingId: booking.trackingId,
      phone: booking.phone
    });

    // send email in background (important)
    if (booking.email) {
      sendBookingEmail(booking).catch(err =>
        console.log("Email error:", err)
      );
    }

  } catch (error) {
    console.error("Booking error:", error);
    res.status(500).json({ error: "Booking failed" });
  }
});

app.get("/api/bookings", async (req, res) => {
  const bookings = await Booking.find()
    .sort({ createdAt: -1 })
    .populate("technicianId");

  res.json(bookings);
});

app.get("/api/bookings/:id", async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) {
    return res.status(404).json({ error: "Booking not found" });
  }

  const booking = await Booking.findById(req.params.id);

  if (!booking) {
    return res.status(404).json({ message: "Booking not found" });
  }

  res.json(booking);
});

app.put("/api/bookings/:id", async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(404).json({ error: "Booking not found" });
    }

    const existingBooking = await Booking.findById(req.params.id);

    if (!existingBooking) {
      return res.status(404).json({ error: "Booking not found" });
    }

    const updatePayload = { ...req.body };
    delete updatePayload.visitOtpHash;
    delete updatePayload.visitOtpSalt;
    delete updatePayload.visitOtpExpiresAt;
    delete updatePayload.visitOtpVerifiedAt;

    if (updatePayload.technicianId === "") {
      updatePayload.technicianId = null;
    }

    if (updatePayload.technicianId) {
      const technician = await Technician.findById(updatePayload.technicianId);

      if (technician) {
        updatePayload.technician = technician.name || updatePayload.technician || "";
        updatePayload.technicianName = technician.name || updatePayload.technicianName || "";
        updatePayload.technicianPhone = technician.phone || updatePayload.technicianPhone || "";
        updatePayload.technicianEmployeeId =
          technician.employeeId || updatePayload.technicianEmployeeId || "";
        updatePayload.technicianPhoto = technician.photoUrl || updatePayload.technicianPhoto || "";
        updatePayload.technicianVerified = Boolean(
          technician.isVerified ?? updatePayload.technicianVerified ?? false
        );
      }
    }

    const booking = await Booking.findByIdAndUpdate(
      req.params.id,
      updatePayload,
      { new: true }
    );

    res.json(booking);

    const previousStatus = String(existingBooking.status || "").trim();
    const nextStatus = String(booking.status || "").trim();
    const statusChanged = previousStatus !== nextStatus;

    const previousTechnicianId = existingBooking.technicianId
      ? String(existingBooking.technicianId)
      : "";
    const nextTechnicianId = booking.technicianId ? String(booking.technicianId) : "";

    const previousTechnicianName = String(
      existingBooking.technicianName || existingBooking.technician || ""
    ).trim();
    const nextTechnicianName = String(
      booking.technicianName || booking.technician || ""
    ).trim();

    const technicianChanged =
      previousTechnicianId !== nextTechnicianId ||
      previousTechnicianName !== nextTechnicianName;

    if (technicianChanged && (nextTechnicianId || nextTechnicianName)) {
      const otpCode = generateOtpCode();
      const otpSalt = crypto.randomBytes(16).toString("hex");
      const otpHash = hashOtp(otpCode, otpSalt);
      const otpExpiresAt = new Date(Date.now() + VISIT_OTP_TTL_MS);

      Booking.findByIdAndUpdate(booking._id, {
        visitOtpHash: otpHash,
        visitOtpSalt: otpSalt,
        visitOtpExpiresAt: otpExpiresAt,
        visitOtpVerifiedAt: null
      }).catch((err) => console.log("Visit OTP save error:", err));

      if (nextTechnicianId) {
        Technician.findById(nextTechnicianId)
          .then((technician) => {
            if (!technician?.email) return null;
            return sendTechnicianVisitOtpEmail({
              technicianEmail: technician.email,
              technicianName: technician.name,
              booking,
              otpCode,
              expiresInMinutes: Math.ceil(VISIT_OTP_TTL_MS / 60000)
            });
          })
          .catch((err) => console.log("Visit OTP technician email error:", err));
      }
    }

    if (booking?.email) {

      let updateType = "Booking details updated by admin";

      if (technicianChanged && statusChanged) {
        updateType = nextTechnicianName
          ? `Technician assigned and status updated by admin: ${nextTechnicianName}`
          : "Technician assignment and status updated by admin";
      } else if (technicianChanged) {
        updateType = nextTechnicianName
          ? `Technician assigned by admin: ${nextTechnicianName}`
          : "Technician assignment updated by admin";
      } else if (statusChanged) {
        updateType = "Booking status updated by admin";
      }

      sendBookingUpdateEmail(booking, {
        updateType,
        previousStatus
      }).catch((err) => {
        console.log("Booking update email error:", err);
      });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put("/api/bookings/:id/status", async (req, res) => {
  try {
    const { status } = req.body || {};

    if (!status) {
      return res.status(400).json({ error: "Status is required" });
    }

    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(404).json({ error: "Booking not found" });
    }

    const existingBooking = await Booking.findById(req.params.id);

    if (!existingBooking) {
      return res.status(404).json({ error: "Booking not found" });
    }

    const booking = await Booking.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    );

    res.json(booking);

    if (booking?.email) {
      sendBookingUpdateEmail(booking, {
        updateType: "Booking status updated by admin",
        previousStatus: existingBooking.status || ""
      }).catch((err) => {
        console.log("Booking status email error:", err);
      });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete("/api/bookings/:id", async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) {
    return res.status(404).json({ error: "Booking not found" });
  }

  await Booking.findByIdAndDelete(req.params.id);
  res.json({ message: "Booking deleted" });
});

/* ================= VISIT OTP CHECK ================= */

app.post("/api/bookings/verify-visit-otp", async (req, res) => {
  try {
    const trackingIdRaw = String(req.body?.trackingId || "").trim();
    const phone = String(req.body?.phone || "").trim();
    const otpCode = String(req.body?.otp || "").trim().replace(/\D/g, "");

    if (!trackingIdRaw || !phone) {
      return res.status(400).json({ error: "Tracking ID and phone are required." });
    }

    if (!/^\d{6}$/.test(otpCode)) {
      return res.status(400).json({ error: "Enter a valid 6-digit OTP." });
    }

    const trackingId = trackingIdRaw.toUpperCase();
    const findQuery = { trackingId, phone };

    const booking = await Booking.findOne(findQuery).select(
      "+visitOtpHash +visitOtpSalt visitOtpExpiresAt visitOtpVerifiedAt technicianId technicianName technician"
    );

    if (!booking && mongoose.isValidObjectId(trackingIdRaw)) {
      const byId = await Booking.findOne({ _id: trackingIdRaw, phone }).select(
        "+visitOtpHash +visitOtpSalt visitOtpExpiresAt visitOtpVerifiedAt technicianId technicianName technician"
      );

      if (byId) {
        return verifyVisitOtpForBooking(byId, otpCode, res);
      }
    }

    if (!booking) {
      return res.status(404).json({ error: "Booking not found" });
    }

    return verifyVisitOtpForBooking(booking, otpCode, res);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

const verifyVisitOtpForBooking = async (booking, otpCode, res) => {
  const technicianAssigned = Boolean(booking?.technicianId || booking?.technicianName || booking?.technician);

  if (!technicianAssigned) {
    return res.status(400).json({ error: "Technician is not assigned yet." });
  }

  if (!booking?.visitOtpHash || !booking?.visitOtpSalt || !booking?.visitOtpExpiresAt) {
    return res.status(400).json({ error: "OTP is not generated yet. Please try again later." });
  }

  if (booking.visitOtpExpiresAt && Date.now() > new Date(booking.visitOtpExpiresAt).getTime()) {
    return res.status(400).json({ error: "OTP expired. Please request a new OTP from support/admin." });
  }

  const incomingHash = hashOtp(otpCode, booking.visitOtpSalt);

  if (!safeEqual(incomingHash, booking.visitOtpHash)) {
    return res.status(400).json({ error: "Invalid OTP. Please re-check and try again." });
  }

  if (!booking.visitOtpVerifiedAt) {
    await Booking.findByIdAndUpdate(booking._id, { visitOtpVerifiedAt: new Date() });
  }

  return res.json({ message: "OTP verified. Technician identity confirmed." });
};

/* ================= TRACK BOOKING ================= */

app.post("/api/bookings/track", async (req, res) => {
  try {
    const token = String(req.body?.token || "").trim();
    let trackingIdentity = null;

    if (token) {
      trackingIdentity = verifyTrackingToken(token);

      if (!trackingIdentity) {
        return res.status(400).json({
          error: "Tracking link expired or invalid."
        });
      }
    } else {
      const trackingId = String(req.body?.trackingId || "").trim().toUpperCase();
      const phone = String(req.body?.phone || "").trim();

      if (!trackingId || !phone) {
        return res.status(400).json({
          error: "Tracking ID and phone are required."
        });
      }

      trackingIdentity = { trackingId, phone };
    }

    const booking = await Booking.findOne({
      trackingId: trackingIdentity.trackingId,
      phone: trackingIdentity.phone
    });

    if (!booking) {
      return res.status(404).json({ error: "Booking not found" });
    }

    const response = booking.toObject();

    const needsTechnicianIdentity =
      Boolean(booking.technicianId) &&
      (
        !response.technicianName ||
        !response.technicianPhone ||
        !response.technicianEmployeeId ||
        !response.technicianPhoto ||
        typeof response.technicianVerified !== "boolean"
      );

    if (needsTechnicianIdentity) {
      const technician = await Technician.findById(booking.technicianId).select(
        "name phone employeeId photoUrl isVerified"
      );

      if (technician) {
        response.technicianName = response.technicianName || technician.name || "";
        response.technicianPhone = response.technicianPhone || technician.phone || "";
        response.technicianEmployeeId = response.technicianEmployeeId || technician.employeeId || "";
        response.technicianPhoto = response.technicianPhoto || technician.photoUrl || "";
        response.technicianVerified = typeof response.technicianVerified === "boolean"
          ? response.technicianVerified
          : Boolean(technician.isVerified);
      }
    }

    res.json(response);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/bookings/track-link", async (req, res) => {
  try {
    const token = String(req.query?.t || req.query?.token || "").trim();
    const trackingIdentity = verifyTrackingToken(token);

    if (!trackingIdentity) {
      return res.status(400).json({
        error: "Tracking link expired or invalid."
      });
    }

    const booking = await Booking.findOne({
      trackingId: trackingIdentity.trackingId,
      phone: trackingIdentity.phone
    });

    if (!booking) {
      return res.status(404).json({ error: "Booking not found" });
    }

    const response = booking.toObject();

    const needsTechnicianIdentity =
      Boolean(booking.technicianId) &&
      (
        !response.technicianName ||
        !response.technicianPhone ||
        !response.technicianEmployeeId ||
        !response.technicianPhoto ||
        typeof response.technicianVerified !== "boolean"
      );

    if (needsTechnicianIdentity) {
      const technician = await Technician.findById(booking.technicianId).select(
        "name phone employeeId photoUrl isVerified"
      );

      if (technician) {
        response.technicianName = response.technicianName || technician.name || "";
        response.technicianPhone = response.technicianPhone || technician.phone || "";
        response.technicianEmployeeId = response.technicianEmployeeId || technician.employeeId || "";
        response.technicianPhoto = response.technicianPhoto || technician.photoUrl || "";
        response.technicianVerified = typeof response.technicianVerified === "boolean"
          ? response.technicianVerified
          : Boolean(technician.isVerified);
      }
    }

    return res.json(response);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

/* ================= SERVICES ================= */

app.post("/api/services", upload.single("image"), async (req, res) => {
  try {
    const { name, subtitle } = req.body;

    const service = await Service.create({
      name,
      subtitle: subtitle || "",
      image: req.file ? `/uploads/${req.file.filename}` : ""
    });

    res.json(service);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/services", async (req, res) => {
  const services = await Service.find().sort({ createdAt: -1 });
  res.json(services);
});

app.put("/api/services/:id", upload.single("image"), async (req, res) => {
  const data = {};

  if (req.body.name) data.name = req.body.name;
  if (req.body.subtitle) data.subtitle = req.body.subtitle;

  if (req.file) {
    data.image = `/uploads/${req.file.filename}`;
  }

  const service = await Service.findByIdAndUpdate(
    req.params.id,
    data,
    { new: true }
  );

  res.json(service);
});

app.delete("/api/services/:id", async (req, res) => {
  try {
    const service = await Service.findById(req.params.id);

    if (service?.image) {
      const filePath = path.join(
        __dirname,
        "uploads",
        path.basename(service.image)
      );

      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
    }

    await Service.findByIdAndDelete(req.params.id);

    res.json({ message: "Service deleted" });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
