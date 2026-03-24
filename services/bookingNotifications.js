const nodemailer = require("nodemailer");

// 🔥 Create transporter
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS,
  },
});

// 🔍 Check SMTP
transporter.verify((error) => {
  if (error) console.log("❌ SMTP ERROR:", error);
  else console.log("✅ SMTP READY");
});

// 🎨 EMAIL WRAPPER (GMAIL SAFE)
const emailWrapper = (content) => `
<!DOCTYPE html>
<html>
<body style="margin:0;background:#f4f6f8;font-family:Arial,sans-serif;">

<table width="100%" cellpadding="0" cellspacing="0">
<tr>
<td align="center">

<table width="600" cellpadding="0" cellspacing="0" 
       style="background:#ffffff;border-radius:12px;overflow:hidden;">
  
  ${content}

  <tr>
    <td style="background:#f4f4f4;padding:15px;text-align:center;font-size:12px;color:#888;">
      Thank you for choosing <b>Servizy</b> ❤️<br/>
      Need help? Contact support anytime.
    </td>
  </tr>

</table>

</td>
</tr>
</table>

</body>
</html>
`;


// 📩 BOOKING EMAIL
const sendBookingEmail = async (booking) => {
  try {
    const html = emailWrapper(`
      <tr>
        <td style="background:#3b82f6;color:white;padding:20px;text-align:center;">
          <h2 style="margin:0;">✅ Booking Confirmed</h2>
          <p style="margin:5px 0;">Tracking ID: <b>${booking.trackingId}</b></p>
        </td>
      </tr>

      <tr>
        <td style="padding:20px;">
          <p>Hello <b>${booking.name || "Customer"}</b>,</p>
          <p>Your booking has been confirmed.</p>

          <table width="100%" cellpadding="5" cellspacing="0" style="font-size:14px;">
            <tr><td><b>Brand:</b></td><td>${booking.brand}</td></tr>
            <tr><td><b>Model:</b></td><td>${booking.model}</td></tr>
            <tr><td><b>Service:</b></td><td>${booking.service}</td></tr>
            <tr><td><b>Pickup:</b></td><td>${booking.pickupOption}</td></tr>
            <tr><td><b>Address:</b></td><td>${booking.address}</td></tr>
          </table>

          <div style="text-align:center;margin:25px;">
            <a href="https://servizy.netlify.app/track/${booking.trackingId}/${booking.phone}" 
               style="background:#4CAF50;color:white;padding:12px 25px;text-decoration:none;border-radius:6px;font-weight:bold;">
               🔍 Track Booking
            </a>
          </div>
        </td>
      </tr>
    `);

    await transporter.sendMail({
      from: `"Servizy" <${process.env.GMAIL_USER}>`,
      to: booking.email,
      subject: `Booking Confirmed - ${booking.trackingId}`,
      html,
    });

    console.log("📩 Booking email sent");
  } catch (err) {
    console.log("❌ Booking Email Error:", err);
  }
};


// 🔄 UPDATE EMAIL
const sendBookingUpdateEmail = async (booking, options = {}) => {
  try {
    const html = emailWrapper(`
      <tr>
        <td style="background:#3b82f6;color:white;padding:20px;text-align:center;">
          <h2 style="margin:0;">🔄 Booking Update</h2>
        </td>
      </tr>

      <tr>
        <td style="padding:20px;">
          <p>Hello <b>${booking.name}</b>,</p>
          <p>${options.updateType || "Your booking has been updated."}</p>

          <p><b>Status:</b> ${booking.status}</p>

          <div style="text-align:center;margin:25px;">
            <a href="https://servizy.netlify.app/track/${booking.trackingId}/${booking.phone}" 
               style="background:#4CAF50;color:white;padding:12px 25px;text-decoration:none;border-radius:6px;font-weight:bold;">
               🔍 Track Booking
            </a>
          </div>
        </td>
      </tr>
    `);

    await transporter.sendMail({
      from: `"Servizy" <${process.env.GMAIL_USER}>`,
      to: booking.email,
      subject: `Booking Update - ${booking.trackingId}`,
      html,
    });

    console.log("📩 Update email sent");
  } catch (err) {
    console.log("❌ Update Email Error:", err);
  }
};


// 🔐 OTP EMAIL (FIXED DESIGN)
const sendCustomerOtpEmail = async ({ email, otpCode, name }) => {
  try {
    const html = emailWrapper(`
      <tr>
        <td style="background:#3b82f6;color:white;padding:20px;text-align:center;">
          <h2 style="margin:0;">🔐 OTP Verification</h2>
        </td>
      </tr>

      <tr>
        <td style="padding:30px;text-align:center;">
          <p>Hello <b>${name || "User"}</b>,</p>
          <p>Your OTP code is:</p>

          <div style="
            display:inline-block;
            background:#f3f4f6;
            padding:15px 30px;
            font-size:28px;
            letter-spacing:6px;
            font-weight:bold;
            color:#111;
            border-radius:8px;
            margin:15px 0;
          ">
            ${otpCode}
          </div>

          <p style="font-size:13px;color:#666;">
            This OTP is valid for a few minutes.
          </p>

          <p style="font-size:12px;color:#999;">
            If you didn’t request this, ignore this email.
          </p>
        </td>
      </tr>
    `);

    await transporter.sendMail({
      from: `"Servizy" <${process.env.GMAIL_USER}>`,
      to: email,
      subject: "Your OTP Code",
      html,
    });

    console.log("📩 OTP email sent");
  } catch (err) {
    console.log("❌ OTP Email Error:", err);
  }
};


// 🔐 TECHNICIAN VISIT OTP EMAIL
const sendTechnicianVisitOtpEmail = async ({
  technicianEmail,
  technicianName,
  booking,
  otpCode,
  expiresInMinutes,
}) => {
  try {
    const html = emailWrapper(`
      <tr>
        <td style="background:#0f766e;color:white;padding:20px;text-align:center;">
          <h2 style="margin:0;">Technician Visit OTP</h2>
        </td>
      </tr>

      <tr>
        <td style="padding:30px;text-align:center;">
          <p>Hello <b>${technicianName || "Technician"}</b>,</p>
          <p>Your visit OTP for this booking is:</p>

          <div style="
            display:inline-block;
            background:#f3f4f6;
            padding:15px 30px;
            font-size:28px;
            letter-spacing:6px;
            font-weight:bold;
            color:#111;
            border-radius:8px;
            margin:15px 0;
          ">
            ${otpCode}
          </div>

          <table width="100%" cellpadding="5" cellspacing="0" style="font-size:14px;text-align:left;">
            <tr><td><b>Booking ID:</b></td><td>${booking?.trackingId || "-"}</td></tr>
            <tr><td><b>Customer:</b></td><td>${booking?.name || "-"}</td></tr>
            <tr><td><b>Phone:</b></td><td>${booking?.phone || "-"}</td></tr>
            <tr><td><b>Service:</b></td><td>${booking?.service || "-"}</td></tr>
          </table>

          <p style="font-size:13px;color:#666;margin-top:18px;">
            This OTP expires in ${expiresInMinutes || 0} minutes.
          </p>

          <p style="font-size:12px;color:#999;">
            Share this OTP with the customer for visit verification.
          </p>
        </td>
      </tr>
    `);

    await transporter.sendMail({
      from: `"Servizy" <${process.env.GMAIL_USER}>`,
      to: technicianEmail,
      subject: `Technician Visit OTP - ${booking?.trackingId || "Booking"}`,
      html,
    });

    console.log("📩 Technician visit OTP email sent");
  } catch (err) {
    console.log("❌ Technician Visit OTP Email Error:", err);
  }
};


// ✅ EXPORT
module.exports = {
  sendBookingEmail,
  sendBookingUpdateEmail,
  sendCustomerOtpEmail,
  sendTechnicianVisitOtpEmail,
};
