import User from "../model/userSchema.js";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";

// ✅ Generate Access Token
const generateAccessToken = (userId, role) => {
  return jwt.sign({ userId, role }, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "50d",
  });
};

// ✅ Set Access Token as Cookie
const setAccessTokenCookie = (res, accessToken) => {
  res.cookie("accessToken", accessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 15 * 60 * 1000,
  });
};

// ✅ Send OTP Email
const sendOTPEmail = async (email, otp) => {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  const mailOptions = {
    from: `"AeVIETNAM Auth" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: "Your OTP Code",
    text: `Your OTP is ${otp}. It will expire in 10 minutes.`,
  };

  await transporter.sendMail(mailOptions);
};

// ✅ Signup Controller
export const signup = async (req, res) => {
  const { email, password, name, role, graduationYear, phoneNumber, college } = req.body;

  try {
    if (!email || !password || !name || !role || !graduationYear || !phoneNumber || !college) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const userExists = await User.findOne({ email });
    if (userExists) return res.status(400).json({ message: "User already exists" });

    const user = await User.create({
      name,
      email,
      password,
      role,
      college,
      graduationYear,
      phoneNumber,
    });

    const accessToken = generateAccessToken(user._id, user.role);
    setAccessTokenCookie(res, accessToken);

    res.status(201).json({
      _id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
    });
  } catch (error) {
    console.error("❌ Signup error:", error);
    res.status(500).json({ message: error.message || "Signup failed" });
  }
};

// ✅ Login Controller
export const login = async (req, res) => {
  const { email, password } = req.body;
  try {
    if (!email || !password) {
      return res.status(400).json({ message: "Email and password required" });
    }

    const user = await User.findOne({ email });
    if (!user || !(await user.comparePassword(password))) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    const accessToken = generateAccessToken(user._id, user.role);
    setAccessTokenCookie(res, accessToken);

    res.json({
      _id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      token: accessToken,
    });
  } catch (error) {
    console.error("❌ Login error:", error);
    res.status(500).json({ message: error.message || "Login failed" });
  }
};

// ✅ Logout Controller
export const logout = async (req, res) => {
  try {
    res.clearCookie("accessToken");
    res.json({ message: "Logged out successfully" });
  } catch (error) {
    console.error("❌ Logout error:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

// ✅ Get Profile
export const getProfile = async (req, res) => {
  try {
    const fetchProfile = await User.findById(req.user._id);
    res.json(fetchProfile);
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

export const editProfile=async(req,res)=>{
    try {
        const { name, email, phoneNumber, college, graduationYear } = req.body;
        const user = await User.findById(req.user._id);
        if (!user) return res.status(404).json({ message: "User not found" });
        user.name = name;
        user.email = email;
        user.phoneNumber = phoneNumber;
        user.college = college;
        user.graduationYear = graduationYear;
        await user.save();
        res.json(user);
    } catch (error) {
        res.status(500).json({ message: "Server error", error: error.message });
    }
}

// ✅ Request OTP (Not Logged In)
export const requestPasswordReset = async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiry = Date.now() + 10 * 60 * 1000;
    user.resetOTP = otp;
    user.resetOTPExpiry = new Date(expiry);
    await user.save();

    await sendOTPEmail(user.email, otp);

    res.json({ message: "OTP sent to your email" });
  } catch (error) {
    console.error("❌ OTP error:", error);
    res.status(500).json({ message: "Failed to send OTP", error: error.message });
  }
};

// ✅ Reset Password
export const resetPassword = async (req, res) => {
  const { email, otp, newPassword } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    if (user.resetOTP !== otp || Date.now() > new Date(user.resetOTPExpiry)) {
      return res.status(400).json({ message: "Invalid or expired OTP" });
    }

    user.password = newPassword;
    user.resetOTP = null;
    user.resetOTPExpiry = null;
    await user.save();

    res.json({ message: "Password reset successfully" });
  } catch (error) {
    console.error("❌ Reset password error:", error);
    res.status(500).json({ message: "Failed to reset password", error: error.message });
  }
};

// ✅ Request OTP (Logged-In User)
export const requestPasswordResetForLoggedIn = async (req, res) => {
  const email = req.user.email;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiry = Date.now() + 10 * 60 * 1000;
    user.resetOTP = otp;
    user.resetOTPExpiry = new Date(expiry);
    await user.save();

    await sendOTPEmail(user.email, otp);

    res.json({ message: "OTP sent to your email" });
  } catch (error) {
    console.error("❌ Logged-in OTP error:", error);
    res.status(500).json({ message: "Failed to send OTP", error: error.message });
  }
};
