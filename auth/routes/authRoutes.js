import express from "express";
import {
  signup,
  login,
  logout,
  refreshToken,
  getProfile,
  requestPasswordResetForLoggedIn,
  requestPasswordReset,
  resetPassword,
} from "../controller/userController.js";
import { verifyAccessToken } from "../middleware/middleware.auth.js";

const router = express.Router();

router.post("/signup", signup);
router.post("/login", login);
router.post("/logout", logout);
router.post("/refresh", refreshToken);
router.get("/profile", verifyAccessToken, getProfile);

// OTP routes
router.post("/request-password-reset", requestPasswordReset); // public
router.post(
  "/request-password-reset-logged-in",
  verifyAccessToken,
  requestPasswordResetForLoggedIn
); // protected
router.post("/reset-password", resetPassword); // OTP + email + new password

export default router;
