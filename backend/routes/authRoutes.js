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

router.post("/signup", signup);                         // Public
router.post("/login", login);                           // Public
router.post("/refresh", refreshToken);                  // Public
router.post("/logout", verifyAccessToken, logout);      // ✅ Secured

router.get("/profile", verifyAccessToken, getProfile);  // ✅ Secured

router.post("/request-password-reset", requestPasswordReset);                // Public
router.post("/request-password-reset-logged-in", verifyAccessToken, requestPasswordResetForLoggedIn); // ✅ Secured
router.post("/reset-password", resetPassword);     
export default router;