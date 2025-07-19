import express from "express";
import {
  signup,
  login,
  logout,
  getProfile,
  editProfile,
  requestPasswordResetForLoggedIn,
  requestPasswordReset,
  resetPassword,
} from "../controller/userController.js";
import { verifyAccessToken } from "../middleware/middleware.auth.js";

const router = express.Router();

router.post("/signup", signup);                         // Public
router.post("/login", login);                           // Public
router.post("/logout", verifyAccessToken, logout);      // ✅ Secured

router.get("/profile", verifyAccessToken, getProfile);  // ✅ Secured
router.put("/profile",verifyAccessToken,editProfile)


router.post("/request-password-reset", requestPasswordReset); // Public
router.post("/request-password-reset-logged-in", verifyAccessToken, requestPasswordResetForLoggedIn); // ✅ Secured
router.post("/reset-password", resetPassword);          // Public

export default router;
