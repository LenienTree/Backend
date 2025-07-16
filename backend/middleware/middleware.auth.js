// middlewares/authMiddleware.js
import jwt from "jsonwebtoken";
import User from "../model/userSchema.js"; // adjust if you're using a different filename

// ✅ Middleware to verify access token
export const verifyAccessToken = async (req, res, next) => {
  try {
    const token = req.cookies.accessToken || req.headers.authorization?.split(" ")[1];

    if (!token) {
      return res
        .status(401)
        .json({ message: "Access denied. No token provided." });
    }

    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
     req.user = {
                id: decoded.userId, // Fix: use userId from token payload
                email: decoded.email, // keep if present in token
                role: decoded.role
            };
            next();

    const user = await User.findById(decoded.userId).select(
      "-password -refreshToken"
    );
    if (!user) {
      return res
        .status(401)
        .json({ message: "Invalid token. User not found." });
    }

    req.user = user; // attach user to request
    next();
  } catch (error) {
    console.error("Auth middleware error:", error.message);
    res.status(401).json({ message: "Unauthorized access" });
  }
};

// ✅ Role-based access control middleware
export const authorizeRoles = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res
        .status(403)
        .json({ message: "Forbidden: Insufficient privileges" });
    }
    next();
  };
};