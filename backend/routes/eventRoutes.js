// routes/eventRoutes.js
import express from "express";
import {
  createEvent,
  updateEvent,
  deleteEvent,
  getAllEvents,
  getEventById,
  uploadEventImage,
  BannerController
  
} from "../controller/eventController.js";

import {
  uploadSingleImage,
  handleUploadError,
  checkFileUpload
} from "../middleware/uploadMiddleware.js";

import { verifyAccessToken } from "../middleware/middleware.auth.js";


const router = express.Router();


// Create event (requires authentication)
router.post(
  "/create",
   verifyAccessToken,
  uploadSingleImage,
  handleUploadError,
  createEvent
);

// Update event by ID
router.put(
  "/update/:id",
  verifyAccessToken,
  uploadSingleImage,
  handleUploadError,
  updateEvent
);

// Upload/replace image for an existing event
router.post(
  "/upload-image/:id",
  verifyAccessToken,
  uploadSingleImage,
  handleUploadError,
  checkFileUpload,
  uploadEventImage
);

// Delete event by ID  (you might restrict to admins only)

router.delete(
  "/delete/:id",
  verifyAccessToken,
  deleteEvent
);



// Get all events (public read? → remove middleware if desired)
router.get("/getAll",  getAllEvents);

// Get event by ID (public read? → remove middleware if desired)
router.get("/get/:id", getEventById);

//Banner Routes
router.post("/banner/create", BannerController.createBanner);
router.get("/banner/getAll", BannerController.getAllBanners);
router.delete("/banner/delete/:id", BannerController.deleteBanner);

export default router;
