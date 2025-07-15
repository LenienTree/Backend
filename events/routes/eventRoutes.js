// routes/eventRoutes.js
import express from "express";
import {
  createEvent,
  updateEvent,
  deleteEvent,
  getAllEvents,
  getEventById,
  uploadEventImage
} from "../controllers/eventController.js";

import {
  uploadSingleImage,
  handleUploadError,
  checkFileUpload
} from "../middleware/uploadMiddleware.js";

import { verifyAuthToken } from "../middleware/authMiddleware.js";


const router = express.Router();


// Create event (requires authentication)
router.post(
  "/create",
   verifyAuthToken,
  uploadSingleImage,
  handleUploadError,
  createEvent
);

// Update event by ID
router.put(
  "/update/:id",
  verifyAuthToken,
  uploadSingleImage,
  handleUploadError,
  updateEvent
);

// Upload/replace image for an existing event
router.post(
  "/upload-image/:id",
  verifyAuthToken,
  uploadSingleImage,
  handleUploadError,
  checkFileUpload,
  uploadEventImage
);

// Delete event by ID  (you might restrict to admins only)

router.delete(
  "/delete/:id",
  verifyAuthToken,  
  deleteEvent
);



// Get all events (public read? → remove middleware if desired)
router.get("/getAll",  getAllEvents);

// Get event by ID (public read? → remove middleware if desired)
router.get("/get/:id", getEventById);

export default router;
