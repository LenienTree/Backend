import express from "express";
import { getallUsers ,getAllevents,deleteUser,editUserbyId,EditeventById,deleteEvent} from "../controller/userController.js";  
import { verifyAccessToken } from "../middleware/middleware.auth.js";
const router = express.Router();


router.get("/users", verifyAccessToken, getallUsers);
router.get("/events", verifyAccessToken, getAllevents);
router.delete("/users/:id", verifyAccessToken, deleteUser);
router.put("/users/:id", verifyAccessToken, editUserbyId);
router.put("/events/:id", verifyAccessToken, EditeventById);
router.delete("/events/:id", verifyAccessToken, deleteEvent);
export default router;
    