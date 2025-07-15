import express from 'express';
import {
    registerForEvent,
    getAllRegistrations,
    getRegistrationsByEvent,
    getMyRegistrations,
    updateRegistrationStatus,
    deleteRegistration
} from '../controllers/registrationController.js';

import { verifyAuthToken } from '../middleware/authMiddleware.js';

const router = express.Router();

router.post('/:eventId', verifyAuthToken, registerForEvent);
router.get('/', verifyAuthToken, getAllRegistrations);
router.get('/event/:eventId', verifyAuthToken, getRegistrationsByEvent);
router.get('/my', verifyAuthToken, getMyRegistrations);
router.put('/:id', verifyAuthToken, updateRegistrationStatus);
router.delete('/:id', verifyAuthToken, deleteRegistration);

export default router;
