import { registrationModel } from '../model/eventSchema.js';

/**
 * @desc Register the authenticated user for an event
 * @route POST /api/registrations/:eventId
 * @access Protected (JWT required)
 */
export const registerForEvent = async (req, res) => {
    try {
        const { eventId } = req.params;
        const userId = req.user.id; // ✅ from verified JWT middleware

        if (!eventId) return res.status(400).json({ error: 'Missing eventId' });

        // Check if already registered
        const existing = await registrationModel.findOne({ eventId, userId });
        if (existing) {
            return res.status(409).json({ error: 'Already registered for this event' });
        }

        const registration = await registrationModel.create({
            eventId,
            userId
        });

        res.status(201).json({
            message: 'Registration successful',
            registration
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Failed to register', details: error.message });
    }
};

/**
 * @desc Get all registrations (Admin)
 * @route GET /api/registrations
 * @access Admin only (optional: restrict in middleware)
 */
export const getAllRegistrations = async (_req, res) => {
    try {
        const registrations = await registrationModel.find().sort({ createdAt: -1 });
        res.json(registrations);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch registrations', details: error.message });
    }
};

/**
 * @desc Get registrations by event
 * @route GET /api/registrations/event/:eventId
 * @access Protected
 */
export const getRegistrationsByEvent = async (req, res) => {
    if (req.user.role !== 'admin' ) {
        return res.status(403).json({ error: 'Access denied' });
    }
    if (!req.params.eventId) {
        return res.status(400).json({ error: 'Missing eventId' });
    }   
    try {
        const { eventId } = req.params;
        const registrations = await registrationModel.find({ eventId });
        res.json(registrations);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch registrations', details: error.message });
    }
};

/**
 * @desc Get registrations by current user
 * @route GET /api/registrations/my
 * @access Protected
 */
export const getMyRegistrations = async (req, res) => {
    try {
        const userId = req.user.id;
        const registrations = await registrationModel.find({ userId });
        res.json(registrations);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch user registrations', details: error.message });
    }
};

/**
 * @desc Update registration status (e.g., approve/reject)
 * @route PUT /api/registrations/:id
 * @access Admin or Event Manager (optional: restrict in middleware)
 */
export const updateRegistrationStatus = async (req, res) => {
    try {
        const { id } = req.params;
        const { status } = req.body;

        if (!['pending', 'approved', 'rejected'].includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }

        const updated = await registrationModel.findByIdAndUpdate(
            id,
            { status },
            { new: true }
        );

        if (!updated) return res.status(404).json({ error: 'Registration not found' });

        res.json({ message: 'Status updated', registration: updated });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update registration', details: error.message });
    }
};

/**
 * @desc Delete a registration
 * @route DELETE /api/registrations/:id
 * @access Admin or Event Owner (optional: restrict in middleware)
 */
export const deleteRegistration = async (req, res) => {
    try {
        const { id } = req.params;
        const deleted = await registrationModel.findByIdAndDelete(id);

        if (!deleted) return res.status(404).json({ error: 'Registration not found' });

        res.json({ message: 'Registration deleted' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete registration', details: error.message });
    }
};
