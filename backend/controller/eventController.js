import mongoose from 'mongoose';
import { eventModel, bannerModel, registrationModel } from '../model/eventSchema.js';
import { uploadToS3, deleteFromS3, generateFileName } from '../utils/s3Config.js';

// Helper: Upload image and return URL
const handleImageUpload = async (file, oldUrl = null) => {
    try {
        if (oldUrl) await deleteFromS3(oldUrl);
        const fileName = generateFileName(file.originalname);
        return await uploadToS3(file, fileName);
    } catch (err) {
        console.error('[Image Upload Error]:', err.message, err.stack);
        throw new Error('Failed to upload image to S3.');
    }
};

// Create a new event
export const createEvent = async (req, res) => {
    try {
        const role = req.user.role;
        const userId = req.user.id;

        const {
            eventname, eventMode, paymentMode, singlePrice, description, eventDate,
            college, location, type, community, sponsors, website
        } = req.body;

        if (!eventname || !description || !eventDate || !location || !type || !community || !sponsors) {
            return res.status(400).json({ error: 'Required fields missing.' });
        }
        if (paymentMode === 'paid' && singlePrice <= 0) {
            return res.status(400).json({ error: 'Single price must be greater than 0 for paid events.' });
        }

        const eventData = {
            eventname, eventMode, paymentMode, singlePrice, description, eventDate,
            college, location, type, community, sponsors, website, role, userId
        };

        if (req.file) {
            eventData.eventimage = await handleImageUpload(req.file);
        } else {
            return res.status(400).json({ error: 'Event image is required.' });
        }

        const savedEvent = await new eventModel(eventData).save();
        res.status(201).json(savedEvent);

    } catch (error) {
        console.error('[Create Event Error]:', error.message, error.stack);
        res.status(500).json({ error: 'Failed to create event.', details: error.message });
    }
};

// Update event
export const updateEvent = async (req, res) => {
    try {
        const { id } = req.params;
        const existingEvent = await eventModel.findById(id);
        if (!existingEvent) return res.status(404).json({ error: 'Event not found.' });

        const updateData = { ...req.body };

        if (req.file) {
            updateData.eventimage = await handleImageUpload(req.file, existingEvent.eventimage);
        }

        const updatedEvent = await eventModel.findByIdAndUpdate(id, updateData, { new: true });
        res.json(updatedEvent);

    } catch (error) {
        console.error('[Update Event Error]:', error.message, error.stack);
        res.status(500).json({ error: 'Failed to update event.', details: error.message });
    }
};

// Delete event
export const deleteEvent = async (req, res) => {
    try {
        const { id } = req.params;
        const event = await eventModel.findById(id);
        if (!event) return res.status(404).json({ error: 'Event not found.' });

        if (event.eventimage) await deleteFromS3(event.eventimage);
        await eventModel.findByIdAndDelete(id);

        res.json({ message: 'Event deleted successfully.' });

    } catch (error) {
        console.error('[Delete Event Error]:', error.message, error.stack);
        res.status(500).json({ error: 'Failed to delete event.', details: error.message });
    }
};

// Get event highlights
export const getEventHighlights = async (_req, res) => {
    try {
        const events = await eventModel.find({}, 'eventname description eventimage type');
        res.json(events);
    } catch (error) {
        console.error('[Get Highlights Error]:', error.message, error.stack);
        res.status(500).json({ error: 'Failed to fetch event highlights.', details: error.message });
    }
};

// Get all approved events
export const getAllEvents = async (_req, res) => {
    try {
        const events = await eventModel.find({ status: 'approved' });
        res.json(events);
    } catch (error) {
        console.error('[Fetch All Events Error]:', error.message, error.stack);
        res.status(500).json({ error: 'Failed to fetch events.', details: error.message });
    }
};

// Get events by current user
export const getMyEvents = async (req, res) => {
    try {
        const userId = req.user._id;
        const events = await eventModel.find({ userId });
        res.json(events);
    } catch (error) {
        console.error('[Get My Events Error]:', error.message, error.stack);
        res.status(500).json({ error: 'Failed to fetch your events.', details: error.message });
    }
};

// Get single event
export const getEventById = async (req, res) => {
    try {
        const { id } = req.params;
        const event = await eventModel.findById(id);
        if (!event) return res.status(404).json({ error: 'Event not found.' });
        res.json(event);
    } catch (error) {
        console.error('[Fetch Single Event Error]:', error.message, error.stack);
        res.status(500).json({ error: 'Failed to fetch event.', details: error.message });
    }
};

// Upload/replace event image
export const uploadEventImage = async (req, res) => {
    try {
        const { id } = req.params;
        const event = await eventModel.findById(id);
        if (!event) return res.status(404).json({ error: 'Event not found.' });
        if (!req.file) return res.status(400).json({ error: 'No image file provided.' });

        const newImageUrl = await handleImageUpload(req.file, event.eventimage);
        const updatedEvent = await eventModel.findByIdAndUpdate(id, { eventimage: newImageUrl }, { new: true });

        res.json({ message: 'Image uploaded.', eventimage: newImageUrl, event: updatedEvent });
    } catch (error) {
        console.error('[Upload Event Image Error]:', error.message, error.stack);
        res.status(500).json({ error: 'Failed to upload image.', details: error.message });
    }
};

// Debugging version of check-in
export const checkInToEvent = async (req, res) => {
    console.log("=== [Check-in Handler] Start ===");
    const { eventId } = req.params;
    const userId = req.user?.id;

    console.log("Received eventId:", eventId);
    console.log("Extracted userId from JWT:", userId);

    if (!mongoose.Types.ObjectId.isValid(eventId)) {
        console.log("Invalid eventId:", eventId);
        return res.status(400).json({ error: 'Invalid event ID' });
    }

    if (!userId) {
        console.log("User ID not found in token");
        return res.status(401).json({ error: 'User not authenticated' });
    }

    try {
        const event = await eventModel.findById(eventId);
        console.log("Event fetched:", event ? "Found" : "Not Found");

        if (!event) return res.status(404).json({ error: 'Event not found' });

        let registration = await registrationModel.findOne({ eventId, userId });
        console.log("Registration fetched:", registration ? registration : "None");

        if (!registration) {
            console.log("No existing registration, creating new registration with checkedIn: true");
            registration = await registrationModel.create({
                eventId,
                userId,
                status: 'approved',
                checkedIn: true
            });

            console.log("Registration created successfully:", registration);
        } else if (!registration.checkedIn) {
            console.log("User registered but not checked in. Updating checkedIn to true.");
            registration.checkedIn = true;
            await registration.save();
        } else {
            console.log("User already checked in.");
        }

        return res.status(200).json({
            success: true,
            message: 'Checked in successfully',
            checkedIn: true
        });

    } catch (error) {
        console.error('[Check-In Error]:', error.message, error.stack);
        return res.status(500).json({
            success: false,
            error: 'Server error during check-in',
            details: error.message
        });
    }
};

// Banner Controller
export const BannerController = {
    createBanner: async (req, res) => {
        try {
            if (!req.file) {
                return res.status(400).json({ error: 'Banner image is required.' });
            }

            const imageUrl = await handleImageUpload(req.file);
            const newBanner = await new bannerModel({ image: imageUrl }).save();

            res.status(201).json(newBanner);
        } catch (error) {
            console.error('[Create Banner Error]:', error.message, error.stack);
            res.status(500).json({ error: 'Failed to create banner.', details: error.message });
        }
    },

    getAllBanners: async (_req, res) => {
        try {
            const banners = await bannerModel.find();
            res.json(banners);
        } catch (error) {
            console.error('[Get All Banners Error]:', error.message, error.stack);
            res.status(500).json({ error: 'Failed to fetch banners.', details: error.message });
        }
    },

    deleteBanner: async (req, res) => {
        try {
            const { id } = req.params;
            const banner = await bannerModel.findById(id);
            if (!banner) return res.status(404).json({ error: 'Banner not found.' });

            if (banner.image) await deleteFromS3(banner.image);
            await bannerModel.findByIdAndDelete(id);

            res.json({ message: 'Banner deleted successfully.' });

        } catch (error) {
            console.error('[Delete Banner Error]:', error.message, error.stack);
            res.status(500).json({ error: 'Failed to delete banner.', details: error.message });
        }
    }
};
