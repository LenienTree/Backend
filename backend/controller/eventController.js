import {eventModel,bannerModel} from '../model/eventSchema.js';
import { uploadToS3, deleteFromS3, generateFileName } from '../utils/s3Config.js';

// Helper: Upload image and return URL
const handleImageUpload = async (file, oldUrl = null) => {
    if (oldUrl) await deleteFromS3(oldUrl);
    const fileName = generateFileName(file.originalname);
    return await uploadToS3(file, fileName);
};

// Create a new event
export const createEvent = async (req, res) => {
    try {
        const role = req.user.role; // Get user role from JWT
        const userId = req.user.id; // Get user ID from JWT
        const {
            eventname, eventMode, paymentMode, singlePrice, description, eventDate,
            college, location, type, community, sponsors,website
        } = req.body;

        // Validate required fields
        if (!eventname || !description || !eventDate || !location || !type || !community || !sponsors) {
            return res.status(400).json({ error: 'Required fields missing.' });
        }
        if (paymentMode === 'paid' && singlePrice <= 0) {
            return res.status(400).json({ error: 'Single price must be greater than 0 for paid events.' });
        }
        const eventData = {
            eventname,
            eventMode,
            paymentMode,
            singlePrice,
            description,
            eventDate,
            college,
            location,
            type,
            community,
            sponsors,
            website,
            role,
            userId // Store the user ID who created the event
        };

        if (req.file) {
            eventData.eventimage = await handleImageUpload(req.file);
        } else {
            return res.status(400).json({ error: 'Event image is required.' });
        }

        const savedEvent = await new eventModel(eventData).save();
        res.status(201).json(savedEvent);
    } catch (error) {
        console.error('Create Error:', error);
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
        console.error('Update Error:', error);
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
        console.error('Delete Error:', error);
        res.status(500).json({ error: 'Failed to delete event.', details: error.message });
    }
};

// Get all events with limited fields
export const getEventHighlights = async (_req, res) => {
    try {
        const events = await eventModel.find({}, 'eventname description eventimage type');
        console.log(events);
        res.json(events);
    } catch (error) {
        console.error('Get Highlights Error:', error);
        res.status(500).json({ error: 'Failed to fetch event highlights', details: error.message });
    }
};

// Get all approved events
export const getAllEvents = async (_req, res) => {
    try {
        const events = await eventModel.find({ status: 'approved' });
        console.log(events);
        res.json(events);
    } catch (error) {
        console.error('Fetch All Error:', error);
        res.status(500).json({ error: 'Failed to fetch events.', details: error.message });
    }
};

// Get events created by the current user
export const getMyEvents = async (req, res) => {
    try {
        console.log('User object from request:', req.user);
        const userId = req.user._id; // Use _id from the user object
        console.log('Looking for events with userId:', userId);
        const events = await eventModel.find({ userId });
        console.log('Found events:', events);
        res.json(events);
    } catch (error) {
        console.error('Get My Events Error:', error);
        res.status(500).json({ error: 'Failed to fetch your events', details: error.message });
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
        console.error('Fetch One Error:', error);
        res.status(500).json({ error: 'Failed to fetch event.', details: error.message });
    }
};

// Separate endpoint: Upload/replace event image
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
        console.error('Upload Image Error:', error);
        res.status(500).json({ error: 'Failed to upload image.', details: error.message });
    }
};

export const BannerController = {
    // Create a new banner
    createBanner: async (req, res) => {
        try {
            if (!req.file) {
                return res.status(400).json({ error: 'Banner image is required.' });
            }
            const imageUrl = await handleImageUpload(req.file);
            const bannerData = { image: imageUrl };
            const newBanner = await new bannerModel(bannerData).save();
            res.status(201).json(newBanner);
        }
        catch (error) {
            console.error('Create Banner Error:', error);
            res.status(500).json({ error: 'Failed to create banner.', details: error.message });
        }
    },
    // Get all banners
    getAllBanners: async (_req, res) => {
        try {
            const banners = await bannerModel.find();
            res.json(banners);
        } catch (error) {
            console.error('Fetch Banners Error:', error);
            res.status(500).json({ error: 'Failed to fetch banners.', details: error.message });
        }
    },
    //delete a banner
    deleteBanner: async (req, res) => {
        try {
            const { id } = req.params;
            const banner = await bannerModel.findById(id);
            if (!banner) return res.status(404).json({ error: 'Banner not found.' });
            if (banner.image) await deleteFromS3(banner.image);
            await bannerModel.findByIdAndDelete(id);
            res.json({ message: 'Banner deleted successfully.' });
        } catch (error) {
            console.error('Delete Banner Error:', error);
            res.status(500).json({ error: 'Failed to delete banner.', details: error.message });
        }
    }
};


