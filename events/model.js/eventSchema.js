import mongoose from "mongoose";

/* ---------------- Event Schema ---------------- */
const eventSchema = new mongoose.Schema({
    eventname: {
        type: String,
        required: true,
        trim: true
    },
    eventimage: {
        type: String,
        required: true,
        trim: true
    },
    paymentMode: {
        type: String,
        enum: ["free", "paid"],
        default: "free",
        required: true
    },
    singlePrice: {
        type: Number,
        default: 0
    },
    eventMode: {
        type: String,
        enum: ["online", "offline"],
        default: "null",
        required: true,
        trim: true
    },
    description: {
        type: String,
        required: true,
        trim: true
    },
    eventDate: {
        type: Date,
        required: true
    },
    college: {
        type: String,
        trim: true
    },
    location: {
        type: String,
        required: true,
        trim: true
    },
    type: {
        type: String,
        required: true,
        default: "hackathon"
    },
    community: {
        type: String,
        trim: true
    },
    sponsors: {
        type: [String],
        default: []
    },
    status: {
        type: String,
        enum: ["pending", "approved", "rejected"],
        default: "pending"
    },
    response: {
        type: String,
        default: "You will receive the confirmation email shortly"
    },
    
    role: {
        type: String,
        trim: true
    },
    userId: {
        type: String,
        trim: true,
        required: true
    }
}, { timestamps: true });

/* ---------------- Registration Schema ---------------- */
const registrationSchema = new mongoose.Schema({
    eventId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'event',
        required: true
    },
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        required: true
    },
    registrationDate: {
        type: Date,
        default: Date.now
    },
    status: {
        type: String,
        enum: ["pending", "approved", "rejected"],
        default: "pending"
    }
}, { timestamps: true });

/* ---------------- Models ---------------- */
export const eventModel = mongoose.model('event', eventSchema);
export const registrationModel = mongoose.model('Registration', registrationSchema);
