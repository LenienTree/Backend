import { DataTypes } from "sequelize";
import { sequelize } from "../db/db.js";
import User from "./userSchema.js";

/* ---------------- Event Model ---------------- */
export const eventModel = sequelize.define("Event", {
    id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
    },
    eventname: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    eventimage: {
        type: DataTypes.TEXT,
        allowNull: false,
    },
    paymentMode: {
        type: DataTypes.ENUM("free", "paid"),
        defaultValue: "free",
        allowNull: false,
    },
    singlePrice: {
        type: DataTypes.DECIMAL(10, 2),
        defaultValue: 0,
    },
    eventMode: {
        type: DataTypes.ENUM("online", "offline"),
        defaultValue: "online",
        allowNull: false,
    },
    description: {
        type: DataTypes.TEXT,
        allowNull: false,
    },
    eventDate: {
        type: DataTypes.DATE,
        allowNull: false,
    },
    college: {
        type: DataTypes.STRING,
        allowNull: true,
    },
    location: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    type: {
        type: DataTypes.ENUM("hackathon", "workshop", "competition", "other", "techfest", "ideathon", "webinar", "others"),
        defaultValue: "hackathon",
        allowNull: false,
    },
    community: {
        type: DataTypes.STRING,
        allowNull: true,
    },
    sponsors: {
        type: DataTypes.ARRAY(DataTypes.STRING),
        defaultValue: [],
    },
    website: {
        type: DataTypes.STRING,
        allowNull: true,
    },
    status: {
        type: DataTypes.ENUM("pending", "approved", "rejected"),
        defaultValue: "pending",
    },
    response: {
        type: DataTypes.TEXT,
        defaultValue: "You will receive the confirmation email shortly",
    },
    role: {
        type: DataTypes.STRING,
        allowNull: true,
    },
    userId: {
        type: DataTypes.UUID,
        allowNull: false,
        references: {
            model: User,
            key: 'id'
        }
    }
}, {
    timestamps: true,
    tableName: 'Events'
});

/* ---------------- Registration Model ---------------- */
export const registrationModel = sequelize.define("Registration", {
    id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
    },
    eventId: {
        type: DataTypes.UUID,
        allowNull: false,
        references: {
            model: eventModel,
            key: 'id'
        }
    },
    userId: {
        type: DataTypes.UUID,
        allowNull: false,
        references: {
            model: User,
            key: 'id'
        }
    },
    registrationDate: {
        type: DataTypes.DATE,
        defaultValue: DataTypes.NOW,
    },
    status: {
        type: DataTypes.ENUM("pending", "approved", "rejected"),
        defaultValue: "pending",
    },
    checkedIn: {
        type: DataTypes.BOOLEAN,
        defaultValue: false,
    }
}, {
    timestamps: true,
    tableName: 'Registrations'
});

/* ---------------- Banner Model ---------------- */
export const bannerModel = sequelize.define("Banner", {
    id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
    },
    image: {
        type: DataTypes.TEXT,
        allowNull: false,
    }
}, {
    timestamps: true,
    tableName: 'Banners'
});

// Define associations
User.hasMany(eventModel, { foreignKey: 'userId', as: 'events' });
eventModel.belongsTo(User, { foreignKey: 'userId', as: 'user' });

User.hasMany(registrationModel, { foreignKey: 'userId', as: 'registrations' });
registrationModel.belongsTo(User, { foreignKey: 'userId', as: 'user' });

eventModel.hasMany(registrationModel, { foreignKey: 'eventId', as: 'registrations' });
registrationModel.belongsTo(eventModel, { foreignKey: 'eventId', as: 'event' });
