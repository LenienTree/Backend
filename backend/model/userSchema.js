import { DataTypes } from "sequelize";
import { sequelize } from "../db/db.js";
import validator from "validator";
import bcrypt from "bcrypt";

const User = sequelize.define("User", {
    id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
    },
    name: {
        type: DataTypes.STRING,
        allowNull: false,
        validate: {
            notEmpty: {
                msg: "Name is required"
            }
        }
    },
    email: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
        validate: {
            isEmail: {
                msg: "The value needs to be a valid email"
            }
        },
        set(value) {
            this.setDataValue('email', value.toLowerCase().trim());
        }
    },
    phoneNumber: {
        type: DataTypes.STRING,
        allowNull: false,
        validate: {
            isValidPhone(value) {
                if (!validator.isMobilePhone(value, "any", { strictMode: false })) {
                    throw new Error("The value needs to be a valid phone number");
                }
            }
        }
    },
    college: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    graduationYear: {
        type: DataTypes.INTEGER,
        allowNull: false,
        validate: {
            min: {
                args: [1900],
                msg: "Graduation year must be at least 1900"
            },
            max: {
                args: [2100],
                msg: "Graduation year must be at most 2100"
            }
        }
    },
    password: {
        type: DataTypes.STRING,
        allowNull: false,
        validate: {
            len: {
                args: [7, 255],
                msg: "Password must be at least 7 characters long"
            }
        }
    },
    role: {
        type: DataTypes.ENUM("user", "admin"),
        defaultValue: "user",
    },
    refreshToken: {
        type: DataTypes.TEXT,
        defaultValue: null,
    },
    resetOTP: {
        type: DataTypes.STRING,
        allowNull: true,
    },
    resetOTPExpiry: {
        type: DataTypes.DATE,
        allowNull: true,
    },
    isVerified: {
        type: DataTypes.BOOLEAN,
        defaultValue: false,
    }
}, {
    timestamps: true,
    hooks: {
        beforeCreate: async (user) => {
            if (user.password) {
                const salt = await bcrypt.genSalt(10);
                user.password = await bcrypt.hash(user.password, salt);
            }
        },
        beforeUpdate: async (user) => {
            if (user.changed('password')) {
                const salt = await bcrypt.genSalt(10);
                user.password = await bcrypt.hash(user.password, salt);
            }
        }
    }
});

// Instance method for password comparison
User.prototype.comparePassword = async function (candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

export default User;