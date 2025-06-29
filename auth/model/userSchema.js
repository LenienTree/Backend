import mongoose from "mongoose";
import validator from "validator";
import bcrypt from "bcrypt";

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, "Name is required"],
      trim: true,
    },

    email: {
      type: String,
      required: [true, "Email is required"],
      unique: true,
      lowercase: true,
      trim: true,
      validate(value) {
        if (!validator.isEmail(value)) {
          throw new Error("The value needs to be a valid email");
        }
      },
    },

    password: {
      type: String,
      required: [true, "Password is required"],
      minlength: [7, "Password must be at least 7 characters long"],
      trim: true,
    },

    role: {
      type: String,
      enum: ["user", "manager", "admin"],
      default: "user",
    },

    // For Refresh Token Storage (JWT)
    refreshToken: {
      type: String,
      default: null, // will be null until user logs in
    },

    // For password reset via OTP
    resetOTP: {
      type: String,
    },
    resetOTPExpiry: {
      type: Date,
    },

    // to track if OTP was verified
    isVerified: {
      type: Boolean,
      default: false,
    },

    // Managers can pitch events
    events: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Event",
      },
    ],
  },
  { timestamps: true }
);

// Pre-save: hash password if modified
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();

  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (err) {
    next(err);
  }
});

// Password comparison method
userSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model("User", userSchema);
export default User;
