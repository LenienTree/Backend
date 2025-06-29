import express from "express";
import morgan from "morgan";
import cors from "cors";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import authRoutes from "./routes/authRoutes.js"; // adjust path if needed
import connectDb from "./db/db.js";

dotenv.config();

const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(morgan("dev"));
app.use(
  cors({
    origin: "http://localhost:3000", // frontend URL
    credentials: true,
  })
);

// Database Connection
connectDb();

// Routes
app.use("/", authRoutes); // handles /signup, /login, etc.

app.get("/", (req, res) => {
  res.status(200).send("Hello from the AUTH microservice.");
});

// Start Server
const PORT = process.env.PORT || 5001;
app.listen(PORT, () => {
  console.log(`🚀 AUTH service running at http://localhost:${PORT}`);
});
