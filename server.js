require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

// 🔹 Enable CORS (Update to allow only your frontend URL in production)
app.use(cors({
    origin: "*",  // Change this to your frontend URL: "https://your-frontend.com"
    methods: "GET,POST,PUT,DELETE",
    allowedHeaders: "Content-Type,Authorization"
}));

// 🔹 Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log("✅ MongoDB Connected"))
.catch(err => console.error("❌ MongoDB Connection Error:", err));

// 🔹 User Schema & Model
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});
const User = mongoose.model("User", userSchema, "user_details");

// 🔹 Middleware: Verify JWT Token
const verifyToken = (req, res, next) => {
    const token = req.header("Authorization");
    if (!token) return res.status(401).json({ error: "Access Denied" });

    try {
        const verified = jwt.verify(token.replace("Bearer ", ""), process.env.JWT_SECRET);
        req.user = verified;
        next();
    } catch (error) {
        res.status(400).json({ error: "Invalid Token" });
    }
};

// 🔹 Register User API
app.post("/api/register", async (req, res) => {
    const { name, username, email, password, confirmPass } = req.body;

    if (!name || !username || !email || !password || !confirmPass) {
        return res.status(400).json({ error: "All fields are required" });
    }
    if (password !== confirmPass) {
        return res.status(400).json({ error: "Passwords do not match!" });
    }

    try {
        const existingUser = await User.findOne({ $or: [{ username }, { email }] });
        if (existingUser) {
            return res.status(400).json({ error: "Username or Email already exists!" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ name, username, email, password: hashedPassword });
        await newUser.save();

        res.json({ message: "✅ User registered successfully!" });
    } catch (error) {
        console.error("❌ Error registering user:", error);
        res.status(500).json({ error: "Server Error" });
    }
});

// 🔹 Login API (Returns JWT Token)
app.post("/api/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Email and Password are required!" });
    }

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ error: "User not found!" });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ error: "Invalid password!" });
        }

        // Generate JWT Token
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });

        res.json({ message: "✅ Login successful!", token, user: { id: user._id, name: user.name, email: user.email } });
    } catch (error) {
        console.error("❌ Error logging in:", error);
        res.status(500).json({ error: "Server Error" });
    }
});

// 🔹 Protected Route: Get All Users (Requires JWT)
app.get("/api/users", verifyToken, async (req, res) => {
    try {
        const users = await User.find({}, "-password"); // Exclude password
        res.json(users);
    } catch (error) {
        console.error("❌ Error fetching users:", error);
        res.status(500).json({ error: "Server Error" });
    }
});

// 🔹 Start Server
const PORT = process.env.PORT || 9000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
