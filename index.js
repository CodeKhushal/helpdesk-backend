import express, { json } from "express";
import { connect, Schema, model } from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import { hash, compare } from "bcryptjs";
import pkg from "jsonwebtoken";
const { sign, verify } = pkg;

dotenv.config({});

const app = express();
const PORT = process.env.PORT || 5000;
app.use(cors());
app.use(json());

const whitelist = [
  "http://localhost:5173",
  "http://helpdesk-weanalyze.vercel.app",
];

const corsOptions = {
  origin: whitelist,
  credentials: true, // Required for cookies to be sent
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"], // Ensure headers are properly set
};
app.use(cors(corsOptions));

try {
  await connect(process.env.MONGO_URI);
  console.log("mongodb connected successfully");
} catch (error) {
  console.log(error);
}

const userSchema = new Schema({
  username: { type: String, unique: true, required: true },
  password: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
  },
  role: {
    type: String,
    enum: ["user", "opsteam", "techteam", "admin"],
    default: "user",
    required:true
  },
});

const User = model("User", userSchema);

const JWT_SECRET = process.env.SECRET_KEY;

// Signup
app.post("/api/auth/signup", async (req, res) => {
  const { username, password, email, role } = req.body;
  const hashedPassword = await hash(password, 10);
  try {
    const user = await User.create({
      username,
      password: hashedPassword,
      email,
      role,
    });
    res.status(201).json({ message: "User created", success: true, });
  } catch (err) {
    res.status(400).json({ error: "Username already exists" });
    console.error(err);
  }
});

// Login
app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const isMatch = await compare(password, user.password);
  if (!isMatch) return res.status(401).json({ error: "Invalid credentials" });

  const token = sign({ id: user._id, role: user.role }, JWT_SECRET, {
    expiresIn: "1d",
  });
  res.json({
    token,
    user: { username: user.username, email: user.email, role: user.role },
  });
});

// Auth middleware example (for protected routes)
function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });
  try {
    req.user = verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

app.listen(PORT, () => console.log(`Server listen at port ${PORT}`));
