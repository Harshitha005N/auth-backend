const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
app.use(express.json());

app.get("/", (req, res) => {
  res.send("API is working");
});

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected"));

const UserSchema = new mongoose.Schema({
  email: String,
  password: String
});

const User = mongoose.model("User", UserSchema);

/* REGISTER */
app.post("/api/auth/register", async (req, res) => {
  const { email, password } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = await User.create({ email, password: hashedPassword });

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);

  res.json({
    success: true,
    user_id: user._id,
    token
  });
});

/* LOGIN */
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.status(401).json({ success: false });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ success: false });

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);

  res.json({
    success: true,
    token,
    user: {
      id: user._id,
      email: user.email
    }
  });
});

app.listen(3001, () => {
  console.log("Server running on port 3001");
});
