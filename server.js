/**
 * ============================================================
 *  SECURE REAL-TIME CHAT APPLICATION — COMPLETE SERVER
 *  Student  : Samaila Bello | U22/CPS/1067
 *  Supervisor: Mr Abdullahi Musa Bello
 * ============================================================
 *  Features:
 *    1. Real-time messaging (Socket.io)
 *    2. End-to-End Encryption (AES-256 + RSA-2048)
 *    3. Blockchain-based message verification (SHA-256)
 *    4. Screenshot detection & alerting
 *    5. Hidden identity / anonymous communication
 *    6. JWT Authentication
 *    7. MongoDB persistence
 * ============================================================
 */

"use strict";

// ─────────────────────────────────────────────────────────────
// 1. IMPORTS
// ─────────────────────────────────────────────────────────────
const express    = require("express");
const http       = require("http");
const socketio   = require("socket.io");
const mongoose   = require("mongoose");
const cors       = require("cors");
const dotenv     = require("dotenv");
const bcrypt     = require("bcryptjs");
const jwt        = require("jsonwebtoken");
const crypto     = require("crypto");
const forge      = require("node-forge");
const nodemailer = require("nodemailer");

dotenv.config();

// ─────────────────────────────────────────────────────────────
// 2. APP & SERVER SETUP
// ─────────────────────────────────────────────────────────────
const app    = express();
const server = http.createServer(app);
const io     = socketio(server, {
  cors: {
    origin: process.env.CLIENT_URL || "http://localhost:3000",
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
  },
});

app.use(cors({
  origin: process.env.CLIENT_URL || "http://localhost:3000",
  credentials: true,
}));
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ limit: "10mb", extended: true }));

const PORT      = process.env.PORT      || 5000;
const MONGO_URI = process.env.MONGO_URI || "mongodb://localhost:27017/securechat";
const JWT_SECRET = process.env.JWT_SECRET || "samaila_securechat_secret_2025";
const JWT_EXPIRES = process.env.JWT_EXPIRES_IN || "7d";

// ─────────────────────────────────────────────────────────────
// EMAIL TRANSPORTER (Gmail)
// ─────────────────────────────────────────────────────────────
const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true, // SSL
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS, // 16-char Gmail App Password (no spaces)
  },
  tls: {
    rejectUnauthorized: false,
  },
});

// Verify email connection on startup
transporter.verify((error) => {
  if (error) {
    console.error("❌ Email config error:", error.message);
    console.error("   Check EMAIL_USER and EMAIL_PASS in your .env file");
  } else {
    console.log("✅ Email server ready");
  }
});

// In-memory OTP store: { email: { otp, expires } }
const otpStore = new Map();

const sendOTPEmail = async (email, otp) => {
  const info = await transporter.sendMail({
    from: `"SecureChat 🔐" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: "SecureChat — Your Password Reset Code",
    html: `
      <div style="font-family:monospace;background:#0a0a0f;color:#e8e8f0;padding:32px;max-width:480px;margin:auto;border:1px solid #2a2a3a">
        <h2 style="color:#00ff9d;letter-spacing:2px;margin-top:0">🔐 SecureChat</h2>
        <p style="color:#aaa">You requested a password reset. Use the code below:</p>
        <div style="background:#1a1a24;border:1px solid #2a2a3a;padding:28px;text-align:center;margin:24px 0">
          <p style="color:#7070a0;font-size:12px;letter-spacing:3px;text-transform:uppercase;margin-bottom:12px">Your Reset Code</p>
          <h1 style="color:#00ff9d;font-size:48px;letter-spacing:14px;margin:0;font-weight:900">${otp}</h1>
        </div>
        <p style="color:#7070a0;font-size:12px">⏱ Expires in <strong style="color:#fff">10 minutes</strong>.</p>
        <p style="color:#7070a0;font-size:12px">If you did not request this, ignore this email.</p>
        <hr style="border-color:#2a2a3a;margin-top:24px"/>
        <p style="color:#555;font-size:11px">SecureChat — U22/CPS/1067</p>
      </div>
    `,
  });
  console.log(`📧 OTP sent to ${email} — Message ID: ${info.messageId}`);
};

// ─────────────────────────────────────────────────────────────
// 3. MONGOOSE MODELS
// ─────────────────────────────────────────────────────────────

// ── 3a. USER MODEL ──────────────────────────────────────────
const userSchema = new mongoose.Schema(
  {
    username: {
      type: String, required: true, unique: true,
      trim: true, minlength: 3, maxlength: 30,
    },
    email: {
      type: String, required: true, unique: true,
      lowercase: true, trim: true,
    },
    password:  { type: String, required: true, minlength: 6 },

    // RSA public key — stored so peers can encrypt TO this user
    publicKey: { type: String, default: null },

    // Hidden identity
    isAnonymous:    { type: Boolean, default: false },
    anonymousAlias: { type: String,  default: null },   // e.g. "Ghost_4821"

    // Presence
    isOnline: { type: Boolean, default: false },
    lastSeen:  { type: Date,    default: Date.now },

    // Security audit
    screenshotAttempts: { type: Number, default: 0 },

    // Profile
    avatar: { type: String, default: null }, // base64 image string
    bio:    { type: String, default: "", maxlength: 120 },

    // Password reset OTP
    resetOTP:        { type: String, default: null },
    resetOTPExpires: { type: Date,   default: null },
  },
  { timestamps: true }
);

// Hash password before save
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  const salt = await bcrypt.genSalt(12);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

userSchema.methods.matchPassword = async function (entered) {
  return bcrypt.compare(entered, this.password);
};

userSchema.methods.toSafeObject = function () {
  return {
    id:           this._id,
    username:     this.isAnonymous ? this.anonymousAlias : this.username,
    realUsername: this.username,
    email:        this.email,
    publicKey:    this.publicKey,
    isAnonymous:  this.isAnonymous,
    isOnline:     this.isOnline,
    lastSeen:     this.lastSeen,
    avatar:       this.avatar,
    bio:          this.bio,
  };
};

const User = mongoose.model("User", userSchema);

// ── 3b. MESSAGE MODEL ───────────────────────────────────────
const messageSchema = new mongoose.Schema(
  {
    sender:   { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    receiver: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },

    // AES-256-CBC encrypted payload
    encryptedContent: { type: String, required: true },
    // RSA-encrypted AES key (encrypted with receiver's public key)
    encryptedAESKey:  { type: String, required: true },
    // Initialisation vector for AES
    iv:               { type: String, required: true },
    // Plaintext stored for display (in real E2E this would be omitted)
    plaintext:        { type: String, default: null },

    // ── Blockchain fields ────────────────────────────────
    messageHash:    { type: String, required: true },
    previousHash:   { type: String, default: "0000000000000000" },
    blockIndex:     { type: Number, default: 0 },
    blockTimestamp: { type: String, required: true },
    isVerified:     { type: Boolean, default: false },

    // ── Privacy & security flags ─────────────────────────
    sentAnonymously:    { type: Boolean, default: false },
    screenshotDetected: { type: Boolean, default: false },
    isRead:             { type: Boolean, default: false },
    isEdited:           { type: Boolean, default: false },
    plaintext:          { type: String,  default: null },
  },
  { timestamps: true }
);

const Message = mongoose.model("Message", messageSchema);

// ── 3c. BLOCKCHAIN BLOCK MODEL ──────────────────────────────
const blockSchema = new mongoose.Schema({
  blockIndex:     { type: Number,   required: true, unique: true },
  messageId:      { type: mongoose.Schema.Types.ObjectId, ref: "Message" },
  messageHash:    { type: String,   required: true },
  previousHash:   { type: String,   required: true },
  blockTimestamp: { type: String,   required: true },
  sender:         { type: String },
  receiver:       { type: String },
});

const Block = mongoose.model("Block", blockSchema);

// ─────────────────────────────────────────────────────────────
// 4. ENCRYPTION UTILITIES  (AES-256 + RSA-2048)
// ─────────────────────────────────────────────────────────────

/**
 * Generate a 2048-bit RSA key pair for a new user.
 * Public key  → stored in DB (shared openly).
 * Private key → returned ONCE to user; never stored on server.
 */
const generateRSAKeyPair = () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { publicKey, privateKey };
};

/**
 * Encrypt plaintext with AES-256-CBC.
 * Returns { encryptedContent, iv, aesKey } — all hex strings.
 */
const encryptAES = (plaintext) => {
  const aesKey = crypto.randomBytes(32); // 256-bit
  const iv     = crypto.randomBytes(16); // 128-bit
  const cipher = crypto.createCipheriv("aes-256-cbc", aesKey, iv);
  let enc = cipher.update(plaintext, "utf8", "hex");
  enc    += cipher.final("hex");
  return {
    encryptedContent: enc,
    iv:               iv.toString("hex"),
    aesKey:           aesKey.toString("hex"),
  };
};

/**
 * Decrypt AES-256-CBC ciphertext.
 */
const decryptAES = (encryptedContent, aesKeyHex, ivHex) => {
  const key     = Buffer.from(aesKeyHex, "hex");
  const iv      = Buffer.from(ivHex,     "hex");
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  let dec = decipher.update(encryptedContent, "hex", "utf8");
  dec    += decipher.final("utf8");
  return dec;
};

/**
 * Encrypt the AES key with receiver's RSA public key (RSA-OAEP / SHA-256).
 * Result is Base64.
 */
const encryptAESKeyRSA = (aesKeyHex, receiverPublicKeyPEM) => {
  const pubKey    = forge.pki.publicKeyFromPem(receiverPublicKeyPEM);
  const encrypted = pubKey.encrypt(aesKeyHex, "RSA-OAEP", {
    md: forge.md.sha256.create(),
  });
  return forge.util.encode64(encrypted);
};

/**
 * Decrypt the AES key with the receiver's RSA private key.
 */
const decryptAESKeyRSA = (encryptedAESKeyB64, privateKeyPEM) => {
  const privKey   = forge.pki.privateKeyFromPem(privateKeyPEM);
  const encrypted = forge.util.decode64(encryptedAESKeyB64);
  return privKey.decrypt(encrypted, "RSA-OAEP", {
    md: forge.md.sha256.create(),
  });
};

// ─────────────────────────────────────────────────────────────
// 5. BLOCKCHAIN UTILITIES  (SHA-256 hash chain)
// ─────────────────────────────────────────────────────────────

/**
 * Compute SHA-256 hash for a block.
 */
const computeBlockHash = (index, previousHash, timestamp, encryptedContent, sender, receiver) => {
  const data = `${index}${previousHash}${timestamp}${encryptedContent}${sender}${receiver}`;
  return crypto.createHash("sha256").update(data).digest("hex");
};

/**
 * Fetch the latest block in the chain (or genesis defaults).
 */
const getLastBlock = async () => {
  const last = await Block.findOne().sort({ blockIndex: -1 });
  return last || { blockIndex: -1, messageHash: "0000000000000000" };
};

/**
 * Append a new block to the chain and return block metadata.
 */
const appendToChain = async (messageId, encryptedContent, senderId, receiverId) => {
  const last       = await getLastBlock();
  const newIndex   = last.blockIndex + 1;
  const timestamp  = new Date().toISOString();
  const prevHash   = last.messageHash;

  const hash = computeBlockHash(
    newIndex, prevHash, timestamp,
    encryptedContent,
    senderId.toString(), receiverId.toString()
  );

  await Block.create({
    blockIndex:     newIndex,
    messageId,
    messageHash:    hash,
    previousHash:   prevHash,
    blockTimestamp: timestamp,
    sender:         senderId.toString(),
    receiver:       receiverId.toString(),
  });

  return { blockIndex: newIndex, messageHash: hash, previousHash: prevHash, blockTimestamp: timestamp };
};

/**
 * Verify the integrity of a single block by re-computing its hash.
 */
const verifySingleBlock = async (blockIndex, encryptedContent, senderId, receiverId) => {
  const block = await Block.findOne({ blockIndex });
  if (!block) return false;
  const recomputed = computeBlockHash(
    block.blockIndex, block.previousHash, block.blockTimestamp,
    encryptedContent,
    senderId.toString(), receiverId.toString()
  );
  return recomputed === block.messageHash;
};

/**
 * Verify the ENTIRE blockchain — checks every link in the chain.
 */
const verifyEntireChain = async () => {
  const blocks = await Block.find().sort({ blockIndex: 1 });
  for (let i = 1; i < blocks.length; i++) {
    if (blocks[i].previousHash !== blocks[i - 1].messageHash) {
      return { valid: false, brokenAtBlock: blocks[i].blockIndex };
    }
  }
  return { valid: true, totalBlocks: blocks.length };
};

// ─────────────────────────────────────────────────────────────
// 6. MIDDLEWARE
// ─────────────────────────────────────────────────────────────

const protect = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Not authorised — no token" });
  }
  try {
    const token   = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user      = await User.findById(decoded.id).select("-password");
    if (!req.user) return res.status(401).json({ message: "User not found" });
    next();
  } catch {
    res.status(401).json({ message: "Not authorised — token invalid" });
  }
};

// ─────────────────────────────────────────────────────────────
// 7. AUTH ROUTES
// ─────────────────────────────────────────────────────────────

// ── POST /api/auth/register ─────────────────────────────────
app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password)
      return res.status(400).json({ message: "All fields are required" });

    const exists = await User.findOne({ $or: [{ email }, { username }] });
    if (exists)
      return res.status(400).json({ message: "Username or email already taken" });

    // Generate RSA key pair
    const { publicKey, privateKey } = generateRSAKeyPair();

    // Create anonymous alias
    const anonymousAlias = `Ghost_${Math.floor(1000 + Math.random() * 9000)}`;

    const user = await User.create({
      username, email, password, publicKey, anonymousAlias,
    });

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: JWT_EXPIRES });

    // ⚠️ Private key returned ONCE — user must save it locally
    res.status(201).json({
      message:    "Registration successful",
      token,
      user:       user.toSafeObject(),
      privateKey, // ← store securely on client; NEVER sent again
    });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ message: "Server error during registration" });
  }
});

// ── POST /api/auth/login ────────────────────────────────────
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: "Email and password required" });

    const user = await User.findOne({ email });
    if (!user || !(await user.matchPassword(password)))
      return res.status(401).json({ message: "Invalid credentials" });

    user.isOnline = true;
    user.lastSeen = new Date();
    await user.save();

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: JWT_EXPIRES });

    res.json({ message: "Login successful", token, user: user.toSafeObject() });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Server error during login" });
  }
});

// ── POST /api/auth/logout ───────────────────────────────────
app.post("/api/auth/logout", protect, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.user._id, {
      isOnline: false, lastSeen: new Date(),
    });
    res.json({ message: "Logged out successfully" });
  } catch (err) {
    res.status(500).json({ message: "Logout error" });
  }
});

// ── POST /api/auth/forgot-password ─────────────────────────
// Step 1: User enters email → server sends OTP
app.post("/api/auth/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: "Email is required" });

    const user = await User.findOne({ email: email.toLowerCase() });
    // Always respond OK — don't reveal if email exists
    if (!user) return res.json({ message: "If that email exists, a code was sent." });

    // Generate 6-digit OTP
    const otp     = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Save to DB
    user.resetOTP        = otp;
    user.resetOTPExpires = expires;
    await user.save();

    // Send email
    try {
      await sendOTPEmail(email, otp);
    } catch (emailErr) {
      console.error("❌ Email send failed:", emailErr.message);
      // Rollback OTP
      user.resetOTP = null; user.resetOTPExpires = null;
      await user.save();
      return res.status(500).json({ message: "Failed to send email. Check server EMAIL config in .env" });
    }

    res.json({ message: "Reset code sent! Check your inbox (and spam folder)." });
  } catch (err) {
    console.error("Forgot password error:", err);
    res.status(500).json({ message: "Failed to send reset email. Check server EMAIL config." });
  }
});

// ── POST /api/auth/verify-otp ───────────────────────────────
// Step 2: User enters OTP → server validates it
app.post("/api/auth/verify-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ message: "Email and code required" });

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user || !user.resetOTP)
      return res.status(400).json({ message: "No reset request found. Please request a new code." });

    if (new Date() > user.resetOTPExpires)
      return res.status(400).json({ message: "Code has expired. Please request a new one." });

    if (user.resetOTP !== otp.toString())
      return res.status(400).json({ message: "Incorrect code. Please try again." });

    // OTP valid — issue a short-lived reset token
    const resetToken = jwt.sign({ id: user._id, purpose: "reset" }, JWT_SECRET, { expiresIn: "15m" });

    res.json({ message: "Code verified!", resetToken });
  } catch (err) {
    res.status(500).json({ message: "Verification failed" });
  }
});

// ── POST /api/auth/reset-password ──────────────────────────
// Step 3: User enters new password
app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { resetToken, newPassword } = req.body;
    if (!resetToken || !newPassword)
      return res.status(400).json({ message: "Token and new password required" });

    if (newPassword.length < 6)
      return res.status(400).json({ message: "Password must be at least 6 characters" });

    // Verify reset token
    let decoded;
    try {
      decoded = jwt.verify(resetToken, JWT_SECRET);
    } catch {
      return res.status(400).json({ message: "Reset session expired. Please start again." });
    }

    if (decoded.purpose !== "reset")
      return res.status(400).json({ message: "Invalid reset token" });

    const user = await User.findById(decoded.id);
    if (!user) return res.status(404).json({ message: "User not found" });

    // Update password and clear OTP
    user.password        = newPassword; // pre-save hook will hash it
    user.resetOTP        = null;
    user.resetOTPExpires = null;
    await user.save();

    res.json({ message: "Password reset successfully! You can now log in." });
  } catch (err) {
    console.error("Reset error:", err);
    res.status(500).json({ message: "Reset failed" });
  }
});

// ── PUT /api/auth/toggle-anonymous ─────────────────────────
app.put("/api/auth/toggle-anonymous", protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    user.isAnonymous = !user.isAnonymous;
    await user.save();
    res.json({
      message:     `Anonymous mode ${user.isAnonymous ? "ON" : "OFF"}`,
      isAnonymous: user.isAnonymous,
      alias:       user.anonymousAlias,
    });
  } catch (err) {
    res.status(500).json({ message: "Toggle error" });
  }
});

// ── GET /api/auth/me ────────────────────────────────────────
app.get("/api/auth/me", protect, (req, res) => {
  res.json({ user: req.user.toSafeObject() });
});

// ─────────────────────────────────────────────────────────────
// 8. USER ROUTES
// ─────────────────────────────────────────────────────────────

// ── GET /api/users — all users except self ──────────────────
app.get("/api/users", protect, async (req, res) => {
  try {
    const users = await User.find({ _id: { $ne: req.user._id } }).select(
      "username anonymousAlias isAnonymous isOnline lastSeen publicKey avatar bio"
    );
    res.json({ users });
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch users" });
  }
});

// ── GET /api/users/:id ──────────────────────────────────────
app.get("/api/users/:id", protect, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select(
      "username anonymousAlias isAnonymous isOnline lastSeen publicKey"
    );
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json({ user });
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch user" });
  }
});

// ── PUT /api/users/update-key — update RSA public key ───────
app.put("/api/users/update-key", protect, async (req, res) => {
  try {
    const { publicKey } = req.body;
    if (!publicKey) return res.status(400).json({ message: "Public key required" });
    await User.findByIdAndUpdate(req.user._id, { publicKey });
    res.json({ message: "Public key updated" });
  } catch (err) {
    res.status(500).json({ message: "Key update failed" });
  }
});

// ── PUT /api/users/update-profile ────────────────────────────
app.put("/api/users/update-profile", protect, async (req, res) => {
  try {
    const { username, bio, avatar } = req.body;
    const updates = {};

    if (username) {
      // Check username not taken by someone else
      const existing = await User.findOne({ username, _id: { $ne: req.user._id } });
      if (existing) return res.status(400).json({ message: "Username already taken" });
      updates.username = username.trim();
    }
    if (bio !== undefined) updates.bio = bio.slice(0, 120);
    if (avatar !== undefined) updates.avatar = avatar; // base64 string

    const updated = await User.findByIdAndUpdate(req.user._id, updates, { new: true });
    res.json({ message: "Profile updated", user: updated.toSafeObject() });
  } catch (err) {
    console.error("Profile update error:", err);
    res.status(500).json({ message: "Failed to update profile" });
  }
});

// ─────────────────────────────────────────────────────────────
// 9. MESSAGE ROUTES
// ─────────────────────────────────────────────────────────────

// ── POST /api/messages/send ─────────────────────────────────
app.post("/api/messages/send", protect, async (req, res) => {
  try {
    const { receiverId, plaintext, sentAnonymously } = req.body;
    if (!receiverId || !plaintext)
      return res.status(400).json({ message: "receiverId and plaintext are required" });

    const sender   = req.user;
    const receiver = await User.findById(receiverId);
    if (!receiver)          return res.status(404).json({ message: "Receiver not found" });
    if (!receiver.publicKey) return res.status(400).json({ message: "Receiver has no public key" });

    // ── Step 1: AES-encrypt the message ─────────────────
    const { encryptedContent, iv, aesKey } = encryptAES(plaintext);

    // ── Step 2: RSA-encrypt the AES key ─────────────────
    const encryptedAESKey = encryptAESKeyRSA(aesKey, receiver.publicKey);

    // ── Step 3: Persist message (temporary hash) ─────────
    const newMsg = await Message.create({
      sender:           sender._id,
      receiver:         receiverId,
      encryptedContent,
      encryptedAESKey,
      iv,
      plaintext:        plaintext,
      messageHash:      "pending",
      previousHash:     "pending",
      blockIndex:       0,
      blockTimestamp:   new Date().toISOString(),
      sentAnonymously:  sentAnonymously || sender.isAnonymous,
    });

    // ── Step 4: Add to blockchain ────────────────────────
    const blockData = await appendToChain(
      newMsg._id, encryptedContent, sender._id, receiverId
    );

    // ── Step 5: Update message with real block data ───────
    newMsg.messageHash    = blockData.messageHash;
    newMsg.previousHash   = blockData.previousHash;
    newMsg.blockIndex     = blockData.blockIndex;
    newMsg.blockTimestamp = blockData.blockTimestamp;
    newMsg.isVerified     = true;
    await newMsg.save();

    // ── Step 6: Emit via Socket.io if receiver is online ─
    const receiverSocketId = onlineUsers.get(receiverId.toString());
    if (receiverSocketId) {
      io.to(receiverSocketId).emit("receive_message", {
        messageId:        newMsg._id,
        senderId:         sender._id,
        senderName:       sender.isAnonymous ? sender.anonymousAlias : sender.username,
        plaintext:        plaintext,
        encryptedContent,
        encryptedAESKey,
        iv,
        blockIndex:       blockData.blockIndex,
        messageHash:      blockData.messageHash,
        sentAnonymously:  newMsg.sentAnonymously,
        isVerified:       true,
        createdAt:        newMsg.createdAt,
      });
    }

    res.status(201).json({
      message:  "Message sent",
      data: {
        messageId:       newMsg._id,
        encryptedContent,
        encryptedAESKey,
        iv,
        blockIndex:      blockData.blockIndex,
        messageHash:     blockData.messageHash,
        sentAnonymously: newMsg.sentAnonymously,
        createdAt:       newMsg.createdAt,
      },
    });
  } catch (err) {
    console.error("Send message error:", err);
    res.status(500).json({ message: "Failed to send message" });
  }
});

// ── GET /api/messages/conversation/:userId ──────────────────
app.get("/api/messages/conversation/:userId", protect, async (req, res) => {
  try {
    const me    = req.user._id;
    const other = req.params.userId;

    const messages = await Message.find({
      $or: [
        { sender: me, receiver: other },
        { sender: other, receiver: me },
      ],
    })
      .sort({ createdAt: 1 })
      .populate("sender",   "username anonymousAlias isAnonymous")
      .populate("receiver", "username anonymousAlias isAnonymous");

    res.json({ messages });
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch conversation" });
  }
});

// ── POST /api/messages/decrypt ──────────────────────────────
// Client sends their private key + encrypted data to decrypt on server
// NOTE: In a true E2E setup, decryption happens on the client.
//       This endpoint is provided for demonstration / testing.
app.post("/api/messages/decrypt", protect, async (req, res) => {
  try {
    const { encryptedContent, encryptedAESKey, iv, privateKey } = req.body;
    if (!encryptedContent || !encryptedAESKey || !iv || !privateKey)
      return res.status(400).json({ message: "All fields required for decryption" });

    const aesKey    = decryptAESKeyRSA(encryptedAESKey, privateKey);
    const plaintext = decryptAES(encryptedContent, aesKey, iv);

    res.json({ plaintext });
  } catch (err) {
    console.error("Decrypt error:", err.message);
    res.status(400).json({ message: "Decryption failed — wrong key or corrupted data" });
  }
});

// ── GET /api/messages/verify/:messageId ─────────────────────
app.get("/api/messages/verify/:messageId", protect, async (req, res) => {
  try {
    const msg = await Message.findById(req.params.messageId);
    if (!msg) return res.status(404).json({ message: "Message not found" });

    const isValid = await verifySingleBlock(
      msg.blockIndex, msg.encryptedContent, msg.sender, msg.receiver
    );

    // Update verified flag
    if (msg.isVerified !== isValid) {
      msg.isVerified = isValid;
      await msg.save();
    }

    res.json({
      messageId:  msg._id,
      isVerified: isValid,
      blockIndex: msg.blockIndex,
      hash:       msg.messageHash,
    });
  } catch (err) {
    res.status(500).json({ message: "Verification failed" });
  }
});

// ── GET /api/messages/verify-chain ──────────────────────────
app.get("/api/messages/verify-chain", protect, async (req, res) => {
  try {
    const result = await verifyEntireChain();
    res.json(result);
  } catch (err) {
    res.status(500).json({ message: "Chain verification failed" });
  }
});

// ── GET /api/messages/blockchain ────────────────────────────
app.get("/api/messages/blockchain", protect, async (req, res) => {
  try {
    const blocks = await Block.find().sort({ blockIndex: 1 });
    res.json({ chain: blocks, length: blocks.length });
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch blockchain" });
  }
});

// ── POST /api/messages/screenshot ───────────────────────────
app.post("/api/messages/screenshot", protect, async (req, res) => {
  try {
    const { messageId, receiverId } = req.body;
    const userId = req.user._id;

    // Flag message
    if (messageId) {
      await Message.findByIdAndUpdate(messageId, { screenshotDetected: true });
    }

    // Increment user counter
    await User.findByIdAndUpdate(userId, { $inc: { screenshotAttempts: 1 } });

    // Alert the other party via socket if online
    if (receiverId) {
      const receiverSocketId = onlineUsers.get(receiverId.toString());
      if (receiverSocketId) {
        io.to(receiverSocketId).emit("screenshot_alert", {
          message: "⚠️ The other user attempted a screenshot!",
          by:  userId,
          at:  new Date().toISOString(),
        });
      }
    }

    res.json({ message: "Screenshot attempt logged ⚠️" });
  } catch (err) {
    res.status(500).json({ message: "Failed to log screenshot attempt" });
  }
});

// ── GET /api/messages/screenshot-log ────────────────────────
app.get("/api/messages/screenshot-log", protect, async (req, res) => {
  try {
    const flagged = await Message.find({
      screenshotDetected: true,
      $or: [{ sender: req.user._id }, { receiver: req.user._id }],
    })
      .sort({ updatedAt: -1 })
      .populate("sender",   "username anonymousAlias")
      .populate("receiver", "username anonymousAlias");

    res.json({ flagged });
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch screenshot log" });
  }
});

// ── DELETE MESSAGE
// POST /api/messages/delete
app.post("/api/messages/delete", protect, async (req, res) => {
  try {
    const { messageId } = req.body;
    const msg = await Message.findById(messageId);
    if (!msg) return res.status(404).json({ message: "Message not found" });
    if (msg.sender.toString() !== req.user._id.toString())
      return res.status(403).json({ message: "You can only delete your own messages" });
    await Message.findByIdAndDelete(messageId);
    res.json({ message: "Message deleted" });
  } catch (err) {
    res.status(500).json({ message: "Failed to delete message" });
  }
});

// ── EDIT MESSAGE
// POST /api/messages/edit
app.post("/api/messages/edit", protect, async (req, res) => {
  try {
    const { messageId, newText } = req.body;
    const msg = await Message.findById(messageId);
    if (!msg) return res.status(404).json({ message: "Message not found" });
    if (msg.sender.toString() !== req.user._id.toString())
      return res.status(403).json({ message: "You can only edit your own messages" });
    msg.plaintext  = newText;
    msg.isEdited   = true;
    await msg.save();
    res.json({ message: "Message updated", plaintext: newText });
  } catch (err) {
    res.status(500).json({ message: "Failed to edit message" });
  }
});


// ── MARK MESSAGE AS READ
// PUT /api/messages/read/:messageId
app.put("/api/messages/read/:messageId", protect, async (req, res) => {
  try {
    await Message.findByIdAndUpdate(req.params.messageId, { isRead: true });
    res.json({ message: "Marked as read" });
  } catch (err) {
    res.status(500).json({ message: "Failed to update read status" });
  }
});

// ─────────────────────────────────────────────────────────────
// 10. SOCKET.IO — REAL-TIME EVENTS
// ─────────────────────────────────────────────────────────────

// In-memory map: userId (string) → socketId
const onlineUsers = new Map();

io.on("connection", (socket) => {
  console.log(`🔌 Socket connected: ${socket.id}`);

  // ── USER COMES ONLINE ──────────────────────────────────
  socket.on("user_connected", async (userId) => {
    onlineUsers.set(userId, socket.id);
    socket.userId = userId;

    await User.findByIdAndUpdate(userId, {
      isOnline: true, lastSeen: new Date(),
    });

    // Broadcast updated online list to everyone
    io.emit("online_users", Array.from(onlineUsers.keys()));
    console.log(`✅ User ${userId} online`);
  });

  // ── REAL-TIME MESSAGE ──────────────────────────────────
  // Used when REST /send is too slow or for direct socket delivery
  socket.on("send_message", async (data) => {
    const { receiverId, messageData } = data;
    const receiverSocketId = onlineUsers.get(receiverId);

    if (receiverSocketId) {
      io.to(receiverSocketId).emit("receive_message", {
        ...messageData,
        deliveredAt: new Date().toISOString(),
      });
    } else {
      socket.emit("message_undelivered", {
        receiverId,
        info: "User is offline — message saved to DB.",
      });
    }
  });

  // ── TYPING INDICATORS ─────────────────────────────────
  socket.on("typing", ({ receiverId, senderId }) => {
    const target = onlineUsers.get(receiverId);
    if (target) io.to(target).emit("user_typing", { senderId });
  });

  socket.on("stop_typing", ({ receiverId, senderId }) => {
    const target = onlineUsers.get(receiverId);
    if (target) io.to(target).emit("user_stopped_typing", { senderId });
  });

  // ── SCREENSHOT DETECTED (client-side detection) ────────
  socket.on("screenshot_detected", async ({ senderId, receiverId, messageId }) => {
    // Persist flag
    if (messageId) {
      await Message.findByIdAndUpdate(messageId, { screenshotDetected: true });
    }
    await User.findByIdAndUpdate(senderId, { $inc: { screenshotAttempts: 1 } });

    // Alert receiver
    const receiverSocketId = onlineUsers.get(receiverId);
    if (receiverSocketId) {
      io.to(receiverSocketId).emit("screenshot_alert", {
        message: "⚠️ The other user attempted a screenshot!",
        by:  senderId,
        at:  new Date().toISOString(),
      });
    }
    console.log(`📸 Screenshot attempt by ${senderId}`);
  });

  // ── MESSAGE READ RECEIPT ───────────────────────────────
  socket.on("message_read", ({ messageId, senderId }) => {
    const senderSocketId = onlineUsers.get(senderId);
    if (senderSocketId) {
      io.to(senderSocketId).emit("message_seen", { messageId });
    }
  });

  // ── MESSAGE DELETED ────────────────────────────────────
  socket.on("message_deleted", ({ messageId, receiverId }) => {
    const receiverSocketId = onlineUsers.get(receiverId);
    if (receiverSocketId) {
      io.to(receiverSocketId).emit("message_deleted", { messageId });
    }
  });

  // ── MESSAGE EDITED ─────────────────────────────────────
  socket.on("message_edited", ({ messageId, newText, receiverId }) => {
    const receiverSocketId = onlineUsers.get(receiverId);
    if (receiverSocketId) {
      io.to(receiverSocketId).emit("message_edited", { messageId, newText });
    }
  });

  // ── ANONYMOUS MODE TOGGLE BROADCAST ───────────────────
  socket.on("anonymous_mode_changed", ({ userId, isAnonymous, alias }) => {
    // Notify contacts (optional: only notify active chat partners)
    socket.broadcast.emit("user_anonymous_changed", { userId, isAnonymous, alias });
  });

  // ── DISCONNECT ─────────────────────────────────────────
  socket.on("disconnect", async () => {
    const userId = socket.userId;
    if (userId) {
      onlineUsers.delete(userId);
      await User.findByIdAndUpdate(userId, {
        isOnline: false, lastSeen: new Date(),
      });
      io.emit("online_users", Array.from(onlineUsers.keys()));
      console.log(`❌ User ${userId} offline`);
    }
    console.log(`🔌 Socket disconnected: ${socket.id}`);
  });
});

// ─────────────────────────────────────────────────────────────
// 11. HEALTH CHECK & API SUMMARY
// ─────────────────────────────────────────────────────────────
app.get("/", (req, res) => {
  res.json({
    app:     "SecureChat Server",
    student: "Samaila Bello | U22/CPS/1067",
    status:  "running ✅",
    endpoints: {
      auth:     ["POST /api/auth/register", "POST /api/auth/login", "POST /api/auth/logout", "PUT /api/auth/toggle-anonymous", "GET /api/auth/me"],
      users:    ["GET /api/users", "GET /api/users/:id", "PUT /api/users/update-key"],
      messages: [
        "POST /api/messages/send",
        "GET  /api/messages/conversation/:userId",
        "POST /api/messages/decrypt",
        "GET  /api/messages/verify/:messageId",
        "GET  /api/messages/verify-chain",
        "GET  /api/messages/blockchain",
        "POST /api/messages/screenshot",
        "GET  /api/messages/screenshot-log",
        "PUT  /api/messages/read/:messageId",
      ],
    },
    socketEvents: {
      client_emit: ["user_connected", "send_message", "typing", "stop_typing", "screenshot_detected", "message_read", "anonymous_mode_changed"],
      server_emit: ["receive_message", "online_users", "user_typing", "user_stopped_typing", "screenshot_alert", "message_seen", "message_undelivered", "user_anonymous_changed"],
    },
  });
});

// ─────────────────────────────────────────────────────────────
// 12. START SERVER
// ─────────────────────────────────────────────────────────────
mongoose
  .connect(MONGO_URI)
  .then(() => {
    console.log("✅ MongoDB connected");
    server.listen(PORT, () => {
      console.log(`✅ SecureChat server running on http://localhost:${PORT}`);
      console.log(`   Student  : Samaila Bello | U22/CPS/1067`);
    });
  })
  .catch((err) => {
    console.error("❌ MongoDB connection failed:", err.message);
    process.exit(1);
  });
