require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { sql, getPool } = require("./db");

const app = express();
app.use(cors());
app.use(express.json());

// ====== Health ======
app.get("/health", (req, res) => res.json({ ok: true }));

// ====== Auth middleware ======
function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ message: "Missing token" });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }
}

// ====== REGISTER ======
app.post("/auth/register", async (req, res) => {
  const { email, password, role } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "email/password required" });
  }

  try {
    const password_hash = await bcrypt.hash(password, 10);
    const pool = await getPool();

    await pool.request()
      .input("email", sql.NVarChar(255), email)
      .input("password_hash", sql.NVarChar(255), password_hash)
      .input("role", sql.NVarChar(20), role === "owner" ? "owner" : "employee")
      .query(`
        INSERT INTO users (email, password_hash, role)
        VALUES (@email, @password_hash, @role)
      `);

    return res.json({ message: "registered" });
  } catch (e) {
    const msg = String(e.message || e);

    // email ซ้ำ (unique constraint)
    if (msg.toLowerCase().includes("unique") || msg.toLowerCase().includes("duplicate")) {
      return res.status(409).json({ message: "email already exists" });
    }

    return res.status(500).json({ message: "server error", error: msg });
  }
});

// ====== LOGIN ======
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "email/password required" });
  }

  try {
    const pool = await getPool();

    const r = await pool.request()
      .input("email", sql.NVarChar(255), email)
      .query(`SELECT TOP 1 id, email, password_hash, role FROM users WHERE email = @email`);

    const user = r.recordset?.[0];
    if (!user) return res.status(401).json({ message: "invalid credentials" });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ message: "invalid credentials" });

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    return res.json({
      token,
      user: { id: user.id, email: user.email, role: user.role },
    });
  } catch (e) {
    return res.status(500).json({ message: "server error", error: String(e.message || e) });
  }
});

// ====== ME (ทดสอบ token) ======
app.get("/me", auth, (req, res) => {
  res.json({ user: req.user });
});

app.listen(process.env.PORT || 3000, () => {
  console.log("[API] running on port", process.env.PORT || 3000);
});
