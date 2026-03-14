require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { google } = require("googleapis");
const mongoose = require("mongoose");
const { sql, getPool } = require("./db");
const { connectMongo } = require("./mongo");

const app = express();
const api = express.Router();

const BUILD_TAG = "auth-google-v3-login-redirect"; // ✅ change this string when you update server.js

console.log("========================================");
console.log("[SERVER] BUILD:", BUILD_TAG);
console.log("[SERVER] FILE :", __filename);
console.log("[SERVER] CWD  :", process.cwd());
console.log("========================================");

app.use(cors());
app.use(express.json({ limit: "2mb" }));

(async () => {
  try {
    await connectMongo();
    console.log("[MONGO] connected");
  } catch (e) {
    console.error("[MONGO] connect failed:", e.message);
  }
})();

app.get("/__version", (req, res) => {
  res.json({ build: BUILD_TAG, file: __filename, cwd: process.cwd() });
});

app.get("/health", (req, res) => res.json({ ok: true, build: BUILD_TAG }));

app.get("/mongo/ping", async (req, res) => {
  try {
    await connectMongo();
    res.json({ ok: true, message: "MongoDB Atlas connected" });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

function makeSafeNickname(name, email) {
  const base =
    String(name || "").trim() ||
    String(email || "").trim().split("@")[0] ||
    "google_user";
  return base.slice(0, 100);
}

const googleOAuth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI
);

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
// ✅ เพิ่ม nickname
app.post("/auth/register", async (req, res) => {
  const { email, password, nickname, role } = req.body;

  if (!email || !password || !nickname) {
    return res.status(400).json({ message: "email/password/nickname required" });
  }

  try {
    const password_hash = await bcrypt.hash(password, 10);
    const pool = await getPool();

    await pool
      .request()
      .input("email", sql.NVarChar(255), email)
      .input("password_hash", sql.NVarChar(255), password_hash)
      .input("nickname", sql.NVarChar(100), nickname)
      .input("role", sql.NVarChar(20), role === "owner" ? "owner" : "employee")
      .query(`
        INSERT INTO users (email, password_hash, nickname, role)
        VALUES (@email, @password_hash, @nickname, @role)
      `);

    return res.json({ message: "registered" });
  } catch (e) {
    const msg = String(e.message || e);

    // email / nickname ซ้ำ (unique constraint)
    if (msg.toLowerCase().includes("unique") || msg.toLowerCase().includes("duplicate")) {
      return res.status(409).json({ message: "email or nickname already exists" });
    }

    return res.status(500).json({ message: "server error", error: msg });
  }
});

// ====== LOGIN ======
// ✅ ส่ง nickname กลับ + ใส่ใน token
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "email/password required" });
  }

  try {
    const pool = await getPool();

    const r = await pool
      .request()
      .input("email", sql.NVarChar(255), email)
      .query(`
        SELECT TOP 1 id, email, password_hash, nickname, role
        FROM users
        WHERE email = @email
      `);

    const user = r.recordset?.[0];
    if (!user) return res.status(401).json({ message: "invalid credentials" });

    if (!user.password_hash) {
      return res.status(401).json({ message: "invalid credentials" });
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ message: "invalid credentials" });

    const token = jwt.sign(
      { id: user.id, email: user.email, nickname: user.nickname, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    return res.json({
      token,
      user: { id: user.id, email: user.email, nickname: user.nickname, role: user.role },
    });
  } catch (e) {
    return res.status(500).json({ message: "server error", error: String(e.message || e) });
  }
});

// ====== ME (ทดสอบ token) ======
app.get("/me", auth, (req, res) => {
  res.json({ user: req.user });
});

// ====== GOOGLE LOGIN ======
app.get("/auth/google/start", (req, res) => {
  try {
    if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET || !process.env.GOOGLE_REDIRECT_URI) {
      return res.status(500).json({
        message: "Google OAuth env is missing",
        required: ["GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "GOOGLE_REDIRECT_URI"],
      });
    }

    const url = googleOAuth2Client.generateAuthUrl({
      access_type: "offline",
      prompt: "consent",
      scope: ["openid", "email", "profile"],
    });

    return res.redirect(url);
  } catch (e) {
    return res.status(500).json({ message: "google start failed", error: String(e.message || e) });
  }
});

app.get("/auth/google/callback", async (req, res) => {
  try {
    const frontendUrl = process.env.FRONTEND_URL || "http://localhost:3000";
    const code = String(req.query.code || "");

    if (!code) {
      return res.redirect(`${frontendUrl}/login?error=${encodeURIComponent("Missing Google code")}`);
    }

    const { tokens } = await googleOAuth2Client.getToken(code);
    googleOAuth2Client.setCredentials(tokens);

    const oauth2 = google.oauth2({ auth: googleOAuth2Client, version: "v2" });
    const { data } = await oauth2.userinfo.get();

    const email = String(data.email || "").trim().toLowerCase();
    const nickname = makeSafeNickname(data.name, email);

    if (!email) {
      return res.redirect(`${frontendUrl}/login?error=${encodeURIComponent("Google email not found")}`);
    }

    const pool = await getPool();

    let userRes = await pool
      .request()
      .input("email", sql.NVarChar(255), email)
      .query(`
        SELECT TOP 1 id, email, password_hash, nickname, role
        FROM users
        WHERE email = @email
      `);

    let user = userRes.recordset?.[0];

    if (!user) {
      await pool
        .request()
        .input("email", sql.NVarChar(255), email)
        .input("password_hash", sql.NVarChar(255), "")
        .input("nickname", sql.NVarChar(100), nickname)
        .input("role", sql.NVarChar(20), "employee")
        .query(`
          INSERT INTO users (email, password_hash, nickname, role)
          VALUES (@email, @password_hash, @nickname, @role)
        `);

      userRes = await pool
        .request()
        .input("email", sql.NVarChar(255), email)
        .query(`
          SELECT TOP 1 id, email, password_hash, nickname, role
          FROM users
          WHERE email = @email
        `);

      user = userRes.recordset?.[0];
    } else if (!String(user.nickname || "").trim() && nickname) {
      await pool
        .request()
        .input("id", sql.Int, user.id)
        .input("nickname", sql.NVarChar(100), nickname)
        .query(`
          UPDATE users
          SET nickname = @nickname
          WHERE id = @id
        `);

      user.nickname = nickname;
    }

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        nickname: user.nickname || nickname,
        role: user.role || "employee",
      },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    return res.redirect(`${frontendUrl}/login?token=${encodeURIComponent(token)}`);
  } catch (e) {
    const frontendUrl = process.env.FRONTEND_URL || "http://localhost:3000";
    return res.redirect(`${frontendUrl}/login?error=${encodeURIComponent(String(e.message || e))}`);
  }
});

// ==============================
// DUWIMS /api (MongoDB persistent)
// ตามเอกสาร DUWIMS_pages_data_requirements.docx
// ==============================

const mongoose = require("mongoose");

// ----- Models (inline, single-file) -----
// NOTE: ใช้ mongoose.models.* เพื่อกันประกาศซ้ำเวลา hot-reload / nodemon
const Plot =
  mongoose.models.Plot ||
  mongoose.model(
    "Plot",
    new mongoose.Schema(
      {
        // meta
        alias: { type: String, default: "", trim: true },
        plotName: { type: String, default: "", trim: true }, // ชื่อเต็ม
        caretaker: { type: String, default: "", trim: true },
        plantType: { type: String, default: "", trim: true },
        plantedAt: { type: String, default: null }, // เก็บเป็น string (YYYY-MM-DD/ISO) เพื่อให้ FE ง่าย
        status: { type: String, default: "ACTIVE" },

        // backward compat (ของเดิมในไฟล์ server.js)
        name: { type: String, default: "", trim: true },
        cropType: { type: String, default: "", trim: true },
        ownerName: { type: String, default: "", trim: true },
      },
      { timestamps: true }
    )
  );

const NodeModel =
  mongoose.models.Node ||
  mongoose.model(
    "Node",
    new mongoose.Schema(
      {
        plotId: { type: String, required: true, index: true },
        category: { type: String, default: "soil", index: true }, // air | soil
        name: { type: String, default: "", trim: true },
        firmware: { type: String, default: "", trim: true },
        lastSeen: { type: String, default: null },
        status: { type: String, default: "ONLINE" },
      },
      { timestamps: true }
    )
  );

const Polygon =
  mongoose.models.Polygon ||
  mongoose.model(
    "Polygon",
    new mongoose.Schema(
      {
        plotId: { type: String, required: true, index: true },
        polygonId: { type: String, default: () => require("crypto").randomUUID() },
        color: { type: String, default: "#2563eb" },
        coords: { type: [[Number]], required: true }, // [[lat,lng],...]
      },
      { timestamps: true }
    )
  );
// ✅ รองรับหลาย polygons ต่อ 1 plot
Polygon.schema.index({ plotId: 1, polygonId: 1 }, { unique: true });
Polygon.schema.index({ plotId: 1 });

const Pin =
  mongoose.models.Pin ||
  mongoose.model(
    "Pin",
    new mongoose.Schema(
      {
        plotId: { type: String, required: true, index: true },
        nodeId: { type: String, default: null, index: true }, // optional
        sensorId: { type: String, default: null, index: true }, // optional (กรณี pin ผูกกับ sensor)
        number: { type: Number, required: true },
        lat: { type: Number, required: true },
        lng: { type: Number, required: true },
      },
      { timestamps: true }
    )
  );
Pin.schema.index({ plotId: 1, number: 1 }, { unique: true });

const Sensor =
  mongoose.models.Sensor ||
  mongoose.model(
    "Sensor",
    new mongoose.Schema(
      {
        // เก็บเป็น String เพื่อ backward compat กับของเดิม (FE ส่งมาเป็น string id)
        nodeId: { type: String, required: true, index: true },
        pinId: { type: String, default: null, index: true }, // optional
        sensorType: { type: String, required: true, index: true }, // soil_moisture, temp_rh, wind...
        name: { type: String, default: "", trim: true },
        unit: { type: String, default: "" },
        valueHint: { type: String, default: "" }, // optional
        status: { type: String, default: "OK" },

        // ✅ ค่าอ่านล่าสุด (สำหรับหน้าเว็บโหลดเร็ว)
        lastReading: {
          value: { type: Number, default: null },
          ts: { type: String, default: null }, // ISO string
        },
      },
      { timestamps: true }
    )
  );

// ✅ กัน sensor ซ้ำ: 1 node + 1 pin + 1 type + 1 name = 1 sensor
Sensor.schema.index({ nodeId: 1, pinId: 1, sensorType: 1, name: 1 }, { unique: true });

const Note =
  mongoose.models.Note ||
  mongoose.model(
    "Note",
    new mongoose.Schema(
      {
        plotId: { type: String, required: true, index: true },
        topic: { type: String, required: true, trim: true },
        content: { type: String, default: "", trim: true },
        author: { type: String, default: "" },
        updatedBy: { type: String, default: "" },
      },
      { timestamps: true }
    )
  );

// ✅ เก็บ "ประวัติการวัด" ทุกครั้ง (สำหรับกราฟ/ย้อนหลัง)
const Reading =
  mongoose.models.Reading ||
  mongoose.model(
    "Reading",
    new mongoose.Schema(
      {
        sensorId: { type: String, required: true, index: true },
        nodeId: { type: String, default: null, index: true },
        pinId: { type: String, default: null, index: true },

        ts: { type: String, required: true, index: true }, // ISO string
        value: { type: Number, required: true },

        status: { type: String, default: "OK" }, // optional
        raw: { type: mongoose.Schema.Types.Mixed }, // optional payload ดิบ
      },
      { timestamps: true }
    )
  );
// ใช้ sort/ช่วงเวลา/กราฟเร็ว
Reading.schema.index({ sensorId: 1, ts: -1 });

// ----- helpers -----
const toNum = (v) => (v === undefined || v === null || v === "" ? null : Number(v));
const isValidLatLng = (lat, lng) =>
  typeof lat === "number" &&
  typeof lng === "number" &&
  !Number.isNaN(lat) &&
  lat >= -90 &&
  lat <= 90 &&
  lng >= -180 &&
  lng <= 180;

// ✅ ObjectId guard (กัน CastError เวลา id ไม่ใช่ ObjectId)
const isValidObjectId = (id) => mongoose.Types.ObjectId.isValid(String(id));
const idOf = (doc) => (doc ? String(doc._id) : "");
const leanWithId = (doc) => {
  if (!doc) return null;
  const d = doc.toObject ? doc.toObject() : doc;
  d.id = String(d._id);
  return d;
};

// ==============================
// Public Ingest (รับค่าจากตัวกลาง/อุปกรณ์) - ไม่บังคับ auth
// แนะนำให้ตั้ง process.env.INGEST_KEY แล้วส่ง header: x-ingest-key
// ==============================
const ingestReadingHandler = async (req, res) => {
  try {
    const requiredKey = process.env.INGEST_KEY;
    if (requiredKey) {
      const got = String(req.headers["x-ingest-key"] || "");
      if (got !== requiredKey) return res.status(401).json({ ok: false, message: "Invalid ingest key" });
    }

    const b = req.body || {};
    const { sensorId, nodeId, pinId, sensorType, name, unit, valueHint, value, ts, status, raw } = b;

    const v = toNum(value);
    if (v === null || Number.isNaN(v)) {
      return res.status(400).json({ ok: false, message: "value must be number" });
    }

    const readingTs = ts || new Date().toISOString();
    const readingStatus = status || "OK";

    let sensorDoc = null;

    // 1) resolve / upsert sensor
    if (sensorId) {
      if (!isValidObjectId(sensorId)) return res.status(400).json({ ok: false, message: "sensorId invalid" });
      sensorDoc = await Sensor.findById(String(sensorId));
      if (!sensorDoc) return res.status(404).json({ ok: false, message: "Sensor not found" });
    } else {
      if (!nodeId || !pinId || !sensorType || !name) {
        return res.status(400).json({
          ok: false,
          message: "need nodeId, pinId, sensorType, name when sensorId not provided",
        });
      }

      // upsert (กันซ้ำด้วย unique index)
      sensorDoc = await Sensor.findOneAndUpdate(
        { nodeId: String(nodeId), pinId: String(pinId), sensorType: String(sensorType), name: String(name) },
        {
          $setOnInsert: {
            unit: unit || "",
            valueHint: valueHint || "",
            status: readingStatus,
            lastReading: { value: v, ts: readingTs },
          },
        },
        { new: true, upsert: true }
      );

      // ถ้าเป็น doc เดิม ให้ update lastReading ถ้าใหม่กว่า
      if (sensorDoc && sensorDoc.lastReading && sensorDoc.lastReading.ts) {
        const prevTs = new Date(sensorDoc.lastReading.ts).getTime();
        const nextTs = new Date(readingTs).getTime();
        if (!Number.isFinite(prevTs) || (Number.isFinite(nextTs) && nextTs >= prevTs)) {
          await Sensor.updateOne(
            { _id: sensorDoc._id },
            { $set: { lastReading: { value: v, ts: readingTs }, status: readingStatus } }
          );
        }
      }
    }

    // refresh sensor (ensure we have latest nodeId/pinId)
    const sLean = await Sensor.findById(String(sensorDoc._id)).lean();

    // 2) insert history
    const item = await Reading.create({
      sensorId: String(sensorDoc._id),
      nodeId: sLean?.nodeId || String(nodeId || null),
      pinId: sLean?.pinId || String(pinId || null),
      ts: readingTs,
      value: v,
      status: readingStatus,
      raw: raw || undefined,
    });

    return res.json({
      ok: true,
      sensorId: String(sensorDoc._id),
      readingId: String(item._id),
      lastReading: { value: v, ts: readingTs },
      status: readingStatus,
    });
  } catch (e) {
    // เผื่อชน unique index ตอน upsert พร้อมกัน
    return res.status(500).json({ ok: false, message: String(e.message || e) });
  }
};

app.post("/ingest/reading", ingestReadingHandler);
app.post("/api/ingest/reading", ingestReadingHandler);

const api = express.Router();
api.use(auth);

// ====== Enums (ให้ตรงทุกหน้า) ======
const SENSOR_TYPES = [
  { key: "soil_moisture", label: "ความชื้นในดิน", unit: "%" },
  { key: "temp_rh", label: "อุณหภูมิ/ความชื้น", unit: "" },
  { key: "wind", label: "ความเร็วลม", unit: "m/s" },
  { key: "ppfd", label: "ความเข้มแสง", unit: "lux" },
  { key: "rain", label: "ปริมาณน้ำฝน", unit: "mm" },
  { key: "npk", label: "NPK", unit: "" },
  { key: "irrigation", label: "การให้น้ำ", unit: "L" },
];

// 1) reference
api.get("/sensor-types", (req, res) => res.json({ items: SENSOR_TYPES }));

// ==============================
// 2) plots
// ==============================

// GET /api/plots
api.get("/plots", async (req, res, next) => {
  try {
    const items = (await Plot.find().sort({ createdAt: -1 })).map(leanWithId);
    res.json({ items });
  } catch (e) {
    next(e);
  }
});

// POST /api/plots
api.post("/plots", async (req, res, next) => {
  try {
    const b = req.body || {};
    // รองรับทั้ง key ชุดใหม่และของเดิม
    const plotName = b.plotName || b.name || "";
    const alias = b.alias || plotName || "";
    if (!plotName) return res.status(400).json({ message: "plotName (or name) is required" });

    // ✅ ใช้ชื่อผู้ใช้จาก token เท่านั้น เพื่อกัน frontend ส่งค่าค้าง/ค่าผิด เช่น "0"
    const nicknameFromToken = String(req.user?.nickname || "").trim();

    const doc = await Plot.create({
      alias,
      plotName,
      caretaker: nicknameFromToken,
      plantType: b.plantType || b.cropType || "",
      plantedAt: b.plantedAt || null,

      // backward compat
      name: b.name || plotName,
      ownerName: nicknameFromToken,
      cropType: b.cropType || b.plantType || "",
    });

    res.status(201).json({ item: leanWithId(doc) });
  } catch (e) {
    next(e);
  }
});

// GET /api/plots/:plotId
api.get("/plots/:plotId", async (req, res, next) => {
  try {
    const doc = await Plot.findById(req.params.plotId);
    if (!doc) return res.status(404).json({ message: "Plot not found" });

    // polygon (เพื่อหน้า Management/AddPlantingPlots)
    const poly = await Polygon.findOne({ plotId: req.params.plotId }).lean();

    res.json({ item: { ...leanWithId(doc), polygon: poly || null } });
  } catch (e) {
    next(e);
  }
});

// PATCH /api/plots/:plotId
api.patch("/plots/:plotId", async (req, res, next) => {
  try {
    const b = req.body || {};
    const patch = {};
    const allowed = ["alias", "plotName", "caretaker", "plantType", "plantedAt", "status", "name", "ownerName", "cropType"];
    for (const k of allowed) if (k in b) patch[k] = b[k];

    // sync backward compat fields หากส่งชุดใหม่
    if ("plotName" in patch && !("name" in patch)) patch.name = patch.plotName;
    if ("caretaker" in patch && !("ownerName" in patch)) patch.ownerName = patch.caretaker;
    if ("plantType" in patch && !("cropType" in patch)) patch.cropType = patch.plantType;

    const doc = await Plot.findByIdAndUpdate(req.params.plotId, { $set: patch }, { new: true });
    if (!doc) return res.status(404).json({ message: "Plot not found" });

    res.json({ item: leanWithId(doc) });
  } catch (e) {
    next(e);
  }
});

// DELETE /api/plots/:plotId (cascade)
api.delete("/plots/:plotId", async (req, res, next) => {
  try {
    const plotId = req.params.plotId;

    // nodes -> sensors
    const nodeIds = (await NodeModel.find({ plotId }, { _id: 1 }).lean()).map((x) => String(x._id));
    const sensorIds = (await Sensor.find({ nodeId: { $in: nodeIds } }, { _id: 1 }).lean()).map((x) => String(x._id));

    await Reading.deleteMany({ sensorId: { $in: sensorIds } });
    await Sensor.deleteMany({ nodeId: { $in: nodeIds } });
    await NodeModel.deleteMany({ plotId });

    await Pin.deleteMany({ plotId });
    await Polygon.deleteMany({ plotId });
    await Note.deleteMany({ plotId });
    await Plot.findByIdAndDelete(plotId);

    res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ message: "Google auth failed", error: String(e.message || e) });
  }
});

// ==============================
// 3) polygons (1 polygon per plot)
// ==============================

api.get("/plots/:plotId/polygon", async (req, res, next) => {
  try {
    const plotId = req.params.plotId;
    const plot = await Plot.findById(plotId).lean();
    if (!plot) return res.status(404).json({ message: "Plot not found" });

    const item = await Polygon.findOne({ plotId }).lean();
    res.json({ item: item || null });
  } catch (e) {
    next(e);
  }
});

// PUT /api/plots/:plotId/polygon  { coords:[[lat,lng],...], color? }
api.put("/plots/:plotId/polygon", async (req, res, next) => {
  try {
    const plotId = req.params.plotId;
    const plot = await Plot.findById(plotId).lean();
    if (!plot) return res.status(404).json({ message: "Plot not found" });

    const { coords, color, polygonId } = req.body || {};
    if (!Array.isArray(coords) || coords.length < 3) {
      return res.status(400).json({ message: "coords must be array of [lat,lng] with length >= 3" });
    }
    for (const pt of coords) {
      if (!Array.isArray(pt) || pt.length !== 2) return res.status(400).json({ message: "coords must be [lat,lng]" });
      const lat = toNum(pt[0]);
      const lng = toNum(pt[1]);
      if (!isValidLatLng(lat, lng)) return res.status(400).json({ message: "invalid lat/lng in coords" });
    }

    const item = await Polygon.findOneAndUpdate(
      { plotId },
      { $set: { plotId, coords, color: color || "#2563eb", polygonId: polygonId || "" } },
      { upsert: true, new: true }
    ).lean();

    res.json({ item });
  } catch (e) {
    next(e);
  }
});

// ===== polygons (multi) =====
// GET /api/plots/:plotId/polygons  -> { items: [...] }
api.get("/plots/:plotId/polygons", async (req, res, next) => {
  try {
    const plotId = req.params.plotId;
    const plot = await Plot.findById(plotId).lean();
    if (!plot) return res.status(404).json({ message: "Plot not found" });

    const items = (await Polygon.find({ plotId }).sort({ createdAt: -1 }).lean()).map((x) => ({ ...x, id: String(x._id) }));

    res.json({ items });
  } catch (e) {
    next(e);
  }
});

// POST /api/plots/:plotId/polygons  (create new polygon)
api.post("/plots/:plotId/polygons", async (req, res, next) => {
  try {
    const plotId = req.params.plotId;
    const plot = await Plot.findById(plotId).lean();
    if (!plot) return res.status(404).json({ message: "Plot not found" });

    const { coords, coordinates, color, polygonId } = req.body || {};
    const pts = Array.isArray(coords) ? coords : coordinates;

    if (!Array.isArray(pts) || pts.length < 3) {
      return res.status(400).json({ message: "coords/coordinates must be array of [lat,lng] with length >= 3" });
    }
    for (const pt of pts) {
      if (!Array.isArray(pt) || pt.length !== 2) return res.status(400).json({ message: "coords must be [lat,lng]" });
      const lat = toNum(pt[0]);
      const lng = toNum(pt[1]);
      if (!isValidLatLng(lat, lng)) return res.status(400).json({ message: "invalid lat/lng in coords" });
    }

    const doc = await Polygon.create({
      plotId,
      polygonId: polygonId || undefined, // default in schema => randomUUID
      color: color || "#2563eb",
      coords: pts,
    });

    res.status(201).json({ item: { ...doc.toObject(), id: String(doc._id) } });
  } catch (e) {
    next(e);
  }
});

// PATCH /api/plots/:plotId/polygons  (backward compatible upsert: polygonId default "poly-1")
api.patch("/plots/:plotId/polygons", async (req, res, next) => {
  try {
    const plotId = req.params.plotId;
    const plot = await Plot.findById(plotId).lean();
    if (!plot) return res.status(404).json({ message: "Plot not found" });

    const { coords, coordinates, color, polygonId } = req.body || {};
    const pts = Array.isArray(coords) ? coords : coordinates;

    if (!Array.isArray(pts) || pts.length < 3) {
      return res.status(400).json({ message: "coords/coordinates must be array of [lat,lng] with length >= 3" });
    }
    for (const pt of pts) {
      if (!Array.isArray(pt) || pt.length !== 2) return res.status(400).json({ message: "coords must be [lat,lng]" });
      const lat = toNum(pt[0]);
      const lng = toNum(pt[1]);
      if (!isValidLatLng(lat, lng)) return res.status(400).json({ message: "invalid lat/lng in coords" });
    }

    const pid = polygonId || "poly-1";
    const item = await Polygon.findOneAndUpdate(
      { plotId, polygonId: pid },
      { $set: { plotId, polygonId: pid, coords: pts, color: color || "#2563eb" } },
      { upsert: true, new: true }
    );

    res.json({ item: { ...item.toObject(), id: String(item._id) } });
  } catch (e) {
    next(e);
  }
});

// PATCH /api/polygons/:id  (update one polygon by _id)
api.patch("/polygons/:id", async (req, res, next) => {
  try {
    const id = req.params.id;
    const { coords, coordinates, color } = req.body || {};
    const pts = Array.isArray(coords) ? coords : coordinates;

    const update = {};
    if (Array.isArray(pts)) update.coords = pts;
    if (typeof color === "string") update.color = color;

    const doc = await Polygon.findByIdAndUpdate(id, { $set: update }, { new: true }).lean();
    if (!doc) return res.status(404).json({ message: "Polygon not found" });

    res.json({ item: { ...doc, id: String(doc._id) } });
  } catch (e) {
    next(e);
  }
});

// DELETE /api/polygons/:id  (delete one polygon by _id)
api.delete("/polygons/:id", async (req, res, next) => {
  try {
    const id = req.params.id;
    await Polygon.deleteOne({ _id: id });
    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

// DELETE /api/plots/:plotId/polygons  (delete all)
api.delete("/plots/:plotId/polygons", async (req, res, next) => {
  try {
    const plotId = req.params.plotId;
    await Polygon.deleteMany({ plotId });
    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

// ==============================
// 4) nodes (สำหรับ dropdown Node และ filter nodeCategory)
// ==============================

// GET /api/nodes?plotId=&category=
api.get("/nodes", async (req, res, next) => {
  try {
    const { plotId, category } = req.query || {};
    const q = {};
    if (plotId) q.plotId = String(plotId);
    if (category && category !== "all") q.category = String(category);

    const items = (await NodeModel.find(q).sort({ createdAt: -1 })).map(leanWithId);
    res.json({ items });
  } catch (e) {
    next(e);
  }
});

// POST /api/nodes
api.post("/nodes", async (req, res, next) => {
  try {
    const b = req.body || {};
    if (!b.plotId) return res.status(400).json({ message: "plotId is required" });
    const plot = await Plot.findById(String(b.plotId)).lean();
    if (!plot) return res.status(404).json({ message: "Plot not found" });

    const doc = await NodeModel.create({
      plotId: String(b.plotId),
      category: b.category || "soil",
      name: b.name || "",
      firmware: b.firmware || "",
      lastSeen: b.lastSeen || null,
      status: b.status || "ONLINE",
    });
    res.status(201).json({ item: leanWithId(doc) });
  } catch (e) {
    next(e);
  }
});

// PATCH /api/nodes/:nodeId
api.patch("/nodes/:nodeId", async (req, res, next) => {
  try {
    const b = req.body || {};
    const allowed = ["category", "name", "firmware", "lastSeen", "status"];
    const patch = {};
    for (const k of allowed) if (k in b) patch[k] = b[k];

    const doc = await NodeModel.findByIdAndUpdate(req.params.nodeId, { $set: patch }, { new: true });
    if (!doc) return res.status(404).json({ message: "Node not found" });
    res.json({ item: leanWithId(doc) });
  } catch (e) {
    next(e);
  }
});

// DELETE /api/nodes/:nodeId (cascade sensors + readings)
api.delete("/nodes/:nodeId", async (req, res, next) => {
  try {
    const nodeId = req.params.nodeId;
    const sensorIds = (await Sensor.find({ nodeId }, { _id: 1 }).lean()).map((x) => String(x._id));
    await Reading.deleteMany({ sensorId: { $in: sensorIds } });
    await Sensor.deleteMany({ nodeId });
    await NodeModel.findByIdAndDelete(nodeId);
    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

// ==============================
// 5) pins (รองรับ 2 แบบ: /plots/:plotId/pins และ /pins?plotId=&nodeCategory=&sensorType=)
// ==============================

// GET /api/plots/:plotId/pins
api.get("/plots/:plotId/pins", async (req, res, next) => {
  try {
    const plotId = req.params.plotId;
    const plot = await Plot.findById(plotId).lean();
    if (!plot) return res.status(404).json({ message: "Plot not found" });

    const items = (await Pin.find({ plotId }).sort({ number: 1 })).map(leanWithId);
    res.json({ items });
  } catch (e) {
    next(e);
  }
});

// GET /api/pins?plotId=&nodeCategory=&sensorType=
api.get("/pins", async (req, res, next) => {
  try {
    const { plotId, nodeCategory, sensorType, nodeId } = req.query || {};
    const q = {};
    if (plotId) q.plotId = String(plotId);

    let pins = (await Pin.find(q).sort({ number: 1 }).lean()).map((p) => ({ ...p, id: String(p._id) }));

    // filter by nodeId (ตาม requirement: GET /pins?plotId=&nodeId=)
    if (nodeId && String(nodeId).trim()) {
      pins = pins.filter((p) => p.nodeId && String(p.nodeId) === String(nodeId));
    }

    // filter by nodeCategory (air/soil)
    if (nodeCategory && nodeCategory !== "all") {
      const nodes = await NodeModel.find({ plotId: String(plotId), category: String(nodeCategory) }, { _id: 1 }).lean();
      const nodeSet = new Set(nodes.map((n) => String(n._id)));
      pins = pins.filter((p) => p.nodeId && nodeSet.has(String(p.nodeId)));
    }

    // filter by sensorType (ถ้าต้องการให้ map แสดงเฉพาะ pin ที่มี sensorType นั้น)
    if (sensorType && sensorType !== "all") {
      // เอา nodeIds ของ pins แล้วหา sensors ใน node นั้นๆ
      const nodeIds = [...new Set(pins.map((p) => String(p.nodeId)).filter(Boolean))];
      const nodesSensors = await Sensor.find({ nodeId: { $in: nodeIds }, sensorType: String(sensorType) }, { nodeId: 1 }).lean();
      const okNode = new Set(nodesSensors.map((s) => String(s.nodeId)));
      pins = pins.filter((p) => p.nodeId && okNode.has(String(p.nodeId)));
    }

    res.json({ items: pins });
  } catch (e) {
    next(e);
  }
});

// Add pin (requirement: POST /pins)
api.post("/pins", async (req, res, next) => {
  try {
    const { plotId, nodeId, lat, lng } = req.body || {};
    if (!plotId) return res.status(400).json({ message: "plotId is required" });

    const la = toNum(lat);
    const lo = toNum(lng);
    if (la === null || lo === null) return res.status(400).json({ message: "lat, lng are required" });
    if (!isValidLatLng(la, lo)) return res.status(400).json({ message: "invalid lat/lng" });

    const plot = await Plot.findById(String(plotId)).lean();
    if (!plot) return res.status(404).json({ message: "Plot not found" });

    // ✅ nodeId optional: ถ้าไม่ส่งมา -> ใช้/สร้าง Node ดินให้แปลงนี้
    let nodeIdToUse = nodeId ? String(nodeId) : "";
    if (!nodeIdToUse) {
      const found = await NodeModel.findOne({ plotId: String(plotId), category: "soil" }).lean();
      if (found) nodeIdToUse = String(found._id);
      else {
        const createdNode = await NodeModel.create({
          plotId: String(plotId),
          category: "soil",
          name: "Node ดิน",
          status: "ONLINE",
        });
        nodeIdToUse = String(createdNode._id);
      }
    }

    const node = await NodeModel.findById(String(nodeIdToUse)).lean();
    if (!node) return res.status(404).json({ message: "Node not found" });
    if (String(node.plotId) !== String(plotId)) return res.status(400).json({ message: "nodeId does not belong to plotId" });

    // ✅ หาเลขว่างตัวแรกของ plot นี้แบบชัวร์ (กัน last เพี้ยน + กัน race)
    let n = 1;
    const last = await Pin.findOne({ plotId: String(plotId) }).sort({ number: -1 }).lean();
    if (last && typeof last.number === "number") n = last.number + 1;

    while (await Pin.exists({ plotId: String(plotId), number: n })) n += 1;

    for (let attempt = 0; attempt < 50; attempt += 1) {
      try {
        const created = await Pin.create({
          plotId: String(plotId),
          nodeId: String(nodeIdToUse),
          number: n,
          lat: la,
          lng: lo,
        });
        return res.status(201).json({ item: leanWithId(created) });
      } catch (e) {
        const msg = String(e?.message || e);
        if (!msg.includes("E11000")) throw e;
        n += 1;
      }
    }

    return res.status(409).json({ message: "Pin number already exists in this plot" });
  } catch (e) {
    next(e);
  }
});

// DELETE /api/pins?plotId=&nodeCategory=&sensorType=  (delete pins by scope - requirement)
api.delete("/pins", async (req, res, next) => {
  try {
    const { plotId, nodeCategory, sensorType, nodeId } = req.query || {};
    if (!plotId) return res.status(400).json({ message: "plotId is required" });

    // reuse same filtering logic as GET /pins
    const q = { plotId: String(plotId) };
    let pins = await Pin.find(q).sort({ number: 1 }).lean();

    if (nodeCategory && nodeCategory !== "all") {
      const nodes = await NodeModel.find({ plotId: String(plotId), category: String(nodeCategory) }, { _id: 1 }).lean();
      const nodeSet = new Set(nodes.map((n) => String(n._id)));
      pins = pins.filter((p) => p.nodeId && nodeSet.has(String(p.nodeId)));
    }

    if (sensorType && sensorType !== "all") {
      const nodeIds = [...new Set(pins.map((p) => String(p.nodeId)).filter(Boolean))];
      const nodesSensors = await Sensor.find({ nodeId: { $in: nodeIds }, sensorType: String(sensorType) }, { nodeId: 1 }).lean();
      const okNode = new Set(nodesSensors.map((s) => String(s.nodeId)));
      pins = pins.filter((p) => p.nodeId && okNode.has(String(p.nodeId)));
    }

    const pinIds = pins.map((p) => String(p._id));

    // cascade: readings -> sensors -> pins
    const sensorIds = (await Sensor.find({ pinId: { $in: pinIds } }, { _id: 1 }).lean()).map((x) => String(x._id));
    await Reading.deleteMany({ sensorId: { $in: sensorIds } });
    await Sensor.deleteMany({ pinId: { $in: pinIds } });
    await Pin.deleteMany({ _id: { $in: pinIds } });

    res.json({ ok: true, deletedPins: pinIds.length });
  } catch (e) {
    next(e);
  }
});

// POST /api/plots/:plotId/pins
api.post("/plots/:plotId/pins", async (req, res, next) => {
  try {
    const plotId = req.params.plotId;
    const plot = await Plot.findById(plotId).lean();
    if (!plot) return res.status(404).json({ message: "Plot not found" });

    const { number, lat, lng, nodeId } = req.body || {};
    const n = toNum(number);
    const la = toNum(lat);
    const lo = toNum(lng);
    if (!n || la === null || lo === null) return res.status(400).json({ message: "number, lat, lng are required" });
    if (!isValidLatLng(la, lo)) return res.status(400).json({ message: "invalid lat/lng" });

    // ถ้ามี nodeId ให้ validate
    if (nodeId) {
      const node = await NodeModel.findById(String(nodeId)).lean();
      if (!node) return res.status(404).json({ message: "Node not found" });
      if (String(node.plotId) !== String(plotId)) return res.status(400).json({ message: "nodeId does not belong to plot" });
    }

    const doc = await Pin.create({ plotId, nodeId: nodeId ? String(nodeId) : null, number: n, lat: la, lng: lo });
    res.status(201).json({ item: leanWithId(doc) });
  } catch (e) {
    const msg = String(e.message || e);
    if (msg.includes("E11000")) return res.status(409).json({ message: "Pin number already exists in this plot" });
    next(e);
  }
});

// GET /api/pins/:pinId
api.get("/pins/:pinId", async (req, res, next) => {
  try {
    const pinId = req.params.pinId;
    if (!isValidObjectId(pinId)) return res.status(400).json({ message: "Invalid pinId" });
    const pin = await Pin.findById(pinId).lean();
    if (!pin) return res.status(404).json({ message: "Pin not found" });
    res.json({ item: leanWithId(pin) });
  } catch (e) {
    next(e);
  }
});

// PATCH /api/pins/:pinId
api.patch("/pins/:pinId", async (req, res, next) => {
  try {
    const pinId = req.params.pinId;

    if (!isValidObjectId(pinId)) return res.status(400).json({ message: "Invalid pinId" });
    const pin = await Pin.findById(pinId);
    if (!pin) return res.status(404).json({ message: "Pin not found" });

    const { number, lat, lng, nodeId } = req.body || {};
    const patch = {};
    if (number !== undefined) patch.number = toNum(number);
    if (lat !== undefined) patch.lat = toNum(lat);
    if (lng !== undefined) patch.lng = toNum(lng);
    if (nodeId !== undefined) patch.nodeId = nodeId ? String(nodeId) : null;

    if ("lat" in patch || "lng" in patch) {
      const la = "lat" in patch ? patch.lat : pin.lat;
      const lo = "lng" in patch ? patch.lng : pin.lng;
      if (!isValidLatLng(la, lo)) return res.status(400).json({ message: "invalid lat/lng" });
    }
    if ("nodeId" in patch && patch.nodeId) {
      const node = await NodeModel.findById(patch.nodeId).lean();
      if (!node) return res.status(404).json({ message: "Node not found" });
      if (String(node.plotId) !== String(pin.plotId)) return res.status(400).json({ message: "nodeId does not belong to plot" });
    }

    const doc = await Pin.findByIdAndUpdate(pinId, { $set: patch }, { new: true });
    res.json({ item: leanWithId(doc) });
  } catch (e) {
    next(e);
  }
});

// DELETE /api/pins/:pinId
api.delete("/pins/:pinId", async (req, res, next) => {
  try {
    const pinId = req.params.pinId;

    if (!isValidObjectId(pinId)) return res.status(400).json({ message: "Invalid pinId" });
    const pin = await Pin.findById(pinId).lean();
    if (!pin) return res.status(404).json({ message: "Pin not found" });

    // ถ้า sensor ผูกกับ pinId -> ลบ sensor + reading ด้วย (ปลอดภัยไว้ก่อน)
    const sensors = await Sensor.find({ pinId }, { _id: 1 }).lean();
    const sensorIds = sensors.map((s) => String(s._id));
    await Reading.deleteMany({ sensorId: { $in: sensorIds } });
    await Sensor.deleteMany({ pinId });

    await Pin.findByIdAndDelete(pinId);
    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

// DELETE /api/plots/:plotId/pins  (ลบทั้งหมดใน plot)
api.delete("/plots/:plotId/pins", async (req, res, next) => {
  try {
    const plotId = req.params.plotId;
    const plot = await Plot.findById(plotId).lean();
    if (!plot) return res.status(404).json({ message: "Plot not found" });

    const pins = await Pin.find({ plotId }, { _id: 1 }).lean();
    const pinIds = pins.map((p) => String(p._id));

    const sensors = await Sensor.find({ pinId: { $in: pinIds } }, { _id: 1 }).lean();
    const sensorIds = sensors.map((s) => String(s._id));

    await Reading.deleteMany({ sensorId: { $in: sensorIds } });
    await Sensor.deleteMany({ pinId: { $in: pinIds } });
    await Pin.deleteMany({ plotId });

    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

// ==============================
// 6) sensors
// ==============================

// GET /api/pins/:pinId/sensors  (backward compat)
api.get("/pins/:pinId/sensors", async (req, res, next) => {
  try {
    const pinId = req.params.pinId;
    const pin = await Pin.findById(pinId).lean();
    if (!pin) return res.status(404).json({ message: "Pin not found" });

    const items = (await Sensor.find({ pinId }).sort({ createdAt: -1 })).map(leanWithId);
    res.json({ items });
  } catch (e) {
    next(e);
  }
});

// GET /api/sensors?plotId=&nodeCategory=&sensorType=
api.get("/sensors", async (req, res, next) => {
  try {
    const { plotId, nodeCategory, sensorType, nodeId } = req.query || {};
    const q = {};

    if (nodeId) {
      q.nodeId = String(nodeId);
    } else if (plotId) {
      const nq = { plotId: String(plotId) };
      if (nodeCategory && nodeCategory !== "all") nq.category = String(nodeCategory);
      const nodes = await NodeModel.find(nq, { _id: 1 }).lean();
      q.nodeId = { $in: nodes.map((n) => String(n._id)) };
    }

    if (sensorType && sensorType !== "all") q.sensorType = String(sensorType);

    const docs = await Sensor.find(q).sort({ createdAt: -1 });
    res.json({ items: docs.map(leanWithId) });
  } catch (e) {
    next(e);
  }
});

// POST /api/pins/:pinId/sensors (backward compat)  { typeKey|sensorType, name }
api.post("/pins/:pinId/sensors", async (req, res, next) => {
  try {
    const pinId = req.params.pinId;
    const pin = await Pin.findById(pinId).lean();
    if (!pin) return res.status(404).json({ message: "Pin not found" });

    const b = req.body || {};
    const sensorType = b.sensorType || b.typeKey;
    if (!sensorType) return res.status(400).json({ message: "sensorType (or typeKey) is required" });

    // ต้องมี nodeId อย่างน้อย (ตามเอกสาร) ถ้า pin ไม่มี nodeId ให้สร้าง node แบบ default
    let nodeId = pin.nodeId;
    if (!nodeId) {
      const auto = await NodeModel.create({ plotId: String(pin.plotId), category: "soil", name: "Auto Node" });
      nodeId = String(auto._id);
      await Pin.findByIdAndUpdate(pinId, { $set: { nodeId } });
    }

    const st = SENSOR_TYPES.find((t) => t.key === sensorType);
    const unit = b.unit || (st ? st.unit : "");

    const doc = await Sensor.create({
      nodeId: String(nodeId),
      pinId: String(pinId),
      sensorType,
      name: b.name || (st ? st.label : sensorType),
      unit,
      valueHint: b.valueHint || "",
      status: b.status || "OK",
      lastReading: b.lastReading || { value: null, ts: null },
    });

    res.status(201).json({ item: leanWithId(doc) });
  } catch (e) {
    next(e);
  }
});

// POST /api/sensors  (ตามเอกสาร) { nodeId, sensorType, name, unit?, pinId? }
api.post("/sensors", async (req, res, next) => {
  try {
    const b = req.body || {};
    if (!b.nodeId) return res.status(400).json({ message: "nodeId is required" });
    if (!b.sensorType) return res.status(400).json({ message: "sensorType is required" });

    const node = await NodeModel.findById(String(b.nodeId)).lean();
    if (!node) return res.status(404).json({ message: "Node not found" });

    const st = SENSOR_TYPES.find((t) => t.key === b.sensorType);
    const doc = await Sensor.create({
      nodeId: String(b.nodeId),
      pinId: b.pinId ? String(b.pinId) : null,
      sensorType: b.sensorType,
      name: b.name || (st ? st.label : b.sensorType),
      unit: b.unit || (st ? st.unit : ""),
      valueHint: b.valueHint || "",
      status: b.status || "OK",
      lastReading: b.lastReading || { value: null, ts: null },
    });

    res.status(201).json({ item: leanWithId(doc) });
  } catch (e) {
    next(e);
  }
});

// GET /api/sensors/:sensorId
api.get("/sensors/:sensorId", async (req, res, next) => {
  try {
    const sensorId = req.params.sensorId;
    if (!isValidObjectId(sensorId)) return res.status(400).json({ message: "Invalid sensorId" });
    const s = await Sensor.findById(sensorId).lean();
    if (!s) return res.status(404).json({ message: "Sensor not found" });
    res.json({ item: leanWithId(s) });
  } catch (e) {
    next(e);
  }
});

// PATCH /api/sensors/:sensorId
api.patch("/sensors/:sensorId", async (req, res, next) => {
  try {
    const sensorId = req.params.sensorId;
    const sensor = await Sensor.findById(sensorId);
    if (!sensor) return res.status(404).json({ message: "Sensor not found" });

    const b = req.body || {};
    const patch = {};
    const allowed = ["name", "sensorType", "unit", "valueHint", "status", "pinId", "nodeId", "lastReading"];
    for (const k of allowed) if (k in b) patch[k] = b[k];

    // validate nodeId if changed
    if ("nodeId" in patch) {
      const node = await NodeModel.findById(String(patch.nodeId)).lean();
      if (!node) return res.status(404).json({ message: "Node not found" });
      patch.nodeId = String(patch.nodeId);
    }
    if ("pinId" in patch) patch.pinId = patch.pinId ? String(patch.pinId) : null;

    const doc = await Sensor.findByIdAndUpdate(sensorId, { $set: patch }, { new: true });
    res.json({ item: leanWithId(doc) });
  } catch (e) {
    next(e);
  }
});

// DELETE /api/sensors/:sensorId
api.delete("/sensors/:sensorId", async (req, res, next) => {
  try {
    const sensorId = req.params.sensorId;
    const sensor = await Sensor.findById(sensorId).lean();
    if (!sensor) return res.status(404).json({ message: "Sensor not found" });

    await Reading.deleteMany({ sensorId });
    await Sensor.findByIdAndDelete(sensorId);
    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

// ==============================
// 7) notes (หน้า AddPlantingPlots)
// ==============================

// GET /api/plots/:plotId/notes
api.get("/plots/:plotId/notes", async (req, res, next) => {
  try {
    const plotId = req.params.plotId;
    const plot = await Plot.findById(plotId).lean();
    if (!plot) return res.status(404).json({ message: "Plot not found" });

    const items = (await Note.find({ plotId }).sort({ updatedAt: -1 })).map(leanWithId);
    res.json({ items });
  } catch (e) {
    next(e);
  }
});

// POST /api/plots/:plotId/notes
api.post("/plots/:plotId/notes", async (req, res, next) => {
  try {
    const plotId = req.params.plotId;
    const plot = await Plot.findById(plotId).lean();
    if (!plot) return res.status(404).json({ message: "Plot not found" });

    const b = req.body || {};
    if (!b.topic) return res.status(400).json({ message: "topic is required" });

    const doc = await Note.create({
      plotId,
      topic: b.topic,
      content: b.content || "",
      author: b.author || "",
      updatedBy: req.user?.email || "",
    });

    res.status(201).json({ item: leanWithId(doc) });
  } catch (e) {
    next(e);
  }
});

// PATCH /api/notes/:noteId
api.patch("/notes/:noteId", async (req, res, next) => {
  try {
    const noteId = req.params.noteId;
    const b = req.body || {};
    const patch = {};
    const allowed = ["topic", "content", "author"];
    for (const k of allowed) if (k in b) patch[k] = b[k];
    patch.updatedBy = req.user?.email || "";

    const doc = await Note.findByIdAndUpdate(noteId, { $set: patch }, { new: true });
    if (!doc) return res.status(404).json({ message: "Note not found" });
    res.json({ item: leanWithId(doc) });
  } catch (e) {
    next(e);
  }
});

// DELETE /api/notes/:noteId
api.delete("/notes/:noteId", async (req, res, next) => {
  try {
    const noteId = req.params.noteId;
    const doc = await Note.findByIdAndDelete(noteId).lean();
    if (!doc) return res.status(404).json({ message: "Note not found" });
    res.json({ ok: true });
  } catch (e) {
    if (e.statusCode) {
      return res.status(e.statusCode).json({ message: e.message });
    }
    next(e);
  }
});

// ==============================
// 8) readings/history (ของเดิม)
// ==============================

// POST /api/readings  { sensorId, ts?, value, status?, raw? }
api.post("/readings", async (req, res, next) => {
  try {
    const { sensorId, ts, value, status, raw } = req.body || {};
    const s = await Sensor.findById(String(sensorId)).lean();
    if (!s) return res.status(404).json({ message: "Sensor not found" });

    const v = toNum(value);
    if (v === null || Number.isNaN(v)) return res.status(400).json({ message: "value must be number" });

    const readingTs = ts || new Date().toISOString();
    const readingStatus = status || "OK";

    // 1) INSERT history
    const item = await Reading.create({
      sensorId: String(sensorId),
      nodeId: s.nodeId || null,
      pinId: s.pinId || null,
      ts: readingTs,
      value: v,
      status: readingStatus,
      raw: raw || undefined,
    });

    // 2) UPDATE lastReading (เฉพาะถ้า ts ใหม่กว่าเดิม)
    const prevTs = s?.lastReading?.ts ? new Date(s.lastReading.ts).getTime() : null;
    const nextTs = new Date(readingTs).getTime();
    if (!prevTs || (Number.isFinite(nextTs) && nextTs >= prevTs)) {
      await Sensor.findByIdAndUpdate(String(sensorId), {
        $set: { lastReading: { value: v, ts: readingTs }, status: readingStatus },
      });
    }

    res.status(201).json({ item: leanWithId(item) });
  } catch (e) {
    next(e);
  }
});

// GET /api/readings?plotId=&pinId=&sensorType=...&from=&to=
api.get("/readings", async (req, res, next) => {
  try {
    const { plotId, pinId, sensorType, from, to } = req.query || {};
    const q = {};

    // resolve sensorIds
    let sensorIds = [];

    if (pinId) {
      sensorIds = (await Sensor.find({ pinId: String(pinId) }, { _id: 1 }).lean()).map((x) => String(x._id));
    } else if (plotId) {
      // nodes in plot -> sensors
      const nodeIds = (await NodeModel.find({ plotId: String(plotId) }, { _id: 1 }).lean()).map((x) => String(x._id));
      const sq = { nodeId: { $in: nodeIds } };
      if (sensorType && sensorType !== "all") sq.sensorType = String(sensorType);
      sensorIds = (await Sensor.find(sq, { _id: 1 }).lean()).map((x) => String(x._id));
    }

    if (sensorIds.length) q.sensorId = { $in: sensorIds };
    if (from) q.ts = { ...(q.ts || {}), $gte: new Date(from).toISOString() };
    if (to) q.ts = { ...(q.ts || {}), $lte: new Date(to).toISOString() };

    const items = (await Reading.find(q).sort({ ts: 1 }).lean()).map((r) => ({ ...r, id: String(r._id) }));
    res.json({ items });
  } catch (e) {
    next(e);
  }
});

// GET /api/plots/:plotId/summary  (สรุป min/max/avg ล่าสุด)
api.get("/plots/:plotId/summary", async (req, res, next) => {
  try {
    const plotId = req.params.plotId;
    const plot = await Plot.findById(plotId).lean();
    if (!plot) return res.status(404).json({ message: "Plot not found" });

    const nodeIds = (await NodeModel.find({ plotId }, { _id: 1 }).lean()).map((x) => String(x._id));
    const sensors = await Sensor.find({ nodeId: { $in: nodeIds } }).lean();

    const items = [];
    for (const s of sensors) {
      const rs = await Reading.find({ sensorId: String(s._id) }).sort({ ts: 1 }).lean();
      if (!rs.length) continue;

      const values = rs.map((x) => x.value);
      const min = Math.min(...values);
      const max = Math.max(...values);
      const avg = values.reduce((sum, v) => sum + v, 0) / values.length;
      const last = rs[rs.length - 1];

      items.push({
        sensorId: String(s._id),
        sensorType: s.sensorType,
        name: s.name,
        unit: s.unit,
        min,
        max,
        avg,
        last: last.value,
        lastAt: last.ts,
      });
    }

    res.json({ plotId, items });
  } catch (e) {
    next(e);
  }
});

// GET /api/export/readings.csv
api.get("/export/readings.csv", async (req, res, next) => {
  try {
    const { plotId, from, to } = req.query || {};

    const nodeIds = plotId
      ? (await NodeModel.find({ plotId: String(plotId) }, { _id: 1 }).lean()).map((x) => String(x._id))
      : (await NodeModel.find({}, { _id: 1 }).lean()).map((x) => String(x._id));

    const sensors = await Sensor.find({ nodeId: { $in: nodeIds } }).lean();
    const sensorIds = sensors.map((s) => String(s._id));

    const q = { sensorId: { $in: sensorIds } };
    if (from) q.ts = { ...(q.ts || {}), $gte: new Date(from).toISOString() };
    if (to) q.ts = { ...(q.ts || {}), $lte: new Date(to).toISOString() };

    const readings = await Reading.find(q).sort({ ts: 1 }).lean();

    // maps
    const sensorMap = new Map(sensors.map((s) => [String(s._id), s]));
    const plotMap = new Map((await Plot.find().lean()).map((p) => [String(p._id), p]));

    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", 'attachment; filename="readings.csv"');
    res.write("\ufeff");

    const header = ["ts", "plotId", "plotName", "sensorId", "sensorType", "sensorName", "value", "unit"];
    res.write(header.join(",") + "\n");

    for (const r of readings) {
      const s = sensorMap.get(String(r.sensorId));
      const node = s ? await NodeModel.findById(String(s.nodeId)).lean() : null;
      const plot = node ? plotMap.get(String(node.plotId)) : null;
      const row = {
        ts: r.ts,
        plotId: plot ? String(plot._id) : "",
        plotName: plot?.plotName || plot?.name || "",
        sensorId: String(r.sensorId),
        sensorType: s?.sensorType || "",
        sensorName: s?.name || "",
        value: r.value,
        unit: s?.unit || "",
      };
      const line = header
        .map((k) => String(row[k] ?? "").replaceAll('"', '""'))
        .map((v) => `"${v}"`)
        .join(",");
      res.write(line + "\n");
    }

    res.end();
  } catch (e) {
    next(e);
  }
});

// 9) dashboard / weather (ของเดิม – ทำเป็น placeholder ได้)
api.get("/dashboard/overview", async (req, res) => {
  const { plotId } = req.query;
  const pinCount = plotId ? await Pin.countDocuments({ plotId: String(plotId) }) : await Pin.countDocuments({});
  res.json({ plotId: plotId || "all", on: pinCount, off: 0, issues: 0 });
});

api.get("/dashboard/pins", async (req, res) => {
  const { plotId } = req.query;
  const pins = plotId
    ? await Pin.find({ plotId: String(plotId) }).sort({ number: 1 }).lean()
    : await Pin.find().sort({ number: 1 }).lean();
  res.json({ items: pins.map((p) => ({ ...p, id: String(p._id) })) });
});

api.get("/weather/forecast", (req, res) => {
  res.json({
    provider: "mock",
    days: [
      { day: "จันทร์", temp: 32, rainChance: 40 },
      { day: "อังคาร", temp: 31, rainChance: 60 },
      { day: "พุธ", temp: 30, rainChance: 80 },
      { day: "พฤหัส", temp: 32, rainChance: 20 },
      { day: "ศุกร์", temp: 34, rainChance: 10 },
      { day: "เสาร์", temp: 31, rainChance: 50 },
      { day: "อาทิตย์", temp: 32, rainChance: 30 },
    ],
  });
});

// attach router
app.use("/api", api);

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({
    message: "Internal Server Error",
    error: String(err.message || err),
  });
});

const PORT = Number(process.env.PORT || 3001);
app.listen(PORT, () => {
  console.log(`[API] running on port ${PORT}`);
});