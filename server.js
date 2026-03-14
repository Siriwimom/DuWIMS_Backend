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

const BUILD_TAG = "mongo-node-template-v1-fixed";

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

function isValidObjectId(value) {
  return mongoose.isValidObjectId(value);
}

function parseObjectId(value) {
  if (!isValidObjectId(value)) return null;
  return new mongoose.Types.ObjectId(String(value));
}

function requireObjectId(res, value, fieldName) {
  if (!isValidObjectId(value)) {
    res.status(400).json({ message: `Invalid ${fieldName}` });
    return null;
  }
  return new mongoose.Types.ObjectId(String(value));
}

function leanWithId(doc) {
  if (!doc) return null;
  const obj = typeof doc.toObject === "function" ? doc.toObject() : { ...doc };
  obj.id = String(obj._id);
  return obj;
}

function normalizeTopics(topics) {
  if (!Array.isArray(topics)) return [];
  return topics
    .map((x) => ({
      topic: String(x?.topic || x?.Topic || "").trim(),
      description: String(
        x?.description || x?.Description || x?.content || ""
      ).trim(),
    }))
    .filter((x) => x.topic || x.description);
}

function normalizeCoords(coords) {
  if (!Array.isArray(coords)) return [];
  return coords
    .map((pair) => {
      if (!Array.isArray(pair) || pair.length < 2) return null;
      const lat = Number(pair[0]);
      const lng = Number(pair[1]);
      if (!Number.isFinite(lat) || !Number.isFinite(lng)) return null;
      return [lat, lng];
    })
    .filter(Boolean);
}

function normalizeSensor(sensor = {}) {
  return {
    _id:
      sensor._id && isValidObjectId(sensor._id)
        ? new mongoose.Types.ObjectId(String(sensor._id))
        : new mongoose.Types.ObjectId(),
    sensorType: String(sensor.sensorType || "").trim(),
    name: String(sensor.name || "").trim(),
    unit: String(sensor.unit || "").trim(),
    value: sensor.value ?? null,
    valueHint: sensor.valueHint ?? "",
    status: String(sensor.status || "OK"),
    lastReadingAt: sensor.lastReadingAt || sensor?.lastReading?.ts || null,
    lastReading: sensor.lastReading
      ? {
          value: sensor.lastReading.value ?? null,
          ts: sensor.lastReading.ts || null,
        }
      : {
          value: sensor.value ?? null,
          ts: sensor.lastReadingAt || null,
        },
  };
}

function normalizeNode(node = {}) {
  return {
    _id:
      node._id && isValidObjectId(node._id)
        ? new mongoose.Types.ObjectId(String(node._id))
        : new mongoose.Types.ObjectId(),
    sensors: Array.isArray(node.sensors) ? node.sensors.map(normalizeSensor) : [],
  };
}

function normalizePin(pin = {}, index = 0) {
  return {
    _id:
      pin._id && isValidObjectId(pin._id)
        ? new mongoose.Types.ObjectId(String(pin._id))
        : new mongoose.Types.ObjectId(),
    number: Number.isFinite(Number(pin.number)) ? Number(pin.number) : index + 1,
    lat: Number(pin.lat ?? 0),
    lng: Number(pin.lng ?? 0),
    nodeId:
      pin.nodeId && isValidObjectId(pin.nodeId)
        ? new mongoose.Types.ObjectId(String(pin.nodeId))
        : null,
    nodeName: String(pin.nodeName || "").trim(),
    createdAt: pin.createdAt || new Date(),
    updatedAt: new Date(),
  };
}

function normalizePolygon(polygon = {}) {
  return {
    _id:
      polygon._id && isValidObjectId(polygon._id)
        ? new mongoose.Types.ObjectId(String(polygon._id))
        : new mongoose.Types.ObjectId(),
    color: String(polygon.color || "#2563eb"),
    coords: normalizeCoords(polygon.coords || polygon.coordinates || []),
    pins: Array.isArray(polygon.pins) ? polygon.pins.map(normalizePin) : [],
  };
}

/* =========================
   SCHEMAS
========================= */

const SensorSubSchema = new mongoose.Schema(
  {
    sensorType: { type: String, required: true, trim: true },
    name: { type: String, default: "", trim: true },
    unit: { type: String, default: "", trim: true },
    value: { type: mongoose.Schema.Types.Mixed, default: null },
    valueHint: { type: mongoose.Schema.Types.Mixed, default: "" },
    status: { type: String, default: "OK" },
    lastReadingAt: { type: String, default: null },
    lastReading: {
      value: { type: mongoose.Schema.Types.Mixed, default: null },
      ts: { type: String, default: null },
    },
  },
  { _id: true }
);

const NodeSubSchema = new mongoose.Schema(
  {
    sensors: { type: [SensorSubSchema], default: [] },
  },
  { _id: true }
);

const NodeTemplateSchema = new mongoose.Schema(
  {
    nodeName: { type: String, required: true, trim: true, unique: true },
    node_soil: { type: NodeSubSchema, default: () => ({ sensors: [] }) },
    node_air: { type: NodeSubSchema, default: () => ({ sensors: [] }) },
    status: { type: String, default: "ACTIVE" },
  },
  { timestamps: true }
);

const PinSubSchema = new mongoose.Schema(
  {
    number: { type: Number, default: 1 },
    lat: { type: Number, default: 0 },
    lng: { type: Number, default: 0 },
    nodeId: { type: mongoose.Schema.Types.ObjectId, ref: "NodeTemplate", default: null },
    nodeName: { type: String, default: "", trim: true },
  },
  { _id: true, timestamps: true }
);

const PolygonSubSchema = new mongoose.Schema(
  {
    color: { type: String, default: "#2563eb" },
    coords: { type: [[Number]], default: [] },
    pins: { type: [PinSubSchema], default: [] },
  },
  { _id: true }
);

const TopicSubSchema = new mongoose.Schema(
  {
    topic: { type: String, default: "", trim: true },
    description: { type: String, default: "", trim: true },
  },
  { _id: true }
);

const PlotSchema = new mongoose.Schema(
  {
    alias: { type: String, default: "", trim: true },
    plotName: { type: String, required: true, trim: true },
    caretaker: { type: String, default: "", trim: true },
    plantType: { type: String, default: "", trim: true },
    plantedAt: { type: String, default: "" },
    status: { type: String, default: "ACTIVE" },

    name: { type: String, default: "", trim: true },
    cropType: { type: String, default: "", trim: true },
    ownerName: { type: String, default: "", trim: true },

    topics: { type: [TopicSubSchema], default: [] },
    polygon: {
      type: PolygonSubSchema,
      default: () => ({ color: "#2563eb", coords: [], pins: [] }),
    },
  },
  { timestamps: true }
);

const ReadingSchema = new mongoose.Schema(
  {
    plotId: { type: mongoose.Schema.Types.ObjectId, ref: "Plot", required: true },
    pinId: { type: mongoose.Schema.Types.ObjectId, required: true },
    nodeId: { type: mongoose.Schema.Types.ObjectId, ref: "NodeTemplate", required: true },
    nodeType: { type: String, enum: ["soil", "air"], required: true },
    sensorId: { type: mongoose.Schema.Types.ObjectId, required: true },
    sensorType: { type: String, required: true },
    ts: { type: String, required: true },
    value: { type: Number, required: true },
    status: { type: String, default: "OK" },
    raw: { type: mongoose.Schema.Types.Mixed, default: undefined },
  },
  { timestamps: true }
);

ReadingSchema.index({ plotId: 1 });
ReadingSchema.index({ pinId: 1 });
ReadingSchema.index({ nodeId: 1 });
ReadingSchema.index({ sensorId: 1 });
ReadingSchema.index({ sensorType: 1 });
ReadingSchema.index({ ts: 1 });

const Plot = mongoose.models.Plot || mongoose.model("Plot", PlotSchema);
const NodeTemplate =
  mongoose.models.NodeTemplate || mongoose.model("NodeTemplate", NodeTemplateSchema);
const Reading =
  mongoose.models.SensorReading || mongoose.model("SensorReading", ReadingSchema);

/* =========================
   HELPERS
========================= */

async function findPlotByPinId(pinId) {
  if (!isValidObjectId(pinId)) return null;

  const plot = await Plot.findOne({
    "polygon.pins._id": new mongoose.Types.ObjectId(String(pinId)),
  }).lean();

  if (!plot) return null;

  const pin = plot?.polygon?.pins?.find((p) => String(p._id) === String(pinId));
  return { plot, pin };
}

async function getNodeTemplateById(nodeId) {
  if (!isValidObjectId(nodeId)) return null;
  return NodeTemplate.findById(new mongoose.Types.ObjectId(String(nodeId))).lean();
}

async function getNodeTemplateForPin(pin) {
  if (!pin?.nodeId) return null;
  return getNodeTemplateById(pin.nodeId);
}

function findSensorByIdInNode(nodeDoc, sensorId) {
  const soilSensors = nodeDoc?.node_soil?.sensors || [];
  const airSensors = nodeDoc?.node_air?.sensors || [];

  const soil = soilSensors.find((s) => String(s._id) === String(sensorId));
  if (soil) return { nodeType: "soil", sensor: soil };

  const air = airSensors.find((s) => String(s._id) === String(sensorId));
  if (air) return { nodeType: "air", sensor: air };

  return null;
}

function enrichPinWithNode(pin, nodeDoc) {
  return {
    ...pin,
    nodeId: pin?.nodeId ? String(pin.nodeId) : null,
    nodeName: pin?.nodeName || nodeDoc?.nodeName || "",
    node_soil: nodeDoc?.node_soil || { sensors: [] },
    node_air: nodeDoc?.node_air || { sensors: [] },
  };
}

async function createReadingAndUpdateNode({
  pinId,
  sensorId,
  value,
  ts,
  status,
  raw,
}) {
  const pinOid = parseObjectId(pinId);
  if (!pinOid) throw new Error("Invalid pinId");

  const sensorOid = parseObjectId(sensorId);
  if (!sensorOid) throw new Error("Invalid sensorId");

  const found = await findPlotByPinId(String(pinOid));
  if (!found?.pin) {
    const err = new Error("Pin not found");
    err.statusCode = 404;
    throw err;
  }

  const nodeDoc = await getNodeTemplateForPin(found.pin);
  if (!nodeDoc) {
    const err = new Error("NodeTemplate not found for pin");
    err.statusCode = 404;
    throw err;
  }

  const match = findSensorByIdInNode(nodeDoc, String(sensorOid));
  if (!match?.sensor) {
    const err = new Error("Sensor not found");
    err.statusCode = 404;
    throw err;
  }

  const num = Number(value);
  if (!Number.isFinite(num)) {
    const err = new Error("value must be number");
    err.statusCode = 400;
    throw err;
  }

  const readingTs = ts || new Date().toISOString();
  const readingStatus = status || "OK";

  const item = await Reading.create({
    plotId: new mongoose.Types.ObjectId(String(found.plot._id)),
    pinId: pinOid,
    nodeId: new mongoose.Types.ObjectId(String(nodeDoc._id)),
    nodeType: match.nodeType,
    sensorId: sensorOid,
    sensorType: match.sensor.sensorType,
    ts: readingTs,
    value: num,
    status: readingStatus,
    raw: raw || undefined,
  });

  const nodeModel = await NodeTemplate.findById(nodeDoc._id);
  if (nodeModel) {
    const target =
      match.nodeType === "soil"
        ? nodeModel.node_soil.sensors.id(String(sensorOid))
        : nodeModel.node_air.sensors.id(String(sensorOid));

    if (target) {
      target.value = num;
      target.status = readingStatus;
      target.lastReadingAt = readingTs;
      target.lastReading = { value: num, ts: readingTs };
      await nodeModel.save();
    }
  }

  return leanWithId(item);
}

/* =========================
   AUTH
========================= */

app.post("/auth/register", async (req, res) => {
  const { email, password, nickname, role } = req.body || {};

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
    if (msg.toLowerCase().includes("unique") || msg.toLowerCase().includes("duplicate")) {
      return res.status(409).json({ message: "email or nickname already exists" });
    }
    return res.status(500).json({ message: "server error", error: msg });
  }
});

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
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
    if (!user || !user.password_hash) {
      return res.status(401).json({ message: "invalid credentials" });
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ message: "invalid credentials" });

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        nickname: user.nickname,
        role: user.role,
      },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    return res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        nickname: user.nickname,
        role: user.role,
      },
    });
  } catch (e) {
    return res.status(500).json({ message: "server error", error: String(e.message || e) });
  }
});

app.get("/auth/me", auth, async (req, res) => {
  res.json({ user: req.user });
});

app.get("/auth/google", (req, res) => {
  const url = googleOAuth2Client.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: ["openid", "email", "profile"],
  });
  res.json({ url });
});

app.get("/auth/google/callback", async (req, res) => {
  try {
    const code = req.query.code;
    if (!code) return res.status(400).json({ message: "Missing code" });

    const { tokens } = await googleOAuth2Client.getToken(String(code));
    googleOAuth2Client.setCredentials(tokens);

    const oauth2 = google.oauth2({ auth: googleOAuth2Client, version: "v2" });
    const me = await oauth2.userinfo.get();
    const email = me.data.email;
    const nickname = makeSafeNickname(me.data.name, email);

    const token = jwt.sign({ email, nickname, role: "employee" }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    const redirectBase = process.env.FRONTEND_URL || "http://localhost:3000";
    return res.redirect(`${redirectBase}/login?token=${encodeURIComponent(token)}`);
  } catch (e) {
    return res.status(500).json({ message: "Google auth failed", error: String(e.message || e) });
  }
});

/* =========================
   API ROUTER
========================= */

api.use(auth);

/* =========================
   NODE TEMPLATE
========================= */

api.get("/nodes", async (req, res, next) => {
  try {
    const docs = await NodeTemplate.find().sort({ createdAt: -1 }).lean();
    res.json({ items: docs.map(leanWithId) });
  } catch (e) {
    next(e);
  }
});

api.post("/nodes", async (req, res, next) => {
  try {
    const b = req.body || {};
    const nodeName = String(b.nodeName || "").trim();
    if (!nodeName) return res.status(400).json({ message: "nodeName is required" });

    const doc = await NodeTemplate.create({
      nodeName,
      node_soil: normalizeNode(b.node_soil || {}),
      node_air: normalizeNode(b.node_air || {}),
      status: b.status || "ACTIVE",
    });

    res.status(201).json({ item: leanWithId(doc) });
  } catch (e) {
    next(e);
  }
});

api.get("/nodes/:nodeId", async (req, res, next) => {
  try {
    const nodeId = requireObjectId(res, req.params.nodeId, "nodeId");
    if (!nodeId) return;

    const doc = await NodeTemplate.findById(nodeId).lean();
    if (!doc) return res.status(404).json({ message: "NodeTemplate not found" });

    res.json({ item: leanWithId(doc) });
  } catch (e) {
    next(e);
  }
});

api.patch("/nodes/:nodeId", async (req, res, next) => {
  try {
    const nodeId = requireObjectId(res, req.params.nodeId, "nodeId");
    if (!nodeId) return;

    const b = req.body || {};
    const update = {};

    if (b.nodeName !== undefined) update.nodeName = String(b.nodeName || "").trim();
    if (b.node_soil !== undefined) update.node_soil = normalizeNode(b.node_soil || {});
    if (b.node_air !== undefined) update.node_air = normalizeNode(b.node_air || {});
    if (b.status !== undefined) update.status = b.status;

    const doc = await NodeTemplate.findByIdAndUpdate(nodeId, { $set: update }, { new: true }).lean();
    if (!doc) return res.status(404).json({ message: "NodeTemplate not found" });

    res.json({ item: leanWithId(doc) });
  } catch (e) {
    next(e);
  }
});

api.delete("/nodes/:nodeId", async (req, res, next) => {
  try {
    const nodeId = requireObjectId(res, req.params.nodeId, "nodeId");
    if (!nodeId) return;

    await NodeTemplate.findByIdAndDelete(nodeId);
    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

/* =========================
   PLOTS
========================= */

api.get("/plots", async (req, res, next) => {
  try {
    const docs = await Plot.find().sort({ createdAt: -1 }).lean();
    res.json({ items: docs.map(leanWithId) });
  } catch (e) {
    next(e);
  }
});

api.post("/plots", async (req, res, next) => {
  try {
    const b = req.body || {};
    const nicknameFromToken = String(req.user?.nickname || "").trim();

    const doc = await Plot.create({
      alias: b.alias || "",
      plotName: b.plotName || b.name || "Untitled Plot",
      caretaker: nicknameFromToken || b.caretaker || b.ownerName || "",
      plantType: b.plantType || b.cropType || "",
      plantedAt: b.plantedAt || "",
      status: b.status || "ACTIVE",
      name: b.name || b.plotName || "Untitled Plot",
      cropType: b.cropType || b.plantType || "",
      ownerName: nicknameFromToken || b.ownerName || b.caretaker || "",
      topics: normalizeTopics(b.topics || b.topicAll || b.Topic_all || []),
      polygon: normalizePolygon(b.polygon || {}),
    });

    res.status(201).json({ item: leanWithId(doc) });
  } catch (e) {
    next(e);
  }
});

api.get("/plots/:plotId", async (req, res, next) => {
  try {
    const plotId = requireObjectId(res, req.params.plotId, "plotId");
    if (!plotId) return;

    const doc = await Plot.findById(plotId).lean();
    if (!doc) return res.status(404).json({ message: "Plot not found" });

    res.json({ item: leanWithId(doc) });
  } catch (e) {
    next(e);
  }
});

api.get("/plots/:plotId/full", async (req, res, next) => {
  try {
    const plotId = requireObjectId(res, req.params.plotId, "plotId");
    if (!plotId) return;

    const doc = await Plot.findById(plotId).lean();
    if (!doc) return res.status(404).json({ message: "Plot not found" });

    const pins = doc?.polygon?.pins || [];
    const nodeIds = pins.map((p) => p.nodeId).filter(Boolean);
    const nodes = nodeIds.length
      ? await NodeTemplate.find({ _id: { $in: nodeIds } }).lean()
      : [];

    const nodeMap = new Map(nodes.map((n) => [String(n._id), n]));
    const enrichedPins = pins.map((pin) => {
      const nodeDoc = pin?.nodeId ? nodeMap.get(String(pin.nodeId)) : null;
      return enrichPinWithNode(pin, nodeDoc);
    });

    const item = {
      ...leanWithId(doc),
      polygon: {
        ...(doc.polygon || { color: "#2563eb", coords: [], pins: [] }),
        pins: enrichedPins,
      },
    };

    res.json({ item });
  } catch (e) {
    next(e);
  }
});

api.patch("/plots/:plotId", async (req, res, next) => {
  try {
    const plotId = requireObjectId(res, req.params.plotId, "plotId");
    if (!plotId) return;

    const b = req.body || {};
    const update = {};

    if (b.alias !== undefined) update.alias = b.alias;
    if (b.plotName !== undefined) {
      update.plotName = b.plotName;
      update.name = b.plotName;
    }
    if (b.caretaker !== undefined) {
      update.caretaker = b.caretaker;
      update.ownerName = b.caretaker;
    }
    if (b.plantType !== undefined) {
      update.plantType = b.plantType;
      update.cropType = b.plantType;
    }
    if (b.plantedAt !== undefined) update.plantedAt = b.plantedAt;
    if (b.status !== undefined) update.status = b.status;
    if (b.topics !== undefined || b.topicAll !== undefined || b.Topic_all !== undefined) {
      update.topics = normalizeTopics(b.topics || b.topicAll || b.Topic_all || []);
    }
    if (b.polygon !== undefined) update.polygon = normalizePolygon(b.polygon || {});

    const doc = await Plot.findByIdAndUpdate(plotId, { $set: update }, { new: true }).lean();
    if (!doc) return res.status(404).json({ message: "Plot not found" });

    res.json({ item: leanWithId(doc) });
  } catch (e) {
    next(e);
  }
});

api.delete("/plots/:plotId", async (req, res, next) => {
  try {
    const plotId = requireObjectId(res, req.params.plotId, "plotId");
    if (!plotId) return;

    const doc = await Plot.findByIdAndDelete(plotId).lean();
    if (!doc) return res.status(404).json({ message: "Plot not found" });

    await Reading.deleteMany({ plotId });
    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

/* =========================
   TOPICS
========================= */

api.get("/plots/:plotId/topics", async (req, res, next) => {
  try {
    const plotId = requireObjectId(res, req.params.plotId, "plotId");
    if (!plotId) return;

    const doc = await Plot.findById(plotId, { topics: 1 }).lean();
    if (!doc) return res.status(404).json({ message: "Plot not found" });

    res.json({ items: doc.topics || [] });
  } catch (e) {
    next(e);
  }
});

api.put("/plots/:plotId/topics", async (req, res, next) => {
  try {
    const plotId = requireObjectId(res, req.params.plotId, "plotId");
    if (!plotId) return;

    const topics = normalizeTopics(
      req.body?.topics || req.body?.topicAll || req.body?.Topic_all || []
    );

    const doc = await Plot.findByIdAndUpdate(plotId, { $set: { topics } }, { new: true }).lean();
    if (!doc) return res.status(404).json({ message: "Plot not found" });

    res.json({ items: doc.topics || [] });
  } catch (e) {
    next(e);
  }
});

/* =========================
   POLYGON
========================= */

api.get("/plots/:plotId/polygon", async (req, res, next) => {
  try {
    const plotId = requireObjectId(res, req.params.plotId, "plotId");
    if (!plotId) return;

    const doc = await Plot.findById(plotId, { polygon: 1 }).lean();
    if (!doc) return res.status(404).json({ message: "Plot not found" });

    res.json({ item: doc.polygon || null });
  } catch (e) {
    next(e);
  }
});

api.put("/plots/:plotId/polygon", async (req, res, next) => {
  try {
    const plotId = requireObjectId(res, req.params.plotId, "plotId");
    if (!plotId) return;

    const current = await Plot.findById(plotId, { polygon: 1 }).lean();
    if (!current) return res.status(404).json({ message: "Plot not found" });

    const incoming = normalizePolygon(req.body || {});
    const mergedPolygon = {
      _id: current?.polygon?._id || incoming._id,
      color: incoming.color || current?.polygon?.color || "#2563eb",
      coords: incoming.coords || [],
      pins: Array.isArray(req.body?.pins)
        ? incoming.pins
        : current?.polygon?.pins || [],
    };

    const doc = await Plot.findByIdAndUpdate(
      plotId,
      { $set: { polygon: mergedPolygon } },
      { new: true }
    ).lean();

    res.json({ item: doc.polygon || null });
  } catch (e) {
    next(e);
  }
});

/* =========================
   PINS
========================= */

api.get("/plots/:plotId/pins", async (req, res, next) => {
  try {
    const plotId = requireObjectId(res, req.params.plotId, "plotId");
    if (!plotId) return;

    const doc = await Plot.findById(plotId, { "polygon.pins": 1 }).lean();
    if (!doc) return res.status(404).json({ message: "Plot not found" });

    const pins = doc?.polygon?.pins || [];
    const nodeIds = pins.map((p) => p.nodeId).filter(Boolean);
    const nodes = nodeIds.length
      ? await NodeTemplate.find({ _id: { $in: nodeIds } }).lean()
      : [];

    const nodeMap = new Map(nodes.map((n) => [String(n._id), n]));
    const items = pins.map((pin) => {
      const nodeDoc = pin?.nodeId ? nodeMap.get(String(pin.nodeId)) : null;
      return enrichPinWithNode(pin, nodeDoc);
    });

    res.json({ items });
  } catch (e) {
    next(e);
  }
});

api.post("/plots/:plotId/pins", async (req, res, next) => {
  try {
    const plotId = requireObjectId(res, req.params.plotId, "plotId");
    if (!plotId) return;

    const plot = await Plot.findById(plotId);
    if (!plot) return res.status(404).json({ message: "Plot not found" });

    const pin = normalizePin(req.body || {}, (plot.polygon?.pins || []).length);

    if (pin.nodeId) {
      const nodeDoc = await NodeTemplate.findById(pin.nodeId).lean();
      if (!nodeDoc) return res.status(404).json({ message: "NodeTemplate not found" });
      pin.nodeName = nodeDoc.nodeName || pin.nodeName || "";
    }

    if (!plot.polygon) plot.polygon = normalizePolygon({});
    plot.polygon.pins.push(pin);
    await plot.save();

    res.status(201).json({ item: plot.polygon.pins[plot.polygon.pins.length - 1].toObject() });
  } catch (e) {
    next(e);
  }
});

api.get("/pins/:pinId", async (req, res, next) => {
  try {
    const pinId = requireObjectId(res, req.params.pinId, "pinId");
    if (!pinId) return;

    const found = await findPlotByPinId(String(pinId));
    if (!found?.pin) return res.status(404).json({ message: "Pin not found" });

    const nodeDoc = await getNodeTemplateForPin(found.pin);

    res.json({
      item: enrichPinWithNode(found.pin, nodeDoc),
      plotId: String(found.plot._id),
    });
  } catch (e) {
    next(e);
  }
});

api.patch("/pins/:pinId", async (req, res, next) => {
  try {
    const pinId = requireObjectId(res, req.params.pinId, "pinId");
    if (!pinId) return;

    const plot = await Plot.findOne({ "polygon.pins._id": pinId });
    if (!plot) return res.status(404).json({ message: "Pin not found" });

    const pin = plot.polygon.pins.id(String(pinId));
    if (!pin) return res.status(404).json({ message: "Pin not found" });

    const b = req.body || {};
    if (b.number !== undefined) pin.number = Number(b.number);
    if (b.lat !== undefined) pin.lat = Number(b.lat);
    if (b.lng !== undefined) pin.lng = Number(b.lng);

    if (b.nodeId !== undefined) {
      if (b.nodeId === null || b.nodeId === "") {
        pin.nodeId = null;
        pin.nodeName = "";
      } else {
        const nodeId = requireObjectId(res, b.nodeId, "nodeId");
        if (!nodeId) return;

        const nodeDoc = await NodeTemplate.findById(nodeId).lean();
        if (!nodeDoc) return res.status(404).json({ message: "NodeTemplate not found" });

        pin.nodeId = nodeId;
        pin.nodeName = nodeDoc.nodeName || "";
      }
    }

    if (b.nodeName !== undefined && !pin.nodeId) {
      pin.nodeName = String(b.nodeName || "").trim();
    }

    await plot.save();
    res.json({ item: pin.toObject() });
  } catch (e) {
    next(e);
  }
});

api.delete("/pins/:pinId", async (req, res, next) => {
  try {
    const pinId = requireObjectId(res, req.params.pinId, "pinId");
    if (!pinId) return;

    const plot = await Plot.findOne({ "polygon.pins._id": pinId });
    if (!plot) return res.status(404).json({ message: "Pin not found" });

    plot.polygon.pins = plot.polygon.pins.filter((p) => String(p._id) !== String(pinId));
    await plot.save();

    await Reading.deleteMany({ pinId });
    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

api.patch("/pins/:pinId/node", async (req, res, next) => {
  try {
    const pinId = requireObjectId(res, req.params.pinId, "pinId");
    if (!pinId) return;

    const nodeId = requireObjectId(res, req.body?.nodeId, "nodeId");
    if (!nodeId) return;

    const nodeDoc = await NodeTemplate.findById(nodeId).lean();
    if (!nodeDoc) return res.status(404).json({ message: "NodeTemplate not found" });

    const plot = await Plot.findOne({ "polygon.pins._id": pinId });
    if (!plot) return res.status(404).json({ message: "Pin not found" });

    const pin = plot.polygon.pins.id(String(pinId));
    if (!pin) return res.status(404).json({ message: "Pin not found" });

    pin.nodeId = nodeId;
    pin.nodeName = nodeDoc.nodeName || "";

    await plot.save();
    res.json({ item: pin.toObject() });
  } catch (e) {
    next(e);
  }
});

api.get("/pins/:pinId/node", async (req, res, next) => {
  try {
    const pinId = requireObjectId(res, req.params.pinId, "pinId");
    if (!pinId) return;

    const found = await findPlotByPinId(String(pinId));
    if (!found?.pin) return res.status(404).json({ message: "Pin not found" });

    if (!found.pin.nodeId) {
      return res.json({ item: null });
    }

    const nodeDoc = await getNodeTemplateForPin(found.pin);
    res.json({ item: nodeDoc ? leanWithId(nodeDoc) : null });
  } catch (e) {
    next(e);
  }
});

api.get("/pins/:pinId/node-soil", async (req, res, next) => {
  try {
    const pinId = requireObjectId(res, req.params.pinId, "pinId");
    if (!pinId) return;

    const found = await findPlotByPinId(String(pinId));
    if (!found?.pin) return res.status(404).json({ message: "Pin not found" });

    const nodeDoc = await getNodeTemplateForPin(found.pin);
    res.json({ item: nodeDoc?.node_soil || { sensors: [] } });
  } catch (e) {
    next(e);
  }
});

api.get("/pins/:pinId/node-air", async (req, res, next) => {
  try {
    const pinId = requireObjectId(res, req.params.pinId, "pinId");
    if (!pinId) return;

    const found = await findPlotByPinId(String(pinId));
    if (!found?.pin) return res.status(404).json({ message: "Pin not found" });

    const nodeDoc = await getNodeTemplateForPin(found.pin);
    res.json({ item: nodeDoc?.node_air || { sensors: [] } });
  } catch (e) {
    next(e);
  }
});

/* =========================
   SENSORS
========================= */

api.get("/pins/:pinId/sensors", async (req, res, next) => {
  try {
    const pinId = requireObjectId(res, req.params.pinId, "pinId");
    if (!pinId) return;

    const found = await findPlotByPinId(String(pinId));
    if (!found?.pin) return res.status(404).json({ message: "Pin not found" });

    const nodeDoc = await getNodeTemplateForPin(found.pin);
    if (!nodeDoc) return res.json({ items: [] });

    const nodeType = String(req.query.nodeType || "all");
    const items = [];

    if (nodeType === "all" || nodeType === "soil") {
      for (const s of nodeDoc?.node_soil?.sensors || []) {
        items.push({
          ...s,
          nodeType: "soil",
          pinId: String(found.pin._id),
          plotId: String(found.plot._id),
          nodeId: String(nodeDoc._id),
          nodeName: nodeDoc.nodeName || "",
        });
      }
    }

    if (nodeType === "all" || nodeType === "air") {
      for (const s of nodeDoc?.node_air?.sensors || []) {
        items.push({
          ...s,
          nodeType: "air",
          pinId: String(found.pin._id),
          plotId: String(found.plot._id),
          nodeId: String(nodeDoc._id),
          nodeName: nodeDoc.nodeName || "",
        });
      }
    }

    res.json({ items });
  } catch (e) {
    next(e);
  }
});

api.patch("/sensors/:sensorId", async (req, res, next) => {
  try {
    const sensorId = requireObjectId(res, req.params.sensorId, "sensorId");
    if (!sensorId) return;

    const node = await NodeTemplate.findOne({
      $or: [
        { "node_soil.sensors._id": sensorId },
        { "node_air.sensors._id": sensorId },
      ],
    });

    if (!node) return res.status(404).json({ message: "Sensor not found" });

    let updated = null;
    let foundNodeType = null;
    const b = req.body || {};

    const soil = node.node_soil.sensors.id(String(sensorId));
    if (soil) {
      if (b.sensorType !== undefined) soil.sensorType = b.sensorType;
      if (b.name !== undefined) soil.name = b.name;
      if (b.unit !== undefined) soil.unit = b.unit;
      if (b.value !== undefined) soil.value = b.value;
      if (b.valueHint !== undefined) soil.valueHint = b.valueHint;
      if (b.status !== undefined) soil.status = b.status;
      if (b.lastReadingAt !== undefined) soil.lastReadingAt = b.lastReadingAt;
      if (b.lastReading !== undefined) soil.lastReading = b.lastReading;
      updated = soil;
      foundNodeType = "soil";
    }

    const air = node.node_air.sensors.id(String(sensorId));
    if (!updated && air) {
      if (b.sensorType !== undefined) air.sensorType = b.sensorType;
      if (b.name !== undefined) air.name = b.name;
      if (b.unit !== undefined) air.unit = b.unit;
      if (b.value !== undefined) air.value = b.value;
      if (b.valueHint !== undefined) air.valueHint = b.valueHint;
      if (b.status !== undefined) air.status = b.status;
      if (b.lastReadingAt !== undefined) air.lastReadingAt = b.lastReadingAt;
      if (b.lastReading !== undefined) air.lastReading = b.lastReading;
      updated = air;
      foundNodeType = "air";
    }

    await node.save();
    res.json({
      item: {
        ...updated.toObject(),
        nodeType: foundNodeType,
        nodeId: String(node._id),
        nodeName: node.nodeName || "",
      },
    });
  } catch (e) {
    next(e);
  }
});

api.get("/sensors", async (req, res, next) => {
  try {
    const { plotId, pinId, nodeType, sensorType, nodeId } = req.query || {};
    let items = [];
    let plots = [];

    if (plotId) {
      const plotOid = requireObjectId(res, plotId, "plotId");
      if (!plotOid) return;
      plots = await Plot.find({ _id: plotOid }).lean();
    } else {
      plots = await Plot.find().lean();
    }

    const allNodeIds = [];
    for (const plot of plots) {
      for (const pin of plot?.polygon?.pins || []) {
        if (pinId && String(pin._id) !== String(pinId)) continue;
        if (nodeId && String(pin.nodeId || "") !== String(nodeId)) continue;
        if (pin.nodeId) allNodeIds.push(String(pin.nodeId));
      }
    }

    const nodes = allNodeIds.length
      ? await NodeTemplate.find({ _id: { $in: allNodeIds } }).lean()
      : [];

    const nodeMap = new Map(nodes.map((n) => [String(n._id), n]));

    for (const plot of plots) {
      for (const pin of plot?.polygon?.pins || []) {
        if (pinId && String(pin._id) !== String(pinId)) continue;
        if (nodeId && String(pin.nodeId || "") !== String(nodeId)) continue;

        const nodeDoc = pin.nodeId ? nodeMap.get(String(pin.nodeId)) : null;
        if (!nodeDoc) continue;

        if (!nodeType || nodeType === "all" || nodeType === "soil") {
          for (const s of nodeDoc?.node_soil?.sensors || []) {
            if (!sensorType || sensorType === "all" || s.sensorType === sensorType) {
              items.push({
                ...s,
                nodeType: "soil",
                pinId: String(pin._id),
                plotId: String(plot._id),
                nodeId: String(nodeDoc._id),
                nodeName: nodeDoc.nodeName || "",
              });
            }
          }
        }

        if (!nodeType || nodeType === "all" || nodeType === "air") {
          for (const s of nodeDoc?.node_air?.sensors || []) {
            if (!sensorType || sensorType === "all" || s.sensorType === sensorType) {
              items.push({
                ...s,
                nodeType: "air",
                pinId: String(pin._id),
                plotId: String(plot._id),
                nodeId: String(nodeDoc._id),
                nodeName: nodeDoc.nodeName || "",
              });
            }
          }
        }
      }
    }

    res.json({ items });
  } catch (e) {
    next(e);
  }
});

/* =========================
   READINGS
========================= */

api.post("/readings", async (req, res, next) => {
  try {
    const item = await createReadingAndUpdateNode(req.body || {});
    res.status(201).json({ item });
  } catch (e) {
    if (e.statusCode) {
      return res.status(e.statusCode).json({ message: e.message });
    }
    next(e);
  }
});

api.post("/ingest/reading", async (req, res, next) => {
  try {
    const { pinId, nodeType, sensorType, value, ts, status, raw } = req.body || {};

    const pinOid = requireObjectId(res, pinId, "pinId");
    if (!pinOid) return;

    const found = await findPlotByPinId(String(pinOid));
    if (!found?.pin) return res.status(404).json({ message: "Pin not found" });

    const nodeDoc = await getNodeTemplateForPin(found.pin);
    if (!nodeDoc) return res.status(404).json({ message: "NodeTemplate not found for pin" });

    const sensors =
      nodeType === "air"
        ? nodeDoc?.node_air?.sensors || []
        : nodeDoc?.node_soil?.sensors || [];

    const sensor = sensors.find((s) => s.sensorType === sensorType);
    if (!sensor) {
      return res.status(404).json({ message: "Sensor not found for given nodeType/sensorType" });
    }

    const item = await createReadingAndUpdateNode({
      pinId: String(pinOid),
      sensorId: String(sensor._id),
      value,
      ts,
      status,
      raw,
    });

    res.status(201).json({ item });
  } catch (e) {
    if (e.statusCode) {
      return res.status(e.statusCode).json({ message: e.message });
    }
    next(e);
  }
});

api.get("/readings", async (req, res, next) => {
  try {
    const { plotId, pinId, sensorType, nodeType, from, to, nodeId } = req.query || {};
    const q = {};

    if (plotId) {
      const plotOid = requireObjectId(res, plotId, "plotId");
      if (!plotOid) return;
      q.plotId = plotOid;
    }

    if (pinId) {
      const pinOid = requireObjectId(res, pinId, "pinId");
      if (!pinOid) return;
      q.pinId = pinOid;
    }

    if (nodeId) {
      const nodeOid = requireObjectId(res, nodeId, "nodeId");
      if (!nodeOid) return;
      q.nodeId = nodeOid;
    }

    if (sensorType && sensorType !== "all") q.sensorType = String(sensorType);
    if (nodeType && nodeType !== "all") q.nodeType = String(nodeType);

    if (from || to) {
      q.ts = {};
      if (from) q.ts.$gte = String(from);
      if (to) q.ts.$lte = String(to);
    }

    const items = (await Reading.find(q).sort({ ts: 1 }).lean()).map(leanWithId);
    res.json({ items });
  } catch (e) {
    next(e);
  }
});

api.get("/plots/:plotId/summary", async (req, res, next) => {
  try {
    const plotId = requireObjectId(res, req.params.plotId, "plotId");
    if (!plotId) return;

    const plot = await Plot.findById(plotId).lean();
    if (!plot) return res.status(404).json({ message: "Plot not found" });

    const pinIds = (plot?.polygon?.pins || []).map((p) => parseObjectId(p._id)).filter(Boolean);

    const readings = await Reading.find({
      plotId,
      pinId: { $in: pinIds },
    }).lean();

    const map = new Map();

    for (const r of readings) {
      const key = `${r.nodeType}:${r.sensorId}:${r.sensorType}`;
      if (!map.has(key)) map.set(key, []);
      map.get(key).push(r);
    }

    const items = [];
    for (const list of map.values()) {
      const values = list.map((x) => Number(x.value)).filter(Number.isFinite);
      if (!values.length) continue;

      const last = list[list.length - 1];
      items.push({
        nodeId: String(last.nodeId),
        nodeType: last.nodeType,
        sensorId: String(last.sensorId),
        sensorType: last.sensorType,
        min: Math.min(...values),
        max: Math.max(...values),
        avg: values.reduce((a, b) => a + b, 0) / values.length,
        last: last.value,
        lastAt: last.ts,
      });
    }

    res.json({ plotId: String(plotId), items });
  } catch (e) {
    next(e);
  }
});

/* =========================
   MOUNT + ERROR
========================= */

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