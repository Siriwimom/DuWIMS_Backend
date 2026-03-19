require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { google } = require("googleapis");
const admin = require("firebase-admin");
const nodemailer = require("nodemailer");

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.applicationDefault(),
  });
}

console.log(
  "GOOGLE_APPLICATION_CREDENTIALS =",
  process.env.GOOGLE_APPLICATION_CREDENTIALS
);
console.log(
  "project_id from env hint =",
  process.env.GOOGLE_CLOUD_PROJECT || process.env.GCLOUD_PROJECT
);

const firestore = admin.firestore();

const app = express();
const api = express.Router();

const BUILD_TAG = "firestore-100-auth-v1";
const COLLECTIONS = {
  plots: "plots",
  nodes: "nodeTemplates",
  readings: "sensorReadings",
  users: "users",
  passwordOtps: "passwordOtps",
};

console.log("========================================");
console.log("[SERVER] BUILD:", BUILD_TAG);
console.log("[SERVER] FILE :", __filename);
console.log("[SERVER] CWD  :", process.cwd());
console.log("========================================");

app.use(cors());
app.use(express.json({ limit: "2mb" }));
const mailer = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASS,
  },
});

function generateOtp() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function getOtpTtlMs() {
  const ttlMin = Number(process.env.OTP_TTL_MIN || 10);
  return ttlMin * 60 * 1000;
}

async function savePasswordOtp(email, code) {
  const safeEmail = String(email || "").trim().toLowerCase();
  await firestore.collection(COLLECTIONS.passwordOtps).doc(safeEmail).set({
    email: safeEmail,
    code: String(code),
    verified: false,
    createdAt: nowIso(),
    expiresAt: Date.now() + getOtpTtlMs(),
  });
}

async function getPasswordOtp(email) {
  const safeEmail = String(email || "").trim().toLowerCase();
  const doc = await firestore.collection(COLLECTIONS.passwordOtps).doc(safeEmail).get();
  if (!doc.exists) return null;
  return doc.data();
}

async function markPasswordOtpVerified(email) {
  const safeEmail = String(email || "").trim().toLowerCase();
  await firestore.collection(COLLECTIONS.passwordOtps).doc(safeEmail).set(
    {
      verified: true,
      verifiedAt: nowIso(),
    },
    { merge: true }
  );
}

async function deletePasswordOtp(email) {
  const safeEmail = String(email || "").trim().toLowerCase();
  await firestore.collection(COLLECTIONS.passwordOtps).doc(safeEmail).delete();
}

async function sendOtpEmail(toEmail, otp) {
  const ttlMin = Number(process.env.OTP_TTL_MIN || 10);

  return await mailer.sendMail({
    from: `"DuWIMS" <${process.env.MAIL_USER}>`,
    to: toEmail,
    subject: "OTP สำหรับรีเซ็ตรหัสผ่าน",
    text: `รหัส OTP ของคุณคือ ${otp} และจะหมดอายุใน ${ttlMin} นาที`,
    html: `
      <div style="font-family:Arial,sans-serif;line-height:1.6">
        <h2>รีเซ็ตรหัสผ่าน</h2>
        <p>รหัส OTP ของคุณคือ</p>
        <div style="font-size:32px;font-weight:700;letter-spacing:6px">${otp}</div>
        <p>OTP นี้จะหมดอายุใน ${ttlMin} นาที</p>
      </div>
    `,
  });
}

app.get("/__version", (req, res) => {
  res.json({ build: BUILD_TAG, file: __filename, cwd: process.cwd() });
});

app.get("/health", (req, res) => res.json({ ok: true, build: BUILD_TAG }));

app.get("/firestore/ping", async (req, res) => {
  try {
    await firestore.collection("__healthcheck").doc("ping").set(
      {
        ok: true,
        ts: new Date().toISOString(),
      },
      { merge: true }
    );
    res.json({ ok: true, message: "Cloud Firestore connected" });
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

function nowIso() {
  return new Date().toISOString();
}

function makeId(prefix = "id") {
  return `${prefix}_${Math.random().toString(36).slice(2, 10)}${Date.now().toString(36)}`;
}

function cleanUndefined(obj) {
  if (Array.isArray(obj)) return obj.map(cleanUndefined);
  if (!obj || typeof obj !== "object") return obj;
  return Object.fromEntries(
    Object.entries(obj)
      .filter(([, v]) => v !== undefined)
      .map(([k, v]) => [k, cleanUndefined(v)])
  );
}

function withId(id, data) {
  if (!data) return null;
  return { ...data, id: id || data.id || null };
}

function requireId(res, value, fieldName) {
  const id = String(value || "").trim();
  if (!id) {
    res.status(400).json({ message: `Invalid ${fieldName}` });
    return null;
  }
  return id;
}

function normalizeTopics(topics) {
  if (!Array.isArray(topics)) return [];
  return topics
    .map((x) => ({
      id: String(x?.id || x?._id || makeId("topic")),
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
    .map((point) => {
      if (Array.isArray(point) && point.length >= 2) {
        const lat = Number(point[0]);
        const lng = Number(point[1]);
        if (!Number.isFinite(lat) || !Number.isFinite(lng)) return null;
        return { lat, lng };
      }

      if (point && typeof point === "object") {
        const lat = Number(point.lat);
        const lng = Number(point.lng);
        if (!Number.isFinite(lat) || !Number.isFinite(lng)) return null;
        return { lat, lng };
      }

      return null;
    })
    .filter(Boolean);
}

function defaultAirSensors() {
  return [
    {
      id: makeId("sensor"),
      sensorType: "temp_rh",
      name: "อุณหภูมิและความชื้น",
      unit: "°C / %",
      value: null,
      valueHint: "",
      status: "OK",
      lastReadingAt: null,
      lastReading: { value: null, ts: null },
    },
    {
      id: makeId("sensor"),
      sensorType: "wind_speed",
      name: "วัดความเร็วลม",
      unit: "m/s",
      value: null,
      valueHint: "",
      status: "OK",
      lastReadingAt: null,
      lastReading: { value: null, ts: null },
    },
    {
      id: makeId("sensor"),
      sensorType: "light",
      name: "ความเข้มแสง",
      unit: "lux",
      value: null,
      valueHint: "",
      status: "OK",
      lastReadingAt: null,
      lastReading: { value: null, ts: null },
    },
    {
      id: makeId("sensor"),
      sensorType: "rain",
      name: "ปริมาณน้ำฝน",
      unit: "mm",
      value: null,
      valueHint: "",
      status: "OK",
      lastReadingAt: null,
      lastReading: { value: null, ts: null },
    },
  ];
}

function defaultSoilSensors() {
  return [
    {
      id: makeId("sensor"),
      sensorType: "soil_moisture",
      name: "ความชื้นในดิน",
      unit: "%",
      value: null,
      valueHint: "",
      status: "OK",
      lastReadingAt: null,
      lastReading: { value: null, ts: null },
    },
    {
      id: makeId("sensor"),
      sensorType: "npk",
      name: "ความเข้มข้นธาตุอาหาร (N,P,K)",
      unit: "mg/kg",
      value: null,
      valueHint: "",
      status: "OK",
      lastReadingAt: null,
      lastReading: { value: null, ts: null },
    },
    {
      id: makeId("sensor"),
      sensorType: "water_level",
      name: "การให้น้ำ / ความพร้อมใช้น้ำ",
      unit: "%",
      value: null,
      valueHint: "",
      status: "OK",
      lastReadingAt: null,
      lastReading: { value: null, ts: null },
    },
  ];
}

function normalizeSensor(sensor = {}) {
  const lastTs = sensor.lastReadingAt || sensor?.lastReading?.ts || null;
  return cleanUndefined({
    id: String(sensor.id || sensor._id || makeId("sensor")),
    sensorType: String(sensor.sensorType || "").trim(),
    name: String(sensor.name || "").trim(),
    unit: String(sensor.unit || "").trim(),
    value: sensor.value ?? null,
    valueHint: sensor.valueHint ?? "",
    status: String(sensor.status || "OK"),
    lastReadingAt: lastTs,
    lastReading: {
      value: sensor?.lastReading?.value ?? sensor.value ?? null,
      ts: lastTs,
    },
  });
}

function normalizeNodeTemplatePart(node = {}, fallbackType = "air") {
  const type = String(node.nodeType || fallbackType);
  let sensors = Array.isArray(node.sensors) ? node.sensors.map(normalizeSensor) : [];
  if (!sensors.length) {
    sensors = type === "soil" ? defaultSoilSensors() : defaultAirSensors();
  }

  return {
    id: String(node.id || node._id || makeId("nodepart")),
    nodeType: type,
    nodeName: String(node.nodeName || node.name || "").trim(),
    sensors,
  };
}

function normalizePinNode(node = {}, fallbackType = "air") {
  const type = String(node.nodeType || fallbackType);
  let sensors = Array.isArray(node.sensors) ? node.sensors.map(normalizeSensor) : [];
  if (!sensors.length) {
    sensors = type === "soil" ? defaultSoilSensors() : defaultAirSensors();
  }

  return {
    id: String(node.id || node._id || makeId("node")),
    uid: String(node.uid || node.UID || "").trim(),
    templateId: node.templateId ? String(node.templateId) : null,
    nodeType: type,
    nodeName: String(node.nodeName || node.name || "").trim(),
    sensors,
    createdAt: String(node.createdAt || nowIso()),
    updatedAt: nowIso(),
  };
}

function normalizePinNodeArray(items, type) {
  if (!Array.isArray(items)) return [];
  return items.map((x) => normalizePinNode(x, type));
}

function normalizePin(pin = {}, index = 0) {
  const createdAt = pin.createdAt || nowIso();

  const nodeAir =
    Array.isArray(pin.node_air) && pin.node_air.length
      ? normalizePinNodeArray(pin.node_air, "air")
      : [];

  const nodeSoil =
    Array.isArray(pin.node_soil) && pin.node_soil.length
      ? normalizePinNodeArray(pin.node_soil, "soil")
      : [];

  return {
    id: String(pin.id || pin._id || makeId("pin")),
    number: Number.isFinite(Number(pin.number)) ? Number(pin.number) : index + 1,
    pinName: String(pin.pinName || pin.name || "").trim(),
    lat: Number(pin.lat ?? 0),
    lng: Number(pin.lng ?? 0),
    node_air: nodeAir,
    node_soil: nodeSoil,
    createdAt,
    updatedAt: nowIso(),
  };
}

function normalizePolygon(polygon = {}) {
  return {
    id: String(polygon.id || polygon._id || makeId("polygon")),
    color: String(polygon.color || "#2563eb"),
    coords: normalizeCoords(polygon.coords || polygon.coordinates || []),
    pins: Array.isArray(polygon.pins) ? polygon.pins.map(normalizePin) : [],
  };
}

function normalizePlotCreate(body = {}) {
  return {
    alias: String(body.alias || ""),
    plotName: String(body.plotName || body.name || "Untitled Plot"),
    caretaker: String(body.caretaker || body.ownerName || ""),
    plantType: String(body.plantType || body.cropType || ""),
    plantedAt: String(body.plantedAt || ""),
    status: String(body.status || "ACTIVE"),
    name: String(body.name || body.plotName || "Untitled Plot"),
    cropType: String(body.cropType || body.plantType || ""),
    ownerName: String(body.ownerName || body.caretaker || ""),
    topics: normalizeTopics(body.topics || body.topicAll || body.Topic_all || []),
    polygon: normalizePolygon(body.polygon || {}),
    createdAt: nowIso(),
    updatedAt: nowIso(),
  };
}

function normalizeNodeTemplateCreate(body = {}) {
  return {
    nodeName: String(body.nodeName || body.name || "").trim(),
    node_soil: normalizeNodeTemplatePart(body.node_soil || {}, "soil"),
    node_air: normalizeNodeTemplatePart(body.node_air || {}, "air"),
    status: String(body.status || "ACTIVE"),
    createdAt: nowIso(),
    updatedAt: nowIso(),
  };
}

function normalizeReadingCreate(body = {}) {
  return cleanUndefined({
    plotId: String(body.plotId || "").trim(),
    pinId: String(body.pinId || "").trim(),
    nodeId: String(body.nodeId || "").trim(),
    nodeUid: String(body.nodeUid || "").trim(),
    nodeType: String(body.nodeType || "").trim(),
    sensorId: String(body.sensorId || "").trim(),
    sensorType: String(body.sensorType || "").trim(),
    ts: String(body.ts || nowIso()),
    value: body.value,
    status: String(body.status || "OK"),
    raw: body.raw ?? null,
    createdAt: nowIso(),
    updatedAt: nowIso(),
  });
}

function normalizeUserCreate(body = {}) {
  return cleanUndefined({
    email: String(body.email || "").trim().toLowerCase(),
    password_hash: String(body.password_hash || ""),
    nickname: String(body.nickname || "").trim(),
    role: body.role === "owner" ? "owner" : "employee",
    provider: String(body.provider || "local"),
    createdAt: nowIso(),
    updatedAt: nowIso(),
  });
}

async function getCollectionItems(name) {
  const snap = await firestore.collection(name).get();
  return snap.docs.map((doc) => withId(doc.id, doc.data()));
}

async function getPlotById(plotId) {
  const doc = await firestore.collection(COLLECTIONS.plots).doc(String(plotId)).get();
  if (!doc.exists) return null;
  return withId(doc.id, doc.data());
}

async function getNodeTemplateById(nodeId) {
  const doc = await firestore.collection(COLLECTIONS.nodes).doc(String(nodeId)).get();
  if (!doc.exists) return null;
  return withId(doc.id, doc.data());
}

async function savePlot(plotId, data) {
  await firestore.collection(COLLECTIONS.plots).doc(String(plotId)).set(cleanUndefined(data), {
    merge: true,
  });
}

async function saveNodeTemplate(nodeId, data) {
  await firestore.collection(COLLECTIONS.nodes).doc(String(nodeId)).set(cleanUndefined(data), {
    merge: true,
  });
}

async function getUserByEmail(email) {
  const safeEmail = String(email || "").trim().toLowerCase();
  if (!safeEmail) return null;

  const snap = await firestore
    .collection(COLLECTIONS.users)
    .where("email", "==", safeEmail)
    .limit(1)
    .get();

  if (snap.empty) return null;
  const doc = snap.docs[0];
  return withId(doc.id, doc.data());
}

async function getUserByNickname(nickname) {
  const safeNickname = String(nickname || "").trim();
  if (!safeNickname) return null;

  const snap = await firestore
    .collection(COLLECTIONS.users)
    .where("nickname", "==", safeNickname)
    .limit(1)
    .get();

  if (snap.empty) return null;
  const doc = snap.docs[0];
  return withId(doc.id, doc.data());
}

async function createUser(data) {
  const payload = normalizeUserCreate(data || {});
  const ref = firestore.collection(COLLECTIONS.users).doc();
  await ref.set(payload);
  return withId(ref.id, payload);
}

function buildAuthToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      nickname: user.nickname,
      role: user.role,
      provider: user.provider || "local",
    },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function findNodeByIdInPin(pin, nodeId) {
  const safeId = String(nodeId || "").trim();
  if (!safeId) return null;

  const air = (pin?.node_air || []).find((x) => String(x.id) === safeId);
  if (air) return { nodeType: "air", node: air };

  const soil = (pin?.node_soil || []).find((x) => String(x.id) === safeId);
  if (soil) return { nodeType: "soil", node: soil };

  return null;
}

function findNodeByUidInPin(pin, uid) {
  const safeUid = String(uid || "").trim();
  if (!safeUid) return null;

  const air = (pin?.node_air || []).find((x) => String(x.uid || "") === safeUid);
  if (air) return { nodeType: "air", node: air };

  const soil = (pin?.node_soil || []).find((x) => String(x.uid || "") === safeUid);
  if (soil) return { nodeType: "soil", node: soil };

  return null;
}

function findSensorByIdInPin(pin, sensorId) {
  const safeId = String(sensorId || "").trim();
  if (!safeId) return null;

  for (const node of pin?.node_air || []) {
    const sensor = (node.sensors || []).find((s) => String(s.id) === safeId);
    if (sensor) return { nodeType: "air", node, sensor };
  }

  for (const node of pin?.node_soil || []) {
    const sensor = (node.sensors || []).find((s) => String(s.id) === safeId);
    if (sensor) return { nodeType: "soil", node, sensor };
  }

  return null;
}

async function findPlotAndPinByPinId(pinId) {
  const safeId = String(pinId || "").trim();
  if (!safeId) return { plot: null, pin: null };

  const snap = await firestore.collection(COLLECTIONS.plots).get();
  for (const doc of snap.docs) {
    const plot = withId(doc.id, doc.data());
    const pins = plot?.polygon?.pins || [];
    const pin = pins.find((p) => String(p.id) === safeId);
    if (pin) return { plot, pin };
  }
  return { plot: null, pin: null };
}

async function findPlotAndPinByNodeUid(nodeUid) {
  const safeUid = String(nodeUid || "").trim();
  if (!safeUid) return { plot: null, pin: null, node: null, nodeType: null };

  const snap = await firestore.collection(COLLECTIONS.plots).get();
  for (const doc of snap.docs) {
    const plot = withId(doc.id, doc.data());
    const pins = plot?.polygon?.pins || [];

    for (const pin of pins) {
      const match = findNodeByUidInPin(pin, safeUid);
      if (match?.node) {
        return {
          plot,
          pin,
          node: match.node,
          nodeType: match.nodeType,
        };
      }
    }
  }

  return { plot: null, pin: null, node: null, nodeType: null };
}

async function appendReadingAndUpdateLatest({ pinId, nodeUid, sensorId, sensorType, value, ts, status, raw }) {
  const safePinId = String(pinId || "").trim();
  const safeNodeUid = String(nodeUid || "").trim();
  const safeSensorId = String(sensorId || "").trim();
  const safeSensorType = String(sensorType || "").trim();

  let found = null;

  if (safePinId) {
    const byPin = await findPlotAndPinByPinId(safePinId);
    if (!byPin?.plot || !byPin?.pin) {
      const err = new Error("Pin not found");
      err.statusCode = 404;
      throw err;
    }
    found = {
      plot: byPin.plot,
      pin: byPin.pin,
    };
  } else if (safeNodeUid) {
    const byNodeUid = await findPlotAndPinByNodeUid(safeNodeUid);
    if (!byNodeUid?.plot || !byNodeUid?.pin) {
      const err = new Error("Node UID not found");
      err.statusCode = 404;
      throw err;
    }
    found = {
      plot: byNodeUid.plot,
      pin: byNodeUid.pin,
    };
  } else {
    const err = new Error("pinId or nodeUid is required");
    err.statusCode = 400;
    throw err;
  }

  let match = null;

  if (safeSensorId) {
    match = findSensorByIdInPin(found.pin, safeSensorId);
  } else if (safeNodeUid && safeSensorType) {
    const nodeMatch = findNodeByUidInPin(found.pin, safeNodeUid);
    if (nodeMatch?.node) {
      const sensor = (nodeMatch.node.sensors || []).find(
        (s) => String(s.sensorType) === safeSensorType
      );
      if (sensor) {
        match = {
          nodeType: nodeMatch.nodeType,
          node: nodeMatch.node,
          sensor,
        };
      }
    }
  }

  if (!match?.sensor || !match?.node) {
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

  const reading = normalizeReadingCreate({
    plotId: found.plot.id,
    pinId: found.pin.id,
    nodeId: match.node.id,
    nodeUid: match.node.uid || "",
    nodeType: match.nodeType,
    sensorId: match.sensor.id,
    sensorType: match.sensor.sensorType,
    value: num,
    ts: ts || nowIso(),
    status: status || "OK",
    raw,
  });

  const readingRef = firestore.collection(COLLECTIONS.readings).doc();
  await readingRef.set(reading);

  const plot = found.plot;
  const pins = [...(plot?.polygon?.pins || [])];
  const pinIdx = pins.findIndex((p) => String(p.id) === String(found.pin.id));
  if (pinIdx < 0) {
    const err = new Error("Pin not found");
    err.statusCode = 404;
    throw err;
  }

  const pin = normalizePin(pins[pinIdx]);

  const updateNodeList = (list = []) =>
    list.map((node) => {
      if (String(node.id) !== String(match.node.id)) return node;
      return {
        ...node,
        updatedAt: nowIso(),
        sensors: (node.sensors || []).map((s) => {
          if (String(s.id) !== String(match.sensor.id)) return s;
          return {
            ...s,
            value: num,
            status: String(status || "OK"),
            lastReadingAt: String(ts || reading.ts),
            lastReading: { value: num, ts: String(ts || reading.ts) },
          };
        }),
      };
    });

  if (match.nodeType === "air") {
    pin.node_air = updateNodeList(pin.node_air || []);
  } else {
    pin.node_soil = updateNodeList(pin.node_soil || []);
  }

  pin.updatedAt = nowIso();
  pins[pinIdx] = pin;
  plot.polygon.pins = pins;
  plot.updatedAt = nowIso();

  await savePlot(plot.id, plot);
  return withId(readingRef.id, reading);
}

app.post("/auth/register", async (req, res) => {
  const { email, password, nickname, role } = req.body || {};

  if (!email || !password || !nickname) {
    return res.status(400).json({ message: "email/password/nickname required" });
  }

  try {
    const safeEmail = String(email || "").trim().toLowerCase();
    const safeNickname = String(nickname || "").trim();

    const [dupEmail, dupNickname] = await Promise.all([
      getUserByEmail(safeEmail),
      getUserByNickname(safeNickname),
    ]);

    if (dupEmail || dupNickname) {
      return res.status(409).json({ message: "email or nickname already exists" });
    }

    const password_hash = await bcrypt.hash(String(password), 10);
    const user = await createUser({
      email: safeEmail,
      password_hash,
      nickname: safeNickname,
      role,
      provider: "local",
    });

    return res.status(201).json({
      message: "registered",
      user: {
        id: user.id,
        email: user.email,
        nickname: user.nickname,
        role: user.role,
        provider: user.provider,
      },
    });
  } catch (e) {
    return res.status(500).json({ message: "server error", error: String(e.message || e) });
  }
});

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ message: "email/password required" });
  }

  try {
    const safeEmail = String(email || "").trim().toLowerCase();
    const user = await getUserByEmail(safeEmail);

    if (!user || !user.password_hash) {
      return res.status(401).json({ message: "invalid credentials" });
    }

    const ok = await bcrypt.compare(String(password), user.password_hash);
    if (!ok) return res.status(401).json({ message: "invalid credentials" });

    const token = buildAuthToken(user);

    return res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        nickname: user.nickname,
        role: user.role,
        provider: user.provider || "local",
      },
    });
  } catch (e) {
    return res
      .status(500)
      .json({ message: "server error", error: String(e.message || e) });
  }
});
app.post("/auth/forgot", async (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    if (!email) {
      return res.status(400).json({ message: "email required" });
    }

    const user = await getUserByEmail(email);

    // ป้องกันการเดา email ว่ามีในระบบไหม
    if (!user) {
      return res.json({
        ok: true,
        message: "If this email exists, OTP has been sent",
      });
    }

    if (!process.env.MAIL_USER || !process.env.MAIL_PASS) {
      return res.status(500).json({
        message: "Mail service is not configured",
      });
    }

    const otp = generateOtp();
    await savePasswordOtp(email, otp);
    await sendOtpEmail(email, otp);

    return res.json({
      ok: true,
      message: "OTP has been sent to your email",
    });
  } catch (e) {
    return res.status(500).json({
      message: "Failed to send OTP",
      error: String(e.message || e),
    });
  }
});

app.post("/auth/verify-otp", async (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const code = String(req.body?.code || "").trim();

    if (!email || !code) {
      return res.status(400).json({ message: "email/code required" });
    }

    const otpDoc = await getPasswordOtp(email);
    if (!otpDoc) {
      return res.status(400).json({ message: "OTP not found" });
    }

    if (Date.now() > Number(otpDoc.expiresAt || 0)) {
      await deletePasswordOtp(email);
      return res.status(400).json({ message: "OTP expired" });
    }

    if (String(otpDoc.code) !== code) {
      return res.status(400).json({ message: "OTP invalid" });
    }

    await markPasswordOtpVerified(email);

    return res.json({
      ok: true,
      message: "OTP verified",
    });
  } catch (e) {
    return res.status(500).json({
      message: "Verify OTP failed",
      error: String(e.message || e),
    });
  }
});

app.post("/auth/reset-password", async (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const code = String(req.body?.code || "").trim();
    const newPassword = String(req.body?.newPassword || "");

    if (!email || !code || !newPassword) {
      return res.status(400).json({
        message: "email/code/newPassword required",
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({
        message: "Password must be at least 6 characters",
      });
    }

    const user = await getUserByEmail(email);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const otpDoc = await getPasswordOtp(email);
    if (!otpDoc) {
      return res.status(400).json({ message: "OTP not found" });
    }

    if (Date.now() > Number(otpDoc.expiresAt || 0)) {
      await deletePasswordOtp(email);
      return res.status(400).json({ message: "OTP expired" });
    }

    if (String(otpDoc.code) !== code) {
      return res.status(400).json({ message: "OTP invalid" });
    }

    if (!otpDoc.verified) {
      return res.status(400).json({ message: "OTP not verified yet" });
    }

    const password_hash = await bcrypt.hash(newPassword, 10);

    await firestore.collection(COLLECTIONS.users).doc(String(user.id)).set(
      {
        password_hash,
        updatedAt: nowIso(),
      },
      { merge: true }
    );

    await deletePasswordOtp(email);

    return res.json({
      ok: true,
      message: "Password reset successful",
    });
  } catch (e) {
    return res.status(500).json({
      message: "Reset password failed",
      error: String(e.message || e),
    });
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
app.get("/auth/me", auth, async (req, res) => {
  res.json({ user: req.user });
});

app.get("/auth/google/start", (req, res) => {
  try {
    const url = googleOAuth2Client.generateAuthUrl({
      access_type: "offline",
      prompt: "consent",
      scope: ["openid", "email", "profile"],
    });

    return res.redirect(url);
  } catch (e) {
    return res
      .status(500)
      .json({ message: "Google auth start failed", error: String(e.message || e) });
  }
});

app.get("/auth/google/callback", async (req, res) => {
  try {
    const code = req.query.code;
    if (!code) return res.status(400).json({ message: "Missing code" });

    const { tokens } = await googleOAuth2Client.getToken(String(code));
    googleOAuth2Client.setCredentials(tokens);

    const oauth2 = google.oauth2({ auth: googleOAuth2Client, version: "v2" });
    const me = await oauth2.userinfo.get();

    const email = String(me?.data?.email || "").trim().toLowerCase();
    if (!email) {
      return res.status(400).json({ message: "Google account has no email" });
    }

    let user = await getUserByEmail(email);

    if (!user) {
      let nickname = makeSafeNickname(me?.data?.name, email);
      const exists = await getUserByNickname(nickname);
      if (exists) {
        nickname = `${nickname}_${Date.now().toString().slice(-6)}`.slice(0, 100);
      }

      user = await createUser({
        email,
        password_hash: "",
        nickname,
        role: "employee",
        provider: "google",
      });
    }

    const token = buildAuthToken(user);

    const redirectBase = process.env.FRONTEND_URL || "http://localhost:3000";

    return res.redirect(
      `${redirectBase}/login?token=${encodeURIComponent(token)}`
    );
  } catch (e) {
    const redirectBase = process.env.FRONTEND_URL || "http://localhost:3000";
    return res.redirect(
      `${redirectBase}/login?error=${encodeURIComponent(
        e?.message || "Google auth failed"
      )}`
    );
  }
});

api.use(auth);
api.get("/users", async (req, res, next) => {
  try {
    const role = String(req.query.role || "").trim().toLowerCase();

    let ref = firestore.collection(COLLECTIONS.users);

    if (role) {
      ref = ref.where("role", "==", role);
    }

    const snap = await ref.get();

    const items = snap.docs.map((doc) => {
      const data = doc.data() || {};
      return {
        id: doc.id,
        email: String(data.email || "").trim(),
        nickname: String(data.nickname || "").trim(),
        role: String(data.role || "").trim(),
        provider: String(data.provider || "").trim(),
        createdAt: data.createdAt || "",
        updatedAt: data.updatedAt || "",
      };
    });

    res.json({ items });
  } catch (e) {
    next(e);
  }
});

api.get("/nodes", async (req, res, next) => {
  try {
    const items = await getCollectionItems(COLLECTIONS.nodes);
    res.json({ items });
  } catch (e) {
    next(e);
  }
});

api.post("/nodes", async (req, res, next) => {
  try {
    const data = normalizeNodeTemplateCreate(req.body || {});
    if (!data.nodeName) {
      return res.status(400).json({ message: "nodeName is required" });
    }

    const dup = await firestore
      .collection(COLLECTIONS.nodes)
      .where("nodeName", "==", data.nodeName)
      .limit(1)
      .get();

    if (!dup.empty) {
      return res.status(409).json({ message: "nodeName already exists" });
    }

    const ref = firestore.collection(COLLECTIONS.nodes).doc();
    await ref.set(data);
    res.status(201).json({ item: withId(ref.id, data) });
  } catch (e) {
    next(e);
  }
});

api.get("/nodes/:nodeId", async (req, res, next) => {
  try {
    const nodeId = requireId(res, req.params.nodeId, "nodeId");
    if (!nodeId) return;
    const item = await getNodeTemplateById(nodeId);
    if (!item) return res.status(404).json({ message: "NodeTemplate not found" });
    res.json({ item });
  } catch (e) {
    next(e);
  }
});

api.patch("/nodes/:nodeId", async (req, res, next) => {
  try {
    const nodeId = requireId(res, req.params.nodeId, "nodeId");
    if (!nodeId) return;

    const current = await getNodeTemplateById(nodeId);
    if (!current) return res.status(404).json({ message: "NodeTemplate not found" });

    const b = req.body || {};
    const update = {
      ...current,
      updatedAt: nowIso(),
    };

    if (b.nodeName !== undefined) update.nodeName = String(b.nodeName || "").trim();
    if (b.node_soil !== undefined) {
      update.node_soil = normalizeNodeTemplatePart(b.node_soil || {}, "soil");
    }
    if (b.node_air !== undefined) {
      update.node_air = normalizeNodeTemplatePart(b.node_air || {}, "air");
    }
    if (b.status !== undefined) update.status = b.status;

    await saveNodeTemplate(nodeId, update);
    res.json({ item: withId(nodeId, update) });
  } catch (e) {
    next(e);
  }
});

api.delete("/nodes/:nodeId", async (req, res, next) => {
  try {
    const nodeId = requireId(res, req.params.nodeId, "nodeId");
    if (!nodeId) return;
    await firestore.collection(COLLECTIONS.nodes).doc(nodeId).delete();
    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

api.get("/plots", async (req, res, next) => {
  try {
    const items = await getCollectionItems(COLLECTIONS.plots);
    res.json({ items });
  } catch (e) {
    next(e);
  }
});

api.post("/plots", async (req, res, next) => {
  try {
    const data = normalizePlotCreate(req.body || {});
    const ref = firestore.collection(COLLECTIONS.plots).doc();
    await ref.set(data);
    res.status(201).json({ item: withId(ref.id, data) });
  } catch (e) {
    next(e);
  }
});

api.get("/plots/:plotId", async (req, res, next) => {
  try {
    const plotId = requireId(res, req.params.plotId, "plotId");
    if (!plotId) return;
    const item = await getPlotById(plotId);
    if (!item) return res.status(404).json({ message: "Plot not found" });
    res.json({ item });
  } catch (e) {
    next(e);
  }
});

api.get("/plots/:plotId/full", async (req, res, next) => {
  try {
    const plotId = requireId(res, req.params.plotId, "plotId");
    if (!plotId) return;
    const item = await getPlotById(plotId);
    if (!item) return res.status(404).json({ message: "Plot not found" });
    res.json({ item });
  } catch (e) {
    next(e);
  }
});

api.patch("/plots/:plotId", async (req, res, next) => {
  try {
    const plotId = requireId(res, req.params.plotId, "plotId");
    if (!plotId) return;

    const current = await getPlotById(plotId);
    if (!current) return res.status(404).json({ message: "Plot not found" });

    const b = req.body || {};
    const update = {
      ...current,
      updatedAt: nowIso(),
    };

    if (b.alias !== undefined) update.alias = String(b.alias || "");
    if (b.plotName !== undefined) update.plotName = String(b.plotName || "");
    if (b.name !== undefined) update.name = String(b.name || "");
    if (b.caretaker !== undefined) update.caretaker = String(b.caretaker || "");
    if (b.ownerName !== undefined) update.ownerName = String(b.ownerName || "");
    if (b.plantType !== undefined) update.plantType = String(b.plantType || "");
    if (b.cropType !== undefined) update.cropType = String(b.cropType || "");
    if (b.plantedAt !== undefined) update.plantedAt = String(b.plantedAt || "");
    if (b.status !== undefined) update.status = String(b.status || "ACTIVE");
    if (b.topics !== undefined || b.topicAll !== undefined || b.Topic_all !== undefined) {
      update.topics = normalizeTopics(b.topics || b.topicAll || b.Topic_all || []);
    }
    if (b.polygon !== undefined) update.polygon = normalizePolygon(b.polygon || {});

    await savePlot(plotId, update);
    res.json({ item: withId(plotId, update) });
  } catch (e) {
    next(e);
  }
});

api.delete("/plots/:plotId", async (req, res, next) => {
  try {
    const plotId = requireId(res, req.params.plotId, "plotId");
    if (!plotId) return;
    await firestore.collection(COLLECTIONS.plots).doc(plotId).delete();
    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

api.get("/plots/:plotId/topics", async (req, res, next) => {
  try {
    const plotId = requireId(res, req.params.plotId, "plotId");
    if (!plotId) return;

    const plot = await getPlotById(plotId);
    if (!plot) return res.status(404).json({ message: "Plot not found" });

    res.json({ items: normalizeTopics(plot.topics || []) });
  } catch (e) {
    next(e);
  }
});

api.put("/plots/:plotId/topics", async (req, res, next) => {
  try {
    const plotId = requireId(res, req.params.plotId, "plotId");
    if (!plotId) return;

    const plot = await getPlotById(plotId);
    if (!plot) return res.status(404).json({ message: "Plot not found" });

    plot.topics = normalizeTopics(req.body?.topics || req.body?.items || []);
    plot.updatedAt = nowIso();

    await savePlot(plotId, plot);
    res.json({ items: plot.topics });
  } catch (e) {
    next(e);
  }
});

api.get("/plots/:plotId/polygon", async (req, res, next) => {
  try {
    const plotId = requireId(res, req.params.plotId, "plotId");
    if (!plotId) return;

    const plot = await getPlotById(plotId);
    if (!plot) return res.status(404).json({ message: "Plot not found" });

    res.json({ item: normalizePolygon(plot.polygon || {}) });
  } catch (e) {
    next(e);
  }
});

api.put("/plots/:plotId/polygon", async (req, res, next) => {
  try {
    const plotId = requireId(res, req.params.plotId, "plotId");
    if (!plotId) return;

    const plot = await getPlotById(plotId);
    if (!plot) return res.status(404).json({ message: "Plot not found" });

    plot.polygon = normalizePolygon(req.body || {});
    plot.updatedAt = nowIso();

    await savePlot(plotId, plot);
    res.json({ item: plot.polygon });
  } catch (e) {
    next(e);
  }
});

api.get("/plots/:plotId/pins", async (req, res, next) => {
  try {
    const plotId = requireId(res, req.params.plotId, "plotId");
    if (!plotId) return;

    const plot = await getPlotById(plotId);
    if (!plot) return res.status(404).json({ message: "Plot not found" });

    res.json({ items: (plot?.polygon?.pins || []).map(normalizePin) });
  } catch (e) {
    next(e);
  }
});

api.post("/plots/:plotId/pins", async (req, res, next) => {
  try {
    const plotId = requireId(res, req.params.plotId, "plotId");
    if (!plotId) return;

    const plot = await getPlotById(plotId);
    if (!plot) return res.status(404).json({ message: "Plot not found" });

    const pins = [...(plot?.polygon?.pins || [])];
    const pin = normalizePin(req.body || {}, pins.length);
    pins.push(pin);

    plot.polygon = normalizePolygon({ ...(plot.polygon || {}), pins });
    plot.updatedAt = nowIso();

    await savePlot(plotId, plot);
    res.status(201).json({ item: pin });
  } catch (e) {
    next(e);
  }
});

api.get("/pins/:pinId", async (req, res, next) => {
  try {
    const pinId = requireId(res, req.params.pinId, "pinId");
    if (!pinId) return;

    const { plot, pin } = await findPlotAndPinByPinId(pinId);
    if (!plot || !pin) return res.status(404).json({ message: "Pin not found" });

    res.json({ item: normalizePin(pin) });
  } catch (e) {
    next(e);
  }
});

api.patch("/pins/:pinId", async (req, res, next) => {
  try {
    const pinId = requireId(res, req.params.pinId, "pinId");
    if (!pinId) return;

    const { plot, pin } = await findPlotAndPinByPinId(pinId);
    if (!plot || !pin) return res.status(404).json({ message: "Pin not found" });

    const pins = [...(plot?.polygon?.pins || [])];
    const idx = pins.findIndex((p) => String(p.id) === String(pin.id));
    if (idx < 0) return res.status(404).json({ message: "Pin not found" });

    const current = normalizePin(pins[idx], idx);
    const b = req.body || {};

    if (b.number !== undefined) current.number = Number(b.number);
    if (b.pinName !== undefined) current.pinName = String(b.pinName || "").trim();
    if (b.name !== undefined) current.pinName = String(b.name || "").trim();
    if (b.lat !== undefined) current.lat = Number(b.lat);
    if (b.lng !== undefined) current.lng = Number(b.lng);
    if (b.node_air !== undefined) current.node_air = normalizePinNodeArray(b.node_air, "air");
    if (b.node_soil !== undefined) current.node_soil = normalizePinNodeArray(b.node_soil, "soil");
    current.updatedAt = nowIso();

    pins[idx] = current;
    plot.polygon.pins = pins;
    plot.updatedAt = nowIso();

    await savePlot(plot.id, plot);
    res.json({ item: current });
  } catch (e) {
    next(e);
  }
});

api.delete("/pins/:pinId", async (req, res, next) => {
  try {
    const pinId = requireId(res, req.params.pinId, "pinId");
    if (!pinId) return;

    const { plot, pin } = await findPlotAndPinByPinId(pinId);
    if (!plot || !pin) return res.status(404).json({ message: "Pin not found" });

    plot.polygon.pins = (plot?.polygon?.pins || []).filter(
      (p) => String(p.id) !== String(pin.id)
    );
    plot.updatedAt = nowIso();

    await savePlot(plot.id, plot);
    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

api.patch("/pins/:pinId/node", async (req, res, next) => {
  try {
    const pinId = requireId(res, req.params.pinId, "pinId");
    if (!pinId) return;

    const { plot, pin } = await findPlotAndPinByPinId(pinId);
    if (!plot || !pin) return res.status(404).json({ message: "Pin not found" });

    const pins = [...(plot?.polygon?.pins || [])];
    const idx = pins.findIndex((p) => String(p.id) === String(pin.id));
    if (idx < 0) return res.status(404).json({ message: "Pin not found" });

    const current = normalizePin(pins[idx], idx);
    const b = req.body || {};

    if (b.node_air !== undefined) current.node_air = normalizePinNodeArray(b.node_air, "air");
    if (b.node_soil !== undefined) current.node_soil = normalizePinNodeArray(b.node_soil, "soil");
    current.updatedAt = nowIso();

    pins[idx] = current;
    plot.polygon.pins = pins;
    plot.updatedAt = nowIso();

    await savePlot(plot.id, plot);
    res.json({ item: current });
  } catch (e) {
    next(e);
  }
});

api.get("/pins/:pinId/node", async (req, res, next) => {
  try {
    const pinId = requireId(res, req.params.pinId, "pinId");
    if (!pinId) return;

    const { plot, pin } = await findPlotAndPinByPinId(pinId);
    if (!plot || !pin) return res.status(404).json({ message: "Pin not found" });

    res.json({
      item: {
        node_air: pin.node_air || [],
        node_soil: pin.node_soil || [],
      },
    });
  } catch (e) {
    next(e);
  }
});

api.get("/pins/:pinId/node-air", async (req, res, next) => {
  try {
    const pinId = requireId(res, req.params.pinId, "pinId");
    if (!pinId) return;

    const { plot, pin } = await findPlotAndPinByPinId(pinId);
    if (!plot || !pin) return res.status(404).json({ message: "Pin not found" });

    res.json({ items: pin.node_air || [] });
  } catch (e) {
    next(e);
  }
});

api.get("/pins/:pinId/node-soil", async (req, res, next) => {
  try {
    const pinId = requireId(res, req.params.pinId, "pinId");
    if (!pinId) return;

    const { plot, pin } = await findPlotAndPinByPinId(pinId);
    if (!plot || !pin) return res.status(404).json({ message: "Pin not found" });

    res.json({ items: pin.node_soil || [] });
  } catch (e) {
    next(e);
  }
});

api.post("/pins/:pinId/node-air", async (req, res, next) => {
  try {
    const pinId = requireId(res, req.params.pinId, "pinId");
    if (!pinId) return;

    const { plot, pin } = await findPlotAndPinByPinId(pinId);
    if (!plot || !pin) return res.status(404).json({ message: "Pin not found" });

    const pins = [...(plot?.polygon?.pins || [])];
    const idx = pins.findIndex((p) => String(p.id) === String(pin.id));
    if (idx < 0) return res.status(404).json({ message: "Pin not found" });

    const current = normalizePin(pins[idx], idx);
    const item = normalizePinNode(req.body || {}, "air");
    current.node_air = [...(current.node_air || []), item];
    current.updatedAt = nowIso();

    pins[idx] = current;
    plot.polygon.pins = pins;
    plot.updatedAt = nowIso();

    await savePlot(plot.id, plot);
    res.status(201).json({ item });
  } catch (e) {
    next(e);
  }
});

api.post("/pins/:pinId/node-soil", async (req, res, next) => {
  try {
    const pinId = requireId(res, req.params.pinId, "pinId");
    if (!pinId) return;

    const { plot, pin } = await findPlotAndPinByPinId(pinId);
    if (!plot || !pin) return res.status(404).json({ message: "Pin not found" });

    const pins = [...(plot?.polygon?.pins || [])];
    const idx = pins.findIndex((p) => String(p.id) === String(pin.id));
    if (idx < 0) return res.status(404).json({ message: "Pin not found" });

    const current = normalizePin(pins[idx], idx);
    const item = normalizePinNode(req.body || {}, "soil");
    current.node_soil = [...(current.node_soil || []), item];
    current.updatedAt = nowIso();

    pins[idx] = current;
    plot.polygon.pins = pins;
    plot.updatedAt = nowIso();

    await savePlot(plot.id, plot);
    res.status(201).json({ item });
  } catch (e) {
    next(e);
  }
});

api.patch("/pins/:pinId/nodes/:nodeId", async (req, res, next) => {
  try {
    const pinId = requireId(res, req.params.pinId, "pinId");
    const nodeId = requireId(res, req.params.nodeId, "nodeId");
    if (!pinId || !nodeId) return;

    const { plot, pin } = await findPlotAndPinByPinId(pinId);
    if (!plot || !pin) return res.status(404).json({ message: "Pin not found" });

    const pins = [...(plot?.polygon?.pins || [])];
    const pinIdx = pins.findIndex((p) => String(p.id) === String(pin.id));
    if (pinIdx < 0) return res.status(404).json({ message: "Pin not found" });

    const currentPin = normalizePin(pins[pinIdx], pinIdx);
    const current = findNodeByIdInPin(currentPin, nodeId);
    if (!current?.node) return res.status(404).json({ message: "Node not found" });

    const b = req.body || {};
    const patchNode = (node) => {
      const updated = { ...node, updatedAt: nowIso() };
      if (b.uid !== undefined) updated.uid = String(b.uid || "").trim();
      if (b.templateId !== undefined) updated.templateId = b.templateId ? String(b.templateId) : null;
      if (b.nodeName !== undefined) updated.nodeName = String(b.nodeName || "").trim();
      if (b.name !== undefined) updated.nodeName = String(b.name || "").trim();
      if (b.sensors !== undefined) updated.sensors = (b.sensors || []).map(normalizeSensor);
      return updated;
    };

    if (current.nodeType === "air") {
      currentPin.node_air = (currentPin.node_air || []).map((n) =>
        String(n.id) === String(nodeId) ? patchNode(n) : n
      );
    } else {
      currentPin.node_soil = (currentPin.node_soil || []).map((n) =>
        String(n.id) === String(nodeId) ? patchNode(n) : n
      );
    }

    currentPin.updatedAt = nowIso();
    pins[pinIdx] = currentPin;
    plot.polygon.pins = pins;
    plot.updatedAt = nowIso();

    await savePlot(plot.id, plot);
    const updatedNode = findNodeByIdInPin(currentPin, nodeId);
    res.json({ item: updatedNode?.node || null });
  } catch (e) {
    next(e);
  }
});

api.delete("/pins/:pinId/nodes/:nodeId", async (req, res, next) => {
  try {
    const pinId = requireId(res, req.params.pinId, "pinId");
    const nodeId = requireId(res, req.params.nodeId, "nodeId");
    if (!pinId || !nodeId) return;

    const { plot, pin } = await findPlotAndPinByPinId(pinId);
    if (!plot || !pin) return res.status(404).json({ message: "Pin not found" });

    const pins = [...(plot?.polygon?.pins || [])];
    const pinIdx = pins.findIndex((p) => String(p.id) === String(pin.id));
    if (pinIdx < 0) return res.status(404).json({ message: "Pin not found" });

    const currentPin = normalizePin(pins[pinIdx], pinIdx);
    currentPin.node_air = (currentPin.node_air || []).filter((n) => String(n.id) !== String(nodeId));
    currentPin.node_soil = (currentPin.node_soil || []).filter((n) => String(n.id) !== String(nodeId));
    currentPin.updatedAt = nowIso();

    pins[pinIdx] = currentPin;
    plot.polygon.pins = pins;
    plot.updatedAt = nowIso();

    await savePlot(plot.id, plot);
    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

api.get("/pins/:pinId/sensors", async (req, res, next) => {
  try {
    const pinId = requireId(res, req.params.pinId, "pinId");
    if (!pinId) return;

    const { plot, pin } = await findPlotAndPinByPinId(pinId);
    if (!plot || !pin) return res.status(404).json({ message: "Pin not found" });

    const items = [
      ...(pin.node_air || []).flatMap((node) =>
        (node.sensors || []).map((sensor) => ({ ...sensor, nodeId: node.id, nodeUid: node.uid || "", nodeType: "air" }))
      ),
      ...(pin.node_soil || []).flatMap((node) =>
        (node.sensors || []).map((sensor) => ({ ...sensor, nodeId: node.id, nodeUid: node.uid || "", nodeType: "soil" }))
      ),
    ];

    res.json({ items });
  } catch (e) {
    next(e);
  }
});

api.patch("/sensors/:sensorId", async (req, res, next) => {
  try {
    const sensorId = requireId(res, req.params.sensorId, "sensorId");
    if (!sensorId) return;

    const plots = await getCollectionItems(COLLECTIONS.plots);
    for (const plot of plots) {
      const pins = [...(plot?.polygon?.pins || [])];
      let touched = false;

      const updatedPins = pins.map((pin, pinIndex) => {
        const currentPin = normalizePin(pin, pinIndex);

        const patchNodeList = (list = []) =>
          list.map((node) => ({
            ...node,
            sensors: (node.sensors || []).map((sensor) => {
              if (String(sensor.id) !== String(sensorId)) return sensor;
              touched = true;
              const next = { ...sensor };
              const b = req.body || {};
              if (b.sensorType !== undefined) next.sensorType = String(b.sensorType || "").trim();
              if (b.name !== undefined) next.name = String(b.name || "").trim();
              if (b.unit !== undefined) next.unit = String(b.unit || "").trim();
              if (b.value !== undefined) next.value = b.value;
              if (b.valueHint !== undefined) next.valueHint = b.valueHint ?? "";
              if (b.status !== undefined) next.status = String(b.status || "OK");
              if (b.lastReadingAt !== undefined) next.lastReadingAt = b.lastReadingAt;
              if (b.lastReading !== undefined) next.lastReading = b.lastReading;
              return normalizeSensor(next);
            }),
          }));

        currentPin.node_air = patchNodeList(currentPin.node_air || []);
        currentPin.node_soil = patchNodeList(currentPin.node_soil || []);
        if (touched) currentPin.updatedAt = nowIso();
        return currentPin;
      });

      if (touched) {
        plot.polygon.pins = updatedPins;
        plot.updatedAt = nowIso();
        await savePlot(plot.id, plot);

        const fresh = await getPlotById(plot.id);
        const pin = (fresh?.polygon?.pins || []).find((p) =>
          findSensorByIdInPin(p, sensorId)?.sensor
        );
        const match = pin ? findSensorByIdInPin(pin, sensorId) : null;
        return res.json({ item: match?.sensor || null });
      }
    }

    return res.status(404).json({ message: "Sensor not found" });
  } catch (e) {
    next(e);
  }
});

api.get("/sensors", async (req, res, next) => {
  try {
    const items = [];
    const plots = await getCollectionItems(COLLECTIONS.plots);

    for (const plot of plots) {
      for (const pin of plot?.polygon?.pins || []) {
        for (const node of pin.node_air || []) {
          for (const sensor of node.sensors || []) {
            items.push({
              ...sensor,
              plotId: plot.id,
              pinId: pin.id,
              nodeId: node.id,
              nodeUid: node.uid || "",
              nodeType: "air",
            });
          }
        }
        for (const node of pin.node_soil || []) {
          for (const sensor of node.sensors || []) {
            items.push({
              ...sensor,
              plotId: plot.id,
              pinId: pin.id,
              nodeId: node.id,
              nodeUid: node.uid || "",
              nodeType: "soil",
            });
          }
        }
      }
    }

    res.json({ items });
  } catch (e) {
    next(e);
  }
});

api.post("/readings", async (req, res, next) => {
  try {
    const item = await appendReadingAndUpdateLatest(req.body || {});
    res.status(201).json({ item });
  } catch (e) {
    next(e);
  }
});

api.post("/ingest/reading", async (req, res, next) => {
  try {
    const item = await appendReadingAndUpdateLatest(req.body || {});
    res.status(201).json({ item });
  } catch (e) {
    next(e);
  }
});

api.get("/readings", async (req, res, next) => {
  try {
    const items = await getCollectionItems(COLLECTIONS.readings);
    res.json({ items });
  } catch (e) {
    next(e);
  }
});

api.get("/plots/:plotId/summary", async (req, res, next) => {
  try {
    const plotId = requireId(res, req.params.plotId, "plotId");
    if (!plotId) return;

    const plot = await getPlotById(plotId);
    if (!plot) return res.status(404).json({ message: "Plot not found" });

    const pins = plot?.polygon?.pins || [];
    const nodeAirCount = pins.reduce((sum, pin) => sum + (pin.node_air || []).length, 0);
    const nodeSoilCount = pins.reduce((sum, pin) => sum + (pin.node_soil || []).length, 0);
    const sensorCount = pins.reduce(
      (sum, pin) =>
        sum +
        (pin.node_air || []).reduce((a, n) => a + (n.sensors || []).length, 0) +
        (pin.node_soil || []).reduce((a, n) => a + (n.sensors || []).length, 0),
      0
    );

    res.json({
      item: {
        plotId: plot.id,
        plotName: plot.plotName || plot.name || "",
        pinCount: pins.length,
        nodeAirCount,
        nodeSoilCount,
        sensorCount,
      },
    });
  } catch (e) {
    next(e);
  }
});

app.use("/api", api);

app.use((req, res) => {
  res.status(404).json({ message: `Cannot ${req.method} ${req.originalUrl}` });
});

app.use((err, req, res, next) => {
  console.error("[ERROR]", err);
  const status = Number(err?.statusCode || err?.status || 500);
  res.status(status).json({
    message: status >= 500 ? "Internal Server Error" : err.message || "Request failed",
    error: String(err?.message || err),
  });
});

const PORT = Number(process.env.PORT || 3001);
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});