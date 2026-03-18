require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { google } = require("googleapis");
const admin = require("firebase-admin");
const { sql, getPool } = require("./db");

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

const BUILD_TAG = "firestore-pin-multi-node-v2";
const COLLECTIONS = {
  plots: "plots",
  nodes: "nodeTemplates",
  readings: "sensorReadings",
};

console.log("========================================");
console.log("[SERVER] BUILD:", BUILD_TAG);
console.log("[SERVER] FILE :", __filename);
console.log("[SERVER] CWD  :", process.cwd());
console.log("========================================");

app.use(cors());
app.use(express.json({ limit: "2mb" }));

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
    .map((pair) => {
      if (!Array.isArray(pair) || pair.length < 2) return null;
      const lat = Number(pair[0]);
      const lng = Number(pair[1]);
      if (!Number.isFinite(lat) || !Number.isFinite(lng)) return null;
      return [lat, lng];
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
    nodeName: String(body.nodeName || "").trim(),
    node_soil: normalizeNodeTemplatePart(body.node_soil || {}, "soil"),
    node_air: normalizeNodeTemplatePart(body.node_air || {}, "air"),
    status: String(body.status || "ACTIVE"),
    createdAt: nowIso(),
    updatedAt: nowIso(),
  };
}

function normalizeReadingCreate(body = {}) {
  return cleanUndefined({
    plotId: String(body.plotId || ""),
    pinId: String(body.pinId || ""),
    nodeId: String(body.nodeId || ""),
    nodeType: String(body.nodeType || ""),
    sensorId: String(body.sensorId || ""),
    sensorType: String(body.sensorType || ""),
    ts: String(body.ts || nowIso()),
    value: Number(body.value),
    status: String(body.status || "OK"),
    raw: body.raw,
    createdAt: nowIso(),
    updatedAt: nowIso(),
  });
}

async function getCollectionItems(name, orderByField = "createdAt", direction = "desc") {
  const snap = await firestore.collection(name).orderBy(orderByField, direction).get();
  return snap.docs.map((d) => withId(d.id, d.data()));
}

async function getPlotById(plotId) {
  const snap = await firestore.collection(COLLECTIONS.plots).doc(String(plotId)).get();
  if (!snap.exists) return null;
  return withId(snap.id, snap.data());
}

async function getNodeTemplateById(nodeId) {
  const snap = await firestore.collection(COLLECTIONS.nodes).doc(String(nodeId)).get();
  if (!snap.exists) return null;
  return withId(snap.id, snap.data());
}

async function findPlotByPinId(pinId) {
  const plots = await firestore.collection(COLLECTIONS.plots).get();
  for (const doc of plots.docs) {
    const plot = withId(doc.id, doc.data());
    const pin = plot?.polygon?.pins?.find((p) => String(p.id) === String(pinId));
    if (pin) return { plot, pin };
  }
  return null;
}

function makePinNodeFromTemplatePart(part, type, templateId, fallbackName) {
  if (!part) return null;
  return normalizePinNode(
    {
      templateId,
      nodeType: type,
      nodeName: part.nodeName || fallbackName || "",
      sensors: part.sensors || [],
    },
    type
  );
}

function applyTemplateToPin(pin, templateDoc) {
  const next = normalizePin(pin);

  if (!Array.isArray(next.node_air)) next.node_air = [];
  if (!Array.isArray(next.node_soil)) next.node_soil = [];

  const airNode = makePinNodeFromTemplatePart(
    templateDoc?.node_air,
    "air",
    templateDoc?.id || templateDoc?._id || null,
    templateDoc?.nodeName || "Node Air"
  );
  const soilNode = makePinNodeFromTemplatePart(
    templateDoc?.node_soil,
    "soil",
    templateDoc?.id || templateDoc?._id || null,
    templateDoc?.nodeName || "Node Soil"
  );

  if (airNode && airNode.sensors?.length) next.node_air.push(airNode);
  if (soilNode && soilNode.sensors?.length) next.node_soil.push(soilNode);

  next.updatedAt = nowIso();
  return next;
}

function flattenSensorsFromPin(pin, plotId) {
  const items = [];

  for (const node of pin?.node_air || []) {
    for (const s of node?.sensors || []) {
      items.push({
        ...s,
        pinId: String(pin.id),
        plotId: String(plotId),
        nodeId: String(node.id),
        nodeName: node.nodeName || "",
        nodeType: "air",
      });
    }
  }

  for (const node of pin?.node_soil || []) {
    for (const s of node?.sensors || []) {
      items.push({
        ...s,
        pinId: String(pin.id),
        plotId: String(plotId),
        nodeId: String(node.id),
        nodeName: node.nodeName || "",
        nodeType: "soil",
      });
    }
  }

  return items;
}

function findNodeByIdInPin(pin, nodeId) {
  const air = (pin?.node_air || []).find((n) => String(n.id) === String(nodeId));
  if (air) return { nodeType: "air", node: air };

  const soil = (pin?.node_soil || []).find((n) => String(n.id) === String(nodeId));
  if (soil) return { nodeType: "soil", node: soil };

  return null;
}

function findSensorByIdInPin(pin, sensorId) {
  for (const node of pin?.node_air || []) {
    const sensor = (node?.sensors || []).find((s) => String(s.id) === String(sensorId));
    if (sensor) return { nodeType: "air", node, sensor };
  }

  for (const node of pin?.node_soil || []) {
    const sensor = (node?.sensors || []).find((s) => String(s.id) === String(sensorId));
    if (sensor) return { nodeType: "soil", node, sensor };
  }

  return null;
}

function findSensorByTypeInPin(pin, nodeType, sensorType) {
  const list = nodeType === "air" ? pin?.node_air || [] : pin?.node_soil || [];
  for (const node of list) {
    const sensor = (node?.sensors || []).find(
      (s) => String(s.sensorType) === String(sensorType)
    );
    if (sensor) return { node, sensor };
  }
  return null;
}

async function saveNodeTemplate(nodeId, data) {
  await firestore
    .collection(COLLECTIONS.nodes)
    .doc(String(nodeId))
    .set(cleanUndefined(data), { merge: true });
}

async function savePlot(plotId, data) {
  await firestore
    .collection(COLLECTIONS.plots)
    .doc(String(plotId))
    .set(cleanUndefined(data), { merge: true });
}

async function createReadingAndUpdateNode({ pinId, sensorId, value, ts, status, raw }) {
  const safePinId = String(pinId || "").trim();
  const safeSensorId = String(sensorId || "").trim();
  if (!safePinId) throw new Error("Invalid pinId");
  if (!safeSensorId) throw new Error("Invalid sensorId");

  const found = await findPlotByPinId(safePinId);
  if (!found?.pin) {
    const err = new Error("Pin not found");
    err.statusCode = 404;
    throw err;
  }

  const match = findSensorByIdInPin(found.pin, safeSensorId);
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
    pinId: safePinId,
    nodeId: match.node.id,
    nodeType: match.nodeType,
    sensorId: safeSensorId,
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
  const pinIdx = pins.findIndex((p) => String(p.id) === safePinId);
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
          if (String(s.id) !== safeSensorId) return s;
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
    if (
      msg.toLowerCase().includes("unique") ||
      msg.toLowerCase().includes("duplicate")
    ) {
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
    return res
      .status(500)
      .json({ message: "server error", error: String(e.message || e) });
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

    const token = jwt.sign(
      { email, nickname, role: "employee" },
      process.env.JWT_SECRET,
      {
        expiresIn: "7d",
      }
    );

    const redirectBase = process.env.FRONTEND_URL || "http://localhost:3000";
    return res.redirect(`${redirectBase}/?token=${encodeURIComponent(token)}`);
  } catch (e) {
    return res
      .status(500)
      .json({ message: "Google auth failed", error: String(e.message || e) });
  }
});

api.use(auth);

/* =========================
   NODE TEMPLATES
========================= */

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

/* =========================
   PLOTS
========================= */

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

    const plot = await getPlotById(plotId);
    if (!plot) return res.status(404).json({ message: "Plot not found" });

    const pins = (plot?.polygon?.pins || []).map((p, i) => normalizePin(p, i));

    res.json({
      item: {
        ...plot,
        polygon: {
          ...(plot.polygon || { color: "#2563eb", coords: [], pins: [] }),
          pins,
        },
      },
    });
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
    const update = { ...current, updatedAt: nowIso() };

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
    const current = await getPlotById(plotId);
    if (!current) return res.status(404).json({ message: "Plot not found" });

    await firestore.collection(COLLECTIONS.plots).doc(plotId).delete();

    const readingSnap = await firestore
      .collection(COLLECTIONS.readings)
      .where("plotId", "==", plotId)
      .get();

    const batch = firestore.batch();
    readingSnap.docs.forEach((d) => batch.delete(d.ref));
    await batch.commit();

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
    const plotId = requireId(res, req.params.plotId, "plotId");
    if (!plotId) return;
    const plot = await getPlotById(plotId);
    if (!plot) return res.status(404).json({ message: "Plot not found" });
    res.json({ items: plot.topics || [] });
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

    plot.topics = normalizeTopics(
      req.body?.topics || req.body?.topicAll || req.body?.Topic_all || []
    );
    plot.updatedAt = nowIso();

    await savePlot(plotId, plot);
    res.json({ items: plot.topics || [] });
  } catch (e) {
    next(e);
  }
});

/* =========================
   POLYGON
========================= */

api.get("/plots/:plotId/polygon", async (req, res, next) => {
  try {
    const plotId = requireId(res, req.params.plotId, "plotId");
    if (!plotId) return;
    const plot = await getPlotById(plotId);
    if (!plot) return res.status(404).json({ message: "Plot not found" });
    res.json({ item: plot.polygon || null });
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

    const incoming = normalizePolygon(req.body || {});
    const current = plot.polygon || {
      id: makeId("polygon"),
      color: "#2563eb",
      coords: [],
      pins: [],
    };

    plot.polygon = {
      id: current.id || incoming.id,
      color: incoming.color || current.color || "#2563eb",
      coords: incoming.coords || [],
      pins: Array.isArray(req.body?.pins) ? incoming.pins : current.pins || [],
    };
    plot.updatedAt = nowIso();

    await savePlot(plotId, plot);
    res.json({ item: plot.polygon || null });
  } catch (e) {
    next(e);
  }
});

/* =========================
   PINS
========================= */

api.get("/plots/:plotId/pins", async (req, res, next) => {
  try {
    const plotId = requireId(res, req.params.plotId, "plotId");
    if (!plotId) return;

    const plot = await getPlotById(plotId);
    if (!plot) return res.status(404).json({ message: "Plot not found" });

    const items = (plot?.polygon?.pins || []).map((p, i) => normalizePin(p, i));
    res.json({ items });
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

    if (!plot.polygon) plot.polygon = normalizePolygon({});

    let pin = normalizePin(req.body || {}, (plot.polygon?.pins || []).length);

    if (req.body?.nodeId) {
      const templateDoc = await getNodeTemplateById(req.body.nodeId);
      if (!templateDoc) {
        return res.status(404).json({ message: "NodeTemplate not found" });
      }
      pin = applyTemplateToPin(pin, templateDoc);
    }

    plot.polygon.pins = [...(plot.polygon.pins || []), pin];
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

    const found = await findPlotByPinId(pinId);
    if (!found?.pin) return res.status(404).json({ message: "Pin not found" });

    res.json({
      item: normalizePin(found.pin),
      plotId: String(found.plot.id),
    });
  } catch (e) {
    next(e);
  }
});

api.patch("/pins/:pinId", async (req, res, next) => {
  try {
    const pinId = requireId(res, req.params.pinId, "pinId");
    if (!pinId) return;

    const found = await findPlotByPinId(pinId);
    if (!found?.pin) return res.status(404).json({ message: "Pin not found" });

    const plot = found.plot;
    const pins = [...(plot?.polygon?.pins || [])];
    const idx = pins.findIndex((p) => String(p.id) === pinId);
    if (idx < 0) return res.status(404).json({ message: "Pin not found" });

    let pin = normalizePin(pins[idx], idx);
    const b = req.body || {};

    if (b.number !== undefined) pin.number = Number(b.number);
    if (b.pinName !== undefined) pin.pinName = String(b.pinName || "").trim();
    if (b.lat !== undefined) pin.lat = Number(b.lat);
    if (b.lng !== undefined) pin.lng = Number(b.lng);

    if (b.node_air !== undefined) {
      pin.node_air = normalizePinNodeArray(b.node_air || [], "air");
    }
    if (b.node_soil !== undefined) {
      pin.node_soil = normalizePinNodeArray(b.node_soil || [], "soil");
    }

    if (b.nodeId !== undefined && b.nodeId !== null && b.nodeId !== "") {
      const templateDoc = await getNodeTemplateById(b.nodeId);
      if (!templateDoc) {
        return res.status(404).json({ message: "NodeTemplate not found" });
      }
      pin = applyTemplateToPin(pin, templateDoc);
    }

    pin.updatedAt = nowIso();
    pins[idx] = pin;
    plot.polygon.pins = pins;
    plot.updatedAt = nowIso();

    await savePlot(plot.id, plot);
    res.json({ item: pin });
  } catch (e) {
    next(e);
  }
});

api.delete("/pins/:pinId", async (req, res, next) => {
  try {
    const pinId = requireId(res, req.params.pinId, "pinId");
    if (!pinId) return;

    const found = await findPlotByPinId(pinId);
    if (!found?.pin) return res.status(404).json({ message: "Pin not found" });

    const plot = found.plot;
    plot.polygon.pins = (plot?.polygon?.pins || []).filter(
      (p) => String(p.id) !== pinId
    );
    plot.updatedAt = nowIso();

    await savePlot(plot.id, plot);

    const readingSnap = await firestore
      .collection(COLLECTIONS.readings)
      .where("pinId", "==", pinId)
      .get();

    const batch = firestore.batch();
    readingSnap.docs.forEach((d) => batch.delete(d.ref));
    await batch.commit();

    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

/* =========================
   PIN NODES
========================= */

api.patch("/pins/:pinId/node", async (req, res, next) => {
  try {
    const pinId = requireId(res, req.params.pinId, "pinId");
    if (!pinId) return;

    const templateId = requireId(res, req.body?.nodeId, "nodeId");
    if (!templateId) return;

    const templateDoc = await getNodeTemplateById(templateId);
    if (!templateDoc) {
      return res.status(404).json({ message: "NodeTemplate not found" });
    }

    const found = await findPlotByPinId(pinId);
    if (!found?.pin) return res.status(404).json({ message: "Pin not found" });

    const plot = found.plot;
    plot.polygon.pins = (plot?.polygon?.pins || []).map((p) => {
      if (String(p.id) !== pinId) return p;
      return applyTemplateToPin(p, templateDoc);
    });
    plot.updatedAt = nowIso();

    await savePlot(plot.id, plot);

    const pin = plot.polygon.pins.find((p) => String(p.id) === pinId) || null;
    res.json({ item: pin });
  } catch (e) {
    next(e);
  }
});

api.get("/pins/:pinId/node", async (req, res, next) => {
  try {
    const pinId = requireId(res, req.params.pinId, "pinId");
    if (!pinId) return;

    const found = await findPlotByPinId(pinId);
    if (!found?.pin) return res.status(404).json({ message: "Pin not found" });

    res.json({
      item: {
        node_air: found.pin?.node_air || [],
        node_soil: found.pin?.node_soil || [],
      },
    });
  } catch (e) {
    next(e);
  }
});

api.get("/pins/:pinId/node-soil", async (req, res, next) => {
  try {
    const pinId = requireId(res, req.params.pinId, "pinId");
    if (!pinId) return;

    const found = await findPlotByPinId(pinId);
    if (!found?.pin) return res.status(404).json({ message: "Pin not found" });

    res.json({ item: found.pin?.node_soil || [] });
  } catch (e) {
    next(e);
  }
});

api.get("/pins/:pinId/node-air", async (req, res, next) => {
  try {
    const pinId = requireId(res, req.params.pinId, "pinId");
    if (!pinId) return;

    const found = await findPlotByPinId(pinId);
    if (!found?.pin) return res.status(404).json({ message: "Pin not found" });

    res.json({ item: found.pin?.node_air || [] });
  } catch (e) {
    next(e);
  }
});

api.post("/pins/:pinId/node-air", async (req, res, next) => {
  try {
    const pinId = requireId(res, req.params.pinId, "pinId");
    if (!pinId) return;

    const found = await findPlotByPinId(pinId);
    if (!found?.pin) return res.status(404).json({ message: "Pin not found" });

    const plot = found.plot;
    const pins = [...(plot?.polygon?.pins || [])];
    const idx = pins.findIndex((p) => String(p.id) === pinId);
    if (idx < 0) return res.status(404).json({ message: "Pin not found" });

    const pin = normalizePin(pins[idx], idx);
    const node = normalizePinNode(req.body || {}, "air");
    pin.node_air = [...(pin.node_air || []), node];
    pin.updatedAt = nowIso();

    pins[idx] = pin;
    plot.polygon.pins = pins;
    plot.updatedAt = nowIso();

    await savePlot(plot.id, plot);
    res.status(201).json({ item: node });
  } catch (e) {
    next(e);
  }
});

api.post("/pins/:pinId/node-soil", async (req, res, next) => {
  try {
    const pinId = requireId(res, req.params.pinId, "pinId");
    if (!pinId) return;

    const found = await findPlotByPinId(pinId);
    if (!found?.pin) return res.status(404).json({ message: "Pin not found" });

    const plot = found.plot;
    const pins = [...(plot?.polygon?.pins || [])];
    const idx = pins.findIndex((p) => String(p.id) === pinId);
    if (idx < 0) return res.status(404).json({ message: "Pin not found" });

    const pin = normalizePin(pins[idx], idx);
    const node = normalizePinNode(req.body || {}, "soil");
    pin.node_soil = [...(pin.node_soil || []), node];
    pin.updatedAt = nowIso();

    pins[idx] = pin;
    plot.polygon.pins = pins;
    plot.updatedAt = nowIso();

    await savePlot(plot.id, plot);
    res.status(201).json({ item: node });
  } catch (e) {
    next(e);
  }
});

api.patch("/pins/:pinId/nodes/:nodeId", async (req, res, next) => {
  try {
    const pinId = requireId(res, req.params.pinId, "pinId");
    const nodeId = requireId(res, req.params.nodeId, "nodeId");
    if (!pinId || !nodeId) return;

    const found = await findPlotByPinId(pinId);
    if (!found?.pin) return res.status(404).json({ message: "Pin not found" });

    const plot = found.plot;
    const pins = [...(plot?.polygon?.pins || [])];
    const pinIdx = pins.findIndex((p) => String(p.id) === pinId);
    if (pinIdx < 0) return res.status(404).json({ message: "Pin not found" });

    const pin = normalizePin(pins[pinIdx], pinIdx);
    const match = findNodeByIdInPin(pin, nodeId);
    if (!match?.node) return res.status(404).json({ message: "Node not found" });

    const b = req.body || {};
    const updateList = (list, type) =>
      (list || []).map((n) => {
        if (String(n.id) !== nodeId) return n;
        return {
          ...n,
          nodeType: type,
          nodeName:
            b.nodeName !== undefined ? String(b.nodeName || "").trim() : n.nodeName,
          sensors:
            b.sensors !== undefined
              ? (b.sensors || []).map(normalizeSensor)
              : n.sensors || [],
          updatedAt: nowIso(),
        };
      });

    if (match.nodeType === "air") {
      pin.node_air = updateList(pin.node_air, "air");
    } else {
      pin.node_soil = updateList(pin.node_soil, "soil");
    }

    pin.updatedAt = nowIso();
    pins[pinIdx] = pin;
    plot.polygon.pins = pins;
    plot.updatedAt = nowIso();

    await savePlot(plot.id, plot);

    const updatedNode = findNodeByIdInPin(pin, nodeId)?.node || null;
    res.json({ item: updatedNode });
  } catch (e) {
    next(e);
  }
});

api.delete("/pins/:pinId/nodes/:nodeId", async (req, res, next) => {
  try {
    const pinId = requireId(res, req.params.pinId, "pinId");
    const nodeId = requireId(res, req.params.nodeId, "nodeId");
    if (!pinId || !nodeId) return;

    const found = await findPlotByPinId(pinId);
    if (!found?.pin) return res.status(404).json({ message: "Pin not found" });

    const plot = found.plot;
    const pins = [...(plot?.polygon?.pins || [])];
    const pinIdx = pins.findIndex((p) => String(p.id) === pinId);
    if (pinIdx < 0) return res.status(404).json({ message: "Pin not found" });

    const pin = normalizePin(pins[pinIdx], pinIdx);
    pin.node_air = (pin.node_air || []).filter((n) => String(n.id) !== nodeId);
    pin.node_soil = (pin.node_soil || []).filter((n) => String(n.id) !== nodeId);
    pin.updatedAt = nowIso();

    pins[pinIdx] = pin;
    plot.polygon.pins = pins;
    plot.updatedAt = nowIso();

    await savePlot(plot.id, plot);

    const readingSnap = await firestore
      .collection(COLLECTIONS.readings)
      .where("pinId", "==", pinId)
      .where("nodeId", "==", nodeId)
      .get();

    const batch = firestore.batch();
    readingSnap.docs.forEach((d) => batch.delete(d.ref));
    await batch.commit();

    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

/* =========================
   SENSORS
========================= */

api.get("/pins/:pinId/sensors", async (req, res, next) => {
  try {
    const pinId = requireId(res, req.params.pinId, "pinId");
    if (!pinId) return;

    const found = await findPlotByPinId(pinId);
    if (!found?.pin) return res.status(404).json({ message: "Pin not found" });

    const nodeType = String(req.query.nodeType || "all");
    let items = flattenSensorsFromPin(found.pin, found.plot.id);

    if (nodeType !== "all") {
      items = items.filter((x) => String(x.nodeType) === nodeType);
    }

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
    let target = null;

    for (const plot of plots) {
      for (const pin of plot?.polygon?.pins || []) {
        const found = findSensorByIdInPin(pin, sensorId);
        if (found?.sensor) {
          target = {
            plot,
            pinId: pin.id,
            nodeId: found.node.id,
            nodeType: found.nodeType,
          };
          break;
        }
      }
      if (target) break;
    }

    if (!target) return res.status(404).json({ message: "Sensor not found" });

    const plot = target.plot;
    const pins = [...(plot?.polygon?.pins || [])];
    const pinIdx = pins.findIndex((p) => String(p.id) === String(target.pinId));
    if (pinIdx < 0) return res.status(404).json({ message: "Pin not found" });

    const pin = normalizePin(pins[pinIdx], pinIdx);
    const b = req.body || {};

    const updateNodeList = (list = []) =>
      list.map((node) => {
        if (String(node.id) !== String(target.nodeId)) return node;
        return {
          ...node,
          updatedAt: nowIso(),
          sensors: (node.sensors || []).map((s) => {
            if (String(s.id) !== String(sensorId)) return s;
            return {
              ...s,
              ...(b.sensorType !== undefined ? { sensorType: b.sensorType } : {}),
              ...(b.name !== undefined ? { name: b.name } : {}),
              ...(b.unit !== undefined ? { unit: b.unit } : {}),
              ...(b.value !== undefined ? { value: b.value } : {}),
              ...(b.valueHint !== undefined ? { valueHint: b.valueHint } : {}),
              ...(b.status !== undefined ? { status: b.status } : {}),
              ...(b.lastReadingAt !== undefined ? { lastReadingAt: b.lastReadingAt } : {}),
              ...(b.lastReading !== undefined ? { lastReading: b.lastReading } : {}),
            };
          }),
        };
      });

    if (target.nodeType === "air") {
      pin.node_air = updateNodeList(pin.node_air || []);
    } else {
      pin.node_soil = updateNodeList(pin.node_soil || []);
    }

    pin.updatedAt = nowIso();
    pins[pinIdx] = pin;
    plot.polygon.pins = pins;
    plot.updatedAt = nowIso();

    await savePlot(plot.id, plot);

    const item =
      flattenSensorsFromPin(pin, plot.id).find((s) => String(s.id) === sensorId) || null;
    res.json({ item });
  } catch (e) {
    next(e);
  }
});

api.get("/sensors", async (req, res, next) => {
  try {
    const { plotId, pinId, nodeType, sensorType, nodeId } = req.query || {};

    let plots = [];
    if (plotId) {
      const plot = await getPlotById(String(plotId));
      plots = plot ? [plot] : [];
    } else {
      plots = await getCollectionItems(COLLECTIONS.plots);
    }

    const items = [];
    for (const plot of plots) {
      for (const pin of plot?.polygon?.pins || []) {
        if (pinId && String(pin.id) !== String(pinId)) continue;

        let sensors = flattenSensorsFromPin(pin, plot.id);

        if (nodeId) sensors = sensors.filter((x) => String(x.nodeId) === String(nodeId));
        if (nodeType && nodeType !== "all") {
          sensors = sensors.filter((x) => String(x.nodeType) === String(nodeType));
        }
        if (sensorType && sensorType !== "all") {
          sensors = sensors.filter((x) => String(x.sensorType) === String(sensorType));
        }

        items.push(...sensors);
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
    if (e.statusCode) return res.status(e.statusCode).json({ message: e.message });
    next(e);
  }
});

api.post("/ingest/reading", async (req, res, next) => {
  try {
    const { pinId, nodeType, sensorType, value, ts, status, raw } = req.body || {};
    const safePinId = requireId(res, pinId, "pinId");
    if (!safePinId) return;

    const safeNodeType = String(nodeType || "");
    if (!["air", "soil"].includes(safeNodeType)) {
      return res.status(400).json({ message: "nodeType must be air or soil" });
    }

    const found = await findPlotByPinId(safePinId);
    if (!found?.pin) return res.status(404).json({ message: "Pin not found" });

    const match = findSensorByTypeInPin(found.pin, safeNodeType, sensorType);
    if (!match?.sensor) {
      return res
        .status(404)
        .json({ message: "Sensor not found for given nodeType/sensorType" });
    }

    const item = await createReadingAndUpdateNode({
      pinId: safePinId,
      sensorId: String(match.sensor.id),
      value,
      ts,
      status,
      raw,
    });

    res.status(201).json({ item });
  } catch (e) {
    if (e.statusCode) return res.status(e.statusCode).json({ message: e.message });
    next(e);
  }
});

api.get("/readings", async (req, res, next) => {
  try {
    const { plotId, pinId, sensorType, nodeType, from, to, nodeId } = req.query || {};

    const snap = await firestore
      .collection(COLLECTIONS.readings)
      .orderBy("ts", "asc")
      .get();

    let items = snap.docs.map((d) => withId(d.id, d.data()));

    if (plotId) items = items.filter((x) => String(x.plotId) === String(plotId));
    if (pinId) items = items.filter((x) => String(x.pinId) === String(pinId));
    if (nodeId) items = items.filter((x) => String(x.nodeId) === String(nodeId));
    if (sensorType && sensorType !== "all") {
      items = items.filter((x) => x.sensorType === String(sensorType));
    }
    if (nodeType && nodeType !== "all") {
      items = items.filter((x) => x.nodeType === String(nodeType));
    }
    if (from) items = items.filter((x) => String(x.ts) >= String(from));
    if (to) items = items.filter((x) => String(x.ts) <= String(to));

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

    const pinIds = (plot?.polygon?.pins || []).map((p) => String(p.id));

    const snap = await firestore
      .collection(COLLECTIONS.readings)
      .where("plotId", "==", plotId)
      .orderBy("ts", "asc")
      .get();

    const readings = snap.docs
      .map((d) => withId(d.id, d.data()))
      .filter((r) => pinIds.includes(String(r.pinId)));

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

    res.json({ plotId, items });
  } catch (e) {
    next(e);
  }
});

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