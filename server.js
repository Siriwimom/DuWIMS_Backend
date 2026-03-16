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
console.log("GOOGLE_APPLICATION_CREDENTIALS =", process.env.GOOGLE_APPLICATION_CREDENTIALS);
console.log("project_id from env hint =", process.env.GOOGLE_CLOUD_PROJECT || process.env.GCLOUD_PROJECT);
const db = admin.firestore();
const app = express();
const api = express.Router();

const BUILD_TAG = "firestore-node-template-v1";
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
    await db.collection("__healthcheck").doc("ping").set(
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
      description: String(x?.description || x?.Description || x?.content || "").trim(),
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

function normalizeNode(node = {}) {
  return {
    id: String(node.id || node._id || makeId("nodepart")),
    sensors: Array.isArray(node.sensors) ? node.sensors.map(normalizeSensor) : [],
  };
}

function normalizePin(pin = {}, index = 0) {
  const createdAt = pin.createdAt || nowIso();
  return {
    id: String(pin.id || pin._id || makeId("pin")),
    number: Number.isFinite(Number(pin.number)) ? Number(pin.number) : index + 1,
    lat: Number(pin.lat ?? 0),
    lng: Number(pin.lng ?? 0),
    nodeId: pin.nodeId ? String(pin.nodeId) : null,
    nodeName: String(pin.nodeName || "").trim(),
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
    node_soil: normalizeNode(body.node_soil || {}),
    node_air: normalizeNode(body.node_air || {}),
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
  const snap = await db.collection(name).orderBy(orderByField, direction).get();
  return snap.docs.map((d) => withId(d.id, d.data()));
}

async function getPlotById(plotId) {
  const snap = await db.collection(COLLECTIONS.plots).doc(String(plotId)).get();
  if (!snap.exists) return null;
  return withId(snap.id, snap.data());
}

async function getNodeTemplateById(nodeId) {
  const snap = await db.collection(COLLECTIONS.nodes).doc(String(nodeId)).get();
  if (!snap.exists) return null;
  return withId(snap.id, snap.data());
}

async function findPlotByPinId(pinId) {
  const plots = await db.collection(COLLECTIONS.plots).get();
  for (const doc of plots.docs) {
    const plot = withId(doc.id, doc.data());
    const pin = plot?.polygon?.pins?.find((p) => String(p.id) === String(pinId));
    if (pin) return { plot, pin };
  }
  return null;
}

async function getNodeTemplateForPin(pin) {
  if (!pin?.nodeId) return null;
  return getNodeTemplateById(pin.nodeId);
}

function findSensorByIdInNode(nodeDoc, sensorId) {
  const soilSensors = nodeDoc?.node_soil?.sensors || [];
  const airSensors = nodeDoc?.node_air?.sensors || [];

  const soil = soilSensors.find((s) => String(s.id) === String(sensorId));
  if (soil) return { nodeType: "soil", sensor: soil };

  const air = airSensors.find((s) => String(s.id) === String(sensorId));
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

async function saveNodeTemplate(nodeId, data) {
  await db.collection(COLLECTIONS.nodes).doc(String(nodeId)).set(cleanUndefined(data), { merge: true });
}

async function savePlot(plotId, data) {
  await db.collection(COLLECTIONS.plots).doc(String(plotId)).set(cleanUndefined(data), { merge: true });
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

  const nodeDoc = await getNodeTemplateForPin(found.pin);
  if (!nodeDoc) {
    const err = new Error("NodeTemplate not found for pin");
    err.statusCode = 404;
    throw err;
  }

  const match = findSensorByIdInNode(nodeDoc, safeSensorId);
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

  const reading = normalizeReadingCreate({
    plotId: found.plot.id,
    pinId: safePinId,
    nodeId: nodeDoc.id,
    nodeType: match.nodeType,
    sensorId: safeSensorId,
    sensorType: match.sensor.sensorType,
    value: num,
    ts: ts || nowIso(),
    status: status || "OK",
    raw,
  });

  const readingRef = db.collection(COLLECTIONS.readings).doc();
  await readingRef.set(reading);

  const targetList = match.nodeType === "soil" ? [...(nodeDoc.node_soil?.sensors || [])] : [...(nodeDoc.node_air?.sensors || [])];
  const idx = targetList.findIndex((s) => String(s.id) === safeSensorId);
  if (idx >= 0) {
    targetList[idx] = {
      ...targetList[idx],
      value: num,
      status: String(status || "OK"),
      lastReadingAt: String(ts || reading.ts),
      lastReading: { value: num, ts: String(ts || reading.ts) },
    };
  }

  const updatedNode = {
    ...nodeDoc,
    updatedAt: nowIso(),
    node_soil: match.nodeType === "soil" ? { ...(nodeDoc.node_soil || { sensors: [] }), sensors: targetList } : nodeDoc.node_soil || { sensors: [] },
    node_air: match.nodeType === "air" ? { ...(nodeDoc.node_air || { sensors: [] }), sensors: targetList } : nodeDoc.node_air || { sensors: [] },
  };

  await saveNodeTemplate(nodeDoc.id, updatedNode);
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
    return res.redirect(`${redirectBase}/?token=${encodeURIComponent(token)}`);
  } catch (e) {
    return res.status(500).json({ message: "Google auth failed", error: String(e.message || e) });
  }
});

api.use(auth);

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
    if (!data.nodeName) return res.status(400).json({ message: "nodeName is required" });

    const dup = await db.collection(COLLECTIONS.nodes).where("nodeName", "==", data.nodeName).limit(1).get();
    if (!dup.empty) return res.status(409).json({ message: "nodeName already exists" });

    const ref = db.collection(COLLECTIONS.nodes).doc();
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
    if (b.node_soil !== undefined) update.node_soil = normalizeNode(b.node_soil || {});
    if (b.node_air !== undefined) update.node_air = normalizeNode(b.node_air || {});
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
    await db.collection(COLLECTIONS.nodes).doc(nodeId).delete();
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
    const ref = db.collection(COLLECTIONS.plots).doc();
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

    const pins = plot?.polygon?.pins || [];
    const nodeIds = [...new Set(pins.map((p) => p.nodeId).filter(Boolean))];
    const nodes = await Promise.all(nodeIds.map((id) => getNodeTemplateById(id)));
    const nodeMap = new Map(nodes.filter(Boolean).map((n) => [String(n.id), n]));

    const enrichedPins = pins.map((pin) => enrichPinWithNode(pin, pin?.nodeId ? nodeMap.get(String(pin.nodeId)) : null));
    res.json({
      item: {
        ...plot,
        polygon: {
          ...(plot.polygon || { color: "#2563eb", coords: [], pins: [] }),
          pins: enrichedPins,
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

    await db.collection(COLLECTIONS.plots).doc(plotId).delete();

    const readingSnap = await db.collection(COLLECTIONS.readings).where("plotId", "==", plotId).get();
    const batch = db.batch();
    readingSnap.docs.forEach((d) => batch.delete(d.ref));
    await batch.commit();

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

    plot.topics = normalizeTopics(req.body?.topics || req.body?.topicAll || req.body?.Topic_all || []);
    plot.updatedAt = nowIso();
    await savePlot(plotId, plot);
    res.json({ items: plot.topics || [] });
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
    const current = plot.polygon || { id: makeId("polygon"), color: "#2563eb", coords: [], pins: [] };

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

api.get("/plots/:plotId/pins", async (req, res, next) => {
  try {
    const plotId = requireId(res, req.params.plotId, "plotId");
    if (!plotId) return;
    const plot = await getPlotById(plotId);
    if (!plot) return res.status(404).json({ message: "Plot not found" });

    const pins = plot?.polygon?.pins || [];
    const nodeIds = [...new Set(pins.map((p) => p.nodeId).filter(Boolean))];
    const nodes = await Promise.all(nodeIds.map((id) => getNodeTemplateById(id)));
    const nodeMap = new Map(nodes.filter(Boolean).map((n) => [String(n.id), n]));
    const items = pins.map((pin) => enrichPinWithNode(pin, pin?.nodeId ? nodeMap.get(String(pin.nodeId)) : null));
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
    const pin = normalizePin(req.body || {}, (plot.polygon?.pins || []).length);

    if (pin.nodeId) {
      const nodeDoc = await getNodeTemplateById(pin.nodeId);
      if (!nodeDoc) return res.status(404).json({ message: "NodeTemplate not found" });
      pin.nodeName = nodeDoc.nodeName || pin.nodeName || "";
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
    const nodeDoc = await getNodeTemplateForPin(found.pin);
    res.json({ item: enrichPinWithNode(found.pin, nodeDoc), plotId: String(found.plot.id) });
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

    const b = req.body || {};
    const pin = { ...pins[idx] };
    if (b.number !== undefined) pin.number = Number(b.number);
    if (b.lat !== undefined) pin.lat = Number(b.lat);
    if (b.lng !== undefined) pin.lng = Number(b.lng);

    if (b.nodeId !== undefined) {
      if (b.nodeId === null || b.nodeId === "") {
        pin.nodeId = null;
        pin.nodeName = "";
      } else {
        const nodeId = requireId(res, b.nodeId, "nodeId");
        if (!nodeId) return;
        const nodeDoc = await getNodeTemplateById(nodeId);
        if (!nodeDoc) return res.status(404).json({ message: "NodeTemplate not found" });
        pin.nodeId = nodeId;
        pin.nodeName = nodeDoc.nodeName || "";
      }
    }

    if (b.nodeName !== undefined && !pin.nodeId) pin.nodeName = String(b.nodeName || "").trim();
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
    plot.polygon.pins = (plot?.polygon?.pins || []).filter((p) => String(p.id) !== pinId);
    plot.updatedAt = nowIso();
    await savePlot(plot.id, plot);

    const readingSnap = await db.collection(COLLECTIONS.readings).where("pinId", "==", pinId).get();
    const batch = db.batch();
    readingSnap.docs.forEach((d) => batch.delete(d.ref));
    await batch.commit();

    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

api.patch("/pins/:pinId/node", async (req, res, next) => {
  try {
    const pinId = requireId(res, req.params.pinId, "pinId");
    if (!pinId) return;
    const nodeId = requireId(res, req.body?.nodeId, "nodeId");
    if (!nodeId) return;

    const nodeDoc = await getNodeTemplateById(nodeId);
    if (!nodeDoc) return res.status(404).json({ message: "NodeTemplate not found" });

    const found = await findPlotByPinId(pinId);
    if (!found?.pin) return res.status(404).json({ message: "Pin not found" });

    const plot = found.plot;
    plot.polygon.pins = (plot?.polygon?.pins || []).map((p) =>
      String(p.id) === pinId
        ? { ...p, nodeId, nodeName: nodeDoc.nodeName || "", updatedAt: nowIso() }
        : p
    );
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
    if (!found.pin.nodeId) return res.json({ item: null });
    const nodeDoc = await getNodeTemplateForPin(found.pin);
    res.json({ item: nodeDoc || null });
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
    const nodeDoc = await getNodeTemplateForPin(found.pin);
    res.json({ item: nodeDoc?.node_soil || { sensors: [] } });
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
    const nodeDoc = await getNodeTemplateForPin(found.pin);
    res.json({ item: nodeDoc?.node_air || { sensors: [] } });
  } catch (e) {
    next(e);
  }
});

api.get("/pins/:pinId/sensors", async (req, res, next) => {
  try {
    const pinId = requireId(res, req.params.pinId, "pinId");
    if (!pinId) return;
    const found = await findPlotByPinId(pinId);
    if (!found?.pin) return res.status(404).json({ message: "Pin not found" });
    const nodeDoc = await getNodeTemplateForPin(found.pin);
    if (!nodeDoc) return res.json({ items: [] });

    const nodeType = String(req.query.nodeType || "all");
    const items = [];

    if (nodeType === "all" || nodeType === "soil") {
      for (const s of nodeDoc?.node_soil?.sensors || []) {
        items.push({ ...s, nodeType: "soil", pinId, plotId: String(found.plot.id), nodeId: String(nodeDoc.id), nodeName: nodeDoc.nodeName || "" });
      }
    }
    if (nodeType === "all" || nodeType === "air") {
      for (const s of nodeDoc?.node_air?.sensors || []) {
        items.push({ ...s, nodeType: "air", pinId, plotId: String(found.plot.id), nodeId: String(nodeDoc.id), nodeName: nodeDoc.nodeName || "" });
      }
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

    const nodes = await getCollectionItems(COLLECTIONS.nodes);
    const node = nodes.find(
      (n) =>
        (n?.node_soil?.sensors || []).some((s) => String(s.id) === sensorId) ||
        (n?.node_air?.sensors || []).some((s) => String(s.id) === sensorId)
    );
    if (!node) return res.status(404).json({ message: "Sensor not found" });

    let updated = null;
    let foundNodeType = null;
    const b = req.body || {};

    const updateSensorInList = (list, type) => {
      return (list || []).map((s) => {
        if (String(s.id) !== sensorId) return s;
        foundNodeType = type;
        updated = {
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
        return updated;
      });
    };

    node.node_soil = { ...(node.node_soil || { sensors: [] }), sensors: updateSensorInList(node?.node_soil?.sensors || [], "soil") };
    if (!updated) {
      node.node_air = { ...(node.node_air || { sensors: [] }), sensors: updateSensorInList(node?.node_air?.sensors || [], "air") };
    }
    node.updatedAt = nowIso();

    await saveNodeTemplate(node.id, node);
    res.json({ item: { ...updated, nodeType: foundNodeType, nodeId: String(node.id), nodeName: node.nodeName || "" } });
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

    const allNodeIds = [];
    for (const plot of plots) {
      for (const pin of plot?.polygon?.pins || []) {
        if (pinId && String(pin.id) !== String(pinId)) continue;
        if (nodeId && String(pin.nodeId || "") !== String(nodeId)) continue;
        if (pin.nodeId) allNodeIds.push(String(pin.nodeId));
      }
    }

    const uniqNodeIds = [...new Set(allNodeIds)];
    const nodes = await Promise.all(uniqNodeIds.map((id) => getNodeTemplateById(id)));
    const nodeMap = new Map(nodes.filter(Boolean).map((n) => [String(n.id), n]));
    const items = [];

    for (const plot of plots) {
      for (const pin of plot?.polygon?.pins || []) {
        if (pinId && String(pin.id) !== String(pinId)) continue;
        if (nodeId && String(pin.nodeId || "") !== String(nodeId)) continue;
        const nodeDoc = pin.nodeId ? nodeMap.get(String(pin.nodeId)) : null;
        if (!nodeDoc) continue;

        if (!nodeType || nodeType === "all" || nodeType === "soil") {
          for (const s of nodeDoc?.node_soil?.sensors || []) {
            if (!sensorType || sensorType === "all" || s.sensorType === sensorType) {
              items.push({ ...s, nodeType: "soil", pinId: String(pin.id), plotId: String(plot.id), nodeId: String(nodeDoc.id), nodeName: nodeDoc.nodeName || "" });
            }
          }
        }
        if (!nodeType || nodeType === "all" || nodeType === "air") {
          for (const s of nodeDoc?.node_air?.sensors || []) {
            if (!sensorType || sensorType === "all" || s.sensorType === sensorType) {
              items.push({ ...s, nodeType: "air", pinId: String(pin.id), plotId: String(plot.id), nodeId: String(nodeDoc.id), nodeName: nodeDoc.nodeName || "" });
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

    const found = await findPlotByPinId(safePinId);
    if (!found?.pin) return res.status(404).json({ message: "Pin not found" });
    const nodeDoc = await getNodeTemplateForPin(found.pin);
    if (!nodeDoc) return res.status(404).json({ message: "NodeTemplate not found for pin" });

    const sensors = nodeType === "air" ? nodeDoc?.node_air?.sensors || [] : nodeDoc?.node_soil?.sensors || [];
    const sensor = sensors.find((s) => s.sensorType === sensorType);
    if (!sensor) return res.status(404).json({ message: "Sensor not found for given nodeType/sensorType" });

    const item = await createReadingAndUpdateNode({
      pinId: safePinId,
      sensorId: String(sensor.id),
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
    const snap = await db.collection(COLLECTIONS.readings).orderBy("ts", "asc").get();
    let items = snap.docs.map((d) => withId(d.id, d.data()));

    if (plotId) items = items.filter((x) => String(x.plotId) === String(plotId));
    if (pinId) items = items.filter((x) => String(x.pinId) === String(pinId));
    if (nodeId) items = items.filter((x) => String(x.nodeId) === String(nodeId));
    if (sensorType && sensorType !== "all") items = items.filter((x) => x.sensorType === String(sensorType));
    if (nodeType && nodeType !== "all") items = items.filter((x) => x.nodeType === String(nodeType));
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
    const snap = await db.collection(COLLECTIONS.readings).where("plotId", "==", plotId).orderBy("ts", "asc").get();
    const readings = snap.docs.map((d) => withId(d.id, d.data())).filter((r) => pinIds.includes(String(r.pinId)));

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
