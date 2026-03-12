require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { google } = require("googleapis");
const { sql, getPool } = require("./db");
const crypto = require("crypto");
const fdb = require("./firebase");

const app = express();

const BUILD_TAG = "firebase-firestore-v1";

console.log("========================================");
console.log("[SERVER] BUILD:", BUILD_TAG);
console.log("[SERVER] FILE :", __filename);
console.log("[SERVER] CWD  :", process.cwd());
console.log("========================================");

app.get("/__version", (req, res) => {
  res.json({ build: BUILD_TAG, file: __filename, cwd: process.cwd() });
});

app.use(cors());
app.use(express.json({ limit: "10mb" }));

app.get("/firestore/ping", async (req, res) => {
  try {
    await fdb.collection("__ping").limit(1).get();
    res.json({ ok: true, message: "Firestore connected" });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e.message || e) });
  }
});

app.get("/health", (req, res) => res.json({ ok: true }));

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
    if (msg.toLowerCase().includes("unique") || msg.toLowerCase().includes("duplicate")) {
      return res.status(409).json({ message: "email or nickname already exists" });
    }
    return res.status(500).json({ message: "server error", error: msg });
  }
});

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
    if (!user.password_hash) return res.status(401).json({ message: "invalid credentials" });

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

app.get("/me", auth, (req, res) => {
  res.json({ user: req.user });
});

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

const SENSOR_TYPES = [
  { key: "soil_moisture", label: "ความชื้นในดิน", unit: "%" },
  { key: "temp_rh", label: "อุณหภูมิ/ความชื้น", unit: "" },
  { key: "wind", label: "ความเร็วลม", unit: "m/s" },
  { key: "ppfd", label: "ความเข้มแสง", unit: "lux" },
  { key: "rain", label: "ปริมาณน้ำฝน", unit: "mm" },
  { key: "npk", label: "NPK", unit: "" },
  { key: "irrigation", label: "การให้น้ำ", unit: "L" },
];

const COL = {
  plots: "plots",
  nodes: "nodes",
  polygons: "polygons",
  pins: "pins",
  sensors: "sensors",
  notes: "notes",
  readings: "readings",
};

function nowIso() {
  return new Date().toISOString();
}

function baseFields(user = "system") {
  const now = nowIso();
  return {
    createdAt: now,
    updatedAt: now,
    createdBy: user,
  };
}

function updateFields(user = "system") {
  return {
    updatedAt: nowIso(),
    updatedBy: user,
  };
}

function cleanUndefined(obj) {
  const out = {};
  Object.keys(obj || {}).forEach((k) => {
    if (obj[k] !== undefined) out[k] = obj[k];
  });
  return out;
}

function docToItem(doc) {
  if (!doc || !doc.exists) return null;
  return { id: doc.id, ...doc.data() };
}

async function getDoc(col, id) {
  const snap = await fdb.collection(col).doc(String(id)).get();
  return snap.exists ? { id: snap.id, ...snap.data() } : null;
}

async function listDocs(col, opts = {}) {
  let ref = fdb.collection(col);
  if (opts.orderBy) ref = ref.orderBy(opts.orderBy.field, opts.orderBy.direction || "asc");
  const snap = await ref.get();
  let items = snap.docs.map((d) => ({ id: d.id, ...d.data() }));
  if (typeof opts.filter === "function") items = items.filter(opts.filter);
  return items;
}

async function setDoc(col, id, data, merge = true) {
  await fdb.collection(col).doc(String(id)).set(cleanUndefined(data), { merge });
  return getDoc(col, id);
}

async function addDoc(col, data, preferredId) {
  const id = preferredId ? String(preferredId) : fdb.collection(col).doc().id;
  await fdb.collection(col).doc(id).set(cleanUndefined(data), { merge: true });
  return getDoc(col, id);
}

async function deleteDoc(col, id) {
  await fdb.collection(col).doc(String(id)).delete();
}

function toNum(v) {
  return v === undefined || v === null || v === "" ? null : Number(v);
}

function isValidLatLng(lat, lng) {
  return (
    typeof lat === "number" &&
    typeof lng === "number" &&
    !Number.isNaN(lat) &&
    lat >= -90 &&
    lat <= 90 &&
    lng >= -180 &&
    lng <= 180
  );
}

function byCreatedDesc(items) {
  return [...items].sort((a, b) => String(b.createdAt || "").localeCompare(String(a.createdAt || "")));
}

function byUpdatedDesc(items) {
  return [...items].sort((a, b) => String(b.updatedAt || "").localeCompare(String(a.updatedAt || "")));
}

function byTsAsc(items) {
  return [...items].sort((a, b) => String(a.ts || "").localeCompare(String(b.ts || "")));
}

function byNumberAsc(items) {
  return [...items].sort((a, b) => Number(a.number || 0) - Number(b.number || 0));
}

async function getPlot(plotId) {
  return getDoc(COL.plots, plotId);
}

async function getNode(nodeId) {
  return getDoc(COL.nodes, nodeId);
}

async function getPin(pinId) {
  return getDoc(COL.pins, pinId);
}

async function getSensor(sensorId) {
  return getDoc(COL.sensors, sensorId);
}

async function getNote(noteId) {
  return getDoc(COL.notes, noteId);
}

async function getPolygon(polygonId) {
  return getDoc(COL.polygons, polygonId);
}

async function listNodesByPlot(plotId) {
  return byCreatedDesc(await listDocs(COL.nodes, { filter: (x) => String(x.plotId || "") === String(plotId) }));
}

async function listPinsByPlot(plotId) {
  return byNumberAsc(await listDocs(COL.pins, { filter: (x) => String(x.plotId || "") === String(plotId) }));
}

async function listSensorsByNodeIds(nodeIds) {
  const set = new Set(nodeIds.map(String));
  return byCreatedDesc(await listDocs(COL.sensors, { filter: (x) => set.has(String(x.nodeId || "")) }));
}

async function listReadingsBySensorIds(sensorIds) {
  const set = new Set(sensorIds.map(String));
  return byTsAsc(await listDocs(COL.readings, { filter: (x) => set.has(String(x.sensorId || "")) }));
}

async function nextPinNumber(plotId) {
  const pins = await listPinsByPlot(plotId);
  let n = pins.length ? Math.max(...pins.map((p) => Number(p.number || 0))) + 1 : 1;
  const used = new Set(pins.map((p) => Number(p.number || 0)));
  while (used.has(n)) n += 1;
  return n;
}

async function upsertSensorByNaturalKey({ nodeId, pinId, sensorType, name, unit, valueHint, readingValue, readingTs, status }) {
  const sensors = await listDocs(COL.sensors, {
    filter: (x) =>
      String(x.nodeId || "") === String(nodeId) &&
      String(x.pinId || "") === String(pinId) &&
      String(x.sensorType || "") === String(sensorType) &&
      String(x.name || "") === String(name),
  });

  const existing = sensors[0] || null;
  const lastReading = { value: readingValue, ts: readingTs };

  if (existing) {
    const prevTs = new Date(existing?.lastReading?.ts || 0).getTime();
    const nextTs = new Date(readingTs).getTime();
    const patch = {
      unit: unit || existing.unit || "",
      valueHint: valueHint || existing.valueHint || "",
      status: status || existing.status || "OK",
    };
    if (!Number.isFinite(prevTs) || (Number.isFinite(nextTs) && nextTs >= prevTs)) {
      patch.lastReading = lastReading;
    }
    await setDoc(COL.sensors, existing.id, patch, true);
    return getSensor(existing.id);
  }

  const created = await addDoc(COL.sensors, {
    nodeId: String(nodeId),
    pinId: pinId ? String(pinId) : null,
    sensorType: String(sensorType),
    name: String(name),
    unit: unit || "",
    valueHint: valueHint || "",
    status: status || "OK",
    lastReading,
    ...baseFields("ingest"),
  });
  return created;
}

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
    if (v === null || Number.isNaN(v)) return res.status(400).json({ ok: false, message: "value must be number" });

    const readingTs = ts || nowIso();
    const readingStatus = status || "OK";

    let sensorDoc = null;
    if (sensorId) {
      sensorDoc = await getSensor(sensorId);
      if (!sensorDoc) return res.status(404).json({ ok: false, message: "Sensor not found" });
      const prevTs = new Date(sensorDoc?.lastReading?.ts || 0).getTime();
      const nextTs = new Date(readingTs).getTime();
      const patch = { status: readingStatus };
      if (!Number.isFinite(prevTs) || (Number.isFinite(nextTs) && nextTs >= prevTs)) {
        patch.lastReading = { value: v, ts: readingTs };
      }
      await setDoc(COL.sensors, sensorDoc.id, patch, true);
      sensorDoc = await getSensor(sensorDoc.id);
    } else {
      if (!nodeId || !pinId || !sensorType || !name) {
        return res.status(400).json({ ok: false, message: "need nodeId, pinId, sensorType, name when sensorId not provided" });
      }
      sensorDoc = await upsertSensorByNaturalKey({
        nodeId,
        pinId,
        sensorType,
        name,
        unit,
        valueHint,
        readingValue: v,
        readingTs,
        status: readingStatus,
      });
    }

    const reading = await addDoc(COL.readings, {
      sensorId: String(sensorDoc.id),
      nodeId: sensorDoc.nodeId || String(nodeId || ""),
      pinId: sensorDoc.pinId || String(pinId || ""),
      ts: readingTs,
      value: v,
      status: readingStatus,
      raw: raw || null,
      ...baseFields("ingest"),
    });

    return res.json({
      ok: true,
      sensorId: String(sensorDoc.id),
      readingId: String(reading.id),
      lastReading: { value: v, ts: readingTs },
      status: readingStatus,
    });
  } catch (e) {
    return res.status(500).json({ ok: false, message: String(e.message || e) });
  }
};

app.post("/ingest/reading", ingestReadingHandler);
app.post("/api/ingest/reading", ingestReadingHandler);

const api = express.Router();
api.use(auth);

api.get("/sensor-types", (req, res) => res.json({ items: SENSOR_TYPES }));

api.get("/plots", async (req, res, next) => {
  try {
    const items = byCreatedDesc(await listDocs(COL.plots));
    res.json({ items });
  } catch (e) {
    next(e);
  }
});

api.post("/plots", async (req, res, next) => {
  try {
    const b = req.body || {};
    const plotName = b.plotName || b.name || "";
    const alias = b.alias || plotName || "";
    if (!plotName) return res.status(400).json({ message: "plotName (or name) is required" });

    const nicknameFromToken = String(req.user?.nickname || "").trim() || String(req.user?.email || "system");

    const item = await addDoc(COL.plots, {
      alias,
      plotName,
      caretaker: nicknameFromToken,
      plantType: b.plantType || b.cropType || "",
      plantedAt: b.plantedAt || null,
      status: b.status || "ACTIVE",
      name: b.name || plotName,
      ownerName: nicknameFromToken,
      cropType: b.cropType || b.plantType || "",
      ...baseFields(nicknameFromToken),
    });

    res.status(201).json({ item });
  } catch (e) {
    next(e);
  }
});

api.get("/plots/:plotId", async (req, res, next) => {
  try {
    const doc = await getPlot(req.params.plotId);
    if (!doc) return res.status(404).json({ message: "Plot not found" });

    const polygons = await listDocs(COL.polygons, { filter: (x) => String(x.plotId || "") === String(req.params.plotId) });
    const polygon = polygons[0] || null;

    res.json({ item: { ...doc, polygon } });
  } catch (e) {
    next(e);
  }
});

api.patch("/plots/:plotId", async (req, res, next) => {
  try {
    const current = await getPlot(req.params.plotId);
    if (!current) return res.status(404).json({ message: "Plot not found" });

    const b = req.body || {};
    const patch = {};
    const allowed = ["alias", "plotName", "caretaker", "plantType", "plantedAt", "status", "name", "ownerName", "cropType"];
    for (const k of allowed) if (k in b) patch[k] = b[k];
    if ("plotName" in patch && !("name" in patch)) patch.name = patch.plotName;
    if ("caretaker" in patch && !("ownerName" in patch)) patch.ownerName = patch.caretaker;
    if ("plantType" in patch && !("cropType" in patch)) patch.cropType = patch.plantType;

    const item = await setDoc(COL.plots, req.params.plotId, {
      ...patch,
      ...updateFields(String(req.user?.email || req.user?.nickname || "system")),
    });

    res.json({ item });
  } catch (e) {
    next(e);
  }
});

api.delete("/plots/:plotId", async (req, res, next) => {
  try {
    const plotId = req.params.plotId;
    const plot = await getPlot(plotId);
    if (!plot) return res.status(404).json({ message: "Plot not found" });

    const nodes = await listNodesByPlot(plotId);
    const nodeIds = nodes.map((x) => x.id);
    const sensors = await listSensorsByNodeIds(nodeIds);
    const sensorIds = sensors.map((x) => x.id);
    const pins = await listPinsByPlot(plotId);
    const polygons = await listDocs(COL.polygons, { filter: (x) => String(x.plotId || "") === String(plotId) });
    const notes = await listDocs(COL.notes, { filter: (x) => String(x.plotId || "") === String(plotId) });
    const readings = await listReadingsBySensorIds(sensorIds);

    await Promise.all(readings.map((x) => deleteDoc(COL.readings, x.id)));
    await Promise.all(sensors.map((x) => deleteDoc(COL.sensors, x.id)));
    await Promise.all(nodes.map((x) => deleteDoc(COL.nodes, x.id)));
    await Promise.all(pins.map((x) => deleteDoc(COL.pins, x.id)));
    await Promise.all(polygons.map((x) => deleteDoc(COL.polygons, x.id)));
    await Promise.all(notes.map((x) => deleteDoc(COL.notes, x.id)));
    await deleteDoc(COL.plots, plotId);

    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

api.get("/plots/:plotId/polygon", async (req, res, next) => {
  try {
    const plot = await getPlot(req.params.plotId);
    if (!plot) return res.status(404).json({ message: "Plot not found" });

    const items = await listDocs(COL.polygons, { filter: (x) => String(x.plotId || "") === String(req.params.plotId) });
    res.json({ item: items[0] || null });
  } catch (e) {
    next(e);
  }
});

api.put("/plots/:plotId/polygon", async (req, res, next) => {
  try {
    const plotId = req.params.plotId;
    const plot = await getPlot(plotId);
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

    const existing = await listDocs(COL.polygons, { filter: (x) => String(x.plotId || "") === String(plotId) });
    const id = existing[0]?.id || polygonId || fdb.collection(COL.polygons).doc().id;
    const item = await setDoc(COL.polygons, id, {
      plotId,
      polygonId: polygonId || existing[0]?.polygonId || id,
      color: color || "#2563eb",
      coords,
      ...(existing[0] ? updateFields(String(req.user?.email || "system")) : baseFields(String(req.user?.email || "system"))),
    });

    res.json({ item });
  } catch (e) {
    next(e);
  }
});

api.get("/plots/:plotId/polygons", async (req, res, next) => {
  try {
    const plot = await getPlot(req.params.plotId);
    if (!plot) return res.status(404).json({ message: "Plot not found" });
    const items = byCreatedDesc(await listDocs(COL.polygons, { filter: (x) => String(x.plotId || "") === String(req.params.plotId) }));
    res.json({ items });
  } catch (e) {
    next(e);
  }
});

api.post("/plots/:plotId/polygons", async (req, res, next) => {
  try {
    const plotId = req.params.plotId;
    const plot = await getPlot(plotId);
    if (!plot) return res.status(404).json({ message: "Plot not found" });

    const { coords, coordinates, color, polygonId } = req.body || {};
    const pts = Array.isArray(coords) ? coords : coordinates;
    if (!Array.isArray(pts) || pts.length < 3) {
      return res.status(400).json({ message: "coords/coordinates must be array of [lat,lng] with length >= 3" });
    }

    const item = await addDoc(COL.polygons, {
      plotId,
      polygonId: polygonId || crypto.randomUUID(),
      color: color || "#2563eb",
      coords: pts,
      ...baseFields(String(req.user?.email || "system")),
    });
    res.status(201).json({ item });
  } catch (e) {
    next(e);
  }
});

api.patch("/plots/:plotId/polygons", async (req, res, next) => {
  try {
    const plotId = req.params.plotId;
    const plot = await getPlot(plotId);
    if (!plot) return res.status(404).json({ message: "Plot not found" });

    const { coords, coordinates, color, polygonId } = req.body || {};
    const pts = Array.isArray(coords) ? coords : coordinates;
    if (!Array.isArray(pts) || pts.length < 3) {
      return res.status(400).json({ message: "coords/coordinates must be array of [lat,lng] with length >= 3" });
    }

    const pid = polygonId || "poly-1";
    const items = await listDocs(COL.polygons, {
      filter: (x) => String(x.plotId || "") === String(plotId) && String(x.polygonId || "") === String(pid),
    });
    const existing = items[0] || null;
    const item = await setDoc(COL.polygons, existing?.id || fdb.collection(COL.polygons).doc().id, {
      plotId,
      polygonId: pid,
      coords: pts,
      color: color || "#2563eb",
      ...(existing ? updateFields(String(req.user?.email || "system")) : baseFields(String(req.user?.email || "system"))),
    });

    res.json({ item });
  } catch (e) {
    next(e);
  }
});

api.patch("/polygons/:id", async (req, res, next) => {
  try {
    const current = await getPolygon(req.params.id);
    if (!current) return res.status(404).json({ message: "Polygon not found" });

    const { coords, coordinates, color } = req.body || {};
    const pts = Array.isArray(coords) ? coords : coordinates;
    const patch = {};
    if (Array.isArray(pts)) patch.coords = pts;
    if (typeof color === "string") patch.color = color;

    const item = await setDoc(COL.polygons, req.params.id, {
      ...patch,
      ...updateFields(String(req.user?.email || "system")),
    });
    res.json({ item });
  } catch (e) {
    next(e);
  }
});

api.delete("/polygons/:id", async (req, res, next) => {
  try {
    await deleteDoc(COL.polygons, req.params.id);
    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

api.delete("/plots/:plotId/polygons", async (req, res, next) => {
  try {
    const items = await listDocs(COL.polygons, { filter: (x) => String(x.plotId || "") === String(req.params.plotId) });
    await Promise.all(items.map((x) => deleteDoc(COL.polygons, x.id)));
    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

api.get("/nodes", async (req, res, next) => {
  try {
    const { plotId, category } = req.query || {};
    let items = await listDocs(COL.nodes);
    if (plotId) items = items.filter((x) => String(x.plotId || "") === String(plotId));
    if (category && category !== "all") items = items.filter((x) => String(x.category || "") === String(category));
    res.json({ items: byCreatedDesc(items) });
  } catch (e) {
    next(e);
  }
});

api.post("/nodes", async (req, res, next) => {
  try {
    const b = req.body || {};
    if (!b.plotId) return res.status(400).json({ message: "plotId is required" });
    const plot = await getPlot(b.plotId);
    if (!plot) return res.status(404).json({ message: "Plot not found" });

    const item = await addDoc(COL.nodes, {
      plotId: String(b.plotId),
      category: b.category || "soil",
      name: b.name || "",
      firmware: b.firmware || "",
      lastSeen: b.lastSeen || null,
      status: b.status || "ONLINE",
      ...baseFields(String(req.user?.email || "system")),
    });
    res.status(201).json({ item });
  } catch (e) {
    next(e);
  }
});

api.patch("/nodes/:nodeId", async (req, res, next) => {
  try {
    const current = await getNode(req.params.nodeId);
    if (!current) return res.status(404).json({ message: "Node not found" });

    const b = req.body || {};
    const allowed = ["category", "name", "firmware", "lastSeen", "status"];
    const patch = {};
    for (const k of allowed) if (k in b) patch[k] = b[k];

    const item = await setDoc(COL.nodes, req.params.nodeId, {
      ...patch,
      ...updateFields(String(req.user?.email || "system")),
    });
    res.json({ item });
  } catch (e) {
    next(e);
  }
});

api.delete("/nodes/:nodeId", async (req, res, next) => {
  try {
    const nodeId = req.params.nodeId;
    const current = await getNode(nodeId);
    if (!current) return res.status(404).json({ message: "Node not found" });

    const sensors = await listDocs(COL.sensors, { filter: (x) => String(x.nodeId || "") === String(nodeId) });
    const sensorIds = sensors.map((x) => x.id);
    const readings = await listReadingsBySensorIds(sensorIds);

    await Promise.all(readings.map((x) => deleteDoc(COL.readings, x.id)));
    await Promise.all(sensors.map((x) => deleteDoc(COL.sensors, x.id)));
    await deleteDoc(COL.nodes, nodeId);
    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

api.get("/plots/:plotId/pins", async (req, res, next) => {
  try {
    const plot = await getPlot(req.params.plotId);
    if (!plot) return res.status(404).json({ message: "Plot not found" });
    const items = await listPinsByPlot(req.params.plotId);
    res.json({ items });
  } catch (e) {
    next(e);
  }
});

api.get("/pins", async (req, res, next) => {
  try {
    const { plotId, nodeCategory, sensorType, nodeId } = req.query || {};
    let pins = await listDocs(COL.pins);
    if (plotId) pins = pins.filter((p) => String(p.plotId || "") === String(plotId));
    pins = byNumberAsc(pins);

    if (nodeId && String(nodeId).trim()) {
      pins = pins.filter((p) => String(p.nodeId || "") === String(nodeId));
    }

    if (nodeCategory && nodeCategory !== "all" && plotId) {
      const nodes = await listDocs(COL.nodes, {
        filter: (n) => String(n.plotId || "") === String(plotId) && String(n.category || "") === String(nodeCategory),
      });
      const nodeSet = new Set(nodes.map((n) => String(n.id)));
      pins = pins.filter((p) => p.nodeId && nodeSet.has(String(p.nodeId)));
    }

    if (sensorType && sensorType !== "all") {
      const nodeIds = [...new Set(pins.map((p) => String(p.nodeId || "")).filter(Boolean))];
      const sensors = await listDocs(COL.sensors, {
        filter: (s) => nodeIds.includes(String(s.nodeId || "")) && String(s.sensorType || "") === String(sensorType),
      });
      const okNode = new Set(sensors.map((s) => String(s.nodeId)));
      pins = pins.filter((p) => p.nodeId && okNode.has(String(p.nodeId)));
    }

    res.json({ items: pins });
  } catch (e) {
    next(e);
  }
});

api.post("/pins", async (req, res, next) => {
  try {
    const { plotId, nodeId, lat, lng } = req.body || {};
    if (!plotId) return res.status(400).json({ message: "plotId is required" });

    const la = toNum(lat);
    const lo = toNum(lng);
    if (la === null || lo === null) return res.status(400).json({ message: "lat, lng are required" });
    if (!isValidLatLng(la, lo)) return res.status(400).json({ message: "invalid lat/lng" });

    const plot = await getPlot(plotId);
    if (!plot) return res.status(404).json({ message: "Plot not found" });

    let nodeIdToUse = nodeId ? String(nodeId) : "";
    if (!nodeIdToUse) {
      const found = (await listDocs(COL.nodes, {
        filter: (n) => String(n.plotId || "") === String(plotId) && String(n.category || "") === "soil",
      }))[0];
      if (found) nodeIdToUse = String(found.id);
      else {
        const createdNode = await addDoc(COL.nodes, {
          plotId: String(plotId),
          category: "soil",
          name: "Node ดิน",
          status: "ONLINE",
          ...baseFields(String(req.user?.email || "system")),
        });
        nodeIdToUse = String(createdNode.id);
      }
    }

    const node = await getNode(nodeIdToUse);
    if (!node) return res.status(404).json({ message: "Node not found" });
    if (String(node.plotId) !== String(plotId)) return res.status(400).json({ message: "nodeId does not belong to plotId" });

    const n = await nextPinNumber(plotId);
    const item = await addDoc(COL.pins, {
      plotId: String(plotId),
      nodeId: String(nodeIdToUse),
      number: n,
      lat: la,
      lng: lo,
      ...baseFields(String(req.user?.email || "system")),
    });

    return res.status(201).json({ item });
  } catch (e) {
    next(e);
  }
});

api.delete("/pins", async (req, res, next) => {
  try {
    const { plotId, nodeCategory, sensorType } = req.query || {};
    if (!plotId) return res.status(400).json({ message: "plotId is required" });

    let pins = await listPinsByPlot(plotId);

    if (nodeCategory && nodeCategory !== "all") {
      const nodes = await listDocs(COL.nodes, {
        filter: (n) => String(n.plotId || "") === String(plotId) && String(n.category || "") === String(nodeCategory),
      });
      const nodeSet = new Set(nodes.map((n) => String(n.id)));
      pins = pins.filter((p) => p.nodeId && nodeSet.has(String(p.nodeId)));
    }

    if (sensorType && sensorType !== "all") {
      const nodeIds = [...new Set(pins.map((p) => String(p.nodeId || "")).filter(Boolean))];
      const sensors = await listDocs(COL.sensors, {
        filter: (s) => nodeIds.includes(String(s.nodeId || "")) && String(s.sensorType || "") === String(sensorType),
      });
      const okNode = new Set(sensors.map((s) => String(s.nodeId)));
      pins = pins.filter((p) => p.nodeId && okNode.has(String(p.nodeId)));
    }

    const pinIds = pins.map((p) => String(p.id));
    const sensors = await listDocs(COL.sensors, { filter: (s) => pinIds.includes(String(s.pinId || "")) });
    const readings = await listReadingsBySensorIds(sensors.map((s) => s.id));

    await Promise.all(readings.map((x) => deleteDoc(COL.readings, x.id)));
    await Promise.all(sensors.map((x) => deleteDoc(COL.sensors, x.id)));
    await Promise.all(pins.map((x) => deleteDoc(COL.pins, x.id)));

    res.json({ ok: true, deletedPins: pinIds.length });
  } catch (e) {
    next(e);
  }
});

api.post("/plots/:plotId/pins", async (req, res, next) => {
  try {
    const plotId = req.params.plotId;
    const plot = await getPlot(plotId);
    if (!plot) return res.status(404).json({ message: "Plot not found" });

    const { number, lat, lng, nodeId } = req.body || {};
    const n = toNum(number);
    const la = toNum(lat);
    const lo = toNum(lng);
    if (!n || la === null || lo === null) return res.status(400).json({ message: "number, lat, lng are required" });
    if (!isValidLatLng(la, lo)) return res.status(400).json({ message: "invalid lat/lng" });

    if (nodeId) {
      const node = await getNode(nodeId);
      if (!node) return res.status(404).json({ message: "Node not found" });
      if (String(node.plotId) !== String(plotId)) return res.status(400).json({ message: "nodeId does not belong to plot" });
    }

    const exists = await listDocs(COL.pins, {
      filter: (x) => String(x.plotId || "") === String(plotId) && Number(x.number || 0) === Number(n),
    });
    if (exists.length) return res.status(409).json({ message: "Pin number already exists in this plot" });

    const item = await addDoc(COL.pins, {
      plotId,
      nodeId: nodeId ? String(nodeId) : null,
      number: n,
      lat: la,
      lng: lo,
      ...baseFields(String(req.user?.email || "system")),
    });
    res.status(201).json({ item });
  } catch (e) {
    next(e);
  }
});

api.get("/pins/:pinId", async (req, res, next) => {
  try {
    const pin = await getPin(req.params.pinId);
    if (!pin) return res.status(404).json({ message: "Pin not found" });
    res.json({ item: pin });
  } catch (e) {
    next(e);
  }
});

api.patch("/pins/:pinId", async (req, res, next) => {
  try {
    const pinId = req.params.pinId;
    const pin = await getPin(pinId);
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
      const node = await getNode(patch.nodeId);
      if (!node) return res.status(404).json({ message: "Node not found" });
      if (String(node.plotId) !== String(pin.plotId)) return res.status(400).json({ message: "nodeId does not belong to plot" });
    }
    if ("number" in patch) {
      const exists = await listDocs(COL.pins, {
        filter: (x) => String(x.plotId || "") === String(pin.plotId) && Number(x.number || 0) === Number(patch.number) && String(x.id) !== String(pinId),
      });
      if (exists.length) return res.status(409).json({ message: "Pin number already exists in this plot" });
    }

    const item = await setDoc(COL.pins, pinId, {
      ...patch,
      ...updateFields(String(req.user?.email || "system")),
    });
    res.json({ item });
  } catch (e) {
    next(e);
  }
});

api.delete("/pins/:pinId", async (req, res, next) => {
  try {
    const pinId = req.params.pinId;
    const pin = await getPin(pinId);
    if (!pin) return res.status(404).json({ message: "Pin not found" });

    const sensors = await listDocs(COL.sensors, { filter: (s) => String(s.pinId || "") === String(pinId) });
    const readings = await listReadingsBySensorIds(sensors.map((s) => s.id));
    await Promise.all(readings.map((x) => deleteDoc(COL.readings, x.id)));
    await Promise.all(sensors.map((x) => deleteDoc(COL.sensors, x.id)));
    await deleteDoc(COL.pins, pinId);

    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

api.delete("/plots/:plotId/pins", async (req, res, next) => {
  try {
    const plot = await getPlot(req.params.plotId);
    if (!plot) return res.status(404).json({ message: "Plot not found" });

    const pins = await listPinsByPlot(req.params.plotId);
    const pinIds = pins.map((p) => p.id);
    const sensors = await listDocs(COL.sensors, { filter: (s) => pinIds.includes(String(s.pinId || "")) });
    const readings = await listReadingsBySensorIds(sensors.map((s) => s.id));

    await Promise.all(readings.map((x) => deleteDoc(COL.readings, x.id)));
    await Promise.all(sensors.map((x) => deleteDoc(COL.sensors, x.id)));
    await Promise.all(pins.map((x) => deleteDoc(COL.pins, x.id)));

    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

api.get("/pins/:pinId/sensors", async (req, res, next) => {
  try {
    const pin = await getPin(req.params.pinId);
    if (!pin) return res.status(404).json({ message: "Pin not found" });

    const items = byCreatedDesc(await listDocs(COL.sensors, { filter: (x) => String(x.pinId || "") === String(req.params.pinId) }));
    res.json({ items });
  } catch (e) {
    next(e);
  }
});

api.get("/sensors", async (req, res, next) => {
  try {
    const { plotId, nodeCategory, sensorType, nodeId } = req.query || {};
    let items = await listDocs(COL.sensors);

    if (nodeId) {
      items = items.filter((s) => String(s.nodeId || "") === String(nodeId));
    } else if (plotId) {
      let nodes = await listDocs(COL.nodes, { filter: (n) => String(n.plotId || "") === String(plotId) });
      if (nodeCategory && nodeCategory !== "all") {
        nodes = nodes.filter((n) => String(n.category || "") === String(nodeCategory));
      }
      const nodeSet = new Set(nodes.map((n) => String(n.id)));
      items = items.filter((s) => nodeSet.has(String(s.nodeId || "")));
    }

    if (sensorType && sensorType !== "all") items = items.filter((s) => String(s.sensorType || "") === String(sensorType));

    res.json({ items: byCreatedDesc(items) });
  } catch (e) {
    next(e);
  }
});

api.post("/pins/:pinId/sensors", async (req, res, next) => {
  try {
    const pinId = req.params.pinId;
    const pin = await getPin(pinId);
    if (!pin) return res.status(404).json({ message: "Pin not found" });

    const b = req.body || {};
    const sensorType = b.sensorType || b.typeKey;
    if (!sensorType) return res.status(400).json({ message: "sensorType (or typeKey) is required" });

    let nodeId = pin.nodeId;
    if (!nodeId) {
      const auto = await addDoc(COL.nodes, {
        plotId: String(pin.plotId),
        category: "soil",
        name: "Auto Node",
        status: "ONLINE",
        ...baseFields(String(req.user?.email || "system")),
      });
      nodeId = String(auto.id);
      await setDoc(COL.pins, pinId, { nodeId, ...updateFields(String(req.user?.email || "system")) });
    }

    const st = SENSOR_TYPES.find((t) => t.key === sensorType);
    const item = await addDoc(COL.sensors, {
      nodeId: String(nodeId),
      pinId: String(pinId),
      sensorType,
      name: b.name || (st ? st.label : sensorType),
      unit: b.unit || (st ? st.unit : ""),
      valueHint: b.valueHint || "",
      status: b.status || "OK",
      lastReading: b.lastReading || { value: null, ts: null },
      ...baseFields(String(req.user?.email || "system")),
    });

    res.status(201).json({ item });
  } catch (e) {
    next(e);
  }
});

api.post("/sensors", async (req, res, next) => {
  try {
    const b = req.body || {};
    if (!b.nodeId) return res.status(400).json({ message: "nodeId is required" });
    if (!b.sensorType) return res.status(400).json({ message: "sensorType is required" });

    const node = await getNode(b.nodeId);
    if (!node) return res.status(404).json({ message: "Node not found" });

    const st = SENSOR_TYPES.find((t) => t.key === b.sensorType);
    const item = await addDoc(COL.sensors, {
      nodeId: String(b.nodeId),
      pinId: b.pinId ? String(b.pinId) : null,
      sensorType: b.sensorType,
      name: b.name || (st ? st.label : b.sensorType),
      unit: b.unit || (st ? st.unit : ""),
      valueHint: b.valueHint || "",
      status: b.status || "OK",
      lastReading: b.lastReading || { value: null, ts: null },
      ...baseFields(String(req.user?.email || "system")),
    });

    res.status(201).json({ item });
  } catch (e) {
    next(e);
  }
});

api.get("/sensors/:sensorId", async (req, res, next) => {
  try {
    const s = await getSensor(req.params.sensorId);
    if (!s) return res.status(404).json({ message: "Sensor not found" });
    res.json({ item: s });
  } catch (e) {
    next(e);
  }
});

api.patch("/sensors/:sensorId", async (req, res, next) => {
  try {
    const sensorId = req.params.sensorId;
    const sensor = await getSensor(sensorId);
    if (!sensor) return res.status(404).json({ message: "Sensor not found" });

    const b = req.body || {};
    const patch = {};
    const allowed = ["name", "sensorType", "unit", "valueHint", "status", "pinId", "nodeId", "lastReading"];
    for (const k of allowed) if (k in b) patch[k] = b[k];

    if ("nodeId" in patch) {
      const node = await getNode(patch.nodeId);
      if (!node) return res.status(404).json({ message: "Node not found" });
      patch.nodeId = String(patch.nodeId);
    }
    if ("pinId" in patch) patch.pinId = patch.pinId ? String(patch.pinId) : null;

    const item = await setDoc(COL.sensors, sensorId, {
      ...patch,
      ...updateFields(String(req.user?.email || "system")),
    });
    res.json({ item });
  } catch (e) {
    next(e);
  }
});

api.delete("/sensors/:sensorId", async (req, res, next) => {
  try {
    const sensorId = req.params.sensorId;
    const sensor = await getSensor(sensorId);
    if (!sensor) return res.status(404).json({ message: "Sensor not found" });

    const readings = await listDocs(COL.readings, { filter: (r) => String(r.sensorId || "") === String(sensorId) });
    await Promise.all(readings.map((x) => deleteDoc(COL.readings, x.id)));
    await deleteDoc(COL.sensors, sensorId);
    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

api.get("/plots/:plotId/notes", async (req, res, next) => {
  try {
    const plot = await getPlot(req.params.plotId);
    if (!plot) return res.status(404).json({ message: "Plot not found" });
    const items = byUpdatedDesc(await listDocs(COL.notes, { filter: (x) => String(x.plotId || "") === String(req.params.plotId) }));
    res.json({ items });
  } catch (e) {
    next(e);
  }
});

api.post("/plots/:plotId/notes", async (req, res, next) => {
  try {
    const plotId = req.params.plotId;
    const plot = await getPlot(plotId);
    if (!plot) return res.status(404).json({ message: "Plot not found" });

    const b = req.body || {};
    if (!b.topic) return res.status(400).json({ message: "topic is required" });

    const item = await addDoc(COL.notes, {
      plotId,
      topic: b.topic,
      content: b.content || "",
      author: b.author || "",
      updatedBy: req.user?.email || "",
      ...baseFields(String(req.user?.email || "system")),
    });

    res.status(201).json({ item });
  } catch (e) {
    next(e);
  }
});

api.patch("/notes/:noteId", async (req, res, next) => {
  try {
    const noteId = req.params.noteId;
    const note = await getNote(noteId);
    if (!note) return res.status(404).json({ message: "Note not found" });

    const b = req.body || {};
    const patch = {};
    const allowed = ["topic", "content", "author"];
    for (const k of allowed) if (k in b) patch[k] = b[k];
    patch.updatedBy = req.user?.email || "";

    const item = await setDoc(COL.notes, noteId, {
      ...patch,
      ...updateFields(String(req.user?.email || "system")),
    });
    res.json({ item });
  } catch (e) {
    next(e);
  }
});

api.delete("/notes/:noteId", async (req, res, next) => {
  try {
    const note = await getNote(req.params.noteId);
    if (!note) return res.status(404).json({ message: "Note not found" });
    await deleteDoc(COL.notes, req.params.noteId);
    res.json({ ok: true });
  } catch (e) {
    next(e);
  }
});

api.post("/readings", async (req, res, next) => {
  try {
    const { sensorId, ts, value, status, raw } = req.body || {};
    const s = await getSensor(String(sensorId));
    if (!s) return res.status(404).json({ message: "Sensor not found" });

    const v = toNum(value);
    if (v === null || Number.isNaN(v)) return res.status(400).json({ message: "value must be number" });

    const readingTs = ts || nowIso();
    const readingStatus = status || "OK";

    const item = await addDoc(COL.readings, {
      sensorId: String(sensorId),
      nodeId: s.nodeId || null,
      pinId: s.pinId || null,
      ts: readingTs,
      value: v,
      status: readingStatus,
      raw: raw || null,
      ...baseFields(String(req.user?.email || "system")),
    });

    const prevTs = s?.lastReading?.ts ? new Date(s.lastReading.ts).getTime() : null;
    const nextTs = new Date(readingTs).getTime();
    if (!prevTs || (Number.isFinite(nextTs) && nextTs >= prevTs)) {
      await setDoc(COL.sensors, String(sensorId), {
        lastReading: { value: v, ts: readingTs },
        status: readingStatus,
        ...updateFields(String(req.user?.email || "system")),
      });
    }

    res.status(201).json({ item });
  } catch (e) {
    next(e);
  }
});

api.get("/readings", async (req, res, next) => {
  try {
    const { plotId, pinId, sensorType, from, to } = req.query || {};
    let sensorIds = [];

    if (pinId) {
      const sensors = await listDocs(COL.sensors, { filter: (s) => String(s.pinId || "") === String(pinId) });
      sensorIds = sensors.map((x) => x.id);
    } else if (plotId) {
      const nodes = await listDocs(COL.nodes, { filter: (n) => String(n.plotId || "") === String(plotId) });
      let sensors = await listSensorsByNodeIds(nodes.map((n) => n.id));
      if (sensorType && sensorType !== "all") {
        sensors = sensors.filter((s) => String(s.sensorType || "") === String(sensorType));
      }
      sensorIds = sensors.map((x) => x.id);
    }

    let items = await listDocs(COL.readings);
    if (sensorIds.length) items = items.filter((r) => sensorIds.includes(String(r.sensorId || "")));
    if (from) items = items.filter((r) => String(r.ts || "") >= new Date(from).toISOString());
    if (to) items = items.filter((r) => String(r.ts || "") <= new Date(to).toISOString());

    res.json({ items: byTsAsc(items) });
  } catch (e) {
    next(e);
  }
});

api.get("/plots/:plotId/summary", async (req, res, next) => {
  try {
    const plotId = req.params.plotId;
    const plot = await getPlot(plotId);
    if (!plot) return res.status(404).json({ message: "Plot not found" });

    const nodes = await listNodesByPlot(plotId);
    const sensors = await listSensorsByNodeIds(nodes.map((x) => x.id));

    const items = [];
    for (const s of sensors) {
      const rs = await listDocs(COL.readings, { filter: (r) => String(r.sensorId || "") === String(s.id) });
      if (!rs.length) continue;
      const ordered = byTsAsc(rs);
      const values = ordered.map((x) => Number(x.value));
      const min = Math.min(...values);
      const max = Math.max(...values);
      const avg = values.reduce((sum, v) => sum + v, 0) / values.length;
      const last = ordered[ordered.length - 1];

      items.push({
        sensorId: String(s.id),
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

api.get("/export/readings.csv", async (req, res, next) => {
  try {
    const { plotId, from, to } = req.query || {};

    let nodes = await listDocs(COL.nodes);
    if (plotId) nodes = nodes.filter((n) => String(n.plotId || "") === String(plotId));
    const nodeSet = new Set(nodes.map((n) => String(n.id)));

    const sensors = (await listDocs(COL.sensors)).filter((s) => nodeSet.has(String(s.nodeId || "")));
    const sensorIds = sensors.map((s) => String(s.id));

    let readings = (await listDocs(COL.readings)).filter((r) => sensorIds.includes(String(r.sensorId || "")));
    if (from) readings = readings.filter((r) => String(r.ts || "") >= new Date(from).toISOString());
    if (to) readings = readings.filter((r) => String(r.ts || "") <= new Date(to).toISOString());
    readings = byTsAsc(readings);

    const sensorMap = new Map(sensors.map((s) => [String(s.id), s]));
    const plotMap = new Map((await listDocs(COL.plots)).map((p) => [String(p.id), p]));
    const nodeMap = new Map(nodes.map((n) => [String(n.id), n]));

    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", 'attachment; filename="readings.csv"');
    res.write("\ufeff");

    const header = ["ts", "plotId", "plotName", "sensorId", "sensorType", "sensorName", "value", "unit"];
    res.write(header.join(",") + "\n");

    for (const r of readings) {
      const s = sensorMap.get(String(r.sensorId));
      const node = s ? nodeMap.get(String(s.nodeId)) : null;
      const plot = node ? plotMap.get(String(node.plotId)) : null;
      const row = {
        ts: r.ts,
        plotId: plot ? String(plot.id) : "",
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

api.get("/dashboard/overview", async (req, res) => {
  const { plotId } = req.query;
  let pins = await listDocs(COL.pins);
  if (plotId) pins = pins.filter((p) => String(p.plotId || "") === String(plotId));
  res.json({ plotId: plotId || "all", on: pins.length, off: 0, issues: 0 });
});

api.get("/dashboard/pins", async (req, res) => {
  const { plotId } = req.query;
  let pins = await listDocs(COL.pins);
  if (plotId) pins = pins.filter((p) => String(p.plotId || "") === String(plotId));
  res.json({ items: byNumberAsc(pins) });
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

app.use("/api", api);

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ message: "Internal Server Error", error: String(err.message || err) });
});

app.listen(process.env.PORT || 3000, () => {
  console.log("[API] running on port", process.env.PORT || 3000);
});
