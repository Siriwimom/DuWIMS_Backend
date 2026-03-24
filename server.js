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

const firestore = admin.firestore();
const app = express();
const api = express.Router();

const PORT = Number(process.env.PORT || 3001);
const BUILD_TAG = "duwims-firestore-v2-structure";
const OTP_TTL_MIN = Number(process.env.OTP_TTL_MIN || 10);
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:3000";
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "7d";

const COLLECTIONS = {
  users: "users",
  plots: "plots",
  managementPlants: "managementPlants",
  sensorReadings: "sensorReadings",
  passwordOtps: "passwordOtps",
};

app.use(cors());
app.use(express.json({ limit: "2mb" }));

const mailer = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASS,
  },
});

const googleOAuth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI
);

function nowIso() {
  return new Date().toISOString();
}

function makeId(prefix = "id") {
  return `${prefix}_${Math.random().toString(36).slice(2, 10)}${Date.now()
    .toString(36)
    .slice(-6)}`;
}

function cleanUndefined(value) {
  if (Array.isArray(value)) return value.map(cleanUndefined);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value)
      .filter(([, v]) => v !== undefined)
      .map(([k, v]) => [k, cleanUndefined(v)])
  );
}

function withId(id, data) {
  if (!data) return null;
  return { id, ...(data || {}) };
}

function toNumberOrNull(value) {
  if (value === "" || value === null || value === undefined) return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function toTrimmed(value) {
  return String(value || "").trim();
}

function toLowerTrimmed(value) {
  return String(value || "").trim().toLowerCase();
}

function isIsoDateLike(value) {
  if (!value) return false;
  const d = new Date(value);
  return !Number.isNaN(d.getTime());
}

function requireStringField(res, value, fieldName) {
  const text = toTrimmed(value);
  if (!text) {
    res.status(400).json({ message: `${fieldName} is required` });
    return null;
  }
  return text;
}

function generateOtp() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function getOtpTtlMs() {
  return OTP_TTL_MIN * 60 * 1000;
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
    { expiresIn: JWT_EXPIRES_IN }
  );
}

function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) {
    return res.status(401).json({ message: "Missing token" });
  }

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }
}

async function getDocById(collectionName, id) {
  const doc = await firestore.collection(collectionName).doc(String(id)).get();
  if (!doc.exists) return null;
  return withId(doc.id, doc.data() || {});
}

async function getUserByEmail(email) {
  const safe = toLowerTrimmed(email);
  if (!safe) return null;
  const snap = await firestore
    .collection(COLLECTIONS.users)
    .where("email", "==", safe)
    .limit(1)
    .get();
  if (snap.empty) return null;
  const doc = snap.docs[0];
  return withId(doc.id, doc.data() || {});
}

async function getUserByNickname(nickname) {
  const safe = toTrimmed(nickname);
  if (!safe) return null;
  const snap = await firestore
    .collection(COLLECTIONS.users)
    .where("nickname", "==", safe)
    .limit(1)
    .get();
  if (snap.empty) return null;
  const doc = snap.docs[0];
  return withId(doc.id, doc.data() || {});
}

async function createUser(input) {
  const id = makeId("user");
  const doc = cleanUndefined({
    email: toLowerTrimmed(input.email),
    passwordHash: input.passwordHash || "",
    nickname: toTrimmed(input.nickname),
    role: toTrimmed(input.role || "employee") || "employee",
    provider: toTrimmed(input.provider || "local") || "local",
    createdAt: nowIso(),
    updatedAt: nowIso(),
  });
  await firestore.collection(COLLECTIONS.users).doc(id).set(doc);
  return withId(id, doc);
}

function makeSafeNickname(name, email) {
  const base =
    toTrimmed(name) || toLowerTrimmed(email).split("@")[0] || "google_user";
  return base.slice(0, 100);
}

async function savePasswordOtp(email, code) {
  const safeEmail = toLowerTrimmed(email);
  await firestore.collection(COLLECTIONS.passwordOtps).doc(safeEmail).set({
    email: safeEmail,
    code: String(code),
    verified: false,
    createdAt: nowIso(),
    expiresAt: Date.now() + getOtpTtlMs(),
  });
}

async function getPasswordOtp(email) {
  const safeEmail = toLowerTrimmed(email);
  const doc = await firestore.collection(COLLECTIONS.passwordOtps).doc(safeEmail).get();
  if (!doc.exists) return null;
  return doc.data() || null;
}

async function markPasswordOtpVerified(email) {
  const safeEmail = toLowerTrimmed(email);
  await firestore.collection(COLLECTIONS.passwordOtps).doc(safeEmail).set(
    {
      verified: true,
      verifiedAt: nowIso(),
    },
    { merge: true }
  );
}

async function deletePasswordOtp(email) {
  const safeEmail = toLowerTrimmed(email);
  await firestore.collection(COLLECTIONS.passwordOtps).doc(safeEmail).delete();
}

async function sendOtpEmail(toEmail, otp) {
  return mailer.sendMail({
    from: `"DuWIMS" <${process.env.MAIL_USER}>`,
    to: toEmail,
    subject: "OTP สำหรับรีเซ็ตรหัสผ่าน",
    text: `รหัส OTP ของคุณคือ ${otp} และจะหมดอายุใน ${OTP_TTL_MIN} นาที`,
    html: `
      <div style="font-family:Arial,sans-serif;line-height:1.6">
        <h2>รีเซ็ตรหัสผ่าน</h2>
        <p>รหัส OTP ของคุณคือ</p>
        <div style="font-size:32px;font-weight:700;letter-spacing:6px">${otp}</div>
        <p>OTP นี้จะหมดอายุใน ${OTP_TTL_MIN} นาที</p>
      </div>
    `,
  });
}

function normalizePolygon(input) {
  const coords = Array.isArray(input) ? input : [];
  return coords
    .map((pt) => ({
      lat: toNumberOrNull(pt?.lat),
      lng: toNumberOrNull(pt?.lng),
    }))
    .filter((pt) => pt.lat !== null && pt.lng !== null);
}

function normalizePolygonPayload(body) {
  // รองรับทั้ง
  // { polygon: [{lat,lng}] }
  // และ { coords: [{lat,lng}] }
  // และ { polygon: { coords: [...] } }

  if (Array.isArray(body?.polygon)) {
    return normalizePolygon(body.polygon);
  }

  if (Array.isArray(body?.coords)) {
    return normalizePolygon(body.coords);
  }

  if (Array.isArray(body?.polygon?.coords)) {
    return normalizePolygon(body.polygon.coords);
  }

  return [];
}

function normalizeSensor(input, existing = null) {
  const id = toTrimmed(input?._id || existing?._id) || makeId("sensor");
  return cleanUndefined({
    _id: id,
    uid: toTrimmed(input?.uid || existing?.uid || id),
    name: toTrimmed(input?.name || existing?.name),
    status: toTrimmed(input?.status || existing?.status || "NO_DATA"),
    minValue:
      input?.minValue !== undefined
        ? toNumberOrNull(input.minValue)
        : toNumberOrNull(existing?.minValue),
    maxValue:
      input?.maxValue !== undefined
        ? toNumberOrNull(input.maxValue)
        : toNumberOrNull(existing?.maxValue),
    latestValue:
      input?.latestValue !== undefined
        ? toNumberOrNull(input.latestValue)
        : toNumberOrNull(existing?.latestValue),
    latestTimestamp:
      input?.latestTimestamp !== undefined
        ? input.latestTimestamp || null
        : existing?.latestTimestamp || null,
  });
}

function normalizeNode(input, existing = null) {
  const id = toTrimmed(input?._id || existing?._id) || makeId("node");
  const sensorsInput = Array.isArray(input?.sensors)
    ? input.sensors
    : Array.isArray(existing?.sensors)
    ? existing.sensors
    : [];

  return cleanUndefined({
    _id: id,
    uid: toTrimmed(input?.uid || existing?.uid || id),
    nodeName: toTrimmed(input?.nodeName || existing?.nodeName),
    status: toTrimmed(input?.status || existing?.status || "INACTIVE"),
    lat:
      input?.lat !== undefined ? toNumberOrNull(input.lat) : toNumberOrNull(existing?.lat),
    lng:
      input?.lng !== undefined ? toNumberOrNull(input.lng) : toNumberOrNull(existing?.lng),
    sensors: sensorsInput.map((sensor) => normalizeSensor(sensor)),
  });
}

function normalizePlotCreate(body) {
  return cleanUndefined({
    plotName: toTrimmed(body.plotName),
    caretaker: toTrimmed(body.caretaker),
    polygon: normalizePolygon(body.polygon),
    nodes: Array.isArray(body.nodes) ? body.nodes.map((n) => normalizeNode(n)) : [],
    createdAt: nowIso(),
    updatedAt: nowIso(),
  });
}

function normalizePlotPatch(existing, body) {
  const output = {
    plotName:
      body.plotName !== undefined ? toTrimmed(body.plotName) : existing.plotName || "",
    caretaker:
      body.caretaker !== undefined ? toTrimmed(body.caretaker) : existing.caretaker || "",
    polygon:
      body.polygon !== undefined ? normalizePolygon(body.polygon) : existing.polygon || [],
    nodes:
      body.nodes !== undefined
        ? (Array.isArray(body.nodes) ? body.nodes.map((n) => normalizeNode(n)) : [])
        : existing.nodes || [],
    createdAt: existing.createdAt || nowIso(),
    updatedAt: nowIso(),
  };
  return cleanUndefined(output);
}

function normalizeManagementPlantCreate(body) {
  return cleanUndefined({
    plot: toTrimmed(body.plot),
    species: toTrimmed(body.species),
    startDate: body.startDate || null,
    harvestDate: body.harvestDate || null,
    volume: toNumberOrNull(body.volume),
    createdAt: nowIso(),
    updatedAt: nowIso(),
  });
}

function normalizeManagementPlantPatch(existing, body) {
  return cleanUndefined({
    plot: body.plot !== undefined ? toTrimmed(body.plot) : existing.plot || "",
    species: body.species !== undefined ? toTrimmed(body.species) : existing.species || "",
    startDate: body.startDate !== undefined ? body.startDate || null : existing.startDate || null,
    harvestDate:
      body.harvestDate !== undefined ? body.harvestDate || null : existing.harvestDate || null,
    volume: body.volume !== undefined ? toNumberOrNull(body.volume) : toNumberOrNull(existing.volume),
    createdAt: existing.createdAt || nowIso(),
    updatedAt: nowIso(),
  });
}

async function findPlotContainingSensor(plotId, nodeId, sensorId) {
  const plot = await getDocById(COLLECTIONS.plots, plotId);
  if (!plot) return null;
  const nodeIndex = Array.isArray(plot.nodes)
    ? plot.nodes.findIndex((n) => String(n?._id) === String(nodeId))
    : -1;
  if (nodeIndex < 0) return null;
  const sensors = Array.isArray(plot.nodes[nodeIndex]?.sensors) ? plot.nodes[nodeIndex].sensors : [];
  const sensorIndex = sensors.findIndex((s) => String(s?._id) === String(sensorId));
  if (sensorIndex < 0) return null;
  return { plot, nodeIndex, sensorIndex };
}

async function syncLatestSensorState({ plotId, nodeId, sensorId, value, timestamp, status }) {
  const found = await findPlotContainingSensor(plotId, nodeId, sensorId);
  if (!found) return false;

  const plotDoc = found.plot;
  const nextNodes = Array.isArray(plotDoc.nodes) ? [...plotDoc.nodes] : [];
  const nextNode = { ...(nextNodes[found.nodeIndex] || {}) };
  const nextSensors = Array.isArray(nextNode.sensors) ? [...nextNode.sensors] : [];
  const currentSensor = { ...(nextSensors[found.sensorIndex] || {}) };

  currentSensor.latestValue = toNumberOrNull(value);
  currentSensor.latestTimestamp = timestamp;
  currentSensor.status = toTrimmed(status || currentSensor.status || "OK") || "OK";

  nextSensors[found.sensorIndex] = currentSensor;
  nextNode.sensors = nextSensors;
  nextNode.status = nextNode.status || "ONLINE";
  nextNodes[found.nodeIndex] = nextNode;

  await firestore.collection(COLLECTIONS.plots).doc(String(plotId)).set(
    {
      nodes: nextNodes,
      updatedAt: nowIso(),
    },
    { merge: true }
  );

  return true;
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
        ts: nowIso(),
      },
      { merge: true }
    );
    res.json({ ok: true, message: "Cloud Firestore connected" });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.post("/auth/register", async (req, res) => {
  try {
    const email = requireStringField(res, req.body?.email, "email");
    if (!email) return;
    const password = requireStringField(res, req.body?.password, "password");
    if (!password) return;
    const nickname = requireStringField(res, req.body?.nickname, "nickname");
    if (!nickname) return;

    const safeEmail = toLowerTrimmed(email);
    if (password.length < 6) {
      return res.status(400).json({ message: "password must be at least 6 characters" });
    }

    const exists = await getUserByEmail(safeEmail);
    if (exists) {
      return res.status(409).json({ message: "email already exists" });
    }

    const nicknameExists = await getUserByNickname(nickname);
    if (nicknameExists) {
      return res.status(409).json({ message: "nickname already exists" });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await createUser({
      email: safeEmail,
      passwordHash,
      nickname,
      role: toTrimmed(req.body?.role || "employee") || "employee",
      provider: "local",
    });

    const token = buildAuthToken(user);
    return res.status(201).json({
      ok: true,
      token,
      user: {
        id: user.id,
        email: user.email,
        nickname: user.nickname,
        role: user.role,
        provider: user.provider,
      },
    });
  } catch (e) {
    return res.status(500).json({ message: "Register failed", error: String(e.message || e) });
  }
});

app.post("/auth/login", async (req, res) => {
  try {
    const email = requireStringField(res, req.body?.email, "email");
    if (!email) return;
    const password = requireStringField(res, req.body?.password, "password");
    if (!password) return;

    const user = await getUserByEmail(email);
    if (!user || !user.passwordHash) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const token = buildAuthToken(user);
    return res.json({
      ok: true,
      token,
      user: {
        id: user.id,
        email: user.email,
        nickname: user.nickname,
        role: user.role,
        provider: user.provider,
      },
    });
  } catch (e) {
    return res.status(500).json({ message: "Login failed", error: String(e.message || e) });
  }
});

app.post("/auth/forgot-password/send-otp", async (req, res) => {
  try {
    const email = requireStringField(res, req.body?.email, "email");
    if (!email) return;

    const user = await getUserByEmail(email);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const otp = generateOtp();
    await savePasswordOtp(email, otp);
    await sendOtpEmail(email, otp);

    return res.json({ ok: true, message: "OTP sent" });
  } catch (e) {
    return res.status(500).json({ message: "Send OTP failed", error: String(e.message || e) });
  }
});

app.post("/auth/forgot-password/verify-otp", async (req, res) => {
  try {
    const email = requireStringField(res, req.body?.email, "email");
    if (!email) return;
    const code = requireStringField(res, req.body?.code, "code");
    if (!code) return;

    const saved = await getPasswordOtp(email);
    if (!saved) {
      return res.status(404).json({ message: "OTP not found" });
    }
    if (Date.now() > Number(saved.expiresAt || 0)) {
      await deletePasswordOtp(email);
      return res.status(400).json({ message: "OTP expired" });
    }
    if (String(saved.code) !== String(code)) {
      return res.status(400).json({ message: "Invalid OTP" });
    }

    await markPasswordOtpVerified(email);
    return res.json({ ok: true, message: "OTP verified" });
  } catch (e) {
    return res.status(500).json({ message: "Verify OTP failed", error: String(e.message || e) });
  }
});

app.post("/auth/forgot-password/reset", async (req, res) => {
  try {
    const email = requireStringField(res, req.body?.email, "email");
    if (!email) return;
    const newPassword = requireStringField(res, req.body?.newPassword, "newPassword");
    if (!newPassword) return;

    if (newPassword.length < 6) {
      return res.status(400).json({ message: "newPassword must be at least 6 characters" });
    }

    const saved = await getPasswordOtp(email);
    if (!saved || !saved.verified) {
      return res.status(400).json({ message: "OTP not verified" });
    }
    if (Date.now() > Number(saved.expiresAt || 0)) {
      await deletePasswordOtp(email);
      return res.status(400).json({ message: "OTP expired" });
    }

    const user = await getUserByEmail(email);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const passwordHash = await bcrypt.hash(newPassword, 10);
    await firestore.collection(COLLECTIONS.users).doc(user.id).set(
      {
        passwordHash,
        updatedAt: nowIso(),
      },
      { merge: true }
    );

    await deletePasswordOtp(email);
    return res.json({ ok: true, message: "Password reset successful" });
  } catch (e) {
    return res.status(500).json({ message: "Reset password failed", error: String(e.message || e) });
  }
});

app.get("/auth/google", (req, res) => {
  const url = googleOAuth2Client.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: ["openid", "email", "profile"],
  });
  res.json({ url });
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
    return res.status(500).json({ message: "Google auth start failed", error: String(e.message || e) });
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

    const email = toLowerTrimmed(me?.data?.email);
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
        passwordHash: "",
        nickname,
        role: "employee",
        provider: "google",
      });
    }

    const token = buildAuthToken(user);
    return res.redirect(`${FRONTEND_URL}/login?token=${encodeURIComponent(token)}`);
  } catch (e) {
    return res.redirect(
      `${FRONTEND_URL}/login?error=${encodeURIComponent(e?.message || "Google auth failed")}`
    );
  }
});

app.get("/auth/me", auth, async (req, res) => {
  return res.json({ user: req.user });
});

api.use(auth);

api.get("/users", async (req, res, next) => {
  try {
    let ref = firestore.collection(COLLECTIONS.users);
    const role = toLowerTrimmed(req.query.role);
    if (role) ref = ref.where("role", "==", role);
    const snap = await ref.get();
    const items = snap.docs.map((doc) => {
      const data = doc.data() || {};
      return {
        id: doc.id,
        email: data.email || "",
        nickname: data.nickname || "",
        role: data.role || "",
        provider: data.provider || "",
        createdAt: data.createdAt || "",
        updatedAt: data.updatedAt || "",
      };
    });
    res.json({ items });
  } catch (e) {
    next(e);
  }
});

api.get("/plots", async (req, res, next) => {
  try {
    const snap = await firestore.collection(COLLECTIONS.plots).orderBy("createdAt", "desc").get();
    const items = snap.docs.map((doc) => withId(doc.id, doc.data() || {}));
    res.json({ items });
  } catch (e) {
    next(e);
  }
});

api.post("/plots", async (req, res, next) => {
  try {
    const data = normalizePlotCreate(req.body || {});
    if (!data.plotName) return res.status(400).json({ message: "plotName is required" });
    if (!data.caretaker) return res.status(400).json({ message: "caretaker is required" });

    const caretaker = await getDocById(COLLECTIONS.users, data.caretaker);
    if (!caretaker) return res.status(400).json({ message: "caretaker user not found" });

    const id = makeId("plot");
    await firestore.collection(COLLECTIONS.plots).doc(id).set(data);
    res.status(201).json({ item: withId(id, data) });
  } catch (e) {
    next(e);
  }
});

api.get("/plots/:plotId", async (req, res, next) => {
  try {
    const item = await getDocById(COLLECTIONS.plots, req.params.plotId);
    if (!item) return res.status(404).json({ message: "plot not found" });
    res.json({ item });
  } catch (e) {
    next(e);
  }
});

api.patch("/plots/:plotId", async (req, res, next) => {
  try {
    const plot = await getDocById(COLLECTIONS.plots, req.params.plotId);
    if (!plot) return res.status(404).json({ message: "plot not found" });

    const nextData = normalizePlotPatch(plot, req.body || {});
    if (!nextData.plotName) return res.status(400).json({ message: "plotName is required" });
    if (!nextData.caretaker) return res.status(400).json({ message: "caretaker is required" });

    const caretaker = await getDocById(COLLECTIONS.users, nextData.caretaker);
    if (!caretaker) return res.status(400).json({ message: "caretaker user not found" });

    await firestore.collection(COLLECTIONS.plots).doc(req.params.plotId).set(nextData, { merge: false });
    res.json({ item: withId(req.params.plotId, nextData) });
  } catch (e) {
    next(e);
  }
});

api.delete("/plots/:plotId", async (req, res, next) => {
  try {
    const plotId = String(req.params.plotId);
    const plot = await getDocById(COLLECTIONS.plots, plotId);
    if (!plot) return res.status(404).json({ message: "plot not found" });

    await firestore.collection(COLLECTIONS.plots).doc(plotId).delete();

    const mgmtSnap = await firestore
      .collection(COLLECTIONS.managementPlants)
      .where("plot", "==", plotId)
      .get();
    const readingsSnap = await firestore
      .collection(COLLECTIONS.sensorReadings)
      .where("plotId", "==", plotId)
      .get();

    const batch = firestore.batch();
    mgmtSnap.docs.forEach((doc) => batch.delete(doc.ref));
    readingsSnap.docs.forEach((doc) => batch.delete(doc.ref));
    await batch.commit();

    res.json({ ok: true, deletedId: plotId });
  } catch (e) {
    next(e);
  }
});

api.put("/plots/:plotId/polygon", async (req, res, next) => {
  try {
    const plot = await getDocById(COLLECTIONS.plots, req.params.plotId);
    if (!plot) return res.status(404).json({ message: "plot not found" });
    const polygon = normalizePolygon(req.body?.polygon);
    await firestore.collection(COLLECTIONS.plots).doc(req.params.plotId).set(
      {
        polygon,
        updatedAt: nowIso(),
      },
      { merge: true }
    );
    res.json({ ok: true, polygon });
  } catch (e) {
    next(e);
  }
});
api.put("/plots/:plotId/polygon", async (req, res, next) => {
  try {
    const plot = await getDocById(COLLECTIONS.plots, req.params.plotId);
    if (!plot) return res.status(404).json({ message: "plot not found" });

    const polygon = normalizePolygonPayload(req.body || {});
    if (polygon.length < 3) {
      return res.status(400).json({ message: "polygon must have at least 3 points" });
    }

    await firestore.collection(COLLECTIONS.plots).doc(req.params.plotId).set(
      {
        polygon,
        updatedAt: nowIso(),
      },
      { merge: true }
    );

    res.json({
      ok: true,
      item: {
        plotId: req.params.plotId,
        coords: polygon,
      },
    });
  } catch (e) {
    next(e);
  }
});
api.get("/plots/:plotId/polygon", async (req, res, next) => {
  try {
    const plot = await getDocById(COLLECTIONS.plots, req.params.plotId);
    if (!plot) return res.status(404).json({ message: "plot not found" });

    const polygon = normalizePolygon(plot.polygon || []);

    res.json({
      item: {
        plotId: req.params.plotId,
        coords: polygon,
      },
    });
  } catch (e) {
    next(e);
  }
});
api.delete("/plots/:plotId/polygon", async (req, res, next) => {
  try {
    const plot = await getDocById(COLLECTIONS.plots, req.params.plotId);
    if (!plot) return res.status(404).json({ message: "plot not found" });

    await firestore.collection(COLLECTIONS.plots).doc(req.params.plotId).set(
      {
        polygon: [],
        updatedAt: nowIso(),
      },
      { merge: true }
    );

    res.json({
      ok: true,
      item: {
        plotId: req.params.plotId,
        coords: [],
      },
    });
  } catch (e) {
    next(e);
  }
});

api.post("/plots/:plotId/nodes", async (req, res, next) => {
  try {
    const plot = await getDocById(COLLECTIONS.plots, req.params.plotId);
    if (!plot) return res.status(404).json({ message: "plot not found" });

    const node = normalizeNode(req.body || {});
    if (!node.nodeName) return res.status(400).json({ message: "nodeName is required" });
    if (!node.uid) return res.status(400).json({ message: "uid is required" });
    if (node.lat === null || node.lng === null) {
      return res.status(400).json({ message: "lat and lng are required" });
    }

    const nodes = Array.isArray(plot.nodes) ? plot.nodes : [];
    const dupUid = nodes.find((n) => String(n?.uid) === String(node.uid));
    if (dupUid) return res.status(409).json({ message: "node uid already exists in this plot" });

    const nextNodes = [...nodes, node];
    await firestore.collection(COLLECTIONS.plots).doc(req.params.plotId).set(
      {
        nodes: nextNodes,
        updatedAt: nowIso(),
      },
      { merge: true }
    );

    res.status(201).json({ item: node });
  } catch (e) {
    next(e);
  }
});

api.patch("/plots/:plotId/nodes/:nodeId", async (req, res, next) => {
  try {
    const plot = await getDocById(COLLECTIONS.plots, req.params.plotId);
    if (!plot) return res.status(404).json({ message: "plot not found" });

    const nodes = Array.isArray(plot.nodes) ? [...plot.nodes] : [];
    const index = nodes.findIndex((n) => String(n?._id) === String(req.params.nodeId));
    if (index < 0) return res.status(404).json({ message: "node not found" });

    const existing = nodes[index];
    const next = normalizeNode({ ...existing, ...req.body, sensors: req.body?.sensors ?? existing.sensors }, existing);
    if (!next.nodeName) return res.status(400).json({ message: "nodeName is required" });
    if (!next.uid) return res.status(400).json({ message: "uid is required" });
    if (next.lat === null || next.lng === null) {
      return res.status(400).json({ message: "lat and lng are required" });
    }

    const dupUid = nodes.find(
      (n, i) => i !== index && String(n?.uid) === String(next.uid)
    );
    if (dupUid) return res.status(409).json({ message: "node uid already exists in this plot" });

    nodes[index] = next;
    await firestore.collection(COLLECTIONS.plots).doc(req.params.plotId).set(
      {
        nodes,
        updatedAt: nowIso(),
      },
      { merge: true }
    );

    res.json({ item: next });
  } catch (e) {
    next(e);
  }
});

api.delete("/plots/:plotId/nodes/:nodeId", async (req, res, next) => {
  try {
    const plotId = String(req.params.plotId);
    const nodeId = String(req.params.nodeId);
    const plot = await getDocById(COLLECTIONS.plots, plotId);
    if (!plot) return res.status(404).json({ message: "plot not found" });

    const nodes = Array.isArray(plot.nodes) ? plot.nodes : [];
    const found = nodes.find((n) => String(n?._id) === nodeId);
    if (!found) return res.status(404).json({ message: "node not found" });

    const nextNodes = nodes.filter((n) => String(n?._id) !== nodeId);
    await firestore.collection(COLLECTIONS.plots).doc(plotId).set(
      {
        nodes: nextNodes,
        updatedAt: nowIso(),
      },
      { merge: true }
    );

    const readingsSnap = await firestore
      .collection(COLLECTIONS.sensorReadings)
      .where("plotId", "==", plotId)
      .where("nodeId", "==", nodeId)
      .get();
    const batch = firestore.batch();
    readingsSnap.docs.forEach((doc) => batch.delete(doc.ref));
    await batch.commit();

    res.json({ ok: true, deletedId: nodeId });
  } catch (e) {
    next(e);
  }
});

api.post("/plots/:plotId/nodes/:nodeId/sensors", async (req, res, next) => {
  try {
    const plot = await getDocById(COLLECTIONS.plots, req.params.plotId);
    if (!plot) return res.status(404).json({ message: "plot not found" });

    const nodes = Array.isArray(plot.nodes) ? [...plot.nodes] : [];
    const nodeIndex = nodes.findIndex((n) => String(n?._id) === String(req.params.nodeId));
    if (nodeIndex < 0) return res.status(404).json({ message: "node not found" });

    const node = { ...(nodes[nodeIndex] || {}) };
    const sensors = Array.isArray(node.sensors) ? [...node.sensors] : [];
    const sensor = normalizeSensor(req.body || {});
    if (!sensor.name) return res.status(400).json({ message: "sensor name is required" });
    if (!sensor.uid) return res.status(400).json({ message: "sensor uid is required" });

    const dupUid = sensors.find((s) => String(s?.uid) === String(sensor.uid));
    if (dupUid) return res.status(409).json({ message: "sensor uid already exists in this node" });

    sensors.push(sensor);
    node.sensors = sensors;
    nodes[nodeIndex] = node;

    await firestore.collection(COLLECTIONS.plots).doc(req.params.plotId).set(
      {
        nodes,
        updatedAt: nowIso(),
      },
      { merge: true }
    );

    res.status(201).json({ item: sensor });
  } catch (e) {
    next(e);
  }
});

api.patch("/plots/:plotId/nodes/:nodeId/sensors/:sensorId", async (req, res, next) => {
  try {
    const plot = await getDocById(COLLECTIONS.plots, req.params.plotId);
    if (!plot) return res.status(404).json({ message: "plot not found" });

    const nodes = Array.isArray(plot.nodes) ? [...plot.nodes] : [];
    const nodeIndex = nodes.findIndex((n) => String(n?._id) === String(req.params.nodeId));
    if (nodeIndex < 0) return res.status(404).json({ message: "node not found" });

    const node = { ...(nodes[nodeIndex] || {}) };
    const sensors = Array.isArray(node.sensors) ? [...node.sensors] : [];
    const sensorIndex = sensors.findIndex((s) => String(s?._id) === String(req.params.sensorId));
    if (sensorIndex < 0) return res.status(404).json({ message: "sensor not found" });

    const existing = sensors[sensorIndex];
    const next = normalizeSensor({ ...existing, ...req.body }, existing);
    if (!next.name) return res.status(400).json({ message: "sensor name is required" });
    if (!next.uid) return res.status(400).json({ message: "sensor uid is required" });

    const dupUid = sensors.find(
      (s, i) => i !== sensorIndex && String(s?.uid) === String(next.uid)
    );
    if (dupUid) return res.status(409).json({ message: "sensor uid already exists in this node" });

    sensors[sensorIndex] = next;
    node.sensors = sensors;
    nodes[nodeIndex] = node;

    await firestore.collection(COLLECTIONS.plots).doc(req.params.plotId).set(
      {
        nodes,
        updatedAt: nowIso(),
      },
      { merge: true }
    );

    res.json({ item: next });
  } catch (e) {
    next(e);
  }
});

api.delete("/plots/:plotId/nodes/:nodeId/sensors/:sensorId", async (req, res, next) => {
  try {
    const plotId = String(req.params.plotId);
    const nodeId = String(req.params.nodeId);
    const sensorId = String(req.params.sensorId);
    const plot = await getDocById(COLLECTIONS.plots, plotId);
    if (!plot) return res.status(404).json({ message: "plot not found" });

    const nodes = Array.isArray(plot.nodes) ? [...plot.nodes] : [];
    const nodeIndex = nodes.findIndex((n) => String(n?._id) === nodeId);
    if (nodeIndex < 0) return res.status(404).json({ message: "node not found" });

    const node = { ...(nodes[nodeIndex] || {}) };
    const sensors = Array.isArray(node.sensors) ? node.sensors : [];
    const found = sensors.find((s) => String(s?._id) === sensorId);
    if (!found) return res.status(404).json({ message: "sensor not found" });

    node.sensors = sensors.filter((s) => String(s?._id) !== sensorId);
    nodes[nodeIndex] = node;

    await firestore.collection(COLLECTIONS.plots).doc(plotId).set(
      {
        nodes,
        updatedAt: nowIso(),
      },
      { merge: true }
    );

    const readingsSnap = await firestore
      .collection(COLLECTIONS.sensorReadings)
      .where("plotId", "==", plotId)
      .where("nodeId", "==", nodeId)
      .where("sensorId", "==", sensorId)
      .get();
    const batch = firestore.batch();
    readingsSnap.docs.forEach((doc) => batch.delete(doc.ref));
    await batch.commit();

    res.json({ ok: true, deletedId: sensorId });
  } catch (e) {
    next(e);
  }
});

api.get("/management-plants", async (req, res, next) => {
  try {
    let ref = firestore.collection(COLLECTIONS.managementPlants);
    const plotId = toTrimmed(req.query.plot);
    if (plotId) ref = ref.where("plot", "==", plotId);
    const snap = await ref.orderBy("createdAt", "desc").get();
    const items = snap.docs.map((doc) => withId(doc.id, doc.data() || {}));
    res.json({ items });
  } catch (e) {
    next(e);
  }
});

api.post("/management-plants", async (req, res, next) => {
  try {
    const data = normalizeManagementPlantCreate(req.body || {});
    if (!data.plot) return res.status(400).json({ message: "plot is required" });
    if (!data.species) return res.status(400).json({ message: "species is required" });
    if (!data.startDate || !isIsoDateLike(data.startDate)) {
      return res.status(400).json({ message: "startDate is required" });
    }
    const plot = await getDocById(COLLECTIONS.plots, data.plot);
    if (!plot) return res.status(400).json({ message: "plot not found" });

    const id = makeId("mgmt");
    await firestore.collection(COLLECTIONS.managementPlants).doc(id).set(data);
    res.status(201).json({ item: withId(id, data) });
  } catch (e) {
    next(e);
  }
});

api.patch("/management-plants/:managementId", async (req, res, next) => {
  try {
    const existing = await getDocById(COLLECTIONS.managementPlants, req.params.managementId);
    if (!existing) return res.status(404).json({ message: "management plant not found" });

    const nextData = normalizeManagementPlantPatch(existing, req.body || {});
    if (!nextData.plot) return res.status(400).json({ message: "plot is required" });
    if (!nextData.species) return res.status(400).json({ message: "species is required" });

    const plot = await getDocById(COLLECTIONS.plots, nextData.plot);
    if (!plot) return res.status(400).json({ message: "plot not found" });

    await firestore.collection(COLLECTIONS.managementPlants).doc(req.params.managementId).set(nextData, { merge: false });
    res.json({ item: withId(req.params.managementId, nextData) });
  } catch (e) {
    next(e);
  }
});

api.delete("/management-plants/:managementId", async (req, res, next) => {
  try {
    const existing = await getDocById(COLLECTIONS.managementPlants, req.params.managementId);
    if (!existing) return res.status(404).json({ message: "management plant not found" });
    await firestore.collection(COLLECTIONS.managementPlants).doc(req.params.managementId).delete();
    res.json({ ok: true, deletedId: req.params.managementId });
  } catch (e) {
    next(e);
  }
});

api.get("/sensor-readings", async (req, res, next) => {
  try {
    const sensorId = toTrimmed(req.query.sensorId);
    const plotId = toTrimmed(req.query.plotId);
    const nodeId = toTrimmed(req.query.nodeId);
    const limit = Math.min(Number(req.query.limit || 100), 500);

    let ref = firestore.collection(COLLECTIONS.sensorReadings);
    if (sensorId) ref = ref.where("sensorId", "==", sensorId);
    if (plotId) ref = ref.where("plotId", "==", plotId);
    if (nodeId) ref = ref.where("nodeId", "==", nodeId);

    const snap = await ref.orderBy("timestamp", "desc").limit(limit).get();
    const items = snap.docs.map((doc) => withId(doc.id, doc.data() || {}));
    res.json({ items });
  } catch (e) {
    next(e);
  }
});

api.post("/sensor-readings", async (req, res, next) => {
  try {
    const plotId = requireStringField(res, req.body?.plotId, "plotId");
    if (!plotId) return;
    const nodeId = requireStringField(res, req.body?.nodeId, "nodeId");
    if (!nodeId) return;
    const sensorId = requireStringField(res, req.body?.sensorId, "sensorId");
    if (!sensorId) return;

    const value = toNumberOrNull(req.body?.value);
    if (value === null) return res.status(400).json({ message: "value is required" });

    const timestamp = req.body?.timestamp && isIsoDateLike(req.body.timestamp) ? req.body.timestamp : nowIso();
    const found = await findPlotContainingSensor(plotId, nodeId, sensorId);
    if (!found) {
      return res.status(400).json({ message: "sensor not found in plot/node" });
    }

    const sensor = found.plot.nodes[found.nodeIndex].sensors[found.sensorIndex];
    const reading = cleanUndefined({
      plotId,
      nodeId,
      sensorId,
      sensorName: sensor.name || "",
      value,
      timestamp,
      status: toTrimmed(req.body?.status || sensor.status || "OK") || "OK",
      createdAt: nowIso(),
    });

    const id = makeId("reading");
    await firestore.collection(COLLECTIONS.sensorReadings).doc(id).set(reading);
    await syncLatestSensorState({
      plotId,
      nodeId,
      sensorId,
      value,
      timestamp,
      status: reading.status,
    });

    res.status(201).json({ item: withId(id, reading) });
  } catch (e) {
    next(e);
  }
});

api.get("/sensor-readings/latest", async (req, res, next) => {
  try {
    const sensorId = requireStringField(res, req.query.sensorId, "sensorId");
    if (!sensorId) return;

    const snap = await firestore
      .collection(COLLECTIONS.sensorReadings)
      .where("sensorId", "==", sensorId)
      .orderBy("timestamp", "desc")
      .limit(1)
      .get();

    if (snap.empty) return res.status(404).json({ message: "No readings found" });
    const doc = snap.docs[0];
    res.json({ item: withId(doc.id, doc.data() || {}) });
  } catch (e) {
    next(e);
  }
});

app.use("/api", api);

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({
    message: err?.message || "Internal Server Error",
  });
});

app.listen(PORT, () => {
  console.log("========================================");
  console.log("[SERVER] BUILD:", BUILD_TAG);
  console.log("[SERVER] FILE :", __filename);
  console.log("[SERVER] CWD  :", process.cwd());
  console.log("[SERVER] PORT :", PORT);
  console.log("========================================");
});
