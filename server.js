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
  nodes: "node",
  history: "history",
  managementPlants: "managementPlants",
  sensorReadings: "sensorReadings",
  passwordOtps: "passwordOtps",
  emailVerifications: "emailVerifications",
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
      ownerUid: user.ownerUid || "",
      ownerRef: user.ownerRef || "",
    },
    process.env.JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
}

function sanitizeUser(user) {
  if (!user) return null;
  return {
    id: user.id,
    email: user.email || "",
    nickname: user.nickname || "",
    role: user.role || "",
    ownerUid: user.ownerUid || "",
    ownerRef: user.ownerRef || "",
    provider: user.provider || "local",
    isEmailVerified: !!user.isEmailVerified,
    createdAt: user.createdAt || "",
    updatedAt: user.updatedAt || "",
  };
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



async function getUniqueOwnerUid() {
  while (true) {
    const candidate = generateOwnerUid();
    const existing = await getUserByOwnerUid(candidate);
    if (!existing) return candidate;
  }
}

async function getUserByOwnerUid(ownerUid) {
  const safe = toTrimmed(ownerUid);
  if (!safe) return null;

  const snap = await firestore
    .collection(COLLECTIONS.users)
    .where("ownerUid", "==", safe)
    .where("role", "==", "owner")
    .limit(1)
    .get();

  if (snap.empty) return null;
  const doc = snap.docs[0];
  return withId(doc.id, doc.data() || {});
}

function getOwnerScope(user) {
  if (!user) return "";
  if (String(user.role || "").toLowerCase() === "owner") return String(user.id || "");
  return String(user.ownerRef || "");
}

function canAccessOwnedDoc(user, ownerRef) {
  return String(getOwnerScope(user)) === String(ownerRef || "");
}

async function createUser(input) {
  const id = makeId("user");
  const role = toTrimmed(input.role || "employee") || "employee";

  let ownerUid = "";
  let ownerRef = "";

  if (role === "owner") {
    ownerUid = await getUniqueOwnerUid();
    ownerRef = id;
  } else {
    ownerUid = "";
    ownerRef = "";
  }

  const doc = cleanUndefined({
    email: toLowerTrimmed(input.email),
    passwordHash: input.passwordHash || "",
    nickname: toTrimmed(input.nickname),
    role,
    ownerUid,
    ownerRef,
    provider: toTrimmed(input.provider || "local") || "local",
    isEmailVerified: Boolean(input.isEmailVerified || false),
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
async function saveEmailVerification(email, code) {
  const safeEmail = toLowerTrimmed(email);
  await firestore.collection(COLLECTIONS.emailVerifications).doc(safeEmail).set({
    email: safeEmail,
    code: String(code),
    verified: false,
    createdAt: nowIso(),
    expiresAt: Date.now() + getOtpTtlMs(),
  });
}

async function getEmailVerification(email) {
  const safeEmail = toLowerTrimmed(email);
  const doc = await firestore
    .collection(COLLECTIONS.emailVerifications)
    .doc(safeEmail)
    .get();
  if (!doc.exists) return null;
  return doc.data() || null;
}

async function markEmailVerificationVerified(email) {
  const safeEmail = toLowerTrimmed(email);
  await firestore.collection(COLLECTIONS.emailVerifications).doc(safeEmail).set(
    {
      verified: true,
      verifiedAt: nowIso(),
    },
    { merge: true }
  );
}

async function deleteEmailVerification(email) {
  const safeEmail = toLowerTrimmed(email);
  await firestore
    .collection(COLLECTIONS.emailVerifications)
    .doc(safeEmail)
    .delete();
}

async function sendVerificationEmail(toEmail, code) {
  return mailer.sendMail({
    from: `"DuWIMS" <${process.env.MAIL_USER}>`,
    to: toEmail,
    subject: "ยืนยันอีเมลสำหรับสมัครสมาชิก DuWIMS",
    text: `รหัสยืนยันอีเมลของคุณคือ ${code} และจะหมดอายุใน ${OTP_TTL_MIN} นาที`,
    html: `
      <div style="font-family:Arial,sans-serif;line-height:1.6">
        <h2>ยืนยันอีเมล</h2>
        <p>รหัสยืนยันอีเมลของคุณคือ</p>
        <div style="font-size:32px;font-weight:700;letter-spacing:6px">${code}</div>
        <p>รหัสนี้จะหมดอายุใน ${OTP_TTL_MIN} นาที</p>
      </div>
    `,
  });
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
function sanitizeNodeDoc(node) {
  if (!node) return null;

  return cleanUndefined({
    _id: toTrimmed(node._id || node.id) || "",
    uid: toTrimmed(node.uid || ""),
    nodeName: toTrimmed(node.nodeName || ""),
    status: toTrimmed(node.status || "ACTIVE") || "ACTIVE",
    lat:
      node.lat === undefined ? null : toNumberOrNull(node.lat),
    lng:
      node.lng === undefined ? null : toNumberOrNull(node.lng),
    plotId:
      node.plotId === undefined || node.plotId === null || node.plotId === ""
        ? null
        : toTrimmed(node.plotId),
    ownerRef: toTrimmed(node.ownerRef || ""),
    sensors: Array.isArray(node.sensors)
      ? node.sensors.map((s) => normalizeSensor(s))
      : [],
    createdAt: node.createdAt || nowIso(),
    updatedAt: nowIso(),
  });
}

async function getNodeByUidForOwner(uid, ownerRef) {
  const safeUid = toTrimmed(uid);
  if (!safeUid) return null;

  if (ownerRef) {
    const scopedSnap = await firestore
      .collection(COLLECTIONS.nodes)
      .where("uid", "==", safeUid)
      .where("ownerRef", "==", ownerRef)
      .limit(1)
      .get();

    if (!scopedSnap.empty) {
      const doc = scopedSnap.docs[0];
      return withId(doc.id, doc.data() || {});
    }
  }

  // fallback สำหรับ node เก่าที่ยังไม่มี ownerRef
  const fallbackSnap = await firestore
    .collection(COLLECTIONS.nodes)
    .where("uid", "==", safeUid)
    .limit(1)
    .get();

  if (fallbackSnap.empty) return null;
  const doc = fallbackSnap.docs[0];
  return withId(doc.id, doc.data() || {});
}

async function getNodeByIdForOwner(nodeId, ownerRef) {
  const node = await getDocById(COLLECTIONS.nodes, nodeId);
  if (!node) return null;
  if (String(node.ownerRef || "") !== String(ownerRef || "")) return null;
  return node;
}

async function getNodesByPlotId(plotId, ownerRef) {
  const snap = await firestore
    .collection(COLLECTIONS.nodes)
    .where("plotId", "==", String(plotId))
    .where("ownerRef", "==", String(ownerRef))
    .get();

  return snap.docs.map((doc) => sanitizeNodeDoc(withId(doc.id, doc.data() || {})));
}

async function attachNodesToPlot(plot) {
  if (!plot) return null;
  const nodes = await getNodesByPlotId(plot.id, plot.ownerRef);
  return {
    ...plot,
    nodes,
  };
}

function normalizePlotCreate(body) {
  const caretaker = toTrimmed(body.caretaker);

  return cleanUndefined({
    plotName: toTrimmed(body.plotName),
    caretaker: caretaker || undefined,
    polygon: normalizePolygon(body.polygon),
    nodes: Array.isArray(body.nodes) ? body.nodes.map((n) => normalizeNode(n)) : [],
    createdAt: nowIso(),
    updatedAt: nowIso(),
  });
}

function normalizePlotPatch(existing, body) {
  const caretaker =
    body.caretaker !== undefined
      ? toTrimmed(body.caretaker) || undefined
      : existing.caretaker || undefined;

  const output = {
    plotName:
      body.plotName !== undefined ? toTrimmed(body.plotName) : existing.plotName || "",
    caretaker,
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
function generateOwnerUid() {
  return `DW-${Math.random().toString(36).slice(2, 6).toUpperCase()}${Date.now()
    .toString(36)
    .slice(-4)
    .toUpperCase()}`;
}

async function getUserByOwnerUid(ownerUid) {
  const snap = await firestore
    .collection(COLLECTIONS.users)
    .where("ownerUid", "==", ownerUid)
    .where("role", "==", "owner")
    .limit(1)
    .get();

  if (snap.empty) return null;
  const doc = snap.docs[0];
  return withId(doc.id, doc.data());
}

function getOwnerScope(user) {
  if (user.role === "owner") return user.id;
  return user.ownerRef;
}

app.get("/__version", (req, res) => {
  res.json({ build: BUILD_TAG, file: __filename, cwd: process.cwd() });
});

app.get("/health", (req, res) => res.json({ ok: true, build: BUILD_TAG, message: "14/4/2026 - Server is healthy12" }));

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

    const safeEmail = toLowerTrimmed(email);

    if (password.length < 8) {
      return res.status(400).json({ message: "password must be at least 8 characters" });
    }

    const exists = await getUserByEmail(safeEmail);
    if (exists) {
      return res.status(409).json({ message: "email already exists" });
    }

    const passwordHash = await bcrypt.hash(password, 10);



    const role = toTrimmed(req.body?.role || "employee") || "employee";

    const user = await createUser({
      email: safeEmail,
      passwordHash,
      nickname: "",
      role,
      provider: "local",
      isEmailVerified: false,
    });

    const code = generateOtp();
    await saveEmailVerification(safeEmail, code);
    await sendVerificationEmail(safeEmail, code);

    return res.status(201).json({
      ok: true,
      message: "Register success. Please verify your email.",
      user: {
        id: user.id,
        email: user.email,
        nickname: user.nickname || "",
        role: user.role,
        provider: user.provider,
        isEmailVerified: false,
      },
    });
  } catch (e) {
    return res.status(500).json({
      message: "Register failed",
      error: String(e.message || e),
    });
  }
});
app.post("/auth/send-email-verification", async (req, res) => {
  try {
    const email = requireStringField(res, req.body?.email, "email");
    if (!email) return;

    const safeEmail = toLowerTrimmed(email);
    const user = await getUserByEmail(safeEmail);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (user.provider === "google") {
      return res.status(400).json({ message: "Google account does not require email verification" });
    }

    if (user.isEmailVerified) {
      return res.json({ ok: true, message: "Email already verified" });
    }

    const code = generateOtp();
    await saveEmailVerification(safeEmail, code);
    await sendVerificationEmail(safeEmail, code);

    return res.json({ ok: true, message: "Verification email sent" });
  } catch (e) {
    return res.status(500).json({
      message: "Send email verification failed",
      error: String(e.message || e),
    });
  }
});
app.post("/auth/verify-email", async (req, res) => {
  try {
    const email = requireStringField(res, req.body?.email, "email");
    if (!email) return;
    const code = requireStringField(res, req.body?.code, "code");
    if (!code) return;

    const safeEmail = toLowerTrimmed(email);
    const user = await getUserByEmail(safeEmail);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const saved = await getEmailVerification(safeEmail);
    if (!saved) {
      return res.status(404).json({ message: "Verification code not found" });
    }

    if (Date.now() > Number(saved.expiresAt || 0)) {
      await deleteEmailVerification(safeEmail);
      return res.status(400).json({ message: "Verification code expired" });
    }

    if (String(saved.code) !== String(code)) {
      return res.status(400).json({ message: "Invalid verification code" });
    }

    await firestore.collection(COLLECTIONS.users).doc(user.id).set(
      {
        isEmailVerified: true,
        updatedAt: nowIso(),
      },
      { merge: true }
    );

    await markEmailVerificationVerified(safeEmail);
    await deleteEmailVerification(safeEmail);

    return res.json({
      ok: true,
      message: "Email verified successfully",
    });
  } catch (e) {
    return res.status(500).json({
      message: "Verify email failed",
      error: String(e.message || e),
    });
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

    if (user.provider !== "google" && !user.isEmailVerified) {
      return res.status(403).json({ message: "Please verify your email before login" });
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
        isEmailVerified: !!user.isEmailVerified,
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
    const role = toTrimmed(req.query.role || "employee") || "employee";

    const state = Buffer.from(
      JSON.stringify({ role })
    ).toString("base64");

    const url = googleOAuth2Client.generateAuthUrl({
      access_type: "offline",
      prompt: "consent",
      scope: ["openid", "email", "profile"],
      state,
    });

    return res.redirect(url);
  } catch (e) {
    return res.status(500).json({
      message: "Google auth start failed",
      error: String(e.message || e),
    });
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

      let role = "employee";
      if (req.query.state) {
        try {
          const parsed = JSON.parse(
            Buffer.from(String(req.query.state), "base64").toString()
          );
          role = toTrimmed(parsed?.role || "employee") || "employee";
        } catch {}
      }

      user = await createUser({
        email,
        passwordHash: "",
        nickname,
        role,
        provider: "google",
        isEmailVerified: true,
      });
    }

    const token = buildAuthToken(user);

    // เปลี่ยนจาก /dashboard เป็น /
    return res.redirect(`${FRONTEND_URL}/?token=${encodeURIComponent(token)}`);
  } catch (e) {
    return res.redirect(
      `${FRONTEND_URL}/?error=${encodeURIComponent(e?.message || "Google auth failed")}`
    );
  }
});

app.get("/auth/me", auth, async (req, res) => {
  try {
    const userId = String(req.user?.id || "");
    if (!userId) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const user = await getDocById(COLLECTIONS.users, userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    return res.json({ user: sanitizeUser(user) });
  } catch (e) {
    return res.status(500).json({
      message: "Get current user failed",
      error: String(e.message || e),
    });
  }
});
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

app.patch("/auth/update-profile", auth, async (req, res) => {
  try {
    const userId = String(req.user?.id || "");
    if (!userId) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const user = await getDocById(COLLECTIONS.users, userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const nextNickname = toTrimmed(
      req.body?.nickname ?? req.body?.displayName ?? req.body?.name
    );

    if (!nextNickname) {
      return res.json({
        ok: true,
        message: "No profile changes",
        token: buildAuthToken(user),
        user: sanitizeUser(user),
      });
    }

    const nicknameExists = await getUserByNickname(nextNickname);
    if (nicknameExists && String(nicknameExists.id) !== String(userId)) {
      return res.status(409).json({ message: "nickname already exists" });
    }

    const patch = {
      nickname: nextNickname,
      updatedAt: nowIso(),
    };

    await firestore.collection(COLLECTIONS.users).doc(userId).set(patch, { merge: true });

    const updatedUser = {
      ...user,
      ...patch,
    };

    const token = buildAuthToken(updatedUser);

    return res.json({
      ok: true,
      message: "Profile updated successfully",
      token,
      user: sanitizeUser(updatedUser),
    });
  } catch (e) {
    return res.status(500).json({
      message: "Update profile failed",
      error: String(e.message || e),
    });
  }
});

app.post("/auth/change-password", auth, async (req, res) => {
  try {
    const userId = String(req.user?.id || "");
    if (!userId) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const user = await getDocById(COLLECTIONS.users, userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (user.provider === "google") {
      return res.status(400).json({
        message: "Google account cannot change password with this method",
      });
    }

    if (!user.passwordHash) {
      return res.status(400).json({
        message: "Password is not available for this account",
      });
    }

    const currentPassword = toTrimmed(req.body?.currentPassword || req.body?.oldPassword);
    const newPassword = toTrimmed(req.body?.newPassword || req.body?.password);
    const confirmPassword = toTrimmed(req.body?.confirmPassword);

    if (!currentPassword) {
      return res.status(400).json({ message: "currentPassword is required" });
    }

    if (!newPassword) {
      return res.status(400).json({ message: "newPassword is required" });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({
        message: "newPassword must be at least 8 characters",
      });
    }

    if (confirmPassword && newPassword !== confirmPassword) {
      return res.status(400).json({ message: "confirmPassword does not match" });
    }

    const isCorrect = await bcrypt.compare(currentPassword, user.passwordHash);
    if (!isCorrect) {
      return res.status(400).json({ message: "Current password is incorrect" });
    }

    const isSamePassword = await bcrypt.compare(newPassword, user.passwordHash);
    if (isSamePassword) {
      return res.status(400).json({
        message: "New password must be different from current password",
      });
    }

    const passwordHash = await bcrypt.hash(newPassword, 10);

    await firestore.collection(COLLECTIONS.users).doc(userId).set(
      {
        passwordHash,
        updatedAt: nowIso(),
      },
      { merge: true }
    );

    return res.json({
      ok: true,
      message: "Password changed successfully",
    });
  } catch (e) {
    return res.status(500).json({
      message: "Change password failed",
      error: String(e.message || e),
    });
  }
});
app.post("/auth/link-owner", auth, async (req, res) => {
  try {
    const userId = String(req.user?.id || "");
    if (!userId) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const ownerUid = toTrimmed(req.body?.ownerUid);
    if (!ownerUid) {
      return res.status(400).json({ message: "ownerUid is required" });
    }

    const user = await getDocById(COLLECTIONS.users, userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (String(user.role || "").toLowerCase() !== "employee") {
      return res.status(400).json({ message: "Only employee can link owner UID" });
    }

    const owner = await getUserByOwnerUid(ownerUid);
    if (!owner) {
      return res.status(404).json({ message: "Owner UID not found" });
    }

    await firestore.collection(COLLECTIONS.users).doc(userId).set(
      {
        ownerUid: owner.ownerUid,
        ownerRef: owner.id,
        updatedAt: nowIso(),
      },
      { merge: true }
    );

    const updatedUser = {
      ...user,
      ownerUid: owner.ownerUid,
      ownerRef: owner.id,
      updatedAt: nowIso(),
    };

    const token = buildAuthToken(updatedUser);

    return res.json({
      ok: true,
      message: "Linked owner successfully",
      token,
      user: sanitizeUser(updatedUser),
    });
  } catch (e) {
    return res.status(500).json({
      message: "Link owner failed",
      error: String(e.message || e),
    });
  }
});

api.use(auth);
api.get("/nodes", async (req, res, next) => {
  try {
    const ownerRef = getOwnerScope(req.user);
    if (!ownerRef) {
      return res.json({ items: [] });
    }

    const snap = await firestore
      .collection(COLLECTIONS.nodes)
      .where("ownerRef", "==", ownerRef)
      .get();

    const items = snap.docs.map((doc) =>
      sanitizeNodeDoc(withId(doc.id, doc.data() || {}))
    );

    res.json({ items });
  } catch (e) {
    next(e);
  }
});
api.get("/nodes/by-uid/:uid", async (req, res, next) => {
  try {
    const ownerRef = getOwnerScope(req.user);
    const uid = toTrimmed(req.params.uid);

    if (!uid) {
      return res.status(400).json({ message: "uid is required" });
    }

    const node = await getNodeByUidForOwner(uid, ownerRef);
    if (!node) {
      return res.status(404).json({ message: "node uid not found" });
    }

    res.json({ item: sanitizeNodeDoc(node) });
  } catch (e) {
    next(e);
  }
});
api.get("/users", async (req, res, next) => {
  try {
    const scopeOwnerRef = getOwnerScope(req.user);
    if (!scopeOwnerRef) {
      return res.json({ items: [] });
    }

    const snap = await firestore.collection(COLLECTIONS.users).get();

    const items = snap.docs
      .map((doc) => withId(doc.id, doc.data() || {}))
      .filter((user) => {
        const role = String(user.role || "").toLowerCase();

        if (role === "owner") {
          return String(user.id) === String(scopeOwnerRef);
        }

        return String(user.ownerRef || "") === String(scopeOwnerRef);
      })
      .map((data) => ({
        id: data.id,
        email: data.email || "",
        nickname: data.nickname || "",
        role: data.role || "",
        ownerUid: data.ownerUid || "",
        ownerRef: data.ownerRef || "",
        provider: data.provider || "",
        createdAt: data.createdAt || "",
        updatedAt: data.updatedAt || "",
      }));

    res.json({ items });
  } catch (e) {
    next(e);
  }
});

api.get("/plots", async (req, res, next) => {
  try {
    const ownerRef = getOwnerScope(req.user);

    if (!ownerRef) {
      return res.json({ items: [] });
    }

    const snap = await firestore
      .collection(COLLECTIONS.plots)
      .where("ownerRef", "==", ownerRef)
      .get();

    const basePlots = snap.docs.map((doc) => withId(doc.id, doc.data() || {}));
    const items = await Promise.all(basePlots.map((plot) => attachNodesToPlot(plot)));

    res.json({ items });
  } catch (e) {
    next(e);
  }
});

api.post("/plots", async (req, res, next) => {
  try {
    const ownerRef = getOwnerScope(req.user);
    if (!ownerRef) {
      return res.status(400).json({ message: "No owner scope" });
    }

    const data = {
      ...normalizePlotCreate(req.body || {}),
      ownerRef,
    };
    if (!data.plotName) {
      return res.status(400).json({ message: "plotName is required" });
    }

    if (data.caretaker) {
      const caretaker = await getDocById(COLLECTIONS.users, data.caretaker);
      if (!caretaker) {
        return res.status(400).json({ message: "caretaker user not found" });
      }
    }

    const id = makeId("plot");
    await firestore.collection(COLLECTIONS.plots).doc(id).set(data);
    res.status(201).json({ item: withId(id, data) });
  } catch (e) {
    next(e);
  }
});

api.get("/plots/:plotId", async (req, res, next) => {
  try {
    const plot = await getDocById(COLLECTIONS.plots, req.params.plotId);
    if (!plot) return res.status(404).json({ message: "plot not found" });

    if (!canAccessOwnedDoc(req.user, plot.ownerRef)) {
      return res.status(403).json({ message: "Forbidden" });
    }

    const item = await attachNodesToPlot(plot);
    res.json({ item });
  } catch (e) {
    next(e);
  }
});

api.patch("/plots/:plotId", async (req, res, next) => {
  try {
    const plot = await getDocById(COLLECTIONS.plots, req.params.plotId);
    if (!plot) {
      return res.status(404).json({ message: "plot not found" });
    }

    if (!canAccessOwnedDoc(req.user, plot.ownerRef)) {
      return res.status(403).json({ message: "Forbidden" });
    }

    const nextData = normalizePlotPatch(plot, req.body || {});
    nextData.ownerRef = plot.ownerRef;

    if (!nextData.plotName) {
      return res.status(400).json({ message: "plotName is required" });
    }

    if (nextData.caretaker) {
      const caretaker = await getDocById(COLLECTIONS.users, nextData.caretaker);
      if (!caretaker) {
        return res.status(400).json({ message: "caretaker user not found" });
      }
    }

    await firestore
      .collection(COLLECTIONS.plots)
      .doc(req.params.plotId)
      .set(nextData, { merge: false });

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

    if (!canAccessOwnedDoc(req.user, plot.ownerRef)) {
      return res.status(403).json({ message: "Forbidden" });
    }

    // หา node ที่ผูกอยู่กับ plot นี้ก่อน
    const linkedNodesSnap = await firestore
      .collection(COLLECTIONS.nodes)
      .where("plotId", "==", plotId)
      .where("ownerRef", "==", String(plot.ownerRef || ""))
      .get();

    // หา managementPlants + sensorReadings ที่เกี่ยวข้อง
    const mgmtSnap = await firestore
      .collection(COLLECTIONS.managementPlants)
      .where("plot", "==", plotId)
      .get();

    const readingsSnap = await firestore
      .collection(COLLECTIONS.sensorReadings)
      .where("plotId", "==", plotId)
      .get();

    const batch = firestore.batch();

    // 1) ลบ plot
    batch.delete(firestore.collection(COLLECTIONS.plots).doc(plotId));

    // 2) unlink node ทั้งหมดที่อยู่ใน plot นี้
    linkedNodesSnap.docs.forEach((doc) => {
      batch.set(
        doc.ref,
        {
          plotId: null,
          lat: null,
          lng: null,
          updatedAt: nowIso(),
        },
        { merge: true }
      );
    });

    // 3) ลบ managementPlants ของ plot นี้
    mgmtSnap.docs.forEach((doc) => batch.delete(doc.ref));

    // 4) ลบ sensorReadings ของ plot นี้
    readingsSnap.docs.forEach((doc) => batch.delete(doc.ref));

    await batch.commit();

    res.json({
      ok: true,
      deletedId: plotId,
      unlinkedNodeCount: linkedNodesSnap.size,
    });
  } catch (e) {
    next(e);
  }
});

api.put("/plots/:plotId/polygon", async (req, res, next) => {
  try {
    const plot = await getDocById(COLLECTIONS.plots, req.params.plotId);
    if (!plot) return res.status(404).json({ message: "plot not found" });

    if (!canAccessOwnedDoc(req.user, plot.ownerRef)) {
      return res.status(403).json({ message: "Forbidden" });
    }

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

    if (!canAccessOwnedDoc(req.user, plot.ownerRef)) {
      return res.status(403).json({ message: "Forbidden" });
    }

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

    if (!canAccessOwnedDoc(req.user, plot.ownerRef)) {
      return res.status(403).json({ message: "Forbidden" });
    }

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
    const ownerRef = getOwnerScope(req.user);
    if (!ownerRef) {
      return res.status(400).json({ message: "No owner scope" });
    }

    const plot = await getDocById(COLLECTIONS.plots, req.params.plotId);
    if (!plot) return res.status(404).json({ message: "plot not found" });

    if (!canAccessOwnedDoc(req.user, plot.ownerRef)) {
      return res.status(403).json({ message: "Forbidden" });
    }

    const uid = requireStringField(res, req.body?.uid, "uid");
    if (!uid) return;

    const existingNode = await getNodeByUidForOwner(uid, ownerRef);
    if (!existingNode) {
      return res.status(404).json({ message: "node uid not found in nodes collection" });
    }

    const nextNode = sanitizeNodeDoc({
  ...existingNode,
  nodeName: req.body?.nodeName ?? existingNode.nodeName,
  status: req.body?.status ?? existingNode.status,
  lat: req.body?.lat ?? existingNode.lat,
  lng: req.body?.lng ?? existingNode.lng,
  sensors: req.body?.sensors ?? existingNode.sensors,
  plotId: String(req.params.plotId),
  ownerRef,
  updatedAt: nowIso(),
});

    if (nextNode.lat === null || nextNode.lng === null) {
      return res.status(400).json({ message: "lat and lng are required" });
    }

    // กัน node ซ้ำใน plot เดียวกันด้วย uid
    const dupSnap = await firestore
      .collection(COLLECTIONS.nodes)
      .where("plotId", "==", String(req.params.plotId))
      .where("ownerRef", "==", ownerRef)
      .where("uid", "==", uid)
      .limit(1)
      .get();

    if (!dupSnap.empty && dupSnap.docs[0].id !== existingNode.id) {
      return res.status(409).json({ message: "node uid already exists in this plot" });
    }

    await firestore
      .collection(COLLECTIONS.nodes)
      .doc(existingNode.id)
      .set(nextNode, { merge: true });

    res.status(201).json({ item: withId(existingNode.id, nextNode) });
  } catch (e) {
    next(e);
  }
});
api.patch("/nodes/link-by-uid", async (req, res, next) => {
  try {
    const ownerRef = getOwnerScope(req.user);
    if (!ownerRef) {
      return res.status(400).json({ message: "No owner scope" });
    }

    const uid = requireStringField(res, req.body?.uid, "uid");
    if (!uid) return;

    const plotId = requireStringField(res, req.body?.plotId, "plotId");
    if (!plotId) return;

    const plot = await getDocById(COLLECTIONS.plots, plotId);
    if (!plot) {
      return res.status(404).json({ message: "plot not found" });
    }

    if (!canAccessOwnedDoc(req.user, plot.ownerRef)) {
      return res.status(403).json({ message: "Forbidden" });
    }

    const node = await getNodeByUidForOwner(uid, ownerRef);
    if (!node) {
      return res.status(404).json({ message: "node uid not found" });
    }

    if (node.plotId && String(node.plotId) !== String(plotId)) {
      return res.status(409).json({
        message: "node is already linked to another plot",
      });
    }

    const nextNode = sanitizeNodeDoc({
  ...node,
  nodeName: req.body?.nodeName ?? node.nodeName,
  status: req.body?.status ?? node.status,
  lat: req.body?.lat,
  lng: req.body?.lng,
  plotId,
  ownerRef,
  sensors: req.body?.sensors ?? node.sensors,
  createdAt: node.createdAt || nowIso(),
  updatedAt: nowIso(),
});

    if (nextNode.lat === null || nextNode.lng === null) {
      return res.status(400).json({ message: "lat and lng are required" });
    }

    await firestore
      .collection(COLLECTIONS.nodes)
      .doc(node.id)
      .set(nextNode, { merge: false });

    res.json({ item: withId(node.id, nextNode) });
  } catch (e) {
    next(e);
  }
});
api.patch("/nodes/:nodeId", async (req, res, next) => {
  try {
    const ownerRef = getOwnerScope(req.user);
    if (!ownerRef) {
      return res.status(400).json({ message: "No owner scope" });
    }

    const node = await getNodeByIdForOwner(req.params.nodeId, ownerRef);
    if (!node) {
      return res.status(404).json({ message: "node not found" });
    }

    const nextPlotId =
      req.body?.plotId !== undefined
        ? toTrimmed(req.body.plotId) || null
        : node.plotId || null;

    if (nextPlotId) {
      const plot = await getDocById(COLLECTIONS.plots, nextPlotId);
      if (!plot) {
        return res.status(404).json({ message: "plot not found" });
      }
      if (!canAccessOwnedDoc(req.user, plot.ownerRef)) {
        return res.status(403).json({ message: "Forbidden" });
      }
    }

    const nextNode = sanitizeNodeDoc({
      ...node,
      ...req.body,
      plotId: nextPlotId,
      ownerRef,
      createdAt: node.createdAt || nowIso(),
      updatedAt: nowIso(),
    });

    if (!nextNode.uid) {
      return res.status(400).json({ message: "uid is required" });
    }
    if (!nextNode.nodeName) {
      return res.status(400).json({ message: "nodeName is required" });
    }
    if (nextNode.lat === null || nextNode.lng === null) {
      return res.status(400).json({ message: "lat and lng are required" });
    }

    await firestore
      .collection(COLLECTIONS.nodes)
      .doc(node.id)
      .set(nextNode, { merge: false });

    res.json({ item: withId(node.id, nextNode) });
  } catch (e) {
    next(e);
  }
});
api.patch("/nodes/:nodeId/unlink", async (req, res, next) => {
  try {
    const ownerRef = getOwnerScope(req.user);
    if (!ownerRef) {
      return res.status(400).json({ message: "No owner scope" });
    }

    const node = await getNodeByIdForOwner(req.params.nodeId, ownerRef);
    if (!node) {
      return res.status(404).json({ message: "node not found" });
    }

    await firestore.collection(COLLECTIONS.nodes).doc(node.id).set(
      {
        plotId: null,
        lat: null,
        lng: null,
        updatedAt: nowIso(),
      },
      { merge: true }
    );

    res.json({ ok: true, item: { ...node, plotId: null, lat: null, lng: null } });
  } catch (e) {
    next(e);
  }
});

api.patch("/plots/:plotId/nodes/:nodeId", async (req, res, next) => {
  try {
    const ownerRef = getOwnerScope(req.user);
    if (!ownerRef) {
      return res.status(400).json({ message: "No owner scope" });
    }

    const plot = await getDocById(COLLECTIONS.plots, req.params.plotId);
    if (!plot) return res.status(404).json({ message: "plot not found" });

    if (!canAccessOwnedDoc(req.user, plot.ownerRef)) {
      return res.status(403).json({ message: "Forbidden" });
    }

    const existingNode = await getDocById(COLLECTIONS.nodes, req.params.nodeId);
    if (!existingNode) {
      return res.status(404).json({ message: "node not found" });
    }

    if (String(existingNode.ownerRef || "") !== String(ownerRef)) {
      return res.status(403).json({ message: "Forbidden" });
    }

    const nextNode = sanitizeNodeDoc({
      ...existingNode,
      ...req.body,
      plotId: String(req.params.plotId),
      ownerRef,
      updatedAt: nowIso(),
    });

    if (!nextNode.nodeName) return res.status(400).json({ message: "nodeName is required" });
    if (!nextNode.uid) return res.status(400).json({ message: "uid is required" });
    if (nextNode.lat === null || nextNode.lng === null) {
      return res.status(400).json({ message: "lat and lng are required" });
    }

    await firestore
      .collection(COLLECTIONS.nodes)
      .doc(req.params.nodeId)
      .set(nextNode, { merge: true });

    res.json({ item: withId(req.params.nodeId, nextNode) });
  } catch (e) {
    next(e);
  }
});

api.delete("/plots/:plotId/nodes/:nodeId", async (req, res, next) => {
  try {
    const ownerRef = getOwnerScope(req.user);
    if (!ownerRef) {
      return res.status(400).json({ message: "No owner scope" });
    }

    const plot = await getDocById(COLLECTIONS.plots, req.params.plotId);
    if (!plot) return res.status(404).json({ message: "plot not found" });

    if (!canAccessOwnedDoc(req.user, plot.ownerRef)) {
      return res.status(403).json({ message: "Forbidden" });
    }

    const node = await getDocById(COLLECTIONS.nodes, req.params.nodeId);
    if (!node) return res.status(404).json({ message: "node not found" });

    if (String(node.ownerRef || "") !== String(ownerRef)) {
      return res.status(403).json({ message: "Forbidden" });
    }

    // unlink จาก plot โดยไม่ลบ node ทิ้ง
    await firestore.collection(COLLECTIONS.nodes).doc(req.params.nodeId).set(
      {
        plotId: null,
        updatedAt: nowIso(),
      },
      { merge: true }
    );

    res.json({ ok: true, deletedId: req.params.nodeId });
  } catch (e) {
    next(e);
  }
});

api.post("/plots/:plotId/nodes/:nodeId/sensors", async (req, res, next) => {
  try {
    const plot = await getDocById(COLLECTIONS.plots, req.params.plotId);
    if (!plot) return res.status(404).json({ message: "plot not found" });

    if (!canAccessOwnedDoc(req.user, plot.ownerRef)) {
      return res.status(403).json({ message: "Forbidden" });
    }

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

    if (!canAccessOwnedDoc(req.user, plot.ownerRef)) {
      return res.status(403).json({ message: "Forbidden" });
    }

    const nodes = Array.isArray(plot.nodes) ? [...plot.nodes] : [];
    const nodeIndex = nodes.findIndex((n) => String(n?._id) === String(req.params.nodeId));
    if (nodeIndex < 0) return res.status(404).json({ message: "node not found" });

    const node = { ...(nodes[nodeIndex] || {}) };
    const sensors = Array.isArray(node.sensors) ? [...node.sensors] : [];
    const sensorIndex = sensors.findIndex((s) => String(s?._id) === String(req.params.sensorId));
    if (sensorIndex < 0) return res.status(404).json({ message: "sensor not found" });

    const existing = sensors[sensorIndex];
    const nextSensor = normalizeSensor({ ...existing, ...req.body }, existing);

    if (!nextSensor.name) return res.status(400).json({ message: "sensor name is required" });
    if (!nextSensor.uid) return res.status(400).json({ message: "sensor uid is required" });

    const dupUid = sensors.find((s, i) => i !== sensorIndex && String(s?.uid) === String(nextSensor.uid));
    if (dupUid) {
      return res.status(409).json({ message: "sensor uid already exists in this node" });
    }

    const hasIncomingLatestValue = req.body?.latestValue !== undefined;
    const incomingLatestValue = hasIncomingLatestValue
      ? toNumberOrNull(req.body.latestValue)
      : undefined;

    if (hasIncomingLatestValue && incomingLatestValue === null) {
      return res.status(400).json({ message: "latestValue must be a number" });
    }

    const incomingLatestTimestamp =
      req.body?.latestTimestamp !== undefined
        ? (req.body.latestTimestamp && isIsoDateLike(req.body.latestTimestamp)
          ? req.body.latestTimestamp
          : nowIso())
        : undefined;

    const oldValue = toNumberOrNull(existing?.latestValue);
    const oldTimestamp =
      existing?.latestTimestamp && isIsoDateLike(existing.latestTimestamp)
        ? existing.latestTimestamp
        : null;

    if (hasIncomingLatestValue && oldValue !== null) {
      const historyReading = cleanUndefined({
        plotId: String(req.params.plotId),
        nodeId: String(req.params.nodeId),
        sensorId: String(req.params.sensorId),
        sensorName: existing?.name || nextSensor?.name || "",
        value: oldValue,
        timestamp: oldTimestamp || nowIso(),
        status: toTrimmed(existing?.status || "OK") || "OK",
        createdAt: nowIso(),
      });

      const readingId = makeId("reading");
      await firestore.collection(COLLECTIONS.sensorReadings).doc(readingId).set(historyReading);
    }

    if (hasIncomingLatestValue && req.body?.latestTimestamp === undefined) {
      nextSensor.latestTimestamp = nowIso();
    }

    if (incomingLatestTimestamp !== undefined) {
      nextSensor.latestTimestamp = incomingLatestTimestamp;
    }

    sensors[sensorIndex] = nextSensor;
    node.sensors = sensors;
    nodes[nodeIndex] = node;

    await firestore.collection(COLLECTIONS.plots).doc(req.params.plotId).set(
      {
        nodes,
        updatedAt: nowIso(),
      },
      { merge: true }
    );

    res.json({ item: nextSensor });
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

    if (!canAccessOwnedDoc(req.user, plot.ownerRef)) {
      return res.status(403).json({ message: "Forbidden" });
    }

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

api.patch("/plots/:plotId", async (req, res, next) => {
  try {
    const plot = await getDocById(COLLECTIONS.plots, req.params.plotId);
    if (!plot) {
      return res.status(404).json({ message: "plot not found" });
    }

    if (!canAccessOwnedDoc(req.user, plot.ownerRef)) {
      return res.status(403).json({ message: "Forbidden" });
    }

    const nextData = normalizePlotPatch(plot, req.body || {});
    nextData.ownerRef = plot.ownerRef;

    if (!nextData.plotName) {
      return res.status(400).json({ message: "plotName is required" });
    }

    if (nextData.caretaker) {
      const caretaker = await getDocById(COLLECTIONS.users, nextData.caretaker);
      if (!caretaker) {
        return res.status(400).json({ message: "caretaker user not found" });
      }
    }

    await firestore
      .collection(COLLECTIONS.plots)
      .doc(req.params.plotId)
      .set(nextData, { merge: false });

    res.json({ item: withId(req.params.plotId, nextData) });
  } catch (e) {
    next(e);
  }
});


api.put("/plots/:plotId/polygon", async (req, res, next) => {
  try {
    const plot = await getDocById(COLLECTIONS.plots, req.params.plotId);
    if (!plot) return res.status(404).json({ message: "plot not found" });

    if (!canAccessOwnedDoc(req.user, plot.ownerRef)) {
      return res.status(403).json({ message: "Forbidden" });
    }

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

    if (!canAccessOwnedDoc(req.user, plot.ownerRef)) {
      return res.status(403).json({ message: "Forbidden" });
    }

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

    if (!canAccessOwnedDoc(req.user, plot.ownerRef)) {
      return res.status(403).json({ message: "Forbidden" });
    }

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

    if (!canAccessOwnedDoc(req.user, plot.ownerRef)) {
      return res.status(403).json({ message: "Forbidden" });
    }

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

    if (!canAccessOwnedDoc(req.user, plot.ownerRef)) {
      return res.status(403).json({ message: "Forbidden" });
    }

    const nodes = Array.isArray(plot.nodes) ? [...plot.nodes] : [];
    const index = nodes.findIndex((n) => String(n?._id) === String(req.params.nodeId));
    if (index < 0) return res.status(404).json({ message: "node not found" });

    const existing = nodes[index];
    const next = normalizeNode(
      { ...existing, ...req.body, sensors: req.body?.sensors ?? existing.sensors },
      existing
    );

    if (!next.nodeName) return res.status(400).json({ message: "nodeName is required" });
    if (!next.uid) return res.status(400).json({ message: "uid is required" });
    if (next.lat === null || next.lng === null) {
      return res.status(400).json({ message: "lat and lng are required" });
    }

    const dupUid = nodes.find((n, i) => i !== index && String(n?.uid) === String(next.uid));
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

    if (!canAccessOwnedDoc(req.user, plot.ownerRef)) {
      return res.status(403).json({ message: "Forbidden" });
    }

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

    if (!canAccessOwnedDoc(req.user, plot.ownerRef)) {
      return res.status(403).json({ message: "Forbidden" });
    }

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

    if (!canAccessOwnedDoc(req.user, plot.ownerRef)) {
      return res.status(403).json({ message: "Forbidden" });
    }

    const nodes = Array.isArray(plot.nodes) ? [...plot.nodes] : [];
    const nodeIndex = nodes.findIndex((n) => String(n?._id) === String(req.params.nodeId));
    if (nodeIndex < 0) return res.status(404).json({ message: "node not found" });

    const node = { ...(nodes[nodeIndex] || {}) };
    const sensors = Array.isArray(node.sensors) ? [...node.sensors] : [];
    const sensorIndex = sensors.findIndex((s) => String(s?._id) === String(req.params.sensorId));
    if (sensorIndex < 0) return res.status(404).json({ message: "sensor not found" });

    const existing = sensors[sensorIndex];
    const nextSensor = normalizeSensor({ ...existing, ...req.body }, existing);

    if (!nextSensor.name) return res.status(400).json({ message: "sensor name is required" });
    if (!nextSensor.uid) return res.status(400).json({ message: "sensor uid is required" });

    const dupUid = sensors.find((s, i) => i !== sensorIndex && String(s?.uid) === String(nextSensor.uid));
    if (dupUid) {
      return res.status(409).json({ message: "sensor uid already exists in this node" });
    }

    const hasIncomingLatestValue = req.body?.latestValue !== undefined;
    const incomingLatestValue = hasIncomingLatestValue
      ? toNumberOrNull(req.body.latestValue)
      : undefined;

    if (hasIncomingLatestValue && incomingLatestValue === null) {
      return res.status(400).json({ message: "latestValue must be a number" });
    }

    const incomingLatestTimestamp =
      req.body?.latestTimestamp !== undefined
        ? (req.body.latestTimestamp && isIsoDateLike(req.body.latestTimestamp)
          ? req.body.latestTimestamp
          : nowIso())
        : undefined;

    const oldValue = toNumberOrNull(existing?.latestValue);
    const oldTimestamp =
      existing?.latestTimestamp && isIsoDateLike(existing.latestTimestamp)
        ? existing.latestTimestamp
        : null;

    if (hasIncomingLatestValue && oldValue !== null) {
      const historyReading = cleanUndefined({
        plotId: String(req.params.plotId),
        nodeId: String(req.params.nodeId),
        sensorId: String(req.params.sensorId),
        sensorName: existing?.name || nextSensor?.name || "",
        value: oldValue,
        timestamp: oldTimestamp || nowIso(),
        status: toTrimmed(existing?.status || "OK") || "OK",
        createdAt: nowIso(),
      });

      const readingId = makeId("reading");
      await firestore.collection(COLLECTIONS.sensorReadings).doc(readingId).set(historyReading);
    }

    if (hasIncomingLatestValue && req.body?.latestTimestamp === undefined) {
      nextSensor.latestTimestamp = nowIso();
    }

    if (incomingLatestTimestamp !== undefined) {
      nextSensor.latestTimestamp = incomingLatestTimestamp;
    }

    sensors[sensorIndex] = nextSensor;
    node.sensors = sensors;
    nodes[nodeIndex] = node;

    await firestore.collection(COLLECTIONS.plots).doc(req.params.plotId).set(
      {
        nodes,
        updatedAt: nowIso(),
      },
      { merge: true }
    );

    res.json({ item: nextSensor });
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

    if (!canAccessOwnedDoc(req.user, plot.ownerRef)) {
      return res.status(403).json({ message: "Forbidden" });
    }

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

api.patch("/plots/:plotId", async (req, res, next) => {
  try {
    const plot = await getDocById(COLLECTIONS.plots, req.params.plotId);
    if (!plot) {
      return res.status(404).json({ message: "plot not found" });
    }

    const nextData = normalizePlotPatch(plot, req.body || {});
    if (!nextData.plotName) {
      return res.status(400).json({ message: "plotName is required" });
    }

    if (nextData.caretaker) {
      const caretaker = await getDocById(COLLECTIONS.users, nextData.caretaker);
      if (!caretaker) {
        return res.status(400).json({ message: "caretaker user not found" });
      }
    }

    await firestore
      .collection(COLLECTIONS.plots)
      .doc(req.params.plotId)
      .set(nextData, { merge: false });

    res.json({ item: withId(req.params.plotId, nextData) });
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
    const nextSensor = normalizeSensor({ ...existing, ...req.body }, existing);

    if (!nextSensor.name) return res.status(400).json({ message: "sensor name is required" });
    if (!nextSensor.uid) return res.status(400).json({ message: "sensor uid is required" });

    const dupUid = sensors.find(
      (s, i) => i !== sensorIndex && String(s?.uid) === String(nextSensor.uid)
    );
    if (dupUid) {
      return res.status(409).json({ message: "sensor uid already exists in this node" });
    }

    const hasIncomingLatestValue = req.body?.latestValue !== undefined;
    const incomingLatestValue = hasIncomingLatestValue
      ? toNumberOrNull(req.body.latestValue)
      : undefined;

    if (hasIncomingLatestValue && incomingLatestValue === null) {
      return res.status(400).json({ message: "latestValue must be a number" });
    }

    const incomingLatestTimestamp =
      req.body?.latestTimestamp !== undefined
        ? (req.body.latestTimestamp && isIsoDateLike(req.body.latestTimestamp)
          ? req.body.latestTimestamp
          : nowIso())
        : undefined;

    const oldValue = toNumberOrNull(existing?.latestValue);
    const oldTimestamp =
      existing?.latestTimestamp && isIsoDateLike(existing.latestTimestamp)
        ? existing.latestTimestamp
        : null;

    if (hasIncomingLatestValue && oldValue !== null) {
      const historyReading = cleanUndefined({
        plotId: String(req.params.plotId),
        nodeId: String(req.params.nodeId),
        sensorId: String(req.params.sensorId),
        sensorName: existing?.name || nextSensor?.name || "",
        value: oldValue,
        timestamp: oldTimestamp || nowIso(),
        status: toTrimmed(existing?.status || "OK") || "OK",
        createdAt: nowIso(),
      });

      const readingId = makeId("reading");
      await firestore
        .collection(COLLECTIONS.sensorReadings)
        .doc(readingId)
        .set(historyReading);
    }

    if (hasIncomingLatestValue && req.body?.latestTimestamp === undefined) {
      nextSensor.latestTimestamp = nowIso();
    }

    if (incomingLatestTimestamp !== undefined) {
      nextSensor.latestTimestamp = incomingLatestTimestamp;
    }

    sensors[sensorIndex] = nextSensor;
    node.sensors = sensors;
    nodes[nodeIndex] = node;

    await firestore.collection(COLLECTIONS.plots).doc(req.params.plotId).set(
      {
        nodes,
        updatedAt: nowIso(),
      },
      { merge: true }
    );

    res.json({ item: nextSensor });
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
    const scopeOwnerRef = getOwnerScope(req.user);
    if (!scopeOwnerRef) {
      return res.json({ items: [] });
    }

    let ref = firestore.collection(COLLECTIONS.managementPlants);
    const plotId = toTrimmed(req.query.plot);
    if (plotId) ref = ref.where("plot", "==", plotId);

    const snap = await ref.orderBy("createdAt", "desc").get();

    const items = [];
    for (const doc of snap.docs) {
      const item = withId(doc.id, doc.data() || {});
      const plot = await getDocById(COLLECTIONS.plots, item.plot);
      if (plot && canAccessOwnedDoc(req.user, plot.ownerRef)) {
        items.push(item);
      }
    }

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

    if (!canAccessOwnedDoc(req.user, plot.ownerRef)) {
      return res.status(403).json({ message: "Forbidden" });
    }

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

    const currentPlot = await getDocById(COLLECTIONS.plots, existing.plot);
    if (!currentPlot || !canAccessOwnedDoc(req.user, currentPlot.ownerRef)) {
      return res.status(403).json({ message: "Forbidden" });
    }

    const nextData = normalizeManagementPlantPatch(existing, req.body || {});
    if (!nextData.plot) return res.status(400).json({ message: "plot is required" });
    if (!nextData.species) return res.status(400).json({ message: "species is required" });

    const plot = await getDocById(COLLECTIONS.plots, nextData.plot);
    if (!plot) return res.status(400).json({ message: "plot not found" });

    if (!canAccessOwnedDoc(req.user, plot.ownerRef)) {
      return res.status(403).json({ message: "Forbidden" });
    }

    await firestore
      .collection(COLLECTIONS.managementPlants)
      .doc(req.params.managementId)
      .set(nextData, { merge: false });

    res.json({ item: withId(req.params.managementId, nextData) });
  } catch (e) {
    next(e);
  }
});

api.delete("/management-plants/:managementId", async (req, res, next) => {
  try {
    const existing = await getDocById(COLLECTIONS.managementPlants, req.params.managementId);
    if (!existing) return res.status(404).json({ message: "management plant not found" });

    const plot = await getDocById(COLLECTIONS.plots, existing.plot);
    if (!plot || !canAccessOwnedDoc(req.user, plot.ownerRef)) {
      return res.status(403).json({ message: "Forbidden" });
    }

    await firestore.collection(COLLECTIONS.managementPlants).doc(req.params.managementId).delete();
    res.json({ ok: true, deletedId: req.params.managementId });
  } catch (e) {
    next(e);
  }
});

api.get("/management-plants", async (req, res, next) => {
  try {
    const scopeOwnerRef = getOwnerScope(req.user);
    if (!scopeOwnerRef) {
      return res.json({ items: [] });
    }

    let ref = firestore.collection(COLLECTIONS.managementPlants);
    const plotId = toTrimmed(req.query.plot);
    if (plotId) ref = ref.where("plot", "==", plotId);

    const snap = await ref.orderBy("createdAt", "desc").get();

    const items = [];
    for (const doc of snap.docs) {
      const item = withId(doc.id, doc.data() || {});
      const plot = await getDocById(COLLECTIONS.plots, item.plot);
      if (plot && canAccessOwnedDoc(req.user, plot.ownerRef)) {
        items.push(item);
      }
    }

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

    if (!canAccessOwnedDoc(req.user, plot.ownerRef)) {
      return res.status(403).json({ message: "Forbidden" });
    }

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

    const currentPlot = await getDocById(COLLECTIONS.plots, existing.plot);
    if (!currentPlot || !canAccessOwnedDoc(req.user, currentPlot.ownerRef)) {
      return res.status(403).json({ message: "Forbidden" });
    }

    const nextData = normalizeManagementPlantPatch(existing, req.body || {});
    if (!nextData.plot) return res.status(400).json({ message: "plot is required" });
    if (!nextData.species) return res.status(400).json({ message: "species is required" });

    const plot = await getDocById(COLLECTIONS.plots, nextData.plot);
    if (!plot) return res.status(400).json({ message: "plot not found" });

    if (!canAccessOwnedDoc(req.user, plot.ownerRef)) {
      return res.status(403).json({ message: "Forbidden" });
    }

    await firestore
      .collection(COLLECTIONS.managementPlants)
      .doc(req.params.managementId)
      .set(nextData, { merge: false });

    res.json({ item: withId(req.params.managementId, nextData) });
  } catch (e) {
    next(e);
  }
});

api.delete("/management-plants/:managementId", async (req, res, next) => {
  try {
    const existing = await getDocById(COLLECTIONS.managementPlants, req.params.managementId);
    if (!existing) return res.status(404).json({ message: "management plant not found" });

    const plot = await getDocById(COLLECTIONS.plots, existing.plot);
    if (!plot || !canAccessOwnedDoc(req.user, plot.ownerRef)) {
      return res.status(403).json({ message: "Forbidden" });
    }

    await firestore.collection(COLLECTIONS.managementPlants).doc(req.params.managementId).delete();
    res.json({ ok: true, deletedId: req.params.managementId });
  } catch (e) {
    next(e);
  }
});
function readingTimestampMs(item) {
  const raw = item?.timestamp || item?.ts || item?.time || item?.createdAt || item?.updatedAt;
  const ms = new Date(raw).getTime();
  return Number.isFinite(ms) ? ms : 0;
}

function filterReadingItems(items, { sensorId = "", plotId = "", nodeId = "" } = {}) {
  return (Array.isArray(items) ? items : []).filter((item) => {
    if (sensorId && String(item?.sensorId || "").trim() !== String(sensorId).trim()) return false;
    if (plotId && String(item?.plotId || "").trim() !== String(plotId).trim()) return false;
    if (nodeId && String(item?.nodeId || "").trim() !== String(nodeId).trim()) return false;
    return true;
  });
}

async function fetchSensorReadingsNoIndexFallback({ sensorId = "", plotId = "", nodeId = "", limit = 2000 } = {}) {
  const hardLimit = Math.max(1, Math.min(Number(limit) || 2000, 5000));
  const collectionRef = firestore.collection(COLLECTIONS.sensorReadings);

  const queryPlan = sensorId
    ? collectionRef.where("sensorId", "==", sensorId)
    : nodeId
      ? collectionRef.where("nodeId", "==", nodeId)
      : plotId
        ? collectionRef.where("plotId", "==", plotId)
        : collectionRef;

  const snap = await queryPlan.limit(Math.max(hardLimit * 5, 500)).get();
  const rawItems = snap.docs.map((doc) => withId(doc.id, doc.data() || {}));

  return filterReadingItems(rawItems, { sensorId, plotId, nodeId })
    .sort((a, b) => readingTimestampMs(b) - readingTimestampMs(a))
    .slice(0, hardLimit);
}

api.get("/sensor-readings", async (req, res, next) => {
  try {
    const sensorId = toTrimmed(req.query.sensorId);
    const plotId = toTrimmed(req.query.plotId);
    const nodeId = toTrimmed(req.query.nodeId);
    const limit = Math.max(1, Math.min(Number(req.query.limit || 2000), 5000));

    if (plotId) {
      const plot = await getDocById(COLLECTIONS.plots, plotId);
      if (!plot || !canAccessOwnedDoc(req.user, plot.ownerRef)) {
        return res.json({ items: [] });
      }
    }

    const rawItems = await fetchSensorReadingsNoIndexFallback({
      sensorId,
      plotId,
      nodeId,
      limit,
    });

    const items = [];
    for (const item of rawItems) {
      if (!item?.plotId) continue;
      const plot = await getDocById(COLLECTIONS.plots, item.plotId);
      if (plot && canAccessOwnedDoc(req.user, plot.ownerRef)) {
        items.push(item);
      }
    }

    res.json({ items });
  } catch (e) {
    next(e);
  }
});

function readingTimestampMs(item) {
  const raw = item?.timestamp || item?.ts || item?.time || item?.createdAt || item?.updatedAt;
  const ms = new Date(raw).getTime();
  return Number.isFinite(ms) ? ms : 0;
}

function filterReadingItems(items, { sensorId = "", plotId = "", nodeId = "" } = {}) {
  return (Array.isArray(items) ? items : []).filter((item) => {
    if (sensorId && String(item?.sensorId || "").trim() !== String(sensorId).trim()) return false;
    if (plotId && String(item?.plotId || "").trim() !== String(plotId).trim()) return false;
    if (nodeId && String(item?.nodeId || "").trim() !== String(nodeId).trim()) return false;
    return true;
  });
}

async function fetchSensorReadingsNoIndexFallback({ sensorId = "", plotId = "", nodeId = "", limit = 2000 } = {}) {
  const hardLimit = Math.max(1, Math.min(Number(limit) || 2000, 5000));
  const collectionRef = firestore.collection(COLLECTIONS.sensorReadings);

  const queryPlan = sensorId
    ? collectionRef.where("sensorId", "==", sensorId)
    : nodeId
      ? collectionRef.where("nodeId", "==", nodeId)
      : plotId
        ? collectionRef.where("plotId", "==", plotId)
        : collectionRef;

  const snap = await queryPlan.limit(Math.max(hardLimit * 5, 500)).get();
  const rawItems = snap.docs.map((doc) => withId(doc.id, doc.data() || {}));

  return filterReadingItems(rawItems, { sensorId, plotId, nodeId })
    .sort((a, b) => readingTimestampMs(b) - readingTimestampMs(a))
    .slice(0, hardLimit);
}

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

    const found = await findPlotContainingSensor(plotId, nodeId, sensorId);
    if (!found) {
      return res.status(400).json({ message: "sensor not found in plot/node" });
    }

    if (!canAccessOwnedDoc(req.user, found.plot.ownerRef)) {
      return res.status(403).json({ message: "Forbidden" });
    }

    const timestamp =
      req.body?.timestamp && isIsoDateLike(req.body.timestamp)
        ? req.body.timestamp
        : nowIso();

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

    const rawItems = await fetchSensorReadingsNoIndexFallback({ sensorId, limit: 20 });

    const items = [];
    for (const item of rawItems) {
      if (!item?.plotId) continue;
      const plot = await getDocById(COLLECTIONS.plots, item.plotId);
      if (plot && canAccessOwnedDoc(req.user, plot.ownerRef)) {
        items.push(item);
      }
    }

    if (!items.length) {
      return res.status(404).json({ message: "No readings found" });
    }

    res.json({ item: items[0] });
  } catch (e) {
    next(e);
  }
});
function parseDmyDateTimeString(raw) {
  const text = String(raw || "").trim();
  const match = text.match(
    /^(\d{1,2})\/(\d{1,2})\/(\d{4})(?:[ ,T]+(\d{1,2}):(\d{2})(?::(\d{2}))?)?$/
  );
  if (!match) return null;

  const [, dd, mm, yyyy, hh = "0", mi = "0", ss = "0"] = match;
  const d = new Date(
    Number(yyyy),
    Number(mm) - 1,
    Number(dd),
    Number(hh),
    Number(mi),
    Number(ss)
  );

  return Number.isNaN(d.getTime()) ? null : d;
}

function parseFlexibleDate(raw) {
  if (!raw) return null;
  if (raw instanceof Date) return Number.isNaN(raw.getTime()) ? null : raw;

  if (typeof raw === "object") {
    const sec = Number(raw?.seconds ?? raw?._seconds);
    const nano = Number(raw?.nanoseconds ?? raw?._nanoseconds ?? 0);
    if (Number.isFinite(sec)) {
      const d = new Date(sec * 1000 + nano / 1e6);
      return Number.isNaN(d.getTime()) ? null : d;
    }
    if (typeof raw?.toDate === "function") {
      const d = raw.toDate();
      return Number.isNaN(d?.getTime?.()) ? null : d;
    }
  }

  const dmy = parseDmyDateTimeString(raw);
  if (dmy) return dmy;

  const d = new Date(raw);
  return Number.isNaN(d.getTime()) ? null : d;
}

function historyTimestampOf(item) {
  return (
    item?.server_timestamp ||
    item?.serverTimestamp ||
    item?.history_timestamp ||
    item?.historyTimestamp ||
    item?.timestamp ||
    item?.createdAt ||
    null
  );
}

api.get("/history", auth, async (req, res) => {
  try {
    const ownerRef = getOwnerScope(req.user);

    const uid = String(req.query.uid || req.query.nodeUid || "").trim();
    const nodeId = String(req.query.nodeId || "").trim();
    const plotId = String(req.query.plotId || "").trim();
    const startDate = String(req.query.startDate || "").trim();
    const endDate = String(req.query.endDate || "").trim();
    const limit = Math.min(Number(req.query.limit) || 5000, 20000);

    let items = [];

    const snap = await firestore.collection(COLLECTIONS.history).limit(limit).get();
    items = snap.docs.map((doc) => withId(doc.id, doc.data() || {}));

    if (uid) {
      items = items.filter((item) => String(item.uid || item.nodeUid || "").trim() === uid);
    }

    if (nodeId) {
      items = items.filter((item) => String(item.nodeId || "").trim() === nodeId);
    }

    if (plotId) {
      items = items.filter((item) => String(item.plotId || "").trim() === plotId);
    }

    // owner scope ผ่าน node collection
    if (ownerRef) {
      const nodeSnap = await firestore
        .collection(COLLECTIONS.nodes)
        .where("ownerRef", "==", String(ownerRef))
        .get();

      const allowedNodeUids = new Set();
      const allowedNodeIds = new Set();
      const allowedPlotIds = new Set();

      nodeSnap.docs.forEach((doc) => {
        const data = doc.data() || {};
        allowedNodeIds.add(String(doc.id));
        if (data.uid) allowedNodeUids.add(String(data.uid));
        if (data.plotId) allowedPlotIds.add(String(data.plotId));
      });

      items = items.filter((item) => {
        const itemUid = String(item.uid || item.nodeUid || "").trim();
        const itemNodeId = String(item.nodeId || "").trim();
        const itemPlotId = String(item.plotId || "").trim();

        return (
          (itemUid && allowedNodeUids.has(itemUid)) ||
          (itemNodeId && allowedNodeIds.has(itemNodeId)) ||
          (itemPlotId && allowedPlotIds.has(itemPlotId))
        );
      });
    }

    const startMs = startDate
      ? new Date(`${startDate}T00:00:00`).getTime()
      : null;
    const endMs = endDate
      ? new Date(`${endDate}T23:59:59`).getTime()
      : null;

    items = items.filter((item) => {
      const d = parseFlexibleDate(historyTimestampOf(item));
      const ms = d?.getTime?.();
      if (!Number.isFinite(ms)) return false;
      if (Number.isFinite(startMs) && ms < startMs) return false;
      if (Number.isFinite(endMs) && ms > endMs) return false;
      return true;
    });

    items.sort((a, b) => {
      const ams = parseFlexibleDate(historyTimestampOf(a))?.getTime?.() || 0;
      const bms = parseFlexibleDate(historyTimestampOf(b))?.getTime?.() || 0;
      return ams - bms;
    });

    return res.json({ items });
  } catch (e) {
    return res.status(500).json({
      message: "Load history failed",
      error: String(e.message || e),
    });
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