require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { sql, getPool } = require("./db");

const app = express();
app.use(cors());
app.use(express.json());

const { connectMongo } = require("./mongo");

(async () => {
  try {
    await connectMongo();
  } catch (e) {
    console.error("[MONGO] connect failed:", e.message);
  }
})();
app.get("/mongo/ping", async (req, res) => {
  try {
    await connectMongo();
    res.json({ ok: true, message: "MongoDB Atlas connected" });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});



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


// ==============================
// IoT Plots / Pins / Sensors API (mock in-memory)
// ==============================

const api = express.Router();

// Protect all /api routes with JWT
api.use(auth);

// ----- helpers -----
const nowIso = () => new Date().toISOString();
const toNum = (v) => (v === undefined || v === null || v === "" ? null : Number(v));
const clampNum = (v, a, b) => Math.max(a, Math.min(b, v));
const genId = () => Math.random().toString(16).slice(2) + Date.now().toString(16);

// ----- sensor type registry (matches your UI keys) -----
const SENSOR_TYPES = [
  { key: "soil", label: "ความชื้นในดิน", unit: "%" },
  { key: "temp", label: "อุณหภูมิ", unit: "°C" },
  { key: "rh", label: "ความชื้นสัมพัทธ์", unit: "%" },
  { key: "npk", label: "NPK", unit: "" },
  { key: "light", label: "ความเข้มแสง", unit: "lux" },
  { key: "rain", label: "ปริมาณน้ำฝน", unit: "mm" },
  { key: "wind", label: "ความเร็วลม", unit: "m/s" },
  { key: "water", label: "การให้น้ำ", unit: "L" },
];

// ----- in-memory data (replace with DB later) -----
const db = {
  plots: [
    {
      id: "plot_A",
      name: "แปลง A",
      cropType: "ทุเรียนหมอนทอง",
      ownerName: "สมชาย ใจดี",
      plantedAt: "2025-06-15",
      createdAt: nowIso(),
      updatedAt: nowIso(),
    },
  ],
  polygons: [
    {
      id: "poly_A",
      plotId: "plot_A",
      coordinates: [
        [13.35, 101.0],
        [13.35, 101.2],
        [13.25, 101.2],
        [13.25, 101.0],
      ],
      createdAt: nowIso(),
      updatedAt: nowIso(),
    },
  ],
  pins: [
    { id: "pin_1", plotId: "plot_A", number: 1, lat: 13.34, lng: 101.08, createdAt: nowIso(), updatedAt: nowIso() },
    { id: "pin_2", plotId: "plot_A", number: 2, lat: 13.33, lng: 101.15, createdAt: nowIso(), updatedAt: nowIso() },
    { id: "pin_3", plotId: "plot_A", number: 3, lat: 13.30, lng: 101.12, createdAt: nowIso(), updatedAt: nowIso() },
  ],
  sensors: [
    { id: "sen_1", pinId: "pin_1", typeKey: "soil", name: "เซนเซอร์ความชื้นดิน #1", unit: "%", createdAt: nowIso(), updatedAt: nowIso() },
    { id: "sen_2", pinId: "pin_1", typeKey: "temp", name: "เซนเซอร์อุณหภูมิ #1", unit: "°C", createdAt: nowIso(), updatedAt: nowIso() },
  ],
  readings: [
    // { id, sensorId, ts, value }
  ],
};

// ----- basic lookups -----
function getPlot(plotId) {
  return db.plots.find((p) => p.id === plotId);
}
function getPolygonByPlot(plotId) {
  return db.polygons.find((p) => p.plotId === plotId);
}
function getPin(pinId) {
  return db.pins.find((p) => p.id === pinId);
}
function getSensorsByPin(pinId) {
  return db.sensors.filter((s) => s.pinId === pinId);
}
function getSensor(sensorId) {
  return db.sensors.find((s) => s.id === sensorId);
}

// ==============================
// 1) Reference endpoints
// ==============================

// Sensor types (for dropdown)
api.get("/sensor-types", (req, res) => {
  res.json({ items: SENSOR_TYPES });
});

// ==============================
// 2) Plots (used by dashboard, management, history filters)
// ==============================

api.get("/plots", (req, res) => {
  res.json({ items: db.plots });
});

api.post("/plots", (req, res) => {
  const { name, cropType, ownerName, plantedAt } = req.body || {};
  if (!name) return res.status(400).json({ message: "name is required" });

  const plot = {
    id: genId(),
    name,
    cropType: cropType || "",
    ownerName: ownerName || "",
    plantedAt: plantedAt || null,
    createdAt: nowIso(),
    updatedAt: nowIso(),
  };
  db.plots.push(plot);
  res.status(201).json({ item: plot });
});

api.get("/plots/:plotId", (req, res) => {
  const plot = getPlot(req.params.plotId);
  if (!plot) return res.status(404).json({ message: "Plot not found" });
  res.json({ item: plot });
});

api.patch("/plots/:plotId", (req, res) => {
  const plot = getPlot(req.params.plotId);
  if (!plot) return res.status(404).json({ message: "Plot not found" });

  const { name, cropType, ownerName, plantedAt } = req.body || {};
  if (name !== undefined) plot.name = name;
  if (cropType !== undefined) plot.cropType = cropType;
  if (ownerName !== undefined) plot.ownerName = ownerName;
  if (plantedAt !== undefined) plot.plantedAt = plantedAt;
  plot.updatedAt = nowIso();

  res.json({ item: plot });
});

api.delete("/plots/:plotId", (req, res) => {
  const { plotId } = req.params;
  db.plots = db.plots.filter((p) => p.id !== plotId);
  db.polygons = db.polygons.filter((p) => p.plotId !== plotId);
  const pinIds = db.pins.filter((p) => p.plotId === plotId).map((p) => p.id);
  db.pins = db.pins.filter((p) => p.plotId !== plotId);
  db.sensors = db.sensors.filter((s) => !pinIds.includes(s.pinId));
  res.json({ ok: true });
});

// ==============================
// 3) Polygon (Edit/Delete page needs this)
// ==============================

// Get polygon of a plot
api.get("/plots/:plotId/polygon", (req, res) => {
  const plot = getPlot(req.params.plotId);
  if (!plot) return res.status(404).json({ message: "Plot not found" });
  const poly = getPolygonByPlot(req.params.plotId);
  res.json({ item: poly || null });
});

// Replace polygon coordinates (simple, all-in-one)
api.put("/plots/:plotId/polygon", (req, res) => {
  const plotId = req.params.plotId;
  const plot = getPlot(plotId);
  if (!plot) return res.status(404).json({ message: "Plot not found" });

  const { coordinates } = req.body || {};
  if (!Array.isArray(coordinates) || coordinates.length < 3) {
    return res.status(400).json({ message: "coordinates must be array of [lat,lng] and length >= 3" });
  }

  let poly = getPolygonByPlot(plotId);
  if (!poly) {
    poly = { id: genId(), plotId, coordinates, createdAt: nowIso(), updatedAt: nowIso() };
    db.polygons.push(poly);
  } else {
    poly.coordinates = coordinates;
    poly.updatedAt = nowIso();
  }

  res.json({ item: poly });
});

// ==============================
// 4) Pins (AddSensor, Edit/Delete, Dashboard map)
// ==============================

api.get("/plots/:plotId/pins", (req, res) => {
  const plotId = req.params.plotId;
  const plot = getPlot(plotId);
  if (!plot) return res.status(404).json({ message: "Plot not found" });
  const items = db.pins.filter((p) => p.plotId === plotId).sort((a, b) => a.number - b.number);
  res.json({ items });
});

api.post("/plots/:plotId/pins", (req, res) => {
  const plotId = req.params.plotId;
  const plot = getPlot(plotId);
  if (!plot) return res.status(404).json({ message: "Plot not found" });

  const { number, lat, lng } = req.body || {};
  const n = toNum(number);
  const la = toNum(lat);
  const lo = toNum(lng);
  if (!n || la === null || lo === null) return res.status(400).json({ message: "number, lat, lng are required" });

  if (db.pins.some((p) => p.plotId === plotId && p.number === n)) {
    return res.status(409).json({ message: "Pin number already exists in this plot" });
  }

  const pin = { id: genId(), plotId, number: n, lat: la, lng: lo, createdAt: nowIso(), updatedAt: nowIso() };
  db.pins.push(pin);
  res.status(201).json({ item: pin });
});

// Update pin position / number
api.patch("/pins/:pinId", (req, res) => {
  const pin = getPin(req.params.pinId);
  if (!pin) return res.status(404).json({ message: "Pin not found" });

  const { number, lat, lng } = req.body || {};
  if (number !== undefined) pin.number = toNum(number);
  if (lat !== undefined) pin.lat = toNum(lat);
  if (lng !== undefined) pin.lng = toNum(lng);
  pin.updatedAt = nowIso();

  res.json({ item: pin });
});

// Delete pin (Edit/Delete per-row)
api.delete("/pins/:pinId", (req, res) => {
  const pinId = req.params.pinId;
  const pin = getPin(pinId);
  if (!pin) return res.status(404).json({ message: "Pin not found" });

  // cascade delete sensors + readings
  const sensorIds = db.sensors.filter((s) => s.pinId === pinId).map((s) => s.id);
  db.readings = db.readings.filter((r) => !sensorIds.includes(r.sensorId));
  db.sensors = db.sensors.filter((s) => s.pinId !== pinId);
  db.pins = db.pins.filter((p) => p.id !== pinId);

  res.json({ ok: true });
});

// Delete all pins in a plot (Edit/Delete "ลบทั้งหมด")
api.delete("/plots/:plotId/pins", (req, res) => {
  const plotId = req.params.plotId;
  const plot = getPlot(plotId);
  if (!plot) return res.status(404).json({ message: "Plot not found" });

  const pinIds = db.pins.filter((p) => p.plotId === plotId).map((p) => p.id);
  const sensorIds = db.sensors.filter((s) => pinIds.includes(s.pinId)).map((s) => s.id);

  db.readings = db.readings.filter((r) => !sensorIds.includes(r.sensorId));
  db.sensors = db.sensors.filter((s) => !pinIds.includes(s.pinId));
  db.pins = db.pins.filter((p) => p.plotId !== plotId);

  res.json({ ok: true });
});

// ==============================
// 5) Sensors (AddSensor page needs add/list/delete sensors per pin)
// ==============================

api.get("/pins/:pinId/sensors", (req, res) => {
  const pin = getPin(req.params.pinId);
  if (!pin) return res.status(404).json({ message: "Pin not found" });
  res.json({ items: getSensorsByPin(pin.id) });
});

api.post("/pins/:pinId/sensors", (req, res) => {
  const pin = getPin(req.params.pinId);
  if (!pin) return res.status(404).json({ message: "Pin not found" });

  const { typeKey, name } = req.body || {};
  if (!typeKey) return res.status(400).json({ message: "typeKey is required" });

  const st = SENSOR_TYPES.find((t) => t.key === typeKey);
  if (!st) return res.status(400).json({ message: "unknown typeKey" });

  const sensor = {
    id: genId(),
    pinId: pin.id,
    typeKey,
    name: name || st.label,
    unit: st.unit,
    createdAt: nowIso(),
    updatedAt: nowIso(),
  };
  db.sensors.push(sensor);
  res.status(201).json({ item: sensor });
});

// Update sensor meta
api.patch("/sensors/:sensorId", (req, res) => {
  const sensor = getSensor(req.params.sensorId);
  if (!sensor) return res.status(404).json({ message: "Sensor not found" });

  const { name, typeKey } = req.body || {};
  if (name !== undefined) sensor.name = name;
  if (typeKey !== undefined) {
    const st = SENSOR_TYPES.find((t) => t.key === typeKey);
    if (!st) return res.status(400).json({ message: "unknown typeKey" });
    sensor.typeKey = typeKey;
    sensor.unit = st.unit;
  }
  sensor.updatedAt = nowIso();
  res.json({ item: sensor });
});

// Delete sensor
api.delete("/sensors/:sensorId", (req, res) => {
  const sensorId = req.params.sensorId;
  const sensor = getSensor(sensorId);
  if (!sensor) return res.status(404).json({ message: "Sensor not found" });

  db.readings = db.readings.filter((r) => r.sensorId !== sensorId);
  db.sensors = db.sensors.filter((s) => s.id !== sensorId);
  res.json({ ok: true });
});

// ==============================
// 6) Readings + History (History page needs query + stats + export)
// ==============================

// Device / gateway can post readings
api.post("/readings", (req, res) => {
  const { sensorId, ts, value } = req.body || {};
  const sensor = getSensor(sensorId);
  if (!sensor) return res.status(404).json({ message: "Sensor not found" });

  const v = toNum(value);
  if (v === null || Number.isNaN(v)) return res.status(400).json({ message: "value must be number" });

  const r = { id: genId(), sensorId, ts: ts || nowIso(), value: v };
  db.readings.push(r);
  res.status(201).json({ item: r });
});

// Query readings:
// /api/readings?plotId=plot_A&sensorKeys=soil,temp&from=2025-09-01&to=2025-09-30&bucket=hour
api.get("/readings", (req, res) => {
  const { plotId, pinId, sensorKeys, from, to } = req.query;

  let sensorKeyList = [];
  if (typeof sensorKeys === "string" && sensorKeys.trim()) {
    sensorKeyList = sensorKeys.split(",").map((s) => s.trim()).filter(Boolean);
  }

  let sensorIds = db.sensors.map((s) => s.id);

  if (pinId) {
    sensorIds = db.sensors.filter((s) => s.pinId === pinId).map((s) => s.id);
  } else if (plotId) {
    const pinIds = db.pins.filter((p) => p.plotId === plotId).map((p) => p.id);
    sensorIds = db.sensors.filter((s) => pinIds.includes(s.pinId)).map((s) => s.id);
  }

  if (sensorKeyList.length) {
    sensorIds = db.sensors
      .filter((s) => sensorIds.includes(s.id) && sensorKeyList.includes(s.typeKey))
      .map((s) => s.id);
  }

  const fromTs = from ? new Date(from).getTime() : null;
  const toTs = to ? new Date(to).getTime() : null;

  const items = db.readings
    .filter((r) => sensorIds.includes(r.sensorId))
    .filter((r) => {
      const t = new Date(r.ts).getTime();
      if (fromTs !== null && t < fromTs) return false;
      if (toTs !== null && t > toTs) return false;
      return true;
    })
    .sort((a, b) => new Date(a.ts).getTime() - new Date(b.ts).getTime());

  res.json({ items });
});

// Summary stats per plot (min/max/avg/last for selected sensors)
api.get("/plots/:plotId/summary", (req, res) => {
  const plotId = req.params.plotId;
  const plot = getPlot(plotId);
  if (!plot) return res.status(404).json({ message: "Plot not found" });

  const pinIds = db.pins.filter((p) => p.plotId === plotId).map((p) => p.id);
  const sensors = db.sensors.filter((s) => pinIds.includes(s.pinId));
  const byType = {};

  for (const s of sensors) {
    const rs = db.readings.filter((r) => r.sensorId === s.id).sort((a, b) => new Date(a.ts) - new Date(b.ts));
    if (!rs.length) continue;

    const values = rs.map((x) => x.value);
    const min = Math.min(...values);
    const max = Math.max(...values);
    const avg = values.reduce((sum, v) => sum + v, 0) / values.length;
    const last = rs[rs.length - 1];

    const key = s.typeKey;
    if (!byType[key]) byType[key] = { typeKey: key, unit: s.unit, min, max, avg, last: last.value, lastAt: last.ts };
    else {
      // merge across sensors of same type -> average the avg, min/min, max/max, last = latest
      byType[key].min = Math.min(byType[key].min, min);
      byType[key].max = Math.max(byType[key].max, max);
      byType[key].avg = (byType[key].avg + avg) / 2;

      if (new Date(last.ts) > new Date(byType[key].lastAt)) {
        byType[key].last = last.value;
        byType[key].lastAt = last.ts;
      }
    }
  }

  res.json({ plotId, items: Object.values(byType) });
});

// Export CSV (History "EXPORT CSV")
api.get("/export/readings.csv", (req, res) => {
  const { plotId, pinId, sensorKeys, from, to } = req.query;

  // reuse logic by calling the query function inline
  // (simple duplicate, keeps this file dependency-free)
  let sensorKeyList = [];
  if (typeof sensorKeys === "string" && sensorKeys.trim()) {
    sensorKeyList = sensorKeys.split(",").map((s) => s.trim()).filter(Boolean);
  }

  let sensorIds = db.sensors.map((s) => s.id);

  if (pinId) {
    sensorIds = db.sensors.filter((s) => s.pinId === pinId).map((s) => s.id);
  } else if (plotId) {
    const pinIds = db.pins.filter((p) => p.plotId === plotId).map((p) => p.id);
    sensorIds = db.sensors.filter((s) => pinIds.includes(s.pinId)).map((s) => s.id);
  }

  if (sensorKeyList.length) {
    sensorIds = db.sensors
      .filter((s) => sensorIds.includes(s.id) && sensorKeyList.includes(s.typeKey))
      .map((s) => s.id);
  }

  const fromTs = from ? new Date(from).getTime() : null;
  const toTs = to ? new Date(to).getTime() : null;

  const rows = db.readings
    .filter((r) => sensorIds.includes(r.sensorId))
    .filter((r) => {
      const t = new Date(r.ts).getTime();
      if (fromTs !== null && t < fromTs) return false;
      if (toTs !== null && t > toTs) return false;
      return true;
    })
    .map((r) => {
      const s = getSensor(r.sensorId);
      const pin = s ? getPin(s.pinId) : null;
      const plot = pin ? getPlot(pin.plotId) : null;
      return {
        ts: r.ts,
        plotId: plot?.id || "",
        plotName: plot?.name || "",
        pinId: pin?.id || "",
        pinNumber: pin?.number ?? "",
        sensorId: s?.id || "",
        sensorType: s?.typeKey || "",
        sensorName: s?.name || "",
        value: r.value,
        unit: s?.unit || "",
      };
    });

  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", 'attachment; filename="readings.csv"');

  // write BOM for Excel
  res.write("\ufeff");
  const header = Object.keys(rows[0] || { ts: "", plotId: "", plotName: "", pinId: "", pinNumber: "", sensorId: "", sensorType: "", sensorName: "", value: "", unit: "" });
  res.write(header.join(",") + "\n");
  for (const row of rows) {
    const line = header.map((k) => String(row[k] ?? "").replaceAll('"', '""')).map((v) => `"${v}"`).join(",");
    res.write(line + "\n");
  }
  res.end();
});

// ==============================
// 7) Dashboard convenience endpoints (optional but recommended)
// ==============================

// Overview cards: device on/off + issue count
api.get("/dashboard/overview", (req, res) => {
  const { plotId } = req.query;
  const pins = plotId ? db.pins.filter((p) => p.plotId === plotId) : db.pins;

  // mock online: all pins online; mock issue: pin number 3
  const on = pins.length;
  const off = 0;
  const issues = pins.some((p) => p.number === 3) ? 1 : 0;

  res.json({ plotId: plotId || "all", on, off, issues });
});

// Pin cards for dashboard (latest values grouped)
api.get("/dashboard/pins", (req, res) => {
  const { plotId } = req.query;
  const pins = (plotId ? db.pins.filter((p) => p.plotId === plotId) : db.pins).sort((a, b) => a.number - b.number);

  const items = pins.map((p) => {
    const sensors = getSensorsByPin(p.id);
    const groups = sensors.reduce((acc, s) => {
      if (!acc[s.typeKey]) acc[s.typeKey] = { typeKey: s.typeKey, label: SENSOR_TYPES.find((t) => t.key === s.typeKey)?.label || s.typeKey, unit: s.unit, sensors: [] };
      const last = db.readings.filter((r) => r.sensorId === s.id).sort((a, b) => new Date(a.ts) - new Date(b.ts)).at(-1);
      acc[s.typeKey].sensors.push({ sensorId: s.id, name: s.name, lastValue: last ? last.value : null, lastAt: last ? last.ts : null });
      return acc;
    }, {});
    return {
      pinId: p.id,
      pinNumber: p.number,
      lat: p.lat,
      lng: p.lng,
      status: p.number === 3 ? "ALERT" : "OK",
      groups: Object.values(groups),
    };
  });

  res.json({ items });
});

// Weather endpoints (placeholder: wire to real provider later)
api.get("/weather/forecast", (req, res) => {
  // expected query: lat, lng, days=7
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

// finally mount router
app.use("/api", api);
app.listen(process.env.PORT || 3000, () => {
  console.log("[API] running on port", process.env.PORT || 3000);
});
