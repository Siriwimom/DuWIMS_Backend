require("dotenv").config();
const mongoose = require("mongoose");
const admin = require("firebase-admin");
const serviceAccount = require("./serviceAccountKey.json");


admin.initializeApp({
  credential: admin.credential.applicationDefault()
});

const db = admin.firestore();

// ===== 1) connect mongo =====
mongoose.connect(process.env.MONGO_URI);

// ===== 2) define minimal schemas =====
const PlotSchema = new mongoose.Schema({}, { strict: false, collection: "plots" });
const NodeSchema = new mongoose.Schema({}, { strict: false, collection: "nodes" });
const PinSchema = new mongoose.Schema({}, { strict: false, collection: "pins" });
const SensorSchema = new mongoose.Schema({}, { strict: false, collection: "sensors" });
const ReadingSchema = new mongoose.Schema({}, { strict: false, collection: "readings" });

const Plot = mongoose.model("PlotTmp", PlotSchema);
const NodeM = mongoose.model("NodeTmp", NodeSchema);
const Pin = mongoose.model("PinTmp", PinSchema);
const Sensor = mongoose.model("SensorTmp", SensorSchema);
const Reading = mongoose.model("ReadingTmp", ReadingSchema);

function convertDoc(doc) {
  const obj = doc.toObject ? doc.toObject() : doc;

  function deepConvert(value) {
    if (value === null || value === undefined) return value;

    if (value instanceof mongoose.Types.ObjectId) {
      return value.toString();
    }

    if (value instanceof Date) {
      return value; // Firestore รองรับ Date
    }

    if (Array.isArray(value)) {
      return value.map(deepConvert);
    }

    if (typeof value === "object") {
      const out = {};
      for (const k of Object.keys(value)) {
        out[k] = deepConvert(value[k]);
      }
      return out;
    }

    return value;
  }

  const converted = deepConvert(obj);
  converted.mongoId = obj._id.toString();
  delete converted._id;
  delete converted.__v;
  return converted;
}

async function migrateCollection(model, collectionName) {
  const docs = await model.find({});
  console.log(`Migrating ${collectionName}: ${docs.length} docs`);

  for (const doc of docs) {
    const id = doc._id.toString();
    const data = convertDoc(doc);
    await db.collection(collectionName).doc(id).set(data, { merge: true });
  }

  console.log(`Done: ${collectionName}`);
}

async function run() {
  try {
    await migrateCollection(Plot, "plots");
    await migrateCollection(NodeM, "nodes");
    await migrateCollection(Pin, "pins");
    await migrateCollection(Sensor, "sensors");
    await migrateCollection(Reading, "readings");

    console.log("Migration completed");
  } catch (err) {
    console.error(err);
  } finally {
    await mongoose.disconnect();
    process.exit();
  }
}

run();