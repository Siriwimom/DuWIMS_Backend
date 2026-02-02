// mongo.js
const mongoose = require("mongoose");

let connected = false;

async function connectMongo() {
  if (connected) return mongoose.connection;

  const uri = process.env.MONGO_URI;
  if (!uri) throw new Error("Missing MONGO_URI");

  await mongoose.connect(uri);
  connected = true;

  console.log("[MONGO] connected to Atlas");
  return mongoose.connection;
}

module.exports = { connectMongo };
