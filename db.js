const sql = require("mssql");

const config = {
  server: process.env.DB_HOST || "127.0.0.1",
  port: Number(process.env.DB_PORT || 14330),
  database: process.env.DB_NAME || "pmtool",
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  options: {
    encrypt: String(process.env.DB_ENCRYPT).toLowerCase() === "true",
    trustServerCertificate: String(process.env.DB_TRUST_CERT).toLowerCase() === "true",
  },
  pool: { max: 10, min: 0, idleTimeoutMillis: 30000 },
  connectionTimeout: 30000,
  requestTimeout: 30000,
};

let pool;

async function getPool() {
  if (pool) return pool;
  pool = await sql.connect(config);
  console.log("[MSSQL] connected:", `${config.server}:${config.port}/${config.database}`);
  return pool;
}

module.exports = { sql, getPool };
