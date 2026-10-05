// IP -> country (ISO 3166-1 alpha-2) using the offline geoip-country database.
// "??" means the IP has no public country (private range, reserved, unknown).
const geoip = require("geoip-country");
const db = require("./db");

const UNKNOWN = "??";

function countryOf(ip) {
  if (!ip) return null;
  try {
    const r = geoip.lookup(String(ip).replace(/^::ffff:/i, ""));
    return (r && r.country) || UNKNOWN;
  } catch (e) {
    return UNKNOWN;
  }
}

// Fills in the country of logs stored before the column existed.
function backfillCountries() {
  const rows = db.prepare("SELECT DISTINCT source_ip FROM ssh_logs WHERE country IS NULL AND source_ip IS NOT NULL").all();
  if (!rows.length) return;
  const upd = db.prepare("UPDATE ssh_logs SET country = ? WHERE source_ip = ? AND country IS NULL");
  db.exec("BEGIN");
  try {
    for (const r of rows) upd.run(countryOf(r.source_ip), r.source_ip);
    db.exec("COMMIT");
  } catch (e) {
    db.exec("ROLLBACK");
    throw e;
  }
  console.log(`[geo] filled country for ${rows.length} IP(s)`);
}

module.exports = { countryOf, backfillCountries, UNKNOWN };
