// Risk assessment engine (per note.md)
// Failed login thresholds:
//   < 5   -> LOW
//   >= 5  -> MEDIUM
//   >= 20 -> HIGH
//   >= 50 -> CRITICAL
// Brute force + successful login -> CRITICAL

function calculateRisk(failedAttempts, loginSuccess = false) {
  if (loginSuccess && failedAttempts >= 5) return "CRITICAL";
  if (failedAttempts >= 50) return "CRITICAL";
  if (failedAttempts >= 20) return "HIGH";
  if (failedAttempts >= 5) return "MEDIUM";
  return "LOW";
}

const RISK_ORDER = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };

function maxRisk(a, b) {
  return RISK_ORDER[a] >= RISK_ORDER[b] ? a : b;
}

module.exports = { calculateRisk, maxRisk, RISK_ORDER };
