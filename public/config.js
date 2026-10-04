// The backend (Fly.io) serves this frontend directly, so every request is same-origin.
// Kept as an object (instead of deleting it) because app.js / get-key.html / index.html
// all read API_CONFIG.BACKEND_URL - an empty string here means "same origin".
const API_CONFIG = {
  BACKEND_URL: "",
};
