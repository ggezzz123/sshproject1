// Set RENDER_BACKEND_URL to your Render service URL (no trailing slash).
// When the page is served by the backend itself (localhost / Render), requests stay same-origin.
const RENDER_BACKEND_URL = "https://ssh-monitor-backend.onrender.com";

const API_CONFIG = {
  BACKEND_URL: window.location.hostname.endsWith("netlify.app") ? RENDER_BACKEND_URL : "",
};
