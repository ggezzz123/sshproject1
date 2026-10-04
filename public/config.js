// Set this to wherever the backend actually runs (Fly.io, Render, ...), no trailing slash.
// When the page is served by the backend itself (localhost, or the backend's own domain),
// requests stay same-origin and this value is ignored.
const PROD_BACKEND_URL = "https://ssh-monitor.fly.dev";

const API_CONFIG = {
  BACKEND_URL: window.location.hostname.endsWith("netlify.app") ? PROD_BACKEND_URL : "",
};
