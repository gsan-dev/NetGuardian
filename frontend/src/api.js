/**
 * Cliente API de NetGuardian: login/JWT, REST y WebSocket en tiempo real.
 *
 * La autenticación (mejora futura del README ya integrada) guarda el
 * token en localStorage. Si el backend responde 401, se limpia el
 * token para forzar un nuevo login.
 */
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";
const WS_BASE_URL = API_BASE_URL.replace(/^http/, "ws");
const TOKEN_KEY = "netguardian_token";

export class ApiAuthError extends Error {}

export function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token) {
  if (token) localStorage.setItem(TOKEN_KEY, token);
  else localStorage.removeItem(TOKEN_KEY);
}

async function apiFetch(path, options = {}) {
  const token = getToken();
  const headers = { "Content-Type": "application/json", ...options.headers };
  if (token) headers.Authorization = `Bearer ${token}`;

  const response = await fetch(`${API_BASE_URL}${path}`, { ...options, headers });

  if (response.status === 401) {
    setToken(null);
    throw new ApiAuthError("Sesión expirada, inicia sesión de nuevo");
  }
  if (!response.ok) {
    throw new Error(`Error ${response.status} llamando a ${path}`);
  }
  return response;
}

export async function login(username, password) {
  const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!response.ok) {
    throw new Error("Credenciales inválidas");
  }
  const data = await response.json();
  setToken(data.access_token);
  return data;
}

export async function fetchServices(activeOnly = true) {
  const response = await apiFetch(`/api/services?active_only=${activeOnly}`);
  return response.json();
}

export async function fetchAlerts(limit = 100) {
  const response = await apiFetch(`/api/alerts?limit=${limit}`);
  return response.json();
}

export async function fetchTrafficWindows(limit = 100) {
  const response = await apiFetch(`/api/traffic/windows?limit=${limit}`);
  return response.json();
}

export async function fetchBlockedIps() {
  const response = await apiFetch(`/api/alerts/blocked-ips`);
  return response.json();
}

export async function downloadWeeklyReport() {
  const response = await apiFetch(`/api/reports/weekly`);
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "netguardian_informe_semanal.pdf";
  link.click();
  URL.revokeObjectURL(url);
}

export function connectWebSocket({ onMessage, onOpen, onClose }) {
  const token = getToken();
  const url = `${WS_BASE_URL}/ws${token ? `?token=${encodeURIComponent(token)}` : ""}`;
  const ws = new WebSocket(url);
  ws.onopen = () => onOpen && onOpen();
  ws.onclose = () => onClose && onClose();
  ws.onmessage = (event) => {
    try {
      const message = JSON.parse(event.data);
      onMessage && onMessage(message);
    } catch (err) {
      console.error("Mensaje de WebSocket inválido", err);
    }
  };
  return ws;
}
