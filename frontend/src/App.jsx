import { useCallback, useEffect, useRef, useState } from "react";
import AlertsFeed from "./components/AlertsFeed";
import LoginForm from "./components/LoginForm";
import ServicesPanel from "./components/ServicesPanel";
import TrafficChart from "./components/TrafficChart";
import {
  ApiAuthError,
  connectWebSocket,
  downloadWeeklyReport,
  fetchAlerts,
  fetchTrafficWindows,
  getToken,
  setToken,
} from "./api";

const MAX_WINDOWS = 120;
const MAX_ALERTS = 100;

export default function App() {
  const [authed, setAuthed] = useState(() => Boolean(getToken()));
  const [windows, setWindows] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [wsStatus, setWsStatus] = useState("desconectado");
  const wsRef = useRef(null);

  const loadInitialData = useCallback(async () => {
    try {
      const [windowsData, alertsData] = await Promise.all([
        fetchTrafficWindows(MAX_WINDOWS),
        fetchAlerts(MAX_ALERTS),
      ]);
      setWindows(windowsData);
      setAlerts(alertsData);
    } catch (err) {
      if (err instanceof ApiAuthError) {
        setAuthed(false);
      }
    }
  }, []);

  useEffect(() => {
    if (!authed) return undefined;

    loadInitialData();

    const ws = connectWebSocket({
      onOpen: () => setWsStatus("conectado"),
      onClose: () => setWsStatus("desconectado"),
      onMessage: (message) => {
        if (message.type === "traffic_window") {
          setWindows((prev) => [...prev.slice(-(MAX_WINDOWS - 1)), message.data]);
        } else if (message.type === "alert") {
          setAlerts((prev) => [message.data, ...prev].slice(0, MAX_ALERTS));
        }
      },
    });
    wsRef.current = ws;

    return () => ws.close();
  }, [authed, loadInitialData]);

  function handleLogout() {
    setToken(null);
    wsRef.current?.close();
    setAuthed(false);
  }

  if (!authed) {
    return <LoginForm onLoggedIn={() => setAuthed(true)} />;
  }

  return (
    <div className="app">
      <header className="topbar">
        <h1>🛡️ NetGuardian</h1>
        <div className="topbar-actions">
          <span className={`ws-badge ${wsStatus === "conectado" ? "ws-on" : "ws-off"}`}>
            {wsStatus === "conectado" ? "● En vivo" : "○ Sin conexión"}
          </span>
          <button onClick={downloadWeeklyReport}>Informe semanal (PDF)</button>
          <button className="ghost" onClick={handleLogout}>
            Salir
          </button>
        </div>
      </header>

      <main className="dashboard">
        <ServicesPanel />
        <TrafficChart windows={windows} />
        <AlertsFeed alerts={alerts} />
      </main>
    </div>
  );
}
