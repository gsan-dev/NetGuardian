import { useEffect, useState } from "react";
import { fetchServices } from "../api";

const REFRESH_MS = 10000;

export default function ServicesPanel() {
  const [services, setServices] = useState([]);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const data = await fetchServices(true);
        if (!cancelled) setServices(data);
      } catch (err) {
        if (!cancelled) setError(err.message);
      }
    }

    load();
    const interval = setInterval(load, REFRESH_MS);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  return (
    <section className="panel">
      <h2>Servicios activos</h2>
      {error && <p className="error">{error}</p>}
      <div className="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>Puerto</th>
              <th>Protocolo</th>
              <th>Proceso / Contenedor</th>
              <th>Origen</th>
            </tr>
          </thead>
          <tbody>
            {services.length === 0 && (
              <tr>
                <td colSpan={4} className="empty">
                  Sin servicios detectados todavía
                </td>
              </tr>
            )}
            {services.map((s) => (
              <tr key={`${s.port}-${s.protocol}-${s.process_name}-${s.container_id}`}>
                <td>{s.port || "—"}</td>
                <td>{s.protocol}</td>
                <td>{s.container_name || s.process_name || "—"}</td>
                <td>{s.is_docker ? "🐳 Docker" : "Proceso"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
