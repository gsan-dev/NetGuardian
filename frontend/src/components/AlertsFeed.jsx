const SEVERITY_LABEL = { low: "Baja", medium: "Media", high: "Alta", none: "—" };

function formatDate(ts) {
  return new Date(ts * 1000).toLocaleString();
}

export default function AlertsFeed({ alerts }) {
  return (
    <section className="panel">
      <h2>Alertas</h2>
      {alerts.length === 0 && <p className="empty">Sin alertas todavía. Buena señal.</p>}
      <ul className="alerts-list">
        {alerts.map((a) => (
          <li key={a.id} className={`alert alert-${a.severity}`}>
            <div className="alert-header">
              <span className="severity">{SEVERITY_LABEL[a.severity] || a.severity}</span>
              <span className="time">{formatDate(a.created_at)}</span>
            </div>
            <div className="alert-body">
              <strong>{a.source_ip || "IP desconocida"}</strong>
              {a.port ? `:${a.port}` : ""} — {a.reason}
            </div>
          </li>
        ))}
      </ul>
    </section>
  );
}
