import {
  Area,
  CartesianGrid,
  ComposedChart,
  Legend,
  Line,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

function formatTime(ts) {
  return new Date(ts * 1000).toLocaleTimeString();
}

export default function TrafficChart({ windows }) {
  const data = windows.map((w) => ({
    time: formatTime(w.window_end),
    bytes: w.total_bytes,
    connections: w.num_connections,
    anomaly: w.is_anomaly ? w.total_bytes : null,
  }));

  return (
    <section className="panel panel-wide">
      <h2>Tráfico de red</h2>
      <ResponsiveContainer width="100%" height={280}>
        <ComposedChart data={data} margin={{ top: 8, right: 16, bottom: 0, left: 0 }}>
          <CartesianGrid strokeDasharray="3 3" opacity={0.15} />
          <XAxis dataKey="time" tick={{ fontSize: 11 }} minTickGap={30} />
          <YAxis tick={{ fontSize: 11 }} />
          <Tooltip
            contentStyle={{ background: "#1e293b", border: "1px solid #334155", borderRadius: 8 }}
          />
          <Legend />
          <Area
            type="monotone"
            dataKey="bytes"
            name="Bytes por ventana"
            fill="#38bdf8"
            stroke="#0ea5e9"
            fillOpacity={0.25}
          />
          <Line
            type="monotone"
            dataKey="connections"
            name="Conexiones"
            stroke="#a78bfa"
            dot={false}
            strokeWidth={2}
          />
          <Line
            dataKey="anomaly"
            name="Anomalía detectada"
            stroke="none"
            dot={{ r: 5, fill: "#f87171", stroke: "#7f1d1d" }}
            isAnimationActive={false}
          />
        </ComposedChart>
      </ResponsiveContainer>
      {data.length === 0 && <p className="empty">Esperando datos del sensor…</p>}
    </section>
  );
}
