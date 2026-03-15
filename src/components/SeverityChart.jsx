import { useEffect, useState } from "react";
import { Pie } from "react-chartjs-2";
import { Chart as ChartJS, ArcElement, Tooltip } from "chart.js";
import { getVulnerabilities } from "../api/api";

ChartJS.register(ArcElement, Tooltip);

const SEVERITY_META = [
  { label: "Critical", color: "#ef4444" },
  { label: "High",     color: "#f97316" },
  { label: "Medium",   color: "#eab308" },
  { label: "Low",      color: "#22c55e" },
];

export default function SeverityChart({ refresh }) {
  const [vulns, setVulns] = useState([]);

  useEffect(() => {
    getVulnerabilities().then(data => {
      setVulns(Array.isArray(data) ? data : []);
    });
  }, [refresh]);

  const counts = SEVERITY_META.map(s =>
    vulns.filter(v => v.severity === s.label).length
  );
  const total = counts.reduce((a, b) => a + b, 0);

  const chartData = {
    labels: SEVERITY_META.map(s => s.label),
    datasets: [{
      data: counts,
      backgroundColor: SEVERITY_META.map(s => s.color + "cc"),
      borderColor: SEVERITY_META.map(s => s.color),
      borderWidth: 1.5,
      hoverOffset: 6,
    }]
  };

  const options = {
    maintainAspectRatio: true,
    plugins: { legend: { display: false }, tooltip: { enabled: true } },
    cutout: "62%",
  };

  return (
    <div className="panel">
      <p className="panel-title">Severity Distribution</p>

      {total === 0 ? (
        <p style={{ color: "var(--text-muted)", fontSize: 13, textAlign: "center", padding: "24px 0" }}>
          No vulnerability data available.
        </p>
      ) : (
        <div className="chart-row">
          {/* Donut chart */}
          <div style={{ width: 220, height: 220, position: "relative", margin: "0 auto" }}>
            <Pie data={chartData} options={options} />
            <div style={{
              position: "absolute", inset: 0,
              display: "flex", flexDirection: "column",
              alignItems: "center", justifyContent: "center",
              pointerEvents: "none"
            }}>
              <span style={{ fontSize: 28, fontWeight: 800, color: "var(--text-primary)" }}>{total}</span>
              <span style={{ fontSize: 10, color: "var(--text-muted)", letterSpacing: "0.08em", textTransform: "uppercase" }}>Total</span>
            </div>
          </div>

          {/* Legend */}
          <div className="chart-legend">
            {SEVERITY_META.map((s, i) => (
              <div className="legend-item" key={s.label}>
                <div className="legend-left">
                  <div className="legend-dot" style={{ background: s.color }} />
                  <span className="legend-name">{s.label}</span>
                </div>
                <span className="legend-count">{counts[i]}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}