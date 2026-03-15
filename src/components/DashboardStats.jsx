import { useEffect, useState } from "react";
import { getAssets, getVulnerabilities } from "../api/api";

export default function DashboardStats({ refresh }) {
  const [assets, setAssets] = useState([]);
  const [vulns, setVulns]   = useState([]);

  useEffect(() => {
    Promise.all([getAssets(), getVulnerabilities()])
      .then(([a, v]) => {
        setAssets(Array.isArray(a) ? a : []);
        setVulns(Array.isArray(v) ? v : []);
      })
      .catch(() => { setAssets([]); setVulns([]); });
  }, [refresh]);

  const critical = vulns.filter(v => v.severity === "Critical").length;
  const high     = vulns.filter(v => v.severity === "High").length;
  const medium   = vulns.filter(v => v.severity === "Medium").length;
  const low      = vulns.filter(v => v.severity === "Low").length;

  const cards = [
    { label: "Total Assets",        value: assets.length, cls: "default" },
    { label: "Vulnerabilities",     value: vulns.length,  cls: "default" },
    { label: "Critical",            value: critical,       cls: "critical" },
    { label: "High",                value: high,           cls: "high" },
    { label: "Medium",              value: medium,         cls: "medium" },
    { label: "Low",                 value: low,            cls: "low" },
  ];

  return (
    <div className="stats-grid">
      {cards.map(c => (
        <div key={c.label} className={`stat-card ${c.cls}`}>
          <span className="stat-label">{c.label}</span>
          <span className="stat-value">{c.value}</span>
        </div>
      ))}
    </div>
  );
}