import { useEffect, useState } from "react";
import { getFindings } from "../api/api";

export default function FindingTable({ refresh }) {
  const [findings, setFindings] = useState([]);

  useEffect(() => {
    getFindings().then(data => setFindings(Array.isArray(data) ? data : []));
  }, [refresh]);

  return (
    <div className="panel">
      <p className="panel-title">Findings — {findings.length} records</p>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Asset ID</th>
              <th>Vulnerability ID</th>
              <th>Port</th>
              <th>Risk Score</th>
            </tr>
          </thead>
          <tbody>
            {findings.length === 0 ? (
              <tr className="empty-row"><td colSpan={5}>No findings found</td></tr>
            ) : findings.map(f => (
              <tr key={f.id}>
                <td>{f.id}</td>
                <td>{f.asset_id}</td>
                <td>{f.vulnerability_id}</td>
                <td>{f.port || "—"}</td>
                <td>{f.risk_score != null ? f.risk_score.toFixed(1) : "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}