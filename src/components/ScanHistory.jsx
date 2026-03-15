import { useEffect, useState } from "react";
import { getScans } from "../api/api";

export default function ScanHistory({ refresh }) {
  const [scans, setScans] = useState([]);

  useEffect(() => {
    getScans().then(data => setScans(Array.isArray(data) ? data : []));
  }, [refresh]);

  return (
    <div className="panel">
      <p className="panel-title">Scan History — {scans.length} scans</p>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Assets</th>
              <th>Vulnerabilities</th>
              <th>Findings</th>
              <th>Timestamp</th>
            </tr>
          </thead>
          <tbody>
            {scans.length === 0 ? (
              <tr className="empty-row"><td colSpan={5}>No scans uploaded yet</td></tr>
            ) : scans.map(s => (
              <tr key={s.id}>
                <td>{s.id}</td>
                <td>{s.assets}</td>
                <td>{s.vulnerabilities}</td>
                <td>{s.findings}</td>
                <td>{new Date(s.created_at).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}