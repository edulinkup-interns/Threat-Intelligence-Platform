import { useEffect, useState } from "react";
import { getAssets } from "../api/api";

export default function AssetTable({ refresh }) {
  const [assets, setAssets] = useState([]);

  useEffect(() => {
    getAssets().then(data => setAssets(Array.isArray(data) ? data : []));
  }, [refresh]);

  return (
    <div className="panel">
      <p className="panel-title">Assets — {assets.length} records</p>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Hostname</th>
              <th>IP Address</th>
              <th>Criticality</th>
            </tr>
          </thead>
          <tbody>
            {assets.length === 0 ? (
              <tr className="empty-row"><td colSpan={4}>No assets found</td></tr>
            ) : assets.map(a => (
              <tr key={a.id}>
                <td>{a.id}</td>
                <td>{a.hostname}</td>
                <td>{a.ip}</td>
                <td>{a.criticality_score ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}