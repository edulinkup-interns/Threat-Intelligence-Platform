import { useEffect, useState } from "react";
import {
  getRiskSummary,
  getRankedAssets,
  getAssetRiskDetail,
  updateCriticality,
  forceRecalculate,
} from "../api/api";
import toast from "react-hot-toast";

// ── Severity badge ────────────────────────────────────────────────────────
function Badge({ severity }) {
  if (!severity) return <span className="badge badge-none">Unknown</span>;
  return (
    <span className={`badge badge-${severity.toLowerCase()}`}>{severity}</span>
  );
}

// ── Risk bar (visual score bar) ───────────────────────────────────────────
function RiskBar({ score, max }) {
  const pct = max > 0 ? Math.min((score / max) * 100, 100) : 0;
  const color =
    pct > 66 ? "#ef4444" : pct > 33 ? "#f97316" : "#eab308";
  return (
    <div style={{
      background: "var(--bg-hover)",
      borderRadius: 4,
      height: 6,
      width: "100%",
      overflow: "hidden",
    }}>
      <div style={{
        width: `${pct}%`,
        height: "100%",
        background: color,
        borderRadius: 4,
        transition: "width 0.4s ease",
        boxShadow: `0 0 8px ${color}88`,
      }} />
    </div>
  );
}

// ── CVE detail drawer ─────────────────────────────────────────────────────
function AssetDrawer({ asset, onClose, onCriticalityChange }) {
  const [detail, setDetail]         = useState(null);
  const [loading, setLoading]       = useState(true);
  const [editCrit, setEditCrit]     = useState("");
  const [savingCrit, setSavingCrit] = useState(false);

  useEffect(() => {
    if (!asset) return;
    setLoading(true);
    getAssetRiskDetail(asset.id)
      .then(d => { setDetail(d); setEditCrit(String(d.criticality_score)); })
      .finally(() => setLoading(false));
  }, [asset]);

  const saveCriticality = async () => {
    const val = parseFloat(editCrit);
    if (isNaN(val) || val < 0.1 || val > 5.0) {
      toast.error("Criticality must be between 0.1 and 5.0");
      return;
    }
    setSavingCrit(true);
    try {
      await updateCriticality(asset.id, val);
      toast.success("Criticality updated — scores recalculated");
      onCriticalityChange();
      getAssetRiskDetail(asset.id).then(setDetail);
    } catch {
      toast.error("Failed to update criticality");
    } finally {
      setSavingCrit(false);
    }
  };

  if (!asset) return null;

  return (
    <>
      {/* Backdrop */}
      <div
        onClick={onClose}
        style={{
          position: "fixed", inset: 0,
          background: "#00000088",
          zIndex: 40,
        }}
      />

      {/* Drawer */}
      <div style={{
        position: "fixed", top: 0, right: 0,
        width: "min(600px, 92vw)",
        height: "100vh",
        background: "var(--bg-surface)",
        borderLeft: "1px solid var(--border)",
        zIndex: 50,
        display: "flex",
        flexDirection: "column",
        overflow: "hidden",
      }}>

        {/* Drawer header */}
        <div style={{
          padding: "24px 28px",
          borderBottom: "1px solid var(--border)",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-start",
          flexShrink: 0,
        }}>
          <div>
            <div style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "var(--font-mono)", letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 6 }}>
              Asset Risk Detail
            </div>
            <div style={{ fontSize: 17, fontWeight: 700, color: "var(--text-primary)" }}>
              {asset.hostname}
            </div>
            <div style={{ fontSize: 12, color: "var(--text-muted)", fontFamily: "var(--font-mono)", marginTop: 3 }}>
              {asset.ip}
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              background: "var(--bg-hover)",
              border: "1px solid var(--border)",
              color: "var(--text-secondary)",
              borderRadius: 6,
              padding: "6px 12px",
              cursor: "pointer",
              fontFamily: "var(--font-display)",
              fontSize: 13,
            }}
          >
            Close
          </button>
        </div>

        {/* Drawer body */}
        <div style={{ flex: 1, overflowY: "auto", padding: "24px 28px" }}>
          {loading ? (
            <div className="loading-state" style={{ padding: 60 }}>
              <div className="spinner" />
              <p>Loading findings...</p>
            </div>
          ) : detail && (
            <>
              {/* Score + criticality editor */}
              <div style={{
                display: "grid",
                gridTemplateColumns: "1fr 1fr",
                gap: 14,
                marginBottom: 24,
              }}>
                <div className="stat-card default">
                  <span className="stat-label">Risk Score</span>
                  <span className="stat-value" style={{ fontSize: 26 }}>
                    {detail.risk_score.toFixed(1)}
                  </span>
                </div>
                <div className="stat-card" style={{ background: "var(--bg-elevated)", border: "1px solid var(--border)" }}>
                  <span className="stat-label">Criticality</span>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 6 }}>
                    <input
                      type="number"
                      min="0.1"
                      max="5.0"
                      step="0.1"
                      value={editCrit}
                      onChange={e => setEditCrit(e.target.value)}
                      style={{
                        width: 64,
                        background: "var(--bg-base)",
                        border: "1px solid var(--border-bright)",
                        borderRadius: 6,
                        color: "var(--purple-bright)",
                        fontFamily: "var(--font-mono)",
                        fontSize: 18,
                        fontWeight: 700,
                        padding: "4px 8px",
                      }}
                    />
                    <button
                      className="btn-primary"
                      style={{ padding: "5px 12px", fontSize: 12 }}
                      onClick={saveCriticality}
                      disabled={savingCrit}
                    >
                      {savingCrit ? "..." : "Set"}
                    </button>
                  </div>
                  <span style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 4 }}>
                    range 0.1 – 5.0
                  </span>
                </div>
              </div>

              {/* Findings list */}
              <div style={{ fontSize: 11, fontWeight: 600, letterSpacing: "0.1em", textTransform: "uppercase", color: "var(--text-muted)", fontFamily: "var(--font-mono)", marginBottom: 12 }}>
                Findings — {detail.findings.length}
              </div>

              <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                {detail.findings.map(f => (
                  <div key={f.finding_id} style={{
                    background: "var(--bg-elevated)",
                    border: "1px solid var(--border)",
                    borderRadius: 10,
                    padding: "16px 18px",
                  }}>
                    {/* Finding header */}
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 10 }}>
                      <div style={{ flex: 1, paddingRight: 12 }}>
                        <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text-primary)", marginBottom: 4, lineHeight: 1.4 }}>
                          {f.vulnerability.name}
                        </div>
                        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                          <Badge severity={f.vulnerability.severity} />
                          {f.vulnerability.cve && (
                            <a
                              href={`https://nvd.nist.gov/vuln/detail/${f.vulnerability.cve}`}
                              target="_blank"
                              rel="noreferrer"
                              style={{
                                fontSize: 11,
                                fontFamily: "var(--font-mono)",
                                color: "var(--purple-bright)",
                                textDecoration: "none",
                                background: "var(--purple-glow)",
                                border: "1px solid #7c3aed44",
                                borderRadius: 4,
                                padding: "2px 7px",
                              }}
                            >
                              {f.vulnerability.cve} ↗
                            </a>
                          )}
                          {f.vulnerability.cwe && (
                            <span style={{
                              fontSize: 11,
                              fontFamily: "var(--font-mono)",
                              color: "var(--text-muted)",
                              background: "var(--bg-hover)",
                              border: "1px solid var(--border)",
                              borderRadius: 4,
                              padding: "2px 7px",
                            }}>
                              {f.vulnerability.cwe}
                            </span>
                          )}
                        </div>
                      </div>

                      {/* Per-finding risk score */}
                      <div style={{ textAlign: "right", flexShrink: 0 }}>
                        <div style={{ fontSize: 18, fontWeight: 800, color: f.risk_score > 10 ? "#ef4444" : f.risk_score > 5 ? "#f97316" : "#eab308" }}>
                          {f.risk_score.toFixed(1)}
                        </div>
                        <div style={{ fontSize: 9, color: "var(--text-muted)", fontFamily: "var(--font-mono)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
                          risk
                        </div>
                      </div>
                    </div>

                    {/* CVSS + port row */}
                    <div style={{ display: "flex", gap: 16, marginBottom: f.vulnerability.description ? 10 : 0 }}>
                      {f.vulnerability.cvss_score > 0 && (
                        <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                          CVSS <span style={{ color: "var(--text-secondary)" }}>{f.vulnerability.cvss_score.toFixed(1)}</span>
                        </div>
                      )}
                      {f.port && f.port !== "0" && (
                        <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                          Port <span style={{ color: "var(--text-secondary)" }}>{f.port}</span>
                        </div>
                      )}
                      {f.vulnerability.patch_available && (
                        <div style={{ fontSize: 11, color: "#22c55e", fontFamily: "var(--font-mono)" }}>
                          Patch available
                        </div>
                      )}
                      {f.vulnerability.nvd_fetched && !f.vulnerability.patch_available && (
                        <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                          No patch
                        </div>
                      )}
                      {!f.vulnerability.nvd_fetched && f.vulnerability.cve && (
                        <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                          NVD pending...
                        </div>
                      )}
                    </div>

                    {/* NVD description */}
                    {f.vulnerability.description && (
                      <div style={{
                        fontSize: 11.5,
                        color: "var(--text-muted)",
                        lineHeight: 1.6,
                        fontFamily: "var(--font-mono)",
                        borderTop: "1px solid var(--border)",
                        paddingTop: 10,
                        marginTop: 4,
                      }}>
                        {f.vulnerability.description.length > 240
                          ? f.vulnerability.description.slice(0, 240) + "..."
                          : f.vulnerability.description}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      </div>
    </>
  );
}

// ── Main RiskDashboard component ──────────────────────────────────────────
export default function RiskDashboard({ refresh }) {
  const [summary, setSummary]           = useState(null);
  const [assets, setAssets]             = useState([]);
  const [selectedAsset, setSelectedAsset] = useState(null);
  const [loading, setLoading]           = useState(true);
  const [recalcing, setRecalcing]       = useState(false);

  const load = () => {
    setLoading(true);
    Promise.all([getRiskSummary(), getRankedAssets()])
      .then(([s, a]) => {
        setSummary(s);
        setAssets(Array.isArray(a) ? a : []);
      })
      .catch(() => { setSummary(null); setAssets([]); })
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, [refresh]);

  const maxRisk = assets.length > 0
    ? Math.max(...assets.map(a => a.risk_score))
    : 1;

  const handleRecalculate = async () => {
    setRecalcing(true);
    try {
      await forceRecalculate();
      toast.success("Risk scores recalculated");
      load();
    } catch {
      toast.error("Recalculation failed");
    } finally {
      setRecalcing(false);
    }
  };

  if (loading) return (
    <div className="loading-state">
      <div className="spinner" />
      <p>Loading risk data...</p>
    </div>
  );

  return (
    <>
      {/* Summary cards */}
      {summary && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 14, marginBottom: 24 }}>
          <div className="stat-card default">
            <span className="stat-label">Total Risk Score</span>
            <span className="stat-value">{summary.total_risk.toFixed(0)}</span>
          </div>
          <div className="stat-card default">
            <span className="stat-label">Avg Risk / Asset</span>
            <span className="stat-value" style={{ fontSize: 26 }}>{summary.avg_risk.toFixed(1)}</span>
          </div>
          <div className="stat-card low">
            <span className="stat-label">Patch Available</span>
            <span className="stat-value">{summary.patch_available}</span>
          </div>
          <div className="stat-card default">
            <span className="stat-label">NVD Enriched</span>
            <span className="stat-value" style={{ fontSize: 26 }}>{summary.nvd_enriched}</span>
          </div>
        </div>
      )}

      {/* Ranked assets table */}
      <div className="panel">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
          <p className="panel-title" style={{ marginBottom: 0 }}>
            Assets by Exposure — {assets.length} total
          </p>
          <button
            className="btn-secondary"
            style={{ fontSize: 12, padding: "7px 14px" }}
            onClick={handleRecalculate}
            disabled={recalcing}
          >
            {recalcing ? "Recalculating..." : "Recalculate Scores"}
          </button>
        </div>

        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Rank</th>
                <th>Hostname</th>
                <th>IP</th>
                <th>Criticality</th>
                <th>Findings</th>
                <th>Risk Score</th>
                <th>Exposure</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {assets.length === 0 ? (
                <tr className="empty-row">
                  <td colSpan={8}>No asset data available</td>
                </tr>
              ) : assets.map((a, i) => (
                <tr key={a.id}>
                  <td style={{ color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                    #{i + 1}
                  </td>
                  <td style={{ color: "var(--text-primary)", fontWeight: 600 }}>{a.hostname}</td>
                  <td>{a.ip}</td>
                  <td>
                    <span style={{
                      fontFamily: "var(--font-mono)",
                      color: a.criticality_score >= 3 ? "#ef4444" : a.criticality_score >= 2 ? "#f97316" : "var(--text-secondary)",
                    }}>
                      {a.criticality_score?.toFixed(1)}
                    </span>
                  </td>
                  <td>{a.finding_count}</td>
                  <td>
                    <span style={{
                      fontFamily: "var(--font-mono)",
                      fontWeight: 700,
                      color: a.risk_score > (maxRisk * 0.66)
                        ? "#ef4444"
                        : a.risk_score > (maxRisk * 0.33)
                        ? "#f97316"
                        : "#eab308",
                    }}>
                      {a.risk_score.toFixed(1)}
                    </span>
                  </td>
                  <td style={{ width: 120 }}>
                    <RiskBar score={a.risk_score} max={maxRisk} />
                  </td>
                  <td>
                    <button
                      onClick={() => setSelectedAsset(a)}
                      style={{
                        background: "var(--purple-glow)",
                        border: "1px solid #7c3aed44",
                        color: "var(--purple-bright)",
                        borderRadius: 6,
                        padding: "5px 12px",
                        fontSize: 11,
                        cursor: "pointer",
                        fontFamily: "var(--font-display)",
                        fontWeight: 600,
                        whiteSpace: "nowrap",
                      }}
                    >
                      View CVEs
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Asset detail drawer */}
      {selectedAsset && (
        <AssetDrawer
          asset={selectedAsset}
          onClose={() => setSelectedAsset(null)}
          onCriticalityChange={load}
        />
      )}
    </>
  );
}