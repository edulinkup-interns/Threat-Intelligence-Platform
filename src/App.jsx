import { useState, useEffect } from "react";
import UploadScan from "./components/UploadScan";
import AssetTable from "./components/AssetTable";
import VulnerabilityTable from "./components/VulnerabilityTable";
import FindingTable from "./components/FindingTable";
import DashboardStats from "./components/DashboardStats";
import SeverityChart from "./components/SeverityChart";
import ScanHistory from "./components/ScanHistory";
import RiskDashboard from "./components/RiskDashboard";
import { getScans, downloadReport } from "./api/api";
import toast from "react-hot-toast";

function App() {
  const [refresh, setRefresh]             = useState(false);
  const [hasData, setHasData]             = useState(false);
  const [activeTab, setActiveTab]         = useState("overview");
  const [checkingData, setCheckingData]   = useState(true);
  const [generatingPDF, setGeneratingPDF] = useState(false);

  useEffect(() => {
    getScans()
      .then(data => setHasData(Array.isArray(data) && data.length > 0))
      .catch(() => setHasData(false))
      .finally(() => setCheckingData(false));
  }, [refresh]);

  const reloadDashboard = () => setRefresh(prev => !prev);

  const handleDownloadReport = async () => {
    setGeneratingPDF(true);
    const tid = toast.loading("Generating PDF report...");
    try {
      await downloadReport();
      toast.dismiss(tid);
      toast.success("Report downloaded successfully");
    } catch (err) {
      toast.dismiss(tid);
      toast.error("Failed to generate report");
      console.error(err);
    } finally {
      setGeneratingPDF(false);
    }
  };

  const tabs = [
    { id: "overview",        label: "Overview",        group: "Dashboard" },
    { id: "risk",            label: "Risk & CVEs",     group: "Dashboard" },
    { id: "assets",          label: "Assets",          group: "Data"      },
    { id: "vulnerabilities", label: "Vulnerabilities", group: "Data"      },
    { id: "findings",        label: "Findings",        group: "Data"      },
    { id: "history",         label: "Scan History",    group: "Data"      },
  ];

  const groups = ["Dashboard", "Data"];

  return (
    <div className="app-shell">

      {/* ── Sidebar ── */}
      <aside className="sidebar">
        <div className="sidebar-brand">
          <span className="brand-name">Compliance Capstone Project</span>
        </div>

        <nav className="sidebar-nav">
          {groups.map(group => (
            <div key={group}>
              <span className="nav-section-label">{group}</span>
              {tabs
                .filter(t => t.group === group)
                .map(t => {
                  const locked = !hasData && t.id !== "overview";
                  return (
                    <button
                      key={t.id}
                      className={`nav-item ${activeTab === t.id ? "active" : ""} ${locked ? "disabled" : ""}`}
                      onClick={() => !locked && setActiveTab(t.id)}
                    >
                      <span className="nav-dot" />
                      {t.label}
                    </button>
                  );
                })}
            </div>
          ))}
        </nav>

     <div className="sidebar-footer">
  <div className="status-indicator">
    <span className="status-dot" />
    <span>API Connected</span>
  </div>
  <div style={{
    marginTop: 10,
    fontSize: 11,
    color: "var(--text-muted)",
    fontFamily: "var(--font-mono)",
  }}>
    Made by Eishit Balyan
  </div>
</div>
      </aside>

      {/* ── Main ── */}
      <main className="main-content">
        <header className="topbar">
          <div className="topbar-left">
            <h1 className="page-title">
              {tabs.find(t => t.id === activeTab)?.label}
            </h1>
            <span className="page-sub">Security Vulnerability Management</span>
          </div>
          <div className="topbar-right" style={{ display: "flex", gap: 10 }}>

            {/* Generate Report button — only shown when data exists */}
            {hasData && (
              <button
                className="btn-secondary"
                onClick={handleDownloadReport}
                disabled={generatingPDF}
                style={{ fontSize: 13, padding: "9px 16px" }}
              >
                {generatingPDF ? "Generating..." : "Export PDF Report"}
              </button>
            )}

            <button
              className="upload-trigger-btn"
              onClick={() => setActiveTab("overview")}
            >
              + Upload Scan
            </button>
          </div>
        </header>

        <div className="content-area">
          {checkingData ? (
            <div className="loading-state">
              <div className="spinner" />
              <p>Initializing...</p>
            </div>
          ) : (
            <>
              {activeTab === "overview" && (
                <>
                  <UploadScan onUpload={reloadDashboard} />
                  {hasData ? (
                    <div className="fade-in">
                      <DashboardStats refresh={refresh} />
                      <SeverityChart refresh={refresh} />
                    </div>
                  ) : (
                    <div className="empty-state">
                      <div className="empty-icon">◈</div>
                      <h2>No scan data yet</h2>
                      <p>Upload a Nessus CSV file above to populate your dashboard.</p>
                    </div>
                  )}
                </>
              )}

              {activeTab === "risk"            && hasData && <RiskDashboard refresh={refresh} />}
              {activeTab === "assets"          && hasData && <AssetTable refresh={refresh} />}
              {activeTab === "vulnerabilities" && hasData && <VulnerabilityTable refresh={refresh} />}
              {activeTab === "findings"        && hasData && <FindingTable refresh={refresh} />}
              {activeTab === "history"         && hasData && <ScanHistory refresh={refresh} />}
            </>
          )}
        </div>
      </main>
    </div>
  );
}

export default App;