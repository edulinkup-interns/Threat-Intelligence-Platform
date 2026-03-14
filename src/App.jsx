import { useState, useEffect } from "react";
import UploadScan from "./components/UploadScan";
import AssetTable from "./components/AssetTable";
import VulnerabilityTable from "./components/VulnerabilityTable";
import FindingTable from "./components/FindingTable";
import DashboardStats from "./components/DashboardStats";
import SeverityChart from "./components/SeverityChart";
import ScanHistory from "./components/ScanHistory";
import { getScans } from "./api/api";

function App() {
  const [refresh, setRefresh]         = useState(false);
  const [hasData, setHasData]         = useState(false);
  const [activeTab, setActiveTab]     = useState("overview");
  const [checkingData, setCheckingData] = useState(true);

  useEffect(() => {
    getScans()
      .then(data => setHasData(Array.isArray(data) && data.length > 0))
      .catch(() => setHasData(false))
      .finally(() => setCheckingData(false));
  }, [refresh]);

  const reloadDashboard = () => setRefresh(prev => !prev);

  const tabs = [
    { id: "overview",        label: "Overview" },
    { id: "assets",          label: "Assets" },
    { id: "vulnerabilities", label: "Vulnerabilities" },
    { id: "findings",        label: "Findings" },
    { id: "history",         label: "Scan History" },
  ];

  return (
    <div className="app-shell">

      {/* Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-brand">
          <span className="brand-icon">◈</span>
          <span className="brand-name">VaultScan</span>
        </div>

        <nav className="sidebar-nav">
          <span className="nav-section-label">Navigation</span>
          {tabs.map(t => {
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
        </nav>

        <div className="sidebar-footer">
          <div className="status-indicator">
            <span className="status-dot" />
            <span>API Connected</span>
          </div>
        </div>
      </aside>

      {/* Main */}
      <main className="main-content">
        <header className="topbar">
          <div className="topbar-left">
            <h1 className="page-title">{tabs.find(t => t.id === activeTab)?.label}</h1>
            <span className="page-sub">Security Vulnerability Management</span>
          </div>
          <div className="topbar-right">
            <button className="upload-trigger-btn" onClick={() => setActiveTab("overview")}>
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

              {activeTab === "assets"          && <AssetTable refresh={refresh} />}
              {activeTab === "vulnerabilities" && <VulnerabilityTable refresh={refresh} />}
              {activeTab === "findings"        && <FindingTable refresh={refresh} />}
              {activeTab === "history"         && <ScanHistory refresh={refresh} />}
            </>
          )}
        </div>
      </main>
    </div>
  );
}

export default App;