
const API = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";

async function apiFetch(path, options = {}) {
  const res = await fetch(`${API}${path}`, options);
  if (!res.ok) {
    const detail = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(detail.detail || res.statusText);
  }
  return res.json();
}

//  Core endpoints

export async function getAssets() {
  return apiFetch("/assets");
}

export async function getVulnerabilities() {
  return apiFetch("/vulnerabilities");
}

export async function getFindings() {
  return apiFetch("/findings");
}

export async function getScans() {
  return apiFetch("/scans");
}

export async function uploadScan(file) {
  const formData = new FormData();
  formData.append("file", file);
  return apiFetch("/scan/upload", { method: "POST", body: formData });
}

// ── Risk & CVE endpoints 

export async function getRiskSummary() {
  return apiFetch("/risk/summary");
}

export async function getRankedAssets() {
  return apiFetch("/risk/assets");
}

export async function getAssetRiskDetail(assetId) {
  return apiFetch(`/risk/assets/${assetId}`);
}

export async function updateCriticality(assetId, value) {
  return apiFetch(`/risk/assets/${assetId}/criticality?criticality=${value}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
  });
}

export async function forceRecalculate() {
  return apiFetch("/risk/recalculate", { method: "POST" });
}

// Report 

export async function downloadReport() {
  const res = await fetch(`${API}/report/pdf`);
  if (!res.ok) throw new Error("Report generation failed");

  const blob = await res.blob();
  const disposition = res.headers.get("Content-Disposition") || "";
  const match = disposition.match(/filename=(.+)/);
  const filename = match ? match[1] : "security_report.pdf";

  const url = URL.createObjectURL(blob);
  const a   = document.createElement("a");
  a.href     = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
