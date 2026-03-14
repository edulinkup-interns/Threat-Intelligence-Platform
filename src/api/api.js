const API = "http://127.0.0.1:8000";

// ✅ FIX: Was /api/assets — backend router prefix is now /assets
export async function getAssets() {
  const res = await fetch(`${API}/assets`);
  return res.json();
}

export async function getVulnerabilities() {
  const res = await fetch(`${API}/vulnerabilities`);
  return res.json();
}

export async function getFindings() {
  const res = await fetch(`${API}/findings`);
  return res.json();
}

export async function getScans() {
  const res = await fetch(`${API}/scans`);
  return res.json();
}

export async function uploadScan(file) {
  const formData = new FormData();
  formData.append("file", file);

  const res = await fetch(`${API}/scan/upload`, {
    method: "POST",
    body: formData
  });

  return res.json();
}