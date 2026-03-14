import { useState, useRef } from "react";
import { uploadScan } from "../api/api";
import toast from "react-hot-toast";

export default function UploadScan({ onUpload }) {
  const [file, setFile]       = useState(null);
  const [drag, setDrag]       = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult]   = useState(null);
  const inputRef              = useRef();

  const validate = (f) => {
    if (!f?.name.endsWith(".csv")) { toast.error("Only .csv scan files are accepted"); return false; }
    return true;
  };

  const handleFileChange = (e) => {
    const f = e.target.files[0];
    if (f && validate(f)) { setFile(f); setResult(null); }
  };

  const handleDrop = (e) => {
    e.preventDefault(); setDrag(false);
    const f = e.dataTransfer.files[0];
    if (f && validate(f)) { setFile(f); setResult(null); }
  };

  const handleUpload = async () => {
    if (!file) { toast.error("Select a scan file first"); return; }
    try {
      setLoading(true);
      const tid = toast.loading("Processing scan...");
      const res = await uploadScan(file);
      toast.dismiss(tid);
      if (res.detail) { toast.error(res.detail); return; }
      toast.success("Scan ingested successfully");
      setResult(res);
      setFile(null);
      if (inputRef.current) inputRef.current.value = "";
      if (onUpload) onUpload();
    } catch (err) {
      toast.dismiss();
      toast.error("Upload failed");
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="panel">
      <p className="panel-title">Upload Scan</p>

      {/* Drop zone */}
      <div
        className={`upload-zone ${drag ? "drag-over" : ""}`}
        onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
        onDragLeave={() => setDrag(false)}
        onDrop={handleDrop}
        onClick={() => inputRef.current?.click()}
      >
        <div className="upload-zone-icon">⬆</div>
        <div className="upload-zone-title">
          {file ? file.name : "Drop Nessus CSV here"}
        </div>
        <div className="upload-zone-sub">
          {file ? "Ready to upload" : "or click to browse"}
        </div>
        <input
          ref={inputRef}
          type="file"
          accept=".csv"
          className="upload-file-input"
          onChange={handleFileChange}
        />
      </div>

      {/* Actions */}
      <div className="upload-actions" style={{ marginTop: 16 }}>
        {file && (
          <div className="file-pill">
            {file.name}
          </div>
        )}
        <button
          className="btn-primary"
          onClick={handleUpload}
          disabled={loading || !file}
        >
          {loading ? "Processing..." : "Upload Scan"}
        </button>
        {file && (
          <button
            className="btn-secondary"
            onClick={() => { setFile(null); setResult(null); if (inputRef.current) inputRef.current.value = ""; }}
          >
            Clear
          </button>
        )}
      </div>

      {/* Result */}
      {result && (
        <div className="scan-result">
          <div className="scan-result-item">
            <span className="scan-result-label">Assets Discovered</span>
            <span className="scan-result-value">{result.assets}</span>
          </div>
          <div className="scan-result-item">
            <span className="scan-result-label">Vulnerabilities</span>
            <span className="scan-result-value">{result.vulnerabilities}</span>
          </div>
          <div className="scan-result-item">
            <span className="scan-result-label">Findings Stored</span>
            <span className="scan-result-value">{result.findings}</span>
          </div>
        </div>
      )}
    </div>
  );
}