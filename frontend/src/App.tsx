import { useState } from "react";
import './styles/tailwind.css';

function App() {
  const [formData, setFormData] = useState({
    requestor: "",
    department: "",
    exceptionType: "",
    reason: "",
    startDate: "",
    hostnames: "",
    unitHead: "",
    riskAssessment: "",
    impactedSystems: "",
    dataLevelStored: "",
    dataAccessLevel: "",
    vulnScanner: "",
    edrAllowed: "",
    managementAccess: "",
    publicIP: "",
    osUpToDate: "",
    osPatchFrequency: "",
    appPatchFrequency: "",
    localFirewall: "",
    networkFirewall: "",
    dependencyLevel: "",
    userImpact: "",
    universityImpact: "",
    mitigation: "",
  });

  const [response, setResponse] = useState("");

  const handleChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>
  ) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetch("http://localhost:8000/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formData),
      });
      const data = await res.json();
      setResponse(data.reply || "No response from backend");
    } catch {
      setResponse("Error: Could not reach backend");
    }
  };

  return (
    <div className="page">
      {/* ===== HEADER ===== */}
      <header className="header">
        <div className="header-top">
          <img src="/ud-logo.png" alt="University of Delaware" className="h-16 w-auto" />
        </div>
        <nav className="header-nav">
          <a href="#" className="header-link">Service Portal Home</a>
          <a href="#" className="header-link">Services</a>
          <a href="#" className="header-link">Knowledge Base</a>
        </nav>
      </header>

      {/* ===== MAIN ===== */}
      <main className="flex-grow">
        <div className="container">
          <nav className="breadcrumb">
            <a href="#" className="hover:underline">Service Catalog</a> /{" "}
            <a href="#" className="hover:underline">Security</a> /{" "}
            <a href="#" className="hover:underline">Security Policy Exception Request</a> /{" "}
            <span className="text-gray-700">Request Security Exception</span>
          </nav>

          <h2 className="text-2xl font-bold text-gray-800 mb-2">Request Security Exception</h2>
          <p className="text-gray-600 mb-6">All fields marked with an asterisk (*) are required.</p>

          <form onSubmit={handleSubmit} className="space-y-6">
            {/* ===== BASIC INFO ===== */}
            <div>
              <label className="label">
                Requestor <span className="text-red-500">*</span>
              </label>
              <input name="requestor" value={formData.requestor} onChange={handleChange} className="input" />
            </div>

            <div>
              <label className="label">
                Department <span className="text-red-500">*</span>
              </label>
              <input name="department" value={formData.department} onChange={handleChange} className="input" />
            </div>

            <div>
              <label className="label">
                Type of Exception <span className="text-red-500">*</span>
              </label>
              <select name="exceptionType" value={formData.exceptionType} onChange={handleChange} className="input">
                <option value="">Select an option...</option>
                <option value="Firewall">Firewall</option>
                <option value="Identity">Identity</option>
                <option value="Vulnerability">Vulnerability</option>
                <option value="Other">Other</option>
              </select>
            </div>

            <div>
              <label className="label">
                Reason for Request <span className="text-red-500">*</span>
              </label>
              <textarea name="reason" value={formData.reason} onChange={handleChange} className="textarea h-36" />
            </div>

            <div>
              <label className="label">
                Exception Start Date <span className="text-red-500">*</span>
              </label>
              <input type="date" name="startDate" value={formData.startDate} onChange={handleChange} className="input" />
              <p className="text-xs text-gray-500 mt-1">
                NOTE: Exception End Date will automatically be calculated to 3 months after the Exception Start Date unless otherwise specified.
              </p>
            </div>

            <div>
              <label className="label">
                Hostnames <span className="text-red-500">*</span>
              </label>
              <textarea
                name="hostnames"
                value={formData.hostnames}
                onChange={handleChange}
                placeholder="example1.server.udel.edu&#10;example2.udel.edu"
                className="textarea h-28 italic text-gray-700"
              />
            </div>

            <div>
              <label className="label">
                Unit Head <span className="text-red-500">*</span>
              </label>
              <input name="unitHead" value={formData.unitHead} onChange={handleChange} className="input" />
            </div>

            <div>
              <label className="label">
                Risk Assessment Justification <span className="text-red-500">*</span>
              </label>
              <textarea name="riskAssessment" value={formData.riskAssessment} onChange={handleChange} className="textarea h-28" />
            </div>

            {/* ===== DATA LEVELS ===== */}
            <div className="definition-section">
              <h3 className="section-title">Data Levels</h3>
              <table className="ud-table">
                <tbody>
                  {[
                    ["Level 1", "Unintentional, unlawful, or unauthorized disclosure presents limited or no risk.May be shared publicly", "#008000", "#FFFFFF"],
                    ["Level 2", "Unintentional, unlawful, or unauthorized disclosure presents moderate risk. Share only with those who 'need to know'", "#FFD700", "#000000"],
                    ["Level 3", "Unintentional, unlawful, or unauthorized disclosure presents significant risk. Encrypt at rest and in transit. Access, process, store, and transmit only using managed computers. Do not use cloud services unless approved.", "#FF0000", "#FFFFFF"],
                  ].map(([label, desc, bg, color]) => (
                    <tr key={label}>
                      <td className="ud-cell-colored" style={{ backgroundColor: bg, color }}>
                        <strong>{label}</strong>
                      </td>
                      <td className="ud-cell-desc">{desc}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* ===== DATA-RELATED QUESTIONS ===== */}
            <div className="pt-4 space-y-4">
              <div>
                <label className="label">Level of Data Stored on System *</label>
                <select name="dataLevelStored" onChange={handleChange} className="input">
                  <option value="">Select...</option>
                  <option value="Level I">Level I - Low impact</option>
                  <option value="Level II">Level II - Moderate impact</option>
                  <option value="Level III">Level III - High impact</option>
                </select>
              </div>

              <div>
                <label className="label">Level of Data the Device has Access to *</label>
                <select name="dataAccessLevel" onChange={handleChange} className="input">
                  <option value="">Select...</option>
                  <option value="Level I">Level I - Low impact</option>
                  <option value="Level II">Level II - Moderate impact</option>
                  <option value="Level III">Level III - High impact</option>
                </select>
              </div>

              <div>
                <label className="label">
                  Allow Vulnerability Scanning Agent on Client? <span className="text-red-500">*</span>
                </label>
                <select
                  name="vulnScanner"
                  value={formData.vulnScanner}
                  onChange={handleChange}
                  className="input"
                >
                  <option value="">Select...</option>
                  <option value="Yes">Yes</option>
                  <option value="No">No</option>
                </select>
              </div>

              <div>
                <label className="label">
                  Allow EDR (Crowdstrike on Client)? <span className="text-red-500">*</span>
                </label>
                <select
                  name="edrAllowed"
                  value={formData.edrAllowed}
                  onChange={handleChange}
                  className="input"
                >
                  <option value="">Select...</option>
                  <option value="Yes">Yes</option>
                  <option value="No">No</option>
                </select>
              </div>



            {/* ===== FIREWALL DEFINITIONS ===== */}
            <div className="definition-section">
              <h3 className="section-title">Firewall Coverage definitions</h3>
              <table className="ud-table">
                <tbody>
                  {[
                    ["High Coverage", "Majority of traffic blocked with some exceptions.", "#008000", "#FFFFFF"],
                    ["Moderate Coverage", "Access is locked down to portions of campus.", "#FFD700", "#000000"],
                    ["Minimal Coverage", "Access is granted to most/all of campus.", "#FFA500", "#FFFFFF"],
                    ["No Coverage", "", "#FF0000", "#FFFFFF"],
                  ].map(([label, desc, bg, color]) => (
                    <tr key={label}>
                      <td className="ud-cell-colored" style={{ backgroundColor: bg, color }}>
                        <strong>{label}</strong>
                      </td>
                      <td className="ud-cell-desc">{desc}</td>
                    </tr>
                  ))}
                </tbody>
              </table>

              <div className="pt-4 space-y-4">
                <div>
                  <label className="label">Local Firewall Rules *</label>
                  <select name="localFirewall" onChange={handleChange} className="input">
                    <option value="">Select...</option>
                    <option value="High Coverage">High Coverage</option>
                    <option value="Moderate Coverage">Moderate Coverage</option>
                    <option value="Minimal Coverage">Minimal Coverage</option>
                    <option value="No Coverage">No Coverage</option>
                  </select>
                </div>

                <div>
                  <label className="label">Network Firewall Rules *</label>
                  <select name="networkFirewall" onChange={handleChange} className="input">
                    <option value="">Select...</option>
                    <option value="High Coverage">High Coverage</option>
                    <option value="Moderate Coverage">Moderate Coverage</option>
                    <option value="Minimal Coverage">Minimal Coverage</option>
                    <option value="No Coverage">No Coverage</option>
                  </select>
                </div>
              </div>
            </div>

              <div>
                <label className="label">Does system have access to management network? *</label>
                <select name="managementAccess" onChange={handleChange} className="input">
                  <option value="">Select...</option>
                  <option value="Yes">Yes</option>
                  <option value="No">No</option>
                </select>
              </div>

              <div>
                <label className="label">Does this machine have a public IP address? *</label>
                <select name="publicIP" onChange={handleChange} className="input">
                  <option value="">Select...</option>
                  <option value="Yes">Yes</option>
                  <option value="No">No</option>
                </select>
              </div>

              <div>
                <label className="label">Is the OS up to date with the latest patch? *</label>
                <select name="osUpToDate" onChange={handleChange} className="input">
                  <option value="">Select...</option>
                  <option value="Yes">Yes</option>
                  <option value="No">No</option>
                </select>
              </div>

              <div>
                <label className="label">How often are OS patches installed? *</label>
                <select name="osPatchFrequency" onChange={handleChange} className="input">
                  <option value="">Select...</option>
                  <option value="Monthly">Monthly</option>
                  <option value="Quarterly">Quarterly</option>
                  <option value="Every 3-6 months">Every 3–6 months</option>
                  <option value="Every 6-12 months">Every 6–12 months</option>
                  <option value="Yearly">Yearly +</option>
                  <option value="Unavailable">Patches Unavailable</option>
                </select>
              </div>

              <div>
                <label className="label">How often are application patches installed? *</label>
                <select name="appPatchFrequency" onChange={handleChange} className="input">
                  <option value="">Select...</option>
                  <option value="Monthly">Monthly</option>
                  <option value="Quarterly">Quarterly</option>
                  <option value="Every 3-6 months">Every 3–6 months</option>
                  <option value="Every 6-12 months">Every 6–12 months</option>
                  <option value="Yearly">Yearly +</option>
                  <option value="Unavailable">Patches Unavailable</option>
                </select>
              </div>
            </div>

            {/* ===== DEPENDENCY ===== */}
            <div className="definition-section">
              <h3 className="section-title">Server/asset dependency definitions</h3>
              <table className="ud-table">
                <tbody>
                  {[
                    ["Low", "Limited to no dependent assets/services.", "#008000", "#FFFFFF"],
                    ["Moderate", "Some dependent assets/services.", "#FFD700", "#000000"],
                    ["Extensive", "Pervasive dependent assets.", "#FF0000", "#FFFFFF"],
                  ].map(([label, desc, bg, color]) => (
                    <tr key={label}>
                      <td className="ud-cell-colored" style={{ backgroundColor: bg, color }}>
                        <strong>{label}</strong>
                      </td>
                      <td className="ud-cell-desc">{desc}</td>
                    </tr>
                  ))}
                </tbody>
              </table>

              <div className="pt-4">
                <label className="label">How many assets or servers depend on this asset? *</label>
                <select name="dependencyLevel" onChange={handleChange} className="input">
                  <option value="">Select...</option>
                  <option value="Low">Low</option>
                  <option value="Moderate">Moderate</option>
                  <option value="Extensive">Extensive</option>
                </select>
              </div>
            </div>

            {/* ===== USER IMPACT ===== */}
            <div className="definition-section">
              <h3 className="section-title">User impact definitions</h3>
              <table className="ud-table">
                <tbody>
                  {[
                    ["Low", "One unit or less than 10 individuals.", "#008000", "#FFFFFF"],
                    ["Moderate", "Small groups or 10-250 individuals (eg., students in a specific course)", "#FFD700", "#000000"],
                    ["Extensive", "A large group (e.g., all sophomores).", "#FFA500", "#FFFFFF"],
                    ["Widespread", "Multiple large groups or institution-wide (eg., all students and faculty)", "#FF0000", "#FFFFFF"],
                  ].map(([label, desc, bg, color]) => (
                    <tr key={label}>
                      <td className="ud-cell-colored" style={{ backgroundColor: bg, color }}>
                        <strong>{label}</strong>
                      </td>
                      <td className="ud-cell-desc">{desc}</td>
                    </tr>
                  ))}
                </tbody>
              </table>

              <div className="pt-4">
                <label className="label">How many users are impacted by this asset? *</label>
                <select name="userImpact" onChange={handleChange} className="input">
                  <option value="">Select...</option>
                  <option value="Low">Low</option>
                  <option value="Moderate">Moderate</option>
                  <option value="Extensive">Extensive</option>
                  <option value="Widespread">Widespread</option>
                </select>
              </div>
            </div>

            {/* ===== UNIVERSITY IMPACT ===== */}
            <div className="definition-section">
              <h3 className="section-title">University impact definitions</h3>
              <table className="ud-table">
                <tbody>
                  {[
                    ["Non-Critical", "Loss of integrity or availability would only have little to no short-term impact on business continuity or operational effectiveness. Some services or functions may be slightly delayed or degraded if non-critical data loses integrity or availability.", "#008000", "#FFFFFF"],
                    ["Critical", "Loss of integrity or availability would have moderate short-term impact on business continuity or operational effectiveness. Key services or functions may be noticeably and disruptively delayed or degraded if critical data loses integrity or availability.", "#FFD700", "#000000"],
                    ["Mission Critical", "Loss of integrity or availability would have significant short-term impact and possible long-term impact on business continuity or operational effectiveness. Key services or functions may be severely delayed or degraded, or may become impossible to deliver. Prolonged loss of mission critical data may threaten the University's ability to recover.", "#FF0000", "#FFFFFF"],
                  ].map(([label, desc, bg, color]) => (
                    <tr key={label}>
                      <td className="ud-cell-colored" style={{ backgroundColor: bg, color }}>
                        <strong>{label}</strong>
                      </td>
                      <td className="ud-cell-desc">{desc}</td>
                    </tr>
                  ))}
                </tbody>
              </table>

              <div className="pt-4">
                <label className="label">How important is this asset to the University as a whole? *</label>
                <select name="universityImpact" onChange={handleChange} className="input">
                  <option value="">Select...</option>
                  <option value="Non-Critical">Non-Critical</option>
                  <option value="Critical">Critical</option>
                  <option value="Mission Critical">Mission Critical</option>
                </select>
              </div>
            </div>

            {/* ===== FINAL SECTION ===== */}
            <div className="pt-6">
              <label className="label">
                Impacted Systems, Services and Data <span className="text-red-500">*</span>
              </label>
              <textarea
                name="impactedSystems"
                value={formData.impactedSystems}
                onChange={handleChange}
                className="textarea h-24"
              />

              {/* ===== ADDITIONAL MITIGATION CONTROLS ===== */}
              <div className="pt-6">
                <label className="label font-semibold">
                  Please describe any other mitigation tools or techniques you are using to secure the system that aren't listed above{" "}
                  <span className="text-red-500">*</span>
                </label>
                <textarea
                  name="mitigation"
                  value={formData.mitigation}
                  onChange={handleChange}
                  className="textarea h-32"
                />
              </div>

              <p className="text-xs text-gray-500 mt-2">
                IT Information Security will determine the end date of the exception (valid up to one year after approval).
              </p>
            </div>

            <button
              type="submit"
              className="bg-blue-700 text-white px-6 py-2 rounded-md hover:bg-blue-800 transition font-medium"
            >
              Submit
            </button>
          </form>

          {response && (
            <div className="mt-10 border-t pt-6">
              <h3 className="text-xl font-semibold text-[var(--ud-blue)] mb-2">
                AI Evaluation
              </h3>
              <div className="bg-gray-50 border border-gray-200 rounded-md p-4">
                <p className="text-gray-800 whitespace-pre-wrap">{response}</p>
              </div>
            </div>
          )}
        </div>
      </main>

      {/* ===== FOOTER ===== */}
      <footer className="footer">
        <img src="/ud-logo.png" alt="UD Circular Logo" className="h-12 w-auto mx-auto mb-2" />
        <p>© {new Date().getFullYear()} University of Delaware</p>
        <p className="text-xs text-gray-500 mt-1">
          IT Security · Policy Exemption Analyzer
        </p>
      </footer>
    </div>
  );
}

export default App;
