import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, AlertOctagon, Activity, Server, 
  Terminal, Globe, Lock, Layers, Eye, X, Zap, ShieldAlert, Cpu 
} from 'lucide-react';

function App() {
  // Application state management for dashboard data and UI states
  const [telemetry, setTelemetry] = useState([]);
  const [incidents, setIncidents] = useState([]); 
  const [systemStatus, setSystemStatus] = useState('ACTIVE');
  const [metrics, setMetrics] = useState({ totalScanned: 0, activeThreats: 0 });
  const [selectedIncidentModal, setSelectedIncidentModal] = useState(null);
  const [loadingDemo, setLoadingDemo] = useState(false);
  const [history, setHistory] = useState([]);

  // Fetch the historical incident database from the backend API
  const fetchHistory = () => {
    fetch('http://localhost:8000/api/history')
      .then(res => res.json())
      .then(data => {
        if (data.status === 'success') {
          setHistory(data.data);
        }
      })
      .catch(err => console.error("Error fetching history:", err));
  };

  // Initial data load on component mount
  useEffect(() => {
    fetchHistory();
  }, []);

  // Establish and manage the WebSocket connection for real-time network traffic
  useEffect(() => {
    const ws = new WebSocket('ws://127.0.0.1:8000/ws/traffic');    
    
    ws.onopen = () => setSystemStatus('ACTIVE');
    
    ws.onmessage = (event) => {
      const packet = JSON.parse(event.data);
      
      // Update telemetry stream, keeping only the most recent 25 packets
      setTelemetry((prev) => [packet, ...prev].slice(0, 25));
      
      // Update running metrics for scanned packets and identified threats
      setMetrics((prev) => ({
        totalScanned: prev.totalScanned + 1,
        activeThreats: packet.prediction === 'Suspicious' ? prev.activeThreats + 1 : prev.activeThreats
      }));

      // Handle detected threats
      if (packet.prediction === 'Suspicious') {
        // Keep the most recent 15 suspicious incidents
        setIncidents((prev) => [packet, ...prev].slice(0, 15));
        // Immediately refresh the historical data table upon detecting a new threat
        fetchHistory(); 
      }
    };

    ws.onclose = () => setSystemStatus('DISCONNECTED');
    
    // Cleanup WebSocket connection on component unmount
    return () => ws.close();
  }, []);

  // Calculate the true anomaly percentage based on active threats versus total scanned packets
  const anomalyRate = metrics.totalScanned > 0 
    ? ((metrics.activeThreats / metrics.totalScanned) * 100).toFixed(1) 
    : '0.0';

  // Trigger a simulated network attack via the backend API
  const triggerDemoAttack = async () => {
    setLoadingDemo(true);
    try {
      const response = await fetch('http://localhost:8000/alerts/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          source_ip: "0.0.0.0", 
          destination_ip: "10.0.0.15", 
          port: 999, 
          features: Array(78).fill(0.0) 
        })
      });
      
      const data = await response.json();
      const alertData = data.alert_data;
      
      // Construct a standardized packet object from the mock API response
      const demoPkt = {
        id: Math.floor(Math.random() * 100000),
        time: new Date().toLocaleTimeString(),
        source_ip: alertData.source_ip,
        destination_ip: alertData.destination_ip,
        port: alertData.port,
        protocol: alertData.protocol,
        length: alertData.length,
        prediction: "Suspicious",
        risk_level: alertData.risk_level,
        confidence: alertData.risk_score,
        attack_type: alertData.attack_type,
        gemini_reason: alertData.llm_incident_report
      };

      // Inject the simulated packet into the active dashboard state
      setTelemetry((prev) => [demoPkt, ...prev]);
      setIncidents((prev) => [demoPkt, ...prev]);
      setMetrics((prev) => ({ 
        totalScanned: prev.totalScanned + 1, 
        activeThreats: prev.activeThreats + 1 
      }));
    } catch (e) {
      console.error(e);
    } finally {
      setLoadingDemo(false);
    }
  };

  // Automatically refresh the incident history table on every render cycle
  fetchHistory(); 

  return (
    <div className="min-h-screen bg-[#07090e] text-slate-200 font-sans antialiased selection:bg-indigo-500 selection:text-white relative">
      
      {/* PROFESSIONAL SOC HEADER */}
      <header className="border-b border-slate-800/80 bg-[#0b0f19]/90 backdrop-blur-md sticky top-0 z-40 px-6 py-3.5 flex justify-between items-center">
        <div className="flex items-center gap-3">
          <div className="bg-indigo-600/20 border border-indigo-500/30 p-2 rounded-lg">
            <ShieldCheck className="text-indigo-400 h-5 w-5" />
          </div>
          <div>
            <h1 className="font-bold tracking-wider text-sm text-white font-mono">SENTINEL-IDS // SECURITY OPERATIONS CENTER</h1>
            <p className="text-[11px] text-slate-400 font-mono">Real-Time Network Telemetry & AI Incident Analysis</p>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <button 
            onClick={triggerDemoAttack}
            disabled={loadingDemo}
            className="bg-rose-600 hover:bg-rose-500 text-white text-xs font-mono font-bold px-3.5 py-2 rounded-lg shadow-lg shadow-rose-900/20 flex items-center gap-2 transition-all border border-rose-500/30"
          >
            <Zap size={14} />
            {loadingDemo ? 'Simulating...' : 'Simulate Attack Vector'}
          </button>

          <div className="flex items-center gap-2 bg-slate-900/90 border border-slate-800 px-3 py-1.5 rounded-full text-xs font-mono">
            <span className={`w-2 h-2 rounded-full ${systemStatus === 'ACTIVE' ? 'bg-emerald-500 animate-pulse' : 'bg-rose-500'}`}></span>
            <span className="text-slate-300">ENGINE: {systemStatus}</span>
          </div>
        </div>
      </header>

      {/* MAIN DASHBOARD */}
      <main className="p-6 max-w-[1600px] mx-auto space-y-6">

        {/* PRACTICAL SOC METRICS */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="bg-[#0b0f19] border border-slate-800/80 rounded-xl p-4">
            <p className="text-xs font-mono text-slate-400 uppercase tracking-wider">Total Packets Processed</p>
            <h3 className="text-2xl font-bold font-mono text-white mt-1">{metrics.totalScanned.toLocaleString()}</h3>
            <div className="mt-2 text-[11px] text-slate-500 font-mono">Active NIC Socket Listener</div>
          </div>

          <div className="bg-[#0b0f19] border border-slate-800/80 rounded-xl p-4">
            <p className="text-xs font-mono text-slate-400 uppercase tracking-wider">Threats Flagged</p>
            <h3 className="text-2xl font-bold font-mono text-rose-400 mt-1">{metrics.activeThreats}</h3>
            <div className="mt-2 text-[11px] text-rose-400 font-mono">Random Forest Classifier</div>
          </div>

          <div className="bg-[#0b0f19] border border-slate-800/80 rounded-xl p-4">
            <p className="text-xs font-mono text-slate-400 uppercase tracking-wider">Anomaly Ratio</p>
            <h3 className="text-2xl font-bold font-mono text-amber-400 mt-1">{anomalyRate}%</h3>
            <div className="mt-2 text-[11px] text-slate-500 font-mono">Suspicious vs Total Traffic</div>
          </div>

          <div className="bg-[#0b0f19] border border-slate-800/80 rounded-xl p-4">
            <p className="text-xs font-mono text-slate-400 uppercase tracking-wider">Inference Latency</p>
            <h3 className="text-2xl font-bold font-mono text-emerald-400 mt-1">~4.2 ms</h3>
            <div className="mt-2 text-[11px] text-emerald-400 font-mono">Real-time Feature Pipeline</div>
          </div>
        </div>

        {/* 2-COLUMN LAYOUT */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          
          {/* LIVE TELEMETRY STREAM */}
          <div className="lg:col-span-2 bg-[#0b0f19] border border-slate-800/80 rounded-xl p-5 flex flex-col h-[550px]">
            <div className="flex justify-between items-center pb-4 border-b border-slate-800/80 mb-4">
              <div className="flex items-center gap-2">
                <Globe size={16} className="text-indigo-400" />
                <h2 className="text-sm font-bold uppercase tracking-wider text-slate-200 font-mono">Live Network Telemetry Stream</h2>
              </div>
              <span className="text-[11px] font-mono text-slate-400 bg-slate-900 border border-slate-800 px-2.5 py-1 rounded">Passive Tap</span>
            </div>

            <div className="grid grid-cols-5 text-[11px] font-mono text-slate-400 uppercase tracking-wider pb-2 border-b border-slate-800/40 px-2">
              <div>Timestamp</div>
              <div>Source IP</div>
              <div>Destination</div>
              <div>Port / Proto</div>
              <div>Status</div>
            </div>

            <div className="flex-1 overflow-y-auto space-y-1.5 mt-2 pr-1 font-mono text-xs">
              {telemetry.length === 0 ? (
                <div className="h-full flex items-center justify-center text-slate-600 font-mono text-xs">Listening for network packets...</div>
              ) : (
                telemetry.map((pkt, i) => (
                  <div key={i} className="grid grid-cols-5 gap-2 p-2.5 rounded bg-[#0e1422]/60 border border-slate-800/40 items-center">
                    <span className="text-slate-400 text-[11px]">{pkt.time}</span>
                    <span className="text-indigo-300 font-mono truncate">{pkt.source_ip}</span>
                    <span className="text-purple-300 font-mono truncate">{pkt.destination_ip}</span>
                    <span className="text-slate-300">{pkt.port} <span className="text-[10px] text-slate-500">({pkt.protocol})</span></span>
                    <span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${pkt.prediction === 'Suspicious' ? 'bg-rose-500/10 text-rose-400 border border-rose-500/30' : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'}`}>
                        {pkt.prediction}
                      </span>
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* SUSPICIOUS INCIDENTS FEED */}
          <div className="bg-[#0b0f19] border border-slate-800/80 rounded-xl p-5 flex flex-col h-[550px]">
            <div className="flex justify-between items-center pb-4 border-b border-slate-800/80 mb-4">
              <div className="flex items-center gap-2">
                <ShieldAlert size={16} className="text-rose-400" />
                <h2 className="text-sm font-bold uppercase tracking-wider text-slate-200 font-mono">Suspicious Incidents Feed</h2>
              </div>
              <span className="text-[10px] font-mono bg-rose-500/10 text-rose-400 border border-rose-500/20 px-2 py-0.5 rounded">
                {incidents.length} Events
              </span>
            </div>

            <div className="flex-1 overflow-y-auto space-y-2 pr-1 font-mono text-xs">
              {incidents.length === 0 ? (
                <div className="h-full flex flex-col items-center justify-center text-center text-slate-600 text-xs">
                  <ShieldAlert size={32} className="mb-2 opacity-30" />
                  <p>No anomalies logged. Perimeter secure.</p>
                </div>
              ) : (
                incidents.map((inc, i) => (
                  <div 
                    key={i}
                    onClick={() => setSelectedIncidentModal(inc)}
                    className="p-3 rounded-lg border bg-[#07090e] border-slate-800 hover:border-rose-500/50 hover:bg-rose-950/10 cursor-pointer transition-all group"
                  >
                    <div className="flex justify-between items-center mb-1">
                      <span className="text-rose-400 font-bold text-xs truncate">
                        {inc.attack_type || 'Network Intrusion'}
                      </span>
                      <span className="text-[10px] text-slate-500">{inc.time}</span>
                    </div>
                    <div className="text-[11px] text-slate-400 flex justify-between items-center">
                      <span>Source: {inc.source_ip}</span>
                      <span className="text-indigo-400 opacity-0 group-hover:opacity-100 transition-opacity text-[10px] flex items-center gap-1">
                        <Eye size={12} /> View Report
                      </span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

        </div>

        {/* PROFESSIONAL INCIDENT HISTORY SECTION */}
        <div className="bg-[#0b0f19] border border-slate-800/80 rounded-xl p-5 mt-6 flex flex-col">
          <div className="flex justify-between items-center pb-4 border-b border-slate-800/80 mb-4">
            <div className="flex items-center gap-2">
              <Layers size={16} className="text-indigo-400" />
              <h2 className="text-sm font-bold uppercase tracking-wider text-slate-200 font-mono">Incident History Database</h2>
            </div>
            <div className="flex gap-2">
              <a href="http://localhost:8000/api/export-db" download className="bg-emerald-600/20 hover:bg-emerald-500/30 text-emerald-400 border border-emerald-500/30 px-3 py-1.5 rounded text-xs font-mono transition-colors flex items-center gap-1 cursor-pointer no-underline">
                💾 Export .db
              </a>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead>
                <tr className="text-slate-400 border-b border-slate-800/80">
                  <th className="pb-3 px-4 font-normal tracking-wider uppercase">Timestamp</th>
                  <th className="pb-3 px-4 font-normal tracking-wider uppercase">Attacker IP</th>
                  <th className="pb-3 px-4 font-normal tracking-wider uppercase">Risk Level</th>
                  <th className="pb-3 px-4 font-normal tracking-wider uppercase">AI Analysis Summary</th>
                </tr>
              </thead>
              <tbody className="text-slate-300">
                {history.length === 0 ? (
                  <tr>
                    <td colSpan="4" className="text-center py-8 text-slate-500">No historical data found in database.</td>
                  </tr>
                ) : (
                  history.map((alert, index) => (
                    <tr key={index} className="border-b border-slate-800/40 hover:bg-[#0e1422]/60 transition-colors">
                      <td className="py-3 px-4 text-slate-500">{alert.timestamp}</td>
                      <td className="py-3 px-4 text-rose-400 font-bold">{alert.source_ip}</td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-1 rounded text-[10px] font-bold ${alert.risk_score === 'High' ? 'bg-rose-500/10 text-rose-400 border border-rose-500/30' : 'bg-amber-500/10 text-amber-400 border border-amber-500/30'}`}>
                          {alert.risk_score}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-[11px] leading-relaxed max-w-md truncate hover:whitespace-normal hover:bg-[#0b0f19] hover:absolute hover:z-10 hover:p-4 hover:border hover:border-slate-700 hover:rounded-lg hover:shadow-2xl cursor-pointer">
                        {alert.ai_report}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </main>

      {/* INCIDENT DETAILS & AI ANALYSIS MODAL */}
      {selectedIncidentModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0b0f19] border border-slate-700 w-full max-w-2xl rounded-2xl shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
            
            <div className="flex justify-between items-center px-6 py-4 border-b border-slate-800 bg-[#0e1422]">
              <div className="flex items-center gap-2 font-mono text-sm font-bold text-white">
                <AlertOctagon size={18} className="text-rose-400" />
                {selectedIncidentModal.attack_type || 'Security Incident'} — ID: #{selectedIncidentModal.id}
              </div>
              <button 
                onClick={() => setSelectedIncidentModal(null)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition-colors"
              >
                <X size={18} />
              </button>
            </div>

            <div className="p-6 space-y-5 font-mono text-xs max-h-[75vh] overflow-y-auto">
              
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-[#07090e] p-3 rounded-lg border border-slate-800/80">
                  <span className="text-slate-500 block mb-1">Source IP Address</span>
                  <span className="text-slate-200 font-bold text-sm">{selectedIncidentModal.source_ip}</span>
                </div>
                <div className="bg-[#07090e] p-3 rounded-lg border border-slate-800/80">
                  <span className="text-slate-500 block mb-1">Destination Target</span>
                  <span className="text-indigo-300 font-bold text-sm">{selectedIncidentModal.destination_ip}:{selectedIncidentModal.port}</span>
                </div>
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div className="bg-[#07090e] p-3 rounded-lg border border-slate-800/80">
                  <span className="text-slate-500 block mb-1">Protocol / Size</span>
                  <span className="text-slate-300 font-bold">{selectedIncidentModal.protocol} ({selectedIncidentModal.length} B)</span>
                </div>
                <div className="bg-[#07090e] p-3 rounded-lg border border-slate-800/80">
                  <span className="text-slate-500 block mb-1">Risk Severity</span>
                  <span className="text-rose-400 font-bold">{selectedIncidentModal.risk_level}</span>
                </div>
                <div className="bg-[#07090e] p-3 rounded-lg border border-slate-800/80">
                  <span className="text-slate-500 block mb-1">Confidence Score</span>
                  <span className="text-emerald-400 font-bold">{selectedIncidentModal.confidence || '98.2'}%</span>
                </div>
              </div>

              <div className="bg-[#07090e] p-4 rounded-lg border border-rose-500/30 space-y-2">
                <span className="text-rose-400 font-bold block flex items-center gap-1.5 text-sm pb-2 border-b border-slate-800">
                  <Terminal size={16} /> Gemini AI Incident Report & Mitigation Steps:
                </span>
                <p className="text-slate-300 leading-relaxed whitespace-pre-wrap pt-2">
                  {selectedIncidentModal.gemini_reason}
                </p>
              </div>

            </div>

            <div className="px-6 py-3 border-t border-slate-800 bg-[#0e1422] flex justify-end">
              <button 
                onClick={() => setSelectedIncidentModal(null)}
                className="bg-slate-800 hover:bg-slate-700 text-slate-200 px-4 py-2 rounded-lg font-mono text-xs transition-colors"
              >
                Close Report
              </button>
            </div>

          </div>
        </div>
      )}

    </div>
  );
}

export default App;