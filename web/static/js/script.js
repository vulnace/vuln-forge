// ════════════════════════════════════════
// STATE
// ════════════════════════════════════════
let currentDomain = null;
let websocket     = null;
let scanning      = false;
let allResults    = [];
let activeFilter  = "all";
let toggleStates  = { fresh:false, test:false, active:false, silent:false, debug:false };


// ════════════════════════════════════════
// PARTICLES
// ════════════════════════════════════════
(function initParticles() {
    const canvas = document.getElementById("particles");
    const ctx    = canvas.getContext("2d");
    let particles = [];
    let W, H;

    function resize() {
        W = canvas.width  = window.innerWidth;
        H = canvas.height = window.innerHeight;
    }

    function spawnParticle() {
        return {
            x:  Math.random() * W,
            y:  Math.random() * H,
            vx: (Math.random() - 0.5) * 0.3,
            vy: (Math.random() - 0.5) * 0.3,
            r:  Math.random() * 1.5 + 0.3,
            a:  Math.random() * 0.5 + 0.1
        };
    }

    function init() {
        resize();
        particles = Array.from({ length: 80 }, spawnParticle);
    }

    function draw() {
        ctx.clearRect(0, 0, W, H);

        for (let i = 0; i < particles.length; i++) {
            for (let j = i + 1; j < particles.length; j++) {
                const dx   = particles[i].x - particles[j].x;
                const dy   = particles[i].y - particles[j].y;
                const dist = Math.sqrt(dx*dx + dy*dy);
                if (dist < 120) {
                    ctx.beginPath();
                    ctx.moveTo(particles[i].x, particles[i].y);
                    ctx.lineTo(particles[j].x, particles[j].y);
                    ctx.strokeStyle = `rgba(16,185,129,${0.08 * (1 - dist/120)})`;
                    ctx.lineWidth   = 0.5;
                    ctx.stroke();
                }
            }
        }

        particles.forEach(p => {
            ctx.beginPath();
            ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(16,185,129,${p.a})`;
            ctx.fill();

            p.x += p.vx;
            p.y += p.vy;

            if (p.x < 0 || p.x > W) p.vx *= -1;
            if (p.y < 0 || p.y > H) p.vy *= -1;
        });

        requestAnimationFrame(draw);
    }

    window.addEventListener("resize", resize);
    init();
    draw();
})();


// ════════════════════════════════════════
// INIT
// ════════════════════════════════════════
document.addEventListener("DOMContentLoaded", () => {
    startClock();
    loadHistory();

    const inp = document.getElementById("domainInput");
    if (inp) {
        inp.addEventListener("input",   e => validateDomain(e.target.value));
        inp.addEventListener("keydown", e => { if (e.key === "Enter") startScan(); });
    }
});


// ════════════════════════════════════════
// CLOCK
// ════════════════════════════════════════
function startClock() {
    const el = document.getElementById("clock");
    if (!el) return;
    setInterval(() => {
        el.textContent = new Date().toISOString().replace("T"," ").slice(0,19) + " UTC";
    }, 1000);
}


// ════════════════════════════════════════
// SLIDING WORKSPACE SYSTEM
// ════════════════════════════════════════
function slideWorkspace(index) {
    const container = document.getElementById('workspace-container');
    if (!container) return;
    const translateValue = index === 0 ? '0' : '-50%';
    container.style.transform = `translateX(${translateValue})`;
}


// ════════════════════════════════════════
// TOGGLE OPTIONS
// ════════════════════════════════════════
function toggleOpt(el) {
    el.classList.toggle("on");
    const key = el.id.replace("tog-", "");
    toggleStates[key] = el.classList.contains("on");
}


// ════════════════════════════════════════
// DOMAIN VALIDATION
// ════════════════════════════════════════
function validateDomain(val) {
    const dot = document.querySelector(".ts-dot");
    const domain = val.trim().toLowerCase();
    const ok = /^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/.test(domain);

    if (dot) dot.className = "ts-dot" + (domain ? (ok ? " valid" : " invalid") : "");
}


// ════════════════════════════════════════
// START SCAN
// ════════════════════════════════════════
async function startScan() {
    const domain = document.getElementById("domainInput").value.trim().toLowerCase();

    if (!domain) { toast("Target domain is required", "error"); return; }
    if (scanning) { toast("Scan already in progress", "error"); return; }

    currentDomain = domain;
    clearTerminal();
    setScanState(true);
    resetStages();

    const scanProgress = document.getElementById("scanProgress");
    if (scanProgress) scanProgress.style.display = "flex";

    log(`[*] ══════════════════════════════════════`, "success");
    log(`[*]  TARGET: ${domain.toUpperCase()}`, "success");
    log(`[*] ══════════════════════════════════════`, "success");
    log(`[*] Initializing pipeline...`, "info");

    const body = {
        domain,
        fresh:     toggleStates.fresh,
        test:      toggleStates.test,
        active:    toggleStates.active,
        no_notify: toggleStates.silent,
        debug:     toggleStates.debug,
    };

    try {
        const res  = await fetch("/api/scan/start", {
            method:  "POST",
            headers: { "Content-Type": "application/json" },
            body:    JSON.stringify(body)
        });
        const data = await res.json();

        if (!res.ok) {
            log(`[!] ${data.detail}`, "error");
            setScanState(false);
            toast(data.detail, "error");
            return;
        }

        log(`[+] Pipeline started`, "success");
        connectWS(domain);

    } catch (err) {
        log(`[!] Connection failed: ${err}`, "error");
        setScanState(false);
        toast("Failed to reach scan engine", "error");
    }
}


// ════════════════════════════════════════
// STOP SCAN
// ════════════════════════════════════════
async function stopScan() {
    if (!scanning) return;
    try {
        await fetch("/api/scan/stop", {
            method:  "POST",
            headers: { "Content-Type": "application/json" },
            body:    JSON.stringify({ domain: currentDomain })
        });
        log("[!] MISSION ABORTED", "warning");
        setScanState(false);
        if (websocket) { websocket.close(); websocket = null; }
    } catch (e) { log(`[!] Abort failed: ${e}`, "error"); }
}


// ════════════════════════════════════════
// WEBSOCKET
// ════════════════════════════════════════
function connectWS(domain) {
    websocket = new WebSocket(`ws://${location.host}/ws/logs/${domain}`);

    websocket.onopen = () => log("[+] Telemetry stream connected", "success");

    websocket.onmessage = e => {
        try {
            const msg = JSON.parse(e.data);
            if (msg.type === "log")    processLog(msg.data);
            if (msg.type === "status") onScanDone(msg.status);
        } catch { processLog(e.data); }
    };

    websocket.onerror  = () => log("[!] Stream error", "error");
    websocket.onclose  = () => { if (scanning) { log("[!] Stream closed", "warning"); setScanState(false); } };
}


// ════════════════════════════════════════
// PROCESS LOG — update stage indicators
// ════════════════════════════════════════
function processLog(line) {
    log(line);
    const l = line.toLowerCase();

    if (l.includes("starting stage: subdomain"))    setStage("subdomains", "running");
    if (l.includes("subdomains stored"))             setStage("subdomains", "done");
    if (l.includes("starting stage: live"))         setStage("livehosts",  "running");
    if (l.includes("live hosts stored"))            setStage("livehosts",  "done");
    if (l.includes("starting stage: endpoint"))     setStage("endpoints",  "running");
    if (l.includes("endpoints stored"))             setStage("endpoints",  "done");
    if (l.includes("starting stage: parameter"))    setStage("parameters", "running");
    if (l.includes("parameter discovery complete"))  setStage("parameters", "done");
    if (l.includes("starting stage: vuln"))         setStage("vulnscan",   "running");
    if (l.includes("all vulnerability results"))    setStage("vulnscan",   "done");
}


// ════════════════════════════════════════
// STAGE HELPERS
// ════════════════════════════════════════
const STAGES = ["subdomains","livehosts","endpoints","parameters","vulnscan"];

function setStage(id, status) {
    const el = document.getElementById(`ps-${id}`);
    if (el) el.className = `prog-stage ${status}`;
}

function resetStages() {
    STAGES.forEach(id => setStage(id, ""));
}


// ════════════════════════════════════════
// SCAN DONE
// ════════════════════════════════════════
async function onScanDone(status) {
    setScanState(false);
    if (websocket) { websocket.close(); websocket = null; }

    if (status === "completed") {
        log("", "");
        log("[+] ══════════════════════════════════════", "success");
        log("[+]  OPERATION COMPLETE", "success");
        log("[+] ══════════════════════════════════════", "success");
        toast("Scan completed!");
        await loadResults(currentDomain);
        await loadHistory();
        setTimeout(() => { slideWorkspace(1); }, 800);
    } else if (status === "failed") {
        log("[!] OPERATION FAILED", "error");
        toast("Scan failed", "error");
    } else {
        log("[!] OPERATION ABORTED", "warning");
    }
}


// ════════════════════════════════════════
// LOAD RESULTS
// ════════════════════════════════════════
async function loadResults(domain) {
    try {
        const res = await fetch(`/api/results/${domain}`);
        if (!res.ok) { toast(`No data for ${domain}`, "error"); return; }

        allResults = await res.json();
        currentDomain = domain;

        const resultsTarget = document.getElementById("resultsTarget");
        if (resultsTarget) {
            resultsTarget.textContent = `TARGET: ${domain.toUpperCase()} // ${allResults.length} FINDING(S)`;
        }

        const counts = { critical:0, high:0, medium:0, low:0, info:0 };
        allResults.forEach(r => {
            const s = (r.severity||"info").toLowerCase();
            if (s in counts) counts[s]++;
        });

        animateCount("sc-critical", counts.critical);
        animateCount("sc-high",     counts.high);
        animateCount("sc-medium",   counts.medium);
        animateCount("sc-low",      counts.low);
        animateCount("sc-info",     counts.info);
        animateCount("sc-total",    allResults.length);

        // Distribution chart
        const total = Math.max(allResults.length, 1);
        const dbCrit = document.getElementById("db-crit");
        const dbHigh = document.getElementById("db-high");
        const dbMed  = document.getElementById("db-med");
        const dbLow  = document.getElementById("db-low");
        if (dbCrit) dbCrit.style.width = `${(counts.critical/total)*100}%`;
        if (dbHigh) dbHigh.style.width = `${(counts.high/total)*100}%`;
        if (dbMed)  dbMed.style.width  = `${(counts.medium/total)*100}%`;
        if (dbLow)  dbLow.style.width  = `${(counts.low/total)*100}%`;

        const liveBadges = document.getElementById("liveBadges");
        if (liveBadges) liveBadges.style.display = "flex";
        
        const bc = document.getElementById("bc");
        const bh = document.getElementById("bh");
        const bm = document.getElementById("bm");
        const bl = document.getElementById("bl");

        if (bc) bc.textContent = `C:${counts.critical}`;
        if (bh) bh.textContent = `H:${counts.high}`;
        if (bm) bm.textContent = `M:${counts.medium}`;
        if (bl) bl.textContent = `L:${counts.low}`;

        renderTable(allResults);

    } catch (err) { toast(`Failed: ${err}`, "error"); }
}

function animateCount(id, target) {
    const el = document.getElementById(id);
    if (!el) return;
    el.classList.remove("animate");
    void el.offsetWidth;
    el.classList.add("animate");

    let start = 0;
    const dur = 600;
    const step = ts => {
        if (!start) start = ts;
        const prog = Math.min((ts - start) / dur, 1);
        el.textContent = Math.floor(prog * target);
        if (prog < 1) requestAnimationFrame(step);
        else el.textContent = target;
    };
    requestAnimationFrame(step);
}


// ════════════════════════════════════════
// RENDER TABLE
// ════════════════════════════════════════
function renderTable(results) {
    const tbody = document.getElementById("vtbody");
    if (!tbody) return;

    if (!results.length) {
        tbody.innerHTML = `<tr><td colspan="4" class="empty-row">NO VULNERABILITIES DETECTED</td></tr>`;
        return;
    }

    tbody.innerHTML = results.map((r, i) => {
        const sev     = (r.severity || "info").toLowerCase();
        const details = r.details || {};
        const info    = details.msg || details.payload || details.name || "—";

        return `<tr
            data-sev="${sev}"
            data-search="${esc((r.type+r.target+info).toLowerCase())}"
            onclick="showModal(${i})"
        >
            <td style="color:var(--text-dim)">${i+1}</td>
            <td><span class="sev-pill ${sev}">${sev.toUpperCase()}</span></td>
            <td style="color:var(--text-bright)">${esc(r.type||"")}</td>
            <td style="max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
                title="${esc(r.target||"")}">${esc(r.target||"")}</td>
        </tr>`;
    }).join("");
}


// ════════════════════════════════════════
// FILTER + SEARCH
// ════════════════════════════════════════
function filter(sev, btn) {
    activeFilter = sev;
    document.querySelectorAll(".pill").forEach(p => p.classList.remove("active"));
    if (btn) btn.classList.add("active");
    applyFilters();
}

function applyFilters() {
    const searchBox = document.getElementById("searchBox");
    if (!searchBox) return;
    const q = (searchBox.value || "").toLowerCase();
    document.querySelectorAll("#vtbody tr").forEach(row => {
        const ms = activeFilter === "all" || row.dataset.sev === activeFilter;
        const mq = !q || (row.dataset.search || "").includes(q);
        row.style.display = ms && mq ? "" : "none";
    });
}


// ════════════════════════════════════════
// MODAL
// ════════════════════════════════════════
function showModal(idx) {
    const r = allResults[idx];
    if (!r) return;

    const sev = (r.severity || "info").toLowerCase();
    const d   = r.details || {};

    const modalTitle = document.getElementById("modalTitle");
    if (modalTitle) modalTitle.textContent = r.type || "FINDING DETAIL";

    const fields = [
        ["SEVERITY",  `<span class="sev-pill ${sev}">${sev.toUpperCase()}</span>`],
        ["TYPE",      esc(r.type || "—")],
        ["TOOL",      `<span class="tool-pill">${esc(r.tool || "—")}</span>`],
        ["TARGET",    esc(r.target || "—")],
        ["PARAMETER", esc(d.parameter || "—")],
        ["PAYLOAD",   esc(d.payload   || "—")],
        ["MESSAGE",   esc(d.msg       || "—")],
        ["NAME",      esc(d.name      || "—")],
        ["OSVDB ID",  esc(d.osvdbid   || d.id || "—")],
    ];

    const modalBody = document.getElementById("modalBody");
    if (modalBody) {
        modalBody.innerHTML = fields
            .filter(([,v]) => v !== "—" && v !== esc("—"))
            .map(([k,v]) => `
                <div class="modal-field">
                    <span class="mf-key">${k}</span>
                    <span class="mf-val">${v}</span>
                </div>
            `).join("");
    }

    const modalOverlay = document.getElementById("modalOverlay");
    if (modalOverlay) modalOverlay.classList.add("open");
}

function closeModal() {
    const modalOverlay = document.getElementById("modalOverlay");
    if (modalOverlay) modalOverlay.classList.remove("open");
}

document.addEventListener("keydown", e => {
    if (e.key === "Escape") closeModal();
});


// ════════════════════════════════════════
// DOWNLOADS
// ════════════════════════════════════════
function downloadPDF() {
    if (!currentDomain) { toast("No target selected", "error"); return; }
    window.location.href = `/api/report/${currentDomain}`;
    toast("Generating PDF...");
}

function downloadCSV() {
    if (!allResults.length) { toast("No results to export", "error"); return; }

    const headers = ["#","Severity","Type","Tool","Target","Details"];
    const rows    = allResults.map((r,i) => {
        const d    = r.details || {};
        const info = d.msg || d.payload || d.name || "";
        return [i+1, r.severity, r.type, r.tool, r.target, info]
            .map(v => `"${String(v).replace(/"/g,'""')}"`).join(",");
    });

    const csv  = [headers.join(","), ...rows].join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href     = url;
    a.download = `${currentDomain}_vulns.csv`;
    a.click();
    URL.revokeObjectURL(url);
    toast("CSV downloaded!");
}

async function renotify() {
    if (!currentDomain) { toast("No target selected", "error"); return; }
    try {
        const res  = await fetch(`/api/notify/${currentDomain}`, { method: "POST" });
        const data = await res.json();
        toast(res.ok ? "Notifications sent!" : data.detail, res.ok ? "success" : "error");
    } catch (e) { toast(`Notify failed: ${e}`, "error"); }
}


// ════════════════════════════════════════
// HISTORY
// ════════════════════════════════════════
async function loadHistory() {
    const grid = document.getElementById("histGrid");
    if (!grid) return;
    try {
        const res   = await fetch("/api/scans");
        const scans = await res.json();

        if (!scans.length) {
            grid.innerHTML = `<p class="empty-row" style="padding:32px">No previous operations found.</p>`;
            return;
        }

        grid.innerHTML = scans.map(s => `
            <div class="hist-card" onclick="viewScan('${esc(s.domain)}')">
                <div class="hc-domain">${esc(s.domain)}</div>
                <div class="hc-meta">
                    <span>${fmtBytes(s.size)}</span>
                    <span>${fmtDate(s.modified)}</span>
                </div>
                <div class="hc-actions">
                    <button class="hc-btn" onclick="event.stopPropagation();viewScan('${esc(s.domain)}')">▶ VIEW</button>
                    <button class="hc-btn pdf" onclick="event.stopPropagation();dlPDF('${esc(s.domain)}')">↓ PDF</button>
                    <button class="hc-btn csv" onclick="event.stopPropagation();dlCSV('${esc(s.domain)}')">↓ CSV</button>
                    <button class="hc-btn del" onclick="event.stopPropagation();deleteScan('${esc(s.domain)}')">✕ DEL</button>
                </div>
            </div>
        `).join("");
    } catch {
        grid.innerHTML = `<p class="empty-row" style="padding:32px">Failed to load history.</p>`;
    }
}

async function viewScan(domain) {
    await loadResults(domain);
    slideWorkspace(1);
}

function dlPDF(domain) { window.location.href = `/api/report/${domain}`; }

async function dlCSV(domain) {
    await loadResults(domain);
    downloadCSV();
}

async function deleteScan(domain) {
    if (!confirm(`Are you sure you want to permanently delete the scan history for ${domain}?`)) return;
    
    try {
        const res = await fetch(`/api/scans/${domain}`, { method: 'DELETE' });
        const data = await res.json();
        
        if (res.ok) {
            toast(`Deleted history for ${domain}`, "success");
            
            // If deleting the actively viewed scan, clear the dashboard UI
            if (currentDomain === domain) {
                currentDomain = null;
                allResults = [];
                
                const targetEl = document.getElementById("resultsTarget");
                if (targetEl) targetEl.textContent = "AWAITING SCAN DATA";
                
                ["sc-critical", "sc-high", "sc-medium", "sc-low", "sc-info", "sc-total"].forEach(id => {
                    const el = document.getElementById(id);
                    if(el) el.textContent = "0";
                });
                
                ["db-crit", "db-high", "db-med", "db-low"].forEach(id => {
                    const el = document.getElementById(id);
                    if(el) el.style.width = "0%";
                });
                
                const liveBadges = document.getElementById("liveBadges");
                if (liveBadges) liveBadges.style.display = "none";
                
                renderTable([]); // Renders the empty state
            }
            
            await loadHistory(); // Refresh the history grid
        } else {
            toast(data.detail || `Failed to delete ${domain}`, "error");
        }
    } catch (e) {
        toast(`Error: ${e}`, "error");
    }
}


// ════════════════════════════════════════
// TERMINAL
// ════════════════════════════════════════
function log(line, type) {
    const term    = document.getElementById("terminal");
    if (!term) return;
    const welcome = document.getElementById("termWelcome");
    if (welcome) welcome.remove();

    const span = document.createElement("span");
    span.className = `log-line ${classifyLog(line, type)}`;
    span.textContent = line;
    term.appendChild(span);
    term.scrollTop = term.scrollHeight;
}

function classifyLog(line, type) {
    if (type) return `log-${type}`;
    const l = line.toLowerCase();
    if (l.includes("[error]") || l.includes("[!]"))   return "log-error";
    if (l.includes("[warning]") || l.includes("[~]")) return "log-warning";
    if (l.includes("[debug]"))                         return "log-debug";
    if (l.includes("[+]") || l.includes("[*]"))        return "log-success";
    return "log-info";
}

function clearTerminal() {
    const term = document.getElementById("terminal");
    if (term) term.innerHTML = "";
}


// ════════════════════════════════════════
// UI STATE
// ════════════════════════════════════════
function setScanState(active) {
    scanning = active;
    const btnStart = document.getElementById("btnStart");
    const btnStop = document.getElementById("btnStop");

    if (btnStart) btnStart.disabled = active;
    if (btnStop)  btnStop.disabled  = !active;

    const scanProgress = document.getElementById("scanProgress");
    if (!active && scanProgress) {
        scanProgress.style.display = "none";
    }
}


// ════════════════════════════════════════
// TOAST
// ════════════════════════════════════════
function toast(msg, type = "success") {
    const wrap = document.getElementById("toastWrap");
    if (!wrap) return;
    const el   = document.createElement("div");
    el.className = `toast-item ${type}`;
    el.innerHTML = `<span>${msg}</span>`;
    wrap.appendChild(el);
    setTimeout(() => { 
        el.style.opacity = "0"; 
        el.style.transform = "translateX(20px)"; 
        el.style.transition = "all 0.3s"; 
        setTimeout(() => el.remove(), 300); 
    }, 3000);
}


// ════════════════════════════════════════
// UTILS
// ════════════════════════════════════════
function esc(str) {
    return String(str)
        .replace(/&/g,"&amp;").replace(/</g,"&lt;")
        .replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

function fmtBytes(b) {
    if (b < 1024) return `${b}B`;
    if (b < 1048576) return `${(b/1024).toFixed(1)}KB`;
    return `${(b/1048576).toFixed(1)}MB`;
}

function fmtDate(ts) {
    return new Date(ts * 1000).toLocaleDateString("en-GB", { day:"2-digit", month:"short", year:"numeric" });
}