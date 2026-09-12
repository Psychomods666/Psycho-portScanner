let socket = null;

let selectedMode = "quick";
let results = [];
let scanning = false;

/* =========================================================
HELPER
========================================================= */

function $(id) {
return document.getElementById(id);
}

/* =========================================================
CLOCK
========================================================= */

function updateClock() {

 
const clock = $("clock");

if (!clock) return;

const now = new Date();

clock.textContent =
    now.toLocaleTimeString([], {
        hour12: false
    });
 

}

setInterval(updateClock, 1000);
updateClock();

/* =========================================================
MODE SELECTION
========================================================= */

document.querySelectorAll(".profile").forEach(button => {

 
button.addEventListener("click", () => {

    document
        .querySelectorAll(".profile")
        .forEach(item => {
            item.classList.remove("active");
        });

    button.classList.add("active");

    selectedMode =
        button.dataset.mode;

    const descriptions = {
        quick: "Common service ports",
        standard: "Ports 1 — 1024",
        custom: "Custom port range"
    };

    $("profileDescription").textContent =
        descriptions[selectedMode];

    $("customRange").classList.toggle(
        "hidden",
        selectedMode !== "custom"
    );

});
 

});

/* =========================================================
LOGGING
========================================================= */

function log(message) {

 
const container = $("log");

if (!container) return;

const line =
    document.createElement("div");

line.className = "console-line";

const time =
    new Date().toLocaleTimeString();

line.textContent =
    `[${time}] ${message}`;

container.prepend(line);

const autoScroll =
    $("autoScrollToggle");

if (
    !autoScroll ||
    autoScroll.checked
) {
    container.scrollTop = 0;
}
 

}

/* =========================================================
STATUS
========================================================= */

function setStatus(text, active = true) {

 
$("statusText").textContent =
    text;

const dots =
    document.querySelectorAll(".status-dot");

dots.forEach(dot => {

    dot.style.background =
        active
            ? "var(--accent)"
            : "#555";

    dot.style.boxShadow =
        active
            ? "0 0 10px var(--accent)"
            : "none";

});
 

}

/* =========================================================
START SCAN
========================================================= */

function startScan() {

 
if (scanning) {
    return;
}

const authorized =
    $("authorized").checked;

if (!authorized) {

    alert(
        "Please confirm that you are authorized to scan this target."
    );

    return;
}

const target =
    $("target").value.trim();

if (!target) {

    alert(
        "Enter a domain or IP address."
    );

    $("target").focus();

    return;
}


let payload = {
    target: target,
    mode: selectedMode
};


if (selectedMode === "custom") {

    payload.start =
        Number($("startPort").value);

    payload.end =
        Number($("endPort").value);

    if (
        payload.start < 1 ||
        payload.start > 65535 ||
        payload.end < 1 ||
        payload.end > 65535 ||
        payload.start > payload.end
    ) {

        alert(
            "Enter a valid port range between 1 and 65535."
        );

        return;
    }

}


resetResults();

scanning = true;

updateButtons();

setStatus("SCANNING");

log(
    `Starting ${selectedMode.toUpperCase()} scan against ${target}`
);


const protocol =
    location.protocol === "https:"
        ? "wss"
        : "ws";


socket =
    new WebSocket(
        `${protocol}://${location.host}/ws/scan`
    );


socket.onopen = () => {

    socket.send(
        JSON.stringify(payload)
    );

    log(
        "WebSocket connection established."
    );

};


socket.onmessage = event => {

    try {

        const data =
            JSON.parse(event.data);

        handleEvent(data);

    } catch (error) {

        log(
            "Unable to parse server response."
        );

    }

};


socket.onerror = () => {

    log(
        "WebSocket connection error."
    );

    setStatus(
        "ERROR",
        false
    );

};


socket.onclose = () => {

    if (scanning) {

        scanning = false;

        updateButtons();

        if (
            $("statusText").textContent ===
            "SCANNING"
        ) {

            setStatus(
                "DISCONNECTED",
                false
            );

        }

    }

};
 

}

/* =========================================================
EVENT HANDLER
========================================================= */

function handleEvent(data) {

 
if (data.type === "started") {

    log(
        `Testing ${data.ports} TCP ports.`
    );

    $("scanMessage").textContent =
        `Preparing ${data.ports} TCP checks...`;

    return;
}


if (data.type === "resolved") {

    $("domain").textContent =
        data.target;

    $("ip").textContent =
        data.ip;

    $("scanMessage").textContent =
        `Resolved ${data.target} → ${data.ip}`;

    log(
        `DNS resolution: ${data.target} → ${data.ip}`
    );

    return;
}


if (data.type === "port") {

    const result =
        data.result;

    results.push(result);

    renderResult(result);

    $("tested").textContent =
        data.completed;

    $("resultCount").textContent =
        `${results.length} results`;


    const openCount =
        results.filter(
            item =>
                item.state === "OPEN"
        ).length;


    const filteredCount =
        results.filter(
            item =>
                item.state === "FILTERED"
        ).length;


    const respondedCount =
        results.filter(
            item =>
                item.state === "OPEN" ||
                item.state === "CLOSED"
        ).length;


    $("open").textContent =
        openCount;

    $("openMetric").textContent =
        openCount;

    $("filteredMetric").textContent =
        filteredCount;

    $("respondedMetric").textContent =
        respondedCount;


    const progress =
        Number(data.progress) || 0;

    $("progressText").textContent =
        `${progress}%`;

    $("progressBar").style.width =
        `${progress}%`;


    $("scanMessage").textContent =
        `Scanning ${data.completed} / ${data.total}`;


    updateRisk();


    if (result.state === "OPEN") {

        log(
            `OPEN → ${result.port}/${result.service}`
        );

    }

    return;
}


if (data.type === "complete") {

    scanning = false;

    updateButtons();

    const message =
        data.stopped
            ? "Scan stopped."
            : "Scan complete.";

    $("scanMessage").textContent =
        message;

    log(message);

    setStatus(
        data.stopped
            ? "STOPPED"
            : "COMPLETE",
        !data.stopped
    );

    $("exportBtn").disabled =
        results.length === 0;

    return;
}


if (data.type === "duration") {

    $("duration").textContent =
        `${data.seconds}s`;

    log(
        `Scan duration: ${data.seconds}s`
    );

    return;
}


if (data.type === "error") {

    scanning = false;

    updateButtons();

    log(
        `ERROR: ${data.message}`
    );

    setStatus(
        "ERROR",
        false
    );

    alert(
        data.message
    );

}
 

}

/* =========================================================
RENDER RESULT
========================================================= */

function renderResult(result) {

 
$("emptyState").style.display =
    "none";

const tbody =
    $("results");

const row =
    document.createElement("tr");


const stateClass =
    String(result.state || "UNKNOWN")
        .toLowerCase();


const riskClass =
    String(result.risk || "UNKNOWN")
        .toLowerCase();


const latency =
    result.latency_ms !== null &&
    result.latency_ms !== undefined
        ? `${result.latency_ms} ms`
        : "—";


row.innerHTML = `

    <td>
        <strong>
            ${escapeHtml(result.port)}
        </strong>
    </td>

    <td class="${stateClass}">
        ${escapeHtml(result.state || "UNKNOWN")}
    </td>

    <td>
        ${escapeHtml(result.service || "Unknown")}
    </td>

    <td class="risk-${riskClass}">
        ${escapeHtml(result.risk || "UNKNOWN")}
    </td>

    <td>
        ${escapeHtml(latency)}
    </td>

    <td title="${escapeHtml(result.banner || "")}">
        ${escapeHtml(result.banner || "—")}
    </td>

`;


tbody.appendChild(row);
 

}

/* =========================================================
RISK
========================================================= */

function updateRisk() {

 
const high =
    results.filter(
        item =>
            item.risk === "HIGH"
    ).length;


const medium =
    results.filter(
        item =>
            item.risk === "MEDIUM"
    ).length;


const low =
    results.filter(
        item =>
            item.risk === "LOW"
    ).length;


$("highRisk").textContent =
    high;

$("mediumRisk").textContent =
    medium;

$("lowRisk").textContent =
    low;

$("riskCount").textContent =
    high;


const total =
    high + medium + low;


const highPercent =
    total > 0
        ? (high / total) * 360
        : 0;


const ring =
    document.querySelector(".risk-ring");


if (!ring) return;


ring.style.background =
    `conic-gradient(
        var(--danger, #ff5f67) 0deg ${highPercent}deg,
        var(--accent-soft) ${highPercent}deg 360deg
    )`;
 

}

/* =========================================================
STOP
========================================================= */

function stopScan() {

 
if (socket) {

    socket.close();

    socket = null;

}

scanning = false;

updateButtons();

setStatus(
    "STOPPED",
    false
);

$("scanMessage").textContent =
    "Scan stopped by user.";

log(
    "Scan stopped by user."
);
 

}

/* =========================================================
BUTTON STATE
========================================================= */

function updateButtons() {

 
$("scanBtn").disabled =
    scanning;

$("stopBtn").disabled =
    !scanning;
 

}

/* =========================================================
RESET
========================================================= */

function resetResults() {

 
results = [];

$("results").innerHTML = "";

$("emptyState").style.display =
    "flex";


$("tested").textContent =
    "0";

$("open").textContent =
    "0";

$("openMetric").textContent =
    "0";

$("filteredMetric").textContent =
    "0";

$("respondedMetric").textContent =
    "0";


$("domain").textContent =
    "—";

$("ip").textContent =
    "—";


$("progressText").textContent =
    "0%";

$("progressBar").style.width =
    "0%";


$("resultCount").textContent =
    "0 results";


$("duration").textContent =
    "—";


$("scanMessage").textContent =
    "Waiting for scan...";


$("highRisk").textContent =
    "0";

$("mediumRisk").textContent =
    "0";

$("lowRisk").textContent =
    "0";

$("riskCount").textContent =
    "0";


const ring =
    document.querySelector(".risk-ring");

if (ring) {

    ring.style.background =
        `conic-gradient(
            var(--accent) 0deg,
            var(--accent-soft) 0deg
        )`;

}


$("exportBtn").disabled =
    true;
 

}

/* =========================================================
CSV EXPORT
========================================================= */

async function exportReport() {

 
if (!results.length) {

    alert(
        "No scan results available."
    );

    return;
}


try {

    const response =
        await fetch(
            "/report/csv",
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    results: results
                })
            }
        );


    if (!response.ok) {

        throw new Error(
            "Unable to generate report."
        );

    }


    const blob =
        await response.blob();


    const url =
        URL.createObjectURL(blob);


    const link =
        document.createElement("a");


    link.href = url;

    link.download =
        "psychoport-report.csv";


    document.body.appendChild(link);

    link.click();

    link.remove();


    URL.revokeObjectURL(url);


    log(
        "CSV report exported."
    );

} catch (error) {

    alert(
        error.message
    );

}
 

}

/* =========================================================
NAVIGATION
========================================================= */

function goToSection(id) {

 
const target =
    document.getElementById(id);

if (!target) return;

target.scrollIntoView({
    behavior: "smooth",
    block: "start"
});

updateNavigation(id);
 

}

function focusScanner() {

 
$("scannerSection")
    .scrollIntoView({
        behavior: "smooth",
        block: "start"
    });

updateNavigation("scanner");

closeSidebar();
 

}

function focusHistory() {

 
$("historySection")
    .scrollIntoView({
        behavior: "smooth",
        block: "start"
    });

updateNavigation("history");

closeSidebar();
 

}

function updateNavigation(section) {

 
document
    .querySelectorAll(".nav-item")
    .forEach(item => {

        item.classList.toggle(
            "active",
            item.dataset.section === section
        );

    });


document
    .querySelectorAll(".mobile-nav-item")
    .forEach((item, index) => {

        item.classList.remove("active");

        if (
            section === "overview" &&
            index === 0
        ) item.classList.add("active");

        if (
            section === "scanner" &&
            index === 1
        ) item.classList.add("active");

        if (
            section === "history" &&
            index === 2
        ) item.classList.add("active");

    });
 

}

/* =========================================================
MOBILE SIDEBAR
========================================================= */

function toggleSidebar() {

 
const sidebar =
    document.querySelector(".sidebar");

const overlay =
    document.querySelector(".sidebar-overlay");

sidebar.classList.toggle("open");

overlay.classList.toggle("open");
 

}

function closeSidebar() {

 
const sidebar =
    document.querySelector(".sidebar");

const overlay =
    document.querySelector(".sidebar-overlay");

if (!sidebar || !overlay) return;

sidebar.classList.remove("open");

overlay.classList.remove("open");
 

}

/* =========================================================
SETTINGS
========================================================= */

function openSettings() {

 
$("settingsOverlay")
    .classList.add("open");
 

}

function closeSettings() {

 
$("settingsOverlay")
    .classList.remove("open");
 

}

$("settingsOverlay").addEventListener(
"click",
event => {

 
    if (
        event.target ===
        $("settingsOverlay")
    ) {

        closeSettings();

    }

}
 

);

/* =========================================================
THEME
========================================================= */

function changeTheme(theme) {

 
document.body.classList.remove(
    "theme-violet",
    "theme-cyan"
);

if (theme === "violet") {

    document.body.classList.add(
        "theme-violet"
    );

}

if (theme === "cyan") {

    document.body.classList.add(
        "theme-cyan"
    );

}

localStorage.setItem(
    "psychoport-theme",
    theme
);
 

}

/* =========================================================
GLASS INTENSITY
========================================================= */

function changeGlass(value) {

 
const opacity =
    Number(value) / 100;

document.documentElement
    .style
    .setProperty(
        "--glass-opacity",
        opacity
    );

localStorage.setItem(
    "psychoport-glass",
    value
);
 

}

/* =========================================================
MOTION
========================================================= */

function toggleMotion(enabled) {

 
document.body.classList.toggle(
    "reduce-motion",
    !enabled
);

localStorage.setItem(
    "psychoport-motion",
    enabled
);
 

}

/* =========================================================
DEFAULT PROFILE
========================================================= */

function setDefaultProfile(mode) {

 
localStorage.setItem(
    "psychoport-profile",
    mode
);

const button =
    document.querySelector(
        `.profile[data-mode="${mode}"]`
    );

if (button) {
    button.click();
}
 

}

/* =========================================================
CLEAR CONSOLE
========================================================= */

function clearConsole() {

 
$("log").innerHTML = "";

log(
    "Activity console cleared."
);
 

}

/* =========================================================
HTML ESCAPING
========================================================= */

function escapeHtml(value) {

 
return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
 

}

/* =========================================================
LOAD SETTINGS
========================================================= */

function loadSettings() {

 
const theme =
    localStorage.getItem(
        "psychoport-theme"
    ) || "cyber";

const glass =
    localStorage.getItem(
        "psychoport-glass"
    ) || "55";

const motion =
    localStorage.getItem(
        "psychoport-motion"
    );

const profile =
    localStorage.getItem(
        "psychoport-profile"
    ) || "quick";


$("themeSelect").value =
    theme;

$("glassRange").value =
    glass;

$("defaultProfile").value =
    profile;


changeTheme(theme);

changeGlass(glass);


if (motion !== null) {

    const enabled =
        motion === "true";

    $("motionToggle").checked =
        enabled;

    toggleMotion(enabled);

}


setDefaultProfile(profile);
 

}

/* =========================================================
KEYBOARD SHORTCUTS
========================================================= */

document.addEventListener(
"keydown",
event => {

 
    if (event.key === "Escape") {

        closeSettings();
        closeSidebar();

    }

    if (
        event.key === "/" &&
        document.activeElement.tagName !== "INPUT"
    ) {

        event.preventDefault();

        $("target").focus();

    }

}
 

);

/* =========================================================
SCROLL REVEAL
========================================================= */

const revealObserver =
new IntersectionObserver(
entries => {

 
        entries.forEach(entry => {

            if (entry.isIntersecting) {

                entry.target.classList.add(
                    "visible"
                );

            }

        });

    },
    {
        threshold: .08
    }
);
 

document
.querySelectorAll(".reveal")
.forEach(element => {

 
    revealObserver.observe(element);

});
 

/* =========================================================
INITIAL STATE
========================================================= */

document.addEventListener(
"DOMContentLoaded",
() => {

 
    setStatus(
        "READY",
        true
    );

    updateButtons();

    loadSettings();

    log(
        "PsychoPort network intelligence initialized."
    );

    log(
        "Scanner ready for authorized testing."
    );

}
 

);
