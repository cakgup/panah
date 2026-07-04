const state = {
  config: null,
  modules: [],
  jobs: [],
  assessments: [],
  activeAssessmentId: null,
  activeAssessment: null,
  activeApprovals: [],
  activeRecommendations: null,
  activeFindings: [],
  activeFindingSummary: null,
  activeAssessmentDetail: null,
  activeCorrelation: null,
  activeWorkspace: null,
  activeDiff: null,
  activeDrift: null,
  approvalsDashboard: null,
  chainPresets: [],
  toolsStatus: null,
  toolingCatalog: [],
  toolSearchQuery: "",
  toolStatusFilter: "all",
  toolSortMode: "usage",
  selectedToolLabel: "",
  highlightedModuleId: "",
  engagements: [],
  referenceFindings: [],
  assets: [],
  targetAsset: null,
  importResult: null,
  destructiveActions: [],
  destructiveResult: null,
  workspacePreviewPath: "",
  activeJobId: null,
  activeJob: null,
  pollTimer: null,
  tooling: null,
  selectedPhase: "all",
  catalogSurface: "modules",
  viewMode: "playbook",
  operationsTab: "workspace",
  healthTab: "strategy",
  advancedTab: "findings",
  moduleExecutionProfile: "fast",
  moduleSearchQuery: "",
  insightTab: "console",
  consoleHeightLocked: false,
  operationsVisible: false,
  moduleRenderFrame: 0,
  expandedModuleCommandIds: [],
  moduleDryRunCache: {},
  targetAssetTimer: 0,
  targetAssetRequestSeq: 0,
  lastTargetAssetKey: "",
  moduleSearchTimer: 0,
  toolSearchTimer: 0,
  operatorWorkspaceLoaded: false,
  toolCatalogLoaded: false,
  toolCatalogLoading: false,
  toolCatalogLoadPromise: null,
  apiBaseUrl: "",
  apiBasePromise: null,
  chainRunPending: false,
  chainRunStage: "idle",
  chainRunUiTimer: 0,
  referencePanelLoaded: false,
  activeInteractiveSession: null,
  interactivePollTimer: 0,
  interactiveTabState: null
};

const $ = (selector) => document.querySelector(selector);
const LAST_TARGET_STORAGE_KEY = "lab-console-last-target";
const CONSOLE_MIN_HEIGHT = 260;
const MODULES_CACHE_KEY = "lab-console-modules-cache-v1";
const MODULES_CACHE_TTL_MS = 60 * 1000;
const BACKEND_DEFAULT_PORT = "4080";
const INTERACTIVE_COMMAND_HINTS = {
  metasploit: [
    "help",
    "search",
    "use",
    "show",
    "show options",
    "show payloads",
    "show exploits",
    "show auxiliary",
    "info",
    "check",
    "run",
    "exploit",
    "set",
    "setg",
    "unset",
    "unsetg",
    "back",
    "sessions",
    "jobs",
    "route",
    "workspace",
    "notes",
    "creds",
    "services",
    "hosts",
    "version",
    "banner",
    "exit",
    "quit"
  ],
  ssh: ["help", "exit", "quit", "pwd", "ls", "cd", "cat", "whoami", "id", "uname -a"],
  smbclient: ["help", "ls", "dir", "cd", "pwd", "get", "put", "mget", "mkdir", "rmdir", "exit", "quit"],
  rpcclient: ["help", "enumdomusers", "enumdomgroups", "queryuser", "querygroup", "lsaquery", "srvinfo", "exit", "quit"],
  mysql: ["help", "show databases;", "use ", "show tables;", "select ", "status;", "exit"],
  psql: ["\\?", "\\l", "\\c ", "\\dt", "\\d ", "select ", "\\q"],
  ftp: ["help", "ls", "pwd", "cd ", "get ", "put ", "passive", "binary", "ascii", "bye", "quit"],
  telnet: ["help", "open ", "close", "quit", "status", "send "]
};

function isAbsoluteUrl(value) {
  return /^https?:\/\//i.test(String(value || ""));
}

function normalizeRequestPath(path) {
  const value = String(path || "").trim();
  if (!value) return "/";
  if (isAbsoluteUrl(value)) return value;
  return value.startsWith("/") ? value : `/${value}`;
}

function candidateApiBases() {
  const candidates = [];
  const append = (value) => {
    const normalized = String(value || "").trim().replace(/\/+$/, "");
    if (!normalized || candidates.includes(normalized)) return;
    candidates.push(normalized);
  };
  append(window.localStorage.getItem("lab-console-api-base"));
  append(window.__LAB_CONSOLE_API_BASE__);
  append(window.location.origin);
  if (window.location.port !== BACKEND_DEFAULT_PORT) {
    append(`${window.location.protocol}//${window.location.hostname}:${BACKEND_DEFAULT_PORT}`);
  }
  if (window.location.hostname === "localhost") {
    append(`${window.location.protocol}//127.0.0.1:${BACKEND_DEFAULT_PORT}`);
  }
  return candidates;
}

function buildRequestUrl(path, base = "") {
  const normalizedPath = normalizeRequestPath(path);
  if (isAbsoluteUrl(normalizedPath)) return normalizedPath;
  if (!base) return normalizedPath;
  return `${String(base).replace(/\/+$/, "")}${normalizedPath}`;
}

function apiUrl(path) {
  const normalizedPath = normalizeRequestPath(path);
  if (!normalizedPath.startsWith("/api/")) {
    return buildRequestUrl(normalizedPath);
  }
  const base = state.apiBaseUrl
    || candidateApiBases().find((entry) => entry.endsWith(`:${BACKEND_DEFAULT_PORT}`))
    || window.location.origin;
  return buildRequestUrl(normalizedPath, base);
}

async function probeApiBase(base) {
  try {
    const response = await fetch(buildRequestUrl("/api/health", base), {
      method: "GET",
      cache: "no-store"
    });
    return response.ok;
  } catch (error) {
    return false;
  }
}

async function resolveApiBase(force = false) {
  if (!force && state.apiBaseUrl) return state.apiBaseUrl;
  if (!force && state.apiBasePromise) return state.apiBasePromise;
  state.apiBasePromise = (async () => {
    for (const base of candidateApiBases()) {
      if (await probeApiBase(base)) {
        state.apiBaseUrl = base;
        window.localStorage.setItem("lab-console-api-base", base);
        return base;
      }
    }
    throw new Error("Backend API tidak terdeteksi. Pastikan server backend berjalan di port 4080.");
  })();
  try {
    return await state.apiBasePromise;
  } finally {
    state.apiBasePromise = null;
  }
}

function debounce(fn, delay = 160) {
  let timer = 0;
  return (...args) => {
    window.clearTimeout(timer);
    timer = window.setTimeout(() => fn(...args), delay);
  };
}

function scheduleModulesRender() {
  if (state.moduleRenderFrame) return;
  state.moduleRenderFrame = window.requestAnimationFrame(() => {
    state.moduleRenderFrame = 0;
    renderModules();
  });
}

function scheduleDeferredTask(task) {
  const runner = () => Promise.resolve().then(task).catch((error) => console.warn(error));
  if (typeof window.requestIdleCallback === "function") {
    window.requestIdleCallback(() => runner(), { timeout: 1200 });
    return;
  }
  window.setTimeout(runner, 120);
}

function readModulesCache() {
  try {
    const raw = localStorage.getItem(MODULES_CACHE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    const savedAt = Number(parsed?.savedAt || 0);
    const modules = Array.isArray(parsed?.modules) ? parsed.modules : null;
    if (!modules?.length || !savedAt) return null;
    if (Date.now() - savedAt > MODULES_CACHE_TTL_MS) return null;
    return modules;
  } catch (error) {
    localStorage.removeItem(MODULES_CACHE_KEY);
    return null;
  }
}

function writeModulesCache(modules) {
  try {
    localStorage.setItem(MODULES_CACHE_KEY, JSON.stringify({
      savedAt: Date.now(),
      modules: Array.isArray(modules) ? modules : []
    }));
  } catch (error) {
    // Abaikan jika storage penuh atau tidak tersedia.
  }
}

function clampConsoleHeight(value) {
  const numericValue = Number(value);
  if (!Number.isFinite(numericValue)) return CONSOLE_MIN_HEIGHT;
  return Math.max(CONSOLE_MIN_HEIGHT, Math.round(numericValue));
}

function insightScrollPanels() {
  return ["#consoleOutput", "#evidenceList"]
    .map((selector) => $(selector))
    .filter(Boolean);
}

function activeInsightScrollPanel() {
  if (state.insightTab === "evidence") return $("#evidenceList");
  return $("#consoleOutput");
}

function applyInsightPanelHeight(value) {
  const height = clampConsoleHeight(value);
  insightScrollPanels().forEach((panel) => {
    panel.style.height = `${height}px`;
  });
}

function persistConsoleHeight() {
  const activePanel = activeInsightScrollPanel();
  if (!activePanel) return;
  state.consoleHeightLocked = true;
  applyInsightPanelHeight(activePanel.getBoundingClientRect().height);
}

function syncConsoleHeightToModulePane({ force = false } = {}) {
  const activePanel = activeInsightScrollPanel();
  const modulePane = document.querySelector(".module-pane");
  const insightCard = document.querySelector(".insight-card");
  if (!activePanel || !modulePane || !insightCard) return;

  if (state.consoleHeightLocked && !force) {
    return;
  }

  const activePanelRect = activePanel.getBoundingClientRect();
  const modulePaneRect = modulePane.getBoundingClientRect();
  const insightCardRect = insightCard.getBoundingClientRect();
  const desiredHeight = activePanelRect.height + (modulePaneRect.bottom - insightCardRect.bottom);
  applyInsightPanelHeight(desiredHeight);
}

function queueConsoleHeightSync(options = {}) {
  window.requestAnimationFrame(() => syncConsoleHeightToModulePane(options));
}

function bindConsoleResizeHandle() {
  let resizeIntent = false;
  const armResize = (event) => {
    const target = event.currentTarget;
    if (!target) return;
    const rect = target.getBoundingClientRect();
    resizeIntent = rect.bottom - event.clientY <= 28;
  };
  const commitResize = () => {
    if (!resizeIntent) return;
    resizeIntent = false;
    persistConsoleHeight();
  };

  insightScrollPanels().forEach((panel) => {
    panel.addEventListener("pointerdown", armResize);
  });
  window.addEventListener("pointerup", commitResize);
  window.addEventListener("mouseup", commitResize);
  window.addEventListener("resize", () => {
    if (!state.consoleHeightLocked) {
      queueConsoleHeightSync();
    }
  });
}

function showToast(message) {
  const toast = $("#toast");
  if (!toast) return;
  toast.textContent = message;
  toast.classList.add("show");
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => toast.classList.remove("show"), 2200);
}

function setRunChainUiState(stage = "idle", message = "") {
  state.chainRunStage = stage || "idle";
  state.chainRunPending = !["idle", "success", "error"].includes(state.chainRunStage);
  const button = $("#runChainBtn");
  const note = $("#runChainStatusNote");
  const stepTarget = $("#workflowStepTarget");
  const stepAssessment = $("#workflowStepAssessment");
  const stepReview = $("#workflowStepReview");
  const applyStepState = (element, mode) => {
    if (!element) return;
    element.classList.toggle("is-active", mode === "active");
    element.classList.toggle("is-done", mode === "done");
  };

  let buttonLabel = "Run Full Simulation Chain";
  let noteLabel = message || "Siap menjalankan full chain untuk target aktif.";
  let stepTargetMode = "";
  let stepAssessmentMode = "";
  let stepReviewMode = "";

  if (stage === "preflight") {
    buttonLabel = "Running...";
    noteLabel = message || "Memvalidasi target dan menyiapkan payload eksekusi.";
    stepTargetMode = "active";
  } else if (stage === "assessment") {
    buttonLabel = "Running...";
    noteLabel = message || "Membuat atau menyelaraskan assessment aktif.";
    stepTargetMode = "done";
    stepAssessmentMode = "active";
  } else if (stage === "approval") {
    buttonLabel = "Running...";
    noteLabel = message || "Menyimpan approval chain yang dibutuhkan sebelum eksekusi.";
    stepTargetMode = "done";
    stepAssessmentMode = "active";
  } else if (stage === "submitting") {
    buttonLabel = "Running...";
    noteLabel = message || "Mengirim full simulation chain ke backend worker.";
    stepTargetMode = "done";
    stepAssessmentMode = "done";
    stepReviewMode = "active";
  } else if (stage === "success") {
    buttonLabel = "Run Full Simulation Chain";
    noteLabel = message || "Job full chain berhasil dibuat. Pantau live console dan evidence.";
    stepTargetMode = "done";
    stepAssessmentMode = "done";
    stepReviewMode = "active";
  } else if (stage === "error") {
    buttonLabel = "Run Full Simulation Chain";
    noteLabel = message || "Eksekusi chain berhenti. Periksa toast atau recent jobs untuk detail.";
    stepTargetMode = "";
    stepAssessmentMode = "";
    stepReviewMode = "";
  }

  if (button) {
    button.disabled = state.chainRunPending;
    button.textContent = buttonLabel;
    button.setAttribute("aria-busy", String(state.chainRunPending));
  }
  if (note) {
    note.textContent = noteLabel;
  }
  applyStepState(stepTarget, stepTargetMode);
  applyStepState(stepAssessment, stepAssessmentMode);
  applyStepState(stepReview, stepReviewMode);
}

function renderInsightTabs() {
  const tabs = Array.from(document.querySelectorAll("[data-insight-tab]"));
  const tabIds = tabs.map((button) => button.dataset.insightTab);
  if (!tabIds.includes(state.insightTab)) {
    state.insightTab = tabIds.includes("console") ? "console" : (tabIds[0] || "console");
  }

  tabs.forEach((button) => {
    button.classList.toggle("is-active", button.dataset.insightTab === state.insightTab);
  });
  document.querySelectorAll("[data-insight-panel]").forEach((panel) => {
    panel.classList.toggle("hidden", panel.dataset.insightPanel !== state.insightTab);
  });
  queueConsoleHeightSync();
}

function requestRangePassword() {
  const modal = $("#rangePasswordModal");
  const input = $("#rangePasswordInput");
  const confirmBtn = $("#confirmRangePasswordBtn");
  const cancelBtn = $("#cancelRangePasswordBtn");
  if (!modal || !input || !confirmBtn || !cancelBtn) {
    return Promise.resolve(window.prompt("Masukkan password simpan ranges") || "");
  }

  return new Promise((resolve) => {
    const cleanup = () => {
      modal.classList.add("hidden");
      modal.setAttribute("aria-hidden", "true");
      input.value = "";
      confirmBtn.removeEventListener("click", onConfirm);
      cancelBtn.removeEventListener("click", onCancel);
      modal.removeEventListener("click", onBackdrop);
      input.removeEventListener("keydown", onKeydown);
      document.removeEventListener("keydown", onEscape);
    };

    const onConfirm = () => {
      const value = input.value;
      cleanup();
      resolve(value);
    };

    const onCancel = () => {
      cleanup();
      resolve("");
    };

    const onBackdrop = (event) => {
      if (event.target === modal) {
        onCancel();
      }
    };

    const onKeydown = (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        onConfirm();
      }
    };

    const onEscape = (event) => {
      if (event.key === "Escape") {
        onCancel();
      }
    };

    modal.classList.remove("hidden");
    modal.setAttribute("aria-hidden", "false");
    confirmBtn.addEventListener("click", onConfirm);
    cancelBtn.addEventListener("click", onCancel);
    modal.addEventListener("click", onBackdrop);
    input.addEventListener("keydown", onKeydown);
    document.addEventListener("keydown", onEscape);
    window.setTimeout(() => input.focus(), 0);
  });
}

async function api(path, options = {}) {
  const normalizedPath = normalizeRequestPath(path);
  const requestUrl = normalizedPath.startsWith("/api/")
    ? buildRequestUrl(normalizedPath, await resolveApiBase())
    : buildRequestUrl(normalizedPath);
  const response = await fetch(requestUrl, {
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {})
    },
    ...options
  });

  if (response.status === 401) {
    let loginUrl = `/login?next=${encodeURIComponent(window.location.pathname + window.location.search)}`;
    try {
      const data = await response.json();
      if (data?.login_url) {
        loginUrl = data.login_url;
      }
    } catch (error) {
      // Abaikan dan gunakan fallback login URL.
    }
    window.location.href = loginUrl;
    throw new Error("Sesi login berakhir. Silakan masuk kembali.");
  }

  if (response.redirected && response.url.includes("/login")) {
    window.location.href = response.url;
    throw new Error("Sesi login berakhir. Silakan masuk kembali.");
  }

  if (!response.ok) {
    let message = `HTTP ${response.status}`;
    try {
      const data = await response.json();
      message = data.detail || message;
    } catch (error) {
      // Keep fallback.
    }
    throw new Error(message);
  }

  const contentType = response.headers.get("content-type") || "";
  if (!contentType.includes("application/json")) {
    throw new Error("Respon backend tidak valid. Muat ulang halaman dan login kembali bila diperlukan.");
  }

  return response.json();
}

async function apiOptional(path, fallback = null, options = {}) {
  try {
    return await api(path, options);
  } catch (error) {
    return fallback;
  }
}

function groupModulesByPhase(modules) {
  return modules.reduce((accumulator, module) => {
    const key = module.phase_id;
    if (!accumulator[key]) {
      accumulator[key] = {
        label: module.phase_label,
        order: module.phase_order,
        modules: []
      };
    }
    accumulator[key].modules.push(module);
    return accumulator;
  }, {});
}

function moduleUiPriority(module) {
  const priority = {
    "sensitive-file-discovery": -20,
    "read-sensitive-file": -20,
    "baseline-nikto-review": -10,
    "recon-service-scan": -10
  };
  return priority[module?.id] ?? 0;
}

function severityBadgeMarkup(key, value) {
  return `<span class="severity-pill severity-${key}">${key} ${value}</span>`;
}

function chipMarkup(items = [], className = "") {
  return items.map((item) => `<span class="${className}">${item}</span>`).join("");
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function currentTargetValue() {
  return $("#targetInput")?.value?.trim() || "TARGET";
}

function selectedRiskMode() {
  return riskModeForProfile(selectedModuleProfile());
}

function currentOperatorName() {
  return $("#operatorNameInput")?.value?.trim() || "operator";
}

function currentTicketRef() {
  return $("#ticketRefInput")?.value?.trim() || "";
}

function activeAssessmentRiskMode() {
  return state.activeAssessment?.risk_mode || selectedRiskMode();
}

function riskModeForProfile(profile) {
  if (profile === "deep") return "intrusive";
  if (profile === "balanced") return "deep";
  return "safe";
}

function profileForRiskMode(riskMode) {
  if (riskMode === "intrusive") return "deep";
  if (riskMode === "deep") return "balanced";
  return "fast";
}

function currentTargetKind() {
  return $("#targetKindSelect")?.value === "url" ? "url" : "ip";
}

const INTERACTIVE_TOOL_LABELS = new Set(["metasploit", "ssh", "smbclient", "rpcclient"]);

function isInteractiveToolLabel(label = "") {
  return INTERACTIVE_TOOL_LABELS.has(String(label || "").trim().toLowerCase());
}

function selectedChainPreset() {
  return selectedRiskMode() === "intrusive" ? "intrusive-validation" : "full-chain-default";
}

function severityClass(label) {
  const value = String(label || "info").toLowerCase();
  if (value === "kritis") return "critical";
  if (value === "tinggi") return "high";
  if (value === "sedang") return "medium";
  if (value === "rendah") return "low";
  return "info";
}

function remediationPromptDefaults(findingId) {
  const finding = (state.activeFindings || []).find((item) => item.id === findingId) || {};
  const metadata = finding.metadata || {};
  return {
    owner: metadata.owner || "",
    due_date: metadata.due_date || "",
    sla: metadata.sla || ""
  };
}

function renderApprovalsDashboard() {
  const container = $("#approvalsDashboardList");
  const label = $("#approvalsDashboardLabel");
  if (!container) return;
  if (label) label.textContent = "0 active / 0 expired";
  container.innerHTML = '<p class="empty-jobs">Approval flow nonaktif untuk workflow harian.</p>';
}

function renderAssessmentSummary() {
  const container = $("#assessmentSummary");
  if (!container) return;
  const assessment = state.activeAssessment;
  if (!assessment) {
    container.textContent = "Belum ada assessment aktif.";
    return;
  }

  const recommendations = state.activeRecommendations?.recommended_modules || [];
  const detail = state.activeAssessmentDetail || {};
  const severitySummary = state.activeFindingSummary?.severity_summary || {};
  const diffSummary = detail.diff_summary || {};
  const remediationSummary = detail.remediation_summary || {};
  const driftSummary = detail.drift_summary || {};
  const severityMarkup = Object.entries(severitySummary)
    .filter(([, count]) => Number(count || 0) > 0)
    .map(([label, count]) => `<span class="severity-pill severity-${severityClass(label)}">${label}: ${count}</span>`)
    .join(" ") || '<span class="severity-pill severity-info">Belum ada finding</span>';
  const recommendationMarkup = recommendations.length
    ? `<ul>${recommendations.map((item) => `<li><strong>${item.phase_label}</strong> - ${item.title} <em>(${item.risk_class})</em></li>`).join("")}</ul>`
    : "<div>Tidak ada rekomendasi tambahan. Coverage assessment sudah penuh atau belum ada data.</div>";
  container.innerHTML = `
    <div><strong>ID:</strong> ${assessment.id}</div>
    <div><strong>Target:</strong> ${assessment.target}</div>
    <div><strong>Target Kind:</strong> ${assessment.target_kind || "ip"}</div>
    <div><strong>Mode:</strong> ${assessment.risk_mode}</div>
    <div><strong>Operator:</strong> ${assessment.operator_name}</div>
    <div><strong>Ticket:</strong> ${assessment.ticket_ref || "-"}</div>
    <div><strong>Workspace:</strong> ${detail.workspace || assessment.metadata?.workspace || "-"}</div>
    <div><strong>Jobs terkait:</strong> ${detail.job_count || 0}</div>
    <div><strong>Coverage:</strong> ${state.activeRecommendations?.completed_modules || 0}/${state.activeRecommendations?.total_chain_modules || 0}</div>
    <div><strong>Normalized findings:</strong> ${detail.finding_count || 0}</div>
    <div><strong>Severity summary:</strong> ${severityMarkup}</div>
    <div><strong>Diff vs assessment sebelumnya:</strong> new ${diffSummary.new || 0}, recurring ${diffSummary.recurring || 0}, resolved ${diffSummary.resolved || 0}</div>
    <div><strong>Drift exposure:</strong> port baru ${driftSummary.open_ports?.new || 0}, path baru ${driftSummary.paths?.new || 0}, subdomain/DNS baru ${(driftSummary.subdomains?.new || 0) + (driftSummary.dns_records?.new || 0)}</div>
    <div><strong>Remediation tracking:</strong> owner ${remediationSummary.assigned || 0}, due date ${remediationSummary.with_due_date || 0}, overdue ${remediationSummary.overdue_open || 0}</div>
    <div><strong>Next recommended modules:</strong>${recommendationMarkup}</div>
  `;
}

function renderAssessmentFindings() {
  const container = $("#assessmentFindings");
  const label = $("#assessmentFindingsLabel");
  if (!container) return;
  const findings = Array.isArray(state.activeFindings) ? state.activeFindings : [];
  const diff = state.activeDiff || { new: [], recurring: [], resolved: [] };
  const newIds = new Set((diff.new || []).map((item) => item.id));
  const recurringIds = new Set((diff.recurring || []).map((item) => item.id));
  if (label) label.textContent = `${findings.length} findings`;
  if (!findings.length) {
    container.innerHTML = '<p class="empty-jobs">Belum ada normalized finding pada assessment aktif.</p>';
    return;
  }
  container.innerHTML = findings.map((finding) => {
    const diffLabel = newIds.has(finding.id) ? 'new' : recurringIds.has(finding.id) ? 'recurring' : 'current';
    return `
    <article class="evidence-item severity-border-${severityClass(finding.severity)}">
      <div class="evidence-head finding-head-wrap">
        <strong>${finding.title}</strong>
        <div class="finding-pill-row">
          <span class="severity-pill severity-${severityClass(finding.severity)}">${finding.severity}</span>
          <span class="severity-pill severity-info">${finding.status || 'open'}</span>
          <span class="severity-pill severity-low">${diffLabel}</span>
          <span class="severity-pill severity-medium">${(finding.metadata || {}).rule_id || 'generic'}</span>
        </div>
      </div>
      <p class="evidence-detail">${Array.isArray(finding.description) && finding.description.length ? finding.description[0] : 'Temuan telah dinormalisasi dari evidence assessment.'}</p>
      ${(Array.isArray(finding.evidence_lines) ? finding.evidence_lines : []).slice(0, 3).map((line) => `<p class="evidence-detail evidence-detail-code">- ${line}</p>`).join('')}
      <div class="finding-actions-row">
        <button class="ghost-button compact" type="button" data-finding-action="open" data-finding-id="${finding.id}">Open</button>
        <button class="ghost-button compact" type="button" data-finding-action="accepted-risk" data-finding-id="${finding.id}">Accepted Risk</button>
        <button class="ghost-button compact" type="button" data-finding-action="mitigated" data-finding-id="${finding.id}">Mitigated</button>
        <button class="ghost-button compact" type="button" data-finding-action="false-positive" data-finding-id="${finding.id}">False Positive</button>
      </div>
      <small>${finding.phase_label || '-'} - ${finding.module_title || '-'} - owner: ${(finding.metadata || {}).owner || '-'} - due: ${(finding.metadata || {}).due_date || '-'} - sla: ${(finding.metadata || {}).sla || '-'} - note: ${(finding.metadata || {}).status_note || '-'}</small>
    </article>`;
  }).join('');
}

function renderApprovalQueue() {
  const card = $("#approvalQueueCard");
  const container = $("#approvalQueueList");
  const label = $("#approvalQueueLabel");
  if (!container) return;
  if (label) label.textContent = "0 pending";
  if (card) card.classList.add("hidden");
  container.innerHTML = '<p class="empty-jobs">Approval queue dinonaktifkan.</p>';
}

function formatDateLabel(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString("id-ID", {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit"
  });
}

function renderChainPresetSelect() {
  const select = $("#chainPresetSelect");
  if (!select) return;
  const presets = Array.isArray(state.chainPresets) ? state.chainPresets : [];
  if (!presets.length) {
    select.innerHTML = '<option value="full-chain-default">full-chain-default</option>';
    return;
  }
  const activeValue = selectedChainPreset();
  select.innerHTML = presets.map((preset) => `
    <option value="${preset.id}" ${preset.id === activeValue ? "selected" : ""}>${preset.label}</option>
  `).join("");
}

function renderChainPresetList() {
  const container = $("#chainPresetList");
  if (!container) return;
  const presets = Array.isArray(state.chainPresets) ? state.chainPresets : [];
  if (!presets.length) {
    container.innerHTML = '<p class="empty-jobs">Belum ada chain preset.</p>';
    return;
  }
  const activePreset = selectedChainPreset();
  container.innerHTML = presets.map((preset) => `
    <article class="preset-item${preset.id === activePreset ? " is-active" : ""}">
      <div class="preset-item-head">
        <strong>${preset.label}</strong>
        <span class="severity-pill severity-info">${preset.recommended_risk_mode || "safe"}</span>
      </div>
      <p>${preset.description}</p>
      <div class="preset-item-meta">
        <span class="module-chip module-chip-muted">${preset.id}</span>
        <span class="module-chip module-chip-soft">${(preset.priority_module_ids || []).length} priority modules</span>
      </div>
    </article>
  `).join("");
}

function toolCategoryForLabel(label) {
  const tool = String(label || "").toLowerCase();
  if (["nmap", "masscan", "rustscan", "naabu", "ncat", "socat"].some((item) => tool.includes(item))) return "Discovery";
  if (["subfinder", "dnsx", "dnsrecon", "fierce", "chaos", "amass", "dig", "shuffledns"].some((item) => tool.includes(item))) return "DNS & Surface";
  if (["httpx", "whatweb", "wappalyzer", "nikto", "nuclei", "ffuf", "gobuster", "katana", "urlscan", "curl"].some((item) => tool.includes(item))) return "Web Assessment";
  if (["sqlmap", "dalfox", "xsstrike", "commix", "jwt", "wpscan"].some((item) => tool.includes(item))) return "Validation";
  if (["hydra", "medusa", "crowbar", "kerbrute", "john", "hashcat", "ncrack", "patator"].some((item) => tool.includes(item))) return "Credential";
  if (["metasploit", "searchsploit", "beef", "bettercap", "responder", "mitm6", "bloodhound", "impacket", "enum4linux", "mimikatz", "proxychains", "chisel", "ssh", "smbclient", "ldapsearch", "rpcclient"].some((item) => tool.includes(item))) return "Post Exploitation";
  if (["openssl", "sslyze", "tcpdump", "wireshark", "zeek", "suricata", "sigma", "sysmon", "yara", "strings", "file", "sha256sum"].some((item) => tool.includes(item))) return "Detection & Forensics";
  if (["jq", "pandoc", "graphviz", "markdown", "mailparser", "swaks", "otp-review", "killchain", "ngrok"].some((item) => tool.includes(item))) return "Utility";
  return "Other";
}

function toolPurposeCopy(category) {
  const mapping = {
    "Discovery": "Dipakai untuk memastikan host hidup, membuka port map, dan membangun baseline exposure sebelum validasi lebih dalam.",
    "DNS & Surface": "Dipakai saat kita perlu memperluas scope permukaan, host, subdomain, atau jejak layanan yang terhubung ke target.",
    "Web Assessment": "Dipakai untuk fingerprinting, crawling, content discovery, dan observasi misconfiguration web secara cepat.",
    "Validation": "Dipakai ketika perlu menguji hipotesis temuan spesifik seperti injection, auth issue, atau komponen rentan.",
    "Credential": "Dipakai untuk mengukur risiko paparan kredensial atau validasi account attack path secara terkontrol.",
    "Post Exploitation": "Dipakai pada fase lanjutan untuk eksploitasi, pivot, lateral movement, atau emulasi attacker pasca-akses.",
    "Detection & Forensics": "Dipakai untuk melihat jejak, paket, indikator pertahanan, dan artefak yang berguna untuk hunting atau evidence.",
    "Utility": "Dipakai sebagai alat bantu pengolahan data, dokumentasi, parsing, dan workflow pendukung operator.",
    "Other": "Dipakai sebagai tool pendukung yang belum masuk kelompok dominan tertentu."
  };
  return mapping[category] || mapping.Other;
}

function toolUsageModules(label) {
  return (state.modules || [])
    .filter((module) => Array.isArray(module.tooling) && module.tooling.includes(label))
    .map((module) => ({
      id: module.id,
      title: module.title,
      phaseId: module.phase_id,
      phase: module.phase_label,
      risk: module.risk
    }));
}

function selectedToolSortMode() {
  return $("#toolSortSelect")?.value || state.toolSortMode || "usage";
}

function filteredToolCatalogEntries() {
  const toolMap = state.toolsStatus?.tools || {};
  const rows = Array.isArray(state.toolingCatalog) && state.toolingCatalog.length
    ? state.toolingCatalog.map((entry) => [entry.label, entry.status || toolMap[entry.label] || {}])
    : Object.entries(toolMap);

  const matchesFilter = (status) => {
    if (state.toolStatusFilter === "installed") return status?.installed === true;
    if (state.toolStatusFilter === "missing") return status?.installed === false;
    if (state.toolStatusFilter === "conceptual") return status?.kind === "conceptual";
    return true;
  };

  const matchesSearch = (label, status, category) => {
    const needle = String(state.toolSearchQuery || "").trim().toLowerCase();
    if (!needle) return true;
    const haystack = [label, category, status?.command, status?.kind].filter(Boolean).join(" ").toLowerCase();
    return haystack.includes(needle);
  };

  return rows
    .map(([label, status]) => ({ label, status, category: toolCategoryForLabel(label) }))
    .filter((entry) => matchesFilter(entry.status) && matchesSearch(entry.label, entry.status, entry.category))
    .sort((a, b) => {
      const aUsage = toolUsageModules(a.label).length;
      const bUsage = toolUsageModules(b.label).length;
      const installedRank = (entry, mode) => {
        if (mode === "missing") return entry.status?.installed === false ? 0 : entry.status?.kind === "conceptual" ? 2 : 1;
        return entry.status?.installed === true ? 0 : entry.status?.kind === "conceptual" ? 2 : 1;
      };
      const sortMode = selectedToolSortMode();
      if (sortMode === "usage") return bUsage - aUsage || a.category.localeCompare(b.category) || a.label.localeCompare(b.label);
      if (sortMode === "installed" || sortMode === "missing") {
        return installedRank(a, sortMode) - installedRank(b, sortMode) || bUsage - aUsage || a.label.localeCompare(b.label);
      }
      return a.label.localeCompare(b.label);
    });
}

function toolReferenceContext(status) {
  const target = currentTargetValue();
  const domainTarget = currentTargetKind() === "ip" || currentTargetKind() === "cidr" ? target : target;
  const httpTarget = currentTargetKind() === "url"
    ? target
    : `http://${currentTargetKind() === "ip" || currentTargetKind() === "cidr" ? target : domainTarget}`;
  return {
    target,
    domainTarget,
    httpTarget,
    command: status?.command || "tool",
    riskMode: selectedRiskMode()
  };
}

function fallbackToolReference(label, status, category) {
  const context = toolReferenceContext(status);
  const primaryCommand = status?.command || label;
  const usageModules = toolUsageModules(label);
  const usageCopy = usageModules.length
    ? `${usageModules.length} modul memakai ${label}. Fokusnya ada pada fase ${[...new Set(usageModules.map((item) => item.phase))].join(", ")}.`
    : `${label} belum dipetakan langsung ke modul katalog, jadi paling pas dipakai sebagai alat bantu eksplorasi atau verifikasi manual.`;

  const categoryPlaybooks = {
    "Discovery": [
      { title: "Quick Discovery", tone: "baseline", description: "Mulai dengan enumerasi ringan untuk memastikan host dan port utama.", command: `${primaryCommand} ${context.target}` },
      { title: "Safer Validation", tone: "safe", description: "Lihat opsi aman sebelum menambah agresivitas scan.", command: `${primaryCommand} --help` }
    ],
    "DNS & Surface": [
      { title: "Quick Enumeration", tone: "baseline", description: "Mulai dari domain aktif lalu perluas permukaan secara bertahap.", command: `${primaryCommand} -d ${context.domainTarget}` },
      { title: "Review Options", tone: "safe", description: "Cek syntax dan mode yang tersedia sebelum menjalankan wordlist besar.", command: `${primaryCommand} --help` }
    ],
    "Web Assessment": [
      { title: "Quick Baseline", tone: "baseline", description: "Lakukan fingerprinting web ringan pada target aktif.", command: `${primaryCommand} ${context.httpTarget}` },
      { title: "Review Options", tone: "safe", description: "Pastikan flag yang dipakai sesuai scope dan risk mode.", command: `${primaryCommand} --help` }
    ],
    "Validation": [
      { title: "Targeted Check", tone: "baseline", description: "Gunakan hanya setelah ada hipotesis temuan yang cukup kuat.", command: `${primaryCommand} --help` },
      { title: "Operator Guardrail", tone: "safe", description: "Cek lagi approval dan risk mode sebelum validasi agresif.", command: `echo "Risk mode: ${context.riskMode}"` }
    ],
    "Credential": [
      { title: "Dry Review", tone: "baseline", description: "Mulai dari mode bantuan atau audit lokal sebelum brute-force terkontrol.", command: `${primaryCommand} --help` },
      { title: "Operator Guardrail", tone: "safe", description: "Pastikan lockout policy target dipahami sebelum validasi kredensial.", command: `echo "Review lockout policy sebelum memakai ${label}"` }
    ],
    "Post Exploitation": [
      { title: "Operator Prep", tone: "baseline", description: "Tool fase lanjutan perlu konteks akses, scope, dan approval yang jelas.", command: `${primaryCommand} --help` },
      { title: "Guardrail", tone: "safe", description: "Gunakan hanya saat assessment memang mengizinkan validasi lanjut.", command: `echo "Pastikan approval tersedia untuk ${label}"` }
    ],
    "Detection & Forensics": [
      { title: "Quick Collection", tone: "baseline", description: "Ambil baseline artefak atau traffic lebih dulu sebelum analisis mendalam.", command: `${primaryCommand} --help` },
      { title: "Operator Note", tone: "safe", description: "Verifikasi format output agar mudah diimpor ke evidence parser.", command: `echo "Simpan output ${label} ke workspace assessment"` }
    ],
    "Utility": [
      { title: "Quick Use", tone: "baseline", description: "Tool utilitas biasanya dipakai sebagai pendukung parsing, relay, atau dokumentasi.", command: `${primaryCommand} --help` },
      { title: "Workflow Hint", tone: "safe", description: "Cek contoh command dan integrasikan ke module output bila perlu.", command: `${primaryCommand} --version` }
    ],
    "Other": [
      { title: "Primary Command", tone: "baseline", description: "Mulai dari alias utama yang terdeteksi di backend.", command: primaryCommand },
      { title: "Review Options", tone: "safe", description: "Buka bantuan tool untuk melihat mode yang tersedia.", command: `${primaryCommand} --help` }
    ]
  };

  return {
    commands: categoryPlaybooks[category] || categoryPlaybooks.Other,
    usage: usageCopy,
    notes: [
      "Sesuaikan wordlist, rate, dan concurrency dengan scope lab.",
      "Simpan output mentah ke workspace assessment agar evidence tetap dapat ditelusuri.",
      status?.installed === false ? "Status backend menunjukkan tool ini belum tersedia di environment." : "Status backend menunjukkan binary terdeteksi atau tool bersifat wrapper."
    ]
  };
}

function toolReferenceData(label, status) {
  const tool = String(label || "").toLowerCase();
  const category = toolCategoryForLabel(label);
  const context = toolReferenceContext(status);
  const explicit = {
    nmap: {
      commands: [
        { title: "Quick Port Baseline", tone: "baseline", description: "Cocok untuk melihat port penting lebih dulu tanpa sweep penuh.", command: `nmap -Pn -sV -T4 ${context.target}` },
        { title: "Safe Web Triage", tone: "safe", description: "Kalau scope hati-hati, fokuskan ke port web dan simpan output normal.", command: `nmap -Pn -p 80,443,8080,8443 --open -sV ${context.target} -oN nmap-web.txt` },
        { title: "Deep Service Review", tone: "advanced", description: "Pakai hanya saat butuh service fingerprint lebih lengkap.", command: `nmap -Pn -sC -sV -O ${context.target} -oA nmap-deep` }
      ],
      notes: ["Mulai dari `-Pn` bila ICMP diblokir.", "Gunakan `-oA` saat hasil akan dipakai modul lain atau dibandingkan antar assessment.", "Jaga `-T4` hanya untuk subnet yang memang diizinkan."]
    },
    masscan: {
      commands: [
        { title: "Fast Port Sweep", tone: "baseline", description: "Untuk baseline port exposure dengan rate terkontrol.", command: `masscan ${context.target} -p1-1000 --rate 1000` },
        { title: "Conservative Rate", tone: "safe", description: "Turunkan laju ketika target sensitif atau jaringan terbatas.", command: `masscan ${context.target} -p80,443,445,3389 --rate 300` }
      ],
      notes: ["Masscan cepat tetapi mudah bising.", "Selalu turunkan `--rate` pada scope internal yang sensitif.", "Validasi hasil penting dengan `nmap`."]
    },
    rustscan: {
      commands: [
        { title: "Fast Port Discovery", tone: "baseline", description: "Bagus untuk buka peta port cepat lalu chaining ke nmap.", command: `rustscan -a ${context.target} --ulimit 5000` },
        { title: "Focused Range", tone: "safe", description: "Batasi port bila target tidak butuh sweep penuh.", command: `rustscan -a ${context.target} -r 1-1000` }
      ],
      notes: ["Rustscan cocok sebagai pre-scan.", "Bila ada hasil menarik, lanjutkan ke `nmap -sV`."]
    },
    subfinder: {
      commands: [
        { title: "Passive Subdomain Enum", tone: "baseline", description: "Mulai dari enumerasi pasif untuk memperluas permukaan domain.", command: `subfinder -d ${context.domainTarget} -silent` },
        { title: "Save Resolved Hosts", tone: "safe", description: "Simpan hasil yang akan dipakai httpx atau dnsx.", command: `subfinder -d ${context.domainTarget} -all -o subfinder.txt` }
      ],
      notes: ["Cocok dikombinasikan dengan `httpx` atau `dnsx`.", "Gunakan mode pasif lebih dulu untuk mengurangi noise."]
    },
    amass: {
      commands: [
        { title: "Passive Mapping", tone: "baseline", description: "Bangun baseline permukaan subdomain dan ASN secara bertahap.", command: `amass enum -passive -d ${context.domainTarget}` },
        { title: "Deeper Enum", tone: "advanced", description: "Lebih lengkap, tetapi lebih berat dan perlu review sumber data.", command: `amass enum -src -ip -d ${context.domainTarget} -o amass.txt` }
      ],
      notes: ["Bagus untuk ekspansi asset.", "Hindari mode terlalu agresif bila belum ada kebutuhan."]
    },
    dnsx: {
      commands: [
        { title: "Resolve Candidate Hosts", tone: "baseline", description: "Validasi host hasil enumerasi agar cepat terlihat yang hidup.", command: `dnsx -l subfinder.txt -resp -a -aaaa -cname` },
        { title: "Direct Probe", tone: "safe", description: "Pakai untuk domain tunggal saat perlu cek record dasar.", command: `echo ${context.domainTarget} | dnsx -silent -resp` }
      ],
      notes: ["Sangat cocok sebagai filter setelah subdomain enum.", "Simpan hasil resolved untuk pipeline berikutnya."]
    },
    httpx: {
      commands: [
        { title: "Quick HTTP Probe", tone: "baseline", description: "Cek host mana yang benar-benar menyajikan service web.", command: `echo ${context.domainTarget} | httpx -title -tech-detect -status-code` },
        { title: "Batch From File", tone: "safe", description: "Pakailah file host hasil subfinder agar alur kerja lebih rapi.", command: `httpx -l subfinder.txt -title -tech-detect -follow-redirects -o httpx.txt` }
      ],
      notes: ["Sangat baik untuk triage awal sebelum nuclei atau ffuf.", "Gunakan output file agar bisa dipakai ulang."]
    },
    nuclei: {
      commands: [
        { title: "Quick Exposure Check", tone: "baseline", description: "Jalankan template severity rendah-menengah lebih dulu.", command: `nuclei -u ${context.httpTarget} -severity low,medium,high` },
        { title: "Safe Template Scope", tone: "safe", description: "Batasi template agar tetap relevan dengan stack target.", command: `nuclei -u ${context.httpTarget} -tags exposure,misconfig -rl 50` },
        { title: "Batch Scan", tone: "advanced", description: "Jalankan terhadap daftar host setelah triage web selesai.", command: `nuclei -l httpx.txt -severity medium,high,critical -o nuclei.txt` }
      ],
      notes: ["Selalu review template yang dipakai.", "Batasi rate dengan `-rl` di lingkungan sensitif.", "Validasi finding penting secara manual."]
    },
    ffuf: {
      commands: [
        { title: "Directory Discovery", tone: "baseline", description: "Gunakan untuk menemukan route dan endpoint umum.", command: `ffuf -u ${context.httpTarget}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc all -fs 0` },
        { title: "Conservative Content Fuzz", tone: "safe", description: "Mulai dengan thread rendah dan filter status umum.", command: `ffuf -u ${context.httpTarget}/FUZZ -w /usr/share/wordlists/dirb/common.txt -t 20 -fc 404` }
      ],
      notes: ["Perhatikan baseline size/words/lines agar filtering akurat.", "Mulai dengan thread rendah pada aplikasi rapuh."]
    },
    gobuster: {
      commands: [
        { title: "Dir Enumeration", tone: "baseline", description: "Versi aman untuk target yang memberi respons wildcard atau fallback page.", command: `gobuster dir -u ${context.httpTarget} -w /usr/share/wordlists/dirb/common.txt -k --wildcard` },
        { title: "Vhost Enumeration", tone: "advanced", description: "Pakai saat ada indikasi virtual host tambahan.", command: `gobuster vhost -u ${context.httpTarget} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain` }
      ],
      notes: ["Jika server membalas 200 untuk path acak, gunakan `--wildcard` atau `--exclude-length <ukuran>`.", "Untuk baseline yang lebih stabil di target wildcard, prioritaskan ffuf dengan auto-calibration (`-ac`)."]
    },
    katana: {
      commands: [
        { title: "Quick Crawl", tone: "baseline", description: "Bangun daftar URL cepat untuk dipakai tool lain.", command: `katana -u ${context.httpTarget} -d 2 -silent` },
        { title: "Save URLs", tone: "safe", description: "Simpan endpoint hasil crawl untuk workflow berikutnya.", command: `katana -u ${context.httpTarget} -d 3 -o katana.txt` }
      ],
      notes: ["Cocok dipakai sebelum dalfox atau nuclei.", "Batasi depth supaya crawl tetap terkendali."]
    },
    whatweb: {
      commands: [
        { title: "Fingerprint Web Stack", tone: "baseline", description: "Lihat teknologi web yang muncul tanpa crawling agresif.", command: `whatweb ${context.httpTarget}` },
        { title: "Verbose Review", tone: "safe", description: "Tambah detail hanya bila memang diperlukan.", command: `whatweb -a 3 ${context.httpTarget}` }
      ],
      notes: ["Gunakan untuk baseline technology stack.", "Temuan fingerprint sebaiknya divalidasi silang dengan header atau source HTML."]
    },
    nikto: {
      commands: [
        { title: "Quick Web Misconfig Review", tone: "baseline", description: "Cocok untuk baseline exposure di web server yang sudah jelas scope-nya.", command: `nikto -h ${context.httpTarget}` },
        { title: "Port-Specific Check", tone: "safe", description: "Pakai saat service web ada di port non-standar.", command: `nikto -h ${context.target} -p 8080` }
      ],
      notes: ["Nikto cukup noisy, jadi pakai setelah web target dipastikan relevan.", "Hasil perlu divalidasi manual."]
    },
    curl: {
      commands: [
        { title: "Header Triage", tone: "baseline", description: "Paling cepat untuk melihat response dan header inti.", command: `curl -I ${context.httpTarget}` },
        { title: "Verbose Request", tone: "safe", description: "Lihat redirect, TLS, dan negotiation saat debugging.", command: `curl -vk ${context.httpTarget}` }
      ],
      notes: ["Sangat berguna untuk verifikasi manual hasil tool lain.", "Simpan request penting ke evidence."]
    },
    sqlmap: {
      commands: [
        { title: "Targeted Param Check", tone: "baseline", description: "Gunakan hanya pada URL/parameter yang sudah punya indikasi injeksi.", command: `sqlmap -u "${context.httpTarget}/item?id=1" -p id --batch --risk=1 --level=1` },
        { title: "Cookie Session Validation", tone: "advanced", description: "Pakai bila endpoint butuh autentikasi dan approval sudah jelas.", command: `sqlmap -u "${context.httpTarget}/app.php?id=1" --cookie="SESSION=lab" --batch --risk=2 --level=3` }
      ],
      notes: ["Jangan dipakai membabi buta ke semua URL.", "Selalu mulai dari risk dan level rendah.", "Pastikan approval untuk pengujian injection aktif."]
    },
    dalfox: {
      commands: [
        { title: "Single URL XSS Check", tone: "baseline", description: "Cocok untuk parameter yang sudah dicurigai reflektif.", command: `dalfox url "${context.httpTarget}/search?q=test"` },
        { title: "Pipe From URL List", tone: "advanced", description: "Jalankan setelah ada daftar endpoint hasil crawl.", command: `cat katana.txt | dalfox pipe` }
      ],
      notes: ["Sangat efektif setelah crawling.", "Review payload dan hasil PoC sebelum menyimpulkan impact."]
    },
    xsstrike: {
      commands: [
        { title: "Focused XSS Test", tone: "baseline", description: "Alternatif saat ingin eksplor payload XSS lebih interaktif.", command: `python xsstrike.py -u "${context.httpTarget}/search?q=test"` },
        { title: "POST Data Review", tone: "advanced", description: "Pakai untuk parameter POST yang sudah teridentifikasi.", command: `python xsstrike.py -u ${context.httpTarget}/login --data "username=test&next=/home"` }
      ],
      notes: ["Lebih cocok untuk validasi tertarget.", "Jangan mulai dari seluruh aplikasi."]
    },
    wpscan: {
      commands: [
        { title: "WordPress Baseline", tone: "baseline", description: "Gunakan saat fingerprint menunjukkan WordPress.", command: `wpscan --url ${context.httpTarget} --enumerate vp,vt,cb` },
        { title: "API Token Mode", tone: "advanced", description: "Tambah konteks plugin/theme exposure bila token tersedia.", command: `wpscan --url ${context.httpTarget} --api-token YOUR_TOKEN` }
      ],
      notes: ["Jalankan hanya bila CMS WordPress terkonfirmasi.", "Batasi enumerasi sesuai kebutuhan."]
    },
    hydra: {
      commands: [
        { title: "Controlled Credential Check", tone: "baseline", description: "Validasi kecil pada service yang memang diizinkan untuk diuji.", command: `hydra -L users.txt -P passwords.txt ssh://${context.target} -t 4 -f` },
        { title: "HTTP Form Validation", tone: "advanced", description: "Gunakan bila login form sudah dipahami dan lockout policy aman.", command: `hydra -L users.txt -P passwords.txt ${context.domainTarget} http-post-form "/login:user=^USER^&pass=^PASS^:F=invalid"` }
      ],
      notes: ["Wajib pahami lockout policy lebih dulu.", "Mulai dengan thread rendah dan sample credential kecil."]
    },
    medusa: {
      commands: [
        { title: "Service Login Validation", tone: "baseline", description: "Alternatif brute-force terkontrol untuk service tertentu.", command: `medusa -h ${context.target} -U users.txt -P passwords.txt -M ssh -t 4` },
        { title: "Single User Audit", tone: "safe", description: "Lebih aman saat memvalidasi satu akun yang disetujui.", command: `medusa -h ${context.target} -u admin -P passwords.txt -M smbnt -t 2` }
      ],
      notes: ["Turunkan paralelisme di lingkungan sensitif.", "Utamakan validasi akun yang memang diizinkan."]
    },
    kerbrute: {
      commands: [
        { title: "User Enumeration", tone: "baseline", description: "Cocok untuk validasi user AD pada scope internal berizin.", command: `kerbrute userenum -d ${context.domainTarget} users.txt --dc ${context.target}` },
        { title: "Password Spray", tone: "advanced", description: "Pakai sangat hati-hati dengan approval dan window yang disetujui.", command: `kerbrute passwordspray -d ${context.domainTarget} users.txt 'Spring2026!' --dc ${context.target}` }
      ],
      notes: ["Risiko lockout tinggi.", "Pastikan ada approval eksplisit sebelum spray."]
    },
    john: {
      commands: [
        { title: "Offline Hash Review", tone: "baseline", description: "Gunakan untuk audit hash yang sudah sah diperoleh.", command: `john hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt` },
        { title: "Show Cracked", tone: "safe", description: "Tampilkan hasil tanpa mengulang cracking.", command: `john --show hashes.txt` }
      ],
      notes: ["Cocok untuk validasi impact offline.", "Simpan hash source dan hasil crack secara terpisah."]
    },
    hashcat: {
      commands: [
        { title: "Offline Crack Baseline", tone: "baseline", description: "Mulai dari mode hash yang sudah pasti dan wordlist kecil.", command: `hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt` },
        { title: "Sessioned Run", tone: "advanced", description: "Gunakan session agar pekerjaan panjang bisa dilanjutkan.", command: `hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt --session audit1 --status` }
      ],
      notes: ["Pastikan mode hash benar.", "Pantau penggunaan GPU/CPU agar tidak mengganggu host operator."]
    },
    responder: {
      commands: [
        { title: "LLMNR/NBT-NS Observe", tone: "baseline", description: "Gunakan pada segment internal yang memang mengizinkan emulasi poisoned response.", command: `responder -I eth0 -dwv` },
        { title: "Analyze Mode", tone: "safe", description: "Mode analisis lebih aman untuk memahami noise lebih dulu.", command: `responder -I eth0 -A` }
      ],
      notes: ["Jangan jalankan di luar segment lab yang disetujui.", "Mode analyze cocok sebagai langkah awal."]
    },
    bloodhound: {
      commands: [
        { title: "Open GUI", tone: "baseline", description: "Pakai setelah data AD berhasil dikumpulkan.", command: `bloodhound` },
        { title: "Prep Imported Data", tone: "safe", description: "Pastikan collector output tersimpan rapi sebelum analisis.", command: `echo "Import ZIP collector ke BloodHound UI"` }
      ],
      notes: ["BloodHound lebih kuat setelah data collector lengkap.", "Simpan snapshot graph per assessment."]
    },
    "bloodhound-python": {
      commands: [
        { title: "Collect AD Graph Data", tone: "baseline", description: "Kumpulkan data relasi AD secara terkontrol.", command: `bloodhound-python -d ${context.domainTarget} -u USER -p PASS -ns ${context.target} -c All` },
        { title: "Stealthier Collection", tone: "safe", description: "Batasi collection bila hanya butuh subset hubungan.", command: `bloodhound-python -d ${context.domainTarget} -u USER -p PASS -ns ${context.target} -c DCOnly` }
      ],
      notes: ["Gunakan akun yang memang diizinkan.", "Sesuaikan collection set dengan tujuan assessment."]
    },
    enum4linux: {
      commands: [
        { title: "SMB Enum Baseline", tone: "baseline", description: "Mulai dari enumerasi SMB standar pada host yang relevan.", command: `enum4linux -a ${context.target}` }
      ],
      notes: ["Bagus untuk triage awal Windows share exposure."]
    },
    "enum4linux-ng": {
      commands: [
        { title: "SMB Enum Baseline", tone: "baseline", description: "Versi lebih modern untuk enumerasi SMB.", command: `enum4linux-ng -A ${context.target}` }
      ],
      notes: ["Mulai dari mode all bila scope host tunggal jelas."]
    },
    impacket: {
      commands: [
        { title: "List Available Examples", tone: "baseline", description: "Impacket adalah koleksi banyak script; mulai dengan melihat contoh yang tersedia.", command: `ls /usr/share/doc/python3-impacket/examples` },
        { title: "Common SMB Exec Pattern", tone: "advanced", description: "Gunakan hanya bila approval pasca-akses sudah jelas.", command: `python /usr/share/doc/python3-impacket/examples/psexec.py DOMAIN/user:pass@${context.target}` }
      ],
      notes: ["Impacket bukan satu binary tunggal.", "Pilih script sesuai tujuan: enum, exec, relay, atau kerberos."]
    },
    smbclient: {
      commands: [
        { title: "Anonymous Share Check", tone: "baseline", description: "Cek apakah ada share terbuka tanpa kredensial.", command: `smbclient -L //${context.target}/ -N` },
        { title: "Authenticated Browse", tone: "safe", description: "Gunakan akun audit bila akses anonim ditolak.", command: `smbclient //${context.target}/share -U DOMAIN\\\\user` }
      ],
      notes: ["Simpan daftar share yang terpapar ke evidence.", "Validasi akses tulis dengan sangat hati-hati."]
    },
    ldapsearch: {
      commands: [
        { title: "Anonymous LDAP Query", tone: "baseline", description: "Validasi cepat apakah LDAP mengizinkan query dasar.", command: `ldapsearch -x -H ldap://${context.target} -s base` },
        { title: "Domain User Query", tone: "advanced", description: "Pakai untuk enumerasi tertarget bila bind account tersedia.", command: `ldapsearch -x -H ldap://${context.target} -D "user@${context.domainTarget}" -W -b "dc=target,dc=lab"` }
      ],
      notes: ["Sesuaikan base DN dengan domain aktual.", "Jangan simpan password bind di command history."]
    },
    rpcclient: {
      commands: [
        { title: "Null Session Check", tone: "baseline", description: "Lihat apakah RPC mengizinkan enumerasi tanpa auth.", command: `rpcclient -U '' -N ${context.target} -c enumdomusers` },
        { title: "Authenticated Query", tone: "safe", description: "Pakai akun audit untuk query lebih stabil.", command: `rpcclient -U DOMAIN\\\\user%Passw0rd ${context.target} -c enumdomusers` }
      ],
      notes: ["Query RPC klasik masih berguna untuk triage Windows.", "Perhatikan format escape domain user di shell."]
    },
    ssh: {
      commands: [
        { title: "Safe Banner Review", tone: "baseline", description: "Mulai dari koneksi interaktif biasa untuk melihat banner dan host key.", command: `ssh user@${context.target}` },
        { title: "Non-Interactive Check", tone: "safe", description: "Jalankan command ringan untuk verifikasi akses yang sudah sah.", command: `ssh user@${context.target} "whoami && hostname"` }
      ],
      notes: ["Jangan bypass host key di luar kebutuhan lab.", "Gunakan akun audit yang disetujui."]
    },
    openssl: {
      commands: [
        { title: "TLS Handshake Review", tone: "baseline", description: "Lihat sertifikat dan negosiasi TLS dengan cepat.", command: `openssl s_client -connect ${context.target}:443 -servername ${context.domainTarget}` },
        { title: "Certificate Extract", tone: "safe", description: "Ambil chain sertifikat untuk dianalisis lebih lanjut.", command: `echo | openssl s_client -connect ${context.target}:443 -servername ${context.domainTarget} 2>/dev/null | openssl x509 -noout -text` }
      ],
      notes: ["Cocok untuk verifikasi manual hasil sslyze atau scanner lain."]
    },
    sslyze: {
      commands: [
        { title: "TLS Config Audit", tone: "baseline", description: "Audit cepat konfigurasi TLS pada endpoint web.", command: `sslyze --regular ${context.target}:443` },
        { title: "SNI-Aware Audit", tone: "safe", description: "Tambahkan hostname jika sertifikat bergantung pada SNI.", command: `sslyze --regular --sni ${context.domainTarget} ${context.target}:443` }
      ],
      notes: ["Gunakan untuk baseline cryptography posture.", "Simpan output saat perlu dibandingkan antar assessment."]
    },
    dig: {
      commands: [
        { title: "Quick DNS Lookup", tone: "baseline", description: "Lihat record dasar domain target.", command: `dig ${context.domainTarget}` },
        { title: "Specific Record Check", tone: "safe", description: "Gunakan bila butuh MX/TXT/NS secara tertarget.", command: `dig ${context.domainTarget} TXT +short` }
      ],
      notes: ["Sangat cocok untuk validasi manual hasil enumerasi."]
    },
    tcpdump: {
      commands: [
        { title: "Interface Capture", tone: "baseline", description: "Tangkap traffic terbatas untuk bukti atau triage protokol.", command: `tcpdump -ni eth0 host ${context.target}` },
        { title: "Write PCAP", tone: "safe", description: "Simpan capture agar bisa dianalisis ulang di Wireshark.", command: `tcpdump -ni eth0 host ${context.target} -w capture-${context.target}.pcap` }
      ],
      notes: ["Selalu batasi filter agar capture tidak berlebihan.", "Pastikan penyimpanan PCAP sesuai kebijakan evidence."]
    },
    wireshark: {
      commands: [
        { title: "Open PCAP", tone: "baseline", description: "Buka hasil capture untuk analisis visual cepat.", command: `wireshark capture-${context.target}.pcap` },
        { title: "Live Interface", tone: "advanced", description: "Gunakan hanya bila host operator memang diizinkan live capture.", command: `wireshark` }
      ],
      notes: ["Lebih aman menganalisis PCAP hasil tcpdump dibanding langsung live capture."]
    },
    ngrok: {
      commands: [
        { title: "Expose Local Web Port", tone: "baseline", description: "Pakai saat perlu share service lokal untuk validasi terkontrol.", command: `ngrok http 8080` },
        { title: "Expose TCP Service", tone: "advanced", description: "Gunakan untuk service non-HTTP bila workflow memang membutuhkannya.", command: `ngrok tcp 22` }
      ],
      notes: ["Pastikan exposure ini memang sesuai policy lab.", "Catat URL tunnel ke assessment notes."]
    },
    jq: {
      commands: [
        { title: "Pretty Print JSON", tone: "baseline", description: "Sederhanakan inspeksi output JSON dari tool lain.", command: `cat evidence.json | jq` },
        { title: "Extract Key Fields", tone: "safe", description: "Ambil field penting untuk ringkasan cepat.", command: `cat evidence.json | jq '.findings[] | {title, severity}'` }
      ],
      notes: ["Sangat berguna untuk post-processing evidence parser."]
    },
    yara: {
      commands: [
        { title: "Scan File Set", tone: "baseline", description: "Cocok untuk validasi artefak atau sample yang sudah terkumpul.", command: `yara rules.yar sample.bin` },
        { title: "Recursive Folder Scan", tone: "advanced", description: "Gunakan pada koleksi file yang memang sudah di-scope.", command: `yara -r rules.yar ./samples` }
      ],
      notes: ["Pastikan rule source tepercaya.", "Simpan hit dan sample secara terpisah."]
    }
  };
  const defaultReference = fallbackToolReference(label, status, category);
  return {
    ...defaultReference,
    ...(explicit[tool] || {})
  };
}

function activeToolEntry() {
  const toolMap = state.toolsStatus?.tools || {};
  const rows = Array.isArray(state.toolingCatalog) && state.toolingCatalog.length
    ? state.toolingCatalog.map((entry) => ({ label: entry.label, status: entry.status || toolMap[entry.label] || {} }))
    : Object.entries(toolMap).map(([label, status]) => ({ label, status }));
  return rows.find((entry) => entry.label === state.selectedToolLabel) || null;
}

function closeToolInspectModal() {
  const modal = $("#toolInspectModal");
  if (!modal) return;
  modal.classList.add("hidden");
  modal.setAttribute("aria-hidden", "true");
}

function openImportParserModal() {
  const modal = $("#importParserModal");
  if (!modal) return;
  modal.classList.remove("hidden");
  modal.setAttribute("aria-hidden", "false");
}

function closeImportParserModal() {
  const modal = $("#importParserModal");
  if (!modal) return;
  modal.classList.add("hidden");
  modal.setAttribute("aria-hidden", "true");
}

function clearImportParserModal() {
  const content = $("#importContentInput");
  if (content) content.value = "";
  state.importResult = null;
  renderImportResult();
}

async function copyToolCommand(button) {
  const card = button.closest("[data-tool-command-card]");
  const input = card?.querySelector("[data-tool-command-input]");
  if (!input) return;
  await navigator.clipboard.writeText(input.value || "");
  button.textContent = "Copied";
  window.setTimeout(() => {
    button.textContent = "Copy";
  }, 1200);
}

async function executeToolCommandCard(button) {
  const card = button.closest("[data-tool-command-card]");
  const input = card?.querySelector("[data-tool-command-input]");
  const output = card?.querySelector("[data-tool-command-output]");
  const status = card?.querySelector("[data-tool-command-status]");
  const sudoField = card?.querySelector("[data-tool-sudo-field]");
  const sudoInput = card?.querySelector("[data-tool-sudo-password]");
  const toolName = card?.dataset.toolLabel || state.selectedToolLabel || "";
  if (!card || !input || !output || !status || !toolName) return;

  const command = String(input.value || "").trim();
  if (!command) {
    status.textContent = "Command kosong.";
    status.className = "tool-command-status error";
    output.classList.remove("hidden");
    output.textContent = "Isi command dulu sebelum dieksekusi.";
    return;
  }

  button.disabled = true;
  status.textContent = "Running...";
  status.className = "tool-command-status running";
  output.classList.remove("hidden");
  output.textContent = "Menjalankan command...";

  try {
    const result = await api("/api/tools/execute", {
      method: "POST",
      body: JSON.stringify({
        tool_name: toolName,
        command,
        sudo_password: sudoInput?.value || "",
        timeout: 180
      })
    });
    status.textContent = result.success
      ? (result.cached ? "Success (cached)" : "Success")
      : `Failed (${result.returncode})`;
    status.className = `tool-command-status ${result.success ? "success" : "error"}`;
    sudoField?.classList.toggle("hidden", !result.requires_sudo_password);
    const stdout = String(result.stdout || "").trim();
    const stderr = String(result.stderr || "").trim();
    output.textContent = [
      `$ ${result.command}`,
      stdout ? `\nSTDOUT\n${stdout}` : "",
      stderr ? `\nSTDERR\n${stderr}` : "",
      !stdout && !stderr ? "\nTidak ada output." : ""
    ].join("\n").trim();
  } catch (error) {
    status.textContent = "Failed";
    status.className = "tool-command-status error";
    output.textContent = error.message || "Eksekusi command gagal.";
  } finally {
    button.disabled = false;
  }
}

async function copyModuleCommand(button) {
  const card = button.closest("[data-module-command-card]");
  const command = card?.querySelector(".module-command")?.textContent || "";
  if (!command) return;
  await navigator.clipboard.writeText(command);
  button.textContent = "Copied";
  window.setTimeout(() => {
    button.textContent = "Copy";
  }, 1200);
}

async function executeModuleCommandCard(button) {
  const card = button.closest("[data-module-command-card]");
  const output = card?.querySelector("[data-module-command-output]");
  const status = card?.querySelector("[data-module-command-status]");
  const sudoField = card?.querySelector("[data-tool-sudo-field]");
  const sudoInput = card?.querySelector("[data-tool-sudo-password]");
  const toolName = card?.dataset.toolLabel || "";
  const command = String(card?.querySelector(".module-command")?.textContent || "").trim();
  if (!card || !output || !status || !toolName) return;

  if (!command) {
    status.textContent = "Command kosong.";
    status.className = "tool-command-status error";
    output.classList.remove("hidden");
    output.textContent = "Tidak ada command yang bisa dieksekusi.";
    return;
  }

  button.disabled = true;
  status.textContent = "Running...";
  status.className = "tool-command-status running";
  output.classList.remove("hidden");
  output.textContent = "Menjalankan command...";

  try {
    const result = await api("/api/tools/execute", {
      method: "POST",
      body: JSON.stringify({
        tool_name: toolName,
        command,
        sudo_password: sudoInput?.value || "",
        timeout: 180
      })
    });
    status.textContent = result.success
      ? (result.cached ? "Success (cached)" : "Success")
      : `Failed (${result.returncode})`;
    status.className = `tool-command-status ${result.success ? "success" : "error"}`;
    sudoField?.classList.toggle("hidden", !result.requires_sudo_password);
    const stdout = String(result.stdout || "").trim();
    const stderr = String(result.stderr || "").trim();
    output.textContent = [
      `$ ${result.command}`,
      stdout ? `\nSTDOUT\n${stdout}` : "",
      stderr ? `\nSTDERR\n${stderr}` : "",
      !stdout && !stderr ? "\nTidak ada output." : ""
    ].join("\n").trim();
  } catch (error) {
    status.textContent = "Failed";
    status.className = "tool-command-status error";
    output.textContent = error.message || "Eksekusi command gagal.";
  } finally {
    button.disabled = false;
  }
}

function interactiveConsolePayload(toolName, command, sudoInput = null) {
  return {
    tool_name: toolName,
    command,
    sudo_password: sudoInput?.value || ""
  };
}

function interactiveToolHints(toolName = "") {
  const normalized = String(toolName || "").trim().toLowerCase();
  return INTERACTIVE_COMMAND_HINTS[normalized] || ["help", "exit", "quit"];
}

function resetInteractiveTabState() {
  state.interactiveTabState = null;
}

function updateInteractiveHintLabel(message = "") {
  const hint = $("#interactiveHintLabel");
  if (!hint) return;
  hint.textContent = message || "Tab untuk auto-complete command umum. Enter untuk kirim.";
}

function applyInteractiveTabCompletion(input) {
  const session = state.activeInteractiveSession;
  if (!session || !input) return false;
  const value = String(input.value || "");
  const cursor = input.selectionStart ?? value.length;
  const beforeCursor = value.slice(0, cursor);
  const afterCursor = value.slice(cursor);
  const tokenMatch = beforeCursor.match(/(?:^|\s)([^\s]*)$/);
  const currentToken = tokenMatch ? tokenMatch[1] : "";
  const tokenStart = tokenMatch ? cursor - currentToken.length : cursor;
  const trimmed = beforeCursor.trimStart();
  const hints = interactiveToolHints(session.tool_name);

  let candidates = [];
  if (!trimmed || (trimmed === currentToken && !beforeCursor.includes(" "))) {
    candidates = hints.filter((entry) => entry.startsWith(currentToken));
  } else if (!currentToken) {
    candidates = hints;
  } else {
    candidates = hints.filter((entry) => entry.startsWith(currentToken));
  }
  if (!candidates.length) {
    updateInteractiveHintLabel("Tidak ada saran command yang cocok.");
    resetInteractiveTabState();
    return false;
  }

  const tabKey = `${session.tool_name}:${currentToken}:${candidates.join("|")}`;
  let index = 0;
  if (state.interactiveTabState?.key === tabKey) {
    index = (state.interactiveTabState.index + 1) % candidates.length;
  }
  const suggestion = candidates[index];
  const replacement = suggestion;
  input.value = `${value.slice(0, tokenStart)}${replacement}${afterCursor}`;
  const nextCursor = tokenStart + replacement.length;
  input.selectionStart = nextCursor;
  input.selectionEnd = nextCursor;
  state.interactiveTabState = { key: tabKey, index };
  updateInteractiveHintLabel(
    candidates.length > 1
      ? `Saran ${index + 1}/${candidates.length}: ${suggestion}`
      : `Auto-complete: ${suggestion}`
  );
  return true;
}

function isPlainEnterKey(event) {
  const key = String(event?.key || "");
  const code = String(event?.code || "");
  const keyCode = Number(event?.keyCode || 0);
  const which = Number(event?.which || 0);
  return (
    !event?.shiftKey &&
    !event?.ctrlKey &&
    !event?.metaKey &&
    !event?.altKey &&
    !event?.isComposing &&
    (key === "Enter" || code === "Enter" || code === "NumpadEnter" || keyCode === 13 || which === 13)
  );
}

function renderInteractiveConsoleSession(session) {
  const output = $("#consoleOutput");
  const activeLabel = $("#activeJobLabel");
  const commandLabel = $("#activeCommandLabel");
  const toolbarLabel = $("#terminalToolbarLabel");
  const promptLabel = $("#interactivePromptLabel");
  const inputRow = $("#interactiveConsoleControls");
  const input = $("#interactiveConsoleInput");
  const sendButton = $("#sendInteractiveConsoleBtn");
  const closeButton = $("#closeInteractiveConsoleBtn");
  if (!output || !activeLabel || !commandLabel || !inputRow) return;

  if (!session) {
    inputRow.classList.add("hidden");
    if (input) input.value = "";
    if (sendButton) sendButton.disabled = true;
    if (closeButton) closeButton.disabled = true;
    if (toolbarLabel) toolbarLabel.textContent = "console@redteam: ready";
    if (promptLabel) promptLabel.textContent = "$";
    updateInteractiveHintLabel();
    return;
  }

  activeLabel.textContent = `${session.tool_name} interactive session`;
  commandLabel.textContent = session.status === "running"
    ? (session.started_command || session.command || "Interactive command")
    : `${session.tool_name} session stopped`;
  if (toolbarLabel) {
    toolbarLabel.textContent = `${session.tool_name}@redteam: ${session.status}`;
  }
  if (promptLabel) {
    promptLabel.textContent = session.tool_name === "metasploit" ? "msf6 >" : `${session.tool_name} $`;
  }
  output.textContent = session.output || "Menunggu output interactive session...";
  output.scrollTop = output.scrollHeight;
  inputRow.classList.remove("hidden");
  if (sendButton) sendButton.disabled = session.status !== "running";
  if (closeButton) closeButton.disabled = false;
  updateInteractiveHintLabel();
  setConsoleStatus(session.status === "running" ? "running" : "idle", session.status);
}

async function setTerminalFullscreen(force = null) {
  const panel = document.querySelector('.insight-panel[data-insight-panel="console"]');
  const button = $("#toggleTerminalFullscreenBtn");
  if (!panel || !button) return;
  const isNativeFullscreen = document.fullscreenElement === panel;
  const isFallbackFullscreen = panel.classList.contains("console-fullscreen");
  const currentEnabled = isNativeFullscreen || isFallbackFullscreen;
  const shouldEnable = force === null ? !currentEnabled : Boolean(force);

  try {
    if (shouldEnable && document.fullscreenElement !== panel && panel.requestFullscreen) {
      await panel.requestFullscreen();
    } else if (!shouldEnable && document.fullscreenElement === panel && document.exitFullscreen) {
      await document.exitFullscreen();
    }
  } catch (error) {
    // Fallback handled below.
  }

  const nativeActive = document.fullscreenElement === panel;
  const fallbackActive = shouldEnable && !nativeActive;
  panel.classList.toggle("console-fullscreen", fallbackActive || nativeActive);
  button.textContent = shouldEnable ? "Exit Full Screen" : "Full Screen";
  button.setAttribute("aria-pressed", shouldEnable ? "true" : "false");
  document.body.classList.toggle("terminal-fullscreen-open", shouldEnable);
}

async function pollInteractiveConsoleSession() {
  if (!state.activeInteractiveSession?.id) return;
  try {
    const result = await api(`/api/tools/interactive/${encodeURIComponent(state.activeInteractiveSession.id)}`);
    state.activeInteractiveSession = result.session || null;
    renderInteractiveConsoleSession(state.activeInteractiveSession);
    if (state.activeInteractiveSession?.status === "running") {
      window.clearTimeout(state.interactivePollTimer);
      state.interactivePollTimer = window.setTimeout(pollInteractiveConsoleSession, 900);
    }
  } catch (error) {
    window.clearTimeout(state.interactivePollTimer);
    state.activeInteractiveSession = null;
    renderInteractiveConsoleSession(null);
    if (state.activeJob) {
      renderConsole(state.activeJob);
    }
    showToast(error.message || "Interactive session terputus.");
  }
}

async function openInteractiveConsoleSession(toolName, command, sudoInput = null) {
  const result = await api("/api/tools/interactive/open", {
    method: "POST",
    body: JSON.stringify(interactiveConsolePayload(toolName, command, sudoInput))
  });
  state.activeInteractiveSession = result.session || null;
  state.insightTab = "console";
  renderInsightTabs();
  renderInteractiveConsoleSession(state.activeInteractiveSession);
  window.clearTimeout(state.interactivePollTimer);
  if (state.activeInteractiveSession?.status === "running") {
    state.interactivePollTimer = window.setTimeout(pollInteractiveConsoleSession, 900);
  }
  showToast(`${toolName} live console dibuka.`);
}

async function sendInteractiveConsoleInput() {
  const sessionId = state.activeInteractiveSession?.id;
  const input = $("#interactiveConsoleInput");
  if (!sessionId || !input) return;
  const command = String(input.value || "").trim();
  if (!command) return;
  const result = await api(`/api/tools/interactive/${encodeURIComponent(sessionId)}/input`, {
    method: "POST",
    body: JSON.stringify({ command })
  });
  state.activeInteractiveSession = result.session || null;
  input.value = "";
  resetInteractiveTabState();
  renderInteractiveConsoleSession(state.activeInteractiveSession);
  if (state.activeInteractiveSession?.status === "running") {
    window.clearTimeout(state.interactivePollTimer);
    state.interactivePollTimer = window.setTimeout(pollInteractiveConsoleSession, 900);
  }
}

async function closeInteractiveConsoleSession() {
  const sessionId = state.activeInteractiveSession?.id;
  window.clearTimeout(state.interactivePollTimer);
  if (!sessionId) {
    state.activeInteractiveSession = null;
    renderInteractiveConsoleSession(null);
    if (state.activeJob) renderConsole(state.activeJob);
    return;
  }
  try {
    await api(`/api/tools/interactive/${encodeURIComponent(sessionId)}/close`, { method: "POST" });
  } catch (error) {
    showToast(error.message || "Gagal menutup interactive session.");
  }
  state.activeInteractiveSession = null;
  renderInteractiveConsoleSession(null);
  if (state.activeJob) renderConsole(state.activeJob);
  else renderConsole(null);
}

async function openToolCommandInLiveConsole(button) {
  const card = button.closest("[data-tool-command-card]");
  const input = card?.querySelector("[data-tool-command-input]");
  const sudoInput = card?.querySelector("[data-tool-sudo-password]");
  const toolName = card?.dataset.toolLabel || state.selectedToolLabel || "";
  if (!card || !input || !toolName) return;
  const command = String(input.value || "").trim();
  if (!command) {
    showToast("Command kosong.");
    return;
  }
  await openInteractiveConsoleSession(toolName, command, sudoInput);
}

async function openModuleCommandInLiveConsole(button) {
  const card = button.closest("[data-module-command-card]");
  const sudoInput = card?.querySelector("[data-tool-sudo-password]");
  const toolName = card?.dataset.toolLabel || "";
  const command = String(card?.querySelector(".module-command")?.textContent || "").trim();
  if (!card || !toolName || !command) return;
  await openInteractiveConsoleSession(toolName, command, sudoInput);
}

function openToolInspectModal(label, status) {
  const modal = $("#toolInspectModal");
  const title = $("#toolInspectTitle");
  const badge = $("#toolInspectBadge");
  const meta = $("#toolInspectMeta");
  const purpose = $("#toolInspectPurpose");
  const commands = $("#toolInspectCommands");
  const usage = $("#toolInspectUsage");
  const notes = $("#toolInspectNotes");
  const modules = $("#toolInspectModules");
  if (!modal || !title || !badge || !meta || !purpose || !commands || !usage || !notes || !modules) return;

  if (!label) {
    closeToolInspectModal();
    return;
  }

  const category = toolCategoryForLabel(label);
  const severityKey = status?.installed === true ? "low" : status?.kind === "conceptual" ? "info" : "high";
  const usageModules = toolUsageModules(label);
  const reference = toolReferenceData(label, status);

  title.textContent = label;
  badge.textContent = status?.installed === true ? "installed" : status?.kind || "missing";
  badge.className = `severity-pill severity-${severityKey}`;
  meta.innerHTML = `
    <span class="module-chip module-chip-soft">${category}</span>
    ${status?.command ? `<span class="module-chip module-chip-muted">${status.command}</span>` : ""}
    ${status?.kind ? `<span class="module-chip module-chip-soft">${status.kind}</span>` : ""}
    <span class="module-chip module-chip-soft">risk ${selectedRiskMode()}</span>
    <span class="module-chip module-chip-muted">used in ${usageModules.length} modules</span>
  `;
  purpose.textContent = toolPurposeCopy(category);
  commands.innerHTML = (reference.commands || []).map((item, index) => `
    <article class="tool-command-card" data-tool-command-card="${index}" data-tool-label="${escapeHtml(label)}">
      <header>
        <strong>${item.title}</strong>
        <span class="severity-pill severity-${item.tone === "advanced" ? "high" : item.tone === "safe" ? "low" : "info"}">${item.tone}</span>
      </header>
      <p>${item.description}</p>
      <textarea class="tool-command-editor" data-tool-command-input spellcheck="false">${escapeHtml(normalizeCommandForTarget(item.command, currentTargetValue()))}</textarea>
      ${toolCommandSudoFieldMarkup(normalizeCommandForTarget(item.command, currentTargetValue()))}
      <div class="tool-command-actions">
        <button class="ghost-button compact" type="button" data-copy-tool-command>Copy</button>
        ${isInteractiveToolLabel(label)
          ? `<button class="primary-button compact" type="button" data-open-tool-console>Open Live Console</button>`
          : `<button class="primary-button compact" type="button" data-run-tool-command>Execute</button>`}
        <span class="tool-command-status" data-tool-command-status>Ready</span>
      </div>
      <pre class="tool-command-output hidden" data-tool-command-output>Belum ada output.</pre>
    </article>
  `).join("");
  usage.textContent = reference.usage;
  notes.innerHTML = (reference.notes || []).map((item) => `<span class="tool-note-chip">${item}</span>`).join("");
  modules.innerHTML = usageModules.length
    ? usageModules.map((module) => `
      <button class="module-chip module-chip-soft" type="button" data-jump-module="${module.id}">${module.phase} - ${module.title}</button>
    `).join("")
    : '<span class="module-chip module-chip-muted">Belum terhubung ke modul katalog</span>';

  modal.classList.remove("hidden");
  modal.setAttribute("aria-hidden", "false");
}

function renderToolingHealth() {
  const summaryContainer = $("#toolSummaryGrid");
  const listContainer = $("#toolHealthList");
  const catalogLabel = $("#toolCatalogLabel");
  if (!summaryContainer) return;
  const summary = state.toolsStatus?.summary || {};
  const toolMap = state.toolsStatus?.tools || {};
  const rows = Array.isArray(state.toolingCatalog) && state.toolingCatalog.length
    ? state.toolingCatalog.map((entry) => [entry.label, entry.status || toolMap[entry.label] || {}])
    : Object.entries(toolMap);

  summaryContainer.innerHTML = `
    <div class="tool-summary-card">
      <span>Total Tools</span>
      <strong>${summary.total || rows.length || 0}</strong>
      <small>Terdaftar di backend</small>
    </div>
    <div class="tool-summary-card">
      <span>Available</span>
      <strong>${summary.available || 0}</strong>
      <small>Terdeteksi di environment</small>
    </div>
    <div class="tool-summary-card">
      <span>Conceptual</span>
      <strong>${summary.conceptual || 0}</strong>
      <small>Masih konseptual atau wrapper</small>
    </div>
  `;

  if (!listContainer) {
    return;
  }

  if (!rows.length) {
    listContainer.innerHTML = '<p class="empty-jobs">Belum ada data tooling.</p>';
    return;
  }

  const filtered = filteredToolCatalogEntries();

  if (catalogLabel) {
    catalogLabel.textContent = `Tool Catalog (${filtered.length}/${rows.length})`;
  }

  document.querySelectorAll("[data-tool-filter]").forEach((button) => {
    button.classList.toggle("active", button.dataset.toolFilter === state.toolStatusFilter);
  });

  if (!filtered.some((entry) => entry.label === state.selectedToolLabel)) {
    state.selectedToolLabel = filtered[0]?.label || "";
  }

  const grouped = filtered.reduce((accumulator, entry) => {
    if (!accumulator[entry.category]) accumulator[entry.category] = [];
    accumulator[entry.category].push(entry);
    return accumulator;
  }, {});

  const categoryOrder = ["Discovery", "DNS & Surface", "Web Assessment", "Validation", "Credential", "Post Exploitation", "Detection & Forensics", "Utility", "Other"];
  const sections = categoryOrder
    .filter((category) => Array.isArray(grouped[category]) && grouped[category].length);

  if (!sections.length) {
    listContainer.innerHTML = '<p class="empty-jobs">Tidak ada tool yang cocok dengan filter saat ini.</p>';
    return;
  }

  listContainer.innerHTML = sections.map((category) => `
    <section class="tool-category-group">
      <div class="tool-category-head">
        <strong>${category}</strong>
        <span class="severity-pill severity-info">${grouped[category].length} tools</span>
      </div>
      <div class="tool-grid">
        ${grouped[category].map(({ label, status }) => `
          <article class="tool-item${label === state.selectedToolLabel ? " is-active" : ""}">
            <div class="tool-item-head">
              <strong>${label}</strong>
              <span class="severity-pill severity-${status?.installed ? "low" : status?.kind === "conceptual" ? "info" : "high"}">${status?.installed ? "installed" : status?.kind || "missing"}</span>
            </div>
            <div class="tool-item-meta">
              ${status?.command ? `<span class="module-chip module-chip-soft">${status.command}</span>` : ""}
              <span class="module-chip module-chip-muted">${category}</span>
              <span class="module-chip module-chip-soft">used in ${toolUsageModules(label).length} modules</span>
            </div>
            <div class="assessment-actions-row">
              <button class="ghost-button compact" type="button" data-select-tool="${label}">Inspect</button>
              <button class="ghost-button compact" type="button" data-check-tool="${label}">Check</button>
            </div>
          </article>
        `).join("")}
      </div>
    </section>
  `).join("");

  const selectedEntry = filtered.find((entry) => entry.label === state.selectedToolLabel) || filtered[0];
  state.selectedToolLabel = selectedEntry?.label || "";
}

function renderAssessmentLibrary() {
  const container = $("#assessmentList");
  if (!container) return;
  if (!state.assessments.length) {
    container.innerHTML = '<p class="empty-jobs">Belum ada assessment tersimpan.</p>';
    return;
  }
  container.innerHTML = state.assessments.map((assessment) => `
    <article class="assessment-item${assessment.id === state.activeAssessmentId ? " is-active" : ""}">
      <div class="assessment-item-head">
        <strong>${assessment.target}</strong>
        <span class="severity-pill severity-info">${assessment.risk_mode || "safe"}</span>
      </div>
      <div class="assessment-item-meta">
        <span class="module-chip module-chip-soft">${assessment.target_kind || "ip"}</span>
        <span class="module-chip module-chip-muted">${assessment.operator_name || "operator"}</span>
        <span class="module-chip module-chip-soft">${assessment.finding_count || 0} findings</span>
      </div>
      <small>${assessment.id} - ${formatDateLabel(assessment.updated_at || assessment.created_at)}</small>
      <div class="assessment-actions-row">
        <button class="ghost-button compact" type="button" data-select-assessment="${assessment.id}">Open</button>
      </div>
    </article>
  `).join("");
}

function renderWorkspaceBrowser() {
  const sectionsContainer = $("#workspaceSections");
  const pathLabel = $("#workspacePathLabel");
  const refreshButton = $("#refreshWorkspaceBtn");
  const previewTitle = $("#workspacePreviewTitle");
  const previewMeta = $("#workspacePreviewMeta");
  const previewContent = $("#workspacePreviewContent");
  if (!sectionsContainer || !pathLabel || !previewTitle || !previewMeta || !previewContent) return;

  refreshButton.disabled = !state.activeAssessmentId;

  if (!state.activeWorkspace?.workspace) {
    pathLabel.textContent = "Workspace belum dipilih";
    sectionsContainer.innerHTML = "Belum ada assessment aktif atau workspace belum tersedia.";
    previewTitle.textContent = "Preview file";
    previewMeta.textContent = "Belum ada file dipilih";
    previewContent.textContent = "Workspace assessment aktif akan tampil di sini bersama file report, parsed JSON, dan log.";
    return;
  }

  pathLabel.textContent = state.activeWorkspace.workspace;
  const sections = Array.isArray(state.activeWorkspace.sections) ? state.activeWorkspace.sections : [];
  sectionsContainer.innerHTML = sections.map((section) => `
    <article class="asset-item">
      <div class="asset-item-head">
        <strong>${section.name}</strong>
        <span class="severity-pill severity-info">${(section.entries || []).length} files</span>
      </div>
      <div class="assessment-actions-row">
        ${(section.entries || []).map((entry) => `
          <button class="ghost-button compact" type="button" data-workspace-file="${entry.path}">${entry.name}</button>
        `).join("")}
      </div>
    </article>
  `).join("");

  if (!state.workspacePreviewPath) {
    previewTitle.textContent = "Preview file";
    previewMeta.textContent = "Belum ada file dipilih";
    previewContent.textContent = "Pilih file report, parsed JSON, atau log dari workspace assessment.";
  }
}

function renderTargetAsset() {
  const container = $("#targetAssetCard");
  if (!container) return;
  const asset = state.targetAsset;
  if (!asset) {
    container.textContent = "Belum ada asset match untuk target aktif.";
    return;
  }
  container.innerHTML = `
    <div class="asset-item-head">
      <strong>${asset.application}</strong>
      <span class="severity-pill severity-${severityClass(asset.criticality)}">${asset.criticality}</span>
    </div>
    <div class="asset-item-meta">
      <span class="module-chip module-chip-soft">${asset.ip}</span>
      <span class="module-chip module-chip-muted">${asset.hostname}</span>
      <span class="module-chip module-chip-soft">${asset.monitoring}</span>
    </div>
    <small>${asset.owner_unit} - ${asset.owner_name} - ${asset.environment}</small>
    <p>${asset.note}</p>
  `;
}

function renderReferenceData() {
  renderTargetAsset();
}

function renderImportResult() {
  const container = $("#importResult");
  if (!container) return;
  if (!state.importResult) {
    container.textContent = "Belum ada output yang diparse.";
    return;
  }
  const findings = Array.isArray(state.importResult.findings) ? state.importResult.findings : [];
  container.textContent = [
    `Tool        : ${state.importResult.tool_name}`,
    `Target      : ${state.importResult.target}`,
    `Line Count  : ${state.importResult.line_count}`,
    "",
    "Summary:",
    ...(state.importResult.summary || []).map((item) => `- ${item}`),
    "",
    "Findings:",
    ...(findings.length ? findings.map((item) => `- [${item.severity}] ${item.title}: ${item.detail}`) : ["- Tidak ada finding terstruktur."])
  ].join("\n");
}

function renderDestructiveActions() {
  const modeLabel = $("#destructiveModeLabel");
  const note = $("#destructiveNote");
  const container = $("#destructiveActionsList");
  const result = $("#destructiveResult");
  if (!modeLabel || !note || !container || !result) return;
  const enabled = state.config?.destructive_mode === "enabled";
  modeLabel.textContent = enabled ? "Policy enabled di backend." : "Policy disabled di backend.";
  note.textContent = enabled
    ? "Action destructive hanya boleh dijalankan pada assessment intrusive dengan approval tersimpan."
    : "Destructive mode masih dimatikan di backend. Panel ini tetap menampilkan registry action untuk review.";
  container.innerHTML = (state.destructiveActions || []).map((action) => `
    <article class="destructive-item">
      <div class="destructive-item-head">
        <strong>${action.description}</strong>
        <span class="severity-pill severity-${severityClass(action.severity)}">${action.severity}</span>
      </div>
      <small>${action.id}</small>
      <div class="destructive-actions-row">
        <button class="ghost-button compact" type="button" data-approve-destructive="${action.id}" ${state.activeAssessmentId ? "" : "disabled"}>Approve</button>
        <button class="primary-button compact" type="button" data-execute-destructive="${action.id}" ${enabled && state.activeAssessmentId ? "" : "disabled"}>Execute</button>
      </div>
    </article>
  `).join("") || '<p class="empty-jobs">Belum ada destructive action registry.</p>';
  result.textContent = state.destructiveResult || "Belum ada destructive action dijalankan.";
}

function renderAssessmentExportButtons() {
  const hasAssessment = Boolean(state.activeAssessmentId);
  const workspaceButton = $("#refreshWorkspaceBtn");
  const evidenceButton = $("#viewAssessmentEvidenceBtn");
  const markdownButton = $("#viewAssessmentMarkdownBtn");
  const htmlButton = $("#viewAssessmentHtmlBtn");
  if (workspaceButton) workspaceButton.disabled = !hasAssessment;
  if (evidenceButton) evidenceButton.disabled = !hasAssessment;
  if (markdownButton) markdownButton.disabled = !hasAssessment;
  if (htmlButton) htmlButton.disabled = !hasAssessment;
}

function persistLastTarget(value) {
  const normalized = String(value || "").trim();
  if (!normalized) return;
  localStorage.setItem(LAST_TARGET_STORAGE_KEY, normalized);
}

function restoreLastTarget() {
  const input = $("#targetInput");
  if (!input) return;
  const saved = localStorage.getItem(LAST_TARGET_STORAGE_KEY);
  if (!saved) return;
  input.value = saved;
}

function selectedModuleProfile() {
  const activeValue = $("#moduleProfileSelect")?.value;
  return ["fast", "balanced", "deep"].includes(activeValue)
    ? activeValue
    : state.moduleExecutionProfile || "fast";
}

function setModuleExecutionProfile(profile) {
  const next = ["fast", "balanced", "deep"].includes(profile) ? profile : "fast";
  state.moduleExecutionProfile = next;
  const select = $("#moduleProfileSelect");
  if (select) select.value = next;
}

function commandPreviewMarkup(commands = []) {
  const target = currentTargetValue();
  const resolved = (commands || [])
    .map((command) => String(command || "").replaceAll("TARGET", target))
    .filter(Boolean);
  if (!resolved.length) {
    return `<div class="module-command-list"><code class="module-command">No command preview</code></div>`;
  }
  return `
    <div class="module-command-list">
      ${resolved.map((command) => `<code class="module-command">${command}</code>`).join("")}
    </div>
  `;
}

function inferToolNameFromCommand(command, module = null) {
  const literal = String(command || "").trim();
  const parts = literal.split(/\s+/).filter(Boolean);
  const token = parts[0]?.trim().toLowerCase() || "";
  const effectiveToken = token === "sudo" ? (parts[1] || "").trim().toLowerCase() : token;
  if (effectiveToken) return effectiveToken;
  const tooling = Array.isArray(module?.tooling_details) ? module.tooling_details : [];
  const binary = tooling.find((item) => item?.kind === "binary" && item?.label);
  if (binary?.label) return String(binary.label).toLowerCase();
  const first = Array.isArray(module?.tooling) ? module.tooling.find(Boolean) : "";
  return String(first || "").toLowerCase();
}

function commandNeedsSudoField(command) {
  return String(command || "").trim().toLowerCase().startsWith("sudo ");
}

function toolCommandSudoFieldMarkup(command = "") {
  return `
    <label class="tool-command-secret hidden" data-tool-sudo-field>
      <span>Sudo password</span>
      <input type="password" autocomplete="current-password" placeholder="Masukkan password sudo bila diperlukan" data-tool-sudo-password>
    </label>
  `;
}

function isModuleCommandsExpanded(moduleId) {
  return state.expandedModuleCommandIds.includes(moduleId);
}

function setModuleCommandsExpanded(moduleId, expanded = true) {
  const next = new Set(state.expandedModuleCommandIds);
  if (expanded) next.add(moduleId);
  else next.delete(moduleId);
  state.expandedModuleCommandIds = [...next];
}

function commandActionMarkup(module, commands = []) {
  const target = currentTargetValue();
  const resolved = (commands || [])
    .map((command) => String(command || "").replaceAll("TARGET", target))
    .filter(Boolean);
  if (!resolved.length) {
    return `<div class="module-command-list"><code class="module-command">No command preview</code></div>`;
  }
  return `
    <div class="module-command-list">
      ${resolved.map((command, index) => `
        <article class="module-command-card" data-module-command-card="${module.id}-${index}" data-tool-label="${escapeHtml(inferToolNameFromCommand(command, module))}">
          <code class="module-command">${escapeHtml(command)}</code>
          ${toolCommandSudoFieldMarkup(command)}
          <div class="module-command-actions">
            <button class="ghost-button compact" type="button" data-copy-module-command>Copy</button>
            ${isInteractiveToolLabel(inferToolNameFromCommand(command, module))
              ? `<button class="primary-button compact" type="button" data-open-module-console>Open Live Console</button>`
              : `<button class="primary-button compact" type="button" data-run-module-command>Run</button>`}
            <span class="tool-command-status" data-module-command-status>Ready</span>
          </div>
          <pre class="tool-command-output hidden" data-module-command-output>Belum ada output.</pre>
        </article>
      `).join("")}
    </div>
  `;
}

function commandPreviewBlockMarkup(module) {
  if (isModuleCommandsExpanded(module.id)) {
    const commands = commandPreviewForModule(module);
    if (!commands.length) {
      return `
        <div class="module-command-collapsed" data-module-command-collapsed="${module.id}">
          <code class="module-command">Memuat command preview...</code>
        </div>
      `;
    }
    return commandActionMarkup(module, commands);
  }
  return `
    <div class="module-command-collapsed" data-module-command-collapsed="${module.id}">
      <code class="module-command">Command preview dimuat saat dibuka.</code>
      <div class="module-command-actions">
        <button class="ghost-button compact" type="button" data-expand-module-commands="${module.id}">
          Buka Command
        </button>
      </div>
    </div>
  `;
}

function commandPreviewForModule(module) {
  const byProfile = module?.command_preview_by_profile || state.moduleDryRunCache?.[module?.id]?.command_preview_by_profile || {};
  return byProfile[selectedModuleProfile()] || byProfile.balanced || [];
}

async function fetchModuleDryRunData(moduleId) {
  if (state.moduleDryRunCache[moduleId]) {
    return state.moduleDryRunCache[moduleId];
  }
  const payload = readTargetPayload();
  const result = await api(`/api/modules/${moduleId}/dry-run?target=${encodeURIComponent(payload.target)}&note=${encodeURIComponent(payload.note)}&execution_profile=${encodeURIComponent(payload.execution_profile)}`);
  const cached = {
    target: payload.target,
    execution_profile: payload.execution_profile,
    command_preview_by_profile: {
      [payload.execution_profile]: Array.isArray(result?.dry_run?.commands) ? result.dry_run.commands : []
    },
    dry_run: result.dry_run || null
  };
  state.moduleDryRunCache[moduleId] = cached;
  return cached;
}

function executionFlowMarkup(lines = []) {
  const items = (lines || []).filter(Boolean).slice(0, 3);
  if (!items.length) {
    return `<div class="playbook-flow-list"><p class="playbook-flow-item">No execution flow preview</p></div>`;
  }
  return `
    <div class="playbook-flow-list">
      ${items.map((line) => `<p class="playbook-flow-item">${line}</p>`).join("")}
    </div>
  `;
}

function toolDetailMap(module) {
  return new Map((module.tooling_details || []).map((item) => [item.label, item]));
}

function toolingChipMarkup(module, labels, baseClass) {
  const detailMap = toolDetailMap(module);
  return labels.map((label) => {
    const detail = detailMap.get(label);
    if (!detail) return `<span class="${baseClass}">${label}</span>`;
    const stateClass = detail.installed === false
      ? "module-chip-missing"
      : detail.installed === true
        ? "module-chip-installed"
        : "module-chip-conceptual";
    const suffix = detail.installed === false
      ? " (missing)"
      : detail.kind === "conceptual"
        ? " (concept)"
        : "";
    return `<span class="${baseClass} ${stateClass}">${label}${suffix}</span>`;
  }).join("");
}

function phaseGroupsList() {
  return Object.entries(groupModulesByPhase(state.modules))
    .sort((a, b) => a[1].order - b[1].order)
    .map(([phaseId, group]) => [
      phaseId,
      {
        ...group,
        modules: [...group.modules].sort((a, b) => {
          const priorityDelta = moduleUiPriority(a) - moduleUiPriority(b);
          if (priorityDelta !== 0) return priorityDelta;
          return String(a.title || "").localeCompare(String(b.title || ""));
        })
      }
    ]);
}

function moduleMatchesSearch(module, query) {
  const needle = String(query || "").trim().toLowerCase();
  if (!needle) return true;
  const haystack = [
    module.title,
    module.description,
    module.phase_label,
    module.risk,
    module.mitre,
    module.engine,
    module.skill_level,
    module.operator_focus,
    module.simulation_stance,
    module.depth_profile,
    ...(module.tooling || []),
    ...(module.evidence || []),
    ...(module.telemetry || []),
    ...(module.allowed_checks || []),
    ...(module.preview || [])
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  return haystack.includes(needle);
}

function animatePhaseSwap() {
  const groups = $("#phaseGroups");
  const bar = $("#activePhaseBar");
  if (groups) {
    groups.classList.remove("is-switching");
    void groups.offsetWidth;
    groups.classList.add("is-switching");
    window.setTimeout(() => groups.classList.remove("is-switching"), 240);
  }
  if (bar) {
    bar.classList.remove("is-switching");
    void bar.offsetWidth;
    bar.classList.add("is-switching");
    window.setTimeout(() => bar.classList.remove("is-switching"), 240);
  }
}

function setViewMode(mode) {
  state.viewMode = "detail";
  document.body.dataset.viewMode = state.viewMode;
  localStorage.setItem("lab-console-view-mode", state.viewMode);
  updateViewModeNote();
}

function syncModuleProfileSelect() {
  const select = $("#moduleProfileSelect");
  if (!select) return;
  select.value = selectedModuleProfile();
}

function jobExecutionProfile(job) {
  return currentRun(job)?.execution_profile
    || job?.module_runs?.find((run) => run.execution_profile)?.execution_profile
    || job?.execution_profile
    || "fast";
}

function updateViewModeNote() {
  const note = $("#viewModeNote");
  if (!note) return;
  note.textContent = "Mode detail menampilkan deskripsi, command preview, toolset, dan konteks modul yang lengkap.";
}

function setOperationsTab(tab) {
  const allowed = new Set(["workspace", "health", "advanced"]);
  state.operationsTab = allowed.has(tab) ? tab : "workspace";
  localStorage.setItem("lab-console-operations-tab", state.operationsTab);
  document.querySelectorAll("[data-operations-tab]").forEach((button) => {
    const isActive = button.dataset.operationsTab === state.operationsTab;
    button.classList.toggle("is-active", isActive);
    button.setAttribute("aria-selected", String(isActive));
  });
  document.querySelectorAll("[data-operations-panel]").forEach((panel) => {
    panel.classList.toggle("hidden", panel.dataset.operationsPanel !== state.operationsTab);
  });
  const note = $("#operationsTabNote");
  if (note) {
    note.textContent = state.operationsTab === "workspace"
      ? "Riwayat assessment, export, dan file hasil yang paling sering dipakai operator."
      : state.operationsTab === "health"
        ? "Status tool, preset, asset, dan reference untuk validasi lingkungan kerja."
        : "Parser, findings, approval, dan destructive flow yang lebih sensitif atau jarang dipakai.";
  }
  if (state.operationsVisible) {
    if (state.operationsTab === "workspace") {
      scheduleDeferredTask(ensureOperatorWorkspaceDataLoaded);
    } else if (state.operationsTab === "health") {
      if (state.healthTab === "strategy") {
        scheduleDeferredTask(ensureToolCatalogDataLoaded);
      } else {
        scheduleDeferredTask(ensureReferencePanelDataLoaded);
      }
    }
  }
}

function setOperationsVisibility(visible) {
  state.operationsVisible = Boolean(visible);
  const shell = document.querySelector(".operations-shell");
  const body = $("#operationsShellBody");
  const toggle = $("#toggleOperationsBtn");
  if (shell) shell.classList.toggle("is-collapsed", !state.operationsVisible);
  if (body) body.classList.toggle("hidden", !state.operationsVisible);
  if (toggle) {
    toggle.textContent = state.operationsVisible ? "Sembunyikan Workspace" : "Buka Workspace";
    toggle.setAttribute("aria-expanded", String(state.operationsVisible));
  }
  if (state.operationsVisible) {
    scheduleDeferredTask(ensureOperatorWorkspaceDataLoaded);
  }
}

function setHealthTab(tab) {
  const allowed = new Set(["strategy", "reference"]);
  state.healthTab = allowed.has(tab) ? tab : "strategy";
  localStorage.setItem("lab-console-health-tab", state.healthTab);
  document.querySelectorAll("[data-health-tab]").forEach((button) => {
    const isActive = button.dataset.healthTab === state.healthTab;
    button.classList.toggle("is-active", isActive);
    button.setAttribute("aria-selected", String(isActive));
  });
  document.querySelectorAll("[data-health-panel]").forEach((panel) => {
    panel.classList.toggle("hidden", panel.dataset.healthPanel !== state.healthTab);
  });
  if (state.operationsVisible && state.operationsTab === "health") {
    if (state.healthTab === "strategy") {
      scheduleDeferredTask(ensureToolCatalogDataLoaded);
    } else if (state.healthTab === "reference") {
      scheduleDeferredTask(ensureReferencePanelDataLoaded);
    }
  }
}

function openToolCatalogWorkspace() {
  const nextSurface = state.catalogSurface === "tools" ? "modules" : "tools";
  setCatalogSurface(nextSurface);
  if (nextSurface === "tools") {
    void ensureToolCatalogDataLoaded();
  }
}

function setCatalogSurface(surface) {
  state.catalogSurface = surface === "tools" ? "tools" : "modules";
  const eyebrow = $("#catalogEyebrow");
  const title = $("#catalogTitle");
  const note = $("#viewModeNote");
  const toggle = $("#openToolCatalogBtn");
  const search = $("#moduleSearchInput");

  if (eyebrow) eyebrow.textContent = state.catalogSurface === "tools" ? "Tool Catalog" : "Module Catalog";
  if (title) title.textContent = state.catalogSurface === "tools" ? "Katalog Tools WSL" : "Modul Cyber Kill Chain";
  if (note) {
    note.textContent = state.catalogSurface === "tools"
      ? "Status tool, referensi command, dan kepadatan penggunaan modul ditampilkan langsung di area katalog utama."
      : "Mode detail menampilkan deskripsi, command preview, toolset, dan konteks modul yang lengkap.";
  }
  if (toggle) toggle.textContent = state.catalogSurface === "tools" ? "Module Catalog" : "Tool Catalog";
  if (search) {
    search.placeholder = state.catalogSurface === "tools"
      ? "Cari tool, alias, command, kategori..."
      : "Cari modul, tool, MITRE, risk...";
    search.value = state.catalogSurface === "tools" ? state.toolSearchQuery : state.moduleSearchQuery;
  }
  renderModules();
  document.querySelector(".module-pane")?.scrollIntoView({ behavior: "smooth", block: "start" });
}

function setAdvancedTab(tab) {
  const allowed = new Set(["findings"]);
  state.advancedTab = allowed.has(tab) ? tab : "findings";
  localStorage.setItem("lab-console-advanced-tab", state.advancedTab);
  document.querySelectorAll("[data-advanced-tab]").forEach((button) => {
    const isActive = button.dataset.advancedTab === state.advancedTab;
    button.classList.toggle("is-active", isActive);
    button.setAttribute("aria-selected", String(isActive));
  });
  document.querySelectorAll("[data-advanced-panel]").forEach((panel) => {
    panel.classList.toggle("hidden", panel.dataset.advancedPanel !== state.advancedTab);
  });
}

function renderDetailCard(module) {
  return `
    <article class="module-card${module.id === state.highlightedModuleId ? " is-highlighted" : ""}" data-module-card="${module.id}">
      <div class="module-card-head">
        <div>
          <h4>${module.title}</h4>
          <div class="module-subhead">
            <span class="skill-pill">${module.skill_level}</span>
            <span class="focus-pill">${module.operator_focus}</span>
            <span class="stance-pill">${module.simulation_stance}</span>
          </div>
        </div>
        <span class="risk-pill risk-${module.risk}">${module.risk}</span>
      </div>
      <p>${module.description}</p>
      <div class="module-tags">
        <span>${module.engine}</span>
        <span>${selectedModuleProfile()}</span>
        <span>${module.mitre}</span>
      </div>
      <div class="module-detail-block">
        <strong>Depth profile</strong>
        <div class="module-chip-row">
          <span class="module-chip module-chip-depth">${module.depth_profile}</span>
          ${chipMarkup(module.allowed_checks, "module-chip module-chip-muted")}
        </div>
      </div>
      <div class="module-detail-block">
        <strong>WSL toolset</strong>
        <div class="module-chip-row">${toolingChipMarkup(module, module.tooling, "module-chip")}</div>
      </div>
      <div class="module-detail-block">
        <strong>Evidence target</strong>
        <div class="module-chip-row">${chipMarkup(module.evidence, "module-chip module-chip-soft")}</div>
      </div>
      <div class="module-detail-block">
        <strong>Detection surface</strong>
        <div class="module-chip-row">${chipMarkup(module.telemetry, "module-chip module-chip-muted")}</div>
      </div>
      <div class="module-detail-block">
        <strong>Command preview</strong>
        ${commandPreviewBlockMarkup(module)}
      </div>
      <div class="module-actions">
        <button class="ghost-button compact" type="button" data-preview="${module.id}">Preview</button>
      </div>
    </article>
  `;
}

function ensureSelectedPhase(groups) {
  if (!groups.length) {
    state.selectedPhase = "";
    return;
  }
  const exists = groups.some(([phaseId]) => phaseId === state.selectedPhase);
  if (!exists || state.selectedPhase === "all") {
    state.selectedPhase = groups[0][0];
  }
}

function renderPhaseTabs() {
  const container = $("#phaseTabs");
  if (!container) return;
  if (state.catalogSurface === "tools") {
    container.innerHTML = `
      <button class="phase-tab${state.toolStatusFilter === "all" ? " active" : ""}" type="button" data-tool-catalog-filter="all">All</button>
      <button class="phase-tab${state.toolStatusFilter === "installed" ? " active" : ""}" type="button" data-tool-catalog-filter="installed">Installed</button>
      <button class="phase-tab${state.toolStatusFilter === "missing" ? " active" : ""}" type="button" data-tool-catalog-filter="missing">Missing</button>
      <button class="phase-tab${state.toolStatusFilter === "conceptual" ? " active" : ""}" type="button" data-tool-catalog-filter="conceptual">Conceptual</button>
    `;
    return;
  }
  if (String(state.moduleSearchQuery || "").trim()) {
    container.innerHTML = "";
    return;
  }
  const groups = phaseGroupsList();
  ensureSelectedPhase(groups);

  container.innerHTML = groups.map(([phaseId, group]) => `
    <button class="phase-tab${phaseId === state.selectedPhase ? " active" : ""}" type="button" data-phase-tab="${phaseId}" aria-label="${String(group.order).padStart(2, "0")} ${group.label}">
      ${String(group.order).padStart(2, "0")}
    </button>
  `).join("");
}

function renderActivePhaseBar() {
  const container = $("#activePhaseBar");
  if (!container) return;
  if (state.catalogSurface === "tools") {
    const filtered = filteredToolCatalogEntries();
    const summary = state.toolsStatus?.summary || {};
    container.innerHTML = `
      <div class="tool-main-toolbar">
        <div class="tool-main-summary">
          <span class="active-phase-number">${filtered.length}</span>
          <div class="tool-main-summary-copy">
            <strong>${summary.total || filtered.length} total tools</strong>
            <span>${summary.available || 0} installed di environment aktif</span>
          </div>
        </div>
        <label class="catalog-search tool-main-sort" aria-label="Urutkan tool utama">
          <select id="mainToolSortSelect">
            <option value="usage" ${selectedToolSortMode() === "usage" ? "selected" : ""}>Most Used</option>
            <option value="installed" ${selectedToolSortMode() === "installed" ? "selected" : ""}>Installed First</option>
            <option value="missing" ${selectedToolSortMode() === "missing" ? "selected" : ""}>Missing First</option>
            <option value="alpha" ${selectedToolSortMode() === "alpha" ? "selected" : ""}>A-Z</option>
          </select>
        </label>
      </div>
    `;
    return;
  }
  if (String(state.moduleSearchQuery || "").trim()) {
    container.innerHTML = "";
    return;
  }
  const groups = phaseGroupsList();
  const active = groups.find(([phaseId]) => phaseId === state.selectedPhase);
  if (!active) {
    container.innerHTML = "";
    return;
  }
  const [, group] = active;
  container.innerHTML = `
    <div class="active-phase-number">${String(group.order).padStart(2, "0")}</div>
    <div class="active-phase-name">${group.label}</div>
  `;
}

function renderModules() {
  const container = $("#phaseGroups");
  if (!container) return;
  if (state.catalogSurface === "tools") {
    renderPhaseTabs();
    if ((state.toolCatalogLoading || !state.toolCatalogLoaded) && !state.toolingCatalog.length && !Object.keys(state.toolsStatus?.tools || {}).length) {
      renderActivePhaseBar();
      container.innerHTML = `
        <section class="phase-section phase-section-compact">
          <p class="empty-jobs">Memuat katalog tools...</p>
        </section>
      `;
      queueConsoleHeightSync();
      return;
    }
    renderActivePhaseBar();
    const filtered = filteredToolCatalogEntries();
    const total = Object.keys(state.toolsStatus?.tools || {}).length;
    if (!filtered.length) {
      container.innerHTML = `
        <section class="phase-section phase-section-compact">
          <p class="empty-jobs">Tidak ada tool yang cocok dengan filter saat ini.</p>
        </section>
      `;
      queueConsoleHeightSync();
      return;
    }
    const grouped = filtered.reduce((accumulator, entry) => {
      if (!accumulator[entry.category]) accumulator[entry.category] = [];
      accumulator[entry.category].push(entry);
      return accumulator;
    }, {});
    const categoryOrder = ["Discovery", "DNS & Surface", "Web Assessment", "Validation", "Credential", "Post Exploitation", "Detection & Forensics", "Utility", "Other"];
    const sections = categoryOrder.filter((category) => Array.isArray(grouped[category]) && grouped[category].length);
    container.innerHTML = sections.map((category) => `
      <section class="phase-section phase-section-compact tool-phase-section">
        <div class="phase-title">
          <span>${String(grouped[category].length).padStart(2, "0")}</span>
          <h3>${category}</h3>
        </div>
        <div class="tool-grid tool-grid-main">
          ${grouped[category].map(({ label, status }) => `
            <article class="tool-item tool-item-compact${label === state.selectedToolLabel ? " is-active" : ""}">
              <div class="tool-item-head">
                <strong>${label}</strong>
                <span class="severity-pill severity-${status?.installed ? "low" : status?.kind === "conceptual" ? "info" : "high"}">${status?.installed ? "installed" : status?.kind || "missing"}</span>
              </div>
              <div class="tool-item-meta">
                ${status?.command ? `<span class="module-chip module-chip-soft">${status.command}</span>` : ""}
                <span class="module-chip module-chip-muted">used in ${toolUsageModules(label).length} modules</span>
              </div>
              <div class="assessment-actions-row">
                <button class="ghost-button compact" type="button" data-select-tool="${label}">Inspect</button>
                <button class="ghost-button compact" type="button" data-check-tool="${label}">Check</button>
              </div>
            </article>
          `).join("")}
        </div>
      </section>
    `).join("");
    state.selectedToolLabel = filtered.find((entry) => entry.label === state.selectedToolLabel)?.label || filtered[0]?.label || "";
    queueConsoleHeightSync();
    return;
  }
  const groups = phaseGroupsList();
  ensureSelectedPhase(groups);
  renderPhaseTabs();
  renderActivePhaseBar();
  const query = String(state.moduleSearchQuery || "").trim();

  if (query) {
    const matchingGroups = groups
      .map(([phaseId, group]) => ({
        phaseId,
        group,
        modules: group.modules.filter((module) => moduleMatchesSearch(module, query))
      }))
      .filter((entry) => entry.modules.length > 0);

    if (!matchingGroups.length) {
      container.innerHTML = `
        <section class="phase-section phase-section-compact">
          <p class="empty-jobs">Tidak ada modul yang cocok dengan pencarian.</p>
        </section>
      `;
      queueConsoleHeightSync();
      return;
    }

    container.innerHTML = matchingGroups.map(({ phaseId, group, modules }) => `
      <section class="phase-section phase-section-compact" data-phase="${phaseId}">
        <div class="phase-title">
          <span>${String(group.order).padStart(2, "0")}</span>
          <h3>${group.label}</h3>
        </div>
        <div class="module-grid">
          ${modules.map((module) => renderDetailCard(module)).join("")}
        </div>
      </section>
    `).join("");
    queueConsoleHeightSync();
    return;
  }

  const active = groups.find(([phaseId]) => phaseId === state.selectedPhase);

  if (!active) {
    container.innerHTML = `<p class="empty-jobs">Tidak ada modul pada tahapan yang dipilih.</p>`;
    queueConsoleHeightSync();
    return;
  }

  const [phaseId, group] = active;
  const filteredModules = group.modules.filter((module) => moduleMatchesSearch(module, state.moduleSearchQuery));
  if (!filteredModules.length) {
    container.innerHTML = `
      <section class="phase-section phase-section-compact" data-phase="${phaseId}">
        <p class="empty-jobs">Tidak ada modul yang cocok dengan pencarian pada fase ini.</p>
      </section>
    `;
    queueConsoleHeightSync();
    return;
  }
  container.innerHTML = `
    <section class="phase-section phase-section-compact" data-phase="${phaseId}">
      <div class="module-grid">
        ${filteredModules.map((module) => renderDetailCard(module)).join("")}
      </div>
    </section>
  `;
  if (state.highlightedModuleId) {
    window.setTimeout(() => {
      const card = document.querySelector(`[data-module-card="${state.highlightedModuleId}"]`);
      if (card) {
        card.scrollIntoView({ behavior: "smooth", block: "center" });
      }
    }, 40);
  }
  queueConsoleHeightSync();
}

function renderJobs() {
  const container = $("#jobList");
  if (!container) return;

  if (!state.jobs.length) {
    container.innerHTML = `<p class="empty-jobs">Belum ada job. Jalankan satu modul atau full simulation chain.</p>`;
    return;
  }

  container.innerHTML = state.jobs.map((job) => `
    <article class="job-item${job.id === state.activeJobId ? " active" : ""}" data-job-card="${job.id}">
      <div class="job-item-main">
        <strong>${job.scope_label}</strong>
        <span>${jobHeadline(job)}</span>
        <div class="job-item-profile-row">
          <span class="job-profile-pill">${jobExecutionProfile(job)}</span>
        </div>
        <small>${job.status} - ${job.progress}% - ${(currentRun(job)?.title || "waiting")} - ${formatJobStamp(job.created_at)}</small>
      </div>
      <div class="job-item-actions">
        <button class="ghost-button compact job-open-btn" type="button" data-job="${job.id}">Lihat hasil</button>
        ${["pending", "running", "stopping"].includes(job.status)
          ? `<button class="ghost-button compact job-stop-btn" type="button" data-stop-job="${job.id}">Stop</button>`
          : ""}
        <button class="ghost-button compact job-delete-btn" type="button" data-delete-job="${job.id}">Hapus</button>
      </div>
    </article>
  `).join("");
}

function renderConfig() {
  if (!state.config) return;
  const input = $("#allowedSubnetsInput");
  const meta = $("#configMetaLabel");
  const saveButton = $("#saveRangesBtn");
  if (input) {
    input.value = (state.config.allowed_subnets || []).join(", ");
  }
  if (meta) {
    const source = state.config.config_source || "unknown";
    const path = state.config.config_path || "-";
    const passwordState = state.config.range_password_configured
      ? "range password configured"
      : "range password optional";
    meta.textContent = `${source} - ${path} - ${passwordState}`;
  }
  if (saveButton) {
    saveButton.disabled = false;
    saveButton.title = state.config.range_password_configured
      ? "Simpan perubahan ranges dengan verifikasi password."
      : "Simpan perubahan ranges langsung ke konfigurasi backend.";
  }
}

function setConsoleStatus(status, label = status) {
  $("#statusLabel").textContent = label;
  $("#statusDot").dataset.state = status;
}

function formatShortTime(value) {
  if (!value) return "--:--:--";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "--:--:--";
  return date.toLocaleTimeString("id-ID", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false
  });
}

function formatJobStamp(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "-";
  return `${date.toLocaleDateString("id-ID")} ${formatShortTime(value)}`;
}

function currentRun(job) {
  return (job?.module_runs || []).find((run) => run.status === "running")
    || (job?.module_runs || []).find((run) => run.status === "stalled")
    || null;
}

function evidenceCount(job) {
  return Array.isArray(job?.evidence) ? job.evidence.length : 0;
}

function compareJobFreshness(a, b) {
  const aTime = new Date(a?.updated_at || a?.created_at || 0).getTime();
  const bTime = new Date(b?.updated_at || b?.created_at || 0).getTime();
  return bTime - aTime;
}

function selectPreferredJobId(jobs, activeJobId = null) {
  const list = Array.isArray(jobs) ? jobs.filter(Boolean) : [];
  if (!list.length) return null;

  const activeJob = activeJobId
    ? list.find((job) => job.id === activeJobId)
    : null;
  if (activeJob) return activeJob.id;

  const jobsWithEvidence = list
    .filter((job) => evidenceCount(job) > 0)
    .sort((a, b) => {
      const evidenceDelta = evidenceCount(b) - evidenceCount(a);
      if (evidenceDelta !== 0) return evidenceDelta;
      return compareJobFreshness(a, b);
    });
  if (jobsWithEvidence.length) return jobsWithEvidence[0].id;

  const activeRuns = list
    .filter((job) => ["running", "pending", "stopping"].includes(String(job?.status || "")))
    .sort(compareJobFreshness);
  if (activeRuns.length) return activeRuns[0].id;

  return list.slice().sort(compareJobFreshness)[0].id;
}

function currentCommand(job) {
  const logs = job?.logs || [];
  for (let index = logs.length - 1; index >= 0; index -= 1) {
    const message = String(logs[index]?.message || "").trim();
    if (message.startsWith("$ ")) return message;
  }
  const run = currentRun(job);
  return run ? `Preparing ${run.title}` : "No active command";
}

function logLines(logs) {
  return (logs || []).map((entry) => {
    const stamp = entry.timestamp ? `[${formatShortTime(entry.timestamp)}]` : "";
    const sev = `[${String(entry.severity || "info").toUpperCase()}]`;
    return [stamp, sev, entry.message].filter(Boolean).join(" ");
  }).join("\n");
}

function renderSeveritySummary(summary = {}) {
  const container = $("#severitySummary");
  container.innerHTML = ["critical", "high", "medium", "low", "info"]
    .map((key) => severityBadgeMarkup(key, Number(summary[key] || 0)))
    .join("");
}

function summarizeEvidenceBySeverity(evidence = []) {
  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const item of evidence) {
    const severity = String(item?.severity || "info").toLowerCase();
    if (!(severity in summary)) {
      summary.info += 1;
      continue;
    }
    summary[severity] += 1;
  }
  return summary;
}

function moduleById(moduleId) {
  return state.modules.find((item) => item.id === moduleId) || null;
}

function toolsForEvidenceItem(item) {
  const module = moduleById(item?.module_id);
  const moduleTools = Array.isArray(module?.tooling) ? module.tooling : [];
  const artifactCommand = String(item?.artifacts?.command || "").trim();
  const inferredTool = artifactCommand ? inferToolNameFromCommand(artifactCommand, module) : "";
  const tools = [...moduleTools];
  if (inferredTool && !tools.includes(inferredTool)) tools.push(inferredTool);
  return tools.filter(Boolean);
}

function visibleEvidenceExportPayload() {
  const activeJob = state.jobs.find((item) => item.id === state.activeJobId) || null;
  const resolved = resolveVisibleEvidence(activeJob);
  const evidenceJob = resolved?.evidenceJob || activeJob;
  const evidence = Array.isArray(resolved?.evidence) ? resolved.evidence : [];
  const toolsUsed = Array.from(new Set(evidence.flatMap((item) => toolsForEvidenceItem(item))));

  return {
    exported_at: new Date().toISOString(),
    source: "visible-evidence-panel",
    assessment: state.activeAssessment
      ? {
          id: state.activeAssessment.id,
          target: state.activeAssessment.target,
          target_kind: state.activeAssessment.target_kind || "ip",
          risk_mode: state.activeAssessment.risk_mode,
          operator_name: state.activeAssessment.operator_name || "",
          ticket_ref: state.activeAssessment.ticket_ref || ""
        }
      : null,
    job: evidenceJob
      ? {
          id: evidenceJob.id,
          scope_type: evidenceJob.scope_type,
          scope_label: evidenceJob.scope_label,
          target: evidenceJob.target,
          status: evidenceJob.status,
          progress: evidenceJob.progress,
          created_at: evidenceJob.created_at,
          updated_at: evidenceJob.updated_at
        }
      : null,
    summary: {
      evidence_count: evidence.length,
      severity: summarizeEvidenceBySeverity(evidence),
      tools_used: toolsUsed
    },
    evidence: evidence.map((item) => {
      const module = moduleById(item?.module_id);
      return {
        module_id: item?.module_id || "",
        module_title: item?.module_title || "",
        phase_label: item?.phase_label || "",
        severity: item?.severity || "info",
        summary: item?.summary || "",
        details: Array.isArray(item?.details) ? item.details : [],
        execution_profile: item?.execution_profile || "",
        collected_at: item?.collected_at || "",
        tools_used: toolsForEvidenceItem(item),
        command_preview: module ? commandPreviewForModule(module).map((command) => normalizeCommandForTarget(command, evidenceJob?.target || currentTargetValue())) : [],
        artifacts: item?.artifacts || {}
      };
    })
  };
}

function downloadJsonFile(filename, payload) {
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

function severityRank(key) {
  return { critical: 4, high: 3, medium: 2, low: 1, info: 0 }[String(key || "info").toLowerCase()] ?? 0;
}

function resolveVisibleEvidence(job) {
  let evidenceJob = job;
  let evidence = (job?.evidence || []).slice();

  if (!evidence.length) {
    const fallbackJob = (state.jobs || [])
      .filter((entry) => entry?.id !== job?.id && evidenceCount(entry) > 0)
      .sort((a, b) => {
        const evidenceDelta = evidenceCount(b) - evidenceCount(a);
        if (evidenceDelta !== 0) return evidenceDelta;
        return compareJobFreshness(a, b);
      })[0];
    if (fallbackJob) {
      evidenceJob = fallbackJob;
      evidence = (fallbackJob.evidence || []).slice();
    }
  }

  evidence = evidence.sort((a, b) => {
    const severityDelta = severityRank(b?.severity) - severityRank(a?.severity);
    if (severityDelta !== 0) return severityDelta;
    const aTime = new Date(a?.collected_at || 0).getTime();
    const bTime = new Date(b?.collected_at || 0).getTime();
    return bTime - aTime;
  });

  return {
    evidenceJob,
    evidence,
    severitySummary: summarizeEvidenceBySeverity(evidence)
  };
}

function evidenceArtifactHighlights(item) {
  const artifacts = item?.artifacts || {};
  const severity = String(item?.severity || "info").toLowerCase();
  const highlights = [];

  const push = (text, level = severity) => {
    if (!text) return;
    highlights.push({ severity: String(level || severity).toLowerCase(), text: String(text) });
  };

  const artifactLines = (value) => String(value || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  const openPorts = Array.isArray(artifacts.open_ports) ? artifacts.open_ports : [];
  for (const entry of openPorts.slice(0, 6)) {
    if (!entry?.port) continue;
    const versionPart = entry.version ? ` ${entry.version}` : "";
    push(`Open port detected: ${entry.port}/${entry.state || "tcp"} ${entry.service || "unknown"}${versionPart}`);
  }

  if (artifacts.host_alive === true) {
    push("Host aktif di jaringan", "low");
  }

  const ipAddresses = Array.isArray(artifacts.ip_addresses) ? artifacts.ip_addresses : [];
  for (const ip of ipAddresses.slice(0, 4)) {
    push(`IP target aktif: ${ip}`, "low");
  }

  const hostnames = []
    .concat(Array.isArray(artifacts.hostnames) ? artifacts.hostnames : [])
    .concat(typeof artifacts.hostname === "string" && artifacts.hostname ? [artifacts.hostname] : []);
  for (const host of hostnames.slice(0, 3)) {
    push(`Hostname/perangkat: ${host}`, "low");
  }

  const macAddresses = Array.isArray(artifacts.mac_addresses) ? artifacts.mac_addresses : [];
  for (const mac of macAddresses.slice(0, 3)) {
    push(`MAC address: ${mac}`, "low");
  }

  const vendors = Array.isArray(artifacts.vendors) ? artifacts.vendors : [];
  for (const vendor of vendors.slice(0, 3)) {
    push(`Vendor perangkat: ${vendor}`, "low");
  }

  const deviceTypes = Array.isArray(artifacts.device_types) ? artifacts.device_types : [];
  for (const device of deviceTypes.slice(0, 3)) {
    push(`Jenis perangkat: ${device}`, "low");
  }

  if (Number.isFinite(Number(artifacts.closed_count)) && Number(artifacts.closed_count) > 0) {
    push(`Port tertutup terdeteksi: ${artifacts.closed_count}`, "low");
  }
  if (Number.isFinite(Number(artifacts.filtered_count)) && Number(artifacts.filtered_count) > 0) {
    push(`Port ter-filter/firewall: ${artifacts.filtered_count}`, "medium");
  }

  if (artifacts.latency) {
    push(`Latency host: ${artifacts.latency}`, "low");
  }
  if (artifacts.network_distance) {
    push(`Network distance: ${artifacts.network_distance}`, "low");
  }

  const osGuesses = []
    .concat(Array.isArray(artifacts.os_matches) ? artifacts.os_matches : [])
    .concat(Array.isArray(artifacts.os_guess) ? artifacts.os_guess : [])
    .concat(typeof artifacts.os_guess === "string" ? [artifacts.os_guess] : []);
  for (const guess of osGuesses.slice(0, 2)) {
    push(`OS hint: ${guess}`, "medium");
  }

  const versions = Array.isArray(artifacts.service_versions) ? artifacts.service_versions : [];
  for (const version of versions.slice(0, 4)) {
    push(`Service/version: ${version}`, "medium");
  }

  const databaseServices = Array.isArray(artifacts.database_services) ? artifacts.database_services : [];
  for (const service of databaseServices.slice(0, 6)) {
    push(`Database service exposed: ${service}`, "high");
  }

  const cves = Array.isArray(artifacts.cves) ? artifacts.cves : [];
  for (const cve of cves.slice(0, 8)) {
    push(`CVE detected: ${cve}`, "high");
  }

  const subdomains = Array.isArray(artifacts.subdomains) ? artifacts.subdomains : [];
  for (const subdomain of subdomains.slice(0, 8)) {
    push(`Subdomain discovered: ${subdomain}`, "medium");
  }

  const dnsRecords = Array.isArray(artifacts.dns_records) ? artifacts.dns_records : [];
  for (const record of dnsRecords.slice(0, 8)) {
    push(`DNS record: ${record}`, "low");
  }

  const paths = Array.isArray(artifacts.paths) ? artifacts.paths : [];
  for (const path of paths.slice(0, 6)) {
    push(`Sensitive path exposed: ${path}`, severity);
  }

  const robotsPaths = Array.isArray(artifacts.robots_paths) ? artifacts.robots_paths : [];
  for (const path of robotsPaths.slice(0, 8)) {
    push(`robots.txt hint: ${path}`, "medium");
  }

  const indexedPaths = Array.isArray(artifacts.indexed_paths) ? artifacts.indexed_paths : [];
  for (const path of indexedPaths.slice(0, 8)) {
    push(`Directory indexing enabled: ${path}`, "high");
  }

  const routes = Array.isArray(artifacts.routes) ? artifacts.routes : [];
  for (const route of routes.slice(0, 8)) {
    push(`Route discovered: ${route}`, /\b401\b|\b403\b/.test(route) ? "medium" : "high");
  }

  const httpTitles = Array.isArray(artifacts.http_titles) ? artifacts.http_titles : [];
  for (const title of httpTitles.slice(0, 4)) {
    push(`HTTP title: ${title}`, "medium");
  }

  const httpHeaders = Array.isArray(artifacts.http_headers) ? artifacts.http_headers : [];
  for (const header of httpHeaders.slice(0, 6)) {
    push(`HTTP header/server info: ${header}`, "medium");
  }

  const httpMethods = Array.isArray(artifacts.http_methods) ? artifacts.http_methods : [];
  for (const method of httpMethods.slice(0, 4)) {
    push(`HTTP methods: ${method}`, /put|delete|trace/i.test(method) ? "high" : "medium");
  }

  const smbDetails = Array.isArray(artifacts.smb_details) ? artifacts.smb_details : [];
  for (const detail of smbDetails.slice(0, 6)) {
    push(`SMB/Windows detail: ${detail}`, "medium");
  }

  const tracerouteHops = Array.isArray(artifacts.traceroute_hops) ? artifacts.traceroute_hops : [];
  for (const hop of tracerouteHops.slice(0, 6)) {
    push(`Traceroute hop: ${hop}`, "low");
  }

  const firewallIndicators = Array.isArray(artifacts.firewall_indicators) ? artifacts.firewall_indicators : [];
  for (const value of firewallIndicators.slice(0, 6)) {
    push(`Firewall/ACL indicator: ${value}`, "medium");
  }

  const serviceMisconfigs = Array.isArray(artifacts.service_misconfigurations) ? artifacts.service_misconfigurations : [];
  for (const value of serviceMisconfigs.slice(0, 6)) {
    push(`Service misconfiguration: ${value}`, "high");
  }

  const sensitiveFiles = Array.isArray(artifacts.sensitive_files) ? artifacts.sensitive_files : [];
  for (const file of sensitiveFiles.slice(0, 8)) {
    push(`Sensitive file discovered: ${file}`, /id_rsa|authorized_keys|\.env|wp-config\.php|config\.php|\.pem|\.key|shadow/i.test(file) ? "critical" : "high");
  }

  const suspiciousPhpFiles = Array.isArray(artifacts.suspicious_php_files) ? artifacts.suspicious_php_files : [];
  for (const file of suspiciousPhpFiles.slice(0, 10)) {
    push(`Suspicious PHP file exposed: ${file}`, "high");
  }

  const sensitiveLines = Array.isArray(artifacts.sensitive_lines) ? artifacts.sensitive_lines : [];
  for (const line of sensitiveLines.slice(0, 8)) {
    push(`Sensitive content excerpt: ${line}`, "critical");
  }

  const redactedPreview = Array.isArray(artifacts.redacted_preview) ? artifacts.redacted_preview : [];
  for (const line of redactedPreview.slice(0, 5)) {
    push(`Redacted file preview: ${line}`, "high");
  }

  if (artifacts.file_path) {
    push(`Sensitive file path: ${artifacts.file_path}`, "high");
  }

  const httpxOutput = artifactLines(artifacts.httpx_output);
  for (const line of httpxOutput.slice(0, 3)) {
    push(`HTTP fingerprint: ${line}`, "medium");
  }

  const whatwebOutput = artifactLines(artifacts.whatweb_output);
  for (const line of whatwebOutput.slice(0, 3)) {
    push(`Web tech/version: ${line}`, "medium");
  }

  const nucleiOutput = artifactLines(artifacts.nuclei_output);
  for (const line of nucleiOutput.slice(0, 8)) {
    push(`Nuclei finding: ${line}`, /critical|high/i.test(line) ? "high" : "medium");
  }

  const nucleiStructuredGroups = [
    ["exposed_admin_panels", "Exposed admin panel", "high"],
    ["exposed_config_files", "Exposed config file", "critical"],
    ["exposed_secrets", "Exposed secret/token", "critical"],
    ["misconfigurations", "Nuclei misconfiguration", "high"],
    ["default_credential_indicators", "Default credential indicator", "high"],
    ["vulnerable_endpoints", "Vulnerable endpoint", "high"],
    ["directory_exposures", "Directory exposure", "high"],
    ["subdomain_takeover_indicators", "Subdomain takeover indicator", "high"],
    ["open_redirect_indicators", "Open redirect indicator", "medium"],
    ["cors_misconfigurations", "CORS misconfiguration", "medium"],
    ["ssrf_indicators", "SSRF indicator", "high"],
    ["sqli_indicators", "SQL injection indicator", "high"],
    ["xss_indicators", "XSS indicator", "high"],
    ["rce_indicators", "RCE indicator", "critical"],
    ["lfi_rfi_indicators", "LFI/RFI indicator", "high"],
    ["auth_bypass_indicators", "Authentication bypass indicator", "high"],
    ["information_disclosures", "Information disclosure", "medium"],
    ["technology_fingerprints", "Technology fingerprint", "medium"],
    ["cloud_exposures", "Cloud exposure", "high"],
    ["network_misconfigurations", "Network/service misconfiguration", "high"],
    ["ssl_issues", "SSL/TLS issue", "medium"],
    ["security_header_issues", "Security header issue", "medium"],
    ["vulnerable_components", "Vulnerable CMS/plugin/framework", "high"]
  ];
  for (const [key, label, level] of nucleiStructuredGroups) {
    const values = Array.isArray(artifacts[key]) ? artifacts[key] : [];
    for (const value of values.slice(0, 6)) {
      push(`${label}: ${value}`, level);
    }
  }

  const niktoFindings = []
    .concat(Array.isArray(artifacts.nikto_findings) ? artifacts.nikto_findings : [])
    .concat(artifactLines(artifacts.nikto_output));
  for (const line of niktoFindings.slice(0, 12)) {
    if (line.startsWith("+") || line.startsWith("!")) {
      push(`Nikto finding: ${line}`, /OSVDB|CVE|admin|backup|upload|exposed|outdated|interesting/i.test(line) ? "high" : "medium");
    }
  }

  const niktoGroups = [
    ["server_banners", "Web server/banner", "medium"],
    ["outdated_components", "Outdated component", "high"],
    ["sensitive_paths", "Sensitive/default path", "high"],
    ["directory_indexing", "Directory listing open", "high"],
    ["default_pages", "Default page/file", "medium"],
    ["cgi_risks", "CGI risk", "high"],
    ["http_methods", "Dangerous HTTP method", "high"],
    ["security_headers", "Missing security header", "medium"],
    ["cookie_issues", "Cookie issue", "medium"],
    ["ssl_issues", "Nikto SSL/TLS issue", "medium"],
    ["interesting_urls", "Interesting URL", "medium"],
    ["misconfigurations", "Web server misconfiguration", "high"]
  ];
  for (const [key, label, level] of niktoGroups) {
    const values = Array.isArray(artifacts[key]) ? artifacts[key] : [];
    for (const value of values.slice(0, 6)) {
      push(`${label}: ${value}`, level);
    }
  }

  const dirEntries = []
    .concat(Array.isArray(artifacts.dir_entries) ? artifacts.dir_entries : [])
    .concat(Array.isArray(artifacts.gobbuster_paths) ? artifacts.gobbuster_paths : []);
  for (const entry of dirEntries.slice(0, 10)) {
    if (entry && typeof entry === "object") {
      const path = entry.path ? `/${entry.path}` : "/";
      const status = entry.status ? ` (Status: ${entry.status})` : "";
      const redirect = entry.redirect ? ` -> ${entry.redirect}` : "";
      push(`Directory/file found: ${path}${status}${redirect}`, entry.status === 403 || entry.status === 401 ? "medium" : "high");
    } else {
      push(`Directory/file found: ${entry}`, "high");
    }
  }

  const tlsFindings = []
    .concat(Array.isArray(artifacts.tls_findings) ? artifacts.tls_findings : [])
    .concat(Array.isArray(artifacts.certificate_details) ? artifacts.certificate_details : [])
    .concat(Array.isArray(artifacts.tls_details) ? artifacts.tls_details : []);
  for (const finding of tlsFindings.slice(0, 8)) {
    push(`TLS finding: ${finding}`, /expired|weak|tls 1\.0|tls 1\.1|self-signed/i.test(finding) ? "high" : "medium");
  }

  if (artifacts.tls_version) {
    push(`TLS version: ${artifacts.tls_version}`, "medium");
  }
  if (artifacts.cipher) {
    push(`TLS cipher: ${artifacts.cipher}`, "medium");
  }

  if (artifacts.vulnerable_parameter) {
    push(`SQL injection parameter: ${artifacts.vulnerable_parameter}`, "critical");
  }

  const sqlFindings = Array.isArray(artifacts.sql_findings) ? artifacts.sql_findings : [];
  for (const finding of sqlFindings.slice(0, 8)) {
    push(`SQLMap finding: ${finding}`, /critical|dbms|payload|inject/i.test(finding) ? "critical" : "high");
  }

  const jwtFindings = Array.isArray(artifacts.jwt_findings) ? artifacts.jwt_findings : [];
  for (const finding of jwtFindings.slice(0, 8)) {
    push(`JWT finding: ${finding}`, /none|weak|signature|kid/i.test(finding) ? "high" : "medium");
  }

  const bloodhoundFindings = Array.isArray(artifacts.bloodhound_findings) ? artifacts.bloodhound_findings : [];
  for (const finding of bloodhoundFindings.slice(0, 8)) {
    push(`Lateral path insight: ${finding}`, "high");
  }

  const credentialArtifacts = [
    ["hardcoded_credentials", "Hardcoded credential"],
    ["credential_hits", "Credential hit"],
    ["credentials", "Credential exposed"],
    ["secrets", "Secret exposed"],
    ["password_hits", "Password exposure"],
    ["exposed_files", "Exposed file"],
    ["cracked_hashes", "Cracked hash"],
    ["users", "User account discovered"],
    ["john_hits", "John password hit"],
  ];
  for (const [key, label] of credentialArtifacts) {
    const values = Array.isArray(artifacts[key]) ? artifacts[key] : [];
    for (const value of values.slice(0, 5)) {
      push(`${label}: ${value}`, "high");
    }
  }

  if (artifacts.ftp_anonymous === true) {
    push("Anonymous FTP login allowed", "critical");
  }

  const ftpListing = Array.isArray(artifacts.ftp_listing) ? artifacts.ftp_listing : [];
  for (const file of ftpListing.slice(0, 10)) {
    push(`FTP file listed: ${file}`, /config|cred|backup|db|secret|sql|env/i.test(file) ? "high" : "medium");
  }

  if (artifacts.download_url) {
    push(`Downloaded from: ${artifacts.download_url}`, "medium");
  }

  if (artifacts.file_type) {
    push(`File type: ${artifacts.file_type}`, "medium");
  }

  if (artifacts.has_sensitive_data === true) {
    push("Sensitive data indicators detected in downloaded content", "critical");
  }

  const observations = Array.isArray(artifacts.http_observations) ? artifacts.http_observations : [];
  for (const value of observations.slice(0, 4)) {
    push(`HTTP observation: ${value}`, "medium");
  }

  const cookies = Array.isArray(artifacts.cookies) ? artifacts.cookies : [];
  for (const cookie of cookies.slice(0, 4)) {
    push(`Cookie observed: ${cookie}`, /secure|httponly|samesite/i.test(cookie) ? "medium" : "low");
  }

  const genericArtifactOutputs = [
    { key: "ping_result", label: "Ping result", level: "low", limit: 2 },
    { key: "nmap_output", label: "Host discovery", level: "low", limit: 4 },
    { key: "dig_output", label: "DNS output", level: "low", limit: 4 },
    { key: "dnsx_output", label: "DNSx output", level: "medium", limit: 4 },
    { key: "sslyze_output", label: "SSLyze finding", level: "medium", limit: 6 },
    { key: "sqlmap_output", label: "SQLMap finding", level: "high", limit: 6 },
    { key: "hydra_output", label: "Hydra finding", level: "high", limit: 6 },
    { key: "jwt_output", label: "JWT output", level: "medium", limit: 6 },
    { key: "bloodhound_output", label: "BloodHound finding", level: "high", limit: 6 },
    { key: "certificate", label: "Certificate detail", level: "medium", limit: 4 },
  ];
  for (const source of genericArtifactOutputs) {
    const lines = artifactLines(artifacts[source.key]);
    for (const line of lines.slice(0, source.limit)) {
      if (line.length < 3) continue;
      if (/^Nikto|^\-+$|^\d+\s+host\(s\)\s+tested/i.test(line)) continue;
      push(`${source.label}: ${line}`, /critical|vulnerable|injection|weak|exposed|found/i.test(line) ? "high" : source.level);
    }
  }

  const evidenceText = Array.isArray(item?.details) ? item.details : [];
  for (const line of evidenceText.slice(0, 20)) {
    const text = String(line || "").trim();
    if (!text) continue;
    if (/CVE-\d{4}-\d+/i.test(text)) {
      push(`CVE detected: ${text}`, "high");
    } else if (/LFI|local file inclusion|path traversal|\.\.\/|\/etc\/passwd/i.test(text)) {
      push(`LFI/path traversal indicator: ${text}`, "high");
    } else if (/missing .*header|x-frame-options|x-content-type-options|content-security-policy/i.test(text)) {
      push(`Security header issue: ${text}`, "medium");
    } else if (/password|credential|secret|api[_ -]?key|token/i.test(text)) {
      push(`Credential indicator: ${text}`, "high");
    } else if (/\/[A-Za-z0-9._\-\/]+\s+\(Status:\s*(200|204|301|302|307|401|403)\)/i.test(text)) {
      push(`Route discovered: ${text}`, /401|403/.test(text) ? "medium" : "high");
    } else if (/^\+\s+/i.test(text)) {
      push(`Scanner finding: ${text}`, /admin|backup|upload|exposed|interesting|cve/i.test(text) ? "high" : "medium");
    } else if (/\[(?:critical|high|medium|low|info)\]/i.test(text) || /\[[a-z0-9\-_/]+\]/i.test(text)) {
      push(`Template finding: ${text}`, /critical|high/i.test(text) ? "high" : "medium");
    } else if (/hardcoded|default credentials|password reuse|weak password/i.test(text)) {
      push(`Credential weakness: ${text}`, "high");
    } else if (/^\/\S+\s+\((200|204|301|302|307|401|403)\)/i.test(text)) {
      push(`Route discovered: ${text}`, /\b401\b|\b403\b/.test(text) ? "medium" : "high");
    } else if (/\/tcp\s+open|open\s+\w+/i.test(text)) {
      push(`Service exposure: ${text}`, severity);
    } else if (/Apache|nginx|IIS|OpenSSH|PHP|WordPress|Tomcat|Jetty|MySQL|PostgreSQL/i.test(text)) {
      push(`Version/technology hint: ${text}`, "medium");
    }
  }

  const unique = [];
  const seen = new Set();
  for (const entry of highlights) {
    const key = `${entry.severity}|${entry.text}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(entry);
  }
  return unique.slice(0, 40);
}

function inferDetailSeverity(text, fallback = "info") {
  const value = String(text || "");
  if (/critical|vulnerable|sql injection|credential|password|secret|token|exposed|cracked|downloadable/i.test(value)) return "critical";
  if (/cve|high|outdated|backup|admin|jwt|nikto|nuclei|route|path|subdomain/i.test(value)) return "high";
  if (/tls|ssl|cookie|http|tech|service|version|dns|medium/i.test(value)) return "medium";
  if (/info|low|host|port|status/i.test(value)) return "low";
  return fallback;
}

function evidenceRawDetailEntries(item) {
  const details = Array.isArray(item?.details) ? item.details : [];
  return details
    .map((line) => String(line || "").trim())
    .filter(Boolean)
    .slice(0, 12)
    .map((text) => ({
      severity: inferDetailSeverity(text, String(item?.severity || "info").toLowerCase()),
      text
    }));
}

function jobNseHighlights(job, limit = 2) {
  const found = [];
  const seen = new Set();
  for (const item of (job?.evidence || [])) {
    const structured = item?.artifacts?.nse_findings_structured || [];
    for (const entry of structured) {
      if (!entry?.finding) continue;
      const key = `${entry.script}|${entry.severity}|${entry.finding}`;
      if (seen.has(key)) continue;
      seen.add(key);
      found.push({
        severity: String(entry.severity || "info").toLowerCase(),
        script: entry.script || "nse",
        finding: entry.finding
      });
    }
  }
  return found
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity))
    .slice(0, limit);
}

function jobHeadline(job) {
  const nse = jobNseHighlights(job, 1)[0];
  if (nse) {
    return `${String(nse.severity).toUpperCase()} · nmap/${nse.script} · ${nse.finding}`;
  }
  const topEvidence = (job?.evidence || [])
    .slice()
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity))[0];
  return topEvidence?.summary || (job?.scope_type === "chain" ? "Full chain assessment" : job?.target || "-");
}

function timelineEvidenceForRun(job, run) {
  return (job?.evidence || [])
    .filter((item) => item.module_id === run.module_id)
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
}

function timelineCommandsForRun(job, run, nextRun) {
  const logs = job?.logs || [];
  const startTitle = `=== [${run.phase_label}] ${run.title} ===`;
  const endTitle = nextRun ? `=== [${nextRun.phase_label}] ${nextRun.title} ===` : null;
  let capture = false;
  const commands = [];
  const seen = new Set();

  for (const entry of logs) {
    const message = String(entry?.message || "");
    if (message === startTitle) {
      capture = true;
      continue;
    }
    if (capture && endTitle && message === endTitle) {
      break;
    }
    if (!capture) continue;
    if (!message.trim().startsWith("$ ")) continue;
    if (seen.has(message)) continue;
    seen.add(message);
    commands.push(message);
  }

  return commands.slice(0, 4);
}

function normalizeCommandForTarget(command, target) {
  const safeTarget = String(target || "").trim();
  if (!safeTarget) return command;

  return String(command || "")
    .replaceAll("target.lab.local", safeTarget)
    .replaceAll("mail.lab.local", safeTarget)
    .replaceAll("user@lab.local", `user@${safeTarget}`)
    .replaceAll("redteam@lab.local", `redteam@${safeTarget}`)
    .replaceAll("https://lab.local", `https://${safeTarget}`)
    .replaceAll("http://lab.local", `http://${safeTarget}`)
    .replaceAll("ssh://target", `ssh://${safeTarget}`)
    .replaceAll("target:443", `${safeTarget}:443`)
    .replaceAll("TARGET/page", `${safeTarget}/page`)
    .replaceAll("TARGET", safeTarget)
    .replaceAll(" lab.local ", ` ${safeTarget} `)
    .replaceAll("-d lab.local", `-d ${safeTarget}`)
    .replaceAll(" lab.local]", ` ${safeTarget}]`)
    .replaceAll(" lab.local", ` ${safeTarget}`);
}

function renderTimeline(job) {
  const container = $("#timelineList");
  const label = $("#timelineCountLabel");
  if (!container || !label) return;
  const runs = (job?.module_runs || []).filter((run) => {
    const status = String(run?.status || "");
    const evidenceCount = Number(run?.evidence_count || 0);
    return evidenceCount > 0 || ["running", "completed", "failed", "stalled"].includes(status);
  });
  label.textContent = `${runs.length} phases`;

  if (!runs.length) {
    container.innerHTML = `<p class="empty-jobs">Hanya modul yang sedang berjalan atau memiliki finding yang akan tampil di timeline.</p>`;
    return;
  }

  container.innerHTML = runs.map((run, index) => `
    ${(() => {
      const module = moduleById(run.module_id);
      const nextRun = runs[index + 1];
      const evidenceItems = timelineEvidenceForRun(job, run);
      const topEvidence = evidenceItems[0];
      const topNse = jobNseHighlights({ evidence: evidenceItems }, 2);
      const commands = timelineCommandsForRun(job, run, nextRun)
        .map((command) => normalizeCommandForTarget(command, job?.target));
      const toolChips = (module?.tooling || []).slice(0, 4)
        .map((tool) => `<span class="timeline-chip timeline-chip-tool">${tool}</span>`)
        .join("");
      const commandMarkup = commands.length
        ? `
          <div class="timeline-commands">
            <strong>Commands</strong>
            <div class="timeline-command-list">
              ${commands.map((command) => `<p class="timeline-command-code">${command}</p>`).join("")}
            </div>
          </div>
        `
        : ``;
      const findingMarkup = topEvidence
        ? `
          <div class="timeline-finding">
            <strong>Finding</strong>
            <p>${topEvidence.summary}</p>
            <div class="timeline-finding-meta">
              <span class="timeline-chip timeline-chip-severity severity-${topEvidence.severity}">${topEvidence.severity}</span>
              <span class="timeline-chip timeline-chip-evidence">${topEvidence.execution_profile}</span>
            </div>
            ${topNse.length ? `
              <div class="timeline-nse-list">
                ${topNse.map((entry) => `
                  <div class="timeline-nse-item severity-border-${entry.severity}">
                    <span class="severity-pill severity-${entry.severity}">${entry.severity}</span>
                    <span class="timeline-nse-text">nmap/${entry.script} · ${entry.finding}</span>
                  </div>
                `).join("")}
              </div>
            ` : ""}
          </div>
        `
        : ``;
      return `
    <article class="timeline-item-card severity-border-${run.highest_severity}">
      <div class="timeline-item-head">
        <strong>${String(index + 1).padStart(2, "0")} - ${run.phase_label}</strong>
        <span class="severity-pill severity-${run.highest_severity}">${run.highest_severity}</span>
      </div>
      <p>${run.title}</p>
      <div class="timeline-meta">
        <span>${run.status}</span>
        <span>${run.progress}%</span>
        <span>${run.execution_profile}</span>
        <span>${run.evidence_count} evidence</span>
      </div>
      <div class="timeline-tools">
        <strong>Tools</strong>
        <div class="timeline-chip-row">${toolChips || '<span class="timeline-chip timeline-chip-evidence">no tool mapped</span>'}</div>
      </div>
      ${commandMarkup}
      ${findingMarkup}
      <div class="timeline-progress">
        <div class="timeline-progress-fill" style="width:${Number(run.progress || 0)}%"></div>
      </div>
    </article>
      `;
    })()}
  `).join("");
}

function renderEvidence(job, resolved = resolveVisibleEvidence(job)) {
  const container = $("#evidenceList");
  const label = $("#evidenceCountLabel");
  const exportButton = $("#exportVisibleEvidenceBtn");
  const evidenceJob = resolved?.evidenceJob || job;
  const evidence = Array.isArray(resolved?.evidence) ? resolved.evidence : [];
  label.textContent = `${evidence.length} items`;
  if (exportButton) exportButton.disabled = !evidence.length;

  if (!evidence.length) {
    container.innerHTML = `<p class="empty-jobs">Evidence akan muncul setelah modul mulai menghasilkan temuan.</p>`;
    return;
  }

  const fallbackNotice = evidenceJob?.id && evidenceJob.id !== job?.id
    ? `
      <article class="evidence-item severity-border-info">
        <div class="evidence-head">
          <strong>Menampilkan temuan terbaru yang tersedia</strong>
          <span class="severity-pill severity-info">info</span>
        </div>
        <p class="evidence-detail">Job yang sedang dipilih belum menghasilkan evidence. Panel ini menampilkan ${evidence.length} temuan dari ${evidenceJob.scope_label} agar finding terbaru tetap terlihat di layar.</p>
        <small>${evidenceJob.scope_label} - ${evidenceJob.phase_label || evidenceJob.status || "job"}</small>
      </article>
    `
    : "";

  const severityDetailMarkup = (entry) => {
    const text = String(entry?.text || "");
    const level = String(entry?.severity || "info").toLowerCase();
    return `
      <div class="evidence-detail-row severity-border-${level}">
        <span class="severity-pill severity-${level}">${level}</span>
        <p class="evidence-detail evidence-detail-code">${text}</p>
      </div>
    `;
  };

  const toolsMarkup = (item) => {
    const tools = Array.from(new Set(
      ((Array.isArray(item?.tools_used) ? item.tools_used : []).concat(toolsForEvidenceItem(item)))
        .map((tool) => String(tool || "").trim())
        .filter(Boolean)
    ));
    if (!tools.length) return "";
    return `
      <div class="evidence-tools">
        <strong>Tools</strong>
        <div class="timeline-chip-row">${tools.map((tool) => `<span class="timeline-chip timeline-chip-tool">${tool}</span>`).join("")}</div>
      </div>
    `;
  };

  const itemDetailMarkup = (item) => {
    const structured = Array.isArray(item?.artifacts?.nse_findings_structured)
      ? item.artifacts.nse_findings_structured
          .filter((entry) => entry && entry.finding)
          .slice(0, 8)
          .map((entry) => ({
            severity: entry.severity || "info",
            text: `nmap/${entry.script || "nse"} · ${entry.finding}`
          }))
      : [];
    const artifactHighlights = evidenceArtifactHighlights(item);
    const rawDetails = evidenceRawDetailEntries(item);
    const combined = [...structured, ...artifactHighlights, ...rawDetails];
    const deduped = [];
    const seen = new Set();
    for (const entry of combined) {
      const text = String(entry?.text || "").trim();
      if (!text) continue;
      const key = text.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      deduped.push({
        severity: String(entry?.severity || item?.severity || "info").toLowerCase(),
        text
      });
    }
    if (!deduped.length) {
      return `<p class="evidence-detail">Belum ada detail temuan tambahan.</p>`;
    }
    return deduped.slice(0, 40).map(severityDetailMarkup).join("");
  };

  container.innerHTML = `${fallbackNotice}${evidence.map((item) => `
    <article class="evidence-item severity-border-${item.severity}">
      <div class="evidence-head">
        <strong>${item.summary}</strong>
        <span class="severity-pill severity-${item.severity}">${item.severity}</span>
      </div>
      ${toolsMarkup(item)}
      ${itemDetailMarkup(item)}
      <small>${item.module_title} - ${item.phase_label}</small>
    </article>
  `).join("")}`;
}

function renderJobProgress(job) {
  const progress = Number(job?.progress || 0);
  $("#jobProgressValue").textContent = `${progress}%`;
  $("#jobProgressBar").style.width = `${progress}%`;
  const hasJob = Boolean(job);
  $("#viewHtmlBtn").disabled = !hasJob;
  $("#viewJobEvidenceBtn").disabled = !hasJob;
  $("#viewJobMarkdownBtn").disabled = !hasJob;
}

function renderConsole(job) {
  if (state.activeInteractiveSession) {
    renderInteractiveConsoleSession(state.activeInteractiveSession);
    return;
  }
  const output = $("#consoleOutput");
  const activeLabel = $("#activeJobLabel");
  const commandLabel = $("#activeCommandLabel");
  if (!job) {
    state.activeJob = null;
    output.textContent = "Pilih job dari riwayat atau jalankan modul baru.";
    activeLabel.textContent = "No job selected";
    if (commandLabel) commandLabel.textContent = "No active command";
    renderSeveritySummary({});
    renderTimeline(null);
    renderEvidence(null);
    renderJobProgress(null);
    setConsoleStatus("idle", "idle");
    return;
  }

  state.activeJob = job;
  if (job.target) {
    const targetInput = $("#targetInput");
    if (targetInput) targetInput.value = job.target;
    persistLastTarget(job.target);
  }
  activeLabel.textContent = job.scope_label.includes(job.target)
    ? job.scope_label
    : `${job.scope_label} - ${job.target}`;
  if (commandLabel) commandLabel.textContent = currentCommand(job);
  output.textContent = logLines(job.logs) || "Job belum memiliki log.";
  output.scrollTop = output.scrollHeight;
  const resolvedEvidence = resolveVisibleEvidence(job);
  renderSeveritySummary(resolvedEvidence.severitySummary);
  renderTimeline(job);
  renderEvidence(job, resolvedEvidence);
  renderJobProgress(job);
  setConsoleStatus(job.status, job.status);
}

async function loadConfig() {
  state.config = await api("/api/config");
  renderConfig();
  renderDestructiveActions();
}

function readAllowedSubnets() {
  return ($("#allowedSubnetsInput").value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

async function saveAllowedSubnets() {
  try {
    const allowedSubnets = readAllowedSubnets();
    let password = "";
    if (state.config?.range_password_configured) {
      password = await requestRangePassword();
      if (!password) {
        showToast("Simpan ranges dibatalkan.");
        return;
      }
    }
    const result = await api("/api/config/allowed-subnets", {
      method: "POST",
      body: JSON.stringify({ allowed_subnets: allowedSubnets, password })
    });
    state.config = result.config;
    renderConfig();
    showToast(result.message || "Approved ranges berhasil disimpan.");
  } catch (error) {
    showToast(error.message);
  }
}

async function reloadConfig() {
  try {
    const result = await api("/api/config/reload", { method: "POST" });
    state.config = result.config;
    renderConfig();
    showToast(result.message || "Konfigurasi lab dimuat ulang.");
  } catch (error) {
    showToast(error.message);
  }
}

async function loadModules(forceRefresh = false) {
  const cachedModules = !forceRefresh ? readModulesCache() : null;
  if (cachedModules?.length) {
    state.modules = cachedModules;
    syncModuleProfileSelect();
    scheduleModulesRender();
    scheduleDeferredTask(async () => {
      try {
        const refresh = await api("/api/modules");
        const freshModules = Array.isArray(refresh?.modules) ? refresh.modules : [];
        if (!freshModules.length) return;
        state.modules = freshModules;
        writeModulesCache(freshModules);
        syncModuleProfileSelect();
        scheduleModulesRender();
      } catch (error) {
        console.warn(error);
      }
    });
    return;
  }

  const result = await api("/api/modules");
  state.modules = result.modules;
  writeModulesCache(result.modules);
  syncModuleProfileSelect();
  scheduleModulesRender();
}

async function loadChainPresets() {
  const result = await api("/api/chain-presets");
  state.chainPresets = Array.isArray(result.presets) ? result.presets : [];
  renderChainPresetSelect();
  renderChainPresetList();
}

async function loadToolingHealth() {
  const [catalogResult, statusResult] = await Promise.all([
    apiOptional("/api/tooling", { tools: [] }),
    apiOptional("/api/tools/status", { tools: {}, summary: {} })
  ]);
  state.toolingCatalog = Array.isArray(catalogResult.tools) ? catalogResult.tools : [];
  state.toolsStatus = statusResult || null;
  renderToolingHealth();
  if (state.catalogSurface === "tools") {
    scheduleModulesRender();
  }
}

async function loadReferenceData() {
  const [engagementResult, findingResult, assetResult] = await Promise.all([
    apiOptional("/api/engagements", { engagements: [] }),
    apiOptional("/api/findings", { findings: [] }),
    apiOptional("/api/assets", { assets: [] })
  ]);
  state.engagements = Array.isArray(engagementResult.engagements) ? engagementResult.engagements : [];
  state.referenceFindings = Array.isArray(findingResult.findings) ? findingResult.findings : [];
  state.assets = Array.isArray(assetResult.assets) ? assetResult.assets : [];
  renderReferenceData();
}

async function loadTargetAsset() {
  const target = currentTargetValue();
  const targetKey = `${currentTargetKind()}::${target}`;
  if (!target) {
    state.targetAsset = null;
    state.lastTargetAssetKey = "";
    renderTargetAsset();
    return;
  }
  if (state.lastTargetAssetKey === targetKey) {
    renderTargetAsset();
    return;
  }
  const requestSeq = ++state.targetAssetRequestSeq;
  try {
    const result = await api(`/api/assets/${encodeURIComponent(target)}`);
    if (requestSeq !== state.targetAssetRequestSeq) return;
    state.targetAsset = result.asset || null;
  } catch (error) {
    if (requestSeq !== state.targetAssetRequestSeq) return;
    state.targetAsset = null;
  }
  state.lastTargetAssetKey = targetKey;
  renderTargetAsset();
}

async function loadDestructiveActions() {
  const result = await apiOptional("/api/destructive/actions", { actions: [] });
  state.destructiveActions = Array.isArray(result.actions) ? result.actions : [];
  renderDestructiveActions();
}

async function loadAssessments() {
  const result = await api("/api/assessments");
  state.assessments = Array.isArray(result.assessments) ? result.assessments : [];
  if (!state.activeAssessmentId && state.assessments.length) {
    state.activeAssessmentId = state.assessments[0].id;
  }
  if (state.activeAssessmentId) {
    await loadAssessment(state.activeAssessmentId);
  } else {
    state.activeAssessment = null;
    state.activeApprovals = [];
    state.activeRecommendations = null;
    state.activeFindings = [];
    state.activeFindingSummary = null;
    state.activeAssessmentDetail = null;
    state.activeCorrelation = null;
    state.activeWorkspace = null;
    state.activeDiff = null;
    state.activeDrift = null;
    state.workspacePreviewPath = "";
    renderAssessmentSummary();
    renderAssessmentFindings();
    renderApprovalQueue();
    renderApprovalsDashboard();
    renderAssessmentLibrary();
    renderWorkspaceBrowser();
    renderAssessmentExportButtons();
  }
  renderAssessmentLibrary();
}

async function loadAssessment(assessmentId) {
  const result = await api(`/api/assessments/${assessmentId}`);
  state.activeAssessmentId = result.assessment.id;
  state.activeAssessment = result.assessment;
  state.activeApprovals = Array.isArray(result.approvals) ? result.approvals : [];
  state.activeRecommendations = result.recommendations || null;
  state.activeFindings = Array.isArray(result.findings) ? result.findings : [];
  state.activeFindingSummary = result.finding_summary || null;
  state.activeAssessmentDetail = result.detail || null;
  state.activeCorrelation = result.correlation || null;
  state.activeWorkspace = result.workspace || null;
  state.activeDiff = result.diff || null;
  state.activeDrift = result.drift || null;
  state.approvalsDashboard = result.approvals_dashboard || state.approvalsDashboard;
  setModuleExecutionProfile(profileForRiskMode(result.assessment.risk_mode || "safe"));
  if ($("#targetKindSelect")) {
    $("#targetKindSelect").value = result.assessment.target_kind === "url" ? "url" : "ip";
  }
  if ($("#targetInput")) {
    $("#targetInput").value = result.assessment.target || currentTargetValue();
    persistLastTarget(result.assessment.target || "");
  }
  if ($("#operatorNameInput")) {
    $("#operatorNameInput").value = result.assessment.operator_name || "operator";
  }
  if ($("#ticketRefInput")) {
    $("#ticketRefInput").value = result.assessment.ticket_ref || "";
  }
  renderAssessmentSummary();
  renderAssessmentFindings();
  renderApprovalQueue();
  renderApprovalsDashboard();
  renderChainPresetList();
  renderAssessmentLibrary();
  renderWorkspaceBrowser();
  renderAssessmentExportButtons();
  await loadTargetAsset();
}

function assessmentMatchesPayload(assessment, payload) {
  if (!assessment || !payload) return false;
  return assessment.target === payload.target
    && (assessment.target_kind || "ip") === payload.target_kind
    && assessment.risk_mode === payload.risk_mode;
}

async function createAssessment(payloadOverride = null) {
  try {
    const payload = payloadOverride || readTargetPayload();
    const result = await api("/api/assessments", {
      method: "POST",
      body: JSON.stringify({
        target: payload.target,
        target_kind: payload.target_kind,
        assessment_type: "internal",
        risk_mode: payload.risk_mode,
        chain_preset: payload.chain_preset,
        operator_name: payload.operator_name,
        ticket_ref: payload.ticket_ref,
        note: payload.note
      })
    });
    state.activeAssessmentId = result.assessment.id;
    state.assessments = [
      result.assessment,
      ...state.assessments.filter((item) => item.id !== result.assessment.id)
    ];
    renderAssessmentLibrary();
    await loadAssessment(result.assessment.id);
    showToast(`Assessment ${result.assessment.id.slice(0, 8)} dibuat.`);
    return result.assessment;
  } catch (error) {
    showToast(error.message);
    return null;
  }
}

async function ensureAssessmentForRiskMode(riskMode, payloadOverride = null) {
  const payload = payloadOverride || readTargetPayload();
  const desiredPayload = { ...payload, risk_mode: riskMode };
  if (assessmentMatchesPayload(state.activeAssessment, desiredPayload)) {
    return state.activeAssessment;
  }
  if (riskMode === "safe") {
    return null;
  }
  return await createAssessment(desiredPayload);
}

async function ensureModuleApproval(moduleId, payloadOverride = null) {
  return true;
}

async function ensureChainApproval(riskMode, chainPreset, payloadOverride = null) {
  return true;
}

async function approveAllPendingModules() {
  if (!state.activeAssessmentId || !state.activeAssessment) return;
  const approved = await ensureChainApproval(
    state.activeAssessment.risk_mode || activeAssessmentRiskMode(),
    state.activeAssessment?.metadata?.chain_preset || selectedChainPreset()
  );
  if (approved && state.activeAssessmentId) {
    await loadAssessment(state.activeAssessmentId);
  }
}

async function updateFindingStatus(findingId, status) {
  if (!state.activeAssessmentId) return;
  try {
    const note = window.prompt(`Catatan status untuk ${status}`, "") || "";
    const defaults = remediationPromptDefaults(findingId);
    const owner = window.prompt("Owner remediation", defaults.owner) || "";
    const due_date = window.prompt("Due date ISO (contoh 2026-07-15T17:00:00+07:00)", defaults.due_date) || "";
    const sla = window.prompt("SLA (contoh P1-3hari)", defaults.sla) || "";
    const result = await api(`/api/assessments/${state.activeAssessmentId}/findings/${findingId}`, {
      method: "PATCH",
      body: JSON.stringify({ status, note, owner, due_date, sla })
    });
    state.activeFindingSummary = result.summary || state.activeFindingSummary;
    state.activeDiff = result.diff || state.activeDiff;
    state.activeAssessmentDetail = result.detail || state.activeAssessmentDetail;
    await loadAssessment(state.activeAssessmentId);
    showToast(`Status finding diubah ke ${status}.`);
  } catch (error) {
    showToast(error.message);
  }
}

async function approveModuleFromQueue(moduleId) {
  const approved = await ensureModuleApproval(moduleId);
  if (approved && state.activeAssessmentId) {
    await loadAssessment(state.activeAssessmentId);
  }
}

async function loadJobs() {
  const result = await api("/api/jobs");
  state.jobs = result.jobs;
  if (state.jobs.length) {
    state.activeJobId = selectPreferredJobId(state.jobs, state.activeJobId);
  } else {
    state.activeJobId = null;
  }
  renderJobs();
}

async function loadJob(jobId) {
  const result = await api(`/api/jobs/${jobId}`);
  state.activeJobId = result.job.id;
  if (state.activeRecommendations && Array.isArray(result.recommendations)) {
    state.activeRecommendations = {
      ...(state.activeRecommendations || {}),
      recommended_modules: result.recommendations
    };
    renderAssessmentSummary();
  }
  renderConsole(result.job);
  renderJobs();
  if (state.activeAssessmentId && result.job?.runtime_meta?.assessment_id === state.activeAssessmentId) {
    await loadAssessment(state.activeAssessmentId);
  }

  const activeStates = new Set(["pending", "running"]);
  window.clearTimeout(state.pollTimer);
  if (activeStates.has(result.job.status)) {
    state.pollTimer = window.setTimeout(async () => {
      await loadJobs();
      await loadJob(jobId);
    }, 1200);
  }
}

async function deleteJob(jobId) {
  try {
    await api(`/api/jobs/${jobId}`, { method: "DELETE" });
    if (state.activeJobId === jobId) {
      state.activeJobId = null;
      renderConsole(null);
    }
    await loadJobs();
    if (state.jobs.length) {
      await loadJob(state.jobs[0].id);
    } else {
      renderConsole(null);
    }
    showToast("Job berhasil dihapus.");
  } catch (error) {
    showToast(error.message);
  }
}

async function stopJob(jobId) {
  try {
    const result = await api(`/api/jobs/${jobId}/stop`, { method: "POST" });
    showToast(result.message || "Stop request dikirim.");
    await loadJobs();
    if (state.activeJobId === jobId) {
      await loadJob(jobId);
    }
  } catch (error) {
    showToast(error.message);
  }
}

async function stopAllJobs() {
  try {
    const result = await api("/api/jobs/stop-all", { method: "POST" });
    showToast(result.message || "Stop request dikirim ke seluruh job aktif.");
    await loadJobs();
    if (state.activeJobId) {
      await loadJob(state.activeJobId);
    }
  } catch (error) {
    showToast(error.message);
  }
}

async function clearJobs() {
  try {
    await api("/api/jobs", { method: "DELETE" });
    state.activeJobId = null;
    await loadJobs();
    renderConsole(null);
    showToast("Seluruh job berhasil dihapus.");
  } catch (error) {
    showToast(error.message);
  }
}

function readTargetPayload() {
  const target = $("#targetInput").value.trim();
  const target_kind = currentTargetKind();
  const risk_mode = selectedRiskMode();
  const activeAssessmentMatches = assessmentMatchesPayload(state.activeAssessment, {
    target,
    target_kind,
    risk_mode
  });
  persistLastTarget(target);
  return {
    target,
    target_kind,
    note: `Phase filter: ${state.selectedPhase}`,
    execution_profile: selectedModuleProfile(),
    chain_preset: selectedChainPreset(),
    risk_mode,
    operator_name: currentOperatorName(),
    ticket_ref: currentTicketRef(),
    assessment_id: activeAssessmentMatches ? (state.activeAssessmentId || "") : ""
  };
}

async function runModule(moduleId) {
  try {
    const payload = readTargetPayload();
    const module = state.modules.find((item) => item.id === moduleId);
    if (!module) throw new Error("Module tidak ditemukan.");
    if (payload.risk_mode !== "safe") {
      const assessment = await ensureAssessmentForRiskMode(payload.risk_mode, payload);
      payload.assessment_id = assessment?.id || payload.assessment_id || "";
    }
    const result = await api("/api/jobs", {
      method: "POST",
      body: JSON.stringify({
        module_id: moduleId,
        target: payload.target,
        target_kind: payload.target_kind,
        note: payload.note,
        execution_profile: payload.execution_profile,
        assessment_id: payload.assessment_id,
        risk_mode: payload.risk_mode
      })
    });
    showToast("Job berhasil dibuat.");
    await loadJobs();
    await loadJob(result.job.id);
  } catch (error) {
    showToast(error.message);
  }
}

async function runFullChain() {
  if (state.chainRunPending) {
    showToast("Full simulation chain sedang diproses. Tunggu tahap saat ini selesai.");
    return;
  }
  try {
    window.clearTimeout(state.chainRunUiTimer);
    setRunChainUiState("preflight", "Memvalidasi target, profile, dan koneksi backend...");
    showToast("Memvalidasi target dan menyiapkan full chain...");
    const payload = readTargetPayload();
    let assessment = assessmentMatchesPayload(state.activeAssessment, payload)
      ? state.activeAssessment
      : null;

    if (!assessment) {
      setRunChainUiState("assessment", "Membuat assessment aktif untuk target dan mode yang dipilih...");
      showToast("Membuat assessment aktif...");
      assessment = await createAssessment(payload);
      if (!assessment?.id) {
        throw new Error("Assessment aktif gagal dibuat.");
      }
    }

    payload.assessment_id = assessment.id || "";

    setRunChainUiState("submitting", "Mengirim full simulation chain ke backend worker...");
    showToast("Mengirim full simulation chain ke backend tanpa approval queue...");
    const result = await api("/api/jobs/full-chain", {
      method: "POST",
      body: JSON.stringify({
        target: payload.target,
        target_kind: payload.target_kind,
        note: payload.note,
        execution_profile: payload.execution_profile,
        assessment_id: payload.assessment_id,
        risk_mode: payload.risk_mode,
        chain_preset: payload.chain_preset
      })
    });
    setRunChainUiState("success", "Job full chain berhasil dibuat. Membuka live console terbaru...");
    showToast(`Assessment ${payload.target} dimulai dengan profile ${payload.execution_profile} dan mode ${payload.risk_mode}.`);
    await loadJobs();
    await loadJob(result.job.id);
    state.chainRunUiTimer = window.setTimeout(() => setRunChainUiState("idle"), 2800);
  } catch (error) {
    setRunChainUiState("error", `Full chain gagal: ${error.message}`);
    showToast(error.message);
    state.chainRunUiTimer = window.setTimeout(() => setRunChainUiState("idle"), 3200);
  }
}

async function previewModule(moduleId) {
  const module = state.modules.find((item) => item.id === moduleId);
  if (!module) return;

  const payload = readTargetPayload();
  let dryRun = null;
  try {
    const cached = await fetchModuleDryRunData(moduleId);
    dryRun = cached?.dry_run || null;
  } catch (error) {
    showToast(error.message);
  }

  const preview = [
    `[ Preview ] ${module.title}`,
    `Fase              : ${module.phase_label}`,
    `Risk              : ${module.risk}`,
    `Skill Level       : ${module.skill_level}`,
    `Operator Focus    : ${module.operator_focus}`,
    `Sim Stance        : ${module.simulation_stance}`,
    `Depth Profile     : ${module.depth_profile}`,
    `Engine            : ${module.engine}`,
    `Mode              : ${module.mode}`,
    `Execution Profile : ${payload.execution_profile}`,
    `MITRE             : ${module.mitre}`,
    "",
    module.description,
    "",
    "Allowed Checks:",
    module.allowed_checks.map((item) => `- ${item}`).join("\n"),
    "",
    "Recommended WSL Tooling:",
    module.tooling.map((item) => `- ${item}`).join("\n"),
    "",
    "Evidence Targets:",
    module.evidence.map((item) => `- ${item}`).join("\n"),
    "",
    "Detection Surface:",
    module.telemetry.map((item) => `- ${item}`).join("\n"),
    "",
    "Resolved Commands:",
    (dryRun?.commands?.length
      ? dryRun.commands.map((item) => `${item}`).join("\n")
      : "- Tidak ada command reference untuk modul ini.").replaceAll("Â·", "·"),
    "",
    "Module Notes:",
    module.preview.join("\n")
  ].join("\n");

  $("#activeJobLabel").textContent = `${module.title} - preview`;
  $("#consoleOutput").textContent = preview;
  renderSeveritySummary({});
  renderTimeline(null);
  renderEvidence(null);
  setConsoleStatus("preview", "preview");
}

async function viewHtmlReport() {
  if (!state.activeJobId) return;
  const reportUrl = apiUrl(`/api/jobs/${state.activeJobId}/report.html`);
  const opened = window.open(reportUrl, "_blank", "noopener,noreferrer");
  if (!opened) {
    showToast("Popup diblokir browser. Izinkan tab baru untuk melihat report HTML.");
    return;
  }
  showToast("Report HTML dibuka di tab baru.");
}

function openUrlInNewTab(url, successMessage) {
  const opened = window.open(apiUrl(url), "_blank", "noopener,noreferrer");
  if (!opened) {
    showToast("Popup diblokir browser. Izinkan tab baru untuk membuka artefak.");
    return;
  }
  if (successMessage) showToast(successMessage);
}

function viewJobEvidence() {
  if (!state.activeJobId) return;
  openUrlInNewTab(`/api/jobs/${state.activeJobId}/evidence`, "Evidence job dibuka di tab baru.");
}

function viewJobMarkdown() {
  if (!state.activeJobId) return;
  openUrlInNewTab(`/api/jobs/${state.activeJobId}/report.md`, "Report markdown job dibuka di tab baru.");
}

function viewAssessmentEvidence() {
  if (!state.activeAssessmentId) return;
  openUrlInNewTab(`/api/assessments/${state.activeAssessmentId}/evidence`, "Assessment evidence dibuka di tab baru.");
}

function viewAssessmentMarkdown() {
  if (!state.activeAssessmentId) return;
  openUrlInNewTab(`/api/assessments/${state.activeAssessmentId}/report.md`, "Assessment markdown dibuka di tab baru.");
}

function viewAssessmentHtml() {
  if (!state.activeAssessmentId) return;
  openUrlInNewTab(`/api/assessments/${state.activeAssessmentId}/report.html`, "Assessment HTML dibuka di tab baru.");
}

function exportVisibleEvidenceJson() {
  const payload = visibleEvidenceExportPayload();
  if (!payload.evidence.length) {
    showToast("Belum ada evidence yang bisa diekspor.");
    return;
  }
  const targetLabel = String(payload.job?.target || payload.assessment?.target || "target")
    .replace(/[^a-z0-9._-]+/gi, "-")
    .replace(/^-+|-+$/g, "")
    || "target";
  downloadJsonFile(`evidence-highlights-${targetLabel}.json`, payload);
  showToast("Evidence JSON berhasil diekspor.");
}

async function refreshWorkspace() {
  if (!state.activeAssessmentId) return;
  const result = await api(`/api/assessments/${state.activeAssessmentId}/workspace`);
  state.activeWorkspace = result.workspace || null;
  renderWorkspaceBrowser();
}

async function openWorkspaceFile(path) {
  if (!state.activeAssessmentId || !path) return;
  const result = await api(`/api/assessments/${state.activeAssessmentId}/workspace/file?path=${encodeURIComponent(path)}`);
  state.workspacePreviewPath = result.file?.path || path;
  $("#workspacePreviewTitle").textContent = result.file?.name || path;
  $("#workspacePreviewMeta").textContent = `${result.file?.mime || "text/plain"} - ${result.file?.path || path}`;
  $("#workspacePreviewContent").textContent = result.file?.content || "";
}

async function parseImportedOutput() {
  try {
    const payload = readTargetPayload();
  const result = await api("/api/imports/parse", {
      method: "POST",
      body: JSON.stringify({
        tool_name: $("#importToolSelect")?.value || "generic",
        target: payload.target,
        target_kind: payload.target_kind,
        content: $("#importContentInput")?.value || ""
      })
    });
    state.importResult = result.result || null;
    renderImportResult();
    showToast("Output tool berhasil diparse.");
    openImportParserModal();
  } catch (error) {
    showToast(error.message);
  }
}

async function checkSingleTool(toolName) {
  try {
    const result = await api(`/api/tools/check/${encodeURIComponent(toolName)}`);
    const tools = { ...(state.toolsStatus?.tools || {}), [toolName]: result };
    state.toolsStatus = {
      ...(state.toolsStatus || {}),
      tools
    };
    renderToolingHealth();
    showToast(`Status tool ${toolName} diperbarui.`);
  } catch (error) {
    showToast(error.message);
  }
}

function jumpToModuleFromTool(moduleId) {
  const module = (state.modules || []).find((item) => item.id === moduleId);
  if (!module) return;
  state.selectedPhase = module.phase_id;
  state.highlightedModuleId = moduleId;
  renderModules();
  animatePhaseSwap();
  document.querySelector(".module-pane")?.scrollIntoView({ behavior: "smooth", block: "start" });
  window.setTimeout(() => {
    state.highlightedModuleId = "";
    renderModules();
  }, 2600);
}

async function approveDestructiveAction(actionId) {
  if (!state.activeAssessmentId) {
    showToast("Buat atau pilih assessment intrusive terlebih dahulu.");
    return;
  }
  try {
    const reason = window.prompt(`Alasan destructive approval untuk ${actionId}`, `Approved destructive action ${actionId}`) || "";
    const result = await api(`/api/assessments/${state.activeAssessmentId}/approve-destructive`, {
      method: "POST",
      body: JSON.stringify({
        action: actionId,
        approved_by: currentOperatorName(),
        ticket_ref: currentTicketRef(),
        reason
      })
    });
    state.activeApprovals = [result.approval, ...state.activeApprovals];
    renderApprovalsDashboard();
    renderAssessmentSummary();
    showToast(`Approval destructive ${actionId} tersimpan.`);
  } catch (error) {
    showToast(error.message);
  }
}

async function executeDestructiveAction(actionId) {
  if (!state.activeAssessmentId) {
    showToast("Pilih assessment aktif terlebih dahulu.");
    return;
  }
  const approval = (state.activeApprovals || []).find((item) => item.metadata?.action === actionId);
  if (!approval?.metadata?.confirmation_token) {
    showToast("Approval destructive belum ada. Simpan approval dulu.");
    return;
  }
  try {
    const result = await api("/api/destructive/execute", {
      method: "POST",
      body: JSON.stringify({
        action: actionId,
        target: currentTargetValue(),
        assessment_id: state.activeAssessmentId,
        confirmation_token: approval.metadata.confirmation_token
      })
    });
    state.destructiveResult = [
      `Action     : ${result.action}`,
      `Success    : ${result.success}`,
      `Target     : ${result.target}`,
      `Approved By: ${result.approved_by || "-"}`,
      `Ticket Ref : ${result.ticket_ref || "-"}`,
      "",
      "Command:",
      result.command || "-",
      "",
      "Output:",
      result.output || "-"
    ].join("\n");
    renderDestructiveActions();
    showToast(`Destructive action ${actionId} dieksekusi.`);
  } catch (error) {
    showToast(error.message);
  }
}

function bindEvents() {
  $("#logoutBtn")?.addEventListener("click", async () => {
    try {
      await fetch("/logout", {
        method: "POST",
        credentials: "same-origin"
      });
    } finally {
      window.location.href = "/login";
    }
  });
  $("#phaseGroups")?.addEventListener("click", (event) => {
    const selectedTool = event.target.closest?.("[data-select-tool]")?.dataset?.selectTool;
    if (selectedTool) {
      state.selectedToolLabel = selectedTool;
      const entry = activeToolEntry();
      openToolInspectModal(entry?.label || selectedTool, entry?.status || null);
      return;
    }
    const checkTool = event.target.closest?.("[data-check-tool]")?.dataset?.checkTool;
    if (checkTool) {
      checkSingleTool(checkTool);
      return;
    }
    const expandCommandsButton = event.target.closest?.("[data-expand-module-commands]")?.dataset?.expandModuleCommands;
    if (expandCommandsButton) {
      fetchModuleDryRunData(expandCommandsButton)
        .then(() => {
          setModuleCommandsExpanded(expandCommandsButton, true);
          scheduleModulesRender();
        })
        .catch((error) => showToast(error.message || "Gagal memuat command preview."));
      return;
    }
    const copyCommandButton = event.target.closest?.("[data-copy-module-command]");
    if (copyCommandButton) {
      copyModuleCommand(copyCommandButton).catch((error) => showToast(error.message || "Gagal copy command."));
      return;
    }
    const runCommandButton = event.target.closest?.("[data-run-module-command]");
    if (runCommandButton) {
      executeModuleCommandCard(runCommandButton);
      return;
    }
    const openInteractiveModuleButton = event.target.closest?.("[data-open-module-console]");
    if (openInteractiveModuleButton) {
      openModuleCommandInLiveConsole(openInteractiveModuleButton)
        .catch((error) => showToast(error.message || "Gagal membuka live console."));
      return;
    }
    const runId = event.target.closest?.("[data-run]")?.dataset?.run;
    const previewId = event.target.closest?.("[data-preview]")?.dataset?.preview;
    if (runId) runModule(runId);
    if (previewId) previewModule(previewId);
  });

  $("#jobList")?.addEventListener("click", (event) => {
    const stopButton = event.target.closest("[data-stop-job]");
    if (stopButton) {
      event.stopPropagation();
      stopJob(stopButton.dataset.stopJob);
      return;
    }
    const deleteButton = event.target.closest("[data-delete-job]");
    if (deleteButton) {
      event.stopPropagation();
      deleteJob(deleteButton.dataset.deleteJob);
      return;
    }
    const card = event.target.closest("[data-job-card]");
    if (card && !event.target.closest("button")) {
      loadJob(card.dataset.jobCard);
      return;
    }
    const button = event.target.closest("[data-job]");
    if (!button) return;
    loadJob(button.dataset.job);
  });

  $("#runChainBtn")?.addEventListener("click", runFullChain);
  $("#refreshAssessmentsBtn")?.addEventListener("click", loadAssessments);
  $("#refreshWorkspaceBtn")?.addEventListener("click", refreshWorkspace);
  $("#refreshToolsBtn")?.addEventListener("click", loadToolingHealth);
  $("#refreshAssetsBtn")?.addEventListener("click", async () => {
    await loadTargetAsset();
  });
  $("#reloadConfigBtn")?.addEventListener("click", reloadConfig);
  $("#saveRangesBtn")?.addEventListener("click", saveAllowedSubnets);
  $("#viewAssessmentEvidenceBtn")?.addEventListener("click", viewAssessmentEvidence);
  $("#exportVisibleEvidenceBtn")?.addEventListener("click", exportVisibleEvidenceJson);
  $("#viewAssessmentMarkdownBtn")?.addEventListener("click", viewAssessmentMarkdown);
  $("#viewAssessmentHtmlBtn")?.addEventListener("click", viewAssessmentHtml);
  $("#assessmentFindings")?.addEventListener("click", async (event) => {
    const action = event.target?.dataset?.findingAction;
    const findingId = event.target?.dataset?.findingId;
    if (!action || !findingId) return;
    await updateFindingStatus(findingId, action);
  });
  $("#assessmentList")?.addEventListener("click", async (event) => {
    const assessmentId = event.target?.dataset?.selectAssessment;
    if (!assessmentId) return;
    await loadAssessment(assessmentId);
  });
  $("#approvalQueueList")?.addEventListener("click", async (event) => {
    const approveAll = event.target?.dataset?.approveAllModules;
    if (approveAll !== undefined) {
      await approveAllPendingModules();
      return;
    }
    const moduleId = event.target?.dataset?.approveModule;
    if (!moduleId) return;
    await approveModuleFromQueue(moduleId);
  });
  $("#workspaceSections")?.addEventListener("click", async (event) => {
    const path = event.target?.dataset?.workspaceFile;
    if (!path) return;
    await openWorkspaceFile(path);
  });
  $("#toolHealthList")?.addEventListener("click", async (event) => {
    const selectedTool = event.target.closest?.("[data-select-tool]")?.dataset?.selectTool;
    if (selectedTool) {
      state.selectedToolLabel = selectedTool;
      renderToolingHealth();
      const entry = activeToolEntry();
      openToolInspectModal(entry?.label || selectedTool, entry?.status || null);
      return;
    }
    const toolName = event.target.closest?.("[data-check-tool]")?.dataset?.checkTool;
    if (!toolName) return;
    await checkSingleTool(toolName);
  });
  $("#toolInspectModules")?.addEventListener("click", (event) => {
    const moduleId = event.target?.dataset?.jumpModule;
    if (!moduleId) return;
    closeToolInspectModal();
    jumpToModuleFromTool(moduleId);
  });
  $("#openImportModalBtn")?.addEventListener("click", openImportParserModal);
  $("#closeImportModalBtn")?.addEventListener("click", closeImportParserModal);
  $("#clearImportModalBtn")?.addEventListener("click", clearImportParserModal);
  $("#closeToolInspectBtn")?.addEventListener("click", closeToolInspectModal);
  $("#toolInspectModal")?.addEventListener("click", (event) => {
    const copyButton = event.target.closest?.("[data-copy-tool-command]");
    if (copyButton) {
      copyToolCommand(copyButton).catch((error) => showToast(error.message || "Gagal copy command."));
      return;
    }
    const runButton = event.target.closest?.("[data-run-tool-command]");
    if (runButton) {
      executeToolCommandCard(runButton);
      return;
    }
    const openInteractiveButton = event.target.closest?.("[data-open-tool-console]");
    if (openInteractiveButton) {
      openToolCommandInLiveConsole(openInteractiveButton)
        .catch((error) => showToast(error.message || "Gagal membuka live console."));
      return;
    }
    if (event.target?.id === "toolInspectModal") {
      closeToolInspectModal();
    }
  });
  $("#sendInteractiveConsoleBtn")?.addEventListener("click", () => {
    sendInteractiveConsoleInput().catch((error) => showToast(error.message || "Gagal mengirim command."));
  });
  $("#interactiveConsoleInput")?.addEventListener("keydown", (event) => {
    if (event.key === "Tab") {
      event.preventDefault();
      applyInteractiveTabCompletion(event.currentTarget);
      return;
    }
    if (!isPlainEnterKey(event)) return;
    event.preventDefault();
    sendInteractiveConsoleInput().catch((error) => showToast(error.message || "Gagal mengirim command."));
  });
  $("#interactiveConsoleInput")?.addEventListener("keypress", (event) => {
    if (!isPlainEnterKey(event)) return;
    event.preventDefault();
    sendInteractiveConsoleInput().catch((error) => showToast(error.message || "Gagal mengirim command."));
  });
  $("#interactiveConsoleInput")?.addEventListener("input", () => {
    resetInteractiveTabState();
    updateInteractiveHintLabel();
  });
  $("#closeInteractiveConsoleBtn")?.addEventListener("click", () => {
    closeInteractiveConsoleSession().catch((error) => showToast(error.message || "Gagal menutup live console."));
  });
  $("#toggleTerminalFullscreenBtn")?.addEventListener("click", () => {
    setTerminalFullscreen().catch((error) => showToast(error.message || "Gagal membuka full screen."));
  });
  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") return;
    const panel = document.querySelector('.insight-panel[data-insight-panel="console"]');
    if (!panel?.classList.contains("console-fullscreen")) return;
    setTerminalFullscreen(false).catch(() => {});
  });
  document.addEventListener("fullscreenchange", () => {
    const panel = document.querySelector('.insight-panel[data-insight-panel="console"]');
    const button = $("#toggleTerminalFullscreenBtn");
    const active = document.fullscreenElement === panel || panel?.classList.contains("console-fullscreen");
    if (button) {
      button.textContent = active ? "Exit Full Screen" : "Full Screen";
      button.setAttribute("aria-pressed", active ? "true" : "false");
    }
    document.body.classList.toggle("terminal-fullscreen-open", Boolean(active));
  });
  $("#importParserModal")?.addEventListener("click", (event) => {
    if (event.target?.id === "importParserModal") {
      closeImportParserModal();
    }
  });
  $("#toolSearchInput")?.addEventListener("input", (event) => {
    state.toolSearchQuery = event.target.value || "";
    debouncedToolingHealthRender();
  });
  $("#toolFilterRow")?.addEventListener("click", (event) => {
    const button = event.target.closest("[data-tool-filter]");
    if (!button) return;
    state.toolStatusFilter = button.dataset.toolFilter || "all";
    renderToolingHealth();
  });
  $("#toolSortSelect")?.addEventListener("change", (event) => {
    state.toolSortMode = event.target.value || "usage";
    renderToolingHealth();
  });
  $("#parseImportBtn")?.addEventListener("click", parseImportedOutput);
  $("#destructiveActionsList")?.addEventListener("click", async (event) => {
    const approveId = event.target?.dataset?.approveDestructive;
    const executeId = event.target?.dataset?.executeDestructive;
    if (approveId) {
      await approveDestructiveAction(approveId);
      return;
    }
    if (executeId) {
      await executeDestructiveAction(executeId);
    }
  });
  $("#phaseTabs")?.addEventListener("click", (event) => {
    const toolFilter = event.target.closest("[data-tool-catalog-filter]")?.dataset?.toolCatalogFilter;
    if (toolFilter) {
      state.toolStatusFilter = toolFilter;
      renderModules();
      return;
    }
    const button = event.target.closest("[data-phase-tab]");
    if (!button) return;
    if (state.selectedPhase === button.dataset.phaseTab) return;
    state.selectedPhase = button.dataset.phaseTab;
    renderModules();
    animatePhaseSwap();
  });
  $("#operationsTabRow")?.addEventListener("click", (event) => {
    const button = event.target.closest("[data-operations-tab]");
    if (!button) return;
    setOperationsTab(button.dataset.operationsTab || "workspace");
  });
  $("#toggleOperationsBtn")?.addEventListener("click", () => {
    setOperationsVisibility(!state.operationsVisible);
  });
  $("#healthTabRow")?.addEventListener("click", (event) => {
    const button = event.target.closest("[data-health-tab]");
    if (!button) return;
    setHealthTab(button.dataset.healthTab || "strategy");
  });
  $("#advancedTabRow")?.addEventListener("click", (event) => {
    const button = event.target.closest("[data-advanced-tab]");
    if (!button) return;
    setAdvancedTab(button.dataset.advancedTab || "findings");
  });
  $("#openToolCatalogBtn")?.addEventListener("click", openToolCatalogWorkspace);
  $("#activePhaseBar")?.addEventListener("change", (event) => {
    const sortSelect = event.target.closest?.("#mainToolSortSelect");
    if (!sortSelect) return;
    state.toolSortMode = sortSelect.value || "usage";
    renderModules();
  });
  $("#insightTabs")?.addEventListener("click", (event) => {
    const button = event.target.closest("[data-insight-tab]");
    if (!button) return;
    state.insightTab = button.dataset.insightTab || "console";
    renderInsightTabs();
  });
  $("#stopAllJobsBtn")?.addEventListener("click", stopAllJobs);
  $("#clearJobsBtn")?.addEventListener("click", clearJobs);
  $("#viewHtmlBtn")?.addEventListener("click", viewHtmlReport);
  $("#viewJobEvidenceBtn")?.addEventListener("click", viewJobEvidence);
  $("#viewJobMarkdownBtn")?.addEventListener("click", viewJobMarkdown);
  $("#targetInput")?.addEventListener("input", () => {
    persistLastTarget($("#targetInput").value);
    state.moduleDryRunCache = {};
    state.expandedModuleCommandIds = [];
    scheduleModulesRender();
    const modal = $("#toolInspectModal");
    if (modal && !modal.classList.contains("hidden") && state.selectedToolLabel) {
      const entry = activeToolEntry();
      openToolInspectModal(entry?.label || state.selectedToolLabel, entry?.status || null);
    }
    if (state.referencePanelLoaded) {
      debouncedLoadTargetAsset();
    }
  });
  $("#targetKindSelect")?.addEventListener("change", () => {
    state.moduleDryRunCache = {};
    state.expandedModuleCommandIds = [];
    scheduleModulesRender();
    const modal = $("#toolInspectModal");
    if (modal && !modal.classList.contains("hidden") && state.selectedToolLabel) {
      const entry = activeToolEntry();
      openToolInspectModal(entry?.label || state.selectedToolLabel, entry?.status || null);
    }
    if (state.referencePanelLoaded) {
      loadTargetAsset();
    }
  });
  $("#moduleSearchInput")?.addEventListener("input", (event) => {
    if (state.catalogSurface === "tools") {
      state.toolSearchQuery = event.target.value || "";
    } else {
      state.moduleSearchQuery = event.target.value || "";
    }
    debouncedModuleSearchRender();
  });
  $("#moduleProfileSelect")?.addEventListener("change", (event) => {
    setModuleExecutionProfile(event.target.value || "fast");
    state.moduleDryRunCache = {};
    state.expandedModuleCommandIds = [];
    renderChainPresetList();
    scheduleModulesRender();
  });

  $("#themeToggle")?.addEventListener("click", () => {
    const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    localStorage.setItem("lab-console-theme", next);
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      closeToolInspectModal();
    }
  });
}

function initTheme() {
  document.documentElement.dataset.theme = localStorage.getItem("lab-console-theme") || "light";
}

function initViewMode() {
  setViewMode("detail");
}

function initOperationsTab() {
  setOperationsTab(localStorage.getItem("lab-console-operations-tab") || "workspace");
  setOperationsVisibility(false);
}

function initHealthTab() {
  setHealthTab(localStorage.getItem("lab-console-health-tab") || "strategy");
}

function initAdvancedTab() {
  setAdvancedTab("findings");
}

const debouncedLoadTargetAsset = debounce(() => {
  loadTargetAsset();
}, 220);

const debouncedModuleSearchRender = debounce(() => {
  scheduleModulesRender();
}, 120);

const debouncedToolingHealthRender = debounce(() => {
  renderToolingHealth();
}, 120);

async function ensureOperatorWorkspaceDataLoaded() {
  if (state.operatorWorkspaceLoaded) return;
  state.operatorWorkspaceLoaded = true;
  const results = await Promise.allSettled([
    loadAssessments(),
    apiOptional("/api/approvals/dashboard", { counts: {}, approvals: [], pending: [] })
  ]);
  const approvalsResult = results[1];
  if (approvalsResult?.status === "fulfilled") {
    state.approvalsDashboard = approvalsResult.value || { counts: {}, approvals: [], pending: [] };
  }
  renderAssessmentSummary();
  renderApprovalQueue();
  renderAssessmentExportButtons();
  renderImportResult();
}

async function ensureToolCatalogDataLoaded() {
  if (state.toolCatalogLoaded) return;
  if (state.toolCatalogLoadPromise) return state.toolCatalogLoadPromise;
  state.toolCatalogLoading = true;
  scheduleModulesRender();
  state.toolCatalogLoadPromise = Promise.allSettled([
    loadChainPresets(),
    loadToolingHealth()
  ]).finally(() => {
    state.toolCatalogLoaded = true;
    state.toolCatalogLoading = false;
    state.toolCatalogLoadPromise = null;
    scheduleModulesRender();
  });
  return state.toolCatalogLoadPromise;
}

async function ensureReferencePanelDataLoaded() {
  if (state.referencePanelLoaded) return;
  state.referencePanelLoaded = true;
  await Promise.allSettled([
    loadReferenceData(),
    loadTargetAsset()
  ]);
}

async function init() {
  initTheme();
  initViewMode();
  initOperationsTab();
  initHealthTab();
  initAdvancedTab();
  restoreLastTarget();
  state.toolSortMode = selectedToolSortMode();
  setModuleExecutionProfile("fast");
  syncModuleProfileSelect();
  bindEvents();
  bindConsoleResizeHandle();
  setRunChainUiState("idle");
  if ($("#activePhaseBar")) {
    $("#activePhaseBar").innerHTML = '<div class="empty-jobs">Memuat katalog modul...</div>';
  }
  if ($("#phaseGroups")) {
    $("#phaseGroups").innerHTML = '<div class="empty-jobs">Memuat modul dan command preview...</div>';
  }
  try {
    await Promise.all([
      loadConfig(),
      loadModules(),
      loadJobs()
    ]);
    renderInsightTabs();
    queueConsoleHeightSync();
    if (state.activeJobId) {
      void loadJob(state.activeJobId);
    } else {
      renderConsole(null);
    }
  } catch (error) {
    $("#consoleOutput").textContent = `Gagal memuat backend.\n\n${error.message}\n\nPastikan FastAPI sudah berjalan dari WSL.`;
    setConsoleStatus("error", "backend unavailable");
  }
}

document.addEventListener("DOMContentLoaded", init);
