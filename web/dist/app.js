// State variables
let currentDevices = [];
let currentProxies = [];
let activeTab = "tab-devices";
let autoRefreshTimer = null;

// Initialize app
document.addEventListener("DOMContentLoaded", () => {
  setupEventListeners();
  checkAuth();
});

// Toast Helper
function showToast(msg, duration = 3000) {
  const toast = document.getElementById("toast");
  toast.innerText = msg;
  toast.style.display = "block";
  setTimeout(() => {
    toast.style.display = "none";
  }, duration);
}

// Authentication Flow
async function checkAuth() {
  try {
    const res = await fetch("/api/auth/me");
    const data = await res.json();
    if (data.authenticated) {
      showDashboard();
    } else {
      showLogin();
    }
  } catch (err) {
    showLogin();
  }
}

function showLogin() {
  if (autoRefreshTimer) clearInterval(autoRefreshTimer);
  document.getElementById("login-container").style.display = "flex";
  document.getElementById("app-container").style.display = "none";
}

function showDashboard() {
  document.getElementById("login-container").style.display = "none";
  document.getElementById("app-container").style.display = "block";
  loadAllData();

  if (autoRefreshTimer) clearInterval(autoRefreshTimer);
  autoRefreshTimer = setInterval(() => {
    loadStatus();
    if (activeTab === "tab-devices") loadDevices();
  }, 10000);
}

// Event Listeners
function setupEventListeners() {
  // Login Form
  document.getElementById("login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const pass = document.getElementById("password").value;
    const errBox = document.getElementById("login-error");
    errBox.style.display = "none";

    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: pass }),
      });
      const data = await res.json();
      if (res.ok && data.success) {
        document.getElementById("password").value = "";
        showDashboard();
      } else {
        errBox.innerText = data.error || "Mật khẩu không chính xác";
        errBox.style.display = "block";
      }
    } catch (err) {
      errBox.innerText = "Lỗi kết nối máy chủ";
      errBox.style.display = "block";
    }
  });

  // Logout
  document.getElementById("btn-logout").addEventListener("click", async () => {
    await fetch("/api/auth/logout", { method: "POST" });
    showLogin();
  });

  // Tab switching
  document.querySelectorAll(".tab-btn[data-tab]").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab-btn[data-tab]").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach((c) => (c.style.display = "none"));

      btn.classList.add("active");
      activeTab = btn.getAttribute("data-tab");
      document.getElementById(activeTab).style.display = "block";

      if (activeTab === "tab-devices") loadDevices();
      if (activeTab === "tab-proxies") loadProxies();
      if (activeTab === "tab-leakguard") {
        loadStatus();
        loadLogs();
      }
    });
  });

  // Device Filter and Search
  document.getElementById("device-search").addEventListener("input", renderDevicesTable);
  document.getElementById("device-filter").addEventListener("change", renderDevicesTable);
  document.getElementById("btn-refresh-devices").addEventListener("click", () => {
    loadDevices();
    showToast("Đã làm mới danh sách thiết bị");
  });

  // System actions
  document.getElementById("btn-reconcile").addEventListener("click", async () => {
    const btn = document.getElementById("btn-reconcile");
    btn.disabled = true;
    btn.innerText = "Đang đồng bộ...";
    try {
      const res = await fetch("/api/system/reconcile", { method: "POST" });
      if (res.ok) {
        showToast("Đồng bộ RouterOS thành công!");
        loadStatus();
      } else {
        showToast("Đồng bộ thất bại");
      }
    } finally {
      btn.disabled = false;
      btn.innerText = "⚡ Đồng bộ lại Router";
    }
  });

  document.getElementById("btn-flush-all").addEventListener("click", async () => {
    if (!confirm("Bạn có chắc chắn muốn cắt toàn bộ kết nối hiện tại của các thiết bị đang qua Proxy?")) return;
    await fetch("/api/system/flush-all", { method: "POST" });
    showToast("Đã cắt toàn bộ kết nối!");
  });

  document.getElementById("btn-refresh-logs").addEventListener("click", loadLogs);

  // Modals
  document.getElementById("btn-open-add-proxy").addEventListener("click", () => {
    document.getElementById("p-id").value = "";
    document.getElementById("modal-proxy-title").innerText = "Thêm Proxy Mới";
    document.getElementById("proxy-manual-form").reset();
    document.getElementById("import-text").value = "";
    switchProxyModalTab("quick");
    document.getElementById("modal-proxy").style.display = "flex";
  });

  document.getElementById("btn-close-proxy-modal").addEventListener("click", () => {
    document.getElementById("modal-proxy").style.display = "none";
  });

  document.getElementById("tab-btn-quick-import").addEventListener("click", () => switchProxyModalTab("quick"));
  document.getElementById("tab-btn-manual-form").addEventListener("click", () => switchProxyModalTab("manual"));

  document.getElementById("p-protocol").addEventListener("change", updateManualFormFields);
  document.getElementById("p-security").addEventListener("change", () => {
    const sec = document.getElementById("p-security").value;
    document.getElementById("p-reality-fields").style.display = sec === "reality" ? "grid" : "none";
  });

  // Proxy Import Submit
  document.getElementById("btn-submit-import").addEventListener("click", async () => {
    const text = document.getElementById("import-text").value.trim();
    const defaultProto = document.getElementById("import-default-proto").value;
    if (!text) {
      alert("Vui lòng dán ít nhất 1 link URI");
      return;
    }

    const res = await fetch("/api/proxies/import", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text, defaultProto }),
    });
    const data = await res.json();
    if (res.ok) {
      showToast(`Đã nhập thành công ${data.imported} proxy!`);
      document.getElementById("modal-proxy").style.display = "none";
      loadProxies();
      loadDevices();
    } else {
      alert(data.error || "Nhập proxy thất bại");
    }
  });

  // Manual Form Submit
  document.getElementById("proxy-manual-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const id = document.getElementById("p-id").value;
    const proto = document.getElementById("p-protocol").value;

    const payload = {
      name: document.getElementById("p-name").value.trim(),
      protocol: proto,
      host: document.getElementById("p-host").value.trim(),
      port: parseInt(document.getElementById("p-port").value, 10),
      username: document.getElementById("p-username").value.trim(),
      password: document.getElementById("p-password").value.trim(),
      udp: document.getElementById("p-udp").checked,
    };

    if (proto === "shadowsocks") {
      payload.method = document.getElementById("p-ss-method").value;
      payload.password = document.getElementById("p-ss-pass").value.trim();
    } else if (proto === "vless" || proto === "vmess") {
      payload.uuid = document.getElementById("p-uuid").value.trim();
      payload.security = document.getElementById("p-security").value;
      payload.sni = document.getElementById("p-sni").value.trim();
      if (payload.security === "reality") {
        payload.publicKey = document.getElementById("p-pbk").value.trim();
        payload.shortId = document.getElementById("p-sid").value.trim();
      }
    }

    const url = id ? `/api/proxies/${id}` : "/api/proxies";
    const method = id ? "PUT" : "POST";

    const res = await fetch(url, {
      method,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (res.ok) {
      showToast("Lưu cấu hình proxy thành công!");
      document.getElementById("modal-proxy").style.display = "none";
      loadProxies();
      loadDevices();
    } else {
      alert(data.error || "Lưu proxy thất bại");
    }
  });

  // Nickname Modal
  document.getElementById("btn-close-nickname-modal").addEventListener("click", () => {
    document.getElementById("modal-nickname").style.display = "none";
  });

  document.getElementById("nickname-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const ip = document.getElementById("nick-ip").value;
    const nick = document.getElementById("nick-input").value.trim();

    const res = await fetch(`/api/devices/${ip}/nickname`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ nickname: nick }),
    });
    if (res.ok) {
      showToast("Đã cập nhật tên gợi nhớ");
      document.getElementById("modal-nickname").style.display = "none";
      loadDevices();
    }
  });
}

function switchProxyModalTab(mode) {
  const quickBtn = document.getElementById("tab-btn-quick-import");
  const manualBtn = document.getElementById("tab-btn-manual-form");
  const quickWrap = document.getElementById("proxy-quick-import-wrap");
  const manualForm = document.getElementById("proxy-manual-form");

  if (mode === "quick") {
    quickBtn.classList.add("active");
    manualBtn.classList.remove("active");
    quickWrap.style.display = "block";
    manualForm.style.display = "none";
  } else {
    manualBtn.classList.add("active");
    quickBtn.classList.remove("active");
    quickWrap.style.display = "none";
    manualForm.style.display = "block";
    updateManualFormFields();
  }
}

function updateManualFormFields() {
  const proto = document.getElementById("p-protocol").value;
  document.getElementById("p-group-auth").style.display = (proto === "http" || proto === "https" || proto === "socks5") ? "grid" : "none";
  document.getElementById("p-group-ss").style.display = proto === "shadowsocks" ? "grid" : "none";
  document.getElementById("p-group-uuid").style.display = (proto === "vless" || proto === "vmess") ? "block" : "none";
  document.getElementById("p-group-reality").style.display = (proto === "vless" || proto === "vmess" || proto === "trojan") ? "block" : "none";
}

// Data Loaders
async function loadAllData() {
  await Promise.all([loadStatus(), loadProxies(), loadDevices()]);
}

async function loadStatus() {
  try {
    const res = await fetch("/api/system/status");
    if (!res.ok) return;
    const data = await res.json();

    // MikroTik Badge
    const mkBadge = document.getElementById("badge-mikrotik");
    mkBadge.className = "badge badge-green";
    mkBadge.innerHTML = '<span class="badge-dot"></span> RouterOS 7.25 Kết Nối';

    // sing-box Badge
    const sbBadge = document.getElementById("badge-singbox");
    if (data.singbox && data.singbox.running) {
      sbBadge.className = "badge badge-green";
      sbBadge.innerHTML = `<span class="badge-dot"></span> sing-box Online (PID ${data.singbox.pid})`;
    } else {
      sbBadge.className = "badge badge-red";
      sbBadge.innerHTML = '<span class="badge-dot"></span> sing-box Dừng';
    }

    // Leak Guard
    const lg = data.leakGuard;
    if (lg) {
      document.getElementById("metric-proxied-count").innerText = lg.assignedDeviceCount || 0;
      document.getElementById("metric-ks-packets").innerText = (lg.killSwitchPackets || 0).toLocaleString();
      document.getElementById("metric-v6-packets").innerText = (lg.ipv6BlockedPackets || 0).toLocaleString();
      
      const overallElem = document.getElementById("metric-overall-status");
      overallElem.innerText = lg.overallStatus;
      if (lg.overallStatus === "protected") {
        overallElem.style.color = "var(--accent-green)";
      } else if (lg.overallStatus === "degraded") {
        overallElem.style.color = "var(--accent-yellow)";
      } else {
        overallElem.style.color = "var(--accent-red)";
      }

      renderLeakGuardLayers(lg.layers || []);
    }
  } catch (err) {
    const mkBadge = document.getElementById("badge-mikrotik");
    mkBadge.className = "badge badge-red";
    mkBadge.innerHTML = '<span class="badge-dot"></span> Mất kết nối RouterOS';
  }
}

function renderLeakGuardLayers(layers) {
  const container = document.getElementById("leakguard-layers");
  container.innerHTML = "";

  layers.forEach((l) => {
    let badgeClass = "badge-green";
    let icon = "✓";
    if (l.status === "warning") {
      badgeClass = "badge-yellow";
      icon = "!";
    } else if (l.status === "error") {
      badgeClass = "badge-red";
      icon = "✕";
    }

    const div = document.createElement("div");
    div.className = "checklist-item";
    div.innerHTML = `
      <div class="checklist-left">
        <span class="badge ${badgeClass}" style="width:24px; height:24px; border-radius:50%; justify-content:center; font-size:0.9rem;">${icon}</span>
        <div class="checklist-info">
          <h4>${escapeHTML(l.name)}</h4>
          <p>${escapeHTML(l.description)}</p>
        </div>
      </div>
      <div>
        <span class="badge ${badgeClass}">${l.status.toUpperCase()}</span>
      </div>
    `;
    container.appendChild(div);
  });
}

async function loadProxies() {
  try {
    const res = await fetch("/api/proxies");
    if (!res.ok) return;
    currentProxies = await res.json();
    document.getElementById("count-tab-proxies").innerText = currentProxies.length;
    renderProxiesList();
  } catch (err) {
    console.error("Failed to load proxies:", err);
  }
}

function renderProxiesList() {
  const container = document.getElementById("proxies-list");
  container.innerHTML = "";

  if (currentProxies.length === 0) {
    container.innerHTML = `
      <div style="grid-column: 1 / -1; text-align: center; padding: 40px; color: var(--text-secondary);">
        Chưa có proxy nào. Hãy bấm <strong>"+ Thêm Proxy Mới"</strong> hoặc Dán nhanh link để bắt đầu!
      </div>
    `;
    return;
  }

  currentProxies.forEach((p) => {
    const card = document.createElement("div");
    card.className = "metric-card";
    card.style.flexDirection = "column";
    card.style.alignItems = "stretch";
    card.style.gap = "12px";

    // Protocol badge color
    let protoBadge = "badge-blue";
    if (p.protocol === "socks5") protoBadge = "badge-green";
    if (p.protocol === "vless" || p.protocol === "vmess") protoBadge = "badge-purple";
    if (p.protocol === "shadowsocks") protoBadge = "badge-yellow";

    // Test result info
    let testInfo = '<span style="color:var(--text-muted); font-size:0.75rem;">Chưa kiểm tra</span>';
    if (p.lastTest) {
      if (p.lastTest.status === "ok") {
        testInfo = `
          <div style="font-size:0.75rem; color:#34d399; margin-top:4px;">
            ● Live: <strong>${p.lastTest.exitIp}</strong> (${p.lastTest.countryCode || ""}) - ${p.lastTest.latencyMs}ms
          </div>
        `;
      } else {
        testInfo = `<div style="font-size:0.75rem; color:#f87171; margin-top:4px;">✕ Không kết nối được</div>`;
      }
    }

    card.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: flex-start;">
        <div>
          <span class="badge ${protoBadge}" style="text-transform:uppercase;">${p.protocol}</span>
          ${p.udp ? '<span class="badge badge-gray" style="margin-left:4px;">UDP ON</span>' : '<span class="badge badge-gray" style="margin-left:4px;">TCP ONLY</span>'}
          <h3 style="font-size: 1rem; font-weight: 600; margin-top: 6px;">${escapeHTML(p.name)}</h3>
        </div>
        <div style="text-align: right;">
          <button class="btn btn-sm btn-test-proxy" data-id="${p.id}">⚡ Test</button>
        </div>
      </div>

      <div style="font-size: 0.82rem; color: var(--text-secondary); background: rgba(0,0,0,0.2); padding: 8px; border-radius: 6px;">
        <div><strong>Server:</strong> ${escapeHTML(p.host)}:${p.port}</div>
        ${p.username ? `<div><strong>User:</strong> ${escapeHTML(p.username)}</div>` : ""}
        ${testInfo}
      </div>

      <div style="display: flex; justify-content: flex-end; gap: 8px;">
        <button class="btn btn-sm btn-delete-proxy" data-id="${p.id}" style="color:#f87171;">Xóa</button>
      </div>
    `;

    // Event listeners for card buttons
    card.querySelector(".btn-test-proxy").addEventListener("click", () => testProxy(p.id));
    card.querySelector(".btn-delete-proxy").addEventListener("click", () => deleteProxy(p.id));

    container.appendChild(card);
  });
}

async function testProxy(id) {
  const btn = document.querySelector(`.btn-test-proxy[data-id="${id}"]`);
  if (btn) {
    btn.disabled = true;
    btn.innerText = "⏳...";
  }

  try {
    const res = await fetch(`/api/proxies/${id}/test`, { method: "POST" });
    const data = await res.json();
    if (res.ok) {
      if (data.status === "ok") {
        showToast(`Proxy sống! IP: ${data.exitIp} (${data.country || ""}) - ${data.latencyMs}ms`);
      } else {
        showToast(`Proxy lỗi: ${data.error || "Không kết nối được"}`);
      }
      loadProxies();
    } else {
      showToast(data.error || "Kiểm tra thất bại");
    }
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerText = "⚡ Test";
    }
  }
}

async function deleteProxy(id) {
  if (!confirm("Bạn có chắc chắn muốn xóa proxy này? Mọi thiết bị đang gán proxy này sẽ tự động chuyển về mạng trực tiếp.")) return;
  const res = await fetch(`/api/proxies/${id}`, { method: "DELETE" });
  if (res.ok) {
    showToast("Đã xóa proxy");
    loadProxies();
    loadDevices();
  }
}

async function loadDevices() {
  try {
    const res = await fetch("/api/devices");
    if (!res.ok) return;
    currentDevices = await res.json();
    document.getElementById("count-tab-devices").innerText = currentDevices.length;
    renderDevicesTable();
  } catch (err) {
    console.error("Failed to load devices:", err);
  }
}

function renderDevicesTable() {
  const tbody = document.getElementById("devices-tbody");
  const searchQuery = document.getElementById("device-search").value.toLowerCase().trim();
  const filter = document.getElementById("device-filter").value;

  tbody.innerHTML = "";

  const filtered = currentDevices.filter((d) => {
    // Search filter
    const matchesSearch =
      (d.ip && d.ip.toLowerCase().includes(searchQuery)) ||
      (d.mac && d.mac.toLowerCase().includes(searchQuery)) ||
      (d.hostname && d.hostname.toLowerCase().includes(searchQuery)) ||
      (d.nickname && d.nickname.toLowerCase().includes(searchQuery));

    if (!matchesSearch) return false;

    // Category filter
    if (filter === "proxied") return d.assigned;
    if (filter === "direct") return !d.assigned;
    if (filter === "online") return d.online;
    return true;
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:30px; color:var(--text-secondary);">Không tìm thấy thiết bị nào phù hợp</td></tr>`;
    return;
  }

  filtered.forEach((d) => {
    const tr = document.createElement("tr");

    // Online status dot
    const statusDot = d.online
      ? '<span class="badge badge-green" title="Đang online"><span class="badge-dot"></span></span>'
      : '<span class="badge badge-gray" title="Offline"><span class="badge-dot"></span></span>';

    // Device Display Name
    const displayName = d.nickname || d.hostname || "Thiết bị không tên";
    const editNickBtn = `<button class="btn btn-sm btn-edit-nick" data-ip="${d.ip}" data-nick="${escapeHTML(d.nickname || "")}" data-host="${escapeHTML(d.hostname || "")}" style="background:none; border:none; color:var(--text-secondary); cursor:pointer;">✏️</button>`;

    // Proxy Dropdown
    let proxyOptions = '<option value="">(Mạng trực tiếp - Direct)</option>';
    currentProxies.forEach((p) => {
      const selected = d.proxyId === p.id ? "selected" : "";
      proxyOptions += `<option value="${p.id}" ${selected}>${escapeHTML(p.name)} (${p.protocol.toUpperCase()})</option>`;
    });

    // Zero-Leak Shields
    let shields = "";
    if (d.assigned) {
      shields = `
        <span class="badge badge-green" title="RouterOS Firewall Kill-Switch">IPv4 KS</span>
        <span class="badge badge-purple" title="Khóa cứng IPv6 theo MAC">IPv6 Block</span>
        <span class="badge badge-blue" title="DNS Hijack về sing-box FakeIP">DNS Hijack</span>
      `;
    } else {
      shields = `<span class="badge badge-gray">Direct</span>`;
    }

    tr.innerHTML = `
      <td style="text-align:center;">${statusDot}</td>
      <td>
        <div style="font-weight:600; display:flex; align-items:center; gap:6px;">
          ${escapeHTML(displayName)} ${editNickBtn}
        </div>
        ${d.hostname && d.nickname ? `<div style="font-size:0.75rem; color:var(--text-muted);">${escapeHTML(d.hostname)}</div>` : ""}
      </td>
      <td>
        <div style="font-family:monospace; font-weight:600;">${d.ip}</div>
        <div style="font-family:monospace; font-size:0.75rem; color:var(--text-secondary);">${d.mac || "N/A"}</div>
      </td>
      <td>
        <div style="display:flex; gap:6px; align-items:center;">
          <select class="device-proxy-select" data-ip="${d.ip}" style="max-width:210px;">
            ${proxyOptions}
          </select>
          <button class="btn btn-sm btn-primary btn-apply-proxy" data-ip="${d.ip}" data-mac="${d.mac}">Lưu</button>
        </div>
      </td>
      <td>${shields}</td>
      <td style="text-align:right;">
        <button class="btn btn-sm btn-flush-device" data-ip="${d.ip}" title="Cắt kết nối TCP/UDP đang mở để ép qua tuyến mới">✂️ Cắt</button>
      </td>
    `;

    // Event listeners
    tr.querySelector(".btn-edit-nick").addEventListener("click", (e) => {
      const ip = e.currentTarget.getAttribute("data-ip");
      const nick = e.currentTarget.getAttribute("data-nick");
      const host = e.currentTarget.getAttribute("data-host");
      document.getElementById("nick-ip").value = ip;
      document.getElementById("nick-input").value = nick;
      document.getElementById("nick-device-label").innerText = `Thiết bị: ${ip} (${host || "No hostname"})`;
      document.getElementById("modal-nickname").style.display = "flex";
    });

    tr.querySelector(".btn-apply-proxy").addEventListener("click", async (e) => {
      const ip = e.currentTarget.getAttribute("data-ip");
      const mac = e.currentTarget.getAttribute("data-mac");
      const sel = tr.querySelector(`.device-proxy-select[data-ip="${ip}"]`);
      const proxyId = sel.value;

      e.currentTarget.disabled = true;
      e.currentTarget.innerText = "⏳...";

      try {
        const res = await fetch(`/api/devices/${ip}/assignment`, {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ mac, proxyId }),
        });
        if (res.ok) {
          showToast(`Đã cập nhật tuyến Proxy cho ${ip}`);
          loadDevices();
          loadStatus();
        } else {
          const err = await res.json();
          alert(err.error || "Gán proxy thất bại");
        }
      } finally {
        e.currentTarget.disabled = false;
        e.currentTarget.innerText = "Lưu";
      }
    });

    tr.querySelector(".btn-flush-device").addEventListener("click", async (e) => {
      const ip = e.currentTarget.getAttribute("data-ip");
      await fetch(`/api/devices/${ip}/flush`, { method: "POST" });
      showToast(`Đã cắt kết nối của ${ip}`);
    });

    tbody.appendChild(tr);
  });
}

async function loadLogs() {
  try {
    const res = await fetch("/api/system/logs");
    if (!res.ok) return;
    const logs = await res.json();
    const box = document.getElementById("singbox-logs");
    if (logs && logs.length > 0) {
      box.innerText = logs.join("\n");
      box.scrollTop = box.scrollHeight;
    } else {
      box.innerText = "Chưa có nhật ký nào.";
    }
  } catch (err) {
    console.error("Failed to load logs:", err);
  }
}

function escapeHTML(str) {
  if (!str) return "";
  return str.replace(/[&<>'"]/g, 
    tag => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[tag] || tag)
  );
}
