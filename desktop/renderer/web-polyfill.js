(function () {
  installStylesheets();
  if (!window.ctfCompass) installBrowserPreviewApi();

  window.setTimeout(() => {
    installCtf2ConnectorUi();
    installUpdateCard();
    installSelectSkins();
  }, 0);

  function installStylesheets() {
    ["./compact-ui.css", "./sidebar-stable.css"].forEach((href) => {
      if (document.querySelector(`link[href="${href}"]`)) return;
      const link = document.createElement("link");
      link.rel = "stylesheet";
      link.href = href;
      document.head.append(link);
    });
  }

  function installBrowserPreviewApi() {
    const delay = (value, ms = 120) => new Promise((resolve) => window.setTimeout(() => resolve(value), ms));
    const sandboxRoot = "Browser preview sandbox";
    const mockChallenges = [
      { id: "preview-signin", friendlyId: "signin", groundId: "BUUCTF", groundName: "BUUCTF", name: "签到", category: "MISC", difficulty: "Easy", description: "签到题 flag{buu_ctf}", points: 1, solveCount: 900, files: [] },
      { id: "preview-warmup", friendlyId: "warmup", groundId: "BUUCTF", groundName: "BUUCTF", name: "[HCTF 2018]WarmUp", category: "WEB", difficulty: "Easy", description: "Web 入门题。", points: 1, solveCount: 511, files: [] },
      { id: "preview-crypto", friendlyId: "crypto", groundId: "BUUCTF", groundName: "BUUCTF", name: "看我回旋踢", category: "CRYPTO", difficulty: "Easy", description: "示例附件题。", points: 1, solveCount: 451, files: [{ id: "zip", name: "challenge.zip", size: 470 }] },
    ];
    const makeArtifact = (name = "readme.txt") => ({ id: `preview-${Date.now()}`, path: `preview://ctf2/${name}`, name, family: "text", familyLabel: "文本", badge: "TXT", sizeLabel: "1.0 KB", sourceKind: "input" });

    window.ctfCompass = {
      pickFiles: () => delay([makeArtifact()]),
      pickFolder: () => delay([makeArtifact()]),
      prepareArtifacts: (paths) => delay((paths || []).map((path, index) => makeArtifact(String(path || `artifact-${index}.txt`).split(/[\\/]/).pop()))),
      analyzeChallenge: (payload = {}) => delay({ challenge: { title: payload.title || "Browser Preview", description: payload.description || "", notes: payload.notes || "", tags: payload.tags || [] }, classification: { primary: "misc", label: "杂项", confidence: 0.5, reason: "浏览器预览。", evidence: [], nextMoves: ["使用桌面版运行真实分析。"], tools: [] }, artifacts: payload.artifacts || [], pipelineLog: [], pipelineErrors: [], solver: { status: "partial", title: "预览模式", summary: "浏览器预览不会运行本地工具。", candidates: [], confidence: 0.5, nextActions: [] }, quickFindings: [], flagCandidates: [], warnings: ["当前为浏览器预览 mock。"], toolStatus: { installed: [], missing: [] }, bundledTools: [] }),
      analyzeWebTarget: () => delay({ pages: [], findings: ["浏览器预览不会扫描真实靶机。"], flagCandidates: [], nextSteps: [] }),
      runArtifactAction: () => delay({ message: "浏览器预览不会运行本地工具。", generatedArtifacts: [] }),
      revealArtifact: () => delay(null),
      loadWorkspace: () => delay(null),
      loadPreviousWorkspace: () => delay(null),
      saveWorkspace: () => delay({ path: "preview://workspace/session.json" }),
      clearWorkspace: () => delay({ cleared: true }),
      getSandboxInfo: () => delay({ root: sandboxRoot, generated: sandboxRoot, downloads: sandboxRoot, ctf2Downloads: sandboxRoot, tools: sandboxRoot, session: sandboxRoot, bytes: 0, sizeLabel: "0 B", fileCount: 0 }),
      revealSandbox: () => delay({ root: sandboxRoot, sizeLabel: "0 B", fileCount: 0 }),
      clearSandbox: () => delay({ root: sandboxRoot, sizeLabel: "0 B", fileCount: 0 }),
      exportReport: (payload) => delay({ filePath: `preview://${payload?.suggestedName || "ctf-compass-report.md"}` }),
      getMeta: () => delay({ version: "0.9.2", packaged: false, mode: "browser-preview", sandboxRoot }),
      checkForUpdates: () => delay({ currentVersion: "0.9.2", latestVersion: "0.9.2", hasUpdate: false, name: "CTF Compass v0.9.2", url: "https://github.com/Becauseiloveyo/ctf-compass/releases/latest", assetCount: 1 }),
      openExternal: () => delay({ opened: true }),
      getCtf2Status: () => delay({ connected: false, cookieCount: 0, profile: null }),
      openCtf2Login: () => delay({ opened: true }),
      openCtf2SystemLogin: () => delay({ opened: true }),
      importCtf2Token: () => delay({ connected: true, cookieCount: 0, profile: { username: "preview" } }),
      logoutCtf2: () => delay({ connected: false, cookieCount: 0, profile: null }),
      listCtf2Challenges: (filters = {}) => delay(filterPreviewChallenges(filters)),
      importCtf2Challenge: (payload = {}) => delay(importPreviewChallenge(payload)),
      getCtf2History: () => delay([]),
      clearCtf2Data: () => delay({ cleared: true }),
      revealCtf2Downloads: () => delay({ root: sandboxRoot }),
    };

    function filterPreviewChallenges(filters) {
      const query = String(filters.query || "").toLowerCase();
      const category = String(filters.category || "all").toLowerCase();
      const challenges = mockChallenges.filter((item) => {
        if (category && category !== "all" && item.category.toLowerCase() !== category) return false;
        if (!query) return true;
        return [item.name, item.category, item.description, item.friendlyId].join("\n").toLowerCase().includes(query);
      });
      return { total: 7536, challenges, categories: ["CRYPTO", "MISC", "PWN", "REVERSE", "WEB"] };
    }

    function importPreviewChallenge(payload) {
      const challenge = mockChallenges.find((item) => item.id === payload.challengeId) || mockChallenges[0];
      return { challenge, paths: challenge.files?.length ? ["preview://ctf2/challenge.zip"] : [], metadataPath: "preview://ctf2/ctf2-challenge.json", artifacts: challenge.files?.length ? [makeArtifact("challenge.zip")] : [] };
    }
  }

  function installSelectSkins() {
    installSelectSkin("ctf2-category-select", "题型");
    installSelectSkin("web-max-pages-select", "最多页面");
    installSelectSkin("web-max-depth-select", "同源深度");
  }

  function installSelectSkin(selectId, fallbackLabel) {
    const select = document.getElementById(selectId);
    if (!select || document.getElementById(`${selectId}-skin`)) return;
    const field = select.closest(".field");
    const label = field?.querySelector("span")?.textContent?.trim() || fallbackLabel;
    if (field) field.classList.add("select-native-field");
    const root = document.createElement("div");
    root.id = `${selectId}-skin`;
    root.className = `select-skin ${selectId}-skin`;
    root.innerHTML = `<button class="select-skin-button" type="button" aria-expanded="false"><span class="select-skin-label"></span><strong class="select-skin-current"></strong><span class="select-skin-caret">▾</span></button><div class="select-skin-menu" hidden></div>`;
    root.querySelector(".select-skin-label").textContent = label;
    (field || select).after(root);
    const button = root.querySelector(".select-skin-button");
    const current = root.querySelector(".select-skin-current");
    const menu = root.querySelector(".select-skin-menu");

    function labelOf(option) {
      return option?.textContent?.trim() || option?.value || "全部";
    }
    function sync() {
      const options = Array.from(select.options || []);
      const active = options.find((option) => option.value === select.value) || options[0];
      current.textContent = labelOf(active);
      menu.innerHTML = "";
      options.forEach((option) => {
        const item = document.createElement("button");
        item.type = "button";
        item.className = `select-skin-option${option.value === select.value ? " is-active" : ""}`;
        item.textContent = labelOf(option);
        item.addEventListener("click", () => {
          select.value = option.value;
          select.dispatchEvent(new Event("change", { bubbles: true }));
          closeMenu();
          sync();
        });
        menu.append(item);
      });
    }
    function openMenu() {
      menu.hidden = false;
      button.setAttribute("aria-expanded", "true");
      root.classList.add("is-open");
    }
    function closeMenu() {
      menu.hidden = true;
      button.setAttribute("aria-expanded", "false");
      root.classList.remove("is-open");
    }
    button.addEventListener("click", (event) => {
      event.stopPropagation();
      if (menu.hidden) openMenu();
      else closeMenu();
    });
    document.addEventListener("click", (event) => {
      if (!root.contains(event.target)) closeMenu();
    });
    select.addEventListener("change", sync);
    new MutationObserver(sync).observe(select, { childList: true, subtree: true, attributes: true });
    sync();
  }

  function installUpdateCard() {
    const list = document.querySelector("#settings-view .settings-list");
    if (!list || document.getElementById("update-status-text")) return;
    const row = document.createElement("div");
    row.className = "settings-row update-row";
    row.innerHTML = `<div><strong>版本更新</strong><p id="update-status-text">当前版本随 Release 发布，可手动检查新版。</p></div><div class="settings-actions"><button id="check-update-button" class="secondary-button" type="button">检查更新</button><button id="open-release-button" class="secondary-button" type="button">打开 Release</button></div>`;
    list.append(row);
    const status = row.querySelector("#update-status-text");
    const checkButton = row.querySelector("#check-update-button");
    const openButton = row.querySelector("#open-release-button");
    let releaseUrl = "https://github.com/Becauseiloveyo/ctf-compass/releases/latest";
    checkButton.addEventListener("click", async () => {
      checkButton.disabled = true;
      status.textContent = "正在检查 Release...";
      try {
        const result = await window.ctfCompass.checkForUpdates?.();
        releaseUrl = result?.url || releaseUrl;
        status.textContent = result?.hasUpdate ? `发现新版：${result.name || result.latestVersion}。` : `当前已是最新版本 ${result?.currentVersion || ""}。`;
      } catch (error) {
        status.textContent = `检查失败：${error.message}`;
      } finally {
        checkButton.disabled = false;
      }
    });
    openButton.addEventListener("click", () => window.ctfCompass.openExternal?.(releaseUrl));
  }

  function installCtf2ConnectorUi() {
    const nav = document.querySelector(".nav");
    const main = document.querySelector(".main");
    if (!nav || !main || document.getElementById("ctf2-view")) return;
    const state = { status: null, challenges: [], selected: null, busy: false, searchTimer: null };
    const navButton = document.createElement("button");
    navButton.className = "nav-item ctf2-nav-item";
    navButton.type = "button";
    navButton.dataset.view = "ctf2";
    navButton.innerHTML = `<span class="nav-icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none"><path d="M5 5h14v14H5zM8 9h8M8 13h5M8 17h8" /><path d="M16 13h.01" /></svg></span><span>CTF2</span>`;
    const webNav = nav.querySelector('[data-view="web"]');
    if (webNav) webNav.after(navButton);
    else nav.prepend(navButton);

    const view = document.createElement("section");
    view.id = "ctf2-view";
    view.className = "view ctf2-view";
    view.innerHTML = `<div class="ctf2-toolbar panel"><div><p class="panel-kicker">CTF2 CONNECTOR</p><h3 class="panel-title">直接浏览并导入 CTF2 题目</h3><p class="body-copy">题库可公开浏览；附件下载需要登录令牌。</p></div><div class="ctf2-account-actions"><span id="ctf2-account-status" class="scope-badge">检查登录状态...</span><button id="ctf2-login-button" class="secondary-button" type="button">应用内登录</button><button id="ctf2-system-login-button" class="secondary-button" type="button">浏览器登录</button><button id="ctf2-logout-button" class="secondary-button danger-button" type="button">退出</button></div></div><details class="panel ctf2-token-help"><summary>浏览器 token</summary><div class="ctf2-token-help-body"><p class="body-copy">Passkey 无法在应用内验证时，使用系统浏览器登录后复制 localStorage token。</p><div class="ctf2-token-row"><label class="field ctf2-token-field" for="ctf2-token-input"><span>粘贴 token</span><input id="ctf2-token-input" type="password" placeholder="在这里粘贴 CTF2 token" autocomplete="off" /></label><button id="ctf2-token-import-button" class="primary-button" type="button">验证并连接</button></div></div></details><div class="ctf2-layout"><section class="panel ctf2-browser-panel"><div class="ctf2-filters"><label class="field ctf2-search-field"><span>搜索题目</span><input id="ctf2-search-input" type="search" placeholder="题目名、描述或编号" autocomplete="off" /></label><label class="field"><span>题型</span><select id="ctf2-category-select"><option value="all">全部</option></select></label><button id="ctf2-refresh-button" class="secondary-button" type="button">刷新</button></div><div class="section-label-row"><div><h3 class="section-title">BUUCTF 公开练习题</h3><p id="ctf2-result-count" class="body-copy">尚未加载。</p></div></div><div id="ctf2-challenge-list" class="ctf2-challenge-list"></div></section><aside class="panel ctf2-detail-panel"><div class="panel-head compact-head"><div><p class="panel-kicker">SELECTED CHALLENGE</p><h3 id="ctf2-detail-title" class="panel-title">选择一道题目</h3></div></div><div id="ctf2-detail-meta" class="ctf2-detail-meta"></div><p id="ctf2-detail-description" class="body-copy">选择题目后可查看描述、附件和导入操作。</p><div id="ctf2-file-list" class="stack-list compact-stack"></div><button id="ctf2-import-button" class="primary-button ctf2-import-button" type="button" disabled>导入并求解</button><p id="ctf2-import-status" class="empty-copy">不会自动启动靶机，也不会自动提交 flag。</p></aside></div>`;
    main.append(view);
    const el = { account: view.querySelector("#ctf2-account-status"), login: view.querySelector("#ctf2-login-button"), systemLogin: view.querySelector("#ctf2-system-login-button"), logout: view.querySelector("#ctf2-logout-button"), token: view.querySelector("#ctf2-token-input"), importToken: view.querySelector("#ctf2-token-import-button"), search: view.querySelector("#ctf2-search-input"), category: view.querySelector("#ctf2-category-select"), refresh: view.querySelector("#ctf2-refresh-button"), count: view.querySelector("#ctf2-result-count"), list: view.querySelector("#ctf2-challenge-list"), detailTitle: view.querySelector("#ctf2-detail-title"), detailMeta: view.querySelector("#ctf2-detail-meta"), detailDescription: view.querySelector("#ctf2-detail-description"), fileList: view.querySelector("#ctf2-file-list"), importChallenge: view.querySelector("#ctf2-import-button"), importStatus: view.querySelector("#ctf2-import-status") };
    navButton.addEventListener("click", activateCtf2View);
    document.addEventListener("click", (event) => {
      const item = event.target.closest?.(".nav-item");
      if (item && item !== navButton) view.classList.remove("is-active");
    });

    function setStatus(message, kind = "info") {
      const banner = document.getElementById("status-banner");
      if (!banner) return;
      banner.textContent = message;
      banner.dataset.kind = kind;
      banner.classList.remove("is-hidden", "is-error");
      banner.classList.toggle("is-error", kind === "error");
    }
    function setBusy(busy) {
      state.busy = busy;
      [el.login, el.systemLogin, el.logout, el.importToken, el.refresh, el.importChallenge].forEach((button) => {
        if (!button) return;
        button.disabled = busy || (button === el.logout && !state.status?.connected) || (button === el.importChallenge && !state.selected?.files?.length);
      });
    }
    function activateCtf2View() {
      document.querySelectorAll(".nav-item").forEach((item) => item.classList.toggle("active", item === navButton));
      document.querySelectorAll(".view").forEach((node) => node.classList.toggle("is-active", node === view));
      document.body.dataset.view = "ctf2";
      document.getElementById("view-kicker").textContent = "CTF2";
      document.getElementById("view-title").textContent = "题库连接器";
      installSelectSkins();
      if (!state.challenges.length) {
        refreshStatus().catch(() => {});
        loadChallenges(false).catch(() => {});
      }
    }
    function renderStatus() {
      const connected = Boolean(state.status?.connected);
      el.account.textContent = connected ? `已登录${state.status?.profile?.username ? ` · ${state.status.profile.username}` : ""}` : "未登录 · 可浏览题库";
      setBusy(false);
    }
    function renderCategories(categories) {
      const current = el.category.value || "all";
      el.category.innerHTML = '<option value="all">全部</option>';
      (categories || []).forEach((category) => {
        const option = document.createElement("option");
        option.value = category;
        option.textContent = category;
        el.category.append(option);
      });
      el.category.value = Array.from(el.category.options).some((option) => option.value === current) ? current : "all";
      installSelectSkins();
    }
    function renderList(total) {
      el.count.textContent = `当前显示 ${state.challenges.length} 道题${Number.isFinite(total) ? ` / 匹配 ${total}` : ""}`;
      el.list.innerHTML = "";
      if (!state.challenges.length) {
        el.list.innerHTML = '<p class="empty-copy">没有匹配题目。</p>';
        renderDetail();
        return;
      }
      state.challenges.forEach((challenge) => {
        const item = document.createElement("button");
        item.type = "button";
        item.className = `ctf2-challenge-item${state.selected?.id === challenge.id ? " is-selected" : ""}`;
        item.innerHTML = `<div class="ctf2-challenge-copy"><strong>${escapeHtml(challenge.name)}</strong><small>${escapeHtml([challenge.category, challenge.difficulty].filter(Boolean).join(" · ") || "CTF2")}</small></div><span class="ctf2-challenge-stats">${challenge.files?.length ? `${challenge.files.length} 附件` : "无附件"}<br />${challenge.solveCount || 0} solves</span>`;
        item.addEventListener("click", () => {
          state.selected = challenge;
          renderList(total);
          renderDetail();
        });
        el.list.append(item);
      });
      renderDetail();
    }
    function renderDetail() {
      const selected = state.selected;
      el.detailTitle.textContent = selected?.name || "选择一道题目";
      el.detailDescription.textContent = selected?.description || "选择题目后可查看描述、附件和导入操作。";
      el.detailMeta.innerHTML = "";
      if (selected) [selected.category, selected.difficulty, selected.points ? `${selected.points} 分` : "", selected.solveCount ? `${selected.solveCount} solves` : ""].filter(Boolean).forEach((label) => { const tag = document.createElement("span"); tag.textContent = label; el.detailMeta.append(tag); });
      el.fileList.innerHTML = "";
      const files = selected?.files || [];
      if (!files.length) el.fileList.innerHTML = `<p class="empty-copy">${selected ? "该题没有附件；靶机题需要在 CTF2 页面手动启动环境。" : "尚未选择题目。"}</p>`;
      else files.forEach((file) => { const row = document.createElement("div"); row.className = "stack-item"; row.innerHTML = `<strong>${escapeHtml(file.name || "attachment.bin")}</strong><p>${file.size || 0} B</p>`; el.fileList.append(row); });
      setBusy(state.busy);
    }
    async function refreshStatus() {
      try { state.status = await window.ctfCompass.getCtf2Status?.(); } catch (error) { state.status = { connected: false, error: error.message }; }
      renderStatus();
    }
    async function loadChallenges(force = false) {
      setBusy(true);
      try {
        const result = await window.ctfCompass.listCtf2Challenges?.({ query: el.search.value.trim(), category: el.category.value, force, limit: 160 });
        state.challenges = result?.challenges || [];
        if (!state.challenges.some((item) => item.id === state.selected?.id)) state.selected = state.challenges[0] || null;
        renderCategories(result?.categories || []);
        renderList(Number(result?.total));
        setStatus(`已加载 CTF2 题目，共匹配 ${result?.total || state.challenges.length} 道。`);
      } catch (error) {
        setStatus(`CTF2 题库加载失败：${error.message}`, "error");
        await refreshStatus().catch(() => {});
      } finally { setBusy(false); }
    }
    async function importToken() {
      const token = el.token.value.trim();
      if (!token) { setStatus("请先粘贴 CTF2 token。", "error"); el.token.focus(); return; }
      setBusy(true);
      try { state.status = await window.ctfCompass.importCtf2Token(token); el.token.value = ""; renderStatus(); setStatus("CTF2 登录令牌已验证并加密保存在本机。"); await loadChallenges(true); }
      catch (error) { setStatus(`CTF2 token 验证失败：${error.message}`, "error"); }
      finally { setBusy(false); }
    }
    async function importChallenge() {
      if (!state.selected || !window.ctfCompass.importCtf2Challenge) return;
      setBusy(true);
      try {
        el.importStatus.textContent = "正在下载附件...";
        const imported = await window.ctfCompass.importCtf2Challenge({ challengeId: state.selected.id, groundId: state.selected.groundId });
        const challenge = imported.challenge || state.selected;
        setValue("title-input", challenge.name || "");
        setValue("tags-input", [challenge.category, "CTF2", challenge.groundName || "BUUCTF"].filter(Boolean).join(" "));
        setValue("description-input", challenge.description || "");
        setValue("notes-input", `CTF2 导入：${challenge.groundName || "BUUCTF"}\n附件已下载到沙盒。`);
        if (typeof window.appendPreparedArtifacts === "function") await window.appendPreparedArtifacts(Promise.resolve(imported.artifacts || []));
        activateWorkspaceView();
        el.importStatus.textContent = `已导入 ${imported.artifacts?.length || 0} 个附件，已进入工作台。`;
      } catch (error) {
        el.importStatus.textContent = `导入失败：${error.message}`;
        setStatus(`CTF2 导入失败：${error.message}`, "error");
      } finally { setBusy(false); }
    }
    function setValue(id, value) { const node = document.getElementById(id); if (node) { node.value = value; node.dispatchEvent(new Event("input", { bubbles: true })); } }
    function activateWorkspaceView() { document.querySelectorAll(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.view === "workspace")); document.querySelectorAll(".view").forEach((node) => node.classList.toggle("is-active", node.id === "workspace-view")); document.body.dataset.view = "workspace"; document.getElementById("view-kicker").textContent = "工作台"; document.getElementById("view-title").textContent = "以附件为中心的 CTF 工作台"; }
    el.login.addEventListener("click", async () => { await window.ctfCompass.openCtf2Login?.(); window.setTimeout(() => refreshStatus().catch(() => {}), 800); });
    el.systemLogin.addEventListener("click", () => window.ctfCompass.openCtf2SystemLogin?.());
    el.logout.addEventListener("click", async () => { state.status = await window.ctfCompass.logoutCtf2?.(); renderStatus(); });
    el.importToken.addEventListener("click", importToken);
    el.refresh.addEventListener("click", () => loadChallenges(true));
    el.importChallenge.addEventListener("click", importChallenge);
    el.search.addEventListener("input", () => { window.clearTimeout(state.searchTimer); state.searchTimer = window.setTimeout(() => loadChallenges(false), 280); });
    el.category.addEventListener("change", () => loadChallenges(false));
    refreshStatus().catch(() => {});
  }

  function escapeHtml(value) {
    return String(value ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#039;");
  }
})();
