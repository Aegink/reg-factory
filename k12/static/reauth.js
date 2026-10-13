(() => {
  const $ = (selector) => document.querySelector(selector);
  const modes = {
    reauth: {action: '开始重登', help: '粘贴已有账号的邮箱、密码和 2FA 密钥，重新获取 Codex 凭据。'},
    convert: {action: '转换文件', help: '读取或粘贴 Sub2API 单账号、合并文件或账号数组，转换为 CPA / Sub2 / Cockpit。'},
    redeem: {action: '兑换成品', help: '使用邮箱、密码和 2FA 卡密，从已配置的上游取回成品文件。'},
  };
  const statusNames = {pending: '排队中', running: '处理中', done: '完成', error: '失败'};
  const outputNames = {'cpa': 'CPA', 'sub2-merged': 'Sub2 合并 JSON', 'sub2-single': 'Sub2 单独文件', 'cockpit': 'Cockpit'};
  const jobs = new Map();
  let mode = 'reauth', token = '', tokenExpiry = 0, polling = false;
  const escape = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[char]));

  function message(text, ok = false) {
    $('#reauth-message').textContent = text;
    $('#reauth-message').className = `message ${ok ? 'ok' : 'bad'}`;
  }

  async function request(path, options = {}) {
    const response = await fetch(path, {cache: 'no-store', ...options});
    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      const detail = Array.isArray(data.detail) ? '输入格式不正确，请检查内容' : data.detail;
      const error = new Error(data.error || detail || `HTTP ${response.status}`);
      error.status = response.status;
      throw error;
    }
    return response;
  }

  async function json(path, options = {}) { return (await request(path, options)).json(); }

  async function post(path, body) {
    if (!token || Date.now() >= tokenExpiry) {
      const session = await json('/api/reauth/session');
      token = session.token;
      tokenExpiry = Date.now() + (session.expires_in - 30) * 1000;
    }
    try {
      return await json(path, {method: 'POST', headers: {'Content-Type': 'application/json', 'X-REAUTH-TOKEN': token}, body: JSON.stringify(body)});
    } catch (error) {
      if (error.status === 403) { token = ''; tokenExpiry = 0; }
      throw error;
    }
  }

  function selectMode(value) {
    mode = value;
    for (const button of document.querySelectorAll('[data-reauth-mode]')) {
      const selected = button.dataset.reauthMode === mode;
      button.classList.toggle('secondary', !selected);
      button.setAttribute('aria-pressed', String(selected));
    }
    $('#reauth-account-label').hidden = mode === 'convert';
    $('#reauth-convert-input').hidden = mode !== 'convert';
    $('#reauth-submit').textContent = modes[mode].action;
    $('#reauth-help').textContent = modes[mode].help;
  }

  function rememberJobs() {
    try { sessionStorage.setItem('k12-reauth-jobs', JSON.stringify([...jobs.keys()])); } catch (_) { /* Storage may be disabled. */ }
  }

  function render() {
    $('#reauth-jobs').innerHTML = [...jobs.values()].reverse().map((job) => {
      const download = job.finished && job.ok > 0 ? Object.entries(outputNames).map(([kind, label]) => `<button class="secondary" data-reauth-download="${escape(job.job_id)}" data-kind="${kind}">${label}</button>`).join('') : '';
      const accounts = (job.accounts || []).map((account) => `<article class="reauth-account"><div class="task-head"><strong>${escape(account.email)}</strong><span class="${account.status === 'error' ? 'failed' : account.status === 'done' ? 'success' : 'running'}">${escape(statusNames[account.status] || account.status)}</span>${account.plan_type ? `<span class="plan">${escape(account.plan_type)}</span>` : ''}</div><p>${escape(account.message)}</p><ol class="reauth-steps">${(account.steps || []).map((step) => `<li class="step-${escape(step.status)}" title="${escape(step.message)}">${escape(step.label)}</li>`).join('')}</ol></article>`).join('');
      return `<article class="task reauth-job"><div class="task-head"><strong>${escape(modes[job.mode]?.action || '任务')} · ${job.done || 0}/${job.total || 0}</strong><span>${job.finished ? '已完成' : '运行中'} · 成功 ${job.ok || 0} · 失败 ${job.failed || 0}</span></div>${job.errors?.length ? `<p class="message bad">${job.errors.map(escape).join('<br>')}</p>` : ''}${accounts}<div class="actions reauth-downloads">${download}</div></article>`;
    }).join('') || '<p class="muted">提交账号或 JSON 文件后，可在这里查看进度并下载结果。</p>';
  }

  async function loadMeta() {
    const [meta, configData] = await Promise.all([json('/api/reauth/meta'), json('/api/config')]);
    const config = configData.config || {};
    $('#reauth-meta').textContent = `并发 ${meta.concurrency} · 单批最多 ${meta.max_accounts} 个账号 · 结果保留 ${Math.round(meta.result_ttl_seconds / 3600)} 小时`;
    $('#reauth-upstream-base').value = config.reauth_upstream_base || '';
    $('#reauth-proxy').placeholder = config.reauth_proxy_present ? '已保存专用代理，留空保留' : '留空跟随 K12 网络出口';
    $('#reauth-upstream-key').placeholder = config.reauth_upstream_key_present ? '已保存密钥，留空保留' : 'X-CPA-Server-Key';
    if (mode === 'redeem' && !meta.redeem_configured) message('兑换通道尚未配置，请展开设置填写上游地址和密钥');
  }

  async function saveSettings() {
    await json('/api/config', {method: 'PATCH', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({
      reauth_proxy: $('#reauth-proxy').value.trim(), reauth_upstream_base: $('#reauth-upstream-base').value.trim(),
      reauth_upstream_key: $('#reauth-upstream-key').value.trim(), clear_reauth_proxy: $('#reauth-clear-proxy').checked,
      clear_reauth_upstream_key: $('#reauth-clear-key').checked,
    })});
    $('#reauth-proxy').value = ''; $('#reauth-upstream-key').value = '';
    $('#reauth-clear-proxy').checked = false; $('#reauth-clear-key').checked = false;
    await loadMeta();
    message('重登与兑换设置已保存', true);
  }

  async function submit() {
    const text = $(mode === 'convert' ? '#reauth-json' : '#reauth-accounts').value.trim();
    if (!text) return message(mode === 'convert' ? '请粘贴或读取 Sub2API JSON 文件' : '请填写邮箱、密码和 2FA 密钥');
    $('#reauth-submit').disabled = true;
    try {
      const job = await post(`/api/reauth/${mode === 'convert' ? 'convert' : 'submit'}`, {text, mode});
      jobs.set(job.job_id, job);
      if (jobs.size > 20) {
        const old = [...jobs.values()].find((item) => item.finished && item.job_id !== job.job_id);
        if (old) jobs.delete(old.job_id);
      }
      rememberJobs(); render();
      message(job.finished ? `转换完成：成功 ${job.ok} 个账号` : '任务已提交，正在处理', true);
    } finally { $('#reauth-submit').disabled = false; }
  }

  async function poll(all = false) {
    if (polling) return;
    polling = true;
    try {
      await Promise.all([...jobs.values()].filter((job) => all || !job.finished).map(async (job) => {
        try { jobs.set(job.job_id, await json(`/api/reauth/job/${encodeURIComponent(job.job_id)}`)); }
        catch (error) {
          if (error.status === 404) { jobs.delete(job.job_id); rememberJobs(); message('部分任务已过期或服务已重启，请重新提交'); }
          else throw error;
        }
      }));
      render();
    } finally { polling = false; }
  }

  async function download(button) {
    button.disabled = true;
    try {
      const response = await request(`/api/reauth/job/${encodeURIComponent(button.dataset.reauthDownload)}/download/${button.dataset.kind}`);
      const filename = response.headers.get('Content-Disposition')?.match(/filename\*=UTF-8''([^;]+)/i)?.[1];
      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement('a');
      link.href = url; link.download = filename ? decodeURIComponent(filename) : `${button.dataset.kind}.json`;
      document.body.appendChild(link); link.click(); link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } finally { button.disabled = false; }
  }

  async function loadVisits(record = false) {
    let visitorId = '';
    try {
      visitorId = localStorage.getItem('k12-reauth-visitor') || crypto.randomUUID();
      localStorage.setItem('k12-reauth-visitor', visitorId);
    } catch (_) { visitorId = crypto.randomUUID(); }
    const data = record ? await json('/api/reauth/visit', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({visitor_id: visitorId})}) : await json('/api/reauth/visit');
    $('#reauth-visits-summary').textContent = `匿名访问统计 · 今日访客 ${data.today_visitors} · 今日访问 ${data.today_visits} · 近 10 分钟 ${data.online}`;
    $('#reauth-visits-days').innerHTML = `<table><thead><tr><th>日期</th><th>访客</th><th>访问</th></tr></thead><tbody>${data.days.map((day) => `<tr><td>${escape(day.date)}</td><td>${day.visitors}</td><td>${day.visits}</td></tr>`).join('')}</tbody></table>`;
  }

  const safe = (action) => async (...args) => { try { await action(...args); } catch (error) { message(error.message); } };
  document.querySelectorAll('[data-reauth-mode]').forEach((button) => { button.onclick = () => selectMode(button.dataset.reauthMode); });
  $('#reauth-submit').onclick = safe(submit);
  $('#reauth-save').onclick = safe(saveSettings);
  $('#reauth-refresh').onclick = safe(() => Promise.all([poll(true), loadMeta(), loadVisits()]));
  $('#reauth-jobs').onclick = safe((event) => {
    const button = event.target.closest('[data-reauth-download]');
    if (button) return download(button);
  });
  $('#reauth-file').onchange = safe(async (event) => {
    const accounts = [];
    for (const file of event.target.files || []) {
      if (file.size > 2000000) throw new Error('单个 JSON 文件不能超过 2 MB');
      const payload = JSON.parse((await file.text()).replace(/^\uFEFF/, ''));
      const items = Array.isArray(payload) ? payload : Array.isArray(payload.accounts) ? payload.accounts : [payload];
      accounts.push(...items);
    }
    if (accounts.length) $('#reauth-json').value = JSON.stringify({accounts}, null, 2);
    event.target.value = '';
  });
  try {
    const remembered = JSON.parse(sessionStorage.getItem('k12-reauth-jobs') || '[]');
    if (Array.isArray(remembered)) for (const id of remembered.slice(-20)) {
      if (typeof id === 'string' && /^[a-f0-9]{32}$/.test(id)) jobs.set(id, {job_id: id});
    }
  } catch (_) { /* Storage may be disabled. */ }
  render();
  safe(() => Promise.all([loadMeta(), poll(true), loadVisits(true)]))();
  setInterval(safe(() => poll()), 2500);
})();
