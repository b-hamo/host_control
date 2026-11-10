/* Example: wiring the MINOBOX dashboard page (minobox-dashboard.html) to this backend.
 * Load it at the end of the page: <script src="example-wiring.js"></script>
 * It fills the "리소스 · 세션" tab and the "라이브 뷰" tab from GET /api/dashboard/overview every 2 s.
 * A reference for the frontend, not the product page. Contract: dashboard/README.md.
 *
 * Every string from the API (task, risk_type, file names) comes from what an Agent or a web page
 * typed: it is escaped before it goes into innerHTML. Keep that when you rewrite this.
 */
(function () {
  var token = new URLSearchParams(location.search).get('token') || '';
  var C = {ok: '#73BF69', warn: '#F2CC0C', bad: '#F2495C', blue: '#5794F2', dim: '#8e9196', faint: '#5c5f66', text: '#d8d9da'};
  var selected = null, data = null, shotAt = {};

  function esc(x) {
    return String(x == null ? '' : x).replace(/[&<>"']/g, function (c) {
      return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c];
    });
  }
  function color(s) {
    if (s.display_state === 'VIOLATION' || s.state === 'FAILED') return C.bad;
    if (s.state === 'RUNNING' || s.state === 'STARTED') return C.ok;
    if (s.state === 'TERMINATED') return C.faint;
    return C.warn;
  }
  function pct(p) { return p == null ? '—' : Math.round(p) + '%'; }
  function gb(b, unit) { return b == null ? '—' : (b / 1073741824).toFixed(1) + (unit || 'G'); }
  function elapsed(s) {
    var a = Date.parse(s.started_at), b = s.ended_at ? Date.parse(s.ended_at) : Date.now();
    if (!a) return '—';
    var t = Math.max(0, Math.round((b - a) / 1000));
    return Math.floor(t / 60) + 'm ' + String(t % 60).padStart(2, '0') + 's';
  }
  function shotUrl(s) {
    return '/api/runtimes/' + encodeURIComponent(s.id) + '/screenshot?token=' + encodeURIComponent(token) +
      '&v=' + encodeURIComponent(s.screenshot.captured_at || '');
  }
  function tile(label, body) {
    return '<div class="tile"><div style="font-size:13px; color:' + C.dim + '; margin-bottom:8px;">' + label + '</div>' + body + '</div>';
  }
  function bar(label, p, warnAt) {
    var c = p == null ? C.faint : p >= warnAt ? C.warn : C.ok;
    return '<div class="tile"><div style="display:flex; justify-content:space-between; font-size:13px; margin-bottom:9px;">' +
      '<span style="color:' + C.dim + ';">' + label + '</span><span style="font-family:var(--font-mono); color:' + c +
      '; font-size:18px;">' + pct(p) + '</span></div><div style="height:10px; background:#0b0c0e; border:1px solid #2e3036;' +
      ' border-radius:999px; overflow:hidden;"><div style="width:' + (p || 0) + '%; height:100%; background:' + c + ';"></div></div></div>';
  }
  function heading(text) {
    return '<div style="font-size:12px; letter-spacing:2px; color:' + C.dim + '; text-transform:uppercase; margin-bottom:10px;">' + text + '</div>';
  }

  function renderResources(o) {
    var w = o.runtimes.windows_sandbox, m = o.runtimes.micro_vm, r = o.host_resources;
    var rows = o.sessions.map(function (s) {
      return '<tr style="border-top:1px solid #24262b;"><td style="padding:11px 16px;">' + esc(s.label) + '</td>' +
        '<td style="color:' + (s.runtime === 'windows_sandbox' ? C.blue : C.dim) + ';">' + (s.runtime === 'windows_sandbox' ? 'Win Sandbox' : 'micro VM') + '</td>' +
        '<td style="color:' + (s.display_state === 'VIOLATION' ? C.bad : C.dim) + ';">' + esc(s.risk_type) + '</td>' +
        '<td style="color:' + color(s) + ';">' + esc(s.display_state) + '</td>' +
        '<td style="text-align:right;">' + pct(s.cpu_percent) + '</td>' +
        '<td style="text-align:right; padding-right:16px;">' + gb(s.mem_bytes) + '</td></tr>';
    }).join('') || '<tr><td colspan="6" style="padding:16px; color:' + C.faint + ';">진행 중인 세션이 없습니다</td></tr>';
    document.getElementById('mb-res').innerHTML =
      '<div>' + heading('격리 런타임') + '<div style="display:grid; grid-template-columns:1fr 1fr; gap:12px;">' +
      tile('Windows Sandbox', '<div style="font-size:36px; font-weight:500; color:' + (w.running ? C.ok : C.faint) +
        '; font-family:var(--font-mono); line-height:1;">' + w.running + '<span style="font-size:18px; color:' + C.faint + ';"> / 1</span></div>' +
        '<div style="margin-top:10px; font-size:12px; color:' + C.dim + '; font-family:var(--font-mono);">' + esc(w.state) + ' · 창 ' + esc(w.window_state) + '</div>') +
      tile('micro VM', '<div style="font-size:36px; font-weight:500; color:' + C.ok + '; font-family:var(--font-mono); line-height:1;">' +
        m.running + '<span style="font-size:18px; color:' + C.faint + ';"> / ' + m.max + '</span></div>' +
        '<div style="margin-top:10px; font-size:12px; color:' + C.dim + '; font-family:var(--font-mono);">running <span style="color:' + C.ok + ';">' +
        m.running + '</span> · starting <span style="color:' + C.warn + ';">' + m.starting + '</span></div>') +
      '</div></div>' +
      '<div>' + heading('리소스 (Host)') + '<div style="display:grid; grid-template-columns:1fr 1fr 0.8fr; gap:12px;">' +
      bar('CPU', r.cpu_percent, 80) + bar('메모리', r.mem_percent, 70) +
      '<div class="tile" style="text-align:center;"><div style="font-size:13px; color:' + C.dim + '; margin-bottom:4px;">VM 남은 슬롯</div>' +
      '<div style="font-size:34px; font-weight:500; color:' + C.ok + '; font-family:var(--font-mono); line-height:1;">' + m.free_slots + '</div>' +
      '<div style="font-size:11px; color:' + C.faint + '; font-family:var(--font-mono); margin-top:3px;">' + m.running + ' / ' + m.max + ' 가동</div></div>' +
      '</div></div>' +
      '<div style="flex:1; display:flex; flex-direction:column;">' + heading('진행중 세션') +
      '<div class="tile" style="padding:0; flex:1;"><table style="font-size:13px; font-family:var(--font-mono); color:' + C.text + ';">' +
      '<thead><tr style="color:' + C.dim + '; text-align:left;"><th style="font-weight:400; padding:11px 16px;">session</th><th style="font-weight:400;">런타임</th>' +
      '<th style="font-weight:400;">위험 유형</th><th style="font-weight:400;">상태</th><th style="font-weight:400; text-align:right;">CPU</th>' +
      '<th style="font-weight:400; text-align:right; padding-right:16px;">MEM</th></tr></thead><tbody>' + rows + '</tbody></table></div>' +
      (o.metrics.per_session === 'hcs' ? '' : '<div style="font-size:11px; color:' + C.faint + '; margin-top:6px;">세션별 CPU·메모리: ' + esc(o.metrics.reason) + '</div>') +
      '</div>';
  }

  function thumb(s) {
    var screen = s.screenshot.available
      ? '<img alt="" src="' + shotUrl(s) + '" style="position:absolute; inset:0; width:100%; height:100%; object-fit:cover;">'
      : '<div class="task"></div>';
    return '<div class="thumb' + (s.id === selected ? ' on' : '') + '" data-id="' + esc(s.id) + '"><div class="scr">' + screen +
      '<span class="ov"><span class="dot" style="background:' + color(s) + ';"></span>' + esc(s.label) + '</span></div>' +
      '<div style="padding:7px 9px; display:flex; justify-content:space-between; color:' + C.text + ';"><span style="font-size:13px;">' +
      esc(s.label) + '</span><span style="font-size:11px; color:' + color(s) + ';">' + esc(s.display_state) + '</span></div></div>';
  }

  function renderLive(o) {
    var wsb = o.sessions.filter(function (s) { return s.runtime === 'windows_sandbox'; });
    var vms = o.sessions.filter(function (s) { return s.runtime === 'micro_vm'; });
    if (!selected || !o.sessions.some(function (s) { return s.id === selected; })) selected = (wsb[0] || vms[0] || {}).id || null;
    var left = document.querySelector('#mb-live > div:first-child');
    left.innerHTML = '<div style="font-size:13px; letter-spacing:3px; color:' + C.dim + '; text-transform:uppercase; margin-bottom:9px;">sandbox</div>' +
      (wsb.map(thumb).join('') || '<div style="font-size:12px; color:' + C.faint + ';">꺼져 있음</div>') +
      '<div style="height:1px; background:#24262b; margin:14px 0;"></div>' +
      '<div style="font-size:13px; letter-spacing:2px; color:' + C.dim + '; text-transform:uppercase; margin-bottom:9px;">Micro VM <span style="letter-spacing:0; color:' +
      C.faint + '; font-size:12px;">' + o.runtimes.micro_vm.running + '/' + o.runtimes.micro_vm.max + '</span></div>' +
      '<div style="display:flex; flex-direction:column; gap:10px; max-height:420px; overflow-y:auto;">' + vms.map(thumb).join('') + '</div>';
    left.querySelectorAll('.thumb').forEach(function (t) {
      t.addEventListener('click', function () { selected = t.getAttribute('data-id'); renderLive(data); });
    });
    var s = o.sessions.filter(function (x) { return x.id === selected; })[0];
    if (!s) return;
    var box = document.querySelector('#mb-live > div:nth-child(2) > div:first-child');
    var img = box.querySelector('img.preview');
    if (!img) {
      img = document.createElement('img');
      img.className = 'preview'; img.alt = '';
      img.style.cssText = 'position:absolute; inset:0; width:100%; height:100%; object-fit:contain; background:#050607;';
      box.insertBefore(img, box.children[2]);
    }
    if (s.screenshot.available) {
      if (shotAt[s.id] !== s.screenshot.captured_at || img.dataset.id !== s.id) img.src = shotUrl(s);
      shotAt[s.id] = s.screenshot.captured_at; img.dataset.id = s.id; img.hidden = false;
    } else { img.hidden = true; }
    document.getElementById('pv-name').textContent = s.label;
    document.getElementById('pv-type').textContent = s.runtime === 'windows_sandbox' ? 'Windows Sandbox' : 'micro VM';
    document.getElementById('pv-dot').style.background = color(s);
    document.getElementById('d-type').textContent = s.runtime === 'windows_sandbox' ? 'Windows Sandbox' : 'micro VM';
    var st = document.getElementById('d-state'); st.textContent = s.display_state; st.style.color = color(s);
    document.getElementById('d-risk').textContent = s.risk_type + (s.task ? ' — ' + s.task : '');
    document.getElementById('d-elapsed').textContent = elapsed(s);
    document.getElementById('d-cpu').textContent = pct(s.cpu_percent);
    document.getElementById('d-mem').textContent = gb(s.mem_bytes, ' GB');
    document.getElementById('d-iso').textContent = s.runtime === 'windows_sandbox'
      ? '창 ' + (s.window_state || '—') + ' · 네트워크 ' + s.network
      : '네트워크 차단' + (s.screenshot.captured_at ? ' · 마지막 화면 ' + new Date(s.screenshot.captured_at).toLocaleTimeString() : '');
  }

  function refresh() {
    fetch('/api/dashboard/overview', {headers: {Authorization: 'Bearer ' + token}, cache: 'no-store'})
      .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); })
      .then(function (o) { data = o; renderResources(o); renderLive(o); })
      .catch(function (e) { console.warn('dashboard overview failed', e); });
  }
  refresh();
  setInterval(refresh, 2000);
})();
