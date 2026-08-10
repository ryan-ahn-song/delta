'use strict';

const state = { scenario: 'suspicious', report: null };
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
const escapeHTML = (value) => String(value ?? '').replace(/[&<>'"]/g, (char) => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[char]));
const labels = {
  file_read: 'FILE READ', file_write: 'FILE WRITE', network_connect: 'NETWORK',
  process_spawn: 'PROCESS', env_read: 'ENV READ', process_inspect: 'PROC INSPECT',
  persistence: 'PERSISTENCE', download_execute: 'DOWNLOAD+EXEC'
};

document.addEventListener('DOMContentLoaded', async () => {
  $$('.scenario').forEach((button) => button.addEventListener('click', () => selectScenario(button)));
  $('#run-button').addEventListener('click', runScenario);
  await Promise.all([checkHealth(), loadHistory(true)]);
});

function selectScenario(button) {
  $$('.scenario').forEach((item) => item.classList.remove('active'));
  button.classList.add('active');
  state.scenario = button.dataset.scenario;
}

async function checkHealth() {
  try {
    const health = await api('/api/health');
    $('#health-dot').className = 'status-dot';
    $('#health-text').textContent = health.docker_sandbox.ready ? '격리 센서 사용 가능' : '재생 모드 · Docker 선택사항';
  } catch (_) {
    $('#health-dot').className = 'status-dot off';
    $('#health-text').textContent = 'API 연결 끊김';
  }
}

async function runScenario() {
  const button = $('#run-button');
  button.disabled = true;
  button.querySelector('span').textContent = '분석 중…';
  try {
    const report = await api('/api/analyze/demo', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({scenario: state.scenario, provider: 'heuristic'})
    });
    renderReport(report);
    await loadHistory(false);
    toast('새 분석이 완료되었습니다.');
  } catch (error) {
    toast(error.message, true);
  } finally {
    button.disabled = false;
    button.querySelector('span').textContent = '분석 실행';
  }
}

async function loadHistory(openLatest) {
  try {
    const data = await api('/api/analyses');
    $('#history-count').textContent = `${data.count} records`;
    $('#history').innerHTML = data.reports.map((item) => `
      <button class="history-item" data-id="${escapeHTML(item.analysis_id)}">
        <b>${escapeHTML(item.package_name)}</b>
        <strong class="${item.final_score >= 6 ? 'hot' : ''}">${formatScore(item.final_score)}</strong>
        <small>${escapeHTML(shortDate(item.created_at))} · ${escapeHTML(item.decision)}</small>
      </button>`).join('');
    $$('.history-item').forEach((button) => button.addEventListener('click', () => openReport(button.dataset.id)));
    if (openLatest && data.reports.length) await openReport(data.reports[0].analysis_id);
  } catch (error) {
    toast(error.message, true);
  }
}

async function openReport(id) {
  try { renderReport(await api(`/api/analyses/${encodeURIComponent(id)}`)); }
  catch (error) { toast(error.message, true); }
}

function renderReport(report) {
  state.report = report;
  $('#empty-state').classList.add('hidden');
  $('#report').classList.remove('hidden');
  $('#analysis-id').textContent = report.analysis_id;
  $('#package-name').textContent = report.package_name;
  $('#package-version').textContent = `v${report.package_version}`;
  $('#score').textContent = formatScore(report.final_score);
  $('#threshold').textContent = `/ ${formatScore(report.threshold)}`;
  $('#decision').textContent = report.decision;
  const verdict = $('#verdict');
  verdict.className = `verdict ${report.final_score >= report.threshold ? 'danger' : report.final_score > 0 ? 'warn' : 'safe'}`;

  const categories = Object.entries(report.document.categories || {}).sort((a,b) => b[1]-a[1]);
  $('#category-chips').innerHTML = categories.map(([name, confidence]) => `<span class="chip">${escapeHTML(name)} <b>${Math.round(confidence*100)}%</b></span>`).join('');
  const unexplained = report.mismatches.filter((item) => !item.expected);
  $('#expected-count').textContent = report.expected.length;
  $('#observed-count').textContent = report.observed.length;
  $('#unmatched-count').textContent = unexplained.length;
  $('#chain-bonus').textContent = `+${formatScore(report.chain_bonus)}`;
  $('#runner-label').textContent = `${String(report.runner).toUpperCase()} · ${report.observation_window}S WINDOW`;

  $('#expected-list').innerHTML = report.expected.length ? report.expected.map((item) => eventRow(item.capability, item.target, item.purpose, true, 0)).join('') : '<div class="empty-list">NO POLICY-APPROVED INSTALL BEHAVIOR</div>';
  $('#observed-list').innerHTML = report.mismatches.length ? report.mismatches.map((item) => eventRow(item.event.capability, item.event.target, item.reason, item.expected, item.weight)).join('') : '<div class="empty-list">NO EVENT OBSERVED</div>';
  $('#timeline').innerHTML = report.mismatches.map((item) => {
    const stateClass = item.expected ? '' : item.event.status === 'attempted' ? 'attempt' : 'bad';
    return `<div class="time-event ${stateClass}"><b>${escapeHTML(labels[item.event.capability] || item.event.capability)}</b><small title="${escapeHTML(item.event.target)}">${escapeHTML(item.event.target)}</small><time>T+${Number(item.event.timestamp).toFixed(2)}s</time></div>`;
  }).join('') || '<div class="empty-list">TIMELINE EMPTY</div>';

  const signals = report.document.injection_signals || [];
  $('#injection-card').classList.toggle('hidden', !signals.length);
  $('#injection-text').textContent = signals.length ? `${signals.length}개 패턴을 명령이 아닌 비신뢰 데이터로 처리했습니다: ${signals.join(', ')}` : '';
}

function eventRow(capability, target, reason, expected, weight) {
  return `<div class="event-row">
    <span class="mark ${expected ? '' : 'bad'}">${expected ? '✓' : '!'}</span>
    <span class="cap">${escapeHTML(labels[capability] || capability)}</span>
    <span class="target" title="${escapeHTML(target)}">${escapeHTML(target)}</span>
    <span class="weight ${weight ? '' : 'zero'}" title="${escapeHTML(reason)}">${weight ? `+${formatScore(weight)}` : 'OK'}</span>
  </div>`;
}

async function api(url, options = {}) {
  const response = await fetch(url, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}

function toast(message, error = false) {
  const element = $('#toast');
  element.textContent = message;
  element.className = `toast show ${error ? 'error' : ''}`;
  window.setTimeout(() => { element.className = 'toast'; }, 2600);
}

function formatScore(value) { return Number(value) % 1 ? Number(value).toFixed(1) : String(Number(value)); }
function shortDate(value) { const date = new Date(value); return Number.isNaN(date.getTime()) ? value : date.toLocaleString('ko-KR', {month:'2-digit', day:'2-digit', hour:'2-digit', minute:'2-digit'}); }

