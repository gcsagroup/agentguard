import { uiText } from './workspace-i18n.js';
const byId = id => document.getElementById(id);
const node = (tag, text, className) => {
  const el = document.createElement(tag);
  if (text !== undefined) el.textContent = text;
  if (className) el.className = className;
  return el;
};
const categories = new Set(['alert', 'blocked', 'unknown', 'record']);
const time = ms => Number.isSafeInteger(ms) && Number.isFinite(new Date(ms).getTime()) ? new Date(ms).toLocaleString() : uiText('executionTimeUnknown');

export function initializeExecutionRecords(invoke, openTechnique) {
  let generation = 0;
  let visibleLimit = 50;
  let view = null;
  let catalog = null;
  let sessions = [];
  let listTruncated = false;
  const select = byId('execution-session');
  const body = byId('execution-records');
  const status = byId('execution-status');
  const category = byId('execution-outcome');

  function render() {
    body.replaceChildren();
    if (!view) return;
    for (const channel of view.channels) {
      const section = node('section', undefined, 'card execution-channel');
      section.append(node('h2', uiText(`executionChannel_${channel.channel}`)));
      body.append(section);
      if (channel.status !== 'verified') {
        section.append(node('p', uiText(channel.status === 'not_recorded' ? 'executionNotRecorded' : 'executionUnavailable'), 'boundary'));
        continue;
      }
      const log = channel.log;
      section.append(node('p', `${uiText('executionIntegrity')} · ${log.records_verified}`, 'boundary'));
      const actions = log.actions.filter(a => category.value === 'all' || category.value === a.classification);
      section.append(node('p', uiText('executionCount').replace('{shown}', Math.min(visibleLimit, actions.length)).replace('{matched}', actions.length).replace('{total}', log.actions.length), 'muted'));
      if (!actions.length) section.append(node('p', uiText('executionNoMatch'), 'empty-state'));
      for (const action of actions.slice(0, visibleLimit)) {
        const card = node('article', undefined, 'execution-action');
        card.dataset.classification = action.classification;
        card.append(node('strong', uiText(`executionState_${action.state}`)), node('span', uiText(`executionCategory_${action.classification}`), 'badge outcome-badge'));
        const latest = action.stages.at(-1);
        card.append(node('p', `${time(latest.timestamp_ms)} · ${action.id_sha256.slice(0, 12)}`, 'muted'));
        const details = node('details'); details.append(node('summary', uiText('executionEvidence')));
        const stages = node('ol', undefined, 'execution-stages');
        for (const stage of action.stages) {
          const row = node('li');
          row.append(node('strong', `${stage.sequence} · ${uiText(`executionStage_${stage.kind}`)}`), node('span', `${time(stage.timestamp_ms)} · ${uiText(`executionOutcome_${stage.outcome}`)}`));
          row.append(node('small', uiText(stage.dispatched === true ? 'executionDispatched' : stage.kind === 'GatewayExecutionFinished' && stage.dispatched === false ? 'executionNotDispatched' : 'executionDispatchUnknown')));
          stages.append(row);
        }
        details.append(stages, node('p', uiText('executionEffectsBoundary'), 'boundary'));
        details.append(node('h3', uiText('executionSources')));
        if (!action.sources.length) details.append(node('p', uiText('executionNoSource'), 'muted'));
        for (const source of action.sources) {
          details.append(node('p', `${uiText(`executionSource_${source.status}`)} · ${source.entry ? uiText(`executionEntry_${source.entry}`) : uiText('executionUnknown')}`), node('code', source.source_id_sha256));
          if (source.content_sha256) details.append(node('p', `SHA-256 ${source.content_sha256}`, 'muted'));
        }
        details.append(node('h3', uiText('executionRules')));
        if (!action.findings.length) details.append(node('p', uiText('executionNoRule'), 'muted'));
        for (const finding of action.findings) {
          details.append(node('p', finding.rule_id));
          const mapping = catalog?.rules.find(rule => rule.id === finding.rule_id);
          for (const id of mapping?.technique_ids || []) {
            const technique = catalog.techniques.find(t => t.id === id);
            if (!technique) continue;
            const button = node('button', `${uiText('executionReference')} · ${technique.name}`, 'text-button');
            button.onclick = () => openTechnique(id);
            details.append(button);
          }
        }
        details.append(node('p', uiText('executionReferenceBoundary'), 'boundary'));
        const technical = node('details'); technical.append(node('summary', uiText('technicalDetails')));
        // 经后端校验的固定摘要，仍只作为文字；不显示命令、路径、输出正文或批准凭据。
        const metadata = { action_id_sha256: action.id_sha256, session_sha256: action.session_sha256, action_sha256: action.action_sha256, request_id_sha256: action.request_id_sha256, policy_version_sha256: action.policy_version_sha256, tool_identity_sha256: action.tool_identity_sha256, target_sha256: action.target_sha256, parameters_sha256: action.parameters_sha256, rule_package: action.rule_package, log_head_sha256: log.head_sha256, signature_attribution: log.signature_attribution };
        technical.append(node('pre', JSON.stringify(metadata, null, 2)));
        details.append(technical); card.append(details); section.append(card);
      }
      if (actions.length > visibleLimit) {
        const more = node('button', uiText('executionMore'), 'secondary');
        more.onclick = () => { visibleLimit += 50; render(); };
        section.append(more);
      }
    }
  }

  async function read() {
    const current = ++generation;
    const id = select.value;
    visibleLimit = 50;
    view = null; body.replaceChildren();
    if (!id) { status.textContent = uiText('executionEmpty'); return; }
    status.textContent = uiText('checking');
    try {
      const result = await invoke('read_execution_session', { sessionId: id });
      if (current !== generation || select.value !== id) return;
      if (result?.session_id !== id || !Array.isArray(result.channels) || result.channels.length !== 2
        || result.channels[0].channel !== 'gateway' || result.channels[1].channel !== 'browser') throw new Error('EXECUTION_VIEW');
      for (const channel of result.channels) {
        if (!['verified', 'not_recorded', 'unavailable'].includes(channel.status)) throw new Error('EXECUTION_STATUS');
        if (channel.status !== 'verified') { if (channel.log !== null) throw new Error('EXECUTION_STATUS'); continue; }
        const log = channel.log;
        if (log?.integrity !== 'hash_chain_verified' || log.signature_attribution !== 'not_verified'
          || !Array.isArray(log.actions) || log.actions.length > 8192 || log.actions.some(a => !categories.has(a.classification) || !Array.isArray(a.stages) || !a.stages.length)) throw new Error('EXECUTION_UNVERIFIED');
      }
      view = result; render();
      status.textContent = uiText(listTruncated ? 'executionListTruncated' : 'executionLoaded');
    } catch {
      if (current !== generation) return;
      view = null; body.replaceChildren(); status.textContent = uiText('executionUnavailable');
    }
  }

  async function load() {
    const current = ++generation;
    const previous = select.value;
    view = null; catalog = null; sessions = []; body.replaceChildren(); select.replaceChildren(); status.textContent = uiText('checking');
    try {
      const [listing, knowledge] = await Promise.all([
        invoke('list_execution_sessions'), invoke('get_knowledge_catalog').catch(() => null),
      ]);
      if (current !== generation) return;
      if (!Array.isArray(listing?.sessions) || listing.sessions.length > 256 || typeof listing.truncated !== 'boolean') throw new Error('EXECUTION_LIST');
      sessions = listing.sessions; listTruncated = listing.truncated;
      if (knowledge?.source === 'embedded_reference' && knowledge.instruction_authority === 'none' && knowledge.catalog?.trust?.authorization_effect === 'none') catalog = knowledge.catalog;
      for (const session of sessions) {
        const option = node('option', `${time(session.modified_ms)} · ${session.id.slice(0, 12)}`);
        option.value = session.id; select.append(option);
      }
      if (sessions.some(session => session.id === previous)) select.value = previous;
      await read();
    } catch {
      if (current !== generation) return;
      status.textContent = uiText('executionUnavailable');
    }
  }
  select.onchange = read;
  category.onchange = () => { visibleLimit = 50; render(); };
  byId('execution-refresh').onclick = load;
  window.addEventListener('agentguard-locale-change', () => {
    render();
    if (view) status.textContent = uiText(listTruncated ? 'executionListTruncated' : 'executionLoaded');
  });
  return { load };
}
