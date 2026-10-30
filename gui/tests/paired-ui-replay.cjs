const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createReplay } = require('../../scripts/paired-ui-replay.cjs');
test('UI-only replay requires exact separate gates and rejects every provider/recovery/export route', async () => {
  const later = [];
  const data = { schemaVersion: 'aiw.dev/paired-workflow-ui-replay/v0alpha1', realProviderApplicationControlCalls: 0, scope: 'SYNTHETIC UI REPLAY: test', results: { synthetic: true }, states: {
    idle: { phase: 'idle', defaults: { evidence: 'fixture' } }, preparing: { phase: 'preparing' },
    review: { phase: 'review', workflowId: 'owned', review: { operatorIdentity: 'synthetic', challengeId: 'approval', exactConfirmation: 'approve exact' } },
    approved: { phase: 'approved', workflowId: 'owned', startChallengeId: 'start' }, running: { phase: 'running' }, completed: { phase: 'completed' },
  } };
  const invoke = createReplay(data, callback => later.push(callback));
  await assert.rejects(invoke('start_approved_workflow', {}));
  await assert.rejects(invoke('prepare_workflow', { kind: 'msix' }));
  await invoke('prepare_workflow', { kind: 'paired', operatorIdentity: 'synthetic' });
  await assert.rejects(invoke('prepare_workflow', { kind: 'paired', operatorIdentity: 'synthetic' }));
  later.shift()();
  await assert.rejects(invoke('submit_approval', { workflowId: 'other', challengeId: 'approval', confirmation: 'approve exact' }));
  await assert.rejects(invoke('submit_approval', { workflowId: 'owned', challengeId: 'approval', confirmation: 'wrong' }));
  await invoke('submit_approval', { workflowId: 'owned', challengeId: 'approval', confirmation: 'approve exact' });
  assert.equal((await invoke('get_state')).phase, 'approved');
  await assert.rejects(invoke('start_approved_workflow', { workflowId: 'owned', challengeId: 'stale' }));
  await invoke('start_approved_workflow', { workflowId: 'owned', challengeId: 'start' });
  await assert.rejects(invoke('start_approved_workflow', { workflowId: 'owned', challengeId: 'start' }));
  for (const name of ['recover_paired_workflow', 'cancel_paired_workflow', 'recover_msix_worker', 'export_results', 'load_retained_report', 'create_package']) await assert.rejects(invoke(name));
  assert.deepEqual(await invoke('open_results'), data.results);
  later.shift()(); assert.equal((await invoke('get_state')).phase, 'completed');
});
