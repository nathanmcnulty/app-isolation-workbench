// UI-only state replay. No filesystem, process, provider or durable-approval interface.
function createReplay(data, schedule = setTimeout) {
  if (data.schemaVersion !== 'aiw.dev/paired-workflow-ui-replay/v0alpha1' || data.realProviderApplicationControlCalls !== 0 || !data.scope.startsWith('SYNTHETIC UI REPLAY:')) throw new Error('Expected explicit synthetic Controller snapshots');
  const states = data.states;
  let current = states.idle;
  const requirePhase = phase => { if (current.phase !== phase) throw new Error('Replay phase does not allow this action'); };
  const requireId = args => { if (args.workflowId !== current.workflowId) throw new Error('Replay workflow does not match'); };
  return async (name, args = {}) => {
    if (name === 'get_state') return current;
    if (name === 'choose_input' && args.kind === 'evidence') return states.idle.defaults.evidence;
    if (name === 'prepare_workflow') {
      requirePhase('idle');
      if (args.kind !== 'paired' || args.installer || args.documentInput || args.package || args.operatorIdentity !== states.review.review.operatorIdentity) throw new Error('Use the fixed paired replay and its synthetic operator identity');
      current = states.preparing;
      schedule(() => { if (current === states.preparing) current = states.review; }, 150);
      return;
    }
    if (name === 'submit_approval') {
      requirePhase('review'); requireId(args);
      if (args.challengeId !== current.review.challengeId || args.confirmation !== current.review.exactConfirmation) throw new Error('Replay requires its exact displayed confirmation');
      current = states.approved; return;
    }
    if (name === 'start_approved_workflow') {
      requirePhase('approved'); requireId(args);
      if (args.challengeId !== current.startChallengeId) throw new Error('Replay Start challenge does not match');
      current = states.running;
      schedule(() => { current = states.completed; }, 15000);
      return;
    }
    if (name === 'open_results') return data.results;
    throw new Error('UI replay has no native backend. Use the accompanying Rust-generated summary files.');
  };
}
module.exports = { createReplay };
