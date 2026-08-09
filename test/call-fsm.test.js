const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const loadCallFSM = () => {
  const source = fs.readFileSync(
    path.join(__dirname, "..", "public", "js", "call_fsm.js"),
    "utf8"
  );
  const sandbox = { window: {} };
  vm.runInNewContext(source, sandbox, { filename: "call_fsm.js" });
  return sandbox.window.CallFSM;
};

test("outgoing call reaches in_call and resets its context", () => {
  const CallFSM = loadCallFSM();
  const fsm = CallFSM.create();

  fsm.transition("outgoing", { callId: "call-1", peerId: "bob" });
  assert.equal(fsm.state, "outgoing");
  assert.deepEqual(
    { ...fsm.context },
    { callId: "call-1", peerId: "bob", initiator: true }
  );

  fsm.transition("accepted");
  assert.equal(fsm.state, "in_call");

  fsm.transition("hangup");
  assert.equal(fsm.state, "ending");

  fsm.transition("reset");
  assert.equal(fsm.state, "idle");
  assert.deepEqual(
    { ...fsm.context },
    { callId: null, peerId: null, initiator: false }
  );
});

test("incoming rejection reports its reason and ignores invalid transitions", () => {
  const CallFSM = loadCallFSM();
  const changes = [];
  const fsm = CallFSM.create({
    onStateChange: (state, context, previous, meta) => {
      changes.push({ state, context, previous, meta });
    },
  });

  fsm.transition("accepted");
  assert.equal(fsm.state, "idle");

  fsm.transition("incoming", { callId: "call-2", peerId: "alice" });
  assert.equal(fsm.state, "incoming");
  assert.equal(fsm.context.initiator, false);

  fsm.transition("rejected");
  assert.equal(fsm.state, "ending");
  assert.equal(changes.at(-1).meta.reason, "rejected");
});
