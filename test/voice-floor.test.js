const test = require("node:test");
const assert = require("node:assert/strict");
const { createVoiceFloor, FLOOR_DURATION_MS } = require("../proxy/voice-floor");

function fixture() {
  let now = 1000;
  const timers = [], expired = [];
  const floor = createVoiceFloor({ now: () => now,
    schedule: (callback, delay) => { const timer = { callback, due: now + delay }; timers.push(timer); return timer; },
    cancel: (timer) => { timer.cancelled = true; },
    onExpired: (room) => expired.push({ room, owner: floor.owner(room) }),
  });
  const advance = (ms) => {
    now += ms;
    for (const timer of [...timers]) {
      if (!timer.cancelled && !timer.fired && timer.due <= now) { timer.fired = true; timer.callback(); }
    }
  };
  return { floor, advance, timers, expired };
}

test("floor expires after exactly 60 seconds; retries and competitors cannot extend it", () => {
  const { floor, advance, timers, expired } = fixture();
  assert.equal(FLOOR_DURATION_MS, 60000);
  const first = floor.take("room", "alice");
  assert.equal(first.floorRemainingMs, 60000);
  advance(1000);
  assert.equal(floor.take("room", "alice").floorExpiresAt, first.floorExpiresAt);
  assert.equal(floor.take("room", "bob").floorOwner, "alice");
  assert.equal(timers.length, 1);
  assert.equal(floor.snapshot("room").floorRemainingMs, 59000);
  advance(58999);
  assert.equal(floor.owner("room"), "alice");
  assert.equal(expired.length, 0);
  advance(1);
  assert.equal(floor.owner("room"), null);
  assert.deepEqual(expired, [{ room: "room", owner: null }]);
  assert.deepEqual(floor.snapshot("room"), { floorOwner: null, floorExpiresAt: null, floorRemainingMs: 0 });
});

test("manual release cancels the timer; a stale callback cannot release the next lease", () => {
  const { floor, advance, timers, expired } = fixture();
  floor.take("room", "alice");
  const old = timers[0];
  advance(30000);
  assert.equal(floor.release("room"), true);
  assert.equal(old.cancelled, true);
  floor.take("room", "bob");
  old.callback(); // A callback queued before cancellation must still be harmless.
  assert.equal(floor.owner("room"), "bob");
  advance(30000);
  assert.equal(floor.owner("room"), "bob");
  advance(30000);
  assert.equal(floor.owner("room"), null);
  assert.deepEqual(expired, [{ room: "room", owner: null }]);
});

test("leave/rejoin of the same owner gets a new minute; other rooms expire independently", () => {
  const { floor, advance, timers, expired } = fixture();
  floor.take("a", "alice");
  const old = timers[0];
  advance(10000);
  floor.take("b", "bob");
  floor.release("a");
  floor.take("a", "alice");
  old.callback();
  assert.equal(floor.owner("a"), "alice");
  assert.equal(floor.snapshot("a").floorRemainingMs, 60000);
  advance(50000);
  assert.equal(floor.owner("a"), "alice");
  assert.equal(floor.owner("b"), "bob");
  advance(10000);
  assert.deepEqual(expired.map((item) => item.room).sort(), ["a", "b"]);
  assert.equal(floor.release("a"), false);
});
