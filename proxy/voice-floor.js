const FLOOR_DURATION_MS = 60_000;

function createVoiceFloor({ now = Date.now, schedule = setTimeout, cancel = clearTimeout, onExpired = () => {} } = {}) {
  const rooms = new Map();
  const owner = (room) => rooms.get(room)?.owner || null;
  const snapshot = (room) => {
    const floor = rooms.get(room);
    return {
      floorOwner: floor?.owner || null,
      floorExpiresAt: floor?.expiresAt || null,
      floorRemainingMs: floor ? Math.max(0, floor.expiresAt - now()) : 0,
    };
  };
  const release = (room) => {
    const floor = rooms.get(room);
    if (!floor) return false;
    rooms.delete(room);
    cancel(floor.timer);
    return true;
  };
  const take = (room, id) => {
    if (rooms.has(room)) return snapshot(room); // Retries cannot extend the lease.
    const floor = { owner: id, expiresAt: now() + FLOOR_DURATION_MS, timer: null };
    rooms.set(room, floor);
    floor.timer = schedule(() => {
      if (rooms.get(room) !== floor) return; // An old timer cannot release a new owner.
      rooms.delete(room);
      onExpired(room);
    }, FLOOR_DURATION_MS);
    floor.timer?.unref?.();
    return snapshot(room);
  };
  return { owner, take, release, snapshot };
}

module.exports = { createVoiceFloor, FLOOR_DURATION_MS };
