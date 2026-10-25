// A rejected operation must not stop subsequent hardware work.
export function createSerialQueue(maxPending = 64) {
  let tail = Promise.resolve();
  let pending = 0;
  return (operation) => {
    if (pending >= maxPending) return Promise.reject(new Error("USBKey 请求队列已满"));
    pending += 1;
    const result = tail.then(operation).finally(() => { pending -= 1; });
    tail = result.catch(() => {});
    return result;
  };
}
