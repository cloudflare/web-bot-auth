import { mkdir, writeFile } from "node:fs/promises";
import { Session } from "node:inspector/promises";
import { operations } from "./fixtures.mjs";

const operationName = process.env.OP ?? "verify";
const iterations = Number(process.env.ITERS ?? "2000");
const operation = operations[operationName];
if (operation === undefined) {
  throw new Error(
    `unknown OP=${operationName} (one of: ${Object.keys(operations).join(", ")})`
  );
}
if (!Number.isSafeInteger(iterations) || iterations <= 0) {
  throw new Error("ITERS must be a positive integer");
}

const events = [];
function instrumentWebCrypto() {
  const origin = performance.now();
  const subtle = crypto.subtle;
  for (const name of Object.getOwnPropertyNames(
    Object.getPrototypeOf(subtle)
  )) {
    if (name === "constructor" || typeof subtle[name] !== "function") continue;
    const original = subtle[name].bind(subtle);
    subtle[name] = (...arguments_) => {
      const start = (performance.now() - origin) * 1_000;
      return Promise.resolve(original(...arguments_)).finally(() => {
        events.push({
          name,
          ph: "X",
          pid: 1,
          tid: 1,
          ts: start,
          dur: (performance.now() - origin) * 1_000 - start,
        });
      });
    };
  }
}

async function run() {
  for (let index = 0; index < iterations; index++) await operation();
}

for (let index = 0; index < Math.min(iterations, 200); index++)
  await operation();

const cpuSession = new Session();
cpuSession.connect();
await cpuSession.post("Profiler.enable");
await cpuSession.post("Profiler.setSamplingInterval", { interval: 50 });
await cpuSession.post("Profiler.start");
await run();
const { profile } = await cpuSession.post("Profiler.stop");
cpuSession.disconnect();

const heapSession = new Session();
heapSession.connect();
await heapSession.post("HeapProfiler.enable");
await heapSession.post("HeapProfiler.startSampling", {
  samplingInterval: 4_096,
  includeObjectsCollectedByMajorGC: true,
  includeObjectsCollectedByMinorGC: true,
});
await run();
const { profile: heap } = await heapSession.post("HeapProfiler.stopSampling");
heapSession.disconnect();

instrumentWebCrypto();
await run();

await mkdir("bench/.trace", { recursive: true });
const output = `bench/.trace/${operationName}`;
await Promise.all([
  writeFile(`${output}.cpuprofile`, JSON.stringify(profile)),
  writeFile(`${output}.heapprofile`, JSON.stringify(heap)),
  writeFile(`${output}.trace.json`, JSON.stringify({ traceEvents: events })),
]);
console.log(
  `wrote ${output}.{cpuprofile,heapprofile,trace.json} (${events.length} WebCrypto calls)`
);
