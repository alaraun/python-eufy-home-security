// Batch driver for scripts/gen_models.py and scripts/thing_models.py. Holds no vendor
// code: it loads the handler file whose path it is given and calls its exported entry
// points in a vm sandbox.
//
// job:    {"handler": "<path to <PN>Handle.mix.js>",
//          "requests": [{"kind": "set", "identifier", "payload", "device"}
//                     | {"kind": "action", "identifier", "payload", "device"}
//                     | {"kind": "get", "cmds", "device"}]}
// "set" sends the action "setProperty"; "action" sends the identifier itself as the action.
// reply:  a JSON array with one reply per request; a throwing request yields {"error": "..."}.
//
// Without arguments: one job on stdin, its reply on stdout.
// --serve: one job per stdin line, one reply line per job, until stdin ends; a job that
// cannot run (unreadable handler, bad JSON) yields the line {"error": "..."}.
//
// Every job runs in a fresh sandbox, so a handler's state never crosses jobs; only the
// compiled handler is reused. Math.random is reseeded before every request, so seeded
// fields (transaction ids) repeat across runs and requests.
"use strict";

const fs = require("fs");
const readline = require("readline");
const vm = require("vm");

function mulberry32(seed) {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const quiet = {};
for (const name of ["log", "info", "warn", "error", "debug", "trace"]) quiet[name] = () => {};

const SEEDED_RANDOM = new vm.Script("Math.random = () => __rng.next();");
// A fixed clock: recipes that embed the current time (sequence numbers, timestamps)
// repeat across runs. The same value is FIXED_CLOCK_MS in scripts/gen_models_codec.py.
const FIXED_CLOCK = new vm.Script(
  `Date = (() => {
    const Real = Date;
    class Fixed extends Real {
      constructor(...args) { if (args.length) super(...args); else super(__clock); }
      static now() { return __clock; }
    }
    return Fixed;
  })();`,
);

// The last handler compiled: a worker serves one product's jobs in a row.
let compiled = { path: null, script: null };

function handlerScript(path) {
  if (compiled.path !== path) {
    compiled = { path, script: new vm.Script(fs.readFileSync(path, "utf8")) };
  }
  return compiled.script;
}

function load(path) {
  // The sandbox exposes only a CommonJS module stub, a silent console, Buffer and timers.
  const sandbox = { module: { exports: {} }, console: quiet, Buffer, setTimeout, clearTimeout };
  sandbox.exports = sandbox.module.exports;
  sandbox.self = sandbox;
  sandbox.global = sandbox;
  vm.createContext(sandbox);
  handlerScript(path).runInContext(sandbox);
  const rng = { next: mulberry32(1) };
  sandbox.__rng = rng;
  SEEDED_RANDOM.runInContext(sandbox);
  sandbox.__clock = 1700000000000;
  FIXED_CLOCK.runInContext(sandbox);
  return { handler: sandbox.module.exports, rng };
}

function call(handler, request) {
  if (request.kind === "get") {
    const msg = {
      action: "getProperty",
      input: { property: [], commandId: request.cmds },
      device: request.device,
    };
    return handler.deviceStatus(JSON.stringify(msg) + "EOF;", 1);
  }
  if (request.kind === "action") {
    const input = { [request.identifier]: JSON.stringify({ "payload-value": request.payload }) };
    const msg = { action: request.identifier, input, device: request.device };
    return handler.controlDevice(JSON.stringify(msg) + "EOF;", 0);
  }
  const msg = {
    action: "setProperty",
    input: { [request.identifier]: JSON.stringify({ "payload-value": request.payload }) },
    device: request.device,
  };
  return handler.controlDevice(JSON.stringify(msg) + "EOF;", 0);
}

function run(job) {
  const { handler, rng } = load(job.handler);
  return job.requests.map((request) => {
    rng.next = mulberry32(1);
    try {
      const out = call(handler, request);
      return typeof out === "string" ? JSON.parse(out) : out;
    } catch (e) {
      return { error: String(e) };
    }
  });
}

if (process.argv[2] === "--serve") {
  const lines = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  lines.on("line", (line) => {
    let reply;
    try {
      reply = run(JSON.parse(line));
    } catch (e) {
      reply = { error: String(e) };
    }
    process.stdout.write(JSON.stringify(reply) + "\n");
  });
  // A handler's pending timers must not keep a worker alive once stdin ends.
  lines.on("close", () => process.exit(0));
} else {
  process.stdout.write(JSON.stringify(run(JSON.parse(fs.readFileSync(0, "utf8")))));
}
