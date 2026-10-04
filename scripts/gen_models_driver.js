// Batch driver for scripts/gen_models.py and scripts/thing_models.py. Holds no vendor
// code: it loads the handler file whose path it is given and calls its exported entry
// points in a vm sandbox.
//
// stdin:  {"handler": "<path to <PN>Handle.mix.js>",
//          "requests": [{"kind": "set", "identifier", "payload", "device"}
//                     | {"kind": "action", "identifier", "payload", "device"}
//                     | {"kind": "get", "cmds", "device"}]}
// "set" sends the action "setProperty"; "action" sends the identifier itself as the action.
// stdout: a JSON array with one reply per request; a throwing request yields {"error": "..."}.
//
// Math.random is reseeded before every request, so seeded fields (transaction ids) repeat
// across runs and requests.
"use strict";

const fs = require("fs");
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

const job = JSON.parse(fs.readFileSync(0, "utf8"));

const quiet = {};
for (const name of ["log", "info", "warn", "error", "debug", "trace"]) quiet[name] = () => {};

// The sandbox exposes only a CommonJS module stub, a silent console, Buffer and timers.
const sandbox = { module: { exports: {} }, console: quiet, Buffer, setTimeout, clearTimeout };
sandbox.exports = sandbox.module.exports;
sandbox.self = sandbox;
sandbox.global = sandbox;
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(job.handler, "utf8"), sandbox);
const handler = sandbox.module.exports;

const rng = { next: mulberry32(1) };
sandbox.__rng = rng;
vm.runInContext("Math.random = () => __rng.next();", sandbox);

// A fixed clock: recipes that embed the current time (sequence numbers, timestamps)
// repeat across runs. The same value is FIXED_CLOCK_MS in scripts/gen_models_codec.py.
sandbox.__clock = 1700000000000;
vm.runInContext(
  `Date = (() => {
    const Real = Date;
    class Fixed extends Real {
      constructor(...args) { if (args.length) super(...args); else super(__clock); }
      static now() { return __clock; }
    }
    return Fixed;
  })();`,
  sandbox,
);

function call(request) {
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

const replies = job.requests.map((request) => {
  rng.next = mulberry32(1);
  try {
    const out = call(request);
    return typeof out === "string" ? JSON.parse(out) : out;
  } catch (e) {
    return { error: String(e) };
  }
});

process.stdout.write(JSON.stringify(replies));
