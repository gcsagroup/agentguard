const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { randomUUID } = require("node:crypto");

const source = fs.readFileSync(
  path.resolve(__dirname, "../../Extension/Resources/background.js"),
  "utf8"
);

function createHarness(sendNativeMessage) {
  let messageListener;
  const browser = {
    runtime: {
      sendNativeMessage,
      onMessage: {
        addListener(listener) { messageListener = listener; }
      },
      onInstalled: {
        addListener() {}
      }
    }
  };
  vm.runInNewContext(source, {
    browser,
    crypto: { randomUUID }
  }, { filename: "background.js" });
  return {
    status: () => messageListener({ type: "webshield:get-status" })
  };
}

function nativeStatus(enabled, privacyAccepted) {
  return async (_identifier, request) => ({
    version: 1,
    requestId: request.requestId,
    ok: true,
    enabled,
    privacyAccepted,
    policyRevision: "builtin-1"
  });
}

test("native enabled and disabled replies become explicit states", async () => {
  const enabled = createHarness(nativeStatus(true, true));
  assert.deepEqual({ ...(await enabled.status()) }, {
    state: "enabled",
    enabled: true,
    privacyAccepted: true,
    policyRevision: "builtin-1",
    nativeAvailable: true
  });

  const disabled = createHarness(nativeStatus(false, true));
  assert.deepEqual({ ...(await disabled.status()) }, {
    state: "disabled",
    enabled: false,
    privacyAccepted: true,
    policyRevision: "builtin-1",
    nativeAvailable: true
  });
});

test("native errors and malformed replies become unavailable, never disabled", async () => {
  const rejected = createHarness(async () => { throw new Error("native host unavailable"); });
  assert.equal((await rejected.status()).state, "unavailable");

  const malformed = createHarness(async () => ({ ok: false, error: "storage_unavailable" }));
  const status = await malformed.status();
  assert.equal(status.state, "unavailable");
  assert.equal(status.nativeAvailable, false);

  const ambiguous = createHarness(async (_identifier, request) => ({
    version: 1,
    requestId: request.requestId,
    ok: true,
    policyRevision: "builtin-1"
  }));
  assert.equal((await ambiguous.status()).state, "unavailable");
});
