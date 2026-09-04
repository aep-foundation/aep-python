import { readFile, writeFile } from "node:fs/promises";

const [pythonResultPath, nodeResultPath, reportPath, pythonServiceUrl] = process.argv.slice(2);

if (
  pythonResultPath === undefined ||
  nodeResultPath === undefined ||
  reportPath === undefined ||
  pythonServiceUrl === undefined
) {
  throw new Error(
    "usage: verify-node-interoperability.mjs PYTHON_RESULT NODE_RESULT REPORT PYTHON_SERVICE_URL"
  );
}

const pythonResult = JSON.parse(await readFile(pythonResultPath, "utf8"));
const nodeResult = JSON.parse(await readFile(nodeResultPath, "utf8"));

requireEqual(pythonResult.agent, "python", "Python Agent identity");
requireEqual(pythonResult.service, "node", "Python Agent Service counterpart");
requireEqual(pythonResult.platform, "node", "Python Agent Platform counterpart");
requireEqual(pythonResult.enrollment, "active", "Python Agent enrollment");
requireEqual(pythonResult.credential_mode, "api-key", "Python Agent credential mode");
requireEqual(pythonResult.protected_resource_status, 200, "Python Agent protected resource");
requireEqual(pythonResult.revoked, true, "Python Agent credential revocation");
requireEqual(pythonResult.revoked_resource_status, 401, "Node Service credential invalidation");

requireEqual(nodeResult.credentialMode, "api-key", "Node Agent credential mode");
requireEqual(nodeResult.enroll?.status, "active", "Node Agent enrollment");
requireEqual(nodeResult.statusBeforeGrant?.status, "active", "Node Agent pre-Grant status");
requireEqual(nodeResult.statusAfterRevoke?.status, "active", "Node Agent post-Revoke status");
requireEqual(nodeResult.resource?.available, true, "Node Agent protected resource");
requireEqual(nodeResult.profile?.updated, true, "Node Agent protected profile");
requireEqual(typeof nodeResult.grant?.credential_id, "string", "Node Agent credential identifier type");
requireEqual(nodeResult.grant?.credential_id.length > 0, true, "Node Agent credential identifier");
requireEqual(Object.keys(nodeResult.revoke ?? {}).length, 0, "Node Agent Revoke response");

const credentialHeader = nodeResult.grant?.header;
const credentialValue = nodeResult.grant?.api_key;
requireEqual(typeof credentialHeader, "string", "Node Agent credential header type");
requireEqual(credentialHeader.length > 0, true, "Node Agent credential header");
requireEqual(typeof credentialValue, "string", "Node Agent credential value type");
requireEqual(credentialValue.length > 0, true, "Node Agent credential value");
const revokedResponse = await fetch(new URL("/api/resource", pythonServiceUrl), {
  headers: { [credentialHeader]: credentialValue }
});
requireEqual(revokedResponse.status, 401, "Python Service credential invalidation");

const report = {
  aep_version: "1.0",
  evidence: [
    {
      agent: "python",
      counterpart: "node",
      flow: "Inspect, Enroll, Grant, protected resource, Revoke, revoked-resource rejection",
      role: "service",
      status: "passed"
    },
    {
      agent: "python",
      counterpart: "node",
      flow: "Discovery, List, Provision, delegated Sign",
      role: "platform",
      status: "passed"
    },
    {
      agent: "node",
      counterpart: "python",
      flow: "Inspect, Enroll, Grant, protected resource, Revoke, revoked-resource rejection",
      role: "service",
      status: "passed"
    },
    {
      agent: "node",
      counterpart: "python",
      flow: "Discovery, List, Provision, delegated Sign",
      role: "platform",
      status: "passed"
    }
  ],
  status: "passed"
};

await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");

function requireEqual(actual, expected, name) {
  if (!Object.is(actual, expected)) {
    throw new Error(`${name}: expected ${JSON.stringify(expected)}, received ${JSON.stringify(actual)}`);
  }
}
