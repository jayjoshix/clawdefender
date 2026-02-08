
import { createServer } from '../src/server/index.js';

// Simple wrapper to run server with env-configured paths for E2E testing
const policyPath = process.env.POLICY_PATH;
const logDir = process.env.LOG_DIR;
const approversPath = process.env.APPROVERS_PATH;
const port = parseInt(process.env.PORT || '3000', 10);

console.log(`Starting test server with:
  Policy: ${policyPath}
  LogDir: ${logDir}
  Approvers: ${approversPath}
  Port: ${port}
`);

const { app } = await createServer({
    policyPath,
    logDir,
    approversPath
});

const address = await app.listen({ port, host: '127.0.0.1' });
console.log(`E2E_BASE_URL=${address}`);
