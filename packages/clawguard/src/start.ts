import { createServer } from './server/index.js';

async function main() {
    // Explicitly pass env vars to ensure configuration is honored
    const { app } = await createServer({
        policyPath: process.env.POLICY_PATH,
        logDir: process.env.LOGDIR,
        trustProxy: process.env.TRUST_PROXY === 'true', // Enable only if explicitly 'true'
        approversPath: process.env.APPROVERS_PATH,
    });

    const port = parseInt(process.env.PORT ?? '3000', 10);
    // Bind to 0.0.0.0 for Docker accessibility
    await app.listen({ port, host: '0.0.0.0' });
    console.log(`ClawGuard server listening on http://0.0.0.0:${port}`);
}

main().catch(err => {
    console.error(err);
    process.exit(1);
});
