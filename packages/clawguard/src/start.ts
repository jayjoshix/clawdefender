import { createServer } from './server/index.js';

async function main() {
    const { app } = await createServer();
    const port = parseInt(process.env.PORT ?? '3000', 10);
    await app.listen({ port, host: '0.0.0.0' }); // 0.0.0.0 for Docker
    console.log(`ClawGuard server listening on http://0.0.0.0:${port}`);
}

main().catch(err => {
    console.error(err);
    process.exit(1);
});
