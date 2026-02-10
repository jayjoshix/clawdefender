import { NextResponse } from 'next/server';

function bytesToHex(bytes: number[] | string) {
    if (Array.isArray(bytes)) {
        return bytes.map(b => b.toString(16).padStart(2, '0')).join('');
    }
    // Handle Base64 string from RPC
    if (typeof bytes === 'string') {
        const buf = Buffer.from(bytes, 'base64');
        return buf.toString('hex');
    }
    return '';
}

function bytesToString(bytes: number[] | string) {
    if (Array.isArray(bytes)) {
        return new TextDecoder().decode(new Uint8Array(bytes));
    }
    // Handle Base64 string from RPC
    if (typeof bytes === 'string') {
        return Buffer.from(bytes, 'base64').toString('utf8');
    }
    return '';
}

export async function GET(req: Request) {
    const { searchParams } = new URL(req.url);
    const objectId = searchParams.get('objectId');
    const network = searchParams.get('network') ?? 'testnet';

    if (!objectId?.startsWith('0x')) {
        return NextResponse.json({ error: 'invalid objectId' }, { status: 400 });
    }

    // Use env vars or public defaults
    const rpc = network === 'mainnet'
        ? (process.env.SUI_RPC_MAINNET || 'https://fullnode.mainnet.sui.io:443')
        : (process.env.SUI_RPC_TESTNET || 'https://fullnode.testnet.sui.io:443');

    const body = {
        jsonrpc: '2.0',
        id: 1,
        method: 'sui_getObject',
        params: [objectId, { showContent: true }],
    };

    try {
        const r = await fetch(rpc, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(body),
        });

        if (!r.ok) {
            throw new Error(`RPC error: ${r.statusText}`);
        }

        const j = await r.json();

        if (j.error) {
            return NextResponse.json({ error: j.error.message }, { status: 400 });
        }

        const fields = j?.result?.data?.content?.fields;
        if (!fields) {
            // If object exists but content is missing/not parsed
            if (j?.result?.data?.content) {
                return NextResponse.json({ error: 'unexpected object content structure' }, { status: 500 });
            }
            return NextResponse.json({ error: 'object not found or not a move object' }, { status: 404 });
        }

        // Mapping snake_case Move fields to camelCase for frontend
        const out = {
            objectId,
            network,
            sessionId: bytesToString(fields.session_id),
            walrusBlobId: bytesToString(fields.walrus_blob_id),
            policyHash: bytesToHex(fields.policy_sha256),
            bundleHash: bytesToHex(fields.bundle_sha256),
            finalLogHash: bytesToHex(fields.final_log_hash),
            // Generated command heavily useful for users
            verifyCommand: `pnpm demo -- --receipt ${objectId}`,
            suiscanLink: `https://suiscan.xyz/${network}/object/${objectId}`
        };

        return NextResponse.json(out);
    } catch (error: any) {
        return NextResponse.json({ error: error.message }, { status: 500 });
    }
}
