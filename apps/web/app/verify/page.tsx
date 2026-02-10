'use client';

import { useState } from 'react';

export default function VerifyPage() {
    const [network, setNetwork] = useState('testnet');
    const [objectId, setObjectId] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [data, setData] = useState<any>(null);

    const fetchReceipt = async () => {
        setLoading(true);
        setError('');
        setData(null);

        try {
            const res = await fetch(`/api/receipt?objectId=${objectId}&network=${network}`);
            const json = await res.json();

            if (!res.ok) {
                throw new Error(json.error || 'Failed to fetch receipt');
            }

            setData(json);
        } catch (err: any) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const copyCommand = () => {
        if (data?.verifyCommand) {
            navigator.clipboard.writeText(data.verifyCommand);
            alert('Command copied to clipboard!');
        }
    };

    return (
        <div className="min-h-screen bg-gray-900 text-white p-8 font-sans">
            <div className="max-w-2xl mx-auto">
                <h1 className="text-3xl font-bold mb-2 text-cyan-400">ClawGuard Verification Portal</h1>
                <p className="text-gray-400 mb-8">
                    Verify session integrity using on-chain receipts. Trust the chain, verify the logs.
                </p>

                <div className="bg-gray-800 rounded-lg p-6 shadow-xl border border-gray-700">
                    <div className="flex gap-4 mb-6">
                        <div className="flex-1">
                            <label className="block text-sm font-medium text-gray-400 mb-1">Network</label>
                            <select
                                value={network}
                                onChange={(e) => setNetwork(e.target.value)}
                                className="w-full bg-gray-900 border border-gray-600 rounded px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
                            >
                                <option value="testnet">Sui Testnet</option>
                                <option value="mainnet">Sui Mainnet</option>
                            </select>
                        </div>
                        <div className="flex-[2]">
                            <label className="block text-sm font-medium text-gray-400 mb-1">Session Receipt Object ID</label>
                            <input
                                type="text"
                                value={objectId}
                                onChange={(e) => setObjectId(e.target.value)}
                                placeholder="0x..."
                                className="w-full bg-gray-900 border border-gray-600 rounded px-3 py-2 text-white focus:outline-none focus:border-cyan-500 font-mono"
                            />
                        </div>
                    </div>

                    <button
                        onClick={fetchReceipt}
                        disabled={loading || !objectId}
                        className={`w-full py-3 rounded font-bold transition-colors ${loading || !objectId
                            ? 'bg-gray-600 cursor-not-allowed text-gray-400'
                            : 'bg-cyan-600 hover:bg-cyan-500 text-white'
                            }`}
                    >
                        {loading ? 'Fetching from Chain...' : 'Fetch Receipt'}
                    </button>

                    {error && (
                        <div className="mt-4 p-4 bg-red-900/50 border border-red-700 rounded text-red-200">
                            ❌ Error: {error}
                        </div>
                    )}

                    {data && (
                        <div className="mt-8 animate-fade-in space-y-6">
                            <div className="bg-gray-900 rounded-lg p-6 border border-gray-700 shadow-inner">
                                <h2 className="text-xl font-semibold mb-4 text-green-400 flex items-center gap-2">
                                    ✅ On-Chain Receipt Found
                                    <span className="text-xs bg-green-900/50 text-green-300 px-2 py-0.5 rounded border border-green-800">Verified</span>
                                </h2>

                                <div className="space-y-3 font-mono text-sm">
                                    <div className="flex justify-between border-b border-gray-800 pb-2">
                                        <span className="text-gray-500">Session ID</span>
                                        <span className="text-yellow-300 font-bold">{data.sessionId}</span>
                                    </div>
                                    <div className="flex justify-between border-b border-gray-800 pb-2">
                                        <span className="text-gray-500">Walrus Blob ID</span>
                                        <span className="text-blue-300">{data.walrusBlobId}</span>
                                    </div>
                                    <div>
                                        <span className="text-gray-500 block mb-1">Final Log Hash</span>
                                        <span className="text-purple-300 break-all block bg-black/30 p-2 rounded">{data.finalLogHash}</span>
                                    </div>
                                    <div>
                                        <span className="text-gray-500 block mb-1">Bundle Hash</span>
                                        <span className="text-gray-300 break-all block bg-black/30 p-2 rounded">{data.bundleHash}</span>
                                    </div>
                                    <div>
                                        <span className="text-gray-500 block mb-1">Policy Hash</span>
                                        <span className="text-gray-300 break-all block bg-black/30 p-2 rounded">{data.policyHash}</span>
                                    </div>
                                </div>

                                <div className="mt-6 p-4 bg-cyan-900/20 border border-cyan-800/50 rounded text-sm text-cyan-200">
                                    <p>
                                        These values are read directly from the on-chain <strong>SessionReceipt</strong>.
                                        The CLI re-fetches Walrus ciphertext, decrypts via Seal (AccessCap-gated), and matches Bundle Hash + Final Log Hash.
                                    </p>
                                </div>
                            </div>

                            <div className="flex flex-col gap-3">
                                <a
                                    href={`https://suiscan.xyz/${network}/object/${objectId}`}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="w-full flex items-center justify-center gap-2 py-3 bg-gray-800 hover:bg-gray-700 rounded text-cyan-400 font-semibold transition-colors border border-gray-700"
                                >
                                    🔍 View on Suiscan ({network}) ↗
                                </a>

                                <div className="bg-black/40 p-5 rounded border border-green-900/50 relative group">
                                    <p className="text-xs text-green-400 mb-2 uppercase tracking-wide font-bold">Cryptographic Verification Command</p>
                                    <code className="block text-gray-300 mb-4 font-mono break-all text-sm bg-black p-3 rounded border border-gray-800">
                                        {data.verifyCommand}
                                    </code>
                                    <button
                                        onClick={copyCommand}
                                        className="w-full py-2 bg-green-700 hover:bg-green-600 text-white rounded font-bold shadow-lg transition-all active:scale-95 flex items-center justify-center gap-2"
                                    >
                                        📋 Copy Command
                                    </button>
                                </div>

                                <div className="mt-4">
                                    <details className="text-gray-500 text-xs cursor-pointer group">
                                        <summary className="hover:text-gray-300 transition-colors">Show Raw JSON Response</summary>
                                        <pre className="mt-2 p-4 bg-black rounded border border-gray-800 overflow-x-auto text-gray-400 font-mono">
                                            {JSON.stringify(data, null, 2)}
                                        </pre>
                                    </details>
                                </div>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
