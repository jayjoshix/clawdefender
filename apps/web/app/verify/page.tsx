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
                        <div className="mt-8 animate-fade-in">
                            <h2 className="text-xl font-semibold mb-4 text-green-400">✅ On-Chain Receipt Found</h2>

                            <div className="bg-gray-900 rounded p-4 font-mono text-sm overflow-x-auto border border-gray-700 space-y-3">
                                <div>
                                    <span className="text-gray-500 block">Session ID</span>
                                    <span className="text-yellow-300">{data.sessionId}</span>
                                </div>
                                <div>
                                    <span className="text-gray-500 block">Walrus Blob ID</span>
                                    <span className="text-blue-300">{data.walrusBlobId}</span>
                                </div>
                                <div>
                                    <span className="text-gray-500 block">Final Log Hash</span>
                                    <span className="text-purple-300 break-all">{data.finalLogHash}</span>
                                </div>
                                <div>
                                    <span className="text-gray-500 block">Bundle Hash</span>
                                    <span className="text-gray-300 break-all">{data.bundleHash}</span>
                                </div>
                                <div>
                                    <span className="text-gray-500 block">Policy Hash</span>
                                    <span className="text-gray-300 break-all">{data.policyHash}</span>
                                </div>
                            </div>

                            <div className="mt-6 flex flex-col gap-3">
                                <a
                                    href={`https://suiscan.xyz/${network}/object/${objectId}`}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="block w-full text-center py-2 bg-gray-700 hover:bg-gray-600 rounded text-cyan-300 transition-colors border border-gray-600"
                                >
                                    View on Suiscan ↗
                                </a>

                                <div className="bg-black/50 p-4 rounded border border-cyan-900/50">
                                    <p className="text-xs text-gray-500 mb-2 uppercase tracking-wide">Deep Verification Command</p>
                                    <code className="block text-green-400 mb-3 break-all">{data.verifyCommand}</code>
                                    <button
                                        onClick={copyCommand}
                                        className="w-full py-2 bg-cyan-900/50 hover:bg-cyan-900 text-cyan-200 rounded text-sm transition-colors border border-cyan-800"
                                    >
                                        📋 Copy Command
                                    </button>
                                </div>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
