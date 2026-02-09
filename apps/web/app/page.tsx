import Link from 'next/link';

export default function Home() {
  return (
    <div className="min-h-screen bg-black text-white flex flex-col items-center justify-center p-8">
      <h1 className="text-5xl font-bold mb-4 bg-gradient-to-r from-cyan-400 to-purple-500 text-transparent bg-clip-text">
        ClawGuard
      </h1>
      <p className="text-xl text-gray-400 mb-8 max-w-lg text-center">
        The Agentic Policy Firewall. Protect your agents with cryptographic access control and tamper-evident logging.
      </p>

      <div className="flex gap-4">
        <Link
          href="/verify"
          className="px-8 py-3 bg-cyan-600 hover:bg-cyan-500 rounded font-bold transition-colors"
        >
          Verify Session Receipt 🛡️
        </Link>
        <a
          href="https://github.com/jayjoshix/clawdefender"
          target="_blank"
          rel="noopener noreferrer"
          className="px-8 py-3 bg-gray-800 hover:bg-gray-700 rounded font-bold transition-colors border border-gray-700"
        >
          GitHub ↗
        </a>
      </div>
    </div>
  );
}
