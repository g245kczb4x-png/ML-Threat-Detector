'use client';

import React, { useState, useEffect } from 'react';

// Define the exact data structure streaming from the FastAPI backend
interface ThreatAlert {
    timestamp: string;
    attacker_ip: string;
    session_id: string;
    command: string;
    old_state: string;
    new_state: string;
    tactic: string;
    confidence: number;
}

export default function DashboardPage() {
    const [alerts, setAlerts] = useState<ThreatAlert[]>([]);
    const [siemStatus, setSiemStatus] = useState<'Connecting' | 'Live' | 'Disconnected'>('Connecting');

    useEffect(() => {
        // Connect to the central FastAPI processing pipeline
        const socket = new WebSocket('ws://127.0.0.1:8000/ws/telemetry');

        socket.onopen = () => {
            setSiemStatus('Live');
            console.log('[+] Operational WebSocket stream established with SIEM core.');
        };

        socket.onmessage = (event) => {
            try {
                const incomingData: ThreatAlert = JSON.parse(event.data);

                // Append new alert directly to the top of the feed stack
                setAlerts((prevAlerts) => [incomingData, ...prevAlerts]);
            } catch (error) {
                console.error('[-] Failed parsing streaming telemetry frame:', error);
            }
        };

        socket.onclose = () => {
            setSiemStatus('Disconnected');
        };

        socket.onerror = () => {
            setSiemStatus('Disconnected');
        };

        // THE DUPLICATION CURE: Closes the stale connection when React forces a component lifecycle remount
        return () => {
            if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING) {
                socket.close();
            }
        };
    }, []);

    // Helper mapping to color-code the MITRE tactics badges elegantly
    const getTacticBadgeStyle = (tactic: string) => {
        const base = "px-3 py-1 rounded text-xs font-bold tracking-wider uppercase inline-block ";
        switch (tactic.toUpperCase()) {
            case 'CREDENTIAL_ACCESS':
                return base + "bg-red-950 text-red-400 border border-red-800";
            case 'RECONNAISSANCE':
                return base + "bg-purple-950 text-purple-400 border border-purple-800";
            case 'SYSTEM_DISCOVERY':
                return base + "bg-blue-950 text-blue-400 border border-blue-800";
            case 'EXFILTRATION':
                return base + "bg-orange-950 text-orange-400 border border-orange-800";
            default:
                return base + "bg-zinc-800 text-zinc-400 border border-zinc-700";
        }
    };

    return (
        <div className="min-h-screen bg-zinc-950 text-zinc-100 p-8 font-sans">
            {/* Upper Navigation / Control Bar Header */}
            <header className="border-b border-zinc-800 pb-6 mb-8 flex justify-between items-center">
                <div>
                    <h1 className="text-2xl font-black tracking-tight text-white">
                        AGENTIC DECEPTION PLATFORM
                    </h1>
                    <p className="text-zinc-500 text-sm mt-1">Real-time Autonomous Honeypot Telemetry Classifier</p>
                </div>

                {/* Connection Pulse Signal */}
                <div className="flex items-center gap-3 bg-zinc-900 border border-zinc-800 px-4 py-2 rounded-lg">
                    <span className="text-xs font-semibold uppercase text-zinc-400 tracking-wide">
                        SIEM Status:
                    </span>
                    <div className="flex items-center gap-2">
                        <span className={`w-2 h-2 rounded-full ${siemStatus === 'Live' ? 'bg-emerald-500 animate-pulse' :
                                siemStatus === 'Connecting' ? 'bg-amber-500 animate-pulse' : 'bg-rose-500'
                            }`} />
                        <span className={`text-xs font-bold ${siemStatus === 'Live' ? 'text-emerald-400' :
                                siemStatus === 'Connecting' ? 'text-amber-400' : 'text-rose-400'
                            }`}>
                            {siemStatus}
                        </span>
                    </div>
                </div>
            </header>

            {/* Main Monitoring Workspace Grid */}
            <main className="space-y-6">
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
                                    <th className="px-6 py-4">Intercepted Payload Command</th>
                                    <th className="px-6 py-4 w-52">Classified Intent Tactic</th>
                                    <th className="px-6 py-4 w-32 text-right">ML Confidence</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-zinc-800/60 font-mono text-sm">
                                {alerts.length === 0 ? (
                                    <tr>
                                        <td colSpan={5} className="px-6 py-12 text-center text-zinc-600 italic">
                                            No inbound telemetry signatures identified yet. Awaiting network interactions on port :8022...
                                        </td>
                                    </tr>
                                ) : (
                                    alerts.map((alert, index) => (
                                        <tr
                                            key={index}
                                            className="hover:bg-zinc-900/40 transition-colors duration-150 group"
                                        >
                                            <td className="px-6 py-4 text-zinc-500">{alert.timestamp}</td>
                                            <td className="px-6 py-4 font-semibold text-zinc-300">{alert.attacker_ip}</td>
                                            <td className="px-6 py-4">
                                                <span className="bg-zinc-950 text-emerald-400 px-2.5 py-1 rounded border border-zinc-800 block font-medium overflow-x-auto whitespace-pre group-hover:border-zinc-700 transition-colors">
                                                    {alert.command}
                                                </span>
                                            </td>
                                            <td className="px-6 py-4">
                                                <span className={getTacticBadgeStyle(alert.tactic)}>
                                                    {alert.tactic.replace('_', ' ')}
                                                </span>
                                            </td>
                                            <td className="px-6 py-4 text-right font-bold text-zinc-200">
                                                <span className={`${alert.confidence >= 90 ? 'text-rose-400' :
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