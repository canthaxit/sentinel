"""
Threat Intelligence Dashboard HTML Template
Dark theme matching existing Sentinel dashboard.
"""

THREAT_INTEL_DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Sentinel - Threat Intelligence</title>
    <link rel="stylesheet" href="/static/tailwind.min.css">
    <meta http-equiv="refresh" content="30">
    <style>
        .heat-low { background-color: rgba(34, 197, 94, 0.2); }
        .heat-med { background-color: rgba(234, 179, 8, 0.3); }
        .heat-high { background-color: rgba(239, 68, 68, 0.3); }
        .heat-crit { background-color: rgba(239, 68, 68, 0.6); }
    </style>
</head>
<body class="bg-gray-900 text-gray-100 p-6">
    <div class="max-w-7xl mx-auto">
        {{ nav_html|safe }}

        <!-- Header -->
        <header class="flex justify-between items-center mb-6 border-b border-gray-700 pb-4">
            <div>
                <h1 class="text-3xl font-bold text-red-500 tracking-widest">SENTINEL</h1>
                <p class="text-gray-400 text-sm">Threat Intelligence Center // STIX 2.1 Export Ready</p>
            </div>
            <div class="flex gap-4">
                <a href="/threat-intel/api/reports/pdf" class="text-sm bg-red-800 hover:bg-red-700 px-3 py-1 rounded transition">
                    Export PDF
                </a>
                <a href="/threat-intel/api/stix/bundle" class="text-sm bg-blue-800 hover:bg-blue-700 px-3 py-1 rounded transition">
                    Export STIX Bundle
                </a>
                <a href="/threat-intel/api/export/csv" class="text-sm bg-green-800 hover:bg-green-700 px-3 py-1 rounded transition">
                    Export CSV
                </a>
            </div>
        </header>

        <!-- Panel 1: Threat Overview (3 stat cards) -->
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
            <div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <h2 class="text-sm font-bold text-cyan-400 mb-3 border-b border-gray-700 pb-2">Total IOCs</h2>
                <div class="text-4xl font-mono text-cyan-300 mb-2">{{ stats.total_iocs }}</div>
                <div class="text-xs text-gray-400 space-y-1">
                    {% for type_name, count in stats.by_type.items() %}
                    <div class="flex justify-between">
                        <span>{{ type_name }}:</span>
                        <span class="text-cyan-200">{{ count }}</span>
                    </div>
                    {% endfor %}
                </div>
                <div class="mt-2 text-xs text-gray-500">
                    {{ stats.total_sightings }} total sightings |
                    {{ stats.unique_payload_hashes }} unique payloads
                </div>
            </div>

            <div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <h2 class="text-sm font-bold text-purple-400 mb-3 border-b border-gray-700 pb-2">Active Campaigns</h2>
                <div class="text-4xl font-mono text-purple-300 mb-2">{{ campaigns|length }}</div>
                <div class="text-xs text-gray-400 space-y-1">
                    {% for campaign in campaigns[:5] %}
                    <div class="flex justify-between">
                        <span class="truncate mr-2">{{ campaign.session_id[:8] }}...</span>
                        <span class="text-red-300">{{ campaign.threat_count }} threats</span>
                    </div>
                    {% endfor %}
                </div>
            </div>

            <div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <h2 class="text-sm font-bold text-green-400 mb-3 border-b border-gray-700 pb-2">Feed Status</h2>
                <div class="text-xs space-y-2 mt-2">
                    {% for feed in feeds %}
                    <div class="flex justify-between items-center">
                        <span class="text-gray-300">{{ feed.name }}</span>
                        {% if feed.status == 'active' %}
                        <span class="text-green-400 text-xs">Active</span>
                        {% elif feed.status == 'disabled' %}
                        <span class="text-gray-500 text-xs">Disabled</span>
                        {% else %}
                        <span class="text-yellow-400 text-xs">{{ feed.status }}</span>
                        {% endif %}
                    </div>
                    {% endfor %}
                </div>
                <div class="mt-3 text-xs text-gray-500">
                    STIX 2.1: {{ 'Available' if stix_available else 'Fallback Mode' }}
                </div>
            </div>
        </div>

        <!-- Panel 2 + 3: Attack Heatmap + MITRE Coverage -->
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
            <!-- Attack Pattern Heatmap -->
            <div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <h2 class="text-lg font-bold text-yellow-400 mb-3 border-b border-gray-700 pb-2">Attack Category Heatmap</h2>
                <div class="space-y-2">
                    {% for cat_id, cat_data in categories.items() %}
                    {% set count = stats.by_threat_type.get(cat_id, 0) %}
                    {% set heat = 'heat-crit' if count > 20 else 'heat-high' if count > 10 else 'heat-med' if count > 3 else 'heat-low' %}
                    <div class="flex items-center gap-2">
                        <div class="w-40 text-xs text-gray-300 truncate">{{ cat_data.label }}</div>
                        <div class="flex-1 {{ heat }} rounded px-2 py-1">
                            <div class="flex justify-between text-xs">
                                <span class="text-gray-200">{{ count }} IOCs</span>
                                <span class="text-gray-400">{{ cat_data.severity }}</span>
                            </div>
                        </div>
                    </div>
                    {% endfor %}
                </div>
                <div class="mt-3 text-xs text-gray-500 flex gap-4">
                    <span class="heat-low px-2 rounded">Low (1-3)</span>
                    <span class="heat-med px-2 rounded">Med (4-10)</span>
                    <span class="heat-high px-2 rounded">High (11-20)</span>
                    <span class="heat-crit px-2 rounded">Crit (20+)</span>
                </div>
            </div>

            <!-- MITRE ATT&CK Coverage -->
            <div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <h2 class="text-lg font-bold text-blue-400 mb-3 border-b border-gray-700 pb-2">
                    MITRE ATT&CK/ATLAS Coverage
                    <span class="text-sm font-normal text-blue-300 ml-2">
                        {{ "%.0f"|format(mitre_coverage.coverage_percent) }}%
                    </span>
                </h2>
                <div class="overflow-y-auto max-h-64">
                    <table class="w-full text-xs">
                        <thead>
                            <tr class="text-gray-400 border-b border-gray-700">
                                <th class="text-left py-1">T-Code</th>
                                <th class="text-left py-1">Name</th>
                                <th class="text-left py-1">Tactic</th>
                                <th class="text-right py-1">Scenarios</th>
                                <th class="text-right py-1">Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for tid, tech in mitre_coverage.techniques.items() %}
                            <tr class="border-b border-gray-800 hover:bg-gray-700">
                                <td class="py-1 font-mono text-blue-300">{{ tid }}</td>
                                <td class="py-1 text-gray-300">{{ tech.name }}</td>
                                <td class="py-1 text-gray-400">{{ tech.tactic }}</td>
                                <td class="py-1 text-right text-gray-300">{{ tech.scenario_count }}</td>
                                <td class="py-1 text-right">
                                    {% if tech.detected %}
                                    <span class="text-green-400">Covered</span>
                                    {% else %}
                                    <span class="text-red-400">Gap</span>
                                    {% endif %}
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Panel 4: Recent IOC Feed -->
        <div class="bg-gray-800 rounded-lg p-4 border border-gray-700 mb-6">
            <div class="flex justify-between items-center mb-3 border-b border-gray-700 pb-2">
                <h2 class="text-lg font-bold text-red-400">Recent IOC Feed</h2>
                <div class="flex gap-2">
                    <button onclick="location.href='/threat-intel/api/iocs/extract'" class="text-xs bg-orange-800 hover:bg-orange-700 px-2 py-1 rounded transition">
                        Extract Now
                    </button>
                    <span class="text-xs text-gray-500">Last 100 indicators</span>
                </div>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-xs font-mono">
                    <thead>
                        <tr class="text-gray-400 border-b border-gray-700">
                            <th class="text-left py-1 px-2">Time</th>
                            <th class="text-left py-1 px-2">Type</th>
                            <th class="text-left py-1 px-2">Payload Preview</th>
                            <th class="text-left py-1 px-2">Threat</th>
                            <th class="text-left py-1 px-2">Severity</th>
                            <th class="text-right py-1 px-2">ML Score</th>
                            <th class="text-right py-1 px-2">Sightings</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for ioc in recent_iocs %}
                        {% set sev_color = 'text-red-400' if ioc.severity == 'critical' else 'text-orange-400' if ioc.severity == 'high' else 'text-yellow-400' if ioc.severity == 'medium' else 'text-gray-400' %}
                        <tr class="border-b border-gray-800 hover:bg-gray-700">
                            <td class="py-1 px-2 text-gray-400">{{ ioc.first_seen[:19] }}</td>
                            <td class="py-1 px-2 text-cyan-300">{{ ioc.type }}</td>
                            <td class="py-1 px-2 text-gray-200 max-w-xs truncate">{{ ioc.value[:80] }}</td>
                            <td class="py-1 px-2 text-purple-300">{{ ioc.threat_type }}</td>
                            <td class="py-1 px-2 {{ sev_color }}">{{ ioc.severity }}</td>
                            <td class="py-1 px-2 text-right text-cyan-300">{{ "%.2f"|format(ioc.ml_score) if ioc.ml_score else '-' }}</td>
                            <td class="py-1 px-2 text-right text-gray-300">{{ ioc.sighting_count }}</td>
                        </tr>
                        {% endfor %}
                        {% if not recent_iocs %}
                        <tr>
                            <td colspan="7" class="py-4 text-center text-gray-500">
                                No IOCs extracted yet. Send a malicious message via /api/chat or click "Extract Now".
                            </td>
                        </tr>
                        {% endif %}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Panel 5: Detection Method Breakdown -->
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <h2 class="text-lg font-bold text-green-400 mb-3 border-b border-gray-700 pb-2">Detection Methods</h2>
                <div class="space-y-2">
                    {% for method, count in stats.by_detection_method.items() %}
                    {% set pct = (count / stats.total_iocs * 100) if stats.total_iocs > 0 else 0 %}
                    <div>
                        <div class="flex justify-between text-xs mb-1">
                            <span class="text-gray-300">{{ method }}</span>
                            <span class="text-green-300">{{ count }} ({{ "%.0f"|format(pct) }}%)</span>
                        </div>
                        <div class="w-full bg-gray-700 rounded h-2">
                            <div class="bg-green-500 rounded h-2" style="width: {{ pct }}%"></div>
                        </div>
                    </div>
                    {% endfor %}
                </div>
            </div>

            <div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <h2 class="text-lg font-bold text-purple-400 mb-3 border-b border-gray-700 pb-2">Severity Distribution</h2>
                <div class="space-y-2">
                    {% set severity_colors = {'critical': 'bg-red-500', 'high': 'bg-orange-500', 'medium': 'bg-yellow-500', 'low': 'bg-green-500'} %}
                    {% for sev in ['critical', 'high', 'medium', 'low'] %}
                    {% set count = stats.by_severity.get(sev, 0) %}
                    {% set pct = (count / stats.total_iocs * 100) if stats.total_iocs > 0 else 0 %}
                    <div>
                        <div class="flex justify-between text-xs mb-1">
                            <span class="text-gray-300">{{ sev|upper }}</span>
                            <span class="text-gray-200">{{ count }}</span>
                        </div>
                        <div class="w-full bg-gray-700 rounded h-2">
                            <div class="{{ severity_colors.get(sev, 'bg-gray-500') }} rounded h-2" style="width: {{ pct }}%"></div>
                        </div>
                    </div>
                    {% endfor %}
                </div>
            </div>
        </div>

        <footer class="mt-6 text-center text-xs text-gray-600">
            Sentinel Platform v{{ version }} // Threat Intel Module v1.0.0 // Auto-refresh: 30s
        </footer>
    </div>
</body>
</html>
"""
