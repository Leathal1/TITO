package dataflow

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{TITLE}}</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif;
            background: #060a1a;
            color: #e8edf5;
            overflow: hidden;
            position: relative;
        }

        /* Animated gradient background */
        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: radial-gradient(ellipse at top, #1a1f3a 0%, #0a0e27 50%, #050810 100%);
            z-index: -2;
        }

        /* Animated grid lines */
        body::after {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-image: 
                linear-gradient(rgba(88, 166, 255, 0.03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(88, 166, 255, 0.03) 1px, transparent 1px);
            background-size: 50px 50px;
            animation: gridPulse 20s ease-in-out infinite;
            z-index: -1;
            opacity: 0.4;
        }

        @keyframes gridPulse {
            0%, 100% { opacity: 0.2; transform: scale(1); }
            50% { opacity: 0.4; transform: scale(1.05); }
        }

        #container {
            display: flex;
            height: 100vh;
            flex-direction: column;
        }

        /* Header bar */
        #header {
            background: rgba(13, 17, 35, 0.85);
            backdrop-filter: blur(20px) saturate(180%);
            border-bottom: 1px solid rgba(88, 166, 255, 0.2);
            padding: 16px 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            z-index: 1000;
            box-shadow: 0 4px 24px rgba(0, 0, 0, 0.4);
        }

        .header-left {
            display: flex;
            align-items: center;
            gap: 16px;
        }

        .header-logo {
            font-size: 24px;
            font-weight: 700;
            background: linear-gradient(135deg, #4488ff 0%, #2860cc 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            letter-spacing: -0.5px;
        }

        .header-repo {
            font-size: 14px;
            color: #8b949e;
            font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
        }

        .header-center {
            display: flex;
            gap: 24px;
            align-items: center;
        }

        .stat-pill {
            display: flex;
            align-items: center;
            gap: 8px;
            background: rgba(22, 27, 34, 0.6);
            padding: 6px 14px;
            border-radius: 20px;
            border: 1px solid rgba(88, 166, 255, 0.2);
            font-size: 13px;
        }

        .stat-pill-label {
            color: #8b949e;
        }

        .stat-pill-value {
            color: #e6edf3;
            font-weight: 600;
        }

        .header-right {
            display: flex;
            gap: 8px;
        }

        .header-btn {
            background: rgba(88, 166, 255, 0.1);
            border: 1px solid rgba(88, 166, 255, 0.3);
            color: #58a6ff;
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 12px;
            font-weight: 500;
            transition: all 0.2s ease;
        }

        .header-btn:hover {
            background: rgba(88, 166, 255, 0.2);
            border-color: rgba(88, 166, 255, 0.5);
            transform: translateY(-1px);
        }

        .header-btn:active {
            transform: translateY(0);
        }

        /* Main content area */
        #main {
            display: flex;
            flex: 1;
            overflow: hidden;
        }

        #diagram-container {
            flex: 1;
            position: relative;
        }

        svg {
            width: 100%;
            height: 100%;
        }

        /* Glassmorphism nodes */
        .node circle {
            stroke-width: 2.5px;
            cursor: pointer;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            filter: drop-shadow(0 0 0px transparent);
        }

        .node:hover circle {
            stroke-width: 4px;
            filter: drop-shadow(0 0 12px currentColor) brightness(1.2);
            transform: scale(1.1);
        }

        .node.selected circle {
            stroke-width: 5px;
            filter: drop-shadow(0 0 20px currentColor) brightness(1.3);
        }

        .node text {
            font-size: 11px;
            font-weight: 500;
            pointer-events: none;
            fill: #e6edf3;
            text-shadow: 0 2px 8px rgba(0, 0, 0, 0.8);
        }

        .node-icon {
            font-size: 20px;
            text-anchor: middle;
            dominant-baseline: central;
            pointer-events: none;
        }

        /* Risk-based color coding with glows */
        .node.critical circle {
            fill: rgba(255, 39, 64, 0.2);
            stroke: #ff2740;
            backdrop-filter: blur(10px);
        }

        .node.critical:hover circle,
        .node.critical.selected circle {
            filter: drop-shadow(0 0 20px #ff2740) brightness(1.3);
        }

        .node.high circle {
            fill: rgba(255, 140, 66, 0.2);
            stroke: #ff8c42;
        }

        .node.high:hover circle,
        .node.high.selected circle {
            filter: drop-shadow(0 0 20px #ff8c00) brightness(1.3);
        }

        .node.medium circle {
            fill: rgba(255, 210, 63, 0.2);
            stroke: #ffd23f;
        }

        .node.medium:hover circle,
        .node.medium.selected circle {
            filter: drop-shadow(0 0 20px #ffd700) brightness(1.3);
        }

        .node.low circle {
            fill: rgba(0, 212, 170, 0.2);
            stroke: #00d4aa;
        }

        .node.low:hover circle,
        .node.low.selected circle {
            filter: drop-shadow(0 0 20px #3fb950) brightness(1.3);
        }

        .node.info circle {
            fill: rgba(88, 166, 255, 0.2);
            stroke: #58a6ff;
        }

        .node.info:hover circle,
        .node.info.selected circle {
            filter: drop-shadow(0 0 20px #58a6ff) brightness(1.3);
        }

        /* Critical node pulse animation */
        @keyframes criticalPulse {
            0%, 100% { 
                filter: drop-shadow(0 0 15px #f85149);
                opacity: 1;
            }
            50% { 
                filter: drop-shadow(0 0 25px #f85149);
                opacity: 0.8;
            }
        }

        .node.critical circle {
            animation: criticalPulse 2s ease-in-out infinite;
        }

        /* Edges with particle effects */
        .link {
            fill: none;
            stroke-width: 2px;
            transition: all 0.3s ease;
            opacity: 0.6;
        }

        .link.normal {
            stroke: rgba(88, 166, 255, 0.3);
        }

        .link.sensitive {
            stroke: rgba(255, 140, 0, 0.5);
            stroke-dasharray: 5, 5;
            animation: dashFlow 20s linear infinite;
        }

        .link.encrypted {
            stroke: rgba(63, 185, 80, 0.4);
        }

        .link:hover {
            stroke-width: 3.5px;
            opacity: 1;
        }

        @keyframes dashFlow {
            to { stroke-dashoffset: -200; }
        }

        /* Particle effects */
        .particle {
            fill: currentColor;
            opacity: 0.8;
        }

        /* Trust boundaries */
        .trust-boundary {
            fill: none;
            stroke-width: 2px;
            stroke-dasharray: 8, 4;
            opacity: 0.4;
            filter: drop-shadow(0 0 8px currentColor);
        }

        .trust-boundary.internet {
            stroke: #f85149;
        }

        .trust-boundary.dmz {
            stroke: #ff8c00;
        }

        .trust-boundary.internal {
            stroke: #58a6ff;
        }

        .trust-boundary.secure {
            stroke: #3fb950;
        }

        /* Sidebar */
        #sidebar {
            width: 380px;
            background: rgba(13, 17, 35, 0.85);
            backdrop-filter: blur(20px) saturate(180%);
            border-left: 1px solid rgba(88, 166, 255, 0.2);
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            box-shadow: -4px 0 24px rgba(0, 0, 0, 0.4);
        }

        #sidebar::-webkit-scrollbar {
            width: 8px;
        }

        #sidebar::-webkit-scrollbar-track {
            background: rgba(0, 0, 0, 0.2);
        }

        #sidebar::-webkit-scrollbar-thumb {
            background: rgba(88, 166, 255, 0.3);
            border-radius: 4px;
        }

        #sidebar::-webkit-scrollbar-thumb:hover {
            background: rgba(88, 166, 255, 0.5);
        }

        .sidebar-section {
            padding: 20px;
            border-bottom: 1px solid rgba(48, 54, 61, 0.5);
        }

        .sidebar-section.collapsible h3 {
            cursor: pointer;
            user-select: none;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .sidebar-section.collapsible h3::after {
            content: '▼';
            font-size: 10px;
            transition: transform 0.2s ease;
        }

        .sidebar-section.collapsible.collapsed h3::after {
            transform: rotate(-90deg);
        }

        .sidebar-section.collapsible.collapsed .section-content {
            display: none;
        }

        .sidebar-section h3 {
            font-size: 14px;
            font-weight: 600;
            color: #58a6ff;
            margin-bottom: 16px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .search-box {
            width: 100%;
            background: rgba(22, 27, 34, 0.6);
            border: 1px solid rgba(88, 166, 255, 0.3);
            border-radius: 6px;
            padding: 10px 12px;
            color: #e6edf3;
            font-size: 13px;
            outline: none;
            transition: all 0.2s ease;
        }

        .search-box:focus {
            border-color: #58a6ff;
            background: rgba(22, 27, 34, 0.8);
        }

        .search-box::placeholder {
            color: #8b949e;
        }

        /* Node detail panel */
        #node-detail {
            max-height: 600px;
            overflow-y: auto;
        }

        #node-detail::-webkit-scrollbar {
            width: 6px;
        }

        #node-detail::-webkit-scrollbar-thumb {
            background: rgba(88, 166, 255, 0.3);
            border-radius: 3px;
        }

        .detail-empty {
            color: #8b949e;
            font-size: 13px;
            font-style: italic;
            text-align: center;
            padding: 24px;
        }

        .detail-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 16px;
            padding-bottom: 12px;
            border-bottom: 1px solid rgba(48, 54, 61, 0.5);
        }

        .detail-icon {
            font-size: 32px;
        }

        .detail-title {
            flex: 1;
        }

        .detail-title h4 {
            font-size: 16px;
            color: #e6edf3;
            margin-bottom: 4px;
        }

        .detail-title .detail-type {
            font-size: 12px;
            color: #8b949e;
        }

        .detail-row {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            font-size: 13px;
            border-bottom: 1px solid rgba(48, 54, 61, 0.3);
        }

        .detail-row:last-child {
            border-bottom: none;
        }

        .detail-label {
            color: #8b949e;
            font-weight: 500;
        }

        .detail-value {
            color: #e6edf3;
            font-weight: 600;
            text-align: right;
        }

        .risk-meter {
            width: 100%;
            height: 24px;
            background: rgba(22, 27, 34, 0.6);
            border-radius: 12px;
            overflow: hidden;
            margin-top: 8px;
            position: relative;
        }

        .risk-meter-fill {
            height: 100%;
            border-radius: 12px;
            transition: width 0.5s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 11px;
            font-weight: 700;
            color: white;
            text-shadow: 0 1px 2px rgba(0, 0, 0, 0.5);
        }

        .risk-meter-fill.critical {
            background: linear-gradient(90deg, #f85149 0%, #ff6b6b 100%);
        }

        .risk-meter-fill.high {
            background: linear-gradient(90deg, #ff8c00 0%, #ffa500 100%);
        }

        .risk-meter-fill.medium {
            background: linear-gradient(90deg, #ffd700 0%, #ffed4e 100%);
        }

        .risk-meter-fill.low {
            background: linear-gradient(90deg, #3fb950 0%, #56d364 100%);
        }

        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 600;
            margin: 4px 4px 4px 0;
            border: 1px solid;
        }

        .badge.stride {
            background: rgba(88, 166, 255, 0.15);
            border-color: #58a6ff;
            color: #58a6ff;
        }

        .badge.maestro {
            background: rgba(137, 87, 229, 0.15);
            border-color: #8957e5;
            color: #bc8cff;
        }

        .badge.mitre {
            background: rgba(248, 81, 73, 0.15);
            border-color: #f85149;
            color: #ff7b72;
        }

        .badge.severity-critical {
            background: rgba(248, 81, 73, 0.2);
            border-color: #f85149;
            color: #ff7b72;
        }

        .badge.severity-high {
            background: rgba(255, 140, 0, 0.2);
            border-color: #ff8c00;
            color: #ffa657;
        }

        .badge.severity-medium {
            background: rgba(255, 215, 0, 0.2);
            border-color: #ffd700;
            color: #ffed4e;
        }

        .badge.severity-low {
            background: rgba(63, 185, 80, 0.2);
            border-color: #3fb950;
            color: #56d364;
        }

        /* Threat list */
        .threat-item {
            background: rgba(22, 27, 34, 0.4);
            border-left: 3px solid;
            padding: 12px;
            margin: 8px 0;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .threat-item:hover {
            background: rgba(22, 27, 34, 0.7);
            transform: translateX(4px);
        }

        .threat-item.critical { border-color: #f85149; }
        .threat-item.high { border-color: #ff8c00; }
        .threat-item.medium { border-color: #ffd700; }
        .threat-item.low { border-color: #3fb950; }

        .threat-title {
            font-size: 13px;
            font-weight: 600;
            color: #e6edf3;
            margin-bottom: 6px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .threat-desc {
            font-size: 12px;
            color: #8b949e;
            line-height: 1.5;
            margin-bottom: 8px;
        }

        .threat-node {
            font-size: 11px;
            color: #58a6ff;
            font-family: 'SF Mono', Monaco, monospace;
        }

        /* MAESTRO layer chart */
        .layer-bar {
            display: flex;
            align-items: center;
            margin: 10px 0;
        }

        .layer-label {
            width: 120px;
            font-size: 12px;
            color: #8b949e;
            font-weight: 500;
        }

        .layer-bar-bg {
            flex: 1;
            height: 24px;
            background: rgba(22, 27, 34, 0.6);
            border-radius: 4px;
            overflow: hidden;
            position: relative;
        }

        .layer-bar-fill {
            height: 100%;
            background: linear-gradient(90deg, #58a6ff 0%, #79c0ff 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 11px;
            font-weight: 700;
            color: white;
            transition: width 0.5s ease;
        }

        /* MITRE ATT&CK list */
        .mitre-item {
            display: inline-block;
            background: rgba(248, 81, 73, 0.1);
            border: 1px solid rgba(248, 81, 73, 0.3);
            padding: 6px 10px;
            margin: 4px;
            border-radius: 6px;
            font-size: 12px;
            font-family: 'SF Mono', Monaco, monospace;
            color: #ff7b72;
            transition: all 0.2s ease;
            cursor: pointer;
        }

        .mitre-item:hover {
            background: rgba(248, 81, 73, 0.2);
            border-color: #f85149;
            transform: translateY(-2px);
        }

        /* Minimap */
        #minimap {
            position: absolute;
            bottom: 80px;
            right: 20px;
            width: 200px;
            height: 150px;
            background: rgba(13, 17, 35, 0.9);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(88, 166, 255, 0.3);
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 24px rgba(0, 0, 0, 0.6);
        }

        #minimap svg {
            width: 100%;
            height: 100%;
        }

        #minimap .viewport-rect {
            fill: rgba(88, 166, 255, 0.1);
            stroke: #58a6ff;
            stroke-width: 2;
        }

        /* Zoom controls */
        #zoom-controls {
            position: absolute;
            bottom: 20px;
            right: 20px;
            display: flex;
            flex-direction: column;
            gap: 8px;
            background: rgba(13, 17, 35, 0.9);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(88, 166, 255, 0.3);
            border-radius: 8px;
            padding: 8px;
            box-shadow: 0 4px 24px rgba(0, 0, 0, 0.6);
        }

        .zoom-btn {
            width: 36px;
            height: 36px;
            background: rgba(88, 166, 255, 0.1);
            border: 1px solid rgba(88, 166, 255, 0.3);
            border-radius: 6px;
            color: #58a6ff;
            font-size: 18px;
            font-weight: 700;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.2s ease;
        }

        .zoom-btn:hover {
            background: rgba(88, 166, 255, 0.2);
            border-color: #58a6ff;
            transform: scale(1.1);
        }

        .zoom-btn:active {
            transform: scale(0.95);
        }

        /* Footer */
        #footer {
            background: rgba(13, 17, 35, 0.85);
            backdrop-filter: blur(20px);
            border-top: 1px solid rgba(88, 166, 255, 0.2);
            padding: 12px 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-size: 12px;
            color: #8b949e;
        }

        .footer-brand {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .footer-brand a {
            color: #58a6ff;
            text-decoration: none;
            font-weight: 600;
        }

        .footer-brand a:hover {
            text-decoration: underline;
        }

        .footer-timestamp {
            font-family: 'SF Mono', Monaco, monospace;
        }

        /* Tooltip */
        .tooltip {
            position: absolute;
            background: rgba(13, 17, 35, 0.98);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(88, 166, 255, 0.4);
            border-radius: 8px;
            padding: 12px 16px;
            font-size: 12px;
            pointer-events: none;
            opacity: 0;
            transition: opacity 0.2s ease;
            max-width: 320px;
            z-index: 10000;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.6);
        }

        .tooltip.show {
            opacity: 1;
        }

        .tooltip-title {
            font-weight: 600;
            color: #e6edf3;
            margin-bottom: 8px;
            font-size: 13px;
        }

        .tooltip-row {
            display: flex;
            justify-content: space-between;
            margin: 4px 0;
        }

        .tooltip-label {
            color: #8b949e;
        }

        .tooltip-value {
            color: #e6edf3;
            font-weight: 500;
        }

        /* Mitigation list */
        .mitigation-item {
            background: rgba(63, 185, 80, 0.1);
            border-left: 3px solid #3fb950;
            padding: 10px;
            margin: 8px 0;
            border-radius: 6px;
            font-size: 12px;
        }

        .mitigation-title {
            font-weight: 600;
            color: #56d364;
            margin-bottom: 4px;
        }

        .mitigation-desc {
            color: #8b949e;
            line-height: 1.4;
        }

        /* Semgrep findings */
        .semgrep-finding {
            background: rgba(248, 81, 73, 0.1);
            border-left: 3px solid #f85149;
            padding: 10px;
            margin: 8px 0;
            border-radius: 6px;
            font-size: 12px;
        }

        .semgrep-title {
            font-weight: 600;
            color: #ff7b72;
            margin-bottom: 4px;
            font-family: 'SF Mono', Monaco, monospace;
        }

        .semgrep-location {
            color: #8b949e;
            font-size: 11px;
            font-family: 'SF Mono', Monaco, monospace;
        }

        /* Loading animation */
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .fade-in {
            animation: fadeIn 0.5s ease;
        }

        /* Responsive tweaks */
        @media (max-width: 1400px) {
            #sidebar {
                width: 320px;
            }
            .stat-pill {
                font-size: 12px;
                padding: 5px 12px;
            }
        }
    </style>
</head>
<body>
    <div id="container">
        <!-- Header -->
        <div id="header">
            <div class="header-left">
                <div class="header-logo">🛡️ TITO</div>
                <div class="header-repo" id="repo-name"></div>
            </div>
            <div class="header-center" id="header-stats"></div>
            <div class="header-right">
                <button class="header-btn" onclick="exportSVG()">📥 Export SVG</button>
                <button class="header-btn" onclick="toggleLabels()">🏷️ Labels</button>
                <button class="header-btn" onclick="toggleBoundaries()">🔒 Boundaries</button>
                <button class="header-btn" onclick="toggleAnimation()">✨ Animation</button>
            </div>
        </div>

        <!-- Main content -->
        <div id="main">
            <div id="diagram-container">
                <svg id="svg"></svg>
                
                <!-- Minimap -->
                <div id="minimap">
                    <svg id="minimap-svg"></svg>
                </div>

                <!-- Zoom controls -->
                <div id="zoom-controls">
                    <button class="zoom-btn" onclick="zoomIn()" title="Zoom In">+</button>
                    <button class="zoom-btn" onclick="resetZoom()" title="Reset Zoom">⟲</button>
                    <button class="zoom-btn" onclick="zoomOut()" title="Zoom Out">−</button>
                </div>
            </div>

            <!-- Sidebar -->
            <div id="sidebar">
                <!-- Search -->
                <div class="sidebar-section">
                    <input type="text" class="search-box" id="search-box" placeholder="🔍 Search threats, nodes, techniques...">
                </div>

                <!-- Node Details -->
                <div class="sidebar-section">
                    <h3>📍 Selected Component</h3>
                    <div id="node-detail">
                        <div class="detail-empty">Click on a node to see details</div>
                    </div>
                </div>

                <!-- Threats -->
                <div class="sidebar-section collapsible">
                    <h3 onclick="toggleSection(this)">⚠️ Threats</h3>
                    <div class="section-content" id="threats-list"></div>
                </div>

                <!-- MAESTRO Layers -->
                <div class="sidebar-section collapsible">
                    <h3 onclick="toggleSection(this)">🎯 MAESTRO Layers</h3>
                    <div class="section-content" id="maestro-layers"></div>
                </div>

                <!-- MITRE ATT&CK -->
                <div class="sidebar-section collapsible">
                    <h3 onclick="toggleSection(this)">🎯 MITRE ATT&CK</h3>
                    <div class="section-content" id="mitre-list"></div>
                </div>
            </div>
        </div>

        <!-- Footer -->
        <div id="footer">
            <div class="footer-brand">
                Generated by <a href="https://tito.security" target="_blank">TITO v2.1.0</a> • Threat Intelligence & Tactical Operations
            </div>
            <div class="footer-timestamp" id="timestamp"></div>
        </div>
    </div>

    <!-- Tooltip -->
    <div class="tooltip" id="tooltip"></div>

    <script>
        // Data from Go template
        const data = {{DIAGRAM_DATA}};

        // Configuration
        let showLabels = true;
        let showBoundaries = true;
        let animationEnabled = true;
        let selectedNode = null;

        // Node type icons
        const nodeIcons = {
            'API': '🔌',
            'Database': '🗄️',
            'Auth': '🔐',
            'File': '📁',
            'External': '🌐',
            'Cache': '⚡',
            'Queue': '📨',
            'Crypto': '🔑',
            'Service': '⚙️',
            'Frontend': '💻',
            'Backend': '🖥️',
            'Storage': '💾',
            'Network': '🌐',
            'default': '🔵'
        };

        // Setup SVG
        const container = document.getElementById('diagram-container');
        const width = container.clientWidth;
        const height = container.clientHeight;
        const svg = d3.select("#svg");
        const g = svg.append("g");

        // Zoom behavior
        let currentTransform = d3.zoomIdentity;
        const zoom = d3.zoom()
            .scaleExtent([0.1, 8])
            .on("zoom", (event) => {
                currentTransform = event.transform;
                g.attr("transform", event.transform);
                updateMinimap();
            });
        svg.call(zoom);

        // Force simulation
        const simulation = d3.forceSimulation(data.nodes)
            .force("link", d3.forceLink(data.edges).id(d => d.id).distance(d => 150))
            .force("charge", d3.forceManyBody().strength(-800))
            .force("center", d3.forceCenter(width / 2, height / 2))
            .force("collision", d3.forceCollide().radius(60))
            .force("x", d3.forceX(width / 2).strength(0.05))
            .force("y", d3.forceY(height / 2).strength(0.05));

        // Draw trust boundaries using convex hulls around member nodes
        const boundariesGroup = g.append("g").attr("class", "boundaries");
        const boundaryHulls = [];
        if (data.trustBoundaries) {
            data.trustBoundaries.forEach(boundary => {
                const path = boundariesGroup.append("path")
                    .attr("class", "trust-boundary " + boundary.zone)
                    .attr("fill", boundary.color || "#888")
                    .attr("fill-opacity", 0.08)
                    .attr("stroke", boundary.color || "#888")
                    .attr("stroke-opacity", 0.4)
                    .attr("stroke-width", 2)
                    .attr("stroke-dasharray", "8,4");

                const label = boundariesGroup.append("text")
                    .attr("class", "boundary-label")
                    .attr("fill", boundary.color || "#888")
                    .attr("fill-opacity", 0.7)
                    .attr("font-size", "12px")
                    .attr("font-weight", "bold")
                    .text(boundary.name);

                boundaryHulls.push({ boundary, path, label, nodeIds: new Set(boundary.nodes) });
            });
        }

        function updateBoundaryHulls() {
            boundaryHulls.forEach(({ boundary, path, label, nodeIds }) => {
                const points = [];
                data.nodes.forEach(n => {
                    if (nodeIds.has(n.id) && n.x != null && n.y != null) {
                        points.push([n.x, n.y]);
                    }
                });
                if (points.length < 2) {
                    path.attr("d", "");
                    return;
                }
                // Expand hull with padding
                const hull = d3.polygonHull(points);
                if (!hull) {
                    // Collinear points — draw a rounded rect around them
                    const xs = points.map(p => p[0]), ys = points.map(p => p[1]);
                    const pad = 40;
                    const x1 = Math.min(...xs) - pad, y1 = Math.min(...ys) - pad;
                    const x2 = Math.max(...xs) + pad, y2 = Math.max(...ys) + pad;
                    path.attr("d", "M" + x1 + "," + y1 + "L" + x2 + "," + y1 + "L" + x2 + "," + y2 + "L" + x1 + "," + y2 + "Z");
                    label.attr("x", x1 + 5).attr("y", y1 - 5);
                    return;
                }
                // Expand hull outward by padding
                const pad = 40;
                const cx = d3.mean(hull, p => p[0]);
                const cy = d3.mean(hull, p => p[1]);
                const expanded = hull.map(p => {
                    const dx = p[0] - cx, dy = p[1] - cy;
                    const dist = Math.sqrt(dx*dx + dy*dy) || 1;
                    return [p[0] + dx/dist * pad, p[1] + dy/dist * pad];
                });
                path.attr("d", "M" + expanded.map(p => p.join(",")).join("L") + "Z");
                // Position label at top of hull
                const topPt = expanded.reduce((a, b) => a[1] < b[1] ? a : b);
                label.attr("x", topPt[0]).attr("y", topPt[1] - 8);
            });
        }

        // Draw edges
        const linkGroup = g.append("g");
        const link = linkGroup.selectAll("path")
            .data(data.edges)
            .enter().append("path")
            .attr("class", d => {
                let cls = "link";
                if (d.sensitive) cls += " sensitive";
                if (d.encrypted) cls += " encrypted";
                if (!d.sensitive && !d.encrypted) cls += " normal";
                return cls;
            });

        // Particle effects on edges
        const particlesGroup = g.append("g");
        
        function createParticles() {
            if (!animationEnabled) return;
            
            data.edges.forEach((edge, i) => {
                if (Math.random() > 0.3) return; // Don't animate all edges
                
                const particle = particlesGroup.append("circle")
                    .attr("class", "particle")
                    .attr("r", 3)
                    .style("fill", edge.sensitive ? "#ff8c00" : "#58a6ff");

                function animateParticle() {
                    const source = edge.source;
                    const target = edge.target;
                    
                    particle
                        .attr("cx", source.x)
                        .attr("cy", source.y)
                        .transition()
                        .duration(3000 + Math.random() * 2000)
                        .ease(d3.easeLinear)
                        .attr("cx", target.x)
                        .attr("cy", target.y)
                        .on("end", animateParticle);
                }
                
                setTimeout(animateParticle, Math.random() * 3000);
            });
        }

        // Draw nodes
        const nodeGroup = g.append("g");
        const node = nodeGroup.selectAll("g")
            .data(data.nodes)
            .enter().append("g")
            .attr("class", d => {
                const risk = (d.riskLevel || 'info').toLowerCase();
                return "node " + risk;
            })
            .call(d3.drag()
                .on("start", dragstarted)
                .on("drag", dragged)
                .on("end", dragended));

        // Node circles
        node.append("circle")
            .attr("r", 30);

        // Node icons
        node.append("text")
            .attr("class", "node-icon")
            .text(d => {
                const type = d.type || 'default';
                return nodeIcons[type] || nodeIcons['default'];
            });

        // Node labels
        node.append("text")
            .attr("dy", 48)
            .attr("text-anchor", "middle")
            .text(d => d.label ? d.label.substring(0, 20) : d.id)
            .style("display", showLabels ? "block" : "none");

        // Node interactions
        node.on("click", (event, d) => {
            event.stopPropagation();
            selectNode(d);
        });

        // Tooltip
        const tooltip = d3.select("#tooltip");
        
        node.on("mouseover", (event, d) => {
            if (selectedNode === d) return;
            
            const threats = (d.threats || []).length;
            const risk = (d.riskLevel || 'info').toLowerCase();
            
            tooltip
                .style("left", (event.pageX + 15) + "px")
                .style("top", (event.pageY + 15) + "px")
                .html(` + "`" + `
                    <div class="tooltip-title">${d.label || d.id}</div>
                    <div class="tooltip-row">
                        <span class="tooltip-label">Type:</span>
                        <span class="tooltip-value">${d.type || 'Unknown'}</span>
                    </div>
                    <div class="tooltip-row">
                        <span class="tooltip-label">Risk:</span>
                        <span class="tooltip-value" style="color: ${getRiskColor(risk)}">${risk.toUpperCase()}</span>
                    </div>
                    <div class="tooltip-row">
                        <span class="tooltip-label">Threats:</span>
                        <span class="tooltip-value">${threats}</span>
                    </div>
                ` + "`" + `)
                .classed("show", true);
        }).on("mouseout", () => {
            tooltip.classed("show", false);
        });

        // Edge tooltips
        link.on("mouseover", (event, d) => {
            const sourceLabel = d.source.label || d.source.id;
            const targetLabel = d.target.label || d.target.id;
            
            tooltip
                .style("left", (event.pageX + 15) + "px")
                .style("top", (event.pageY + 15) + "px")
                .html(` + "`" + `
                    <div class="tooltip-title">Data Flow</div>
                    <div class="tooltip-row">
                        <span class="tooltip-label">From:</span>
                        <span class="tooltip-value">${sourceLabel}</span>
                    </div>
                    <div class="tooltip-row">
                        <span class="tooltip-label">To:</span>
                        <span class="tooltip-value">${targetLabel}</span>
                    </div>
                    <div class="tooltip-row">
                        <span class="tooltip-label">Sensitive:</span>
                        <span class="tooltip-value">${d.sensitive ? '⚠️ Yes' : '✓ No'}</span>
                    </div>
                    <div class="tooltip-row">
                        <span class="tooltip-label">Encrypted:</span>
                        <span class="tooltip-value">${d.encrypted ? '🔒 Yes' : '🔓 No'}</span>
                    </div>
                ` + "`" + `)
                .classed("show", true);
        }).on("mouseout", () => {
            tooltip.classed("show", false);
        });

        // Click background to deselect
        svg.on("click", () => {
            if (selectedNode) {
                selectedNode = null;
                node.classed("selected", false);
                showEmptyDetail();
            }
        });

        // Simulation tick
        simulation.on("tick", () => {
            link.attr("d", d => {
                const dx = d.target.x - d.source.x;
                const dy = d.target.y - d.source.y;
                const dr = Math.sqrt(dx * dx + dy * dy) * 1.5;
                return ` + "`M${d.source.x},${d.source.y}A${dr},${dr} 0 0,1 ${d.target.x},${d.target.y}`" + `;
            });

            node.attr("transform", d => ` + "`translate(${d.x},${d.y})`" + `);

            // Update trust boundary hulls to follow nodes
            updateBoundaryHulls();
        });

        // Wait for simulation to stabilize, then create particles
        setTimeout(() => {
            createParticles();
            simulation.alpha(0.3).restart();
        }, 2000);

        // Minimap
        const minimapSvg = d3.select("#minimap-svg");
        const minimapG = minimapSvg.append("g");
        const minimapScale = 0.1;

        // Minimap nodes
        minimapG.selectAll("circle")
            .data(data.nodes)
            .enter().append("circle")
            .attr("r", 3)
            .attr("fill", d => getRiskColor((d.riskLevel || 'info').toLowerCase()));

        // Minimap viewport rect
        const viewportRect = minimapG.append("rect")
            .attr("class", "viewport-rect");

        function updateMinimap() {
            minimapG.selectAll("circle")
                .attr("cx", d => d.x * minimapScale)
                .attr("cy", d => d.y * minimapScale);

            const scale = currentTransform.k;
            const vw = width / scale * minimapScale;
            const vh = height / scale * minimapScale;
            const vx = -currentTransform.x / scale * minimapScale;
            const vy = -currentTransform.y / scale * minimapScale;

            viewportRect
                .attr("x", vx)
                .attr("y", vy)
                .attr("width", vw)
                .attr("height", vh);
        }

        simulation.on("tick", updateMinimap);

        // Functions
        function dragstarted(event, d) {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }

        function dragged(event, d) {
            d.fx = event.x;
            d.fy = event.y;
        }

        function dragended(event, d) {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }

        function zoomIn() {
            svg.transition().duration(300).call(zoom.scaleBy, 1.3);
        }

        function zoomOut() {
            svg.transition().duration(300).call(zoom.scaleBy, 0.7);
        }

        function resetZoom() {
            svg.transition().duration(750).call(zoom.transform, d3.zoomIdentity);
        }

        function toggleLabels() {
            showLabels = !showLabels;
            node.selectAll("text:not(.node-icon)")
                .style("display", showLabels ? "block" : "none");
        }

        function toggleBoundaries() {
            showBoundaries = !showBoundaries;
            boundariesGroup.style("display", showBoundaries ? "block" : "none");
        }

        function toggleAnimation() {
            animationEnabled = !animationEnabled;
            if (animationEnabled) {
                particlesGroup.selectAll("*").remove();
                createParticles();
            } else {
                particlesGroup.selectAll("*").remove();
            }
        }

        function exportSVG() {
            const svgData = document.getElementById("svg").outerHTML;
            const blob = new Blob([svgData], {type: "image/svg+xml"});
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = "tito-threat-model.svg";
            a.click();
            URL.revokeObjectURL(url);
        }

        function getRiskColor(risk) {
            const colors = {
                critical: '#f85149',
                high: '#ff8c00',
                medium: '#ffd700',
                low: '#3fb950',
                info: '#58a6ff'
            };
            return colors[risk] || colors.info;
        }

        function getRiskScore(risk) {
            const scores = { critical: 100, high: 75, medium: 50, low: 25, info: 10 };
            return scores[risk] || 0;
        }

        function selectNode(d) {
            selectedNode = d;
            node.classed("selected", n => n === d);
            showNodeDetails(d);
            
            // Highlight connected edges
            link.style("opacity", e => {
                return (e.source === d || e.target === d) ? 1 : 0.3;
            });
        }

        function showNodeDetails(d) {
            const detail = document.getElementById('node-detail');
            const risk = (d.riskLevel || 'info').toLowerCase();
            const riskScore = getRiskScore(risk);
            const threats = d.threats || [];
            const findings = d.findings || [];
            const mitigations = d.mitigations || [];

            let html = ` + "`" + `
                <div class="detail-header">
                    <div class="detail-icon">${nodeIcons[d.type] || nodeIcons.default}</div>
                    <div class="detail-title">
                        <h4>${d.label || d.id}</h4>
                        <div class="detail-type">${d.type || 'Unknown'}</div>
                    </div>
                </div>

                <div class="detail-row">
                    <span class="detail-label">Risk Level</span>
                    <span class="detail-value" style="color: ${getRiskColor(risk)}">${risk.toUpperCase()}</span>
                </div>
                
                <div class="risk-meter">
                    <div class="risk-meter-fill ${risk}" style="width: ${riskScore}%">${riskScore}%</div>
                </div>

                <div class="detail-row">
                    <span class="detail-label">Threats</span>
                    <span class="detail-value">${threats.length}</span>
                </div>
            ` + "`" + `;

            // STRIDE-LM classifications
            if (d.stride && d.stride.length > 0) {
                html += '<div style="margin-top: 16px; margin-bottom: 8px; font-weight: 600; color: #58a6ff;">STRIDE-LM Classification</div>';
                d.stride.forEach(s => {
                    html += ` + "`<span class=\"badge stride\">${s}</span>`" + `;
                });
            }

            // MAESTRO layer
            if (d.maestro) {
                html += ` + "`" + `<div style="margin-top: 16px; margin-bottom: 8px; font-weight: 600; color: #8957e5;">MAESTRO Layer</div>
                         <span class="badge maestro">${d.maestro}</span>` + "`" + `;
                if (d.maestroDesc) {
                    html += ` + "`<div style=\"font-size: 12px; color: #8b949e; margin-top: 8px;\">${d.maestroDesc}</div>`" + `;
                }
            }

            // MITRE ATT&CK techniques
            if (d.mitre && d.mitre.length > 0) {
                html += '<div style="margin-top: 16px; margin-bottom: 8px; font-weight: 600; color: #f85149;">MITRE ATT&CK Techniques</div>';
                d.mitre.forEach(technique => {
                    html += ` + "`<span class=\"badge mitre\">${technique}</span>`" + `;
                });
            }

            // Semgrep findings
            if (findings.length > 0) {
                html += '<div style="margin-top: 16px; margin-bottom: 8px; font-weight: 600; color: #ff7b72;">Semgrep Findings</div>';
                findings.forEach(f => {
                    html += ` + "`" + `
                        <div class="semgrep-finding">
                            <div class="semgrep-title">${f.checkId || f.title || 'Security Finding'}</div>
                            <div class="semgrep-location">${f.path || ''}${f.line ? ':' + f.line : ''}</div>
                        </div>
                    ` + "`" + `;
                });
            }

            // Mitigations
            if (mitigations.length > 0) {
                html += '<div style="margin-top: 16px; margin-bottom: 8px; font-weight: 600; color: #56d364;">Recommended Mitigations</div>';
                mitigations.forEach(m => {
                    html += ` + "`" + `
                        <div class="mitigation-item">
                            <div class="mitigation-title">${m.title || 'Mitigation'}</div>
                            <div class="mitigation-desc">${m.description || ''}</div>
                        </div>
                    ` + "`" + `;
                });
            }

            detail.innerHTML = html;
            detail.classList.add('fade-in');
        }

        function showEmptyDetail() {
            const detail = document.getElementById('node-detail');
            detail.innerHTML = '<div class="detail-empty">Click on a node to see details</div>';
        }

        function toggleSection(header) {
            header.parentElement.classList.toggle('collapsed');
        }

        // Initialize header
        const metadata = data.metadata || {};
        document.getElementById('repo-name').textContent = (metadata.repository || '').split('/').pop() || 'Unknown Repository';
        
        // Header stats
        const stats = document.getElementById('header-stats');
        const threatCounts = { critical: 0, high: 0, medium: 0, low: 0 };
        (data.nodes || []).forEach(n => {
            const threats = n.threats || [];
            threats.forEach(t => {
                const sev = (t.severity || 'low').toLowerCase();
                if (threatCounts[sev] !== undefined) threatCounts[sev]++;
            });
        });

        stats.innerHTML = ` + "`" + `
            <div class="stat-pill">
                <span class="stat-pill-label">Nodes:</span>
                <span class="stat-pill-value">${metadata.totalNodes || data.nodes.length}</span>
            </div>
            <div class="stat-pill">
                <span class="stat-pill-label">Flows:</span>
                <span class="stat-pill-value">${metadata.totalEdges || data.edges.length}</span>
            </div>
            <div class="stat-pill">
                <span class="stat-pill-label">🔴</span>
                <span class="stat-pill-value">${threatCounts.critical}</span>
            </div>
            <div class="stat-pill">
                <span class="stat-pill-label">🟠</span>
                <span class="stat-pill-value">${threatCounts.high}</span>
            </div>
            <div class="stat-pill">
                <span class="stat-pill-label">🟡</span>
                <span class="stat-pill-value">${threatCounts.medium}</span>
            </div>
            <div class="stat-pill">
                <span class="stat-pill-label">🟢</span>
                <span class="stat-pill-value">${threatCounts.low}</span>
            </div>
        ` + "`" + `;

        // Populate threats list
        const threatsList = document.getElementById('threats-list');
        const allThreats = [];
        (data.nodes || []).forEach(n => {
            (n.threats || []).forEach(t => {
                allThreats.push({ ...t, node: n });
            });
        });
        allThreats.sort((a, b) => {
            const order = { critical: 0, high: 1, medium: 2, low: 3 };
            return (order[a.severity] || 99) - (order[b.severity] || 99);
        });

        if (allThreats.length > 0) {
            threatsList.innerHTML = allThreats.map(t => ` + "`" + `
                <div class="threat-item ${t.severity || 'low'}" onclick="selectNodeById('${t.node.id}')">
                    <div class="threat-title">
                        <span>${t.title || 'Threat'}</span>
                        <span class="badge severity-${t.severity || 'low'}">${(t.severity || 'low').toUpperCase()}</span>
                    </div>
                    <div class="threat-desc">${(t.description || '').substring(0, 120)}...</div>
                    <div class="threat-node">📍 ${t.node.label || t.node.id}</div>
                </div>
            ` + "`" + `).join('');
        } else {
            threatsList.innerHTML = '<div class="detail-empty">No threats identified</div>';
        }

        // MAESTRO layers breakdown
        const maestroLayers = {};
        (data.nodes || []).forEach(n => {
            if (n.maestro) {
                maestroLayers[n.maestro] = (maestroLayers[n.maestro] || 0) + 1;
            }
        });

        const maestroList = document.getElementById('maestro-layers');
        const totalNodes = data.nodes.length || 1;
        if (Object.keys(maestroLayers).length > 0) {
            maestroList.innerHTML = Object.entries(maestroLayers)
                .sort((a, b) => b[1] - a[1])
                .map(([layer, count]) => {
                    const pct = Math.round((count / totalNodes) * 100);
                    return ` + "`" + `
                        <div class="layer-bar">
                            <div class="layer-label">${layer}</div>
                            <div class="layer-bar-bg">
                                <div class="layer-bar-fill" style="width: ${pct}%">${count}</div>
                            </div>
                        </div>
                    ` + "`" + `;
                }).join('');
        } else {
            maestroList.innerHTML = '<div class="detail-empty">No MAESTRO data</div>';
        }

        // MITRE ATT&CK techniques
        const mitreSet = new Set();
        (data.nodes || []).forEach(n => {
            (n.mitre || []).forEach(t => mitreSet.add(t));
        });

        const mitreListEl = document.getElementById('mitre-list');
        if (mitreSet.size > 0) {
            mitreListEl.innerHTML = Array.from(mitreSet).sort().map(t => 
                ` + "`<span class=\"mitre-item\" onclick=\"window.open('https://attack.mitre.org/techniques/${t.replace('.', '/')}', '_blank')\">${t}</span>`" + `
            ).join('');
        } else {
            mitreListEl.innerHTML = '<div class="detail-empty">No MITRE ATT&CK data</div>';
        }

        // Search functionality
        const searchBox = document.getElementById('search-box');
        searchBox.addEventListener('input', (e) => {
            const query = e.target.value.toLowerCase();
            if (!query) {
                node.style("opacity", 1);
                link.style("opacity", 0.6);
                return;
            }

            node.style("opacity", d => {
                const label = (d.label || '').toLowerCase();
                const type = (d.type || '').toLowerCase();
                const stride = (d.stride || []).join(' ').toLowerCase();
                const maestro = (d.maestro || '').toLowerCase();
                const mitre = (d.mitre || []).join(' ').toLowerCase();
                
                return (label.includes(query) || type.includes(query) || 
                        stride.includes(query) || maestro.includes(query) || 
                        mitre.includes(query)) ? 1 : 0.2;
            });

            link.style("opacity", 0.2);
        });

        function selectNodeById(id) {
            const n = data.nodes.find(node => node.id === id);
            if (n) selectNode(n);
        }

        // Footer timestamp
        document.getElementById('timestamp').textContent = new Date().toLocaleString();

        // Initial animations
        setTimeout(() => {
            document.querySelectorAll('.sidebar-section').forEach((el, i) => {
                setTimeout(() => el.classList.add('fade-in'), i * 100);
            });
        }, 500);
    </script>
</body>
</html>
`
