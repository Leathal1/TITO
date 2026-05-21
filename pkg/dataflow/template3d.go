package dataflow

const htmlTemplate3D = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>{{TITLE}} - TITO 3D</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        html, body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Inter', Roboto, sans-serif;
            background: #060a1a;
            color: #e8edf5;
            overflow: hidden;
            width: 100%; height: 100%;
            -webkit-font-smoothing: antialiased;
        }
        #graph-container { width: 100vw; height: 100vh; }
        #graph-container canvas { pointer-events: auto; }

        /* Cyberpunk scanlines overlay */
        body::after {
            content: '';
            position: fixed; inset: 0; z-index: 100;
            pointer-events: none;
            background: repeating-linear-gradient(
                0deg,
                transparent 0px,
                transparent 2px,
                rgba(0,0,0,0.04) 2px,
                rgba(0,0,0,0.04) 4px
            );
        }

        /* Vignette overlay */
        body::before {
            content: '';
            position: fixed; inset: 0; z-index: 101;
            pointer-events: none;
            background: radial-gradient(ellipse at center, transparent 50%, rgba(6,10,26,0.9) 100%);
        }

        /* Corner accents rendered by JS */

        .panel {
            position: absolute;
            background: rgba(6, 10, 30, 0.72);
            backdrop-filter: blur(16px) saturate(1.5);
            -webkit-backdrop-filter: blur(16px) saturate(1.5);
            border: 1px solid rgba(255,255,255,0.07);
            border-radius: 10px;
            padding: 16px 18px;
            z-index: 100;
            box-shadow: 0 8px 32px rgba(0,0,0,0.5);
            pointer-events: auto;
            transition: opacity 0.25s ease, transform 0.25s ease;
        }
        .panel h2 {
            font-size: 12px; font-weight: 600; text-transform: uppercase;
            letter-spacing: 1.2px; color: rgba(255,255,255,0.35);
            margin-bottom: 10px;
        }

        #loading {
            position: fixed; inset: 0; z-index: 999;
            display: flex; flex-direction: column;
            align-items: center; justify-content: center;
            background: #060a1a;
            transition: opacity 0.8s ease;
        }
        #loading.hidden { opacity: 0; pointer-events: none; display: none; }
        .loader-ring {
            width: 48px; height: 48px;
            border: 3px solid rgba(68,136,255,0.12);
            border-top-color: #4488ff;
            border-radius: 50%;
            animation: spin 0.9s linear infinite;
            margin-bottom: 20px;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        #loading p { font-size: 14px; color: rgba(255,255,255,0.4); letter-spacing: 0.3px; }
        #loading .loader-sub { font-size: 11px; color: rgba(255,255,255,0.2); margin-top: 6px; }

        #header {
            position: absolute; top: 16px; left: 16px;
            z-index: 100; pointer-events: auto;
            display: flex; align-items: center; gap: 12px;
            background: rgba(6, 10, 30, 0.7);
            backdrop-filter: blur(14px) saturate(1.4);
            border: 1px solid rgba(255,255,255,0.07);
            border-radius: 10px;
            padding: 10px 16px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.4);
        }
        #header .shield {
            width: 28px; height: 28px;
            background: linear-gradient(135deg, #4488ff, #2860cc);
            border-radius: 6px;
            display: flex; align-items: center; justify-content: center;
            font-size: 15px; font-weight: 800; color: #fff;
            flex-shrink: 0;
        }
        #header .info { display: flex; flex-direction: column; }
        #header .name { font-size: 15px; font-weight: 600; color: #fff; line-height: 1.2; }
        #header .sub { font-size: 11px; color: rgba(255,255,255,0.35); letter-spacing: 0.2px; }

        #overview {
            position: absolute; top: 16px; right: 16px;
            min-width: 190px; z-index: 100;
            background: rgba(6, 10, 30, 0.7);
            backdrop-filter: blur(14px) saturate(1.4);
            border: 1px solid rgba(255,255,255,0.07);
            border-radius: 10px;
            padding: 12px 16px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.4);
            pointer-events: none;
        }
        #overview .stat-row { display: flex; justify-content: space-between; padding: 4px 0; font-size: 12px; }
        #overview .stat-row .lbl { color: rgba(255,255,255,0.4); }
        #overview .stat-row .val { color: #e8edf5; font-weight: 600; }
        #overview .divider { height: 1px; background: rgba(255,255,255,0.06); margin: 8px 0; }
        #overview .sev-row { display: flex; align-items: center; gap: 16px; padding: 3px 0; font-size: 11px; }
        #overview .sev-row .dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; margin-right: 4px; }
        #overview .sev-row .lbl { color: rgba(255,255,255,0.35); }
        #overview .sev-row .cnt { color: #e8edf5; font-weight: 600; margin-left: auto; }

        #controls {
            position: absolute; bottom: 16px; left: 50%;
            transform: translateX(-50%);
            display: flex; gap: 6px; z-index: 100;
            background: rgba(6, 10, 30, 0.75);
            backdrop-filter: blur(14px) saturate(1.4);
            border: 1px solid rgba(255,255,255,0.07);
            border-radius: 10px;
            padding: 6px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.5);
            pointer-events: auto;
            flex-wrap: wrap;
            justify-content: center;
        }
        #controls button {
            background: rgba(255,255,255,0.04);
            border: 1px solid rgba(255,255,255,0.06);
            border-radius: 6px;
            color: rgba(255,255,255,0.55);
            cursor: pointer;
            font-size: 13px;
            padding: 6px 10px;
            transition: all 0.15s ease;
            display: flex; align-items: center; gap: 4px;
            white-space: nowrap;
            font-family: inherit;
        }
        #controls button:hover { background: rgba(255,255,255,0.1); color: #fff; border-color: rgba(255,255,255,0.15); }
        #controls button.active { background: rgba(68,136,255,0.15); border-color: rgba(68,136,255,0.3); color: #8ab4ff; }
        #controls button .key { font-size: 9px; opacity: 0.3; margin-left: 2px; }

        #info-panel {
            position: absolute; top: 50%; right: 16px;
            transform: translateY(-50%) translateX(20px);
            opacity: 0; pointer-events: none;
            min-width: 280px; max-width: 340px;
            max-height: 70vh; overflow-y: auto;
            z-index: 200;
            background: rgba(6, 10, 30, 0.85);
            backdrop-filter: blur(18px) saturate(1.5);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 12px;
            padding: 18px;
            box-shadow: 0 12px 48px rgba(0,0,0,0.6);
            transition: opacity 0.25s ease, transform 0.25s ease;
        }
        #info-panel.visible { opacity: 1; pointer-events: auto; transform: translateY(-50%) translateX(0); }
        #info-panel .close-btn {
            position: absolute; top: 10px; right: 10px;
            width: 26px; height: 26px; border-radius: 50%;
            border: none; background: rgba(255,255,255,0.06);
            color: rgba(255,255,255,0.4); cursor: pointer;
            display: flex; align-items: center; justify-content: center;
            font-size: 14px;
        }
        #info-panel .close-btn:hover { background: rgba(255,255,255,0.15); color: #fff; }
        #info-panel h3 { font-size: 16px; font-weight: 600; margin-bottom: 12px; padding-right: 20px; }
        #info-panel .info-sect { margin: 12px 0; }
        #info-panel .info-sect h4 { font-size: 10px; text-transform: uppercase; letter-spacing: 0.8px; color: rgba(255,255,255,0.3); margin-bottom: 4px; }
        #info-panel .info-val { font-size: 13px; color: #e8edf5; }
        #info-panel .finding { background: rgba(0,0,0,0.25); border-left: 2px solid; padding: 10px 12px; margin: 6px 0; border-radius: 4px; font-size: 11px; }
        #info-panel .finding.critical { border-color: #ff2740; }
        #info-panel .finding.high { border-color: #ff8c42; }
        #info-panel .finding.medium { border-color: #ffd23f; }
        #info-panel .finding.low { border-color: #00d4aa; }
        #info-panel .finding .ftitle { font-weight: 600; margin-bottom: 3px; }
        #info-panel .finding .fdesc { color: rgba(255,255,255,0.5); font-size: 10px; line-height: 1.4; }
        #info-panel .badge { display: inline-block; padding: 2px 6px; border-radius: 8px; font-size: 9px; font-weight: 600; margin: 2px; }
        #info-panel .badge.stride { background: #1f6feb33; color: #6ba0ff; }
        #info-panel .badge.maestro { background: #8957e533; color: #b48aff; }
        #info-panel .badge.attack { background: #da363333; color: #ff6b6b; }

        #attack-paths-panel {
            position: absolute; top: 16px; right: 16px;
            min-width: 300px; max-width: 360px;
            max-height: 80vh; overflow-y: auto;
            z-index: 200; display: none;
            background: rgba(6, 10, 30, 0.85);
            backdrop-filter: blur(18px) saturate(1.5);
            border: 1px solid rgba(255,68,68,0.15);
            border-radius: 12px; padding: 16px;
            box-shadow: 0 12px 48px rgba(0,0,0,0.6);
            pointer-events: auto;
        }
        #attack-paths-panel.visible { display: block; animation: panelIn 0.25s ease; }
        @keyframes panelIn { from { opacity: 0; transform: translateX(16px); } to { opacity: 1; transform: translateX(0); } }
        #attack-paths-panel .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; }
        #attack-paths-panel .header h2 { font-size: 14px; color: #ff6b6b; font-weight: 600; text-transform: none; letter-spacing: 0; }
        #attack-paths-panel .close-btn { width: 24px; height: 24px; border-radius: 50%; border: none; background: rgba(255,255,255,0.06); color: rgba(255,255,255,0.4); cursor: pointer; display: flex; align-items: center; justify-content: center; font-size: 13px; }
        .ap-item { background: rgba(0,0,0,0.2); border-left: 3px solid; padding: 12px; margin: 8px 0; border-radius: 4px; cursor: pointer; }
        .ap-item:hover { background: rgba(0,0,0,0.35); }
        .ap-item.critical { border-color: #ff2740; }
        .ap-item.high { border-color: #ff8c42; }
        .ap-item.medium { border-color: #ffd23f; }
        .ap-item.low { border-color: #00d4aa; }
        .ap-item.active { background: rgba(255,68,68,0.12); border-width: 3px; }
        .ap-item .ap-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }
        .ap-item .ap-risk { font-size: 15px; font-weight: 700; }
        .ap-item .ap-score { font-size: 14px; font-weight: 700; color: #ff6b6b; }
        .ap-item .ap-title { font-size: 12px; font-weight: 600; margin-bottom: 4px; }
        .ap-item .ap-summary { font-size: 11px; color: rgba(255,255,255,0.5); }
        .ap-item .ap-stats { margin-top: 6px; padding-top: 6px; border-top: 1px solid rgba(255,255,255,0.06); font-size: 10px; color: rgba(255,255,255,0.35); }

        #cdn-error { display: none; position: fixed; inset: 0; z-index: 1000; background: #060a1a; color: rgba(255,255,255,0.6); flex-direction: column; align-items: center; justify-content: center; padding: 40px; text-align: center; }
        #cdn-error.visible { display: flex; }
        #cdn-error h3 { font-size: 18px; margin-bottom: 8px; color: #ff6b6b; }
        #cdn-error p { font-size: 13px; max-width: 400px; line-height: 1.5; }

        @media (max-width: 768px) {
            #controls { padding: 4px; gap: 4px; }
            #controls button { font-size: 11px; padding: 4px 7px; }
            #header { top: 10px; left: 10px; padding: 8px 12px; }
            #header .name { font-size: 13px; }
            #overview { top: 10px; right: 10px; min-width: 140px; padding: 10px 12px; }
            #info-panel { right: 10px; min-width: 220px; max-width: 280px; }
        }
        @media (max-width: 480px) {
            #overview { display: none; }
            #info-panel { right: 6px; left: 6px; max-width: none; min-width: 0; }
            #controls button .key { display: none; }
        }
    </style>
</head>

<body>
    <div id="loading">
        <div class="loader-ring"></div>
        <p>Loading 3D Threat Model</p>
        <div class="loader-sub">Analyzing {{TITLE}} &middot; TITO</div>
    </div>
    <div id="cdn-error">
        <h3>&#9888; Failed to load</h3>
        <p>Could not load the 3D engine. Please check your internet connection and refresh.</p>
    </div>
    <div id="graph-container"></div>

    <div id="header">
        <div class="shield">T</div>
        <div class="info">
            <div class="name" id="repo-name">...</div>
            <div class="sub">3D Threat Model &middot; TITO</div>
        </div>
    </div>

    <div id="overview">
        <h2>overview</h2>
        <div id="overview-stats"></div>
        <div class="divider"></div>
        <div>
            <div class="sev-row"><div class="dot" style="background:#ff2740"></div><span class="lbl">Critical</span><span class="cnt" id="cnt-critical">0</span></div>
            <div class="sev-row"><div class="dot" style="background:#ff8c42"></div><span class="lbl">High</span><span class="cnt" id="cnt-high">0</span></div>
            <div class="sev-row"><div class="dot" style="background:#ffd23f"></div><span class="lbl">Medium</span><span class="cnt" id="cnt-medium">0</span></div>
            <div class="sev-row"><div class="dot" style="background:#00d4aa"></div><span class="lbl">Low</span><span class="cnt" id="cnt-low">0</span></div>
        </div>
    </div>

    <div id="controls">
        <button onclick="resetCamera()" title="Reset view">&#9678; <span class="key">R</span></button>
        <button id="btn-labels" class="active" onclick="toggleLabels()" title="Toggle labels">Ab <span class="key">L</span></button>
        <button id="btn-boundaries" class="active" onclick="toggleBoundaries()" title="Toggle boundaries">&#9711; <span class="key">B</span></button>
        <button id="btn-particles" class="active" onclick="toggleParticles()" title="Toggle particles">~ <span class="key">P</span></button>
        <button onclick="toggleAttackPaths()" title="Attack paths">&#9876; <span class="key">A</span></button>
        <button onclick="exportScreenshot()" title="Screenshot">&#128247;</button>
    </div>

    <div id="info-panel">
        <button class="close-btn" onclick="closeInfoPanel()">&times;</button>
        <div id="info-content"></div>
    </div>

    <div id="attack-paths-panel">
        <div class="header">
            <h2>&#9876; Attack Paths</h2>
            <button class="close-btn" onclick="closeAttackPathsPanel()">&times;</button>
        </div>
        <div id="attack-paths-list"></div>
    </div>

    <script src="https://unpkg.com/three@0.160.0/build/three.min.js"></script>
    <script src="https://unpkg.com/3d-force-graph@1.75.0/dist/3d-force-graph.min.js"></script>

    <script>
    (function() {
        if (typeof THREE === 'undefined' || typeof ForceGraph3D === 'undefined') {
            document.getElementById('cdn-error').classList.add('visible');
            document.getElementById('loading').classList.add('hidden');
            return;
        }

        // ── Data ──
        const rawData = {{DIAGRAM_DATA}};
        const attackPaths = {{ATTACK_PATHS}};

        const graphData = {
            nodes: (rawData.nodes || []).map(n => ({
                id: n.id, label: n.label || n.id, type: n.type || '',
                riskLevel: n.riskLevel || 'low',
                threats: n.threats || [], findings: n.findings || [],
                description: n.description, technology: n.technology,
                __inAttackPath: false, __isEntryPoint: false, __isTarget: false
            })),
            links: (rawData.edges || []).map(e => ({
                source: e.source, target: e.target, label: e.label || '',
                sensitive: !!e.sensitive, encrypted: !!e.encrypted,
                __inAttackPath: false
            }))
        };

        const COLORS = {
            critical: { hex: 0xff2740, str: '#ff2740', emissive: 0xff2740 },
            high:     { hex: 0xff8c42, str: '#ff8c42', emissive: 0xff8c42 },
            medium:   { hex: 0xffd23f, str: '#ffd23f', emissive: 0xffd23f },
            low:      { hex: 0x00d4aa, str: '#00d4aa', emissive: 0x00d4aa }
        };
        const DEF_C = { hex: 0x4488ff, str: '#4488ff', emissive: 0x2244aa };
        const NODE_SIZES = { critical: 28, high: 22, medium: 16, low: 12 };

        let labelsVisible = true;
        let boundariesVisible = true;
        let particlesVisible = true;
        let autoRotate = true;
        let lastInteraction = Date.now();
        let boundaryMeshes = [];
        const nodeObjectCache = new Map();
        const spawnProgress = new Map(); // nodeId -> spawn scale (0-1)

        // ── Label sprites ──
        function makeLabelSprite(text, riskLevel) {
            const short = text.length > 22 ? text.slice(0, 20) + '..' : text;
            const c = COLORS[riskLevel] || DEF_C;
            const canvas = document.createElement('canvas');
            canvas.width = 360; canvas.height = 90;
            const ctx = canvas.getContext('2d');
            // Dark pill background for readability
            const metrics = ctx.measureText(short);
            const textW = Math.min(metrics.width || (short.length * 16), 320);
            const pillW = textW + 32;
            const pillH = 38;
            const pillX = (360 - pillW) / 2;
            const pillY = 26;
            ctx.globalAlpha = 0.8;
            ctx.fillStyle = '#060a1a';
            ctx.beginPath();
            ctx.roundRect ? ctx.roundRect(pillX, pillY, pillW, pillH, 6) : ctx.rect(pillX, pillY, pillW, pillH);
            ctx.fill();
            ctx.globalAlpha = 1;
            // Subtle border glow
            ctx.strokeStyle = c.str;
            ctx.globalAlpha = 0.2;
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.roundRect ? ctx.roundRect(pillX, pillY, pillW, pillH, 6) : ctx.rect(pillX, pillY, pillW, pillH);
            ctx.stroke();
            ctx.globalAlpha = 1;
            // Text
            ctx.shadowColor = 'rgba(0,0,0,0.9)'; ctx.shadowBlur = 12; ctx.shadowOffsetY = 2;
            ctx.fillStyle = '#ffffff';
            ctx.font = '700 26px -apple-system, "Segoe UI", Inter, sans-serif';
            ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
            ctx.fillText(short, 180, 45);
            ctx.shadowColor = 'transparent';
            // Color underline
            ctx.fillStyle = c.str;
            ctx.globalAlpha = 0.5;
            ctx.fillRect(130, 62, 100, 2);
            ctx.globalAlpha = 1;
            const tex = new THREE.CanvasTexture(canvas);
            tex.minFilter = THREE.LinearFilter;
            const mat = new THREE.SpriteMaterial({ map: tex, transparent: true, depthWrite: false });
            const sprite = new THREE.Sprite(mat);
            sprite.scale.set(80, 20, 1);
            return sprite;
        }

        // ── Node object ──
        function createNodeObject(node) {
            const c = COLORS[node.riskLevel] || DEF_C;
            const sz = NODE_SIZES[node.riskLevel] || 8;
            const group = new THREE.Group();

            // Outer glow aura
            const glowG = new THREE.SphereGeometry(sz * 0.6, 24, 24);
            const glowM = new THREE.MeshBasicMaterial({ color: c.hex, transparent: true, opacity: 0.2 });
            const glow = new THREE.Mesh(glowG, glowM);
            glow.scale.set(4.0, 4.0, 4.0);
            group.add(glow);

            // Core sphere with PBR
            const coreG = new THREE.SphereGeometry(sz, 32, 32);
            const coreM = new THREE.MeshStandardMaterial({
                color: c.hex, emissive: c.emissive, emissiveIntensity: 1.2,
                metalness: 0.3, roughness: 0.2
            });
            const core = new THREE.Mesh(coreG, coreM);
            core.userData.isCore = true;
            group.add(core);

            // Inner bright point
            const innerG = new THREE.SphereGeometry(sz * 0.3, 16, 16);
            const innerM = new THREE.MeshBasicMaterial({ color: c.hex, transparent: true, opacity: 0.5 });
            group.add(new THREE.Mesh(innerG, innerM));

            if (node.riskLevel === 'critical') group.userData.pulse = true;
            if (node.riskLevel === 'high') group.userData.pulse = true;

            const sprite = makeLabelSprite(node.label, node.riskLevel);
            sprite.position.y = sz + 16;
            group.add(sprite);
            group.userData.labelSprite = sprite;

            // Store id for hover
            group.userData.nodeId = node.id;
            group.userData.nodeRiskLevel = node.riskLevel;

            return group;
        }

        // ── Graph init ──
        const elem = document.getElementById('graph-container');
        const Graph = ForceGraph3D()(elem);

        Graph.graphData(graphData)
            .nodeThreeObject(node => {
                const obj = createNodeObject(node);
                nodeObjectCache.set(node.id, obj);
                spawnProgress.set(node.id, 0);
                // Nodes start at scale 0 for spawn animation
                obj.scale.set(0.01, 0.01, 0.01);
                return obj;
            })
            .linkWidth(link => link.__inAttackPath ? 3 : (link.sensitive ? 1.5 : 1))
            .linkColor(link => {
                if (link.__inAttackPath) return '#ff6b6b';
                return link.sensitive ? '#ff4455' : '#4488ff';
            })
            .linkOpacity(0.75)
            .linkDirectionalParticles(l => l.__inAttackPath ? 8 : (particlesVisible ? 4 : 0))
            .linkDirectionalParticleSpeed(0.005)
            .linkDirectionalParticleWidth(l => l.__inAttackPath ? 3 : 1.5)
            .linkDirectionalParticleColor(l => l.__inAttackPath ? '#ff6b6b' : (l.sensitive ? '#ff4455' : '#4488ff'))
            .onNodeClick(node => { showNodeInfo(node); flyToNode(node); })
            .onNodeHover(node => { elem.style.cursor = node ? 'pointer' : null; })
            .d3Force('charge').strength(-150);
        Graph.d3Force('link').distance(120);

        window.Graph = Graph;
        window.graphData = graphData;

        // ── Corner accents (JS) ──
        (function() {
            var colors = ['#4488ff', '#66aaff', '#4488ff', '#66aaff'];
            var corners = [
                {top: 0, left: 0, borderTop: '3px solid ' + colors[0], borderLeft: '3px solid ' + colors[0], width: '70px', height: '70px', borderRadius: '0 0 0 4px'},
                {top: 0, right: 0, borderTop: '3px solid ' + colors[1], borderRight: '3px solid ' + colors[1], width: '70px', height: '70px', borderRadius: '0 0 4px 0'},
                {bottom: 0, left: 0, borderBottom: '3px solid ' + colors[2], borderLeft: '3px solid ' + colors[2], width: '70px', height: '70px', borderRadius: '0 4px 0 0'},
                {bottom: 0, right: 0, borderBottom: '3px solid ' + colors[3], borderRight: '3px solid ' + colors[3], width: '70px', height: '70px', borderRadius: '0 0 0 4px'}
            ];
            corners.forEach(function(p, i) {
                var el = document.createElement('div');
                el.style.cssText = 'position:fixed;z-index:9999;pointer-events:none;';
                Object.keys(p).forEach(function(k) { el.style[k] = p[k]; });
                document.body.appendChild(el);
                (function(el2, offset) {
                    setInterval(function() {
                        el2.style.opacity = 0.3 + Math.sin(Date.now() * 0.002 + offset) * 0.35;
                    }, 50);
                })(el, i * 1.57);
            });
        })();

        // ── Scene ──
        const scene = Graph.scene();
        scene.background = new THREE.Color(0x060a1a);
        scene.fog = new THREE.FogExp2(0x060a1a, 0.0010);

        const ambient = new THREE.AmbientLight(0x6688cc, 0.5);
        scene.add(ambient);
        const cool = new THREE.DirectionalLight(0x4488ff, 1.5);
        cool.position.set(200, 300, 200);
        scene.add(cool);
        const warm = new THREE.DirectionalLight(0xff8844, 0.5);
        warm.position.set(-200, -100, -300);
        scene.add(warm);

        // ── Animated Nebula (replaces static stars) ──
        (function() {
            const starCount = 3000;
            const g = new THREE.BufferGeometry();
            const pos = new Float32Array(starCount * 3);
            const sizes = new Float32Array(starCount);
            const phases = new Float32Array(starCount);
            for (let i = 0; i < starCount; i++) {
                const r = 400 + Math.random() * 600;
                const th = Math.random() * Math.PI * 2;
                const ph = Math.acos(2 * Math.random() - 1);
                pos[i*3] = r * Math.sin(ph) * Math.cos(th);
                pos[i*3+1] = r * Math.cos(ph);
                pos[i*3+2] = r * Math.sin(ph) * Math.sin(th);
                sizes[i] = 0.3 + Math.random() * 1.2;
                phases[i] = Math.random() * Math.PI * 2;
            }
            g.setAttribute('position', new THREE.BufferAttribute(pos, 3));
            g.setAttribute('size', new THREE.BufferAttribute(sizes, 1));
            g.setAttribute('phase', new THREE.BufferAttribute(phases, 1));

            // Use two overlapping color layers for depth
            const starMat = new THREE.PointsMaterial({
                color: 0x88aaff, size: 2.0, transparent: true, opacity: 1.0,
                blending: THREE.AdditiveBlending, depthWrite: false
            });
            const starField = new THREE.Points(g, starMat);
            starField.userData.isNebula = true;
            scene.add(starField);

            // Second layer smaller/warmer
            const g2 = new THREE.BufferGeometry();
            const pos2 = new Float32Array(1500 * 3);
            for (let i = 0; i < 800; i++) {
                const r = 250 + Math.random() * 350;
                const th = Math.random() * Math.PI * 2;
                const ph = Math.acos(2 * Math.random() - 1);
                pos2[i*3] = r * Math.sin(ph) * Math.cos(th);
                pos2[i*3+1] = r * Math.cos(ph);
                pos2[i*3+2] = r * Math.sin(ph) * Math.sin(th);
            }
            g2.setAttribute('position', new THREE.BufferAttribute(pos2, 3));
            const starMat2 = new THREE.PointsMaterial({
                color: 0xdd99ff, size: 1.5, transparent: true, opacity: 0.7,
                blending: THREE.AdditiveBlending, depthWrite: false
            });
            const starField2 = new THREE.Points(g2, starMat2);
            starField2.userData.isNebula = true;
            starField2.userData.phase = 0;
            scene.add(starField2);

            window.__nebulae = [starField, starField2];
        })();

        // Ground glow disc
        const gg = new THREE.CircleGeometry(400, 32);
        const gm = new THREE.MeshBasicMaterial({ color: 0x1a2255, transparent: true, opacity: 0.12, side: THREE.DoubleSide });
        const disc = new THREE.Mesh(gg, gm);
        disc.rotation.x = -Math.PI / 2;
        disc.position.y = -219;
        scene.add(disc);

        const grid = new THREE.GridHelper(1000, 40, 0x1a2255, 0x111833);
        grid.position.y = -220;
        scene.add(grid);

        // Animated ground pulse ring
        (function() {
            const rG = new THREE.RingGeometry(180, 200, 64);
            const rM = new THREE.MeshBasicMaterial({
                color: 0x4488ff, transparent: true,
                opacity: 0.06, side: THREE.DoubleSide,
                depthWrite: false
            });
            const ring = new THREE.Mesh(rG, rM);
            ring.rotation.x = -Math.PI / 2;
            ring.position.y = -218;
            ring.userData.isPulseRing = true;
            scene.add(ring);
            window.__pulseRing = ring;
        })();

        // ── Trust boundaries ──
        function addTrustBoundaries(boundaries) {
            const s = Graph.scene();
            let placed = 0;
            const tryPlace = () => {
                let allDone = true;
                boundaries.forEach(b => {
                    if (b._placed) return;
                    const members = graphData.nodes.filter(n => b.nodes.includes(n.id));
                    if (!members.length) return;
                    const firstObj = nodeObjectCache.get(members[0].id);
                    if (!firstObj || !firstObj.position || (firstObj.position.x === 0 && firstObj.position.y === 0 && firstObj.position.z === 0)) {
                        allDone = false;
                        return;
                    }
                    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity, minZ = Infinity, maxZ = -Infinity;
                    members.forEach(n => {
                        const obj = nodeObjectCache.get(n.id);
                        if (obj && obj.position) {
                            const p = obj.position;
                            minX = Math.min(minX, p.x); maxX = Math.max(maxX, p.x);
                            minY = Math.min(minY, p.y); maxY = Math.max(maxY, p.y);
                            minZ = Math.min(minZ, p.z); maxZ = Math.max(maxZ, p.z);
                        }
                    });
                    if (!isFinite(minX)) return;
                    const pad = 40;
                    const cx = (minX + maxX) / 2, cy = (minY + maxY) / 2, cz = (minZ + maxZ) / 2;
                    const sx = Math.max(maxX - minX + pad * 2, 30);
                    const sy = Math.max(maxY - minY + pad * 2, 30);
                    const sz = Math.max(maxZ - minZ + pad * 2, 30);
                    const color = new THREE.Color(b.color || '#4488ff');

                    const boxG = new THREE.BoxGeometry(sx, sy, sz);
                    const boxM = new THREE.MeshPhysicalMaterial({ color, transparent: true, opacity: 0.04, side: THREE.BackSide });
                    const box = new THREE.Mesh(boxG, boxM);
                    box.position.set(cx, cy, cz);
                    s.add(box);

                    const edgeG = new THREE.EdgesGeometry(boxG);
                    const edgeM = new THREE.LineBasicMaterial({ color, transparent: true, opacity: 0.2 });
                    const wire = new THREE.LineSegments(edgeG, edgeM);
                    wire.position.set(cx, cy, cz);
                    wire.userData.boundaryColor = color;
                    s.add(wire);

                    const lc = document.createElement('canvas');
                    lc.width = 512; lc.height = 64;
                    const lctx = lc.getContext('2d');
                    lctx.fillStyle = '#' + color.getHexString();
                    lctx.font = 'bold 28px -apple-system, sans-serif';
                    lctx.textAlign = 'center'; lctx.textBaseline = 'middle';
                    lctx.shadowColor = 'rgba(0,0,0,0.5)'; lctx.shadowBlur = 6;
                    lctx.fillText(b.name, 256, 36);
                    const lt = new THREE.CanvasTexture(lc);
                    const lm = new THREE.SpriteMaterial({ map: lt, transparent: true, opacity: 0.5, depthWrite: false });
                    const lbl = new THREE.Sprite(lm);
                    lbl.position.set(cx, maxY + pad + 15, cz);
                    lbl.scale.set(70, 9, 1);
                    s.add(lbl);

                    boundaryMeshes.push({ box, wire, lbl, visible: true });
                    b._placed = true;
                    placed++;
                });
                if (!allDone && placed < boundaries.length) setTimeout(tryPlace, 300);
            };
            setTimeout(tryPlace, 200);
        }

        if (rawData.trustBoundaries && rawData.trustBoundaries.length > 0) {
            addTrustBoundaries(rawData.trustBoundaries);
        }

        // ── Spawn animation state ──
        let spawnStartTime = Date.now();
        const nodeSpawnDelay = 50; // ms between each node spawn start
        const nodeSpawnDuration = 600; // ms for each node to reach full scale

        // ── Animation loop ──
        Graph.onEngineTick(() => {
            const t = Date.now();

            // Node spawn animation (spring-eased)
            const elapsed = t - spawnStartTime;
            graphData.nodes.forEach((node, i) => {
                const obj = nodeObjectCache.get(node.id);
                if (!obj) return;
                const nodeDelay = i * nodeSpawnDelay;
                if (elapsed < nodeDelay) {
                    obj.scale.set(0.01, 0.01, 0.01);
                    return;
                }
                const localElapsed = elapsed - nodeDelay;
                const raw = Math.min(localElapsed / nodeSpawnDuration, 1);
                // Overshoot bounce: cubic with slight overshoot
                let s;
                if (raw < 1) {
                    // Elastic ease-out
                    s = 1 + Math.pow(2, -12 * raw) * Math.sin(20 * raw * Math.PI * 0.25);
                } else {
                    s = 1;
                }
                obj.scale.set(s, s, s);
            });

            // Pulse critical/high nodes
            graphData.nodes.forEach(node => {
                const obj = nodeObjectCache.get(node.id);
                if (obj && obj.userData && obj.userData.pulse) {
                    const s = 1 + Math.sin(t * 0.0025) * 0.12;
                    // Scale children but not the group itself (spawn anim owns that)
                    obj.children.forEach(child => {
                        if (child.userData && child.userData.isCore) {
                            child.scale.set(s, s, s);
                        }
                    });
                }
            });

            // Auto-rotate camera with vertical oscillation (cinematic)
            if (autoRotate && t - lastInteraction > 5000) {
                const cam = Graph.camera();
                const dist = cam.position.length();
                const angle = t * 0.00008;
                const vertOsc = Math.sin(t * 0.00003) * 15;
                cam.position.x = dist * Math.sin(angle);
                cam.position.z = dist * Math.cos(angle);
                cam.position.y = 30 + vertOsc;
                cam.lookAt(scene.position);
            }

            // Nebula slow rotation
            const nebulae = window.__nebulae || [];
            nebulae.forEach((n, idx) => {
                const speed = idx === 0 ? 0.00004 : -0.000025;
                n.rotation.y += speed;
            });

            // Pulse ring animation
            const pr = window.__pulseRing;
            if (pr) {
                const ps = 1 + Math.sin(t * 0.001) * 0.08;
                pr.scale.set(ps, ps, ps);
                pr.material.opacity = 0.04 + Math.sin(t * 0.0015) * 0.03;
            }

            // Boundary wire shimmer
            boundaryMeshes.forEach(m => {
                if (m.wire && m.wire.visible && m.wire.material) {
                    const shimmer = 0.15 + Math.sin(t * 0.002 + (m.wire.position.x * 0.01)) * 0.1;
                    m.wire.material.opacity = shimmer;
                }
            });
        });

        elem.addEventListener('mousedown', () => { lastInteraction = Date.now(); });
        elem.addEventListener('wheel', () => { lastInteraction = Date.now(); });

        // ── Finish loading ──
        setTimeout(() => {
            document.getElementById('loading').classList.add('hidden');
            // Dramatic camera fly-in
            const startPos = { x: 100, y: 160, z: 680 };
            const endPos = { x: 0, y: 30, z: 380 };
            const startTime = Date.now();
            const flyDuration = 1200;
            function cameraFlyIn() {
                const t = Date.now();
                const elapsed = t - startTime;
                let p = Math.min(elapsed / flyDuration, 1);
                // Cubic ease-out
                p = 1 - Math.pow(1 - p, 3);
                const cx = startPos.x + (endPos.x - startPos.x) * p;
                const cy = startPos.y + (endPos.y - startPos.y) * p;
                const cz = startPos.z + (endPos.z - startPos.z) * p;
                Graph.cameraPosition({ x: cx, y: cy, z: cz }, { x: 0, y: 0, z: 0 }, 0);
                if (p < 1) requestAnimationFrame(cameraFlyIn);
            }
            requestAnimationFrame(cameraFlyIn);
        }, 800);

        // ── Overview stats ──
        (function() {
            const m = rawData.metadata || {};
            const repoName = (m.repository || '').split('/').pop() || 'unknown';
            document.getElementById('repo-name').textContent = repoName;
            const se = document.getElementById('overview-stats');
            se.innerHTML =
                '<div class="stat-row"><span class="lbl">Nodes</span><span class="val">' + graphData.nodes.length + '</span></div>' +
                '<div class="stat-row"><span class="lbl">Edges</span><span class="val">' + graphData.links.length + '</span></div>' +
                '<div class="stat-row"><span class="lbl">Threats</span><span class="val">' + (m.totalThreats || 0) + '</span></div>';
            const counts = { critical: 0, high: 0, medium: 0, low: 0 };
            graphData.nodes.forEach(n => { const r = n.riskLevel; if (counts[r] !== undefined) counts[r]++; });
            document.getElementById('cnt-critical').textContent = counts.critical;
            document.getElementById('cnt-high').textContent = counts.high;
            document.getElementById('cnt-medium').textContent = counts.medium;
            document.getElementById('cnt-low').textContent = counts.low;
        })();

        // ── Keyboard ──
        document.addEventListener('keydown', e => {
            if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
            switch (e.key.toLowerCase()) {
                case 'r': resetCamera(); break;
                case 'l': toggleLabels(); break;
                case 'b': toggleBoundaries(); break;
                case 'p': toggleParticles(); break;
                case 'a': toggleAttackPaths(); break;
            }
        });

        // ══════════════════════════════════════════
        //  CONTROL FUNCTIONS
        // ══════════════════════════════════════════

        window.resetCamera = function() {
            Graph.cameraPosition({ x: 0, y: 30, z: 380 }, { x: 0, y: 0, z: 0 }, 800);
            lastInteraction = Date.now();
        };
        window.toggleLabels = function() {
            labelsVisible = !labelsVisible;
            document.getElementById('btn-labels').classList.toggle('active');
            graphData.nodes.forEach(node => {
                const obj = nodeObjectCache.get(node.id);
                if (obj && obj.userData && obj.userData.labelSprite) {
                    obj.userData.labelSprite.visible = labelsVisible;
                }
            });
        };
        window.toggleBoundaries = function() {
            boundariesVisible = !boundariesVisible;
            document.getElementById('btn-boundaries').classList.toggle('active');
            boundaryMeshes.forEach(m => { m.box.visible = boundariesVisible; m.wire.visible = boundariesVisible; m.lbl.visible = boundariesVisible; });
        };
        window.toggleParticles = function() {
            particlesVisible = !particlesVisible;
            document.getElementById('btn-particles').classList.toggle('active');
            Graph.linkDirectionalParticles(() => particlesVisible ? 4 : 0);
        };
        window.toggleAttackPaths = function() {
            const panel = document.getElementById('attack-paths-panel');
            const isVisible = panel.style.display !== 'none';
            panel.style.display = isVisible ? 'none' : 'block';
            panel.classList.toggle('visible', !isVisible);
            if (!isVisible && attackPaths && attackPaths.length) initializeAttackPathsPanel();
            if (isVisible) clearAttackPathHighlight();
            lastInteraction = Date.now();
        };
        window.closeAttackPathsPanel = function() {
            document.getElementById('attack-paths-panel').style.display = 'none';
            clearAttackPathHighlight();
        };
        window.exportScreenshot = function() {
            const renderer = Graph.renderer();
            if (!renderer) return;
            const link = document.createElement('a');
            link.download = 'tito-3d-threat-model.png';
            link.href = renderer.domElement.toDataURL('image/png');
            link.click();
        };

        function flyToNode(node) {
            if (!node || !node.x) return;
            const dist = 180;
            const r = 1 + dist / Math.hypot(node.x, node.y, node.z);
            Graph.cameraPosition({ x: node.x * r, y: node.y * r + 20, z: node.z * r }, node, 800);
            lastInteraction = Date.now();
        }

        window.showNodeInfo = function(node) {
            const panel = document.getElementById('info-panel');
            const content = document.getElementById('info-content');
            const c = COLORS[node.riskLevel] || DEF_C;
            let html = '<h3 style="color:' + c.str + '">' + (node.label || 'Unknown') + '</h3>';
            html += '<div class="info-sect"><h4>Type</h4><div class="info-val">' + (node.type || '—') + '</div></div>';
            html += '<div class="info-sect"><h4>Risk Level</h4><div class="info-val" style="color:' + c.str + '">' + (node.riskLevel || 'unknown').toUpperCase() + '</div></div>';
            html += '<div class="info-sect"><h4>Threats</h4><div class="info-val">' + (node.threats ? node.threats.length : 0) + ' identified</div></div>';
            if (node.description) html += '<div class="info-sect"><h4>Description</h4><div class="info-val">' + node.description + '</div></div>';
            if (node.findings && node.findings.length) {
                html += '<div class="info-sect"><h4>Findings</h4>';
                node.findings.slice(0, 6).forEach(f => {
                    const sev = f.severity || 'medium';
                    html += '<div class="finding ' + sev + '"><div class="ftitle">' + (f.title || '') + '</div><div class="fdesc">' + (f.description ? f.description.slice(0, 120) : '') + '</div>';
                    if (f.stride) html += '<span class="badge stride">STRIDE: ' + f.stride + '</span>';
                    if (f.maestro) html += '<span class="badge maestro">MAESTRO: ' + f.maestro + '</span>';
                    if (f.attackIds && f.attackIds.length) html += '<span class="badge attack">MITRE: ' + f.attackIds[0] + '</span>';
                    html += '</div>';
                });
                html += '</div>';
            }
            content.innerHTML = html;
            panel.classList.add('visible');
        };
        window.closeInfoPanel = function() { document.getElementById('info-panel').classList.remove('visible'); };

        // ── Attack paths ──
        window.initializeAttackPathsPanel = function() {
            const list = document.getElementById('attack-paths-list');
            if (!attackPaths || !attackPaths.length) {
                list.innerHTML = '<div style="color:rgba(255,255,255,0.35);text-align:center;padding:20px;font-size:12px">No attack paths found</div>';
                return;
            }
            let html = '';
            attackPaths.forEach((path, i) => {
                const rl = getRiskLevel(path.compositeRisk);
                html += '<div class="ap-item ' + rl.toLowerCase() + '" id="ap-' + i + '" onclick="selectAttackPath(' + i + ')">' +
                    '<div class="ap-header"><span class="ap-risk">' + getRiskEmoji(path.compositeRisk) + ' ' + rl + '</span>' +
                    '<span class="ap-score">' + (path.compositeRisk || 0).toFixed(1) + '/10</span></div>' +
                    '<div class="ap-title">Path #' + (i + 1) + ': ' + (path.steps ? path.steps.length : 0) + ' steps</div>' +
                    '<div class="ap-summary">' + (getGraphNode(path.entryPoint)?.label || path.entryPoint) + ' &rarr; ' + (getGraphNode(path.target)?.label || path.target) + '</div>' +
                    '<div class="ap-stats">Difficulty: ' + getDifficultyLevel(path.totalDifficulty) +
                    (path.mitreTactics && path.mitreTactics.length ? ' &middot; ' + path.mitreTactics.slice(0, 3).join(', ') : '') + '</div></div>';
            });
            list.innerHTML = html;
        };

        window.selectAttackPath = function(idx) {
            document.querySelectorAll('.ap-item').forEach((el, i) => el.classList.toggle('active', i === idx));
            highlightAttackPath(attackPaths[idx]);
            lastInteraction = Date.now();
        };

        function highlightAttackPath(path) {
            clearAttackPathHighlight();
            if (!path || !path.steps) return;
            const pathNodeIds = new Set();
            const pathLinkPairs = new Set();
            pathNodeIds.add(path.entryPoint);
            path.steps.forEach(s => { pathNodeIds.add(s.fromNode); pathNodeIds.add(s.toNode); pathLinkPairs.add(s.fromNode + '::' + s.toNode); });
            graphData.nodes.forEach(n => { n.__inAttackPath = pathNodeIds.has(n.id); n.__isEntryPoint = n.id === path.entryPoint; n.__isTarget = n.id === path.target; });
            graphData.links.forEach(l => {
                const sid = (typeof l.source === 'object' ? l.source.id : l.source) || '';
                const tid = (typeof l.target === 'object' ? l.target.id : l.target) || '';
                l.__inAttackPath = pathLinkPairs.has(sid + '::' + tid);
            });
            graphData.nodes.forEach(node => {
                const obj = nodeObjectCache.get(node.id);
                if (!obj) return;
                const inPath = node.__inAttackPath || node.__isEntryPoint || node.__isTarget;
                obj.visible = !(!inPath);
                if (inPath) {
                    const hColor = node.__isEntryPoint ? 0x00ff88 : (node.__isTarget ? 0xff2740 : 0xff8c42);
                    obj.children.forEach(child => {
                        if (child.type === 'Mesh' && child.material && child.material.emissive) {
                            child.material.emissive.setHex(hColor);
                            child.material.emissiveIntensity = 0.9;
                        }
                    });
                }
            });
            Graph.linkColor(l => l.__inAttackPath ? '#ff6b6b' : 'rgba(100,100,120,0.15)');
            Graph.linkWidth(l => l.__inAttackPath ? 3 : 0.5);
            Graph.linkDirectionalParticles(l => l.__inAttackPath ? 8 : 0);
        }

        window.clearAttackPathHighlight = function() {
            graphData.nodes.forEach(n => { n.__inAttackPath = false; n.__isEntryPoint = false; n.__isTarget = false; });
            graphData.links.forEach(l => { l.__inAttackPath = false; });
            graphData.nodes.forEach(node => {
                const cached = nodeObjectCache.get(node.id);
                if (cached) {
                    cached.visible = true;
                    const c = COLORS[node.riskLevel] || DEF_C;
                    cached.children.forEach(child => {
                        if (child.type === 'Mesh' && child.material && child.material.emissive) {
                            child.material.emissive.setHex(c.emissive);
                            child.material.emissiveIntensity = 0.7;
                        }
                    });
                }
            });
            Graph.linkColor(l => l.sensitive ? '#ff4455' : '#4488ff');
            Graph.linkWidth(l => l.sensitive ? 1.5 : 1);
            Graph.linkDirectionalParticles(l => particlesVisible ? 4 : 0);
        };

        // ── Helpers ──
        function getRiskLevel(s) { if (s >= 8) return 'CRITICAL'; if (s >= 6) return 'HIGH'; if (s >= 4) return 'MEDIUM'; return 'LOW'; }
        function getRiskEmoji(s) { if (s >= 8) return '\u{1F534}'; if (s >= 6) return '\u{1F7E0}'; if (s >= 4) return '\u{1F7E1}'; return '\u{1F7E2}'; }
        function getDifficultyLevel(d) { if (d < 0.1) return 'TRIVIAL'; if (d < 0.3) return 'LOW'; if (d < 0.6) return 'MEDIUM'; if (d < 0.8) return 'HIGH'; return 'VERY HIGH'; }
        function getGraphNode(id) { return graphData.nodes.find(n => n.id === id); }

        console.log('TITO 3D visualization ready — cinematic mode');
    })();
    </script>
</body>
</html>`
