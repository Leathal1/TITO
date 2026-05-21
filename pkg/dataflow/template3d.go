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

        /* ── Panel base ── */
        .panel {
            position: absolute;
            background: rgba(6, 10, 30, 0.78);
            backdrop-filter: blur(14px) saturate(1.4);
            -webkit-backdrop-filter: blur(14px) saturate(1.4);
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

        /* ── Loading ── */
        #loading {
            position: fixed; inset: 0; z-index: 999;
            display: flex; flex-direction: column;
            align-items: center; justify-content: center;
            background: #060a1a;
            transition: opacity 0.6s ease;
        }
        #loading.hidden { opacity: 0; pointer-events: none; }
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
        #loading .loader-sub {
            font-size: 11px; color: rgba(255,255,255,0.2);
            margin-top: 6px;
        }

        /* ── Header ── */
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
        #header .sub {
            font-size: 11px; color: rgba(255,255,255,0.35);
            letter-spacing: 0.2px;
        }

        /* ── Overview ── */
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
        #overview .stat-row {
            display: flex; justify-content: space-between;
            padding: 4px 0; font-size: 12px;
        }
        #overview .stat-row .lbl { color: rgba(255,255,255,0.4); }
        #overview .stat-row .val { color: #e8edf5; font-weight: 600; }
        #overview .divider {
            height: 1px; background: rgba(255,255,255,0.06);
            margin: 8px 0;
        }
        #overview .sev-row {
            display: flex; align-items: center; gap: 16px;
            padding: 3px 0; font-size: 11px;
        }
        #overview .sev-row .dot {
            width: 8px; height: 8px; border-radius: 50%;
            flex-shrink: 0; margin-right: 4px;
        }
        #overview .sev-row .lbl { color: rgba(255,255,255,0.35); }
        #overview .sev-row .cnt { color: #e8edf5; font-weight: 600; margin-left: auto; }

        /* ── Controls ── */
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
        #controls button:hover {
            background: rgba(255,255,255,0.1);
            color: #fff;
            border-color: rgba(255,255,255,0.15);
        }
        #controls button.active {
            background: rgba(68,136,255,0.15);
            border-color: rgba(68,136,255,0.3);
            color: #8ab4ff;
        }
        #controls button .key {
            font-size: 9px; opacity: 0.3; margin-left: 2px;
        }

        /* ── Info Panel ── */
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
        #info-panel.visible {
            opacity: 1; pointer-events: auto;
            transform: translateY(-50%) translateX(0);
        }
        #info-panel .close-btn {
            position: absolute; top: 10px; right: 10px;
            width: 26px; height: 26px; border-radius: 50%;
            border: none; background: rgba(255,255,255,0.06);
            color: rgba(255,255,255,0.4); cursor: pointer;
            display: flex; align-items: center; justify-content: center;
            font-size: 14px; transition: all 0.15s;
        }
        #info-panel .close-btn:hover { background: rgba(255,255,255,0.15); color: #fff; }
        #info-panel h3 { font-size: 16px; font-weight: 600; margin-bottom: 12px; padding-right: 20px; }
        #info-panel .info-sect { margin: 12px 0; }
        #info-panel .info-sect h4 {
            font-size: 10px; text-transform: uppercase;
            letter-spacing: 0.8px; color: rgba(255,255,255,0.3);
            margin-bottom: 4px;
        }
        #info-panel .info-val { font-size: 13px; color: #e8edf5; }
        #info-panel .finding {
            background: rgba(0,0,0,0.25); border-left: 2px solid;
            padding: 10px 12px; margin: 6px 0; border-radius: 4px;
            font-size: 11px;
        }
        #info-panel .finding.critical { border-color: #ff2740; }
        #info-panel .finding.high { border-color: #ff8c42; }
        #info-panel .finding.medium { border-color: #ffd23f; }
        #info-panel .finding.low { border-color: #00d4aa; }
        #info-panel .finding .ftitle { font-weight: 600; margin-bottom: 3px; }
        #info-panel .finding .fdesc { color: rgba(255,255,255,0.5); font-size: 10px; line-height: 1.4; }
        #info-panel .badge {
            display: inline-block; padding: 2px 6px; border-radius: 8px;
            font-size: 9px; font-weight: 600; margin: 2px;
        }
        #info-panel .badge.stride { background: #1f6feb33; color: #6ba0ff; }
        #info-panel .badge.maestro { background: #8957e533; color: #b48aff; }
        #info-panel .badge.attack { background: #da363333; color: #ff6b6b; }

        /* ── Attack Paths Panel ── */
        #attack-paths-panel {
            position: absolute; top: 16px; right: 16px;
            min-width: 300px; max-width: 360px;
            max-height: 80vh; overflow-y: auto;
            z-index: 200;
            display: none;
            background: rgba(6, 10, 30, 0.85);
            backdrop-filter: blur(18px) saturate(1.5);
            border: 1px solid rgba(255,68,68,0.15);
            border-radius: 12px;
            padding: 16px;
            box-shadow: 0 12px 48px rgba(0,0,0,0.6);
            pointer-events: auto;
        }
        #attack-paths-panel.visible { display: block; animation: panelIn 0.25s ease; }
        @keyframes panelIn { from { opacity: 0; transform: translateX(16px); } to { opacity: 1; transform: translateX(0); } }
        #attack-paths-panel .header {
            display: flex; justify-content: space-between; align-items: center;
            margin-bottom: 14px;
        }
        #attack-paths-panel .header h2 {
            font-size: 14px; color: #ff6b6b; font-weight: 600;
            text-transform: none; letter-spacing: 0;
        }
        #attack-paths-panel .close-btn {
            width: 24px; height: 24px; border-radius: 50%;
            border: none; background: rgba(255,255,255,0.06);
            color: rgba(255,255,255,0.4); cursor: pointer;
            display: flex; align-items: center; justify-content: center;
            font-size: 13px; transition: 0.15s;
        }
        #attack-paths-panel .close-btn:hover { background: rgba(255,255,255,0.15); color: #fff; }

        .ap-item {
            background: rgba(0,0,0,0.2); border-left: 3px solid;
            padding: 12px; margin: 8px 0; border-radius: 4px;
            cursor: pointer; transition: all 0.15s ease;
        }
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

        /* ── Scrollbar ── */
        #info-panel::-webkit-scrollbar, #attack-paths-panel::-webkit-scrollbar { width: 5px; }
        #info-panel::-webkit-scrollbar-track, #attack-paths-panel::-webkit-scrollbar-track { background: transparent; }
        #info-panel::-webkit-scrollbar-thumb, #attack-paths-panel::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.08); border-radius: 3px; }
        #info-panel::-webkit-scrollbar-thumb:hover, #attack-paths-panel::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.15); }

        /* ── Responsive ── */
        @media (max-width: 768px) {
            #controls { padding: 4px; gap: 4px; }
            #controls button { font-size: 11px; padding: 4px 7px; }
            #header { top: 10px; left: 10px; padding: 8px 12px; }
            #header .name { font-size: 13px; }
            #overview { top: 10px; right: 10px; min-width: 140px; padding: 10px 12px; }
            #overview .stat-row { font-size: 10px; }
            #overview .sev-row { font-size: 10px; }
            #info-panel { right: 10px; min-width: 220px; max-width: 280px; }
            #attack-paths-panel { right: 10px; min-width: 240px; max-width: 300px; }
        }
        @media (max-width: 480px) {
            #overview { display: none; }
            #info-panel { right: 6px; left: 6px; max-width: none; min-width: 0; }
            #attack-paths-panel { right: 6px; left: 6px; max-width: none; min-width: 0; }
            #controls button .key { display: none; }
        }

        /* ── CDN error ── */
        #cdn-error {
            display: none; position: fixed; inset: 0; z-index: 1000;
            background: #060a1a; color: rgba(255,255,255,0.6);
            flex-direction: column; align-items: center; justify-content: center;
            padding: 40px; text-align: center;
        }
        #cdn-error.visible { display: flex; }
        #cdn-error h3 { font-size: 18px; margin-bottom: 8px; color: #ff6b6b; }
        #cdn-error p { font-size: 13px; max-width: 400px; line-height: 1.5; }
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

    <!-- Header -->
    <div id="header">
        <div class="shield">T</div>
        <div class="info">
            <div class="name" id="repo-name">...</div>
            <div class="sub">3D Threat Model &middot; TITO</div>
        </div>
    </div>

    <!-- Overview panel -->
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

    <!-- Controls -->
    <div id="controls">
        <button onclick="resetCamera()" title="Reset view">&#9678; <span class="key">R</span></button>
        <button id="btn-labels" class="active" onclick="toggleLabels()" title="Toggle labels">Ab <span class="key">L</span></button>
        <button id="btn-boundaries" class="active" onclick="toggleBoundaries()" title="Toggle boundaries">&#9711; <span class="key">B</span></button>
        <button id="btn-particles" class="active" onclick="toggleParticles()" title="Toggle particles">~ <span class="key">P</span></button>
        <button onclick="toggleAttackPaths()" title="Attack paths">&#9876; <span class="key">A</span></button>
        <button onclick="exportScreenshot()" title="Screenshot">&#128247;</button>
    </div>

    <!-- Info panel -->
    <div id="info-panel">
        <button class="close-btn" onclick="closeInfoPanel()">&times;</button>
        <div id="info-content"></div>
    </div>

    <!-- Attack paths panel -->
    <div id="attack-paths-panel">
        <div class="header">
            <h2>&#9876; Attack Paths</h2>
            <button class="close-btn" onclick="closeAttackPathsPanel()">&times;</button>
        </div>
        <div id="attack-paths-list"></div>
    </div>

    <!-- Scripts -->
    <script src="https://unpkg.com/three@0.160.0/build/three.min.js"></script>
    <script src="https://unpkg.com/3d-force-graph@1.75.0/dist/3d-force-graph.min.js"></script>

    <script>
    // ── Error guard ──
    if (typeof THREE === 'undefined' || typeof ForceGraph3D === 'undefined') {
        document.getElementById('cdn-error').classList.add('visible');
        document.getElementById('loading').classList.add('hidden');
    }

    // ── Data ──
    const rawData = {{DIAGRAM_DATA}};
    const attackPaths = {{ATTACK_PATHS}};
    window.rawData = rawData;

    const graphData = {
        nodes: (rawData.nodes || []).map(n => ({
            id: n.id, label: n.label, type: n.type, riskLevel: n.riskLevel || 'low',
            threats: n.threats || [], findings: n.findings || [],
            description: n.description, technology: n.technology
        })),
        links: (rawData.edges || []).map(e => ({
            source: e.source, target: e.target, label: e.label,
            sensitive: !!e.sensitive, encrypted: !!e.encrypted
        }))
    };
    window.graphData = graphData;

    // ── Config ──
    const COLORS = {
        critical: { hex: 0xff2740, emissive: 0xff2740, rgba: 'rgba(255,39,64,1)', name: '#ff2740' },
        high:     { hex: 0xff8c42, emissive: 0xff8c42, rgba: 'rgba(255,140,66,1)', name: '#ff8c42' },
        medium:   { hex: 0xffd23f, emissive: 0xffd23f, rgba: 'rgba(255,210,63,1)', name: '#ffd23f' },
        low:      { hex: 0x00d4aa, emissive: 0x00d4aa, rgba: 'rgba(0,212,170,1)', name: '#00d4aa' }
    };
    const DEFAULT_COLOR = { hex: 0x4488ff, emissive: 0x2244aa };
    const NODE_SIZES = { critical: 22, high: 16, medium: 12, low: 9 };

    let labelsVisible = true;
    let boundariesVisible = true;
    let particlesVisible = true;
    let autoRotate = true;
    let lastInteraction = Date.now();
    let currentAttackPathIdx = null;
    let boundaryMeshes = [];

    // ── Init Graph ──
    const elem = document.getElementById('graph-container');
    const Graph = ForceGraph3D()(elem);

    Graph.graphData(graphData)
        .nodeLabel(null)
        .nodeAutoColorBy(null)
        .nodeThreeObject(node => createNodeObject(node))
        .linkWidth(link => link.__inAttackPath ? 3 : (link.sensitive ? 1.5 : 1))
        .linkColor(link => {
            if (link.__inAttackPath) return '#ff6b6b';
            return link.sensitive ? 'rgba(255,68,85,0.5)' : 'rgba(68,136,255,0.35)';
        })
        .linkOpacity(l => l.__inAttackPath ? 0.9 : 0.4)
        .linkDirectionalParticles(l => l.__inAttackPath ? 6 : (particlesVisible ? 2 : 0))
        .linkDirectionalParticleSpeed(l => l.__inAttackPath ? 0.012 : 0.004)
        .linkDirectionalParticleWidth(l => l.__inAttackPath ? 3 : 1.5)
        .linkDirectionalParticleColor(l => l.__inAttackPath ? '#ff6b6b' : '#4488ff')
        .onNodeClick(node => { showNodeInfo(node); flyToNode(node); })
        .onNodeHover(node => { elem.style.cursor = node ? 'pointer' : null; })
        .d3Force('charge').strength(-150);
    Graph.d3Force('link').distance(120);

    window.Graph = Graph;

    // ── Scene setup ──
    const scene = Graph.scene();
    scene.background = new THREE.Color(0x060a1a);

    // Fog
    scene.fog = new THREE.FogExp2(0x060a1a, 0.0012);

    // Lights
    const ambient = new THREE.AmbientLight(0x6688cc, 0.35);
    scene.add(ambient);

    const coolLight = new THREE.DirectionalLight(0x4488ff, 1.2);
    coolLight.position.set(200, 300, 200);
    scene.add(coolLight);

    const warmLight = new THREE.DirectionalLight(0xff8844, 0.6);
    warmLight.position.set(-200, -100, -300);
    scene.add(warmLight);

    const rimLight = new THREE.DirectionalLight(0x88ccff, 0.3);
    rimLight.position.set(-100, 200, -200);
    scene.add(rimLight);

    // Star field
    (function addStars() {
        const g = new THREE.BufferGeometry();
        const verts = [];
        for (let i = 0; i < 1200; i++) {
            const r = 1200 + Math.random() * 800;
            const theta = Math.random() * Math.PI * 2;
            const phi = Math.acos(2 * Math.random() - 1);
            verts.push(r * Math.sin(phi) * Math.cos(theta), r * Math.sin(phi) * Math.sin(theta), r * Math.cos(phi));
        }
        g.setAttribute('position', new THREE.Float32BufferAttribute(verts, 3));
        const m = new THREE.PointsMaterial({ color: 0x8899cc, size: 0.8, transparent: true, opacity: 0.6 });
        scene.add(new THREE.Points(g, m));
    })();

    // Ground grid
    const grid = new THREE.GridHelper(1000, 40, 0x1a2255, 0x111833);
    grid.position.y = -220;
    scene.add(grid);

    // Subtle ground glow
    const groundGlow = new THREE.Mesh(
        new THREE.PlaneGeometry(1000, 1000),
        new THREE.MeshBasicMaterial({ color: 0x0a0e27, transparent: true, opacity: 0.3, side: THREE.DoubleSide })
    );
    groundGlow.rotation.x = -Math.PI / 2;
    groundGlow.position.y = -218;
    scene.add(groundGlow);

    // ── Node factory ──
    function createNodeObject(node) {
        const c = COLORS[node.riskLevel] || DEFAULT_COLOR;
        const sz = NODE_SIZES[node.riskLevel] || 8;

        const group = new THREE.Group();

        // Glow sphere (outer halo)
        const glowGeo = new THREE.SphereGeometry(sz * 0.6, 24, 24);
        const glowMat = new THREE.MeshBasicMaterial({
            color: c.hex, transparent: true, opacity: 0.15
        });
        const glow = new THREE.Mesh(glowGeo, glowMat);
        glow.scale.set(2, 2, 2);
        group.add(glow);

        // Core sphere with PBR-ish material
        const coreGeo = new THREE.SphereGeometry(sz, 32, 32);
        const coreMat = new THREE.MeshStandardMaterial({
            color: c.hex,
            emissive: c.emissive || c.hex,
            emissiveIntensity: 0.25,
            metalness: 0.5,
            roughness: 0.3,
            envMapIntensity: 0.6
        });
        const core = new THREE.Mesh(coreGeo, coreMat);
        group.add(core);

        // Inner bright core
        const innerGeo = new THREE.SphereGeometry(sz * 0.3, 16, 16);
        const innerMat = new THREE.MeshBasicMaterial({
            color: c.hex, transparent: true, opacity: 0.4
        });
        const inner = new THREE.Mesh(innerGeo, innerMat);
        group.add(inner);

        // Pulse data for critical
        if (node.riskLevel === 'critical') {
            group.userData.pulse = true;
        }

        // Label sprite
        const sprite = createLabelSprite(node.label, node.riskLevel);
        sprite.position.y = sz + 14;
        group.add(sprite);
        group.userData.labelSprite = sprite;

        return group;
    }

    function createLabelSprite(text, riskLevel) {
        const short = text.length > 22 ? text.substring(0, 20) + '..' : text;
        const canvas = document.createElement('canvas');
        canvas.width = 320;
        canvas.height = 72;

        const ctx = canvas.getContext('2d');

        // Shadow
        ctx.shadowColor = 'rgba(0,0,0,0.6)';
        ctx.shadowBlur = 8;
        ctx.shadowOffsetY = 2;

        ctx.fillStyle = '#ffffff';
        ctx.font = '600 26px -apple-system, "Segoe UI", Inter, sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'bottom';
        ctx.fillText(short, 160, 64);

        // Accent line
        ctx.shadowColor = 'transparent';
        const c = COLORS[riskLevel];
        if (c) {
            ctx.fillStyle = c.name;
            ctx.fillRect(120, 66, 80, 2);
        }

        const tex = new THREE.CanvasTexture(canvas);
        tex.minFilter = THREE.LinearFilter;
        const mat = new THREE.SpriteMaterial({ map: tex, transparent: true, depthWrite: false });
        const sprite = new THREE.Sprite(mat);
        sprite.scale.set(50, 12, 1);
        return sprite;
    }

    // ── Trust boundaries ──
    function addTrustBoundaries(boundaries) {
        const s = Graph.scene();
        let placed = 0;

        const tryPlace = () => {
            let allDone = true;
            boundaries.forEach(b => {
                const members = graphData.nodes.filter(n => b.nodes.includes(n.id));
                if (members.length === 0) return;
                const obj = Graph.nodeThreeObject(members[0]);
                if (!obj || (obj.position && obj.position.x === 0 && obj.position.y === 0 && obj.position.z === 0)) {
                    allDone = false;
                    return;
                }
                if (b._placed) return;

                let minX = Infinity, maxX = -Infinity;
                let minY = Infinity, maxY = -Infinity;
                let minZ = Infinity, maxZ = -Infinity;
                members.forEach(n => {
                    const o = Graph.nodeThreeObject(n);
                    if (!o) return;
                    const p = o.position;
                    if (p) {
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

                const boxGeo = new THREE.BoxGeometry(sx, sy, sz);
                const boxMat = new THREE.MeshPhysicalMaterial({
                    color: color, transparent: true, opacity: 0.04,
                    side: THREE.BackSide, roughness: 0.5, metalness: 0.1
                });
                const box = new THREE.Mesh(boxGeo, boxMat);
                box.position.set(cx, cy, cz);
                s.add(box);

                const edgeGeo = new THREE.EdgesGeometry(boxGeo);
                const edgeMat = new THREE.LineBasicMaterial({
                    color: color, transparent: true, opacity: 0.2
                });
                const wire = new THREE.LineSegments(edgeGeo, edgeMat);
                wire.position.set(cx, cy, cz);
                s.add(wire);

                // Label
                const lblCanvas = document.createElement('canvas');
                lblCanvas.width = 512; lblCanvas.height = 64;
                const lctx = lblCanvas.getContext('2d');
                lctx.fillStyle = '#' + color.getHexString();
                lctx.font = 'bold 28px -apple-system, sans-serif';
                lctx.textAlign = 'center';
                lctx.textBaseline = 'middle';
                lctx.shadowColor = 'rgba(0,0,0,0.5)';
                lctx.shadowBlur = 6;
                lctx.fillText(b.name, 256, 36);
                const lblTex = new THREE.CanvasTexture(lblCanvas);
                const lblMat = new THREE.SpriteMaterial({ map: lblTex, transparent: true, opacity: 0.5, depthWrite: false });
                const lbl = new THREE.Sprite(lblMat);
                lbl.position.set(cx, maxY + pad + 15, cz);
                lbl.scale.set(70, 9, 1);
                s.add(lbl);

                boundaryMeshes.push({ box, wire, lbl, visible: true });
                b._placed = true;
                placed++;
            });
            if (!allDone && placed < boundaries.length) {
                setTimeout(tryPlace, 200);
            }
        };
        setTimeout(tryPlace, 100);
    }

    if (rawData.trustBoundaries && rawData.trustBoundaries.length > 0) {
        addTrustBoundaries(rawData.trustBoundaries);
    }

    // ── Animation loop ──
    Graph.onEngineTick(() => {
        // Pulse critical nodes
        graphData.nodes.forEach(node => {
            const obj = Graph.nodeThreeObject(node);
            if (obj && obj.userData && obj.userData.pulse) {
                const s = 1 + Math.sin(Date.now() * 0.0025) * 0.12;
                obj.scale.set(s, s, s);
            }
        });

        // Auto-rotate
        if (autoRotate && Date.now() - lastInteraction > 5000) {
            const cam = Graph.camera();
            const dist = cam.position.length();
            const angle = Date.now() * 0.00008;
            cam.position.x = dist * Math.sin(angle);
            cam.position.z = dist * Math.cos(angle);
            cam.lookAt(scene.position);
        }
    });

    elem.addEventListener('mousedown', () => { lastInteraction = Date.now(); });
    elem.addEventListener('wheel', () => { lastInteraction = Date.now(); });

    // ── Warmup ──
    Graph.numDimensions(3);
    for (let i = 0; i < 250; i++) Graph.tickFrame();

    // ── Hide loading ──
    setTimeout(() => {
        document.getElementById('loading').classList.add('hidden');
    }, 400);

    // ── Overview stats ──
    (function initOverview() {
        const m = rawData.metadata || {};
        const repoName = (m.repository || '').split('/').pop() || 'unknown';
        document.getElementById('repo-name').textContent = repoName;

        const statsEl = document.getElementById('overview-stats');
        statsEl.innerHTML =
            '<div class="stat-row"><span class="lbl">Nodes</span><span class="val">' + (m.totalNodes || graphData.nodes.length) + '</span></div>' +
            '<div class="stat-row"><span class="lbl">Edges</span><span class="val">' + (m.totalEdges || graphData.links.length) + '</span></div>' +
            '<div class="stat-row"><span class="lbl">Threats</span><span class="val">' + (m.totalThreats || 0) + '</span></div>';

        const counts = { critical: 0, high: 0, medium: 0, low: 0 };
        graphData.nodes.forEach(n => { if (counts[n.riskLevel] !== undefined) counts[n.riskLevel]++; });
        document.getElementById('cnt-critical').textContent = counts.critical;
        document.getElementById('cnt-high').textContent = counts.high;
        document.getElementById('cnt-medium').textContent = counts.medium;
        document.getElementById('cnt-low').textContent = counts.low;
    })();

    // ── Keyboard shortcuts ──
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
    //  GLOBAL CONTROL FUNCTIONS
    // ══════════════════════════════════════════

    window.resetCamera = function() {
        window.Graph.cameraPosition({ x: 0, y: 30, z: 380 }, { x: 0, y: 0, z: 0 }, 800);
        lastInteraction = Date.now();
    };

    window.toggleLabels = function() {
        labelsVisible = !labelsVisible;
        const btn = document.getElementById('btn-labels');
        btn.classList.toggle('active');
        graphData.nodes.forEach(node => {
            const obj = Graph.nodeThreeObject(node);
            if (obj && obj.userData && obj.userData.labelSprite) {
                obj.userData.labelSprite.visible = labelsVisible;
            }
        });
    };

    window.toggleBoundaries = function() {
        boundariesVisible = !boundariesVisible;
        const btn = document.getElementById('btn-boundaries');
        btn.classList.toggle('active');
        boundaryMeshes.forEach(b => {
            b.box.visible = boundariesVisible;
            b.wire.visible = boundariesVisible;
            b.lbl.visible = boundariesVisible;
        });
    };

    window.toggleParticles = function() {
        particlesVisible = !particlesVisible;
        const btn = document.getElementById('btn-particles');
        btn.classList.toggle('active');
        Graph.linkDirectionalParticles(l => l.__inAttackPath ? 6 : (particlesVisible ? 2 : 0));
    };

    window.toggleAttackPaths = function() {
        const panel = document.getElementById('attack-paths-panel');
        const isVisible = panel.style.display !== 'none';
        panel.style.display = isVisible ? 'none' : 'block';
        panel.classList.toggle('visible', !isVisible);
        if (!isVisible && attackPaths && attackPaths.length > 0) {
            initializeAttackPathsPanel();
        }
        if (isVisible) {
            clearAttackPathHighlight();
        }
        lastInteraction = Date.now();
    };

    window.closeAttackPathsPanel = function() {
        document.getElementById('attack-paths-panel').style.display = 'none';
        clearAttackPathHighlight();
    };

    window.exportScreenshot = function() {
        const renderer = Graph.renderer();
        if (!renderer) return;
        const canvas = renderer.domElement;
        const dataURL = canvas.toDataURL('image/png');
        const link = document.createElement('a');
        link.download = 'tito-3d-threat-model.png';
        link.href = dataURL;
        link.click();
    };

    // ── Node interaction ──
    function flyToNode(node) {
        if (!node.x) return;
        const dist = 180;
        const r = 1 + dist / Math.hypot(node.x, node.y, node.z);
        Graph.cameraPosition(
            { x: node.x * r, y: node.y * r + 20, z: node.z * r },
            node, 800
        );
        lastInteraction = Date.now();
    }

    window.showNodeInfo = function(node) {
        const panel = document.getElementById('info-panel');
        const content = document.getElementById('info-content');
        const c = COLORS[node.riskLevel] || { name: '#4488ff' };
        const color = c.name || '#4488ff';

        let html = '<h3 style="color:' + color + '">' + (node.label || 'Unknown') + '</h3>';
        html += '<div class="info-sect"><h4>Type</h4><div class="info-val">' + (node.type || '—') + '</div></div>';
        html += '<div class="info-sect"><h4>Risk Level</h4><div class="info-val" style="color:' + color + '">' + (node.riskLevel || 'unknown').toUpperCase() + '</div></div>';
        html += '<div class="info-sect"><h4>Threats</h4><div class="info-val">' + (node.threats ? node.threats.length : 0) + ' identified</div></div>';

        if (node.description) {
            html += '<div class="info-sect"><h4>Description</h4><div class="info-val">' + node.description + '</div></div>';
        }

        if (node.findings && node.findings.length > 0) {
            html += '<div class="info-sect"><h4>Findings</h4>';
            node.findings.slice(0, 6).forEach(f => {
                const sev = f.severity || 'medium';
                html += '<div class="finding ' + sev + '"><div class="ftitle">' + (f.title || '') + '</div>' +
                    '<div class="fdesc">' + (f.description ? f.description.substring(0, 120) : '') + '</div>';
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

    window.closeInfoPanel = function() {
        document.getElementById('info-panel').classList.remove('visible');
    };

    // ── Attack paths ──
    window.initializeAttackPathsPanel = function() {
        const list = document.getElementById('attack-paths-list');
        if (!attackPaths || attackPaths.length === 0) {
            list.innerHTML = '<div style="color:rgba(255,255,255,0.35);text-align:center;padding:20px;font-size:12px">No attack paths found</div>';
            return;
        }

        let html = '';
        attackPaths.forEach((path, i) => {
            const rl = getRiskLevel(path.compositeRisk);
            const rc = rl.toLowerCase();
            html += '<div class="ap-item ' + rc + '" id="ap-' + i + '" onclick="selectAttackPath(' + i + ')">' +
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
        currentAttackPathIdx = idx;
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
        path.steps.forEach(s => {
            pathNodeIds.add(s.fromNode);
            pathNodeIds.add(s.toNode);
            pathLinkPairs.add(s.fromNode + '::' + s.toNode);
        });

        graphData.nodes.forEach(n => {
            n.__inAttackPath = pathNodeIds.has(n.id);
            n.__isEntryPoint = n.id === path.entryPoint;
            n.__isTarget = n.id === path.target;
        });
        graphData.links.forEach(l => {
            const sid = (typeof l.source === 'object' ? l.source.id : l.source) || '';
            const tid = (typeof l.target === 'object' ? l.target.id : l.target) || '';
            l.__inAttackPath = pathLinkPairs.has(sid + '::' + tid);
        });

        Graph.nodeThreeObject(node => {
            const isEntry = node.__isEntryPoint;
            const isTarget = node.__isTarget;
            const inPath = node.__inAttackPath;

            let group = createNodeObject(node);

            // Override color for path highlights
            if (isEntry || isTarget || inPath) {
                const highlightColor = isEntry ? 0x00ff88 : (isTarget ? 0xff2740 : 0xff8c42);
                const child = group.children.find(c => c.type === 'Mesh' && c.material && c.material.emissive);
                if (child) {
                    child.material = child.material.clone();
                    child.material.emissive.setHex(highlightColor);
                    child.material.emissiveIntensity = 0.6;
                }
                // Glow
                const glowChild = group.children.find(c => c.type === 'Mesh' && c.material && c.material.opacity === 0.15);
                if (glowChild) {
                    glowChild.material = glowChild.material.clone();
                    glowChild.material.color.setHex(highlightColor);
                    glowChild.scale.set(3, 3, 3);
                }
            }

            // Re-attach label sprite from original if it exists
            const origObj = Graph.nodeThreeObject(node);
            if (origObj && origObj.userData && origObj.userData.labelSprite) {
                const labelClone = origObj.userData.labelSprite.clone();
                labelClone.visible = labelsVisible;
                group.add(labelClone);
                group.userData.labelSprite = labelClone;
            }

            return group;
        });

        Graph.linkColor(l => l.__inAttackPath ? '#ff6b6b' : '#4488ff');
        Graph.linkWidth(l => l.__inAttackPath ? 3 : 1);
        Graph.linkDirectionalParticles(l => l.__inAttackPath ? 8 : (particlesVisible ? 2 : 0));
    }

    window.clearAttackPathHighlight = function() {
        currentAttackPathIdx = null;
        graphData.nodes.forEach(n => { n.__inAttackPath = false; n.__isEntryPoint = false; n.__isTarget = false; });
        graphData.links.forEach(l => { l.__inAttackPath = false; });

        Graph.nodeThreeObject(node => {
            const g = createNodeObject(node);
            // Preserve labels
            const orig = Graph.nodeThreeObject(node);
            if (orig && orig.userData && orig.userData.labelSprite) {
                const lbl = orig.userData.labelSprite.clone();
                lbl.visible = labelsVisible;
                g.add(lbl);
                g.userData.labelSprite = lbl;
            }
            if (node.riskLevel === 'critical') g.userData.pulse = true;
            return g;
        });

        Graph.linkColor(l => l.sensitive ? 'rgba(255,68,85,0.5)' : 'rgba(68,136,255,0.35)');
        Graph.linkWidth(1);
        Graph.linkDirectionalParticles(l => particlesVisible ? 2 : 0);
    };

    // ── Helpers ──
    function getRiskLevel(s) { if (s >= 8.0) return 'CRITICAL'; if (s >= 6.0) return 'HIGH'; if (s >= 4.0) return 'MEDIUM'; return 'LOW'; }
    function getRiskEmoji(s) { if (s >= 8.0) return '\u{1F534}'; if (s >= 6.0) return '\u{1F7E0}'; if (s >= 4.0) return '\u{1F7E1}'; return '\u{1F7E2}'; }
    function getDifficultyLevel(d) { if (d < 0.1) return 'TRIVIAL'; if (d < 0.3) return 'LOW'; if (d < 0.6) return 'MEDIUM'; if (d < 0.8) return 'HIGH'; return 'VERY HIGH'; }
    function getGraphNode(id) { return graphData.nodes.find(n => n.id === id); }

    console.log('TITO 3D visualization ready');
    </script>
</body>
</html>`
