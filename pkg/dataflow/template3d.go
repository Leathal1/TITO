package dataflow

const htmlTemplate3D = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{TITLE}} - 3D Visualization</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #000011;
            color: #ffffff;
            overflow: hidden;
        }

        #graph-container {
            width: 100vw;
            height: 100vh;
        }

        /* Header */
        #header {
            position: absolute;
            top: 20px;
            left: 20px;
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            padding: 20px 30px;
            z-index: 100;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        }

        #header h1 {
            font-size: 24px;
            font-weight: 600;
            color: #ffffff;
            margin-bottom: 5px;
        }

        #header .subtitle {
            font-size: 13px;
            color: rgba(255, 255, 255, 0.6);
        }

        /* Overview Panel */
        #overview {
            position: absolute;
            top: 20px;
            right: 20px;
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            padding: 20px;
            z-index: 100;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            min-width: 280px;
        }

        #overview h2 {
            font-size: 16px;
            color: #58a6ff;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }

        .stat {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            font-size: 13px;
        }

        .stat-label {
            color: rgba(255, 255, 255, 0.6);
        }

        .stat-value {
            color: #ffffff;
            font-weight: 600;
        }

        .risk-breakdown {
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
        }

        .risk-item {
            display: flex;
            align-items: center;
            padding: 5px 0;
            font-size: 12px;
        }

        .risk-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 10px;
            box-shadow: 0 0 8px currentColor;
        }

        /* Controls */
        #controls {
            position: absolute;
            bottom: 20px;
            left: 20px;
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            padding: 20px;
            z-index: 100;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        }

        #controls h2 {
            font-size: 14px;
            color: #ffffff;
            margin-bottom: 12px;
        }

        button {
            background: rgba(255, 255, 255, 0.1);
            color: #ffffff;
            border: 1px solid rgba(255, 255, 255, 0.2);
            padding: 10px 20px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 12px;
            margin: 5px 0;
            width: 200px;
            transition: all 0.3s ease;
            font-weight: 500;
        }

        button:hover {
            background: rgba(255, 255, 255, 0.2);
            border-color: #58a6ff;
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(88, 166, 255, 0.3);
        }

        button:active {
            transform: translateY(0);
        }

        /* Info Panel */
        #info-panel {
            position: absolute;
            top: 50%;
            right: 20px;
            transform: translateY(-50%);
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            padding: 20px;
            z-index: 100;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            min-width: 320px;
            max-width: 400px;
            max-height: 70vh;
            overflow-y: auto;
            display: none;
        }

        #info-panel.visible {
            display: block;
            animation: slideIn 0.3s ease;
        }

        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(-50%) translateX(20px);
            }
            to {
                opacity: 1;
                transform: translateY(-50%) translateX(0);
            }
        }

        #info-panel h3 {
            font-size: 18px;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }

        .info-section {
            margin: 15px 0;
        }

        .info-section h4 {
            font-size: 13px;
            color: rgba(255, 255, 255, 0.6);
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .info-value {
            font-size: 14px;
            color: #ffffff;
            margin-bottom: 10px;
        }

        .finding {
            background: rgba(0, 0, 0, 0.3);
            border-left: 3px solid;
            padding: 12px;
            margin: 8px 0;
            border-radius: 4px;
            font-size: 12px;
        }

        .finding.critical { border-color: #ff0040; }
        .finding.high { border-color: #ff6600; }
        .finding.medium { border-color: #ffcc00; }
        .finding.low { border-color: #00ff88; }

        .finding-title {
            font-weight: 600;
            margin-bottom: 5px;
        }

        .finding-desc {
            color: rgba(255, 255, 255, 0.6);
            font-size: 11px;
            line-height: 1.5;
        }

        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 10px;
            font-weight: 600;
            margin: 2px;
        }

        .badge.stride { background: #1f6feb; color: white; }
        .badge.maestro { background: #8957e5; color: white; }
        .badge.attack { background: #da3633; color: white; }

        .close-btn {
            position: absolute;
            top: 15px;
            right: 15px;
            background: rgba(255, 255, 255, 0.1);
            border: none;
            color: white;
            font-size: 20px;
            cursor: pointer;
            width: 30px;
            height: 30px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 0;
        }

        .close-btn:hover {
            background: rgba(255, 255, 255, 0.2);
        }

        /* Scrollbar */
        #info-panel::-webkit-scrollbar {
            width: 8px;
        }

        #info-panel::-webkit-scrollbar-track {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 4px;
        }

        #info-panel::-webkit-scrollbar-thumb {
            background: rgba(255, 255, 255, 0.2);
            border-radius: 4px;
        }

        #info-panel::-webkit-scrollbar-thumb:hover {
            background: rgba(255, 255, 255, 0.3);
        }

        /* Loading */
        #loading {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            font-size: 18px;
            color: rgba(255, 255, 255, 0.6);
            z-index: 200;
        }

        /* Attack Paths Panel */
        #attack-paths-panel {
            position: absolute;
            top: 110px;
            right: 20px;
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 68, 68, 0.3);
            border-radius: 12px;
            padding: 20px;
            z-index: 101;
            box-shadow: 0 8px 32px rgba(255, 0, 0, 0.2);
            min-width: 350px;
            max-width: 400px;
            max-height: 70vh;
            overflow-y: auto;
        }

        .attack-path-item {
            background: rgba(0, 0, 0, 0.3);
            border-left: 4px solid;
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .attack-path-item:hover {
            background: rgba(0, 0, 0, 0.5);
            transform: translateX(-3px);
        }

        .attack-path-item.critical { border-color: #ff0040; }
        .attack-path-item.high { border-color: #ff6600; }
        .attack-path-item.medium { border-color: #ffcc00; }
        .attack-path-item.low { border-color: #00ff88; }

        .attack-path-item.active {
            background: rgba(255, 68, 68, 0.2);
            border-width: 4px;
        }

        .attack-path-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }

        .attack-path-risk {
            font-size: 20px;
            font-weight: 700;
        }

        .attack-path-title {
            font-size: 14px;
            font-weight: 600;
            margin-bottom: 8px;
            color: #ffffff;
        }

        .attack-path-summary {
            font-size: 12px;
            color: rgba(255, 255, 255, 0.7);
            line-height: 1.6;
        }

        .attack-path-stats {
            margin-top: 10px;
            padding-top: 10px;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            font-size: 11px;
            color: rgba(255, 255, 255, 0.6);
        }

        .play-attack-btn {
            margin-top: 10px;
            width: 100%;
            background: rgba(255, 68, 68, 0.3);
            border-color: #ff4444;
        }

        .play-attack-btn:hover {
            background: rgba(255, 68, 68, 0.5);
        }

        #attack-paths-panel::-webkit-scrollbar {
            width: 8px;
        }

        #attack-paths-panel::-webkit-scrollbar-track {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 4px;
        }

        #attack-paths-panel::-webkit-scrollbar-thumb {
            background: rgba(255, 68, 68, 0.3);
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <div id="loading">🚀 Loading 3D Threat Model...</div>
    <div id="graph-container"></div>

    <div id="header">
        <h1>🛡️ TITO 3D Threat Model</h1>
        <div class="subtitle">Interactive 3D Data Flow Visualization</div>
    </div>

    <div id="overview">
        <h2>📊 Overview</h2>
        <div id="overview-stats"></div>
        <div class="risk-breakdown">
            <div class="risk-item">
                <div class="risk-dot" style="background: #ff0040;"></div>
                <span>Critical: <strong id="critical-count">0</strong></span>
            </div>
            <div class="risk-item">
                <div class="risk-dot" style="background: #ff6600;"></div>
                <span>High: <strong id="high-count">0</strong></span>
            </div>
            <div class="risk-item">
                <div class="risk-dot" style="background: #ffcc00;"></div>
                <span>Medium: <strong id="medium-count">0</strong></span>
            </div>
            <div class="risk-item">
                <div class="risk-dot" style="background: #00ff88;"></div>
                <span>Low: <strong id="low-count">0</strong></span>
            </div>
        </div>
    </div>

    <div id="controls">
        <h2>⚙️ Controls</h2>
        <button id="reset-camera">🎯 Reset Camera</button>
        <button id="toggle-labels">🏷️ Toggle Labels</button>
        <button id="toggle-boundaries">🛡️ Toggle Boundaries</button>
        <button id="toggle-particles">✨ Toggle Particles</button>
        <button id="toggle-attack-paths">⚔️ Show Attack Paths</button>
        <button id="export-screenshot">📸 Export Screenshot</button>
    </div>

    <div id="info-panel">
        <button class="close-btn" onclick="closeInfoPanel()">×</button>
        <div id="info-content"></div>
    </div>

    <div id="attack-paths-panel" style="display: none;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
            <h2 style="font-size: 18px; color: #ff4444;">⚔️ Attack Paths</h2>
            <button class="close-btn" onclick="closeAttackPathsPanel()">×</button>
        </div>
        <div id="attack-paths-list"></div>
    </div>

    <script src="https://unpkg.com/three@0.160.0/build/three.min.js"></script>
    <script src="https://unpkg.com/3d-force-graph@1.74.0/dist/3d-force-graph.min.js"></script>

    <script>

        // Data from Go
        const rawData = {{DIAGRAM_DATA}};
        const attackPaths = {{ATTACK_PATHS}};

        // Transform data for 3d-force-graph
        const graphData = {
            nodes: rawData.nodes.map(node => ({
                id: node.id,
                label: node.label,
                type: node.type,
                riskLevel: node.riskLevel,
                threats: node.threats || [],
                findings: node.findings || [],
                description: node.description,
                technology: node.technology
            })),
            links: rawData.edges.map(edge => ({
                source: edge.source,
                target: edge.target,
                label: edge.label,
                sensitive: edge.sensitive,
                encrypted: edge.encrypted
            }))
        };

        // Configuration
        let labelsVisible = true;
        let boundariesVisible = true;
        let particlesVisible = true;
        let currentAttackPath = null;
        let attackPathParticles = [];
        let autoRotate = true;
        let lastInteraction = Date.now();

        // Risk colors and sizes
        const riskConfig = {
            critical: { color: 0xff0040, size: 20, emissive: 0xff0040, emissiveIntensity: 0.8 },
            high: { color: 0xff6600, size: 15, emissive: 0xff6600, emissiveIntensity: 0.6 },
            medium: { color: 0xffcc00, size: 10, emissive: 0xffcc00, emissiveIntensity: 0.4 },
            low: { color: 0x00ff88, size: 8, emissive: 0x00ff88, emissiveIntensity: 0.3 }
        };

        // Initialize graph
        const elem = document.getElementById('graph-container');
        const Graph = ForceGraph3D()(elem)
            .graphData(graphData)
            .nodeLabel('label')
            .nodeAutoColorBy('riskLevel')
            .nodeThreeObject(node => {
                const config = riskConfig[node.riskLevel] || riskConfig.low;
                
                const geometry = new THREE.SphereGeometry(config.size, 32, 32);
                const material = new THREE.MeshStandardMaterial({
                    color: config.color,
                    emissive: config.emissive,
                    emissiveIntensity: config.emissiveIntensity,
                    metalness: 0.3,
                    roughness: 0.4
                });
                
                const sphere = new THREE.Mesh(geometry, material);
                
                // Add pulsing animation for critical nodes
                if (node.riskLevel === 'critical') {
                    sphere.userData.pulse = true;
                }
                
                // Add label
                if (labelsVisible) {
                    const sprite = createTextSprite(node.label);
                    sprite.position.y = config.size + 15;
                    sphere.add(sprite);
                    sphere.userData.labelSprite = sprite;
                }
                
                return sphere;
            })
            .linkWidth(2)
            .linkColor(link => link.sensitive ? '#ff0040' : '#4488ff')
            .linkOpacity(0.6)
            .linkDirectionalParticles(link => particlesVisible ? 2 : 0)
            .linkDirectionalParticleSpeed(0.005)
            .linkDirectionalParticleWidth(2)
            .linkDirectionalParticleColor(link => link.sensitive ? '#ff0040' : '#4488ff')
            .onNodeClick(node => {
                showNodeInfo(node);
                // Smooth camera fly-to
                const distance = 200;
                const distRatio = 1 + distance/Math.hypot(node.x, node.y, node.z);
                Graph.cameraPosition(
                    { x: node.x * distRatio, y: node.y * distRatio, z: node.z * distRatio },
                    node,
                    1000
                );
            })
            .onNodeHover(node => {
                elem.style.cursor = node ? 'pointer' : null;
            })
            .d3Force('charge').strength(-120);
        
        Graph.d3Force('link').distance(100);

        // Add stars background
        addStarField();

        // Add grid plane
        addGridPlane();

        // Add trust boundaries
        if (rawData.trustBoundaries && rawData.trustBoundaries.length > 0) {
            addTrustBoundaries(rawData.trustBoundaries);
        }

        // Setup scene enhancements
        const scene = Graph.scene();
        scene.background = new THREE.Color(0x000011);
        
        // Ambient light
        const ambientLight = new THREE.AmbientLight(0xffffff, 0.3);
        scene.add(ambientLight);
        
        // Point lights for drama
        const pointLight1 = new THREE.PointLight(0x4488ff, 1, 500);
        pointLight1.position.set(200, 200, 200);
        scene.add(pointLight1);
        
        const pointLight2 = new THREE.PointLight(0xff0040, 1, 500);
        pointLight2.position.set(-200, -200, -200);
        scene.add(pointLight2);

        // Animation loop for pulsing and rotation
        Graph.onEngineTick(() => {
            // Pulse critical nodes
            graphData.nodes.forEach(node => {
                const obj = Graph.nodeThreeObject(node);
                if (obj && obj.userData.pulse) {
                    const scale = 1 + Math.sin(Date.now() * 0.003) * 0.15;
                    obj.scale.set(scale, scale, scale);
                }
            });

            // Auto-rotate when inactive
            if (autoRotate && Date.now() - lastInteraction > 5000) {
                const camera = Graph.camera();
                const distance = camera.position.length();
                const angle = Date.now() * 0.0001;
                camera.position.x = distance * Math.sin(angle);
                camera.position.z = distance * Math.cos(angle);
                camera.lookAt(scene.position);
            }
        });

        // Track interaction
        elem.addEventListener('mousedown', () => {
            lastInteraction = Date.now();
        });
        elem.addEventListener('wheel', () => {
            lastInteraction = Date.now();
        });

        // Warmup simulation
        Graph.numDimensions(3);
        for (let i = 0; i < 200; i++) {
            Graph.tickFrame();
        }

        // Initialize controls after Graph is ready
        setTimeout(initializeControls, 100);

        // Helper functions
        function createTextSprite(text) {
            const canvas = document.createElement('canvas');
            const context = canvas.getContext('2d');
            canvas.width = 256;
            canvas.height = 64;
            
            context.fillStyle = 'rgba(255, 255, 255, 0.9)';
            context.font = 'bold 24px Arial';
            context.textAlign = 'center';
            context.textBaseline = 'middle';
            context.fillText(text.substring(0, 20), 128, 32);
            
            const texture = new THREE.CanvasTexture(canvas);
            const material = new THREE.SpriteMaterial({ map: texture, transparent: true });
            const sprite = new THREE.Sprite(material);
            sprite.scale.set(40, 10, 1);
            
            return sprite;
        }

        function addStarField() {
            const starGeometry = new THREE.BufferGeometry();
            const starMaterial = new THREE.PointsMaterial({
                color: 0xffffff,
                size: 1,
                transparent: true,
                opacity: 0.8
            });

            const starVertices = [];
            for (let i = 0; i < 1000; i++) {
                const x = (Math.random() - 0.5) * 2000;
                const y = (Math.random() - 0.5) * 2000;
                const z = (Math.random() - 0.5) * 2000;
                starVertices.push(x, y, z);
            }

            starGeometry.setAttribute('position', new THREE.Float32BufferAttribute(starVertices, 3));
            const stars = new THREE.Points(starGeometry, starMaterial);
            scene.add(stars);
        }

        function addGridPlane() {
            const gridHelper = new THREE.GridHelper(800, 40, 0x222244, 0x111122);
            gridHelper.position.y = -200;
            scene.add(gridHelper);
        }

        function addTrustBoundaries(boundaries) {
            const scene = Graph.scene();
            // Wait for the graph layout to stabilize before positioning boundaries
            setTimeout(() => {
                boundaries.forEach(boundary => {
                    const memberNodes = graphData.nodes.filter(n => boundary.nodes.includes(n.id));
                    if (memberNodes.length === 0) return;

                    // Compute bounding box of member nodes
                    let minX = Infinity, maxX = -Infinity;
                    let minY = Infinity, maxY = -Infinity;
                    let minZ = Infinity, maxZ = -Infinity;

                    memberNodes.forEach(n => {
                        const obj = Graph.nodeThreeObject(n);
                        if (obj) {
                            const p = obj.position;
                            minX = Math.min(minX, p.x); maxX = Math.max(maxX, p.x);
                            minY = Math.min(minY, p.y); maxY = Math.max(maxY, p.y);
                            minZ = Math.min(minZ, p.z); maxZ = Math.max(maxZ, p.z);
                        }
                    });

                    if (!isFinite(minX)) return;

                    const pad = 30;
                    const cx = (minX + maxX) / 2;
                    const cy = (minY + maxY) / 2;
                    const cz = (minZ + maxZ) / 2;
                    const sx = (maxX - minX) + pad * 2;
                    const sy = (maxY - minY) + pad * 2;
                    const sz = (maxZ - minZ) + pad * 2;

                    // Semi-transparent bounding box
                    const color = new THREE.Color(boundary.color || '#888888');
                    const geometry = new THREE.BoxGeometry(
                        Math.max(sx, 20), Math.max(sy, 20), Math.max(sz, 20)
                    );
                    const material = new THREE.MeshPhongMaterial({
                        color: color,
                        transparent: true,
                        opacity: 0.06,
                        side: THREE.DoubleSide
                    });
                    const box = new THREE.Mesh(geometry, material);
                    box.position.set(cx, cy, cz);
                    scene.add(box);

                    // Wireframe edges
                    const edgeGeo = new THREE.EdgesGeometry(geometry);
                    const edgeMat = new THREE.LineBasicMaterial({
                        color: color, transparent: true, opacity: 0.35
                    });
                    const wireframe = new THREE.LineSegments(edgeGeo, edgeMat);
                    wireframe.position.set(cx, cy, cz);
                    scene.add(wireframe);

                    // Label using sprite
                    const canvas = document.createElement('canvas');
                    canvas.width = 512; canvas.height = 64;
                    const ctx = canvas.getContext('2d');
                    ctx.fillStyle = boundary.color || '#888888';
                    ctx.font = 'bold 32px Arial';
                    ctx.textAlign = 'center';
                    ctx.fillText(boundary.name, 256, 40);
                    const texture = new THREE.CanvasTexture(canvas);
                    const spriteMat = new THREE.SpriteMaterial({
                        map: texture, transparent: true, opacity: 0.7
                    });
                    const sprite = new THREE.Sprite(spriteMat);
                    sprite.position.set(cx, maxY + pad + 10, cz);
                    sprite.scale.set(60, 8, 1);
                    scene.add(sprite);
                });
            }, 3000); // Wait for layout
        }

        function showNodeInfo(node) {
            const panel = document.getElementById('info-panel');
            const content = document.getElementById('info-content');
            
            const config = riskConfig[node.riskLevel] || riskConfig.low;
            const colorHex = '#' + config.color.toString(16).padStart(6, '0');
            
            let html = ` + "`" + `
                <h3 style="color: ${colorHex};">${node.label}</h3>
                <div class="info-section">
                    <h4>Type</h4>
                    <div class="info-value">${node.type}</div>
                </div>
                <div class="info-section">
                    <h4>Risk Level</h4>
                    <div class="info-value" style="color: ${colorHex};">${node.riskLevel.toUpperCase()}</div>
                </div>
                <div class="info-section">
                    <h4>Threats</h4>
                    <div class="info-value">${node.threats.length} identified</div>
                </div>
            ` + "`" + `;

            if (node.description) {
                html += ` + "`" + `
                    <div class="info-section">
                        <h4>Description</h4>
                        <div class="info-value">${node.description}</div>
                    </div>
                ` + "`" + `;
            }

            if (node.findings && node.findings.length > 0) {
                html += '<div class="info-section"><h4>Findings</h4>';
                node.findings.slice(0, 5).forEach(f => {
                    html += ` + "`" + `
                        <div class="finding ${f.severity}">
                            <div class="finding-title">${f.title}</div>
                            <div class="finding-desc">${f.description.substring(0, 150)}...</div>
                            ${f.stride ? '<span class="badge stride">STRIDE: '+f.stride+'</span>' : ''}
                            ${f.maestro ? '<span class="badge maestro">MAESTRO: '+f.maestro+'</span>' : ''}
                            ${f.attackIds && f.attackIds.length > 0 ? '<span class="badge attack">MITRE: '+f.attackIds[0]+'</span>' : ''}
                        </div>
                    ` + "`" + `;
                });
                html += '</div>';
            }

            content.innerHTML = html;
            panel.classList.add('visible');
        }

        function closeInfoPanel() {
            document.getElementById('info-panel').classList.remove('visible');
        }
        window.closeInfoPanel = closeInfoPanel;

        // Controls initialization function
        function initializeControls() {
            document.getElementById('reset-camera').addEventListener('click', () => {
            Graph.cameraPosition(
                { x: 0, y: 0, z: 400 },
                { x: 0, y: 0, z: 0 },
                1000
            );
        });

        document.getElementById('toggle-labels').addEventListener('click', () => {
            labelsVisible = !labelsVisible;
            graphData.nodes.forEach(node => {
                const obj = Graph.nodeThreeObject(node);
                if (obj && obj.userData.labelSprite) {
                    obj.userData.labelSprite.visible = labelsVisible;
                }
            });
        });

        document.getElementById('toggle-boundaries').addEventListener('click', () => {
            boundariesVisible = !boundariesVisible;
            // Would toggle boundary visibility here
        });

        document.getElementById('toggle-particles').addEventListener('click', () => {
            particlesVisible = !particlesVisible;
            Graph.linkDirectionalParticles(link => particlesVisible ? 2 : 0);
        });

        document.getElementById('export-screenshot').addEventListener('click', () => {
            const renderer = Graph.renderer();
            const canvas = renderer.domElement;
            const dataURL = canvas.toDataURL('image/png');
            const link = document.createElement('a');
            link.download = 'tito-3d-threat-model.png';
            link.href = dataURL;
            link.click();
        });

        // Attack paths control
        document.getElementById('toggle-attack-paths').addEventListener('click', () => {
            const panel = document.getElementById('attack-paths-panel');
            const isVisible = panel.style.display !== 'none';
            panel.style.display = isVisible ? 'none' : 'block';
            if (!isVisible && attackPaths && attackPaths.length > 0) {
                initializeAttackPathsPanel();
            }
        });
        }  // End initializeControls

        function closeAttackPathsPanel() {
            document.getElementById('attack-paths-panel').style.display = 'none';
            clearAttackPathHighlight();
        }
        window.closeAttackPathsPanel = closeAttackPathsPanel;

        function initializeAttackPathsPanel() {
            const list = document.getElementById('attack-paths-list');
            if (!attackPaths || attackPaths.length === 0) {
                list.innerHTML = '<div style="color: rgba(255,255,255,0.6); text-align: center; padding: 20px;">No attack paths found</div>';
                return;
            }

            let html = '';
            attackPaths.forEach((path, index) => {
                const riskLevel = getRiskLevel(path.compositeRisk);
                const riskClass = riskLevel.toLowerCase();
                const emoji = getRiskEmoji(path.compositeRisk);
                
                html += ` + "`" + `
                    <div class="attack-path-item ${riskClass}" id="attack-path-${index}" onclick="selectAttackPath(${index})">
                        <div class="attack-path-header">
                            <span class="attack-path-risk">${emoji} ${riskLevel}</span>
                            <span style="font-size: 18px; font-weight: 700; color: #ff4444;">${path.compositeRisk.toFixed(1)}/10</span>
                        </div>
                        <div class="attack-path-title">
                            Path #${index + 1}: ${path.steps.length} steps
                        </div>
                        <div class="attack-path-summary">
                            ${getGraphNode(path.entryPoint)?.label || path.entryPoint} → 
                            ${getGraphNode(path.target)?.label || path.target}
                        </div>
                        <div class="attack-path-stats">
                            Difficulty: ${getDifficultyLevel(path.totalDifficulty)}<br>
                            ${path.mitreTactics && path.mitreTactics.length > 0 ? 'Tactics: ' + path.mitreTactics.slice(0, 3).join(', ') : ''}
                        </div>
                    </div>
                ` + "`" + `;
            });

            list.innerHTML = html;
        }

        function selectAttackPath(index) {
            currentAttackPath = index;
            
            // Update active state
            document.querySelectorAll('.attack-path-item').forEach((el, i) => {
                el.classList.toggle('active', i === index);
            });

            // Highlight path on graph
            highlightAttackPath(attackPaths[index]);
        }
        window.selectAttackPath = selectAttackPath;

        function highlightAttackPath(path) {
            if (!path || !path.steps) return;

            // Clear previous highlights
            clearAttackPathHighlight();

            // Collect nodes and links in path
            const pathNodeIds = new Set();
            const pathLinkIds = new Set();

            pathNodeIds.add(path.entryPoint);
            path.steps.forEach(step => {
                pathNodeIds.add(step.fromNode);
                pathNodeIds.add(step.toNode);
                pathLinkIds.add(step.fromNode + '-' + step.toNode);
            });

            // Highlight nodes - set a property the graph can read
            graphData.nodes.forEach(node => {
                node.__inAttackPath = pathNodeIds.has(node.id);
                node.__isEntryPoint = node.id === path.entryPoint;
                node.__isTarget = node.id === path.target;
            });

            // Highlight links
            graphData.links.forEach(link => {
                const linkId = link.source.id ? link.source.id + '-' + link.target.id : link.source + '-' + link.target;
                link.__inAttackPath = pathLinkIds.has(linkId);
            });

            // Force graph update
            Graph.nodeColor(node => {
                if (node.__isEntryPoint) return '#00ff00';
                if (node.__isTarget) return '#ff0040';
                if (node.__inAttackPath) return '#ff4444';
                return riskConfig[node.riskLevel]?.color || 0x888888;
            });

            Graph.linkColor(link => {
                if (link.__inAttackPath) return '#ff4444';
                return link.sensitive ? 'rgba(255, 100, 100, 0.4)' : 'rgba(100, 100, 100, 0.3)';
            });

            Graph.linkWidth(link => link.__inAttackPath ? 4 : 1);
            Graph.linkDirectionalParticles(link => link.__inAttackPath ? 8 : (particlesVisible ? 2 : 0));
            Graph.linkDirectionalParticleSpeed(link => link.__inAttackPath ? 0.01 : 0.005);
        }

        function clearAttackPathHighlight() {
            graphData.nodes.forEach(node => {
                node.__inAttackPath = false;
                node.__isEntryPoint = false;
                node.__isTarget = false;
            });

            graphData.links.forEach(link => {
                link.__inAttackPath = false;
            });

            // Reset colors
            Graph.nodeColor(node => riskConfig[node.riskLevel]?.color || 0x888888);
            Graph.linkColor(link => link.sensitive ? 'rgba(255, 100, 100, 0.4)' : 'rgba(100, 100, 100, 0.3)');
            Graph.linkWidth(1);
            Graph.linkDirectionalParticles(link => particlesVisible ? 2 : 0);
            Graph.linkDirectionalParticleSpeed(0.005);
        }

        function getRiskLevel(score) {
            if (score >= 8.0) return 'CRITICAL';
            if (score >= 6.0) return 'HIGH';
            if (score >= 4.0) return 'MEDIUM';
            return 'LOW';
        }

        function getRiskEmoji(score) {
            if (score >= 8.0) return '🔴';
            if (score >= 6.0) return '🟠';
            if (score >= 4.0) return '🟡';
            return '🟢';
        }

        function getDifficultyLevel(difficulty) {
            if (difficulty < 0.1) return 'TRIVIAL';
            if (difficulty < 0.3) return 'LOW';
            if (difficulty < 0.6) return 'MEDIUM';
            if (difficulty < 0.8) return 'HIGH';
            return 'VERY HIGH';
        }

        function getGraphNode(nodeId) {
            return graphData.nodes.find(n => n.id === nodeId);
        }

        // Initialize overview stats
        const stats = document.getElementById('overview-stats');
        const repoName = rawData.metadata.repository.split('/').pop();
        stats.innerHTML = ` + "`" + `
            <div class="stat"><span class="stat-label">Repository:</span><span class="stat-value">${repoName}</span></div>
            <div class="stat"><span class="stat-label">Nodes:</span><span class="stat-value">${rawData.metadata.totalNodes}</span></div>
            <div class="stat"><span class="stat-label">Edges:</span><span class="stat-value">${rawData.metadata.totalEdges}</span></div>
            <div class="stat"><span class="stat-label">Threats:</span><span class="stat-value">${rawData.metadata.totalThreats}</span></div>
        ` + "`" + `;

        // Calculate risk breakdown
        const riskCounts = { critical: 0, high: 0, medium: 0, low: 0 };
        graphData.nodes.forEach(node => {
            riskCounts[node.riskLevel] = (riskCounts[node.riskLevel] || 0) + 1;
        });

        document.getElementById('critical-count').textContent = riskCounts.critical;
        document.getElementById('high-count').textContent = riskCounts.high;
        document.getElementById('medium-count').textContent = riskCounts.medium;
        document.getElementById('low-count').textContent = riskCounts.low;

        // Hide loading
        document.getElementById('loading').style.display = 'none';
    </script>
</body>
</html>
`
