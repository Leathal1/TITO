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
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            overflow: hidden;
        }

        #container {
            display: flex;
            height: 100vh;
        }

        #diagram {
            flex: 1;
            position: relative;
            background: linear-gradient(135deg, #0d1117 0%, #161b22 100%);
        }

        #sidebar {
            width: 350px;
            background: #161b22;
            border-left: 1px solid #30363d;
            overflow-y: auto;
            padding: 20px;
        }

        #header {
            position: absolute;
            top: 0;
            left: 0;
            right: 350px;
            background: rgba(22, 27, 34, 0.95);
            backdrop-filter: blur(10px);
            padding: 20px 30px;
            border-bottom: 1px solid #30363d;
            z-index: 100;
        }

        h1 {
            font-size: 24px;
            font-weight: 600;
            color: #58a6ff;
            margin-bottom: 5px;
        }

        .subtitle {
            font-size: 14px;
            color: #8b949e;
        }

        svg {
            width: 100%;
            height: 100%;
        }

        /* Nodes */
        .node circle {
            stroke-width: 3px;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .node:hover circle {
            stroke-width: 5px;
            filter: brightness(1.3);
        }

        .node text {
            font-size: 12px;
            pointer-events: none;
            text-shadow: 0 0 3px #0d1117, 0 0 6px #0d1117;
        }

        .node.critical circle {
            fill: #ff4444;
            stroke: #ff6666;
            animation: pulse-critical 2s infinite;
        }

        .node.high circle {
            fill: #ff8c00;
            stroke: #ffa500;
        }

        .node.medium circle {
            fill: #ffd700;
            stroke: #ffed4e;
        }

        .node.low circle {
            fill: #00d4aa;
            stroke: #00ffcc;
        }

        @keyframes pulse-critical {
            0%, 100% { filter: brightness(1); }
            50% { filter: brightness(1.5); box-shadow: 0 0 20px #ff4444; }
        }

        /* Edges */
        .link {
            stroke: #30363d;
            stroke-width: 2px;
            fill: none;
            transition: all 0.3s ease;
        }

        .link.sensitive {
            stroke: #ff8c00;
            stroke-dasharray: 5,5;
            animation: dash 20s linear infinite;
        }

        @keyframes dash {
            to {
                stroke-dashoffset: -100;
            }
        }

        .link:hover {
            stroke: #58a6ff;
            stroke-width: 3px;
        }

        .link-label {
            font-size: 10px;
            fill: #8b949e;
            pointer-events: none;
        }

        /* Trust Boundaries */
        .trust-boundary {
            fill: none;
            stroke-width: 2px;
            stroke-dasharray: 10,5;
            opacity: 0.5;
            filter: drop-shadow(0 0 10px currentColor);
        }

        /* Sidebar */
        .sidebar-section {
            margin-bottom: 25px;
        }

        .sidebar-section h2 {
            font-size: 16px;
            color: #58a6ff;
            margin-bottom: 12px;
            padding-bottom: 8px;
            border-bottom: 1px solid #30363d;
        }

        .stat {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            font-size: 13px;
        }

        .stat-label {
            color: #8b949e;
        }

        .stat-value {
            color: #c9d1d9;
            font-weight: 600;
        }

        .finding {
            background: #0d1117;
            border-left: 3px solid;
            padding: 12px;
            margin: 10px 0;
            border-radius: 4px;
            font-size: 12px;
        }

        .finding.critical { border-color: #ff4444; }
        .finding.high { border-color: #ff8c00; }
        .finding.medium { border-color: #ffd700; }
        .finding.low { border-color: #00d4aa; }

        .finding-title {
            font-weight: 600;
            margin-bottom: 5px;
        }

        .finding-desc {
            color: #8b949e;
            font-size: 11px;
            line-height: 1.5;
        }

        .badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 10px;
            font-weight: 600;
            margin: 2px;
        }

        .badge.stride { background: #1f6feb; color: white; }
        .badge.maestro { background: #8957e5; color: white; }
        .badge.attack { background: #da3633; color: white; }

        /* Legend */
        #legend {
            position: absolute;
            bottom: 20px;
            left: 20px;
            background: rgba(22, 27, 34, 0.95);
            backdrop-filter: blur(10px);
            padding: 15px;
            border-radius: 8px;
            border: 1px solid #30363d;
            font-size: 12px;
        }

        .legend-item {
            display: flex;
            align-items: center;
            margin: 8px 0;
        }

        .legend-color {
            width: 20px;
            height: 20px;
            border-radius: 50%;
            margin-right: 10px;
            border: 2px solid #fff;
        }

        /* Controls */
        #controls {
            position: absolute;
            top: 100px;
            left: 20px;
            background: rgba(22, 27, 34, 0.95);
            backdrop-filter: blur(10px);
            padding: 15px;
            border-radius: 8px;
            border: 1px solid #30363d;
        }

        button {
            background: #21262d;
            color: #c9d1d9;
            border: 1px solid #30363d;
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 12px;
            margin: 5px 0;
            width: 100%;
            transition: all 0.2s ease;
        }

        button:hover {
            background: #30363d;
            border-color: #58a6ff;
        }

        .glow {
            filter: drop-shadow(0 0 8px currentColor);
        }

        /* Tooltip */
        .tooltip {
            position: absolute;
            background: rgba(22, 27, 34, 0.98);
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 12px;
            font-size: 12px;
            pointer-events: none;
            opacity: 0;
            transition: opacity 0.2s;
            max-width: 300px;
            z-index: 1000;
            box-shadow: 0 4px 12px rgba(0,0,0,0.5);
        }

        .tooltip.show {
            opacity: 1;
        }
    </style>
</head>
<body>
    <div id="container">
        <div id="diagram">
            <div id="header">
                <h1>🛡️ TITO Threat Model</h1>
                <div class="subtitle">Interactive Data Flow Diagram with STRIDE-LM & MAESTRO Analysis</div>
            </div>
            <svg id="svg"></svg>
            <div id="legend">
                <div style="font-weight: 600; margin-bottom: 10px;">Risk Levels</div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #ff4444;"></div>
                    <span>Critical</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #ff8c00;"></div>
                    <span>High</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #ffd700;"></div>
                    <span>Medium</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #00d4aa;"></div>
                    <span>Low</span>
                </div>
            </div>
            <div id="controls">
                <div style="font-weight: 600; margin-bottom: 10px;">Controls</div>
                <button onclick="resetZoom()">Reset View</button>
                <button onclick="exportSVG()">Export SVG</button>
                <button onclick="toggleBoundaries()">Toggle Boundaries</button>
            </div>
        </div>
        <div id="sidebar">
            <div class="sidebar-section">
                <h2>📊 Overview</h2>
                <div id="stats"></div>
            </div>
            <div class="sidebar-section">
                <h2>🔍 Selected Component</h2>
                <div id="selected-info">
                    <p style="color: #8b949e; font-size: 13px;">Click on a node to see details</p>
                </div>
            </div>
        </div>
    </div>
    <div class="tooltip" id="tooltip"></div>

    <script>
        // Data from Go
        const data = {{DIAGRAM_DATA}};

        // Setup
        const width = window.innerWidth - 350;
        const height = window.innerHeight;
        const svg = d3.select("#svg");
        const g = svg.append("g");

        // Zoom
        const zoom = d3.zoom()
            .scaleExtent([0.1, 4])
            .on("zoom", (event) => g.attr("transform", event.transform));
        svg.call(zoom);

        // Force simulation
        const simulation = d3.forceSimulation(data.nodes)
            .force("link", d3.forceLink(data.edges).id(d => d.id).distance(150))
            .force("charge", d3.forceManyBody().strength(-500))
            .force("center", d3.forceCenter(width / 2, height / 2))
            .force("collision", d3.forceCollide().radius(50));

        // Draw trust boundaries
        let boundariesVisible = true;
        const boundaries = g.append("g").attr("class", "boundaries");
        
        // Draw edges
        const link = g.append("g")
            .selectAll("path")
            .data(data.edges)
            .enter().append("path")
            .attr("class", d => "link " + (d.sensitive ? "sensitive" : ""))
            .attr("stroke", d => d.sensitive ? "#ff8c00" : "#30363d");

        // Draw nodes
        const node = g.append("g")
            .selectAll("g")
            .data(data.nodes)
            .enter().append("g")
            .attr("class", d => "node " + d.riskLevel)
            .call(d3.drag()
                .on("start", dragstarted)
                .on("drag", dragged)
                .on("end", dragended));

        node.append("circle")
            .attr("r", 25);

        node.append("text")
            .attr("dy", 40)
            .attr("text-anchor", "middle")
            .attr("fill", "#c9d1d9")
            .text(d => d.label.substring(0, 20));

        // Node click handler
        node.on("click", (event, d) => {
            showNodeDetails(d);
            event.stopPropagation();
        });

        // Tooltips
        const tooltip = d3.select("#tooltip");
        node.on("mouseover", (event, d) => {
            tooltip
                .style("left", (event.pageX + 10) + "px")
                .style("top", (event.pageY - 10) + "px")
                .html(` + "`" + `
                    <strong>${d.label}</strong><br>
                    Type: ${d.type}<br>
                    Risk: <span style="color: ${getRiskColor(d.riskLevel)}">${d.riskLevel}</span><br>
                    Threats: ${d.threats.length}
                ` + "`" + `)
                .classed("show", true);
        }).on("mouseout", () => {
            tooltip.classed("show", false);
        });

        // Update positions
        simulation.on("tick", () => {
            link.attr("d", d => {
                const dx = d.target.x - d.source.x;
                const dy = d.target.y - d.source.y;
                const dr = Math.sqrt(dx * dx + dy * dy);
                return ` + "`M${d.source.x},${d.source.y}A${dr},${dr} 0 0,1 ${d.target.x},${d.target.y}`" + `;
            });

            node.attr("transform", d => ` + "`translate(${d.x},${d.y})`" + `);
        });

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

        function resetZoom() {
            svg.transition().duration(750).call(zoom.transform, d3.zoomIdentity);
        }

        function exportSVG() {
            const svgData = document.getElementById("svg").outerHTML;
            const blob = new Blob([svgData], {type: "image/svg+xml"});
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = "threat-model.svg";
            a.click();
        }

        function toggleBoundaries() {
            boundariesVisible = !boundariesVisible;
            boundaries.style("display", boundariesVisible ? "block" : "none");
        }

        function getRiskColor(risk) {
            const colors = {critical: "#ff4444", high: "#ff8c00", medium: "#ffd700", low: "#00d4aa"};
            return colors[risk] || "#888";
        }

        function showNodeDetails(node) {
            const info = document.getElementById("selected-info");
            let html = ` + "`" + `
                <h3 style="color: ${getRiskColor(node.riskLevel)}; margin-bottom: 10px;">${node.label}</h3>
                <div class="stat"><span class="stat-label">Type:</span><span class="stat-value">${node.type}</span></div>
                <div class="stat"><span class="stat-label">Risk Level:</span><span class="stat-value">${node.riskLevel}</span></div>
                <div class="stat"><span class="stat-label">Threats:</span><span class="stat-value">${node.threats.length}</span></div>
            ` + "`" + `;

            if (node.findings && node.findings.length > 0) {
                html += '<h4 style="margin-top: 15px; margin-bottom: 10px; color: #58a6ff;">Findings:</h4>';
                node.findings.forEach(f => {
                    html += ` + "`" + `
                        <div class="finding ${f.severity}">
                            <div class="finding-title">${f.title}</div>
                            <div class="finding-desc">${f.description.substring(0, 100)}...</div>
                            ${f.stride ? '<span class="badge stride">'+f.stride+'</span>' : ''}
                            ${f.maestro ? '<span class="badge maestro">'+f.maestro+'</span>' : ''}
                        </div>
                    ` + "`" + `;
                });
            }

            info.innerHTML = html;
        }

        // Initialize stats
        const stats = document.getElementById("stats");
        stats.innerHTML = ` + "`" + `
            <div class="stat"><span class="stat-label">Repository:</span><span class="stat-value">${data.metadata.repository.split('/').pop()}</span></div>
            <div class="stat"><span class="stat-label">Branch:</span><span class="stat-value">${data.metadata.branch}</span></div>
            <div class="stat"><span class="stat-label">Total Nodes:</span><span class="stat-value">${data.metadata.totalNodes}</span></div>
            <div class="stat"><span class="stat-label">Data Flows:</span><span class="stat-value">${data.metadata.totalEdges}</span></div>
            <div class="stat"><span class="stat-label">Threats:</span><span class="stat-value">${data.metadata.totalThreats}</span></div>
        ` + "`" + `;
    </script>
</body>
</html>
`
