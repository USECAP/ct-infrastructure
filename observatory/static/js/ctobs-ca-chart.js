/* 
 * This file contains the functions for drawing the CA relation graphs
 */

function draw_ca_graph(graphdata, panelwidth){
	var nodes = {};

	// Compute the distinct nodes from the links.
	graphdata.edges.forEach(function(link) {
		link.source = nodes[link.source] || (nodes[link.source] = {name: link.source});
		link.target = nodes[link.target] || (nodes[link.target] = {name: link.target});
	});

	var width = 960,
	height = 500;

	var force = d3.layout.force()
	.nodes(d3.values(nodes))
	.links(graphdata["edges"])
	.size([width, height])
	.linkDistance(200)
	.friction(0.9)
	.charge(-300)
	.on("tick", tick)
	.start();

	var drag = force.drag()
	.on("dragstart", dragstart);

	var svg = d3.select("#treeview").append("svg")
	.attr("width", panelwidth)
	.attr("height", height);

	svg.append("defs").append("marker")
	.attr("id", "arrow")
	.attr("viewBox", "0 -5 10 10")
	.attr("refX", 15)
	.attr("refY", -1.5)
	.attr("markerWidth", 8)
	.attr("markerHeight", 8)
	.attr("orient", "auto")
	.append("path")
	.attr("d", "M0,-5L10,0L0,5");

	var path = svg.append("g").selectAll("path")
	.data(force.links())
	.enter().append("path")
	.attr("class", function(d) { return "link"; })
	.attr("marker-end", function(d) { return "url(#arrow)"; });

	var circle = svg.append("g").selectAll("circle")
	.data(force.nodes())
	.enter().append("circle")
	.attr("r", 15)
	.attr("class", function(d){
		if(graphdata["names"][d.name]["current"]){
			return "current";
		}else{
			return "";
		}
	})
	.call(force.drag);

	var text = svg.append("g").selectAll("text")
	.data(force.nodes())
	.enter().append("text")
	.attr("x", 18)
	.attr("y", ".31em")
	.text(function(d) { return graphdata["names"][d.name]["name"]; })
	.on("click", function(d){
		window.location.href = "../"+d.name;
	});


	// Use elliptical arc path segments to doubly-encode directionality.
	function tick() {
		
		path.attr("d", linkArc);
		circle.attr("transform", transform);
		text.attr("transform", transform);
	}

	function linkArc(d) {
		var dx = d.target.x - d.source.x,
		dy = d.target.y - d.source.y,
		dr = Math.sqrt(dx * dx + dy * dy);
		return "M" + d.source.x + "," + d.source.y + "A" + dr + "," + dr + " 0 0,1 " + d.target.x + "," + d.target.y;
	}

	function transform(d) {
		return "translate(" + d.x + "," + d.y + ")";
	}

	function dragstart(d) {
		d3.select(this).classed("fixed", d.fixed = true);
	}
}