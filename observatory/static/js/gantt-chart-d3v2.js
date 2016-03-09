/**
 * @author Dimitry Kudrayvtsev
 * @version 2.0
 */

d3.gantt = function() {
    
    var margin = {
	top : 20,
	right : 40,
	bottom : 20,
	left : 150 
    };
    var timeDomainStart = d3.time.day.offset(new Date(),-3);
    var timeDomainEnd = d3.time.hour.offset(new Date(),+3);
    var taskTypes = [];
    var statusExplanation = {};
    var height = document.body.clientHeight - margin.top - margin.bottom-5;
    var width = document.body.clientWidth - margin.right - margin.left-5;
    var sortmethod = "end";
    
    var color = d3.scale.ordinal()
      .domain(["active-sha256","expired-sha256","active-sha1","expired-sha1","active-ecdsa","expired-ecdsa","active-md5","expired-md5","active-other","expired-other"])
      .range(['#2ca02c','url(#diagonalHatchGreen)','#1f77b4','url(#diagonalHatchBlue)','#ff7f0e', 'url(#diagonalHatchOrange)', '#9467bd','url(#diagonalHatchPurple)', "#aaa","url(#diagonalHatchGray)", "#f00"]);
    
    var legendRectSize = 18;
    var legendSpacing = 4;

    var tickFormat = "%H:%M";

    var keyFunction = function(d) {
        if(d != undefined){
            //return d.startDate + d.taskName + d.endDate;
            return d.endDate + d.taskName + d.startDate;
        }
    };

    var x = d3.time.scale.utc().domain([ timeDomainStart, timeDomainEnd ]).nice(d3.time.year, 1).range([ 0, width ]).clamp(true);

    var y = d3.scale.ordinal().domain(taskTypes).rangeRoundBands([ 0, height - margin.top - margin.bottom ], .1);
    
    var xAxis = d3.svg.axis().scale(x).orient("bottom").tickFormat(d3.time.format(tickFormat)).tickSubdivide(true)
	    .tickSize(8).tickPadding(8);

    var yAxis = d3.svg.axis().scale(y).orient("left").tickSize(0);

    var initTimeDomain = function() {
	    if (tasks === undefined || tasks.length < 1) {
		timeDomainStart = d3.time.year.offset(new Date(), -1);
		timeDomainEnd = d3.time.year.offset(new Date(), +1);
		return;
	    }
	    tasks.sort(function(a, b) {
		return a.endDate - b.endDate;
	    });
	    timeDomainEnd = d3.time.year.offset(tasks[tasks.length - 1].endDate, +1);
	    tasks.sort(function(a, b) {
		return a.startDate - b.startDate;
	    });
	    timeDomainStart = d3.time.year.offset(tasks[0].startDate, -1);
            if(sortmethod == "end"){
                tasks.sort(function(a, b) {
                    return a.endDate - b.endDate;
                });
            }
    };

    var initAxis = function() {
	x = d3.time.scale.utc().domain([ timeDomainStart, timeDomainEnd ]).nice(d3.time.year, 1).range([ 0, width ]).clamp(true);
	y = d3.scale.ordinal().domain(taskTypes).rangeRoundBands([ 0, height - margin.top - margin.bottom ], .1);
	xAxis = d3.svg.axis().scale(x).orient("bottom").tickFormat(d3.time.format(tickFormat)).tickSubdivide(true)
		.tickSize(8).tickPadding(8);

	yAxis = d3.svg.axis().scale(y).orient("left").tickSize(0);
    };
    
    function gantt(tasks) {
        
        taskTypes = [];
        tasks.forEach(function(d,i){taskTypes.push(d.taskName)});
	
	initTimeDomain();
	initAxis();
	
	var svg = d3.select("#chart")
	.append("svg")
	.attr("class", "chart")
	.attr("width", width + margin.left + margin.right)
	.attr("height", height + margin.top + margin.bottom + color.domain().length * (legendRectSize + legendSpacing));
        
           
        
        g = svg.append("g")
        .attr("class", "gantt-chart")
	.attr("width", width + margin.left + margin.right)
	.attr("height", height + margin.top + margin.bottom)
	.attr("transform", "translate(" + margin.left + ", " + margin.top + ")") 
        .on("mouseover", function() { focus.style("display", null); })
            .on("mouseout", function() { focus.style("display", "none"); })
            .on("mousemove", mousemove);
        
        g.append("rect")
            .attr("class", "background")
            .attr("width", width)
            .attr("height", height);
             
        // Patterns (stripes)
        var defs = svg.append("defs");
        defs.append('pattern')
            .attr('id', 'diagonalHatchGray')
            .attr('patternUnits', 'userSpaceOnUse')
            .attr('width', 8)
            .attr('height', 8)
            .append('path')
            .attr('d', 'M-2,2 l4,-4 M0,8 l8,-8 M6,10 l4,-4')
            .attr('stroke', '#666')
            .attr('stroke-width', 2);
        defs.append('pattern')
            .attr('id', 'diagonalHatchGreen')
            .attr('patternUnits', 'userSpaceOnUse')
            .attr('width', 8)
            .attr('height', 8)
            .append('path')
            .attr('d', 'M-2,2 l4,-4 M0,8 l8,-8 M6,10 l4,-4')
            .attr('stroke', '#2ca02c')
            .attr('stroke-width', 2);
        defs.append('pattern')
            .attr('id', 'diagonalHatchBlue')
            .attr('patternUnits', 'userSpaceOnUse')
            .attr('width', 8)
            .attr('height', 8)
            .append('path')
            .attr('d', 'M-2,2 l4,-4 M0,8 l8,-8 M6,10 l4,-4')
            .attr('stroke', '#1f77b4')
            .attr('stroke-width', 2);
        defs.append('pattern')
            .attr('id', 'diagonalHatchOrange')
            .attr('patternUnits', 'userSpaceOnUse')
            .attr('width', 8)
            .attr('height', 8)
            .append('path')
            .attr('d', 'M-2,2 l4,-4 M0,8 l8,-8 M6,10 l4,-4')
            .attr('stroke', '#ff7f0e')
            .attr('stroke-width', 2);
        defs.append('pattern')
            .attr('id', 'diagonalHatchPurple')
            .attr('patternUnits', 'userSpaceOnUse')
            .attr('width', 8)
            .attr('height', 8)
            .append('path')
            .attr('d', 'M-2,2 l4,-4 M0,8 l8,-8 M6,10 l4,-4')
            .attr('stroke', '#9467bd')
            .attr('stroke-width', 2);
	
        // insert the bars
        g.selectAll(".certificate-bar")
	 .data(tasks, keyFunction).enter()
	 .append("rect")
	 .attr("rx", 1)
         .attr("ry", 1)
         .attr("class", "certificate-bar")
         .attr("fill", function(d){
             return color(gantt.mapcolor(d.status));
         })
	 .attr("x", function(d){return x(d.startDate)})
	 .attr("y", function(d){return y(d.taskName)})
	 .attr("height", function(d) { return y.rangeBand(); })
	 .attr("width", function(d) { 
	     return (x(d.endDate) - x(d.startDate)); 
	     })
         .on("click", function(d) { window.location.href = "../" + d.taskName; });
	 
	 
	g.append("g")
	 .attr("class", "x axis")
	 .attr("transform", "translate(0, " + (height - margin.top - margin.bottom) + ")")
	 .transition()
	 .call(xAxis);
	 
	g.append("g").attr("class", "y axis").transition().call(yAxis);
         
        var legendItems = [];
        tasks.forEach(function(d){
            var item = gantt.mapcolor(d.status);
            if(legendItems.indexOf(item) == -1){
                legendItems.push(item);
            }
        });
         
         // Draw a legend that lists the colors/fills and their respective meanings
         var legend = svg.selectAll('.legend')
            //.data(color.domain())
            .data(legendItems)
            .enter()
            .append('g')
            .attr('class', 'legend')
            .attr('transform', function(d, i) {
                var height = legendRectSize + legendSpacing;
                var horz = 2 * legendRectSize;
                var vert = gantt.height() + margin.top + i * height;
                return 'translate(' + horz + ',' + vert + ')';
            });

        legend.append('rect')
            .attr('width', legendRectSize)
            .attr('height', legendRectSize)
            .style('fill', color)
            .style('stroke', color);

        legend.append('text')
            .attr('x', legendRectSize + legendSpacing)
            .attr('y', legendRectSize - legendSpacing)
            .text(function(d) { return statusExplanation[d]; });
         
            
        // add a line and overlay text where the cursor is
        var focus = svg.append("g")
            .attr("class", "focus")
            .style("display", "none");

        var focustext = focus.append("text")
            .attr("x", 9)
            .attr("dy", ".35em");
        
        focus.append("line")
            .attr("x1", 0)
            .attr("y1", margin.top)
            .attr("x2", 0)
            .attr("y2", height - margin.bottom)
            .style("stroke-width", 1)
            .style("stroke", "red")
            .style("fill", "none");

        var dateFormat = d3.time.format.utc("%Y-%m-%d");

        function mousemove() {
            var x0 = d3.mouse(this)[0],
                y0 = d3.mouse(this)[1];
            focus.attr("transform", "translate(" + (x0+margin.left) + ",0)");
            focus.select("text").text(dateFormat(x.invert(x0))).attr("transform", "translate(0," + (y0+margin.top) + ")");
        }
	 
	 return gantt;

    };
    
    gantt.orderStart = function() {
         var y0 = y.domain(tasks.sort(
             function(a, b) { return b.startDate - a.startDate;})
        .map(function(d) { return d.taskName; }))
        .copy();
        
        d3.select('.gantt-chart').selectAll(".certificate-bar")
        .sort(function(a, b) { return y0(a.taskName) - y0(b.taskName); });

    var transition = d3.select('.gantt-chart').transition().duration(500),
        delay = function(d, i) { return i * 20; };

        
    transition.selectAll(".certificate-bar")
        .delay(delay)
        .attr("transform", "translate(0,0)")
        .attr("y", function(d) { return y0(d.taskName);})
        .attr("x", function(d) { return x(d.startDate);});
        
    transition.select(".y.axis")
        .call(yAxis)
      .selectAll("g")
        .delay(delay);
    }
    
    gantt.orderEnd = function() {
         var y0 = y.domain(tasks.sort(
             function(a, b) { return b.endDate - a.endDate;})
        .map(function(d) { return d.taskName; }))
        .copy();
        
        d3.select('.gantt-chart').selectAll(".certificate-bar")
        .sort(function(a, b) { return y0(a.taskName) - y0(b.taskName); });

    var transition = d3.select('.gantt-chart').transition().duration(500),
        delay = function(d, i) { return i * 20; };

        
    transition.selectAll(".certificate-bar")
        .delay(delay)
        .attr("transform", "translate(0,0)")
        .attr("y", function(d) { return y0(d.taskName);})
        .attr("x", function(d) { return x(d.startDate);});
        
    transition.select(".y.axis")
        .call(yAxis)
      .selectAll("g")
        .delay(delay);
    }
    
    gantt.orderLength = function() {
        var y0 = y.domain(tasks.sort(
            function(a, b) { return (a.endDate - a.startDate) - (b.endDate - b.startDate);})
            .map(function(d) { return d.taskName; }))
            .copy();
            
        d3.select('.gantt-chart').selectAll(".certificate-bar")
            .sort(function(a, b) { return y0(a.taskName) - y0(b.taskName); });

        var transition = d3.select('.gantt-chart').transition().duration(500),
            delay = function(d, i) { return i * 10; };

            
        transition.selectAll(".certificate-bar")
            .delay(delay)
            .attr("transform", "translate(0,0)")
            .attr("y", function(d) { return y0(d.taskName);})
            .attr("x", function(d) { return x(d.startDate);});
            
        transition.select(".y.axis")
            .call(yAxis)
        .selectAll("g")
            .delay(delay);
    }
    
    gantt.redraw = function() {

	d3.select("#chart").select("svg").remove();
        
        return gantt(tasks);
    };

    gantt.margin = function(value) {
	if (!arguments.length)
	    return margin;
	margin = value;
	return gantt;
    };

    gantt.timeDomain = function(value) {
	if (!arguments.length)
	    return [ timeDomainStart, timeDomainEnd ];
	timeDomainStart = +value[0], timeDomainEnd = +value[1];
	return gantt;
    };

    /**
     * @param {string}
     *                vale The value can be "fit" - the domain fits the data or
     *                "fixed" - fixed domain.
     */
    gantt.timeDomainMode = function(value) {
	if (!arguments.length)
	    return timeDomainMode;
        timeDomainMode = value;
        return gantt;

    };

    gantt.statusExplanation = function(value) {
	if (!arguments.length)
	    return statusExplanation;
	statusExplanation = value;
	return gantt;
    };

    gantt.width = function(value) {
	if (!arguments.length)
	    return width;
	width = +value;
	return gantt;
    };

    gantt.height = function(value) {
	if (!arguments.length)
	    return height;
	height = +value;
	return gantt;
    };

    gantt.tickFormat = function(value) {
        if (!arguments.length)
            return tickFormat;
        tickFormat = value;
        return gantt;
    };
    
    gantt.color = function(value) {
	if (!arguments.length)
	    return color;
	color = value;
	return gantt;
    };
    
    gantt.mapcolor = function(value) {
        var status = "expired";
        var algorithm = "other";
        var startpos = 5;
        if(value.substring(0,6) == "False-"){
            status = "active";
            startpos = 6;
        }
        if(value.substring(startpos, startpos+4) == "sha1"){
            algorithm = "sha1";
        }
        else if(value.substring(startpos, startpos+3) == "md5"){
            algorithm = "md5";
        }
        else if(value.substring(startpos, startpos+6) == "sha256"){
            algorithm = "sha256";
        }
        else if(value.substring(startpos, startpos+5) == "ecdsa"){
            algorithm = "ecdsa";
        }
        return status+"-"+algorithm;
    }


    
    return gantt;
};
