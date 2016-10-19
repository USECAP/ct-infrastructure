/* 
 * This file contains the functions that fetch pre-generated diagram data
 * and draw the corresponding diagrams on the index page of the CT observatory.
 * 
 */

$(function(){
	
	//getloginfo
	
	try{
	d3.json("/static/data/getloginfo", function(error, data){
		d3.select('#certsinlogdistribution .spinner').remove();
		if(error){
			d3.select('#certsinlogdistribution').text("No data available.");
		} else {
			nv.addGraph(function() {
				var chart = nv.models.multiBarHorizontalChart()
				.x(function(d) { return d.label })
				.y(function(d) { return d.value })
				.margin({top: 20, right: 20, bottom: 20, left: 20})
				.showValues(true)
				.showLegend(false)
				.showXAxis(false)
				.stacked(true)
				;
				
				chart.yAxis
				.tickFormat(d3.format('d'));
				
				chart.valueFormat(d3.format('d'));
				
				chart.tooltip.valueFormatter(function(d,i){
					return d+ " ("+d3.format(',.2f')(d*100/data.unique_certificates)+"%)";
				});
				
				d3.select('#certsinlogdistribution svg')
				.datum(data.data)
				.call(chart);
				
				nv.utils.windowResize(chart.update);
				
				return chart;
			});
			
			// create table underneath diagram
			$.each(data.data, function(index, log){
				$('#logentries').append("<tr><td style='background-color: "+log.color+"'></td><td> <a href='/log/"+log.id+"'>"+log.key+"</a></td><td>"+log.values[0].value+"</td></tr>");
			});
		}
	});
	} catch(err){
		console.log(err);
		d3.select('#certsinlogdistribution').text("An error occured.");
	}
	
	//getlogdist
	try{
	d3.json("/static/data/getlogdist", function(error, json) {
		d3.select('#distributionchart .spinner').remove();
		if(error){
			d3.select('#distributionchart').text("No data available.");
		} else {
			nv.addGraph(function() {
				var chart = nv.models.pieChart()
				.x(function(d) { return d.logs })
				.y(function(d) { return d.certificates })
				.showLabels(true)
				.labelType("percent")
				;
				
				chart.tooltip.keyFormatter(function(d){
					return "Certificates in "+d+" logs";
				});
				
				chart.tooltip.valueFormatter(function(d,i){
					return d3.format('d')(d);
				});
				if (error) return console.warn(error);
				d3.select("#distributionchart svg")
				.datum(json.data)
				.transition().duration(350)
				.call(chart);
				
				return chart;
			});
		}
	});
	} catch(err){
		console.log(err);
		d3.select('#distributionchart').text("An error occured.");
	}
	
	
	//getcadistribution
	try{
	d3.json('/static/data/getcadistribution', function(error, data) {
		
		d3.select('#cadiagram .spinner').remove();
		if(error){
			d3.select('#cadiagram').text("No data available.");
		} else {
			max_value = 0
			data.data.forEach(function(entry){
				last_element = entry.values[entry.values.length-1];
				last_element_date = new Date(last_element[0].substr(0,4),
							last_element[0].substr(5,2)).getTime();
							if (last_element_date > max_value)
								max_value = last_element_date;
			});
			
			
			var format = d3.time.format('%Y-%m');
			nv.addGraph(function() {
				chart = nv.models.stackedAreaWithFocusChart()
				.options({
					brushExtent: [ 1293836400000, max_value]
				})
				.useInteractiveGuideline(true)
				.x(function(d) { return format.parse(d[0]); })
				.y(function(d) { return d[1]; })
				.duration(300)
				.margin({"left":60});
				
				chart.xAxis.tickFormat(function(d) { return d3.time.format('%Y-%m')(new Date(d)) });
				chart.x2Axis.tickFormat(function(d) { return d3.time.format('%Y-%m')(new Date(d)) });
				chart.yAxis.tickFormat(d3.format('0,'));
				d3.select('#cadiagram svg')
				.datum(data.data)
				.transition().duration(1000)
				.call(chart)
				.each('start', function() {
					setTimeout(function() {
						d3.selectAll('#cadiagram svg *').each(function() {
							if(this.__transition__)
								this.__transition__.duration = 1;
						})
					}, 0)
				});
				nv.utils.windowResize(chart.update);
				return chart;
			});
		}
	});
	} catch(err){
		console.log(err);
		d3.select('#cadiagram').text("An error occured.");
	}
	
	
	//getactivekeysizedistribution
	try{
	d3.json('/static/data/getactivekeysizedistribution', function(error, data) {
		d3.select('#keysizediagram .spinner').remove();
		if(error){
			d3.select('#keysizediagram').text("No data available.");
		} else {
			nv.addGraph(function() {
				var chart = nv.models.multiBarHorizontalChart()
				.x(function(d) { return d.label })
				.y(function(d) { return d.value })
				.margin({top: 20, right: 40, bottom: 20, left: 20})
				.showValues(true)
				.showLegend(true)
				.showXAxis(false)
				.stacked(true)
				
				chart.yAxis
				.tickFormat(d3.format('d'));
				
				chart.valueFormat(d3.format('d'));
				
				d3.select('#keysizediagram svg')
				.datum(data.data)
				.call(chart);
				
				nv.utils.windowResize(chart.update);
				
				return chart;
			});
		}
	});
	} catch(err){
		console.log(err);
		d3.select('#keysizediagram').text("An error occured.");
	}
	
	
	//getsignaturealgorithmdistribution
	try{
	d3.json('/static/data/getsignaturealgorithmdistribution', function(error, data) {
		d3.select('#signaturealgorithmdiagram .spinner').remove();
		if(error){
			d3.select('#signaturealgorithmdiagram').text("No data available.");
		} else {
			max_value = 0
			data.data.forEach(function(entry){
				last_element = entry.values[entry.values.length-1];
				last_element_date = new Date(last_element[0].substr(0,4),
							last_element[0].substr(5,2)).getTime();
							if (last_element_date > max_value)
								max_value = last_element_date;
			});
			
			
			var format = d3.time.format('%Y-%m');
			nv.addGraph(function() {
				chart = nv.models.stackedAreaWithFocusChart()
				.options({
					brushExtent: [ 1293836400000, max_value]
				})
				.useInteractiveGuideline(true)
				.x(function(d) { return format.parse(d[0]); })
				.y(function(d) { return d[1] })
				//.controlLabels({stacked: "Stacked"})
				.duration(300)
				.margin({"left":60});
				
				chart.xAxis.tickFormat(function(d) { return d3.time.format('%Y-%m')(new Date(d)) });
				chart.x2Axis.tickFormat(function(d) { return d3.time.format('%Y-%m')(new Date(d)) });
				chart.yAxis.tickFormat(d3.format('0,'));
				d3.select('#signaturealgorithmdiagram svg')
				.datum(data.data)
				.transition().duration(1000)
				.call(chart)
				.each('start', function() {
					setTimeout(function() {
						d3.selectAll('#signaturealgorithmdiagram svg *').each(function() {
							if(this.__transition__)
								this.__transition__.duration = 1;
						})
					}, 0)
				});
				nv.utils.windowResize(chart.update);
				return chart;
			});
		}
	});
	} catch(err){
		console.log(err);
		d3.select('#signaturealgorithmdiagram').text("An error occured.");
	}
	
});