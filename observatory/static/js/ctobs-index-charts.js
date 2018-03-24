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
				$('#logentries').append("<tr><td style='background-color: "+log.color+"'></td><td> <a href='/log/"+log.id+"'>"+log.key+"</a></td><td>"+log.values[0].value+"</td><td>"+log.values[0].latest_entry_id+" <span class='tag tag-default'>"+log.values[0].fetched_percentage+"</span></td></tr>");
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
			}, function(){
                    d3.selectAll("#cadiagram").on('click', function(d){
                    
                        var text = d3.event.path[9].childNodes[4].innerHTML,
                        match_date = text.match(/<strong class="x-value">([^<]*)<\/strong>/),
                        youGotThis = match_date[1];
                        
                        var rgb = d3.event.path["0"].style.fill.match(/rgb\(([^<]*)\)/);
                        
                        var re = '<td class="key" style="border-bottom-color:.*?(?=\>|$).([^<]*)<\\/td>|rgb\\(' + rgb[1] + '\\);"><\\/div><\\/td><td.*?(?=\>|$).([^<]*)<\\/td>';
                        var rgxp = new RegExp(re);
                        
                        
                        var match_key = text.match(rgxp);
                        
                     
                        var partsArray = youGotThis.split('-');
                       
                        if(typeof match_key[1] == 'undefined')
                            link = "https://localhost/cert/all/1?issuer_ca=&date_notbefore=" + partsArray[1] + "%2F01%2F" + partsArray[0] + "&date_notafter=&is_active=&issuer_ca=" + match_key[2];
                        else
                            link = "https://localhost/cert/all/1?issuer_ca=&date_notbefore=" + partsArray[1] + "%2F01%2F" + partsArray[0] + "&date_notafter=&is_active=&issuer_ca=" + match_key[1];
                        window.open( link, "_blank" );
                        
                        console.log(d3.event.path["0"].style.fill, match_key[1]);
                        
                        //.context.style.fill
                    });
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
			}, function(){
                    d3.selectAll("#signaturealgorithmdiagram").on('click', function(d){
                    
                        var text = d3.event.path[9].childNodes[4].innerHTML,
                        match_date = text.match(/<strong class="x-value">([^<]*)<\/strong>/),
                        youGotThis = match_date[1];
                        
                        
                        
                        var rgb = d3.event.path["0"].style.fill.match(/rgb\(([^<]*)\)/);
                        
                        var re = '<td class="key" style="border-bottom-color:.*?(?=\>|$).([^<]*)<\\/td>|rgb\\(' + rgb[1] + '\\);"><\\/div><\\/td><td.*?(?=\>|$).([^<]*)<\\/td>';
                        var rgxp = new RegExp(re);
                        
                        //https://localhost/cert/all/1?issuer_ca=&date_notbefore=01%2F31%2F2013&date_notbefore_gte=01%2F01%2F2013&is_active=&date_notafter=&date_notafter_lte=
                        var match_key = text.match(rgxp);
                        
                        var partsArray = youGotThis.split('-');
                        
                        
                        if(typeof match_key[1] == 'undefined')
                            link = "https://localhost/cert/all/1?issuer_ca=&date_notbefore=" + partsArray[1] + "%2F31%2F" + partsArray[0] + "&date_notafter=&is_active=&algorithm=" + match_key[2] + "&date_notbefore_gte=" + partsArray[1] + "%2F01%2F" + partsArray[0];
                        else
                            link = "https://localhost/cert/all/1?issuer_ca=&date_notbefore=" + partsArray[1] + "%2F31%2F" + partsArray[0] + "&date_notafter=&is_active=&algorithm=" + match_key[1] + "&date_notbefore_gte=" + partsArray[1] + "%2F01%2F" + partsArray[0];
                        window.open( link, "_blank" );
                        
                        console.log(d3.event.path["0"].style.fill, match_key[1]);
                        
                        //.context.style.fill
                    });
       });
		}
	});
	} catch(err){
		console.log(err);
		d3.select('#signaturealgorithmdiagram').text("An error occured.");
	}
	
});

