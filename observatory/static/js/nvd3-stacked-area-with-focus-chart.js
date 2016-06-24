nv.models.stackedAreaWithFocusChart = function() {
    "use strict";

    //============================================================
    // Public Variables with Default Settings
    //------------------------------------------------------------

    var lines = nv.models.stackedArea()
    , lines2 = nv.models.stackedArea()
        , xAxis = nv.models.axis()
        , yAxis = nv.models.axis()
        , x2Axis = nv.models.axis()
        , y2Axis = nv.models.axis()
        , legend = nv.models.legend()
        , controls = nv.models.legend()
        , brush = d3.svg.brush()
        , tooltip = nv.models.tooltip()
        , interactiveLayer = nv.interactiveGuideline()
        ;

    var margin = {top: 30, right: 30, bottom: 30, left: 60}
        , margin2 = {top: 10, right: 30, bottom: 20, left: 60}
        , color = nv.utils.defaultColor()
        , showControls = true
        , showXAxis = true
        , showYAxis = true
        , rightAlignYAxis = false
        , width = null
        , height = null
        , height2 = 60
        , useInteractiveGuideline = false
        , x
        , y
        , x2
        , y2
        , showLegend = true
        , brushExtent = null
        , noData = null
        , dispatch = d3.dispatch('brush', 'stateChange', 'changeState')
        , transitionDuration = 250
        , state = nv.utils.state()
        , defaultState = null
        , controlWidth = 250
        , controlOptions = ['Stacked','Stream','Expanded']
        , controlLabels = {}
        , duration = 250
        ;

    lines.clipEdge(true).duration(0);
    lines2.interactive(false);
    xAxis.orient('bottom').tickPadding(5);
    yAxis.orient('left');
    x2Axis.orient('bottom').tickPadding(5);
    y2Axis.orient('left');

    tooltip
    .headerFormatter(function(d, i) {
        return xAxis.tickFormat()(d, i);
    })
    .valueFormatter(function(d, i) {
        return yAxis.tickFormat()(d, i);
    });
    
    interactiveLayer.tooltip
    .headerFormatter(function(d, i) {
        return xAxis.tickFormat()(d, i);
    })
    .valueFormatter(function(d, i) {
        return yAxis.tickFormat()(d, i);
    });
    
    var oldYTickFormat = null,
 oldValueFormatter = null;
 
 controls.updateState(false);

    //============================================================
    // Private Variables
    //------------------------------------------------------------

    var stateGetter = function(data) {
        return function(){
            return {
                active: data.map(function(d) { return !d.disabled })
            };
        }
    };

    var stateSetter = function(data) {
        return function(state) {
            if (state.active !== undefined)
                data.forEach(function(series,i) {
                    series.disabled = !state.active[i];
                });
        }
    };

    function chart(selection) {
        selection.each(function(data) {
            var container = d3.select(this),
                that = this;
            nv.utils.initSVG(container);
            var availableWidth = nv.utils.availableWidth(width, container, margin),
                availableHeight1 = nv.utils.availableHeight(height, container, margin) - height2,
                availableHeight2 = height2 - margin2.top - margin2.bottom;

            chart.update = function() { container.transition().duration(transitionDuration).call(chart) };
            chart.container = this;

            state
                .setter(stateSetter(data), chart.update)
                .getter(stateGetter(data))
                .update();

            // DEPRECATED set state.disableddisabled
            state.disabled = data.map(function(d) { return !!d.disabled });

            if (!defaultState) {
                var key;
                defaultState = {};
                for (key in state) {
                    if (state[key] instanceof Array)
                        defaultState[key] = state[key].slice(0);
                    else
                        defaultState[key] = state[key];
                }
            }

            // Display No Data message if there's nothing to show.
            if (!data || !data.length || !data.filter(function(d) { return d.values.length }).length) {
                nv.utils.noData(chart, container)
                return chart;
            } else {
                container.selectAll('.nv-noData').remove();
            }

            // Setup Scales
            x = lines.xScale();
            y = lines.yScale();
            x2 = lines2.xScale();
            y2 = lines2.yScale();

            // Setup containers and skeleton of chart
            var wrap = container.selectAll('g.nv-wrap.nv-lineWithFocusChart').data([data]);
            var gEnter = wrap.enter().append('g').attr('class', 'nvd3 nv-wrap nv-lineWithFocusChart').append('g');
            var g = wrap.select('g');

            gEnter.append('g').attr('class', 'nv-legendWrap');
            gEnter.append('g').attr('class', 'nv-controlsWrap');

            var focusEnter = gEnter.append('g').attr('class', 'nv-focus');
            focusEnter.append('g').attr('class', 'nv-x nv-axis');
            focusEnter.append('g').attr('class', 'nv-y nv-axis');
            focusEnter.append('g').attr('class', 'nv-linesWrap');
            focusEnter.append('g').attr('class', 'nv-interactive');

            var contextEnter = gEnter.append('g').attr('class', 'nv-context');
            contextEnter.append('g').attr('class', 'nv-text-instruction')
                .append("text")
                .text("Click and drag to select focus area:")
                .style('text-anchor', 'middle')
                .attr("transform", "translate("+availableWidth/2+", 0)");
            contextEnter.append('g').attr('class', 'nv-x nv-axis');
            contextEnter.append('g').attr('class', 'nv-y nv-axis');
            contextEnter.append('g').attr('class', 'nv-linesWrap');
            contextEnter.append('g').attr('class', 'nv-brushBackground');
            contextEnter.append('g').attr('class', 'nv-x nv-brush');

            // Legend
            if (showLegend) {
                var legendWidth = (showControls) ? availableWidth - controlWidth : availableWidth;
                
                legend.width(legendWidth);
                g.select('.nv-legendWrap').datum(data).call(legend);
                
                if ( margin.top != legend.height()) {
                    margin.top = legend.height();
                    availableHeight1 = nv.utils.availableHeight(height, container, margin) - height2;
                }
                
                g.select('.nv-legendWrap')
                .attr('transform', 'translate(' + (availableWidth-legendWidth) + ',' + (-margin.top) +')');
            }
            
            // Controls
            if (showControls) {
                var controlsData = [
                {
                    key: controlLabels.stacked || 'Stacked',
                    metaKey: 'Stacked',
                    disabled: lines.style() != 'stack',
                       style: 'stack'
                },
                {
                    key: controlLabels.stream || 'Stream',
                    metaKey: 'Stream',
                    disabled: lines.style() != 'stream',
                       style: 'stream'
                },
                {
                    key: controlLabels.expanded || 'Expanded',
                    metaKey: 'Expanded',
                    disabled: lines.style() != 'expand',
                       style: 'expand'
                },
                {
                    key: controlLabels.stack_percent || 'Stack %',
                    metaKey: 'Stack_Percent',
                    disabled: lines.style() != 'stack_percent',
                       style: 'stack_percent'
                }
                ];
                
                controlWidth = (controlOptions.length/3) * 260;
                controlsData = controlsData.filter(function(d) {
                    return controlOptions.indexOf(d.metaKey) !== -1;
                });
                
                controls
                .width( controlWidth )
                .color(['#444', '#444', '#444']);
                
                g.select('.nv-controlsWrap')
                .datum(controlsData)
                .call(controls);
                
                if ( margin.top != Math.max(controls.height(), legend.height()) ) {
                    margin.top = Math.max(controls.height(), legend.height());
                    availableHeight1 = nv.utils.availableHeight(height, container, margin);
                }
                
                g.select('.nv-controlsWrap')
                .attr('transform', 'translate(0,' + (-margin.top) +')');
            }
            
            wrap.attr('transform', 'translate(' + margin.left + ',' + margin.top + ')');
            
            if (rightAlignYAxis) {
                g.select(".nv-y.nv-axis")
                .attr("transform", "translate(" + availableWidth + ",0)");
            }
            
            //Set up interactive layer
            if (useInteractiveGuideline) {
                interactiveLayer
                .width(availableWidth)
                .height(availableHeight1)
                .margin({left: margin.left, top: margin.top})
                .svgContainer(container)
                .xScale(x);
                wrap.select(".nv-interactive").call(interactiveLayer);
            }
            
            lines
            .width(availableWidth)
            .height(availableHeight1);
            
            var stackedWrap = g.select('.nv-stackedWrap')
            .datum(data);
            
            stackedWrap.transition().call(lines);
            
            // Main Chart Component(s)
            lines
                .width(availableWidth)
                .height(availableHeight1)
                .color(
                data
                    .map(function(d,i) {
                        return d.color || color(d, i);
                    })
                    .filter(function(d,i) {
                        return !data[i].disabled;
                    })
            );

            lines2
                //.defined(lines.defined())
                .width(availableWidth)
                .height(availableHeight2)
                .color(
                data
                    .map(function(d,i) {
                        return d.color || color(d, i);
                    })
                    .filter(function(d,i) {
                        return !data[i].disabled;
                    })
            );

            g.select('.nv-context')
                .attr('transform', 'translate(0,' + ( availableHeight1 + margin.bottom + margin2.top) + ')')

            var contextLinesWrap = g.select('.nv-context .nv-linesWrap')
                .datum(data.filter(function(d) { return !d.disabled }))

            d3.transition(contextLinesWrap).call(lines);
            d3.transition(contextLinesWrap).call(lines2);

            // Setup Main (Focus) Axes
            xAxis
                .scale(x)
                ._ticks( nv.utils.calcTicksX(availableWidth/100, data) )
                .tickSize(-availableHeight1, 0);

            yAxis
                .scale(y)
                ._ticks( nv.utils.calcTicksY(availableHeight1/36, data) )
                .tickSize( -availableWidth, 0);

            g.select('.nv-focus .nv-x.nv-axis')
                .attr('transform', 'translate(0,' + availableHeight1 + ')');

            // Setup Brush
            brush
                .x(x2)
                .on('brush', function() {
                    onBrush();
                });

            if (brushExtent) brush.extent(brushExtent);

            var brushBG = g.select('.nv-brushBackground').selectAll('g')
                .data([brushExtent || brush.extent()])

            var brushBGenter = brushBG.enter()
                .append('g');

            brushBGenter.append('rect')
                .attr('class', 'left')
                .attr('x', 0)
                .attr('y', 0)
                .attr('height', availableHeight2);

            brushBGenter.append('rect')
                .attr('class', 'right')
                .attr('x', 0)
                .attr('y', 0)
                .attr('height', availableHeight2);

            var gBrush = g.select('.nv-x.nv-brush')
                .call(brush);
            gBrush.selectAll('rect')
                .attr('height', availableHeight2);
            gBrush.selectAll('.resize').append('path').attr('d', resizePath);

            onBrush();

            // Setup Secondary (Context) Axes
            x2Axis
                .scale(x2)
                ._ticks( nv.utils.calcTicksX(availableWidth/100, data) )
                .tickSize(-availableHeight2, 0);

            g.select('.nv-context .nv-x.nv-axis')
                .attr('transform', 'translate(0,' + y2.range()[0] + ')');
            d3.transition(g.select('.nv-context .nv-x.nv-axis'))
                .call(x2Axis);

            y2Axis
                .scale(y2)
                ._ticks( nv.utils.calcTicksY(availableHeight2/36, data) )
                .tickSize( -availableWidth, 0);

            d3.transition(g.select('.nv-context .nv-y.nv-axis'))
                .call(y2Axis);

            g.select('.nv-context .nv-x.nv-axis')
                .attr('transform', 'translate(0,' + y2.range()[0] + ')');

            //============================================================
            // Event Handling/Dispatching (in chart's scope)
            //------------------------------------------------------------

            lines.dispatch.on('areaClick.toggle', function(e) {
                if (data.filter(function(d) { return !d.disabled }).length === 1)
                    data.forEach(function(d) {
                        d.disabled = false;
                    });
                else
                    data.forEach(function(d,i) {
                        d.disabled = (i != e.seriesIndex);
                    });

                state.disabled = data.map(function(d) { return !!d.disabled });
                dispatch.stateChange(state);

                chart.update();
            });

            legend.dispatch.on('stateChange', function(newState) {
                for (var key in newState)
                    state[key] = newState[key];
                dispatch.stateChange(state);
                chart.update();
            });

            controls.dispatch.on('legendClick', function(d,i) {
                if (!d.disabled) return;

                controlsData = controlsData.map(function(s) {
                    s.disabled = true;
                    return s;
                });
                d.disabled = false;

                lines.style(d.style);
                lines2.style(d.style);


                state.style = lines.style();
                dispatch.stateChange(state);

                chart.update();
            });

            interactiveLayer.dispatch.on('elementMousemove', function(e) {
                lines.clearHighlights();
                var singlePoint, pointIndex, pointXLocation, allData = [];
                data
                    .filter(function(series, i) {
                        series.seriesIndex = i;
                        return !series.disabled;
                    })
                    .forEach(function(series,i) {
                        var extent = brush.empty() ? x2.domain() : brush.extent();
                        var currentValues = series.values.filter(function(d,i) {
                            return lines.x()(d,i) >= extent[0] && lines.x()(d,i) <= extent[1];
                        });
                        
                        pointIndex = nv.interactiveBisect(currentValues, e.pointXValue, lines.x());
                        var point = currentValues[pointIndex];
//                         pointIndex = nv.interactiveBisect(series.values, e.pointXValue, chart.x());
//                         var point = series.values[pointIndex];
                        var pointYValue = chart.y()(point, pointIndex);
                        if (pointYValue != null) {
                            lines.highlightPoint(i, pointIndex, true);
                        }
                        if (typeof point === 'undefined') return;
                        if (typeof singlePoint === 'undefined') singlePoint = point;
                        if (typeof pointXLocation === 'undefined') pointXLocation = chart.xScale()(chart.x()(point,pointIndex));

                        //If we are in 'expand' mode, use the stacked percent value instead of raw value.
                             var tooltipValue = (lines.style() == 'expand') ? point.display.y : chart.y()(point,pointIndex);
                        allData.push({
                            key: series.key,
                            value: tooltipValue,
                            color: color(series,series.seriesIndex),
                            stackedValue: point.display
                        });
                    });

                allData.reverse();

                //Highlight the tooltip entry based on which stack the mouse is closest to.
                if (allData.length > 2) {
                    var yValue = chart.yScale().invert(e.mouseY);
                    var yDistMax = Infinity, indexToHighlight = null;
                    allData.forEach(function(series,i) {

                        //To handle situation where the stacked area chart is negative, we need to use absolute values
                        //when checking if the mouse Y value is within the stack area.
                        yValue = Math.abs(yValue);
                        var stackedY0 = Math.abs(series.stackedValue.y0);
                        var stackedY = Math.abs(series.stackedValue.y);
                        if ( yValue >= stackedY0 && yValue <= (stackedY + stackedY0))
                        {
                            indexToHighlight = i;
                            return;
                        }
                    });
                    if (indexToHighlight != null)
                        allData[indexToHighlight].highlight = true;
                }

                var xValue = xAxis.tickFormat()(chart.x()(singlePoint,pointIndex));

                var valueFormatter = interactiveLayer.tooltip.valueFormatter();
                // Keeps track of the tooltip valueFormatter if the chart changes to expanded view
                if (lines.style() === 'expand' || lines.style() === 'stack_percent') {
                    if ( !oldValueFormatter ) {
                        oldValueFormatter = valueFormatter;
                    }
                    //Forces the tooltip to use percentage in 'expand' mode.
                    valueFormatter = d3.format(".1%");
                }
                else {
                    if (oldValueFormatter) {
                        valueFormatter = oldValueFormatter;
                        oldValueFormatter = null;
                    }
                }

                interactiveLayer.tooltip
                    .position({left: pointXLocation + margin.left, top: e.mouseY + margin.top})
                    .chartContainer(that.parentNode)
                    .valueFormatter(valueFormatter)
                    .data(
                    {
                        value: xValue,
                        series: allData
                    }
                )();

                interactiveLayer.renderGuideLine(pointXLocation);

            });

            interactiveLayer.dispatch.on("elementMouseout",function(e) {
                lines.clearHighlights();
            });

            // Update chart from a state object passed to event handler
            dispatch.on('changeState', function(e) {

                if (typeof e.disabled !== 'undefined' && data.length === e.disabled.length) {
                    data.forEach(function(series,i) {
                        series.disabled = e.disabled[i];
                    });

                    state.disabled = e.disabled;
                }

                if (typeof e.style !== 'undefined') {
                    stacked.style(e.style);
                    style = e.style;
                }

                chart.update();
            });

            //============================================================
            // Functions
            //------------------------------------------------------------

            // Taken from crossfilter (http://square.github.com/crossfilter/)
            function resizePath(d) {
                var e = +(d == 'e'),
                    x = e ? 1 : -1,
                    y = availableHeight2 / 3;
                return 'M' + (.5 * x) + ',' + y
                    + 'A6,6 0 0 ' + e + ' ' + (6.5 * x) + ',' + (y + 6)
                    + 'V' + (2 * y - 6)
                    + 'A6,6 0 0 ' + e + ' ' + (.5 * x) + ',' + (2 * y)
                    + 'Z'
                    + 'M' + (2.5 * x) + ',' + (y + 8)
                    + 'V' + (2 * y - 8)
                    + 'M' + (4.5 * x) + ',' + (y + 8)
                    + 'V' + (2 * y - 8);
            }


            function updateBrushBG() {
                if (!brush.empty()) brush.extent(brushExtent);
                brushBG
                    .data([brush.empty() ? x2.domain() : brushExtent])
                    .each(function(d,i) {
                        var leftWidth = x2(d[0]) - x.range()[0],
                            rightWidth = availableWidth - x2(d[1]);
                        d3.select(this).select('.left')
                            .attr('width',  leftWidth < 0 ? 0 : leftWidth);

                        d3.select(this).select('.right')
                            .attr('x', x2(d[1]))
                            .attr('width', rightWidth < 0 ? 0 : rightWidth);
                    });
            }


            function onBrush() {
                brushExtent = brush.empty() ? null : brush.extent();
                var extent = brush.empty() ? x2.domain() : brush.extent();

                //The brush extent cannot be less than one.  If it is, don't update the line chart.
                if (Math.abs(extent[0] - extent[1]) <= 1) {
                    return;
                }

                dispatch.brush({extent: extent, brush: brush});


                updateBrushBG();

                // Update Main (Focus)
                var focusLinesWrap = g.select('.nv-focus .nv-linesWrap')
                    .datum(
                    data
                        .filter(function(d) { return !d.disabled })
                        .map(function(d,i) {
                            return {
                                key: d.key,
                                area: d.area,
                                values: d.values.filter(function(d,i) {
                                    return lines.x()(d,i) >= extent[0] && lines.x()(d,i) <= extent[1];
                                })
                            }
                        })
                );
                focusLinesWrap.transition().duration(transitionDuration).call(lines);


                // Update Main (Focus) Axes
                g.select('.nv-focus .nv-x.nv-axis').transition().duration(transitionDuration)
                    .call(xAxis);
                g.select('.nv-focus .nv-y.nv-axis').transition().duration(transitionDuration)
                    .call(yAxis);
            }
        });

        return chart;
    }

    //============================================================
    // Event Handling/Dispatching (out of chart's scope)
    //------------------------------------------------------------

    lines.dispatch.on('elementMouseover.tooltip', function(evt) {
//         evt.point['x'] = lines.x()(evt.point);
//         evt.point['y'] = lines.y()(evt.point);
        tooltip.data(evt).position(evt.pos).hidden(false);
    });

    lines.dispatch.on('elementMouseout.tooltip', function(evt) {
        tooltip.hidden(true)
    });

    //============================================================
    // Expose Public Variables
    //------------------------------------------------------------

    // expose chart's sub-components
    chart.dispatch = dispatch;
    chart.legend = legend;
    chart.controls = controls;
    chart.lines = lines;
    chart.lines2 = lines2;
    chart.xAxis = xAxis;
    chart.yAxis = yAxis;
    chart.x2Axis = x2Axis;
    chart.y2Axis = y2Axis;
    chart.interactiveLayer = interactiveLayer;
    chart.tooltip = tooltip;

    chart.options = nv.utils.optionsFunc.bind(chart);

    chart._options = Object.create({}, {
        // simple options, just get/set the necessary values
        width:      {get: function(){return width;}, set: function(_){width=_;}},
        height:     {get: function(){return height;}, set: function(_){height=_;}},
        focusHeight:     {get: function(){return height2;}, set: function(_){height2=_;}},
        showLegend: {get: function(){return showLegend;}, set: function(_){showLegend=_;}},
        brushExtent: {get: function(){return brushExtent;}, set: function(_){brushExtent=_;}},
        defaultState:    {get: function(){return defaultState;}, set: function(_){defaultState=_;}},
        noData:    {get: function(){return noData;}, set: function(_){noData=_;}},
        showControls:    {get: function(){return showControls;}, set: function(_){showControls=_;}},
        controlLabels:    {get: function(){return controlLabels;}, set: function(_){controlLabels=_;}},
        controlOptions:    {get: function(){return controlOptions;}, set: function(_){controlOptions=_;}},

        // deprecated options
        tooltips:    {get: function(){return tooltip.enabled();}, set: function(_){
            // deprecated after 1.7.1
            nv.deprecated('tooltips', 'use chart.tooltip.enabled() instead');
            tooltip.enabled(!!_);
        }},
        tooltipContent:    {get: function(){return tooltip.contentGenerator();}, set: function(_){
            // deprecated after 1.7.1
            nv.deprecated('tooltipContent', 'use chart.tooltip.contentGenerator() instead');
            tooltip.contentGenerator(_);
        }},

        // options that require extra logic in the setter
        margin: {get: function(){return margin;}, set: function(_){
            margin.top    = _.top    !== undefined ? _.top    : margin.top;
            margin.right  = _.right  !== undefined ? _.right  : margin.right;
            margin.bottom = _.bottom !== undefined ? _.bottom : margin.bottom;
            margin.left   = _.left   !== undefined ? _.left   : margin.left;
        }},
        color:  {get: function(){return color;}, set: function(_){
            color = nv.utils.getColor(_);
            legend.color(color);
            // line color is handled above?
        }},
        interpolate: {get: function(){return lines.interpolate();}, set: function(_){
            lines.interpolate(_);
            lines2.interpolate(_);
        }},
        xTickFormat: {get: function(){return xAxis.tickFormat();}, set: function(_){
            xAxis.tickFormat(_);
            x2Axis.tickFormat(_);
        }},
        yTickFormat: {get: function(){return yAxis.tickFormat();}, set: function(_){
            yAxis.tickFormat(_);
            y2Axis.tickFormat(_);
        }},
        duration:    {get: function(){return transitionDuration;}, set: function(_){
            transitionDuration=_;
            yAxis.duration(transitionDuration);
            y2Axis.duration(transitionDuration);
            xAxis.duration(transitionDuration);
            x2Axis.duration(transitionDuration);
        }},
        x: {get: function(){return lines.x();}, set: function(_){
            lines.x(_);
            lines2.x(_);
        }},
        y: {get: function(){return lines.y();}, set: function(_){
            lines.y(_);
            lines2.y(_);
        }},
        useInteractiveGuideline: {get: function(){return useInteractiveGuideline;}, set: function(_){
            useInteractiveGuideline = _;
            if (useInteractiveGuideline) {
                lines.interactive(false);
                lines.useVoronoi(false);
            }
        }}
    });

    nv.utils.inheritOptions(chart, lines);
    nv.utils.initOptions(chart);

    return chart;
};