var observatoryapp = angular.module("observatory", [])

observatoryapp.controller("IndexController",function($scope, $http){
    /*$scope.active_certs = 0
    $scope.expired_certs = 0
    $scope.revoked_certs = 0*/

    $scope.logs = []

    /*$http.get("/api/getallcertinfo").then(function(promise){
        $scope.active_certs = promise.data.active_certs
        $scope.expired_certs = promise.data.expired_certs
        $scope.revoked_certs = promise.data.revoked_certs
    });*/

// DIAGRAMS
//     $http.get("/api/getloginfo").then(function(promise){
// 	    d3.select('#certsinlogdistribution .spinner').remove();
//         nv.addGraph(function() {
//             var chart = nv.models.multiBarHorizontalChart()
//                 .x(function(d) { return d.label })
//                 .y(function(d) { return d.value })
//                 .margin({top: 20, right: 20, bottom: 20, left: 20})
//                 .showValues(true)
//                 .showLegend(false)
//                 .showXAxis(false)
//                 .stacked(true)
// 
//             chart.yAxis
//                 .tickFormat(d3.format('d'));
// 
//             chart.valueFormat(d3.format('d'));
// 
//             chart.tooltip.valueFormatter(function(d,i){
//                 return d+ " ("+d3.format(',.2f')(d*100/promise.data.unique_certificates)+"%)";
//             });
// 
//             d3.select('#certsinlogdistribution svg')
//                 .datum(promise.data.data)
//                 .call(chart);
// 
//             nv.utils.windowResize(chart.update);
// 
//             return chart;
//         });
//         $scope.logs = promise.data.data;
//     });

// DIAGRAMS
//     nv.addGraph(function() {
//       var chart = nv.models.pieChart()
//           .x(function(d) { return d.logs })
//           .y(function(d) { return d.certificates })
//           .showLabels(true)
//           .labelType("percent")
//           ;
// 
//       chart.tooltip.keyFormatter(function(d){
//           return "Certificates in "+d+" logs";
//       });
// 
//       chart.tooltip.valueFormatter(function(d,i){
//         return d3.format('d')(d);
//       });
//       d3.json("/api/getlogdist", function(error, json) {
// 	d3.select('#distributionchart .spinner').remove();
//         if (error) return console.warn(error);
//         d3.select("#distributionchart svg")
//             .datum(json)
//             .transition().duration(350)
//             .call(chart);
//       });
//       return chart;
//     });

});

observatoryapp.controller("CaController", function($scope, $http){
    $scope.cas =[];
    $scope.caOrder = "name"
    $scope.filterText = ""

    $http.get("/api/getcas").then(function (response){
        $scope.cas = response.data;
    }, function (errorResponse){
        $scope.cas = [];
    });

    $scope.caFilter = function(ca){
        return (ca.name.toLowerCase().indexOf($scope.filterText.toLowerCase()) > -1) &&
            ($scope.showOnlyRootCa ? ca.parent.length==0 : ca.parent.length >= 0 );
    }

    $scope.toggleSort = function(column) {
        $scope.caOrder = ($scope.caOrder[0] == "-"?"":"-")+column
    }
});

observatoryapp.controller("CertListController", function($scope, $http){
    $scope.displayedData = {};
    $scope.displayedData.active = 0;
    $scope.displayedData.keySizes = {};
    $scope.displayedData.durations = {};

    $http.get("/api/getcertdistribution").then(function(promise){

    });
});
