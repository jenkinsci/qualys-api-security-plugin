function drawsverityWiseCharts(result){
	drawPieChart(result.security, "#secVulns", "#secVulns-error", "#security-vulns-legend-div");
	drawPieChart(result.data, "#dataVulns", "#dataVulns-error", "#data-vulns-legend-div");
	drawPieChart(result.validation, "#valVulns", "#valVulns-error", "#validation-vulns-legend-div");
}

function drawPieChart(data, canvas_id, error_div, lgend_div){
	jQuery(error_div).hide();
	jQuery(canvas_id).show();
	jQuery(lgend_div).show();
	if(!data){
		jQuery(canvas_id).hide();
		jQuery(lgend_div).hide();
		jQuery(error_div).show();
	}else{
		var count = Array();
		var severity = Array();
		
		var i = 0;
		for (var key in data) {
			count[i] = data[key];
		    severity[i] = key;
		    i++;
		}
		var options = {
		    animateRotate: true,
		    animateScale: false,
		    percentageInnerCutout: 50,
		    tooltipTemplate: "<%= label %>"
		}
		var colors = ["#E8E4AE", "#F4BB48", "#FAA23B", "#DE672A","#D61E1C"];
		var labels = count; 
		if(! count.some(el => el !== 0)){
			count = ["1", "1", "1", "1", "1"];
			severity = ["1", "2", "3", "4", "5"];
			labels = ["0", "0", "0", "0", "0"];	
			colors = ["#B0BFc6", "#B0BFc6", "#B0BFc6", "#B0BFc6", "#B0BFc6"];
		}
		
		var c = jQuery(canvas_id).get(0);
			var ctx = c.getContext("2d");
		
			var pieData = [
				{
				value: count[4].toString(),
				label: "Criticality " + severity[4].toString() + " (" + labels[4] + ")",
				color: colors[4]
				},
				{
				value: count[3].toString(),
				label: "Criticality " + severity[3].toString() + " (" + labels[3] + ")",
				color: colors[3]
				},
				{
				value: count[2].toString(),
				label: "Criticality " + severity[2].toString() + " (" + labels[2] + ")",
				color: colors[2]
				},
				{
				value: count[1].toString(),
				label: "Criticality " + severity[1].toString() + " (" + labels[1] + ")",
				color: colors[1]
				},
				{
				value: count[0].toString(),
				label: "Criticality " + severity[0].toString() + " (" + labels[0] + ")",
				color: colors[0]
				}
			];
			
		var chart = new Chart(ctx).Doughnut(pieData,options);		
		jQuery(lgend_div).append(chart.generateLegend());
	}
}

function drawVulnsCharts(scanResults){
	jQuery("#sevVulns-error").hide();
	jQuery("#sevVulns").show();
	jQuery("#pie-legend-div").show();
	if(!scanResults){
		jQuery("#sevVulns").hide();
		jQuery("#pie-legend-div").hide();
		jQuery("#sevVulns-error").show();
	}else{
		var count = [];
		var keys = [];
		
		var i = 0;
		var total = 0;
		Object.keys(scanResults).forEach(function(key,i) {
			count[i] = scanResults[key];
		    keys[i] = key;
		});
		
		var options = {
		    animateRotate: true,
		    animateScale: false,
		    percentageInnerCutout: 50,
		    tooltipTemplate: "<%= label %>"
		}
		var colors = ["#D61E1C", "#DE672A", "#FAA23B", "#F4BB48","#E8E4AE"];
		var labels = count; 
		
		var c = jQuery("#sevVulns").get(0);
		var ctx = c.getContext("2d");
	
		var pieData = [];
		var j = 0;
		for (index = 0; index < keys.length; index++) { 
			pieData.push({
				value: count[index].toString(),
				label: keys[index] + " (" + labels[index] + ")",
				color: colors[index]
			});
		}
		
		var chart = new Chart(ctx).Doughnut(pieData,options);		
		jQuery("#pie-legend-div").append(chart.generateLegend());
	}
}

function updateSummaryTable(evaluationResult){
	result = evaluationResult.result;
	if(result){
		var gradeObj = result.grade;
		if(gradeObj){
			if(gradeObj.configured != null || gradeObj.configured != undefined){
				jQuery("#grade-found .image-scan-status").removeClass("not-configured").addClass(gradeObj.result ? "ok" : "fail");
				jQuery("#grade-found .image-scan-status .tooltip-text").html("<b>configured:</b> "+gradeObj.configured + "<br /><b>Found: </b>"+ (gradeObj.found ? gradeObj.found : "None"));
			}
		}
		var groupCriticality = result.groupCriticality;
		var groups = ["security", "data", "validation"];
		if(groupCriticality){
			groups.forEach(function(group){
				groupObj = groupCriticality[group];
				if(groupObj && (groupObj.configured != null || groupObj.configured != undefined)){
					jQuery("#"+ group +"-found .image-scan-status").removeClass("not-configured").addClass(groupObj.result ? "ok" : "fail");
					jQuery("#"+ group +"-found .image-scan-status .tooltip-text").html("<b>configured count:</b> "+groupObj.configured.count + " with criticality "+ groupObj.configured.criticality +" or more.<br /><b>Found: </b>"+ (groupObj.found ? groupObj.found : "None"));
				}
			})
		}
	}
}

function showVulnsTable(vulns){
	//Vulns Table
	var table = jQuery('#vulnsTable').DataTable({             
		"autoWidth": false, 
		"language": {
    		"emptyTable": "No Issues found"
		 },
		 "dom": '<"vulns-table-top"l<"custom-filters">>rt<"vulns-table-bottom"ip><"clear">',
        "aaData": vulns,
        "aoColumns":[
        	{ "className": 'details-control', "orderable": false, "data":null, "defaultContent": '', "width": "3%"},
            { "mData": "findingKey", sDefaultContent :  '', "width": "50%"},
            { "mData": "findings", sDefaultContent :  '', "width": "20%"}
        ],
        'aoColumnDefs': [
        	{ "sTitle": "", "aTargets": [0] },
            { "sTitle": "Finding Key", "aTargets": [1] },
            { "sTitle": "Total Issues", "aTargets": [2],
            	"render":  function ( data, type, row ) {
        			var count = data.length;
            		return count;
    			}
            }
        ]
    });
	
	jQuery('#vulnsTable tbody').on('click', 'td.details-control', function () {
        var tr = jQuery(this).closest('tr');
        var row = table.row( tr );
 
        if ( row.child.isShown() ) {
            // This row is already open - close it
            row.child.hide();
            tr.removeClass('shown');
        }
        else {
            // Open this row
            row.child( format(row.data()) ).show();
            tr.addClass('shown');
        }
    });
	
	function format ( d ) {
		
	    var table = '<table cellpadding="5" cellspacing="0" border="0" style="padding-left:50px;">'+
		    '<tr><th>Path</th><th style="width:65px;">Criticality</th><th style="width:80px;">Fix Impact</th><th>Description</th></tr>';
	    
	    d.findings.forEach(function(finding, index){
	    	table += '<tr>'+
		    	'<td>'+ (finding.path != undefined ? finding.path : "-") +'</td>'+
		    	'<td>'+ (finding.type != undefined ? finding.criticality : "-") +'</td>'+
		    	'<td>'+ (finding.score != undefined ? finding.score : "-") +'</td>'+
		    	'<td>'+ (finding.score != undefined ? finding.message : "-") +'</td>'+
	    	'</tr>';
	    });
	    	
	    table +='</table>';
	    return table;
	}
	
}