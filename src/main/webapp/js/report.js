function drawsverityWiseCharts(result){
	drawPieChart(result.security, "#secVulns", "#secVulns-error", "#security-vulns-legend-div");
	drawPieChart(result["data validation"], "#dataVulns", "#dataVulns-error", "#data-vulns-legend-div");
	drawPieChart(result["oas violation"], "#valVulns", "#valVulns-error", "#validation-vulns-legend-div");
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
		var colors = ["#E8E4AE", "#FAA23B", "#D61E1C"];
		var labels = count; 
		if(! count.some(el => el !== 0)){
			count = ["1", "1", "1"];
			severity = ["Low", "Medium", "High"];
			labels = ["0", "0", "0"];	
			colors = ["#B0BFc6", "#B0BFc6", "#B0BFc6"];
		}
		
		var c = jQuery(canvas_id).get(0);
			var ctx = c.getContext("2d");
		
			var pieData = [
				{
					value: count[0].toString(),
					label: severity[0].toString() + " Severity  (" + labels[0] + ")",
					color: colors[0]
				},
				{
					value: count[1].toString(),
					label: severity[1].toString() + " Severity (" + labels[1] + ")",
					color: colors[1]
				},
				{
					value: count[2].toString(),
					label: severity[2].toString() + " Severity  (" + labels[2] + ")",
					color: colors[2]
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
		var colors = ["#34c4f2","#1f568d", "#ffe5c8"]
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
				jQuery("#grade-found .image-scan-status .tooltip-text").html("<b>Configured:</b> "+gradeObj.configured + "<br /><b>Found: </b>"+ (gradeObj.found ? gradeObj.found : "None"));
			}
		}
		var groupCriticality = result.groupCriticality;
		var groups = ["security", "data validation", "oas violation"];
		if(groupCriticality){
			groups.forEach(function(group){
				groupObj = groupCriticality[group];
				if(groupObj && (groupObj.configured != null || groupObj.configured != undefined))
				{
					group = group.replace(/ /g, "");
					jQuery("#"+ group +"-found .image-scan-status").removeClass("not-configured").addClass(groupObj.result ? "ok" : "fail");
					jQuery("#"+ group +"-found .image-scan-status .tooltip-text").html("<b>Configured count:</b> "+groupObj.configured.count + " with severity "+ groupObj.configured.criticality +" or above.<br /><b>Found: </b>"+ (groupObj.found ? groupObj.found : "None"));
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
        	{ "mData": "qid", sDefaultContent :  '', "width": "20%"},
            { "mData": "findings", sDefaultContent :  '', "width": "50%"},
            { "mData": "findings", sDefaultContent :  '', "width": "20%"}
        ],
        'aoColumnDefs': [
        	{ "sTitle": "", "aTargets": [0] },
        	{ "sTitle": "QID", "aTargets": [1] },
        	{ "sTitle": "Finding Key", "aTargets": [2],
                "render" : function( data, type, row){
                	var findingkey = row.type;
                		return findingkey;
            }},
            { "sTitle": "Total Issues", "aTargets": [3],
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
		    '<tr><th style="width:30px;">Path</th><th style="width:50px;">Severity</th><th style="width:60px;">Fix Impact</th><th style="width:150px;">Description</th><th style="width:240px;">Pointer Location (Column, Row, Position)</th><th style="width:20px;">Fix Recommendation</th></tr>';
	    
	    var fixedRecommendation;
	    var jsonData;
	    if(d.fixRecommendation)
	    {
	    	 jsonData = JSON.parse(d.fixRecommendation);
	    }
	  
	    
	    d.findings.forEach(function(finding, index){
	    	var htmlString="";
            for (var i = 0; i < jsonData.sections.length; i++) 
            {
                var section = jsonData.sections[i];
                if(section.text != undefined)
                {
                	htmlString+= section.text;
                }
                if(section.code != undefined)
                {
                	htmlString+= section.code;
                }
            }
            var final = htmlString;  
            var pointer="";     
            var scoreInPercentage = "";

            if(finding.pointerLocationColumn != undefined)
            {
                pointer+='( ' + finding.pointerLocationColumn;
            }
            if(finding.pointerLocationRow != undefined)
            {
                pointer+=', ' + finding.pointerLocationRow;
            }
            if(finding.pointerLocationPos != undefined)
            {
                pointer+= ", " + finding.pointerLocationPos + ' )';
            }
            if(finding.score != undefined)
	    	{
	    		var scoreStr = finding.score.toString();
	    		if(scoreStr.indexOf("-") != -1)
	    		{
	    		    scoreStr = scoreStr.replace("-", "");
	    		}
	            var scoreFloat = parseFloat(scoreStr).toFixed(2);
	    	    scoreInPercentage = scoreFloat.concat("%");
	    	}
            
            var severity = "";
            if(finding.criticality != undefined)
            {
            	if(finding.criticality<3)
            	{
            		severity= "Low";
            	}
            	else if(finding.criticality>2 && finding.criticality<4)
            	{
            		severity= "Medium";
            	}
            	else if(finding.criticality>3 && finding.criticality<6)
            	{
            		severity= "High";
            	}
            	else
            	{
            		severity="-";
            	}
            	
            }
            
	    	table += '<tr>'+
		    	'<td>'+ (finding.path != undefined ? finding.path : "-") +'</td>'+
		    	'<td>'+ (severity) +'</td>'+
		    	'<td>'+ (finding.score != undefined ? scoreInPercentage : "-") +'</td>'+
		    	'<td>'+ (finding.score != undefined ? finding.message : "-") +'</td>'+
		    	'<td>'+ pointer + '</td>'+
		    	'<td>'+ final +'</td>'+
	    	'</tr>';
	    });
	    	
	    table +='</table>';
	    return table;
	}
	
}