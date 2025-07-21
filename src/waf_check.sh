#!/bin/bash

# Check if input file is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <input_file>"
    exit 1
fi

# Validate input file exists
if [ ! -f "$1" ]; then
    echo "Error: Input file '$1' not found"
    exit 1
fi

# Load default config file
set +e
source config.cfg
#mkdir backup

# Generate timestamp for report file
timestamp=$(date +"%Y%m%d_%H%M%S")
report_file="report_${timestamp}.csv"
log_file="log_${timestamp}.txt"

count=0
countz=0
start=`date +%s`
waf_status="null"

# Format csv headers
echo "Service Name, Service ID, NGWAF Code, NGWAF Activated, Legacy WAF Status" >> "$report_file"

# Loop through input file
# ** Note: Input file must end with an empty new line, otherwise it will skip the last entry **
while read line 
do
    #Set line as service ID
    sid=$line

    # Pull service details
    curl -s --request GET $fUrl/service/$sid/details \
    --header 'Accept: application/json' \
    --header "Fastly-Key: $fastly_key" > payload.tmp
    #echo $sDetails >> $log_file

    # Store service data
    sver=$(jq -r '.active_version.number' payload.tmp 2> /dev/null )
    sname=$(jq -r '.name' payload.tmp 2> /dev/null )
    wafID=$(jq -r '.active_version.wafs[].id' payload.tmp 2> /dev/null )
    edgeDid=$(jq -r '.active_version.dictionaries[] | select(.name == "Edge_Security") | .id' payload.tmp 2> /dev/null )

     # Initial WAF Check
  if [[ -z $wafID ]]
  then
    LwafCheck="❌"
  else
    LwafCheck="✅"
  fi

    # Get NGWAF service snippets
    findWAF=$( curl -s -w "\n%{http_code}" --request GET $fUrl/service/$sid/version/$sver/snippet/$snipName \
    --header 'Accept: application/json' \
    --header "Fastly-Key: $fastly_key" )
    echo $findWAF >> $log_file

    # Extract status code
    status_code=$(echo "$findWAF" | tail -n1)
    # Extract response body
    response_body=$(echo "$findWAF" | sed '$d')

    echo "Site Check: $response_body | $status_code" >> $log_file

    # Get NGWAF Activation Status
    getKey=$( curl -s -w "\n%{http_code}" --request GET $fUrl/service/$sid/dictionary/$edgeDid/item/$edgeKey \
    --header 'Accept: application/json' \
    --header "Fastly-Key: $fastly_key" )
    echo "NGWAF Edge Value = "$getKey >> $log_file
     
    edgeValue=$( echo $getKey | jq -r '.item_value' 2> /dev/null )

    #NGWAF Activation Reporting
    if [[ $edgeValue -eq 100 ]]
    then 
        ngwafActive="✅"
    else  
        ngwafActive="❌"
    fi


    # Site Check
    if [[ $status_code -eq 404 ]]
    then
        waf_status="❌"
    elif [[ $status_code -eq 200 ]]
    then
        waf_status="✅"
    else
        waf_status=$response_body
    fi

    # Report Changes
    echo "$sname, $sid, $waf_status", $ngwafActive ,"$LwafCheck" >> "$report_file"

done < "$1"

# Cleanup temporary files
rm -f payload.tmp

# Calculate runtime
end=`date +%s`
runtime=$((end-start))
runmins=$((runtime / 60))
echo "Completed in $runmins minutes"
echo "Report saved as: $report_file"