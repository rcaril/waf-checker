#!/bin/bash

# Check if parameter was provided
if [ $# -lt 1 ]; then
  echo "Usage: $0 <customer_id_file_or_direct_cid>"
  echo "Example: $0 customer_ids.txt"
  echo "Example: $0 12345"
  exit 1
fi

input="$1"

# Load default config file
set +e
source account_config.cfg

# Generate timestamp for report file
timestamp=$(date +"%Y%m%d_%H%M%S")
log_file="account_log_$timestamp.txt"
report_file="account_report_${timestamp}.csv"

count=0
countz=0
start=`date +%s`
waf_status="null"

# Format csv headers with all 5 columns
echo "Service Name, Service ID, NGWAF Code, NGWAF Activated, Legacy WAF Status" >> "$report_file"

# Function to process a single customer ID
process_customer_id() {
    local cid=$1
    
    # Pull Account Name
    accountGet=$(curl -s --globoff --request GET $fUrl/customer/$cid \
    --header 'Accept: application/json' \
    --header "Fastly-Key: $fastly_key" )
    echo $accountGet >> $log_file
    
    cname=$( echo $accountGet | jq -r '.name' 2> /dev/null )

    # Pull service list from CID
    cidList=$(curl -s --globoff --request GET $fUrl/services?filter[customer_id]=$cid \
    --header 'Accept: application/json' \
    --header "Fastly-Key: $fastly_key" )
    echo $cidList >> $log_file

    # Extract service IDs and process each one
    echo $cidList | jq -r '.data[].id' 2> /dev/null | while read -r sid
    do
        # Only process if service ID is not empty
        if [ -n "$sid" ]; then

            # Pull service details - store to file instead of memory
            curl -s --request GET $fUrl/service/$sid/details \
            --header 'Accept: application/json' \
            --header "Fastly-Key: $fastly_key" > payload.tmp

            # Store service data from file
            sver=$(jq -r '.active_version.number' payload.tmp 2> /dev/null )
            sname=$(jq -r '.name' payload.tmp 2> /dev/null )
            wafID=$(jq -r '.active_version.wafs[].id' payload.tmp 2> /dev/null )
            edgeDid=$(jq -r '.active_version.dictionaries[] | select(.name == "Edge_Security") | .id' payload.tmp 2> /dev/null )

            # Skip if no active version found
            if [[ -z "$sver" || "$sver" == "null" ]]; then
                echo "Skipping service $sid - no active version found" >> $log_file
                continue
            fi

            # Initial Legacy WAF Check
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

            # NGWAF Activation Reporting
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

            # Report Changes with all 5 columns
            echo "$sname, $sid, $waf_status", $ngwafActive ,"$LwafCheck" >> "$report_file"
        fi

    done
}

# Determine if input is a file or direct customer ID
if [ -f "$input" ]; then
    # Input is a file - process each line
    echo "Processing customer IDs from file: $input"
    while read -r line 
    do
        if [ -n "$line" ]; then
            process_customer_id "$line"
        fi
    done < "$input"
else
    # Input is a direct customer ID - process directly
    echo "Processing single customer ID: $input"
    process_customer_id "$input"
fi

# Cleanup temporary files
rm -f payload.tmp

# Calculate runtime
end=`date +%s`
runtime=$((end-start))
runmins=$((runtime / 60))
echo "Completed in $runmins minutes"
echo "Report saved as: $report_file"