# Fastly NGWAF / Legacy Status Checker

These scripts can be leveraged to report on Fastly NGWAF and Legacy WAF status for services. This is accomplished via API by checking the VCL of a given service to see if it contains legacy WAF code as well as NGWAF snippets and an appropriate edge dictionary.

## Overview

This repository contains two scripts for different analysis approaches:
- **waf_check.sh** - Service-level analysis (requires service ID input via file)
- **account_waf_check.sh** - Account-level analysis (requires CID text input or file list input)

Both scripts determine:
- Legacy WAF presence via WAF objects in service configuration
- NGWAF code deployment via ngwaf_config_init snippet detection
- NGWAF activation status via Edge_Security dictionary values

## Prerequisites

- jq (given in this repo, but you can provide your own binary)
- Valid Fastly API token

## Configuration

### Service-level script (waf_check.sh)
Requires `config.cfg`:
```bash
fastly_key="your_api_token" // or provided with env variable
fUrl="https://api.fastly.com"
snipName="ngwaf_config_init"
edgeKey="Enabled"
```

### Account-level script (account_waf_check.sh)
Requires `account_config.cfg`:
```bash
fastly_key="your_api_token" // or provided with env variable
fUrl="https://api.fastly.com"
snipName="ngwaf_config_init"
edgeKey="Enabled"
```

## Usage

### Service-level checking
```bash
./waf_check.sh <service_ids_file>
```

Input file format (one service ID per line):
```
1a2b3c4d5e6f7g8h
9i0j1k2l3m4n5o6p
```

### Account-level checking
```bash
# Single customer ID
./account_waf_check.sh 12345

# Multiple customer IDs from file
./account_waf_check.sh customer_ids.txt
```

Customer file format (one customer ID per line):
```
12345
67890
```

## Output

Output files:
- `report_YYYYMMDD_HHMMSS.csv` - Results
- `log_YYYYMMDD_HHMMSS.txt` - Debug information (account script only)

## Notes

- Input files must end with empty newline
- Services without active versions are skipped

## Troubleshooting

Common issues:
- Missing jq: Install via package manager
- Authentication errors: Verify API token in config file
- Empty results: Check input file format and newline endings
- Permissions: Ensure scripts are executable (chmod +x)