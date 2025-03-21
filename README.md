<img width="826" alt="image" src="https://github.com/user-attachments/assets/f4139d8f-305e-4fed-92e7-f872c3186675" />

# Vulnerability Management
Vulnerability management is the practice of identifying, analyzing, prioritizing, remediating, and reporting on security vulnerabilities. It is typically driven by vulnerability scans, threat models, and other sources, while feeding into a company's risk management program.

## What are the Risks?
An inadequate or informal vulnerability management process may fail to identify, prioritize, or remediate security vulnerabilities that could then be exploited by a bad actor. Vulnerability management is also hard. Security teams are inundated by vulnerabilities from various sources; prioritizing vulnerabilities is a difficult process that requires substantial investment in tools or resources.

## What are Potential Mitigations?
For this demo, we will focus on vulnerability prioritization. 

Vulnerabilities are typically evaluated based on a Common Vulnerability Scoring System (CVSS) score ranging from 0-10. Unfortunately, these CVSS scores often lack the context that makes them useful in organizations. Other methods, such as Exploit Prediction Scoring System (EPSS), may be difficult to implement effectively. 

To aid security teams with prioritizing vulnerabilities, I have modified the code from [CVE_Prioritizer](https://github.com/TURROKS/CVE_Prioritizer) to work in a Tines story. This allows teams to automate vulnerability prioritization based on the open-source CVE_Prioritizer tool.

<img width="967" alt="image" src="https://github.com/user-attachments/assets/55527123-a68e-4e1d-827d-d89f2f219a0d" />

Credit for CVE_Prioritizer goes to [TURROKS](https://github.com/TURROKS).

# Getting Started
This demo will run CVE_Prioritizer in Tines. For steps on how to run the tool using the CLI, refer to [CVE_Prioritizer](https://github.com/TURROKS/CVE_Prioritizer). Highly recommended - Review the README too!

Notes: 
1. For this demo, I have installed CVE_Prioritizer on a MacBook running OSX Sonoma 14.5 running an M1 processor with 16 GB of RAM.
2. You will need the latest version of `python3` installed.
3. You will need to sign up for a free Tines Community account @ https://www.tines.com/

## Installation
1. Clone this repo.

```
git clone https://github.com/jian-me/CVE_Prioritizer.git
cd tines
```
2. Find the `execute-cve-prioritizer-in-tines.json` file and import it to Tines following [these instructions](https://www.tines.com/docs/stories/importing-and-exporting/)
3. Create an OAuth app in your GitHub account and follow [these instructions](https://explained.tines.com/en/articles/8052219-github-oauth-authentication-guide) to set up the `github` CREDENTIAL in Tines
4. Follow the instructions in [CVE_Prioritizer](https://github.com/TURROKS/CVE_Prioritizer) to request API tokens for NIST NVD and VULNCHECK.

   *NOTE: You may need to try multiple NVD API tokens. It took me 4 separate requests to get an API token that worked. You can request a token, follow the rest of the steps below to test it out, and if you run into an error, go to the NVD site to request another token.*

7. Set the `nist_api` and `vulncheck_api` CREDENTIALS in Tines using the tokens you requested in Step 6.
8. Fill in the following RESOURCE values in Tines.
   - `github_repo_owner` - GitHub username of the repository owner
   - `github_repo` - GitHub repository name
   - `script_file_path` - Path to the script on GitHub
   - `epss_threshold` - EPSS threshold, defaults to 0.2
   - `cvss_threshold` - CVSS threshold, defaults to 6
   - `use_vulncheck_kev` - Use VulnCheck KEV flag
   - `use_nvd_plus` - Use NVD+ flag

   For example:
      - `github_repo_owner` = Your GitHub username
      - `github_repo` = CVE_Prioritizer
      - `script_file_path` = `tines/cve_prioritizer_tines.py`

9. Run the Tines story with a CVE ID. You can send a POST request to the webhook URL in the "Webhook Action", or for testing purposes, hard-code the CVE ID in the "Global Variables" action.

### Sample Request and Response

**Request**

Note: Replace `{SUBDOMAIN}`, `{PATH}`, and `{SECRET}` with the values in your Tines tenant.
```
curl -v \
--http1.1 \
-X POST \
--location \
"https://{SUBDOMAIN}.tines.com/webhook/{PATH}/{SECRET}" \
-H 'Content-Type: application/json' \
-d '{"cve_id":"CVE-2024-0001"}'
```

**Response**

From CLI
```
[{"cve_id":"","priority":"P2","epss":0.00027,"cvss_base_score":10.0,"cvss_version":"CVSS V2","cvss_severity":"","kev":"FALSE","kev_source":"CISA","cpe":"cpe:2.3:a:eric_allman:sendmail:5.58:*:*:*:*:*:*:*","vector":"AV:N/AC:L/Au:N/C:C/I:C/A:C"}]%
```

From Tines
```
"output": [
    {
      "cve_id": "",
      "priority": "P2",
      "epss": 0.00027,
      "cvss_base_score": 10.0,
      "cvss_version": "CVSS V2",
      "cvss_severity": "",
      "kev": "FALSE",
      "kev_source": "CISA",
      "cpe": "cpe:2.3:a:eric_allman:sendmail:5.58:*:*:*:*:*:*:*",
      "vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C"
    }
  ]
```

## Future / Planned Work
1. Add authentication checks to the Webhook Action
2. Test other use cases when using NVD+ and VULNCHECK KEV databases

# Scenarios
1. Using Tines:
   - Export or retrieve findings from different vulnerability management tools
   - Extract the CVE IDs for each finding, where available
   - For each CVE ID, call this Tines story using the `cve_id` as input
   - For each CVE ID, retrieve the output from the Tines story and plug the `priority` and other fields into reports
2. Manually:
   - For each CVE ID you have, use the `curl` request above to call the Tines story
   - You can also use the original CVE_Prioritizer code by following the steps in [CVE_Prioritizer](https://github.com/TURROKS/CVE_Prioritizer)
