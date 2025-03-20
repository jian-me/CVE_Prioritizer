#!/usr/bin/env python3

__author__ = "Mario Rojas"
__license__ = "BSD 3-clause"
__version__ = "1.8.3"
__maintainer__ = "Mario Rojas"
__status__ = "Production"

import json
import os
from pickle import TRUE
import re
import threading
import time
from threading import Semaphore
import requests
import click
import xml.etree.ElementTree as ET
from termcolor import colored

import click
from dotenv import load_dotenv
from datetime import datetime, timezone

# API URLs
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
NIST_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NUCLEI_BASE_URL = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json"
VULNCHECK_BASE_URL = "https://api.vulncheck.com/v3/index/nist-nvd2"
VULNCHECK_KEV_BASE_URL = "https://api.vulncheck.com/v3/index/vulncheck-kev"

# Visuals
SIMPLE_HEADER = f"{'CVE-ID':<18}Priority"+"\n"+("-"*30)
VERBOSE_HEADER = (f"{'CVE-ID':<18}{'PRIORITY':<13}{'EPSS':<9}{'CVSS':<6}{'VERSION':<10}{'SEVERITY':<10}{'KEV':<7}"
                  f"{'RANSOMWARE':<12}{'VENDOR':<18}{'PRODUCT':<23}VECTOR")+"\n"+("-"*170)
LOGO = r"""
#    ______   ______                         
#   / ___/ | / / __/                         
#  / /__ | |/ / _/                           
#  \___/_|___/___/        _ __  _            
#    / _ \____(_)__  ____(_) /_(_)__ ___ ____
#   / ___/ __/ / _ \/ __/ / __/ /_ // -_) __/
#  /_/  /_/ /_/\___/_/ /_/\__/_//__/\__/_/   
#  v1.8.3                          BY TURROKS
                                                  
"""""
import xml.etree.ElementTree as ET

load_dotenv()
Throttle_msg = ''

# Configure logging to write to a file in the current working directory
# logging.basicConfig(
#    filename=os.path.join(os.getcwd(), 'cve_prioritizer_logs.txt'),
#    filemode='w',  # Overwrite the log file on each run
#    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
#    level=logging.INFO
# )
# logger = logging.getLogger(__name__)

# Main function. Receives input params from Tines story:
# - nist_api_key
# - vulncheck_api_key
# - cve
# - epss_threshold
# - cvss_threshold
#
# TO DO:
# - Add inputs for verbose, colored_output, write_file, and other values
def main(input):
    # Global Arguments
    throttle_msg = ''

    # Set params based on input from Tines' Python action
    nist_api = input["nist_api_key"]
    vulncheck_api = input["vulncheck_api_key"]
    cve = input["cve"]
    epss_score = input["epss_threshold"]
    cvss_score = input["cvss_threshold"]

    save_output = ''
    verbose = True
    colored_output = True
    vc_kev = input["use_vulncheck_kev"]
    nvd_plus = input["use_nvd_plus"]

    # By default, make the output verbose
    header = VERBOSE_HEADER

    sem = Semaphore(1)

    # Temporal lists
    cve_list = []
    threads = []

    # Tines is set up to pass only 1 CVE at a time to this function.
    cve_list.append(cve)

    # Removed set_api code because it is not needed in the Tines story.
    # Verbose header is set by default
    # Tines will only input one cve at a time
    # Removed print statement to display the logo

    # Instantiate a blank list
    results = []

    # Iterate through the CVEs. In Tines, this should only be 1 cve at a time.
    for cve in cve_list:
        throttle = 1

        # Removed the throttle check code b/c this can be handled in Tines.

        # Print for debug purposes
        print(cve)

        # Use vulncheck KEV or NVD+ if specified in input
        # Both are FALSE by default
        try:
            kev_source = 'CISA'
            print(kev_source)
            print(vc_kev)

            if vc_kev:
                print("vulncheck in")
                cve_result = vulncheck_check(cve, vulncheck_api, vc_kev)
                # exploited = vulncheck_kev(cve_id, api)[0]
                exploited = cve_result.get('cisa_kev')
                kev_source = 'VULNCHECK'
                print(cve_result)
                print(exploited)
                print("vulncheck out")
            elif nvd_plus:
                print("nvd+ in")
                cve_result = vulncheck_check(cve, vulncheck_api, vc_kev)
                exploited = cve_result.get("cisa_kevs")
            else:
                cve_result = nist_check(cve, nist_api)
                print(cve_result)
                exploited = cve_result.get("cisa_kev")
                print(exploited)
            
            print(kev_source)

            # Retrieve the EPSS result
            epss_result = epss_check(cve)
            print(epss_result)

            try:
                if exploited:
                    ransomware = cve_result.get('ransomware')
                    print_and_write(save_output, cve, 'Priority 1+', epss_result.get('epss'),
                                    cve_result.get('cvss_baseScore'), cve_result.get('cvss_version'),
                                    cve_result.get('cvss_severity'), 'TRUE', ransomware, kev_source, verbose,
                                    cve_result.get('cpe'), cve_result.get('vector'), colored_output)
                elif cve_result.get("cvss_baseScore") >= cvss_score:
                    if epss_result.get("epss") >= epss_score:
                        print_and_write(save_output, cve, 'Priority 1', epss_result.get('epss'),
                                        cve_result.get('cvss_baseScore'), cve_result.get('cvss_version'),
                                        cve_result.get('cvss_severity'), '', '', kev_source, verbose,
                                        cve_result.get('cpe'), cve_result.get('vector'), colored_output)
                    else:
                        print_and_write(save_output, cve, 'Priority 2', epss_result.get('epss'),
                                        cve_result.get('cvss_baseScore'), cve_result.get('cvss_version'),
                                        cve_result.get('cvss_severity'), '', '', kev_source, verbose,
                                        cve_result.get('cpe'), cve_result.get('vector'), colored_output)
                else:
                    if epss_result.get("epss") >= epss_score:
                        print_and_write(save_output, cve, 'Priority 3', epss_result.get('epss'),
                                        cve_result.get('cvss_baseScore'), cve_result.get('cvss_version'),
                                        cve_result.get('cvss_severity'), '', '', kev_source, verbose,
                                        cve_result.get('cpe'), cve_result.get('vector'), colored_output)
                    else:
                        print_and_write(save_output, cve, 'Priority 4', epss_result.get('epss'),
                                        cve_result.get('cvss_baseScore'), cve_result.get('cvss_version'),
                                        cve_result.get('cvss_severity'), '', '', kev_source, verbose,
                                        cve_result.get('cpe'), cve_result.get('vector'), colored_output)
                if results is not None:
                    results.append({
                        'cve_id': cve,
                        'priority': 'P1+' if exploited else 'P1' if cve_result.get(
                            "cvss_baseScore") >= cvss_score and epss_result.get(
                            "epss") >= epss_score else 'P2' if epss_result.get(
                            "epss") < epss_score else 'P3' if epss_result.get("epss") >= epss_score else 'P4',
                        'epss': epss_result.get('epss'),
                        'cvss_base_score': cve_result.get('cvss_baseScore'),
                        'cvss_version': cve_result.get('cvss_version'),
                        'cvss_severity': cve_result.get('cvss_severity'),
                        'kev': 'TRUE' if exploited else 'FALSE',
                        'kev_source': kev_source,
                        'cpe': cve_result.get('cpe'),
                        'vector': cve_result.get('vector')
                    })

                    return results
            except (TypeError, AttributeError):
                pass
        except Exception as e:
            print(f"Error in worker thread for CVE {cve}: {e}")
        finally:
            sem.release()

# Check NIST NVD for the CVE
# Modified code from CVE_Prioritizer, scripts/helpers.py
# Added print statements for debugging 
# Replaced click.echo with print statements to output to Script action logs
def nist_check(cve_id, api_key):
    """
    Function collects NVD Data
    """
    try:
        nvd_key = api_key
        nvd_url = NIST_BASE_URL + f"?cveId={cve_id}"
        headers = {'apiKey': nvd_key} if nvd_key else {}

        print(nvd_url)
        print(headers)

        nvd_response = requests.get(nvd_url, headers=headers)
        print(nvd_response)
        nvd_response.raise_for_status()

        response_data = nvd_response.json()
        if response_data.get("totalResults") > 0:
            for unique_cve in response_data.get("vulnerabilities"):
                cisa_kev = unique_cve.get("cve").get("cisaExploitAdd", False)
                ransomware = ''
                if cisa_kev:
                    kev_data = requests.get(CISA_KEV_URL)
                    kev_data.raise_for_status()
                    kev_list = kev_data.json()
                    for entry in kev_list.get('vulnerabilities', []):
                        if entry.get('cveID') == cve_id:
                            ransomware = str(entry.get('knownRansomwareCampaignUse')).upper()

                cpe = unique_cve.get("cve").get("configurations", [{}])[0].get("nodes", [{}])[0].get("cpeMatch", [{}])[0].get("criteria", 'cpe:2.3:::::::::::')

                metrics = unique_cve.get("cve").get("metrics", {})
                for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if version in metrics:
                        for metric in metrics[version]:
                            return {
                                "cvss_version": version.replace("cvssMetric", "CVSS "),
                                "cvss_baseScore": float(metric.get("cvssData", {}).get("baseScore", 0)),
                                "cvss_severity": metric.get("cvssData", {}).get("baseSeverity", ""),
                                "cisa_kev": cisa_kev,
                                "ransomware": ransomware,
                                "cpe": cpe,
                                "vector": metric.get("cvssData", {}).get("vectorString", "")
                            }

                if unique_cve.get("cve").get("vulnStatus") == "Awaiting Analysis":
                    print(f"{cve_id:<18}Awaiting NVD Analysis")
                    return {
                        "cvss_version": "",
                        "cvss_baseScore": "",
                        "cvss_severity": "",
                        "cisa_kev": "",
                        "ransomware": "",
                        "cpe": "",
                        "vector": ""
                    }
        else:
            print(f"{cve_id:<18}Not Found in NIST NVD.")
            return {
                "cvss_version": "",
                "cvss_baseScore": "",
                "cvss_severity": "",
                "cisa_kev": "",
                "ransomware": "",
                "cpe": "",
                "vector": ""
            }
    except requests.exceptions.HTTPError:
        print(f"{cve_id:<18}HTTP error occurred, check CVE ID or API Key")
    except requests.exceptions.ConnectionError:
        print("Unable to connect to NIST NVD, check your Internet connection or try again")
    except requests.exceptions.Timeout:
        print("The request to NIST NVD timed out")
    except requests.exceptions.RequestException as req_err:
        print(f"An error occurred: {req_err}")
    except ValueError as val_err:
        print(f"Error processing the response: {val_err}")

    return {
        "cvss_version": "",
        "cvss_baseScore": "",
        "cvss_severity": "",
        "cisa_kev": "",
        "ransomware": "",
        "cpe": "",
        "vector": ""
    }

# Collect EPSS Scores
# Modified code from CVE_Prioritizer, scripts/helpers.py
# Added print statements for debugging 
# Replaced click.echo with print statements to output to Script action logs
def epss_check(cve_id):
    """
    Function collects EPSS from FIRST.org
    """
    try:
        epss_url = EPSS_URL + f"?cve={cve_id}"
        epss_response = requests.get(epss_url)
        epss_response.raise_for_status()

        print(epss_url)
        print(epss_response)

        response_data = epss_response.json()
        if response_data.get("total") > 0:
            for cve in response_data.get("data"):
                results = {"epss": float(cve.get("epss")),
                           "percentile": int(float(cve.get("percentile")) * 100)}
                return results
        else:
            print(f"{cve_id:<18}Not Found in EPSS.")
            return {"epss": None, "percentile": None}
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
    except requests.exceptions.ConnectionError:
        print("Unable to connect to EPSS, check your Internet connection or try again")
    except requests.exceptions.Timeout:
        print("The request to EPSS timed out")
    except requests.exceptions.RequestException as req_err:
        print(f"An error occurred: {req_err}")
    except ValueError as val_err:
        print(f"Error processing the response: {val_err}")

    return {"epss": None, "percentile": None}

# Check Vulncheck NVD++
# Modified code from CVE_Prioritizer, scripts/helpers.py
# Added print statements for debugging 
# Replaced click.echo with print statements to output to Script action logs
def vulncheck_check(cve_id, api_key, kev_check):
    """
    Function collects VulnCheck NVD2 Data
    """
    try:
        vulncheck_key = api_key
        if not vulncheck_key:
            print("VulnCheck requires an API key")
            return {
                "cvss_version": "",
                "cvss_baseScore": "",
                "cvss_severity": "",
                "cisa_kev": "",
                "ransomware": "",
                "cpe": "",
                "vector": ""
            }

        vulncheck_url = VULNCHECK_BASE_URL + f"?cve={cve_id}"

        # Print the URL for debugging purposes
        print(vulncheck_url)
        
        header = {"accept": "application/json"}
        params = {"token": vulncheck_key}

        vulncheck_response = requests.get(vulncheck_url, headers=header, params=params)
        vulncheck_response.raise_for_status()

        response_data = vulncheck_response.json()
        if response_data.get("_meta", {}).get("total_documents", 0) > 0:
            kev_data = requests.get(CISA_KEV_URL)
            kev_data.raise_for_status()
            kev_list = kev_data.json()

            for unique_cve in response_data.get("data", []):
                vc_kev = False
                vc_used_by_ransomware = ''
                if kev_check:
                    vc_kev, vc_used_by_ransomware = vulncheck_kev(unique_cve.get('id'), api_key)
                elif unique_cve.get("cisaExploitAdd"):
                    vc_kev = True
                    for entry in kev_list.get('vulnerabilities', []):
                        if entry.get('cveID') == cve_id:
                            vc_used_by_ransomware = str(entry.get('knownRansomwareCampaignUse')).upper()

                cpe = unique_cve.get("configurations", [{}])[0].get("nodes", [{}])[0].get("cpeMatch", [{}])[0].get("criteria", 'cpe:2.3:::::::::::')

                metrics = unique_cve.get("metrics", {})
                for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if version in metrics:
                        for metric in metrics[version]:
                            return {
                                "cvss_version": version.replace("cvssMetric", "CVSS "),
                                "cvss_baseScore": float(metric.get("cvssData", {}).get("baseScore", 0)),
                                "cvss_severity": metric.get("cvssData", {}).get("baseSeverity", ""),
                                "cisa_kev": vc_kev,
                                "ransomware": vc_used_by_ransomware,
                                "cpe": cpe,
                                "vector": metric.get("cvssData", {}).get("vectorString", "")
                            }

                if unique_cve.get("vulnStatus") == "Awaiting Analysis":
                    print(f"{cve_id:<18}NIST Status: {unique_cve.get('vulnStatus')}")
                    
                    return {
                        "cvss_version": "",
                        "cvss_baseScore": "",
                        "cvss_severity": "",
                        "cisa_kev": "",
                        "ransomware": "",
                        "cpe": "",
                        "vector": ""
                    }
        else:
            print(f"{cve_id:<18}Not Found in VulnCheck.")
            
            return {
                "cvss_version": "",
                "cvss_baseScore": "",
                "cvss_severity": "",
                "cisa_kev": "",
                "ransomware": "",
                "cpe": "",
                "vector": ""
            }
    except requests.exceptions.HTTPError:
        print(f"{cve_id:<18}HTTP error occurred, check CVE ID or API Key")
    except requests.exceptions.ConnectionError:
        print("Unable to connect to VulnCheck, check your Internet connection or try again")
    except requests.exceptions.Timeout:
        print("The request to VulnCheck timed out")
    except requests.exceptions.RequestException as req_err:
        print(f"An error occurred: {req_err}")
    except ValueError as val_err:
        print(f"Error processing the response: {val_err}")

    return {
        "cvss_version": "",
        "cvss_baseScore": "",
        "cvss_severity": "",
        "cisa_kev": "",
        "ransomware": "",
        "cpe": "",
        "vector": ""
    }

# Checks VULNCHECK's KEV catalog for the CVE
# Modified code from CVE_Prioritizer, scripts/helpers.py
# Set vulncheck_key equal to api_key without conditional statement
# Added print statements for debugging 
# Replaced click.echo with print statements to output to Script action logs
def vulncheck_kev(cve_id, api_key):
    """
    Check Vulncheck's KEV catalog
    """

    vc_exploited = False
    vc_used_by_ransomware = False

    try:
        # Set the vulncheck API key to what is passed into the function
        vulncheck_key = api_key
        
        # local variables
        vulncheck_url = VULNCHECK_KEV_BASE_URL + f"?cve={cve_id}"
        header = {"accept": "application/json"}
        params = {"token": vulncheck_key}

        # Check if API has been provided
        if vulncheck_key:
            vulncheck_response = requests.get(vulncheck_url, headers=header, params=params).json()

            if vulncheck_response.get('data'):
                vc_exploited = True
                vc_used_by_ransomware = str(vulncheck_response.get('data')[0].get('knownRansomwareCampaignUse')).upper()
                return vc_exploited, vc_used_by_ransomware
            else:
                return vc_exploited, vc_used_by_ransomware
        else:
            print("VulnCheck requires an API key")
            exit()
    except requests.exceptions.ConnectionError:
        print(f"Unable to connect to VulnCheck, Check your Internet connection or try again")
        return None, None

# Function manages the outputs
# Modified code from CVE_Prioritizer, scripts/helpers.py
# Added return statement and replaced click.echo with print statements
#
# TO DO: 
# - Update write to working_file.
def print_and_write(working_file, cve_id, priority, epss, cvss_base_score, cvss_version, cvss_severity, kev, ransomware,
                    source, verbose, cpe, vector, no_color):
    color_priority = colored_print(priority)
    vendor, product = parse_cpe(cpe)

    if verbose:
        if no_color:
            print(
                f"{cve_id:<18}{color_priority:<22}{epss:<9}{cvss_base_score:<6}{cvss_version:<10}{cvss_severity:<10}"
                f"{kev:<7}{ransomware:<12}{truncate_string(vendor, 15):<18}"
                f"{truncate_string(product, 20):<23}{vector}")
        else:
            print(f"{cve_id:<18}{priority:<13}{epss:<9}{cvss_base_score:<6}{cvss_version:<10}{cvss_severity:<10}"
                       f"{kev:<7}{ransomware:<12}{truncate_string(vendor, 15):<18}"
                       f"{truncate_string(product, 20):<23}{vector}")
    else:
        if no_color:
            print(f"{cve_id:<18}{color_priority:<22}")
        else:
            print(f"{cve_id:<18}{priority:<13}")
    if working_file:
        working_file.write(f"{cve_id},{priority},{epss},{cvss_base_score},{cvss_version},{cvss_severity},"
                           f"{kev},{ransomware},{source},{cpe},{vendor},{product},{vector}\n")

    return {"cve_id": cve_id, "priority": priority, "epss": epss, "cvss_base_score": cvss_base_score, "cvss_version": cvss_version, "cvss_severity": cvss_severity, "kev": kev, "ransomware": ransomware, "vendor": truncate_string(vendor, 15), "product": truncate_string(product, 20), "vector": vector}

# Prints outputs in color
# Original code from CVE_Prioritizer, scripts/helpers.py
def colored_print(priority):
    """
    Function used to handle colored print
    """
    if priority == 'Priority 1+':
        return colored(priority, 'red')
    elif priority == 'Priority 1':
        return colored(priority, 'red')
    elif priority == 'Priority 2':
        return colored(priority, 'yellow')
    elif priority == 'Priority 3':
        return colored(priority, 'yellow')
    elif priority == 'Priority 4':
        return colored(priority, 'green')

# Truncate for printing
# Original code from CVE_Prioritizer, scripts/helpers.py
def truncate_string(input_string, max_length):
    """
    Truncates a string to a maximum length, appending an ellipsis if the string is too long.
    """
    if len(input_string) > max_length:
        return input_string[:max_length - 3] + "..."
    else:
        return input_string

# Extract CVE product details
# Original code from CVE_Prioritizer, scripts/helpers.py
def parse_cpe(cpe_str):
    """
    Parses a CPE URI string and extracts the vendor, product, and version.
    Assumes the CPE string is in the format: cpe:/a:vendor:product:version:update:edition:language
    """
    # Splitting the CPE string into components
    parts = cpe_str.split(':')

    # Extracting vendor, product, and version
    vendor = parts[3] if len(parts) > 2 else None
    product = parts[4] if len(parts) > 3 else None

    return vendor, product

if __name__ == '__main__':
    main()