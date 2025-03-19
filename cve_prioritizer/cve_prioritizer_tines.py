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

# argparse setup
#@click.command()
#@click.option('-a', '--api', type=str, help='Your API Key')
#@click.option('-c', '--cve', type=str, help='Unique CVE-ID')
#@click.option('-e', '--epss', type=float, default=0.2, help='EPSS threshold (Default 0.2)')
#@click.option('-f', '--file', type=click.File('r'), help='TXT file with CVEs (One per Line)')
#@click.option('-j', '--json_file', type=click.Path(), required=False, help='JSON output')
#@click.option('-n', '--cvss', type=float, default=6.0, help='CVSS threshold (Default 6.0)')
#@click.option('-o', '--output', type=click.File('w'), help='Output filename')
#@click.option('-t', '--threads', type=int, default=100, help='Number of concurrent threads')
#@click.option('-v', '--verbose', is_flag=True, help='Verbose mode')
#@click.option('-l', '--list', help='Comma separated list of CVEs')
#@click.option('-nc', '--no-color', is_flag=True, help='Disable Colored Output')
#@click.option('-sa', '--set-api', is_flag=True, help='Save API keys')
#@click.option('-vc', '--vulncheck', is_flag=True, help='Use NVD++ - Requires VulnCheck API')
#@click.option('-vck', '--vulncheck_kev', is_flag=True, help='Use Vulncheck KEV - Requires VulnCheck API')
#@click.option('--nessus', is_flag=True, help='Parse Nessus file')
#@click.option('--openvas', is_flag=True, help='Parse OpenVAS file')
#def main(api, cve, epss, file, cvss, output, threads, verbose, list, no_color, set_api, vulncheck, vulncheck_kev,
#         json_file, nessus, openvas):
def main(input):
    # Global Arguments
  #  color_enabled = not no_color
    throttle_msg = ''

    # Set the NIST API and VULNCHECK API keys based on input from Tines' Python action
    nist_api = input["nist_api_key"]
    vulncheck_api = input["vulncheck_api_key"]
    cve = input["cve"]

    save_output = ''
    verbose = True
    colored_output = True

    # By default, make the output verbose
    header = VERBOSE_HEADER

  #  header = VERBOSE_HEADER if verbose else SIMPLE_HEADER
  #  epss_threshold = epss
  #  cvss_threshold = cvss
    sem = Semaphore(1)

    # Temporal lists
    cve_list = []
    threads = []

    # Tines is set up to pass only 1 CVE at a time to this function.
    cve_list.append(cve)

    # Testing "cve" value
    # return { "result": 'The cve is: ' + cve}

  #  if set_api:
  #      services = ['nist_nvd', 'vulncheck']
  #      service = click.prompt("Please choose a service to set the API key",
  #                             type=click.Choice(services, case_sensitive=False))
  #      api_key = click.prompt(f"Enter the API key for {service}", hide_input=True)

  #      if service == 'nist_nvd':
  #          update_env_file('.env', 'NIST_API', api_key)
  #      elif service == 'vulncheck':
  #          update_env_file('.env', 'VULNCHECK_API', api_key)

  #      click.echo(f"API key for {service} updated successfully.")
  #  if verbose:
  #      header = VERBOSE_HEADER

  #  if cve:
  #      cve_list.append(cve)
  #  elif list:
  #      cve_list = list.split(',')
  #  elif file:
  #      if nessus:
  #          cve_list = parse_report(file, 'nessus')
  #      elif openvas:
  #          cve_list = parse_report(file, 'openvas')
  #      else:
  #          cve_list = [line.rstrip() for line in file]

  #  if not api and not os.getenv('NIST_API') and not vulncheck:
  #      if len(cve_list) > 75:
  #          throttle_msg = 'Large number of CVEs detected, requests will be throttle to avoid API issues'
  #          click.echo(LOGO + throttle_msg + '\n' +
  #                     'Warning: Using this tool without specifying a NIST API may result in errors'
  #                     + '\n\n' + header)
  #      else:
  #          click.echo(LOGO + 'Warning: Using this tool without specifying a NIST API may result in errors'
  #                     + '\n\n' + header)
  #  else:
  #      print(LOGO + header)

    #if output:
    #    output.write("cve_id,priority,epss,cvss,cvss_version,cvss_severity,kev,ransomware,kev_source,cpe,vendor,"
    #                 "product,vector" + "\n")

    results = []
    for cve in cve_list:
        throttle = 1
  #      if len(cve_list) > 75 and not os.getenv('NIST_API') and not api and not vulncheck:
  #          throttle = 6
  #      if (vulncheck or vulncheck_kev) and (os.getenv('VULNCHECK_API') or api):
  #          throttle = 0.25
  #      elif (vulncheck or vulncheck_kev) and not os.getenv('VULNCHECK_API') and not api:
  #          click.echo("VulnCheck requires an API key")
  #          exit()
  #      if not re.match(r'(CVE|cve-\d{4}-\d+$)', cve):
  #          click.echo(f'{cve} Error: CVEs should be provided in the standard format CVE-0000-0000*')
  #      else:
        print(cve)

        try:
            kev_source = 'CISA'
            print(kev_source)
            #if vc_kev:
            #    cve_result = vulncheck_check(cve_id, api, vc_kev)
                # exploited = vulncheck_kev(cve_id, api)[0]
            #    exploited = cve_result.get('cisa_kev')
            #    kev_source = 'VULNCHECK'
            #elif nvd_plus:
            #    cve_result = vulncheck_check(cve_id, api, vc_kev)
            #    exploited = cve_result.get("cisa_kevs")
            #else:
            #    if 'vulncheck' in str(api).lower():
            #        click.echo("Wrong API Key provided (VulnCheck)")
            #        exit()
            cve_result = nist_check(cve, nist_api)
            print(cve_result)
            exploited = cve_result.get("cisa_kev")
            print(exploited)
            epss_result = epss_check(cve)
            print(epss_result)

            cvss_score = 6
            epss_score = 0.2

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

                    return {results}
            except (TypeError, AttributeError):
                pass
        except Exception as e:
            print(f"Error in worker thread for CVE {cve}: {e}")
        finally:
            sem.release()

    #for t in threads:
    #    t.join()

    #if json_file:
    #    metadata = {
    #        'generator': 'CVE Prioritizer',
    #        'generation_date': datetime.now(timezone.utc).isoformat(),
    #        'total_cves': len(cve_list),
    #        'cvss_threshold': cvss_threshold,
    #        'epss_threshold': epss_threshold,
    #    }
    #    output_data = {
    #        'metadata': metadata,
    #        'cves': results,
    #    }
    #    with open(json_file, 'w') as json_file:
    #        json.dump(output_data, json_file, indent=4)


if __name__ == '__main__':
    main()

# Check NIST NVD for the CVE
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
            click.echo(f"{cve_id:<18}Not Found in EPSS.")
            return {"epss": None, "percentile": None}
    except requests.exceptions.HTTPError as http_err:
        click.echo(f"HTTP error occurred: {http_err}")
    except requests.exceptions.ConnectionError:
        click.echo("Unable to connect to EPSS, check your Internet connection or try again")
    except requests.exceptions.Timeout:
        click.echo("The request to EPSS timed out")
    except requests.exceptions.RequestException as req_err:
        click.echo(f"An error occurred: {req_err}")
    except ValueError as val_err:
        click.echo(f"Error processing the response: {val_err}")

    return {"epss": None, "percentile": None}

# Function manages the outputs
def print_and_write(working_file, cve_id, priority, epss, cvss_base_score, cvss_version, cvss_severity, kev, ransomware,
                    source, verbose, cpe, vector, no_color):
    color_priority = colored_print(priority)
    vendor, product = parse_cpe(cpe)

    if verbose:
        if no_color:
            click.echo(
                f"{cve_id:<18}{color_priority:<22}{epss:<9}{cvss_base_score:<6}{cvss_version:<10}{cvss_severity:<10}"
                f"{kev:<7}{ransomware:<12}{truncate_string(vendor, 15):<18}"
                f"{truncate_string(product, 20):<23}{vector}")
        else:
            click.echo(f"{cve_id:<18}{priority:<13}{epss:<9}{cvss_base_score:<6}{cvss_version:<10}{cvss_severity:<10}"
                       f"{kev:<7}{ransomware:<12}{truncate_string(vendor, 15):<18}"
                       f"{truncate_string(product, 20):<23}{vector}")
    else:
        if no_color:
            click.echo(f"{cve_id:<18}{color_priority:<22}")
        else:
            click.echo(f"{cve_id:<18}{priority:<13}")
    if working_file:
        working_file.write(f"{cve_id},{priority},{epss},{cvss_base_score},{cvss_version},{cvss_severity},"
                           f"{kev},{ransomware},{source},{cpe},{vendor},{product},{vector}\n")

    return {"cve_id": cve_id, "priority": priority, "epss": epss, "cvss_base_score": cvss_base_score, "cvss_version": cvss_version, "cvss_severity": cvss_severity, "kev": kev, "ransomware": ransomware, "vendor": truncate_string(vendor, 15), "product": truncate_string(product, 20), "vector": vector}

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
def truncate_string(input_string, max_length):
    """
    Truncates a string to a maximum length, appending an ellipsis if the string is too long.
    """
    if len(input_string) > max_length:
        return input_string[:max_length - 3] + "..."
    else:
        return input_string

# Extract CVE product details
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