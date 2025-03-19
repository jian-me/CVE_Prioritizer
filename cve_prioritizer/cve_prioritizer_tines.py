#!/usr/bin/env python3

__author__ = "Mario Rojas"
__license__ = "BSD 3-clause"
__version__ = "1.8.3"
__maintainer__ = "Mario Rojas"
__status__ = "Production"

import json
import os
import re
import threading
import time
from threading import Semaphore

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
def main(nist_api_key,vulncheck_api_key,cve):
    # Global Arguments
  #  color_enabled = not no_color
    throttle_msg = ''

    # Set the NIST API and VULNCHECK API keys based on input from Tines' Python action
    nist_api = input["nist_api_key"]
    vulncheck_api = input["vulncheck_api_key"]
    cve = input["cve"]

    # By default, make the output verbose
    header = VERBOSE_HEADER

  #  header = VERBOSE_HEADER if verbose else SIMPLE_HEADER
  #  epss_threshold = epss
  #  cvss_threshold = cvss
  #  sem = Semaphore(threads)

    # Temporal lists
    cve_list = []
    threads = []

    # Tines is set up to pass only 1 CVE at a time to this function.
    cve_list.append(cve)

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

    if output:
        output.write("cve_id,priority,epss,cvss,cvss_version,cvss_severity,kev,ransomware,kev_source,cpe,vendor,"
                     "product,vector" + "\n")

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
