import os

import requests
from mcp.server.fastmcp import FastMCP

CytrixMCP_Version = "1.0.1"
CytrixMCP_URL = "https://docs.cytrix.io/"
CytrixDescriptio = """
CYTRIX Description:
    CYTRIX is an Agentic Red Team: The Future of Web and API Security
    Empower your cybersecurity with CYTRIX’s Agentic-AI Red Team. Our autonomous platform perform continuous penetration testing, adapt in
    real-time, and uncover vulnerabilities others miss. By combining human insight with AI, 
    CYTRIX enhances your web security posture without relying on external consultants keeping you proactive, efficient, and ahead of threats.

    CytrixMCP is a powerful automation engine within the Cytrix platform, designed to seamlessly execute security operations, 
    Execute Penetration Testing, and integration workflows through simple API-driven AI tasks. It empowers cybersecurity teams to automate their penetration testing, 
    streamline remediation processes, and integrate with third-party tools like Jira, Slack, and AWS.

    Cytrix is an advanced AI-driven cybersecurity platform that specializes in automated penetration testing, 
    real-time threat detection, and exploit generation. Built for enterprises and governments, Cytrix combines 
    machine learning with deep security knowledge to identify vulnerabilities across web applications, APIs, 
    and infrastructure—prioritizing critical risks and providing actionable insights. Its modular design supports 
    dynamic attack surface mapping, continuous monitoring, and rapid integration, making it ideal for both offensive 
    and defensive security teams.
"""

mcp = FastMCP("CytrixMCP")
API_KEY = os.getenv("API_KEY", "")
API_GATEWAY = os.getenv("API_GATEWAY", "https://api.cytrix.io/")


@mcp.tool()
def get_dashboard_stats(classify) -> dict:
    """
    This endpoint is used to obtain statistics on the entire system, vulnerability percentages / number of scans and targets / average Cyscore score / active scans / how many assets were not scanned from the Discovery Tool/the last five discoveries performed, and more

    Args:
        classify (str, optional): Classification filter for metrics; allowed values: “ALL”, “Gray”, “API schema”, “Black”; defaults to “ALL”.

	Returns:
		dict
		- Returns Params
		HistoryCyscore.EveryDayCyscore.2025-03-20, HistoryCyscore.EveryDayCyscore.2025-03-21, HistoryCyscore.Targets, HistoryCyscore.Scans, HistoryCyscore.Discovery main domain, HistoryCyscore.High, HistoryCyscore.Average Cyscore
		ActiveScans.InProgress, ActiveScans.Queue, ActiveScans.Schedule, RiskCoverage.BaseUrls, RiskCoverage.NotScannedYet, RiskCoverage.Percentage, VulnerabilitiesPercentage.High
		VulnerabilitiesPercentage.Medium, VulnerabilitiesPercentage.Low, Cyscore.Api, Cyscore.Gray, Cyscore.Black, DashboardFooter, last_date
    """
    path = "GetDashboardStats"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "classify": classify
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.get(url, headers=headers, params=data)
    return response.json()


@mcp.tool()
def get_discovery_scan_stats(token, classify) -> dict:
    """
        This endpoint returns Discovery-only metrics: Cyscore history, active scan counts, risk-coverage ratios, vulnerability severity percentages, and asset Cyscore breakdown.

    Args:
        token (str): Unique identifier of the discovery scan target, e.g. “yjb6hl4a-y4ej-ngnl-z80j5ulr”.
        classify (str, optional): Classification filter for metrics; allowed values: “ALL”, “Gray”, “API schema”, “Black”; defaults to “ALL”.

	Returns:
		dict
    """
    path = "GetDiscoveryStats"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "token": token,
        "classify": classify
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.get(url, headers=headers, params=data)
    return response.json()



@mcp.tool()
def get_system_overview() -> dict:
    """
    Retrieve a comprehensive snapshot of the entire security platform.

    This endpoint aggregates and returns high-level metrics across all system modules,
    giving you a real-time, bird’s-eye view of your security posture and operational health.
    Key insights include:

      - **User & Role Distribution:** Total users, breakdown by Administrator, Viewer,
        Private User and end-user roles, plus recent login activity and IP addresses.
      - **Scan Statistics:** Total number of scans run, active scans in progress,
        success/failure rates, and targets covered versus skipped.
      - **Vulnerability Trends:** Percentage breakdown of findings by severity (Critical,
        High, Medium, Low), and changes over time.
      - **CyScore Overview:** Average risk score across all assets, plus distribution
        of scores to highlight high-risk areas.
      - **Asset Discovery Coverage:** Count of assets discovered, scanned, and those
        pending scanning from the Discovery Tool.
      - **Recent Discovery Events:** Details of the last five discovery runs
        (timestamps, assets identified, and any anomalies).

    Returns:
        dict
    """
    path = "SystemOverView"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        # no parameters
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.get(url, headers=headers, params=data)
    return response.json()



@mcp.tool()
def create_new_scan(target, targets, every, secondProfileLoginName, idorParams, useOneSession, rps, hour, minutes, mobile, cookies, crtName, keyName, exclude, fixedIp, request_headers, include, interval, autoSpeed, emailType, levelDeep, proxyName, skipCrash, description, enumeration, projectName, singleCheck, AllowedHosts, interception, scheduleMode, apiSchemaFile, apiFileEnv, attackProfile, durationLimit, durationStatus, excludeClicks, modifiedEmail, jiraProjectName, profileLoginName, targetsExcelFile, ApiIncludeSpider) -> dict:
    """
    Create a new scan on one or multiple assets (Domains) to perform an automated penetration test.
    You can configure all the settings for the scan in this route.

    Args:
        target (str): Primary scan target (URL, domain, or IP). Required if neither `targets` nor `targetsExcelFile` is set.
        targets (list, optional): Provide multiple scan targets as a list. Overrides the single `target` parameter when present. Ex. targets=["https://app.example.com", "https://api.example.com"]
        targetsExcelFile (str, optional): Name of an uploaded Excel file (via the “storage” upload) containing a column of scan targets. The file must be retrievable from the `GetFiles` route. Ex. targetsExcelFile="my_scan_targets.xlsx"
        autoSpeed (bool, optional): When true (the default), Cytrix dynamically adjusts scan speed based on response times, status codes, and errors; when false, it uses the manual `rps` (request per second) value you specify. Ex. autoSpeed=false ⇒ scan at a fixed rate defined by `rps`.
        rps (int, optional): Request Per Second, Number of requests to send per second when `autoSpeed=false`. Default: 70, Valid range: 1–70, Ignored if `autoSpeed=true`, Ex. autoSpeed=false + rps=30 ⇒ send 30 requests per second.
        mobile (bool, optional): When true, performs a mobile-friendly scan—using a mobile user-agent string and viewport; when false (the default), performs a standard desktop scan.
        crtName (str, optional): Certificate name to use to authenticate, you can retrieve all of your files name from "GetFiles" route.
        keyName (str, optional): Key name to use to authenticate, you can retrieve all of your files name from "GetFiles" route.
        fixedIp (str, optional): The fixed IP address of the server, you can retrieve all your IPs from "getallfixedip" route.
        headers (dict, optional): Set headers during the scan, ex. {"key1": "value1", "key2": "value2"}, default is {}
        cookies (dict, optional): Set cookies during the scan, ex. {"example.com": "key1=val1;key2=val2"} or {"example.com": {"key:val"}}, default is {}
        exclude (list, optional): Set domains to exclude from scan, ex. ["https://example1.com", "https://example2.com"], default is []
        include (list, optional): Set domains to include from scan, ex. ["https://example1.com", "https://example2.com"], default is []
        levelDeep (int, optional): Maximum link-crawl depth when enumerating pages. Default is 7 and the range is (1-10), Ex. levelDeep=3 ⇒ follow links up to 3 hops away from the initial target.
        attackProfile (str, optional): The name of the attack profile, can retrieve all profile from "GetAllAttackProfile" route
        durationLimit (int, optional): Decide how long the scan will run for (maximum hours 1-23), by default there is no limit.
        durationStatus (str, optional): Just if "durationLimit" gt "0" you can set that the scan move to on of these statuses (Completed,Aborted,Pause)
        scheduleMode (bool, optional): When true, enables automatic recurring execution; when false (the default), runs immediately or only on demand. Ex. scheduleMode=true + every=“w” + interval=3 + hour=15 + minute=45 ⇒ run every 3 weeks at 15:45.
        every (str, optional): Time unit for the interval. One of: y → years | m → months | w → weeks | d → days
        interval (int, optional): Number of “every” units between runs (required if scheduleMode=true). Ex. interval=2 + every=“d” ⇒ every 2 days.
        hour (int, optional): Hour of day (0–23) when the task executes. Defaults is 0.
        minute (int, optional): Minute of the hour (0–59) when the task executes. Defaults is 0.
        apiSchemaFile (str, optional): Name of the API schema file to use for this scan. Must match one of the filenames returned by the `GetFiles` route. Ex. apiSchemaFile="petstore.yaml"
        apiFileEnv (str, optional): Name of the environment variables file for the schema. Must match one of the filenames returned by the `GetFiles` route. Ex. apiFileEnv="dev.env"
        ApiIncludeSpider (str, optional): When true, runs a crawler (spider) using the schema to discover additional routes; when false (the default), only scans the routes explicitly defined in the schema. Ex. ApiIncludeSpider=true
        profileLoginName: profile Login Name, Must match one of the login profiles returned by the `GetLogins` route. Ex. profileLoginName="example login"
        secondProfileLoginName: Another profile Login Name, Must match one of the login profiles returned by the `GetLogins` route. Ex. secondProfileLoginName="example login2"


        useOneSession: useOneSession
        emailType: emailType
        proxyName: proxyName
        skipCrash: skipCrash
        description: description
        enumeration: enumeration
        projectName: projectName
        singleCheck: singleCheck
        AllowedHosts: AllowedHosts
        interception: interception
        idorParams: idorParams
        excludeClicks: excludeClicks,
        modifiedEmail: modifiedEmail,
        jiraProjectName: jiraProjectName,

	Returns:
		Dict
		- Returns Params
		target, status, token
    """
    path = "NewTarget"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "target": target,
        "targets": targets,
        "every": every,
        "rps": rps,
        "mobile": mobile,
        "cookies": cookies,
        "crtName": crtName,
        "keyName": keyName,
        "exclude": exclude,
        "fixedIp": fixedIp,
        "headers": request_headers,
        "include": include,
        "interval": interval,
        "autoSpeed": autoSpeed,
        "emailType": emailType,
        "levelDeep": levelDeep,
        "proxyName": proxyName,
        "skipCrash": skipCrash,
        "description": description,
        "enumeration": enumeration,
        "projectName": projectName,
        "singleCheck": singleCheck,
        "AllowedHosts": AllowedHosts,
        "interception": interception,
        "scheduleMode": scheduleMode,
        "apiSchemaFile": apiSchemaFile,
        "apiFileEnv": apiFileEnv,
        "attackProfile": attackProfile,
        "durationLimit": durationLimit,
        "durationStatus": durationStatus,
        "excludeClicks": excludeClicks,
        "modifiedEmail": modifiedEmail,
        "jiraProjectName": jiraProjectName,
        "profileLoginName": profileLoginName,
        "secondProfileLoginName": secondProfileLoginName,
        "useOneSession": useOneSession,
        "idorParams": idorParams,
        "targetsExcelFile": targetsExcelFile,
        "ApiIncludeSpider": ApiIncludeSpider,
        "hour": hour,
        "minutes": minutes,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def duplicate_scan(token) -> dict:
    """
    Duplicate an existing scan with the exact same settings on the same asset (Domain)


    Args:
        token (str): Unique identifier of an existing scan target to be duplicated, Ex. yjb6hl4a-y4ej-ngnl-z80j5ulr .

	Returns:
		dict
    """
    path = "DuplicateTarget"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "token": token,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def retest_specific_vulnerability(token, vulnId) -> dict:
    """
    Retesting a specific vulnerability to see if it has been successfully fixed, after running this route, use the "GetVulnById" route to check the status.

    Args:
    token (str): A unique identifier of the scan target, Ex. yjb6hl4a-y4ej-ngnl-z80j5ulr .
    vulnId (int): A unique numeric identifier of the vulnerability to be replicated for retesting,  Ex. 30149. Use the `GetVulnsScan` endpoint to retrieve valid IDs.

	Returns:
		dict
    """
    path = "Retest"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "token": token,
        "vulnId": vulnId,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def pause_scan(tokens) -> dict:
    """
    This route is used to pause a scan (target) only if its status is "In Progress".

    Args:
    token (str): A unique identifier of the scan target, Ex. yjb6hl4a-y4ej-ngnl-z80j5ulr .

	Returns:
		dict
    """
    path = "TargetPause"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "tokens": tokens,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()


@mcp.tool()
def pause_all_scans() -> dict:
    """
    This endpoint pauses all scan targets that are currently "In Progress".

	Returns:
		dict
    """
    path = "PauseAllScans"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        # no parameter
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.get(url, headers=headers, params=data)
    return response.json()



@mcp.tool()
def unpause_scan(tokens) -> dict:
    """
    This route is used to Resume (Unpause) a scan (target) only if its status is "Paused" or "Aborted".

    Args:
    token (str): A unique identifier of the scan target, Ex. yjb6hl4a-y4ej-ngnl-z80j5ulr .

	Returns:
		dict
    """
    path = "TargetUnpause"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "tokens": tokens,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def delete_scan(token) -> dict:
    """
    This endpoint is used to delete the entire scan (target) and all its data.

    Args:
    token (str): A unique identifier of the scan target, Ex. yjb6hl4a-y4ej-ngnl-z80j5ulr .

	Returns:
		dict
    """
    path = "DeleteScan"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "token": token,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def get_all_scans_tokens(urls) -> dict:
    """
    This endpoint retrieves all scans tokens from the server.

    Args:
    urls (str, optional): Required if you want to return URLs instead of tokens. Set to `True` to return URLs; default is `False`.

	Returns:
		Dict
    """
    path = "GetAllScans"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "urls": urls,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.get(url, headers=headers, params=data)
    return response.json()



@mcp.tool()
def get_full_data_of_scan(token) -> dict:
    """
    This endpoint is used to retrieve detailed information about the scan results, including any vulnerabilities detected, technologies, and full scan data, scan time, and more.

    Args:
    token (str): A unique identifier of the scan target, Ex. yjb6hl4a-y4ej-ngnl-z80j5ulr .

	Returns:
		dict
		- Returns Params
		id, url, base_url, description, protocol, tls_version, ip
		server, os_type, technologies, speed, scan_duration, response_time, num_vulns
		num_info, num_low, num_med, num_high, avg_threat, exclude, ports
		ports_num, links, link_folders, subdomains, subdomains_num, token, in_progress
		date, user_id, status, headers, cookies, search_list, single_check
		percent, list_paths, new_headers, shodan_info, shodan_main, project_id, whois
		emails_enum, responsive, is_spa, started, login_method, waiting_forlogin, enumeration
		profile_login_id, level_deep, auto_speed, proxy_id, pfx_file, allow_host, fixed_ip
		login_localStorage, login_sessionStorage, login_localCookies, server_ip, api_schema, dialog, login_headers
		mobile, SPA, link_checked, structure_links, detect_SPA, ns_record, geo_ip
		external_links, duration_limit, jira_id, modifier_email, robots_txt, sitemap_xml, just_cves
		vuln_id, refresh_token, stored, use_payloads, scan_subdomains, all_ports, scan_ports
		login_name, second_profile_login_id, techs_len, external_links_len, event_log_upload, lest_status_change_date, include
		vpn_conf_name, crt_name, key_name, status_code, first_status_code, current_level_deep, monday_project
		postmen_env, save_db, duration_status, approve_duplicate_form, idor_params, use_one_session, dialog_login_id
		proxy_tor, targets.second_profile_login_id, cyscore, exclude_clicks, exclude_wp, req_per_sec, interception
		current_req_per_sec, classify, came_from, skip_crash, include_spider, agent_describe_website, forms
		crnt_forms, event_log, api_schema_status, num_paths, attack_profile_name, vulns
    """
    path = "GetScan"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "token": token,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def get_status_from_specific_scan(token) -> dict:
    """
    This endpoint is used to retrieve the status of a specific scan (Completed / Aborted / Paused / Initiating).

    Args:
    token (str): A unique identifier of the scan target, Ex. yjb6hl4a-y4ej-ngnl-z80j5ulr .

	Returns:
		dict
    """
    path = "GetStatus"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "token": token,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def get_scan_ip(token) -> dict:
    """
    This endpoint is used to obtain the IP address from which the scan was performed.

    Args:
    token (str): A unique identifier of the scan target, Ex. yjb6hl4a-y4ej-ngnl-z80j5ulr .

	Returns:
		dict
		- Returns Params
		Scan IP
    """
    path = "GetScanIP"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "token": token,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def get_endpoints_from_scan(token) -> dict:
    """
    This endpoint (Forms & parameters) allows you to retrieve the scan forms, the endpoint, and all the parameters on which the scan (penetration test) is performed.

    Args:
    token (str): A unique identifier of the scan target, Ex. yjb6hl4a-y4ej-ngnl-z80j5ulr .

	Returns:
		Dict
		- Returns Params
		id, url, action, parameters.tbshg, parameters.#, parameters.user-agent, method
		label, status, request, data, headers.user-agent, combination, ai_prompt
		excluded
    """
    path = "GetForms"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "token": token,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def search_scan(url) -> dict:
    """
    This endpoint allows you to search for scans (targets) based on part of the domain (ex example.com).

    Args:
    url (str): Provide a full URL or a domain name. Ex. "https://www.example.com", "example.com".

	Returns:
		dict
		- Returns Params
		Count, Tokens
    """
    path = "SearchScan"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "url": url,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def scans_work() -> dict:
    """
    This endpoint is used to retrieve all scans whose status is "In Progress" on the platform that are currently active in the system.

	Returns:
		dict
		- Returns Params
		Count, Tokens
    """
    path = "ScansWork"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        # no parameters

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.get(url, headers=headers, params=data)
    return response.json()



@mcp.tool()
def get_all_scans_are_in_progress() -> dict:
    """
    This endpoint is used to retrieve all scans whose status is "In Progress" on the platform that are currently active in the system.

	Returns:
		dict
		- Returns Params
		Count, Tokens
    """
    path = "ScansInProgress"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        # no parameters

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.get(url, headers=headers, params=data)
    return response.json()



@mcp.tool()
def get_all_scans_are_aborted() -> dict:
    """
    This endpoint is used to retrieve all scans whose status is "Aborted" on the platform.

	Returns:
		dict
		- Returns Params
		Count, Tokens
    """
    path = "ScansAborted"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        # no parameters

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.get(url, headers=headers, params=data)
    return response.json()



@mcp.tool()
def get_all_scans_are_completed() -> dict:
    """
    This endpoint is used to retrieve all scans whose status is "Completed".

	Returns:
		dict
		- Returns Params
		Count, Tokens
    """
    path = "ScansCompleted"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        # no parameters

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.get(url, headers=headers, params=data)
    return response.json()



@mcp.tool()
def get_all_scans_are_paused() -> dict:
    """
    This endpoint is used to retrieve all scans whose status is "Paused".

	Returns:
		dict
		- Returns Params
		Count, Tokens
    """
    path = "ScansPaused"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        # no parameters

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.get(url, headers=headers, params=data)
    return response.json()


@mcp.tool()
def change_scan_protection(token) -> dict:
    """
    The **ChangeProtect** endpoint is used to modify or update the protection settings for a specific scan.
	The purpose of this route is to prevent deletion of a specific scan.

    Args:
    token (str): A unique identifier of the scan target, Ex. yjb6hl4a-y4ej-ngnl-z80j5ulr .

	Returns:
		dict
    """
    path = "ChangeProtect"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "token": token,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def change_description_to_specific_scan(token, description) -> dict:
    """
    This endpoint allows users to update a description for a specific scan.

    Args:
    token (str): A unique identifier of the scan target, Ex. yjb6hl4a-y4ej-ngnl-z80j5ulr.
    description (str): User-defined text summarizing the scan’s intent and context.

	Returns:
		dict
    """
    path = "ChangeDescription"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "token": token,
        "description": description,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def change_speed_to_specific_scan(token, speed) -> dict:
    """
    This endpoint allows users to change the speed setting of a specified scan.
	 This operation can only be performed when the scan's status is "In Progress" or "Paused".

    Args:
    token (str): A unique identifier of the scan target, Ex. yjb6hl4a-y4ej-ngnl-z80j5ulr.
    speed (int): Desired scan speed level; valid values are '1' (slowest) through '10' (fastest).

	Returns:
		dict
    """
    path = "ChangeSpeed"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "token": token,
        "speed": speed,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def change_auto_speed_for_running_scan(token) -> dict:
    """
    This endpoint allows users to change the speed setting of a specified scan to Auto speed .
	 This operation can only be performed when the scan's status is "In Progress" or "Paused".

    Args:
    token (str): A unique identifier of the scan target, Ex. yjb6hl4a-y4ej-ngnl-z80j5ulr.

	Returns:
		dict
    """
    path = "ChangeAutoSpeed"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "token": token,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def change_project_for_scan(token, project_name) -> dict:
    """
    This endpoint allows users to assign scans for a project.
	 This operation can be performed for all status scan.

    Args:
    token (str): A unique identifier for the scan target. Ex. yjb6hl4a-y4ej-ngnl-z80j5ulr.
    projectName (str): The name for the project to associate with this scan.

	Returns:
		dict
    """
    path = "ChangeProject"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "token": token,
        "projectName": project_name
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def change_cookies_for_paused_scan(token, cookies) -> dict:
    """
    This endpoint allows users to change the cookies of a specified scan.
	 This operation can only be performed when the scan's status is "Paused".

	Args:
    token (str): A unique identifier for the scan target. Ex. yjb6hl4a-y4ej-ngnl-z80j5ulr.
    cookies (dict): Set cookies during the scan, ex. {"example.com": "key1=val1;key2=val2"} or {"example.com": {"key:val"}}.

	Returns:
		dict
    """
    path = "ChangeCookies"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "token": token,
        "cookies": cookies,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def set_new_headers_for_paused_scan(token, headers) -> dict:
    """
    This endpoint allows users to change the headers of a specified scan.
	 This operation can only be performed when the scan's status is "Paused".

    Args:
    token (str): A unique identifier for the scan target. Ex. yjb6hl4a-y4ej-ngnl-z80j5ulr.
    headers (dict): Set headers during the scan, ex. {"key1": "value1"}


	Returns:
		dict
    """
    path = "SetNewHeaders"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "token": token,
        "headers": headers,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def change_profile_login_for_paused_scan(token, profile_login_name) -> dict:
    """
    This endpoint allows users to change the Login Profile of a specified scan.
	 This operation can only be performed when the scan's status is "Paused".

    Args:
    token (str): A unique identifier for the scan target. Ex. yjb6hl4a-y4ej-ngnl-z80j5ulr.
    profile_login_name (str): profile Login Name, Must match one of the login profiles returned by the `GetLogins` route.



	Returns:
		dict
    """
    path = "ChangeProfileLogin"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "token": token,
        "profile_login_name": profile_login_name,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def get_queue(sort, desc) -> dict:
    """
    This endpoint retrieves the scans that are queued and waiting to start.

    Args:
    sort (str, optional): Field to sort queued scans by. Allowed values: "STATUS", "TARGET", "ID", "DATE".
    desc (str, optional): Set to `True` to sort in descending order; defaults to `False`.

	Returns:
		Dict
		- Returns Params
		token, url, date, status, waiting_forlogin, login_method, priority
		fixed_ip, permission
    """
    path = "GetQueue"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "sort": sort,
        "desc": desc,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.get(url, headers=headers, params=data)
    return response.json()



@mcp.tool()
def delete_queue(token) -> dict:
    """
    This endpoint is used to delete scans from the queue.

    Args:
    token (str): A unique identifier for the scan target. Ex. yjb6hl4a-y4ej-ngnl-z80j5ulr.
    tokens (str, optional): Comma-separated of scan target identifiers for bulk deletion; required if `token` is not provided. Ex. yjb6hl4a-y4ej-ngnl-z80j5ulr, yjb6hl4a-y4ej-ngnl-z80j5ulr.

	Returns:
		dict
		- Returns Params
		token, code, info
    """
    path = "DeleteQueue"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "token": token,

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def enable_queue(token) -> dict:
    """
    This endpoint is allows you to Enable scans in your queue.

    Args:
    token (str): A unique identifier for the scan target. Ex. yjb6hl4a-y4ej-ngnl-z80j5ulr.
    tokens (str, optional): Comma-separated of scan target identifiers for bulk enabling; required if `token` is not provided. Ex. yjb6hl4a-y4ej-ngnl-z80j5ulr, yjb6hl4a-y4ej-ngnl-z80j5ulr.

	Returns:
		dict
		- Returns Params
		token, code, info
    """
    path = "EnableQueue"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "token": token,

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def disable_queue(token) -> dict:
    """
    This endpoint is allows you to Disable scans in your queue.

    Args:
    token (str): A unique identifier for the scan target. Ex. yjb6hl4a-y4ej-ngnl-z80j5ulr.
    tokens (str, optional): Comma-separated of scan target identifiers for bulk disabling; required if `token` is not provided, e.g. yjb6hl4a-y4ej-ngnl-z80j5ulr, yjb6hl4a-y4ej-ngnl-z80j5ulr.

	Returns:
		dict
		- Returns Params
		token, code, info
    """
    path = "DisableQueue"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "token": token,

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def make_queue_priority(status, qToken) -> dict:
    """
    This endpoint allow you to set priority to each queue.

    Args:
    status (str): Flag indicating queue priority. Set to `True` to assign priority or `False` to remove it.
    qToken (str): Unique identifier of the scan target queue. Ex. yjb6hl4a-y4ej-ngnl-z80j5ulr.

	Returns:
		dict
    """
    path = "MakeQueuePriority"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "status": status,
        "qToken": qToken,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def disable_all_queue() -> dict:
    """
    This endpoint is used to disable all queues in the system that are enabled.

	Returns:
		dict
    """
    path = "DisableAllQueue"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        # no parameters

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.get(url, headers=headers, params=data)
    return response.json()



@mcp.tool()
def enable_all_queue() -> dict:
    """
    This endpoint is used to enable all queues in the system that are disabled.

	Returns:
		dict
    """
    path = "EnableAllQueue"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        # no parameters

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.get(url, headers=headers, params=data)
    return response.json()



@mcp.tool()
def get_schedule(sort, desc) -> dict:
    """
    This endpoint retrieves all schedule scans.

    Args:
    sort (str, optional): Field to sort schedule scans by. Allowed values: "STATUS", "TARGET", "ID", "DATE", "EVERY".
    desc (str, optional): Set to `True` to sort in descending order; defaults to `False`.

	Returns:
		Dict
		- Returns Params
		id, url, token, interval_every, user_id, date, status
		login_method, waiting_forlogin, permission
    """
    path = "GetSchedule"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "sort": sort,
        "desc": desc,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.get(url, headers=headers, params=data)
    return response.json()



@mcp.tool()
def delete_schedule(schedule_id) -> dict:
    """
    This endpoint allow to delete a schedule scans.

    Args:
        scheduleId (int): Unique numeric identifier of the scheduled scan to delete; e.g. 1000. Retrieve valid IDs via the `GetSchedule` endpoint.
        scheduleIds (str, optional): Comma-separated of scheduled scan IDs for bulk deletion; required if `scheduleId` is not provided e.g. "1001, 1001".

	Returns:
		dict
		- Returns Params
		0.schedule_id, 0.code, 0.info
    """
    path = "DeleteSchedule"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "scheduleId": schedule_id
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def enable_schedule(schedule_id) -> dict:
    """
    This endpoint allows you to enable scheduled scans that are disabled.

    Args:
        scheduleId (int): Unique numeric identifier of the scheduled scan to enable; Use the `GetSchedule` endpoint to retrieve valid IDs. Ex. 1000.
        scheduleIds (str, optional): Comma-separated of scheduled scan IDs for bulk enabling; required if `scheduleId` is not provided. Use the `GetSchedule` endpoint to retrieve valid IDs. Ex. "1001,1002".


	Returns:
		dict
		- Returns Params
		0.schedule_id, 0.code, 0.info
    """
    path = "EnableSchedule"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "scheduleId": schedule_id

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def disable_schedule(schedule_id) -> dict:
    """
    This endpoint allows you to disable scheduled scans that are enabled.

    Args:
        scheduleId (int): Unique numeric identifier of the scheduled scan to disable; Retrieve valid IDs via the `GetSchedule` endpoint. Example: 1000.
        scheduleIds (str, optional): Comma-separated of scheduled scan IDs to disable in bulk; required if `scheduleId` is not provided. Retrieve valid IDs via the `GetSchedule` endpoint. Example: "1001, 1002".

	Returns:
		dict
		- Returns Params
		0.schedule_id, 0.code, 0.info
    """
    path = "DisableSchedule"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "scheduleId": schedule_id

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def get_projects(sort, desc) -> dict:
    """
    This endpoint retrieves a list of all projects on your system.

    Args:
    sort (str, optional): Field to sort projects by. Allowed values: "NAME", "ID", "COMPANYNAME".
    desc (str, optional): Set to `True` to sort in descending order; defaults to `False`.


	Returns:
		Dict
		- Returns Params
		id, proj_name, user_id, company_name, description, img, duplicate_from_id
		jira_id, create_date, email_notify_string, mail_per_notify, on_completed, on_aborted, on_delete
		on_paused, avg_cyscore_history, queue, targets, permission
    """
    path = "GetProjects"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "sort": sort,
        "desc": desc,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.get(url, headers=headers, params=data)
    return response.json()



@mcp.tool()
def project_targets(project_id, project_name, sort, desc) -> dict:
    """
    This endpoint is used to retrive project's targets associated with a specific project, identified by its full Project id or full project name.

    Args:
        projectId (int): Unique numeric identifier of the project. Use the `GetProjects` endpoint to retrieve valid IDs.
        projectName (str, optional): Name of the project; required if `projectId` is not provided.
        sort (str, optional): Field to sort projects by. Allowed values: "NAME", "ID", "COMPANYNAME".
        desc (str, optional): Set to `True` for descending order; defaults to `False`.

	Returns:
		dict
		- Returns Params
		Targets, Queue, project_name, avg_cyscore
    """
    path = "ProjectTargets"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "projectId": project_id,
        "projectName": project_name,
        "sort": sort,
        "desc": desc,

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def details_project(projectName) -> dict:
    """
    This endpoint allows the user to view detailed information about a specific project.

    Args:
        projectName (str): Name of the project, Use the `GetProjects` endpoint to retrieve valid Names.

	Returns:
		dict
		- Returns Params
		id, proj_name, company_name, description, img, duplicate_from_id, targets
		queue
    """
    path = "DetailsProject"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "projectName": projectName,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def new_project(projectName, jiraProjectName) -> dict:
    """
    This endpoint is used to create a new project in order to merge multiple scans and assets in one place.

    Args:
        projectName (str): Name of the new project.
        jiraProjectName (str, optional): Name of Jira Project to associate with this project, Use the `GetAllJira` endpoint to retrieve valid jira projects names, Default is ''.

	Returns:
		dict
    """
    path = "NewProject"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "projectName": projectName,
        "jiraProjectName": jiraProjectName,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def edit_project(projectName, projectId, jiraProjectName) -> dict:
    """
    This endpoint is used to update (edit) the details of an existing project in the system.
	It allows the user to modify the project's name and its associated Jira project.

    Args:
        projectId (int): Unique numeric identifier of the project to edit, Use the `GetProjects` endpoint to retrieve valid IDs.
        projectName (str, optional): Newly designated formal name for the project.
        jiraProjectName (str, optional): Name of Jira Project to associate with this project, Use the `GetAllJira` endpoint to retrieve valid jira projects names, Default is ''.


	Returns:
		dict
    """
    path = "EditProject"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "projectName": projectName,
        "projectId": projectId,
        "jiraProjectName": jiraProjectName,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def delete_project(projectName, recursive) -> dict:
    """
    This endpoint allows users to delete a project.
	If the recursive parameter is set to true, all scans associated with that project will also be removed.

	Args:
	    projectName (str): Name of the project to delete, Use the `GetProjects` endpoint to retrieve valid Names.
	    recursive (str, optional): Set to `True` to delete all scans associated with that project, Default is `False`.

	Returns:
		dict
    """
    path = "DeleteProject"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "projectName": projectName,
        "recursive": recursive,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def get_all_vulns() -> dict:
    """
    This endpoint retrieves a list of all vulnerabilities id from the system.

	Returns:
		Dict
		- Returns Params
		id
    """
    path = "GetAllVulns"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        # no parameters

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.get(url, headers=headers, params=data)
    return response.json()



@mcp.tool()
def get_vuln_by_id(vulnId) -> dict:
    """
    This endpoint retrieves full detailed information about a specific vulnerability based on its unique ID.

    Args:
        vulnId (int): System-assigned numeric identifier of the vulnerability instance, Ex. 122628.

	Returns:
		dict
		- Returns Params
		id, id_connection, url, action, vuln_name, severity, request
		key, payload.WAF, payload.Found At, payload.Found With, method, params, cookies
		headers, status_code, content_type, fixed, token, version, form
		img, user_append, sqli_table, form_id, markup, date, response
		comment, ai_rec, form_json, business_logic, description, impact, recommendation
		links, more_details, cwe, cvss
    """
    path = "GetVulnById"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "vulnId": vulnId,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def get_vuln_by_name(vulnName) -> dict:
    """
    This endpoint allows users to retrieve information about a specific vulnerability by its name.

    Args:
        vulnName (str): Unique name of the vulnerability to retrieve information for.


	Returns:
		dict
		- Returns Params
		id, ai_rec, id_connection, url, action, vuln_name, severity
		request, response, key, payload, method, params, cookies
		headers, hosts_file, status_code, content_type, fixed, token, version
		form, img, user_append, sqli_table, markup, form_id, date
		jira_ticket_id, user_id, comment, findByEngine
    """
    path = "GetVulnByName"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "vulnName": vulnName,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def get_vulns_scan(token) -> dict:
    """
    This endpoint allows users to retrieve information about a specific vulnerability by its token.

    Args:
        token (str): Unique identifier of the scan target . Ex. yjb6hl4a-y4ej-ngnl-z80j5ulr.

	Returns:
		Dict
		- Returns Params
		id, url, action, vuln_name, severity, method, fixed
		user_append, request, response, key, payload, params, cookies
		headers, status_code, token, version, img, markup, ai_rec
    """
    path = "GetVulnsScan"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "token": token,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def last_scans_vuln(by) -> dict:
    """
    This endpoint use to retrieve the latest scan vulnerability data.
	Example Values - 
		by=

    Args:
        by (str, optional): Required filter field; set to “url” or “base_url” to retrieve vulnerabilities by full URL or base URL.

	Returns:
		Dict
		- Returns Params
		token, url, base_url, description, protocol, tls_version, ip
		server, os_type, technologies, speed, scan_duration, response_time, num_vulns
		num_info, num_low, num_med, num_high, avg_threat, exclude, ports
		ports_num, links, link_folders, num_links, subdomains, subdomains_num, in_progress
		date, user_id, status, scan headers, scan cookies, search_list, single_check
		percent, list_paths, new_headers, shodan_info, shodan_main, project_id, whois
		emails_enum, responsive, is_spa, started, login_method, waiting_forlogin, integrity_token
		enumeration, profile_login_id, level_deep, auto_speed, proxy_id, pfx_file, har
		api_target, file_crawler, fixed_ip, login_localStorage, login_sessionStorage, login_localCookies, server_ip
		api_schema, dialog, login_headers, mobile, SPA, link_checked, structure_links
		detect_SPA, ns_record, geo_ip, external_links, duration_limit, jira_id, modifier_email
		robots_txt, sitemap_xml, just_cves, vuln_id, refresh_token, stored, use_payloads
		Vulnerabilities
    """
    path = "LastScansVuln"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "by": by,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.get(url, headers=headers, params=data)
    return response.json()



@mcp.tool()
def vuln_fix(vulnId, token, isFixed) -> dict:
    """
    This endpoint is used to report the resolution status of a specific vulnerability identified by its ID.
	This allows users to indicate whether a vulnerability has been fixed or not.

    Args:
        vulnId (int): Unique numeric identifier of the vulnerability. Ex. 122628.
        token (str): Unique identifier of the scan target. Ex. yjb6hl4a-y4ej-ngnl-z80j5ulr.
        isFixed (str): Resolution flag; set to `True` to mark the vulnerability as fixed; defaults is `False`.

	Returns:
		dict
    """
    path = "VulnFix"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "vulnId": vulnId,
        "token": token,
        "isFixed": isFixed,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def mark_fp(vulnId, token) -> dict:
    """
    This endpoint is used to mark a specific vulnerability as a FalsePositive, in order to improve the user's system and prevent a situation of false positives.

    Args:
        vulnId (int): Unique numeric identifier of the vulnerability. Ex. 122628.
        token (str): Unique identifier of the scan target. Ex. yjb6hl4a-y4ej-ngnl-z80j5ulr.

	Returns:
		dict
    """
    path = "MarkFP"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "vulnId": vulnId,
        "token": token,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def update_vuln_severity(vulnId, token, newSeverity) -> dict:
    """
    This endpoint can be used to change the severity level of an existing vulnerability found in a scan (High/Medium/Low/Informative).

    Args:
        vulnId (int): Unique numeric identifier of the vulnerability. Ex. 122628.
        token (str): Unique identifier of the scan target. Ex. yjb6hl4a-y4ej-ngnl-z80j5ulr.
        newSeverity (str): New severity level for the vulnerability; allowed values are "High", "Medium", "Low", "Informative".

	Returns:
		dict
    """
    path = "UpdateVulnSeverity"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "vulnId": vulnId,
        "token": token,
        "newSeverity": newSeverity,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def append_vuln(token, vulnname, severity, key, payload, url, action, method, statusCode, img, description, impact, recommendation, links, cwe, cvss, details) -> dict:
    """
    This endpoint allows users to add a new vulnerability entry to the scan.
	It is primarily used to report vulnerabilities found during a manual scan process - this way the vulnerability can be added to the scan

    Args:
        token (str): Unique identifier of the scan target, e.g. yjb6hl4a-y4ej-ngnl-z80j5ulr.
        vulnName (str): Internal reference name of the vulnerability, e.g. SQL_INJECTION.
        severity (str): Severity level; allowed values “High”, “Medium”, “Low”, “Informative”.
        key (str, optional): HTTP parameter or header name exploited during testing.
        payload (str, optional): Attack vector or input used to verify the vulnerability.
        url (str, optional): Full URL where the issue was detected.
        action (str, optional): Target endpoint or form action associated with the test.
        method (str, optional): HTTP method used for the test, e.g. “GET” or “POST”.
        statusCode (str, optional): HTTP response code observed during testing, e.g. “200”.
        img (str, optional): Filename of the uploaded evidence image, e.g. “screenshot_123.png”.
        description (str, optional): Detailed summary of the vulnerability’s behavior and context.
        impact (str, optional): Potential security or business impact if exploited.
        recommendation (str, optional): Remediation guidance, such as input validation or patch instructions.
        links (str, optional): Comma-separated list of reference URLs, e.g. OWASP or CVE entries.
        cwe (str, optional): Related CWE identifier, e.g. “CWE-79”.
        cvss (str, optional): CVSS score representing severity, e.g. “7.5”.
        details (str, optional): Additional technical context, logs, or reproduction steps.

	Returns:
		dict
    """
    path = "AppendVuln"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "token": token,
        "vulnName": vulnname,
        "severity": severity,
        "key": key,
        "payload": payload,
        "url": url,
        "action": action,
        "method": method,
        "statusCode": statusCode,
        "img": img,
        "description": description,
        "impact": impact,
        "recommendation": recommendation,
        "links": links,
        "cwe": cwe,
        "cvss": cvss,
        "details": details
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def del_vuln(vulnId, token) -> dict:
    """
    This endpoint used to delete a vulnerability from specific scan.

    Args:
        vulnId (int): Unique numeric identifier of the vulnerability. Ex. 122628.
        token (str): Unique identifier of the scan target, e.g. yjb6hl4a-y4ej-ngnl-z80j5ulr.

	Returns:
		dict
    """
    path = "DelVuln"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "vulnId": vulnId,
        "token": token,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def search_vulns(search, url, token, severity, limit, offset) -> dict:
    """
    This endpoint allows users to submit a search query and receive a list of vulnerabilities that match the specified parameters.
	---
	Default Offset = 0
	Default Limit = 20
	Maximum Limit = 20
	For Example:
	offset = 1500, limit = 20
	Will give you results from 1500 until 1520.
	---
	severities = High/Medium/Low/Informative
	sorted by severity: High-> Informative

    Args:
        search (str, optional): Search expression matching vulnerability name or action.
        url (str, optional): Filter results by full URL or domain.
        token (str, optional): Scan target identifier, e.g. yjb6hl4a-y4ej-ngnl-z80j5ulr.
        severity (str, optional): Severity level; allowed values “High”, “Medium”, “Low”, “Informative”.
        limit (int, optional): Number of records to return; defaults to 20; maximum 20.
        offset (int, optional): Number of records to skip; defaults to 0.

	Returns:
		Dict
		- Returns Params
		id, url, action, vuln_name, severity, method, fixed
		user_append, request, response, key, payload, params, cookies
		headers, status_code, token, version, img, markup
    """
    path = "SearchVulns"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "search": search,
         "url": url,
        "token": token,
        "severity": severity,
        "limit": limit,
        "offset": offset

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def get_all_unique_vulns(search) -> dict:
    """
    This endpoint is used to return a summary of how many times the vulnerabilities were found and in how many different scans.
	
	
	Search param empty for all vulnerabilities or write for example "xss" just for xss vulnerability

	Args:
	    search (str, optional): Search vulnerabilities by name, e.g. "DOM Cross-site Scripting (XSS)".

	Returns:
		dict
		- Returns Params
		CSP header not implemented.found, CSP header not implemented.scans
    """
    path = "GetAllUniqueVulns"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "search": search,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def vulns_summary() -> dict:
    """
    This endpoint is used to return a summary of how many times the vulnerabilities were found and in how many different scans.

	Returns:
		dict
		- Returns Params
		Total_High_Number, Total_Medium_Number, Total_Low_Number, Total_Informative_Number, Total_Vulnerabilities, Last_HighVulnerability_Found.Severity, Last_HighVulnerability_Found.Vulnerability Name
		Last_HighVulnerability_Found.Date, Last_HighVulnerability_Found.Website, Last_MediumVulnerability_Found.Severity, Last_MediumVulnerability_Found.Vulnerability Name, Last_MediumVulnerability_Found.Date, Last_MediumVulnerability_Found.Website, Last_LowVulnerability_Found.Severity
		Last_LowVulnerability_Found.Vulnerability Name, Last_LowVulnerability_Found.Date, Last_LowVulnerability_Found.Website, Last_InformativeVulnerability_Found.Severity, Last_InformativeVulnerability_Found.Vulnerability Name, Last_InformativeVulnerability_Found.Date, Last_InformativeVulnerability_Found.Website
    """
    path = "VulnsSummary"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        # no parameters

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.get(url, headers=headers, params=data)
    return response.json()



@mcp.tool()
def server_info() -> dict:
    """
    This endpoint is used to retrieve information about the server like scan count / company name / edition (License) / Target Capacity / Allowed IPs and more.

	Returns:
		dict
		- Returns Params
		ScansCount, CompanyName, Edition, DomainCapacity, Allowed ips
    """
    path = "ServerInfo"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        # no parameters

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.get(url, headers=headers, params=data)
    return response.json()



@mcp.tool()
def get_all_fixedip() -> dict:
    """
    This endpoint is used to retrieve all Fixed IP that assign to your server.

	Returns:
		Dict
    """
    path = "GetAllFixedIP"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        # no parameters

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.get(url, headers=headers, params=data)
    return response.json()



@mcp.tool()
def update_company(name, address, areaCode, phone, email, website, description, timeZoneOffset, mailNotify) -> dict:
    """
    This endpoint allows users to update the details of a company.

    Args:
        name (str): Full, official company name as registered in your system.
        address (str): Complete street address, including street number, city and country.
        areaCode (str): area code corresponding to the company’s location (e.g., “972”).
        phone (str): Primary contact number (e.g., “54444444”).
        email (str): Main contact email address for correspondence and notifications.
        website (str): Public-facing URL of the company’s website.
        description (str, optional): Detailed overview of the company’s mission, services and expertise.
        timeZoneOffset (str, optional): Time zone offset for scheduling (e.g., “+03:00”); defaults to “-00:00”.
        mailNotify (str, optional): Flag to enable or disable email alerts; set to “True” to receive notifications or “False” to suppress them.



	Returns:
		dict
    """
    path = "UpdateCompany"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "name": name,
        "address": address,
        "areaCode": areaCode,
        "phone": phone,
        "email": email,
        "website": website,
        "description": description,
        "timeZoneOffset": timeZoneOffset,
        "mailNotify": mailNotify

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def change_server_token(token) -> dict:
    """
    This endpoint is used to change the server token (3-12 chars, a-z 0-9).

    Args:
        token (str): New server token for authentication; must consist of 3–12 lowercase alphanumeric characters (a–z, 0–9).


	Returns:
		dict
    """
    path = "ChangeServerToken"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "token": token,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def get_proxies() -> dict:
    """
    This endpoint used to fetch all of the Proxies list that exists in your server.

	Returns:
		Dict
		- Returns Params
		id, ip, port, name, permission
    """
    path = "GetProxies"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        # no parameters

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.get(url, headers=headers, params=data)
    return response.json()



@mcp.tool()
def get_proxy(proxyName) -> dict:
    """
    This endpoint used to fetch a specific Proxy.

    Args:
        proxyName (str): Name of the proxy to fetch, use the `GetProxies` endpoint to retrieve valid names.

	Returns:
		dict
		- Returns Params
		id, ip, port, name
    """
    path = "GetProxy"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "proxyName": proxyName,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def add_proxy(ip, port, name, auth, username, password) -> dict:
    """
    This endpoint allows you to create a custom Proxy for your own use.

    Args:
        ip (str): IP address of the proxy server.
        port (str): TCP port number to connect to the proxy.
        name (str): Custom name for this proxy configuration.
        auth (str, optional): Flag to enable basic authentication; set to `True` to require `username` and `password`; defaults to `False`.
        username (str, optional): Username for basic authentication; required if `auth` is `True`.
        password (str, optional): Password for basic authentication; required if `auth` is `True`.




	Returns:
		dict
    """
    path = "AddProxy"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "ip": ip,
        "port": port,
        "name": name,
        "auth": auth,
        "username": username,
        "password": password

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def check_proxy(ip, port, name, auth, username, password) -> dict:
    """
    This endpoint used to check if an existing Proxy is Working (Alive) to use or not working.

    Args:
        ip (str): IPv4 or IPv6 address of the proxy to validate.
        port (str): TCP port number of the proxy to validate.
        name (str): Registered name of the proxy configuration in your system, use the `GetProxies` endpoint to retrieve valid names.
        auth (str, optional): Flag to enable authentication; set to `True` to require `username` and `password`; defaults to `False`.
        username (str, optional): Username for basic authentication; required if `auth` is `True`.
        password (str, optional): Password for basic authentication; required if `auth` is `True`.


	Returns:
		dict
    """
    path = "CheckProxy"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "ip": ip,
        "port": port,
        "name": name,
        "auth": auth,
        "username": username,
        "password": password

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def delete_proxy(name) -> dict:
    """
    This endpoint allow user to delete existing Proxy.

    Args:
        name (str): Name of the proxy configuration to delete; retrieve valid names via the `GetProxies` endpoint.


	Returns:
		dict
    """
    path = "DeleteProxy"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "name": name,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def get_payloads() -> dict:
    """
    StartFragment
	 This endpoint allows the user to retrieve all payloads that the user has created themselves.EndFragment

	Returns:
		Dict
		- Returns Params
		uuid, user_id, name, payloads, src_result, severity, permissions
    """
    path = "GetPayloads"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        # no parameters

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.get(url, headers=headers, params=data)
    return response.json()



@mcp.tool()
def new_payload(name, payload, srcResult, severity, description, impact, recommendation, links, cwe, cvss, details) -> dict:
    """
    This endpoint used to create and upload a new payload for Cytrix to use during scanning (Penetration Testing).

    Args:
        name (str): Unique, descriptive identifier for the custom payload.
        payload (str): Payload content or script to be executed during scanning.
        srcResult (str): Source reference or expected result identifier for this payload.
        severity (str): Impact classification; allowed values “High”, “Medium”, “Low”, “Informative”.
        description (str, optional): Brief overview of the payload’s purpose and behavior.
        impact (str, optional): Analysis of potential risks if the payload is executed.
        recommendation (str, optional): Suggested mitigation steps or handling procedures.
        links (str, optional): Comma-separated list of reference URLs for further information.
        cwe (str, optional): Associated CWE identifier, e.g. “CWE-89”.
        cvss (str, optional): CVSS score representing severity, e.g. “7.5”.
        details (str, optional): Additional technical context, code snippets, or usage instructions.


	Returns:
		dict
    """
    path = "NewPayload"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "name": name,
        "payload": payload,
        "srcResult": srcResult,
        "severity": severity,
        "description": description,
        "impact": impact,
        "recommendation": recommendation,
        "links": links,
        "cwe": cwe,
        "cvss": cvss,
        "details": details

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def update_payload(payloadId, name, payload, srcResult, severity) -> dict:
    """
    This endpoint used to Edit and Update a Payload that exists on your Server.

    Args:
        payloadId (str): Unique identifier of the custom payload to modify; retrieve valid IDs via `GetPayloads`.
        name (str, optional): New unique identifier for the payload.
        payload (str, optional): Updated content or script to execute during scanning.
        srcResult (str, optional): Updated source reference or expected result identifier.
        severity (str, optional): Updated impact classification; allowed values “High”, “Medium”, “Low”, “Informative”.


	Returns:
		dict
    """
    path = "UpdatePayload"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "payloadId": payloadId,
        "name": name,
        "payload": payload,
        "srcResult": srcResult,
        "severity": severity,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def delete_payload(payloadId) -> dict:
    """
    This endpoint allows you to Delete a Payload from your Server.

    Args:
        payloadId (str): Unique identifier of the custom payload to delete; retrieve valid IDs via `GetPayloads`.

	Returns:
		dict
    """
    path = "DeletePayload"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "payloadId": payloadId,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def get_logins() -> dict:
    """
    This endpoint used to fetch all existing Login Authentications\\Login Profiles.

	Returns:
		Dict
		- Returns Params
		id, url, username, type_login, headers, name, permission
    """
    path = "GetLogins"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        # no parameters

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.get(url, headers=headers, params=data)
    return response.json()



@mcp.tool()
def get_emails() -> dict:
    """
    This endpoint retrieves all email addresses associated with Authentication/Login Profiles.

	Returns:
		Dict
		- Returns Params
		id, email
    """
    path = "GetAllEmails"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        # no parameters

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.get(url, headers=headers, params=data)
    return response.json()



@mcp.tool()
def get_phone_numbers() -> dict:
    """
    This endpoint retrieves all phone numbers registered in the Authentication/Login Profiles

	Returns:
		Dict
		- Returns Params
		id, email
    """
    path = "GetAllPhones"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        # no parameters

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.get(url, headers=headers, params=data)
    return response.json()



@mcp.tool()
def create_login_profile(loginMethod, loginName, loginUrl, username, password, params, headers_login, otpPhoneNumber,
             otpEmail, otpReg, logout, verifyLoginStatus, verifyLoginUrl, verifyLoginPage, verifyLoginStr, loginAutoAfter,
             ssoSelector, authSecretKey, cookies, data, prompt) -> dict:
    """
    This endpoint allow you to create new Login Authentication\\Login Profiles to use in your scans.

	Login Methods are:
        - **login_ai** (Recommended)
          AI-driven assistance for any login flow—automates form interactions, handles dynamic challenges, and retrieves verification codes.
          **Required:** `loginMethod`, `loginName`, `loginUrl`, `prompt`

        - **otp_email**
          Email-based one-time password authentication.
          **Required:** `loginMethod`, `loginName`, `loginUrl`, `username`, `otpEmail`, `otpReg`

        - **otp_sms**
          SMS-based one-time password authentication.
          **Required:** `loginMethod`, `loginName`, `loginUrl`, `username`, `otpPhoneNumber`, `otpReg`

        - **google_authenticator**
          Time-based OTP using Google Authenticator.
          **Required:** `loginMethod`, `loginName`, `loginUrl`, `username`, `authSecretKey`

        - **microsoft_authenticator**
          Time-based OTP using Microsoft Authenticator.
          **Required:** `loginMethod`, `loginName`, `loginUrl`, `username`, `authSecretKey`

        - **google_sso**
          Single Sign-On via Google identity provider.
          **Required:** `loginMethod`, `loginName`, `loginUrl`, `ssoSelector`

        - **microsoft_sso**
          Single Sign-On via Microsoft identity provider.
          **Required:** `loginMethod`, `loginName`, `loginUrl`, `ssoSelector`

        - **custom_login**
          Custom form-based login with user-defined request body.
          **Required:** `loginMethod`, `loginName`, `loginUrl`, `params`

        - **headers**
          Header-based authentication (e.g., API tokens in headers).
          **Required:** `loginMethod`, `loginName`, `loginUrl`, `headers`

        - **basic_auth**
          Standard login dialog using HTTP Basic authentication.
          **Required:** `loginMethod`, `loginName`, `loginUrl`, `username`, `password`

        # You may include additional optional parameters as needed for your specific login scenario:
            - `logout`
            - `verifyLoginStatus`
            - `verifyLoginUrl`
            - `verifyLoginPage`
            - `verifyLoginStr`
            - `loginAutoAfter`
            - `data`
            - `prompt`

    Args:
        loginName (str): Unique name for this login profile, e.g. “MyLoginProfile”.
        loginMethod (str, optional): Authentication method; one of “login_ai” (recommended), “otp_email”, “otp_sms”, “google_authenticator”, “microsoft_authenticator”, “google_sso”, “microsoft_sso”, “custom_login”, “headers”, “basic_auth”, e.g. “login_ai”.
        loginUrl (str, optional): URL of the login endpoint, e.g. “https://example.com/login”.
        username (str, optional): Username credential for authentication. Use just for “google_sso”, “microsoft_sso”, and “basic_auth”
        password (str, optional): Password credential for authentication. Use just for “google_sso”, “microsoft_sso”, and “basic_auth”
        params (dict, optional): Additional form parameters as key–value pairs for login. e.g. {"id": 123456, "username": "admin", "password": "admin"}, Use just for “login_ai”
        headers (dict, optional): HTTP headers to include in the authentication request, e.g. {"key1": "value1"}, default is {}.
        otpPhoneNumber (str, optional): Phone number for OTP SMS authentication, e.g. “+1234567890”, Use 'GetAllPhones' to retrieve all phone numbers.
        otpEmail (str, optional): Email address for OTP email authentication, e.g. “user@example.com”, use 'GetAllEmails' to retrieve all emails.
        otpReg (str, optional): Regex pattern to extract OTP from messages; choose from:
                                                                                            1. r"\b\d{6}\b"
                                                                                            2. r"\b\d{9}\b"
                                                                                            3. r"\b\d{8}\b"
                                                                                            4. r"\b\d{4}\b"
                                                                                            5. r"\b[a-zA-Z0-9]{6}\b"
                                                                                            6. r"\b[a-zA-Z0-9]{9}\b"
                                                                                            7. r"\b[a-zA-Z0-9]{8}\b"
                                                                                            8. r"\b[a-zA-Z0-9]{4}\b"
                                                                                            9. r"\b\d{5}\b"
                                                                                            10. r"\b[a-zA-Z0-9]{5}\b"

        logout (str, optional): Text pattern identifying logout/signout elements to skip clicking (e.g. "logout", "signout")
        verifyLoginStatus (str, optional): HTTP status code or condition indicating successful login, e.g. “200”.
        verifyLoginUrl (str, optional): URL to confirm login success, e.g. “https://example.com/dashboard”.
        verifyLoginPage (str, optional): DOM selector or content snippet to verify the post-login page, e.g. “#welcome-message”.
        verifyLoginStr (str, optional): Text expected on the success page to confirm authentication, e.g. “Welcome, user!”.
        loginAutoAfter (int, optional): Interval in hours after which the system automatically retries login.
        ssoSelector (str, optional): CSS selector to locate the SSO element on the login page, e.g. “.sso-button”.
        authSecretKey (str, optional): Secret key or token used for authentication flows, e.g. “abc123secret”.
        cookies (dict, optional): Cookie name–value pairs to set prior to authentication, e.g. {"example.com": "key1=val1;key2=val2"} or {"example.com": {"key:val"}}, default is {}.
        data (dict, optional): Custom request body parameters for “login_ai” flows, e.g. {"token": "xyz"}.
        prompt (str, optional): Instruction prompt for AI-driven authentication (used with “login_ai”), e.g. “Please solve the captcha.”.


	Returns:
		dict
    """
    path = "AddLogin"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "loginMethod": loginMethod,
        "loginName": loginName,
        "loginUrl": loginUrl,
        "username": username,
        "password": password,
        "params": params,
        "headers": headers_login,
        "otpPhoneNumber": otpPhoneNumber,
        "otpEmail": otpEmail,
        "otpReg": otpReg,
        "logout": logout,
        "verifyLoginStatus": verifyLoginStatus,
        "verifyLoginUrl": verifyLoginUrl,
        "verifyLoginPage": verifyLoginPage,
        "verifyLoginStr": verifyLoginStr,
        "loginAutoAfter": loginAutoAfter,
        "ssoSelector": ssoSelector,
        "authSecretKey": authSecretKey,
        "cookies": cookies,
        "data": data,
        "prompt": prompt
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def delete_login(loginName) -> dict:
    """
    This endpoint allow you to delete existing Login Authentications\\Profiles from your server.

    Args:
        loginName (str): Unique name of the login profile to delete.

	Returns:
		dict
    """
    path = "DeleteLogin"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "loginName": loginName,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def get_files() -> dict:
    """
    This endpoint used to retrieve all files on the server.

	Returns:
		Dict
		- Returns Params
		name, size, date, category, description, user_id, permission
		user_name
    """
    path = "GetFiles"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        # no parameters

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.get(url, headers=headers, params=data)
    return response.json()



@mcp.tool()
def upload_file(name, fileExtension, file, category, description) -> dict:
    """
    This endpoint is used to upload files to your storage for use during scanning.
	Categories:
	1.
	api_schema (json,gql,zip,yaml,txt,ql)


	2.
	img (jpg/png)


	3.
	crt


	4.
	custom_template (doc/docx)


	5.
	idor_params (json file)

    Args:
        name (str): Descriptive name for the uploaded file.
        fileExtension (str): File extension without the dot, e.g. “json”, “jpg”, “docx”.
        file (str): Base64-encoded content of the file.
        category (str): File category; one of “api_schema”, “img”, “crt”, “custom_template”, “idor_params”.
        description (str, optional): Brief description of the file’s purpose.

	Returns:
		dict
    """
    path = "UploadFile"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "name": name,
        "fileExtension": fileExtension,
        "file": file,
        "category": category,
        "description": description

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def delete_file(name) -> dict:
    """
    This endpoint is used to delete files from your storage.

    Args:
        name (str): System-registered identifier of the file to delete.

	Returns:
		dict
    """
    path = "DeleteFile"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "name": name,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def get_users() -> dict:
    """
    This endpoint allows you to retrieve all the details about all existing users on your server.

	Returns:
		Dict
		- Returns Params
		Id, Email, FirstName, LastName, Phone, Admin, Last_Login
		Title, Last_Ip, Role
    """
    path = "GetUsers"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        # no parameters

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.get(url, headers=headers, params=data)
    return response.json()



@mcp.tool()
def get_user(email) -> dict:
    """
    This endpoint allow you to fetch information of a certain user on your server.

    Args:
        email (str): Registered email address of the user to fetch.

	Returns:
		dict
		- Returns Params
		id, Email, FirstName, LastName, Phone, Admin, Role
    """
    path = "GetUser"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "email": email,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def adduser(email, firstName, lastName, password, areaCode, phone, role, title, projectids) -> dict:
    """
    This endpoint allows administrators to add users to the server.

   Args:
        email (str): Registered email address of the user to add, e.g. “user@example.com”.
        firstName (str): User’s first name, e.g. “Alice”.
        lastName (str): User’s last name, e.g. “Smith”.
        password (str): User’s password (minimum 8 characters, must include at least one uppercase letter, one number, and one special character).
        areaCode (str): Country calling code, e.g. “972”.
        phone (str): Local phone number, e.g. “501234567”.
        role (str): User role; allowed values: “Administrator”, “User”, “PrivateUser”, “Viewer”.
        title (str, optional): Job title or position, e.g. “Security Analyst”.
        projectIds (str, optional): Comma-separated of project IDs (e.g. “1180, 1184”); required only if `role` is “Viewer”. Use the `GetProjects` endpoint to retrieve valid IDs.

	Returns:
		dict
    """
    path = "AddUser"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "email": email,
        "firstName": firstName,
        "lastName": lastName,
        "password": password,
        "areaCode": areaCode,
        "phone": phone,
        "role": role,
        "title": title,
        "projectIds": projectids

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def get_user_profile() -> dict:
    """
    This endpoint allows the user to view their profile.

	Returns:
		dict
		- Returns Params
		email, firstName, lastName, phone, emailNotifications.onDelete, emailNotifications.onStop, emailNotifications.onChangeStatus
		emailNotifications.onQueueStart, emailNotifications.onScheduleStart, emailNotifications.onAborted
    """
    path = "GetUserProfile"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        # no parameters

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.get(url, headers=headers, params=data)
    return response.json()



@mcp.tool()
def change_my_details(firstName, lastName, areaCode, phone) -> dict:
    """
    This endpoint allows the user to change their details.

    Args:
        firstName (str, optional): New first name of the user, e.g. “Alice.”
        lastName (str, optional): New last name of the user, e.g. “Smith.”
        areaCode (str, optional): Country calling code, e.g. “972.”
        phone (str, optional): Local phone number, e.g. “501234567.”

	Returns:
		dict
    """
    path = "ChangeMyDetails"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "firstName": firstName,
        "lastName": lastName,
        "areaCode": areaCode,
        "phone": phone,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def change_password(newPassword, oldPassword) -> dict:
    """
    This endpoint allows the user to change their password.

    Args:
        oldPassword (str): Current password for verification.
        newPassword (str): New password (minimum 8 characters, including at least one uppercase letter, one number, and one special character).

	Returns:
		dict
    """
    path = "ChangePassword"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "newPassword": newPassword,
        "oldPassword": oldPassword,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def change_password_user(newPassword, adminPassword, id) -> dict:
    """
    This endpoint allows an administrator to change the password of another user.

    Args:
        newPassword (str): New password for the user (minimum 8 characters, including at least one uppercase letter, one number, and one special character).
        adminPassword (str): Administrator’s current password for authorization.
        id (int): Numeric identifier of the user whose password will be changed; retrieve via the `GetUsers` endpoint.


	Returns:
		dict
    """
    path = "ChangePasswordUser"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "newPassword": newPassword,
        "adminPassword": adminPassword,
        "id": id,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def update_mail_notify_for_user(mailCompleted, mailStop, mailPause, mailUnpause, mailDelete, mailStatus, mailQueue, mailSchedule, mailAborted) -> dict:
    """
    This endpoint allows the user to edit anything related to receiving email notifications about their scans.

    Args:
        mailCompleted (str): Set to ‘True’ to receive an email when a scan completes; defaults to ‘False’.
        mailStop (str): Set to ‘True’ to receive an email when a scan is stopped; defaults to ‘False’.
        mailPause (str): Set to ‘True’ to receive an email when a scan is paused; defaults to ‘False’.
        mailUnpause (str): Set to ‘True’ to receive an email when a scan is resumed; defaults to ‘False’.
        mailDelete (str): Set to ‘True’ to receive an email when a scan is deleted; defaults to ‘False’.
        mailStatus (str): Set to ‘True’ to receive an email on any status change; defaults to ‘False’.
        mailQueue (str): Set to ‘True’ to receive an email when a scan is queued; defaults to ‘False’.
        mailSchedule (str): Set to ‘True’ to receive an email when a scan is scheduled; defaults to ‘False’.
        mailAborted (str): Set to ‘True’ to receive an email when a scan is aborted; defaults to ‘False’.

	Returns:
		dict
    """
    path = "UpdateMailNotify"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "mailCompleted": mailCompleted,
        "mailStop": mailStop,
        "mailPause": mailPause,
        "mailUnpause": mailUnpause,
        "mailDelete": mailDelete,
        "mailStatus": mailStatus,
        "mailQueue": mailQueue,
        "mailSchedule": mailSchedule,
        "mailAborted": mailAborted,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def change_details_user(u_id, email, firstName, lastName, areaCode, phone, role, title, projectIds) -> dict:
    """
    This endpoint allows an administrator to change another user's details

    Args:
        id (int): Unique numeric identifier of the user to update; retrieve via the `GetUsers` endpoint.
        email (str): Registered email address for identity verification; must match the user’s existing email.
        firstName (str, optional): New first name for the user, e.g. “Alice”.
        lastName (str, optional): New last name for the user, e.g. “Smith”.
        areaCode (int, optional): Country calling code, e.g. 972.
        phone (str, optional): Local phone number, e.g. "4151234567".
        role (str, optional): New role; allowed values: “Administrator”, “User”, “PrivateUser”, “Viewer”.
        title (str, optional): New job title or position, e.g. “Security Analyst”.
        projectIds (str, optional): Comma-separated of project IDs to assign e.g. "1180,1184"; required if `role` is “Viewer”.

	Returns:
		dict
    """
    path = "ChangeDetailsUser"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "id": u_id,
        "email": email,
        "firstName": firstName,
        "lastName": lastName,
        "areaCode": areaCode,
        "phone": phone,
        "role": role,
        "title": title,
        "projectIds": projectIds
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def delete_user(email, id) -> dict:
    """
    This endpoint allows a system administrator to remove a user from the system.

    Args:
        email (str): Registered email address of the user to delete.
        id (int): Unique numeric identifier of the user; retrieve valid IDs via the `GetUsers` endpoint.

	Returns:
		dict
    """
    path = "DeleteUser"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "email": email,
        "id": id,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def getreports() -> dict:
    """
    This endpoint allows access to view exported reports.

	Returns:
		Dict
		- Returns Params
		uuid, date, name, status, content_type, created_by, ext
		report_security, permission
    """
    path = "GetReports"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        # no parameters

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.get(url, headers=headers, params=data)
    return response.json()



@mcp.tool()
def create_report(type, token, vulnsIds) -> dict:
    """
    This endpoint allows the user to begin the process of creating a report that summarizes a particular scan.

    Args:
        type (str): Report format; allowed values: “csv”, “html”, “doc”, “pdf”, “dev”, “black”, “bir”, “temp”, “json”, “xml”.
        token (str, optional): Scan target identifier, e.g. “yjb6hl4a-y4ej-ngnl-z80j5ulr”.
        vulnsIds (str): Comma-separated list of vulnerability IDs to include in the report (e.g. “122628,122629”); use the `GetVulnsScan` endpoint to retrieve valid IDs or set to “all” to include every finding.

	Returns:
		dict
    """
    path = "CreateReport"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "type": type,
        "token": token,
        "vulnsIds": vulnsIds,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def create_project_report(type_of_doc, projectName, projectId) -> dict:
    """
    This endpoint allows the user to create a summary report on an entire project, even if it consists of multiple scans.

    Args:
        type (str): Report format; allowed values: “csv”, “html”, “doc”, “pdf”, “dev”, “black”, “bir”, “temp”, “json”, “xml”.
        projectName (str): Name of the project to generate the report for; retrieve valid names via the `GetProjects` endpoint.
        projectId (int, optional): Unique numeric identifier of the project; required if `projectName` is not provided.

	Returns:
		dict
    """
    path = "CreateProjectReport"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "type": type_of_doc,
        "projectName": projectName,
        "projectId": projectId

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def download_report(uuid) -> any:
    """
    This endpoint allows a user to enable downloading a specific report via their UUID.

    Args:
        uuid (str): Unique identifier (UUID) of the report to download; retrieve valid values via the `GetReports` endpoint.

	Returns:
		any
    """
    path = "DownloadReport"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "uuid": uuid,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.content



@mcp.tool()
def delete_report(uuid) -> dict:
    """
    This endpoint allows a user to permits delete a specific report via its UUID.

    Args:
        uuid (str): Unique identifier (UUID) of the report to delete; retrieve valid values via the `GetReports` endpoint.

	Returns:
		dict
    """
    path = "DeleteReport"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "uuid": uuid,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def change_shodan_integration(key) -> dict:
    """
    This endpoint allows users to integrate and use Shodan on their server.

    Args:
        key (str): User’s Shodan API key for authenticating requests to the Shodan service.

	Returns:
		dict
    """
    path = "ChangeShodan"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "key": key,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def delete_shodan_integration() -> dict:
    """
    This endpoint will delete/disable any Shodan key in use on your server.

	Returns:
		dict
    """
    path = "DeleteShodan"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        # no parameters

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.get(url, headers=headers, params=data)
    return response.json()



@mcp.tool()
def update_slack_integration(channelId, slackToken, slackNotify, slackStartFromSchedule, slackStartFromQueue,
                             slackCompleteAborted, slackDelete, slackStop, slackAborted, slack_pause, slack_unpause,
                             on_high, on_medium, on_low, on_informative) -> dict:
    """
    This endpoint allows users to integrate and connect Slack to CYTRIX.

    Args:
        channelId (str): Slack channel ID to post notifications to, e.g. “C0123ABCD”.
        slackToken (str): OAuth token for Slack API authentication, e.g. “xoxb-6245354291536-8162859889155-2o9PvDYnGnNpQQpK8yasdasdasd”.
        slackNotify (str, optional): Enable general scan notifications; set to “True”; defaults to “False”.
        slackStartFromSchedule (str, optional): Notify when scheduled scans start; set to “True”; defaults to “False”.
        slackStartFromQueue (str, optional): Notify when scans enter the queue; set to “True”; defaults to “False”.
        slackCompleteAborted (str, optional): Notify when scans complete or are aborted; set to “True”; defaults to “False”.
        slackDelete (str, optional): Notify when scans are deleted; set to “True”; defaults to “False”.
        slackStop (str, optional): Notify when scans are stopped; set to “True”; defaults to “False”.
        slackAborted (str, optional): Notify when scans fail or abort; set to “True”; defaults to “False”.
        slack_pause (str, optional): Notify when scans are paused; set to “True”; defaults to “False”.
        slack_unpause (str, optional): Notify when paused scans resume; set to “True”; defaults to “False”.
        on_high (str, optional): Notify on High-severity findings; set to “True”; defaults to “False”.
        on_medium (str, optional): Notify on Medium-severity findings; set to “True”; defaults to “False”.
        on_low (str, optional): Notify on Low-severity findings; set to “True”; defaults to “False”.
        on_informative (str, optional): Notify on Informative-severity findings; set to “True”; defaults to “False”.


	Returns:
		dict
    """
    path = "UpdateSlack"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "channelId": channelId,
        "slackToken": slackToken,
        "slackNotify": slackNotify,
        "slackStartFromSchedule": slackStartFromSchedule,
        "slackStartFromQueue": slackStartFromQueue,
        "slackCompleteAborted": slackCompleteAborted,
        "slackDelete": slackDelete,
        "slackStop": slackStop,
        "slackAborted": slackAborted,
        "slack_pause": slack_pause,
        "slack_unpause": slack_unpause,
        "on_high": on_high,
        "on_medium": on_medium,
        "on_low": on_low,
        "on_informative": on_informative

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def update_teams_integration(teamsWebhook, teamsAvgThreat, teamsNotify, teamsStartFromSchedule, teamsStartFromQueue, teamsCompleteAborted,
                             teamsDelete, teamsStop, teamsAborted, teamsPause, teamsUnpause) -> dict:
    """
    This endpoint allows users to integrate and connect Teams to CYTRIX


    Args:
        teamsWebhook (str): Incoming webhook URL for your Teams channel, e.g. “https://outlook.office.com/webhook/{your-webhook-id}”.
        teamsAvgThreat (str, optional): Average threat level threshold to include in notifications, e.g. “7.5”.
        teamsNotify (str, optional): Enable general scan notifications; set to “True”; defaults to “False”.
        teamsStartFromSchedule (str, optional): Notify when scheduled scans start; set to “True”; defaults to “False”.
        teamsStartFromQueue (str, optional): Notify when scans enter the queue; set to “True”; defaults to “False”.
        teamsCompleteAborted (str, optional): Notify when scans complete or are aborted; set to “True”; defaults to “False”.
        teamsDelete (str, optional): Notify when scans are deleted; set to “True”; defaults to “False”.
        teamsStop (str, optional): Notify when scans are stopped; set to “True”; defaults to “False”.
        teamsAborted (str, optional): Notify when scans fail or abort; set to “True”; defaults to “False”.
        teamsPause (str, optional): Notify when scans are paused; set to “True”; defaults to “False”.
        teamsUnpause (str, optional): Notify when paused scans resume; set to “True”; defaults to “False”.


	Returns:
		dict
    """
    path = "UpdateTeams"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "teamsWebhook": teamsWebhook,
        "teamsAvgThreat": teamsAvgThreat,
        "teamsNotify": teamsNotify,
        "teamsStartFromSchedule": teamsStartFromSchedule,
        "teamsStartFromQueue": teamsStartFromQueue,
        "teamsCompleteAborted": teamsCompleteAborted,
        "teamsDelete": teamsDelete,
        "teamsStop": teamsStop,
        "teamsAborted": teamsAborted,
        "teamsPause": teamsPause,
        "teamsUnpause": teamsUnpause

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def get_all_jira_connections() -> dict:
    """
    This endpoint allows users to fetch all existing Jira connections on the server.

	Returns:
		Dict
		- Returns Params
		project_name, project_key
    """
    path = "GetAllJira"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        # no parameters

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.get(url, headers=headers, params=data)
    return response.json()



@mcp.tool()
def add_jira_connection(serverName, projectKey, projectName, jiraApiKey, email, onHigh, onMedium, onLow, onInformative) -> dict:
    """
    This endpoint allows you to add a connection to Jira.

    Args:
        serverName (str): URL of your Jira Cloud instance, e.g. “https://mycompany.atlassian.net”.
        projectKey (str): Project key used in issue IDs, e.g. “CYTR”.
        projectName (str): Display name of the Jira project, e.g. “CYTRIX Vulnerability Scans”.
        jiraApiKey (str): API token generated from your Atlassian account; e.g. “my-api-token” :contentReference[oaicite:0]{index=0}.
        email (str): Email address associated with the Atlassian account, e.g. “admin@mycompany.com”.
        onHigh (str, optional): Set to “True” to create issues for High-severity findings; defaults to “False”.
        onMedium (str, optional): Set to “True” to create issues for Medium-severity findings; defaults to “False”.
        onLow (str, optional): Set to “True” to create issues for Low-severity findings; defaults to “False”.
        onInformative (str, optional): Set to “True” to create issues for Informative findings; defaults to “False”.

	Returns:
		dict
    """
    path = "AddJiraConnection"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "serverName": serverName,
        "projectKey": projectKey,
        "projectName": projectName,
        "jiraApiKey": jiraApiKey,
        "email": email,
        "onHigh": onHigh,
        "onMedium": onMedium,
        "onLow": onLow,
        "onInformative": onInformative

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def change_jira_connection_for_scan(token, projectName) -> dict:
    """
    This endpoint allows the user to associate an existing scan with a Jira project.

    Args:
        token (str): Unique identifier of the scan target, e.g. yjb6hl4a-y4ej-ngnl-z80j5ulr.
        projectName (str): Name of the Jira project to associate with this scan; retrieve valid names via the `GetAllJira` endpoint.


	Returns:
		dict
    """
    path = "ChangeJira"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "token": token,
        "projectName": projectName,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def delete_jira_connection(projectName) -> dict:
    """
    This endpoint allows the user to delete a Jira project from the server.

    Args:
        projectName (str): Name of the Jira project to delete; retrieve valid names via the `GetAllJira` endpoint.


	Returns:
		dict
    """
    path = "DeleteJira"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "projectName": projectName,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def get_all_monday_connection() -> dict:
    """
    This endpoint allows users to fetch all existing Monday connections on the server.

	Returns:
		Dict
		- Returns Params
		project_name
    """
    path = "GetAllMonday"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        # no parameters

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.get(url, headers=headers, params=data)
    return response.json()



@mcp.tool()
def add_monday_connection(monday_name, monday_oauth_token, onHigh, onMedium, onLow, onInformative) -> dict:
    """
    This endpoint allows you to add a connection to Monday.

    Args:
        monday_name (str): Display name of the Monday project, e.g. “CYTRIX Vulnerability Scans”.
        monday_oauth_token (str): OAuth token for Monday.com API authentication, e.g. “eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9…”.
        onHigh (str, optional): Set to “True” to create items for High-severity findings; defaults to “False”.
        onMedium (str, optional): Set to “True” to create items for Medium-severity findings; defaults to “False”.
        onLow (str, optional): Set to “True” to create items for Low-severity findings; defaults to “False”.
        onInformative (str, optional): Set to “True” to create items for Informative-severity findings; defaults to “False”.

	Returns:
		dict
    """
    path = "AddMondayConnection"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "monday_name": monday_name,
        "monday_oauth_token": monday_oauth_token,
        "onHigh": onHigh,
        "onMedium": onMedium,
        "onLow": onLow,
        "onInformative": onInformative
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def delete_monday_connection(projectName) -> dict:
    """
    This endpoint allows the user to delete a Monday project from the server.

    Args:
        projectName (str): System-registered name of the Monday.com project to delete; retrieve valid names via the `GetAllMonday` endpoint.

	Returns:
		dict
    """
    path = "DeleteMonday"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "projectName": projectName,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def change_monday_connection_for_scan(token, projectName) -> dict:
    """
    This endpoint allows the user to associate an existing scan with a Monday project.

    Args:
        token (str): Unique identifier of the scan target, e.g. yjb6hl4a-y4ej-ngnl-z80j5ulr.
        projectName (str): Name of the Monday project to associate with this scan; retrieve valid names via the `GetAllMonday` endpoint.

	Returns:
		dict
    """
    path = "ChangeMonday"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "token": token,
        "projectName": projectName,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def changeapitoken() -> dict:
    """
    This endpoint allows the user to obtain a new API key to use when using our API.

	Returns:
		dict
    """
    path = "ChangeApiToken"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        # no parameters

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.get(url, headers=headers, params=data)
    return response.json()



@mcp.tool()
def getalldiscovery() -> dict:
    """
    This endpoint allows the user to retrieve and view all discovery scans on the server.

	Returns:
		Dict
		- Returns Params
		token, user_id, domain, name, status, in_progress, project_id
		assets, percent, avg_cyscore, auto_rediscovery
    """
    path = "GetAllDiscovery"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        # no parameters

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.get(url, headers=headers, params=data)
    return response.json()



@mcp.tool()
def getdiscovery(token) -> dict:
    """
    This endpoint allows the user to retrieve and view a specific discovery scan.

    Args:
        token (str): Unique identifier of the discovery scan target, e.g. yjb6hl4a-y4ej-ngnl-z80j5ulr.

	Returns:
		Dict
		- Returns Params
		id, subdomain, domain, date, status_code, title, length
		ip, http, https, redirect_url
    """
    path = "GetDiscovery"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "token": token,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def create_discovery_scan(domain, name, start_blackbox, proxy_name, fixed_ip, project_name, exclude_regex, find_vulnerabilities) -> dict:
    """
    This endpoint allows the user to start a new discovery scan.

    Args:
        domain (str): Target domain to scan, e.g. “example.com”.
        name (str): Custom name for this scan, e.g. “Example”.
        start_blackbox (str, optional): Flag to enable blackbox scanning; set to “True”; defaults to “False”.
        proxy_name (str, optional): Name of a preconfigured proxy to route scan traffic; retrieve valid names via the `GetProxies` endpoint.
        fixed_ip (str, optional): Pre-allocated source IP provided by the system from which the scan will originate, e.g. “203.0.113.5”.
        project_name (str, optional): Project to associate with this scan; retrieve valid names via the `GetProjects` endpoint.
        exclude_regex (str, optional): Regex pattern to exclude domains or paths, e.g. “xxx”.
        find_vulnerabilities (str, optional): Detect vulnerabilities during discovery; set to “False”; defaults to “True”.

	Returns:
		Dict
		- Returns Params
		domain, status, token
    """
    path = "CreateDiscovery"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "domain": domain,
        "name": name,
        "start_blackbox": start_blackbox,
        "proxy_name": proxy_name,
        "fixed_ip" : fixed_ip,
        "project_name": project_name,
        "exclude_regex": exclude_regex,
        "find_vulnerabilities": find_vulnerabilities


    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()


@mcp.tool()
def edit_discovery_scan(token, name, start_blackbox, proxy_name, fixed_ip, project_name, exclude_regex, find_vulnerabilities) -> dict:
    """
    This endpoint allows the user to update a discovery scan’s parameters—target domain, scan mode, network settings, and vulnerability detection.

    Args:
        token (str): Unique identifier of the discovery scan; retrieve via the `GetDiscovery` endpoint, e.g. yjb6hl4a-y4ej-ngnl-z80j5ulr.
        name (str, optional): New custom name for the scan; include only if renaming, e.g. “ExampleScan”.
        start_blackbox (str, optional): Flag to enable blackbox scanning; set to “True”; defaults to “False”.
        proxy_name (str, optional): Name of a preconfigured proxy to route scan traffic; retrieve valid names via the `GetProxies` endpoint.
        fixed_ip (str, optional): Pre-allocated source IP provided by the system from which the scan will originate, e.g. “203.0.113.5”.
        project_name (str, optional): Project to associate with this scan; retrieve valid names via the `GetProjects` endpoint.
        exclude_regex (str, optional): Regex pattern to exclude domains or paths, e.g. “xxx”.
        find_vulnerabilities (str, optional): Detect vulnerabilities during discovery; set to “False”; defaults to “True”.

	Returns:
		Dict
		- Returns Params
		domain, status, token
    """
    path = "EditDiscovery"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "token": token,
        "name": name,
        "start_blackbox": start_blackbox,
        "proxy_name": proxy_name,
        "fixed_ip" : fixed_ip,
        "project_name": project_name,
        "exclude_regex": exclude_regex,
        "find_vulnerabilities": find_vulnerabilities

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def delete_discovery_scan(token) -> dict:
    """
    This endpoint allows the user to delete an existing scan.

    Args:
        token (str): Unique identifier of the discovery scan target, e.g. yjb6hl4a-y4ej-ngnl-z80j5ulr.

	Returns:
		dict
    """
    path = "DeleteDiscovery"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "token": token,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def export_all_discovery_scans(tp) -> dict:
    """
    This endpoint allows the user to export the results of all discovery scans.

    Args:
        type (str, optional): Export format; one of “raw”, “csv”, “json”; defaults to “raw”.

	Returns:
		dict
    """
    path = "ExportAllDiscovery"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "type": tp,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def export_specific_discovery_scan(token, tp) -> dict:
    """
    This endpoint allows the user to export the results of a specific discovery scan.

    Args:
        token (str): Unique identifier of the discovery scan target, e.g. yjb6hl4a-y4ej-ngnl-z80j5ulr.
        type (str, optional): Export format; one of “raw”, “csv”, “json”; defaults to “raw”.

	Returns:
		dict
    """
    path = "ExportDiscovery"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "token": token,
        "type": tp,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def add_subdomain_for_specific_discovery_scan(token, subdomain, subdomain_file, start_blackbox) -> dict:
    """
    This endpoint allows the user to add a subdomain/s to the target list.

    Args:
        token (str): Unique identifier of the discovery scan, e.g. yjb6hl4a-y4ej-ngnl-z80j5ulr.
        subdomain (str): Subdomain to add to the scan, e.g. “app.example.com”.
        subdomain_file (str, optional): Name of an already uploaded file containing subdomains; retrieve valid names via the `GetFiles` endpoint.
        start_blackbox (str, optional): Set to “True” to initiate a blackbox scan on the new subdomains; defaults to “False”.

	Returns:
		Dict
		- Returns Params
		domain, status, token
    """
    path = "AddSubdomain"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "token": token,
        "subdomain": subdomain,
        "subdomain_file": subdomain_file,
        "start_blackbox": start_blackbox

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def delete_discovery_subdomain(subdomain_id, token) -> dict:
    """
    This endpoint allows the user to delete an existing subdomain from your discovery scan.

    Args:
        subdomain_id (int): Unique identifier of the subdomain to remove; retrieve via the `GetDiscovery` endpoint.
        token (str): Unique identifier of the discovery scan, e.g. yjb6hl4a-y4ej-ngnl-z80j5ulr.

	Returns:
		dict
    """
    path = "DeleteDiscoverySubdomain"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "subdomain_id": subdomain_id,
        "token": token,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def create_discovery_blackbox(token) -> dict:
    """
    This endpoint enables black-box scanning of all assets discovered via Discovery

    Args:
        token (str): Unique identifier of the discovery scan, e.g. yjb6hl4a-y4ej-ngnl-z80j5ulr.

	Returns:
		Dict
		- Returns Params
		target, status, token, project_name, project_id
    """
    path = "DiscoveryBlackBox"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "token": token,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def discovery_subdomain_blackbox(subdomain_id, subdomain, token) -> dict:
    """
    This endpoint enables black-box scanning of subdomain assets discovered via Discovery.

    Args:
        subdomain_id (int): Unique identifier of the subdomain; retrieve via the `GetDiscovery` endpoint.
        subdomain (str): Subdomain name to scan, e.g. “app.example.com”, retrieve via the `GetDiscovery` endpoint.
        token (str): Unique identifier of the discovery scan, e.g. yjb6hl4a-y4ej-ngnl-z80j5ulr.

	Returns:
		Dict
		- Returns Params
		target, status, token
    """
    path = "DiscoverySubdomainBlackBox"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "subdomain_id": subdomain_id,
        "subdomain": subdomain,
        "token": token,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()


@mcp.tool()
def get_discovery_subdomain(subdomain_id) -> dict:
    """
    This endpoint allows the user to retrieve and view a specific discovery subdomain.

    Args:
        subdomain_id (int): Unique identifier of the subdomain; retrieve via the `GetDiscovery` endpoint.

	Returns:
		Dict
    """
    path = "GetDiscoverySubdomain"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "subdomain_id": subdomain_id
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()

@mcp.tool()
def get_discovery_scan_vulnerabilities(token, offset, limit, search) -> dict:
    """
    This endpoint allows users to retrieve vulnerability information using their scan token.

    Args:
        token (str): Unique identifier of the discovery scan target, e.g. “yjb6hl4a-y4ej-ngnl-z80j5ulr”.
        offset (int, optional): Number of records to skip; defaults to 0.
        limit (int, optional): Maximum number of records to return; defaults to 20; maximum is 20.
        search (str, optional): Filter vulnerabilities by name or action, e.g. “DOM XSS”; omit to retrieve all.

	Returns:
		Dict
    """
    path = "GetDiscoveryVulns"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "token": token,
        "offset": offset,
        "limit": limit,
        "search": search
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()


@mcp.tool()
def get_discovery_scan_technologies(token, offset, limit, search) -> dict:
    """
    This endpoint returns all technologies detected in a given scan, identified by its scan token.

    Args:
        token (str): Unique identifier of the discovery scan, e.g. “yjb6hl4a-y4ej-ngnl-z80j5ulr”.
        offset (int, optional): Number of records to skip.
        limit (int, optional): Maximum number of records to return.
        search (str, optional): Filter technologies by name or category, e.g. “Angular”; omit to retrieve all.

	Returns:
		Dict
    """
    path = "GetDiscoveryTechs"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "token": token,
        "offset": offset,
        "limit": limit,
        "search": search
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()

@mcp.tool()
def get_discovery_subdomain_vulnerabilities(token, subdomain, offset, limit, search) -> dict:
    """
    This endpoint retrieves all vulnerabilities detected on a specific subdomain, identified by its unique subdomain ID.

    Args:
        token (str): Unique identifier of the discovery scan, e.g. yjb6hl4a-y4ej-ngnl-z80j5ulr.
        subdomain (str): Target subdomain to query, e.g. “app.example.com”; retrieve valid subdomains via the `GetDiscovery` endpoint.
        offset (int, optional): Number of records to skip; defaults to 0.
        limit (int, optional): Maximum number of records to return; defaults to 20.
        search (str, optional): Filter vulnerabilities by name or action, e.g. “SQL Injection”.

	Returns:
		Dict
    """
    path = "GetDiscoverySubdomainVulns"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "token": token,
        "subdomain": subdomain,
        "offset": offset,
        "limit": limit,
        "search": search
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def get_notify() -> dict:
    """
    This endpoint is used to retrieve notifications for the user.

	Returns:
		Dict
		- Returns Params
		title, description, full_name, time_notify
    """
    path = "GetNotification"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        # no parameters

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.get(url, headers=headers, params=data)
    return response.json()



@mcp.tool()
def get_all_attack_profile() -> dict:
    """
    This endpoint retrieves all existing attack profiles on the server.

	Returns:
		Dict
		- Returns Params
		id, profile_name, profiles, date, user_id, user
    """
    path = "GetAllAttackProfile"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        # no parameters

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.get(url, headers=headers, params=data)
    return response.json()



@mcp.tool()
def get_attack_options() -> dict:
    """
    This endpoint retrieves all attack options available in CYTRIX.

	Returns:
		dict
		- Returns Params
		Engines.AI Prompt Injection, Engines.Broken Access Control, Engines.JWT Signature Bypass, Engines.Insecure Direct Object References (IDOR), Engines.Broken Object Level Authorization (BOLA), Engines.Remote Code Execution (RCE), Engines.Remote File Inclusion (RFI)
		Engines.SQL Injection (SQLI), Engines.Server-Side Template Injection (SSTI), Engines.Cross-site Scripting (XSS), Engines.XML external entity (XXE) injection, Engines.Carriage Return, Line Feed. (CRLF), Engines.Default Login, Engines.Local File Inclusion (LFI)
		Engines.Open Redirect, Engines.Code injection, Engines.Improper Error Handling, Engines.Stored Injection, Engines.Server-Side Request Forgery (SSRF), Engines.Unrestricted File Upload, Engines.Unrestricted File Upload (EICAR File)
		Engines.Content Type Control, Engines.Path Traversal, Directory Listing, Public S3 Bucket Exposure, Fuzzing S3 Bucket Exposure, CORS Misconfigurations, HTTPS.sys RCE
		Development build of React, Microsoft SMBv3 Remote Code Execution Vulnerability, Drupal, Elasticsearch service accessible, GraphQL, Joomla, Directory & Path Enumeration
		Headers.Headers, Headers.Host Header Attack, Active Mixed Content over HTTPS, Sensitive res, Source Code.Check Error Params, Source Code.S3 Bucket Exposed, Source Code.Exposed API Schema
		Source Code.Dev Environment Exposed, Source Code.External IP Disclosure, Source Code.Internal IP Disclosure, Source Code.Exposed PII, Source Code.Logs file Disclosure, Source Code.SQL File Exposed, Source Code.SRI (SubResource Integrity)
		Source Code.Email Exposed, Source Code.Console Enabled, Source Code.Credentials Disclosure, Source Code.Debug Applications, Source Code.SQL Statement, Source Code.Content-Type Missing, Source Code.Source Code Disclosure
		Source Code.Path Disclosure, Source Code.Secret Key, Source Code.Detection File Upload, Source Code.SQL Connection Exposed, Source Code.Elastic Search Exposed, Source Code.PHP info Exposed, Source Code.Certificate Exposed
		Source Code.Login Detection, TLS/SSL certificate, Version Information Disclosure, CVEs (Over 30K vulnerabilities), Custom Payloads, Templates, Folder Zip Backup
		Same Site Scripting, Password field submitted using GET method, Wordpress.User Disclosure, Wordpress.Config Files, Wordpress.CVEs (WP Core), Wordpress.CVEs (Plugins), Wordpress.CVEs (Themes)
		Wordpress.CVEs (WP General), Wordpress.Admin Ajax XSS, Wordpress.WordPress XML-RPC authentication brute force, Wordpress.CORS Misconfiguration, Wordpress.Debug Mode and Files, Wordpress.Install PHP, Wordpress.WP Admin - Login Page
		Wordpress.Dos CVE-2018-6389, exploits
    """
    path = "GetAttackOptions"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        # no parameters

    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.get(url, headers=headers, params=data)
    return response.json()



@mcp.tool()
def get_specific_attack_profile(profile_id) -> dict:
    """
    This endpoint retrieves a specific attack profile.

    Args:
        profile_id (int): Unique identifier of the attack profile to retrieve; retrieve valid IDs via the `GetAllAttackProfile` endpoint.

	Returns:
		dict
		- Returns Params
		id, profile_name, profiles, date, user_id, user
    """
    path = "GetAttackProfile"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "profile_id": profile_id,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def newattackprofile(profile_name, profiles) -> dict:
    """
    This endpoint allows the user to create a new attack profile.

    Args:
        profile_name (str): Descriptive name for the new attack profile.
        profiles (str): Comma-separated of profile IDs to include, e.g. “7,8,9,10”.

	Returns:
		dict
    """
    path = "NewAttackProfile"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "profile_name": profile_name,
        "profiles": profiles,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def edit_attack_profile(profile_id, profile_name, profiles) -> dict:
    """
    This endpoint allows the user to edit an existing attack profile.

    Args:
        profile_id (int): Unique identifier of the attack profile to modify; retrieve valid IDs via the `GetAllAttackProfile` endpoint.
        profile_name (str, optional): New descriptive name for the attack profile, e.g. “Standard Attack Profile”.
        profiles (str, optional): Comma-separated  of profile IDs to include, e.g. “7,8,9,10”.

	Returns:
		dict
    """
    path = "EditAttackProfile"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "profile_id": profile_id,
        "profile_name": profile_name,
        "profiles": profiles,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()



@mcp.tool()
def delete_attack_profile(profile_name) -> dict:
    """
    This endpoint allows the user to delete an existing attack profile.

    Args:
        profile_name (str): Name of the attack profile to remove; retrieve valid names via the `GetAllAttackProfile` endpoint.

	Returns:
		dict
    """
    path = "DeleteAttackProfile"
    headers = {
        "Apikey": API_KEY
    }

    data = {
        "profile_name": profile_name,
    }

    url = f"{API_GATEWAY}/{path}"
    response = requests.post(url, headers=headers, json=data)
    return response.json()

