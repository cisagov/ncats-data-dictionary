# NCATS Data Dictionary #

## April 28, 2020 ##

This document provides a data dictionary for the data stored in the
following NoSQL MongoDB databases:

- `assessment` - Risk/Vulnerability Assessment (RVA) management data
- `cyhy` - Cyber Hygiene port and vulnerability scanning
- `pca` - Phishing Campaign Assessment management data
- `scan`
  - Domains gathered from Cyber Hygiene, GSA, the End of Term Web
    Archive, or self-reported
  - SPF/DMARC/STARTTLS trustworthy email scanning
  - HTTPS web server scanning
  - SSL server scanning
  - Certificates and pre-certificates from [Certificate
    Transparency](https://www.certificate-transparency.org) logs

This information is organized by database and collection (table).

[assessment Database:](#assessment-database)

- [assessments Collection](#assessments-collection)
- [findings Collection](#findings-collection)

[Cyhy Database:](#cyhy-database)

- [cves Collection](#cves-collection)
- [host\_scans Collection](#host_scans-collection)
- [hosts Collection](#hosts-collection)
- [kevs Collection](#kevs-collection)
- [notifications Collection](#notifications-collection)
- [places Collection](#places-collection)
- [port\_scans Collection](#port_scans-collection)
- [reports Collection](#reports-collection)
- [requests Collection](#requests-collection)
- [snapshots Collection](#snapshots-collection)
- [tallies Collection](#tallies-collection)
- [tickets Collection](#tickets-collection)
- [vuln\_scans Collection](#vuln_scans-collection)

[PCA Database:](#pca-database)

- [applications Collection](#applications-collection)
- [assessments Collection](#assessments-collection-1)
- [campaigns Collection](#campaigns-collection)
- [clicks Collection](#clicks-collection)
- [customers Collection](#customers-collection)
- [emails Collection](#emails-collection)
- [templates Collection](#templates-collection)
- [user_reports Collection](#user_reports-collection)
- [users Collection](#users-collection)

[scan Database:](#scan-database)

- [certs Collection](#certs-collection)
- [domains Collection](#domains-collection)
- [https\_scan Collection](#https_scan-collection)
- [precerts Collection](#precerts-collection)
- [sslyze\_scan Collection](#sslyze_scan-collection)
- [trustymail Collection](#trustymail-collection)

---

## assessment Database ##

### assessments Collection ###

- `_id` [ObjectId]: Assessment ID (RV0XXX for RVA/HVA/PCA or VR0XXX for VADR)
- `appendix_a_signed_date` [ISO date]: Date Appendix A was signed
- `appendix_a_signed` [boolean]: Was Appendix A signed?
- `appendix_b_signed` [boolean]: Was Appendix B signed?
- `assessment_completed` [ISO date]: Date when assessment was completed
- `assessment_name` [string]: Assessment Name (Usually customer name and assessment
  type)
- `assessment_status` [string]: Assessment Status (Open -\> Planning -\>
  Testing -\> Reporting -\> Wrap Up -\> Completed)
- `assessment_summary` [string]: Assessment Summary (ASMT\_ID / ASMT\_NAME)
- `assessment_type` [string]: Assessment Type (RVA, HVA, RPT, PCA, VADR)
- `ci_systems` [list]: If any subsystems assessed belong to a different
  critical infrastructure category from the `ci_type` field, it will be listed
  here (For example, Hoover Dam would be `ci_type: CI_WATER` and
  `ci_systems: [CI_ENERGY]` for electric)
- `ci_type` [string]: Critical Infrastructure Type (Selected from among 16 CI
  Sectors)
- `contractor_count` [integer]: Number of contractors assigned
- `created` [ISO date]: Date ticket was created
- `draft_completed` [ISO date]: Date when draft report is sent to the
  customer
- `election` [boolean]: Is this assessment election-related?
- `external_testing_begin` [ISO date]: Date of beginning of external testing
- `external_testing_end` [ISO date]: Date of end of external testing
- `fed_count` [integer]: Number of Federal operators assigned
- `fed_lead` [string]: Federal Team Lead assigned to the assessment
- `group_project` [string]: Group or Project
- `internal_testing_begin` [ISO date]: Date of beginning of internal testing
- `internal_testing_city` [string]: Location (city) of on-site testing, if
  applicable
- `internal_testing_end` [ISO date]: Date of end of internal testing
- `last_change` [ISO date]: Last update date
- `management_request` [string/boolean]: Source (if any) for assessments
  requested by management (DHS, NCCIC, EOP, false)
- `mandated_category` [string/boolean]: Category (if any) for mandated
  assessments (Aviation, Elections, FERC, HI, Pipeline, EOP, false)
- `operators` [list]: List of operator names (contractor or federal)
- `report_final_date` [integer]: Date when report is marked Final
- `requested_services` [list]: NCATS services requested for this engagement
- `roe_number` [integer]: ROE Number (assigned by NCATS)
- `roe_signed` [boolean]: ROE Signed
- `roe_signed_date` [ISO date]: Date ROE is signed
- `sector` [string]: Fed/State/Local/Tribal/Territorial/Critical
  Infrastructure
- `stakeholder_id` [string]: TBD
- `stakeholder_name` [string]: Stakeholder Name
- `stakeholder_state` [string]: State where stakeholder is located
- `testing_begin` [ISO date]: Date when all testing begins
- `testing_complete` [ISO date]: Date on which all testing is completed
- `testing_phase` [list]: The currently-active phase(s) of testing

### findings Collection ###

- `_id` [ObjectId]: Unique key for DB to identify individual finding
- `Assessment Type` [string]: Type of Assessment [RVA, HVA, RPT]
- `CI Subtype` [string]: Identifies which of 16 Critical Infrastructure
  sectors customer belongs to, if any
- `Custom Finding Name` [string]: Custom name for finding identified by Fed
  Team Lead, if applicable
- `Default Finding Severity` [string]: Default level of severity for this type
  of finding. Please see notes in Severity for more info on how Fed Team Leads
  assign severity ratings.
- `FED/SLTT/CI` [string]: Customer Sector
- `FY` [string]: Fiscal Year during which testing was conducted. Due to
  ever-changing cybersecurity landscape, more current data is recommended when
  conducting analysis
- `Int/Ext` [string]: Was the finding identified during Internal or External
  testing?
- `Man/Tool` [string]: Was the finding identified manually or with a tool
  (Burp Suite, Cobalt Strike, Nessus, etc.) Tool will not be identified
- `Mitigate Finding Response Date` [ISO date]: Date on which customer
  responded with Mitigation data
- `Mitigated Finding Status` [string]: Mitigation status as reported by
  customer during 180-day mitigation survey. Note-survey is optional and
  self-reported, no validation performed by NCATS that mitigations were
  performed as stated. Please be careful using this metric.
- `Name` [string]: Name of Finding
- `NCATS ID` [integer]: Standard number assigned by NCATS to the Finding Name
- `NCSF` [array]: This array will list which controls in the NICE
  Cybersecurity Framework are applicable to the finding identified. This is a
  more universal standard than NIST 800-53
- `NIST 800-53` [array]: This array will list which controls in NIST 800-53
  are applicable to the finding identified. As NIST 800-53 is a Federal
  standard, this is more applicable for Federal customers
- `RVA ID` [string]: Assessment ID during which finding was identified. Note -
  this number identifies the customer when paired with information from
  Assessments collection. This number is provided with Findings info to
  identify unique assessments.
- `Service` [string]: RVA service during which finding was identified
- `Severity` [string]: Ranking of severity assigned by Fed Team Lead. Severity
  can vary depending on importance of the system, or other environmental
  factors [Low, Medium, High, Critical]
- `Std Text Modify` [string]: Was there a custom Finding name provided?

## Cyhy Database ##

### cves Collection ###

The data in this collection is derived from the National Vulnerability
Database [CVE feeds](https://nvd.nist.gov/vuln/data-feeds).

- `_id` [string]: [Common Vulnerabilities and
  Exposures](https://cve.mitre.org/)
  identifier
- `cvss_score` [decimal]: [CVSS base
  score](https://nvd.nist.gov/vuln-metrics)
- `cvss_version` [string]: CVSS version used for the CVSS base score
- `severity` [decimal]: [CVSS severity
  rating](https://nvd.nist.gov/vuln-metrics)

### host_scans Collection ###

The data in this collection is derived from IP addresses supplied by the
CyHy stakeholders.

- `_id` [ObjectId]: Internal database id of this host scan document
- `accuracy` [integer]: Confidence rating by scanner in OS class guess
- `classes` [list of dictionaries]: Guesses for OS class (comes
  directly from scanner; see nmap details
  [here](https://nmap.org/book/app-nmap-dtd.html))
- `hostname` [string]: Hostname, if one was detected
- `ip` [string]: IP address that was scanned
- `ip_int` [long integer]: Integer version of IP address that was scanned
- `latest` [boolean]: Is this the latest scan of this host?
- `line` [integer]: Line number in the [nmap OS
  database](https://svn.nmap.org/nmap/nmap-os-db)
  corresponding to the OS class guess
- `name` [string]: Type of host detected (best guess, comes directly
  from scanner)
- `owner` [string]: Organization that claims the IP address associated
  with this scan
- `snapshots` [list of ObjectIds]: Snapshots that include this scan
- `source` [string]: Source of the scan (e.g. "nmap")
- `time` [ISO date]: Timestamp when the scan occurred

### hosts Collection ###

The data in this collection is derived from IP addresses supplied by the
CyHy stakeholders.

- `_id` [long integer]: Integer version of this host document’s IP
  address
- `ip` [string]: IP address corresponding to this host document
- `last_change` [ISO date]: Timestamp of when this host document was
  last updated
- `latest_scan` [dictionary]: Timestamps of last time host completed
  each scan stage
- `loc` [list]: Longitude and latitude of host, according to geolocation
  database
- `priority` [integer]: Scan priority of this host document, from -16
  (most urgent) to 1 (least urgent)
  - -16: Most severe vulnerability detected on this host is Critical
    severity
  - -8: Most severe vulnerability detected on this host is High severity
  - -4: Most severe vulnerability detected on this host is Medium
    severity
  - -2: Most severe vulnerability detected on this host is Low severity
  - -1: No vulnerabilities detected on this host
  - 1: Host document represents a "dark space" IP address; i.e. live
    host not detected
- `next_scan` [ISO date]: Timestamp of when this host document is
  scheduled to be scanned next; a value of null indicates that the
  host document has a status other than "DONE" (i.e. currently queued
  up for a scan or running a scan)
- `owner` [string]: Organization that claims the IP address associated
  with this host document
- `r` [decimal]: A random number between 0 and 1 used to randomize scan
  order
- `stage` [string]: Current scan stage for this host document
  - "NETSCAN1" - Port scan of top 30 most-common ports
  - "NETSCAN2" - Port scan of next 970 most-common ports
  - "PORTSCAN" - Full port scan of all 65,535 ports
  - "VULNSCAN" - Vulnerability scan
- `state` [dictionary]: Current state of this host document
  - reason [string]: Reason given by the port scanner as to whether or
    not this host document represents a live host
  - up [boolean]: Whether or not a live host was detected at this host
    document’s IP address by the port scanner
- `status` [string]: Current scan status for this host document:
  - "WAITING" - Waiting to be  for scanning
  - "READY" - Ready to be assigned to a scanner
  - "RUNNING" - Currently being scanned
  - "DONE" - Latest scan has completed

### kevs Collection ###

The data in this collection is derived from the
[JSON feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
of the [CISA Known Exploited Vulnerabilities
Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

- `_id` [string]: [Common Vulnerabilities and
  Exposures](https://cve.mitre.org/)
  identifier for a Known Exploited Vulnerability (KEV)

### notifications Collection ###

The data in this collection is generated as part of Cyber Hygiene, whenever
a new [ticket](#tickets-collection) is created after detection of a Critical or
High-severity vulnerability, or detection of a potentially-risky service.

- `_id` [ObjectId]: Internal database id of this notification document
- `generated_for` [list]: Organizations that have already generated a
notification PDF document that includes the data from the ticket
referenced in this notification
- `ticket_id` [ObjectId]: Internal database identifier for the ticket that
this notification refers to
- `ticket_owner` [string]: The organization that owns the ticket that this
notification refers to

### places Collection ###

The data in this collection is derived from the "Government Units" and
"Populated Places" Topical Gazetteers files from
[USGS](https://geonames.usgs.gov/domestic/download_data.htm).

- `_id` [long integer]: [GNIS
  ID](https://geonames.usgs.gov/domestic/index.html) corresponding to
  this place
- `class` [string]: Class of this place ("COUNTY", "STATE", "Populated
  Place", "Civil")
- `country` [string]: Two-letter abbreviation of the country where this
  place is
- `country_name` [string]: Full name of the country where this place is
- `county` [string]: Full name of the county where this place is
- `county_fips` [string]: [FIPS
  code](https://catalog.data.gov/dataset/fips-county-code-look-up-tool)
  for the county where this place is
- `name` [string]: Full name of this place
- `state` [string]: Two-letter postal abbreviation of the state where
  this place is
- `state_fips` [string]: [FIPS
  code](https://catalog.data.gov/dataset/fips-state-codes) for the
  state where this place is
- `state_name` [string]: Full name of the state where this place is

### port_scans Collection ###

The data in this collection is derived from IP addresses supplied by the
CyHy stakeholders.

- `_id` [ObjectId]: Internal database id of this port scan document
- `ip` [string]: IP address of the host that was port scanned
- `ip_int` [long integer]: Integer version of IP address that was port
  scanned
- `latest` [boolean]: Is this the latest scan of this port?
- `owner` [string]: Organization that claims the IP address associated
  with this port scan
- `port` [integer]: Number of the port that was scanned
- `protocol` [string]: Protocol for this port scan ("tcp" or "udp")
- `reason` [string]: Why this port is determined to be open, as reported
  by the port scanner
- `service` [dictionary]: Details about this port, as reported by the
  scanner
- `snapshots` [list of ObjectIds]: Snapshots that include this port scan
- `source` [string]: Source of the scan (e.g. "nmap")
- `state` [string]: State of the port, as reported by the scanner; see
  nmap states
  [here](https://nmap.org/book/man-port-scanning-basics.html)
- `time` [ISO date]: Timestamp when the port was scanned

### reports Collection ###

The data in this collection is generated as part of Cyber Hygiene report
creation process.

- `_id` [ObjectId]: Internal database id of this report document
- `generated_time` [ISO date]: Timestamp when this report or scorecard`
  was generated
- `owner` [string]: Organization that this report was created for; a
  value of null indicates that this report was a scorecard that
  contained results for multiple organizations
- `report_types` [list of strings]: Type of report that was generated
  - "CYBEX" - Cyber Exposure scorecard
  - "CYHY" - Cyber Hygiene report
- `snapshot_oid` [ObjectId]: Snapshot that was the basis for this Cyber
  Hygiene report (value is null for Cyber Exposure scorecards)

### requests Collection ###

The data in this collection is derived from data supplied by the CyHy
stakeholders.

- `_id` [string]: Organization identifier (corresponds to owner field
  in many collections)
- `agency` [dictionary]: Details about the organization
  - `acronym` [string]: Organization acronym
  - `contacts` [list of dictionaries]: Contact details for the
  organization
    - `email` [string]: Contact email address
    - `name` [string]: Contact name
    - `phone` [string]: Contact phone number
    - `type` [string]: Contact type ("TECHNICAL" or "DISTRO")
  - `location` [dictionary]: Organization location details, typically
    represents headquarters or base of operations for organizations that
    are spread across multiple localities
    - `country` [string]: Two-letter abbreviation of the country
    - `country_name` [string]: Full name of the country
    - `county` [string]: Full name of the county
    - `county_fips` [string]: [FIPS
      code](https://catalog.data.gov/dataset/fips-county-code-look-up-tool)
      of the county
    - `gnis_id` [long integer]: [GNIS
      ID](https://geonames.usgs.gov/domestic/index.html) of the
      location
    - `name` [string]: Full name of the location
    - `state` [string]: Two-letter postal abbreviation of the state
    - `state_fips` [string]: [FIPS
      code](https://catalog.data.gov/dataset/fips-state-codes) for the
      state
    - `state_name` [string]: Full name of the state
  - `name` [string]: Full name of the organization
  - `type` [string]: Organization type ("FEDERAL", "STATE", "LOCAL",
    "TRIBAL", "TERRITORIAL", "PRIVATE")
- `children` [list of strings]: Identifiers of organizations that are
  children of this organization
- `init_stage` [string]: First scan stage for this organization
- `key` [string]: Password used to encrypt reports for this organization
- `networks` [list of strings]: CIDR blocks of IP addresses claimed by
  this organization
- `period_start` [ISO date]: Timestamp when scanning can begin for this
  organization
- `report_period` [string]: Frequency of reports; only current
  supported value is "WEEKLY"
- `report_types` [list of strings]: Types of reports that this
  organization receives ("CYHY", "CYBEX")
- `retired` [boolean]: Whether or not this organization is currently
  subscribed to the Cyber Hygiene service
- `scan_limits` [list of dictionaries]: Limits on scan concurrency
  - `concurrent` [integer]: Number of concurrent scans of that type
  - `scanType` [string]: Type of scan to limit ("NETSCAN1", "NETSCAN2",
    "PORTSCAN", "VULNSCAN")
- `scan_types` [list of strings]: Types of scanning that this
  organization receives; only current supported value is "CYHY"
- `scheduler` [string]: Name of the scheduler used to schedule scans;
  only current supported value is "PERSISTENT1"
- `stakeholder` [boolean]: Whether or not this organization is
  considered to be a CyHy stakeholder
- `windows` [list of dictionaries]: Windows when the organization allows
  us to scan
  - `day` [string]: Day that scanning is allowed
  - `start` [string]: Time of day when scanning is allowed to start
  - `duration` [integer]: Duration of scan window, in hours

### snapshots Collection ###

The data in this collection is derived from IP addresses supplied by the
CyHy stakeholders.

- `_id` [ObjectId]: Internal database id of this snapshot document
- `cvss_average_all` [decimal]: Average CVSS score of all hosts in
  this snapshot
- `cvss_average_vulnerable` [decimal]: Average CVSS score of
  vulnerable hosts in this snapshot
- `end_time` [ISO date]: Timestamp of the last scan in this snapshot
- `host_count` [integer]: Number of hosts detected in this snapshot
- `last_change` [ISO date]: Timestamp of when this snapshot document
  was last updated
- `latest` [boolean]: Is this the latest snapshot for this organization?
- `networks` [list of strings]: CIDR blocks claimed by the organization
  at the time this snapshot was generated
- `owner` [string]: Organization that this snapshot is associated with
- `parents` [ObjectId]: Identifier of the parent snapshot(s); used only
  for organizations with children; if this value is equal to the \_id
  of this snapshot, then this snapshot has no parent
- `port_count` [integer]: Total number of open ports detected in this
  snapshot
- `services` [dictionary]: Number of services detected in this snapshot,
  grouped by service name
- `start_time` [ISO date]: Timestamp of the first scan in this snapshot
- `tix_msec_open`[dictionary]: Time a ticket has been open
- `tix_msec_to_close`[dictionary]: Time it took to close a ticket
- `unique_operating_systems` [integer]: Number of unique operating
  systems detected in this snapshot
- `unique_port_count` [integer]: Number of unique open ports detected
  in this snapshot
- `unique_vulnerabilities` [dictionary]: Number of unique
  vulnerabilities in this snapshot, grouped by severity
- `vulnerable_host_count` [integer]: Number of vulnerable hosts
  detected in this snapshot
- `vulnerabilities` [dictionary]: Total number of vulnerabilities in
  this snapshot, grouped by severity
- `world` [dictionary]: DEPRECATED; metrics about the overall state of
  CyHy at the time this snapshot was generated

### tallies Collection ###

The data in this collection is derived from IP addresses supplied by the
CyHy stakeholders.

- `_id` [string]: Organization identifier (corresponds to owner field
  in many collections)
- `counts` [dictionary]: Number of hosts currently in each scan stage
  and scan status
  - `BASESCAN` [dictionary]: DEPRECATED
  - `NETSCAN1, NETSCAN2, PORTSCAN, VULNSCAN` [dictionaries]
    - `DONE` [integer]: Number of hosts for this organization in "DONE"
    status for the given scan stage
    - `READY` [integer]: Number of hosts for this organization in "READY"
    status for the given scan stage
    - `RUNNING` [integer]: Number of hosts for this organization in
    "RUNNING" status for the given scan stage
    - `WAITING` [integer]: Number of hosts for this organization in
    "WAITING" status for the given scan stage
  - `last_change` [ISO date]: Timestamp of when this tally document was
    last updated

### tickets Collection ###

The data in this collection is derived from IP addresses supplied by the
CyHy stakeholders.

- `_id` [ObjectId]: Internal database id of this ticket document
- `details` [dictionary]: Vulnerability details
  - `cve` [string]: [Common Vulnerabilities and
    Exposures](https://cve.mitre.org/) identifier
  - `cvss_base_score` [decimal]: [CVSS base
    score](https://nvd.nist.gov/vuln-metrics)
  - `cvss_version` [string]: CVSS version used for the CVSS base score
  - `kev` [boolean]: Is this ticket marked as a Known Exploited Vulnerability (KEV)?
  - `name` [string]: Vulnerability name
  - `score_source` [string]: Source of the CVSS base score (e.g. "nvd" or
    "nessus")
  - `service` [string]: Name of the service detected in this ticket; this field
    is specific to tickets where the ticket `source` is a port scanner
    (e.g. "nmap")
  - `severity` [decimal]: [CVSS severity
    rating](https://nvd.nist.gov/vuln-metrics)
  - `vpr_score` [decimal]: Tenable
    [Vulnerability Priority Rating](https://docs.tenable.com/nessus/Content/RiskMetrics.htm)
- `events` [dictionary]: Details of key ticket events
  - `action` [string]: Event type
    - ``"OPENED"`` - Ticket opened for the first time
    - ``"VERIFIED"`` - Verified that an open ticket is still open
    - ``"CHANGED"`` - Data within the ticket changed (e.g. marked as a false
      positive or the vulnerability’s CVSS score changed)
    - ``"CLOSED"`` - Ticket closed (vulnerability no longer detected)
    - ``"REOPENED"`` - A closed ticket reopened
    - ``"UNVERIFIED"`` - A vulnerability was detected for a ticket that is
      marked as a false positive
  - `reason` [string]: Short description of the event
  - `reference` [ObjectId]: The identifier for the vulnerability scan
    related to the event
  - `time` [ISO date]: Timestamp of the event
  - `delta` [list of dictionaries]: Only applies to "CHANGED" events; list
  of what changed
    - `key` [string]: Ticket field that changed
    - `from` [type depends on key]: Value of key before the "CHANGED" event
    - `to` [type depends on key]: Value of key after the "CHANGED" event
- `false_positive` [boolean]: Is this ticket marked as a false positive?
- `ip` [string]: IP address of the host that was vulnerability scanned
- `ip_int` [long integer]: Integer version of IP address that was
  vulnerability scanned
- `last_change` [ISO date]: Timestamp of when this ticket document was
  last updated
- `loc` [list]: Longitude and latitude of host (according to geolocation
  database) associated with this ticket
- `open` [boolean]: Was this vulnerability detected in the latest scan
  of the associated host?
- `owner` [string]: Organization that claims the IP address associated
  with this ticket
- `port` [integer]: Number of the vulnerable port in this ticket
- `protocol` [string]: Protocol for the vulnerable port in this ticket
  ("tcp" or "udp")
- `snapshots` [list of ObjectIds]: Snapshots that include this ticket
- `source` [string]: Source of the vulnerability scan (e.g. "nessus" or "nmap")
- `source_id` [integer]: Source-specific identifier for the
  vulnerability scan (e.g. the scanner plugin identifier that detected
  the vulnerability)
- `time_closed` [ISO date]: Timestamp when this ticket was closed
  (vulnerability was no longer detected); value of null indicates that
  this ticket is currently open
- `time_opened` [ISO date]: Timestamp when this ticket was opened
  (vulnerability was first detected)

### vuln_scans Collection ###

The data in this collection is derived from IP addresses supplied by the
CyHy stakeholders.

- `_id` [ObjectId]: Internal database id of this vulnerability scan
  document
- `bid` [string]: [Bugtraq ID](https://en.wikipedia.org/wiki/Bugtraq)
- `cert` [string]: [CERT ID](http://www.kb.cert.org/vuls)
- `cpe` [string]: [Common Platform
  Enumerator](https://nvd.nist.gov/products/cpe)
- `cve` [string]: [Common Vulnerabilities and
  Exposures](https://cve.mitre.org/) identifier
- `cvss_base_score` [string]: [CVSS base
  score](https://nvd.nist.gov/vuln-metrics)
- `cvss_temporal_score` [string]: [CVSS temporal
  score](https://nvd.nist.gov/vuln-metrics)
- `cvss_temporal_vector` [string]: [CVSS temporal
  vector](https://nvd.nist.gov/vuln-metrics)
- `cvss_vector` [string]: [CVSS
  vector](https://nvd.nist.gov/vuln-metrics)
- `description` [string]: Description of the vulnerability, according to
  the vulnerability scanner
- `exploit_available` [string]: Whether or not an exploit is available,
  according to the vulnerability scanner
- `exploitability_ease` [string]: Ease of exploitation, according to
  the vulnerability scanner
- `fname` [string]: Filename of the vulnerability scanner plugin that
  detected this vulnerability
- `ip` [string]: IP address of the host that was vulnerability scanned
- `ip_int` [long integer]: Integer version of IP address that was
  vulnerability scanned
- `latest` [boolean]: Is this the latest vulnerability scan of this
  port/protocol/host?
- `owner` [string]: Organization that claims the IP address associated
  with this vulnerability scan
- `osvdb` [string]: [Open Source Vulnerability
  Database](https://en.wikipedia.org/wiki/Open_Source_Vulnerability_Database)
  identifier for the detected vulnerability
- `patch_publication_date` [ISO date]: Date when a patch was published
  for this vulnerability
- `plugin_family` [string]: Family of the plugin run by the
  vulnerability scanner that detected this vulnerability
- `plugin_id` [integer]: ID of the plugin run by the vulnerability
  scanner that detected this vulnerability
- `plugin_modification_date` [ISO date]: Latest modification date of
  the vulnerability scanner plugin that detected this vulnerability
- `plugin_name` [string]: Name of the vulnerability scanner plugin that
  detected this vulnerability
- `plugin_output` [string]: Plugin-specific output from the
  vulnerability scanner
- `plugin_publication_date` [ISO date]: Publication date of the
  vulnerability scanner plugin that detected this vulnerability
- `plugin_type` [string]: Vulnerability scanner plugin type
- `port` [integer]: Number of the port that was vulnerability scanned
- `protocol` [string]: Protocol for the vulnerable port in this scan
  ("tcp" or "udp")
- `risk_factor` [string]: Risk factor of the detected vulnerability
  according to the vulnerability scanner
- `script_version` [string]: Script version string
- `see_also` [string]: Additional reference(s) for this vulnerability
  provided by the vulnerability scanner
- `service` [string]: Service detected at the vulnerable port in this
  scan
- `severity` [decimal]: CVSS v2.0 severity rating from the vulnerability
  scanner
- `snapshots` [list of ObjectIds]: Snapshots that include this
  vulnerability scan
- `solution` [string]: Solution to mitigate the detected vulnerability,
  according to the vulnerability scanner
- `source` [string]: Source of the vulnerability scan (e.g. "nessus")
- `synopsis` [string]: Brief overview of the vulnerability
- `time` [ISO date]: Timestamp when the vulnerability was detected
- `vuln_publication_date` [ISO date]: Vulnerability publication date
- `xref` [string]: External reference

## PCA Database ##

### applications Collection ###

- `_id` [ObjectId]: Internal database id of this detected application
- `assessment` [string]: ID of PCA assessment where this application was detected
- `campaign` [string]:  ID of PCA campaign where this application was detected
- `customer` [string]: PCA customer identifier associated with this assessment
- `external_ip` [string]: External IP address of the host where the application
was detected
- `external_ip_int` [long integer]: Integer version of the external IP address
where the application was detected
- `internal_ip` [string]: Internal IP address of the host where the application
was detected
- `internal_ip_int` [string]: Integer version of the internal IP address where
the application was detected
- `name` [string]: Name of application detected
- `time` [ISO date]: Timestamp of when this application was detected
- `user` [string]: PCA ID of the user that was running the application detected
- `version` [string]: Version of application detected

### assessments Collection ###

- `_id` [ObjectId]: PCA assessment (RV) ID
- `customer` [string]: PCA customer identifier associated with this assessment
- `end_time` [ISO date]: Date the final campaign in the assessment ended
- `start_time` [ISO date]: Date the first campaign in the assessment started
- `team_lead` [string]: Name of Federal lead for the assessment

### campaigns Collection ###

- `_id` [string]: Internal ID of phishing campaign
- `assessment` [string]: ID of PCA assessment this campaign is part of
- `customer` [string]: PCA customer identifier associated with this campaign
- `end_time` [ISO date]: Timestamp when the campaign ended
- `images` [dictionary]: Images associated with this campaign
  - ``“landing-page”`` - Internal ID of landing page image
  - ``“sent-email”`` - Internal ID of sent email image
  - ``“link-warning”`` - Internal ID of link warning image
- `start_time` [ISO date]: Timestamp when the campaign started
- `subject` [string]: Subject used in the phishing email for this campaign
- `template` [ObjectID]: ID of template associated with this campaign
- `url` [string] : Phishing URL found within the email template
- `users` [list of strings]: PCA IDs of the users phished in this campaign

### clicks Collection ###

- `_id` [ObjectId]: Internal database id of this click document
- `assessment` [string]: ID of PCA assessment where this click was detected
- `campaign` [string]:  ID of PCA campaign where this click was detected
- `customer` [string]: PCA customer identifier associated with this assessment
- `source_ip` [string]: IP address of the host that generated this click
- `source_ip_int` [long integer]: Integer version of the IP address of the host
that generated this click
- `time` [ISO date]: Timestamp of when this click was detected
- `user` [string]: PCA ID of the user that generated this click

### customers Collection ###

- `_id` [string]: PCA customer identifier
- `acronym` [string]: PCA customer acronym
- `name` [string]: PCA customer full name
- `contacts` [list]: POC Contact Information
- `email` [string]: Contact email address
- `name` [string]: Contact name
- `phone` [string]: Contact phone number
- `type` [string]: Contact type (“TECHNICAL” or “DISTRO”)

### emails Collection ###

- `_id` [ObjectId]: Internal database id of this email document
- `user` [string]: PCA ID of the user that this email was sent to
- `customer` [string]: PCA customer identifier associated with this assessment
- `assessment` [string]: ID of PCA assessment for which this email was generated
- `campaign` [string]:  ID of PCA campaign for which this email was generated
- `time` [ISO date]: Timestamp of when this email was sent
- `status` [string]: Status message indicating if the email was successfully
sent to the target

### templates Collection ###

- `_id` [ObjectId]: Internal database id of this template document
- `name` [string]: Name of the template
- `text` [string]: Content of the email template; should include subject, body,
 etc; can be HTML
- `appearance` [dictionary]: Appearance indicator ratings
- `grammar` [integer]:
  - 0: Poor
  - 1: Decent
  - 2: Proper
- `link_domain` [integer]:
  - 0: Completely fake/unrelated to the subject
  - 1: Attempt to look like/related to a real domain
- `logo_graphics` [integer]:
  - 0: Completely fake/unrelated to the subject
  - 1: Close imposters
- `sender` [dictionary]: Sender indicator ratings
- `external` [integer]:
  - 0: Completely fake/unrelated to the subject
  - 1: Looks like real external entities
- `internal` [integer]:
  - 0: Completely fake/unrelated to the subject
  - 1: Looks like a possibly real internal person or group
  - 2: Spoofs a real internal person or group
- `authoritative` [integer]:
  - 0: Not authoritative in nature
  - 1: Sender is making a request or demand and speaks from a position of power
   that could be associated with a corporate/local sender
  - 2: Sender is making a request or demand and speaks from a position of power
   that could be associated with a Federal/State office sender
- `relevancy` [dictionary]: Relevancy indicator ratings
- `organization` [integer]:
  - 0: Content is not pertinent to organization’s current events, news, and does
   not use the name/email of the targeted user
  - 1: Content is pertinent to organization’s current events, news, or uses the
   name/email of the targeted user
- `public_news` [integer]:
  - 0: Content is not pertinent to current events in the local area or nation
  - 1: Content is pertinent to current events in the local area or nation
- `behavior` [dictionary]: Behavior indicator ratings
- `fear` [integer]:
  - 0: Does not appeal to a sense of fear
  - 1: Email contains scareware or appeals to the emotion of fear within the
   theme of the email
- `duty_obligation` [integer]:
  - 0: Does not evoke a sense of duty or obligation
  - 1: Email appeals to the sense of responsibility within the theme of the email
- `curiosity` [integer]:
  - 0: Does not evoke a sense of curiosity
  - 1: Email appeals to the desire to learn more are within the theme of the email
- `greed` [integer]:
  - 0: Does not evoke a sense of greed
  - 1: Email appeals to greed and monetary gain are within the theme of the email

### user_reports Collection ###

- `assessment` [string]: PCA assessment identifier that this user_report is associated
with
- `campaign` [string]: PCA campaign identifier that this user_report is associated
with
- `customer` [string]: PCA customer identifier that this user_report is associated
with
- `first_report` [ISO date]: Timestamp when the first user click is reported for
a campaign
- `total_num_reports` [integer]: The total number of clicks reported for a campaign

### users Collection ###

- `_id` [ObjectId]: PCA ID of this user
- `customer` [string]: PCA customer identifier that this user is associated with
- `customer_defined_labels` [dictionary]: Customer-defined text labels for
grouping users for statistical purposes

## scan Database ##

### certs Collection ###

The data in this collection is derived from certificates collected by
our [Certificate
Transparency](https://www.certificate-transparency.org/) log scanner,
which only grabs certificates that apply to domains in our [domains
collection](#domains-collection).  NOTE: More details may be available in
the GitHub
[README](https://github.com/cisagov/cyhy-ct-logs/blob/initial/README.md)
document for
[cyhy-ct-logs](https://github.com/cisagov/cyhy-ct-logs).

- `_id` [string]: Internal certificate identifier from the certificate
  transparency log where the certificate was detected
- `issuer` [string]: The entity that signed and issued the
 certificate; see [RFC
 5280](https://tools.ietf.org/html/rfc5280%23section-4.1.2.4) for
 details
- `not_after` [ISO date]: Timestamp when certificate expires
- `not_before` [ISO date]: Timestamp when certificate became/becomes
  valid
- `pem` [string]: The certificate in [PEM
  format](https://tools.ietf.org/html/rfc1421)
- `sct_exists` [boolean]: Whether or not the timestamp in
  sct\_or\_not\_before refers to a Signed Certificate Timestamp
- `sct_or_not_before` [ISO date]: The earliest [Signed Certificate
  Timestamp](https://tools.ietf.org/html/rfc6962%23section-3), if one
  exists, otherwise equal to the not\_before timestamp
- `serial` [string]: Unique identifier assigned to this certificate by
  the issuing Certificate Authority; see [RFC
  5280](https://tools.ietf.org/html/rfc5280%23section-4.1.2.2) for
  details
- `subjects` [list of strings]: List of hostnames/domains where this
  certificate can be used.  This field is a concatenated list of the
  Common Name (if it exists; this field is deprecated) and the
  [Subject Alternative
  Names](https://tools.ietf.org/html/rfc5280%23section-4.2.1.6).
- `trimmed_subjects` [list of strings]: List of second-level domains
  where this certificate can be used.  These are extracted from the
  subjects field.

### domains Collection ###

The data in this collection is derived from domains collected by our
[gatherer](https://github.com/cisagov/gatherer), which pulls in
domains from Cyber Hygiene and the GSA.  NOTE: More details may be
available in the GitHub
[README](https://github.com/cisagov/cyhy-ct-logs/blob/initial/README.md)
documents for [gatherer](https://github.com/cisagov/gatherer) and
[saver](https://github.com/cisagov/saver).

- `_id` [string]: Base domain name
- `agency` [dictionary]: The organization that claims ownership of the
  scanned domain
  - `id` [string]: Organization identifier
  - `name` [string]: Organization name
- `cyhy_stakeholder` [boolean]: Is the organization that claims to own this host
a Cyber Hygiene stakeholder?
- `scan_date` [ISO date]: Timestamp when the domain was inserted in the
  database

### https_scan Collection ###

The data in this collection is derived from domain names collected by
our [gatherer](https://github.com/cisagov/gatherer), which pulls in
domains from Cyber Hygiene and the GSA.  NOTE: More details may be
available in the GitHub
[README](https://github.com/cisagov/pshtt/blob/develop/README.md)
document for [pshtt](https://github.com/cisagov/pshtt).

- `_id` [string]: Internal database id of this HTTPS scan document
- `agency` [dictionary]: The organization that claims ownership of the
  scanned domain
  - `id` [string]: Organization identifier
  - `name` [string]: Organization name
- `base_domain` [string]: Base domain that was HTTPS scanned
- `canonical_url` [string]: URL based on the observed redirect logic of
  the scanned domain
- `cyhy_stakeholder` [boolean]: Is the organization that claims to own
  this host a Cyber Hygiene stakeholder?
- `defaults_https` [boolean]: True if the canonical\_url uses HTTPS
- `domain` [string]: The domain that was HTTPS scanned
- `domain_enforces_https` [boolean]: Does the scanned domain both
  support HTTPS and default to HTTPS?
- `domain_supports_https` [boolean]: True if `downgrades_https` is
  False and either (1) valid\_https is True or (2) https\_bad\_chain
  is True and https\_bad\_hostname is False
- `domain_uses_strong_hsts` [boolean]: True if hsts is True for the
  scanned domain and hsts\_max\_age is at least 31,536,000 seconds (365 days)
- `downgrades_https` [boolean]: True if HTTPS is supported in some way,
  but the canonical HTTPS endpoint immediately redirects internally to
  HTTP
- `https_bad_chain` [boolean]: True if either HTTPS endpoint
  (`https://<domain>`, `https://www.<domain>`) contains a bad chain
- `https_bad_hostname` [boolean]: True if either HTTPS endpoint
  (`https://<domain>`, `https://www.<domain>`) fails hostname
  validation
- `https_expired_cert` [boolean]: True if either HTTPS endpoint
  (`https://<domain>`, `https://www.<domain>`) has an expired
  certificate
- `https_self_signed_cert` [boolean]: True if either HTTPS endpoint
  (`https://<domain>`, `https://www.<domain>`) has a self-signed
  certificate
- `hsts` [boolean]: True if the canonical\_url has
  [HSTS](https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security)
  enabled
- `hsts_base_domain_preloaded` [boolean]: True if base\_domain appears
  in appears in the [Chrome preload
  list](https://chromium.googlesource.com/chromium/src/net/%2B/master/http/transport_security_state_static.json)
  with the include\_subdomains flag equal to True
- `hsts_entire_domain` [boolean]: True if the root HTTPS endpoint (not
  the canonical HTTPS endpoint) has HSTS enabled and uses the HSTS
  include\_subdomains flag
- `hsts_header` [string]: HSTS header at the canonical endpoint of the
  scanned domain
- `hsts_max_age` [integer]: Max-age listed in the HSTS header at the
  canonical endpoint of the scanned domain
- `hsts_preload_pending` [boolean]: True if the scanned domain appears
  in the [Chrome preload pending
  list](https://hstspreload.org/api/v2/pending) with the
  include\_subdomains flag equal to True
- `hsts_preload_ready` [boolean]: True if the root HTTPS endpoint (not
  the canonical HTTPS endpoint) has HSTS enabled, has a max-age of at
  least 18 weeks, and uses the include\_subdomains and preload flag.
- `hsts_preloaded` [boolean]: True if if the scanned domain appears in
  the [Chrome preload
  list](https://chromium.googlesource.com/chromium/src/net/%2B/master/http/transport_security_state_static.json)
  with the include\_subdomains flag equal to True, regardless of what
  header is present on any endpoint
- `is_base_domain` [boolean]: True if domain is equal to base\_domain
- `latest` [boolean]: Is this the latest HTTPS scan of this host?
- `live` [boolean]: Are any of the endpoints (`http://<domain>`,
  `http://www.<domain>`, `https://<domain>`, `https://www.<domain>`)
  for this domain live?
- `redirect` [boolean]: True if at least one endpoint is a redirect, and
  all endpoints are either redirects or down
- `redirect_to` [string]: URI that the scanned domain redirects to (if
  redirect is True)
- `scan_date` [ISO date]: Timestamp when the HTTPS scan was done
- `strictly_forces_https` [boolean]: True if one of the HTTPS
  endpoints (`https://<domain>`, `https://www.<domain>`) is live, and
  if both HTTP endpoints (`http://<domain>`, `http://www.<domain>`)
  are either down or redirect immediately to any HTTPS URI
- `unknown_error` [boolean]: True if an unknown error occurred during
  the HTTPS scan
- `valid_https` [boolean]: True if the canonical\_url responds on port
  443 with an unexpired valid certificate for the hostname; can be
  True even if canonical\_url uses HTTP

### precerts Collection ###

The data in this collection is derived from certificates collected by
our [Certificate
Transparency](https://www.certificate-transparency.org/) log scanner,
which only grabs certificates that apply to domains in our [domains
collection](#domains-collection).  NOTE: More details may be available in
the GitHub
[README](https://github.com/cisagov/cyhy-ct-logs/blob/initial/README.md)
document for
[cyhy-ct-logs](https://github.com/cisagov/cyhy-ct-logs).

- `_id` [string]: Internal certificate identifier from the certificate
  transparency log where the certificate was detected
- `issuer` [string]: The entity that signed and issued the
  certificate; see [RFC
  5280](https://tools.ietf.org/html/rfc5280%23section-4.1.2.4) for
  details
- `not_after` [ISO date]: Timestamp when certificate expires
- `not_before` [ISO date]: Timestamp when certificate became/becomes
  valid
- `pem` [string]: The certificate in [PEM
  format](https://tools.ietf.org/html/rfc1421)
- `sct_exists` [boolean]: Whether or not the timestamp in
  sct\_or\_not\_before refers to the Signed Certificate Timestamp
- `sct_or_not_before` [ISO date]: The [Signed Certificate
  Timestamp](https://tools.ietf.org/html/rfc6962%23section-3), if it
  exists, otherwise equal to the not\_before timestamp
- `serial` [string]: Unique identifier assigned to this certificate by
  the issuing Certificate Authority; see [RFC
  5280](https://tools.ietf.org/html/rfc5280%23section-4.1.2.2) for
  details
- `subjects` [list of strings]: List of hostnames/domains where this
  certificate can be used.  This field is a concatenated list of the
  Common Name (if it exists; this field is deprecated) and the
  [Subject Alternative
  Names](https://tools.ietf.org/html/rfc5280%23section-4.2.1.6).
- `trimmed_subjects` [list of strings]: List of second-level domains
  where this certificate can be used.  These are extracted from the
  subjects field.

### sslyze_scan Collection ###

The data in this collection is derived from domain names collected by
our [gatherer](https://github.com/cisagov/gatherer), which pulls in
domains from Cyber Hygiene and the GSA.  NOTE: More details may be
available in the GitHub
[README](https://github.com/nabla-c0d3/sslyze/blob/master/README.md)
document for [SSLyze](https://github.com/nabla-c0d3/sslyze).

- `_id` [string]: Internal database id of this SSLyze scan document
- `agency` [dictionary]: The organization that claims ownership of the
  scanned domain
  - `id` [string]: Organization identifier
  - `name` [string]: Organization name
- `all_forward_secrecy` [boolean]: True if every cipher supported by
  scanned\_hostname supports forward secrecy
- `all_rc4` [boolean]: True if every cipher supported by
  scanned\_hostname supports RC4
- `any_3des` [boolean]: True if any cipher supported by
  scanned\_hostname supports 3DES
- `any_forward_secrecy` [boolean]: True if any cipher supported by
  scanned\_hostname supports forward secrecy
- `any_rc4` [boolean]: True if any cipher supported by
  scanned\_hostname supports RC4
- `base_domain` [string]: Base domain that was scanned by SSLyze
- `cyhy_stakeholder` [boolean]: Whether or not the organization that
  claims this host is a Cyber Hygiene stakeholder
- `domain` [string]: The domain that was scanned by SSLyze
- `errors` [string]: List of errors encountered when SSLyze scanned
  scanned\_hostname
- `highest_constructed_issuer` [string]: Highest certificate issuer in
  the chain constructed when scanned\_hostname was scanned by SSLyze
- `highest_served_issuer` [string]: Highest certificate issuer in the
  chain served when scanned\_hostname was scanned by SSLyze
- `is_base_domain` [boolean]: True if domain is equal to base\_domain
- `is_symantec_cert` [boolean]: True if certificate detected by SSLyze
  was issued by Symantec Corporation
- `key_length` [integer]: Public key length of certificate detected by
  SSLyze for scanned\_hostname
- `key_type` [string]: Public key type of certificate detected by
  SSLyze for scanned\_hostname
- `latest` [boolean]: Is this the latest SSLyze scan of this host?
- `not_after` [ISO date]: Timestamp when certificate for
  scanned\_hostname expires
- `not_before` [ISO date]: Timestamp when certificate for
  scanned\_hostname became/becomes valid
- `scan_date` [ISO date]: Timestamp when the SSLyze scan was done
- `scanned_hostname` [string]: The hostname that was scanned by SSLyze
- `scanned_port` [integer]: The port number that was scanned by SSLyze
- `sha1_in_construsted_chain` [boolean]: True if any certificates in
  the chain constructed when scanned\_hostname was scanned by SSLyze
  support SHA-1
- `sha1_in_served_chain` [boolean]: True if any certificates in the
  chain served when scanned\_hostname was scanned by SSLyze support
  SHA-1
- `signature_algorithm` [string]: Signature algorithm of certificate
  detected by SSLyze for scanned\_hostname
- `symantec_distrust_date` [string]: Month and year when certificates
  issued by Symantec Corporation will no longer be trusted
- `sslv2` [boolean]: True if SSLv2 is supported by scanned\_hostname
- `sslv3` [boolean]: True if SSLv3 is supported by scanned\_hostname
- `starttls_smtp` [boolean]: True if STARTTLS on SMTP is supported by
  scanned\_hostname
- `tlsv1_0` [boolean]: True if TLS 1.0 is supported by
  scanned\_hostname
- `tlsv1_1` [boolean]: True if TLS 1.1 is supported by
  scanned\_hostname
- `tlsv1_2` [boolean]: True if TLS 1.2 is supported by
  scanned\_hostname

### trustymail Collection ###

The data in this collection is derived from domain names collected by
our [gatherer](https://github.com/cisagov/gatherer), which pulls in
domains from Cyber Hygiene and the GSA.  NOTE: More details may be
available in the GitHub
[README](https://github.com/cisagov/trustymail/blob/develop/README.md)
document for [trustymail](https://github.com/cisagov/trustymail).

- `_id` [string]: Internal database id of this Trustymail scan document
- `agency` [dictionary]: The organization that claims ownership of the
  scanned domain
  - `id` [string]: Organization identifier
  - `name` [string]: Organization name
- `aggregate_report_uris` [list of dictionaries]: List of DMARC
  aggregate report URIs specified by the scanned domain
  - `modifier` [string]: DMARC aggregate report URI modifier
  - `uri` [string]: DMARC aggregate report URI
- `base_domain` [string]: Base domain that was scanned by Trustymail
- `debug_info` [string]: List of warnings or errors reported by
  Trustymail while scanning the domain
- `dmarc_policy` [string]: Applicable DMARC policy for the scanned
  domain, based on policies found in dmarc\_results and
  dmarc\_results\_base\_domain
- `dmarc_policy_percentage` [integer]: Percentage of mail that should
  be subjected to the dmarc\_policy according to dmarc\_results
- `dmarc_record` [boolean]: True if a DMARC record was found for the
  scanned domain
- `dmarc_record_base_domain` [boolean]: True if a DMARC record was
  found for base\_domain
- `dmarc_results` [string]: DMARC record that was discovered when
  querying DNS for the scanned domain
- dmarc\_results\_base\_domain [string]: DMARC record that was
  discovered when querying DNS for base\_domain
- `domain` [string]: The domain that was scanned by Trustymail
- `domain_supports_smtp` [boolean]: True if any mail servers specified
  in an MX record associated with the scanned domain support SMTP
- `domain_supports_smtp_results` [string]: List of mail server and
  port combinations from the scanned domain that support SMTP
- `domain_supports_starttls` [boolean]: True if all mail servers
  associated with the scanned domain that support SMTP also support
  STARTTLS
- `domain_supports_starttls_results` [string]: List of mail server
  and port combinations from the scanned domain that support STARTTLS
- `forensic_report_uris` [list of dictionaries]: List of DMARC
  forensic report URIs specified by the scanned domain
  - `modifier` [string]: DMARC forensic report URI modifier
  - `uri` [string]: DMARC forensic report URI
- `has_aggregate_report_uri` [boolean]: True if
  dmarc\_results include valid rua URIs that tell recipients where to
  send DMARC aggregate reports.
- `has_forensic_report_uri` [boolean]: True if dmarc\_results include
  valid ruf URIs that tell recipients where to send DMARC forensic
  reports.
- `is_base_domain` [boolean]: True if domain is equal to base\_domain
- `latest` [boolean]: Is this the latest Trustymail scan of this host?
- `live` [boolean]: True if the scanned domain is published in public
  DNS
- `mail_server_ports_tested` [string]: List of ports tested by
  Trustymail for SMTP and STARTTLS support
- `mail_servers` [string]: List of hosts found in the MX record of the
  scanned domain
- `mx_record` [boolean]: True if an MX record for the scanned domain
  was found that contains one or more mail servers
- `scan_date` [ISO date]: Timestamp when the Trustymail scan was done
- `spf_results` [string]: Text representation of any SPF record found
  for the scanned domain
- `syntax_errors` [string]: List of syntax errors encountered when
  Trustymail analyzed SPF records of the scanned domain
- `valid_dmarc` [boolean]: True if the DMARC record found for the
  scanned domain is syntactically correct
- `valid_dmarc_base_domain` [boolean]: True if the DMARC record found
  for base\_domain is syntactically correct
- `valid_spf` [boolean]: True if the SPF record found for the scanned
  domain is syntactically correct, per [RFC
  4408](https://www.ietf.org/rfc/rfc4408.txt)
