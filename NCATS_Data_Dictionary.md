# NCATS Data Dictionary #

26th March 2019

This document provides a data dictionary for the data stored in the
following NoSQL MongoDB databases:

-   cyhy - Cyber Hygiene port and vulnerability scanning
-   scan

-   Domains gathered from Cyber Hygiene and the GSA
-   SPF/DMARC/STARTTLS trustworthy email scanning
-   HTTPS web server scanning
-   SSL server scanning
-   Certificates and pre-certificates from [Certificate
    Transparency](https://www.google.com/url?q=https://www.certificate-transparency.org/&sa=D&ust=1553612329747000) logs

-   assessment - Risk/Vulnerability Assessment (RVA) management data

This information is organized by database and collection (table).

[cyhy Database](#cyhy database)

[cves Collection](#h.apcsjqsir0bk)

[host\_scans Collection](#h.7dknfbriok3q)

[hosts Collection](#h.w88pyenorwyp)

[places Collection](#h.mzrl7zl1buq4)

[port\_scans Collection](#h.uyx91jau9a12)

[reports Collection](#h.xtcuyt1km9iy)

[requests Collection](#h.17e48hdereq9)

[snapshots Collection](#h.l980tmvl2rzr)

[tallies Collection](#h.ajapc322d6th)

[tickets Collection](#h.8ebvbk7glftr)

[vuln\_scans Collection](#h.yr3f80azd8jd)

[scan Database:](#h.8p8z7vcs08gu)

[certs Collection](#h.vkvlb4gapxkz)

[domains Collection](#h.qwt153c8i5hu)

[https\_scan Collection](#h.7yzwy0vl6wdl)

[precerts Collection](#h.e3bxszywt6cz)

[sslyze\_scan Collection](#h.jdvt2g4p7kc1)

[trustymail Collection](#h.yqcj55euwwjs)

[assessment Database:](#h.s1bjtae0qgd6)

[rva Collection](#h.4ixfrma0cnea)

Go to section
* [Cyhy Database](#cyhy-database)  
* [Hello World](#hello-world)
* [Another section](#new-section)    <-- it's called 'Another section' in this list but refers to 'New section'

## Cyhy Database
### Hello World
## New section

* * * * *

 {#h.6k1y2l3r3ao8 .c23 .c37}

## Cyhy Database:
==============

cves Collection {#h.apcsjqsir0bk .c20}
---------------

The data in this collection is derived from the National Vulnerability
Database [CVE
feeds](https://www.google.com/url?q=https://nvd.nist.gov/vuln/data-feeds&sa=D&ust=1553612329754000).

-   \_id [string]: [Common Vulnerabilities and
    Exposures](https://www.google.com/url?q=https://cve.mitre.org/&sa=D&ust=1553612329755000) identifier
-   cvss\_score [decimal]: [CVSS v2.0 base
    score](https://www.google.com/url?q=https://nvd.nist.gov/vuln-metrics&sa=D&ust=1553612329755000)
-   severity [decimal]: [CVSS v2.0 severity
    rating](https://www.google.com/url?q=https://nvd.nist.gov/vuln-metrics&sa=D&ust=1553612329756000)

host\_scans Collection {#h.7dknfbriok3q .c20}
----------------------

The data in this collection is derived from IP addresses supplied by the
CyHy stakeholders.

-   \_id [ObjectId]: Internal database id of this host scan document
-   accuracy [integer]: Confidence rating by scanner in OS class guess
-   classes [list of dictionaries]: Guesses for OS class (comes directly
    from scanner; see nmap details
    [here](https://www.google.com/url?q=https://nmap.org/book/app-nmap-dtd.html&sa=D&ust=1553612329758000)) 
-   hostname [string]: Hostname, if one was detected
-   ip [string]: IP address that was scanned
-   ip\_int [long integer]: Integer version of IP address that was
    scanned
-   latest [boolean]: Is this the latest scan of this host?
-   line [integer]: Line number in the [nmap OS
    database](https://www.google.com/url?q=https://svn.nmap.org/nmap/nmap-os-db&sa=D&ust=1553612329759000) corresponding
    the the OS class guess
-   name [string]: Type of host detected (best guess, comes directly
    from scanner)
-   owner [string]: Organization that claims the IP address associated
    with this scan
-   snapshots [list of ObjectIds]: Snapshots that include this scan
-   source [string]: Source of the scan (e.g. “nmap”)
-   time [ISO date]: Timestamp when the scan occurred

hosts Collection {#h.w88pyenorwyp .c20}
----------------

The data in this collection is derived from IP addresses supplied by the
CyHy stakeholders.

-   \_id [long integer]: Integer version of this host document’s IP
    address
-   ip [string]: IP address corresponding to this host document
-   last\_change [ISO date]: Timestamp of when this host document was
    last updated
-   latest\_scan [dictionary]: Timestamps of last time host completed
    each scan stage
-   loc [list]: Longitude and latitude of host, according to geolocation
    database
-   priority [integer]: Scan priority of this host document, from -16
    (most urgent) to 1 (least urgent)

-   -16: Most severe vulnerability detected on this host is Critical
    severity
-   -8: Most severe vulnerability detected on this host is High severity
-   -4: Most severe vulnerability detected on this host is Medium
    severity
-   -2: Most severe vulnerability detected on this host is Low severity
-   -1: No vulnerabilities detected on this host
-   1: Host document represents a “dark space” IP address; i.e. live
    host not detected

-   next\_scan [ISO date]: Timestamp of when this host document is
    scheduled to be scanned next; a value of null indicates that the
    host document has a status other than “DONE” (i.e. currently queued
    up for a scan or running a scan)
-   owner [string]: Organization that claims the IP address associated
    with this host document
-   r [decimal]: A random number between 0 and 1 used to randomize scan
    order
-   stage [string]: Current scan stage for this host document

-   “NETSCAN1” - Port scan of top 30 most-common ports
-   “NETSCAN2” - Port scan of next 970 most-common ports
-   “PORTSCAN” - Full port scan of all 65,535 ports
-   “VULNSCAN” - Vulnerability scan

-   state [dictionary]: Current state of this host document

-   reason [string]: Reason given by the port scanner as to whether or
    not this host document represents a live host
-   up [boolean]: Whether or not a live host was detected at this host
    document’s IP address by the port scanner

-   status [string]: Current scan status for this host document:

-   “WAITING” - Waiting to be  for scanning
-   “READY” - Ready to be assigned to a scanner
-   “RUNNING” - Currently being scanned
-   “DONE” - Latest scan has completed

places Collection {#h.mzrl7zl1buq4 .c20}
-----------------

The data in this collection is derived from the “Government Units” and
“Populated Places” Topical Gazetteers files from
[USGS](https://www.google.com/url?q=https://geonames.usgs.gov/domestic/download_data.htm&sa=D&ust=1553612329765000).

-   \_id [long integer]: [GNIS
    ID](https://www.google.com/url?q=https://geonames.usgs.gov/domestic/index.html&sa=D&ust=1553612329766000) corresponding
    to this place
-   class [string]: Class of this place (“COUNTY”, “STATE”, “Populated
    Place”, “Civil”)
-   country [string]: Two-letter abbreviation of the country where this
    place is
-   country\_name [string]: Full name of the country where this place is
-   county [string]: Full name of the county where this place is
-   county\_fips [string]: [FIPS
    code](https://www.google.com/url?q=https://catalog.data.gov/dataset/fips-county-code-look-up-tool&sa=D&ust=1553612329767000) for
    the county where this place is
-   name [string]: Full name of this place
-   state [string]: Two-letter postal abbreviation of the state where
    this place is
-   state\_fips [string]: [FIPS
    code](https://www.google.com/url?q=https://catalog.data.gov/dataset/fips-state-codes&sa=D&ust=1553612329768000) for
    the state where this place is
-   state\_name [string]: Full name of the state where this place is

port\_scans Collection {#h.uyx91jau9a12 .c20}
----------------------

The data in this collection is derived from IP addresses supplied by the
CyHy stakeholders.

-   \_id [ObjectId]: Internal database id of this port scan document
-   ip [string]: IP address of the host that was port scanned
-   ip\_int [long integer]: Integer version of IP address that was port
    scanned
-   latest [boolean]: Is this the latest scan of this port?
-   owner [string]: Organization that claims the IP address associated
    with this port scan
-   port [integer]: Number of the port that was scanned
-   protocol [string]: Protocol for this port scan (“tcp” or “udp”)
-   reason [string]: Why this port is determined to be open, as reported
    by the port scanner
-   service [dictionary]: Details about this port, as reported by the
    scanner
-   snapshots [list of ObjectIds]: Snapshots that include this port scan
-   source [string]: Source of the scan (e.g. “nmap”)
-   state [string]: State of the port, as reported by the scanner; see
    nmap states
    [here](https://www.google.com/url?q=https://nmap.org/book/man-port-scanning-basics.html&sa=D&ust=1553612329771000)
-   time [ISO date]: Timestamp when the port was scanned

reports Collection {#h.xtcuyt1km9iy .c20}
------------------

The data in this collection is generated as part of Cyber Hygiene report
creation process.

-   \_id [ObjectId]: Internal database id of this report document
-   generated\_time [ISO date]: Timestamp when this report or scorecard
    was generated
-   owner [string]: Organization that this report was created for; a
    value of null indicates that this report was a scorecard that
    contained results for multiple organizations
-   report\_types [list of strings]: Type of report that was generated

-   “CYBEX” - Cyber Exposure scorecard
-   “CYHY” - Cyber Hygiene report

-   snapshot\_oid [ObjectId]: Snapshot that was the basis for this Cyber
    Hygiene report (value is null for Cyber Exposure scorecards)

requests Collection {#h.17e48hdereq9 .c20}
-------------------

The data in this collection is derived from data supplied by the CyHy
stakeholders.

-   \_id [string]: Organization identifier (corresponds to owner field
    in many collections)
-   agency [dictionary]: Details about the organization

-   acronym [string]: Organization acronym
-   contacts [list of dictionaries]: Contact details for the
    organization

-   email [string]: Contact email address
-   name [string]: Contact name
-   phone [string]: Contact phone number
-   type [string]: Contact type (“TECHNICAL” or “DISTRO”)

-   location [dictionary]: Organization location details, typically
    represents headquarters or base of operations for organizations that
    are spread across multiple localities

-   country [string]: Two-letter abbreviation of the country
-   country\_name [string]: Full name of the country
-   county [string]: Full name of the county
-   county\_fips [string]: [FIPS
    code](https://www.google.com/url?q=https://catalog.data.gov/dataset/fips-county-code-look-up-tool&sa=D&ust=1553612329776000) of
    the county
-   gnid\_id [long integer]: [GNIS
    ID](https://www.google.com/url?q=https://geonames.usgs.gov/domestic/index.html&sa=D&ust=1553612329777000) of
    the location
-   name [string]: Full name of the location
-   state [string]: Two-letter postal abbreviation of the state
-   state\_fips [string]: [FIPS
    code](https://www.google.com/url?q=https://catalog.data.gov/dataset/fips-state-codes&sa=D&ust=1553612329778000) for
    the state
-   state\_name [string]: Full name of the state

-   name [string]: Full name of the organization
-   type [string]: Organization type (“FEDERAL”, “STATE”, “LOCAL”,
    “TRIBAL”, “TERRITORIAL”, “PRIVATE”)

-   children [list of strings]: Identifiers of organizations that are
    children of this organization
-   init\_stage [string]: First scan stage for this organization
-   key [string]: Password used to encrypt reports for this organization
-   networks [list of strings]: CIDR blocks of IP addresses claimed by
    this organization
-   period\_start [ISO date]: Timestamp when scanning can begin for this
    organization
-   report\_period [string]: Frequency of reports; only current
    supported value is “WEEKLY”
-   report\_types [list of strings]: Types of reports that this
    organization receives (“CYHY”, “CYBEX”)
-   retired [boolean]: Whether or not this organization is currently
    subscribed to the Cyber Hygiene service
-   scan\_limits [list of dictionaries]: Limits on scan concurrency

-   concurrent [integer]: Number of concurrent scans of that type
-   scanType [string]: Type of scan to limit (“NETSCAN1”, “NETSCAN2”,
    “PORTSCAN”, “VULNSCAN”)

-   scan\_types [list of strings]: Types of scanning that this
    organization receives; only current supported value is “CYHY”
-   scheduler [string]: Name of the scheduler used to schedule scans;
    only current supported value is “PERSISTENT1”
-   stakeholder [boolean]: Whether or not this organization is
    considered to be a CyHy stakeholder
-   windows [list of dictionaries]: Windows when the organization allows
    us to scan

-   day [string]: Day that scanning is allowed
-   start [string]: Time of day when scanning is allowed to start
-   duration [integer]: Duration of scan window, in hours

snapshots Collection {#h.l980tmvl2rzr .c20}
--------------------

The data in this collection is derived from IP addresses supplied by the
CyHy stakeholders.

-   \_id [ObjectId]: Internal database id of this snapshot document
-   cvss\_average\_all [decimal]: Average CVSS score of all hosts in
    this snapshot
-   cvss\_average\_vulnerable [decimal]: Average CVSS score of
    vulnerable hosts in this snapshot
-   end\_time [ISO date]: Timestamp of the last scan in this snapshot
-   host\_count [integer]: Number of hosts detected in this snapshot
-   last\_change [ISO date]: Timestamp of when this snapshot document
    was last updated
-   latest [boolean]: Is this the latest snapshot for this organization?
-   networks [list of strings]: CIDR blocks claimed by the organization
    at the time this snapshot was generated
-   owner [string]: Organization that this snapshot is associated with
-   parents [ObjectId]: Identifier of the parent snapshot(s); used only
    for organizations with children; if this value is equal to the \_id
    of this snapshot, then this snapshot has no parent
-   port\_count [integer]: Total number of open ports detected in this
    snapshot
-   services [dictionary]: Number of services detected in this snapshot,
    grouped by service name
-   start\_time [ISO date]: Timestamp of the first scan in this snapshot
-   tix\_msec\_open[dictionary]:
-   tix\_msec\_to\_close[dictionary]:
-   unique\_operating\_systems [integer]: Number of unique operating
    systems detected in this snapshot
-   unique\_port\_count [integer]: Number of unique open ports detected
    in this snapshot
-   unique\_vulnerabilities [dictionary]: Number of unique
    vulnerabilities in this snapshot, grouped by severity
-   vulnerable\_host\_count [integer]: Number of vulnerable hosts
    detected in this snapshot
-   vulnerabilities [dictionary]: Total number of vulnerabilities in
    this snapshot, grouped by severity
-   world [dictionary]: DEPRECATED; metrics about the overall state of
    CyHy at the time this snapshot was generated

tallies Collection {#h.ajapc322d6th .c9}
------------------

The data in this collection is derived from IP addresses supplied by the
CyHy stakeholders.

-   \_id [string]: Organization identifier (corresponds to owner field
    in many collections)
-   counts [dictionary]: Number of hosts currently in each scan stage
    and scan status

-   BASESCAN [dictionary]: DEPRECATED
-   NETSCAN1, NETSCAN2, PORTSCAN, VULNSCAN [dictionaries]

-   DONE [integer]: Number of hosts for this organization in “DONE”
    status for the given scan stage
-   READY [integer]: Number of hosts for this organization in “READY”
    status for the given scan stage
-   RUNNING [integer]: Number of hosts for this organization in
    “RUNNING” status for the given scan stage
-   WAITING [integer]: Number of hosts for this organization in
    “WAITING” status for the given scan stage

-   last\_change [ISO date]: Timestamp of when this tally document was
    last updated

tickets Collection {#h.8ebvbk7glftr .c26}
------------------

The data in this collection is derived from IP addresses supplied by the
CyHy stakeholders.

-   \_id [ObjectId]: Internal database id of this ticket document
-   details [dictionary]: Vulnerability details

-   cve [string]: [Common Vulnerabilities and
    Exposures](https://www.google.com/url?q=https://cve.mitre.org/&sa=D&ust=1553612329789000) identifier
-   cvss\_base\_score [decimal]: [CVSS v2.0 base
    score](https://www.google.com/url?q=https://nvd.nist.gov/vuln-metrics&sa=D&ust=1553612329790000)
-   name [string]: Vulnerability name
-   score\_source [string]: Source of the CVSS base score (e.g. “nvd” or
    “nessus”)
-   severity [decimal]: [CVSS v2.0 severity
    rating](https://www.google.com/url?q=https://nvd.nist.gov/vuln-metrics&sa=D&ust=1553612329791000)

-   events [dictionary]: Details of key ticket events

-   action [string]: Event type

-   “OPENED” - Ticket opened for the first time
-   “VERIFIED” - Verified that an open ticket is still open
-   “CHANGED” - Data within the ticket changed (e.g. marked as a false
    positive or the vulnerability’s CVSS score changed)
-   “CLOSED” - Ticket closed (vulnerability no longer detected)
-   “REOPENED” - A closed ticket reopened
-   “UNVERIFIED” - A vulnerability was detected for a ticket that is
    marked as a false positive

-   reason [string]: Short description of the event
-   reference [ObjectId]: The identifier for the vulnerability scan
    related to the event
-   time [ISO date]: Timestamp of the event
-   delta [list of dictionaries]: Only applies to “CHANGED” events; list
    of what changed

-   key [string]: Ticket field that changed
-   from [type depends on key]: Value of key before the “CHANGED” event
-   to [type depends on key]: Value of key after the “CHANGED” event

-   false\_positive [boolean]: Is this ticket marked as a false
    positive?
-   ip [string]: IP address of the host that was vulnerability scanned
-   ip\_int [long integer]: Integer version of IP address that was
    vulnerability scanned
-   last\_change [ISO date]: Timestamp of when this ticket document was
    last updated
-   loc [list]: Longitude and latitude of host (according to geolocation
    database) associated with this ticket
-   open [boolean]: Was this vulnerability detected in the latest scan
    of the associated host?
-   owner [string]: Organization that claims the IP address associated
    with this ticket
-   port [integer]: Number of the vulnerable port in this ticket
-   protocol [string]: Protocol for the vulnerable port in this ticket
    (“tcp” or “udp”)
-   snapshots [list of ObjectIds]: Snapshots that include this ticket
-   source [string]: Source of the vulnerability scan (e.g. “nessus”)
-   source\_id [integer]: Source-specific identifier for the
    vulnerability scan (e.g. the scanner plugin identifier that detected
    the vulnerability)
-   time\_closed [ISO date]: Timestamp when this ticket was closed
    (vulnerability was no longer detected); value of null indicates that
    this ticket is currently open
-   time\_opened [ISO date]: Timestamp when this ticket was opened
    (vulnerability was first detected)

vuln\_scans Collection {#h.yr3f80azd8jd .c20}
----------------------

The data in this collection is derived from IP addresses supplied by the
CyHy stakeholders.

-   \_id [ObjectId]: Internal database id of this vulnerability scan
    document
-   bid [string]: [Bugtraq
    ID](https://www.google.com/url?q=https://en.wikipedia.org/wiki/Bugtraq&sa=D&ust=1553612329796000)
-   cert [string]: [CERT
    ID](https://www.google.com/url?q=http://www.kb.cert.org/vuls&sa=D&ust=1553612329797000)
-   cpe [string]: [Common Platform
    Enumerator](https://www.google.com/url?q=https://nvd.nist.gov/products/cpe&sa=D&ust=1553612329797000)
-   cve [string]: [Common Vulnerabilities and
    Exposures](https://www.google.com/url?q=https://cve.mitre.org/&sa=D&ust=1553612329798000) identifier
-   cvss\_base\_score [string]: [CVSS base
    score](https://www.google.com/url?q=https://nvd.nist.gov/vuln-metrics&sa=D&ust=1553612329798000)
-   cvss\_temporal\_score [string]: [CVSS temporal
    score](https://www.google.com/url?q=https://nvd.nist.gov/vuln-metrics&sa=D&ust=1553612329799000)
-   cvss\_temporal\_vector [string]: [CVSS temporal
    vector](https://www.google.com/url?q=https://nvd.nist.gov/vuln-metrics&sa=D&ust=1553612329799000)
-   cvss\_vector [string]: [CVSS
    vector](https://www.google.com/url?q=https://nvd.nist.gov/vuln-metrics&sa=D&ust=1553612329800000)
-   description [string]: Description of the vulnerability, according to
    the vulnerability scanner
-   exploit\_available [string]: Whether or not an exploit is available,
    according to the vulnerability scanner
-   exploitability\_ease [string]: Ease of exploitation, according to
    the vulnerability scanner
-   fname [string]: Filename of the vulnerability scanner plugin that
    detected this vulnerability
-   ip [string]: IP address of the host that was vulnerability scanned
-   ip\_int [long integer]: Integer version of IP address that was
    vulnerability scanned
-   latest [boolean]: Is this the latest vulnerability scan of this
    port/protocol/host?
-   owner [string]: Organization that claims the IP address associated
    with this vulnerability scan
-   osvdb [string]: [Open Source Vulnerability
    Database](https://www.google.com/url?q=https://en.wikipedia.org/wiki/Open_Source_Vulnerability_Database&sa=D&ust=1553612329802000) identifier
    for the detected vulnerability
-   patch\_publication\_date [ISO date]: Date when a patch was published
    for this vulnerability
-   plugin\_family [string]: Family of the plugin run by the
    vulnerability scanner that detected this vulnerability
-   plugin\_id [integer]: ID of the plugin run by the vulnerability
    scanner that detected this vulnerability
-   plugin\_modification\_date [ISO date]: Latest modification date of
    the vulnerability scanner plugin that detected this vulnerability
-   plugin\_name [string]: Name of the vulnerability scanner plugin that
    detected this vulnerability
-   plugin\_output [string]: Plugin-specific output from the
    vulnerability scanner
-   plugin\_publication\_date [ISO date]: Publication date of the
    vulnerability scanner plugin that detected this vulnerability
-   plugin\_type [string]: Vulnerability scanner plugin type
-   port [integer]: Number of the port that was vulnerability scanned
-   protocol [string]: Protocol for the vulnerable port in this scan
    (“tcp” or “udp”)
-   risk\_factor [string]: Risk factor of the detected vulnerability
    according to the vulnerability scanner
-   script\_version [string]: Script version string
-   see\_also [string]: Additional reference(s) for this vulnerability
    provided by the vulnerability scanner
-   service [string]: Service detected at the vulnerable port in this
    scan
-   severity [decimal]: CVSS v2.0 severity rating from the vulnerability
    scanner
-   snapshots [list of ObjectIds]: Snapshots that include this
    vulnerability scan
-   solution [string]: Solution to mitigate the detected vulnerability,
    according to the vulnerability scanner
-   source [string]: Source of the vulnerability scan (e.g. “nessus”)
-   synopsis [string]: Brief overview of the vulnerability
-   time [ISO date]: Timestamp when the vulnerability was detected
-   vuln\_publication\_date [ISO date]: Vulnerability publication date
-   xref [string]: External reference

scan Database: {#h.8p8z7vcs08gu .c23}
==============

certs Collection {#h.vkvlb4gapxkz .c20}
----------------

The data in this collection is derived from certificates collected by
our [Certificate
Transparency](https://www.google.com/url?q=https://www.certificate-transparency.org/&sa=D&ust=1553612329808000) log
scanner, which only grabs certificates that apply to domains in our
[domains collection](#h.qwt153c8i5hu).  NOTE: More details may be
available in the GitHub
[README](https://www.google.com/url?q=https://github.com/dhs-ncats/cyhy-ct-logs/blob/initial/README.md&sa=D&ust=1553612329808000) document
for
[cyhy-ct-logs](https://www.google.com/url?q=https://github.com/dhs-ncats/cyhy-ct-logs&sa=D&ust=1553612329808000).

-   \_id [string]: Internal certificate identifier from the certificate
    transparency log where the certificate was detected
-   issuer [string]: The entity that signed and issued the certificate;
    see [RFC
    5280](https://www.google.com/url?q=https://tools.ietf.org/html/rfc5280%23section-4.1.2.4&sa=D&ust=1553612329809000) for
    details
-   not\_after [ISO date]: Timestamp when certificate expires
-   not\_before [ISO date]: Timestamp when certificate became/becomes
    valid
-   pem [string]: The certificate in [PEM
    format](https://www.google.com/url?q=https://tools.ietf.org/html/rfc1421&sa=D&ust=1553612329810000)
-   sct\_exists [boolean]: Whether or not the timestamp in
    sct\_or\_not\_before refers to a Signed Certificate Timestamp
-   sct\_or\_not\_before [ISO date]: The earliest [Signed Certificate
    Timestamp](https://www.google.com/url?q=https://tools.ietf.org/html/rfc6962%23section-3&sa=D&ust=1553612329811000),
    if one exists, otherwise equal to the not\_before timestamp
-   serial [string]: Unique identifier assigned to this certificate by
    the issuing Certificate Authority; see [RFC
    5280](https://www.google.com/url?q=https://tools.ietf.org/html/rfc5280%23section-4.1.2.2&sa=D&ust=1553612329811000) for
    details
-   subjects [list of strings]: List of hostnames/domains where this
    certificate can be used.  This field is a concatenated list of the
    Common Name (if it exists; this field is deprecated) and the
    [Subject Alternative
    Names](https://www.google.com/url?q=https://tools.ietf.org/html/rfc5280%23section-4.2.1.6&sa=D&ust=1553612329812000).
-   trimmed\_subjects [list of strings]: List of second-level domains
    where this certificate can be used.  These are extracted from the
    subjects field.

domains Collection {#h.qwt153c8i5hu .c20}
------------------

The data in this collection is derived from domains collected by our
[gatherer](https://www.google.com/url?q=https://github.com/dhs-ncats/gatherer&sa=D&ust=1553612329813000),
which pulls in domains from Cyber Hygiene and the GSA.  NOTE: More
details may be available in the GitHub
[README](https://www.google.com/url?q=https://github.com/dhs-ncats/cyhy-ct-logs/blob/initial/README.md&sa=D&ust=1553612329813000) documents
for
[gatherer](https://www.google.com/url?q=https://github.com/dhs-ncats/gatherer&sa=D&ust=1553612329814000) and
[saver](https://www.google.com/url?q=https://github.com/dhs-ncats/saver&sa=D&ust=1553612329814000).

-   \_id [string]: Base domain name
-   agency [dictionary]: The organization that claims ownership of the
    scanned domain

-   id [string]: Organization identifier
-   name [string]: Organization name

-   cyhy\_stakeholder [boolean]: Is the organization that claims to own
    this host a Cyber Hygiene stakeholder?
-   scan\_date [ISO date]: Timestamp when the domain was inserted in the
    database

https\_scan Collection {#h.7yzwy0vl6wdl .c20}
----------------------

The data in this collection is derived from domain names collected by
our
[gatherer](https://www.google.com/url?q=https://github.com/dhs-ncats/gatherer&sa=D&ust=1553612329816000),
which pulls in domains from Cyber Hygiene and the GSA.  NOTE: More
details may be available in the GitHub
[README](https://www.google.com/url?q=https://github.com/dhs-ncats/pshtt/blob/develop/README.md&sa=D&ust=1553612329816000) document
for
[pshtt](https://www.google.com/url?q=https://github.com/dhs-ncats/pshtt&sa=D&ust=1553612329817000).

-   \_id [string]: Internal database id of this HTTPS scan document
-   agency [dictionary]: The organization that claims ownership of the
    scanned domain

-   id [string]: Organization identifier
-   name [string]: Organization name

-   base\_domain [string]: Base domain that was HTTPS scanned
-   canonical\_url [string]: URL based on the observed redirect logic of
    the scanned domain
-   cyhy\_stakeholder [boolean]: Is the organization that claims to own
    this host a Cyber Hygiene stakeholder?
-   defaults\_https [boolean]: True if the canonical\_url uses HTTPS
-   domain [string]: The domain that was HTTPS scanned
-   domain\_enforces\_https [boolean]: Does the scanned domain both
    support HTTPS and default to HTTPS?
-   domain\_supports\_https [boolean]: True if:

-   downgrades\_https is False and valid\_https is True

OR

-   downgrades\_https is False and https\_bad\_chain is True and
    https\_bad\_hostname is False

-   domain\_uses\_strong\_hsts [boolean]: True if hsts is True for the
    scanned domain and hsts\_max\_age is at least 31,536,000 seconds
    (365 days)
-   downgrades\_https [boolean]: True if HTTPS is supported in some way,
    but the canonical HTTPS endpoint immediately redirects internally to
    HTTP
-   https\_bad\_chain [boolean]: True if either HTTPS endpoint
    (https://\<domain\>, https://www.\<domain\>) contains a bad chain
-   https\_bad\_hostname [boolean]: True if either HTTPS endpoint
    (https://\<domain\>, https://www.\<domain\>) fails hostname
    validation
-   https\_expired\_cert [boolean]: True if either HTTPS endpoint
    (https://\<domain\>, https://www.\<domain\>) has an expired
    certificate
-   https\_self\_signed\_cert [boolean]: True if either HTTPS endpoint
    (https://\<domain\>, https://www.\<domain\>) has a self-signed
    certificate
-   hsts [boolean]: True if the canonical\_url has
    [HSTS](https://www.google.com/url?q=https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security&sa=D&ust=1553612329822000) enabled
-   hsts\_base\_domain\_preloaded [boolean]: True if
    base\_domain appears in appears in the [Chrome preload
    list](https://www.google.com/url?q=https://chromium.googlesource.com/chromium/src/net/%2B/master/http/transport_security_state_static.json&sa=D&ust=1553612329823000) with
    the include\_subdomains flag equal to True
-   hsts\_entire\_domain [boolean]: True if the root HTTPS endpoint (not
    the canonical HTTPS endpoint) has HSTS enabled and uses the HSTS
    include\_subdomains flag
-   hsts\_header [string]: HSTS header at the canonical endpoint of the
    scanned domain
-   hsts\_max\_age [integer]: Max-age listed in the HSTS header at the
    canonical endpoint of the scanned domain
-   hsts\_preload\_pending [boolean]: True if the scanned domain appears
    in the [Chrome preload pending
    list](https://www.google.com/url?q=https://hstspreload.org/api/v2/pending&sa=D&ust=1553612329824000) with
    the include\_subdomains flag equal to True
-   hsts\_preload\_ready [boolean]: True if the root HTTPS endpoint (not
    the canonical HTTPS endpoint) has HSTS enabled, has a max-age of at
    least 18 weeks, and uses the include\_subdomains and preload flag.
-   hsts\_preloaded [boolean]: True if if the scanned domain appears in
    the [Chrome preload
    list](https://www.google.com/url?q=https://chromium.googlesource.com/chromium/src/net/%2B/master/http/transport_security_state_static.json&sa=D&ust=1553612329825000) 
    with the include\_subdomains flag equal to True, regardless of what
    header is present on any endpoint
-   is\_base\_domain [boolean]: True if domain is equal to base\_domain
-   latest [boolean]: Is this the latest HTTPS scan of this host?
-   live [boolean]: Are any of the endpoints (http://\<domain\>,
    http://www.\<domain\>, https://\<domain\>, https://www.\<domain\>)
    for this domain live?
-   redirect [boolean]: True if at least one endpoint is a redirect, and
    all endpoints are either redirects or down
-   redirect\_to [string]: URI that the scanned domain redirects to (if
    redirect is True)
-   scan\_date [ISO date]: Timestamp when the HTTPS scan was done
-   strictly\_forces\_https [boolean]: True if one of the HTTPS
    endpoints (https://\<domain\>, https://www.\<domain\>) is live, and
    if both HTTP endpoints (http://\<domain\>, http://www.\<domain\>)
    are either down or redirect immediately to any HTTPS URI
-   unknown\_error [boolean]: True if an unknown error occurred during
    the HTTPS scan
-   valid\_https [boolean]: True if the canonical\_url responds on port
    443 with an unexpired valid certificate for the hostname; can be
    True even if canonical\_url uses HTTP

precerts Collection {#h.e3bxszywt6cz .c20}
-------------------

The data in this collection is derived from certificates collected by
our [Certificate
Transparency](https://www.google.com/url?q=https://www.certificate-transparency.org/&sa=D&ust=1553612329828000) log
scanner, which only grabs certificates that apply to domains in our
[domains collection](#h.qwt153c8i5hu).  NOTE: More details may be
available in the GitHub
[README](https://www.google.com/url?q=https://github.com/dhs-ncats/cyhy-ct-logs/blob/initial/README.md&sa=D&ust=1553612329829000) document
for
[cyhy-ct-logs](https://www.google.com/url?q=https://github.com/dhs-ncats/cyhy-ct-logs&sa=D&ust=1553612329829000).

-   \_id [string]: Internal certificate identifier from the certificate
    transparency log where the certificate was detected
-   issuer [string]: The entity that signed and issued the certificate;
    see [RFC
    5280](https://www.google.com/url?q=https://tools.ietf.org/html/rfc5280%23section-4.1.2.4&sa=D&ust=1553612329830000) for
    details
-   not\_after [ISO date]: Timestamp when certificate expires
-   not\_before [ISO date]: Timestamp when certificate became/becomes
    valid
-   pem [string]: The certificate in [PEM
    format](https://www.google.com/url?q=https://tools.ietf.org/html/rfc1421&sa=D&ust=1553612329831000)
-   sct\_exists [boolean]: Whether or not the timestamp in
    sct\_or\_not\_before refers to the Signed Certificate Timestamp
-   sct\_or\_not\_before [ISO date]: The [Signed Certificate
    Timestamp](https://www.google.com/url?q=https://tools.ietf.org/html/rfc6962%23section-3&sa=D&ust=1553612329832000),
    if it exists, otherwise equal to the not\_before timestamp
-   serial [string]: Unique identifier assigned to this certificate by
    the issuing Certificate Authority; see [RFC
    5280](https://www.google.com/url?q=https://tools.ietf.org/html/rfc5280%23section-4.1.2.2&sa=D&ust=1553612329833000) for
    details
-   subjects [list of strings]: List of hostnames/domains where this
    certificate can be used.  This field is a concatenated list of  the
    Common Name (if it exists; this field is deprecated) and the
    [Subject Alternative
    Names](https://www.google.com/url?q=https://tools.ietf.org/html/rfc5280%23section-4.2.1.6&sa=D&ust=1553612329834000).
-   trimmed\_subjects [list of strings]: List of second-level domains
    where this certificate can be used.  These are extracted from the
    subjects field.

sslyze\_scan Collection {#h.jdvt2g4p7kc1 .c20}
-----------------------

The data in this collection is derived from domain names collected by
our
[gatherer](https://www.google.com/url?q=https://github.com/dhs-ncats/gatherer&sa=D&ust=1553612329835000),
which pulls in domains from Cyber Hygiene and the GSA.  NOTE: More
details may be available in the GitHub
[README](https://www.google.com/url?q=https://github.com/nabla-c0d3/sslyze/blob/master/README.md&sa=D&ust=1553612329835000) document
for
[SSLyze](https://www.google.com/url?q=https://github.com/nabla-c0d3/sslyze&sa=D&ust=1553612329836000).

-   \_id [string]: Internal database id of this SSLyze scan document
-   agency [dictionary]: The organization that claims ownership of the
    scanned domain

-   id [string]: Organization identifier
-   name [string]: Organization name

-   all\_forward\_secrecy [boolean]: True if every cipher supported by
    scanned\_hostname supports forward secrecy
-   all\_rc4 [boolean]: True if every cipher supported by
    scanned\_hostname supports RC4
-   any\_3des [boolean]: True if any cipher supported by
    scanned\_hostname supports 3DES
-   any\_forward\_secrecy [boolean]: True if any cipher supported by
    scanned\_hostname supports forward secrecy
-   any\_rc4 [boolean]: True if any cipher supported by
    scanned\_hostname supports RC4
-   base\_domain [string]: Base domain that was scanned by SSLyze
-   cyhy\_stakeholder [boolean]: Whether or not the organization that
    claims this host is a Cyber Hygiene stakeholder
-   domain [string]: The domain that was scanned by SSLyze
-   errors [string]: List of errors encountered when SSLyze scanned
    scanned\_hostname
-   highest\_constructed\_issuer [string]: Highest certificate issuer in
    the chain constructed when scanned\_hostname was scanned by SSLyze
-   highest\_served\_issuer [string]: Highest certificate issuer in the
    chain served when scanned\_hostname was scanned by SSLyze
-   is\_base\_domain [boolean]: True if domain is equal to base\_domain
-   is\_symantec\_cert [boolean]: True if certificate detected by SSLyze
    was issued by Symantec Corporation
-   key\_length [integer]: Public key length of certificate detected by
    SSLyze for scanned\_hostname
-   key\_type [string]: Public key type of certificate detected by
    SSLyze for scanned\_hostname
-   latest [boolean]: Is this the latest SSLyze scan of this host?
-   not\_after [ISO date]: Timestamp when certificate for
    scanned\_hostname expires
-   not\_before [ISO date]: Timestamp when certificate for
    scanned\_hostname became/becomes valid
-   scan\_date [ISO date]: Timestamp when the SSLyze scan was done
-   scanned\_hostname [string]: The hostname that was scanned by SSLyze
-   scanned\_port [integer]: The port number that was scanned by SSLyze
-   sha1\_in\_construsted\_chain [boolean]: True if any certificates in
    the chain constructed when scanned\_hostname was scanned by SSLyze
    support SHA-1
-   sha1\_in\_served\_chain [boolean]: True if any certificates in the
    chain served when scanned\_hostname was scanned by SSLyze support
    SHA-1
-   signature\_algorithm [string]: Signature algorithm of certificate
    detected by SSLyze for scanned\_hostname
-   symantec\_distrust\_date [string]: Month and year when certificates
    issued by Symantec Corporation will no longer be trusted
-   sslv2 [boolean]: True if SSLv2 is supported by scanned\_hostname
-   sslv3 [boolean]: True if SSLv3 is supported by scanned\_hostname
-   starttls\_smtp [boolean]: True if STARTTLS on SMTP is supported by
    scanned\_hostname
-   tlsv1\_0 [boolean]: True if TLS 1.0 is supported by
    scanned\_hostname
-   tlsv1\_1 [boolean]: True if TLS 1.1 is supported by
    scanned\_hostname
-   tlsv1\_2 [boolean]: True if TLS 1.2 is supported by
    scanned\_hostname

trustymail Collection {#h.yqcj55euwwjs .c20}
---------------------

The data in this collection is derived from domain names collected by
our
[gatherer](https://www.google.com/url?q=https://github.com/dhs-ncats/gatherer&sa=D&ust=1553612329845000),
which pulls in domains from Cyber Hygiene and the GSA.  NOTE: More
details may be available in the GitHub
[README](https://www.google.com/url?q=https://github.com/dhs-ncats/trustymail/blob/develop/README.md&sa=D&ust=1553612329846000) document
for
[trustymail](https://www.google.com/url?q=https://github.com/dhs-ncats/trustymail&sa=D&ust=1553612329846000).

-   \_id [string]: Internal database id of this Trustymail scan document
-   agency [dictionary]: The organization that claims ownership of the
    scanned domain

-   id [string]: Organization identifier
-   name [string]: Organization name

-   aggregate\_report\_uris [list of dictionaries]: List of DMARC
    aggregate report URIs specified by the scanned domain

-   modifier [string]: DMARC aggregate report URI modifier
-   uri [string]: DMARC aggregate report URI

-   base\_domain [string]: Base domain that was scanned by Trustymail
-   debug\_info [string]: List of warnings or errors reported by
    Trustymail while scanning the domain
-   dmarc\_policy [string]: Applicable DMARC policy for the scanned
    domain, based on policies found in dmarc\_results and
    dmarc\_results\_base\_domain
-   dmarc\_policy\_percentage [integer]: Percentage of mail that should
    be subjected to the dmarc\_policy according to dmarc\_results
-   dmarc\_record [boolean]: True if a DMARC record was found for the
    scanned domain
-   dmarc\_record\_base\_domain [boolean]: True if a DMARC record was
    found for base\_domain
-   dmarc\_results [string]: DMARC record that was discovered when
    querying DNS for the scanned domain
-   dmarc\_results\_base\_domain [string]: DMARC record that was
    discovered when querying DNS for base\_domain
-   domain [string]: The domain that was scanned by Trustymail
-   domain\_supports\_smtp [boolean]: True if any mail servers specified
    in an MX record associated with the scanned domain support SMTP
-   domain\_supports\_smtp\_results [string]: List of mail server and
    port combinations from the scanned domain that support SMTP
-   domain\_supports\_starttls [boolean]: True if all mail servers
    associated with the scanned domain that support SMTP also support
    STARTTLS
-   domain\_supports\_starttls\_results [string]: List of mail server
    and port combinations from the scanned domain that support STARTTLS
-   forensic\_report\_uris [list of dictionaries]: List of DMARC
    forensic report URIs specified by the scanned domain

-   modifier [string]: DMARC forensic report URI modifier
-   uri [string]: DMARC forensic report URI

-   has\_aggregate\_report\_uri [boolean]: True if
    dmarc\_results include valid rua URIs that tell recipients where to
    send DMARC aggregate reports.
-   has\_forensic\_report\_uri [boolean]: True if dmarc\_results include
    valid ruf URIs that tell recipients where to send DMARC forensic
    reports.
-   is\_base\_domain [boolean]: True if domain is equal to base\_domain
-   latest [boolean]: Is this the latest Trustymail scan of this host?
-   live [boolean]: True if the scanned domain is published in public
    DNS
-   mail\_server\_ports\_tested [string]: List of ports tested by
    Trustymail for SMTP and STARTTLS support
-   mail\_servers [string]: List of hosts found in the MX record of the
    scanned domain
-   mx\_record [boolean]: True if an MX record for the scanned domain
    was found that contains one or more mail servers
-   scan\_date [ISO date]: Timestamp when the Trustymail scan was done
-   spf\_results [string]: Text representation of any SPF record found
    for the scanned domain
-   syntax\_errors [string]: List of syntax errors encountered when
    Trustymail analyzed SPF records of the scanned domain
-   valid\_dmarc [boolean]: True if the DMARC record found for the
    scanned domain is syntactically correct
-   valid\_dmarc\_base\_domain [boolean]: True if the DMARC record found
    for base\_domain is syntactically correct
-   valid\_spf [boolean]: True if the SPF record found for the scanned
    domain is syntactically correct, per [RFC
    4408](https://www.google.com/url?q=https://www.ietf.org/rfc/rfc4408.txt&sa=D&ust=1553612329855000)

assessment Database: {#h.1xhfi3sik1o7 .c23}
====================

rva Collection {#h.4ixfrma0cnea .c20}
--------------

-   Summary = Assessment Summary (ASMT\_ID / ASMT\_NAME)
-   Status = Assessment Status (Open -\> Planning -\> Testing -\>
    Reporting -\> Wrap Up -\> Completed)
-   Created = Date ticket was created
-   Updated = Last update date
-   App A Date = Date Appendix A was signed
-   App A Signed = Was appendix A signed? (Boolean)
-   App B Signed = Date Appendix B was signed, if applicable
-   Asmt Type = Assessment Type (RVA, HVA, RPT, PCA, VADR)
-   External Testing Begin = Date of beginning of external testing
-   External Testing End = Date of end of external testing
-   Group/Project = Group or Project
-   Internal Testing Begin = Date of beginning of internal testing
-   Internal City = Location (City) of on-site testing if applicable
-   Internal Testing End = Date of end of internal testing
-   Mgmt Req = Management Request (DHS, NCCIC, EOP, FALSE)
-   POC Email = POC E-mail address
-   POC Name = POC Name
-   POC Phone = POC Phone Number
-   ROE Date = Date ROE is signed
-   ROE Number = ROE Number (assigned by NCATS)
-   ROE Signed = ROE Signed (Boolean)
-   \_ID = Assessment ID (RV0XXX for RVA/HVA/PCA or VR0XXX for VADR)
-   Asmt Name = Assessment Name (Usually customer name and assessment
    type)
-   Requested Svcs = Array containing list of NCATS services requested
    for this engagement (List of Services here)
-   Stakeholder Name = Stakeholder Name
-   State = State where stakeholder is located
-   Testing Complete Date = Date on which all testing is completed
-   Testing Phase = Phase of Testing (External / Internal)
-   Election = Elections Related (Boolean)
-   Sector = Fed/State/Local/Tribal/Territorial/Critical Infrastructure
-   CI Type = Critical Infrastructure Type (Selected from among 16 CI
    Sectors)
-   CI Systems = If any subsystems assessed belong to a different
    critical infrastructure category from the CI\_TYPE field, it will be
    listed here in an array (For example, Hoover Dam would be CI\_WATER
    for CI\_TYPE, but would have CI\_SYSTEMS=CI\_ENERGY for electric)
-   Fed Lead = Federal Team Lead assigned to the assessment
-   Contractor Count = Number of contractors assigned
-   Draft w/ POC Date = Date when draft report is sent to the customer
-   Fed Count = Number of Federal operators assigned
-   Report Final Date = Date when report is marked Final
-   Operator = Name of the Operator (Contractor or Fed)
-   Stakeholder Id = TBD
-   Testing Begin Date = Date when all testing begins

findings Collection {#h.lt8ipmvo5woa .c20}
-------------------

-    \_id: Unique key for DB to identify individual finding
-   Custom Finding Name: Custom name for finding identified by Fed Team
    Lead, if applicable
-   Severity: Ranking of severity assigned by Fed Team Lead. Severity
    can vary depending on importance of the system, or other
    environmental factors [Low, Medium, High, Critical]
-   Service: RVA service during which finding was identified
-   FY: Fiscal Year during which testing was conducted. Due to
    ever-changing cybersecurity landscape, more current data is
    recommended when conducting analysis
-   Assessment Type: Type of Assessment [RVA, HVA, RPT]
-   NCATS ID: Standard number assigned by NCATS to the Finding Name
-   FED/SLTT/CI: Customer Sector
-   Mitigated Finding Status: Mitigation status as reported by customer
    during 180-day mitigation survey. Note-survey is optional and
    self-reported, no validation performed by NCATS that mitigations
    were performed as stated. Please be careful using this metric.
-   RVA ID: Assessment ID during which finding was identified. Note -
    this number identifies the customer when paired with information
    from Assessments collection. This number is provided with Findings
    info to identify unique assessments.
-   Name: Name of Finding
-   Man/Tool: Was the finding identified manually or with a tool (Burp
    Suite, Cobalt Strike, Nessus, etc.) Tool will not be identified
-   Int/Ext: Was the finding identified during Internal or External
    testing?^[[a]](#cmnt1)^
-   Std Text Modify: Was there a custom Finding name provided?
-   Mitigate Finding Response Date: Date on which customer responded
    with Mitigation data
-   Default Finding Severity: Default level of severity for this type of
    finding. Please see notes in Severity for more info on how Fed Team
    Leads assign severity ratings.
-   CI Subtype: Identifies which of 16 Critical Infrastructure sectors
    customer belongs to, if any
-   NIST 800-53 [array]: This array will list which controls in NIST
    800-53 are applicable to the finding identified. As NIST 800-53 is a
    Federal standard, this is more applicable for Federal customers
-   NCSF [array]: This array will list which controls in the NICE
    Cybersecurity Framework are applicable to the finding identified.
    This is a more universal standard than NIST 800-53
