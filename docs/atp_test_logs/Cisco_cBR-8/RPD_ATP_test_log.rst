Remote PHY ATP Test Process - OpenRPD Compliance

CCAP: Cisco c-BR8, software release:

==============================================================================
Change Log: Identify build and source for ATP results
+============================================================================+
| OpenRPD Build Version                                     | ATP Run Date   |
+============================================================================+
|   Build # xxxx - created Feb x, 2018                      | Feb x, 2018    |
|   Git Hash - 123412341234not_a_real_hash1234123412341     |                |
|   Notes - Tests run during _not_a_real_note_ and so on.   |                |
+-----------------------------------------------------------+----------------+
+============================================================================+


==============================================================================

Test Results Format (Example) :

The test procedures listed in the table below are often composed of multiple
steps, each of which have their own result.  We've chosen to encode those
detailed results in the following form:

+-----------------------------------------------------------+----------------+
| Description                                               | Result         |
+-----------------------------------------------------------+----------------+
| Procedure 1.foo: Determine blah, blah, blah...            | wP-xF-yS-zB    |
+-----------------------------------------------------------+----------------+

where P, F, S, & B are "Pass", "Fail", "Skipped", and "Blocked" respectively
and w, x, y, & z are integer counts for each of the above categories

These 4 result values are determined by the Automated ATP test runner app.

==============================================================================


Initialization ATP

Part 1: Network Authentication

+-----------------------------------------------------------+----------------+
| Description                                               | Result         |
+-----------------------------------------------------------+----------------+
| Procedure 1.1: Determine if RPD Requires Network          |                |
| Authentication and Uses EAP-TLS                           |                |
+-----------------------------------------------------------+----------------+
| Procedure 1.2: Determine if RPD Requires Network          |                |
| Authentication and Uses MKA                               |                |
+-----------------------------------------------------------+----------------+
| Procedure 1.3: RPD Network Authentication                 |                |
| via IEEE 802.1x                                           |                |
+-----------------------------------------------------------+----------------+

Part 2: DHCP and ToD Initialization

+-----------------------------------------------------------+----------------+
| Description                                               | Result         |
+-----------------------------------------------------------+----------------+
| Procedure 2.1: RPD IPv4 Address Acquisition               |                |
+-----------------------------------------------------------+----------------+
| Procedure 2.2: RPD IPv4 Address Acquisition - No DHCP     |                |
| OFFER from Server                                         |                |
+-----------------------------------------------------------+----------------+
| Procedure 2.3: RPD IPv4 Address Acquisition - No DHCP     |                |
| ACK from Server                                           |                |
+-----------------------------------------------------------+----------------+
| Procedure 2.4: RPD IPv4 Address Acquisition - Required    |                |
| Fields Missing                                            |                |
+-----------------------------------------------------------+----------------+
| Procedure 2.5: RPD IPv4 Address Acquisition - Time of     |                |
| Day Server Fault                                          |                |
+-----------------------------------------------------------+----------------+
| Procedure 2.6: RPD IPv4 Address Acquisition - Time of     |                |
| Day Response Invalid                                      |                |
+-----------------------------------------------------------+----------------+
| Procedure 2.7: RPD IPv4 Address Acquisition - Lease       |                |
| Renewal                                                   |                |
+-----------------------------------------------------------+----------------+
| Procedure 2.8: RPD IPv6 Address Acquisition - RFCs        |                |
+-----------------------------------------------------------+----------------+
| Procedure 2.9: RPD IPv6 Address Acquisition - DHCPv6      |                |
| Solicit Retries                                           |                |
+-----------------------------------------------------------+----------------+
| Procedure 2.10: RPD IPv6 Address Acquisition - Missing    |                |
| Options in DHCPv6 Advertise and Reply                     |                |
+-----------------------------------------------------------+----------------+
| Procedure 2.11: RPD IPv6 Address Acquisition - Time of    |                |
| Day Acquisition Retries                                   |                |
+-----------------------------------------------------------+----------------+
| Procedure 2.12: RPD IPv6 Address Acquisition - Renewal    |                |
| and Rebind Using T1 and T2 Timers                         |                |
+-----------------------------------------------------------+----------------+
| Procedure 2.13: RPD IPv6 Address Acquisition - Duplicate  |                |
| Link-Local Address Handling                               |                |
+-----------------------------------------------------------+----------------+
| Procedure 2.14: RPD IPv6 Address Acquisition - Duplicate  |                |
| RPD Management Address Handling                           |                |
+-----------------------------------------------------------+----------------+

Part 3: Mutual Authentication

+-----------------------------------------------------------+----------------+
| Procedure 3.1: Establishment of a mutual authenticated    |                |
| secure connection between the RPD and Core                |                |
+-----------------------------------------------------------+----------------+

Part 4: GCP Configuration

+-----------------------------------------------------------+----------------+
| Description                                               | Result         |
+-----------------------------------------------------------+----------------+
| Procedure 4.1: RPD Establishes GCP Connection with        |                |
| Auxiliary CCAP Core as First Core in List                 |                |
+-----------------------------------------------------------+----------------+
| Procedure 4.2: RPD Establishes GCP Connection with Active |                |
| Principal Core Identifies Itself and Responds to          |                |
| Capabilities Request from Core                            |                |
+-----------------------------------------------------------+----------------+
| Procedure 4.3: RPD Establishes GCP Connection with        |                |
| Auxiliary CCAP Core and Responds to Capabilities Request  |                |
| from Core after Completing Configuration with Principal   |                |
| Core                                                      |                |
+-----------------------------------------------------------+----------------+
| Procedure 4.4: RPD Establishes GCP Connection with        |                |
| Principal CCAP Core Operating in Active Mode as           |                |
| Additional Principal Core after Completing Configuration  |                |
| with Principal Core                                       |                |
+-----------------------------------------------------------+----------------+
| Procedure 4.5: RPD Establishes GCP Connection with        |                |
| Principal or Auxiliary CCAP Core Operating in Standby     |                |
| Mode after Completing Configuration with Principal Core   |                |
+-----------------------------------------------------------+----------------+
| Procedure 4.6: RPD Establishes GCP Connection with        |                |
| Auxiliary Core Not Operating as Active or Backup Core     |                |
| after Completing Configuration with Principal Core        |                |
+-----------------------------------------------------------+----------------+
| Procedure 4.7: RPD Establishes GCP Connection with        |                |
| Principal Core Containing Redirect Information and        |                |
| Establishes Connection with New Principal CCAP Core       |                |
+-----------------------------------------------------------+----------------+
| Procedure 4.8: RPD Established GCP Connection with        |                |
| Principal Core then CCAP Core Commands the RPD to         |                |
| Perform SW Upgrade                                        |                |
+-----------------------------------------------------------+----------------+
| Procedure 4.9: RPD Establishes GCP Connection with        |                |
| Auxiliary CCAP Core and Responds to REX REQ Messages      |                |
| Containing Write Operations to Elements Core Doesn't Own  |                |
| After Completing Configuration with Principal Core        |                |
+-----------------------------------------------------------+----------------+
| Procedure 4.10: RPD Establishes GCP Connection with       |                |
| Auxiliary CCAP Core and Responds to REX REQ Messages      |                |
| Containing AllocateWrite Operations to ResourceSet        |                |
| Table Allocated by Principal Core                         |                |
+-----------------------------------------------------------+----------------+
| Procedure 4.11: RPD Attempts to Establish GCP             |                |
| Connection with CCAP Core and IRA Fails                   |                |
+-----------------------------------------------------------+----------------+
| Procedure 4.12: RPD Attempts to Establish GCP             |                |
| Connection with CCAP Core Configuration REX Fails         |                |
+-----------------------------------------------------------+----------------+
| Procedure 4.13: RPD Attempts to Establish GCP Connection  |                |
| with Standby Principal CCAP Cores Listed as First         |                |
+-----------------------------------------------------------+----------------+
| Procedure 4.14: RPD Attempts to Establish GCP Connection  |                |
| with Active Principal CCAP Cores which Doesn't Send       |                |
| MoveToOperational TLV                                     |                |
+-----------------------------------------------------------+----------------+
| Procedure 4.15: RPD Attempts to Establish GCP Connection  |                |
| with PTP Fails                                            |                |
+-----------------------------------------------------------+----------------+
| Procedure 4.16: RPD Attempts to Establish GCP Connection  |                |
| with CCAP Core GCP Fails                                  |                |
+-----------------------------------------------------------+----------------+
| Procedure 4.17: RPD Startup Configuration and Messaging   |                |
+-----------------------------------------------------------+----------------+
| Procedure 4.18: RPD Response to Unsupported GCP Messages  |                |
+-----------------------------------------------------------+----------------+
| Procedure 4.19: GCP RCP TLVs                              |                |
+-----------------------------------------------------------+----------------+
| Procedure 4.20: GCP Keep Alive Transmission Interval      |                |
| And Response Window                                       |                |
+-----------------------------------------------------------+----------------+
| Procedure 4.21: RPD Attempts to Establish GCP Connection  |                |
| with CCAP Core Keep Alive Fails after Completing          |                |
| Configuration with Principal Core                         |                |
+-----------------------------------------------------------+----------------+

Part 5: Time Synchronization of RPD and CCAP Core with GM

+-----------------------------------------------------------+----------------+
| Description                                               | Result         |
+-----------------------------------------------------------+----------------+
| Procedure 5.1: PTP NODE_SLAVE Mode for CCAP Core and RPD  |                |
+-----------------------------------------------------------+----------------+
| Procedure 5.2: Checking PTP Time/Phase Synchronization    |                |
| Accuracy                                                  |                |
+-----------------------------------------------------------+----------------+

Part 6: R-DEPI Initialization

+-----------------------------------------------------------+----------------+
| Description                                               | Result         |
+-----------------------------------------------------------+----------------+
| Procedure 6.1: TLV Based Verification of RPD              |                |
| Capabilities, Mode Support etc.                           |                |
+-----------------------------------------------------------+----------------+
| Procedure 6.2: Verifying Ethernet 802.3, 802.1Q, IPv4     |                |
| Headers for CCAP Core and RPD                             |                |
+-----------------------------------------------------------+----------------+
| Procedure 6.3: Verifying IPv6 Headers between CCAP        |                |
| Core and RPD                                              |                |
+-----------------------------------------------------------+----------------+
| Procedure 6.4: Verifying L2TPv3 Ctrl Messages - Ctrl      |                |
| Connection for pair of LCCE entities                      |                |
+-----------------------------------------------------------+----------------+
| Procedure 6.5: L2TPv3 unicast R-DEPI Sessions between     |                |
| CCAP Core and RPD                                         |                |
+-----------------------------------------------------------+----------------+
| Procedure 6.6: L2TPv3 DSCP Policy between CCAP Core       |                |
| and RPD                                                   |                |
+-----------------------------------------------------------+----------------+
| Procedure 6.7: Verifying Mandatory AVPs in L2TPv3         |                |
| Ctrl Plane between LCCE Entities                          |                |
+-----------------------------------------------------------+----------------+
| Procedure 6.8: R-DEPI Data Forwarding Plane R-DEPI        |                |
| MPT Sublayer                                              |                |
+-----------------------------------------------------------+----------------+
| Procedure 6.9: R-DEPI Data Forwarding Plane R- DEPI       |                |
| PSP Sublayer                                              |                |
+-----------------------------------------------------------+----------------+

Part 7: R-UEPI Initialization

+-----------------------------------------------------------+----------------+
| Description                                               | Result         |
+-----------------------------------------------------------+----------------+
| Procedure 7.1: The R-UEPI L2TPv3 Ethernet 802.3 and       |                |
| IPv4 Headers                                              |                |
+-----------------------------------------------------------+----------------+
| Procedure 7.2: The R-UEPI L2TPv3 Ethernet 802.3 and       |                |
| IPv6 Headers                                              |                |
+-----------------------------------------------------------+----------------+
| Procedure 7.3: R-UEPI L2TPv3 IPv4 and IPv6 DSCP           |                |
| Field Verification                                        |                |
+-----------------------------------------------------------+----------------+
| Procedure 7.4: PSP SC-QAM RNG-REQ R-UEPI Pseudowire       |                |
| Packet                                                    |                |
+-----------------------------------------------------------+----------------+
| Procedure 7.5: SC-QAM RNG-REQ R-UEPI PW Contains          |                |
| Only IUC3 and IUC4 Bursts                                 |                |
+-----------------------------------------------------------+----------------+
| Procedure 7.6: SC-QAM Data R-UEPI PW Does Not Contain     |                |
| IUC3 & IUC4 Bursts                                        |                |
+-----------------------------------------------------------+----------------+
| Procedure 7.7: R-UEPI PSP SC-QAM MAP Pseudowire Packet    |                |
+-----------------------------------------------------------+----------------+

Service ATP

Part 1: Time Synchronization

+-----------------------------------------------------------+----------------+
| Description                                               | Result         |
+-----------------------------------------------------------+----------------+
| Procedure 1.1: M/N Locking for DTI/CCAP Master Clock      |                |
| and RPD/CCAP Symbol Clock                                 |                |
+-----------------------------------------------------------+----------------+
| Procedure 1.2: RPD Local Timestamp Derived From PTP       |                |
| Timestamp and Applied to Both Downstream and Upstream PHY |                |
+-----------------------------------------------------------+----------------+
| Procedure 1.3: DOCSIS Time Synchronization MAC Message    |                |
| from CCAP Core to RPD                                     |                |
+-----------------------------------------------------------+----------------+
| Procedure 1.4: DOCSIS Time Synchronization MAC Message    |                |
| from RPD to CM                                            |                |
+-----------------------------------------------------------+----------------+

Part 2: DEPI Data Forwarding

+-----------------------------------------------------------+----------------+
| Description                                               | Result         |
+-----------------------------------------------------------+----------------+
| Procedure 2.1: TLV Based Verification of RPD              |                |
| Capabilities, Mode Support Etc.                           |                |
+-----------------------------------------------------------+----------------+
| Procedure 2.4: Verifying L2TPv3 unicast DEPI Session      |                |
| Information  between CCAP Core and RPD                    |                |
+-----------------------------------------------------------+----------------+
| Procedure 2.9: DEPI Latency Measurement (DLM) Sublayer    |                |
| Header                                                    |                |
+-----------------------------------------------------------+----------------+
| Procedure 2.11: DOCSIS Time Synchronization MAC Message   |                |
| from CCAP Core                                            |                |
+-----------------------------------------------------------+----------------+
| Procedure 2.12: DOCSIS Time Synchronization MAC Message   |                |
| from RPD                                                  |                |
+-----------------------------------------------------------+----------------+
| Procedure 2.13: RPD Synchronous Mode Packet Loss          |                |
| Compensation                                              |                |
+-----------------------------------------------------------+----------------+
| Procedure 2.14: Latency and Skew Measurement of RPD       |                |
+-----------------------------------------------------------+----------------+
| Procedure 2.15: CW Tones                                  |                |
+-----------------------------------------------------------+----------------+

Part 3: UEPI Data Forwarding

+-----------------------------------------------------------+----------------+
| Description                                               | Result         |
+-----------------------------------------------------------+----------------+
| Procedure 3.1: Ethernet MTU                               |                |
+-----------------------------------------------------------+----------------+
| Procedure 3.2: PSP OFDMA Data Pseudowire Packet           |                |
+-----------------------------------------------------------+----------------+
| Procedure 3.3: OFDMA Data PW Contains Only Bursts from    |                |
| that US Channel                                           |                |
+-----------------------------------------------------------+----------------+
| Procedure 3.4: OFDMA Data PW Supports PSP Fragmentation   |                |
+-----------------------------------------------------------+----------------+
| Procedure 3.5: OFDMA Data PW Supports PSP Concatenation   |                |
+-----------------------------------------------------------+----------------+
| Procedure 3.6: PSP OFDMA RNG-REQ Pseudowire Packet        |                |
+-----------------------------------------------------------+----------------+
| Procedure 3.7: OFDMA RNG-REQ PW Contains Only IUC3 &      |                |
| IUC4 Bursts                                               |                |
+-----------------------------------------------------------+----------------+
| Procedure 3.8: OFDMA Data PW Does Not Contain IUC3 &      |                |
| IUC4 Bursts                                               |                |
+-----------------------------------------------------------+----------------+
| Procedure 3.9: PSP OFDMA BW-REQ Pseudowire Packet         |                |
+-----------------------------------------------------------+----------------+
| Procedure 3.10: OFDMA BW-REQ PW Standalone and            |                |
| Piggyback Requests                                        |                |
+-----------------------------------------------------------+----------------+
| Procedure 3.11: PSP OFDMA MAP Pseudowire Packet           |                |
+-----------------------------------------------------------+----------------+
| Procedure 3.12: PSP OFDMA Probe Pseudowire Packet         |                |
+-----------------------------------------------------------+----------------+
| Procedure 3.13: OFDMA Probe PW Supports Fragmentation -   |                |
| Not Concatenation                                         |                |
+-----------------------------------------------------------+----------------+
| Procedure 3.14: OFDMA Probe Equalizer Coefficient Sets    |                |
+-----------------------------------------------------------+----------------+
| Procedure 3.15: PSP SC-QAM Data Pseudowire Packet         |                |
+-----------------------------------------------------------+----------------+
| Procedure 3.16: SC-QAM Data PW Contains Only Bursts       |                |
| from that US Channel                                      |                |
+-----------------------------------------------------------+----------------+
| Procedure 3.17: SC-QAM Data PW Supports PSP Fragmentation |                |
+-----------------------------------------------------------+----------------+
| Procedure 3.18: SC-QAM Data PW Does Not Support PSP       |                |
| Concatenation                                             |                |
+-----------------------------------------------------------+----------------+
| Procedure 3.19: PSP SC-QAM RNG-REQ Pseudowire Packet      |                |
+-----------------------------------------------------------+----------------+
| Procedure 3.20: SC-QAM RNG-REQ PW Contains Only IUC3 &    |                |
| IUC4 Bursts                                               |                |
+-----------------------------------------------------------+----------------+
| Procedure 3.21: SC-QAM Data PW Does Not Contain IUC3 &    |                |
| IUC4 Bursts                                               |                |
+-----------------------------------------------------------+----------------+
| Procedure 3.22: PSP SC-QAM BW-REQ Pseudowire Packet       |                |
+-----------------------------------------------------------+----------------+
| Procedure 3.23: SC-QAM BW-REQ PW Standalone and           |                |
| Piggyback Requests                                        |                |
+-----------------------------------------------------------+----------------+
| Procedure 3.24: PSP SC-QAM MAP Pseudowire Packet          |                |
+-----------------------------------------------------------+----------------+
| Procedure 3.25: QOS Support on OFDMA Data PW with 4 Flows |                |
+-----------------------------------------------------------+----------------+
| Procedure 3.26: QOS Support on SC-QAM Data PW with        |                |
| 4 Flows                                                   |                |
+-----------------------------------------------------------+----------------+
| Procedure 3.27: QOS Mapping to any Valid Value of the     |                |
| Appropriate QOS Header                                    |                |
+-----------------------------------------------------------+----------------+
| Procedure 3.28: Sequence Numbers Used to Report Dropped   |                |
| or Misordered Pkts                                        |                |
+-----------------------------------------------------------+----------------+
| Procedure 3.29: No Burst Event Scenario - Event is        |                |
| Counted                                                   |                |
+-----------------------------------------------------------+----------------+
| Procedure 3.30: No Burst Event Scenario - Message Sent    |                |
| to CCAP Core                                              |                |
+-----------------------------------------------------------+----------------+
| Procedure 3.31: UEPI Request Block Aggregation            |                |
| Enforcement                                               |                |
+-----------------------------------------------------------+----------------+
| Procedure 3.32: OFDMA Bandwidth Request Aggregation       |                |
| Attributes                                                |                |
+-----------------------------------------------------------+----------------+
| Procedure 3.33: SC-QAM BW Request Aggregation Attributes  |                |
| - RPD Granularity                                         |                |
+-----------------------------------------------------------+----------------+
| Procedure 3.34:  OFDMA BW Request Aggregation Attributes  |                |
| - RPD Granularity                                         |                |
+-----------------------------------------------------------+----------------+

Part 4: Out-Of-Band Signalling

+-----------------------------------------------------------+----------------+
| Description                                               | Result         |
+-----------------------------------------------------------+----------------+
| Procedure 4.1:  R-OOB SCTE 55-1 Frequency, Power and      |                |
| Fidelity                                                  |                |
+-----------------------------------------------------------+----------------+
| Procedure 4.2: OOB RPD SCTE 55-1 Downstream Modulator     |                |
| Functionality                                             |                |
+-----------------------------------------------------------+----------------+
| Procedure 4.3: R-OOB SCTE 55-1 Burst Receiver and Virtual |                |
| ARPD Functionality                                        |                |
+-----------------------------------------------------------+----------------+

Part 5: GCP Connection Faults

+-----------------------------------------------------------+----------------+
| Description                                               | Result         |
+-----------------------------------------------------------+----------------+
| Procedure 5.1: GCP Connection Monitoring                  |                |
+-----------------------------------------------------------+----------------+

OSSI ATP

2    CCAP Core Test cases (ROSS)

3    RPD Test CASES (ROSS)

3.1  RPD Secure Software Download (ROSS-100)

+-----------------------------------------------------------+----------------+
| Description                                               | Result         |
+-----------------------------------------------------------+----------------+
| TC-56 (ROSS-100) Procedure 1: GCP RPD Secure              |                |
| Software Download                                         |                |
+-----------------------------------------------------------+----------------+
| TC-57 (ROSS-100) Procedure 2: Software Image Rejected     |                |
+-----------------------------------------------------------+----------------+
| TC-58 (ROSS-100) Procedure 3: Manufacturer CVC Rejected   |                |
+-----------------------------------------------------------+----------------+
| TC-59 (ROSS-100) Procedure 4: Co-Signer CVC Rejected      |                |
+-----------------------------------------------------------+----------------+

3.2  RPD Capabilities Reporting (ROSS-101)

+-----------------------------------------------------------+----------------+
| Description                                               | Result         |
+-----------------------------------------------------------+----------------+
| TC-60 (ROSS-101) Procedure 1: RPD Identification          |                |
+-----------------------------------------------------------+----------------+
| TC-61 (ROSS-101) Procedure 2: RPD Capabilities            |                |
+-----------------------------------------------------------+----------------+
| TC-62 (ROSS-101) Procedure 3: RPD Entity Reporting        |                |
+-----------------------------------------------------------+----------------+
| TC-102 (ROSS-101) Procedure 4: RPD Interface Mapping      |                |
| Tables                                                    |                |
+-----------------------------------------------------------+----------------+

3.3  RPD Event Reporting (ROSS-102)

Part 1. Event Reporting Control

+-----------------------------------------------------------+----------------+
| Description                                               | Result         |
+-----------------------------------------------------------+----------------+
| TC-63 (ROSS-102) Procedure 1.1: Configuration of Event    |                |
| Reporting for Priority: Critical                          |                |
+-----------------------------------------------------------+----------------+
| TC-64 (ROSS-102) Procedure 1.2: Configuration of Event    |                |
| Reporting for Priority: Error                             |                |
+-----------------------------------------------------------+----------------+
| TC-65 (ROSS-102) Procedure 1.3: Configuration of Event    |                |
| Reporting for Priority: Notice                            |                |
+-----------------------------------------------------------+----------------+
| TC-66 (ROSS-102) Procedure 1.4: Group configuration       |                |
| object DefaultRpdEvReportingCfg                           |                |
+-----------------------------------------------------------+----------------+
| TC-67 (ROSS-102) Procedure 1.5: RPD Log Persistence and   |                |
| Minimum Log Size                                          |                |
+-----------------------------------------------------------+----------------+
| TC-68 (ROSS-102) Procedure 1.6: RPD Pending Event Report  |                |
| Queue                                                     |                |
+-----------------------------------------------------------+----------------+

Part 2. Event Framework

+-----------------------------------------------------------+----------------+
| Description                                               | Result         |
+-----------------------------------------------------------+----------------+
| TC-69 (ROSS-102) Procedure 2.1: Local Log, GCP            |                |
| Notification Event Reporting                              |                |
+-----------------------------------------------------------+----------------+
| TC-70 (ROSS-102) Procedure 2.2: Disable GCP Notifications |                |
+-----------------------------------------------------------+----------------+
| TC-71 (ROSS-102) Procedure 2.3: linkDown/linkUp           |                |
| Notification                                              |                |
+-----------------------------------------------------------+----------------+

Part 3. Event Throttling, Limiting and Inhibiting

+-----------------------------------------------------------+----------------+
| Description                                               | Result         |
+-----------------------------------------------------------+----------------+
| TC-72 (ROSS-102) Procedure 3.1: Event Throttling          |                |
+-----------------------------------------------------------+----------------+
| TC-73 (ROSS-102) Procedure 3.2: Event Limiting            |                |
+-----------------------------------------------------------+----------------+
| TC-74 (ROSS-102) Procedure 3.3: Event Inhibiting and      |                |
| Events Unconstrained                                      |                |
+-----------------------------------------------------------+----------------+
| TC-75 (ROSS-102) Procedure 3.4: Group Configuration       |                |
| Object DefaultRpdEvThrottleCfg                            |                |
+-----------------------------------------------------------+----------------+

3.4  RPD Operational Status Reporting (ROSS-103)

Part 1. RPD Location Provisioning and Reporting

+-----------------------------------------------------------+----------------+
| Description                                               | Result         |
+-----------------------------------------------------------+----------------+
| TC-76 (ROSS-103) Procedure 1.1: Location                  |                |
| Provisioned Manually via CLI                              |                |
+-----------------------------------------------------------+----------------+
| TC-77 (ROSS-103) Procedure 1.2: Location Provisioned by   |                |
| Integrated GPS                                            |                |
+-----------------------------------------------------------+----------------+
| TC-78 (ROSS-103) Procedure 1.3: Location Provisioned via  |                |
| SNMP/GCP                                                  |                |
+-----------------------------------------------------------+----------------+

Part 2. RPD Cores Connected

+-----------------------------------------------------------+----------------+
| Principal CCAP Core Only                                  |                |
+-----------------------------------------------------------+----------------+
| TC-80 (ROSS-103) Procedure 2.2: RPD Connected to          |                |
| Principal CCAP Core and One Auxiliary CCAP Core           |                |
+-----------------------------------------------------------+----------------+
| TC-81 (ROSS-103) Procedure 2.3: RPD Connected to          |                |
| Principal CCAP Core and Two or More Auxiliary CCAP Cores  |                |
+-----------------------------------------------------------+----------------+

Part 3. RPD Host Resources Reporting

+-----------------------------------------------------------+----------------+
| Description                                               | Result         |
+-----------------------------------------------------------+----------------+
| TC-82 (ROSS-103) Procedure 3.1: Host Resources Reporting  |                |
+-----------------------------------------------------------+----------------+

3.5  RPD Troubleshooting Capabilities (ROSS-104)

+-----------------------------------------------------------+----------------+
| Description                                               | Result         |
+-----------------------------------------------------------+----------------+
| TC-83 (ROSS-104) Procedure 1: RPD Crash File Analysis     |                |
+-----------------------------------------------------------+----------------+
| TC-84 (ROSS-104) Procedure 2: RPD Crash File Management   |                |
| via CCAP Core                                             |                |
+-----------------------------------------------------------+----------------+
| TC-85 (ROSS-104) Procedure 3: RPD Crash File Management   |                |
| via Direct RPD Management                                 |                |
+-----------------------------------------------------------+----------------+
| TC-86 (ROSS-104) Procedure 4: RPD Diagnostic Status       |                |
+-----------------------------------------------------------+----------------+
| TC-101 (ROSS-104) Procedure 5: RPD Crash Data File        |                |
| Control                                                   |                |
+-----------------------------------------------------------+----------------+

3.6  RPD Provisioning Control (ROSS-105)

+-----------------------------------------------------------+----------------+
| Description                                               | Result         |
+-----------------------------------------------------------+----------------+
| TC-87 (ROSS-105) Procedure 1: RPD System Identification   |                |
+-----------------------------------------------------------+----------------+

3.7  Direct RPD Management (ROSS-106)

+-----------------------------------------------------------+----------------+
| Description                                               | Result         |
+-----------------------------------------------------------+----------------+
| TC-88 (ROSS-106) Procedure 1: RPD Reboot Control          |                |
+-----------------------------------------------------------+----------------+

3.8  RPD Ethernet Interface Management (ROSS-107)

+-----------------------------------------------------------+----------------+
| Description                                               | Result         |
+-----------------------------------------------------------+----------------+
| TC-89 (ROSS-107) Procedure 1: RPD Ethernet Interface      |                |
| Reporting                                                 |                |
+-----------------------------------------------------------+----------------+
| TC-90 (ROSS-107) Procedure 2: RPD Ethernet Interface      |                |
| Counters                                                  |                |
+-----------------------------------------------------------+----------------+

3.9  RPD IP Management (ROSS-108)

+-----------------------------------------------------------+----------------+
| Description                                               | Result         |
+-----------------------------------------------------------+----------------+
| TC-91 (ROSS-108) Procedure 1: RPD Internet Address        |                |
| Reporting                                                 |                |
+-----------------------------------------------------------+----------------+
| TC-92 (ROSS-108) Procedure 2: RPD Internet Address        |                |
| Translation Reporting                                     |                |
+-----------------------------------------------------------+----------------+
| TC-93 (ROSS-108) Procedure 3: RPD IP Statistics Reporting |                |
+-----------------------------------------------------------+----------------+

3.10 RPD Statistics Reporting (ROSS-109)

+-----------------------------------------------------------+----------------+
| Description                                               | Result         |
+-----------------------------------------------------------+----------------+
| TC-104 (ROSS-109) Procedure 1: RPD Interface Statistics   |                |
| Reporting                                                 |                |
+-----------------------------------------------------------+----------------+
| TC-105 (ROSS-109) Procedure 2: RPD Interface Statistics   |                |
| RPD Request Fails                                         |                |
+-----------------------------------------------------------+----------------+

