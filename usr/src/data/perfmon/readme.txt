---------------------	
This package contains performance monitoring event lists for Intel processors, as well as a mapping file	
to help match event lists to processor Family/Model/Stepping codes. 	
---------------------	
	
The event lists are available in 2 formats:	
	Tab delimited (.tsv)
	Json (.json)
	
Event lists are created per microarchitecture, and each has a version. Versions are listed in the event list	
name as well as the header for each file. For some microarchitectures, up to three different event lists will	
be available. These event lists correspond to the types of events that can be collected: 	
	
core - Contains events counted from within a logical processor core.		
offcore - Contains matrix events counted from the core, but measuring responses that come from offcore.	
	
The event list filename indicates which type of list it contains, and follows this format:	
<microarchitecture-codename>_<core/offcore>_<version>

New version releases will be announced in the mail list perfmon-announce@lists.01.org 	
	
Different microarchitectures provide different performance monitoring capabilities, so field names and categories	
of events may vary.	
	
---------------------
Licensing Information
---------------------
The following files are distributed under the terms of the 3-clause BSD license:

- Mapfile.csv
- All .tsv files
- All .json files

Copyright (C) 2018 Intel Corporation

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

SPDX-License-Identifier: BSD-3-Clause


Other files in this package are ALL RIGHTS RESERVED.


---------------------	
Event List Field Defitions: 	
---------------------	
Below is a list of the fields/headers in the event files and a description of how SW tools should	
interpret these values. A particular event list from this package may not contain all the fields described	
below. For more detailed information of the Performance monitoring unit please refer to chapters 18 and 19	
of Intel® 64 and IA-32 Architectures Software Developer's Manual Volume 3B: System Programming Guide, Part 2.	
	
http://www.intel.com/content/www/us/en/processors/architectures-software-developer-manuals.html	
	
	
----EventCode----	
This field maps to the Event Select field in the IA32_PERFEVTSELx[7:0]MSRs. The set of values for this field	
is defined architecturally. Each value corresponds to an event logic unit and should be used with a unit 	
mask value to obtain an architectural performance event.	
	
----UMask----	
This field maps to the Unit Mask filed in the IA32_PERFEVTSELx[15:8] MSRs. It further qualifies the event logic 
unit selected in the event select field to detect a specific micro-architectural condition.
 	
----EventName----	
It is a string of characters to identify the programming of an event.	
	
----BriefDescription----	
This field contains a description of what is being counted by a particular event.	
	
----PublicDescription----	
In some cases, this field will contain a more detailed description of what is counted by an event.	
	
----Counter----	
This field lists the fixed (PERF_FIXED_CTRX) or programmable (IA32_PMCX) counters that can be used to count the event.	
	
----CounterHTOff----	
This field lists the counters where this event can be sampled when Intel® Hyper-Threading Technology (Intel® HT Technology) is 	
disabled. When Intel® HT Technology is disabled, some processor cores gain access to the programmable counters of the second 	
thread, making a total of eight programmable counters available. The additional counters will be numbered 4,5,6,7. Fixed counter 	
behavior remains unaffected.

----PEBScounters----	
This field is only relevant to PEBS events. It lists the counters where the event can be sampled when it is programmed as a PEBS event.
	
----SampleAfterValue----	
Sample After Value (SAV) is the value that can be pre-loaded into the counter registers to set the point at which they will overflow. 	
To make the counter overflow after N occurrences of the event, it should be loaded with (0xFF..FF – N) or –(N-1). On overflow a 	
hardware interrupt is generated through the Local APIC and additional architectural state can be collected in the interrupt handler. 	
This is useful in event-based sampling. This field gives a recommended default overflow value, which may be adjusted based on 	
workload or tool preference. 	
	
----MSRIndex----	
Additional MSRs may be required for programming certain events. This field gives the address of such MSRS. 	
Potential values are: 	
0x3F6: MSR_PEBS_LD_LAT - used to configure the Load Latency Perforamnce Monitoring Facility 	
0x1A6/0x1A7: MSR_OFFCORE_RSP_X - used to configure the offcore response events	
	
----MSRValue----	
When an MSRIndex is used (indicated by the MSRIndex column), this field will contain the value that needs to be loaded into the	
register whose address is given in MSRIndex column. For example, in the case of the load latency events, MSRValue defines the	
latency threshold value to write into the MSR defined in MSRIndex (0x3F6).	
	
----CollectPEBSRecord----
Applies to processors that support both precise and non-precise events in Processor Event Based Sampling, such as Goldmont.	
0: The event cannot be programmed to collect a PEBS record.  
1: The event may be programmed to collect a PEBS record, but caution is advised.  
For instance, PEBS collection of this event may consume limited PEBS resources whereas interrupt-based sampling may be sufficient for the usage model.  
2: The event may programmed to collect a PEBS record, and due to the nature of the event, PEBS collection may be preferred.  For instance, 
PEBS collection of Goldmont’s HW_INTERUPTS.RECIEVED event is recommended because the hardware interrupt being counted may lead to the masking of
interrupts which would interfere with interrupt-based sampling.

	
	----TakenAlone----	
This field is set for an event which can only be sampled or counted by itself, meaning that when this event is being collected,	
the remaining programmable counters are not available to count any other events.	
	
----CounterMask----	
This field maps to the Counter Mask (CMASK) field in IA32_PERFEVTSELx[31:24] MSR.
	
----Invert----	
This field corresponds to the Invert Counter Mask (INV) field in IA32_PERFEVTSELx[23] MSR.
		
----AnyThread----	
This field corresponds to the Any Thread (ANY) bit of IA32_PERFEVTSELx[21] MSR. 
	
----EdgeDetect----	
This field corresponds to the Edge Detect (E) bit of IA32_PERFEVTSELx[18] MSR.
 	
----PEBS----	
A '0' in this field means that the event cannot collect a PEBS record with a Precise IP.  A '1' in this field means that the event is a 
precise event and can be programmed in one of two ways – as a regular event or as a PEBS event. And a '2' in this field means 
that the event can only be programmed as a PEBS event. 	
	
----PRECISE_STORE----	
A '1' in this field means the event uses the Precise Store feature and Bit 3 and bit 63 in IA32_PEBS_ENABLE MSR must be set 
to enable IA32_PMC3 as a PEBS counter and enable the precise store facility respectively. Processors based on SandyBridge and 
IvyBridge micro-architecture offer a precise store capability that provides a means to profile store memory references in 
the system.	
	
----DATA_LA---- 	
A '1' in this field means that when the event is configured as a PEBS event, the Data Linear Address facility is supported. 
The Data Linear Address facility is a new feature added to Haswell as a replacement or extension of the precise store facility 
in SNB.	

----L1_HIT_INDICATION----	
A '1' in this field means that when the event is configured as a PEBS event, the DCU hit field of the PEBS record is set to 1 
when the store hits in the L1 cache and 0 when it misses.	
	
----Errata----	
This field lists the known bugs that apply to the events. For the latest, up to date errata refer to	
	
Haswell:	
http://www.intel.com/content/dam/www/public/us/en/documents/specification-updates/4th-gen-core-family-mobile-specification-update.pdf	
	
IvyBridge:	
https://www-ssl.intel.com/content/dam/www/public/us/en/documents/specification-updates/3rd-gen-core-desktop-specification-update.pdf	
	
SandyBridge:	
https://www-ssl.intel.com/content/dam/www/public/us/en/documents/specification-updates/2nd-gen-core-family-mobile-specification-update.pdf	

----offcore----
This field is specific to the json format. There is only 1 file for core and offcore events in this format. This field is set to 1 for offcore events
and 0 for core events. 
	
---------------------	
For additional information:	
---------------------	
Intel Platform Monitoring Homepage	
http://software.intel.com/en-us/platform-monitoring/	
  	
http://software.intel.com/en-us/articles/performance-monitoring-on-intel-xeon-processor-e5-family	
 	
http://software.intel.com/en-us/articles/monitoring-integrated-memory-controller-requests-in-the-2nd-3rd-and-4th-generation-intel

http://www.intel.com/content/dam/www/public/us/en/documents/specification-updates/4th-gen-core-family-desktop-specification-update.pdf	
	
---------------------	
For questions:	
---------------------
email perfmon-discuss@lists.01.org	

---------------------
Notices:
---------------------
INFORMATION IN THIS DOCUMENT IS PROVIDED IN CONNECTION WITH INTEL PRODUCTS. NO LICENSE, EXPRESS OR IMPLIED, BY ESTOPPEL OR OTHERWISE, 
TO ANY INTELLECTUAL PROPERTY RIGHTS IS GRANTED BY THIS DOCUMENT. EXCEPT AS PROVIDED IN INTEL'S TERMS AND CONDITIONS OF SALE FOR SUCH 
PRODUCTS, INTEL ASSUMES NO LIABILITY WHATSOEVER AND INTEL DISCLAIMS ANY EXPRESS OR IMPLIED WARRANTY, RELATING TO SALE AND/OR USE OF 
INTEL PRODUCTS INCLUDING LIABILITY OR WARRANTIES RELATING TO FITNESS FOR A PARTICULAR PURPOSE, MERCHANTABILITY, OR INFRINGEMENT OF ANY 
PATENT, COPYRIGHT OR OTHER INTELLECTUAL PROPERTY RIGHT. 

A "Mission Critical Application" is any application in which failure of the Intel Product could result, directly or indirectly, in 
personal injury or death. SHOULD YOU PURCHASE OR USE INTEL'S PRODUCTS FOR ANY SUCH MISSION CRITICAL APPLICATION, YOU SHALL INDEMNIFY 
AND HOLD INTEL AND ITS SUBSIDIARIES, SUBCONTRACTORS AND AFFILIATES, AND THE DIRECTORS, OFFICERS, AND EMPLOYEES OF EACH, HARMLESS AGAINST 
ALL CLAIMS COSTS, DAMAGES, AND EXPENSES AND REASONABLE ATTORNEYS' FEES ARISING OUT OF, DIRECTLY OR INDIRECTLY, ANY CLAIM OF PRODUCT 
LIABILITY, PERSONAL INJURY, OR DEATH ARISING IN ANY WAY OUT OF SUCH MISSION CRITICAL APPLICATION, WHETHER OR NOT INTEL OR ITS SUBCONTRACTOR 
WAS NEGLIGENT IN THE DESIGN, MANUFACTURE, OR WARNING OF THE INTEL PRODUCT OR ANY OF ITS PARTS. 

Intel may make changes to specifications and product descriptions at any time, without notice. Designers must not rely on the absence or 
characteristics of any features or instructions marked "reserved" or "undefined". Intel reserves these for future definition and shall have 
no responsibility whatsoever for conflicts or incompatibilities arising from future changes to them. The information here is subject to 
change without notice. Do not finalize a design with this information. 

The products described in this document may contain design defects or errors known as errata which may cause the product to deviate from 
published specifications. Current characterized errata are available on request. 

Contact your local Intel sales office or your distributor to obtain the latest specifications and before placing your product order. 

Copies of documents which have an order number and are referenced in this document, or other Intel literature, may be obtained by calling 
1-800-548-4725, or go to: http://www.intel.com/design/literature.htm

Copyright © 2014 Intel Corporation. All rights reserved.
