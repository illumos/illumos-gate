# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms. 
#

TITLE: Dynamic Memory Implementation Overview

DATE:  10/13/2000

AUTHOR: Jim Guerrera (james.guerrera@east)


1.0 Dynamic Memory Implementation in the SCM Module

The system memory allocation required by the Storage Cache Manager (SCM)
has been modified to more fully conform to the requirements of the Solaris
OS. The previous implementation required that the total memory requirements
of the package be allocated 'up front' during bootup and was never released. 
The current implementation performs 'on demand' allocations at the time
memory is required in a piecemeal manner. In addition the requisitioned
memory will be released back to the system at some later time.

2.0 Implementation

2.1 Memory Allocation

The memory allocation involves modifications primarily to sd_alloc_buf()
in module sd_bcache.c. When a request is received for cache and system 
resources it is broken down and each piece catagorized both as an
independent entity and as a member of a group with close neighbors. Cache
resources comprise cache control entries (ccent), write control entries 
(wctrl for FWC support) and system memory. The current allocation algorithim
for ccent and wrctl remains the same. The memory allocation has been modified
and falls into two general catagories - single page and multi-page 
allocations.

2.1.1 A single page allocation means exactly that  - the ccent points to and
owns one page of system memory. If two or more ccent are requisitioned to 
support the caching request then only the first entry in the group actually 
owns the the allocated memory of two or more pages. The secondary entries 
simply point to page boundaries within this larger piece of contiguous memory.
The first entry is termed a host and the secondaries are termed parasites. 

The process for determining what is a host, a parasite or anything else is 
done in three phases. Phase one simply determines whether the caching request
references a disk area already in cache and  marks it as such. If it is not
in cache it is typed as eligible - i.e. needing memory allocation. Phase
two scans this list of typed cache entries and based on immediate neighbors
is catagorized as host, pest or downgraded to other. A host can only exist 
if there is one or more eligible entries immediately following it and it 
itself either starts the list or immediately follows a non-eligible entry. 
If either condition proves false the catagory remains as eligible (i.e. 
needs memory allocation) but the type is cleared to not host (i.e. other). 
The next phase is simply a matter of scanning the cache entry list and 
allocating multipage memory for hosts, single page entries for others or 
simply setting up pointers in the parasitic entries into it's corresponding
host multipage memory allocation block.

2.1.2 The maximum number of parasitic entries following a host memory 
allocation is adjustable by the system administrator. The details of this 
are under the description of the KSTAT interface (Sec 3.0).

2.2 Memory Deallocation

Memory deallocation is implemented in  sd_dealloc_dm() in module sd_io.c. 
This possibly overly complicated routine works as follows:

In general the routine sleeps a specified amount of time then wakes and 
examines the entire centry list. If an entry is available (i.e. not in use 
by another thread and has memory which may be deallocated) it takes 
possession and ages the centry by one tick. It then determines if the 
centry has aged sufficiently to have its memory deallocated and for it to 
be placed at the top of the lru.

2.3 There are two general deallocation schemes in place depending on 
whether the centry is a single page allocation centry or it is a member 
of a host/parasite multipage allocation chain.

2.3.1 The behavior for a single page allocation centry is as follows:

If the given centry is selected as a 'holdover' it will age normally 
however at full aging it will only be placed at the head of the lru. 
It's memory will not be deallocated until a further aging level has 
been reached. The entries selected for this behavior are governed by 
counting the number of these holdovers in existence on each wakeup 
and comparing it to a specified percentage. This comparision is always 
one cycle out of date and will float in the relative vicinity of the 
specified number.

In addition there is a placeholder for centries identified as 'sticky 
meta-data' with its own aging counter. It operates exactly as the holdover 
entries as regards to aging but is absolute - i.e. no percentage governs 
the number of such entries. 

2.3.2 The percentage and additional aging count are adjustable by the 
system administrator. The details of this are under the description of 
the KSTAT interface (Sec. 3.0).

2.3.3 The behavior for a host/parasite chain is as follows:

The host/parasite subchain is examined. If all entries are fully aged the 
entire chain is removed - i.e memory is deallocated from the host centry 
and all centry fields are cleared and each entry requeued on to the lru.

There are three sleep times and two percentage levels specifiable by the 
system administrator. A meaningful relationship between these variables 
is:

sleeptime1 >= sleeptime2 >= sleeptime2 and
100% >= pcntfree1 >= pcntfree2 >= 0%

sleeptime1 is honored between 100% free and pcntfree1. sleeptime2 is 
honored between pcntfree1 and pcntfree2. sleeptime3 is honored between 
pcntfree2 and 0% free. The general thrust here is to automatically 
adjust sleep time to centry load. 

In addition  there exist an accelerated aging flag which mimics hysterisis 
behavior. If the available centrys fall between pcntfree1 and pcntfree2 
an 8 bit counter is switched on. The effect is to keep the timer value 
at sleeptime2 for 8 cycles even if the number available cache entries 
drifts above pcntfree1. If it falls below pcntfree2 an additional 8 bit 
counter is switched on. This causes the sleep timer to remain at sleeptime3 
for at least 8 cycles even if it floats above pcntfree2 or even pcntfree1. 
The overall effect of this is to accelerate the release of system resources
under what the thread thinks is a heavy load as measured by the number of 
used cache entries.

3.0 Dynamic Memory Tuning

A number of behavior modification variables are accessible via system calls 
to the kstat library. A sample program exercising the various features can 
be found in ./src/cmd/ns/sdbc/sdbc_dynmem.c. In addition the behavior variable 
identifiers can be placed in the sdbc.conf file and will take effect on bootup.
There is also a 
number of dynamic memory statistics available to gauge its current state.

3.1 Behavior Variables

sdbc_monitor_dynmem --- D0=monitor thread shutdown in the console window
                        D1=print deallocation thread stats to the console 
                        window
                        D2=print more deallocation thread stats to the console 
                        window
                        (usage: setting a value of 6 = 2+4 sets D1 and D2)
sdbc_max_dyn_list ----- 1 to ?: sets the maximum host/parasite list length
                        (A length of 1 prevents any multipage allocations from 
                        occuring and effectively removes the concept of 
                        host/parasite.)
sdbc_cache_aging_ct1 -- 1 to 255: fully aged count (everything but meta and 
			holdover)
sdbc_cache_aging_ct2 -- 1 to 255: fully aged count for meta-data entries
sdbc_cache_aging_ct3 -- 1 to 255: fully aged count for holdovers
sdbc_cache_aging_sec1 - 1 to 255: sleep level 1 for 100% to pcnt1 free cache 
			entries
sdbc_cache_aging_sec2 - 1 to 255: sleep level 2 for pcnt1 to pcnt2 free cache 
			entries
sdbc_cache_aging_sec3 - 1 to 255: sleep level 3 for pcnt2 to 0% free cache 
			entries
sdbc_cache_aging_pcnt1- 0 to 100: cache free percent for transition from 
			sleep1 to sleep2
sdbc_cache_aging_pcnt2- 0 to 100: cache free percent for transition from 
			sleep2 to sleep3
sdbc_max_holds_pcnt --- 0 to 100: max percent of cache entries to be maintained 
			as holdovers

3.2 Statistical Variables

Cache Stats (per wake cycle) (r/w):
sdbc_alloc_ct --------- total allocations performed
sdbc_dealloc_ct ------- total deallocations performed
sdbc_history ---------- current hysterisis flag setting
sdbc_nodatas ---------- cache entries w/o memory assigned
sdbc_candidates ------- cache entries ready to be aged or released
sdbc_deallocs --------- cache entries w/memory deallocated and requeued
sdbc_hosts ------------ number of host cache entries
sdbc_pests ------------ number of parasitic cache entries
sdbc_metas ------------ number of meta-data cache entries
sdbc_holds ------------ number of holdovers (fully aged w/memory and requeued)
sdbc_others ----------- number of not [host, pests or metas]
sdbc_notavail --------- number of cache entries to bypass (nodatas+'in use by 
                        other processes')
sdbc_process_directive- D0=1 wake thread
                        D1=1 temporaily accelerate aging (set the hysterisis
                        flag)
sdbc_simplect --------- simple count of the number of times the kstat update 
			routine has been called          


3.3 Range Checks and Limits

Only range limits are checked. Internal inconsistencies are not checked 
(e.g. pcnt2 > pcnt1). Inconsistencies won't break the system you just won't 
get meaningful behavior. 

The aging counter and sleep timer limits are arbitrarily limited to a byte 
wide counter. This can be expanded. However max'ing the values under the 
current implementation yields about 18 hours for full aging.

3.4 Kstat Lookup Name

The kstat_lookup() module name is "sdbc:dynmem" with an instance of 0.

3.5 Defaults

Default values are:
sdbc_max_dyn_list = 8
sdbc_monitor_dynmem = 0
sdbc_cache_aging_ct1 = 3
sdbc_cache_aging_ct2 = 3
sdbc_cache_aging_ct3 = 3
sdbc_cache_aging_sec1 = 10
sdbc_cache_aging_sec2 = 5
sdbc_cache_aging_sec3 = 1
sdbc_cache_aging_pcnt1 = 50
sdbc_cache_aging_pcnt2 = 25
sdbc_max_holds_pcnt = 0

To make the dynmem act for all intents and purposes like the static model 
beyond the inital startup the appropriate values are:
sdbc_max_dyn_list = 1,
sdbc_cache_aging_ct1/2/3=255,
sdbc_cache_aging_sec1/2/3=255
The remaining variables are irrelevant.

4.0 KSTAT Implementation for Existing Statistics

The existing cache statistical reporting mechanism has been replaced by 
the kstat library reporting mechanism. In general the statistics fall into 
two general catagories - global and shared. The global stats reflect gross 
behavior over all cached volumes and shared reflects behavior particular 
to each cached volume.

4.1 Global KSTAT lookup_name

The kstat_lookup() module name is "sdbc:gstats" with an instance of 0. The 
identifying ascii strings and associated values matching the sd_stats driver 
structure are:

sdbc_dirty -------- net_dirty
sdbc_pending ------ net_pending
sdbc_free --------- net_free
sdbc_count -------- st_count		- number of opens for device
sdbc_loc_count ---- st_loc_count	- number of open devices
sdbc_rdhits ------- st_rdhits		- number of read hits
sdbc_rdmiss ------- st_rdmiss		- number of read misses
sdbc_wrhits ------- st_wrhits		- number of write hits
sdbc_wrmiss ------- st_wrmiss		- number of write misses
sdbc_blksize ------ st_blksize		- cache block size
sdbc_num_memsize -- SD_MAX_MEM		- number of defined blocks 
					  (currently 6)
To find the size of each memory blocks append the numbers 0 to 5 to 
'sdbc_memsize'.
sdbc_memsize0 ----- local memory
sdbc_memsize1 ----- cache memory
sdbc_memsize2 ----- iobuf memory
sdbc_memsize3 ----- hash memory
sdbc_memsize4 ----- global memory
sdbc_memsize5 ----- stats memory
sdbc_total_cmem --- st_total_cmem	- memory used by cache structs
sdbc_total_smem --- st_total_smem	- memory used by stat  structs 
sdbc_lru_blocks --- st_lru_blocks
sdbc_lru_noreq ---- st_lru_noreq
sdbc_lru_req ------ st_lru_req
sdbc_num_wlru_inq - MAX_CACHE_NET	- number of net (currently 4)
To find the size of the least recently used write cache per net append 
the numbers 0-3 to sdbc_wlru_inq
sdbc_wlru_inq0 ---- net 0
sdbc_wlru_inq1 ---- net 1
sdbc_wlru_inq2 ---- net 2
sdbc_wlru_inq3 ---- net 3
sdbc_cachesize ---- st_cachesize	- cache size
sdbc_numblocks ---- st_numblocks	- cache blocks
sdbc_num_shared --- MAXFILES*2		- number of shared structures (one for
					  each cached volume)
					  This number dictates the maximum 
					  index size for shared stats and 
					  names given below.
sdbc_simplect ----- simple count of the number of times the kstat update routine
		    has been called

All fields are read only.


4.2 Shared Structures KSTAT lookup_name

The kstat_lookup() module name is "sdbc:shstats" and "sdbc:shname" both with 
an instance of 0. The identifying ascii strings and associated values matching 
the sd_shared driver structure are:

sdbc:shstats module
sdbc_index ------- structure index number 
sdbc_alloc ------- sh_alloc		- is this allocated?
sdbc_failed ------ sh_failed		- Disk failure status (0=ok,1= /o error
						,2= open failed)
sdbc_cd ---------- sh_cd		- the cache descriptor. (for stats)
sdbc_cache_read -- sh_cache_read	- Number of bytes read from cache
sdbc_cache_write - sh_cache_write	- Number of bytes written  to cache
sdbc_disk_read --- sh_disk_read		- Number of bytes read from disk 
sdbc_disk_write -- sh_disk_write	- Number of bytes written  to disk
sdbc_filesize ---- sh_filesize		- Filesize
sdbc_numdirty ---- sh_numdirty		- Number of dirty blocks
sdbc_numio ------- sh_numio		- Number of blocks on way to disk
sdbc_numfail ----- sh_numfail		- Number of blocks failed
sdbc_flushloop --- sh_flushloop		- Loops delayed so far
sdbc_flag -------- sh_flag		- Flags visible to user programs 
sdbc_simplect ---- simple count of the number of times the kstat update routine
		   has been called

sdbc:shname module
read in as raw bytes and interpreted as a nul terminated assci string.

These two modules operate hand in hand based on information obtained from the
"sdbc:gstats" module. "sdbc:gstats - sdbc_num_shared" gives the maximum number
possible of shared devices. It does not tell how many devices are actually 
cached - just the maximum possible. In order to determine the number present 
and retrieve the statistics for each device the user must:

1. open and read "sdbc:shstats" 
2. set the index "sdbc_index" to a starting value (presumably 0)
3. write the kstat module ( the only item in the module is sdbc_index)

What this does is set a starting index for all subsequent reads. 

4. to get the device count and associated statistics the user now simply 
reads each module "sdbc:shstats" and "sdbc:shname" as a group repeatedly - 
the index will auto increment

To reset the index set "sdbc:shstats - sdbc_index" to the required value 
and write the module.

The first entry returning a nul string to "sdbc:shname" signifies no more 
configured devices.

