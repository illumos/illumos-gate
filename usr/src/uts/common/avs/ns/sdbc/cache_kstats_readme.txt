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
================================================================================

TITLE:	Kstats Specification for SDBC

DATE:	10-28-2002

AUTHOR:	Chris Juhasz (chris.juhasz@sun.com)

LOCATION: src/uts/common/ns/sdbc/cache_kstats_readme.txt
================================================================================

The existing sd_stat cache statistical reporting mechanism has been expanded  
with the kstat library reporting mechanism. The existing mechanism will probably
eventually be phased out.  In general the statistics have fallen 
into two general categories - "global" and "cd." The global stats reflect gross 
behavior over all cached volumes, while "cd" stats reflect behavior particular 
to each cached volume (or cache descriptor).

The sdbc module makes use of two types of kstats.  For generic statistic
reporting, "regular" kstat_named_t type kstats are used.  For timing-specific
reporting, sdbc relies on the kstat_io_t type.

For more information on kstats, see [1] in the References section.

1.0 NAMING:
===========
The names for the sdbc kstats are defined in src/uts/common/ns/sdbc/sd_misc.h

2.0 REGULAR KSTATS:
===================
The following are kstats of type kstat_named_t, used to gather generic
statistics.

These make use of the original statistics gathering mechanism for sdbc, 
_sd_stats_t and _sd_shared_t structs, defined in 
src/uts/common/ns/sdbc/sd_bcache.h.  The _sd_stats_t structure tracks 
statistics that are global to the entire cache, while the _sd_shared_t struct 
is used to track statistics particular to a cache descriptor (cd). 

2.1 GLOBAL KSTATS:
~~~~~~~~~~~~~~~~~~
This global kstat represents statistics which reflect the state of the entire
cache, summed over all cache descriptors.

2.1.1 Field Definitions:
------------------------
The "global" kstat corresponds to fields in the _sd_stats_t structure.  The
following table maps the name of the kstat field to its equivalent field in
the _sd_stats_t structure, also providing a description where appropriate.
 
KSTAT FIELD		_sd_stats_t	DESCRIPTION
-----------		-----------	-----------
sdbc_count		st_count	- number of opens for device
sdbc_loc_count		st_loc_count	- number of open devices
sdbc_rdhits		st_rdhits	- number of read hits
sdbc_rdmiss		st_rdmiss	- number of read misses
sdbc_wrhits		st_wrhits	- number of write hits
sdbc_wrmiss		st_wrmiss	- number of write misses
sdbc_blksize		st_blksize	- cache block size (in bytes)

/* I'm not very sure what the next three fields track--we might take them out */
sdbc_lru_blocks		st_lru_blocks
sdbc_lru_noreq		st_lru_noreq
sdbc_lru_req		st_lru_req

sdbc_wlru_inq		st_wlru_inq	- number of write blocks
sdbc_cachesize		st_cachesize	- cache size (in bytes)
sdbc_numblocks		st_numblocks	- cache blocks
sdbc_num_shared		MAXFILES*2	- number of shared structures (one for
					  each cached volume)
					  This number dictates the maximum 
					  index size for shared stats and 
					  names given below.
sdbc_destaged		st_destaged	- number of bytes destaged to disk
					  (flushed from the cache to disk).
sdbc_wrcancelns		st_wrcancelns	- number of write cancellations
					  (writes to cached blocks that are 
					  already dirty).
sdbc_nodehints		---		- node hints (such as wrthru/nowrthru)

All fields are read-only and are of type KSTAT_DATA_ULONG. Note that the
"sdbc_wrcancelns" and "sdbc_destaged" are new, and have also been added to the
_sd_stats_t struct.

2.1.2 Naming characteristics:
-----------------------------
module:		SDBC_KSTAT_MODULE	"sdbc"  
class:		SDBC_KSTAT_CLASS	"storedge"
name:		SDBC_KSTAT_GSTATS	"global"
instance #:	0 


2.2 KSTATS (PER CACHE DESCRIPTOR):
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
These "cd" kstats present statistics which reflect the state of a single cache 
descriptor.  One of these kstats exists for each open cache descriptor.

2.2.1 Field Definitions:
------------------------
The "cd" kstats correspond to fields in the _sd_shared_t structure.  The
following table maps the name of the kstat field to its equivalent field in
the _sd_shared_t structure, also providing a description where appropriate.

KSTAT FIELD		_sd_shared_t	DESCRIPTION
-----------		------------	-----------
sdbc_vol_name		sh_filename	- last 16 characters of the volume name
sdbc_alloc		sh_alloc	- is this allocated?
sdbc_failed		sh_failed	- Disk failure status (0=ok,1= /o 
					  error ,2= open failed)
sdbc_cd			sh_cd		- the cache descriptor. (for stats)
sdbc_cache_read		sh_cache_read	- Number of FBA's read from cache
sdbc_cache_write	sh_cache_write	- Number of FBA's written  to cache
sdbc_disk_read		sh_disk_read	- Number of FBA's read from disk 
sdbc_disk_write		sh_disk_write	- Number of FBA's written to disk
sdbc_filesize		sh_filesize	- Filesize (in FBA's)
sdbc_numdirty		sh_numdirty	- Number of dirty blocks
sdbc_numio		sh_numio	- Number of blocks on way to disk
sdbc_numfail		sh_numfail	- Number of blocks failed
sdbc_flushloop		sh_flushloop	- Loops delayed so far
sdbc_flag		sh_flag		- Flags visible to user programs 
sdbc_destaged		sh_destaged	- number of bytes destaged to disk
					  (flushed from the cache to disk).
sdbc_cdhints		---		- cd hints (such as wrthru/nowrthru)

All fields are read-only kstat_named_t kstats, with data type KSTAT_DATA_ULONG.
The instance number of the kstat corresponds to the cache descriptor number.   
Note that the "sdbc_wrcancelns" and "sdbc_destaged" are new, and have also 
been added to the _sd_shared_t struct.

2.2.2 Naming characteristics:
-----------------------------
module:		SDBC_KSTAT_MODULE	"sdbc"  
class:		SDBC_KSTAT_CLASS	"storedge"
name:		SDBC_KSTAT_CDSTATS	"cd%d"	(%d = < cd number >)
instance #:	< cache descriptor number > 

3.0 I/O KSTATS:
===============
The sdbc module now contains kstats of type kstat_io_t.  These are used to
track timing through the cache.  As with the "regular" kstats, sdbc tracks
global statistics, as well as those per cache descriptor.  Since kstat_io_t
is a built-in kstat type, all are defined the same way. 

3.0.1 Time-Gathering:
---------------------
These kstat_io_t types provide two built-in time-gathering mechanisms, which it 
refers to as "waitq" and "runq," where "waitq" is intended to be interpreted 
as the amount of time a request spends in its pre-service state, and "runq" the 
amount of time a request spends in its service state.  Transitions to the
runq and the waitq must be  made via built-in functions, such as
kstat_runq_enter() and kstat_runq_exit().  The relevant fields in the 
kstat_io_t structure should not be considered explicitly.  (See comment below).
The iostat(1M) utility may be used to gather timing-related information
collected through this mechanism.

Please note that sdbc does not use waitq.
sdbc uses runq as follows:

An I/O request transitions to the runq (both global, and per-cd) upon entering 
the cache through _sd_read(), _sd_write(), or _sd_alloc_buf().  It
transitions off the runq after the request has been serviced, either by the 
cache, or as the result of disk I/O.  Thus, this allows a user to track the
total time spent in the cache, which includes disk I/O time.

 
3.0.2 kstat_io_t Fields:
------------------------
These I/O kstats include the following fields:

        u_longlong_t    nread;          /* number of bytes read */
        u_longlong_t    nwritten;       /* number of bytes written */
        uint_t          reads;          /* number of read operations */
        uint_t          writes;         /* number of write operations */

# The following fields are automatically updated by the built-in
# kstat_waitq_enter(), kstat_waitq_exit(), kstat_runq_enter() and
# kstat_runq_exit() functions.

	hrtime_t wtime;		/* cumulative wait (pre-service) time */
	hrtime_t wlentime;	/* cumulative wait length*time product */
	hrtime_t wlastupdate;	/* last time wait queue changed */
	hrtime_t rtime;		/* cumulative run (service) time */
	hrtime_t rlentime;	/* cumulative run length*time product */
	hrtime_t rlastupdate;	/* last time run queue changed */

	uint_t	wcnt;		/* count of elements in wait state */
	uint_t	rcnt;		/* count of elements in run state */

For more information, refer to [2] in the References section. 

3.1 GLOBAL IO KSTATS:
~~~~~~~~~~~~~~~~~~~~~
sdbc includes "global" I/O kstats which track the timings through the cache as 
a whole, taking into account all cache descriptors.  The fields definitions
are built-in, as explained above.

3.1.1 Naming characteristics:
-----------------------------
module:		SDBC_KSTAT_MODULE	"sdbc"  
class:					"disk"
name:		SDBC_IOKSTAT_GSTATS	"gsdbc"
instance #:	0

3.2 IO KSTATS (PER CACHE DESCRIPTOR):
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
These "cd" I/O kstats present statistics which reflect the state of a single 
cache descriptor.  One of these I/O kstats exists for each open cache 
descriptor. The fields definitions are built-in, as explained above.

3.2.1 Naming characteristics:
-----------------------------
module:		SDBC_KSTAT_MODULE	"sdbc"  
class:					"disk"
name:		SDBC_IOKSTAT_STATS	"sdbc%d" (%d = < cd number >) 
instance #:	< cache descriptor number > 

4.0 DYNMEM KSTATS:
==================
The sdbc module also a "regular" kstat to track dynamic memory
allocation in the cache.  These are "global" statistics.

Its fields can be divided logically between behavior variables, and statistical 
variable

4.1 Field Definitions: 
~~~~~~~~~~~~~~~~~~~~~~

4.1.1 Behavior Variables:
-------------------------
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

4.1.2 Statistical Variables:
----------------------------
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
			routine has been called (used for debugging)         

The behavior fields (along with the "sdbc_process_directive" field) may be both 
read and written.  The remaining statistical fields are read-only. 

For more information, please refer to [3] in the References section.

4.2 Naming characteristics:
~~~~~~~~~~~~~~~~~~~~~~~~~~~
module:		SDBC_KSTAT_MODULE	"sdbc"  
class:		SDBC_KSTAT_CLASS	"storedge"
name:		SDBC_KSTAT_DYNMEM	"dynmem"
instance #:	0	

5.0 REFERENCES FOR FURTHER READING:
===================================
1. generic kstat information: kstat(1M), <sys/include/kstat.h>
2. kstat_io_t information: kstat_io(9S), kstat_queue(9F)
3. sdbc dynamic memory implementation:
<ds[3,4]>/src/uts/common/ns/sdbc/dynmem_readme.txt
