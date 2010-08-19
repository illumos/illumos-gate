/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _ZONESTAT_IMPL_H
#define	_ZONESTAT_IMPL_H

#include <zonestat.h>
#include <sys/list.h>
#include <sys/priv_const.h>

#ifdef __cplusplus
extern "C" {

#endif

#define	ZS_VERSION	1

#define	ZS_PSET_DEFAULT		PS_NONE
#define	ZS_PSET_MULTI		PS_MYID
#define	ZS_PSET_ERROR		PS_QUERY

#define	ZS_DOOR_PATH		"/etc/svc/volatile/zonestat_door"

#define	ZSD_CMD_READ		1
#define	ZSD_CMD_CONNECT		2
#define	ZSD_CMD_NEW_ZONE	3

/* The following read commands are unimplemented */
#define	ZSD_CMD_READ_TIME	3
#define	ZSD_CMD_READ_SET	4
#define	ZSD_CMD_READ_SET_TIME	5

#define	ZSD_STATUS_OK			0
#define	ZSD_STATUS_VERSION_MISMATCH	1
#define	ZSD_STATUS_PERMISSION		2
#define	ZSD_STATUS_INTERNAL_ERROR	3

#define	TIMESTRUC_ADD_NANOSEC(ts, nsec)				\
	{							\
		(ts).tv_sec += (time_t)((nsec) / NANOSEC);	\
		(ts).tv_nsec += (long)((nsec) % NANOSEC);	\
		if ((ts).tv_nsec > NANOSEC) {			\
			(ts).tv_sec += (ts).tv_nsec / NANOSEC;	\
			(ts).tv_nsec = (ts).tv_nsec % NANOSEC;	\
		}						\
	}

#define	TIMESTRUC_ADD_TIMESTRUC(ts, add)			\
	{							\
		(ts).tv_sec += (add).tv_sec;			\
		(ts).tv_nsec += (add).tv_nsec;			\
		if ((ts).tv_nsec > NANOSEC) {			\
			(ts).tv_sec += (ts).tv_nsec / NANOSEC;	\
			(ts).tv_nsec = (ts).tv_nsec % NANOSEC;	\
		}						\
	}

#define	TIMESTRUC_DELTA(delta, new, old)			\
	{							\
		(delta).tv_sec = (new).tv_sec - (old).tv_sec;	\
		(delta).tv_nsec = (new).tv_nsec - (old).tv_nsec;\
		if ((delta).tv_nsec < 0) {			\
			delta.tv_nsec += NANOSEC;		\
			delta.tv_sec -= 1;			\
		}						\
		if ((delta).tv_sec < 0) {			\
			delta.tv_sec = 0;			\
			delta.tv_nsec = 0;			\
		}						\
	}

typedef struct zs_system {

	uint64_t zss_ram_total;
	uint64_t zss_ram_kern;
	uint64_t zss_ram_zones;

	uint64_t zss_locked_kern;
	uint64_t zss_locked_zones;

	uint64_t zss_vm_total;
	uint64_t zss_vm_kern;
	uint64_t zss_vm_zones;

	uint64_t zss_swap_total;
	uint64_t zss_swap_used;

	timestruc_t zss_cpu_total_time;
	timestruc_t zss_cpu_usage_kern;
	timestruc_t zss_cpu_usage_zones;

	uint64_t zss_processes_max;
	uint64_t zss_lwps_max;
	uint64_t zss_shm_max;
	uint64_t zss_shmids_max;
	uint64_t zss_semids_max;
	uint64_t zss_msgids_max;
	uint64_t zss_lofi_max;

	uint64_t zss_processes;
	uint64_t zss_lwps;
	uint64_t zss_shm;
	uint64_t zss_shmids;
	uint64_t zss_semids;
	uint64_t zss_msgids;
	uint64_t zss_lofi;

	uint64_t zss_ncpus;
	uint64_t zss_ncpus_online;

} zs_system_t;

struct zs_pset_zone {

	list_node_t	zspz_next;
	struct zs_pset	*zspz_pset;
	struct zs_zone	*zspz_zone;
	zoneid_t	zspz_zoneid;
	time_t		zspz_start;
	hrtime_t	zspz_hrstart;
	uint_t		zspz_intervals;

	uint64_t	zspz_cpu_shares;
	uint_t		zspz_scheds;

	timestruc_t	zspz_cpu_usage;

};

struct zs_ctl {
	int	 zsctl_door;
	uint64_t zsctl_gen;
	zs_usage_t *zsctl_start;
};

struct zs_zone {
	list_node_t	zsz_next;
	struct zs_system *zsz_system;
	char		zsz_name[ZS_ZONENAME_MAX];
	char		zsz_pool[ZS_POOLNAME_MAX];
	char		zsz_pset[ZS_PSETNAME_MAX];
	zoneid_t	zsz_id;
	uint_t		zsz_cputype;
	uint_t		zsz_iptype;
	time_t		zsz_start;
	hrtime_t	zsz_hrstart;
	uint_t		zsz_intervals;

	uint_t		zsz_scheds;
	uint64_t	zsz_cpu_shares;
	uint64_t	zsz_cpu_cap;
	uint64_t	zsz_ram_cap;
	uint64_t	zsz_vm_cap;
	uint64_t	zsz_locked_cap;

	uint64_t	zsz_cpus_online;
	timestruc_t	zsz_cpu_usage;
	timestruc_t	zsz_pset_time;
	timestruc_t	zsz_cap_time;
	timestruc_t	zsz_share_time;

	uint64_t	zsz_usage_ram;
	uint64_t	zsz_usage_locked;
	uint64_t	zsz_usage_vm;

	uint64_t	zsz_processes_cap;
	uint64_t	zsz_lwps_cap;
	uint64_t	zsz_shm_cap;
	uint64_t	zsz_shmids_cap;
	uint64_t	zsz_semids_cap;
	uint64_t	zsz_msgids_cap;
	uint64_t	zsz_lofi_cap;

	uint64_t	zsz_processes;
	uint64_t	zsz_lwps;
	uint64_t	zsz_shm;
	uint64_t	zsz_shmids;
	uint64_t	zsz_semids;
	uint64_t	zsz_msgids;
	uint64_t	zsz_lofi;

};

struct zs_pset {
	list_node_t	zsp_next;
	char		zsp_name[ZS_PSETNAME_MAX];
	psetid_t	zsp_id;
	uint_t		zsp_cputype;
	time_t		zsp_start;
	hrtime_t	zsp_hrstart;
	uint_t		zsp_intervals;

	uint64_t	zsp_online;
	uint64_t	zsp_size;
	uint64_t	zsp_min;
	uint64_t	zsp_max;
	int64_t		zsp_importance;

	uint_t		zsp_scheds;
	uint64_t	zsp_cpu_shares;
	timestruc_t	zsp_total_time;
	timestruc_t	zsp_usage_kern;
	timestruc_t	zsp_usage_zones;

	uint_t		zsp_nusage;
	list_t		zsp_usage_list;
};

struct zs_usage {
	time_t		zsu_start;
	hrtime_t	zsu_hrstart;
	time_t		zsu_time;
	hrtime_t	zsu_hrtime;
	uint64_t	zsu_size;
	uint_t		zsu_intervals;
	uint64_t	zsu_gen;
	boolean_t	zsu_mmap;
	uint_t		zsu_nzones;
	uint_t		zsu_npsets;
	zs_system_t	*zsu_system;
	list_t		zsu_zone_list;
	list_t		zsu_pset_list;
};

struct zs_usage_set {
	struct zs_usage *zsus_total;
	struct zs_usage *zsus_avg;
	struct zs_usage *zsus_high;
	uint_t		zsus_count;
};

struct zs_property {
	int zsp_type;
	int zsp_id;
	union zsp_value_union {
		char zsv_string[ZS_PSETNAME_MAX];
		timestruc_t zsv_ts;
		double zsv_double;
		uint64_t zsv_uint64;
		int64_t zsv_int64;
		uint_t zsv_uint;
		int zsv_int;
	} zsp_v;
};

typedef struct zs_usage_cache {
	int zsuc_ref;
	uint_t zsuc_size;
	uint64_t zsuc_gen;
	zs_usage_t *zsuc_usage;
} zs_usage_cache_t;


#ifdef __cplusplus
}
#endif

#endif	/* _ZONESTAT_IMPL_H */
