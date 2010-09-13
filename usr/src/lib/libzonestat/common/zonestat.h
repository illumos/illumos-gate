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

#ifndef _ZONESTAT_H
#define	_ZONESTAT_H



#include <limits.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/pset.h>
#include <sys/zone.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	ZS_IPTYPE_SHARED	1
#define	ZS_IPTYPE_EXCLUSIVE	2

#define	ZS_CPUTYPE_DEFAULT_PSET	1
#define	ZS_CPUTYPE_POOL_PSET	2
#define	ZS_CPUTYPE_PSRSET_PSET	3
#define	ZS_CPUTYPE_DEDICATED	4


#define	ZS_LIMIT_NONE			(UINT64_MAX)
#define	ZS_PCT_NONE			(UINT_MAX)
#define	ZS_SHARES_UNLIMITED		(UINT16_MAX)

#define	ZS_ZONENAME_MAX			ZONENAME_MAX
#define	ZS_PSETNAME_MAX			(1024 + 1)
#define	ZS_POOLNAME_MAX			(1024 + 1)

#define	ZS_RESOURCE_TYPE_TIME		1
#define	ZS_RESOURCE_TYPE_COUNT		2
#define	ZS_RESOURCE_TYPE_BYTES		3

#define	ZS_LIMIT_TYPE_TIME		1
#define	ZS_LIMIT_TYPE_COUNT		2
#define	ZS_LIMIT_TYPE_BYTES		3

#define	ZS_PROP_TYPE_STRING		1
#define	ZS_PROP_TYPE_TIME		2
#define	ZS_PROP_TYPE_UINT64		3
#define	ZS_PROP_TYPE_INT64		4
#define	ZS_PROP_TYPE_UINT		5
#define	ZS_PROP_TYPE_INT		6
#define	ZS_PROP_TYPE_DOUBLE		7

#define	ZS_SCHED_TS			0x1
#define	ZS_SCHED_IA			0x2
#define	ZS_SCHED_RT			0x4
#define	ZS_SCHED_FX			0x8
#define	ZS_SCHED_FX_60			0x10
#define	ZS_SCHED_FSS			0x20
#define	ZS_SCHED_CONFLICT		0x40

#define	ZS_RESOURCE_PROP_CPU_TOTAL	1
#define	ZS_RESOURCE_PROP_CPU_ONLINE	2
#define	ZS_RESOURCE_PROP_CPU_LOAD_1MIN	3
#define	ZS_RESOURCE_PROP_CPU_LOAD_5MIN	4
#define	ZS_RESOURCE_PROP_CPU_LOAD_15MIN	5

#define	ZS_RESOURCE_CPU			1
#define	ZS_RESOURCE_RAM_RSS		2
#define	ZS_RESOURCE_RAM_LOCKED		3
#define	ZS_RESOURCE_VM			4
#define	ZS_RESOURCE_DISK_SWAP		5
#define	ZS_RESOURCE_LWPS		6
#define	ZS_RESOURCE_PROCESSES		7
#define	ZS_RESOURCE_SHM_MEMORY		8
#define	ZS_RESOURCE_SHM_IDS		9
#define	ZS_RESOURCE_SEM_IDS		10
#define	ZS_RESOURCE_MSG_IDS		11
#define	ZS_RESOURCE_LOFI		12

#define	ZS_USER_ALL			1
#define	ZS_USER_KERNEL			2
#define	ZS_USER_ZONES			3
#define	ZS_USER_FREE			4

#define	ZS_LIMIT_CPU			1
#define	ZS_LIMIT_CPU_SHARES		2
#define	ZS_LIMIT_RAM_RSS		3
#define	ZS_LIMIT_RAM_LOCKED		4
#define	ZS_LIMIT_VM			5
#define	ZS_LIMIT_LWPS			6
#define	ZS_LIMIT_PROCESSES		7
#define	ZS_LIMIT_SHM_MEMORY		8
#define	ZS_LIMIT_SHM_IDS		9
#define	ZS_LIMIT_MSG_IDS		10
#define	ZS_LIMIT_SEM_IDS		11
#define	ZS_LIMIT_LOFI			12

#define	ZS_ZONE_PROP_NAME		1
#define	ZS_ZONE_PROP_ID			2
#define	ZS_ZONE_PROP_IPTYPE		3
#define	ZS_ZONE_PROP_CPUTYPE		4
#define	ZS_ZONE_PROP_DEFAULT_SCHED	5
#define	ZS_ZONE_PROP_SCHEDULERS		6
#define	ZS_ZONE_PROP_CPU_SHARES		7
#define	ZS_ZONE_PROP_POOLNAME		8
#define	ZS_ZONE_PROP_PSETNAME		9
#define	ZS_ZONE_PROP_UPTIME		10
#define	ZS_ZONE_PROP_BOOTTIME		11

#define	ZS_PSET_PROP_NAME		1
#define	ZS_PSET_PROP_ID			2
#define	ZS_PSET_PROP_CPUTYPE		3
#define	ZS_PSET_PROP_SIZE		4
#define	ZS_PSET_PROP_ONLINE		5
#define	ZS_PSET_PROP_MIN		6
#define	ZS_PSET_PROP_MAX		7
#define	ZS_PSET_PROP_CPU_SHARES		8
#define	ZS_PSET_PROP_SCHEDULERS		9
#define	ZS_PSET_PROP_CREATETIME		10
#define	ZS_PSET_PROP_LOAD_1MIN		11
#define	ZS_PSET_PROP_LOAD_5MIN		12
#define	ZS_PSET_PROP_LOAD_15MIN		13

#define	ZS_PZ_PROP_SCHEDULERS	1
#define	ZS_PZ_PROP_CPU_SHARES	2
#define	ZS_PZ_PROP_CPU_CAP	4

#define	ZS_COMPUTE_USAGE_INTERVAL	1
#define	ZS_COMPUTE_USAGE_TOTAL		2
#define	ZS_COMPUTE_USAGE_AVERAGE	3
#define	ZS_COMPUTE_USAGE_HIGH		4

#define	ZS_COMPUTE_SET_TOTAL		1
#define	ZS_COMPUTE_SET_AVERAGE		2
#define	ZS_COMPUTE_SET_HIGH		3

#define	ZS_PZ_PCT_PSET		1
#define	ZS_PZ_PCT_CPU_CAP	2
#define	ZS_PZ_PCT_PSET_SHARES	3
#define	ZS_PZ_PCT_CPU_SHARES	4


/* Per-client handle to libzonestat */
typedef struct zs_ctl zs_ctl_t;

/*
 * These usage structure contains the system's utilization (overall, zones,
 * psets, memory) at a given point in time.
 */
typedef struct zs_usage zs_usage_t;

/*
 * The usage set is for computations on multiple usage structures to describe
 * a range of time.
 */
typedef struct zs_usage_set zs_usage_set_t;

/*
 * The following structures desribe each zone, pset, and each zone's usage
 * of each pset.  Each usage structure (above) contains lists of these that
 * can be traversed.
 */
typedef struct zs_zone zs_zone_t;
typedef struct zs_pset zs_pset_t;
typedef struct zs_pset_zone zs_pset_zone_t;

/*
 * Opaque structure for properties.
 */
typedef struct zs_property zs_property_t;


/* functions for opening/closing a handle for reading current usage */
zs_ctl_t *zs_open();
void zs_close(zs_ctl_t *);

/* function for reading current resource usage */
zs_usage_t *zs_usage_read(zs_ctl_t *);

/* functions for manimulating usage data: zs_usage */
zs_usage_t *zs_usage_compute(zs_usage_t *, zs_usage_t *, zs_usage_t *, int);
void zs_usage_free(zs_usage_t *);

/* functions for manipulating sets of usage data: zs_usage_set */
zs_usage_set_t *zs_usage_set_alloc();
void zs_usage_set_free(zs_usage_set_t *);
int zs_usage_set_add(zs_usage_set_t *, zs_usage_t *);
int zs_usage_set_count(zs_usage_set_t *);
zs_usage_t *zs_usage_set_compute(zs_usage_set_t *, int);

/* functions for overall system resources: zs_resource */
void zs_resource_property(zs_usage_t *, int, int, zs_property_t *);
int zs_resource_type(int);
uint64_t zs_resource_total_uint64(zs_usage_t *, int);
uint64_t zs_resource_used_uint64(zs_usage_t *, int, int);
uint64_t zs_resource_used_zone_uint64(zs_zone_t *, int);
void zs_resource_total_time(zs_usage_t *, int, timestruc_t *);
void zs_resource_used_time(zs_usage_t *, int, int, timestruc_t *);
void zs_resource_used_zone_time(zs_zone_t *, int, timestruc_t *);
uint_t zs_resource_used_pct(zs_usage_t *, int, int);
uint_t zs_resource_used_zone_pct(zs_zone_t *, int);

/* functions for individual zone usage: zs_zone */
int zs_zone_list(zs_usage_t *, zs_zone_t **, int);
zs_zone_t *zs_zone_first(zs_usage_t *);
zs_zone_t *zs_zone_next(zs_usage_t *, zs_zone_t *);
void zs_zone_property(zs_zone_t *, int, zs_property_t *);
int zs_zone_limit_type(int);
uint64_t zs_zone_limit_uint64(zs_zone_t *, int);
uint64_t zs_zone_limit_used_uint64(zs_zone_t *, int);
void zs_zone_limit_time(zs_zone_t *, int, timestruc_t *);
void zs_zone_limit_used_time(zs_zone_t *, int, timestruc_t *);
uint_t zs_zone_limit_used_pct(zs_zone_t *, int);

/* functions for individual psets: zs_pset_list */
int zs_pset_list(zs_usage_t *, zs_pset_t **, int);
zs_pset_t *zs_pset_first(zs_usage_t *);
zs_pset_t *zs_pset_next(zs_usage_t *, zs_pset_t *);
void zs_pset_property(zs_pset_t *, int, zs_property_t *);
void zs_pset_total_time(zs_pset_t *, timestruc_t *);
uint64_t zs_pset_total_cpus(zs_pset_t *);
void zs_pset_used_time(zs_pset_t *, int, timestruc_t *);
uint64_t zs_pset_used_cpus(zs_pset_t *, int);
uint_t zs_pset_used_pct(zs_pset_t *, int);

/* functions for a pset's per-zone usage: zs_pset_zone */
int zs_pset_zone_list(zs_pset_t *, zs_pset_zone_t **, int);
zs_pset_zone_t *zs_pset_zone_first(zs_pset_t *);
zs_pset_zone_t *zs_pset_zone_next(zs_pset_t *, zs_pset_zone_t *);
zs_zone_t *zs_pset_zone_get_zone(zs_pset_zone_t *);
zs_pset_t *zs_pset_zone_get_pset(zs_pset_zone_t *);
void zs_pset_zone_property(zs_pset_zone_t *, int, zs_property_t *);
void zs_pset_zone_used_time(zs_pset_zone_t *, timestruc_t *);
uint64_t zs_pset_zone_used_cpus(zs_pset_zone_t *);
uint_t zs_pset_zone_used_pct(zs_pset_zone_t *, int);

/* functions for accessing properties */
zs_property_t *zs_property_alloc();
size_t zs_property_size();
void zs_property_free(zs_property_t *);
int zs_property_type(zs_property_t *);
int zs_property_id(zs_property_t *);
char *zs_property_string(zs_property_t *);
double zs_property_double(zs_property_t *);
void zs_property_time(zs_property_t *, timestruc_t *);
uint64_t zs_property_uint64(zs_property_t *);
int64_t zs_property_int64(zs_property_t *);
uint_t zs_property_uint(zs_property_t *);
int zs_property_int(zs_property_t *);

#ifdef __cplusplus
}
#endif

#endif	/* _ZONESTAT_H */
