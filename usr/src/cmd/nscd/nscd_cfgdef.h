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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_NSCD_CFGDEF_H
#define	_NSCD_CFGDEF_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <limits.h>
#include <nss_dbdefs.h>
#include "nscd_config.h"
#include "nscd_log.h"
#include "cache.h"

/*
 * structure used for preliminary checking of an integer
 * configuration value
 */
typedef	struct {
	int	min;
	int	max;
} nscd_cfg_int_check_t;

/*
 * structure used for preliminary checking of a bitmap
 * configuration value
 */
typedef	struct {
	nscd_cfg_bitmap_t	valid_bits;
} nscd_cfg_bitmap_check_t;

/*
 * structure used for preliminary checking of a string
 * configuration value
 */
typedef	struct {
	nscd_bool_t	must_not_null;
	int		maxlen;
} nscd_cfg_str_check_t;

/*
 * Per nsswitch database config data
 */
typedef struct {
	nscd_cfg_frontend_t	fe;
	nscd_cfg_switch_t	sw;
	nscd_cfg_cache_t	cache;
} nscd_cfg_nsw_db_data_t;

/*
 * Per nsswitch database statistics data
 */
typedef struct {
	nscd_cfg_stat_switch_t		sw;
	nscd_cfg_stat_cache_t		cache;
} nscd_cfg_stat_nsw_db_data_t;

/*
 * global statistics data
 */
typedef struct {
	nscd_cfg_stat_global_log_t	log;
	nscd_cfg_stat_global_switch_t	sw;
	nscd_cfg_stat_cache_t		cache;
} nscd_cfg_stat_global_data_t;

/*
 * global config data
 */
typedef struct {
	nscd_cfg_global_log_t		log;
	nscd_cfg_global_frontend_t	fe;
	nscd_cfg_global_selfcred_t	sc;
	nscd_cfg_global_switch_t	sw;
	nscd_cfg_global_cache_t		cache;
} nscd_cfg_global_data_t;

/*
 * structure for handling the switch database specific group
 * or parameter default
 */
typedef struct nscd_cfg_nsw_spc_default {
	char	*db;
	int	group_off;
	int	param_off;
	void	*data;		/* pointer or link to data */
	int	data_len;
} nscd_cfg_nsw_spc_default_t;

/*
 * name service switch source (repository) table
 */
nscd_cfg_id_t _nscd_cfg_nsw_src[] = {
	{	0,	"files"			},
	{	1,	"ldap"			},
	{	2,	"nis"			},
	{	3,	"mdns"			},
	{	4,	"dns"			},
	{	5,	"compat"		},
	{	6,	"user"			},
	{	7,	"ad"			},
	{	-1,	NULL			}
};

/*
 * name service related smf service table
 * (the order of the services should match the order of the source
 *  listed above, 0: files, 1: ldap, 2: nis, 3: mdns.
 *  dns is not needed)
 */
nscd_cfg_id_t _nscd_cfg_smf_services[] = {
	{	0,	"svc:/system/name-service-cache:default"},
	{	1,	"svc:/network/ldap/client:default"	},
	{	2,	"svc:/network/nis/client:default"	},
	{	3,	"svc:/network/dns/multicast:default"	},
	{	-1,	NULL					}
};

/*
 * default version for supported sources/backends
 */
void	*_nscd_be_version = NULL;

/*
 * name service database table
 */
nscd_cfg_id_t _nscd_cfg_nsw_db[] = {
	{	0,	NSS_DBNAM_PASSWD	},
	{	1,	NSS_DBNAM_GROUP		},
	{	2,	NSS_DBNAM_HOSTS		},
	{	3,	NSS_DBNAM_IPNODES	},
	{	4,	NSS_DBNAM_EXECATTR	},
	{	5,	NSS_DBNAM_PROFATTR	},
	{	6,	NSS_DBNAM_USERATTR	},
	{	7,	NSS_DBNAM_NETWORKS	},
	{	8,	NSS_DBNAM_PROTOCOLS	},
	{	9,	NSS_DBNAM_RPC		},
	{	10,	NSS_DBNAM_ETHERS	},
	{	11,	NSS_DBNAM_NETMASKS	},
	{	12,	NSS_DBNAM_BOOTPARAMS	},
	{	13,	NSS_DBNAM_PUBLICKEY	},
	{	14,	NSS_DBNAM_NETGROUP	},
	{	15,	NSS_DBNAM_SERVICES	},
	{	16,	NSS_DBNAM_PRINTERS	},
	{	17,	NSS_DBNAM_AUTHATTR	},
	{	18,	NSS_DBNAM_PROJECT	},
	{	19,	NSS_DBNAM_SHADOW	},
	{	20,	NSS_DBNAM_AUDITUSER	},
	{	21,	NSS_DBNAM_TSOL_TP	},
	{	22,	NSS_DBNAM_TSOL_RH	},
	/* pseudo-databases for the compat backend */
	{	23,	NSS_DBNAM_PASSWD_COMPAT },
	{	24,	NSS_DBNAM_GROUP_COMPAT  },
#define	NSS_DBNAM_COMPAT_NUM_DB	5
	/*
	 * pseudo-databases that use the switch policy that is
	 * configured for NSS_DBNAM_PASSWD_COMPAT
	 */
	{	25,	NSS_DBNAM_PASSWD	},
	{	26,	NSS_DBNAM_SHADOW	},
	{	27,	NSS_DBNAM_AUDITUSER	},
	{	28,	NSS_DBNAM_USERATTR	},
	/*
	 * pseudo-database that uses the switch policy that is
	 * configured for NSS_DBNAM_GROUP_COMPAT
	 */
	{	29,	NSS_DBNAM_GROUP		},
	{	-1,	NULL			}
};

/*
 * A special way to indicate all switch databases
 */
static	nscd_cfg_id_t _nscd_cfg_nsw_alldb = {
		NSCD_CFG_NSW_ALLDB_INDEX,
		NSCD_CFG_NSW_ALLDB
};

/*
 * data for preliminary checking of the log configuration
 */
static nscd_cfg_str_check_t	NSCD_CFG_LOGFILE_PCHECK =
				{nscd_false, PATH_MAX};
static nscd_cfg_bitmap_check_t	NSCD_CFG_LOGCOMP_PCHECK =
				{NSCD_LOG_ALL};
static nscd_cfg_bitmap_check_t	NSCD_CFG_LOGLEVEL_PCHECK =
				{NSCD_LOG_LEVEL_ALL};

/* data for preliminary checking of the switch configuration */
static nscd_cfg_str_check_t	NSCD_CFG_NSWCFGSTR_PCHECK =
				{nscd_true, 128};

/*
 * macros for defining the static param table
 */
#define	NSCD_CFG_PGROUP_DESC(pn, type, pflag, gf, g_in_t, pcheck_p,\
		nfunc_name, vfunc_name) \
	{ \
		{-1, pn}, type, (NSCD_CFG_PFLAG_GROUP | pflag), \
		0, 0, 0,\
		NSCD_SIZEOF(g_in_t, gf), offsetof(g_in_t, gf), -1, \
		pcheck_p, nfunc_name, vfunc_name \
	}

#define	NSCD_CFG_PARAM_DESC(pn, type, pflag, pf, p_in_t, \
		gf, g_in_t, pcheck_p, nfunc_name, vfunc_name) \
	{ \
		{-1, pn}, type, pflag, \
		NSCD_SIZEOF(p_in_t, pf), offsetof(p_in_t, pf), -1, \
		NSCD_SIZEOF(g_in_t, gf), offsetof(g_in_t, gf), -1, \
		pcheck_p, nfunc_name, vfunc_name \
	}

#define	NSCD_CFG_PGROUP_DESC_NULL \
	{ \
		{-1, NULL}, -1, NSCD_CFG_PFLAG_GROUP, \
		0, 0, 0, \
		0, 0, 0, \
		NULL, NULL, NULL \
	}

/* nscd internal cfg_*_notify() cfg_*_verify() and cfg_*_get_stat()  */
extern	nscd_rc_t	_nscd_cfg_log_notify();
extern	nscd_rc_t	_nscd_cfg_log_verify();
extern	nscd_rc_t	_nscd_cfg_frontend_notify();
extern	nscd_rc_t	_nscd_cfg_frontend_verify();
extern	nscd_rc_t	_nscd_cfg_selfcred_notify();
extern	nscd_rc_t	_nscd_cfg_selfcred_verify();
extern	nscd_rc_t	_nscd_cfg_switch_notify();
extern	nscd_rc_t	_nscd_cfg_switch_verify();
extern	nscd_rc_t	_nscd_cfg_cache_notify();
extern	nscd_rc_t	_nscd_cfg_cache_verify();
extern	nscd_rc_t	_nscd_cfg_log_get_stat();
extern	nscd_rc_t	_nscd_cfg_switch_get_stat();
extern	nscd_rc_t	_nscd_cfg_cache_get_stat();

/*
 * the following macros are used to indicate a parameter's
 * notify/verify/get_stat functions are the same as those
 * of the group
 */
#define	NSCD_CFG_FUNC_NOTIFY_AS_GROUP	((nscd_cfg_func_notify_t)-1)
#define	NSCD_CFG_FUNC_VERIFY_AS_GROUP	((nscd_cfg_func_verify_t)-1)
#define	NSCD_CFG_FUNC_GET_STAT_AS_GROUP	((nscd_cfg_func_get_stat_t)-1)

/*
 * the static config parameter description table
 */
static	nscd_cfg_param_desc_t	_nscd_cfg_param_desc[] = {

	NSCD_CFG_PGROUP_DESC(
		"param-group-global-log",
		NSCD_CFG_DATA_NONE,
		NSCD_CFG_PFLAG_INIT_SEND_WHOLE_GROUP |
		NSCD_CFG_PFLAG_GLOBAL,
		log,
		nscd_cfg_global_data_t,
		NULL,
		_nscd_cfg_log_notify,
		_nscd_cfg_log_verify),

	NSCD_CFG_PARAM_DESC(
		"logfile",
		NSCD_CFG_DATA_STRING,
		NSCD_CFG_PFLAG_GLOBAL |
		NSCD_CFG_PFLAG_VLEN_DATA,
		logfile,
		nscd_cfg_global_log_t,
		log,
		nscd_cfg_global_data_t,
		&NSCD_CFG_LOGFILE_PCHECK,
		NSCD_CFG_FUNC_NOTIFY_AS_GROUP,
		NSCD_CFG_FUNC_VERIFY_AS_GROUP),

	NSCD_CFG_PARAM_DESC(
		"debug-level",
		NSCD_CFG_DATA_BITMAP,
		NSCD_CFG_PFLAG_GLOBAL,
		debug_level,
		nscd_cfg_global_log_t,
		log,
		nscd_cfg_global_data_t,
		&NSCD_CFG_LOGLEVEL_PCHECK,
		NSCD_CFG_FUNC_NOTIFY_AS_GROUP,
		NSCD_CFG_FUNC_VERIFY_AS_GROUP),

	NSCD_CFG_PARAM_DESC(
		"debug-components",
		NSCD_CFG_DATA_BITMAP,
		NSCD_CFG_PFLAG_GLOBAL,
		debug_comp,
		nscd_cfg_global_log_t,
		log,
		nscd_cfg_global_data_t,
		&NSCD_CFG_LOGCOMP_PCHECK,
		NSCD_CFG_FUNC_NOTIFY_AS_GROUP,
		NSCD_CFG_FUNC_VERIFY_AS_GROUP),

	NSCD_CFG_PGROUP_DESC(
		"param-group-global-frontend",
		NSCD_CFG_DATA_NONE,
		NSCD_CFG_PFLAG_INIT_SEND_WHOLE_GROUP |
		NSCD_CFG_PFLAG_GLOBAL,
		fe,
		nscd_cfg_global_data_t,
		NULL,
		_nscd_cfg_frontend_notify,
		_nscd_cfg_frontend_verify),

	NSCD_CFG_PARAM_DESC(
		"common-worker-threads",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_PFLAG_SEND_BIT_SELECTED |
		NSCD_CFG_PFLAG_GLOBAL,
		common_worker_threads,
		nscd_cfg_global_frontend_t,
		fe,
		nscd_cfg_global_data_t,
		NULL,
		NSCD_CFG_FUNC_NOTIFY_AS_GROUP,
		NSCD_CFG_FUNC_VERIFY_AS_GROUP),

	NSCD_CFG_PARAM_DESC(
		"cache-hit-threads",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_PFLAG_SEND_BIT_SELECTED |
		NSCD_CFG_PFLAG_GLOBAL,
		cache_hit_threads,
		nscd_cfg_global_frontend_t,
		fe,
		nscd_cfg_global_data_t,
		NULL,
		NSCD_CFG_FUNC_NOTIFY_AS_GROUP,
		NSCD_CFG_FUNC_VERIFY_AS_GROUP),

	NSCD_CFG_PGROUP_DESC(
		"param-group-global-selfcred",
		NSCD_CFG_DATA_NONE,
		NSCD_CFG_PFLAG_INIT_SEND_WHOLE_GROUP |
		NSCD_CFG_PFLAG_GLOBAL,
		sc,
		nscd_cfg_global_data_t,
		NULL,
		_nscd_cfg_selfcred_notify,
		_nscd_cfg_selfcred_verify),

	NSCD_CFG_PARAM_DESC(
		"enable-selfcred",
		NSCD_CFG_DATA_BOOLEAN,
		NSCD_CFG_PFLAG_GLOBAL,
		enable_selfcred,
		nscd_cfg_global_selfcred_t,
		sc,
		nscd_cfg_global_data_t,
		NULL,
		NSCD_CFG_FUNC_NOTIFY_AS_GROUP,
		NSCD_CFG_FUNC_VERIFY_AS_GROUP),

	NSCD_CFG_PARAM_DESC(
		"per-user-nscd-ttl",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_PFLAG_GLOBAL,
		per_user_nscd_ttl,
		nscd_cfg_global_selfcred_t,
		sc,
		nscd_cfg_global_data_t,
		NULL,
		NSCD_CFG_FUNC_NOTIFY_AS_GROUP,
		NSCD_CFG_FUNC_VERIFY_AS_GROUP),

	NSCD_CFG_PGROUP_DESC(
		"param-group-global-switch",
		NSCD_CFG_DATA_NONE,
		NSCD_CFG_PFLAG_INIT_SEND_WHOLE_GROUP |
		NSCD_CFG_PFLAG_GLOBAL,
		sw,
		nscd_cfg_global_data_t,
		NULL,
		_nscd_cfg_switch_notify,
		_nscd_cfg_switch_verify),

	NSCD_CFG_PARAM_DESC(
		"global-enable-lookup",
		NSCD_CFG_DATA_BOOLEAN,
		NSCD_CFG_PFLAG_GLOBAL,
		enable_lookup_g,
		nscd_cfg_global_switch_t,
		sw,
		nscd_cfg_global_data_t,
		NULL,
		NSCD_CFG_FUNC_NOTIFY_AS_GROUP,
		NSCD_CFG_FUNC_VERIFY_AS_GROUP),

	NSCD_CFG_PARAM_DESC(
		"global-enable-loopback-checking",
		NSCD_CFG_DATA_BOOLEAN,
		NSCD_CFG_PFLAG_GLOBAL,
		enable_loopback_checking_g,
		nscd_cfg_global_switch_t,
		sw,
		nscd_cfg_global_data_t,
		NULL,
		NSCD_CFG_FUNC_NOTIFY_AS_GROUP,
		NSCD_CFG_FUNC_VERIFY_AS_GROUP),

	NSCD_CFG_PARAM_DESC(
		"global-check-smf-state-interval",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_PFLAG_GLOBAL,
		check_smf_state_interval_g,
		nscd_cfg_global_switch_t,
		sw,
		nscd_cfg_global_data_t,
		NULL,
		NSCD_CFG_FUNC_NOTIFY_AS_GROUP,
		NSCD_CFG_FUNC_VERIFY_AS_GROUP),

	NSCD_CFG_PGROUP_DESC(
		"param-group-global-cache",
		NSCD_CFG_DATA_NONE,
		NSCD_CFG_PFLAG_INIT_SEND_WHOLE_GROUP |
		NSCD_CFG_PFLAG_INIT_SET_ALL_DB |
		NSCD_CFG_PFLAG_GLOBAL,
		cache,
		nscd_cfg_global_data_t,
		NULL,
		_nscd_cfg_cache_notify,
		_nscd_cfg_cache_verify),

	NSCD_CFG_PARAM_DESC(
		"global-enable-cache",
		NSCD_CFG_DATA_BOOLEAN,
		NSCD_CFG_PFLAG_GLOBAL,
		enable,
		nscd_cfg_global_cache_t,
		cache,
		nscd_cfg_global_data_t,
		NULL,
		NSCD_CFG_FUNC_NOTIFY_AS_GROUP,
		NSCD_CFG_FUNC_VERIFY_AS_GROUP),

	/* non-global config param from this point on */

	NSCD_CFG_PGROUP_DESC(
		"param-group-frontend",
		NSCD_CFG_DATA_NONE,
		NSCD_CFG_PFLAG_INIT_SEND_WHOLE_GROUP,
		fe,
		nscd_cfg_nsw_db_data_t,
		NULL,
		_nscd_cfg_frontend_notify,
		_nscd_cfg_frontend_verify),

	NSCD_CFG_PARAM_DESC(
		"worker-thread-per-nsw-db",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_PFLAG_NONE,
		worker_thread_per_nsw_db,
		nscd_cfg_frontend_t,
		fe,
		nscd_cfg_nsw_db_data_t,
		NULL,
		NSCD_CFG_FUNC_NOTIFY_AS_GROUP,
		NSCD_CFG_FUNC_VERIFY_AS_GROUP),

	NSCD_CFG_PGROUP_DESC(
		"param-group-switch",
		NSCD_CFG_DATA_NONE,
		NSCD_CFG_PFLAG_INIT_SEND_WHOLE_GROUP |
		NSCD_CFG_PFLAG_NONE,
		sw,
		nscd_cfg_nsw_db_data_t,
		NULL,
		_nscd_cfg_switch_notify,
		_nscd_cfg_switch_verify),

	NSCD_CFG_PARAM_DESC(
		"nsw-config-string",
		NSCD_CFG_DATA_STRING,
		NSCD_CFG_PFLAG_VLEN_DATA |
		NSCD_CFG_PFLAG_LINKED,
		nsw_config_string,
		nscd_cfg_switch_t,
		sw,
		nscd_cfg_nsw_db_data_t,
		&NSCD_CFG_NSWCFGSTR_PCHECK,
		NSCD_CFG_FUNC_NOTIFY_AS_GROUP,
		NSCD_CFG_FUNC_VERIFY_AS_GROUP),

	NSCD_CFG_PARAM_DESC(
		"nsw-config-database",
		NSCD_CFG_DATA_STRING,
		NSCD_CFG_PFLAG_VLEN_DATA |
		NSCD_CFG_PFLAG_HIDDEN,
		nsw_config_db,
		nscd_cfg_switch_t,
		sw,
		nscd_cfg_nsw_db_data_t,
		&NSCD_CFG_NSWCFGSTR_PCHECK,
		NSCD_CFG_FUNC_NOTIFY_AS_GROUP,
		NSCD_CFG_FUNC_VERIFY_AS_GROUP),

	NSCD_CFG_PARAM_DESC(
		"enable-lookup",
		NSCD_CFG_DATA_BOOLEAN,
		NSCD_CFG_PFLAG_NONE,
		enable_lookup,
		nscd_cfg_switch_t,
		sw,
		nscd_cfg_nsw_db_data_t,
		NULL,
		NSCD_CFG_FUNC_NOTIFY_AS_GROUP,
		NSCD_CFG_FUNC_VERIFY_AS_GROUP),

	NSCD_CFG_PARAM_DESC(
		"enable-loopback-checking",
		NSCD_CFG_DATA_BOOLEAN,
		NSCD_CFG_PFLAG_NONE,
		enable_loopback_checking,
		nscd_cfg_switch_t,
		sw,
		nscd_cfg_nsw_db_data_t,
		NULL,
		NSCD_CFG_FUNC_NOTIFY_AS_GROUP,
		NSCD_CFG_FUNC_VERIFY_AS_GROUP),

	NSCD_CFG_PARAM_DESC(
		"max-nsw-state-per-db",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_PFLAG_NONE,
		max_nsw_state_per_db,
		nscd_cfg_switch_t,
		sw,
		nscd_cfg_nsw_db_data_t,
		NULL,
		NSCD_CFG_FUNC_NOTIFY_AS_GROUP,
		NSCD_CFG_FUNC_VERIFY_AS_GROUP),

	NSCD_CFG_PARAM_DESC(
		"max-nsw-state-per-thread",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_PFLAG_NONE,
		max_nsw_state_per_thread,
		nscd_cfg_switch_t,
		sw,
		nscd_cfg_nsw_db_data_t,
		NULL,
		NSCD_CFG_FUNC_NOTIFY_AS_GROUP,
		NSCD_CFG_FUNC_VERIFY_AS_GROUP),

	NSCD_CFG_PARAM_DESC(
		"max-getent-ctx-per-db",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_PFLAG_NONE,
		max_getent_ctx_per_db,
		nscd_cfg_switch_t,
		sw,
		nscd_cfg_nsw_db_data_t,
		NULL,
		NSCD_CFG_FUNC_NOTIFY_AS_GROUP,
		NSCD_CFG_FUNC_VERIFY_AS_GROUP),

	NSCD_CFG_PGROUP_DESC(
		"param-group-cache",
		NSCD_CFG_DATA_NONE,
		NSCD_CFG_PFLAG_INIT_SEND_WHOLE_GROUP,
		cache,
		nscd_cfg_nsw_db_data_t,
		NULL,
		_nscd_cfg_cache_notify,
		_nscd_cfg_cache_verify),

	NSCD_CFG_PARAM_DESC(
		"enable-cache",
		NSCD_CFG_DATA_BOOLEAN,
		NSCD_CFG_PFLAG_NONE,
		enable,
		nscd_cfg_cache_t,
		cache,
		nscd_cfg_nsw_db_data_t,
		NULL,
		NSCD_CFG_FUNC_NOTIFY_AS_GROUP,
		NSCD_CFG_FUNC_VERIFY_AS_GROUP),

	NSCD_CFG_PARAM_DESC(
		"enable-per-user-cache",
		NSCD_CFG_DATA_BOOLEAN,
		NSCD_CFG_PFLAG_NONE,
		per_user,
		nscd_cfg_cache_t,
		cache,
		nscd_cfg_nsw_db_data_t,
		NULL,
		NSCD_CFG_FUNC_NOTIFY_AS_GROUP,
		NSCD_CFG_FUNC_VERIFY_AS_GROUP),

	NSCD_CFG_PARAM_DESC(
		"avoid-nameservice",
		NSCD_CFG_DATA_BOOLEAN,
		NSCD_CFG_PFLAG_NONE,
		avoid_ns,
		nscd_cfg_cache_t,
		cache,
		nscd_cfg_nsw_db_data_t,
		NULL,
		NSCD_CFG_FUNC_NOTIFY_AS_GROUP,
		NSCD_CFG_FUNC_VERIFY_AS_GROUP),

	NSCD_CFG_PARAM_DESC(
		"check-files",
		NSCD_CFG_DATA_BOOLEAN,
		NSCD_CFG_PFLAG_NONE,
		check_files,
		nscd_cfg_cache_t,
		cache,
		nscd_cfg_nsw_db_data_t,
		NULL,
		NSCD_CFG_FUNC_NOTIFY_AS_GROUP,
		NSCD_CFG_FUNC_VERIFY_AS_GROUP),

	NSCD_CFG_PARAM_DESC(
		"check-file-interval",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_PFLAG_NONE,
		check_interval,
		nscd_cfg_cache_t,
		cache,
		nscd_cfg_nsw_db_data_t,
		NULL,
		NSCD_CFG_FUNC_NOTIFY_AS_GROUP,
		NSCD_CFG_FUNC_VERIFY_AS_GROUP),

	NSCD_CFG_PARAM_DESC(
		"positive-time-to-live",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_PFLAG_NONE,
		pos_ttl,
		nscd_cfg_cache_t,
		cache,
		nscd_cfg_nsw_db_data_t,
		NULL,
		NSCD_CFG_FUNC_NOTIFY_AS_GROUP,
		NSCD_CFG_FUNC_VERIFY_AS_GROUP),

	NSCD_CFG_PARAM_DESC(
		"negative-time-to-live",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_PFLAG_NONE,
		neg_ttl,
		nscd_cfg_cache_t,
		cache,
		nscd_cfg_nsw_db_data_t,
		NULL,
		NSCD_CFG_FUNC_NOTIFY_AS_GROUP,
		NSCD_CFG_FUNC_VERIFY_AS_GROUP),

	NSCD_CFG_PARAM_DESC(
		"keep-hot-count",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_PFLAG_NONE,
		keephot,
		nscd_cfg_cache_t,
		cache,
		nscd_cfg_nsw_db_data_t,
		NULL,
		NSCD_CFG_FUNC_NOTIFY_AS_GROUP,
		NSCD_CFG_FUNC_VERIFY_AS_GROUP),

	NSCD_CFG_PARAM_DESC(
		"hint-size",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_PFLAG_NONE,
		hint_size,
		nscd_cfg_cache_t,
		cache,
		nscd_cfg_nsw_db_data_t,
		NULL,
		NSCD_CFG_FUNC_NOTIFY_AS_GROUP,
		NSCD_CFG_FUNC_VERIFY_AS_GROUP),

	NSCD_CFG_PARAM_DESC(
		"maximum-entries-allowed",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_PFLAG_NONE,
		maxentries,
		nscd_cfg_cache_t,
		cache,
		nscd_cfg_nsw_db_data_t,
		NULL,
		NSCD_CFG_FUNC_NOTIFY_AS_GROUP,
		NSCD_CFG_FUNC_VERIFY_AS_GROUP),

	NSCD_CFG_PARAM_DESC(
		"suggested-size",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_PFLAG_OBSOLETE,
		suggestedsize,
		nscd_cfg_cache_t,
		cache,
		nscd_cfg_nsw_db_data_t,
		NULL,
		NSCD_CFG_FUNC_NOTIFY_AS_GROUP,
		NSCD_CFG_FUNC_VERIFY_AS_GROUP),

	NSCD_CFG_PARAM_DESC(
		"old-data-ok",
		NSCD_CFG_DATA_BOOLEAN,
		NSCD_CFG_PFLAG_OBSOLETE,
		old_data_ok,
		nscd_cfg_cache_t,
		cache,
		nscd_cfg_nsw_db_data_t,
		NULL,
		NSCD_CFG_FUNC_NOTIFY_AS_GROUP,
		NSCD_CFG_FUNC_VERIFY_AS_GROUP),

	NSCD_CFG_PGROUP_DESC_NULL
};

/*
 * defaults for the global configuration
 */
static nscd_cfg_global_data_t nscd_cfg_global_default = {

	/*
	 * nscd_cfg_global_log_t
	 */
	{

	NSCD_CFG_GROUP_INFO_GLOBAL_LOG,
	NULL,
	NSCD_LOG_LEVEL_NONE,	/* debug_level */
	NSCD_LOG_CACHE,		/* debug_comp */

	},

	/*
	 * nscd_cfg_global_frontend_t
	 */
	{

	NSCD_CFG_GROUP_INFO_GLOBAL_FRONTEND,
	100,			/* common_worker_threads */
	100,			/* cache_hit_threads */

	},

	/*
	 * nscd_cfg_global_selfcred_t
	 */
	{

	NSCD_CFG_GROUP_INFO_GLOBAL_SELFCRED,
	nscd_true,		/* enable_selfcred */
	120,			/* per_user_nscd_ttl: 120 seconds */

	},

	/*
	 * nscd_cfg_global_switch_t
	 */
	{

	NSCD_CFG_GROUP_INFO_GLOBAL_SWITCH,
	nscd_true,		/* enable_lookup_g */
	nscd_false,		/* enable_loopback_checking_g */
	120,			/* check_smf_state_interval_g */

	},

	/*
	 * nscd_cfg_global_cache_t
	 */
	NSCD_CFG_GLOBAL_CACHE_DEFAULTS
};

/*
 * defaults for the per switch database configuration
 */
static nscd_cfg_nsw_db_data_t nscd_cfg_nsw_db_data_default = {

	/*
	 * nscd_cfg_frontend_t
	 */
	{

	NSCD_CFG_GROUP_INFO_FRONTEND,
	50,			/* worker_thread_per_nsw_db */

	},

	/*
	 * nscd_cfg_switch_t
	 */
	{

	NSCD_CFG_GROUP_INFO_SWITCH,
	"nis files",		/* nsw_config_string */
	NULL,			/* nsw_config_db */
	nscd_true,		/* enable_lookup */
	nscd_false,		/* enable_loopback_checking */
	288,			/* max_nsw_state_per_db */
	32,			/* max_nsw_state_per_thread */
	256,			/* max_getent_ctx_per_db */

	},

	/*
	 * nscd_cfg_cache_t
	 */
	NSCD_CFG_CACHE_DEFAULTS
};

/*
 * macros for defining the database specific defaults
 */
#define	NSCD_CFG_DB_DEFAULT_PARAM(db, gf, pf, gt, defaddr, deflen) \
	{ \
		db, offsetof(nscd_cfg_nsw_db_data_t, gf), \
		offsetof(gt, pf), defaddr, deflen \
	}

#define	NSCD_CFG_DB_DEFAULT_GROUP(db, gf, defaddr, deflen) \
	{ \
		db, offsetof(nscd_cfg_nsw_db_data_t, gf), \
		0, defaddr, deflen \
	}

#define	NSCD_CFG_DB_DEFAULT_NULL \
	{ \
		NULL, 0, 0, NULL, 0 \
	}

/*
 * shadow, and user_attr use the same switch policy
 * as that of passwd. exec_attr use that of prof_attr.
 */
static char *nscd_cfg_shadow_cfg_db	= NSS_DBNAM_PASSWD;
static char *nscd_cfg_userattr_cfg_db	= NSS_DBNAM_PASSWD;
static char *nscd_cfg_execattr_cfg_db	= NSS_DBNAM_PROFATTR;

/*
 * default switch policy for pseudo-databases passwd_compat and
 * and group_compa is "nis"
 */
static char *nscd_cfg_def_passwd_compat	= NSS_DEFCONF_PASSWD_COMPAT;
static char *nscd_cfg_def_group_compat	= NSS_DEFCONF_GROUP_COMPAT;

static nscd_cfg_nsw_spc_default_t nscd_cfg_passwd_cfg_link =
	NSCD_CFG_DB_DEFAULT_PARAM(
		NSS_DBNAM_PASSWD,
		sw,
		nsw_config_string,
		nscd_cfg_switch_t,
		NULL,
		NSCD_SIZEOF(nscd_cfg_switch_t, nsw_config_string));

static nscd_cfg_nsw_spc_default_t nscd_cfg_profattr_cfg_link =
	NSCD_CFG_DB_DEFAULT_PARAM(
		NSS_DBNAM_PROFATTR,
		sw,
		nsw_config_string,
		nscd_cfg_switch_t,
		NULL,
		NSCD_SIZEOF(nscd_cfg_switch_t, nsw_config_string));


/*
 * switch database specific defaults
 */
nscd_cfg_nsw_spc_default_t	_nscd_cfg_nsw_spc_default[] = {

	NSCD_CFG_DB_DEFAULT_PARAM(
	NSS_DBNAM_SHADOW,
		sw,
		nsw_config_db,
		nscd_cfg_switch_t,
		&nscd_cfg_shadow_cfg_db,
		sizeof (nscd_cfg_shadow_cfg_db)),

	NSCD_CFG_DB_DEFAULT_PARAM(
		NSS_DBNAM_USERATTR,
		sw,
		nsw_config_db,
		nscd_cfg_switch_t,
		&nscd_cfg_userattr_cfg_db,
		sizeof (nscd_cfg_userattr_cfg_db)),

	NSCD_CFG_DB_DEFAULT_PARAM(
		NSS_DBNAM_EXECATTR,
		sw,
		nsw_config_db,
		nscd_cfg_switch_t,
		&nscd_cfg_execattr_cfg_db,
		sizeof (nscd_cfg_execattr_cfg_db)),

	NSCD_CFG_DB_DEFAULT_PARAM(
		NSS_DBNAM_PASSWD_COMPAT,
		sw,
		nsw_config_string,
		nscd_cfg_switch_t,
		&nscd_cfg_def_passwd_compat,
		sizeof (nscd_cfg_def_passwd_compat)),

	NSCD_CFG_DB_DEFAULT_PARAM(
		NSS_DBNAM_GROUP_COMPAT,
		sw,
		nsw_config_string,
		nscd_cfg_switch_t,
		&nscd_cfg_def_group_compat,
		sizeof (nscd_cfg_def_group_compat)),

	NSCD_CFG_DB_DEFAULT_NULL
};

/*
 * switch database specific defaults that are linked to
 * those of other databases
 */
nscd_cfg_nsw_spc_default_t	_nscd_cfg_nsw_link_default[] = {

	NSCD_CFG_DB_DEFAULT_PARAM(
		NSS_DBNAM_SHADOW,
		sw,
		nsw_config_string,
		nscd_cfg_switch_t,
		&nscd_cfg_passwd_cfg_link,
		0),

	NSCD_CFG_DB_DEFAULT_PARAM(
		NSS_DBNAM_USERATTR,
		sw,
		nsw_config_string,
		nscd_cfg_switch_t,
		&nscd_cfg_passwd_cfg_link,
		0),

	NSCD_CFG_DB_DEFAULT_PARAM(
		NSS_DBNAM_AUDITUSER,
		sw,
		nsw_config_string,
		nscd_cfg_switch_t,
		&nscd_cfg_passwd_cfg_link,
		0),

	NSCD_CFG_DB_DEFAULT_PARAM(
		NSS_DBNAM_EXECATTR,
		sw,
		nsw_config_string,
		nscd_cfg_switch_t,
		&nscd_cfg_profattr_cfg_link,
		0),

	NSCD_CFG_DB_DEFAULT_NULL
};

/*
 * macros for defining the static stats table
 */
#define	NSCD_CFG_SGROUP_DESC(sn, type, sflag, gi, \
		gf, g_in_t, gsfunc_name) \
	{ \
		{-1, sn}, type, NSCD_CFG_SFLAG_GROUP | sflag, gi, \
		0, 0, 0,\
		NSCD_SIZEOF(g_in_t, gf), offsetof(g_in_t, gf), -1, \
		gsfunc_name \
	}

#define	NSCD_CFG_STAT_DESC(sn, type, sflag, sf, s_in_t, \
		gf, g_in_t, gsfunc_name) \
	{ \
		{-1, sn}, type, sflag, NSCD_CFG_GROUP_INFO_NULL, \
		NSCD_SIZEOF(s_in_t, sf), offsetof(s_in_t, sf), -1, \
		NSCD_SIZEOF(g_in_t, gf), offsetof(g_in_t, gf), -1, \
		gsfunc_name \
	}

#define	NSCD_CFG_SGROUP_DESC_NULL \
	{ \
		{-1, NULL}, -1, NSCD_CFG_SFLAG_GROUP, 0, \
		0, 0, 0, \
		0, 0, 0, \
		0 \
	}

/*
 * the static statistics description table
 */
static	nscd_cfg_stat_desc_t	_nscd_cfg_stat_desc[] = {

	NSCD_CFG_SGROUP_DESC(
		"stat-group-global-log",
		NSCD_CFG_DATA_NONE,
		NSCD_CFG_SFLAG_GLOBAL,
		NSCD_CFG_STAT_GROUP_INFO_GLOBAL_LOG,
		log,
		nscd_cfg_stat_global_data_t,
		_nscd_cfg_log_get_stat),

	NSCD_CFG_STAT_DESC(
		"entries-logged",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_SFLAG_GLOBAL,
		entries_logged,
		nscd_cfg_stat_global_log_t,
		log,
		nscd_cfg_stat_global_data_t,
		NSCD_CFG_FUNC_GET_STAT_AS_GROUP),

	NSCD_CFG_SGROUP_DESC(
		"stat-group-global-switch",
		NSCD_CFG_DATA_NONE,
		NSCD_CFG_SFLAG_GLOBAL,
		NSCD_CFG_STAT_GROUP_INFO_GLOBAL_SWITCH,
		sw,
		nscd_cfg_stat_global_data_t,
		_nscd_cfg_switch_get_stat),

	NSCD_CFG_STAT_DESC(
		"global-lookup-request-received",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_SFLAG_GLOBAL,
		lookup_request_received_g,
		nscd_cfg_stat_global_switch_t,
		sw,
		nscd_cfg_stat_global_data_t,
		NSCD_CFG_FUNC_GET_STAT_AS_GROUP),

	NSCD_CFG_STAT_DESC(
		"global-lookup-request-queued",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_SFLAG_GLOBAL,
		lookup_request_queued_g,
		nscd_cfg_stat_global_switch_t,
		sw,
		nscd_cfg_stat_global_data_t,
		NSCD_CFG_FUNC_GET_STAT_AS_GROUP),

	NSCD_CFG_STAT_DESC(
		"global-lookup-request-in-progress",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_SFLAG_GLOBAL,
		lookup_request_in_progress_g,
		nscd_cfg_stat_global_switch_t,
		sw,
		nscd_cfg_stat_global_data_t,
		NSCD_CFG_FUNC_GET_STAT_AS_GROUP),

	NSCD_CFG_STAT_DESC(
		"global-lookup-request-succeeded",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_SFLAG_GLOBAL,
		lookup_request_succeeded_g,
		nscd_cfg_stat_global_switch_t,
		sw,
		nscd_cfg_stat_global_data_t,
		NSCD_CFG_FUNC_GET_STAT_AS_GROUP),

	NSCD_CFG_STAT_DESC(
		"global-lookup-request-failed",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_SFLAG_GLOBAL,
		lookup_request_failed_g,
		nscd_cfg_stat_global_switch_t,
		sw,
		nscd_cfg_stat_global_data_t,
		NSCD_CFG_FUNC_GET_STAT_AS_GROUP),

	NSCD_CFG_STAT_DESC(
		"global-loopback-nsw-db-skipped",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_SFLAG_GLOBAL,
		loopback_nsw_db_skipped_g,
		nscd_cfg_stat_global_switch_t,
		sw,
		nscd_cfg_stat_global_data_t,
		NSCD_CFG_FUNC_GET_STAT_AS_GROUP),

	NSCD_CFG_SGROUP_DESC(
		"stat-group-global-cache",
		NSCD_CFG_DATA_NONE,
		NSCD_CFG_SFLAG_GLOBAL,
		NSCD_CFG_STAT_GROUP_INFO_CACHE,
		cache,
		nscd_cfg_stat_global_data_t,
		_nscd_cfg_cache_get_stat),

	NSCD_CFG_STAT_DESC(
		"global-cache-hits-on-positive",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_SFLAG_GLOBAL,
		pos_hits,
		nscd_cfg_stat_cache_t,
		cache,
		nscd_cfg_stat_global_data_t,
		NSCD_CFG_FUNC_GET_STAT_AS_GROUP),

	NSCD_CFG_STAT_DESC(
		"global-cache-hits-on-negative",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_SFLAG_GLOBAL,
		neg_hits,
		nscd_cfg_stat_cache_t,
		cache,
		nscd_cfg_stat_global_data_t,
		NSCD_CFG_FUNC_GET_STAT_AS_GROUP),

	NSCD_CFG_STAT_DESC(
		"global-cache-misses-on-positive",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_SFLAG_GLOBAL,
		pos_misses,
		nscd_cfg_stat_cache_t,
		cache,
		nscd_cfg_stat_global_data_t,
		NSCD_CFG_FUNC_GET_STAT_AS_GROUP),

	NSCD_CFG_STAT_DESC(
		"global-cache-misses-on-negative",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_SFLAG_GLOBAL,
		neg_misses,
		nscd_cfg_stat_cache_t,
		cache,
		nscd_cfg_stat_global_data_t,
		NSCD_CFG_FUNC_GET_STAT_AS_GROUP),

	NSCD_CFG_STAT_DESC(
		"global-cache-queries-queued",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_SFLAG_GLOBAL,
		wait_count,
		nscd_cfg_stat_cache_t,
		cache,
		nscd_cfg_stat_global_data_t,
		NSCD_CFG_FUNC_GET_STAT_AS_GROUP),

	NSCD_CFG_STAT_DESC(
		"global-total-cache-entries",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_SFLAG_GLOBAL,
		entries,
		nscd_cfg_stat_cache_t,
		cache,
		nscd_cfg_stat_global_data_t,
		NSCD_CFG_FUNC_GET_STAT_AS_GROUP),

	NSCD_CFG_STAT_DESC(
		"global-complete-cache-invalidations",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_SFLAG_GLOBAL,
		invalidate_count,
		nscd_cfg_stat_cache_t,
		cache,
		nscd_cfg_stat_global_data_t,
		NSCD_CFG_FUNC_GET_STAT_AS_GROUP),

	NSCD_CFG_STAT_DESC(
		"global-cache-queries-dropped",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_SFLAG_GLOBAL,
		drop_count,
		nscd_cfg_stat_cache_t,
		cache,
		nscd_cfg_stat_global_data_t,
		NSCD_CFG_FUNC_GET_STAT_AS_GROUP),

	NSCD_CFG_STAT_DESC(
		"global-cache-hit-rate",
		NSCD_CFG_DATA_PERCENT,
		NSCD_CFG_SFLAG_GLOBAL,
		hitrate,
		nscd_cfg_stat_cache_t,
		cache,
		nscd_cfg_stat_global_data_t,
		NSCD_CFG_FUNC_GET_STAT_AS_GROUP),

	/* non-global stat from this point on */

	NSCD_CFG_SGROUP_DESC(
		"stat-group-switch",
		NSCD_CFG_DATA_NONE,
		NSCD_CFG_SFLAG_GROUP,
		NSCD_CFG_STAT_GROUP_INFO_SWITCH,
		cache,
		nscd_cfg_stat_nsw_db_data_t,
		_nscd_cfg_switch_get_stat),

	NSCD_CFG_STAT_DESC(
		"lookup-request-received",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_SFLAG_NONE,
		lookup_request_received,
		nscd_cfg_stat_switch_t,
		sw,
		nscd_cfg_stat_nsw_db_data_t,
		NSCD_CFG_FUNC_GET_STAT_AS_GROUP),

	NSCD_CFG_STAT_DESC(
		"lookup-request-queued",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_SFLAG_NONE,
		lookup_request_queued,
		nscd_cfg_stat_switch_t,
		sw,
		nscd_cfg_stat_nsw_db_data_t,
		NSCD_CFG_FUNC_GET_STAT_AS_GROUP),

	NSCD_CFG_STAT_DESC(
		"lookup-request-in-progress",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_SFLAG_NONE,
		lookup_request_in_progress,
		nscd_cfg_stat_switch_t,
		sw,
		nscd_cfg_stat_nsw_db_data_t,
		NSCD_CFG_FUNC_GET_STAT_AS_GROUP),

	NSCD_CFG_STAT_DESC(
		"lookup-request-succeeded",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_SFLAG_NONE,
		lookup_request_succeeded,
		nscd_cfg_stat_switch_t,
		sw,
		nscd_cfg_stat_nsw_db_data_t,
		NSCD_CFG_FUNC_GET_STAT_AS_GROUP),

	NSCD_CFG_STAT_DESC(
		"lookup-request-failed",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_SFLAG_NONE,
		lookup_request_failed,
		nscd_cfg_stat_switch_t,
		sw,
		nscd_cfg_stat_nsw_db_data_t,
		NSCD_CFG_FUNC_GET_STAT_AS_GROUP),

	NSCD_CFG_STAT_DESC(
		"loopback-nsw-db-skipped",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_SFLAG_NONE,
		loopback_nsw_db_skipped,
		nscd_cfg_stat_switch_t,
		sw,
		nscd_cfg_stat_nsw_db_data_t,
		NSCD_CFG_FUNC_GET_STAT_AS_GROUP),

	NSCD_CFG_SGROUP_DESC(
		"stat-group-cache",
		NSCD_CFG_DATA_NONE,
		NSCD_CFG_SFLAG_GROUP,
		NSCD_CFG_STAT_GROUP_INFO_CACHE,
		cache,
		nscd_cfg_stat_nsw_db_data_t,
		_nscd_cfg_cache_get_stat),

	NSCD_CFG_STAT_DESC(
		"cache-hits-on-positive",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_SFLAG_NONE,
		pos_hits,
		nscd_cfg_stat_cache_t,
		cache,
		nscd_cfg_stat_nsw_db_data_t,
		NSCD_CFG_FUNC_GET_STAT_AS_GROUP),

	NSCD_CFG_STAT_DESC(
		"cache-hits-on-negative",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_SFLAG_NONE,
		neg_hits,
		nscd_cfg_stat_cache_t,
		cache,
		nscd_cfg_stat_nsw_db_data_t,
		NSCD_CFG_FUNC_GET_STAT_AS_GROUP),

	NSCD_CFG_STAT_DESC(
		"cache-misses-on-positive",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_SFLAG_NONE,
		pos_misses,
		nscd_cfg_stat_cache_t,
		cache,
		nscd_cfg_stat_nsw_db_data_t,
		NSCD_CFG_FUNC_GET_STAT_AS_GROUP),

	NSCD_CFG_STAT_DESC(
		"cache-misses-on-negative",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_SFLAG_NONE,
		neg_misses,
		nscd_cfg_stat_cache_t,
		cache,
		nscd_cfg_stat_nsw_db_data_t,
		NSCD_CFG_FUNC_GET_STAT_AS_GROUP),

	NSCD_CFG_STAT_DESC(
		"cache-queries-queued",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_SFLAG_NONE,
		wait_count,
		nscd_cfg_stat_cache_t,
		cache,
		nscd_cfg_stat_nsw_db_data_t,
		NSCD_CFG_FUNC_GET_STAT_AS_GROUP),

	NSCD_CFG_STAT_DESC(
		"total-cache-entries",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_SFLAG_NONE,
		entries,
		nscd_cfg_stat_cache_t,
		cache,
		nscd_cfg_stat_nsw_db_data_t,
		NSCD_CFG_FUNC_GET_STAT_AS_GROUP),

	NSCD_CFG_STAT_DESC(
		"complete-cache-invalidations",
		NSCD_CFG_DATA_INTEGER,
		NSCD_CFG_SFLAG_NONE,
		invalidate_count,
		nscd_cfg_stat_cache_t,
		cache,
		nscd_cfg_stat_nsw_db_data_t,
		NSCD_CFG_FUNC_GET_STAT_AS_GROUP),

	NSCD_CFG_STAT_DESC(
		"cache-hit-rate",
		NSCD_CFG_DATA_PERCENT,
		NSCD_CFG_SFLAG_NONE,
		hitrate,
		nscd_cfg_stat_cache_t,
		cache,
		nscd_cfg_stat_nsw_db_data_t,
		NSCD_CFG_FUNC_GET_STAT_AS_GROUP),

	NSCD_CFG_STAT_DESC(
		"cache-queries-dropped",
		NSCD_CFG_DATA_PERCENT,
		NSCD_CFG_SFLAG_NONE,
		drop_count,
		nscd_cfg_stat_cache_t,
		cache,
		nscd_cfg_stat_nsw_db_data_t,
		NSCD_CFG_FUNC_GET_STAT_AS_GROUP),


	NSCD_CFG_SGROUP_DESC_NULL
};

/* number of entries in the static tables */

int _nscd_cfg_num_nsw_src =
	(sizeof (_nscd_cfg_nsw_src) /
		sizeof (_nscd_cfg_nsw_src[0]) - 1);

int _nscd_cfg_num_smf_services =
	(sizeof (_nscd_cfg_smf_services) /
		sizeof (_nscd_cfg_smf_services[0]) - 1);

/* number of supported nsw databases (including pseudo ones) */
int _nscd_cfg_num_nsw_db_all =
	(sizeof (_nscd_cfg_nsw_db) /
		sizeof (_nscd_cfg_nsw_db[0]) - 1);

/* number of supported nsw databases (not including pseudo ones) */
int _nscd_cfg_num_nsw_db =
	(sizeof (_nscd_cfg_nsw_db) /
		sizeof (_nscd_cfg_nsw_db[0]) - 1) -
		NSS_DBNAM_COMPAT_NUM_DB;

static int _nscd_cfg_num_param =
	(sizeof (_nscd_cfg_param_desc) /
		sizeof (_nscd_cfg_param_desc[0]) - 1);

static int _nscd_cfg_num_stat =
	(sizeof (_nscd_cfg_stat_desc) /
		sizeof (_nscd_cfg_stat_desc[0]) - 1);

int _nscd_cfg_num_nsw_default =
	(sizeof (_nscd_cfg_nsw_spc_default) /
		sizeof (_nscd_cfg_nsw_spc_default[0]) - 1);

int _nscd_cfg_num_link_default =
	(sizeof (_nscd_cfg_nsw_link_default) /
		sizeof (_nscd_cfg_nsw_link_default[0]) - 1);

#ifdef	__cplusplus
}
#endif

#endif	/* _NSCD_CFGDEF_H */
