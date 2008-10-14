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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef	_SDBC_IOCTL_H
#define	_SDBC_IOCTL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/unistat/spcs_s.h>  /* included for unistat */

/*
 * Generic sdbc ioctl arguments structure.
 * Individual ioctl's will use 0-n of these arguments.
 *
 * Each sdbc ioctl is described first by the command number
 * e.g. #define	SDBC_ADUMP		_SDBC_(4)
 *
 * Followed by a description of each argument (if any).
 * Each argument is on a single line.
 *
 */

typedef struct _sdbc_ioctl_s {
	long arg0;
	long arg1;
	long arg2;
	long arg3;
	long arg4;
	long magic;
	spcs_s_info_t sdbc_ustatus;
	long pad[1];
} _sdbc_ioctl_t;

typedef struct _sdbc_ioctl32_s {
	int32_t arg0;
	int32_t arg1;
	int32_t arg2;
	int32_t arg3;
	int32_t arg4;
	int32_t magic;
	spcs_s_info32_t sdbc_ustatus;
	int32_t pad[1];
} _sdbc_ioctl32_t;

/*
 * Ioctl command numbers
 */

#define	_SDBC_(x)	(('B'<<16)|('C'<<8)|(x))

/*
 * Old ioctl commands prior to ioctl reorg. These could be re-used
 * at a later date
 */
#define	SDBC_UNUSED_1 _SDBC_(1)	/* OLD out of date syscall -> ioctl stuff */
#define	SDBC_UNUSED_2 _SDBC_(2)	/* OLD INFSD_CONC_WRITE */
#define	SDBC_UNUSED_3 _SDBC_(3)	/* OLD muli-subopcode configuration */

#define	SDBC_ADUMP _SDBC_(4)
/*
 *	int		cd;
 *	_sdtr_table *	table;
 *	_sdtr_t *	trace_buffer;
 *	int		size_of_trace_buffer;
 *	int		flags;
 */

#define	SDBC_TEST_INIT _SDBC_(5)	/* TESTING - tdaemon parameters */
/*
 *	char *		device_name;
 *	int		index;
 *	int		len;
 *	int		track_size;
 *	int		flags;
 */

#define	SDBC_TEST_START _SDBC_(6)	/* TESTING - tdaemon .... */
/*
 *	int		num;
 *	int		type;
 *	int		loops;
 *	int		from;
 *	int		seed;
 */

#define	SDBC_TEST_END _SDBC_(7)		/* TESTING - tdaemon .... */
/* NO-ARGS */

#define	SDBC_ENABLE _SDBC_(8)		/* configure sdbc */
/*
 *	_sd_cache_param_t *	user_configuration;
 */

#define	SDBC_DISABLE _SDBC_(9)		/* deconfigure sdbc */
/* NO-ARGS */

#define	SDBC_SET_CD_HINT _SDBC_(10)
/*
 *	int		cd;
 *	int		hint;
 *	int		flags;
 */

#define	SDBC_GET_CD_HINT _SDBC_(11)
/*
 *	int		cd;
 */

#define	SDBC_SET_NODE_HINT _SDBC_(12)
/*
 *	int		hint;
 *	int		flags;
 */

#define	SDBC_GET_NODE_HINT _SDBC_(13)
/* NO-ARGS */

#define	SDBC_STATS _SDBC_(14)
/*
 *	_sd_stats_t *	stats buffer;
 */

#define	SDBC_ZAP_STATS _SDBC_(15)
/* NO-ARGS */

#define	SDBC_GET_CD_BLK _SDBC_(16)
/*
 *	int		cd;
 *	nsc_off_t *	block_number;
 *	void *		addresses[5];
 */

#define	SDBC_GET_CLUSTER_SIZE _SDBC_(17)
/*
 *	int *		cluster_size;
 */

#define	SDBC_GET_CLUSTER_DATA _SDBC_(18)
/*
 *	char *		buffer[2*cluster_size];
 */

#define	SDBC_GET_GLMUL_SIZES _SDBC_(19)
/*
 *	int *		global_sizes;
 */

#define	SDBC_GET_GLMUL_INFO _SDBC_(20)
/*
 *	char *		buffer[ 2 times sum of global_sizes];
 */

/* Unused _SDBC(21,22) */

#define	SDBC_STATE_DEV _SDBC_(23)	/* set path to sdbc state file/volume */
/*
 *	char *		device_name;
 *	int		device_name_length;
 */
#define	SDBC_TOGGLE_FLUSH _SDBC_(24)	/* TESTING - toggle flusher enable */
	/* NO-ARGS */

#define	SDBC_INJ_IOERR _SDBC_(25)	/* TESTING - inject i/o error */
/*
 *	int		cd
 *	int		io_error_number;
 */

#define	SDBC_CLR_IOERR _SDBC_(26)	/* TESTING - clear injected i/o error */
/*
 *	int		cd
 */

#define	SDBC_GET_CONFIG _SDBC_(27)	/* retrieve current configuration */
/*
 *	_sdbc_config_t *current_config;
 */

#define	SDBC_SET_CONFIG _SDBC_(28)	/* enable cache configuration info */
/*
 *	_sdbc_config_t *mgmt_config_info;
 */

/* Unused _SDBC(29) */

#define	SDBC_MAXFILES _SDBC_(30)	/* get maxfiles */
/*
 *	int *		max_files;
 */

#define	SDBC_VERSION	_SDBC_(31)
/*
 *	cache_version_t	*cache_version;
 */

#define	_SD_MAGIC   0xD017

#define	MAX_CACHE_NET	4
#define	MAX_REMOTE_MIRRORS 64
#define	MAX_MIR_SEGS MAX_REMOTE_MIRRORS
#define	MAX_CACHE_SIZE 1024

/* unexposed configuration bits */
#define	CFG_USE_DMCHAIN 0x1
#define	CFG_STATIC_CACHE 0x2

#define	RESERVED1_DEFAULTS (CFG_STATIC_CACHE)

/* maintain _sd_cache_param struct layout (MAX_CACHE_NET is deprecated) */
#define	CACHE_MEM_PAD 4

typedef struct _sd_cache_param {
	int mirror_host;
	int blk_size;
	int threads;
	int procs;
	int test_demons;
	int write_cache;
	int trace_size;
	int trace_mask;
	int trace_lbolt;
	int trace_good;
	int trace_net;				/* not used */
	int iobuf;
	int num_handles;
	int cache_mem[CACHE_MEM_PAD];
	int prot_lru;
	int gen_pattern;
	uint_t fill_pattern;
	short nodes_conf[MAX_REMOTE_MIRRORS];	/* Actual Nodes in conf file */
	short num_nodes;			/* Number of nodes in sd.cf */
	short net_type;				/*  not used */
	ushort_t magic;				/* Check for proper sd_cadmin */
	int reserved1;				/* unexposed config options */
	int reserved[8];
} _sd_cache_param_t;

typedef struct _sdbc_config {
	int cache_mem[CACHE_MEM_PAD];
	int threads;
	int enabled;
	ushort_t magic;
} _sdbc_config_t;

typedef struct cache_version {
	int	major;			/* Major release number */
	int	minor;			/* Minor release number */
	int	micro;			/* Micro release number */
	int	baseline;		/* Baseline revison number */
} cache_version_t;

#if !defined(_KERNEL)


/* Keep this definition in sync with the one in rdc_ioctl.h. */
#ifndef SDBC_IOCTL
#define	SDBC_IOCTL(cmd, a0, a1, a2, a3, a4, ustatus) \
		sdbc_ioctl((long)(cmd), (long)(a0), (long)(a1), (long)(a2), \
		    (long)(a3), (long)(a4), (spcs_s_info_t *)(ustatus))
#endif

int sdbc_ioctl(long, long, long, long, long, long, spcs_s_info_t *);


#endif	/* ! _KERNEL */

#ifdef __cplusplus
}
#endif

#endif	/* _SDBC_IOCTL_H */
