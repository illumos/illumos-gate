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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_DEVID_CACHE_H
#define	_SYS_DEVID_CACHE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/list.h>

/*
 * The top-level nvpair identifiers in the
 * /etc/devices/devid_cache nvlist format
 */
#define	DP_DEVID_ID			"devid"

#ifdef	_KERNEL

/* devid-specific list element */
typedef struct nvp_devid {
	int			nvp_flags;
	char			*nvp_devpath;
	dev_info_t		*nvp_dip;
	ddi_devid_t		nvp_devid;
	list_node_t		nvp_link;	/* link to next element */
} nvp_devid_t;


/*
 * nvp_flags - devid
 */
#define	NVP_DEVID_REGISTERED	0x01	/* devid registered on this boot */
#define	NVP_DEVID_DIP		0x02	/* devinfo valid for this devid */

/*
 * tunables - see devid_cache.c for more details
 */
extern int devid_discovery_boot;
extern int devid_discovery_postboot;
extern int devid_discovery_postboot_always;
extern int devid_discovery_secs;

extern int devid_cache_read_disable;
extern int devid_cache_write_disable;

/*
 * More thorough error reporting available both debug &
 * non-debug kernels, but turned off by default.
 */
extern int devid_report_error;		/* devid cache operations */


/*
 * function prototypes
 */
static int	devid_cache_pack_list(nvf_handle_t, nvlist_t **);
static int	devid_cache_unpack_nvlist(nvf_handle_t, nvlist_t *, char *);
static void	devid_list_free(nvf_handle_t);


#ifdef	DEBUG

#define	DEVID_DEBUG(args)	{ if (devid_debug) cmn_err args; }
#define	DEVID_DEBUG1(args)	{ if (devid_debug > 1) cmn_err args; }
#define	DEVID_DEBUG2(args)	{ if (devid_debug > 2) cmn_err args; }
#define	DEVID_DUMP(args)	{ if (devid_debug > 2) args; }
#define	DEVID_LOG_REG(args)	{ if (devid_log_registers) devid_log args; }
#define	DEVID_LOG_FIND(args)	{ if (devid_log_finds) devid_log args; }
#define	DEVID_LOG_LOOKUP(args)	{ if (devid_log_lookups) cmn_err args; }
#define	DEVID_LOG_MATCH(args)	{ if (devid_log_matches) devid_log args; }
#define	DEVID_LOG_PATHS(args)	{ if (devid_log_paths) cmn_err args; }
#define	DEVID_LOG_ERR(args)	{ if (devid_log_failures) devid_log args; }
#define	DEVID_LOG_DISC(args)	{ if (devid_log_discovery) cmn_err args; }
#define	DEVID_LOG_HOLD(args)	{ if (devid_log_hold) cmn_err args; }
#define	DEVID_LOG_UNREG(args)	{ if (devid_log_unregisters) cmn_err args; }
#define	DEVID_LOG_REMOVE(args)	{ if (devid_log_removes) cmn_err args; }
#define	DEVID_LOG_STALE(args)	{ if (devid_log_stale) devid_log args; }
#define	DEVID_LOG_DETACH(args)	{ if (devid_log_detaches) cmn_err args; }


#define	NVP_DEVID_DEBUG_PATH(arg) {					\
		if (nvp_devid_debug)					\
			cmn_err(CE_CONT, "%s\n", arg);			\
	}

#define	NVP_DEVID_DEBUG_DEVID(arg) {					\
		if (nvp_devid_debug) {					\
			char *ds = ddi_devid_str_encode(arg, NULL);	\
			cmn_err(CE_CONT, "devid: %s\n", ds);		\
			ddi_devid_str_free(ds);				\
		}							\
	}

static void devid_log(char *, ddi_devid_t, char *);

#else

#define	DEVID_DEBUG(args)
#define	DEVID_DEBUG1(args)
#define	DEVID_DEBUG2(args)
#define	DEVID_DUMP(args)
#define	DEVID_LOG_REG(args)
#define	DEVID_LOG_FIND(args)
#define	DEVID_LOG_LOOKUP(args)
#define	DEVID_LOG_MATCH(args)
#define	DEVID_LOG_PATHS(args)
#define	DEVID_LOG_ERR(args)
#define	DEVID_LOG_DISC(args)
#define	DEVID_LOG_HOLD(args)
#define	DEVID_LOG_UNREG(args)
#define	DEVID_LOG_REMOVE(args)
#define	DEVID_LOG_STALE(args)
#define	DEVID_LOG_DETACH(args)
#define	NVP_DEVID_DEBUG_PATH(arg)
#define	NVP_DEVID_DEBUG_DEVID(arg)

#endif	/* DEBUG */

#define	DEVIDERR(args)		{ if (devid_report_error) cmn_err args; }

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DEVID_CACHE_H */
