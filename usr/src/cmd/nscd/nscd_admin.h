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

#ifndef _NSCD_ADMIN_H
#define	_NSCD_ADMIN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include "cache.h"
#include "nscd_common.h"
#include "nscd_config.h"

#define	NSCD_LOGFILE_LEN 128

/*
 * structure used for door call NSCD_GETADMIN and NSCD_GETPUADMIN
 */
typedef struct nscd_admin {
	int			debug_level;
	char			logfile[NSCD_LOGFILE_LEN];
	nscd_cfg_cache_t	cache_cfg[CACHE_CTX_COUNT];
	nscd_cfg_stat_cache_t	cache_stats[CACHE_CTX_COUNT];
} nscd_admin_t;

/*
 * structure used for door call NSCD_SETADMIN and NSCD_SETPUADMIN
 */
typedef struct nscd_admin_mod {
	int			total_size;
	nscd_bool_t		debug_level_set;
	nscd_bool_t		logfile_set;
	uint8_t			cache_cfg_set[CACHE_CTX_COUNT];
	uint8_t			cache_flush_set[CACHE_CTX_COUNT];
	nscd_bool_t		global_cfg_set;
	uint8_t			cache_cfg_num;
	uint8_t			cache_flush_num;
	int			debug_level;
	char			logfile[NSCD_LOGFILE_LEN];
	nscd_cfg_cache_t	cache_cfg[CACHE_CTX_COUNT];
} nscd_admin_mod_t;

#ifdef	__cplusplus
}
#endif

int _nscd_client_getadmin(char opt);
int _nscd_client_setadmin();
void _nscd_client_showstats();
nscd_rc_t _nscd_server_setadmin(nscd_admin_mod_t *set);
int _nscd_door_getadmin(void *outbuf);
void _nscd_door_setadmin(void *buf);
int _nscd_add_admin_mod(char *dbname, char opt,
		char *val, char *msg, int msglen);

#endif	/* _NSCD_ADMIN_H */
