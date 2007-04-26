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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_RCAPD_CONF_H
#define	_RCAPD_CONF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <stdio.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	CFG_TEMPLATE_SUFFIX	".XXXXXX"	/* suffix of mkstemp() arg */

/*
 * Operating modes
 */
typedef enum {
	rctype_project = 1	/* projects are the only collection type */
} rctype_t;

/*
 * Configuration
 */
typedef struct {
	char		rcfg_filename[MAXPATHLEN];	/* cfg filename */
	int		rcfg_fd;			/* reserved cfg fd */
	time_t		rcfg_last_modification;		/* last mod time */
	rctype_t	rcfg_mode;		/* mode (collection type) */
	char		*rcfg_mode_name;  	/* mode name ("project" only) */
	uint32_t	rcfg_proc_walk_interval;	/* /proc readdir() */
							/* interval (s), */
							/* undocumented */
	uint32_t	rcfg_reconfiguration_interval;	/* lnode or project */
							/* cap reconfig. */
							/* interval (s) */
	uint32_t	rcfg_report_interval;	/* report interval (s) */
	int		rcfg_memory_cap_enforcement_pressure;  /* pressure */
				/* above which memory caps are enforced */
	char		rcfg_stat_file[MAXPATHLEN];	/* statistics file */
	uint32_t	rcfg_rss_sample_interval; /* RSS sampling interval */
} rcfg_t;

typedef enum {
	RCT_MODE_VAR = 257,
	RCT_PROC_WALK_INTERVAL_VAR,
	RCT_RECONFIGURATION_INTERVAL_VAR,
	RCT_REPORT_INTERVAL_VAR,
	RCT_RSS_SAMPLE_INTERVAL_VAR,
	RCT_MEMORY_CAP_ENFORCEMENT_PRESSURE_VAR,
	RCT_STAT_FILE_VAR,
	RCT_EQUALS,
	RCT_NUMBER,
	RCT_PROJECT,
	RCT_LNODE,
	RCT_ON,
	RCT_OFF,
	RCT_FILENAME,
	RCT_STATE,
	RCT_INVALID
} rctoken_t;

extern int rcfg_read(rcfg_t *, int(*)(void));
extern void rcfg_init(rcfg_t *);
extern int modify_config(rcfg_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _RCAPD_CONF_H */
