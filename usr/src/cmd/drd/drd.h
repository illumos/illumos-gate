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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _DRD_H
#define	_DRD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/drctl.h>

typedef int32_t cpuid_t;

/*
 * Logging support
 */
extern void drd_err(char *fmt, ...);
extern void drd_info(char *fmt, ...);
extern void drd_dbg(char *fmt, ...);

extern boolean_t drd_daemonized;
extern boolean_t drd_debug;

#define	s_free(x)	(((x) != NULL) ? (free(x), (x) = NULL) : (void *)0)
#define	s_nvfree(x)	(((x) != NULL) ? (nvlist_free(x)) : (void)0)

/*
 * Backend support
 */
typedef struct {
	int (*init)(void);
	int (*fini)(void);
	int (*cpu_config_request)(drctl_rsrc_t *rsrcs, int nrsrc);
	int (*cpu_config_notify)(drctl_rsrc_t *rsrcs, int nrsrc);
	int (*cpu_unconfig_request)(drctl_rsrc_t *rsrcs, int nrsrc);
	int (*cpu_unconfig_notify)(drctl_rsrc_t *rsrcs, int nrsrc);
	int (*io_config_request)(drctl_rsrc_t *rsrc, int nrsrc);
	int (*io_config_notify)(drctl_rsrc_t *rsrc, int nrsrc);
	int (*io_unconfig_request)(drctl_rsrc_t *rsrc, int nrsrc);
	int (*io_unconfig_notify)(drctl_rsrc_t *rsrc, int nrsrc);
	int (*mem_config_request)(drctl_rsrc_t *rsrcs, int nrsrc);
	int (*mem_config_notify)(drctl_rsrc_t *rsrcs, int nrsrc);
	int (*mem_unconfig_request)(drctl_rsrc_t *rsrcs, int nrsrc);
	int (*mem_unconfig_notify)(drctl_rsrc_t *rsrcs, int nrsrc);
} drd_backend_t;

extern drd_backend_t drd_rcm_backend;

#ifdef __cplusplus
}
#endif

#endif /* _DRD_H */
