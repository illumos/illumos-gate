/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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

#ifndef _TOPO_SUBR_H
#define	_TOPO_SUBR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fm/libtopo.h>
#include <topo_list.h>

#include <pthread.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct topo_debug_mode {
	char *tdm_name;		/* mode name */
	char *tdm_desc;		/* mode description */
	int tdm_mode;		/* mode: See below */
} topo_debug_mode_t;

#define	TOPO_DBOUT_STDERR	0	/* Debug messages to stderr */
#define	TOPO_DBOUT_SYSLOG	1	/* Debug messages to syslog */

extern int topo_rw_read_held(pthread_rwlock_t *);
extern int topo_rw_write_held(pthread_rwlock_t *);
extern int topo_mutex_held(pthread_mutex_t *);

extern void topo_hdl_lock(topo_hdl_t *);
extern void topo_hdl_unlock(topo_hdl_t *);

extern const char *topo_stability_name(topo_stability_t);
extern char *topo_version_num2str(topo_version_t, char *, size_t);
extern int topo_version_str2num(const char *, topo_version_t);
extern int topo_version_defined(topo_version_t);

extern void topo_dprintf(int, const char *, ...);
extern void topo_vdprintf(int, const char *, va_list);

extern tnode_t *topo_hdl_root(topo_hdl_t *, const char *);

#ifdef __cplusplus
}
#endif

#endif	/* _TOPO_SUBR_H */
