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

#ifndef _KMDB_PROMIF_IMPL_H
#define	_KMDB_PROMIF_IMPL_H

#include <sys/consdev.h>

#include <kmdb/kmdb_promif.h>
#include <kmdb/kmdb_auxv.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(__i386) || defined(__amd64)
struct boot_syscalls;
extern struct boot_syscalls *kmdb_sysp;
#endif

/*
 * We don't have an easy way of asking for the window size, so we're going to
 * hard-code the current values.
 */
#ifdef	__sparc
#define	KMDB_PIF_WINSIZE_ROWS	34
#else
#define	KMDB_PIF_WINSIZE_ROWS	25
#endif
#define	KMDB_PIF_WINSIZE_COLS	80

typedef struct kmdb_promif {
	char *pif_oterm;	/* term type for local console (NULL if rem) */
	struct termios pif_tios; /* derived settings for console */
	struct winsize pif_wsz;	/* winsize for local console */
} kmdb_promif_t;

extern void kmdb_prom_init_finish_isadep(kmdb_auxv_t *);

extern char *kmdb_prom_get_ddi_prop(kmdb_auxv_t *, char *);
extern void kmdb_prom_free_ddi_prop(char *);

extern ssize_t kmdb_prom_obp_writer(caddr_t, size_t);

extern int kmdb_prom_stdout_is_framebuffer(kmdb_auxv_t *);
extern void kmdb_prom_get_tem_size(kmdb_auxv_t *, ushort_t *, ushort_t *);

#ifdef __cplusplus
}
#endif

#endif /* _KMDB_PROMIF_IMPL_H */
