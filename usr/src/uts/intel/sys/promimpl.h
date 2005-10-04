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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_PROMIMPL_H
#define	_SYS_PROMIMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Promif implementation functions and variables.
 *
 * These interfaces are not 'exported' in the same sense that
 * those described in promif.h
 *
 * Used so that the kernel and other stand-alones (eg boot)
 * don't have to directly reference the prom (of which there
 * are now several completely different variants).
 */

#include <sys/types.h>
#include <sys/promif.h>
#include <sys/dditypes.h>
#include <sys/ddidmareq.h>
#include <sys/ddi_impldefs.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Debugging macros for the promif functions.
 */

#define	PROMIF_DMSG_VERBOSE		2
#define	PROMIF_DMSG_NORMAL		1

extern int promif_debug;		/* externally patchable */

#define	PROMIF_DEBUG			/* define this to enable debugging */

#ifdef PROMIF_DEBUG
#define	PROMIF_DPRINTF(args)				\
	if (promif_debug) { 				\
		if (promif_debug == PROMIF_DMSG_VERBOSE)	\
			prom_printf("file %s line %d: ", __FILE__, __LINE__); \
		prom_printf args;			\
	}
#else
#define	PROMIF_DPRINTF(args)
#endif /* PROMIF_DEBUG */

/*
 * minimum alignment required by prom
 */
#define	PROMIF_MIN_ALIGN	1

/*
 * Private utility routines (not exported as part of the interface)
 */

extern	char		*prom_strcpy(char *s1, char *s2);
extern	char		*prom_strncpy(char *s1, char *s2, size_t n);
extern	int		prom_strcmp(char *s1, char *s2);
extern	int		prom_strncmp(char *s1, char *s2, size_t n);
extern	int		prom_strlen(char *s);
extern	char		*prom_strrchr(char *s1, char c);
extern	char		*prom_strcat(char *s1, char *s2);

/*
 * Used to print a common before-reboot message.
 */
extern	void		prom_reboot_prompt(void);

/*
 * Some calls into the prom (those expected to generate output on the console)
 * are wrappered with these calls so that the caller can ensure that
 * the console framebuffer will be brought to full power before entering the
 * firmware.
 */
extern	promif_owrap_t	*promif_preout(void);
extern	void		promif_postout(promif_owrap_t *);

#ifdef	__cplusplus
}
#endif

#endif /* !_SYS_PROMIMPL_H */
