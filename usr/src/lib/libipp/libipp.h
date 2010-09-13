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
 * Copyright 2001-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LIBIPP_H
#define	_LIBIPP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libnvpair.h>
#include <ipp/ipp.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	DEBUG

#define	DBG_ERR	0x00000001
#define	DBG_IO	0x00000002

#endif	/* DEBUG */

/*
 * interface functions
 */

extern int	ipp_action_create(const char *, const char *, nvlist_t **,
    ipp_flags_t);
extern int	ipp_action_destroy(const char *, ipp_flags_t);
extern int	ipp_action_modify(const char *, nvlist_t **, ipp_flags_t);
extern int	ipp_action_info(const char *, int (*)(nvlist_t *, void *),
    void *, ipp_flags_t);
extern int	ipp_action_mod(const char *, char **);
extern int	ipp_list_mods(char ***, int *);
extern int	ipp_mod_list_actions(const char *, char ***, int *);
extern void	ipp_free(char *);
extern void	ipp_free_array(char **, int);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBIPP_H */
