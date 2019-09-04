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

#ifndef _UTIL_GETRESPONSE_H
#define	_UTIL_GETRESPONSE_H

/*
 * Declarations for getresponse().
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	ERR_MSG_INIT_YES "Error initializing international response strings: %s"

extern char	*yesstr;
extern char	*nostr;
extern int	init_yes(void);
extern void	fini_yes(void);
extern int	yes(void);
extern int	yes_check(char *);
extern int	no(void);
extern int	no_check(char *);

#ifdef __cplusplus
}
#endif

#endif /* _UTIL_GETRESPONSE_H */
