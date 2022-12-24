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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _GETOPTSTR_H
#define	_GETOPTSTR_H

/*
 * Declarations for getoptstr().
 */

#ifdef __cplusplus
extern "C" {
#endif


#include <sys/types.h>



/*
 * These macros are defined here so getoptstr() callers can handle spaces and
 * words consistently.
 */
#define	ISSPACE(c)	((c) == ' ' || (c) == '\t')
#define	SKIP_WORD(cp)	while (*cp != '\0' && !ISSPACE(*cp)) ++cp;
#define	SKIP_SPC(cp)	while (ISSPACE(*cp)) ++cp;


struct gos_params {
	/* To be set before use. */
	const char	*gos_opts;	/* String of acceptable options. */
	const char	*gos_strp;	/* String of arguments to process. */

	/* Publically readable. */
	char		gos_last_opt;	/* Last option seen. */
	const char	*gos_optargp;	/* Option argument. */
	size_t		gos_optarglen;	/* Length of option argument. */
	const char	*gos_errp;	/* Location of erroneous character. */

	/* Private state. */
	int		gos_pos;	/* Current position in the current */
					/* word.  A la _pos in getopt(). */
};


void	getoptstr_init(struct gos_params *params);
int	getoptstr(struct gos_params *params);



#ifdef __cplusplus
}
#endif

#endif /* _GETOPTSTR_H */
