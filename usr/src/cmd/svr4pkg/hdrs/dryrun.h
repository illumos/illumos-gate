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


#ifndef __DRYRUN_H__
#define	__DRYRUN_H__

#include	"cfext.h"

/* The various types of status entry in the info file. */
#define	PARTIAL	1
#define	RUNLEVEL 2
#define	PKGFILES 3
#define	DEPEND 4
#define	SPACE 5
#define	CONFLICT 6
#define	SETUID 7
#define	PRIV 8
#define	PKGDIRS 9
#define	REQUESTEXITCODE 10
#define	CHECKEXITCODE 11
#define	EXITCODE 12
#define	DR_TYPE 13

#define	INSTALL_TYPE	1
#define	REMOVE_TYPE	0

#if defined(__STDC__)
#define	__P(protos) protos
#else	/* __STDC__ */
#define	__P(protos) ()
#endif	/* __STDC__ */

extern void	set_dryrun_mode __P((void));
extern int	in_dryrun_mode __P((void));
extern void	set_continue_mode __P((void));
extern int	in_continue_mode __P((void));
extern void	init_contfile __P((char *cn_dir));
extern void	init_dryrunfile __P((char *dr_dir));
extern void	set_dr_info __P((int type, int value));
extern int	cmd_ln_respfile __P((void));
extern int	is_a_respfile __P((void));
extern void	write_dryrun_file __P((struct cfextra **extlist));
extern boolean_t	read_continuation __P((int *error));

#endif	/* __DRYRUN_H__ */
