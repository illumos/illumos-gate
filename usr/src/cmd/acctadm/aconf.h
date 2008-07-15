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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_ACONF_H
#define	_ACONF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <stdio.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	MAXRESLEN	256

typedef struct acctconf {
	int	state;
	char	file[MAXPATHLEN];
	char	tracked[MAXRESLEN];
	char	untracked[MAXRESLEN];
} acctconf_t;

/*
 * Predefined strings
 */
#define	AC_STR_NONE		"none"

/*
 * Configuration property group name
 */
#define	AC_PGNAME		"config"

/*
 * Configuration property names
 */
#define	AC_PROP_STATE		"enabled"
#define	AC_PROP_FILE		"file"
#define	AC_PROP_TRACKED		"tracked"
#define	AC_PROP_UNTRACKED	"untracked"

extern void	aconf_init(acctconf_t *, int);
extern int	aconf_setup(const char *);
extern int	aconf_scf_init(const char *);
extern void	aconf_scf_fini(void);
extern int	aconf_set_string(const char *, const char *);
extern int	aconf_set_bool(const char *, boolean_t);
extern int	aconf_save(void);
extern void	aconf_print(FILE *, int);
extern boolean_t aconf_have_smf_auths(void);
extern const char *aconf_type2fmri(int);

#ifdef	__cplusplus
}
#endif

#endif	/* _ACONF_H */
