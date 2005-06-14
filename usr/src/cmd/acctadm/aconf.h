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
 * Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
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

/*
 * Permissions and ownership for the configuration file:
 */
#define	AC_OWNER	0		/* Uid 0 (root) */
#define	AC_GROUP	1		/* Gid 1 (other) */
#define	AC_PERM		(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)	/* Mode 0644 */

#define	MAXRESLEN	256

typedef struct acctconf {
	FILE	*ac_conf_fp;		/* file pointer for config file */
	int	ac_conf_fd;		/* file descriptor for config file */
	int	ac_proc_state;
	char	ac_proc_file[MAXPATHLEN];
	char	ac_proc_tracked[MAXRESLEN];
	char	ac_proc_untracked[MAXRESLEN];
	char	ac_task_file[MAXPATHLEN];
	char	ac_task_tracked[MAXRESLEN];
	char	ac_task_untracked[MAXRESLEN];
	int	ac_task_state;
	char	ac_flow_file[MAXPATHLEN];
	char	ac_flow_tracked[MAXRESLEN];
	char	ac_flow_untracked[MAXRESLEN];
	int	ac_flow_state;
} acctconf_t;

/*
 * Predefined strings
 */
#define	AC_STR_YES	"yes"
#define	AC_STR_NO	"no"
#define	AC_STR_NONE	"none"

extern void	aconf_init(acctconf_t *);
extern int	aconf_create(acctconf_t *, const char *);
extern int	aconf_open(acctconf_t *, const char *);
extern int	aconf_close(acctconf_t *);
extern int	aconf_setup(acctconf_t *);
extern int	aconf_write(acctconf_t *);
extern int	aconf_update(acctconf_t *);
extern void	aconf_print(acctconf_t *, FILE *, int);

extern int	aconf_str2enable(acctconf_t *, char *, int);
extern int	aconf_str2file(acctconf_t *, char *, int);
extern int	aconf_str2tracked(acctconf_t *, char *, int);
extern int	aconf_str2untracked(acctconf_t *, char *, int);

#ifdef	__cplusplus
}
#endif

#endif	/* _ACONF_H */
