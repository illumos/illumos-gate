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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/devpolicy.h>

#define	DEV_POLICY	"/etc/security/device_policy"
#define	EXTRA_PRIVS	"/etc/security/extra_privs"

typedef struct fileentry {
	char	*rawbuf;		/* raw text from file */
	char	*orgentry;		/* pointer to first non comment line */
	char	*entry;			/* entry w/ escaped newlines removed */
	int	startline;		/* line # of non comments */
} fileentry_t;

fileentry_t *fgetline(FILE *fp);

int delete_plcy_entry(const char *, const char *);
int update_device_policy(const char *, const char *, boolean_t);
char *check_plcy_entry(char *, const char *, boolean_t);
int check_priv_entry(const char *, boolean_t);
int parse_plcy_token(char *, devplcysys_t *);
int parse_minor_range(const char *, minor_t *, minor_t *, char *);

void devplcy_init(void);

extern size_t devplcysys_sz;
extern const priv_impl_info_t *privimplinfo;
