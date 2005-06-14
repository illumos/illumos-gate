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
 *      nisaddcred.h
 *
 *      Copyright (c) 1988-1995 Sun Microsystems, Inc.
 *      All Rights Reserved.
 */
 
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#define	MAXIPRINT	(11)	/* max length of printed integer */
#define	CRED_TABLE "cred.org_dir"

extern nis_object *init_entry(void);
extern char *default_principal(char *);
extern char *program_name;
extern uid_t my_uid;
extern nis_name my_nisname;
extern char *my_host;
extern char *my_group;
extern char nispasswd[];
extern int explicit_domain;
extern struct passwd *getpwuid_nisplus_master(uid_t, nis_error *);
extern int addonly;
