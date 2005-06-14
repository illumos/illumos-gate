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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


#include "mtlib.h"
#include <synch.h>

/* Severity */
struct sev_tab {
	int severity;
	char *string;
};

extern char __pfmt_label[MAXLABEL];
extern struct sev_tab *__pfmt_sev_tab;
extern int __pfmt_nsev;

extern rwlock_t _rw_pfmt_label;
extern rwlock_t _rw_pfmt_sev_tab;

extern const char *__gtxt(const char *, int, const char *);
extern int __pfmt_print(FILE *, long, const char *,
	const char **, const char **, va_list);
extern int __lfmt_log(const char *, const char *, va_list, long, int);
