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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_RDUTIL_H
#define	_RDUTIL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/processor.h>
#include <sys/types.h>

#include "rdimpl.h"

#ifdef	__cplusplus
extern "C" {
#endif

#define	RDS_MAXLINE	512
#define	RDS_MAXLOG_FILE (1024 * 1024)
extern void format_err(char *, ...);
extern void dmerror(char *, ...);
extern void *Realloc(void *ptr, size_t size);
extern void *Malloc(size_t);
extern void *Zalloc(size_t);
extern void Free(void *ptr);
extern void list_alloc(list_t *, int);
extern void list_init(list_t *, int);
extern int Setrlimit();
extern longlong_t get_timestamp();
extern size_t ctok(pgcnt_t clicks);
extern void getusrname(int uid, char *name, int length);
extern void getprojname(projid_t projid, char *str, int len);
extern void napms(int ms);
extern void log_open(char *file);
extern void log_close();
extern void log_msg(char *fmt, ...);
extern void log_err(char *fmt, ...);
extern void log_dumpf(char *file);
#ifdef	__cplusplus
}
#endif

#endif	/* _RDUTIL_H */
