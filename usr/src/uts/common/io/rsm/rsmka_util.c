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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/user.h>
#include <sys/buf.h>
#include <sys/systm.h>
#include <sys/vm.h>
#include <sys/uio.h>
#include <vm/seg.h>
#include <sys/stat.h>

#include <sys/time.h>
#include <sys/varargs.h>

#include <sys/rsm/rsm.h>

/* lint -w2 */

extern char *vsprintf_len(size_t, char *, const char *, va_list);
extern char *sprintf(char *buf, const char *fmt, ...);

/*
 * From kmdb, read printfs using : *rsmka_dbg/s
 */
#define	RSMKA_BUFSIZE	0x10000

char    rsmka_buf[RSMKA_BUFSIZE];
char    *rsmka_dbg = rsmka_buf;
char    *rsmka_buf_end = rsmka_buf;
char    *rsmka_buf_top = rsmka_buf + RSMKA_BUFSIZE - 256;
kmutex_t rsmka_buf_lock;

int rsmdbg_category = RSM_KERNEL_ALL;
#ifdef DEBUG
int rsmdbg_level = RSM_DEBUG_VERBOSE;
#else
int rsmdbg_level = RSM_NOTICE;
#endif

void dbprintf(char *fmt, ...) {
	va_list ap;
/* lint -save -e40 */
	va_start(ap, fmt);
/* lint -restore */
	mutex_enter(&rsmka_buf_lock);
	(void) vsprintf_len(255, rsmka_buf_end, fmt, ap);
	rsmka_buf_end += strlen(rsmka_buf_end);
	if (rsmka_buf_end > rsmka_buf_top) {
		rsmka_buf_end = rsmka_buf;
	}
	va_end(ap);
	mutex_exit(&rsmka_buf_lock);
}

void
dbg_printf(int msg_category, int msg_level, char *fmt, ...)
{
	if ((msg_category & rsmdbg_category) &&
	    (msg_level <= rsmdbg_level)) {
		va_list	ap;
		va_start(ap, fmt);
		mutex_enter(&rsmka_buf_lock);
		(void) sprintf(rsmka_buf_end, "%16" PRIx64 ":",
			curthread->t_did);
		rsmka_buf_end += 17;
		(void) vsprintf_len(255, rsmka_buf_end, fmt, ap);
		rsmka_buf_end += strlen(rsmka_buf_end);
		if (rsmka_buf_end > rsmka_buf_top) {
			rsmka_buf_end = rsmka_buf;
		}
		mutex_exit(&rsmka_buf_lock);
		va_end(ap);
	}
}
