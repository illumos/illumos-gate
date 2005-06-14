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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file provides common helper routines to the Wildcat RSM driver.
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/wrsm_common.h>
#include <sys/varargs.h>

#ifdef DEBUG
#define	WRSM_USE_CIRCBUF	0x01
#define	WRSM_USE_CMNERR	0x02
static int wrsmdbgmode = WRSM_USE_CMNERR | WRSM_USE_CIRCBUF;

#ifdef DEBUG_LOG
kmutex_t wrsmdbglock;
#endif
#endif


/*
 * The protocol_versions_supported is a bit mask representing all of
 * the protocols supported by this driver.  protocol_version is the
 * preferred native version.
 */
#define	BIT(arg) (1 << arg)
int protocol_version = 1;
uint32_t protocol_versions_supported = BIT(0);

uint_t
wrsmset_isnull(uint32_t *s, int masksize)
{
	uint32_t *tmp = (uint32_t *)s;

	while (masksize--) {
		if (*tmp++ != 0)
			return (0);
	}
	return (1);
}

uint_t
wrsmset_cmp(uint32_t *s1, uint32_t *s2, int masksize)
{
	uint32_t *t1 = (uint32_t *)s1, *t2 = (uint32_t *)s2;

	while (masksize--) {
		if (*t1++ != *t2++)
			return (0);
	}
	return (1);
}



#ifdef DEBUG
void
dprintnodes(cnode_bitmask_t cb)
{
	int i;

	for (i = 0; i < WRSM_MAX_CNODES; i++) {
		if (WRSM_IN_SET(cb, i)) {
			wrsmdprintf(CE_CONT, " %d", i);
		}
	}
}


#define	WRSM_DEBUG_LINE	512

#ifdef DEBUG_LOG

/*
 * The following variables support the debug log buffer scheme.
 */
#define	WRSM_DEBUG_LOG_SIZE 0x80000

/* don't make these static; we want to access through adb */
int wrsmdbginit = 0;		/* Nonzero if wrsmdbglock's inited */
char wrsmdbgbuf[WRSM_DEBUG_LOG_SIZE];	/* The log buffer */
int wrsmdbgsize = sizeof (wrsmdbgbuf);	/* Size of the log buffer */
int wrsmdbgnext;		/* Next byte to write in buffer (note */
				/*  this is an index, not a pointer */

/*
 * Add the string str to the end of the debug log, followed by a newline.
 */
static void
wrsmdbglog(char *str)
{
	int length, remlen;

	mutex_enter(&wrsmdbglock);

	/*
	 * Note the log is circular; if this string would run over the end,
	 * we copy the first piece to the end and then the last piece to
	 * the beginning of the log.
	 */
	length = strlen(str);

	remlen = sizeof (wrsmdbgbuf) - wrsmdbgnext;

	if (length > remlen) {
		if (remlen)
			bcopy(str, wrsmdbgbuf + wrsmdbgnext, remlen);
		str += remlen;
		length -= remlen;
		wrsmdbgnext = 0;
	}

	bcopy(str, wrsmdbgbuf + wrsmdbgnext, length);
	wrsmdbgnext += length;

	if (wrsmdbgnext >= sizeof (wrsmdbgbuf))
		wrsmdbgnext = 0;

	/*
	 * We probably don't need to append a \n, but if we did, we
	 * could do this:
	 * wrsmdbgbuf[wrsmdbgnext++] = '\n';
	 */

	mutex_exit(&wrsmdbglock);
}

#endif /* DEBUG_LOG */

/*
 * Add a printf-style message to whichever debug logs we're currently using.
 */
void
wrsmdprintf(int ce, const char *fmt, ...)
{
	char buf[WRSM_DEBUG_LINE];
	va_list ap;

	va_start(ap, fmt);
	(void) vsprintf(buf, fmt, ap);
	va_end(ap);

#ifdef DEBUG_LOG
	if (wrsmdbgmode & WRSM_USE_CIRCBUF)
		wrsmdbglog(buf);
#endif /* DEBUG_LOG */

	if (wrsmdbgmode & WRSM_USE_CMNERR)
		cmn_err(ce, "%s", buf);
}
#endif /* DEBUG */
