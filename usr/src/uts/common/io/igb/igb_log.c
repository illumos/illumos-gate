/*
 * CDDL HEADER START
 *
 * Copyright(c) 2007-2008 Intel Corporation. All rights reserved.
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at:
 *	http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When using or redistributing this file, you may do so under the
 * License only. No other modification of this header is permitted.
 *
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms of the CDDL.
 */

#include "igb_sw.h"

#define	LOG_BUF_LEN	1024

extern int igb_debug;

void
igb_log(void *arg, igb_debug_t level, const char *fmt, ...)
{
	igb_t *igbp = (igb_t *)arg;
	char buf[LOG_BUF_LEN];
	int celevel;
	va_list ap;

	va_start(ap, fmt);
	(void) vsnprintf(buf, sizeof (buf), fmt, ap);
	va_end(ap);

	DTRACE_PROBE2(igb__log, igb_t *, igbp, const char *, buf);

	if (level > igb_debug)
		return;

	switch (level) {
	case IGB_LOG_ERROR:
		celevel = CE_WARN;
		break;
	case IGB_LOG_INFO:
		celevel = CE_NOTE;
		break;
	case IGB_LOG_TRACE:
		celevel = CE_CONT;
		break;
	default:
		celevel = CE_IGNORE;
	}

	if (igbp != NULL)
		dev_err(igbp->dip, celevel, "!%s", buf);
	else
		cmn_err(celevel, "!%s", buf);
}
