/*
 * CDDL HEADER START
 *
 * Copyright(c) 2007-2008 Intel Corporation. All rights reserved.
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at:
 *      http://www.opensolaris.org/os/licensing.
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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "ixgbe_sw.h"

#define	LOG_BUF_LEN	128

/*
 * ixgbe_notice - Report a run-time event (CE_NOTE, to console & log)
 */
void
ixgbe_notice(void *arg, const char *fmt, ...)
{
	ixgbe_t *ixgbep = (ixgbe_t *)arg;
	char buf[LOG_BUF_LEN];
	va_list ap;

	va_start(ap, fmt);
	(void) vsnprintf(buf, sizeof (buf), fmt, ap);
	va_end(ap);

	if (ixgbep != NULL)
		cmn_err(CE_NOTE, "%s%d: %s", MODULE_NAME, ixgbep->instance,
		    buf);
	else
		cmn_err(CE_NOTE, "%s: %s", MODULE_NAME, buf);
}

/*
 * ixgbe_log - Log a run-time event (CE_NOTE, to log only)
 */
void
ixgbe_log(void *arg, const char *fmt, ...)
{
	ixgbe_t *ixgbep = (ixgbe_t *)arg;
	char buf[LOG_BUF_LEN];
	va_list ap;

	va_start(ap, fmt);
	(void) vsnprintf(buf, sizeof (buf), fmt, ap);
	va_end(ap);

	if (ixgbep != NULL)
		cmn_err(CE_NOTE, "!%s%d: %s", MODULE_NAME, ixgbep->instance,
		    buf);
	else
		cmn_err(CE_NOTE, "!%s: %s", MODULE_NAME, buf);
}

/*
 * ixgbe_error - Log a run-time problem (CE_WARN, to log only)
 */
void
ixgbe_error(void *arg, const char *fmt, ...)
{
	ixgbe_t *ixgbep = (ixgbe_t *)arg;
	char buf[LOG_BUF_LEN];
	va_list ap;

	va_start(ap, fmt);
	(void) vsnprintf(buf, sizeof (buf), fmt, ap);
	va_end(ap);

	if (ixgbep != NULL)
		cmn_err(CE_WARN, "!%s%d: %s", MODULE_NAME, ixgbep->instance,
		    buf);
	else
		cmn_err(CE_WARN, "!%s: %s", MODULE_NAME, buf);
}
