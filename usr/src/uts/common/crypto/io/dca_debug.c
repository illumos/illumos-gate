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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Deimos - cryptographic acceleration based upon Broadcom 582x.
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/varargs.h>
#include <sys/crypto/dca.h>

/*
 * Debugging and messaging.
 */
#if DEBUG
static int dca_debug = 0;

void
dca_dprintf(dca_t *dca, int level, const char *fmt, ...)
{
	va_list ap;
	char	buf[256];

	if (dca_debug & level) {
		va_start(ap, fmt);
		if (dca == NULL) {
			(void) sprintf(buf, "%s\n", fmt);
		} else {
			(void) sprintf(buf, "%s/%d: %s\n",
			    ddi_driver_name(dca->dca_dip),
			    ddi_get_instance(dca->dca_dip), fmt);
		}
		vprintf(buf, ap);
		va_end(ap);
	}
}
#endif

void
dca_error(dca_t *dca, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	dca_dipverror(dca->dca_dip, fmt, ap);
	va_end(ap);
}

void
dca_diperror(dev_info_t *dip, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	dca_dipverror(dip, fmt, ap);
	va_end(ap);
}

void
dca_dipverror(dev_info_t *dip, const char *fmt, va_list ap)
{
	char	buf[256];
	(void) sprintf(buf, "%s%d: %s", ddi_driver_name(dip),
			ddi_get_instance(dip), fmt);
	vcmn_err(CE_WARN, buf, ap);
}
