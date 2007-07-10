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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/varargs.h>
#include <sys/n2rng.h>

/*
 * Debugging and messaging.
 */
#if DEBUG
static unsigned int n2rng_debug = DWARN;

int
n2rng_dflagset(int flag)
{
	return (flag & n2rng_debug);
}

void
n2rng_dprintf(n2rng_t *n2rng, int level, const char *fmt, ...)
{
	va_list ap;
	char	buf[256];

	if (n2rng_debug & level) {
		va_start(ap, fmt);
		if (n2rng == NULL) {
			(void) sprintf(buf, "%s\n", fmt);
		} else {
			(void) sprintf(buf, "%s/%d: %s\n",
			    ddi_driver_name(n2rng->n_dip),
			    ddi_get_instance(n2rng->n_dip), fmt);
		}
		vprintf(buf, ap);
		va_end(ap);
	}
}
#endif

void
n2rng_error(n2rng_t *n2rng, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	n2rng_dipverror(n2rng->n_dip, fmt, ap);
	va_end(ap);
}

void
n2rng_diperror(dev_info_t *dip, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	n2rng_dipverror(dip, fmt, ap);
	va_end(ap);
}

void
n2rng_dipverror(dev_info_t *dip, const char *fmt, va_list ap)
{
	char	buf[256];

	(void) sprintf(buf, "%s%d: %s", ddi_driver_name(dip),
	    ddi_get_instance(dip), fmt);
	vcmn_err(CE_WARN, buf, ap);
}
