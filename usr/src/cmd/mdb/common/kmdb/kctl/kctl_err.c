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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/varargs.h>
#include <sys/bootconf.h>
#include <sys/sysmacros.h>
#include <sys/kmdb.h>

/*
 * The boot printing interfaces don't expose anything that'll allow us
 * to print multiple arguments at once.  That is, they expose printf-like
 * interfaces, but these interfaces only support one format specifier per
 * invocation.  The routines in this file allow the rest of the driver
 * to pretend that this limitation doesn't exist.
 */

#include <kmdb/kctl/kctl.h>

static void
kctl_vprintf(int code, const char *format, va_list ap)
{
	if (kctl.kctl_boot_ops == NULL) {
		vcmn_err(code, format, ap);

	} else {
		char buf[128];

		if (code == CE_WARN)
			BOP_PUTSARG(kctl.kctl_boot_ops, "WARNING: ", NULL);
		else if (code == CE_NOTE)
			BOP_PUTSARG(kctl.kctl_boot_ops, "NOTE: ", NULL);

		(void) vsnprintf(buf, sizeof (buf), format, ap);
		BOP_PUTSARG(kctl.kctl_boot_ops, "%s\n", buf);
	}
}

void
kctl_warn(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	kctl_vprintf(CE_WARN, format, ap);
	va_end(ap);
}

void
kctl_dprintf(const char *format, ...)
{
	va_list ap;

	if (!(kctl.kctl_flags & KMDB_F_DRV_DEBUG))
		return;

	va_start(ap, format);
	kctl_vprintf(CE_NOTE, format, ap);
	va_end(ap);
}
