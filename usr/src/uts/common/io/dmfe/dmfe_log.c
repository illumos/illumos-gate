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

#include "dmfe_impl.h"


/*
 * Debug flags
 */

#if	DMFEDEBUG
uint32_t dmfe_debug = 0;
#endif	/* DMFEDEBUG */


/*
 *	========== Message printing & debug routines ==========
 */

static struct {
	kmutex_t mutex[1];
	const char *ifname;
	const char *fmt;
	int level;
} prtdata;

void
dmfe_log_init()
{
	mutex_init(prtdata.mutex, NULL, MUTEX_DRIVER, NULL);
}

void
dmfe_log_fini()
{
	mutex_destroy(prtdata.mutex);
}

/*
 * Backend print routine for all the routines below
 */
static void
dmfe_vprt(const char *fmt, va_list args)
{
	char buf[128];

	ASSERT(mutex_owned(prtdata.mutex));

	(void) vsnprintf(buf, sizeof (buf), fmt, args);
	cmn_err(prtdata.level, prtdata.fmt, prtdata.ifname, buf);
}

#if	DMFEDEBUG

static void
dmfe_prt(const char *fmt, ...)
{
	va_list args;

	ASSERT(mutex_owned(prtdata.mutex));

	va_start(args, fmt);
	dmfe_vprt(fmt, args);
	va_end(args);

	mutex_exit(prtdata.mutex);
}

void
(*dmfe_db(dmfe_t *dmfep))(const char *fmt, ...)
{
	mutex_enter(prtdata.mutex);
	prtdata.ifname = dmfep->ifname;
	prtdata.fmt = "^%s: %s\n";
	prtdata.level = CE_CONT;

	return (dmfe_prt);
}

void
(*dmfe_gdb())(const char *fmt, ...)
{
	mutex_enter(prtdata.mutex);
	prtdata.ifname = "dmfe";
	prtdata.fmt = "^%s: %s\n";
	prtdata.level = CE_CONT;

	return (dmfe_prt);
}

#endif	/* DMFEDEBUG */

/*
 * Report a run-time error (CE_WARN, to console & log)
 * Also logs all the chip's operating registers
 */
void
dmfe_warning(dmfe_t *dmfep, const char *fmt, ...)
{
	va_list args;
	uint32_t reg;
	int i;

	mutex_enter(prtdata.mutex);
	prtdata.ifname = dmfep->ifname;
	prtdata.fmt = "%s: %s";
	prtdata.level = CE_WARN;

	va_start(args, fmt);
	dmfe_vprt(fmt, args);
	va_end(args);

	/*
	 * Record all the chip registers in the logfile
	 */
	for (i = 0; i < 16; ++i) {
		reg = dmfe_chip_get32(dmfep, 8*i);
		cmn_err(CE_NOTE, "!%s: CR%d\t%08x", dmfep->ifname, i, reg);
	}

	mutex_exit(prtdata.mutex);
}

/*
 * Log a programming error (CE_WARN, log only)
 */
void
dmfe_error(dmfe_t *dmfep, const char *fmt, ...)
{
	va_list args;

	mutex_enter(prtdata.mutex);
	prtdata.ifname = dmfep->ifname;
	prtdata.fmt = "!%s: %s";
	prtdata.level = CE_WARN;

	va_start(args, fmt);
	dmfe_vprt(fmt, args);
	va_end(args);

	mutex_exit(prtdata.mutex);
}

/*
 * Report a run-time event (CE_NOTE, to console & log)
 */
void
dmfe_notice(dmfe_t *dmfep, const char *fmt, ...)
{
	va_list args;

	mutex_enter(prtdata.mutex);
	prtdata.ifname = dmfep->ifname;
	prtdata.fmt = "%s: %s";
	prtdata.level = CE_NOTE;

	va_start(args, fmt);
	dmfe_vprt(fmt, args);
	va_end(args);

	mutex_exit(prtdata.mutex);
}

/*
 * Log a run-time event (CE_NOTE, log only)
 */
void
dmfe_log(dmfe_t *dmfep, const char *fmt, ...)
{
	va_list args;

	mutex_enter(prtdata.mutex);
	prtdata.ifname = dmfep->ifname;
	prtdata.fmt = "!%s: %s";
	prtdata.level = CE_NOTE;

	va_start(args, fmt);
	dmfe_vprt(fmt, args);
	va_end(args);

	mutex_exit(prtdata.mutex);
}
