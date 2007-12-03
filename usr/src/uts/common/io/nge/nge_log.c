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

#include "nge.h"


/*
 * Global variable for default debug flags
 */
uint32_t nge_debug;

/*
 * Global mutex used by logging routines below
 */
kmutex_t nge_log_mutex[1];

/*
 * Static data used by logging routines; protected by <nge_log_mutex>
 */
static struct {
	const char *who;
	const char *fmt;
	int level;
} nge_log_data;


/*
 * Backend print routine for all the routines below
 */
static void
nge_vprt(const char *fmt, va_list args)
{
	char buf[128];

	ASSERT(mutex_owned(nge_log_mutex));

	(void) vsnprintf(buf, sizeof (buf), fmt, args);
	cmn_err(nge_log_data.level, nge_log_data.fmt, nge_log_data.who, buf);
}


/*
 * Log a run-time event (CE_NOTE, log only)
 */
void
nge_log(nge_t *ngep, const char *fmt, ...)
{
	va_list args;

	mutex_enter(nge_log_mutex);
	nge_log_data.who = ngep->ifname;
	nge_log_data.fmt = "!%s: %s";
	nge_log_data.level = CE_NOTE;

	va_start(args, fmt);
	nge_vprt(fmt, args);
	va_end(args);

	mutex_exit(nge_log_mutex);
}

/*
 * Log a run-time problem (CE_WARN, log only)
 */
void
nge_problem(nge_t *ngep, const char *fmt, ...)
{
	va_list args;

	mutex_enter(nge_log_mutex);
	nge_log_data.who = ngep->ifname;
	nge_log_data.fmt = "!%s: %s";
	nge_log_data.level = CE_WARN;

	va_start(args, fmt);
	nge_vprt(fmt, args);
	va_end(args);

	mutex_exit(nge_log_mutex);
}

/*
 * Log a programming error (CE_WARN, log only)
 */
void
nge_error(nge_t *ngep, const char *fmt, ...)
{
	va_list args;

	mutex_enter(nge_log_mutex);
	nge_log_data.who = ngep->ifname;
	nge_log_data.fmt = "!%s: %s";
	nge_log_data.level = CE_WARN;

	va_start(args, fmt);
	nge_vprt(fmt, args);
	va_end(args);

	mutex_exit(nge_log_mutex);
}

static const char *
nge_class_string(uint8_t class_id)
{
	const char *msg;
	switch (class_id) {
	default:
		msg = "none";
	break;

	case NGE_HW_ERR:
		msg = "Hardware fatal error. Hardware will be reset";
	break;

	case NGE_HW_LINK:
		msg = "the link is broken, please check the connection";
	break;

	case NGE_HW_BM:
		msg = "Reset the hardware buffer management fails,"
		    "need to power off/power on system. It is hardware bug";
		break;

	case NGE_HW_RCHAN:
		msg = "Reset rx's channel fails. Need to power off/power"
		    "on system";
		break;

	case NGE_HW_TCHAN:
		msg = "Reset rx's channel fails. Need to power off/power"
		    "on system";
		break;

	case NGE_HW_ROM:
		msg = "Unlock eeprom lock fails.";
		break;

	case NGE_SW_PROBLEM_ID:
		msg = "Refill rx's bd fails";
	break;
	}
	return (msg);
}

void
nge_report(nge_t *ngep, uint8_t error_id)
{
	const char *err_msg;

	err_msg = nge_class_string(error_id);
	nge_error(ngep, err_msg);

}
static void
nge_prt(const char *fmt, ...)
{
	va_list args;

	ASSERT(mutex_owned(nge_log_mutex));

	va_start(args, fmt);
	nge_vprt(fmt, args);
	va_end(args);

	mutex_exit(nge_log_mutex);
}

void
(*nge_gdb(void))(const char *fmt, ...)
{
	mutex_enter(nge_log_mutex);

	nge_log_data.who = "nge";
	nge_log_data.fmt = "?%s: %s\n";
	nge_log_data.level = CE_CONT;

	return (nge_prt);
}

void
(*nge_db(nge_t *ngep))(const char *fmt, ...)
{
	mutex_enter(nge_log_mutex);

	nge_log_data.who = ngep->ifname;
	nge_log_data.fmt = "?%s: %s\n";
	nge_log_data.level = CE_CONT;

	return (nge_prt);
}
