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

#include "rge.h"

/*
 * Global variable for default debug flags
 */
uint32_t rge_debug;

/*
 * Global mutex used by logging routines below
 */
kmutex_t rge_log_mutex[1];

/*
 * Static data used by logging routines; protected by <rge_log_mutex>
 */
static struct {
	const char *who;
	const char *fmt;
	int level;
} rge_log_data;


/*
 * Backend print routine for all the routines below
 */
static void
rge_vprt(const char *fmt, va_list args)
{
	char buf[128];

	ASSERT(mutex_owned(rge_log_mutex));

	(void) vsnprintf(buf, sizeof (buf), fmt, args);
	cmn_err(rge_log_data.level, rge_log_data.fmt, rge_log_data.who, buf);
}

/*
 * Report a run-time event (CE_NOTE, to console & log)
 */
void
rge_notice(rge_t *rgep, const char *fmt, ...)
{
	va_list args;

	mutex_enter(rge_log_mutex);
	rge_log_data.who = rgep->ifname;
	rge_log_data.fmt = "%s: %s";
	rge_log_data.level = CE_NOTE;

	va_start(args, fmt);
	rge_vprt(fmt, args);
	va_end(args);

	mutex_exit(rge_log_mutex);
}

/*
 * Log a run-time event (CE_NOTE, log only)
 */
void
rge_log(rge_t *rgep, const char *fmt, ...)
{
	va_list args;

	mutex_enter(rge_log_mutex);
	rge_log_data.who = rgep->ifname;
	rge_log_data.fmt = "!%s: %s";
	rge_log_data.level = CE_NOTE;

	va_start(args, fmt);
	rge_vprt(fmt, args);
	va_end(args);

	mutex_exit(rge_log_mutex);
}

/*
 * Log a run-time problem (CE_WARN, log only)
 */
void
rge_problem(rge_t *rgep, const char *fmt, ...)
{
	va_list args;

	mutex_enter(rge_log_mutex);
	rge_log_data.who = rgep->ifname;
	rge_log_data.fmt = "!%s: %s";
	rge_log_data.level = CE_WARN;

	va_start(args, fmt);
	rge_vprt(fmt, args);
	va_end(args);

	mutex_exit(rge_log_mutex);
}

/*
 * Log a programming error (CE_WARN, log only)
 */
void
rge_error(rge_t *rgep, const char *fmt, ...)
{
	va_list args;

	mutex_enter(rge_log_mutex);
	rge_log_data.who = rgep->ifname;
	rge_log_data.fmt = "!%s: %s";
	rge_log_data.level = CE_WARN;

	va_start(args, fmt);
	rge_vprt(fmt, args);
	va_end(args);

	mutex_exit(rge_log_mutex);
}

#if	RGE_DEBUGGING

static void
rge_prt(const char *fmt, ...)
{
	va_list args;

	ASSERT(mutex_owned(rge_log_mutex));

	va_start(args, fmt);
	rge_vprt(fmt, args);
	va_end(args);

	mutex_exit(rge_log_mutex);
}

void
(*rge_gdb(void))(const char *fmt, ...)
{
	mutex_enter(rge_log_mutex);
	rge_log_data.who = "rge";
	rge_log_data.fmt = "?%s: %s\n";
	rge_log_data.level = CE_CONT;

	return (rge_prt);
}

void
(*rge_db(rge_t *rgep))(const char *fmt, ...)
{
	mutex_enter(rge_log_mutex);
	rge_log_data.who = rgep->ifname;
	rge_log_data.fmt = "?%s: %s\n";
	rge_log_data.level = CE_CONT;

	return (rge_prt);
}

/*
 * Dump a chunk of memory, 16 bytes at a time
 */
static void
minidump(rge_t *rgep, const char *caption, void *dp, uint_t len)
{
	uint32_t buf[4];
	uint32_t nbytes;

	rge_log(rgep, "%d bytes of %s at address %p:-", len, caption, dp);

	for (len = MIN(len, rgep->rxbuf_size); len != 0; len -= nbytes) {
		nbytes = MIN(len, sizeof (buf));
		bzero(buf, sizeof (buf));
		bcopy(dp, buf, nbytes);
		rge_log(rgep, "%08x %08x %08x %08x",
		    buf[0], buf[1], buf[2], buf[3]);
		dp = (caddr_t)dp + nbytes;
	}
}

void
rge_pkt_dump(rge_t *rgep, rge_bd_t *hrbdp, sw_rbd_t *srbdp, const char *msg)
{
	rge_problem(rgep, "driver-detected hardware error: %s", msg);

	minidump(rgep, "hardware descriptor", hrbdp, sizeof (*hrbdp));

	rge_log(rgep, "PCI address %lx flags_len 0x%x"
	    "vlan_tag 0x%x",
	    hrbdp->host_buf_addr,
	    hrbdp->flags_len,
	    hrbdp->vlan_tag);

	if (srbdp != NULL) {
		minidump(rgep, "software descriptor", srbdp, sizeof (*srbdp));

		rge_log(rgep, "PCI address %llx buffer len 0x%x token 0x%x",
		    srbdp->rx_buf->pbuf.cookie.dmac_laddress,
		    srbdp->rx_buf->pbuf.alength,
		    srbdp->rx_buf->pbuf.token);

		minidump(rgep, "packet data", srbdp->rx_buf->pbuf.mem_va,
		    hrbdp->flags_len & RBD_LEN_MASK);
	}
}

void
rge_dbg_enter(rge_t *rgep, const char *s)
{
	uint32_t debug;

	debug = rgep != NULL ? rgep->debug : rge_debug;
	if (debug & RGE_DBG_STOP) {
		cmn_err(CE_CONT, "rge_dbg_enter(%p): %s\n", (void *)rgep, s);
		debug_enter("");
	}
}

#endif	/* RGE_DEBUGGING */
