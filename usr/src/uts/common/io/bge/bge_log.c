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

#include "bge_impl.h"


/*
 * Global variable for default debug flags
 */
uint32_t bge_debug;

/*
 * Global mutex used by logging routines below
 */
kmutex_t bge_log_mutex[1];

/*
 * Static data used by logging routines; protected by <bge_log_mutex>
 */
static struct {
	const char *who;
	const char *fmt;
	int level;
} bge_log_data;


/*
 * Backend print routine for all the routines below
 */
static void
bge_vprt(const char *fmt, va_list args)
{
	char buf[128];

	ASSERT(mutex_owned(bge_log_mutex));

	(void) vsnprintf(buf, sizeof (buf), fmt, args);
	cmn_err(bge_log_data.level, bge_log_data.fmt, bge_log_data.who, buf);
}

/*
 * Log a run-time event (CE_NOTE, log only)
 */
void
bge_log(bge_t *bgep, const char *fmt, ...)
{
	va_list args;

	mutex_enter(bge_log_mutex);
	bge_log_data.who = bgep->ifname;
	bge_log_data.fmt = "!%s: %s";
	bge_log_data.level = CE_NOTE;

	va_start(args, fmt);
	bge_vprt(fmt, args);
	va_end(args);

	mutex_exit(bge_log_mutex);
}

/*
 * Log a run-time problem (CE_WARN, log only)
 */
void
bge_problem(bge_t *bgep, const char *fmt, ...)
{
	va_list args;

	mutex_enter(bge_log_mutex);
	bge_log_data.who = bgep->ifname;
	bge_log_data.fmt = "!%s: %s";
	bge_log_data.level = CE_WARN;

	va_start(args, fmt);
	bge_vprt(fmt, args);
	va_end(args);

	mutex_exit(bge_log_mutex);
}

/*
 * Log a programming error (CE_WARN, log only)
 */
void
bge_error(bge_t *bgep, const char *fmt, ...)
{
	va_list args;

	mutex_enter(bge_log_mutex);
	bge_log_data.who = bgep->ifname;
	bge_log_data.fmt = "!%s: %s";
	bge_log_data.level = CE_WARN;

	va_start(args, fmt);
	bge_vprt(fmt, args);
	va_end(args);

	mutex_exit(bge_log_mutex);
}

void
bge_fm_ereport(bge_t *bgep, char *detail)
{
	uint64_t ena;
	char buf[FM_MAX_CLASS];

	(void) snprintf(buf, FM_MAX_CLASS, "%s.%s", DDI_FM_DEVICE, detail);
	ena = fm_ena_generate(0, FM_ENA_FMT1);
	if (DDI_FM_EREPORT_CAP(bgep->fm_capabilities)) {
		ddi_fm_ereport_post(bgep->devinfo, buf, ena, DDI_NOSLEEP,
		    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0, NULL);
	}
}

#if	BGE_DEBUGGING

static void
bge_prt(const char *fmt, ...)
{
	va_list args;

	ASSERT(mutex_owned(bge_log_mutex));

	va_start(args, fmt);
	bge_vprt(fmt, args);
	va_end(args);

	mutex_exit(bge_log_mutex);
}

void
(*bge_gdb(void))(const char *fmt, ...)
{
	mutex_enter(bge_log_mutex);
	bge_log_data.who = "bge";
	bge_log_data.fmt = "?%s: %s\n";
	bge_log_data.level = CE_CONT;

	return (bge_prt);
}

void
(*bge_db(bge_t *bgep))(const char *fmt, ...)
{
	mutex_enter(bge_log_mutex);
	bge_log_data.who = bgep->ifname;
	bge_log_data.fmt = "?%s: %s\n";
	bge_log_data.level = CE_CONT;

	return (bge_prt);
}

/*
 * Dump a chunk of memory, 16 bytes at a time
 */
static void
minidump(bge_t *bgep, const char *caption, void *dp, uint_t len)
{
	uint32_t buf[4];
	uint32_t nbytes;

	bge_log(bgep, "%d bytes of %s at address %p:-", len, caption, dp);

	for (len = MIN(len, BGE_STD_BUFF_SIZE); len != 0; len -= nbytes) {
		nbytes = MIN(len, sizeof (buf));
		bzero(buf, sizeof (buf));
		bcopy(dp, buf, nbytes);
		bge_log(bgep, "%08x %08x %08x %08x",
			buf[0], buf[1], buf[2], buf[3]);
		dp = (caddr_t)dp + nbytes;
	}
}

void
bge_pkt_dump(bge_t *bgep, bge_rbd_t *hrbdp, sw_rbd_t *srbdp, const char *msg)
{
	bge_problem(bgep, "driver-detected hardware error: %s", msg);

	minidump(bgep, "hardware descriptor", hrbdp, sizeof (*hrbdp));

	bge_log(bgep, "PCI address %llx packet len 0x%x token 0x%x "
			"flags 0x%x index 0x%x",
			hrbdp->host_buf_addr,
			hrbdp->len,
			hrbdp->opaque,
			hrbdp->flags,
			hrbdp->index);

	if (srbdp != NULL) {
		minidump(bgep, "software descriptor", srbdp, sizeof (*srbdp));

		bge_log(bgep, "PCI address %llx buffer len 0x%x token 0x%x",
			srbdp->pbuf.cookie.dmac_laddress,
			srbdp->pbuf.alength,
			srbdp->pbuf.token);

		minidump(bgep, "packet data", srbdp->pbuf.mem_va, hrbdp->len);
	}
}

void
bge_dbg_enter(bge_t *bgep, const char *s)
{
	uint32_t debug;

	debug = bgep != NULL ? bgep->debug : bge_debug;
	if (debug & BGE_DBG_STOP) {
		cmn_err(CE_CONT, "bge_dbg_enter(%p): %s\n", (void *)bgep, s);
		debug_enter("");
	}
}

#endif	/* BGE_DEBUGGING */
