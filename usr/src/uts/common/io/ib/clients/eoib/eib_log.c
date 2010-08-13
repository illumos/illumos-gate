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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ksynch.h>
#include <sys/varargs.h>

#include <sys/ib/clients/eoib/eib_impl.h>

/*
 * Defaults
 */
uint_t eib_log_size = EIB_LOGSZ_DEFAULT;
int eib_log_level = EIB_MSGS_DEFAULT | EIB_MSGS_DEBUG;
int eib_log_timestamps = 0;

/*
 * Debug variables, should not be tunables so allocated debug buffer
 * and its size remain consistent.
 */
static kmutex_t eib_debug_buf_lock;
static uint8_t *eib_debug_buf;
static uint32_t eib_debug_buf_ndx;
static uint_t eib_debug_buf_sz = 0;

/*
 * Local declarations
 */
static void eib_log(char *);

void
eib_debug_init(void)
{
	eib_debug_buf_ndx = 0;
	eib_debug_buf_sz = eib_log_size;
	eib_debug_buf = kmem_zalloc(eib_debug_buf_sz, KM_SLEEP);

	mutex_init(&eib_debug_buf_lock, NULL, MUTEX_DRIVER, NULL);
}

void
eib_debug_fini(void)
{
	mutex_destroy(&eib_debug_buf_lock);

	if (eib_debug_buf && eib_debug_buf_sz) {
		kmem_free(eib_debug_buf, eib_debug_buf_sz);
		eib_debug_buf = NULL;
	}
	eib_debug_buf_sz = 0;
	eib_debug_buf_ndx = 0;
}

void
eib_log(char *msg)
{
	uint32_t off;
	int msglen;
	char msgbuf[EIB_MAX_LINE];

	if (eib_debug_buf == NULL)
		return;

	if (eib_log_timestamps) {
		msglen = snprintf(msgbuf, EIB_MAX_LINE, "%llx: %s",
		    (unsigned long long)ddi_get_lbolt64(), msg);
	} else {
		msglen = snprintf(msgbuf, EIB_MAX_LINE, "%s", msg);
	}

	if (msglen < 0)
		return;
	else if (msglen >= EIB_MAX_LINE)
		msglen = EIB_MAX_LINE - 1;

	mutex_enter(&eib_debug_buf_lock);
	if ((eib_debug_buf_ndx == 0) ||
	    (eib_debug_buf[eib_debug_buf_ndx-1] != '\n')) {
		eib_debug_buf[eib_debug_buf_ndx] = '\n';
		eib_debug_buf_ndx++;
	}

	off = eib_debug_buf_ndx;	/* current msg should go here */

	eib_debug_buf_ndx += msglen;	/* next msg should start here */
	eib_debug_buf[eib_debug_buf_ndx] = 0;	/* terminate current msg */

	if (eib_debug_buf_ndx >= (eib_debug_buf_sz - 2 * EIB_MAX_LINE))
		eib_debug_buf_ndx = 0;

	mutex_exit(&eib_debug_buf_lock);

	bcopy(msgbuf, eib_debug_buf+off, msglen);    /* no lock needed */
}

#ifdef EIB_DEBUG
void
eib_dprintf_verbose(int inst, const char *fmt, ...)
{
	va_list ap;
	int msglen;
	char msgbuf[EIB_MAX_LINE];
	char newfmt[EIB_MAX_LINE];

	if ((eib_log_level & EIB_MSGS_VERBOSE) != EIB_MSGS_VERBOSE)
		return;

	(void) snprintf(newfmt, EIB_MAX_LINE, "eoib%d__%s", inst, fmt);

	va_start(ap, fmt);
	msglen = vsnprintf(msgbuf, EIB_MAX_LINE, newfmt, ap);
	va_end(ap);

	if (msglen > 0) {
		eib_log(msgbuf);
	}
}

void
eib_dprintf_pkt(int inst, uint8_t *pkt, uint_t sz)
{
	char msgbuf[EIB_MAX_LINE];
	char *bufp;
	uint8_t *p = pkt;
	uint_t len;
	uint_t i;

	if ((eib_log_level & EIB_MSGS_PKT) != EIB_MSGS_PKT)
		return;

	while (sz >= 16) {
		(void) snprintf(msgbuf, EIB_MAX_LINE,
		    "eoib%02d__%02x %02x %02x %02x %02x %02x %02x %02x "
		    "%02x %02x %02x %02x %02x %02x %02x %02x\n", inst,
		    p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
		    p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);

		eib_log(msgbuf);

		p += 16;
		sz -= 16;
	}

	len = EIB_MAX_LINE;
	bufp = msgbuf;
	for (i = 0; i < sz; i++) {
		if (i == 0) {
			(void) snprintf(bufp, len, "eoib%02d__%02x ",
			    inst, p[i]);
			len -= 11;
			bufp += 11;
		} else if (i < (sz - 1)) {
			(void) snprintf(bufp, len, "%02x ", p[i]);
			len -= 3;
			bufp += 3;
		} else {
			(void) snprintf(bufp, len, "%02x\n", p[i]);
			len -= 3;
			bufp += 3;
		}
	}

	eib_log(msgbuf);
}

void
eib_dprintf_args(int inst, const char *fmt, ...)
{
	va_list ap;
	int msglen;
	char msgbuf[EIB_MAX_LINE];
	char newfmt[EIB_MAX_LINE];

	if ((eib_log_level & EIB_MSGS_ARGS) != EIB_MSGS_ARGS)
		return;

	(void) snprintf(newfmt, EIB_MAX_LINE, "eoib%d__%s", inst, fmt);

	va_start(ap, fmt);
	msglen = vsnprintf(msgbuf, EIB_MAX_LINE, newfmt, ap);
	va_end(ap);

	if (msglen > 0) {
		eib_log(msgbuf);
	}
}

void
eib_dprintf_debug(int inst, const char *fmt, ...)
{
	va_list ap;
	int msglen;
	char msgbuf[EIB_MAX_LINE];
	char newfmt[EIB_MAX_LINE];

	if ((eib_log_level & EIB_MSGS_DEBUG) != EIB_MSGS_DEBUG)
		return;

	(void) snprintf(newfmt, EIB_MAX_LINE, "eoib%d__%s", inst, fmt);

	va_start(ap, fmt);
	msglen = vsnprintf(msgbuf, EIB_MAX_LINE, newfmt, ap);
	va_end(ap);

	if (msglen > 0) {
		eib_log(msgbuf);
	}
}
#endif

void
eib_dprintf_warn(int inst, const char *fmt, ...)
{
	va_list ap;
	int msglen;
	char msgbuf[EIB_MAX_LINE];
	char newfmt[EIB_MAX_LINE];

	if ((eib_log_level & EIB_MSGS_WARN) != EIB_MSGS_WARN)
		return;

	(void) snprintf(newfmt, EIB_MAX_LINE, "eoib%d__%s", inst, fmt);

	va_start(ap, fmt);
	msglen = vsnprintf(msgbuf, EIB_MAX_LINE, newfmt, ap);
	va_end(ap);

	if (msglen > 0) {
		eib_log(msgbuf);
	}
}

void
eib_dprintf_err(int inst, const char *fmt, ...)
{
	va_list ap;
	int msglen;
	char msgbuf[EIB_MAX_LINE];
	char newfmt[EIB_MAX_LINE];

	if ((eib_log_level & EIB_MSGS_ERR) != EIB_MSGS_ERR)
		return;

	(void) snprintf(newfmt, EIB_MAX_LINE, "eoib%d__%s", inst, fmt);

	va_start(ap, fmt);
	msglen = vsnprintf(msgbuf, EIB_MAX_LINE, newfmt, ap);
	va_end(ap);

	if (msglen > 0) {
		eib_log(msgbuf);
		cmn_err(CE_WARN, "!%s\n", msgbuf);
	}
}

void
eib_dprintf_crit(int inst, const char *fmt, ...)
{
	va_list ap;
	int msglen;
	char msgbuf[EIB_MAX_LINE];
	char newfmt[EIB_MAX_LINE];

	if ((eib_log_level & EIB_MSGS_CRIT) != EIB_MSGS_CRIT)
		return;

	(void) snprintf(newfmt, EIB_MAX_LINE, "eoib%d__%s", inst, fmt);

	va_start(ap, fmt);
	msglen = vsnprintf(msgbuf, EIB_MAX_LINE, newfmt, ap);
	va_end(ap);

	if (msglen > 0) {
		eib_log(msgbuf);
		cmn_err(CE_PANIC, "!%s\n", msgbuf);
	}
}
