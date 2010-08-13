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

#include <sys/ib/clients/eoib/enx_impl.h>

/*
 * Defaults
 */
uint_t enx_log_size = ENX_LOGSZ_DEFAULT;
int enx_log_level = ENX_MSGS_DEFAULT | ENX_MSGS_DEBUG;
int enx_log_timestamps = 0;

/*
 * Debug variables, should not be tunables so allocated debug buffer
 * and its size remain consistent.
 */
static kmutex_t enx_debug_buf_lock;
static uint8_t *enx_debug_buf;
static uint32_t enx_debug_buf_ndx;
static uint_t enx_debug_buf_sz;

static void eibnx_log(char *);

void
eibnx_debug_init(void)
{
	enx_debug_buf_ndx = 0;
	enx_debug_buf_sz = enx_log_size;
	enx_debug_buf = kmem_zalloc(enx_debug_buf_sz, KM_SLEEP);

	mutex_init(&enx_debug_buf_lock, NULL, MUTEX_DRIVER, NULL);
}

void
eibnx_debug_fini(void)
{
	mutex_destroy(&enx_debug_buf_lock);

	if (enx_debug_buf && enx_debug_buf_sz) {
		kmem_free(enx_debug_buf, enx_debug_buf_sz);
		enx_debug_buf = NULL;
	}
	enx_debug_buf_sz = 0;
	enx_debug_buf_ndx = 0;
}

void
eibnx_log(char *msg)
{
	uint32_t off;
	int msglen;
	char msgbuf[ENX_MAX_LINE];

	if (enx_debug_buf == NULL)
		return;

	if (enx_log_timestamps) {
		msglen = snprintf(msgbuf, ENX_MAX_LINE, "%llx: %s",
		    (unsigned long long)ddi_get_lbolt64(), msg);
	} else {
		msglen = snprintf(msgbuf, ENX_MAX_LINE, "%s", msg);
	}

	if (msglen < 0)
		return;
	else if (msglen >= ENX_MAX_LINE)
		msglen = ENX_MAX_LINE - 1;

	mutex_enter(&enx_debug_buf_lock);

	if ((enx_debug_buf_ndx == 0) ||
	    (enx_debug_buf[enx_debug_buf_ndx-1] != '\n')) {
		enx_debug_buf[enx_debug_buf_ndx] = '\n';
		enx_debug_buf_ndx++;
	}

	off = enx_debug_buf_ndx;	/* current msg should go here */

	enx_debug_buf_ndx += msglen;	/* next msg should start here */
	enx_debug_buf[enx_debug_buf_ndx] = 0;	/* terminate current msg */

	if (enx_debug_buf_ndx >= (enx_debug_buf_sz - 2 * ENX_MAX_LINE))
		enx_debug_buf_ndx = 0;

	mutex_exit(&enx_debug_buf_lock);

	bcopy(msgbuf, enx_debug_buf+off, msglen);    /* no lock needed */
}

#ifdef ENX_DEBUG
void
eibnx_dprintf_verbose(const char *fmt, ...)
{
	va_list ap;
	int msglen;
	char msgbuf[ENX_MAX_LINE];
	char newfmt[ENX_MAX_LINE];

	if ((enx_log_level & ENX_MSGS_VERBOSE) != ENX_MSGS_VERBOSE)
		return;

	(void) snprintf(newfmt, ENX_MAX_LINE, "..........%s", fmt);

	va_start(ap, fmt);
	msglen = vsnprintf(msgbuf, ENX_MAX_LINE, newfmt, ap);
	va_end(ap);

	if (msglen > 0) {
		eibnx_log(msgbuf);
	}
}

void
eibnx_dprintf_args(const char *fmt, ...)
{
	va_list ap;
	int msglen;
	char msgbuf[ENX_MAX_LINE];
	char newfmt[ENX_MAX_LINE];

	if ((enx_log_level & ENX_MSGS_ARGS) != ENX_MSGS_ARGS)
		return;

	(void) snprintf(newfmt, ENX_MAX_LINE, "........%s", fmt);

	va_start(ap, fmt);
	msglen = vsnprintf(msgbuf, ENX_MAX_LINE, newfmt, ap);
	va_end(ap);

	if (msglen > 0) {
		eibnx_log(msgbuf);
	}
}

void
eibnx_dprintf_debug(const char *fmt, ...)
{
	va_list ap;
	int msglen;
	char msgbuf[ENX_MAX_LINE];
	char newfmt[ENX_MAX_LINE];

	if ((enx_log_level & ENX_MSGS_DEBUG) != ENX_MSGS_DEBUG)
		return;

	(void) snprintf(newfmt, ENX_MAX_LINE, "......%s", fmt);

	va_start(ap, fmt);
	msglen = vsnprintf(msgbuf, ENX_MAX_LINE, newfmt, ap);
	va_end(ap);

	if (msglen > 0) {
		eibnx_log(msgbuf);
	}
}
#endif

void
eibnx_dprintf_warn(const char *fmt, ...)
{
	va_list ap;
	int msglen;
	char msgbuf[ENX_MAX_LINE];
	char newfmt[ENX_MAX_LINE];

	if ((enx_log_level & ENX_MSGS_WARN) != ENX_MSGS_WARN)
		return;

	(void) snprintf(newfmt, ENX_MAX_LINE, "....%s", fmt);

	va_start(ap, fmt);
	msglen = vsnprintf(msgbuf, ENX_MAX_LINE, newfmt, ap);
	va_end(ap);

	if (msglen > 0) {
		eibnx_log(msgbuf);
	}
}

void
eibnx_dprintf_err(const char *fmt, ...)
{
	va_list ap;
	int msglen;
	char msgbuf[ENX_MAX_LINE];
	char newfmt[ENX_MAX_LINE];

	if ((enx_log_level & ENX_MSGS_ERR) != ENX_MSGS_ERR)
		return;

	(void) snprintf(newfmt, ENX_MAX_LINE, "..%s", fmt);

	va_start(ap, fmt);
	msglen = vsnprintf(msgbuf, ENX_MAX_LINE, newfmt, ap);
	va_end(ap);

	if (msglen > 0) {
		eibnx_log(msgbuf);
		cmn_err(CE_WARN, "!%s\n", msgbuf);
	}
}

void
eibnx_dprintf_crit(const char *fmt, ...)
{
	va_list ap;
	int msglen;
	char msgbuf[ENX_MAX_LINE];

	if ((enx_log_level & ENX_MSGS_CRIT) != ENX_MSGS_CRIT)
		return;

	va_start(ap, fmt);
	msglen = vsnprintf(msgbuf, ENX_MAX_LINE, fmt, ap);
	va_end(ap);

	if (msglen > 0) {
		eibnx_log(msgbuf);
		cmn_err(CE_PANIC, "!%s\n", msgbuf);
	}
}
