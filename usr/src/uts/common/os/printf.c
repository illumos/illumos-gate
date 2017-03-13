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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2016 Joyent, Inc.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/inline.h>
#include <sys/varargs.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/syslog.h>
#include <sys/log.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/session.h>
#include <sys/stream.h>
#include <sys/kmem.h>
#include <sys/kobj.h>
#include <sys/atomic.h>
#include <sys/console.h>
#include <sys/cpuvar.h>
#include <sys/modctl.h>
#include <sys/reboot.h>
#include <sys/debug.h>
#include <sys/panic.h>
#include <sys/spl.h>
#include <sys/zone.h>
#include <sys/sunddi.h>

/*
 * In some debugging situations it's useful to log all messages to panicbuf,
 * which is persistent across reboots (on most platforms).  The range
 * panicbuf[panicbuf_log..PANICBUFSIZE-1] may be used for this purpose.
 * By default, panicbuf_log == PANICBUFSIZE and no messages are logged.
 * To enable panicbuf logging, set panicbuf_log to a small value, say 1K;
 * this will reserve 1K for panic information and 7K for message logging.
 */
uint32_t panicbuf_log = PANICBUFSIZE;
uint32_t panicbuf_index = PANICBUFSIZE;

static int aask, aok;
static int ce_to_sl[CE_IGNORE] = { SL_NOTE, SL_NOTE, SL_WARN, SL_FATAL };
static char ce_prefix[CE_IGNORE][10] = { "", "NOTICE: ", "WARNING: ", "" };
static char ce_suffix[CE_IGNORE][2] = { "", "\n", "\n", "" };

static void
cprintf(const char *fmt, va_list adx, int sl, const char *prefix,
    const char *suffix, void *site, int mid, int sid, int level,
    zoneid_t zoneid, dev_info_t *dip)
{
	uint32_t msgid;
	size_t bufsize = LOG_MSGSIZE;
	char buf[LOG_MSGSIZE];
	char *bufp = buf;
	char *body, *msgp, *bufend;
	mblk_t *mp;
	int s, on_intr;
	size_t len;

	s = splhi();
	on_intr = CPU_ON_INTR(CPU) ||
	    (interrupts_unleashed && (spltoipl(s) > LOCK_LEVEL));
	splx(s);

	ASSERT(zoneid == GLOBAL_ZONEID || !on_intr);

	STRLOG_MAKE_MSGID(fmt, msgid);

	if (strchr("^!?", fmt[0]) != NULL) {
		if (fmt[0] == '^')
			sl |= SL_CONSONLY;
		else if (fmt[0] == '!' ||
		    (prefix[0] == '\0' && !(boothowto & RB_VERBOSE)))
			sl = (sl & ~(SL_USER | SL_NOTE)) | SL_LOGONLY;
		fmt++;
	}

	if ((sl & SL_USER) && (MUTEX_HELD(&pidlock) || on_intr)) {
		zoneid = getzoneid();
		sl = sl & ~(SL_USER | SL_LOGONLY) | SL_CONSOLE;
	}

retry:
	bufend = bufp + bufsize;
	msgp = bufp;
	body = msgp += snprintf(msgp, bufend - msgp,
	    "%s: [ID %u FACILITY_AND_PRIORITY] ",
	    mod_containing_pc(site), msgid);
	msgp += snprintf(msgp, bufend - msgp, prefix);
	if (dip != NULL)
		msgp += snprintf(msgp, bufend - msgp, "%s%d: ",
		    ddi_driver_name(dip), ddi_get_instance(dip));
	msgp += vsnprintf(msgp, bufend - msgp, fmt, adx);
	msgp += snprintf(msgp, bufend - msgp, suffix);
	len = strlen(body);

	if (((sl & SL_CONSONLY) && panicstr) ||
	    (zoneid == GLOBAL_ZONEID && log_global.lz_active == 0)) {
		console_printf("%s", body);
		goto out;
	}

	if (msgp - bufp >= bufsize && !on_intr) {
		ASSERT(bufp == buf);
		bufsize = msgp - bufp + 1;
		bufp = kmem_alloc(bufsize, KM_NOSLEEP);
		if (bufp != NULL)
			goto retry;
		bufsize = LOG_MSGSIZE;
		bufp = buf;
	}

	mp = log_makemsg(mid, sid, level, sl, LOG_KERN, bufp,
	    MIN(bufsize, msgp - bufp + 1), on_intr);
	if (mp == NULL) {
		if ((sl & (SL_CONSOLE | SL_LOGONLY)) == SL_CONSOLE && !on_intr)
			console_printf("%s", body);
		goto out;
	}

	if (sl & SL_USER) {
		ssize_t resid;
		sess_t *sp;

		if ((sp = tty_hold()) != NULL) {
			if (sp->s_vp != NULL)
				(void) vn_rdwr(UIO_WRITE, sp->s_vp, body,
				    len, 0LL, UIO_SYSSPACE, FAPPEND,
				    (rlim64_t)LOG_HIWAT, kcred, &resid);
			tty_rele(sp);
		}
	}

	if (on_intr && !panicstr) {
		(void) putq(log_intrq, mp);
		softcall((void (*)(void *))log_flushq, log_intrq);
	} else {
		log_sendmsg(mp, zoneid);
	}
out:
	if (panicbuf_log + len < PANICBUFSIZE) {
		uint32_t old, new;
		do {
			old = panicbuf_index;
			new = old + len;
			if (new >= PANICBUFSIZE)
				new = panicbuf_log + len;
		} while (atomic_cas_32(&panicbuf_index, old, new) != old);
		bcopy(body, &panicbuf[new - len], len);
	}
	if (bufp != buf)
		kmem_free(bufp, bufsize);
}

void
vzprintf(zoneid_t zoneid, const char *fmt, va_list adx)
{
	cprintf(fmt, adx, SL_CONSOLE | SL_NOTE, "", "", caller(), 0, 0, 0,
	    zoneid, NULL);
}

void
vprintf(const char *fmt, va_list adx)
{
	vzprintf(GLOBAL_ZONEID, fmt, adx);
}

/*PRINTFLIKE1*/
void
printf(const char *fmt, ...)
{
	va_list adx;

	va_start(adx, fmt);
	cprintf(fmt, adx, SL_CONSOLE | SL_NOTE, "", "", caller(), 0, 0, 0,
	    GLOBAL_ZONEID, NULL);
	va_end(adx);
}

/*PRINTFLIKE2*/
void
zprintf(zoneid_t zoneid, const char *fmt, ...)
{
	va_list adx;

	va_start(adx, fmt);
	cprintf(fmt, adx, SL_CONSOLE | SL_NOTE, "", "", caller(), 0, 0, 0,
	    zoneid, NULL);
	va_end(adx);
}

void
vuprintf(const char *fmt, va_list adx)
{
	va_list adxcp;
	va_copy(adxcp, adx);

	/* Message the user tty, if any, and the global zone syslog */
	cprintf(fmt, adx, SL_CONSOLE | SL_LOGONLY | SL_USER | SL_NOTE,
	    "", "", caller(), 0, 0, 0, GLOBAL_ZONEID, NULL);

	/* Now message the local zone syslog */
	if (!INGLOBALZONE(curproc))
		cprintf(fmt, adxcp, SL_CONSOLE | SL_LOGONLY | SL_NOTE,
		    "", "", caller(), 0, 0, 0, getzoneid(), NULL);

	va_end(adxcp);
}

/*PRINTFLIKE1*/
void
uprintf(const char *fmt, ...)
{
	va_list adx;

	va_start(adx, fmt);

	vuprintf(fmt, adx);

	va_end(adx);
}

static void
vzdcmn_err(zoneid_t zoneid, void *site, int ce, const char *fmt, va_list adx,
    dev_info_t *dip)
{
	if (ce == CE_PANIC)
		vpanic(fmt, adx);
	if ((uint_t)ce < CE_IGNORE) {
		cprintf(fmt, adx, ce_to_sl[ce] | SL_CONSOLE,
		    ce_prefix[ce], ce_suffix[ce], site, 0, 0, 0,
		    zoneid, dip);
	}
}

void
vzcmn_err(zoneid_t zoneid, int ce, const char *fmt, va_list adx)
{
	vzdcmn_err(zoneid, caller(), ce, fmt, adx, NULL);
}

void
vcmn_err(int ce, const char *fmt, va_list adx)
{
	vzdcmn_err(GLOBAL_ZONEID, caller(), ce, fmt, adx, NULL);
}

/*PRINTFLIKE3*/
void
vdev_err(dev_info_t *dip, int ce, const char *fmt, va_list adx)
{
	vzdcmn_err(GLOBAL_ZONEID, caller(), ce, fmt, adx, dip);
}

/*PRINTFLIKE2*/
void
cmn_err(int ce, const char *fmt, ...)
{
	va_list adx;

	va_start(adx, fmt);
	vzdcmn_err(GLOBAL_ZONEID, caller(), ce, fmt, adx, NULL);
	va_end(adx);
}

/*PRINTFLIKE3*/
void
zcmn_err(zoneid_t zoneid, int ce, const char *fmt, ...)
{
	va_list adx;

	va_start(adx, fmt);
	vzdcmn_err(zoneid, caller(), ce, fmt, adx, NULL);
	va_end(adx);
}

/*PRINTFLIKE3*/
void
dev_err(dev_info_t *dip, int ce, char *fmt, ...)
{
	va_list adx;

	va_start(adx, fmt);
	vzdcmn_err(GLOBAL_ZONEID, caller(), ce, fmt, adx, dip);
	va_end(adx);
}

int
assfail(const char *a, const char *f, int l)
{
	if (aask)  {
		printf("ASSERTION CAUGHT: %s, file: %s, line: %d", a, f, l);
		debug_enter(NULL);
	}

	if (!aok && !panicstr)
		panic("assertion failed: %s, file: %s, line: %d", a, f, l);

	return (0);
}

void
assfail3(const char *a, uintmax_t lv, const char *op, uintmax_t rv,
    const char *f, int l)
{
	if (aask)  {
		printf("ASSERTION CAUGHT: %s (0x%llx %s 0x%llx), file: %s, "
		    "line: %d", a, (u_longlong_t)lv, op, (u_longlong_t)rv,
		    f, l);
		debug_enter(NULL);
	}

	if (!aok && !panicstr)
		panic("assertion failed: %s (0x%llx %s 0x%llx), file: %s, "
		    "line: %d", a, (u_longlong_t)lv, op, (u_longlong_t)rv,
		    f, l);
}

int
strlog(short mid, short sid, char level, ushort_t sl, char *fmt, ...)
{
	if (sl & log_global.lz_active) {
		va_list adx;
		va_start(adx, fmt);
		cprintf(fmt, adx, sl, "", "", caller(), mid, sid, level,
		    GLOBAL_ZONEID, NULL);
		va_end(adx);
	}
	return (1);
}

int
vstrlog(short mid, short sid, char level, ushort_t sl, char *fmt, va_list adx)
{
	if (sl & log_global.lz_active)
		cprintf(fmt, adx, sl, "", "", caller(), mid, sid, level,
		    GLOBAL_ZONEID, NULL);
	return (1);
}
