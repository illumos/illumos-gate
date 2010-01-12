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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <atomic.h>
#include <alloca.h>
#include <syslog.h>
#include <strings.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <exacct.h>

#include <fmd_subr.h>
#include <fmd_conf.h>
#include <fmd_error.h>
#include <fmd_thread.h>
#include <fmd_protocol.h>
#include <fmd_event.h>
#include <fmd_dispq.h>
#include <fmd_log.h>

#include <fmd.h>

int
fmd_assert(const char *expr, const char *file, int line)
{
	fmd_panic("\"%s\", line %d: assertion failed: %s\n", file, line, expr);
	/*NOTREACHED*/
	return (0);
}

/*
 * To implement a reasonable panic() equivalent for fmd, we atomically bump a
 * global counter of calls to fmd_vpanic() and attempt to print a panic message
 * to stderr and dump core as a result of raising SIGABRT.  This function must
 * not attempt to grab any locks so that it can be called from any fmd code.
 */
void
fmd_vpanic(const char *format, va_list ap)
{
	int oserr = errno;
	pthread_t tid = pthread_self();

	fmd_thread_t *tp;
	char msg[BUFSIZ];
	size_t len;

	/*
	 * If this is not the first call to fmd_vpanic(), then check d_panictid
	 * to see if we are the panic thread.  If so, then proceed directly to
	 * abort() because we have recursively panicked.  If not, then pause()
	 * indefinitely waiting for the panic thread to terminate the daemon.
	 */
	if (atomic_add_32_nv(&fmd.d_panicrefs, 1) != 1) {
		while (fmd.d_panictid != tid)
			(void) pause();
		goto abort;
	}

	/*
	 * Use fmd.d_pid != 0 as a cheap test to see if fmd.d_key is valid
	 * (i.e. we're after fmd_create() and before fmd_destroy()).
	 */
	if (fmd.d_pid != 0 && (tp = pthread_getspecific(fmd.d_key)) != NULL)
		(void) tp->thr_trfunc(tp->thr_trdata, FMD_DBG_ERR, format, ap);

	fmd.d_panicstr = msg;
	fmd.d_panictid = tid;

	(void) snprintf(msg, sizeof (msg), "%s: ABORT: ",
	    fmd.d_pname ? fmd.d_pname : "fmd");

	len = strlen(msg);
	(void) vsnprintf(msg + len, sizeof (msg) - len, format, ap);

	if (strchr(format, '\n') == NULL) {
		len = strlen(msg);
		(void) snprintf(msg + len, sizeof (msg) - len, ": %s\n",
		    fmd_strerror(oserr));
	}

	(void) write(STDERR_FILENO, msg, strlen(msg));

abort:
	abort();
	_exit(FMD_EXIT_ERROR);
}

/*PRINTFLIKE1*/
void
fmd_panic(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	fmd_vpanic(format, ap);
	va_end(ap);
}

void
fmd_verror(int err, const char *format, va_list ap)
{
	int oserr = errno;
	fmd_thread_t *tp;
	nvlist_t *nvl;
	fmd_event_t *e;
	char *class;

	if ((tp = pthread_getspecific(fmd.d_key)) != NULL) {
		(void) tp->thr_trfunc(tp->thr_trdata, FMD_DBG_ERR, format, ap);
		tp->thr_errdepth++;
	}

	(void) pthread_mutex_lock(&fmd.d_err_lock);

	if (fmd.d_errstats != NULL && err >= EFMD_UNKNOWN && err < EFMD_END)
		fmd.d_errstats[err - EFMD_UNKNOWN].fmds_value.ui64++;

	if (fmd.d_fg || !fmd.d_running) {
		(void) fprintf(stderr, "%s: ", fmd.d_pname);
		(void) vfprintf(stderr, format, ap);

		if (strchr(format, '\n') == NULL)
			(void) fprintf(stderr, ": %s\n", fmd_strerror(oserr));
	}

	(void) pthread_mutex_unlock(&fmd.d_err_lock);

	/*
	 * If we are at error nesting level one and running in the background,
	 * log the error as an ereport to our own log and dispatch it.  If the
	 * FMD_LF_BUSY flag is set, we can't attempt to log the event because
	 * a replay is running and we will deadlock on ourself in log_append.
	 */
	if (!fmd.d_fg && fmd.d_running &&
	    tp != NULL && tp->thr_errdepth == 1 &&
	    (nvl = fmd_protocol_fmderror(err, format, ap)) != NULL) {

		(void) nvlist_lookup_string(nvl, FM_CLASS, &class);
		e = fmd_event_create(FMD_EVT_PROTOCOL, FMD_HRT_NOW, nvl, class);

		(void) pthread_rwlock_rdlock(&fmd.d_log_lock);
		if (!(fmd.d_errlog->log_flags & FMD_LF_BUSY))
			fmd_log_append(fmd.d_errlog, e, NULL);
		(void) pthread_rwlock_unlock(&fmd.d_log_lock);

		fmd_dispq_dispatch(fmd.d_disp, e, class);
	}

	if (tp != NULL)
		tp->thr_errdepth--;

	if (err == EFMD_EXIT) {
		int core = 0;

		(void) fmd_conf_getprop(fmd.d_conf, "core", &core);
		if (core)
			fmd_panic("forcing core dump at user request\n");

		exit(FMD_EXIT_ERROR);
	}
}

/*PRINTFLIKE2*/
void
fmd_error(int err, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	fmd_verror(err, format, ap);
	va_end(ap);
}

void
fmd_vdprintf(int mask, const char *format, va_list ap)
{
	fmd_thread_t *tp;
	char *msg;
	size_t len;
	char c;

	if (!(fmd.d_fmd_debug & mask))
		return; /* none of the specified modes are enabled */

	if ((tp = pthread_getspecific(fmd.d_key)) != NULL)
		(void) tp->thr_trfunc(tp->thr_trdata, mask, format, ap);

	if (fmd.d_fmd_dbout == 0)
		return; /* no debugging output sinks are enabled */

	len = vsnprintf(&c, 1, format, ap);
	msg = alloca(len + 2);
	(void) vsnprintf(msg, len + 1, format, ap);

	if (msg[len - 1] != '\n')
		(void) strcpy(&msg[len], "\n");

	if (fmd.d_fmd_dbout & FMD_DBOUT_STDERR) {
		(void) pthread_mutex_lock(&fmd.d_err_lock);
		(void) fprintf(stderr, "%s DEBUG: %s", fmd.d_pname, msg);
		(void) pthread_mutex_unlock(&fmd.d_err_lock);
	}

	if (fmd.d_fmd_dbout & FMD_DBOUT_SYSLOG) {
		syslog(LOG_DEBUG | LOG_DAEMON,
		    "%s DEBUG: %s", fmd.d_pname, msg);
	}
}

/*PRINTFLIKE2*/
void
fmd_dprintf(int mask, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	fmd_vdprintf(mask, format, ap);
	va_end(ap);
}

/*
 * The fmd_trace.c routines set tr_file and tr_line to NULL and 0 respectively.
 * If they are invoked from a macro (see <fmd_subr.h>) this tail function is
 * called as part of the TRACE() macro to fill in these fields from the cpp
 * macro values for __FILE__ and __LINE__.  No locking is needed because all
 * trace buffers are allocated separately for each fmd thread.
 */
void
fmd_trace_cpp(void *ptr, const char *file, int line)
{
	fmd_tracerec_t *trp = ptr;

	if (trp != NULL) {
		trp->tr_file = file;
		trp->tr_line = line;
	}
}

/*
 * The fmd_trace() function is the wrapper for the tracing routines provided in
 * fmd_trace.c.  It is invoked by the TRACE() macro in <fmd_subr.h>, and uses
 * the per-thread trace buffer set up in fmd_thread.c to trace debugging info.
 */
/*PRINTFLIKE2*/
void *
fmd_trace(uint_t tag, const char *format, ...)
{
	fmd_thread_t *tp = pthread_getspecific(fmd.d_key);
	va_list ap;
	void *trp;

	if (tp == NULL)
		return (NULL); /* drop trace record if not ready yet */

	va_start(ap, format);
	trp = tp->thr_trfunc(tp->thr_trdata, tag, format, ap);
	va_end(ap);

	return (trp);
}

const char *
fmd_ea_strerror(int err)
{
	switch (err) {
	case EXR_OK:		return ("no exacct error");
	case EXR_SYSCALL_FAIL:	return (fmd_strerror(errno));
	case EXR_CORRUPT_FILE:	return ("file corruption detected");
	case EXR_EOF:		return ("end-of-file reached");
	case EXR_NO_CREATOR:	return ("creator tag mismatch");
	case EXR_INVALID_BUF:	return ("invalid unpack buffer");
	case EXR_NOTSUPP:	return ("exacct operation not supported");
	case EXR_UNKN_VERSION:	return ("unsupported exacct file version");
	case EXR_INVALID_OBJ:	return ("invalid exacct object");
	default:		return ("unknown exacct error");
	}
}

/*
 * Create a local ENA value for fmd-generated ereports.  We use ENA Format 1
 * with the low bits of gethrtime() and pthread_self() as the processor ID.
 */
uint64_t
fmd_ena(void)
{
	hrtime_t hrt = fmd_time_gethrtime();

	return ((uint64_t)((FM_ENA_FMT1 & ENA_FORMAT_MASK) |
	    ((pthread_self() << ENA_FMT1_CPUID_SHFT) & ENA_FMT1_CPUID_MASK) |
	    ((hrt << ENA_FMT1_TIME_SHFT) & ENA_FMT1_TIME_MASK)));
}

/*
 * fmd_ntz32() computes the number of trailing zeroes.  The algorithm here is
 * from "Hacker's Delight" by Henry Warren, Jr.
 */
uint32_t
fmd_ntz32(uint32_t x)
{
	uint_t n = 1;

	if (x == 0)
		return (32);

	if ((x & 0xFFFF) == 0) {
		n += 16;
		x >>= 16;
	}

	if ((x & 0xFF) == 0) {
		n += 8;
		x >>= 8;
	}

	if ((x & 0xF) == 0) {
		n += 4;
		x >>= 4;
	}

	if ((x & 0x3) == 0) {
		n += 2;
		x >>= 2;
	}

	return (n - (x & 1));
}
