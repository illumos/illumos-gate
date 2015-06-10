/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>

#include <smbsrv/smbinfo.h>
#include <smbsrv/smb_ioctl.h>
#include "smbd.h"

#define	CBUFSIZ 26	/* ctime(3c) */

static const char *pri_name[LOG_DEBUG+1] = {
	"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"
};

static void
smb_svc_log(int pri, const char *fmt, va_list ap)
{
	static time_t prev_ts;
	char fbuf[SMBD_LOG_MSGSIZE];
	char cbuf[CBUFSIZ];
	char *newfmt;
	time_t ts;
	int save_errno = errno;

	pri &= LOG_PRIMASK;
	if (smbd.s_debug == 0 && pri == LOG_DEBUG)
		return;

	ts = time(NULL);
	if (prev_ts != ts) {
		prev_ts = ts;
		/* NB: cbuf has \n */
		(void) fprintf(stdout, "@ %s",
		    ctime_r(&ts, cbuf, sizeof (cbuf)));
	}

	newfmt = smb_syslog_fmt_m(fbuf, sizeof (fbuf), fmt, save_errno);

	flockfile(stdout);
	(void) fprintf(stdout, "smbd.%s: ", pri_name[pri]);
	/* LINTED E_SEC_PRINTF_VAR_FMT */
	(void) vfprintf(stdout, newfmt, ap);
	(void) fprintf(stdout, "\n");
	funlockfile(stdout);

	(void) fflush(stdout);
}

/*
 * Provide a replacement for libsmb:smb_vsyslog() that prints messages
 * both to the normal sysloc(3c), and to stdout, which ends up in:
 *  /var/svc/log/network-smb-server:default.log
 * It's much easier to follow debug messages in the service log.
 */
void
smb_vsyslog(int pri, const char *fmt, va_list ap)
{
	va_list tap;

	va_copy(tap, ap);
	smb_svc_log(pri, fmt, tap);
	va_end(tap);

	vsyslog(pri, fmt, ap);
}

/*
 * An override for libsmb:smb_trace().  As the comment there says:
 *
 * This function is designed to be used with dtrace, i.e. see:
 * usr/src/cmd/smbsrv/dtrace/smbd-all.d
 *
 * Outside of dtrace, the messages passed to this function usually
 * lack sufficient context to be useful, so don't log them.
 * However, if you insist, set debug >= 3 and this will log them.
 */
void
smb_trace(const char *s)
{
	if (smbd.s_debug >= 3)
		(void) fprintf(stdout, "smbd.trace: %s\n", s);
}
