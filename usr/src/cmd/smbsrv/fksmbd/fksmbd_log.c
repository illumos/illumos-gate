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
#include <sys/strlog.h>

#include <smbsrv/smbinfo.h>
#include <smbsrv/smb_ioctl.h>
#include "smbd.h"

#include <libfakekernel/fakekernel.h>

static const char *pri_name[LOG_DEBUG+1] = {
	"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"
};


/*
 * Provide a replacement for libsmb:smb_vsyslog() that just
 * prints the messages to stdout for "fksmbd" debugging.
 */
void
smb_vsyslog(int pri, const char *fmt, va_list ap)
{
	int save_errno = errno;
	char buf[SMBD_LOG_MSGSIZE];
	char *newfmt;

	pri &= LOG_PRIMASK;

	if (smbd.s_debug == 0 && pri > LOG_INFO)
		return;

	newfmt = smb_syslog_fmt_m(buf, sizeof (buf), fmt, save_errno);

	flockfile(stdout);
	(void) fprintf(stdout, "fksmbd.%s: ", pri_name[pri]);
	/* LINTED E_SEC_PRINTF_VAR_FMT */
	(void) vfprintf(stdout, newfmt, ap);
	(void) fprintf(stdout, "\n");
	funlockfile(stdout);

	(void) fflush(stdout);
}

/*
 * Provide a real function (one that prints something) to replace
 * the stub in libfakekernel.  This prints cmn_err() messages.
 */
void
fakekernel_putlog(char *msg, size_t len, int flags)
{

	/*
	 * [CE_CONT, CE_NOTE, CE_WARN, CE_PANIC] maps to
	 * [SL_NOTE, SL_NOTE, SL_WARN, SL_FATAL]
	 */
	if (smbd.s_debug == 0 && (flags & SL_NOTE))
		return;
	(void) fwrite(msg, 1, len, stdout);
	(void) fflush(stdout);
}

/*
 * Initialization function called at the start of fksmbd:main().
 * Call an empty function in both of libfksmbsrv, libfakekernel,
 * just to force them to load so we can set breakpoints in them
 * without debugger forceload tricks.  This also avoids elfchk
 * complaints from libfakekernel, which we don't call directly
 * except for here.
 */
void
fksmbd_init(void)
{
	fksmbsrv_drv_load();
	fakekernel_init();
}
