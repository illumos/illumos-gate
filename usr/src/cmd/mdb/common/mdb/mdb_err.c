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

#include <mdb/mdb_signal.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb.h>

#include <thread_db.h>
#include <rtld_db.h>
#include <libctf.h>
#include <strings.h>
#include <stdlib.h>

static const char *const _mdb_errlist[] = {
	"unknown symbol name",				/* EMDB_NOSYM */
	"unknown object file name",			/* EMDB_NOOBJ */
	"no mapping for address",			/* EMDB_NOMAP */
	"unknown dcmd name",				/* EMDB_NODCMD */
	"unknown walk name",				/* EMDB_NOWALK */
	"dcmd name already in use",			/* EMDB_DCMDEXISTS */
	"walk name already in use",			/* EMDB_WALKEXISTS */
	"no support for platform",			/* EMDB_NOPLAT */
	"no process active",				/* EMDB_NOPROC */
	"specified name is too long",			/* EMDB_NAME2BIG */
	"specified name contains illegal characters",	/* EMDB_NAMEBAD */
	"failed to allocate needed memory",		/* EMDB_ALLOC */
	"specified module is not loaded",		/* EMDB_NOMOD */
	"cannot unload built-in module",		/* EMDB_BUILTINMOD */
	"no walk is currently active",			/* EMDB_NOWCB */
	"invalid walk state argument",			/* EMDB_BADWCB */
	"walker does not accept starting address",	/* EMDB_NOWALKLOC */
	"walker requires starting address",		/* EMDB_NOWALKGLOB */
	"failed to initialize walk",			/* EMDB_WALKINIT */
	"walker cannot be layered on itself",		/* EMDB_WALKLOOP */
	"i/o stream is read-only",			/* EMDB_IORO */
	"i/o stream is write-only",			/* EMDB_IOWO */
	"no symbol corresponds to address",		/* EMDB_NOSYMADDR */
	"unknown disassembler name",			/* EMDB_NODIS */
	"disassembler name already in use",		/* EMDB_DISEXISTS */
	"no such software event specifier",		/* EMDB_NOSESPEC */
	"no such xdata available",			/* EMDB_NOXD */
	"xdata name already in use",			/* EMDB_XDEXISTS */
	"operation not supported by target",		/* EMDB_TGTNOTSUP */
	"target is not open for writing",		/* EMDB_TGTRDONLY */
	"invalid register name",			/* EMDB_BADREG */
	"no register set available for thread",		/* EMDB_NOREGS */
	"stack address is not properly aligned",	/* EMDB_STKALIGN */
	"no executable file is open",			/* EMDB_NOEXEC */
	"failed to evaluate command",			/* EMDB_EVAL */
	"command cancelled by user",			/* EMDB_CANCEL */
	"only %lu of %lu bytes could be read",		/* EMDB_PARTIAL */
	"dcmd failed",					/* EMDB_DCFAIL */
	"improper dcmd usage",				/* EMDB_DCUSAGE */
	"target error",					/* EMDB_TGT */
	"invalid system call number",			/* EMDB_BADSYSNUM */
	"invalid signal number",			/* EMDB_BADSIGNUM */
	"invalid fault number",				/* EMDB_BADFLTNUM */
	"target is currently executing",		/* EMDB_TGTBUSY */
	"target has completed execution",		/* EMDB_TGTZOMB */
	"target is a core file",			/* EMDB_TGTCORE */
	"debugger lost control of target",		/* EMDB_TGTLOST */
	"libthread_db call failed unexpectedly",	/* EMDB_TDB */
	"failed to dlopen library",			/* EMDB_RTLD */
	"librtld_db call failed unexpectedly",		/* EMDB_RTLD_DB */
	"runtime linker data not available",		/* EMDB_NORTLD */
	"invalid thread identifier",			/* EMDB_NOTHREAD */
	"event specifier disabled",			/* EMDB_SPECDIS */
	"unknown link map id",				/* EMDB_NOLMID */
	"failed to determine return address",		/* EMDB_NORETADDR */
	"watchpoint size exceeds address space limit",	/* EMDB_WPRANGE */
	"conflict with existing watchpoint",		/* EMDB_WPDUP */
	"address not aligned on an instruction boundary", /* EMDB_BPALIGN */
	"library is missing demangler entry point",	/* EMDB_NODEM */
	"cannot read past current end of file",		/* EMDB_EOF */
	"no symbolic debug information available for module", /* EMDB_NOCTF */
	"libctf call failed unexpectedly",		/* EMDB_CTF */
	"thread local storage has not yet been allocated", /* EMDB_TLS */
	"object does not support thread local storage",	/* EMDB_NOTLS */
	"no such member of structure or union",		/* EMDB_CTFNOMEMB */
	"inappropriate context for action",		/* EMDB_CTX */
	"module incompatible with target",		/* EMDB_INCOMPAT */
	"operation not supported by target on this platform",
							/* EMDB_TGTHWNOTSUP */
	"kmdb is not loaded",				/* EMDB_KINACTIVE */
	"kmdb is loading",				/* EMDB_KACTIVATING */
	"kmdb is already loaded",			/* EMDB_KACTIVE */
	"kmdb is unloading",				/* EMDB_KDEACTIVATING */
	"kmdb could not be loaded",			/* EMDB_KNOLOAD */
	"boot-loaded kmdb cannot be unloaded",		/* EMDB_KNOUNLOAD */
	"too many enabled watchpoints for this machine", /* EMDB_WPTOOMANY */
	"DTrace is active",				/* EMDB_DTACTIVE */
	"boot-loaded module cannot be unloaded",	/* EMDB_KMODNOUNLOAD */
	"stack frame pointer is invalid",		/* EMDB_STKFRAME */
	"unexpected short write"			/* EMDB_SHORTWRITE */

};

static const int _mdb_nerr = sizeof (_mdb_errlist) / sizeof (_mdb_errlist[0]);

static size_t errno_rbytes;	/* EMDB_PARTIAL actual bytes read */
static size_t errno_nbytes;	/* EMDB_PARTIAL total bytes requested */
static int errno_libctf;	/* EMDB_CTF underlying error code */
#ifndef _KMDB
static int errno_rtld_db;	/* EMDB_RTLD_DB underlying error code */
#endif

const char *
mdb_strerror(int err)
{
	static char buf[256];
	const char *str;

	if (err >= EMDB_BASE && (err - EMDB_BASE) < _mdb_nerr)
		str = _mdb_errlist[err - EMDB_BASE];
	else
		str = strerror(err);

	switch (err) {
	case EMDB_PARTIAL:
		(void) mdb_iob_snprintf(buf, sizeof (buf), str,
		    errno_rbytes, errno_nbytes);
		str = buf;
		break;

#ifndef _KMDB
	case EMDB_RTLD_DB:
		if (rd_errstr(errno_rtld_db) != NULL)
			str = rd_errstr(errno_rtld_db);
		break;
#endif

	case EMDB_CTF:
		if (ctf_errmsg(errno_libctf) != NULL)
			str = ctf_errmsg(errno_libctf);
		break;
	}

	return (str ? str : "unknown error");
}

void
vwarn(const char *format, va_list alist)
{
	int err = errno;

	mdb_iob_printf(mdb.m_err, "%s: ", mdb.m_pname);
	mdb_iob_vprintf(mdb.m_err, format, alist);

	if (strchr(format, '\n') == NULL)
		mdb_iob_printf(mdb.m_err, ": %s\n", mdb_strerror(err));
}

void
vdie(const char *format, va_list alist)
{
	vwarn(format, alist);
	mdb_destroy();
	exit(1);
}

void
vfail(const char *format, va_list alist)
{
	extern const char *volatile _mdb_abort_str;
	static char buf[256];
	static int nfail;

	if (_mdb_abort_str == NULL) {
		_mdb_abort_str = buf; /* Do this first so we don't recurse */
		(void) mdb_iob_vsnprintf(buf, sizeof (buf), format, alist);

		nfail = 1;
	}

	/*
	 * We'll try to print failure messages twice.  Any more than that,
	 * and we're probably hitting an assertion or some other problem in
	 * the printing routines, and will recurse until we run out of stack.
	 */
	if (nfail++ < 3) {
		mdb_iob_printf(mdb.m_err, "%s ABORT: ", mdb.m_pname);
		mdb_iob_vprintf(mdb.m_err, format, alist);
		mdb_iob_flush(mdb.m_err);

		(void) mdb_signal_blockall();
		(void) mdb_signal_raise(SIGABRT);
		(void) mdb_signal_unblock(SIGABRT);
	}

	exit(1);
}

/*PRINTFLIKE1*/
void
warn(const char *format, ...)
{
	va_list alist;

	va_start(alist, format);
	vwarn(format, alist);
	va_end(alist);
}

/*PRINTFLIKE1*/
void
die(const char *format, ...)
{
	va_list alist;

	va_start(alist, format);
	vdie(format, alist);
	va_end(alist);
}

/*PRINTFLIKE1*/
void
fail(const char *format, ...)
{
	va_list alist;

	va_start(alist, format);
	vfail(format, alist);
	va_end(alist);
}

int
set_errbytes(size_t rbytes, size_t nbytes)
{
	errno_rbytes = rbytes;
	errno_nbytes = nbytes;
	errno = EMDB_PARTIAL;
	return (-1);
}

int
set_errno(int err)
{
	errno = err;
	return (-1);
}

int
ctf_to_errno(int err)
{
	errno_libctf = err;
	return (EMDB_CTF);
}

#ifndef _KMDB
/*
 * The libthread_db interface is a superfund site and provides no strerror
 * equivalent for us to call: we try to provide some sensible handling for its
 * garbage bin of error return codes here.  First of all, we don't bother
 * interpreting all of the possibilities, since many of them aren't even used
 * in the implementation anymore.  We try to map thread_db errors we may see
 * to UNIX errnos or mdb errnos as appropriate.
 */
int
tdb_to_errno(int err)
{
	switch (err) {
	case TD_OK:
	case TD_PARTIALREG:
		return (0);
	case TD_NOCAPAB:
		return (ENOTSUP);
	case TD_BADPH:
	case TD_BADTH:
	case TD_BADSH:
	case TD_BADTA:
	case TD_BADKEY:
	case TD_NOEVENT:
		return (EINVAL);
	case TD_NOFPREGS:
	case TD_NOXREGS:
		return (EMDB_NOREGS);
	case TD_NOTHR:
		return (EMDB_NOTHREAD);
	case TD_MALLOC:
		return (EMDB_ALLOC);
	case TD_TLSDEFER:
		return (EMDB_TLS);
	case TD_NOTLS:
		return (EMDB_NOTLS);
	case TD_DBERR:
	case TD_ERR:
	default:
		return (EMDB_TDB);
	}
}

int
rdb_to_errno(int err)
{
	errno_rtld_db = err;
	return (EMDB_RTLD_DB);
}
#endif /* _KMDB */
