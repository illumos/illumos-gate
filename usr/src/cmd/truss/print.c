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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2015, Joyent, Inc. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/* Copyright (c) 2013, OmniTI Computer Consulting, Inc. All rights reserved. */

#define	_SYSCALL32	/* make 32-bit compat headers visible */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <termio.h>
#include <stddef.h>
#include <limits.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/ulimit.h>
#include <sys/utsname.h>
#include <sys/kstat.h>
#include <sys/modctl.h>
#include <sys/acl.h>
#include <stropts.h>
#include <sys/isa_defs.h>
#include <sys/systeminfo.h>
#include <sys/cladm.h>
#include <sys/lwp.h>
#include <bsm/audit.h>
#include <libproc.h>
#include <priv.h>
#include <sys/aio.h>
#include <sys/aiocb.h>
#include <sys/corectl.h>
#include <sys/cpc_impl.h>
#include <sys/priocntl.h>
#include <sys/tspriocntl.h>
#include <sys/iapriocntl.h>
#include <sys/rtpriocntl.h>
#include <sys/fsspriocntl.h>
#include <sys/fxpriocntl.h>
#include <netdb.h>
#include <nss_dbdefs.h>
#include <sys/socketvar.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/sctp.h>
#include <net/route.h>
#include <sys/utrap.h>
#include <sys/lgrp_user.h>
#include <sys/door.h>
#include <sys/tsol/tndb.h>
#include <sys/rctl.h>
#include <sys/rctl_impl.h>
#include <sys/fork.h>
#include <sys/task.h>
#include <sys/random.h>
#include "ramdata.h"
#include "print.h"
#include "proto.h"
#include "systable.h"

void grow(private_t *, int nbyte);

#define	GROW(nb) if (pri->sys_leng + (nb) >= pri->sys_ssize) grow(pri, (nb))


/*ARGSUSED*/
void
prt_nov(private_t *pri, int raw, long val)	/* print nothing */
{
}

/*ARGSUSED*/
void
prt_dec(private_t *pri, int raw, long val)	/* print as decimal */
{
	GROW(24);
	if (data_model == PR_MODEL_ILP32)
		pri->sys_leng += sprintf(pri->sys_string + pri->sys_leng,
		    "%d", (int)val);
	else
		pri->sys_leng += sprintf(pri->sys_string + pri->sys_leng,
		    "%ld", val);
}

/*ARGSUSED*/
void
prt_uns(private_t *pri, int raw, long val)	/* print as unsigned decimal */
{
	GROW(24);
	if (data_model == PR_MODEL_ILP32)
		pri->sys_leng += sprintf(pri->sys_string + pri->sys_leng,
		    "%u", (int)val);
	else
		pri->sys_leng += sprintf(pri->sys_string + pri->sys_leng,
		    "%lu", val);
}

/* print as unsigned decimal, except for -1 */
void
prt_un1(private_t *pri, int raw, long val)
{
	if ((int)val == -1)
		prt_dec(pri, raw, val);
	else
		prt_uns(pri, raw, val);
}

/*ARGSUSED*/
void
prt_oct(private_t *pri, int raw, long val)	/* print as octal */
{
	GROW(24);
	if (data_model == PR_MODEL_ILP32)
		pri->sys_leng += sprintf(pri->sys_string + pri->sys_leng,
		    "%#o", (int)val);
	else
		pri->sys_leng += sprintf(pri->sys_string + pri->sys_leng,
		    "%#lo", val);
}

/*ARGSUSED*/
void
prt_hex(private_t *pri, int raw, long val)	/* print as hexadecimal */
{
	GROW(20);
	if (data_model == PR_MODEL_ILP32)
		pri->sys_leng += sprintf(pri->sys_string + pri->sys_leng,
		    "0x%.8X", (int)val);
	else
		pri->sys_leng += sprintf(pri->sys_string + pri->sys_leng,
		    "0x%.8lX", val);
}

/* print as hexadecimal (half size) */
/*ARGSUSED*/
void
prt_hhx(private_t *pri, int raw, long val)
{
	GROW(20);
	if (data_model == PR_MODEL_ILP32)
		pri->sys_leng += sprintf(pri->sys_string + pri->sys_leng,
		    "0x%.4X", (int)val);
	else
		pri->sys_leng += sprintf(pri->sys_string + pri->sys_leng,
		    "0x%.4lX", val);
}

/* print as decimal if small, else hexadecimal */
/*ARGSUSED*/
void
prt_dex(private_t *pri, int raw, long val)
{
	if (val & 0xff000000)
		prt_hex(pri, 0, val);
	else
		prt_dec(pri, 0, val);
}

/* print long long offset */
/*ARGSUSED*/
void
prt_llo(private_t *pri, int raw, long val1, long val2)
{
	int hival;
	int loval;

#ifdef	_LONG_LONG_LTOH
	hival = (int)val2;
	loval = (int)val1;
#else
	hival = (int)val1;
	loval = (int)val2;
#endif

	if (hival == 0) {
		prt_dex(pri, 0, loval);
	} else {
		GROW(18);
		pri->sys_leng +=
		    sprintf(pri->sys_string + pri->sys_leng, "0x%.8X%.8X",
		    hival, loval);
	}
}

void
escape_string(private_t *pri, const char *s)
{
	/*
	 * We want to avoid outputting unprintable characters that may
	 * destroy the user's terminal.  So we do one pass to find any
	 * unprintable characters, size the array appropriately, and
	 * then walk each character by hand.  Those that are unprintable
	 * are replaced by a hex escape (\xNN).  We also escape quotes for
	 * completeness.
	 */
	int i, unprintable, quotes;
	size_t len = strlen(s);
	for (i = 0, unprintable = 0, quotes = 0; i < len; i++) {
		if (!isprint(s[i]))
			unprintable++;
		if (s[i] == '"')
			quotes++;
	}

	GROW(len + 3 * unprintable + quotes + 2);

	pri->sys_string[pri->sys_leng++] = '"';
	for (i = 0; i < len; i++) {
		if (s[i] == '"')
			pri->sys_string[pri->sys_leng++] = '\\';

		if (isprint(s[i])) {
			pri->sys_string[pri->sys_leng++] = s[i];
		} else {
			pri->sys_leng += sprintf(pri->sys_string +
			    pri->sys_leng, "\\x%02x", (uint8_t)s[i]);
		}
	}
	pri->sys_string[pri->sys_leng++] = '"';
}

void
prt_stg(private_t *pri, int raw, long val)	/* print as string */
{
	char *s = raw? NULL : fetchstring(pri, (long)val, PATH_MAX);

	if (s == NULL)
		prt_hex(pri, 0, val);
	else
		escape_string(pri, s);
}

/* print as string returned from syscall */
void
prt_rst(private_t *pri, int raw, long val)
{
	char *s = (raw || pri->Errno)? NULL :
	    fetchstring(pri, (long)val, PATH_MAX);

	if (s == NULL)
		prt_hex(pri, 0, val);
	else {
		GROW((int)strlen(s) + 2);
		pri->sys_leng += snprintf(pri->sys_string + pri->sys_leng,
		    pri->sys_ssize - pri->sys_leng, "\"%s\"", s);
	}
}

/* print contents of readlink() buffer */
void
prt_rlk(private_t *pri, int raw, long val)
{
	char *s = (raw || pri->Errno || pri->Rval1 <= 0)? NULL :
	    fetchstring(pri, (long)val,
	    (pri->Rval1 > PATH_MAX)? PATH_MAX : (int)pri->Rval1);

	if (s == NULL)
		prt_hex(pri, 0, val);
	else {
		GROW((int)strlen(s) + 2);
		pri->sys_leng += snprintf(pri->sys_string + pri->sys_leng,
		    pri->sys_ssize - pri->sys_leng, "\"%s\"", s);
	}
}

void
prt_ioc(private_t *pri, int raw, long val)	/* print ioctl code */
{
	const char *s = raw? NULL : ioctlname(pri, (int)val);

	if (s == NULL)
		prt_hex(pri, 0, val);
	else
		outstring(pri, s);
}

void
prt_ioa(private_t *pri, int raw, long val)	/* print ioctl argument */
{
	const char *s;

	/* cheating -- look at the ioctl() code */
	switch (pri->sys_args[1]) {

	/* kstat ioctl()s */
	case KSTAT_IOC_READ:
	case KSTAT_IOC_WRITE:
#ifdef _LP64
		if (data_model == PR_MODEL_ILP32)
			prt_stg(pri, raw,
			    val + offsetof(kstat32_t, ks_name[0]));
		else
#endif
			prt_stg(pri, raw,
			    val + offsetof(kstat_t, ks_name[0]));
		break;

	/* streams ioctl()s */
	case I_LOOK:
		prt_rst(pri, raw, val);
		break;
	case I_PUSH:
	case I_FIND:
		prt_stg(pri, raw, val);
		break;
	case I_LINK:
	case I_UNLINK:
	case I_SENDFD:
		prt_dec(pri, 0, val);
		break;
	case I_SRDOPT:
		if (raw || (s = strrdopt(val)) == NULL)
			prt_dec(pri, 0, val);
		else
			outstring(pri, s);
		break;
	case I_SETSIG:
		if (raw || (s = strevents(pri, val)) == NULL)
			prt_hex(pri, 0, val);
		else
			outstring(pri, s);
		break;
	case I_FLUSH:
		if (raw || (s = strflush(val)) == NULL)
			prt_dec(pri, 0, val);
		else
			outstring(pri, s);
		break;

	/* tty ioctl()s */
	case TCSBRK:
	case TCXONC:
	case TCFLSH:
	case TCDSET:
		prt_dec(pri, 0, val);
		break;

	default:
		prt_hex(pri, 0, val);
		break;
	}
}

void
prt_pip(private_t *pri, int raw, long val)	/* print pipe code */
{
	const char *s = NULL;

	if (!raw) {
		switch (val) {
		case O_CLOEXEC:
			s = "O_CLOEXEC";
			break;
		case O_NONBLOCK:
			s = "O_NONBLOCK";
			break;
		case O_CLOEXEC|O_NONBLOCK:
			s = "O_CLOEXEC|O_NONBLOCK";
			break;
		}
	}

	if (s == NULL)
		prt_dex(pri, 0, val);
	else
		outstring(pri, s);
}

void
prt_pfd(private_t *pri, int raw, long val)	/* print pipe code */
{
	int fds[2];
	char str[32];

	/* the fds only have meaning if the return value is 0 */
	if (!raw &&
	    pri->Rval1 >= 0 &&
	    Pread(Proc, fds, sizeof (fds), (long)val) == sizeof (fds)) {
		(void) snprintf(str, sizeof (str), "[%d,%d]", fds[0], fds[1]);
		outstring(pri, str);
	} else {
		prt_hex(pri, 0, val);
	}
}

void
prt_fcn(private_t *pri, int raw, long val)	/* print fcntl code */
{
	const char *s = raw? NULL : fcntlname(val);

	if (s == NULL)
		prt_dec(pri, 0, val);
	else
		outstring(pri, s);
}

void
prt_s86(private_t *pri, int raw, long val)	/* print sysi86 code */
{

	const char *s = raw? NULL : si86name(val);

	if (s == NULL)
		prt_dec(pri, 0, val);
	else
		outstring(pri, s);
}

void
prt_uts(private_t *pri, int raw, long val)	/* print utssys code */
{
	const char *s = raw? NULL : utscode(val);

	if (s == NULL)
		prt_dec(pri, 0, val);
	else
		outstring(pri, s);
}

void
prt_msc(private_t *pri, int raw, long val)	/* print msgsys command */
{
	const char *s = raw? NULL : msgcmd(val);

	if (s == NULL)
		prt_dec(pri, 0, val);
	else
		outstring(pri, s);
}

void
prt_msf(private_t *pri, int raw, long val)	/* print msgsys flags */
{
	const char *s = raw? NULL : msgflags(pri, (int)val);

	if (s == NULL)
		prt_oct(pri, 0, val);
	else
		outstring(pri, s);
}

void
prt_smc(private_t *pri, int raw, long val)	/* print semsys command */
{
	const char *s = raw? NULL : semcmd(val);

	if (s == NULL)
		prt_dec(pri, 0, val);
	else
		outstring(pri, s);
}

void
prt_sef(private_t *pri, int raw, long val)	/* print semsys flags */
{
	const char *s = raw? NULL : semflags(pri, (int)val);

	if (s == NULL)
		prt_oct(pri, 0, val);
	else
		outstring(pri, s);
}

void
prt_shc(private_t *pri, int raw, long val)	/* print shmsys command */
{
	const char *s = raw? NULL : shmcmd(val);

	if (s == NULL)
		prt_dec(pri, 0, val);
	else
		outstring(pri, s);
}

void
prt_shf(private_t *pri, int raw, long val)	/* print shmsys flags */
{
	const char *s = raw? NULL : shmflags(pri, (int)val);

	if (s == NULL)
		prt_oct(pri, 0, val);
	else
		outstring(pri, s);
}

void
prt_sfs(private_t *pri, int raw, long val)	/* print sysfs code */
{
	const char *s = raw? NULL : sfsname(val);

	if (s == NULL)
		prt_dec(pri, 0, val);
	else
		outstring(pri, s);
}

void
prt_opn(private_t *pri, int raw, long val)	/* print open code */
{
	const char *s = raw? NULL : openarg(pri, val);

	if (s == NULL)
		prt_oct(pri, 0, val);
	else
		outstring(pri, s);
}

void
prt_sig(private_t *pri, int raw, long val)	/* print signal name */
{
	const char *s = raw? NULL : signame(pri, (int)val);

	if (s == NULL)
		prt_hex(pri, 0, val);
	else
		outstring(pri, s);
}

void
prt_smf(private_t *pri, int raw, long val) /* print streams message flags */
{
	switch (val) {
	case 0:
		prt_dec(pri, 0, val);
		break;
	case RS_HIPRI:
		if (raw)
			prt_hhx(pri, 0, val);
		else
			outstring(pri, "RS_HIPRI");
		break;
	default:
		prt_hhx(pri, 0, val);
		break;
	}
}

void
prt_mtf(private_t *pri, int raw, long val)	/* print mount flags */
{
	const char *s = raw? NULL : mountflags(pri, val);

	if (s == NULL)
		prt_hex(pri, 0, val);
	else
		outstring(pri, s);
}

void
prt_mft(private_t *pri, int raw, long val) /* print mount file system type */
{
	if (val >= 0 && val < 256)
		prt_dec(pri, 0, val);
	else if (raw)
		prt_hex(pri, 0, val);
	else
		prt_stg(pri, raw, val);
}

#define	ISREAD(code) \
	((code) == SYS_read || (code) == SYS_pread || (code) == SYS_pread64 || \
	(code) == SYS_recv || (code) == SYS_recvfrom)
#define	ISWRITE(code) \
	((code) == SYS_write || (code) == SYS_pwrite || \
	(code) == SYS_pwrite64 || (code) == SYS_send || (code) == SYS_sendto)

/* print contents of read() or write() I/O buffer */
void
prt_iob(private_t *pri, int raw, long val)
{
	const lwpstatus_t *Lsp = pri->lwpstat;
	int syscall = Lsp->pr_what;
	int fdp1 = pri->sys_args[0] + 1;
	ssize_t nbyte = ISWRITE(syscall)? pri->sys_args[2] :
	    (pri->Errno? 0 : pri->Rval1);
	int elsewhere = FALSE;		/* TRUE iff dumped elsewhere */
	char buffer[IOBSIZE];

	pri->iob_buf[0] = '\0';

	if (Lsp->pr_why == PR_SYSEXIT && nbyte > IOBSIZE) {
		if (ISREAD(syscall))
			elsewhere = prismember(&readfd, fdp1);
		else
			elsewhere = prismember(&writefd, fdp1);
	}

	if (nbyte <= 0 || elsewhere)
		prt_hex(pri, 0, val);
	else {
		int nb = nbyte > IOBSIZE? IOBSIZE : (int)nbyte;

		if (Pread(Proc, buffer, (size_t)nb, (long)val) != nb)
			prt_hex(pri, 0, val);
		else {
			pri->iob_buf[0] = '"';
			showbytes(buffer, nb, pri->iob_buf + 1);
			(void) strlcat(pri->iob_buf,
			    (nb == nbyte)?
			    (const char *)"\"" : (const char *)"\"..",
			    sizeof (pri->iob_buf));
			if (raw)
				prt_hex(pri, 0, val);
			else
				outstring(pri, pri->iob_buf);
		}
	}
}
#undef	ISREAD
#undef	ISWRITE

void
prt_idt(private_t *pri, int raw, long val) /* print idtype_t, waitid() arg */
{
	const char *s = raw? NULL : idtype_enum(pri, val);

	if (s == NULL)
		prt_dec(pri, 0, val);
	else
		outstring(pri, s);
}

void
prt_wop(private_t *pri, int raw, long val)	/* print waitid() options */
{
	const char *s = raw? NULL : woptions(pri, (int)val);

	if (s == NULL)
		prt_oct(pri, 0, val);
	else
		outstring(pri, s);
}

void
prt_whn(private_t *pri, int raw, long val) /* print lseek() whence argument */
{
	const char *s = raw? NULL : whencearg(val);

	if (s == NULL)
		prt_dec(pri, 0, val);
	else
		outstring(pri, s);
}

/*ARGSUSED*/
void
prt_spm(private_t *pri, int raw, long val)	/* print sigprocmask argument */
{
	const char *s = NULL;

	if (!raw) {
		switch (val) {
		case SIG_BLOCK:		s = "SIG_BLOCK";	break;
		case SIG_UNBLOCK:	s = "SIG_UNBLOCK";	break;
		case SIG_SETMASK:	s = "SIG_SETMASK";	break;
		}
	}

	if (s == NULL)
		prt_dec(pri, 0, val);
	else
		outstring(pri, s);
}

const char *
mmap_protect(private_t *pri, long arg)
{
	char *str = pri->code_buf;

	if (arg & ~(PROT_READ|PROT_WRITE|PROT_EXEC))
		return ((char *)NULL);

	if (arg == PROT_NONE)
		return ("PROT_NONE");

	*str = '\0';
	if (arg & PROT_READ)
		(void) strlcat(str, "|PROT_READ", sizeof (pri->code_buf));
	if (arg & PROT_WRITE)
		(void) strlcat(str, "|PROT_WRITE", sizeof (pri->code_buf));
	if (arg & PROT_EXEC)
		(void) strlcat(str, "|PROT_EXEC", sizeof (pri->code_buf));
	return ((const char *)(str + 1));
}

const char *
mmap_type(private_t *pri, long arg)
{
	char *str = pri->code_buf;
	size_t used;

#define	CBSIZE	sizeof (pri->code_buf)
	switch (arg & MAP_TYPE) {
	case MAP_SHARED:
		used = strlcpy(str, "MAP_SHARED", CBSIZE);
		break;
	case MAP_PRIVATE:
		used = strlcpy(str, "MAP_PRIVATE", CBSIZE);
		break;
	default:
		used = snprintf(str, CBSIZE, "%ld", arg&MAP_TYPE);
		break;
	}

	arg &= ~(_MAP_NEW|MAP_TYPE);

	if (arg & ~(MAP_FIXED|MAP_RENAME|MAP_NORESERVE|MAP_ANON|MAP_ALIGN|
	    MAP_TEXT|MAP_INITDATA|MAP_32BIT))
		(void) snprintf(str + used, sizeof (pri->code_buf) - used,
		    "|0x%lX", arg);
	else {
		if (arg & MAP_FIXED)
			(void) strlcat(str, "|MAP_FIXED", CBSIZE);
		if (arg & MAP_RENAME)
			(void) strlcat(str, "|MAP_RENAME", CBSIZE);
		if (arg & MAP_NORESERVE)
			(void) strlcat(str, "|MAP_NORESERVE", CBSIZE);
		if (arg & MAP_ANON)
			(void) strlcat(str, "|MAP_ANON", CBSIZE);
		if (arg & MAP_ALIGN)
			(void) strlcat(str, "|MAP_ALIGN", CBSIZE);
		if (arg & MAP_TEXT)
			(void) strlcat(str, "|MAP_TEXT", CBSIZE);
		if (arg & MAP_INITDATA)
			(void) strlcat(str, "|MAP_INITDATA", CBSIZE);
		if (arg & MAP_32BIT)
			(void) strlcat(str, "|MAP_32BIT", CBSIZE);
	}

	return ((const char *)str);
#undef CBSIZE
}

void
prt_mpr(private_t *pri, int raw, long val) /* print mmap()/mprotect() flags */
{
	const char *s = raw? NULL : mmap_protect(pri, val);

	if (s == NULL)
		prt_hhx(pri, 0, val);
	else
		outstring(pri, s);
}

void
prt_mty(private_t *pri, int raw, long val) /* print mmap() mapping type flags */
{
	const char *s = raw? NULL : mmap_type(pri, val);

	if (s == NULL)
		prt_hhx(pri, 0, val);
	else
		outstring(pri, s);
}

void
prt_mob(private_t *pri, int raw, long val) /* print mmapobj() flags */
{
	if (val == 0)
		prt_dec(pri, 0, val);
	else if (raw || (val & ~(MMOBJ_PADDING|MMOBJ_INTERPRET)) != 0)
		prt_hhx(pri, 0, val);
	else {
#define	CBSIZE	sizeof (pri->code_buf)
		char *s = pri->code_buf;

		*s = '\0';
		if (val & MMOBJ_PADDING)
			(void) strlcat(s, "|MMOBJ_PADDING", CBSIZE);
		if (val & MMOBJ_INTERPRET)
			(void) strlcat(s, "|MMOBJ_INTERPRET", CBSIZE);
		outstring(pri, s + 1);
#undef CBSIZE
	}
}

/*ARGSUSED*/
void
prt_mcf(private_t *pri, int raw, long val)	/* print memcntl() function */
{
	const char *s = NULL;

	if (!raw) {
		switch (val) {
		case MC_SYNC:		s = "MC_SYNC";		break;
		case MC_LOCK:		s = "MC_LOCK";		break;
		case MC_UNLOCK:		s = "MC_UNLOCK";	break;
		case MC_ADVISE:		s = "MC_ADVISE";	break;
		case MC_LOCKAS:		s = "MC_LOCKAS";	break;
		case MC_UNLOCKAS:	s = "MC_UNLOCKAS";	break;
		case MC_HAT_ADVISE:	s = "MC_HAT_ADVISE";	break;
		}
	}

	if (s == NULL)
		prt_dec(pri, 0, val);
	else
		outstring(pri, s);
}

void
prt_mad(private_t *pri, int raw, long val)	/* print madvise() argument */
{
	const char *s = NULL;

	if (!raw) {
		switch (val) {
		case MADV_NORMAL:	s = "MADV_NORMAL";	break;
		case MADV_RANDOM:	s = "MADV_RANDOM";	break;
		case MADV_SEQUENTIAL:	s = "MADV_SEQUENTIAL";	break;
		case MADV_WILLNEED:	s = "MADV_WILLNEED";	break;
		case MADV_DONTNEED:	s = "MADV_DONTNEED";	break;
		case MADV_FREE:		s = "MADV_FREE";	break;
		case MADV_ACCESS_DEFAULT: s = "MADV_ACCESS_DEFAULT";	break;
		case MADV_ACCESS_LWP:	s = "MADV_ACCESS_LWP";	break;
		case MADV_ACCESS_MANY:	s = "MADV_ACCESS_MANY";	break;
		}
	}

	if (s == NULL)
		prt_dec(pri, 0, val);
	else
		outstring(pri, s);
}

void
prt_mc4(private_t *pri, int raw, long val) /* print memcntl() (4th) argument */
{
	if (val == 0)
		prt_dec(pri, 0, val);
	else if (raw)
		prt_hhx(pri, 0, val);
	else {
		char *s = NULL;

#define	CBSIZE	sizeof (pri->code_buf)
		/* cheating -- look at memcntl func */
		switch (pri->sys_args[2]) {
		case MC_ADVISE:
			prt_mad(pri, 0, val);
			return;

		case MC_SYNC:
			if ((val & ~(MS_SYNC|MS_ASYNC|MS_INVALIDATE)) == 0) {
				*(s = pri->code_buf) = '\0';
				if (val & MS_SYNC)
					(void) strlcat(s, "|MS_SYNC", CBSIZE);
				if (val & MS_ASYNC)
					(void) strlcat(s, "|MS_ASYNC", CBSIZE);
				if (val & MS_INVALIDATE)
					(void) strlcat(s, "|MS_INVALIDATE",
					    CBSIZE);
			}
			break;

		case MC_LOCKAS:
		case MC_UNLOCKAS:
			if ((val & ~(MCL_CURRENT|MCL_FUTURE)) == 0) {
				*(s = pri->code_buf) = '\0';
				if (val & MCL_CURRENT)
					(void) strlcat(s, "|MCL_CURRENT",
					    CBSIZE);
				if (val & MCL_FUTURE)
					(void) strlcat(s, "|MCL_FUTURE",
					    CBSIZE);
			}
			break;
		}
#undef CBSIZE

		if (s == NULL || *s == '\0')
			prt_hhx(pri, 0, val);
		else
			outstring(pri, ++s);
	}
}

void
prt_mc5(private_t *pri, int raw, long val) /* print memcntl() (5th) argument */
{
	char *s;

#define	CBSIZE	sizeof (pri->code_buf)
	if (val == 0)
		prt_dec(pri, 0, val);
	else if (raw || (val & ~VALID_ATTR))
		prt_hhx(pri, 0, val);
	else {
		s = pri->code_buf;
		*s = '\0';
		if (val & SHARED)
			(void) strlcat(s, "|SHARED", CBSIZE);
		if (val & PRIVATE)
			(void) strlcat(s, "|PRIVATE", CBSIZE);
		if (val & PROT_READ)
			(void) strlcat(s, "|PROT_READ", CBSIZE);
		if (val & PROT_WRITE)
			(void) strlcat(s, "|PROT_WRITE", CBSIZE);
		if (val & PROT_EXEC)
			(void) strlcat(s, "|PROT_EXEC", CBSIZE);
		if (*s == '\0')
			prt_hhx(pri, 0, val);
		else
			outstring(pri, ++s);
	}
#undef CBSIZE
}

void
prt_ulm(private_t *pri, int raw, long val)	/* print ulimit() argument */
{
	const char *s = NULL;

	if (!raw) {
		switch (val) {
		case UL_GFILLIM:	s = "UL_GFILLIM";	break;
		case UL_SFILLIM:	s = "UL_SFILLIM";	break;
		case UL_GMEMLIM:	s = "UL_GMEMLIM";	break;
		case UL_GDESLIM:	s = "UL_GDESLIM";	break;
		}
	}

	if (s == NULL)
		prt_dec(pri, 0, val);
	else
		outstring(pri, s);
}

void
prt_rlm(private_t *pri, int raw, long val) /* print get/setrlimit() argument */
{
	const char *s = NULL;

	if (!raw) {
		switch (val) {
		case RLIMIT_CPU:	s = "RLIMIT_CPU";	break;
		case RLIMIT_FSIZE:	s = "RLIMIT_FSIZE";	break;
		case RLIMIT_DATA:	s = "RLIMIT_DATA";	break;
		case RLIMIT_STACK:	s = "RLIMIT_STACK";	break;
		case RLIMIT_CORE:	s = "RLIMIT_CORE";	break;
		case RLIMIT_NOFILE:	s = "RLIMIT_NOFILE";	break;
		case RLIMIT_VMEM:	s = "RLIMIT_VMEM";	break;
		}
	}

	if (s == NULL)
		prt_dec(pri, 0, val);
	else
		outstring(pri, s);
}

void
prt_cnf(private_t *pri, int raw, long val)	/* print sysconfig code */
{
	const char *s = raw? NULL : sconfname(val);

	if (s == NULL)
		prt_dec(pri, 0, val);
	else
		outstring(pri, s);
}

void
prt_inf(private_t *pri, int raw, long val)	/* print sysinfo code */
{
	const char *s = NULL;

	if (!raw) {
		switch (val) {
		case SI_SYSNAME:	s = "SI_SYSNAME";	break;
		case SI_HOSTNAME:	s = "SI_HOSTNAME";	break;
		case SI_RELEASE:	s = "SI_RELEASE";	break;
		case SI_VERSION:	s = "SI_VERSION";	break;
		case SI_MACHINE:	s = "SI_MACHINE";	break;
		case SI_ARCHITECTURE:	s = "SI_ARCHITECTURE";	break;
		case SI_ARCHITECTURE_32:s = "SI_ARCHITECTURE_32"; break;
		case SI_ARCHITECTURE_64:s = "SI_ARCHITECTURE_64"; break;
		case SI_ARCHITECTURE_K:	s = "SI_ARCHITECTURE_K"; break;
		case SI_HW_SERIAL:	s = "SI_HW_SERIAL";	break;
		case SI_HW_PROVIDER:	s = "SI_HW_PROVIDER";	break;
		case SI_SRPC_DOMAIN:	s = "SI_SRPC_DOMAIN";	break;
		case SI_SET_HOSTNAME:	s = "SI_SET_HOSTNAME";	break;
		case SI_SET_SRPC_DOMAIN: s = "SI_SET_SRPC_DOMAIN"; break;
		case SI_PLATFORM:	s = "SI_PLATFORM";	break;
		case SI_ISALIST:	s = "SI_ISALIST";	break;
		case SI_DHCP_CACHE:	s = "SI_DHCP_CACHE";	break;
		}
	}

	if (s == NULL)
		prt_dec(pri, 0, val);
	else
		outstring(pri, s);
}

void
prt_ptc(private_t *pri, int raw, long val)	/* print pathconf code */
{
	const char *s = raw? NULL : pathconfname(val);

	if (s == NULL)
		prt_dec(pri, 0, val);
	else
		outstring(pri, s);
}

void
prt_fui(private_t *pri, int raw, long val) /* print fusers() input argument */
{
	const char *s = raw? NULL : fuiname(val);

	if (s == NULL)
		prt_hhx(pri, 0, val);
	else
		outstring(pri, s);
}

void
prt_lwf(private_t *pri, int raw, long val)	/* print lwp_create() flags */
{
	char *s;

	if (val == 0)
		prt_dec(pri, 0, val);
	else if (raw ||
	    (val & ~(LWP_DAEMON|LWP_DETACHED|LWP_SUSPENDED)))
		prt_hhx(pri, 0, val);
	else {
#define	CBSIZE	sizeof (pri->code_buf)
		s = pri->code_buf;
		*s = '\0';
		if (val & LWP_DAEMON)
			(void) strlcat(s, "|LWP_DAEMON", CBSIZE);
		if (val & LWP_DETACHED)
			(void) strlcat(s, "|LWP_DETACHED", CBSIZE);
		if (val & LWP_SUSPENDED)
			(void) strlcat(s, "|LWP_SUSPENDED", CBSIZE);
		outstring(pri, ++s);
#undef CBSIZE
	}
}

void
prt_itm(private_t *pri, int raw, long val) /* print [get|set]itimer() arg */
{
	const char *s = NULL;

	if (!raw) {
		switch (val) {
		case ITIMER_REAL:	s = "ITIMER_REAL";	break;
		case ITIMER_VIRTUAL:	s = "ITIMER_VIRTUAL";	break;
		case ITIMER_PROF:	s = "ITIMER_PROF";	break;
#ifdef ITIMER_REALPROF
		case ITIMER_REALPROF:	s = "ITIMER_REALPROF";	break;
#endif
		}
	}

	if (s == NULL)
		prt_dec(pri, 0, val);
	else
		outstring(pri, s);
}

void
prt_mod(private_t *pri, int raw, long val)	/* print modctl() code */
{
	const char *s = NULL;

	if (!raw) {
		switch (val) {
		case MODLOAD:		s = "MODLOAD";		break;
		case MODUNLOAD:		s = "MODUNLOAD";	break;
		case MODINFO:		s = "MODINFO";		break;
		case MODRESERVED:	s = "MODRESERVED";	break;
		case MODSETMINIROOT:	s = "MODSETMINIROOT";	break;
		case MODADDMAJBIND:	s = "MODADDMAJBIND";	break;
		case MODGETPATH:	s = "MODGETPATH";	break;
		case MODGETPATHLEN:	s = "MODGETPATHLEN";	break;
		case MODREADSYSBIND:	s = "MODREADSYSBIND";	break;
		case MODGETMAJBIND:	s = "MODGETMAJBIND";	break;
		case MODGETNAME:	s = "MODGETNAME";	break;
		case MODSIZEOF_DEVID:	s = "MODSIZEOF_DEVID";	break;
		case MODGETDEVID:	s = "MODGETDEVID";	break;
		case MODSIZEOF_MINORNAME: s = "MODSIZEOF_MINORNAME"; break;
		case MODGETMINORNAME:	s = "MODGETMINORNAME";	break;
		case MODGETFBNAME:	s = "MODGETFBNAME";	break;
		case MODEVENTS:		s = "MODEVENTS";	break;
		case MODREREADDACF:	s = "MODREREADDACF";	break;
		case MODLOADDRVCONF:	s = "MODLOADDRVCONF";	break;
		case MODUNLOADDRVCONF:	s = "MODUNLOADDRVCONF";	break;
		case MODREMMAJBIND:	s = "MODREMMAJBIND";	break;
		case MODDEVT2INSTANCE:	s = "MODDEVT2INSTANCE";	break;
		case MODGETDEVFSPATH_LEN: s = "MODGETDEVFSPATH_LEN"; break;
		case MODGETDEVFSPATH:	s = "MODGETDEVFSPATH";	break;
		case MODDEVID2PATHS:	s = "MODDEVID2PATHS";	break;
		case MODSETDEVPOLICY:	s = "MODSETDEVPOLICY";	break;
		case MODGETDEVPOLICY:	s = "MODGETDEVPOLICY";	break;
		case MODALLOCPRIV:	s = "MODALLOCPRIV";	break;
		case MODGETDEVPOLICYBYNAME:
					s = "MODGETDEVPOLICYBYNAME"; break;
		case MODLOADMINORPERM:	s = "MODLOADMINORPERM"; break;
		case MODADDMINORPERM:	s = "MODADDMINORPERM"; break;
		case MODREMMINORPERM:	s = "MODREMMINORPERM"; break;
		case MODREMDRVCLEANUP:	s = "MODREMDRVCLEANUP"; break;
		case MODDEVEXISTS:	s = "MODDEVEXISTS"; break;
		case MODDEVREADDIR:	s = "MODDEVREADDIR"; break;
		case MODDEVEMPTYDIR:	s = "MODDEVEMPTYDIR"; break;
		case MODDEVNAME:	s = "MODDEVNAME"; break;
		case MODGETDEVFSPATH_MI_LEN:
					s = "MODGETDEVFSPATH_MI_LEN"; break;
		case MODGETDEVFSPATH_MI:
					s = "MODGETDEVFSPATH_MI"; break;
		case MODREMDRVALIAS:	s = "MODREMDRVALIAS"; break;
		case MODHPOPS:	s = "MODHPOPS"; break;
		}
	}

	if (s == NULL)
		prt_dec(pri, 0, val);
	else
		outstring(pri, s);
}

void
prt_acl(private_t *pri, int raw, long val)	/* print acl() code */
{
	const char *s = NULL;

	if (!raw) {
		switch (val) {
		case GETACL:		s = "GETACL";		break;
		case SETACL:		s = "SETACL";		break;
		case GETACLCNT:		s = "GETACLCNT";	break;
		case ACE_GETACL:	s = "ACE_GETACL";	break;
		case ACE_SETACL:	s = "ACE_SETACL";	break;
		case ACE_GETACLCNT:	s = "ACE_GETACLCNT";	break;
		}
	}

	if (s == NULL)
		prt_dec(pri, 0, val);
	else
		outstring(pri, s);
}

void
prt_aio(private_t *pri, int raw, long val)	/* print kaio() code */
{
	const char *s = NULL;
	char buf[32];

	if (!raw) {
		switch (val & ~AIO_POLL_BIT) {
		case AIOREAD:		s = "AIOREAD";		break;
		case AIOWRITE:		s = "AIOWRITE";		break;
		case AIOWAIT:		s = "AIOWAIT";		break;
		case AIOCANCEL:		s = "AIOCANCEL";	break;
		case AIONOTIFY:		s = "AIONOTIFY";	break;
		case AIOINIT:		s = "AIOINIT";		break;
		case AIOSTART:		s = "AIOSTART";		break;
		case AIOLIO:		s = "AIOLIO";		break;
		case AIOSUSPEND:	s = "AIOSUSPEND";	break;
		case AIOERROR:		s = "AIOERROR";		break;
		case AIOLIOWAIT:	s = "AIOLIOWAIT";	break;
		case AIOAREAD:		s = "AIOAREAD";		break;
		case AIOAWRITE:		s = "AIOAWRITE";	break;
		/*
		 * We have to hardcode the values for the 64-bit versions of
		 * these calls, because <sys/aio.h> defines them to be identical
		 * when compiled 64-bit.  If our target is 32-bit, we still need
		 * to decode them correctly.
		 */
		case 13:		s = "AIOLIO64";		break;
		case 14:		s = "AIOSUSPEND64";	break;
		case 15:		s = "AUIOERROR64";	break;
		case 16:		s = "AIOLIOWAIT64";	break;
		case 17:		s = "AIOAREAD64";	break;
		case 18:		s = "AIOAWRITE64";	break;
		case 19:		s = "AIOCANCEL64";	break;

		/*
		 * AIOFSYNC doesn't correspond to a syscall.
		 */
		case AIOWAITN:		s = "AIOWAITN";		break;
		}
		if (s != NULL && (val & AIO_POLL_BIT)) {
			(void) strlcpy(buf, s, sizeof (buf));
			(void) strlcat(buf, "|AIO_POLL_BIT", sizeof (buf));
			s = (const char *)buf;
		}
	}

	if (s == NULL)
		prt_dec(pri, 0, val);
	else
		outstring(pri, s);
}

void
prt_aud(private_t *pri, int raw, long val)	/* print auditsys() code */
{
	const char *s = NULL;

	if (!raw) {
		switch (val) {
		case BSM_GETAUID:	s = "BSM_GETAUID";	break;
		case BSM_SETAUID:	s = "BSM_SETAUID";	break;
		case BSM_GETAUDIT:	s = "BSM_GETAUDIT";	break;
		case BSM_SETAUDIT:	s = "BSM_SETAUDIT";	break;
		case BSM_AUDIT:		s = "BSM_AUDIT";	break;
		case BSM_AUDITCTL:	s = "BSM_AUDITCTL";	break;
		case BSM_GETAUDIT_ADDR:	s = "BSM_GETAUDIT_ADDR"; break;
		case BSM_SETAUDIT_ADDR:	s = "BSM_SETAUDIT_ADDR"; break;
		}
	}

	if (s == NULL)
		prt_dec(pri, 0, val);
	else
		outstring(pri, s);
}

void
prt_cor(private_t *pri, int raw, long val)	/* print corectl() subcode */
{
	const char *s = NULL;

	if (!raw) {
		switch (val) {
		case CC_SET_OPTIONS:
			s = "CC_SET_OPTIONS";		break;
		case CC_GET_OPTIONS:
			s = "CC_GET_OPTIONS";		break;
		case CC_SET_GLOBAL_PATH:
			s = "CC_SET_GLOBAL_PATH";	break;
		case CC_GET_GLOBAL_PATH:
			s = "CC_GET_GLOBAL_PATH";	break;
		case CC_SET_PROCESS_PATH:
			s = "CC_SET_PROCESS_PATH";	break;
		case CC_GET_PROCESS_PATH:
			s = "CC_GET_PROCESS_PATH";	break;
		case CC_SET_GLOBAL_CONTENT:
			s = "CC_SET_GLOBAL_CONTENT";	break;
		case CC_GET_GLOBAL_CONTENT:
			s = "CC_GET_GLOBAL_CONTENT";	break;
		case CC_SET_PROCESS_CONTENT:
			s = "CC_SET_PROCESS_CONTENT";	break;
		case CC_GET_PROCESS_CONTENT:
			s = "CC_GET_PROCESS_CONTENT";	break;
		case CC_SET_DEFAULT_PATH:
			s = "CC_SET_DEFAULT_PATH";	break;
		case CC_GET_DEFAULT_PATH:
			s = "CC_GET_DEFAULT_PATH";	break;
		case CC_SET_DEFAULT_CONTENT:
			s = "CC_SET_DEFAULT_CONTENT";	break;
		case CC_GET_DEFAULT_CONTENT:
			s = "CC_GET_DEFAULT_CONTENT";	break;
		}
	}

	if (s == NULL)
		prt_dec(pri, 0, val);
	else
		outstring(pri, s);
}

void
prt_cco(private_t *pri, int raw, long val)	/* print corectl() options */
{
	char *s;

	if (val == 0)
		prt_dec(pri, 0, val);
	else if (raw || (val & ~CC_OPTIONS))
		prt_hhx(pri, 0, val);
	else {
#define	CBSIZE	sizeof (pri->code_buf)
		s = pri->code_buf;
		*s = '\0';
		if (val & CC_GLOBAL_PATH)
			(void) strlcat(s, "|CC_GLOBAL_PATH", CBSIZE);
		if (val & CC_PROCESS_PATH)
			(void) strlcat(s, "|CC_PROCESS_PATH", CBSIZE);
		if (val & CC_GLOBAL_SETID)
			(void) strlcat(s, "|CC_GLOBAL_SETID", CBSIZE);
		if (val & CC_PROCESS_SETID)
			(void) strlcat(s, "|CC_PROCESS_SETID", CBSIZE);
		if (val & CC_GLOBAL_LOG)
			(void) strlcat(s, "|CC_GLOBAL_LOG", CBSIZE);
		if (*s == '\0')
			prt_hhx(pri, 0, val);
		else
			outstring(pri, ++s);
#undef CBSIZE
	}
}

void
prt_ccc(private_t *pri, int raw, long val)	/* print corectl() content */
{
	core_content_t ccc;

	if (Pread(Proc, &ccc, sizeof (ccc), val) != sizeof (ccc))
		prt_hex(pri, 0, val);
	else if (!raw && proc_content2str(ccc, pri->code_buf,
	    sizeof (pri->code_buf)) >= 0)
		outstring(pri, pri->code_buf);
	else
		prt_hhx(pri, 0, (long)ccc);
}

void
prt_rcc(private_t *pri, int raw, long val)	/* print corectl() ret. cont. */
{
	core_content_t ccc;

	if (pri->Errno || Pread(Proc, &ccc, sizeof (ccc), val) != sizeof (ccc))
		prt_hex(pri, 0, val);
	else if (!raw && proc_content2str(ccc, pri->code_buf,
	    sizeof (pri->code_buf)) >= 0)
		outstring(pri, pri->code_buf);
	else
		prt_hhx(pri, 0, (long)ccc);
}

void
prt_cpc(private_t *pri, int raw, long val)	/* print cpc() subcode */
{
	const char *s = NULL;

	if (!raw) {
		switch (val) {
		case CPC_BIND:		s = "CPC_BIND";		break;
		case CPC_SAMPLE:	s = "CPC_SAMPLE";	break;
		case CPC_INVALIDATE:	s = "CPC_INVALIDATE";	break;
		case CPC_RELE:		s = "CPC_RELE";		break;
		case CPC_EVLIST_SIZE:	s = "CPC_EVLIST_SIZE";	break;
		case CPC_LIST_EVENTS:	s = "CPC_LIST_EVENTS";	break;
		case CPC_ATTRLIST_SIZE:	s = "CPC_ATTRLIST_SIZE"; break;
		case CPC_LIST_ATTRS:	s = "CPC_LIST_ATTRS";	break;
		case CPC_IMPL_NAME:	s = "CPC_IMPL_NAME";	break;
		case CPC_CPUREF:	s = "CPC_CPUREF";	break;
		case CPC_USR_EVENTS:	s = "CPC_USR_EVENTS";	break;
		case CPC_SYS_EVENTS:	s = "CPC_SYS_EVENTS";	break;
		case CPC_NPIC:		s = "CPC_NPIC";		break;
		case CPC_CAPS:		s = "CPC_CAPS";		break;
		case CPC_ENABLE:	s = "CPC_ENABLE";	break;
		case CPC_DISABLE:	s = "CPC_DISABLE";	break;
		}
	}

	if (s == NULL)
		prt_dec(pri, 0, val);
	else
		outstring(pri, s);
}

void
outstring(private_t *pri, const char *s)
{
	int len = strlen(s);

	GROW(len);
	(void) strcpy(pri->sys_string + pri->sys_leng, s);
	pri->sys_leng += len;
}

void
grow(private_t *pri, int nbyte)	/* reallocate format buffer if necessary */
{
	while (pri->sys_leng + nbyte >= pri->sys_ssize)
		pri->sys_string = my_realloc(pri->sys_string,
		    pri->sys_ssize *= 2, "format buffer");
}

void
prt_clc(private_t *pri, int raw, long val)
{
	const char *s = NULL;

	if (!raw) {
		switch (val) {
		case CL_INITIALIZE:	s = "CL_INITIALIZE";	break;
		case CL_CONFIG:		s = "CL_CONFIG";	break;
		}
	}

	if (s == NULL)
		prt_dec(pri, 0, val);
	else
		outstring(pri, s);
}

void
prt_clf(private_t *pri, int raw, long val)
{
	const char *s = NULL;

	if (!raw) {
		switch (pri->sys_args[0]) {
		case CL_CONFIG:
			switch (pri->sys_args[1]) {
			case CL_NODEID:
				s = "CL_NODEID";		break;
			case CL_HIGHEST_NODEID:
				s = "CL_HIGHEST_NODEID";	break;
			}
			break;
		case CL_INITIALIZE:
			switch (pri->sys_args[1]) {
			case CL_GET_BOOTFLAG:
				s = "CL_GET_BOOTFLAG";		break;
			}
			break;
		}
	}

	if (s == NULL)
		prt_dec(pri, 0, val);
	else
		outstring(pri, s);
}

void
prt_sqc(private_t *pri, int raw, long val)	/* print sigqueue() si_code */
{
	const char *s = NULL;

	if (!raw) {
		switch ((int)val) {
		case SI_QUEUE:		s = "SI_QUEUE";		break;
		case SI_TIMER:		s = "SI_TIMER";		break;
		case SI_ASYNCIO:	s = "SI_ASYNCIO";	break;
		case SI_MESGQ:		s = "SI_MESGQ";		break;
		}
	}

	if (s == NULL)
		prt_dec(pri, 0, val);
	else
		outstring(pri, s);
}

/*
 * print priocntlsys() (key, value) pair key.
 */
void
print_pck(private_t *pri, int raw, long val)
{
	const char	*s = NULL;
	char		clname[PC_CLNMSZ];

	if ((pri->sys_args[2] != PC_GETXPARMS &&
	    pri->sys_args[2] != PC_SETXPARMS) || val == 0 || raw) {
		prt_dec(pri, 0, val);
		return;
	}

	if (pri->sys_args[3] == NULL) {
		if (val == PC_KY_CLNAME) {
			s = "PC_KY_CLNAME";
			outstring(pri, s);
		} else
			prt_dec(pri, 0, val);
		return;
	}

	if (Pread(Proc, &clname, PC_CLNMSZ, pri->sys_args[3]) != PC_CLNMSZ) {
		prt_dec(pri, 0, val);
		return;
	}

	if (strcmp(clname, "TS") == 0) {
		switch (val) {
		case TS_KY_UPRILIM: 	s = "TS_KY_UPRILIM";	break;
		case TS_KY_UPRI:	s = "TS_KY_UPRI";	break;
		default:					break;
		}
	} else if (strcmp(clname, "IA") == 0) {
		switch (val) {
		case IA_KY_UPRILIM: 	s = "IA_KY_UPRILIM";	break;
		case IA_KY_UPRI:	s = "IA_KY_UPRI";	break;
		case IA_KY_MODE:	s = "IA_KY_MODE";	break;
		default:					break;
		}
	} else if (strcmp(clname, "RT") == 0) {
		switch (val) {
		case RT_KY_PRI: 	s = "RT_KY_PRI";	break;
		case RT_KY_TQSECS:	s = "RT_KY_TQSECS";	break;
		case RT_KY_TQNSECS:	s = "RT_KY_TQNSECS";	break;
		case RT_KY_TQSIG:	s = "RT_KY_TQSIG";	break;
		default:					break;
		}
	} else if (strcmp(clname, "FSS") == 0) {
		switch (val) {
		case FSS_KY_UPRILIM: 	s = "FSS_KY_UPRILIM";	break;
		case FSS_KY_UPRI:	s = "FSS_KY_UPRI";	break;
		default:					break;
		}
	} else if (strcmp(clname, "FX") == 0) {
		switch (val) {
		case FX_KY_UPRILIM: 	s = "FX_KY_UPRILIM";	break;
		case FX_KY_UPRI:	s = "FX_KY_UPRI";	break;
		case FX_KY_TQSECS:	s = "FX_KY_TQSECS";	break;
		case FX_KY_TQNSECS:	s = "FX_KY_TQNSECS";	break;
		default:					break;
		}
	}

	if (s == NULL)
		prt_dec(pri, 0, val);
	else
		outstring(pri, s);
}

/*
 * print priocntlsys() fourth argument.
 */
/*ARGSUSED*/
void
prt_pc4(private_t *pri, int raw, long val)
{
	/* look at pricntlsys function */
	if ((pri->sys_args[2] != PC_GETXPARMS &&
	    pri->sys_args[2] != PC_SETXPARMS))
		prt_hex(pri, 0, val);
	else if (val)
		prt_stg(pri, 0, val);
	else
		prt_dec(pri, 0, val);
}

/*
 * print priocntlsys() (key, value) pairs (5th argument).
 */
/*ARGSUSED*/
void
prt_pc5(private_t *pri, int raw, long val)
{
	pc_vaparms_t	prms;
	pc_vaparm_t	*vpp = &prms.pc_parms[0];
	uint_t		cnt;


	/* look at pricntlsys function */
	if ((pri->sys_args[2] != PC_GETXPARMS &&
	    pri->sys_args[2] != PC_SETXPARMS) || val == 0) {
		prt_dec(pri, 0, 0);
		return;
	}

	if (Pread(Proc, &prms, sizeof (prms), val) != sizeof (prms)) {
		prt_hex(pri, 0, val);
		return;
	}

	if ((cnt = prms.pc_vaparmscnt) > PC_VAPARMCNT)
		return;

	for (; cnt--; vpp++) {
		print_pck(pri, 0, vpp->pc_key);
		outstring(pri, ", ");
		prt_hex(pri, 0, (long)vpp->pc_parm);
		outstring(pri, ", ");
	}

	prt_dec(pri, 0, PC_KY_NULL);
}

/*
 * Print processor set id, including logical expansion of "special" ids.
 */
void
prt_pst(private_t *pri, int raw, long val)
{
	const char *s = NULL;

	if (!raw) {
		switch ((psetid_t)val) {
		case PS_NONE:		s = "PS_NONE";		break;
		case PS_QUERY:		s = "PS_QUERY";		break;
		case PS_MYID:		s = "PS_MYID";		break;
		}
	}

	if (s == NULL)
		prt_dec(pri, 0, val);
	else
		outstring(pri, s);
}

/*
 * Print meminfo() argument.
 */
/*ARGSUSED*/
void
prt_mif(private_t *pri, int raw, long val)
{
	struct meminfo	minfo;

#ifdef _LP64
	if (data_model == PR_MODEL_ILP32) {
		struct meminfo32 minfo32;

		if (Pread(Proc, &minfo32, sizeof (struct meminfo32), val) !=
			sizeof (struct meminfo32)) {
			prt_dec(pri, 0, pri->sys_args[1]);	/* addr_count */
			outstring(pri, ", ");
			prt_hex(pri, 0, val);
			return;
		}
		/*
		 * arrange the arguments in the order that user calls with
		 */
		prt_hex(pri, 0, minfo32.mi_inaddr);
		outstring(pri, ", ");
		prt_dec(pri, 0, pri->sys_args[1]);	/* addr_count */
		outstring(pri, ", ");
		prt_hex(pri, 0, minfo32.mi_info_req);
		outstring(pri, ", ");
		prt_dec(pri, 0, minfo32.mi_info_count);
		outstring(pri, ", ");
		prt_hex(pri, 0, minfo32.mi_outdata);
		outstring(pri, ", ");
		prt_hex(pri, 0, minfo32.mi_validity);
		return;
	}
#endif
	if (Pread(Proc, &minfo, sizeof (struct meminfo), val) !=
		sizeof (struct meminfo)) {
		prt_dec(pri, 0, pri->sys_args[1]);	/* addr_count */
		outstring(pri, ", ");
		prt_hex(pri, 0, val);
		return;
	}
	/*
	 * arrange the arguments in the order that user calls with
	 */
	prt_hex(pri, 0, (long)minfo.mi_inaddr);
	outstring(pri, ", ");
	prt_dec(pri, 0, pri->sys_args[1]);	/* addr_count */
	outstring(pri, ", ");
	prt_hex(pri, 0, (long)minfo.mi_info_req);
	outstring(pri, ", ");
	prt_dec(pri, 0, minfo.mi_info_count);
	outstring(pri, ", ");
	prt_hex(pri, 0, (long)minfo.mi_outdata);
	outstring(pri, ", ");
	prt_hex(pri, 0, (long)minfo.mi_validity);
}


/*
 * Print so_socket() 1st argument.
 */
/*ARGSUSED*/
void
prt_pfm(private_t *pri, int raw, long val)
{
	/* Protocol Families have same names as Address Families */
	if ((ulong_t)val < MAX_AFCODES) {
		outstring(pri, "PF_");
		outstring(pri, afcodes[val]);
	} else {
		prt_dec(pri, 0, val);
	}
}

/*
 * Print sockconfig() subcode.
 */
/*ARGSUSED*/
void
prt_skc(private_t *pri, int raw, long val)
{
	const char *s = NULL;

	if (!raw) {
		switch (val) {
		case SOCKCONFIG_ADD_SOCK:
			s = "SOCKCONFIG_ADD_SOCK"; break;
		case SOCKCONFIG_REMOVE_SOCK:
			s = "SOCKCONFIG_REMOVE_SOCK"; break;
		case SOCKCONFIG_ADD_FILTER:
			s = "SOCKCONFIG_ADD_FILTER"; break;
		case SOCKCONFIG_REMOVE_FILTER:
			s = "SOCKCONFIG_REMOVE_FILTER"; break;
		}
	}
	if (s == NULL)
		prt_dec(pri, 0, val);
	else
		outstring(pri, s);
}
/*
 * Print so_socket() 2nd argument.
 */
/*ARGSUSED*/
void
prt_skt(private_t *pri, int raw, long val)
{
	const char *s;
	long type = val & SOCK_TYPE_MASK;

	if ((ulong_t)type <= MAX_SOCKTYPES &&
	    (s = socktype_codes[type]) != NULL) {
		outstring(pri, s);
		if ((val & SOCK_CLOEXEC) != 0) {
			outstring(pri, "|SOCK_CLOEXEC");
		}
	} else {
		prt_dec(pri, 0, val);
	}
}


/*
 * Print so_socket() 3rd argument.
 */
/*ARGSUSED*/
void
prt_skp(private_t *pri, int raw, long val)
{
	const char *s;

	/* cheating -- look at the protocol-family */
	switch (pri->sys_args[0]) {
	case PF_INET6:
	case PF_INET:
	case PF_NCA:	if ((s = ipprotos((int)val)) != NULL) {
				outstring(pri, s);
				break;
			}
			/* FALLTHROUGH */
	default:	prt_dec(pri, 0, val);
			break;
	}
}


/*
 * Print so_socket() 5th argument.
 */
/*ARGSUSED*/
void
prt_skv(private_t *pri, int raw, long val)
{
	switch (val) {
	case SOV_STREAM:	outstring(pri, "SOV_STREAM");	break;
	case SOV_DEFAULT:	outstring(pri, "SOV_DEFAULT");	break;
	case SOV_SOCKSTREAM:	outstring(pri, "SOV_SOCKSTREAM");	break;
	case SOV_SOCKBSD:	outstring(pri, "SOV_SOCKBSD");	break;
	case SOV_XPG4_2:	outstring(pri, "SOV_XPG4_2");	break;
	default:		prt_dec(pri, 0, val);		break;
	}
}

/*
 * Print accept4() flags argument.
 */
void
prt_acf(private_t *pri, int raw, long val)
{
	int first = 1;
	if (raw || !val ||
	    (val & ~(SOCK_CLOEXEC|SOCK_NDELAY|SOCK_NONBLOCK))) {
		prt_dex(pri, 0, val);
		return;
	}

	if (val & SOCK_CLOEXEC) {
		outstring(pri, "|SOCK_CLOEXEC" + first);
		first = 0;
	}
	if (val & SOCK_NDELAY) {
		outstring(pri, "|SOCK_NDELAY" + first);
		first = 0;
	}
	if (val & SOCK_NONBLOCK) {
		outstring(pri, "|SOCK_NONBLOCK" + first);
	}
}


/*
 * Print setsockopt()/getsockopt() 2nd argument.
 */
/*ARGSUSED*/
void
prt_sol(private_t *pri, int raw, long val)
{
	if (val == SOL_SOCKET) {
		outstring(pri, "SOL_SOCKET");
	} else if (val == SOL_ROUTE) {
		outstring(pri, "SOL_ROUTE");
	} else {
		const struct protoent *p;
		struct protoent res;
		char buf[NSS_BUFLEN_PROTOCOLS];

		if ((p = getprotobynumber_r(val, &res,
		    (char *)buf, sizeof (buf))) != NULL)
			outstring(pri, p->p_name);
		else
			prt_dec(pri, 0, val);
	}
}


const char *
sol_optname(private_t *pri, long val)
{
#define	CBSIZE	sizeof (pri->code_buf)
	if (val >= SO_SNDBUF) {
		switch (val) {
		case SO_SNDBUF:		return ("SO_SNDBUF");
		case SO_RCVBUF:		return ("SO_RCVBUF");
		case SO_SNDLOWAT:	return ("SO_SNDLOWAT");
		case SO_RCVLOWAT:	return ("SO_RCVLOWAT");
		case SO_SNDTIMEO:	return ("SO_SNDTIMEO");
		case SO_RCVTIMEO:	return ("SO_RCVTIMEO");
		case SO_ERROR:		return ("SO_ERROR");
		case SO_TYPE:		return ("SO_TYPE");
		case SO_PROTOTYPE:	return ("SO_PROTOTYPE");
		case SO_ANON_MLP:	return ("SO_ANON_MLP");
		case SO_MAC_EXEMPT:	return ("SO_MAC_EXEMPT");
		case SO_ALLZONES:	return ("SO_ALLZONES");
		case SO_MAC_IMPLICIT:	return ("SO_MAC_IMPLICIT");
		case SO_VRRP:		return ("SO_VRRP");
		case SO_EXCLBIND:	return ("SO_EXCLBIND");
		case SO_DOMAIN:		return ("SO_DOMAIN");

		default:		(void) snprintf(pri->code_buf, CBSIZE,
					    "0x%lx", val);
					return (pri->code_buf);
		}
	} else {
		char *s = pri->code_buf;
		size_t used = 1;
		long val2;

		*s = '\0';
		val2 = val & ~(SO_DEBUG|SO_ACCEPTCONN|SO_REUSEADDR|SO_KEEPALIVE|
		    SO_DONTROUTE|SO_BROADCAST|SO_USELOOPBACK|SO_LINGER|
		    SO_OOBINLINE|SO_DGRAM_ERRIND|SO_RECVUCRED);
		if (val2)
			used = snprintf(s, CBSIZE, "|0x%lx", val2);
		if (val & SO_DEBUG)
			used = strlcat(s, "|SO_DEBUG", CBSIZE);
		if (val & SO_ACCEPTCONN)
			used = strlcat(s, "|SO_ACCEPTCONN", CBSIZE);
		if (val & SO_REUSEADDR)
			used = strlcat(s, "|SO_REUSEADDR", CBSIZE);
		if (val & SO_KEEPALIVE)
			used = strlcat(s, "|SO_KEEPALIVE", CBSIZE);
		if (val & SO_DONTROUTE)
			used = strlcat(s, "|SO_DONTROUTE", CBSIZE);
		if (val & SO_BROADCAST)
			used = strlcat(s, "|SO_BROADCAST", CBSIZE);
		if (val & SO_USELOOPBACK)
			used = strlcat(s, "|SO_USELOOPBACK", CBSIZE);
		if (val & SO_LINGER)
			used = strlcat(s, "|SO_LINGER", CBSIZE);
		if (val & SO_OOBINLINE)
			used = strlcat(s, "|SO_OOBINLINE", CBSIZE);
		if (val & SO_DGRAM_ERRIND)
			used = strlcat(s, "|SO_DGRAM_ERRIND", CBSIZE);
		if (val & SO_RECVUCRED)
			used = strlcat(s, "|SO_RECVUCRED", CBSIZE);
		if (used >= CBSIZE || val == 0)
			(void) snprintf(s + 1, CBSIZE-1, "0x%lx", val);
		return ((const char *)(s + 1));
	}
#undef CBSIZE
}

const char *
route_optname(private_t *pri, long val)
{
	switch (val) {
	case RT_AWARE:
		return ("RT_AWARE");
	default:
		(void) snprintf(pri->code_buf, sizeof (pri->code_buf),
		    "0x%lx", val);
		return (pri->code_buf);
	}
}

const char *
tcp_optname(private_t *pri, long val)
{
	switch (val) {
	case TCP_NODELAY:		return ("TCP_NODELAY");
	case TCP_MAXSEG:		return ("TCP_MAXSEG");
	case TCP_KEEPALIVE:		return ("TCP_KEEPALIVE");
	case TCP_NOTIFY_THRESHOLD:	return ("TCP_NOTIFY_THRESHOLD");
	case TCP_ABORT_THRESHOLD:	return ("TCP_ABORT_THRESHOLD");
	case TCP_CONN_NOTIFY_THRESHOLD:	return ("TCP_CONN_NOTIFY_THRESHOLD");
	case TCP_CONN_ABORT_THRESHOLD:	return ("TCP_CONN_ABORT_THRESHOLD");
	case TCP_RECVDSTADDR:		return ("TCP_RECVDSTADDR");
	case TCP_ANONPRIVBIND:		return ("TCP_ANONPRIVBIND");
	case TCP_EXCLBIND:		return ("TCP_EXCLBIND");
	case TCP_INIT_CWND:		return ("TCP_INIT_CWND");
	case TCP_KEEPALIVE_THRESHOLD:	return ("TCP_KEEPALIVE_THRESHOLD");
	case TCP_KEEPALIVE_ABORT_THRESHOLD:
		return ("TCP_KEEPALIVE_ABORT_THRESHOLD");
	case TCP_CORK:			return ("TCP_CORK");
	case TCP_RTO_INITIAL:		return ("TCP_RTO_INITIAL");
	case TCP_RTO_MIN:		return ("TCP_RTO_MIN");
	case TCP_RTO_MAX:		return ("TCP_RTO_MAX");
	case TCP_LINGER2:		return ("TCP_LINGER2");
	case TCP_KEEPIDLE:		return ("TCP_KEEPIDLE");
	case TCP_KEEPCNT:		return ("TCP_KEEPCNT");
	case TCP_KEEPINTVL:		return ("TCP_KEEPINTVL");

	default:			(void) snprintf(pri->code_buf,
					    sizeof (pri->code_buf),
					    "0x%lx", val);
					return (pri->code_buf);
	}
}


const char *
sctp_optname(private_t *pri, long val)
{
	switch (val) {
	case SCTP_RTOINFO:		return ("SCTP_RTOINFO");
	case SCTP_ASSOCINFO:		return ("SCTP_ASSOCINFO");
	case SCTP_INITMSG:		return ("SCTP_INITMSG");
	case SCTP_NODELAY:		return ("SCTP_NODELAY");
	case SCTP_AUTOCLOSE:		return ("SCTP_AUTOCLOSE");
	case SCTP_SET_PEER_PRIMARY_ADDR:
		return ("SCTP_SET_PEER_PRIMARY_ADDR");
	case SCTP_PRIMARY_ADDR:		return ("SCTP_PRIMARY_ADDR");
	case SCTP_ADAPTATION_LAYER:	return ("SCTP_ADAPTATION_LAYER");
	case SCTP_DISABLE_FRAGMENTS:	return ("SCTP_DISABLE_FRAGMENTS");
	case SCTP_PEER_ADDR_PARAMS:	return ("SCTP_PEER_ADDR_PARAMS");
	case SCTP_DEFAULT_SEND_PARAM:	return ("SCTP_DEFAULT_SEND_PARAM");
	case SCTP_EVENTS:		return ("SCTP_EVENTS");
	case SCTP_I_WANT_MAPPED_V4_ADDR:
		return ("SCTP_I_WANT_MAPPED_V4_ADDR");
	case SCTP_MAXSEG:		return ("SCTP_MAXSEG");
	case SCTP_STATUS:		return ("SCTP_STATUS");
	case SCTP_GET_PEER_ADDR_INFO:	return ("SCTP_GET_PEER_ADDR_INFO");

	case SCTP_ADD_ADDR:		return ("SCTP_ADD_ADDR");
	case SCTP_REM_ADDR:		return ("SCTP_REM_ADDR");

	default:			(void) snprintf(pri->code_buf,
					    sizeof (pri->code_buf),
					    "0x%lx", val);
					return (pri->code_buf);
	}
}


const char *
udp_optname(private_t *pri, long val)
{
	switch (val) {
	case UDP_CHECKSUM:		return ("UDP_CHECKSUM");
	case UDP_ANONPRIVBIND:		return ("UDP_ANONPRIVBIND");
	case UDP_EXCLBIND:		return ("UDP_EXCLBIND");
	case UDP_RCVHDR:		return ("UDP_RCVHDR");
	case UDP_NAT_T_ENDPOINT:	return ("UDP_NAT_T_ENDPOINT");

	default:			(void) snprintf(pri->code_buf,
					    sizeof (pri->code_buf), "0x%lx",
					    val);
					return (pri->code_buf);
	}
}


/*
 * Print setsockopt()/getsockopt() 3rd argument.
 */
/*ARGSUSED*/
void
prt_son(private_t *pri, int raw, long val)
{
	/* cheating -- look at the level */
	switch (pri->sys_args[1]) {
	case SOL_SOCKET:	outstring(pri, sol_optname(pri, val));
				break;
	case SOL_ROUTE:		outstring(pri, route_optname(pri, val));
				break;
	case IPPROTO_TCP:	outstring(pri, tcp_optname(pri, val));
				break;
	case IPPROTO_UDP:	outstring(pri, udp_optname(pri, val));
				break;
	case IPPROTO_SCTP:	outstring(pri, sctp_optname(pri, val));
				break;
	default:		prt_dec(pri, 0, val);
				break;
	}
}


/*
 * Print utrap type
 */
/*ARGSUSED*/
void
prt_utt(private_t *pri, int raw, long val)
{
	const char *s = NULL;

#ifdef __sparc
	if (!raw) {
		switch (val) {
		case UT_INSTRUCTION_DISABLED:
			s = "UT_INSTRUCTION_DISABLED"; break;
		case UT_INSTRUCTION_ERROR:
			s = "UT_INSTRUCTION_ERROR"; break;
		case UT_INSTRUCTION_PROTECTION:
			s = "UT_INSTRUCTION_PROTECTION"; break;
		case UT_ILLTRAP_INSTRUCTION:
			s = "UT_ILLTRAP_INSTRUCTION"; break;
		case UT_ILLEGAL_INSTRUCTION:
			s = "UT_ILLEGAL_INSTRUCTION"; break;
		case UT_PRIVILEGED_OPCODE:
			s = "UT_PRIVILEGED_OPCODE"; break;
		case UT_FP_DISABLED:
			s = "UT_FP_DISABLED"; break;
		case UT_FP_EXCEPTION_IEEE_754:
			s = "UT_FP_EXCEPTION_IEEE_754"; break;
		case UT_FP_EXCEPTION_OTHER:
			s = "UT_FP_EXCEPTION_OTHER"; break;
		case UT_TAG_OVERFLOW:
			s = "UT_TAG_OVERFLOW"; break;
		case UT_DIVISION_BY_ZERO:
			s = "UT_DIVISION_BY_ZERO"; break;
		case UT_DATA_EXCEPTION:
			s = "UT_DATA_EXCEPTION"; break;
		case UT_DATA_ERROR:
			s = "UT_DATA_ERROR"; break;
		case UT_DATA_PROTECTION:
			s = "UT_DATA_PROTECTION"; break;
		case UT_MEM_ADDRESS_NOT_ALIGNED:
			s = "UT_MEM_ADDRESS_NOT_ALIGNED"; break;
		case UT_PRIVILEGED_ACTION:
			s = "UT_PRIVILEGED_ACTION"; break;
		case UT_ASYNC_DATA_ERROR:
			s = "UT_ASYNC_DATA_ERROR"; break;
		case UT_TRAP_INSTRUCTION_16:
			s = "UT_TRAP_INSTRUCTION_16"; break;
		case UT_TRAP_INSTRUCTION_17:
			s = "UT_TRAP_INSTRUCTION_17"; break;
		case UT_TRAP_INSTRUCTION_18:
			s = "UT_TRAP_INSTRUCTION_18"; break;
		case UT_TRAP_INSTRUCTION_19:
			s = "UT_TRAP_INSTRUCTION_19"; break;
		case UT_TRAP_INSTRUCTION_20:
			s = "UT_TRAP_INSTRUCTION_20"; break;
		case UT_TRAP_INSTRUCTION_21:
			s = "UT_TRAP_INSTRUCTION_21"; break;
		case UT_TRAP_INSTRUCTION_22:
			s = "UT_TRAP_INSTRUCTION_22"; break;
		case UT_TRAP_INSTRUCTION_23:
			s = "UT_TRAP_INSTRUCTION_23"; break;
		case UT_TRAP_INSTRUCTION_24:
			s = "UT_TRAP_INSTRUCTION_24"; break;
		case UT_TRAP_INSTRUCTION_25:
			s = "UT_TRAP_INSTRUCTION_25"; break;
		case UT_TRAP_INSTRUCTION_26:
			s = "UT_TRAP_INSTRUCTION_26"; break;
		case UT_TRAP_INSTRUCTION_27:
			s = "UT_TRAP_INSTRUCTION_27"; break;
		case UT_TRAP_INSTRUCTION_28:
			s = "UT_TRAP_INSTRUCTION_28"; break;
		case UT_TRAP_INSTRUCTION_29:
			s = "UT_TRAP_INSTRUCTION_29"; break;
		case UT_TRAP_INSTRUCTION_30:
			s = "UT_TRAP_INSTRUCTION_30"; break;
		case UT_TRAP_INSTRUCTION_31:
			s = "UT_TRAP_INSTRUCTION_31"; break;
		}
	}
#endif /* __sparc */

	if (s == NULL)
		prt_dec(pri, 0, val);
	else
		outstring(pri, s);
}


/*
 * Print utrap handler
 */
void
prt_uth(private_t *pri, int raw, long val)
{
	const char *s = NULL;

	if (!raw) {
		switch (val) {
		case (long)UTH_NOCHANGE:	s = "UTH_NOCHANGE"; break;
		}
	}

	if (s == NULL)
		prt_hex(pri, 0, val);
	else
		outstring(pri, s);
}

const char *
access_flags(private_t *pri, long arg)
{
#define	E_OK 010
	char *str = pri->code_buf;

	if (arg & ~(R_OK|W_OK|X_OK|E_OK))
		return (NULL);

	/* NB: F_OK == 0 */
	if (arg == F_OK)
		return ("F_OK");
	if (arg == E_OK)
		return ("F_OK|E_OK");

	*str = '\0';
	if (arg & R_OK)
		(void) strlcat(str, "|R_OK", sizeof (pri->code_buf));
	if (arg & W_OK)
		(void) strlcat(str, "|W_OK", sizeof (pri->code_buf));
	if (arg & X_OK)
		(void) strlcat(str, "|X_OK", sizeof (pri->code_buf));
	if (arg & E_OK)
		(void) strlcat(str, "|E_OK", sizeof (pri->code_buf));
	return ((const char *)(str + 1));
#undef E_OK
}

/*
 * Print access() flags.
 */
void
prt_acc(private_t *pri, int raw, long val)
{
	const char *s = raw? NULL : access_flags(pri, val);

	if (s == NULL)
		prt_dex(pri, 0, val);
	else
		outstring(pri, s);
}

/*
 * Print shutdown() "how" (2nd) argument
 */
void
prt_sht(private_t *pri, int raw, long val)
{
	if (raw) {
		prt_dex(pri, 0, val);
		return;
	}
	switch (val) {
	case SHUT_RD:	outstring(pri, "SHUT_RD");	break;
	case SHUT_WR:	outstring(pri, "SHUT_WR");	break;
	case SHUT_RDWR:	outstring(pri, "SHUT_RDWR");	break;
	default:	prt_dec(pri, 0, val);		break;
	}
}

/*
 * Print fcntl() F_SETFL flags (3rd) argument or fdsync flag (2nd arg)
 */
static struct fcntl_flags {
	long		val;
	const char	*name;
} fcntl_flags[] = {
#define	FC_FL(flag)	{ (long)flag, "|" # flag }
	FC_FL(FREVOKED),
	FC_FL(FREAD),
	FC_FL(FWRITE),
	FC_FL(FNDELAY),
	FC_FL(FAPPEND),
	FC_FL(FSYNC),
	FC_FL(FDSYNC),
	FC_FL(FRSYNC),
	FC_FL(FOFFMAX),
	FC_FL(FNONBLOCK),
	FC_FL(FCREAT),
	FC_FL(FTRUNC),
	FC_FL(FEXCL),
	FC_FL(FNOCTTY),
	FC_FL(FXATTR),
	FC_FL(FASYNC),
	FC_FL(FNODSYNC)
#undef FC_FL
};

void
prt_ffg(private_t *pri, int raw, long val)
{
#define	CBSIZE	sizeof (pri->code_buf)
	char *s = pri->code_buf;
	size_t used = 1;
	struct fcntl_flags *fp;

	if (raw) {
		(void) snprintf(s, CBSIZE, "0x%lx", val);
		outstring(pri, s);
		return;
	}
	if (val == 0) {
		outstring(pri, "(no flags)");
		return;
	}

	*s = '\0';
	for (fp = fcntl_flags;
	    fp < &fcntl_flags[sizeof (fcntl_flags) / sizeof (*fp)]; fp++) {
		if (val & fp->val) {
			used = strlcat(s, fp->name, CBSIZE);
			val &= ~fp->val;
		}
	}

	if (val != 0 && used <= CBSIZE)
		used += snprintf(s + used, CBSIZE - used, "|0x%lx", val);

	if (used >= CBSIZE)
		(void) snprintf(s + 1, CBSIZE-1, "0x%lx", val);
	outstring(pri, s + 1);
#undef CBSIZE
}

void
prt_prs(private_t *pri, int raw, long val)
{
	static size_t setsize;
	priv_set_t *set = priv_allocset();

	if (setsize == 0) {
		const priv_impl_info_t *info = getprivimplinfo();
		if (info != NULL)
			setsize = info->priv_setsize * sizeof (priv_chunk_t);
	}

	if (setsize != 0 && !raw && set != NULL &&
	    Pread(Proc, set, setsize, val) == setsize) {
		int i;

		outstring(pri, "{");
		for (i = 0; i < setsize / sizeof (priv_chunk_t); i++) {
			char buf[9];	/* 8 hex digits + '\0' */
			(void) snprintf(buf, sizeof (buf), "%08x",
			    ((priv_chunk_t *)set)[i]);
			outstring(pri, buf);
		}

		outstring(pri, "}");
	} else {
		prt_hex(pri, 0, val);
	}

	if (set != NULL)
		priv_freeset(set);
}

/*
 * Print privilege set operation.
 */
void
prt_pro(private_t *pri, int raw, long val)
{
	const char *s = NULL;

	if (!raw) {
		switch ((priv_op_t)val) {
		case PRIV_ON:		s = "PRIV_ON";		break;
		case PRIV_OFF:		s = "PRIV_OFF";		break;
		case PRIV_SET:		s = "PRIV_SET";		break;
		}
	}

	if (s == NULL)
		prt_dec(pri, 0, val);
	else
		outstring(pri, s);
}

/*
 * Print privilege set name
 */
void
prt_prn(private_t *pri, int raw, long val)
{
	const char *s = NULL;

	if (!raw)
		s = priv_getsetbynum((int)val);

	if (s == NULL)
		prt_dec(pri, 0, val);
	else {
		char *dup = strdup(s);
		char *q;

		/* Do the best we can in this case */
		if (dup == NULL) {
			outstring(pri, s);
			return;
		}

		outstring(pri, "PRIV_");

		q = dup;

		while (*q != '\0') {
			*q = toupper(*q);
			q++;
		}
		outstring(pri, dup);
		free(dup);
	}
}

/*
 * Print process flag names.
 */
void
prt_pfl(private_t *pri, int raw, long val)
{
	const char *s = NULL;

	if (!raw) {
		switch ((int)val) {
		case PRIV_DEBUG:	s = "PRIV_DEBUG";	break;
		case PRIV_AWARE:	s = "PRIV_AWARE";	break;
		case PRIV_XPOLICY:	s = "PRIV_XPOLICY";	break;
		case PRIV_AWARE_RESET:  s = "PRIV_AWARE_RESET"; break;
		case PRIV_PFEXEC:	s = "PRIV_PFEXEC";	break;
		case NET_MAC_AWARE:	s =  "NET_MAC_AWARE";	break;
		case NET_MAC_AWARE_INHERIT:
			s = "NET_MAC_AWARE_INHERIT";
			break;
		}
	}

	if (s == NULL)
		prt_dec(pri, 0, val);
	else
		outstring(pri, s);
}

/*
 * Print lgrp_affinity_{get,set}() arguments.
 */
/*ARGSUSED*/
void
prt_laf(private_t *pri, int raw, long val)
{
	lgrp_affinity_args_t	laff;

	if (Pread(Proc, &laff, sizeof (lgrp_affinity_args_t), val) !=
	    sizeof (lgrp_affinity_args_t)) {
		prt_hex(pri, 0, val);
		return;
	}
	/*
	 * arrange the arguments in the order that user calls with
	 */
	prt_dec(pri, 0, laff.idtype);
	outstring(pri, ", ");
	prt_dec(pri, 0, laff.id);
	outstring(pri, ", ");
	prt_dec(pri, 0, laff.lgrp);
	outstring(pri, ", ");
	if (pri->sys_args[0] == LGRP_SYS_AFFINITY_SET)
		prt_dec(pri, 0, laff.aff);
}

/*
 * Print a key_t as IPC_PRIVATE if it is 0.
 */
void
prt_key(private_t *pri, int raw, long val)
{
	if (!raw && val == 0)
		outstring(pri, "IPC_PRIVATE");
	else
		prt_dec(pri, 0, val);
}


/*
 * Print zone_getattr() attribute types.
 */
void
prt_zga(private_t *pri, int raw, long val)
{
	const char *s = NULL;

	if (!raw) {
		switch ((int)val) {
		case ZONE_ATTR_NAME:	s = "ZONE_ATTR_NAME";	break;
		case ZONE_ATTR_ROOT:	s = "ZONE_ATTR_ROOT";	break;
		case ZONE_ATTR_STATUS:	s = "ZONE_ATTR_STATUS";	break;
		case ZONE_ATTR_PRIVSET:	s = "ZONE_ATTR_PRIVSET"; break;
		case ZONE_ATTR_UNIQID:	s = "ZONE_ATTR_UNIQID"; break;
		case ZONE_ATTR_POOLID:	s = "ZONE_ATTR_POOLID"; break;
		case ZONE_ATTR_INITPID:	s = "ZONE_ATTR_INITPID"; break;
		case ZONE_ATTR_SLBL:	s = "ZONE_ATTR_SLBL"; break;
		case ZONE_ATTR_INITNAME:	s = "ZONE_ATTR_INITNAME"; break;
		case ZONE_ATTR_BOOTARGS:	s = "ZONE_ATTR_BOOTARGS"; break;
		case ZONE_ATTR_BRAND:	s = "ZONE_ATTR_BRAND"; break;
		case ZONE_ATTR_FLAGS:	s = "ZONE_ATTR_FLAGS"; break;
		case ZONE_ATTR_PHYS_MCAP: s = "ZONE_ATTR_PHYS_MCAP"; break;
		}
	}

	if (s == NULL)
		prt_dec(pri, 0, val);
	else
		outstring(pri, s);
}

/*
 * Print a file descriptor as AT_FDCWD if necessary
 */
void
prt_atc(private_t *pri, int raw, long val)
{
	if ((int)val == AT_FDCWD) {
		if (raw)
			prt_hex(pri, 0, (uint_t)AT_FDCWD);
		else
			outstring(pri, "AT_FDCWD");
	} else {
		prt_dec(pri, 0, val);
	}
}

/*
 * Print Trusted Networking database operation codes (labelsys; tn*)
 */
static void
prt_tnd(private_t *pri, int raw, long val)
{
	const char *s = NULL;

	if (!raw) {
		switch ((tsol_dbops_t)val) {
		case TNDB_NOOP:		s = "TNDB_NOOP";	break;
		case TNDB_LOAD:		s = "TNDB_LOAD";	break;
		case TNDB_DELETE:	s = "TNDB_DELETE";	break;
		case TNDB_FLUSH:	s = "TNDB_FLUSH";	break;
		case TNDB_GET:		s = "TNDB_GET";		break;
		}
	}

	if (s == NULL)
		prt_dec(pri, 0, val);
	else
		outstring(pri, s);
}

/*
 * Print LIO_XX flags
 */
void
prt_lio(private_t *pri, int raw, long val)
{
	if (raw)
		prt_dec(pri, 0, val);
	else if (val == LIO_WAIT)
		outstring(pri, "LIO_WAIT");
	else if (val == LIO_NOWAIT)
		outstring(pri, "LIO_NOWAIT");
	else
		prt_dec(pri, 0, val);
}

const char *
door_flags(private_t *pri, long val)
{
	door_attr_t attr = (door_attr_t)val;
	char *str = pri->code_buf;

	*str = '\0';
#define	PROCESS_FLAG(flg)						\
	if (attr & flg) {						\
		(void) strlcat(str, "|" #flg, sizeof (pri->code_buf));	\
		attr &= ~flg;						\
	}

	PROCESS_FLAG(DOOR_UNREF);
	PROCESS_FLAG(DOOR_UNREF_MULTI);
	PROCESS_FLAG(DOOR_PRIVATE);
	PROCESS_FLAG(DOOR_REFUSE_DESC);
	PROCESS_FLAG(DOOR_NO_CANCEL);
	PROCESS_FLAG(DOOR_LOCAL);
	PROCESS_FLAG(DOOR_REVOKED);
	PROCESS_FLAG(DOOR_IS_UNREF);
#undef PROCESS_FLAG

	if (attr != 0 || *str == '\0') {
		size_t len = strlen(str);
		(void) snprintf(str + len, sizeof (pri->code_buf) - len,
		    "|0x%X", attr);
	}

	return (str + 1);
}

/*
 * Print door_create() flags
 */
void
prt_dfl(private_t *pri, int raw, long val)
{
	if (raw)
		prt_hex(pri, 0, val);
	else
		outstring(pri, door_flags(pri, val));
}

/*
 * Print door_*param() param argument
 */
void
prt_dpm(private_t *pri, int raw, long val)
{
	if (raw)
		prt_hex(pri, 0, val);
	else if (val == DOOR_PARAM_DESC_MAX)
		outstring(pri, "DOOR_PARAM_DESC_MAX");
	else if (val == DOOR_PARAM_DATA_MIN)
		outstring(pri, "DOOR_PARAM_DATA_MIN");
	else if (val == DOOR_PARAM_DATA_MAX)
		outstring(pri, "DOOR_PARAM_DATA_MAX");
	else
		prt_hex(pri, 0, val);
}

/*
 * Print rctlsys subcodes
 */
void
prt_rsc(private_t *pri, int raw, long val)	/* print utssys code */
{
	const char *s = raw? NULL : rctlsyscode(val);

	if (s == NULL)
		prt_dec(pri, 0, val);
	else
		outstring(pri, s);
}

/*
 * Print getrctl flags
 */
void
prt_rgf(private_t *pri, int raw, long val)
{
	long action = val & (~RCTLSYS_ACTION_MASK);

	if (raw)
		prt_hex(pri, 0, val);
	else if (action == RCTL_FIRST)
		outstring(pri, "RCTL_FIRST");
	else if (action == RCTL_NEXT)
		outstring(pri, "RCTL_NEXT");
	else if (action == RCTL_USAGE)
		outstring(pri, "RCTL_USAGE");
	else
		prt_hex(pri, 0, val);
}

/*
 * Print setrctl flags
 */
void
prt_rsf(private_t *pri, int raw, long val)
{
	long action = val & (~RCTLSYS_ACTION_MASK);
	long pval = val & RCTL_LOCAL_ACTION_MASK;
	char *s = pri->code_buf;

	if (raw) {
		prt_hex(pri, 0, val);
		return;
	} else if (action == RCTL_INSERT)
		(void) strcpy(s, "RCTL_INSERT");
	else if (action == RCTL_DELETE)
		(void) strcpy(s, "RCTL_DELETE");
	else if (action == RCTL_REPLACE)
		(void) strcpy(s, "RCTL_REPLACE");
	else {
		prt_hex(pri, 0, val);
		return;
	}

	if (pval & RCTL_USE_RECIPIENT_PID) {
		pval ^= RCTL_USE_RECIPIENT_PID;
		(void) strlcat(s, "|RCTL_USE_RECIPIENT_PID",
		    sizeof (pri->code_buf));
	}

	if ((pval & RCTLSYS_ACTION_MASK) != 0)
		prt_hex(pri, 0, val);
	else if (*s != '\0')
		outstring(pri, s);
	else
		prt_hex(pri, 0, val);
}

/*
 * Print rctlctl flags
 */
void
prt_rcf(private_t *pri, int raw, long val)
{
	long action = val & (~RCTLSYS_ACTION_MASK);

	if (raw)
		prt_hex(pri, 0, val);
	else if (action == RCTLCTL_GET)
		outstring(pri, "RCTLCTL_GET");
	else if (action == RCTLCTL_SET)
		outstring(pri, "RCTLCTL_SET");
	else
		prt_hex(pri, 0, val);
}

/*
 * Print setprojrctl flags
 */
void
prt_spf(private_t *pri, int raw, long val)
{
	long action = val & TASK_PROJ_MASK;

	if (!raw && (action == TASK_PROJ_PURGE))
		outstring(pri, "TASK_PROJ_PURGE");
	else
		prt_hex(pri, 0, val);
}

/*
 * Print forkx() flags
 */
void
prt_fxf(private_t *pri, int raw, long val)
{
	char *str;

	if (val == 0)
		outstring(pri, "0");
	else if (raw || (val & ~(FORK_NOSIGCHLD | FORK_WAITPID)))
		prt_hhx(pri, 0, val);
	else {
		str = pri->code_buf;
		*str = '\0';
		if (val & FORK_NOSIGCHLD)
			(void) strlcat(str, "|FORK_NOSIGCHLD",
			    sizeof (pri->code_buf));
		if (val & FORK_WAITPID)
			(void) strlcat(str, "|FORK_WAITPID",
			    sizeof (pri->code_buf));
		outstring(pri, str + 1);
	}
}

/*
 * Print faccessat() flag
 */
void
prt_fat(private_t *pri, int raw, long val)
{
	if (val == 0)
		outstring(pri, "0");
	else if (!raw && val == AT_EACCESS)
		outstring(pri, "AT_EACCESS");
	else
		prt_hex(pri, 0, val);
}

/*
 * Print unlinkat() flag
 */
void
prt_uat(private_t *pri, int raw, long val)
{
	if (val == 0)
		outstring(pri, "0");
	else if (!raw && val == AT_REMOVEDIR)
		outstring(pri, "AT_REMOVEDIR");
	else
		prt_hex(pri, 0, val);
}

/*
 * Print AT_SYMLINK_NOFOLLOW / AT_SYMLINK_FOLLOW flag
 */
void
prt_snf(private_t *pri, int raw, long val)
{
	if (val == 0)
		outstring(pri, "0");
	else if (!raw && val == AT_SYMLINK_NOFOLLOW)
		outstring(pri, "AT_SYMLINK_NOFOLLOW");
	else if (!raw && val == AT_SYMLINK_FOLLOW)
		outstring(pri, "AT_SYMLINK_FOLLOW");
	else
		prt_hex(pri, 0, val);
}

void
prt_grf(private_t *pri, int raw, long val)
{
	int first = 1;

	if (raw != 0 || val == 0 ||
	    (val & ~(GRND_NONBLOCK | GRND_RANDOM)) != 0) {
		outstring(pri, "0");
		return;
	}

	if (val & GRND_NONBLOCK) {
		outstring(pri, "|GRND_NONBLOCK" + first);
		first = 0;
	}
	if (val & GRND_RANDOM) {
		outstring(pri, "|GRND_RANDOM" + first);
		first = 0;
	}
}

/*
 * Array of pointers to print functions, one for each format.
 */
void (* const Print[])() = {
	prt_nov,	/* NOV -- no value */
	prt_dec,	/* DEC -- print value in decimal */
	prt_oct,	/* OCT -- print value in octal */
	prt_hex,	/* HEX -- print value in hexadecimal */
	prt_dex,	/* DEX -- print value in hexadecimal if big enough */
	prt_stg,	/* STG -- print value as string */
	prt_ioc,	/* IOC -- print ioctl code */
	prt_fcn,	/* FCN -- print fcntl code */
	prt_s86,	/* S86 -- print sysi86 code */
	prt_uts,	/* UTS -- print utssys code */
	prt_opn,	/* OPN -- print open code */
	prt_sig,	/* SIG -- print signal name plus flags */
	prt_uat,	/* UAT -- print unlinkat() flag */
	prt_msc,	/* MSC -- print msgsys command */
	prt_msf,	/* MSF -- print msgsys flags */
	prt_smc,	/* SMC -- print semsys command */
	prt_sef,	/* SEF -- print semsys flags */
	prt_shc,	/* SHC -- print shmsys command */
	prt_shf,	/* SHF -- print shmsys flags */
	prt_fat,	/* FAT -- print faccessat( flag */
	prt_sfs,	/* SFS -- print sysfs code */
	prt_rst,	/* RST -- print string returned by syscall */
	prt_smf,	/* SMF -- print streams message flags */
	prt_ioa,	/* IOA -- print ioctl argument */
	prt_pip,	/* PIP -- print pipe flags */
	prt_mtf,	/* MTF -- print mount flags */
	prt_mft,	/* MFT -- print mount file system type */
	prt_iob,	/* IOB -- print contents of I/O buffer */
	prt_hhx,	/* HHX -- print value in hexadecimal (half size) */
	prt_wop,	/* WOP -- print waitsys() options */
	prt_spm,	/* SPM -- print sigprocmask argument */
	prt_rlk,	/* RLK -- print readlink buffer */
	prt_mpr,	/* MPR -- print mmap()/mprotect() flags */
	prt_mty,	/* MTY -- print mmap() mapping type flags */
	prt_mcf,	/* MCF -- print memcntl() function */
	prt_mc4,	/* MC4 -- print memcntl() (fourth) argument */
	prt_mc5,	/* MC5 -- print memcntl() (fifth) argument */
	prt_mad,	/* MAD -- print madvise() argument */
	prt_ulm,	/* ULM -- print ulimit() argument */
	prt_rlm,	/* RLM -- print get/setrlimit() argument */
	prt_cnf,	/* CNF -- print sysconfig() argument */
	prt_inf,	/* INF -- print sysinfo() argument */
	prt_ptc,	/* PTC -- print pathconf/fpathconf() argument */
	prt_fui,	/* FUI -- print fusers() input argument */
	prt_idt,	/* IDT -- print idtype_t, waitid() argument */
	prt_lwf,	/* LWF -- print lwp_create() flags */
	prt_itm,	/* ITM -- print [get|set]itimer() arg */
	prt_llo,	/* LLO -- print long long offset arg */
	prt_mod,	/* MOD -- print modctl() subcode */
	prt_whn,	/* WHN -- print lseek() whence arguiment */
	prt_acl,	/* ACL -- print acl() code */
	prt_aio,	/* AIO -- print kaio() code */
	prt_aud,	/* AUD -- print auditsys() code */
	prt_uns,	/* DEC -- print value in unsigned decimal */
	prt_clc,	/* CLC -- print cladm command argument */
	prt_clf,	/* CLF -- print cladm flag argument */
	prt_cor,	/* COR -- print corectl() subcode */
	prt_cco,	/* CCO -- print corectl() options */
	prt_ccc,	/* CCC -- print corectl() content */
	prt_rcc,	/* RCC -- print corectl() returned content */
	prt_cpc,	/* CPC -- print cpc() subcode */
	prt_sqc,	/* SQC -- print sigqueue() si_code argument */
	prt_pc4,	/* PC4 -- print priocntlsys() (fourth) argument */
	prt_pc5,	/* PC5 -- print priocntlsys() (key, value) pairs */
	prt_pst,	/* PST -- print processor set id */
	prt_mif,	/* MIF -- print meminfo() arguments */
	prt_pfm,	/* PFM -- print so_socket() proto-family (1st) arg */
	prt_skt,	/* SKT -- print so_socket() socket-type (2nd) arg */
	prt_skp,	/* SKP -- print so_socket() protocol (3rd) arg */
	prt_skv,	/* SKV -- print socket version arg */
	prt_sol,	/* SOL -- print [sg]etsockopt() level (2nd) arg */
	prt_son,	/* SON -- print [sg]etsockopt() opt-name (3rd) arg */
	prt_utt,	/* UTT -- print utrap type */
	prt_uth,	/* UTH -- print utrap handler */
	prt_acc,	/* ACC -- print access() flags */
	prt_sht,	/* SHT -- print shutdown() how (2nd) argument */
	prt_ffg,	/* FFG -- print fcntl() flags (3rd) argument */
	prt_prs,	/* PRS -- print privilege set */
	prt_pro,	/* PRO -- print privilege set operation */
	prt_prn,	/* PRN -- print privilege set name */
	prt_pfl,	/* PFL -- print privilege/process flag name */
	prt_laf,	/* LAF -- print lgrp_affinity arguments */
	prt_key,	/* KEY -- print key_t 0 as IPC_PRIVATE */
	prt_zga,	/* ZGA -- print zone_getattr attribute types */
	prt_atc,	/* ATC -- print AT_FDCWD or file descriptor */
	prt_lio,	/* LIO -- print LIO_XX flags */
	prt_dfl,	/* DFL -- print door_create() flags */
	prt_dpm,	/* DPM -- print DOOR_PARAM_XX flags */
	prt_tnd,	/* TND -- print trusted network data base opcode */
	prt_rsc,	/* RSC -- print rctlsys() subcodes */
	prt_rgf,	/* RGF -- print getrctl() flags */
	prt_rsf,	/* RSF -- print setrctl() flags */
	prt_rcf,	/* RCF -- print rctlsys_ctl() flags */
	prt_fxf,	/* FXF -- print forkx() flags */
	prt_spf,	/* SPF -- print rctlsys_projset() flags */
	prt_un1,	/* UN1 -- as prt_uns except for -1 */
	prt_mob,	/* MOB -- print mmapobj() flags */
	prt_snf,	/* SNF -- print AT_SYMLINK_[NO]FOLLOW flag */
	prt_skc,	/* SKC -- print sockconfig() subcode */
	prt_acf,	/* ACF -- print accept4 flags */
	prt_pfd,	/* PFD -- print pipe fds */
	prt_grf,	/* GRF -- print getrandom flags */
	prt_dec,	/* HID -- hidden argument, make this the last one */
};
