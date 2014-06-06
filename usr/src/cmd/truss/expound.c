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
 * Copyright 2012 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#define	_SYSCALL32

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <libproc.h>
#include <string.h>
#include <limits.h>
#include <sys/statfs.h>
#include <sys/times.h>
#include <sys/timex.h>
#include <sys/utssys.h>
#include <sys/utsname.h>
#include <sys/ipc.h>
#include <sys/ipc_impl.h>
#include <sys/msg.h>
#include <sys/msg_impl.h>
#include <sys/sem.h>
#include <sys/sem_impl.h>
#include <sys/shm.h>
#include <sys/shm_impl.h>
#include <sys/dirent.h>
#include <ustat.h>
#include <fcntl.h>
#include <time.h>
#include <sys/termios.h>
#include <sys/termiox.h>
#include <sys/termio.h>
#include <sys/ttold.h>
#include <sys/jioctl.h>
#include <sys/filio.h>
#include <stropts.h>
#include <poll.h>
#include <sys/uio.h>
#include <sys/resource.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/aio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <sys/byteorder.h>
#include <arpa/inet.h>
#include <sys/audioio.h>
#include <sys/cladm.h>
#include <sys/synch.h>
#include <sys/synch32.h>
#include <sys/sysmacros.h>
#include <sys/sendfile.h>
#include <priv.h>
#include <ucred.h>
#include <sys/ucred.h>
#include <sys/port_impl.h>
#include <sys/zone.h>
#include <sys/priv_impl.h>
#include <sys/priv.h>
#include <tsol/label.h>
#include <sys/nvpair.h>
#include <libnvpair.h>
#include <sys/rctl_impl.h>
#include <sys/socketvar.h>
#include <sys/fs/zfs.h>
#include <sys/zfs_ioctl.h>

#include "ramdata.h"
#include "systable.h"
#include "proto.h"

void	show_sigset(private_t *, long, const char *);
void	show_ioctl(private_t *, int, long);
void	show_zfs_ioc(private_t *, long);

static void
mk_ctime(char *str, size_t maxsize, time_t value)
{
	(void) strftime(str, maxsize, "%b %e %H:%M:%S %Z %Y",
	    localtime(&value));
}

void
prtime(private_t *pri, const char *name, time_t value)
{
	char str[80];

	mk_ctime(str, sizeof (str), value);
	(void) printf("%s\t%s%s  [ %lu ]\n",
	    pri->pname,
	    name,
	    str,
	    value);
}

void
prtimeval(private_t *pri, const char *name, struct timeval *value)
{
	char str[80];

	mk_ctime(str, sizeof (str), value->tv_sec);
	(void) printf("%s\t%s%s  [ %lu.%6.6lu ]\n",
	    pri->pname,
	    name,
	    str,
	    value->tv_sec,
	    value->tv_usec);
}

void
prtimestruc(private_t *pri, const char *name, timestruc_t *value)
{
	char str[80];

	mk_ctime(str, sizeof (str), value->tv_sec);
	(void) printf("%s\t%s%s  [ %lu.%9.9lu ]\n",
	    pri->pname,
	    name,
	    str,
	    value->tv_sec,
	    value->tv_nsec);
}

static void
show_utimens(private_t *pri, long offset)
{
	struct {
		timespec_t atime;
		timespec_t mtime;
	} utimbuf;

	if (offset == 0)
		return;

	if (data_model == PR_MODEL_NATIVE) {
		if (Pread(Proc, &utimbuf, sizeof (utimbuf), offset)
		    != sizeof (utimbuf))
			return;
	} else {
		struct {
			timespec32_t atime;
			timespec32_t mtime;
		} utimbuf32;

		if (Pread(Proc, &utimbuf32, sizeof (utimbuf32), offset)
		    != sizeof (utimbuf32))
			return;

		TIMESPEC32_TO_TIMESPEC(&utimbuf.atime, &utimbuf32.atime);
		TIMESPEC32_TO_TIMESPEC(&utimbuf.mtime, &utimbuf32.mtime);
	}

	/* print access and modification times */
	if (utimbuf.atime.tv_nsec == UTIME_OMIT)
		(void) printf("%s\tat = UTIME_OMIT\n", pri->pname);
	else if (utimbuf.atime.tv_nsec == UTIME_NOW)
		(void) printf("%s\tat = UTIME_NOW\n", pri->pname);
	else
		prtimestruc(pri, "at = ", &utimbuf.atime);
	if (utimbuf.mtime.tv_nsec == UTIME_OMIT)
		(void) printf("%s\tmt = UTIME_OMIT\n", pri->pname);
	else if (utimbuf.mtime.tv_nsec == UTIME_NOW)
		(void) printf("%s\tmt = UTIME_NOW\n", pri->pname);
	else
		prtimestruc(pri, "mt = ", &utimbuf.mtime);
}

void
show_timeofday(private_t *pri)
{
	struct timeval tod;
	long offset;

	if (pri->sys_nargs < 1 || (offset = pri->sys_args[0]) == NULL)
		return;

	if (data_model == PR_MODEL_NATIVE) {
		if (Pread(Proc, &tod, sizeof (tod), offset)
		    != sizeof (tod))
			return;
	} else {
		struct timeval32 tod32;

		if (Pread(Proc, &tod32, sizeof (tod32), offset)
		    != sizeof (tod32))
			return;

		TIMEVAL32_TO_TIMEVAL(&tod, &tod32);
	}

	prtimeval(pri, "time: ", &tod);
}

void
show_itimerval(private_t *pri, long offset, const char *name)
{
	struct itimerval itimerval;

	if (offset == 0)
		return;

	if (data_model == PR_MODEL_NATIVE) {
		if (Pread(Proc, &itimerval, sizeof (itimerval), offset)
		    != sizeof (itimerval))
			return;
	} else {
		struct itimerval32 itimerval32;

		if (Pread(Proc, &itimerval32, sizeof (itimerval32), offset)
		    != sizeof (itimerval32))
			return;

		ITIMERVAL32_TO_ITIMERVAL(&itimerval, &itimerval32);
	}

	(void) printf(
	    "%s\t%s:  interval: %4ld.%6.6ld sec  value: %4ld.%6.6ld sec\n",
	    pri->pname,
	    name,
	    itimerval.it_interval.tv_sec,
	    itimerval.it_interval.tv_usec,
	    itimerval.it_value.tv_sec,
	    itimerval.it_value.tv_usec);
}

void
show_timeval(private_t *pri, long offset, const char *name)
{
	struct timeval timeval;

	if (offset == 0)
		return;

	if (data_model == PR_MODEL_NATIVE) {
		if (Pread(Proc, &timeval, sizeof (timeval), offset)
		    != sizeof (timeval))
			return;
	} else {
		struct timeval32 timeval32;

		if (Pread(Proc, &timeval32, sizeof (timeval32), offset)
		    != sizeof (timeval32))
			return;

		TIMEVAL32_TO_TIMEVAL(&timeval, &timeval32);
	}

	(void) printf(
	    "%s\t%s: %ld.%6.6ld sec\n",
	    pri->pname,
	    name,
	    timeval.tv_sec,
	    timeval.tv_usec);
}

void
show_timestruc(private_t *pri, long offset, const char *name)
{
	timestruc_t timestruc;

	if (offset == 0)
		return;

	if (data_model == PR_MODEL_NATIVE) {
		if (Pread(Proc, &timestruc, sizeof (timestruc), offset)
		    != sizeof (timestruc))
			return;
	} else {
		timestruc32_t timestruc32;

		if (Pread(Proc, &timestruc32, sizeof (timestruc32), offset)
		    != sizeof (timestruc32))
			return;

		TIMESPEC32_TO_TIMESPEC(&timestruc, &timestruc32);
	}

	(void) printf(
	    "%s\t%s: %ld.%9.9ld sec\n",
	    pri->pname,
	    name,
	    timestruc.tv_sec,
	    timestruc.tv_nsec);
}

void
show_stime(private_t *pri)
{
	if (pri->sys_nargs >= 1) {
		/* print new system time */
		prtime(pri, "systime = ", (time_t)pri->sys_args[0]);
	}
}

void
show_times(private_t *pri)
{
	long hz = sysconf(_SC_CLK_TCK);
	long offset;
	struct tms tms;

	if (pri->sys_nargs < 1 || (offset = pri->sys_args[0]) == NULL)
		return;

	if (data_model == PR_MODEL_NATIVE) {
		if (Pread(Proc, &tms, sizeof (tms), offset)
		    != sizeof (tms))
			return;
	} else {
		struct tms32 tms32;

		if (Pread(Proc, &tms32, sizeof (tms32), offset)
		    != sizeof (tms32))
			return;

		/*
		 * This looks a bit odd (since the values are actually
		 * signed), but we need to suppress sign extension to
		 * preserve compatibility (we've always printed these
		 * numbers as unsigned quantities).
		 */
		tms.tms_utime = (unsigned)tms32.tms_utime;
		tms.tms_stime = (unsigned)tms32.tms_stime;
		tms.tms_cutime = (unsigned)tms32.tms_cutime;
		tms.tms_cstime = (unsigned)tms32.tms_cstime;
	}

	(void) printf(
	    "%s\tutim=%-6lu stim=%-6lu cutim=%-6lu cstim=%-6lu (HZ=%ld)\n",
	    pri->pname,
	    tms.tms_utime,
	    tms.tms_stime,
	    tms.tms_cutime,
	    tms.tms_cstime,
	    hz);
}

void
show_uname(private_t *pri, long offset)
{
	/*
	 * Old utsname buffer (no longer accessible in <sys/utsname.h>).
	 */
	struct {
		char	sysname[9];
		char	nodename[9];
		char	release[9];
		char	version[9];
		char	machine[9];
	} ubuf;

	if (offset != NULL &&
	    Pread(Proc, &ubuf, sizeof (ubuf), offset) == sizeof (ubuf)) {
		(void) printf(
		    "%s\tsys=%-9.9snod=%-9.9srel=%-9.9sver=%-9.9smch=%.9s\n",
		    pri->pname,
		    ubuf.sysname,
		    ubuf.nodename,
		    ubuf.release,
		    ubuf.version,
		    ubuf.machine);
	}
}

/* XX64 -- definition of 'struct ustat' is strange -- check out the defn */
void
show_ustat(private_t *pri, long offset)
{
	struct ustat ubuf;

	if (offset != NULL &&
	    Pread(Proc, &ubuf, sizeof (ubuf), offset) == sizeof (ubuf)) {
		(void) printf(
		    "%s\ttfree=%-6ld tinode=%-5lu fname=%-6.6s fpack=%-.6s\n",
		    pri->pname,
		    ubuf.f_tfree,
		    ubuf.f_tinode,
		    ubuf.f_fname,
		    ubuf.f_fpack);
	}
}

#ifdef _LP64
void
show_ustat32(private_t *pri, long offset)
{
	struct ustat32 ubuf;

	if (offset != NULL &&
	    Pread(Proc, &ubuf, sizeof (ubuf), offset) == sizeof (ubuf)) {
		(void) printf(
		    "%s\ttfree=%-6d tinode=%-5u fname=%-6.6s fpack=%-.6s\n",
		    pri->pname,
		    ubuf.f_tfree,
		    ubuf.f_tinode,
		    ubuf.f_fname,
		    ubuf.f_fpack);
	}
}
#endif	/* _LP64 */

void
show_fusers(private_t *pri, long offset, long nproc)
{
	f_user_t fubuf;
	int serial = (nproc > 4);

	if (offset == 0)
		return;

	/* enter region of lengthy output */
	if (serial)
		Eserialize();

	while (nproc > 0 &&
	    Pread(Proc, &fubuf, sizeof (fubuf), offset) == sizeof (fubuf)) {
		(void) printf("%s\tpid=%-5d uid=%-5u flags=%s\n",
		    pri->pname,
		    (int)fubuf.fu_pid,
		    fubuf.fu_uid,
		    fuflags(pri, fubuf.fu_flags));
		nproc--;
		offset += sizeof (fubuf);
	}

	/* exit region of lengthy output */
	if (serial)
		Xserialize();
}

void
show_utssys(private_t *pri, long r0)
{
	if (pri->sys_nargs >= 3) {
		switch (pri->sys_args[2]) {
		case UTS_UNAME:
			show_uname(pri, (long)pri->sys_args[0]);
			break;
		case UTS_USTAT:
			show_ustat(pri, (long)pri->sys_args[0]);
			break;
		case UTS_FUSERS:
			show_fusers(pri, (long)pri->sys_args[3], r0);
			break;
		}
	}
}

#ifdef _LP64
void
show_utssys32(private_t *pri, long r0)
{
	if (pri->sys_nargs >= 3) {
		switch (pri->sys_args[2]) {
		case UTS_UNAME:
			show_uname(pri, (long)pri->sys_args[0]);
			break;
		case UTS_USTAT:
			show_ustat32(pri, (long)pri->sys_args[0]);
			break;
		case UTS_FUSERS:
			show_fusers(pri, (long)pri->sys_args[3], r0);
			break;
		}
	}
}
#endif	/* _LP64 */

void
show_cladm(private_t *pri, int code, int function, long offset)
{
	int	arg;

	switch (code) {
	case CL_INITIALIZE:
		switch (function) {
		case CL_GET_BOOTFLAG:
			if (Pread(Proc, &arg, sizeof (arg), offset)
			    == sizeof (arg)) {
				if (arg & CLUSTER_CONFIGURED)
					(void) printf("%s\tbootflags="
					    "CLUSTER_CONFIGURED", pri->pname);
				if (arg & CLUSTER_BOOTED)
					(void) printf("|CLUSTER_BOOTED\n");
			}
			break;
		}
		break;
	case CL_CONFIG:
		switch (function) {
		case CL_NODEID:
		case CL_HIGHEST_NODEID:
			if (Pread(Proc, &arg, sizeof (arg), offset)
			    == sizeof (arg))
				(void) printf("%s\tnodeid=%d\n",
				    pri->pname, arg);
		}
		break;
	}
}

#define	ALL_LOCK_TYPES						\
	(USYNC_PROCESS | LOCK_ERRORCHECK | LOCK_RECURSIVE | 	\
	LOCK_PRIO_INHERIT | LOCK_PRIO_PROTECT | LOCK_ROBUST | 	\
	USYNC_PROCESS_ROBUST)

/* return cv and mutex types */
const char *
synch_type(private_t *pri, uint_t type)
{
	char *str = pri->code_buf;

	if (type & USYNC_PROCESS)
		(void) strcpy(str, "USYNC_PROCESS");
	else
		(void) strcpy(str, "USYNC_THREAD");

	if (type & LOCK_ERRORCHECK)
		(void) strcat(str, "|LOCK_ERRORCHECK");
	if (type & LOCK_RECURSIVE)
		(void) strcat(str, "|LOCK_RECURSIVE");
	if (type & LOCK_PRIO_INHERIT)
		(void) strcat(str, "|LOCK_PRIO_INHERIT");
	if (type & LOCK_PRIO_PROTECT)
		(void) strcat(str, "|LOCK_PRIO_PROTECT");
	if (type & LOCK_ROBUST)
		(void) strcat(str, "|LOCK_ROBUST");
	if (type & USYNC_PROCESS_ROBUST)
		(void) strcat(str, "|USYNC_PROCESS_ROBUST");

	if ((type &= ~ALL_LOCK_TYPES) != 0)
		(void) sprintf(str + strlen(str), "|0x%.4X", type);

	return ((const char *)str);
}

void
show_mutex(private_t *pri, long offset)
{
	lwp_mutex_t mutex;

	if (Pread(Proc, &mutex, sizeof (mutex), offset) == sizeof (mutex)) {
		(void) printf("%s\tmutex type: %s\n",
		    pri->pname,
		    synch_type(pri, mutex.mutex_type));
	}
}

void
show_condvar(private_t *pri, long offset)
{
	lwp_cond_t condvar;

	if (Pread(Proc, &condvar, sizeof (condvar), offset)
	    == sizeof (condvar)) {
		(void) printf("%s\tcondvar type: %s\n",
		    pri->pname,
		    synch_type(pri, condvar.cond_type));
	}
}

void
show_sema(private_t *pri, long offset)
{
	lwp_sema_t sema;

	if (Pread(Proc, &sema, sizeof (sema), offset) == sizeof (sema)) {
		(void) printf("%s\tsema type: %s  count = %u\n",
		    pri->pname,
		    synch_type(pri, sema.sema_type),
		    sema.sema_count);
	}
}

void
show_rwlock(private_t *pri, long offset)
{
	lwp_rwlock_t rwlock;

	if (Pread(Proc, &rwlock, sizeof (rwlock), offset) == sizeof (rwlock)) {
		(void) printf("%s\trwlock type: %s  readers = %d\n",
		    pri->pname,
		    synch_type(pri, rwlock.rwlock_type),
		    rwlock.rwlock_readers);
	}
}

/* represent character as itself ('c') or octal (012) */
char *
show_char(char *buf, int c)
{
	const char *fmt;

	if (c >= ' ' && c < 0177)
		fmt = "'%c'";
	else
		fmt = "%.3o";

	(void) sprintf(buf, fmt, c&0xff);
	return (buf);
}

void
show_termio(private_t *pri, long offset)
{
	struct termio termio;
	char cbuf[8];
	int i;

	if (Pread(Proc, &termio, sizeof (termio), offset) == sizeof (termio)) {
		(void) printf(
		"%s\tiflag=0%.6o oflag=0%.6o cflag=0%.6o lflag=0%.6o line=%d\n",
		    pri->pname,
		    termio.c_iflag,
		    termio.c_oflag,
		    termio.c_cflag,
		    termio.c_lflag,
		    termio.c_line);
		(void) printf("%s\t    cc: ", pri->pname);
		for (i = 0; i < NCC; i++)
			(void) printf(" %s",
			    show_char(cbuf, (int)termio.c_cc[i]));
		(void) fputc('\n', stdout);
	}
}

void
show_termios(private_t *pri, long offset)
{
	struct termios termios;
	char cbuf[8];
	int i;

	if (Pread(Proc, &termios, sizeof (termios), offset)
	    == sizeof (termios)) {
		(void) printf(
		    "%s\tiflag=0%.6o oflag=0%.6o cflag=0%.6o lflag=0%.6o\n",
		    pri->pname,
		    termios.c_iflag,
		    termios.c_oflag,
		    termios.c_cflag,
		    termios.c_lflag);
		(void) printf("%s\t    cc: ", pri->pname);
		for (i = 0; i < NCCS; i++) {
			if (i == NCC)	/* show new chars on new line */
				(void) printf("\n%s\t\t", pri->pname);
			(void) printf(" %s",
			    show_char(cbuf, (int)termios.c_cc[i]));
		}
		(void) fputc('\n', stdout);
	}
}

void
show_termiox(private_t *pri, long offset)
{
	struct termiox termiox;
	int i;

	if (Pread(Proc, &termiox, sizeof (termiox), offset)
	    == sizeof (termiox)) {
		(void) printf("%s\thflag=0%.3o cflag=0%.3o rflag=0%.3o",
		    pri->pname,
		    termiox.x_hflag,
		    termiox.x_cflag,
		    termiox.x_rflag[0]);
		for (i = 1; i < NFF; i++)
			(void) printf(",0%.3o", termiox.x_rflag[i]);
		(void) printf(" sflag=0%.3o\n",
		    termiox.x_sflag);
	}
}

void
show_sgttyb(private_t *pri, long offset)
{
	struct sgttyb sgttyb;

	if (Pread(Proc, &sgttyb, sizeof (sgttyb), offset) == sizeof (sgttyb)) {
		char erase[8];
		char kill[8];

		(void) printf(
		"%s\tispeed=%-2d ospeed=%-2d erase=%s kill=%s flags=0x%.8x\n",
		    pri->pname,
		    sgttyb.sg_ispeed&0xff,
		    sgttyb.sg_ospeed&0xff,
		    show_char(erase, sgttyb.sg_erase),
		    show_char(kill, sgttyb.sg_kill),
		    sgttyb.sg_flags);
	}
}

void
show_ltchars(private_t *pri, long offset)
{
	struct ltchars ltchars;
	char *p;
	char cbuf[8];
	int i;

	if (Pread(Proc, &ltchars, sizeof (ltchars), offset)
	    == sizeof (ltchars)) {
		(void) printf("%s\t    cc: ", pri->pname);
		for (p = (char *)&ltchars, i = 0; i < sizeof (ltchars); i++)
			(void) printf(" %s", show_char(cbuf, (int)*p++));
		(void) fputc('\n', stdout);
	}
}

void
show_tchars(private_t *pri, long offset)
{
	struct tchars tchars;
	char *p;
	char cbuf[8];
	int i;

	if (Pread(Proc, &tchars, sizeof (tchars), offset) == sizeof (tchars)) {
		(void) printf("%s\t    cc: ", pri->pname);
		for (p = (char *)&tchars, i = 0; i < sizeof (tchars); i++)
			(void) printf(" %s", show_char(cbuf, (int)*p++));
		(void) fputc('\n', stdout);
	}
}

void
show_termcb(private_t *pri, long offset)
{
	struct termcb termcb;

	if (Pread(Proc, &termcb, sizeof (termcb), offset) == sizeof (termcb)) {
		(void) printf(
		    "%s\tflgs=0%.2o termt=%d crow=%d ccol=%d vrow=%d lrow=%d\n",
		    pri->pname,
		    termcb.st_flgs&0xff,
		    termcb.st_termt&0xff,
		    termcb.st_crow&0xff,
		    termcb.st_ccol&0xff,
		    termcb.st_vrow&0xff,
		    termcb.st_lrow&0xff);
	}
}

/* integer value pointed to by ioctl() arg */
void
show_strint(private_t *pri, int code, long offset)
{
	int val;

	if (Pread(Proc, &val, sizeof (val), offset) == sizeof (val)) {
		const char *s = NULL;

		switch (code) {		/* interpret these symbolically */
		case I_GRDOPT:
			s = strrdopt(val);
			break;
		case I_GETSIG:
			s = strevents(pri, val);
			break;
		case TIOCFLUSH:
			s = tiocflush(pri, val);
			break;
		}

		if (s == NULL)
			(void) printf("%s\t0x%.8lX: %d\n",
			    pri->pname, offset, val);
		else
			(void) printf("%s\t0x%.8lX: %s\n",
			    pri->pname, offset, s);
	}
}

void
show_strioctl(private_t *pri, long offset)
{
	struct strioctl strioctl;

	if (Pread(Proc, &strioctl, sizeof (strioctl), offset) ==
	    sizeof (strioctl)) {
		(void) printf(
		    "%s\tcmd=%s timout=%d len=%d dp=0x%.8lX\n",
		    pri->pname,
		    ioctlname(pri, strioctl.ic_cmd),
		    strioctl.ic_timout,
		    strioctl.ic_len,
		    (long)strioctl.ic_dp);

		if (pri->recur++ == 0)	/* avoid indefinite recursion */
			show_ioctl(pri, strioctl.ic_cmd,
			    (long)strioctl.ic_dp);
		--pri->recur;
	}
}

#ifdef _LP64
void
show_strioctl32(private_t *pri, long offset)
{
	struct strioctl32 strioctl;

	if (Pread(Proc, &strioctl, sizeof (strioctl), offset) ==
	    sizeof (strioctl)) {
		(void) printf(
		    "%s\tcmd=%s timout=%d len=%d dp=0x%.8lX\n",
		    pri->pname,
		    ioctlname(pri, strioctl.ic_cmd),
		    strioctl.ic_timout,
		    strioctl.ic_len,
		    (long)strioctl.ic_dp);

		if (pri->recur++ == 0)	/* avoid indefinite recursion */
			show_ioctl(pri, strioctl.ic_cmd,
			    (long)strioctl.ic_dp);
		--pri->recur;
	}
}
#endif	/* _LP64 */

void
print_strbuf(private_t *pri, struct strbuf *sp, const char *name, int dump)
{
	(void) printf(
	    "%s\t%s:  maxlen=%-4d len=%-4d buf=0x%.8lX",
	    pri->pname,
	    name,
	    sp->maxlen,
	    sp->len,
	    (long)sp->buf);
	/*
	 * Should we show the buffer contents?
	 * Keyed to the '-r fds' and '-w fds' options?
	 */
	if (sp->buf == NULL || sp->len <= 0)
		(void) fputc('\n', stdout);
	else {
		int nb = (sp->len > 8)? 8 : sp->len;
		char buffer[8];
		char obuf[40];

		if (Pread(Proc, buffer, (size_t)nb, (long)sp->buf) == nb) {
			(void) strcpy(obuf, ": \"");
			showbytes(buffer, nb, obuf+3);
			(void) strcat(obuf,
			    (nb == sp->len)?
			    (const char *)"\"" : (const char *)"\"..");
			(void) fputs(obuf, stdout);
		}
		(void) fputc('\n', stdout);
		if (dump && sp->len > 8)
			showbuffer(pri, (long)sp->buf, (long)sp->len);
	}
}

#ifdef _LP64
void
print_strbuf32(private_t *pri, struct strbuf32 *sp, const char *name, int dump)
{
	(void) printf(
	    "%s\t%s:  maxlen=%-4d len=%-4d buf=0x%.8lX",
	    pri->pname,
	    name,
	    sp->maxlen,
	    sp->len,
	    (long)sp->buf);
	/*
	 * Should we show the buffer contents?
	 * Keyed to the '-r fds' and '-w fds' options?
	 */
	if (sp->buf == NULL || sp->len <= 0)
		(void) fputc('\n', stdout);
	else {
		int nb = (sp->len > 8)? 8 : sp->len;
		char buffer[8];
		char obuf[40];

		if (Pread(Proc, buffer, (size_t)nb, (long)sp->buf) == nb) {
			(void) strcpy(obuf, ": \"");
			showbytes(buffer, nb, obuf+3);
			(void) strcat(obuf,
			    (nb == sp->len)?
			    (const char *)"\"" : (const char *)"\"..");
			(void) fputs(obuf, stdout);
		}
		(void) fputc('\n', stdout);
		if (dump && sp->len > 8)
			showbuffer(pri, (long)sp->buf, (long)sp->len);
	}
}
#endif	/* _LP64 */

/* strpeek and strfdinsert flags word */
const char *
strflags(private_t *pri, int flags)
{
	const char *s;

	switch (flags) {
	case 0:
		s = "0";
		break;
	case RS_HIPRI:
		s = "RS_HIPRI";
		break;
	default:
		(void) sprintf(pri->code_buf, "0x%.4X", flags);
		s = pri->code_buf;
	}

	return (s);
}

void
show_strpeek(private_t *pri, long offset)
{
	struct strpeek strpeek;

	if (Pread(Proc, &strpeek, sizeof (strpeek), offset)
	    == sizeof (strpeek)) {

		print_strbuf(pri, &strpeek.ctlbuf, "ctl", FALSE);
		print_strbuf(pri, &strpeek.databuf, "dat", FALSE);

		(void) printf("%s\tflags=%s\n",
		    pri->pname,
		    strflags(pri, strpeek.flags));
	}
}

#ifdef _LP64
void
show_strpeek32(private_t *pri, long offset)
{
	struct strpeek32 strpeek;

	if (Pread(Proc, &strpeek, sizeof (strpeek), offset)
	    == sizeof (strpeek)) {

		print_strbuf32(pri, &strpeek.ctlbuf, "ctl", FALSE);
		print_strbuf32(pri, &strpeek.databuf, "dat", FALSE);

		(void) printf("%s\tflags=%s\n",
		    pri->pname,
		    strflags(pri, strpeek.flags));
	}
}
#endif	/* _LP64 */

void
show_strfdinsert(private_t *pri, long offset)
{
	struct strfdinsert strfdinsert;

	if (Pread(Proc, &strfdinsert, sizeof (strfdinsert), offset) ==
	    sizeof (strfdinsert)) {

		print_strbuf(pri, &strfdinsert.ctlbuf, "ctl", FALSE);
		print_strbuf(pri, &strfdinsert.databuf, "dat", FALSE);

		(void) printf("%s\tflags=%s fildes=%d offset=%d\n",
		    pri->pname,
		    strflags(pri, strfdinsert.flags),
		    strfdinsert.fildes,
		    strfdinsert.offset);
	}
}

#ifdef _LP64
void
show_strfdinsert32(private_t *pri, long offset)
{
	struct strfdinsert32 strfdinsert;

	if (Pread(Proc, &strfdinsert, sizeof (strfdinsert), offset) ==
	    sizeof (strfdinsert)) {

		print_strbuf32(pri, &strfdinsert.ctlbuf, "ctl", FALSE);
		print_strbuf32(pri, &strfdinsert.databuf, "dat", FALSE);

		(void) printf("%s\tflags=%s fildes=%d offset=%d\n",
		    pri->pname,
		    strflags(pri, strfdinsert.flags),
		    strfdinsert.fildes,
		    strfdinsert.offset);
	}
}
#endif	/* _LP64 */

void
show_strrecvfd(private_t *pri, long offset)
{
	struct strrecvfd strrecvfd;

	if (Pread(Proc, &strrecvfd, sizeof (strrecvfd), offset) ==
	    sizeof (strrecvfd)) {
		(void) printf(
		    "%s\tfd=%-5d uid=%-5u gid=%u\n",
		    pri->pname,
		    strrecvfd.fd,
		    strrecvfd.uid,
		    strrecvfd.gid);
	}
}

void
show_strlist(private_t *pri, long offset)
{
	struct str_list strlist;
	struct str_mlist list;
	int count;

	if (Pread(Proc, &strlist, sizeof (strlist), offset) ==
	    sizeof (strlist)) {
		(void) printf("%s\tnmods=%d  modlist=0x%.8lX\n",
		    pri->pname,
		    strlist.sl_nmods,
		    (long)strlist.sl_modlist);

		count = strlist.sl_nmods;
		offset = (long)strlist.sl_modlist;
		while (!interrupt && --count >= 0) {
			if (Pread(Proc, &list, sizeof (list), offset) !=
			    sizeof (list))
				break;
			(void) printf("%s\t\t\"%.*s\"\n",
			    pri->pname,
			    (int)sizeof (list.l_name),
			    list.l_name);
			offset += sizeof (struct str_mlist);
		}
	}
}

#ifdef _LP64
void
show_strlist32(private_t *pri, long offset)
{
	struct str_list32 strlist;
	struct str_mlist list;
	int count;

	if (Pread(Proc, &strlist, sizeof (strlist), offset) ==
	    sizeof (strlist)) {
		(void) printf("%s\tnmods=%d  modlist=0x%.8lX\n",
		    pri->pname,
		    strlist.sl_nmods,
		    (long)strlist.sl_modlist);

		count = strlist.sl_nmods;
		offset = (long)strlist.sl_modlist;
		while (!interrupt && --count >= 0) {
			if (Pread(Proc, &list, sizeof (list), offset) !=
			    sizeof (list))
				break;
			(void) printf("%s\t\t\"%.*s\"\n",
			    pri->pname,
			    (int)sizeof (list.l_name),
			    list.l_name);
			offset += sizeof (struct str_mlist);
		}
	}
}
#endif	/* _LP64 */

void
show_jwinsize(private_t *pri, long offset)
{
	struct jwinsize jwinsize;

	if (Pread(Proc, &jwinsize, sizeof (jwinsize), offset) ==
	    sizeof (jwinsize)) {
		(void) printf(
		    "%s\tbytesx=%-3u bytesy=%-3u bitsx=%-3u bitsy=%-3u\n",
		    pri->pname,
		    (unsigned)jwinsize.bytesx,
		    (unsigned)jwinsize.bytesy,
		    (unsigned)jwinsize.bitsx,
		    (unsigned)jwinsize.bitsy);
	}
}

void
show_winsize(private_t *pri, long offset)
{
	struct winsize winsize;

	if (Pread(Proc, &winsize, sizeof (winsize), offset)
	    == sizeof (winsize)) {
		(void) printf(
		    "%s\trow=%-3d col=%-3d xpixel=%-3d ypixel=%-3d\n",
		    pri->pname,
		    winsize.ws_row,
		    winsize.ws_col,
		    winsize.ws_xpixel,
		    winsize.ws_ypixel);
	}
}

struct audio_stuff {
	uint_t	bit;
	const char *str;
};

const struct audio_stuff audio_output_ports[] = {
	{ AUDIO_SPEAKER, "SPEAKER" },
	{ AUDIO_HEADPHONE, "HEADPHONE" },
	{ AUDIO_LINE_OUT, "LINE_OUT" },
	{ AUDIO_SPDIF_OUT, "SPDIF_OUT" },
	{ AUDIO_AUX1_OUT, "AUX1_OUT" },
	{ AUDIO_AUX2_OUT, "AUX2_OUT" },
	{ 0, NULL }
};

const struct audio_stuff audio_input_ports[] = {
	{ AUDIO_MICROPHONE, "MICROPHONE" },
	{ AUDIO_LINE_IN, "LINE_IN" },
	{ AUDIO_CD, "CD" },
	{ AUDIO_SPDIF_IN, "SPDIF_IN" },
	{ AUDIO_AUX1_IN, "AUX1_IN" },
	{ AUDIO_AUX2_IN, "AUX2_IN" },
	{ AUDIO_CODEC_LOOPB_IN, "CODEC_LOOPB_IN" },
	{ AUDIO_SUNVTS, "SUNVTS" },
	{ 0, NULL }
};

static const struct audio_stuff audio_hw_features[] = {
	{ AUDIO_HWFEATURE_DUPLEX, "DUPLEX" },
	{ AUDIO_HWFEATURE_MSCODEC, "MSCODEC" },
	{ AUDIO_HWFEATURE_IN2OUT, "IN2OUT" },
	{ AUDIO_HWFEATURE_PLAY, "PLAY" },
	{ AUDIO_HWFEATURE_RECORD, "RECORD" },
	{ 0, NULL }
};

static const struct audio_stuff audio_sw_features[] = {
	{ AUDIO_SWFEATURE_MIXER, "MIXER" },
	{ 0, NULL }
};

void
show_audio_features(const private_t *pri,
	const struct audio_stuff *audio_porttab, uint_t features,
	const char *name)
{
	(void) printf("%s\t%s=", pri->pname, name);
	if (features == 0) {
		(void) printf("0\n");
		return;
	}

	for (; audio_porttab->bit != 0; ++audio_porttab) {
		if (features & audio_porttab->bit) {
			(void) printf(audio_porttab->str);
			features &= ~audio_porttab->bit;
			if (features)
				(void) putchar('|');
		}
	}
	if (features)
		(void) printf("0x%x", features);
	(void) putchar('\n');
}

void
show_audio_ports(private_t *pri, const char *mode,
	const char *field, uint_t ports)
{
	const struct audio_stuff *audio_porttab;

	(void) printf("%s\t%s\t%s=", pri->pname, mode, field);
	if (ports == 0) {
		(void) printf("0\n");
		return;
	}
	if (*mode == 'p')
		audio_porttab = audio_output_ports;
	else
		audio_porttab = audio_input_ports;
	for (; audio_porttab->bit != 0; ++audio_porttab) {
		if (ports & audio_porttab->bit) {
			(void) printf(audio_porttab->str);
			ports &= ~audio_porttab->bit;
			if (ports)
				(void) putchar('|');
		}
	}
	if (ports)
		(void) printf("0x%x", ports);
	(void) putchar('\n');
}

void
show_audio_prinfo(private_t *pri, const char *mode, struct audio_prinfo *au_pr)
{
	const char *s;

	/*
	 * The following values describe the audio data encoding.
	 */

	(void) printf("%s\t%s\tsample_rate=%u channels=%u precision=%u\n",
	    pri->pname, mode,
	    au_pr->sample_rate,
	    au_pr->channels,
	    au_pr->precision);

	s = NULL;
	switch (au_pr->encoding) {
	case AUDIO_ENCODING_NONE:	s = "NONE";	break;
	case AUDIO_ENCODING_ULAW:	s = "ULAW";	break;
	case AUDIO_ENCODING_ALAW:	s = "ALAW";	break;
	case AUDIO_ENCODING_LINEAR:	s = "LINEAR";	break;
	case AUDIO_ENCODING_DVI:	s = "DVI";	break;
	case AUDIO_ENCODING_LINEAR8:	s = "LINEAR8";	break;
	}
	if (s)
		(void) printf("%s\t%s\tencoding=%s\n", pri->pname, mode, s);
	else {
		(void) printf("%s\t%s\tencoding=%u\n",
		    pri->pname, mode, au_pr->encoding);
	}

	/*
	 * The following values control audio device configuration
	 */

	(void) printf(
	    "%s\t%s\tgain=%u buffer_size=%u\n",
	    pri->pname, mode,
	    au_pr->gain,
	    au_pr->buffer_size);
	show_audio_ports(pri, mode, "port", au_pr->port);
	show_audio_ports(pri, mode, "avail_ports", au_pr->avail_ports);
	show_audio_ports(pri, mode, "mod_ports", au_pr->mod_ports);

	/*
	 * The following values describe driver state
	 */

	(void) printf("%s\t%s\tsamples=%u eof=%u pause=%u error=%u\n",
	    pri->pname, mode,
	    au_pr->samples,
	    au_pr->eof,
	    au_pr->pause,
	    au_pr->error);
	(void) printf("%s\t%s\twaiting=%u balance=%u minordev=%u\n",
	    pri->pname, mode,
	    au_pr->waiting,
	    au_pr->balance,
	    au_pr->minordev);

	/*
	 * The following values are read-only state flags
	 */
	(void) printf("%s\t%s\topen=%u active=%u\n",
	    pri->pname, mode,
	    au_pr->open,
	    au_pr->active);
}

void
show_audio_info(private_t *pri, long offset)
{
	struct audio_info au;

	if (Pread(Proc, &au, sizeof (au), offset) == sizeof (au)) {
		show_audio_prinfo(pri, "play", &au.play);
		show_audio_prinfo(pri, "record", &au.record);
		(void) printf("%s\tmonitor_gain=%u output_muted=%u\n",
		    pri->pname, au.monitor_gain, au.output_muted);
		show_audio_features(pri, audio_hw_features, au.hw_features,
		    "hw_features");
		show_audio_features(pri, audio_sw_features, au.sw_features,
		    "sw_features");
		show_audio_features(pri, audio_sw_features,
		    au.sw_features_enabled, "sw_features_enabled");
	}
}

void
show_ioctl(private_t *pri, int code, long offset)
{
	int lp64 = (data_model == PR_MODEL_LP64);
	int err = pri->Errno;	/* don't display output parameters */
				/* for a failed system call */
#ifndef _LP64
	if (lp64)
		return;
#endif
	if (offset == 0)
		return;

	switch (code) {
	case TCGETA:
		if (err)
			break;
		/*FALLTHROUGH*/
	case TCSETA:
	case TCSETAW:
	case TCSETAF:
		show_termio(pri, offset);
		break;
	case TCGETS:
		if (err)
			break;
		/*FALLTHROUGH*/
	case TCSETS:
	case TCSETSW:
	case TCSETSF:
		show_termios(pri, offset);
		break;
	case TCGETX:
		if (err)
			break;
		/*FALLTHROUGH*/
	case TCSETX:
	case TCSETXW:
	case TCSETXF:
		show_termiox(pri, offset);
		break;
	case TIOCGETP:
		if (err)
			break;
		/*FALLTHROUGH*/
	case TIOCSETN:
	case TIOCSETP:
		show_sgttyb(pri, offset);
		break;
	case TIOCGLTC:
		if (err)
			break;
		/*FALLTHROUGH*/
	case TIOCSLTC:
		show_ltchars(pri, offset);
		break;
	case TIOCGETC:
		if (err)
			break;
		/*FALLTHROUGH*/
	case TIOCSETC:
		show_tchars(pri, offset);
		break;
	case LDGETT:
		if (err)
			break;
		/*FALLTHROUGH*/
	case LDSETT:
		show_termcb(pri, offset);
		break;
	/* streams ioctl()s */
#if 0
		/* these are displayed as strings in the arg list */
		/* by prt_ioa().  don't display them again here */
	case I_PUSH:
	case I_LOOK:
	case I_FIND:
		/* these are displayed as decimal in the arg list */
		/* by prt_ioa().  don't display them again here */
	case I_LINK:
	case I_UNLINK:
	case I_SENDFD:
		/* these are displayed symbolically in the arg list */
		/* by prt_ioa().  don't display them again here */
	case I_SRDOPT:
	case I_SETSIG:
	case I_FLUSH:
		break;
		/* this one just ignores the argument */
	case I_POP:
		break;
#endif
		/* these return something in an int pointed to by arg */
	case I_NREAD:
	case I_GRDOPT:
	case I_GETSIG:
	case TIOCGSID:
	case TIOCGPGRP:
	case TIOCLGET:
	case FIONREAD:
	case FIORDCHK:
		if (err)
			break;
		/*FALLTHROUGH*/
		/* these pass something in an int pointed to by arg */
	case TIOCSPGRP:
	case TIOCFLUSH:
	case TIOCLBIS:
	case TIOCLBIC:
	case TIOCLSET:
		show_strint(pri, code, offset);
		break;
		/* these all point to structures */
	case I_STR:
#ifdef _LP64
		if (lp64)
			show_strioctl(pri, offset);
		else
			show_strioctl32(pri, offset);
#else
		show_strioctl(pri, offset);
#endif
		break;
	case I_PEEK:
#ifdef _LP64
		if (lp64)
			show_strpeek(pri, offset);
		else
			show_strpeek32(pri, offset);
#else
		show_strpeek(pri, offset);
#endif
		break;
	case I_FDINSERT:
#ifdef _LP64
		if (lp64)
			show_strfdinsert(pri, offset);
		else
			show_strfdinsert32(pri, offset);
#else
		show_strfdinsert(pri, offset);
#endif
		break;
	case I_RECVFD:
		if (err)
			break;
		show_strrecvfd(pri, offset);
		break;
	case I_LIST:
		if (err)
			break;
#ifdef _LP64
		if (lp64)
			show_strlist(pri, offset);
		else
			show_strlist32(pri, offset);
#else
		show_strlist(pri, offset);
#endif
		break;
	case JWINSIZE:
		if (err)
			break;
		show_jwinsize(pri, offset);
		break;
	case TIOCGWINSZ:
		if (err)
			break;
		/*FALLTHROUGH*/
	case TIOCSWINSZ:
		show_winsize(pri, offset);
		break;
	case AUDIO_GETINFO:
	case (int)AUDIO_SETINFO:
		show_audio_info(pri, offset);
		break;

	default:
		if ((code & ~0xff) == ZFS_IOC) {
			show_zfs_ioc(pri, offset);
			break;
		}

		if (code & IOC_INOUT) {
			const char *str = ioctldatastruct(code);

			(void) printf("\t\t%s",
			    (code & IOC_INOUT) == IOC_INOUT ? "write/read" :
			    code & IOC_IN ? "write" : "read");
			if (str != NULL) {
				(void) printf(" (struct %s)\n", str);
			} else {
				(void) printf(" %d bytes\n",
				    (code >> 16) & IOCPARM_MASK);
			}
		}
	}
}

void
show_statvfs(private_t *pri)
{
	long offset;
	struct statvfs statvfs;
	char *cp;

	if (pri->sys_nargs > 1 && (offset = pri->sys_args[1]) != NULL &&
	    Pread(Proc, &statvfs, sizeof (statvfs), offset)
	    == sizeof (statvfs)) {
		(void) printf(
		"%s\tbsize=%-10lu frsize=%-9lu blocks=%-8llu bfree=%-9llu\n",
		    pri->pname,
		    statvfs.f_bsize,
		    statvfs.f_frsize,
		    (u_longlong_t)statvfs.f_blocks,
		    (u_longlong_t)statvfs.f_bfree);
		(void) printf(
		"%s\tbavail=%-9llu files=%-10llu ffree=%-9llu favail=%-9llu\n",
		    pri->pname,
		    (u_longlong_t)statvfs.f_bavail,
		    (u_longlong_t)statvfs.f_files,
		    (u_longlong_t)statvfs.f_ffree,
		    (u_longlong_t)statvfs.f_favail);
		(void) printf(
		    "%s\tfsid=0x%-9.4lX basetype=%-7.16s namemax=%ld\n",
		    pri->pname,
		    statvfs.f_fsid,
		    statvfs.f_basetype,
		    (long)statvfs.f_namemax);
		(void) printf(
		    "%s\tflag=%s\n",
		    pri->pname,
		    svfsflags(pri, (ulong_t)statvfs.f_flag));
		cp = statvfs.f_fstr + strlen(statvfs.f_fstr);
		if (cp < statvfs.f_fstr + sizeof (statvfs.f_fstr) - 1 &&
		    *(cp+1) != '\0')
			*cp = ' ';
		(void) printf("%s\tfstr=\"%.*s\"\n",
		    pri->pname,
		    (int)sizeof (statvfs.f_fstr),
		    statvfs.f_fstr);
	}
}

#ifdef _LP64
void
show_statvfs32(private_t *pri)
{
	long offset;
	struct statvfs32 statvfs;
	char *cp;

	if (pri->sys_nargs > 1 && (offset = pri->sys_args[1]) != NULL &&
	    Pread(Proc, &statvfs, sizeof (statvfs), offset)
	    == sizeof (statvfs)) {
		(void) printf(
		    "%s\tbsize=%-10u frsize=%-9u blocks=%-8u bfree=%-9u\n",
		    pri->pname,
		    statvfs.f_bsize,
		    statvfs.f_frsize,
		    statvfs.f_blocks,
		    statvfs.f_bfree);
		(void) printf(
		    "%s\tbavail=%-9u files=%-10u ffree=%-9u favail=%-9u\n",
		    pri->pname,
		    statvfs.f_bavail,
		    statvfs.f_files,
		    statvfs.f_ffree,
		    statvfs.f_favail);
		(void) printf(
		    "%s\tfsid=0x%-9.4X basetype=%-7.16s namemax=%d\n",
		    pri->pname,
		    statvfs.f_fsid,
		    statvfs.f_basetype,
		    (int)statvfs.f_namemax);
		(void) printf(
		    "%s\tflag=%s\n",
		    pri->pname,
		    svfsflags(pri, (ulong_t)statvfs.f_flag));
		cp = statvfs.f_fstr + strlen(statvfs.f_fstr);
		if (cp < statvfs.f_fstr + sizeof (statvfs.f_fstr) - 1 &&
		    *(cp+1) != '\0')
			*cp = ' ';
		(void) printf("%s\tfstr=\"%.*s\"\n",
		    pri->pname,
		    (int)sizeof (statvfs.f_fstr),
		    statvfs.f_fstr);
	}
}
#endif	/* _LP64 */

void
show_statvfs64(private_t *pri)
{
	long offset;
	struct statvfs64_32 statvfs;
	char *cp;

	if (pri->sys_nargs > 1 && (offset = pri->sys_args[1]) != NULL &&
	    Pread(Proc, &statvfs, sizeof (statvfs), offset)
	    == sizeof (statvfs)) {
		(void) printf(
		    "%s\tbsize=%-10u frsize=%-9u blocks=%-8llu bfree=%-9llu\n",
		    pri->pname,
		    statvfs.f_bsize,
		    statvfs.f_frsize,
		    (u_longlong_t)statvfs.f_blocks,
		    (u_longlong_t)statvfs.f_bfree);
		(void) printf(
		"%s\tbavail=%-9llu files=%-10llu ffree=%-9llu favail=%-9llu\n",
		    pri->pname,
		    (u_longlong_t)statvfs.f_bavail,
		    (u_longlong_t)statvfs.f_files,
		    (u_longlong_t)statvfs.f_ffree,
		    (u_longlong_t)statvfs.f_favail);
		(void) printf(
		    "%s\tfsid=0x%-9.4X basetype=%-7.16s namemax=%d\n",
		    pri->pname,
		    statvfs.f_fsid,
		    statvfs.f_basetype,
		    (int)statvfs.f_namemax);
		(void) printf(
		    "%s\tflag=%s\n",
		    pri->pname,
		    svfsflags(pri, (ulong_t)statvfs.f_flag));
		cp = statvfs.f_fstr + strlen(statvfs.f_fstr);
		if (cp < statvfs.f_fstr + sizeof (statvfs.f_fstr) - 1 &&
		    *(cp+1) != '\0')
			*cp = ' ';
		(void) printf("%s\tfstr=\"%.*s\"\n",
		    pri->pname,
		    (int)sizeof (statvfs.f_fstr),
		    statvfs.f_fstr);
	}
}

void
show_statfs(private_t *pri)
{
	long offset;
	struct statfs statfs;

	if (pri->sys_nargs >= 2 && (offset = pri->sys_args[1]) != NULL &&
	    Pread(Proc, &statfs, sizeof (statfs), offset) == sizeof (statfs)) {
		(void) printf(
		"%s\tfty=%d bsz=%ld fsz=%ld blk=%ld bfr=%ld fil=%lu ffr=%lu\n",
		    pri->pname,
		    statfs.f_fstyp,
		    statfs.f_bsize,
		    statfs.f_frsize,
		    statfs.f_blocks,
		    statfs.f_bfree,
		    statfs.f_files,
		    statfs.f_ffree);
		(void) printf("%s\t    fname=%.6s fpack=%.6s\n",
		    pri->pname,
		    statfs.f_fname,
		    statfs.f_fpack);
	}
}

#ifdef _LP64
void
show_statfs32(private_t *pri)
{
	long offset;
	struct statfs32 statfs;

	if (pri->sys_nargs >= 2 && (offset = pri->sys_args[1]) != NULL &&
	    Pread(Proc, &statfs, sizeof (statfs), offset) == sizeof (statfs)) {
		(void) printf(
		    "%s\tfty=%d bsz=%d fsz=%d blk=%d bfr=%d fil=%u ffr=%u\n",
		    pri->pname,
		    statfs.f_fstyp,
		    statfs.f_bsize,
		    statfs.f_frsize,
		    statfs.f_blocks,
		    statfs.f_bfree,
		    statfs.f_files,
		    statfs.f_ffree);
		(void) printf("%s\t    fname=%.6s fpack=%.6s\n",
		    pri->pname,
		    statfs.f_fname,
		    statfs.f_fpack);
	}
}
#endif	/* _LP64 */

void
show_flock32(private_t *pri, long offset)
{
	struct flock32 flock;

	if (Pread(Proc, &flock, sizeof (flock), offset) == sizeof (flock)) {
		const char *str = NULL;

		(void) printf("%s\ttyp=", pri->pname);

		switch (flock.l_type) {
		case F_RDLCK:
			str = "F_RDLCK";
			break;
		case F_WRLCK:
			str = "F_WRLCK";
			break;
		case F_UNLCK:
			str = "F_UNLCK";
			break;
		}
		if (str != NULL)
			(void) printf("%s", str);
		else
			(void) printf("%-7d", flock.l_type);

		str = whencearg(flock.l_whence);
		if (str != NULL)
			(void) printf("  whence=%s", str);
		else
			(void) printf("  whence=%-8u", flock.l_whence);

		(void) printf(
		    " start=%-5d len=%-5d sys=%-2u pid=%d\n",
		    flock.l_start,
		    flock.l_len,
		    flock.l_sysid,
		    flock.l_pid);
	}
}

void
show_flock64(private_t *pri, long offset)
{
	struct flock64 flock;

	if (Pread(Proc, &flock, sizeof (flock), offset) == sizeof (flock)) {
		const char *str = NULL;

		(void) printf("%s\ttyp=", pri->pname);

		switch (flock.l_type) {
		case F_RDLCK:
			str = "F_RDLCK";
			break;
		case F_WRLCK:
			str = "F_WRLCK";
			break;
		case F_UNLCK:
			str = "F_UNLCK";
			break;
		}
		if (str != NULL)
			(void) printf("%s", str);
		else
			(void) printf("%-7d", flock.l_type);

		str = whencearg(flock.l_whence);
		if (str != NULL)
			(void) printf("  whence=%s", str);
		else
			(void) printf("  whence=%-8u", flock.l_whence);

		(void) printf(
		    " start=%-5lld len=%-5lld sys=%-2u pid=%d\n",
		    (long long)flock.l_start,
		    (long long)flock.l_len,
		    flock.l_sysid,
		    (int)flock.l_pid);
	}
}

void
show_share(private_t *pri, long offset)
{
	struct fshare fshare;

	if (Pread(Proc, &fshare, sizeof (fshare), offset) == sizeof (fshare)) {
		const char *str = NULL;
		int manddny = 0;

		(void) printf("%s\taccess=", pri->pname);

		switch (fshare.f_access) {
		case F_RDACC:
			str = "F_RDACC";
			break;
		case F_WRACC:
			str = "F_WRACC";
			break;
		case F_RWACC:
			str = "F_RWACC";
			break;
		}
		if (str != NULL)
			(void) printf("%s", str);
		else
			(void) printf("%-7d", fshare.f_access);

		str = NULL;
		if (fshare.f_deny & F_MANDDNY) {
			fshare.f_deny &= ~F_MANDDNY;
			manddny = 1;
		}
		switch (fshare.f_deny) {
		case F_NODNY:
			str = "F_NODNY";
			break;
		case F_RDDNY:
			str = "F_RDDNY";
			break;
		case F_WRDNY:
			str = "F_WRDNY";
			break;
		case F_RWDNY:
			str = "F_RWDNY";
			break;
		case F_COMPAT:
			str = "F_COMPAT";
			break;
		}
		if (str != NULL) {
			if (manddny)
				(void) printf("  deny=F_MANDDNY|%s", str);
			else
				(void) printf("  deny=%s", str);
		} else {
			(void) printf("  deny=0x%x", manddny?
			    fshare.f_deny | F_MANDDNY : fshare.f_deny);
		}

		(void) printf("  id=%x\n", fshare.f_id);
	}
}

void
show_ffg(private_t *pri)
{
	(void) putchar('\t');
	(void) putchar('\t');
	prt_ffg(pri, 0, pri->Rval1);
	(void) puts(pri->sys_string);
}

/* print values in fcntl() pointed-to structure */
void
show_fcntl(private_t *pri)
{
	long offset;

	if (pri->sys_nargs >= 2 && pri->sys_args[1] == F_GETFL) {
		show_ffg(pri);
		return;
	}

	if (pri->sys_nargs < 3 || (offset = pri->sys_args[2]) == NULL)
		return;

	switch (pri->sys_args[1]) {
#ifdef _LP64
	case F_GETLK:
	case F_SETLK:
	case F_SETLKW:
	case F_FREESP:
	case F_ALLOCSP:
	case F_SETLK_NBMAND:
		if (data_model == PR_MODEL_LP64)
			show_flock64(pri, offset);
		else
			show_flock32(pri, offset);
		break;
	case 33:	/* F_GETLK64 */
	case 34:	/* F_SETLK64 */
	case 35:	/* F_SETLKW64 */
	case 27:	/* F_FREESP64 */
	case 28:	/* F_ALLOCSP64 */
	case 44:	/* F_SETLK64_NBMAND */
		show_flock64(pri, offset);
		break;
#else	/* _LP64 */
	case F_GETLK:
	case F_SETLK:
	case F_SETLKW:
	case F_FREESP:
	case F_ALLOCSP:
	case F_SETLK_NBMAND:
		show_flock32(pri, offset);
		break;
	case F_GETLK64:
	case F_SETLK64:
	case F_SETLKW64:
	case F_FREESP64:
	case F_ALLOCSP64:
	case F_SETLK64_NBMAND:
		show_flock64(pri, offset);
		break;
#endif	/* _LP64 */
	case F_SHARE:
	case F_UNSHARE:
		show_share(pri, offset);
		break;
	}
}

void
show_strbuf(private_t *pri, long offset, const char *name, int dump)
{
	struct strbuf strbuf;

	if (Pread(Proc, &strbuf, sizeof (strbuf), offset) == sizeof (strbuf))
		print_strbuf(pri, &strbuf, name, dump);
}

#ifdef _LP64
void
show_strbuf32(private_t *pri, long offset, const char *name, int dump)
{
	struct strbuf32 strbuf;

	if (Pread(Proc, &strbuf, sizeof (strbuf), offset) == sizeof (strbuf))
		print_strbuf32(pri, &strbuf, name, dump);
}
#endif	/* _LP64 */

void
show_gp_msg(private_t *pri, int what)
{
	long offset;
	int dump = FALSE;
	int fdp1 = pri->sys_args[0] + 1;

	switch (what) {
	case SYS_getmsg:
	case SYS_getpmsg:
		if (pri->Errno == 0 && prismember(&readfd, fdp1))
			dump = TRUE;
		break;
	case SYS_putmsg:
	case SYS_putpmsg:
		if (prismember(&writefd, fdp1))
			dump = TRUE;
		break;
	}

	/* enter region of lengthy output */
	if (dump)
		Eserialize();

#ifdef _LP64
	if (pri->sys_nargs >= 2 && (offset = pri->sys_args[1]) != NULL) {
		if (data_model == PR_MODEL_LP64)
			show_strbuf(pri, offset, "ctl", dump);
		else
			show_strbuf32(pri, offset, "ctl", dump);
	}
	if (pri->sys_nargs >= 3 && (offset = pri->sys_args[2]) != NULL) {
		if (data_model == PR_MODEL_LP64)
			show_strbuf(pri, offset, "dat", dump);
		else
			show_strbuf32(pri, offset, "dat", dump);
	}
#else	/* _LP64 */
	if (pri->sys_nargs >= 2 && (offset = pri->sys_args[1]) != NULL)
		show_strbuf(pri, offset, "ctl", dump);
	if (pri->sys_nargs >= 3 && (offset = pri->sys_args[2]) != NULL)
		show_strbuf(pri, offset, "dat", dump);
#endif	/* _LP64 */

	/* exit region of lengthy output */
	if (dump)
		Xserialize();
}

void
show_int(private_t *pri, long offset, const char *name)
{
	int value;

	if (offset != 0 &&
	    Pread(Proc, &value, sizeof (value), offset) == sizeof (value))
		(void) printf("%s\t%s:\t%d\n",
		    pri->pname,
		    name,
		    value);
}

void
show_hhex_int(private_t *pri, long offset, const char *name)
{
	int value;

	if (Pread(Proc, &value, sizeof (value), offset) == sizeof (value))
		(void) printf("%s\t%s:\t0x%.4X\n",
		    pri->pname,
		    name,
		    value);
}

#define	ALL_POLL_FLAGS	(POLLIN|POLLPRI|POLLOUT| \
	POLLRDNORM|POLLRDBAND|POLLWRBAND|POLLERR|POLLHUP|POLLNVAL)

const char *
pollevent(private_t *pri, int arg)
{
	char *str = pri->code_buf;

	if (arg == 0)
		return ("0");
	if (arg & ~ALL_POLL_FLAGS) {
		(void) sprintf(str, "0x%-5X", arg);
		return ((const char *)str);
	}

	*str = '\0';
	if (arg & POLLIN)
		(void) strcat(str, "|POLLIN");
	if (arg & POLLPRI)
		(void) strcat(str, "|POLLPRI");
	if (arg & POLLOUT)
		(void) strcat(str, "|POLLOUT");
	if (arg & POLLRDNORM)
		(void) strcat(str, "|POLLRDNORM");
	if (arg & POLLRDBAND)
		(void) strcat(str, "|POLLRDBAND");
	if (arg & POLLWRBAND)
		(void) strcat(str, "|POLLWRBAND");
	if (arg & POLLERR)
		(void) strcat(str, "|POLLERR");
	if (arg & POLLHUP)
		(void) strcat(str, "|POLLHUP");
	if (arg & POLLNVAL)
		(void) strcat(str, "|POLLNVAL");

	return ((const char *)(str+1));
}

static void
show_one_pollfd(private_t *pri, struct pollfd *ppollfd)
{
	/*
	 * can't print both events and revents in same printf.
	 * pollevent() returns a pointer to a TSD location.
	 */
	(void) printf("%s\tfd=%-2d ev=%s",
	    pri->pname, ppollfd->fd, pollevent(pri, ppollfd->events));
	(void) printf(" rev=%s\n", pollevent(pri, ppollfd->revents));
}

static void
show_all_pollfds(private_t *pri, long offset, int nfds)
{
	struct pollfd pollfd[2];
	int skip = -1;

	for (; nfds && !interrupt; nfds--, offset += sizeof (struct pollfd)) {
		if (Pread(Proc, &pollfd[0], sizeof (struct pollfd), offset) !=
		    sizeof (struct pollfd))
			continue;

		if (skip >= 0 && pollfd[0].fd == pollfd[1].fd &&
		    pollfd[0].events == pollfd[1].events &&
		    pollfd[0].revents == pollfd[1].revents) {
			skip++;
			continue;
		}

		if (skip > 0)
			(void) printf("%s\t...last pollfd structure"
			    " repeated %d time%s...\n",
			    pri->pname, skip, (skip == 1 ? "" : "s"));

		skip = 0;
		show_one_pollfd(pri, &pollfd[0]);
		pollfd[1] = pollfd[0];
	}

	if (skip > 0)
		(void) printf(
		    "%s\t...last pollfd structure repeated %d time%s...\n",
		    pri->pname, skip, (skip == 1 ? "" : "s"));
}

void
show_pollsys(private_t *pri)
{
	long offset;
	int nfds;
	int serial = 0;

	if (pri->sys_nargs < 2)
		return;

	offset = pri->sys_args[0];
	nfds = pri->sys_args[1];

	/* enter region of lengthy output */
	if (offset != NULL && nfds > 32) {
		Eserialize();
		serial = 1;
	}

	if (offset != NULL && nfds > 0)
		show_all_pollfds(pri, offset, nfds);

	if (pri->sys_nargs > 2)
		show_timestruc(pri, (long)pri->sys_args[2], "timeout");

	if (pri->sys_nargs > 3)
		show_sigset(pri, (long)pri->sys_args[3], "sigmask");

	/* exit region of lengthy output */
	if (serial)
		Xserialize();
}

static void
show_perm64(private_t *pri, struct ipc_perm64 *ip)
{
	(void) printf("%s\tu=%-5u g=%-5u cu=%-5u cg=%-5u z=%-5d "
	    "m=0%.6o key=%d projid=%-5d\n",
	    pri->pname,
	    ip->ipcx_uid,
	    ip->ipcx_gid,
	    ip->ipcx_cuid,
	    ip->ipcx_cgid,
	    (int)ip->ipcx_zoneid,
	    (unsigned int)ip->ipcx_mode,
	    ip->ipcx_key,
	    (int)ip->ipcx_projid);
}

void
show_perm(private_t *pri, struct ipc_perm *ip)
{
	(void) printf(
	    "%s\tu=%-5u g=%-5u cu=%-5u cg=%-5u m=0%.6o seq=%u key=%d\n",
	    pri->pname,
	    ip->uid,
	    ip->gid,
	    ip->cuid,
	    ip->cgid,
	    (int)ip->mode,
	    ip->seq,
	    ip->key);
}

#ifdef _LP64
void
show_perm32(private_t *pri, struct ipc_perm32 *ip)
{
	(void) printf(
	    "%s\tu=%-5u g=%-5u cu=%-5u cg=%-5u m=0%.6o seq=%u key=%d\n",
	    pri->pname,
	    ip->uid,
	    ip->gid,
	    ip->cuid,
	    ip->cgid,
	    ip->mode,
	    ip->seq,
	    ip->key);
}
#endif	/* _LP64 */

static void
show_msgctl64(private_t *pri, long offset)
{
	struct msqid_ds64 msgq;

	if (offset != NULL &&
	    Pread(Proc, &msgq, sizeof (msgq), offset) == sizeof (msgq)) {
		show_perm64(pri, &msgq.msgx_perm);

		(void) printf("%s\tbytes=%-5llu msgs=%-5llu maxby=%-5llu "
		    "lspid=%-5d lrpid=%-5d\n", pri->pname,
		    (unsigned long long)msgq.msgx_cbytes,
		    (unsigned long long)msgq.msgx_qnum,
		    (unsigned long long)msgq.msgx_qbytes,
		    (int)msgq.msgx_lspid,
		    (int)msgq.msgx_lrpid);

		prtime(pri, "    st = ", (time_t)msgq.msgx_stime);
		prtime(pri, "    rt = ", (time_t)msgq.msgx_rtime);
		prtime(pri, "    ct = ", (time_t)msgq.msgx_ctime);
	}
}

void
show_msgctl(private_t *pri, long offset)
{
	struct msqid_ds msgq;

	if (offset != NULL &&
	    Pread(Proc, &msgq, sizeof (msgq), offset) == sizeof (msgq)) {
		show_perm(pri, &msgq.msg_perm);

		(void) printf(
	"%s\tbytes=%-5lu msgs=%-5lu maxby=%-5lu lspid=%-5u lrpid=%-5u\n",
		    pri->pname,
		    msgq.msg_cbytes,
		    msgq.msg_qnum,
		    msgq.msg_qbytes,
		    (int)msgq.msg_lspid,
		    (int)msgq.msg_lrpid);

		prtime(pri, "    st = ", msgq.msg_stime);
		prtime(pri, "    rt = ", msgq.msg_rtime);
		prtime(pri, "    ct = ", msgq.msg_ctime);
	}
}

#ifdef _LP64
void
show_msgctl32(private_t *pri, long offset)
{
	struct msqid_ds32 msgq;

	if (offset != NULL &&
	    Pread(Proc, &msgq, sizeof (msgq), offset) == sizeof (msgq)) {
		show_perm32(pri, &msgq.msg_perm);

		(void) printf(
	"%s\tbytes=%-5u msgs=%-5u maxby=%-5u lspid=%-5u lrpid=%-5u\n",
		    pri->pname,
		    msgq.msg_cbytes,
		    msgq.msg_qnum,
		    msgq.msg_qbytes,
		    msgq.msg_lspid,
		    msgq.msg_lrpid);

		prtime(pri, "    st = ", msgq.msg_stime);
		prtime(pri, "    rt = ", msgq.msg_rtime);
		prtime(pri, "    ct = ", msgq.msg_ctime);
	}
}
#endif	/* _LP64 */

void
show_msgbuf(private_t *pri, long offset, long msgsz)
{
	struct msgbuf msgb;

	if (offset != NULL &&
	    Pread(Proc, &msgb, sizeof (msgb.mtype), offset) ==
	    sizeof (msgb.mtype)) {
		/* enter region of lengthy output */
		if (msgsz > MYBUFSIZ / 4)
			Eserialize();

		(void) printf("%s\tmtype=%lu  mtext[]=\n",
		    pri->pname,
		    msgb.mtype);
		showbuffer(pri,
		    (long)(offset + sizeof (msgb.mtype)), msgsz);

		/* exit region of lengthy output */
		if (msgsz > MYBUFSIZ / 4)
			Xserialize();
	}
}

#ifdef _LP64
void
show_msgbuf32(private_t *pri, long offset, long msgsz)
{
	struct ipcmsgbuf32 msgb;

	if (offset != NULL &&
	    Pread(Proc, &msgb, sizeof (msgb.mtype), offset) ==
	    sizeof (msgb.mtype)) {
		/* enter region of lengthy output */
		if (msgsz > MYBUFSIZ / 4)
			Eserialize();

		(void) printf("%s\tmtype=%u  mtext[]=\n",
		    pri->pname,
		    msgb.mtype);
		showbuffer(pri,
		    (long)(offset + sizeof (msgb.mtype)), msgsz);

		/* exit region of lengthy output */
		if (msgsz > MYBUFSIZ / 4)
			Xserialize();
	}
}
#endif	/* _LP64 */

#ifdef _LP64
void
show_msgsys(private_t *pri, long msgsz)
{
	switch (pri->sys_args[0]) {
	case 0:			/* msgget() */
		break;
	case 1:			/* msgctl() */
		if (pri->sys_nargs > 3) {
			switch (pri->sys_args[2]) {
			case IPC_STAT:
				if (pri->Errno)
					break;
				/*FALLTHROUGH*/
			case IPC_SET:
				if (data_model == PR_MODEL_LP64)
					show_msgctl(pri,
					    (long)pri->sys_args[3]);
				else
					show_msgctl32(pri,
					    (long)pri->sys_args[3]);
				break;
			case IPC_STAT64:
				if (pri->Errno)
					break;
				/*FALLTHROUGH*/
			case IPC_SET64:
				show_msgctl64(pri, (long)pri->sys_args[3]);
				break;
			}
		}
		break;
	case 2:			/* msgrcv() */
		if (!pri->Errno && pri->sys_nargs > 2) {
			if (data_model == PR_MODEL_LP64)
				show_msgbuf(pri, pri->sys_args[2], msgsz);
			else
				show_msgbuf32(pri, pri->sys_args[2], msgsz);
		}
		break;
	case 3:			/* msgsnd() */
		if (pri->sys_nargs > 3) {
			if (data_model == PR_MODEL_LP64)
				show_msgbuf(pri, pri->sys_args[2],
				    pri->sys_args[3]);
			else
				show_msgbuf32(pri, pri->sys_args[2],
				    pri->sys_args[3]);
		}
		break;
	case 4:			/* msgids() */
	case 5:			/* msgsnap() */
	default:		/* unexpected subcode */
		break;
	}
}
#else	/* _LP64 */
void
show_msgsys(private_t *pri, long msgsz)
{
	switch (pri->sys_args[0]) {
	case 0:			/* msgget() */
		break;
	case 1:			/* msgctl() */
		if (pri->sys_nargs > 3) {
			switch (pri->sys_args[2]) {
			case IPC_STAT:
				if (pri->Errno)
					break;
				/*FALLTHROUGH*/
			case IPC_SET:
				show_msgctl(pri, (long)pri->sys_args[3]);
				break;
			case IPC_STAT64:
				if (pri->Errno)
					break;
				/*FALLTHROUGH*/
			case IPC_SET64:
				show_msgctl64(pri, (long)pri->sys_args[3]);
				break;
			}
		}
		break;
	case 2:			/* msgrcv() */
		if (!pri->Errno && pri->sys_nargs > 2)
			show_msgbuf(pri, pri->sys_args[2], msgsz);
		break;
	case 3:			/* msgsnd() */
		if (pri->sys_nargs > 3)
			show_msgbuf(pri, pri->sys_args[2],
			    pri->sys_args[3]);
		break;
	case 4:			/* msgids() */
	case 5:			/* msgsnap() */
	default:		/* unexpected subcode */
		break;
	}
}
#endif	/* _LP64 */

static void
show_semctl64(private_t *pri, long offset)
{
	struct semid_ds64 semds;

	if (offset != NULL &&
	    Pread(Proc, &semds, sizeof (semds), offset) == sizeof (semds)) {
		show_perm64(pri, &semds.semx_perm);

		(void) printf("%s\tnsems=%u\n", pri->pname, semds.semx_nsems);

		prtime(pri, "    ot = ", (time_t)semds.semx_otime);
		prtime(pri, "    ct = ", (time_t)semds.semx_ctime);
	}
}

void
show_semctl(private_t *pri, long offset)
{
	struct semid_ds semds;

	if (offset != NULL &&
	    Pread(Proc, &semds, sizeof (semds), offset) == sizeof (semds)) {
		show_perm(pri, &semds.sem_perm);

		(void) printf("%s\tnsems=%u\n",
		    pri->pname,
		    semds.sem_nsems);

		prtime(pri, "    ot = ", semds.sem_otime);
		prtime(pri, "    ct = ", semds.sem_ctime);
	}
}

#ifdef _LP64
void
show_semctl32(private_t *pri, long offset)
{
	struct semid_ds32 semds;

	if (offset != NULL &&
	    Pread(Proc, &semds, sizeof (semds), offset) == sizeof (semds)) {
		show_perm32(pri, &semds.sem_perm);

		(void) printf("%s\tnsems=%u\n",
		    pri->pname,
		    semds.sem_nsems);

		prtime(pri, "    ot = ", semds.sem_otime);
		prtime(pri, "    ct = ", semds.sem_ctime);
	}
}
#endif	/* _LP64 */

void
show_semop(private_t *pri, long offset, long nsops, long timeout)
{
	struct sembuf sembuf;
	const char *str;

	if (offset == 0)
		return;

	if (nsops > 40)		/* let's not be ridiculous */
		nsops = 40;

	for (; nsops > 0 && !interrupt; --nsops, offset += sizeof (sembuf)) {
		if (Pread(Proc, &sembuf, sizeof (sembuf), offset) !=
		    sizeof (sembuf))
			break;

		(void) printf("%s\tsemnum=%-5u semop=%-5d semflg=",
		    pri->pname,
		    sembuf.sem_num,
		    sembuf.sem_op);

		if (sembuf.sem_flg == 0)
			(void) printf("0\n");
		else if ((str = semflags(pri, sembuf.sem_flg)) != NULL)
			(void) printf("%s\n", str);
		else
			(void) printf("0%.6o\n", sembuf.sem_flg);
	}
	if (timeout)
		show_timestruc(pri, timeout, "timeout");
}

void
show_semsys(private_t *pri)
{
	switch (pri->sys_args[0]) {
	case 0:			/* semctl() */
		if (pri->sys_nargs > 4) {
			switch (pri->sys_args[3]) {
			case IPC_STAT:
				if (pri->Errno)
					break;
				/*FALLTHROUGH*/
			case IPC_SET:
#ifdef _LP64
				if (data_model == PR_MODEL_LP64)
					show_semctl(pri,
					    (long)pri->sys_args[4]);
				else
					show_semctl32(pri,
					    (long)pri->sys_args[4]);
#else
				show_semctl(pri, (long)pri->sys_args[4]);
#endif
				break;
			case IPC_STAT64:
				if (pri->Errno)
					break;
				/*FALLTHROUGH*/
			case IPC_SET64:
				show_semctl64(pri, (long)pri->sys_args[4]);
				break;
			}
		}
		break;
	case 1:			/* semget() */
		break;
	case 2:			/* semop() */
		if (pri->sys_nargs > 3)
			show_semop(pri, (long)pri->sys_args[2],
			    pri->sys_args[3], 0);
		break;
	case 3:			/* semids() */
		break;
	case 4:			/* semtimedop() */
		if (pri->sys_nargs > 4)
			show_semop(pri, (long)pri->sys_args[2],
			    pri->sys_args[3], pri->sys_args[4]);
		break;
	default:		/* unexpected subcode */
		break;
	}
}

static void
show_shmctl64(private_t *pri, long offset)
{
	struct shmid_ds64 shmds;

	if (offset != NULL &&
	    Pread(Proc, &shmds, sizeof (shmds), offset) == sizeof (shmds)) {
		show_perm64(pri, &shmds.shmx_perm);

		(void) printf(
		    "%s\tsize=%-6llu lpid=%-5d cpid=%-5d na=%-5llu cna=%llu\n",
		    pri->pname,
		    (unsigned long long)shmds.shmx_segsz,
		    (int)shmds.shmx_lpid,
		    (int)shmds.shmx_cpid,
		    (unsigned long long)shmds.shmx_nattch,
		    (unsigned long long)shmds.shmx_cnattch);

		prtime(pri, "    at = ", (time_t)shmds.shmx_atime);
		prtime(pri, "    dt = ", (time_t)shmds.shmx_dtime);
		prtime(pri, "    ct = ", (time_t)shmds.shmx_ctime);
	}
}

void
show_shmctl(private_t *pri, long offset)
{
	struct shmid_ds shmds;

	if (offset != NULL &&
	    Pread(Proc, &shmds, sizeof (shmds), offset) == sizeof (shmds)) {
		show_perm(pri, &shmds.shm_perm);

		(void) printf(
		    "%s\tsize=%-6lu lpid=%-5u cpid=%-5u na=%-5lu cna=%lu\n",
		    pri->pname,
		    (ulong_t)shmds.shm_segsz,
		    (int)shmds.shm_lpid,
		    (int)shmds.shm_cpid,
		    shmds.shm_nattch,
		    shmds.shm_cnattch);

		prtime(pri, "    at = ", shmds.shm_atime);
		prtime(pri, "    dt = ", shmds.shm_dtime);
		prtime(pri, "    ct = ", shmds.shm_ctime);
	}
}

#ifdef _LP64
void
show_shmctl32(private_t *pri, long offset)
{
	struct shmid_ds32 shmds;

	if (offset != NULL &&
	    Pread(Proc, &shmds, sizeof (shmds), offset) == sizeof (shmds)) {
		show_perm32(pri, &shmds.shm_perm);

		(void) printf(
		    "%s\tsize=%-6u lpid=%-5u cpid=%-5u na=%-5u cna=%u\n",
		    pri->pname,
		    shmds.shm_segsz,
		    shmds.shm_lpid,
		    shmds.shm_cpid,
		    shmds.shm_nattch,
		    shmds.shm_cnattch);

		prtime(pri, "    at = ", shmds.shm_atime);
		prtime(pri, "    dt = ", shmds.shm_dtime);
		prtime(pri, "    ct = ", shmds.shm_ctime);
	}
}
#endif	/* _LP64 */

void
show_shmsys(private_t *pri)
{
	switch (pri->sys_args[0]) {
	case 0:			/* shmat() */
		break;
	case 1:			/* shmctl() */
		if (pri->sys_nargs > 3) {
			switch (pri->sys_args[2]) {
			case IPC_STAT:
				if (pri->Errno)
					break;
				/*FALLTHROUGH*/
			case IPC_SET:
#ifdef _LP64
				if (data_model == PR_MODEL_LP64)
					show_shmctl(pri,
					    (long)pri->sys_args[3]);
				else
					show_shmctl32(pri,
					    (long)pri->sys_args[3]);
#else
				show_shmctl(pri, (long)pri->sys_args[3]);
#endif
				break;
			case IPC_STAT64:
				if (pri->Errno)
					break;
				/*FALLTHROUGH*/
			case IPC_SET64:
				show_shmctl64(pri, (long)pri->sys_args[3]);
				break;
			}
		}
		break;
	case 2:			/* shmdt() */
	case 3:			/* shmget() */
	case 4:			/* shmids() */
	default:		/* unexpected subcode */
		break;
	}
}

void
show_groups(private_t *pri, long offset, long count)
{
	int groups[100];

	if (count > 100)
		count = 100;

	if (count > 0 && offset != NULL &&
	    Pread(Proc, &groups[0], count*sizeof (int), offset) ==
	    count*sizeof (int)) {
		int n;

		(void) printf("%s\t", pri->pname);
		for (n = 0; !interrupt && n < count; n++) {
			if (n != 0 && n%10 == 0)
				(void) printf("\n%s\t", pri->pname);
			(void) printf(" %5d", groups[n]);
		}
		(void) fputc('\n', stdout);
	}
}

/*
 * This assumes that a sigset_t is simply an array of ints.
 */
char *
sigset_string(private_t *pri, sigset_t *sp)
{
	char *s = pri->code_buf;
	int n = sizeof (*sp) / sizeof (int32_t);
	int32_t *lp = (int32_t *)sp;

	while (--n >= 0) {
		int32_t val = *lp++;

		if (val == 0)
			s += sprintf(s, " 0");
		else
			s += sprintf(s, " 0x%.8X", val);
	}

	return (pri->code_buf);
}

void
show_sigset(private_t *pri, long offset, const char *name)
{
	sigset_t sigset;

	if (offset != NULL &&
	    Pread(Proc, &sigset, sizeof (sigset), offset) == sizeof (sigset)) {
		(void) printf("%s\t%s =%s\n",
		    pri->pname, name, sigset_string(pri, &sigset));
	}
}

#ifdef _LP64
void
show_sigaltstack32(private_t *pri, long offset, const char *name)
{
	struct sigaltstack32 altstack;

	if (offset != NULL &&
	    Pread(Proc, &altstack, sizeof (altstack), offset) ==
	    sizeof (altstack)) {
		(void) printf("%s\t%s: sp=0x%.8X size=%u flags=0x%.4X\n",
		    pri->pname,
		    name,
		    altstack.ss_sp,
		    altstack.ss_size,
		    altstack.ss_flags);
	}
}
#endif	/* _LP64 */

void
show_sigaltstack(private_t *pri, long offset, const char *name)
{
	struct sigaltstack altstack;

#ifdef _LP64
	if (data_model != PR_MODEL_LP64) {
		show_sigaltstack32(pri, offset, name);
		return;
	}
#endif
	if (offset != NULL &&
	    Pread(Proc, &altstack, sizeof (altstack), offset) ==
	    sizeof (altstack)) {
		(void) printf("%s\t%s: sp=0x%.8lX size=%lu flags=0x%.4X\n",
		    pri->pname,
		    name,
		    (ulong_t)altstack.ss_sp,
		    (ulong_t)altstack.ss_size,
		    altstack.ss_flags);
	}
}

#ifdef _LP64
void
show_sigaction32(private_t *pri, long offset, const char *name, long odisp)
{
	struct sigaction32 sigaction;

	if (offset != NULL &&
	    Pread(Proc, &sigaction, sizeof (sigaction), offset) ==
	    sizeof (sigaction)) {
		/* This is stupid, we shouldn't have to do this */
		if (odisp != NULL)
			sigaction.sa_handler = (caddr32_t)odisp;
		(void) printf(
		    "%s    %s: hand = 0x%.8X mask =%s flags = 0x%.4X\n",
		    pri->pname,
		    name,
		    sigaction.sa_handler,
		    sigset_string(pri, (sigset_t *)&sigaction.sa_mask),
		    sigaction.sa_flags);
	}
}
#endif	/* _LP64 */

void
show_sigaction(private_t *pri, long offset, const char *name, long odisp)
{
	struct sigaction sigaction;

#ifdef _LP64
	if (data_model != PR_MODEL_LP64) {
		show_sigaction32(pri, offset, name, odisp);
		return;
	}
#endif
	if (offset != NULL &&
	    Pread(Proc, &sigaction, sizeof (sigaction), offset) ==
	    sizeof (sigaction)) {
		/* This is stupid, we shouldn't have to do this */
		if (odisp != NULL)
			sigaction.sa_handler = (void (*)())odisp;
		(void) printf(
		    "%s    %s: hand = 0x%.8lX mask =%s flags = 0x%.4X\n",
		    pri->pname,
		    name,
		    (long)sigaction.sa_handler,
		    sigset_string(pri, &sigaction.sa_mask),
		    sigaction.sa_flags);
	}
}

#ifdef _LP64
void
print_siginfo32(private_t *pri, const siginfo32_t *sip)
{
	const char *code = NULL;

	(void) printf("%s      siginfo: %s", pri->pname,
	    signame(pri, sip->si_signo));

	if (sip->si_signo != 0 && SI_FROMUSER(sip) && sip->si_pid != 0) {
		(void) printf(" pid=%d uid=%d", sip->si_pid, sip->si_uid);
		if (sip->si_code != 0)
			(void) printf(" code=%d", sip->si_code);
		(void) fputc('\n', stdout);
		return;
	}

	switch (sip->si_signo) {
	default:
		(void) fputc('\n', stdout);
		return;
	case SIGILL:
	case SIGTRAP:
	case SIGFPE:
	case SIGSEGV:
	case SIGBUS:
	case SIGEMT:
	case SIGCLD:
	case SIGPOLL:
	case SIGXFSZ:
		break;
	}

	switch (sip->si_signo) {
	case SIGILL:
		switch (sip->si_code) {
		case ILL_ILLOPC:	code = "ILL_ILLOPC";	break;
		case ILL_ILLOPN:	code = "ILL_ILLOPN";	break;
		case ILL_ILLADR:	code = "ILL_ILLADR";	break;
		case ILL_ILLTRP:	code = "ILL_ILLTRP";	break;
		case ILL_PRVOPC:	code = "ILL_PRVOPC";	break;
		case ILL_PRVREG:	code = "ILL_PRVREG";	break;
		case ILL_COPROC:	code = "ILL_COPROC";	break;
		case ILL_BADSTK:	code = "ILL_BADSTK";	break;
		}
		break;
	case SIGTRAP:
		switch (sip->si_code) {
		case TRAP_BRKPT:	code = "TRAP_BRKPT";	break;
		case TRAP_TRACE:	code = "TRAP_TRACE";	break;
		case TRAP_RWATCH:	code = "TRAP_RWATCH";	break;
		case TRAP_WWATCH:	code = "TRAP_WWATCH";	break;
		case TRAP_XWATCH:	code = "TRAP_XWATCH";	break;
		case TRAP_DTRACE:	code = "TRAP_DTRACE";	break;
		}
		break;
	case SIGFPE:
		switch (sip->si_code) {
		case FPE_INTDIV:	code = "FPE_INTDIV";	break;
		case FPE_INTOVF:	code = "FPE_INTOVF";	break;
		case FPE_FLTDIV:	code = "FPE_FLTDIV";	break;
		case FPE_FLTOVF:	code = "FPE_FLTOVF";	break;
		case FPE_FLTUND:	code = "FPE_FLTUND";	break;
		case FPE_FLTRES:	code = "FPE_FLTRES";	break;
		case FPE_FLTINV:	code = "FPE_FLTINV";	break;
		case FPE_FLTSUB:	code = "FPE_FLTSUB";	break;
#if defined(FPE_FLTDEN)
		case FPE_FLTDEN:	code = "FPE_FLTDEN";	break;
#endif
		}
		break;
	case SIGSEGV:
		switch (sip->si_code) {
		case SEGV_MAPERR:	code = "SEGV_MAPERR";	break;
		case SEGV_ACCERR:	code = "SEGV_ACCERR";	break;
		}
		break;
	case SIGEMT:
		switch (sip->si_code) {
#ifdef EMT_TAGOVF
		case EMT_TAGOVF:	code = "EMT_TAGOVF";	break;
#endif
		case EMT_CPCOVF:	code = "EMT_CPCOVF";	break;
		}
		break;
	case SIGBUS:
		switch (sip->si_code) {
		case BUS_ADRALN:	code = "BUS_ADRALN";	break;
		case BUS_ADRERR:	code = "BUS_ADRERR";	break;
		case BUS_OBJERR:	code = "BUS_OBJERR";	break;
		}
		break;
	case SIGCLD:
		switch (sip->si_code) {
		case CLD_EXITED:	code = "CLD_EXITED";	break;
		case CLD_KILLED:	code = "CLD_KILLED";	break;
		case CLD_DUMPED:	code = "CLD_DUMPED";	break;
		case CLD_TRAPPED:	code = "CLD_TRAPPED";	break;
		case CLD_STOPPED:	code = "CLD_STOPPED";	break;
		case CLD_CONTINUED:	code = "CLD_CONTINUED";	break;
		}
		break;
	case SIGPOLL:
		switch (sip->si_code) {
		case POLL_IN:		code = "POLL_IN";	break;
		case POLL_OUT:		code = "POLL_OUT";	break;
		case POLL_MSG:		code = "POLL_MSG";	break;
		case POLL_ERR:		code = "POLL_ERR";	break;
		case POLL_PRI:		code = "POLL_PRI";	break;
		case POLL_HUP:		code = "POLL_HUP";	break;
		}
		break;
	}

	if (code == NULL) {
		(void) sprintf(pri->code_buf, "code=%d", sip->si_code);
		code = (const char *)pri->code_buf;
	}

	switch (sip->si_signo) {
	case SIGILL:
	case SIGTRAP:
	case SIGFPE:
	case SIGSEGV:
	case SIGBUS:
	case SIGEMT:
		(void) printf(" %s addr=0x%.8X",
		    code,
		    sip->si_addr);
		break;
	case SIGCLD:
		(void) printf(" %s pid=%d status=0x%.4X",
		    code,
		    sip->si_pid,
		    sip->si_status);
		break;
	case SIGPOLL:
	case SIGXFSZ:
		(void) printf(" %s fd=%d band=%d",
		    code,
		    sip->si_fd,
		    sip->si_band);
		break;
	}

	if (sip->si_errno != 0) {
		const char *ename = errname(sip->si_errno);

		(void) printf(" errno=%d", sip->si_errno);
		if (ename != NULL)
			(void) printf("(%s)", ename);
	}

	(void) fputc('\n', stdout);
}
#endif	/* _LP64 */

void
print_siginfo(private_t *pri, const siginfo_t *sip)
{
	const char *code = NULL;

	(void) printf("%s      siginfo: %s", pri->pname,
	    signame(pri, sip->si_signo));

	if (sip->si_signo != 0 && SI_FROMUSER(sip) && sip->si_pid != 0) {
		(void) printf(" pid=%d uid=%u",
		    (int)sip->si_pid,
		    sip->si_uid);
		if (sip->si_code != 0)
			(void) printf(" code=%d", sip->si_code);
		(void) fputc('\n', stdout);
		return;
	}

	switch (sip->si_signo) {
	default:
		(void) fputc('\n', stdout);
		return;
	case SIGILL:
	case SIGTRAP:
	case SIGFPE:
	case SIGSEGV:
	case SIGBUS:
	case SIGEMT:
	case SIGCLD:
	case SIGPOLL:
	case SIGXFSZ:
		break;
	}

	switch (sip->si_signo) {
	case SIGILL:
		switch (sip->si_code) {
		case ILL_ILLOPC:	code = "ILL_ILLOPC";	break;
		case ILL_ILLOPN:	code = "ILL_ILLOPN";	break;
		case ILL_ILLADR:	code = "ILL_ILLADR";	break;
		case ILL_ILLTRP:	code = "ILL_ILLTRP";	break;
		case ILL_PRVOPC:	code = "ILL_PRVOPC";	break;
		case ILL_PRVREG:	code = "ILL_PRVREG";	break;
		case ILL_COPROC:	code = "ILL_COPROC";	break;
		case ILL_BADSTK:	code = "ILL_BADSTK";	break;
		}
		break;
	case SIGTRAP:
		switch (sip->si_code) {
		case TRAP_BRKPT:	code = "TRAP_BRKPT";	break;
		case TRAP_TRACE:	code = "TRAP_TRACE";	break;
		case TRAP_RWATCH:	code = "TRAP_RWATCH";	break;
		case TRAP_WWATCH:	code = "TRAP_WWATCH";	break;
		case TRAP_XWATCH:	code = "TRAP_XWATCH";	break;
		case TRAP_DTRACE:	code = "TRAP_DTRACE";	break;
		}
		break;
	case SIGFPE:
		switch (sip->si_code) {
		case FPE_INTDIV:	code = "FPE_INTDIV";	break;
		case FPE_INTOVF:	code = "FPE_INTOVF";	break;
		case FPE_FLTDIV:	code = "FPE_FLTDIV";	break;
		case FPE_FLTOVF:	code = "FPE_FLTOVF";	break;
		case FPE_FLTUND:	code = "FPE_FLTUND";	break;
		case FPE_FLTRES:	code = "FPE_FLTRES";	break;
		case FPE_FLTINV:	code = "FPE_FLTINV";	break;
		case FPE_FLTSUB:	code = "FPE_FLTSUB";	break;
#if defined(FPE_FLTDEN)
		case FPE_FLTDEN:	code = "FPE_FLTDEN";	break;
#endif
		}
		break;
	case SIGSEGV:
		switch (sip->si_code) {
		case SEGV_MAPERR:	code = "SEGV_MAPERR";	break;
		case SEGV_ACCERR:	code = "SEGV_ACCERR";	break;
		}
		break;
	case SIGEMT:
		switch (sip->si_code) {
#ifdef EMT_TAGOVF
		case EMT_TAGOVF:	code = "EMT_TAGOVF";	break;
#endif
		case EMT_CPCOVF:	code = "EMT_CPCOVF";	break;
		}
		break;
	case SIGBUS:
		switch (sip->si_code) {
		case BUS_ADRALN:	code = "BUS_ADRALN";	break;
		case BUS_ADRERR:	code = "BUS_ADRERR";	break;
		case BUS_OBJERR:	code = "BUS_OBJERR";	break;
		}
		break;
	case SIGCLD:
		switch (sip->si_code) {
		case CLD_EXITED:	code = "CLD_EXITED";	break;
		case CLD_KILLED:	code = "CLD_KILLED";	break;
		case CLD_DUMPED:	code = "CLD_DUMPED";	break;
		case CLD_TRAPPED:	code = "CLD_TRAPPED";	break;
		case CLD_STOPPED:	code = "CLD_STOPPED";	break;
		case CLD_CONTINUED:	code = "CLD_CONTINUED";	break;
		}
		break;
	case SIGPOLL:
		switch (sip->si_code) {
		case POLL_IN:		code = "POLL_IN";	break;
		case POLL_OUT:		code = "POLL_OUT";	break;
		case POLL_MSG:		code = "POLL_MSG";	break;
		case POLL_ERR:		code = "POLL_ERR";	break;
		case POLL_PRI:		code = "POLL_PRI";	break;
		case POLL_HUP:		code = "POLL_HUP";	break;
		}
		break;
	}

	if (code == NULL) {
		(void) sprintf(pri->code_buf, "code=%d", sip->si_code);
		code = (const char *)pri->code_buf;
	}

	switch (sip->si_signo) {
	case SIGILL:
	case SIGTRAP:
	case SIGFPE:
	case SIGSEGV:
	case SIGBUS:
	case SIGEMT:
		(void) printf(" %s addr=0x%.8lX",
		    code,
		    (long)sip->si_addr);
		break;
	case SIGCLD:
		(void) printf(" %s pid=%d status=0x%.4X",
		    code,
		    (int)sip->si_pid,
		    sip->si_status);
		break;
	case SIGPOLL:
	case SIGXFSZ:
		(void) printf(" %s fd=%d band=%ld",
		    code,
		    sip->si_fd,
		    sip->si_band);
		break;
	}

	if (sip->si_errno != 0) {
		const char *ename = errname(sip->si_errno);

		(void) printf(" errno=%d", sip->si_errno);
		if (ename != NULL)
			(void) printf("(%s)", ename);
	}

	(void) fputc('\n', stdout);
}

#ifdef _LP64
void
show_siginfo32(private_t *pri, long offset)
{
	struct siginfo32 siginfo;

	if (offset != NULL &&
	    Pread(Proc, &siginfo, sizeof (siginfo), offset) == sizeof (siginfo))
		print_siginfo32(pri, &siginfo);
}
#endif	/* _LP64 */

void
show_siginfo(private_t *pri, long offset)
{
	struct siginfo siginfo;

#ifdef _LP64
	if (data_model != PR_MODEL_LP64) {
		show_siginfo32(pri, offset);
		return;
	}
#endif
	if (offset != NULL &&
	    Pread(Proc, &siginfo, sizeof (siginfo), offset) == sizeof (siginfo))
		print_siginfo(pri, &siginfo);
}

void
show_bool(private_t *pri, long offset, int count)
{
	int serial = (count > MYBUFSIZ / 4);

	/* enter region of lengthy output */
	if (serial)
		Eserialize();

	while (count > 0) {
		char buf[32];
		int nb = (count < 32)? count : 32;
		int i;

		if (Pread(Proc, buf, (size_t)nb, offset) != nb)
			break;

		(void) printf("%s   ", pri->pname);
		for (i = 0; i < nb; i++)
			(void) printf(" %d", buf[i]);
		(void) fputc('\n', stdout);

		count -= nb;
		offset += nb;
	}

	/* exit region of lengthy output */
	if (serial)
		Xserialize();
}

#ifdef _LP64
void
show_iovec32(private_t *pri, long offset, int niov, int showbuf, long count)
{
	iovec32_t iovec[16];
	iovec32_t *ip;
	long nb;
	int serial = (count > MYBUFSIZ / 4 && showbuf);

	if (niov > 16)		/* is this the real limit? */
		niov = 16;

	if (offset != NULL && niov > 0 &&
	    Pread(Proc, &iovec[0], niov*sizeof (iovec32_t), offset)
	    == niov*sizeof (iovec32_t)) {
		/* enter region of lengthy output */
		if (serial)
			Eserialize();

		for (ip = &iovec[0]; niov-- && !interrupt; ip++) {
			(void) printf("%s\tiov_base = 0x%.8X  iov_len = %d\n",
			    pri->pname,
			    ip->iov_base,
			    ip->iov_len);
			if ((nb = count) > 0) {
				if (nb > ip->iov_len)
					nb = ip->iov_len;
				if (nb > 0)
					count -= nb;
			}
			if (showbuf && nb > 0)
				showbuffer(pri, (long)ip->iov_base, nb);
		}

		/* exit region of lengthy output */
		if (serial)
			Xserialize();
	}
}
#endif	/* _LP64 */

void
show_iovec(private_t *pri, long offset, long niov, int showbuf, long count)
{
	iovec_t iovec[16];
	iovec_t *ip;
	long nb;
	int serial = (count > MYBUFSIZ / 4 && showbuf);

#ifdef _LP64
	if (data_model != PR_MODEL_LP64) {
		show_iovec32(pri, offset, niov, showbuf, count);
		return;
	}
#endif
	if (niov > 16)		/* is this the real limit? */
		niov = 16;

	if (offset != NULL && niov > 0 &&
	    Pread(Proc, &iovec[0], niov*sizeof (iovec_t), offset)
	    == niov*sizeof (iovec_t)) {
		/* enter region of lengthy output */
		if (serial)
			Eserialize();

		for (ip = &iovec[0]; niov-- && !interrupt; ip++) {
			(void) printf("%s\tiov_base = 0x%.8lX  iov_len = %lu\n",
			    pri->pname,
			    (long)ip->iov_base,
			    ip->iov_len);
			if ((nb = count) > 0) {
				if (nb > ip->iov_len)
					nb = ip->iov_len;
				if (nb > 0)
					count -= nb;
			}
			if (showbuf && nb > 0)
				showbuffer(pri, (long)ip->iov_base, nb);
		}

		/* exit region of lengthy output */
		if (serial)
			Xserialize();
	}
}

void
show_dents32(private_t *pri, long offset, long count)
{
	long buf[MYBUFSIZ / sizeof (long)];
	struct dirent32 *dp;
	int serial = (count > 100);

	if (offset == 0)
		return;

	/* enter region of lengthy output */
	if (serial)
		Eserialize();

	while (count > 0 && !interrupt) {
		int nb = count < MYBUFSIZ? (int)count : MYBUFSIZ;

		if ((nb = Pread(Proc, &buf[0], (size_t)nb, offset)) <= 0)
			break;

		dp = (struct dirent32 *)&buf[0];
		if (nb < (int)(dp->d_name - (char *)dp))
			break;
		if ((unsigned)nb < dp->d_reclen) {
			/* getdents() error? */
			(void) printf(
			    "%s    ino=%-5u off=%-4d rlen=%-3d\n",
			    pri->pname,
			    dp->d_ino,
			    dp->d_off,
			    dp->d_reclen);
			break;
		}

		while (!interrupt &&
		    nb >= (int)(dp->d_name - (char *)dp) &&
		    (unsigned)nb >= dp->d_reclen) {
			(void) printf(
			    "%s    ino=%-5u off=%-4d rlen=%-3d \"%.*s\"\n",
			    pri->pname,
			    dp->d_ino,
			    dp->d_off,
			    dp->d_reclen,
			    dp->d_reclen - (int)(dp->d_name - (char *)dp),
			    dp->d_name);
			nb -= dp->d_reclen;
			count -= dp->d_reclen;
			offset += dp->d_reclen;
			/* LINTED improper alignment */
			dp = (struct dirent32 *)((char *)dp + dp->d_reclen);
		}
	}

	/* exit region of lengthy output */
	if (serial)
		Xserialize();
}

void
show_dents64(private_t *pri, long offset, long count)
{
	long long buf[MYBUFSIZ / sizeof (long long)];
	struct dirent64 *dp;
	int serial = (count > 100);

	if (offset == 0)
		return;

	/* enter region of lengthy output */
	if (serial)
		Eserialize();

	while (count > 0 && !interrupt) {
		int nb = count < MYBUFSIZ? (int)count : MYBUFSIZ;

		if ((nb = Pread(Proc, &buf[0], (size_t)nb, offset)) <= 0)
			break;

		dp = (struct dirent64 *)&buf[0];
		if (nb < (int)(dp->d_name - (char *)dp))
			break;
		if ((unsigned)nb < dp->d_reclen) {
			/* getdents() error? */
			(void) printf(
			    "%s    ino=%-5llu off=%-4lld rlen=%-3d\n",
			    pri->pname,
			    (long long)dp->d_ino,
			    (long long)dp->d_off,
			    dp->d_reclen);
			break;
		}

		while (!interrupt &&
		    nb >= (int)(dp->d_name - (char *)dp) &&
		    (unsigned)nb >= dp->d_reclen) {
			(void) printf(
			    "%s    ino=%-5llu off=%-4lld rlen=%-3d \"%.*s\"\n",
			    pri->pname,
			    (long long)dp->d_ino,
			    (long long)dp->d_off,
			    dp->d_reclen,
			    dp->d_reclen - (int)(dp->d_name - (char *)dp),
			    dp->d_name);
			nb -= dp->d_reclen;
			count -= dp->d_reclen;
			offset += dp->d_reclen;
			/* LINTED improper alignment */
			dp = (struct dirent64 *)((char *)dp + dp->d_reclen);
		}
	}

	/* exit region of lengthy output */
	if (serial)
		Xserialize();
}

void
show_rlimit32(private_t *pri, long offset)
{
	struct rlimit32 rlimit;

	if (offset != NULL &&
	    Pread(Proc, &rlimit, sizeof (rlimit), offset) == sizeof (rlimit)) {
		(void) printf("%s\t", pri->pname);
		switch (rlimit.rlim_cur) {
		case RLIM32_INFINITY:
			(void) fputs("cur = RLIM_INFINITY", stdout);
			break;
		case RLIM32_SAVED_MAX:
			(void) fputs("cur = RLIM_SAVED_MAX", stdout);
			break;
		case RLIM32_SAVED_CUR:
			(void) fputs("cur = RLIM_SAVED_CUR", stdout);
			break;
		default:
			(void) printf("cur = %lu", (long)rlimit.rlim_cur);
			break;
		}
		switch (rlimit.rlim_max) {
		case RLIM32_INFINITY:
			(void) fputs("  max = RLIM_INFINITY\n", stdout);
			break;
		case RLIM32_SAVED_MAX:
			(void) fputs("  max = RLIM_SAVED_MAX\n", stdout);
			break;
		case RLIM32_SAVED_CUR:
			(void) fputs("  max = RLIM_SAVED_CUR\n", stdout);
			break;
		default:
			(void) printf("  max = %lu\n", (long)rlimit.rlim_max);
			break;
		}
	}
}

void
show_rlimit64(private_t *pri, long offset)
{
	struct rlimit64 rlimit;

	if (offset != NULL &&
	    Pread(Proc, &rlimit, sizeof (rlimit), offset) == sizeof (rlimit)) {
		(void) printf("%s\t", pri->pname);
		switch (rlimit.rlim_cur) {
		case RLIM64_INFINITY:
			(void) fputs("cur = RLIM64_INFINITY", stdout);
			break;
		case RLIM64_SAVED_MAX:
			(void) fputs("cur = RLIM64_SAVED_MAX", stdout);
			break;
		case RLIM64_SAVED_CUR:
			(void) fputs("cur = RLIM64_SAVED_CUR", stdout);
			break;
		default:
			(void) printf("cur = %llu",
			    (unsigned long long)rlimit.rlim_cur);
			break;
		}
		switch (rlimit.rlim_max) {
		case RLIM64_INFINITY:
			(void) fputs("  max = RLIM64_INFINITY\n", stdout);
			break;
		case RLIM64_SAVED_MAX:
			(void) fputs("  max = RLIM64_SAVED_MAX\n", stdout);
			break;
		case RLIM64_SAVED_CUR:
			(void) fputs("  max = RLIM64_SAVED_CUR\n", stdout);
			break;
		default:
			(void) printf("  max = %llu\n",
			    (unsigned long long)rlimit.rlim_max);
			break;
		}
	}
}

void
show_nuname(private_t *pri, long offset)
{
	struct utsname ubuf;

	if (offset != NULL &&
	    Pread(Proc, &ubuf, sizeof (ubuf), offset) == sizeof (ubuf)) {
		(void) printf(
		    "%s\tsys=%s nod=%s rel=%s ver=%s mch=%s\n",
		    pri->pname,
		    ubuf.sysname,
		    ubuf.nodename,
		    ubuf.release,
		    ubuf.version,
		    ubuf.machine);
	}
}

void
show_adjtime(private_t *pri, long off1, long off2)
{
	show_timeval(pri, off1, "   delta");
	show_timeval(pri, off2, "olddelta");
}

void
show_sockaddr(private_t *pri,
	const char *str, long addroff, long lenoff, long len)
{
	/*
	 * A buffer large enough for PATH_MAX size AF_UNIX address, which is
	 * also large enough to store a sockaddr_in or a sockaddr_in6.
	 */
	long buf[(sizeof (short) + PATH_MAX + sizeof (long) - 1)
	    / sizeof (long)];
	struct sockaddr *sa = (struct sockaddr *)buf;
	struct sockaddr_in *sin = (struct sockaddr_in *)buf;
	struct sockaddr_un *soun = (struct sockaddr_un *)buf;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)buf;
	char addrbuf[INET6_ADDRSTRLEN];

	if (lenoff != 0) {
		uint_t ilen;
		if (Pread(Proc, &ilen, sizeof (ilen), lenoff) != sizeof (ilen))
			return;
		len = ilen;
	}

	if (len >= sizeof (buf))	/* protect against ridiculous length */
		len = sizeof (buf) - 1;
	if (Pread(Proc, buf, len, addroff) != len)
		return;

	switch (sa->sa_family) {
	case AF_INET6:
		(void) printf("%s\tAF_INET6  %s = %s  port = %u\n",
		    pri->pname, str,
		    inet_ntop(AF_INET6, &sin6->sin6_addr, addrbuf,
		    sizeof (addrbuf)),
		    ntohs(sin6->sin6_port));
		(void) printf("%s\tscope id = %u  source id = 0x%x\n"
		    "%s\tflow class = 0x%02x  flow label = 0x%05x\n",
		    pri->pname, ntohl(sin6->sin6_scope_id),
		    ntohl(sin6->__sin6_src_id),
		    pri->pname,
		    ntohl((sin6->sin6_flowinfo & IPV6_FLOWINFO_TCLASS) >> 20),
		    ntohl(sin6->sin6_flowinfo & IPV6_FLOWINFO_FLOWLABEL));
		break;
	case AF_INET:
		(void) printf("%s\tAF_%s  %s = %s  port = %u\n",
		    pri->pname, "INET",
		    str, inet_ntop(AF_INET, &sin->sin_addr, addrbuf,
		    sizeof (addrbuf)), ntohs(sin->sin_port));
		break;
	case AF_UNIX:
		len -= sizeof (soun->sun_family);
		if (len >= 0) {
			/* Null terminate */
			soun->sun_path[len] = NULL;
			(void) printf("%s\tAF_UNIX  %s = %s\n", pri->pname,
			    str, soun->sun_path);
		}
		break;
	}
}

void
show_msghdr(private_t *pri, long offset)
{
	const lwpstatus_t *Lsp = pri->lwpstat;
	int what = Lsp->pr_what;
	int err = pri->Errno;
	struct msghdr msg;
	int showbuf = FALSE;
	int i = pri->sys_args[0]+1;
	long nb = (what == SYS_recvmsg)? pri->Rval1 : 32*1024;

	if (Pread(Proc, &msg, sizeof (msg), offset) != sizeof (msg))
		return;

	if (msg.msg_name != NULL && msg.msg_namelen != 0)
		show_sockaddr(pri, "msg_name",
		    (long)msg.msg_name, 0, (long)msg.msg_namelen);

	/*
	 * Print the iovec if the syscall was successful and the fd is
	 * part of the set being traced.
	 */
	if ((what == SYS_recvmsg && !err &&
	    prismember(&readfd, i)) ||
	    (what == SYS_sendmsg &&
	    prismember(&writefd, i)))
		showbuf = TRUE;

	show_iovec(pri, (long)msg.msg_iov, msg.msg_iovlen, showbuf, nb);

}

#ifdef _LP64
void
show_msghdr32(private_t *pri, long offset)
{
	struct msghdr32 {
		caddr32_t	msg_name;
		uint32_t	msg_namelen;
		caddr32_t 	msg_iov;
		int32_t		msg_iovlen;
	} msg;
	const lwpstatus_t *Lsp = pri->lwpstat;
	int what = Lsp->pr_what;
	int err = pri->Errno;
	int showbuf = FALSE;
	int i = pri->sys_args[0]+1;
	long nb = (what == SYS_recvmsg)? pri->Rval1 : 32*1024;

	if (Pread(Proc, &msg, sizeof (msg), offset) != sizeof (msg))
		return;

	if (msg.msg_name != NULL && msg.msg_namelen != 0)
		show_sockaddr(pri, "msg_name",
		    (long)msg.msg_name, 0, (long)msg.msg_namelen);
	/*
	 * Print the iovec if the syscall was successful and the fd is
	 * part of the set being traced.
	 */
	if ((what == SYS_recvmsg && !err &&
	    prismember(&readfd, i)) ||
	    (what == SYS_sendmsg &&
	    prismember(&writefd, i)))
		showbuf = TRUE;

	show_iovec32(pri, (long)msg.msg_iov, msg.msg_iovlen, showbuf, nb);

}
#endif	/* _LP64 */

static void
show_doorargs(private_t *pri, long offset)
{
	door_arg_t args;

	if (Pread(Proc, &args, sizeof (args), offset) == sizeof (args)) {
		(void) printf("%s\tdata_ptr=0x%lX data_size=%lu\n",
		    pri->pname,
		    (ulong_t)args.data_ptr,
		    (ulong_t)args.data_size);
		(void) printf("%s\tdesc_ptr=0x%lX desc_num=%u\n",
		    pri->pname,
		    (ulong_t)args.desc_ptr,
		    args.desc_num);
		(void) printf("%s\trbuf=0x%lX rsize=%lu\n",
		    pri->pname,
		    (ulong_t)args.rbuf,
		    (ulong_t)args.rsize);
	}
}

static void
show_ucred_privsets(private_t *pri, ucred_t *uc)
{
	int i = 0;
	const priv_set_t *s;
	priv_ptype_t sn;
	char *str;

	while ((sn = priv_getsetbynum(i++)) != NULL) {
		s = ucred_getprivset(uc, sn);

		if (s == NULL)
			continue;

		(void) printf("%s\t%c: %s\n",
		    pri->pname,
		    *sn,
		    str = priv_set_to_str(s, ',', PRIV_STR_SHORT));

		free(str);
	}
}

static void
show_ucred(private_t *pri, long offset)
{
	ucred_t *uc = _ucred_alloc();
	size_t sz;

	if (uc == NULL)
		return;

	sz = Pread(Proc, uc, uc->uc_size, offset);

	/*
	 * A new uc_size is read, it could be smaller than the previously
	 * value.  We accept short reads that fill the whole header.
	 */
	if (sz >= sizeof (ucred_t) && sz >= uc->uc_size) {
		(void) printf("%s\teuid=%u egid=%u\n",
		    pri->pname,
		    ucred_geteuid(uc),
		    ucred_getegid(uc));
		(void) printf("%s\truid=%u rgid=%u\n",
		    pri->pname,
		    ucred_getruid(uc),
		    ucred_getrgid(uc));
		(void) printf("%s\tpid=%d zoneid=%d\n",
		    pri->pname,
		    (int)ucred_getpid(uc),
		    (int)ucred_getzoneid(uc));
		show_ucred_privsets(pri, uc);
	}
	ucred_free(uc);
}

static void
show_privset(private_t *pri, long offset, size_t size, char *label)
{
	priv_set_t *tmp = priv_allocset();
	size_t sz;

	if (tmp == NULL)
		return;

	sz = Pread(Proc, tmp, size, offset);

	if (sz == size) {
		char *str = priv_set_to_str(tmp, ',', PRIV_STR_SHORT);
		if (str != NULL) {
			(void) printf("%s\t%s%s\n", pri->pname, label, str);
			free(str);
		}
	}
	priv_freeset(tmp);
}

static void
show_doorinfo(private_t *pri, long offset)
{
	door_info_t info;
	door_attr_t attr;

	if (Pread(Proc, &info, sizeof (info), offset) != sizeof (info))
		return;
	(void) printf("%s\ttarget=%d proc=0x%llX data=0x%llX\n",
	    pri->pname,
	    (int)info.di_target,
	    info.di_proc,
	    info.di_data);
	attr = info.di_attributes;
	(void) printf("%s\tattributes=%s\n", pri->pname, door_flags(pri, attr));
	(void) printf("%s\tuniquifier=%llu\n", pri->pname, info.di_uniquifier);
}

static void
show_doorparam(private_t *pri, long offset)
{
	ulong_t val;

	if (Pread(Proc, &val, sizeof (val), offset) == sizeof (val)) {
		(void) printf("%s\tvalue=%lu\n",
		    pri->pname,
		    val);
	}
}

#ifdef _LP64

static void
show_doorargs32(private_t *pri, long offset)
{
	struct door_arg32 args;

	if (Pread(Proc, &args, sizeof (args), offset) == sizeof (args)) {
		(void) printf("%s\tdata_ptr=%X data_size=%u\n",
		    pri->pname,
		    args.data_ptr,
		    args.data_size);
		(void) printf("%s\tdesc_ptr=0x%X desc_num=%u\n",
		    pri->pname,
		    args.desc_ptr,
		    args.desc_num);
		(void) printf("%s\trbuf=0x%X rsize=%u\n",
		    pri->pname,
		    args.rbuf,
		    args.rsize);
	}
}

static void
show_doorparam32(private_t *pri, long offset)
{
	uint_t val;

	if (Pread(Proc, &val, sizeof (val), offset) == sizeof (val)) {
		(void) printf("%s\tvalue=%u\n",
		    pri->pname,
		    val);
	}
}

#endif	/* _LP64 */

static void
show_doors(private_t *pri)
{
	switch (pri->sys_args[5]) {
	case DOOR_CALL:
#ifdef _LP64
		if (data_model == PR_MODEL_LP64)
			show_doorargs(pri, (long)pri->sys_args[1]);
		else
			show_doorargs32(pri, (long)pri->sys_args[1]);
#else
		show_doorargs(pri, (long)pri->sys_args[1]);
#endif
		break;
	case DOOR_UCRED:
		if (!pri->Errno)
			show_ucred(pri, (long)pri->sys_args[0]);
		break;
	case DOOR_INFO:
		if (!pri->Errno)
			show_doorinfo(pri, (long)pri->sys_args[1]);
		break;
	case DOOR_GETPARAM:
		if (!pri->Errno) {
#ifdef _LP64
			if (data_model == PR_MODEL_LP64)
				show_doorparam(pri, (long)pri->sys_args[2]);
			else
				show_doorparam32(pri, (long)pri->sys_args[2]);
#else
			show_doorparam(pri, (long)pri->sys_args[2]);
#endif
		}
		break;
	}
}

static void
show_portargs(private_t *pri, long offset)
{
	port_event_t args;

	if (Pread(Proc, &args, sizeof (args), offset) == sizeof (args)) {
		(void) printf("%s\tevents=0x%x source=%u\n",
		    pri->pname,
		    args.portev_events,
		    args.portev_source);
		(void) printf("%s\tobject=0x%p user=0x%p\n",
		    pri->pname,
		    (void *)args.portev_object,
		    (void *)args.portev_user);
	}
}


#ifdef _LP64

static void
show_portargs32(private_t *pri, long offset)
{
	port_event32_t args;

	if (Pread(Proc, &args, sizeof (args), offset) == sizeof (args)) {
		(void) printf("%s\tevents=0x%x source=%u\n",
		    pri->pname,
		    args.portev_events,
		    args.portev_source);
		(void) printf("%s\tobject=0x%x user=0x%x\n",
		    pri->pname,
		    args.portev_object,
		    args.portev_user);
	}
}

#endif	/* _LP64 */

static void
show_ports(private_t *pri)
{
	switch (pri->sys_args[0]) {
	case PORT_GET:
#ifdef _LP64
		if (data_model == PR_MODEL_LP64)
			show_portargs(pri, (long)pri->sys_args[2]);
		else
			show_portargs32(pri, (long)pri->sys_args[2]);
#else
		show_portargs(pri, (long)pri->sys_args[2]);
#endif
		break;
	}
}

#define	MAX_SNDFL_PRD 16

#ifdef _LP64

static void
show_ksendfilevec32(private_t *pri, int fd,
    ksendfilevec32_t *sndvec, int sfvcnt)
{
	ksendfilevec32_t *snd_ptr, snd[MAX_SNDFL_PRD];
	size_t cpy_rqst;

	Eserialize();
	while (sfvcnt > 0) {
		cpy_rqst = MIN(sfvcnt, MAX_SNDFL_PRD);
		sfvcnt -= cpy_rqst;
		cpy_rqst *= sizeof (snd[0]);

		if (Pread(Proc, snd, cpy_rqst, (uintptr_t)sndvec) != cpy_rqst)
			break;

		snd_ptr = &snd[0];

		while (cpy_rqst) {
			(void) printf(
			    "sfv_fd=%d\tsfv_flag=0x%x\t"
			    "sfv_off=%d\tsfv_len=%u\n",
			    snd_ptr->sfv_fd,
			    snd_ptr->sfv_flag,
			    snd_ptr->sfv_off,
			    snd_ptr->sfv_len);

			if (snd_ptr->sfv_fd == SFV_FD_SELF &&
			    prismember(&writefd, fd)) {
				showbuffer(pri,
				    (long)snd_ptr->sfv_off & 0xffffffff,
				    (long)snd_ptr->sfv_len);
			}

			cpy_rqst -= sizeof (snd[0]);
			snd_ptr++;
		}

		sndvec += MAX_SNDFL_PRD;
	}
	Xserialize();
}

static void
show_ksendfilevec64(private_t *pri, int fd,
    ksendfilevec64_t *sndvec, int sfvcnt)
{
	ksendfilevec64_t *snd_ptr, snd[MAX_SNDFL_PRD];
	size_t cpy_rqst;

	Eserialize();
	while (sfvcnt > 0) {
		cpy_rqst = MIN(sfvcnt, MAX_SNDFL_PRD);
		sfvcnt -= cpy_rqst;
		cpy_rqst *= sizeof (snd[0]);

		if (Pread(Proc, snd, cpy_rqst, (uintptr_t)sndvec) != cpy_rqst)
			break;

		snd_ptr = &snd[0];

		while (cpy_rqst) {
			(void) printf(
			    "sfv_fd=%d\tsfv_flag=0x%x\t"
			    "sfv_off=%ld\tsfv_len=%u\n",
			    snd_ptr->sfv_fd,
			    snd_ptr->sfv_flag,
			    snd_ptr->sfv_off,
			    snd_ptr->sfv_len);

			if (snd_ptr->sfv_fd == SFV_FD_SELF &&
			    prismember(&writefd, fd)) {
				showbuffer(pri,
				    (long)snd_ptr->sfv_off & 0xffffffff,
				    (long)snd_ptr->sfv_len);
			}

			cpy_rqst -= sizeof (snd[0]);
			snd_ptr++;
		}

		sndvec += MAX_SNDFL_PRD;
	}
	Xserialize();
}

#endif /* _LP64 */

/*ARGSUSED*/
static void
show_sendfilevec(private_t *pri, int fd, sendfilevec_t *sndvec, int sfvcnt)
{
	sendfilevec_t *snd_ptr, snd[MAX_SNDFL_PRD];
	size_t cpy_rqst;

#ifdef _LP64
	if (data_model != PR_MODEL_LP64) {
		show_ksendfilevec32(pri, fd,
		    (ksendfilevec32_t *)sndvec, sfvcnt);
		return;
	}
#endif
	Eserialize();
	while (sfvcnt > 0) {
		cpy_rqst = MIN(sfvcnt, MAX_SNDFL_PRD);
		sfvcnt -= cpy_rqst;
		cpy_rqst *= sizeof (snd[0]);

		if (Pread(Proc, snd, cpy_rqst, (uintptr_t)sndvec) != cpy_rqst)
			break;

		snd_ptr = &snd[0];

		while (cpy_rqst) {
			(void) printf(
			    "sfv_fd=%d\tsfv_flag=0x%x\t"
			    "sfv_off=%ld\tsfv_len=%lu\n",
			    snd_ptr->sfv_fd,
			    snd_ptr->sfv_flag,
			    snd_ptr->sfv_off,
			    (ulong_t)snd_ptr->sfv_len);

			if (snd_ptr->sfv_fd == SFV_FD_SELF &&
			    prismember(&writefd, fd)) {
				showbuffer(pri, (long)snd_ptr->sfv_off,
				    (long)snd_ptr->sfv_len);
			}

			cpy_rqst -= sizeof (snd[0]);
			snd_ptr++;
		}

		sndvec += MAX_SNDFL_PRD;
	}
	Xserialize();
}

/*ARGSUSED*/
static void
show_sendfilevec64(private_t *pri, int fd, sendfilevec64_t *sndvec, int sfvcnt)
{
	sendfilevec64_t *snd_ptr, snd[MAX_SNDFL_PRD];
	size_t cpy_rqst;

#ifdef _LP64
	if (data_model != PR_MODEL_LP64) {
		show_ksendfilevec64(pri, fd,
		    (ksendfilevec64_t *)sndvec, sfvcnt);
		return;
	}
#endif

	Eserialize();
	while (sfvcnt > 0) {
		cpy_rqst = MIN(sfvcnt, MAX_SNDFL_PRD);
		sfvcnt -= cpy_rqst;
		cpy_rqst *= sizeof (snd[0]);

		if (Pread(Proc, snd, cpy_rqst, (uintptr_t)sndvec) != cpy_rqst)
			break;

		snd_ptr = &snd[0];

		while (cpy_rqst) {
			(void) printf(
#ifdef _LP64
			    "sfv_fd=%d\tsfv_flag=0x%x\t"
			    "sfv_off=%ld\tsfv_len=%lu\n",
#else
			    "sfv_fd=%d\tsfv_flag=0x%x\t"
			    "sfv_off=%lld\tsfv_len=%lu\n",
#endif
			    snd_ptr->sfv_fd,
			    snd_ptr->sfv_flag,
			    snd_ptr->sfv_off,
			    (ulong_t)snd_ptr->sfv_len);

			if (snd_ptr->sfv_fd == SFV_FD_SELF &&
			    prismember(&writefd, fd)) {
				showbuffer(pri, (long)snd_ptr->sfv_off,
				    (long)snd_ptr->sfv_len);
			}

			cpy_rqst -= sizeof (snd[0]);
			snd_ptr++;
		}

		sndvec += MAX_SNDFL_PRD;
	}
	Xserialize();
}

static void
show_memcntl_mha(private_t *pri, long offset)
{
	struct memcntl_mha mha;
	const char *s = NULL;

	if (Pread(Proc, &mha, sizeof (mha), offset) == sizeof (mha)) {
		switch (mha.mha_cmd) {
		case MHA_MAPSIZE_VA:	    s = "MHA_MAPSIZE_VA";	break;
		case MHA_MAPSIZE_BSSBRK:    s = "MHA_MAPSIZE_BSSBRK";	break;
		case MHA_MAPSIZE_STACK:	    s = "MHA_MAPSIZE_STACK";	break;
		}
		if (s)
			(void) printf("%s\tmha_cmd=%s mha_flags=0x%x"
			    " mha_pagesize=%lu\n",
			    pri->pname, s, mha.mha_flags,
			    (ulong_t)mha.mha_pagesize);
		else
			(void) printf("%s\tmha_cmd=0x%.8x mha_flags=0x%x"
			    " mha_pagesize=%lu\n",
			    pri->pname, mha.mha_cmd, mha.mha_flags,
			    (ulong_t)mha.mha_pagesize);
	}
}

#ifdef _LP64

static void
show_memcntl_mha32(private_t *pri, long offset)
{
	struct memcntl_mha32 mha32;
	const char *s = NULL;

	if (Pread(Proc, &mha32, sizeof (mha32), offset) ==
	    sizeof (mha32)) {
		switch (mha32.mha_cmd) {
		case MHA_MAPSIZE_VA:	    s = "MHA_MAPSIZE_VA";	break;
		case MHA_MAPSIZE_BSSBRK:    s = "MHA_MAPSIZE_BSSBRK";	break;
		case MHA_MAPSIZE_STACK:	    s = "MHA_MAPSIZE_STACK";	break;
		}
		if (s)
			(void) printf("%s\tmha_cmd=%s mha_flags=0x%x"
			    " mha_pagesize=%u\n",
			    pri->pname, s, mha32.mha_flags, mha32.mha_pagesize);
		else
			(void) printf("%s\tmha_cmd=0x%.8x mha_flags=0x%x"
			    " mha_pagesize=%u\n",
			    pri->pname, mha32.mha_cmd, mha32.mha_flags,
			    mha32.mha_pagesize);
	}
}

#endif	/* _LP64 */

static void
show_memcntl(private_t *pri)
{

	if ((int)pri->sys_args[2] != MC_HAT_ADVISE)
		return;
#ifdef _LP64
	if (data_model == PR_MODEL_LP64)
		show_memcntl_mha(pri, (long)pri->sys_args[3]);
	else
		show_memcntl_mha32(pri, (long)pri->sys_args[3]);
#else
	show_memcntl_mha(pri, (long)pri->sys_args[3]);
#endif
}

void
show_ids(private_t *pri, long offset, int count)
{
	id_t buf[MYBUFSIZ / sizeof (id_t)];
	id_t *idp;
	int serial = (count > MYBUFSIZ / 48);

	if (offset == 0)
		return;

	/* enter region of lengthy output */
	if (serial)
		Eserialize();

	while (count > 0 && !interrupt) {
		ssize_t nb = (count * sizeof (id_t) < MYBUFSIZ)?
		    count * sizeof (id_t) : MYBUFSIZ;

		if ((nb = Pread(Proc, &buf[0], (size_t)nb, offset)) < 0 ||
		    nb < sizeof (id_t))
			break;

		idp = buf;
		while (!interrupt && nb >= sizeof (id_t)) {
			(void) printf("%s\t%8d\n", pri->pname, (int)*idp);
			offset += sizeof (id_t);
			nb -= sizeof (id_t);
			idp++;
			count--;
		}
	}

	/* exit region of lengthy output */
	if (serial)
		Xserialize();
}

void
show_ntp_gettime(private_t *pri)
{
	struct ntptimeval ntv;
	long offset;

	if (pri->sys_nargs < 1 || (offset = pri->sys_args[0]) == NULL)
		return;

	if (data_model == PR_MODEL_NATIVE) {
		if (Pread(Proc, &ntv, sizeof (ntv), offset)
		    != sizeof (ntv))
			return;
	} else {
		struct ntptimeval32 ntv32;

		if (Pread(Proc, &ntv32, sizeof (ntv32), offset)
		    != sizeof (ntv32))
			return;

		TIMEVAL32_TO_TIMEVAL(&ntv.time, &ntv32.time);
		ntv.maxerror = ntv32.maxerror;
		ntv.esterror = ntv32.esterror;
	}

	(void) printf("\ttime:     %ld.%6.6ld sec\n",
	    ntv.time.tv_sec, ntv.time.tv_usec);
	(void) printf("\tmaxerror: %11d usec\n", ntv.maxerror);
	(void) printf("\testerror: %11d usec\n", ntv.esterror);
}

static char *
get_timex_modes(private_t *pri, uint32_t val)
{
	char *str = pri->code_buf;
	size_t used = 0;

	*str = '\0';
	if (val & MOD_OFFSET)
		used = strlcat(str, "|MOD_OFFSET", sizeof (pri->code_buf));
	if (val & MOD_FREQUENCY)
		used = strlcat(str, "|MOD_FREQUENCY", sizeof (pri->code_buf));
	if (val & MOD_MAXERROR)
		used = strlcat(str, "|MOD_MAXERROR", sizeof (pri->code_buf));
	if (val & MOD_ESTERROR)
		used = strlcat(str, "|MOD_ESTERROR", sizeof (pri->code_buf));
	if (val & MOD_STATUS)
		used = strlcat(str, "|MOD_STATUS", sizeof (pri->code_buf));
	if (val & MOD_TIMECONST)
		used = strlcat(str, "|MOD_TIMECONST", sizeof (pri->code_buf));
	if (val & MOD_CLKB)
		used = strlcat(str, "|MOD_CLKB", sizeof (pri->code_buf));
	if (val & MOD_CLKA)
		used = strlcat(str, "|MOD_CLKA", sizeof (pri->code_buf));

	if (used == 0 || used >= sizeof (pri->code_buf))
		(void) snprintf(str, sizeof (pri->code_buf), " 0x%.4x", val);

	return (str + 1);
}

static char *
get_timex_status(private_t *pri, int32_t val)
{
	char *str = pri->code_buf;
	size_t used = 0;

	*str = '\0';
	if (val & STA_PLL)
		used = strlcat(str, "|STA_PLL", sizeof (pri->code_buf));
	if (val & STA_PPSFREQ)
		used = strlcat(str, "|STA_PPSFREQ", sizeof (pri->code_buf));
	if (val & STA_PPSTIME)
		used = strlcat(str, "|STA_PPSTIME", sizeof (pri->code_buf));
	if (val & STA_FLL)
		used = strlcat(str, "|STA_FLL", sizeof (pri->code_buf));

	if (val & STA_INS)
		used = strlcat(str, "|STA_INS", sizeof (pri->code_buf));
	if (val & STA_DEL)
		used = strlcat(str, "|STA_DEL", sizeof (pri->code_buf));
	if (val & STA_UNSYNC)
		used = strlcat(str, "|STA_UNSYNC", sizeof (pri->code_buf));
	if (val & STA_FREQHOLD)
		used = strlcat(str, "|STA_FREQHOLD", sizeof (pri->code_buf));

	if (val & STA_PPSSIGNAL)
		used = strlcat(str, "|STA_PPSSIGNAL", sizeof (pri->code_buf));
	if (val & STA_PPSJITTER)
		used = strlcat(str, "|STA_PPSJITTER", sizeof (pri->code_buf));
	if (val & STA_PPSWANDER)
		used = strlcat(str, "|STA_PPSWANDER", sizeof (pri->code_buf));
	if (val & STA_PPSERROR)
		used = strlcat(str, "|STA_PPSERROR", sizeof (pri->code_buf));

	if (val & STA_CLOCKERR)
		used = strlcat(str, "|STA_CLOCKERR", sizeof (pri->code_buf));

	if (used == 0 || used >= sizeof (pri->code_buf))
		(void) snprintf(str, sizeof (pri->code_buf), " 0x%.4x", val);

	return (str + 1);
}

void
show_ntp_adjtime(private_t *pri)
{
	struct timex timex;
	long offset;

	if (pri->sys_nargs < 1 || (offset = pri->sys_args[0]) == NULL)
		return;

	if (Pread(Proc, &timex, sizeof (timex), offset) != sizeof (timex))
		return;

	(void) printf("\tmodes:     %s\n", get_timex_modes(pri, timex.modes));
	(void) printf("\toffset:    %11d usec\n", timex.offset);
	(void) printf("\tfreq:      %11d scaled ppm\n", timex.freq);
	(void) printf("\tmaxerror:  %11d usec\n", timex.maxerror);
	(void) printf("\testerror:  %11d usec\n", timex.esterror);
	(void) printf("\tstatus:    %s\n", get_timex_status(pri, timex.status));
	(void) printf("\tconstant:  %11d\n", timex.constant);
	(void) printf("\tprecision: %11d usec\n", timex.precision);
	(void) printf("\ttolerance: %11d scaled ppm\n", timex.tolerance);
	(void) printf("\tppsfreq:   %11d scaled ppm\n", timex.ppsfreq);
	(void) printf("\tjitter:    %11d usec\n", timex.jitter);
	(void) printf("\tshift:     %11d sec\n", timex.shift);
	(void) printf("\tstabil:    %11d scaled ppm\n", timex.stabil);
	(void) printf("\tjitcnt:    %11d\n", timex.jitcnt);
	(void) printf("\tcalcnt:    %11d\n", timex.calcnt);
	(void) printf("\terrcnt:    %11d\n", timex.errcnt);
	(void) printf("\tstbcnt:    %11d\n", timex.stbcnt);
}

void
show_getrusage(long offset)
{
	struct rusage r;
	if (Pread(Proc, &r, sizeof (r), offset) != sizeof (r))
		return;
	(void) printf("\t       user time: %ld.%6.6ld sec\n",
	    r.ru_utime.tv_sec,
	    r.ru_utime.tv_usec);
	(void) printf("\t     system time: %ld.%6.6ld sec\n",
	    r.ru_stime.tv_sec,
	    r.ru_stime.tv_usec);
	(void) printf("\t         max rss: <unimpl> %ld\n",
	    r.ru_maxrss);
	(void) printf("\t     shared data: <unimpl> %ld\n",
	    r.ru_ixrss);
	(void) printf("\t   unshared data: <unimpl> %ld\n",
	    r.ru_idrss);
	(void) printf("\t  unshared stack: <unimpl> %ld\n",
	    r.ru_isrss);
	(void) printf("\t    minor faults: %ld\n",
	    r.ru_minflt);
	(void) printf("\t    major faults: %ld\n",
	    r.ru_majflt);
	(void) printf("\t      # of swaps: %ld\n",
	    r.ru_nswap);
	(void) printf("\t  blocked inputs: %ld\n",
	    r.ru_inblock);
	(void) printf("\t blocked outputs: %ld\n",
	    r.ru_oublock);
	(void) printf("\t       msgs sent: %ld\n",
	    r.ru_msgsnd);
	(void) printf("\t      msgs rcv'd: %ld\n",
	    r.ru_msgrcv);
	(void) printf("\t   signals rcv'd: %ld\n",
	    r.ru_nsignals);
	(void) printf("\tvol cntxt swtchs: %ld\n",
	    r.ru_nvcsw);
	(void) printf("\tinv cntxt swtchs: %ld\n",
	    r.ru_nivcsw);
}

#ifdef _LP64
void
show_getrusage32(long offset)
{
	struct rusage32 r;
	if (Pread(Proc, &r, sizeof (r), offset) != sizeof (r))
		return;
	(void) printf("\t       user time: %d.%6.6d sec\n",
	    r.ru_utime.tv_sec,
	    r.ru_utime.tv_usec);
	(void) printf("\t     system time: %d.%6.6d sec\n",
	    r.ru_stime.tv_sec,
	    r.ru_stime.tv_usec);
	(void) printf("\t         max rss: <unimpl> %d\n",
	    r.ru_maxrss);
	(void) printf("\t     shared data: <unimpl> %d\n",
	    r.ru_ixrss);
	(void) printf("\t   unshared data: <unimpl> %d\n",
	    r.ru_idrss);
	(void) printf("\t  unshared stack: <unimpl> %d\n",
	    r.ru_isrss);
	(void) printf("\t    minor faults: %d\n",
	    r.ru_minflt);
	(void) printf("\t    major faults: %d\n",
	    r.ru_majflt);
	(void) printf("\t      # of swaps: %d\n",
	    r.ru_nswap);
	(void) printf("\t  blocked inputs: %d\n",
	    r.ru_inblock);
	(void) printf("\t blocked outputs: %d\n",
	    r.ru_oublock);
	(void) printf("\t       msgs sent: %d\n",
	    r.ru_msgsnd);
	(void) printf("\t      msgs rcv'd: %d\n",
	    r.ru_msgrcv);
	(void) printf("\t   signals rcv'd: %d\n",
	    r.ru_nsignals);
	(void) printf("\tvol cntxt swtchs: %d\n",
	    r.ru_nvcsw);
	(void) printf("\tinv cntxt swtchs: %d\n",
	    r.ru_nivcsw);
}
#endif

/*
 * Utility function to print a packed nvlist by unpacking
 * and calling the libnvpair pretty printer.  Frees all
 * allocated memory internally.
 */
static void
show_packed_nvlist(private_t *pri, uintptr_t offset, size_t size)
{
	nvlist_t *nvl = NULL;
	size_t readsize;
	char *buf;

	if ((offset == 0) || (size == 0)) {
		return;
	}

	buf = my_malloc(size, "nvlist decode buffer");
	readsize = Pread(Proc, buf, size, offset);
	if (readsize != size) {
		(void) printf("%s\t<?>", pri->pname);
	} else {
		int result;

		result = nvlist_unpack(buf, size, &nvl, 0);
		if (result == 0) {
			dump_nvlist(nvl, 8);
			nvlist_free(nvl);
		} else {
			(void) printf("%s\tunpack of nvlist"
			    " failed: %d\n", pri->pname, result);
		}
	}
	free(buf);
}

static void
show_zone_create_args(private_t *pri, long offset)
{
	zone_def args;
	char zone_name[ZONENAME_MAX];
	char zone_root[MAXPATHLEN];
	char *zone_zfs = NULL;

	if (Pread(Proc, &args, sizeof (args), offset) == sizeof (args)) {

		if (Pread_string(Proc, zone_name, sizeof (zone_name),
		    (uintptr_t)args.zone_name) == -1)
			(void) strcpy(zone_name, "<?>");

		if (Pread_string(Proc, zone_root, sizeof (zone_root),
		    (uintptr_t)args.zone_root) == -1)
			(void) strcpy(zone_root, "<?>");

		if (args.zfsbufsz > 0) {
			zone_zfs = malloc(MIN(4, args.zfsbufsz));
			if (zone_zfs != NULL) {
				if (Pread(Proc, zone_zfs, args.zfsbufsz,
				    (uintptr_t)args.zfsbuf) == -1)
					(void) strcpy(zone_zfs, "<?>");
			}
		} else {
			zone_zfs = "";
		}

		(void) printf("%s\t     zone_name: %s\n", pri->pname,
		    zone_name);
		(void) printf("%s\t     zone_root: %s\n", pri->pname,
		    zone_root);

		show_privset(pri, (uintptr_t)args.zone_privs,
		    args.zone_privssz, "    zone_privs: ");

		(void) printf("%s\t       rctlbuf: 0x%p\n", pri->pname,
		    (void *)args.rctlbuf);
		(void) printf("%s\t     rctlbufsz: %lu\n", pri->pname,
		    (ulong_t)args.rctlbufsz);

		show_packed_nvlist(pri, (uintptr_t)args.rctlbuf,
		    args.rctlbufsz);

		(void) printf("%s\t           zfs: %s\n", pri->pname, zone_zfs);

		(void) printf("%s\textended_error: 0x%p\n", pri->pname,
		    (void *)args.extended_error);

		if (is_system_labeled()) {
			char		*label_str = NULL;
			bslabel_t	zone_label;

			(void) printf("%s\t         match: %d\n", pri->pname,
			    args.match);
			(void) printf("%s\t           doi: %d\n", pri->pname,
			    args.doi);

			if (Pread_string(Proc, (char *)&zone_label,
			    sizeof (zone_label), (uintptr_t)args.label) != -1) {
				/* show the label as string */
				if (label_to_str(&zone_label, &label_str,
				    M_LABEL, SHORT_NAMES) != 0) {
					/* have to dump label as raw string */
					(void) label_to_str(&zone_label,
					    &label_str, M_INTERNAL,
					    SHORT_NAMES);
				}
			}

			(void) printf("%s\t         label: %s\n",
			    pri->pname, label_str != NULL ? label_str : "<?>");
			if (label_str)
				free(label_str);
		}

		if (args.zfsbufsz > 0)
			free(zone_zfs);
	}
}


#ifdef _LP64

static void
show_zone_create_args32(private_t *pri, long offset)
{
	zone_def32 args;
	char zone_name[ZONENAME_MAX];
	char zone_root[MAXPATHLEN];
	char *zone_zfs = NULL;

	if (Pread(Proc, &args, sizeof (args), offset) == sizeof (args)) {

		if (Pread_string(Proc, zone_name, sizeof (zone_name),
		    (uintptr_t)args.zone_name) == -1)
			(void) strcpy(zone_name, "<?>");

		if (Pread_string(Proc, zone_root, sizeof (zone_root),
		    (uintptr_t)args.zone_root) == -1)
			(void) strcpy(zone_root, "<?>");

		if (args.zfsbufsz > 0) {
			zone_zfs = malloc(MIN(4, args.zfsbufsz));
			if (zone_zfs != NULL) {
				if (Pread(Proc, zone_zfs, args.zfsbufsz,
				    (uintptr_t)args.zfsbuf) == -1)
					(void) strcpy(zone_zfs, "<?>");
			}
		} else {
			zone_zfs = "";
		}

		(void) printf("%s\t     zone_name: %s\n", pri->pname,
		    zone_name);
		(void) printf("%s\t     zone_root: %s\n", pri->pname,
		    zone_root);

		show_privset(pri, (uintptr_t)args.zone_privs,
		    args.zone_privssz, "    zone_privs: ");

		(void) printf("%s\t       rctlbuf: 0x%x\n", pri->pname,
		    (caddr32_t)args.rctlbuf);
		(void) printf("%s\t     rctlbufsz: %lu\n", pri->pname,
		    (ulong_t)args.rctlbufsz);

		show_packed_nvlist(pri, (uintptr_t)args.rctlbuf,
		    args.rctlbufsz);

		(void) printf("%s\t           zfs: %s\n", pri->pname, zone_zfs);

		(void) printf("%s\textended_error: 0x%x\n", pri->pname,
		    (caddr32_t)args.extended_error);

		if (is_system_labeled()) {
			char		*label_str = NULL;
			bslabel_t	zone_label;

			(void) printf("%s\t         match: %d\n", pri->pname,
			    args.match);
			(void) printf("%s\t           doi: %d\n", pri->pname,
			    args.doi);

			if (Pread_string(Proc, (char *)&zone_label,
			    sizeof (zone_label), (caddr32_t)args.label) != -1) {
				/* show the label as string */
				if (label_to_str(&zone_label, &label_str,
				    M_LABEL, SHORT_NAMES) != 0) {
					/* have to dump label as raw string */
					(void) label_to_str(&zone_label,
					    &label_str, M_INTERNAL,
					    SHORT_NAMES);
				}
			}
			(void) printf("%s\t         label: %s\n",
			    pri->pname, label_str != NULL ? label_str : "<?>");
			if (label_str)
				free(label_str);
		}

		if (args.zfsbufsz > 0)
			free(zone_zfs);
	}
}

#endif

static void
show_zones(private_t *pri)
{
	switch (pri->sys_args[0]) {
	case ZONE_CREATE:
#ifdef _LP64
		if (data_model == PR_MODEL_LP64)
			show_zone_create_args(pri, (long)pri->sys_args[1]);
		else
			show_zone_create_args32(pri, (long)pri->sys_args[1]);
#else
		show_zone_create_args(pri, (long)pri->sys_args[1]);
#endif
		break;
	}
}

static void
show_rctlblk(private_t *pri, long _rctlblk)
{
	rctlblk_t *blk;
	int size = rctlblk_size();
	size_t readsize;
	const char *s;

	blk = my_malloc(size, "rctlblk decode buffer");
	readsize = Pread(Proc, blk, size, _rctlblk);
	if (readsize != size) {
		(void) printf("%s\t\t<?>", pri->pname);
	} else {
		(void) printf("%s\t\t     Privilege: 0x%x\n",
		    pri->pname,
		    rctlblk_get_privilege(blk));
		(void) printf("%s\t\t         Value: %lld\n",
		    pri->pname,
		    rctlblk_get_value(blk));
		(void) printf("%s\t\tEnforced Value: %lld\n",
		    pri->pname,
		    rctlblk_get_enforced_value(blk));

		{
			int sig, act;
			act = rctlblk_get_local_action(blk, &sig);

			s = rctl_local_action(pri, act);
			if (s == NULL) {
				(void) printf("%s\t\t  Local action: 0x%x\n",
				    pri->pname, act);
			} else {
				(void) printf("%s\t\t  Local action: %s\n",
				    pri->pname, s);
			}

			if (act & RCTL_LOCAL_SIGNAL) {
				(void) printf("%s\t\t                "
				    "For signal %s\n",
				    pri->pname, signame(pri, sig));
			}
		}

		s = rctl_local_flags(pri, rctlblk_get_local_flags(blk));
		if (s == NULL) {
			(void) printf("%s\t\t   Local flags: 0x%x\n",
			    pri->pname, rctlblk_get_local_flags(blk));
		} else {
			(void) printf("%s\t\t   Local flags: %s\n",
			    pri->pname, s);
		}

#ifdef _LP64
		(void) printf("%s\t\t Recipient PID: %d\n",
		    pri->pname,
		    rctlblk_get_recipient_pid(blk));
#else
		(void) printf("%s\t\t Recipient PID: %ld\n",
		    pri->pname,
		    rctlblk_get_recipient_pid(blk));
#endif
		(void) printf("%s\t\t   Firing Time: %lld\n",
		    pri->pname,
		    rctlblk_get_firing_time(blk));
	}
	free(blk);
}

static void
show_rctls(private_t *pri)
{
	int entry;

	switch (pri->sys_args[0]) {
	case 0:	/* getrctl */
	case 1: /* setrctl */
		/*
		 * If these offsets look a little odd, remember that they're
		 * into the _raw_ system call
		 */
		(void) printf("%s\tOld rctlblk: 0x%lx\n", pri->pname,
		    pri->sys_args[2]);
		if (pri->sys_args[2] != NULL) {
			show_rctlblk(pri, pri->sys_args[2]);
		}
		(void) printf("%s\tNew rctlblk: 0x%lx\n", pri->pname,
		    pri->sys_args[3]);
		if (pri->sys_args[3] != NULL) {
			show_rctlblk(pri, pri->sys_args[3]);
		}
		break;
	case 4: /* setprojrctl */
		for (entry = 0; entry < pri->sys_args[4]; entry++) {
			(void) printf("%s\tNew rctlblk[%d]: 0x%lx\n",
			    pri->pname, entry,
			    (long)RCTLBLK_INC(pri->sys_args[3], entry));
			if (RCTLBLK_INC(pri->sys_args[3], entry) != NULL) {
				show_rctlblk(pri,
				    (long)RCTLBLK_INC(pri->sys_args[3], entry));
			}
		}
	}
}

void
show_utimesys(private_t *pri)
{
	switch (pri->sys_args[0]) {
	case 0:			/* futimens() */
		if (pri->sys_nargs > 2)
			show_utimens(pri, (long)pri->sys_args[2]);
		break;
	case 1:			/* utimensat */
		if (pri->sys_nargs > 3)
			show_utimens(pri, (long)pri->sys_args[3]);
		break;
	default:		/* unexpected subcode */
		break;
	}
}

#ifdef _LP64
static void
show_sockconfig_filter_prop32(private_t *pri, long addr)
{
	struct sockconfig_filter_props32 props;
	const char *s = NULL;
	char buf[MAX(FILNAME_MAX, MODMAXNAMELEN)];
	sof_socktuple32_t *tup;
	size_t sz;
	int i;

	if (Pread(Proc, &props, sizeof (props), addr) == sizeof (props)) {
		if (Pread_string(Proc, buf, sizeof (buf),
		    (uintptr_t)props.sfp_modname) == -1)
			(void) strcpy(buf, "<?>");
		(void) printf("%s\tmodule name: %s\n", pri->pname, buf);
		(void) printf("%s\tattach semantics: %s", pri->pname,
		    props.sfp_autoattach ? "automatic" : "progammatic");
		if (props.sfp_autoattach) {
			buf[0] = '\0';
			switch (props.sfp_hint) {
			case SOF_HINT_TOP:	s = "top"; break;
			case SOF_HINT_BOTTOM:	s = "bottom"; break;
			case SOF_HINT_BEFORE:
			case SOF_HINT_AFTER:
				s = (props.sfp_hint == SOF_HINT_BEFORE) ?
				    "before" : "after";
				if (Pread_string(Proc, buf, sizeof (buf),
				    (uintptr_t)props.sfp_hintarg) == -1)
					(void) strcpy(buf, "<?>");
			}
			if (s != NULL) {
				(void) printf(", placement: %s %s", s, buf);
			}
		}
		(void) printf("\n");
		(void) printf("%s\tsocket tuples:\n", pri->pname);
		if (props.sfp_socktuple_cnt == 0) {
			(void) printf("\t\t<empty>\n");
			return;
		}
		sz = props.sfp_socktuple_cnt * sizeof (*tup);
		tup = my_malloc(sz, "socket tuple buffer");
		if (Pread(Proc, tup, sz, (uintptr_t)props.sfp_socktuple) == sz)
			for (i = 0; i < props.sfp_socktuple_cnt; i++) {
				(void) printf(
				    "\t\tfamily: %d, type: %d, proto: %d\n",
				    tup[i].sofst_family, tup[i].sofst_type,
				    tup[i].sofst_protocol);
			}
	}
}
#endif	/* _LP64 */
static void
show_sockconfig_filter_prop(private_t *pri, long addr)
{
	struct sockconfig_filter_props props;
	const char *s = NULL;
	char buf[MAX(FILNAME_MAX, MODMAXNAMELEN)];
	sof_socktuple_t *tup;
	size_t sz;
	int i;

	if (Pread(Proc, &props, sizeof (props), addr) == sizeof (props)) {
		if (Pread_string(Proc, buf, sizeof (buf),
		    (uintptr_t)props.sfp_modname) == -1)
			(void) strcpy(buf, "<?>");
		(void) printf("%s\tmodule name: %s\n", pri->pname, buf);
		(void) printf("%s\tattach semantics: %s", pri->pname,
		    props.sfp_autoattach ? "automatic" : "progammatic");
		if (props.sfp_autoattach) {
			buf[0] = '\0';
			switch (props.sfp_hint) {
			case SOF_HINT_TOP:	s = "top"; break;
			case SOF_HINT_BOTTOM:	s = "bottom"; break;
			case SOF_HINT_BEFORE:
			case SOF_HINT_AFTER:
				s = (props.sfp_hint == SOF_HINT_BEFORE) ?
				    "before" : "after";
				if (Pread_string(Proc, buf, sizeof (buf),
				    (uintptr_t)props.sfp_hintarg) == -1)
					(void) strcpy(buf, "<?>");
			}
			if (s != NULL) {
				(void) printf(", placement: %s", s);
			}
		}
		(void) printf("\n");
		(void) printf("%s\tsocket tuples:\n", pri->pname);
		if (props.sfp_socktuple_cnt == 0) {
			(void) printf("\t\t<empty>\n");
			return;
		}
		sz = props.sfp_socktuple_cnt * sizeof (*tup);
		tup = my_malloc(sz, "socket tuple buffer");
		if (Pread(Proc, tup, sz, (uintptr_t)props.sfp_socktuple) == sz)
			for (i = 0; i < props.sfp_socktuple_cnt; i++) {
				(void) printf(
				    "\t\tfamily: %d, type: %d, proto: %d\n",
				    tup[i].sofst_family, tup[i].sofst_type,
				    tup[i].sofst_protocol);
			}
	}
}

void
show_sockconfig(private_t *pri)
{
	switch (pri->sys_args[0]) {
	case SOCKCONFIG_ADD_FILTER:
#ifdef _LP64
		if (data_model == PR_MODEL_LP64)
			show_sockconfig_filter_prop(pri,
			    (long)pri->sys_args[2]);
		else
			show_sockconfig_filter_prop32(pri,
			    (long)pri->sys_args[2]);
#else
		show_sockconfig_filter_prop(pri, (long)pri->sys_args[2]);
#endif
		break;
	default:
		break;
	}
}

void
show_zfs_ioc(private_t *pri, long addr)
{
	static const zfs_share_t zero_share = {0};
	static const dmu_objset_stats_t zero_objstats = {0};
	static const struct drr_begin zero_drrbegin = {0};
	static const zinject_record_t zero_injectrec = {0};
	static const zfs_stat_t zero_zstat = {0};
	zfs_cmd_t zc;

	if (Pread(Proc, &zc, sizeof (zc), addr) != sizeof (zc)) {
		(void) printf(" zfs_ioctl read failed\n");
		return;
	}

	if (zc.zc_name[0])
		(void) printf("    zc_name=%s\n", zc.zc_name);
	if (zc.zc_value[0])
		(void) printf("    zc_value=%s\n", zc.zc_value);
	if (zc.zc_string[0])
		(void) printf("    zc_string=%s\n", zc.zc_string);
	if (zc.zc_guid != 0) {
		(void) printf("    zc_guid=%llu\n",
		    (u_longlong_t)zc.zc_guid);
	}
	if (zc.zc_nvlist_conf_size) {
		(void) printf("    nvlist_conf:\n");
		show_packed_nvlist(pri, zc.zc_nvlist_conf,
		    zc.zc_nvlist_conf_size);
	}
	if (zc.zc_nvlist_src_size) {
		(void) printf("    nvlist_src:\n");
		show_packed_nvlist(pri, zc.zc_nvlist_src,
		    zc.zc_nvlist_src_size);
	}
	if (zc.zc_nvlist_dst_size) {
		(void) printf("    nvlist_dst:\n");
		show_packed_nvlist(pri, zc.zc_nvlist_dst,
		    zc.zc_nvlist_dst_size);
	}
	if (zc.zc_cookie != 0) {
		(void) printf("    zc_cookie=%llu\n",
		    (u_longlong_t)zc.zc_cookie);
	}
	if (zc.zc_objset_type != 0) {
		(void) printf("    zc_objset_type=%llu\n",
		    (u_longlong_t)zc.zc_objset_type);
	}
	if (zc.zc_perm_action != 0) {
		(void) printf("    zc_perm_action=%llu\n",
		    (u_longlong_t)zc.zc_perm_action);
	}
	if (zc.zc_history != 0) {
		(void) printf("    zc_history=%llu\n",
		    (u_longlong_t)zc.zc_history);
	}
	if (zc.zc_obj != 0) {
		(void) printf("    zc_obj=%llu\n",
		    (u_longlong_t)zc.zc_obj);
	}
	if (zc.zc_iflags != 0) {
		(void) printf("    zc_obj=0x%llx\n",
		    (u_longlong_t)zc.zc_iflags);
	}

	if (memcmp(&zc.zc_share, &zero_share, sizeof (zc.zc_share))) {
		zfs_share_t *z = &zc.zc_share;
		(void) printf("    zc_share:\n");
		if (z->z_exportdata) {
			(void) printf("\tz_exportdata=0x%llx\n",
			    (u_longlong_t)z->z_exportdata);
		}
		if (z->z_sharedata) {
			(void) printf("\tz_sharedata=0x%llx\n",
			    (u_longlong_t)z->z_sharedata);
		}
		if (z->z_sharetype) {
			(void) printf("\tz_sharetype=%llu\n",
			    (u_longlong_t)z->z_sharetype);
		}
		if (z->z_sharemax) {
			(void) printf("\tz_sharemax=%llu\n",
			    (u_longlong_t)z->z_sharemax);
		}
	}

	if (memcmp(&zc.zc_objset_stats, &zero_objstats,
	    sizeof (zc.zc_objset_stats))) {
		dmu_objset_stats_t *dds = &zc.zc_objset_stats;
		(void) printf("    zc_objset_stats:\n");
		if (dds->dds_num_clones) {
			(void) printf("\tdds_num_clones=%llu\n",
			    (u_longlong_t)dds->dds_num_clones);
		}
		if (dds->dds_creation_txg) {
			(void) printf("\tdds_creation_txg=%llu\n",
			    (u_longlong_t)dds->dds_creation_txg);
		}
		if (dds->dds_guid) {
			(void) printf("\tdds_guid=%llu\n",
			    (u_longlong_t)dds->dds_guid);
		}
		if (dds->dds_type)
			(void) printf("\tdds_type=%u\n", dds->dds_type);
		if (dds->dds_is_snapshot) {
			(void) printf("\tdds_is_snapshot=%u\n",
			    dds->dds_is_snapshot);
		}
		if (dds->dds_inconsistent) {
			(void) printf("\tdds_inconsitent=%u\n",
			    dds->dds_inconsistent);
		}
		if (dds->dds_origin[0]) {
			(void) printf("\tdds_origin=%s\n", dds->dds_origin);
		}
	}

	if (memcmp(&zc.zc_begin_record, &zero_drrbegin,
	    sizeof (zc.zc_begin_record))) {
		struct drr_begin *drr = &zc.zc_begin_record;
		(void) printf("    zc_begin_record:\n");
		if (drr->drr_magic) {
			(void) printf("\tdrr_magic=%llu\n",
			    (u_longlong_t)drr->drr_magic);
		}
		if (drr->drr_versioninfo) {
			(void) printf("\tdrr_versioninfo=%llu\n",
			    (u_longlong_t)drr->drr_versioninfo);
		}
		if (drr->drr_creation_time) {
			(void) printf("\tdrr_creation_time=%llu\n",
			    (u_longlong_t)drr->drr_creation_time);
		}
		if (drr->drr_type)
			(void) printf("\tdrr_type=%u\n", drr->drr_type);
		if (drr->drr_flags)
			(void) printf("\tdrr_flags=0x%x\n", drr->drr_flags);
		if (drr->drr_toguid) {
			(void) printf("\tdrr_toguid=%llu\n",
			    (u_longlong_t)drr->drr_toguid);
		}
		if (drr->drr_fromguid) {
			(void) printf("\tdrr_fromguid=%llu\n",
			    (u_longlong_t)drr->drr_fromguid);
		}
		if (drr->drr_toname[0]) {
			(void) printf("\tdrr_toname=%s\n", drr->drr_toname);
		}
	}

	if (memcmp(&zc.zc_inject_record, &zero_injectrec,
	    sizeof (zc.zc_inject_record))) {
		zinject_record_t *zi = &zc.zc_inject_record;
		(void) printf("    zc_inject_record:\n");
		if (zi->zi_objset) {
			(void) printf("\tzi_objset=%llu\n",
			    (u_longlong_t)zi->zi_objset);
		}
		if (zi->zi_object) {
			(void) printf("\tzi_object=%llu\n",
			    (u_longlong_t)zi->zi_object);
		}
		if (zi->zi_start) {
			(void) printf("\tzi_start=%llu\n",
			    (u_longlong_t)zi->zi_start);
		}
		if (zi->zi_end) {
			(void) printf("\tzi_end=%llu\n",
			    (u_longlong_t)zi->zi_end);
		}
		if (zi->zi_guid) {
			(void) printf("\tzi_guid=%llu\n",
			    (u_longlong_t)zi->zi_guid);
		}
		if (zi->zi_level) {
			(void) printf("\tzi_level=%lu\n",
			    (ulong_t)zi->zi_level);
		}
		if (zi->zi_error) {
			(void) printf("\tzi_error=%lu\n",
			    (ulong_t)zi->zi_error);
		}
		if (zi->zi_type) {
			(void) printf("\tzi_type=%llu\n",
			    (u_longlong_t)zi->zi_type);
		}
		if (zi->zi_freq) {
			(void) printf("\tzi_freq=%lu\n",
			    (ulong_t)zi->zi_freq);
		}
		if (zi->zi_failfast) {
			(void) printf("\tzi_failfast=%lu\n",
			    (ulong_t)zi->zi_failfast);
		}
		if (zi->zi_func[0])
			(void) printf("\tzi_func=%s\n", zi->zi_func);
		if (zi->zi_iotype) {
			(void) printf("\tzi_iotype=%lu\n",
			    (ulong_t)zi->zi_iotype);
		}
		if (zi->zi_duration) {
			(void) printf("\tzi_duration=%ld\n",
			    (long)zi->zi_duration);
		}
		if (zi->zi_timer) {
			(void) printf("\tzi_timer=%llu\n",
			    (u_longlong_t)zi->zi_timer);
		}
	}

	if (zc.zc_defer_destroy) {
		(void) printf("    zc_defer_destroy=%d\n",
		    (int)zc.zc_defer_destroy);
	}
	if (zc.zc_flags) {
		(void) printf("    zc_flags=0x%x\n",
		    zc.zc_flags);
	}
	if (zc.zc_action_handle) {
		(void) printf("    zc_action_handle=%llu\n",
		    (u_longlong_t)zc.zc_action_handle);
	}
	if (zc.zc_cleanup_fd >= 0)
		(void) printf("    zc_cleanup_fd=%d\n", zc.zc_cleanup_fd);
	if (zc.zc_sendobj) {
		(void) printf("    zc_sendobj=%llu\n",
		    (u_longlong_t)zc.zc_sendobj);
	}
	if (zc.zc_fromobj) {
		(void) printf("    zc_fromobj=%llu\n",
		    (u_longlong_t)zc.zc_fromobj);
	}
	if (zc.zc_createtxg) {
		(void) printf("    zc_createtxg=%llu\n",
		    (u_longlong_t)zc.zc_createtxg);
	}

	if (memcmp(&zc.zc_stat, &zero_zstat, sizeof (zc.zc_stat))) {
		zfs_stat_t *zs = &zc.zc_stat;
		(void) printf("    zc_stat:\n");
		if (zs->zs_gen) {
			(void) printf("\tzs_gen=%llu\n",
			    (u_longlong_t)zs->zs_gen);
		}
		if (zs->zs_mode) {
			(void) printf("\tzs_mode=%llu\n",
			    (u_longlong_t)zs->zs_mode);
		}
		if (zs->zs_links) {
			(void) printf("\tzs_links=%llu\n",
			    (u_longlong_t)zs->zs_links);
		}
		if (zs->zs_ctime[0]) {
			(void) printf("\tzs_ctime[0]=%llu\n",
			    (u_longlong_t)zs->zs_ctime[0]);
		}
		if (zs->zs_ctime[1]) {
			(void) printf("\tzs_ctime[1]=%llu\n",
			    (u_longlong_t)zs->zs_ctime[1]);
		}
	}
}

/* expound verbosely upon syscall arguments */
/*ARGSUSED*/
void
expound(private_t *pri, long r0, int raw)
{
	const lwpstatus_t *Lsp = pri->lwpstat;
	int lp64 = (data_model == PR_MODEL_LP64);
	int what = Lsp->pr_what;
	int err = pri->Errno;		/* don't display output parameters */
					/* for a failed system call */
#ifndef _LP64
	/* We are a 32-bit truss; we can't grok a 64-bit process */
	if (lp64)
		return;
#endif
	/* for reporting sleeping system calls */
	if (what == 0 && (Lsp->pr_flags & (PR_ASLEEP|PR_VFORKP)))
		what = Lsp->pr_syscall;

	switch (what) {
	case SYS_gettimeofday:
		if (!err)
			show_timeofday(pri);
		break;
	case SYS_getitimer:
		if (!err && pri->sys_nargs > 1)
			show_itimerval(pri, (long)pri->sys_args[1],
			    " value");
		break;
	case SYS_setitimer:
		if (pri->sys_nargs > 1)
			show_itimerval(pri, (long)pri->sys_args[1],
			    " value");
		if (!err && pri->sys_nargs > 2)
			show_itimerval(pri, (long)pri->sys_args[2],
			    "ovalue");
		break;
	case SYS_stime:
		show_stime(pri);
		break;
	case SYS_times:
		if (!err)
			show_times(pri);
		break;
	case SYS_utssys:
		if (err)
			break;
#ifdef _LP64
		if (lp64)
			show_utssys(pri, r0);
		else
			show_utssys32(pri, r0);
#else
		show_utssys(pri, r0);
#endif
		break;
	case SYS_ioctl:
		if (pri->sys_nargs >= 3) /* each case must decide for itself */
			show_ioctl(pri, pri->sys_args[1],
			    (long)pri->sys_args[2]);
		break;
	case SYS_fstatat:
		if (!err && pri->sys_nargs >= 3)
			show_stat(pri, (long)pri->sys_args[2]);
		break;
	case SYS_fstatat64:
		if (!err && pri->sys_nargs >= 3)
			show_stat64_32(pri, (long)pri->sys_args[2]);
		break;
	case SYS_stat:
	case SYS_fstat:
	case SYS_lstat:
		if (!err && pri->sys_nargs >= 2)
			show_stat(pri, (long)pri->sys_args[1]);
		break;
	case SYS_stat64:
	case SYS_fstat64:
	case SYS_lstat64:
		if (!err && pri->sys_nargs >= 2)
			show_stat64_32(pri, (long)pri->sys_args[1]);
		break;
	case SYS_statvfs:
	case SYS_fstatvfs:
		if (err)
			break;
#ifdef _LP64
		if (!lp64) {
			show_statvfs32(pri);
			break;
		}
#endif
		show_statvfs(pri);
		break;
	case SYS_statvfs64:
	case SYS_fstatvfs64:
		if (err)
			break;
		show_statvfs64(pri);
		break;
	case SYS_statfs:
	case SYS_fstatfs:
		if (err)
			break;
#ifdef _LP64
		if (lp64)
			show_statfs(pri);
		else
			show_statfs32(pri);
#else
		show_statfs(pri);
#endif
		break;
	case SYS_fcntl:
		show_fcntl(pri);
		break;
	case SYS_msgsys:
		show_msgsys(pri, r0); /* each case must decide for itself */
		break;
	case SYS_semsys:
		show_semsys(pri);	/* each case must decide for itself */
		break;
	case SYS_shmsys:
		show_shmsys(pri);	/* each case must decide for itself */
		break;
	case SYS_getdents:
		if (err || pri->sys_nargs <= 1 || r0 <= 0)
			break;
#ifdef _LP64
		if (!lp64) {
			show_dents32(pri, (long)pri->sys_args[1], r0);
			break;
		}
		/* FALLTHROUGH */
#else
		show_dents32(pri, (long)pri->sys_args[1], r0);
		break;
#endif
	case SYS_getdents64:
		if (err || pri->sys_nargs <= 1 || r0 <= 0)
			break;
		show_dents64(pri, (long)pri->sys_args[1], r0);
		break;
	case SYS_getmsg:
		show_gp_msg(pri, what);
		if (pri->sys_nargs > 3)
			show_hhex_int(pri, (long)pri->sys_args[3], "flags");
		break;
	case SYS_getpmsg:
		show_gp_msg(pri, what);
		if (pri->sys_nargs > 3)
			show_hhex_int(pri, (long)pri->sys_args[3], "band");
		if (pri->sys_nargs > 4)
			show_hhex_int(pri, (long)pri->sys_args[4], "flags");
		break;
	case SYS_putmsg:
	case SYS_putpmsg:
		show_gp_msg(pri, what);
		break;
	case SYS_pollsys:
		show_pollsys(pri);
		break;
	case SYS_setgroups:
		if (pri->sys_nargs > 1 && (r0 = pri->sys_args[0]) > 0)
			show_groups(pri, (long)pri->sys_args[1], r0);
		break;
	case SYS_getgroups:
		if (!err && pri->sys_nargs > 1 && pri->sys_args[0] > 0)
			show_groups(pri, (long)pri->sys_args[1], r0);
		break;
	case SYS_sigprocmask:
		if (pri->sys_nargs > 1)
			show_sigset(pri, (long)pri->sys_args[1], " set");
		if (!err && pri->sys_nargs > 2)
			show_sigset(pri, (long)pri->sys_args[2], "oset");
		break;
	case SYS_sigsuspend:
	case SYS_sigtimedwait:
		if (pri->sys_nargs > 0)
			show_sigset(pri, (long)pri->sys_args[0], "sigmask");
		if (!err && pri->sys_nargs > 1)
			show_siginfo(pri, (long)pri->sys_args[1]);
		if (pri->sys_nargs > 2)
			show_timestruc(pri, (long)pri->sys_args[2], "timeout");
		break;
	case SYS_sigaltstack:
		if (pri->sys_nargs > 0)
			show_sigaltstack(pri, (long)pri->sys_args[0],
			    "new");
		if (!err && pri->sys_nargs > 1)
			show_sigaltstack(pri, (long)pri->sys_args[1],
			    "old");
		break;
	case SYS_sigaction:
		if (pri->sys_nargs > 1)
			show_sigaction(pri, (long)pri->sys_args[1],
			    "new", NULL);
		if (!err && pri->sys_nargs > 2)
			show_sigaction(pri, (long)pri->sys_args[2],
			    "old", r0);
		break;
	case SYS_signotify:
		if (pri->sys_nargs > 1)
			show_siginfo(pri, (long)pri->sys_args[1]);
		break;
	case SYS_sigresend:
		if (pri->sys_nargs > 1)
			show_siginfo(pri, (long)pri->sys_args[1]);
		if (pri->sys_nargs > 2)
			show_sigset(pri, (long)pri->sys_args[2], "sigmask");
		break;
	case SYS_sigpending:
		if (!err && pri->sys_nargs > 1)
			show_sigset(pri, (long)pri->sys_args[1], "sigmask");
		break;
	case SYS_waitid:
		if (!err && pri->sys_nargs > 2)
			show_siginfo(pri, (long)pri->sys_args[2]);
		break;
	case SYS_sigsendsys:
		if (pri->sys_nargs > 0)
			show_procset(pri, (long)pri->sys_args[0]);
		break;
	case SYS_priocntlsys:
		if (pri->sys_nargs > 1)
			show_procset(pri, (long)pri->sys_args[1]);
		break;
	case SYS_mincore:
		if (!err && pri->sys_nargs > 2)
			show_bool(pri, (long)pri->sys_args[2],
			    (pri->sys_args[1] + pagesize - 1) / pagesize);
		break;
	case SYS_readv:
	case SYS_writev:
		if (pri->sys_nargs > 2) {
			int i = pri->sys_args[0]+1;
			int showbuf = FALSE;
			long nb = (what == SYS_readv)? r0 : 32*1024;

			if ((what == SYS_readv && !err &&
			    prismember(&readfd, i)) ||
			    (what == SYS_writev &&
			    prismember(&writefd, i)))
				showbuf = TRUE;
			show_iovec(pri, (long)pri->sys_args[1],
			    pri->sys_args[2], showbuf, nb);
		}
		break;
	case SYS_getrlimit:
		if (err)
			break;
		/*FALLTHROUGH*/
	case SYS_setrlimit:
		if (pri->sys_nargs <= 1)
			break;
#ifdef _LP64
		if (lp64)
			show_rlimit64(pri, (long)pri->sys_args[1]);
		else
			show_rlimit32(pri, (long)pri->sys_args[1]);
#else
		show_rlimit32(pri, (long)pri->sys_args[1]);
#endif
		break;
	case SYS_getrlimit64:
		if (err)
			break;
		/*FALLTHROUGH*/
	case SYS_setrlimit64:
		if (pri->sys_nargs <= 1)
			break;
		show_rlimit64(pri, (long)pri->sys_args[1]);
		break;
	case SYS_uname:
		if (!err && pri->sys_nargs > 0)
			show_nuname(pri, (long)pri->sys_args[0]);
		break;
	case SYS_adjtime:
		if (!err && pri->sys_nargs > 1)
			show_adjtime(pri, (long)pri->sys_args[0],
			    (long)pri->sys_args[1]);
		break;
	case SYS_lwp_info:
		if (!err && pri->sys_nargs > 0)
			show_timestruc(pri, (long)pri->sys_args[0], "cpu time");
		break;
	case SYS_lwp_wait:
		if (!err && pri->sys_nargs > 1)
			show_int(pri, (long)pri->sys_args[1], "lwpid");
		break;
	case SYS_lwp_mutex_wakeup:
	case SYS_lwp_mutex_unlock:
	case SYS_lwp_mutex_trylock:
	case SYS_lwp_mutex_register:
		if (pri->sys_nargs > 0)
			show_mutex(pri, (long)pri->sys_args[0]);
		break;
	case SYS_lwp_mutex_timedlock:
		if (pri->sys_nargs > 0)
			show_mutex(pri, (long)pri->sys_args[0]);
		if (pri->sys_nargs > 1)
			show_timestruc(pri, (long)pri->sys_args[1], "timeout");
		break;
	case SYS_lwp_cond_wait:
		if (pri->sys_nargs > 0)
			show_condvar(pri, (long)pri->sys_args[0]);
		if (pri->sys_nargs > 1)
			show_mutex(pri, (long)pri->sys_args[1]);
		if (pri->sys_nargs > 2)
			show_timestruc(pri, (long)pri->sys_args[2], "timeout");
		break;
	case SYS_lwp_cond_signal:
	case SYS_lwp_cond_broadcast:
		if (pri->sys_nargs > 0)
			show_condvar(pri, (long)pri->sys_args[0]);
		break;
	case SYS_lwp_sema_trywait:
	case SYS_lwp_sema_post:
		if (pri->sys_nargs > 0)
			show_sema(pri, (long)pri->sys_args[0]);
		break;
	case SYS_lwp_sema_timedwait:
		if (pri->sys_nargs > 0)
			show_sema(pri, (long)pri->sys_args[0]);
		if (pri->sys_nargs > 1)
			show_timestruc(pri, (long)pri->sys_args[1], "timeout");
		break;
	case SYS_lwp_rwlock_sys:
		if (pri->sys_nargs > 1)
			show_rwlock(pri, (long)pri->sys_args[1]);
		if (pri->sys_nargs > 2 &&
		    (pri->sys_args[0] == 0 || pri->sys_args[0] == 1))
			show_timestruc(pri, (long)pri->sys_args[2], "timeout");
		break;
	case SYS_lwp_create:
		/* XXX print some values in ucontext ??? */
		if (!err && pri->sys_nargs > 2)
			show_int(pri, (long)pri->sys_args[2], "lwpid");
		break;
	case SYS_kaio:
		if (pri->sys_args[0] == AIOWAIT && !err && pri->sys_nargs > 1)
			show_timeval(pri, (long)pri->sys_args[1], "timeout");
		break;
	case SYS_nanosleep:
		if (pri->sys_nargs > 0)
			show_timestruc(pri, (long)pri->sys_args[0], "tmout");
		if (pri->sys_nargs > 1 && (err == 0 || err == EINTR))
			show_timestruc(pri, (long)pri->sys_args[1], "resid");
		break;
	case SYS_privsys:
		switch (pri->sys_args[0]) {
		case PRIVSYS_SETPPRIV:
		case PRIVSYS_GETPPRIV:
			if (!err)
				show_privset(pri, (long)pri->sys_args[3],
				    (size_t)pri->sys_args[4], "");
		}
		break;
	case SYS_ucredsys:
		switch (pri->sys_args[0]) {
		case UCREDSYS_UCREDGET:
		case UCREDSYS_GETPEERUCRED:
			if (err == 0)
				show_ucred(pri, (long)pri->sys_args[2]);
			break;
		}
		break;
	case SYS_bind:
	case SYS_connect:
		if (pri->sys_nargs > 2)
			show_sockaddr(pri, "name", (long)pri->sys_args[1],
			    0, (long)pri->sys_args[2]);
		break;
	case SYS_sendto:
		if (pri->sys_nargs > 5)
			show_sockaddr(pri, "to", (long)pri->sys_args[4], 0,
			    pri->sys_args[5]);
		break;
	case SYS_accept:
		if (!err && pri->sys_nargs > 2)
			show_sockaddr(pri, "name", (long)pri->sys_args[1],
			    (long)pri->sys_args[2], 0);
		break;
	case SYS_getsockname:
	case SYS_getpeername:
		if (!err && pri->sys_nargs > 2)
			show_sockaddr(pri, "name", (long)pri->sys_args[1],
			    (long)pri->sys_args[2], 0);
		break;
	case SYS_cladm:
		if (!err && pri->sys_nargs > 2)
			show_cladm(pri, pri->sys_args[0], pri->sys_args[1],
			    (long)pri->sys_args[2]);
		break;
	case SYS_recvfrom:
		if (!err && pri->sys_nargs > 5)
			show_sockaddr(pri, "from", (long)pri->sys_args[4],
			    (long)pri->sys_args[5], 0);
		break;
	case SYS_recvmsg:
		if (err)
			break;
		/* FALLTHROUGH */
	case SYS_sendmsg:
		if (pri->sys_nargs <= 2)
			break;
#ifdef _LP64
		if (lp64)
			show_msghdr(pri, pri->sys_args[1]);
		else
			show_msghdr32(pri, pri->sys_args[1]);
#else
		show_msghdr(pri, pri->sys_args[1]);
#endif
		break;
	case SYS_door:
		show_doors(pri);
		break;
	case SYS_sendfilev:
		if (pri->sys_nargs != 5)
			break;

		if (pri->sys_args[0] == SENDFILEV) {
			show_sendfilevec(pri, (int)pri->sys_args[1],
			    (sendfilevec_t *)pri->sys_args[2],
			    (int)pri->sys_args[3]);
		} else if (pri->sys_args[0] == SENDFILEV64) {
			show_sendfilevec64(pri, (int)pri->sys_args[1],
			    (sendfilevec64_t *)pri->sys_args[2],
			    (int)pri->sys_args[3]);
		}
		break;
	case SYS_memcntl:
		show_memcntl(pri);
		break;
	case SYS_lwp_park:
		/*
		 * subcode 0: lwp_park(timespec_t *, id_t)
		 * subcode 4: lwp_set_park(timespec_t *, id_t)
		 */
		if (pri->sys_nargs > 1 &&
		    (pri->sys_args[0] == 0 || pri->sys_args[0] == 4))
			show_timestruc(pri, (long)pri->sys_args[1], "timeout");
		/* subcode 2: lwp_unpark_all(id_t *, int) */
		if (pri->sys_nargs > 2 && pri->sys_args[0] == 2)
			show_ids(pri, (long)pri->sys_args[1],
			    (int)pri->sys_args[2]);
		break;
	case SYS_ntp_gettime:
		if (!err)
			show_ntp_gettime(pri);
		break;
	case SYS_ntp_adjtime:
		if (!err)
			show_ntp_adjtime(pri);
		break;
	case SYS_rusagesys:
		if (!err)
			if (pri->sys_args[0] == _RUSAGESYS_GETRUSAGE) {
#ifdef _LP64
				if (!lp64)
					show_getrusage32(pri->sys_args[1]);
				else
#endif
					show_getrusage(pri->sys_args[1]);
			}
		break;
	case SYS_port:
		show_ports(pri);
		break;
	case SYS_zone:
		show_zones(pri);
		break;
	case SYS_rctlsys:
		show_rctls(pri);
		break;
	case SYS_utimesys:
		show_utimesys(pri);
		break;
	case SYS_sockconfig:
		show_sockconfig(pri);
		break;
	}
}
