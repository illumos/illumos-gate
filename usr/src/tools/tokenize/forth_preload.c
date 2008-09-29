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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This preload library must be applied to forth after libthread is
 * folded into libc because forth/tokenize.exe is not ABI compliant; it
 * uses all of the %g registers, including %g7, for its internal purposes.
 * This preload library interposes on all of the external calls made
 * from forth/tokenize.exe and, assuming that forth is single-threaded,
 * sets %g7 properly for use inside libc and restores it to forth's
 * use on return from the interposed-upon function.
 */

enum ix {
	ix___filbuf = 0,
	ix___flsbuf,
	ix__dgettext,
	ix__exit,
	ix_access,
	ix_atexit,
	ix_atoi,
	ix_cfgetospeed,
	ix_chdir,
	ix_close,
	ix_exit,
	ix_exit_handler,
	ix_fclose,
	ix_fflush,
	ix_fgetc,
	ix_fileno,
	ix_fopen,
	ix_fprintf,
	ix_fputc,
	ix_fputs,
	ix_fread,
	ix_free,
	ix_fseek,
	ix_fstat,
	ix_ftell,
	ix_fwrite,
	ix_getcwd,
	ix_getenv,
	ix_getopt,
	ix_getwd,
	ix_ioctl,
	ix_isatty,
	ix_kill,
	ix_localtime,
	ix_lseek,
	ix_malloc,
	ix_memcpy,
	ix_memset,
	ix_open,
	ix_perror,
	ix_printf,
	ix_psignal,
	ix_putchar,
	ix_read,
	ix_sbrk,
	ix_signal,
	ix_sigset,
	ix_snprintf,
	ix_sprintf,
	ix_stat,
	ix_strcat,
	ix_strchr,
	ix_strcmp,
	ix_strcpy,
	ix_strdup,
	ix_strlen,
	ix_strncmp,
	ix_strncpy,
	ix_strrchr,
	ix_system,
	ix_tcgetattr,
	ix_tcsetattr,
	ix_tgetent,
	ix_tgetflag,
	ix_tgetnum,
	ix_tgetstr,
	ix_tgoto,
	ix_time,
	ix_tputs,
	ix_tzset,
	ix_ungetc,
	ix_unlink,
	ix_write
};

typedef long (*realfunc_t)(long, long, long, long, long, long);

struct intpose {
	char fname[12];
	realfunc_t realfunc;
} intpose[] = {
	{ "__filbuf",		0 },
	{ "__flsbuf",		0 },
	{ "_dgettext",		0 },
	{ "_exit",		0 },
	{ "access",		0 },
	{ "atexit",		0 },
	{ "atoi",		0 },
	{ "cfgetospeed",	0 },
	{ "chdir",		0 },
	{ "close",		0 },
	{ "exit",		0 },
	{ "exit_handler",	0 },
	{ "fclose",		0 },
	{ "fflush",		0 },
	{ "fgetc",		0 },
	{ "fileno",		0 },
	{ "fopen",		0 },
	{ "fprintf",		0 },
	{ "fputc",		0 },
	{ "fputs",		0 },
	{ "fread",		0 },
	{ "free",		0 },
	{ "fseek",		0 },
	{ "fstat",		0 },
	{ "ftell",		0 },
	{ "fwrite",		0 },
	{ "getcwd",		0 },
	{ "getenv",		0 },
	{ "getopt",		0 },
	{ "getwd",		0 },
	{ "ioctl",		0 },
	{ "isatty",		0 },
	{ "kill",		0 },
	{ "localtime",		0 },
	{ "lseek",		0 },
	{ "malloc",		0 },
	{ "memcpy",		0 },
	{ "memset",		0 },
	{ "open",		0 },
	{ "perror",		0 },
	{ "printf",		0 },
	{ "psignal",		0 },
	{ "putchar",		0 },
	{ "read",		0 },
	{ "sbrk",		0 },
	{ "signal",		0 },
	{ "sigset",		0 },
	{ "snprintf",		0 },
	{ "sprintf",		0 },
	{ "stat",		0 },
	{ "strcat",		0 },
	{ "strchr",		0 },
	{ "strcmp",		0 },
	{ "strcpy",		0 },
	{ "strdup",		0 },
	{ "strlen",		0 },
	{ "strncmp",		0 },
	{ "strncpy",		0 },
	{ "strrchr",		0 },
	{ "system",		0 },
	{ "tcgetattr",		0 },
	{ "tcsetattr",		0 },
	{ "tgetent",		0 },
	{ "tgetflag",		0 },
	{ "tgetnum",		0 },
	{ "tgetstr",		0 },
	{ "tgoto",		0 },
	{ "time",		0 },
	{ "tputs",		0 },
	{ "tzset",		0 },
	{ "ungetc",		0 },
	{ "unlink",		0 },
	{ "write",		0 },
};

#define	RTLD_NEXT	(void *)-1
extern	void	*dlsym(void *handle, const char *name);

static	long	global_g7 = -1;

long	get_g5(void);
void	set_g5(long);

long	get_g7(void);
void	set_g7(long);

static long
callfunc(struct intpose *ip,
	long a0, long a1, long a2, long a3, long a4, long a5)
{
	realfunc_t realfunc;
	long my_g5;
	long my_g7;
	long rv;

	my_g5 = get_g5();
	my_g7 = get_g7();
	if (global_g7 == -1)
		global_g7 = my_g7;
	set_g7(global_g7);
	if ((realfunc = ip->realfunc) == 0)
		ip->realfunc = realfunc =
		    (realfunc_t)dlsym(RTLD_NEXT, ip->fname);
	rv = realfunc(a0, a1, a2, a3, a4, a5);
	set_g5(my_g5);
	set_g7(my_g7);
	return (rv);
}

#define	ipose(func)							\
long									\
func(long a0, long a1, long a2, long a3, long a4, long a5)		\
{									\
	return (callfunc(&intpose[ix_##func], a0, a1, a2, a3, a4, a5));	\
}

ipose(__filbuf)
ipose(__flsbuf)
ipose(_dgettext)
ipose(_exit)
ipose(access)
ipose(atexit)
ipose(atoi)
ipose(cfgetospeed)
ipose(chdir)
ipose(close)
ipose(exit)
ipose(exit_handler)
ipose(fclose)
ipose(fflush)
ipose(fgetc)
ipose(fileno)
ipose(fopen)
ipose(fprintf)
ipose(fputc)
ipose(fputs)
ipose(fread)
ipose(free)
ipose(fseek)
ipose(fstat)
ipose(ftell)
ipose(fwrite)
ipose(getcwd)
ipose(getenv)
ipose(getopt)
ipose(getwd)
ipose(ioctl)
ipose(isatty)
ipose(kill)
ipose(localtime)
ipose(lseek)
ipose(malloc)
ipose(memcpy)
ipose(memset)
ipose(open)
ipose(perror)
ipose(printf)
ipose(psignal)
ipose(putchar)
ipose(read)
ipose(sbrk)
ipose(signal)
ipose(sigset)
ipose(snprintf)
ipose(sprintf)
ipose(stat)
ipose(strcat)
ipose(strchr)
ipose(strcmp)
ipose(strcpy)
ipose(strdup)
ipose(strlen)
ipose(strncmp)
ipose(strncpy)
ipose(strrchr)
ipose(system)
ipose(tcgetattr)
ipose(tcsetattr)
ipose(tgetent)
ipose(tgetflag)
ipose(tgetnum)
ipose(tgetstr)
ipose(tgoto)
ipose(time)
ipose(tputs)
ipose(tzset)
ipose(ungetc)
ipose(unlink)
ipose(write)
