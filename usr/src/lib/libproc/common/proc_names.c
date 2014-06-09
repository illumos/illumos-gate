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
 * Copyright (c) 1997, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2015, Joyent, Inc.  All rights reserved.
 */

#include <stdio.h>
#define	__EXTENSIONS__
#include <string.h>
#undef  __EXTENSIONS__
#include <signal.h>
#include <errno.h>
#include "libproc.h"

static const char *
rawfltname(int flt)
{
	const char *name;

	switch (flt) {
	case FLTILL:	name = "FLTILL";	break;
	case FLTPRIV:	name = "FLTPRIV";	break;
	case FLTBPT:	name = "FLTBPT";	break;
	case FLTTRACE:	name = "FLTTRACE";	break;
	case FLTACCESS:	name = "FLTACCESS";	break;
	case FLTBOUNDS:	name = "FLTBOUNDS";	break;
	case FLTIOVF:	name = "FLTIOVF";	break;
	case FLTIZDIV:	name = "FLTIZDIV";	break;
	case FLTFPE:	name = "FLTFPE";	break;
	case FLTSTACK:	name = "FLTSTACK";	break;
	case FLTPAGE:	name = "FLTPAGE";	break;
	case FLTWATCH:	name = "FLTWATCH";	break;
	case FLTCPCOVF:	name = "FLTCPCOVF";	break;
	default:	name = NULL;		break;
	}

	return (name);
}

/*
 * Return the name of a fault.
 * Manufacture a name for unknown fault.
 */
char *
proc_fltname(int flt, char *buf, size_t bufsz)
{
	const char *name = rawfltname(flt);
	size_t len;

	if (bufsz == 0)		/* force a program failure */
		return (NULL);

	if (name != NULL) {
		len = strlen(name);
		(void) strncpy(buf, name, bufsz);
	} else {
		len = snprintf(buf, bufsz, "FLT#%d", flt);
	}

	if (len >= bufsz)	/* ensure null-termination */
		buf[bufsz-1] = '\0';

	return (buf);
}

/*
 * Return the name of a signal.
 * Manufacture a name for unknown signal.
 */
char *
proc_signame(int sig, char *buf, size_t bufsz)
{
	char name[SIG2STR_MAX+4];
	size_t len;

	if (bufsz == 0)		/* force a program failure */
		return (NULL);

	/* sig2str() omits the leading "SIG" */
	(void) strcpy(name, "SIG");

	if (sig2str(sig, name+3) == 0) {
		len = strlen(name);
		(void) strncpy(buf, name, bufsz);
	} else {
		len = snprintf(buf, bufsz, "SIG#%d", sig);
	}

	if (len >= bufsz)	/* ensure null-termination */
		buf[bufsz-1] = '\0';

	return (buf);
}

static const char *const systable[] = {
	NULL,			/*  0 */
	"_exit",		/*  1 */
	NULL,			/*  2 */
	"read",			/*  3 */
	"write",		/*  4 */
	"open",			/*  5 */
	"close",		/*  6 */
	"linkat",		/*  7 */
	NULL,			/*  8 */
	"link",			/*  9 */
	"unlink",		/* 10 */
	"symlinkat",		/* 11 */
	"chdir",		/* 12 */
	"time",			/* 13 */
	"mknod",		/* 14 */
	"chmod",		/* 15 */
	"chown",		/* 16 */
	"brk",			/* 17 */
	"stat",			/* 18 */
	"lseek",		/* 19 */
	"getpid",		/* 20 */
	"mount",		/* 21 */
	"readlinkat",		/* 22 */
	"setuid",		/* 23 */
	"getuid",		/* 24 */
	"stime",		/* 25 */
	"ptrace",		/* 26 */
	"alarm",		/* 27 */
	"fstat",		/* 28 */
	"pause",		/* 29 */
	NULL,			/* 30 */
	"stty",			/* 31 */
	"gtty",			/* 32 */
	"access",		/* 33 */
	"nice",			/* 34 */
	"statfs",		/* 35 */
	"sync",			/* 36 */
	"kill",			/* 37 */
	"fstatfs",		/* 38 */
	"pgrpsys",		/* 39 */
	"uucopystr",		/* 40 */
	NULL,			/* 41 */
	"pipe",			/* 42 */
	"times",		/* 43 */
	"profil",		/* 44 */
	"faccessat",		/* 45 */
	"setgid",		/* 46 */
	"getgid",		/* 47 */
	"mknodat",		/* 48 */
	"msgsys",		/* 49 */
	"sysi86",		/* 50 */
	"acct",			/* 51 */
	"shmsys",		/* 52 */
	"semsys",		/* 53 */
	"ioctl",		/* 54 */
	"uadmin",		/* 55 */
	"fchownat",		/* 56 */
	"utssys",		/* 57 */
	"fdsync",		/* 58 */
	"execve",		/* 59 */
	"umask",		/* 60 */
	"chroot",		/* 61 */
	"fcntl",		/* 62 */
	"ulimit",		/* 63 */
	"renameat",		/* 64 */
	"unlinkat",		/* 65 */
	"fstatat",		/* 66 */
	"fstatat64",		/* 67 */
	"openat",		/* 68 */
	"openat64",		/* 69 */
	"tasksys",		/* 70 */
	"acctctl",		/* 71 */
	"exacctsys",		/* 72 */
	"getpagesizes",		/* 73 */
	"rctlsys",		/* 74 */
	"issetugid",		/* 75 */
	"fsat",			/* 76 */
	"lwp_park",		/* 77 */
	"sendfilev",		/* 78 */
	"rmdir",		/* 79 */
	"mkdir",		/* 80 */
	"getdents",		/* 81 */
	"privsys",		/* 82 */
	"ucredsys",		/* 83 */
	"sysfs",		/* 84 */
	"getmsg",		/* 85 */
	"putmsg",		/* 86 */
	NULL,			/* 87 */
	"lstat",		/* 88 */
	"symlink",		/* 89 */
	"readlink",		/* 90 */
	"setgroups",		/* 91 */
	"getgroups",		/* 92 */
	"fchmod",		/* 93 */
	"fchown",		/* 94 */
	"sigprocmask",		/* 95 */
	"sigsuspend",		/* 96 */
	"sigaltstack",		/* 97 */
	"sigaction",		/* 98 */
	"sigpending",		/* 99 */
	"context",		/* 100 */
	"fchmodat",		/* 101 */
	"mkdirat",		/* 102 */
	"statvfs",		/* 103 */
	"fstatvfs",		/* 104 */
	"getloadavg",		/* 105 */
	"nfssys",		/* 106 */
	"waitid",		/* 107 */
	"sigsendsys",		/* 108 */
	"hrtsys",		/* 109 */
	"acancel",		/* 110 */
	"async",		/* 111 */
	"priocntlsys",		/* 112 */
	"pathconf",		/* 113 */
	"mincore",		/* 114 */
	"mmap",			/* 115 */
	"mprotect",		/* 116 */
	"munmap",		/* 117 */
	"fpathconf",		/* 118 */
	"vfork",		/* 119 */
	"fchdir",		/* 120 */
	"readv",		/* 121 */
	"writev",		/* 122 */
	"preadv",		/* 123 */
	"pwritev",		/* 124 */
	NULL,			/* 125 */
	NULL,			/* 126 */
	"mmapobj",		/* 127 */
	"setrlimit",		/* 128 */
	"getrlimit",		/* 129 */
	"lchown",		/* 130 */
	"memcntl",		/* 131 */
	"getpmsg",		/* 132 */
	"putpmsg",		/* 133 */
	"rename",		/* 134 */
	"uname",		/* 135 */
	"setegid",		/* 136 */
	"sysconfig",		/* 137 */
	"adjtime",		/* 138 */
	"systeminfo",		/* 139 */
	"sharefs",		/* 140 */
	"seteuid",		/* 141 */
	"forksys",		/* 142 */
	NULL,			/* 143 */
	"sigtimedwait",		/* 144 */
	"lwp_info",		/* 145 */
	"yield",		/* 146 */
	NULL,			/* 147 */
	"lwp_sema_post",	/* 148 */
	"lwp_sema_trywait",	/* 149 */
	"lwp_detatch",		/* 150 */
	"corectl",		/* 151 */
	"modctl",		/* 152 */
	"fchroot",		/* 153 */
	NULL,			/* 154 */
	"vhangup",		/* 155 */
	"gettimeofday",		/* 156 */
	"getitimer",		/* 157 */
	"setitimer",		/* 158 */
	"lwp_create",		/* 159 */
	"lwp_exit",		/* 160 */
	"lwp_suspend",		/* 161 */
	"lwp_continue",		/* 162 */
	"lwp_kill",		/* 163 */
	"lwp_self",		/* 164 */
	"lwp_sigmask",		/* 165 */
	"lwp_private",		/* 166 */
	"lwp_wait",		/* 167 */
	"lwp_mutex_wakeup",	/* 168 */
	NULL,			/* 169 */
	"lwp_cond_wait",	/* 170 */
	"lwp_cond_signal",	/* 171 */
	"lwp_cond_broadcast",	/* 172 */
	"pread",		/* 173 */
	"pwrite",		/* 174 */
	"llseek",		/* 175 */
	"inst_sync",		/* 176 */
	"brand",		/* 177 */
	"kaio",			/* 178 */
	"cpc",			/* 179 */
	"lgrpsys",		/* 180 */
	"rusagesys",		/* 181 */
	"portfs",		/* 182 */
	"pollsys",		/* 183 */
	"labelsys",		/* 184 */
	"acl",			/* 185 */
	"auditsys",		/* 186 */
	"processor_bind",	/* 187 */
	"processor_info",	/* 188 */
	"p_online",		/* 189 */
	"sigqueue",		/* 190 */
	"clock_gettime",	/* 191 */
	"clock_settime",	/* 192 */
	"clock_getres",		/* 193 */
	"timer_create",		/* 194 */
	"timer_delete",		/* 195 */
	"timer_settime",	/* 196 */
	"timer_gettime",	/* 197 */
	"timer_getoverrun",	/* 198 */
	"nanosleep",		/* 199 */
	"facl",			/* 200 */
	"door",			/* 201 */
	"setreuid",		/* 202 */
	"setregid",		/* 203 */
	"install_utrap",	/* 204 */
	"signotify",		/* 205 */
	"schedctl",		/* 206 */
	"pset",			/* 207 */
	"sparc_utrap_install",	/* 208 */
	"resolvepath",		/* 209 */
	"lwp_mutex_timedlock",	/* 210 */
	"lwp_sema_timedwait",	/* 211 */
	"lwp_rwlock_sys",	/* 212 */
	"getdents64",		/* 213 */
	"mmap64",		/* 214 */
	"stat64",		/* 215 */
	"lstat64",		/* 216 */
	"fstat64",		/* 217 */
	"statvfs64",		/* 218 */
	"fstatvfs64",		/* 219 */
	"setrlimit64",		/* 220 */
	"getrlimit64",		/* 221 */
	"pread64",		/* 222 */
	"pwrite64",		/* 223 */
	NULL,			/* 224 */
	"open64",		/* 225 */
	"rpcmod",		/* 226 */
	"zone",			/* 227 */
	"autofssys",		/* 228 */
	"getcwd",		/* 229 */
	"so_socket",		/* 230 */
	"so_socketpair",	/* 231 */
	"bind",			/* 232 */
	"listen",		/* 233 */
	"accept",		/* 234 */
	"connect",		/* 235 */
	"shutdown",		/* 236 */
	"recv",			/* 237 */
	"recvfrom",		/* 238 */
	"recvmsg",		/* 239 */
	"send",			/* 240 */
	"sendmsg",		/* 241 */
	"sendto",		/* 242 */
	"getpeername",		/* 243 */
	"getsockname",		/* 244 */
	"getsockopt",		/* 245 */
	"setsockopt",		/* 246 */
	"sockconfig",		/* 247 */
	"ntp_gettime",		/* 248 */
	"ntp_adjtime",		/* 249 */
	"lwp_mutex_unlock",	/* 250 */
	"lwp_mutex_trylock",	/* 251 */
	"lwp_mutex_register",	/* 252 */
	"cladm",		/* 253 */
	"uucopy",		/* 254 */
	"umount2"		/* 255 */
};

/* SYSEND == max syscall number + 1 */
#define	SYSEND	(sizeof (systable) / sizeof (systable[0]))

/*
 * Return the name of a system call.
 * Manufacture a name for unknown system call.
 */
char *
proc_sysname(int sys, char *buf, size_t bufsz)
{
	const char *name;
	size_t len;

	if (bufsz == 0)		/* force a program failure */
		return (NULL);

	if (sys >= 0 && sys < SYSEND)
		name = systable[sys];
	else
		name = NULL;

	if (name != NULL) {
		len = strlen(name);
		(void) strncpy(buf, name, bufsz);
	} else {
		len = snprintf(buf, bufsz, "SYS#%d", sys);
	}

	if (len >= bufsz)	/* ensure null-termination */
		buf[bufsz-1] = '\0';

	return (buf);
}

/*
 * Convert a string representation of a fault to the corresponding number.
 */
int
proc_str2flt(const char *str, int *fltnum)
{
	char *next;
	int i;

	i = strtol(str, &next, 0);
	if (i > 0 && i <= PRMAXFAULT && *next == '\0') {
		*fltnum = i;
		return (0);
	}

	for (i = 1; i <= PRMAXFAULT; i++) {
		const char *s = rawfltname(i);

		if (s && (strcasecmp(s, str) == 0 ||
		    strcasecmp(s + 3, str) == 0)) {
			*fltnum = i;
			return (0);
		}
	}

	return (-1);
}

/*
 * Convert a string representation of a signal to the signal number.  This
 * functionality is already available in libc, but the interface doesn't
 * optionally accept a "SIG" prefix.  We strip that first, and then call libc.
 */
int
proc_str2sig(const char *str, int *signum)
{
	if (strncasecmp(str, "SIG", 3) == 0)
		str += 3; /* skip prefix */

	return (str2sig(str, signum));
}

/*
 * Convert a string representation of a system call to the corresponding number.
 * We do this by performing a simple linear search of the table above.
 */
int
proc_str2sys(const char *str, int *sysnum)
{
	char *next;
	int i;

	i = strtol(str, &next, 0);
	if (i > 0 && i <= PRMAXSYS && *next == '\0') {
		*sysnum = i;
		return (0);
	}

	for (i = 1; i < SYSEND; i++) {
		if (systable[i] != NULL && strcmp(systable[i], str) == 0) {
			*sysnum = i;
			return (0);
		}
	}

	return (-1);
}

/*
 * Convert a fltset_t to a string representation consisting of canonical
 * machine fault names separated by the given delimeter string.  If
 * m is non-zero (TRUE), set members are printed.  If m is zero (FALSE), set
 * non-members are printed.  If the specified buf is too small to hold the
 * complete formatted set, NULL is returned; otherwise buf is returned.
 */
char *
proc_fltset2str(const fltset_t *set, const char *delim, int m,
	char *buf, size_t len)
{
	char name[FLT2STR_MAX], *p = buf;
	size_t n;
	int i;

	if (buf == NULL || len < 1) {
		errno = EINVAL;
		return (NULL);
	}

	buf[0] = '\0';  /* Set first byte to \0 */

	for (i = 1; i <= PRMAXFAULT; i++) {
		if ((prismember(set, i) != 0) ^ (m == 0)) {
			(void) proc_fltname(i, name, sizeof (name));

			if (buf[0] != '\0')
				n = snprintf(p, len, "%s%s", delim, name);
			else
				n = snprintf(p, len, "%s", name);

			if (n != strlen(p)) {
				errno = ENAMETOOLONG; /* Output was truncated */
				return (NULL);
			}
			len -= n;
			p += n;
		}
	}
	return (buf);
}

/*
 * Convert a sigset_t to a string representation consisting of canonical signal
 * names (without the SIG prefix). Parameters and return values analogous to
 * proc_fltset2str().
 */
char *
proc_sigset2str(const sigset_t *set, const char *delim, int m,
	char *buf, size_t len)
{
	char name[SIG2STR_MAX], *p = buf;
	size_t n;
	int i;

	if (buf == NULL || len < 1) {
		errno = EINVAL;
		return (NULL);
	}

	m = (m != 0);	/* Make sure m is 0 or 1 */
	buf[0] = '\0';	/* Set first byte to \0 */

	/*
	 * Unlike proc_fltset2str() and proc_sysset2str(), we don't loop
	 * until i <= NSIG here, because sigismember() rejects i == NSIG.
	 */
	for (i = 1; i < NSIG; i++) {
		if (sigismember(set, i) == m) {
			(void) sig2str(i, name);

			if (buf[0] != '\0')
				n = snprintf(p, len, "%s%s", delim, name);
			else
				n = snprintf(p, len, "%s", name);

			if (n != strlen(p)) {
				errno = ENAMETOOLONG; /* Output was truncated */
				return (NULL);
			}

			len -= n;
			p += n;
		}
	}

	return (buf);
}

/*
 * Convert a sysset_t to a string representation consisting of canonical system
 * call names. Parameters and return values analogous to proc_fltset2str().
 */
char *
proc_sysset2str(const sysset_t *set, const char *delim, int m,
	char *buf, size_t len)
{
	char name[SYS2STR_MAX], *p = buf;
	size_t n;
	int i;

	if (buf == NULL || len < 1) {
		errno = EINVAL;
		return (NULL);
	}

	buf[0] = '\0';  /* Set first byte to \0 */

	for (i = 1; i <= PRMAXSYS; i++) {
		if ((prismember(set, i) != 0) ^ (m == 0)) {
			(void) proc_sysname(i, name, sizeof (name));

			if (buf[0] != '\0')
				n = snprintf(p, len, "%s%s", delim, name);
			else
				n = snprintf(p, len, "%s", name);

			if (n != strlen(p)) {
				errno = ENAMETOOLONG; /* Output was truncated */
				return (NULL);
			}
			len -= n;
			p += n;
		}
	}
	return (buf);
}

/*
 * Convert a string representation of a fault set (names separated by
 * one or more of the given delimeters) to a fltset_t.
 * If m is non-zero (TRUE), members of the string representation are set.
 * If m is zero (FALSE), non-members of the string representation are set.
 * This function returns NULL for success. Otherwise it returns a pointer
 * to the token of the string that couldn't be identified as a string
 * representation of a fault.
 */
char *
proc_str2fltset(const char *s, const char *delim, int m, fltset_t *set)
{
	char *p, *q, *t;
	int flt;

	if (m) {
		premptyset(set);
	} else {
		prfillset(set);
	}

	t = strdupa(s);

	for (p = strtok_r(t, delim, &q); p != NULL;
	    p = strtok_r(NULL, delim, &q)) {
		if (proc_str2flt(p, &flt) == -1) {
			errno = EINVAL;
			return ((char *)s + (p - t));
		}
		if (m)
			praddset(set, flt);
		else
			prdelset(set, flt);
	}
	return (NULL);
}

/*
 * Convert a string representation of a signal set (names with or without the
 * SIG prefix separated by one or more of the given delimeters) to a sigset_t.
 * Parameters and return values analogous to proc_str2fltset().
 */
char *
proc_str2sigset(const char *s, const char *delim, int m, sigset_t *set)
{
	char *p, *q, *t;
	int sig;

	if (m) {
		premptyset(set);
	} else {
		prfillset(set);
	}

	t = strdupa(s);

	for (p = strtok_r(t, delim, &q); p != NULL;
	    p = strtok_r(NULL, delim, &q)) {
		if (proc_str2sig(p, &sig) == -1) {
			errno = EINVAL;
			return ((char *)s + (p - t));
		}
		if (m)
			praddset(set, sig);
		else
			prdelset(set, sig);
	}
	return (NULL);
}

/*
 * Convert a string representation of a system call set (names separated by
 * one or more of the given delimeters) to a sysset_t. Parameters and return
 * values analogous to proc_str2fltset().
 */
char *
proc_str2sysset(const char *s, const char *delim, int m, sysset_t *set)
{
	char *p, *q, *t;
	int sys;

	if (m) {
		premptyset(set);
	} else {
		prfillset(set);
	}

	t = strdupa(s);

	for (p = strtok_r(t, delim, &q); p != NULL;
	    p = strtok_r(NULL, delim, &q)) {
		if (proc_str2sys(p, &sys) == -1) {
			errno = EINVAL;
			return ((char *)s + (p - t));
		}
		if (m)
			praddset(set, sys);
		else
			prdelset(set, sys);
	}
	return (NULL);
}
