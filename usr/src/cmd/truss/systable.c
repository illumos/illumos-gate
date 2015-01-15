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
 * Copyright (c) 2015, Joyent, Inc.  All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/* Copyright (c) 2013, OmniTI Computer Consulting, Inc. All rights reserved. */

/*
 * Copyright (c) 2014, Joyent, Inc. All rights reserved.
 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <libproc.h>
#include <sys/aio.h>
#include <sys/port_impl.h>
#include "ramdata.h"
#include "systable.h"
#include "print.h"
#include "proto.h"

/*
 * Tables of information about system calls - read-only data.
 */

const	char *const	errcode[] = {	/* error code names */
	NULL,		/*  0 */
	"EPERM",	/*  1 */
	"ENOENT",	/*  2 */
	"ESRCH",	/*  3 */
	"EINTR",	/*  4 */
	"EIO",		/*  5 */
	"ENXIO",	/*  6 */
	"E2BIG",	/*  7 */
	"ENOEXEC",	/*  8 */
	"EBADF",	/*  9 */
	"ECHILD",	/* 10 */
	"EAGAIN",	/* 11 */
	"ENOMEM",	/* 12 */
	"EACCES",	/* 13 */
	"EFAULT",	/* 14 */
	"ENOTBLK",	/* 15 */
	"EBUSY",	/* 16 */
	"EEXIST",	/* 17 */
	"EXDEV",	/* 18 */
	"ENODEV",	/* 19 */
	"ENOTDIR",	/* 20 */
	"EISDIR",	/* 21 */
	"EINVAL",	/* 22 */
	"ENFILE",	/* 23 */
	"EMFILE",	/* 24 */
	"ENOTTY",	/* 25 */
	"ETXTBSY",	/* 26 */
	"EFBIG",	/* 27 */
	"ENOSPC",	/* 28 */
	"ESPIPE",	/* 29 */
	"EROFS",	/* 30 */
	"EMLINK",	/* 31 */
	"EPIPE",	/* 32 */
	"EDOM",		/* 33 */
	"ERANGE",	/* 34 */
	"ENOMSG",	/* 35 */
	"EIDRM",	/* 36 */
	"ECHRNG",	/* 37 */
	"EL2NSYNC",	/* 38 */
	"EL3HLT",	/* 39 */
	"EL3RST",	/* 40 */
	"ELNRNG",	/* 41 */
	"EUNATCH",	/* 42 */
	"ENOCSI",	/* 43 */
	"EL2HLT",	/* 44 */
	"EDEADLK",	/* 45 */
	"ENOLCK",	/* 46 */
	"ECANCELED",	/* 47 */
	"ENOTSUP",	/* 48 */
	"EDQUOT",	/* 49 */
	"EBADE",	/* 50 */
	"EBADR",	/* 51 */
	"EXFULL",	/* 52 */
	"ENOANO",	/* 53 */
	"EBADRQC",	/* 54 */
	"EBADSLT",	/* 55 */
	"EDEADLOCK",	/* 56 */
	"EBFONT",	/* 57 */
	"EOWNERDEAD",	/* 58 */
	"ENOTRECOVERABLE",	/* 59 */
	"ENOSTR",	/* 60 */
	"ENODATA",	/* 61 */
	"ETIME",	/* 62 */
	"ENOSR",	/* 63 */
	"ENONET",	/* 64 */
	"ENOPKG",	/* 65 */
	"EREMOTE",	/* 66 */
	"ENOLINK",	/* 67 */
	"EADV",		/* 68 */
	"ESRMNT",	/* 69 */
	"ECOMM",	/* 70 */
	"EPROTO",	/* 71 */
	"ELOCKUNMAPPED",	/* 72 */
	"ENOTACTIVE",	/* 73 */
	"EMULTIHOP",	/* 74 */
	NULL,		/* 75 */
	NULL,		/* 76 */
	"EBADMSG",	/* 77 */
	"ENAMETOOLONG",	/* 78 */
	"EOVERFLOW",	/* 79 */
	"ENOTUNIQ",	/* 80 */
	"EBADFD",	/* 81 */
	"EREMCHG",	/* 82 */
	"ELIBACC",	/* 83 */
	"ELIBBAD",	/* 84 */
	"ELIBSCN",	/* 85 */
	"ELIBMAX",	/* 86 */
	"ELIBEXEC",	/* 87 */
	"EILSEQ",	/* 88 */
	"ENOSYS",	/* 89 */
	"ELOOP",	/* 90 */
	"ERESTART",	/* 91 */
	"ESTRPIPE",	/* 92 */
	"ENOTEMPTY",	/* 93 */
	"EUSERS",	/* 94 */
	"ENOTSOCK",	/* 95 */
	"EDESTADDRREQ",	/* 96 */
	"EMSGSIZE",	/* 97 */
	"EPROTOTYPE",	/* 98 */
	"ENOPROTOOPT",	/* 99 */
	NULL,		/* 100 */
	NULL,		/* 101 */
	NULL,		/* 102 */
	NULL,		/* 103 */
	NULL,		/* 104 */
	NULL,		/* 105 */
	NULL,		/* 106 */
	NULL,		/* 107 */
	NULL,		/* 108 */
	NULL,		/* 109 */
	NULL,		/* 110 */
	NULL,		/* 111 */
	NULL,		/* 112 */
	NULL,		/* 113 */
	NULL,		/* 114 */
	NULL,		/* 115 */
	NULL,		/* 116 */
	NULL,		/* 117 */
	NULL,		/* 118 */
	NULL,		/* 119 */
	"EPROTONOSUPPORT",	/* 120 */
	"ESOCKTNOSUPPORT",	/* 121 */
	"EOPNOTSUPP",	/* 122 */
	"EPFNOSUPPORT",	/* 123 */
	"EAFNOSUPPORT",	/* 124 */
	"EADDRINUSE",	/* 125 */
	"EADDRNOTAVAIL", /* 126 */
	"ENETDOWN",	/* 127 */
	"ENETUNREACH",	/* 128 */
	"ENETRESET",	/* 129 */
	"ECONNABORTED",	/* 130 */
	"ECONNRESET",	/* 131 */
	"ENOBUFS",	/* 132 */
	"EISCONN",	/* 133 */
	"ENOTCONN",	/* 134 */
	NULL,		/* 135 */
	NULL,		/* 136 */
	NULL,		/* 137 */
	NULL,		/* 138 */
	NULL,		/* 139 */
	NULL,		/* 140 */
	NULL,		/* 141 */
	NULL,		/* 142 */
	"ESHUTDOWN",	/* 143 */
	"ETOOMANYREFS",	/* 144 */
	"ETIMEDOUT",	/* 145 */
	"ECONNREFUSED",	/* 146 */
	"EHOSTDOWN",	/* 147 */
	"EHOSTUNREACH",	/* 148 */
	"EALREADY",	/* 149 */
	"EINPROGRESS",	/* 150 */
	"ESTALE"	/* 151 */
};

#define	NERRCODE	(sizeof (errcode) / sizeof (char *))


const char *
errname(int err)	/* return the error code name (NULL if none) */
{
	const char *ename = NULL;

	if (err >= 0 && err < NERRCODE)
		ename = errcode[err];

	return (ename);
}


const struct systable systable[] = {
{ NULL,		8, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX},
{"_exit",	1, DEC, NOV, DEC},				/*   1 */
{ NULL,		8, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX},
{"read",	3, DEC, NOV, DEC, IOB, UNS},			/*   3 */
{"write",	3, DEC, NOV, DEC, IOB, UNS},			/*   4 */
{"open",	3, DEC, NOV, STG, OPN, OCT},			/*   5 */
{"close",	1, DEC, NOV, DEC},				/*   6 */
{"linkat",	5, DEC, NOV, ATC, STG, ATC, STG, SNF},		/*   7 */
{ NULL,		8, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX},
{"link",	2, DEC, NOV, STG, STG},				/*   9 */
{"unlink",	1, DEC, NOV, STG},				/*  10 */
{"symlinkat",	3, DEC, NOV, STG, ATC, STG},			/*  11 */
{"chdir",	1, DEC, NOV, STG},				/*  12 */
{"time",	0, DEC, NOV},					/*  13 */
{"mknod",	3, DEC, NOV, STG, OCT, HEX},			/*  14 */
{"chmod",	2, DEC, NOV, STG, OCT},				/*  15 */
{"chown",	3, DEC, NOV, STG, DEC, DEC},			/*  16 */
{"brk",		1, DEC, NOV, HEX},				/*  17 */
{"stat",	2, DEC, NOV, STG, HEX},				/*  18 */
{"lseek",	3, DEC, NOV, DEC, DEX, WHN},			/*  19 */
{"getpid",	0, DEC, DEC},					/*  20 */
{"mount",	8, DEC, NOV, STG, STG, MTF, MFT, HEX, DEC, HEX, DEC}, /* 21 */
{"readlinkat",	4, DEC, NOV, ATC, STG, RLK, UNS},		/*  22 */
{"setuid",	1, DEC, NOV, UNS},				/*  23 */
{"getuid",	0, UNS, UNS},					/*  24 */
{"stime",	1, DEC, NOV, DEC},				/*  25 */
{"pcsample",	2, DEC, NOV, HEX, DEC},				/*  26 */
{"alarm",	1, DEC, NOV, UNS},				/*  27 */
{"fstat",	2, DEC, NOV, DEC, HEX},				/*  28 */
{"pause",	0, DEC, NOV},					/*  29 */
{ NULL,		8, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX},
{"stty",	2, DEC, NOV, DEC, DEC},				/*  31 */
{"gtty",	2, DEC, NOV, DEC, DEC},				/*  32 */
{"access",	2, DEC, NOV, STG, ACC},				/*  33 */
{"nice",	1, DEC, NOV, DEC},				/*  34 */
{"statfs",	4, DEC, NOV, STG, HEX, DEC, DEC},		/*  35 */
{"sync",	0, DEC, NOV},					/*  36 */
{"kill",	2, DEC, NOV, DEC, SIG},				/*  37 */
{"fstatfs",	4, DEC, NOV, DEC, HEX, DEC, DEC},		/*  38 */
{"pgrpsys",	3, DEC, NOV, DEC, DEC, DEC},			/*  39 */
{"uucopystr",	3, DEC, NOV, STG, RST, UNS},			/*  40 */
{ NULL,		8, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX},
{"pipe",	2, DEC, NOV, PFD, PIP},				/*  42 */
{"times",	1, DEC, NOV, HEX},				/*  43 */
{"profil",	4, DEC, NOV, HEX, UNS, HEX, OCT},		/*  44 */
{"faccessat",	4, DEC, NOV, ATC, STG, ACC, FAT},		/*  45 */
{"setgid",	1, DEC, NOV, UNS},				/*  46 */
{"getgid",	0, UNS, UNS},					/*  47 */
{"mknodat",	4, DEC, NOV, ATC, STG, OCT, HEX},		/*  48 */
{"msgsys",	6, DEC, NOV, DEC, DEC, DEC, DEC, DEC, DEC},	/*  49 */
{"sysi86",	4, HEX, NOV, S86, HEX, HEX, HEX, DEC, DEC},	/*  50 */
{"acct",	1, DEC, NOV, STG},				/*  51 */
{"shmsys",	4, DEC, NOV, DEC, HEX, HEX, HEX},		/*  52 */
{"semsys",	5, DEC, NOV, DEC, HEX, HEX, HEX, HEX},		/*  53 */
{"ioctl",	3, DEC, NOV, DEC, IOC, IOA},			/*  54 */
{"uadmin",	3, DEC, NOV, DEC, DEC, DEC},			/*  55 */
{"fchownat",	5, DEC, NOV, ATC, STG, DEC, DEC, SNF},		/*  56 */
{"utssys",	4, DEC, NOV, HEX, DEC, UTS, HEX},		/*  57 */
{"fdsync",	2, DEC, NOV, DEC, FFG},				/*  58 */
{"execve",	3, DEC, NOV, STG, HEX, HEX},			/*  59 */
{"umask",	1, OCT, NOV, OCT},				/*  60 */
{"chroot",	1, DEC, NOV, STG},				/*  61 */
{"fcntl",	3, DEC, NOV, DEC, FCN, HEX},			/*  62 */
{"ulimit",	2, DEX, NOV, ULM, DEC},				/*  63 */
{"renameat",	4, DEC, NOV, ATC, STG, ATC, STG},		/*  64 */
{"unlinkat",	3, DEC, NOV, ATC, STG, UAT},			/*  65 */
{"fstatat",	4, DEC, NOV, ATC, STG, HEX, SNF},		/*  66 */
{"fstatat64",	4, DEC, NOV, ATC, STG, HEX, SNF},		/*  67 */
{"openat",	4, DEC, NOV, ATC, STG, OPN, OCT},		/*  68 */
{"openat64",	4, DEC, NOV, ATC, STG, OPN, OCT},		/*  69 */
{"tasksys",	5, DEC, NOV, DEC, DEC, DEC, HEX, DEC},		/*  70 */
{"acctctl",	3, DEC, NOV, HEX, HEX, UNS},			/*  71 */
{"exacctsys",	6, DEC, NOV, DEC, IDT, DEC, HEX, DEC, HEX},	/*  72 */
{"getpagesizes", 2, DEC, NOV, HEX, DEC},			/*  73 */
{"rctlsys",	6, DEC, NOV, RSC, STG, HEX, HEX, DEC, DEC},	/*  74 */
{"sidsys",	4, UNS, UNS, DEC, DEC, DEC, DEC},		/*  75 */
{ NULL,		8, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX},
{"lwp_park",	3, DEC, NOV, DEC, HEX, DEC},			/*  77 */
{"sendfilev",	5, DEC, NOV, DEC, DEC, HEX, DEC, HEX},		/*  78 */
{"rmdir",	1, DEC, NOV, STG},				/*  79 */
{"mkdir",	2, DEC, NOV, STG, OCT},				/*  80 */
{"getdents",	3, DEC, NOV, DEC, HEX, UNS},			/*  81 */
{"privsys",	5, HEX, NOV, DEC, DEC, DEC, HEX, DEC},		/*  82 */
{"ucredsys",	3, DEC, NOV, DEC, DEC, HEX},			/*  83 */
{"sysfs",	3, DEC, NOV, SFS, DEX, DEX},			/*  84 */
{"getmsg",	4, DEC, NOV, DEC, HEX, HEX, HEX},		/*  85 */
{"putmsg",	4, DEC, NOV, DEC, HEX, HEX, SMF},		/*  86 */
{ NULL,		8, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX},
{"lstat",	2, DEC, NOV, STG, HEX},				/*  88 */
{"symlink",	2, DEC, NOV, STG, STG},				/*  89 */
{"readlink",	3, DEC, NOV, STG, RLK, UNS},			/*  90 */
{"setgroups",	2, DEC, NOV, DEC, HEX},				/*  91 */
{"getgroups",	2, DEC, NOV, DEC, HEX},				/*  92 */
{"fchmod",	2, DEC, NOV, DEC, OCT},				/*  93 */
{"fchown",	3, DEC, NOV, DEC, DEC, DEC},			/*  94 */
{"sigprocmask",	3, DEC, NOV, SPM, HEX, HEX},			/*  95 */
{"sigsuspend",	1, DEC, NOV, HEX},				/*  96 */
{"sigaltstack",	2, DEC, NOV, HEX, HEX},				/*  97 */
{"sigaction",	3, DEC, NOV, SIG, HEX, HEX},			/*  98 */
{"sigpendsys",	2, DEC, NOV, DEC, HEX},				/*  99 */
{"context",	2, DEC, NOV, DEC, HEX},				/* 100 */
{"fchmodat",	4, DEC, NOV, ATC, STG, OCT, SNF},		/* 101 */
{"mkdirat",	3, DEC, NOV, ATC, STG, OCT},			/* 102 */
{"statvfs",	2, DEC, NOV, STG, HEX},				/* 103 */
{"fstatvfs",	2, DEC, NOV, DEC, HEX},				/* 104 */
{"getloadavg",	2, DEC, NOV, HEX, DEC},				/* 105 */
{"nfssys",	2, DEC, NOV, DEC, HEX},				/* 106 */
{"waitid",	4, DEC, NOV, IDT, DEC, HEX, WOP},		/* 107 */
{"sigsendsys",	2, DEC, NOV, HEX, SIG},				/* 108 */
{"hrtsys",	5, DEC, NOV, DEC, HEX, HEX, HEX, HEX},		/* 109 */
{"utimesys",	5, DEC, NOV, DEC, HEX, HEX, HEX, HEX},		/* 110 */
{"sigresend",	3, DEC, NOV, SIG, HEX, HEX},			/* 111 */
{"priocntlsys",	5, DEC, NOV, DEC, HEX, DEC, PC4, PC5},		/* 112 */
{"pathconf",	2, DEC, NOV, STG, PTC},				/* 113 */
{"mincore",	3, DEC, NOV, HEX, UNS, HEX},			/* 114 */
{"mmap",	6, HEX, NOV, HEX, UNS, MPR, MTY, DEC, DEC},	/* 115 */
{"mprotect",	3, DEC, NOV, HEX, UNS, MPR},			/* 116 */
{"munmap",	2, DEC, NOV, HEX, UNS},				/* 117 */
{"fpathconf",	2, DEC, NOV, DEC, PTC},				/* 118 */
{"vfork",	0, DEC, NOV},					/* 119 */
{"fchdir",	1, DEC, NOV, DEC},				/* 120 */
{"readv",	3, DEC, NOV, DEC, HEX, DEC},			/* 121 */
{"writev",	3, DEC, NOV, DEC, HEX, DEC},			/* 122 */
{"preadv",	4, DEC, NOV, DEC, HEX, DEC, DEC},		/* 123 */
{"pwritev",	4, DEC, NOV, DEC, HEX, DEC, DEC},		/* 124 */
{ NULL,		8, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX},
{ NULL,		8, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX},
{"mmapobj",	5, DEC, NOV, DEC, MOB, HEX, HEX, HEX},		/* 127 */
{"setrlimit",	2, DEC, NOV, RLM, HEX},				/* 128 */
{"getrlimit",	2, DEC, NOV, RLM, HEX},				/* 129 */
{"lchown",	3, DEC, NOV, STG, DEC, DEC},			/* 130 */
{"memcntl",	6, DEC, NOV, HEX, UNS, MCF, MC4, MC5, DEC},	/* 131 */
{"getpmsg",	5, DEC, NOV, DEC, HEX, HEX, HEX, HEX},		/* 132 */
{"putpmsg",	5, DEC, NOV, DEC, HEX, HEX, DEC, HHX},		/* 133 */
{"rename",	2, DEC, NOV, STG, STG},				/* 134 */
{"uname",	1, DEC, NOV, HEX},				/* 135 */
{"setegid",	1, DEC, NOV, UNS},				/* 136 */
{"sysconfig",	1, DEC, NOV, CNF},				/* 137 */
{"adjtime",	2, DEC, NOV, HEX, HEX},				/* 138 */
{"sysinfo",	3, DEC, NOV, INF, RST, DEC},			/* 139 */
{"sharefs",	3, DEC, NOV, DEC, HEX, DEC},			/* 140 */
{"seteuid",	1, DEC, NOV, UNS},				/* 141 */
{"forksys",	2, DEC, NOV, DEC, HHX},				/* 142 */
{ NULL,		8, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX},
{"sigtimedwait", 3, DEC, NOV, HEX, HEX, HEX},			/* 144 */
{"lwp_info",	1, DEC, NOV, HEX},				/* 145 */
{"yield",	0, DEC, NOV},					/* 146 */
{ NULL,		8, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX},
{"lwp_sema_post", 1, DEC, NOV, HEX},				/* 148 */
{"lwp_sema_trywait", 1, DEC, NOV, HEX},				/* 149 */
{"lwp_detach",	1, DEC, NOV, DEC},				/* 150 */
{"corectl",	4, DEC, NOV, DEC, HEX, HEX, HEX},		/* 151 */
{"modctl",	5, DEC, NOV, MOD, HEX, HEX, HEX, HEX},		/* 152 */
{"fchroot",	1, DEC, NOV, DEC},				/* 153 */
{ NULL,		8, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX},
{"vhangup",	0, DEC, NOV},					/* 155 */
{"gettimeofday", 1, DEC, NOV, HEX},				/* 156 */
{"getitimer",	2, DEC, NOV, ITM, HEX},				/* 157 */
{"setitimer",	3, DEC, NOV, ITM, HEX, HEX},			/* 158 */
{"lwp_create",	3, DEC, NOV, HEX, LWF, HEX},			/* 159 */
{"lwp_exit",	0, DEC, NOV},					/* 160 */
{"lwp_suspend",	1, DEC, NOV, DEC},				/* 161 */
{"lwp_continue", 1, DEC, NOV, DEC},				/* 162 */
{"lwp_kill",	2, DEC, NOV, DEC, SIG},				/* 163 */
{"lwp_self",	0, DEC, NOV},					/* 164 */
{"lwp_sigmask",	5, HEX, HEX, SPM, HEX, HEX, HEX, HEX},		/* 165 */
{"lwp_private",	3, HEX, NOV, DEC, DEC, HEX},			/* 166 */
{"lwp_wait",	2, DEC, NOV, DEC, HEX},				/* 167 */
{"lwp_mutex_wakeup", 2, DEC, NOV, HEX, DEC},			/* 168 */
{ NULL,		8, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX},
{"lwp_cond_wait", 4, DEC, NOV, HEX, HEX, HEX, DEC},		/* 170 */
{"lwp_cond_signal", 1, DEC, NOV, HEX},				/* 171 */
{"lwp_cond_broadcast", 1, DEC, NOV, HEX},			/* 172 */
{"pread",	4, DEC, NOV, DEC, IOB, UNS, DEX},		/* 173 */
{"pwrite",	4, DEC, NOV, DEC, IOB, UNS, DEX},		/* 174 */
{"llseek",	4, LLO, NOV, DEC, LLO, HID, WHN},		/* 175 */
{"inst_sync",	2, DEC, NOV, STG, DEC},				/* 176 */
{"brand",	6, DEC, NOV, DEC, HEX, HEX, HEX, HEX, HEX},	/* 177 */
{"kaio",	7, DEC, NOV, AIO, HEX, HEX, HEX, HEX, HEX, HEX}, /* 178 */
{"cpc",		5, DEC, NOV, CPC, DEC, HEX, HEX, HEX},		/* 179 */
{"lgrpsys",	3, DEC, NOV, DEC, DEC, HEX},			/* 180 */
{"rusagesys",	5, DEC, NOV, DEC, HEX, DEC, HEX, HEX},		/* 181 */
{"portfs",	6, HEX, HEX, DEC, HEX, HEX, HEX, HEX, HEX},	/* 182 */
{"pollsys",	4, DEC, NOV, HEX, DEC, HEX, HEX},		/* 183 */
{"labelsys",	2, DEC, NOV, DEC, HEX},				/* 184 */
{"acl",		4, DEC, NOV, STG, ACL, DEC, HEX},		/* 185 */
{"auditsys",	4, DEC, NOV, AUD, HEX, HEX, HEX},		/* 186 */
{"processor_bind", 4, DEC, NOV, IDT, DEC, DEC, HEX},		/* 187 */
{"processor_info", 2, DEC, NOV, DEC, HEX},			/* 188 */
{"p_online",	2, DEC, NOV, DEC, DEC},				/* 189 */
{"sigqueue",	5, DEC, NOV, DEC, SIG, HEX, SQC, DEC},		/* 190 */
{"clock_gettime", 2, DEC, NOV, DEC, HEX},			/* 191 */
{"clock_settime", 2, DEC, NOV, DEC, HEX},			/* 192 */
{"clock_getres", 2, DEC, NOV, DEC, HEX},			/* 193 */
{"timer_create", 3, DEC, NOV, DEC, HEX, HEX},			/* 194 */
{"timer_delete", 1, DEC, NOV, DEC},				/* 195 */
{"timer_settime", 4, DEC, NOV, DEC, DEC, HEX, HEX},		/* 196 */
{"timer_gettime", 2, DEC, NOV, DEC, HEX},			/* 197 */
{"timer_getoverrun", 1, DEC, NOV, DEC},				/* 198 */
{"nanosleep",	2, DEC, NOV, HEX, HEX},				/* 199 */
{"facl",	4, DEC, NOV, DEC, ACL, DEC, HEX},		/* 200 */
{"door",	6, DEC, NOV, DEC, HEX, HEX, HEX, HEX, DEC},	/* 201 */
{"setreuid",	2, DEC, NOV, UN1, UN1},				/* 202 */
{"setregid",	2, DEC, NOV, UN1, UN1},				/* 203 */
{"install_utrap", 3, DEC, NOV, DEC, HEX, HEX},			/* 204 */
{"signotify",	3, DEC, NOV, DEC, HEX, HEX},			/* 205 */
{"schedctl",	0, HEX, NOV},					/* 206 */
{"pset",	5, DEC, NOV, DEC, HEX, HEX, HEX, HEX},		/* 207 */
{"sparc_utrap_install", 5, DEC, NOV, UTT, UTH, UTH, HEX, HEX},	/* 208 */
{"resolvepath",	3, DEC, NOV, STG, RLK, DEC},			/* 209 */
{"lwp_mutex_timedlock", 3, DEC, NOV, HEX, HEX, HEX},		/* 210 */
{"lwp_sema_timedwait", 3, DEC, NOV, HEX, HEX, DEC},		/* 211 */
{"lwp_rwlock_sys", 3, DEC, NOV, DEC, HEX, HEX},			/* 212 */
{"getdents64",	3, DEC, NOV, DEC, HEX, UNS},			/* 213 */
{"mmap64",	7, HEX, NOV, HEX, UNS, MPR, MTY, DEC, LLO, HID}, /* 214 */
{"stat64",	2, DEC, NOV, STG, HEX},				/* 215 */
{"lstat64",	2, DEC, NOV, STG, HEX},				/* 216 */
{"fstat64",	2, DEC, NOV, DEC, HEX},				/* 217 */
{"statvfs64",	2, DEC, NOV, STG, HEX},				/* 218 */
{"fstatvfs64",	2, DEC, NOV, DEC, HEX},				/* 219 */
{"setrlimit64",	2, DEC, NOV, RLM, HEX},				/* 220 */
{"getrlimit64",	2, DEC, NOV, RLM, HEX},				/* 221 */
{"pread64",	5, DEC, NOV, DEC, IOB, UNS, LLO, HID},		/* 222 */
{"pwrite64",	5, DEC, NOV, DEC, IOB, UNS, LLO, HID},		/* 223 */
{ NULL,		8, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX},
{"open64",	3, DEC, NOV, STG, OPN, OCT},			/* 225 */
{"rpcmod",	3, DEC, NOV, DEC, HEX},				/* 226 */
{"zone",	5, DEC, NOV, DEC, HEX, HEX, HEX, HEX},		/* 227 */
{"autofssys",	2, DEC, NOV, DEC, HEX},				/* 228 */
{"getcwd",	3, DEC, NOV, RST, DEC},				/* 229 */
{"so_socket",	5, DEC, NOV, PFM, SKT, SKP, STG, SKV},		/* 230 */
{"so_socketpair", 1, DEC, NOV, HEX},				/* 231 */
{"bind",	4, DEC, NOV, DEC, HEX, DEC, SKV},		/* 232 */
{"listen",	3, DEC, NOV, DEC, DEC, SKV},			/* 233 */
{"accept",	5, DEC, NOV, DEC, HEX, HEX, SKV, ACF},		/* 234 */
{"connect",	4, DEC, NOV, DEC, HEX, DEC, SKV},		/* 235 */
{"shutdown",	3, DEC, NOV, DEC, SHT, SKV},			/* 236 */
{"recv",	4, DEC, NOV, DEC, IOB, DEC, DEC},		/* 237 */
{"recvfrom",	6, DEC, NOV, DEC, IOB, DEC, DEC, HEX, HEX},	/* 238 */
{"recvmsg",	3, DEC, NOV, DEC, HEX, DEC},			/* 239 */
{"send",	4, DEC, NOV, DEC, IOB, DEC, DEC},		/* 240 */
{"sendmsg",	3, DEC, NOV, DEC, HEX, DEC},			/* 241 */
{"sendto",	6, DEC, NOV, DEC, IOB, DEC, DEC, HEX, DEC},	/* 242 */
{"getpeername", 4, DEC, NOV, DEC, HEX, HEX, SKV},		/* 243 */
{"getsockname", 4, DEC, NOV, DEC, HEX, HEX, SKV},		/* 244 */
{"getsockopt",	6, DEC, NOV, DEC, SOL, SON, HEX, HEX, SKV},	/* 245 */
{"setsockopt",	6, DEC, NOV, DEC, SOL, SON, HEX, DEC, SKV},	/* 246 */
{"sockconfig",	5, DEC, NOV, DEC, HEX, HEX, HEX, HEX},		/* 247 */
{"ntp_gettime",	1, DEC, NOV, HEX},				/* 248 */
{"ntp_adjtime",	1, DEC, NOV, HEX},				/* 249 */
{"lwp_mutex_unlock", 1, DEC, NOV, HEX},				/* 250 */
{"lwp_mutex_trylock", 2, DEC, NOV, HEX, HEX},			/* 251 */
{"lwp_mutex_register", 2, DEC, NOV, HEX, HEX},			/* 252 */
{"cladm",	3, DEC, NOV, CLC, CLF, HEX},			/* 253 */
{"uucopy",	3, DEC, NOV, HEX, HEX, UNS},			/* 254 */
{"umount2",	2, DEC, NOV, STG, MTF},				/* 255 */
{ NULL, -1, DEC, NOV},
};

/* SYSEND == max syscall number + 1 */
#define	SYSEND	((sizeof (systable) / sizeof (struct systable))-1)


/*
 * The following are for interpreting syscalls with sub-codes.
 */

const	struct systable	faccessattable[] = {
{"faccessat",	4, DEC, NOV, ATC, STG, ACC, FAT},		/*  0 */
{"access",	3, DEC, NOV, HID, STG, ACC},			/*  1 */
};
#define	NACCESSCODE	(sizeof (faccessattable) / sizeof (struct systable))

const	struct systable	fchmodattable[] = {
{"fchmodat",	4, DEC, NOV, ATC, STG, OCT, SNF},		/*  0 */
{"chmod",	3, DEC, NOV, HID, STG, OCT},			/*  1 */
{"fchmodat",	4, DEC, NOV, ATC, STG, OCT, SNF},		/*  2 */
{"fchmod",	3, DEC, NOV, DEC, HID, OCT},			/*  3 */
};
#define	NCHMODCODE	(sizeof (fchmodattable) / sizeof (struct systable))

const	struct systable	fchownattable[] = {
{"fchownat",	5, DEC, NOV, ATC, STG, DEC, DEC, SNF},		/*  0 */
{"chown",	4, DEC, NOV, HID, STG, DEC, DEC},		/*  1 */
{"lchown",	4, DEC, NOV, HID, STG, DEC, DEC},		/*  2 */
{"fchown",	4, DEC, NOV, DEC, HID, DEC, DEC},		/*  3 */
};
#define	NCHOWNCODE	(sizeof (fchownattable) / sizeof (struct systable))

const	struct systable	mkdiratattable[] = {
{"mkdirat",	3, DEC, NOV, ATC, STG, OCT},			/*  0 */
{"mkdir",	3, DEC, NOV, HID, STG, OCT},			/*  1 */
};
#define	NMKDIRCODE	(sizeof (mkdiratattable) / sizeof (struct systable))

const	struct systable	mknodatattable[] = {
{"mknodat",	4, DEC, NOV, ATC, STG, OCT, HEX},		/*  0 */
{"mknod",	4, DEC, NOV, HID, STG, OCT, HEX},		/*  1 */
};
#define	NMKMODCODE	(sizeof (mknodatattable) / sizeof (struct systable))

const	struct systable	renameattable[] = {
{"renameat",	4, DEC, NOV, ATC, STG, ATC, STG},		/*  0 */
{"rename",	4, DEC, NOV, HID, STG, HID, STG},		/*  1 */
};
#define	NRENAMECODE	(sizeof (renameattable) / sizeof (struct systable))

const	struct systable	linkattable[] = {
{"linkat",	5, DEC, NOV, ATC, STG, ATC, STG, SNF},		/*  0 */
{"link",	4, DEC, NOV, HID, STG, HID, STG},		/*  1 */
};
#define	NLINKATCODE	(sizeof (linkattable) / sizeof (struct systable))

const	struct systable	unlinkattable[] = {
{"unlinkat",	3, DEC, NOV, ATC, STG, UAT},			/*  0 */
{"unlink",	2, DEC, NOV, HID, STG},				/*  1 */
{"rmdir",	2, DEC, NOV, HID, STG},				/*  2 */
};
#define	NUNLINKCODE	(sizeof (unlinkattable) / sizeof (struct systable))

const	struct systable	symlinkattable[] = {
{"symlinkat",	3, DEC, NOV, STG, ATC, STG},			/*  0 */
{"symlink",	3, DEC, NOV, STG, HID, STG},			/*  1 */
};
#define	NSYMLINKCODE	(sizeof (symlinkattable) / sizeof (struct systable))

const	struct systable	readlinkattable[] = {
{"readlinkat",	4, DEC, NOV, ATC, STG, RLK, UNS},		/*  0 */
{"readlink",	4, DEC, NOV, HID, STG, RLK, UNS},		/*  1 */
};
#define	NREADLINKCODE	(sizeof (readlinkattable) / sizeof (struct systable))

const	struct systable	fstatattable[] = {
{"fstatat",	4, DEC, NOV, ATC, STG, HEX, SNF},		/*  0 */
{"stat",	3, DEC, NOV, HID, STG, HEX},			/*  1 */
{"lstat",	3, DEC, NOV, HID, STG, HEX},			/*  2 */
{"fstat",	3, DEC, NOV, DEC, HID, HEX},			/*  3 */
};
#define	NSTATCODE	(sizeof (fstatattable) / sizeof (struct systable))

const	struct systable	fstatat64table[] = {
{"fstatat64",	4, DEC, NOV, ATC, STG, HEX, SNF},		/*  0 */
{"stat64",	3, DEC, NOV, HID, STG, HEX},			/*  1 */
{"lstat64",	3, DEC, NOV, HID, STG, HEX},			/*  2 */
{"fstat64",	3, DEC, NOV, DEC, HID, HEX},			/*  3 */
};
#define	NSTAT64CODE	(sizeof (fstatat64table) / sizeof (struct systable))

const	struct systable openattable[] = {
{"openat",	3, DEC, NOV, ATC, STG, OPN},			/* 0 */
{"openat",	4, DEC, NOV, ATC, STG, OPN, OCT},		/* 1 */
{"open",	3, DEC, NOV, HID, STG, OPN},			/* 2 */
{"open",	4, DEC, NOV, HID, STG, OPN, OCT},		/* 3 */
};
#define	NOPENATCODE	(sizeof (openattable) / sizeof (struct systable))

const	struct systable openat64table[] = {
{"openat64",	3, DEC, NOV, ATC, STG, OPN},			/* 0 */
{"openat64",	4, DEC, NOV, ATC, STG, OPN, OCT},		/* 1 */
{"open64",	3, DEC, NOV, HID, STG, OPN},			/* 2 */
{"open64",	4, DEC, NOV, HID, STG, OPN, OCT},		/* 3 */
};
#define	NOPENAT64CODE	(sizeof (openat64table) / sizeof (struct systable))

const	struct systable opentable[] = {
{"open",	2, DEC, NOV, STG, OPN},				/* 0 */
{"open",	3, DEC, NOV, STG, OPN, OCT},			/* 1 */
};
#define	NOPENCODE	(sizeof (opentable) / sizeof (struct systable))

const	struct systable open64table[] = {
{"open64",	2, DEC, NOV, STG, OPN},				/* 0 */
{"open64",	3, DEC, NOV, STG, OPN, OCT},			/* 1 */
};
#define	NOPEN64CODE	(sizeof (open64table) / sizeof (struct systable))

const	struct systable fcntltable[] = {
{"fcntl",	3, DEC, NOV, DEC, FCN, HEX},			/* 0: default */
{"fcntl",	2, DEC, NOV, DEC, FCN},				/* 1: no arg */
{"fcntl",	3, DEC, NOV, DEC, FCN, FFG},			/* 2: F_SETFL */
};
#define	NFCNTLCODE	(sizeof (fcntltable) / sizeof (struct systable))

const	struct systable msgtable[] = {
{"msgget",	3, DEC, NOV, HID, KEY, MSF},			/* 0 */
{"msgctl",	4, DEC, NOV, HID, DEC, MSC, HEX},		/* 1 */
{"msgrcv",	6, DEC, NOV, HID, DEC, HEX, UNS, DEC, MSF},	/* 2 */
{"msgsnd",	5, DEC, NOV, HID, DEC, HEX, UNS, MSF},		/* 3 */
{"msgids",	4, DEC, NOV, HID, HEX, UNS, HEX},		/* 4 */
{"msgsnap",	5, DEC, NOV, HID, DEC, HEX, UNS, DEC},		/* 5 */
};
#define	NMSGCODE	(sizeof (msgtable) / sizeof (struct systable))

const	struct systable semtable[] = {
{"semctl",	5, DEC, NOV, HID, DEC, DEC, SMC, DEX},		/* 0 */
{"semget",	4, DEC, NOV, HID, KEY, DEC, SEF},		/* 1 */
{"semop",	4, DEC, NOV, HID, DEC, HEX, UNS},		/* 2 */
{"semids",	4, DEC, NOV, HID, HEX, UNS, HEX},		/* 3 */
{"semtimedop",	5, DEC, NOV, HID, DEC, HEX, UNS, HEX},		/* 4 */
};
#define	NSEMCODE	(sizeof (semtable) / sizeof (struct systable))

const	struct systable shmtable[] = {
{"shmat",	4, HEX, NOV, HID, DEC, DEX, SHF},		/* 0 */
{"shmctl",	4, DEC, NOV, HID, DEC, SHC, DEX},		/* 1 */
{"shmdt",	2, DEC, NOV, HID, HEX},				/* 2 */
{"shmget",	4, DEC, NOV, HID, KEY, UNS, SHF},		/* 3 */
{"shmids",	4, DEC, NOV, HID, HEX, UNS, HEX},		/* 4 */
};
#define	NSHMCODE	(sizeof (shmtable) / sizeof (struct systable))

const	struct systable pidtable[] = {
{"getpgrp",	1, DEC, NOV, HID},				/* 0 */
{"setpgrp",	1, DEC, NOV, HID},				/* 1 */
{"getsid",	2, DEC, NOV, HID, DEC},				/* 2 */
{"setsid",	1, DEC, NOV, HID},				/* 3 */
{"getpgid",	2, DEC, NOV, HID, DEC},				/* 4 */
{"setpgid",	3, DEC, NOV, HID, DEC, DEC},			/* 5 */
};
#define	NPIDCODE	(sizeof (pidtable) / sizeof (struct systable))

const	struct systable sfstable[] = {
{"sysfs",	3, DEC, NOV, SFS, DEX, DEX},			/* 0 */
{"sysfs",	2, DEC, NOV, SFS, STG},				/* 1 */
{"sysfs",	3, DEC, NOV, SFS, DEC, RST},			/* 2 */
{"sysfs",	1, DEC, NOV, SFS},				/* 3 */
};
#define	NSFSCODE	(sizeof (sfstable) / sizeof (struct systable))

const	struct systable utstable[] = {
{"utssys",	3, DEC, NOV, HEX, DEC, UTS},			/* 0 */
{"utssys",	4, DEC, NOV, HEX, HEX, HEX, HEX},		/* err */
{"utssys",	3, DEC, NOV, HEX, HHX, UTS},			/* 2 */
{"utssys",	4, DEC, NOV, STG, FUI, UTS, HEX}		/* 3 */
};
#define	NUTSCODE	(sizeof (utstable) / sizeof (struct systable))

const	struct systable rctltable[] = {
{"getrctl",	6, DEC, NOV, HID, STG, HEX, HEX, HID, RGF},	/* 0 */
{"setrctl",	6, DEC, NOV, HID, STG, HEX, HEX, HID, RSF},	/* 1 */
{"rctlsys_lst",	6, DEC, NOV, HID, HID, HEX, HID, HEX, HID},	/* 2 */
{"rctlsys_ctl",	6, DEC, NOV, HID, STG, HEX, HID, HID, RCF},	/* 3 */
{"setprojrctl",	6, DEC, NOV, HID, STG, HID, HEX, HEX, SPF},	/* 4 */
};
#define	NRCTLCODE	(sizeof (rctltable) / sizeof (struct systable))

const	struct systable sgptable[] = {
{"sigpendsys",	2, DEC, NOV, DEC, HEX},				/* err */
{"sigpending",	2, DEC, NOV, HID, HEX},				/* 1 */
{"sigfillset",	2, DEC, NOV, HID, HEX},				/* 2 */
};
#define	NSGPCODE	(sizeof (sgptable) / sizeof (struct systable))

const	struct systable ctxtable[] = {
{"getcontext",	2, DEC, NOV, HID, HEX},				/* 0 */
{"setcontext",	2, DEC, NOV, HID, HEX},				/* 1 */
{"getustack",	2, DEC, NOV, HID, HEX},				/* 2 */
{"setustack",	2, DEC, NOV, HID, HEX},				/* 3 */
};
#define	NCTXCODE	(sizeof (ctxtable) / sizeof (struct systable))

const	struct systable hrttable[] = {
{"hrtcntl",	5, DEC, NOV, HID, DEC, DEC, HEX, HEX},		/* 0 */
{"hrtalarm",	3, DEC, NOV, HID, HEX, DEC},			/* 1 */
{"hrtsleep",	2, DEC, NOV, HID, HEX},				/* 2 */
{"hrtcancel",	3, DEC, NOV, HID, HEX, DEC},			/* 3 */
};
#define	NHRTCODE	(sizeof (hrttable) / sizeof (struct systable))

const	struct systable cortable[] = {
{"corectl",	4, DEC, NOV, COR, HEX, HEX, HEX},		/* 0 */
{"corectl",	2, DEC, NOV, COR, CCO},				/* 1 */
{"corectl",	1, HHX, NOV, COR},				/* 2 */
{"corectl",	3, DEC, NOV, COR, STG, DEC},			/* 3 */
{"corectl",	3, DEC, NOV, COR, RST, DEC},			/* 4 */
{"corectl",	4, DEC, NOV, COR, STG, DEC, DEC},		/* 5 */
{"corectl",	4, DEC, NOV, COR, RST, DEC, DEC},		/* 6 */
{"corectl",	2, DEC, NOV, COR, CCC},				/* 7 */
{"corectl",	2, DEC, NOV, COR, RCC},				/* 8 */
{"corectl",	3, DEC, NOV, COR, CCC, DEC},			/* 9 */
{"corectl",	3, DEC, NOV, COR, RCC, DEC},			/* 10 */
{"corectl",	3, DEC, NOV, COR, STG, DEC},			/* 11 */
{"corectl",	3, DEC, NOV, COR, RST, DEC},			/* 12 */
{"corectl",	2, DEC, NOV, COR, CCC},				/* 13 */
{"corectl",	2, DEC, NOV, COR, RCC},				/* 14 */
};
#define	NCORCODE	(sizeof (cortable) / sizeof (struct systable))

const	struct systable aiotable[] = {
{"kaio",	7, DEC, NOV, AIO, DEC, HEX, DEC, LLO, HID, HEX}, /* 0 */
{"kaio",	7, DEC, NOV, AIO, DEC, HEX, DEC, LLO, HID, HEX}, /* 1 */
{"kaio",	3, DEC, NOV, AIO, HEX, DEC},			/* 2 */
{"kaio",	3, DEC, NOV, AIO, DEC, HEX},			/* 3 */
{"kaio",	1, DEC, NOV, AIO},				/* 4 */
{"kaio",	1, DEC, NOV, AIO},				/* 5 */
{"kaio",	1, DEC, NOV, AIO},				/* 6 */
{"kaio",	5, DEC, NOV, AIO, LIO, HEX, DEC, HEX},		/* 7 */
{"kaio",	5, DEC, NOV, AIO, HEX, DEC, HEX, DEC},		/* 8 */
{"kaio",	2, DEC, NOV, AIO, HEX},				/* 9 */
{"kaio",	5, DEC, NOV, AIO, LIO, HEX, DEC, HEX},		/* 10 */
{"kaio",	2, DEC, NOV, AIO, HEX},				/* 11 */
{"kaio",	2, DEC, NOV, AIO, HEX},				/* 12 */
{"kaio",	5, DEC, NOV, AIO, LIO, HEX, DEC, HEX},		/* 13 */
{"kaio",	5, DEC, NOV, AIO, HEX, DEC, HEX, DEC},		/* 14 */
{"kaio",	2, DEC, NOV, AIO, HEX},				/* 15 */
{"kaio",	5, DEC, NOV, AIO, LIO, HEX, DEC, HEX},		/* 16 */
{"kaio",	2, DEC, NOV, AIO, HEX},				/* 17 */
{"kaio",	2, DEC, NOV, AIO, HEX},				/* 18 */
{"kaio",	3, DEC, NOV, AIO, DEC, HEX},			/* 19 */
{"kaio",	1, DEC, NOV, AIO},				/* 20 */
{"kaio",	5, DEC, NOV, AIO, HEX, DEC, HEX, HEX},		/* 21 */
};
#define	NAIOCODE	(sizeof (aiotable) / sizeof (struct systable))

const	struct systable doortable[] = {
{"door_create", 3, DEC, NOV, HEX, HEX, DFL},			/* 0 */
{"door_revoke", 1, DEC, NOV, DEC},				/* 1 */
{"door_info",	2, DEC, NOV, DEC, HEX},				/* 2 */
{"door_call",	2, DEC, NOV, DEC, HEX},				/* 3 */
{"door_return", 4, DEC, NOV, HEX, DEC, HEX, DEC},		/* 4 (old) */
{"door_cred",	1, DEC, NOV, HEX},				/* 5 (old) */
{"door_bind",	1, DEC, NOV, DEC},				/* 6 */
{"door_unbind", 0, DEC, NOV},					/* 7 */
{"door_unref",	0, DEC, NOV},					/* 8 */
{"door_ucred",	1, DEC, NOV, HEX},				/* 9 */
{"door_return", 5, DEC, NOV, HEX, DEC, HEX, HEX, DEC},		/* 10 */
{"door_getparam", 3, DEC, NOV, DEC, DPM, HEX},			/* 11 */
{"door_setparam", 3, DEC, NOV, DEC, DPM, DEC},			/* 12 */
};
#define	NDOORCODE	(sizeof (doortable) / sizeof (struct systable))

const	struct systable psettable[] = {
{"pset_create", 2, DEC, NOV, HID, HEX},				/* 0 */
{"pset_destroy", 2, DEC, NOV, HID, PST},			/* 1 */
{"pset_assign",	4, DEC, NOV, HID, PST, DEC, HEX},		/* 2 */
{"pset_info",	5, DEC, NOV, HID, PST, HEX, HEX, HEX},		/* 3 */
{"pset_bind",	5, DEC, NOV, HID, PST, IDT, DEC, HEX},		/* 4 */
{"pset_getloadavg", 4, DEC, NOV, HID, PST, HEX, DEC},		/* 5 */
{"pset_list",	3, DEC, NOV, HID, HEX, HEX},			/* 6 */
{"pset_setattr", 3, DEC, NOV, HID, PST, HEX},			/* 7 */
{"pset_getattr", 3, DEC, NOV, HID, PST, HEX},			/* 8 */
{"pset_assign_forced",	4, DEC, NOV, HID, PST, DEC, HEX},	/* 9 */
};
#define	NPSETCODE	(sizeof (psettable) / sizeof (struct systable))

const	struct systable lwpcreatetable[] = {
{"lwp_create",	3, DEC, NOV, HEX, LWF, HEX},			/* 0 */
{"lwp_create",	0, DEC, NOV},					/* 1 */
};
#define	NLWPCREATECODE	(sizeof (lwpcreatetable) / sizeof (struct systable))

static	const	struct systable tasksystable[] = {
{"settaskid",	3, DEC, NOV, HID, DEC, HEX},			/* 0 */
{"gettaskid",	1, DEC, NOV, HID},				/* 1 */
{"getprojid",	1, DEC, NOV, HID},				/* 2 */
};
#define	NTASKSYSCODE	(sizeof (tasksystable) / sizeof (struct systable))

static const	struct systable privsystable[] = {
{"setppriv",		4, DEC, NOV, HID, PRO, PRN, PRS},	/* 0 */
{"getppriv",		4, DEC, NOV, HID, HID, PRN, PRS},	/* 1 */
{"getprivimplinfo",	5, DEC, NOV, HID, HID, HID, HEX, DEC},	/* 2 */
{"setpflags",		3, DEC, NOV, HID, PFL, DEC},		/* 3 */
{"getpflags",		2, DEC, NOV, HID, PFL},			/* 4 */
{"issetugid",		0, DEC, NOV, HID},			/* 5 */
};
#define	NPRIVSYSCODE	(sizeof (privsystable) / sizeof (struct systable))

static	const	struct systable exacctsystable[] = {
{"getacct",	5, DEC, NOV, HID, IDT, DEC, HEX, UNS},		/* 0 */
{"putacct",	6, DEC, NOV, HID, IDT, DEC, HEX, UNS, HEX},	/* 1 */
{"wracct",	4, DEC, NOV, HID, IDT, DEC, HEX},		/* 2 */
};
#define	NEXACCTSYSCODE	(sizeof (exacctsystable) / sizeof (struct systable))

static	const	struct systable lwpparktable[] = {
{"lwp_park",	3, DEC, NOV, HID, HEX, DEC},			/* 0 */
{"lwp_unpark",	2, DEC, NOV, HID, DEC},				/* 1 */
{"lwp_unpark_all", 3, DEC, NOV, HID, HEX, DEC},			/* 2 */
{"lwp_unpark_cancel",	2, DEC, NOV, HID, DEC},			/* 3 */
{"lwp_set_park",	3, DEC, NOV, HID, HEX, DEC},		/* 4 */
};
#define	NLWPPARKCODE	(sizeof (lwpparktable) / sizeof (struct systable))

static	const	struct systable lwprwlocktable[] = {
{"lwp_rwlock_rdlock", 3, DEC, NOV, HID, HEX, HEX},		/* 0 */
{"lwp_rwlock_wrlock", 3, DEC, NOV, HID, HEX, HEX},		/* 1 */
{"lwp_rwlock_tryrdlock", 2, DEC, NOV, HID, HEX},		/* 2 */
{"lwp_rwlock_trywrlock", 2, DEC, NOV, HID, HEX},		/* 3 */
{"lwp_rwlock_unlock", 2, DEC, NOV, HID, HEX},			/* 4 */
};
#define	NLWPRWLOCKCODE	(sizeof (lwprwlocktable) / sizeof (struct systable))

static	const	struct systable sendfilevsystable[] = {
{"sendfilev",	5, DEC, NOV, DEC, DEC, HEX, DEC, HEX},		/* 0 */
{"sendfilev64",	5, DEC, NOV, DEC, DEC, HEX, DEC, HEX},		/* 1 */
};
#define	NSENDFILESYSCODE \
		(sizeof (sendfilevsystable) / sizeof (struct systable))

static	const	struct systable lgrpsystable[] = {
{"meminfo",		3, DEC, NOV, HID, NOV, MIF},		/* 0 */
{"_lgrpsys",		3, DEC, NOV, DEC, DEC, NOV},		/* 1 */
{"lgrp_version",	3, DEC, NOV, HID, DEC, NOV},		/* 2 */
{"_lgrpsys",		3, DEC, NOV, DEC, HEX, HEX},		/* 3 */
{"lgrp_affinity_get",	3, DEC, NOV, HID, NOV, LAF},		/* 4 */
{"lgrp_affinity_set",	3, DEC, NOV, HID, NOV, LAF},		/* 5 */
{"lgrp_latency",	3, DEC, NOV, HID, DEC, DEC},		/* 6 */
};
#define	NLGRPSYSCODE	(sizeof (lgrpsystable) / sizeof (struct systable))

static	const	struct systable rusagesystable[] = {
{"getrusage",		2, DEC, NOV, HID, HEX},			/* 0 */
{"getrusage_chld",	2, DEC, NOV, HID, HEX},			/* 1 */
{"getrusage_lwp",	2, DEC, NOV, HID, HEX},			/* 2 */
{"getvmusage",		5, DEC, NOV, HID, HEX, DEC, HEX, HEX},	/* 3 */
};
#define	NRUSAGESYSCODE \
		(sizeof (rusagesystable) / sizeof (struct systable))

static const	struct systable ucredsystable[] = {
{"ucred_get",	3, DEC, NOV, HID, DEC, HEX},
{"getpeerucred", 3, DEC, NOV, HID, DEC, HEX},
};
#define	NUCREDSYSCODE \
		(sizeof (ucredsystable) / sizeof (struct systable))

const	struct systable portfstable[] = {
{"port_create",	2, DEC, NOV, HID, DEC},				/* 0 */
{"port_associate",	6, DEC, NOV, HID, DEC, DEC, HEX, HEX, HEX}, /* 1 */
{"port_dissociate",	4, DEC, NOV, HID, DEC, DEC, HEX}, 	/* 2 */
{"port_send",	4, DEC, NOV, HID, DEC, HEX, HEX},		/* 3 */
{"port_sendn",	6, DEC, DEC, HID, HEX, HEX, DEC, HEX, HEX},	/* 4 */
{"port_get",	4, DEC, NOV, HID, DEC, HEX, HEX},		/* 5 */
{"port_getn",	6, DEC, DEC, HID, DEC, HEX, DEC, DEC, HEX},	/* 6 */
{"port_alert",	5, DEC, NOV, HID, DEC, HEX, HEX, HEX},		/* 7 */
{"port_dispatch", 6, DEC, NOV, HID, DEC, DEC, HEX, HEX, HEX},	/* 8 */
};
#define	NPORTCODE	(sizeof (portfstable) / sizeof (struct systable))

static const struct systable zonetable[] = {
{"zone_create",	2, DEC, NOV, HID, HEX},				/* 0 */
{"zone_destroy", 2, DEC, NOV, HID, DEC},			/* 1 */
{"zone_getattr", 5, DEC, NOV, HID, DEC, ZGA, HEX, DEC},		/* 2 */
{"zone_enter",	2, DEC, NOV, HID, DEC},				/* 3 */
{"zone_list",	3, DEC, NOV, HID, HEX, HEX},			/* 4 */
{"zone_shutdown", 2, DEC, NOV, HID, DEC},			/* 5 */
{"zone_lookup",	2, DEC, NOV, HID, STG},				/* 6 */
{"zone_boot",	2, DEC, NOV, HID, DEC},				/* 7 */
{"zone_version", 2, HEX, NOV, HID, DEC},			/* 8 */
{"zone_setattr", 5, DEC, NOV, HID, DEC, ZGA, HEX, DEC},		/* 9 */
{"zone_add_datalink", 3, DEC, NOV, HID, DEC, STG},		/* 10 */
{"zone_remove_datalink", 3, DEC, NOV, HID, DEC, STG},		/* 11 */
{"zone_check_datalink", 3, DEC, NOV, HID, HEX, STG},		/* 12 */
{"zone_list_datalink", 4, DEC, NOV, HID, DEC, HEX, HEX},	/* 13 */
};
#define	NZONECODE	(sizeof (zonetable) / sizeof (struct systable))

static const struct systable labeltable[] = {
{"labelsys",	3, DEC, NOV, HID, HEX, HEX},			/* 0 */
{"is_system_labeled", 1, DEC, NOV, HID},			/* 1 */
{"tnrh",	3, DEC, NOV, HID, TND, HEX},			/* 2 */
{"tnrhtp",	3, DEC, NOV, HID, TND, HEX},			/* 3 */
{"tnmlp",	3, DEC, NOV, HID, TND, HEX},			/* 4 */
{"getlabel",	3, DEC, NOV, HID, STG, HEX},			/* 5 */
{"fgetlabel",	3, DEC, NOV, HID, DEC, HEX},			/* 6 */
};
#define	NLABELCODE	(sizeof (labeltable) / sizeof (struct systable))

const	struct systable forktable[] = {
/* parent codes */
{"forkx",	2, DEC, NOV, HID, FXF},				/* 0 */
{"forkallx",	2, DEC, NOV, HID, FXF},				/* 1 */
{"vforkx",	2, DEC, NOV, HID, FXF},				/* 2 */
/* child codes */
{"forkx",	0, DEC, NOV},					/* 3 */
{"forkallx",	0, DEC, NOV},					/* 4 */
{"vforkx",	0, DEC, NOV},					/* 5 */
};
#define	NFORKCODE	(sizeof (forktable) / sizeof (struct systable))

const	struct systable sidsystable[] = {
{"allocids",	4, UNS, UNS, HID, DEC, DEC, DEC},		/* 0 */
{"idmap_reg",	2, DEC, NOV, HID, DEC},				/* 1 */
{"idmap_unreg",	2, DEC, NOV, HID, DEC},				/* 2 */
};
#define	NSIDSYSCODE	(sizeof (sidsystable) / sizeof (struct systable))

const	struct systable utimesystable[] = {
{"futimens",	3, DEC, NOV, HID, DEC, HEX},			/* 0 */
{"utimensat",	5, DEC, NOV, HID, ATC, STG, HEX, SNF},		/* 1 */
};
#define	NUTIMESYSCODE	(sizeof (utimesystable) / sizeof (struct systable))

const	struct systable sockconfigtable[] = {
{"sockconfig", 5, DEC, NOV, SKC, DEC, DEC, DEC, STG},	/* 0 */
{"sockconfig", 4, DEC, NOV, SKC, DEC, DEC, DEC},	/* 1 */
{"sockconfig", 3, DEC, NOV, SKC, STG, HEX },		/* 2 */
{"sockconfig", 2, DEC, NOV, SKC, STG },			/* 3 */
};
#define	NSOCKCONFIGCODE	(sizeof (sockconfigtable) / sizeof (struct systable))

const	struct sysalias sysalias[] = {
	{ "exit",	SYS_exit	},
	{ "fork",	SYS_forksys	},
	{ "fork1",	SYS_forksys	},
	{ "forkall",	SYS_forksys	},
	{ "forkx",	SYS_forksys	},
	{ "forkallx",	SYS_forksys	},
	{ "vforkx",	SYS_forksys	},
	{ "sbrk",	SYS_brk		},
	{ "getppid",	SYS_getpid	},
	{ "geteuid",	SYS_getuid	},
	{ "getpgrp",	SYS_pgrpsys	},
	{ "setpgrp",	SYS_pgrpsys	},
	{ "getsid",	SYS_pgrpsys	},
	{ "setsid",	SYS_pgrpsys	},
	{ "getpgid",	SYS_pgrpsys	},
	{ "setpgid",	SYS_pgrpsys	},
	{ "getegid",	SYS_getgid	},
	{ "msgget",	SYS_msgsys	},
	{ "msgctl",	SYS_msgsys	},
	{ "msgctl64",	SYS_msgsys	},
	{ "msgrcv",	SYS_msgsys	},
	{ "msgsnd",	SYS_msgsys	},
	{ "msgids",	SYS_msgsys	},
	{ "msgsnap",	SYS_msgsys	},
	{ "msgop",	SYS_msgsys	},
	{ "shmat",	SYS_shmsys	},
	{ "shmctl",	SYS_shmsys	},
	{ "shmctl64",	SYS_shmsys	},
	{ "shmdt",	SYS_shmsys	},
	{ "shmget",	SYS_shmsys	},
	{ "shmids",	SYS_shmsys	},
	{ "shmop",	SYS_shmsys	},
	{ "semctl",	SYS_semsys	},
	{ "semctl64",	SYS_semsys	},
	{ "semget",	SYS_semsys	},
	{ "semids",	SYS_semsys	},
	{ "semop",	SYS_semsys	},
	{ "semtimedop",	SYS_semsys	},
	{ "uname",	SYS_utssys	},
	{ "ustat",	SYS_utssys	},
	{ "fusers",	SYS_utssys	},
	{ "exec",	SYS_execve	},
	{ "execl",	SYS_execve	},
	{ "execv",	SYS_execve	},
	{ "execle",	SYS_execve	},
	{ "execlp",	SYS_execve	},
	{ "execvp",	SYS_execve	},
	{ "sigfillset",	SYS_sigpending	},
	{ "getcontext",	SYS_context	},
	{ "setcontext",	SYS_context	},
	{ "getustack",	SYS_context	},
	{ "setustack",	SYS_context	},
	{ "hrtcntl",	SYS_hrtsys	},
	{ "hrtalarm",	SYS_hrtsys	},
	{ "hrtsleep",	SYS_hrtsys	},
	{ "hrtcancel",	SYS_hrtsys	},
	{ "aioread",	SYS_kaio	},
	{ "aiowrite",	SYS_kaio	},
	{ "aiowait",	SYS_kaio	},
	{ "aiocancel",	SYS_kaio	},
	{ "aionotify",	SYS_kaio	},
	{ "audit",	SYS_auditsys	},
	{ "door_create",	SYS_door	},
	{ "door_revoke",	SYS_door	},
	{ "door_info",		SYS_door	},
	{ "door_call",		SYS_door	},
	{ "door_return",	SYS_door	},
	{ "door_bind",		SYS_door	},
	{ "door_unbind",	SYS_door	},
	{ "door_unref",		SYS_door	},
	{ "door_ucred",		SYS_door	},
	{ "door_getparam",	SYS_door	},
	{ "door_setparam",	SYS_door	},
	{ "pset_create",	SYS_pset	},
	{ "pset_destroy",	SYS_pset	},
	{ "pset_assign",	SYS_pset	},
	{ "pset_info",		SYS_pset	},
	{ "pset_bind",		SYS_pset	},
	{ "pset_getloadavg",	SYS_pset	},
	{ "pset_list",		SYS_pset	},
	{ "pset_setattr",	SYS_pset	},
	{ "pset_getattr",	SYS_pset	},
	{ "pset_assign_forced",	SYS_pset	},
	{ "settaskid",		SYS_tasksys	},
	{ "gettaskid",		SYS_tasksys	},
	{ "getprojid",		SYS_tasksys	},
	{ "setppriv",		SYS_privsys	},
	{ "getppriv",		SYS_privsys	},
	{ "getprivimplinfo",	SYS_privsys	},
	{ "setpflags",		SYS_privsys	},
	{ "getpflags",		SYS_privsys	},
	{ "getacct",		SYS_exacctsys	},
	{ "putacct",		SYS_exacctsys	},
	{ "wracct",		SYS_exacctsys	},
	{ "lwp_cond_timedwait",	SYS_lwp_cond_wait },
	{ "lwp_sema_wait",	SYS_lwp_sema_timedwait },
	{ "lwp_park",		SYS_lwp_park	},
	{ "lwp_unpark",		SYS_lwp_park	},
	{ "lwp_unpark_all",	SYS_lwp_park	},
	{ "lwp_rwlock_rdlock",	SYS_lwp_rwlock_sys },
	{ "lwp_rwlock_wrlock",	SYS_lwp_rwlock_sys },
	{ "lwp_rwlock_tryrdlock", SYS_lwp_rwlock_sys },
	{ "lwp_rwlock_trywrlock", SYS_lwp_rwlock_sys },
	{ "lwp_rwlock_unlock",	SYS_lwp_rwlock_sys },
	{ "lwp_mutex_lock",	SYS_lwp_mutex_timedlock },
	{ "sendfilev64",	SYS_sendfilev	},
	{ "creat",		SYS_open	},
	{ "creat64",		SYS_open64	},
	{ "openattrdirat",	SYS_openat	},
	{ "lgrpsys",		SYS_lgrpsys	},
	{ "getrusage",		SYS_rusagesys	},
	{ "getrusage_chld",	SYS_rusagesys	},
	{ "getrusage_lwp",	SYS_rusagesys	},
	{ "getvmusage",		SYS_rusagesys	},
	{ "getpeerucred",	SYS_ucredsys	},
	{ "ucred_get",		SYS_ucredsys	},
	{ "port_create",	SYS_port	},
	{ "port_associate",	SYS_port	},
	{ "port_dissociate",	SYS_port	},
	{ "port_send",		SYS_port	},
	{ "port_sendn",		SYS_port	},
	{ "port_get",		SYS_port	},
	{ "port_getn",		SYS_port	},
	{ "port_alert",		SYS_port	},
	{ "port_dispatch",	SYS_port	},
	{ "zone_create",	SYS_zone	},
	{ "zone_destroy",	SYS_zone	},
	{ "zone_getattr",	SYS_zone	},
	{ "zone_setattr",	SYS_zone	},
	{ "zone_enter",		SYS_zone	},
	{ "getzoneid",		SYS_zone	},
	{ "zone_list",		SYS_zone	},
	{ "zone_shutdown",	SYS_zone	},
	{ "zone_add_datalink",	SYS_zone	},
	{ "zone_remove_datalink", SYS_zone	},
	{ "zone_check_datalink", SYS_zone	},
	{ "zone_list_datalink",	SYS_zone	},
	{ "is_system_labeled",	SYS_labelsys	},
	{ "tnrh",		SYS_labelsys	},
	{ "tnrhtp",		SYS_labelsys	},
	{ "tnmlp",		SYS_labelsys	},
	{ "getlabel",		SYS_labelsys	},
	{ "fgetlabel",		SYS_labelsys	},
	{ "getrctl",		SYS_rctlsys	},
	{ "setrctl",		SYS_rctlsys	},
	{ "rctlsys_lst",	SYS_rctlsys	},
	{ "rctlsys_ctl",	SYS_rctlsys	},
	{ "allocids",		SYS_sidsys	},
	{ "futimens",		SYS_utimesys	},
	{ "utimensat",		SYS_utimesys	},
	{ "poll",		SYS_pollsys	},
	{ "umount",		SYS_umount2	},
	{ "wait",		SYS_waitid	},
	{  NULL,	0	}	/* end-of-list */
};

/*
 * Return structure to interpret system call with sub-codes.
 */
const struct systable *
subsys(int syscall, int subcode)
{
	const struct systable *stp = NULL;

	if (subcode != -1) {
		switch (syscall) {
		case SYS_faccessat:
			if ((unsigned)subcode < NACCESSCODE)
				stp = &faccessattable[subcode];
			break;
		case SYS_fchmodat:
			if ((unsigned)subcode < NCHMODCODE)
				stp = &fchmodattable[subcode];
			break;
		case SYS_fchownat:
			if ((unsigned)subcode < NCHOWNCODE)
				stp = &fchownattable[subcode];
			break;
		case SYS_mkdirat:
			if ((unsigned)subcode < NMKDIRCODE)
				stp = &mkdiratattable[subcode];
			break;
		case SYS_mknodat:
			if ((unsigned)subcode < NMKMODCODE)
				stp = &mknodatattable[subcode];
			break;
		case SYS_renameat:
			if ((unsigned)subcode < NRENAMECODE)
				stp = &renameattable[subcode];
			break;
		case SYS_linkat:
			if ((unsigned)subcode < NLINKATCODE)
				stp = &linkattable[subcode];
			break;
		case SYS_unlinkat:
			if ((unsigned)subcode < NUNLINKCODE)
				stp = &unlinkattable[subcode];
			break;
		case SYS_symlinkat:
			if ((unsigned)subcode < NSYMLINKCODE)
				stp = &symlinkattable[subcode];
			break;
		case SYS_readlinkat:
			if ((unsigned)subcode < NREADLINKCODE)
				stp = &readlinkattable[subcode];
			break;
		case SYS_fstatat:
			if ((unsigned)subcode < NSTATCODE)
				stp = &fstatattable[subcode];
			break;
		case SYS_fstatat64:
			if ((unsigned)subcode < NSTAT64CODE)
				stp = &fstatat64table[subcode];
			break;
		case SYS_openat:
			if ((unsigned)subcode < NOPENATCODE)
				stp = &openattable[subcode];
			break;
		case SYS_openat64:
			if ((unsigned)subcode < NOPENAT64CODE)
				stp = &openat64table[subcode];
			break;
		case SYS_open:
			if ((unsigned)subcode < NOPENCODE)
				stp = &opentable[subcode];
			break;
		case SYS_open64:
			if ((unsigned)subcode < NOPEN64CODE)
				stp = &open64table[subcode];
			break;
		case SYS_msgsys:	/* msgsys() */
			if ((unsigned)subcode < NMSGCODE)
				stp = &msgtable[subcode];
			break;
		case SYS_semsys:	/* semsys() */
			if ((unsigned)subcode < NSEMCODE)
				stp = &semtable[subcode];
			break;
		case SYS_shmsys:	/* shmsys() */
			if ((unsigned)subcode < NSHMCODE)
				stp = &shmtable[subcode];
			break;
		case SYS_pgrpsys:	/* pgrpsys() */
			if ((unsigned)subcode < NPIDCODE)
				stp = &pidtable[subcode];
			break;
		case SYS_utssys:	/* utssys() */
			if ((unsigned)subcode < NUTSCODE)
				stp = &utstable[subcode];
			break;
		case SYS_sysfs:		/* sysfs() */
			if ((unsigned)subcode < NSFSCODE)
				stp = &sfstable[subcode];
			break;
		case SYS_sigpending:	/* sigpending()/sigfillset() */
			if ((unsigned)subcode < NSGPCODE)
				stp = &sgptable[subcode];
			break;
		case SYS_context:	/* [get|set]context() */
			if ((unsigned)subcode < NCTXCODE)
				stp = &ctxtable[subcode];
			break;
		case SYS_hrtsys:	/* hrtsys() */
			if ((unsigned)subcode < NHRTCODE)
				stp = &hrttable[subcode];
			break;
		case SYS_corectl:	/* corectl() */
			if ((unsigned)subcode < NCORCODE)
				stp = &cortable[subcode];
			break;
		case SYS_kaio:		/* kaio() */
			if ((unsigned)subcode < NAIOCODE)
				stp = &aiotable[subcode];
			break;
		case SYS_door:		/* doors */
			if ((unsigned)subcode < NDOORCODE)
				stp = &doortable[subcode];
			break;
		case SYS_pset:		/* pset() */
			if ((unsigned)subcode < NPSETCODE)
				stp = &psettable[subcode];
			break;
		case SYS_lwp_create:	/* lwp_create() */
			if ((unsigned)subcode < NLWPCREATECODE)
				stp = &lwpcreatetable[subcode];
			break;
		case SYS_tasksys:	/* tasks */
			if ((unsigned)subcode < NTASKSYSCODE)
				stp = &tasksystable[subcode];
			break;
		case SYS_exacctsys:	/* exacct */
			if ((unsigned)subcode < NEXACCTSYSCODE)
				stp = &exacctsystable[subcode];
			break;
		case SYS_privsys:	/* privileges */
			if ((unsigned)subcode < NPRIVSYSCODE)
				stp = &privsystable[subcode];
			break;
		case SYS_lwp_park:	/* lwp_park */
			if ((unsigned)subcode < NLWPPARKCODE)
				stp = &lwpparktable[subcode];
			break;
		case SYS_lwp_rwlock_sys:
			if ((unsigned)subcode < NLWPRWLOCKCODE)
				stp = &lwprwlocktable[subcode];
			break;
		case SYS_sendfilev:	/* sendfilev */
			if ((unsigned)subcode < NSENDFILESYSCODE)
				stp = &sendfilevsystable[subcode];
			break;
		case SYS_lgrpsys:	/* lgrpsys */
			if ((unsigned)subcode < NLGRPSYSCODE)
				stp = &lgrpsystable[subcode];
			break;
		case SYS_rusagesys:	/* rusagesys */
			if ((unsigned)subcode < NRUSAGESYSCODE)
				stp = &rusagesystable[subcode];
			break;
		case SYS_fcntl:		/* fcntl */
			if ((unsigned)subcode < NFCNTLCODE)
				stp = &fcntltable[subcode];
			break;
		case SYS_ucredsys:
			if ((unsigned)subcode < NUCREDSYSCODE)
				stp = &ucredsystable[subcode];
			break;
		case SYS_port:	/* portfs */
			if ((unsigned)subcode < NPORTCODE)
				stp = &portfstable[subcode];
			break;
		case SYS_zone:		/* zone family */
			if ((unsigned)subcode < NZONECODE)
				stp = &zonetable[subcode];
			break;
		case SYS_labelsys:	/* label family */
			if ((unsigned)subcode < NLABELCODE)
				stp = &labeltable[subcode];
			break;
		case SYS_rctlsys:	/* rctl family */
			if ((unsigned)subcode < NRCTLCODE)
				stp = &rctltable[subcode];
			break;
		case SYS_forksys:	/* fork family */
			if ((unsigned)subcode < NFORKCODE)
				stp = &forktable[subcode];
			break;
		case SYS_sidsys:	/* SID family */
			if ((unsigned)subcode < NSIDSYSCODE)
				stp = &sidsystable[subcode];
			break;
		case SYS_utimesys:	/* utime family */
			if ((unsigned)subcode < NUTIMESYSCODE)
				stp = &utimesystable[subcode];
			break;
		case SYS_sockconfig:	/* sockconfig family */
			if ((unsigned)subcode < NSOCKCONFIGCODE)
				stp = &sockconfigtable[subcode];
			break;
		}
	}

	if (stp == NULL)
		stp = &systable[((unsigned)syscall < SYSEND)? syscall : 0];

	return (stp);
}

/*
 * Return the name of the system call.
 */
const char *
sysname(private_t *pri, int syscall, int subcode)
{
	const struct systable *stp = subsys(syscall, subcode);
	const char *name = stp->name;	/* may be NULL */

	if (name == NULL) {		/* manufacture a name */
		(void) sprintf(pri->sys_name, "sys#%d", syscall);
		name = pri->sys_name;
	}

	return (name);
}

/*
 * Return the name of the signal.
 * Return NULL if unknown signal.
 */
const char *
rawsigname(private_t *pri, int sig)
{
	/*
	 * The C library function sig2str() omits the leading "SIG".
	 */
	(void) strcpy(pri->raw_sig_name, "SIG");

	if (sig > 0 && sig2str(sig, pri->raw_sig_name+3) == 0)
		return (pri->raw_sig_name);
	return (NULL);
}

/*
 * Return the name of the signal.
 * Manufacture a name for unknown signal.
 */
const char *
signame(private_t *pri, int sig)
{
	const char *name = rawsigname(pri, sig);

	if (name == NULL) {			/* manufacture a name */
		(void) sprintf(pri->sig_name, "SIG#%d", sig);
		name = pri->sig_name;
	}

	return (name);
}

/*
 * Determine the subcode for this syscall, if any.
 */
int
getsubcode(private_t *pri)
{
	const lwpstatus_t *Lsp = pri->lwpstat;
	int syscall = Lsp->pr_syscall;
	int nsysarg = Lsp->pr_nsysarg;
	int subcode = -1;
	int arg0;

	if (syscall > 0 && nsysarg > 0 && !prismember(&rawout, syscall)) {
		arg0 = Lsp->pr_sysarg[0];
		switch (syscall) {
		case SYS_utssys:	/* utssys() */
			if (nsysarg > 2)
				subcode = Lsp->pr_sysarg[2];
			break;
		case SYS_faccessat:
			if (nsysarg > 3)
				subcode = ((int)Lsp->pr_sysarg[0] == AT_FDCWD &&
				    Lsp->pr_sysarg[3] == 0)? 1 : 0;
			break;
		case SYS_fchmodat:
			if (nsysarg > 1 && Lsp->pr_sysarg[1] == NULL) {
				subcode = 3;
				break;
			}
			if (nsysarg > 0 && (int)Lsp->pr_sysarg[0] != AT_FDCWD) {
				subcode = 0;
				break;
			}
			if (nsysarg > 3)
				subcode = (Lsp->pr_sysarg[3] == 0)? 1 :
				    (Lsp->pr_sysarg[3] == AT_SYMLINK_NOFOLLOW)?
				    2 : 0;
			break;
		case SYS_fchownat:
			if (nsysarg > 1 && Lsp->pr_sysarg[1] == NULL) {
				subcode = 3;
				break;
			}
			if (nsysarg > 0 && (int)Lsp->pr_sysarg[0] != AT_FDCWD) {
				subcode = 0;
				break;
			}
			if (nsysarg > 4)
				subcode = (Lsp->pr_sysarg[4] == 0)? 1 :
				    (Lsp->pr_sysarg[4] == AT_SYMLINK_NOFOLLOW)?
				    2 : 0;
			break;
		case SYS_mkdirat:
		case SYS_mknodat:
		case SYS_readlinkat:
			if (nsysarg > 0)
				subcode = ((int)Lsp->pr_sysarg[0] == AT_FDCWD)?
				    1 : 0;
			break;
		case SYS_renameat:
			if (nsysarg > 2)
				subcode = ((int)Lsp->pr_sysarg[0] == AT_FDCWD &&
				    (int)Lsp->pr_sysarg[2] == AT_FDCWD)? 1 : 0;
			break;
		case SYS_linkat:
			if (nsysarg > 4)
				subcode = ((int)Lsp->pr_sysarg[0] == AT_FDCWD &&
				    (int)Lsp->pr_sysarg[2] == AT_FDCWD &&
				    Lsp->pr_sysarg[4] == 0)? 1 : 0;
			break;
		case SYS_unlinkat:
			if (nsysarg > 2)
				subcode =
				    ((int)Lsp->pr_sysarg[0] != AT_FDCWD)? 0 :
				    (Lsp->pr_sysarg[2] == AT_REMOVEDIR)? 2 :
				    (Lsp->pr_sysarg[2] == 0)? 1 : 0;
			break;
		case SYS_symlinkat:
			if (nsysarg > 1)
				subcode = ((int)Lsp->pr_sysarg[1] == AT_FDCWD)?
				    1 : 0;
			break;
		case SYS_fstatat:
		case SYS_fstatat64:
			if (nsysarg > 1 && Lsp->pr_sysarg[1] == NULL) {
				subcode = 3;
				break;
			}
			if (nsysarg > 0 && (int)Lsp->pr_sysarg[0] != AT_FDCWD) {
				subcode = 0;
				break;
			}
			if (nsysarg > 3)
				subcode = (Lsp->pr_sysarg[3] == 0)? 1 :
				    (Lsp->pr_sysarg[3] == AT_SYMLINK_NOFOLLOW)?
				    2 : 0;
			break;
		case SYS_openat:	/* openat() w/ and w/o AT_FDCWD */
		case SYS_openat64:	/* and with and w/o O_CREAT */
			if (nsysarg > 2)
				subcode = ((int)Lsp->pr_sysarg[0] == AT_FDCWD)?
				    ((Lsp->pr_sysarg[2] & O_CREAT)? 3 : 2) :
				    ((Lsp->pr_sysarg[2] & O_CREAT)? 1 : 0);
			break;
		case SYS_open:		/* open() w/ and w/o O_CREAT */
		case SYS_open64:
			if (nsysarg > 1)
				subcode = (Lsp->pr_sysarg[1] & O_CREAT)? 1 : 0;
			break;
		case SYS_kaio:		/* kaio() */
			subcode = arg0 & ~AIO_POLL_BIT;
			break;
		case SYS_door:		/* doors */
			if (nsysarg > 5)
				subcode = Lsp->pr_sysarg[5];
			break;
		case SYS_lwp_create:	/* lwp_create() */
			subcode =	/* 0 for parent, 1 for child */
			    (Lsp->pr_why == PR_SYSEXIT && Lsp->pr_errno == 0 &&
			    Lsp->pr_rval1 == 0);
			break;
		case SYS_forksys:	/* forksys */
			subcode = arg0;
			if (Lsp->pr_why == PR_SYSEXIT && Lsp->pr_errno == 0 &&
			    pri->Rval2 != 0)	/* this is the child */
				subcode += 3;
			break;
		case SYS_msgsys:	/* msgsys() */
		case SYS_semsys:	/* semsys() */
		case SYS_shmsys:	/* shmsys() */
		case SYS_pgrpsys:	/* pgrpsys() */
		case SYS_sysfs:		/* sysfs() */
		case SYS_sigpending:	/* sigpending()/sigfillset() */
		case SYS_context:	/* [get|set]context() */
		case SYS_hrtsys:	/* hrtsys() */
		case SYS_corectl:	/* corectl() */
		case SYS_pset:		/* pset() */
		case SYS_tasksys:	/* tasks */
		case SYS_privsys:	/* privileges */
		case SYS_exacctsys:	/* exacct */
		case SYS_lwp_park:	/* lwp_park */
		case SYS_lwp_rwlock_sys: /* lwp_rwlock_*() */
		case SYS_sendfilev:	/* sendfilev */
		case SYS_lgrpsys:	/* lgrpsys */
		case SYS_rusagesys:	/* rusagesys */
		case SYS_ucredsys:	/* ucredsys */
		case SYS_zone:		/* zone */
		case SYS_labelsys:	/* labelsys */
		case SYS_rctlsys:	/* rctlsys */
		case SYS_sidsys:	/* sidsys */
		case SYS_utimesys:	/* utimesys */
		case SYS_sockconfig:	/* sockconfig */
			subcode = arg0;
			break;
		case SYS_fcntl:		/* fcntl() */
			if (nsysarg > 2) {
				switch (Lsp->pr_sysarg[1]) {
				default:	subcode = 0; break;
				case F_GETFL:
				case F_GETOWN:
				case F_GETXFL:	subcode = 1; break;
				case F_SETFL:	subcode = 2; break;
				}
			}
			break;
		case SYS_port:		/* portfs */
			subcode = arg0 & PORT_CODE_MASK;
			break;
		}
	}

	return (subcode);
}

/*
 * Return the maximum number of system calls, counting
 * all system calls with subcodes as separate calls.
 */
int
maxsyscalls()
{
	return (PRMAXSYS + 1
	    + NACCESSCODE - 1
	    + NCHMODCODE - 1
	    + NCHOWNCODE - 1
	    + NMKDIRCODE - 1
	    + NMKMODCODE - 1
	    + NRENAMECODE - 1
	    + NLINKATCODE - 1
	    + NUNLINKCODE - 1
	    + NSYMLINKCODE - 1
	    + NREADLINKCODE - 1
	    + NSTATCODE - 1
	    + NSTAT64CODE - 1
	    + NOPENATCODE - 1
	    + NOPENAT64CODE - 1
	    + NOPENCODE - 1
	    + NOPEN64CODE - 1
	    + NMSGCODE - 1
	    + NSEMCODE - 1
	    + NSHMCODE - 1
	    + NPIDCODE - 1
	    + NSFSCODE - 1
	    + NUTSCODE - 1
	    + NSGPCODE - 1
	    + NCTXCODE - 1
	    + NHRTCODE - 1
	    + NCORCODE - 1
	    + NAIOCODE - 1
	    + NDOORCODE - 1
	    + NPSETCODE - 1
	    + NLWPCREATECODE - 1
	    + NTASKSYSCODE - 1
	    + NEXACCTSYSCODE - 1
	    + NLWPPARKCODE - 1
	    + NLWPRWLOCKCODE - 1
	    + NSENDFILESYSCODE - 1
	    + NLGRPSYSCODE - 1
	    + NRUSAGESYSCODE - 1
	    + NFCNTLCODE - 1
	    + NPRIVSYSCODE - 1
	    + NUCREDSYSCODE - 1
	    + NPORTCODE - 1
	    + NZONECODE - 1
	    + NLABELCODE - 1
	    + NRCTLCODE - 1
	    + NFORKCODE - 1
	    + NSIDSYSCODE - 1
	    + NUTIMESYSCODE - 1
	    + NSOCKCONFIGCODE - 1);
}

/*
 * Return the number of subcodes for the specified system call number.
 */
int
nsubcodes(int syscall)
{
	switch (syscall) {
	case SYS_faccessat:
		return (NACCESSCODE);
	case SYS_fchmodat:
		return (NCHMODCODE);
	case SYS_fchownat:
		return (NCHOWNCODE);
	case SYS_mkdirat:
		return (NMKDIRCODE);
	case SYS_mknodat:
		return (NMKMODCODE);
	case SYS_renameat:
		return (NRENAMECODE);
	case SYS_linkat:
		return (NLINKATCODE);
	case SYS_unlinkat:
		return (NUNLINKCODE);
	case SYS_symlinkat:
		return (NSYMLINKCODE);
	case SYS_readlinkat:
		return (NREADLINKCODE);
	case SYS_fstatat:
		return (NSTATCODE);
	case SYS_fstatat64:
		return (NSTAT64CODE);
	case SYS_openat:
		return (NOPENATCODE);
	case SYS_openat64:
		return (NOPENAT64CODE);
	case SYS_open:
		return (NOPENCODE);
	case SYS_open64:
		return (NOPEN64CODE);
	case SYS_msgsys:
		return (NMSGCODE);
	case SYS_semsys:
		return (NSEMCODE);
	case SYS_shmsys:
		return (NSHMCODE);
	case SYS_pgrpsys:
		return (NPIDCODE);
	case SYS_utssys:
		return (NUTSCODE);
	case SYS_sysfs:
		return (NSFSCODE);
	case SYS_sigpending:
		return (NSGPCODE);
	case SYS_context:
		return (NCTXCODE);
	case SYS_hrtsys:
		return (NHRTCODE);
	case SYS_corectl:
		return (NCORCODE);
	case SYS_kaio:
		return (NAIOCODE);
	case SYS_door:
		return (NDOORCODE);
	case SYS_pset:
		return (NPSETCODE);
	case SYS_lwp_create:
		return (NLWPCREATECODE);
	case SYS_tasksys:
		return (NTASKSYSCODE);
	case SYS_exacctsys:
		return (NEXACCTSYSCODE);
	case SYS_privsys:
		return (NPRIVSYSCODE);
	case SYS_lwp_park:
		return (NLWPPARKCODE);
	case SYS_lwp_rwlock_sys:
		return (NLWPRWLOCKCODE);
	case SYS_sendfilev:
		return (NSENDFILESYSCODE);
	case SYS_lgrpsys:
		return (NLGRPSYSCODE);
	case SYS_rusagesys:
		return (NRUSAGESYSCODE);
	case SYS_fcntl:
		return (NFCNTLCODE);
	case SYS_ucredsys:
		return (NUCREDSYSCODE);
	case SYS_port:
		return (NPORTCODE);
	case SYS_zone:
		return (NZONECODE);
	case SYS_labelsys:
		return (NLABELCODE);
	case SYS_rctlsys:
		return (NRCTLCODE);
	case SYS_forksys:
		return (NFORKCODE);
	case SYS_sidsys:
		return (NSIDSYSCODE);
	case SYS_utimesys:
		return (NUTIMESYSCODE);
	case SYS_sockconfig:
		return (NSOCKCONFIGCODE);
	default:
		return (1);
	}
}



/* Socket address families (and protocol families) */
const char * const afcodes[] = {
	"UNSPEC",	/* 0 */
	"UNIX",		/* 1 */
	"INET",		/* 2 */
	"IMPLINK",	/* 3 */
	"PUP",		/* 4 */
	"CHAOS",	/* 5 */
	"NS",		/* 6 */
	"NBS",		/* 7 */
	"ECMA",		/* 8 */
	"DATAKIT",	/* 9 */
	"CCITT",	/* 10 */
	"SNA",		/* 11 */
	"DECnet",	/* 12 */
	"DLI",		/* 13 */
	"LAT",		/* 14 */
	"HYLINK",	/* 15 */
	"APPLETALK",	/* 16 */
	"NIT",		/* 17 */
	"802",		/* 18 */
	"OSI",		/* 19 */
	"X25",		/* 20 */
	"OSINET",	/* 21 */
	"GOSIP",	/* 22 */
	"IPX",		/* 23 */
	"ROUTE",	/* 24 */
	"LINK",		/* 25 */
	"INET6",	/* 26 */
	"KEY",		/* 27 */
	"NCA",		/* 28 */
	"POLICY",	/* 29 */
	"RDS",		/* 30 */
	"TRILL",	/* 31 */
	"PACKET",	/* 32 */
	"LX_NETLINK"	/* 33 */
};
#if MAX_AFCODES != 34
#error Need to update address-family table
#endif


const char * const socktype_codes[] = {		/* cf socket.h */
	NULL,
	"SOCK_DGRAM",		/* 1 */
	"SOCK_STREAM",		/* 2 */
	NULL,
	"SOCK_RAW",		/* 4 */
	"SOCK_RDM",		/* 5 */
	"SOCK_SEQPACKET"	/* 6 */
};
#if MAX_SOCKTYPES != 7
#error Need to update socket-type table
#endif
