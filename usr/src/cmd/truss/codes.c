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
 * Copyright (c) 2013, 2016 by Delphix. All rights reserved.
 * Copyright 2011 Nexenta Systems, Inc. All rights reserved.
 * Copyright (c) 2015, Joyent, Inc. All rights reserved.
 * Copyright (c) 2014, OmniTI Computer Consulting, Inc. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <libproc.h>

#include <ctype.h>
#include <string.h>
#include <sys/dlpi.h>
#include <sys/ipc.h>
#include <sys/ipc_impl.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/fstyp.h>
#if defined(__i386) || defined(__amd64)
#include <sys/sysi86.h>
#endif /* __i386 */
#include <sys/unistd.h>
#include <sys/file.h>
#include <sys/tiuser.h>
#include <sys/timod.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/termios.h>
#include <sys/termiox.h>
#include <sys/jioctl.h>
#include <sys/filio.h>
#include <fcntl.h>
#include <sys/termio.h>
#include <sys/stermio.h>
#include <sys/ttold.h>
#include <sys/mount.h>
#include <sys/utssys.h>
#include <sys/sysconfig.h>
#include <sys/statvfs.h>
#include <sys/kstat.h>
#include <sys/audio.h>
#include <sys/mixer.h>
#include <sys/cpc_impl.h>
#include <sys/devpoll.h>
#include <sys/strredir.h>
#include <sys/sockio.h>
#include <netinet/ip_mroute.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ptyvar.h>
#include <sys/des.h>
#include <sys/prnio.h>
#include <sys/dtrace.h>
#include <sys/crypto/ioctladmin.h>
#include <sys/crypto/ioctl.h>
#include <sys/kbio.h>
#include <sys/ptms.h>
#include <sys/aggr.h>
#include <sys/dld.h>
#include <net/simnet.h>
#include <sys/vnic.h>
#include <sys/fs/zfs.h>
#include <inet/kssl/kssl.h>
#include <sys/dkio.h>
#include <sys/fdio.h>
#include <sys/cdio.h>
#include <sys/scsi/impl/uscsi.h>
#include <sys/devinfo_impl.h>
#include <sys/dumpadm.h>
#include <sys/mntio.h>
#include <inet/iptun.h>
#include <sys/zcons.h>
#include <sys/usb/clients/hid/hid.h>
#include <sys/pm.h>
#include <sys/soundcard.h>

#include "ramdata.h"
#include "proto.h"

#define	FCNTLMIN	F_DUPFD
#define	FCNTLMAX	F_FLOCKW
const char *const FCNTLname[] = {
	"F_DUPFD",
	"F_GETFD",
	"F_SETFD",
	"F_GETFL",
	"F_SETFL",
	"F_O_GETLK",
	"F_SETLK",
	"F_SETLKW",
	"F_CHKFL",
	"F_DUP2FD",
	"F_ALLOCSP",
	"F_FREESP",
	NULL,		/* 12 */
	NULL,		/* 13 */
	"F_GETLK",
	NULL,		/* 15 */
	NULL,		/* 16 */
	NULL,		/* 17 */
	NULL,		/* 18 */
	NULL,		/* 19 */
	NULL,		/* 20 */
	NULL,		/* 21 */
	NULL,		/* 22 */
	"F_GETOWN",
	"F_SETOWN",
	"F_REVOKE",
	"F_HASREMOTELOCKS",
	"F_FREESP64",
	NULL,		/* 28 */
	NULL,		/* 29 */
	NULL,		/* 30 */
	NULL,		/* 31 */
	NULL,		/* 32 */
	"F_GETLK64",
	"F_SETLK64",
	"F_SETLKW64",
	"F_DUP2FD_CLOEXEC",
	"F_DUPFD_CLOEXEC",
	NULL,		/* 38 */
	NULL,		/* 39 */
	"F_SHARE",
	"F_UNSHARE",
	"F_SETLK_NBMAND",
	"F_SHARE_NBMAND",
	"F_SETLK64_NBMAND",
	NULL,		/* 45 */
	"F_BADFD",
	"F_OFD_GETLK",
	"F_OFD_SETLK",
	"F_OFD_SETLKW",
	NULL,		/* 50 */
	NULL,		/* 51 */
	NULL,		/* 52 */
	"F_FLOCK",
	"F_FLOCKW"
};

#define	SYSFSMIN	GETFSIND
#define	SYSFSMAX	GETNFSTYP
const char *const SYSFSname[] = {
	"GETFSIND",
	"GETFSTYP",
	"GETNFSTYP"
};

#define	SCONFMIN	_CONFIG_NGROUPS
#define	SCONFMAX	_CONFIG_EPHID_MAX
const char *const SCONFname[] = {
	"_CONFIG_NGROUPS",		/*  2 */
	"_CONFIG_CHILD_MAX",		/*  3 */
	"_CONFIG_OPEN_FILES",		/*  4 */
	"_CONFIG_POSIX_VER",		/*  5 */
	"_CONFIG_PAGESIZE",		/*  6 */
	"_CONFIG_CLK_TCK",		/*  7 */
	"_CONFIG_XOPEN_VER",		/*  8 */
	"_CONFIG_HRESCLK_TCK",		/*  9 */
	"_CONFIG_PROF_TCK",		/* 10 */
	"_CONFIG_NPROC_CONF",		/* 11 */
	"_CONFIG_NPROC_ONLN",		/* 12 */
	"_CONFIG_AIO_LISTIO_MAX",	/* 13 */
	"_CONFIG_AIO_MAX",		/* 14 */
	"_CONFIG_AIO_PRIO_DELTA_MAX",	/* 15 */
	"_CONFIG_DELAYTIMER_MAX",	/* 16 */
	"_CONFIG_MQ_OPEN_MAX",		/* 17 */
	"_CONFIG_MQ_PRIO_MAX",		/* 18 */
	"_CONFIG_RTSIG_MAX",		/* 19 */
	"_CONFIG_SEM_NSEMS_MAX",	/* 20 */
	"_CONFIG_SEM_VALUE_MAX",	/* 21 */
	"_CONFIG_SIGQUEUE_MAX",		/* 22 */
	"_CONFIG_SIGRT_MIN",		/* 23 */
	"_CONFIG_SIGRT_MAX",		/* 24 */
	"_CONFIG_TIMER_MAX",		/* 25 */
	"_CONFIG_PHYS_PAGES",		/* 26 */
	"_CONFIG_AVPHYS_PAGES",		/* 27 */
	"_CONFIG_COHERENCY",		/* 28 */
	"_CONFIG_SPLIT_CACHE",		/* 29 */
	"_CONFIG_ICACHESZ",		/* 30 */
	"_CONFIG_DCACHESZ",		/* 31 */
	"_CONFIG_ICACHELINESZ",		/* 32 */
	"_CONFIG_DCACHELINESZ",		/* 33 */
	"_CONFIG_ICACHEBLKSZ",		/* 34 */
	"_CONFIG_DCACHEBLKSZ",		/* 35 */
	"_CONFIG_DCACHETBLKSZ",		/* 36 */
	"_CONFIG_ICACHE_ASSOC",		/* 37 */
	"_CONFIG_DCACHE_ASSOC",		/* 38 */
	NULL,				/* 39 */
	NULL,				/* 40 */
	NULL,				/* 41 */
	"_CONFIG_MAXPID",		/* 42 */
	"_CONFIG_STACK_PROT",		/* 43 */
	"_CONFIG_NPROC_MAX",		/* 44 */
	"_CONFIG_CPUID_MAX",		/* 45 */
	"_CONFIG_SYMLOOP_MAX",		/* 46 */
	"_CONFIG_EPHID_MAX",		/* 47 */
};

#define	PATHCONFMIN	_PC_LINK_MAX
#define	PATHCONFMAX	_PC_XATTR_EXISTS
const char *const PATHCONFname[] = {
	"_PC_LINK_MAX",			/*  1 */
	"_PC_MAX_CANON",		/*  2 */
	"_PC_MAX_INPUT",		/*  3 */
	"_PC_NAME_MAX",			/*  4 */
	"_PC_PATH_MAX",			/*  5 */
	"_PC_PIPE_BUF",			/*  6 */
	"_PC_NO_TRUNC",			/*  7 */
	"_PC_VDISABLE",			/*  8 */
	"_PC_CHOWN_RESTRICTED",		/*  9 */
	"_PC_ASYNC_IO",			/* 10 */
	"_PC_PRIO_IO",			/* 11 */
	"_PC_SYNC_IO",			/* 12 */
	"_PC_ALLOC_SIZE_MIN",		/* 13 */
	"_PC_REC_INCR_XFER_SIZE",	/* 14 */
	"_PC_REC_MAX_XFER_SIZE",	/* 15 */
	"_PC_REC_MIN_XFER_SIZE",	/* 16 */
	"_PC_REC_XFER_ALIGN",		/* 17 */
	"_PC_SYMLINK_MAX",		/* 18 */
	"_PC_2_SYMLINKS",		/* 19 */
	"_PC_ACL_ENABLED",		/* 20 */
	"_PC_MIN_HOLE_SIZE",		/* 21 */
	"_PC_CASE_BEHAVIOR",		/* 22 */
	"_PC_SATTR_ENABLED",		/* 23 */
	"_PC_SATTR_EXISTS",		/* 24 */
	"_PC_ACCESS_FILTERING",		/* 25 */
	"_PC_TIMESTAMP_RESOLUTION",	/* 26 */
	NULL,				/* 27 */
	NULL,				/* 28 */
	NULL,				/* 29 */
	NULL,				/* 30 */
	NULL,				/* 31 */
	NULL,				/* 32 */
	NULL,				/* 33 */
	NULL,				/* 34 */
	NULL,				/* 35 */
	NULL,				/* 36 */
	NULL,				/* 37 */
	NULL,				/* 38 */
	NULL,				/* 39 */
	NULL,				/* 40 */
	NULL,				/* 41 */
	NULL,				/* 42 */
	NULL,				/* 43 */
	NULL,				/* 44 */
	NULL,				/* 45 */
	NULL,				/* 46 */
	NULL,				/* 47 */
	NULL,				/* 48 */
	NULL,				/* 49 */
	NULL,				/* 50 */
	NULL,				/* 51 */
	NULL,				/* 52 */
	NULL,				/* 53 */
	NULL,				/* 54 */
	NULL,				/* 55 */
	NULL,				/* 56 */
	NULL,				/* 57 */
	NULL,				/* 58 */
	NULL,				/* 59 */
	NULL,				/* 60 */
	NULL,				/* 61 */
	NULL,				/* 62 */
	NULL,				/* 63 */
	NULL,				/* 64 */
	NULL,				/* 65 */
	NULL,				/* 66 */
	"_PC_FILESIZEBITS",		/* 67 */
	NULL,				/* 68 */
	NULL,				/* 69 */
	NULL,				/* 70 */
	NULL,				/* 71 */
	NULL,				/* 72 */
	NULL,				/* 73 */
	NULL,				/* 74 */
	NULL,				/* 75 */
	NULL,				/* 76 */
	NULL,				/* 77 */
	NULL,				/* 78 */
	NULL,				/* 79 */
	NULL,				/* 80 */
	NULL,				/* 81 */
	NULL,				/* 82 */
	NULL,				/* 83 */
	NULL,				/* 84 */
	NULL,				/* 85 */
	NULL,				/* 86 */
	NULL,				/* 87 */
	NULL,				/* 88 */
	NULL,				/* 89 */
	NULL,				/* 90 */
	NULL,				/* 91 */
	NULL,				/* 92 */
	NULL,				/* 93 */
	NULL,				/* 94 */
	NULL,				/* 95 */
	NULL,				/* 96 */
	NULL,				/* 97 */
	NULL,				/* 98 */
	NULL,				/* 99 */
	"_PC_XATTR_ENABLED",		/* 100 */
	"_PC_XATTR_EXISTS",		/* 101, _PC_LAST */
};

const struct ioc {
	uint_t	code;
	const char *name;
	const char *datastruct;
} ioc[] = {
	{ (uint_t)TCGETA,	"TCGETA",	NULL },
	{ (uint_t)TCSETA,	"TCSETA",	NULL },
	{ (uint_t)TCSETAW,	"TCSETAW",	NULL },
	{ (uint_t)TCSETAF,	"TCSETAF",	NULL },
	{ (uint_t)TCFLSH,	"TCFLSH",	NULL },
	{ (uint_t)TIOCKBON,	"TIOCKBON",	NULL },
	{ (uint_t)TIOCKBOF,	"TIOCKBOF",	NULL },
	{ (uint_t)KBENABLED,	"KBENABLED",	NULL },
	{ (uint_t)TCGETS,	"TCGETS",	NULL },
	{ (uint_t)TCSETS,	"TCSETS",	NULL },
	{ (uint_t)TCSETSW,	"TCSETSW",	NULL },
	{ (uint_t)TCSETSF,	"TCSETSF",	NULL },
	{ (uint_t)TCXONC,	"TCXONC",	NULL },
	{ (uint_t)TCSBRK,	"TCSBRK",	NULL },
	{ (uint_t)TCDSET,	"TCDSET",	NULL },
	{ (uint_t)RTS_TOG,	"RTS_TOG",	NULL },
	{ (uint_t)TIOCSWINSZ,	"TIOCSWINSZ",	NULL },
	{ (uint_t)TIOCGWINSZ,	"TIOCGWINSZ",	NULL },
	{ (uint_t)TIOCGETD,	"TIOCGETD",	NULL },
	{ (uint_t)TIOCSETD,	"TIOCSETD",	NULL },
	{ (uint_t)TIOCHPCL,	"TIOCHPCL",	NULL },
	{ (uint_t)TIOCGETP,	"TIOCGETP",	NULL },
	{ (uint_t)TIOCSETP,	"TIOCSETP",	NULL },
	{ (uint_t)TIOCSETN,	"TIOCSETN",	NULL },
	{ (uint_t)TIOCEXCL,	"TIOCEXCL",	NULL },
	{ (uint_t)TIOCNXCL,	"TIOCNXCL",	NULL },
	{ (uint_t)TIOCFLUSH,	"TIOCFLUSH",	NULL },
	{ (uint_t)TIOCSETC,	"TIOCSETC",	NULL },
	{ (uint_t)TIOCGETC,	"TIOCGETC",	NULL },
	{ (uint_t)TIOCGPGRP,	"TIOCGPGRP",	NULL },
	{ (uint_t)TIOCSPGRP,	"TIOCSPGRP",	NULL },
	{ (uint_t)TIOCGSID,	"TIOCGSID",	NULL },
	{ (uint_t)TIOCSTI,	"TIOCSTI",	NULL },
	{ (uint_t)TIOCMSET,	"TIOCMSET",	NULL },
	{ (uint_t)TIOCMBIS,	"TIOCMBIS",	NULL },
	{ (uint_t)TIOCMBIC,	"TIOCMBIC",	NULL },
	{ (uint_t)TIOCMGET,	"TIOCMGET",	NULL },
	{ (uint_t)TIOCREMOTE,	"TIOCREMOTE",	NULL },
	{ (uint_t)TIOCSIGNAL,	"TIOCSIGNAL",	NULL },
	{ (uint_t)TIOCSTART,	"TIOCSTART",	NULL },
	{ (uint_t)TIOCSTOP,	"TIOCSTOP",	NULL },
	{ (uint_t)TIOCNOTTY,	"TIOCNOTTY",	NULL },
	{ (uint_t)TIOCSCTTY,	"TIOCSCTTY",	NULL },
	{ (uint_t)TIOCOUTQ,	"TIOCOUTQ",	NULL },
	{ (uint_t)TIOCGLTC,	"TIOCGLTC",	NULL },
	{ (uint_t)TIOCSLTC,	"TIOCSLTC",	NULL },
	{ (uint_t)TIOCCDTR,	"TIOCCDTR",	NULL },
	{ (uint_t)TIOCSDTR,	"TIOCSDTR",	NULL },
	{ (uint_t)TIOCCBRK,	"TIOCCBRK",	NULL },
	{ (uint_t)TIOCSBRK,	"TIOCSBRK",	NULL },
	{ (uint_t)TIOCLGET,	"TIOCLGET",	NULL },
	{ (uint_t)TIOCLSET,	"TIOCLSET",	NULL },
	{ (uint_t)TIOCLBIC,	"TIOCLBIC",	NULL },
	{ (uint_t)TIOCLBIS,	"TIOCLBIS",	NULL },

	{ (uint_t)TIOCSILOOP,	"TIOCSILOOP",	NULL },
	{ (uint_t)TIOCCILOOP,	"TIOCSILOOP",	NULL },

	{ (uint_t)TIOCGPPS,	"TIOCGPPS",	NULL },
	{ (uint_t)TIOCSPPS,	"TIOCSPPS",	NULL },
	{ (uint_t)TIOCGPPSEV,	"TIOCGPPSEV",	NULL },

	{ (uint_t)TIOCPKT,	"TIOCPKT",	NULL },	/* ptyvar.h */
	{ (uint_t)TIOCUCNTL,	"TIOCUCNTL",	NULL },
	{ (uint_t)TIOCTCNTL,	"TIOCTCNTL",	NULL },
	{ (uint_t)TIOCISPACE,	"TIOCISPACE",	NULL },
	{ (uint_t)TIOCISIZE,	"TIOCISIZE",	NULL },
	{ (uint_t)TIOCSSIZE,	"TIOCSSIZE",	"ttysize" },
	{ (uint_t)TIOCGSIZE,	"TIOCGSIZE",	"ttysize" },

	/*
	 * Unfortunately, the DLIOC and LDIOC codes overlap.  Since the LDIOC
	 * ioctls (for xenix compatibility) are far less likely to be used, we
	 * give preference to DLIOC.
	 */
	{ (uint_t)DLIOCRAW,	"DLIOCRAW",	NULL },
	{ (uint_t)DLIOCNATIVE,	"DLIOCNATIVE",	NULL },
	{ (uint_t)DLIOCIPNETINFO, "DLIOCIPNETINFO", NULL},
	{ (uint_t)DLIOCLOWLINK,	"DLIOCLOWLINK",	NULL },

	{ (uint_t)LDOPEN,	"LDOPEN",	NULL },
	{ (uint_t)LDCLOSE,	"LDCLOSE",	NULL },
	{ (uint_t)LDCHG,	"LDCHG",	NULL },
	{ (uint_t)LDGETT,	"LDGETT",	NULL },
	{ (uint_t)LDSETT,	"LDSETT",	NULL },
	{ (uint_t)LDSMAP,	"LDSMAP",	NULL },
	{ (uint_t)LDGMAP,	"LDGMAP",	NULL },
	{ (uint_t)LDNMAP,	"LDNMAP",	NULL },
	{ (uint_t)TCGETX,	"TCGETX",	NULL },
	{ (uint_t)TCSETX,	"TCSETX",	NULL },
	{ (uint_t)TCSETXW,	"TCSETXW",	NULL },
	{ (uint_t)TCSETXF,	"TCSETXF",	NULL },
	{ (uint_t)FIORDCHK,	"FIORDCHK",	NULL },
	{ (uint_t)FIOCLEX,	"FIOCLEX",	NULL },
	{ (uint_t)FIONCLEX,	"FIONCLEX",	NULL },
	{ (uint_t)FIONREAD,	"FIONREAD",	NULL },
	{ (uint_t)FIONBIO,	"FIONBIO",	NULL },
	{ (uint_t)FIOASYNC,	"FIOASYNC",	NULL },
	{ (uint_t)FIOSETOWN,	"FIOSETOWN",	NULL },
	{ (uint_t)FIOGETOWN,	"FIOGETOWN",	NULL },
#ifdef DIOCGETP
	{ (uint_t)DIOCGETP,	"DIOCGETP",	NULL },
	{ (uint_t)DIOCSETP,	"DIOCSETP",	NULL },
#endif
#ifdef DIOCGETC
	{ (uint_t)DIOCGETC,	"DIOCGETC",	NULL },
	{ (uint_t)DIOCGETB,	"DIOCGETB",	NULL },
	{ (uint_t)DIOCSETE,	"DIOCSETE",	NULL },
#endif
#ifdef IFFORMAT
	{ (uint_t)IFFORMAT,	"IFFORMAT",	NULL },
	{ (uint_t)IFBCHECK,	"IFBCHECK",	NULL },
	{ (uint_t)IFCONFIRM,	"IFCONFIRM",	NULL },
#endif
#ifdef LIOCGETP
	{ (uint_t)LIOCGETP,	"LIOCGETP",	NULL },
	{ (uint_t)LIOCSETP,	"LIOCSETP",	NULL },
	{ (uint_t)LIOCGETS,	"LIOCGETS",	NULL },
	{ (uint_t)LIOCSETS,	"LIOCSETS",	NULL },
#endif
#ifdef JBOOT
	{ (uint_t)JBOOT,	"JBOOT",	NULL },
	{ (uint_t)JTERM,	"JTERM",	NULL },
	{ (uint_t)JMPX,		"JMPX",	NULL },
#ifdef JTIMO
	{ (uint_t)JTIMO,	"JTIMO",	NULL },
#endif
	{ (uint_t)JWINSIZE,	"JWINSIZE",	NULL },
	{ (uint_t)JTIMOM,	"JTIMOM",	NULL },
	{ (uint_t)JZOMBOOT,	"JZOMBOOT",	NULL },
	{ (uint_t)JAGENT,	"JAGENT",	NULL },
	{ (uint_t)JTRUN,	"JTRUN",	NULL },
	{ (uint_t)JXTPROTO,	"JXTPROTO",	NULL },
#endif
	{ (uint_t)KSTAT_IOC_CHAIN_ID,	"KSTAT_IOC_CHAIN_ID",	NULL },
	{ (uint_t)KSTAT_IOC_READ,	"KSTAT_IOC_READ",	NULL },
	{ (uint_t)KSTAT_IOC_WRITE,	"KSTAT_IOC_WRITE",	NULL },
	{ (uint_t)STGET,	"STGET",	NULL },
	{ (uint_t)STSET,	"STSET",	NULL },
	{ (uint_t)STTHROW,	"STTHROW",	NULL },
	{ (uint_t)STWLINE,	"STWLINE",	NULL },
	{ (uint_t)STTSV,	"STTSV",	NULL },
	{ (uint_t)I_NREAD,	"I_NREAD",	NULL },
	{ (uint_t)I_PUSH,	"I_PUSH",	NULL },
	{ (uint_t)I_POP,	"I_POP",	NULL },
	{ (uint_t)I_LOOK,	"I_LOOK",	NULL },
	{ (uint_t)I_FLUSH,	"I_FLUSH",	NULL },
	{ (uint_t)I_SRDOPT,	"I_SRDOPT",	NULL },
	{ (uint_t)I_GRDOPT,	"I_GRDOPT",	NULL },
	{ (uint_t)I_STR,	"I_STR",	NULL },
	{ (uint_t)I_SETSIG,	"I_SETSIG",	NULL },
	{ (uint_t)I_GETSIG,	"I_GETSIG",	NULL },
	{ (uint_t)I_FIND,	"I_FIND",	NULL },
	{ (uint_t)I_LINK,	"I_LINK",	NULL },
	{ (uint_t)I_UNLINK,	"I_UNLINK",	NULL },
	{ (uint_t)I_PEEK,	"I_PEEK",	NULL },
	{ (uint_t)I_FDINSERT,	"I_FDINSERT",	NULL },
	{ (uint_t)I_SENDFD,	"I_SENDFD",	NULL },
	{ (uint_t)I_RECVFD,	"I_RECVFD",	NULL },
	{ (uint_t)I_SWROPT,	"I_SWROPT",	NULL },
	{ (uint_t)I_GWROPT,	"I_GWROPT",	NULL },
	{ (uint_t)I_LIST,	"I_LIST",	NULL },
	{ (uint_t)I_PLINK,	"I_PLINK",	NULL },
	{ (uint_t)I_PUNLINK,	"I_PUNLINK",	NULL },
	{ (uint_t)I_FLUSHBAND,	"I_FLUSHBAND",	NULL },
	{ (uint_t)I_CKBAND,	"I_CKBAND",	NULL },
	{ (uint_t)I_GETBAND,	"I_GETBAND",	NULL },
	{ (uint_t)I_ATMARK,	"I_ATMARK",	NULL },
	{ (uint_t)I_SETCLTIME,	"I_SETCLTIME",	NULL },
	{ (uint_t)I_GETCLTIME,	"I_GETCLTIME",	NULL },
	{ (uint_t)I_CANPUT,	"I_CANPUT",	NULL },
	{ (uint_t)I_ANCHOR,	"I_ANCHOR",	NULL },
	{ (uint_t)_I_CMD,	"_I_CMD",	NULL },
#ifdef TI_GETINFO
	{ (uint_t)TI_GETINFO,	"TI_GETINFO",	NULL },
	{ (uint_t)TI_OPTMGMT,	"TI_OPTMGMT",	NULL },
	{ (uint_t)TI_BIND,	"TI_BIND",	NULL },
	{ (uint_t)TI_UNBIND,	"TI_UNBIND",	NULL },
#endif
#ifdef	TI_CAPABILITY
	{ (uint_t)TI_CAPABILITY,	"TI_CAPABILITY",	NULL },
#endif
#ifdef TI_GETMYNAME
	{ (uint_t)TI_GETMYNAME,		"TI_GETMYNAME",		NULL },
	{ (uint_t)TI_GETPEERNAME,	"TI_GETPEERNAME",	NULL },
	{ (uint_t)TI_SETMYNAME,		"TI_SETMYNAME",		NULL },
	{ (uint_t)TI_SETPEERNAME,	"TI_SETPEERNAME",	NULL },
#endif
#ifdef V_PREAD
	{ (uint_t)V_PREAD,	"V_PREAD",	NULL },
	{ (uint_t)V_PWRITE,	"V_PWRITE",	NULL },
	{ (uint_t)V_PDREAD,	"V_PDREAD",	NULL },
	{ (uint_t)V_PDWRITE,	"V_PDWRITE",	NULL },
#if !defined(__i386) && !defined(__amd64)
	{ (uint_t)V_GETSSZ,	"V_GETSSZ",	NULL },
#endif /* !__i386 */
#endif
	/* audio */
	{ (uint_t)AUDIO_GETINFO,	"AUDIO_GETINFO",	NULL },
	{ (uint_t)AUDIO_SETINFO,	"AUDIO_SETINFO",	NULL },
	{ (uint_t)AUDIO_DRAIN,		"AUDIO_DRAIN",		NULL },
	{ (uint_t)AUDIO_GETDEV,		"AUDIO_GETDEV",		NULL },
	{ (uint_t)AUDIO_DIAG_LOOPBACK,	"AUDIO_DIAG_LOOPBACK",	NULL },
	{ (uint_t)AUDIO_GET_CH_NUMBER,	"AUDIO_GET_CH_NUMBER",	NULL },
	{ (uint_t)AUDIO_GET_CH_TYPE,	"AUDIO_GET_CH_TYPE",	NULL },
	{ (uint_t)AUDIO_GET_NUM_CHS,	"AUDIO_GET_NUM_CHS",	NULL },
	{ (uint_t)AUDIO_GET_AD_DEV,	"AUDIO_GET_AD_DEV",	NULL },
	{ (uint_t)AUDIO_GET_APM_DEV,	"AUDIO_GET_APM_DEV",	NULL },
	{ (uint_t)AUDIO_GET_AS_DEV,	"AUDIO_GET_AS_DEV",	NULL },
	{ (uint_t)AUDIO_MIXER_MULTIPLE_OPEN,	"AUDIO_MIXER_MULTIPLE_OPEN",
	    NULL },
	{ (uint_t)AUDIO_MIXER_SINGLE_OPEN,	"AUDIO_MIXER_SINGLE_OPEN",
	    NULL },
	{ (uint_t)AUDIO_MIXER_GET_SAMPLE_RATES,	"AUDIO_MIXER_GET_SAMPLE_RATES",
	    NULL },
	{ (uint_t)AUDIO_MIXERCTL_GETINFO,	"AUDIO_MIXERCTL_GETINFO",
	    NULL },
	{ (uint_t)AUDIO_MIXERCTL_SETINFO,	"AUDIO_MIXERCTL_SETINFO",
	    NULL },
	{ (uint_t)AUDIO_MIXERCTL_GET_CHINFO,	"AUDIO_MIXERCTL_GET_CHINFO",
	    NULL },
	{ (uint_t)AUDIO_MIXERCTL_SET_CHINFO,	"AUDIO_MIXERCTL_SET_CHINFO",
	    NULL },
	{ (uint_t)AUDIO_MIXERCTL_GET_MODE,	"AUDIO_MIXERCTL_GET_MODE",
	    NULL },
	{ (uint_t)AUDIO_MIXERCTL_SET_MODE,	"AUDIO_MIXERCTL_SET_MODE",
	    NULL },
	/* new style Boomer (OSS) ioctls */
	{ (uint_t)SNDCTL_SYSINFO,	"SNDCTL_SYSINFO",	NULL },
	{ (uint_t)SNDCTL_AUDIOINFO,	"SNDCTL_AUDIOINFO",	NULL },
	{ (uint_t)SNDCTL_AUDIOINFO_EX,	"SNDCTL_AUDIOINFO_EX",	NULL },
	{ (uint_t)SNDCTL_MIXERINFO,	"SNDCTL_MIXERINFO",	NULL },
	{ (uint_t)SNDCTL_CARDINFO,	"SNDCTL_CARDINFO",	NULL },
	{ (uint_t)SNDCTL_ENGINEINFO,	"SNDCTL_ENGINEINFO",	NULL },
	{ (uint_t)SNDCTL_MIX_NRMIX,	"SNDCTL_MIX_NRMIX",	NULL },
	{ (uint_t)SNDCTL_MIX_NREXT,	"SNDCTL_MIX_NREXT",	NULL },
	{ (uint_t)SNDCTL_MIX_EXTINFO,	"SNDCTL_MIX_EXTINFO",	NULL },
	{ (uint_t)SNDCTL_MIX_READ,	"SNDCTL_MIX_READ",	NULL },
	{ (uint_t)SNDCTL_MIX_WRITE,	"SNDCTL_MIX_WRITE",	NULL },
	{ (uint_t)SNDCTL_MIX_ENUMINFO,	"SNDCTL_MIX_ENUMINFO",	NULL },
	{ (uint_t)SNDCTL_MIX_DESCRIPTION,	"SNDCTL_MIX_DESCRIPTION",
	    NULL },
	{ (uint_t)SNDCTL_SETSONG,	"SNDCTL_SETSONG",	NULL },
	{ (uint_t)SNDCTL_GETSONG,	"SNDCTL_GETSONG",	NULL },
	{ (uint_t)SNDCTL_SETNAME,	"SNDCTL_SETNAME",	NULL },
	{ (uint_t)SNDCTL_SETLABEL,	"SNDCTL_SETLABEL",	NULL },
	{ (uint_t)SNDCTL_GETLABEL,	"SNDCTL_GETLABEL",	NULL },
	{ (uint_t)SNDCTL_DSP_HALT,	"SNDCTL_DSP_HALT",	NULL },
	{ (uint_t)SNDCTL_DSP_RESET,	"SNDCTL_DSP_RESET",	NULL },
	{ (uint_t)SNDCTL_DSP_SYNC,	"SNDCTL_DSP_SYNC",	NULL },
	{ (uint_t)SNDCTL_DSP_SPEED,	"SNDCTL_DSP_SPEED",	NULL },
	{ (uint_t)SNDCTL_DSP_STEREO,	"SNDCTL_DSP_STEREO",	NULL },
	{ (uint_t)SNDCTL_DSP_GETBLKSIZE,	"SNDCTL_DSP_GETBLKSIZE",
	    NULL },
	{ (uint_t)SNDCTL_DSP_SAMPLESIZE,	"SNDCTL_DSP_SAMPLESIZE",
	    NULL },
	{ (uint_t)SNDCTL_DSP_CHANNELS,	"SNDCTL_DSP_CHANNELS",  NULL },
	{ (uint_t)SNDCTL_DSP_POST,	"SNDCTL_DSP_POST",	NULL },
	{ (uint_t)SNDCTL_DSP_SUBDIVIDE,	"SNDCTL_DSP_SUBDIVIDE",	NULL },
	{ (uint_t)SNDCTL_DSP_SETFRAGMENT,	"SNDCTL_DSP_SETFRAGMENT",
	    NULL },
	{ (uint_t)SNDCTL_DSP_GETFMTS,	"SNDCTL_DSP_GETFMTS",	NULL },
	{ (uint_t)SNDCTL_DSP_SETFMT,	"SNDCTL_DSP_SETFMT",	NULL },
	{ (uint_t)SNDCTL_DSP_GETOSPACE,	"SNDCTL_DSP_GETOSPACE",	NULL },
	{ (uint_t)SNDCTL_DSP_GETISPACE,	"SNDCTL_DSP_GETISPACE",	NULL },
	{ (uint_t)SNDCTL_DSP_GETCAPS,	"SNDCTL_DSP_CAPS",	NULL },
	{ (uint_t)SNDCTL_DSP_GETTRIGGER,	"SNDCTL_DSP_GETTRIGGER",
	    NULL },
	{ (uint_t)SNDCTL_DSP_SETTRIGGER,	"SNDCTL_DSP_SETTRIGGER",
	    NULL },
	{ (uint_t)SNDCTL_DSP_GETIPTR,	"SNDCTL_DSP_GETIPTR",	NULL },
	{ (uint_t)SNDCTL_DSP_GETOPTR,	"SNDCTL_DSP_GETOPTR",	NULL },
	{ (uint_t)SNDCTL_DSP_SETSYNCRO,	"SNDCTL_DSP_SETSYNCRO",	NULL },
	{ (uint_t)SNDCTL_DSP_SETDUPLEX,	"SNDCTL_DSP_SETDUPLEX",	NULL },
	{ (uint_t)SNDCTL_DSP_PROFILE,	"SNDCTL_DSP_PROFILE",	NULL },
	{ (uint_t)SNDCTL_DSP_GETODELAY,	"SNDCTL_DSP_GETODELAY",	NULL },
	{ (uint_t)SNDCTL_DSP_GETPLAYVOL,	"SNDCTL_DSP_GETPLAYVOL",
	    NULL },
	{ (uint_t)SNDCTL_DSP_SETPLAYVOL,	"SNDCTL_DSP_SETPLAYVOL",
	    NULL },
	{ (uint_t)SNDCTL_DSP_GETERROR,	"SNDCTL_DSP_GETERROR",	NULL },
	{ (uint_t)SNDCTL_DSP_READCTL,	"SNDCTL_DSP_READCTL",	NULL },
	{ (uint_t)SNDCTL_DSP_WRITECTL,	"SNDCTL_DSP_WRITECTL",	NULL },
	{ (uint_t)SNDCTL_DSP_SYNCGROUP,	"SNDCTL_DSP_SYNCGROUP",	NULL },
	{ (uint_t)SNDCTL_DSP_SYNCSTART,	"SNDCTL_DSP_SYNCSTART",	NULL },
	{ (uint_t)SNDCTL_DSP_COOKEDMODE,	"SNDCTL_DSP_COOKEDMODE",
	    NULL },
	{ (uint_t)SNDCTL_DSP_SILENCE,	"SNDCTL_DSP_SILENCE",	NULL },
	{ (uint_t)SNDCTL_DSP_SKIP,	"SNDCTL_DSP_SKIP",	NULL },
	{ (uint_t)SNDCTL_DSP_HALT_INPUT,	"SNDCTL_DSP_HALT_INPUT",
	    NULL },
	{ (uint_t)SNDCTL_DSP_HALT_OUTPUT,	"SNDCTL_DSP_HALT_OUTPUT",
	    NULL },
	{ (uint_t)SNDCTL_DSP_LOW_WATER,	"SNDCTL_DSP_LOW_WATER",	NULL },
	{ (uint_t)SNDCTL_DSP_CURRENT_OPTR,	"SNDCTL_DSP_CURRENT_OPTR",
	    NULL },
	{ (uint_t)SNDCTL_DSP_CURRENT_IPTR,	"SNDCTL_DSP_CURRENT_IPTR",
	    NULL },
	{ (uint_t)SNDCTL_DSP_GET_RECSRC_NAMES,	"SNDCTL_DSP_GET_RECSRC_NAMES",
	    NULL },
	{ (uint_t)SNDCTL_DSP_GET_RECSRC,	"SNDCTL_DSP_GET_RECSRC",
	    NULL },
	{ (uint_t)SNDCTL_DSP_SET_RECSRC,	"SNDCTL_DSP_SET_RECSRC",
	    NULL },
	{ (uint_t)SNDCTL_DSP_GET_PLAYTGT_NAMES,	"SNDCTL_DSP_GET_PLAYTGT_NAMES",
	    NULL },
	{ (uint_t)SNDCTL_DSP_GET_PLAYTGT,	"SNDCTL_DSP_GET_PLAYTGT",
	    NULL },
	{ (uint_t)SNDCTL_DSP_SET_PLAYTGT,	"SNDCTL_DSP_SET_PLAYTGT",
	    NULL },
	{ (uint_t)SNDCTL_DSP_GETRECVOL,		"SNDCTL_DSP_GETRECVOL",
	    NULL },
	{ (uint_t)SNDCTL_DSP_SETRECVOL,		"SNDCTL_DSP_SETRECVOL",
	    NULL },
	{ (uint_t)SNDCTL_DSP_GET_CHNORDER,	"SNDCTL_DSP_GET_CHNORDER",
	    NULL },
	{ (uint_t)SNDCTL_DSP_SET_CHNORDER,	"SNDCTL_DSP_SET_CHNORDER",
	    NULL },
	{ (uint_t)SNDCTL_DSP_GETIPEAKS,	"SNDCTL_DSP_GETIPEAKS",	NULL },
	{ (uint_t)SNDCTL_DSP_GETOPEAKS,	"SNDCTL_DSP_GETOPEAKS",	NULL },
	{ (uint_t)SNDCTL_DSP_POLICY,	"SNDCTL_DSP_POLICY",	NULL },
	{ (uint_t)SNDCTL_DSP_GETCHANNELMASK,	"SNDCTL_DSP_GETCHANNELMASK",
	    NULL },
	{ (uint_t)SNDCTL_DSP_BIND_CHANNEL,	"SNDCTL_DSP_BIND_CHANNEL",
	    NULL },
	{ (uint_t)SOUND_MIXER_READ_VOLUME,	"SOUND_MIXER_READ_VOLUME",
	    NULL },
	{ (uint_t)SOUND_MIXER_READ_OGAIN,	"SOUND_MIXER_READ_OGAIN",
	    NULL },
	{ (uint_t)SOUND_MIXER_READ_PCM,	"SOUND_MIXER_READ_PCM",	NULL },
	{ (uint_t)SOUND_MIXER_READ_IGAIN,	"SOUND_MIXER_READ_IGAIN",
	    NULL },
	{ (uint_t)SOUND_MIXER_READ_RECLEV,	"SOUND_MIXER_READ_RECLEV",
	    NULL },
	{ (uint_t)SOUND_MIXER_READ_RECSRC,	"SOUND_MIXER_READ_RECSRC",
	    NULL },
	{ (uint_t)SOUND_MIXER_READ_DEVMASK,	"SOUND_MIXER_READ_DEVMASK",
	    NULL },
	{ (uint_t)SOUND_MIXER_READ_RECMASK,	"SOUND_MIXER_READ_RECMASK",
	    NULL },
	{ (uint_t)SOUND_MIXER_READ_CAPS,	"SOUND_MIXER_READ_CAPS",
	    NULL },
	{ (uint_t)SOUND_MIXER_READ_STEREODEVS,	"SOUND_MIXER_READ_STEREODEVS",
	    NULL },
	{ (uint_t)SOUND_MIXER_READ_RECGAIN,	"SOUND_MIXER_READ_RECGAIN",
	    NULL },
	{ (uint_t)SOUND_MIXER_READ_MONGAIN,	"SOUND_MIXER_READ_MONGAIN",
	    NULL },
	{ (uint_t)SOUND_MIXER_WRITE_VOLUME,	"SOUND_MIXER_WRITE_VOLUME",
	    NULL },
	{ (uint_t)SOUND_MIXER_WRITE_OGAIN,	"SOUND_MIXER_WRITE_OGAIN",
	    NULL },
	{ (uint_t)SOUND_MIXER_WRITE_PCM,	"SOUND_MIXER_WRITE_PCM",
	    NULL },
	{ (uint_t)SOUND_MIXER_WRITE_IGAIN,	"SOUND_MIXER_WRITE_IGAIN",
	    NULL },
	{ (uint_t)SOUND_MIXER_WRITE_RECLEV,	"SOUND_MIXER_WRITE_RECLEV",
	    NULL },
	{ (uint_t)SOUND_MIXER_WRITE_RECSRC,	"SOUND_MIXER_WRITE_RECSRC",
	    NULL },
	{ (uint_t)SOUND_MIXER_WRITE_RECGAIN,	"SOUND_MIXER_WRITE_RECGAIN",
	    NULL },
	{ (uint_t)SOUND_MIXER_WRITE_MONGAIN,	"SOUND_MIXER_WRITE_MONGAIN",
	    NULL },

	/* STREAMS redirection ioctls */
	{ (uint_t)SRIOCSREDIR,		"SRIOCSREDIR",	NULL },
	{ (uint_t)SRIOCISREDIR,		"SRIOCISREDIR",	NULL },
	{ (uint_t)CPCIO_BIND,		"CPCIO_BIND",		NULL },
	{ (uint_t)CPCIO_SAMPLE,		"CPCIO_SAMPLE",		NULL },
	{ (uint_t)CPCIO_RELE,		"CPCIO_RELE",		NULL },
	/* /dev/poll ioctl() control codes */
	{ (uint_t)DP_POLL,	"DP_POLL",	NULL },
	{ (uint_t)DP_ISPOLLED,	"DP_ISPOLLED",	NULL },
	{ (uint_t)DP_PPOLL,	"DP_PPOLL",	NULL },
	{ (uint_t)DP_EPOLLCOMPAT, "DP_EPOLLCOMPAT",	NULL },
	/* the old /proc ioctl() control codes */
#define	PIOC	('q'<<8)
	{ (uint_t)(PIOC|1),	"PIOCSTATUS",	NULL },
	{ (uint_t)(PIOC|2),	"PIOCSTOP",	NULL },
	{ (uint_t)(PIOC|3),	"PIOCWSTOP",	NULL },
	{ (uint_t)(PIOC|4),	"PIOCRUN",	NULL },
	{ (uint_t)(PIOC|5),	"PIOCGTRACE",	NULL },
	{ (uint_t)(PIOC|6),	"PIOCSTRACE",	NULL },
	{ (uint_t)(PIOC|7),	"PIOCSSIG",	NULL },
	{ (uint_t)(PIOC|8),	"PIOCKILL",	NULL },
	{ (uint_t)(PIOC|9),	"PIOCUNKILL",	NULL },
	{ (uint_t)(PIOC|10),	"PIOCGHOLD",	NULL },
	{ (uint_t)(PIOC|11),	"PIOCSHOLD",	NULL },
	{ (uint_t)(PIOC|12),	"PIOCMAXSIG",	NULL },
	{ (uint_t)(PIOC|13),	"PIOCACTION",	NULL },
	{ (uint_t)(PIOC|14),	"PIOCGFAULT",	NULL },
	{ (uint_t)(PIOC|15),	"PIOCSFAULT",	NULL },
	{ (uint_t)(PIOC|16),	"PIOCCFAULT",	NULL },
	{ (uint_t)(PIOC|17),	"PIOCGENTRY",	NULL },
	{ (uint_t)(PIOC|18),	"PIOCSENTRY",	NULL },
	{ (uint_t)(PIOC|19),	"PIOCGEXIT",	NULL },
	{ (uint_t)(PIOC|20),	"PIOCSEXIT",	NULL },
	{ (uint_t)(PIOC|21),	"PIOCSFORK",	NULL },
	{ (uint_t)(PIOC|22),	"PIOCRFORK",	NULL },
	{ (uint_t)(PIOC|23),	"PIOCSRLC",	NULL },
	{ (uint_t)(PIOC|24),	"PIOCRRLC",	NULL },
	{ (uint_t)(PIOC|25),	"PIOCGREG",	NULL },
	{ (uint_t)(PIOC|26),	"PIOCSREG",	NULL },
	{ (uint_t)(PIOC|27),	"PIOCGFPREG",	NULL },
	{ (uint_t)(PIOC|28),	"PIOCSFPREG",	NULL },
	{ (uint_t)(PIOC|29),	"PIOCNICE",	NULL },
	{ (uint_t)(PIOC|30),	"PIOCPSINFO",	NULL },
	{ (uint_t)(PIOC|31),	"PIOCNMAP",	NULL },
	{ (uint_t)(PIOC|32),	"PIOCMAP",	NULL },
	{ (uint_t)(PIOC|33),	"PIOCOPENM",	NULL },
	{ (uint_t)(PIOC|34),	"PIOCCRED",	NULL },
	{ (uint_t)(PIOC|35),	"PIOCGROUPS",	NULL },
	{ (uint_t)(PIOC|36),	"PIOCGETPR",	NULL },
	{ (uint_t)(PIOC|37),	"PIOCGETU",	NULL },
	{ (uint_t)(PIOC|38),	"PIOCSET",	NULL },
	{ (uint_t)(PIOC|39),	"PIOCRESET",	NULL },
	{ (uint_t)(PIOC|43),	"PIOCUSAGE",	NULL },
	{ (uint_t)(PIOC|44),	"PIOCOPENPD",	NULL },
	{ (uint_t)(PIOC|45),	"PIOCLWPIDS",	NULL },
	{ (uint_t)(PIOC|46),	"PIOCOPENLWP",	NULL },
	{ (uint_t)(PIOC|47),	"PIOCLSTATUS",	NULL },
	{ (uint_t)(PIOC|48),	"PIOCLUSAGE",	NULL },
	{ (uint_t)(PIOC|49),	"PIOCNAUXV",	NULL },
	{ (uint_t)(PIOC|50),	"PIOCAUXV",	NULL },
	{ (uint_t)(PIOC|51),	"PIOCGXREGSIZE",	NULL },
	{ (uint_t)(PIOC|52),	"PIOCGXREG",	NULL },
	{ (uint_t)(PIOC|53),	"PIOCSXREG",	NULL },
	{ (uint_t)(PIOC|101),	"PIOCGWIN",	NULL },
	{ (uint_t)(PIOC|103),	"PIOCNLDT",	NULL },
	{ (uint_t)(PIOC|104),	"PIOCLDT",	NULL },

	/* ioctl's applicable on sockets */
	{ (uint_t)SIOCSHIWAT,	"SIOCSHIWAT",	NULL },
	{ (uint_t)SIOCGHIWAT,	"SIOCGHIWAT",	NULL },
	{ (uint_t)SIOCSLOWAT,	"SIOCSLOWAT",	NULL },
	{ (uint_t)SIOCGLOWAT,	"SIOCGLOWAT",	NULL },
	{ (uint_t)SIOCATMARK,	"SIOCATMARK",	NULL },
	{ (uint_t)SIOCSPGRP,	"SIOCSPGRP",	NULL },
	{ (uint_t)SIOCGPGRP,	"SIOCGPGRP",	NULL },
	{ (uint_t)SIOCADDRT,	"SIOCADDRT",	"rtentry" },
	{ (uint_t)SIOCDELRT,	"SIOCDELRT",	"rtentry" },
	{ (uint_t)SIOCGETVIFCNT,	"SIOCGETVIFCNT", "sioc_vif_req" },
	{ (uint_t)SIOCGETSGCNT,	"SIOCGETSGCNT",	"sioc_sg_req" },
	{ (uint_t)SIOCGETLSGCNT,	"SIOCGETLSGCNT", "sioc_lsg_req" },
	{ (uint_t)SIOCSIFADDR,	"SIOCSIFADDR",	"ifreq" },
	{ (uint_t)SIOCGIFADDR,	"SIOCGIFADDR",	"ifreq" },
	{ (uint_t)SIOCSIFDSTADDR,	"SIOCSIFDSTADDR", "ifreq" },
	{ (uint_t)SIOCGIFDSTADDR,	"SIOCGIFDSTADDR", "ifreq" },
	{ (uint_t)SIOCSIFFLAGS,	"SIOCSIFFLAGS",	"ifreq" },
	{ (uint_t)SIOCGIFFLAGS,	"SIOCGIFFLAGS",	"ifreq" },
	{ (uint_t)SIOCSIFMEM,	"SIOCSIFMEM",	"ifreq" },
	{ (uint_t)SIOCGIFMEM,	"SIOCGIFMEM",	"ifreq" },
	{ (uint_t)SIOCGIFCONF,	"SIOCGIFCONF",	"ifconf" },
	{ (uint_t)SIOCSIFMTU,	"SIOCSIFMTU",	"ifreq" },
	{ (uint_t)SIOCGIFMTU,	"SIOCGIFMTU",	"ifreq" },
	{ (uint_t)SIOCGIFBRDADDR,	"SIOCGIFBRDADDR",	"ifreq" },
	{ (uint_t)SIOCSIFBRDADDR,	"SIOCSIFBRDADDR",	"ifreq" },
	{ (uint_t)SIOCGIFNETMASK,	"SIOCGIFNETMASK",	"ifreq" },
	{ (uint_t)SIOCSIFNETMASK,	"SIOCSIFNETMASK",	"ifreq" },
	{ (uint_t)SIOCGIFMETRIC,	"SIOCGIFMETRIC",	"ifreq" },
	{ (uint_t)SIOCSIFMETRIC,	"SIOCSIFMETRIC",	"ifreq" },
	{ (uint_t)SIOCSARP,	"SIOCSARP",	"arpreq" },
	{ (uint_t)SIOCGARP,	"SIOCGARP",	"arpreq" },
	{ (uint_t)SIOCDARP,	"SIOCDARP",	"arpreq" },
	{ (uint_t)SIOCUPPER,	"SIOCUPPER",	"ifreq" },
	{ (uint_t)SIOCLOWER,	"SIOCLOWER",	"ifreq" },
	{ (uint_t)SIOCSETSYNC,	"SIOCSETSYNC",	"ifreq" },
	{ (uint_t)SIOCGETSYNC,	"SIOCGETSYNC",	"ifreq" },
	{ (uint_t)SIOCSSDSTATS,	"SIOCSSDSTATS",	"ifreq" },
	{ (uint_t)SIOCSSESTATS,	"SIOCSSESTATS",	"ifreq" },
	{ (uint_t)SIOCSPROMISC,	"SIOCSPROMISC",	NULL },
	{ (uint_t)SIOCADDMULTI,	"SIOCADDMULTI",	"ifreq" },
	{ (uint_t)SIOCDELMULTI,	"SIOCDELMULTI",	"ifreq" },
	{ (uint_t)SIOCGETNAME,	"SIOCGETNAME",	"sockaddr" },
	{ (uint_t)SIOCGETPEER,	"SIOCGETPEER",	"sockaddr" },
	{ (uint_t)IF_UNITSEL,	"IF_UNITSEL",	NULL },
	{ (uint_t)SIOCXPROTO,	"SIOCXPROTO",	NULL },
	{ (uint_t)SIOCIFDETACH,	"SIOCIFDETACH",	"ifreq" },
	{ (uint_t)SIOCGENPSTATS,	"SIOCGENPSTATS",	"ifreq" },
	{ (uint_t)SIOCX25XMT,	"SIOCX25XMT",	"ifreq" },
	{ (uint_t)SIOCX25RCV,	"SIOCX25RCV",	"ifreq" },
	{ (uint_t)SIOCX25TBL,	"SIOCX25TBL",	"ifreq" },
	{ (uint_t)SIOCSLGETREQ,	"SIOCSLGETREQ",	"ifreq" },
	{ (uint_t)SIOCSLSTAT,	"SIOCSLSTAT",	"ifreq" },
	{ (uint_t)SIOCSIFNAME,	"SIOCSIFNAME",	"ifreq" },
	{ (uint_t)SIOCGENADDR,	"SIOCGENADDR",	"ifreq" },
	{ (uint_t)SIOCGIFNUM,	"SIOCGIFNUM",	NULL },
	{ (uint_t)SIOCGIFMUXID,	"SIOCGIFMUXID",	"ifreq" },
	{ (uint_t)SIOCSIFMUXID,	"SIOCSIFMUXID",	"ifreq" },
	{ (uint_t)SIOCGIFINDEX,	"SIOCGIFINDEX",	"ifreq" },
	{ (uint_t)SIOCSIFINDEX,	"SIOCSIFINDEX",	"ifreq" },
	{ (uint_t)SIOCLIFREMOVEIF,	"SIOCLIFREMOVEIF",	"lifreq" },
	{ (uint_t)SIOCLIFADDIF,		"SIOCLIFADDIF",		"lifreq" },
	{ (uint_t)SIOCSLIFADDR,		"SIOCSLIFADDR",		"lifreq" },
	{ (uint_t)SIOCGLIFADDR,		"SIOCGLIFADDR",		"lifreq" },
	{ (uint_t)SIOCSLIFDSTADDR,	"SIOCSLIFDSTADDR",	"lifreq" },
	{ (uint_t)SIOCGLIFDSTADDR,	"SIOCGLIFDSTADDR",	"lifreq" },
	{ (uint_t)SIOCSLIFFLAGS,	"SIOCSLIFFLAGS",	"lifreq" },
	{ (uint_t)SIOCGLIFFLAGS,	"SIOCGLIFFLAGS",	"lifreq" },
	{ (uint_t)SIOCGLIFCONF,		"SIOCGLIFCONF",		"lifconf" },
	{ (uint_t)SIOCSLIFMTU,		"SIOCSLIFMTU",		"lifreq" },
	{ (uint_t)SIOCGLIFMTU,		"SIOCGLIFMTU",		"lifreq" },
	{ (uint_t)SIOCGLIFBRDADDR,	"SIOCGLIFBRDADDR",	"lifreq" },
	{ (uint_t)SIOCSLIFBRDADDR,	"SIOCSLIFBRDADDR",	"lifreq" },
	{ (uint_t)SIOCGLIFNETMASK,	"SIOCGLIFNETMASK",	"lifreq" },
	{ (uint_t)SIOCSLIFNETMASK,	"SIOCSLIFNETMASK",	"lifreq" },
	{ (uint_t)SIOCGLIFMETRIC,	"SIOCGLIFMETRIC",	"lifreq" },
	{ (uint_t)SIOCSLIFMETRIC,	"SIOCSLIFMETRIC",	"lifreq" },
	{ (uint_t)SIOCSLIFNAME,		"SIOCSLIFNAME",		"lifreq" },
	{ (uint_t)SIOCGLIFNUM,		"SIOCGLIFNUM",		"lifnum" },
	{ (uint_t)SIOCGLIFMUXID,	"SIOCGLIFMUXID",	"lifreq" },
	{ (uint_t)SIOCSLIFMUXID,	"SIOCSLIFMUXID",	"lifreq" },
	{ (uint_t)SIOCGLIFINDEX,	"SIOCGLIFINDEX",	"lifreq" },
	{ (uint_t)SIOCSLIFINDEX,	"SIOCSLIFINDEX",	"lifreq" },
	{ (uint_t)SIOCSLIFTOKEN,	"SIOCSLIFTOKEN",	"lifreq" },
	{ (uint_t)SIOCGLIFTOKEN,	"SIOCGLIFTOKEN",	"lifreq" },
	{ (uint_t)SIOCSLIFSUBNET,	"SIOCSLIFSUBNET",	"lifreq" },
	{ (uint_t)SIOCGLIFSUBNET,	"SIOCGLIFSUBNET",	"lifreq" },
	{ (uint_t)SIOCSLIFLNKINFO,	"SIOCSLIFLNKINFO",	"lifreq" },
	{ (uint_t)SIOCGLIFLNKINFO,	"SIOCGLIFLNKINFO",	"lifreq" },
	{ (uint_t)SIOCLIFDELND,		"SIOCLIFDELND",		"lifreq" },
	{ (uint_t)SIOCLIFGETND,		"SIOCLIFGETND",		"lifreq" },
	{ (uint_t)SIOCLIFSETND,		"SIOCLIFSETND",		"lifreq" },
	{ (uint_t)SIOCTMYADDR,		"SIOCTMYADDR",	"sioc_addrreq" },
	{ (uint_t)SIOCTONLINK,		"SIOCTONLINK",	"sioc_addrreq" },
	{ (uint_t)SIOCTMYSITE,		"SIOCTMYSITE",	"sioc_addrreq" },
	{ (uint_t)SIOCGLIFBINDING,	"SIOCGLIFBINDING",	"lifreq" },
	{ (uint_t)SIOCSLIFGROUPNAME,	"SIOCSLIFGROUPNAME",	"lifreq" },
	{ (uint_t)SIOCGLIFGROUPNAME,	"SIOCGLIFGROUPNAME",	"lifreq" },
	{ (uint_t)SIOCGLIFGROUPINFO,	"SIOCGLIFGROUPINFO", "lifgroupinfo" },
	{ (uint_t)SIOCGDSTINFO,		"SIOCGDSTINFO",		NULL },
	{ (uint_t)SIOCGIP6ADDRPOLICY,	"SIOCGIP6ADDRPOLICY",	NULL },
	{ (uint_t)SIOCSIP6ADDRPOLICY,	"SIOCSIP6ADDRPOLICY", 	NULL },
	{ (uint_t)SIOCSXARP,		"SIOCSXARP",		"xarpreq" },
	{ (uint_t)SIOCGXARP,		"SIOCGXARP",		"xarpreq" },
	{ (uint_t)SIOCDXARP,		"SIOCDXARP",		"xarpreq" },
	{ (uint_t)SIOCGLIFZONE,		"SIOCGLIFZONE",		"lifreq" },
	{ (uint_t)SIOCSLIFZONE,		"SIOCSLIFZONE",		"lifreq" },
	{ (uint_t)SIOCSCTPSOPT,		"SIOCSCTPSOPT",		NULL },
	{ (uint_t)SIOCSCTPGOPT,		"SIOCSCTPGOPT",		NULL },
	{ (uint_t)SIOCSCTPPEELOFF,	"SIOPCSCTPPEELOFF",	"int" },
	{ (uint_t)SIOCGLIFUSESRC,	"SIOCGLIFUSESRC",	"lifreq" },
	{ (uint_t)SIOCSLIFUSESRC,	"SIOCSLIFUSESRC",	"lifreq" },
	{ (uint_t)SIOCGLIFSRCOF,	"SIOCGLIFSRCOF",	"lifsrcof" },
	{ (uint_t)SIOCGMSFILTER,	"SIOCGMSFILTER",    "group_filter" },
	{ (uint_t)SIOCSMSFILTER,	"SIOCSMSFILTER",    "group_filter" },
	{ (uint_t)SIOCGIPMSFILTER,	"SIOCGIPMSFILTER",  "ip_msfilter" },
	{ (uint_t)SIOCSIPMSFILTER,	"SIOCSIPMSFILTER",  "ip_msfilter" },
	{ (uint_t)SIOCGLIFDADSTATE,	"SIOCGLIFDADSTATE",  "lifreq" },
	{ (uint_t)SIOCSLIFPREFIX,	"SIOCSLIFPREFIX", "lifreq" },
	{ (uint_t)SIOCGSTAMP,		"SIOCGSTAMP",		"timeval" },
	{ (uint_t)SIOCGIFHWADDR,	"SIOCGIFHWADDR",	"ifreq" },
	{ (uint_t)SIOCGLIFHWADDR,	"SIOCGLIFHWADDR",	"lifreq" },

	/* DES encryption */
	{ (uint_t)DESIOCBLOCK,	"DESIOCBLOCK", 	"desparams" },
	{ (uint_t)DESIOCQUICK,	"DESIOCQUICK", 	"desparams" },

	/* Printing system */
	{ (uint_t)PRNIOC_GET_IFCAP,	"PRNIOC_GET_IFCAP", 	NULL },
	{ (uint_t)PRNIOC_SET_IFCAP,	"PRNIOC_SET_IFCAP", 	NULL },
	{ (uint_t)PRNIOC_GET_IFINFO,	"PRNIOC_GET_IFINFO",
	    "prn_interface_info" },
	{ (uint_t)PRNIOC_GET_STATUS,	"PRNIOC_GET_STATUS", 	NULL },
	{ (uint_t)PRNIOC_GET_1284_DEVID,	"PRNIOC_GET_1284_DEVID",
	    "prn_1284_device_id" },
	{ (uint_t)PRNIOC_GET_1284_STATUS,
	    "PRNIOC_GET_IFCANIOC_GET_1284_STATUS", NULL },
	{ (uint_t)PRNIOC_GET_TIMEOUTS,	"PRNIOC_GET_TIMEOUTS",
	    "prn_timeouts" },
	{ (uint_t)PRNIOC_SET_TIMEOUTS,	"PRNIOC_SET_TIMEOUTS",
	    "prn_timeouts" },
	{ (uint_t)PRNIOC_RESET,	"PRNIOC_RESET", 	NULL },

	/* DTrace */
	{ (uint_t)DTRACEIOC_PROVIDER,	"DTRACEIOC_PROVIDER",	NULL },
	{ (uint_t)DTRACEIOC_PROBES,	"DTRACEIOC_PROBES",	NULL },
	{ (uint_t)DTRACEIOC_BUFSNAP,	"DTRACEIOC_BUFSNAP",	NULL },
	{ (uint_t)DTRACEIOC_PROBEMATCH,	"DTRACEIOC_PROBEMATCH",	NULL },
	{ (uint_t)DTRACEIOC_ENABLE,	"DTRACEIOC_ENABLE",	NULL },
	{ (uint_t)DTRACEIOC_AGGSNAP,	"DTRACEIOC_AGGSNAP",	NULL },
	{ (uint_t)DTRACEIOC_EPROBE,	"DTRACEIOC_EPROBE",	NULL },
	{ (uint_t)DTRACEIOC_PROBEARG,   "DTRACEIOC_PROBEARG",   NULL },
	{ (uint_t)DTRACEIOC_CONF,	"DTRACEIOC_CONF",	NULL },
	{ (uint_t)DTRACEIOC_STATUS,	"DTRACEIOC_STATUS",	NULL },
	{ (uint_t)DTRACEIOC_GO,		"DTRACEIOC_GO",		NULL },
	{ (uint_t)DTRACEIOC_STOP,	"DTRACEIOC_STOP",	NULL },
	{ (uint_t)DTRACEIOC_AGGDESC,	"DTRACEIOC_AGGDESC",	NULL },
	{ (uint_t)DTRACEIOC_FORMAT,	"DTRACEIOC_FORMAT",	NULL },
	{ (uint_t)DTRACEIOC_DOFGET,	"DTRACEIOC_DOFGET",	NULL },
	{ (uint_t)DTRACEIOC_REPLICATE,	"DTRACEIOC_REPLICATE",	NULL },

	{ (uint_t)DTRACEHIOC_ADD,	"DTRACEHIOC_ADD",	NULL },
	{ (uint_t)DTRACEHIOC_REMOVE,	"DTRACEHIOC_REMOVE",	NULL },
	{ (uint_t)DTRACEHIOC_ADDDOF,	"DTRACEHIOC_ADDDOF",	NULL },

	/* /dev/cryptoadm ioctl() control codes */
	{ (uint_t)CRYPTO_GET_VERSION,	"CRYPTO_GET_VERSION",	NULL },
	{ (uint_t)CRYPTO_GET_DEV_LIST,	"CRYPTO_GET_DEV_LIST",	NULL },
	{ (uint_t)CRYPTO_GET_SOFT_LIST,	"CRYPTO_GET_SOFT_LIST",	NULL },
	{ (uint_t)CRYPTO_GET_DEV_INFO,	"CRYPTO_GET_DEV_INFO",	NULL },
	{ (uint_t)CRYPTO_GET_SOFT_INFO,	"CRYPTO_GET_SOFT_INFO",	NULL },
	{ (uint_t)CRYPTO_LOAD_DEV_DISABLED,	"CRYPTO_LOAD_DEV_DISABLED",
	    NULL },
	{ (uint_t)CRYPTO_LOAD_SOFT_DISABLED,	"CRYPTO_LOAD_SOFT_DISABLED",
	    NULL },
	{ (uint_t)CRYPTO_UNLOAD_SOFT_MODULE,	"CRYPTO_UNLOAD_SOFT_MODULE",
	    NULL },
	{ (uint_t)CRYPTO_LOAD_SOFT_CONFIG,	"CRYPTO_LOAD_SOFT_CONFIG",
	    NULL },
	{ (uint_t)CRYPTO_POOL_CREATE,	"CRYPTO_POOL_CREATE",	NULL },
	{ (uint_t)CRYPTO_POOL_WAIT,	"CRYPTO_POOL_WAIT",	NULL },
	{ (uint_t)CRYPTO_POOL_RUN,	"CRYPTO_POOL_RUN",	NULL },
	{ (uint_t)CRYPTO_LOAD_DOOR,	"CRYPTO_LOAD_DOOR",	NULL },

	/* /dev/crypto ioctl() control codes */
	{ (uint_t)CRYPTO_GET_FUNCTION_LIST,	"CRYPTO_GET_FUNCTION_LIST",
	    NULL },
	{ (uint_t)CRYPTO_GET_MECHANISM_NUMBER,	"CRYPTO_GET_MECHANISM_NUMBER",
	    NULL },
	{ (uint_t)CRYPTO_OPEN_SESSION,	"CRYPTO_OPEN_SESSION",	NULL },
	{ (uint_t)CRYPTO_CLOSE_SESSION,	"CRYPTO_CLOSE_SESSION",	NULL },
	{ (uint_t)CRYPTO_CLOSE_ALL_SESSIONS,	"CRYPTO_CLOSE_ALL_SESSIONS",
	    NULL },
	{ (uint_t)CRYPTO_LOGIN,		"CRYPTO_LOGIN",		NULL },
	{ (uint_t)CRYPTO_LOGOUT,	"CRYPTO_LOGOUT",	NULL },
	{ (uint_t)CRYPTO_ENCRYPT,	"CRYPTO_ENCRYPT",	NULL },
	{ (uint_t)CRYPTO_ENCRYPT_INIT,	"CRYPTO_ENCRYPT_INIT",	NULL },
	{ (uint_t)CRYPTO_ENCRYPT_UPDATE,	"CRYPTO_ENCRYPT_UPDATE",
	    NULL },
	{ (uint_t)CRYPTO_ENCRYPT_FINAL,	"CRYPTO_ENCRYPT_FINAL",	NULL },
	{ (uint_t)CRYPTO_DECRYPT,	"CRYPTO_DECRYPT",	NULL },
	{ (uint_t)CRYPTO_DECRYPT_INIT,	"CRYPTO_DECRYPT_INIT",	NULL },
	{ (uint_t)CRYPTO_DECRYPT_UPDATE,	"CRYPTO_DECRYPT_UPDATE",
	    NULL },
	{ (uint_t)CRYPTO_DECRYPT_FINAL,	"CRYPTO_DECRYPT_FINAL",	NULL },
	{ (uint_t)CRYPTO_DIGEST,	"CRYPTO_DIGEST",	NULL },
	{ (uint_t)CRYPTO_DIGEST_INIT,	"CRYPTO_DIGEST_INIT",	NULL },
	{ (uint_t)CRYPTO_DIGEST_UPDATE,	"CRYPTO_DIGEST_UPDATE",	NULL },
	{ (uint_t)CRYPTO_DIGEST_KEY,	"CRYPTO_DIGEST_KEY",	NULL },
	{ (uint_t)CRYPTO_DIGEST_FINAL,	"CRYPTO_DIGEST_FINAL",	NULL },
	{ (uint_t)CRYPTO_MAC,		"CRYPTO_MAC",		NULL },
	{ (uint_t)CRYPTO_MAC_INIT,	"CRYPTO_MAC_INIT",	NULL },
	{ (uint_t)CRYPTO_MAC_UPDATE,	"CRYPTO_MAC_UPDATE",	NULL },
	{ (uint_t)CRYPTO_MAC_FINAL,	"CRYPTO_MAC_FINAL",	NULL },
	{ (uint_t)CRYPTO_SIGN,		"CRYPTO_SIGN",		NULL },
	{ (uint_t)CRYPTO_SIGN_INIT,	"CRYPTO_SIGN_INIT",	NULL },
	{ (uint_t)CRYPTO_SIGN_UPDATE,	"CRYPTO_SIGN_UPDATE",	NULL },
	{ (uint_t)CRYPTO_SIGN_FINAL,	"CRYPTO_SIGN_FINAL",	NULL },
	{ (uint_t)CRYPTO_SIGN_RECOVER_INIT,	"CRYPTO_SIGN_RECOVER_INIT",
	    NULL },
	{ (uint_t)CRYPTO_SIGN_RECOVER,	"CRYPTO_SIGN_RECOVER",	NULL },
	{ (uint_t)CRYPTO_VERIFY,	"CRYPTO_VERIFY",	NULL },
	{ (uint_t)CRYPTO_VERIFY_INIT,	"CRYPTO_VERIFY_INIT",	NULL },
	{ (uint_t)CRYPTO_VERIFY_UPDATE,	"CRYPTO_VERIFY_UPDATE",	NULL },
	{ (uint_t)CRYPTO_VERIFY_FINAL,	"CRYPTO_VERIFY_FINAL",	NULL },
	{ (uint_t)CRYPTO_VERIFY_RECOVER_INIT,	"CRYPTO_VERIFY_RECOVER_INIT",
	    NULL },
	{ (uint_t)CRYPTO_VERIFY_RECOVER,	"CRYPTO_VERIFY_RECOVER",
	    NULL },
	{ (uint_t)CRYPTO_DIGEST_ENCRYPT_UPDATE,	"CRYPTO_DIGEST_ENCRYPT_UPDATE",
	    NULL },
	{ (uint_t)CRYPTO_DECRYPT_DIGEST_UPDATE,	"CRYPTO_DECRYPT_DIGEST_UPDATE",
	    NULL },
	{ (uint_t)CRYPTO_SIGN_ENCRYPT_UPDATE,	"CRYPTO_SIGN_ENCRYPT_UPDATE",
	    NULL },
	{ (uint_t)CRYPTO_DECRYPT_VERIFY_UPDATE,	"CRYPTO_DECRYPT_VERIFY_UPDATE",
	    NULL },
	{ (uint_t)CRYPTO_SEED_RANDOM,	"CRYPTO_SEED_RANDOM",	NULL },
	{ (uint_t)CRYPTO_GENERATE_RANDOM,	"CRYPTO_GENERATE_RANDOM",
	    NULL },
	{ (uint_t)CRYPTO_OBJECT_CREATE,	"CRYPTO_OBJECT_CREATE",	NULL },
	{ (uint_t)CRYPTO_OBJECT_COPY,	"CRYPTO_OBJECT_COPY",	NULL },
	{ (uint_t)CRYPTO_OBJECT_DESTROY,	"CRYPTO_OBJECT_DESTROY",
	    NULL },
	{ (uint_t)CRYPTO_OBJECT_GET_ATTRIBUTE_VALUE,
	    "CRYPTO_OBJECT_GET_ATTRIBUTE_VALUE",	NULL },
	{ (uint_t)CRYPTO_OBJECT_GET_SIZE, "CRYPTO_OBJECT_GET_SIZE",	NULL },
	{ (uint_t)CRYPTO_OBJECT_SET_ATTRIBUTE_VALUE,
	    "CRYPTO_OBJECT_SET_ATTRIBUTE_VALUE",	NULL },
	{ (uint_t)CRYPTO_OBJECT_FIND_INIT,	"CRYPTO_OBJECT_FIND_INIT",
	    NULL },
	{ (uint_t)CRYPTO_OBJECT_FIND_UPDATE,	"CRYPTO_OBJECT_FIND_UPDATE",
	    NULL },
	{ (uint_t)CRYPTO_OBJECT_FIND_FINAL,	"CRYPTO_OBJECT_FIND_FINAL",
	    NULL },
	{ (uint_t)CRYPTO_GENERATE_KEY,	"CRYPTO_GENERATE_KEY",	NULL },
	{ (uint_t)CRYPTO_GENERATE_KEY_PAIR,	"CRYPTO_GENERATE_KEY_PAIR",
	    NULL },
	{ (uint_t)CRYPTO_WRAP_KEY,	"CRYPTO_WRAP_KEY",	NULL },
	{ (uint_t)CRYPTO_UNWRAP_KEY,	"CRYPTO_UNWRAP_KEY",	NULL },
	{ (uint_t)CRYPTO_DERIVE_KEY,	"CRYPTO_DERIVE_KEY",	NULL },
	{ (uint_t)CRYPTO_GET_PROVIDER_LIST,	"CRYPTO_GET_PROVIDER_LIST",
	    NULL },
	{ (uint_t)CRYPTO_GET_PROVIDER_INFO,	"CRYPTO_GET_PROVIDER_INFO",
	    NULL },
	{ (uint_t)CRYPTO_GET_PROVIDER_MECHANISMS,
	    "CRYPTO_GET_PROVIDER_MECHANISMS",	NULL },
	{ (uint_t)CRYPTO_GET_PROVIDER_MECHANISM_INFO,
	    "CRYPTO_GET_PROVIDER_MECHANISM_INFO",	NULL },
	{ (uint_t)CRYPTO_INIT_TOKEN,	"CRYPTO_INIT_TOKEN",	NULL },
	{ (uint_t)CRYPTO_INIT_PIN,	"CRYPTO_INIT_PIN",	NULL },
	{ (uint_t)CRYPTO_SET_PIN,	"CRYPTO_SET_PIN",	NULL },
	{ (uint_t)CRYPTO_NOSTORE_GENERATE_KEY,
	    "CRYPTO_NOSTORE_GENERATE_KEY",	NULL },
	{ (uint_t)CRYPTO_NOSTORE_GENERATE_KEY_PAIR,
	    "CRYPTO_NOSTORE_GENERATE_KEY_PAIR",	NULL },
	{ (uint_t)CRYPTO_NOSTORE_DERIVE_KEY,
	    "CRYPTO_NOSTORE_DERIVE_KEY",	NULL },
	{ (uint_t)CRYPTO_FIPS140_STATUS,	"CRYPTO_FIPS140_STATUS", NULL },
	{ (uint_t)CRYPTO_FIPS140_SET,	"CRYPTO_FIPS140_SET",	NULL },

	/* kbio ioctls */
	{ (uint_t)KIOCTRANS,		"KIOCTRANS",	NULL },
	{ (uint_t)KIOCGTRANS,		"KIOCGTRANS",	NULL },
	{ (uint_t)KIOCTRANSABLE,	"KIOCTRANSABLE",	NULL },
	{ (uint_t)KIOCGTRANSABLE,	"KIOCGTRANSABLE",	NULL },
	{ (uint_t)KIOCSETKEY,		"KIOCSETKEY",	NULL },
	{ (uint_t)KIOCGETKEY,		"KIOCGETKEY",	NULL },
	{ (uint_t)KIOCCMD,		"KIOCCMD",	NULL },
	{ (uint_t)KIOCTYPE,		"KIOCTYPE",	NULL },
	{ (uint_t)KIOCSDIRECT,		"KIOCSDIRECT",	NULL },
	{ (uint_t)KIOCGDIRECT,		"KIOCGDIRECT",	NULL },
	{ (uint_t)KIOCSKEY,		"KIOCSKEY",	NULL },
	{ (uint_t)KIOCGKEY,		"KIOCGKEY",	NULL },
	{ (uint_t)KIOCSLED,		"KIOCSLED",	NULL },
	{ (uint_t)KIOCGLED,		"KIOCGLED",	NULL },
	{ (uint_t)KIOCSCOMPAT,		"KIOCSCOMPAT",	NULL },
	{ (uint_t)KIOCGCOMPAT,		"KIOCGCOMPAT",	NULL },
	{ (uint_t)KIOCSLAYOUT,		"KIOCSLAYOUT",	NULL },
	{ (uint_t)KIOCLAYOUT,		"KIOCLAYOUT",	NULL },
	{ (uint_t)KIOCSKABORTEN,	"KIOCSKABORTEN",	NULL },
	{ (uint_t)KIOCGRPTDELAY,	"KIOCGRPTDELAY",	NULL },
	{ (uint_t)KIOCSRPTDELAY,	"KIOCSRPTDELAY",	NULL },
	{ (uint_t)KIOCGRPTRATE,		"KIOCGRPTRATE",	NULL },
	{ (uint_t)KIOCSRPTRATE,		"KIOCSRPTRATE",	NULL },
	{ (uint_t)KIOCSETFREQ,		"KIOCSETFREQ",	NULL },
	{ (uint_t)KIOCMKTONE,		"KIOCMKTONE",	NULL },

	/* ptm/pts driver I_STR ioctls */
	{ (uint_t)ISPTM,		"ISPTM",		NULL},
	{ (uint_t)UNLKPT,		"UNLKPT",		NULL},
	{ (uint_t)PTSSTTY,		"PTSSTTY",		NULL},
	{ (uint_t)ZONEPT,		"ZONEPT",		NULL},
	{ (uint_t)OWNERPT,		"OWNERPT",		NULL},

	/* aggr link aggregation pseudo driver ioctls */
	{ (uint_t)LAIOC_CREATE,		"LAIOC_CREATE",		"laioc_create"},
	{ (uint_t)LAIOC_DELETE,		"LAIOC_DELETE",		"laioc_delete"},
	{ (uint_t)LAIOC_INFO,		"LAIOC_INFO",		"laioc_info"},
	{ (uint_t)LAIOC_ADD,		"LAIOC_ADD",
	    "laioc_add_rem"},
	{ (uint_t)LAIOC_REMOVE,		"LAIOC_REMOVE",
	    "laioc_add_rem"},
	{ (uint_t)LAIOC_MODIFY,		"LAIOC_MODIFY",		"laioc_modify"},

	/* dld data-link ioctls */
	{ (uint_t)DLDIOC_ATTR,		"DLDIOC_ATTR",		"dld_ioc_attr"},
	{ (uint_t)DLDIOC_PHYS_ATTR,	"DLDIOC_PHYS_ATTR",
		"dld_ioc_phys_attr"},
	{ (uint_t)DLDIOC_DOORSERVER,	"DLDIOC_DOORSERVER", "dld_ioc_door"},
	{ (uint_t)DLDIOC_RENAME,	"DLDIOC_RENAME", "dld_ioc_rename"},
	{ (uint_t)DLDIOC_SECOBJ_GET,		"DLDIOC_SECOBJ_GET",
		"dld_ioc_secobj_get"},
	{ (uint_t)DLDIOC_SECOBJ_SET,		"DLDIOC_SECOBJ_SET",
		"dld_ioc_secobj_set"},
	{ (uint_t)DLDIOC_SECOBJ_UNSET,		"DLDIOC_SECOBJ_UNSET",
		"dld_ioc_secobj_unset"},
	{ (uint_t)DLDIOC_MACADDRGET,		"DLDIOC_MACADDRGET",
		"dld_ioc_macaddrget"},
	{ (uint_t)DLDIOC_SETMACPROP,		"DLDIOC_SETMACPROP",
		"dld_ioc_macprop_s"},
	{ (uint_t)DLDIOC_GETMACPROP,		"DLDIOC_GETMACPROP",
		"dld_ioc_macprop_s"},
	{ (uint_t)DLDIOC_ADDFLOW,		"DLDIOC_ADDFLOW",
		"dld_ioc_addflow"},
	{ (uint_t)DLDIOC_REMOVEFLOW,		"DLDIOC_REMOVEFLOW",
		"dld_ioc_removeflow"},
	{ (uint_t)DLDIOC_MODIFYFLOW,		"DLDIOC_MODIFYFLOW",
		"dld_ioc_modifyflow"},
	{ (uint_t)DLDIOC_WALKFLOW,		"DLDIOC_WALKFLOW",
		"dld_ioc_walkflow"},
	{ (uint_t)DLDIOC_USAGELOG,		"DLDIOC_USAGELOG",
		"dld_ioc_usagelog"},

	/* simnet ioctls */
	{ (uint_t)SIMNET_IOC_CREATE,		"SIMNET_IOC_CREATE",
		"simnet_ioc_create"},
	{ (uint_t)SIMNET_IOC_DELETE,		"SIMNET_IOC_DELETE",
		"simnet_ioc_delete"},
	{ (uint_t)SIMNET_IOC_INFO,		"SIMNET_IOC_INFO",
		"simnet_ioc_info"},
	{ (uint_t)SIMNET_IOC_MODIFY,		"SIMNET_IOC_MODIFY",
		"simnet_ioc_info"},

	/* vnic ioctls */
	{ (uint_t)VNIC_IOC_CREATE,		"VNIC_IOC_CREATE",
		"vnic_ioc_create"},
	{ (uint_t)VNIC_IOC_DELETE,		"VNIC_IOC_DELETE",
		"vnic_ioc_delete"},
	{ (uint_t)VNIC_IOC_INFO,		"VNIC_IOC_INFO",
		"vnic_ioc_info"},

	/* ZFS ioctls */
	{ (uint_t)ZFS_IOC_POOL_CREATE,		"ZFS_IOC_POOL_CREATE",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_POOL_DESTROY,		"ZFS_IOC_POOL_DESTROY",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_POOL_IMPORT,		"ZFS_IOC_POOL_IMPORT",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_POOL_EXPORT,		"ZFS_IOC_POOL_EXPORT",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_POOL_CONFIGS,		"ZFS_IOC_POOL_CONFIGS",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_POOL_STATS,		"ZFS_IOC_POOL_STATS",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_POOL_TRYIMPORT,	"ZFS_IOC_POOL_TRYIMPORT",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_POOL_SCAN,		"ZFS_IOC_POOL_SCAN",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_POOL_FREEZE,		"ZFS_IOC_POOL_FREEZE",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_POOL_UPGRADE,		"ZFS_IOC_POOL_UPGRADE",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_POOL_GET_HISTORY,	"ZFS_IOC_POOL_GET_HISTORY",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_VDEV_ADD,		"ZFS_IOC_VDEV_ADD",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_VDEV_REMOVE,		"ZFS_IOC_VDEV_REMOVE",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_VDEV_SET_STATE,	"ZFS_IOC_VDEV_SET_STATE",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_VDEV_ATTACH,		"ZFS_IOC_VDEV_ATTACH",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_VDEV_DETACH,		"ZFS_IOC_VDEV_DETACH",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_VDEV_SETPATH,		"ZFS_IOC_VDEV_SETPATH",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_VDEV_SETFRU,		"ZFS_IOC_VDEV_SETFRU",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_OBJSET_STATS,		"ZFS_IOC_OBJSET_STATS",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_OBJSET_ZPLPROPS,	"ZFS_IOC_OBJSET_ZPLPROPS",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_DATASET_LIST_NEXT,	"ZFS_IOC_DATASET_LIST_NEXT",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_SNAPSHOT_LIST_NEXT,	"ZFS_IOC_SNAPSHOT_LIST_NEXT",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_SET_PROP,		"ZFS_IOC_SET_PROP",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_CREATE,		"ZFS_IOC_CREATE",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_DESTROY,		"ZFS_IOC_DESTROY",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_ROLLBACK,		"ZFS_IOC_ROLLBACK",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_RENAME,		"ZFS_IOC_RENAME",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_RECV,			"ZFS_IOC_RECV",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_SEND,			"ZFS_IOC_SEND",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_INJECT_FAULT,		"ZFS_IOC_INJECT_FAULT",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_CLEAR_FAULT,		"ZFS_IOC_CLEAR_FAULT",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_INJECT_LIST_NEXT,	"ZFS_IOC_INJECT_LIST_NEXT",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_ERROR_LOG,		"ZFS_IOC_ERROR_LOG",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_CLEAR,		"ZFS_IOC_CLEAR",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_PROMOTE,		"ZFS_IOC_PROMOTE",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_SNAPSHOT,		"ZFS_IOC_SNAPSHOT",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_DSOBJ_TO_DSNAME,	"ZFS_IOC_DSOBJ_TO_DSNAME",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_OBJ_TO_PATH,		"ZFS_IOC_OBJ_TO_PATH",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_POOL_SET_PROPS,	"ZFS_IOC_POOL_SET_PROPS",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_POOL_GET_PROPS,	"ZFS_IOC_POOL_GET_PROPS",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_SET_FSACL,		"ZFS_IOC_SET_FSACL",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_GET_FSACL,		"ZFS_IOC_GET_FSACL",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_SHARE,		"ZFS_IOC_SHARE",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_INHERIT_PROP,		"ZFS_IOC_INHERIT_PROP",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_SMB_ACL,		"ZFS_IOC_SMB_ACL",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_USERSPACE_ONE,	"ZFS_IOC_USERSPACE_ONE",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_USERSPACE_MANY,	"ZFS_IOC_USERSPACE_MANY",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_USERSPACE_UPGRADE,	"ZFS_IOC_USERSPACE_UPGRADE",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_HOLD,			"ZFS_IOC_HOLD",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_RELEASE,		"ZFS_IOC_RELEASE",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_GET_HOLDS,		"ZFS_IOC_GET_HOLDS",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_OBJSET_RECVD_PROPS,	"ZFS_IOC_OBJSET_RECVD_PROPS",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_VDEV_SPLIT,		"ZFS_IOC_VDEV_SPLIT",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_NEXT_OBJ,		"ZFS_IOC_NEXT_OBJ",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_DIFF,			"ZFS_IOC_DIFF",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_TMP_SNAPSHOT,		"ZFS_IOC_TMP_SNAPSHOT",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_OBJ_TO_STATS,		"ZFS_IOC_OBJ_TO_STATS",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_SPACE_WRITTEN,	"ZFS_IOC_SPACE_WRITTEN",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_DESTROY_SNAPS,	"ZFS_IOC_DESTROY_SNAPS",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_POOL_REGUID,		"ZFS_IOC_POOL_REGUID",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_POOL_REOPEN,		"ZFS_IOC_POOL_REOPEN",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_SEND_PROGRESS,	"ZFS_IOC_SEND_PROGRESS",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_LOG_HISTORY,		"ZFS_IOC_LOG_HISTORY",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_SEND_NEW,		"ZFS_IOC_SEND_NEW",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_SEND_SPACE,		"ZFS_IOC_SEND_SPACE",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_CLONE,		"ZFS_IOC_CLONE",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_REMAP,		"ZFS_IOC_REMAP",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_BOOKMARK,		"ZFS_IOC_BOOKMARK",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_GET_BOOKMARKS,	"ZFS_IOC_GET_BOOKMARKS",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_DESTROY_BOOKMARKS,	"ZFS_IOC_DESTROY_BOOKMARKS",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_CHANNEL_PROGRAM,	"ZFS_IOC_CHANNEL_PROGRAM",
		"zfs_cmd_t" },

	/* kssl ioctls */
	{ (uint_t)KSSL_ADD_ENTRY,		"KSSL_ADD_ENTRY",
		"kssl_params_t"},
	{ (uint_t)KSSL_DELETE_ENTRY,		"KSSL_DELETE_ENTRY",
		"sockaddr_in"},

	/* disk ioctls - (0x04 << 8) - dkio.h */
	{ (uint_t)DKIOCGGEOM,		"DKIOCGGEOM",
		"struct dk_geom"},
	{ (uint_t)DKIOCINFO,		"DKIOCINFO",
		"struct dk_info"},
	{ (uint_t)DKIOCEJECT,		"DKIOCEJECT",
		NULL},
	{ (uint_t)DKIOCGVTOC,		"DKIOCGVTOC",
		"struct vtoc"},
	{ (uint_t)DKIOCSVTOC,		"DKIOCSVTOC",
		"struct vtoc"},
	{ (uint_t)DKIOCGEXTVTOC,	"DKIOCGEXTVTOC",
		"struct extvtoc"},
	{ (uint_t)DKIOCSEXTVTOC,	"DKIOCSEXTVTOC",
		"struct extvtoc"},
	{ (uint_t)DKIOCFLUSHWRITECACHE,	"DKIOCFLUSHWRITECACHE",
		NULL},
	{ (uint_t)DKIOCGETWCE,		"DKIOCGETWCE",
		NULL},
	{ (uint_t)DKIOCSETWCE,		"DKIOCSETWCE",
		NULL},
	{ (uint_t)DKIOCSGEOM,		"DKIOCSGEOM",
		"struct dk_geom"},
	{ (uint_t)DKIOCSAPART,		"DKIOCSAPART",
		"struct dk_allmap"},
	{ (uint_t)DKIOCGAPART,		"DKIOCGAPART",
		"struct dk_allmap"},
	{ (uint_t)DKIOCG_PHYGEOM,	"DKIOCG_PHYGEOM",
		"struct dk_geom"},
	{ (uint_t)DKIOCG_VIRTGEOM,	"DKIOCG_VIRTGEOM",
		"struct dk_geom"},
	{ (uint_t)DKIOCLOCK,		"DKIOCLOCK",
		NULL},
	{ (uint_t)DKIOCUNLOCK,		"DKIOCUNLOCK",
		NULL},
	{ (uint_t)DKIOCSTATE,		"DKIOCSTATE",
		NULL},
	{ (uint_t)DKIOCREMOVABLE,	"DKIOCREMOVABLE",
		NULL},
	{ (uint_t)DKIOCHOTPLUGGABLE,	"DKIOCHOTPLUGGABLE",
		NULL},
	{ (uint_t)DKIOCADDBAD,		"DKIOCADDBAD",
		NULL},
	{ (uint_t)DKIOCGETDEF,		"DKIOCGETDEF",
		NULL},
	{ (uint_t)DKIOCPARTINFO,	"DKIOCPARTINFO",
		"struct part_info"},
	{ (uint_t)DKIOCEXTPARTINFO,	"DKIOCEXTPARTINFO",
		"struct extpart_info"},
	{ (uint_t)DKIOCGMEDIAINFO,	"DKIOCGMEDIAINFO",
		"struct dk_minfo"},
	{ (uint_t)DKIOCGMBOOT,		"DKIOCGMBOOT",
		NULL},
	{ (uint_t)DKIOCSMBOOT,		"DKIOCSMBOOT",
		NULL},
	{ (uint_t)DKIOCSETEFI,		"DKIOCSETEFI",
		"struct dk_efi"},
	{ (uint_t)DKIOCGETEFI,		"DKIOCGETEFI",
		"struct dk_efi"},
	{ (uint_t)DKIOCPARTITION,	"DKIOCPARTITION",
		"struct partition64"},
	{ (uint_t)DKIOCGETVOLCAP,	"DKIOCGETVOLCAP",
		"struct volcap_t"},
	{ (uint_t)DKIOCSETVOLCAP,	"DKIOCSETVOLCAP",
		"struct volcap_t"},
	{ (uint_t)DKIOCDMR,		"DKIOCDMR",
		"struct vol_directed_rd"},
	{ (uint_t)DKIOCDUMPINIT,	"DKIOCDUMPINIT",
		NULL},
	{ (uint_t)DKIOCDUMPFINI,	"DKIOCDUMPFINI",
		NULL},
	{ (uint_t)DKIOCREADONLY,	"DKIOCREADONLY",
		NULL},

	/* disk ioctls - (0x04 << 8) - fdio.h */
	{ (uint_t)FDIOGCHAR,		"FDIOGCHAR",
		"struct fd_char"},
	{ (uint_t)FDIOSCHAR,		"FDIOSCHAR",
		"struct fd_char"},
	{ (uint_t)FDEJECT,		"FDEJECT",
		NULL},
	{ (uint_t)FDGETCHANGE,		"FDGETCHANGE",
		NULL},
	{ (uint_t)FDGETDRIVECHAR,	"FDGETDRIVECHAR",
		"struct fd_drive"},
	{ (uint_t)FDSETDRIVECHAR,	"FDSETDRIVECHAR",
		"struct fd_drive"},
	{ (uint_t)FDGETSEARCH,		"FDGETSEARCH",
		NULL},
	{ (uint_t)FDSETSEARCH,		"FDSETSEARCH",
		NULL},
	{ (uint_t)FDIOCMD,		"FDIOCMD",
		"struct fd_cmd"},
	{ (uint_t)FDRAW,		"FDRAW",
		"struct fd_raw"},
	{ (uint_t)FDDEFGEOCHAR,		"FDDEFGEOCHAR",
		NULL},

	/* disk ioctls - (0x04 << 8) - cdio.h */
	{ (uint_t)CDROMPAUSE,		"CDROMPAUSE",
		NULL},
	{ (uint_t)CDROMRESUME,		"CDROMRESUME",
		NULL},
	{ (uint_t)CDROMPLAYMSF,		"CDROMPLAYMSF",
		"struct cdrom_msf"},
	{ (uint_t)CDROMPLAYTRKIND,	"CDROMPLAYTRKIND",
		"struct cdrom_ti"},
	{ (uint_t)CDROMREADTOCHDR,	"CDROMREADTOCHDR",
		"struct cdrom_tochdr"},
	{ (uint_t)CDROMREADTOCENTRY,	"CDROMREADTOCENTRY",
		"struct cdrom_tocentry"},
	{ (uint_t)CDROMSTOP,		"CDROMSTOP",
		NULL},
	{ (uint_t)CDROMSTART,		"CDROMSTART",
		NULL},
	{ (uint_t)CDROMEJECT,		"CDROMEJECT",
		NULL},
	{ (uint_t)CDROMVOLCTRL,		"CDROMVOLCTRL",
		"struct cdrom_volctrl"},
	{ (uint_t)CDROMSUBCHNL,		"CDROMSUBCHNL",
		"struct cdrom_subchnl"},
	{ (uint_t)CDROMREADMODE2,	"CDROMREADMODE2",
		"struct cdrom_read"},
	{ (uint_t)CDROMREADMODE1,	"CDROMREADMODE1",
		"struct cdrom_read"},
	{ (uint_t)CDROMREADOFFSET,	"CDROMREADOFFSET",
		NULL},
	{ (uint_t)CDROMGBLKMODE,	"CDROMGBLKMODE",
		NULL},
	{ (uint_t)CDROMSBLKMODE,	"CDROMSBLKMODE",
		NULL},
	{ (uint_t)CDROMCDDA,		"CDROMCDDA",
		"struct cdrom_cdda"},
	{ (uint_t)CDROMCDXA,		"CDROMCDXA",
		"struct cdrom_cdxa"},
	{ (uint_t)CDROMSUBCODE,		"CDROMSUBCODE",
		"struct cdrom_subcode"},
	{ (uint_t)CDROMGDRVSPEED,	"CDROMGDRVSPEED",
		NULL},
	{ (uint_t)CDROMSDRVSPEED,	"CDROMSDRVSPEED",
		NULL},
	{ (uint_t)CDROMCLOSETRAY,	"CDROMCLOSETRAY",
		NULL},

	/* disk ioctls - (0x04 << 8) - uscsi.h */
	{ (uint_t)USCSICMD,		"USCSICMD",
		"struct uscsi_cmd"},

	/* dumpadm ioctls - (0xdd << 8) */
	{ (uint_t)DIOCGETDEV,	"DIOCGETDEV",
		NULL},

	/* mntio ioctls - ('m' << 8) */
	{ (uint_t)MNTIOC_NMNTS,		"MNTIOC_NMNTS",
		NULL},
	{ (uint_t)MNTIOC_GETDEVLIST,	"MNTIOC_GETDEVLIST",
		NULL},
	{ (uint_t)MNTIOC_SETTAG,	"MNTIOC_SETTAG",
		"struct mnttagdesc"},
	{ (uint_t)MNTIOC_CLRTAG,	"MNTIOC_CLRTAG",
		"struct mnttagdesc"},
	{ (uint_t)MNTIOC_SHOWHIDDEN,	"MNTIOC_SHOWHIDDEN",
		NULL},
	{ (uint_t)MNTIOC_GETMNTENT,	"MNTIOC_GETMNTENT",
		"struct mnttab"},
	{ (uint_t)MNTIOC_GETEXTMNTENT,	"MNTIOC_GETEXTMNTENT",
		"struct extmnttab"},
	{ (uint_t)MNTIOC_GETMNTANY,	"MNTIOC_GETMNTANY",
		"struct mnttab"},

	/* devinfo ioctls - ('df' << 8) - devinfo_impl.h */
	{ (uint_t)DINFOUSRLD,		"DINFOUSRLD",
		NULL},
	{ (uint_t)DINFOLODRV,		"DINFOLODRV",
		NULL},
	{ (uint_t)DINFOIDENT,		"DINFOIDENT",
		NULL},

	{ (uint_t)IPTUN_CREATE,	"IPTUN_CREATE",	"iptun_kparams_t"},
	{ (uint_t)IPTUN_DELETE,	"IPTUN_DELETE", "datalink_id_t"},
	{ (uint_t)IPTUN_MODIFY, "IPTUN_MODIFY", "iptun_kparams_t"},
	{ (uint_t)IPTUN_INFO,	"IPTUN_INFO",	NULL},
	{ (uint_t)IPTUN_SET_6TO4RELAY, "IPTUN_SET_6TO4RELAY",	NULL},
	{ (uint_t)IPTUN_GET_6TO4RELAY, "IPTUN_GET_6TO4RELAY",	NULL},

	/* zcons ioctls */
	{ (uint_t)ZC_HOLDSLAVE,		"ZC_HOLDSLAVE",		NULL },
	{ (uint_t)ZC_RELEASESLAVE,	"ZC_RELEASESLAVE",	NULL },

	/* hid ioctls - ('h' << 8) - hid.h */
	{ (uint_t)HIDIOCKMGDIRECT,	"HIDIOCKMGDIRECT",	NULL },
	{ (uint_t)HIDIOCKMSDIRECT,	"HIDIOCKMSDIRECT",	NULL },

	/* pm ioctls */
	{ (uint_t)PM_SCHEDULE,		"PM_SCHEDULE",		NULL },
	{ (uint_t)PM_GET_IDLE_TIME,	"PM_GET_IDLE_TIME",	NULL },
	{ (uint_t)PM_GET_NUM_CMPTS,	"PM_GET_NUM_CMPTS",	NULL },
	{ (uint_t)PM_GET_THRESHOLD,	"PM_GET_THRESHOLD",	NULL },
	{ (uint_t)PM_SET_THRESHOLD,	"PM_SET_THRESHOLD",	NULL },
	{ (uint_t)PM_GET_NORM_PWR,	"PM_GET_NORM_PWR",	NULL },
	{ (uint_t)PM_SET_CUR_PWR,	"PM_SET_CUR_PWR",	NULL },
	{ (uint_t)PM_GET_CUR_PWR,	"PM_GET_CUR_PWR",	NULL },
	{ (uint_t)PM_GET_NUM_DEPS,	"PM_GET_NUM_DEPS",	NULL },
	{ (uint_t)PM_GET_DEP,		"PM_GET_DEP",		NULL },
	{ (uint_t)PM_ADD_DEP,		"PM_ADD_DEP",		NULL },
	{ (uint_t)PM_REM_DEP,		"PM_REM_DEP",		NULL },
	{ (uint_t)PM_REM_DEVICE,	"PM_REM_DEVICE",	NULL },
	{ (uint_t)PM_REM_DEVICES,	"PM_REM_DEVICES",	NULL },
	{ (uint_t)PM_DISABLE_AUTOPM,	"PM_DISABLE_AUTOPM",	NULL },
	{ (uint_t)PM_REENABLE_AUTOPM,	"PM_REENABLE_AUTOPM",	NULL },
	{ (uint_t)PM_SET_NORM_PWR,	"PM_SET_NORM_PWR",	NULL },
	{ (uint_t)PM_GET_SYSTEM_THRESHOLD,	"PM_GET_SYSTEM_THRESHOLD",
		NULL },
	{ (uint_t)PM_GET_DEFAULT_SYSTEM_THRESHOLD,
		"PM_GET_DEFAULT_SYSTEM_THRESHOLD", NULL },
	{ (uint_t)PM_SET_SYSTEM_THRESHOLD,	"PM_SET_SYSTEM_THRESHOLD",
		NULL },
	{ (uint_t)PM_START_PM,		"PM_START_PM",		NULL },
	{ (uint_t)PM_STOP_PM,		"PM_STOP_PM",		NULL },
	{ (uint_t)PM_RESET_PM,		"PM_RESET_PM",		NULL },
	{ (uint_t)PM_GET_PM_STATE,	"PM_GET_PM_STATE",	NULL },
	{ (uint_t)PM_GET_AUTOS3_STATE,	"PM_GET_AUTOS3_STATE",	NULL },
	{ (uint_t)PM_GET_S3_SUPPORT_STATE,	"PM_GET_S3_SUPPORT_STATE",
		NULL },
	{ (uint_t)PM_IDLE_DOWN,		"PM_IDLE_DOWN",		NULL },
	{ (uint_t)PM_START_CPUPM,	"PM_START_CPUPM",	NULL },
	{ (uint_t)PM_START_CPUPM_EV,	"PM_START_CPUPM_EV",	NULL },
	{ (uint_t)PM_START_CPUPM_POLL,	"PM_START_CPUPM_POLL",	NULL },
	{ (uint_t)PM_STOP_CPUPM,	"PM_STOP_CPUPM",	NULL },
	{ (uint_t)PM_GET_CPU_THRESHOLD,	"PM_GET_CPU_THRESHOLD",	NULL },
	{ (uint_t)PM_SET_CPU_THRESHOLD,	"PM_SET_CPU_THRESHOLD",	NULL },
	{ (uint_t)PM_GET_CPUPM_STATE,	"PM_GET_CPUPM_STATE",	NULL },
	{ (uint_t)PM_START_AUTOS3,	"PM_START_AUTOS3",	NULL },
	{ (uint_t)PM_STOP_AUTOS3,	"PM_STOP_AUTOS3",	NULL },
	{ (uint_t)PM_ENABLE_S3,		"PM_ENABLE_S3",		NULL },
	{ (uint_t)PM_DISABLE_S3,	"PM_DISABLE_S3",	NULL },
	{ (uint_t)PM_ENTER_S3,		"PM_ENTER_S3",		NULL },
	{ (uint_t)PM_DISABLE_CPU_DEEP_IDLE,	"PM_DISABLE_CPU_DEEP_IDLE",
		NULL },
	{ (uint_t)PM_ENABLE_CPU_DEEP_IDLE,	"PM_START_CPU_DEEP_IDLE",
		NULL },
	{ (uint_t)PM_DEFAULT_CPU_DEEP_IDLE,	"PM_DFLT_CPU_DEEP_IDLE",
		NULL },
#ifdef _SYSCALL32
	{ (uint_t)PM_GET_STATE_CHANGE,		"PM_GET_STATE_CHANGE",
		"pm_state_change32_t" },
	{ (uint_t)PM_GET_STATE_CHANGE_WAIT,	"PM_GET_STATE_CHANGE_WAIT",
		"pm_state_change32_t" },
	{ (uint_t)PM_DIRECT_NOTIFY,		"PM_DIRECT_NOTIFY",
		"pm_state_change32_t" },
	{ (uint_t)PM_DIRECT_NOTIFY_WAIT,	"PM_DIRECT_NOTIFY_WAIT",
		"pm_state_change32_t" },
	{ (uint_t)PM_REPARSE_PM_PROPS,		"PM_REPARSE_PM_PROPS",
		"pm_req32_t" },
	{ (uint_t)PM_SET_DEVICE_THRESHOLD,	"PM_SET_DEVICE_THRESHOLD",
		"pm_req32_t" },
	{ (uint_t)PM_GET_STATS,			"PM_GET_STATS",
		"pm_req32_t" },
	{ (uint_t)PM_GET_DEVICE_THRESHOLD,	"PM_GET_DEVICE_THRESHOLD",
		"pm_req32_t" },
	{ (uint_t)PM_GET_POWER_NAME,		"PM_GET_POWER_NAME",
		"pm_req32_t" },
	{ (uint_t)PM_GET_POWER_LEVELS,		"PM_GET_POWER_LEVELS",
		"pm_req32_t" },
	{ (uint_t)PM_GET_NUM_COMPONENTS,	"PM_GET_NUM_COMPONENTS",
		"pm_req32_t" },
	{ (uint_t)PM_GET_COMPONENT_NAME,	"PM_GET_COMPONENT_NAME",
		"pm_req32_t" },
	{ (uint_t)PM_GET_NUM_POWER_LEVELS,	"PM_GET_NUM_POWER_LEVELS",
		"pm_req32_t" },
	{ (uint_t)PM_DIRECT_PM,			"PM_DIRECT_PM",
		"pm_req32_t" },
	{ (uint_t)PM_RELEASE_DIRECT_PM,		"PM_RELEASE_DIRECT_PM",
		"pm_req32_t" },
	{ (uint_t)PM_RESET_DEVICE_THRESHOLD,	"PM_RESET_DEVICE_THRESHOLD",
		"pm_req32_t" },
	{ (uint_t)PM_GET_DEVICE_TYPE,		"PM_GET_DEVICE_TYPE",
		"pm_req32_t" },
	{ (uint_t)PM_SET_COMPONENT_THRESHOLDS,	"PM_SET_COMPONENT_THRESHOLDS",
		"pm_req32_t" },
	{ (uint_t)PM_GET_COMPONENT_THRESHOLDS,	"PM_GET_COMPONENT_THRESHOLDS",
		"pm_req32_t" },
	{ (uint_t)PM_GET_DEVICE_THRESHOLD_BASIS,
		"PM_GET_DEVICE_THRESHOLD_BASIS",	"pm_req32_t" },
	{ (uint_t)PM_SET_CURRENT_POWER,		"PM_SET_CURRENT_POWER",
		"pm_req32_t" },
	{ (uint_t)PM_GET_CURRENT_POWER,		"PM_GET_CURRENT_POWER",
		"pm_req32_t" },
	{ (uint_t)PM_GET_FULL_POWER,		"PM_GET_FULL_POWER",
		"pm_req32_t" },
	{ (uint_t)PM_ADD_DEPENDENT,		"PM_ADD_DEPENDENT",
		"pm_req32_t" },
	{ (uint_t)PM_GET_TIME_IDLE,		"PM_GET_TIME_IDLE",
		"pm_req32_t" },
	{ (uint_t)PM_ADD_DEPENDENT_PROPERTY,	"PM_ADD_DEPENDENT_PROPERTY",
		"pm_req32_t" },
	{ (uint_t)PM_GET_CMD_NAME,		"PM_GET_CMD_NAME",
		"pm_req32_t" },
	{ (uint_t)PM_SEARCH_LIST,		"PM_SEARCH_LIST",
		"pm_searchargs32_t" },
#else  /* _SYSCALL32 */
	{ (uint_t)PM_GET_STATE_CHANGE,		"PM_GET_STATE_CHANGE",
		"pm_state_change_t" },
	{ (uint_t)PM_GET_STATE_CHANGE_WAIT,	"PM_GET_STATE_CHANGE_WAIT",
		"pm_state_change_t" },
	{ (uint_t)PM_DIRECT_NOTIFY,		"PM_DIRECT_NOTIFY",
		"pm_state_change_t" },
	{ (uint_t)PM_DIRECT_NOTIFY_WAIT,	"PM_DIRECT_NOTIFY_WAIT",
		"pm_state_change_t" },
	{ (uint_t)PM_REPARSE_PM_PROPS,		"PM_REPARSE_PM_PROPS",
		"pm_req_t" },
	{ (uint_t)PM_SET_DEVICE_THRESHOLD,	"PM_SET_DEVICE_THRESHOLD",
		"pm_req_t" },
	{ (uint_t)PM_GET_STATS,			"PM_GET_STATS",
		"pm_req_t" },
	{ (uint_t)PM_GET_DEVICE_THRESHOLD,	"PM_GET_DEVICE_THRESHOLD",
		"pm_req_t" },
	{ (uint_t)PM_GET_POWER_NAME,		"PM_GET_POWER_NAME",
		"pm_req_t" },
	{ (uint_t)PM_GET_POWER_LEVELS,		"PM_GET_POWER_LEVELS",
		"pm_req_t" },
	{ (uint_t)PM_GET_NUM_COMPONENTS,	"PM_GET_NUM_COMPONENTS",
		"pm_req_t" },
	{ (uint_t)PM_GET_COMPONENT_NAME,	"PM_GET_COMPONENT_NAME",
		"pm_req_t" },
	{ (uint_t)PM_GET_NUM_POWER_LEVELS,	"PM_GET_NUM_POWER_LEVELS",
		"pm_req_t" },
	{ (uint_t)PM_DIRECT_PM,			"PM_DIRECT_PM",
		"pm_req_t" },
	{ (uint_t)PM_RELEASE_DIRECT_PM,		"PM_RELEASE_DIRECT_PM",
		"pm_req_t" },
	{ (uint_t)PM_RESET_DEVICE_THRESHOLD,	"PM_RESET_DEVICE_THRESHOLD",
		"pm_req_t" },
	{ (uint_t)PM_GET_DEVICE_TYPE,		"PM_GET_DEVICE_TYPE",
		"pm_req_t" },
	{ (uint_t)PM_SET_COMPONENT_THRESHOLDS,	"PM_SET_COMPONENT_THRESHOLDS",
		"pm_req_t" },
	{ (uint_t)PM_GET_COMPONENT_THRESHOLDS,	"PM_GET_COMPONENT_THRESHOLDS",
		"pm_req_t" },
	{ (uint_t)PM_GET_DEVICE_THRESHOLD_BASIS,
		"PM_GET_DEVICE_THRESHOLD_BASIS",	"pm_req_t" },
	{ (uint_t)PM_SET_CURRENT_POWER,		"PM_SET_CURRENT_POWER",
		"pm_req_t" },
	{ (uint_t)PM_GET_CURRENT_POWER,		"PM_GET_CURRENT_POWER",
		"pm_req_t" },
	{ (uint_t)PM_GET_FULL_POWER,		"PM_GET_FULL_POWER",
		"pm_req_t" },
	{ (uint_t)PM_ADD_DEPENDENT,		"PM_ADD_DEPENDENT",
		"pm_req_t" },
	{ (uint_t)PM_GET_TIME_IDLE,		"PM_GET_TIME_IDLE",
		"pm_req_t" },
	{ (uint_t)PM_ADD_DEPENDENT_PROPERTY,	"PM_ADD_DEPENDENT_PROPERTY",
		"pm_req_t" },
	{ (uint_t)PM_GET_CMD_NAME,		"PM_GET_CMD_NAME",
		"pm_req_t" },
	{ (uint_t)PM_SEARCH_LIST,	"PM_SEARCH_LIST",
		"pm_searchargs_t" },
#endif /* _SYSCALL */

	{ (uint_t)0, NULL, NULL	}
};

void
ioctl_ioccom(char *buf, size_t size, uint_t code, int nbytes, int x, int y)
{
	const char *inoutstr;

	if (code & IOC_VOID)
		inoutstr = "";
	else if ((code & IOC_INOUT) == IOC_INOUT)
		inoutstr = "WR";
	else
		inoutstr = code & IOC_IN ? "W" : "R";

	if (isascii(x) && isprint(x))
		(void) snprintf(buf, size, "_IO%sN('%c', %d, %d)", inoutstr,
		    x, y, nbytes);
	else
		(void) snprintf(buf, size, "_IO%sN(0x%x, %d, %d)", inoutstr,
		    x, y, nbytes);
}


const char *
ioctlname(private_t *pri, uint_t code)
{
	const struct ioc *ip;
	const char *str = NULL;

	for (ip = &ioc[0]; ip->name; ip++) {
		if (code == ip->code) {
			str = ip->name;
			break;
		}
	}

	/*
	 * Developers hide ascii ioctl names in the ioctl subcode; for example
	 * 0x445210 should be printed 'D'<<16|'R'<<8|10.  We allow for all
	 * three high order bytes (called hi, mid and lo) to contain ascii
	 * characters.
	 */
	if (str == NULL) {
		int c_hi = code >> 24;
		int c_mid = (code >> 16) & 0xff;
		int c_mid_nm = (code >> 16);
		int c_lo = (code >> 8) & 0xff;
		int c_lo_nm = code >> 8;

		if (isascii(c_lo) && isprint(c_lo) &&
		    isascii(c_mid) && isprint(c_mid) &&
		    isascii(c_hi) && isprint(c_hi))
			(void) sprintf(pri->code_buf,
			    "(('%c'<<24)|('%c'<<16)|('%c'<<8)|%d)",
			    c_hi, c_mid, c_lo, code & 0xff);
		else if (isascii(c_lo) && isprint(c_lo) &&
		    isascii(c_mid_nm) && isprint(c_mid_nm))
			(void) sprintf(pri->code_buf,
			    "(('%c'<<16)|('%c'<<8)|%d)", c_mid, c_lo,
			    code & 0xff);
		else if (isascii(c_lo_nm) && isprint(c_lo_nm))
			(void) sprintf(pri->code_buf, "(('%c'<<8)|%d)",
			    c_lo_nm, code & 0xff);
		else if (code & (IOC_VOID|IOC_INOUT))
			ioctl_ioccom(pri->code_buf, sizeof (pri->code_buf),
			    code, c_mid, c_lo, code & 0xff);
		else
			(void) sprintf(pri->code_buf, "0x%.4X", code);
		str = (const char *)pri->code_buf;
	}

	return (str);
}


const char *
ioctldatastruct(uint_t code)
{
	const struct ioc *ip;
	const char *str = NULL;

	for (ip = &ioc[0]; ip->name != NULL; ip++) {
		if (code == ip->code) {
			str = ip->datastruct;
			break;
		}
	}
	return (str);
}


const char *
fcntlname(int code)
{
	const char *str = NULL;

	if (code >= FCNTLMIN && code <= FCNTLMAX)
		str = FCNTLname[code-FCNTLMIN];
	return (str);
}

const char *
sfsname(int code)
{
	const char *str = NULL;

	if (code >= SYSFSMIN && code <= SYSFSMAX)
		str = SYSFSname[code-SYSFSMIN];
	return (str);
}

/* ARGSUSED */
const char *
si86name(int code)
{
	const char *str = NULL;

#if defined(__i386) || defined(__amd64)
	switch (code) {
	case SI86SWPI:		str = "SI86SWPI";	break;
	case SI86SYM:		str = "SI86SYM";	break;
	case SI86CONF:		str = "SI86CONF";	break;
	case SI86BOOT:		str = "SI86BOOT";	break;
	case SI86AUTO:		str = "SI86AUTO";	break;
	case SI86EDT:		str = "SI86EDT";	break;
	case SI86SWAP:		str = "SI86SWAP";	break;
	case SI86FPHW:		str = "SI86FPHW";	break;
	case SI86FPSTART:	str = "SI86FPSTART";	break;
	case GRNON:		str = "GRNON";		break;
	case GRNFLASH:		str = "GRNFLASH";	break;
	case STIME:		str = "STIME";		break;
	case SETNAME:		str = "SETNAME";	break;
	case RNVR:		str = "RNVR";		break;
	case WNVR:		str = "WNVR";		break;
	case RTODC:		str = "RTODC";		break;
	case CHKSER:		str = "CHKSER";		break;
	case SI86NVPRT:		str = "SI86NVPRT";	break;
	case SANUPD:		str = "SANUPD";		break;
	case SI86KSTR:		str = "SI86KSTR";	break;
	case SI86MEM:		str = "SI86MEM";	break;
	case SI86TODEMON:	str = "SI86TODEMON";	break;
	case SI86CCDEMON:	str = "SI86CCDEMON";	break;
	case SI86CACHE:		str = "SI86CACHE";	break;
	case SI86DELMEM:	str = "SI86DELMEM";	break;
	case SI86ADDMEM:	str = "SI86ADDMEM";	break;
/* 71 through 74 reserved for VPIX */
	case SI86V86: 		str = "SI86V86";	break;
	case SI86SLTIME:	str = "SI86SLTIME";	break;
	case SI86DSCR:		str = "SI86DSCR";	break;
	case RDUBLK:		str = "RDUBLK";		break;
/* NFA entry point */
	case SI86NFA:		str = "SI86NFA";	break;
	case SI86VM86:		str = "SI86VM86";	break;
	case SI86VMENABLE:	str = "SI86VMENABLE";	break;
	case SI86LIMUSER:	str = "SI86LIMUSER";	break;
	case SI86RDID: 		str = "SI86RDID";	break;
	case SI86RDBOOT:	str = "SI86RDBOOT";	break;
/* Merged Product defines */
	case SI86SHFIL:		str = "SI86SHFIL";	break;
	case SI86PCHRGN:	str = "SI86PCHRGN";	break;
	case SI86BADVISE:	str = "SI86BADVISE";	break;
	case SI86SHRGN:		str = "SI86SHRGN";	break;
	case SI86CHIDT:		str = "SI86CHIDT";	break;
	case SI86EMULRDA: 	str = "SI86EMULRDA";	break;
/* RTC commands */
	case WTODC:		str = "WTODC";		break;
	case SGMTL:		str = "SGMTL";		break;
	case GGMTL:		str = "GGMTL";		break;
	case RTCSYNC:		str = "RTCSYNC";	break;
	}
#endif /* __i386 */

	return (str);
}

const char *
utscode(int code)
{
	const char *str = NULL;

	switch (code) {
	case UTS_UNAME:		str = "UNAME";	break;
	case UTS_USTAT:		str = "USTAT";	break;
	case UTS_FUSERS:	str = "FUSERS";	break;
	}

	return (str);
}

const char *
rctlsyscode(int code)
{
	const char *str = NULL;
	switch (code) {
	case 0:		str = "GETRCTL";	break;
	case 1:		str = "SETRCTL";	break;
	case 2:		str = "RCTLSYS_LST";	break;
	case 3:		str = "RCTLSYS_CTL";	break;
	case 4:		str = "RCTLSYS_SETPROJ";	break;
	default:	str = "UNKNOWN";	break;
	}
	return (str);
}

const char *
rctl_local_action(private_t *pri, uint_t val)
{
	uint_t action = val & (~RCTL_LOCAL_ACTION_MASK);

	char *s = pri->code_buf;

	*s = '\0';

	if (action & RCTL_LOCAL_NOACTION) {
		action ^= RCTL_LOCAL_NOACTION;
		(void) strlcat(s, "|RCTL_LOCAL_NOACTION",
		    sizeof (pri->code_buf));
	}
	if (action & RCTL_LOCAL_SIGNAL) {
		action ^= RCTL_LOCAL_SIGNAL;
		(void) strlcat(s, "|RCTL_LOCAL_SIGNAL",
		    sizeof (pri->code_buf));
	}
	if (action & RCTL_LOCAL_DENY) {
		action ^= RCTL_LOCAL_DENY;
		(void) strlcat(s, "|RCTL_LOCAL_DENY",
		    sizeof (pri->code_buf));
	}

	if ((action & (~RCTL_LOCAL_ACTION_MASK)) != 0)
		return (NULL);
	else if (*s != '\0')
		return (s+1);
	else
		return (NULL);
}


const char *
rctl_local_flags(private_t *pri, uint_t val)
{
	uint_t pval = val & RCTL_LOCAL_ACTION_MASK;
	char *s = pri->code_buf;

	*s = '\0';

	if (pval & RCTL_LOCAL_MAXIMAL) {
		pval ^= RCTL_LOCAL_MAXIMAL;
		(void) strlcat(s, "|RCTL_LOCAL_MAXIMAL",
		    sizeof (pri->code_buf));
	}

	if ((pval & RCTL_LOCAL_ACTION_MASK) != 0)
		return (NULL);
	else if (*s != '\0')
		return (s+1);
	else
		return (NULL);
}


const char *
sconfname(int code)
{
	const char *str = NULL;

	if (code >= SCONFMIN && code <= SCONFMAX)
		str = SCONFname[code-SCONFMIN];
	return (str);
}

const char *
pathconfname(int code)
{
	const char *str = NULL;

	if (code >= PATHCONFMIN && code <= PATHCONFMAX)
		str = PATHCONFname[code-PATHCONFMIN];
	return (str);
}

#define	ALL_O_FLAGS \
	(O_NDELAY|O_APPEND|O_SYNC|O_DSYNC|O_NONBLOCK|O_CREAT|O_TRUNC\
	|O_EXCL|O_NOCTTY|O_LARGEFILE|O_RSYNC|O_XATTR|O_NOFOLLOW|O_NOLINKS\
	|O_CLOEXEC|FXATTRDIROPEN)

const char *
openarg(private_t *pri, int arg)
{
	char *str = pri->code_buf;

	if ((arg & ~(O_ACCMODE | ALL_O_FLAGS)) != 0)
		return (NULL);

	switch (arg & O_ACCMODE) {
	default:
		return (NULL);
	case O_RDONLY:
		(void) strcpy(str, "O_RDONLY");
		break;
	case O_WRONLY:
		(void) strcpy(str, "O_WRONLY");
		break;
	case O_RDWR:
		(void) strcpy(str, "O_RDWR");
		break;
	case O_SEARCH:
		(void) strcpy(str, "O_SEARCH");
		break;
	case O_EXEC:
		(void) strcpy(str, "O_EXEC");
		break;
	}

	if (arg & O_NDELAY)
		(void) strlcat(str, "|O_NDELAY", sizeof (pri->code_buf));
	if (arg & O_APPEND)
		(void) strlcat(str, "|O_APPEND", sizeof (pri->code_buf));
	if (arg & O_SYNC)
		(void) strlcat(str, "|O_SYNC", sizeof (pri->code_buf));
	if (arg & O_DSYNC)
		(void) strlcat(str, "|O_DSYNC", sizeof (pri->code_buf));
	if (arg & O_NONBLOCK)
		(void) strlcat(str, "|O_NONBLOCK", sizeof (pri->code_buf));
	if (arg & O_CREAT)
		(void) strlcat(str, "|O_CREAT", sizeof (pri->code_buf));
	if (arg & O_TRUNC)
		(void) strlcat(str, "|O_TRUNC", sizeof (pri->code_buf));
	if (arg & O_EXCL)
		(void) strlcat(str, "|O_EXCL", sizeof (pri->code_buf));
	if (arg & O_NOCTTY)
		(void) strlcat(str, "|O_NOCTTY", sizeof (pri->code_buf));
	if (arg & O_LARGEFILE)
		(void) strlcat(str, "|O_LARGEFILE", sizeof (pri->code_buf));
	if (arg & O_RSYNC)
		(void) strlcat(str, "|O_RSYNC", sizeof (pri->code_buf));
	if (arg & O_XATTR)
		(void) strlcat(str, "|O_XATTR", sizeof (pri->code_buf));
	if (arg & O_NOFOLLOW)
		(void) strlcat(str, "|O_NOFOLLOW", sizeof (pri->code_buf));
	if (arg & O_NOLINKS)
		(void) strlcat(str, "|O_NOLINKS", sizeof (pri->code_buf));
	if (arg & O_CLOEXEC)
		(void) strlcat(str, "|O_CLOEXEC", sizeof (pri->code_buf));
	if (arg & FXATTRDIROPEN)
		(void) strlcat(str, "|FXATTRDIROPEN", sizeof (pri->code_buf));

	return ((const char *)str);
}

const char *
whencearg(int arg)
{
	const char *str = NULL;

	switch (arg) {
	case SEEK_SET:	str = "SEEK_SET";	break;
	case SEEK_CUR:	str = "SEEK_CUR";	break;
	case SEEK_END:	str = "SEEK_END";	break;
	case SEEK_DATA:	str = "SEEK_DATA";	break;
	case SEEK_HOLE:	str = "SEEK_HOLE";	break;
	}

	return (str);
}

#define	IPC_FLAGS	(IPC_ALLOC|IPC_CREAT|IPC_EXCL|IPC_NOWAIT)

char *
ipcflags(private_t *pri, int arg)
{
	char *str = pri->code_buf;

	if (arg & 0777)
		(void) sprintf(str, "0%.3o", arg&0777);
	else
		*str = '\0';

	if (arg & IPC_ALLOC)
		(void) strcat(str, "|IPC_ALLOC");
	if (arg & IPC_CREAT)
		(void) strcat(str, "|IPC_CREAT");
	if (arg & IPC_EXCL)
		(void) strcat(str, "|IPC_EXCL");
	if (arg & IPC_NOWAIT)
		(void) strcat(str, "|IPC_NOWAIT");

	return (str);
}

const char *
msgflags(private_t *pri, int arg)
{
	char *str;

	if (arg == 0 || (arg & ~(IPC_FLAGS|MSG_NOERROR|0777)) != 0)
		return ((char *)NULL);

	str = ipcflags(pri, arg);

	if (arg & MSG_NOERROR)
		(void) strcat(str, "|MSG_NOERROR");

	if (*str == '|')
		str++;
	return ((const char *)str);
}

const char *
semflags(private_t *pri, int arg)
{
	char *str;

	if (arg == 0 || (arg & ~(IPC_FLAGS|SEM_UNDO|0777)) != 0)
		return ((char *)NULL);

	str = ipcflags(pri, arg);

	if (arg & SEM_UNDO)
		(void) strcat(str, "|SEM_UNDO");

	if (*str == '|')
		str++;
	return ((const char *)str);
}

const char *
shmflags(private_t *pri, int arg)
{
	char *str;

	if (arg == 0 || (arg & ~(IPC_FLAGS|SHM_RDONLY|SHM_RND|0777)) != 0)
		return ((char *)NULL);

	str = ipcflags(pri, arg);

	if (arg & SHM_RDONLY)
		(void) strcat(str, "|SHM_RDONLY");
	if (arg & SHM_RND)
		(void) strcat(str, "|SHM_RND");

	if (*str == '|')
		str++;
	return ((const char *)str);
}

#define	MSGCMDMIN	0
#define	MSGCMDMAX	IPC_STAT64
const char *const MSGCMDname[MSGCMDMAX+1] = {
	NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL,
	"IPC_RMID",	/* 10 */
	"IPC_SET",	/* 11 */
	"IPC_STAT",	/* 12 */
	"IPC_SET64",	/* 13 */
	"IPC_STAT64",	/* 14 */
};

#define	SEMCMDMIN	0
#define	SEMCMDMAX	IPC_STAT64
const char *const SEMCMDname[SEMCMDMAX+1] = {
	NULL,		/* 0 */
	NULL,		/* 1 */
	NULL,		/* 2 */
	"GETNCNT",	/* 3 */
	"GETPID",	/* 4 */
	"GETVAL",	/* 5 */
	"GETALL",	/* 6 */
	"GETZCNT",	/* 7 */
	"SETVAL",	/* 8 */
	"SETALL",	/* 9 */
	"IPC_RMID",	/* 10 */
	"IPC_SET",	/* 11 */
	"IPC_STAT",	/* 12 */
	"IPC_SET64",	/* 13 */
	"IPC_STAT64",	/* 14 */
};

#define	SHMCMDMIN	0
#define	SHMCMDMAX	IPC_STAT64
const char *const SHMCMDname[SHMCMDMAX+1] = {
	NULL,		/* 0 */
	NULL,		/* 1 */
	NULL,		/* 2 */
	"SHM_LOCK",	/* 3 */
	"SHM_UNLOCK",	/* 4 */
	NULL, NULL, NULL, NULL, NULL,			/* 5 NULLs */
	"IPC_RMID",	/* 10 */
	"IPC_SET",	/* 11 */
	"IPC_STAT",	/* 12 */
	"IPC_SET64",	/* 13 */
	"IPC_STAT64",	/* 14 */
};

const char *
msgcmd(int arg)
{
	const char *str = NULL;

	if (arg >= MSGCMDMIN && arg <= MSGCMDMAX)
		str = MSGCMDname[arg-MSGCMDMIN];
	return (str);
}

const char *
semcmd(int arg)
{
	const char *str = NULL;

	if (arg >= SEMCMDMIN && arg <= SEMCMDMAX)
		str = SEMCMDname[arg-SEMCMDMIN];
	return (str);
}

const char *
shmcmd(int arg)
{
	const char *str = NULL;

	if (arg >= SHMCMDMIN && arg <= SHMCMDMAX)
		str = SHMCMDname[arg-SHMCMDMIN];
	return (str);
}

const char *
strrdopt(int arg)	/* streams read option (I_SRDOPT I_GRDOPT) */
{
	const char *str = NULL;

	switch (arg) {
	case RNORM:	str = "RNORM";		break;
	case RMSGD:	str = "RMSGD";		break;
	case RMSGN:	str = "RMSGN";		break;
	}

	return (str);
}

/* bit map of streams events (I_SETSIG & I_GETSIG) */
const char *
strevents(private_t *pri, int arg)
{
	char *str = pri->code_buf;

	if (arg & ~(S_INPUT|S_HIPRI|S_OUTPUT|S_MSG|S_ERROR|S_HANGUP))
		return ((char *)NULL);

	*str = '\0';
	if (arg & S_INPUT)
		(void) strcat(str, "|S_INPUT");
	if (arg & S_HIPRI)
		(void) strcat(str, "|S_HIPRI");
	if (arg & S_OUTPUT)
		(void) strcat(str, "|S_OUTPUT");
	if (arg & S_MSG)
		(void) strcat(str, "|S_MSG");
	if (arg & S_ERROR)
		(void) strcat(str, "|S_ERROR");
	if (arg & S_HANGUP)
		(void) strcat(str, "|S_HANGUP");

	return ((const char *)(str+1));
}

const char *
tiocflush(private_t *pri, int arg)	/* bit map passsed by TIOCFLUSH */
{
	char *str = pri->code_buf;

	if (arg & ~(FREAD|FWRITE))
		return ((char *)NULL);

	*str = '\0';
	if (arg & FREAD)
		(void) strcat(str, "|FREAD");
	if (arg & FWRITE)
		(void) strcat(str, "|FWRITE");

	return ((const char *)(str+1));
}

const char *
strflush(int arg)	/* streams flush option (I_FLUSH) */
{
	const char *str = NULL;

	switch (arg) {
	case FLUSHR:	str = "FLUSHR";		break;
	case FLUSHW:	str = "FLUSHW";		break;
	case FLUSHRW:	str = "FLUSHRW";	break;
	}

	return (str);
}

#define	ALL_MOUNT_FLAGS	(MS_RDONLY|MS_FSS|MS_DATA|MS_NOSUID|MS_REMOUNT| \
	MS_NOTRUNC|MS_OVERLAY|MS_OPTIONSTR|MS_GLOBAL|MS_FORCE|MS_NOMNTTAB)

const char *
mountflags(private_t *pri, int arg)	/* bit map of mount syscall flags */
{
	char *str = pri->code_buf;
	size_t used = 0;

	if (arg & ~ALL_MOUNT_FLAGS)
		return ((char *)NULL);

	*str = '\0';
	if (arg & MS_RDONLY)
		used = strlcat(str, "|MS_RDONLY", sizeof (pri->code_buf));
	if (arg & MS_FSS)
		used = strlcat(str, "|MS_FSS", sizeof (pri->code_buf));
	if (arg & MS_DATA)
		used = strlcat(str, "|MS_DATA", sizeof (pri->code_buf));
	if (arg & MS_NOSUID)
		used = strlcat(str, "|MS_NOSUID", sizeof (pri->code_buf));
	if (arg & MS_REMOUNT)
		used = strlcat(str, "|MS_REMOUNT", sizeof (pri->code_buf));
	if (arg & MS_NOTRUNC)
		used = strlcat(str, "|MS_NOTRUNC", sizeof (pri->code_buf));
	if (arg & MS_OVERLAY)
		used = strlcat(str, "|MS_OVERLAY", sizeof (pri->code_buf));
	if (arg & MS_OPTIONSTR)
		used = strlcat(str, "|MS_OPTIONSTR", sizeof (pri->code_buf));
	if (arg & MS_GLOBAL)
		used = strlcat(str, "|MS_GLOBAL", sizeof (pri->code_buf));
	if (arg & MS_FORCE)
		used = strlcat(str, "|MS_FORCE", sizeof (pri->code_buf));
	if (arg & MS_NOMNTTAB)
		used = strlcat(str, "|MS_NOMNTTAB", sizeof (pri->code_buf));

	if (used == 0 || used >= sizeof (pri->code_buf))
		return ((char *)NULL);			/* use prt_hex() */

	return ((const char *)(str+1));
}

const char *
svfsflags(private_t *pri, ulong_t arg)	/* bit map of statvfs syscall flags */
{
	char *str = pri->code_buf;

	if (arg & ~(ST_RDONLY|ST_NOSUID|ST_NOTRUNC)) {
		(void) sprintf(str, "0x%lx", arg);
		return (str);
	}
	*str = '\0';
	if (arg & ST_RDONLY)
		(void) strcat(str, "|ST_RDONLY");
	if (arg & ST_NOSUID)
		(void) strcat(str, "|ST_NOSUID");
	if (arg & ST_NOTRUNC)
		(void) strcat(str, "|ST_NOTRUNC");
	if (*str == '\0')
		(void) strcat(str, "|0");
	return ((const char *)(str+1));
}

const char *
fuiname(int arg)	/* fusers() input argument */
{
	const char *str = NULL;

	switch (arg) {
	case F_FILE_ONLY:	str = "F_FILE_ONLY";		break;
	case F_CONTAINED:	str = "F_CONTAINED";		break;
	}

	return (str);
}

const char *
fuflags(private_t *pri, int arg)	/* fusers() output flags */
{
	char *str = pri->code_buf;

	if (arg & ~(F_CDIR|F_RDIR|F_TEXT|F_MAP|F_OPEN|F_TRACE|F_TTY)) {
		(void) sprintf(str, "0x%x", arg);
		return (str);
	}
	*str = '\0';
	if (arg & F_CDIR)
		(void) strcat(str, "|F_CDIR");
	if (arg & F_RDIR)
		(void) strcat(str, "|F_RDIR");
	if (arg & F_TEXT)
		(void) strcat(str, "|F_TEXT");
	if (arg & F_MAP)
		(void) strcat(str, "|F_MAP");
	if (arg & F_OPEN)
		(void) strcat(str, "|F_OPEN");
	if (arg & F_TRACE)
		(void) strcat(str, "|F_TRACE");
	if (arg & F_TTY)
		(void) strcat(str, "|F_TTY");
	if (*str == '\0')
		(void) strcat(str, "|0");
	return ((const char *)(str+1));
}


const char *
ipprotos(int arg)	/* IP protocols cf. netinet/in.h */
{
	switch (arg) {
	case IPPROTO_IP:	return ("IPPROTO_IP");
	case IPPROTO_ICMP:	return ("IPPROTO_ICMP");
	case IPPROTO_IGMP:	return ("IPPROTO_IGMP");
	case IPPROTO_GGP:	return ("IPPROTO_GGP");
	case IPPROTO_ENCAP:	return ("IPPROTO_ENCAP");
	case IPPROTO_TCP:	return ("IPPROTO_TCP");
	case IPPROTO_EGP:	return ("IPPROTO_EGP");
	case IPPROTO_PUP:	return ("IPPROTO_PUP");
	case IPPROTO_UDP:	return ("IPPROTO_UDP");
	case IPPROTO_IDP:	return ("IPPROTO_IDP");
	case IPPROTO_IPV6:	return ("IPPROTO_IPV6");
	case IPPROTO_ROUTING:	return ("IPPROTO_ROUTING");
	case IPPROTO_FRAGMENT:	return ("IPPROTO_FRAGMENT");
	case IPPROTO_RSVP:	return ("IPPROTO_RSVP");
	case IPPROTO_ESP:	return ("IPPROTO_ESP");
	case IPPROTO_AH:	return ("IPPROTO_AH");
	case IPPROTO_ICMPV6:	return ("IPPROTO_ICMPV6");
	case IPPROTO_NONE:	return ("IPPROTO_NONE");
	case IPPROTO_DSTOPTS:	return ("IPPROTO_DSTOPTS");
	case IPPROTO_HELLO:	return ("IPPROTO_HELLO");
	case IPPROTO_ND:	return ("IPPROTO_ND");
	case IPPROTO_EON:	return ("IPPROTO_EON");
	case IPPROTO_PIM:	return ("IPPROTO_PIM");
	case IPPROTO_SCTP:	return ("IPPROTO_SCTP");
	case IPPROTO_RAW:	return ("IPPROTO_RAW");
	default:		return (NULL);
	}
}
