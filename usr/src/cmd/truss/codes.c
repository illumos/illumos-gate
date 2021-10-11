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
 * Copyright (c) 2011, 2017 by Delphix. All rights reserved.
 * Copyright 2011 Nexenta Systems, Inc. All rights reserved.
 * Copyright 2020 Joyent, Inc.
 * Copyright (c) 2014, OmniTI Computer Consulting, Inc. All rights reserved.
 * Copyright 2022 Garrett D'Amore <garrett@damore.org>
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/


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
#if defined(__x86)
#include <sys/sysi86.h>
#endif /* __x86 */
#include <sys/unistd.h>
#include <sys/file.h>
#include <sys/tiuser.h>
#include <sys/timod.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/termios.h>
#include <sys/termiox.h>
#include <sys/ioctl.h>
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
#include <sys/cpuid_drv.h>

#include "codes.h"
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

const struct ioc Tioc[] = { /* ('T'<<8) */
	{ (uint_t)TCGETA,	"TCGETA",	NULL },	/* 1 */
	{ (uint_t)TCSETA,	"TCSETA",	NULL },	/* 2 */
	{ (uint_t)TCSETAW,	"TCSETAW",	NULL },	/* 3 */
	{ (uint_t)TCSETAF,	"TCSETAF",	NULL },	/* 4 */
	{ (uint_t)TCSBRK,	"TCSBRK",	NULL },	/* 5 */
	{ (uint_t)TCXONC,	"TCXONC",	NULL },	/* 6 */
	{ (uint_t)TCFLSH,	"TCFLSH",	NULL },	/* 7 */
	{ (uint_t)TIOCKBON,	"TIOCKBON",	NULL },	/* 8 */
	{ (uint_t)TIOCKBOF,	"TIOCKBOF",	NULL },	/* 9 */
	{ (uint_t)KBENABLED,	"KBENABLED",	NULL },	/* 10 */

	{ (uint_t)TCGETS,	"TCGETS",	NULL }, /* 13 */
	{ (uint_t)TCSETS,	"TCSETS",	NULL }, /* 14 */
	{ (uint_t)TCSETSW,	"TCSETSW",	NULL }, /* 15 */
	{ (uint_t)TCSETSF,	"TCSETSF",	NULL }, /* 16 */

	{ (uint_t)TCDSET,	"TCDSET",	NULL }, /* 32 */
	{ (uint_t)RTS_TOG,	"RTS_TOG",	NULL }, /* 33 */

	{ (uint_t)TIOCSWINSZ,	"TIOCSWINSZ",	NULL }, /* 103 */
	{ (uint_t)TIOCGWINSZ,	"TIOCGWINSZ",	NULL }, /* 104 */

	{ (uint_t)TIOCGPPS,	"TIOCGPPS",	NULL }, /* 125 */
	{ (uint_t)TIOCSPPS,	"TIOCSPPS",	NULL }, /* 126 */
	{ (uint_t)TIOCGPPSEV,	"TIOCGPPSEV",	NULL }, /* 127 */
};

const struct ioc tioc[] = { /* ('t'<<8) */
	{ (uint_t)TIOCGETD,	"TIOCGETD",	NULL }, /* 0 */
	{ (uint_t)TIOCSETD,	"TIOCSETD",	NULL }, /* 1 */
	{ (uint_t)TIOCHPCL,	"TIOCHPCL",	NULL }, /* 2 */

	{ (uint_t)TIOCGETP,	"TIOCGETP",	NULL }, /* 8 */
	{ (uint_t)TIOCSETP,	"TIOCSETP",	NULL }, /* 9 */
	{ (uint_t)TIOCSETN,	"TIOCSETN",	NULL }, /* 10 */

	{ (uint_t)TIOCEXCL,	"TIOCEXCL",	NULL }, /* 13 */
	{ (uint_t)TIOCNXCL,	"TIOCNXCL",	NULL }, /* 14 */

	{ (uint_t)TIOCFLUSH,	"TIOCFLUSH",	NULL }, /* 16 */
	{ (uint_t)TIOCSETC,	"TIOCSETC",	NULL }, /* 17 */
	{ (uint_t)TIOCGETC,	"TIOCGETC",	NULL }, /* 18 */

	{ (uint_t)TIOCGPGRP,	"TIOCGPGRP",	NULL }, /* 20 */
	{ (uint_t)TIOCSPGRP,	"TIOCSPGRP",	NULL }, /* 21 */
	{ (uint_t)TIOCGSID,	"TIOCGSID",	NULL }, /* 22 */
	{ (uint_t)TIOCSTI,	"TIOCSTI",	NULL }, /* 23 */

	{ (uint_t)TIOCMSET,	"TIOCMSET",	NULL }, /* 26 */
	{ (uint_t)TIOCMBIS,	"TIOCMBIS",	NULL }, /* 27 */
	{ (uint_t)TIOCMBIC,	"TIOCMBIC",	NULL }, /* 28 */
	{ (uint_t)TIOCMGET,	"TIOCMGET",	NULL }, /* 29 */

	{ (uint_t)TIOCREMOTE,	"TIOCREMOTE",	NULL }, /* 30 */
	{ (uint_t)TIOCSIGNAL,	"TIOCSIGNAL",	NULL }, /* 31 */

	{ (uint_t)TIOCCILOOP,	"TIOCSILOOP",	NULL }, /* 108 */
	{ (uint_t)TIOCSILOOP,	"TIOCSILOOP",	NULL }, /* 109 */
	{ (uint_t)TIOCSTART,	"TIOCSTART",	NULL }, /* 110 */
	{ (uint_t)TIOCSTOP,	"TIOCSTOP",	NULL }, /* 111 */

	{ (uint_t)TIOCNOTTY,	"TIOCNOTTY",	NULL }, /* 113 */
	{ (uint_t)TIOCOUTQ,	"TIOCOUTQ",	NULL }, /* 115 */
	{ (uint_t)TIOCGLTC,	"TIOCGLTC",	NULL }, /* 116 */
	{ (uint_t)TIOCSLTC,	"TIOCSLTC",	NULL }, /* 117 */

	{ (uint_t)TIOCCDTR,	"TIOCCDTR",	NULL }, /* 120 */
	{ (uint_t)TIOCSDTR,	"TIOCSDTR",	NULL }, /* 121 */
	{ (uint_t)TIOCCBRK,	"TIOCCBRK",	NULL }, /* 122 */
	{ (uint_t)TIOCSBRK,	"TIOCSBRK",	NULL }, /* 123 */
	{ (uint_t)TIOCLGET,	"TIOCLGET",	NULL }, /* 124 */
	{ (uint_t)TIOCLSET,	"TIOCLSET",	NULL }, /* 125 */
	{ (uint_t)TIOCLBIC,	"TIOCLBIC",	NULL }, /* 126 */
	{ (uint_t)TIOCLBIS,	"TIOCLBIS",	NULL }, /* 127 */

	{ (uint_t)TIOCSCTTY,	"TIOCSCTTY",	NULL }, /* 132 */
};

const struct ioc pty_ioc[] = { /* ('t'<<8) */
	{ (uint_t)TIOCPKT,	"TIOCPKT",	NULL },	/* ptyvar.h */
	{ (uint_t)TIOCUCNTL,	"TIOCUCNTL",	NULL },
	{ (uint_t)TIOCTCNTL,	"TIOCTCNTL",	NULL },
	{ (uint_t)TIOCISPACE,	"TIOCISPACE",	NULL },
	{ (uint_t)TIOCISIZE,	"TIOCISIZE",	NULL },
	{ (uint_t)TIOCSSIZE,	"TIOCSSIZE",	"ttysize" },
	{ (uint_t)TIOCGSIZE,	"TIOCGSIZE",	"ttysize" }
};

const struct ioc dlpi_ioc[] = { /* ('D'<<8) */
	/*
	 * Unfortunately, the DLIOC and LDIOC codes overlap.  Since the LDIOC
	 * ioctls (for xenix compatibility) are far less likely to be used, we
	 * give preference to DLIOC.
	 */
	{ (uint_t)DLIOCRAW,	"DLIOCRAW",	NULL }, /* 1 */
	{ (uint_t)DLIOCNATIVE,	"DLIOCNATIVE",	NULL }, /* 2 */
	{ (uint_t)DLIOCMARGININFO,	"DLIOCMARGININFO",	NULL }, /* 3 */
	{ (uint_t)DLIOCIPNETINFO, "DLIOCIPNETINFO", NULL}, /* 4 */
	{ (uint_t)DLIOCLOWLINK,	"DLIOCLOWLINK",	NULL }, /* 5 */
	{ (uint_t)DLIOCHDRINFO,	"DLIOCHDRINFO",	NULL }, /* 10 */
};

const struct ioc ldioc_ioc[] = { /* ('D'<<8) */
	{ (uint_t)LDOPEN,	"LDOPEN",	NULL }, /* 0 */
	{ (uint_t)LDCLOSE,	"LDCLOSE",	NULL }, /* 1 */
	{ (uint_t)LDCHG,	"LDCHG",	NULL }, /* 2 */
	{ (uint_t)LDGETT,	"LDGETT",	NULL }, /* 8 */
	{ (uint_t)LDSETT,	"LDSETT",	NULL }, /* 9 */
	{ (uint_t)LDSMAP,	"LDSMAP",	NULL }, /* 110 */
	{ (uint_t)LDGMAP,	"LDGMAP",	NULL }, /* 111 */
	{ (uint_t)LDNMAP,	"LDNMAP",	NULL }, /* 112 */
	{ (uint_t)LDEMAP,	"LDEMAP",	NULL }, /* 113 */
	{ (uint_t)LDDMAP,	"LDDMAP",	NULL }, /* 114 */
};

const struct ioc xioc_ioc[] = { /* ('X'<<8) */
	{ (uint_t)TCGETX,	"TCGETX",	NULL }, /* 1 */
	{ (uint_t)TCSETX,	"TCSETX",	NULL }, /* 2 */
	{ (uint_t)TCSETXW,	"TCSETXW",	NULL }, /* 3 */
	{ (uint_t)TCSETXF,	"TCSETXF",	NULL }, /* 4 */
};

const struct ioc fio_ioc[] = { /* ('f'<<8) */
	{ (uint_t)FIORDCHK,	"FIORDCHK",	NULL }, /* 3 */
};


const struct ioc fil_ioc[] = {
	{ (uint_t)FIOCLEX,	"FIOCLEX",	NULL }, /* 1 */
	{ (uint_t)FIONCLEX,	"FIONCLEX",	NULL }, /* 2 */

	{ (uint_t)FIOGETOWN,	"FIOGETOWN",	NULL }, /* 123 */
	{ (uint_t)FIOSETOWN,	"FIOSETOWN",	NULL }, /* 124 */
	{ (uint_t)FIOASYNC,	"FIOASYNC",	NULL }, /* 125 */
	{ (uint_t)FIONBIO,	"FIONBIO",	NULL }, /* 126 */
	{ (uint_t)FIONREAD,	"FIONREAD",	NULL }, /* 127 */
};

const struct ioc dioc_ioc[] = { /* ('d'<<8) */
	{ (uint_t)DIOCGETC,	"DIOCGETC",	NULL }, /* 1 */
	{ (uint_t)DIOCGETB,	"DIOCGETB",	NULL }, /* 2 */
	{ (uint_t)DIOCSETE,	"DIOCSETE",	NULL }, /* 3 */
	{ (uint_t)DIOCGETP,	"DIOCGETP",	NULL }, /* 8 */
	{ (uint_t)DIOCSETP,	"DIOCSETP",	NULL }, /* 9 */
};

const struct ioc lioc_ioc[] = { /* ('l'<<8) */
	{ (uint_t)LIOCGETP,	"LIOCGETP",	NULL }, /* 1 */
	{ (uint_t)LIOCSETP,	"LIOCSETP",	NULL }, /* 2 */
	{ (uint_t)LIOCGETS,	"LIOCGETS",	NULL }, /* 5 */
	{ (uint_t)LIOCSETS,	"LIOCSETS",	NULL }, /* 6 */
};

const struct ioc jerq_ioc[] = { /* ('j'<<8) */
	{ (uint_t)JBOOT,	"JBOOT",	NULL }, /* 1 */
	{ (uint_t)JTERM,	"JTERM",	NULL }, /* 2 */
	{ (uint_t)JMPX,		"JMPX",	NULL }, /* 3 */
	{ (uint_t)JWINSIZE,	"JWINSIZE",	NULL }, /* 5 */
	{ (uint_t)JTIMOM,	"JTIMOM",	NULL }, /* 6 */
	{ (uint_t)JZOMBOOT,	"JZOMBOOT",	NULL }, /* 7 */
	{ (uint_t)JAGENT,	"JAGENT",	NULL }, /* 9 */
	{ (uint_t)JTRUN,	"JTRUN",	NULL }, /* 10 */
	{ (uint_t)JXTPROTO,	"JXTPROTO",	NULL }, /* 11 */
};

const struct ioc kstat_ioc[] = { /* ('K'<<8) */
	{ (uint_t)KSTAT_IOC_CHAIN_ID,	"KSTAT_IOC_CHAIN_ID",	NULL },
	{ (uint_t)KSTAT_IOC_READ,	"KSTAT_IOC_READ",	NULL },
	{ (uint_t)KSTAT_IOC_WRITE,	"KSTAT_IOC_WRITE",	NULL },
};

const struct ioc stream_ioc[] = { /* ('X'<<8) */
	{ (uint_t)STGET,	"STGET",	NULL }, /* 0 */
	{ (uint_t)STSET,	"STSET",	NULL }, /* 1 */
	{ (uint_t)STTHROW,	"STTHROW",	NULL }, /* 2 */
	{ (uint_t)STWLINE,	"STWLINE",	NULL }, /* 3 */
	{ (uint_t)STTSV,	"STTSV",	NULL }, /* 4 */
};

const struct ioc str_ioc[] = { /* ('S'<<8) */
	{ (uint_t)I_NREAD,	"I_NREAD",	NULL }, /* 1 */
	{ (uint_t)I_PUSH,	"I_PUSH",	NULL }, /* 2 */
	{ (uint_t)I_POP,	"I_POP",	NULL }, /* 3 */
	{ (uint_t)I_LOOK,	"I_LOOK",	NULL }, /* 4 */
	{ (uint_t)I_FLUSH,	"I_FLUSH",	NULL }, /* 5 */
	{ (uint_t)I_SRDOPT,	"I_SRDOPT",	NULL }, /* 6 */
	{ (uint_t)I_GRDOPT,	"I_GRDOPT",	NULL }, /* 7 */
	{ (uint_t)I_STR,	"I_STR",	NULL }, /* 10 */
	{ (uint_t)I_SETSIG,	"I_SETSIG",	NULL }, /* 11 */
	{ (uint_t)I_GETSIG,	"I_GETSIG",	NULL }, /* 12 */
	{ (uint_t)I_FIND,	"I_FIND",	NULL }, /* 13 */
	{ (uint_t)I_LINK,	"I_LINK",	NULL }, /* 14 */
	{ (uint_t)I_UNLINK,	"I_UNLINK",	NULL }, /* 15 */
	{ (uint_t)I_PEEK,	"I_PEEK",	NULL }, /* 17 */
	{ (uint_t)I_FDINSERT,	"I_FDINSERT",	NULL }, /* 20 */
	{ (uint_t)I_SENDFD,	"I_SENDFD",	NULL }, /* 21 */
	{ (uint_t)I_RECVFD,	"I_RECVFD",	NULL }, /* 16 */
	{ (uint_t)I_SWROPT,	"I_SWROPT",	NULL }, /* 23 */
	{ (uint_t)I_GWROPT,	"I_GWROPT",	NULL }, /* 24 */
	{ (uint_t)I_LIST,	"I_LIST",	NULL }, /* 25 */
	{ (uint_t)I_PLINK,	"I_PLINK",	NULL }, /* 26 */
	{ (uint_t)I_PUNLINK,	"I_PUNLINK",	NULL }, /* 27 */
	{ (uint_t)I_ANCHOR,	"I_ANCHOR",	NULL }, /* 30 */
	{ (uint_t)I_FLUSHBAND,	"I_FLUSHBAND",	NULL }, /* 34 */
	{ (uint_t)I_CKBAND,	"I_CKBAND",	NULL }, /* 35 */
	{ (uint_t)I_GETBAND,	"I_GETBAND",	NULL }, /* 36 */
	{ (uint_t)I_ATMARK,	"I_ATMARK",	NULL }, /* 37 */
	{ (uint_t)I_SETCLTIME,	"I_SETCLTIME",	NULL }, /* 40 */
	{ (uint_t)I_GETCLTIME,	"I_GETCLTIME",	NULL }, /* 41 */
	{ (uint_t)I_CANPUT,	"I_CANPUT",	NULL }, /* 42 */
	{ (uint_t)I_SERROPT,	"I_SERROPT",	NULL }, /* 43 */
	{ (uint_t)I_GERROPT,	"I_GERROPT",	NULL }, /* 44 */
	{ (uint_t)I_ESETSIG,	"I_ESETSIG",	NULL }, /* 45 */
	{ (uint_t)I_EGETSIG,	"I_EGETSIG",	NULL }, /* 46 */
	{ (uint_t)_I_CMD,	"_I_CMD",	NULL }, /* 63 */
};

const struct ioc timod_ioc[] = {	/* ('T'<<8) */
	{ (uint_t)TI_GETINFO,	"TI_GETINFO",	NULL }, /* 140 */
	{ (uint_t)TI_OPTMGMT,	"TI_OPTMGMT",	NULL }, /* 141 */
	{ (uint_t)TI_BIND,	"TI_BIND",	NULL }, /* 142 */
	{ (uint_t)TI_UNBIND,	"TI_UNBIND",	NULL }, /* 143 */
	{ (uint_t)TI_GETMYNAME, "TI_GETMYNAME",	 NULL }, /* 144 */
	{ (uint_t)TI_GETPEERNAME, "TI_GETPEERNAME", NULL }, /* 145 */
	{ (uint_t)TI_SETMYNAME, "TI_SETMYNAME",	 NULL }, /* 146 */
	{ (uint_t)TI_SETPEERNAME, "TI_SETPEERNAME", NULL }, /* 147 */
	{ (uint_t)TI_SYNC,	"TI_SYNC",	NULL }, /* 148 */
	{ (uint_t)TI_GETADDRS,	"TI_GETADDRS",	NULL }, /* 149 */
	{ (uint_t)TI_CAPABILITY, "TI_CAPABILITY", NULL }, /* 150 */
};

const struct ioc audio_ioc[] = { /* ('A'<<8) */
	{ (uint_t)AUDIO_GETINFO,	"AUDIO_GETINFO",	NULL }, /* 1 */
	{ (uint_t)AUDIO_SETINFO,	"AUDIO_SETINFO",	NULL }, /* 2 */
	{ (uint_t)AUDIO_DRAIN,		"AUDIO_DRAIN",		NULL }, /* 3 */
	{ (uint_t)AUDIO_GETDEV,		"AUDIO_GETDEV",		NULL }, /* 4 */
	{ (uint_t)AUDIO_DIAG_LOOPBACK, "AUDIO_DIAG_LOOPBACK", NULL }, /* 101 */
	{ (uint_t)AUDIO_GET_CH_NUMBER,	"AUDIO_GET_CH_NUMBER",	NULL }, /* 10 */
	{ (uint_t)AUDIO_GET_CH_TYPE,	"AUDIO_GET_CH_TYPE",	NULL }, /* 11 */
	{ (uint_t)AUDIO_GET_NUM_CHS,	"AUDIO_GET_NUM_CHS",	NULL }, /* 12 */
	{ (uint_t)AUDIO_GET_AD_DEV,	"AUDIO_GET_AD_DEV",	NULL }, /* 13 */
	{ (uint_t)AUDIO_GET_APM_DEV,	"AUDIO_GET_APM_DEV",	NULL }, /* 14 */
	{ (uint_t)AUDIO_GET_AS_DEV,	"AUDIO_GET_AS_DEV",	NULL }, /* 15 */
};

const struct ioc audiom_ioc[] = { /* ('M'<<8) */
	{ (uint_t)AUDIO_MIXER_MULTIPLE_OPEN,	"AUDIO_MIXER_MULTIPLE_OPEN",
	    NULL }, /* 10 */
	{ (uint_t)AUDIO_MIXER_SINGLE_OPEN,	"AUDIO_MIXER_SINGLE_OPEN",
	    NULL }, /* 11 */
	{ (uint_t)AUDIO_MIXER_GET_SAMPLE_RATES,	"AUDIO_MIXER_GET_SAMPLE_RATES",
	    NULL }, /* 12 */
	{ (uint_t)AUDIO_MIXERCTL_GETINFO,	"AUDIO_MIXERCTL_GETINFO",
	    NULL }, /* 13 */
	{ (uint_t)AUDIO_MIXERCTL_SETINFO,	"AUDIO_MIXERCTL_SETINFO",
	    NULL }, /* 14 */
	{ (uint_t)AUDIO_MIXERCTL_GET_CHINFO,	"AUDIO_MIXERCTL_GET_CHINFO",
	    NULL }, /* 15 */
	{ (uint_t)AUDIO_MIXERCTL_SET_CHINFO,	"AUDIO_MIXERCTL_SET_CHINFO",
	    NULL }, /* 16 */
	{ (uint_t)AUDIO_MIXERCTL_GET_MODE,	"AUDIO_MIXERCTL_GET_MODE",
	    NULL }, /* 17 */
	{ (uint_t)AUDIO_MIXERCTL_SET_MODE,	"AUDIO_MIXERCTL_SET_MODE",
	    NULL }, /* 18 */
};

const struct ioc ossx_ioc[] = { /* ('X'<<8) */
	/* new style Boomer (OSS) ioctls */
	{ (uint_t)SNDCTL_SYSINFO,	"SNDCTL_SYSINFO",	NULL }, /* 1 */
	{ (uint_t)SNDCTL_MIX_NRMIX,	"SNDCTL_MIX_NRMIX",	NULL }, /* 2 */
	{ (uint_t)SNDCTL_MIX_NREXT,	"SNDCTL_MIX_NREXT",	NULL }, /* 3 */
	{ (uint_t)SNDCTL_MIX_EXTINFO,	"SNDCTL_MIX_EXTINFO",	NULL }, /* 4 */
	{ (uint_t)SNDCTL_MIX_READ,	"SNDCTL_MIX_READ",	NULL }, /* 5 */
	{ (uint_t)SNDCTL_MIX_WRITE,	"SNDCTL_MIX_WRITE",	NULL }, /* 6 */
	{ (uint_t)SNDCTL_AUDIOINFO,	"SNDCTL_AUDIOINFO",	NULL }, /* 7 */
	{ (uint_t)SNDCTL_MIX_ENUMINFO,	"SNDCTL_MIX_ENUMINFO",	NULL }, /* 8 */
	{ (uint_t)SNDCTL_MIDIINFO,	"SNDCTL_MIDIINFO",	NULL }, /* 9 */
	{ (uint_t)SNDCTL_MIXERINFO,	"SNDCTL_MIXERINFO",	NULL }, /* 10 */
	{ (uint_t)SNDCTL_CARDINFO,	"SNDCTL_CARDINFO",	NULL }, /* 11 */
	{ (uint_t)SNDCTL_ENGINEINFO,	"SNDCTL_ENGINEINFO",	NULL }, /* 12 */
	{ (uint_t)SNDCTL_AUDIOINFO_EX,	"SNDCTL_AUDIOINFO_EX",	NULL }, /* 13 */
	{ (uint_t)SNDCTL_MIX_DESCRIPTION,	"SNDCTL_MIX_DESCRIPTION",
	    NULL }, /* 14 */
};

const struct ioc ossy_ioc[] = { /* ('Y'<<8) */
	{ (uint_t)SNDCTL_SETSONG,	"SNDCTL_SETSONG",	NULL }, /* 2 */
	{ (uint_t)SNDCTL_GETSONG,	"SNDCTL_GETSONG",	NULL }, /* 2 */
	{ (uint_t)SNDCTL_SETNAME,	"SNDCTL_SETNAME",	NULL }, /* 3 */
	{ (uint_t)SNDCTL_SETLABEL,	"SNDCTL_SETLABEL",	NULL }, /* 4 */
	{ (uint_t)SNDCTL_GETLABEL,	"SNDCTL_GETLABEL",	NULL }, /* 4 */
};

const struct ioc ossp_ioc[] = { /* ('P'<<8) */
	{ (uint_t)SNDCTL_DSP_HALT,	"SNDCTL_DSP_HALT",	NULL }, /* 0 */
	{ (uint_t)SNDCTL_DSP_SYNC,	"SNDCTL_DSP_SYNC",	NULL }, /* 1 */
	{ (uint_t)SNDCTL_DSP_SPEED,	"SNDCTL_DSP_SPEED",	NULL }, /* 2 */
	{ (uint_t)SNDCTL_DSP_STEREO,	"SNDCTL_DSP_STEREO",	NULL }, /* 3 */
	{ (uint_t)SNDCTL_DSP_GETBLKSIZE,	"SNDCTL_DSP_GETBLKSIZE",
	    NULL }, /* 4 */
	{ (uint_t)SNDCTL_DSP_SAMPLESIZE,	"SNDCTL_DSP_SAMPLESIZE",
	    NULL }, /* 5 */
	{ (uint_t)SNDCTL_DSP_CHANNELS,	"SNDCTL_DSP_CHANNELS",  NULL }, /* 6 */
	{ (uint_t)SNDCTL_DSP_POST,	"SNDCTL_DSP_POST",	NULL }, /* 8 */
	{ (uint_t)SNDCTL_DSP_SUBDIVIDE,	"SNDCTL_DSP_SUBDIVIDE",	NULL }, /* 9 */
	{ (uint_t)SNDCTL_DSP_SETFRAGMENT,	"SNDCTL_DSP_SETFRAGMENT",
	    NULL }, /* 10 */
	{ (uint_t)SNDCTL_DSP_GETFMTS,	"SNDCTL_DSP_GETFMTS",	NULL }, /* 11 */
	{ (uint_t)SNDCTL_DSP_SETFMT,	"SNDCTL_DSP_SETFMT",	NULL }, /* 5 */
	{ (uint_t)SNDCTL_DSP_GETOSPACE,	"SNDCTL_DSP_GETOSPACE",	NULL }, /* 12 */
	{ (uint_t)SNDCTL_DSP_GETISPACE,	"SNDCTL_DSP_GETISPACE",	NULL }, /* 13 */
	{ (uint_t)SNDCTL_DSP_GETCAPS,	"SNDCTL_DSP_CAPS",	NULL }, /* 15 */
	{ (uint_t)SNDCTL_DSP_GETTRIGGER,	"SNDCTL_DSP_GETTRIGGER",
	    NULL }, /* 16 */
	{ (uint_t)SNDCTL_DSP_SETTRIGGER,	"SNDCTL_DSP_SETTRIGGER",
	    NULL }, /* 16 */
	{ (uint_t)SNDCTL_DSP_GETIPTR,	"SNDCTL_DSP_GETIPTR",	NULL }, /* 17 */
	{ (uint_t)SNDCTL_DSP_GETOPTR,	"SNDCTL_DSP_GETOPTR",	NULL }, /* 18 */
	{ (uint_t)SNDCTL_DSP_SETSYNCRO,	"SNDCTL_DSP_SETSYNCRO",	NULL }, /* 21 */
	{ (uint_t)SNDCTL_DSP_SETDUPLEX,	"SNDCTL_DSP_SETDUPLEX",	NULL }, /* 22 */
	{ (uint_t)SNDCTL_DSP_PROFILE,	"SNDCTL_DSP_PROFILE",	NULL }, /* 23 */
	{ (uint_t)SNDCTL_DSP_GETODELAY,	"SNDCTL_DSP_GETODELAY",	NULL }, /* 23 */
	{ (uint_t)SNDCTL_DSP_GETPLAYVOL,	"SNDCTL_DSP_GETPLAYVOL",
	    NULL }, /* 24 */
	{ (uint_t)SNDCTL_DSP_SETPLAYVOL,	"SNDCTL_DSP_SETPLAYVOL",
	    NULL }, /* 24 */
	{ (uint_t)SNDCTL_DSP_GETERROR,	"SNDCTL_DSP_GETERROR",	NULL }, /* 25 */
	{ (uint_t)SNDCTL_DSP_READCTL,	"SNDCTL_DSP_READCTL",	NULL }, /* 26 */
	{ (uint_t)SNDCTL_DSP_WRITECTL,	"SNDCTL_DSP_WRITECTL",	NULL }, /* 27 */
	{ (uint_t)SNDCTL_DSP_SYNCGROUP,	"SNDCTL_DSP_SYNCGROUP",	NULL }, /* 28 */
	{ (uint_t)SNDCTL_DSP_SYNCSTART,	"SNDCTL_DSP_SYNCSTART",	NULL }, /* 29 */
	{ (uint_t)SNDCTL_DSP_COOKEDMODE,	"SNDCTL_DSP_COOKEDMODE",
	    NULL }, /* 30 */
	{ (uint_t)SNDCTL_DSP_SILENCE,	"SNDCTL_DSP_SILENCE",	NULL }, /* 31 */
	{ (uint_t)SNDCTL_DSP_SKIP,	"SNDCTL_DSP_SKIP",	NULL }, /* 32 */
	{ (uint_t)SNDCTL_DSP_HALT_INPUT,	"SNDCTL_DSP_HALT_INPUT",
	    NULL }, /* 33 */
	{ (uint_t)SNDCTL_DSP_HALT_OUTPUT,	"SNDCTL_DSP_HALT_OUTPUT",
	    NULL }, /* 34 */
	{ (uint_t)SNDCTL_DSP_LOW_WATER,	"SNDCTL_DSP_LOW_WATER",	NULL }, /* 34 */
	{ (uint_t)SNDCTL_DSP_CURRENT_IPTR,	"SNDCTL_DSP_CURRENT_IPTR",
	    NULL }, /* 35 */
	{ (uint_t)SNDCTL_DSP_CURRENT_OPTR,	"SNDCTL_DSP_CURRENT_OPTR",
	    NULL }, /* 36 */
	{ (uint_t)SNDCTL_DSP_GET_RECSRC_NAMES,	"SNDCTL_DSP_GET_RECSRC_NAMES",
	    NULL }, /* 37 */
	{ (uint_t)SNDCTL_DSP_GET_RECSRC,	"SNDCTL_DSP_GET_RECSRC",
	    NULL }, /* 38 */
	{ (uint_t)SNDCTL_DSP_SET_RECSRC,	"SNDCTL_DSP_SET_RECSRC",
	    NULL }, /* 38 */
	{ (uint_t)SNDCTL_DSP_GET_PLAYTGT_NAMES,	"SNDCTL_DSP_GET_PLAYTGT_NAMES",
	    NULL }, /* 39 */
	{ (uint_t)SNDCTL_DSP_GET_PLAYTGT,	"SNDCTL_DSP_GET_PLAYTGT",
	    NULL }, /* 40 */
	{ (uint_t)SNDCTL_DSP_SET_PLAYTGT,	"SNDCTL_DSP_SET_PLAYTGT",
	    NULL }, /* 40 */
	{ (uint_t)SNDCTL_DSP_GETRECVOL,		"SNDCTL_DSP_GETRECVOL",
	    NULL }, /* 41 */
	{ (uint_t)SNDCTL_DSP_SETRECVOL,		"SNDCTL_DSP_SETRECVOL",
	    NULL }, /* 41 */
	{ (uint_t)SNDCTL_DSP_GET_CHNORDER,	"SNDCTL_DSP_GET_CHNORDER",
	    NULL }, /* 42 */
	{ (uint_t)SNDCTL_DSP_SET_CHNORDER,	"SNDCTL_DSP_SET_CHNORDER",
	    NULL }, /* 42 */
	{ (uint_t)SNDCTL_DSP_GETIPEAKS,	"SNDCTL_DSP_GETIPEAKS",	NULL }, /* 43 */
	{ (uint_t)SNDCTL_DSP_GETOPEAKS,	"SNDCTL_DSP_GETOPEAKS",	NULL }, /* 44 */
	{ (uint_t)SNDCTL_DSP_POLICY,	"SNDCTL_DSP_POLICY",	NULL }, /* 45 */
	{ (uint_t)SNDCTL_DSP_GETCHANNELMASK,	"SNDCTL_DSP_GETCHANNELMASK",
	    NULL }, /* 64 */
	{ (uint_t)SNDCTL_DSP_BIND_CHANNEL,	"SNDCTL_DSP_BIND_CHANNEL",
	    NULL }, /* 65 */
};

const struct ioc ossm_ioc[] = { /* ('M'<<8) */
	{ (uint_t)SOUND_MIXER_READ_VOLUME,	"SOUND_MIXER_READ_VOLUME",
	    NULL }, /* 0 */
	{ (uint_t)SOUND_MIXER_READ_OGAIN,	"SOUND_MIXER_READ_OGAIN",
	    NULL }, /* 13 */
	{ (uint_t)SOUND_MIXER_READ_PCM,	"SOUND_MIXER_READ_PCM",	NULL }, /* 4 */
	{ (uint_t)SOUND_MIXER_READ_IGAIN,	"SOUND_MIXER_READ_IGAIN",
	    NULL }, /* 12 */
	{ (uint_t)SOUND_MIXER_READ_RECLEV,	"SOUND_MIXER_READ_RECLEV",
	    NULL }, /* 11 */
	{ (uint_t)SOUND_MIXER_READ_RECSRC,	"SOUND_MIXER_READ_RECSRC",
	    NULL }, /* 0xff */
	{ (uint_t)SOUND_MIXER_READ_DEVMASK,	"SOUND_MIXER_READ_DEVMASK",
	    NULL }, /* 0xfe */
	{ (uint_t)SOUND_MIXER_READ_RECMASK,	"SOUND_MIXER_READ_RECMASK",
	    NULL }, /* 0xfd */
	{ (uint_t)SOUND_MIXER_READ_CAPS,	"SOUND_MIXER_READ_CAPS",
	    NULL }, /* 0xfc */
	{ (uint_t)SOUND_MIXER_READ_STEREODEVS,	"SOUND_MIXER_READ_STEREODEVS",
	    NULL }, /* 0xfb */
	{ (uint_t)SOUND_MIXER_READ_RECGAIN,	"SOUND_MIXER_READ_RECGAIN",
	    NULL }, /* 119 */
	{ (uint_t)SOUND_MIXER_READ_MONGAIN,	"SOUND_MIXER_READ_MONGAIN",
	    NULL }, /* 120 */
	{ (uint_t)SOUND_MIXER_WRITE_VOLUME,	"SOUND_MIXER_WRITE_VOLUME",
	    NULL }, /* 0 */
	{ (uint_t)SOUND_MIXER_WRITE_OGAIN,	"SOUND_MIXER_WRITE_OGAIN",
	    NULL }, /* 13 */
	{ (uint_t)SOUND_MIXER_WRITE_PCM,	"SOUND_MIXER_WRITE_PCM",
	    NULL }, /* 4 */
	{ (uint_t)SOUND_MIXER_WRITE_IGAIN,	"SOUND_MIXER_WRITE_IGAIN",
	    NULL }, /* 12 */
	{ (uint_t)SOUND_MIXER_WRITE_RECLEV,	"SOUND_MIXER_WRITE_RECLEV",
	    NULL }, /* 11 */
	{ (uint_t)SOUND_MIXER_WRITE_RECSRC,	"SOUND_MIXER_WRITE_RECSRC",
	    NULL }, /* 0xff */
	{ (uint_t)SOUND_MIXER_WRITE_RECGAIN,	"SOUND_MIXER_WRITE_RECGAIN",
	    NULL }, /* 119 */
	{ (uint_t)SOUND_MIXER_WRITE_MONGAIN,	"SOUND_MIXER_WRITE_MONGAIN",
	    NULL }, /* 120 */
};

const struct ioc strredir_ioc[] = { /* STRREDIR_MODID<<16 or 0 */
	/* STREAMS redirection ioctls */
	{ (uint_t)SRIOCSREDIR,		"SRIOCSREDIR",	NULL }, /* 1 */
	{ (uint_t)SRIOCISREDIR,		"SRIOCISREDIR",	NULL }, /* 2 */
};

const struct ioc cpc_ioc[] = { /* (((('c'<<8)|'p')<<8)|'c')<<8 */
	{ (uint_t)CPCIO_BIND,		"CPCIO_BIND",		NULL }, /* 1 */
	{ (uint_t)CPCIO_SAMPLE,		"CPCIO_SAMPLE",		NULL }, /* 2 */
	{ (uint_t)CPCIO_RELE,		"CPCIO_RELE",		NULL }, /* 3 */
};

const struct ioc dp_ioc[] = { /* 0xD0<<8 */
	/* /dev/poll ioctl() control codes */
	{ (uint_t)DP_POLL,	"DP_POLL",	NULL },
	{ (uint_t)DP_ISPOLLED,	"DP_ISPOLLED",	NULL },
	{ (uint_t)DP_PPOLL,	"DP_PPOLL",	NULL },
	{ (uint_t)DP_EPOLLCOMPAT, "DP_EPOLLCOMPAT",	NULL },
};

const struct ioc p_ioc[] = { /* 'q'<<8 */
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
};

const struct ioc socket_ioc[] = { /* 's'<<8 */
	/* ioctl's applicable on sockets */
	{ (uint_t)SIOCSHIWAT,	"SIOCSHIWAT",	NULL }, /* 0 */
	{ (uint_t)SIOCGHIWAT,	"SIOCGHIWAT",	NULL }, /* 1 */
	{ (uint_t)SIOCSLOWAT,	"SIOCSLOWAT",	NULL }, /* 2 */
	{ (uint_t)SIOCGLOWAT,	"SIOCGLOWAT",	NULL }, /* 3 */
	{ (uint_t)SIOCATMARK,	"SIOCATMARK",	NULL }, /* 7 */
	{ (uint_t)SIOCSPGRP,	"SIOCSPGRP",	NULL }, /* 8 */
	{ (uint_t)SIOCGPGRP,	"SIOCGPGRP",	NULL }, /* 9 */
	{ (uint_t)SIOCGETNAME,	"SIOCGETNAME",	"sockaddr" }, /* 52 */
	{ (uint_t)SIOCGETPEER,	"SIOCGETPEER",	"sockaddr" }, /* 53 */
	{ (uint_t)IF_UNITSEL,	"IF_UNITSEL",	NULL }, /* 54 */
	{ (uint_t)SIOCXPROTO,	"SIOCXPROTO",	NULL }, /* 55 */
};

const struct ioc routing_ioc[] = { /* 'r'<<8 */
	{ (uint_t)SIOCADDRT, "SIOCADDRT",	"rtentry" }, /* 10 */
	{ (uint_t)SIOCDELRT, "SIOCDELRT",	"rtentry" }, /* 11 */
	{ (uint_t)SIOCGETVIFCNT, "SIOCGETVIFCNT", "sioc_vif_req" }, /* 20 */
	{ (uint_t)SIOCGETSGCNT,	"SIOCGETSGCNT",	"sioc_sg_req" }, /* 21 */
	{ (uint_t)SIOCGETLSGCNT, "SIOCGETLSGCNT", "sioc_lsg_req" }, /* 21 */
};

const struct ioc sockio_ioc[] = { /* 'i'<<8 */
	{ (uint_t)SIOCSIFADDR,	"SIOCSIFADDR",	"ifreq" }, /* 12 */
	{ (uint_t)SIOCGIFADDR,	"SIOCGIFADDR",	"ifreq" }, /* 13 */
	{ (uint_t)SIOCSIFDSTADDR,	"SIOCSIFDSTADDR", "ifreq" }, /* 14 */
	{ (uint_t)SIOCGIFDSTADDR,	"SIOCGIFDSTADDR", "ifreq" }, /* 15 */
	{ (uint_t)SIOCSIFFLAGS,	"SIOCSIFFLAGS",	"ifreq" }, /* 16 */
	{ (uint_t)SIOCGIFFLAGS,	"SIOCGIFFLAGS",	"ifreq" }, /* 17 */
	{ (uint_t)SIOCSIFMEM,	"SIOCSIFMEM",	"ifreq" }, /* 18 */
	{ (uint_t)SIOCGIFMEM,	"SIOCGIFMEM",	"ifreq" }, /* 19 */
	{ (uint_t)SIOCSIFMTU,	"SIOCSIFMTU",	"ifreq" }, /* 21 */
	{ (uint_t)SIOCGIFMTU,	"SIOCGIFMTU",	"ifreq" }, /* 22 */
	{ (uint_t)SIOCGIFBRDADDR, "SIOCGIFBRDADDR", "ifreq" }, /* 23 */
	{ (uint_t)SIOCSIFBRDADDR, "SIOCSIFBRDADDR", "ifreq" }, /* 24 */
	{ (uint_t)SIOCGIFNETMASK, "SIOCGIFNETMASK", "ifreq" }, /* 25 */
	{ (uint_t)SIOCSIFNETMASK, "SIOCSIFNETMASK", "ifreq" }, /* 26 */
	{ (uint_t)SIOCGIFMETRIC, "SIOCGIFMETRIC", "ifreq" }, /* 27 */
	{ (uint_t)SIOCSIFMETRIC, "SIOCSIFMETRIC", "ifreq" }, /* 28 */
	{ (uint_t)SIOCSARP,	"SIOCSARP",	"arpreq" }, /* 30 */
	{ (uint_t)SIOCGARP,	"SIOCGARP",	"arpreq" }, /* 31 */
	{ (uint_t)SIOCDARP,	"SIOCDARP",	"arpreq" }, /* 32 */
	{ (uint_t)SIOCUPPER,	"SIOCUPPER",	"ifreq" },  /* 40 */
	{ (uint_t)SIOCLOWER,	"SIOCLOWER",	"ifreq" }, /* 41 */
	{ (uint_t)SIOCSETSYNC,	"SIOCSETSYNC",	"ifreq" }, /* 44 */
	{ (uint_t)SIOCGETSYNC,	"SIOCGETSYNC",	"ifreq" }, /* 45 */
	{ (uint_t)SIOCSSDSTATS,	"SIOCSSDSTATS",	"ifreq" }, /* 46 */
	{ (uint_t)SIOCSSESTATS,	"SIOCSSESTATS",	"ifreq" }, /* 47 */
	{ (uint_t)SIOCSPROMISC,	"SIOCSPROMISC",	NULL }, /* 48 */
	{ (uint_t)SIOCADDMULTI,	"SIOCADDMULTI",	"ifreq" }, /* 49 */
	{ (uint_t)SIOCDELMULTI,	"SIOCDELMULTI",	"ifreq" }, /* 50 */
	{ (uint_t)SIOCIFDETACH,	"SIOCIFDETACH",	"ifreq" }, /* 56 */
	{ (uint_t)SIOCGENPSTATS, "SIOCGENPSTATS", "ifreq" }, /* 57 */
	{ (uint_t)SIOCX25XMT,	"SIOCX25XMT",	"ifreq" }, /* 59 */
	{ (uint_t)SIOCX25RCV,	"SIOCX25RCV",	"ifreq" }, /* 60 */
	{ (uint_t)SIOCX25TBL,	"SIOCX25TBL",	"ifreq" }, /* 61 */
	{ (uint_t)SIOCSLGETREQ,	"SIOCSLGETREQ",	"ifreq" }, /* 71 */
	{ (uint_t)SIOCSLSTAT,	"SIOCSLSTAT",	"ifreq" }, /* 72 */
	{ (uint_t)SIOCSIFNAME,	"SIOCSIFNAME",	"ifreq" }, /* 73 */
	{ (uint_t)SIOCGENADDR,	"SIOCGENADDR",	"ifreq" }, /* 85 */
	{ (uint_t)SIOCGIFNUM,	"SIOCGIFNUM",	NULL }, /* 87 */
	{ (uint_t)SIOCGIFMUXID,	"SIOCGIFMUXID",	"ifreq" }, /* 88 */
	{ (uint_t)SIOCSIFMUXID,	"SIOCSIFMUXID",	"ifreq" }, /* 89 */
	{ (uint_t)SIOCGIFINDEX,	"SIOCGIFINDEX",	"ifreq" }, /* 90 */
	{ (uint_t)SIOCSIFINDEX,	"SIOCSIFINDEX",	"ifreq" }, /* 91 */
	{ (uint_t)SIOCGIFCONF,	"SIOCGIFCONF",	"ifconf" }, /* 92 */
	{ (uint_t)SIOCLIFREMOVEIF, "SIOCLIFREMOVEIF",	"lifreq" }, /* 110 */
	{ (uint_t)SIOCLIFADDIF,	"SIOCLIFADDIF",		"lifreq" }, /* 111 */
	{ (uint_t)SIOCSLIFADDR,	"SIOCSLIFADDR",		"lifreq" }, /* 112 */
	{ (uint_t)SIOCGLIFADDR,	"SIOCGLIFADDR",		"lifreq" }, /* 113 */
	{ (uint_t)SIOCSLIFDSTADDR, "SIOCSLIFDSTADDR",	"lifreq" }, /* 114 */
	{ (uint_t)SIOCGLIFDSTADDR, "SIOCGLIFDSTADDR",	"lifreq" }, /* 115 */
	{ (uint_t)SIOCSLIFFLAGS, "SIOCSLIFFLAGS",	"lifreq" }, /* 116 */
	{ (uint_t)SIOCGLIFFLAGS, "SIOCGLIFFLAGS",	"lifreq" }, /* 117 */
	{ (uint_t)SIOCSLIFMTU, "SIOCSLIFMTU",		"lifreq" }, /* 121 */
	{ (uint_t)SIOCGLIFMTU,	"SIOCGLIFMTU",		"lifreq" }, /* 122 */
	{ (uint_t)SIOCGLIFBRDADDR, "SIOCGLIFBRDADDR",	"lifreq" }, /* 123 */
	{ (uint_t)SIOCSLIFBRDADDR, "SIOCSLIFBRDADDR",	"lifreq" }, /* 124 */
	{ (uint_t)SIOCGLIFNETMASK, "SIOCGLIFNETMASK",	"lifreq" }, /* 125 */
	{ (uint_t)SIOCSLIFNETMASK, "SIOCSLIFNETMASK",	"lifreq" }, /* 126 */
	{ (uint_t)SIOCGLIFMETRIC, "SIOCGLIFMETRIC",	"lifreq" }, /* 127 */
	{ (uint_t)SIOCSLIFMETRIC, "SIOCSLIFMETRIC",	"lifreq" }, /* 128 */
	{ (uint_t)SIOCSLIFNAME,	 "SIOCSLIFNAME",	"lifreq" }, /* 129 */
	{ (uint_t)SIOCGLIFNUM,	 "SIOCGLIFNUM",		"lifnum" }, /* 130 */
	{ (uint_t)SIOCGLIFMUXID, "SIOCGLIFMUXID",	"lifreq" }, /* 131 */
	{ (uint_t)SIOCSLIFMUXID, "SIOCSLIFMUXID",	"lifreq" }, /* 132 */
	{ (uint_t)SIOCGLIFINDEX, "SIOCGLIFINDEX",	"lifreq" }, /* 133 */
	{ (uint_t)SIOCSLIFINDEX, "SIOCSLIFINDEX",	"lifreq" }, /* 134 */
	{ (uint_t)SIOCSLIFTOKEN, "SIOCSLIFTOKEN",	"lifreq" }, /* 135 */
	{ (uint_t)SIOCGLIFTOKEN, "SIOCGLIFTOKEN",	"lifreq" }, /* 136 */
	{ (uint_t)SIOCSLIFSUBNET, "SIOCSLIFSUBNET",	"lifreq" }, /* 137 */
	{ (uint_t)SIOCGLIFSUBNET, "SIOCGLIFSUBNET",	"lifreq" }, /* 138 */
	{ (uint_t)SIOCSLIFLNKINFO, "SIOCSLIFLNKINFO",	"lifreq" }, /* 139 */
	{ (uint_t)SIOCGLIFLNKINFO, "SIOCGLIFLNKINFO",	"lifreq" }, /* 140 */
	{ (uint_t)SIOCLIFDELND,	"SIOCLIFDELND",		"lifreq" }, /* 141 */
	{ (uint_t)SIOCLIFGETND,	"SIOCLIFGETND",		"lifreq" }, /* 142 */
	{ (uint_t)SIOCLIFSETND,	"SIOCLIFSETND",		"lifreq" }, /* 143 */
	{ (uint_t)SIOCTMYADDR,	"SIOCTMYADDR",	"sioc_addrreq" }, /* 144 */
	{ (uint_t)SIOCTONLINK,	"SIOCTONLINK",	"sioc_addrreq" }, /* 145 */
	{ (uint_t)SIOCTMYSITE,	"SIOCTMYSITE",	"sioc_addrreq" }, /* 146 */
	{ (uint_t)SIOCGLIFBINDING, "SIOCGLIFBINDING",	"lifreq" }, /* 154 */
	{ (uint_t)SIOCSLIFGROUPNAME, "SIOCSLIFGROUPNAME", "lifreq" }, /* 155 */
	{ (uint_t)SIOCGLIFGROUPNAME, "SIOCGLIFGROUPNAME", "lifreq" }, /* 156 */
	{ (uint_t)SIOCGLIFGROUPINFO, "SIOCGLIFGROUPINFO",
	    "lifgroupinfo" }, /* 157 */
	{ (uint_t)SIOCGIP6ADDRPOLICY, "SIOCGIP6ADDRPOLICY", NULL }, /* 162 */
	{ (uint_t)SIOCSIP6ADDRPOLICY, "SIOCSIP6ADDRPOLICY", NULL }, /* 163 */
	{ (uint_t)SIOCGDSTINFO,	"SIOCGDSTINFO",	NULL }, /* 164 */
	{ (uint_t)SIOCGLIFCONF, "SIOCGLIFCONF",		"lifconf" }, /* 165 */
	{ (uint_t)SIOCSXARP,	"SIOCSXARP",		"xarpreq" }, /* 166 */
	{ (uint_t)SIOCGXARP,	"SIOCGXARP",		"xarpreq" }, /* 167 */
	{ (uint_t)SIOCDXARP,	"SIOCDXARP",		"xarpreq" }, /* 168 */
	{ (uint_t)SIOCGLIFZONE,	"SIOCGLIFZONE",		"lifreq" }, /* 170 */
	{ (uint_t)SIOCSLIFZONE,	"SIOCSLIFZONE",		"lifreq" }, /* 171 */
	{ (uint_t)SIOCSCTPSOPT,	"SIOCSCTPSOPT",		NULL }, /* 172 */
	{ (uint_t)SIOCSCTPGOPT,	"SIOCSCTPGOPT",		NULL }, /* 173 */
	{ (uint_t)SIOCSCTPPEELOFF, "SIOPCSCTPPEELOFF",	"int" }, /* 174 */
	{ (uint_t)SIOCGLIFUSESRC, "SIOCGLIFUSESRC",	"lifreq" }, /* 175 */
	{ (uint_t)SIOCSLIFUSESRC, "SIOCSLIFUSESRC",	"lifreq" }, /* 176 */
	{ (uint_t)SIOCGLIFSRCOF, "SIOCGLIFSRCOF",	"lifsrcof" }, /* 177 */
	{ (uint_t)SIOCGMSFILTER, "SIOCGMSFILTER",    "group_filter" }, /* 178 */
	{ (uint_t)SIOCSMSFILTER, "SIOCSMSFILTER",    "group_filter" }, /* 179 */
	{ (uint_t)SIOCGIPMSFILTER, "SIOCGIPMSFILTER", "ip_msfilter" }, /* 180 */
	{ (uint_t)SIOCSIPMSFILTER, "SIOCSIPMSFILTER", "ip_msfilter" }, /* 181 */
	{ (uint_t)SIOCGIFHWADDR, "SIOCGIFHWADDR",	"ifreq" }, /* 185 */
	{ (uint_t)SIOCGSTAMP,	"SIOCGSTAMP",		"timeval" }, /* 186 */
	{ (uint_t)SIOCGLIFDADSTATE, "SIOCGLIFDADSTATE",  "lifreq" }, /* 190 */
	{ (uint_t)SIOCSLIFPREFIX, "SIOCSLIFPREFIX", "lifreq" }, /* 191 */
	{ (uint_t)SIOCGLIFHWADDR, "SIOCGLIFHWADDR",	"lifreq" }, /* 192 */
};

const struct ioc des_ioc[] = { /* 'd'<<8 */
	/* DES encryption */
	{ (uint_t)DESIOCBLOCK,	"DESIOCBLOCK",	"desparams" }, /* 6 */
	{ (uint_t)DESIOCQUICK,	"DESIOCQUICK",	"desparams" }, /* 7 */
};

const struct ioc prn_ioc[] = { /* 'p'<<8 */
	/* Printing system */
	{ (uint_t)PRNIOC_GET_IFCAP,	"PRNIOC_GET_IFCAP",	NULL }, /* 90 */
	{ (uint_t)PRNIOC_SET_IFCAP,	"PRNIOC_SET_IFCAP",	NULL }, /* 91 */
	{ (uint_t)PRNIOC_GET_IFINFO,	"PRNIOC_GET_IFINFO",
	    "prn_interface_info" }, /* 92 */
	{ (uint_t)PRNIOC_GET_STATUS,	"PRNIOC_GET_STATUS",	NULL }, /* 93 */
	{ (uint_t)PRNIOC_GET_1284_DEVID,	"PRNIOC_GET_1284_DEVID",
	    "prn_1284_device_id" }, /* 94 */
	{ (uint_t)PRNIOC_GET_1284_STATUS,
	    "PRNIOC_GET_IFCANIOC_GET_1284_STATUS", NULL }, /* 95 */
	{ (uint_t)PRNIOC_GET_TIMEOUTS,	"PRNIOC_GET_TIMEOUTS",
	    "prn_timeouts" }, /* 96 */
	{ (uint_t)PRNIOC_SET_TIMEOUTS,	"PRNIOC_SET_TIMEOUTS",
	    "prn_timeouts" }, /* 97 */
	{ (uint_t)PRNIOC_RESET,	"PRNIOC_RESET",	NULL }, /* 98 */
};

const struct ioc dtrace_ioc[] = { /* ('d' << 24) | ('t' << 16) | ('r' << 8) */
	/* DTrace */
	{ (uint_t)DTRACEIOC_PROVIDER,	"DTRACEIOC_PROVIDER",	NULL }, /* 1 */
	{ (uint_t)DTRACEIOC_PROBES,	"DTRACEIOC_PROBES",	NULL }, /* 2 */
	{ (uint_t)DTRACEIOC_BUFSNAP,	"DTRACEIOC_BUFSNAP",	NULL }, /* 4 */
	{ (uint_t)DTRACEIOC_PROBEMATCH,	"DTRACEIOC_PROBEMATCH",	NULL }, /* 5 */
	{ (uint_t)DTRACEIOC_ENABLE,	"DTRACEIOC_ENABLE",	NULL }, /* 6 */
	{ (uint_t)DTRACEIOC_AGGSNAP,	"DTRACEIOC_AGGSNAP",	NULL }, /* 7 */
	{ (uint_t)DTRACEIOC_EPROBE,	"DTRACEIOC_EPROBE",	NULL }, /* 8 */
	{ (uint_t)DTRACEIOC_PROBEARG,   "DTRACEIOC_PROBEARG",   NULL }, /* 9 */
	{ (uint_t)DTRACEIOC_CONF,	"DTRACEIOC_CONF",	NULL }, /* 10 */
	{ (uint_t)DTRACEIOC_STATUS,	"DTRACEIOC_STATUS",	NULL }, /* 11 */
	{ (uint_t)DTRACEIOC_GO,		"DTRACEIOC_GO",		NULL }, /* 12 */
	{ (uint_t)DTRACEIOC_STOP,	"DTRACEIOC_STOP",	NULL }, /* 13 */
	{ (uint_t)DTRACEIOC_AGGDESC,	"DTRACEIOC_AGGDESC",	NULL }, /* 14 */
	{ (uint_t)DTRACEIOC_FORMAT,	"DTRACEIOC_FORMAT",	NULL }, /* 15 */
	{ (uint_t)DTRACEIOC_DOFGET,	"DTRACEIOC_DOFGET",	NULL }, /* 16 */
	{ (uint_t)DTRACEIOC_REPLICATE,	"DTRACEIOC_REPLICATE",	NULL }, /* 17 */
};

const struct ioc dtraceh_ioc[] = { /* ('d' << 24) | ('t' << 16) | ('h' << 8) */
	{ (uint_t)DTRACEHIOC_ADD,	"DTRACEHIOC_ADD",	NULL }, /* 1 */
	{ (uint_t)DTRACEHIOC_REMOVE,	"DTRACEHIOC_REMOVE",	NULL }, /* 2 */
	{ (uint_t)DTRACEHIOC_ADDDOF,	"DTRACEHIOC_ADDDOF",	NULL }, /* 3 */
};

const struct ioc crypto_ioc[] = { /* 'y'<<8 */
	/* /dev/cryptoadm ioctl() control codes */
	{ (uint_t)CRYPTO_GET_VERSION,	"CRYPTO_GET_VERSION",	NULL }, /* 1 */
	{ (uint_t)CRYPTO_GET_DEV_LIST,	"CRYPTO_GET_DEV_LIST",	NULL }, /* 2 */
	{ (uint_t)CRYPTO_GET_SOFT_LIST,	"CRYPTO_GET_SOFT_LIST",	NULL }, /* 3 */
	{ (uint_t)CRYPTO_GET_DEV_INFO,	"CRYPTO_GET_DEV_INFO",	NULL }, /* 4 */
	{ (uint_t)CRYPTO_GET_SOFT_INFO,	"CRYPTO_GET_SOFT_INFO",	NULL }, /* 5 */
	{ (uint_t)CRYPTO_LOAD_DEV_DISABLED,	"CRYPTO_LOAD_DEV_DISABLED",
	    NULL }, /* 8 */
	{ (uint_t)CRYPTO_LOAD_SOFT_DISABLED,	"CRYPTO_LOAD_SOFT_DISABLED",
	    NULL }, /* 9 */
	{ (uint_t)CRYPTO_UNLOAD_SOFT_MODULE,	"CRYPTO_UNLOAD_SOFT_MODULE",
	    NULL }, /* 10 */
	{ (uint_t)CRYPTO_LOAD_SOFT_CONFIG,	"CRYPTO_LOAD_SOFT_CONFIG",
	    NULL }, /* 11 */
	{ (uint_t)CRYPTO_POOL_CREATE,	"CRYPTO_POOL_CREATE",	NULL }, /* 12 */
	{ (uint_t)CRYPTO_POOL_WAIT,	"CRYPTO_POOL_WAIT",	NULL }, /* 13 */
	{ (uint_t)CRYPTO_POOL_RUN,	"CRYPTO_POOL_RUN",	NULL }, /* 14 */
	{ (uint_t)CRYPTO_LOAD_DOOR,	"CRYPTO_LOAD_DOOR",	NULL }, /* 15 */
	{ (uint_t)CRYPTO_FIPS140_STATUS,
	    "CRYPTO_FIPS140_STATUS", NULL }, /* 16 */
	{ (uint_t)CRYPTO_FIPS140_SET, "CRYPTO_FIPS140_SET", NULL }, /* 17 */

	/* /dev/crypto ioctl() control codes */
	{ (uint_t)CRYPTO_GET_FUNCTION_LIST,	"CRYPTO_GET_FUNCTION_LIST",
	    NULL }, /* 20 */
	{ (uint_t)CRYPTO_GET_MECHANISM_NUMBER,	"CRYPTO_GET_MECHANISM_NUMBER",
	    NULL }, /* 21 */
	{ (uint_t)CRYPTO_OPEN_SESSION,	"CRYPTO_OPEN_SESSION",	NULL }, /* 30 */
	{ (uint_t)CRYPTO_CLOSE_SESSION,	"CRYPTO_CLOSE_SESSION",	NULL }, /* 31 */
	{ (uint_t)CRYPTO_CLOSE_ALL_SESSIONS,	"CRYPTO_CLOSE_ALL_SESSIONS",
	    NULL }, /* 32 */
	{ (uint_t)CRYPTO_LOGIN,		"CRYPTO_LOGIN",		NULL }, /* 40 */
	{ (uint_t)CRYPTO_LOGOUT,	"CRYPTO_LOGOUT",	NULL }, /* 41 */
	{ (uint_t)CRYPTO_ENCRYPT,	"CRYPTO_ENCRYPT",	NULL }, /* 50 */
	{ (uint_t)CRYPTO_ENCRYPT_INIT,	"CRYPTO_ENCRYPT_INIT",	NULL }, /* 51 */
	{ (uint_t)CRYPTO_ENCRYPT_UPDATE,	"CRYPTO_ENCRYPT_UPDATE",
	    NULL }, /* 52 */
	{ (uint_t)CRYPTO_ENCRYPT_FINAL,	"CRYPTO_ENCRYPT_FINAL",	NULL }, /* 53 */
	{ (uint_t)CRYPTO_DECRYPT,	"CRYPTO_DECRYPT",	NULL }, /* 54 */
	{ (uint_t)CRYPTO_DECRYPT_INIT,	"CRYPTO_DECRYPT_INIT",	NULL }, /* 55 */
	{ (uint_t)CRYPTO_DECRYPT_UPDATE,	"CRYPTO_DECRYPT_UPDATE",
	    NULL }, /* 56 */
	{ (uint_t)CRYPTO_DECRYPT_FINAL,	"CRYPTO_DECRYPT_FINAL",	NULL }, /* 57 */
	{ (uint_t)CRYPTO_DIGEST,	"CRYPTO_DIGEST",	NULL }, /* 58 */
	{ (uint_t)CRYPTO_DIGEST_INIT,	"CRYPTO_DIGEST_INIT",	NULL }, /* 59 */
	{ (uint_t)CRYPTO_DIGEST_UPDATE,	"CRYPTO_DIGEST_UPDATE",	NULL }, /* 60 */
	{ (uint_t)CRYPTO_DIGEST_KEY,	"CRYPTO_DIGEST_KEY",	NULL }, /* 61 */
	{ (uint_t)CRYPTO_DIGEST_FINAL,	"CRYPTO_DIGEST_FINAL",	NULL }, /* 62 */
	{ (uint_t)CRYPTO_MAC,		"CRYPTO_MAC",		NULL }, /* 63 */
	{ (uint_t)CRYPTO_MAC_INIT,	"CRYPTO_MAC_INIT",	NULL }, /* 64 */
	{ (uint_t)CRYPTO_MAC_UPDATE,	"CRYPTO_MAC_UPDATE",	NULL }, /* 65 */
	{ (uint_t)CRYPTO_MAC_FINAL,	"CRYPTO_MAC_FINAL",	NULL }, /* 66 */
	{ (uint_t)CRYPTO_SIGN,		"CRYPTO_SIGN",		NULL }, /* 67 */
	{ (uint_t)CRYPTO_SIGN_INIT,	"CRYPTO_SIGN_INIT",	NULL }, /* 68 */
	{ (uint_t)CRYPTO_SIGN_UPDATE,	"CRYPTO_SIGN_UPDATE",	NULL }, /* 69 */
	{ (uint_t)CRYPTO_SIGN_FINAL,	"CRYPTO_SIGN_FINAL",	NULL }, /* 70 */
	{ (uint_t)CRYPTO_SIGN_RECOVER_INIT,	"CRYPTO_SIGN_RECOVER_INIT",
	    NULL }, /* 71 */
	{ (uint_t)CRYPTO_SIGN_RECOVER,	"CRYPTO_SIGN_RECOVER",	NULL }, /* 72 */
	{ (uint_t)CRYPTO_VERIFY,	"CRYPTO_VERIFY",	NULL }, /* 73 */
	{ (uint_t)CRYPTO_VERIFY_INIT,	"CRYPTO_VERIFY_INIT",	NULL }, /* 74 */
	{ (uint_t)CRYPTO_VERIFY_UPDATE,	"CRYPTO_VERIFY_UPDATE",	NULL }, /* 75 */
	{ (uint_t)CRYPTO_VERIFY_FINAL,	"CRYPTO_VERIFY_FINAL",	NULL }, /* 76 */
	{ (uint_t)CRYPTO_VERIFY_RECOVER_INIT,	"CRYPTO_VERIFY_RECOVER_INIT",
	    NULL }, /* 77 */
	{ (uint_t)CRYPTO_VERIFY_RECOVER,	"CRYPTO_VERIFY_RECOVER",
	    NULL }, /* 78 */
	{ (uint_t)CRYPTO_DIGEST_ENCRYPT_UPDATE,	"CRYPTO_DIGEST_ENCRYPT_UPDATE",
	    NULL }, /* 79 */
	{ (uint_t)CRYPTO_DECRYPT_DIGEST_UPDATE,	"CRYPTO_DECRYPT_DIGEST_UPDATE",
	    NULL }, /* 80 */
	{ (uint_t)CRYPTO_SIGN_ENCRYPT_UPDATE,	"CRYPTO_SIGN_ENCRYPT_UPDATE",
	    NULL }, /* 81 */
	{ (uint_t)CRYPTO_DECRYPT_VERIFY_UPDATE,	"CRYPTO_DECRYPT_VERIFY_UPDATE",
	    NULL }, /* 82 */
	{ (uint_t)CRYPTO_SEED_RANDOM,	"CRYPTO_SEED_RANDOM",	NULL }, /* 90 */
	{ (uint_t)CRYPTO_GENERATE_RANDOM,	"CRYPTO_GENERATE_RANDOM",
	    NULL }, /* 91 */
	{ (uint_t)CRYPTO_OBJECT_CREATE,
	    "CRYPTO_OBJECT_CREATE", NULL }, /* 100 */
	{ (uint_t)CRYPTO_OBJECT_COPY, "CRYPTO_OBJECT_COPY", NULL }, /* 101 */
	{ (uint_t)CRYPTO_OBJECT_DESTROY,	"CRYPTO_OBJECT_DESTROY",
	    NULL }, /* 102 */
	{ (uint_t)CRYPTO_OBJECT_GET_ATTRIBUTE_VALUE,
	    "CRYPTO_OBJECT_GET_ATTRIBUTE_VALUE",	NULL }, /* 103 */
	{ (uint_t)CRYPTO_OBJECT_GET_SIZE, "CRYPTO_OBJECT_GET_SIZE",
	    NULL }, /* 104 */
	{ (uint_t)CRYPTO_OBJECT_SET_ATTRIBUTE_VALUE,
	    "CRYPTO_OBJECT_SET_ATTRIBUTE_VALUE",	NULL }, /* 105 */
	{ (uint_t)CRYPTO_OBJECT_FIND_INIT,	"CRYPTO_OBJECT_FIND_INIT",
	    NULL }, /* 106 */
	{ (uint_t)CRYPTO_OBJECT_FIND_UPDATE,	"CRYPTO_OBJECT_FIND_UPDATE",
	    NULL }, /* 107 */
	{ (uint_t)CRYPTO_OBJECT_FIND_FINAL,	"CRYPTO_OBJECT_FIND_FINAL",
	    NULL }, /* 108 */
	{ (uint_t)CRYPTO_GENERATE_KEY, "CRYPTO_GENERATE_KEY", NULL }, /* 110 */
	{ (uint_t)CRYPTO_GENERATE_KEY_PAIR, "CRYPTO_GENERATE_KEY_PAIR",
	    NULL }, /* 111 */
	{ (uint_t)CRYPTO_WRAP_KEY, "CRYPTO_WRAP_KEY", NULL }, /* 112 */
	{ (uint_t)CRYPTO_UNWRAP_KEY, "CRYPTO_UNWRAP_KEY", NULL }, /* 113 */
	{ (uint_t)CRYPTO_DERIVE_KEY, "CRYPTO_DERIVE_KEY", NULL }, /* 114 */
	{ (uint_t)CRYPTO_GET_PROVIDER_LIST,	"CRYPTO_GET_PROVIDER_LIST",
	    NULL }, /* 120 */
	{ (uint_t)CRYPTO_GET_PROVIDER_INFO,	"CRYPTO_GET_PROVIDER_INFO",
	    NULL }, /* 121 */
	{ (uint_t)CRYPTO_GET_PROVIDER_MECHANISMS,
	    "CRYPTO_GET_PROVIDER_MECHANISMS",	NULL }, /* 122 */
	{ (uint_t)CRYPTO_GET_PROVIDER_MECHANISM_INFO,
	    "CRYPTO_GET_PROVIDER_MECHANISM_INFO", NULL }, /* 123 */
	{ (uint_t)CRYPTO_INIT_TOKEN, "CRYPTO_INIT_TOKEN", NULL }, /* 124 */
	{ (uint_t)CRYPTO_INIT_PIN, "CRYPTO_INIT_PIN", NULL }, /* 125 */
	{ (uint_t)CRYPTO_SET_PIN, "CRYPTO_SET_PIN", NULL }, /* 126 */
	{ (uint_t)CRYPTO_NOSTORE_GENERATE_KEY,
	    "CRYPTO_NOSTORE_GENERATE_KEY",	NULL }, /* 127 */
	{ (uint_t)CRYPTO_NOSTORE_GENERATE_KEY_PAIR,
	    "CRYPTO_NOSTORE_GENERATE_KEY_PAIR",	NULL }, /* 128 */
	{ (uint_t)CRYPTO_NOSTORE_DERIVE_KEY,
	    "CRYPTO_NOSTORE_DERIVE_KEY",	NULL }, /* 129 */
	{ (uint_t)CRYPTO_GET_MECHANISM_LIST,
	    "CRYPTO_GET_MECHANISM_LIST",	NULL }, /* 140 */
	{ (uint_t)CRYPTO_GET_ALL_MECHANISM_INFO,
	    "CRYPTO_GET_ALL_MECHANISM_INFO",	NULL }, /* 141 */
	{ (uint_t)CRYPTO_GET_PROVIDER_BY_MECH,
	    "CRYPTO_GET_PROVIDER_BY_MECH",	NULL }, /* 142 */
};

const struct ioc kbd_ioc[] = { /* 'k'<<8 */
	/* kbio ioctls */
	{ (uint_t)KIOCTRANS,		"KIOCTRANS",	NULL }, /* 30 */
	{ (uint_t)KIOCSETKEY,		"KIOCSETKEY",	NULL }, /* 31 */
	{ (uint_t)KIOCGETKEY,		"KIOCGETKEY",	NULL }, /* 32 */
	{ (uint_t)KIOCGTRANS,		"KIOCGTRANS",	NULL }, /* 35 */
	{ (uint_t)KIOCTRANSABLE,	"KIOCTRANSABLE",	NULL }, /* 36 */
	{ (uint_t)KIOCGTRANSABLE,	"KIOCGTRANSABLE",	NULL }, /* 37 */
	{ (uint_t)KIOCCMD,		"KIOCCMD",	NULL }, /* 8 */
	{ (uint_t)KIOCTYPE,		"KIOCTYPE",	NULL }, /* 9 */
	{ (uint_t)KIOCSDIRECT,		"KIOCSDIRECT",	NULL }, /* 10 */
	{ (uint_t)KIOCGDIRECT,		"KIOCGDIRECT",	NULL }, /* 41 */
	{ (uint_t)KIOCSKEY,		"KIOCSKEY",	NULL }, /* 42 */
	{ (uint_t)KIOCGKEY,		"KIOCGKEY",	NULL }, /* 13 */
	{ (uint_t)KIOCSLED,		"KIOCSLED",	NULL }, /* 14 */
	{ (uint_t)KIOCGLED,		"KIOCGLED",	NULL }, /* 15 */
	{ (uint_t)KIOCSCOMPAT,		"KIOCSCOMPAT",	NULL }, /* 16 */
	{ (uint_t)KIOCGCOMPAT,		"KIOCGCOMPAT",	NULL }, /* 17 */
	{ (uint_t)KIOCSLAYOUT,		"KIOCSLAYOUT",	NULL }, /* 19 */
	{ (uint_t)KIOCLAYOUT,		"KIOCLAYOUT",	NULL }, /* 20 */
	{ (uint_t)KIOCSKABORTEN,	"KIOCSKABORTEN",	NULL }, /* 21 */
	{ (uint_t)KIOCGRPTDELAY,	"KIOCGRPTDELAY",	NULL }, /* 22 */
	{ (uint_t)KIOCSRPTDELAY,	"KIOCSRPTDELAY",	NULL }, /* 23 */
	{ (uint_t)KIOCGRPTRATE,		"KIOCGRPTRATE",	NULL }, /* 24 */
	{ (uint_t)KIOCSRPTRATE,		"KIOCSRPTRATE",	NULL }, /* 25 */
	{ (uint_t)KIOCSETFREQ,		"KIOCSETFREQ",	NULL }, /* 26 */
	{ (uint_t)KIOCMKTONE,		"KIOCMKTONE",	NULL }, /* 27 */
	{ (uint_t)KIOCGRPTCOUNT,	"KIOCGRPTCOUNT",	NULL }, /* 28 */
	{ (uint_t)KIOCSRPTCOUNT,	"KIOCSRPTCOUNT",	NULL }, /* 29 */
};

const struct ioc ptm_ioc[] = { /* 'P'<<8 */
	/* ptm/pts driver I_STR ioctls */
	{ (uint_t)ISPTM,		"ISPTM",	NULL }, /* 1 */
	{ (uint_t)UNLKPT,		"UNLKPT",	NULL }, /* 2 */
	{ (uint_t)PTSSTTY,		"PTSSTTY",	NULL }, /* 3 */
	{ (uint_t)ZONEPT,		"ZONEPT",	NULL }, /* 4 */
	{ (uint_t)OWNERPT,		"OWNERPT",	NULL }, /* 5 */
};

const struct ioc aggr_ioc[] = { /* 0x0A66 << 16 */
	/* aggr link aggregation pseudo driver ioctls */
	{ (uint_t)LAIOC_CREATE,	"LAIOC_CREATE",	"laioc_create"}, /* 1 */
	{ (uint_t)LAIOC_DELETE,	"LAIOC_DELETE",	"laioc_delete"}, /* 2 */
	{ (uint_t)LAIOC_INFO,	"LAIOC_INFO",	"laioc_info"}, /* 3 */
	{ (uint_t)LAIOC_ADD,	"LAIOC_ADD", "laioc_add_rem"}, /* 4 */
	{ (uint_t)LAIOC_REMOVE,	"LAIOC_REMOVE", "laioc_add_rem"}, /* 5 */
	{ (uint_t)LAIOC_MODIFY,	"LAIOC_MODIFY",	"laioc_modify"}, /* 6 */
};

const struct ioc dld_ioc[] = { /* 0x0D1D << 16 */
	/* dld data-link ioctls */
	{ (uint_t)DLDIOC_ATTR, "DLDIOC_ATTR", "dld_ioc_attr"}, /* 3 */
	{ (uint_t)DLDIOC_VLAN_ATTR, "DLDIOC_VLAN_ATTR",
	    "dld_ioc_vlan_attr"}, /* 4 */
	{ (uint_t)DLDIOC_PHYS_ATTR, "DLDIOC_PHYS_ATTR",
	    "dld_ioc_phys_attr"}, /* 5 */
	{ (uint_t)DLDIOC_SECOBJ_SET, "DLDIOC_SECOBJ_SET",
		"dld_ioc_secobj_set"}, /* 6 */
	{ (uint_t)DLDIOC_SECOBJ_GET, "DLDIOC_SECOBJ_GET",
		"dld_ioc_secobj_get"}, /* 7 */
	{ (uint_t)DLDIOC_SECOBJ_UNSET, "DLDIOC_SECOBJ_UNSET",
		"dld_ioc_secobj_unset"}, /* 10 */
	{ (uint_t)DLDIOC_CREATE_VLAN, "DLDIOC_CREATE_VLAN",
		"dld_ioc_create_vlan"}, /* 11 */
	{ (uint_t)DLDIOC_DELETE_VLAN, "DLDIOC_DELETE_VLAN",
		"dld_ioc_delete_vlan"}, /* 12 */
	{ (uint_t)DLDIOC_DOORSERVER, "DLDIOC_DOORSERVER",
		"dld_ioc_door"}, /* 16 */
	{ (uint_t)DLDIOC_RENAME, "DLDIOC_RENAME", "dld_ioc_rename"}, /* 17 */
	{ (uint_t)DLDIOC_MACADDRGET, "DLDIOC_MACADDRGET", /* 21 */
		"dld_ioc_macaddrget"},
	{ (uint_t)DLDIOC_ADDFLOW, "DLDIOC_ADDFLOW",
		"dld_ioc_addflow"}, /* 22 */
	{ (uint_t)DLDIOC_REMOVEFLOW, "DLDIOC_REMOVEFLOW",
		"dld_ioc_removeflow"}, /* 23 */
	{ (uint_t)DLDIOC_MODIFYFLOW, "DLDIOC_MODIFYFLOW",
		"dld_ioc_modifyflow"}, /* 24 */
	{ (uint_t)DLDIOC_WALKFLOW, "DLDIOC_WALKFLOW",
		"dld_ioc_walkflow"}, /* 25 */
	{ (uint_t)DLDIOC_USAGELOG, "DLDIOC_USAGELOG",
		"dld_ioc_usagelog"}, /* 26 */
	{ (uint_t)DLDIOC_SETMACPROP, "DLDIOC_SETMACPROP",
		"dld_ioc_macprop_s"}, /* 27 */
	{ (uint_t)DLDIOC_GETMACPROP, "DLDIOC_GETMACPROP",
		"dld_ioc_macprop_s"}, /* 28 */
	{ (uint_t)DLDIOC_GETHWGRP, "DLDIOC_GETHWGRP",
		"dld_ioc_hwgrpget"}, /* 29 */
	{ (uint_t)DLDIOC_GETTRAN, "DLDIOC_GETTRAN",
		"dld_ioc_gettran"}, /* 30 */
	{ (uint_t)DLDIOC_READTRAN, "DLDIOC_READTRAN",
		"dld_ioc_tranio"}, /* 31 */
};

const struct ioc simnet_ioc[] = { /* 0x5132 << 16 */
	/* simnet ioctls */
	{ (uint_t)SIMNET_IOC_CREATE,		"SIMNET_IOC_CREATE",
		"simnet_ioc_create"}, /* 1 */
	{ (uint_t)SIMNET_IOC_DELETE,		"SIMNET_IOC_DELETE",
		"simnet_ioc_delete"}, /* 2 */
	{ (uint_t)SIMNET_IOC_INFO,		"SIMNET_IOC_INFO",
		"simnet_ioc_info"}, /* 3 */
	{ (uint_t)SIMNET_IOC_MODIFY,		"SIMNET_IOC_MODIFY",
		"simnet_ioc_info"}, /* 4 */
};

const struct ioc vnic_ioc[] = { /* 0x0171 << 16 */
	/* vnic ioctls */
	{ (uint_t)VNIC_IOC_CREATE,		"VNIC_IOC_CREATE",
		"vnic_ioc_create"}, /* 1 */
	{ (uint_t)VNIC_IOC_DELETE,		"VNIC_IOC_DELETE",
		"vnic_ioc_delete"}, /* 2 */
	{ (uint_t)VNIC_IOC_INFO,		"VNIC_IOC_INFO",
		"vnic_ioc_info"}, /* 3 */
	{ (uint_t)VNIC_IOC_MODIFY,		"VNIC_IOC_MODIFY",
		"vnic_ioc_modify"}, /* 4 */
};

const struct ioc zfs_ioc[] = { /* 'Z' << 8 */
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
	{ (uint_t)ZFS_IOC_SPACE_SNAPS,		"ZFS_IOC_SPACE_SNAPS",
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
	{ (uint_t)ZFS_IOC_POOL_SYNC,		"ZFS_IOC_POOL_SYNC",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_CHANNEL_PROGRAM,	"ZFS_IOC_CHANNEL_PROGRAM",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_LOAD_KEY,		"ZFS_IOC_LOAD_KEY",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_UNLOAD_KEY,		"ZFS_IOC_UNLOAD_KEY",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_CHANGE_KEY,		"ZFS_IOC_CHANGE_KEY",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_REMAP,		"ZFS_IOC_REMAP",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_POOL_CHECKPOINT,	"ZFS_IOC_POOL_CHECKPOINT",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_POOL_DISCARD_CHECKPOINT,
		"ZFS_IOC_POOL_DISCARD_CHECKPOINT", "zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_POOL_INITIALIZE,	"ZFS_IOC_POOL_INITIALIZE",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_POOL_TRIM,		"ZFS_IOC_POOL_TRIM",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_REDACT,		"ZFS_IOC_REDACT",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_GET_BOOKMARK_PROPS,	"ZFS_IOC_GET_BOOKMARK_PROPS",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_EVENTS_NEXT,		"ZFS_IOC_EVENTS_NEXT",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_EVENTS_CLEAR,		"ZFS_IOC_EVENTS_CLEAR",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_EVENTS_SEEK,		"ZFS_IOC_EVENTS_SEEK",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_NEXTBOOT,		"ZFS_IOC_NEXTBOOT",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_JAIL,			"ZFS_IOC_JAIL",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_UNJAIL,		"ZFS_IOC_UNJAIL",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_SET_BOOTENV,		"ZFS_IOC_SET_BOOTENV",
		"zfs_cmd_t" },
	{ (uint_t)ZFS_IOC_GET_BOOTENV,		"ZFS_IOC_GET_BOOTENV",
		"zfs_cmd_t" },
};

const struct ioc dkio_ioc[] = { /* 0x4 << 8 */
	/* disk ioctls - (0x04 << 8) - dkio.h */
	{ (uint_t)DKIOCGGEOM,		"DKIOCGGEOM",
		"dk_geom"}, /* 1 */
	{ (uint_t)DKIOCSGEOM,		"DKIOCSGEOM",
		"dk_geom"}, /* 2 */
	{ (uint_t)DKIOCINFO,		"DKIOCINFO",
		"dk_info"}, /* 3 */
	{ (uint_t)DKIOCSAPART,		"DKIOCSAPART",
		"dk_allmap"}, /* 4 */
	{ (uint_t)DKIOCGAPART,		"DKIOCGAPART",
		"dk_allmap"}, /* 5 */
	{ (uint_t)DKIOCEJECT,		"DKIOCEJECT",
		NULL}, /* 6 */
	{ (uint_t)DKIOCLOCK,		"DKIOCLOCK",
		NULL}, /* 7 */
	{ (uint_t)DKIOCUNLOCK,		"DKIOCUNLOCK",
		NULL}, /* 8 */
	{ (uint_t)DKIOCPARTITION,	"DKIOCPARTITION",
		"partition64"}, /* 9 */
	{ (uint_t)DKIOCGVTOC,		"DKIOCGVTOC",
		"vtoc"}, /* 11 */
	{ (uint_t)DKIOCSVTOC,		"DKIOCSVTOC",
		"vtoc"}, /* 12 */
	{ (uint_t)DKIOCSTATE,		"DKIOCSTATE",
		NULL}, /* 13 */
	{ (uint_t)DKIOCREMOVABLE,	"DKIOCREMOVABLE",
		NULL}, /* 16 */
	{ (uint_t)DKIOCSETEFI,		"DKIOCSETEFI",
		"dk_efi"}, /* 17 */
	{ (uint_t)DKIOCGETEFI,		"DKIOCGETEFI",
		"dk_efi"}, /* 18 */
	{ (uint_t)DKIOCEXTPARTINFO,	"DKIOCEXTPARTINFO",
		"extpart_info"}, /* 19 */
	{ (uint_t)DKIOCADDBAD,		"DKIOCADDBAD",
		NULL}, /* 20 */
	{ (uint_t)DKIOCGETDEF,		"DKIOCGETDEF",
		NULL}, /* 21 */
	{ (uint_t)DKIOCPARTINFO,	"DKIOCPARTINFO",
		"part_info"}, /* 22 */
	{ (uint_t)DKIOCGEXTVTOC,	"DKIOCGEXTVTOC",
		"extvtoc"}, /* 23 */
	{ (uint_t)DKIOCSEXTVTOC,	"DKIOCSEXTVTOC",
		"extvtoc"}, /* 24 */
	{ (uint_t)DKIOCGETVOLCAP,	"DKIOCGETVOLCAP",
		"volcap_t"}, /* 25 */
	{ (uint_t)DKIOCSETVOLCAP,	"DKIOCSETVOLCAP",
		"volcap_t"}, /* 26 */
	{ (uint_t)DKIOCDMR,		"DKIOCDMR",
		"vol_directed_rd"}, /* 27 */
	{ (uint_t)DKIOCDUMPINIT,	"DKIOCDUMPINIT",
		NULL}, /* 28 */
	{ (uint_t)DKIOCDUMPFINI,	"DKIOCDUMPFINI",
		NULL}, /* 29 */
	{ (uint_t)DKIOCG_PHYGEOM,	"DKIOCG_PHYGEOM",
		"dk_geom"}, /* 32 */
	{ (uint_t)DKIOCG_VIRTGEOM,	"DKIOCG_VIRTGEOM",
		"dk_geom"}, /* 33 */
	{ (uint_t)DKIOCFLUSHWRITECACHE,	"DKIOCFLUSHWRITECACHE",
		NULL}, /* 34 */
	{ (uint_t)DKIOCHOTPLUGGABLE,	"DKIOCHOTPLUGGABLE",
		NULL}, /* 35 */
	{ (uint_t)DKIOCGETWCE,		"DKIOCGETWCE",
		NULL}, /* 36 */
	{ (uint_t)DKIOCSETWCE,		"DKIOCSETWCE",
		NULL}, /* 37 */
	{ (uint_t)DKIOCSOLIDSTATE,	"DKIOCSOLIDSTATE",
		NULL}, /* 38 */
	{ (uint_t)DKIOCGMEDIAINFO,	"DKIOCGMEDIAINFO",
		"dk_minfo"}, /* 42 */
	{ (uint_t)DKIOCGMBOOT,		"DKIOCGMBOOT",
		NULL}, /* 43 */
	{ (uint_t)DKIOCSMBOOT,		"DKIOCSMBOOT",
		NULL}, /* 44 */
	{ (uint_t)DKIOCGTEMPERATURE,	"DKIOCGTEMPERATURE",
		"dk_temperature"}, /* 45 */
	{ (uint_t)DKIOCSETEXTPART,	"DKIOCSETEXTPART",
		NULL}, /* 46 */
	{ (uint_t)DKIOC_GETDISKID,	"DKIOC_GETDISKID",
		"dk_disk_id"}, /* 46 - bug? */
	{ (uint_t)DKIOC_UPDATEFW,	"DKIOC_UPDATEFW",
		"dk_updatefw"}, /* 47 */
	{ (uint_t)DKIOCGMEDIAINFOEXT,	"DKIOCGMEDIAINFOEXT",
		"dk_minfo_ext"}, /* 48 */
	{ (uint_t)DKIOCREADONLY,	"DKIOCREADONLY",
		NULL}, /* 49 */
	{ (uint_t)DKIOCFREE,		"DKIOCFREE",
		"dkioc_free_list_s"}, /* 50 */
	{ (uint_t)DKIOC_CANFREE,	"DKIOC_CANFREE",
		NULL}, /* 60 */

	/* disk ioctls - (0x04 << 8) - fdio.h */
	{ (uint_t)FDIOGCHAR,		"FDIOGCHAR",
		"fd_char"}, /* 51 */
	{ (uint_t)FDIOSCHAR,		"FDIOSCHAR",
		"fd_char"}, /* 52 */
	{ (uint_t)FDEJECT,		"FDEJECT",
		NULL}, /* 53 */
	{ (uint_t)FDGETCHANGE,		"FDGETCHANGE",
		NULL}, /* 54 */
	{ (uint_t)FDGETDRIVECHAR,	"FDGETDRIVECHAR",
		"fd_drive"}, /* 55 */
	{ (uint_t)FDSETDRIVECHAR,	"FDSETDRIVECHAR",
		"fd_drive"}, /* 56 */
	{ (uint_t)FDGETSEARCH,		"FDGETSEARCH",
		NULL}, /* 57 */
	{ (uint_t)FDSETSEARCH,		"FDSETSEARCH",
		NULL}, /* 58 */
	{ (uint_t)FDIOCMD,		"FDIOCMD",
		"fd_cmd"}, /* 59 */
	{ (uint_t)FDRAW,		"FDRAW",
		"fd_raw"}, /* 70 */
	{ (uint_t)FDDEFGEOCHAR,		"FDDEFGEOCHAR",
		NULL}, /* 86 */

	/* disk ioctls - (0x04 << 8) - cdio.h */
	{ (uint_t)CDROMPAUSE,		"CDROMPAUSE",
		NULL}, /* 151 */
	{ (uint_t)CDROMRESUME,		"CDROMRESUME",
		NULL}, /* 152 */
	{ (uint_t)CDROMPLAYMSF,		"CDROMPLAYMSF",
		"cdrom_msf"}, /* 153 */
	{ (uint_t)CDROMPLAYTRKIND,	"CDROMPLAYTRKIND",
		"cdrom_ti"}, /* 154 */
	{ (uint_t)CDROMREADTOCHDR,	"CDROMREADTOCHDR",
		"cdrom_tochdr"}, /* 155 */
	{ (uint_t)CDROMREADTOCENTRY,	"CDROMREADTOCENTRY",
		"cdrom_tocentry"}, /* 156 */
	{ (uint_t)CDROMSTOP,		"CDROMSTOP",
		NULL}, /* 157 */
	{ (uint_t)CDROMSTART,		"CDROMSTART",
		NULL}, /* 158 */
	{ (uint_t)CDROMEJECT,		"CDROMEJECT",
		NULL}, /* 159 */
	{ (uint_t)CDROMVOLCTRL,		"CDROMVOLCTRL",
		"cdrom_volctrl"}, /* 160 */
	{ (uint_t)CDROMSUBCHNL,		"CDROMSUBCHNL",
		"cdrom_subchnl"}, /* 161 */
	{ (uint_t)CDROMREADMODE2,	"CDROMREADMODE2",
		"cdrom_read"}, /* 162 */
	{ (uint_t)CDROMREADMODE1,	"CDROMREADMODE1",
		"cdrom_read"}, /* 163 */
	{ (uint_t)CDROMREADOFFSET,	"CDROMREADOFFSET",
		NULL}, /* 164 */
	{ (uint_t)CDROMGBLKMODE,	"CDROMGBLKMODE",
		NULL}, /* 165 */
	{ (uint_t)CDROMSBLKMODE,	"CDROMSBLKMODE",
		NULL}, /* 166 */
	{ (uint_t)CDROMCDDA,		"CDROMCDDA",
		"cdrom_cdda"}, /* 167 */
	{ (uint_t)CDROMCDXA,		"CDROMCDXA",
		"cdrom_cdxa"}, /* 168 */
	{ (uint_t)CDROMSUBCODE,		"CDROMSUBCODE",
		"cdrom_subcode"}, /* 169 */
	{ (uint_t)CDROMGDRVSPEED,	"CDROMGDRVSPEED",
		NULL}, /* 170 */
	{ (uint_t)CDROMSDRVSPEED,	"CDROMSDRVSPEED",
		NULL}, /* 171 */
	{ (uint_t)CDROMCLOSETRAY,	"CDROMCLOSETRAY",
		NULL}, /* 172 */

	/* disk ioctls - (0x04 << 8) - uscsi.h */
	{ (uint_t)USCSICMD,		"USCSICMD",
		"uscsi_cmd"}, /* 201 */
	{ (uint_t)USCSIMAXXFER,		"USCSIMAXXFER",
		NULL}, /* 202 */
};

const struct ioc dumpadm_ioc[] = { /* 0xdd << 8 */
	/* dumpadm ioctls - (0xdd << 8) */
	{ (uint_t)DIOCGETDUMPSIZE, "DIOCGETDEV", NULL}, /* 0x10 */
	{ (uint_t)DIOCGETCONF, "DIOCGETCONF", NULL}, /* 0x11 */
	{ (uint_t)DIOCSETCONF, "DIOCSETCONF", NULL}, /* 0x12 */
	{ (uint_t)DIOCGETDEV, "DIOCGETDEV", NULL}, /* 0x13 */
	{ (uint_t)DIOCSETDEV, "DIOCSETDEV", NULL}, /* 0x14 */
	{ (uint_t)DIOCTRYDEV, "DIOCTRYDEV", NULL}, /* 0x15 */
	{ (uint_t)DIOCDUMP, "DIOCDUMP", NULL}, /* 0x16 */
	{ (uint_t)DIOCSETUUID, "DIOCSETUUID", NULL}, /* 0x17 */
	{ (uint_t)DIOCGETUUID, "DIOCGETUUID", NULL}, /* 0x18 */
	{ (uint_t)DIOCRMDEV, "DIOCRMDEV", NULL}, /* 0x19 */
};

const struct ioc mnt_ioc[] = { /* 'm' << 8 */
	/* mntio ioctls - ('m' << 8) */
	{ (uint_t)MNTIOC_NMNTS, "MNTIOC_NMNTS", NULL }, /* 1 */
	{ (uint_t)MNTIOC_GETDEVLIST, "MNTIOC_GETDEVLIST", NULL }, /* 2 */
	{ (uint_t)MNTIOC_SETTAG, "MNTIOC_SETTAG", "mnttagdesc" }, /* 3 */
	{ (uint_t)MNTIOC_CLRTAG, "MNTIOC_CLRTAG", "mnttagdesc" }, /* 4 */
	{ (uint_t)MNTIOC_SHOWHIDDEN, "MNTIOC_SHOWHIDDEN", NULL }, /* 6 */
	{ (uint_t)MNTIOC_GETMNTENT, "MNTIOC_GETMNTENT", "mnttab" }, /* 7 */
	{ (uint_t)MNTIOC_GETEXTMNTENT, "MNTIOC_GETEXTMNTENT",
	    "extmnttab" }, /* 8 */
	{ (uint_t)MNTIOC_GETMNTANY, "MNTIOC_GETMNTANY", "mnttab" }, /* 9 */
};

const struct ioc devinfo_ioc[] = { /* 0xdf << 8 */
	/* devinfo ioctls - ('df' << 8) - devinfo_impl.h */
	{ (uint_t)DINFOUSRLD, "DINFOUSRLD", NULL}, /* 80 */
	{ (uint_t)DINFOLODRV, "DINFOLODRV", NULL}, /* 81 */
	{ (uint_t)DINFOIDENT, "DINFOIDENT", NULL}, /* 82 */
};

const struct ioc iptun_ioc[] = { /* 0x454A << 16 */
	{ (uint_t)IPTUN_CREATE,	"IPTUN_CREATE",	"iptun_kparams_t"}, /* 1 */
	{ (uint_t)IPTUN_DELETE,	"IPTUN_DELETE", "datalink_id_t"}, /* 2 */
	{ (uint_t)IPTUN_MODIFY, "IPTUN_MODIFY", "iptun_kparams_t"}, /* 3 */
	{ (uint_t)IPTUN_INFO,	"IPTUN_INFO",	NULL}, /* 4 */
	{ (uint_t)IPTUN_SET_6TO4RELAY, "IPTUN_SET_6TO4RELAY",	NULL}, /* 9 */
	{ (uint_t)IPTUN_GET_6TO4RELAY, "IPTUN_GET_6TO4RELAY",	NULL}, /* 10 */
};

const struct ioc zcons_ioc[] = { /* (('Z' << 24) | ('o' << 16) | ('n' << 8)) */
	/* zcons ioctls */
	{ (uint_t)ZC_HOLDSUBSID,	"ZC_HOLDSUBSID",	NULL }, /* 0 */
	{ (uint_t)ZC_RELEASESUBSID,	"ZC_RELEASESUBSID",	NULL }, /* 1 */
};

const struct ioc hid_ioc[] = { /* 'h' << 8 */
	/* hid ioctls - ('h' << 8) - hid.h */
	{ (uint_t)HIDIOCKMGDIRECT,	"HIDIOCKMGDIRECT",	NULL }, /* 0 */
	{ (uint_t)HIDIOCKMSDIRECT,	"HIDIOCKMSDIRECT",	NULL }, /* 1 */
};

const struct ioc pm_ioc[] = { /* 0 */
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
};

const struct ioc cpuid_ioc[] = { /* (('c'<<24)|('i'<<16)|('d'<<8)) */
	/* cpuid ioctls */
	{ (uint_t)CPUID_GET_HWCAP, "CPUID_GET_HWCAP", NULL }, /* 0 */
	{ (uint_t)CPUID_RDMSR, "CPUID_RDMSR", NULL }, /* 1 */
};

/*
 * Because some IOC codes do overlap, and we are performing linear
 * lookup with first match returned, care must be taken about the order
 * of the array elements.
 */
const struct iocs iocs[] = {
	/* GLDv3 module ioc lists */
	{ .nitems = ARRAY_SIZE(aggr_ioc), .data = aggr_ioc},
	{ .nitems = ARRAY_SIZE(dld_ioc), .data = dld_ioc},
	{ .nitems = ARRAY_SIZE(simnet_ioc), .data = simnet_ioc},
	{ .nitems = ARRAY_SIZE(vnic_ioc), .data = vnic_ioc},
	{ .nitems = ARRAY_SIZE(iptun_ioc), .data = iptun_ioc},

	{ .nitems = ARRAY_SIZE(Tioc), .data = Tioc},
	{ .nitems = ARRAY_SIZE(tioc), .data = tioc},
	{ .nitems = ARRAY_SIZE(pty_ioc), .data = pty_ioc},
	{ .nitems = ARRAY_SIZE(dlpi_ioc), .data = dlpi_ioc},
	{ .nitems = ARRAY_SIZE(ldioc_ioc), .data = ldioc_ioc},
	{ .nitems = ARRAY_SIZE(xioc_ioc), .data = xioc_ioc},
	{ .nitems = ARRAY_SIZE(fio_ioc), .data = fio_ioc},
	{ .nitems = ARRAY_SIZE(fil_ioc), .data = fil_ioc},
	{ .nitems = ARRAY_SIZE(dioc_ioc), .data = dioc_ioc},
	{ .nitems = ARRAY_SIZE(lioc_ioc), .data = lioc_ioc},
	{ .nitems = ARRAY_SIZE(jerq_ioc), .data = jerq_ioc},
	{ .nitems = ARRAY_SIZE(kstat_ioc), .data = kstat_ioc},
	{ .nitems = ARRAY_SIZE(stream_ioc), .data = stream_ioc},
	{ .nitems = ARRAY_SIZE(str_ioc), .data = str_ioc},
	{ .nitems = ARRAY_SIZE(audio_ioc), .data = audio_ioc},
	{ .nitems = ARRAY_SIZE(audiom_ioc), .data = audiom_ioc},
	{ .nitems = ARRAY_SIZE(ossx_ioc), .data = ossx_ioc},
	{ .nitems = ARRAY_SIZE(ossy_ioc), .data = ossy_ioc},
	{ .nitems = ARRAY_SIZE(ossp_ioc), .data = ossp_ioc},
	{ .nitems = ARRAY_SIZE(ossm_ioc), .data = ossm_ioc},
	{ .nitems = ARRAY_SIZE(strredir_ioc), .data = strredir_ioc},
	{ .nitems = ARRAY_SIZE(cpc_ioc), .data = cpc_ioc},
	{ .nitems = ARRAY_SIZE(dp_ioc), .data = dp_ioc},
	{ .nitems = ARRAY_SIZE(p_ioc), .data = p_ioc},
	{ .nitems = ARRAY_SIZE(socket_ioc), .data = socket_ioc},
	{ .nitems = ARRAY_SIZE(routing_ioc), .data = routing_ioc},
	{ .nitems = ARRAY_SIZE(sockio_ioc), .data = sockio_ioc},
	{ .nitems = ARRAY_SIZE(des_ioc), .data = des_ioc},
	{ .nitems = ARRAY_SIZE(prn_ioc), .data = prn_ioc},
	{ .nitems = ARRAY_SIZE(dtrace_ioc), .data = dtrace_ioc},
	{ .nitems = ARRAY_SIZE(dtraceh_ioc), .data = dtraceh_ioc},
	{ .nitems = ARRAY_SIZE(crypto_ioc), .data = crypto_ioc},
	{ .nitems = ARRAY_SIZE(kbd_ioc), .data = kbd_ioc},
	{ .nitems = ARRAY_SIZE(ptm_ioc), .data = ptm_ioc},
	{ .nitems = ARRAY_SIZE(zfs_ioc), .data = zfs_ioc},
	{ .nitems = ARRAY_SIZE(dkio_ioc), .data = dkio_ioc},
	{ .nitems = ARRAY_SIZE(dumpadm_ioc), .data = dumpadm_ioc},
	{ .nitems = ARRAY_SIZE(mnt_ioc), .data = mnt_ioc},
	{ .nitems = ARRAY_SIZE(devinfo_ioc), .data = devinfo_ioc},
	{ .nitems = ARRAY_SIZE(zcons_ioc), .data = zcons_ioc},
	{ .nitems = ARRAY_SIZE(hid_ioc), .data = hid_ioc},
	{ .nitems = ARRAY_SIZE(cpuid_ioc), .data = cpuid_ioc},
	{ .nitems = ARRAY_SIZE(pm_ioc), .data = pm_ioc},
	{ .nitems = 0, .data = NULL }
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

static const struct ioc *
find_ioc(const struct iocs *iocs, uint_t code)
{
	const struct iocs *ptr;
	const struct ioc *ip;

	for (ptr = &iocs[0]; ptr->nitems > 0; ptr++) {
		/* search for "close enough" table */
		if ((ptr->data->code & 0xffff0000) != (code & 0xffff0000) &&
		    (ptr->data->code & 0xffff00) != (code & 0xffff00) &&
		    (ptr->data->code & IOCTYPE) != (code & IOCTYPE)) {
			continue;
		}

		ip = ptr->data;
		for (uint_t i = 0; i < ptr->nitems; i++) {
			/* Do exact match there */
			if (code == ip[i].code)
				return (&ip[i]);
		}
	}

	return (NULL);
}

const char *
ioctlname(private_t *pri, uint_t code)
{
	const struct ioc *ip;
	const char *str = NULL;

	ip = find_ioc(vmm_iocs, code);
	if (ip == NULL)
		ip = find_ioc(iocs, code);

	if (ip != NULL)
		str = ip->name;
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

	ip = find_ioc(vmm_iocs, code);
	if (ip == NULL)
		ip = find_ioc(iocs, code);

	if (ip != NULL)
		str = ip->datastruct;
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

#if defined(__x86)
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
	case SI86V86:		str = "SI86V86";	break;
	case SI86SLTIME:	str = "SI86SLTIME";	break;
	case SI86DSCR:		str = "SI86DSCR";	break;
	case RDUBLK:		str = "RDUBLK";		break;
/* NFA entry point */
	case SI86NFA:		str = "SI86NFA";	break;
	case SI86VM86:		str = "SI86VM86";	break;
	case SI86VMENABLE:	str = "SI86VMENABLE";	break;
	case SI86LIMUSER:	str = "SI86LIMUSER";	break;
	case SI86RDID:		str = "SI86RDID";	break;
	case SI86RDBOOT:	str = "SI86RDBOOT";	break;
/* Merged Product defines */
	case SI86SHFIL:		str = "SI86SHFIL";	break;
	case SI86PCHRGN:	str = "SI86PCHRGN";	break;
	case SI86BADVISE:	str = "SI86BADVISE";	break;
	case SI86SHRGN:		str = "SI86SHRGN";	break;
	case SI86CHIDT:		str = "SI86CHIDT";	break;
	case SI86EMULRDA:	str = "SI86EMULRDA";	break;
/* RTC commands */
	case WTODC:		str = "WTODC";		break;
	case SGMTL:		str = "SGMTL";		break;
	case GGMTL:		str = "GGMTL";		break;
	case RTCSYNC:		str = "RTCSYNC";	break;
	}
#endif /* __x86 */

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
	|O_CLOEXEC|O_DIRECTORY|O_DIRECT|FXATTRDIROPEN)

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
	if (arg & O_DIRECTORY)
		(void) strlcat(str, "|O_DIRECTORY", sizeof (pri->code_buf));
	if (arg & O_DIRECT)
		(void) strlcat(str, "|O_DIRECT", sizeof (pri->code_buf));
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
