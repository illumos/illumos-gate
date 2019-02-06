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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ks.h>

#include <ctype.h>
#include <sys/types.h>
#include <sys/strsubr.h>
#include <sys/stream.h>
#include <sys/modctl.h>
#include <sys/strft.h>
#include <sys/strsun.h>
#include <sys/sysmacros.h>

#include "streams.h"

typedef struct str_flags {
	uint_t strf_flag;
	const char *strf_name;
	const char *strf_descr;
} strflags_t;

typedef struct str_types {
	const char *strt_name;
	int strt_value;
	const char *strt_descr;
} strtypes_t;

typedef struct ftblk_data {
	ftblk_t ft_data;	/* Copy of ftblk */
	int	ft_ix;		/* Index in event list */
	boolean_t ft_in_evlist;	/* Iterating through evlist */
} ftblkdata_t;

typedef void qprint_func(queue_t *, queue_t *);
typedef void sdprint_func(stdata_t *, stdata_t *);

#define	SF(flag)	flag, #flag

/*
 * Queue flags
 */
static const strflags_t qf[] = {
	{ SF(QENAB),		"Queue is already enabled to run"	},
	{ SF(QWANTR),		"Someone wants to read Q"		},
	{ SF(QWANTW),		"Someone wants to write Q"		},
	{ SF(QFULL),		"Q is considered full"			},
	{ SF(QREADR),		"This is the reader (first) Q"		},
	{ SF(QUSE),		"This queue in use (allocation)"	},
	{ SF(QNOENB),		"Don't enable Q via putq"		},
	{ SF(QWANTRMQSYNC),	"Want to remove sync stream Q"		},
	{ SF(QBACK),		"queue has been back-enabled"		},
	{ SF(0x00000200),	"unused (was QHLIST)"			},
	{ SF(0x00000400),	"unused (was QUNSAFE)"			},
	{ SF(QPAIR),		"per queue-pair syncq"			},
	{ SF(QPERQ),		"per queue-instance syncq"		},
	{ SF(QPERMOD),		"per module syncq"			},
	{ SF(QMTSAFE),		"stream module is MT-safe"		},
	{ SF(QMTOUTPERIM),	"Has outer perimeter"			},
	{ SF(QINSERVICE),	"service routine executing"		},
	{ SF(QWCLOSE),		"will not be enabled"			},
	{ SF(QEND),		"last queue in stream"			},
	{ SF(QWANTWSYNC),	"Streamhead wants to write Q"		},
	{ SF(QSYNCSTR),		"Q supports Synchronous STREAMS"	},
	{ SF(QISDRV),		"the Queue is attached to a driver"	},
	{ SF(0x00400000),	"unused (was QHOT)"			},
	{ SF(0x00800000),	"unused (was QNEXTHOT)"			},
	{ SF(0x01000000),	"unused (was _QNEXTLESS)"		},
	{ SF(0x02000000),	"unused"				},
	{ SF(_QINSERTING),	"module is inserted with _I_INSERT"	},
	{ SF(_QREMOVING)	"module is removed with _I_REMOVE"	},
	{ SF(_QASSOCIATED),	"queue is associated with a device"	},
	{ 0, NULL,		NULL					}
};

/*
 * Syncq flags
 */
static const struct str_flags sqf[] = {
	{ SF(SQ_EXCL),		"Exclusive access to inner perimeter"	},
	{ SF(SQ_BLOCKED),	"qprocsoff in progress"			},
	{ SF(SQ_FROZEN),	"freezestr in progress"			},
	{ SF(SQ_WRITER),	"qwriter(OUTER) pending or running"	},
	{ SF(SQ_MESSAGES),	"There are messages on syncq"		},
	{ SF(SQ_WANTWAKEUP)	"Thread waiting on sq_wait"		},
	{ SF(SQ_WANTEXWAKEUP),	"Thread waiting on sq_exwait"		},
	{ SF(SQ_EVENTS),	"There are events on syncq"		},
	{ 0, NULL,		NULL					}
};

/*
 * Syncq types
 */
static const struct str_flags sqt[] = {
	{ SF(SQ_CIPUT),		"Concurrent inner put procedure"	},
	{ SF(SQ_CISVC),		"Concurrent inner svc procedure"	},
	{ SF(SQ_CIOC),		"Concurrent inner open/close"		},
	{ SF(SQ_CICB),		"Concurrent inner callback"		},
	{ SF(SQ_COPUT),		"Concurrent outer put procedure"	},
	{ SF(SQ_COSVC),		"Concurrent outer svc procedure"	},
	{ SF(SQ_COOC),		"Concurrent outer open/close"		},
	{ SF(SQ_COCB),		"Concurrent outer callback"		},
	{ 0, NULL,		NULL					}
};

/*
 * Stdata flags
 */
static const struct str_flags stdf[] = {
	{ SF(IOCWAIT),		"someone is doing an ioctl"		},
	{ SF(RSLEEP),		"someone wants to read/recv msg"	},
	{ SF(WSLEEP),		"someone wants to write"		},
	{ SF(STRPRI),		"an M_PCPROTO is at stream head"	},
	{ SF(STRHUP),		"device has vanished"			},
	{ SF(STWOPEN),		"waiting for 1st open"			},
	{ SF(STPLEX),		"stream is being multiplexed"		},
	{ SF(STRISTTY),		"stream is a terminal"			},
	{ SF(STRGETINPROG),	"(k)strgetmsg is running"		},
	{ SF(IOCWAITNE),	"STR_NOERROR ioctl running"		},
	{ SF(STRDERR),		"fatal read error from M_ERROR"		},
	{ SF(STWRERR),		"fatal write error from M_ERROR"	},
	{ SF(STRDERRNONPERSIST), "nonpersistent read errors"		},
	{ SF(STWRERRNONPERSIST), "nonpersistent write errors"		},
	{ SF(STRCLOSE),		"wait for a close to complete"		},
	{ SF(SNDMREAD),		"used for read notification"		},
	{ SF(OLDNDELAY),	"use old NDELAY TTY semantics"		},
	{ SF(0x00020000),	"unused"				},
	{ SF(0x00040000),	"unused"				},
	{ SF(STRTOSTOP),	"block background writes"		},
	{ SF(STRCMDWAIT),	"someone is doing an _I_CMD"		},
	{ SF(0x00200000),	"unused"				},
	{ SF(STRMOUNT),		"stream is mounted"			},
	{ SF(STRNOTATMARK),	"Not at mark (when empty read q)"	},
	{ SF(STRDELIM),		"generate delimited messages"		},
	{ SF(STRATMARK),	"at mark (due to MSGMARKNEXT)"		},
	{ SF(STZCNOTIFY),	"wait for zerocopy mblk to be acked"	},
	{ SF(STRPLUMB),		"stream plumbing changes in progress"	},
	{ SF(STREOF),		"End-of-file indication"		},
	{ SF(STREOPENFAIL),	"re-open has failed"			},
	{ SF(STRMATE),		"this stream is a mate"			},
	{ SF(STRHASLINKS),	"there are I_LINKs under this stream"	},
	{ 0, NULL,		NULL					}
};

static const struct str_flags mbf[] = {
	{ SF(MSGMARK),		"last byte of message is marked"	},
	{ SF(MSGNOLOOP),	"don't loop message to write side"	},
	{ SF(MSGDELIM),		"message is delimited"			},
	{ SF(0x08),		"unused"				},
	{ SF(MSGMARKNEXT),	"Private: b_next's first byte marked"	},
	{ SF(MSGNOTMARKNEXT),	"Private: ... not marked"		},
	{ 0, NULL,		NULL					}
};

#define	M_DATA_T 0xff

static const strtypes_t mbt[] = {
	{ "M_DATA",	M_DATA_T,	"regular data"			},
	{ "M_PROTO",	M_PROTO,	"protocol control"		},
	{ "M_MULTIDATA", M_MULTIDATA,	"multidata"			},
	{ "M_BREAK",	M_BREAK,	"line break"			},
	{ "M_PASSFP",	M_PASSFP,	"pass file pointer"		},
	{ "M_EVENT",	M_EVENT,	"Obsoleted: do not use"		},
	{ "M_SIG",	M_SIG,		"generate process signal"	},
	{ "M_DELAY",	M_DELAY,	"real-time xmit delay"		},
	{ "M_CTL",	M_CTL,		"device-specific control message" },
	{ "M_IOCTL",	M_IOCTL,	"ioctl; set/get params"		},
	{ "M_SETOPTS",	M_SETOPTS,	"set stream head options"	},
	{ "M_RSE",	M_RSE,		"reserved for RSE use only"	},
	{ "M_IOCACK",	M_IOCACK,	"acknowledge ioctl"		},
	{ "M_IOCNAK",	M_IOCNAK,	"negative ioctl acknowledge"	},
	{ "M_PCPROTO",	M_PCPROTO,	"priority proto message"	},
	{ "M_PCSIG",	M_PCSIG,	"generate process signal"	},
	{ "M_READ",	M_READ,		"generate read notification"	},
	{ "M_FLUSH",	M_FLUSH,	"flush your queues"		},
	{ "M_STOP",	M_STOP,		"stop transmission immediately" },
	{ "M_START",	M_START,	"restart transmission after stop" },
	{ "M_HANGUP",	M_HANGUP,	"line disconnect"		},
	{ "M_ERROR",	M_ERROR,	"send error to stream head"	},
	{ "M_COPYIN",	M_COPYIN,	"request to copyin data"	},
	{ "M_COPYOUT",	M_COPYOUT,	"request to copyout data"	},
	{ "M_IOCDATA",	M_IOCDATA,	"response to M_COPYIN and M_COPYOUT" },
	{ "M_PCRSE",	M_PCRSE,	"reserved for RSE use only"	},
	{ "M_STOPI",	M_STOPI,	"stop reception immediately"	},
	{ "M_STARTI",	M_STARTI,	"restart reception after stop"	},
	{ "M_PCEVENT",	M_PCEVENT,	"Obsoleted: do not use"		},
	{ "M_UNHANGUP",	M_UNHANGUP,	"line reconnect"		},
	{ "M_CMD",	M_CMD,		"out-of-band ioctl command"	},
	{ NULL,		0,		NULL				}
};

/* Allocation flow trace events, starting from 0 */
static const char *ftev_alloc[] = {
/* 0 */	"allocb",
/* 1 */	"esballoc",
/* 2 */	"desballoc",
/* 3 */	"esballoca",
/* 4 */	"desballoca",
/* 5 */	"allocbig",
/* 6 */	"allocbw",
/* 7 */	"bcallocb",
/* 8 */	"freeb",
/* 9 */	"dupb",
/* A */	"copyb",
};

#define	FTEV_PROC_START FTEV_PUT

/* Procedures recorded by flow tracing, starting from 0x100 */
static const char *ftev_proc[] = {
/* 100 */	"put",
/* 101 */	"0x101",
/* 102 */	"0x102",
/* 103 */	"0x103",
/* 104 */	"0x104",
/* 105 */	"putq",
/* 106 */	"getq",
/* 107 */	"rmvq",
/* 108 */	"insq",
/* 109 */	"putbq",
/* 10A */	"flushq",
/* 10B */	"0x10b",
/* 10C */	"0x10c",
/* 10D */	"putnext",
/* 10E */	"rwnext",
};

static const char *db_control_types[] = {
/* 00 */	"data",
/* 01 */	"proto",
/* 02 */	"multidata",
/* 03 */	"0x03",
/* 04 */	"0x04",
/* 05 */	"0x05",
/* 06 */	"0x06",
/* 07 */	"0x07",
/* 08 */	"break",
/* 09 */	"passfp",
/* 0a */	"event",
/* 0b */	"sig",
/* 0c */	"delay",
/* 0d */	"ctl",
/* 0e */	"ioctl",
/* 0f */	"unused",
/* 10 */	"setopts",
/* 11 */	"rse",
};

static const char *db_control_hipri_types[] = {
/* 81 */	"iocack",
/* 82 */	"iocnak",
/* 83 */	"pcproto",
/* 84 */	"pcsig",
/* 85 */	"read",
/* 86 */	"flush",
/* 87 */	"stop",
/* 88 */	"start",
/* 89 */	"hangup",
/* 8a */	"error",
/* 8b */	"copyin",
/* 8c */	"copyout",
/* 8d */	"iocdata",
/* 8e */	"pcrse",
/* 8f */	"stopi",
/* 90 */	"starti",
/* 91 */	"pcevent",
/* 92 */	"unhangup",
/* 93 */	"cmd",
};

#define	A_SIZE(a) (sizeof (a) / sizeof (a[0]))

static void ft_printevent(ushort_t);

static int
streams_parse_flag(const strflags_t ftable[], const char *arg, uint32_t *flag)
{
	int i;

	for (i = 0; ftable[i].strf_name != NULL; i++) {
		if (strcasecmp(arg, ftable[i].strf_name) == 0) {
			*flag |= (1 << i);
			return (0);
		}
	}

	return (-1);
}

static void
streams_flag_usage(const strflags_t ftable[])
{
	int i;

	for (i = 0; ftable[i].strf_name != NULL; i++)
		mdb_printf("%-14s %s\n",
		    ftable[i].strf_name, ftable[i].strf_descr);
}

static int
streams_parse_type(const strtypes_t ftable[], const char *arg, uint32_t *flag)
{
	int i;

	for (i = 0; ftable[i].strt_name != NULL; i++) {
		if (strcasecmp(arg, ftable[i].strt_name) == 0) {
			*flag = ftable[i].strt_value;
			return (0);
		}
	}

	return (-1);
}

static void
streams_type_usage(const strtypes_t ftable[])
{
	int i;

	for (i = 0; ftable[i].strt_name != NULL; i++)
		mdb_printf("%-12s %s\n",
		    ftable[i].strt_name, ftable[i].strt_descr);
}

int
queue(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	const int QUEUE_FLGDELT = (int)(sizeof (uintptr_t) * 2 + 15);

	char name[MODMAXNAMELEN];
	int nblks = 0;
	uintptr_t maddr;
	mblk_t mblk;
	queue_t q;

	const char *mod = NULL, *flag = NULL, *not_flag = NULL;
	uint_t quiet = FALSE;
	uint_t verbose = FALSE;
	uint32_t mask = 0, not_mask = 0;
	uintptr_t syncq = 0;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("genunix`queue_cache", "genunix`queue",
		    argc, argv) == -1) {
			mdb_warn("failed to walk queue cache");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (flags & DCMD_PIPE_OUT)
		quiet = TRUE;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose,
	    'q', MDB_OPT_SETBITS, TRUE, &quiet,
	    'm', MDB_OPT_STR, &mod,
	    'f', MDB_OPT_STR, &flag,
	    'F', MDB_OPT_STR, &not_flag,
	    's', MDB_OPT_UINTPTR, &syncq,
	    NULL) != argc)
		return (DCMD_USAGE);

	/*
	 * If any of the filtering flags is specified, don't print anything
	 * except the matching pointer.
	 */
	if (flag != NULL || not_flag != NULL || mod != NULL || syncq != 0)
		quiet = TRUE;

	if (DCMD_HDRSPEC(flags) && !quiet) {
		mdb_printf("%?s %-13s %6s %4s\n",
		    "ADDR", "MODULE", "FLAGS", "NBLK");
	}

	if (flag != NULL && streams_parse_flag(qf, flag, &mask) == -1) {
		mdb_warn("unrecognized queue flag '%s'\n", flag);
		streams_flag_usage(qf);
		return (DCMD_USAGE);
	}

	if (not_flag != NULL &&
	    streams_parse_flag(qf, not_flag, &not_mask) == -1) {
		mdb_warn("unrecognized queue flag '%s'\n", flag);
		streams_flag_usage(qf);
		return (DCMD_USAGE);
	}

	if (mdb_vread(&q, sizeof (q), addr) == -1) {
		mdb_warn("couldn't read queue at %p", addr);
		return (DCMD_ERR);
	}

	for (maddr = (uintptr_t)q.q_first; maddr != 0; nblks++) {
		if (mdb_vread(&mblk, sizeof (mblk), maddr) == -1) {
			mdb_warn("couldn't read mblk %p for queue %p",
			    maddr, addr);
			break;
		}
		maddr = (uintptr_t)mblk.b_next;
	}

	(void) mdb_qname(&q, name, sizeof (name));

	/*
	 * If queue doesn't pass filtering criteria, don't print anything and
	 * just return.
	 */

	if (mod != NULL && strcmp(mod, name) != 0)
		return (DCMD_OK);

	if (mask != 0 && !(q.q_flag & mask))
		return (DCMD_OK);

	if (not_mask != 0 && (q.q_flag & not_mask))
		return (DCMD_OK);

	if (syncq != 0 && q.q_syncq != (syncq_t *)syncq)
		return (DCMD_OK);

	/*
	 * Options are specified for filtering, so If any option is specified on
	 * the command line, just print address and exit.
	 */
	if (quiet) {
		mdb_printf("%0?p\n", addr);
		return (DCMD_OK);
	}

	mdb_printf("%0?p %-13s %06x %4d %0?p\n",
	    addr, name, q.q_flag, nblks, q.q_first);

	if (verbose) {
		int i, arm = 0;

		for (i = 0; qf[i].strf_name != NULL; i++) {
			if (!(q.q_flag & (1 << i)))
				continue;
			if (!arm) {
				mdb_printf("%*s|\n%*s+-->  ",
				    QUEUE_FLGDELT, "", QUEUE_FLGDELT, "");
				arm = 1;
			} else
				mdb_printf("%*s      ", QUEUE_FLGDELT, "");

			mdb_printf("%-12s %s\n",
			    qf[i].strf_name, qf[i].strf_descr);
		}
	}

	return (DCMD_OK);
}

int
syncq(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	const int SYNC_FLGDELT = (int)(sizeof (uintptr_t) * 2 + 1);
	const int SYNC_TYPDELT = (int)(sizeof (uintptr_t) * 2 + 5);
	syncq_t sq;

	const char *flag = NULL, *not_flag = NULL;
	const char *typ = NULL, *not_typ = NULL;
	uint_t verbose = FALSE;
	uint_t quiet = FALSE;
	uint32_t mask = 0, not_mask = 0;
	uint32_t tmask = 0, not_tmask = 0;
	uint8_t sqtype = 0;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("genunix`syncq_cache", "genunix`syncq",
		    argc, argv) == -1) {
			mdb_warn("failed to walk syncq cache");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (flags & DCMD_PIPE_OUT)
		quiet = TRUE;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose,
	    'q', MDB_OPT_SETBITS, TRUE, &quiet,
	    'f', MDB_OPT_STR, &flag,
	    'F', MDB_OPT_STR, &not_flag,
	    't', MDB_OPT_STR, &typ,
	    'T', MDB_OPT_STR, &not_typ,
	    NULL) != argc)
		return (DCMD_USAGE);

	/*
	 * If any of the filtering flags is specified, don't print anything
	 * except the matching pointer.
	 */
	if (flag != NULL || not_flag != NULL || typ != NULL || not_typ != NULL)
		quiet = TRUE;

	if (DCMD_HDRSPEC(flags) && !quiet) {
		mdb_printf("%?s %s %s %s %s %?s %s %s\n",
		    "ADDR", "FLG", "TYP", "CNT", "NQS", "OUTER", "SF", "PRI");
	}

	if (flag != NULL && streams_parse_flag(sqf, flag, &mask) == -1) {
		mdb_warn("unrecognized syncq flag '%s'\n", flag);
		streams_flag_usage(sqf);
		return (DCMD_USAGE);
	}

	if (typ != NULL && streams_parse_flag(sqt, typ, &tmask) == -1) {
		mdb_warn("unrecognized syncq type '%s'\n", typ);
		streams_flag_usage(sqt);
		return (DCMD_USAGE);
	}

	if (not_flag != NULL && streams_parse_flag(sqf, not_flag, &not_mask)
	    == -1) {
		mdb_warn("unrecognized syncq flag '%s'\n", not_flag);
		streams_flag_usage(sqf);
		return (DCMD_USAGE);
	}

	if (not_typ != NULL && streams_parse_flag(sqt, not_typ, &not_tmask)
	    == -1) {
		mdb_warn("unrecognized syncq type '%s'\n", not_typ);
		streams_flag_usage(sqt);
		return (DCMD_USAGE);
	}

	if (mdb_vread(&sq, sizeof (sq), addr) == -1) {
		mdb_warn("couldn't read syncq at %p", addr);
		return (DCMD_ERR);
	}

	if (mask != 0 && !(sq.sq_flags & mask))
		return (DCMD_OK);

	if (not_mask != 0 && (sq.sq_flags & not_mask))
		return (DCMD_OK);

	sqtype = (sq.sq_type >> 8) & 0xff;

	if (tmask != 0 && !(sqtype & tmask))
		return (DCMD_OK);

	if (not_tmask != 0 && (sqtype & not_tmask))
		return (DCMD_OK);

	/*
	 * Options are specified for filtering, so If any option is specified on
	 * the command line, just print address and exit.
	 */
	if (quiet) {
		mdb_printf("%0?p\n", addr);
		return (DCMD_OK);
	}

	mdb_printf("%0?p %02x  %02x  %-3u %-3u %0?p  %1x %-3d\n",
	    addr, sq.sq_flags & 0xff, sqtype, sq.sq_count,
	    sq.sq_nqueues, sq.sq_outer, sq.sq_svcflags, sq.sq_pri);

	if (verbose) {
		int i, arm = 0;

		for (i = 0; sqf[i].strf_name != NULL; i++) {
			if (!(sq.sq_flags & (1 << i)))
				continue;
			if (!arm) {
				mdb_printf("%*s|\n%*s+-->  ",
				    SYNC_FLGDELT, "", SYNC_FLGDELT, "");
				arm = 1;
			} else
				mdb_printf("%*s      ", SYNC_FLGDELT, "");

			mdb_printf("%-12s %s\n",
			    sqf[i].strf_name, sqf[i].strf_descr);
		}

		for (i = 0; sqt[i].strf_name != NULL; i++) {
			if (!(sqtype & (1 << i)))
				continue;
			if (!arm) {
				mdb_printf("%*s|\n%*s+-->  ",
				    SYNC_TYPDELT, "", SYNC_TYPDELT, "");
				arm = 1;
			} else
				mdb_printf("%*s      ", SYNC_TYPDELT, "");

			mdb_printf("%-12s %s\n",
			    sqt[i].strf_name, sqt[i].strf_descr);
		}
	}

	return (DCMD_OK);
}

int
stdata(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	const int STREAM_FLGDELT = (int)(sizeof (uintptr_t) * 2 + 10);

	stdata_t  sd;

	const char *flag = NULL, *not_flag = NULL;
	uint_t verbose = FALSE;
	uint_t quiet = FALSE;
	uint32_t mask = 0, not_mask = 0;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("genunix`stream_head_cache",
		    "genunix`stdata", argc, argv) == -1) {
			mdb_warn("failed to walk stream head cache");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (flags & DCMD_PIPE_OUT)
		quiet = TRUE;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose,
	    'q', MDB_OPT_SETBITS, TRUE, &quiet,
	    'f', MDB_OPT_STR, &flag,
	    'F', MDB_OPT_STR, &not_flag,
	    NULL) != argc)
		return (DCMD_USAGE);

	/*
	 * If any of the filtering flags is specified, don't print anything
	 * except the matching pointer.
	 */
	if (flag != NULL || not_flag != NULL)
		quiet = TRUE;

	if (DCMD_HDRSPEC(flags) && !quiet) {
		mdb_printf("%?s %?s %8s %?s %s %s\n",
		    "ADDR", "WRQ", "FLAGS", "VNODE", "N/A", "REF");
	}

	if (flag != NULL && streams_parse_flag(stdf, flag, &mask) == -1) {
		mdb_warn("unrecognized stream flag '%s'\n", flag);
		streams_flag_usage(stdf);
		return (DCMD_USAGE);
	}

	if (not_flag != NULL &&
	    streams_parse_flag(stdf, not_flag, &not_mask) == -1) {
		mdb_warn("unrecognized stream flag '%s'\n", flag);
		streams_flag_usage(stdf);
		return (DCMD_USAGE);
	}

	if (mdb_vread(&sd, sizeof (sd), addr) == -1) {
		mdb_warn("couldn't read stdata at %p", addr);
		return (DCMD_ERR);
	}

	/*
	 * If stream doesn't pass filtering criteria, don't print anything and
	 * just return.
	 */

	if (mask != 0 && !(sd.sd_flag & mask))
		return (DCMD_OK);

	if (not_mask != 0 && (sd.sd_flag & not_mask))
		return (DCMD_OK);

	/*
	 * Options are specified for filtering, so If any option is specified on
	 * the command line, just print address and exit.
	 */
	if (quiet) {
		mdb_printf("%0?p\n", addr);
		return (DCMD_OK);
	}

	mdb_printf("%0?p %0?p %08x %0?p %d/%d %d\n",
	    addr, sd.sd_wrq, sd.sd_flag, sd.sd_vnode,
	    sd.sd_pushcnt, sd.sd_anchor, sd.sd_refcnt);

	if (verbose) {
		int i, arm = 0;

		for (i = 0; stdf[i].strf_name != NULL; i++) {
			if (!(sd.sd_flag & (1 << i)))
				continue;
			if (!arm) {
				mdb_printf("%*s|\n%*s+-->  ",
				    STREAM_FLGDELT, "", STREAM_FLGDELT, "");
				arm = 1;
			} else
				mdb_printf("%*s      ", STREAM_FLGDELT, "");

			mdb_printf("%-12s %s\n",
			    stdf[i].strf_name, stdf[i].strf_descr);
		}
	}

	return (DCMD_OK);
}

/*ARGSUSED*/
static void
qprint_syncq(queue_t *addr, queue_t *q)
{
	mdb_printf("%p\n", q->q_syncq);
}

/*ARGSUSED*/
static void
qprint_stream(queue_t *addr, queue_t *q)
{
	mdb_printf("%p\n", q->q_stream);
}

static void
qprint_wrq(queue_t *addr, queue_t *q)
{
	mdb_printf("%p\n", ((q)->q_flag & QREADR? (addr)+1: (addr)));
}

static void
qprint_rdq(queue_t *addr, queue_t *q)
{
	mdb_printf("%p\n", ((q)->q_flag & QREADR? (addr): (addr)-1));
}

static void
qprint_otherq(queue_t *addr, queue_t *q)
{
	mdb_printf("%p\n", ((q)->q_flag & QREADR? (addr)+1: (addr)-1));
}

static int
q2x(uintptr_t addr, int argc, qprint_func prfunc)
{
	queue_t q;

	if (argc != 0)
		return (DCMD_USAGE);

	if (mdb_vread(&q, sizeof (q), addr) == -1) {
		mdb_warn("couldn't read queue at %p", addr);
		return (DCMD_ERR);
	}

	prfunc((queue_t *)addr, &q);

	return (DCMD_OK);
}

/*ARGSUSED*/
int
q2syncq(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (q2x(addr, argc, qprint_syncq));
}

/*ARGSUSED*/
int
q2stream(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (q2x(addr, argc, qprint_stream));
}

/*ARGSUSED*/
int
q2rdq(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (q2x(addr, argc, qprint_rdq));
}

/*ARGSUSED*/
int
q2wrq(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (q2x(addr, argc, qprint_wrq));
}

/*ARGSUSED*/
int
q2otherq(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (q2x(addr, argc, qprint_otherq));
}

static int
sd2x(uintptr_t addr, int argc, sdprint_func prfunc)
{
	stdata_t sd;

	if (argc != 0)
		return (DCMD_USAGE);

	if (mdb_vread(&sd, sizeof (sd), addr) == -1) {
		mdb_warn("couldn't read stream head at %p", addr);
		return (DCMD_ERR);
	}

	prfunc((stdata_t *)addr, &sd);

	return (DCMD_OK);
}

/*ARGSUSED*/
static void
sdprint_wrq(stdata_t *addr, stdata_t *sd)
{
	mdb_printf("%p\n", sd->sd_wrq);
}

static void
sdprint_mate(stdata_t *addr, stdata_t *sd)
{
	mdb_printf("%p\n", sd->sd_mate ? sd->sd_mate : addr);
}

/*ARGSUSED*/
int
str2mate(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (sd2x(addr, argc, sdprint_mate));
}

/*ARGSUSED*/
int
str2wrq(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (sd2x(addr, argc, sdprint_wrq));
}

/*
 * If this syncq is a part of the queue pair structure, find the queue for it.
 */
/*ARGSUSED*/
int
syncq2q(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	syncq_t sq;
	queue_t q;
	queue_t *qp;

	if (argc != 0)
		return (DCMD_USAGE);

	if (mdb_vread(&sq, sizeof (sq), addr) == -1) {
		mdb_warn("couldn't read syncq at %p", addr);
		return (DCMD_ERR);
	}

	/* Try to find its queue */
	qp = (queue_t *)addr - 2;

	if ((mdb_vread(&q, sizeof (q), (uintptr_t)qp) == -1) ||
	    (q.q_syncq != (syncq_t *)addr)) {
		mdb_warn("syncq2q: %p is not part of any queue\n", addr);
		return (DCMD_ERR);
	} else
		mdb_printf("%p\n", qp);

	return (DCMD_OK);
}

int
queue_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == 0 &&
	    mdb_readvar(&wsp->walk_addr, "qhead") == -1) {
		mdb_warn("failed to read 'qhead'");
		return (WALK_ERR);
	}

	wsp->walk_data = mdb_alloc(sizeof (queue_t), UM_SLEEP);
	return (WALK_NEXT);
}

int
queue_link_step(mdb_walk_state_t *wsp)
{
	int status;

	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	if (mdb_vread(wsp->walk_data, sizeof (queue_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to read queue at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)(((queue_t *)wsp->walk_data)->q_link);
	return (status);
}

int
queue_next_step(mdb_walk_state_t *wsp)
{
	int status;

	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	if (mdb_vread(wsp->walk_data, sizeof (queue_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to read queue at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)(((queue_t *)wsp->walk_data)->q_next);
	return (status);
}

void
queue_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (queue_t));
}

int
str_walk_init(mdb_walk_state_t *wsp)
{
	stdata_t s;

	if (wsp->walk_addr == 0) {
		mdb_warn("walk must begin at address of stdata_t\n");
		return (WALK_ERR);
	}

	if (mdb_vread(&s, sizeof (s), wsp->walk_addr) == -1) {
		mdb_warn("failed to read stdata at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)s.sd_wrq;
	wsp->walk_data = mdb_alloc(sizeof (queue_t) * 2, UM_SLEEP);

	return (WALK_NEXT);
}

int
strr_walk_step(mdb_walk_state_t *wsp)
{
	queue_t *rq = wsp->walk_data, *wq = rq + 1;
	int status;

	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	if (mdb_vread(wsp->walk_data, sizeof (queue_t) * 2,
	    wsp->walk_addr - sizeof (queue_t)) == -1) {
		mdb_warn("failed to read queue pair at %p",
		    wsp->walk_addr - sizeof (queue_t));
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr - sizeof (queue_t),
	    rq, wsp->walk_cbdata);

	if (wq->q_next != NULL)
		wsp->walk_addr = (uintptr_t)wq->q_next;
	else
		wsp->walk_addr = mdb_qwnext(wq);

	return (status);
}

int
strw_walk_step(mdb_walk_state_t *wsp)
{
	queue_t *rq = wsp->walk_data, *wq = rq + 1;
	int status;

	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	if (mdb_vread(wsp->walk_data, sizeof (queue_t) * 2,
	    wsp->walk_addr - sizeof (queue_t)) == -1) {
		mdb_warn("failed to read queue pair at %p",
		    wsp->walk_addr - sizeof (queue_t));
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, wq, wsp->walk_cbdata);

	if (wq->q_next != NULL)
		wsp->walk_addr = (uintptr_t)wq->q_next;
	else
		wsp->walk_addr = mdb_qwnext(wq);

	return (status);
}

void
str_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (queue_t) * 2);
}

static int
print_qpair(uintptr_t addr, const queue_t *q, uint_t *depth)
{
	static const char box_lid[] =
	    "+-----------------------+-----------------------+\n";
	static const char box_sep[] =
	    "|                       |                       |\n";

	char wname[32], rname[32], info1[256], *info2;

	if (*depth != 0) {
		mdb_printf("            |                       ^\n");
		mdb_printf("            v                       |\n");
	} else
		mdb_printf("\n");

	(void) mdb_qname(_WR(q), wname, sizeof (wname));
	(void) mdb_qname(_RD(q), rname, sizeof (rname));

	mdb_qinfo(_WR(q), info1, sizeof (info1));
	if ((info2 = strchr(info1, '\n')) != NULL)
		*info2++ = '\0';
	else
		info2 = "";

	mdb_printf(box_lid);
	mdb_printf("| 0x%-19p | 0x%-19p | %s\n",
	    addr, addr - sizeof (queue_t), info1);

	mdb_printf("| %<b>%-21s%</b> | %<b>%-21s%</b> |", wname, rname);
	mdb_flush(); /* Account for buffered terminal sequences */

	mdb_printf(" %s\n", info2);
	mdb_printf(box_sep);

	mdb_qinfo(_RD(q), info1, sizeof (info1));
	if ((info2 = strchr(info1, '\n')) != NULL)
		*info2++ = '\0';
	else
		info2 = "";

	mdb_printf("| cnt = 0t%-13lu | cnt = 0t%-13lu | %s\n",
	    _WR(q)->q_count, _RD(q)->q_count, info1);

	mdb_printf("| flg = 0x%08x      | flg = 0x%08x      | %s\n",
	    _WR(q)->q_flag, _RD(q)->q_flag, info2);

	mdb_printf(box_lid);
	*depth += 1;
	return (0);
}

/*ARGSUSED*/
int
stream(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t d = 0;	/* Depth counter for print_qpair */

	if (argc != 0 || !(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_pwalk("writeq", (mdb_walk_cb_t)print_qpair, &d, addr) == -1) {
		mdb_warn("failed to walk writeq");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

int
mblk_walk_init(mdb_walk_state_t *wsp)
{
	wsp->walk_data = mdb_alloc(sizeof (mblk_t), UM_SLEEP);
	return (WALK_NEXT);
}

int
b_cont_step(mdb_walk_state_t *wsp)
{
	int status;

	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	if (mdb_vread(wsp->walk_data, sizeof (mblk_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to read mblk at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)(((mblk_t *)wsp->walk_data)->b_cont);
	return (status);
}

int
b_next_step(mdb_walk_state_t *wsp)
{
	int status;

	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	if (mdb_vread(wsp->walk_data, sizeof (mblk_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to read mblk at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)(((mblk_t *)wsp->walk_data)->b_next);
	return (status);
}

void
mblk_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (mblk_t));
}

/* ARGSUSED */
int
mblk2dblk(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mblk_t mb;

	if (argc != 0)
		return (DCMD_USAGE);

	if (mdb_vread(&mb, sizeof (mb), addr) == -1) {
		mdb_warn("couldn't read mblk at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("%p\n", mb.b_datap);
	return (DCMD_OK);
}

static void
mblk_error(int *error, uintptr_t addr, char *message)
{
	if (!*error)
		mdb_printf("%?lx: ", addr);
	else
		mdb_printf(", ");
	mdb_printf("%s", message);
	*error = 1;
}

int
mblk_verify(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mblk_t	mb;
	dblk_t	db;
	int	error = 0;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("streams_mblk", "mblk_verify", argc, argv) ==
		    -1) {
			mdb_warn("can't walk mblk cache");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_vread(&mb, sizeof (mblk_t), addr) == -1) {
		mdb_warn("can't read mblk_t at 0x%lx", addr);
		return (DCMD_ERR);
	}

	if (mdb_vread(&db, sizeof (dblk_t), (uintptr_t)mb.b_datap) == -1) {
		mdb_warn("%?lx: invalid b_datap pointer\n", addr);
		return (DCMD_ERR);
	}

	if (mb.b_rptr < db.db_base || mb.b_rptr > db.db_lim)
		mblk_error(&error, addr, "b_rptr out of range");

	if (mb.b_wptr < db.db_base || mb.b_wptr > db.db_lim)
		mblk_error(&error, addr, "b_wptr out of range");

	if (error)
		mdb_printf("\n");

	return (error ? DCMD_ERR : DCMD_OK);
}

int
mblk_prt(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	const int MBLK_FLGDELT = (int)(sizeof (uintptr_t) * 2 + 15);
	mblk_t mblk;
	dblk_t dblk;
	int b_flag;
	int db_type;
	int mblklen;
	uint64_t len = ~0UL;
	uint64_t glen = ~0UL;
	uint64_t llen = ~0UL;
	uint64_t blen = ~0UL;
	const char *dbtype;
	const char *flag = NULL, *not_flag = NULL;
	const char *typ = NULL, *not_typ = NULL;
	uintptr_t  dbaddr = 0;
	uint32_t tmask = 0, not_tmask = 0;
	uint32_t mask = 0, not_mask = 0;
	uint_t quiet = FALSE;
	uint_t verbose = FALSE;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("genunix`streams_mblk", "genunix`mblk",
		    argc, argv) == -1) {
			mdb_warn("failed to walk mblk cache");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (flags & DCMD_PIPE_OUT)
		quiet = TRUE;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose,
	    'q', MDB_OPT_SETBITS, TRUE, &quiet,
	    'f', MDB_OPT_STR, &flag,
	    'F', MDB_OPT_STR, &not_flag,
	    't', MDB_OPT_STR, &typ,
	    'T', MDB_OPT_STR, &not_typ,
	    'l', MDB_OPT_UINT64, &len,
	    'L', MDB_OPT_UINT64, &llen,
	    'G', MDB_OPT_UINT64, &glen,
	    'b', MDB_OPT_UINT64, &blen,
	    'd', MDB_OPT_UINTPTR, &dbaddr,
	    NULL) != argc)
		return (DCMD_USAGE);

	/*
	 * If any of the filtering flags is specified, don't print anything
	 * except the matching pointer.
	 */
	if ((flag != NULL) || (not_flag != NULL) || (typ != NULL) ||
	    (not_typ != NULL) || (len != ~0UL) || (glen != ~0UL) ||
	    (llen != ~0UL) || (blen != ~0UL) || (dbaddr != 0))
		quiet = TRUE;

	if (flag != NULL && streams_parse_flag(mbf, flag, &mask) == -1) {
		mdb_warn("unrecognized mblk flag '%s'\n", flag);
		streams_flag_usage(mbf);
		return (DCMD_USAGE);
	}

	if (not_flag != NULL &&
	    streams_parse_flag(mbf, not_flag, &not_mask) == -1) {
		mdb_warn("unrecognized mblk flag '%s'\n", flag);
		streams_flag_usage(mbf);
		return (DCMD_USAGE);
	}

	if (typ != NULL && streams_parse_type(mbt, typ, &tmask) == -1) {
		mdb_warn("unrecognized dblk type '%s'\n", typ);
		streams_type_usage(mbt);
		return (DCMD_USAGE);
	}

	if (not_typ != NULL && streams_parse_type(mbt, not_typ, &not_tmask)
	    == -1) {
		mdb_warn("unrecognized dblk type '%s'\n", not_typ);
		streams_type_usage(mbt);
		return (DCMD_USAGE);
	}

	if (DCMD_HDRSPEC(flags) && !quiet) {
		mdb_printf("%?s %2s %-7s %-5s %-5s %?s %?s\n",
		    "ADDR", "FL", "TYPE", "LEN", "BLEN", "RPTR", "DBLK");
	}

	if (mdb_vread(&mblk, sizeof (mblk), addr) == -1) {
		mdb_warn("couldn't read mblk at %p", addr);
		return (DCMD_ERR);
	}
	b_flag = mblk.b_flag;

	if (mask != 0 && !(b_flag & mask))
		return (DCMD_OK);

	if (not_mask != 0 && (b_flag & not_mask))
		return (DCMD_OK);

	if (mdb_vread(&dblk, sizeof (dblk), (uintptr_t)(mblk.b_datap)) == -1) {
		mdb_warn("couldn't read dblk at %p/%p", addr, mblk.b_datap);
		return (DCMD_ERR);
	}
	db_type = dblk.db_type;

	/* M_DATA is 0, so tmask has special value 0xff for it */
	if (tmask != 0) {
		if ((tmask == M_DATA_T && db_type != M_DATA) ||
		    (tmask != M_DATA_T && db_type != tmask))
			return (DCMD_OK);
	}

	if (not_tmask != 0) {
		if ((not_tmask == M_DATA_T && db_type == M_DATA) ||
		    (db_type == not_tmask))
			return (DCMD_OK);
	}

	if (dbaddr != 0 && (uintptr_t)mblk.b_datap != dbaddr)
		return (DCMD_OK);

	mblklen = MBLKL(&mblk);

	if ((len != ~0UL) && (len != mblklen))
		return (DCMD_OK);

	if ((llen != ~0Ul) && (mblklen > (int)llen))
		return (DCMD_OK);

	if ((glen != ~0Ul) && (mblklen < (int)glen))
		return (DCMD_OK);

	if ((blen != ~0UL) && (blen != (dblk.db_lim - dblk.db_base)))
		return (DCMD_OK);

	/*
	 * Options are specified for filtering, so If any option is specified on
	 * the command line, just print address and exit.
	 */
	if (quiet) {
		mdb_printf("%0?p\n", addr);
		return (DCMD_OK);
	}

	/* Figure out symbolic DB_TYPE */
	if (db_type < A_SIZE(db_control_types)) {
		dbtype = db_control_types[db_type];
	} else {
		/*
		 * Must be a high-priority message -- adjust so that
		 * "QPCTL + 1" corresponds to db_control_hipri_types[0]
		 */
		db_type -= (QPCTL + 1);
		if (db_type >= 0 && db_type < A_SIZE(db_control_hipri_types))
			dbtype = db_control_hipri_types[db_type];
		else
			dbtype = "UNKNOWN";
	}

	mdb_printf("%0?p %-2x %-7s %-5d %-5d %0?p %0?p\n",
	    addr, b_flag, dbtype, mblklen, dblk.db_lim - dblk.db_base,
	    mblk.b_rptr, mblk.b_datap);

	if (verbose) {
		int i, arm = 0;

		for (i = 0; mbf[i].strf_name != NULL; i++) {
			if (!(b_flag & (1 << i)))
				continue;
			if (!arm) {
				mdb_printf("%*s|\n%*s+-->  ",
				    MBLK_FLGDELT, "", MBLK_FLGDELT, "");
				arm = 1;
			} else
				mdb_printf("%*s      ", MBLK_FLGDELT, "");

			mdb_printf("%-12s %s\n",
			    mbf[i].strf_name, mbf[i].strf_descr);
		}
	}
	return (DCMD_OK);
}

/*
 * Streams flow trace walkers.
 */

int
strftblk_walk_init(mdb_walk_state_t *wsp)
{
	ftblkdata_t *ftd;
	dblk_t	db;

	/* Get the dblock from the address */
	if (mdb_vread(&db, sizeof (dblk_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to read dblk at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	/* Is there any flow trace data? */
	if (db.db_fthdr == NULL) {
		return (WALK_DONE);
	}

	wsp->walk_addr = (uintptr_t)((char *)db.db_fthdr +
	    offsetof(fthdr_t, first));

	ftd = mdb_alloc(sizeof (ftblkdata_t), UM_SLEEP);
	ftd->ft_ix = 0;
	ftd->ft_in_evlist = B_FALSE;
	wsp->walk_data = ftd;

	return (WALK_NEXT);
}

int
strftblk_step(mdb_walk_state_t *wsp)
{
	ftblkdata_t *ftd;
	ftblk_t *ftbp;
	int status = WALK_NEXT;

	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	ftd = (ftblkdata_t *)wsp->walk_data;
	ftbp = &(ftd->ft_data);

	if (! ftd->ft_in_evlist) {
		/* Read a new ft block */
		if (mdb_vread(ftbp, sizeof (ftblk_t),
		    wsp->walk_addr) == -1) {
			mdb_warn("failed to read ftblk at %p", wsp->walk_addr);
			return (WALK_ERR);
		}
		/*
		 * Check correctness of the index field.
		 */
		if (ftbp->ix < 0 || ftbp->ix > FTBLK_EVNTS) {
			mdb_warn("ftblk: incorrect index value %i\n", ftbp->ix);
			return (WALK_ERR);
		}
		ftd->ft_ix = 1;
		ftd->ft_in_evlist = B_TRUE;
	}

	if (ftd->ft_ix > ftbp->ix) {
		ftd->ft_in_evlist = B_FALSE;
		/* End of event list reached - move to the next event block */
		wsp->walk_addr = (uintptr_t)ftbp->nxt;
	} else {
		/* Print event address */
		status = wsp->walk_callback((uintptr_t)((char *)wsp->walk_addr +
		    offsetof(ftblk_t, ev) +
		    (ftd->ft_ix - 1) * sizeof (struct ftevnt)),
		    wsp->walk_data, wsp->walk_cbdata);
		ftd->ft_ix++;
	}

	return (status);
}

void
strftblk_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (ftblkdata_t));
}

static const char *
getqname(const void *nameptr, char *buf, uint_t bufsize)
{
	char *cp;

	if (mdb_readstr(buf, bufsize, (uintptr_t)nameptr) == -1)
		goto fail;

	/*
	 * Sanity-check the name we read.  This is needed because the pointer
	 * value may have been recycled for some other purpose in the kernel
	 * (e.g., if the STREAMS module was unloaded).
	 */
	for (cp = buf; *cp != '\0'; cp++) {
		if (!isprint(*cp))
			goto fail;
	}
	return (buf);
fail:
	return (strncpy(buf, "?", bufsize));
}

/*ARGSUSED*/
int
strftevent(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int i;
	struct ftstk stk;
	struct ftevnt ev;
	char name[FMNAMESZ + 1];
	boolean_t havestk = B_FALSE;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%?s %-18s %-9s %-18s %4s %s\n",
		    "ADDR", "Q/CALLER", "QNEXT", "STACK", "DATA", "EVENT");
	}

	if (mdb_vread(&ev, sizeof (ev), addr) == -1) {
		mdb_warn("couldn't read struct ftevnt at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("%0?p", addr);

	if (ev.evnt & FTEV_QMASK)
		mdb_printf(" %-18s", getqname(ev.mid, name, sizeof (name)));
	else
		mdb_printf(" %-18a", ev.mid);

	if ((ev.evnt & FTEV_MASK) == FTEV_PUTNEXT)
		mdb_printf(" %-9s", getqname(ev.midnext, name, sizeof (name)));
	else
		mdb_printf(" %-9s", "--");

	if (ev.stk == NULL) {
		mdb_printf(" %-18s", "--");
	} else if (mdb_vread(&stk, sizeof (stk), (uintptr_t)ev.stk) == -1) {
		mdb_printf(" %-18s", "?");
	} else {
		mdb_printf(" %-18a", stk.fs_stk[0]);
		havestk = B_TRUE;
	}

	mdb_printf(" %4x", ev.data);
	ft_printevent(ev.evnt);
	mdb_printf("\n");

	if (havestk) {
		for (i = 1; i < stk.fs_depth; i++) {
			mdb_printf("%?s %-18s %-9s %-18a\n", "", "", "",
			    stk.fs_stk[i]);
		}
	}

	return (DCMD_OK);
}

static void
ft_printevent(ushort_t ev)
{
	ushort_t proc_ev = (ev & (FTEV_PROC_START | 0xFF)) - FTEV_PROC_START;
	ushort_t alloc_ev = ev & FTEV_CALLER;

	/* Get event class first */
	if (ev & FTEV_PROC_START) {
		if (proc_ev >= A_SIZE(ftev_proc))
			mdb_printf(" undefined");
		else
			mdb_printf(" %s", ftev_proc[proc_ev]);
	} else if (alloc_ev >= A_SIZE(ftev_alloc)) {
		mdb_printf(" undefined");
	} else {
		mdb_printf(" %s", ftev_alloc[alloc_ev]);
	}

	/* Print event modifiers, if any */
	if (ev & (FTEV_PS | FTEV_CS | FTEV_ISWR)) {
		mdb_printf("|");
		if (ev & FTEV_ISWR)
			mdb_printf("W");
		if (ev & FTEV_CS)
			mdb_printf("C");
		if (ev & FTEV_PS)
			mdb_printf("P");
	}
}

/*
 * Help functions for STREAMS debugging facilities.
 */
void
queue_help(void)
{
	mdb_printf("Print queue information for a given queue pointer.\n"
	    "\nWithout the address of a \"queue_t\" structure given, print "
	    "information about all\n"
	    "queues in the \"queue_cache\".\n\n"
	    "Options:\n"
	    "	-v:\t\tbe verbose - print symbolic flags falues\n"
	    "	-q:\t\tbe quiet - print queue pointer only\n"
	    "	-f flag:\tprint only queues with flag set\n"
	    "	-F flag:\tprint only queues with flag NOT set\n"
	    "	-m modname:\tprint only queues with specified module name\n"
	    "	-s syncq_addr:\tprint only queues which use specified syncq\n\n"
	    "Available conversions:\n"
	    "	q2rdq:		given a queue addr print read queue pointer\n"
	    "	q2wrq:		given a queue addr print write queue pointer\n"
	    "	q2otherq:	given a queue addr print other queue pointer\n"
	    "	q2syncq:	given a queue addr print syncq pointer"
	    " (::help syncq)\n"
	    "	q2stream:	given a queue addr print its stream pointer\n"
	    "\t\t(see ::help stream and ::help stdata)\n\n"
	    "To walk q_next pointer of the queue use\n"
	    "	queue_addr::walk qnext\n");
}

void
syncq_help(void)
{
	mdb_printf("Print syncq information for a given syncq pointer.\n"
	    "\nWithout the address of a \"syncq_t\" structure given, print "
	    "information about all\n"
	    "syncqs in the \"syncq_cache\".\n\n"
	    "Options:\n"
	    "	-v:\t\tbe verbose - print symbolic flags falues\n"
	    "	-q:\t\tbe quiet - print syncq pointer only\n"
	    "	-f flag:\tprint only syncqs with flag set\n"
	    "	-F flag:\tprint only syncqs with flag NOT set\n"
	    "	-t type:\tprint only syncqs with specified type\n"
	    "	-T type:\tprint only syncqs with do NOT have specified type\n\n"
	    "Available conversions:\n"
	    "	syncq2q:\tgiven a syncq addr print queue address of the\n"
	    "\t\t\tenclosing queue, if it is part of a queue\n\n"
	    "See also: \"::help queue\" and \"::help stdata\"\n");
}

void
stdata_help(void)
{
	mdb_printf("Print stdata information for a given stdata pointer.\n"
	    "\nWithout the address of a \"stdata_t\" structure given, print "
	    "information about all\n"
	    "stream head pointers from the \"stream_head_cache\".\n\n"
	    "Fields printed:\n"
	    "	ADDR:\tstream head address\n"
	    "	WRQ:\twrite queue pointer\n"
	    "	FLAGS:\tstream head flags (use -v to show in symbolic form)\n"
	    "	VNODE:\tstream vnode pointer\n"
	    "	N/A:\tpushcount and anchor positions\n"
	    "	REF:\tstream head reference counter\n\n"
	    "Options:\n"
	    "	-v:\t\tbe verbose - print symbolic flags falues\n"
	    "	-q:\t\tbe quiet - print stdata pointer only\n"
	    "	-f flag:\tprint only stdatas with flag set\n"
	    "	-F flag:\tprint only stdatas with flag NOT set\n\n"
	    "Available conversions:\n"
	    "	str2mate:\tgiven a stream head addr print its mate\n"
	    "	str2wrq:\tgiven a stream head addr print its write queue\n\n"
	    "See also: \"::help queue\" and \"::help syncq\"\n");
}

void
mblk_help(void)
{
	mdb_printf("Print mblock information for a given mblk pointer.\n"
	    "Without the address, print information about all mblocks.\n\n"
	    "Fields printed:\n"
	    "	ADDR:\tmblk address\n"
	    "	FL:\tFlags\n"
	    "	TYPE:\tType of corresponding dblock\n"
	    "	LEN:\tData length as b_wptr - b_rptr\n"
	    "	BLEN:\tDblock space as db_lim - db_base\n"
	    "	RPTR:\tRead pointer\n"
	    "	DBLK:\tDblock pointer\n\n"
	    "Options:\n"
	    "	-v:\t\tbe verbose - print symbolic flags falues\n"
	    "	-q:\t\tbe quiet - print mblk pointer only\n"
	    "	-d dbaddr:\t\tprint mblks with specified dblk address\n"
	    "	-f flag:\tprint only mblks with flag set\n"
	    "	-F flag:\tprint only mblks with flag NOT set\n"
	    "	-t type:\tprint only mblks of specified db_type\n"
	    "	-T type:\tprint only mblks other then the specified db_type\n"
	    "	-l len:\t\ttprint only mblks with MBLKL == len\n"
	    "	-L len:\t\tprint only mblks with MBLKL <= len \n"
	    "	-G len:\t\tprint only mblks with MBLKL >= len \n"
	    "	-b len:\t\tprint only mblks with db_lim - db_base == len\n"
	    "\n");
}
