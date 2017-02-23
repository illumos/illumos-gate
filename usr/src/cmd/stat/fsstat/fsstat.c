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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#include <stdio.h>
#include <kstat.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <time.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/statvfs.h>
#include <sys/fstyp.h>
#include <sys/fsid.h>
#include <sys/mnttab.h>
#include <values.h>
#include <poll.h>
#include <ctype.h>
#include <libintl.h>
#include <locale.h>
#include <signal.h>

#include "statcommon.h"

/*
 * For now, parsable output is turned off.  Once we gather feedback and
 * stablize the output format, we'll turn it back on.  This prevents
 * the situation where users build tools which depend on a specific
 * format before we declare the output stable.
 */
#define	PARSABLE_OUTPUT	0

#if PARSABLE_OUTPUT
#define	OPTIONS	"FPT:afginv"
#else
#define	OPTIONS	"FT:afginv"
#endif

/* Time stamp values */
#define	NODATE	0	/* Default:  No time stamp */
#define	DDATE	1	/* Standard date format */
#define	UDATE	2	/* Internal representation of Unix time */

#define	RETRY_DELAY	250	/* Timeout for poll() */
#define	HEADERLINES	12	/* Number of lines between display headers */

#define	LBUFSZ		64	/* Generic size for local buffer */

/*
 * The following are used for the nicenum() function
 */
#define	KILO_VAL	1024
#define	ONE_INDEX	3

#define	NENTITY_INIT	1	/* Initial number of entities to allocate */

/*
 * We need to have a mechanism for an old/previous and new/current vopstat
 * structure.  We only need two per entity and we can swap between them.
 */
#define	VS_SIZE	2	/* Size of vopstat array */
#define	CUR_INDEX	(vs_i)
#define	PREV_INDEX	((vs_i == 0) ? 1 : 0)	/* Opposite of CUR_INDEX */
#define	BUMP_INDEX()	vs_i = ((vs_i == 0) ? 1 : 0)

/*
 * An "entity" is anything we're collecting statistics on, it could
 * be a mountpoint or an FS-type.
 * e_name is the name of the entity (e.g. mount point or FS-type)
 * e_ksname is the name of the associated kstat
 * e_vs is an array of vopstats.  This is used to keep track of "previous"
 * and "current" vopstats.
 */
typedef struct entity {
	char		*e_name;		/* name of entity */
	vopstats_t	*e_vs;			/* Array of vopstats */
	ulong_t		e_fsid;			/* fsid for ENTYPE_MNTPT only */
	int		e_type;			/* type of entity */
	char		e_ksname[KSTAT_STRLEN];	/* kstat name */
} entity_t;

/* Types of entities (e_type) */
#define	ENTYPE_UNKNOWN	0	/* UNKNOWN must be zero since we calloc() */
#define	ENTYPE_FSTYPE	1
#define	ENTYPE_MNTPT	2

/* If more sub-one units are added, make sure to adjust ONE_INDEX above */
static char units[] = "num KMGTPE";

char		*cmdname;	/* name of this command */
int		caught_cont = 0;	/* have caught a SIGCONT */

static uint_t	timestamp_fmt = NODATE;	/* print timestamp with stats */

static int	vs_i = 0;	/* Index of current vs[] slot */

static void
usage()
{
	(void) fprintf(stderr, gettext(
	    "Usage: %s [-a|f|i|n|v] [-T d|u] {-F | {fstype | fspath}...} "
	    "[interval [count]]\n"), cmdname);
	exit(2);
}

/*
 * Given a 64-bit number and a starting unit (e.g., n - nanoseconds),
 * convert the number to a 5-character representation including any
 * decimal point and single-character unit.  Put that representation
 * into the array "buf" (which had better be big enough).
 */
char *
nicenum(uint64_t num, char unit, char *buf)
{
	uint64_t n = num;
	int unit_index;
	int index;
	char u;

	/* If the user passed in a NUL/zero unit, use the blank value for 1 */
	if (unit == '\0')
		unit = ' ';

	unit_index = 0;
	while (units[unit_index] != unit) {
		unit_index++;
		if (unit_index > sizeof (units) - 1) {
			(void) sprintf(buf, "??");
			return (buf);
		}
	}

	index = 0;
	while (n >= KILO_VAL) {
		n = (n + (KILO_VAL / 2)) / KILO_VAL; /* Round up or down */
		index++;
		unit_index++;
	}

	if (unit_index >= sizeof (units) - 1) {
		(void) sprintf(buf, "??");
		return (buf);
	}

	u = units[unit_index];

	if (unit_index == ONE_INDEX) {
		(void) sprintf(buf, "%llu", (u_longlong_t)n);
	} else if (n < 10 && (num & (num - 1)) != 0) {
		(void) sprintf(buf, "%.2f%c",
		    (double)num / (1ULL << 10 * index), u);
	} else if (n < 100 && (num & (num - 1)) != 0) {
		(void) sprintf(buf, "%.1f%c",
		    (double)num / (1ULL << 10 * index), u);
	} else {
		(void) sprintf(buf, "%llu%c", (u_longlong_t)n, u);
	}

	return (buf);
}


#define	RAWVAL(ptr, member) ((ptr)->member.value.ui64)
#define	DELTA(member)	\
	(newvsp->member.value.ui64 - (oldvsp ? oldvsp->member.value.ui64 : 0))

#define	PRINTSTAT(isnice, nicestring, rawstring, rawval, unit, buf)	\
	(isnice) ?	 						\
		(void) printf((nicestring), nicenum(rawval, unit, buf))	\
	:								\
		(void) printf((rawstring), (rawval))

/* Values for display flag */
#define	DISP_HEADER	0x1
#define	DISP_RAW	0x2

/*
 * The policy for dealing with multiple flags is dealt with here.
 * Currently, if we are displaying raw output, then don't allow
 * headers to be printed.
 */
int
dispflag_policy(int printhdr, int dispflag)
{
	/* If we're not displaying raw output, then allow headers to print */
	if ((dispflag & DISP_RAW) == 0) {
		if (printhdr) {
			dispflag |= DISP_HEADER;
		}
	}

	return (dispflag);
}

static void
dflt_display(char *name, vopstats_t *oldvsp, vopstats_t *newvsp, int dispflag)
{
	int		niceflag = ((dispflag & DISP_RAW) == 0);
	longlong_t	nnewfile;
	longlong_t	nnamerm;
	longlong_t	nnamechg;
	longlong_t	nattrret;
	longlong_t	nattrchg;
	longlong_t	nlookup;
	longlong_t	nreaddir;
	longlong_t	ndataread;
	longlong_t	ndatawrite;
	longlong_t	readthruput;
	longlong_t	writethruput;
	char		buf[LBUFSZ];

	nnewfile = DELTA(ncreate) + DELTA(nmkdir) + DELTA(nsymlink);
	nnamerm = DELTA(nremove) + DELTA(nrmdir);
	nnamechg = DELTA(nrename) + DELTA(nlink) + DELTA(nsymlink);
	nattrret = DELTA(ngetattr) + DELTA(naccess) +
	    DELTA(ngetsecattr) + DELTA(nfid);
	nattrchg = DELTA(nsetattr) + DELTA(nsetsecattr) + DELTA(nspace);
	nlookup = DELTA(nlookup);
	nreaddir = DELTA(nreaddir);
	ndataread = DELTA(nread);
	ndatawrite = DELTA(nwrite);
	readthruput = DELTA(read_bytes);
	writethruput = DELTA(write_bytes);

	if (dispflag & DISP_HEADER) {
		(void) printf(
" new  name   name  attr  attr lookup rddir  read read  write write\n"
" file remov  chng   get   set    ops   ops   ops bytes   ops bytes\n");
	}

	PRINTSTAT(niceflag, "%5s ", "%lld:", nnewfile, ' ', buf);
	PRINTSTAT(niceflag, "%5s ", "%lld:", nnamerm, ' ', buf);
	PRINTSTAT(niceflag, "%5s ", "%lld:", nnamechg, ' ', buf);
	PRINTSTAT(niceflag, "%5s ", "%lld:", nattrret, ' ', buf);
	PRINTSTAT(niceflag, "%5s ", "%lld:", nattrchg, ' ', buf);
	PRINTSTAT(niceflag, " %5s ", "%lld:", nlookup, ' ', buf);
	PRINTSTAT(niceflag, "%5s ", "%lld:", nreaddir, ' ', buf);
	PRINTSTAT(niceflag, "%5s ", "%lld:", ndataread, ' ', buf);
	PRINTSTAT(niceflag, "%5s ", "%lld:", readthruput, ' ', buf);
	PRINTSTAT(niceflag, "%5s ", "%lld:", ndatawrite, ' ', buf);
	PRINTSTAT(niceflag, "%5s ", "%lld:", writethruput, ' ', buf);
	(void) printf("%s\n", name);
}

static void
io_display(char *name, vopstats_t *oldvsp, vopstats_t *newvsp, int dispflag)
{
	int		niceflag = ((dispflag & DISP_RAW) == 0);
	char		buf[LBUFSZ];

	if (dispflag & DISP_HEADER) {
		(void) printf(
" read read  write write rddir rddir rwlock rwulock\n"
"  ops bytes   ops bytes   ops bytes    ops     ops\n");
	}

	PRINTSTAT(niceflag, "%5s ", "%lld:", DELTA(nread), ' ', buf);
	PRINTSTAT(niceflag, "%5s ", "%lld:", DELTA(read_bytes), ' ', buf);

	PRINTSTAT(niceflag, "%5s ", "%lld:", DELTA(nwrite), ' ', buf);
	PRINTSTAT(niceflag, "%5s ", "%lld:", DELTA(write_bytes), ' ', buf);

	PRINTSTAT(niceflag, "%5s ", "%lld:", DELTA(nreaddir), ' ', buf);
	PRINTSTAT(niceflag, "%5s ", "%lld:", DELTA(readdir_bytes), ' ', buf);

	PRINTSTAT(niceflag, " %5s   ", "%lld:", DELTA(nrwlock), ' ', buf);
	PRINTSTAT(niceflag, "%5s ", "%lld:", DELTA(nrwunlock), ' ', buf);

	(void) printf("%s\n", name);
}

static void
vm_display(char *name, vopstats_t *oldvsp, vopstats_t *newvsp, int dispflag)
{
	int		niceflag = ((dispflag & DISP_RAW) == 0);
	char		buf[LBUFSZ];

	if (dispflag & DISP_HEADER) {
		(void) printf("  map addmap delmap getpag putpag pagio\n");
	}

	PRINTSTAT(niceflag, "%5s ", "%lld:", DELTA(nmap), ' ', buf);
	PRINTSTAT(niceflag, " %5s ", "%lld:", DELTA(naddmap), ' ', buf);
	PRINTSTAT(niceflag, " %5s ", "%lld:", DELTA(ndelmap), ' ', buf);
	PRINTSTAT(niceflag, " %5s ", "%lld:", DELTA(ngetpage), ' ', buf);
	PRINTSTAT(niceflag, " %5s ", "%lld:", DELTA(nputpage), ' ', buf);
	PRINTSTAT(niceflag, "%5s ", "%lld:", DELTA(npageio), ' ', buf);
	(void) printf("%s\n", name);
}

static void
attr_display(char *name, vopstats_t *oldvsp, vopstats_t *newvsp, int dispflag)
{
	int		niceflag = ((dispflag & DISP_RAW) == 0);
	char		buf[LBUFSZ];

	if (dispflag & DISP_HEADER) {
		(void) printf("getattr setattr getsec  setsec\n");
	}

	PRINTSTAT(niceflag, " %5s ", "%lld:", DELTA(ngetattr), ' ', buf);
	PRINTSTAT(niceflag, "  %5s ", "%lld:", DELTA(nsetattr), ' ', buf);
	PRINTSTAT(niceflag, "  %5s ", "%lld:", DELTA(ngetsecattr), ' ', buf);
	PRINTSTAT(niceflag, "  %5s ", "%lld:", DELTA(nsetsecattr), ' ', buf);

	(void) printf("%s\n", name);
}

static void
naming_display(char *name, vopstats_t *oldvsp, vopstats_t *newvsp, int dispflag)
{
	int		niceflag = ((dispflag & DISP_RAW) == 0);
	char		buf[LBUFSZ];

	if (dispflag & DISP_HEADER) {
		(void) printf(
	"lookup creat remov  link renam mkdir rmdir rddir symlnk rdlnk\n");
	}

	PRINTSTAT(niceflag, "%5s  ", "%lld:", DELTA(nlookup), ' ', buf);
	PRINTSTAT(niceflag, "%5s ", "%lld:", DELTA(ncreate), ' ', buf);
	PRINTSTAT(niceflag, "%5s ", "%lld:", DELTA(nremove), ' ', buf);
	PRINTSTAT(niceflag, "%5s ", "%lld:", DELTA(nlink), ' ', buf);
	PRINTSTAT(niceflag, "%5s ", "%lld:", DELTA(nrename), ' ', buf);
	PRINTSTAT(niceflag, "%5s ", "%lld:", DELTA(nmkdir), ' ', buf);
	PRINTSTAT(niceflag, "%5s ", "%lld:", DELTA(nrmdir), ' ', buf);
	PRINTSTAT(niceflag, "%5s ", "%lld:", DELTA(nreaddir), ' ', buf);
	PRINTSTAT(niceflag, " %5s ", "%lld:", DELTA(nsymlink), ' ', buf);
	PRINTSTAT(niceflag, "%5s ", "%lld:", DELTA(nreadlink), ' ', buf);
	(void) printf("%s\n", name);
}


#define	PRINT_VOPSTAT_CMN(niceflag, vop)				\
	if (niceflag)							\
		(void) printf("%10s ", #vop);				\
	PRINTSTAT(niceflag, "%5s ", "%lld:", DELTA(n##vop), ' ', buf);

#define	PRINT_VOPSTAT(niceflag, vop) 					\
	PRINT_VOPSTAT_CMN(niceflag, vop);				\
	if (niceflag)							\
		(void) printf("\n");

#define	PRINT_VOPSTAT_IO(niceflag, vop)					\
	PRINT_VOPSTAT_CMN(niceflag, vop);				\
	PRINTSTAT(niceflag, " %5s\n", "%lld:",				\
		DELTA(vop##_bytes), ' ', buf);

static void
vop_display(char *name, vopstats_t *oldvsp, vopstats_t *newvsp, int dispflag)
{
	int		niceflag = ((dispflag & DISP_RAW) == 0);
	char		buf[LBUFSZ];

	if (niceflag) {
		(void) printf("%s\n", name);
		(void) printf(" operation  #ops  bytes\n");
	}

	PRINT_VOPSTAT(niceflag, open);
	PRINT_VOPSTAT(niceflag, close);
	PRINT_VOPSTAT_IO(niceflag, read);
	PRINT_VOPSTAT_IO(niceflag, write);
	PRINT_VOPSTAT(niceflag, ioctl);
	PRINT_VOPSTAT(niceflag, setfl);
	PRINT_VOPSTAT(niceflag, getattr);
	PRINT_VOPSTAT(niceflag, setattr);
	PRINT_VOPSTAT(niceflag, access);
	PRINT_VOPSTAT(niceflag, lookup);
	PRINT_VOPSTAT(niceflag, create);
	PRINT_VOPSTAT(niceflag, remove);
	PRINT_VOPSTAT(niceflag, link);
	PRINT_VOPSTAT(niceflag, rename);
	PRINT_VOPSTAT(niceflag, mkdir);
	PRINT_VOPSTAT(niceflag, rmdir);
	PRINT_VOPSTAT_IO(niceflag, readdir);
	PRINT_VOPSTAT(niceflag, symlink);
	PRINT_VOPSTAT(niceflag, readlink);
	PRINT_VOPSTAT(niceflag, fsync);
	PRINT_VOPSTAT(niceflag, inactive);
	PRINT_VOPSTAT(niceflag, fid);
	PRINT_VOPSTAT(niceflag, rwlock);
	PRINT_VOPSTAT(niceflag, rwunlock);
	PRINT_VOPSTAT(niceflag, seek);
	PRINT_VOPSTAT(niceflag, cmp);
	PRINT_VOPSTAT(niceflag, frlock);
	PRINT_VOPSTAT(niceflag, space);
	PRINT_VOPSTAT(niceflag, realvp);
	PRINT_VOPSTAT(niceflag, getpage);
	PRINT_VOPSTAT(niceflag, putpage);
	PRINT_VOPSTAT(niceflag, map);
	PRINT_VOPSTAT(niceflag, addmap);
	PRINT_VOPSTAT(niceflag, delmap);
	PRINT_VOPSTAT(niceflag, poll);
	PRINT_VOPSTAT(niceflag, dump);
	PRINT_VOPSTAT(niceflag, pathconf);
	PRINT_VOPSTAT(niceflag, pageio);
	PRINT_VOPSTAT(niceflag, dumpctl);
	PRINT_VOPSTAT(niceflag, dispose);
	PRINT_VOPSTAT(niceflag, getsecattr);
	PRINT_VOPSTAT(niceflag, setsecattr);
	PRINT_VOPSTAT(niceflag, shrlock);
	PRINT_VOPSTAT(niceflag, vnevent);
	PRINT_VOPSTAT(niceflag, reqzcbuf);
	PRINT_VOPSTAT(niceflag, retzcbuf);

	if (niceflag) {
		/* Make it easier on the eyes */
		(void) printf("\n");
	} else {
		(void) printf("%s\n", name);
	}
}


/*
 * Retrieve the vopstats.  If kspp (pointer to kstat_t pointer) is non-NULL,
 * then pass it back to the caller.
 *
 * Returns 0 on success, non-zero on failure.
 */
int
get_vopstats(kstat_ctl_t *kc, char *ksname, vopstats_t *vsp, kstat_t **kspp)
{
	kstat_t		*ksp;

	if (ksname == NULL || *ksname == 0)
		return (1);

	errno = 0;
	/* wait for a possibly up-to-date chain */
	while (kstat_chain_update(kc) == -1) {
		if (errno == EAGAIN) {
			errno = 0;
			(void) poll(NULL, 0, RETRY_DELAY);
			continue;
		}
		perror("kstat_chain_update");
		exit(1);
	}

	if ((ksp = kstat_lookup(kc, NULL, -1, ksname)) == NULL) {
		return (1);
	}

	if (kstat_read(kc, ksp, vsp) == -1) {
		return (1);
	}

	if (kspp)
		*kspp = ksp;

	return (0);
}

/*
 * Given a file system type name, determine if it's part of the
 * exception list of file systems that are not to be displayed.
 */
int
is_exception(char *fsname)
{
	char **xlp;	/* Pointer into the exception list */

	static char *exception_list[] = {
		"specfs",
		"fifofs",
		"fd",
		"swapfs",
		"ctfs",
		"objfs",
		"nfsdyn",
		NULL
	};

	for (xlp = &exception_list[0]; *xlp != NULL; xlp++) {
		if (strcmp(fsname, *xlp) == 0)
			return (1);
	}

	return (0);
}

/*
 * Plain and simple, build an array of names for fstypes
 * Returns 0, if it encounters a problem.
 */
int
build_fstype_list(char ***fstypep)
{
	int	i;
	int	nfstype;
	char	buf[FSTYPSZ + 1];

	if ((nfstype = sysfs(GETNFSTYP)) < 0) {
		perror("sysfs(GETNFSTYP)");
		return (0);
	}

	if ((*fstypep = calloc(nfstype, sizeof (char *))) == NULL) {
		perror("calloc() fstypes");
		return (0);
	}

	for (i = 1; i < nfstype; i++) {
		if (sysfs(GETFSTYP, i, buf) < 0) {
			perror("sysfs(GETFSTYP)");
			return (0);
		}

		if (buf[0] == 0)
			continue;

		/* If this is part of the exception list, move on */
		if (is_exception(buf))
			continue;

		if (((*fstypep)[i] = strdup(buf)) == NULL) {
			perror("strdup() fstype name");
			return (0);
		}
	}

	return (i);
}

/*
 * After we're done with getopts(), process the rest of the
 * operands.  We have three cases and this is the priority:
 *
 * 1) [ operand... ] interval count
 * 2) [ operand... ] interval
 * 3) [ operand... ]
 *
 * The trick is that any of the operands might start with a number or even
 * be made up exclusively of numbers (and we have to handle negative numbers
 * in case a user/script gets out of line).  If we find two operands at the
 * end of the list then we claim case 1.  If we find only one operand at the
 * end made up only of number, then we claim case 2.  Otherwise, case 3.
 * BTW, argc, argv don't change.
 */
int
parse_operands(
	int		argc,
	char		**argv,
	int		optind,
	long		*interval,
	long		*count,
	entity_t	**entityp)	/* Array of stat-able entities */
{
	int	nentities = 0;	/* Number of entities found */
	int	out_of_range;	/* Set if 2nd-to-last operand out-of-range */

	if (argc == optind)
		return (nentities);	/* None found, returns 0 */
	/*
	 * We know exactly what the maximum number of entities is going
	 * to be:  argc - optind
	 */
	if ((*entityp = calloc((argc - optind), sizeof (entity_t))) == NULL) {
		perror("calloc() entities");
		return (-1);
	}

	for (/* void */; argc > optind; optind++) {
		char	*endptr;

		/* If we have more than two operands left to process */
		if ((argc - optind) > 2) {
			(*entityp)[nentities++].e_name = strdup(argv[optind]);
			continue;
		}

		/* If we're here, then we only have one or two operands left */
		errno = 0;
		out_of_range = 0;
		*interval = strtol(argv[optind], &endptr, 10);
		if (*endptr && !isdigit((int)*endptr)) {
			/* Operand was not a number */
			(*entityp)[nentities++].e_name = strdup(argv[optind]);
			continue;
		} else if (errno == ERANGE || *interval <= 0 ||
		    *interval > MAXLONG) {
			/* Operand was a number, just out of range */
			out_of_range++;
		}

		/*
		 * The last operand we saw was a number.  If it happened to
		 * be the last operand, then it is the interval...
		 */
		if ((argc - optind) == 1) {
			/* ...but we need to check the range. */
			if (out_of_range) {
				(void) fprintf(stderr, gettext(
				    "interval must be between 1 and "
				    "%ld (inclusive)\n"), MAXLONG);
				return (-1);
			} else {
				/*
				 * The value of the interval is valid. Set
				 * count to something really big so it goes
				 * virtually forever.
				 */
				*count = MAXLONG;
				break;
			}
		}

		/*
		 * At this point, we *might* have the interval, but if the
		 * next operand isn't a number, then we don't have either
		 * the interval nor the count.  Both must be set to the
		 * defaults.  In that case, both the current and the previous
		 * operands are stat-able entities.
		 */
		errno = 0;
		*count = strtol(argv[optind + 1], &endptr, 10);
		if (*endptr && !isdigit((int)*endptr)) {
			/*
			 * Faked out!  The last operand wasn't a number so
			 * the current and previous operands should be
			 * stat-able entities. We also need to reset interval.
			 */
			*interval = 0;
			(*entityp)[nentities++].e_name = strdup(argv[optind++]);
			(*entityp)[nentities++].e_name = strdup(argv[optind++]);
		} else if (out_of_range || errno == ERANGE || *count <= 0) {
			(void) fprintf(stderr, gettext(
			    "Both interval and count must be between 1 "
			    "and %ld (inclusive)\n"), MAXLONG);
			return (-1);
		}
		break;	/* Done! */
	}
	return (nentities);
}

/*
 * set_mntpt() looks at the entity's name (e_name) and finds its
 * mountpoint.  To do this, we need to build a list of mountpoints
 * from /etc/mnttab.  We only need to do this once and we don't do it
 * if we don't need to look at any mountpoints.
 * Returns 0 on success, non-zero if it couldn't find a mount-point.
 */
int
set_mntpt(entity_t *ep)
{
	static struct mnt {
		struct mnt	*m_next;
		char		*m_mntpt;
		ulong_t		m_fsid;	/* From statvfs(), set only as needed */
	} *mnt_list = NULL;	/* Linked list of mount-points */
	struct mnt *mntp;
	struct statvfs64 statvfsbuf;
	char *original_name = ep->e_name;
	char path[PATH_MAX];

	if (original_name == NULL)		/* Shouldn't happen */
		return (1);

	/* We only set up mnt_list the first time this is called */
	if (mnt_list == NULL) {
		FILE *fp;
		struct mnttab mnttab;

		if ((fp = fopen(MNTTAB, "r")) == NULL) {
			perror(MNTTAB);
			return (1);
		}
		resetmnttab(fp);
		/*
		 * We insert at the front of the list so that when we
		 * search entries we'll have the last mounted entries
		 * first in the list so that we can match the longest
		 * mountpoint.
		 */
		while (getmntent(fp, &mnttab) == 0) {
			if ((mntp = malloc(sizeof (*mntp))) == NULL) {
				perror("malloc() mount list");
				return (1);
			}
			mntp->m_mntpt = strdup(mnttab.mnt_mountp);
			mntp->m_next = mnt_list;
			mnt_list = mntp;
		}
		(void) fclose(fp);
	}

	if (realpath(original_name, path) == NULL) {
		perror(original_name);
		return (1);
	}

	/*
	 * Now that we have the path, walk through the mnt_list and
	 * look for the first (best) match.
	 */
	for (mntp = mnt_list; mntp; mntp = mntp->m_next) {
		if (strncmp(path, mntp->m_mntpt, strlen(mntp->m_mntpt)) == 0) {
			if (mntp->m_fsid == 0) {
				if (statvfs64(mntp->m_mntpt, &statvfsbuf)) {
					/* Can't statvfs so no match */
					continue;
				} else {
					mntp->m_fsid = statvfsbuf.f_fsid;
				}
			}

			if (ep->e_fsid != mntp->m_fsid) {
				/* No match - Move on */
				continue;
			}

			break;
		}
	}

	if (mntp == NULL) {
		(void) fprintf(stderr, gettext(
		    "Can't find mount point for %s\n"), path);
		return (1);
	}

	ep->e_name = strdup(mntp->m_mntpt);
	free(original_name);
	return (0);
}

/*
 * We have an array of entities that are potentially stat-able.  Using
 * the name (e_name) of the entity, attempt to construct a ksname suitable
 * for use by kstat_lookup(3kstat) and fill it into the e_ksname member.
 *
 * We check the e_name against the list of file system types.  If there is
 * no match then test to see if the path is valid.  If the path is valid,
 * then determine the mountpoint.
 */
void
set_ksnames(entity_t *entities, int nentities, char **fstypes, int nfstypes)
{
	int		i, j;
	struct statvfs64 statvfsbuf;

	for (i = 0; i < nentities; i++) {
		entity_t	*ep = &entities[i];

		/* Check the name against the list of fstypes */
		for (j = 1; j < nfstypes; j++) {
			if (fstypes[j] && ep->e_name &&
			    strcmp(ep->e_name, fstypes[j]) == 0) {
				/* It's a file system type */
				ep->e_type = ENTYPE_FSTYPE;
				(void) snprintf(ep->e_ksname, KSTAT_STRLEN,
				    "%s%s", VOPSTATS_STR, ep->e_name);
				/* Now allocate the vopstats array */
				ep->e_vs = calloc(VS_SIZE, sizeof (vopstats_t));
				if (entities[i].e_vs == NULL) {
					perror("calloc() fstype vopstats");
					exit(1);
				}
				break;
			}
		}
		if (j < nfstypes)	/* Found it! */
			continue;

		/*
		 * If the entity in the exception list of fstypes, then
		 * null out the entry so it isn't displayed and move along.
		 */
		if (is_exception(ep->e_name)) {
			ep->e_ksname[0] = 0;
			continue;
		}

		/* If we didn't find it, see if it's a path */
		if (ep->e_name == NULL || statvfs64(ep->e_name, &statvfsbuf)) {
			/* Error - Make sure the entry is nulled out */
			ep->e_ksname[0] = 0;
			continue;
		}
		(void) snprintf(ep->e_ksname, KSTAT_STRLEN, "%s%lx",
		    VOPSTATS_STR, statvfsbuf.f_fsid);
		ep->e_fsid = statvfsbuf.f_fsid;
		if (set_mntpt(ep)) {
			(void) fprintf(stderr,
			    gettext("Can't determine type of \"%s\"\n"),
			    ep->e_name ? ep->e_name : gettext("<NULL>"));
		} else {
			ep->e_type = ENTYPE_MNTPT;
		}

		/* Now allocate the vopstats array */
		ep->e_vs = calloc(VS_SIZE, sizeof (vopstats_t));
		if (entities[i].e_vs == NULL) {
			perror("calloc() vopstats array");
			exit(1);
		}
	}
}

/*
 * The idea is that 'dspfunc' should only be modified from the default
 * once since the display options are mutually exclusive.  If 'dspfunc'
 * only contains the default display function, then all is good and we
 * can set it to the new display function.  Otherwise, bail.
 */
void
set_dispfunc(
	void (**dspfunc)(char *, vopstats_t *, vopstats_t *, int),
	void (*newfunc)(char *, vopstats_t *, vopstats_t *, int))
{
	if (*dspfunc != dflt_display) {
		(void) fprintf(stderr, gettext(
		"%s: Display options -{a|f|i|n|v} are mutually exclusive\n"),
		    cmdname);
		usage();
	}
	*dspfunc = newfunc;
}

int
main(int argc, char *argv[])
{
	int		c;
	int		i, j;		/* Generic counters */
	int		nentities_found;
	int		linesout = 0;	/* Keeps track of lines printed */
	int		printhdr = 0;	/* Print a header?  0 = no, 1 = yes */
	int		nfstypes;	/* Number of fstypes */
	int		dispflag = 0;	/* Flags for display control */
	long		count = 0;	/* Number of iterations for display */
	int		forever; 	/* Run forever */
	long		interval = 0;
	boolean_t	fstypes_only = B_FALSE;	/* Display fstypes only */
	char		**fstypes;	/* Array of names of all fstypes */
	int		nentities;	/* Number of stat-able entities */
	entity_t	*entities;	/* Array of stat-able entities */
	kstat_ctl_t	*kc;
	void (*dfunc)(char *, vopstats_t *, vopstats_t *, int) = dflt_display;
	hrtime_t	start_n;	/* Start time */
	hrtime_t	period_n;	/* Interval in nanoseconds */

	extern int	optind;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	/* Don't let buffering interfere with piped output. */
	(void) setvbuf(stdout, NULL, _IOLBF, 0);

	cmdname = argv[0];
	while ((c = getopt(argc, argv, OPTIONS)) != EOF) {
		switch (c) {

		default:
			usage();
			break;

		case 'F':	/* Only display available FStypes */
			fstypes_only = B_TRUE;
			break;

#if PARSABLE_OUTPUT
		case 'P':	/* Parsable output */
			dispflag |= DISP_RAW;
			break;
#endif /* PARSABLE_OUTPUT */

		case 'T':	/* Timestamp */
			if (optarg) {
				if (strcmp(optarg, "u") == 0) {
					timestamp_fmt = UDATE;
				} else if (strcmp(optarg, "d") == 0) {
					timestamp_fmt = DDATE;
				}
			}

			/* If it was never set properly... */
			if (timestamp_fmt == NODATE) {
				(void) fprintf(stderr, gettext("%s: -T option "
				    "requires either 'u' or 'd'\n"), cmdname);
				usage();
			}
			break;

		case 'a':
			set_dispfunc(&dfunc, attr_display);
			break;

		case 'f':
			set_dispfunc(&dfunc, vop_display);
			break;

		case 'i':
			set_dispfunc(&dfunc, io_display);
			break;

		case 'n':
			set_dispfunc(&dfunc, naming_display);
			break;

		case 'v':
			set_dispfunc(&dfunc, vm_display);
			break;
		}
	}

#if PARSABLE_OUTPUT
	if ((dispflag & DISP_RAW) && (timestamp_fmt != NODATE)) {
		(void) fprintf(stderr, gettext(
		    "-P and -T options are mutually exclusive\n"));
		usage();
	}
#endif /* PARSABLE_OUTPUT */

	/* Gather the list of filesystem types */
	if ((nfstypes = build_fstype_list(&fstypes)) == 0) {
		(void) fprintf(stderr,
		    gettext("Can't build list of fstypes\n"));
		exit(1);
	}

	nentities = parse_operands(
	    argc, argv, optind, &interval, &count, &entities);
	forever = count == MAXLONG;
	period_n = (hrtime_t)interval * NANOSEC;

	if (nentities == -1)	/* Set of operands didn't parse properly  */
		usage();

	if ((nentities == 0) && (fstypes_only == B_FALSE)) {
		(void) fprintf(stderr, gettext(
		    "Must specify -F or at least one fstype or mount point\n"));
		usage();
	}

	if ((nentities > 0) && (fstypes_only == B_TRUE)) {
		(void) fprintf(stderr, gettext(
		    "Cannot use -F with fstypes or mount points\n"));
		usage();
	}

	/*
	 * If we had no operands (except for interval/count) and we
	 * requested FStypes only (-F), then fill in the entities[]
	 * array with all available fstypes.
	 */
	if ((nentities == 0) && (fstypes_only == B_TRUE)) {
		if ((entities = calloc(nfstypes, sizeof (entity_t))) == NULL) {
			perror("calloc() fstype stats");
			exit(1);
		}

		for (i = 1; i < nfstypes; i++) {
			if (fstypes[i]) {
				entities[nentities].e_name = strdup(fstypes[i]);
				nentities++;
			}
		}
	}

	set_ksnames(entities, nentities, fstypes, nfstypes);

	if ((kc = kstat_open()) == NULL) {
		perror("kstat_open");
		exit(1);
	}

	/* Set start time */
	start_n = gethrtime();

	/* Initial timestamp */
	if (timestamp_fmt != NODATE) {
		print_timestamp(timestamp_fmt);
		linesout++;
	}

	/*
	 * The following loop walks through the entities[] list to "prime
	 * the pump"
	 */
	for (j = 0, printhdr = 1; j < nentities; j++) {
		entity_t *ent = &entities[j];
		vopstats_t *vsp = &ent->e_vs[CUR_INDEX];
		kstat_t *ksp = NULL;

		if (get_vopstats(kc, ent->e_ksname, vsp, &ksp) == 0) {
			(*dfunc)(ent->e_name, NULL, vsp,
			    dispflag_policy(printhdr, dispflag));
			linesout++;
		} else {
			/*
			 * If we can't find it the first time through, then
			 * get rid of it.
			 */
			entities[j].e_ksname[0] = 0;

			/*
			 * If we're only displaying FStypes (-F) then don't
			 * complain about any file systems that might not
			 * be loaded.  Otherwise, let the user know that
			 * they chose poorly.
			 */
			if (fstypes_only == B_FALSE) {
				(void) fprintf(stderr, gettext(
				    "No statistics available for %s\n"),
				    entities[j].e_name);
			}
		}
		printhdr = 0;
	}

	if (count > 1)
		/* Set up signal handler for SIGCONT */
		if (signal(SIGCONT, cont_handler) == SIG_ERR)
			fail(1, "signal failed");


	BUMP_INDEX();	/* Swap the previous/current indices */
	i = 1;
	while (forever || i++ <= count) {
		/*
		 * No telling how many lines will be printed in any interval.
		 * There should be a minimum of HEADERLINES between any
		 * header.  If we exceed that, no big deal.
		 */
		if (linesout > HEADERLINES) {
			linesout = 0;
			printhdr = 1;
		}
		/* Have a kip */
		sleep_until(&start_n, period_n, forever, &caught_cont);

		if (timestamp_fmt != NODATE) {
			print_timestamp(timestamp_fmt);
			linesout++;
		}

		for (j = 0, nentities_found = 0; j < nentities; j++) {
			entity_t *ent = &entities[j];

			/*
			 * If this entry has been cleared, don't attempt
			 * to process it.
			 */
			if (ent->e_ksname[0] == 0) {
				continue;
			}

			if (get_vopstats(kc, ent->e_ksname,
			    &ent->e_vs[CUR_INDEX], NULL) == 0) {
				(*dfunc)(ent->e_name, &ent->e_vs[PREV_INDEX],
				    &ent->e_vs[CUR_INDEX],
				    dispflag_policy(printhdr, dispflag));
				linesout++;
				nentities_found++;
			} else {
				if (ent->e_type == ENTYPE_MNTPT) {
					(void) printf(gettext(
					    "<<mount point no longer "
					    "available: %s>>\n"), ent->e_name);
				} else if (ent->e_type == ENTYPE_FSTYPE) {
					(void) printf(gettext(
					    "<<file system module no longer "
					    "loaded: %s>>\n"), ent->e_name);
				} else {
					(void) printf(gettext(
					    "<<%s no longer available>>\n"),
					    ent->e_name);
				}
				/* Disable this so it doesn't print again */
				ent->e_ksname[0] = 0;
			}
			printhdr = 0;	/* Always shut this off */
		}
		BUMP_INDEX();	/* Bump the previous/current indices */

		/*
		 * If the entities we were observing are no longer there
		 * (file system modules unloaded, file systems unmounted)
		 * then we're done.
		 */
		if (nentities_found == 0)
			break;
	}

	return (0);
}
