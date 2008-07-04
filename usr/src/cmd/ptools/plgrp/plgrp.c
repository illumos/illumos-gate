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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * The plgrp utility allows a user to display and modify the home lgroup and
 * lgroup affinities of the specified threads
 */

#include <ctype.h>
#include <errno.h>
#include <libintl.h>
#include <libproc.h>
#include <locale.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/lgrp_user.h>


/*
 * Delimiters
 */
#define	DELIMIT_AFF	'/'	/* lgroup affinity from lgroups */
#define	DELIMIT_LGRP	","	/* lgroups from each other */
#define	DELIMIT_LWP	"/"	/* thread/LWP IDs from process ID */
#define	DELIMIT_RANGE	'-'	/* range of IDs (eg. lgroup) */
#define	DELIMIT_AFF_LST ','	/* list of affinities from another list */

/*
 * Exit values other than EXIT_{SUCCESS,FAILURE}
 */
#define	EXIT_NONFATAL 2		/* non-fatal errors */

/*
 * Header and format strings
 */
#define	HDR_PLGRP_AFF_GET	"     PID/LWPID    HOME  AFFINITY\n"
#define	HDR_PLGRP_AFF_SET	"     PID/LWPID    HOME       AFFINITY\n"
#define	HDR_PLGRP_HOME_GET	"     PID/LWPID    HOME\n"
#define	HDR_PLGRP_HOME_SET	"     PID/LWPID    HOME\n"

/*
 * Part of the HDR_PLGRP_AFF_SET header used to calculate space needed to
 * represent changing home as old => new
 */
#define	HDR_PLGRP_HOME_CHANGE	"HOME       "

#define	FMT_AFF			"%d/%s"
#define	FMT_AFF_STR		"%s"
#define	FMT_HOME		"%-6d"
#define	FMT_NEWHOME		"%d => %d"
#define	FMT_THREAD		"%8d/%-8d"

/*
 * How much to allocate for lgroup bitmap array as it grows
 */
#define	LGRP_BITMAP_CHUNK 8

/*
 * Strings that can be given for lgroups
 */
#define	LGRP_ALL_STR		"all"
#define	LGRP_LEAVES_STR		"leaves"
#define	LGRP_ROOT_STR		"root"

/*
 * Strings corresponding to lgroup affinities
 */
#define	LGRP_AFF_NONE_STR	"none"
#define	LGRP_AFF_STRONG_STR	"strong"
#define	LGRP_AFF_WEAK_STR	"weak"

/*
 * Invalid value for lgroup affinity
 */
#define	LGRP_AFF_INVALID	-1

/*
 * Number of args needed for lgroup system call
 */
#define	LGRPSYS_NARGS		3

#ifndef	TEXT_DOMAIN			/* should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* use this only if it wasn't */
#endif

/*
 * plgrp(1) operations
 */
typedef enum plgrp_ops {
	PLGRP_AFFINITY_GET,
	PLGRP_AFFINITY_SET,
	PLGRP_HOME_GET,
	PLGRP_HOME_SET,
	PLGRP_NO_OP
} plgrp_ops_t;

/*
 * Arguments specified to plgrp(1) and any state needed to do everything
 * that plgrp(1) does for one operation from inside Plwp_iter_all()
 */
typedef struct plgrp_args {
	struct ps_prochandle	*Ph;		/* proc handle for process */
	const char		*lwps;		/* LWPs */
	lgrp_id_t		*lgrps;		/* lgroups */
	lgrp_affinity_t		*affs;		/* lgroup affinities */
	int			nlgrps;		/* number of lgroups */
	int			nelements;	/* number of elements */
	int			index;		/* index */
	int			nthreads;	/* threads processed */
	plgrp_ops_t		op;		/* operation */
} plgrp_args_t;

/*
 * How many signals caught from terminal
 * We bail out as soon as possible when interrupt is set
 */
static int	interrupt = 0;

/*
 * How many non-fatal errors ocurred
 */
static int	nerrors = 0;

/*
 * Name of this program
 */
static char	*progname;

/*
 * Root of the lgroup hierarchy
 */
static lgrp_id_t root = LGRP_NONE;

/*
 * Bitmap of all lgroups in the system
 */
static char *lgrps_bitmap = NULL;

/*
 * Size of lgrps_bitmap array
 */
static int lgrps_bitmap_nelements = 0;

/*
 * Macro LGRP_VALID returns true when lgrp is present in the system.
 */
#define	LGRP_VALID(lgrp) (lgrps_bitmap[lgrp] != 0)


/*
 * Maximum lgroup value.
 */
static int max_lgrpid = LGRP_NONE;

/*
 * Total possible number of lgroups
 */
#define	NLGRPS (max_lgrpid + 1)


static void
usage(int rc)
{
	(void) fprintf(stderr,
	    gettext("Usage:\t%s [-h] <pid> | <core> [/lwps] ...\n"), progname);
	(void) fprintf(stderr,
	    gettext("\t%s [-F] -a <lgroup list> <pid>[/lwps] ...\n"), progname);
	(void) fprintf(stderr,
	    gettext("\t%s [-F] -A <lgroup list>/none|weak|strong[,...] "
	    " <pid>[/lwps] ...\n"), progname);
	(void) fprintf(stderr,
	    gettext("\t%s [-F] -H <lgroup list> <pid>[/lwps] ...\n"), progname);
	(void) fprintf(stderr,
	    gettext("\n\twhere <lgroup list> is a comma separated list of\n"
		"\tone or more of the following:\n\n"
		"\t  - lgroup ID\n"
		"\t  - Range of lgroup IDs specified as\n"
		"\t\t<start lgroup ID>-<end lgroup ID>\n"
		"\t  - \"all\"\n"
		"\t  - \"root\"\n"
		"\t  - \"leaves\"\n\n"));

	exit(rc);
}

/*
 * Handler for catching signals from terminal
 */
/* ARGSUSED */
static void
intr(int sig)
{
	interrupt++;
}


/*
 * Return string name for given lgroup affinity
 */
static char *
lgrp_affinity_string(lgrp_affinity_t aff)
{
	char *rc = "unknown";

	switch (aff) {
	case LGRP_AFF_STRONG:
		rc = "strong";
		break;
	case LGRP_AFF_WEAK:
		rc = "weak";
		break;
	case LGRP_AFF_NONE:
		rc = "none";
		break;
	default:
		break;
	}

	return (rc);
}


/*
 * Add a new lgroup into lgroup array in "arg", growing lgroup and affinity
 * arrays if necessary
 */
static void
lgrps_add_lgrp(plgrp_args_t *arg, int id)
{

	if (arg->nlgrps == arg->nelements) {
		arg->nelements += LGRP_BITMAP_CHUNK;

		arg->lgrps = realloc(arg->lgrps,
		    arg->nelements * sizeof (lgrp_id_t));
		if (arg->lgrps == NULL) {
			(void) fprintf(stderr, gettext("%s: out of memory\n"),
			    progname);
			exit(EXIT_FAILURE);
		}

		arg->affs = realloc(arg->affs,
		    arg->nelements * sizeof (lgrp_affinity_t));

		if (arg->affs == NULL) {
			(void) fprintf(stderr, gettext("%s: out of memory\n"),
			    progname);
			exit(EXIT_FAILURE);
		}
	}

	arg->lgrps[arg->nlgrps] = id;
	arg->affs[arg->nlgrps] = LGRP_AFF_INVALID;
	arg->nlgrps++;
}


/*
 * Return an array having '1' for each lgroup present in given subtree under
 * specified lgroup in lgroup hierarchy
 */
static void
lgrps_bitmap_init(lgrp_cookie_t cookie, lgrp_id_t lgrpid, char **bitmap_array,
	int *bitmap_nelements)
{
	lgrp_id_t	*children;
	int		i;
	int		nchildren;

	if (lgrpid < 0) {
		lgrpid = lgrp_root(cookie);
		if (lgrpid < 0)
			return;
	}

	/*
	 * If new lgroup cannot fit, grow the array and fill unused portion
	 * with zeroes.
	 */
	while (lgrpid >= *bitmap_nelements) {
		*bitmap_nelements += LGRP_BITMAP_CHUNK;
		*bitmap_array = realloc(*bitmap_array,
		    *bitmap_nelements * sizeof (char));
		if (*bitmap_array == NULL) {
			(void) fprintf(stderr, gettext("%s: out of memory\n"),
			    progname);
			exit(EXIT_FAILURE);
		}
		bzero(*bitmap_array + NLGRPS,
		    (*bitmap_nelements - NLGRPS) * sizeof (char));
	}

	/*
	 * Insert lgroup into bitmap and update max lgroup ID seen so far
	 */
	(*bitmap_array)[lgrpid] = 1;
	if (lgrpid > max_lgrpid)
		max_lgrpid = lgrpid;

	/*
	 * Get children of specified lgroup and insert descendants of each
	 * of them
	 */
	nchildren = lgrp_children(cookie, lgrpid, NULL, 0);
	if (nchildren > 0) {
		children = malloc(nchildren * sizeof (lgrp_id_t));
		if (children == NULL) {
			(void) fprintf(stderr, gettext("%s: out of memory\n"),
			    progname);
			exit(EXIT_FAILURE);
		}
		if (lgrp_children(cookie, lgrpid, children, nchildren) !=
		    nchildren) {
			free(children);
			return;
		}

		for (i = 0; i < nchildren; i++)
			lgrps_bitmap_init(cookie, children[i], bitmap_array,
			    bitmap_nelements);

		free(children);
	}
}


/*
 * Parse lgroup affinity from given string
 *
 * Return lgroup affinity or LGRP_AFF_INVALID if string doesn't match any
 * existing lgroup affinity and return pointer to position just after affinity
 * string.
 */
static lgrp_affinity_t
parse_lgrp_affinity(char *string, char  **next)
{
	int rc = LGRP_AFF_INVALID;

	if (string == NULL)
		return (LGRP_AFF_INVALID);

	/*
	 * Skip delimiter
	 */
	if (string[0] == DELIMIT_AFF)
		string++;

	/*
	 * Return lgroup affinity matching string
	 */
	if (strncmp(string, LGRP_AFF_NONE_STR, strlen(LGRP_AFF_NONE_STR))
	    == 0) {
		rc = LGRP_AFF_NONE;
		*next = string + strlen(LGRP_AFF_NONE_STR);
	} else if (strncmp(string,
			LGRP_AFF_WEAK_STR, strlen(LGRP_AFF_WEAK_STR)) == 0) {
		rc = LGRP_AFF_WEAK;
		*next = string + strlen(LGRP_AFF_WEAK_STR);
	} else if (strncmp(string, LGRP_AFF_STRONG_STR,
			strlen(LGRP_AFF_STRONG_STR)) == 0) {
		rc = LGRP_AFF_STRONG;
		*next = string + strlen(LGRP_AFF_STRONG_STR);
	}

	return (rc);
}


/*
 * Parse lgroups from given string
 * Returns the set containing all lgroups parsed or NULL.
 */
static int
parse_lgrps(lgrp_cookie_t cookie, plgrp_args_t *arg, char *s)
{
	lgrp_id_t	i;
	char		*token;

	if (cookie == LGRP_COOKIE_NONE || s == NULL || NLGRPS <= 0)
		return (0);

	/*
	 * Parse first lgroup (if any)
	 */
	token = strtok(s, DELIMIT_LGRP);
	if (token == NULL)
		return (-1);

	do {
		/*
		 * Parse lgroups
		 */
		if (isdigit(*token)) {
			lgrp_id_t	first;
			lgrp_id_t	last;
			char		*p;

			/*
			 * lgroup ID(s)
			 *
			 * Can be <lgroup ID>[-<lgroup ID>]
			 */
			p = strchr(token, DELIMIT_RANGE);
			first = atoi(token);
			if (p == NULL)
				last = first;
			else
				last = atoi(++p);

			for (i = first; i <= last; i++) {
				/*
				 * Add valid lgroups to lgroup array
				 */
				if ((i >= 0) && (i < NLGRPS) && LGRP_VALID(i))
					lgrps_add_lgrp(arg, i);
				else  {
					(void) fprintf(stderr,
					    gettext("%s: bad lgroup %d\n"),
					    progname, i);
					nerrors++;
				}
			}
		} else if (strncmp(token, LGRP_ALL_STR,
				strlen(LGRP_ALL_STR)) == 0) {
			/*
			 * Add "all" lgroups to lgroups array
			 */
			for (i = 0; i < NLGRPS; i++) {
				if (LGRP_VALID(i))
					lgrps_add_lgrp(arg, i);
			}
		} else if (strncmp(token, LGRP_ROOT_STR,
				strlen(LGRP_ROOT_STR)) == 0) {
			if (root < 0)
				root = lgrp_root(cookie);
			lgrps_add_lgrp(arg, root);
		} else if (strncmp(token, LGRP_LEAVES_STR,
		    strlen(LGRP_LEAVES_STR)) == 0) {
			/*
			 * Add leaf lgroups to lgroups array
			 */
			for (i = 0; i < NLGRPS; i++) {
				if (LGRP_VALID(i) &&
				    lgrp_children(cookie, i, NULL, 0) == 0)
					lgrps_add_lgrp(arg, i);
			}
		} else {
			return (-1);
		}
	} while (token = strtok(NULL, DELIMIT_LGRP));

	return (0);
}

/*
 * Print array of lgroup IDs, collapsing any consecutive runs of IDs into a
 * range (eg. 2,3,4 into 2-4)
 */
static void
print_lgrps(lgrp_id_t *lgrps, int nlgrps)
{
	lgrp_id_t	start;
	lgrp_id_t	end;
	int		i;

	/*
	 * Initial range consists of the first element
	 */
	start = end = lgrps[0];

	for (i = 1; i < nlgrps; i++) {
		lgrp_id_t	lgrpid;

		lgrpid = lgrps[i];
		if (lgrpid == end + 1) {
			/*
			 * Got consecutive lgroup ID, so extend end of range
			 * without printing anything since the range may extend
			 * further
			 */
			end = lgrpid;
		} else {
			/*
			 * Next lgroup ID is not consecutive, so print lgroup
			 * IDs gotten so far.
			 */
			if (end == start) {		/* same value */
				(void) printf("%d,", (int)start);
			} else if (end > start + 1) {	/* range */
				(void) printf("%d-%d,", (int)start, (int)end);
			} else {			/* different values */
				(void) printf("%d,%d,", (int)start, (int)end);
			}

			/*
			 * Try finding consecutive range starting from this
			 * lgroup ID
			 */
			start = end = lgrpid;
		}
	}

	/*
	 * Print last lgroup ID(s)
	 */
	if (end == start) {
		(void) printf("%d", (int)start);
	} else if (end > start + 1) {
		(void) printf("%d-%d", (int)start, (int)end);
	} else {
		(void) printf("%d,%d", (int)start, (int)end);
	}
}

/*
 * Print lgroup affinities given array of lgroups, corresponding array of
 * affinities, and number of elements.
 * Skip any lgroups set to LGRP_NONE or having invalid affinity.
 */
static void
print_affinities(lgrp_id_t *lgrps, lgrp_affinity_t *affs, int nelements)
{
	int		i;
	lgrp_id_t	*lgrps_none;
	lgrp_id_t	*lgrps_strong;
	lgrp_id_t	*lgrps_weak;
	int		nlgrps_none;
	int		nlgrps_strong;
	int		nlgrps_weak;

	nlgrps_strong = nlgrps_weak = nlgrps_none = 0;

	lgrps_strong = malloc(nelements * sizeof (lgrp_id_t));
	lgrps_weak = malloc(nelements * sizeof (lgrp_id_t));
	lgrps_none = malloc(nelements * sizeof (lgrp_id_t));

	if (lgrps_strong == NULL || lgrps_weak == NULL || lgrps_none == NULL) {
		(void) fprintf(stderr, gettext("%s: out of memory\n"),
		    progname);
		interrupt = 1;
		return;
	}

	/*
	 * Group lgroups by affinity
	 */
	for (i = 0; i < nelements; i++) {
		lgrp_id_t lgrpid = lgrps[i];

		/*
		 * Skip any lgroups set to LGRP_NONE
		 */
		if (lgrpid == LGRP_NONE)
			continue;

		switch (affs[i]) {
		case LGRP_AFF_STRONG:
			lgrps_strong[nlgrps_strong++] = lgrpid;
			break;
		case LGRP_AFF_WEAK:
			lgrps_weak[nlgrps_weak++] = lgrpid;
			break;
		case LGRP_AFF_NONE:
			lgrps_none[nlgrps_none++] = lgrpid;
			break;
		default:
			/*
			 * Skip any lgroups with invalid affinity.
			 */
			break;
		}
	}

	/*
	 * Print all lgroups with same affinity together
	 */
	if (nlgrps_strong) {
		print_lgrps(lgrps_strong, nlgrps_strong);
		(void) printf("/%s", lgrp_affinity_string(LGRP_AFF_STRONG));
		if (nlgrps_weak || nlgrps_none)
			(void) printf("%c", DELIMIT_AFF_LST);
	}

	if (nlgrps_weak) {
		print_lgrps(lgrps_weak, nlgrps_weak);
		(void) printf("/%s", lgrp_affinity_string(LGRP_AFF_WEAK));
		if (nlgrps_none)
			(void) printf("%c", DELIMIT_AFF_LST);
	}

	if (nlgrps_none) {
		print_lgrps(lgrps_none, nlgrps_none);
		(void) printf("/%s", lgrp_affinity_string(LGRP_AFF_NONE));
	}

	free(lgrps_strong);
	free(lgrps_weak);
	free(lgrps_none);
}


/*
 * Print heading for specified operation
 */
static void
print_heading(plgrp_ops_t op)
{

	switch (op) {
	case PLGRP_AFFINITY_GET:
		(void) printf(HDR_PLGRP_AFF_GET);
		break;

	case PLGRP_AFFINITY_SET:
		(void) printf(HDR_PLGRP_AFF_SET);
		break;

	case PLGRP_HOME_GET:
		(void) printf(HDR_PLGRP_HOME_GET);
		break;

	case PLGRP_HOME_SET:
		(void) printf(HDR_PLGRP_HOME_SET);
		break;

	default:
		break;
	}
}

/*
 * Use /proc to call lgrp_affinity_get() in another process
 */
static lgrp_affinity_t
Plgrp_affinity_get(struct ps_prochandle *Ph, idtype_t idtype, id_t id,
    lgrp_id_t lgrp)
{
	lgrp_affinity_args_t	args;
	argdes_t		Pargd[3];
	argdes_t		*Pargdp;
	int			Pnargs;
	int			Pretval;
	sysret_t		retval;
	int			syscall;

	/*
	 * Fill in arguments needed for syscall(SYS_lgrpsys,
	 * LGRP_SYS_AFFINITY_GET, 0, &args)
	 */
	syscall = SYS_lgrpsys;

	args.idtype = idtype;
	args.id = id;
	args.lgrp = lgrp;
	args.aff = LGRP_AFF_INVALID;

	/*
	 * Fill out /proc argument descriptors for syscall(SYS_lgrpsys,
	 * LGRP_SYS_AFFINITY_GET, idtype, id)
	 */
	Pnargs = LGRPSYS_NARGS;
	Pargdp = &Pargd[0];
	Pargdp->arg_value = LGRP_SYS_AFFINITY_GET;
	Pargdp->arg_object = NULL;
	Pargdp->arg_type = AT_BYVAL;
	Pargdp->arg_inout = AI_INPUT;
	Pargdp->arg_size = 0;
	Pargdp++;

	Pargdp->arg_value = 0;
	Pargdp->arg_object = NULL;
	Pargdp->arg_type = AT_BYVAL;
	Pargdp->arg_inout = AI_INPUT;
	Pargdp->arg_size = 0;
	Pargdp++;

	Pargdp->arg_value = 0;
	Pargdp->arg_object = &args;
	Pargdp->arg_type = AT_BYREF;
	Pargdp->arg_inout = AI_INPUT;
	Pargdp->arg_size = sizeof (lgrp_affinity_args_t);
	Pargdp++;

	/*
	 * Have agent LWP call syscall with appropriate arguments in target
	 * process
	 */
	Pretval = Psyscall(Ph, &retval, syscall, Pnargs, &Pargd[0]);
	if (Pretval) {
		errno = (Pretval < 0) ? ENOSYS : Pretval;
		return (LGRP_AFF_INVALID);
	}

	return (retval.sys_rval1);
}


/*
 * Use /proc to call lgrp_affinity_set() in another process
 */
static int
Plgrp_affinity_set(struct ps_prochandle *Ph, idtype_t idtype, id_t id,
    lgrp_id_t lgrp, lgrp_affinity_t aff)
{
	lgrp_affinity_args_t	args;
	argdes_t		Pargd[3];
	argdes_t		*Pargdp;
	int			Pnargs;
	int			Pretval;
	sysret_t		retval;
	int			syscall;

	/*
	 * Fill in arguments needed for syscall(SYS_lgrpsys,
	 * LGRP_SYS_AFFINITY_SET, 0, &args)
	 */
	syscall = SYS_lgrpsys;

	args.idtype = idtype;
	args.id = id;
	args.lgrp = lgrp;
	args.aff = aff;

	/*
	 * Fill out /proc argument descriptors for syscall(SYS_lgrpsys,
	 * LGRP_SYS_AFFINITY_SET, idtype, id)
	 */
	Pnargs = LGRPSYS_NARGS;
	Pargdp = &Pargd[0];
	Pargdp->arg_value = LGRP_SYS_AFFINITY_SET;
	Pargdp->arg_object = NULL;
	Pargdp->arg_type = AT_BYVAL;
	Pargdp->arg_inout = AI_INPUT;
	Pargdp->arg_size = 0;
	Pargdp++;

	Pargdp->arg_value = 0;
	Pargdp->arg_object = NULL;
	Pargdp->arg_type = AT_BYVAL;
	Pargdp->arg_inout = AI_INPUT;
	Pargdp->arg_size = 0;
	Pargdp++;

	Pargdp->arg_value = 0;
	Pargdp->arg_object = &args;
	Pargdp->arg_type = AT_BYREF;
	Pargdp->arg_inout = AI_INPUT;
	Pargdp->arg_size = sizeof (lgrp_affinity_args_t);
	Pargdp++;

	/*
	 * Have agent LWP call syscall with appropriate arguments in
	 * target process
	 */
	Pretval = Psyscall(Ph, &retval, syscall, Pnargs, &Pargd[0]);
	if (Pretval) {
		errno = (Pretval < 0) ? ENOSYS : Pretval;
		return (-1);
	}

	return (retval.sys_rval1);
}

/*
 * Use /proc to call lgrp_home() in another process
 */
static lgrp_id_t
Plgrp_home(struct ps_prochandle *Ph, idtype_t idtype, id_t id)
{
	argdes_t		Pargd[3];
	argdes_t		*Pargdp;
	int			Pnargs;
	int			Pretval;
	sysret_t		retval;
	int			syscall;

	/*
	 * Fill in arguments needed for syscall(SYS_lgrpsys,
	 * LGRP_SYS_HOME, idtype, id)
	 */
	syscall = SYS_lgrpsys;

	/*
	 * Fill out /proc argument descriptors for syscall(SYS_lgrpsys,
	 * LGRP_SYS_HOME, idtype, id)
	 */
	Pnargs = LGRPSYS_NARGS;
	Pargdp = &Pargd[0];
	Pargdp->arg_value = LGRP_SYS_HOME;
	Pargdp->arg_object = NULL;
	Pargdp->arg_type = AT_BYVAL;
	Pargdp->arg_inout = AI_INPUT;
	Pargdp->arg_size = 0;
	Pargdp++;

	Pargdp->arg_value = idtype;
	Pargdp->arg_object = NULL;
	Pargdp->arg_type = AT_BYVAL;
	Pargdp->arg_inout = AI_INPUT;
	Pargdp->arg_size = 0;
	Pargdp++;

	Pargdp->arg_value = id;
	Pargdp->arg_object = NULL;
	Pargdp->arg_type = AT_BYVAL;
	Pargdp->arg_inout = AI_INPUT;
	Pargdp->arg_size = 0;
	Pargdp++;

	/*
	 * Have agent LWP call syscall with appropriate arguments in
	 * target process
	 */
	Pretval = Psyscall(Ph, &retval, syscall, Pnargs, &Pargd[0]);
	if (Pretval) {
		errno = (Pretval < 0) ? ENOSYS : Pretval;
		return (-1);
	}

	return (retval.sys_rval1);
}

/*
 * Use /proc to call lgrp_affinity_set(3LGRP) to set home lgroup of given
 * thread
 */
static int
Plgrp_home_set(struct ps_prochandle *Ph, idtype_t idtype, id_t id,
    lgrp_id_t lgrp)
{
	return (Plgrp_affinity_set(Ph, idtype, id, lgrp,
	    LGRP_AFF_STRONG));
}


/*
 * Do plgrp(1) operation on specified thread
 */
static int
do_op(plgrp_args_t *plgrp_args, id_t pid, id_t lwpid,
    const lwpsinfo_t *lwpsinfo)
{
	lgrp_affinity_t		*affs;
	lgrp_affinity_t		*cur_affs;
	lgrp_id_t		home;
	int			i;
	lgrp_affinity_t		*init_affs;
	lgrp_id_t		*lgrps;
	lgrp_id_t		*lgrps_changed;
	int			nlgrps;
	lgrp_id_t		old_home;
	lgrp_id_t		lgrpid;
	struct ps_prochandle	*Ph;
	int			nchanged;

	/*
	 * No args, so nothing to do.
	 */
	if (plgrp_args == NULL)
		return (0);

	/*
	 * Unpack plgrp(1) arguments and state needed to process this LWP
	 */
	Ph = plgrp_args->Ph;
	lgrps = plgrp_args->lgrps;
	affs = plgrp_args->affs;
	nlgrps = plgrp_args->nlgrps;

	switch (plgrp_args->op) {

	case PLGRP_HOME_GET:
		/*
		 * Get and display home lgroup for given LWP
		 */
		home = lwpsinfo->pr_lgrp;
		(void) printf(FMT_HOME"\n", (int)home);
		break;

	case PLGRP_AFFINITY_GET:
		/*
		 * Get and display this LWP's home lgroup and affinities
		 * for specified lgroups
		 */
		home = lwpsinfo->pr_lgrp;
		(void) printf(FMT_HOME, (int)home);

		/*
		 * Collect affinity values
		 */
		for (i = 0; i < nlgrps; i++) {
			affs[i] = Plgrp_affinity_get(Ph, P_LWPID, lwpid,
			    lgrps[i]);

			if (affs[i] == LGRP_AFF_INVALID) {
				nerrors++;
				(void) fprintf(stderr,
				    gettext("%s: cannot get affinity"
					" for lgroup %d for %d/%d: %s\n"),
				    progname, lgrps[i], pid, lwpid,
				    strerror(errno));
			}
		}

		/*
		 * Print affinities for each type.
		 */
		print_affinities(lgrps, affs, nlgrps);
		(void) printf("\n");

		break;

	case PLGRP_HOME_SET:
		/*
		 * Get home lgroup before and after setting it and display
		 * change.  If more than one lgroup and one LWP are specified,
		 * then home LWPs to lgroups in round robin fashion.
		 */
		old_home = lwpsinfo->pr_lgrp;

		i = plgrp_args->index;
		if (Plgrp_home_set(Ph, P_LWPID, lwpid, lgrps[i]) != 0) {
			nerrors++;
			(void) fprintf(stderr,
			    gettext("%s: cannot set home lgroup of %d/%d"
				" to lgroup %d: %s\n"),
				progname, pid, lwpid, lgrps[i],
			    strerror(errno));
			(void) printf("\n");
		} else {
			int len;
			int width = strlen(HDR_PLGRP_HOME_CHANGE);

			home = Plgrp_home(Ph, P_LWPID, lwpid);

			if (home < 0) {
				(void) fprintf(stderr,
				    gettext("%s cannot get home lgroup for"
					" %d/%d: %s\n"),
				    progname, pid, lwpid, strerror(errno));
				nerrors++;
			}

			len = printf(FMT_NEWHOME, (int)old_home, (int)home);
			if (len < width)
				(void) printf("%*c\n", (int)(width - len), ' ');
		}

		plgrp_args->index = (i + 1) % nlgrps;

		break;

	case PLGRP_AFFINITY_SET:
		/*
		 * Set affinities for specified lgroups and print old and new
		 * affinities and any resulting change in home lgroups
		 */

		/*
		 * Get initial home lgroup as it may change.
		 */
		old_home = lwpsinfo->pr_lgrp;

		/*
		 * Need to allocate arrays indexed by lgroup (ID) for
		 * affinities and lgroups because user may specify affinity
		 * for same lgroup multiple times....
		 *
		 * Keeping these arrays by lgroup (ID) eliminates any
		 * duplication and makes it easier to just print initial and
		 * final lgroup affinities (instead of trying to keep a list
		 * of lgroups specified which may include duplicates)
		 */
		init_affs = malloc(NLGRPS * sizeof (lgrp_affinity_t));
		cur_affs = malloc(NLGRPS * sizeof (lgrp_affinity_t));
		lgrps_changed = malloc(NLGRPS * sizeof (lgrp_id_t));

		if (init_affs == NULL || cur_affs == NULL ||
		    lgrps_changed == NULL) {
			(void) fprintf(stderr, gettext("%s: out of memory\n"),
			    progname);
			Prelease(Ph, PRELEASE_RETAIN);
			if (init_affs != NULL)
				free(init_affs);
			if (cur_affs != NULL)
				free(cur_affs);
			nerrors++;
			return (EXIT_NONFATAL);
		}

		/*
		 * Initialize current and initial lgroup affinities and
		 * lgroups changed
		 */
		for (lgrpid = 0; lgrpid < NLGRPS; lgrpid++) {

			if (!LGRP_VALID(lgrpid)) {
				init_affs[lgrpid] = LGRP_AFF_INVALID;
			} else {
				init_affs[lgrpid] =
				    Plgrp_affinity_get(Ph, P_LWPID,
					lwpid, lgrpid);

				if (init_affs[lgrpid] == LGRP_AFF_INVALID) {
					nerrors++;
					(void) fprintf(stderr,
					    gettext("%s: cannot get"
						" affinity for lgroup %d"
						" for %d/%d: %s\n"),
					    progname, lgrpid, pid, lwpid,
					    strerror(errno));
				}
			}

			cur_affs[lgrpid] = init_affs[lgrpid];
			lgrps_changed[lgrpid] = LGRP_NONE;
		}

		/*
		 * Change affinities.
		 */
		for (i = 0; i < nlgrps; i++) {
			lgrp_affinity_t	aff = affs[i];

			lgrpid = lgrps[i];

			/*
			 * If the suggested affinity is the same as the current
			 * one, skip this lgroup.
			 */
			if (aff == cur_affs[lgrpid])
				continue;

			/*
			 * Set affinity to the new value
			 */
			if (Plgrp_affinity_set(Ph, P_LWPID, lwpid, lgrpid,
				aff) < 0) {
				nerrors++;
				(void) fprintf(stderr,
				    gettext("%s: cannot set"
					" %s affinity for lgroup %d"
					" for %d/%d: %s\n"),
				    progname, lgrp_affinity_string(aff),
				    lgrpid, pid, lwpid,
				    strerror(errno));
				continue;
			}

			/*
			 * Get the new value and verify that it changed as
			 * expected.
			 */
			cur_affs[lgrpid] =
			    Plgrp_affinity_get(Ph, P_LWPID, lwpid, lgrpid);

			if (cur_affs[lgrpid] == LGRP_AFF_INVALID) {
				nerrors++;
				(void) fprintf(stderr,
				    gettext("%s: cannot get"
					" affinity for lgroup %d"
					" for %d/%d: %s\n"),
				    progname, lgrpid, pid, lwpid,
				    strerror(errno));
				continue;
			}

			if (aff != cur_affs[lgrpid]) {
				(void) fprintf(stderr,
				    gettext("%s: affinity for"
					" lgroup %d is set to %d instead of %d"
					" for %d/%d\n"),
				    progname, lgrpid, cur_affs[lgrpid], aff,
				    pid, lwpid);
				nerrors++;
			}
		}

		/*
		 * Compare current and initial affinities and mark lgroups with
		 * changed affinities.
		 */
		nchanged = 0;
		for (lgrpid = 0; lgrpid < NLGRPS; lgrpid++) {
			if (init_affs[lgrpid] != cur_affs[lgrpid]) {
				lgrps_changed[lgrpid] = lgrpid;
				nchanged++;
			}
		}

		if (nchanged == 0) {
			/*
			 * Nothing changed, so just print current affinities for
			 * specified lgroups.
			 */
			for (i = 0; i < nlgrps; i++) {
				lgrps_changed[lgrps[i]] = lgrps[i];
			}

			(void) printf("%-*d",
			    (int)strlen(HDR_PLGRP_HOME_CHANGE),
			    (int)old_home);

			print_affinities(lgrps_changed, cur_affs, NLGRPS);
			(void) printf("\n");
		} else {
			int width = strlen(HDR_PLGRP_HOME_CHANGE);

			/*
			 * Some lgroup affinities changed, so display old
			 * and new home lgroups for thread and its old and new
			 * affinities for affected lgroups
			 */
			home = Plgrp_home(Ph, P_LWPID, lwpid);
			if (home < 0) {
				(void) fprintf(stderr,
				    gettext("%s: cannot get home"
					" for %d/%d: %s\n"),
				    progname, pid, lwpid, strerror(errno));
				nerrors++;
			}
			if (old_home != home) {
				int len;

				/*
				 * Fit string into fixed width
				 */
				len = printf(FMT_NEWHOME,
				    (int)old_home, (int)home);
				if (len < width)
					(void) printf("%*c", width - len, ' ');
			} else {
				(void) printf("%-*d", width, (int)home);
			}

			/*
			 * Print change in affinities from old to new
			 */
			print_affinities(lgrps_changed, init_affs, NLGRPS);
			(void) printf(" => ");
			print_affinities(lgrps_changed, cur_affs, NLGRPS);
			(void) printf("\n");
		}

		free(lgrps_changed);
		free(init_affs);
		free(cur_affs);

		break;

	default:
		break;
	}

	return (0);
}


/*
 * Routine called by Plwp_iter_all() as it iterates through LWPs of another
 * process
 */
/* ARGSUSED */
static int
Plwp_iter_handler(void *arg, const lwpstatus_t *lwpstatus,
    const lwpsinfo_t *lwpsinfo)
{
	id_t			lwpid;
	struct ps_prochandle	*Ph;
	const pstatus_t		*pstatus;
	plgrp_args_t		*plgrp_args;

	/*
	 * Nothing to do if no arguments
	 */
	if (arg == NULL || interrupt)
		return (0);

	/*
	 * Unpack plgrp(1) arguments and state needed to process this LWP
	 */
	plgrp_args = arg;
	Ph = plgrp_args->Ph;

	/*
	 * Just return if no /proc handle for process
	 */
	if (Ph == NULL)
		return (0);

	pstatus = Pstatus(Ph);

	/*
	 * Skip agent LWP and any LWPs that weren't specified
	 */
	lwpid = lwpsinfo->pr_lwpid;
	if (lwpid == pstatus->pr_agentid ||
	    !proc_lwp_in_set(plgrp_args->lwps, lwpid))
		return (0);

	plgrp_args->nthreads++;

	/*
	 * Do all plgrp(1) operations specified on given thread
	 */
	(void) printf(FMT_THREAD" ", (int)pstatus->pr_pid, (int)lwpid);
	return (do_op(plgrp_args, pstatus->pr_pid, lwpid, lwpsinfo));
}

/*
 * Get target process specified in "pidstring" argument to do operation(s)
 * specified in "plgrp_todo" using /proc and agent LWP
 */
static void
do_process(char *pidstring, plgrp_args_t *plgrp_todo, int force)
{
	int			error;
	const char		*lwps;
	struct ps_prochandle	*Ph;

	/*
	 * Nothing to do, so return.
	 */
	if (plgrp_todo == NULL || interrupt)
		return;

	/*
	 * Grab target process or core and return
	 * /proc handle for process and string of LWP
	 * IDs
	 */
	Ph = proc_arg_xgrab(pidstring, NULL,
	    PR_ARG_ANY, force | PGRAB_RETAIN | PGRAB_NOSTOP, &error, &lwps);
	if (Ph == NULL) {
		(void) fprintf(stderr,
		    gettext("%s: Unable to grab process %s: %s\n"),
		    progname, pidstring, Pgrab_error(error));
		nerrors++;
		return;
	}

	/*
	 * Fill in remaining plgrp(1) arguments and state needed to do
	 * plgrp(1) operation(s) on desired LWPs in our handler
	 * called by Plwp_iter_all() as it iterates over LWPs
	 * in given process
	 */
	plgrp_todo->Ph = Ph;
	plgrp_todo->lwps = lwps;

	/*
	 * Iterate over LWPs in process and do specified
	 * operation(s) on those specified
	 */
	if (Plwp_iter_all(Ph, Plwp_iter_handler, plgrp_todo) != 0) {
		(void) fprintf(stderr,
		    gettext("%s: error iterating over threads\n"),
		    progname);
		nerrors++;
	}

	Prelease(Ph, PRELEASE_RETAIN);
}


/*
 * Parse command line and kick off any resulting actions
 *
 * plgrp(1) has the following command line syntax:
 *
 *	plgrp [-h] <pid> | <core> [/lwps] ...
 *	plgrp [-F] -a <lgroup>,... <pid>[/lwps] ...
 *	plgrp [-F] -H <lgroup>,... <pid>[/lwps] ...
 *	plgrp [-F] -A <lgroup>,... [/none|weak|strong] ... <pid>[/lwps] ...
 *
 *	where <lgroup> is an lgroup ID, "all", "root", "leaves".
 */
int
main(int argc, char *argv[])
{
	lgrp_affinity_t		aff;
	char			*affstring;
	int			c;
	lgrp_cookie_t		cookie;
	int			Fflag;
	int			i;
	int			opt_seen;
	plgrp_args_t		plgrp_todo;
	char			*s;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	opt_seen = 0;

	/*
	 * Get name of program
	 */
	progname = basename(argv[0]);

	/*
	 * Not much to do when only name of program given
	 */
	if (argc == 1)
		usage(0);

	/*
	 * Catch signals from terminal, so they can be handled asynchronously
	 * when we're ready instead of when we're not (;-)
	 */
	if (sigset(SIGHUP, SIG_IGN) == SIG_DFL)
		(void) sigset(SIGHUP, intr);
	if (sigset(SIGINT, SIG_IGN) == SIG_DFL)
		(void) sigset(SIGINT, intr);
	if (sigset(SIGQUIT, SIG_IGN) == SIG_DFL)
		(void) sigset(SIGQUIT, intr);
	(void) sigset(SIGPIPE, intr);
	(void) sigset(SIGTERM, intr);

	/*
	 * Take snapshot of lgroup hierarchy
	 */
	cookie = lgrp_init(LGRP_VIEW_OS);
	if (cookie == LGRP_COOKIE_NONE) {
		(void) fprintf(stderr,
		    gettext("%s: Fatal error: cannot get lgroup"
			" information from the OS: %s\n"),
		    progname, strerror(errno));
		return (EXIT_FAILURE);
	}

	root = lgrp_root(cookie);
	lgrps_bitmap_init(cookie, root, &lgrps_bitmap, &lgrps_bitmap_nelements);

	/*
	 * Remember arguments and state needed to do plgrp(1) operation
	 * on desired LWPs
	 */
	bzero(&plgrp_todo, sizeof (plgrp_args_t));
	plgrp_todo.op = PLGRP_HOME_GET;

	/*
	 * Parse options
	 */
	opterr = 0;
	Fflag = 0;
	while (!interrupt && (c = getopt(argc, argv, "a:A:FhH:")) != -1) {
		/*
		 * Parse option and only allow one option besides -F to be
		 * specified
		 */
		switch (c) {

		case 'h':	/* Get home lgroup */
			/*
			 * Only allow one option (besides -F) to be specified
			 */
			if (opt_seen)
				usage(EXIT_FAILURE);
			opt_seen = 1;

			plgrp_todo.op = PLGRP_HOME_GET;
			break;

		case 'H':	/* Set home lgroup */

			/*
			 * Fail if already specified option (besides -F)
			 * or no more arguments
			 */
			if (opt_seen || optind >= argc) {
				usage(EXIT_FAILURE);
			}
			opt_seen = 1;

			plgrp_todo.op = PLGRP_HOME_SET;

			if (parse_lgrps(cookie, &plgrp_todo, optarg) < 0)
				usage(EXIT_FAILURE);

			/* If there are no valid lgroups exit immediately */
			if (plgrp_todo.nlgrps == 0) {
				(void) fprintf(stderr,
				    gettext("%s: no valid lgroups"
					" specified for -%c\n\n"),
				    progname, c);
				    usage(EXIT_FAILURE);
			}

			break;

		case 'a':	/* Get lgroup affinity */

			/*
			 * Fail if already specified option (besides -F)
			 * or no more arguments
			 */
			if (opt_seen || optind >= argc) {
				usage(EXIT_FAILURE);
			}
			opt_seen = 1;

			plgrp_todo.op = PLGRP_AFFINITY_GET;

			if (parse_lgrps(cookie, &plgrp_todo, optarg) < 0)
				usage(EXIT_FAILURE);

			/* If there are no valid lgroups exit immediately */
			if (plgrp_todo.nlgrps == 0) {
				(void) fprintf(stderr,
				    gettext("%s: no valid lgroups specified"
					" for -%c\n\n"),
				    progname, c);
				    usage(EXIT_FAILURE);
			}

			break;

		case 'A':	/* Set lgroup affinity */

			/*
			 * Fail if already specified option (besides -F)
			 * or no more arguments
			 */
			if (opt_seen || optind >= argc) {
				usage(EXIT_FAILURE);
			}
			opt_seen = 1;

			plgrp_todo.op = PLGRP_AFFINITY_SET;

			/*
			 * 'affstring' is the unparsed prtion of the affinity
			 * specification like 1,2/none,2/weak,0/strong
			 *
			 * 'next' is the next affinity specification to parse.
			 */
			affstring = optarg;
			while (affstring != NULL && strlen(affstring) > 0) {
				char	*next;

				/*
				 * affstring points to the first affinity
				 * specification. Split the string by
				 * DELIMIT_AFF separator and parse lgroups and
				 * affinity value separately.
				 */
				s = strchr(affstring, DELIMIT_AFF);
				if (s == NULL) {
					(void) fprintf(stderr,
					    gettext("%s: invalid "
						"syntax >%s<\n"),
					    progname, affstring);
					usage(EXIT_FAILURE);
				}

				aff = parse_lgrp_affinity(s, &next);
				if (aff == LGRP_AFF_INVALID) {
					(void) fprintf(stderr,
					    gettext("%s: invalid "
						"affinity >%s<\n"),
					    progname, affstring);
					usage(EXIT_FAILURE);
				}

				/*
				 * next should either point to the empty string
				 * or to the DELIMIT_AFF_LST separator.
				 */
				if (*next != '\0') {
					if (*next != DELIMIT_AFF_LST) {
						(void) fprintf(stderr,
						    gettext("%s: invalid "
							"syntax >%s<\n"),
						    progname, next);
						usage(EXIT_FAILURE);
					}
					*next = '\0';
					next++;
				}


				/*
				 * Now parse the list of lgroups
				 */
				if (parse_lgrps(cookie, &plgrp_todo,
					affstring) < 0) {
					usage(EXIT_FAILURE);
				}

				/*
				 * Set desired affinity for specified lgroup to
				 * the specified affinity.
				 */
				for (i = 0; i < plgrp_todo.nlgrps; i++) {
					if (plgrp_todo.affs[i] ==
					    LGRP_AFF_INVALID)
						plgrp_todo.affs[i] = aff;
				}

				/*
				 * We processed the leftmost element of the
				 * list. Advance affstr to the remaining part of
				 * the list. and repeat.
				 */
				affstring = next;
			}

			/*
			 * If there are no valid lgroups, exit immediately
			 */
			if (plgrp_todo.nlgrps == 0) {
				(void) fprintf(stderr,
				    gettext("%s: no valid lgroups specified "
				    "for -%c\n\n"), progname, c);
				    usage(EXIT_FAILURE);
			}

			break;

		case 'F':	/* Force */

			/*
			 * Only allow one occurrence
			 */
			if (Fflag != 0) {
				usage(EXIT_FAILURE);
			}

			/*
			 * Set flag to force /proc to grab process even though
			 * it's been grabbed by another process already
			 */
			Fflag = PGRAB_FORCE;
			break;

		case '?':	/* Unrecognized option */
		default:
			usage(EXIT_FAILURE);
			break;

		}
	}

	/*
	 * Should have more arguments left at least for PID or core
	 */
	if (optind >= argc)
		usage(EXIT_FAILURE);

	(void) lgrp_fini(cookie);

	/*
	 * Print heading and process each [pid | core]/lwps argument
	 */
	print_heading(plgrp_todo.op);
	(void) proc_initstdio();

	for (i = optind; i < argc && !interrupt; i++) {
		(void) proc_flushstdio();
		do_process(argv[i], &plgrp_todo, Fflag);
	}

	(void) proc_finistdio();

	if (plgrp_todo.nthreads == 0) {
		(void) fprintf(stderr, gettext("%s: no matching LWPs found\n"),
		    progname);
	}

	return ((nerrors ||interrupt) ? EXIT_NONFATAL : EXIT_SUCCESS);
}
