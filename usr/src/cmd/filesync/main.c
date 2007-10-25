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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * module:
 *	main.c
 *
 * purpose:
 *	argument handling and top level dispatch
 *
 * contents:
 *	main		argument handling and main loop
 *	usage		(static) print out usage message
 *	confirm		prompt the user for a confirmation and get it
 *	nomem		fatal error handler for malloc failures
 *	findfiles	(static) locate our baseline and rules files
 *	cleanup		(static) unlock baseline and delete temp file
 *	check_access	(static) do we have adequate access to a file/directory
 *	whoami		(static) get uid/gid/umask
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>

#include "filesync.h"
#include "database.h"
#include "messages.h"
#include "debug.h"

/*
 * local routines in this module:
 */
static errmask_t findfiles();		/* find rule and baseline files	*/
static void cleanup(int);		/* cleanup locks and temps	*/
static errmask_t check_access(char *, int *); /* check access to file	*/
static void whoami();			/* gather information about me	*/
static void usage(void);		/* general usage		*/


/*
 * globals exported to the rest of the program
 */
bool_t	opt_mtime;	/* preserve modification times on propagations	*/
bool_t	opt_notouch;	/* don't actually make any changes		*/
bool_t	opt_quiet;	/* disable reconciliation command output	*/
bool_t	opt_verbose;	/* enable analysis descriptions			*/
side_t	opt_force;	/* designated winner for conflicts		*/
side_t	opt_oneway;	/* one way only propagation			*/
side_t	opt_onesided;	/* permit one-sided evaluation			*/
bool_t	opt_everything;	/* everything must agree (modes/uid/gid)	*/
bool_t	opt_yes;	/* pre-confirm massive deletions are OK		*/
bool_t	opt_acls;	/* always scan for acls on all files		*/
bool_t	opt_errors;	/* simulate errors on specified files		*/
bool_t	opt_halt;	/* halt on propagation errors			*/
dbgmask_t opt_debug;	/* debug mask					*/

uid_t	my_uid;		/* default UID for files I create		*/
gid_t	my_gid;		/* default GID for files I create		*/

static char *file_rules; /* name of rules file				*/
static char *file_base;	/* name of baseline file			*/

static int new_baseline; /* are we creating a new baseline		*/
static int new_rules;	/* are we creating a new rules file		*/
static int my_umask;	/* default UMASK for files I create		*/
static int lockfd;	/* file descriptor for locking baseline		*/

static char *rlist[MAX_RLIST];
static int num_restrs = 0;

/*
 * routine:
 *	main
 *
 * purpose:
 *	argument processing and primary dispatch
 *
 * returns:
 *	error codes per filesync.1 (ERR_* in filesync.h)
 *
 * notes:
 *	read filesync.1 in order to understand the argument processing
 *
 *	most of the command line options just set some opt_ global
 *	variable that is later looked at by the code that actually
 *	implements the features.  Only file names are really processed
 *	in this routine.
 */
int
main(int argc, char **argv)
{	int i;
	int c;
	errmask_t errs = ERR_OK;
	int do_prune = 0;
	char *srcname = 0;
	char *dstname = 0;
	struct base *bp;

	/* keep the error messages simple	*/
	argv[0] = "filesync";

	/* gather together all of the options	*/
	while ((c = getopt(argc, argv, "AaehmnqvyD:E:r:s:d:f:o:")) != EOF)
		switch (c) {
			case 'a':	/* always scan for acls	*/
				opt_acls = TRUE;
				break;
			case 'e':	/* everything agrees	*/
				opt_everything = TRUE;
				break;
			case 'h':	/* halt on error	*/
				opt_halt = TRUE;
				break;
			case 'm':	/* preserve modtimes	*/
				opt_mtime = TRUE;
				break;
			case 'n':	/* notouch		*/
				opt_notouch = TRUE;
				break;
			case 'q':	/* quiet		*/
				opt_quiet = TRUE;
				break;
			case 'v':	/* verbose		*/
				opt_verbose = TRUE;
				break;
			case 'y':	/* yes			*/
				opt_yes = TRUE;
				break;
			case 'D':	/* debug options	*/
				if (!isdigit(optarg[0])) {
					dbg_usage();
					exit(ERR_INVAL);
				}
				opt_debug |= strtol(optarg, (char **)NULL, 0);
				break;

			case 'E':	/* error simulation	*/
				if (dbg_set_error(optarg)) {
					err_usage();
					exit(ERR_INVAL);
				}
				opt_errors = TRUE;
				break;

			case 'f':	/* force conflict resolution	*/
				switch (optarg[0]) {
					case 's':
						opt_force = OPT_SRC;
						break;
					case 'd':
						opt_force = OPT_DST;
						break;
					case 'o':
						opt_force = OPT_OLD;
						break;
					case 'n':
						opt_force = OPT_NEW;
						break;
					default:
						fprintf(stderr,
							gettext(ERR_badopt),
							c, optarg);
						errs |= ERR_INVAL;
						break;
				}
				break;

			case 'o':	/* one way propagation		*/
				switch (optarg[0]) {
					case 's':
						opt_oneway = OPT_SRC;
						break;
					case 'd':
						opt_oneway = OPT_DST;
						break;
					default:
						fprintf(stderr,
							gettext(ERR_badopt),
							c, optarg);
						errs |= ERR_INVAL;
						break;
				}
				break;

			case 'r':	/* restricted reconciliation	*/
				if (num_restrs < MAX_RLIST)
					rlist[ num_restrs++ ] = optarg;
				else {
					fprintf(stderr, gettext(ERR_tomany),
						MAX_RLIST);
					errs |= ERR_INVAL;
				}
				break;

			case 's':
				if ((srcname = qualify(optarg)) == 0)
					errs |= ERR_MISSING;
				break;

			case 'd':
				if ((dstname = qualify(optarg)) == 0)
					errs |= ERR_MISSING;
				break;

			default:
			case '?':
				errs |= ERR_INVAL;
				break;
		}

	if (opt_debug & DBG_MISC)
		fprintf(stderr, "MISC: DBG=%s\n", showflags(dbgmap, opt_debug));

	/* if we have file names, we need a source and destination */
	if (optind < argc) {
		if (srcname == 0) {
			fprintf(stderr, gettext(ERR_nosrc));
			errs |= ERR_INVAL;
		}
		if (dstname == 0) {
			fprintf(stderr, gettext(ERR_nodst));
			errs |= ERR_INVAL;
		}
	}

	/* check for simple usage errors	*/
	if (errs & ERR_INVAL) {
		usage();
		exit(errs);
	}

	/* locate our baseline and rules files	*/
	if (c = findfiles())
		exit(c);

	/* figure out file creation defaults	*/
	whoami();

	/* read in our initial baseline		*/
	if (!new_baseline && (c = read_baseline(file_base)))
		errs |= c;

	/* read in the rules file if we need or have rules	*/
	if (optind >= argc && new_rules) {
		fprintf(stderr, ERR_nonames);
		errs |= ERR_INVAL;
	} else if (!new_rules)
		errs |= read_rules(file_rules);

	/* if anything has failed with our setup, go no further	*/
	if (errs) {
		cleanup(errs);
		exit(errs);
	}

	/*
	 * figure out whether or not we are willing to do a one-sided
	 * analysis (where we don't even look at the other side.  This
	 * is an "I'm just curious what has changed" query, and we are
	 * only willing to do it if:
	 *	we aren't actually going to do anything
	 *	we have a baseline we can compare against
	 * otherwise, we are going to insist on being able to access
	 * both the source and destination.
	 */
	if (opt_notouch && !new_baseline)
		opt_onesided = opt_oneway;

	/*
	 * there are two interested usage scenarios:
	 *	file names specified
	 *		create new rules for the specified files
	 *		evaulate and reconcile only the specified files
	 *	no file names specified
	 *		use already existing rules
	 *		consider restricting them to specified subdirs/files
	 */
	if (optind < argc) {
		/* figure out what base pair we're working on	*/
		bp = add_base(srcname, dstname);

		/* perverse default rules to avoid trouble	*/
		if (new_rules) {
			errs |= add_ignore(0, SUFX_RULES);
			errs |= add_ignore(0, SUFX_BASE);
		}

		/* create include rules for each file/dir arg	*/
		while (optind < argc)
			errs |= add_include(bp, argv[ optind++ ]);

		/*
		 * evaluate the specified base on each side,
		 * being careful to limit evaulation to new rules
		 */
		errs |= evaluate(bp, OPT_SRC, TRUE);
		errs |= evaluate(bp, OPT_DST, TRUE);
	} else {
		/* note any possible evaluation restrictions	*/
		for (i = 0; i < num_restrs; i++)
			errs |= add_restr(rlist[i]);

		/*
		 * we can only prune the baseline file if we have done
		 * a complete (unrestricted) analysis.
		 */
		if (i == 0)
			do_prune = 1;

		/* evaulate each base on each side		*/
		for (bp = bases; bp; bp = bp->b_next) {
			errs |= evaluate(bp, OPT_SRC, FALSE);
			errs |= evaluate(bp, OPT_DST, FALSE);
		}
	}

	/* if anything serious happened, skip reconciliation	*/
	if (errs & ERR_FATAL) {
		cleanup(errs);
		exit(errs);
	}

	/* analyze and deal with the differenecs		*/
	errs |= analyze();

	/* see if there is any dead-wood in the baseline	*/
	if (do_prune) {
		c = prune();

		if (c > 0 && opt_verbose)
			fprintf(stdout, V_prunes, c);
	}

	/* print out a final summary				*/
	summary();

	/* update the rules and baseline files (if needed)	*/
	(void) umask(my_umask);
	errs |= write_baseline(file_base);
	errs |= write_rules(file_rules);

	if (opt_debug & DBG_MISC)
		fprintf(stderr, "MISC: EXIT=%s\n", showflags(errmap, errs));

	/* just returning ERR_RESOLVABLE upsets some people	*/
	if (errs == ERR_RESOLVABLE && !opt_notouch)
		errs = 0;

	/* all done	*/
	cleanup(0);
	return (errs);
}


/*
 * routine:
 *	usage
 *
 * purpose:
 *	print out a usage message
 *
 * parameters:
 *	none
 *
 * returns:
 *	none
 *
 * note:
 *	the -D and -E switches are for development/test/support
 *	use only and do not show up in the general usage message.
 */
static void
usage(void)
{
	fprintf(stderr, "%s\t%s %s\n", gettext(ERR_usage), "filesync",
					gettext(USE_simple));
	fprintf(stderr, "\t%s %s\n", "filesync", gettext(USE_all));
	fprintf(stderr, "\t-a .......... %s\n", gettext(USE_a));
	fprintf(stderr, "\t-e .......... %s\n", gettext(USE_e));
	fprintf(stderr, "\t-h .......... %s\n", gettext(USE_h));
	fprintf(stderr, "\t-m .......... %s\n", gettext(USE_m));
	fprintf(stderr, "\t-n .......... %s\n", gettext(USE_n));
	fprintf(stderr, "\t-q .......... %s\n", gettext(USE_q));
	fprintf(stderr, "\t-v .......... %s\n", gettext(USE_v));
	fprintf(stderr, "\t-y .......... %s\n", gettext(USE_y));
	fprintf(stderr, "\t-s dir ...... %s\n", gettext(USE_s));
	fprintf(stderr, "\t-d dir ...... %s\n", gettext(USE_d));
	fprintf(stderr, "\t-r dir ...... %s\n", gettext(USE_r));
	fprintf(stderr, "\t-f [sdon].... %s\n", gettext(USE_f));
	fprintf(stderr, "\t-o src/dst... %s\n", gettext(USE_o));
}

/*
 * routine:
 *	confirm
 *
 * purpose:
 *	to confirm that the user is willing to do something dangerous
 *
 * parameters:
 *	warning message to be printed
 *
 * returns:
 * 	void
 *
 * notes:
 *	if this is a "notouch" or if the user has pre-confirmed,
 *	we should not obtain the confirmation and just return that
 *	the user has confirmed.
 */
void
confirm(char *message)
{	FILE *ttyi, *ttyo;
	char ansbuf[ MAX_LINE ];

	/* if user pre-confirmed, we don't have to ask	*/
	if (opt_yes || opt_notouch)
		return;

	ttyo = fopen("/dev/tty", "w");
	ttyi = fopen("/dev/tty", "r");
	if (ttyi == NULL || ttyo == NULL)
		exit(ERR_OTHER);

	/* explain the problem and prompt for confirmation	*/
	fprintf(ttyo, message);
	fprintf(ttyo, gettext(WARN_proceed));

	/* if the user doesn't kill us, we can continue		*/
	(void) fgets(ansbuf, sizeof (ansbuf), ttyi);

	/* close the files and return				*/
	(void) fclose(ttyi);
	(void) fclose(ttyo);
}

void
nomem(char *reason)
{
	fprintf(stderr, gettext(ERR_nomem), reason);
	exit(ERR_OTHER);
}

/*
 * routine:
 *	findfiles
 *
 * purpose:
 *	to locate our baseline and rules files
 *
 * parameters:
 *	none
 *
 * returns:
 *	error mask
 *	settings of file_base and file_rules
 *
 * side-effects:
 *	in order to keep multiple filesyncs from running in parallel
 *	we put an advisory lock on the baseline file.  If the baseline
 *	file does not exist we create one.  The unlocking (and deletion
 *	of extraneous baselines) is handled in cleanup.
 */
static errmask_t
findfiles(void)		/* find rule and baseline files	*/
{ 	char *s, *where;
	char namebuf[MAX_PATH];
	int ret;
	errmask_t errs = 0;

	/* figure out where the files should be located	*/
	s = getenv("FILESYNC");
	where = (s && *s) ? expand(s) : expand(DFLT_PRFX);

	/* see if we got a viable name		*/
	if (where == 0) {
		fprintf(stderr, gettext(ERR_nofsync));
		return (ERR_FILES);
	}

	/* try to form the name of the rules file */
	strcpy(namebuf, where);
	strcat(namebuf, SUFX_RULES);
	s = strdup(namebuf);
	errs = check_access(namebuf, &new_rules);

	/* if we cannot find a proper rules file, look in the old place */
	if (new_rules && errs == 0) {
		strcpy(namebuf, where);
		strcat(namebuf, SUFX_OLD);
		file_rules = strdup(namebuf);
		errs = check_access(namebuf, &new_rules);

		/* if we couldn't find that either, go with new name	*/
		if (new_rules && errs == 0)
			file_rules = s;
	} else
		file_rules = s;

	/* try to form the name of the baseline file */
	strcpy(namebuf, where);
	strcat(namebuf, SUFX_BASE);
	file_base = strdup(namebuf);
	errs |= check_access(namebuf, &new_baseline);

	if (opt_debug & DBG_FILES) {
		fprintf(stderr, "FILE: %s rules file: %s\n",
			new_rules ? "new" : "existing", file_rules);

		fprintf(stderr, "FILE: %s base file:  %s\n",
			new_baseline ? "new" : "existing", file_base);
	}

	/*
	 * in order to lock out other filesync programs we need some
	 * file we can lock.  We do an advisory lock on the baseline
	 * file.  If no baseline file exists, we create an empty one.
	 */
	if (new_baseline)
		lockfd = creat(file_base, 0666);
	else
		lockfd = open(file_base, O_RDWR);

	if (lockfd < 0) {
		fprintf(stderr, new_baseline ? ERR_creat : ERR_open,
			TXT_base, file_base);
		errs |= ERR_FILES;
	} else {
		ret = lockf(lockfd, F_TLOCK, 0L);
		if (ret < 0) {
			fprintf(stderr, ERR_lock, TXT_base, file_base);
			errs |= ERR_FILES;
		} else if (opt_debug & DBG_FILES)
			fprintf(stderr, "FILE: locking baseline file %s\n",
				file_base);
	}

	return (errs);
}

/*
 * routine:
 *	cleanup
 *
 * purpose:
 *	to clean up temporary files and locking prior to exit
 *
 * paremeters:
 *	error mask
 *
 * returns:
 *	void
 *
 * notes:
 *	if there are no errors, the baseline file is assumed to be good.
 *	Otherwise, if we created a temporary baseline file (just for
 *	locking) we will delete it.
 */
static void
cleanup(errmask_t errmask)
{
	/* unlock the baseline file	*/
	if (opt_debug & DBG_FILES)
		fprintf(stderr, "FILE: unlock baseline file %s\n", file_base);
	(void) lockf(lockfd, F_ULOCK, 0);

	/* see if we need to delete a temporary copy	*/
	if (errmask && new_baseline) {
		if (opt_debug & DBG_FILES)
			fprintf(stderr, "FILE: unlink temp baseline file %s\n",
				file_base);
		(void) unlink(file_base);
	}
}

/*
 * routine:
 *	check_access
 *
 * purpose:
 *	to determine whether or not we can access an existing file
 *	or create a new one
 *
 * parameters:
 *	name of file (in a clobberable buffer)
 *	pointer to new file flag
 *
 * returns:
 *	error mask
 *	setting of the new file flag
 *
 * note:
 *	it is kind of a kluge that this routine clobbers the name,
 *	but it is only called from one place, it needs a modified
 *	copy of the name, and the one caller doesn't mind.
 */
static errmask_t
check_access(char *name, int *newflag)
{	char *s;

	/* start out by asking for what we want		*/
	if (access(name, R_OK|W_OK) == 0) {
		*newflag = 0;
		return (0);
	}

	/* if the problem is isn't non-existence, lose	*/
	if (errno != ENOENT) {
		*newflag = 0;
		fprintf(stderr, gettext(ERR_rdwri), name);
		return (ERR_FILES);
	}

	/*
	 * the file doesn't exist, so there is still hope if we can
	 * write in the directory that should contain the file
	 */
	*newflag = 1;

	/* truncate the file name to its containing directory */
	for (s = name; s[1]; s++);
	while (s > name && *s != '/')
		s--;
	if (s > name)
		*s = 0;
	else if (*s == '/')
		s[1] = 0;
	else
		name = ".";

	/* then see if we have write access to the directory	*/
	if (access(name, W_OK) == 0)
		return (0);

	fprintf(stderr, gettext(ERR_dirwac), name);
	return (ERR_FILES);
}

/*
 * routine:
 *	whoami
 *
 * purpose:
 *	to figure out who I am and what the default modes/ownership
 *	is on files that I create.
 */
static void
whoami()
{
	my_uid = geteuid();
	my_gid = getegid();
	my_umask = umask(0);

	if (opt_debug & DBG_MISC)
		fprintf(stderr, "MISC: my_uid=%u, my_gid=%u, my_umask=%03o\n",
			my_uid, my_gid, my_umask);
}
