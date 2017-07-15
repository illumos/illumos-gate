/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*
 *	Modified to recursively extract all files within a subtree
 *	(supressed by the h option) and recreate the heirarchical
 *	structure of that subtree and move extracted files to their
 *	proper homes (supressed by the m option).
 *	Includes the s (skip files) option for use with multiple
 *	dumps on a single tape.
 *	8/29/80		by Mike Litzkow
 *
 *	Modified to work on the new file system and to recover from
 *	tape read errors.
 *	1/19/82		by Kirk McKusick
 *
 *	Full incremental restore running entirely in user code and
 *	interactive tape browser.
 *	1/19/83		by Kirk McKusick
 */

#include "restore.h"
#include <signal.h>
#include <byteorder.h>
#include <priv_utils.h>

#include <euc.h>
#include <getwidth.h>
#include <sys/mtio.h>
eucwidth_t wp;

int	bflag = 0, dflag = 0, vflag = 0, yflag = 0;
int	hflag = 1, mflag = 1, paginating = 0, offline = 0, autoload = 0;
int	autoload_tries;
int	autoload_period;
int	cvtflag = 0;		/* Converting from old dump format */
char	command = '\0';
long	dumpnum = 1;
int	volno = 0;
uint_t	ntrec;			/* blocking factor, in KB */
uint_t	saved_ntrec;		/* saved blocking factor, in KB */
ssize_t	tape_rec_size = 0;	/* tape record size (ntrec * tp_bsize) */
size_t	newtapebuf_size = 0;	/* save size of last call to newtapebuf */
char	*progname;
char	*dumpmap;
char	*clrimap;
char	*c_label;		/* if non-NULL, we must see this tape label */
ino_t	maxino;
time_t	dumptime;
time_t	dumpdate;
FILE 	*terminal;
char	*tmpdir;
char	*pager_catenated;
char	**pager_vector;
int	pager_len;
int	inattrspace = 0;
int	savepwd;
int32_t	tp_bsize = TP_BSIZE_MIN;
struct byteorder_ctx *byteorder;

static void set_tmpdir(void);

int
main(int argc, char *argv[])
{
	static struct arglist alist = { 0, 0, 0, 0, 0 };
	int  count;
	char *cp;
	char *fname;
	ino_t ino;
	char *inputdev;
	char *archivefile = 0;
	char *symtbl = RESTORESYMTABLE;
	char name[MAXPATHLEN];
	int  fflag = 0;
	struct sigaction sa, osa;
	int multiplier;
	char units;

	if ((progname = strrchr(argv[0], '/')) != NULL)
		progname++;
	else
		progname = argv[0];

	if (strcmp("hsmrestore", progname) == 0) {
		(void) fprintf(stderr,
		    gettext("hsmrestore emulation is no longer supported.\n"));
		done(1);
	}

	/*
	 * Convert the effective uid of 0 to the single privilege
	 * we really want.  When running with all privileges, this
	 * is a no-op.  When the set-uid bit is stripped restore
	 * still works for local tapes.  Fail when trying to access
	 * a remote tape in that case and not immediately.
	 */
	(void) __init_suid_priv(0, PRIV_NET_PRIVADDR, (char *)NULL);

	inputdev = DEFTAPE;

	/*
	 * This doesn't work because ufsrestore is statically linked:
	 * (void) setlocale(LC_ALL, "");
	 * The problem seems to be with LC_COLLATE, so set all the
	 * others explicitly.  Bug 1157128 was created against the I18N
	 * library.  When that bug is fixed this should go back to the way
	 * it was.
	 * XXX 1157128 was closed as a dup of 1099747.  That bug was fixed by
	 * disallowing setlocale() to anything other than "C".  "" is
	 * allowed, but only if none of the envars LC_ALL, LC_COLLATE, or LANG
	 * select anything other than "C".
	 */
	(void) setlocale(LC_CTYPE, "");
	(void) setlocale(LC_NUMERIC, "");
	(void) setlocale(LC_TIME, "");
	(void) setlocale(LC_MONETARY, "");
	(void) setlocale(LC_MESSAGES, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);
	getwidth(&wp);
	if ((byteorder = byteorder_create()) == NULL) {
		(void) fprintf(stderr,
		    gettext("Cannot create byteorder context\n"));
		done(1);
	}

	if ((savepwd = open(".", O_RDONLY)) < 0) {
		(void) fprintf(stderr,
		    gettext("Cannot save current directory context\n"));
		done(1);
	}

	set_tmpdir();

	autoload_period = 12;
	autoload_tries = 12;	/* traditional default of ~2.5 minutes */

	sa.sa_handler = onintr;
	sa.sa_flags = SA_RESTART;
	(void) sigemptyset(&sa.sa_mask);

	(void) sigaction(SIGINT, &sa, &osa);
	if (osa.sa_handler == SIG_IGN)
		(void) sigaction(SIGINT, &osa, (struct sigaction *)0);

	(void) sigaction(SIGTERM, &sa, &osa);
	if (osa.sa_handler == SIG_IGN)
		(void) sigaction(SIGTERM, &osa, (struct sigaction *)0);
	if (argc < 2) {
usage:
		(void) fprintf(stderr, gettext("Usage:\n\
\t%s tabcdfhsvyLloT [file file ...]\n\
\t%s xabcdfhmsvyLloT [file file ...]\n\
\t%s iabcdfhmsvyLloT\n\
\t%s rabcdfsvyLloT\n\
\t%s RabcdfsvyLloT\n\n\
a requires an archive file name\n\
b requires a blocking factor\n\
f requires a dump file\n\
s requires a file number\n\
L requires a tape label\n\
If set, the envar TMPDIR selects where temporary files are kept\n"),
		    progname, progname, progname, progname, progname);
		done(1);
	}

	argv++;			/* the bag-of-options */
	argc -= 2;		/* count of parameters to the options  */
	command = '\0';
	c_label = (char *)NULL;	/* any tape's acceptable */
	for (cp = *argv++; *cp; cp++) {
		switch (*cp) {		/* BE CAUTIOUS OF FALLTHROUGHS */
		case 'T':
			if (argc < 1) {
				(void) fprintf(stderr, gettext(
				    "Missing autoload timeout period\n"));
				done(1);
			}

			count = atoi(*argv);
			if (count < 1) {
				(void) fprintf(stderr, gettext(
			    "Unreasonable autoload timeout period `%s'\n"),
					*argv);
				done(1);
			}
			units = *(*argv + strlen(*argv) - 1);
			switch (units) {
			case 's':
				multiplier = 1;
				break;
			case 'h':
				multiplier = 3600;
				break;
			case '0': case '1': case '2': case '3': case '4':
			case '5': case '6': case '7': case '8': case '9':
			case 'm':
				multiplier = 60;
				break;
			default:
				(void) fprintf(stderr, gettext(
				    "Unknown timeout units indicator `%c'\n"),
				    units);
				done(1);
			}
			autoload_tries = 1 +
			    ((count * multiplier) / autoload_period);
			argv++;
			argc--;
			break;
		case 'l':
			autoload++;
			break;
		case 'o':
			offline++;
			break;
		case '-':
			break;
		case 'a':
			if (argc < 1) {
				(void) fprintf(stderr,
					gettext("missing archive file name\n"));
				done(1);
			}
			archivefile = *argv++;
			if (*archivefile == '\0') {
				(void) fprintf(stderr,
				    gettext("empty archive file name\n"));
				done(1);
			}
			argc--;
			break;
		case 'c':
			cvtflag++;
			break;
		case 'd':
			dflag++;
			break;
		case 'D':
			/*
			 * This used to be the Dflag, but it doesn't
			 * hurt to always check, so was removed.  This
			 * case is here for backward compatability.
			 */
			break;
		case 'h':
			hflag = 0;
			break;
		case 'm':
			mflag = 0;
			break;
		case 'v':
			vflag++;
			break;
		case 'y':
			yflag++;
			break;
		case 'f':
			if (argc < 1) {
				(void) fprintf(stderr,
				    gettext("missing device specifier\n"));
				done(1);
			}
			inputdev = *argv++;
			if (*inputdev == '\0') {
				(void) fprintf(stderr,
				    gettext("empty device specifier\n"));
				done(1);
			}
			fflag++;
			argc--;
			break;
		case 'b':
			/*
			 * change default tape blocksize
			 */
			bflag++;
			if (argc < 1) {
				(void) fprintf(stderr,
					gettext("missing block size\n"));
				done(1);
			}
			saved_ntrec = ntrec = atoi(*argv++);
			if (ntrec == 0 || (ntrec&1)) {
				(void) fprintf(stderr, gettext(
			    "Block size must be a positive, even integer\n"));
				done(1);
			}
			ntrec /= (tp_bsize/DEV_BSIZE);
			argc--;
			break;
		case 's':
			/*
			 * dumpnum (skip to) for multifile dump tapes
			 */
			if (argc < 1) {
				(void) fprintf(stderr,
					gettext("missing dump number\n"));
				done(1);
			}
			dumpnum = atoi(*argv++);
			if (dumpnum <= 0) {
				(void) fprintf(stderr, gettext(
			    "Dump number must be a positive integer\n"));
				done(1);
			}
			argc--;
			break;
		case 't':
		case 'R':
		case 'r':
		case 'x':
		case 'i':
			if (command != '\0') {
				(void) fprintf(stderr, gettext(
				    "%c and %c are mutually exclusive\n"),
				    (uchar_t)*cp, (uchar_t)command);
				goto usage;
			}
			command = *cp;
			break;
		case 'L':
			if (argc < 1 || **argv == '\0') {
				(void) fprintf(stderr,
				    gettext("Missing tape label name\n"));
				done(1);
			}
			c_label = *argv++; /* must get tape with this label */
			if (strlen(c_label) > (sizeof (spcl.c_label) - 1)) {
				c_label[sizeof (spcl.c_label) - 1] = '\0';
				(void) fprintf(stderr, gettext(
		    "Truncating label to maximum supported length: `%s'\n"),
				    c_label);
			}
			argc--;
			break;

		default:
			(void) fprintf(stderr,
			    gettext("Bad key character %c\n"), (uchar_t)*cp);
			goto usage;
		}
	}
	if (command == '\0') {
		(void) fprintf(stderr,
		    gettext("must specify i, t, r, R, or x\n"));
		goto usage;
	}
	setinput(inputdev, archivefile);
	if (argc == 0) {	/* re-use last argv slot for default */
		argc = 1;
		*--argv = mflag ? "." : "2";
	}
	switch (command) {

	/*
	 * Interactive mode.
	 */
	case 'i':
		setup();
		extractdirs(1);
		initsymtable((char *)0);
		initpagercmd();
		runcmdshell();
		done(0);
		/* NOTREACHED */
	/*
	 * Incremental restoration of a file system.
	 */
	case 'r':
		setup();
		if (dumptime > 0) {
			/*
			 * This is an incremental dump tape.
			 */
			vprintf(stdout, gettext("Begin incremental restore\n"));
			initsymtable(symtbl);
			extractdirs(1);
			removeoldleaves();
			vprintf(stdout, gettext("Calculate node updates.\n"));
			strcpy(name, ".");
			name[2] = '\0';
			treescan(name, ROOTINO, nodeupdates);
			attrscan(1, nodeupdates);
			findunreflinks();
			removeoldnodes();
		} else {
			/*
			 * This is a level zero dump tape.
			 */
			vprintf(stdout, gettext("Begin level 0 restore\n"));
			initsymtable((char *)0);
			extractdirs(1);
			vprintf(stdout,
			    gettext("Calculate extraction list.\n"));
			strcpy(name, ".");
			name[2] = '\0';
			treescan(name, ROOTINO, nodeupdates);
			attrscan(1, nodeupdates);
		}
		createleaves(symtbl);
		createlinks();
		setdirmodes();
		checkrestore();
		if (dflag) {
			vprintf(stdout,
			    gettext("Verify the directory structure\n"));
			strcpy(name, ".");
			name[2] = '\0';
			treescan(name, ROOTINO, verifyfile);
		}
		dumpsymtable(symtbl, (long)1);
		done(0);
		/* NOTREACHED */
	/*
	 * Resume an incremental file system restoration.
	 */
	case 'R':
		setupR();
		initsymtable(symtbl);
		skipmaps();
		skipdirs();
		createleaves(symtbl);
		createlinks();
		setdirmodes();
		checkrestore();
		dumpsymtable(symtbl, (long)1);
		done(0);
		/* NOTREACHED */
	/*
	 * List contents of tape.
	 */
	case 't':
		setup();
		extractdirs(0);
		initsymtable((char *)0);
		if (vflag)
			printdumpinfo();
		while (argc--) {
			canon(*argv++, name, sizeof (name));
			name[strlen(name)+1] = '\0';
			ino = dirlookup(name);
			if (ino == 0)
				continue;
			treescan(name, ino, listfile);
		}
		done(0);
		/* NOTREACHED */
	/*
	 * Batch extraction of tape contents.
	 */
	case 'x':
		setup();
		extractdirs(1);
		initsymtable((char *)0);
		while (argc--) {
			if (mflag) {
				canon(*argv++, name, sizeof (name));
				if (expand(name, 0, &alist) == 0) {
					/* no meta-characters to expand */
					ino = dirlookup(name);
					if (ino == 0)
						continue;
					pathcheck(name);
				} else {
					/* add each of the expansions */
					while ((alist.last - alist.head) > 0) {
						fname = alist.head->fname;
						ino = dirlookup(fname);
						if (ino != 0) {
							pathcheck(fname);
							treescan(fname, ino,
							    addfile);
						}
						freename(fname);
						alist.head++;
					}
					alist.head = (struct afile *)NULL;
					continue; /* argc loop */
				}
			} else {
				ino = (ino_t)atol(*argv);
				if ((*(*argv++) == '-') || ino < ROOTINO) {
					(void) fprintf(stderr, gettext(
					    "bad inode number: %ld\n"),
					    ino);
					done(1);
				}
				name[0] = '\0';
			}
			treescan(name, ino, addfile);
			attrscan(0, addfile);
		}
		createfiles();
		createlinks();
		setdirmodes();
		if (dflag)
			checkrestore();
		done(0);
		/* NOTREACHED */
	}
	return (0);
}

/*
 * Determine where the user wants us to put our temporary files,
 * and make sure we can actually do so.  Bail out if there's a problem.
 */
void
set_tmpdir(void)
{
	int fd;
	char name[MAXPATHLEN];

	tmpdir = getenv("TMPDIR");
	if ((tmpdir == (char *)NULL) || (*tmpdir == '\0'))
		tmpdir = "/tmp";

	if (*tmpdir != '/') {
		(void) fprintf(stderr,
		    gettext("TMPDIR is not an absolute path (`%s').\n"),
		    tmpdir);
		done(1);
	}

	/*
	 * The actual use of tmpdir is in dirs.c, and is of the form
	 * tmpdir + "/rst" + type (three characters) + "%ld.XXXXXX" +
	 * a trailing NUL, where %ld is an arbitrary time_t.
	 *
	 * Thus, the magic 31 is strlen(itoa(MAX_TIME_T)) + "/rst" +
	 * ".XXXXXX" + '\0'.  A time_t is 64 bits, so MAX_TIME_T is
	 * LONG_MAX - nineteen digits.  In theory, so many things in
	 * ufsrestore will break once time_t's value goes beyond 32
	 * bits that it's not worth worrying about this particular
	 * instance at this time, but we've got to start somewhere.
	 *
	 * Note that the use of a pid below is just for testing the
	 * validity of the named directory.
	 */
	if (strlen(tmpdir) > (MAXPATHLEN - 31)) {
		(void) fprintf(stderr, gettext("TMPDIR too long\n"));
		done(1);
	}

	/* Guaranteed to fit by above test (sizeof(time_t) >= sizeof(pid_t)) */
	(void) snprintf(name, sizeof (name), "%s/rstdir.%ld", tmpdir, getpid());

	/*
	 * This is effectively a stripped-down version of safe_open(),
	 * because if the file exists, we want to fail.
	 */
	fd = open(name, O_CREAT|O_EXCL|O_RDWR, 0600);
	if (fd < 0) {
		perror(gettext("Can not create temporary file"));
		done(1);
	}

	(void) close(fd);
	if (unlink(name) < 0) {
		perror(gettext("Can not delete temporary file"));
		done(1);
	}
}
