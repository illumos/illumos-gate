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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * autopush(8) is the command interface to the STREAMS autopush
 * mechanism.  The autopush command can be used to configure autopush
 * information about a STREAMS driver, remove autopush information,
 * and report on current configuration information.  Its use is as
 * follows:
 *
 *	autopush -f file
 *	autopush -r -M major -m minor
 *	autopush -g -M major -m minor
 *
 * The -f option allows autopush information to be set from a file.  The
 * format of the file is as follows:
 *
 * # Comment lines begin with a # in column one.
 * # The fields are separated by white space and are:
 * # major	minor	lastminor	module1 module2 ... module8
 *
 * "lastminor" is used to configure ranges of minor devices, from "minor"
 * to "lastminor" inclusive.  It should be set to zero when not in use.
 * The -r option allows autopush information to be removed for the given
 * major/minor pair.  The -g option allows the configuration information
 * to be printed.  The format of printing is the same as for the file.
 */

/*
 * Use autopush version 1; keep before #include <sys/sad.h>.
 * See <sys/sad.h> for details.
 */
#define	AP_VERSION	1

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/sad.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <locale.h>
#include <sys/stat.h>
#include <zone.h>

#define	OPTIONS	"M:f:gm:r"	/* command line options for getopt(3C) */
#define	COMMENT	'#'
#define	MINUS	'-'
#define	SLASH	'/'

/*
 * Output format.
 */
#define	OHEADER		"     Major      Minor  Lastminor\tModules\n"
#define	OFORMAT1_ONE	"%10ld %10ld      -    \t"
#define	OFORMAT1_RANGE	"%10ld %10ld %10ld\t"
#define	OFORMAT1_ALL	"%10ld       ALL       -    \t"

#define	AP_ANCHOR	"[anchor]"

#define	Openerr		gettext("%s: ERROR: Could not open %s: ")
#define	Digiterr	gettext("%s: ERROR: argument to %s option must be " \
			    "numeric\n")
#define	Badline		gettext("%s: WARNING: File %s: bad input line %d " \
			    "ignored\n")

static void	usage();
static int	rem_info(), get_info(), set_info();
static int	is_white_space(), parse_line();

static char	*Cmdp;		/* command name */

/*
 * main():
 *	process command line arguments.
 */
int
main(int argc, char *argv[])
{
	int		c;		/* character read by getopt(3C) */
	char		*filenamep;	/* name of configuration file */
	major_t		major;		/* major device number */
	minor_t		minor;		/* minor device number */
	char		*cp;
	int		exitcode;
	ushort_t	minflag = 0;	/* -m option used */
	ushort_t	majflag = 0;	/* -M option used */
	ushort_t	fflag = 0;	/* -f option used */
	ushort_t	rflag = 0;	/* -r option used */
	ushort_t	gflag = 0;	/* -g option used */
	ushort_t	errflag = 0;	/* options usage error */

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	/*
	 * Get command name.
	 */
	Cmdp = argv[0];
	for (filenamep = argv[0]; *filenamep; filenamep++)
		if (*filenamep == SLASH)
			Cmdp = filenamep + 1;

	/*
	 * Get options.
	 */
	while (!errflag && ((c = getopt(argc, argv, OPTIONS)) != -1)) {
		switch (c) {
		case 'M':
			if (fflag|majflag)
				errflag++;
			else {
				majflag++;
				for (cp = optarg; *cp; cp++)
					if (!isdigit(*cp)) {
						(void) fprintf(stderr,
						    Digiterr, Cmdp, "-M");
						exit(1);
					}
				major = (major_t)atol(optarg);
			}
			break;

		case 'm':
			if (fflag|minflag)
				errflag++;
			else {
				minflag++;
				for (cp = optarg; *cp; cp++)
					if (!isdigit(*cp)) {
						(void) fprintf(stderr,
						    Digiterr, Cmdp, "-m");
						exit(1);
					}
				minor = (minor_t)atol(optarg);
			}
			break;

		case 'f':
			if (fflag|gflag|rflag|majflag|minflag)
				errflag++;
			else {
				fflag++;
				filenamep = optarg;
			}
			break;

		case 'r':
			if (fflag|gflag|rflag)
				errflag++;
			else
				rflag++;
			break;

		case 'g':
			if (fflag|gflag|rflag)
				errflag++;
			else
				gflag++;
			break;

		default:
			errflag++;
			break;
		} /* switch */
		if (errflag) {
			usage();
			exit(1);
		}
	} /* while */
	if (((gflag || rflag) && (!majflag || !minflag)) || (optind != argc)) {
		usage();
		exit(1);
	}

	if (getzoneid() != GLOBAL_ZONEID) {
		(void) fprintf(stderr, gettext("autopush "
		    "can only be run from the global zone.\n"));
		exit(1);
	}

	if (fflag)
		exitcode = set_info(filenamep);
	else if (rflag)
		exitcode = rem_info(major, minor);
	else if (gflag)
		exitcode = get_info(major, minor);
	else {
		usage();
		exit(1);
	}

	return (exitcode);
}

/*
 * usage():
 *	print out usage statement.
 */
static void
usage()
{
	(void) fprintf(stderr,	gettext("%s: USAGE:\n\t%s -f filename\n"
	    "\t%s -r -M major -m minor\n"
	    "\t%s -g -M major -m minor\n"), Cmdp, Cmdp, Cmdp, Cmdp);
}

/*
 * set_info():
 *	set autopush configuration information.
 *	namep: autopush configuration filename
 */
static int
set_info(char *namep)
{
	int		line;		/* line number of file */
	FILE		*fp;		/* file pointer of config file */
	char		buf[256];	/* input buffer */
	struct strapush push;		/* configuration information */
	int		sadfd;		/* file descriptor to SAD driver */
	int		retcode = 0;	/* return code */
	int		parsecode;	/* return value from parse function */

	if ((sadfd = open(ADMINDEV, O_RDWR)) < 0) {
		(void) fprintf(stderr, Openerr, Cmdp, ADMINDEV);
		perror("");
		return (1);
	}
	if ((fp = fopen(namep, "r")) == NULL) {
		(void) fprintf(stderr, Openerr, Cmdp, namep);
		perror("");
		return (1);
	}
	line = 0;
	while (fgets(buf, sizeof (buf), fp) != NULL) {
		line++;
		if ((buf[0] == COMMENT) || is_white_space(buf))
			continue;
		(void) memset(&push, 0, sizeof (struct strapush));

		parsecode = parse_line(buf, line, namep, &push);
		if (parsecode != 0) {
			retcode = parsecode;
			continue;
		}

		if (push.sap_minor == (minor_t)-1)
			push.sap_cmd = SAP_ALL;
		else if (push.sap_lastminor == 0)
			push.sap_cmd = SAP_ONE;
		else
			push.sap_cmd = SAP_RANGE;

		if (ioctl(sadfd, SAD_SAP, &push) < 0) {
			int error = errno;

			retcode = 1;
			(void) fprintf(stderr,
			    gettext("%s: ERROR: File %s: could not configure "
			    "autopush for line %d\n"), Cmdp, namep, line);
			switch (error) {
			case EPERM:
				(void) fprintf(stderr, gettext("%s: ERROR: "
				    "You don't have permission to set autopush "
				    "information\n"), Cmdp);
				break;

			case EINVAL:
				(void) fprintf(stderr, gettext("%s: ERROR: "
				    "Invalid major device number or invalid "
				    "module name or too many modules\n"), Cmdp);
				break;

			case ENOSTR:
				(void) fprintf(stderr, gettext("%s: ERROR: "
				    "Major device is not a STREAMS "
				    "driver\n"), Cmdp);
				break;

			case EEXIST:
				(void) fprintf(stderr, gettext("%s: ERROR: "
				    "Major/minor already configured\n"), Cmdp);
				break;

			case ENOSR:
				(void) fprintf(stderr, gettext("%s: ERROR: Ran "
				    "out of autopush structures\n"), Cmdp);
				break;

			case ERANGE:
				(void) fprintf(stderr, gettext("%s: ERROR: "
				    "lastminor must be greater than minor\n"),
				    Cmdp);
				break;

			default:
				(void) fprintf(stderr, gettext("%s: ERROR: "),
				    Cmdp);
				(void) fprintf(stderr, "%s\n", strerror(error));
				break;
			} /* switch */
		} /* if */
	} /* while */
	return (retcode);
}

/*
 * rem_info():
 *	remove autopush configuration information.
 */
static int
rem_info(major_t maj, minor_t min)
{
	struct strapush push;		/* configuration information */
	int		sadfd;		/* file descriptor to SAD driver */
	int		retcode = 0;	/* return code */

	if ((sadfd = open(ADMINDEV, O_RDWR)) < 0) {
		(void) fprintf(stderr, Openerr, Cmdp, ADMINDEV);
		perror("");
		return (1);
	}
	push.sap_cmd = SAP_CLEAR;
	push.sap_minor = min;
	push.sap_major = maj;

	if (ioctl(sadfd, SAD_SAP, &push) < 0) {
		int error = errno;

		retcode = 1;
		(void) fprintf(stderr, gettext("%s: ERROR: Could not remove "
		    "autopush information\n"), Cmdp);
		switch (error) {
		case EPERM:
			(void) fprintf(stderr, gettext("%s: ERROR: You don't "
			    "have permission to remove autopush "
			    "information\n"), Cmdp);
			break;

		case EINVAL:
			if ((min != 0) && (ioctl(sadfd, SAD_GAP, &push) == 0) &&
			    (push.sap_cmd == SAP_ALL))
				(void) fprintf(stderr, gettext("%s: ERROR: "
				    "When removing an entry for ALL minors, "
				    "minor must be set to 0\n"), Cmdp);
			else
				(void) fprintf(stderr, gettext("%s: ERROR: "
				    "Invalid major device number\n"), Cmdp);
			break;

		case ENODEV:
			(void) fprintf(stderr, gettext("%s: ERROR: Major/minor "
			    "not configured for autopush\n"), Cmdp);
			break;

		case ERANGE:
			(void) fprintf(stderr, gettext("%s: ERROR: minor must "
			    "be set to begining of range when clearing\n"),
			    Cmdp);
			break;

		default:
			(void) fprintf(stderr, gettext("%s: ERROR: "), Cmdp);
			(void) fprintf(stderr, "%s\n", strerror(error));
			break;
		} /* switch */
	}
	return (retcode);
}

/*
 * get_info():
 *	get autopush configuration information.
 */
static int
get_info(major_t maj, minor_t min)
{
	struct strapush push;	/* configuration information */
	int		i;	/* counter */
	int		sadfd;	/* file descriptor to SAD driver */

	if ((sadfd = open(USERDEV, O_RDWR)) < 0) {
		(void) fprintf(stderr, Openerr, Cmdp, USERDEV);
		perror("");
		return (1);
	}
	push.sap_major = maj;
	push.sap_minor = min;

	if (ioctl(sadfd, SAD_GAP, &push) < 0) {
		int error = errno;

		(void) fprintf(stderr, gettext("%s: ERROR: Could not get "
		    "autopush information\n"), Cmdp);
		switch (error) {
		case EINVAL:
			(void) fprintf(stderr, gettext("%s: ERROR: Invalid "
			    "major device number\n"), Cmdp);
			break;

		case ENOSTR:
			(void) fprintf(stderr, gettext("%s: ERROR: Major "
			    "device is not a STREAMS driver\n"), Cmdp);
			break;

		case ENODEV:
			(void) fprintf(stderr, gettext("%s: ERROR: Major/minor "
			    "not configured for autopush\n"), Cmdp);
			break;

		default:
			(void) fprintf(stderr, gettext("%s: ERROR: "), Cmdp);
			(void) fprintf(stderr, "%s\n", strerror(error));
			break;
		} /* switch */
		return (1);
	}
	(void) printf(OHEADER);
	switch (push.sap_cmd) {
	case SAP_ONE:
		(void) printf(OFORMAT1_ONE, push.sap_major, push.sap_minor);
		break;

	case SAP_RANGE:
		(void) printf(OFORMAT1_RANGE, push.sap_major, push.sap_minor,
		    push.sap_lastminor);
		break;

	case SAP_ALL:
		(void) printf(OFORMAT1_ALL, push.sap_major);
		break;

	default:
		(void) fprintf(stderr,
		    gettext("%s: ERROR: Unknown configuration type\n"), Cmdp);
		return (1);
	}

	for (i = 0; i < push.sap_npush; i++) {

		(void) printf("%s", push.sap_list[i]);

		if (push.sap_anchor == (i + 1))
			(void) printf(" %s", AP_ANCHOR);

		if (i < push.sap_npush - 1)
			(void) printf(" ");

	}

	(void) printf("\n");
	return (0);
}

/*
 * is_white_space():
 *	Return 1 if buffer is all white space.
 *	Return 0 otherwise.
 */
static int
is_white_space(char *bufp)
{
	while (*bufp) {
		if (!isspace(*bufp))
			return (0);
		bufp++;
	}
	return (1);
}

/*
 * parse_line():
 *	Parse input line from file and report any errors found.  Fill
 *	strapush structure along the way.  Returns 1 if the line has
 *	errors and 0 if the line is well-formed.  Another hidden
 *	dependency on MAXAPUSH. `linep' is the input buffer, `lineno'
 *	is the current line number, and `namep' is the filename.
 */
static int
parse_line(char *linep, int lineno, char *namep, struct strapush *pushp)
{
	char		*wp;		/* word pointer */
	char		*cp;		/* character pointer */
	int		midx;		/* module index */
	int		npush;		/* number of modules to push */
	char		c;
	major_t		major_num;

	pushp->sap_anchor = 0;		/* by default, no anchor */

	/*
	 * Find the major device number.
	 */
	for (wp = linep; isspace(*wp); wp++)
		;
	for (cp = wp; !isspace(*cp); cp++)
		;
	if (!isspace(*cp)) {
		(void) fprintf(stderr, Badline, Cmdp, namep, lineno);
		return (1);
	}
	c = *cp;
	*cp = '\0';
	if (modctl(MODGETMAJBIND, wp, strlen(wp) + 1, &major_num) != 0) {
		(void) fprintf(stderr, Badline, Cmdp, namep, lineno);
		return (1);
	}
	*cp = c;
	pushp->sap_major = major_num;

	/*
	 * Find the minor device number.  Must handle negative values here.
	 */
	for (wp = cp; isspace(*wp); wp++)
		;
	for (cp = wp; (isdigit(*cp) || (*cp == MINUS)); cp++)
		;
	if (!isspace(*cp)) {
		(void) fprintf(stderr, Badline, Cmdp, namep, lineno);
		return (1);
	}
	pushp->sap_minor = (minor_t)atol(wp);

	/*
	 * Find the lastminor.
	 */
	for (wp = cp; isspace(*wp); wp++)
		;
	for (cp = wp; isdigit(*cp); cp++)
		;
	if (!isspace(*cp)) {
		(void) fprintf(stderr, Badline, Cmdp, namep, lineno);
		return (1);
	}
	pushp->sap_lastminor = (minor_t)atol(wp);

	/*
	 * Read the list of module names.
	 */
	npush = 0;
	while ((npush < MAXAPUSH) && (*cp)) {

		while (isspace(*cp))
			cp++;

		if (strncasecmp(cp, AP_ANCHOR, sizeof (AP_ANCHOR) - 1) == 0) {
			if (pushp->sap_anchor != 0) {
				(void) fprintf(stderr,
				    gettext("%s: ERROR: File %s: more than "
				    "one anchor in line, line %d ignored\n"),
				    Cmdp, namep, lineno);
				return (1);
			}
			if (npush == 0)
				(void) fprintf(stderr,
				    gettext("%s: WARNING: File %s: anchor at "
				    "beginning of stream on line %d ignored\n"),
				    Cmdp, namep, lineno);
			pushp->sap_anchor = npush;
			cp += sizeof (AP_ANCHOR) - 1;
			continue;
		}

		for (midx = 0; !isspace(*cp) && *cp; midx++) {
			if (midx == FMNAMESZ) {
				(void) fprintf(stderr, gettext("%s: ERROR: "
				    "File %s: module name too long, line %d "
				    "ignored\n"), Cmdp, namep, lineno);
				return (1);
			}
			pushp->sap_list[npush][midx] = *cp++;
		}

		if (midx > 0) {
			pushp->sap_list[npush][midx] = '\0';
			npush++;
		}
	}
	pushp->sap_npush = npush;

	/*
	 * We have everything we want from the line.
	 * Now make sure there is no extra garbage on the line.
	 */
	while (isspace(*cp))
		cp++;
	if (*cp) {
		(void) fprintf(stderr,
		    gettext("%s: ERROR: File %s: too many modules, line %d "
		    "ignored\n"), Cmdp, namep, lineno);
		return (1);
	}
	return (0);
}
