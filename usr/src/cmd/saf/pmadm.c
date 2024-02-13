/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "extern.h"
#include "misc.h"
#include <sac.h>
#include "structs.h"

#define	ADD		0x1	/* -a or other required options seen */
#define	REMOVE		0x2	/* -r seen */
#define	ENABLE		0x4	/* -e seen */
#define	DISABLE		0x8	/* -d seen */
#define	PLIST		0x10	/* -l seen */
#define	LIST		0x20	/* -L seen */
#define	CONFIG		0x40	/* -g seen */

# define U_FLAG		0x1	/* -fu seen */
# define X_FLAG		0x2	/* -fx seen */

/*
 * functions
 */

char	*pflags();
char	*pspec();
struct	taglist	*find_type();
void	usage();
void	parseline();
void	add_svc();
void	rem_svc();
void	ed_svc();
void	list_svcs();
void	doconf();

/*
 * format of a _pmtab entry - used to hold parsed info
 */

struct	pmtab {
	char	*p_tag;		/* service tag */
	long	p_flags;	/* flags */
	char	*p_id;		/* logname to start service as */
	char	*p_res1;	/* reserved field */
	char	*p_res2;	/* reserved field */
	char	*p_res3;	/* reserved field */
	char	*p_pmspec;	/* port monitor specific info */
};

/*
 * format of a tag list, which is a list of port monitor tags of
 * a designated type
 */

struct	taglist {
	struct	taglist	*t_next;	/* next in list */
	char	t_tag[PMTAGSIZE + 1];	/* PM tag */
	char	t_type[PMTYPESIZE + 1];	/* PM type */
};

/*
 * common error messages
 */

# define NOTPRIV	"User not privileged for operation"
# define BADINP		"Embedded newlines not allowed"

int	Saferrno;	/* internal `errno' for exit */


/*
 * main - scan args for pmadm and call appropriate handling code
 */

int
main(int argc, char *argv[])
{
	int c;			/* option letter */
	int ret;		/* return code from check_version */
	uid_t uid;		/* invoker's real uid */
	int flag = 0;		/* flag to record requested operations */
	int errflg = 0;		/* error indicator */
	int badcnt = 0;		/* count of bad args to -f */
	int version = -1;	/* argument to -v */
	int sawaflag = 0;	/* true if actually saw -a */
	int conflag = 0;	/* true if output should be in condensed form */
	long flags = 0;		/* arguments to -f */
	char *pmtag = NULL;	/* argument to -p */
	char *type = NULL;	/* argument to -t */
	char *script = NULL;	/* argument to -z */
	char *comment = " ";	/* argument to -y */
	char *id = NULL;	/* argument to -i */
	char *svctag = NULL;	/* argument to -s */
	char *pmspec = NULL;	/* argument to -m */
	char badargs[SIZE];	/* place to hold bad args to -f */
	char buf[SIZE];		/* scratch buffer */
	register char *p;	/* scratch pointer */

	if (argc == 1)
		usage(argv[0]);
	while ((c = getopt(argc, argv, "adef:gi:Llm:p:rs:t:v:y:z:")) != -1) {
		switch (c) {
		case 'a':
			flag |= ADD;
			sawaflag = 1;
			break;
		case 'd':
			flag |= DISABLE;
			break;
		case 'e':
			flag |= ENABLE;
			break;
		case 'f':
			flag |= ADD;
			while (*optarg) {
				switch (*optarg++) {
				case 'u':
					flags |= U_FLAG;
					break;
				case 'x':
					flags |= X_FLAG;
					break;
				default:
					badargs[badcnt++] = *(optarg - 1);
					break;
				}
			}
			/* null terminate just in case anything is there */
			badargs[badcnt] = '\0';
			break;
		case 'g':
			flag |= CONFIG;
			break;
		case 'i':
			if (strchr(optarg, '\n')) {
				Saferrno = E_BADARGS;
				error(BADINP);
			}
			flag |= ADD;
			id = optarg;
			break;
		case 'L':
			flag |= LIST;
			break;
		case 'l':
			flag |= PLIST;
			break;
		case 'm':
			if (strchr(optarg, '\n')) {
				Saferrno = E_BADARGS;
				error(BADINP);
			}
			if (*optarg == '\0') {
				/* this will generate a usage message below */
				errflg++;
				break;
			}
			flag |= ADD;
			pmspec = optarg;
			break;
		case 'p':
			if (strchr(optarg, '\n')) {
				Saferrno = E_BADARGS;
				error(BADINP);
			}
			pmtag = optarg;
			if (strlen(pmtag) > PMTAGSIZE) {
				pmtag[PMTAGSIZE] = '\0';
				(void) fprintf(stderr, "tag too long, truncated to <%s>\n", pmtag);
			}
			for (p = pmtag; *p; p++) {
				if (!isalnum(*p)) {
					Saferrno = E_BADARGS;
					error("port monitor tag must be alphanumeric");
				}
			}
			break;
		case 'r':
			flag |= REMOVE;
			break;
		case 's':
			if (strchr(optarg, '\n')) {
				Saferrno = E_BADARGS;
				error(BADINP);
			}
			svctag = optarg;
			if (strlen(svctag) > SVCTAGSIZE) {
				svctag[SVCTAGSIZE] = '\0';
				(void) fprintf(stderr, "svctag too long, truncated to <%s>\n", svctag);
			}
			for (p = svctag; *p; p++) {
				if (!isalnum(*p)) {
					Saferrno = E_BADARGS;
					error("service tag must be alphanumeric");
				}
			}
			break;
		case 't':
			if (strchr(optarg, '\n')) {
				Saferrno = E_BADARGS;
				error(BADINP);
			}
			type = optarg;
			if (strlen(type) > PMTYPESIZE) {
				type[PMTYPESIZE] = '\0';
				(void) fprintf(stderr, "type too long, truncated to <%s>\n", type);
			}
			for (p = type; *p; p++) {
				if (!isalnum(*p)) {
					Saferrno = E_BADARGS;
					error("port monitor type must be alphanumeric");
				}
			}
			break;
		case 'v':
			flag |= ADD;
			version = atoi(optarg);
			if (version < 0) {
				Saferrno = E_BADARGS;
				error("version number can not be negative");
			}
			break;
		case 'y':
			if (strchr(optarg, '\n')) {
				Saferrno = E_BADARGS;
				error(BADINP);
			}
			flag |= ADD;
			comment = optarg;
			break;
		case 'z':
			if (strchr(optarg, '\n')) {
				Saferrno = E_BADARGS;
				error(BADINP);
			}
			script = optarg;
			break;
		case '?':
			errflg++;
		}
	}
	if (errflg || (optind < argc))
		usage(argv[0]);

	if (badcnt) {
		/* bad flags were given to -f */
		(void) sprintf(buf, "Invalid request, %s are not valid arguments for \"-f\"", badargs);
		Saferrno = E_BADARGS;
		error(buf);
	}

	uid = getuid();

/*
 * don't do anything if _sactab isn't the version we understand
 */

	if ((ret = check_version(VERSION, SACTAB)) == 1) {
		Saferrno = E_SAFERR;
		error("_sactab version number is incorrect");
	}
	else if (ret == 2) {
		(void) sprintf(buf, "could not open %s", SACTAB);
		Saferrno = E_SYSERR;
		error(buf);
	}
	else if (ret == 3) {
		(void) sprintf(buf, "%s file is corrupt", SACTAB);
		Saferrno = E_SAFERR;
		error(buf);
	}

	switch (flag) {
	case ADD:
		if (uid) {
			Saferrno = E_NOPRIV;
			error(NOTPRIV);
		}
		if (!sawaflag || (pmtag && type) || (!pmtag && !type) || !svctag || !id || !pmspec || (version < 0))
			usage(argv[0]);
		add_svc(pmtag, type, svctag, id, pmspec, flags, version, comment, script);
		break;
	case REMOVE:
		if (uid) {
			Saferrno = E_NOPRIV;
			error(NOTPRIV);
		}
		if (!pmtag || !svctag || type || script)
			usage(argv[0]);
		rem_svc(pmtag, svctag);
		break;
	case ENABLE:
		if (uid) {
			Saferrno = E_NOPRIV;
			error(NOTPRIV);
		}
		if (!pmtag || !svctag || type || script)
			usage(argv[0]);
		ed_svc(pmtag, svctag, ENABLE);
		break;
	case DISABLE:
		if (uid) {
			Saferrno = E_NOPRIV;
			error(NOTPRIV);
		}
		if (!pmtag || !svctag || type || script)
			usage(argv[0]);
		ed_svc(pmtag, svctag, DISABLE);
		break;
	case LIST:
		conflag = 1;
		/* fall through */
	case PLIST:
		if ((pmtag && type) || script)
			usage(argv[0]);
		list_svcs(pmtag, type, svctag, conflag);
		break;
	case CONFIG:
		if (script && uid) {
			Saferrno = E_NOPRIV;
			error(NOTPRIV);
		}
		if ((pmtag && type) || (!pmtag && !type) || !svctag || (type && !script))
			usage(argv[0]);
		doconf(script, pmtag, type, svctag);
		break;
	default:
		/* we only get here if more than one flag bit was set */
		usage(argv[0]);
		/* NOTREACHED */
	}
	quit();
	/* NOTREACHED */
}


/*
 * usage - print out a usage message
 *
 *	args:	cmdname - the name command was invoked with
 */

void
usage(cmdname)
char *cmdname;
{
	(void) fprintf(stderr, "Usage:\t%s -a [ -p pmtag | -t type ] -s svctag -i id -m \"pmspecific\"\n", cmdname);
	(void) fprintf(stderr, "\t\t-v version [ -f xu ] [ -y comment ] [ -z script]\n");
	(void) fprintf(stderr, "\t%s -r -p pmtag -s svctag\n", cmdname);
	(void) fprintf(stderr, "\t%s -e -p pmtag -s svctag\n", cmdname);
	(void) fprintf(stderr, "\t%s -d -p pmtag -s svctag\n", cmdname);
	(void) fprintf(stderr, "\t%s -l [ -p pmtag | -t type ] [ -s svctag ]\n", cmdname);
	(void) fprintf(stderr, "\t%s -L [ -p pmtag | -t type ] [ -s svctag ]\n", cmdname);
	(void) fprintf(stderr, "\t%s -g -p pmtag -s svctag [ -z script ]\n", cmdname);
	(void) fprintf(stderr, "\t%s -g -s svctag -t type -z script\n", cmdname);
	Saferrno = E_BADARGS;
	quit();
}


/*
 * add_svc - add a service entry
 *
 *	args:	tag - port monitor's tag (may be null)
 *		type - port monitor's type (may be null)
 *		svctag - service's tag
 *		id - identity under which service should run
 *		pmspec - uninterpreted port monitor-specific info
 *		flags - service flags
 *		version - version number of port monitor's pmtab
 *		comment - comment describing service
 *		script - service's configuration script
 */

void
add_svc(tag, type, svctag, id, pmspec, flags, version, comment, script)
char *tag;
char *type;
char *svctag;
char *id;
char *pmspec;
long flags;
int version;
char *comment;
char *script;
{
	FILE *fp;			/* scratch file pointer */
	struct taglist tl;		/* 'list' for degenerate case (1 PM) */
	register struct taglist *tp = NULL;	/* working pointer */
	int ret;			/* return code from check_version */
	char buf[SIZE];			/* scratch buffer */
	char fname[SIZE];		/* scratch buffer for building names */
	int added;			/* count number added */

	fp = fopen(SACTAB, "r");
	if (fp == NULL) {
		Saferrno = E_SYSERR;
		error("Could not open _sactab");
	}
	if (tag && !find_pm(fp, tag)) {
		(void) sprintf(buf, "Invalid request, %s does not exist", tag);
		Saferrno = E_NOEXIST;
		error(buf);
	}
	if (type && !(tp = find_type(fp, type))) {
		(void) sprintf(buf, "Invalid request, %s does not exist", type);
		Saferrno = E_NOEXIST;
		error(buf);
	}
	(void) fclose(fp);

	if (tag) {

/*
 * treat the case of 1 PM as a degenerate case of a list of PMs from a
 * type specification.  Build the 'list' here.
 */

		tp = &tl;
		tp->t_next = NULL;
		(void) strcpy(tp->t_tag, tag);
	}

	added = 0;
	while (tp) {
		(void) sprintf(fname, "%s/%s/_pmtab", HOME, tp->t_tag);
		if ((ret = check_version(version, fname)) == 1) {
			(void) sprintf(buf, "%s version number is incorrect", fname);
			Saferrno = E_SAFERR;
			error(buf);
		}
		else if (ret == 2) {
			(void) sprintf(buf, "could not open %s", fname);
			Saferrno = E_SYSERR;
			error(buf);
		}
		else if (ret == 3) {
			(void) sprintf(buf, "%s file is corrupt", fname);
			Saferrno = E_SAFERR;
			error(buf);
		}
		fp = fopen(fname, "r");
		if (fp == NULL) {
			(void) sprintf(buf, "Could not open %s", fname);
			Saferrno = E_SYSERR;
			error(buf);
		}
		if (find_svc(fp, tp->t_tag, svctag)) {
			if (tag) {
				/* special case of tag only */
				(void) sprintf(buf, "Invalid request, %s already exists under %s", svctag, tag);
				Saferrno = E_DUP;
				error(buf);
			}
			else {
				(void) fprintf(stderr, "warning - %s already exists under %s - ignoring\n", svctag, tp->t_tag);
				tp = tp->t_next;
				(void) fclose(fp);
				continue;
			}
		}
		(void) fclose(fp);

/*
 * put in the config script, if specified
*/

		if (script) {
			(void) sprintf(fname, "%s/%s", tp->t_tag, svctag);
			if (do_config(script, fname)) {
				/* do_config put out any messages */
				tp = tp->t_next;
				continue;
			}
		}

/*
 * add the line
 */

		(void) sprintf(fname, "%s/%s/_pmtab", HOME, tp->t_tag);
		fp = fopen(fname, "a");
		if (fp == NULL) {
			(void) sprintf(buf, "Could not open %s", fname);
			Saferrno = E_SYSERR;
			error(buf);
		}
		(void) fprintf(fp, "%s:%s:%s:reserved:reserved:reserved:%s#%s\n",
			svctag, (flags ? pflags(flags, FALSE) : ""), id, pmspec,
			(comment ? comment : ""));
		(void) fclose(fp);
		added++;

/*
 * tell the SAC to to tell PM to read _pmtab
 */

		(void) tell_sac(tp->t_tag);
		tp = tp->t_next;
	}
	if (added == 0) {
		Saferrno = E_SAFERR;
		error("No services added");
	}
	return;
}


/*
 * rem_svc - remove a service
 *
 *	args:	pmtag - tag of port monitor responsible for the service
 *		svctag - tag of the service to be removed
 */

void
rem_svc(pmtag, svctag)
char *pmtag;
char *svctag;
{
	FILE *fp;		/* scratch file pointer */
	FILE *tfp;		/* file pointer for temp file */
	int line;		/* line number entry is on */
	char *tname;		/* temp file name */
	char buf[SIZE];		/* scratch buffer */
	char fname[SIZE];	/* path to correct _pmtab */

	fp = fopen(SACTAB, "r");
	if (fp == NULL) {
		Saferrno = E_SYSERR;
		error("Could not open _sactab");
	}
	if (!find_pm(fp, pmtag)) {
		(void) sprintf(buf, "Invalid request, %s does not exist", pmtag);
		Saferrno = E_NOEXIST;
		error(buf);
	}
	(void) fclose(fp);

	(void) sprintf(fname, "%s/_pmtab", pmtag);
	(void) sprintf(buf, "%s/%s", HOME, fname);
	fp = fopen(buf, "r");
	if (fp == NULL) {
		(void) sprintf(buf, "Could not open %s/%s", HOME, fname);
		Saferrno = E_SYSERR;
		error(buf);
	}
	if ((line = find_svc(fp, pmtag, svctag)) == 0) {
		(void) sprintf(buf, "Invalid request, %s does not exist under %s", svctag, pmtag);
		Saferrno = E_NOEXIST;
		error(buf);
	}
	tname = make_tempname(fname);
	tfp = open_temp(tname);
	if (line != 1) {
		if (copy_file(fp, tfp, 1, line - 1)) {
			(void) unlink(tname);
			Saferrno = E_SYSERR;
			error("error accessing temp file");
		}
	}
	if (copy_file(fp, tfp, line + 1, -1)) {
		(void) unlink(tname);
		Saferrno = E_SYSERR;
		error("error accessing temp file");
	}
	(void) fclose(fp);
	if (fclose(tfp) == EOF) {
		(void) unlink(tname);
		Saferrno = E_SYSERR;
		error("error closing tempfile");
	}
	/* note - replace only returns if successful */
	replace(fname, tname);

/*
 * tell the SAC to to tell PM to read _pmtab
 */

	if (tell_sac(pmtag)) {

/*
 * if we got rid of the service, try to remove the config script too.
 * Don't check return status since it may not have existed anyhow.
 */

		(void) sprintf(buf, "%s/%s/%s", HOME, pmtag, svctag);
		(void) unlink(buf);
		return;
	}
}



/*
 * ed_svc - enable or disable a particular service
 *
 *	args:	pmtag - tag of port monitor responsible for the service
 *		svctag - tag of service to be enabled or disabled
 *		flag - operation to perform (ENABLE or DISABLE)
 */

void
ed_svc(pmtag, svctag, flag)
char *pmtag;
char *svctag;
int flag;
{
	FILE *fp;		/* scratch file pointer */
	FILE *tfp;		/* file pointer for temp file */
	int line;		/* line number entry is on */
	register char *from;	/* working pointer */
	register char *to;	/* working pointer */
	char *tname;		/* temp file name */
	char *p;		/* scratch pointer */
	char buf[SIZE];		/* scratch buffer */
	char tbuf[SIZE];	/* scratch buffer */
	char fname[SIZE];	/* path to correct _pmtab */

	fp = fopen(SACTAB, "r");
	if (fp == NULL) {
		Saferrno = E_SYSERR;
		error("Could not open _sactab");
	}
	if (!find_pm(fp, pmtag)) {
		(void) sprintf(buf, "Invalid request, %s does not exist", pmtag);
		Saferrno = E_NOEXIST;
		error(buf);
	}
	(void) fclose(fp);

	(void) sprintf(fname, "%s/_pmtab", pmtag);
	(void) sprintf(buf, "%s/%s", HOME, fname);
	fp = fopen(buf, "r");
	if (fp == NULL) {
		(void) sprintf(buf, "Could not open %s/%s", HOME, fname);
		Saferrno = E_SYSERR;
		error(buf);
	}
	if ((line = find_svc(fp, pmtag, svctag)) == 0) {
		(void) sprintf(buf, "Invalid request, %s does not exist under %s", svctag, pmtag);
		Saferrno = E_NOEXIST;
		error(buf);
	}
	tname = make_tempname(fname);
	tfp = open_temp(tname);
	if (line != 1) {
		if (copy_file(fp, tfp, 1, line - 1)) {
			(void) unlink(tname);
			Saferrno = E_SYSERR;
			error("error accessing temp file");
		}
	}

/*
 * Note: find_svc above has already read and parsed this entry, thus
 * we know it to be well-formed, so just change the flags as appropriate
 */

	if (fgets(buf, SIZE, fp) == NULL) {
		(void) unlink(tname);
		Saferrno = E_SYSERR;
		error("error accessing temp file");
	}
	from = buf;
	to = tbuf;

/*
 * copy initial portion of entry
 */

	p = strchr(from, DELIMC);
	for ( ; from <= p; )
		*to++ = *from++;

/*
 * isolate and fix the flags
 */

	p = strchr(from, DELIMC);
	for ( ; from < p; ) {
		if (*from == 'x') {
			from++;
			continue;
		}
		*to++ = *from++;
	}

/*
 * above we removed x flag, if this was a disable operation, stick it in
 * and also copy the field delimiter
 */

	if (flag == DISABLE)
		*to++ = 'x';
	*to++ = *from++;

/*
 * copy the rest of the line
 */

	for ( ; from < &buf[SIZE - 1] ;)
		*to++ = *from++;
/***	*to = '\0';  BUG: Don't uncomment it ****/

	(void) fprintf(tfp, "%s", tbuf);

	if (copy_file(fp, tfp, line + 1, -1)) {
		(void) unlink(tname);
		Saferrno = E_SYSERR;
		error("error accessing temp file");
	}
	(void) fclose(fp);
	if (fclose(tfp) == EOF) {
		(void) unlink(tname);
		Saferrno = E_SYSERR;
		error("error closing tempfile");
	}
	/* note - replace only returns if successful */
	replace(fname, tname);


/*
 * tell the SAC to to tell PM to read _pmtab
 */

	(void) tell_sac(pmtag);
}


/*
 * doconf - take a config script and have it put where it belongs or
 *	    output an existing one
 *
 *	args:	script - name of file containing script (if NULL, means
 *			 output existing one instead)
 *		tag - tag of port monitor that is responsible for the
 *		      designated service (may be null)
 *		type - type of port monitor that is responsible for the
 *		       designated service (may be null)
 *		svctag - tag of service whose config script we're operating on
 */

void
doconf(script, tag, type, svctag)
char *script;
char *tag;
char *type;
char *svctag;
{
	FILE *fp;			/* scratch file pointer */
	int added;			/* count of config scripts added */
	struct taglist tl;		/* 'list' for degenerate case (1 PM) */
	register struct taglist *tp = NULL;	/* working pointer */
	char buf[SIZE];			/* scratch buffer */
	char fname[SIZE];		/* scratch buffer for names */

	fp = fopen(SACTAB, "r");
	if (fp == NULL) {
		Saferrno = E_SYSERR;
		error("Could not open _sactab");
	}
	if (tag && !find_pm(fp, tag)) {
		(void) sprintf(buf, "Invalid request, %s does not exist", tag);
		Saferrno = E_NOEXIST;
		error(buf);
	}
	if (type && !(tp = find_type(fp, type))) {
		(void) sprintf(buf, "Invalid request, %s does not exist", type);
		Saferrno = E_NOEXIST;
		error(buf);
	}
	(void) fclose(fp);

	if (tag) {

/*
 * treat the case of 1 PM as a degenerate case of a list of PMs from a
 * type specification.  Build the 'list' here.
 */

		tp = &tl;
		tp->t_next = NULL;
		(void) strcpy(tp->t_tag, tag);
	}

	added = 0;
	while (tp) {
		(void) sprintf(fname, "%s/%s/_pmtab", HOME, tp->t_tag);
		fp = fopen(fname, "r");
		if (fp == NULL) {
			(void) sprintf(buf, "Could not open %s", fname);
			Saferrno = E_SYSERR;
			error(buf);
		}
		if (!find_svc(fp, tp->t_tag, svctag)) {
			if (tag) {
				/* special case of tag only */
				(void) sprintf(buf, "Invalid request, %s does not exist under %s", svctag, tag);
				Saferrno = E_NOEXIST;
				error(buf);
			}
			else {
				(void) fprintf(stderr, "warning - %s does not exist under %s - ignoring\n", svctag, tp->t_tag);
				Saferrno = E_NOEXIST;
				tp = tp->t_next;
				(void) fclose(fp);
				continue;
			}
		}
		(void) fclose(fp);

		(void) sprintf(fname, "%s/%s", tp->t_tag, svctag);

/*
 * do_config does all the real work (keep track if any errors occurred)
 */

		if (do_config(script, fname) == 0)
			added++;
		tp = tp->t_next;
	}
	if (added == 0) {
		Saferrno = E_SAFERR;
		error("No configuration scripts installed");
	}
	return;
}


/*
 * tell_sac - use sacadm to tell the sac to tell a port monitor to read
 *	its _pmtab.  Return TRUE on success, FALSE on failure.
 *
 *	args:	tag - tag of port monitor to be notified
 */


int
tell_sac(char *tag)
{
	pid_t pid;	/* returned pid from fork */
	int status;	/* return status from sacadm child */

	if ((pid = fork()) < 0) {
		(void) fprintf(stderr, "warning - fork failed - could not notify <%s> about modified table\n", tag);
		(void) fprintf(stderr, "try executing the command \"sacadm -x -p %s\"\n", tag);
		Saferrno = E_SYSERR;
		return(FALSE);
	}
	else if (pid) {
		/* parent */
		(void) wait(&status);
		if (status) {
			if (((status >> 8) & 0xff) == E_PMNOTRUN) {
				(void) fprintf(stderr, "warning - port monitor, %s is not running\n", tag);
				return (FALSE);
			}
			if (((status >> 8) & 0xff) == E_SACNOTRUN) {
				Saferrno = E_SACNOTRUN;
			} else {
				Saferrno = E_SYSERR;
			}
			(void) fprintf(stderr,
			    "warning - could not notify <%s> about modified"
			    " table\n", tag);
			(void) fprintf(stderr, "try executing the command"
			    " \"sacadm -x -p %s\"\n", tag);
			return(FALSE);
		}
		else {
			return(TRUE);
		}
	}
	else {
		/* set IFS for security */
		(void) putenv("IFS=\" \"");
		/* muffle sacadm warning messages */
		(void) fclose(stderr);
		(void) fopen("/dev/null", "w");
		(void) execl("/usr/sbin/sacadm", "sacadm", "-x", "-p", tag, 0);

/*
 * if we got here, it didn't work, exit status will clue in parent to
 * put out the warning
 */

		exit(1);
	}
	/* NOTREACHED */
}


/*
 * list_svcs - list information about services
 *
 *	args:	pmtag - tag of port monitor responsible for the service
 *			(may be null)
 *		type - type of port monitor responsible for the service
 *		       (may be null)
 *		svctag - tag of service to be listed (may be null)
 *		oflag - true if output should be easily parseable
 */

void
list_svcs(char *pmtag, char *type, char *svctag, int oflag)
{
	FILE *fp;				/* scratch file pointer */
	register struct taglist *tp;		/* pointer to PM list */
	int nprint = 0;				/* count # of svcs printed */
	struct pmtab pmtab;			/* place to hold parsed info */
	register struct pmtab *pp = &pmtab;	/* and a pointer to it */
	register char *p;			/* working pointer */
	char buf[SIZE];				/* scratch buffer */
	char fname[SIZE];			/* scratch buffer for building names */

	fp = fopen(SACTAB, "r");
	if (fp == NULL) {
		Saferrno = E_SYSERR;
		error("Could not open _sactab");
	}
	if (pmtag && !find_pm(fp, pmtag)) {
		(void) sprintf(buf, "Invalid request, %s does not exist", pmtag);
		Saferrno = E_NOEXIST;
		error(buf);
	}
	rewind(fp);
	if (type) {
		tp = find_type(fp, type);
		if (tp == NULL) {
			(void) sprintf(buf, "Invalid request, %s does not exist", type);
			Saferrno = E_NOEXIST;
			error(buf);
		}
	}
	else
		tp = find_type(fp, NULL);
	(void) fclose(fp);

	while (tp) {
		if (pmtag && strcmp(tp->t_tag, pmtag)) {
			/* not interested in this port monitor */
			tp = tp->t_next;
			continue;
		}
		(void) sprintf(fname, "%s/%s/_pmtab", HOME, tp->t_tag);
		fp = fopen(fname, "r");
		if (fp == NULL) {
			(void) sprintf(buf, "Could not open %s", fname);
			Saferrno = E_SYSERR;
			error(buf);
		}
		while (fgets(buf, SIZE, fp)) {
			p = trim(buf);
			if (*p == '\0')
				continue;
			parseline(p, pp, tp->t_tag);
			if (!svctag || !strcmp(pp->p_tag, svctag)) {
				if (oflag) {
					(void) printf("%s:%s:%s:%s:%s:%s:%s:%s:%s#%s\n",
						tp->t_tag, tp->t_type, pp->p_tag,
						pflags(pp->p_flags, FALSE),
						pp->p_id, pp->p_res1, pp->p_res2,
						pp->p_res3,pp->p_pmspec, Comment);
				}
				else {
					if (nprint == 0) {
						(void) printf("PMTAG          PMTYPE         SVCTAG         FLGS ID       <PMSPECIFIC>\n");
					}
					(void) printf("%-14s %-14s %-14s %-4s %-8s %s #%s\n", tp->t_tag, tp->t_type, pp->p_tag,
						pflags(pp->p_flags, TRUE), pp->p_id, pspec(pp->p_pmspec), Comment);
				}
				nprint++;
			}
		}
		if (!feof(fp)) {
			(void) sprintf(buf, "error reading %s", fname);
			Saferrno = E_SYSERR;
			error(buf);
		}
		else {
			(void) fclose(fp);
			tp = tp->t_next;
		}
	}
	/* if we didn't find any valid ones, indicate an error */
	if (nprint == 0) {
		if (svctag)
			(void) fprintf(stderr, "Service <%s> does not exist\n", svctag);
		else
			(void) fprintf(stderr, "No services defined\n");
		Saferrno = E_NOEXIST;
	}
	return;
}


/*
 * find_svc - find an entry in _pmtab for a particular service tag
 *
 *	args:	fp - file pointer for _pmtab
 *		tag - port monitor tag (for error reporting)
 *		svctag - tag of service we're looking for
 */

int
find_svc(FILE *fp, char *tag, char *svctag)
{
	register char *p;	/* working pointer */
	int line = 0;		/* line number we found entry on */
	struct pmtab pmtab;	/* place to hold parsed info */
	static char buf[SIZE];	/* scratch buffer */

	while (fgets(buf, SIZE, fp)) {
		line++;
		p = trim(buf);
		if (*p == '\0')
			continue;
		parseline(p, &pmtab, tag);
		if (!(strcmp(pmtab.p_tag, svctag)))
			return(line);
	}
	if (!feof(fp)) {
		(void) sprintf(buf, "error reading %s/%s/_pmtab", HOME, tag);
		Saferrno = E_SYSERR;
		error(buf);
		/* NOTREACHED */
		return (0);
	} else
		return (0);
}


/*
 * parseline - parse a line from _pmtab.  This routine will return if the
 *		parse wa successful, otherwise it will output an error and
 *		exit.
 *
 *	args:	p - pointer to the data read from the file (note - this is
 *		    a static data region, so we can point into it)
 *		pp - pointer to a structure in which the separated fields
 *		     are placed
 *		tag - port monitor tag (for error reporting)
 *
 *	A line in the file has the following format:
 *
 *	tag:flags:identity:reserved:reserved:reserved:PM_spec_info # comment
 */


void
parseline(p, pp, tag)
register char *p;
register struct pmtab *pp;
char *tag;
{
	char buf[SIZE];	/* scratch buffer */

/*
 * get the service tag
 */

	p = nexttok(p, DELIM, FALSE);
	if (p == NULL) {
		(void) sprintf(buf, "%s/%s/_pmtab is corrupt", HOME, tag);
		Saferrno = E_SAFERR;
		error(buf);
	}
	if (strlen(p) > PMTAGSIZE) {
		p[PMTAGSIZE] = '\0';
		(void) fprintf(stderr, "tag too long, truncated to <%s>", p);
	}
	pp->p_tag = p;

/*
 * get the flags
 */

	p = nexttok(NULL, DELIM, FALSE);
	if (p == NULL) {
		(void) sprintf(buf, "%s/%s/_pmtab is corrupt", HOME, tag);
		Saferrno = E_SAFERR;
		error(buf);
	}
	pp->p_flags = 0;
	while (*p) {
		switch (*p++) {
		case 'u':
			pp->p_flags |= U_FLAG;
			break;
		case 'x':
			pp->p_flags |= X_FLAG;
			break;
		default:
			(void) sprintf(buf, "Unrecognized flag <%c>", *(p - 1));
			Saferrno = E_SAFERR;
			error(buf);
			break;
		}
	}

/*
 * get the identity
 */

	p = nexttok(NULL, DELIM, FALSE);
	if (p == NULL) {
		(void) sprintf(buf, "%s/%s/_pmtab is corrupt", HOME, tag);
		Saferrno = E_SAFERR;
		error(buf);
	}
	pp->p_id = p;

/*
 * get the first reserved field
 */

	p = nexttok(NULL, DELIM, FALSE);
	if (p == NULL) {
		(void) sprintf(buf, "%s/%s/_pmtab is corrupt", HOME, tag);
		Saferrno = E_SAFERR;
		error(buf);
	}
	pp->p_res1 = p;

/*
 * get the second reserved field
 */

	p = nexttok(NULL, DELIM, FALSE);
	if (p == NULL) {
		(void) sprintf(buf, "%s/%s/_pmtab is corrupt", HOME, tag);
		Saferrno = E_SAFERR;
		error(buf);
	}
	pp->p_res2 = p;

/*
 * get the third reserved field
 */

	p = nexttok(NULL, DELIM, FALSE);
	if (p == NULL) {
		(void) sprintf(buf, "%s/%s/_pmtab is corrupt", HOME, tag);
		Saferrno = E_SAFERR;
		error(buf);
	}
	pp->p_res3 = p;

/*
 * the rest is the port monitor specific info
 */

	p = nexttok(NULL, DELIM, TRUE);
	if (p == NULL) {
		(void) sprintf(buf, "%s/%s/_pmtab is corrupt", HOME, tag);
		Saferrno = E_SAFERR;
		error(buf);
	}
	pp->p_pmspec = p;
	return;
}


/*
 * pspec - format port monitor specific information
 *
 *	args:	spec - port monitor specific info, separated by
 *		       field separater character (may be escaped by \)
 */

char *
pspec(spec)
char *spec;
{
	static char buf[SIZE];		/* returned string */
	register char *from;		/* working pointer */
	register char *to;		/* working pointer */
	int newflag;			/* flag indicating new field */

	to = buf;
	from = spec;
	newflag = 1;
	while (*from) {
		switch (*from) {
		case ':':
			if (newflag) {
				*to++ = '-';
			}
			*to++ = ' ';
			from++;
			newflag = 1;
			break;
		case '\\':
			if (*(from + 1) == ':') {
				*to++ = ':';
				/* skip over \: */
				from += 2;
			}
			else
				*to++ = *from++;
			newflag = 0;
			break;
		default:
			newflag = 0;
			*to++ = *from++;
		}
	}
	*to = '\0';
	return(buf);
}


/*
 * pflags - put service flags into intelligible form for output
 *
 *	args:	flags - binary representation of flags
 *		dflag - true if a "-" should be returned if no flags
 */

char *
pflags(flags, dflag)
long flags;
int dflag;
{
	register int i;			/* scratch counter */
	static char buf[SIZE];		/* formatted flags */

	if (flags == 0) {
		if (dflag)
			return("-");
		else
			return("");
	}
	i = 0;
	if (flags & U_FLAG) {
		buf[i++] = 'u';
		flags &= ~U_FLAG;
	}
	if (flags & X_FLAG) {
		buf[i++] = 'x';
		flags &= ~X_FLAG;
	}
	if (flags) {
		Saferrno = E_SAFERR;
		error("Internal error in pflags");
	}
	buf[i] = '\0';
	return(buf);
}


/*
 * find_type - find entries in _sactab for a particular port monitor type
 *
 *	args:	fp - file pointer for _sactab
 *		type - type of port monitor we're looking for (if type is
 *		       null, it means find all PMs)
 */

struct taglist *
find_type(fp, type)
FILE *fp;
char *type;
{
	register char *p;			/* working pointer */
	struct sactab stab;			/* place to hold parsed info */
	register struct sactab *sp = &stab;	/* and a pointer to it */
	char buf[SIZE];				/* scratch buffer */
	struct taglist *thead;			/* linked list of tags */
	register struct taglist *temp;		/* scratch pointer */

	thead = NULL;
	while (fgets(buf, SIZE, fp)) {
		p = trim(buf);
		if (*p == '\0')
			continue;
		parse(p, sp);
		if ((type == NULL) || !(strcmp(sp->sc_type, type))) {
			temp = (struct taglist *) malloc(sizeof(struct taglist));
			if (temp == NULL) {
				Saferrno = E_SYSERR;
				error("malloc failed");
			}
			temp->t_next = thead;
			(void) strcpy(temp->t_tag, sp->sc_tag);
			(void) strcpy(temp->t_type, sp->sc_type);
			thead = temp;
		}
	}
	if (!feof(fp)) {
		Saferrno = E_SYSERR;
		error("error reading _sactab");
		/* NOTREACHED */
		return (0);
	} else
		return (thead ? thead : NULL);
}
