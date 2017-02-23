/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*
 *	synopsis: atrm [-f] [-i] [-a] [[job #] [user] ...]
 *
 *
 *	Remove "at" jobs.
 */

#include <stdio.h>
#include <pwd.h>
#include <ctype.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <locale.h>
#include <strings.h>
#include <stdlib.h>
#include <libintl.h>
#include "cron.h"
#include "getresponse.h"

extern time_t	num();
extern char	*errmsg();
extern void	audit_at_delete(char *, char *, int);

#define	SUPERUSER	0			/* is user super-user? */
#define	CANTCD		"can't change directory to the at directory"
#define	NOREADDIR	"can't read the at directory"

uid_t user;					/* person requesting removal */
int fflag = 0;					/* suppress announcements? */
int iflag = 0;					/* run interactively? */

char login[UNAMESIZE];
char login_authchk[UNAMESIZE]; /* used for authorization checks */

#define	INVALIDUSER	"you are not a valid user (no entry in /etc/passwd)"
#define	NOTALLOWED	"you are not authorized to use at.  Sorry."
#define	NAMETOOLONG	"login name too long"

static void usage(void);
static void atabortperror(char *msg);
static void atabort(char *msg);
static void atperror(char *msg);
static void atperror2(char *msg, char *name);
static void aterror(char *msg);
static void powner(char *file);

int	getjoblist(struct dirent ***, struct stat ***, int (*)());
int	removentry(char *, struct stat *, uid_t);

int
main(int argc, char **argv)
{
	int i;				/* for loop index */
	int numjobs;			/* # of jobs in spooling area */
	int allflag = 0;		/* remove all jobs belonging to user? */
	int jobexists;			/* does a requested job exist? */
	char *pp;
	struct dirent **namelist;	/* names of jobs in spooling area */
	struct stat **statlist;
	struct passwd *pwd;

	/*
	 * If job number, user name, or "-" is not specified, just print
	 * usage info and exit.
	 */
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);
	if (argc < 2)
		usage();

	--argc; ++argv;

	pp = getuser((user = getuid()));
	if (pp == NULL)
		atabort(INVALIDUSER);
	if (strlcpy(login, pp, sizeof (login)) >= sizeof (login))
		atabort(NAMETOOLONG);
	if (strlcpy(login_authchk, pp, sizeof (login_authchk))
	    >= sizeof (NAMETOOLONG))
		atabort(INVALIDUSER);
	if (!allowed(login, ATALLOW, ATDENY))
		atabort(NOTALLOWED);

	/*
	 * Process command line flags.
	 * Special case the "-" option so that others may be grouped.
	 */
	while (argc > 0 && **argv == '-') {
		*(*argv)++;
		while (**argv) {
			switch (*(*argv)++) {

			case 'a':	++allflag;
					break;

			case 'f':	++fflag;
					break;

			case 'i':	++iflag;
					break;

			default:	usage();
			}
		}
		++argv; --argc;
	}

	/*
	 * If all jobs are to be removed and extra command line arguments
	 * are given, print usage info and exit.
	 */
	if (allflag && argc)
		usage();

	/*
	 * If only certain jobs are to be removed and no job #'s or user
	 * names are specified, print usage info and exit.
	 */
	if (!allflag && !argc)
		usage();

	/*
	 * If interactive removal and quiet removal are requested, override
	 * quiet removal and run interactively.
	 */
	if (iflag && fflag)
		fflag = 0;


	/*
	 * Move to spooling directory and get a list of the files in the
	 * spooling area.
	 */
	numjobs = getjoblist(&namelist, &statlist, strcmp);
	/*
	 * If all jobs belonging to the user are to be removed, compare
	 * the user's id to the owner of the file. If they match, remove
	 * the file. If the user is the super-user, don't bother comparing
	 * the id's. After all files are removed, exit (status 0).
	 */
	if (allflag) {
		for (i = 0; i < numjobs; ++i) {
			if (cron_admin(login_authchk) ||
			    user == statlist[i]->st_uid)
				(void) removentry(namelist[i]->d_name,
				    statlist[i], user);
		}
		exit(0);
	}

	/*
	 * If only certain jobs are to be removed, interpret each command
	 * line argument. A check is done to see if it is a user's name or
	 * a job number (inode #). If it's a user's name, compare the argument
	 * to the files owner. If it's a job number, compare the argument to
	 * the file name. In either case, if a match occurs, try to
	 * remove the file.
	 */

	while (argc--) {
		jobexists = 0;
		for (i = 0; i < numjobs; ++i) {

			/* if the inode number is 0, this entry was removed */
			if (statlist[i]->st_ino == 0)
				continue;

			/*
			 * if argv is a username, compare their uid to
			 * the uid of the owner of the file......
			 */
			if (pwd = getpwnam(*argv)) {
				if (statlist[i]->st_uid != pwd->pw_uid)
					continue;
			/*
			 * otherwise, we assume that the argv is a job # and
			 * thus compare argv to the file name.
			 */
			} else {
				if (strcmp(namelist[i]->d_name, *argv))
					continue;
			}
			++jobexists;
			/*
			 * if the entry is ultimately removed, don't
			 * try to remove it again later.
			 */
			if (removentry(namelist[i]->d_name, statlist[i],
			    user)) {
				statlist[i]->st_ino = 0;
			}
		}

		/*
		 * If a requested argument doesn't exist, print a message.
		 */
		if (!jobexists && !fflag) {
			fprintf(stderr, "atrm: %s: no such job number\n",
			    *argv);
		}
		++argv;
	}
	return (0);
}

/*
 * Print usage info and exit.
 */
static void
usage(void)
{
	fprintf(stderr, "usage: atrm [-f] [-i] [-a] [[job #] [user] ...]\n");
	exit(1);
}


/*
 * Remove an entry from the queue. The access of the file is checked for
 * write permission (since all jobs are mode 644). If access is granted,
 * unlink the file. If the fflag (suppress announcements) is not set,
 * print the job number that we are removing and the result of the access
 * check (either "permission denied" or "removed"). If we are running
 * interactively (iflag), prompt the user before we unlink the file. If
 * the super-user is removing jobs, inform them who owns each file before
 * it is removed.  Return TRUE if file removed, else FALSE.
 */
int
removentry(char *filename, struct stat *statptr, uid_t user)
{
	struct passwd *pwd;
	char *pp;
	int r;

	if (init_yes() < 0) {
		(void) fprintf(stderr, gettext(ERR_MSG_INIT_YES),
		    strerror(errno));
		exit(1);
	}

	if (!fflag)
		printf("%s: ", filename);

	if (user != statptr->st_uid && !cron_admin(login_authchk)) {

		if (!fflag) {
			printf("permission denied\n");
		}
		return (0);

	} else {
		if (iflag) {
			if (cron_admin(login_authchk)) {
				printf("\t(owned by ");
				powner(filename);
				printf(") ");
			}
			printf(gettext("remove it? "));
			if (yes() == 0)
				return (0);
		}

		if (cron_admin(login_authchk)) {
			pp = getuser((uid_t)statptr->st_uid);
			if (pp == NULL)
				atabort(INVALIDUSER);
			if (strlcpy(login, pp, sizeof (login)) >=
			    sizeof (login))
				atabort(NAMETOOLONG);
		}
		cron_sendmsg(DELETE, login, filename, AT);
		if ((r = unlink(filename)) < 0) {
			if (!fflag) {
				fputs("could not remove\n", stdout);
				(void) fprintf(stderr, "atrm: %s: %s\n",
				    filename, errmsg(errno));
			}
			audit_at_delete(filename, NULL, r);
			return (0);
		}
		audit_at_delete(filename, NULL, r);
		if (!fflag && !iflag)
			printf("removed\n");
		return (1);
	}
}

/*
 * Print the owner of the job. This is the owner of the spoolfile.
 * If we run into trouble getting the name, we'll just print "???".
 */
static void
powner(char *file)
{
	struct stat statb;
	char *getname();

	if (stat(file, &statb) < 0) {
		printf("%s", "???");
		(void) fprintf(stderr, "atrm: Couldn't stat spoolfile %s: %s\n",
		    file, errmsg(errno));
		return;
	}

	printf("%s", getname(statb.st_uid));
}


int
getjoblist(struct dirent ***namelistp, struct stat ***statlistp,
    int (*sortfunc)())
{
	int numjobs;
	struct dirent **namelist;
	int i;
	struct stat *statptr;	/* pointer to file stat structure */
	struct stat **statlist;
	extern int filewanted();	/* should a file be listed in queue? */
	if (chdir(ATDIR) < 0)
		atabortperror(CANTCD);

	/*
	 * Get a list of the files in the spooling area.
	 */
	if ((numjobs = scandir(".", namelistp, filewanted, sortfunc)) < 0)
		atabortperror(NOREADDIR);

	if ((statlist =
	    (struct stat **)malloc(numjobs * sizeof (struct stat ***)))
	    == NULL)
		atabort("Out of memory");

	namelist = *namelistp;

	/*
	 * Build an array of pointers to the file stats for all jobs in
	 * the spooling area.
	 */
	for (i = 0; i < numjobs; ++i) {
		statptr = (struct stat *)malloc(sizeof (struct stat));
		if (statptr == NULL)
			atabort("Out of memory");
		if (stat(namelist[i]->d_name, statptr) < 0) {
			atperror2("Can't stat", namelist[i]->d_name);
			continue;
		}
		statlist[i] = statptr;
	}

	*statlistp = statlist;
	return (numjobs);
}

/*
 * Get the full login name of a person using their user id.
 */
char *
getname(uid_t uid)
{
	struct passwd *pwdinfo;		/* password info structure */


	if ((pwdinfo = getpwuid(uid)) == 0)
		return ("???");
	return (pwdinfo->pw_name);
}

static void
aterror(char *msg)
{
	fprintf(stderr, "atrm: %s\n", msg);
}

static void
atperror(char *msg)
{
	fprintf(stderr, "atrm: %s: %s\n", msg, errmsg(errno));
}

static void
atperror2(char *msg, char *name)
{
	fprintf(stderr, "atrm: %s %s: %s\n", msg, name, errmsg(errno));
}

static void
atabort(char *msg)
{
	aterror(msg);
	exit(1);
}

static void
atabortperror(char *msg)
{
	atperror(msg);
	exit(1);
}
