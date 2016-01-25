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

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * This is a finger program.  It prints out useful information about users
 * by digging it up from various system files.
 *
 * There are three output formats, all of which give login name, teletype
 * line number, and login time.  The short output format is reminiscent
 * of finger on ITS, and gives one line of information per user containing
 * in addition to the minimum basic requirements (MBR), the user's full name,
 * idle time and location.
 * The quick style output is UNIX who-like, giving only name, teletype and
 * login time.  Finally, the long style output give the same information
 * as the short (in more legible format), the home directory and shell
 * of the user, and, if it exits, a copy of the file .plan in the users
 * home directory.  Finger may be called with or without a list of people
 * to finger -- if no list is given, all the people currently logged in
 * are fingered.
 *
 * The program is validly called by one of the following:
 *
 *	finger			{short form list of users}
 *	finger -l		{long form list of users}
 *	finger -b		{briefer long form list of users}
 *	finger -q		{quick list of users}
 *	finger -i		{quick list of users with idle times}
 *	finger -m		{matches arguments against only username}
 *	finger -f		{suppress header in non-long form}
 *	finger -p		{suppress printing of .plan file}
 *	finger -h		{suppress printing of .project file}
 *	finger -i		{forces "idle" output format}
 *	finger namelist		{long format list of specified users}
 *	finger -s namelist	{short format list of specified users}
 *	finger -w namelist	{narrow short format list of specified users}
 *
 * where 'namelist' is a list of users login names.
 * The other options can all be given after one '-', or each can have its
 * own '-'.  The -f option disables the printing of headers for short and
 * quick outputs.  The -b option briefens long format outputs.  The -p
 * option turns off plans for long format outputs.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <utmpx.h>
#include <sys/signal.h>
#include <pwd.h>
#include <stdio.h>
#include <lastlog.h>
#include <ctype.h>
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <locale.h>
#include <sys/select.h>
#include <stdlib.h>
#include <strings.h>
#include <fcntl.h>
#include <curses.h>
#include <unctrl.h>
#include <maillock.h>
#include <deflt.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <macros.h>

static char gecos_ignore_c = '*';	/* ignore this in real name */
static char gecos_sep_c = ',';		/* separator in pw_gecos field */
static char gecos_samename = '&';	/* repeat login name in real name */

#define	TALKABLE	0220		/* tty is writable if this mode */

#define	NMAX	sizeof (((struct utmpx *)0)->ut_name)
#define	LMAX	sizeof (((struct utmpx *)0)->ut_line)
#define	HMAX	sizeof (((struct utmpx *)0)->ut_host)

struct person {				/* one for each person fingered */
	char *name;			/* name */
	char tty[LMAX+1];		/* null terminated tty line */
	char host[HMAX+1];		/* null terminated remote host name */
	char *ttyloc;			/* location of tty line, if any */
	time_t loginat;			/* time of (last) login */
	time_t idletime;		/* how long idle (if logged in) */
	char *realname;			/* pointer to full name */
	struct passwd *pwd;		/* structure of /etc/passwd stuff */
	char loggedin;			/* person is logged in */
	char writable;			/* tty is writable */
	char original;			/* this is not a duplicate entry */
	struct person *link;		/* link to next person */
};

char PLAN[] = "/.plan";			/* what plan file is */
char PROJ[] = "/.project";		/* what project file */

int unbrief = 1;			/* -b option default */
int header = 1;				/* -f option default */
int hack = 1;				/* -h option default */
int idle = 0;				/* -i option default */
int large = 0;				/* -l option default */
int match = 1;				/* -m option default */
int plan = 1;				/* -p option default */
int unquick = 1;			/* -q option default */
int small = 0;				/* -s option default */
int wide = 1;				/* -w option default */

/*
 * RFC 1288 says that system administrators should have the option of
 * separately allowing ASCII characters less than 32 or greater than
 * 126.  The termpass variable keeps track of this.
 */
char	defaultfile[] = "/etc/default/finger";
char	passvar[] = "PASS=";
int	termpass = 0;			/* default is ASCII only */
char *termopts[] = {
#define	TERM_LOW	0
	"low",
#define	TERM_HIGH	1
	"high",
	(char *)NULL
};
#define	TS_LOW	(1 << TERM_LOW)		/* print characters less than 32 */
#define	TS_HIGH	(1 << TERM_HIGH)	/* print characters greater than 126 */


int unshort;
FILE *lf;				/* LASTLOG file pointer */
struct person *person1;			/* list of people */
size_t nperson;				/* number of people */
time_t tloc;				/* current time */

char usagestr[] = "Usage: "
	"finger [-bfhilmpqsw] [name1 [name2 ...] ]\n";

int AlreadyPrinted(uid_t uid);
void AnyMail(char *name);
void catfile(char *s, mode_t mode, int trunc_at_nl);
void decode(struct person *pers);
void doall(void);
void donames(char **argv);
void findidle(struct person *pers);
void findwhen(struct person *pers);
void fwclose(void);
void fwopen(void);
void initscreening(void);
void ltimeprint(char *before, time_t *dt, char *after);
int matchcmp(char *gname, char *login, char *given);
int namecmp(char *name1, char *name2);
int netfinger(char *name);
void personprint(struct person *pers);
void print(void);
struct passwd *pwdcopy(const struct passwd *pfrom);
void quickprint(struct person *pers);
void shortprint(struct person *pers);
void stimeprint(time_t *dt);
void sort_by_username(void);


int
main(int argc, char **argv)
{
	int c;

	(void) setlocale(LC_ALL, "");
	/* parse command line for (optional) arguments */
	while ((c = getopt(argc, argv, "bfhilmpqsw")) != EOF)
			switch (c) {
			case 'b':
				unbrief = 0;
				break;
			case 'f':
				header = 0;
				break;
			case 'h':
				hack = 0;
				break;
			case 'i':
				idle = 1;
				unquick = 0;
				break;
			case 'l':
				large = 1;
				break;
			case 'm':
				match = 0;
				break;
			case 'p':
				plan = 0;
				break;
			case 'q':
				unquick = 0;
				break;
			case 's':
				small = 1;
				break;
			case 'w':
				wide = 0;
				break;
			default:
				(void) fprintf(stderr, usagestr);
				exit(1);
			}
	if (unquick || idle)
		tloc = time(NULL);

	/* find out what filtering on .plan/.project files we should do */
	initscreening();

	/*
	 * optind == argc means no names given
	 */
	if (optind == argc)
		doall();
	else
		donames(&argv[optind]);

	sort_by_username();

	if (nperson > 0)
		print();
	return (0);
	/* NOTREACHED */
}

void
doall(void)
{
	struct person *p;
	struct passwd *pw;
	struct utmpx *u;
	char name[NMAX + 1];

	unshort = large;
	setutxent();
	if (unquick) {
		setpwent();
		fwopen();
	}
	while ((u = getutxent()) != NULL) {
		if (u->ut_name[0] == 0 ||
		    nonuserx(*u) ||
		    u->ut_type != USER_PROCESS)
			continue;
		if (person1 == NULL)
			p = person1 = malloc(sizeof (*p));
		else {
			p->link = malloc(sizeof (*p));
			p = p->link;
		}
		bcopy(u->ut_name, name, NMAX);
		name[NMAX] = 0;
		bcopy(u->ut_line, p->tty, LMAX);
		p->tty[LMAX] = 0;
		bcopy(u->ut_host, p->host, HMAX);
		p->host[HMAX] = 0;
		p->loginat = u->ut_tv.tv_sec;
		p->pwd = NULL;
		p->loggedin = 1;
		if (unquick && (pw = getpwnam(name))) {
			p->pwd = pwdcopy(pw);
			decode(p);
			p->name = p->pwd->pw_name;
		} else
			p->name = strdup(name);
		p->ttyloc = NULL;

		nperson++;
	}
	if (unquick) {
		fwclose();
		endpwent();
	}
	endutxent();
	if (nperson == 0) {
		(void) printf("No one logged on\n");
		return;
	}
	p->link = NULL;
}

void
donames(char **argv)
{
	struct person	*p;
	struct passwd	*pw;
	struct utmpx	*u;

	/*
	 * get names from command line and check to see if they're
	 * logged in
	 */
	unshort = !small;
	for (; *argv != NULL; argv++) {
		if (netfinger(*argv))
			continue;
		if (person1 == NULL)
			p = person1 = malloc(sizeof (*p));
		else {
			p->link = malloc(sizeof (*p));
			p = p->link;
		}
		p->name = *argv;
		p->loggedin = 0;
		p->original = 1;
		p->pwd = NULL;

		nperson++;
	}
	if (nperson == 0)
		return;
	p->link = NULL;
	/*
	 * if we are doing it, read /etc/passwd for the useful info
	 */
	if (unquick) {
		setpwent();
		if (!match) {
			for (p = person1; p != NULL; p = p->link) {
				if ((pw = getpwnam(p->name)) != NULL)
					p->pwd = pwdcopy(pw);
			}
		} else {
			while ((pw = getpwent()) != NULL) {
				for (p = person1; p != NULL; p = p->link) {
					if (!p->original)
						continue;
					if (strcmp(p->name, pw->pw_name) != 0 &&
					    !matchcmp(pw->pw_gecos, pw->pw_name,
					    p->name)) {
						continue;
					}
					if (p->pwd == NULL) {
						p->pwd = pwdcopy(pw);
					} else {
						struct person *new;
						/*
						 * Handle multiple login names.
						 * Insert new "duplicate" entry
						 * behind.
						 */
						new = malloc(sizeof (*new));
						new->pwd = pwdcopy(pw);
						new->name = p->name;
						new->original = 1;
						new->loggedin = 0;
						new->ttyloc = NULL;
						new->link = p->link;
						p->original = 0;
						p->link = new;
						p = new;

						nperson++;
					}
				}
			}
		}
		endpwent();
	}
	/* Now get login information */
	setutxent();
	while ((u = getutxent()) != NULL) {
		if (u->ut_name[0] == 0 || u->ut_type != USER_PROCESS)
			continue;
		for (p = person1; p != NULL; p = p->link) {
			p->ttyloc = NULL;
			if (p->loggedin == 2)
				continue;
			if (strncmp((p->pwd != NULL) ?
			    p->pwd->pw_name : p->name,
			    u->ut_name, NMAX) != 0)
				continue;
			if (p->loggedin == 0) {
				bcopy(u->ut_line, p->tty, LMAX);
				p->tty[LMAX] = 0;
				bcopy(u->ut_host, p->host, HMAX);
				p->host[HMAX] = 0;
				p->loginat = u->ut_tv.tv_sec;
				p->loggedin = 1;
			} else {	/* p->loggedin == 1 */
				struct person *new;
				new = malloc(sizeof (*new));
				new->name = p->name;
				bcopy(u->ut_line, new->tty, LMAX);
				new->tty[LMAX] = 0;
				bcopy(u->ut_host, new->host, HMAX);
				new->host[HMAX] = 0;
				new->loginat = u->ut_tv.tv_sec;
				new->pwd = p->pwd;
				new->loggedin = 1;
				new->original = 0;
				new->link = p->link;
				p->loggedin = 2;
				p->link = new;
				p = new;

				nperson++;
			}
		}
	}
	endutxent();
	if (unquick) {
		fwopen();
		for (p = person1; p != NULL; p = p->link)
			decode(p);
		fwclose();
	}
}

void
print(void)
{
	struct person *p;
	char *s;

	/*
	 * print out what we got
	 */
	if (header) {
		if (unquick) {
			if (!unshort) {
				if (wide) {
					(void) printf("Login       "
					    "Name               TTY         "
					    "Idle    When    Where\n");
				} else {
					(void) printf("Login    TTY Idle    "
					    "When    Where\n");
				}
			}
		} else {
			(void) printf("Login      TTY                When");
			if (idle)
				(void) printf("             Idle");
			(void) putchar('\n');
		}
	}
	for (p = person1; p != NULL; p = p->link) {
		if (!unquick) {
			quickprint(p);
			continue;
		}
		if (!unshort) {
			shortprint(p);
			continue;
		}
		personprint(p);
		if (p->pwd != NULL && !AlreadyPrinted(p->pwd->pw_uid)) {
			AnyMail(p->pwd->pw_name);
			if (hack) {
				struct stat sbuf;

				s = malloc(strlen(p->pwd->pw_dir) +
				    sizeof (PROJ));
				if (s != NULL) {
					(void) strcpy(s, p->pwd->pw_dir);
					(void) strcat(s, PROJ);
					if (stat(s, &sbuf) != -1 &&
					    (S_ISREG(sbuf.st_mode) ||
					    S_ISFIFO(sbuf.st_mode)) &&
					    (sbuf.st_mode & S_IROTH)) {
						(void) printf("Project: ");
						catfile(s, sbuf.st_mode, 1);
						(void) putchar('\n');
					}
					free(s);
				}
			}
			if (plan) {
				struct stat sbuf;

				s = malloc(strlen(p->pwd->pw_dir) +
				    sizeof (PLAN));
				if (s != NULL) {
					(void) strcpy(s, p->pwd->pw_dir);
					(void) strcat(s, PLAN);
					if (stat(s, &sbuf) == -1 ||
					    (!S_ISREG(sbuf.st_mode) &&
					    !S_ISFIFO(sbuf.st_mode)) ||
					    ((sbuf.st_mode & S_IROTH) == 0))
						(void) printf("No Plan.\n");
					else {
						(void) printf("Plan:\n");
						catfile(s, sbuf.st_mode, 0);
					}
					free(s);
				}
			}
		}
		if (p->link != NULL)
			(void) putchar('\n');
	}
}

/*
 * Duplicate a pwd entry.
 * Note: Only the useful things (what the program currently uses) are copied.
 */
struct passwd *
pwdcopy(const struct passwd *pfrom)
{
	struct passwd *pto;

	pto = malloc(sizeof (*pto));
	pto->pw_name = strdup(pfrom->pw_name);
	pto->pw_uid = pfrom->pw_uid;
	pto->pw_gecos = strdup(pfrom->pw_gecos);
	pto->pw_dir = strdup(pfrom->pw_dir);
	pto->pw_shell = strdup(pfrom->pw_shell);
	return (pto);
}

/*
 * print out information on quick format giving just name, tty, login time
 * and idle time if idle is set.
 */
void
quickprint(struct person *pers)
{
	(void) printf("%-8.8s  ", pers->name);
	if (pers->loggedin) {
		if (idle) {
			findidle(pers);
			(void) printf("%c%-12s %-16.16s",
			    pers->writable ? ' ' : '*',
			    pers->tty, ctime(&pers->loginat));
			ltimeprint("   ", &pers->idletime, "");
		} else {
			(void) printf(" %-12s %-16.16s",
			    pers->tty, ctime(&pers->loginat));
		}
		(void) putchar('\n');
	} else {
		(void) printf("          Not Logged In\n");
	}
}

/*
 * print out information in short format, giving login name, full name,
 * tty, idle time, login time, and host.
 */
void
shortprint(struct person *pers)
{
	char *p;

	if (pers->pwd == NULL) {
		(void) printf("%-15s       ???\n", pers->name);
		return;
	}
	(void) printf("%-8s", pers->pwd->pw_name);
	if (wide) {
		if (pers->realname != NULL) {
			(void) printf(" %-20.20s", pers->realname);
		} else {
			(void) printf("        ???          ");
		}
	}
	(void) putchar(' ');
	if (pers->loggedin && !pers->writable) {
		(void) putchar('*');
	} else {
		(void) putchar(' ');
	}
	if (*pers->tty) {
		(void) printf("%-11.11s ", pers->tty);
	} else {
		(void) printf("            ");  /* 12 spaces */
	}
	p = ctime(&pers->loginat);
	if (pers->loggedin) {
		stimeprint(&pers->idletime);
		(void) printf(" %3.3s %-5.5s ", p, p + 11);
	} else if (pers->loginat == 0) {
		(void) printf(" < .  .  .  . >");
	} else if (tloc - pers->loginat >= 180 * 24 * 60 * 60) {
		(void) printf(" <%-6.6s, %-4.4s>", p + 4, p + 20);
	} else {
		(void) printf(" <%-12.12s>", p + 4);
	}
	if (*pers->host) {
		(void) printf(" %-20.20s", pers->host);
	} else {
		if (pers->ttyloc != NULL)
			(void) printf(" %-20.20s", pers->ttyloc);
	}
	(void) putchar('\n');
}


/*
 * print out a person in long format giving all possible information.
 * directory and shell are inhibited if unbrief is clear.
 */
void
personprint(struct person *pers)
{
	if (pers->pwd == NULL) {
		(void) printf("Login name: %-10s\t\t\tIn real life: ???\n",
		    pers->name);
		return;
	}
	(void) printf("Login name: %-10s", pers->pwd->pw_name);
	if (pers->loggedin && !pers->writable) {
		(void) printf("	(messages off)	");
	} else {
		(void) printf("			");
	}
	if (pers->realname != NULL) {
		(void) printf("In real life: %s", pers->realname);
	}
	if (unbrief) {
		(void) printf("\nDirectory: %-25s", pers->pwd->pw_dir);
		if (*pers->pwd->pw_shell)
			(void) printf("\tShell: %-s", pers->pwd->pw_shell);
	}
	if (pers->loggedin) {
		char *ep = ctime(&pers->loginat);
		if (*pers->host) {
			(void) printf("\nOn since %15.15s on %s from %s",
			    &ep[4], pers->tty, pers->host);
			ltimeprint("\n", &pers->idletime, " Idle Time");
		} else {
			(void) printf("\nOn since %15.15s on %-12s",
			    &ep[4], pers->tty);
			ltimeprint("\n", &pers->idletime, " Idle Time");
		}
	} else if (pers->loginat == 0) {
		(void) printf("\nNever logged in.");
	} else if (tloc - pers->loginat > 180 * 24 * 60 * 60) {
		char *ep = ctime(&pers->loginat);
		(void) printf("\nLast login %10.10s, %4.4s on %s",
		    ep, ep+20, pers->tty);
		if (*pers->host) {
			(void) printf(" from %s", pers->host);
		}
	} else {
		char *ep = ctime(&pers->loginat);
		(void) printf("\nLast login %16.16s on %s", ep, pers->tty);
		if (*pers->host) {
			(void) printf(" from %s", pers->host);
		}
	}
	(void) putchar('\n');
}


/*
 * decode the information in the gecos field of /etc/passwd
 */
void
decode(struct person *pers)
{
	char buffer[256];
	char *bp, *gp, *lp;

	pers->realname = NULL;
	if (pers->pwd == NULL)
		return;
	gp = pers->pwd->pw_gecos;
	bp = buffer;

	if (gecos_ignore_c != '\0' &&
	    *gp == gecos_ignore_c) {
		gp++;
	}
	while (*gp != '\0' &&
	    *gp != gecos_sep_c)	{			/* name */
		if (*gp == gecos_samename) {
			lp = pers->pwd->pw_name;
			if (islower(*lp))
				*bp++ = toupper(*lp++);
			while (*bp++ = *lp++)
				;
			bp--;
			gp++;
		} else {
			*bp++ = *gp++;
		}
	}
	*bp++ = 0;
	if (bp > (buffer + 1))
		pers->realname = strdup(buffer);
	if (pers->loggedin)
		findidle(pers);
	else
		findwhen(pers);
}

/*
 * find the last log in of a user by checking the LASTLOG file.
 * the entry is indexed by the uid, so this can only be done if
 * the uid is known (which it isn't in quick mode)
 */
void
fwopen(void)
{
	if ((lf = fopen(_PATH_LASTLOG, "r")) == NULL)
		(void) fprintf(stderr, "finger: %s open error\n",
		    _PATH_LASTLOG);
}

void
findwhen(struct person *pers)
{
	struct lastlog ll;

	if (lf != NULL) {
		if (fseeko(lf, (off_t)pers->pwd->pw_uid * (off_t)sizeof (ll),
		    SEEK_SET) == 0) {
			if (fread((char *)&ll, sizeof (ll), 1, lf) == 1) {
				int l_max, h_max;

				l_max = min(LMAX, sizeof (ll.ll_line));
				h_max = min(HMAX, sizeof (ll.ll_host));

				bcopy(ll.ll_line, pers->tty, l_max);
				pers->tty[l_max] = '\0';
				bcopy(ll.ll_host, pers->host, h_max);
				pers->host[h_max] = '\0';
				pers->loginat = ll.ll_time;
			} else {
				if (ferror(lf))
					(void) fprintf(stderr,
					    "finger: %s read error\n",
					    _PATH_LASTLOG);
				pers->tty[0] = 0;
				pers->host[0] = 0;
				pers->loginat = 0L;
			}
		} else {
			(void) fprintf(stderr, "finger: %s fseeko error\n",
			    _PATH_LASTLOG);
		}
	} else {
		pers->tty[0] = 0;
		pers->host[0] = 0;
		pers->loginat = 0L;
	}
}

void
fwclose(void)
{
	if (lf != NULL)
		(void) fclose(lf);
}

/*
 * find the idle time of a user by doing a stat on /dev/tty??,
 * where tty?? has been gotten from UTMPX_FILE, supposedly.
 */
void
findidle(struct person *pers)
{
	struct stat ttystatus;
	struct stat inputdevstatus;
#define	TTYLEN (sizeof ("/dev/") - 1)
	static char buffer[TTYLEN + LMAX + 1] = "/dev/";
	time_t t;
	time_t lastinputtime;

	(void) strcpy(buffer + TTYLEN, pers->tty);
	buffer[TTYLEN+LMAX] = 0;
	if (stat(buffer, &ttystatus) < 0) {
		(void) fprintf(stderr, "finger: Can't stat %s\n", buffer);
		exit(4);
	}
	lastinputtime = ttystatus.st_atime;
	if (strcmp(pers->tty, "console") == 0) {
		/*
		 * On the console, the user may be running a window system; if
		 * so, their activity will show up in the last-access times of
		 * "/dev/kbd" and "/dev/mouse", so take the minimum of the idle
		 * times on those two devices and "/dev/console" and treat that
		 * as the idle time.
		 */
		if (stat("/dev/kbd", &inputdevstatus) == 0) {
			if (lastinputtime < inputdevstatus.st_atime)
				lastinputtime = inputdevstatus.st_atime;
		}
		if (stat("/dev/mouse", &inputdevstatus) == 0) {
			if (lastinputtime < inputdevstatus.st_atime)
				lastinputtime = inputdevstatus.st_atime;
		}
	}
	t = time(NULL);
	if (t < lastinputtime)
		pers->idletime = (time_t)0;
	else
		pers->idletime = t - lastinputtime;
	pers->writable = (ttystatus.st_mode & TALKABLE) == TALKABLE;
}

/*
 * print idle time in short format; this program always prints 4 characters;
 * if the idle time is zero, it prints 4 blanks.
 */
void
stimeprint(time_t *dt)
{
	struct tm *delta;

	delta = gmtime(dt);
	if (delta->tm_yday == 0)
		if (delta->tm_hour == 0)
			if (delta->tm_min == 0)
				(void) printf("    ");
			else
				(void) printf("  %2d", delta->tm_min);
		else
			if (delta->tm_hour >= 10)
				(void) printf("%3d:", delta->tm_hour);
			else
				(void) printf("%1d:%02d",
				    delta->tm_hour, delta->tm_min);
	else
		(void) printf("%3dd", delta->tm_yday);
}

/*
 * print idle time in long format with care being taken not to pluralize
 * 1 minutes or 1 hours or 1 days.
 * print "prefix" first.
 */
void
ltimeprint(char *before, time_t *dt, char *after)
{
	struct tm *delta;

	delta = gmtime(dt);
	if (delta->tm_yday == 0 && delta->tm_hour == 0 && delta->tm_min == 0 &&
	    delta->tm_sec <= 10)
		return;
	(void) printf("%s", before);
	if (delta->tm_yday >= 10)
		(void) printf("%d days", delta->tm_yday);
	else if (delta->tm_yday > 0)
		(void) printf("%d day%s %d hour%s",
		    delta->tm_yday, delta->tm_yday == 1 ? "" : "s",
		    delta->tm_hour, delta->tm_hour == 1 ? "" : "s");
	else
		if (delta->tm_hour >= 10)
			(void) printf("%d hours", delta->tm_hour);
		else if (delta->tm_hour > 0)
			(void) printf("%d hour%s %d minute%s",
			    delta->tm_hour, delta->tm_hour == 1 ? "" : "s",
			    delta->tm_min, delta->tm_min == 1 ? "" : "s");
		else
			if (delta->tm_min >= 10)
				(void) printf("%2d minutes", delta->tm_min);
			else if (delta->tm_min == 0)
				(void) printf("%2d seconds", delta->tm_sec);
			else
				(void) printf("%d minute%s %d second%s",
				    delta->tm_min,
				    delta->tm_min == 1 ? "" : "s",
				    delta->tm_sec,
				    delta->tm_sec == 1 ? "" : "s");
	(void) printf("%s", after);
}

/*
 * The grammar of the pw_gecos field is sufficiently complex that the
 * best way to parse it is by using an explicit finite-state machine,
 * in which a table defines the rules of interpretation.
 *
 * Some special rules are necessary to handle the fact that names
 * may contain certain punctuation characters.  At this writing,
 * the possible punctuation characters are '.', '-', and '_'.
 *
 * Other rules are needed to account for characters that require special
 * processing when they appear in the pw_gecos field.  At present, there
 * are three such characters, with these default values and effects:
 *
 *    gecos_ignore_c   '*'    This character is ignored.
 *    gecos_sep_c      ','    Delimits displayed and nondisplayed contents.
 *    gecos_samename   '&'    Copies the login name into the output.
 *
 * As the program examines each successive character in the returned
 * pw_gecos value, it fetches (from the table) the FSM rule applicable
 * for that character in the current machine state, and thus determines
 * the next state.
 *
 * The possible states are:
 *    S0 start
 *    S1 in a word
 *    S2 not in a word
 *    S3 copy login name into output
 *    S4 end of GECOS field
 *
 * Here follows a depiction of the state transitions.
 *
 *
 *              gecos_ignore_c OR isspace OR any other character
 *                  +--+
 *                  |  |
 *                  |  V
 *                 +-----+
 *    NULL OR      | S0  |  isalpha OR isdigit
 * +---------------|start|------------------------+
 * |  gecos_sep_c  +-----+                        |     isalpha OR isdigit
 * |                |  |                          |   +---------------------+
 * |                |  |                          |   | OR '.' '-' '_'      |
 * |                |  |isspace                   |   |                     |
 * |                |  +-------+                  V   V                     |
 * |                |          |              +-----------+                 |
 * |                |          |              |    S1     |<--+             |
 * |                |          |              | in a word |   | isalpha OR  |
 * |                |          |              +-----------+   | isdigit OR  |
 * |                |          |               |  |  |  |     | '.' '-' '_' |
 * |                |    +----- ---------------+  |  |  +-----+             |
 * |                |    |     |                  |  |                      |
 * |                |    |     |   gecos_ignore_c |  |                      |
 * |                |    |     |   isspace        |  |                      |
 * |                |    |     |   ispunct/other  |  |                      |
 * |                |    |     |   any other char |  |                      |
 * |                |    |     |  +---------------+  |                      |
 * |                |    |     |  |                  |NULL OR gecos_sep_c   |
 * |                |    |     |  |                  +------------------+   |
 * |  gecos_samename|    |     V  V                                     |   |
 * |  +-------------+    |    +---------------+                         |   |
 * |  |                  |    |       S2      | isspace OR '.' '-' '_'  |   |
 * |  |  gecos_samename  |    | not in a word |<---------------------+  |   |
 * |  |  +---------------+    +---------------+ OR gecos_ignore_c    |  |   |
 * |  |  |                        |    ^  |  |  OR ispunct OR other  |  |   |
 * |  |  |                        |    |  |  |                       |  |   |
 * |  |  |  gecos_samename        |    |  |  +-----------------------+  |   |
 * |  |  |  +---------------------+    |  |                             |   |
 * |  |  |  |                          |  |                             |   |
 * |  |  |  |            gecos_ignore_c|  | NULL OR gecos_sep_c         |   |
 * |  |  |  |            gecos_samename|  +-----------------------+     |   |
 * |  |  |  |            ispunct/other |                          |     |   |
 * |  V  V  V            isspace       |                          |     |   |
 * | +-----------------+ any other char|                          |     |   |
 * | |      S3         |---------------+  isalpha OR isdigit OR   |     |   |
 * | |insert login name|------------------------------------------ ----- ---+
 * | +-----------------+                  '.' '-' '_'             |     |
 * |                |    NULL OR gecos_sep_c                      |     |
 * |                +------------------------------------------+  |     |
 * |                                                           |  |     |
 * |                                                           V  V     V
 * |                                                         +------------+
 * | NULL OR gecos_sep_c                                     |     S4     |
 * +-------------------------------------------------------->|end of gecos|<--+
 *                                                           +------------+   |
 *                                                                      | all |
 *                                                                      +-----+
 *
 *
 *  The transitions from the above diagram are summarized in
 *  the following table of target states, which is implemented
 *  in code as the gecos_fsm array.
 *
 * Input:
 *        +--gecos_ignore_c
 *        |    +--gecos_sep_c
 *        |    |    +--gecos_samename
 *        |    |    |    +--isalpha
 *        |    |    |    |    +--isdigit
 *        |    |    |    |    |      +--isspace
 *        |    |    |    |    |      |    +--punctuation possible in name
 *        |    |    |    |    |      |    |    +--other punctuation
 *        |    |    |    |    |      |    |    |    +--NULL character
 *        |    |    |    |    |      |    |    |    |    +--any other character
 *        |    |    |    |    |      |    |    |    |    |
 *        V    V    V    V    V      V    V    V    V    V
 * From: ---------------------------------------------------
 * S0   | S0 | S4 | S3 | S1 | S1 |   S0 | S1 | S2 | S4 | S0 |
 * S1   | S2 | S4 | S3 | S1 | S1 |   S2 | S1 | S2 | S4 | S2 |
 * S2   | S2 | S4 | S3 | S1 | S1 |   S2 | S2 | S2 | S4 | S2 |
 * S3   | S2 | S4 | S2 | S1 | S1 |   S2 | S1 | S2 | S4 | S2 |
 * S4   | S4 | S4 | S4 | S4 | S4 |   S4 | S4 | S4 | S4 | S4 |
 *
 */

/*
 * Data types and structures for scanning the pw_gecos field.
 */
typedef enum gecos_state {
	S0,		/* start */
	S1,		/* in a word */
	S2,		/* not in a word */
	S3,		/* copy login */
	S4		/* end of gecos */
} gecos_state_t;

#define	GFSM_ROWS 5
#define	GFSM_COLS 10

gecos_state_t gecos_fsm[GFSM_ROWS][GFSM_COLS] = {
	{S0, S4, S3, S1, S1,	S0, S1, S2, S4, S0},	/* S0 */
	{S2, S4, S3, S1, S1,	S2, S1, S2, S4, S2},	/* S1 */
	{S2, S4, S3, S1, S1,	S2, S2, S2, S4, S2},	/* S2 */
	{S2, S4, S2, S1, S1,	S2, S1, S2, S4, S2},	/* S3 */
	{S4, S4, S4, S4, S4,	S4, S4, S4, S4, S4}	/* S4 */
};

/*
 * Scan the pw_gecos field according to defined state table;
 * return the next state according the the rules.
 */
gecos_state_t
gecos_scan_state(gecos_state_t instate, char ch)
{
	if (ch == gecos_ignore_c) {
		return (gecos_fsm[instate][0]);
	} else if (ch == gecos_sep_c) {
		return (gecos_fsm[instate][1]);
	} else if (ch == gecos_samename) {
		return (gecos_fsm[instate][2]);
	} else if (isalpha(ch)) {
		return (gecos_fsm[instate][3]);
	} else if (isdigit(ch)) {
		return (gecos_fsm[instate][4]);
	} else if (isspace(ch)) {
		return (gecos_fsm[instate][5]);
	} else if (ch == '.' || ch == '-' || ch == '_') {
		return (gecos_fsm[instate][6]);
	} else if (ispunct(ch)) {
		return (gecos_fsm[instate][7]);
	} else if (ch == '\0') {
		return (gecos_fsm[instate][8]);
	}
	return (gecos_fsm[instate][9]);
}


/*
 * Compare the given argument, which is taken to be a username, with
 * the login name and with strings in the the pw_gecos field.
 */
int
matchcmp(char *gname, char *login, char *given)
{
	char	buffer[100];
	char	*bp, *lp, *gp;

	gecos_state_t kstate = S0;
	gecos_state_t kstate_next = S0;

	if (*gname == '\0' && *given == '\0')
		return (1);

	bp = buffer;
	gp = gname;

	do {
		kstate_next = gecos_scan_state(kstate, *gp);

		switch (kstate_next) {

		case S0:
			gp++;
			break;
		case S1:
			if (bp < buffer + sizeof (buffer)) {
				*bp++ = *gp++;
			}
			break;
		case S2:
			if (kstate == S1 || kstate == S3) {
				*bp++ = ' ';
			}
			gp++;
			break;
		case S3:
			lp = login;
			do {
				*bp++ = *lp++;
			} while (*bp != '\0' && bp < buffer + sizeof (buffer));
			bp--;
			break;
		case S4:
			*bp++ = '\0';
			break;
		default:
			*bp++ = '\0';
			break;
		}
		kstate = kstate_next;

	} while ((bp < buffer + sizeof (buffer)) && kstate != S4);

	gp = strtok(buffer, " ");

	while (gp != NULL) {
		if (namecmp(gp, given) > 0) {
			return (1);
		}
		gp = strtok(NULL, " ");
	}
	return (0);
}

/*
 * Perform the character-by-character comparison.
 * It is intended that "finger foo" should match "foo2", but an argument
 * consisting entirely of digits should not be matched too broadly.
 * Also, we do not want "finger foo123" to match "Mr. Foo" in the gecos.
 */
int
namecmp(char *name1, char *name2)
{
	char c1, c2;
	boolean_t alphaseen = B_FALSE;
	boolean_t digitseen = B_FALSE;

	for (;;) {
		c1 = *name1++;
		if (isalpha(c1))
			alphaseen = B_TRUE;
		if (isdigit(c1))
			digitseen = B_TRUE;
		if (isupper(c1))
			c1 = tolower(c1);

		c2 = *name2++;
		if (isupper(c2))
			c2 = tolower(c2);

		if (c1 != c2)
			break;
		if (c1 == '\0')
			return (1);
	}
	if (!c1) {
		for (name2--; isdigit(*name2); name2++)
			;
		if (*name2 == '\0' && digitseen) {
			return (1);
		}
	} else if (!c2) {
		for (name1--; isdigit(*name1); name1++)
			;
		if (*name1 == '\0' && alphaseen) {
			return (1);
		}
	}
	return (0);
}


int
netfinger(char *name)
{
	char *host;
	struct hostent *hp;
	struct sockaddr_in6 sin6;
	struct in6_addr ipv6addr;
	struct in_addr ipv4addr;
	int s;
	FILE *f;
	int c;
	int lastc;
	char abuf[INET6_ADDRSTRLEN];
	int error_num;

	if (name == NULL)
		return (0);
	host = strrchr(name, '@');
	if (host == NULL)
		return (0);
	*host++ = 0;

	if ((hp = getipnodebyname(host, AF_INET6, AI_ALL | AI_ADDRCONFIG |
	    AI_V4MAPPED, &error_num)) == NULL) {
		if (error_num == TRY_AGAIN) {
			(void) fprintf(stderr,
			    "unknown host: %s (try again later)\n", host);
		} else {
			(void) fprintf(stderr, "unknown host: %s\n", host);
		}
		return (1);
	}

	/*
	 * If hp->h_name is a IPv4-mapped IPv6 literal, we'll convert it to
	 * IPv4 literal address.
	 */
	if ((inet_pton(AF_INET6, hp->h_name, &ipv6addr) > 0) &&
	    IN6_IS_ADDR_V4MAPPED(&ipv6addr)) {
		IN6_V4MAPPED_TO_INADDR(&ipv6addr, &ipv4addr);
		(void) printf("[%s] ", inet_ntop(AF_INET, &ipv4addr, abuf,
		    sizeof (abuf)));
	} else {
		(void) printf("[%s] ", hp->h_name);
	}
	bzero(&sin6, sizeof (sin6));
	sin6.sin6_family = hp->h_addrtype;
	bcopy(hp->h_addr_list[0], (char *)&sin6.sin6_addr, hp->h_length);
	sin6.sin6_port = htons(IPPORT_FINGER);
	s = socket(sin6.sin6_family, SOCK_STREAM, 0);
	if (s < 0) {
		(void) fflush(stdout);
		perror("socket");
		freehostent(hp);
		return (1);
	}
	while (connect(s, (struct sockaddr *)&sin6, sizeof (sin6)) < 0) {

		if (hp && hp->h_addr_list[1]) {

			hp->h_addr_list++;
			bcopy(hp->h_addr_list[0],
			    (caddr_t)&sin6.sin6_addr, hp->h_length);
			(void) close(s);
			s = socket(sin6.sin6_family, SOCK_STREAM, 0);
			if (s < 0) {
				(void) fflush(stdout);
				perror("socket");
				freehostent(hp);
				return (0);
			}
			continue;
		}

		(void) fflush(stdout);
		perror("connect");
		(void) close(s);
		freehostent(hp);
		return (1);
	}
	freehostent(hp);
	hp = NULL;

	(void) printf("\n");
	if (large)
		(void) write(s, "/W ", 3);
	(void) write(s, name, strlen(name));
	(void) write(s, "\r\n", 2);
	f = fdopen(s, "r");

	lastc = '\n';
	while ((c = getc(f)) != EOF) {
		/* map CRLF -> newline */
		if ((lastc == '\r') && (c != '\n'))
			/* print out saved CR */
			(void) putchar('\r');
		lastc = c;
		if (c == '\r')
			continue;
		(void) putchar(c);
	}

	if (lastc != '\n')
		(void) putchar('\n');
	(void) fclose(f);
	return (1);
}

/*
 *	AnyMail - takes a username (string pointer thereto), and
 *	prints on standard output whether there is any unread mail,
 *	and if so, how old it is.	(JCM@Shasta 15 March 80)
 */
void
AnyMail(char *name)
{
	struct stat buf;		/* space for file status buffer */
	char *mbxdir = MAILDIR; 	/* string with path preamble */
	char *mbxpath;			/* space for entire pathname */

	char *timestr;

	mbxpath = malloc(strlen(name) + strlen(MAILDIR) + 1);
	if (mbxpath == NULL)
		return;

	(void) strcpy(mbxpath, mbxdir);	/* copy preamble into path name */
	(void) strcat(mbxpath, name);	/* concatenate user name to path */

	if (stat(mbxpath, &buf) == -1 || buf.st_size == 0) {
		/* Mailbox is empty or nonexistent */
		(void) printf("No unread mail\n");
	} else {
		if (buf.st_mtime < buf.st_atime) {
			/*
			 * No new mail since the last time the user read it.
			 */
			(void) printf("Mail last read ");
			(void) printf("%s", ctime(&buf.st_atime));
		} else if (buf.st_mtime > buf.st_atime) {
			/*
			 * New mail has definitely arrived since the last time
			 * mail was read.  mtime is the time the most recent
			 * message arrived; atime is either the time the oldest
			 * unread message arrived, or the last time the mail
			 * was read.
			 */
			(void) printf("New mail received ");
			timestr = ctime(&buf.st_mtime); /* time last modified */
			timestr[24] = '\0';	/* suppress newline (ugh) */
			(void) printf("%s", timestr);
			(void) printf(";\n  unread since ");
			(void) printf("%s", ctime(&buf.st_atime));
		} else {
			/*
			 * There is something in mailbox, but we can't really
			 * be sure whether it is mail held there by the user
			 * or a (single) new message that was placed in a newly
			 * recreated mailbox, so punt and call it "unread mail."
			 */
			(void) printf("Unread mail since ");
			(void) printf("%s", ctime(&buf.st_mtime));
		}
	}
	free(mbxpath);
}

/*
 * return true iff we've already printed project/plan for this uid;
 * if not, enter this uid into table (so this function has a side-effect.)
 */
#define	PPMAX	4096		/* assume no more than 4096 logged-in users */
uid_t	PlanPrinted[PPMAX+1];
int	PPIndex = 0;		/* index of next unused table entry */

int
AlreadyPrinted(uid_t uid)
{
	int i = 0;

	while (i++ < PPIndex) {
		if (PlanPrinted[i] == uid)
		return (1);
	}
	if (i < PPMAX) {
		PlanPrinted[i] = uid;
		PPIndex++;
	}
	return (0);
}

#define	FIFOREADTIMEOUT	(60)	/* read timeout on select */
/* BEGIN CSTYLED */
#define	PRINT_CHAR(c)						\
	(							\
		((termpass & TS_HIGH) && ((int)c) > 126)	\
		||						\
		(isascii((int)c) && 				\
			 (isprint((int)c) || isspace((int)c))	\
		)						\
		||						\
		((termpass & TS_LOW) && ((int)c) < 32)		\
	)
/* END CSTYLED */


void
catfile(char *s, mode_t mode, int trunc_at_nl)
{
	if (S_ISFIFO(mode)) {
		int fd;

		fd = open(s, O_RDONLY | O_NONBLOCK);
		if (fd != -1) {
			fd_set readfds, exceptfds;
			struct timeval tv;

			FD_ZERO(&readfds);
			FD_ZERO(&exceptfds);
			FD_SET(fd, &readfds);
			FD_SET(fd, &exceptfds);

			timerclear(&tv);
			tv.tv_sec = FIFOREADTIMEOUT;

			(void) fflush(stdout);
			while (select(fd + 1, &readfds, (fd_set *) 0,
			    &exceptfds, &tv) != -1) {
				unsigned char buf[BUFSIZ];
				int nread;

				nread = read(fd, buf, sizeof (buf));
				if (nread > 0) {
					unsigned char *p;

					FD_SET(fd, &readfds);
					FD_SET(fd, &exceptfds);
					for (p = buf; p < buf + nread; p++) {
						if (trunc_at_nl && *p == '\n')
							goto out;
						if (PRINT_CHAR(*p))
							(void) putchar((int)*p);
						else if (isascii(*p))
							(void) fputs(unctrl(*p),
							    stdout);
					}
				} else
					break;
			}
out:
			(void) close(fd);
		}
	} else {
		int c;
		FILE *fp;

		fp = fopen(s, "r");
		if (fp) {
			while ((c = getc(fp)) != EOF) {
				if (trunc_at_nl && c == '\n')
					break;
				if (PRINT_CHAR(c))
					(void) putchar((int)c);
				else
					if (isascii(c))
						(void) fputs(unctrl(c), stdout);
			}
			(void) fclose(fp);
		}
	}
}


void
initscreening(void)
{
	char *options, *value;

	if (defopen(defaultfile) == 0) {
		char	*cp;
		int	flags;

		/*
		 * ignore case
		 */
		flags = defcntl(DC_GETFLAGS, 0);
		TURNOFF(flags, DC_CASE);
		(void) defcntl(DC_SETFLAGS, flags);

		if (cp = defread(passvar)) {
			options = cp;
			while (*options != '\0')
				switch (getsubopt(&options, termopts, &value)) {
				case TERM_LOW:
					termpass |= TS_LOW;
					break;
				case TERM_HIGH:
					termpass |= TS_HIGH;
					break;
				}
		}
		(void) defopen(NULL);	/* close default file */
	}
}

int
person_compare(const void *p1, const void *p2)
{
	const struct person *pp1 = *(struct person **)p1;
	const struct person *pp2 = *(struct person **)p2;
	int r;

	/*
	 * Sort by username.
	 */
	r = strcmp(pp1->name, pp2->name);

	if (r != 0)
		return (r);

	/*
	 * If usernames are the same, sort by idle time.
	 */
	r = pp1->idletime - pp2->idletime;

	return (r);
}

void
sort_by_username()
{
	struct person **sortable, *loop;
	size_t i;

	sortable = malloc(sizeof (sortable[0]) * nperson);

	if (sortable == NULL)
		return;

	for (i = 0, loop = person1; i < nperson; i++) {
		struct person *next = loop->link;

		sortable[i] = loop;
		loop->link = NULL;

		loop = next;
	}

	qsort(sortable, nperson, sizeof (sortable[0]), person_compare);

	for (i = 1; i < nperson; i++)
		sortable[i-1]->link = sortable[i];
	person1 = sortable[0];

	free(sortable);
}
