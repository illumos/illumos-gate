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
 *
 * Copyright 2013 Joshua M. Clulow <josh@sysmgr.org>
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*	Copyright (c) 1987, 1988 Microsoft Corporation	*/
/*	  All Rights Reserved	*/

#ifdef lint
/* make lint happy */
#define	__EXTENSIONS__
#endif

#include <sys/contract/process.h>
#include <sys/ctfs.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/task.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#include <security/pam_appl.h>

#include <alloca.h>
#include <ctype.h>
#include <deflt.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <libcontract.h>
#include <libcontract_priv.h>
#include <limits.h>
#include <locale.h>
#include <poll.h>
#include <project.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stropts.h>
#include <time.h>
#include <unistd.h>
#include <libzoneinfo.h>

#include "cron.h"

/*
 * #define	DEBUG
 */

#define	MAIL		"/usr/bin/mail"	/* mail program to use */
#define	CONSOLE		"/dev/console"	/* where messages go when cron dies */

#define	TMPINFILE	"/tmp/crinXXXXXX"  /* file to put stdin in for cmd  */
#define	TMPDIR		"/tmp"
#define	PFX		"crout"
#define	TMPOUTFILE	"/tmp/croutXXXXXX" /* file to place stdout, stderr */

#define	INMODE		00400		/* mode for stdin file	*/
#define	OUTMODE		00600		/* mode for stdout file */
#define	ISUID		S_ISUID		/* mode for verifing at jobs */

#define	INFINITY	2147483647L	/* upper bound on time	*/
#define	CUSHION		180L
#define	ZOMB		100		/* proc slot used for mailing output */

#define	JOBF		'j'
#define	NICEF		'n'
#define	USERF		'u'
#define	WAITF		'w'

#define	BCHAR		'>'
#define	ECHAR		'<'

#define	DEFAULT		0
#define	LOAD		1
#define	QBUFSIZ		80

/* Defined actions for crabort() routine */
#define	NO_ACTION	000
#define	REMOVE_FIFO	001
#define	CONSOLE_MSG	002

#define	BADCD		"can't change directory to the crontab directory."
#define	NOREADDIR	"can't read the crontab directory."

#define	BADJOBOPEN	"unable to read your at job."
#define	BADSHELL	"because your login shell \
isn't /usr/bin/sh, you can't use cron."

#define	BADSTAT		"can't access your crontab or at-job file. Resubmit it."
#define	BADPROJID	"can't set project id for your job."
#define	CANTCDHOME	"can't change directory to %s.\
\nYour commands will not be executed."
#define	CANTEXECSH	"unable to exec the shell, %s, for one of your \
commands."
#define	CANT_STR_LEN (sizeof (CANTEXECSH) > sizeof (CANTCDHOME) ? \
	sizeof (CANTEXECSH) : sizeof (CANTCDHOME))
#define	NOREAD		"can't read your crontab file.  Resubmit it."
#define	BADTYPE		"crontab or at-job file is not a regular file.\n"
#define	NOSTDIN		"unable to create a standard input file for \
one of your crontab commands. \
\nThat command was not executed."

#define	NOTALLOWED	"you are not authorized to use cron.  Sorry."
#define	STDERRMSG	"\n\n********************************************\
*****\nCron: The previous message is the \
standard output and standard error \
\nof one of your cron commands.\n"

#define	STDOUTERR	"one of your commands generated output or errors, \
but cron was unable to mail you this output.\
\nRemember to redirect standard output and standard \
error for each of your commands."

#define	CLOCK_DRIFT	"clock time drifted backwards after event!\n"
#define	PIDERR		"unexpected pid returned %d (ignored)"
#define	CRONTABERR	"Subject: Your crontab file has an error in it\n\n"
#define	MALLOCERR	"out of space, cannot create new string\n"

#define	DIDFORK didfork
#define	NOFORK !didfork

#define	MAILBUFLEN	(8*1024)
#define	LINELIMIT	80
#define	MAILBINITFREE	(MAILBUFLEN - (sizeof (cte_intro) - 1) \
	    - (sizeof (cte_trail1) - 1) - (sizeof (cte_trail2) - 1) - 1)

#define	ERR_CRONTABENT	0	/* error in crontab file entry */
#define	ERR_UNIXERR	1	/* error in some system call */
#define	ERR_CANTEXECCRON 2	/* error setting up "cron" job environment */
#define	ERR_CANTEXECAT	3	/* error setting up "at" job environment */
#define	ERR_NOTREG	4	/* error not a regular file */

#define	PROJECT		"project="

#define	MAX_LOST_CONTRACTS	2048	/* reset if this many failed abandons */

#define	FORMAT	"%a %b %e %H:%M:%S %Y"
static char	timebuf[80];

static struct message msgbuf;

struct shared {
	int count;			/* usage count */
	void (*free)(void *obj);	/* routine that will free obj */
	void *obj;			/* object */
};

struct event {
	time_t time;	/* time of the event	*/
	short etype;	/* what type of event; 0=cron, 1=at	*/
	char *cmd;	/* command for cron, job name for at	*/
	struct usr *u;	/* ptr to the owner (usr) of this event	*/
	struct event *link;	/* ptr to another event for this user */
	union {
		struct { /* for crontab events */
			char *minute;	/*  (these	*/
			char *hour;	/*   fields	*/
			char *daymon;	/*   are	*/
			char *month;	/*   from	*/
			char *dayweek;	/*   crontab)	*/
			char *input;	/* ptr to stdin	*/
			struct shared *tz;	/* timezone of this event */
			struct shared *home;	/* directory for this event */
			struct shared *shell;	/* shell for this event */
		} ct;
		struct { /* for at events */
			short exists;	/* for revising at events	*/
			int eventid;	/* for el_remove-ing at events	*/
		} at;
	} of;
};

struct usr {
	char *name;	/* name of user (e.g. "root")	*/
	char *home;	/* home directory for user	*/
	uid_t uid;	/* user id	*/
	gid_t gid;	/* group id	*/
	int aruncnt;	/* counter for running jobs per uid */
	int cruncnt;	/* counter for running cron jobs per uid */
	int ctid;	/* for el_remove-ing crontab events */
	short ctexists;	/* for revising crontab events	*/
	struct event *ctevents;	/* list of this usr's crontab events */
	struct event *atevents;	/* list of this usr's at events */
	struct usr *nextusr;
};	/* ptr to next user	*/

static struct	queue
{
	int njob;	/* limit */
	int nice;	/* nice for execution */
	int nwait;	/* wait time to next execution attempt */
	int nrun;	/* number running */
}
	qd = {100, 2, 60},		/* default values for queue defs */
	qt[NQUEUE];
static struct	queue	qq;

static struct runinfo
{
	pid_t	pid;
	short	que;
	struct  usr *rusr;	/* pointer to usr struct */
	char	*outfile;	/* file where stdout & stderr are trapped */
	short	jobtype;	/* what type of event: 0=cron, 1=at */
	char	*jobname;	/* command for "cron", jobname for "at" */
	int	mailwhendone;	/* 1 = send mail even if no ouptut */
	struct runinfo *next;
}	*rthead;

static struct miscpid {
	pid_t		pid;
	struct miscpid	*next;
}	*miscpid_head;

static pid_t cron_pid;	/* own pid */
static char didfork = 0; /* flag to see if I'm process group leader */
static int msgfd;	/* file descriptor for fifo queue */
static int ecid = 1;	/* event class id for el_remove(); MUST be set to 1 */
static int delayed;	/* is job being rescheduled or did it run first time */
static int cwd;		/* current working directory */
static struct event *next_event;	/* the next event to execute	*/
static struct usr *uhead;		/* ptr to the list of users	*/

/* Variables for error handling at reading crontabs. */
static char cte_intro[] = "Line(s) with errors:\n\n";
static char cte_trail1[] = "\nMax number of errors encountered.";
static char cte_trail2[] = " Evaluation of crontab aborted.\n";
static int cte_free = MAILBINITFREE;	/* Free buffer space */
static char *cte_text = NULL;		/* Text buffer pointer */
static char *cte_lp;			/* Next free line in cte_text */
static int cte_nvalid;			/* Valid lines found */

/* user's default environment for the shell */
#define	ROOTPATH	"PATH=/usr/sbin:/usr/bin"
#define	NONROOTPATH	"PATH=/usr/bin:"

static char *Def_supath	= NULL;
static char *Def_path		= NULL;
static char path[LINE_MAX]	= "PATH=";
static char supath[LINE_MAX]	= "PATH=";
static char homedir[LINE_MAX]	= ENV_HOME;
static char logname[LINE_MAX]	= "LOGNAME=";
static char tzone[LINE_MAX]	= ENV_TZ;
static char *envinit[] = {
	homedir,
	logname,
	ROOTPATH,
	"SHELL=/usr/bin/sh",
	tzone,
	NULL
};

extern char **environ;

#define	DEFTZ		"GMT"
static	int	log = 0;
static	char	hzname[10];

static void cronend(int);
static void thaw_handler(int);
static void child_handler(int);
static void child_sigreset(void);

static void mod_ctab(char *, time_t);
static void mod_atjob(char *, time_t);
static void add_atevent(struct usr *, char *, time_t, int);
static void rm_ctevents(struct usr *);
static void cleanup(struct runinfo *rn, int r);
static void crabort(char *, int);
static void msg(char *fmt, ...);
static void ignore_msg(char *, char *, struct event *);
static void logit(int, struct runinfo *, int);
static void parsqdef(char *);
static void defaults();
static void initialize(int);
static void quedefs(int);
static int idle(long);
static struct usr *find_usr(char *);
static int ex(struct event *e);
static void read_dirs(int);
static void mail(char *, char *, int);
static char *next_field(int, int);
static void readcron(struct usr *, time_t);
static int next_ge(int, char *);
static void free_if_unused(struct usr *);
static void del_atjob(char *, char *);
static void del_ctab(char *);
static void resched(int);
static int msg_wait(long);
static struct runinfo *rinfo_get(pid_t);
static void rinfo_free(struct runinfo *rp);
static void mail_result(struct usr *p, struct runinfo *pr, size_t filesize);
static time_t next_time(struct event *, time_t);
static time_t get_switching_time(int, time_t);
static time_t xmktime(struct tm *);
static void process_msg(struct message *, time_t);
static void reap_child(void);
static void miscpid_insert(pid_t);
static int miscpid_delete(pid_t);
static void contract_set_template(void);
static void contract_clear_template(void);
static void contract_abandon_latest(pid_t);

static void cte_init(void);
static void cte_add(int, char *);
static void cte_valid(void);
static int cte_istoomany(void);
static void cte_sendmail(char *);

static int set_user_cred(const struct usr *, struct project *);

static struct shared *create_shared_str(char *str);
static struct shared *dup_shared(struct shared *obj);
static void rel_shared(struct shared *obj);
static void *get_obj(struct shared *obj);
/*
 * last_time is set immediately prior to exection of an event (via ex())
 * to indicate the last time an event was executed.  This was (surely)
 * it's original intended use.
 */
static time_t last_time, init_time, t_old;
static int reset_needed; /* set to 1 when cron(1M) needs to re-initialize */

static int		refresh;
static sigset_t		defmask, sigmask;

/*
 * BSM hooks
 */
extern int	audit_cron_session(char *, char *, uid_t, gid_t, char *);
extern void	audit_cron_new_job(char *, int, void *);
extern void	audit_cron_bad_user(char *);
extern void	audit_cron_user_acct_expired(char *);
extern int	audit_cron_create_anc_file(char *, char *, char *, uid_t);
extern int	audit_cron_delete_anc_file(char *, char *);
extern int	audit_cron_is_anc_name(char *);
extern int	audit_cron_mode();

static int cron_conv(int, struct pam_message **,
		struct pam_response **, void *);

static struct pam_conv pam_conv = {cron_conv, NULL};
static pam_handle_t *pamh;	/* Authentication handle */

/*
 * Function to help check a user's credentials.
 */

static int verify_user_cred(struct usr *u);

/*
 * Values returned by verify_user_cred and set_user_cred:
 */

#define	VUC_OK		0
#define	VUC_BADUSER	1
#define	VUC_NOTINGROUP	2
#define	VUC_EXPIRED	3
#define	VUC_NEW_AUTH	4

/*
 * Modes of process_anc_files function
 */
#define	CRON_ANC_DELETE	1
#define	CRON_ANC_CREATE	0

/*
 * Functions to remove a user or job completely from the running database.
 */
static void clean_out_atjobs(struct usr *u);
static void clean_out_ctab(struct usr *u);
static void clean_out_user(struct usr *u);
static void cron_unlink(char *name);
static void process_anc_files(int);

/*
 * functions in elm.c
 */
extern void el_init(int, time_t, time_t, int);
extern int el_add(void *, time_t, int);
extern void el_remove(int, int);
extern int el_empty(void);
extern void *el_first(void);
extern void el_delete(void);

static int valid_entry(char *, int);
static struct usr *create_ulist(char *, int);
static void init_cronevent(char *, int);
static void init_atevent(char *, time_t, int, int);
static void update_atevent(struct usr *, char *, time_t, int);

int
main(int argc, char *argv[])
{
	time_t t;
	time_t ne_time;		/* amt of time until next event execution */
	time_t newtime, lastmtime = 0L;
	struct usr *u;
	struct event *e, *e2, *eprev;
	struct stat buf;
	pid_t rfork;
	struct sigaction act;

	/*
	 * reset_needed is set to 1 whenever el_add() finds out that a cron
	 * job is scheduled to be run before the time when cron(1M) daemon
	 * initialized.
	 * Other cases where a reset is needed is when ex() finds that the
	 * event to be executed is being run at the wrong time, or when idle()
	 * determines that time was reset.
	 * We immediately return to the top of the while (TRUE) loop in
	 * main() where the event list is cleared and rebuilt, and reset_needed
	 * is set back to 0.
	 */
	reset_needed = 0;

	/*
	 * Only the privileged user can run this command.
	 */
	if (getuid() != 0)
		crabort(NOTALLOWED, 0);

begin:
	(void) setlocale(LC_ALL, "");
	/* fork unless 'nofork' is specified */
	if ((argc <= 1) || (strcmp(argv[1], "nofork"))) {
		if (rfork = fork()) {
			if (rfork == (pid_t)-1) {
				(void) sleep(30);
				goto begin;
			}
			return (0);
		}
		didfork++;
		(void) setpgrp();	/* detach cron from console */
	}

	(void) umask(022);
	(void) signal(SIGHUP, SIG_IGN);
	(void) signal(SIGINT, SIG_IGN);
	(void) signal(SIGQUIT, SIG_IGN);
	(void) signal(SIGTERM, cronend);

	defaults();
	initialize(1);
	quedefs(DEFAULT);	/* load default queue definitions */
	cron_pid = getpid();
	msg("*** cron started ***   pid = %d", cron_pid);

	/* setup THAW handler */
	act.sa_handler = thaw_handler;
	act.sa_flags = 0;
	(void) sigemptyset(&act.sa_mask);
	(void) sigaction(SIGTHAW, &act, NULL);

	/* setup CHLD handler */
	act.sa_handler = child_handler;
	act.sa_flags = 0;
	(void) sigemptyset(&act.sa_mask);
	(void) sigaddset(&act.sa_mask, SIGCLD);
	(void) sigaction(SIGCLD, &act, NULL);

	(void) sigemptyset(&defmask);
	(void) sigemptyset(&sigmask);
	(void) sigaddset(&sigmask, SIGCLD);
	(void) sigaddset(&sigmask, SIGTHAW);
	(void) sigprocmask(SIG_BLOCK, &sigmask, NULL);

	t_old = init_time;
	last_time = t_old;
	for (;;) {		/* MAIN LOOP */
		t = time(NULL);
		if ((t_old > t) || (t-last_time > CUSHION) || reset_needed) {
			reset_needed = 0;
			/*
			 * the time was set backwards or forward or
			 * refresh is requested.
			 */
			if (refresh)
				msg("re-scheduling jobs");
			else
				msg("time was reset, re-initializing");
			el_delete();
			u = uhead;
			while (u != NULL) {
				rm_ctevents(u);
				e = u->atevents;
				while (e != NULL) {
					free(e->cmd);
					e2 = e->link;
					free(e);
					e = e2;
				}
				u->atevents = NULL;
				u = u->nextusr;
			}
			(void) close(msgfd);
			initialize(0);
			t = time(NULL);
			last_time = t;
			/*
			 * reset_needed might have been set in the functions
			 * call path from initialize()
			 */
			if (reset_needed) {
				continue;
			}
		}
		t_old = t;

		if (next_event == NULL && !el_empty()) {
			next_event = (struct event *)el_first();
		}
		if (next_event == NULL) {
			ne_time = INFINITY;
		} else {
			ne_time = next_event->time - t;
#ifdef DEBUG
			cftime(timebuf, "%C", &next_event->time);
			(void) fprintf(stderr, "next_time=%ld %s\n",
			    next_event->time, timebuf);
#endif
		}
		if (ne_time > 0) {
			/*
			 * reset_needed may be set in the functions call path
			 * from idle()
			 */
			if (idle(ne_time) || reset_needed) {
				reset_needed = 1;
				continue;
			}
		}

		if (stat(QUEDEFS, &buf)) {
			msg("cannot stat QUEDEFS file");
		} else if (lastmtime != buf.st_mtime) {
			quedefs(LOAD);
			lastmtime = buf.st_mtime;
		}

		last_time = next_event->time; /* save execution time */

		/*
		 * reset_needed may be set in the functions call path
		 * from ex()
		 */
		if (ex(next_event) || reset_needed) {
			reset_needed = 1;
			continue;
		}

		switch (next_event->etype) {
		case CRONEVENT:
			/* add cronevent back into the main event list */
			if (delayed) {
				delayed = 0;
				break;
			}

			/*
			 * check if time(0)< last_time. if so, then the
			 * system clock has gone backwards. to prevent this
			 * job from being started twice, we reschedule this
			 * job for the >>next time after last_time<<, and
			 * then set next_event->time to this. note that
			 * crontab's resolution is 1 minute.
			 */

			if (last_time > time(NULL)) {
				msg(CLOCK_DRIFT);
				/*
				 * bump up to next 30 second
				 * increment
				 * 1 <= newtime <= 30
				 */
				newtime = 30 - (last_time % 30);
				newtime += last_time;

				/*
				 * get the next scheduled event,
				 * not the one that we just
				 * kicked off!
				 */
				next_event->time =
				    next_time(next_event, newtime);
				t_old = time(NULL);
			} else {
				next_event->time =
				    next_time(next_event, (time_t)0);
			}
#ifdef DEBUG
			cftime(timebuf, "%C", &next_event->time);
			(void) fprintf(stderr,
			    "pushing back cron event %s at %ld (%s)\n",
			    next_event->cmd, next_event->time, timebuf);
#endif

			switch (el_add(next_event, next_event->time,
			    (next_event->u)->ctid)) {
			case -1:
				ignore_msg("main", "cron", next_event);
				break;
			case -2: /* event time lower than init time */
				reset_needed = 1;
				break;
			}
			break;
		default:
			/* remove at or batch job from system */
			if (delayed) {
				delayed = 0;
				break;
			}
			eprev = NULL;
			e = (next_event->u)->atevents;
			while (e != NULL) {
				if (e == next_event) {
					if (eprev == NULL)
						(e->u)->atevents = e->link;
					else
						eprev->link = e->link;
					free(e->cmd);
					free(e);
					break;
				} else {
					eprev = e;
					e = e->link;
				}
			}
			break;
		}
		next_event = NULL;
	}

	/*NOTREACHED*/
}

static void
initialize(int firstpass)
{
#ifdef DEBUG
	(void) fprintf(stderr, "in initialize\n");
#endif
	if (firstpass) {
		/* for mail(1), make sure messages come from root */
		if (putenv("LOGNAME=root") != 0) {
			crabort("cannot expand env variable",
			    REMOVE_FIFO|CONSOLE_MSG);
		}
		if (access(FIFO, R_OK) == -1) {
			if (errno == ENOENT) {
				if (mknod(FIFO, S_IFIFO|0600, 0) != 0)
					crabort("cannot create fifo queue",
					    REMOVE_FIFO|CONSOLE_MSG);
			} else {
				if (NOFORK) {
					/* didn't fork... init(1M) is waiting */
					(void) sleep(60);
				}
				perror("FIFO");
				crabort("cannot access fifo queue",
				    REMOVE_FIFO|CONSOLE_MSG);
			}
		} else {
			if (NOFORK) {
				/* didn't fork... init(1M) is waiting */
				(void) sleep(60);
				/*
				 * the wait is painful, but we don't want
				 * init respawning this quickly
				 */
			}
			crabort("cannot start cron; FIFO exists", CONSOLE_MSG);
		}
	}

	if ((msgfd = open(FIFO, O_RDWR)) < 0) {
		perror("! open");
		crabort("cannot open fifo queue", REMOVE_FIFO|CONSOLE_MSG);
	}

	init_time = time(NULL);
	el_init(8, init_time, (time_t)(60*60*24), 10);

	init_time = time(NULL);
	el_init(8, init_time, (time_t)(60*60*24), 10);

	/*
	 * read directories, create users list, and add events to the
	 * main event list. Only zero user list on firstpass.
	 */
	if (firstpass)
		uhead = NULL;
	read_dirs(firstpass);
	next_event = NULL;

	if (!firstpass)
		return;

	/* stdout is log file */
	if (freopen(ACCTFILE, "a", stdout) == NULL)
		(void) fprintf(stderr, "cannot open %s\n", ACCTFILE);

	/* log should be root-only */
	(void) fchmod(1, S_IRUSR|S_IWUSR);

	/* stderr also goes to ACCTFILE */
	(void) close(fileno(stderr));
	(void) dup(1);
	/* null for stdin */
	(void) freopen("/dev/null", "r", stdin);

	contract_set_template();
}

static void
read_dirs(int first)
{
	DIR		*dir;
	struct dirent	*dp;
	char		*ptr;
	int		jobtype;
	time_t		tim;


	if (chdir(CRONDIR) == -1)
		crabort(BADCD, REMOVE_FIFO|CONSOLE_MSG);
	cwd = CRON;
	if ((dir = opendir(".")) == NULL)
		crabort(NOREADDIR, REMOVE_FIFO|CONSOLE_MSG);
	while ((dp = readdir(dir)) != NULL) {
		if (!valid_entry(dp->d_name, CRONEVENT))
			continue;
		init_cronevent(dp->d_name, first);
	}
	(void) closedir(dir);

	if (chdir(ATDIR) == -1) {
		msg("cannot chdir to at directory");
		return;
	}
	if ((dir = opendir(".")) == NULL) {
		msg("cannot read at at directory");
		return;
	}
	cwd = AT;
	while ((dp = readdir(dir)) != NULL) {
		if (!valid_entry(dp->d_name, ATEVENT))
			continue;
		ptr = dp->d_name;
		if (((tim = num(&ptr)) == 0) || (*ptr != '.'))
			continue;
		ptr++;
		if (!isalpha(*ptr))
			continue;
		jobtype = *ptr - 'a';
		if (jobtype >= NQUEUE) {
			cron_unlink(dp->d_name);
			continue;
		}
		init_atevent(dp->d_name, tim, jobtype, first);
	}
	(void) closedir(dir);
}

static int
valid_entry(char *name, int type)
{
	struct stat	buf;

	if (strcmp(name, ".") == 0 ||
	    strcmp(name, "..") == 0)
		return (0);

	/* skip over ancillary file names */
	if (audit_cron_is_anc_name(name))
		return (0);

	if (stat(name, &buf)) {
		mail(name, BADSTAT, ERR_UNIXERR);
		cron_unlink(name);
		return (0);
	}
	if (!S_ISREG(buf.st_mode)) {
		mail(name, BADTYPE, ERR_NOTREG);
		cron_unlink(name);
		return (0);
	}
	if (type == ATEVENT) {
		if (!(buf.st_mode & ISUID)) {
			cron_unlink(name);
			return (0);
		}
	}
	return (1);
}

struct usr *
create_ulist(char *name, int type)
{
	struct usr	*u;

	u = xcalloc(1, sizeof (struct usr));
	u->name = xstrdup(name);
	if (type == CRONEVENT) {
		u->ctexists = TRUE;
		u->ctid = ecid++;
	} else {
		u->ctexists = FALSE;
		u->ctid = 0;
	}
	u->uid = (uid_t)-1;
	u->gid = (uid_t)-1;
	u->nextusr = uhead;
	uhead = u;
	return (u);
}

void
init_cronevent(char *name, int first)
{
	struct usr	*u;

	if (first) {
		u = create_ulist(name, CRONEVENT);
		readcron(u, 0);
	} else {
		if ((u = find_usr(name)) == NULL) {
			u = create_ulist(name, CRONEVENT);
			readcron(u, 0);
		} else {
			u->ctexists = TRUE;
			rm_ctevents(u);
			el_remove(u->ctid, 0);
			readcron(u, 0);
		}
	}
}

void
init_atevent(char *name, time_t tim, int jobtype, int first)
{
	struct usr	*u;

	if (first) {
		u = create_ulist(name, ATEVENT);
		add_atevent(u, name, tim, jobtype);
	} else {
		if ((u = find_usr(name)) == NULL) {
			u = create_ulist(name, ATEVENT);
			add_atevent(u, name, tim, jobtype);
		} else {
			update_atevent(u, name, tim, jobtype);
		}
	}
}

static void
mod_ctab(char *name, time_t reftime)
{
	struct	passwd	*pw;
	struct	stat	buf;
	struct	usr	*u;
	char	namebuf[LINE_MAX];
	char	*pname;

	/* skip over ancillary file names */
	if (audit_cron_is_anc_name(name))
		return;

	if ((pw = getpwnam(name)) == NULL) {
		msg("No such user as %s - cron entries not created", name);
		return;
	}
	if (cwd != CRON) {
		if (snprintf(namebuf, sizeof (namebuf), "%s/%s",
		    CRONDIR, name) >= sizeof (namebuf)) {
			msg("Too long path name %s - cron entries not created",
			    namebuf);
			return;
		}
		pname = namebuf;
	} else {
		pname = name;
	}
	/*
	 * a warning message is given by the crontab command so there is
	 * no need to give one here......  use this code if you only want
	 * users with a login shell of /usr/bin/sh to use cron
	 */
#ifdef BOURNESHELLONLY
	if ((strcmp(pw->pw_shell, "") != 0) &&
	    (strcmp(pw->pw_shell, SHELL) != 0)) {
		mail(name, BADSHELL, ERR_CANTEXECCRON);
		cron_unlink(pname);
		return;
	}
#endif
	if (stat(pname, &buf)) {
		mail(name, BADSTAT, ERR_UNIXERR);
		cron_unlink(pname);
		return;
	}
	if (!S_ISREG(buf.st_mode)) {
		mail(name, BADTYPE, ERR_CRONTABENT);
		return;
	}
	if ((u = find_usr(name)) == NULL) {
#ifdef DEBUG
		(void) fprintf(stderr, "new user (%s) with a crontab\n", name);
#endif
		u = create_ulist(name, CRONEVENT);
		u->home = xmalloc(strlen(pw->pw_dir) + 1);
		(void) strcpy(u->home, pw->pw_dir);
		u->uid = pw->pw_uid;
		u->gid = pw->pw_gid;
		readcron(u, reftime);
	} else {
		u->uid = pw->pw_uid;
		u->gid = pw->pw_gid;
		if (u->home != NULL) {
			if (strcmp(u->home, pw->pw_dir) != 0) {
				free(u->home);
				u->home = xmalloc(strlen(pw->pw_dir) + 1);
				(void) strcpy(u->home, pw->pw_dir);
			}
		} else {
			u->home = xmalloc(strlen(pw->pw_dir) + 1);
			(void) strcpy(u->home, pw->pw_dir);
		}
		u->ctexists = TRUE;
		if (u->ctid == 0) {
#ifdef DEBUG
			(void) fprintf(stderr, "%s now has a crontab\n",
			    u->name);
#endif
			/* user didnt have a crontab last time */
			u->ctid = ecid++;
			u->ctevents = NULL;
			readcron(u, reftime);
			return;
		}
#ifdef DEBUG
		(void) fprintf(stderr, "%s has revised his crontab\n", u->name);
#endif
		rm_ctevents(u);
		el_remove(u->ctid, 0);
		readcron(u, reftime);
	}
}

/* ARGSUSED */
static void
mod_atjob(char *name, time_t reftime)
{
	char	*ptr;
	time_t	tim;
	struct	passwd	*pw;
	struct	stat	buf;
	struct	usr	*u;
	char	namebuf[PATH_MAX];
	char	*pname;
	int	jobtype;

	ptr = name;
	if (((tim = num(&ptr)) == 0) || (*ptr != '.'))
		return;
	ptr++;
	if (!isalpha(*ptr))
		return;
	jobtype = *ptr - 'a';

	/* check for audit ancillary file */
	if (audit_cron_is_anc_name(name))
		return;

	if (cwd != AT) {
		if (snprintf(namebuf, sizeof (namebuf), "%s/%s", ATDIR, name)
		    >= sizeof (namebuf)) {
			return;
		}
		pname = namebuf;
	} else {
		pname = name;
	}
	if (stat(pname, &buf) || jobtype >= NQUEUE) {
		cron_unlink(pname);
		return;
	}
	if (!(buf.st_mode & ISUID) || !S_ISREG(buf.st_mode)) {
		cron_unlink(pname);
		return;
	}
	if ((pw = getpwuid(buf.st_uid)) == NULL) {
		cron_unlink(pname);
		return;
	}
	/*
	 * a warning message is given by the at command so there is no
	 * need to give one here......use this code if you only want
	 * users with a login shell of /usr/bin/sh to use cron
	 */
#ifdef BOURNESHELLONLY
	if ((strcmp(pw->pw_shell, "") != 0) &&
	    (strcmp(pw->pw_shell, SHELL) != 0)) {
		mail(pw->pw_name, BADSHELL, ERR_CANTEXECAT);
		cron_unlink(pname);
		return;
	}
#endif
	if ((u = find_usr(pw->pw_name)) == NULL) {
#ifdef DEBUG
		(void) fprintf(stderr, "new user (%s) with an at job = %s\n",
		    pw->pw_name, name);
#endif
		u = create_ulist(pw->pw_name, ATEVENT);
		u->home = xstrdup(pw->pw_dir);
		u->uid = pw->pw_uid;
		u->gid = pw->pw_gid;
		add_atevent(u, name, tim, jobtype);
	} else {
		u->uid = pw->pw_uid;
		u->gid = pw->pw_gid;
		free(u->home);
		u->home = xstrdup(pw->pw_dir);
		update_atevent(u, name, tim, jobtype);
	}
}

static void
add_atevent(struct usr *u, char *job, time_t tim, int jobtype)
{
	struct event *e;

	e = xmalloc(sizeof (struct event));
	e->etype = jobtype;
	e->cmd = xmalloc(strlen(job) + 1);
	(void) strcpy(e->cmd, job);
	e->u = u;
	e->link = u->atevents;
	u->atevents = e;
	e->of.at.exists = TRUE;
	e->of.at.eventid = ecid++;
	if (tim < init_time)	/* old job */
		e->time = init_time;
	else
		e->time = tim;
#ifdef DEBUG
	(void) fprintf(stderr, "add_atevent: user=%s, job=%s, time=%ld\n",
	    u->name, e->cmd, e->time);
#endif
	if (el_add(e, e->time, e->of.at.eventid) < 0) {
		ignore_msg("add_atevent", "at", e);
	}
}

void
update_atevent(struct usr *u, char *name, time_t tim, int jobtype)
{
	struct event *e;

	e = u->atevents;
	while (e != NULL) {
		if (strcmp(e->cmd, name) == 0) {
			e->of.at.exists = TRUE;
			break;
		} else {
			e = e->link;
		}
	}
	if (e == NULL) {
#ifdef DEBUG
		(void) fprintf(stderr, "%s has a new at job = %s\n",
		    u->name, name);
#endif
			add_atevent(u, name, tim, jobtype);
	}
}

static char line[CTLINESIZE];	/* holds a line from a crontab file */
static int cursor;		/* cursor for the above line */

static void
readcron(struct usr *u, time_t reftime)
{
	/*
	 * readcron reads in a crontab file for a user (u). The list of
	 * events for user u is built, and u->events is made to point to
	 * this list. Each event is also entered into the main event
	 * list.
	 */
	FILE *cf;	/* cf will be a user's crontab file */
	struct event *e;
	int start;
	unsigned int i;
	char namebuf[PATH_MAX];
	char *pname;
	struct shared *tz = NULL;
	struct shared *home = NULL;
	struct shared *shell = NULL;
	int lineno = 0;

	/* read the crontab file */
	cte_init();		/* Init error handling */
	if (cwd != CRON) {
		if (snprintf(namebuf, sizeof (namebuf), "%s/%s",
		    CRONDIR, u->name) >= sizeof (namebuf)) {
			return;
		}
		pname = namebuf;
	} else {
		pname = u->name;
	}
	if ((cf = fopen(pname, "r")) == NULL) {
		mail(u->name, NOREAD, ERR_UNIXERR);
		return;
	}
	while (fgets(line, CTLINESIZE, cf) != NULL) {
		char *tmp;
		/* process a line of a crontab file */
		lineno++;
		if (cte_istoomany())
			break;
		cursor = 0;
		while (line[cursor] == ' ' || line[cursor] == '\t')
			cursor++;
		if (line[cursor] == '#' || line[cursor] == '\n')
			continue;

		if (strncmp(&line[cursor], ENV_TZ,
		    strlen(ENV_TZ)) == 0) {
			if ((tmp = strchr(&line[cursor], '\n')) != NULL) {
				*tmp = NULL;
			}

			if (!isvalid_tz(&line[cursor + strlen(ENV_TZ)], NULL,
			    _VTZ_ALL)) {
				cte_add(lineno, line);
				break;
			}
			if (tz == NULL || strcmp(&line[cursor], get_obj(tz))) {
				rel_shared(tz);
				tz = create_shared_str(&line[cursor]);
			}
			continue;
		}

		if (strncmp(&line[cursor], ENV_HOME,
		    strlen(ENV_HOME)) == 0) {
			if ((tmp = strchr(&line[cursor], '\n')) != NULL) {
				*tmp = NULL;
			}
			if (home == NULL ||
			    strcmp(&line[cursor], get_obj(home))) {
				rel_shared(home);
				home = create_shared_str(
				    &line[cursor + strlen(ENV_HOME)]);
			}
			continue;
		}

		if (strncmp(&line[cursor], ENV_SHELL,
		    strlen(ENV_SHELL)) == 0) {
			if ((tmp = strchr(&line[cursor], '\n')) != NULL) {
				*tmp = NULL;
			}
			if (shell == NULL ||
			    strcmp(&line[cursor], get_obj(shell))) {
				rel_shared(shell);
				shell = create_shared_str(&line[cursor]);
			}
			continue;
		}

		e = xmalloc(sizeof (struct event));
		e->etype = CRONEVENT;
		if (!(((e->of.ct.minute = next_field(0, 59)) != NULL) &&
		    ((e->of.ct.hour = next_field(0, 23)) != NULL) &&
		    ((e->of.ct.daymon = next_field(1, 31)) != NULL) &&
		    ((e->of.ct.month = next_field(1, 12)) != NULL) &&
		    ((e->of.ct.dayweek = next_field(0, 6)) != NULL))) {
			free(e);
			cte_add(lineno, line);
			continue;
		}
		while (line[cursor] == ' ' || line[cursor] == '\t')
			cursor++;
		if (line[cursor] == '\n' || line[cursor] == '\0')
			continue;
		/* get the command to execute	*/
		start = cursor;
again:
		while ((line[cursor] != '%') &&
		    (line[cursor] != '\n') &&
		    (line[cursor] != '\0') &&
		    (line[cursor] != '\\'))
			cursor++;
		if (line[cursor] == '\\') {
			cursor += 2;
			goto again;
		}
		e->cmd = xmalloc(cursor-start + 1);
		(void) strncpy(e->cmd, line + start, cursor-start);
		e->cmd[cursor-start] = '\0';
		/* see if there is any standard input	*/
		if (line[cursor] == '%') {
			e->of.ct.input = xmalloc(strlen(line)-cursor + 1);
			(void) strcpy(e->of.ct.input, line + cursor + 1);
			for (i = 0; i < strlen(e->of.ct.input); i++) {
				if (e->of.ct.input[i] == '%')
					e->of.ct.input[i] = '\n';
			}
		} else {
			e->of.ct.input = NULL;
		}
		/* set the timezone of this entry */
		e->of.ct.tz = dup_shared(tz);
		/* set the shell of this entry */
		e->of.ct.shell = dup_shared(shell);
		/* set the home of this entry */
		e->of.ct.home = dup_shared(home);
		/* have the event point to it's owner	*/
		e->u = u;
		/* insert this event at the front of this user's event list */
		e->link = u->ctevents;
		u->ctevents = e;
		/* set the time for the first occurance of this event	*/
		e->time = next_time(e, reftime);
		/* finally, add this event to the main event list	*/
		switch (el_add(e, e->time, u->ctid)) {
		case -1:
			ignore_msg("readcron", "cron", e);
			break;
		case -2: /* event time lower than init time */
			reset_needed = 1;
			break;
		}
		cte_valid();
#ifdef DEBUG
		cftime(timebuf, "%C", &e->time);
		(void) fprintf(stderr, "inserting cron event %s at %ld (%s)\n",
		    e->cmd, e->time, timebuf);
#endif
	}
	cte_sendmail(u->name);	/* mail errors if any to user */
	(void) fclose(cf);
	rel_shared(tz);
	rel_shared(shell);
	rel_shared(home);
}

/*
 * Below are the functions for handling of errors in crontabs. Concept is to
 * collect faulty lines and send one email at the end of the crontab
 * evaluation. If there are erroneous lines only ((cte_nvalid == 0), evaluation
 * of crontab is aborted. Otherwise reading of crontab is continued to the end
 * of the file but no further error logging appears.
 */
static void
cte_init()
{
	if (cte_text == NULL)
		cte_text = xmalloc(MAILBUFLEN);
	(void) strlcpy(cte_text, cte_intro, MAILBUFLEN);
	cte_lp = cte_text + sizeof (cte_intro) - 1;
	cte_free = MAILBINITFREE;
	cte_nvalid = 0;
}

static void
cte_add(int lineno, char *ctline)
{
	int len;
	char *p;

	if (cte_free >= LINELIMIT) {
		(void) sprintf(cte_lp, "%4d: ", lineno);
		(void) strlcat(cte_lp, ctline, LINELIMIT - 1);
		len = strlen(cte_lp);
		if (cte_lp[len - 1] != '\n') {
			cte_lp[len++] = '\n';
			cte_lp[len] = '\0';
		}
		for (p = cte_lp; *p; p++) {
			if (isprint(*p) || *p == '\n' || *p == '\t')
				continue;
			*p = '.';
		}
		cte_lp += len;
		cte_free -= len;
		if (cte_free < LINELIMIT) {
			size_t buflen = MAILBUFLEN - (cte_lp - cte_text);
			(void) strlcpy(cte_lp, cte_trail1, buflen);
			if (cte_nvalid == 0)
				(void) strlcat(cte_lp, cte_trail2, buflen);
		}
	}
}

static void
cte_valid()
{
	cte_nvalid++;
}

static int
cte_istoomany()
{
	/*
	 * Return TRUE only if all lines are faulty. So evaluation of
	 * a crontab is not aborted if at least one valid line was found.
	 */
	return (cte_nvalid == 0 && cte_free < LINELIMIT);
}

static void
cte_sendmail(char *username)
{
	if (cte_free < MAILBINITFREE)
		mail(username, cte_text, ERR_CRONTABENT);
}

/*
 * Send mail with error message to a user
 */
static void
mail(char *usrname, char *mesg, int format)
{
	/* mail mails a user a message.	*/
	FILE *pipe;
	char *temp;
	struct passwd	*ruser_ids;
	pid_t fork_val;
	int saveerrno = errno;
	struct utsname	name;

#ifdef TESTING
	return;
#endif
	(void) uname(&name);
	if ((fork_val = fork()) == (pid_t)-1) {
		msg("cron cannot fork\n");
		return;
	}
	if (fork_val == 0) {
		child_sigreset();
		contract_clear_template();
		if ((ruser_ids = getpwnam(usrname)) == NULL)
			exit(0);
		(void) setuid(ruser_ids->pw_uid);
		temp = xmalloc(strlen(MAIL) + strlen(usrname) + 2);
		(void) sprintf(temp, "%s %s", MAIL, usrname);
		pipe = popen(temp, "w");
		if (pipe != NULL) {
			(void) fprintf(pipe, "To: %s\n", usrname);
			switch (format) {
			case ERR_CRONTABENT:
				(void) fprintf(pipe, CRONTABERR);
				(void) fprintf(pipe, "Your \"crontab\" on %s\n",
				    name.nodename);
				(void) fprintf(pipe, mesg);
				(void) fprintf(pipe,
				    "\nEntries or crontab have been ignored\n");
				break;
			case ERR_UNIXERR:
				(void) fprintf(pipe, "Subject: %s\n\n", mesg);
				(void) fprintf(pipe,
				    "The error on %s was \"%s\"\n",
				    name.nodename, errmsg(saveerrno));
				break;

			case ERR_CANTEXECCRON:
				(void) fprintf(pipe,
				"Subject: Couldn't run your \"cron\" job\n\n");
				(void) fprintf(pipe,
				    "Your \"cron\" job on %s ", name.nodename);
				(void) fprintf(pipe, "couldn't be run\n");
				(void) fprintf(pipe, "%s\n", mesg);
				(void) fprintf(pipe,
				"The error was \"%s\"\n", errmsg(saveerrno));
				break;

			case ERR_CANTEXECAT:
				(void) fprintf(pipe,
				"Subject: Couldn't run your \"at\" job\n\n");
				(void) fprintf(pipe, "Your \"at\" job on %s ",
				    name.nodename);
				(void) fprintf(pipe, "couldn't be run\n");
				(void) fprintf(pipe, "%s\n", mesg);
				(void) fprintf(pipe,
				"The error was \"%s\"\n", errmsg(saveerrno));
				break;

			default:
				break;
			}
			(void) pclose(pipe);
		}
		free(temp);
		exit(0);
	}

	contract_abandon_latest(fork_val);

	if (cron_pid == getpid()) {
		miscpid_insert(fork_val);
	}
}

static char *
next_field(int lower, int upper)
{
	/*
	 * next_field returns a pointer to a string which holds the next
	 * field of a line of a crontab file.
	 *   if (numbers in this field are out of range (lower..upper),
	 *	or there is a syntax error) then
	 *	NULL is returned, and a mail message is sent to the
	 *	user telling him which line the error was in.
	 */

	char *s;
	int num, num2, start;

	while ((line[cursor] == ' ') || (line[cursor] == '\t'))
		cursor++;
	start = cursor;
	if (line[cursor] == '\0') {
		return (NULL);
	}
	if (line[cursor] == '*') {
		cursor++;
		if ((line[cursor] != ' ') && (line[cursor] != '\t'))
			return (NULL);
		s = xmalloc(2);
		(void) strcpy(s, "*");
		return (s);
	}
	for (;;) {
		if (!isdigit(line[cursor]))
			return (NULL);
		num = 0;
		do {
			num = num*10 + (line[cursor]-'0');
		} while (isdigit(line[++cursor]));
		if ((num < lower) || (num > upper))
			return (NULL);
		if (line[cursor] == '-') {
			if (!isdigit(line[++cursor]))
				return (NULL);
			num2 = 0;
			do {
				num2 = num2*10 + (line[cursor]-'0');
			} while (isdigit(line[++cursor]));
			if ((num2 < lower) || (num2 > upper))
				return (NULL);
		}
		if ((line[cursor] == ' ') || (line[cursor] == '\t'))
			break;
		if (line[cursor] == '\0')
			return (NULL);
		if (line[cursor++] != ',')
			return (NULL);
	}
	s = xmalloc(cursor-start + 1);
	(void) strncpy(s, line + start, cursor-start);
	s[cursor-start] = '\0';
	return (s);
}

#define	tm_cmp(t1, t2) (\
	(t1)->tm_year == (t2)->tm_year && \
	(t1)->tm_mon == (t2)->tm_mon && \
	(t1)->tm_mday == (t2)->tm_mday && \
	(t1)->tm_hour == (t2)->tm_hour && \
	(t1)->tm_min == (t2)->tm_min)

#define	tm_setup(tp, yr, mon, dy, hr, min, dst) \
	(tp)->tm_year = yr; \
	(tp)->tm_mon = mon; \
	(tp)->tm_mday = dy; \
	(tp)->tm_hour = hr; \
	(tp)->tm_min = min; \
	(tp)->tm_isdst = dst; \
	(tp)->tm_sec = 0; \
	(tp)->tm_wday = 0; \
	(tp)->tm_yday = 0;

/*
 * modification for bugid 1104537. the second argument to next_time is
 * now the value of time(2) to be used. if this is 0, then use the
 * current time. otherwise, the second argument is the time from which to
 * calculate things. this is useful to correct situations where you've
 * gone backwards in time (I.e. the system's internal clock is correcting
 * itself backwards).
 */



static time_t
tz_next_time(struct event *e, time_t tflag)
{
	/*
	 * returns the integer time for the next occurance of event e.
	 * the following fields have ranges as indicated:
	 * PRGM  | min	hour	day of month	mon	day of week
	 * ------|-------------------------------------------------------
	 * cron  | 0-59	0-23	    1-31	1-12	0-6 (0=sunday)
	 * time  | 0-59	0-23	    1-31	0-11	0-6 (0=sunday)
	 * NOTE: this routine is hard to understand.
	 */

	struct tm *tm, ref_tm, tmp, tmp1, tmp2;
	int tm_mon, tm_mday, tm_wday, wday, m, min, h, hr, carry, day, days;
	int d1, day1, carry1, d2, day2, carry2, daysahead, mon, yr, db, wd;
	int today;
	time_t t, ref_t, t1, t2, zone_start;
	int fallback;
	extern int days_btwn(int, int, int, int, int, int);

	if (tflag == 0) {
		t = time(NULL);	/* original way of doing things	*/
	} else {
		t =  tflag;
	}

	tm = &ref_tm;	/* use a local variable and call localtime_r() */
	ref_t = t;	/* keep a copy of the reference time */

recalc:
	fallback = 0;

	(void) localtime_r(&t, tm);

	if (daylight) {
		tmp = *tm;
		tmp.tm_isdst = (tm->tm_isdst > 0 ? 0 : 1);
		t1 = xmktime(&tmp);
		/*
		 * see if we will have timezone switch over, and clock will
		 * fall back. zone_start will hold the time when it happens
		 * (ie time of PST -> PDT switch over).
		 */
		if (tm->tm_isdst != tmp.tm_isdst &&
		    (t1 - t) == (timezone - altzone) &&
		    tm_cmp(tm, &tmp)) {
			zone_start = get_switching_time(tmp.tm_isdst, t);
			fallback = 1;
		}
	}

	tm_mon = next_ge(tm->tm_mon + 1, e->of.ct.month) - 1;	/* 0-11 */
	tm_mday = next_ge(tm->tm_mday, e->of.ct.daymon);	/* 1-31 */
	tm_wday = next_ge(tm->tm_wday, e->of.ct.dayweek);	/* 0-6	*/
	today = TRUE;
	if ((strcmp(e->of.ct.daymon, "*") == 0 && tm->tm_wday != tm_wday) ||
	    (strcmp(e->of.ct.dayweek, "*") == 0 && tm->tm_mday != tm_mday) ||
	    (tm->tm_mday != tm_mday && tm->tm_wday != tm_wday) ||
	    (tm->tm_mon != tm_mon)) {
		today = FALSE;
	}
	m = tm->tm_min + (t == ref_t ? 1 : 0);
	if ((tm->tm_hour + 1) <= next_ge(tm->tm_hour, e->of.ct.hour)) {
		m = 0;
	}
	min = next_ge(m%60, e->of.ct.minute);
	carry = (min < m) ? 1 : 0;
	h = tm->tm_hour + carry;
	hr = next_ge(h%24, e->of.ct.hour);
	carry = (hr < h) ? 1 : 0;

	if (carry == 0 && today) {
		/* this event must occur today */
		tm_setup(&tmp, tm->tm_year, tm->tm_mon, tm->tm_mday,
		    hr, min, tm->tm_isdst);
		tmp1 = tmp;
		if ((t1 = xmktime(&tmp1)) == (time_t)-1) {
			return (0);
		}
		if (daylight && tmp.tm_isdst != tmp1.tm_isdst) {
			/* In case we are falling back */
			if (fallback) {
				/* we may need to run the job once more. */
				t = zone_start;
				goto recalc;
			}

			/*
			 * In case we are not in falling back period,
			 * calculate the time assuming the DST. If the
			 * date/time is not altered by mktime, it is the
			 * time to execute the job.
			 */
			tmp2 = tmp;
			tmp2.tm_isdst = tmp1.tm_isdst;
			if ((t1 = xmktime(&tmp2)) == (time_t)-1) {
				return (0);
			}
			if (tmp1.tm_isdst == tmp2.tm_isdst &&
			    tm_cmp(&tmp, &tmp2)) {
				/*
				 * We got a valid time.
				 */
				return (t1);
			} else {
				/*
				 * If the date does not match even if
				 * we assume the alternate timezone, then
				 * it must be the invalid time. eg
				 * 2am while switching 1:59am to 3am.
				 * t1 should point the time before the
				 * switching over as we've calculate the
				 * time with assuming alternate zone.
				 */
				if (tmp1.tm_isdst != tmp2.tm_isdst) {
					t = get_switching_time(tmp1.tm_isdst,
					    t1);
				} else {
					/* does this really happen? */
					t = get_switching_time(tmp1.tm_isdst,
					    t1 - abs(timezone - altzone));
				}
				if (t == (time_t)-1) {
					return (0);
				}
			}
			goto recalc;
		}
		if (tm_cmp(&tmp, &tmp1)) {
			/* got valid time */
			return (t1);
		} else {
			/*
			 * This should never happen, but just in
			 * case, we fall back to the old code.
			 */
			if (tm->tm_min > min) {
				t += (time_t)(hr-tm->tm_hour-1) * HOUR +
				    (time_t)(60-tm->tm_min + min) * MINUTE;
			} else {
				t += (time_t)(hr-tm->tm_hour) * HOUR +
				    (time_t)(min-tm->tm_min) * MINUTE;
			}
			t1 = t;
			t -= (time_t)tm->tm_sec;
			(void) localtime_r(&t, &tmp);
			if ((tm->tm_isdst == 0) && (tmp.tm_isdst > 0))
				t -= (timezone - altzone);
			return ((t <= ref_t) ? t1 : t);
		}
	}

	/*
	 * Job won't run today, however if we have a switch over within
	 * one hour and we will have one hour time drifting back in this
	 * period, we may need to run the job one more time if the job was
	 * set to run on this hour of clock.
	 */
	if (fallback) {
		t = zone_start;
		goto recalc;
	}

	min = next_ge(0, e->of.ct.minute);
	hr = next_ge(0, e->of.ct.hour);

	/*
	 * calculate the date of the next occurance of this event, which
	 * will be on a different day than the current
	 */

	/* check monthly day specification	*/
	d1 = tm->tm_mday + 1;
	day1 = next_ge((d1-1)%days_in_mon(tm->tm_mon, tm->tm_year) + 1,
	    e->of.ct.daymon);
	carry1 = (day1 < d1) ? 1 : 0;

	/* check weekly day specification	*/
	d2 = tm->tm_wday + 1;
	wday = next_ge(d2%7, e->of.ct.dayweek);
	if (wday < d2)
		daysahead = 7 - d2 + wday;
	else
		daysahead = wday - d2;
	day2 = (d1 + daysahead-1)%days_in_mon(tm->tm_mon, tm->tm_year) + 1;
	carry2 = (day2 < d1) ? 1 : 0;

	/*
	 *	based on their respective specifications, day1, and day2 give
	 *	the day of the month for the next occurance of this event.
	 */
	if ((strcmp(e->of.ct.daymon, "*") == 0) &&
	    (strcmp(e->of.ct.dayweek, "*") != 0)) {
		day1 = day2;
		carry1 = carry2;
	}
	if ((strcmp(e->of.ct.daymon, "*") != 0) &&
	    (strcmp(e->of.ct.dayweek, "*") == 0)) {
		day2 = day1;
		carry2 = carry1;
	}

	yr = tm->tm_year;
	if ((carry1 && carry2) || (tm->tm_mon != tm_mon)) {
		/* event does not occur in this month	*/
		m = tm->tm_mon + 1;
		mon = next_ge(m%12 + 1, e->of.ct.month) - 1;	/* 0..11 */
		carry = (mon < m) ? 1 : 0;
		yr += carry;
		/* recompute day1 and day2	*/
		day1 = next_ge(1, e->of.ct.daymon);
		db = days_btwn(tm->tm_mon, tm->tm_mday, tm->tm_year, mon,
		    1, yr) + 1;
		wd = (tm->tm_wday + db)%7;
		/* wd is the day of the week of the first of month mon	*/
		wday = next_ge(wd, e->of.ct.dayweek);
		if (wday < wd)
			day2 = 1 + 7 - wd + wday;
		else
			day2 = 1 + wday - wd;
		if ((strcmp(e->of.ct.daymon, "*") != 0) &&
		    (strcmp(e->of.ct.dayweek, "*") == 0))
			day2 = day1;
		if ((strcmp(e->of.ct.daymon, "*") == 0) &&
		    (strcmp(e->of.ct.dayweek, "*") != 0))
			day1 = day2;
		day = (day1 < day2) ? day1 : day2;
	} else {			/* event occurs in this month	*/
		mon = tm->tm_mon;
		if (!carry1 && !carry2)
			day = (day1 < day2) ? day1 : day2;
		else if (!carry1)
			day = day1;
		else
			day = day2;
	}

	/*
	 * now that we have the min, hr, day, mon, yr of the next event,
	 * figure out what time that turns out to be.
	 */
	tm_setup(&tmp, yr, mon, day, hr, min, -1);
	tmp2 = tmp;
	if ((t1 = xmktime(&tmp2)) == (time_t)-1) {
		return (0);
	}
	if (tm_cmp(&tmp, &tmp2)) {
		/*
		 * mktime returns clock for the current time zone. If the
		 * target date was in fallback period, it needs to be adjusted
		 * to the time comes first.
		 * Suppose, we are at Jan and scheduling job at 1:30am10/26/03.
		 * mktime returns the time in PST, but 1:30am in PDT comes
		 * first. So reverse the tm_isdst, and see if we have such
		 * time/date.
		 */
		if (daylight) {
			int dst = tmp2.tm_isdst;

			tmp2 = tmp;
			tmp2.tm_isdst = (dst > 0 ? 0 : 1);
			if ((t2 = xmktime(&tmp2)) == (time_t)-1) {
				return (0);
			}
			if (tm_cmp(&tmp, &tmp2)) {
				/*
				 * same time/date found in the opposite zone.
				 * check the clock to see which comes early.
				 */
				if (t2 > ref_t && t2 < t1) {
					t1 = t2;
				}
			}
		}
		return (t1);
	} else {
		/*
		 * mktime has set different time/date for the given date.
		 * This means that the next job is scheduled to be run on the
		 * invalid time. There are three possible invalid date/time.
		 * 1. Non existing day of the month. such as April 31th.
		 * 2. Feb 29th in the non-leap year.
		 * 3. Time gap during the DST switch over.
		 */
		d1 = days_in_mon(mon, yr);
		if ((mon != 1 && day > d1) || (mon == 1 && day > 29)) {
			/*
			 * see if we have got a specific date which
			 * is invalid.
			 */
			if (strcmp(e->of.ct.dayweek, "*") == 0 &&
			    mon == (next_ge((mon + 1)%12 + 1,
			    e->of.ct.month) - 1) &&
			    day <= next_ge(1, e->of.ct.daymon)) {
				/* job never run */
				return (0);
			}
			/*
			 * Since the day has gone invalid, we need to go to
			 * next month, and recalcuate the first occurrence.
			 * eg the cron tab such as:
			 * 0 0 1,15,31 1,2,3,4,5 * /usr/bin....
			 * 2/31 is invalid, so the next job is 3/1.
			 */
			tmp2 = tmp;
			tmp2.tm_min = 0;
			tmp2.tm_hour = 0;
			tmp2.tm_mday = 1; /* 1st day of the month */
			if (mon == 11) {
				tmp2.tm_mon = 0;
				tmp2.tm_year = yr + 1;
			} else {
				tmp2.tm_mon = mon + 1;
			}
			if ((t = xmktime(&tmp2)) == (time_t)-1) {
				return (0);
			}
		} else if (mon == 1 && day > d1) {
			/*
			 * ie 29th in the non-leap year. Forwarding the
			 * clock to Feb 29th 00:00 (March 1st), and recalculate
			 * the next time.
			 */
			tmp2 = tmp;
			tmp2.tm_min = 0;
			tmp2.tm_hour = 0;
			if ((t = xmktime(&tmp2)) == (time_t)-1) {
				return (0);
			}
		} else if (daylight) {
			/*
			 * Non existing time, eg 2am PST during summer time
			 * switch.
			 * We need to get the correct isdst which we are
			 * swithing to, by adding time difference to make sure
			 * that t2 is in the zone being switched.
			 */
			t2 = t1;
			t2 += abs(timezone - altzone);
			(void) localtime_r(&t2, &tmp2);
			zone_start = get_switching_time(tmp2.tm_isdst,
			    t1 - abs(timezone - altzone));
			if (zone_start == (time_t)-1) {
				return (0);
			}
			t = zone_start;
		} else {
			/*
			 * This should never happen, but fall back to the
			 * old code.
			 */
			days = days_btwn(tm->tm_mon,
			    tm->tm_mday, tm->tm_year, mon, day, yr);
			t += (time_t)(23-tm->tm_hour)*HOUR
			    + (time_t)(60-tm->tm_min)*MINUTE
			    + (time_t)hr*HOUR + (time_t)min*MINUTE
			    + (time_t)days*DAY;
			t1 = t;
			t -= (time_t)tm->tm_sec;
			(void) localtime_r(&t, &tmp);
			if ((tm->tm_isdst == 0) && (tmp.tm_isdst > 0))
				t -= (timezone - altzone);
			return (t <= ref_t ? t1 : t);
		}
		goto recalc;
	}
	/*NOTREACHED*/
}

static time_t
next_time(struct event *e, time_t tflag)
{
	if (e->of.ct.tz != NULL) {
		time_t ret;

		(void) putenv((char *)get_obj(e->of.ct.tz));
		tzset();
		ret = tz_next_time(e, tflag);
		(void) putenv(tzone);
		tzset();
		return (ret);
	} else {
		return (tz_next_time(e, tflag));
	}
}

/*
 * This returns TOD in time_t that zone switch will happen, and this
 * will be called when clock fallback is about to happen.
 * (ie 30minutes before the time of PST -> PDT switch. 2:00 AM PST
 * will fall back to 1:00 PDT. So this function will be called only
 * for the time between 1:00 AM PST and 2:00 PST(1:00 PST)).
 * First goes through the common time differences to see if zone
 * switch happens at those minutes later. If not, check every minutes
 * until 6 hours ahead see if it happens(We might have 45minutes
 * fallback).
 */
static time_t
get_switching_time(int to_dst, time_t t_ref)
{
	time_t t, t1;
	struct tm tmp, tmp1;
	int hints[] = { 60, 120, 30, 90, 0}; /* minutes */
	int i;

	(void) localtime_r(&t_ref, &tmp);
	tmp1 = tmp;
	tmp1.tm_sec = 0;
	tmp1.tm_min = 0;
	if ((t = xmktime(&tmp1)) == (time_t)-1)
		return ((time_t)-1);

	/* fast path */
	for (i = 0; hints[i] != 0; i++) {
		t1 = t + hints[i] * 60;
		(void) localtime_r(&t1, &tmp1);
		if (tmp1.tm_isdst == to_dst) {
			t1--;
			(void) localtime_r(&t1, &tmp1);
			if (tmp1.tm_isdst != to_dst) {
				return (t1 + 1);
			}
		}
	}

	/* ugly, but don't know other than this. */
	tmp1 = tmp;
	tmp1.tm_sec = 0;
	if ((t = xmktime(&tmp1)) == (time_t)-1)
		return ((time_t)-1);
	while (t < (t_ref + 6*60*60)) { /* 6 hours should be enough */
		t += 60; /* at least one minute, I assume */
		(void) localtime_r(&t, &tmp);
		if (tmp.tm_isdst == to_dst)
			return (t);
	}
	return ((time_t)-1);
}

static time_t
xmktime(struct tm *tmp)
{
	time_t ret;

	if ((ret = mktime(tmp)) == (time_t)-1) {
		if (errno == EOVERFLOW) {
			return ((time_t)-1);
		}
		crabort("internal error: mktime failed",
		    REMOVE_FIFO|CONSOLE_MSG);
	}
	return (ret);
}

#define	DUMMY	100

static int
next_ge(int current, char *list)
{
	/*
	 * list is a character field as in a crontab file;
	 * for example: "40, 20, 50-10"
	 * next_ge returns the next number in the list that is
	 * greater than  or equal to current. if no numbers of list
	 * are >= current, the smallest element of list is returned.
	 * NOTE: current must be in the appropriate range.
	 */

	char *ptr;
	int n, n2, min, min_gt;

	if (strcmp(list, "*") == 0)
		return (current);
	ptr = list;
	min = DUMMY;
	min_gt = DUMMY;
	for (;;) {
		if ((n = (int)num(&ptr)) == current)
			return (current);
		if (n < min)
			min = n;
		if ((n > current) && (n < min_gt))
			min_gt = n;
		if (*ptr == '-') {
			ptr++;
			if ((n2 = (int)num(&ptr)) > n) {
				if ((current > n) && (current <= n2))
					return (current);
			} else {	/* range that wraps around */
				if (current > n)
					return (current);
				if (current <= n2)
					return (current);
			}
		}
		if (*ptr == '\0')
			break;
		ptr += 1;
	}
	if (min_gt != DUMMY)
		return (min_gt);
	else
		return (min);
}

static void
free_if_unused(struct usr *u)
{
	struct usr *cur, *prev;
	/*
	 *	To make sure a usr structure is idle we must check that
	 *	there are no at jobs queued for the user; the user does
	 *	not have a crontab, and also that there are no running at
	 *	or cron jobs (since the runinfo structure also has a
	 *	pointer to the usr structure).
	 */
	if (!u->ctexists && u->atevents == NULL &&
	    u->cruncnt == 0 && u->aruncnt == 0) {
#ifdef DEBUG
		(void) fprintf(stderr, "%s removed from usr list\n", u->name);
#endif
		for (cur = uhead, prev = NULL;
		    cur != u;
		    prev = cur, cur = cur->nextusr) {
			if (cur == NULL) {
				return;
			}
		}

		if (prev == NULL)
			uhead = u->nextusr;
		else
			prev->nextusr = u->nextusr;
		free(u->name);
		free(u->home);
		free(u);
	}
}

static void
del_atjob(char *name, char *usrname)
{

	struct	event	*e, *eprev;
	struct	usr	*u;

	if ((u = find_usr(usrname)) == NULL)
		return;
	e = u->atevents;
	eprev = NULL;
	while (e != NULL) {
		if (strcmp(name, e->cmd) == 0) {
			if (next_event == e)
				next_event = NULL;
			if (eprev == NULL)
				u->atevents = e->link;
			else
				eprev->link = e->link;
			el_remove(e->of.at.eventid, 1);
			free(e->cmd);
			free(e);
			break;
		} else {
			eprev = e;
			e = e->link;
		}
	}

	free_if_unused(u);
}

static void
del_ctab(char *name)
{

	struct	usr *u;

	if ((u = find_usr(name)) == NULL)
		return;
	rm_ctevents(u);
	el_remove(u->ctid, 0);
	u->ctid = 0;
	u->ctexists = 0;

	free_if_unused(u);
}

static void
rm_ctevents(struct usr *u)
{
	struct event *e2, *e3;

	/*
	 * see if the next event (to be run by cron) is a cronevent
	 * owned by this user.
	 */

	if ((next_event != NULL) &&
	    (next_event->etype == CRONEVENT) &&
	    (next_event->u == u)) {
		next_event = NULL;
	}
	e2 = u->ctevents;
	while (e2 != NULL) {
		free(e2->cmd);
		rel_shared(e2->of.ct.tz);
		rel_shared(e2->of.ct.shell);
		rel_shared(e2->of.ct.home);
		free(e2->of.ct.minute);
		free(e2->of.ct.hour);
		free(e2->of.ct.daymon);
		free(e2->of.ct.month);
		free(e2->of.ct.dayweek);
		if (e2->of.ct.input != NULL)
			free(e2->of.ct.input);
		e3 = e2->link;
		free(e2);
		e2 = e3;
	}
	u->ctevents = NULL;
}


static struct usr *
find_usr(char *uname)
{
	struct usr *u;

	u = uhead;
	while (u != NULL) {
		if (strcmp(u->name, uname) == 0)
			return (u);
		u = u->nextusr;
	}
	return (NULL);
}

/*
 * Execute cron command or at/batch job.
 * If ever a premature return is added to this function pay attention to
 * free at_cmdfile and outfile plus jobname buffers of the runinfo structure.
 */
static int
ex(struct event *e)
{
	int r;
	int fd;
	pid_t rfork;
	FILE *atcmdfp;
	char mailvar[4];
	char *at_cmdfile = NULL;
	struct stat buf;
	struct queue *qp;
	struct runinfo *rp;
	struct project proj, *pproj = NULL;
	union {
		struct {
			char buf[PROJECT_BUFSZ];
			char buf2[PROJECT_BUFSZ];
		} p;
		char error[CANT_STR_LEN + PATH_MAX];
	} bufs;
	char *tmpfile;
	FILE *fptr;
	time_t dhltime;
	projid_t projid;
	int projflag = 0;
	char *home;
	char *sh;

	qp = &qt[e->etype];	/* set pointer to queue defs */
	if (qp->nrun >= qp->njob) {
		msg("%c queue max run limit reached", e->etype + 'a');
		resched(qp->nwait);
		return (0);
	}

	rp = rinfo_get(0); /* allocating a new runinfo struct */

	/*
	 * the tempnam() function uses malloc(3C) to allocate space for the
	 * constructed file name, and returns a pointer to this area, which
	 * is assigned to rp->outfile. Here rp->outfile is not overwritten.
	 */

	rp->outfile = tempnam(TMPDIR, PFX);
	rp->jobtype = e->etype;
	if (e->etype == CRONEVENT) {
		rp->jobname = xmalloc(strlen(e->cmd) + 1);
		(void) strcpy(rp->jobname, e->cmd);
		/* "cron" jobs only produce mail if there's output */
		rp->mailwhendone = 0;
	} else {
		at_cmdfile = xmalloc(strlen(ATDIR) + strlen(e->cmd) + 2);
		(void) sprintf(at_cmdfile, "%s/%s", ATDIR, e->cmd);
		if ((atcmdfp = fopen(at_cmdfile, "r")) == NULL) {
			if (errno == ENAMETOOLONG) {
				if (chdir(ATDIR) == 0)
					cron_unlink(e->cmd);
			} else {
				cron_unlink(at_cmdfile);
			}
			mail((e->u)->name, BADJOBOPEN, ERR_CANTEXECAT);
			free(at_cmdfile);
			rinfo_free(rp);
			return (0);
		}
		rp->jobname = xmalloc(strlen(at_cmdfile) + 1);
		(void) strcpy(rp->jobname, at_cmdfile);

		/*
		 * Skip over the first two lines.
		 */
		(void) fscanf(atcmdfp, "%*[^\n]\n");
		(void) fscanf(atcmdfp, "%*[^\n]\n");
		if (fscanf(atcmdfp, ": notify by mail: %3s%*[^\n]\n",
		    mailvar) == 1) {
			/*
			 * Check to see if we should always send mail
			 * to the owner.
			 */
			rp->mailwhendone = (strcmp(mailvar, "yes") == 0);
		} else {
			rp->mailwhendone = 0;
		}

		if (fscanf(atcmdfp, "\n: project: %d\n", &projid) == 1) {
			projflag = 1;
		}
		(void) fclose(atcmdfp);
	}

	/*
	 * we make sure that the system time
	 * hasn't drifted backwards. if it has, el_add() is now
	 * called, to make sure that the event queue is back in order,
	 * and we set the delayed flag. cron will pick up the request
	 * later on at the proper time.
	 */
	dhltime = time(NULL);
	if ((dhltime - e->time) < 0) {
		msg("clock time drifted backwards!\n");
		if (next_event->etype == CRONEVENT) {
			msg("correcting cron event\n");
			next_event->time = next_time(next_event, dhltime);
			switch (el_add(next_event, next_event->time,
			    (next_event->u)->ctid)) {
			case -1:
				ignore_msg("ex", "cron", next_event);
				break;
			case -2: /* event time lower than init time */
				reset_needed = 1;
				break;
			}
		} else { /* etype == ATEVENT */
			msg("correcting batch event\n");
			if (el_add(next_event, next_event->time,
			    next_event->of.at.eventid) < 0) {
				ignore_msg("ex", "at", next_event);
			}
		}
		delayed++;
		t_old = time(NULL);
		free(at_cmdfile);
		rinfo_free(rp);
		return (0);
	}

	if ((rfork = fork()) == (pid_t)-1) {
		reap_child();
		if ((rfork = fork()) == (pid_t)-1) {
			msg("cannot fork");
			free(at_cmdfile);
			rinfo_free(rp);
			resched(60);
			(void) sleep(30);
			return (0);
		}
	}
	if (rfork) {		/* parent process */
		contract_abandon_latest(rfork);

		++qp->nrun;
		rp->pid = rfork;
		rp->que = e->etype;
		if (e->etype != CRONEVENT)
			(e->u)->aruncnt++;
		else
			(e->u)->cruncnt++;
		rp->rusr = (e->u);
		logit(BCHAR, rp, 0);
		free(at_cmdfile);

		return (0);
	}

	child_sigreset();
	contract_clear_template();

	if (e->etype != CRONEVENT) {
		/* open jobfile as stdin to shell */
		if (stat(at_cmdfile, &buf)) {
			if (errno == ENAMETOOLONG) {
				if (chdir(ATDIR) == 0)
					cron_unlink(e->cmd);
			} else
				cron_unlink(at_cmdfile);
			mail((e->u)->name, BADJOBOPEN, ERR_CANTEXECCRON);
			exit(1);
		}
		if (!(buf.st_mode&ISUID)) {
			/*
			 * if setuid bit off, original owner has
			 * given this file to someone else
			 */
			cron_unlink(at_cmdfile);
			exit(1);
		}
		if ((fd = open(at_cmdfile, O_RDONLY)) == -1) {
			mail((e->u)->name, BADJOBOPEN, ERR_CANTEXECCRON);
			cron_unlink(at_cmdfile);
			exit(1);
		}
		if (fd != 0) {
			(void) dup2(fd, 0);
			(void) close(fd);
		}
		/*
		 * retrieve the project id of the at job and convert it
		 * to a project name.  fail if it's not a valid project
		 * or if the user isn't a member of the project.
		 */
		if (projflag == 1) {
			if ((pproj = getprojbyid(projid, &proj,
			    (void *)&bufs.p.buf,
			    sizeof (bufs.p.buf))) == NULL ||
			    !inproj(e->u->name, pproj->pj_name,
			    bufs.p.buf2, sizeof (bufs.p.buf2))) {
				cron_unlink(at_cmdfile);
				mail((e->u)->name, BADPROJID, ERR_CANTEXECAT);
				exit(1);
			}
		}
	}

	/*
	 * Put process in a new session, and create a new task.
	 */
	if (setsid() < 0) {
		msg("setsid failed with errno = %d. job failed (%s)"
		    " for user %s", errno, e->cmd, e->u->name);
		if (e->etype != CRONEVENT)
			cron_unlink(at_cmdfile);
		exit(1);
	}

	/*
	 * set correct user identification and check his account
	 */
	r = set_user_cred(e->u, pproj);
	if (r == VUC_EXPIRED) {
		msg("user (%s) account is expired", e->u->name);
		audit_cron_user_acct_expired(e->u->name);
		clean_out_user(e->u);
		exit(1);
	}
	if (r == VUC_NEW_AUTH) {
		msg("user (%s) password has expired", e->u->name);
		audit_cron_user_acct_expired(e->u->name);
		clean_out_user(e->u);
		exit(1);
	}
	if (r != VUC_OK) {
		msg("bad user (%s)", e->u->name);
		audit_cron_bad_user(e->u->name);
		clean_out_user(e->u);
		exit(1);
	}
	/*
	 * check user and initialize the supplementary group access list.
	 * bugid 1230784: deleted from parent to avoid cron hang. Now
	 * only child handles the call.
	 */

	if (verify_user_cred(e->u) != VUC_OK ||
	    setgid(e->u->gid) == -1 ||
	    initgroups(e->u->name, e->u->gid) == -1) {
		msg("bad user (%s) or setgid failed (%s)",
		    e->u->name, e->u->name);
		audit_cron_bad_user(e->u->name);
		clean_out_user(e->u);
		exit(1);
	}

	if ((e->u)->uid == 0) { /* set default path */
		/* path settable in defaults file */
		envinit[2] = supath;
	} else {
		envinit[2] = path;
	}

	if (e->etype != CRONEVENT) {
		r = audit_cron_session(e->u->name, NULL,
		    e->u->uid, e->u->gid, at_cmdfile);
		cron_unlink(at_cmdfile);
	} else {
		r = audit_cron_session(e->u->name, CRONDIR,
		    e->u->uid, e->u->gid, NULL);
	}
	if (r != 0) {
		msg("cron audit problem. job failed (%s) for user %s",
		    e->cmd, e->u->name);
		exit(1);
	}

	audit_cron_new_job(e->cmd, e->etype, (void *)e);

	if (setuid(e->u->uid) == -1)  {
		msg("setuid failed (%s)", e->u->name);
		clean_out_user(e->u);
		exit(1);
	}

	if (e->etype == CRONEVENT) {
		/* check for standard input to command	*/
		if (e->of.ct.input != NULL) {
			if ((tmpfile = strdup(TMPINFILE)) == NULL) {
				mail((e->u)->name, MALLOCERR,
				    ERR_CANTEXECCRON);
				exit(1);
			}
			if ((fd = mkstemp(tmpfile)) == -1 ||
			    (fptr = fdopen(fd, "w")) == NULL) {
				mail((e->u)->name, NOSTDIN,
				    ERR_CANTEXECCRON);
				cron_unlink(tmpfile);
				free(tmpfile);
				exit(1);
			}
			if ((fwrite(e->of.ct.input, sizeof (char),
			    strlen(e->of.ct.input), fptr)) !=
			    strlen(e->of.ct.input)) {
				mail((e->u)->name, NOSTDIN, ERR_CANTEXECCRON);
				cron_unlink(tmpfile);
				free(tmpfile);
				(void) close(fd);
				(void) fclose(fptr);
				exit(1);
			}
			if (fseek(fptr, (off_t)0, SEEK_SET) != -1) {
				if (fd != 0) {
					(void) dup2(fd, 0);
					(void) close(fd);
				}
			}
			cron_unlink(tmpfile);
			free(tmpfile);
			(void) fclose(fptr);
		} else if ((fd = open("/dev/null", O_RDONLY)) > 0) {
			(void) dup2(fd, 0);
			(void) close(fd);
		}
	}

	/* redirect stdout and stderr for the shell	*/
	if ((fd = open(rp->outfile, O_WRONLY|O_CREAT|O_EXCL, OUTMODE)) == 1)
		fd = open("/dev/null", O_WRONLY);

	if (fd >= 0 && fd != 1)
		(void) dup2(fd, 1);

	if (fd >= 0 && fd != 2) {
		(void) dup2(fd, 2);
		if (fd != 1)
			(void) close(fd);
	}

	if (e->etype == CRONEVENT && e->of.ct.home != NULL) {
		home = (char *)get_obj(e->of.ct.home);
	} else {
		home = (e->u)->home;
	}
	(void) strlcat(homedir, home, sizeof (homedir));
	(void) strlcat(logname, (e->u)->name, sizeof (logname));
	environ = envinit;
	if (chdir(home) == -1) {
		snprintf(bufs.error, sizeof (bufs.error), CANTCDHOME, home);
		mail((e->u)->name, bufs.error,
		    e->etype == CRONEVENT ? ERR_CANTEXECCRON :
		    ERR_CANTEXECAT);
		exit(1);
	}
#ifdef TESTING
	exit(1);
#endif
	/*
	 * make sure that all file descriptors EXCEPT 0, 1 and 2
	 * will be closed.
	 */
	closefrom(3);

	if ((e->u)->uid != 0)
		(void) nice(qp->nice);
	if (e->etype == CRONEVENT) {
		if (e->of.ct.tz) {
			(void) putenv((char *)get_obj(e->of.ct.tz));
		}
		if (e->of.ct.shell) {
			char *name;

			sh = (char *)get_obj(e->of.ct.shell);
			name = strrchr(sh, '/');
			if (name == NULL)
				name = sh;
			else
				name++;

			(void) putenv(sh);
			sh += strlen(ENV_SHELL);
			(void) execl(sh, name, "-c", e->cmd, 0);
		} else {
			(void) execl(SHELL, "sh", "-c", e->cmd, 0);
			sh = SHELL;
		}
	} else {		/* type == ATEVENT */
		(void) execl(SHELL, "sh", 0);
		sh = SHELL;
	}
	snprintf(bufs.error, sizeof (bufs.error), CANTEXECSH, sh);
	mail((e->u)->name, bufs.error,
	    e->etype == CRONEVENT ? ERR_CANTEXECCRON : ERR_CANTEXECAT);
	exit(1);
	/*NOTREACHED*/
}

/*
 * Main idle loop.
 * When timed out to run the job, return 0.
 * If for some reasons we need to reschedule jobs, return 1.
 */
static int
idle(long t)
{
	time_t	now;

	refresh = 0;

	while (t > 0L) {
		if (msg_wait(t) != 0) {
			/* we need to run next job immediately */
			return (0);
		}

		reap_child();

		if (refresh) {
			/* We got THAW or REFRESH message  */
			return (1);
		}

		now = time(NULL);
		if (last_time > now) {
			/* clock has been reset to backward */
			return (1);
		}

		if (next_event == NULL && !el_empty()) {
			next_event = (struct event *)el_first();
		}

		if (next_event == NULL)
			t = INFINITY;
		else
			t = (long)next_event->time - now;
	}
	return (0);
}

/*
 * This used to be in the idle(), but moved to the separate function.
 * This called from various place when cron needs to reap the
 * child. It includes the situation that cron hit maxrun, and needs
 * to reschedule the job.
 */
static void
reap_child()
{
	pid_t	pid;
	int	prc;
	struct	runinfo	*rp;

	for (;;) {
		pid = waitpid((pid_t)-1, &prc, WNOHANG);
		if (pid <= 0)
			break;
#ifdef DEBUG
		fprintf(stderr,
		    "wait returned %x for process %d\n", prc, pid);
#endif
		if ((rp = rinfo_get(pid)) == NULL) {
			if (miscpid_delete(pid) == 0) {
				/* not found in anywhere */
				msg(PIDERR, pid);
			}
		} else if (rp->que == ZOMB) {
			(void) unlink(rp->outfile);
			rinfo_free(rp);
		} else {
			cleanup(rp, prc);
		}
	}
}

static void
cleanup(struct runinfo *pr, int rc)
{
	int	nextfork = 1;
	struct	usr	*p;
	struct	stat	buf;

	logit(ECHAR, pr, rc);
	--qt[pr->que].nrun;
	p = pr->rusr;
	if (pr->que != CRONEVENT)
		--p->aruncnt;
	else
		--p->cruncnt;

	if (lstat(pr->outfile, &buf) == 0) {
		if (!S_ISLNK(buf.st_mode) &&
		    (buf.st_size > 0 || pr->mailwhendone)) {
			/* mail user stdout and stderr */
			for (;;) {
				if ((pr->pid = fork()) < 0) {
					/*
					 * if fork fails try forever in doubling
					 * retry times, up to 16 seconds
					 */
					(void) sleep(nextfork);
					if (nextfork < 16)
						nextfork += nextfork;
					continue;
				} else if (pr->pid == 0) {
					child_sigreset();
					contract_clear_template();

					mail_result(p, pr, buf.st_size);
					/* NOTREACHED */
				} else {
					contract_abandon_latest(pr->pid);
					pr->que = ZOMB;
					break;
				}
			}
		} else {
			(void) unlink(pr->outfile);
			rinfo_free(pr);
		}
	} else {
		rinfo_free(pr);
	}

	free_if_unused(p);
}

/*
 * Mail stdout and stderr of a job to user. Get uid for real user and become
 * that person. We do this so that mail won't come from root since this
 * could be a security hole. If failure, quit - don't send mail as root.
 */
static void
mail_result(struct usr *p, struct runinfo *pr, size_t filesize)
{
	struct	passwd	*ruser_ids;
	FILE	*mailpipe;
	FILE	*st;
	struct utsname	name;
	int	nbytes;
	char	iobuf[BUFSIZ];
	char	*cmd;
	char	*lowname = (pr->jobtype == CRONEVENT ? "cron" : "at");

	(void) uname(&name);
	if ((ruser_ids = getpwnam(p->name)) == NULL)
		exit(0);
	(void) setuid(ruser_ids->pw_uid);

	cmd = xmalloc(strlen(MAIL) + strlen(p->name)+2);
	(void) sprintf(cmd, "%s %s", MAIL, p->name);
	mailpipe = popen(cmd, "w");
	free(cmd);
	if (mailpipe == NULL)
		exit(127);
	(void) fprintf(mailpipe, "To: %s\n", p->name);
	(void) fprintf(mailpipe, "Subject: %s <%s@%s> %s\n",
	    (pr->jobtype == CRONEVENT ? "Cron" : "At"),
	    p->name, name.nodename, pr->jobname);

	/*
	 * RFC3834 (Section 5) defines the Auto-Submitted header to prevent
	 * vacation replies, et al, from being sent in response to
	 * machine-generated mail.
	 */
	(void) fprintf(mailpipe, "Auto-Submitted: auto-generated\n");

	/*
	 * Additional headers for mail filtering and diagnostics:
	 */
	(void) fprintf(mailpipe, "X-Mailer: cron (%s %s)\n", name.sysname,
	    name.release);
	(void) fprintf(mailpipe, "X-Cron-User: %s\n", p->name);
	(void) fprintf(mailpipe, "X-Cron-Host: %s\n", name.nodename);
	(void) fprintf(mailpipe, "X-Cron-Job-Name: %s\n", pr->jobname);
	(void) fprintf(mailpipe, "X-Cron-Job-Type: %s\n", lowname);

	/*
	 * Message Body:
	 *
	 * (Temporary file is fopen'ed with "r", secure open.)
	 */
	(void) fprintf(mailpipe, "\n");
	if (filesize > 0 &&
	    (st = fopen(pr->outfile, "r")) != NULL) {
		while ((nbytes = fread(iobuf, sizeof (char), BUFSIZ, st)) != 0)
			(void) fwrite(iobuf, sizeof (char), nbytes, mailpipe);
		(void) fclose(st);
	} else {
		(void) fprintf(mailpipe, "Job completed with no output.\n");
	}
	(void) pclose(mailpipe);
	exit(0);
}

static int
msg_wait(long tim)
{
	struct	message	msg;
	int	cnt;
	time_t	reftime;
	fd_set	fds;
	struct timespec tout, *toutp;
	static int	pending_msg;
	static time_t	pending_reftime;

	if (pending_msg) {
		process_msg(&msgbuf, pending_reftime);
		pending_msg = 0;
		return (0);
	}

	FD_ZERO(&fds);
	FD_SET(msgfd, &fds);

	toutp = NULL;
	if (tim != INFINITY) {
#ifdef CRON_MAXSLEEP
		/*
		 * CRON_MAXSLEEP can be defined to have cron periodically wake
		 * up, so that cron can detect a change of TOD and adjust the
		 * sleep time more frequently.
		 */
		tim = (tim > CRON_MAXSLEEP) ? CRON_MAXSLEEP : tim;
#endif
		tout.tv_nsec = 0;
		tout.tv_sec = tim;
		toutp = &tout;
	}

	cnt = pselect(msgfd + 1, &fds, NULL, NULL, toutp, &defmask);
	if (cnt == -1 && errno != EINTR)
		perror("! pselect");

	/* pselect timeout or interrupted */
	if (cnt <= 0)
		return (0);

	errno = 0;
	if ((cnt = read(msgfd, &msg, sizeof (msg))) != sizeof (msg)) {
		if (cnt != -1 || errno != EAGAIN)
			perror("! read");
		return (0);
	}
	reftime = time(NULL);
	if (next_event != NULL && reftime >= next_event->time) {
		/*
		 * we need to run the job before reloading crontab.
		 */
		(void) memcpy(&msgbuf, &msg, sizeof (msg));
		pending_msg = 1;
		pending_reftime = reftime;
		return (1);
	}
	process_msg(&msg, reftime);
	return (0);
}

/*
 * process the message supplied via pipe. This will be called either
 * immediately after cron read the message from pipe, or idle time
 * if the message was pending due to the job execution.
 */
static void
process_msg(struct message *pmsg, time_t reftime)
{
	if (pmsg->etype == NULL)
		return;

	switch (pmsg->etype) {
	case AT:
		if (pmsg->action == DELETE)
			del_atjob(pmsg->fname, pmsg->logname);
		else
			mod_atjob(pmsg->fname, (time_t)0);
		break;
	case CRON:
		if (pmsg->action == DELETE)
			del_ctab(pmsg->fname);
		else
			mod_ctab(pmsg->fname, reftime);
		break;
	case REFRESH:
		refresh = 1;
		pmsg->etype = 0;
		return;
	default:
		msg("message received - bad format");
		break;
	}
	if (next_event != NULL) {
		if (next_event->etype == CRONEVENT) {
			switch (el_add(next_event, next_event->time,
			    (next_event->u)->ctid)) {
			case -1:
				ignore_msg("process_msg", "cron", next_event);
				break;
			case -2: /* event time lower than init time */
				reset_needed = 1;
				break;
			}
		} else { /* etype == ATEVENT */
			if (el_add(next_event, next_event->time,
			    next_event->of.at.eventid) < 0) {
				ignore_msg("process_msg", "at", next_event);
			}
		}
		next_event = NULL;
	}
	(void) fflush(stdout);
	pmsg->etype = 0;
}

/*
 * Allocate a new or find an existing runinfo structure
 */
static struct runinfo *
rinfo_get(pid_t pid)
{
	struct runinfo *rp;

	if (pid == 0) {		/* allocate a new entry */
		rp = xcalloc(1, sizeof (struct runinfo));
		rp->next = rthead;	/* link the entry into the list */
		rthead = rp;
		return (rp);
	}
	/* search the list for an existing entry */
	for (rp = rthead; rp != NULL; rp = rp->next) {
		if (rp->pid == pid)
			break;
	}
	return (rp);
}

/*
 * Free a runinfo structure and its associated memory
 */
static void
rinfo_free(struct runinfo *entry)
{
	struct runinfo **rpp;
	struct runinfo *rp;

#ifdef DEBUG
	(void) fprintf(stderr, "freeing job %s\n", entry->jobname);
#endif
	for (rpp = &rthead; (rp = *rpp) != NULL; rpp = &rp->next) {
		if (rp == entry) {
			*rpp = rp->next;	/* unlink the entry */
			free(rp->outfile);
			free(rp->jobname);
			free(rp);
			break;
		}
	}
}

/* ARGSUSED */
static void
thaw_handler(int sig)
{
	refresh = 1;
}


/* ARGSUSED */
static void
cronend(int sig)
{
	crabort("SIGTERM", REMOVE_FIFO);
}

/*ARGSUSED*/
static void
child_handler(int sig)
{
	;
}

static void
child_sigreset(void)
{
	(void) signal(SIGCLD, SIG_DFL);
	(void) sigprocmask(SIG_SETMASK, &defmask, NULL);
}

/*
 * crabort() - handle exits out of cron
 */
static void
crabort(char *mssg, int action)
{
	int	c;

	if (action & REMOVE_FIFO) {
		/* FIFO vanishes when cron finishes */
		if (unlink(FIFO) < 0)
			perror("cron could not unlink FIFO");
	}

	if (action & CONSOLE_MSG) {
		/* write error msg to console */
		if ((c = open(CONSOLE, O_WRONLY)) >= 0) {
			(void) write(c, "cron aborted: ", 14);
			(void) write(c, mssg, strlen(mssg));
			(void) write(c, "\n", 1);
			(void) close(c);
		}
	}

	/* always log the message */
	msg(mssg);
	msg("******* CRON ABORTED ********");
	exit(1);
}

/*
 * msg() - time-stamped error reporting function
 */
/*PRINTFLIKE1*/
static void
msg(char *fmt, ...)
{
	va_list args;
	time_t	t;

	t = time(NULL);

	(void) fflush(stdout);

	(void) fprintf(stderr, "! ");

	va_start(args, fmt);
	(void) vfprintf(stderr, fmt, args);
	va_end(args);

	(void) strftime(timebuf, sizeof (timebuf), FORMAT, localtime(&t));
	(void) fprintf(stderr, " %s\n", timebuf);

	(void) fflush(stderr);
}

static void
ignore_msg(char *func_name, char *job_type, struct event *event)
{
	msg("%s: ignoring %s job (user: %s, cmd: %s, time: %ld)",
	    func_name, job_type,
	    event->u->name ? event->u->name : "unknown",
	    event->cmd ? event->cmd : "unknown",
	    event->time);
}

static void
logit(int cc, struct runinfo *rp, int rc)
{
	time_t t;
	int    ret;

	if (!log)
		return;

	t = time(NULL);
	if (cc == BCHAR)
		(void) printf("%c  CMD: %s\n", cc, next_event->cmd);
	(void) strftime(timebuf, sizeof (timebuf), FORMAT, localtime(&t));
	(void) printf("%c  %s %u %c %s",
	    cc, (rp->rusr)->name, rp->pid, QUE(rp->que), timebuf);
	if ((ret = TSTAT(rc)) != 0)
		(void) printf(" ts=%d", ret);
	if ((ret = RCODE(rc)) != 0)
		(void) printf(" rc=%d", ret);
	(void) putchar('\n');
	(void) fflush(stdout);
}

static void
resched(int delay)
{
	time_t	nt;

	/* run job at a later time */
	nt = next_event->time + delay;
	if (next_event->etype == CRONEVENT) {
		next_event->time = next_time(next_event, (time_t)0);
		if (nt < next_event->time)
			next_event->time = nt;
		switch (el_add(next_event, next_event->time,
		    (next_event->u)->ctid)) {
		case -1:
			ignore_msg("resched", "cron", next_event);
			break;
		case -2: /* event time lower than init time */
			reset_needed = 1;
			break;
		}
		delayed = 1;
		msg("rescheduling a cron job");
		return;
	}
	add_atevent(next_event->u, next_event->cmd, nt, next_event->etype);
	msg("rescheduling at job");
}

static void
quedefs(int action)
{
	int	i;
	int	j;
	char	qbuf[QBUFSIZ];
	FILE	*fd;

	/* set up default queue definitions */
	for (i = 0; i < NQUEUE; i++) {
		qt[i].njob = qd.njob;
		qt[i].nice = qd.nice;
		qt[i].nwait = qd.nwait;
	}
	if (action == DEFAULT)
		return;
	if ((fd = fopen(QUEDEFS, "r")) == NULL) {
		msg("cannot open quedefs file");
		msg("using default queue definitions");
		return;
	}
	while (fgets(qbuf, QBUFSIZ, fd) != NULL) {
		if ((j = qbuf[0]-'a') < 0 || j >= NQUEUE || qbuf[1] != '.')
			continue;
		parsqdef(&qbuf[2]);
		qt[j].njob = qq.njob;
		qt[j].nice = qq.nice;
		qt[j].nwait = qq.nwait;
	}
	(void) fclose(fd);
}

static void
parsqdef(char *name)
{
	int i;

	qq = qd;
	while (*name) {
		i = 0;
		while (isdigit(*name)) {
			i *= 10;
			i += *name++ - '0';
		}
		switch (*name++) {
		case JOBF:
			qq.njob = i;
			break;
		case NICEF:
			qq.nice = i;
			break;
		case WAITF:
			qq.nwait = i;
			break;
		}
	}
}

/*
 * defaults - read defaults from /etc/default/cron
 */
static void
defaults()
{
	int  flags;
	char *deflog;
	char *hz, *tz;

	/*
	 * get HZ value for environment
	 */
	if ((hz = getenv("HZ")) == (char *)NULL)
		(void) sprintf(hzname, "HZ=%d", HZ);
	else
		(void) snprintf(hzname, sizeof (hzname), "HZ=%s", hz);
	/*
	 * get TZ value for environment
	 */
	(void) snprintf(tzone, sizeof (tzone), "TZ=%s",
	    ((tz = getenv("TZ")) != NULL) ? tz : DEFTZ);

	if (defopen(DEFFILE) == 0) {
		/* ignore case */
		flags = defcntl(DC_GETFLAGS, 0);
		TURNOFF(flags, DC_CASE);
		(void) defcntl(DC_SETFLAGS, flags);

		if (((deflog = defread("CRONLOG=")) == NULL) ||
		    (*deflog == 'N') || (*deflog == 'n'))
			log = 0;
		else
			log = 1;
		/* fix for 1087611 - allow paths to be set in defaults file */
		if ((Def_path = defread("PATH=")) != NULL) {
			(void) strlcat(path, Def_path, LINE_MAX);
		} else {
			(void) strlcpy(path, NONROOTPATH, LINE_MAX);
		}
		if ((Def_supath = defread("SUPATH=")) != NULL) {
			(void) strlcat(supath, Def_supath, LINE_MAX);
		} else {
			(void) strlcpy(supath, ROOTPATH, LINE_MAX);
		}
		(void) defopen(NULL);
	}
}

/*
 * Determine if a user entry for a job is still ok.  The method used here
 * is a lot (about 75x) faster than using setgrent() / getgrent()
 * endgrent().  It should be safe because we use the sysconf to determine
 * the max, and it tolerates the max being 0.
 */

static int
verify_user_cred(struct usr *u)
{
	struct passwd *pw;
	size_t numUsrGrps = 0;
	size_t numOrigGrps = 0;
	size_t i;
	int retval;

	/*
	 * Maximum number of groups a user may be in concurrently.  This
	 * is a value which we obtain at runtime through a sysconf()
	 * call.
	 */

	static size_t nGroupsMax = (size_t)-1;

	/*
	 * Arrays for cron user's group list, constructed at startup to
	 * be nGroupsMax elements long, used for verifying user
	 * credentials prior to execution.
	 */

	static gid_t *UsrGrps;
	static gid_t *OrigGrps;

	if ((pw = getpwnam(u->name)) == NULL)
		return (VUC_BADUSER);
	if (u->home != NULL) {
		if (strcmp(u->home, pw->pw_dir) != 0) {
			free(u->home);
			u->home = xmalloc(strlen(pw->pw_dir) + 1);
			(void) strcpy(u->home, pw->pw_dir);
		}
	} else {
		u->home = xmalloc(strlen(pw->pw_dir) + 1);
		(void) strcpy(u->home, pw->pw_dir);
	}
	if (u->uid != pw->pw_uid)
		u->uid = pw->pw_uid;
	if (u->gid != pw->pw_gid)
		u->gid  = pw->pw_gid;

	/*
	 * Create the group id lists needed for job credential
	 * verification.
	 */

	if (nGroupsMax == (size_t)-1) {
		if ((nGroupsMax = sysconf(_SC_NGROUPS_MAX)) > 0) {
			UsrGrps = xcalloc(nGroupsMax, sizeof (gid_t));
			OrigGrps = xcalloc(nGroupsMax, sizeof (gid_t));
		}

#ifdef DEBUG
		(void) fprintf(stderr, "nGroupsMax = %ld\n", nGroupsMax);
#endif
	}

#ifdef DEBUG
	(void) fprintf(stderr, "verify_user_cred (%s-%d)\n", pw->pw_name,
	    pw->pw_uid);
	(void) fprintf(stderr, "verify_user_cred: pw->pw_gid = %d, "
	    "u->gid = %d\n", pw->pw_gid, u->gid);
#endif

	retval = (u->gid == pw->pw_gid) ? VUC_OK : VUC_NOTINGROUP;

	if (nGroupsMax > 0) {
		numOrigGrps = getgroups(nGroupsMax, OrigGrps);

		(void) initgroups(pw->pw_name, pw->pw_gid);
		numUsrGrps = getgroups(nGroupsMax, UsrGrps);

		for (i = 0; i < numUsrGrps; i++) {
			if (UsrGrps[i] == u->gid) {
				retval = VUC_OK;
				break;
			}
		}

		if (OrigGrps) {
			(void) setgroups(numOrigGrps, OrigGrps);
		}
	}

#ifdef DEBUG
	(void) fprintf(stderr, "verify_user_cred: VUC = %d\n", retval);
#endif

	return (retval);
}

static int
set_user_cred(const struct usr *u, struct project *pproj)
{
	static char *progname = "cron";
	int r = 0, rval = 0;

	if ((r = pam_start(progname, u->name, &pam_conv, &pamh))
	    != PAM_SUCCESS) {
#ifdef DEBUG
		msg("pam_start returns %d\n", r);
#endif
		rval = VUC_BADUSER;
		goto set_eser_cred_exit;
	}

	r = pam_acct_mgmt(pamh, 0);
#ifdef DEBUG
	msg("pam_acc_mgmt returns %d\n", r);
#endif
	if (r == PAM_ACCT_EXPIRED) {
		rval = VUC_EXPIRED;
		goto set_eser_cred_exit;
	}
	if (r == PAM_NEW_AUTHTOK_REQD) {
		rval = VUC_NEW_AUTH;
		goto set_eser_cred_exit;
	}
	if (r != PAM_SUCCESS) {
		rval = VUC_BADUSER;
		goto set_eser_cred_exit;
	}

	if (pproj != NULL) {
		size_t sz = sizeof (PROJECT) + strlen(pproj->pj_name);
		char *buf = alloca(sz);

		(void) snprintf(buf, sz, PROJECT "%s", pproj->pj_name);
		(void) pam_set_item(pamh, PAM_RESOURCE, buf);
	}

	r = pam_setcred(pamh, PAM_ESTABLISH_CRED);
	if (r != PAM_SUCCESS)
		rval = VUC_BADUSER;

set_eser_cred_exit:
	(void) pam_end(pamh, r);
	return (rval);
}

static void
clean_out_user(struct usr *u)
{
	if (next_event->u == u) {
		next_event = NULL;
	}

	clean_out_ctab(u);
	clean_out_atjobs(u);
	free_if_unused(u);
}

static void
clean_out_atjobs(struct usr *u)
{
	struct event *ev, *pv;

	for (pv = NULL, ev = u->atevents;
	    ev != NULL;
	    pv = ev, ev = ev->link, free(pv)) {
		el_remove(ev->of.at.eventid, 1);
		if (cwd == AT)
			cron_unlink(ev->cmd);
		else {
			char buf[PATH_MAX];
			if (strlen(ATDIR) + strlen(ev->cmd) + 2
			    < PATH_MAX) {
				(void) sprintf(buf, "%s/%s", ATDIR, ev->cmd);
				cron_unlink(buf);
			}
		}
		free(ev->cmd);
	}

	u->atevents = NULL;
}

static void
clean_out_ctab(struct usr *u)
{
	rm_ctevents(u);
	el_remove(u->ctid, 0);
	u->ctid = 0;
	u->ctexists = 0;
}

static void
cron_unlink(char *name)
{
	int r;

	r = unlink(name);
	if (r == 0 || (r == -1 && errno == ENOENT)) {
		(void) audit_cron_delete_anc_file(name, NULL);
	}
}

static void
create_anc_ctab(struct event *e)
{
	if (audit_cron_create_anc_file(e->u->name,
	    (cwd == CRON) ? NULL:CRONDIR,
	    e->u->name, e->u->uid) == -1) {
		process_anc_files(CRON_ANC_DELETE);
		crabort("cannot create ancillary files for crontabs",
		    REMOVE_FIFO|CONSOLE_MSG);
	}
}

static void
delete_anc_ctab(struct event *e)
{
	(void) audit_cron_delete_anc_file(e->u->name,
	    (cwd == CRON) ? NULL:CRONDIR);
}

static void
create_anc_atjob(struct event *e)
{
	if (!e->of.at.exists)
		return;

	if (audit_cron_create_anc_file(e->cmd,
	    (cwd == AT) ? NULL:ATDIR,
	    e->u->name, e->u->uid) == -1) {
		process_anc_files(CRON_ANC_DELETE);
		crabort("cannot create ancillary files for atjobs",
		    REMOVE_FIFO|CONSOLE_MSG);
	}
}

static void
delete_anc_atjob(struct event *e)
{
	if (!e->of.at.exists)
		return;

	(void) audit_cron_delete_anc_file(e->cmd,
	    (cwd == AT) ? NULL:ATDIR);
}


static void
process_anc_files(int del)
{
	struct usr	*u = uhead;
	struct event	*e;

	if (!audit_cron_mode())
		return;

	for (;;) {
		if (u->ctexists && u->ctevents != NULL) {
			e = u->ctevents;
			for (;;) {
				if (del)
					delete_anc_ctab(e);
				else
					create_anc_ctab(e);
				if ((e = e->link) == NULL)
					break;
			}
		}

		if (u->atevents != NULL) {
			e = u->atevents;
			for (;;) {
				if (del)
					delete_anc_atjob(e);
				else
					create_anc_atjob(e);
				if ((e = e->link) == NULL)
					break;
			}
		}

		if ((u = u->nextusr)  == NULL)
			break;
	}
}

/*ARGSUSED*/
static int
cron_conv(int num_msg, struct pam_message **msgs,
    struct pam_response **response, void *appdata_ptr)
{
	struct pam_message	**m = msgs;
	int i;

	for (i = 0; i < num_msg; i++) {
		switch (m[i]->msg_style) {
		case PAM_ERROR_MSG:
		case PAM_TEXT_INFO:
			if (m[i]->msg != NULL) {
				(void) msg("%s\n", m[i]->msg);
			}
			break;

		default:
			break;
		}
	}
	return (0);
}

/*
 * Cron creates process for other than job. Mail process is the
 * one which rinfo does not cover. Therefore, miscpid will keep
 * track of the pids executed from cron. Otherwise, we will see
 * "unexpected pid returned.." messages appear in the log file.
 */
static void
miscpid_insert(pid_t pid)
{
	struct miscpid *mp;

	mp = xmalloc(sizeof (*mp));
	mp->pid = pid;
	mp->next = miscpid_head;
	miscpid_head = mp;
}

static int
miscpid_delete(pid_t pid)
{
	struct miscpid *mp, *omp;
	int found = 0;

	omp = NULL;
	for (mp = miscpid_head; mp != NULL; mp = mp->next) {
		if (mp->pid == pid) {
			found = 1;
			break;
		}
		omp = mp;
	}
	if (found) {
		if (omp != NULL)
			omp->next = mp->next;
		else
			miscpid_head = NULL;
		free(mp);
	}
	return (found);
}

/*
 * Establish contract terms such that all children are in abandoned
 * process contracts.
 */
static void
contract_set_template(void)
{
	int fd;

	if ((fd = open64(CTFS_ROOT "/process/template", O_RDWR)) < 0)
		crabort("cannot open process contract template",
		    REMOVE_FIFO | CONSOLE_MSG);

	if (ct_pr_tmpl_set_param(fd, 0) ||
	    ct_tmpl_set_informative(fd, 0) ||
	    ct_pr_tmpl_set_fatal(fd, CT_PR_EV_HWERR))
		crabort("cannot establish contract template terms",
		    REMOVE_FIFO | CONSOLE_MSG);

	if (ct_tmpl_activate(fd))
		crabort("cannot activate contract template",
		    REMOVE_FIFO | CONSOLE_MSG);

	(void) close(fd);
}

/*
 * Clear active process contract template.
 */
static void
contract_clear_template(void)
{
	int fd;

	if ((fd = open64(CTFS_ROOT "/process/template", O_RDWR)) < 0)
		crabort("cannot open process contract template",
		    REMOVE_FIFO | CONSOLE_MSG);

	if (ct_tmpl_clear(fd))
		crabort("cannot clear contract template",
		    REMOVE_FIFO | CONSOLE_MSG);

	(void) close(fd);
}

/*
 * Abandon latest process contract unconditionally.  If we have leaked [some
 * critical amount], exit such that the kernel reaps our contracts.
 */
static void
contract_abandon_latest(pid_t pid)
{
	int r;
	ctid_t id;
	static uint_t cts_lost;

	if (cts_lost > MAX_LOST_CONTRACTS)
		crabort("repeated failure to abandon contracts",
		    REMOVE_FIFO | CONSOLE_MSG);

	if (r = contract_latest(&id)) {
		msg("could not obtain latest contract for "
		    "PID %ld: %s", pid, strerror(r));
		cts_lost++;
		return;
	}

	if (r = contract_abandon_id(id)) {
		msg("could not abandon latest contract %ld: %s", id,
		    strerror(r));
		cts_lost++;
		return;
	}
}

static struct shared *
create_shared(void *obj, void * (*obj_alloc)(void *obj),
	void (*obj_free)(void *))
{
	struct shared *out;

	if ((out = xmalloc(sizeof (struct shared))) == NULL) {
		return (NULL);
	}
	if ((out->obj = obj_alloc(obj)) == NULL) {
		free(out);
		return (NULL);
	}
	out->count = 1;
	out->free = obj_free;

	return (out);
}

static struct shared *
create_shared_str(char *str)
{
	return (create_shared(str, (void *(*)(void *))strdup, free));
}

static struct shared *
dup_shared(struct shared *obj)
{
	if (obj != NULL) {
		obj->count++;
	}
	return (obj);
}

static void
rel_shared(struct shared *obj)
{
	if (obj && (--obj->count) == 0) {
		obj->free(obj->obj);
		free(obj);
	}
}

static void *
get_obj(struct shared *obj)
{
	return (obj->obj);
}
