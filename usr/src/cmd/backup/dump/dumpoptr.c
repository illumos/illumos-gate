/*
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#include <errno.h>
#include "dump.h"

time_t *tschedule;
static unsigned int timeout;		/* current timeout */
static char *attnmessage, *saveattn;	/* attention message */

static void alarmcatch(int);
static int idatesort(const void *, const void *);

#ifdef DEBUG
extern int xflag;
#endif

/*
 *	Query the operator; This fascist piece of code requires
 *	an exact response.
 *	It is intended to protect dump aborting by inquisitive
 *	people banging on the console terminal to see what is
 *	happening which might cause dump to croak, destroying
 *	a large number of hours of work.
 *
 *	Every time += 2 minutes we reprint the message, alerting others
 *	that dump needs attention.
 */
int
query(char *question)
{
	int def = -1;

	while (def == -1)
		def = query_once(question, -1);
	return (def);
}

static int in_query_once;
static jmp_buf sjalarmbuf;

/* real simple check-sum */
static int
addem(char *s)
{
	int total = 0;

	if (s == (char *)NULL)
		return (total);
	while (*s)
		total += *s++;
	return (total);
}

int
query_once(char	*question, int def)
{
	static char *lastmsg;
	static int lastmsgsum;
	int	msgsum;
	char	replybuffer[BUFSIZ];
	int	back;
	time32_t timeclockstate;
	pollfd_t pollset;
	struct sigvec sv;

	/* special hook to flush timeout cache */
	if (question == NULL) {
		lastmsg = (char *)NULL;
		lastmsgsum = 0;
		return (0);
	}

	attnmessage = question;
	/*
	 * Only reset the state if the message changed somehow
	 */
	msgsum = addem(question);
	if (lastmsg != question || lastmsgsum != msgsum) {
		timeout = 0;
		if (telapsed && tstart_writing)
			*telapsed += time((time_t *)0) - *tstart_writing;
		lastmsg = question;
		lastmsgsum = msgsum;
	}
	timeclockstate = timeclock((time_t)0);
	if (setjmp(sjalarmbuf) != 0) {
		if (def != -1) {
			if (def)
				msgtail(gettext("YES\n"));
			else
				msgtail(gettext("NO\n"));
		}
		back = def;
		goto done;
	}
	alarmcatch(SIGALRM);
	in_query_once = 1;
	pollset.fd = -1;
	pollset.events = 0;
	pollset.revents = 0;
	if (isatty(fileno(stdin))) {
		pollset.fd = fileno(stdin);
		pollset.events = POLLIN | POLLPRI | POLLRDNORM | POLLRDBAND;
	} else {
		dumpabort();
		/*NOTREACHED*/
	}
	for (;;) {
		if (poll(&pollset, 1, -1) < 0) {
			if (errno == EINTR)
				continue;
			perror("poll(stdin)");
			dumpabort();
			/*NOTREACHED*/
		}
		if (pollset.revents == 0)
			continue;	/* sanity check */
		if (fgets(replybuffer, sizeof (replybuffer), stdin) == NULL) {
			if (ferror(stdin)) {
				clearerr(stdin);
				continue;
			} else {
				dumpabort();
				/*NOTREACHED*/
			}
		}
		timeout = 0;
		if (strcasecmp(replybuffer, gettext("yes\n")) == 0) {
			back = 1;
			lastmsg = (char *)NULL;
			lastmsgsum = 0;
			goto done;
		} else if (strcasecmp(replybuffer, gettext("no\n")) == 0) {
			back = 0;
			lastmsg = (char *)NULL;
			lastmsgsum = 0;
			goto done;
		} else {
			msg(gettext("\"yes\" or \"no\"?\n"));
			in_query_once = 0;
			alarmcatch(SIGALRM);
			in_query_once = 1;
		}
	}
done:
	/*
	 * Turn off the alarm, and reset the signal to trap out..
	 */
	(void) alarm(0);
	attnmessage = NULL;
	sv.sv_handler = sigAbort;
	sv.sv_flags = SA_RESTART;
	(void) sigemptyset(&sv.sa_mask);
	(void) sigvec(SIGALRM, &sv, (struct sigvec *)0);
	if (tstart_writing)
		(void) time(tstart_writing);
	(void) timeclock(timeclockstate);
	in_query_once = 0;
	return (back);
}
/*
 *	Alert the console operator, and enable the alarm clock to
 *	sleep for time += 2 minutes in case nobody comes to satisfy dump
 *	If the alarm goes off while in the query_once for loop, we just
 *	longjmp back there and return the default answer.
 */
static void
alarmcatch(int signal __unused)
{
	struct sigvec sv;

	if (in_query_once) {
		longjmp(sjalarmbuf, 1);
	}
	if (timeout) {
		msgtail("\n");
	}

	timeout += 120;
	msg(gettext("NEEDS ATTENTION: %s"), attnmessage);
	sv.sv_handler = alarmcatch;
	sv.sv_flags = SA_RESTART;
	(void) sigemptyset(&sv.sa_mask);
	(void) sigvec(SIGALRM, &sv, (struct sigvec *)0);
	(void) alarm(timeout);
}

/*
 *	Here if an inquisitive operator interrupts the dump program
 */
/*ARGSUSED*/
void
interrupt(int sig)
{
	if (!saveattn) {
		saveattn = attnmessage;
	}
	msg(gettext("Interrupt received.\n"));
	if (query(gettext(
	    "Do you want to abort dump?: (\"yes\" or \"no\") "))) {
		dumpabort();
		/*NOTREACHED*/
	}
	if (saveattn) {
		attnmessage = saveattn;
		saveattn = NULL;
		alarmcatch(SIGALRM);
	}
}

/*
 *	We use wall(1) to do the actual broadcasting, so
 *	that we don't have to worry about duplicated code
 *	only getting fixed in one place.  This also saves
 *	us from having to worry about process groups,
 *	controlling terminals, and the like.
 */
void
broadcast(char *message)
{
	time_t	clock;
	pid_t	pid;
	int	saverr;
	int	fildes[2];
	FILE	*wall;
	struct tm *localclock;

	if (!notify)
		return;

	if (pipe(fildes) < 0) {
		saverr = errno;
		msg(gettext("pipe: %s\n"), strerror(saverr));
		return;
	}

	switch (pid = fork()) {
	case -1:
		return;
	case 0:
		close(fildes[0]);
		if (dup2(fildes[1], 0) < 0) {
			saverr = errno;
			msg(gettext("dup2: %s\n"), strerror(saverr));
			exit(1);
		}
		execl("/usr/sbin/wall", "wall", "-g", OPGRENT, (char *)NULL);
		saverr = errno;
		msg(gettext("execl: %s\n"), strerror(saverr));
		exit(1);
	default:
		break;		/* parent */
	}

	close(fildes[1]);
	wall = fdopen(fildes[0], "r+");
	if (wall == (FILE *)NULL) {
		saverr = errno;
		msg(gettext("fdopen: %s\n"), strerror(saverr));
		return;
	}

	clock = time((time_t *)0);
	localclock = localtime(&clock);

	(void) fprintf(wall, gettext(
"\n\007\007\007Message from the dump program to all operators at \
%d:%02d ...\n\n%s"),
	    localclock->tm_hour, localclock->tm_min, message);
	fclose(wall);

	while (wait((int *)0) != pid) {
		continue;
		/*LINTED [empty loop body]*/
	}
}

/*
 *	print out an estimate of the amount of time left to do the dump
 */
#define	EST_SEC	600			/* every 10 minutes */
void
timeest(int force, int blkswritten)
{
	time_t tnow, deltat;
	char *msgp;

	if (tschedule == NULL)
		return;
	if (*tschedule == 0)
		*tschedule = time((time_t *)0) + EST_SEC;
	(void) time(&tnow);
	if ((force || tnow >= *tschedule) && blkswritten) {
		*tschedule = tnow + EST_SEC;
		if (!force && blkswritten < 50 * ntrec)
			return;
		deltat = (*telapsed + (tnow - *tstart_writing))
		    * ((double)esize / blkswritten - 1.0);
		msgp = gettext("%3.2f%% done, finished in %d:%02d\n");
		msg(msgp, (blkswritten*100.0)/esize,
		    deltat/3600, (deltat%3600)/60);
	}
}

#include <stdarg.h>

/* VARARGS1 */
void
msg(const char *fmt, ...)
{
	char buf[1024], *cp;
	size_t size;
	va_list args;

	va_start(args, fmt);
	(void) strcpy(buf, "  DUMP: ");
	cp = &buf[strlen(buf)];
#ifdef TDEBUG
	(void) sprintf(cp, "pid=%d ", getpid());
	cp = &buf[strlen(buf)];
#endif
	/* don't need -1, vsnprintf does it right */
	/* LINTED pointer arithmetic result fits in size_t */
	size = ((size_t)sizeof (buf)) - (size_t)(cp - buf);
	(void) vsnprintf(cp, size, fmt, args);
	(void) fputs(buf, stderr);
	(void) fflush(stdout);
	(void) fflush(stderr);
	va_end(args);
}

/* VARARGS1 */
void
msgtail(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	(void) vfprintf(stderr, fmt, args);
	va_end(args);
}

#define	MINUTES(x)	((x) * 60)

/*
 *	Tell the operator what has to be done;
 *	we don't actually do it
 */
void
lastdump(int arg)	/* w ==> just what to do; W ==> most recent dumps */
{
	char *lastname;
	char *date;
	int i;
	time_t tnow, ddate;
	struct mntent *dt;
	int dumpme = 0;
	struct idates *itwalk;

	(void) time(&tnow);
	mnttabread();		/* /etc/fstab input */
	inititimes();		/* /etc/dumpdates input */

	/* Don't use msg(), this isn't a tell-the-world kind of thing */
	if (arg == 'w')
		(void) fprintf(stdout, gettext("Dump these file systems:\n"));
	else
		(void) fprintf(stdout, gettext(
		    "Last dump(s) done (Dump '>' file systems):\n"));

	if (idatev != NULL) {
		qsort((char *)idatev, nidates, sizeof (*idatev), idatesort);
		lastname = "??";
		ITITERATE(i, itwalk) {
			if (strncmp(lastname, itwalk->id_name,
			    sizeof (itwalk->id_name)) == 0)
				continue;
			/* must be ctime(), per ufsdump(5) */
			ddate = itwalk->id_ddate;
			date = (char *)ctime(&ddate);
			date[16] = '\0';	/* blow away seconds and year */
			lastname = itwalk->id_name;
			dt = mnttabsearch(itwalk->id_name, 0);
			if ((time_t)(itwalk->id_ddate) < (tnow - DAY)) {
				dumpme = 1;
			}

			if ((arg == 'w') && dumpme) {
				/*
				 * Handle the w option: print out file systems
				 * which haven't been backed up within a day.
				 */
				(void) printf(gettext("%8s\t(%6s)\n"),
				    itwalk->id_name, dt ? dt->mnt_dir : "");
			}
			if (arg == 'W') {
				/*
				 * Handle the W option: print out ALL
				 * filesystems including recent dump dates and
				 * dump levels.  Mark the backup-needing
				 * filesystems with a >.
				 */
				(void) printf(gettext(
			    "%c %8s\t(%6s) Last dump: Level %c, Date %s\n"),
				    dumpme ? '>' : ' ',
				    itwalk->id_name,
				    dt ? dt->mnt_dir : "",
				    (uchar_t)itwalk->id_incno,
				    date);
			}
			dumpme = 0;
		}
	}
}

static int
idatesort(const void *v1, const void *v2)
{
	struct idates **p1 = (struct idates **)v1;
	struct idates **p2 = (struct idates **)v2;
	int diff;

	diff = strcoll((*p1)->id_name, (*p2)->id_name);
	if (diff == 0) {
		/*
		 * Time may eventually become unsigned, so can't
		 * rely on subtraction to give a useful result.
		 * Note that we are sorting dates into reverse
		 * order, so that we will report based on the
		 * most-recent record for a particular filesystem.
		 */
		if ((*p1)->id_ddate > (*p2)->id_ddate)
			diff = -1;
		else if ((*p1)->id_ddate < (*p2)->id_ddate)
			diff = 1;
	}
	return (diff);
}
