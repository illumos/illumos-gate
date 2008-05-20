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

/*
 *	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
 *	All rights reserved.
 *
 *	Copyright (c) 1987, 1988 Microsoft Corporation.
 *	All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	sulogin - special login program exec'd from init to let user
 *	come up single user, or go to default init state straight away.
 *
 *	Explain the scoop to the user, and prompt for root password or
 *	^D. Good root password gets you single user, ^D exits sulogin,
 *	and init will go to default init state.
 *
 *	If /etc/passwd is missing, or there's no entry for root,
 *	go single user, no questions asked.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/sysmsg_impl.h>
#include <sys/mkdev.h>
#include <sys/resource.h>
#include <sys/uadmin.h>
#include <sys/wait.h>
#include <sys/stermio.h>
#include <fcntl.h>
#include <termio.h>
#include <pwd.h>
#include <shadow.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <siginfo.h>
#include <utmpx.h>
#include <unistd.h>
#include <ucontext.h>
#include <string.h>
#include <strings.h>
#include <deflt.h>
#include <limits.h>
#include <errno.h>
#include <crypt.h>

/*
 * Intervals to sleep after failed login
 */
#ifndef SLEEPTIME
#define	SLEEPTIME	4	/* sleeptime before login incorrect msg */
#endif

#define	SLEEPTIME_MAX	5	/* maximum sleeptime */

/*
 *	the name of the file containing the login defaults we deliberately
 *	use the same file as login(1)
 */

#define	DEFAULT_LOGIN	"/etc/default/login"
#define	DEFAULT_SULOGIN	"/etc/default/sulogin"
#define	DEFAULT_CONSOLE	"/dev/console"

static char	shell[]	= "/sbin/sh";
static char	su[]	= "/sbin/su.static";
static int	sleeptime	= SLEEPTIME;
static int	nchild = 0;
static pid_t	pidlist[10];
static pid_t	masterpid = 0;
static pid_t	originalpid = 0;
static struct sigaction	sa;
static struct termio	ttymodes;

static char	*findttyname(int fd);
static char	*stripttyname(char *);
static char	*sulogin_getpass(char *);
static void	noop(int);
static void	single(const char *, char *);
static void	main_loop(char *, struct spwd *, boolean_t);
static void	parenthandler();
static void	termhandler(int);
static void	setupsigs(void);
static int	pathcmp(char *, char *);
static void	doit(char *, char *, struct spwd *);
static void	childcleanup(int);

/* ARGSUSED */
int
main(int argc, char **argv)
{
	struct spwd	*shpw;
	int		passreq = B_TRUE;
	int		flags;
	int		fd;
	char		*infop, *ptr, *p;
	pid_t		pid;
	int		bufsize;
	struct stat	st;
	char		cttyname[100];
	char		namedlist[500];
	char		scratchlist[500];
	dev_t		cttyd;

	if (geteuid() != 0) {
		(void) fprintf(stderr, "%s: must be root\n", argv[0]);
		return (EXIT_FAILURE);
	}

	/* Do the magic to determine the children */
	if ((fd = open(SYSMSG, 0)) < 0)
		return (EXIT_FAILURE);

	/*
	 * If the console supports the CIOCTTYCONSOLE ioctl, then fetch
	 * its console device list.  If not, then we use the default
	 * console name.
	 */
	if (ioctl(fd, CIOCTTYCONSOLE, &cttyd) == 0) {
		if ((bufsize = ioctl(fd, CIOCGETCONSOLE, NULL)) < 0)
			return (EXIT_FAILURE);

		if (bufsize > 0) {
			if ((infop = calloc(bufsize, sizeof (char))) == NULL)
				return (EXIT_FAILURE);

			if (ioctl(fd, CIOCGETCONSOLE, infop) < 0)
				return (EXIT_FAILURE);

			(void) snprintf(namedlist, sizeof (namedlist), "%s %s",
			    DEFAULT_CONSOLE, infop);
		} else
			(void) snprintf(namedlist, sizeof (namedlist), "%s",
			    DEFAULT_CONSOLE);
	} else {
		(void) snprintf(namedlist, sizeof (namedlist), "%s",
		    DEFAULT_CONSOLE);
		cttyd = NODEV;
	}

	/*
	 * The attempt to turn the controlling terminals dev_t into a string
	 * may not be successful, thus leaving the variable cttyname as a
	 * NULL.  This occurs if during boot we find
	 * the root partition (or some other partition)
	 * requires manual fsck, thus resulting in sulogin
	 * getting invoked.  The ioctl for CIOCTTYCONSOLE
	 * called above returned NODEV for cttyd
	 * in these cases.  NODEV gets returned when the vnode pointer
	 * in our session structure is NULL.  In these cases it
	 * must be assumed that the default console is used.
	 *
	 * See uts/common/os/session.c:cttydev().
	 */
	(void) strcpy(cttyname, DEFAULT_CONSOLE);
	(void) strcpy(scratchlist, namedlist);
	ptr = scratchlist;
	while (ptr != NULL) {
		p = strchr(ptr, ' ');
		if (p == NULL) {
			if (stat(ptr, &st))
				return (EXIT_FAILURE);
			if (st.st_rdev == cttyd)
				(void) strcpy(cttyname, ptr);
			break;
		}
		*p++ = '\0';
		if (stat(ptr, &st))
			return (EXIT_FAILURE);
		if (st.st_rdev == cttyd) {
			(void) strcpy(cttyname, ptr);
			break;
		}
		ptr = p;
	}

	/*
	 * Use the same value of SLEEPTIME that login(1) uses.  This
	 * is obtained by reading the file /etc/default/login using
	 * the def*() functions.
	 */

	if (defopen(DEFAULT_LOGIN) == 0) {

		/* ignore case */

		flags = defcntl(DC_GETFLAGS, 0);
		TURNOFF(flags, DC_CASE);
		(void) defcntl(DC_SETFLAGS, flags);

		if ((ptr = defread("SLEEPTIME=")) != NULL)
			sleeptime = atoi(ptr);

		if (sleeptime < 0 || sleeptime > SLEEPTIME_MAX)
			sleeptime = SLEEPTIME;

		(void) defopen(NULL);	/* closes DEFAULT_LOGIN */
	}

	/*
	 * Use our own value of PASSREQ, separate from the one login(1) uses.
	 * This is obtained by reading the file /etc/default/sulogin using
	 * the def*() functions.
	 */

	if (defopen(DEFAULT_SULOGIN) == 0) {
		if ((ptr = defread("PASSREQ=")) != NULL)
			if (strcmp("NO", ptr) == 0)
				passreq = B_FALSE;

		(void) defopen(NULL);	/* closes DEFAULT_SULOGIN */
	}

	if (passreq == B_FALSE)
		single(shell, NULL);

	/*
	 * if no 'root' entry in /etc/shadow, give maint. mode single
	 * user shell prompt
	 */
	setspent();
	if ((shpw = getspnam("root")) == NULL) {
		(void) fprintf(stderr, "\n*** Unable to retrieve `root' entry "
		    "in shadow password file ***\n\n");
		single(shell, NULL);
	}
	endspent();
	/*
	 * if no 'root' entry in /etc/passwd, give maint. mode single
	 * user shell prompt
	 */
	setpwent();
	if (getpwnam("root") == NULL) {
		(void) fprintf(stderr, "\n*** Unable to retrieve `root' entry "
		    "in password file ***\n\n");
		single(shell, NULL);
	}
	endpwent();
	/* process with controlling tty treated special */
	if ((pid = fork()) != (pid_t)0) {
		if (pid == -1)
			return (EXIT_FAILURE);
		else {
			setupsigs();
			masterpid = pid;
			originalpid = getpid();
			/*
			 * init() was invoked from a console that was not
			 * the default console, nor was it an auxiliary.
			 */
			if (cttyname[0] == NULL)
				termhandler(0);
				/* Never returns */

			main_loop(cttyname, shpw, B_TRUE);
			/* Never returns */
		}
	}
	masterpid = getpid();
	originalpid = getppid();
	pidlist[nchild++] = originalpid;

	sa.sa_handler = childcleanup;
	sa.sa_flags = 0;
	(void) sigemptyset(&sa.sa_mask);
	(void) sigaction(SIGTERM, &sa, NULL);
	(void) sigaction(SIGHUP, &sa, NULL);
	sa.sa_handler = parenthandler;
	sa.sa_flags = SA_SIGINFO;
	(void) sigemptyset(&sa.sa_mask);
	(void) sigaction(SIGUSR1, &sa, NULL);

	sa.sa_handler = SIG_IGN;
	sa.sa_flags = 0;
	(void) sigemptyset(&sa.sa_mask);
	(void) sigaction(SIGCHLD, &sa, NULL);
	/*
	 * If there isn't a password on root, then don't permit
	 * the fanout capability of sulogin.
	 */
	if (*shpw->sp_pwdp != '\0') {
		ptr = namedlist;
		while (ptr != NULL) {
			p = strchr(ptr, ' ');
			if (p == NULL) {
				doit(ptr, cttyname, shpw);
				break;
			}
			*p++ = '\0';
			doit(ptr, cttyname, shpw);
			ptr = p;
		}
	}
	if (pathcmp(cttyname, DEFAULT_CONSOLE) != 0) {
		if ((pid = fork()) == (pid_t)0) {
			setupsigs();
			main_loop(DEFAULT_CONSOLE, shpw, B_FALSE);
		} else if (pid == -1)
			return (EXIT_FAILURE);
		pidlist[nchild++] = pid;
	}
	/*
	 * When parent is all done, it pauses until one of its children
	 * signals that its time to kill the underpriviledged.
	 */
	(void) wait(NULL);

	return (0);
}

/*
 * These flags are taken from stty's "sane" table entries in
 * usr/src/cmd/ttymon/sttytable.c
 */
#define	SET_IFLAG (BRKINT|IGNPAR|ISTRIP|ICRNL|IXON|IMAXBEL)
#define	RESET_IFLAG (IGNBRK|PARMRK|INPCK|INLCR|IGNCR|IUCLC|IXOFF|IXANY)
#define	SET_OFLAG (OPOST|ONLCR)
#define	RESET_OFLAG (OLCUC|OCRNL|ONOCR|ONLRET|OFILL|OFDEL| \
	NLDLY|CRDLY|TABDLY|BSDLY|VTDLY|FFDLY)
#define	SET_LFLAG (ISIG|ICANON|IEXTEN|ECHO|ECHOK|ECHOE|ECHOKE|ECHOCTL)
#define	RESET_LFLAG (XCASE|ECHONL|NOFLSH|STFLUSH|STWRAP|STAPPL)

/*
 * Do the equivalent of 'stty sane' on the terminal since we don't know
 * what state it was in on startup.
 */
static void
sanitize_tty(int fd)
{
	(void) ioctl(fd, TCGETA, &ttymodes);
	ttymodes.c_iflag &= ~RESET_IFLAG;
	ttymodes.c_iflag |= SET_IFLAG;
	ttymodes.c_oflag &= ~RESET_OFLAG;
	ttymodes.c_oflag |= SET_OFLAG;
	ttymodes.c_lflag &= ~RESET_LFLAG;
	ttymodes.c_lflag |= SET_LFLAG;
	ttymodes.c_cc[VERASE] = CERASE;
	ttymodes.c_cc[VKILL] = CKILL;
	ttymodes.c_cc[VQUIT] = CQUIT;
	ttymodes.c_cc[VINTR] = CINTR;
	ttymodes.c_cc[VEOF] = CEOF;
	ttymodes.c_cc[VEOL] = CNUL;
	(void) ioctl(fd, TCSETAF, &ttymodes);
}

/*
 * Fork a child of sulogin for each of the auxiliary consoles.
 */
static void
doit(char *ptr, char *cttyname, struct spwd *shpw)
{
	pid_t	pid;

	if (pathcmp(ptr, DEFAULT_CONSOLE) != 0 &&
	    pathcmp(ptr, cttyname) != 0) {
		if ((pid = fork()) == (pid_t)0) {
			setupsigs();
			main_loop(ptr, shpw, B_FALSE);
		} else if (pid == -1)
			exit(EXIT_FAILURE);
		pidlist[nchild++] = pid;
	}
}

static int
pathcmp(char *adev, char *bdev)
{
	struct stat	st1;
	struct stat	st2;

	if (adev == NULL || bdev == NULL)
		return (1);

	if (strcmp(adev, bdev) == 0)
		return (0);

	if (stat(adev, &st1) || !S_ISCHR(st1.st_mode))
		return (1);

	if (stat(bdev, &st2) || !S_ISCHR(st2.st_mode))
		return (1);

	if (st1.st_rdev == st2.st_rdev)
		return (0);

	return (1);
}

/* Handlers for the children at initialization */
static void
setupsigs()
{
	sa.sa_handler = noop;
	sa.sa_flags = 0;
	(void) sigemptyset(&sa.sa_mask);
	(void) sigaction(SIGINT, &sa, NULL);
	(void) sigaction(SIGQUIT, &sa, NULL);

	sa.sa_handler = termhandler;
	sa.sa_flags = 0;
	(void) sigemptyset(&sa.sa_mask);
	(void) sigaction(SIGTERM, &sa, NULL);
	(void) sigaction(SIGKILL, &sa, NULL);
	(void) sigaction(SIGHUP, &sa, NULL);
}

static void
main_loop(char *devname, struct spwd *shpw, boolean_t cttyflag)
{
	int		fd, i;
	char		*pass;			/* password from user */
	FILE		*sysmsgfd;

	for (i = 0; i < 3; i++)
		(void) close(i);
	if (cttyflag == B_FALSE) {
		if (setsid() == -1)
			exit(EXIT_FAILURE);
	}
	if ((fd = open(devname, O_RDWR)) < 0)
		exit(EXIT_FAILURE);
	if (fd != 0)
		(void) dup2(fd, STDIN_FILENO);
	if (fd != 1)
		(void) dup2(fd, STDOUT_FILENO);
	if (fd != 2)
		(void) dup2(fd, STDERR_FILENO);
	if (fd > 2)
		(void) close(fd);

	sysmsgfd = fopen("/dev/sysmsg", "w");

	sanitize_tty(fileno(stdin));

	for (;;) {
		(void) fputs("\nRoot password for system maintenance "
		    "(control-d to bypass): ", stdout);

		if ((pass = sulogin_getpass(devname)) == NULL) {
			/* signal other children to exit */
			(void) sigsend(P_PID, masterpid, SIGUSR1);
			/* ^D, so straight to default init state */
			exit(EXIT_FAILURE);
		}
		if (*shpw->sp_pwdp == '\0' && *pass == '\0') {
			(void) fprintf(sysmsgfd,
			    "\nsingle-user privilege assigned to %s.\n",
			    devname);
			(void) sigsend(P_PID, masterpid, SIGUSR1);
			(void) wait(NULL);
			single(su, devname);
		} else if (*shpw->sp_pwdp != '\0') {
			/*
			 * There is a special case error to catch here,
			 * because sulogin is statically linked:
			 * If the root password is hashed with an algorithm
			 * other than the old unix crypt the call to crypt(3c)
			 * could fail if /usr is corrupt or not available
			 * since by default /etc/security/crypt.conf will
			 * have the crypt_ modules located under /usr/lib.
			 *
			 * If this happens crypt(3c) will return NULL and
			 * set errno to ELIBACC, in this case we just give
			 * access because this is similar to the case of
			 * root not existing in /etc/passwd.
			 */
			pass = crypt(pass, shpw->sp_pwdp);
			if ((strcmp(pass, shpw->sp_pwdp) == 0) ||
			    ((pass == NULL) && (errno == ELIBACC) &&
			    (shpw->sp_pwdp[0] == '$'))) {
				(void) fprintf(sysmsgfd,
			    "\nsingle-user privilege assigned to %s.\n",
				    devname);
				(void) sigsend(P_PID, masterpid, SIGUSR1);
				(void) wait(NULL);
				single(su, devname);
			}
		}
		(void) sleep(sleeptime);
		(void) printf("Login incorrect\n");
	}
}

/*
 * single() - exec shell for single user mode
 */

static void
single(const char *cmd, char *ttyn)
{
	struct utmpx	*u;
	char		found = B_FALSE;

	if (ttyn == NULL)
		ttyn = findttyname(STDIN_FILENO);

	/*
	 * utmpx records on the console device are expected to be "console"
	 * by other processes, such as dtlogin.
	 */
	ttyn = stripttyname(ttyn);

	/* update the utmpx file. */
	while ((u = getutxent()) != NULL) {
		if (strcmp(u->ut_line, ttyn) == 0) {
			u->ut_tv.tv_sec = time(NULL);
			u->ut_type = USER_PROCESS;
			u->ut_pid = getpid();
			if (strcmp(u->ut_user, "root") != 0)
				(void) strcpy(u->ut_user, "root");
			(void) pututxline(u);
			found = B_TRUE;
			break;
		}
	}
	if (!found) {
		struct utmpx entryx;

		entryx.ut_tv.tv_sec = time(NULL);
		entryx.ut_type = USER_PROCESS;
		entryx.ut_pid = getpid();
		(void) strcpy(entryx.ut_user, "root");
		(void) strcpy(entryx.ut_line, ttyn);
		entryx.ut_tv.tv_usec = 0;
		entryx.ut_session = 0;
		entryx.ut_id[0] = 'c';
		entryx.ut_id[1] = 'o';
		entryx.ut_id[2] = 's';
		entryx.ut_id[3] = 'u';
		entryx.ut_syslen = 1;
		entryx.ut_host[0] = '\0';
		entryx.ut_exit.e_termination = WTERMSIG(0);
		entryx.ut_exit.e_exit = WEXITSTATUS(0);
		(void) pututxline(&entryx);
	}
	endutxent();
	(void) printf("Entering System Maintenance Mode\n\n");

	if (execl(cmd, cmd, "-", (char *)0) < 0)
		exit(EXIT_FAILURE);
}

/*
 * sulogin_getpass() - hacked from the stdio library version so we can
 *		       distinguish newline and EOF.  also don't need this
 *		       routine to give a prompt.
 *
 * returns the password string, or NULL if the used typed EOF.
 */

static char *
sulogin_getpass(char *devname)
{
	struct termio	ttyb;
	int		c;
	FILE		*fi;
	static char	pbuf[PASS_MAX + 1];
	void		(*saved_handler)();
	char		*rval = pbuf;
	int		i = 0;

	if ((fi = fopen(devname, "r")) == NULL)
		fi = stdin;
	else
		setbuf(fi, NULL);

	saved_handler = signal(SIGINT, SIG_IGN);

	ttyb = ttymodes;
	ttyb.c_lflag &= ~(ECHO | ECHOE | ECHONL);
	(void) ioctl(fileno(fi), TCSETAF, &ttyb);

	while ((c = getc(fi)) != '\n') {

		if (c == EOF && i == 0) { 	/* ^D, No password */
			rval = NULL;
			break;
		}

		if (i < PASS_MAX)
			pbuf[i++] = c;
	}
	pbuf[i] = '\0';
	(void) fputc('\n', fi);
	(void) ioctl(fileno(fi), TCSETAW, &ttymodes);

	if (saved_handler != SIG_ERR)
		(void) signal(SIGINT, saved_handler);

	return (rval);
}

static char *
findttyname(int fd)
{
	char	*ttyn = ttyname(fd);

	if (ttyn == NULL)
		ttyn = "/dev/???";
	else {
		/*
		 * /dev/syscon and /dev/systty are usually links to
		 * /dev/console.  prefer /dev/console.
		 */
		if (((strcmp(ttyn, "/dev/syscon") == 0) ||
		    (strcmp(ttyn, "/dev/systty") == 0)) &&
		    access("/dev/console", F_OK))
			ttyn = "/dev/console";
	}
	return (ttyn);
}

static char *
stripttyname(char *ttyn)
{
	/* saw off the /dev/ */
	if (strncmp(ttyn, "/dev/", sizeof ("/dev/") -1) == 0)
		return (ttyn + sizeof ("/dev/") - 1);
	else
		return (ttyn);
}


/* ARGSUSED */
static	void
noop(int sig)
{
	/*
	 * This signal handler does nothing except return.  We use it
	 * as the signal disposition in this program instead of
	 * SIG_IGN so that we do not have to restore the disposition
	 * back to SIG_DFL. Instead we allow exec(2) to set the
	 * dispostion to SIG_DFL to avoid a race condition.
	 */
}

/* ARGSUSED */
static void
parenthandler(int sig, siginfo_t *si, ucontext_t *uc)
{
	int i;

	/*
	 * We get here if someone has successfully entered a password
	 * from the auxiliary console and is getting the single-user shell.
	 * When this happens, the parent needs to kill the children
	 * that didn't get the shell.
	 *
	 */
	for (i = 0; i < nchild; i++) {
		if (pidlist[i] != si->__data.__proc.__pid)
			(void) sigsend(P_PID, pidlist[i], SIGTERM);
	}
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = 0;
	(void) sigemptyset(&sa.sa_mask);
	(void) sigaction(SIGINT, &sa, NULL);
	(void) sigaction(SIGQUIT, &sa, NULL);
	(void) sigaction(SIGTERM, &sa, NULL);
	(void) wait(NULL);
}

/*
 * The master pid will get SIGTERM or SIGHUP from init, and then
 * has to make sure the shell isn't still running.
 */

/* ARGSUSED */
static	void
childcleanup(int sig)
{
	int i;

	/* Only need to kill the child that became the shell. */
	for (i = 0; i < nchild; i++) {
		/* Don't kill gramps before his time */
		if (pidlist[i] != getppid())
			(void) sigsend(P_PID, pidlist[i], SIGHUP);
	}
}

/* ARGSUSED */
static	void
termhandler(int sig)
{
	FILE *fi;
	pid_t pid;

	/* Processes come here when they fail to receive the password. */
	if ((fi = fopen("/dev/tty", "r+")) == NULL)
		fi = stdin;
	else
		setbuf(fi, NULL);
	sanitize_tty(fileno(fi));
	/* If you're the controlling tty, then just wait */
	pid = getpid();
	if (pid == originalpid || pid == masterpid) {
		sa.sa_handler = SIG_IGN;
		sa.sa_flags = 0;
		(void) sigemptyset(&sa.sa_mask);
		(void) sigaction(SIGINT, &sa, NULL);
		(void) sigaction(SIGQUIT, &sa, NULL);
		sa.sa_handler = SIG_DFL;
		sa.sa_flags = 0;
		(void) sigemptyset(&sa.sa_mask);
		(void) sigaction(SIGTERM, &sa, NULL);
		(void) sigaction(SIGHUP, &sa, NULL);
		(void) wait(NULL);
	}
	exit(0);
}
