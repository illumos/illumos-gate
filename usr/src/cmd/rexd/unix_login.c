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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#define	BSD_COMP
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sac.h>		/* for SC_WILDC */
#include <utmpx.h>

#include <rpc/rpc.h>
#include <sys/file.h>
#include <sys/filio.h>
#include <sys/ioctl.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

/*
 * # include <sys/label.h>
 * # include <sys/audit.h>
 *
 *
 *
 * # include <pwdadj.h>
 */

#include <sys/ttold.h>
#include <stropts.h>
#include <sys/stream.h>



#include "rex.h"

#include <security/pam_appl.h>
pam_handle_t *pamh;

#define	NTTYDISC	2	/* New ttydiscipline: stolen from ttold.h */

/*
 * unix_login - hairy junk to simulate logins for Unix
 */

int	Master,	Slave;			/* sides of the pty */
int	Slave_is_closed_on_master_side;

static char	*slavename;
extern char *ptsname();


int	InputSocket,			/* Network sockets */
	OutputSocket;
int	Helper1,			/* pids of the helpers */
	Helper2;
char	UserName[256];			/* saves the user name for loging */
char	HostName[256];			/* saves the host name for loging */

static	int	TtySlot;		/* slot number in Utmpx */

/*
 * pseudo-xprts used to add pty fds to svc_pollfd[]. This allows the
 * polling for all i/o in one poll().
 */
SVCXPRT uxprt[2];

#define	INPUTSOCKET	0		/* InputSocket xprt */
#define	MASTER		1		/* Master xprt */


extern	int child;		/* pid of the executed process */
extern	int ChildDied;		/* flag */
extern	int HasHelper;		/* flag */

extern	void setproctitle(char *user, char *host);
extern int Debug;

extern void audit_rexd_fail(char *, char *, char *, uid_t, gid_t,
				char *, char **);

#define	bzero(s, n)	memset((s), 0, (n))
#define	bcopy(a, b, c)	memcpy((b), (a), (c))

static void LogoutUser(void);

/*
 * Check for user being able to run on this machine.
 * returns 0 if OK, TRUE if problem, error message in "error"
 * copies name of shell and home directory if user is valid.
 */
int
ValidUser(host, uid, gid, error, shell, dir, rst)
	char *host;		/* passed in */
	uid_t uid;
	gid_t gid;
	char *error;		/* filled in on return */
	char *shell;		/* filled in on return */
	char *dir;		/* filled in on return */
	struct rex_start *rst;	/* passed in */
{
	struct passwd *pw, *getpwuid();
	int v;

	pw = getpwuid(uid);
	if (pw == NULL || pw->pw_name == NULL)
	{
		errprintf(error, "rexd: User id %d not valid\n", uid);
		audit_rexd_fail("user id is not valid",
				host,
				NULL,
				uid,
				gid,
				NULL,
				rst->rst_cmd);	    /* BSM */
		return (1);
	}
	strncpy(UserName, pw->pw_name, sizeof (UserName) - 1);
	strncpy(HostName, host, sizeof (HostName) - 1);
	strcpy(shell, pw->pw_shell);
	strcpy(dir, pw->pw_dir);
	setproctitle(pw->pw_name, host);

	if (pam_start("rexd", pw->pw_name, NULL, &pamh) != PAM_SUCCESS ||
	    pam_set_item(pamh, PAM_RHOST, host) != PAM_SUCCESS) {
		audit_rexd_fail("user id is not valid",
				host,
				pw->pw_name,
				uid,
				gid,
				shell,
				rst->rst_cmd);	    /* BSM */
		errprintf(error, "rexd: User id %d not valid\n", uid);
		if (pamh) {
			pam_end(pamh, PAM_ABORT);
			pamh = NULL;
		}
		return (1);
	}

	if ((v = pam_acct_mgmt(pamh, 0)) != PAM_SUCCESS) {
		switch (v) {
		case PAM_NEW_AUTHTOK_REQD:
			errprintf(error,
				"rexd: User id %d Password Expired\n", uid);
			break;
		case PAM_PERM_DENIED:
			errprintf(error,
				"rexd: User id %d Account Expired\n", uid);
			break;
		case PAM_AUTHTOK_EXPIRED:
			errprintf(error,
				"rexd: User id %d Password Expired\n", uid);
			break;
		default:
			errprintf(error,
				"rexd: User id %d not valid\n", uid);
			break;
		}
		pam_end(pamh, PAM_ABORT);
		pamh = NULL;

		audit_rexd_fail("user account expired",
				host,
				pw->pw_name,
				uid,
				gid,
				shell,
				rst->rst_cmd);	    /* BSM */
		return (1);
	}

	return (0);
}

/*
 * Add an audit record with argv that was pre-set, plus the given string
 */

/*
 * Allocate a pseudo-terminal
 * sets the global variables Master and Slave.
 * returns 1 on error, 0 if OK
 */
int
AllocatePty(socket0, socket1)
	int socket0, socket1;
{

	int on = 1;

	sigset(SIGHUP, SIG_IGN);
	sigset(SIGTTOU, SIG_IGN);
	sigset(SIGTTIN, SIG_IGN);

	if ((Master = open("/dev/ptmx", O_RDWR)) == -1) {
	    if (Debug)
		    printf("open-ptmx-failure\n");
	    perror("AloocatePtyMaster fails");
	    return (1);		/* error could not open /dev/ptmx */
	}
	if (Debug)
	    printf("open-ptmx success Master =%d\n", Master);
	if (Debug)
	    printf("Before grantpt...Master=%d\n", Master);

	if (grantpt(Master) == -1) {
	    perror("could not grant slave pty");
	    exit(1);
	}
	if (unlockpt(Master) == -1) {
	    perror("could not unlock slave pty");
	    exit(1);
	}
	if ((slavename = ptsname(Master)) == NULL) {
	    perror("could not enable slave pty");
	    exit(1);
	}
	if ((Slave = open(slavename, O_RDWR)) == -1) {
	    perror("could not open slave pty");
	    exit(1);
	}
	if (ioctl(Slave, I_PUSH, "ptem") == -1) {
	    perror("ioctl I_PUSH ptem");
	    exit(1);
	}
	if (ioctl(Slave, I_PUSH, "ldterm") == -1) {
	    perror("ioctl I_PUSH ldterm");
	    exit(1);
	}
	if (ioctl(Slave, I_PUSH, "ttcompat") == -1) {
	    perror("ioctl I_PUSH ttcompat");
	    exit(1);
	}

	Slave_is_closed_on_master_side = FALSE;
	setsid(); /* get rid of controlling terminal */
	/* LoginUser(); */

	InputSocket = socket0;
	OutputSocket = socket1;
	ioctl(Master, FIONBIO, &on);
	uxprt[INPUTSOCKET].xp_fd = InputSocket;
	xprt_register(&uxprt[INPUTSOCKET]);
	uxprt[MASTER].xp_fd = Master;
	xprt_register(&uxprt[MASTER]);
	return (0);

}

void
OpenPtySlave()
{
	close(Slave);
	Slave = open(slavename, O_RDWR);
	if (Slave < 0) {
		perror(slavename);
		exit(1);
	}
}



	/*
	 * Special processing for interactive operation.
	 * Given pointers to three standard file descriptors,
	 * which get set to point to the pty.
	 */
void
DoHelper(pfd0, pfd1, pfd2)
	int *pfd0, *pfd1, *pfd2;
{
	int pgrp;


	sigset(SIGINT, SIG_IGN);
	close(Master);
	close(InputSocket);
	close(OutputSocket);

	*pfd0 = Slave;
	*pfd1 = Slave;
	*pfd2 = Slave;
}


/*
 * destroy the helpers when the executing process dies
 */
void
KillHelper(int grp)
{
	if (Debug)
		printf("Enter KillHelper\n");
	close(Master);
	xprt_unregister(&uxprt[MASTER]);
	close(InputSocket);
	xprt_unregister(&uxprt[INPUTSOCKET]);
	close(OutputSocket);
	LogoutUser();

	if (grp)
	    kill((-grp), SIGKILL);
}


/*
 * edit the Unix traditional data files that tell who is logged
 * into "the system"
 */
unsigned char	utid[] = {'o', 'n', SC_WILDC, SC_WILDC};

void
LoginUser(void)
{

	char *user;
	char *rhost;
	/* the next 4 variables are needed for utmpx mgmt */
	int		tmplen;
	struct utmpx	*u = NULL;
	struct utmpx	set_utmp;
	char		*ttyntail;

	/* We're pretty drastic here, exiting if an error is detected */
	if (pam_set_item(pamh, PAM_TTY, slavename)	!= PAM_SUCCESS ||
	    pam_get_item(pamh, PAM_USER, (void **) &user) != PAM_SUCCESS ||
	    pam_get_item(pamh, PAM_RHOST, (void **) &rhost) != PAM_SUCCESS ||
	    pam_open_session(pamh, 0)			!= PAM_SUCCESS) {
		/*
		 * XXX should print something but for now we exit
		 */
		exit(1);
	}

	(void) memset((void *)&set_utmp, 0, sizeof (set_utmp));
	(void) time(&set_utmp.ut_tv.tv_sec);
	set_utmp.ut_pid = getpid();
	if (rhost != NULL && rhost[0] != '\0') {
		(void) strcpy(set_utmp.ut_host, rhost);
		tmplen = strlen(rhost) + 1;
		if (tmplen < sizeof (set_utmp.ut_host))
			set_utmp.ut_syslen = tmplen;
		else
			set_utmp.ut_syslen = sizeof (set_utmp.ut_host);
	} else {
		(void) memset(set_utmp.ut_host, 0, sizeof (set_utmp.ut_host));
		set_utmp.ut_syslen = 0;
	}
	(void) strcpy(set_utmp.ut_user, user);

	/*
	 * Copy in the name of the tty minus the "/dev/" if a /dev/ is
	 * in the path name.
	 */
	ttyntail = slavename;
	if (strstr(ttyntail, "/dev/") != 0)
		ttyntail = ttyntail + strlen("/dev/");
	(void) strcpy(set_utmp.ut_line, ttyntail);

	set_utmp.ut_type = USER_PROCESS;
	if (utid != NULL)
		(void) memcpy(set_utmp.ut_id, utid, sizeof (set_utmp.ut_id));
	/*
	 * Go through each entry one by one, looking only at INIT,
	 * LOGIN or USER Processes.  Use the entry found if flags == 0
	 * and the line name matches, or if the process ID matches if
	 * the UPDATE_ENTRY flag is set.  The UPDATE_ENTRY flag is mainly
	 * for login which normally only wants to update an entry if
	 * the pid fields matches.
	 */

	if (u == (struct utmpx *)NULL) {
		(void) makeutx(&set_utmp);
	} else
		updwtmpx(WTMPX_FILE, &set_utmp);

}

/*
 * edit the Unix traditional data files that tell who is logged
 * into "the system".
 */
static void
LogoutUser(void)
{
	struct utmpx *up;
	struct utmpx ut;
	int pid;
	char user[sizeof (ut.ut_user) + 1];
	char ttyn[sizeof (ut.ut_line) + 1];
	char rhost[sizeof (ut.ut_host) + 1];

	sighold(SIGCHLD);		/* no disruption during cleanup */

	if (pamh) {
		pam_end(pamh, PAM_SUCCESS);
		pamh = NULL;
	}

	/* BEGIN RESET UTMP */
	pid = child;
	setutxent();
	while (up = getutxent()) {
		if (up->ut_pid == pid) {
			if (up->ut_type == DEAD_PROCESS) {
				/*
				 * Cleaned up elsewhere.
				 */
				break;
			}

			strncpy(user, up->ut_user, sizeof (up->ut_user));
			user[sizeof (up->ut_user)] = '\0';
			strncpy(ttyn, up->ut_line, sizeof (up->ut_line));
			ttyn[sizeof (up->ut_line)] = '\0';
			strncpy(rhost, up->ut_host, sizeof (up->ut_host));
			rhost[sizeof (up->ut_host)] = '\0';

			if ((pam_start("rexd", user, NULL, &pamh))
							== PAM_SUCCESS) {
				(void) pam_set_item(pamh, PAM_TTY, ttyn);
				(void) pam_set_item(pamh, PAM_RHOST, rhost);
				(void) pam_close_session(pamh, 0);
				(void) pam_end(pamh, PAM_SUCCESS);
				pamh = NULL;
			}

			up->ut_type = DEAD_PROCESS;
			up->ut_exit.e_termination = WTERMSIG(0);
			up->ut_exit.e_exit = WEXITSTATUS(0);
			(void) time(&up->ut_tv.tv_sec);
			if (modutx(up) == NULL) {
				/*
				 * Since modutx failed we'll
				 * write out the new entry
				 * ourselves.
				 */
				(void) pututxline(up);
				updwtmpx("wtmpx", up);
			}
			break;
		}
	}
	endutxent();
	/* END RESET UTMP */
	sigrelse(SIGCHLD);
}

/*
 * set the pty modes to the given values
 */
void
SetPtyMode(mode)
	struct rex_ttymode *mode;
{
	struct sgttyb svr4_sgttyb_var;
	int ldisc = NTTYDISC;

	if (Debug)
		printf("Enter SetPtyMode\n");
	if (Debug)
		printf("SetPtyMode:opened slave\n");
	ioctl(Slave, TIOCSETD, &ldisc);
	if (Debug)
		printf("SetPtyMode:Slave TIOCSETD done\n");

	/*
	 * Copy from over-the-net(bsd) to SVR4 format
	 */
	svr4_sgttyb_var.sg_ispeed = mode->basic.sg_ispeed;
	svr4_sgttyb_var.sg_ospeed = mode->basic.sg_ospeed;
	svr4_sgttyb_var.sg_erase  = mode->basic.sg_erase;
	svr4_sgttyb_var.sg_kill = mode->basic.sg_kill;
	svr4_sgttyb_var.sg_flags = (int)mode->basic.sg_flags;
	/*
	 * Clear any possible sign extension caused by (int)
	 * typecast
	 */
	svr4_sgttyb_var.sg_flags &= 0xFFFF;

	ioctl(Slave, TIOCSETN, &svr4_sgttyb_var);
	if (Debug)
		printf("SetPtyMode:Slave TIOCSETN done\n");
	ioctl(Slave, TIOCSETC, &mode->more);
	if (Debug)
		printf("SetPtyMode:Slave TIOCSETC done\n");
	ioctl(Slave, TIOCSLTC, &mode->yetmore);
	if (Debug)
		printf("SetPtyMode:Slave TIOCSLTC done\n");
	ioctl(Slave, TIOCLSET, &mode->andmore);
	if (Debug)
		printf("SetPtyMode:Slave TIOCSET done\n");

	/* Opened in AllocPty for parent, still open in child */
	if (Slave_is_closed_on_master_side == FALSE) {
		close(Slave);
		Slave_is_closed_on_master_side = TRUE;
	}
}

/*
 * set the pty window size to the given value
 */
void
SetPtySize(struct rex_ttysize *sizep)
{
	struct winsize newsize;

	/* if size has changed, this ioctl changes it */
	/* *and* sends SIGWINCH to process group */

	newsize.ws_row = (unsigned short) sizep->ts_lines;
	newsize.ws_col = (unsigned short) sizep->ts_cols;

	(void) ioctl(Master, TIOCSWINSZ, &newsize);
	if (Slave_is_closed_on_master_side == FALSE) {
		close(Slave);
		Slave_is_closed_on_master_side = TRUE;
	}
}


/*
 * send the given signal to the group controlling the terminal
 */
void
SendSignal(int sig)
{
	pid_t pgrp;

	pgrp = getpgid(child);
	if (pgrp != (pid_t)-1)
		(void) kill((-pgrp), sig);
}

/*
 * called when the main select loop detects that we might want to
 * read something.
 */
void
HelperRead(pollfd_t *fdp, int nfds, int *pollretval)
{
	char buf[128];
	int retval;
	extern int errno;
	int mask;
	int master = -1;
	int inputsocket = -1;

	/*
	 * fdp pollset may be compressed. Search for Master and
	 * InputSocket fds.
	 */
	int i;
	for (i = 0; i < nfds; i++) {
		if (fdp[i].fd == Master && fdp[i].revents != 0)
			master = i;
		if (fdp[i].fd == InputSocket && fdp[i].revents != 0)
			inputsocket = i;
	}

/*	mask = sigsetmask (sigmask (SIGCHLD));	*/
	mask = sighold(SIGCHLD);
	retval = 0;
	if (master != -1) {
		if (!(fdp[master].revents & (POLLERR | POLLHUP | POLLNVAL))) {
			retval = read(Master, buf, sizeof (buf));
			if (retval > 0) {
				(void) write(OutputSocket, buf, retval);
			} else {
				if (errno != EINTR && errno != EIO &&
				    errno != EWOULDBLOCK)
					perror("pty read");
				/* 1 => further sends disallowed */
				shutdown(OutputSocket, 1);
				xprt_unregister(&uxprt[MASTER]);
			}
		}

		/* clear this event for svc_getreq_poll */
		fdp[master].revents = 0;
		*pollretval = *pollretval - 1;

		if (retval <= 0 && ChildDied) {
			KillHelper(child);
			HasHelper = 0;
			if (inputsocket != -1) {
				fdp[inputsocket].revents = 0;
				*pollretval = *pollretval - 1;
			}
			goto done;
		}
	}

	if (inputsocket != -1) {
		if (!(fdp[inputsocket].revents & (POLLERR | POLLHUP |
							    POLLNVAL))) {
			retval = read(InputSocket, buf, sizeof (buf));
			if (retval > 0) {
				(void) write(Master, buf, retval);
			} else {
				if (errno != EINTR && errno != EWOULDBLOCK)
					perror("socket read");
				xprt_unregister(&uxprt[INPUTSOCKET]);
			}
		}

		/* clear this event for svc_getreq_poll */
		fdp[inputsocket].revents = 0;
		*pollretval = *pollretval - 1;
	}

	done:
/*	sigsetmask (mask);	*/
	sigrelse(SIGCHLD);
}
