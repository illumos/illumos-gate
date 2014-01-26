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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 DEY Storage Systems, Inc.
 * Copyright (c) 2014 Gary Mills
 */

/*
 * zlogin provides three types of login which allow users in the global
 * zone to access non-global zones.
 *
 * - "interactive login" is similar to rlogin(1); for example, the user could
 *   issue 'zlogin my-zone' or 'zlogin -e ^ -l me my-zone'.   The user is
 *   granted a new pty (which is then shoved into the zone), and an I/O
 *   loop between parent and child processes takes care of the interactive
 *   session.  In this mode, login(1) (and its -c option, which means
 *   "already authenticated") is employed to take care of the initialization
 *   of the user's session.
 *
 * - "non-interactive login" is similar to su(1M); the user could issue
 *   'zlogin my-zone ls -l' and the command would be run as specified.
 *   In this mode, zlogin sets up pipes as the communication channel, and
 *   'su' is used to do the login setup work.
 *
 * - "console login" is the equivalent to accessing the tip line for a
 *   zone.  For example, the user can issue 'zlogin -C my-zone'.
 *   In this mode, zlogin contacts the zoneadmd process via unix domain
 *   socket.  If zoneadmd is not running, it starts it.  This allows the
 *   console to be available anytime the zone is installed, regardless of
 *   whether it is running.
 */

#include <sys/socket.h>
#include <sys/termios.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/contract/process.h>
#include <sys/ctfs.h>
#include <sys/brand.h>
#include <sys/wait.h>
#include <alloca.h>
#include <assert.h>
#include <ctype.h>
#include <paths.h>
#include <door.h>
#include <errno.h>
#include <nss_dbdefs.h>
#include <poll.h>
#include <priv.h>
#include <pwd.h>
#include <unistd.h>
#include <utmpx.h>
#include <sac.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stropts.h>
#include <wait.h>
#include <zone.h>
#include <fcntl.h>
#include <libdevinfo.h>
#include <libintl.h>
#include <locale.h>
#include <libzonecfg.h>
#include <libcontract.h>
#include <libbrand.h>
#include <auth_list.h>
#include <auth_attr.h>
#include <secdb.h>

static int masterfd;
static struct termios save_termios;
static struct termios effective_termios;
static int save_fd;
static struct winsize winsize;
static volatile int dead;
static volatile pid_t child_pid = -1;
static int interactive = 0;
static priv_set_t *dropprivs;

static int nocmdchar = 0;
static int failsafe = 0;
static char cmdchar = '~';
static int quiet = 0;

static int pollerr = 0;

static const char *pname;
static char *username;

/*
 * When forced_login is true, the user is not prompted
 * for an authentication password in the target zone.
 */
static boolean_t forced_login = B_FALSE;

#if !defined(TEXT_DOMAIN)		/* should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it wasn't */
#endif

#define	SUPATH	"/usr/bin/su"
#define	FAILSAFESHELL	"/sbin/sh"
#define	DEFAULTSHELL	"/sbin/sh"
#define	DEF_PATH	"/usr/sbin:/usr/bin"

#define	CLUSTER_BRAND_NAME	"cluster"

/*
 * The ZLOGIN_BUFSIZ is larger than PIPE_BUF so we can be sure we're clearing
 * out the pipe when the child is exiting.  The ZLOGIN_RDBUFSIZ must be less
 * than ZLOGIN_BUFSIZ (because we share the buffer in doio).  This value is
 * also chosen in conjunction with the HI_WATER setting to make sure we
 * don't fill up the pipe.  We can write FIFOHIWAT (16k) into the pipe before
 * blocking.  By having ZLOGIN_RDBUFSIZ set to 1k and HI_WATER set to 8k, we
 * know we can always write a ZLOGIN_RDBUFSIZ chunk into the pipe when there
 * is less than HI_WATER data already in the pipe.
 */
#define	ZLOGIN_BUFSIZ	8192
#define	ZLOGIN_RDBUFSIZ	1024
#define	HI_WATER	8192

/*
 * See canonify() below.  CANONIFY_LEN is the maximum length that a
 * "canonical" sequence will expand to (backslash, three octal digits, NUL).
 */
#define	CANONIFY_LEN 5

static void
usage(void)
{
	(void) fprintf(stderr, gettext("usage: %s [ -nQCES ] [ -e cmdchar ] "
	    "[-l user] zonename [command [args ...] ]\n"), pname);
	exit(2);
}

static const char *
getpname(const char *arg0)
{
	const char *p = strrchr(arg0, '/');

	if (p == NULL)
		p = arg0;
	else
		p++;

	pname = p;
	return (p);
}

static void
zerror(const char *fmt, ...)
{
	va_list alist;

	(void) fprintf(stderr, "%s: ", pname);
	va_start(alist, fmt);
	(void) vfprintf(stderr, fmt, alist);
	va_end(alist);
	(void) fprintf(stderr, "\n");
}

static void
zperror(const char *str)
{
	const char *estr;

	if ((estr = strerror(errno)) != NULL)
		(void) fprintf(stderr, "%s: %s: %s\n", pname, str, estr);
	else
		(void) fprintf(stderr, "%s: %s: errno %d\n", pname, str, errno);
}

/*
 * The first part of our privilege dropping scheme needs to be called before
 * fork(), since we must have it for security; we don't want to be surprised
 * later that we couldn't allocate the privset.
 */
static int
prefork_dropprivs()
{
	if ((dropprivs = priv_allocset()) == NULL)
		return (1);

	priv_basicset(dropprivs);
	(void) priv_delset(dropprivs, PRIV_PROC_INFO);
	(void) priv_delset(dropprivs, PRIV_PROC_FORK);
	(void) priv_delset(dropprivs, PRIV_PROC_EXEC);
	(void) priv_delset(dropprivs, PRIV_FILE_LINK_ANY);

	/*
	 * We need to keep the basic privilege PROC_SESSION and all unknown
	 * basic privileges as well as the privileges PROC_ZONE and
	 * PROC_OWNER in order to query session information and
	 * send signals.
	 */
	if (interactive == 0) {
		(void) priv_addset(dropprivs, PRIV_PROC_ZONE);
		(void) priv_addset(dropprivs, PRIV_PROC_OWNER);
	} else {
		(void) priv_delset(dropprivs, PRIV_PROC_SESSION);
	}

	return (0);
}

/*
 * The second part of the privilege drop.  We are paranoid about being attacked
 * by the zone, so we drop all privileges.  This should prevent a compromise
 * which gets us to fork(), exec(), symlink(), etc.
 */
static void
postfork_dropprivs()
{
	if ((setppriv(PRIV_SET, PRIV_PERMITTED, dropprivs)) == -1) {
		zperror(gettext("Warning: could not set permitted privileges"));
	}
	if ((setppriv(PRIV_SET, PRIV_LIMIT, dropprivs)) == -1) {
		zperror(gettext("Warning: could not set limit privileges"));
	}
	if ((setppriv(PRIV_SET, PRIV_INHERITABLE, dropprivs)) == -1) {
		zperror(gettext("Warning: could not set inheritable "
		    "privileges"));
	}
}

/*
 * Create the unix domain socket and call the zoneadmd server; handshake
 * with it to determine whether it will allow us to connect.
 */
static int
get_console_master(const char *zname)
{
	int sockfd = -1;
	struct sockaddr_un servaddr;
	char clientid[MAXPATHLEN];
	char handshake[MAXPATHLEN], c;
	int msglen;
	int i = 0, err = 0;

	if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		zperror(gettext("could not create socket"));
		return (-1);
	}

	bzero(&servaddr, sizeof (servaddr));
	servaddr.sun_family = AF_UNIX;
	(void) snprintf(servaddr.sun_path, sizeof (servaddr.sun_path),
	    "%s/%s.console_sock", ZONES_TMPDIR, zname);

	if (connect(sockfd, (struct sockaddr *)&servaddr,
	    sizeof (servaddr)) == -1) {
		zperror(gettext("Could not connect to zone console"));
		goto bad;
	}
	masterfd = sockfd;

	msglen = snprintf(clientid, sizeof (clientid), "IDENT %lu %s\n",
	    getpid(), setlocale(LC_MESSAGES, NULL));

	if (msglen >= sizeof (clientid) || msglen < 0) {
		zerror("protocol error");
		goto bad;
	}

	if (write(masterfd, clientid, msglen) != msglen) {
		zerror("protocol error");
		goto bad;
	}

	bzero(handshake, sizeof (handshake));

	/*
	 * Take care not to accumulate more than our fill, and leave room for
	 * the NUL at the end.
	 */
	while ((err = read(masterfd, &c, 1)) == 1) {
		if (i >= (sizeof (handshake) - 1))
			break;
		if (c == '\n')
			break;
		handshake[i] = c;
		i++;
	}

	/*
	 * If something went wrong during the handshake we bail; perhaps
	 * the server died off.
	 */
	if (err == -1) {
		zperror(gettext("Could not connect to zone console"));
		goto bad;
	}

	if (strncmp(handshake, "OK", sizeof (handshake)) == 0)
		return (0);

	zerror(gettext("Console is already in use by process ID %s."),
	    handshake);
bad:
	(void) close(sockfd);
	masterfd = -1;
	return (-1);
}


/*
 * Routines to handle pty creation upon zone entry and to shuttle I/O back
 * and forth between the two terminals.  We also compute and store the
 * name of the slave terminal associated with the master side.
 */
static int
get_master_pty()
{
	if ((masterfd = open("/dev/ptmx", O_RDWR|O_NONBLOCK)) < 0) {
		zperror(gettext("failed to obtain a pseudo-tty"));
		return (-1);
	}
	if (tcgetattr(STDIN_FILENO, &save_termios) == -1) {
		zperror(gettext("failed to get terminal settings from stdin"));
		return (-1);
	}
	(void) ioctl(STDIN_FILENO, TIOCGWINSZ, (char *)&winsize);

	return (0);
}

/*
 * This is a bit tricky; normally a pts device will belong to the zone it
 * is granted to.  But in the case of "entering" a zone, we need to establish
 * the pty before entering the zone so that we can vector I/O to and from it
 * from the global zone.
 *
 * We use the zonept() call to let the ptm driver know what we are up to;
 * the only other hairy bit is the setting of zoneslavename (which happens
 * above, in get_master_pty()).
 */
static int
init_slave_pty(zoneid_t zoneid, char *devroot)
{
	int slavefd = -1;
	char *slavename, zoneslavename[MAXPATHLEN];

	/*
	 * Set slave permissions, zone the pts, then unlock it.
	 */
	if (grantpt(masterfd) != 0) {
		zperror(gettext("grantpt failed"));
		return (-1);
	}

	if (unlockpt(masterfd) != 0) {
		zperror(gettext("unlockpt failed"));
		return (-1);
	}

	/*
	 * We must open the slave side before zoning this pty; otherwise
	 * the kernel would refuse us the open-- zoning a pty makes it
	 * inaccessible to the global zone.  Note we are trying to open
	 * the device node via the $ZONEROOT/dev path for this pty.
	 *
	 * Later we'll close the slave out when once we've opened it again
	 * from within the target zone.  Blarg.
	 */
	if ((slavename = ptsname(masterfd)) == NULL) {
		zperror(gettext("failed to get name for pseudo-tty"));
		return (-1);
	}

	(void) snprintf(zoneslavename, sizeof (zoneslavename), "%s%s",
	    devroot, slavename);

	if ((slavefd = open(zoneslavename, O_RDWR)) < 0) {
		zerror(gettext("failed to open %s: %s"), zoneslavename,
		    strerror(errno));
		return (-1);
	}

	/*
	 * Push hardware emulation (ptem), line discipline (ldterm),
	 * and V7/4BSD/Xenix compatibility (ttcompat) modules.
	 */
	if (ioctl(slavefd, I_PUSH, "ptem") == -1) {
		zperror(gettext("failed to push ptem module"));
		if (!failsafe)
			goto bad;
	}

	/*
	 * Anchor the stream to prevent malicious I_POPs; we prefer to do
	 * this prior to entering the zone so that we can detect any errors
	 * early, and so that we can set the anchor from the global zone.
	 */
	if (ioctl(slavefd, I_ANCHOR) == -1) {
		zperror(gettext("failed to set stream anchor"));
		if (!failsafe)
			goto bad;
	}

	if (ioctl(slavefd, I_PUSH, "ldterm") == -1) {
		zperror(gettext("failed to push ldterm module"));
		if (!failsafe)
			goto bad;
	}
	if (ioctl(slavefd, I_PUSH, "ttcompat") == -1) {
		zperror(gettext("failed to push ttcompat module"));
		if (!failsafe)
			goto bad;
	}

	/*
	 * Propagate terminal settings from the external term to the new one.
	 */
	if (tcsetattr(slavefd, TCSAFLUSH, &save_termios) == -1) {
		zperror(gettext("failed to set terminal settings"));
		if (!failsafe)
			goto bad;
	}
	(void) ioctl(slavefd, TIOCSWINSZ, (char *)&winsize);

	if (zonept(masterfd, zoneid) != 0) {
		zperror(gettext("could not set zoneid of pty"));
		goto bad;
	}

	return (slavefd);

bad:
	(void) close(slavefd);
	return (-1);
}

/*
 * Place terminal into raw mode.
 */
static int
set_tty_rawmode(int fd)
{
	struct termios term;
	if (tcgetattr(fd, &term) < 0) {
		zperror(gettext("failed to get user terminal settings"));
		return (-1);
	}

	/* Stash for later, so we can revert back to previous mode */
	save_termios = term;
	save_fd = fd;

	/* disable 8->7 bit strip, start/stop, enable any char to restart */
	term.c_iflag &= ~(ISTRIP|IXON|IXANY);
	/* disable NL->CR, CR->NL, ignore CR, UPPER->lower */
	term.c_iflag &= ~(INLCR|ICRNL|IGNCR|IUCLC);
	/* disable output post-processing */
	term.c_oflag &= ~OPOST;
	/* disable canonical mode, signal chars, echo & extended functions */
	term.c_lflag &= ~(ICANON|ISIG|ECHO|IEXTEN);

	term.c_cc[VMIN] = 1;    /* byte-at-a-time */
	term.c_cc[VTIME] = 0;

	if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &term)) {
		zperror(gettext("failed to set user terminal to raw mode"));
		return (-1);
	}

	/*
	 * We need to know the value of VEOF so that we can properly process for
	 * client-side ~<EOF>.  But we have obliterated VEOF in term,
	 * because VMIN overloads the same array slot in non-canonical mode.
	 * Stupid @&^%!
	 *
	 * So here we construct the "effective" termios from the current
	 * terminal settings, and the corrected VEOF and VEOL settings.
	 */
	if (tcgetattr(STDIN_FILENO, &effective_termios) < 0) {
		zperror(gettext("failed to get user terminal settings"));
		return (-1);
	}
	effective_termios.c_cc[VEOF] = save_termios.c_cc[VEOF];
	effective_termios.c_cc[VEOL] = save_termios.c_cc[VEOL];

	return (0);
}

/*
 * Copy terminal window size from our terminal to the pts.
 */
/*ARGSUSED*/
static void
sigwinch(int s)
{
	struct winsize ws;

	if (ioctl(0, TIOCGWINSZ, &ws) == 0)
		(void) ioctl(masterfd, TIOCSWINSZ, &ws);
}

static volatile int close_on_sig = -1;

static void
/*ARGSUSED*/
sigcld(int s)
{
	int status;
	pid_t pid;

	/*
	 * Peek at the exit status.  If this isn't the process we cared
	 * about, then just reap it.
	 */
	if ((pid = waitpid(child_pid, &status, WNOHANG|WNOWAIT)) != -1) {
		if (pid == child_pid &&
		    (WIFEXITED(status) || WIFSIGNALED(status))) {
			dead = 1;
			if (close_on_sig != -1) {
				(void) write(close_on_sig, "a", 1);
				(void) close(close_on_sig);
				close_on_sig = -1;
			}
		} else {
			(void) waitpid(pid, &status, WNOHANG);
		}
	}
}

/*
 * Some signals (currently, SIGINT) must be forwarded on to the process
 * group of the child process.
 */
static void
sig_forward(int s)
{
	if (child_pid != -1) {
		pid_t pgid = getpgid(child_pid);
		if (pgid != -1)
			(void) sigsend(P_PGID, pgid, s);
	}
}

/*
 * reset terminal settings for global environment
 */
static void
reset_tty()
{
	(void) tcsetattr(save_fd, TCSADRAIN, &save_termios);
}

/*
 * Convert character to printable representation, for display with locally
 * echoed command characters (like when we need to display ~^D)
 */
static void
canonify(char c, char *cc)
{
	if (isprint(c)) {
		cc[0] = c;
		cc[1] = '\0';
	} else if (c >= 0 && c <= 31) {	/* ^@ through ^_ */
		cc[0] = '^';
		cc[1] = c + '@';
		cc[2] = '\0';
	} else {
		cc[0] = '\\';
		cc[1] = ((c >> 6) & 7) + '0';
		cc[2] = ((c >> 3) & 7) + '0';
		cc[3] = (c & 7) + '0';
		cc[4] = '\0';
	}
}

/*
 * process_user_input watches the input stream for the escape sequence for
 * 'quit' (by default, tilde-period).  Because we might be fed just one
 * keystroke at a time, state associated with the user input (are we at the
 * beginning of the line?  are we locally echoing the next character?) is
 * maintained by beginning_of_line and local_echo across calls to the routine.
 * If the write to outfd fails, we'll try to read from infd in an attempt
 * to prevent deadlock between the two processes.
 *
 * This routine returns -1 when the 'quit' escape sequence has been issued,
 * or an error is encountered, 1 if stdin is EOF, and 0 otherwise.
 */
static int
process_user_input(int outfd, int infd)
{
	static boolean_t beginning_of_line = B_TRUE;
	static boolean_t local_echo = B_FALSE;
	char ibuf[ZLOGIN_BUFSIZ];
	int nbytes;
	char *buf = ibuf;
	char c = *buf;

	nbytes = read(STDIN_FILENO, ibuf, ZLOGIN_RDBUFSIZ);
	if (nbytes == -1 && (errno != EINTR || dead))
		return (-1);

	if (nbytes == -1)	/* The read was interrupted. */
		return (0);

	/* 0 read means EOF, close the pipe to the child */
	if (nbytes == 0)
		return (1);

	for (c = *buf; nbytes > 0; c = *buf, --nbytes) {
		buf++;
		if (beginning_of_line && !nocmdchar) {
			beginning_of_line = B_FALSE;
			if (c == cmdchar) {
				local_echo = B_TRUE;
				continue;
			}
		} else if (local_echo) {
			local_echo = B_FALSE;
			if (c == '.' || c == effective_termios.c_cc[VEOF]) {
				char cc[CANONIFY_LEN];

				canonify(c, cc);
				(void) write(STDOUT_FILENO, &cmdchar, 1);
				(void) write(STDOUT_FILENO, cc, strlen(cc));
				return (-1);
			}
		}
retry:
		if (write(outfd, &c, 1) <= 0) {
			/*
			 * Since the fd we are writing to is opened with
			 * O_NONBLOCK it is possible to get EAGAIN if the
			 * pipe is full.  One way this could happen is if we
			 * are writing a lot of data into the pipe in this loop
			 * and the application on the other end is echoing that
			 * data back out to its stdout.  The output pipe can
			 * fill up since we are stuck here in this loop and not
			 * draining the other pipe.  We can try to read some of
			 * the data to see if we can drain the pipe so that the
			 * application can continue to make progress.  The read
			 * is non-blocking so we won't hang here.  We also wait
			 * a bit before retrying since there could be other
			 * reasons why the pipe is full and we don't want to
			 * continuously retry.
			 */
			if (errno == EAGAIN) {
				struct timespec rqtp;
				int ln;
				char obuf[ZLOGIN_BUFSIZ];

				if ((ln = read(infd, obuf, ZLOGIN_BUFSIZ)) > 0)
					(void) write(STDOUT_FILENO, obuf, ln);

				/* sleep for 10 milliseconds */
				rqtp.tv_sec = 0;
				rqtp.tv_nsec = 10 * (NANOSEC / MILLISEC);
				(void) nanosleep(&rqtp, NULL);
				if (!dead)
					goto retry;
			}

			return (-1);
		}
		beginning_of_line = (c == '\r' || c == '\n' ||
		    c == effective_termios.c_cc[VKILL] ||
		    c == effective_termios.c_cc[VEOL] ||
		    c == effective_termios.c_cc[VSUSP] ||
		    c == effective_termios.c_cc[VINTR]);
	}
	return (0);
}

/*
 * This function prevents deadlock between zlogin and the application in the
 * zone that it is talking to.  This can happen when we read from zlogin's
 * stdin and write the data down the pipe to the application.  If the pipe
 * is full, we'll block in the write.  Because zlogin could be blocked in
 * the write, it would never read the application's stdout/stderr so the
 * application can then block on those writes (when the pipe fills up).  If the
 * the application gets blocked this way, it can never get around to reading
 * its stdin so that zlogin can unblock from its write.  Once in this state,
 * the two processes are deadlocked.
 *
 * To prevent this, we want to verify that we can write into the pipe before we
 * read from our stdin.  If the pipe already is pretty full, we bypass the read
 * for now.  We'll circle back here again after the poll() so that we can
 * try again.  When this function is called, we already know there is data
 * ready to read on STDIN_FILENO.  We return -1 if there is a problem, 1 if
 * stdin is EOF, and 0 if everything is ok (even though we might not have
 * read/written any data into the pipe on this iteration).
 */
static int
process_raw_input(int stdin_fd, int appin_fd)
{
	int cc;
	struct stat64 sb;
	char ibuf[ZLOGIN_RDBUFSIZ];

	/* Check how much data is already in the pipe */
	if (fstat64(appin_fd, &sb) == -1) {
		perror("stat failed");
		return (-1);
	}

	if (dead)
		return (-1);

	/*
	 * The pipe already has a lot of data in it,  don't write any more
	 * right now.
	 */
	if (sb.st_size >= HI_WATER)
		return (0);

	cc = read(STDIN_FILENO, ibuf, ZLOGIN_RDBUFSIZ);
	if (cc == -1 && (errno != EINTR || dead))
		return (-1);

	if (cc == -1)	/* The read was interrupted. */
		return (0);

	/* 0 read means EOF, close the pipe to the child */
	if (cc == 0)
		return (1);

	/*
	 * stdin_fd is stdin of the target; so, the thing we'll write the user
	 * data *to*.
	 */
	if (write(stdin_fd, ibuf, cc) == -1)
		return (-1);

	return (0);
}

/*
 * Write the output from the application running in the zone.  We can get
 * a signal during the write (usually it would be SIGCHLD when the application
 * has exited) so we loop to make sure we have written all of the data we read.
 */
static int
process_output(int in_fd, int out_fd)
{
	int wrote = 0;
	int cc;
	char ibuf[ZLOGIN_BUFSIZ];

	cc = read(in_fd, ibuf, ZLOGIN_BUFSIZ);
	if (cc == -1 && (errno != EINTR || dead))
		return (-1);
	if (cc == 0)	/* EOF */
		return (-1);
	if (cc == -1)	/* The read was interrupted. */
		return (0);

	do {
		int len;

		len = write(out_fd, ibuf + wrote, cc - wrote);
		if (len == -1 && errno != EINTR)
			return (-1);
		if (len != -1)
			wrote += len;
	} while (wrote < cc);

	return (0);
}

/*
 * This is the main I/O loop, and is shared across all zlogin modes.
 * Parameters:
 * 	stdin_fd:  The fd representing 'stdin' for the slave side; input to
 *		   the zone will be written here.
 *
 * 	appin_fd:  The fd representing the other end of the 'stdin' pipe (when
 *		   we're running non-interactive); used in process_raw_input
 *		   to ensure we don't fill up the application's stdin pipe.
 *
 *	stdout_fd: The fd representing 'stdout' for the slave side; output
 *		   from the zone will arrive here.
 *
 *	stderr_fd: The fd representing 'stderr' for the slave side; output
 *		   from the zone will arrive here.
 *
 *	raw_mode:  If TRUE, then no processing (for example, for '~.') will
 *		   be performed on the input coming from STDIN.
 *
 * stderr_fd may be specified as -1 if there is no stderr (only non-interactive
 * mode supplies a stderr).
 *
 */
static void
doio(int stdin_fd, int appin_fd, int stdout_fd, int stderr_fd, int sig_fd,
    boolean_t raw_mode)
{
	struct pollfd pollfds[4];
	char ibuf[ZLOGIN_BUFSIZ];
	int cc, ret;

	/* read from stdout of zone and write to stdout of global zone */
	pollfds[0].fd = stdout_fd;
	pollfds[0].events = POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI;

	/* read from stderr of zone and write to stderr of global zone */
	pollfds[1].fd = stderr_fd;
	pollfds[1].events = pollfds[0].events;

	/* read from stdin of global zone and write to stdin of zone */
	pollfds[2].fd = STDIN_FILENO;
	pollfds[2].events = pollfds[0].events;

	/* read from signalling pipe so we know when child dies */
	pollfds[3].fd = sig_fd;
	pollfds[3].events = pollfds[0].events;

	for (;;) {
		pollfds[0].revents = pollfds[1].revents =
		    pollfds[2].revents = pollfds[3].revents = 0;

		if (dead)
			break;

		/*
		 * There is a race condition here where we can receive the
		 * child death signal, set the dead flag, but since we have
		 * passed the test above, we would go into poll and hang.
		 * To avoid this we use the sig_fd as an additional poll fd.
		 * The signal handler writes into the other end of this pipe
		 * when the child dies so that the poll will always see that
		 * input and proceed.  We just loop around at that point and
		 * then notice the dead flag.
		 */

		ret = poll(pollfds,
		    sizeof (pollfds) / sizeof (struct pollfd), -1);

		if (ret == -1 && errno != EINTR) {
			perror("poll failed");
			break;
		}

		if (errno == EINTR && dead) {
			break;
		}

		/* event from master side stdout */
		if (pollfds[0].revents) {
			if (pollfds[0].revents &
			    (POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI)) {
				if (process_output(stdout_fd, STDOUT_FILENO)
				    != 0)
					break;
			} else {
				pollerr = pollfds[0].revents;
				break;
			}
		}

		/* event from master side stderr */
		if (pollfds[1].revents) {
			if (pollfds[1].revents &
			    (POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI)) {
				if (process_output(stderr_fd, STDERR_FILENO)
				    != 0)
					break;
			} else {
				pollerr = pollfds[1].revents;
				break;
			}
		}

		/* event from user STDIN side */
		if (pollfds[2].revents) {
			if (pollfds[2].revents &
			    (POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI)) {
				/*
				 * stdin fd is stdin of the target; so,
				 * the thing we'll write the user data *to*.
				 *
				 * Also, unlike on the output side, we
				 * close the pipe on a zero-length message.
				 */
				int res;

				if (raw_mode)
					res = process_raw_input(stdin_fd,
					    appin_fd);
				else
					res = process_user_input(stdin_fd,
					    stdout_fd);

				if (res < 0)
					break;
				if (res > 0) {
					/* EOF (close) child's stdin_fd */
					pollfds[2].fd = -1;
					while ((res = close(stdin_fd)) != 0 &&
					    errno == EINTR)
						;
					if (res != 0)
						break;
				}

			} else if (raw_mode && pollfds[2].revents & POLLHUP) {
				/*
				 * It's OK to get a POLLHUP on STDIN-- it
				 * always happens if you do:
				 *
				 * echo foo | zlogin <zone> <command>
				 *
				 * We reset fd to -1 in this case to clear
				 * the condition and close the pipe (EOF) to
				 * the other side in order to wrap things up.
				 */
				int res;

				pollfds[2].fd = -1;
				while ((res = close(stdin_fd)) != 0 &&
				    errno == EINTR)
					;
				if (res != 0)
					break;
			} else {
				pollerr = pollfds[2].revents;
				break;
			}
		}
	}

	/*
	 * We are in the midst of dying, but try to poll with a short
	 * timeout to see if we can catch the last bit of I/O from the
	 * children.
	 */
retry:
	pollfds[0].revents = pollfds[1].revents = 0;
	(void) poll(pollfds, 2, 100);
	if (pollfds[0].revents &
	    (POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI)) {
		if ((cc = read(stdout_fd, ibuf, ZLOGIN_BUFSIZ)) > 0) {
			(void) write(STDOUT_FILENO, ibuf, cc);
			goto retry;
		}
	}
	if (pollfds[1].revents &
	    (POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI)) {
		if ((cc = read(stderr_fd, ibuf, ZLOGIN_BUFSIZ)) > 0) {
			(void) write(STDERR_FILENO, ibuf, cc);
			goto retry;
		}
	}
}

/*
 * Fetch the user_cmd brand hook for getting a user's passwd(4) entry.
 */
static const char *
zone_get_user_cmd(brand_handle_t bh, const char *login, char *user_cmd,
    size_t len)
{
	bzero(user_cmd, sizeof (user_cmd));
	if (brand_get_user_cmd(bh, login, user_cmd, len) != 0)
		return (NULL);

	return (user_cmd);
}

/* From libc */
extern int str2passwd(const char *, int, void *, char *, int);

/*
 * exec() the user_cmd brand hook, and convert the output string to a
 * struct passwd.  This is to be called after zone_enter().
 *
 */
static struct passwd *
zone_get_user_pw(const char *user_cmd, struct passwd *pwent, char *pwbuf,
    int pwbuflen)
{
	char pwline[NSS_BUFLEN_PASSWD];
	char *cin = NULL;
	FILE *fin;
	int status;

	assert(getzoneid() != GLOBAL_ZONEID);

	if ((fin = popen(user_cmd, "r")) == NULL)
		return (NULL);

	while (cin == NULL && !feof(fin))
		cin = fgets(pwline, sizeof (pwline), fin);

	if (cin == NULL) {
		(void) pclose(fin);
		return (NULL);
	}

	status = pclose(fin);
	if (!WIFEXITED(status))
		return (NULL);
	if (WEXITSTATUS(status) != 0)
		return (NULL);

	if (str2passwd(pwline, sizeof (pwline), pwent, pwbuf, pwbuflen) == 0)
		return (pwent);
	else
		return (NULL);
}

static char **
zone_login_cmd(brand_handle_t bh, const char *login)
{
	static char result_buf[ARG_MAX];
	char **new_argv, *ptr, *lasts;
	int n, a;

	/* Get the login command for the target zone. */
	bzero(result_buf, sizeof (result_buf));

	if (forced_login) {
		if (brand_get_forcedlogin_cmd(bh, login,
		    result_buf, sizeof (result_buf)) != 0)
			return (NULL);
	} else {
		if (brand_get_login_cmd(bh, login,
		    result_buf, sizeof (result_buf)) != 0)
			return (NULL);
	}

	/*
	 * We got back a string that we'd like to execute.  But since
	 * we're not doing the execution via a shell we'll need to convert
	 * the exec string to an array of strings.  We'll do that here
	 * but we're going to be very simplistic about it and break stuff
	 * up based on spaces.  We're not even going to support any kind
	 * of quoting or escape characters.  It's truly amazing that
	 * there is no library function in OpenSolaris to do this for us.
	 */

	/*
	 * Be paranoid.  Since we're deliniating based on spaces make
	 * sure there are no adjacent spaces.
	 */
	if (strstr(result_buf, "  ") != NULL)
		return (NULL);

	/* Remove any trailing whitespace.  */
	n = strlen(result_buf);
	if (result_buf[n - 1] == ' ')
		result_buf[n - 1] = '\0';

	/* Count how many elements there are in the exec string. */
	ptr = result_buf;
	for (n = 2; ((ptr = strchr(ptr + 1, (int)' ')) != NULL); n++)
		;

	/* Allocate the argv array that we're going to return. */
	if ((new_argv = malloc(sizeof (char *) * n)) == NULL)
		return (NULL);

	/* Tokenize the exec string and return. */
	a = 0;
	new_argv[a++] = result_buf;
	if (n > 2) {
		(void) strtok_r(result_buf, " ", &lasts);
		while ((new_argv[a++] = strtok_r(NULL, " ", &lasts)) != NULL)
			;
	} else {
		new_argv[a++] = NULL;
	}
	assert(n == a);
	return (new_argv);
}

/*
 * Prepare argv array for exec'd process; if we're passing commands to the
 * new process, then use su(1M) to do the invocation.  Otherwise, use
 * 'login -z <from_zonename> -f' (-z is an undocumented option which tells
 * login that we're coming from another zone, and to disregard its CONSOLE
 * checks).
 */
static char **
prep_args(brand_handle_t bh, const char *login, char **argv)
{
	int argc = 0, a = 0, i, n = -1;
	char **new_argv;

	if (argv != NULL) {
		size_t subshell_len = 1;
		char *subshell;

		while (argv[argc] != NULL)
			argc++;

		for (i = 0; i < argc; i++) {
			subshell_len += strlen(argv[i]) + 1;
		}
		if ((subshell = calloc(1, subshell_len)) == NULL)
			return (NULL);

		for (i = 0; i < argc; i++) {
			(void) strcat(subshell, argv[i]);
			(void) strcat(subshell, " ");
		}

		if (failsafe) {
			n = 4;
			if ((new_argv = malloc(sizeof (char *) * n)) == NULL)
				return (NULL);

			new_argv[a++] = FAILSAFESHELL;
		} else {
			n = 5;
			if ((new_argv = malloc(sizeof (char *) * n)) == NULL)
				return (NULL);

			new_argv[a++] = SUPATH;
			if (strcmp(login, "root") != 0) {
				new_argv[a++] = "-";
				n++;
			}
			new_argv[a++] = (char *)login;
		}
		new_argv[a++] = "-c";
		new_argv[a++] = subshell;
		new_argv[a++] = NULL;
		assert(a == n);
	} else {
		if (failsafe) {
			n = 2;
			if ((new_argv = malloc(sizeof (char *) * n)) == NULL)
				return (NULL);
			new_argv[a++] = FAILSAFESHELL;
			new_argv[a++] = NULL;
			assert(n == a);
		} else {
			new_argv = zone_login_cmd(bh, login);
		}
	}

	return (new_argv);
}

/*
 * Helper routine for prep_env below.
 */
static char *
add_env(char *name, char *value)
{
	size_t sz = strlen(name) + strlen(value) + 2; /* name, =, value, NUL */
	char *str;

	if ((str = malloc(sz)) == NULL)
		return (NULL);

	(void) snprintf(str, sz, "%s=%s", name, value);
	return (str);
}

/*
 * Prepare envp array for exec'd process.
 */
static char **
prep_env()
{
	int e = 0, size = 1;
	char **new_env, *estr;
	char *term = getenv("TERM");

	size++;	/* for $PATH */
	if (term != NULL)
		size++;

	/*
	 * In failsafe mode we set $HOME, since '-l' isn't valid in this mode.
	 * We also set $SHELL, since neither login nor su will be around to do
	 * it.
	 */
	if (failsafe)
		size += 2;

	if ((new_env = malloc(sizeof (char *) * size)) == NULL)
		return (NULL);

	if ((estr = add_env("PATH", DEF_PATH)) == NULL)
		return (NULL);
	new_env[e++] = estr;

	if (term != NULL) {
		if ((estr = add_env("TERM", term)) == NULL)
			return (NULL);
		new_env[e++] = estr;
	}

	if (failsafe) {
		if ((estr = add_env("HOME", "/")) == NULL)
			return (NULL);
		new_env[e++] = estr;

		if ((estr = add_env("SHELL", FAILSAFESHELL)) == NULL)
			return (NULL);
		new_env[e++] = estr;
	}

	new_env[e++] = NULL;

	assert(e == size);

	return (new_env);
}

/*
 * Finish the preparation of the envp array for exec'd non-interactive
 * zlogins.  This is called in the child process *after* we zone_enter(), since
 * it derives things we can only know within the zone, such as $HOME, $SHELL,
 * etc.  We need only do this in the non-interactive, mode, since otherwise
 * login(1) will do it.  We don't do this in failsafe mode, since it presents
 * additional ways in which the command could fail, and we'd prefer to avoid
 * that.
 */
static char **
prep_env_noninteractive(const char *user_cmd, char **env)
{
	size_t size;
	char **new_env;
	int e, i;
	char *estr;
	char varmail[LOGNAME_MAX + 11]; /* strlen(/var/mail/) = 10, NUL */
	char pwbuf[NSS_BUFLEN_PASSWD + 1];
	struct passwd pwent;
	struct passwd *pw = NULL;

	assert(env != NULL);
	assert(failsafe == 0);

	/*
	 * Exec the "user_cmd" brand hook to get a pwent for the
	 * login user.  If this fails, HOME will be set to "/", SHELL
	 * will be set to $DEFAULTSHELL, and we will continue to exec
	 * SUPATH <login> -c <cmd>.
	 */
	pw = zone_get_user_pw(user_cmd, &pwent, pwbuf, sizeof (pwbuf));

	/*
	 * Get existing envp size.
	 */
	for (size = 0; env[size] != NULL; size++)
		;

	e = size;

	/*
	 * Finish filling out the environment; we duplicate the environment
	 * setup described in login(1), for lack of a better precedent.
	 */
	if (pw != NULL)
		size += 3;	/* LOGNAME, HOME, MAIL */
	else
		size += 1;	/* HOME */

	size++;	/* always fill in SHELL */
	size++; /* terminating NULL */

	if ((new_env = malloc(sizeof (char *) * size)) == NULL)
		goto malloc_fail;

	/*
	 * Copy existing elements of env into new_env.
	 */
	for (i = 0; env[i] != NULL; i++) {
		if ((new_env[i] = strdup(env[i])) == NULL)
			goto malloc_fail;
	}
	assert(e == i);

	if (pw != NULL) {
		if ((estr = add_env("LOGNAME", pw->pw_name)) == NULL)
			goto malloc_fail;
		new_env[e++] = estr;

		if ((estr = add_env("HOME", pw->pw_dir)) == NULL)
			goto malloc_fail;
		new_env[e++] = estr;

		if (chdir(pw->pw_dir) != 0)
			zerror(gettext("Could not chdir to home directory "
			    "%s: %s"), pw->pw_dir, strerror(errno));

		(void) snprintf(varmail, sizeof (varmail), "/var/mail/%s",
		    pw->pw_name);
		if ((estr = add_env("MAIL", varmail)) == NULL)
			goto malloc_fail;
		new_env[e++] = estr;
	} else {
		if ((estr = add_env("HOME", "/")) == NULL)
			goto malloc_fail;
		new_env[e++] = estr;
	}

	if (pw != NULL && strlen(pw->pw_shell) > 0) {
		if ((estr = add_env("SHELL", pw->pw_shell)) == NULL)
			goto malloc_fail;
		new_env[e++] = estr;
	} else {
		if ((estr = add_env("SHELL", DEFAULTSHELL)) == NULL)
			goto malloc_fail;
		new_env[e++] = estr;
	}

	new_env[e++] = NULL;	/* add terminating NULL */

	assert(e == size);
	return (new_env);

malloc_fail:
	zperror(gettext("failed to allocate memory for process environment"));
	return (NULL);
}

static int
close_func(void *slavefd, int fd)
{
	if (fd != *(int *)slavefd)
		(void) close(fd);
	return (0);
}

static void
set_cmdchar(char *cmdcharstr)
{
	char c;
	long lc;

	if ((c = *cmdcharstr) != '\\') {
		cmdchar = c;
		return;
	}

	c = cmdcharstr[1];
	if (c == '\0' || c == '\\') {
		cmdchar = '\\';
		return;
	}

	if (c < '0' || c > '7') {
		zerror(gettext("Unrecognized escape character option %s"),
		    cmdcharstr);
		usage();
	}

	lc = strtol(cmdcharstr + 1, NULL, 8);
	if (lc < 0 || lc > 255) {
		zerror(gettext("Octal escape character '%s' too large"),
		    cmdcharstr);
		usage();
	}
	cmdchar = (char)lc;
}

static int
setup_utmpx(char *slavename)
{
	struct utmpx ut;

	bzero(&ut, sizeof (ut));
	(void) strncpy(ut.ut_user, ".zlogin", sizeof (ut.ut_user));
	(void) strncpy(ut.ut_line, slavename, sizeof (ut.ut_line));
	ut.ut_pid = getpid();
	ut.ut_id[0] = 'z';
	ut.ut_id[1] = ut.ut_id[2] = ut.ut_id[3] = (char)SC_WILDC;
	ut.ut_type = LOGIN_PROCESS;
	(void) time(&ut.ut_tv.tv_sec);

	if (makeutx(&ut) == NULL) {
		zerror(gettext("makeutx failed"));
		return (-1);
	}
	return (0);
}

static void
release_lock_file(int lockfd)
{
	(void) close(lockfd);
}

static int
grab_lock_file(const char *zone_name, int *lockfd)
{
	char pathbuf[PATH_MAX];
	struct flock flock;

	if (mkdir(ZONES_TMPDIR, S_IRWXU) < 0 && errno != EEXIST) {
		zerror(gettext("could not mkdir %s: %s"), ZONES_TMPDIR,
		    strerror(errno));
		return (-1);
	}
	(void) chmod(ZONES_TMPDIR, S_IRWXU);
	(void) snprintf(pathbuf, sizeof (pathbuf), "%s/%s.zoneadm.lock",
	    ZONES_TMPDIR, zone_name);

	if ((*lockfd = open(pathbuf, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR)) < 0) {
		zerror(gettext("could not open %s: %s"), pathbuf,
		    strerror(errno));
		return (-1);
	}
	/*
	 * Lock the file to synchronize with other zoneadmds
	 */
	flock.l_type = F_WRLCK;
	flock.l_whence = SEEK_SET;
	flock.l_start = (off_t)0;
	flock.l_len = (off_t)0;
	if (fcntl(*lockfd, F_SETLKW, &flock) < 0) {
		zerror(gettext("unable to lock %s: %s"), pathbuf,
		    strerror(errno));
		release_lock_file(*lockfd);
		return (-1);
	}
	return (Z_OK);
}

static int
start_zoneadmd(const char *zone_name)
{
	pid_t retval;
	int pstatus = 0, error = -1, lockfd, doorfd;
	struct door_info info;
	char doorpath[MAXPATHLEN];

	(void) snprintf(doorpath, sizeof (doorpath), ZONE_DOOR_PATH, zone_name);

	if (grab_lock_file(zone_name, &lockfd) != Z_OK)
		return (-1);
	/*
	 * We must do the door check with the lock held.  Otherwise, we
	 * might race against another zoneadm/zlogin process and wind
	 * up with two processes trying to start zoneadmd at the same
	 * time.  zoneadmd will detect this, and fail, but we prefer this
	 * to be as seamless as is practical, from a user perspective.
	 */
	if ((doorfd = open(doorpath, O_RDONLY)) < 0) {
		if (errno != ENOENT) {
			zerror("failed to open %s: %s", doorpath,
			    strerror(errno));
			goto out;
		}
	} else {
		/*
		 * Seems to be working ok.
		 */
		if (door_info(doorfd, &info) == 0 &&
		    ((info.di_attributes & DOOR_REVOKED) == 0)) {
			error = 0;
			goto out;
		}
	}

	if ((child_pid = fork()) == -1) {
		zperror(gettext("could not fork"));
		goto out;
	} else if (child_pid == 0) {
		/* child process */
		(void) execl("/usr/lib/zones/zoneadmd", "zoneadmd", "-z",
		    zone_name, NULL);
		zperror(gettext("could not exec zoneadmd"));
		_exit(1);
	}

	/* parent process */
	do {
		retval = waitpid(child_pid, &pstatus, 0);
	} while (retval != child_pid);
	if (WIFSIGNALED(pstatus) ||
	    (WIFEXITED(pstatus) && WEXITSTATUS(pstatus) != 0)) {
		zerror(gettext("could not start %s"), "zoneadmd");
		goto out;
	}
	error = 0;
out:
	release_lock_file(lockfd);
	(void) close(doorfd);
	return (error);
}

static int
init_template(void)
{
	int fd;
	int err = 0;

	fd = open64(CTFS_ROOT "/process/template", O_RDWR);
	if (fd == -1)
		return (-1);

	/*
	 * zlogin doesn't do anything with the contract.
	 * Deliver no events, don't inherit, and allow it to be orphaned.
	 */
	err |= ct_tmpl_set_critical(fd, 0);
	err |= ct_tmpl_set_informative(fd, 0);
	err |= ct_pr_tmpl_set_fatal(fd, CT_PR_EV_HWERR);
	err |= ct_pr_tmpl_set_param(fd, CT_PR_PGRPONLY | CT_PR_REGENT);
	if (err || ct_tmpl_activate(fd)) {
		(void) close(fd);
		return (-1);
	}

	return (fd);
}

static int
noninteractive_login(char *zonename, const char *user_cmd, zoneid_t zoneid,
    char **new_args, char **new_env)
{
	pid_t retval;
	int stdin_pipe[2], stdout_pipe[2], stderr_pipe[2], dead_child_pipe[2];
	int child_status;
	int tmpl_fd;
	sigset_t block_cld;

	if ((tmpl_fd = init_template()) == -1) {
		reset_tty();
		zperror(gettext("could not create contract"));
		return (1);
	}

	if (pipe(stdin_pipe) != 0) {
		zperror(gettext("could not create STDIN pipe"));
		return (1);
	}
	/*
	 * When the user types ^D, we get a zero length message on STDIN.
	 * We need to echo that down the pipe to send it to the other side;
	 * but by default, pipes don't propagate zero-length messages.  We
	 * toggle that behavior off using I_SWROPT.  See streamio(7i).
	 */
	if (ioctl(stdin_pipe[0], I_SWROPT, SNDZERO) != 0) {
		zperror(gettext("could not configure STDIN pipe"));
		return (1);

	}
	if (pipe(stdout_pipe) != 0) {
		zperror(gettext("could not create STDOUT pipe"));
		return (1);
	}
	if (pipe(stderr_pipe) != 0) {
		zperror(gettext("could not create STDERR pipe"));
		return (1);
	}

	if (pipe(dead_child_pipe) != 0) {
		zperror(gettext("could not create signalling pipe"));
		return (1);
	}
	close_on_sig = dead_child_pipe[0];

	/*
	 * If any of the pipe FD's winds up being less than STDERR, then we
	 * have a mess on our hands-- and we are lacking some of the I/O
	 * streams we would expect anyway.  So we bail.
	 */
	if (stdin_pipe[0] <= STDERR_FILENO ||
	    stdin_pipe[1] <= STDERR_FILENO ||
	    stdout_pipe[0] <= STDERR_FILENO ||
	    stdout_pipe[1] <= STDERR_FILENO ||
	    stderr_pipe[0] <= STDERR_FILENO ||
	    stderr_pipe[1] <= STDERR_FILENO ||
	    dead_child_pipe[0] <= STDERR_FILENO ||
	    dead_child_pipe[1] <= STDERR_FILENO) {
		zperror(gettext("process lacks valid STDIN, STDOUT, STDERR"));
		return (1);
	}

	if (prefork_dropprivs() != 0) {
		zperror(gettext("could not allocate privilege set"));
		return (1);
	}

	(void) sigset(SIGCLD, sigcld);
	(void) sigemptyset(&block_cld);
	(void) sigaddset(&block_cld, SIGCLD);
	(void) sigprocmask(SIG_BLOCK, &block_cld, NULL);

	if ((child_pid = fork()) == -1) {
		(void) ct_tmpl_clear(tmpl_fd);
		(void) close(tmpl_fd);
		zperror(gettext("could not fork"));
		return (1);
	} else if (child_pid == 0) { /* child process */
		(void) ct_tmpl_clear(tmpl_fd);

		/*
		 * Do a dance to get the pipes hooked up as FD's 0, 1 and 2.
		 */
		(void) close(STDIN_FILENO);
		(void) close(STDOUT_FILENO);
		(void) close(STDERR_FILENO);
		(void) dup2(stdin_pipe[1], STDIN_FILENO);
		(void) dup2(stdout_pipe[1], STDOUT_FILENO);
		(void) dup2(stderr_pipe[1], STDERR_FILENO);
		(void) closefrom(STDERR_FILENO + 1);

		(void) sigset(SIGCLD, SIG_DFL);
		(void) sigprocmask(SIG_UNBLOCK, &block_cld, NULL);
		/*
		 * In case any of stdin, stdout or stderr are streams,
		 * anchor them to prevent malicious I_POPs.
		 */
		(void) ioctl(STDIN_FILENO, I_ANCHOR);
		(void) ioctl(STDOUT_FILENO, I_ANCHOR);
		(void) ioctl(STDERR_FILENO, I_ANCHOR);

		if (zone_enter(zoneid) == -1) {
			zerror(gettext("could not enter zone %s: %s"),
			    zonename, strerror(errno));
			_exit(1);
		}

		/*
		 * For non-native zones, tell libc where it can find locale
		 * specific getttext() messages.
		 */
		if (access("/.SUNWnative/usr/lib/locale", R_OK) == 0)
			(void) bindtextdomain(TEXT_DOMAIN,
			    "/.SUNWnative/usr/lib/locale");
		else if (access("/native/usr/lib/locale", R_OK) == 0)
			(void) bindtextdomain(TEXT_DOMAIN,
			    "/native/usr/lib/locale");

		if (!failsafe)
			new_env = prep_env_noninteractive(user_cmd, new_env);

		if (new_env == NULL) {
			_exit(1);
		}

		/*
		 * Move into a new process group; the zone_enter will have
		 * placed us into zsched's session, and we want to be in
		 * a unique process group.
		 */
		(void) setpgid(getpid(), getpid());

		/*
		 * The child needs to run as root to
		 * execute the su program.
		 */
		if (setuid(0) == -1) {
			zperror(gettext("insufficient privilege"));
			return (1);
		}

		(void) execve(new_args[0], new_args, new_env);
		zperror(gettext("exec failure"));
		_exit(1);
	}
	/* parent */

	/* close pipe sides written by child */
	(void) close(stdout_pipe[1]);
	(void) close(stderr_pipe[1]);

	(void) sigset(SIGINT, sig_forward);

	postfork_dropprivs();

	(void) ct_tmpl_clear(tmpl_fd);
	(void) close(tmpl_fd);

	(void) sigprocmask(SIG_UNBLOCK, &block_cld, NULL);
	doio(stdin_pipe[0], stdin_pipe[1], stdout_pipe[0], stderr_pipe[0],
	    dead_child_pipe[1], B_TRUE);
	do {
		retval = waitpid(child_pid, &child_status, 0);
		if (retval == -1) {
			child_status = 0;
		}
	} while (retval != child_pid && errno != ECHILD);

	return (WEXITSTATUS(child_status));
}

static char *
get_username()
{
	uid_t	uid;
	struct passwd *nptr;

	/*
	 * Authorizations are checked to restrict access based on the
	 * requested operation and zone name, It is assumed that the
	 * program is running with all privileges, but that the real
	 * user ID is that of the user or role on whose behalf we are
	 * operating. So we start by getting the username that will be
	 * used for subsequent authorization checks.
	 */

	uid = getuid();
	if ((nptr = getpwuid(uid)) == NULL) {
		zerror(gettext("could not get user name."));
		_exit(1);
	}
	return (nptr->pw_name);
}

int
main(int argc, char **argv)
{
	int arg, console = 0;
	zoneid_t zoneid;
	zone_state_t st;
	char *login = "root";
	int lflag = 0;
	int nflag = 0;
	char *zonename = NULL;
	char **proc_args = NULL;
	char **new_args, **new_env;
	sigset_t block_cld;
	char devroot[MAXPATHLEN];
	char *slavename, slaveshortname[MAXPATHLEN];
	priv_set_t *privset;
	int tmpl_fd;
	char zonebrand[MAXNAMELEN];
	char default_brand[MAXNAMELEN];
	struct stat sb;
	char kernzone[ZONENAME_MAX];
	brand_handle_t bh;
	char user_cmd[MAXPATHLEN];
	char authname[MAXAUTHS];

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	(void) getpname(argv[0]);
	username = get_username();

	while ((arg = getopt(argc, argv, "nECR:Se:l:Q")) != EOF) {
		switch (arg) {
		case 'C':
			console = 1;
			break;
		case 'E':
			nocmdchar = 1;
			break;
		case 'R':	/* undocumented */
			if (*optarg != '/') {
				zerror(gettext("root path must be absolute."));
				exit(2);
			}
			if (stat(optarg, &sb) == -1 || !S_ISDIR(sb.st_mode)) {
				zerror(
				    gettext("root path must be a directory."));
				exit(2);
			}
			zonecfg_set_root(optarg);
			break;
		case 'Q':
			quiet = 1;
			break;
		case 'S':
			failsafe = 1;
			break;
		case 'e':
			set_cmdchar(optarg);
			break;
		case 'l':
			login = optarg;
			lflag = 1;
			break;
		case 'n':
			nflag = 1;
			break;
		default:
			usage();
		}
	}

	if (console != 0) {

		if (lflag != 0) {
			zerror(gettext(
			    "-l may not be specified for console login"));
			usage();
		}

		if (nflag != 0) {
			zerror(gettext(
			    "-n may not be specified for console login"));
			usage();
		}

		if (failsafe != 0) {
			zerror(gettext(
			    "-S may not be specified for console login"));
			usage();
		}

		if (zonecfg_in_alt_root()) {
			zerror(gettext(
			    "-R may not be specified for console login"));
			exit(2);
		}

	}

	if (failsafe != 0 && lflag != 0) {
		zerror(gettext("-l may not be specified for failsafe login"));
		usage();
	}

	if (optind == (argc - 1)) {
		/*
		 * zone name, no process name; this should be an interactive
		 * as long as STDIN is really a tty.
		 */
		if (nflag != 0) {
			zerror(gettext(
			    "-n may not be specified for interactive login"));
			usage();
		}
		if (isatty(STDIN_FILENO))
			interactive = 1;
		zonename = argv[optind];
	} else if (optind < (argc - 1)) {
		if (console) {
			zerror(gettext("Commands may not be specified for "
			    "console login."));
			usage();
		}
		/* zone name and process name, and possibly some args */
		zonename = argv[optind];
		proc_args = &argv[optind + 1];
		interactive = 0;
	} else {
		usage();
	}

	if (getzoneid() != GLOBAL_ZONEID) {
		zerror(gettext("'%s' may only be used from the global zone"),
		    pname);
		return (1);
	}

	if (strcmp(zonename, GLOBAL_ZONENAME) == 0) {
		zerror(gettext("'%s' not applicable to the global zone"),
		    pname);
		return (1);
	}

	if (zone_get_state(zonename, &st) != Z_OK) {
		zerror(gettext("zone '%s' unknown"), zonename);
		return (1);
	}

	if (st < ZONE_STATE_INSTALLED) {
		zerror(gettext("cannot login to a zone which is '%s'"),
		    zone_state_str(st));
		return (1);
	}

	/*
	 * In both console and non-console cases, we require all privs.
	 * In the console case, because we may need to startup zoneadmd.
	 * In the non-console case in order to do zone_enter(2), zonept()
	 * and other tasks.
	 */

	if ((privset = priv_allocset()) == NULL) {
		zperror(gettext("priv_allocset failed"));
		return (1);
	}

	if (getppriv(PRIV_EFFECTIVE, privset) != 0) {
		zperror(gettext("getppriv failed"));
		priv_freeset(privset);
		return (1);
	}

	if (priv_isfullset(privset) == B_FALSE) {
		zerror(gettext("You lack sufficient privilege to run "
		    "this command (all privs required)"));
		priv_freeset(privset);
		return (1);
	}
	priv_freeset(privset);

	/*
	 * Check if user is authorized for requested usage of the zone
	 */

	(void) snprintf(authname, MAXAUTHS, "%s%s%s",
	    ZONE_MANAGE_AUTH, KV_OBJECT, zonename);
	if (chkauthattr(authname, username) == 0) {
		if (console) {
			zerror(gettext("%s is not authorized for console "
			    "access to  %s zone."),
			    username, zonename);
			return (1);
		} else {
			(void) snprintf(authname, MAXAUTHS, "%s%s%s",
			    ZONE_LOGIN_AUTH, KV_OBJECT, zonename);
			if (failsafe || !interactive) {
				zerror(gettext("%s is not authorized for  "
				    "failsafe or non-interactive login "
				    "to  %s zone."), username, zonename);
				return (1);
			} else if (chkauthattr(authname, username) == 0) {
				zerror(gettext("%s is not authorized "
				    " to login to %s zone."),
				    username, zonename);
				return (1);
			}
		}
	} else {
		forced_login = B_TRUE;
	}

	/*
	 * The console is a separate case from the rest of the code; handle
	 * it first.
	 */
	if (console) {
		/*
		 * Ensure that zoneadmd for this zone is running.
		 */
		if (start_zoneadmd(zonename) == -1)
			return (1);

		/*
		 * Make contact with zoneadmd.
		 */
		if (get_console_master(zonename) == -1)
			return (1);

		if (!quiet)
			(void) printf(
			    gettext("[Connected to zone '%s' console]\n"),
			    zonename);

		if (set_tty_rawmode(STDIN_FILENO) == -1) {
			reset_tty();
			zperror(gettext("failed to set stdin pty to raw mode"));
			return (1);
		}

		(void) sigset(SIGWINCH, sigwinch);
		(void) sigwinch(0);

		/*
		 * Run the I/O loop until we get disconnected.
		 */
		doio(masterfd, -1, masterfd, -1, -1, B_FALSE);
		reset_tty();
		if (!quiet)
			(void) printf(
			    gettext("\n[Connection to zone '%s' console "
			    "closed]\n"), zonename);

		return (0);
	}

	if (st != ZONE_STATE_RUNNING && st != ZONE_STATE_MOUNTED) {
		zerror(gettext("login allowed only to running zones "
		    "(%s is '%s')."), zonename, zone_state_str(st));
		return (1);
	}

	(void) strlcpy(kernzone, zonename, sizeof (kernzone));
	if (zonecfg_in_alt_root()) {
		FILE *fp = zonecfg_open_scratch("", B_FALSE);

		if (fp == NULL || zonecfg_find_scratch(fp, zonename,
		    zonecfg_get_root(), kernzone, sizeof (kernzone)) == -1) {
			zerror(gettext("cannot find scratch zone %s"),
			    zonename);
			if (fp != NULL)
				zonecfg_close_scratch(fp);
			return (1);
		}
		zonecfg_close_scratch(fp);
	}

	if ((zoneid = getzoneidbyname(kernzone)) == -1) {
		zerror(gettext("failed to get zoneid for zone '%s'"),
		    zonename);
		return (1);
	}

	/*
	 * We need the zone root path only if we are setting up a pty.
	 */
	if (zone_get_devroot(zonename, devroot, sizeof (devroot)) == -1) {
		zerror(gettext("could not get dev path for zone %s"),
		    zonename);
		return (1);
	}

	if (zone_get_brand(zonename, zonebrand, sizeof (zonebrand)) != Z_OK) {
		zerror(gettext("could not get brand for zone %s"), zonename);
		return (1);
	}
	/*
	 * In the alternate root environment, the only supported
	 * operations are mount and unmount.  In this case, just treat
	 * the zone as native if it is cluster.  Cluster zones can be
	 * native for the purpose of LU or upgrade, and the cluster
	 * brand may not exist in the miniroot (such as in net install
	 * upgrade).
	 */
	if (zonecfg_default_brand(default_brand,
	    sizeof (default_brand)) != Z_OK) {
		zerror(gettext("unable to determine default brand"));
		return (1);
	}
	if (zonecfg_in_alt_root() &&
	    strcmp(zonebrand, CLUSTER_BRAND_NAME) == 0) {
		(void) strlcpy(zonebrand, default_brand, sizeof (zonebrand));
	}

	if ((bh = brand_open(zonebrand)) == NULL) {
		zerror(gettext("could not open brand for zone %s"), zonename);
		return (1);
	}

	if ((new_args = prep_args(bh, login, proc_args)) == NULL) {
		zperror(gettext("could not assemble new arguments"));
		brand_close(bh);
		return (1);
	}
	/*
	 * Get the brand specific user_cmd.  This command is used to get
	 * a passwd(4) entry for login.
	 */
	if (!interactive && !failsafe) {
		if (zone_get_user_cmd(bh, login, user_cmd,
		    sizeof (user_cmd)) == NULL) {
			zerror(gettext("could not get user_cmd for zone %s"),
			    zonename);
			brand_close(bh);
			return (1);
		}
	}
	brand_close(bh);

	if ((new_env = prep_env()) == NULL) {
		zperror(gettext("could not assemble new environment"));
		return (1);
	}

	if (!interactive) {
		if (nflag) {
			int nfd;

			if ((nfd = open(_PATH_DEVNULL, O_RDONLY)) < 0) {
				zperror(gettext("failed to open null device"));
				return (1);
			}
			if (nfd != STDIN_FILENO) {
				if (dup2(nfd, STDIN_FILENO) < 0) {
					zperror(gettext(
					    "failed to dup2 null device"));
					return (1);
				}
				(void) close(nfd);
			}
			/* /dev/null is now standard input */
		}
		return (noninteractive_login(zonename, user_cmd, zoneid,
		    new_args, new_env));
	}

	if (zonecfg_in_alt_root()) {
		zerror(gettext("cannot use interactive login with scratch "
		    "zone"));
		return (1);
	}

	/*
	 * Things are more complex in interactive mode; we get the
	 * master side of the pty, then place the user's terminal into
	 * raw mode.
	 */
	if (get_master_pty() == -1) {
		zerror(gettext("could not setup master pty device"));
		return (1);
	}

	/*
	 * Compute the "short name" of the pts.  /dev/pts/2 --> pts/2
	 */
	if ((slavename = ptsname(masterfd)) == NULL) {
		zperror(gettext("failed to get name for pseudo-tty"));
		return (1);
	}
	if (strncmp(slavename, "/dev/", strlen("/dev/")) == 0)
		(void) strlcpy(slaveshortname, slavename + strlen("/dev/"),
		    sizeof (slaveshortname));
	else
		(void) strlcpy(slaveshortname, slavename,
		    sizeof (slaveshortname));

	if (!quiet)
		(void) printf(gettext("[Connected to zone '%s' %s]\n"),
		    zonename, slaveshortname);

	if (set_tty_rawmode(STDIN_FILENO) == -1) {
		reset_tty();
		zperror(gettext("failed to set stdin pty to raw mode"));
		return (1);
	}

	if (prefork_dropprivs() != 0) {
		reset_tty();
		zperror(gettext("could not allocate privilege set"));
		return (1);
	}

	/*
	 * We must mask SIGCLD until after we have coped with the fork
	 * sufficiently to deal with it; otherwise we can race and receive the
	 * signal before child_pid has been initialized (yes, this really
	 * happens).
	 */
	(void) sigset(SIGCLD, sigcld);
	(void) sigemptyset(&block_cld);
	(void) sigaddset(&block_cld, SIGCLD);
	(void) sigprocmask(SIG_BLOCK, &block_cld, NULL);

	/*
	 * We activate the contract template at the last minute to
	 * avoid intermediate functions that could be using fork(2)
	 * internally.
	 */
	if ((tmpl_fd = init_template()) == -1) {
		reset_tty();
		zperror(gettext("could not create contract"));
		return (1);
	}

	if ((child_pid = fork()) == -1) {
		(void) ct_tmpl_clear(tmpl_fd);
		reset_tty();
		zperror(gettext("could not fork"));
		return (1);
	} else if (child_pid == 0) { /* child process */
		int slavefd, newslave;

		(void) ct_tmpl_clear(tmpl_fd);
		(void) close(tmpl_fd);

		(void) sigprocmask(SIG_UNBLOCK, &block_cld, NULL);

		if ((slavefd = init_slave_pty(zoneid, devroot)) == -1)
			return (1);

		/*
		 * Close all fds except for the slave pty.
		 */
		(void) fdwalk(close_func, &slavefd);

		/*
		 * Temporarily dup slavefd to stderr; that way if we have
		 * to print out that zone_enter failed, the output will
		 * have somewhere to go.
		 */
		if (slavefd != STDERR_FILENO)
			(void) dup2(slavefd, STDERR_FILENO);

		if (zone_enter(zoneid) == -1) {
			zerror(gettext("could not enter zone %s: %s"),
			    zonename, strerror(errno));
			return (1);
		}

		if (slavefd != STDERR_FILENO)
			(void) close(STDERR_FILENO);

		/*
		 * We take pains to get this process into a new process
		 * group, and subsequently a new session.  In this way,
		 * we'll have a session which doesn't yet have a controlling
		 * terminal.  When we open the slave, it will become the
		 * controlling terminal; no PIDs concerning pgrps or sids
		 * will leak inappropriately into the zone.
		 */
		(void) setpgrp();

		/*
		 * We need the slave pty to be referenced from the zone's
		 * /dev in order to ensure that the devt's, etc are all
		 * correct.  Otherwise we break ttyname and the like.
		 */
		if ((newslave = open(slavename, O_RDWR)) == -1) {
			(void) close(slavefd);
			return (1);
		}
		(void) close(slavefd);
		slavefd = newslave;

		/*
		 * dup the slave to the various FDs, so that when the
		 * spawned process does a write/read it maps to the slave
		 * pty.
		 */
		(void) dup2(slavefd, STDIN_FILENO);
		(void) dup2(slavefd, STDOUT_FILENO);
		(void) dup2(slavefd, STDERR_FILENO);
		if (slavefd != STDIN_FILENO && slavefd != STDOUT_FILENO &&
		    slavefd != STDERR_FILENO) {
			(void) close(slavefd);
		}

		/*
		 * In failsafe mode, we don't use login(1), so don't try
		 * setting up a utmpx entry.
		 */
		if (!failsafe)
			if (setup_utmpx(slaveshortname) == -1)
				return (1);

		/*
		 * The child needs to run as root to
		 * execute the brand's login program.
		 */
		if (setuid(0) == -1) {
			zperror(gettext("insufficient privilege"));
			return (1);
		}

		(void) execve(new_args[0], new_args, new_env);
		zperror(gettext("exec failure"));
		return (1);
	}

	(void) ct_tmpl_clear(tmpl_fd);
	(void) close(tmpl_fd);

	/*
	 * The rest is only for the parent process.
	 */
	(void) sigset(SIGWINCH, sigwinch);

	postfork_dropprivs();

	(void) sigprocmask(SIG_UNBLOCK, &block_cld, NULL);
	doio(masterfd, -1, masterfd, -1, -1, B_FALSE);

	reset_tty();
	if (!quiet)
		(void) fprintf(stderr,
		    gettext("\n[Connection to zone '%s' %s closed]\n"),
		    zonename, slaveshortname);

	if (pollerr != 0) {
		(void) fprintf(stderr, gettext("Error: connection closed due "
		    "to unexpected pollevents=0x%x.\n"), pollerr);
		return (1);
	}

	return (0);
}
