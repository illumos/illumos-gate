/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2013 Pluribus Networks Inc.
 */

#include <sys/param.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/termios.h>
#include <assert.h>
#include <errno.h>
#include <libgen.h>
#include <stdarg.h>
#include <stdio.h>
#include <strings.h>
#include <unistd.h>

#include <bhyve.h>

static int masterfd;
static struct termios save_termios;
static int save_fd;

static int nocmdchar = 0;
static char cmdchar = '~';

static const char *pname;

#define	BCONS_BUFSIZ		8192

static void
usage(void)
{
	(void) fprintf(stderr, "usage: %s vmname\n", pname);
	exit(2);
}

static void
bcons_error(const char *fmt, ...)
{
	va_list alist;

	(void) fprintf(stderr, "%s: ", pname);
	va_start(alist, fmt);
	(void) vfprintf(stderr, fmt, alist);
	va_end(alist);
	(void) fprintf(stderr, "\n");
}

static void
bcons_perror(const char *str)
{
	const char *estr;

	if ((estr = strerror(errno)) != NULL)
		(void) fprintf(stderr, "%s: %s: %s\n", pname, str, estr);
	else
		(void) fprintf(stderr, "%s: %s: errno %d\n", pname, str, errno);
}

/*
 * Create the unix domain socket and call bhyve; handshake
 * with it to determine whether it will allow us to connect.
 */
static int
get_console(const char *vmname)
{
	int sockfd = -1;
	struct sockaddr_un servaddr;
	char clientid[MAXPATHLEN];
	char handshake[MAXPATHLEN], c;
	int msglen;
	int i = 0, err = 0;

	if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		bcons_perror("could not create socket");
		return (-1);
	}

	bzero(&servaddr, sizeof (servaddr));
	servaddr.sun_family = AF_UNIX;
	(void) snprintf(servaddr.sun_path, sizeof (servaddr.sun_path),
	    BHYVE_CONS_SOCKPATH, vmname);

	if (connect(sockfd, (struct sockaddr *)&servaddr,
	    sizeof (servaddr)) == -1) {
		bcons_perror("Could not connect to console server");
		goto bad;
	}
	masterfd = sockfd;

	msglen = snprintf(clientid, sizeof (clientid), "IDENT %lu\n",
	    getpid());
	assert(msglen > 0 && msglen < sizeof (clientid));

	if (write(masterfd, clientid, msglen) != msglen) {
		bcons_error("protocol error");
		goto bad;
	}

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
	handshake[i] = '\0';

	/*
	 * If something went wrong during the handshake we bail; perhaps
	 * the server died off.
	 */
	if (err == -1) {
		bcons_perror("Could not connect to console server");
		goto bad;
	}

	if (strncmp(handshake, "OK", sizeof (handshake)) == 0)
		return (0);

	bcons_error("Console is already in use by process ID %s.",
	    handshake);
bad:
	(void) close(sockfd);
	masterfd = -1;
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
		bcons_perror("failed to get user terminal settings");
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
		bcons_perror("failed to set user terminal to raw mode");
		return (-1);
	}

	return (0);
}

/*
 * reset terminal settings for global environment
 */
static void
reset_tty(void)
{
	(void) tcsetattr(save_fd, TCSADRAIN, &save_termios);
}

/*
 * process_user_input watches the input stream for the escape sequence for
 * 'quit' (by default, tilde-period).  Because we might be fed just one
 * keystroke at a time, state associated with the user input (are we at the
 * beginning of the line?  are we locally echoing the next character?) is
 * maintained by beginning_of_line and local_echo across calls to the routine.
 *
 * This routine returns -1 when the 'quit' escape sequence has been issued,
 * or an error is encountered and 0 otherwise.
 */
static int
process_user_input(int out_fd, int in_fd)
{
	static boolean_t beginning_of_line = B_TRUE;
	static boolean_t local_echo = B_FALSE;
	char ibuf[BCONS_BUFSIZ];
	int nbytes;
	char *buf = ibuf;
	char c;

	nbytes = read(in_fd, ibuf, sizeof (ibuf));
	if (nbytes == -1 && errno != EINTR)
		return (-1);

	if (nbytes == -1)	/* The read was interrupted. */
		return (0);

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
			if (c == '.') {
				(void) write(STDOUT_FILENO, &cmdchar, 1);
				(void) write(STDOUT_FILENO, &c, 1);
				return (-1);
			}
		}

		(void) write(out_fd, &c, 1);

		beginning_of_line = (c == '\r' || c == '\n');
	}

	return (0);
}

static int
process_output(int in_fd, int out_fd)
{
	int wrote = 0;
	int cc;
	char ibuf[BCONS_BUFSIZ];

	cc = read(in_fd, ibuf, sizeof (ibuf));
	if (cc == -1 && errno != EINTR)
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
 * This is the main I/O loop.
 */
static void
doio(void)
{
	struct pollfd pollfds[2];
	int res;

	/* read from vm and write to stdout */
	pollfds[0].fd = masterfd;
	pollfds[0].events = POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI;

	/* read from stdin and write to vm */
	pollfds[1].fd = STDIN_FILENO;
	pollfds[1].events = pollfds[0].events;

	for (;;) {
		pollfds[0].revents = pollfds[1].revents = 0;

		res = poll(pollfds,
		    sizeof (pollfds) / sizeof (struct pollfd), -1);

		if (res == -1 && errno != EINTR) {
			bcons_perror("poll failed");
			/* we are hosed, close connection */
			break;
		}

		/* event from master side stdout */
		if (pollfds[0].revents) {
			if (pollfds[0].revents &
			    (POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI)) {
				if (process_output(masterfd, STDOUT_FILENO)
				    != 0)
					break;
			} else {
				break;
			}
		}

		/* event from user stdin side */
		if (pollfds[1].revents) {
			if (pollfds[1].revents &
			    (POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI)) {
			  if (process_user_input(masterfd, STDIN_FILENO)
				    != 0)
					break;
			} else {
				break;
			}
		}
	}
}

int
main(int argc, char **argv)
{
	char *vmname;

	pname = basename(argv[0]);

	if (argc == 2) {
		vmname = argv[1];
	} else {
		usage();
	}

	/*
	 * Make contact with bhyve
	 */
	if (get_console(vmname) == -1)
		return (1);

	(void) printf("[Connected to vm '%s' console]\n", vmname);

	if (set_tty_rawmode(STDIN_FILENO) == -1) {
		reset_tty();
		bcons_perror("failed to set stdin pty to raw mode");
		return (1);
	}

	/*
	 * Run the I/O loop until we get disconnected.
	 */
	doio();
	reset_tty();
	(void) printf("\n[Connection to vm '%s' console closed]\n", vmname);

	return (0);
}
