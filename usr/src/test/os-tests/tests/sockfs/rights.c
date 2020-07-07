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
 * Copyright 2020 OmniOS Community Edition (OmniOSce) Association.
 * Copyright 2020 Joyent, Inc.
 */

/*
 * Test file descriptor passing via SCM_RIGHTS, and in particular what happens
 * on message truncation in terms of the represented size of the data in the
 * control message. Ensure that no file descriptors are leaked - the kernel
 * must close any that would not fit in the available buffer space and the
 * userland application must close the rest.
 */

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <libproc.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <assert.h>
#include <alloca.h>
#include <err.h>

static boolean_t debug;

typedef struct cmsg_test {
	char *name;		/* Name of the test */
	uint_t send;		/* Number of FDs to send */
	uint_t recv;		/* Size receive buffer for this number of FDs */
	size_t predata;		/* Prepend dummy cmsg of this size */
	int bufsize;		/* Explicitly set receive buffer size. */
				/* Overrides 'recv' if non-zero */
	uint_t x_controllen;	/* Expected received msg_controllen */
	uint_t x_cmsg_datalen;	/* Expected received cmsg data length */
	uint32_t x_flags;	/* Expected received msf_flags */
} cmsg_test_t;

static cmsg_test_t tests[] = {
	{
		.name = "send 1, recv 1",
		.send = 1,
		.recv = 1,
		.predata = 0,
		.bufsize = 0,
		.x_controllen = 16,
		.x_cmsg_datalen = 4,
		.x_flags = 0,
	},
	{
		.name = "send 10, recv 10",
		.send = 10,
		.recv = 10,
		.predata = 0,
		.bufsize = 0,
		.x_controllen = 52,
		.x_cmsg_datalen = 40,
		.x_flags = 0,
	},
	{
		.name = "send 2, recv 1",
		.send = 2,
		.recv = 1,
		.predata = 0,
		.bufsize = 0,
		.x_controllen = 16,
		.x_cmsg_datalen = 4,
		.x_flags = MSG_CTRUNC,
	},
	{
		.name = "send 2, recv 1, buffer 5",
		.send = 2,
		.recv = 1,
		.predata = 0,
		.bufsize = sizeof (int) * 2 - 3,
		.x_controllen = 17,
		.x_cmsg_datalen = 5,
		.x_flags = MSG_CTRUNC,
	},
	{
		.name = "send 2, recv 1, buffer 6",
		.send = 2,
		.recv = 1,
		.predata = 0,
		.bufsize = sizeof (int) * 2 - 2,
		.x_controllen = 18,
		.x_cmsg_datalen = 6,
		.x_flags = MSG_CTRUNC,
	},
	{
		.name = "send 2, recv 1, buffer 7",
		.send = 2,
		.recv = 1,
		.predata = 0,
		.bufsize = sizeof (int) * 2 - 1,
		.x_controllen = 19,
		.x_cmsg_datalen = 7,
		.x_flags = MSG_CTRUNC,
	},

	/* Tests where there is no room allowed for data */

	{
		.name = "send 2, recv 0, hdronly",
		.send = 2,
		.recv = 0,
		.predata = 0,
		.bufsize = 0,
		.x_controllen = 12,
		.x_cmsg_datalen = 0,
		.x_flags = MSG_CTRUNC,
	},

	{
		.name = "send 2, recv 0, hdr - 1",
		.send = 2,
		.recv = 0,
		.predata = 0,
		.bufsize = -1,
		.x_controllen = 11,
		.x_cmsg_datalen = 0,
		.x_flags = MSG_CTRUNC,
	},

	{
		.name = "send 2, recv 0, hdr - 5",
		.send = 2,
		.recv = 0,
		.predata = 0,
		.bufsize = -5,
		.x_controllen = 7,
		.x_cmsg_datalen = 0,
		.x_flags = MSG_CTRUNC,
	},

	/* Tests where SCM_RIGHTS is not the first message */

	{
		.name = "send 1, recv 1, pre 8",
		.send = 1,
		.recv = 1,
		.predata = 8,
		.bufsize = 0,
		.x_controllen = 36,
		.x_cmsg_datalen = 4,
		.x_flags = 0,
	},
	{
		.name = "send 1, recv 1, pre 7",
		.send = 1,
		.recv = 1,
		.predata = 7,
		.bufsize = 0,
		.x_controllen = 35,
		.x_cmsg_datalen = 4,
		.x_flags = 0,
	},
	{
		.name = "send 1, recv 1, pre 6",
		.send = 1,
		.recv = 1,
		.predata = 6,
		.bufsize = 0,
		.x_controllen = 34,
		.x_cmsg_datalen = 4,
		.x_flags = 0,
	},
	{
		.name = "send 1, recv 1, pre 5",
		.send = 1,
		.recv = 1,
		.predata = 5,
		.bufsize = 0,
		.x_controllen = 33,
		.x_cmsg_datalen = 4,
		.x_flags = 0,
	},

	{
		.name = "send 2, recv 1, pre 8",
		.send = 2,
		.recv = 1,
		.predata = 8,
		.bufsize = 0,
		.x_controllen = 36,
		.x_cmsg_datalen = 8,
		.x_flags = MSG_CTRUNC,
	},
	{
		.name = "send 2, recv 1, pre 7",
		.send = 2,
		.recv = 1,
		.predata = 7,
		.bufsize = 0,
		.x_controllen = 36,
		.x_cmsg_datalen = 8,
		.x_flags = MSG_CTRUNC,
	},
	{
		.name = "send 2, recv 1, pre 6",
		.send = 2,
		.recv = 1,
		.predata = 6,
		.bufsize = 0,
		.x_controllen = 36,
		.x_cmsg_datalen = 8,
		.x_flags = MSG_CTRUNC,
	},
	{
		.name = "send 2, recv 1, pre 5",
		.send = 2,
		.recv = 1,
		.predata = 5,
		.bufsize = 0,
		.x_controllen = 36,
		.x_cmsg_datalen = 8,
		.x_flags = MSG_CTRUNC,
	},
	{
		.name = "send 2, recv 1, pre 4",
		.send = 2,
		.recv = 1,
		.predata = 4,
		.bufsize = 0,
		.x_controllen = 32,
		.x_cmsg_datalen = 8,
		.x_flags = MSG_CTRUNC,
	},
	{
		.name = "send 2, recv 1, pre 3",
		.send = 2,
		.recv = 1,
		.predata = 3,
		.bufsize = 0,
		.x_controllen = 32,
		.x_cmsg_datalen = 8,
		.x_flags = MSG_CTRUNC,
	},
	{
		.name = "send 2, recv 1, pre 2",
		.send = 2,
		.recv = 1,
		.predata = 2,
		.bufsize = 0,
		.x_controllen = 32,
		.x_cmsg_datalen = 8,
		.x_flags = MSG_CTRUNC,
	},
	{
		.name = "send 2, recv 1, pre 1",
		.send = 2,
		.recv = 1,
		.predata = 1,
		.bufsize = 0,
		.x_controllen = 32,
		.x_cmsg_datalen = 8,
		.x_flags = MSG_CTRUNC,
	},

	{
		.name = "send 2, recv 1, pre 8, buffer 5",
		.send = 2,
		.recv = 1,
		.predata = 8,
		.bufsize = sizeof (int) * 2 - 3,
		.x_controllen = 37,
		.x_cmsg_datalen = 8,
		.x_flags = MSG_CTRUNC,
	},
	{
		.name = "send 2, recv 1, pre 8, buffer 6",
		.send = 2,
		.recv = 1,
		.predata = 8,
		.bufsize = sizeof (int) * 2 - 2,
		.x_controllen = 38,
		.x_cmsg_datalen = 8,
		.x_flags = MSG_CTRUNC,
	},
	{
		.name = "send 2, recv 1, pre 8, buffer 7",
		.send = 2,
		.recv = 1,
		.predata = 8,
		.bufsize = sizeof (int) * 2 - 1,
		.x_controllen = 39,
		.x_cmsg_datalen = 8,
		.x_flags = MSG_CTRUNC,
	},
	{
		.name = "send 10, recv 1, pre 8",
		.send = 10,
		.recv = 1,
		.predata = 8,
		.bufsize = 0,
		.x_controllen = 36,
		.x_cmsg_datalen = 24,
		.x_flags = MSG_CTRUNC,
	},

	/* End of tests */

	{
		.name = NULL
	}
};

static int sock = -1, testfd = -1, cfd = -1;
static int fdcount;

static int
fdwalkcb(const prfdinfo_t *info, void *arg)
{
	if (!S_ISDIR(info->pr_mode) && info->pr_fd > 2 &&
	    info->pr_fd != sock && info->pr_fd != testfd &&
	    info->pr_fd != cfd) {
		if (debug) {
			fprintf(stderr, "%s: unexpected fd: %d\n",
			    (char *)arg, info->pr_fd);
		}
		fdcount++;
	}

	return (0);

}

static void
check_fds(char *tag)
{
	fdcount = 0;
	proc_fdwalk(getpid(), fdwalkcb, tag);
}

static void
send_and_wait(pid_t pid, sigset_t *set, int osig, int isig)
{
	int sig;

	if (osig > 0)
		kill(pid, osig);

	if (isig > 0) {
		if (sigwait(set, &sig) != 0) {
			err(EXIT_FAILURE,
			    "sigwait failed waiting for %d", isig);
		}
		if (sig == SIGINT) {
			exit(1);
		}
		if (sig != isig) {
			err(EXIT_FAILURE,
			    "sigwait returned unexpected signal %d", sig);
		}
	}
}

static void
sendtest(cmsg_test_t *t)
{
	struct msghdr msg;
	struct cmsghdr *cm;
	struct iovec iov;
	ssize_t nbytes;
	char c = '*';
	int i, *p;

	bzero(&msg, sizeof (msg));

	msg.msg_name = NULL;
	msg.msg_namelen = 0;

	iov.iov_base = &c;
	iov.iov_len = sizeof (c);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	msg.msg_flags = 0;

	msg.msg_controllen = CMSG_SPACE(sizeof (int) * t->send);

	if (t->predata > 0) {
		/* A dummy cmsg will be inserted at the head of the data */
		msg.msg_controllen += CMSG_SPACE(t->predata);
	}

	msg.msg_control = alloca(msg.msg_controllen);
	bzero(msg.msg_control, msg.msg_controllen);

	cm = CMSG_FIRSTHDR(&msg);

	if (t->predata > 0) {
		/* Insert the dummy cmsg */
		cm->cmsg_len = CMSG_LEN(t->predata);
		cm->cmsg_level = SOL_SOCKET;
		cm->cmsg_type = 0;
		cm = CMSG_NXTHDR(&msg, cm);
	}

	cm->cmsg_len = CMSG_LEN(sizeof (int) * t->send);
	cm->cmsg_level = SOL_SOCKET;
	cm->cmsg_type = SCM_RIGHTS;

	p = (int *)CMSG_DATA(cm);
	for (i = 0; i < t->send; i++) {
		int s = dup(testfd);
		if (s == -1)
			err(EXIT_FAILURE, "dup()");
		*p++ = s;
	}

	if (debug)
		printf("Sending: controllen=%u\n", msg.msg_controllen);

	nbytes = sendmsg(cfd, &msg, 0);
	if (nbytes == -1)
		err(EXIT_FAILURE, "sendmsg()");

	p = (int *)CMSG_DATA(cm);
	for (i = 0; i < t->send; i++)
		(void) close(*p++);
}

static int
server(const char *sockpath, pid_t pid)
{
	struct sockaddr_un addr;
	sigset_t set;
	cmsg_test_t *t;

	sigemptyset(&set);
	sigaddset(&set, SIGUSR2);
	sigaddset(&set, SIGINT);

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock == -1)
		err(EXIT_FAILURE, "failed to create socket");
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, sockpath, sizeof (addr.sun_path));
	if (bind(sock, (struct sockaddr *)&addr, sizeof (addr)) == -1)
		err(EXIT_FAILURE, "bind failed");
	if (listen(sock, 0) == -1)
		err(EXIT_FAILURE, "listen failed");

	if ((testfd = open("/dev/null", O_RDONLY)) == -1)
		err(EXIT_FAILURE, "/dev/null");

	check_fds("server");

	/* Signal the child to connect to the socket */
	send_and_wait(pid, &set, SIGUSR1, SIGUSR2);

	if ((cfd = accept(sock, NULL, 0)) == -1)
		err(EXIT_FAILURE, "accept failed");

	for (t = tests; t->name != NULL; t++) {
		if (debug)
			printf("\n>>> Starting test %s\n", t->name);

		sendtest(t);
		check_fds("server");

		send_and_wait(pid, &set, SIGUSR1, SIGUSR2);
	}

	close(cfd);
	close(testfd);
	close(sock);

	return (0);
}

static boolean_t pass;

static void
check(uint_t actual, uint_t expected, char *tag)
{
	if (actual != expected) {
		fprintf(stderr, "    !!!: "
		    "%1$s = %2$u(%2$#x) (expected %3$u(%3$#x))\n",
		    tag, actual, expected);
		pass = _B_FALSE;
	} else if (debug) {
		fprintf(stderr, "       : "
		    "%1$s = %2$u(%2$#x)\n",
		    tag, actual);
	}
}

static boolean_t
recvtest(cmsg_test_t *t)
{
	struct msghdr msg;
	struct cmsghdr *cm;
	struct iovec iov;
	size_t bufsize;
	ssize_t nbytes;
	char c = '*';

	bzero(&msg, sizeof (msg));

	msg.msg_name = NULL;
	msg.msg_namelen = 0;

	iov.iov_base = &c;
	iov.iov_len = sizeof (c);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	msg.msg_flags = 0;

	/*
	 * If the test does not specify a receive buffer size, calculate one
	 * from the number of file descriptors to receive.
	 */
	if (t->bufsize == 0) {
		bufsize = sizeof (int) * t->recv;
		bufsize = CMSG_SPACE(bufsize);
	} else {
		/*
		 * Use the specific buffer size provided but add in
		 * space for the header
		 */
		bufsize = t->bufsize + CMSG_LEN(0);
	}

	if (t->predata > 0) {
		/* A dummy cmsg will be found at the head of the data */
		bufsize += CMSG_SPACE(t->predata);
	}

	msg.msg_controllen = bufsize;
	msg.msg_control = alloca(bufsize);
	bzero(msg.msg_control, msg.msg_controllen);

	pass = _B_TRUE;

	if (debug)
		printf("Receiving: controllen=%u, \n", msg.msg_controllen);

	nbytes = recvmsg(sock, &msg, 0);

	if (nbytes == -1) {
		pass = _B_FALSE;
		fprintf(stderr, "recvmsg() failed: %s\n", strerror(errno));
		goto out;
	}

	if (debug) {
		printf("Received: controllen=%u, flags=%#x\n",
		    msg.msg_controllen, msg.msg_flags);
	}

	check(msg.msg_flags, t->x_flags, "msg_flags");
	check(msg.msg_controllen, t->x_controllen, "msg_controllen");

	for (cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
		void *data, *end;

		if (debug) {
			printf("    >> : Got cmsg %x/%x - %u\n", cm->cmsg_level,
			    cm->cmsg_type, cm->cmsg_len);
		}

		if (cm->cmsg_type != SCM_RIGHTS) {
			if (debug)
				printf("       : skipping cmsg\n");
			continue;
		}

		check(cm->cmsg_len - CMSG_LEN(0),
		    t->x_cmsg_datalen, "cmsg_len");

		/* Close any received file descriptors */
		data = CMSG_DATA(cm);

		if ((msg.msg_flags & MSG_CTRUNC) &&
		    CMSG_NXTHDR(&msg, cm) == NULL) {
			/*
			 * illumos did not previously adjust cmsg_len on
			 * truncation. This is the last cmsg, derive the
			 * length from msg_controllen
			 */
			end = msg.msg_control + msg.msg_controllen;
		} else {
			end = data + cm->cmsg_len - CMSG_LEN(0);
		}

		while (data <= end - sizeof (int)) {
			int *a = (int *)data;
			if (debug)
				printf("       : close(%d)\n", *a);
			if (close(*a) == -1) {
				pass = _B_FALSE;
				fprintf(stderr, "    !!!: "
				    "failed to close fd %d - %s\n", *a,
				    strerror(errno));
			}
			data += sizeof (int);
		}
	}

out:

	check_fds("client");
	check(fdcount, 0, "client descriptors");
	printf("     + : %s %s\n", pass ? "PASS" : "FAIL", t->name);

	return (pass);
}

static int
client(const char *sockpath, pid_t pid)
{
	struct sockaddr_un addr;
	sigset_t set;
	cmsg_test_t *t;
	int ret = 0;

	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	sigaddset(&set, SIGINT);

	send_and_wait(pid, &set, 0, SIGUSR1);

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock == -1)
		err(EXIT_FAILURE, "failed to create socket");
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, sockpath, sizeof (addr.sun_path));
	if (connect(sock, (struct sockaddr *)&addr, sizeof (addr)) == -1)
		err(EXIT_FAILURE, "could not connect to server socket");

	for (t = tests; t->name != NULL; t++) {
		send_and_wait(pid, &set, SIGUSR2, SIGUSR1);
		if (!recvtest(t))
			ret = 1;
	}

	close(sock);

	return (ret);
}

int
main(int argc, const char **argv)
{
	char sockpath[] = "/tmp/cmsg.testsock.XXXXXX";
	pid_t pid, ppid;
	sigset_t set;
	int ret = 0;

	/*
	 * The tests make assumptions about the number of open file descriptors
	 * present. In case we are invoked with more than just STDIN_FILENO,
	 * STDOUT_FILENO, and STDERR_FILENO open, close any other open
	 * descriptors that might exist. Otherwise their presence will violate
	 * the assumptions of the test and cause an erroneous failure.
	 */
	closefrom(STDERR_FILENO + 1);

	if (argc > 1 && strcmp(argv[1], "-d") == 0)
		debug = _B_TRUE;

	sigfillset(&set);
	sigdelset(&set, SIGINT);
	sigdelset(&set, SIGTSTP);
	sigprocmask(SIG_BLOCK, &set, NULL);

	if (mktemp(sockpath) == NULL)
		err(EXIT_FAILURE, "Failed to make temporary socket path");

	ppid = getpid();
	pid = fork();
	switch (pid) {
	case -1:
		err(EXIT_FAILURE, "fork failed");
	case 0:
		return (server(sockpath, ppid));
	default:
		break;
	}

	ret = client(sockpath, pid);
	kill(pid, SIGINT);

	unlink(sockpath);

	return (ret);
}
