/*
 * Copyright 2016 Jeremy Allison
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

/*
 * This is a regression test for a (former) problem in illumos
 * where a program that tries to send on a "connected" AF_UNIX
 * _datagram_ socket fails if: (a) the file system path used for
 * the socket requires privileges to access, and (b) a process
 * with privileges to access that path does a connect() to that
 * address and then drops privileges.  In that case, a sendmsg()
 * call where the "to" address is left blank should succeed.
 * Before the fix for illumos 7590 that would fail.
 *
 * This program must be run as root.  The expected output is:
 *
 *	non_priv_send - sendmsg fail (expected) Permission denied
 *	CLIENT:TEST0
 *	SERVER:TEST0
 *	CLIENT:TEST1
 *	SERVER:TEST1
 *	CLIENT:TEST2
 *	SERVER:TEST2
 *	CLIENT:TEST3
 *	SERVER:TEST3
 *	CLIENT:TEST4
 *	SERVER:TEST4
 *
 * Without the fix for 7590, one would see:
 *	non_priv_send - sendmsg fail (expected) Permission denied
 *	CLIENT:TEST0
 *	./sendtest - sendmsg fail Permission denied
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

static int
server(struct sockaddr_un *addr)
{
	int ret;
	pid_t pid;
	int sock;
	unsigned int i;

	pid = fork();
	if (pid == (pid_t)-1) {
		fprintf(stderr, "server - fork fail %s\n", strerror(errno));
		return (-1);
	}

	if (pid != 0) {
		/* Parent. */
		return (0);
	}

	/* Child. */
	sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sock == -1) {
		fprintf(stderr, "server - socket fail %s\n", strerror(errno));
		exit(1);
	}

	ret = bind(sock, (struct sockaddr *)addr, sizeof (*addr));

	if (ret == -1) {
		fprintf(stderr, "server - bind fail %s\n", strerror(errno));
		exit(1);
	}

	for (i = 0; i < 5; i++) {
		struct iovec iov;
		struct msghdr msg;
		uint8_t buf[4096];

		iov = (struct iovec) {
			.iov_base = buf,
			.iov_len = sizeof (buf)
		};

		msg = (struct msghdr) {
			.msg_iov = &iov,
			.msg_iovlen = 1,
		};

		ret = recvmsg(sock, &msg, 0);
		if (ret == -1) {
			fprintf(stderr, "server - recvmsg fail %s\n",
			    strerror(errno));
			exit(1);
		}

		printf("SERVER:%s\n", (char *)msg.msg_iov->iov_base);
		fflush(stdout);
	}

	exit(0);
}

static void
non_priv_send(struct sockaddr_un *addr, int uid)
{
	pid_t pid;
	int sock;
	int ret;
	struct iovec iov;
	struct msghdr msg;
	uint8_t buf[4096];

	pid = fork();
	if (pid == (pid_t)-1) {
		fprintf(stderr, "non_priv_send - fork fail %s\n",
		    strerror(errno));
		return;
	}

	if (pid != 0) {
		/* Parent. */
		return;
	}

	/* Child. */
	memcpy(buf, "TEST1\n", sizeof ("TEST1\n"));

	iov = (struct iovec) {
		.iov_base = buf,
		.iov_len = sizeof (buf),
	};

	msg = (struct msghdr) {
		.msg_name = addr,
		.msg_namelen = sizeof (*addr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sock == -1) {
		fprintf(stderr, "non_priv_send - socket fail %s\n",
		    strerror(errno));
		exit(1);
	}

	ret = setreuid(uid, uid);
	if (ret == -1) {
		fprintf(stderr, "non_priv_send - setresuid fail %s\n",
		    strerror(errno));
		exit(1);
	}

	ret = sendmsg(sock, &msg, 0);

	if (ret == -1) {
		printf("non_priv_send - sendmsg fail (expected) %s\n",
		    strerror(errno));
		exit(0);
	}

	fprintf(stderr, "non_priv_send - UNEXPECTED sendmsg OK\n");
	exit(1);
}

/*
 * This should be a place only root is allowed to write.
 * The test will create and destroy this directory.
 */
char testdir[100] = "/var/run/os-tests-sockfs";
struct sockaddr_un addr;
int test_uid = UID_NOBODY;

int
main(int argc, char **argv)
{
	int ret;
	int sock;
	unsigned int i;
	uid_t us = geteuid();

	/* Ensure we're root. */
	if (us != 0) {
		fprintf(stderr, "%s: need to be root\n", argv[0]);
		exit(1);
	}

	if (argc > 1) {
		ret = strlcpy(testdir, argv[1], sizeof (testdir));
		if (ret >= sizeof (testdir)) {
			fprintf(stderr, "%s: too long\n", argv[1]);
			exit(1);
		}
	}

	addr.sun_family = AF_UNIX;
	(void) sprintf(addr.sun_path, "%s/s", testdir);

	if (mkdir(testdir, 0700) != 0) {
		switch (errno) {
		case EEXIST:
		case EISDIR:
			break;
		default:
			perror(testdir);
			exit(1);
		}
	}
	(void) unlink(addr.sun_path);

	/* Set up the server. */
	ret = server(&addr);
	if (ret == -1) {
		fprintf(stderr, "%s - server fork fail %s\n",
		    argv[0], strerror(errno));
		exit(1);
	}

	sleep(1);

	/* Chec non-priv client - should fail. */
	non_priv_send(&addr, test_uid);

	sleep(1);

	/* Create and connect the socket endpoint. */

	sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sock == -1) {
		fprintf(stderr, "%s - socket fail %s\n",
		    argv[0], strerror(errno));
		exit(1);
	}

	ret = connect(sock, (struct sockaddr *)&addr, sizeof (addr));
	if (ret == -1) {
		fprintf(stderr, "%s - connect fail %s\n",
		    argv[0], strerror(errno));
		exit(1);
	}

	/*
	 * Now lose all privilages.
	 * The sendmsg() should still succeed as
	 * 'sock' has been connected to the endpoint,
	 * even though we don't have permissions as
	 * the non privileged user to access the
	 * UNIX domain socket.
	 */

	ret = setreuid(test_uid, test_uid);
	if (ret == -1) {
		printf("%s - setresuid fail %s\n",
		    argv[0], strerror(errno));
		exit(1);
	}

	for (i = 0; i < 5; i++) {
		struct iovec iov;
		struct msghdr msg;
		uint8_t buf[4096];

		memcpy(buf, "TEST0", sizeof ("TEST0"));
		buf[4] = '0' + i;

		printf("CLIENT:%s\n", buf);

		iov = (struct iovec) {
			.iov_base = buf,
			.iov_len = sizeof (buf),
		};

		msg = (struct msghdr) {
			/*
			 * If not for the dropped privileges that are
			 * the essential feature of this test, a more
			 * common practice would be to fill in the
			 * .msg_name, .msg_namelen fields here.
			 * However, when we've dropped privileges,
			 * and when we do specify the "to" address,
			 * the kernel does permission checks and the
			 * sendmsg fails with permission denied.
			 * So long as we do _not_ fill in the "to"
			 * address, send on a connected dgram socket
			 * is supposed to work.  Before the fix for
			 * illumos 7590, that would fail.
			 */
			.msg_iov = &iov,
			.msg_iovlen = 1,
		};

		ret = sendmsg(sock, &msg, 0);

		if (ret == -1) {
			fprintf(stderr, "%s - sendmsg fail %s\n",
			    argv[0], strerror(errno));
			exit(1);
		}

		fflush(stdout);
		sleep(1);
	}

	close(sock);
	return (0);
}
