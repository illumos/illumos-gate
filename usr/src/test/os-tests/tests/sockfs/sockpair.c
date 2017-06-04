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
#include <pthread.h>

extern char *__progname;

static void *
server(void *varg)
{
	int *sfds = (int *)varg;
	int ret;
	int sock = sfds[0];
	unsigned int i;

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
		if (ret == 0) {
			printf("SERVER: got HUP\n");
			break;
		}

		printf("SERVER:%s\n", (char *)msg.msg_iov->iov_base);
		fflush(stdout);
	}

	close(sock);
	return (NULL);
}

void
runtest(int sotype)
{
	int sfds[2];
	int sock;
	int ret;
	unsigned int i;

	/* Create socketpair */
	ret = socketpair(AF_UNIX, sotype, 0, sfds);
	if (ret == -1) {
		fprintf(stderr, "%s - socketpair fail %s\n",
		    __progname, strerror(errno));
		exit(1);
	}

	/* Set up the server.  It closes sfds[0] when done. */
	ret = pthread_create(NULL, NULL, server, sfds);
	if (ret == -1) {
		fprintf(stderr, "%s - thread create fail %s\n",
		    __progname, strerror(errno));
		exit(1);
	}

	sleep(1);

	/* "Server" is sfds[0], "client" is sfds[1] */
	sock = sfds[1];

	/* Send some messages */
	for (i = 0; i < 3; i++) {
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
			.msg_iov = &iov,
			.msg_iovlen = 1,
		};

		ret = sendmsg(sock, &msg, 0);

		if (ret == -1) {
			fprintf(stderr, "%s - sendmsg fail %s\n",
			    __progname, strerror(errno));
			exit(1);
		}

		fflush(stdout);
		sleep(1);
	}

	/*
	 * Tell sever to terminate
	 */
	if (sotype == SOCK_STREAM) {
		printf("CLIENT: close\n");
		close(sock);
	} else {
		printf("CLIENT: send 0\n");
		send(sock, "", 0, 0);
	}
	sleep(1);
}

int
main(int argc, char **argv)
{

	printf("%s SOCK_STREAM test...\n", argv[0]);
	runtest(SOCK_STREAM);

	printf("%s SOCK_DGRAM test...\n", argv[0]);
	runtest(SOCK_DGRAM);

	return (0);
}
