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
 * Copyright 2016 Joyent, Inc.
 */

#include <alloca.h>
#include <door.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/rsa.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	LOG_OOM(SZ)	(void) fprintf(stderr, "Cannot alloca %d bytes\n", SZ)

static const char *DOOR = "/var/tmp/._joyent_sshd_key_is_authorized";
static const char *REQ_FMT_STR = "%s %d %s"; /* name uid fp */
static const int RETURN_SZ = 2;

static const int MAX_ATTEMPTS = 2;
static const int SLEEP_PERIOD = 1;

static int
sshd_allowed_in_capi(struct passwd *pw, const char *fp)
{
	int allowed = 0;
	int fd = -1;
	int blen = 0;
	int attempts = 0;
	char *buf = NULL;
	door_arg_t door_args = {0};

	if (pw == NULL || fp == NULL)
		return (0);

	blen = snprintf(NULL, 0, REQ_FMT_STR, pw->pw_name, pw->pw_uid, fp) + 1;

	buf = (char *)alloca(blen);
	if (buf == NULL) {
		LOG_OOM(blen);
		return (0);
	}

	(void) snprintf(buf, blen, REQ_FMT_STR, pw->pw_name, pw->pw_uid, fp);
	door_args.data_ptr = buf;
	door_args.data_size = blen;

	door_args.rsize = RETURN_SZ;
	door_args.rbuf = alloca(RETURN_SZ);
	if (door_args.rbuf == NULL) {
		LOG_OOM(RETURN_SZ);
		return (0);
	}
	(void) memset(door_args.rbuf, 0, RETURN_SZ);

	do {
		fd = open(DOOR, O_RDWR);
		if (fd < 0) {
			if (errno == ENOENT) {
				/*
				 * On systems which are not running SmartLogin,
				 * such as vanilla SmartOS, the door will be
				 * completely absent.  The sleep/retry loop is
				 * skipped in this case to keep the login
				 * process more lively.
				 */
				perror("smartplugin: door does not exist");
				return (0);
			}
			perror("smartplugin: open (of door FD) failed");
		} else if (door_call(fd, &door_args) < 0) {
			perror("smartplugin: door_call failed");
		} else {
			allowed = atoi(door_args.rbuf);
			if (door_args.rsize > RETURN_SZ) {
				/*
				 * Given what we know about the SmartLogin
				 * daemon on the other end of the door, this
				 * should never occur.  An assert might be
				 * preferable, but that is avoided since the
				 * error can be handled.
				 */
				(void) munmap(door_args.rbuf, door_args.rsize);
			}
			return (allowed);
		}
		if (++attempts < MAX_ATTEMPTS) {
			(void) sleep(SLEEP_PERIOD);
		}
	} while (attempts < MAX_ATTEMPTS);

	return (0);
}

/* ARGSUSED */
int
sshd_user_rsa_key_allowed(struct passwd *pw, RSA *key, const char *fp)
{
	return (sshd_allowed_in_capi(pw, fp));
}

/* ARGSUSED */
int
sshd_user_dsa_key_allowed(struct passwd *pw, DSA *key, const char *fp)
{
	return (sshd_allowed_in_capi(pw, fp));
}


#ifdef __cplusplus
}
#endif
