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
 * Copyright 2022 Oxide Computer Company
 */

#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <stdbool.h>
#include <sys/stropts.h>

/*
 * This is named this way with the hope that it'll be replaced someday by
 * openpty.
 */
bool
openpty(int *mfdp, int *sfdp)
{
	int sfd;
	int mfd = posix_openpt(O_RDWR | O_NOCTTY);
	const char *name;

	if (mfd < 0) {
		warn("failed to open a pseudo-terminal");
		return (false);
	}

	if (grantpt(mfd) != 0 || unlockpt(mfd) != 0) {
		warn("failed to grant and unlock the manager fd");
		(void) close(mfd);
		return (false);
	}

	name = ptsname(mfd);
	if (name == NULL) {
		warnx("failed to get ptsname for fd %d", mfd);
		(void) close(mfd);
		return (false);
	}

	sfd = open(name, O_RDWR | O_NOCTTY);
	if (sfd < 0) {
		warn("failed to open pty %s", name);
		(void) close(mfd);
		return (false);
	}

	if (ioctl(sfd, __I_PUSH_NOCTTY, "ptem") < 0 ||
	    ioctl(sfd, __I_PUSH_NOCTTY, "ldterm") < 0) {
		warn("failed to push streams modules");
		(void) close(mfd);
		(void) close(sfd);
	}

	*sfdp = sfd;
	*mfdp = mfd;
	return (true);
}
