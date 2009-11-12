/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Code for uid-swapping.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "includes.h"
RCSID("$OpenBSD: uidswap.c,v 1.23 2002/07/15 17:15:31 stevesk Exp $");

#include <priv.h>

#include "log.h"
#include "uidswap.h"
#include "buffer.h"
#include "servconf.h"

/*
 * Note: all these functions must work in all of the following cases:
 *    1. euid=0, ruid=0
 *    2. euid=0, ruid!=0
 *    3. euid!=0, ruid!=0
 * Additionally, they must work regardless of whether the system has
 * POSIX saved uids or not.
 */

#if defined(_POSIX_SAVED_IDS) && !defined(BROKEN_SAVED_UIDS)
/* Lets assume that posix saved ids also work with seteuid, even though that
   is not part of the posix specification. */
#define SAVED_IDS_WORK
/* Saved effective uid. */
static uid_t 	saved_euid = 0;
static gid_t	saved_egid = 0;
#endif

/* Saved effective uid. */
static int	privileged = 0;
static int	temporarily_use_uid_effective = 0;
static gid_t	saved_egroups[NGROUPS_UMAX], user_groups[NGROUPS_UMAX];
static int	saved_egroupslen = -1, user_groupslen = -1;

/*
 * Temporarily changes to the given uid.  If the effective user
 * id is not root, this does nothing.  This call cannot be nested.
 */
void
temporarily_use_uid(struct passwd *pw)
{
	/* Save the current euid, and egroups. */
#ifdef SAVED_IDS_WORK
	saved_euid = geteuid();
	saved_egid = getegid();
	debug("temporarily_use_uid: %u/%u (e=%u/%u)",
	    (u_int)pw->pw_uid, (u_int)pw->pw_gid,
	    (u_int)saved_euid, (u_int)saved_egid);
	if (saved_euid != 0) {
		privileged = 0;
		return;
	}
#else
	if (geteuid() != 0) {
		privileged = 0;
		return;
	}
#endif /* SAVED_IDS_WORK */

	privileged = 1;
	temporarily_use_uid_effective = 1;
	saved_egroupslen = getgroups(NGROUPS_UMAX, saved_egroups);
	if (saved_egroupslen < 0)
		fatal("getgroups: %.100s", strerror(errno));

	/* set and save the user's groups */
	if (user_groupslen == -1) {
		if (initgroups(pw->pw_name, pw->pw_gid) < 0)
			fatal("initgroups: %s: %.100s", pw->pw_name,
			    strerror(errno));
		user_groupslen = getgroups(NGROUPS_UMAX, user_groups);
		if (user_groupslen < 0)
			fatal("getgroups: %.100s", strerror(errno));
	}
	/* Set the effective uid to the given (unprivileged) uid. */
	if (setgroups(user_groupslen, user_groups) < 0)
		fatal("setgroups: %.100s", strerror(errno));
#ifdef SAVED_IDS_WORK
	/* Set saved gid and set real gid */
	if (setregid(pw->pw_gid, -1) == -1)
		debug("setregid(%u, -1): %.100s", (uint_t)pw->pw_gid, strerror(errno));
	/* Set saved uid and set real uid */
	if (setreuid(pw->pw_uid, -1) == -1)
		debug("setreuid(%u, -1): %.100s", (uint_t)pw->pw_uid, strerror(errno));
#else
	/* Propagate the privileged gid to all of our gids. */
	if (setgid(getegid()) < 0)
		debug("setgid %u: %.100s", (u_int) getegid(), strerror(errno));
	/* Propagate the privileged uid to all of our uids. */
	if (setuid(geteuid()) < 0)
		debug("setuid %u: %.100s", (u_int) geteuid(), strerror(errno));
#endif /* SAVED_IDS_WORK */
	/* Set effective gid */
	if (setegid(pw->pw_gid) == -1)
		fatal("setegid %u: %.100s", (u_int)pw->pw_uid,
		    strerror(errno));
	/* Set effective uid */
	if (seteuid(pw->pw_uid) == -1)
		fatal("seteuid %u: %.100s", (u_int)pw->pw_uid,
		    strerror(errno));
	/*
	 * If saved set ids work then
	 *
	 *	ruid == euid == pw->pw_uid
	 *	saved uid = previous euid
	 *	rgid == egid == pw->pw_gid
	 *	saved gid = previous egid
	 */
}

/*
 * Restores to the original (privileged) uid.
 */
void
restore_uid(void)
{
	/* it's a no-op unless privileged */
	if (!privileged) {
		debug("restore_uid: (unprivileged)");
		return;
	}
	if (!temporarily_use_uid_effective)
		fatal("restore_uid: temporarily_use_uid not effective");

#ifdef SAVED_IDS_WORK
	debug("restore_uid: %u/%u", (u_int)saved_euid, (u_int)saved_egid);
	/* Set the effective uid back to the saved privileged uid. */
	if (seteuid(saved_euid) < 0)
		fatal("seteuid %u: %.100s", (u_int)saved_euid, strerror(errno));
	if (setuid(saved_euid) < 0)
		fatal("setuid %u: %.100s", (u_int)saved_euid, strerror(errno));
	if (setegid(saved_egid) < 0)
		fatal("setegid %u: %.100s", (u_int)saved_egid, strerror(errno));
	if (setgid(saved_egid) < 0)
		fatal("setgid %u: %.100s", (u_int)saved_egid, strerror(errno));
#else /* SAVED_IDS_WORK */
	/*
	 * We are unable to restore the real uid to its unprivileged value.
	 * Propagate the real uid (usually more privileged) to effective uid
	 * as well.
	 */
	setuid(getuid());
	setgid(getgid());
#endif /* SAVED_IDS_WORK */

	if (setgroups(saved_egroupslen, saved_egroups) < 0)
		fatal("setgroups: %.100s", strerror(errno));
	temporarily_use_uid_effective = 0;
}

/*
 * Permanently sets all uids to the given uid. This cannot be called while
 * temporarily_use_uid is effective. Note that when the ChrootDirectory option
 * is in use we keep a few privileges so that we can call chroot(2) later while
 * already running under UIDs of a connecting user.
 */
void
permanently_set_uid(struct passwd *pw, char *chroot_directory)
{
	priv_set_t *pset;

	if (temporarily_use_uid_effective)
		fatal("%s: temporarily_use_uid effective", __func__);

	debug("%s: %u/%u", __func__, (u_int)pw->pw_uid, (u_int)pw->pw_gid);

	if (initgroups(pw->pw_name, pw->pw_gid) < 0)
		fatal("initgroups: %s: %.100s", pw->pw_name,
		    strerror(errno));

	if (setgid(pw->pw_gid) < 0)
		fatal("setgid %u: %.100s", (u_int)pw->pw_gid, strerror(errno));

	/*
	 * If root is connecting we are done now. Note that we must have called
	 * setgid() in case that the SSH server was run under a group other than
	 * root.
	 */
	if (pw->pw_uid == 0)
		return;

	/*
	 * This means we will keep all privileges after the UID change.
	 */
	if (setpflags(PRIV_AWARE, 1) != 0)
		fatal("setpflags: %s", strerror(errno));

	/* Now we are running under UID of the user. */
	if (setuid(pw->pw_uid) < 0)
		fatal("setuid %u: %.100s", (u_int)pw->pw_uid, strerror(errno));

	/*
	 * We will run with the privileges from the Inheritable set as
	 * we would have after exec(2) if we had stayed in NPA mode
	 * before setuid(2) call (see privileges(5), user_attr(4), and
	 * pam_unix_cred(5)). We want to run with P = E = I, with I as
	 * set by pam_unix_cred(5). We also add PRIV_PROC_CHROOT,
	 * obviously, and then PRIV_PROC_FORK and PRIV_PROC_EXEC, since
	 * those two might have been removed from the I set. Note that
	 * we are expected to finish the login process without them in
	 * the I set, the important thing is that those not be passed on
	 * to a shell or a subsystem later if they were not set in
	 * pam_unix_cred(5).
	 */
	if ((pset = priv_allocset()) == NULL)
		fatal("priv_allocset: %s", strerror(errno));
	if (getppriv(PRIV_INHERITABLE, pset) != 0)
		fatal("getppriv: %s", strerror(errno));

	/* We do not need PRIV_PROC_CHROOT unless chroot()ing. */
	if (chroot_requested(chroot_directory) &&
	    priv_addset(pset, PRIV_PROC_CHROOT) == -1) {
		fatal("%s: priv_addset failed", __func__);
	}

	if (priv_addset(pset, PRIV_PROC_FORK) == -1 ||
	    priv_addset(pset, PRIV_PROC_EXEC) == -1) {
		fatal("%s: priv_addset failed", __func__);
	}

	/* Set only P; this will also set E. */
	if (setppriv(PRIV_SET, PRIV_PERMITTED, pset) == -1)
		fatal("setppriv: %s", strerror(errno));

	/* We don't need the PA flag anymore. */
	if (setpflags(PRIV_AWARE, 0) == -1)
		fatal("setpflags: %s", strerror(errno));

	priv_freeset(pset);
}
