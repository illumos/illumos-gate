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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <fcntl.h>
#include <procfs.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/zone.h>
#include <sys/lx_types.h>
#include <sys/lx_syscall.h>
#include <sys/cred_impl.h>
#include <sys/policy.h>
#include <sys/ucred.h>
#include <sys/syscall.h>
#include <alloca.h>
#include <errno.h>
#include <ucred.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/lx_misc.h>

typedef struct {
	uint32_t version;
	int pid;
} lx_cap_user_header_t;

typedef struct {
	uint32_t effective;
	uint32_t permitted;
	uint32_t inheritable;
} lx_cap_user_data_t;

#define	LX_CAPABILITY_VERSION_1	0x19980330
#define	LX_CAPABILITY_VERSION_2	0x20071026	/* deprecated by Linux */
#define	LX_CAPABILITY_VERSION_3	0x20080522

/*
 * All capabailities for super-user and basic capabilities for regular user.
 * Linux current defines 38 capabilities, the last being CAP_AUDIT_READ.
 * However, for a 32-bit kernel it looks like we only pass back up to
 * CAP_SETFCAP.
 */
#define	LX_ALL_CAPABILITIES	0xFFFFFFFFU

long
lx_setuid16(uintptr_t uid)
{
	return ((setuid(LX_UID16_TO_UID32((lx_uid16_t)uid))) ? -errno : 0);
}

long
lx_getuid16(void)
{
	return ((int)LX_UID32_TO_UID16(getuid()));
}

long
lx_setgid16(uintptr_t gid)
{
	return ((setgid(LX_GID16_TO_GID32((lx_gid16_t)gid))) ? -errno : 0);
}

long
lx_getgid16(void)
{
	return ((int)LX_GID32_TO_GID16(getgid()));
}

long
lx_geteuid16(void)
{
	return ((int)LX_UID32_TO_UID16(geteuid()));
}

long
lx_getegid16(void)
{
	return ((int)LX_GID32_TO_GID16(getegid()));
}

long
lx_geteuid(void)
{
	return ((int)geteuid());
}

long
lx_getegid(void)
{
	return ((int)getegid());
}

long
lx_getresuid(uintptr_t ruid, uintptr_t euid, uintptr_t suid)
{
	lx_uid_t lx_ruid, lx_euid, lx_suid;
	ucred_t	*cr;
	size_t sz;

	/*
	 * We allocate a ucred_t ourselves rather than call ucred_get(3C)
	 * because ucred_get() calls malloc(3C), which the brand library cannot
	 * use.  Because we allocate the space with SAFE_ALLOCA(), there's
	 * no need to free it when we're done.
	 */
	sz = ucred_size();
	cr = (ucred_t *)SAFE_ALLOCA(sz);
	if (cr == NULL)
		return (-ENOMEM);

	if (syscall(SYS_ucredsys, UCREDSYS_UCREDGET, P_MYID, cr) != 0)
		return (-errno);

	if (((lx_ruid = (lx_uid_t)ucred_getruid(cr)) == (lx_uid_t)-1) ||
	    ((lx_euid = (lx_uid_t)ucred_geteuid(cr)) == (lx_uid_t)-1) ||
	    ((lx_suid = (lx_uid_t)ucred_getsuid(cr)) == (lx_uid_t)-1)) {
		return (-errno);
	}

	if (uucopy(&lx_ruid, (void *)ruid, sizeof (lx_uid_t)) != 0)
		return (-errno);

	if (uucopy(&lx_euid, (void *)euid, sizeof (lx_uid_t)) != 0)
		return (-errno);

	return ((uucopy(&lx_suid, (void *)suid, sizeof (lx_uid_t)) != 0)
	    ? -errno : 0);
}

long
lx_getresuid16(uintptr_t ruid16, uintptr_t euid16, uintptr_t suid16)
{
	lx_uid_t lx_ruid, lx_euid, lx_suid;
	lx_uid16_t lx_ruid16, lx_euid16, lx_suid16;
	int rv;

	if ((rv = lx_getresuid((uintptr_t)&lx_ruid, (uintptr_t)&lx_euid,
	    (uintptr_t)&lx_suid)) != 0)
		return (rv);

	lx_ruid16 = LX_UID32_TO_UID16(lx_ruid);
	lx_euid16 = LX_UID32_TO_UID16(lx_euid);
	lx_suid16 = LX_UID32_TO_UID16(lx_suid);

	if (uucopy(&lx_ruid16, (void *)ruid16, sizeof (lx_uid16_t)) != 0)
		return (-errno);

	if (uucopy(&lx_euid16, (void *)euid16, sizeof (lx_uid16_t)) != 0)
		return (-errno);

	return ((uucopy(&lx_suid16, (void *)suid16, sizeof (lx_uid16_t)) != 0)
	    ? -errno : 0);
}

long
lx_getresgid(uintptr_t rgid, uintptr_t egid, uintptr_t sgid)
{
	ucred_t	*cr;
	lx_gid_t lx_rgid, lx_egid, lx_sgid;
	size_t sz;

	/*
	 * We allocate a ucred_t ourselves rather than call ucred_get(3C)
	 * because ucred_get() calls malloc(3C), which the brand library cannot
	 * use.  Because we allocate the space with SAFE_ALLOCA(), there's
	 * no need to free it when we're done.
	 */
	sz = ucred_size();
	cr = (ucred_t *)SAFE_ALLOCA(sz);
	if (cr == NULL)
		return (-ENOMEM);

	if (syscall(SYS_ucredsys, UCREDSYS_UCREDGET, P_MYID, cr) != 0)
		return (-errno);

	if (((lx_rgid = (lx_gid_t)ucred_getrgid(cr)) == (lx_gid_t)-1) ||
	    ((lx_egid = (lx_gid_t)ucred_getegid(cr)) == (lx_gid_t)-1) ||
	    ((lx_sgid = (lx_gid_t)ucred_getsgid(cr)) == (lx_gid_t)-1)) {
		return (-errno);
	}

	if (uucopy(&lx_rgid, (void *)rgid, sizeof (lx_gid_t)) != 0)
		return (-errno);

	if (uucopy(&lx_egid, (void *)egid, sizeof (lx_gid_t)) != 0)
		return (-errno);

	return ((uucopy(&lx_sgid, (void *)sgid, sizeof (lx_gid_t)) != 0)
	    ? -errno : 0);
}

long
lx_getresgid16(uintptr_t rgid16, uintptr_t egid16, uintptr_t sgid16)
{
	lx_gid_t lx_rgid, lx_egid, lx_sgid;
	lx_gid16_t lx_rgid16, lx_egid16, lx_sgid16;
	int rv;

	if ((rv = lx_getresgid((uintptr_t)&lx_rgid, (uintptr_t)&lx_egid,
	    (uintptr_t)&lx_sgid)) != 0)
		return (rv);

	lx_rgid16 = LX_UID32_TO_UID16(lx_rgid);
	lx_egid16 = LX_UID32_TO_UID16(lx_egid);
	lx_sgid16 = LX_UID32_TO_UID16(lx_sgid);

	if (uucopy(&lx_rgid16, (void *)rgid16, sizeof (lx_gid16_t)) != 0)
		return (-errno);

	if (uucopy(&lx_egid16, (void *)egid16, sizeof (lx_gid16_t)) != 0)
		return (-errno);

	return ((uucopy(&lx_sgid16, (void *)sgid16, sizeof (lx_gid16_t)) != 0)
	    ? -errno : 0);
}

long
lx_setreuid16(uintptr_t ruid, uintptr_t euid)
{
	return ((setreuid(LX_UID16_TO_UID32((lx_uid16_t)ruid),
	    LX_UID16_TO_UID32((lx_uid16_t)euid))) ? -errno : 0);
}

long
lx_setregid16(uintptr_t rgid, uintptr_t egid)
{
	return ((setregid(LX_UID16_TO_UID32((lx_gid16_t)rgid),
	    LX_UID16_TO_UID32((lx_gid16_t)egid))) ? -errno : 0);
}

/*
 * The lx brand cannot support the setfs[ug]id16/setfs[ug]id calls as that
 * would require significant rework of Solaris' privilege mechanisms, so
 * instead return the current effective [ug]id.
 *
 * In Linux, fsids track effective IDs, so returning the effective IDs works
 * as a substitute; returning the current value also denotes failure of the
 * call if the caller had specified something different.  We don't need to
 * worry about setting error codes because the Linux calls don't set any.
 */
/*ARGSUSED*/
long
lx_setfsuid16(uintptr_t fsuid16)
{
	return (lx_geteuid16());
}

/*ARGSUSED*/
long
lx_setfsgid16(uintptr_t fsgid16)
{
	return (lx_getegid16());
}

/*ARGSUSED*/
long
lx_setfsuid(uintptr_t fsuid)
{
	return (geteuid());
}

/*ARGSUSED*/
long
lx_setfsgid(uintptr_t fsgid)
{
	return (getegid());
}

/*
 * As a future enhancement we could investigate mapping Linux capabilities
 * into Illumos privileges, but for now we simply pretend we have capabilities
 * and give all of them back if the euid is 0. Likewise, we do nothing when
 * setting capabilities. We could also keep track of which capabilities have
 * been set so we could hand back that subset, instead of always saying we
 * have all of them enabled.
 */
long
lx_capget(uintptr_t p1, uintptr_t p2)
{
	lx_cap_user_header_t *chp = (lx_cap_user_header_t *)p1;
	lx_cap_user_data_t *cdp = (lx_cap_user_data_t *)p2;
	lx_cap_user_header_t ch;
	lx_cap_user_data_t cd;

	if (uucopy(chp, &ch, sizeof (ch)) != 0)
		return (-errno);

	if (ch.version != LX_CAPABILITY_VERSION_1 &&
	    ch.version != LX_CAPABILITY_VERSION_2 &&
	    ch.version != LX_CAPABILITY_VERSION_3)
		return (-EINVAL);

	/* A null data pointer is used when querying supported version */
	if (cdp == 0)
		return (0);

	if (ch.pid < 0)
		return (-EINVAL);

	if (geteuid() == 0) {
		if (ch.pid == getpid() || ch.pid == 0) {
			/* root (or emulate pid 0), have all capabilities */
			cd.effective = LX_ALL_CAPABILITIES;
			cd.permitted = LX_ALL_CAPABILITIES;
			cd.inheritable = 0;
		} else {
			int fd;
			char path[MAXPATHLEN];
			psinfo_t psinfo;

			/* check the given pid */
			(void) snprintf(path, sizeof (path),
			    "/native/proc/%d/psinfo", ch.pid);

			if ((fd = open(path, O_RDONLY)) < 0)
				return (-ESRCH);

			if (read(fd, &psinfo, sizeof (psinfo)) !=
			    sizeof (psinfo)) {
				(void) close(fd);
				return (-ESRCH);
			}
			(void) close(fd);

			if (psinfo.pr_euid == 0) {
				/* root, it has all capabilities */
				cd.effective = LX_ALL_CAPABILITIES;
				cd.permitted = LX_ALL_CAPABILITIES;
				cd.inheritable = 0;
			} else {
				/* not root, it has no capabilities */
				cd.effective = 0;
				cd.permitted = 0;
				cd.inheritable = 0;
			}
		}
	} else {
		/* not root and trying to get another process's capabilities */
		if (ch.pid != getpid())
			return (-EPERM);

		/* not root, you have no capabilities */
		cd.effective = 0;
		cd.permitted = 0;
		cd.inheritable = 0;
	}

	if (uucopy(&cd, cdp, sizeof (cd)) != 0)
		return (-errno);

	return (0);
}

long
lx_capset(uintptr_t p1, uintptr_t p2)
{
	lx_cap_user_header_t ch;

	if ((int)p1 <= 0 || (int)p2 <= 0)
		return (-EFAULT);

	if (uucopy((void *)p1, &ch, sizeof (ch)) != 0)
		return (-errno);

	if (ch.version != LX_CAPABILITY_VERSION_1 &&
	    ch.version != LX_CAPABILITY_VERSION_2 &&
	    ch.version != LX_CAPABILITY_VERSION_3)
		return (-EINVAL);

	if (geteuid() == 0)
		return (0);

	return (-EPERM);
}
