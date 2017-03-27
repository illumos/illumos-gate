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
 * Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2015 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/t_lock.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <sys/time.h>
#include <sys/cmn_err.h>
#include <sys/vnode.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/cred.h>
#include <sys/kmem.h>
#include <sys/atomic.h>
#include <sys/policy.h>
#include <sys/fs/tmp.h>
#include <sys/fs/tmpnode.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#define	KILOBYTE	1024
#define	MEGABYTE	(1024 * KILOBYTE)
#define	GIGABYTE	(1024 * MEGABYTE)

#define	MODESHIFT	3

#define	VALIDMODEBITS	07777

extern pgcnt_t swapfs_minfree;

int
tmp_taccess(void *vtp, int mode, struct cred *cred)
{
	struct tmpnode *tp = vtp;
	int shift = 0;
	/*
	 * Check access based on owner, group and
	 * public permissions in tmpnode.
	 */
	if (crgetuid(cred) != tp->tn_uid) {
		shift += MODESHIFT;
		if (groupmember(tp->tn_gid, cred) == 0)
			shift += MODESHIFT;
	}

	return (secpolicy_vnode_access2(cred, TNTOV(tp), tp->tn_uid,
	    tp->tn_mode << shift, mode));
}

/*
 * Decide whether it is okay to remove within a sticky directory.
 * Two conditions need to be met:  write access to the directory
 * is needed.  In sticky directories, write access is not sufficient;
 * you can remove entries from a directory only if you own the directory,
 * if you are privileged, if you own the entry or if they entry is
 * a plain file and you have write access to that file.
 * Function returns 0 if remove access is granted.
 */
int
tmp_sticky_remove_access(struct tmpnode *dir, struct tmpnode *entry,
    struct cred *cr)
{
	uid_t uid = crgetuid(cr);

	if ((dir->tn_mode & S_ISVTX) &&
	    uid != dir->tn_uid &&
	    uid != entry->tn_uid &&
	    (entry->tn_type != VREG ||
	    tmp_taccess(entry, VWRITE, cr) != 0))
		return (secpolicy_vnode_remove(cr));

	return (0);
}

/*
 * Allocate zeroed memory if tmpfs_maxkmem has not been exceeded
 * or the 'musthave' flag is set.  'musthave' allocations should
 * always be subordinate to normal allocations so that tmpfs_maxkmem
 * can't be exceeded by more than a few KB.  Example: when creating
 * a new directory, the tmpnode is a normal allocation; if that
 * succeeds, the dirents for "." and ".." are 'musthave' allocations.
 */
void *
tmp_memalloc(size_t size, int musthave)
{
	static time_t last_warning;
	time_t now;

	if (atomic_add_long_nv(&tmp_kmemspace, size) < tmpfs_maxkmem ||
	    musthave)
		return (kmem_zalloc(size, KM_SLEEP));

	atomic_add_long(&tmp_kmemspace, -size);
	now = gethrestime_sec();
	if (last_warning != now) {
		last_warning = now;
		cmn_err(CE_WARN, "tmp_memalloc: tmpfs over memory limit");
	}
	return (NULL);
}

void
tmp_memfree(void *cp, size_t size)
{
	kmem_free(cp, size);
	atomic_add_long(&tmp_kmemspace, -size);
}

/*
 * Convert a string containing a number (number of bytes) to a pgcnt_t,
 * containing the corresponding number of pages. On 32-bit kernels, the
 * maximum value encoded in 'str' is PAGESIZE * ULONG_MAX, while the value
 * returned in 'maxpg' is at most ULONG_MAX.
 *
 * The number may be followed by a magnitude suffix: "k" or "K" for kilobytes;
 * "m" or "M" for megabytes; "g" or "G" for gigabytes.  This interface allows
 * for an arguably esoteric interpretation of multiple suffix characters:
 * namely, they cascade.  For example, the caller may specify "2mk", which is
 * interpreted as 2 gigabytes.  It would seem, at this late stage, that the
 * horse has left not only the barn but indeed the country, and possibly the
 * entire planetary system. Alternatively, the number may be followed by a
 * single '%' sign, indicating the size is a percentage of either the zone's
 * swap limit or the system's overall swap size.
 *
 * Parse and overflow errors are detected and a non-zero number returned on
 * error.
 */
int
tmp_convnum(char *str, pgcnt_t *maxpg)
{
	u_longlong_t num = 0;
#ifdef _LP64
	u_longlong_t max_bytes = ULONG_MAX;
#else
	u_longlong_t max_bytes = PAGESIZE * (uint64_t)ULONG_MAX;
#endif
	char *c;
	const struct convchar {
		char *cc_char;
		uint64_t cc_factor;
	} convchars[] = {
		{ "kK", KILOBYTE },
		{ "mM", MEGABYTE },
		{ "gG", GIGABYTE },
		{ NULL, 0 }
	};

	if (str == NULL) {
		return (EINVAL);
	}
	c = str;

	/*
	 * Convert the initial numeric portion of the input string.
	 */
	if (ddi_strtoull(str, &c, 10, &num) != 0) {
		return (EINVAL);
	}

	/*
	 * Handle a size in percent. Anything other than a single percent
	 * modifier is invalid. We use either the zone's swap limit or the
	 * system's total available swap size as the initial value. Perform the
	 * intermediate calculation in pages to avoid overflow.
	 */
	if (*c == '%') {
		u_longlong_t cap;

		if (*(c + 1) != '\0')
			return (EINVAL);

		if (num > 100)
			return (EINVAL);

		cap = (u_longlong_t)curproc->p_zone->zone_max_swap_ctl;
		if (cap == UINT64_MAX) {
			/*
			 * Use the amount of available physical and memory swap
			 */
			mutex_enter(&anoninfo_lock);
			cap = TOTAL_AVAILABLE_SWAP;
			mutex_exit(&anoninfo_lock);
		} else {
			cap = btop(cap);
		}

		num = ptob(cap * num / 100);
		goto done;
	}

	/*
	 * Apply the (potentially cascading) magnitude suffixes until an
	 * invalid character is found, or the string comes to an end.
	 */
	for (; *c != '\0'; c++) {
		int i;

		for (i = 0; convchars[i].cc_char != NULL; i++) {
			/*
			 * Check if this character matches this multiplier
			 * class:
			 */
			if (strchr(convchars[i].cc_char, *c) != NULL) {
				/*
				 * Check for overflow:
				 */
				if (num > max_bytes / convchars[i].cc_factor) {
					return (EINVAL);
				}

				num *= convchars[i].cc_factor;
				goto valid_char;
			}
		}

		/*
		 * This was not a valid multiplier suffix character.
		 */
		return (EINVAL);

valid_char:
		continue;
	}

done:
	/*
	 * Since btopr() rounds up to page granularity, this round-up can
	 * cause an overflow only if 'num' is between (max_bytes - PAGESIZE)
	 * and (max_bytes). In this case the resulting number is zero, which
	 * is what we check for below.
	 */
	if ((*maxpg = (pgcnt_t)btopr(num)) == 0 && num != 0)
		return (EINVAL);
	return (0);
}

/*
 * Parse an octal mode string for use as the permissions set for the root
 * of the tmpfs mount.
 */
int
tmp_convmode(char *str, mode_t *mode)
{
	ulong_t num;
	char *c;

	if (str == NULL) {
		return (EINVAL);
	}

	if (ddi_strtoul(str, &c, 8, &num) != 0) {
		return (EINVAL);
	}

	if ((num & ~VALIDMODEBITS) != 0) {
		return (EINVAL);
	}

	*mode = VALIDMODEBITS & num;
	return (0);
}
