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
 * Copyright 2016 Joyent, Inc.
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
#include <vm/anon.h>

#define	KILOBYTE	1024
#define	MEGABYTE	(1024 * KILOBYTE)
#define	GIGABYTE	(1024 * MEGABYTE)

#define	MODESHIFT	3

#define	VALIDMODEBITS	07777

extern pgcnt_t swapfs_minfree;

void *
tmp_kmem_zalloc(struct tmount *tm, size_t size, int flag)
{
	void *buf;
	zone_t *zone;
	size_t pages;

	mutex_enter(&tm->tm_contents);
	zone = tm->tm_vfsp->vfs_zone;
	if (tm->tm_anonmem + size > tm->tm_anonmax ||
	    tm->tm_anonmem + size < tm->tm_anonmem ||
	    size + ptob(tmpfs_minfree) <= size ||
	    !anon_checkspace(size + ptob(tmpfs_minfree), zone)) {
		mutex_exit(&tm->tm_contents);
		return (NULL);
	}

	/*
	 * Only make anonymous memory reservations when a page boundary is
	 * crossed.  This is necessary since the anon_resv functions rounds up
	 * to PAGESIZE internally.
	 */
	pages = btopr(tm->tm_allocmem + size);
	pages -= btopr(tm->tm_allocmem);
	if (pages > 0 && anon_try_resv_zone(ptob(pages), zone) == 0) {
		mutex_exit(&tm->tm_contents);
		return (NULL);
	}

	tm->tm_allocmem += size;
	tm->tm_anonmem += size;
	mutex_exit(&tm->tm_contents);

	buf = kmem_zalloc(size, flag);
	if (buf == NULL) {
		mutex_enter(&tm->tm_contents);
		ASSERT(tm->tm_anonmem > tm->tm_anonmem - size);
		tm->tm_anonmem -= size;
		if (pages > 0) {
			/*
			 * Re-chasing the zone pointer is necessary since a
			 * forced umount could have been performed while the
			 * tm_contents lock was dropped during allocation.
			 */
			anon_unresv_zone(ptob(pages), tm->tm_vfsp->vfs_zone);
		}
		mutex_exit(&tm->tm_contents);
	}

	return (buf);
}

void
tmp_kmem_free(struct tmount *tm, void *buf, size_t size)
{
	size_t pages;

	kmem_free(buf, size);
	mutex_enter(&tm->tm_contents);
	ASSERT(tm->tm_anonmem > tm->tm_anonmem - size);
	tm->tm_anonmem -= size;
	pages = btopr(tm->tm_allocmem);
	tm->tm_allocmem -= size;
	pages -= btopr(tm->tm_allocmem);
	/*
	 * Like the tmp_kmem_zalloc case, only unreserve anonymous memory when
	 * a page boundary has been crossed.
	 */
	if (pages > 0) {
		anon_unresv_zone(size, tm->tm_vfsp->vfs_zone);
	}
	mutex_exit(&tm->tm_contents);
}

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
 * Convert a string containing a number (number of bytes) to a size_t,
 * containing the corresponding number of bytes. On 32-bit kernels, the
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
tmp_convnum(char *str, size_t *maxbytes)
{
	u_longlong_t num = 0;
#ifdef _LP64
	u_longlong_t max_bytes = ULONG_MAX;
#else
	u_longlong_t max_bytes = PAGESIZE * (uint64_t)ULONG_MAX;
#endif
	size_t pages;
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
	 * We've been given a size in bytes; however, we want to make sure that
	 * we have at least one page worth no matter what. Therefore we use
	 * btopr to round up. However, this may cause an overflow only if 'num'
	 * is between (max_bytes - PAGESIZE) and (max_bytes). In this case the
	 * resulting number is zero, which is what we check for below. Note, we
	 * require at least one page, so if pages is zero, well, it wasn't going
	 * to work anyways.
	 */
	pages = btopr(num);
	if (pages == 0) {
		return (EINVAL);
	}

	*maxbytes = ptob(pages);

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
