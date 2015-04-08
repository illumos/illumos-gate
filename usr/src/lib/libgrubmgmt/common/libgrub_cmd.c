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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2015 Nexenta Systems, Inc.
 */

/*
 * This file contains all the functions that implement the following
 * GRUB commands:
 *	kernel, kernel$, module, module$, findroot, bootfs
 * Return 0 on success, errno on failure.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <alloca.h>
#include <errno.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/fs/ufs_mount.h>
#include <sys/dktp/fdisk.h>
#if defined(__i386)
#include <sys/x86_archext.h>
#endif /* __i386 */

#include "libgrub_impl.h"

#define	RESET_MODULE(barg)	((barg)->gb_module[0] = 0)

#define	BPROP_ZFSBOOTFS	"zfs-bootfs"
#define	BPROP_BOOTPATH	"bootpath"

#if defined(__i386)
static const char cpuid_dev[] = "/dev/cpu/self/cpuid";

/*
 * Return 1 if the system supports 64-bit mode, 0 if it doesn't,
 * or -1 on failure.
 */
static int
cpuid_64bit_capable(void)
{
	int fd, ret = -1;
	struct {
		uint32_t cp_eax, cp_ebx, cp_ecx, cp_edx;
	} cpuid_regs;

	if ((fd = open(cpuid_dev, O_RDONLY)) == -1)
		return (ret);

	if (pread(fd, &cpuid_regs, sizeof (cpuid_regs), 0x80000001) ==
	    sizeof (cpuid_regs))
		ret = ((CPUID_AMD_EDX_LM & cpuid_regs.cp_edx) != 0);

	(void) close(fd);
	return (ret);
}
#endif /* __i386 */


/*
 * Expand $ISAIDR
 */
#if !defined(__i386)
/* ARGSUSED */
#endif /* __i386 */
static size_t
barg_isadir_var(char *var, int sz)
{
#if defined(__i386)
	if (cpuid_64bit_capable() == 1)
		return (strlcpy(var, "amd64", sz));
#endif /* __i386 */

	var[0] = 0;
	return (0);
}

/*
 * Expand $ZFS-BOOTFS
 */
static size_t
barg_bootfs_var(const grub_barg_t *barg, char *var, int sz)
{
	int n;

	assert(barg);
	if (strcmp(barg->gb_root.gr_fstyp, MNTTYPE_ZFS) == 0) {
		n = snprintf(var, sz,
		    BPROP_ZFSBOOTFS "=%s," BPROP_BOOTPATH "=\"%s\"",
		    barg->gb_root.gr_fs[GRBM_ZFS_BOOTFS].gfs_dev,
		    barg->gb_root.gr_physpath);
	} else	{
		var[0] = 0;
		n = 0;
	}
	return (n);
}

/*
 * Expand all the variables without appending them more than once.
 */
static int
expand_var(char *arg, size_t argsz, const char *var, size_t varsz,
    char *val, size_t valsz)
{
	char	*sp = arg;
	size_t	sz = argsz, len;
	char	*buf, *dst, *src;
	int	ret = 0;

	buf = alloca(argsz);
	dst = buf;

	while ((src = strstr(sp, var)) != NULL) {

		len = src - sp;

		if (len + valsz > sz) {
			ret = E2BIG;
			break;
		}

		(void) bcopy(sp, dst, len);
		(void) bcopy(val, dst + len, valsz);
		dst += len + valsz;
		sz -= len + valsz;
		sp = src + varsz;
	}

	if (strlcpy(dst, sp, sz) >= sz)
		ret = E2BIG;

	if (ret == 0)
		bcopy(buf, arg, argsz);
	return (ret);
}

/*
 * Searches first occurence of boot-property 'bprop' in str.
 * str supposed to be in format:
 * " [-B prop=[value][,prop=[value]]...]
 */
static const char *
find_bootprop(const char *str, const char *bprop)
{
	const char *s;
	size_t bplen, len;

	assert(str);
	assert(bprop);

	bplen = strlen(bprop);
	s = str;

	while ((str = strstr(s, " -B")) != NULL ||
	    (str = strstr(s, "\t-B")) != NULL) {
		s = str + 3;
		len = strspn(s, " \t");

		/* empty -B option, skip it */
		if (len != 0 && s[len] == '-')
			continue;

		s += len;
		do {
			len = strcspn(s, "= \t");
			if (s[len] !=  '=')
				break;

			/* boot property we are looking for? */
			if (len == bplen && strncmp(s, bprop, bplen) == 0)
				return (s);

			s += len;

			/* skip boot property value */
			while ((s = strpbrk(s + 1, "\"\', \t")) != NULL) {

				/* skip quoted */
				if (s[0] == '\"' || s[0] == '\'') {
					if ((s = strchr(s + 1, s[0])) == NULL) {
						/* unbalanced quotes */
						return (s);
					}
				}
				else
					break;
			}

			/* no more boot properties */
			if (s == NULL)
				return (s);

			/* no more boot properties in that -B block */
			if (s[0] != ',')
				break;

			s += strspn(s, ",");
		} while (s[0] != ' ' && s[0] != '\t');
	}
	return (NULL);
}

/*
 * Add bootpath property to str if
 * 	1. zfs-bootfs property is set explicitly
 * and
 * 	2. bootpath property is not set
 */
static int
update_bootpath(char *str, size_t strsz, const char *bootpath)
{
	size_t n;
	char *buf;
	const char *bfs;

	/* zfs-bootfs is not specified, or bootpath is allready set */
	if ((bfs = find_bootprop(str, BPROP_ZFSBOOTFS)) == NULL ||
	    find_bootprop(str, BPROP_BOOTPATH) != NULL)
		return (0);

	n = bfs - str;
	buf = alloca(strsz);

	bcopy(str, buf, n);
	if (snprintf(buf + n, strsz - n, BPROP_BOOTPATH "=\"%s\",%s",
	    bootpath, bfs) >= strsz - n)
		return (E2BIG);

	bcopy(buf, str, strsz);
	return (0);
}

static int
match_bootfs(zfs_handle_t *zfh, void *data)
{
	int		ret;
	const char	*zfn;
	grub_barg_t	*barg = (grub_barg_t *)data;

	ret = (zfs_get_type(zfh) == ZFS_TYPE_FILESYSTEM &&
	    (zfn = zfs_get_name(zfh)) != NULL &&
	    strcmp(barg->gb_root.gr_fs[GRBM_ZFS_BOOTFS].gfs_dev, zfn) == 0);

	if (ret != 0)
		barg->gb_walkret = 0;
	else
		(void) zfs_iter_filesystems(zfh, match_bootfs, barg);

	zfs_close(zfh);
	return (barg->gb_walkret == 0);
}

static void
reset_root(grub_barg_t *barg)
{
	(void) memset(&barg->gb_root, 0, sizeof (barg->gb_root));
	barg->gb_bootsign[0] = 0;
	barg->gb_kernel[0] = 0;
	RESET_MODULE(barg);
}

/* ARGSUSED */
int
skip_line(const grub_line_t *lp, grub_barg_t *barg)
{
	return (0);
}

/* ARGSUSED */
int
error_line(const grub_line_t *lp, grub_barg_t *barg)
{
	if (lp->gl_cmdtp == GRBM_ROOT_CMD)
		return (EG_ROOTNOTSUPP);
	return (EG_INVALIDLINE);
}

int
kernel(const grub_line_t *lp, grub_barg_t *barg)
{
	RESET_MODULE(barg);
	if (strlcpy(barg->gb_kernel, lp->gl_arg, sizeof (barg->gb_kernel)) >=
	    sizeof (barg->gb_kernel))
		return (E2BIG);

	return (0);
}

int
module(const grub_line_t *lp, grub_barg_t *barg)
{
	if (strlcpy(barg->gb_module, lp->gl_arg, sizeof (barg->gb_module)) >=
	    sizeof (barg->gb_module))
		return (E2BIG);

	return (0);
}

int
dollar_kernel(const grub_line_t *lp, grub_barg_t *barg)
{
	int	ret;
	size_t	bfslen, isalen;
	char	isadir[32];
	char	bootfs[BOOTARGS_MAX];

	RESET_MODULE(barg);
	if (strlcpy(barg->gb_kernel, lp->gl_arg, sizeof (barg->gb_kernel)) >=
	    sizeof (barg->gb_kernel))
		return (E2BIG);

	bfslen = barg_bootfs_var(barg, bootfs, sizeof (bootfs));
	isalen = barg_isadir_var(isadir, sizeof (isadir));

	if (bfslen >= sizeof (bootfs) || isalen >= sizeof (isadir))
		return (EINVAL);

	if ((ret = expand_var(barg->gb_kernel, sizeof (barg->gb_kernel),
	    ZFS_BOOT_VAR, strlen(ZFS_BOOT_VAR), bootfs, bfslen)) != 0)
		return (ret);

	if ((ret = expand_var(barg->gb_kernel, sizeof (barg->gb_kernel),
	    ISADIR_VAR, strlen(ISADIR_VAR), isadir, isalen)) != 0)
		return (ret);

	if (strcmp(barg->gb_root.gr_fstyp, MNTTYPE_ZFS) == 0)
		ret = update_bootpath(barg->gb_kernel, sizeof (barg->gb_kernel),
		    barg->gb_root.gr_physpath);

	return (ret);
}

int
dollar_module(const grub_line_t *lp, grub_barg_t *barg)
{
	int	ret;
	size_t	isalen;
	char	isadir[32];

	if (strlcpy(barg->gb_module, lp->gl_arg, sizeof (barg->gb_module)) >=
	    sizeof (barg->gb_module))
		return (E2BIG);

	if ((isalen = barg_isadir_var(isadir, sizeof (isadir))) >= sizeof
	    (isadir))
		return (EINVAL);

	ret = expand_var(barg->gb_module, sizeof (barg->gb_module),
	    ISADIR_VAR, strlen(ISADIR_VAR), isadir, isalen);

	return (ret);
}


int
findroot(const grub_line_t *lp, grub_barg_t *barg)
{
	size_t sz, bsz;
	const char *sign;

	reset_root(barg);

	sign = lp->gl_arg;
	barg->gb_prtnum = (uint_t)PRTNUM_INVALID;
	barg->gb_slcnum = (uint_t)SLCNUM_WHOLE_DISK;

	if (sign[0] == '(') {
		const char *pos;

		++sign;
		if ((pos = strchr(sign, ',')) == NULL || (sz = pos - sign) == 0)
			return (EG_FINDROOTFMT);

		++pos;
		if (!IS_PRTNUM_VALID(barg->gb_prtnum = pos[0] - '0'))
			return (EG_FINDROOTFMT);

		++pos;
		/*
		 * check the slice only when its presented
		 */
		if (pos[0] != ')') {
			if (pos[0] != ',' ||
			    !IS_SLCNUM_VALID(barg->gb_slcnum = pos[1]) ||
			    pos[2] != ')')
				return (EG_FINDROOTFMT);
		}
	} else {
		sz = strlen(sign);
	}

	bsz = strlen(BOOTSIGN_DIR "/");
	if (bsz + sz + 1 > sizeof (barg->gb_bootsign))
		return (E2BIG);

	bcopy(BOOTSIGN_DIR "/", barg->gb_bootsign, bsz);
	bcopy(sign, barg->gb_bootsign + bsz, sz);
	barg->gb_bootsign [bsz + sz] = 0;

	return (grub_find_bootsign(barg));
}

int
bootfs(const grub_line_t *lp, grub_barg_t *barg)
{
	zfs_handle_t	*zfh;
	grub_menu_t	*mp = barg->gb_entry->ge_menu;
	char		*gfs_devp;
	size_t		gfs_dev_len;

	/* Check if root is zfs */
	if (strcmp(barg->gb_root.gr_fstyp, MNTTYPE_ZFS) != 0)
		return (EG_NOTZFS);

	gfs_devp = barg->gb_root.gr_fs[GRBM_ZFS_BOOTFS].gfs_dev;
	gfs_dev_len = sizeof (barg->gb_root.gr_fs[GRBM_ZFS_BOOTFS].gfs_dev);

	/*
	 * If the bootfs value is the same as the bootfs for the pool,
	 * do nothing.
	 */
	if (strcmp(lp->gl_arg, gfs_devp) == 0)
		return (0);

	if (strlcpy(gfs_devp, lp->gl_arg, gfs_dev_len) >= gfs_dev_len)
		return (E2BIG);

	/* check if specified bootfs belongs to the root pool */
	if ((zfh = zfs_open(mp->gm_fs.gf_lzfh,
	    barg->gb_root.gr_fs[GRBM_ZFS_TOPFS].gfs_dev,
	    ZFS_TYPE_FILESYSTEM)) == NULL)
		return (EG_OPENZFS);

	barg->gb_walkret = EG_UNKBOOTFS;
	(void) zfs_iter_filesystems(zfh, match_bootfs, barg);
	zfs_close(zfh);

	if (barg->gb_walkret == 0)
		(void) grub_fsd_get_mountp(barg->gb_root.gr_fs +
		    GRBM_ZFS_BOOTFS, MNTTYPE_ZFS);

	return (barg->gb_walkret);
}
