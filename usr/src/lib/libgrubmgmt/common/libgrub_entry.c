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
 * This file contains all the functions that get/set fields
 * in a GRUB menu entry.
 */
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <sys/types.h>
#include <assert.h>
#include <ctype.h>

#include "libgrub_cmd.def"
#include "libgrub_impl.h"

typedef int (*barg_parsef_t)(const grub_line_t *, grub_barg_t *);
static const  barg_parsef_t barg_parse[] = {
#define	menu_cmd(cmd, num, flag, parsef)	parsef,
#include "libgrub_cmd.def"
};

/*
 * Remove extra '/', stops at first isspace character.
 * Return new string length.
 */
size_t
clean_path(char *path)
{
	int	i, c;
	size_t	k, n;

	n = strlen(path) + 1;

	for (i = 0; (c = path[i]) != 0 && !isspace(c); i++) {
		if (c == '/' && (k = strspn(path + i, "/") - 1) != 0) {
			/* bcopy should deal with overlapping buffers */
			n -= k;
			bcopy(path + i + k, path + i, n - i);
		}
	}
	return (n - 1);
}

/*
 * Construct boot command line from the ge_barg field
 */
static size_t
barg_cmdline(const grub_barg_t *barg, char *cmd, size_t size)
{
	size_t n;
	const grub_fsdesc_t *fsd;

	if (!IS_BARG_VALID(barg) ||
	    (fsd = grub_get_rootfsd(&barg->gb_root)) == NULL)
		return ((size_t)-1);

	/* if disk/top dataset is mounted, use mount point */
	if (fsd->gfs_mountp[0] != 0) {
		if ((n = snprintf(cmd, size, "%s%s", fsd->gfs_mountp,
		    barg->gb_kernel)) >= size)
			return (n);
		return (clean_path(cmd));
	} else
		return (snprintf(cmd, size, "%s %s", fsd->gfs_dev,
		    barg->gb_kernel));
}


/*
 * Construct ge_barg field based on the other fields of the entry.
 * Return 0 on success, errno on failure.
 */
int
grub_entry_construct_barg(grub_entry_t *ent)
{
	int ret = 0;
	grub_barg_t *barg;
	grub_line_t *lp, *lend;
	grub_menu_t *mp;

	assert(ent);

	barg = &ent->ge_barg;
	mp = ent->ge_menu;

	assert(barg);
	assert(mp);

	(void) memset(barg, 0, sizeof (*barg));
	barg->gb_entry = ent;
	(void) bcopy(&mp->gm_root, &barg->gb_root, sizeof (barg->gb_root));

	lend = ent->ge_end->gl_next;
	for (lp = ent->ge_start; lp != lend; lp = lp->gl_next) {
		if (lp->gl_cmdtp >= GRBM_CMD_NUM)
			ret = EG_INVALIDCMD;
		else
			ret = barg_parse[lp->gl_cmdtp](lp, barg);

		if (ret != 0)
			break;
	}

	barg->gb_errline = lp;
	if (ret == 0) {
		/* at least kernel and module should be defined */
		if (barg->gb_kernel[0] != 0 && barg->gb_module[0] != 0)
			barg->gb_flags |= GRBM_VALID_FLAG;
	}

	return (ret);
}

const char *
grub_entry_get_fstyp(const grub_entry_t *ent)
{
	if (IS_ENTRY_BARG_VALID(ent))
		return (ent->ge_barg.gb_root.gr_fstyp);
	else
		return (NULL);
}

const char *
grub_entry_get_kernel(const grub_entry_t *ent)
{
	if (IS_ENTRY_BARG_VALID(ent))
		return (ent->ge_barg.gb_kernel);
	else
		return (NULL);
}

const char *
grub_entry_get_module(const grub_entry_t *ent)
{
	if (IS_ENTRY_BARG_VALID(ent))
		return (ent->ge_barg.gb_module);
	else
		return (NULL);
}

const char *
grub_entry_get_error_desc(const grub_entry_t *ent)
{
	assert(ent != NULL);
	return ("Not implemented");
}

const grub_fsdesc_t *
grub_entry_get_rootfs(const grub_entry_t *ent)
{
	if (IS_ENTRY_BARG_VALID(ent))
		return (grub_get_rootfsd(&ent->ge_barg.gb_root));
	else
		return (NULL);
}

size_t
grub_entry_get_cmdline(grub_entry_t *ent, char *cmdline, size_t size)
{
	if (IS_ENTRY_VALID(ent) && (grub_entry_construct_barg(ent) == 0))
		return (barg_cmdline(&ent->ge_barg, cmdline, size));
	else
		return ((size_t)-1);

}
