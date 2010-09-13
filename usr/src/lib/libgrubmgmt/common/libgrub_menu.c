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
 * This file contains functions for manipulating the GRUB menu.
 */
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <stdarg.h>
#include <assert.h>
#include <ctype.h>

#include "libgrub_impl.h"

static const grub_cmd_desc_t grub_cmd_descs[GRBM_CMD_NUM] = {
#define	menu_cmd(cmd, num, flag, parsef)	{cmd, num, flag},
#include "libgrub_cmd.def"
};

static void
append_line(grub_menu_t *mp, grub_line_t *lp)
{
	if (mp->gm_start == NULL) {
		mp->gm_start = lp;
	} else {
		mp->gm_end->gl_next = lp;
		lp->gl_prev = mp->gm_end;
	}
	mp->gm_end = lp;
	lp->gl_line_num = ++mp->gm_line_num;
	lp->gl_entry_num = GRUB_ENTRY_DEFAULT;
}

static void
process_line(grub_menu_t *mp)
{
	int	n;
	grub_line_t	*lp;

	lp = mp->gm_end;
	n = sizeof (grub_cmd_descs) / sizeof (grub_cmd_descs[0]);

	/* search through the table of known commands */
	while (n-- != 0 && strcmp(lp->gl_cmd, grub_cmd_descs[n].gcd_cmd) != 0)
		;

	/* unknown command */
	if (n < 0)
		return;

	/* we found command, fill lp fields */
	lp->gl_flags = grub_cmd_descs[n].gcd_flags;
	lp->gl_cmdtp = grub_cmd_descs[n].gcd_num;
}


static void
check_entry(grub_entry_t *ent)
{
	int i;
	uint_t emask;
	grub_line_t *lp;
	const grub_line_t * const lend = ent->ge_end->gl_next;

	emask = 0;
	for (i = 0, lp = ent->ge_start; lend != lp; lp = lp->gl_next, ++i) {
		lp->gl_entry_num = ent->ge_entry_num;
		if (lp->gl_flags == GRUB_LINE_INVALID ||
		    lp->gl_flags == GRUB_LINE_GLOBAL) {
			emask |= 1 << i;
			lp->gl_flags = GRUB_LINE_INVALID;
		}
	}

	if ((ent->ge_emask = emask) == 0)
		ent->ge_flags |= GRBM_VALID_FLAG;
}

static int
add_entry(grub_menu_t *mp, grub_line_t *start, grub_line_t *end)
{
	grub_entry_t *ent;

	if ((ent = calloc(1, sizeof (*ent))) == NULL)
		return (errno);

	ent->ge_start = start;
	ent->ge_end = end;

	if (mp->gm_ent_end == NULL) {
		mp->gm_ent_start = ent;
	} else {
		mp->gm_ent_end->ge_next = ent;
		ent->ge_prev = mp->gm_ent_end;
	}
	mp->gm_ent_end = ent;
	ent->ge_entry_num = mp->gm_entry_num++;
	ent->ge_menu = mp;
	return (0);
}

static void
default_entry(grub_menu_t *mp)
{
	uint_t defent;
	grub_line_t *lp;
	grub_entry_t *ent;

	defent = 0;
	lp = mp->gm_curdefault;

	if (lp != NULL && lp->gl_flags == GRUB_LINE_GLOBAL &&
	    lp->gl_cmdtp == GRBM_DEFAULT_CMD) {
		defent  = strtoul(lp->gl_arg, NULL, 0);
		if (defent >= mp->gm_entry_num)
			defent = 0;
	}

	for (ent = mp->gm_ent_start; ent != NULL && defent != ent->ge_entry_num;
	    ent = ent->ge_next)
		;

	mp->gm_ent_default = ent;
}

static void
free_line(grub_line_t *lp)
{
	if (lp == NULL)
		return;

	free(lp->gl_cmd);
	free(lp->gl_sep);
	free(lp->gl_arg);
	free(lp->gl_line);
	free(lp);
}

static void
free_linelist(grub_line_t *line)
{
	grub_line_t *lp;

	if (line == NULL)
		return;

	while (line) {
		lp = line;
		line = lp->gl_next;
		free_line(lp);
	}
}

static void
free_entries(grub_menu_t *mp)
{
	grub_entry_t *ent, *tmp;

	if (mp == NULL)
		return;

	for (ent = mp->gm_ent_start; (tmp = ent) != NULL;
	    ent = tmp->ge_next, free(tmp))
		;

	mp->gm_ent_start = NULL;
	mp->gm_ent_end = NULL;
}

static int
grub_menu_append_line(grub_menu_t *mp, const char *line)
{
	int rc;
	size_t n;
	grub_line_t *lp;

	if (line == NULL)
		return (EINVAL);

	rc = 0;
	lp = NULL;
	if ((lp = calloc(1, sizeof (*lp))) == NULL ||
	    (lp->gl_line = strdup(line)) == NULL) {
		free(lp);
		return (errno);
	}

	/* skip initial white space */
	line += strspn(line, " \t");

	/* process comment line */
	if (line[0] == '#') {
		if ((lp->gl_cmd =
		    strdup(grub_cmd_descs[GRBM_COMMENT_CMD].gcd_cmd)) == NULL ||
		    (lp->gl_sep =
		    strdup(grub_cmd_descs[GRBM_EMPTY_CMD].gcd_cmd)) == NULL ||
		    (lp->gl_arg = strdup(line + 1)) == NULL)
			rc = errno;
	} else {
		/* get command */
		n = strcspn(line, " \t=");
		if ((lp->gl_cmd = malloc(n + 1)) == NULL)
			rc = errno;
		else
			(void) strlcpy(lp->gl_cmd, line, n + 1);

		line += n;

		/* get separator */
		n = strspn(line, " \t=");
		if ((lp->gl_sep = malloc(n + 1)) == NULL)
			rc = errno;
		else
			(void) strlcpy(lp->gl_sep, line, n + 1);

		line += n;

		/* get arguments */
		if ((lp->gl_arg = strdup(line)) == NULL)
			rc = errno;
	}

	if (rc != 0) {
		free_line(lp);
		return (rc);
	}

	append_line(mp, lp);
	process_line(mp);
	return (0);
}

static int
grub_menu_process(grub_menu_t *mp)
{
	int ret;
	grub_entry_t *ent;
	grub_line_t *line, *start;

	/* Free remaininig entries, if any */
	free_entries(mp);

	/*
	 * Walk through lines, till first 'title' command is encountered.
	 * Initialize globals.
	 */
	for (line = mp->gm_start; line != NULL; line = line->gl_next) {
		if (line->gl_flags == GRUB_LINE_GLOBAL &&
		    line->gl_cmdtp == GRBM_DEFAULT_CMD)
			mp->gm_curdefault = line;
		else if (line->gl_cmdtp == GRBM_TITLE_CMD)
			break;
	}

	/*
	 * Walk through remaining lines and recreate menu entries.
	 */
	for (start = NULL; line != NULL; line = line->gl_next) {
		if (line->gl_cmdtp == GRBM_TITLE_CMD) {
			/* is first entry */
			if (start != NULL &&
			    (ret = add_entry(mp, start, line->gl_prev)) != 0)
				return (ret);
			start = line;
		}
	}

	/* Add last entry */
	if (start != NULL && (ret = add_entry(mp, start, mp->gm_end)) != 0)
		return (ret);

	for (ent = mp->gm_ent_start; NULL != ent; ent = ent->ge_next)
		check_entry(ent);

	default_entry(mp);

	return (0);
}

static int
grub_fs_init(grub_fs_t *fs)
{
	assert(fs);
	if ((fs->gf_lzfh = libzfs_init()) == NULL ||
	    (fs->gf_diroot = di_init("/", DINFOCPYALL | DINFOPATH))
	    == DI_NODE_NIL ||
	    (fs->gf_dvlh = di_devlink_init(NULL, 0)) == DI_LINK_NIL) {
		return (EG_INITFS);
	}
	return (0);
}

static void
grub_fs_fini(grub_fs_t *fs)
{
	if (fs == NULL)
		return;

	if (fs->gf_dvlh != DI_LINK_NIL)
		(void) di_devlink_fini(&fs->gf_dvlh);
	if (fs->gf_diroot != DI_NODE_NIL)
		di_fini(fs->gf_diroot);
	if (fs->gf_lzfh != NULL)
		libzfs_fini(fs->gf_lzfh);
	(void) memset(fs, 0, sizeof (*fs));
}

/*
 * Reads and parses GRUB menu file into a grub_menu_t data structure.
 * If grub_menu_path file path is NULL, will use 'currently active'
 * GRUB menu file.
 *
 * Memory for the menu data structure is allocated within the routine.
 * Caller must call grub_menu_fini() to release memory after calling
 * grub_menu_init().
 */
int
grub_menu_init(const char *path, grub_menu_t **menup)
{
	FILE *fp;
	char *cp;
	grub_menu_t *mp;
	int len, n, ret;
	char buf[GRBM_MAXLINE];

	if (menup == NULL)
		return (EINVAL);

	/*
	 * Allocate space, perform initialization
	 */
	if ((mp = calloc(1, sizeof (*mp))) == NULL) {
		*menup = mp;
		return (errno);
	}

	if ((ret = grub_fs_init(&mp->gm_fs)) != 0 ||
	    (ret = grub_current_root(&mp->gm_fs, &mp->gm_root)) != 0)
		goto err_out1;

	if (path == NULL) {
		/*
		 * Use default grub-menu.
		 * If top dataset is not mounted, mount it now.
		 */
		if (mp->gm_root.gr_fs[GRBM_FS_TOP].gfs_mountp[0] == 0) {
			if ((ret = grub_fsd_mount_tmp(mp->gm_root.gr_fs +
			    GRBM_FS_TOP, mp->gm_root.gr_fstyp)) != 0)
				goto err_out1;
		}
		(void) snprintf(mp->gm_path, sizeof (mp->gm_path),
		    "%s/%s", mp->gm_root.gr_fs[GRBM_FS_TOP].gfs_mountp,
		    GRUB_MENU);
	} else {
		(void) strlcpy(mp->gm_path, path, sizeof (mp->gm_path));
	}

	if ((fp = fopen(mp->gm_path, "r")) == NULL) {
		ret = errno;
		goto err_out1;
	}

	cp = buf;
	len = sizeof (buf);

	while (fgets(cp, len, fp) != NULL) {

		if (IS_LINE2BIG(cp, len, n)) {
			ret = E2BIG;
			break;
		}

		/* remove white space at the end of line */
		for (; n != 0 && isspace(cp[n - 1]); --n)
			;
		cp[n] = '\0';

		if (n > 0 && cp[n - 1] == '\\') {
			len -= n - 1;
			assert(len >= 2);
			cp += n - 1;
			continue;
		}
		if ((ret = grub_menu_append_line(mp, buf)) != 0)
			break;

		cp = buf;
		len = sizeof (buf);
	}

	if (fclose(fp) == EOF)
		ret = errno;
	else if (ret == 0)
		ret = grub_menu_process(mp);

err_out1:
	grub_fsd_umount_tmp(mp->gm_root.gr_fs + GRBM_FS_TOP);
	if (0 != ret) {
		grub_menu_fini(mp);
		mp = NULL;
	}
	*menup = mp;
	return (ret);
}

void
grub_menu_fini(grub_menu_t *mp)
{
	if (mp == NULL)
		return;

	grub_fs_fini(&mp->gm_fs);
	free_entries(mp);
	free_linelist(mp->gm_start);
	free(mp);
}

grub_line_t *
grub_menu_next_line(const grub_menu_t *mp, const grub_line_t *lp)
{
	assert(mp);
	if (lp == NULL)
		return (mp->gm_start);
	else
		return (lp->gl_next);
}

grub_line_t *
grub_menu_prev_line(const grub_menu_t *mp, const grub_line_t *lp)
{
	assert(mp);
	if (lp == NULL)
		return (mp->gm_end);
	else
		return (lp->gl_prev);
}

grub_line_t *
grub_menu_get_line(const grub_menu_t *mp, int num)
{
	grub_line_t *lp;

	assert(mp);
	if (num > mp->gm_line_num)
		return (NULL);
	for (lp = mp->gm_start; lp != NULL && num != lp->gl_line_num;
	    lp = lp->gl_next)
		;
	return (lp);
}

size_t
grub_menu_get_cmdline(const grub_menu_t *mp, int num, char *cmdl, size_t size)
{
	grub_entry_t *ent;

	assert(mp);
	if ((ent = grub_menu_get_entry(mp, num)) == NULL)
		return (size_t)(-1);

	return (grub_entry_get_cmdline(ent, cmdl, size));
}

grub_entry_t *
grub_menu_next_entry(const grub_menu_t *mp, const grub_entry_t *ent)
{
	assert(mp);
	if (ent == NULL) {
		return (mp->gm_ent_start);
	} else {
		assert(mp == ent->ge_menu);
		return (ent->ge_next);
	}
}

grub_entry_t *
grub_menu_prev_entry(const grub_menu_t *mp, const grub_entry_t *ent)
{
	assert(mp);
	if (ent == NULL) {
		return (mp->gm_ent_end);
	} else {
		assert(mp == ent->ge_menu);
		return (ent->ge_prev);
	}
}

grub_entry_t *
grub_menu_get_entry(const grub_menu_t *mp, int num)
{
	grub_entry_t *ent;

	assert(mp);
	if (num == GRUB_ENTRY_DEFAULT) {
		ent = mp->gm_ent_default;
	} else if (num >= mp->gm_entry_num) {
		ent = NULL;
	} else {
		for (ent = mp->gm_ent_start;
		    ent != NULL && num != ent->ge_entry_num;
		    ent = ent->ge_next)
			;
	}
	return (ent);
}
