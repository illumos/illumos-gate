/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <strings.h>
#include <errno.h>
#include <assert.h>
#include "config_nfs4.h"

#define		NFS4_MAX_DOM_LEN	1024

static int		work_fd;
static int		nfs4_fd;
static struct stat	n4sb;
char			cur_domain[NFS4_MAX_DOM_LEN];
char			nfs4cfg_file[NFS4_MAX_DOM_LEN];
static char		work_file[NFS4_MAX_DOM_LEN];

static nfs4cfg_err_t
gen_nfs4_work_fname(char *src, char *dst)
{
	char	*t;
	char	 dir[NFS4_MAX_DOM_LEN];
	char	*pfx = "mapid";

	snprintf(dir, strlen(src), "%s", src);
	if ((t = strrchr(dir, '/')) != NULL)
		*t = '\0';		/* /etc/default */
	else
		dir[0] = '\0';		/* P_tmpdir */

	/*
	 * Note: tempnam() can still default to P_tmpdir if
	 *	 access perms to the 'dir' are incompatible
	 */
	if ((t = tempnam(dir, pfx)) == NULL)
		return (NFS4CFG_ERR_WRK_FNAME);

	snprintf(dst, strlen(t), "%s", t);
	return (NFS4CFG_OK);
}

static nfs4cfg_err_t
open_nfs4_cfg(FILE **n4_fp)
{
	int	n4_fd;
	int	o_flags = (O_CREAT | O_RDWR | O_TRUNC);

	errno = 0;
	if (stat(nfs4cfg_file, &n4sb) < 0) {
		if (errno != ENOENT)
			return (NFS4CFG_ERR_CFG_STAT);

		/*
		 * config file does not exist, so we create it
		 */
		if ((n4_fd = open(nfs4cfg_file, o_flags, 0644)) < 0)
			return (NFS4CFG_ERR_CFG_OPEN_RW);

		if ((*n4_fp = fdopen(n4_fd, "w")) == NULL) {
			close(n4_fd);
			unlink(nfs4cfg_file);
			return (NFS4CFG_ERR_CFG_FDOPEN);
		}

		if (fchown(n4_fd, UID_ROOT, GID_SYS) < 0) {
			close(n4_fd);
			unlink(nfs4cfg_file);
			return (NFS4CFG_ERR_CFG_WCHOWN);
		}
		return (NFS4CFG_ERR_CFG_CREAT);
	}

	/*
	 * config file exists; open it and
	 * create the appropriate work file
	 */
	if ((n4_fd = open(nfs4cfg_file, O_RDONLY)) < 0)
		return (NFS4CFG_ERR_CFG_OPEN_RO);

	if ((*n4_fp = fdopen(n4_fd, "r")) == NULL) {
		close(n4_fd);
		return (NFS4CFG_ERR_CFG_FDOPEN);
	}

	nfs4_fd = n4_fd;
	return (NFS4CFG_OK);
}

static nfs4cfg_err_t
open_work_file(FILE **wk_fp)
{
	int	wk_fd;
	int	o_flags = (O_CREAT | O_RDWR | O_TRUNC);

	if ((wk_fd = open(work_file, o_flags, 0644)) < 0)
		return (NFS4CFG_ERR_WRK_OPEN);

	if ((*wk_fp = fdopen(wk_fd, "w")) == NULL) {
		close(wk_fd);
		return (NFS4CFG_ERR_WRK_FDOPEN);
	}

	if (fchmod(wk_fd, n4sb.st_mode) < 0) {
		fclose(*wk_fp);
		unlink(work_file);
		return (NFS4CFG_ERR_WRK_WCHMOD);
	}

	if (fchown(wk_fd, n4sb.st_uid, n4sb.st_gid) < 0) {
		fclose(*wk_fp);
		unlink(work_file);
		return (NFS4CFG_ERR_WRK_WCHOWN);
	}

	work_fd = wk_fd;
	return (NFS4CFG_OK);
}

static nfs4cfg_err_t
open_nfs4_files(FILE **n4_fp, FILE **wk_fp)
{
	nfs4cfg_err_t	rv = NFS4CFG_OK;

	if ((rv = open_nfs4_cfg(n4_fp)) != NFS4CFG_OK)
		return (rv);

	if ((rv = open_work_file(wk_fp)) != NFS4CFG_OK)
		close(nfs4_fd);

	return (rv);
}

static void
nfs4_comment_setting(FILE *src, FILE *targ, const char *pattern)
{
	char	 ibuf[NFS4_MAX_DOM_LEN];
	char	 obuf[NFS4_MAX_DOM_LEN];
	char	*iptr;
	char	*p;
	char	*wptr;
	size_t	 slen;

	while (!feof(src)) {
		bzero(ibuf, NFS4_MAX_DOM_LEN);
		bzero(obuf, NFS4_MAX_DOM_LEN);
		if ((iptr = fgets(ibuf, NFS4_MAX_DOM_LEN, src)) == NULL)
			continue;

		if ((p = strstr(ibuf, pattern)) == NULL) {
			/*
			 * Some other line than the one we're interested
			 * in. Just write it out and fetch the next line.
			 */
			wptr = ibuf;

		} else if (p == ibuf || ibuf[0] != '#') {
			/*
			 * If pattern was found at the beginning of the
			 * line _or_ even if it wasn't, if the first char
			 * is not a #, go ahead and insert the # and puke
			 * it out.
			 */
			slen = strlen(ibuf) + 2;
			snprintf(obuf, slen, "#%s", ibuf);
			wptr = obuf;

		} else
			/* already commented */
			wptr = ibuf;

		(void) fputs(wptr, targ);
	}
	(void) fflush(targ);
}

static int
nfs4_check_setting(FILE *src, const char *pattern)
{
	char	 ibuf[NFS4_MAX_DOM_LEN];
	char	*iptr;
	char	*p;
	int	rv = 0;

	while (!feof(src)) {
		bzero(ibuf, NFS4_MAX_DOM_LEN);
		if ((iptr = fgets(ibuf, NFS4_MAX_DOM_LEN, src)) == NULL)
			continue;

		if (ibuf[0] == '#' || (p = strstr(ibuf, pattern)) == NULL)
			/*
			 * If the line is commented out or it's some other
			 * line than the one we're interested in, move on
			 */
			continue;

		else if (p == ibuf) {
			/*
			 * If pattern is found at the beginning of the line,
			 * the setting is active. Use this to present to the
			 * user as the default _iff_ the file does not exist.
			 */
			extern char	*chomp(char *);

			if ((p = strchr(ibuf, '=')) != NULL) {
				bzero(cur_domain, NFS4_MAX_DOM_LEN);
				bcopy(chomp(++p), cur_domain, strlen(p));

				/*
				 * If the sysadmin specified "Auto" from the
				 * sysidcfg script, then continue to comment
				 * the entry and we're done.
				 */
				rv = strcasecmp(cur_domain, "Auto") == 0;
			}
			break;
		}
	}
	return (rv);
}

static void
nfs4_config_setting(FILE *src, FILE *targ, const char *pattern, char *value)
{
	char	 ibuf[NFS4_MAX_DOM_LEN];
	char	 obuf[NFS4_MAX_DOM_LEN];
	char	*iptr;
	char	*p;
	char	*wptr;
	int	 done;
	size_t	 slen;

	done = 0;
	while (!feof(src)) {
		bzero(ibuf, NFS4_MAX_DOM_LEN);
		if ((iptr = fgets(ibuf, NFS4_MAX_DOM_LEN, src)) == NULL)
			continue;

		if ((p = strstr(ibuf, pattern)) == NULL) {
			/*
			 * Some other line than the one we're interested
			 * in. Just write it out and fetch the next line.
			 */
			wptr = ibuf;

		} else if (p == ibuf) {
			/*
			 * pattern found uncommented at the beginning of
			 * the line, so make sure we set the proper value
			 * and write it out.
			 */
			if (!done) {
				slen = strlen(pattern) + strlen(value) + 3;
				snprintf(obuf, slen, "%s=%s\n", pattern, value);
			} else {
				/*
				 * If we've already set the pattern to the
				 * specified value and we happen to encounter
				 * additional active line(s), then comment
				 * them out.
				 */
				slen = strlen(ibuf) + 2;
				snprintf(obuf, slen, "#%s", ibuf);
			}
			wptr = obuf;
			done++;

		} else if (ibuf[0] == '#') {
			/*
			 * pattern was found to be commented. Set to the
			 * specified value if we haven't already done so.
			 */
			if (!done) {
				slen = strlen(pattern) + strlen(value) + 3;
				snprintf(obuf, slen, "%s=%s\n", pattern, value);
				wptr = obuf;

			} else {
				/*
				 * Value was set previously and input line
				 * is already commented; just write it out.
				 */
				wptr = ibuf;
			}
			done++;

		} else {
			/*
			 * Found the pattern, but not commented and with
			 * some garbo at the front. Take the conservative
			 * approach and comment it out.
			 */
			slen = strlen(ibuf) + 2;
			snprintf(obuf, slen, "#%s", ibuf);
			wptr = obuf;
		}
		(void) fputs(wptr, targ);
	}
	(void) fflush(targ);
}

static void
nfs4_create_setting(FILE *targ, const char *pattern, char *value)
{
	char	obuf[NFS4_MAX_DOM_LEN];
	size_t	slen;

	slen = strlen(pattern) + strlen(value) + 3;
	snprintf(obuf, slen, "%s=%s\n", pattern, value);
	(void) fputs(obuf, targ);
	(void) fflush(targ);
}

int
config_nfs4(int cmd, const char *pattern, char *value)
{
	FILE		*nfs4;
	FILE		*work;
	nfs4cfg_err_t	 rv = 0;
	char		 c;

	/*
	 * Make a working copy of the config file.
	 */
	strncpy(nfs4cfg_file, NFS4CFG_FILE, strlen(NFS4CFG_FILE));
	if (cmd == NFS4CMD_CHECK) {
		if ((rv = open_nfs4_cfg(&nfs4)) != NFS4CFG_OK)
			return ((int)rv);
	} else {
		if (rv = gen_nfs4_work_fname(nfs4cfg_file, work_file))
			return ((int)rv);

		if ((rv = open_nfs4_files(&nfs4, &work)) != NFS4CFG_OK) {
			if (rv == NFS4CFG_ERR_CFG_CREAT &&
			    cmd == NFS4CMD_CONFIG) {
				/*
				 * revisit if NFS4CMD_UNCOMMENT
				 * is ever implemented
				 */
				nfs4_create_setting(nfs4, pattern, value);
				fclose(nfs4);
				return (0);
			}
			return ((int)rv);
		}
	}

	/*
	 * Make necessary changes to working copy of the file
	 */
	switch (cmd) {
		case NFS4CMD_CHECK:
			rv = nfs4_check_setting(nfs4, pattern);
			fclose(nfs4);
			return (rv);
			/* NOTREACHED */

		case NFS4CMD_CONFIG:
			assert(value != NULL);
			nfs4_config_setting(nfs4, work, pattern, value);
			break;

		case NFS4CMD_UNCONFIG:
			/* FALLTHROUGH */
		case NFS4CMD_UNCOMMENT:
			break;		/* ENOTSUP */

		case NFS4CMD_COMMENT:
		default:
			nfs4_comment_setting(nfs4, work, pattern);
			break;
	}

	/*
	 * Install working copy (new file) over (old) config file
	 */
	close(work_fd);
	if (rename(work_file, nfs4cfg_file) < 0) {
		unlink(work_file);
		return (NFS4CFG_ERR_WRK_RENAME);
	}
	return (0);
}
