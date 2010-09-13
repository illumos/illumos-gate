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

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */



#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <libinst.h>

char *
srcpath(char *dir, char *src, int part, int nparts)
{
	static char tmppath[PATH_MAX];
	char	*copy;
	size_t	copyLen;

	copy = tmppath;

	if (dir != NULL) {
		size_t theLen = strlen(dir);

		(void) strcpy(copy, dir);
		copy += theLen;
		copyLen = (sizeof (tmppath) - theLen);
	} else {
		copy[0] = '\0';
		copyLen = sizeof (tmppath);
	}

	if (nparts > 1) {
		(void) snprintf(copy, copyLen,
			((src[0] == '/') ? "/root.%d%s" : "/reloc.%d/%s"),
			part, src);
	} else {
		(void) snprintf(copy, copyLen,
			((src[0] == '/') ? "/root%s" : "/reloc/%s"), src);
	}

	return (tmppath);
}

/*
 * During a partial install(Ex. Migration of a zone), if the'contchg' field of
 * mstat structure is set i.e. there is a mismatch between the entry in pkgmap
 * and package database and the file is of type 'f', the source path on the
 * Global zone is to be generated(mostly for being copied again to the NGZ).
 * Given the local source path(relocatable), this function builds the absolute
 * source path.
 *
 * NOTE: This function is a private interface. Should only be called during a
 *	 a partial install and for files of type 'f'.
 *	 Source translation is done differently from 'e' and 'v' types.
 */
char *
trans_srcp_pi(char *local_path)
{
	static char pi_srcPath[PATH_MAX];
	char *tmp_basedir, *tmp_inst_root;
	int inst_root_len, basedir_len;

	/* Get the basedir and it's length */
	tmp_basedir = get_basedir();
	basedir_len = strlen(tmp_basedir);

	/* Get the install root and it's length */
	tmp_inst_root = get_inst_root();
	inst_root_len = strlen(tmp_inst_root);

	/*
	 * Get past install root if something exists
	 * Example:
	 * INSTROOT = /a (on scratch zone)
	 * BASEDIR = /a/usr (on scratch zone)
	 * local_path = "~bin/ls"
	 *
	 * Absolute path for source on GZ:
	 * a) If BASEDIR == INSTROOT
	 *	/<local_path string starting from index 1>
	 * In the above example, absolute path is
	 * 	/bin/ls
	 *
	 * b) If BASEDIR > INSTROOT
	 *	/usr/<local_path string starting from index 1>
	 * In the above example, absolute path is
	 * 	/usr/bin/ls
	 */
	if ((strncmp(tmp_inst_root, tmp_basedir, inst_root_len) == 0) &&
	    (inst_root_len == basedir_len)) {
		/*
		 * Prefix root to the local path. NOTE that local_path[0]
		 * has a '~' character. Move past it.
		 *
		 * NOTE: local_path array size is expected to be >= 2.
		 */
		(void) snprintf(pi_srcPath, PATH_MAX, "/%s",
		    &(local_path[1]));
	} else {
		/*
		 * NOTE: local_path array size is expected to be >= 2.
		 */
		(void) snprintf(pi_srcPath, PATH_MAX, "%s/%s",
		    &(tmp_basedir[inst_root_len]), &(local_path[1]));
	}

	return (pi_srcPath);
}
