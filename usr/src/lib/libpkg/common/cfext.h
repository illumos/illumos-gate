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
 */

#ifndef	_CFEXT_H
#define	_CFEXT_H


#ifdef	__cplusplus
extern "C" {
#endif

#include	<pkgstrct.h>

struct mergstat {
	unsigned setuid:1;  /* pkgmap entry has setuid */
	unsigned setgid:1;  /* ... and/or setgid bit set */
	unsigned contchg:1; /* contents of the files different */
	unsigned attrchg:1; /* attributes are different */
	unsigned shared:1;  /* > 1 pkg associated with this */
	unsigned osetuid:1; /* installed set[ug]id process ... */
	unsigned osetgid:1; /* ... being overwritten by pkg. */
	unsigned rogue:1;   /* conflicting file not owned by a package */
	unsigned dir2nondir:1;  /* was a directory & now a non-directory */
	unsigned replace:1; /* merge makes no sense for this object pair */
	unsigned denied:1;  /* for some reason this was not allowed in */
	unsigned preloaded:1;   /* already checked in a prior pkg op */
	unsigned processed:1;   /* already installed or removed */
	unsigned parentsyml2dir:1;
	/* parent directory changed from symlink to a directory */
};

/*
 * This is information required by pkgadd for fast operation. A
 * cfextra struct is tagged to each cfent structure requiring
 * processing. This is how we avoid some unneeded repetition. The
 * entries incorporating the word 'local' refer to the path that
 * gets us to the delivered package file. In other words, to install
 * a file we usually copy from 'local' to 'path' below. In the case
 * of a link, where no actual copying takes place, local is the source
 * of the link. Note that environment variables are not evaluated in
 * the locals unless they are links since the literal path is how
 * pkgadd finds the entry under the reloc directory.
 */
struct cfextra {
	struct cfent cf_ent;	/* basic contents file entry */
	struct mergstat mstat;  /* merge status for installs */
	uint32_t   fsys_value; /* fstab[] entry index */
	uint32_t   fsys_base;  /* actual base filesystem in fs_tab[] */
	char	*client_path;   /* the client-relative path */
	char	*server_path;   /* the server-relative path */
	char	*map_path;  /* as read from the pkgmap */
	char	*client_local;  /* client_relative local */
	char	*server_local;  /* server relative local */
};

#ifdef	__cplusplus
}
#endif

#endif	/* _CFEXT_H */
