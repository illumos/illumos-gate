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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_ATTR_H
#define	_SYS_ATTR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <nfs/nfs.h>
#endif
#include <sys/nvpair.h>

/* Attribute names for nvlist's */
#define	A_CRTIME		"crtime"
#define	A_HIDDEN		"hidden"
#define	A_SYSTEM		"system"
#define	A_READONLY		"readonly"
#define	A_ARCHIVE		"archive"
#define	A_NOUNLINK		"nounlink"
#define	A_IMMUTABLE		"immutable"
#define	A_APPENDONLY		"appendonly"
#define	A_NODUMP		"nodump"
#define	A_OPAQUE		"opaque"
#define	A_AV_QUARANTINED	"av_quarantined"
#define	A_AV_MODIFIED		"av_modified"
#define	A_FSID			"fsid"
#define	A_AV_SCANSTAMP		"av_scanstamp"
#define	A_OWNERSID		"ownersid"
#define	A_GROUPSID		"groupsid"

/* Attribute option for utilities */
#define	O_HIDDEN	 "H"
#define	O_SYSTEM	 "S"
#define	O_READONLY	 "R"
#define	O_ARCHIVE	 "A"
#define	O_NOUNLINK	 "u"
#define	O_IMMUTABLE	 "i"
#define	O_APPENDONLY	 "a"
#define	O_NODUMP	 "d"
#define	O_AV_QUARANTINED "q"
#define	O_AV_MODIFIED	 "m"
#define	O_NONE		 ""

/* ownersid and groupsid are composed of two nvpairs */
#define	SID_DOMAIN		"domain"
#define	SID_RID			"rid"

typedef enum {
	F_ATTR_INVAL = -1,
	F_ARCHIVE,
	F_HIDDEN,
	F_READONLY,
	F_SYSTEM,
	F_APPENDONLY,
	F_NODUMP,
	F_IMMUTABLE,
	F_AV_MODIFIED,
	F_OPAQUE,
	F_AV_SCANSTAMP,
	F_AV_QUARANTINED,
	F_NOUNLINK,
	F_CRTIME,
	F_OWNERSID,
	F_GROUPSID,
	F_FSID,
	F_ATTR_ALL
} f_attr_t;

#define	VIEW_READONLY	"SUNWattr_ro"
#define	VIEW_READWRITE	"SUNWattr_rw"

/*
 * These are the supported views into the virtual sysattr directory.
 * Additional views should be added before XATTR_VIEW_LAST.
 */
typedef enum {
	XATTR_VIEW_INVALID = -1,
	XATTR_VIEW_READONLY,
	XATTR_VIEW_READWRITE,
	XATTR_VIEW_LAST
} xattr_view_t;

typedef struct {
	char		*x_name;
	char		*x_option;
	xattr_view_t	x_xattr_view;
	data_type_t	x_data_type;
} xattr_entry_t;

#ifdef _KERNEL
#define	XATTR_MAXFIDSZ	NFS_FHMAXDATA

typedef struct {
	uint16_t	len;
	char		parent_fid[XATTR_MAXFIDSZ];
	uint16_t	parent_len;
	uint16_t	dir_offset;
} xattr_fid_t;

#define	XATTR_FIDSZ (sizeof (xattr_fid_t) - sizeof (uint16_t))

int xattr_dir_vget(vfs_t *, vnode_t **, fid_t *);
int xattr_sysattr_casechk(char *name);
#endif

int attr_count(void);
const char *attr_to_name(f_attr_t);
const char *attr_to_option(f_attr_t);
f_attr_t name_to_attr(const char *name);
f_attr_t option_to_attr(const char *option);
xattr_view_t attr_to_xattr_view(f_attr_t attr);
data_type_t attr_to_data_type(f_attr_t attr);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ATTR_H */
