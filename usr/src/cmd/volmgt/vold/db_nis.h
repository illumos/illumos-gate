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
 * Copyright (c) 1992 by Sun Microsystems, Inc.
 */

#ifndef	__DB_NIS_H
#define	__DB_NIS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif


struct nis_table {
	char	*col_name;
	u_int	table_flags;
	u_int	entry_flags;
};

/*
 * This is a description of the nis+ table that we use to store
 * our file system in.  Note that some of the entries are
 * treated as a "union", and their meaning is overloaded depending
 * on the type of object being stored.
 */
static struct nis_table nis_data_table[] = {
#define	DTAB_NAME	0	/* name of the object */
	{ "name", 	TA_SEARCHABLE, 	0},
#define	DTAB_DIR	1	/* directory the object is in */
	{ "directory",	TA_SEARCHABLE, 	0},
#define	DTAB_VERSION	2	/* version of this table entry */
	{ "version",	0, 		0},
#define	DTAB_XID	3	/* transaction id */
	{ "xid", 	0, 		0},
#define	DTAB_TYPE	4	/* type of object */
	{ "type",	TA_SEARCHABLE,	0},
#define	DTAB_ID		5	/* unique id */
	{ "id", 	TA_SEARCHABLE,	0},
#define	DTAB_UID	6	/* user id of the object owner */
	{ "user", 	TA_SEARCHABLE,	0},
#define	DTAB_GID	7	/* group id of the object owner */
	{ "group", 	TA_SEARCHABLE,  0},
#define	DTAB_MODE	8	/* permissions for the object */
	{ "permission", 0, 		0},
#define	DTAB_NLINKS	9	/* number of links */
	{ "nlinks", 	0, 		0},
#define	DTAB_ATIME	10	/* last access time */
	{ "atime", 	TA_XDR, 	EN_XDR},
#define	DTAB_CTIME	11	/* creation time */
	{ "ctime", 	TA_XDR, 	EN_XDR},
#define	DTAB_MTIME	12	/* last modified time */
	{ "mtime", 	TA_XDR, 	EN_XDR},
#define	DTAB_PROPS	13	/* object properties */
	{ "props", 	0, 		0},
#define	DTAB_UN_SS0	14	/* union: string searchable */
	{ "ss0", 	TA_SEARCHABLE, 	0},
#define	DTAB_UN_SS1	15	/* union: string searchable */
	{ "ss1", 	TA_SEARCHABLE, 	0},
#define	DTAB_UN_XN0	16	/* union: xdr non-searchable */
	{ "xn0", 	TA_XDR, 	EN_XDR},
#define	DTAB_UN_SS2	17	/* union: string searchable */
	{ "ss2", 	TA_SEARCHABLE, 	0},
#define	DTAB_UN_SN0	18	/* union: string non-searchable */
	{ "sn0",	0,		0},
#define	DTAB_UN_SN1	19	/* union: string non-searchable */
	{ "sn1",	0,		0},
};
static int ncols_data = sizeof (nis_data_table)/sizeof (struct nis_table);

#define	DTAB_GEN_END	DTAB_MTIME	/* last "generic" object */

#define	DTABLE_VERSION	1

/*
 * The volume specific definitions
 */
#define	VOL_MEDTYPE	DTAB_UN_SS0	/* type of media this is */
#define	VOL_LABTYPE	DTAB_UN_SS1	/* type of label */
#define	VOL_LABEL	DTAB_UN_XN0	/* label specific stuff */
#define	VOL_KEY		DTAB_UN_SS2	/* search key for label */
#define	VOL_LOCATION	DTAB_UN_SN0	/* location of the media */
#define	VOL_USERPROPS	DTAB_UN_SN1	/* user defined properties */


/*
 * The symlink specific definitions
 */
#define	SYM_PTR		DTAB_UN_SN0	/* what this symlink points at */

/*
 * The link specific definitions
 */
#define	LNK_PTR		DTAB_UN_SN0	/* what this link points at */

/*
 * The names we use in the database for each type of object.
 */
#define	DTAB_TYPE_VOL	"volume"
#define	DTAB_TYPE_DIR	"dir"
#define	DTAB_TYPE_LNK	"link"
#define	DTAB_TYPE_SLNK	"symlink"

static struct nis_table nis_control_table[] = {
#define	CTAB_NAME	0
	{ "name", 	TA_SEARCHABLE, 	0},
#define	CTAB_XID	1
	{ "xid", 	0, 		0},
#define	CTAB_ID		2
	{ "id", 	0, 		0},
#define	CTAB_LOCK	3
	{ "lock", 	0, 		0},
};
static int ncols_control = sizeof (nis_control_table)/sizeof (struct nis_table);

#define	CTAB_NAME_VAL		"control"
#define	CTAB_LOCK_LOCKED	"locked"
#define	CTAB_LOCK_UNLOCKED	"unlocked"

#define	DT_EFLAG(ent)		(nis_data_table[(ent)].entry_flags)
#define	DT_TFLAG(ent)		(nis_data_table[(ent)].table_flags)
#define	DT_NAME(ent)		(nis_data_table[(ent)].col_name)
#define	CT_EFLAG(ent)		(nis_control_table[(ent)].entry_flags)
#define	CT_TFLAG(ent)		(nis_control_table[(ent)].table_flags)
#define	CT_NAME(ent)		(nis_control_table[(ent)].col_name)

#define	VOLDIR		"volmgt"		/* name of directory */
#define	DTABNAME	"volumes"		/* name of data table */
#define	CTABNAME	"control"		/* name of control table */
#define	DTABTYPE	"volume"
#define	CTABTYPE	"control"
#define	NISSEP		'|'

#ifdef	__cplusplus
}
#endif

#endif	/* __DB_NIS_H */
