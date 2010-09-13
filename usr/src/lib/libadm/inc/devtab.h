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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef	_DEVTAB_H
#define	_DEVTAB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * devtab.h
 *
 *	This header file is local to the liboam component
 *	and should not contain any data that may need to
 *	be reference anywhere.  The definitions here are used
 *	to reference the device tables and the device-group
 *	tables.
 */

/*
 *  Constant definitions
 *	NULL		Manifest constant NULL (null-address)
 *	TRUE		Boolean TRUE value
 *	FALSE		Boolean FALSE value
 *	DTAB_BUFSIZ	Initial buffersize for reading device table records
 *	DTAB_BUFINC	Amount to increase device table record buffer
 *	DGRP_BUFSIZ	Initial buffersize for reading devgrp table records
 *	DGRP_BUFINC	Amount to increase device-group table record buffer
 *	XTND_MAXCNT	Maximum extend count (may have insane tables)
 *	DTAB_ESCS	Characters that are escaped in fields in the devtab
 */

#ifndef	NULL
#define	NULL	(0)
#endif

#ifndef	TRUE
#define	TRUE	(1)
#endif

#ifndef	FALSE
#define	FALSE	(0)
#endif

#define	DTAB_BUFSIZ	512
#define	DTAB_BUFINC	512
#define	DGRP_BUFSIZ	512
#define	DGRP_BUFINC	512
#define	XTND_MAXCNT	16

#define	DTAB_ESCS	":\\\"\n"

/*
 *	oam_devtab	File descriptor of the open device table
 */

extern	FILE	*oam_devtab;
extern	FILE	*oam_dgroup;

/*
 *  Structure definitions for device table records:
 *	devtabent	Describes an entry in the device table
 *	dgrpent		Describes an entry in the device-group table
 *	attrval		Describes an attribute/value pair
 */

/*
 *  struct devtabent
 *
 *	Describes an entry in the device table.
 *
 *	entryno		This record's entry number in the device table
 *	comment		Comment flag, TRUE if record is a comment
 *	alias		The device's alias
 *	cdevice		A pathname to the inode describing the device as
 *			a character-special device
 *	bdevice		A pathname to the inode describing the device as
 *			a block-special device
 *	pathname	A pathname to the device (not char or blk special)
 *	attrstr		The character-string containing the attributes
 *	attrlist	The address of the first attribute description
 */

struct devtabent {
	int		entryno;	/* Entry number of this record */
	int		comment;	/* Comment flag */
	char		*alias;		/* Alias of the device */
	char		*cdevice;	/* Character device pathname */
	char		*bdevice;	/* Block device pathname */
	char		*pathname;	/* Vanilla pathname */
	char		*attrstr;	/* String containing attributes */
	struct attrval *attrlist;	/* Addr of 1st attribute description */
};

/*
 *  struct attrval
 *
 *	Describes an attribute-value pair
 *
 *	char *attr		Pointer to the name of the attribute
 *	char *val		Pointer to the name of the value of the attr
 *	struct attrval *next	Pointer to the next item in the list
 */

struct attrval {
	char		*attr;		/* Attribute name */
	char		*val;		/* Value of the attribute */
	struct attrval *next;		/* Next attrval in list */
};

/*
 *  Structure definitions for device-group records:
 *	struct dgrptabent	Describes a record in the device-group table
 *	struct member		Describes a member of a device group
 */

/*
 *  struct dgrptabent
 *	entryno			The entry number of this record
 *	comment			Comment flag, TRUE if record is a comment
 *	name			The name of the device group
 *	memberspace		The buffer containing the members of the
 *				device group
 *	membership		Pointer to the head of the list of
 *				members in the group.
 */

struct dgrptabent {
	int		entryno;	/* Entry number of this record */
	int		comment;	/* TRUE if a comment record */
	char		*name;		/* Device group name */
	char		*dataspace;	/* Buffer containing membership */
	struct member  *membership;	/* Ptr to top of membership list */
};


/*
 *  struct member
 *	name			Member name (a device alias or pathname)
 *	next			Ptr to next item in the list
 */

struct member {
	char		*name;		/* Member name */
	struct member  *next;		/* Next member in the list */
};

/*
 *  Global function and data definitions:
 *	_setdevtab()		Rewinds the open device table
 *	_enddevtab()		Closes the open device table
 *	_getdevtabent()		Gets the next device table entry
 *	_freedevtabent()	Frees space allocated to a device-table entry
 *	_getdevrec()		Gets a specific device table entry
 *	_opendevtab()		Open the device table
 *	_devtabpath()		Get the pathname of the device table file
 *
 *	_setdgrptab()		Rewind the open device-group table
 *	_enddgrptab()		Close the open device table
 *	_getdgrptabent()	Get the next device-group table entry
 *	_freedgrptabent()	Frees space alloced to a dev-grp table entry
 *	_getdgrprec()		Gets a specific device-group table entry
 *	_opendgrptab()		Open the device group table
 *	_dgrptabpath()		Get the pathname of the device group table file
 *
 *	_openlkfile()		Open device lock file
 *	rsvtabpath()		Get device lock file pathname
 * 	_closelkfile()		Close device lock file
 *
 *	_validalias()		Determine if a character-string is a valid alias
 *	unreserv()		Remove a device reservation
 */

	void			_setdevtab(void);
	void			_enddevtab(void);
	struct devtabent	*_getdevtabent(void);
	void			_freedevtabent(struct devtabent *);
	struct devtabent	*_getdevrec(char *);
	int			_opendevtab(char *);
	char			*_devtabpath(void);

	void			_setdgrptab(void);
	void			_enddgrptab(void);
	struct dgrptabent	*_getdgrptabent(void);
	void			_freedgrptabent(struct dgrptabent *);
	struct dgrptabent	*_getdgrprec(char *);
	int			_opendgrptab(char *);
	char			*_dgrptabpath(void);

	int			_openlkfile(void);
	char			*_rsvtabpath(void);
	int			_closelkfile(void);

	int			_validalias(char *);
	int			unreserv(int, char *);

extern int _adddevtabrec(char *, char **);
extern int _moddevtabrec(char *, char **);
extern int _putdevtabrec(FILE *stream, struct devtabent *rec);
extern int _rmdevtabattrs(char   *, char **, char ***);
extern int _rmdevtabrec(char *);

extern int _adddgrptabrec(char *dgrp, char  **members);
extern int _putdgrptabrec(FILE *stream, struct dgrptabent *rec);
extern int _rmdgrpmems(char *dgrp, char **mems, char ***notfounds);
extern int _rmdgrptabrec(char *dgrp);

#ifdef	__cplusplus
}
#endif

#endif	/* _DEVTAB_H */
