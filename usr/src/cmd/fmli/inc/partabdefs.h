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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright  (c) 1985 AT&T
 *	All Rights Reserved
 */

#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.2 */

/* Note: this file created with tabstops set to 4.
 *
 * Definitions for the Object Parts Table (OPT).  One of these tables
 * will exist per system, and defines the different parts of different
 * objects.
 */

#define PNAMESIZ	(256)	/* size of a part name should = FILE_NAME_SIZ */
#define MAXOBJPARTS 11		/* max parts a single object can have */
#define MAXPARTS	(24+MAXOBJPARTS) /* max number of parts for all objects */

#define PRT_FILE	0x01	/* the part is a file */
#define PRT_DIR		0x02	/* the part is a directory */
#define PRT_OPT		0x04	/* the part is optional */
#define PRT_BIN		0x08	/* the part is binary */
#define PRT_OEU		0x10	/* the part is an oeu */

struct one_part  {
	char part_name[PNAMESIZ];       /* registered part name*/
	char part_template[PNAMESIZ];	/* template for the name */
	int  part_flags;		/* physical part characteristics */
};

struct opt_entry  {
	char objtype[OTYPESIZ];		/* object type name */
	char objdisp[OTYPESIZ];		/* display name for the object */
	long int_class;			/* internal Telesystem class */
	char *oeu;			/* registered oeu name */
	char *objformat;		/* registered format name */
	char *objapp;			/* registered creating application */
	char *objprod;			/* registered product id */
	char *objclass;			/* registered object classification */
	int  part_offset;		/* first part in Parts list */
	int  numparts;			/* number of parts used */
	int  info_type;			/* type of the info_func program, if any*/
	int  info_int;			/* index of the internal info func */
	char *info_ext;			/* characters of the external info func */
};
