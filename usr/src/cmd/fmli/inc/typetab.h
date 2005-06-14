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

#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.4 */

/* Note: this file created with tabstops set to 4.
 *
 * Definitions for the Object Type Table (OTT).  One of these tables
 * will exist in each Telesystem directory, and will containt information
 * about all the objects in that directory.
 */

#define ONAMESIZ 	(256)	/* should be FILE_NAME_SIZ */
#define DNAMESIZ	(256)	/* maximum size of an object's display name*/
#define OTYPESIZ	(15)		/* maximum size of an object type's name */
#define DISPSIZ		(25)		/* maximum size of an object type's display */
#define OTTNIL		(-1)		/* end of a next_part link */

#define MAX_PRINCIPALS	(12)	/* maximum number of multiple principals */

/* the following defines give the currently implemented object mask bytes
 * for internal use.  The VAR explicitly has control over the low eight bits
 * of the mask, while all the other bits are under Telesystem control.
 */

#define NOMASK	(0x0L)				/* no mask */
#define M_VAR1	(0x0001L)			/* VAR mask #1 */
#define M_VAR2	(0x0002L)			/* VAR mask #2 */
#define M_VAR3	(0x0004L)			/* VAR mask #3 */
#define M_VAR4	(0x0008L)			/* VAR mask #4 */
#define M_VAR5	(0x0010L)			/* VAR mask #5 */
#define M_VAR6	(0x0020L)			/* VAR mask #6 */
#define M_VAR7	(0x0040L)			/* VAR mask #7 */
#define M_VAR8	(0x0080L)			/* VAR mask #8 */

#define M_DL	(0x0100L)			/* deleted */
#define M_EN	(0x0200L)			/* encrypted */
#define M_OB1	(0x0400L)			/* Object dependent mask #1 */
#define M_OB2	(0x0800L)			/* Object dependent mask #2 */
#define M_OB3	(0x1000L)			/* Object dependent mask #3 */
#define M_OB4	(0x2000L)			/* Object dependent mask #4 */
#define M_WB	(0x4000L)			/* waste basket mode */
#define M_RO	(0x8000L)			/* read only */
#define M_ZL	(0x10000L)			/* zero length */
#define M_IN	(0x20000L)			/* install functions */
#define M_OB5	(0x40000L)			/* the people cry out for more masks */

#define M_VF	(M_OB2)				/* view full screen mode */
#define M_NAR	(M_OB3)				/* narrow screen object */
#define M_BR	(M_OB4)				/* browse-only */

/* the high byte of the mask specifies the object classifications */

#define NOCLASS	(0x0L)
#define CL_DIR	(0x1000000L)		/* class directory */
#define CL_MAIL (0x2000000L)		/* class mail */
#define CL_DOC  (0x4000000L)		/* class document */
#define CL_NDIR	(0x8000000L)		/* class not directory (for fmask) */
#define CL_OEU	(0x10000000L)		/* class stored as oeu's */
#define CL_DYN  (0x20000000L)		/* dynamic - always reread */
#define CL_FMLI (0x40000000L)		/* generic FMLI object */

#define STATIC_FMASKS	(M_BR | M_WB | M_IN | CL_DIR | CL_NDIR)	/* fmasks that should not change to children calls */

#define O_FAIL	-1
#define O_OK	0

/* the following defines are for the modes field of the ott */

#define OTT_SALPHA	0x1		/* keep it sorted alphabetically */
#define OTT_SMTIME	0x2		/* sort it by mod time */
#define OTT_DOBJ	0x4		/* display the object name on line 2 */
#define OTT_DMTIME	0x8		/* display mod time on line 2 */
#define OTT_DODI	0x10	/* display object dependent info */
#define OTT_DMAIL	0x20	/* display for electronic mail */
#define OTT_DALL	0x40	/* display dot files */
#define OTT_LOCKED	0x80	/* the internal ott is locked into the table */
#define OTT_DLOCKED 0x100	/* the disk version of the ott is locked */
#define OTT_ACTIVE  0x200	/* this ott is in use */
#define OTT_DIRTY	0x400	/* ott has changed since being written */
#define OTT_SOBJ	0x800	/* sort by object type */
#define OTT_SREV	0x1000	/* reverse the sense of the sort */
#define OTT_DMARK	0x2000	/* display a mark next to names of dirs and execs*/

#define SORTMODES	(OTT_SALPHA|OTT_SMTIME|OTT_SOBJ|OTT_SREV)
#define DISMODES	(OTT_DOBJ|OTT_DMTIME|OTT_DODI|OTT_DMAIL|OTT_DMARK)

/* defines for the prefs field of the ott, tells what came from the .pref file*/

#define PREF_SORT	1
#define PREF_DIS	2

#define OTT_ENTRIES	40			/*init # ott_entries to malloc */

#ifndef WISH
#define MAX_OTT		6			/* maximum number of ott's we will keep */
#else
#define MAX_OTT		18
#endif

struct ott_entry  {
    char name[ONAMESIZ];	/* actual UNIX file name for object */
    char *dirpath;		/* directory where this object lives*/
    char *dname;		/* display name for this object */
    char *display;		/* user viewable display string */
    char *objtype;		/* unique name for type of object */
    int  next_part;		/* index into ott of the next part */
    long objmask;		/* mask bytes for functions */
    char *odi;			/* object dependent information */
    time_t mtime;		/* modification time for object. EFT k16*/
};

struct ott_tab  {
    struct ott_entry *ott;	/* table of otts (malloc'ed) */
    long fmask;			/* pref'ed fmask, only read in dvi() */
    int  *parents;		/* pointers to each parent (malloc'ed) */
    int  curpage;		/* current page we are on */
    int  numpages;		/* number of pages */
    int  modes;			/* method of sorting or displaying */
    long amask, nmask;		/* all/none display masks */
    int  prefs;			/* tells which preferences are external */
    char *path;			/* unix path to this ott's directory */
    time_t ott_mtime;		/* mod time of the ott. EFT abs k16 */
    time_t dir_mtime;		/* mod time of the unix directory. EFT k16 */
    long   last_used; 		/* higher numbers = more recently used.k16 */
    int  priority;		/* swapping priority */
};

struct prininfo {
	char *name;
	char *home;
	char *logid;
};

/* some function definitions for convenience */

struct ott_tab 	*ott_get(), *ott_synch();
