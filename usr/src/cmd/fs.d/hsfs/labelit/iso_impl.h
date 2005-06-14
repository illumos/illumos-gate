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
 * Copyright 2000 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/**************************************************************************
 *
 *	iso_impl.h	internal macros for /usr/etc/fs/HSFS/mkproto
 *
 ***************************************************************************/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Macros for counting and rounding.
 */
#ifdef howmany
#undef howmany
#endif

#if defined(sun386) || defined(i386)
#define howmany(x, y)   ((((u_int)(x))+(((u_int)(y))-1))/((u_int)(y)))
#define roundup(x, y)   ((((u_int)(x)+((u_int)(y)-1))/(u_int)(y))*(u_int)(y))
#else
#define howmany(x, y)   (((x)+((y)-1))/(y))
#define roundup(x, y)   ((((x)+((y)-1))/(y))*(y))
#endif

extern int cdout;
extern int set_size;	
extern int set_seq;	
extern int blk_size; 	
extern int nlbn_per_sec;           
extern char u[], v[];	
extern long unix_voldesc_sec;
extern int prototype;

#define PUTSECTOR(buf, secno, nosec) (putdisk(buf, (secno)*ISO_SECTOR_SIZE, \
                (nosec)*ISO_SECTOR_SIZE))
#define GETSECTOR(buf, secno, nosec) (getdisk(buf, (secno)*ISO_SECTOR_SIZE, \
                (nosec)*ISO_SECTOR_SIZE))
#define PUTLBN(buf, secno, nosec) (putdisk(buf, (secno)*blk_size, \
                (nosec)*blk_size))
#define GETLBN(buf, lbn, nolbn) (getdisk(buf, (lbn)*blk_size, \
                (nolbn)*blk_size))
#define LBN_TO_SEC(lbn) ((lbn)/nlbn_per_sec)
#define SEC_TO_LBN(sec) ((sec)*nlbn_per_sec)
#define LBN_TO_BYTE(lbn) ((lbn)*blk_size)
#define BYTE_TO_SEC(byte) (byte/ISO_SECTOR_SIZE)

#define CD_UNIX		0
#define CD_ISO		1

#define CD_MSB 		0
#define CD_LSB 		1

#define CD_REGULAR	1
#define CD_FILE		2
#define CD_DIRECTORY 	4
#define CD_DOT		8
#define CD_DOTDOT	16

#define UNIX_VOLDESC_SEC ISO_VOLDESC_SEC+1

/* internal data structure */
/* unix file info - to be copied to a cd-rom image */
struct ufname {
        int     fsize;          /* size of file in byte */
        char    fname[1];       /* file name, should be longer */
};

/* dlist - individual element of a directory tree */
struct dlist {
        struct dlist *dnext;    /* point to next */
        struct dlist *pdp;      /* point to parent */
        struct dlist *cdp;      /* point to child */
        struct dlist *ucdp;      /* point to first unix child */
        struct dlist *icdp;      /* point to first iso child */
	struct dlist *unext;	/* pointer to next in UNIX fname order */
	struct dlist *inext;	/* pointer to next in ISO fname order */
	struct dlist *idirnext;	/* pointer to next dir in iso, breadth first order */
	struct dlist *udirnext;	/* pointer to next dir in unix, breadth first order */
        int     idno;        	/* directory number in iso, in breadth first order */
        int     udno;        	/* directory number in unix, in breadth first order */
        int     ipoffset;        /* offset in iso path table - directory only */        
        int     upoffset;        /* offset in unix path table - directory only */        
	int     idlbn;           /* lbn of parent in iso directory */
        int     idoffset;        /* offset of parent in iso directory */
	int     udlbn;           /* lbn of parent in unix directory */
        int     udoffset;        /* offset of parent in unix directory */
        int     idextlbn;         /* lbn of extent in iso */
        int     udextlbn;         /* lbn of extent in unix */
	int	idsize;		/* iso directory size */
	int	udsize;		/* unix directory size */
	int	extlbn;		/* location of the data */
	int	fsize;		/* size of the data */
        time_t  mtime;          /* las modification time */
        long    duid;           /* owner's user id */
        long    dgid;           /* owner's group id */
        long    dmode;          /* mode and type of file */
	long 	nlink;		/* no. of links */	
        struct  ufname *ufnp;   /* pointer to the corresponding UNIX file */
        char    isofname[32];   /* iso file name */
        char    unixfname[1];   /* unix file name, should be longer */
};
 
void update_pvd();
void update_uvd();
void update_pvd_ptbl();
void update_uvd_ptbl();

struct dlist * mkdlist();
struct dlist * mkdlist_proto();
struct dlist * mkdlist_path();
void sortdlist(); 
 

