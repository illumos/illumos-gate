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
 * Copyright 1994 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*      @(#)util.c 1.1 90/01/22 SMI      */
/*
 * mkproto: create a CD-ROM image files 
 *	usage: mkproto [-f] proto cdimage effdate expdate
 *	       mkproto [-f] path  cdimage effdate expdate
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI" 

#include <fcntl.h>
#include <stdio.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/file.h>
#include "iso_spec.h"
#include "iso_impl.h"
#include <sys/isa_defs.h>	/* for ENDIAN defines */

extern char *myname;

/*putdisk - write to cdrom image file */
putdisk(buf, daddr, size)
char *buf; /* buffer area */
int daddr; /* disk addr */
int size; /* no. of byte */
{
/*****
	if ((daddr < 1) || (daddr > 10000000) ) {
		printf("bad address %d\n", daddr);
	}
*****/
	if (lseek(cdout, daddr, L_SET) == -1) {
		perror("putdisk/lseek");
		exit(31+1);
	}
	if (write(cdout, buf, size) != size) {
		perror("putdisk/write");
		exit(31+1);
	}
}

/*readdisk - read from cdrom image file */
getdisk(buf, daddr, size)
char *buf; /* buffer area */
int daddr; /* disk addr */
int size; /* no. of byte */
{
        if (lseek(cdout, daddr, L_SET) == -1) {
                perror("getdisk/lseek");
                exit(31+1);
        }
        if (read(cdout, buf, size) != size) {
                perror("getdisk/read");
                exit(31+1);
        }
 
}

/* copy an integer x to location p in lsb format */
/* location p may not be in integer boundary */
lsb_int(p, x)
char *p;
int x;
{
#if defined(_LITTLE_ENDIAN)
	(void) memcpy(p, &x, sizeof(int));
#else
	*p++= THREE(&x);
	*p++=TWO(&x);
	*p++=ONE(&x);
	*p=ZERO(&x);	
#endif
}

/* copy an integer x to location p in msb format */
/* location p may not be in integer boundary */
msb_int(p, x)
char *p;
int x;
{
#if defined(_LITTLE_ENDIAN)
	*p++= THREE(&x);
	*p++=TWO(&x);
	*p++=ONE(&x);
	*p=ZERO(&x);	
#else
	(void) memcpy(p, &x, sizeof(int));
#endif
}

/* copy an integer x to location p in lsb then msb format */
/* location p may not be in integer boundary */
both_int(p, x)
char *p;
int x;
{
	lsb_int(p, x);	
	p = p + sizeof(x);
	msb_int(p, x);

}

/* copy a short integer x to location p in lsb format */
/* location p may not be in short integer boundary */
lsb_short(p, x)
char *p;
short x;
{
#if defined(_LITTLE_ENDIAN)
	(void) memcpy(p, &x, sizeof(short));
#else
	*p++=ONE(&x);
	*p=ZERO(&x);	
#endif
}

/* copy a short integer x to location p in msb format */
/* location p may not be in short integer boundary */
msb_short(p, x)
char *p;
short x;
{
#if defined(_LITTLE_ENDIAN)
	*p++=ONE(&x);
	*p=ZERO(&x);	
#else
	(void) memcpy(p, &x, sizeof(short));
#endif
}

/* copy a short integer x to location p in lsb then msb format */
/* location p may not be in short integer boundary */
both_short(p, x)
char *p;
short x;
{
	lsb_short(p, x);	
	p = p + sizeof(x);
	msb_short(p, x);
}

parse_hsdirdate(dp)
u_char *dp;
{
}

parse_unixdate(tt, dp)
time_t tt;
u_char *dp;
{
struct tm *t;

	t = gmtime(&tt);
	*dp++ = (u_char) t->tm_year;
	*dp++ = (u_char) t->tm_mon + 1;
	*dp++ = (u_char) t->tm_mday;
	*dp++ = (u_char) t->tm_hour;
	*dp++ = (u_char) t->tm_min;
	*dp++ = (u_char) t->tm_sec;
}

/* reserve and (zero out space) from start secno to end secno */
makespace(start_secno, end_secno)
int start_secno, end_secno;
{
int buf[ISO_SECTOR_SIZE/4];
int i;

	memset(buf, 0, ISO_SECTOR_SIZE);
	for (i=start_secno; i < end_secno; i++)
		PUTSECTOR(buf, i, 1);
}

/* fill logical block lbn, lbn+1... to sector boundary with zero */
fillzero(lbn)
int lbn;
{
int left;
int buf[ISO_SECTOR_SIZE/4];

	/* if lbn size is same as sector size, ok */
	if (nlbn_per_sec == 1) return (lbn);
	left = nlbn_per_sec - (lbn % nlbn_per_sec);
	if (left == nlbn_per_sec) return(lbn);

	memset(buf, 0, ISO_SECTOR_SIZE);
	PUTLBN(buf, lbn, left);
	return(lbn+left);
	
}

/* fillblkzero - fill to end of a logical block with zero
 * length may be longer than a block
 * return the next lbn available 
 */
int
fillblkzero(lbn, length)
int lbn;
int length;
{
int tofill;
int nolbn;
char *buf;
int offset;

	offset = length % blk_size;
	nolbn = howmany(length, blk_size);

	/* nothing to fill */
	if (offset == 0) return(lbn+nolbn);
		
	tofill= blk_size - offset;

	buf = (char *) malloc(tofill);
	(void) memset(buf, 0, tofill);
	(void) putdisk(buf, LBN_TO_BYTE(lbn+nolbn-1)+offset, tofill);
	(void) cfree(buf);
	
	return(lbn+nolbn);
}

/* cleanup - close file and exit */
cleanup()
{
	close(cdout);
	exit(31+1);
}

static u_char dtable[256] = {
0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
0x38, 0x39, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
0x00, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
0x58, 0x59, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x5f,
0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
};

static u_char mtable[256] = {
0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2e, 0x0,
0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
0x38, 0x39, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
0x00, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
0x58, 0x59, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x5f,
0x0, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
0x58, 0x59, 0x5a, 0x0, 0x0, 0x0, 0x0, 0x0,
};

un2in(un, in)
char *un, *in;
{
int i;
char c;
        while ((i = *un++) != '\0') {
                if (c = mtable[i]) *in++=c;
        }
        *in='\0';
}



prntunixdir(dirp)
char *dirp;
{
int i;
int length;
char c;
int offset;

        /* skip dot and dotdot */
        length = (u_int) IDE_NAME_LEN(dirp);
        c = IDE_NAME(dirp)[0];
 
        if ((length == 1 && c == '\0') ||
                (length == 1 && c == '\1')) return;
        printf("%d\t", IDE_XAR_LEN(dirp));
        printf("%d\t", IDE_EXT_LBN(dirp));
        printf("%d\t", IDE_EXT_SIZE(dirp));
        printf("%d\t", IDE_VOL_SET(dirp));
        for (i=0;i<length;i++)
                printf("%c", IDE_NAME(dirp)[i]);

	offset = (u_int) IDE_NAME_LEN(dirp);
	offset = offset & 0x01? offset : offset+1;
	offset = offset + IDE_FDESIZE;
	printf(" %x\t", IDE_UNIX_MODE(dirp + (u_int) offset));
	printf("%d\t", IDE_UNIX_UID(dirp + (u_int) offset));
	printf("%d\t", IDE_UNIX_GID(dirp + (u_int) offset));
	printf("%d\t", IDE_UNIX_NLINK(dirp + (u_int) offset));

        printf("\n");
}

prntisodir(dirp)
char *dirp;
{
int i;
int length;
char c;
        /* skip dot and dotdot */
        length = IDE_NAME_LEN(dirp);
        c = IDE_NAME(dirp)[0];

        if ((length == 1 && c == '\0') ||
                (length == 1 && c == '\1')) return;
        printf("%d\t", IDE_XAR_LEN(dirp));
        printf("%d\t", IDE_EXT_LBN(dirp));
        printf("%d\t", IDE_EXT_SIZE(dirp));
        printf("%d\t", IDE_VOL_SET(dirp));
        for (i=0;i<length;i++)
                printf("%c", IDE_NAME(dirp)[i]);
        printf("\n");
}
 


/*VARARGS*/
fatal(fmt, arg1, arg2)
        char *fmt;
{

        fprintf(stderr, "%s: ", myname);
        fprintf(stderr, fmt, arg1, arg2);
        putc('\n', stderr);
        exit(31+1);
}


