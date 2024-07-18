/*
 * Copyright (c) 1996, 1998 Robert Nordier
 * Copyright 2024 MNX Cloud, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef DOSIO_H
#define	DOSIO_H

/*
 * DOS file attributes
 */

#define	FA_RDONLY	001	/* read-only */
#define	FA_HIDDEN	002	/* hidden file */
#define	FA_SYSTEM	004	/* system file */
#define	FA_LABEL	010	/* volume label */
#define	FA_DIR		020	/* directory */
#define	FA_ARCH		040	/* archive (file modified) */
#define	FA_XDE		017	/* extended directory entry */
#define	FA_MASK		077	/* all attributes */

/*
 * Macros to convert DOS-format 16-bit and 32-bit quantities
 */

#define	cv2(p)  ((uint16_t)(p)[0] |         \
		((uint16_t)(p)[1] << 010))
#define	cv4(p)  ((uint32_t)(p)[0] |          \
		((uint32_t)(p)[1] << 010) |  \
		((uint32_t)(p)[2] << 020) |  \
		((uint32_t)(p)[3] << 030))

/*
 * Directory, filesystem, and file structures.
 */

typedef struct {
    uchar_t x_case;		/* case */
    uchar_t c_hsec;		/* created: secs/100 */
    uchar_t c_time[2];		/* created: time */
    uchar_t c_date[2];		/* created: date */
    uchar_t a_date[2];		/* accessed: date */
    uchar_t h_clus[2];		/* clus[hi] */
} DOS_DEX;

typedef struct {
    uchar_t name[8];		/* name */
    uchar_t ext[3];		/* extension */
    uchar_t attr;		/* attributes */
    DOS_DEX dex;		/* VFAT/FAT32 only */
    uchar_t time[2];		/* modified: time */
    uchar_t date[2];		/* modified: date */
    uchar_t clus[2];		/* starting cluster */
    uchar_t size[4];		/* size */
} DOS_DE;

typedef struct {
    uchar_t seq;		/* flags */
    uchar_t name1[5][2];	/* 1st name area */
    uchar_t attr;		/* (see fat_de) */
    uchar_t res;		/* reserved */
    uchar_t chk;		/* checksum */
    uchar_t name2[6][2];	/* 2nd name area */
    uchar_t clus[2];		/* (see fat_de) */
    uchar_t name3[2][2];	/* 3rd name area */
} DOS_XDE;

typedef union {
    DOS_DE de;			/* standard directory entry */
    DOS_XDE xde;		/* extended directory entry */
} DOS_DIR;

typedef struct {
    struct open_file *fd;	/* file descriptor */
    uchar_t *fatbuf;		/* FAT cache buffer */
    uint_t fatbuf_blknum;	/* number of 128K block in FAT cache buffer */
    uint_t links;		/* active links to structure */
    uint_t spc;			/* sectors per cluster */
    uint_t bsize;		/* cluster size in bytes */
    uint_t bshift;		/* cluster conversion shift */
    uint_t dirents;		/* root directory entries */
    uint_t spf;			/* sectors per fat */
    uint_t rdcl;		/* root directory start cluster */
    daddr_t lsnfat;		/* start of fat */
    daddr_t lsndir;		/* start of root dir */
    daddr_t lsndta;		/* start of data area */
    uint_t fatsz;		/* FAT entry size */
    uint_t xclus;		/* maximum cluster number */
    DOS_DE root;
} DOS_FS;

typedef struct {
    DOS_FS *fs;			/* associated filesystem */
    DOS_DE de;			/* directory entry */
    uint_t offset;		/* current offset */
    uint_t c;			/* last cluster read */
} DOS_FILE;

#endif	/* !DOSIO_H */
