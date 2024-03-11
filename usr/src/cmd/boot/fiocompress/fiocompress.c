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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * fiocompress - a utility to compress files with a filesystem.
 * Used to build compressed boot archives to reduce memory
 * requirements for booting.
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <utility.h>
#include <zlib.h>

#include <sys/filio.h>
#include <sys/fs/decomp.h>

#include "message.h"

static void	setup_infile(char *);
static void	setup_outfile(char *);
static void	do_comp(size_t);
static void	do_decomp(void);

static caddr_t	srcaddr;
static size_t	srclen;

static int	dstfd;

static char	*srcfile;
static char	*dstfile;


int
main(int argc, char **argv)
{
	int compress = 0;
	int decompress = 0;
	int doioc = 0;
	size_t	blksize = 8192;
	int c;

	while ((c = getopt(argc, argv, "mcdb:")) != -1) {
		switch (c) {
		case 'm':
			doioc++;
			break;
		case 'c':
			if (decompress) {
				(void) fprintf(stderr, OPT_DC_EXCL);
				exit(-1);
			}
			compress = 1;
			break;
		case 'd':
			if (compress) {
				(void) fprintf(stderr, OPT_DC_EXCL);
				exit(-1);
			}
			decompress = 1;
			break;
		case 'b':
			blksize = atoi(optarg);
			if (blksize == 0 || (blksize & (blksize-1))) {
				(void) fprintf(stderr, INVALID_BLKSZ);
				exit(-1);
			}
			break;
		case '?':
			(void) fprintf(stderr, UNKNOWN_OPTION, optopt);
			exit(-1);
		}
	}
	if (argc - optind != 2) {
		(void) fprintf(stderr, MISS_FILES);
		exit(-1);
	}

	setup_infile(argv[optind]);
	setup_outfile(argv[optind + 1]);

	if (decompress)
		do_decomp();
	else {
		do_comp(blksize);
		if (doioc) {
			if (ioctl(dstfd, _FIO_COMPRESSED, 0) == -1) {
				(void) fprintf(stderr, FIO_COMP_FAIL,
				    dstfile, strerror(errno));
				exit(-1);
			}
		}
	}
	return (0);
}

static void
setup_infile(char *file)
{
	int fd;
	void *addr;
	struct stat stbuf;

	srcfile = file;

	fd = open(srcfile, O_RDONLY, 0);
	if (fd == -1) {
		(void) fprintf(stderr, CANT_OPEN,
		    srcfile, strerror(errno));
		exit(-1);
	}

	if (fstat(fd, &stbuf) == -1) {
		(void) fprintf(stderr, STAT_FAIL,
		    srcfile, strerror(errno));
		exit(-1);
	}
	srclen = stbuf.st_size;

	addr = mmap(0, srclen, PROT_READ, MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED) {
		(void) fprintf(stderr, MMAP_FAIL, srcfile, strerror(errno));
		exit(-1);
	}
	srcaddr = addr;
}

static void
setup_outfile(char *file)
{
	int fd;

	dstfile = file;

	fd = open(dstfile, O_WRONLY | O_CREAT | O_TRUNC,
	    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fd == -1) {
		(void) fprintf(stderr, OPEN_FAIL, dstfile, strerror(errno));
		exit(-1);
	}
	dstfd = fd;
}

static void
do_comp(size_t blksize)
{
	struct comphdr *hdr;
	off_t offset;
	size_t blks, dstlen, hlen;
	void *dstbuf;
	int i;

	blks = ((srclen - 1) / blksize) + 1;
	hlen = offset = sizeof (struct comphdr) + blks * sizeof (uint64_t);
	hdr = malloc(hlen);
	if (hdr == NULL) {
		(void) fprintf(stderr, HDR_ALLOC, hlen);
		exit(-1);
	}

	hdr->ch_magic = CH_MAGIC_ZLIB;
	hdr->ch_version = CH_VERSION;
	hdr->ch_algorithm = CH_ALG_ZLIB;
	hdr->ch_fsize = srclen;
	hdr->ch_blksize = blksize;

	dstlen = ZMAXBUF(blksize);
	dstbuf = malloc(dstlen);
	if (dstbuf == NULL) {
		(void) fprintf(stderr, BUF_ALLOC, dstlen);
		exit(-1);
	}

	if (lseek(dstfd, offset, SEEK_SET) == (off_t)-1) {
		(void) fprintf(stderr, SEEK_ERR,
		    offset, dstfile, strerror(errno));
		exit(-1);
	}

	for (i = 0; i < blks; i++) {
		ulong_t slen, dlen;
		int ret;

		hdr->ch_blkmap[i] = offset;
		slen = MIN(srclen, blksize);
		dlen = dstlen;
		ret = compress2(dstbuf, &dlen, (Bytef *)srcaddr, slen, 9);
		if (ret != Z_OK) {
			(void) fprintf(stderr, COMP_ERR, srcfile, ret);
			exit(-1);
		}

		if (write(dstfd, dstbuf, dlen) != dlen) {
			(void) fprintf(stderr, WRITE_ERR,
			    dlen, dstfile, strerror(errno));
			exit(-1);
		}

		offset += dlen;
		srclen -= slen;
		srcaddr += slen;
	}

	if (lseek(dstfd, 0, SEEK_SET) == (off_t)-1) {
		(void) fprintf(stderr, SEEK_ERR,
		    0, dstfile, strerror(errno));
		exit(-1);
	}

	if (write(dstfd, hdr, hlen) != hlen) {
		(void) fprintf(stderr, WRITE_ERR,
		    hlen, dstfile, strerror(errno));
		exit(-1);
	}
}

static void
do_decomp()
{
	struct comphdr *hdr;
	size_t blks, blksize;
	void *dstbuf;
	int i;
	ulong_t slen, dlen;
	int ret;

	hdr = (struct comphdr *)(void *)srcaddr;
	if (hdr->ch_magic != CH_MAGIC_ZLIB) {
		(void) fprintf(stderr, BAD_MAGIC,
		    srcfile, (uint64_t)hdr->ch_magic, CH_MAGIC_ZLIB);
		exit(-1);
	}
	if (hdr->ch_version != CH_VERSION) {
		(void) fprintf(stderr, BAD_VERS,
		    srcfile, (uint64_t)hdr->ch_version, CH_VERSION);
		exit(-1);
	}
	if (hdr->ch_algorithm != CH_ALG_ZLIB) {
		(void) fprintf(stderr, BAD_ALG,
		    srcfile, (uint64_t)hdr->ch_algorithm, CH_ALG_ZLIB);
		exit(-1);
	}

	blksize = hdr->ch_blksize;
	dstbuf = malloc(blksize);
	if (dstbuf == NULL) {
		(void) fprintf(stderr, HDR_ALLOC, blksize);
		exit(-1);
	}

	blks = (hdr->ch_fsize - 1) / blksize;
	srcaddr += hdr->ch_blkmap[0];
	for (i = 0; i < blks; i++) {
		dlen = blksize;
		slen = hdr->ch_blkmap[i + 1] - hdr->ch_blkmap[i];
		ret = uncompress(dstbuf, &dlen, (Bytef *)srcaddr, slen);
		if (ret != Z_OK) {
			(void) fprintf(stderr, DECOMP_ERR, srcfile, ret);
			exit(-1);
		}

		if (dlen != blksize) {
			(void) fprintf(stderr, CORRUPT, srcfile);
			exit(-1);
		}
		if (write(dstfd, dstbuf, dlen) != dlen) {
			(void) fprintf(stderr, WRITE_ERR,
			    dlen, dstfile, strerror(errno));
			exit(-1);
		}
		srcaddr += slen;
	}

	dlen = blksize;
	slen = hdr->ch_fsize - hdr->ch_blkmap[i];
	if ((ret = uncompress(dstbuf, &dlen, (Bytef *)srcaddr, slen)) != Z_OK) {
		(void) fprintf(stderr, DECOMP_ERR, dstfile, ret);
		exit(-1);
	}

	if (write(dstfd, dstbuf, dlen) != dlen) {
		(void) fprintf(stderr, WRITE_ERR,
		    dlen, dstfile, strerror(errno));
		exit(-1);
	}
}
