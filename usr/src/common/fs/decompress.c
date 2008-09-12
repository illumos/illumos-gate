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
 * Decompression module for stand alone file systems.
 */

#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/vnode.h>
#include <sys/bootvfs.h>
#include <sys/filep.h>
#include <zmod/zlib.h>

#ifdef	_BOOT
#include "../common/util.h"
#else
#include <sys/sunddi.h>
#endif

#define	MAX_DECOMP_BUFS		8
#define	GZIP_ID_BYTE_1		0x1f
#define	GZIP_ID_BYTE_2		0x8b
#define	GZIP_CM_DEFLATE		0x08
#define	SEEKBUFSIZE		8192

extern void prom_printf(const char *fmt, ...);

#ifdef	_BOOT
#define	dprintf	if (cf_debug) prom_printf
#else
#define	dprintf	if (cf_debug) prom_printf

#endif

extern int bootrd_debug;
extern void *bkmem_alloc(size_t);
extern void bkmem_free(void *, size_t);

caddr_t scratch_bufs[MAX_DECOMP_BUFS];	/* array of free scratch mem bufs */
int decomp_bufcnt;			/* total no, of allocated decomp bufs */
int free_dcomp_bufs;			/* no. of free decomp bufs */
char seek_scrbuf[SEEKBUFSIZE];		/* buffer for seeking */
int cf_debug = 0;			/* non-zero enables debug prints */

void *
cf_alloc(void *opaque, unsigned int items, unsigned int size)
{
	fileid_t *filep;
	unsigned int nbytes;
	caddr_t ptr;

	filep = (fileid_t *)opaque;
	nbytes = roundup(items * size, sizeof (long));
	if (nbytes > (DECOMP_BUFSIZE - filep->fi_dcscrused)) {
		ptr = bkmem_alloc(nbytes);
	} else {
		ptr = &filep->fi_dcscrbuf[filep->fi_dcscrused];
		filep->fi_dcscrused += nbytes;
	}
	bzero(ptr, nbytes);
	return (ptr);
}

/*
 * Decompression scratch memory free routine, does nothing since we free
 * the entire scratch area all at once on file close.
 */
/* ARGSUSED */
void
cf_free(void *opaque, void *addr)
{
}

/*
 * Read the first block of the file described by filep and determine if
 * the file is gzip-compressed.  If so, the compressed flag will be set
 * in the fileid_t struct pointed to by filep and it will be initialized
 * for doing decompression on reads to the file.
 */
int
cf_check_compressed(fileid_t *filep)
{
	unsigned char *filebytes;
	z_stream *zsp;

	/*
	 * checking for a dcfs compressed file first would involve:
	 *
	 *	if (filep->fi_inode->i_cflags & ICOMPRESS)
	 * 		filep->fi_flags |= FI_COMPRESSED;
	 */

	/*
	 * If the file is not long enough to check for a
	 * decompression header then return not compressed.
	 */
	if (filep->fi_inode->i_size < 3)
		return (0);
	filep->fi_offset = 0;
	if ((filep->fi_getblock)(filep) == -1)
		return (-1);
	filep->fi_offset = 0;
	filep->fi_count = 0;
	filep->fi_cfoff = 0;
	filebytes = (unsigned char *)filep->fi_memp;
	if (filebytes[0] != GZIP_ID_BYTE_1 ||
	    filebytes[1] != GZIP_ID_BYTE_2 ||
	    filebytes[2] != GZIP_CM_DEFLATE)
		return (0); /* not compressed */
	filep->fi_flags |= FI_COMPRESSED;

	dprintf("file %s is compressed\n", filep->fi_path);

	/*
	 * Allocate decompress scratch buffer
	 */
	if (free_dcomp_bufs) {
		filep->fi_dcscrbuf = scratch_bufs[--free_dcomp_bufs];
	} else {
		filep->fi_dcscrbuf = bkmem_alloc(DECOMP_BUFSIZE);
		decomp_bufcnt++;
	}
	filep->fi_dcscrused = 0;
	zsp = bkmem_alloc(sizeof (*zsp));
	filep->fi_dcstream = zsp;
	/*
	 * Initialize the decompression stream. Adding 16 to the window size
	 * indicates that zlib should expect a gzip header.
	 */
	bzero(zsp, sizeof (*zsp));
	zsp->opaque = filep;
	zsp->zalloc = cf_alloc;
	zsp->zfree = cf_free;
	zsp->avail_in = 0;
	zsp->next_in = NULL;
	zsp->avail_out = 0;
	zsp->next_out = NULL;
	if (inflateInit2(zsp, MAX_WBITS | 0x20) != Z_OK) {
		dprintf("inflateInit2() failed\n");
		return (-1);
	}
	return (0);
}

/*
 * If the file described by fileid_t struct at *filep is compressed
 * free any resources associated with the decompression.  (decompression
 * buffer, etc.).
 */
void
cf_close(fileid_t *filep)
{
	if ((filep->fi_flags & FI_COMPRESSED) == 0)
		return;
	dprintf("cf_close: %s\n", filep->fi_path);
	(void) inflateEnd(filep->fi_dcstream);
	bkmem_free(filep->fi_dcstream, sizeof (z_stream));
	if (free_dcomp_bufs == MAX_DECOMP_BUFS) {
		bkmem_free(filep->fi_dcscrbuf, DECOMP_BUFSIZE);
	} else {
		scratch_bufs[free_dcomp_bufs++] = filep->fi_dcscrbuf;
	}
}

void
cf_rewind(fileid_t *filep)
{
	z_stream *zsp;

	dprintf("cf_rewind: %s\n", filep->fi_path);
	zsp = filep->fi_dcstream;
	zsp->avail_in = 0;
	zsp->next_in = NULL;
	(void) inflateReset(zsp);
	filep->fi_cfoff = 0;
}

#define	FLG_FHCRC	0x02	/* crc field present */
#define	FLG_FEXTRA	0x04	/* "extra" field present */
#define	FLG_FNAME	0x08	/* file name field present */
#define	FLG_FCOMMENT	0x10	/* comment field present */

/*
 * Read at the current uncompressed offset from the compressed file described
 * by *filep.  Will return decompressed data.
 */
int
cf_read(fileid_t *filep, caddr_t buf, size_t count)
{
	z_stream *zsp;
	struct inode *ip;
	int err = Z_OK;
	int infbytes;
	off_t soff;
	caddr_t smemp;

	dprintf("cf_read: %s ", filep->fi_path);
	dprintf("%lx bytes\n", count);
	zsp = filep->fi_dcstream;
	ip = filep->fi_inode;
	dprintf("   reading at offset %lx\n", zsp->total_out);
	zsp->next_out = (unsigned char *)buf;
	zsp->avail_out = count;
	while (zsp->avail_out != 0) {
		if (zsp->avail_in == 0 && filep->fi_cfoff < ip->i_size) {
			/*
			 * read a block of the file to inflate
			 */
			soff = filep->fi_offset;
			smemp = filep->fi_memp;
			filep->fi_memp = NULL;
			filep->fi_offset = filep->fi_cfoff;
			filep->fi_count = 0;
			if ((*filep->fi_getblock)(filep) == -1)
				return (-1);
			filep->fi_offset = soff;
			zsp->next_in = (unsigned char *)filep->fi_memp;
			zsp->avail_in = filep->fi_count;
			filep->fi_memp = smemp;
			filep->fi_cfoff += filep->fi_count;
		}
		infbytes = zsp->avail_out;
		dprintf("attempting inflate of %x bytes to buf at: %lx\n",
		    zsp->avail_out, (unsigned long)zsp->next_out);
		err = inflate(zsp, Z_NO_FLUSH);
		infbytes -= zsp->avail_out;
		dprintf("inflated %x bytes, errcode=%d\n", infbytes, err);
		/*
		 * break out if we hit end of the compressed file
		 * or the end of the compressed byte stream
		 */
		if (filep->fi_cfoff >= ip->i_size || err == Z_STREAM_END)
			break;
	}
	dprintf("cf_read: returned %lx bytes\n", count - zsp->avail_out);
	return (count - zsp->avail_out);
}

/*
 * Seek to the location specified by addr
 */
void
cf_seek(fileid_t *filep, off_t addr, int whence)
{
	z_stream *zsp;
	int readsz;

	dprintf("cf_seek: %s ", filep->fi_path);
	dprintf("to %lx\n", addr);
	zsp = filep->fi_dcstream;
	if (whence == SEEK_CUR)
		addr += zsp->total_out;
	/*
	 * To seek backwards, must rewind and seek forwards
	 */
	if (addr < zsp->total_out) {
		cf_rewind(filep);
		filep->fi_offset = 0;
	} else {
		addr -= zsp->total_out;
	}
	while (addr > 0) {
		readsz = MIN(addr, SEEKBUFSIZE);
		(void) cf_read(filep, seek_scrbuf, readsz);
		addr -= readsz;
	}
}
