/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_ZCONF_H
#define	_ZCONF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	z_off_t	off_t
#define	OF(p)	p
#define	ZEXTERN	extern
#define	ZEXPORT
#define	ZEXPORTVA
#define	FAR

#define	deflateInit_		z_deflateInit_
#define	deflate			z_deflate
#define	deflateEnd		z_deflateEnd
#define	inflateInit_		z_inflateInit_
#define	inflate			z_inflate
#define	inflateEnd		z_inflateEnd
#define	deflateInit2_		z_deflateInit2_
#define	deflateSetDictionary	z_deflateSetDictionary
#define	deflateCopy   		z_deflateCopy
#define	deflateReset  		z_deflateReset
#define	deflateParams 		z_deflateParams
#define	inflateInit2_ 		z_inflateInit2_
#define	inflateSetDictionary	z_inflateSetDictionary
#define	inflateSync		z_inflateSync
#define	inflateSyncPoint	z_inflateSyncPoint
#define	inflateReset		z_inflateReset
#define	inflate_blocks		z_inflate_blocks
#define	inflate_blocks_free	z_inflate_blocks_free
#define	inflate_blocks_new	z_inflate_blocks_new
#define	inflate_blocks_reset	z_inflate_blocks_reset
#define	inflate_blocks_sync_point z_inflate_blocks_sync_point
#define	inflate_codes		z_inflate_codes
#define	inflate_codes_new	z_inflate_codes_new
#define	inflate_codes_free	z_inflate_codes_free
#define	inflate_fast		z_inflate_fast
#define	inflate_flush		z_inflate_flush
#define	inflate_mask		z_inflate_mask
#define	inflate_trees_fixed	z_inflate_trees_fixed
#define	inflate_trees_bits	z_inflate_trees_bits
#define	inflate_trees_dynamic	z_inflate_trees_dynamic
#define	inflate_set_dictionary	z_inflate_set_dictionary
#define	adler32			z_adler32
#define	crc32			z_crc32
#define	get_crc_table		z_get_crc_table

#define	MAX_MEM_LEVEL	9
#define	MAX_WBITS	15

typedef unsigned char Byte;
typedef unsigned int uInt;
typedef unsigned long uLong;
typedef Byte Bytef;
typedef char charf;
typedef int intf;
typedef uInt uIntf;
typedef uLong uLongf;
typedef void *voidpf;
typedef void *voidp;

#ifdef	__cplusplus
}
#endif

#endif	/* _ZCONF_H */
