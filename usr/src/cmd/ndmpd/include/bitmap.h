/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * BSD 3 Clause License
 *
 * Copyright (c) 2007, The Storage Networking Industry Association.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 	- Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *
 * 	- Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in
 *	  the documentation and/or other materials provided with the
 *	  distribution.
 *
 *	- Neither the name of The Storage Networking Industry Association (SNIA)
 *	  nor the names of its contributors may be used to endorse or promote
 *	  products derived from this software without specific prior written
 *	  permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef _BITMAP_H_
#define	_BITMAP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/errno.h>

/*
 * This interface is designed to provide an abatract data type
 * for manipulating in-core and on-disk bitmaps.
 *
 * When a bitmap is allocated, a descriptor to the bitmap is
 * returned to the caller.  The descriptor is an integer.  All
 * functions of the API use this descriptor to locate the
 * bitmap.
 *
 * Each bitmap is divided into chunks (internally).  Each chunk
 * is BMAP_CHUNK_WORDS words (4K now).  Chunks are kept in an
 * LRU list for caching.
 *
 * There is also a hashing on the chunks for accessing them.
 * Each hash is an MRU list.
 *
 * The interfaces are:
 *  bm_alloc: To allocate a new bitmap.
 *  bm_free: To release the bitmap.
 *  bm_getlen: To get the length of the bitmap.
 *  bm_getiov: To get the bits specified by the vectors.
 *  bm_setiov: To set the bits specified by the vectors.
 *  bm_apply_ifset: Calls a callback function on each set
 *      bit in the bitmap.
 *  bm_apply_ifunset: Calls a callback function on each
 *  	clear bit in the bitmap.
 *
 * There are some other interface for simpilicty of programs:
 *   bm_get To get a range of bits.
 *   bm_set: To set a range of bits.
 *   bm_getone: To get one bit only.
 *   bm_setone: To set one bit only.
 *   bm_unsetone: To unset one bit only.
 *
 * The on-disk bitmap functions are the same except they start
 * with dbm_*
 */

typedef	u_longlong_t u_quad_t;

/*
 * A vector for setting bits in the bitmap.
 *     - bmv_base: The starting bit number.
 *     - bmv_len: Lenght of the vector.
 *     - bmv_val: Pointer to the new value of bits.
 */
typedef struct bm_iovec {
	u_quad_t bmv_base;
	u_quad_t bmv_len;
	uint_t *bmv_val;
} bm_iovec_t;


/*
 * An array of vectors on which the set/get operations
 * will take place.
 *     - bmio_iovcnt: Number of entries in the array.
 *     - bmio_iov: Array of vectors.
 */
typedef struct bm_io {
	int bmio_iovcnt;
	bm_iovec_t *bmio_iov;
} bm_io_t;

extern void bm_print(int);

/*
 * External Interface.
 */
extern int bm_alloc(u_quad_t, int);
extern int dbm_alloc(char *, u_quad_t, int);

extern int bm_free(int);
extern int dbm_free(int);

extern int bm_realloc(int, u_quad_t);
extern int dbm_realloc(int, u_quad_t);

extern int bm_setiov(int, bm_io_t *);
extern int dbm_setiov(int, bm_io_t *);
extern int bm_getiov(int, bm_io_t *);
extern int dbm_getiov(int, bm_io_t *);

extern int bm_apply_ifset(int, int (*)(), void *);
extern int dbm_apply_ifset(int, int (*)(), void *);
extern int bm_apply_ifunset(int, int (*)(), void *);
extern int dbm_apply_ifunset(int, int (*)(), void *);

extern char *dbm_getfname(int);
extern u_quad_t bm_getlen(int);
extern u_quad_t dbm_getlen(int);

extern void dbm_print(int);


/*
 * Statistical and debugging interface.
 */
extern void dbitmap_stats_clear(void);


/*
 * Macros for setting and unsetting only one bit.
 */
#define	bm_setone(bmd, bn)	bm_set((bmd), (bn), 1, 1)
#define	dbm_setone(bmd, bn)	dbm_set((bmd), (bn), 1, 1)
#define	bm_unsetone(bmd, bn)	bm_set((bmd), (bn), 1, 0)
#define	dbm_unsetone(bmd, bn)	dbm_set((bmd), (bn), 1, 0)

extern int bm_set(int, u_quad_t, u_quad_t, uint_t);
extern int dbm_set(int, u_quad_t, u_quad_t, uint_t);
extern int bm_get(int, u_quad_t, u_quad_t, uint_t *);
extern int dbm_get(int, u_quad_t, u_quad_t, uint_t *);
extern int bm_getone(int, u_quad_t);
extern int dbm_getone(int, u_quad_t);

#ifdef __cplusplus
}
#endif
#endif /* _BITMAP_H_ */
