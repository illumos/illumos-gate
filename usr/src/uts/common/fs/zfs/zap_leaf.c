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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * The 512-byte leaf is broken into 32 16-byte chunks.
 * chunk number n means l_chunk[n], even though the header precedes it.
 * the names are stored null-terminated.
 */

#include <sys/zfs_context.h>
#include <sys/zap.h>
#include <sys/zap_impl.h>
#include <sys/zap_leaf.h>
#include <sys/spa.h>
#include <sys/dmu.h>

#define	CHAIN_END 0xffff /* end of the chunk chain */

/* somewhat arbitrary, could go up to around 100k ... */
#define	MAX_ARRAY_BYTES (8<<10)

#define	NCHUNKS(bytes) (((bytes)+ZAP_LEAF_ARRAY_BYTES-1)/ZAP_LEAF_ARRAY_BYTES)

/*
 * XXX This will >> by a negative number when
 * lh_prefix_len > 64-ZAP_LEAF_HASH_SHIFT.
 */
#define	LEAF_HASH(l, h) \
	((ZAP_LEAF_HASH_NUMENTRIES-1) & \
		((h) >> (64 - ZAP_LEAF_HASH_SHIFT-(l)->lh_prefix_len)))

#define	LEAF_HASH_ENTPTR(l, h) (&(l)->l_phys->l_hash[LEAF_HASH(l, h)])

/* #define	MEMCHECK */


static void
zap_memset(void *a, int c, size_t n)
{
	char *cp = a;
	char *cpend = cp + n;

	while (cp < cpend)
		*cp++ = c;
}

static void
stv(int len, void *addr, uint64_t value)
{
	switch (len) {
	case 1:
		*(uint8_t *)addr = value;
		return;
	case 2:
		*(uint16_t *)addr = value;
		return;
	case 4:
		*(uint32_t *)addr = value;
		return;
	case 8:
		*(uint64_t *)addr = value;
		return;
	}
	ASSERT(!"bad int len");
}

static uint64_t
ldv(int len, const void *addr)
{
	switch (len) {
	case 1:
		return (*(uint8_t *)addr);
	case 2:
		return (*(uint16_t *)addr);
	case 4:
		return (*(uint32_t *)addr);
	case 8:
		return (*(uint64_t *)addr);
	}
	ASSERT(!"bad int len");
	return (0xFEEDFACEDEADBEEF);
}

void
zap_leaf_byteswap(zap_leaf_phys_t *buf)
{
	int i;

	buf->l_hdr.lhr_block_type = 	BSWAP_64(buf->l_hdr.lhr_block_type);
	buf->l_hdr.lhr_next = 		BSWAP_64(buf->l_hdr.lhr_next);
	buf->l_hdr.lhr_prefix = 	BSWAP_64(buf->l_hdr.lhr_prefix);
	buf->l_hdr.lhr_magic = 		BSWAP_32(buf->l_hdr.lhr_magic);
	buf->l_hdr.lhr_nfree = 		BSWAP_16(buf->l_hdr.lhr_nfree);
	buf->l_hdr.lhr_nentries = 	BSWAP_16(buf->l_hdr.lhr_nentries);
	buf->l_hdr.lhr_prefix_len = 	BSWAP_16(buf->l_hdr.lhr_prefix_len);
	buf->l_hdr.lh_freelist = 	BSWAP_16(buf->l_hdr.lh_freelist);

	for (i = 0; i < ZAP_LEAF_HASH_NUMENTRIES; i++)
		buf->l_hash[i] = BSWAP_16(buf->l_hash[i]);

	for (i = 0; i < ZAP_LEAF_NUMCHUNKS; i++) {
		struct zap_leaf_entry *le;

		switch (buf->l_chunk[i].l_free.lf_type) {
		case ZAP_LEAF_ENTRY:
			le = &buf->l_chunk[i].l_entry;

			le->le_type = BSWAP_8(le->le_type);
			le->le_int_size = BSWAP_8(le->le_int_size);
			le->le_next = BSWAP_16(le->le_next);
			le->le_name_chunk = BSWAP_16(le->le_name_chunk);
			le->le_name_length = BSWAP_16(le->le_name_length);
			le->le_value_chunk = BSWAP_16(le->le_value_chunk);
			le->le_value_length = BSWAP_16(le->le_value_length);
			le->le_cd = BSWAP_32(le->le_cd);
			le->le_hash = BSWAP_64(le->le_hash);
			break;
		case ZAP_LEAF_FREE:
			buf->l_chunk[i].l_free.lf_type =
			    BSWAP_8(buf->l_chunk[i].l_free.lf_type);
			buf->l_chunk[i].l_free.lf_next =
			    BSWAP_16(buf->l_chunk[i].l_free.lf_next);
			break;
		case ZAP_LEAF_ARRAY:
			/* zap_leaf_array */
			buf->l_chunk[i].l_array.la_type =
			    BSWAP_8(buf->l_chunk[i].l_array.la_type);
			buf->l_chunk[i].l_array.la_next =
			    BSWAP_16(buf->l_chunk[i].l_array.la_next);
			/* la_array doesn't need swapping */
			break;
		default:
			ASSERT(!"bad leaf type");
		}
	}
}

void
zap_leaf_init(zap_leaf_t *l)
{
	int i;

	ASSERT3U(sizeof (zap_leaf_phys_t), ==, l->l_dbuf->db_size);
	zap_memset(&l->l_phys->l_hdr, 0, sizeof (struct zap_leaf_header));
	zap_memset(&l->l_phys->l_hash, CHAIN_END, sizeof (l->l_phys->l_hash));
	for (i = 0; i < ZAP_LEAF_NUMCHUNKS; i++) {
		l->l_phys->l_chunk[i].l_free.lf_type = ZAP_LEAF_FREE;
		l->l_phys->l_chunk[i].l_free.lf_next = i+1;
	}
	l->l_phys->l_chunk[ZAP_LEAF_NUMCHUNKS-1].l_free.lf_next = CHAIN_END;
	l->lh_block_type = ZBT_LEAF;
	l->lh_magic = ZAP_LEAF_MAGIC;
	l->lh_nfree = ZAP_LEAF_NUMCHUNKS;
}

zap_leaf_t *
zap_leaf_chainmore(zap_leaf_t *l, zap_leaf_t *nl)
{
	nl->lh_prefix = l->lh_prefix;
	nl->lh_prefix_len = l->lh_prefix_len;
	nl->l_next = l->l_next;
	l->l_next = nl;
	nl->lh_next = l->lh_next;
	l->lh_next = nl->l_blkid;
	return (nl);
}

/*
 * Routines which manipulate leaf chunks (l_chunk[]).
 */

static uint16_t
zap_leaf_chunk_alloc(zap_leaf_t *l)
{
	int chunk;

	ASSERT(l->lh_nfree > 0);

	chunk = l->l_phys->l_hdr.lh_freelist;
	ASSERT3U(chunk, <, ZAP_LEAF_NUMCHUNKS);
	ASSERT3U(l->l_phys->l_chunk[chunk].l_free.lf_type, ==, ZAP_LEAF_FREE);

	l->l_phys->l_hdr.lh_freelist = l->l_phys->l_chunk[chunk].l_free.lf_next;

#ifdef MEMCHECK
	zap_memset(&l->l_phys->l_chunk[chunk], 0xa1,
	    sizeof (l->l_phys->l_chunk[chunk]));
#endif

	l->lh_nfree--;

	return (chunk);
}

static void
zap_leaf_chunk_free(zap_leaf_t *l, uint16_t chunk)
{
	struct zap_leaf_free *zlf = &l->l_phys->l_chunk[chunk].l_free;
	ASSERT3U(l->lh_nfree, <, ZAP_LEAF_NUMCHUNKS);
	ASSERT3U(chunk, <, ZAP_LEAF_NUMCHUNKS);
	ASSERT(zlf->lf_type != ZAP_LEAF_FREE);

#ifdef MEMCHECK
	zap_memset(&l->l_phys->l_chunk[chunk], 0xf4,
	    sizeof (l->l_phys->l_chunk[chunk]));
#endif

	zlf->lf_type = ZAP_LEAF_FREE;
	zlf->lf_next = l->l_phys->l_hdr.lh_freelist;
	bzero(zlf->lf_pad, sizeof (zlf->lf_pad)); /* help it to compress */
	l->l_phys->l_hdr.lh_freelist = chunk;

	l->lh_nfree++;
}


/*
 * Routines which manipulate leaf arrays (zap_leaf_array type chunks).
 */

static uint16_t
zap_leaf_array_create(const zap_entry_handle_t *zeh, const char *buf,
	int integer_size, int num_integers)
{
	uint16_t chunk_head;
	uint16_t *chunkp = &chunk_head;
	int byten = 0;
	uint64_t value;
	int shift = (integer_size-1)*8;
	int len = num_integers;
	zap_leaf_t *l = zeh->zeh_found_leaf;

	ASSERT3U(num_integers * integer_size, <, MAX_ARRAY_BYTES);

	while (len > 0) {
		uint16_t chunk = zap_leaf_chunk_alloc(l);
		struct zap_leaf_array *la = &l->l_phys->l_chunk[chunk].l_array;
		int i;

		la->la_type = ZAP_LEAF_ARRAY;
		for (i = 0; i < ZAP_LEAF_ARRAY_BYTES; i++) {
			if (byten == 0)
				value = ldv(integer_size, buf);
			la->la_array[i] = (value & (0xff << shift)) >> shift;
			value <<= 8;
			if (++byten == integer_size) {
				byten = 0;
				buf += integer_size;
				if (--len == 0)
					break;
			}
		}

		*chunkp = chunk;
		chunkp = &la->la_next;
	}
	*chunkp = CHAIN_END;

	return (chunk_head);
}

static void
zap_leaf_array_free(zap_entry_handle_t *zeh, uint16_t *chunkp)
{
	uint16_t chunk = *chunkp;
	zap_leaf_t *l = zeh->zeh_found_leaf;

	*chunkp = CHAIN_END;

	while (chunk != CHAIN_END) {
		int nextchunk = l->l_phys->l_chunk[chunk].l_array.la_next;
		ASSERT3U(l->l_phys->l_chunk[chunk].l_array.la_type, ==,
		    ZAP_LEAF_ARRAY);
		zap_leaf_chunk_free(l, chunk);
		chunk = nextchunk;
	}
}

/* array_len and buf_len are in integers, not bytes */
static void
zap_leaf_array_read(const zap_entry_handle_t *zeh, uint16_t chunk,
    int array_int_len, int array_len, int buf_int_len, uint64_t buf_len,
    char *buf)
{
	int len = MIN(array_len, buf_len);
	int byten = 0;
	uint64_t value = 0;
	zap_leaf_t *l = zeh->zeh_found_leaf;

	ASSERT3U(array_int_len, <=, buf_int_len);

	/* Fast path for one 8-byte integer */
	if (array_int_len == 8 && buf_int_len == 8 && len == 1) {
		struct zap_leaf_array *la = &l->l_phys->l_chunk[chunk].l_array;
		uint64_t *buf64 = (uint64_t *)buf;
		uint64_t val = *(uint64_t *)la->la_array;
		*buf64 = BE_64(val);
		return;
	}

	/* Fast path for an array of 1-byte integers (eg. the entry name) */
	if (array_int_len == 1 && buf_int_len == 1 &&
	    buf_len > array_len + ZAP_LEAF_ARRAY_BYTES) {
		while (chunk != CHAIN_END) {
			struct zap_leaf_array *la =
			    &l->l_phys->l_chunk[chunk].l_array;
			bcopy(la->la_array, buf, ZAP_LEAF_ARRAY_BYTES);
			buf += ZAP_LEAF_ARRAY_BYTES;
			chunk = la->la_next;
		}
		return;
	}

	while (len > 0) {
		struct zap_leaf_array *la = &l->l_phys->l_chunk[chunk].l_array;
		int i;

		ASSERT3U(chunk, <, ZAP_LEAF_NUMCHUNKS);
		for (i = 0; i < ZAP_LEAF_ARRAY_BYTES && len > 0; i++) {
			value = (value << 8) | la->la_array[i];
			byten++;
			if (byten == array_int_len) {
				stv(buf_int_len, buf, value);
				byten = 0;
				len--;
				if (len == 0)
					return;
				buf += buf_int_len;
			}
		}
		chunk = la->la_next;
	}
}

/*
 * Only to be used on 8-bit arrays.
 * array_len is actual len in bytes (not encoded le_value_length).
 * buf is null-terminated.
 */
static int
zap_leaf_array_equal(const zap_entry_handle_t *zeh, int chunk,
    int array_len, const char *buf)
{
	int bseen = 0;
	zap_leaf_t *l = zeh->zeh_found_leaf;

	while (bseen < array_len) {
		struct zap_leaf_array *la = &l->l_phys->l_chunk[chunk].l_array;
		int toread = MIN(array_len - bseen, ZAP_LEAF_ARRAY_BYTES);
		ASSERT3U(chunk, <, ZAP_LEAF_NUMCHUNKS);
		if (bcmp(la->la_array, buf + bseen, toread))
			break;
		chunk = la->la_next;
		bseen += toread;
	}
	return (bseen == array_len);
}

/*
 * Routines which manipulate leaf entries.
 */

int
zap_leaf_lookup(zap_leaf_t *l,
    const char *name, uint64_t h, zap_entry_handle_t *zeh)
{
	uint16_t *chunkp;
	struct zap_leaf_entry *le;

	zeh->zeh_head_leaf = l;

again:
	ASSERT3U(l->lh_magic, ==, ZAP_LEAF_MAGIC);

	for (chunkp = LEAF_HASH_ENTPTR(l, h);
	    *chunkp != CHAIN_END; chunkp = &le->le_next) {
		uint16_t chunk = *chunkp;
		le = &l->l_phys->l_chunk[chunk].l_entry;

		ASSERT3U(chunk, <, ZAP_LEAF_NUMCHUNKS);
		ASSERT3U(le->le_type, ==, ZAP_LEAF_ENTRY);

		if (le->le_hash != h)
			continue;

		zeh->zeh_found_leaf = l;
		if (zap_leaf_array_equal(zeh, le->le_name_chunk,
		    le->le_name_length, name)) {
			zeh->zeh_num_integers = le->le_value_length;
			zeh->zeh_integer_size = le->le_int_size;
			zeh->zeh_cd = le->le_cd;
			zeh->zeh_hash = le->le_hash;
			zeh->zeh_chunkp = chunkp;
			zeh->zeh_found_leaf = l;
			return (0);
		}
	}

	if (l->l_next) {
		l = l->l_next;
		goto again;
	}

	return (ENOENT);
}

/* Return (h1,cd1 >= h2,cd2) */
#define	HCD_GTEQ(h1, cd1, h2, cd2) \
	((h1 > h2) ? TRUE : ((h1 == h2 && cd1 >= cd2) ? TRUE : FALSE))

int
zap_leaf_lookup_closest(zap_leaf_t *l,
    uint64_t h, uint32_t cd, zap_entry_handle_t *zeh)
{
	uint16_t chunk;
	uint64_t besth = -1ULL;
	uint32_t bestcd = ZAP_MAXCD;
	uint16_t bestlh = ZAP_LEAF_HASH_NUMENTRIES-1;
	uint16_t lh;
	struct zap_leaf_entry *le;

	zeh->zeh_head_leaf = l;

again:
	ASSERT3U(l->lh_magic, ==, ZAP_LEAF_MAGIC);

	for (lh = LEAF_HASH(l, h); lh <= bestlh; lh++) {
		for (chunk = l->l_phys->l_hash[lh];
		    chunk != CHAIN_END; chunk = le->le_next) {
			le = &l->l_phys->l_chunk[chunk].l_entry;

			ASSERT3U(chunk, <, ZAP_LEAF_NUMCHUNKS);
			ASSERT3U(le->le_type, ==, ZAP_LEAF_ENTRY);

			if (HCD_GTEQ(le->le_hash, le->le_cd, h, cd) &&
			    HCD_GTEQ(besth, bestcd, le->le_hash, le->le_cd)) {
				ASSERT3U(bestlh, >=, lh);
				bestlh = lh;
				besth = le->le_hash;
				bestcd = le->le_cd;

				zeh->zeh_num_integers = le->le_value_length;
				zeh->zeh_integer_size = le->le_int_size;
				zeh->zeh_cd = le->le_cd;
				zeh->zeh_hash = le->le_hash;
				zeh->zeh_fakechunk = chunk;
				zeh->zeh_chunkp = &zeh->zeh_fakechunk;
				zeh->zeh_found_leaf = l;
			}
		}
	}

	if (l->l_next) {
		l = l->l_next;
		goto again;
	}

	return (bestcd == ZAP_MAXCD ? ENOENT : 0);
}

int
zap_entry_read(const zap_entry_handle_t *zeh,
    uint8_t integer_size, uint64_t num_integers, void *buf)
{
	struct zap_leaf_entry *le;

	le = &zeh->zeh_found_leaf->l_phys->l_chunk[*zeh->zeh_chunkp].l_entry;
	ASSERT3U(le->le_type, ==, ZAP_LEAF_ENTRY);

	if (le->le_int_size > integer_size)
		return (EINVAL);

	zap_leaf_array_read(zeh, le->le_value_chunk, le->le_int_size,
	    le->le_value_length, integer_size, num_integers, buf);

	if (zeh->zeh_num_integers > num_integers)
		return (EOVERFLOW);
	return (0);

}

int
zap_entry_read_name(const zap_entry_handle_t *zeh, uint16_t buflen, char *buf)
{
	struct zap_leaf_entry *le;

	le = &zeh->zeh_found_leaf->l_phys->l_chunk[*zeh->zeh_chunkp].l_entry;
	ASSERT3U(le->le_type, ==, ZAP_LEAF_ENTRY);

	zap_leaf_array_read(zeh, le->le_name_chunk, 1,
	    le->le_name_length, 1, buflen, buf);
	if (le->le_name_length > buflen)
		return (EOVERFLOW);
	return (0);
}

int
zap_entry_update(zap_entry_handle_t *zeh,
	uint8_t integer_size, uint64_t num_integers, const void *buf)
{
	int delta_chunks;
	struct zap_leaf_entry *le;
	le = &zeh->zeh_found_leaf->l_phys->l_chunk[*zeh->zeh_chunkp].l_entry;

	delta_chunks = NCHUNKS(num_integers * integer_size) -
	    NCHUNKS(le->le_value_length * le->le_int_size);

	if (zeh->zeh_found_leaf->lh_nfree < delta_chunks)
		return (EAGAIN);

	/*
	 * We should search other chained leaves (via
	 * zap_entry_remove,create?) otherwise returning EAGAIN will
	 * just send us into an infinite loop if we have to chain
	 * another leaf block, rather than being able to split this
	 * block.
	 */

	zap_leaf_array_free(zeh, &le->le_value_chunk);
	le->le_value_chunk =
	    zap_leaf_array_create(zeh, buf, integer_size, num_integers);
	le->le_value_length = (num_integers*integer_size > MAX_ARRAY_BYTES) ?
	    (MAX_ARRAY_BYTES + 1) : (num_integers);
	le->le_int_size = integer_size;
	return (0);
}

void
zap_entry_remove(zap_entry_handle_t *zeh)
{
	uint16_t entry_chunk;
	struct zap_leaf_entry *le;
	zap_leaf_t *l = zeh->zeh_found_leaf;

	ASSERT3P(zeh->zeh_chunkp, !=, &zeh->zeh_fakechunk);

	entry_chunk = *zeh->zeh_chunkp;
	le = &l->l_phys->l_chunk[entry_chunk].l_entry;
	ASSERT3U(le->le_type, ==, ZAP_LEAF_ENTRY);

	zap_leaf_array_free(zeh, &le->le_name_chunk);
	zap_leaf_array_free(zeh, &le->le_value_chunk);

	*zeh->zeh_chunkp = le->le_next;
	zap_leaf_chunk_free(l, entry_chunk);

	l->lh_nentries--;
}

int
zap_entry_create(zap_leaf_t *l, const char *name, uint64_t h, uint32_t cd,
    uint8_t integer_size, uint64_t num_integers, const void *buf,
    zap_entry_handle_t *zeh)
{
	uint16_t chunk;
	uint16_t *chunkp;
	struct zap_leaf_entry *le;
	uint64_t namelen, valuelen;
	int numchunks;

	valuelen = integer_size * num_integers;
	namelen = strlen(name) + 1;
	ASSERT(namelen >= 2);

	zeh->zeh_head_leaf = l;

	if (namelen > MAXNAMELEN)
		return (ENAMETOOLONG);
	/* find the first leaf in the chain that has sufficient free space */
	numchunks = 1 + NCHUNKS(namelen) + NCHUNKS(valuelen);
	if (numchunks > ZAP_LEAF_NUMCHUNKS)
		return (E2BIG);

	if (cd == ZAP_MAXCD) {
		for (cd = 0; cd < ZAP_MAXCD; cd++) {
			zap_leaf_t *ll;
			for (ll = l; ll; ll = ll->l_next) {
				for (chunk = *LEAF_HASH_ENTPTR(ll, h);
				    chunk != CHAIN_END; chunk = le->le_next) {
					le = &ll->l_phys->l_chunk
					    [chunk].l_entry;
					if (le->le_hash == h &&
					    le->le_cd == cd) {
						break;
					}
				}
				/*
				 * if this cd is in use, no need to
				 * check more chained leafs
				 */
				if (chunk != CHAIN_END)
					break;
			}
			/* If this cd is not in use, we are good. */
			if (chunk == CHAIN_END)
				break;
		}
		/* If we tried all the cd's, we lose. */
		if (cd == ZAP_MAXCD)
			return (ENOSPC);
	}

	for (; l; l = l->l_next)
		if (l->lh_nfree >= numchunks)
			break;
	if (l == NULL)
		return (EAGAIN);

	zeh->zeh_found_leaf = l;

	/* make the entry */
	chunk = zap_leaf_chunk_alloc(l);
	le = &l->l_phys->l_chunk[chunk].l_entry;
	le->le_type = ZAP_LEAF_ENTRY;
	le->le_name_chunk = zap_leaf_array_create(zeh, name, 1, namelen);
	le->le_name_length = namelen;
	le->le_value_chunk =
	    zap_leaf_array_create(zeh, buf, integer_size, num_integers);
	le->le_value_length = (num_integers*integer_size > MAX_ARRAY_BYTES) ?
	    (MAX_ARRAY_BYTES + 1) : (num_integers);
	le->le_int_size = integer_size;
	le->le_hash = h;
	le->le_cd = cd;

	/* link it into the hash chain */
	chunkp = LEAF_HASH_ENTPTR(l, h);
	le->le_next = *chunkp;
	*chunkp = chunk;

	l->lh_nentries++;

	zeh->zeh_num_integers = num_integers;
	zeh->zeh_integer_size = le->le_int_size;
	zeh->zeh_cd = le->le_cd;
	zeh->zeh_hash = le->le_hash;
	zeh->zeh_chunkp = chunkp;

	return (0);
}

/*
 * Routines for transferring entries between leafs.
 */

static void
zap_leaf_rehash_entry(zap_leaf_t *l, uint16_t entry)
{
	struct zap_leaf_entry *le = &l->l_phys->l_chunk[entry].l_entry;
	uint16_t *ptr = LEAF_HASH_ENTPTR(l, le->le_hash);
	le->le_next = *ptr;
	*ptr = entry;
}

static void
zap_leaf_rehash_entries(zap_leaf_t *l)
{
	int i;

	if (l->lh_nentries == 0)
		return;

	/* break existing hash chains */
	zap_memset(l->l_phys->l_hash, CHAIN_END, sizeof (l->l_phys->l_hash));

	for (i = 0; i < ZAP_LEAF_NUMCHUNKS; i++) {
		struct zap_leaf_entry *le = &l->l_phys->l_chunk[i].l_entry;
		if (le->le_type != ZAP_LEAF_ENTRY)
			continue;
		zap_leaf_rehash_entry(l, i);
	}
}

static uint16_t
zap_leaf_transfer_array(zap_leaf_t *l, uint16_t chunk, zap_leaf_t *nl)
{
	uint16_t new_chunk;
	uint16_t *nchunkp = &new_chunk;

	while (chunk != CHAIN_END) {
		uint16_t nchunk = zap_leaf_chunk_alloc(nl);
		struct zap_leaf_array *nla =
		    &nl->l_phys->l_chunk[nchunk].l_array;
		struct zap_leaf_array *la =
		    &l->l_phys->l_chunk[chunk].l_array;
		int nextchunk = la->la_next;

		ASSERT3U(chunk, <, ZAP_LEAF_NUMCHUNKS);
		ASSERT3U(nchunk, <, ZAP_LEAF_NUMCHUNKS);

		*nla = *la;

		zap_leaf_chunk_free(l, chunk);
		chunk = nextchunk;
		*nchunkp = nchunk;
		nchunkp = &nla->la_next;
	}
	*nchunkp = CHAIN_END;
	return (new_chunk);
}

static void
zap_leaf_transfer_entry(zap_t *zap, zap_leaf_t *l, int entry, zap_leaf_t *nhl,
    dmu_tx_t *tx)
{
	zap_leaf_t *nl;
	struct zap_leaf_entry *le, *nle;
	uint16_t chunk, nchunks;

	le = &l->l_phys->l_chunk[entry].l_entry;
	ASSERT3U(le->le_type, ==, ZAP_LEAF_ENTRY);

	/* find a leaf in the destination leaf chain with enough free space */
	nchunks = 1 + NCHUNKS(le->le_name_length) +
	    NCHUNKS(le->le_value_length * le->le_int_size);
	for (nl = nhl; nl; nl = nl->l_next)
		if (nl->lh_nfree >= nchunks)
			break;
	if (nl == NULL) {
		nl = zap_leaf_chainmore(nhl, zap_create_leaf(zap, tx));
		dprintf("transfer_entry: chaining leaf %x/%d\n",
		    nl->lh_prefix, nl->lh_prefix_len);
	}

	chunk = zap_leaf_chunk_alloc(nl);
	nle = &nl->l_phys->l_chunk[chunk].l_entry;
	*nle = *le;

	zap_leaf_rehash_entry(nl, chunk);

	nle->le_name_chunk = zap_leaf_transfer_array(l, le->le_name_chunk, nl);
	nle->le_value_chunk =
	    zap_leaf_transfer_array(l, le->le_value_chunk, nl);

	zap_leaf_chunk_free(l, entry);

	l->lh_nentries--;
	nl->lh_nentries++;
}

/*
 * Transfer entries whose hash bit 'bit' is 1 to nl1, and 0 to nl0.
 * Ignore leaf chaining in source (l), but chain in destinations.
 * We'll re-chain all the entries in l as we go along.
 */
static void
zap_leaf_transfer_entries(zap_t *zap, zap_leaf_t *l,
    zap_leaf_t *nl0, zap_leaf_t *nl1, int bit, dmu_tx_t *tx)
{
	int i;

	ASSERT(bit < 64 && bit >= 0);
	/* break existing hash chains */
	zap_memset(l->l_phys->l_hash, CHAIN_END, sizeof (l->l_phys->l_hash));

	if (nl0 != l)
		zap_leaf_rehash_entries(nl0);
	if (nl1 != nl0)
		zap_leaf_rehash_entries(nl1);

	for (i = 0; i < ZAP_LEAF_NUMCHUNKS; i++) {
		struct zap_leaf_entry *le = &l->l_phys->l_chunk[i].l_entry;
		if (le->le_type != ZAP_LEAF_ENTRY)
			continue;

		/*
		 * We could find entries via hashtable instead. That
		 * would be O(hashents+numents) rather than
		 * O(numblks+numents), but this accesses memory more
		 * sequentially, and when we're called, the block is
		 * usually pretty full.
		 */

		if (le->le_hash & (1ULL << bit)) {
			zap_leaf_transfer_entry(zap, l, i, nl1, tx);
		} else {
			if (nl0 == l)
				zap_leaf_rehash_entry(l, i);
			else
				zap_leaf_transfer_entry(zap, l, i, nl0, tx);
		}
	}

}

/*
 * nl will contain the entries whose hash prefix ends in 1
 * handles leaf chaining
 */
zap_leaf_t *
zap_leaf_split(zap_t *zap, zap_leaf_t *hl, dmu_tx_t *tx)
{
	zap_leaf_t *l = hl;
	int bit = 64 - 1 - hl->lh_prefix_len;
	zap_leaf_t *nl = zap_create_leaf(zap, tx);

	/* set new prefix and prefix_len */
	hl->lh_prefix <<= 1;
	hl->lh_prefix_len++;
	nl->lh_prefix = hl->lh_prefix | 1;
	nl->lh_prefix_len = hl->lh_prefix_len;

	/* transfer odd entries from first leaf in hl chain to nl */
	zap_leaf_transfer_entries(zap, hl, hl, nl, bit, tx);

	/* take rest of chain off hl */
	l = hl->l_next;
	hl->l_next = NULL;
	hl->lh_next = 0;

	/* transfer even entries from hl chain back to hl, odd entries to nl */
	while (l) {
		zap_leaf_t *next = l->l_next;
		zap_leaf_transfer_entries(zap, l, hl, nl, bit, tx);
		zap_destroy_leaf(zap, l, tx);
		l = next;
	}

	return (nl);
}

void
zap_stats_leaf(zap_t *zap, zap_leaf_t *l, zap_stats_t *zs)
{
	int n, nchained = 0;

	n = zap->zap_f.zap_phys->zap_ptrtbl.zt_shift - l->lh_prefix_len;
	n = MIN(n, ZAP_HISTOGRAM_SIZE-1);
	zs->zs_leafs_with_2n_pointers[n]++;

	do {
		int i;

		n = l->lh_nentries/5;
		n = MIN(n, ZAP_HISTOGRAM_SIZE-1);
		zs->zs_blocks_with_n5_entries[n]++;

		n = ((1<<ZAP_BLOCK_SHIFT) -
		    l->lh_nfree * (ZAP_LEAF_ARRAY_BYTES+1))*10 /
		    (1<<ZAP_BLOCK_SHIFT);
		n = MIN(n, ZAP_HISTOGRAM_SIZE-1);
		zs->zs_blocks_n_tenths_full[n]++;

		for (i = 0; i < ZAP_LEAF_HASH_NUMENTRIES; i++) {
			int nentries = 0;
			int chunk = l->l_phys->l_hash[i];

			while (chunk != CHAIN_END) {
				struct zap_leaf_entry *le =
				    &l->l_phys->l_chunk[chunk].l_entry;

				n = 1 + NCHUNKS(le->le_name_length) +
				    NCHUNKS(le->le_value_length *
					le->le_int_size);
				n = MIN(n, ZAP_HISTOGRAM_SIZE-1);
				zs->zs_entries_using_n_chunks[n]++;

				chunk = le->le_next;
				nentries++;
			}

			n = nentries;
			n = MIN(n, ZAP_HISTOGRAM_SIZE-1);
			zs->zs_buckets_with_n_entries[n]++;
		}

		nchained++;
		l = l->l_next;
	} while (l);

	n = nchained-1;
	n = MIN(n, ZAP_HISTOGRAM_SIZE-1);
	zs->zs_leafs_with_n_chained[n]++;
}
