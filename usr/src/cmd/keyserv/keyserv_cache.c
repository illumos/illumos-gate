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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <thread.h>
#include <synch.h>
#include <stdlib.h>
#include <syslog.h>
#include <rpc/des_crypt.h>

#include "keyserv_cache.h"

struct cachekey {
	struct cachekey_header	*ch;
	keylen_t		keylen;
	algtype_t		algtype;
	mutex_t			mp;
	struct cachekey		*next;
};

static struct cachekey		*cache = 0;
static mutex_t			cache_lock = DEFAULTMUTEX;
static cond_t			cache_cv = DEFAULTCV;
static u_long			cache_refcnt = 0;

struct skck {
	des_block	common[3];
	des_block	verifier;	/* Checksum */
	struct dhkey	secret;
};

struct cachekey_disklist {
	uid_t				uid;
	struct cachekey_disklist	*prev;		/* LRU order */
	struct cachekey_disklist	*next;
	struct cachekey_disklist	*prevhash;	/* Hash chain */
	struct cachekey_disklist	*nexthash;
	struct dhkey			public;
	/*
	 * Storage for encrypted skck structure here. The length will be
	 * 8 * ( ( ( sizeof(struct skck) - 1 + secret.length ) - 1 ) / 8 + 1 )
	 */
};

/* Length of skck structure for given key length (in bits) */
#define	SKCK_LEN(keylen)	ALIGN8(sizeof (struct skck) + KEYLEN(keylen))
/* Length of a cachekey_disklist record for given key length (in bits) */
#define	CACHEKEY_RECLEN(keylen)	ALIGN8(sizeof (struct cachekey_disklist) - 1 + \
					KEYLEN(keylen) + SKCK_LEN(keylen))
#define	NUMHASHBUCKETS	253
#define	CHUNK_NUMREC	64

#define	CACHEKEY_HEADER_VERSION	0

struct cachekey_header {		/* First in each key cache file */
	u_int		version;	/* version number of interface */
	u_int		headerlength;	/* size of this header */
	keylen_t	keylen;		/* in bits */
	algtype_t	algtype;	/* algorithm type */
	size_t		reclength;	/* cache file record size in bytes */
	int		fd;		/* file descriptor */
	caddr_t		address;	/* mmap()ed here */
	size_t		length;		/* bytes mapped */
	size_t		maxsize;	/* don't grow beyond this */
	u_int		inuse_count;
	struct cachekey_disklist	*inuse;	/* LRU order */
	struct cachekey_disklist	*inuse_end;
	u_int				free_count;
	struct cachekey_disklist	*free;
	struct cachekey_disklist	*bucket[NUMHASHBUCKETS];
	struct cachekey_disklist	array[1];	/* Start of array */
};


static struct cachekey_header	*create_cache_file_ch(keylen_t keylen,
							algtype_t algtype,
							int sizespec);

static struct cachekey_header	*remap_cache_file_ch(struct cachekey_header *ch,
						u_int newrecs);

static struct cachekey_header	*cache_insert_ch(struct cachekey_header *ch,
						uid_t uid, deskeyarray common,
						des_block key,
						keybuf3 *public,
						keybuf3 *secret);

static struct cachekey3_list	*cache_retrieve_ch(struct cachekey_header *ch,
						uid_t uid,
						keybuf3 *public,
						des_block key);

static int			cache_remove_ch(struct cachekey_header *ch,
						uid_t uid,
						keybuf3 *public);

static struct cachekey		*get_cache_header(keylen_t keylen,
							algtype_t algtype);

static void			release_cache_header(struct cachekey *);

static int			cache_remap_addresses_ch(
					struct cachekey_header *);

static struct cachekey_disklist	*find_cache_item(struct cachekey_header **,
						uid_t, struct dhkey *);

static struct dhkey		*keybuf3_2_dhkey(keybuf3 *);

static u_int			hashval(uid_t);

static void			list_remove(struct cachekey_disklist *,
						struct cachekey_disklist **,
						struct cachekey_disklist **,
						u_int *);

static void			list_remove_hash(struct cachekey_disklist *,
						struct cachekey_disklist **,
						struct cachekey_disklist **,
						u_int *);

static void			list_insert(struct cachekey_disklist *,
						struct cachekey_disklist **,
						struct cachekey_disklist **,
						u_int *);

static void			list_insert_hash(struct cachekey_disklist *,
						struct cachekey_disklist **,
						struct cachekey_disklist **,
						u_int *);

static struct cachekey3_list *	copy_cl_item(struct cachekey_header *ch,
						struct cachekey_disklist *cd,
						des_block key);

extern int			hex2bin(u_char *, u_char *, int);
extern int			bin2hex(u_char *, u_char *, int);

/*
 * The folowing set of macros implement address validity checking. A valid
 * address is defined to be either 0, or to fall on a record boundary. In
 * the latter case, the the difference between the address and the start of
 * the record array is divisible by the record length.
 */
#define	FILEOFFSET(ckh)			((u_long)(ckh) - \
					(u_long)((ckh)->address))
#define	ADJUSTEDADDR(addr, ckh)		((u_long)(addr) + FILEOFFSET(ckh))
#define	ARRAYOFFSET(addr, ckh)		(ADJUSTEDADDR(addr, ckh) - \
					(u_long)&((ckh)->array[0]))
#define	INVALID_ADDRESS(addr, ckh)	((addr == 0) ? 0 : \
			(ARRAYOFFSET(addr, ckh) % (ckh)->reclength) != 0)

/* Add offset to old address */
#define	MOVE_ADDR(old, offset)	((old) == 0) ? 0 : \
				(void *)((u_long)(old) + (offset))

/* Number of records in use or on free list */
#define	NUMRECS(ck_header)	((ck_header)->inuse_count + \
				(ck_header)->free_count)

/* Max number of records the mapped file could hold */
#define	MAPRECS(ck_header)	(((ck_header)->length - \
				sizeof (struct cachekey_header)) / \
				(ck_header)->reclength)
/* Max number of records the file will hold if extended to the maxsize */
#define	MAXRECS(ck_header)	(((ck_header)->maxsize - \
				sizeof (struct cachekey_header)) / \
				(ck_header)->reclength)


struct cachekey_header *
create_cache_file_ch(keylen_t keylen, algtype_t algtype, int sizespec)
{
	char				filename[MAXPATHLEN];
	struct cachekey_header		*ch;
	int				fd, newfile = 0, i, checkvalid = 1;
	struct stat			statbuf;
	size_t				reclength, length;
	struct cachekey_header		*oldbase = 0;
	struct cachekey_disklist	*cd;
	size_t maxsize;

	/* Construct cache file name */
	if (snprintf(filename, sizeof (filename), "/var/nis/.keyserv_%d-%d",
			keylen, algtype) > sizeof (filename)) {
		syslog(LOG_WARNING,
		"error constructing file name for mech %d-%d", keylen, algtype);
		return (0);
	}

	/* Open/create the file */
	if ((fd = open(filename, O_RDWR|O_CREAT, 0600)) < 0) {
		syslog(LOG_WARNING, "cache file open error for mech %d-%d: %m",
			keylen, algtype);
		return (0);
	}

	/* We want exclusive use of the file */
	if (lockf(fd, F_LOCK, 0) < 0) {
		syslog(LOG_WARNING, "cache file lock error for mech %d-%d: %m",
			keylen, algtype);
		close(fd);
		return (0);
	}

	/* Zero size means a new file */
	if (fstat(fd, &statbuf) < 0) {
		syslog(LOG_WARNING, "cache file fstat error for mech %d-%d: %m",
			keylen, algtype);
		close(fd);
		return (0);
	}

	reclength = CACHEKEY_RECLEN(keylen);
	if (sizespec < 0) {
		/* specifies the number of records in file */
		maxsize = ALIGN8(sizeof (struct cachekey_header)) +
			-sizespec*reclength;
	} else {
		/* specifies size of file in MB */
		maxsize = sizespec*1024*1024;
	}
	length    = ALIGN8(sizeof (struct cachekey_header)) +
			reclength*CHUNK_NUMREC;
	if (length > maxsize) {
		/*
		 * First record resides partly in the header, so the length
		 * cannot be allowed to be less than header plus one record.
		 */
		if (maxsize > ALIGN8(sizeof (struct cachekey_header)+reclength))
			length = maxsize;
		else {
			length  = ALIGN8(sizeof (struct cachekey_header)+
					reclength);
			maxsize = length;
		}
	}

	if (statbuf.st_size == 0) {
		/* Extend the file if we just created it */
		if (ftruncate(fd, length) < 0) {
			syslog(LOG_WARNING,
				"cache file ftruncate error for mech %d-%d: %m",
				keylen, algtype);
			close(fd);
			return (0);
		}
		newfile = 1;
	} else {
		/*
		 * Temporarily mmap the header, to sanity check and obtain
		 * the address where it was mapped the last time.
		 */
		if ((ch = (void *)mmap(0, sizeof (struct cachekey_header),
				PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0)) ==
			MAP_FAILED) {
			syslog(LOG_WARNING,
				"cache file mmap1 error for mech %d-%d: %m",
				keylen, algtype);
			close(fd);
			return (0);
		}
		if (ch->version != CACHEKEY_HEADER_VERSION ||
			ch->headerlength != sizeof (struct cachekey_header) ||
			ch->keylen != keylen ||
			ch->algtype != algtype ||
			ch->reclength != reclength ||
			ch->length < sizeof (struct cachekey_header) ||
			ch->maxsize < ch->length ||
			INVALID_ADDRESS(ch->inuse, ch) ||
			INVALID_ADDRESS(ch->free, ch)) {
			syslog(LOG_WARNING,
			"cache file consistency error for mech %d-%d",
				keylen, algtype);
			munmap((caddr_t)ch, sizeof (struct cachekey_header));
			close(fd);
			return (0);
		}
		oldbase = (void *)ch->address;
		length  = ch->length;
		if (munmap((caddr_t)ch, sizeof (struct cachekey_header)) < 0) {
			syslog(LOG_WARNING,
				"cache file munmap error for mech %d-%d: %m",
				keylen, algtype);
			close(fd);
			return (0);
		}
	}

	/* Map the file */
	if ((ch = (void *)mmap((caddr_t)oldbase, length,
		PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED) {
		syslog(LOG_WARNING,
			"cache file mmap2 error for mech %d-%d: %m",
				keylen, algtype);
		close(fd);
		return (0);
	}

	ch->fd		= fd;
	ch->maxsize	= maxsize;

	if (newfile) {
		ch->version		= CACHEKEY_HEADER_VERSION;
		ch->headerlength	= sizeof (struct cachekey_header);
		ch->keylen		= keylen;
		ch->algtype		= algtype;
		ch->reclength		= reclength;
		ch->length		= length;
		ch->address		= (caddr_t)ch;
		ch->inuse_count		= 0;
		ch->inuse		= 0;
		ch->inuse_end		= 0;
		ch->free		= 0;
		ch->free_count		= 0;
		for (i = 0; i < NUMHASHBUCKETS; i++) {
			ch->bucket[i] = 0;
		}

		cd = &(ch->array[0]);
		for (i = 0; i < MAPRECS(ch);
			i++, cd = MOVE_ADDR(cd, ch->reclength)) {
			cd->uid		= (uid_t)-1;
			cd->prev	= MOVE_ADDR(cd, -(ch->reclength));
			cd->next	= MOVE_ADDR(cd, +(ch->reclength));
			cd->prevhash	= 0;
			cd->nexthash	= 0;
		}
		/*
		 * Last record next pointer, and first record prev pointer,
		 * are both NULL.
		 */
		cd		= MOVE_ADDR(cd, -(ch->reclength));
		cd->next	= 0;
		cd		= &(ch->array[0]);
		cd->prev	= 0;

		ch->free_count	= MAPRECS(ch);
		ch->free	= &(ch->array[0]);

		(void) msync((caddr_t)ch, ch->length, MS_SYNC);

	} else if (ch->length > maxsize) {
		/* File should shrink */
		if ((ch = remap_cache_file_ch(ch, MAXRECS(ch))) == 0) {
			return (0);
		}
		checkvalid = 0;
	}

	/*
	 * cache_remap_addresses() also checks address consistency, so call
	 * it even if the remap is a no-op. However, if we've called
	 * remap_cache_file_ch(), it will have invoked cache_remap_addresses()
	 * already, so we don't have to do that again.
	 */
	if (checkvalid &&
		cache_remap_addresses_ch(ch) == 0) {
		syslog(LOG_WARNING, "cache file invalid for mech %d-%d",
			keylen, algtype);
		(void) munmap((caddr_t)ch, ch->length);
		close(fd);
		return (0);
	}

	(void) msync((caddr_t)ch, ch->length, MS_SYNC);

	return (ch);
}


static int
cache_remap_addresses_ch(struct cachekey_header *ch)
{
	int				i;
	u_long				offset;
	struct cachekey_disklist	*cd;

	offset = (u_long)ch - (u_long)ch->address;

	if (INVALID_ADDRESS(ch->inuse, ch) ||
		INVALID_ADDRESS(ch->inuse_end, ch) ||
		INVALID_ADDRESS(ch->free, ch)) {
		return (0);
	}

	ch->inuse	= MOVE_ADDR(ch->inuse, offset);
	ch->inuse_end	= MOVE_ADDR(ch->inuse_end, offset);
	ch->free	= MOVE_ADDR(ch->free, offset);

	cd = &(ch->array[0]);
	for (i = 0; i < NUMRECS(ch); i++) {
		if (INVALID_ADDRESS(cd->prev, ch) ||
			INVALID_ADDRESS(cd->next, ch) ||
			INVALID_ADDRESS(cd->prevhash, ch) ||
			INVALID_ADDRESS(cd->nexthash, ch)) {
			return (0);
		}
		cd->prev	= MOVE_ADDR(cd->prev, offset);
		cd->next	= MOVE_ADDR(cd->next, offset);
		cd->prevhash	= MOVE_ADDR(cd->prevhash, offset);
		cd->nexthash	= MOVE_ADDR(cd->nexthash, offset);
		cd = MOVE_ADDR(cd, ch->reclength);
	}

	for (i = 0; i < NUMHASHBUCKETS; i++) {
		if (INVALID_ADDRESS(ch->bucket[i], ch)) {
			return (0);
		}
		ch->bucket[i] = MOVE_ADDR(ch->bucket[i], offset);
	}

	/*
	 * To prevent disaster if this function is invoked again, we
	 * update ch->address, so that offset will be zero if we do
	 * get called once more, and the mapped file hasn't moved.
	 */
	ch->address = (caddr_t)ch;

	return (1);
}


/*
 * Remap cache file with space for 'newrecs' records. The mmap:ed address
 * may have to move; the new address is returned.
 */
static struct cachekey_header *
remap_cache_file_ch(struct cachekey_header *ch, u_int newrecs)
{
	size_t				newsize, oldsize;
	u_int				currecs;
	int				i, fd;
	struct cachekey_header		*newch;
	caddr_t				oldaddr;
	struct cachekey_disklist	*cd = 0;

	if (ch == 0)
		return (0);


	/*
	 * Since the first record partly resides in the cachekey_header,
	 * newrecs cannot be less than 1.
	 */
	if (newrecs < 1)
		newrecs = 1;

	newsize = ALIGN8(sizeof (struct cachekey_header)) +
			(ch->reclength)*newrecs;
	currecs = NUMRECS(ch);

	if (newsize > ch->maxsize) {
		/* Would exceed maximum allowed */
		newsize = ch->maxsize;
	}

	/* Save stuff we need while the file is unmapped */
	oldsize	= ch->length;
	oldaddr	= (caddr_t)ch;
	fd	= ch->fd;

	if (newsize > ch->length) {
		/* Extending the file */
		cd = &(ch->array[0]);
	} else if (newsize == ch->length) {
		/* Already OK */
		return (ch);
	} else {
		size_t				tmpsize;
		struct cachekey_disklist	*fcd;
		/*
		 * Shrink the file by removing records from the end.
		 * First, we have to make sure the file contains valid
		 * addresses.
		 */
		if (cache_remap_addresses_ch(ch) == 0) {
			syslog(LOG_WARNING, "cache file invalid for mech %d-%d",
			ch->keylen, ch->algtype);
			close(ch->fd);
			munmap((caddr_t)ch, ch->length);
			return (0);
		}
		fcd = MOVE_ADDR(&(ch->array[0]),
				ch->reclength*(MAPRECS(ch)-1));
		tmpsize = (u_long)fcd - (u_long)ch + ch->reclength;
		while (tmpsize > newsize && fcd > &(ch->array[0])) {
			if (fcd->uid == (uid_t)-1) {
				list_remove(fcd, &(ch->free), 0,
					&(ch->free_count));
			} else {
				list_remove_hash(fcd,
					&(ch->bucket[hashval(fcd->uid)]), 0, 0);
				list_remove(fcd, &(ch->inuse), &(ch->inuse_end),
						&(ch->inuse_count));
			}
			tmpsize -= ch->reclength;
			fcd = MOVE_ADDR(fcd, -(ch->reclength));
		}
		ch->length = newsize;
		(void) msync((caddr_t)ch, ch->length, MS_SYNC);
	}

	/* Unmap the file */
	if (munmap((caddr_t)oldaddr, oldsize) < 0) {
		return (0);
	}
	ch = 0;

	/* Truncate/extend it */
	if (ftruncate(fd, newsize) < 0) {
		return (0);
	}

	/* Map it again */
	if ((newch = (void *)mmap(oldaddr, newsize,
			PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0)) ==
	MAP_FAILED) {
		return (0);
	}

	/* Update with new values */
	newch->length	= newsize;

	if (cache_remap_addresses_ch(newch) == 0) {
		syslog(LOG_WARNING, "cache file invalid for mech %d-%d",
			newch->keylen, newch->algtype);
		newch->length = oldsize;
		close(newch->fd);
		munmap((caddr_t)newch, newsize);
		return (0);
	}

	/* If extending the file, add new records to the free list */
	if (cd != 0) {
		cd = MOVE_ADDR(&(newch->array[0]), currecs*newch->reclength);
		for (i = currecs; i < MAPRECS(newch); i++) {
			cd->uid		= (uid_t)-1;
			list_insert(cd, &(newch->free), 0,
					&(newch->free_count));
			cd		= MOVE_ADDR(cd, newch->reclength);
		}
	}

	(void) msync(newch->address, newch->length, MS_SYNC);

	return (newch);
}


#ifdef DEBUG
void
print_cache_ch(struct cachekey_header *ch)
{
	int				i, inuse, inuse_err, free, free_err;
	int				pb;
	struct cachekey_disklist	*cd;

	printf(
"\nkeylen = %d, algtype = %d, version = %d, headerlen = %d, reclen = %d\n",
		ch->keylen, ch->algtype, ch->version, ch->headerlength,
		ch->reclength);
	printf("fd = %d, address = 0x%x, mapped length = %d, maxsize = %d\n",
		ch->fd, ch->address, ch->length, ch->maxsize);
	printf("inuse = %d, free = %d\n", ch->inuse_count, ch->free_count);

	printf("Active hash buckets:\n");

	for (i = 0, inuse = 0, inuse_err = 0; i < NUMHASHBUCKETS; i++) {
		cd = ch->bucket[i];
		pb = -1;
		if (cd != 0) {
			pb = 0;
			printf("\t%d: ", i);
		}
		while (cd != 0) {
			pb++;
			printf("%d ", cd->uid);
			if (cd->uid != (uid_t)-1) {
				inuse++;
			} else {
				inuse_err++;
			}
			cd = cd->nexthash;
		}
		if (pb >= 0)
			printf(" (%d)\n", pb);
	}

	printf("\ncounted hash inuse = %d, errors = %d\n", inuse, inuse_err);

	cd = ch->inuse;
	inuse = inuse_err = 0;
	while (cd != 0) {
		if (cd->uid != (uid_t)-1) {
			inuse++;
		} else {
			inuse_err++;
		}
		cd = cd->next;
	}
	printf("counted LRU  inuse = %d, errors = %d\n", inuse, inuse_err);

	cd = ch->free;
	free = free_err = 0;
	while (cd != 0) {
		if (cd->uid == (uid_t)-1) {
			free++;
		} else {
			free_err++;
			fprintf(stderr, "free = %d, err = %d, cd->uid = %d\n",
				free, free_err, cd->uid);
		}
		cd = cd->next;
	}
	printf("counted      free = %d, errors = %d\n", free, free_err);
}

void
print_cache(keylen_t keylen, algtype_t algtype)
{
	struct cachekey	*c;

	if ((c = get_cache_header(keylen, algtype)) == 0)
		return;

	if (c->ch == 0) {
		release_cache_header(c);
		return;
	}

	print_cache_ch(c->ch);

	release_cache_header(c);
}
#endif



static u_int
hashval(uid_t uid)
{
	return (uid % NUMHASHBUCKETS);
}


static void
list_remove(
	struct cachekey_disklist *item,
	struct cachekey_disklist **head,
	struct cachekey_disklist **tail,
	u_int *count)
{
	if (item == NULL) return;

	/* Handle previous item, if any */
	if (item->prev == 0)
		*head = item->next;
	else
		item->prev->next = item->next;

	/* Take care of the next item, if any */
	if (item->next != 0)
		item->next->prev = item->prev;

	/* Handle tail pointer, if supplied */
	if (tail != 0 && *tail == item)
		*tail = item->prev;

	item->prev = item->next = 0;
	if (count != 0)
		(*count)--;
}


static void
list_remove_hash(
	struct cachekey_disklist *item,
	struct cachekey_disklist **head,
	struct cachekey_disklist **tail,
	u_int *count)
{
	if (item == NULL) return;

	/* Handle previous item, if any */
	if (item->prevhash == 0)
		*head = item->nexthash;
	else
		item->prevhash->nexthash = item->nexthash;

	/* Take care of the next item, if any */
	if (item->nexthash != 0)
		item->nexthash->prevhash = item->prevhash;

	/* Handle tail pointer, if supplied */
	if (tail != 0 && *tail == item)
		*tail = item->prevhash;

	item->prevhash = item->nexthash = 0;
	if (count != 0)
		(*count)--;
}


static void
list_insert(
	struct cachekey_disklist *item,
	struct cachekey_disklist **head,
	struct cachekey_disklist **tail,
	u_int *count)
{
	if (item == NULL) return;

	/* Insert at tail, if supplied */
	if (tail != 0) {
		item->prev = *tail;
		if (item->prev != 0)
			item->prev->next = item;
		item->next	= 0;
		*tail		= item;
		if (*head == 0)
			*head	= item;
	} else {
		item->next = *head;
		if (item->next != 0)
			item->next->prev = item;
		item->prev	= 0;
		*head		= item;
	}
	if (count != 0)
		(*count)++;
}

static void
list_insert_hash(
	struct cachekey_disklist *item,
	struct cachekey_disklist **head,
	struct cachekey_disklist **tail,
	u_int *count)
{
	if (item == NULL) return;

	/* Insert at tail, if supplied */
	if (tail != 0) {
		item->prevhash = *tail;
		if (item->prevhash != 0)
			item->prevhash->nexthash = item;
		item->nexthash	= 0;
		*tail		= item;
		if (*head == 0)
			*head	= item;
	} else {
		item->nexthash	= *head;
		if (item->nexthash != 0)
			item->nexthash->prevhash = item;
		item->prevhash	= 0;
		*head		= item;
	}
	if (count != 0)
		(*count)++;
}


/*
 * Find the cache item specified by the header, uid, and public key. If
 * no such uid/public item exists, return a pointer to an empty record.
 * In either case, the item returned has been removed from any and all
 * lists.
 */
static struct cachekey_disklist *
find_cache_item(struct cachekey_header **ch, uid_t uid, struct dhkey *public)
{
	u_int				hash;
	struct cachekey_disklist	*cd;

	hash = hashval(uid);

	if ((ch == NULL) || ((*ch) == NULL)) {
		return (0);
	}
	for (cd = (*ch)->bucket[hash]; cd != 0; cd = cd->nexthash) {
		if (uid == cd->uid &&
			public->length == cd->public.length &&
			memcmp(public->key, cd->public.key,
				cd->public.length) == 0) {
			list_remove_hash(cd, &((*ch)->bucket[hash]), 0, 0);
			list_remove(cd, &((*ch)->inuse), &((*ch)->inuse_end),
					&((*ch)->inuse_count));
			return (cd);
		}
	}

	if ((cd = (*ch)->free) != 0) {
		list_remove(cd, &((*ch)->free), 0, &((*ch)->free_count));
		return (cd);
	}

	/* Try to extend the file by CHUNK_NUMREC records */
	if (((*ch) = remap_cache_file_ch(*ch, NUMRECS(*ch)+CHUNK_NUMREC)) == 0)
		return (0);

	/* If the extend worked, there should now be at least one free record */
	if ((cd = (*ch)->free) != 0) {
		list_remove(cd, &((*ch)->free), 0, &((*ch)->free_count));
		return (cd);
	}

	/* Sacrifice the LRU item, if there is one */
	if ((cd = (*ch)->inuse) == 0)
		return (0);

	/* Extract from hash list */
	list_remove_hash(cd, &((*ch)->bucket[hashval(cd->uid)]), 0, 0);
	/* Extract from LRU list */
	list_remove(cd, &((*ch)->inuse), &((*ch)->inuse_end),
			&((*ch)->inuse_count));

	return (cd);
}


static struct cachekey_header *
cache_insert_ch(
	struct cachekey_header *ch,
	uid_t uid,
	deskeyarray common,
	des_block key,
	keybuf3 *public,
	keybuf3 *secret)
{
	struct cachekey_disklist	*cd;
	struct cachekey_header		*newch;
	int				i, err;
	struct skck			*skck;
	des_block			ivec;
	struct dhkey			*pk;
	struct dhkey			*sk;


	if (ch == 0 || uid == (uid_t)-1) {
		return (0);
	}

	if (common.deskeyarray_len > sizeof (skck->common)/sizeof (des_block) ||
		(pk = keybuf3_2_dhkey(public)) == 0 ||
		(sk = keybuf3_2_dhkey(secret)) == 0) {
		return (0);
	}

	newch = ch;
	if ((cd = find_cache_item(&newch, uid, pk)) == 0) {
		free(pk);
		free(sk);
		return (newch);
	}

	/*
	 * The item may have been free, or may have been the LRU sacrificial
	 * lamb, so reset all fields.
	 */
	cd->uid = uid;
	memcpy(&(cd->public), pk, DHKEYSIZE(pk));

	skck = MOVE_ADDR(&(cd->public), DHKEYSIZE(pk));
	for (i = 0; i < common.deskeyarray_len; i++) {
		skck->common[i] = common.deskeyarray_val[i];
	}
	skck->verifier = key;
	memcpy(&(skck->secret), sk, DHKEYSIZE(sk));
	free(pk);
	free(sk);
	memcpy(ivec.c, key.c, sizeof (key.c));
	err = cbc_crypt(key.c, (char *)skck, SKCK_LEN(newch->keylen),
			DES_ENCRYPT|DES_HW, ivec.c);
	if (DES_FAILED(err)) {
		/* Re-insert on free list */
		list_insert(cd, &(newch->free), 0, &(newch->free_count));
		return (newch);
	}

	/* Re-insert on hash list */
	list_insert_hash(cd, &(newch->bucket[hashval(cd->uid)]), 0, 0);
	/* Insert at end of LRU list */
	list_insert(cd, &(newch->inuse), &(newch->inuse_end),
			&(newch->inuse_count));

	(void) msync((caddr_t)newch, newch->length, MS_SYNC);

	return (newch);
}


static struct cachekey3_list *
copy_cl_item(struct cachekey_header *ch, struct cachekey_disklist *cd,
		des_block key) {

	struct cachekey3_list		*cl;
	struct skck			*skck, *skck_cd;
	int				i, err;
	des_block			ivec;

	/* Allocate the cachekey3_list structure */
	if ((cl = malloc(CACHEKEY3_LIST_SIZE(ch->keylen))) == 0) {
		return (0);
	}

	/* Allocate skck structure for decryption */
	if ((skck = malloc(SKCK_LEN(ch->keylen))) == 0) {
		free(cl);
		return (0);
	}

	/* Decrypt and check verifier */
	skck_cd = MOVE_ADDR(&(cd->public), DHKEYSIZE(&(cd->public)));
	memcpy(skck, skck_cd, SKCK_LEN(ch->keylen));
	memcpy(ivec.c, key.c, sizeof (ivec.c));
	err = cbc_crypt(key.c, (char *)skck, SKCK_LEN(ch->keylen),
			DES_DECRYPT|DES_HW, ivec.c);
	if (DES_FAILED(err)) {
		free(cl);
		free(skck);
		return (0);
	}
	if (memcmp(key.c, skck->verifier.c, sizeof (skck->verifier.c)) != 0) {
		free(cl);
		free(skck);
		return (0);
	}

	/* Everything OK; copy values */
	cl->public		= MOVE_ADDR(cl, sizeof (struct cachekey3_list));
	cl->public->keybuf3_val	= MOVE_ADDR(cl->public, sizeof (keybuf3));
	cl->secret		= MOVE_ADDR(cl->public->keybuf3_val,
					ALIGN4(2*KEYLEN(ch->keylen)+1));
	cl->secret->keybuf3_val	= MOVE_ADDR(cl->secret, sizeof (keybuf3));
	cl->deskey.deskeyarray_val =
				MOVE_ADDR(cl->secret->keybuf3_val,
					ALIGN4(2*KEYLEN(ch->keylen)+1));
	bin2hex(cd->public.key, (u_char *)cl->public->keybuf3_val,
		cd->public.length);
	cl->public->keybuf3_len = cd->public.length*2+1;

	bin2hex(skck->secret.key, (u_char *)cl->secret->keybuf3_val,
		skck->secret.length);
	cl->secret->keybuf3_len = skck->secret.length*2+1;
	cl->deskey.deskeyarray_len = sizeof (skck->common)/sizeof (des_block);
	for (i = 0; i < cl->deskey.deskeyarray_len; i++) {
		cl->deskey.deskeyarray_val[i] = skck->common[i];
	}

	cl->refcnt = 0;
	cl->next   = 0;

	free(skck);

	return (cl);

}


static struct cachekey3_list *
cache_retrieve_ch(struct cachekey_header *ch, uid_t uid, keybuf3 *public,
		des_block key) {

	struct cachekey_disklist	*cd;
	struct cachekey3_list		*cl = 0, **cltmp = &cl;
	u_int				hash;
	struct dhkey			*pk = 0;

	if (uid == (uid_t)-1 ||
		(public != 0 && (pk = keybuf3_2_dhkey(public)) == 0)) {
		return (0);
	}

	hash = hashval(uid);

	for (cd = ch->bucket[hash]; cd != 0; cd = cd->nexthash) {
		if (uid == cd->uid) {
			/* Match on public key as well ? */
			if (pk != 0) {
				if (memcmp(cd->public.key, pk->key,
						cd->public.length) != 0) {
					/* Keep looking... */
					continue;
				}
				cl = copy_cl_item(ch, cd, key);
				/* Match on public key => nothing more to do */
				break;
			}
			*cltmp = copy_cl_item(ch, cd, key);
			if (*cltmp == 0) {
				/* Return what we've got */
				break;
			}
			cltmp = &((*cltmp)->next);
			/* On to the next item */
		}
	}

	if (pk != 0)
		free(pk);

	return (cl);
}


/*
 * Remove specified item. 'public' == 0 => remove all items for uid.
 * Return number of items removed.
 */
static int
cache_remove_ch(struct cachekey_header *ch, uid_t uid, keybuf3 *public) {

	struct cachekey_disklist	*cd, *cdtmp;
	u_int				hash;
	int				match = 0;
	struct dhkey			*pk = 0;

	if (uid == (uid_t)-1 ||
		(public != 0 && (pk = keybuf3_2_dhkey(public)) == 0)) {
		return (0);
	}

	hash = hashval(uid);

	for (cd = ch->bucket[hash]; cd != 0; ) {
		if (uid == cd->uid) {
			/* Match on public key as well ? */
			if (pk != 0) {
				if (memcmp(cd->public.key, pk->key,
						cd->public.length) != 0) {
					/* Keep looking... */
					continue;
				}
				match++;
				list_remove_hash(cd, &(ch->bucket[hash]), 0, 0);
				list_remove(cd, &(ch->inuse), &(ch->inuse_end),
						&(ch->inuse_count));
				cd->uid = (uid_t)-1;
				list_insert(cd, &(ch->free), 0,
						&(ch->free_count));
				/* Match on public key => nothing more to do */
				break;
			}
			match++;
			/*
			 * XXX: Assume that the order of the hash list remains
			 * the same after removal of an item. If this isn't
			 * true, we really should start over from the start
			 * of the hash bucket.
			 */
			cdtmp = cd->nexthash;
			list_remove_hash(cd, &(ch->bucket[hash]), 0, 0);
			list_remove(cd, &(ch->inuse), &(ch->inuse_end),
					&(ch->inuse_count));
			cd->uid = (uid_t)-1;
			list_insert(cd, &(ch->free), 0,
					&(ch->free_count));
			/* On to the next item */
			cd = cdtmp;
		} else {
			cd = cd->nexthash;
		}
	}

	free(pk);
	return (match);
}


#define	INCCACHEREFCNT	mutex_lock(&cache_lock); \
			cache_refcnt++; \
			mutex_unlock(&cache_lock)

#if !defined(lint) && !defined(__lint)
#define	DECCACHEREFCNT	mutex_lock(&cache_lock); \
			if (cache_refcnt > 0) \
				if (cache_refcnt-- == 0) (void) cond_broadcast(&cache_cv); \
			mutex_unlock(&cache_lock)
#else
#define	DECCACHEREFCNT	mutex_lock(&cache_lock); \
			if (cache_refcnt-- == 0) (void) cond_broadcast(&cache_cv); \
			mutex_unlock(&cache_lock)
#endif

/*
 * Return the cachekey structure for the specified keylen and algtype.
 * When returned, the lock in the structure has been activated. It's the
 * responsibility of the caller to unlock it by calling release_cache_header().
 */
static struct cachekey *
get_cache_header(keylen_t keylen, algtype_t algtype) {

	struct cachekey		*c;

	INCCACHEREFCNT;

	for (c = cache; c != 0; c = c->next) {
		if (c->keylen == keylen && c->algtype == algtype) {
			mutex_lock(&c->mp);
			return (c);
		}
	}

	/* Spin until there are no cache readers */
	mutex_lock(&cache_lock);
#if !defined(lint) && !defined(__lint)
	if (cache_refcnt > 0)
#endif
		cache_refcnt--;
	while (cache_refcnt != 0) {
		(void) cond_wait(&cache_cv, &cache_lock);
	}

	if ((c = malloc(sizeof (struct cachekey))) != 0) {
		c->ch		= 0;
		c->keylen	= keylen;
		c->algtype	= algtype;
		mutex_init(&c->mp, 0, 0);
		c->next		= cache;
		cache		= c;
		mutex_lock(&c->mp);
		cache_refcnt++;
		mutex_unlock(&cache_lock);
		return (c);
	}

	mutex_unlock(&cache_lock);
	return (0);
}


static void
release_cache_header(struct cachekey *ck) {

	struct cachekey	*c;

	if (ck == 0)
		return;

	for (c = cache; c != 0; c = c->next) {
		if (c == ck) {
			mutex_unlock(&c->mp);
			DECCACHEREFCNT;
			break;
		}
	}
}


int
create_cache_file(keylen_t keylen, algtype_t algtype, int sizespec)
{
	struct cachekey	*c;
	int		ret;

	if ((c = get_cache_header(keylen, algtype)) == 0)
		return (0);

	if (c->ch != 0) {
		/* Already created and opened */
		release_cache_header(c);
		return (1);
	}

	ret = (c->ch = create_cache_file_ch(keylen, algtype, sizespec)) != 0;
	release_cache_header(c);

	return (ret);
}


int
cache_insert(
	keylen_t keylen,
	algtype_t algtype,
	uid_t uid,
	deskeyarray common,
	des_block key,
	keybuf3 *public,
	keybuf3 *secret)
{
	struct cachekey	*c;
	int		ret;

	if ((c = get_cache_header(keylen, algtype)) == 0)
		return (0);

	if (c->ch == 0) {
		release_cache_header(c);
		return (0);
	}

	ret = (c->ch =
		cache_insert_ch(c->ch, uid, common, key, public, secret)) != 0;

	release_cache_header(c);

	return (ret);
}


struct cachekey3_list *
cache_retrieve(
	keylen_t keylen,
	algtype_t algtype,
	uid_t uid,
	keybuf3 *public,
	des_block key)
{
	struct cachekey		*c;
	struct cachekey3_list	*cl;

	if ((c = get_cache_header(keylen, algtype)) == 0)
		return (0);

	if (c->ch == 0) {
		release_cache_header(c);
		return (0);
	}

	cl = cache_retrieve_ch(c->ch, uid, public, key);

	release_cache_header(c);

	return (cl);
}

int
cache_remove(keylen_t keylen, algtype_t algtype, uid_t uid, keybuf3 *public)
{
	struct cachekey	*c;
	int		ret;

	if ((c = get_cache_header(keylen, algtype)) == 0)
		return (0);

	if (c->ch == 0) {
		release_cache_header(c);
		return (0);
	}

	ret = cache_remove_ch(c->ch, uid, public);

	release_cache_header(c);

	return (ret);
}


static struct dhkey *
keybuf3_2_dhkey(keybuf3 *hexkey)
{
	struct dhkey	*binkey;

	/* hexkey->keybuf3_len*4 is the key length in bits */
	if ((binkey = malloc(DHKEYALLOC(hexkey->keybuf3_len*4))) == 0)
		return (0);

	/* Set to zero to keep dbx and Purify access checking happy */
	memset(binkey, 0, DHKEYALLOC(hexkey->keybuf3_len*4));

	binkey->length = hexkey->keybuf3_len/2;
	hex2bin((u_char *)hexkey->keybuf3_val, binkey->key,
		(int)binkey->length);

	return (binkey);
}
