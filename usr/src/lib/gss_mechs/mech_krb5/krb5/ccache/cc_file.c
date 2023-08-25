/*
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * lib/krb5/ccache/cc_file.c
 *
 * Copyright 1990,1991,1992,1993,1994,2000,2004 Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Original stdio support copyright 1995 by Cygnus Support.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 *
 * implementation of file-based credentials cache
 */

/*
If OPENCLOSE is defined, each of the functions opens and closes the
file whenever it needs to access it.  Otherwise, the file is opened
once in initialize and closed once is close.

This library depends on UNIX-like file descriptors, and UNIX-like
behavior from the functions: open, close, read, write, lseek.

The quasi-BNF grammar for a credentials cache:

file ::=
        principal list-of-credentials

credential ::=
	client (principal)
	server (principal)
	keyblock (keyblock)
	times (ticket_times)
	is_skey (boolean)
	ticket_flags (flags)
	ticket (data)
	second_ticket (data)

principal ::=
	number of components (int32)
	component 1 (data)
	component 2 (data)
	...

data ::=
	length (int32)
	string of length bytes

etc.
 */
/* todo:
   Make sure that each time a function returns KRB5_NOMEM, everything
   allocated earlier in the function and stack tree is freed.

   File locking

   Use pread/pwrite if available, so multiple threads can read
   simultaneously.  (That may require reader/writer locks.)

   fcc_nseq.c and fcc_read don't check return values a lot.
 */
#include "k5-int.h"
#include <syslog.h>	/* Solaris Kerberos */
#include <ctype.h>
#include <locale.h>

#include <stdio.h>
#include <errno.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

/* How long to block if flock fails with EAGAIN */
#define	LOCK_RETRIES	100
#define	WAIT_LENGTH	20	/* in milliseconds */

#ifdef HAVE_NETINET_IN_H
#if !defined(_WIN32)
#include <netinet/in.h>
#else
#include "port-sockets.h"
#endif
#else
# error find some way to use net-byte-order file version numbers.
#endif

static krb5_error_code KRB5_CALLCONV krb5_fcc_close
        (krb5_context, krb5_ccache id);

static krb5_error_code KRB5_CALLCONV krb5_fcc_destroy
        (krb5_context, krb5_ccache id);

static krb5_error_code KRB5_CALLCONV krb5_fcc_end_seq_get
        (krb5_context, krb5_ccache id, krb5_cc_cursor *cursor);

static krb5_error_code KRB5_CALLCONV krb5_fcc_generate_new
        (krb5_context, krb5_ccache *id);

static const char * KRB5_CALLCONV krb5_fcc_get_name
        (krb5_context, krb5_ccache id);

static krb5_error_code KRB5_CALLCONV krb5_fcc_get_principal
        (krb5_context, krb5_ccache id, krb5_principal *princ);

static krb5_error_code KRB5_CALLCONV krb5_fcc_initialize
        (krb5_context, krb5_ccache id, krb5_principal princ);

static krb5_error_code KRB5_CALLCONV krb5_fcc_next_cred
        (krb5_context, krb5_ccache id, krb5_cc_cursor *cursor,
	 krb5_creds *creds);

static krb5_error_code krb5_fcc_read
        (krb5_context, krb5_ccache id, krb5_pointer buf, unsigned int len);
static krb5_error_code krb5_fcc_read_principal
        (krb5_context, krb5_ccache id, krb5_principal *princ);
static krb5_error_code krb5_fcc_read_keyblock
        (krb5_context, krb5_ccache id, krb5_keyblock *keyblock);
static krb5_error_code krb5_fcc_read_data
        (krb5_context, krb5_ccache id, krb5_data *data);
static krb5_error_code krb5_fcc_read_int32
        (krb5_context, krb5_ccache id, krb5_int32 *i);
static krb5_error_code krb5_fcc_read_ui_2
        (krb5_context, krb5_ccache id, krb5_ui_2 *i);
static krb5_error_code krb5_fcc_read_octet
        (krb5_context, krb5_ccache id, krb5_octet *i);
static krb5_error_code krb5_fcc_read_times
        (krb5_context, krb5_ccache id, krb5_ticket_times *t);
static krb5_error_code krb5_fcc_read_addrs
        (krb5_context, krb5_ccache, krb5_address ***);
static krb5_error_code krb5_fcc_read_addr
        (krb5_context, krb5_ccache, krb5_address *);
static krb5_error_code krb5_fcc_read_authdata
        (krb5_context, krb5_ccache, krb5_authdata ***);
static krb5_error_code krb5_fcc_read_authdatum
        (krb5_context, krb5_ccache, krb5_authdata *);

static krb5_error_code KRB5_CALLCONV krb5_fcc_resolve
        (krb5_context, krb5_ccache *id, const char *residual);

static krb5_error_code KRB5_CALLCONV krb5_fcc_retrieve
        (krb5_context, krb5_ccache id, krb5_flags whichfields,
	 krb5_creds *mcreds, krb5_creds *creds);

static krb5_error_code KRB5_CALLCONV krb5_fcc_start_seq_get
        (krb5_context, krb5_ccache id, krb5_cc_cursor *cursor);

static krb5_error_code KRB5_CALLCONV krb5_fcc_store
        (krb5_context, krb5_ccache id, krb5_creds *creds);

static krb5_error_code krb5_fcc_skip_header
        (krb5_context, krb5_ccache);
static krb5_error_code krb5_fcc_skip_principal
        (krb5_context, krb5_ccache id);

static krb5_error_code KRB5_CALLCONV krb5_fcc_set_flags
        (krb5_context, krb5_ccache id, krb5_flags flags);

extern const krb5_cc_ops krb5_cc_file_ops;

krb5_error_code krb5_change_cache (void);

static krb5_error_code krb5_fcc_write
        (krb5_context, krb5_ccache id, krb5_pointer buf, unsigned int len);
static krb5_error_code krb5_fcc_store_principal
        (krb5_context, krb5_ccache id, krb5_principal princ);
static krb5_error_code krb5_fcc_store_keyblock
        (krb5_context, krb5_ccache id, krb5_keyblock *keyblock);
static krb5_error_code krb5_fcc_store_data
        (krb5_context, krb5_ccache id, krb5_data *data);
static krb5_error_code krb5_fcc_store_int32
        (krb5_context, krb5_ccache id, krb5_int32 i);
static krb5_error_code krb5_fcc_store_ui_4
        (krb5_context, krb5_ccache id, krb5_ui_4 i);
static krb5_error_code krb5_fcc_store_ui_2
        (krb5_context, krb5_ccache id, krb5_int32 i);
static krb5_error_code krb5_fcc_store_octet
        (krb5_context, krb5_ccache id, krb5_int32 i);
static krb5_error_code krb5_fcc_store_times
        (krb5_context, krb5_ccache id, krb5_ticket_times *t);
static krb5_error_code krb5_fcc_store_addrs
        (krb5_context, krb5_ccache, krb5_address **);
static krb5_error_code krb5_fcc_store_addr
        (krb5_context, krb5_ccache, krb5_address *);
static krb5_error_code krb5_fcc_store_authdata
        (krb5_context, krb5_ccache, krb5_authdata **);
static krb5_error_code krb5_fcc_store_authdatum
        (krb5_context, krb5_ccache, krb5_authdata *);

static krb5_error_code krb5_fcc_interpret
        (krb5_context, int);

struct _krb5_fcc_data;
static krb5_error_code krb5_fcc_close_file
        (krb5_context, struct _krb5_fcc_data *data);
static krb5_error_code krb5_fcc_open_file
        (krb5_context, krb5_ccache, int);


#define KRB5_OK 0

#define KRB5_FCC_MAXLEN 100

/*
 * FCC version 2 contains type information for principals.  FCC
 * version 1 does not.
 *
 * FCC version 3 contains keyblock encryption type information, and is
 * architecture independent.  Previous versions are not.
 *
 * The code will accept version 1, 2, and 3 ccaches, and depending
 * what KRB5_FCC_DEFAULT_FVNO is set to, it will create version 1, 2,
 * or 3 FCC caches.
 *
 * The default credentials cache should be type 3 for now (see
 * init_ctx.c).
 */

#define KRB5_FCC_FVNO_1 0x0501		/* krb v5, fcc v1 */
#define KRB5_FCC_FVNO_2 0x0502		/* krb v5, fcc v2 */
#define KRB5_FCC_FVNO_3 0x0503		/* krb v5, fcc v3 */
#define KRB5_FCC_FVNO_4 0x0504		/* krb v5, fcc v4 */

#define	FCC_OPEN_AND_ERASE	1
#define	FCC_OPEN_RDWR		2
#define	FCC_OPEN_RDONLY		3
#define	FCC_OPEN_AND_ERASE_NOUNLINK	255	/* Solaris Kerberos */

/* Credential file header tags.
 * The header tags are constructed as:
 *	krb5_ui_2	tag
 *	krb5_ui_2	len
 *	krb5_octet	data[len]
 * This format allows for older versions of the fcc processing code to skip
 * past unrecognized tag formats.
 */
#define FCC_TAG_DELTATIME	1

#ifndef TKT_ROOT
#ifdef MSDOS_FILESYSTEM
#define TKT_ROOT "\\tkt"
#else
#define TKT_ROOT "/tmp/tkt"
#endif
#endif

/* macros to make checking flags easier */
#define OPENCLOSE(id) (((krb5_fcc_data *)id->data)->flags & KRB5_TC_OPENCLOSE)

typedef struct _krb5_fcc_data {
    char *filename;
    /* Lock this one before reading or modifying the data stored here
       that can be changed.  (Filename is fixed after
       initialization.)  */
    k5_mutex_t lock;
    int file;
    krb5_flags flags;
    int mode;				/* needed for locking code */
    int version;	      		/* version number of the file */

    /* Buffer data on reading, for performance.
       We used to have a stdio option, but we get more precise control
       by using the POSIX I/O functions.  */
#define FCC_BUFSIZ 1024
    int valid_bytes;
    int cur_offset;
    char buf[FCC_BUFSIZ];
} krb5_fcc_data;

static inline void invalidate_cache(krb5_fcc_data *data)
{
    data->valid_bytes = 0;
}

static off_t fcc_lseek(krb5_fcc_data *data, off_t offset, int whence)
{
    /* If we read some extra data in advance, and then want to know or
       use our "current" position, we need to back up a little.  */
    if (whence == SEEK_CUR && data->valid_bytes) {
	assert(data->valid_bytes > 0);
	assert(data->cur_offset > 0);
	assert(data->cur_offset <= data->valid_bytes);
	offset -= (data->valid_bytes - data->cur_offset);
    }
    invalidate_cache(data);
    return lseek(data->file, offset, whence);
}

struct fcc_set {
    struct fcc_set *next;
    krb5_fcc_data *data;
    unsigned int refcount;
};

k5_mutex_t krb5int_cc_file_mutex = K5_MUTEX_PARTIAL_INITIALIZER;
static struct fcc_set *fccs = NULL;

/* An off_t can be arbitrarily complex */
typedef struct _krb5_fcc_cursor {
    off_t pos;
} krb5_fcc_cursor;

#define MAYBE_OPEN(CONTEXT, ID, MODE)					\
{									\
    k5_assert_locked(&((krb5_fcc_data *)(ID)->data)->lock);		\
    if (OPENCLOSE (ID)) {						\
	krb5_error_code maybe_open_ret;					\
	maybe_open_ret = krb5_fcc_open_file (CONTEXT,ID,MODE);		\
	if (maybe_open_ret) {						\
	    k5_mutex_unlock(&((krb5_fcc_data *)(ID)->data)->lock);	\
	    return maybe_open_ret;					\
	}								\
    }									\
}

#define MAYBE_CLOSE(CONTEXT, ID, RET)					\
{									\
    if (OPENCLOSE (ID)) {						\
	krb5_error_code maybe_close_ret;				\
        maybe_close_ret = krb5_fcc_close_file (CONTEXT,			\
					       (krb5_fcc_data *)(ID)->data); \
	if (!(RET)) RET = maybe_close_ret; } }

#define MAYBE_CLOSE_IGNORE(CONTEXT, ID) \
{                                                                       \
    if (OPENCLOSE (ID)) {                                               \
        (void) krb5_fcc_close_file (CONTEXT,(krb5_fcc_data *)(ID)->data); } }

#define CHECK(ret) if (ret != KRB5_OK) goto errout;

#define NO_FILE -1

/*
 * Effects:
 * Reads len bytes from the cache id, storing them in buf.
 *
 * Requires:
 * Must be called with mutex locked.
 *
 * Errors:
 * KRB5_CC_END - there were not len bytes available
 * system errors (read)
 */
static krb5_error_code
krb5_fcc_read(krb5_context context, krb5_ccache id, krb5_pointer buf, unsigned int len)
{
#if 0
     int ret;

     k5_assert_locked(&((krb5_fcc_data *) id->data)->lock);

     ret = read(((krb5_fcc_data *) id->data)->file, (char *) buf, len);
     if (ret == -1)
	  return krb5_fcc_interpret(context, errno);
     if (ret != len)
	  return KRB5_CC_END;
     else
	  return KRB5_OK;
#else
     krb5_fcc_data *data = (krb5_fcc_data *) id->data;

     k5_assert_locked(&data->lock);

     while (len > 0) {
	 int nread, e;
	 size_t ncopied;

	 assert (data->valid_bytes >= 0);
	 if (data->valid_bytes > 0)
	     assert(data->cur_offset <= data->valid_bytes);
	 if (data->valid_bytes == 0
	     || data->cur_offset == data->valid_bytes) {
	     /* Fill buffer from current file position.  */
	     nread = read(data->file, data->buf, sizeof(data->buf));
	     e = errno;
	     if (nread < 0)
		 return krb5_fcc_interpret(context, e);
	     if (nread == 0)
		 /* EOF */
		 return KRB5_CC_END;
	     data->valid_bytes = nread;
	     data->cur_offset = 0;
	 }
	 assert(data->cur_offset < data->valid_bytes);
	 ncopied = len;
	 assert(ncopied == len);
	 if (data->valid_bytes - data->cur_offset < ncopied)
	     ncopied = data->valid_bytes - data->cur_offset;
	 memcpy(buf, data->buf + data->cur_offset, ncopied);
	 data->cur_offset += ncopied;
	 assert(data->cur_offset > 0);
	 assert(data->cur_offset <= data->valid_bytes);
	 len -= ncopied;
	 assert(len >= 0);
	 /* Don't do arithmetic on void pointers.  */
	 buf = (char*)buf + ncopied;
     }
     return 0;
#endif
}

/*
 * FOR ALL OF THE FOLLOWING FUNCTIONS:
 *
 * Requires:
 * id is open and set to read at the appropriate place in the file
 *
 * mutex is locked
 *
 * Effects:
 * Fills in the second argument with data of the appropriate type from
 * the file.  In some cases, the functions have to allocate space for
 * variable length fields; therefore, krb5_destroy_<type> must be
 * called for each filled in structure.
 *
 * Errors:
 * system errors (read errors)
 * KRB5_CC_NOMEM
 */

#define ALLOC(NUM,TYPE) \
    (((NUM) <= (((size_t)0-1)/ sizeof(TYPE)))		\
     ? (TYPE *) calloc((NUM), sizeof(TYPE))		\
     : (errno = ENOMEM,(TYPE *) 0))

static krb5_error_code
krb5_fcc_read_principal(krb5_context context, krb5_ccache id, krb5_principal *princ)
{
    krb5_fcc_data *data = (krb5_fcc_data *)id->data;
    krb5_error_code kret;
    register krb5_principal tmpprinc;
    krb5_int32 length, type;
    int i;

    k5_assert_locked(&((krb5_fcc_data *) id->data)->lock);

    *princ = NULL;

    if (data->version == KRB5_FCC_FVNO_1) {
	type = KRB5_NT_UNKNOWN;
    } else {
        /* Read principal type */
        kret = krb5_fcc_read_int32(context, id, &type);
        if (kret != KRB5_OK)
	    return kret;
    }

    /* Read the number of components */
    kret = krb5_fcc_read_int32(context, id, &length);
    if (kret != KRB5_OK)
	return kret;

    /*
     * DCE includes the principal's realm in the count; the new format
     * does not.
     */
    if (data->version == KRB5_FCC_FVNO_1)
	length--;
    if (length < 0)
	return KRB5_CC_NOMEM;

    tmpprinc = (krb5_principal) malloc(sizeof(krb5_principal_data));
    if (tmpprinc == NULL)
	return KRB5_CC_NOMEM;
    if (length) {
	size_t msize = length;
	if (msize != length) {
	    free(tmpprinc);
	    return KRB5_CC_NOMEM;
	}
	tmpprinc->data = ALLOC (msize, krb5_data);
	if (tmpprinc->data == 0) {
	    free((char *)tmpprinc);
	    return KRB5_CC_NOMEM;
	}
    } else
	tmpprinc->data = 0;
    tmpprinc->magic = KV5M_PRINCIPAL;
    tmpprinc->length = length;
    tmpprinc->type = type;

    kret = krb5_fcc_read_data(context, id, krb5_princ_realm(context, tmpprinc));

    i = 0;
    CHECK(kret);

    for (i=0; i < length; i++) {
	kret = krb5_fcc_read_data(context, id, krb5_princ_component(context, tmpprinc, i));
	CHECK(kret);
    }
    *princ = tmpprinc;
    return KRB5_OK;

 errout:
    while(--i >= 0)
	free(krb5_princ_component(context, tmpprinc, i)->data);
    free((char *)tmpprinc->data);
    free((char *)tmpprinc);
    return kret;
}

static krb5_error_code
krb5_fcc_read_addrs(krb5_context context, krb5_ccache id, krb5_address ***addrs)
{
     krb5_error_code kret;
     krb5_int32 length;
     size_t msize;
     int i;

     k5_assert_locked(&((krb5_fcc_data *) id->data)->lock);

     *addrs = 0;

     /* Read the number of components */
     kret = krb5_fcc_read_int32(context, id, &length);
     CHECK(kret);

     /* Make *addrs able to hold length pointers to krb5_address structs
      * Add one extra for a null-terminated list
      */
     msize = length;
     msize += 1;
     if (msize == 0 || msize - 1 != length || length < 0)
	 return KRB5_CC_NOMEM;
     *addrs = ALLOC (msize, krb5_address *);
     if (*addrs == NULL)
	  return KRB5_CC_NOMEM;

     for (i=0; i < length; i++) {
	  (*addrs)[i] = (krb5_address *) malloc(sizeof(krb5_address));
	  if ((*addrs)[i] == NULL) {
	      krb5_free_addresses(context, *addrs);
	      /* Solaris Kerberos */
	      *addrs = NULL;
	      return KRB5_CC_NOMEM;
	  }
	  (*addrs)[i]->contents = NULL;
	  kret = krb5_fcc_read_addr(context, id, (*addrs)[i]);
	  CHECK(kret);
     }

     return KRB5_OK;
 errout:
     if (*addrs) {
	 krb5_free_addresses(context, *addrs);
	 *addrs = NULL;
     }
     return kret;
}

static krb5_error_code
krb5_fcc_read_keyblock(krb5_context context, krb5_ccache id, krb5_keyblock *keyblock)
{
     krb5_fcc_data *data = (krb5_fcc_data *)id->data;
     krb5_error_code kret;
     krb5_ui_2 ui2;
     krb5_int32 int32;

     k5_assert_locked(&((krb5_fcc_data *) id->data)->lock);

     keyblock->magic = KV5M_KEYBLOCK;
     keyblock->contents = 0;

     kret = krb5_fcc_read_ui_2(context, id, &ui2);
     keyblock->enctype = ui2;
     CHECK(kret);
     if (data->version == KRB5_FCC_FVNO_3) {
	 /* This works because the old etype is the same as the new enctype. */
	     kret = krb5_fcc_read_ui_2(context, id, &ui2);
	     /* keyblock->enctype = ui2; */
	     CHECK(kret);
     }

     kret = krb5_fcc_read_int32(context, id, &int32);
     CHECK(kret);
     if (int32 < 0)
	  return KRB5_CC_NOMEM;
     keyblock->length = int32;
     /* Overflow check.  */
     if (keyblock->length != int32)
	 return KRB5_CC_NOMEM;
     if ( keyblock->length == 0 )
	 return KRB5_OK;
     /* Solaris Kerberos */
     keyblock->contents = calloc(keyblock->length, sizeof(krb5_octet));
     if (keyblock->contents == NULL)
	 return KRB5_CC_NOMEM;

     kret = krb5_fcc_read(context, id, keyblock->contents, keyblock->length);
     if (kret)
	 goto errout;

     return KRB5_OK;
 errout:
     if (keyblock->contents) {
	 krb5_xfree(keyblock->contents);
	 keyblock->contents = NULL;
     }
     return kret;
}

static krb5_error_code
krb5_fcc_read_data(krb5_context context, krb5_ccache id, krb5_data *data)
{
     krb5_error_code kret;
     krb5_int32 len;

     k5_assert_locked(&((krb5_fcc_data *) id->data)->lock);

     data->magic = KV5M_DATA;
     data->data = 0;

     kret = krb5_fcc_read_int32(context, id, &len);
     CHECK(kret);
     if (len < 0)
        return KRB5_CC_NOMEM;
     data->length = len;
     if (data->length != len || data->length + 1 == 0)
	 return KRB5_CC_NOMEM;

     if (data->length == 0) {
	data->data = 0;
	return KRB5_OK;
     }

     data->data = (char *) malloc(data->length+1);
     if (data->data == NULL)
	  return KRB5_CC_NOMEM;

     kret = krb5_fcc_read(context, id, data->data, (unsigned) data->length);
     CHECK(kret);

     data->data[data->length] = 0; /* Null terminate, just in case.... */
     return KRB5_OK;
 errout:
     if (data->data) {
	 krb5_xfree(data->data);
	 data->data = NULL;
     }
     return kret;
}

static krb5_error_code
krb5_fcc_read_addr(krb5_context context, krb5_ccache id, krb5_address *addr)
{
     krb5_error_code kret;
     krb5_ui_2 ui2;
     krb5_int32 int32;

     k5_assert_locked(&((krb5_fcc_data *) id->data)->lock);

     addr->magic = KV5M_ADDRESS;
     addr->contents = 0;

     kret = krb5_fcc_read_ui_2(context, id, &ui2);
     CHECK(kret);
     addr->addrtype = ui2;

     kret = krb5_fcc_read_int32(context, id, &int32);
     CHECK(kret);
     if ((int32 & VALID_INT_BITS) != int32)     /* Overflow int??? */
	  return KRB5_CC_NOMEM;
     addr->length = int32;
     /* Length field is "unsigned int", which may be smaller than 32
        bits.  */
     if (addr->length != int32)
	 return KRB5_CC_NOMEM;	/* XXX */

     if (addr->length == 0)
	     return KRB5_OK;

     addr->contents = (krb5_octet *) malloc(addr->length);
     if (addr->contents == NULL)
	  return KRB5_CC_NOMEM;

     kret = krb5_fcc_read(context, id, addr->contents, addr->length);
     CHECK(kret);

     return KRB5_OK;
 errout:
     if (addr->contents) {
	 krb5_xfree(addr->contents);
	 addr->contents = NULL;
     }
     return kret;
}

static krb5_error_code
krb5_fcc_read_int32(krb5_context context, krb5_ccache id, krb5_int32 *i)
{
    krb5_fcc_data *data = (krb5_fcc_data *)id->data;
    krb5_error_code retval;
    unsigned char buf[4];
    krb5_int32 val;

    k5_assert_locked(&((krb5_fcc_data *) id->data)->lock);

    if ((data->version == KRB5_FCC_FVNO_1) ||
	(data->version == KRB5_FCC_FVNO_2))
	return krb5_fcc_read(context, id, (krb5_pointer) i, sizeof(krb5_int32));
    else {
	retval = krb5_fcc_read(context, id, buf, 4);
	if (retval)
	    return retval;
        val = buf[0];
        val = (val << 8) | buf[1];
        val = (val << 8) | buf[2];
        val = (val << 8) | buf[3];
        *i = val;
	return 0;
    }
}

static krb5_error_code
krb5_fcc_read_ui_2(krb5_context context, krb5_ccache id, krb5_ui_2 *i)
{
    krb5_fcc_data *data = (krb5_fcc_data *)id->data;
    krb5_error_code retval;
    unsigned char buf[2];

    k5_assert_locked(&((krb5_fcc_data *) id->data)->lock);

    if ((data->version == KRB5_FCC_FVNO_1) ||
	(data->version == KRB5_FCC_FVNO_2))
	return krb5_fcc_read(context, id, (krb5_pointer) i, sizeof(krb5_ui_2));
    else {
	retval = krb5_fcc_read(context, id, buf, 2);
	if (retval)
	    return retval;
	*i = (buf[0] << 8) + buf[1];
	return 0;
    }
}

static krb5_error_code
krb5_fcc_read_octet(krb5_context context, krb5_ccache id, krb5_octet *i)
{
    k5_assert_locked(&((krb5_fcc_data *) id->data)->lock);
    return krb5_fcc_read(context, id, (krb5_pointer) i, 1);
}


static krb5_error_code
krb5_fcc_read_times(krb5_context context, krb5_ccache id, krb5_ticket_times *t)
{
    krb5_fcc_data *data = (krb5_fcc_data *)id->data;
    krb5_error_code retval;
    krb5_int32 i;

    k5_assert_locked(&((krb5_fcc_data *) id->data)->lock);

    if ((data->version == KRB5_FCC_FVNO_1) ||
	(data->version == KRB5_FCC_FVNO_2))
	return krb5_fcc_read(context, id, (krb5_pointer) t, sizeof(krb5_ticket_times));
    else {
	retval = krb5_fcc_read_int32(context, id, &i);
	CHECK(retval);
	t->authtime = i;

	retval = krb5_fcc_read_int32(context, id, &i);
	CHECK(retval);
	t->starttime = i;

	retval = krb5_fcc_read_int32(context, id, &i);
	CHECK(retval);
	t->endtime = i;

	retval = krb5_fcc_read_int32(context, id, &i);
	CHECK(retval);
	t->renew_till = i;
    }
    return 0;
errout:
    return retval;
}

static krb5_error_code
krb5_fcc_read_authdata(krb5_context context, krb5_ccache id, krb5_authdata ***a)
{
     krb5_error_code kret;
     krb5_int32 length;
     size_t msize;
     int i;

     k5_assert_locked(&((krb5_fcc_data *) id->data)->lock);

     *a = 0;

     /* Read the number of components */
     kret = krb5_fcc_read_int32(context, id, &length);
     CHECK(kret);

     if (length == 0)
	 return KRB5_OK;

     /* Make *a able to hold length pointers to krb5_authdata structs
      * Add one extra for a null-terminated list
      */
     msize = length;
     msize += 1;
     if (msize == 0 || msize - 1 != length || length < 0)
	 return KRB5_CC_NOMEM;
     *a = ALLOC (msize, krb5_authdata *);
     if (*a == NULL)
	  return KRB5_CC_NOMEM;

     for (i=0; i < length; i++) {
	  (*a)[i] = (krb5_authdata *) malloc(sizeof(krb5_authdata));
	  if ((*a)[i] == NULL) {
	      krb5_free_authdata(context, *a);
	      return KRB5_CC_NOMEM;
	  }
	  (*a)[i]->contents = NULL;
	  kret = krb5_fcc_read_authdatum(context, id, (*a)[i]);
	  CHECK(kret);
     }

     return KRB5_OK;
 errout:
     if (*a) {
	 krb5_free_authdata(context, *a);
	 *a = NULL;
     }
     return kret;
}

static krb5_error_code
krb5_fcc_read_authdatum(krb5_context context, krb5_ccache id, krb5_authdata *a)
{
    krb5_error_code kret;
    krb5_int32 int32;
    krb5_ui_2 ui2;

    k5_assert_locked(&((krb5_fcc_data *) id->data)->lock);

    a->magic = KV5M_AUTHDATA;
    a->contents = NULL;

    kret = krb5_fcc_read_ui_2(context, id, &ui2);
    CHECK(kret);
    a->ad_type = (krb5_authdatatype)ui2;
    kret = krb5_fcc_read_int32(context, id, &int32);
    CHECK(kret);
    if ((int32 & VALID_INT_BITS) != int32)     /* Overflow int??? */
          return KRB5_CC_NOMEM;
    a->length = int32;
    /* Value could have gotten truncated if int is smaller than 32
       bits.  */
    if (a->length != int32)
	return KRB5_CC_NOMEM;	/* XXX */

    if (a->length == 0 )
	    return KRB5_OK;

    a->contents = (krb5_octet *) malloc(a->length);
    if (a->contents == NULL)
	return KRB5_CC_NOMEM;

    kret = krb5_fcc_read(context, id, a->contents, a->length);
    CHECK(kret);

     return KRB5_OK;
 errout:
     if (a->contents) {
	 krb5_xfree(a->contents);
	 a->contents = NULL;
     }
     return kret;

}
#undef CHECK

#define CHECK(ret) if (ret != KRB5_OK) return ret;

/*
 * Requires:
 * id is open
 *
 * Effects:
 * Writes len bytes from buf into the file cred cache id.
 *
 * Errors:
 * system errors
 */
static krb5_error_code
krb5_fcc_write(krb5_context context, krb5_ccache id, krb5_pointer buf, unsigned int len)
{
     int ret;

     k5_assert_locked(&((krb5_fcc_data *) id->data)->lock);
     invalidate_cache((krb5_fcc_data *) id->data);

     ret = write(((krb5_fcc_data *)id->data)->file, (char *) buf, len);
     if (ret < 0)
	  return krb5_fcc_interpret(context, errno);
     if (ret != len)
         return KRB5_CC_WRITE;
     return KRB5_OK;
}

/*
 * FOR ALL OF THE FOLLOWING FUNCTIONS:
 *
 * Requires:
 * ((krb5_fcc_data *) id->data)->file is open and at the right position.
 *
 * mutex is locked
 *
 * Effects:
 * Stores an encoded version of the second argument in the
 * cache file.
 *
 * Errors:
 * system errors
 */

static krb5_error_code
krb5_fcc_store_principal(krb5_context context, krb5_ccache id, krb5_principal princ)
{
    krb5_fcc_data *data = (krb5_fcc_data *)id->data;
    krb5_error_code ret;
    krb5_int32 i, length, tmp, type;

    k5_assert_locked(&((krb5_fcc_data *) id->data)->lock);

    type = krb5_princ_type(context, princ);
    tmp = length = krb5_princ_size(context, princ);

    if (data->version == KRB5_FCC_FVNO_1) {
	/*
	 * DCE-compatible format means that the length count
	 * includes the realm.  (It also doesn't include the
	 * principal type information.)
	 */
	tmp++;
    } else {
	ret = krb5_fcc_store_int32(context, id, type);
	CHECK(ret);
    }

    ret = krb5_fcc_store_int32(context, id, tmp);
    CHECK(ret);

    ret = krb5_fcc_store_data(context, id, krb5_princ_realm(context, princ));
    CHECK(ret);

    for (i=0; i < length; i++) {
	ret = krb5_fcc_store_data(context, id, krb5_princ_component(context, princ, i));
	CHECK(ret);
    }

    return KRB5_OK;
}

static krb5_error_code
krb5_fcc_store_addrs(krb5_context context, krb5_ccache id, krb5_address **addrs)
{
     krb5_error_code ret;
     krb5_address **temp;
     krb5_int32 i, length = 0;

     k5_assert_locked(&((krb5_fcc_data *) id->data)->lock);

     /* Count the number of components */
     if (addrs) {
	     temp = addrs;
	     while (*temp++)
		     length += 1;
     }

     ret = krb5_fcc_store_int32(context, id, length);
     CHECK(ret);
     for (i=0; i < length; i++) {
	  ret = krb5_fcc_store_addr(context, id, addrs[i]);
	  CHECK(ret);
     }

     return KRB5_OK;
}

static krb5_error_code
krb5_fcc_store_keyblock(krb5_context context, krb5_ccache id, krb5_keyblock *keyblock)
{
     krb5_fcc_data *data = (krb5_fcc_data *)id->data;
     krb5_error_code ret;

     k5_assert_locked(&((krb5_fcc_data *) id->data)->lock);

     ret = krb5_fcc_store_ui_2(context, id, keyblock->enctype);
     CHECK(ret);
     if (data->version == KRB5_FCC_FVNO_3) {
	 ret = krb5_fcc_store_ui_2(context, id, keyblock->enctype);
	 CHECK(ret);
     }
     ret = krb5_fcc_store_ui_4(context, id, keyblock->length);
     CHECK(ret);
     return krb5_fcc_write(context, id, (char *) keyblock->contents, keyblock->length);
}

static krb5_error_code
krb5_fcc_store_addr(krb5_context context, krb5_ccache id, krb5_address *addr)
{
     krb5_error_code ret;

     k5_assert_locked(&((krb5_fcc_data *) id->data)->lock);

     ret = krb5_fcc_store_ui_2(context, id, addr->addrtype);
     CHECK(ret);
     ret = krb5_fcc_store_ui_4(context, id, addr->length);
     CHECK(ret);
     return krb5_fcc_write(context, id, (char *) addr->contents, addr->length);
}


static krb5_error_code
krb5_fcc_store_data(krb5_context context, krb5_ccache id, krb5_data *data)
{
     krb5_error_code ret;

     k5_assert_locked(&((krb5_fcc_data *) id->data)->lock);

     ret = krb5_fcc_store_ui_4(context, id, data->length);
     CHECK(ret);
     return krb5_fcc_write(context, id, data->data, data->length);
}

static krb5_error_code
krb5_fcc_store_int32(krb5_context context, krb5_ccache id, krb5_int32 i)
{
    krb5_fcc_data *data = (krb5_fcc_data *)id->data;
    unsigned char buf[4];

    k5_assert_locked(&((krb5_fcc_data *) id->data)->lock);

    if ((data->version == KRB5_FCC_FVNO_1) ||
	(data->version == KRB5_FCC_FVNO_2))
	return krb5_fcc_write(context, id, (char *) &i, sizeof(krb5_int32));
    else {
        buf[3] = (unsigned char) (i & 0xFF);
	i >>= 8;
        buf[2] = (unsigned char) (i & 0xFF);
	i >>= 8;
        buf[1] = (unsigned char) (i & 0xFF);
	i >>= 8;
        buf[0] = (unsigned char) (i & 0xFF);
	return krb5_fcc_write(context, id, buf, 4);
    }
}

static krb5_error_code
krb5_fcc_store_ui_4(krb5_context context, krb5_ccache id, krb5_ui_4 i)
{
    krb5_fcc_data *data = (krb5_fcc_data *)id->data;
    unsigned char buf[4];

    k5_assert_locked(&((krb5_fcc_data *) id->data)->lock);

    if ((data->version == KRB5_FCC_FVNO_1) ||
	(data->version == KRB5_FCC_FVNO_2))
	return krb5_fcc_write(context, id, (char *) &i, sizeof(krb5_int32));
    else {
        buf[3] = (unsigned char) (i & 0xFF);
	i >>= 8;
        buf[2] = (unsigned char) (i & 0xFF);
	i >>= 8;
        buf[1] = (unsigned char) (i & 0xFF);
	i >>= 8;
        buf[0] = (unsigned char) (i & 0xFF);
	return krb5_fcc_write(context, id, buf, 4);
    }
}

static krb5_error_code
krb5_fcc_store_ui_2(krb5_context context, krb5_ccache id, krb5_int32 i)
{
    krb5_fcc_data *data = (krb5_fcc_data *)id->data;
    krb5_ui_2 ibuf;
    unsigned char buf[2];

    k5_assert_locked(&((krb5_fcc_data *) id->data)->lock);

    if ((data->version == KRB5_FCC_FVNO_1) ||
	(data->version == KRB5_FCC_FVNO_2)) {
        ibuf = (krb5_ui_2) i;
	return krb5_fcc_write(context, id, (char *) &ibuf, sizeof(krb5_ui_2));
    } else {
        buf[1] = (unsigned char) (i & 0xFF);
	i >>= 8;
        buf[0] = (unsigned char) (i & 0xFF);
	return krb5_fcc_write(context, id, buf, 2);
    }
}

static krb5_error_code
krb5_fcc_store_octet(krb5_context context, krb5_ccache id, krb5_int32 i)
{
    krb5_octet ibuf;

    k5_assert_locked(&((krb5_fcc_data *) id->data)->lock);

    ibuf = (krb5_octet) i;
    return krb5_fcc_write(context, id, (char *) &ibuf, 1);
}

static krb5_error_code
krb5_fcc_store_times(krb5_context context, krb5_ccache id, krb5_ticket_times *t)
{
    krb5_fcc_data *data = (krb5_fcc_data *)id->data;
    krb5_error_code retval;

    k5_assert_locked(&((krb5_fcc_data *) id->data)->lock);

    if ((data->version == KRB5_FCC_FVNO_1) ||
	(data->version == KRB5_FCC_FVNO_2))
	return krb5_fcc_write(context, id, (char *) t, sizeof(krb5_ticket_times));
    else {
	retval = krb5_fcc_store_int32(context, id, t->authtime);
	CHECK(retval);
	retval = krb5_fcc_store_int32(context, id, t->starttime);
	CHECK(retval);
	retval = krb5_fcc_store_int32(context, id, t->endtime);
	CHECK(retval);
	retval = krb5_fcc_store_int32(context, id, t->renew_till);
	CHECK(retval);
	return 0;
    }
}

static krb5_error_code
krb5_fcc_store_authdata(krb5_context context, krb5_ccache id, krb5_authdata **a)
{
    krb5_error_code ret;
    krb5_authdata **temp;
    krb5_int32 i, length=0;

    k5_assert_locked(&((krb5_fcc_data *) id->data)->lock);

    if (a != NULL) {
	for (temp=a; *temp; temp++)
	    length++;
    }

    ret = krb5_fcc_store_int32(context, id, length);
    CHECK(ret);
    for (i=0; i<length; i++) {
	ret = krb5_fcc_store_authdatum (context, id, a[i]);
	CHECK(ret);
    }
    return KRB5_OK;
}

static krb5_error_code
krb5_fcc_store_authdatum (krb5_context context, krb5_ccache id, krb5_authdata *a)
{
    krb5_error_code ret;

    k5_assert_locked(&((krb5_fcc_data *) id->data)->lock);

    ret = krb5_fcc_store_ui_2(context, id, a->ad_type);
    CHECK(ret);
    ret = krb5_fcc_store_ui_4(context, id, a->length);
    CHECK(ret);
    return krb5_fcc_write(context, id, (krb5_pointer) a->contents, a->length);
}
#undef CHECK

static krb5_error_code
krb5_fcc_close_file (krb5_context context, krb5_fcc_data *data)
{
     int ret;
     krb5_error_code retval;

     k5_assert_locked(&data->lock);

     if (data->file == NO_FILE)
	 return KRB5_FCC_INTERNAL;

     retval = krb5_unlock_file(context, data->file);
     ret = close (data->file);
     data->file = NO_FILE;
     if (retval)
	 return retval;

     return ret ? krb5_fcc_interpret (context, errno) : 0;
}

#if defined(ANSI_STDIO) || defined(_WIN32)
#define BINARY_MODE "b"
#else
#define BINARY_MODE ""
#endif

#ifndef HAVE_SETVBUF
#undef setvbuf
#define setvbuf(FILE,BUF,MODE,SIZE) \
  ((SIZE) < BUFSIZE ? (abort(),0) : setbuf(FILE, BUF))
#endif

/* Solaris Kerberos */
static krb5_error_code
krb5_fcc_open_nounlink(char *filename, int open_flag, int *ret_fd, int *new)
{
     struct stat lres;
     struct stat fres;
     int error;
     uid_t uid, euid;
     int fd;
     int newfile = 0;

     *ret_fd = -1;
     /*
      * Solaris Kerberos
      * If we are opening in NOUNLINK mode, we have to check that the
      * existing file, if any, is not a symlink. If it is, we try to
      * delete and re-create it.
      */
     error = lstat(filename, &lres);
     if (error == -1 && errno != ENOENT) {
	  syslog(LOG_ERR, "lstat failed for %s [%m]", filename);
	  return (-1);
     }

     if (error == 0 && !S_ISREG(lres.st_mode)) {
	  syslog(LOG_WARNING, "%s is not a plain file!", filename);
	  syslog(LOG_WARNING, "trying to unlink %s", filename);
	  if (unlink(filename) != 0) {
	       syslog(LOG_ERR, "could not unlink %s [%m]", filename);
	       return (-1);
	  }
     }

     fd = THREEPARAMOPEN(filename, open_flag | O_NONBLOCK | O_NOFOLLOW, 0600);
     if (fd == -1) {
	  if (errno == ENOENT) {
	       fd = THREEPARAMOPEN(filename,
				   open_flag | O_EXCL | O_CREAT, 0600);
	       if (fd != -1) {
		    newfile = 1;
	       } else {
		    /* If the file got created after the open we must retry */
		    if (errno == EEXIST)
			 return (0);
	       }
	  } else if (errno == EACCES) {
		    /*
		     * We failed since the file existed with wrong permissions.
		     * Let's try to unlink it and if that succeeds retry.
		     */
		    syslog(LOG_WARNING, "Insufficient permissions on %s",
			   filename);
		    syslog(LOG_WARNING, "trying to unlink %s", filename);
		    if (unlink(filename) != 0) {
			 syslog(LOG_ERR, "could not unlink %s [%m]", filename);
			 return (-1);
		    }
		    return (0);
	  }
     }
     /* If we still don't have a valid fd, we stop trying */
     if (fd == -1)
	  return (-1);

     /*
      * Solaris Kerberos
      * If the file was not created now with a O_CREAT | O_EXCL open,
      * we have opened an existing file. We should check if the file
      * owner is us, if not, unlink and retry. If unlink fails we log
      * the error and return.
      */
     if (!newfile) {
	    if (fstat(fd, &fres) == -1) {
	       syslog(LOG_ERR, "lstat failed for %s [%m]", filename);
	       close(fd);
	       return (-1);
	  }
	  /* Check if this is the same file we lstat'd earlier */
	  if (lres.st_dev != fres.st_dev || lres.st_ino != fres.st_ino) {
	       syslog(LOG_ERR, "%s changed between stat and open!", filename);
	       close(fd);
	       return (-1);
	  }

	  /*
	   * Solaris Kerberos
	   * Check if the cc filename uid matches owner of file.
	   * Expects cc file to be in the form of /tmp/krb5cc_<uid>,
	   * else skip this check.
	   */
	  if (strncmp(filename, "/tmp/krb5cc_", strlen("/tmp/krb5cc_")) == 0) {
		uid_t fname_uid;
		char *uidstr = strchr(filename, '_');
		char *s = NULL;

		/* make sure we have some non-null char after '_' */
		if (!*++uidstr)
			goto out;

		/* make sure the uid part is all digits */
		for (s = uidstr; *s; s++)
			if (!isdigit(*s))
				goto out;

		fname_uid = (uid_t) atoi(uidstr);
		if (fname_uid != fres.st_uid) {
			close(fd);
			syslog(LOG_WARNING,
			    "%s owned by %d instead of %d",
			    filename, fres.st_uid, fname_uid);
			syslog(LOG_WARNING, "trying to unlink %s", filename);
			if (unlink(filename) != 0) {
				syslog(LOG_ERR,
				    "could not unlink %s [%m]", filename);
				return (-1);
			}
			return (0);
		}
	  }
     }

out:
     *new = newfile;
     *ret_fd = fd;
     return (0);
}


static krb5_error_code
krb5_fcc_open_file (krb5_context context, krb5_ccache id, int mode)
{
    krb5_os_context os_ctx = (krb5_os_context)context->os_context;
    krb5_fcc_data *data = (krb5_fcc_data *)id->data;
    krb5_ui_2 fcc_fvno;
    krb5_ui_2 fcc_flen;
    krb5_ui_2 fcc_tag;
    krb5_ui_2 fcc_taglen;
    int f, open_flag;
    int lock_flag;
    krb5_error_code retval = 0;
    int retries;
    int newfile = 0;

    k5_assert_locked(&data->lock);
    invalidate_cache(data);

    if (data->file != NO_FILE) {
	/* Don't know what state it's in; shut down and start anew.  */
	(void) krb5_unlock_file(context, data->file);
	(void) close (data->file);
	data->file = NO_FILE;
    }

    switch(mode) {
    /* Solaris Kerberos */
    case FCC_OPEN_AND_ERASE_NOUNLINK:
        open_flag = O_RDWR;
        break;
    case FCC_OPEN_AND_ERASE:
	unlink(data->filename);
	open_flag = O_CREAT|O_EXCL|O_TRUNC|O_RDWR;
	break;
    case FCC_OPEN_RDWR:
	open_flag = O_RDWR;
	break;
    case FCC_OPEN_RDONLY:
    default:
	open_flag = O_RDONLY;
	break;
    }

fcc_retry:
    /*
     * Solaris Kerberos
     * If we are opening in NOUNLINK mode, check whether we are opening a
     * symlink or a file owned by some other user and take preventive action.
     */
     newfile = 0;
     if (mode == FCC_OPEN_AND_ERASE_NOUNLINK) {
	  retval = krb5_fcc_open_nounlink(data->filename, open_flag,
					  &f, &newfile);
	  if (retval == 0 && f == -1)
	       goto fcc_retry;
     } else {
	  f = THREEPARAMOPEN (data->filename, open_flag | O_BINARY | O_NOFOLLOW,
	      0600);
     }
    if (f == NO_FILE)
	return krb5_fcc_interpret (context, errno);

    data->mode = mode;

    if (data->mode == FCC_OPEN_RDONLY)
	lock_flag = KRB5_LOCKMODE_SHARED;
    else
	lock_flag = KRB5_LOCKMODE_EXCLUSIVE;
    if ((retval = krb5_lock_file(context, f, lock_flag))) {
	(void) close(f);
        if (retval == EAGAIN && retries++ < LOCK_RETRIES) {
	    /* Solaris Kerberos wait some time before retrying */
	    if (poll(NULL, 0, WAIT_LENGTH) == 0)
	        goto fcc_retry;
	}
	syslog(LOG_ERR, "Failed to lock %s [%m]", data->filename);
	return retval;
    }

    if (mode == FCC_OPEN_AND_ERASE || mode == FCC_OPEN_AND_ERASE_NOUNLINK) {
        int cnt;

	/*
	 * Solaris Kerberos
	 * If this file was not created, we have to flush existing data.
	 * This will happen only if we are doing an ERASE_NOUNLINK open.
	 */
	if (newfile == 0 && (ftruncate(f, 0) == -1)) {
	    syslog(LOG_ERR, "ftruncate failed for %s [%m]", data->filename);
	    close(f);
	    return (krb5_fcc_interpret(context, errno));
	}

	/* write the version number */
	fcc_fvno = htons(context->fcc_default_format);
	data->version = context->fcc_default_format;
	if ((cnt = write(f, (char *)&fcc_fvno, sizeof(fcc_fvno))) !=
	    sizeof(fcc_fvno)) {
	    retval = ((cnt == -1) ? krb5_fcc_interpret(context, errno) :
		    KRB5_CC_IO);
             goto done;
         }
         data->file = f;

	 if (data->version == KRB5_FCC_FVNO_4) {
             /* V4 of the credentials cache format allows for header tags */
	     fcc_flen = 0;

	     if (os_ctx->os_flags & KRB5_OS_TOFFSET_VALID)
		 fcc_flen += (2*sizeof(krb5_ui_2) + 2*sizeof(krb5_int32));

	     /* Write header length */
	     retval = krb5_fcc_store_ui_2(context, id, (krb5_int32)fcc_flen);
	     if (retval) goto done;

	     if (os_ctx->os_flags & KRB5_OS_TOFFSET_VALID) {
		 /* Write time offset tag */
		 fcc_tag = FCC_TAG_DELTATIME;
		 fcc_taglen = 2*sizeof(krb5_int32);

		 retval = krb5_fcc_store_ui_2(context,id,(krb5_int32)fcc_tag);
		 if (retval) goto done;
		 retval = krb5_fcc_store_ui_2(context,id,(krb5_int32)fcc_taglen);
		 if (retval) goto done;
		 retval = krb5_fcc_store_int32(context,id,os_ctx->time_offset);
		 if (retval) goto done;
		 retval = krb5_fcc_store_int32(context,id,os_ctx->usec_offset);
		 if (retval) goto done;
	     }
	 }
	 invalidate_cache(data);
	 goto done;
     }

     /* verify a valid version number is there */
    invalidate_cache(data);
     if (read(f, (char *)&fcc_fvno, sizeof(fcc_fvno)) != sizeof(fcc_fvno)) {
	 retval = KRB5_CC_FORMAT;
	 goto done;
     }
     data->version = ntohs(fcc_fvno);
    if ((data->version != KRB5_FCC_FVNO_4) &&
	(data->version != KRB5_FCC_FVNO_3) &&
	(data->version != KRB5_FCC_FVNO_2) &&
	(data->version != KRB5_FCC_FVNO_1)) {
	retval = KRB5_CCACHE_BADVNO;
	goto done;
    }

    data->file = f;

     if (data->version == KRB5_FCC_FVNO_4) {
	 char buf[1024];

	 if (krb5_fcc_read_ui_2(context, id, &fcc_flen) ||
	     (fcc_flen > sizeof(buf)))
	 {
	     retval = KRB5_CC_FORMAT;
	     goto done;
	 }

	 while (fcc_flen) {
	     if ((fcc_flen < (2 * sizeof(krb5_ui_2))) ||
		 krb5_fcc_read_ui_2(context, id, &fcc_tag) ||
		 krb5_fcc_read_ui_2(context, id, &fcc_taglen) ||
		 (fcc_taglen > (fcc_flen - 2*sizeof(krb5_ui_2))))
	     {
		 retval = KRB5_CC_FORMAT;
		 goto done;
	     }

	     switch (fcc_tag) {
	     case FCC_TAG_DELTATIME:
		 if (fcc_taglen != 2*sizeof(krb5_int32)) {
		     retval = KRB5_CC_FORMAT;
		     goto done;
		 }
		 if (!(context->library_options & KRB5_LIBOPT_SYNC_KDCTIME) ||
		     (os_ctx->os_flags & KRB5_OS_TOFFSET_VALID))
		 {
		     if (krb5_fcc_read(context, id, buf, fcc_taglen)) {
			 retval = KRB5_CC_FORMAT;
			 goto done;
		     }
		     break;
		 }
		 if (krb5_fcc_read_int32(context, id, &os_ctx->time_offset) ||
		     krb5_fcc_read_int32(context, id, &os_ctx->usec_offset))
		 {
		     retval = KRB5_CC_FORMAT;
		     goto done;
		 }
		 os_ctx->os_flags =
		     ((os_ctx->os_flags & ~KRB5_OS_TOFFSET_TIME) |
		      KRB5_OS_TOFFSET_VALID);
		 break;
	     default:
		 if (fcc_taglen && krb5_fcc_read(context,id,buf,fcc_taglen)) {
		     retval = KRB5_CC_FORMAT;
		     goto done;
		 }
		 break;
	     }
	     fcc_flen -= (2*sizeof(krb5_ui_2) + fcc_taglen);
	 }
     }

done:
     if (retval) {
         data->file = -1;
         (void) krb5_unlock_file(context, f);
         (void) close(f);
     }
     return retval;
}

static krb5_error_code
krb5_fcc_skip_header(krb5_context context, krb5_ccache id)
{
     krb5_fcc_data *data = (krb5_fcc_data *)id->data;
     krb5_error_code kret;
     krb5_ui_2 fcc_flen;

     k5_assert_locked(&((krb5_fcc_data *) id->data)->lock);

     fcc_lseek(data, (off_t) sizeof(krb5_ui_2), SEEK_SET);
     if (data->version == KRB5_FCC_FVNO_4) {
	 kret = krb5_fcc_read_ui_2(context, id, &fcc_flen);
	 if (kret) return kret;
         if(fcc_lseek(data, (off_t) fcc_flen, SEEK_CUR) < 0)
		return errno;
     }
     return KRB5_OK;
}

static krb5_error_code
krb5_fcc_skip_principal(krb5_context context, krb5_ccache id)
{
     krb5_error_code kret;
     krb5_principal princ;

     k5_assert_locked(&((krb5_fcc_data *) id->data)->lock);

     kret = krb5_fcc_read_principal(context, id, &princ);
     if (kret != KRB5_OK)
	  return kret;

     krb5_free_principal(context, princ);
     return KRB5_OK;
}


/*
 * Modifies:
 * id
 *
 * Effects:
 * Creates/refreshes the file cred cache id.  If the cache exists, its
 * contents are destroyed.
 *
 * Errors:
 * system errors
 * permission errors
 */
static krb5_error_code KRB5_CALLCONV
krb5_fcc_initialize(krb5_context context, krb5_ccache id, krb5_principal princ)
{
     krb5_error_code kret = 0;
     int reti = 0;

     kret = k5_mutex_lock(&((krb5_fcc_data *) id->data)->lock);
     if (kret)
	 return kret;

     MAYBE_OPEN(context, id, FCC_OPEN_AND_ERASE_NOUNLINK); /* Solaris Kerberos */

     /*
      * SUN14resync
      * This is not needed and can cause problems with ktkt_warnd(8)
      * because it does tricks with getuid and if we enable this fchmod
      * we get EPERM [file_owner] failures on fchmod.
      */
#if 0
#if defined(HAVE_FCHMOD) || defined(HAVE_CHMOD)
     {
#ifdef HAVE_FCHMOD
         reti = fchmod(((krb5_fcc_data *) id->data)->file, S_IREAD | S_IWRITE);
#else
         reti = chmod(((krb5_fcc_data *) id->data)->filename, S_IREAD | S_IWRITE);
#endif
#endif
         if (reti == -1) {
             kret = krb5_fcc_interpret(context, errno);
             MAYBE_CLOSE(context, id, kret);
	     k5_mutex_unlock(&((krb5_fcc_data *) id->data)->lock);
             return kret;
         }
     }
#endif
     kret = krb5_fcc_store_principal(context, id, princ);

     MAYBE_CLOSE(context, id, kret);
     k5_mutex_unlock(&((krb5_fcc_data *) id->data)->lock);
     krb5_change_cache ();
     return kret;
}

/*
 * Drop the ref count; if it hits zero, remove the entry from the
 * fcc_set list and free it.
 */
static krb5_error_code dereference(krb5_context context, krb5_fcc_data *data)
{
    krb5_error_code kerr;
    struct fcc_set **fccsp;

    kerr = k5_mutex_lock(&krb5int_cc_file_mutex);
    if (kerr)
	return kerr;
    for (fccsp = &fccs; *fccsp != NULL; fccsp = &(*fccsp)->next)
	if ((*fccsp)->data == data)
	    break;
    assert(*fccsp != NULL);
    assert((*fccsp)->data == data);
    (*fccsp)->refcount--;
    if ((*fccsp)->refcount == 0) {
        struct fcc_set *temp;
	data = (*fccsp)->data;
	temp = *fccsp;
	*fccsp = (*fccsp)->next;
	free(temp);
	k5_mutex_unlock(&krb5int_cc_file_mutex);
	k5_mutex_assert_unlocked(&data->lock);
	free(data->filename);
	zap(data->buf, sizeof(data->buf));
	if (data->file >= 0) {
	    k5_mutex_lock(&data->lock);
	    krb5_fcc_close_file(context, data);
	    k5_mutex_unlock(&data->lock);
	}
	k5_mutex_destroy(&data->lock);
	free(data);
    } else
	k5_mutex_unlock(&krb5int_cc_file_mutex);
    return 0;
}

/*
 * Modifies:
 * id
 *
 * Effects:
 * Closes the file cache, invalidates the id, and frees any resources
 * associated with the cache.
 */
static krb5_error_code KRB5_CALLCONV
krb5_fcc_close(krb5_context context, krb5_ccache id)
{
     dereference(context, (krb5_fcc_data *) id->data);
     krb5_xfree(id);
     return KRB5_OK;
}

/*
 * Effects:
 * Destroys the contents of id.
 *
 * Errors:
 * system errors
 */
static krb5_error_code KRB5_CALLCONV
krb5_fcc_destroy(krb5_context context, krb5_ccache id)
{
     krb5_error_code kret = 0;
     krb5_fcc_data *data = (krb5_fcc_data *) id->data;
     register int ret;

     struct stat buf;
     unsigned long i, size;
     unsigned int wlen;
     char zeros[BUFSIZ];

     kret = k5_mutex_lock(&data->lock);
     if (kret)
	 return kret;

     if (OPENCLOSE(id)) {
	 invalidate_cache(data);
	  ret = THREEPARAMOPEN(data->filename,
			       O_RDWR | O_BINARY, 0);
	  if (ret < 0) {
	      kret = krb5_fcc_interpret(context, errno);
	      goto cleanup;
	  }
	  data->file = ret;
     }
     else
	  fcc_lseek(data, (off_t) 0, SEEK_SET);

#ifdef MSDOS_FILESYSTEM
/* "disgusting bit of UNIX trivia" - that's how the writers of NFS describe
** the ability of UNIX to still write to a file which has been unlinked.
** Naturally, the PC can't do this. As a result, we have to delete the file
** after we wipe it clean but that throws off all the error handling code.
** So we have do the work ourselves.
*/
    ret = fstat(data->file, &buf);
    if (ret == -1) {
        kret = krb5_fcc_interpret(context, errno);
        size = 0;                               /* Nothing to wipe clean */
    } else
        size = (unsigned long) buf.st_size;

    memset(zeros, 0, BUFSIZ);
    while (size > 0) {
        wlen = (int) ((size > BUFSIZ) ? BUFSIZ : size); /* How much to write */
        i = write(data->file, zeros, wlen);
        if (i < 0) {
            kret = krb5_fcc_interpret(context, errno);
            /* Don't jump to cleanup--we still want to delete the file. */
            break;
        }
        size -= i;                              /* We've read this much */
    }

    if (OPENCLOSE(id)) {
        (void) close(((krb5_fcc_data *)id->data)->file);
        data->file = -1;
    }

    ret = unlink(data->filename);
    if (ret < 0) {
        kret = krb5_fcc_interpret(context, errno);
        goto cleanup;
    }

#else /* MSDOS_FILESYSTEM */

     ret = unlink(data->filename);
     if (ret < 0) {
	 kret = krb5_fcc_interpret(context, errno);
	 if (OPENCLOSE(id)) {
	     (void) close(((krb5_fcc_data *)id->data)->file);
	     data->file = -1;
             kret = ret;
	 }
	 goto cleanup;
     }

     ret = fstat(data->file, &buf);
     if (ret < 0) {
	 kret = krb5_fcc_interpret(context, errno);
	 if (OPENCLOSE(id)) {
	     (void) close(((krb5_fcc_data *)id->data)->file);
	     data->file = -1;
	 }
	 goto cleanup;
     }

     /* XXX This may not be legal XXX */
     size = (unsigned long) buf.st_size;
     memset(zeros, 0, BUFSIZ);
     for (i=0; i < size / BUFSIZ; i++)
	  if (write(data->file, zeros, BUFSIZ) < 0) {
	      kret = krb5_fcc_interpret(context, errno);
	      if (OPENCLOSE(id)) {
		  (void) close(((krb5_fcc_data *)id->data)->file);
		  data->file = -1;
	      }
	      goto cleanup;
	  }

     wlen = (unsigned int) (size % BUFSIZ);
     if (write(data->file, zeros, wlen) < 0) {
	 kret = krb5_fcc_interpret(context, errno);
	 if (OPENCLOSE(id)) {
	     (void) close(((krb5_fcc_data *)id->data)->file);
	     data->file = -1;
	 }
	 goto cleanup;
     }

     ret = close(data->file);
     data->file = -1;

     if (ret)
	 kret = krb5_fcc_interpret(context, errno);

#endif /* MSDOS_FILESYSTEM */

  cleanup:
     k5_mutex_unlock(&data->lock);
     dereference(context, data);
     krb5_xfree(id);

     krb5_change_cache ();
     return kret;
}

extern const krb5_cc_ops krb5_fcc_ops;

/*
 * Requires:
 * residual is a legal path name, and a null-terminated string
 *
 * Modifies:
 * id
 *
 * Effects:
 * creates a file-based cred cache that will reside in the file
 * residual.  The cache is not opened, but the filename is reserved.
 *
 * Returns:
 * A filled in krb5_ccache structure "id".
 *
 * Errors:
 * KRB5_CC_NOMEM - there was insufficient memory to allocate the
 * 		krb5_ccache.  id is undefined.
 * permission errors
 */
static krb5_error_code KRB5_CALLCONV
krb5_fcc_resolve (krb5_context context, krb5_ccache *id, const char *residual)
{
     krb5_ccache lid;
     krb5_error_code kret;
     krb5_fcc_data *data;
     struct fcc_set *setptr;

     kret = k5_mutex_lock(&krb5int_cc_file_mutex);
     if (kret)
	 return kret;
     for (setptr = fccs; setptr; setptr = setptr->next) {
	 if (!strcmp(setptr->data->filename, residual))
	     break;
     }
     if (setptr) {
	 data = setptr->data;
	 assert(setptr->refcount != 0);
	 setptr->refcount++;
	 assert(setptr->refcount != 0);
	 kret = k5_mutex_lock(&data->lock);
	 if (kret) {
	     k5_mutex_unlock(&krb5int_cc_file_mutex);
	     return kret;
	 }
	 k5_mutex_unlock(&krb5int_cc_file_mutex);
     } else {
	 data = malloc(sizeof(krb5_fcc_data));
	 if (data == NULL) {
	     k5_mutex_unlock(&krb5int_cc_file_mutex);
	     return KRB5_CC_NOMEM;
	 }
	 data->filename = strdup(residual);
	 if (data->filename == NULL) {
	     k5_mutex_unlock(&krb5int_cc_file_mutex);
	     free(data);
	     return KRB5_CC_NOMEM;
	 }
	 kret = k5_mutex_init(&data->lock);
	 if (kret) {
	     k5_mutex_unlock(&krb5int_cc_file_mutex);
	     free(data->filename);
	     free(data);
	     return kret;
	 }
	 kret = k5_mutex_lock(&data->lock);
	 if (kret) {
	     k5_mutex_unlock(&krb5int_cc_file_mutex);
	     k5_mutex_destroy(&data->lock);
	     free(data->filename);
	     free(data);
	     return kret;
	 }
	 /* data->version,mode filled in for real later */
	 data->version = data->mode = 0;
	 data->flags = KRB5_TC_OPENCLOSE;
	 data->file = -1;
	 data->valid_bytes = 0;
	 setptr = malloc(sizeof(struct fcc_set));
	 if (setptr == NULL) {
	     k5_mutex_unlock(&krb5int_cc_file_mutex);
	     k5_mutex_destroy(&data->lock);
	     free(data->filename);
	     free(data);
	     return KRB5_CC_NOMEM;
	 }
	 setptr->refcount = 1;
	 setptr->data = data;
	 setptr->next = fccs;
	 fccs = setptr;
	 k5_mutex_unlock(&krb5int_cc_file_mutex);
     }

     k5_mutex_assert_locked(&data->lock);
     k5_mutex_unlock(&data->lock);
     lid = (krb5_ccache) malloc(sizeof(struct _krb5_ccache));
     if (lid == NULL) {
	 dereference(context, data);
	 return KRB5_CC_NOMEM;
     }

     lid->ops = &krb5_fcc_ops;
     lid->data = data;
     lid->magic = KV5M_CCACHE;

     /* other routines will get errors on open, and callers must expect them,
	if cache is non-existent/unusable */
     *id = lid;
     return KRB5_OK;
}

/*
 * Effects:
 * Prepares for a sequential search of the credentials cache.
 * Returns and krb5_cc_cursor to be used with krb5_fcc_next_cred and
 * krb5_fcc_end_seq_get.
 *
 * If the cache is modified between the time of this call and the time
 * of the final krb5_fcc_end_seq_get, the results are undefined.
 *
 * Errors:
 * KRB5_CC_NOMEM
 * system errors
 */
static krb5_error_code KRB5_CALLCONV
krb5_fcc_start_seq_get(krb5_context context, krb5_ccache id,
		       krb5_cc_cursor *cursor)
{
     krb5_fcc_cursor *fcursor;
     krb5_error_code kret = KRB5_OK;
     krb5_fcc_data *data = (krb5_fcc_data *)id->data;

     kret = k5_mutex_lock(&data->lock);
     if (kret)
	 return kret;

     fcursor = (krb5_fcc_cursor *) malloc(sizeof(krb5_fcc_cursor));
     if (fcursor == NULL) {
	 k5_mutex_unlock(&data->lock);
	 return KRB5_CC_NOMEM;
     }
     if (OPENCLOSE(id)) {
          kret = krb5_fcc_open_file(context, id, FCC_OPEN_RDONLY);
          if (kret) {
              krb5_xfree(fcursor);
	      k5_mutex_unlock(&data->lock);
              return kret;
          }
     }

     /* Make sure we start reading right after the primary principal */
     kret = krb5_fcc_skip_header(context, id);
     if (kret) {
	    /* Solaris Kerberos - fix mem leak */
	    krb5_xfree(fcursor);
	    goto done;
     }
     kret = krb5_fcc_skip_principal(context, id);
     if (kret) {
	    /* Solaris Kerberos - fix mem leak */
	    krb5_xfree(fcursor);
	    goto done;
     }

     fcursor->pos = fcc_lseek(data, (off_t) 0, SEEK_CUR);
     *cursor = (krb5_cc_cursor) fcursor;

done:
     MAYBE_CLOSE(context, id, kret);
     k5_mutex_unlock(&data->lock);
     return kret;
}


/*
 * Requires:
 * cursor is a krb5_cc_cursor originally obtained from
 * krb5_fcc_start_seq_get.
 *
 * Modifes:
 * cursor, creds
 *
 * Effects:
 * Fills in creds with the "next" credentals structure from the cache
 * id.  The actual order the creds are returned in is arbitrary.
 * Space is allocated for the variable length fields in the
 * credentials structure, so the object returned must be passed to
 * krb5_destroy_credential.
 *
 * The cursor is updated for the next call to krb5_fcc_next_cred.
 *
 * Errors:
 * system errors
 */
static krb5_error_code KRB5_CALLCONV
krb5_fcc_next_cred(krb5_context context, krb5_ccache id, krb5_cc_cursor *cursor,
		   krb5_creds *creds)
{
#define TCHECK(ret) if (ret != KRB5_OK) goto lose;
     krb5_error_code kret;
     krb5_fcc_cursor *fcursor;
     krb5_int32 int32;
     krb5_octet octet;
     krb5_fcc_data *d = (krb5_fcc_data *) id->data;

     kret = k5_mutex_lock(&d->lock);
     if (kret)
	 return kret;

     memset((char *)creds, 0, sizeof(*creds));
     MAYBE_OPEN(context, id, FCC_OPEN_RDONLY);
     fcursor = (krb5_fcc_cursor *) *cursor;

     kret = (fcc_lseek(d, fcursor->pos, SEEK_SET) == (off_t) -1);
     if (kret) {
	 kret = krb5_fcc_interpret(context, errno);
	 MAYBE_CLOSE(context, id, kret);
	 k5_mutex_unlock(&d->lock);
	 return kret;
     }

     kret = krb5_fcc_read_principal(context, id, &creds->client);
     TCHECK(kret);
     kret = krb5_fcc_read_principal(context, id, &creds->server);
     TCHECK(kret);
     kret = krb5_fcc_read_keyblock(context, id, &creds->keyblock);
     TCHECK(kret);
     kret = krb5_fcc_read_times(context, id, &creds->times);
     TCHECK(kret);
     kret = krb5_fcc_read_octet(context, id, &octet);
     TCHECK(kret);
     creds->is_skey = octet;
     kret = krb5_fcc_read_int32(context, id, &int32);
     TCHECK(kret);
     creds->ticket_flags = int32;
     kret = krb5_fcc_read_addrs(context, id, &creds->addresses);
     TCHECK(kret);
     kret = krb5_fcc_read_authdata(context, id, &creds->authdata);
     TCHECK(kret);
     kret = krb5_fcc_read_data(context, id, &creds->ticket);
     TCHECK(kret);
     kret = krb5_fcc_read_data(context, id, &creds->second_ticket);
     TCHECK(kret);

     fcursor->pos = fcc_lseek(d, (off_t) 0, SEEK_CUR);
     cursor = (krb5_cc_cursor *) fcursor;

lose:
     MAYBE_CLOSE (context, id, kret);
     k5_mutex_unlock(&d->lock);
     if (kret != KRB5_OK)
	 krb5_free_cred_contents(context, creds);
     return kret;
}

/*
 * Requires:
 * cursor is a krb5_cc_cursor originally obtained from
 * krb5_fcc_start_seq_get.
 *
 * Modifies:
 * id, cursor
 *
 * Effects:
 * Finishes sequential processing of the file credentials ccache id,
 * and invalidates the cursor (it must never be used after this call).
 */
/* ARGSUSED */
static krb5_error_code KRB5_CALLCONV
krb5_fcc_end_seq_get(krb5_context context, krb5_ccache id, krb5_cc_cursor *cursor)
{
     /* We don't do anything with the file cache itself, so
	no need to lock anything.  */

     /* don't close; it may be left open by the caller,
        and if not, fcc_start_seq_get and/or fcc_next_cred will do the
        MAYBE_CLOSE.
     MAYBE_CLOSE(context, id, kret); */
     krb5_xfree((krb5_fcc_cursor *) *cursor);
     return 0;
}


/*
 * Effects:
 * Creates a new file cred cache whose name is guaranteed to be
 * unique.  The name begins with the string TKT_ROOT (from fcc.h).
 * The cache is not opened, but the new filename is reserved.
 *
 * Returns:
 * The filled in krb5_ccache id.
 *
 * Errors:
 * KRB5_CC_NOMEM - there was insufficient memory to allocate the
 * 		krb5_ccache.  id is undefined.
 * system errors (from open)
 */
static krb5_error_code KRB5_CALLCONV
krb5_fcc_generate_new (krb5_context context, krb5_ccache *id)
{
     krb5_ccache lid;
     int ret;
     krb5_error_code    kret = 0;
     char scratch[sizeof(TKT_ROOT)+6+1]; /* +6 for the scratch part, +1 for
					    NUL */
     krb5_fcc_data *data;
     krb5_int16 fcc_fvno = htons(context->fcc_default_format);
     krb5_int16 fcc_flen = 0;
     int errsave, cnt;
     struct fcc_set *setptr;

     /* Set master lock */
     kret = k5_mutex_lock(&krb5int_cc_file_mutex);
     if (kret)
	 return kret;

     (void) strcpy(scratch, TKT_ROOT);
     (void) strcat(scratch, "XXXXXX");
#ifdef HAVE_MKSTEMP
     ret = mkstemp(scratch);
     if (ret == -1) {
         k5_mutex_unlock(&krb5int_cc_file_mutex);
	 return krb5_fcc_interpret(context, errno);
     }
#else /*HAVE_MKSTEMP*/
     mktemp(scratch);
     /* Make sure the file name is reserved */
     ret = THREEPARAMOPEN(scratch, O_CREAT | O_EXCL | O_WRONLY | O_BINARY, 0);
     if (ret == -1) {
	  return krb5_fcc_interpret(context, errno);
     }
#endif

     /* Allocate memory */
     data = (krb5_pointer) malloc(sizeof(krb5_fcc_data));
     if (data == NULL) {
	  close(ret);
	  unlink(scratch);
	  k5_mutex_unlock(&krb5int_cc_file_mutex);
	  return KRB5_CC_NOMEM;
     }

     data->filename = strdup(scratch);
     if (data->filename == NULL) {
          k5_mutex_unlock(&krb5int_cc_file_mutex);
	  free(data);
	  close(ret);
	  unlink(scratch);
	  k5_mutex_unlock(&krb5int_cc_file_mutex);
	  return KRB5_CC_NOMEM;
     }

     kret = k5_mutex_init(&data->lock);
     if (kret) {
       k5_mutex_unlock(&krb5int_cc_file_mutex);
       free(data->filename);
       free(data);
       close(ret);
       unlink(scratch);
       return kret;
     }
     kret = k5_mutex_lock(&data->lock);
     if (kret) {
       k5_mutex_unlock(&krb5int_cc_file_mutex);
       k5_mutex_destroy(&data->lock);
       free(data->filename);
       free(data);
       close(ret);
       unlink(scratch);
       return kret;
     }

     /*
      * The file is initially closed at the end of this call...
      */
     data->flags = 0;
     data->file = -1;
     data->valid_bytes = 0;
     /* data->version,mode filled in for real later */
     data->version = data->mode = 0;


     /* Ignore user's umask, set mode = 0600 */
#ifndef HAVE_FCHMOD
#ifdef HAVE_CHMOD
     chmod(data->filename, S_IRUSR | S_IWUSR);
#endif
#else
     fchmod(ret, S_IRUSR | S_IWUSR);
#endif
     if ((cnt = write(ret, (char *)&fcc_fvno, sizeof(fcc_fvno)))
	 != sizeof(fcc_fvno)) {
	  errsave = errno;
	  (void) close(ret);
	  (void) unlink(data->filename);
	  kret = (cnt == -1) ? krb5_fcc_interpret(context, errsave) : KRB5_CC_IO;
	  goto err_out;
     }
     /* For version 4 we save a length for the rest of the header */
     if (context->fcc_default_format == KRB5_FCC_FVNO_4) {
	  if ((cnt = write(ret, (char *)&fcc_flen, sizeof(fcc_flen)))
	      != sizeof(fcc_flen)) {
	       errsave = errno;
	       (void) close(ret);
	       (void) unlink(data->filename);
	       kret = (cnt == -1) ? krb5_fcc_interpret(context, errsave) : KRB5_CC_IO;
	       goto err_out;
	  }
     }
     if (close(ret) == -1) {
	  errsave = errno;
	  (void) unlink(data->filename);
	  kret = krb5_fcc_interpret(context, errsave);
	  goto err_out;
     }


     setptr = malloc(sizeof(struct fcc_set));
     if (setptr == NULL) {
       k5_mutex_unlock(&krb5int_cc_file_mutex);
       k5_mutex_destroy(&data->lock);
       free(data->filename);
       free(data);
       (void) close(ret);
       (void) unlink(scratch);
       return KRB5_CC_NOMEM;
     }
     setptr->refcount = 1;
     setptr->data = data;
     setptr->next = fccs;
     fccs = setptr;
     k5_mutex_unlock(&krb5int_cc_file_mutex);

     k5_mutex_assert_locked(&data->lock);
     k5_mutex_unlock(&data->lock);
     lid = (krb5_ccache) malloc(sizeof(struct _krb5_ccache));
     if (lid == NULL) {
	 dereference(context, data);
	 return KRB5_CC_NOMEM;
     }

     lid->ops = &krb5_fcc_ops;
     lid->data = data;
     lid->magic = KV5M_CCACHE;

     /* default to open/close on every trn - otherwise destroy
	will get as to state confused */
     ((krb5_fcc_data *) lid->data)->flags = KRB5_TC_OPENCLOSE;

     *id = lid;


     krb5_change_cache ();
     return KRB5_OK;

err_out:
     k5_mutex_unlock(&krb5int_cc_file_mutex);
     k5_mutex_destroy(&data->lock);
     free(data->filename);
     free(data);
     return kret;
}

/*
 * Requires:
 * id is a file credential cache
 *
 * Returns:
 * The name of the file cred cache id.
 */
static const char * KRB5_CALLCONV
krb5_fcc_get_name (krb5_context context, krb5_ccache id)
{
     return (char *) ((krb5_fcc_data *) id->data)->filename;
}

/*
 * Modifies:
 * id, princ
 *
 * Effects:
 * Retrieves the primary principal from id, as set with
 * krb5_fcc_initialize.  The principal is returned is allocated
 * storage that must be freed by the caller via krb5_free_principal.
 *
 * Errors:
 * system errors
 * KRB5_CC_NOMEM
 */
static krb5_error_code KRB5_CALLCONV
krb5_fcc_get_principal(krb5_context context, krb5_ccache id, krb5_principal *princ)
{
     krb5_error_code kret = KRB5_OK;

     kret = k5_mutex_lock(&((krb5_fcc_data *) id->data)->lock);
     if (kret)
	 return kret;

     MAYBE_OPEN(context, id, FCC_OPEN_RDONLY);

     /* make sure we're beyond the header */
     kret = krb5_fcc_skip_header(context, id);
     if (kret) goto done;
     kret = krb5_fcc_read_principal(context, id, princ);

done:
     MAYBE_CLOSE(context, id, kret);
     k5_mutex_unlock(&((krb5_fcc_data *) id->data)->lock);
     return kret;
}


static krb5_error_code KRB5_CALLCONV
krb5_fcc_retrieve(krb5_context context, krb5_ccache id, krb5_flags whichfields, krb5_creds *mcreds, krb5_creds *creds)
{
    return krb5_cc_retrieve_cred_default (context, id, whichfields,
					  mcreds, creds);
}


/*
 * Modifies:
 * the file cache
 *
 * Effects:
 * stores creds in the file cred cache
 *
 * Errors:
 * system errors
 * storage failure errors
 */
static krb5_error_code KRB5_CALLCONV
krb5_fcc_store(krb5_context context, krb5_ccache id, krb5_creds *creds)
{
#define TCHECK(ret) if (ret != KRB5_OK) goto lose;
     krb5_error_code ret;

     ret = k5_mutex_lock(&((krb5_fcc_data *) id->data)->lock);
     if (ret)
	 return ret;

     /* Make sure we are writing to the end of the file */
     MAYBE_OPEN(context, id, FCC_OPEN_RDWR);

     /* Make sure we are writing to the end of the file */
     ret = fcc_lseek((krb5_fcc_data *) id->data, (off_t) 0, SEEK_END);
     if (ret < 0) {
          MAYBE_CLOSE_IGNORE(context, id);
	  k5_mutex_unlock(&((krb5_fcc_data *) id->data)->lock);
	  return krb5_fcc_interpret(context, errno);
     }

     ret = krb5_fcc_store_principal(context, id, creds->client);
     TCHECK(ret);
     ret = krb5_fcc_store_principal(context, id, creds->server);
     TCHECK(ret);
     ret = krb5_fcc_store_keyblock(context, id, &creds->keyblock);
     TCHECK(ret);
     ret = krb5_fcc_store_times(context, id, &creds->times);
     TCHECK(ret);
     ret = krb5_fcc_store_octet(context, id, (krb5_int32) creds->is_skey);
     TCHECK(ret);
     ret = krb5_fcc_store_int32(context, id, creds->ticket_flags);
     TCHECK(ret);
     ret = krb5_fcc_store_addrs(context, id, creds->addresses);
     TCHECK(ret);
     ret = krb5_fcc_store_authdata(context, id, creds->authdata);
     TCHECK(ret);
     ret = krb5_fcc_store_data(context, id, &creds->ticket);
     TCHECK(ret);
     ret = krb5_fcc_store_data(context, id, &creds->second_ticket);
     TCHECK(ret);

lose:
     MAYBE_CLOSE(context, id, ret);
     k5_mutex_unlock(&((krb5_fcc_data *) id->data)->lock);
     krb5_change_cache ();
     return ret;
#undef TCHECK
}

/*
 * Non-functional stub implementation for krb5_fcc_remove
 *
 * Errors:
 *    KRB5_CC_NOSUPP - not implemented
 */
static krb5_error_code KRB5_CALLCONV
krb5_fcc_remove_cred(krb5_context context, krb5_ccache cache, krb5_flags flags,
                     krb5_creds *creds)
{
    return KRB5_CC_NOSUPP;
}

/*
 * Requires:
 * id is a cred cache returned by krb5_fcc_resolve or
 * krb5_fcc_generate_new, but has not been opened by krb5_fcc_initialize.
 *
 * Modifies:
 * id
 *
 * Effects:
 * Sets the operational flags of id to flags.
 */
static krb5_error_code KRB5_CALLCONV
krb5_fcc_set_flags(krb5_context context, krb5_ccache id, krb5_flags flags)
{
    krb5_error_code ret = KRB5_OK;

    ret = k5_mutex_lock(&((krb5_fcc_data *) id->data)->lock);
    if (ret)
	return ret;

    /* XXX This should check for illegal combinations, if any.. */
    if (flags & KRB5_TC_OPENCLOSE) {
	/* asking to turn on OPENCLOSE mode */
	if (!OPENCLOSE(id)
	    /* XXX Is this test necessary? */
	    && ((krb5_fcc_data *) id->data)->file != NO_FILE)
            (void) krb5_fcc_close_file (context, ((krb5_fcc_data *) id->data));
    } else {
	/* asking to turn off OPENCLOSE mode, meaning it must be
	   left open.  We open if it's not yet open */
        MAYBE_OPEN(context, id, FCC_OPEN_RDONLY);
    }

    ((krb5_fcc_data *) id->data)->flags = flags;
    k5_mutex_unlock(&((krb5_fcc_data *) id->data)->lock);
    return ret;
}

/*
 * Requires:
 * id is a cred cache returned by krb5_fcc_resolve or
 * krb5_fcc_generate_new, but has not been opened by krb5_fcc_initialize.
 *
 * Modifies:
 * id (mutex only; temporary)
 *
 * Effects:
 * Returns the operational flags of id.
 */
static krb5_error_code KRB5_CALLCONV
krb5_fcc_get_flags(krb5_context context, krb5_ccache id, krb5_flags *flags)
{
    krb5_error_code ret = KRB5_OK;

    ret = k5_mutex_lock(&((krb5_fcc_data *) id->data)->lock);
    if (ret)
	return ret;
    *flags = ((krb5_fcc_data *) id->data)->flags;
    k5_mutex_unlock(&((krb5_fcc_data *) id->data)->lock);
    return ret;
}


static krb5_error_code
krb5_fcc_interpret(krb5_context context, int errnum)
{
    register krb5_error_code retval;
    switch (errnum) {
    case ENOENT:
	retval = KRB5_FCC_NOFILE;
	break;
    case EPERM:
    case EACCES:
#ifdef EISDIR
    case EISDIR:                        /* Mac doesn't have EISDIR */
#endif
    case ENOTDIR:
#ifdef ELOOP
    case ELOOP:                         /* Bad symlink is like no file. */
#endif
#ifdef ETXTBSY
    case ETXTBSY:
#endif
    case EBUSY:
    case EROFS:
	retval = KRB5_FCC_PERM;
	break;
    case EINVAL:
    case EEXIST:			/* XXX */
    case EFAULT:
    case EBADF:
#ifdef ENAMETOOLONG
    case ENAMETOOLONG:
#endif
#ifdef EWOULDBLOCK
    case EWOULDBLOCK:
#endif
	retval = KRB5_FCC_INTERNAL;
	break;
#ifdef EDQUOT
    case EDQUOT:
#endif
    case ENOSPC:
    case EIO:
    case ENFILE:
    case EMFILE:
    case ENXIO:
    default:
	retval = KRB5_CC_IO;		/* XXX */
	krb5_set_error_message(context, retval,
			    dgettext(TEXT_DOMAIN,
				"Credentials cache I/O operation failed (%s)"),
			    strerror(errnum));
    }
    return retval;
}

const krb5_cc_ops krb5_fcc_ops = {
     0,
     "FILE",
     krb5_fcc_get_name,
     krb5_fcc_resolve,
     krb5_fcc_generate_new,
     krb5_fcc_initialize,
     krb5_fcc_destroy,
     krb5_fcc_close,
     krb5_fcc_store,
     krb5_fcc_retrieve,
     krb5_fcc_get_principal,
     krb5_fcc_start_seq_get,
     krb5_fcc_next_cred,
     krb5_fcc_end_seq_get,
     krb5_fcc_remove_cred,
     krb5_fcc_set_flags,
     krb5_fcc_get_flags,
};

#if defined(_WIN32)
/*
 * krb5_change_cache should be called after the cache changes.
 * A notification message is is posted out to all top level
 * windows so that they may recheck the cache based on the
 * changes made.  We register a unique message type with which
 * we'll communicate to all other processes.
 */

krb5_error_code
krb5_change_cache (void) {

    PostMessage(HWND_BROADCAST, krb5_get_notification_message(), 0, 0);

    return 0;
}

unsigned int KRB5_CALLCONV
krb5_get_notification_message (void) {
    static unsigned int message = 0;

    if (message == 0)
        message = RegisterWindowMessage(WM_KERBEROS5_CHANGED);

    return message;
}
#else /* _WIN32 */

krb5_error_code
krb5_change_cache (void)
{
    return 0;
}
unsigned int
krb5_get_notification_message (void)
{
    return 0;
}

#endif /* _WIN32 */

const krb5_cc_ops krb5_cc_file_ops = {
     0,
     "FILE",
     krb5_fcc_get_name,
     krb5_fcc_resolve,
     krb5_fcc_generate_new,
     krb5_fcc_initialize,
     krb5_fcc_destroy,
     krb5_fcc_close,
     krb5_fcc_store,
     krb5_fcc_retrieve,
     krb5_fcc_get_principal,
     krb5_fcc_start_seq_get,
     krb5_fcc_next_cred,
     krb5_fcc_end_seq_get,
     krb5_fcc_remove_cred,
     krb5_fcc_set_flags,
     krb5_fcc_get_flags,
     NULL,
     NULL,
     NULL,
     NULL,
     NULL,
     NULL,
};
