/*
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright 1993 by OpenVision Technologies, Inc.
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 *
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _GSSAPIP_GENERIC_H_
#define _GSSAPIP_GENERIC_H_

/*
 * $Id: gssapiP_generic.h 18396 2006-07-25 20:29:43Z lxs $
 */

#if defined(_WIN32)
#include "k5-int.h"
#else
#include "autoconf.h"
#ifndef _KERNEL
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif /* !_KERNEL */
#endif
#endif

#include "k5-thread.h"

#include "gssapi_generic.h"

#include "gssapi_err_generic.h"
#ifndef _KERNEL
#include <errno.h>
#else
#include <sys/errno.h>
#endif /* !_KERNEL */

#include "k5-platform.h"
typedef UINT64_TYPE gssint_uint64;

#include "gssapi/gssapi_ext.h"

/** helper macros **/

#if 0 /* SUNW15resync - on Solaris g_OID_equal is in gssapi_ext.h */
#define g_OID_equal(o1, o2) \
   (((o1)->length == (o2)->length) && \
    (memcmp((o1)->elements,(o2)->elements,(unsigned int) (o1)->length) == 0))
#endif

/* this code knows that an int on the wire is 32 bits.  The type of
   num should be at least this big, or the extra shifts may do weird
   things */

#define TWRITE_INT(ptr, num, bigend) \
   (ptr)[0] = (char) ((bigend)?((num)>>24):((num)&0xff)); \
   (ptr)[1] = (char) ((bigend)?(((num)>>16)&0xff):(((num)>>8)&0xff)); \
   (ptr)[2] = (char) ((bigend)?(((num)>>8)&0xff):(((num)>>16)&0xff)); \
   (ptr)[3] = (char) ((bigend)?((num)&0xff):((num)>>24)); \
   (ptr) += 4;

#define TWRITE_INT16(ptr, num, bigend) \
   (ptr)[0] = (char) ((bigend)?((num)>>24):((num)&0xff)); \
   (ptr)[1] = (char) ((bigend)?(((num)>>16)&0xff):(((num)>>8)&0xff)); \
   (ptr) += 2;

#define TREAD_INT(ptr, num, bigend) \
   (num) = (((ptr)[0]<<((bigend)?24: 0)) | \
            ((ptr)[1]<<((bigend)?16: 8)) | \
            ((ptr)[2]<<((bigend)? 8:16)) | \
            ((ptr)[3]<<((bigend)? 0:24))); \
   (ptr) += 4;

#define TREAD_INT16(ptr, num, bigend) \
   (num) = (((ptr)[0]<<((bigend)?24: 0)) | \
            ((ptr)[1]<<((bigend)?16: 8))); \
   (ptr) += 2;

#define TWRITE_STR(ptr, str, len) \
  (void) memcpy((ptr), (char *) (str), (len)); \
   (ptr) += (len);

#define TREAD_STR(ptr, str, len) \
   (str) = (ptr); \
   (ptr) += (len);

#define TWRITE_BUF(ptr, buf, bigend) \
   TWRITE_INT((ptr), (buf).length, (bigend)); \
   TWRITE_STR((ptr), (buf).value, (buf).length);

/** malloc wrappers; these may actually do something later */

#ifdef _KERNEL
#define xmalloc(n) MALLOC(n)
#else
#define xmalloc(n) malloc(n)
#endif

#define xrealloc(p,n) realloc(p,n)
#ifdef xfree
#undef xfree
#endif

#ifdef _KERNEL
#define xfree_wrap(p,sze) kmem_free(p,sze)
#else
#define xfree_wrap(p,sze) free(p)
#define xfree(p) free(p)
#endif

/** helper functions **/

/* hide names from applications, especially glib applications */
#define	g_set_init		gssint_g_set_init
#define	g_set_destroy		gssint_g_set_destroy
#define	g_set_entry_add		gssint_g_set_entry_add
#define	g_set_entry_delete	gssint_g_set_entry_delete
#define	g_set_entry_get		gssint_g_set_entry_get
#define	g_save_name		gssint_g_save_name
#define	g_save_cred_id		gssint_g_save_cred_id
#define	g_save_ctx_id		gssint_g_save_ctx_id
#define	g_save_lucidctx_id	gssint_g_save_lucidctx_id
#define	g_validate_name		gssint_g_validate_name
#define	g_validate_cred_id	gssint_g_validate_cred_id
#define	g_validate_ctx_id	gssint_g_validate_ctx_id
#define	g_validate_lucidctx_id	gssint_g_validate_lucidctx_id
#define	g_delete_name		gssint_g_delete_name
#define	g_delete_cred_id	gssint_g_delete_cred_id
#define	g_delete_ctx_id		gssint_g_delete_ctx_id
#define	g_delete_lucidctx_id	gssint_g_delete_lucidctx_id
#define	g_make_string_buffer	gssint_g_make_string_buffer
#define	g_token_size		gssint_g_token_size
#define	g_make_token_header	gssint_g_make_token_header
#define	g_verify_token_header	gssint_g_verify_token_header
#define	g_display_major_status	gssint_g_display_major_status
#define	g_display_com_err_status gssint_g_display_com_err_status
#define	g_order_init		gssint_g_order_init
#define	g_order_check		gssint_g_order_check
#define	g_order_free		gssint_g_order_free
#define	g_queue_size		gssint_g_queue_size
#define	g_queue_externalize	gssint_g_queue_externalize
#define	g_queue_internalize	gssint_g_queue_internalize
#define	g_canonicalize_host	gssint_g_canonicalize_host
#define	g_local_host_name	gssint_g_local_host_name
#define	g_strdup		gssint_g_strdup

typedef struct _g_set_elt *g_set_elt;
typedef struct {
    k5_mutex_t mutex;
    void *data;
} g_set;
#define G_SET_INIT { K5_MUTEX_PARTIAL_INITIALIZER, 0 }

int g_set_init (g_set_elt *s);
int g_set_destroy (g_set_elt *s);
int g_set_entry_add (g_set_elt *s, void *key, void *value);
int g_set_entry_delete (g_set_elt *s, void *key);
int g_set_entry_get (g_set_elt *s, void *key, void **value);

int g_save_name (g_set *vdb, gss_name_t name);
int g_save_cred_id (g_set *vdb, gss_cred_id_t cred);
int g_save_ctx_id (g_set *vdb, gss_ctx_id_t ctx);
int g_save_lucidctx_id (g_set *vdb, void *lctx);

int g_validate_name (g_set *vdb, gss_name_t name);
int g_validate_cred_id (g_set *vdb, gss_cred_id_t cred);
int g_validate_ctx_id (g_set *vdb, gss_ctx_id_t ctx);
int g_validate_lucidctx_id (g_set *vdb, void *lctx);

int g_delete_name (g_set *vdb, gss_name_t name);
int g_delete_cred_id (g_set *vdb, gss_cred_id_t cred);
int g_delete_ctx_id (g_set *vdb, gss_ctx_id_t ctx);
int g_delete_lucidctx_id (g_set *vdb, void *lctx);

int g_make_string_buffer (const char *str, gss_buffer_t buffer);

unsigned int g_token_size (const gss_OID_desc * mech, unsigned int body_size);

void g_make_token_header (const gss_OID_desc * mech, unsigned int body_size,
			  unsigned char **buf, int tok_type);

gss_int32 g_verify_token_header (const gss_OID_desc * mech,
				 unsigned int *body_size,
				 unsigned char **buf, int tok_type,
				 unsigned int toksize_in,
				 int wrapper_required);

OM_uint32 g_display_major_status (OM_uint32 *minor_status,
				 OM_uint32 status_value,
				 OM_uint32 *message_context,
				 gss_buffer_t status_string);

OM_uint32 g_display_com_err_status (OM_uint32 *minor_status,
				   OM_uint32 status_value,
				   gss_buffer_t status_string);

gss_int32 g_order_init (void **queue, gssint_uint64 seqnum,
				  int do_replay, int do_sequence, int wide);

gss_int32 g_order_check (void **queue, gssint_uint64 seqnum);

void g_order_free (void **queue);

gss_uint32 g_queue_size(void *vqueue, size_t *sizep);
gss_uint32 g_queue_externalize(void *vqueue, unsigned char **buf,
			       size_t *lenremain);
gss_uint32 g_queue_internalize(void **vqueue, unsigned char **buf,
			       size_t *lenremain);

char *g_strdup (char *str);

/** declarations of internal name mechanism functions **/

#if 0 /* SUNW15resync - mved to mglueP.h for sake of non-krb5 mechs */
OM_uint32 generic_gss_release_buffer
(OM_uint32*,       /* minor_status */
            gss_buffer_t      /* buffer */
           );

OM_uint32 generic_gss_release_oid_set
(OM_uint32*,       /* minor_status */
            gss_OID_set*      /* set */
           );

OM_uint32 generic_gss_release_oid
(OM_uint32*,       /* minor_status */
            gss_OID*         /* set */
           );

OM_uint32 generic_gss_copy_oid
(OM_uint32 *,	/* minor_status */
            gss_OID_desc * const,   /* oid */ /* SUNW15resync */
	    gss_OID *		/* new_oid */
	    );

OM_uint32 generic_gss_create_empty_oid_set
(OM_uint32 *,	/* minor_status */
	    gss_OID_set *	/* oid_set */
	   );

OM_uint32 generic_gss_add_oid_set_member
(OM_uint32 *,	/* minor_status */
	    const gss_OID_desc * const,		/* member_oid */
	    gss_OID_set *	/* oid_set */
	   );

OM_uint32 generic_gss_test_oid_set_member
(OM_uint32 *,	/* minor_status */
	    const gss_OID_desc * const,		/* member */
	    gss_OID_set,	/* set */
	    int *		/* present */
	   );

OM_uint32 generic_gss_oid_to_str
(OM_uint32 *,	/* minor_status */
	    const gss_OID_desc * const,		/* oid */
	    gss_buffer_t	/* oid_str */
	   );

OM_uint32 generic_gss_str_to_oid
(OM_uint32 *,	/* minor_status */
	    gss_buffer_t,	/* oid_str */
	    gss_OID *		/* oid */
	   );

OM_uint32
generic_gss_oid_compose(
    OM_uint32 *,        /* minor_status */
    const char *,       /* prefix */
    size_t,             /* prefix_len */
    int,                /* suffix */
    gss_OID_desc *);    /* oid */

OM_uint32
generic_gss_oid_decompose(
    OM_uint32 *,        /* minor_status */
    const char *,       /*prefix */
    size_t,             /* prefix_len */
    gss_OID_desc *,     /* oid */
    int *);             /* suffix */

#endif /* 0 */

#ifndef _KERNEL
int gssint_mecherrmap_init(void);
void gssint_mecherrmap_destroy(void);
OM_uint32 gssint_mecherrmap_map(OM_uint32 minor, const gss_OID_desc *oid);
int gssint_mecherrmap_get(OM_uint32 minor, gss_OID mech_oid,
			OM_uint32 *mech_minor);
OM_uint32 gssint_mecherrmap_map_errcode(OM_uint32 errcode);
#endif

#endif /* _GSSAPIP_GENERIC_H_ */
