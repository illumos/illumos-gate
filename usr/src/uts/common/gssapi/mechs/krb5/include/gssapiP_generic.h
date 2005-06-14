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

/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _GSSAPIP_GENERIC_H_
#define _GSSAPIP_GENERIC_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * $Id: gssapiP_generic.h,v 1.24 1998/10/30 02:54:06 marc Exp $
 */

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(PROTOTYPE) 
#define     PROTOTYPE(x) x 
#endif 

#if (defined(_MSDOS) || defined(_WIN32) || defined(macintosh))
#include <k5-int.h>
#else
#ifdef HAVE_STDLIB_H
#ifndef _KERNEL
#include <stdlib.h>
#endif /* !_KERNEL */
#endif /* HAVE_STDLIB_H */
#endif

#include <mechglueP.h>
#include <gssapi/gssapi_ext.h>
#include <gssapi/gssapi.h>
#include "gssapi_generic.h"
#include "gssapi_err_generic.h"
#ifdef  _KERNEL
#include <sys/errno.h>
#else
#include <errno.h>
#endif

/** helper macros **/

typedef uint64_t gssint_uint64;

#if 0 	/* this is defined in usr/src/uts/common/gssapi/gssapi_ext.h */
#define g_OID_equal(o1,o2) \
   (((o1)->length == (o2)->length) && \
    (memcmp((o1)->elements,(o2)->elements,(int) (o1)->length) == 0))
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

typedef struct _g_set *g_set;

int g_set_init (g_set *s);
int g_set_destroy (g_set *s);
int g_set_entry_add (g_set *s, void *key, void *value);
int g_set_entry_delete (g_set *s, void *key);
int g_set_entry_get (g_set *s, void *key, void **value);

int g_save_name (void **vdb, gss_name_t name);
int g_save_cred_id (void **vdb, gss_cred_id_t cred);
int g_save_ctx_id (void **vdb, gss_ctx_id_t ctx);

int g_validate_name (void **vdb, gss_name_t name);
int g_validate_cred_id (void **vdb, gss_cred_id_t cred);
int g_validate_ctx_id (void **vdb, gss_ctx_id_t ctx);

int g_delete_name (void **vdb, gss_name_t name);
int g_delete_cred_id (void **vdb, gss_cred_id_t cred);
int g_delete_ctx_id (void **vdb, gss_ctx_id_t ctx);

int g_make_string_buffer (const char *str, gss_buffer_t buffer);

int g_copy_OID_set (const gss_OID_set_desc * const in, gss_OID_set *out);

int g_token_size (gss_OID mech, unsigned int body_size);

void g_make_token_header (gss_OID mech, int body_size,
			  unsigned char **buf, int tok_type);

gss_int32 g_verify_token_header (gss_OID mech, unsigned int *body_size,
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

char *g_local_host_name (void);

char *g_strdup (char *str);

#ifdef __cplusplus
}
#endif

#endif /* _GSSAPIP_GENERIC_H_ */
