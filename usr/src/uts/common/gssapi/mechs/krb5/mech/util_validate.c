/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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

/*
 * $Id: util_validate.c 18721 2006-10-16 16:18:29Z epeisach $
 */

/*
 * functions to validate name, credential, and context handles
 */

#include "gssapiP_generic.h"
#ifndef	_KERNEL
#include "gss_libinit.h"
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef	_KERNEL
#include <sys/fcntl.h>
#else
#include <fcntl.h>
#include <limits.h>
#endif

#ifdef HAVE_BSD_DB
#include <sys/file.h>
#include <db.h>

static const int one = 1;
static const DBT dbtone = { (void *) &one, sizeof(one) };

typedef struct _vkey {
   int type;
   void *ptr;
} vkey;
#endif

#define V_NAME		1
#define V_CRED_ID	2
#define V_CTX_ID	3
#define V_LCTX_ID	4

/* SUNW15resync
   beware some of the uses below of type look dubious but seem
   to have been working in Solaris for a long time */

/* All these functions return 0 on failure, and non-zero on success */

static int g_save(db, type, ptr)
     g_set *db;
     int type;
     void *ptr;
{
   int ret;
#ifdef HAVE_BSD_DB
   DB **vdb;
   vkey vk;
   DBT key;

#ifndef	_KERNEL
   ret = gssint_initialize_library();
   if (ret)
       return 0;
#endif
   ret = k5_mutex_lock(&db->mutex);
   if (ret)
       return 0;

   vdb = (DB **) &db->data;

   if (!*vdb)
      *vdb = dbopen(NULL, O_CREAT|O_RDWR, O_CREAT|O_RDWR, DB_HASH, NULL);

   vk.type = type;
   vk.ptr = ptr;

   key.data = &vk;
   key.size = sizeof(vk);

   ret = ((*((*vdb)->put))(*vdb, &key, &dbtone, 0) == 0);
   (void) k5_mutex_unlock(&db->mutex);
   return ret;
#else
   g_set_elt *gs;

#ifndef _KERNEL
   ret = gssint_initialize_library();
   if (ret)
       return 0;
#endif
   ret = k5_mutex_lock(&db->mutex);
   if (ret)
       return 0;

   gs = (g_set_elt *) &db->data;

   if (!*gs)
      if (g_set_init(gs)) {
	 (void) k5_mutex_unlock(&db->mutex);
	 return(0);
      }

   /* SUNW15resync */
   ret = (g_set_entry_add(gs, ptr, (void *)(intptr_t)type) == 0);
   (void) k5_mutex_unlock(&db->mutex);
   return ret;
#endif
}

static int g_validate(db, type, ptr)
     g_set *db;
     int type;
     void *ptr;
{
   int ret;
#ifdef HAVE_BSD_DB
   DB **vdb;
   vkey vk;
   DBT key, value;

   ret = k5_mutex_lock(&db->mutex);
   if (ret)
       return 0;

   vdb = (DB **) &db->data;
   if (!*vdb) {
      (void) k5_mutex_unlock(&db->mutex);
      return(0);
   }

   vk.type = type;
   vk.ptr = ptr;

   key.data = &vk;
   key.size = sizeof(vk);

   if ((*((*vdb)->get))(*vdb, &key, &value, 0)) {
      (void) k5_mutex_unlock(&db->mutex);
      return(0);
   }

   (void) k5_mutex_unlock(&db->mutex);
   return((value.size == sizeof(one)) &&
	  (*((int *) value.data) == one));
#else
   g_set_elt *gs;
   void *value;

   ret = k5_mutex_lock(&db->mutex);
   if (ret)
       return 0;

   gs = (g_set_elt *) &db->data;
   if (!*gs) {
      (void) k5_mutex_unlock(&db->mutex);
      return(0);
   }

   if (g_set_entry_get(gs, ptr, (void **) &value)) {
      (void) k5_mutex_unlock(&db->mutex);
      return(0);
   }
   (void) k5_mutex_unlock(&db->mutex);
   return((intptr_t)value == (intptr_t)type); /* SUNW15resync */
#endif
}

/*ARGSUSED*/
static int g_delete(db, type, ptr)
     g_set *db;
     int type;
     void *ptr;
{
   int ret;
#ifdef HAVE_BSD_DB
   DB **vdb;
   vkey vk;
   DBT key;

   ret = k5_mutex_lock(&db->mutex);
   if (ret)
       return 0;

   vdb = (DB **) &db->data;
   if (!*vdb) {
      (void) k5_mutex_unlock(&db->mutex);
      return(0);
   }

   vk.type = type;
   vk.ptr = ptr;

   key.data = &vk;
   key.size = sizeof(vk);

   ret = ((*((*vdb)->del))(*vdb, &key, 0) == 0);
   (void) k5_mutex_unlock(&db->mutex);
   return ret;
#else
   g_set_elt *gs;

   ret = k5_mutex_lock(&db->mutex);
   if (ret)
       return 0;

   gs = (g_set_elt *) &db->data;
   if (!*gs) {
      (void) k5_mutex_unlock(&db->mutex);
      return(0);
   }

   if (g_set_entry_delete(gs, ptr)) {
      (void) k5_mutex_unlock(&db->mutex);
      return(0);
   }
   (void) k5_mutex_unlock(&db->mutex);
   return(1);
#endif
}

/* functions for each type */

/* save */

int g_save_name(vdb, name)
     g_set *vdb;
     gss_name_t name;
{
   return(g_save(vdb, V_NAME, (void *) name));
}
int g_save_cred_id(vdb, cred)
     g_set *vdb;
     gss_cred_id_t cred;
{
   return(g_save(vdb, V_CRED_ID, (void *) cred));
}
int g_save_ctx_id(vdb, ctx)
     g_set *vdb;
     gss_ctx_id_t ctx;
{
   return(g_save(vdb, V_CTX_ID, (void *) ctx));
}
int g_save_lucidctx_id(vdb, lctx)
     g_set *vdb;
     void *lctx;
{
   return(g_save(vdb, V_LCTX_ID, (void *) lctx));
}


/* validate */

int g_validate_name(vdb, name)
     g_set *vdb;
     gss_name_t name;
{
   return(g_validate(vdb, V_NAME, (void *) name));
}
int g_validate_cred_id(vdb, cred)
     g_set *vdb;
     gss_cred_id_t cred;
{
   return(g_validate(vdb, V_CRED_ID, (void *) cred));
}
int g_validate_ctx_id(vdb, ctx)
     g_set *vdb;
     gss_ctx_id_t ctx;
{
   return(g_validate(vdb, V_CTX_ID, (void *) ctx));
}
int g_validate_lucidctx_id(vdb, lctx)
     g_set *vdb;
     void *lctx;
{
   return(g_validate(vdb, V_LCTX_ID, (void *) lctx));
}

/* delete */

int g_delete_name(vdb, name)
     g_set *vdb;
     gss_name_t name;
{
   return(g_delete(vdb, V_NAME, (void *) name));
}
int g_delete_cred_id(vdb, cred)
     g_set *vdb;
     gss_cred_id_t cred;
{
   return(g_delete(vdb, V_CRED_ID, (void *) cred));
}
int g_delete_ctx_id(vdb, ctx)
     g_set *vdb;
     gss_ctx_id_t ctx;
{
   return(g_delete(vdb, V_CTX_ID, (void *) ctx));
}
int g_delete_lucidctx_id(vdb, lctx)
     g_set *vdb;
     void *lctx;
{
   return(g_delete(vdb, V_LCTX_ID, (void *) lctx));
}

