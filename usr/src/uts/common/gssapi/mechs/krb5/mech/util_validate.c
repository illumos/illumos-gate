/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
 * $Id: util_validate.c,v 1.8 1996/08/28 21:50:37 tytso Exp $
 */

/*
 * functions to validate name, credential, and context handles
 */

#include <gssapiP_generic.h>

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

/* All these functions return 0 on failure, and non-zero on success */

static int g_save(db, type, ptr)
     void **db;
     int type;
     void *ptr;
{
#ifdef HAVE_BSD_DB
   DB **vdb = (DB **) db;
   vkey vk;
   DBT key;

   if (!*vdb)
      *vdb = dbopen(NULL, O_CREAT|O_RDWR, O_CREAT|O_RDWR, DB_HASH, NULL);

   vk.type = type;
   vk.ptr = ptr;

   key.data = &vk;
   key.size = sizeof(vk);

   return((*((*vdb)->put))(*vdb, &key, &dbtone, 0) == 0);
#else
   g_set *gs = (g_set *) db;

   if (!*gs)
      if (g_set_init(gs))
	 return(0);

   return(g_set_entry_add(gs, ptr, (void *)(intptr_t)type) == 0);
#endif
}

static int g_validate(db, type, ptr)
     void **db;
     int type;
     void *ptr;
{
#ifdef HAVE_BSD_DB
   DB **vdb = (DB **) db;
   vkey vk;
   DBT key, value;

   if (!*vdb)
      return(0);

   vk.type = type;
   vk.ptr = ptr;

   key.data = &vk;
   key.size = sizeof(vk);

   if ((*((*vdb)->get))(*vdb, &key, &value, 0))
      return(0);

   return((value.size == sizeof(one)) &&
	  (*((int *) value.data) == one));
#else
   g_set *gs = (g_set *) db;
   void *value;

   if (!*gs)
      return(0);

   if (g_set_entry_get(gs, ptr, (void **) &value))
      return(0);

   return((intptr_t)value == (intptr_t)type);
#endif
}

/*ARGSUSED*/
static int g_delete(db, type, ptr)
     void **db;
     int type;
     void *ptr;
{
#ifdef HAVE_BSD_DB
   DB **vdb = (DB **) db;
   vkey vk;
   DBT key;

   if (!*vdb)
      return(0);

   vk.type = type;
   vk.ptr = ptr;

   key.data = &vk;
   key.size = sizeof(vk);

   return((*((*vdb)->del))(*vdb, &key, 0) == 0);
#else
   g_set *gs = (g_set *) db;

   if (!*gs)
      return(0);

   if (g_set_entry_delete(gs, ptr))
      return(0);

   return(1);
#endif
}

/* functions for each type */

/* save */

int g_save_name(vdb, name)
     void **vdb;
     gss_name_t name;
{
   return(g_save(vdb, V_NAME, (void *) name));
}
int g_save_cred_id(vdb, cred)
     void **vdb;
     gss_cred_id_t cred;
{
   return(g_save(vdb, V_CRED_ID, (void *) cred));
}
int g_save_ctx_id(vdb, ctx)
     void **vdb;
     gss_ctx_id_t ctx;
{
   return(g_save(vdb, V_CTX_ID, (void *) ctx));
}

/* validate */

int g_validate_name(vdb, name)
     void **vdb;
     gss_name_t name;
{
   return(g_validate(vdb, V_NAME, (void *) name));
}
int g_validate_cred_id(vdb, cred)
     void **vdb;
     gss_cred_id_t cred;
{
   return(g_validate(vdb, V_CRED_ID, (void *) cred));
}
int g_validate_ctx_id(vdb, ctx)
     void **vdb;
     gss_ctx_id_t ctx;
{
   return(g_validate(vdb, V_CTX_ID, (void *) ctx));
}

/* delete */

int g_delete_name(vdb, name)
     void **vdb;
     gss_name_t name;
{
   return(g_delete(vdb, V_NAME, (void *) name));
}
int g_delete_cred_id(vdb, cred)
     void **vdb;
     gss_cred_id_t cred;
{
   return(g_delete(vdb, V_CRED_ID, (void *) cred));
}
int g_delete_ctx_id(vdb, ctx)
     void **vdb;
     gss_ctx_id_t ctx;
{
   return(g_delete(vdb, V_CTX_ID, (void *) ctx));
}

