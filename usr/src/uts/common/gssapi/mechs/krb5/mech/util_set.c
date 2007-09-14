/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright 1995 by OpenVision Technologies, Inc.
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
 * $Id: util_set.c 16165 2004-03-14 05:31:43Z raeburn $
 */

#include <mechglueP.h>  /* SUNW15resync - for MALLOC/FREE */
#include "gssapiP_generic.h"

struct _g_set_elt {
   void *key;
   void *value;
   struct _g_set_elt *next;
};

int g_set_init(g_set_elt *s)
{
   *s = NULL;

   return(0);
}

#if 0
int g_set_destroy(g_set_elt *s)
{
   g_set next;

   while (*s) {
      next = (*s)->next;
      FREE(*s, sizeof(struct _g_set));
      *s = next;
   }

   return(0);
}
#endif

int g_set_entry_add(g_set_elt *s, void *key, void *value)
{
   g_set_elt first;

   if ((first = (struct _g_set_elt *) MALLOC(sizeof(struct _g_set_elt))) == NULL)
      return(ENOMEM);

   first->key = key;
   first->value = value;
   first->next = *s;

   *s = first;

   return(0);
}

int g_set_entry_delete(g_set_elt *s, void *key)
{
   g_set_elt *p;

   for (p=s; *p; p = &((*p)->next)) {
      if ((*p)->key == key) {
	 g_set_elt next = (*p)->next;
	 FREE(*p, sizeof(struct _g_set_elt));
	 *p = next;

	 return(0);
      }
   }

   return(-1);
}

int g_set_entry_get(g_set_elt *s, void *key, void **value)
{
   g_set_elt p;

   for (p = *s; p; p = p->next) {
      if (p->key == key) {
	 *value = p->value;

	 return(0);
      }
   }

   *value = NULL;

   return(-1);
}
