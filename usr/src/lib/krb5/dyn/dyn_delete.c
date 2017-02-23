#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file is part of libdyn.a, the C Dynamic Object library.  It
 * contains the source code for the function DynDelete().
 *
 * There are no restrictions on this code; however, if you make any
 * changes, I request that you document them so that I do not get
 * credit or blame for your modifications.
 *
 * Written by Barr3y Jaspan, Student Information Processing Board (SIPB)
 * and MIT-Project Athena, 1989.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#include <stdio.h>
#include <strings.h>
#include <string.h>

#include "dynP.h"

/*
 * Checkers!  Get away from that "hard disk erase" button!
 *    (Stupid dog.  He almost did it to me again ...)
 */
int DynDelete(obj, idx)
   DynObjectP obj;
   int idx;
{
     if (idx < 0) {
	  if (obj->debug)
	       fprintf(stderr, "dyn: delete: bad index %d\n", idx);
	  return DYN_BADINDEX;
     }

     if (idx >= obj->num_el) {
	  if (obj->debug)
	       fprintf(stderr, "dyn: delete: Highest index is %d.\n",
		       obj->num_el);
	  return DYN_BADINDEX;
     }

     if (idx == obj->num_el-1) {
	  if (obj->paranoid) {
	       if (obj->debug)
		    fprintf(stderr, "dyn: delete: last element, zeroing.\n");
	       memset(obj->array + idx*obj->el_size, 0, obj->el_size);
	  }
	  else {
	       if (obj->debug)
		    fprintf(stderr, "dyn: delete: last element, punting.\n");
	  }
     }
     else {
	  if (obj->debug)
	       fprintf(stderr,
		       "dyn: delete: copying %d bytes from %d + %d to + %d.\n",
		       obj->el_size*(obj->num_el - idx), obj->array,
		       (idx+1)*obj->el_size, idx*obj->el_size);

#ifdef HAVE_MEMMOVE
	  memmove(obj->array + idx*obj->el_size,
		  obj->array + (idx+1)*obj->el_size,
		  obj->el_size*(obj->num_el - idx));
#else
	  bcopy(obj->array + (idx+1)*obj->el_size,
		  obj->array + idx*obj->el_size,
		  obj->el_size*(obj->num_el - idx));
#endif
	  if (obj->paranoid) {
	       if (obj->debug)
		    fprintf(stderr,
			    "dyn: delete: zeroing %d bytes from %d + %d\n",
			    obj->el_size, obj->array,
			    obj->el_size*(obj->num_el - 1));
	       memset(obj->array + obj->el_size*(obj->num_el - 1), 0,
		     obj->el_size);
	  }
     }

     --obj->num_el;

     if (obj->debug)
	  fprintf(stderr, "dyn: delete: done.\n");

     return DYN_OK;
}
