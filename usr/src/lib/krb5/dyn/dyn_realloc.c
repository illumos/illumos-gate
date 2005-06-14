#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file is part of libdyn.a, the C Dynamic Object library.  It
 * contains the source code for the internal function _DynRealloc().
 *
 * There are no restrictions on this code; however, if you make any
 * changes, I request that you document them so that I do not get
 * credit or blame for your modifications.
 *
 * Written by Barr3y Jaspan, Student Information Processing Board (SIPB)
 * and MIT-Project Athena, 1989.
 */

#include <stdio.h>
#include <stdlib.h>

#include "dynP.h"

/*
 * Resize the array so that element req exists.
 */
int _DynResize(obj, req)
   DynObjectP obj;
   int req;
{
     int cnt, size;
     
     if (obj->size > req)
	  return DYN_OK;
     else if (obj->inc > 0)
	  return _DynRealloc(obj, (req - obj->size) / obj->inc + 1);
     else {
	  if (obj->size == 0)
	       size = -obj->inc;
	  else 
	       size = obj->size;
	  
	  while (size <= req)
	       size <<= 1;

	  return _DynRealloc(obj, size);
     }
}

/*
 * Resize the array by num_incs units.  If obj->inc is positive, this
 * means make it obj->inc*num_incs elements larger.  If obj->inc is
 * negative, this means make the array num_incs elements long.
 * 
 * Ideally, this function should not be called from outside the
 * library.  However, nothing will break if it is.
 */
int _DynRealloc(obj, num_incs)
   DynObjectP obj;
   int num_incs;
{
     DynPtr temp;
     int new_size_in_bytes;

     if (obj->inc > 0)
	  new_size_in_bytes = obj->el_size*(obj->size + obj->inc*num_incs);
     else
	  new_size_in_bytes = obj->el_size*num_incs;
     
     if (obj->debug)
	  fprintf(stderr,
		  "dyn: alloc: Increasing object by %d bytes (%d incs).\n",
		  new_size_in_bytes - obj->el_size*obj->size,
		  num_incs);
     
     temp = (DynPtr) realloc(obj->array, new_size_in_bytes);
     if (temp == NULL) {
	  if (obj->debug)
	       fprintf(stderr, "dyn: alloc: Out of memory.\n");
	  return DYN_NOMEM;
     }
     else {
	  obj->array = temp;
	  if (obj->inc > 0)
	       obj->size += obj->inc*num_incs;
	  else
	       obj->size = num_incs;
     }

     if (obj->debug)
	  fprintf(stderr, "dyn: alloc: done.\n");
	  
     return DYN_OK;
}
