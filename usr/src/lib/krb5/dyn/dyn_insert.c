#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file is part of libdyn.a, the C Dynamic Object library.  It
 * contains the source code for the function DynInsert().
 * 
 * There are no restrictions on this code; however, if you make any
 * changes, I request that you document them so that I do not get
 * credit or blame for your modifications.
 *
 * Written by Barr3y Jaspan, Student Information Processing Board (SIPB)
 * and MIT-Project Athena, 1989.
 */

#include <stdio.h>
#include <strings.h>
#include "dynP.h"

int DynInsert(obj, idx, els_in, num)
   DynObjectP obj;
   void *els_in;
   int idx, num;
{
     DynPtr els = (DynPtr) els_in;
     int ret;
     
     if (idx < 0 || idx > obj->num_el) {
	  if (obj->debug)
	       fprintf(stderr, "dyn: insert: index %d is not in [0,%d]\n",
		       idx, obj->num_el);
	  return DYN_BADINDEX;
     }

     if (num < 1) {
	  if (obj->debug)
	       fprintf(stderr, "dyn: insert: cannot insert %d elements\n",
		       num);
	  return DYN_BADVALUE;
     }

     if (obj->debug)
	  fprintf(stderr,"dyn: insert: Moving %d bytes from %d + %d to + %d\n",
		  (obj->num_el-idx)*obj->el_size, obj->array,
		  obj->el_size*idx, obj->el_size*(idx+num));

     if ((ret = _DynResize(obj, obj->num_el + num)) != DYN_OK)
	  return ret;
#ifdef HAVE_MEMMOVE
     memmove(obj->array + obj->el_size*(idx + num),
	     obj->array + obj->el_size*idx,
	     (obj->num_el-idx)*obj->el_size);
#else
     bcopy(obj->array + obj->el_size*idx,
	   obj->array + obj->el_size*(idx + num), 
	   (obj->num_el-idx)*obj->el_size);
#endif	     

     if (obj->debug)
	  fprintf(stderr, "dyn: insert: Copying %d bytes from %d to %d + %d\n",
		  obj->el_size*num, els, obj->array, obj->el_size*idx);

#ifdef HAVE_MEMMOVE
     memmove(obj->array + obj->el_size*idx, els, obj->el_size*num);
#else
     bcopy(els, obj->array + obj->el_size*idx, obj->el_size*num);
#endif     
     obj->num_el += num;

     if (obj->debug)
	  fprintf(stderr, "dyn: insert: done.\n");

     return DYN_OK;
}
