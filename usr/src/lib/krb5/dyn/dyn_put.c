#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file is part of libdyn.a, the C Dynamic Object library.  It
 * contains the source code for the functions DynGet() and DynAdd().
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

DynPtr DynArray(obj)
   DynObjectP obj;
{
     if (obj->debug)
	  fprintf(stderr, "dyn: array: returning array pointer %d.\n",
		  obj->array);

     return obj->array;
}

DynPtr DynGet(obj, num)
   DynObjectP obj;
   int num;
{
     if (num < 0) {
	  if (obj->debug)
	       fprintf(stderr, "dyn: get: bad index %d\n", num);
	  return NULL;
     }
     
     if (num >= obj->num_el) {
	  if (obj->debug)
	       fprintf(stderr, "dyn: get: highest element is %d.\n",
		       obj->num_el);
	  return NULL;
     }
     
     if (obj->debug)
	  fprintf(stderr, "dyn: get: Returning address %d + %d.\n",
		  obj->array, obj->el_size*num);
     
     return (DynPtr) obj->array + obj->el_size*num;
}

int DynAdd(obj, el)
   DynObjectP obj;
   void *el;
{
     int	ret;
     
     ret = DynPut(obj, el, obj->num_el);
     if (ret != DYN_OK)
	  return ret;

     ++obj->num_el;
     return ret;
}

/*
 * WARNING!  There is a reason this function is not documented in the
 * man page.  If DynPut used to mutate already existing elements,
 * everything will go fine.  If it is used to add new elements
 * directly, however, the state within the object (such as
 * obj->num_el) will not be updated properly and many other functions
 * in the library will lose.  Have a nice day.
 */
int DynPut(obj, el_in, idx)
   DynObjectP obj;
   void *el_in;
   int idx;
{
     DynPtr el = (DynPtr) el_in;
     int ret;
     
     if (obj->debug)
	  fprintf(stderr, "dyn: put: Writing %d bytes from %d to %d + %d\n",
		  obj->el_size, el, obj->array, idx*obj->el_size);

     if ((ret = _DynResize(obj, idx)) != DYN_OK)
	  return ret;

#ifdef HAVE_MEMMOVE
     memmove(obj->array + idx*obj->el_size, el, obj->el_size);
#else
     bcopy(el, obj->array + idx*obj->el_size, obj->el_size);
#endif     

     if (obj->debug)
	  fprintf(stderr, "dyn: put: done.\n");
     
     return DYN_OK;
}
