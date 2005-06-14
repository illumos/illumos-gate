#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file is part of libdyn.a, the C Dynamic Object library.  It
 * contains the source code for the functions DynCreate() and
 * DynDestroy().
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
#include <string.h>

#include "dynP.h"

#ifndef DEFAULT_INC
#define DEFAULT_INC	100
#endif

static int default_increment = DEFAULT_INC;

DynObjectP DynCreate(el_size, inc)
   int	el_size, inc;
{
     DynObjectP obj;

     obj = (DynObjectP) malloc(sizeof(DynObjectRecP));
     if (obj == NULL)
	  return NULL;

#ifdef USE_DBMALLOC
     obj->array = (DynPtr) malloc(1);
#else
     obj->array = (DynPtr) malloc(0);
#endif
     obj->el_size = el_size;
     obj->num_el = obj->size = 0;
     obj->debug = obj->paranoid = 0;
     obj->inc = (!! inc) ? inc : default_increment;

     return obj;
}

DynObjectP DynCopy(obj)
   DynObjectP obj;
{
     DynObjectP obj1;
     
     obj1 = (DynObjectP) malloc(sizeof(DynObjectRecP));
     if (obj1 == NULL)
	  return NULL;

     obj1->el_size = obj->el_size;
     obj1->num_el = obj->num_el;
     obj1->size = obj->size;
     obj1->inc = obj->inc;
     obj1->debug = obj->debug;
     obj1->paranoid = obj->paranoid;
     obj1->initzero = obj->initzero;
     obj1->array = (char *) malloc(obj1->el_size * obj1->size);
     if (obj1->array == NULL) {
	  free(obj1);
	  return NULL;
     }
     memcpy(obj->array, obj1->array, 
	    (size_t) (obj1->el_size * obj1->size));

     return obj1;
}

int DynDestroy(obj)
   DynObjectP obj;
{
     if (obj->paranoid) {
	  if (obj->debug)
	       fprintf(stderr, "dyn: destroy: zeroing %d bytes from %d.\n",
		       obj->el_size * obj->size, obj->array);
	  memset(obj->array, 0, obj->el_size * obj->size);
     }
     free(obj->array);
     free(obj);
     return DYN_OK;
}

int DynRelease(obj)
   DynObjectP obj;
{
     if (obj->debug)
	  fprintf(stderr, "dyn: release: freeing object structure.\n");
     free(obj);
     return DYN_OK;
}
