/*

  Copyright (C) 2000,2004 Silicon Graphics, Inc.  All Rights Reserved.

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2.1 of the GNU Lesser General Public License 
  as published by the Free Software Foundation.

  This program is distributed in the hope that it would be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  

  Further, this software is distributed without any warranty that it is
  free of the rightful claim of any third person regarding infringement 
  or the like.  Any license provided herein, whether implied or 
  otherwise, applies only to this software file.  Patent licenses, if
  any, provided herein do not apply to combinations of this program with 
  other software, or any other product whatsoever.  

  You should have received a copy of the GNU Lesser General Public 
  License along with this program; if not, write the Free Software 
  Foundation, Inc., 59 Temple Place - Suite 330, Boston MA 02111-1307, 
  USA.

  Contact information:  Silicon Graphics, Inc., 1600 Amphitheatre Pky,
  Mountain View, CA 94043, or:

  http://www.sgi.com

  For further information regarding this notice, see:

  http://oss.sgi.com/projects/GenInfo/NoticeExplan

*/



#include "config.h"
#include "dwarf_incl.h"
#include <stdlib.h>

/*
	The allocator wants to know which region
	this is to be in so it can allocate the new space
	with respect to the right region.
*/
 /*ARGSUSED*/
    Dwarf_Ptr _dwarf_p_get_alloc(Dwarf_P_Debug dbg, Dwarf_Unsigned size)
{
    void *sp;

    sp = malloc(size);
    memset(sp,0, (int) size);
    return sp;
}


 /*ARGSUSED*/ void
dwarf_p_dealloc(void *space, Dwarf_Unsigned typ)
{
    free(space);
    return;
}


/* Essentially a stub for now. */
 /*ARGSUSED*/ void
_dwarf_p_dealloc(Dwarf_P_Debug dbg, Dwarf_Small * ptr)
{
    dwarf_p_dealloc(ptr, DW_DLA_STRING);
}
