/*

  Copyright (C) 2000,2002,2004 Silicon Graphics, Inc.  All Rights Reserved.
  Portions Copyright 2011 David Anderson. All Rights Reserved.

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
  Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston MA 02110-1301,
  USA.

*/

#include "config.h"
#include "libdwarfdefs.h"

#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h> /* for exit(), C89 malloc */
#endif /* HAVE_STDLIB_H */
#include "pro_incl.h"
#include <stddef.h>
#include "dwarf.h"
#include "libdwarf.h"
#include "pro_opaque.h"
#include "pro_error.h"
#include "pro_alloc.h"


extern char *_dwarf_errmsgs[];

/*
    This function performs error handling as described in the
    libdwarf consumer document section 3.  Dbg is the Dwarf_P_debug
    structure being processed.  Error is a pointer to the pointer
    to the error descriptor that will be returned.  Errval is an
    error code listed in dwarf_error.h.

    The error number may be retrieved from the Dwarf_Error
    by calling dwarf_errno().
    The error string implied by the error number may be retrieved
    from the Dwarf_Error by calling dwarf_errmsg().
*/
void
_dwarf_p_error(Dwarf_P_Debug dbg,
    Dwarf_Error * error, Dwarf_Unsigned errval)
{
    Dwarf_Error errptr;

    if (errval > DW_DLE_LAST) {
        /*  We do not expect to ever see such an error number,
            DW_DLE_LO_USER is not used. */
        fprintf(stderr,"ERROR VALUE: %lu - %s\n",
            (unsigned long) errval, "this error value is unknown to libdwarf.");
    }
    /*  Allow NULL dbg on entry, since sometimes that can happen and we
        want to report the upper-level error, not this one. */
    if (error != NULL) {
        errptr = (Dwarf_Error)
            _dwarf_p_get_alloc(dbg, sizeof(struct Dwarf_Error_s));
        if (errptr == NULL) {
            fprintf(stderr,
                "Could not allocate Dwarf_Error structure\n");
            abort();
        }
        errptr->er_errval = (Dwarf_Signed) errval;
        *error = errptr;
        return;
    }

    if (dbg != NULL && dbg->de_errhand != NULL) {
        errptr = (Dwarf_Error)
            _dwarf_p_get_alloc(dbg, sizeof(struct Dwarf_Error_s));
        if (errptr == NULL) {
            fprintf(stderr,
                "Could not allocate Dwarf_Error structure\n");
            abort();
        }
        errptr->er_errval = (Dwarf_Signed) errval;
        dbg->de_errhand(errptr, dbg->de_errarg);
        return;
    }

    abort();
}
