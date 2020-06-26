/*

  Copyright (C) 2000-2005 Silicon Graphics, Inc. All Rights Reserved.
  Portions Copyright (C) 2008-2014 David Anderson.  All Rights Reserved.

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
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif /* HAVE_STDLIB_H */
#include "dwarf_incl.h"
#include "dwarf_alloc.h"
#include "dwarfstring.h"
#include "dwarf_error.h"

/* Array to hold string representation of errors. Any time a
   define is added to the list in libdwarf.h, a string should be
   added to this Array
*/
#include "dwarf_errmsg_list.h"

/*  This function performs error handling as described in the
    libdwarf consumer document section 3.  Dbg is the Dwarf_debug
    structure being processed.  Error is a pointer to the pointer
    to the error descriptor that will be returned.  Errval is an
    error code listed in dwarf_error.h.

    If the malloc arena is exhausted we return a pointer to
    a special static error record.  This special singleton
    is mostly ignored by dwarf_dealloc().
    Users should not be storing Dwarf_Error pointers
    for long so this singleton is only going to cause
    confusion when callers try to save an out-of-memory
    Dwarf_Error pointer.
    The _dwarf_failsafe_error is intended to
    be an improvement over an abort() call.
    The failsafe means we will not abort due to
    a Dwarf_Error struct creation.
*/

/*  The user provides an explanatory string, the error
    number itself explains little.
    This prepends DW_DLE_USER_DECLARED_ERROR to the
    caller-provided string.
    New in April, 2020 .  Used by dwarfdump in a few
    circumstances. */
void
dwarf_error_creation(Dwarf_Debug dbg,
    Dwarf_Error *err,
    char *errmsg)
{
    dwarfstring m;
    if(!dbg) {
        return;
    }
    dwarfstring_constructor(&m);
    dwarfstring_append(&m,"DW_DLE_USER_DECLARED_ERROR: ");
    dwarfstring_append(&m,errmsg);
    _dwarf_error_string(dbg,err,
        DW_DLE_USER_DECLARED_ERROR,
        dwarfstring_string(&m));
    dwarfstring_destructor(&m);
}


void
_dwarf_error(Dwarf_Debug dbg, Dwarf_Error * error,
    Dwarf_Signed errval)
{
    _dwarf_error_string(dbg,error,errval,0);
}
void
_dwarf_error_string(Dwarf_Debug dbg, Dwarf_Error * error,
    Dwarf_Signed errval,char *msg)
{
    Dwarf_Error errptr;

    /*  Allow NULL dbg on entry, since sometimes that can happen and we
        want to report the upper-level error, not this one. */
    if (error) {
        /*  If dbg is NULL, use the alternate error struct. However,
            this will overwrite the earlier error. */
        if (dbg) {
            errptr =
                (Dwarf_Error) _dwarf_get_alloc(dbg, DW_DLA_ERROR, 1);
            if (!errptr) {
                errptr = &_dwarf_failsafe_error;
                errptr->er_static_alloc = DE_STATIC;
            } else {
                errptr->er_static_alloc = DE_STANDARD;
            }
        } else {
            /*  We have no dbg to work with. dwarf_init
                failed. We hack
                up a special area. */
            errptr = _dwarf_special_no_dbg_error_malloc();
            if (!errptr) {
                errptr = &_dwarf_failsafe_error;
                errptr->er_static_alloc = DE_STATIC;
            } else {
                errptr->er_static_alloc = DE_MALLOC;
            }
        }
        errptr->er_errval = errval;
        if (msg) {
            dwarfstring *em = 0;

#ifdef DEBUG
printf("libdwarfdetector ALLOC creating error string %s errval %ld errptr 0x%lx \n",msg,(long)errval,(unsigned long)errptr);
#endif
            em = (dwarfstring *)calloc(1,sizeof(dwarfstring));
            if (em) {
                dwarfstring_constructor(em);
                dwarfstring_append(em,msg);
                errptr->er_msg = (void*)em;
            }
        }
        *error = errptr;
        return;
    }

    if (dbg != NULL && dbg->de_errhand != NULL) {
        errptr = (Dwarf_Error) _dwarf_get_alloc(dbg, DW_DLA_ERROR, 1);
        if (errptr == NULL) {
            errptr = &_dwarf_failsafe_error;
            errptr->er_static_alloc = DE_STATIC;
        }
        errptr->er_errval = errval;
        dbg->de_errhand(errptr, dbg->de_errarg);
        return;
    }
    fflush(stdout);
    fprintf(stdout,
        "\nNow abort() in libdwarf. "
        "No error argument or handler available.\n");
    fflush(stdout);
    abort();
}


Dwarf_Unsigned
dwarf_errno(Dwarf_Error error)
{
    if (!error) {
        return (0);
    }
    return (error->er_errval);
}

char*
dwarf_errmsg_by_number(Dwarf_Unsigned errornum )
{
    if (errornum >=
        (Dwarf_Signed)(sizeof(_dwarf_errmsgs) / sizeof(char *))) {
        return "Dwarf_Error value out of range";
    }
    return ((char *) _dwarf_errmsgs[errornum]);
}


/*
*/
char *
dwarf_errmsg(Dwarf_Error error)
{
    if (!error) {
        return "Dwarf_Error is NULL";
    }
    if (error->er_msg) {
        return dwarfstring_string(error->er_msg);
    }
    return  dwarf_errmsg_by_number(error->er_errval);
}
