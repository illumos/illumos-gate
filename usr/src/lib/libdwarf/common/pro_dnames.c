/*
  Copyright 2018-2018 David Anderson.  All Rights Reserved.

  This program is free software; you can redistribute it
  and/or modify it under the terms of version 2.1 of the
  GNU Lesser General Public License as published by the Free
  Software Foundation.

  This program is distributed in the hope that it would be
  useful, but WITHOUT ANY WARRANTY; without even the implied
  warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
  PURPOSE.

  Further, this software is distributed without any warranty
  that it is free of the rightful claim of any third person
  regarding infringement or the like.  Any license provided
  herein, whether implied or otherwise, applies only to this
  software file.  Patent licenses, if any, provided herein
  do not apply to combinations of this program with other
  software, or any other product whatsoever.

  You should have received a copy of the GNU Lesser General
  Public License along with this program; if not, write the
  Free Software Foundation, Inc., 51 Franklin Street - Fifth
  Floor, Boston MA 02110-1301, USA.

*/

#include "config.h"
#include "libdwarfdefs.h"
#include <stdio.h>
#include <string.h>
#ifdef HAVE_ELFACCESS_H
#include <elfaccess.h>
#endif
#include "pro_incl.h"
#include <stddef.h>
#include "dwarf.h"
#include "libdwarf.h"
#include "pro_opaque.h"
#include "pro_error.h"
#include "pro_alloc.h"
#include "pro_arange.h"
#include "pro_section.h"
#include "pro_reloc.h"
#include "pro_dnames.h"

#define FALSE 0
#define TRUE  1


int
dwarf_force_debug_names(Dwarf_P_Debug dbg,
    Dwarf_Error * error)
{

    Dwarf_P_Dnames dn;

    if (dbg == NULL) {
        _dwarf_p_error(NULL, error, DW_DLE_DBG_NULL);
        return DW_DLV_ERROR;
    }

    dn = (Dwarf_P_Dnames)
        _dwarf_p_get_alloc(dbg, sizeof(struct Dwarf_P_Dnames_s));
    if (dn == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }
    if (!dbg->de_dnames) {
        dbg->de_dnames = dn;
    }
    dn->dn_create_section = TRUE;

    return DW_DLV_OK;
}
