/*
  Copyright (C) 2000-2006 Silicon Graphics, Inc.  All Rights Reserved.
  Portions Copyright 2007-2010 Sun Microsystems, Inc. All rights reserved.
  Portions Copyright 2008-2010 Arxan Technologies, Inc. All rights reserved.
  Portions Copyright 2011-2015 David Anderson. All rights reserved.
  Portions Copyright 2012 SN Systems Ltd. All rights reserved.

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
#ifdef HAVE_LIBELF_H
#include <libelf.h>
#else
#ifdef HAVE_LIBELF_LIBELF_H
#include <libelf/libelf.h>
#endif
#endif
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif /* HAVE_STDLIB_H */

#include "dwarf_incl.h"
#include "dwarf_error.h"
#include "dwarf_elf_access.h"
#include "dwarf_object_detector.h"


#define DWARF_DBG_ERROR(dbg,errval,retval) \
    _dwarf_error(dbg, error, errval); return(retval);

#define FALSE  0
#define TRUE   1

/* New March 2017 */
int
dwarf_elf_init_b(
#ifndef DWARF_WITH_LIBELF
    UNUSEDARG dwarf_elf_handle elf_file_pointer,
    UNUSEDARG Dwarf_Unsigned access,
    UNUSEDARG unsigned group_number,
    UNUSEDARG Dwarf_Handler errhand,
    UNUSEDARG Dwarf_Ptr errarg,
    UNUSEDARG Dwarf_Debug * ret_dbg,
#else
    dwarf_elf_handle elf_file_pointer,
    Dwarf_Unsigned access,
    unsigned group_number,
    Dwarf_Handler errhand,
    Dwarf_Ptr errarg,
    Dwarf_Debug * ret_dbg,
#endif /* DWARF_WITH_LIBELF */
    Dwarf_Error * error)
{
#ifndef DWARF_WITH_LIBELF
    DWARF_DBG_ERROR(NULL, DW_DLE_NO_ELF_SUPPORT, DW_DLV_ERROR);
#else /* DWARF_WITH_LIBELF */
    Dwarf_Obj_Access_Interface *binary_interface = 0;
    int res = DW_DLV_OK;
    int localerrnum = 0;
    int libdwarf_owns_elf = FALSE;

    if (!ret_dbg) {
        DWARF_DBG_ERROR(NULL,DW_DLE_DWARF_INIT_DBG_NULL,DW_DLV_ERROR);
    }
    if (access != DW_DLC_READ) {
        DWARF_DBG_ERROR(NULL, DW_DLE_INIT_ACCESS_WRONG, DW_DLV_ERROR);
    }

    /* This allocates and fills in *binary_interface. */
    res = dwarf_elf_object_access_init(
        elf_file_pointer,
        libdwarf_owns_elf,
        &binary_interface,
        &localerrnum);
    if (res != DW_DLV_OK) {
        if (res == DW_DLV_NO_ENTRY) {
            return res;
        }
        DWARF_DBG_ERROR(NULL, localerrnum, DW_DLV_ERROR);
    }
    /* allocates and initializes Dwarf_Debug */
    res = dwarf_object_init_b(binary_interface, errhand, errarg,
        group_number,
        ret_dbg, error);
    if (res != DW_DLV_OK){
        dwarf_elf_object_access_finish(binary_interface);
        return res;
    }
    res = dwarf_add_debuglink_global_path(*ret_dbg,
        "/usr/lib/debug",error);
    if (res != DW_DLV_OK){
        dwarf_elf_object_access_finish(binary_interface);
        return res;
    }
    /* DBG known */
    return res;
#endif /* DWARF_WITH_LIBELF */
}

int
dwarf_elf_init(
#ifndef DWARF_WITH_LIBELF
    UNUSEDARG dwarf_elf_handle elf_file_pointer,
    UNUSEDARG Dwarf_Unsigned access,
    UNUSEDARG Dwarf_Handler errhand,
    UNUSEDARG Dwarf_Ptr errarg,
    UNUSEDARG Dwarf_Debug * ret_dbg,
#else
    dwarf_elf_handle elf_file_pointer,
    Dwarf_Unsigned access,
    Dwarf_Handler errhand,
    Dwarf_Ptr errarg,
    Dwarf_Debug * ret_dbg,
#endif
    Dwarf_Error * error)
{
#ifndef DWARF_WITH_LIBELF
    DWARF_DBG_ERROR(NULL, DW_DLE_NO_ELF_SUPPORT, DW_DLV_ERROR);
#else /* DWARF_WITH_LIBELF */
    int res = 0;
    res = dwarf_elf_init_b(elf_file_pointer,
        DW_GROUPNUMBER_ANY,
        access,errhand,errarg,ret_dbg,error);
    return res;
#endif /* DWARF_WITH_LIBELF */
}

int
_dwarf_elf_setup(
#ifndef  DWARF_WITH_LIBELF
    UNUSEDARG int fd,
    UNUSEDARG char *path,
    UNUSEDARG unsigned ftype,
    UNUSEDARG unsigned endian,
    UNUSEDARG unsigned offsetsize,
    UNUSEDARG size_t filesize,
    UNUSEDARG Dwarf_Unsigned access,
    UNUSEDARG unsigned groupnumber,
    UNUSEDARG Dwarf_Handler errhand,
    UNUSEDARG Dwarf_Ptr errarg,
    UNUSEDARG Dwarf_Debug *dbg,
#else
    int fd,
    UNUSEDARG char *path,
    UNUSEDARG unsigned ftype,
    UNUSEDARG unsigned endian,
    UNUSEDARG unsigned offsetsize,
    size_t filesize,
    UNUSEDARG Dwarf_Unsigned access,
    unsigned groupnumber,
    Dwarf_Handler errhand,
    Dwarf_Ptr errarg,
    Dwarf_Debug *dbg,
#endif /* DWARF_WITH_LIBELF */
    Dwarf_Error *error)
{
#ifndef DWARF_WITH_LIBELF
    DWARF_DBG_ERROR(NULL, DW_DLE_PRODUCER_CODE_NOT_AVAILABLE, DW_DLV_ERROR);
#else /* DWARF_WITH_LIBELF */
    Elf_Cmd what_kind_of_elf_read = ELF_C_READ;
    Dwarf_Obj_Access_Interface *binary_interface = 0;
    int res = DW_DLV_OK;
    int localerrnum = 0;
    int libdwarf_owns_elf = TRUE;
    dwarf_elf_handle elf_file_pointer = 0;

    elf_version(EV_CURRENT);
    elf_file_pointer = elf_begin(fd, what_kind_of_elf_read, 0);
    if (elf_file_pointer == NULL) {
        DWARF_DBG_ERROR(NULL, DW_DLE_ELF_BEGIN_ERROR, DW_DLV_ERROR);
    }
    /* Sets up elf access function pointers. */
    res = dwarf_elf_object_access_init(
        elf_file_pointer,
        libdwarf_owns_elf,
        &binary_interface,
        &localerrnum);
    if (res != DW_DLV_OK) {
        if (res == DW_DLV_NO_ENTRY) {
            return res;
        }
        DWARF_DBG_ERROR(NULL, localerrnum, DW_DLV_ERROR);
    }
    /* allocates and initializes Dwarf_Debug */
    res = dwarf_object_init_b(binary_interface, errhand, errarg,
        groupnumber,
        dbg, error);
    if (res != DW_DLV_OK){
        dwarf_elf_object_access_finish(binary_interface);
        return res;
    }
    (*dbg)->de_filesize = filesize;
    res = dwarf_add_debuglink_global_path(*dbg,
        "/usr/lib/debug",error);
    if (res != DW_DLV_OK){
        dwarf_elf_object_access_finish(binary_interface);
    }
    return res;
#endif /* DWARF_WITH_LIBELF */
}
