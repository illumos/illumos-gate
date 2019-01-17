/*

  Copyright (C) 2000,2001,2002,2005,2006 Silicon Graphics, Inc.  All Rights Reserved.
  Portions Copyright 2007-2010 Sun Microsystems, Inc. All rights reserved.
  Portions Copyright 2008-2010 Arxan Technologies, Inc. All rights reserved.

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

  Contact information:  Silicon Graphics, Inc., 1500 Crittenden Lane,
  Mountain View, CA 94043, or:

  http://www.sgi.com

  For further information regarding this notice, see:

  http://oss.sgi.com/projects/GenInfo/NoticeExplan

*/


#include "config.h"
#include "dwarf_incl.h"
#include "dwarf_elf_access.h"

#ifdef HAVE_ELF_H
#include <elf.h>
#endif
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
#include <stdlib.h>

#define DWARF_DBG_ERROR(dbg,errval,retval) \
     _dwarf_error(dbg, error, errval); return(retval);

#define FALSE  0
#define TRUE   1

static int
dwarf_elf_init_file_ownership(dwarf_elf_handle elf_file_pointer,
                              int libdwarf_owns_elf,
                              Dwarf_Unsigned access,
                              Dwarf_Handler errhand,
                              Dwarf_Ptr errarg,
                              Dwarf_Debug * ret_dbg,
                              Dwarf_Error * error);


/*
    The basic dwarf initializer function for consumers using
    libelf. 
    Return a libdwarf error code on error, return DW_DLV_OK
    if this succeeds.
*/
int
dwarf_init(int fd,
    Dwarf_Unsigned access,
    Dwarf_Handler errhand,
    Dwarf_Ptr errarg, Dwarf_Debug * ret_dbg, Dwarf_Error * error)
{
    struct stat fstat_buf;
    dwarf_elf_handle elf_file_pointer = 0;
    /* ELF_C_READ is a portable value */
    Elf_Cmd what_kind_of_elf_read = ELF_C_READ;

#if !defined(S_ISREG)
#define S_ISREG(mode) (((mode) & S_IFMT) == S_IFREG)
#endif
    if (fstat(fd, &fstat_buf) != 0) {
        DWARF_DBG_ERROR(NULL, DW_DLE_FSTAT_ERROR, DW_DLV_ERROR);
    }
    if (!S_ISREG(fstat_buf.st_mode)) {
        DWARF_DBG_ERROR(NULL, DW_DLE_FSTAT_MODE_ERROR, DW_DLV_ERROR);
    }

    if (access != DW_DLC_READ) {
        DWARF_DBG_ERROR(NULL, DW_DLE_INIT_ACCESS_WRONG, DW_DLV_ERROR);
    }

    elf_version(EV_CURRENT);
    /* changed to mmap request per bug 281217. 6/95 */
#ifdef HAVE_ELF_C_READ_MMAP
    /* ELF_C_READ_MMAP is an SGI IRIX specific enum value from IRIX
       libelf.h meaning read but use mmap */
    what_kind_of_elf_read = ELF_C_READ_MMAP;
#endif /* !HAVE_ELF_C_READ_MMAP */

    elf_file_pointer = elf_begin(fd, what_kind_of_elf_read, 0);
    if (elf_file_pointer == NULL) {
        DWARF_DBG_ERROR(NULL, DW_DLE_ELF_BEGIN_ERROR, DW_DLV_ERROR);
    }

    return dwarf_elf_init_file_ownership(elf_file_pointer, 
                                         TRUE, 
                                         access, 
                                         errhand, 
                                         errarg, 
                                         ret_dbg, 
                                         error);
}

/*
    An alternate dwarf setup call for consumers using
    libelf.
    When the caller has opened libelf already, so the
    caller must free libelf.
*/
int
dwarf_elf_init(dwarf_elf_handle elf_file_pointer,
    Dwarf_Unsigned access,
    Dwarf_Handler errhand,
    Dwarf_Ptr errarg,
    Dwarf_Debug * ret_dbg, Dwarf_Error * error)
{
  return dwarf_elf_init_file_ownership(elf_file_pointer, 
                                       FALSE, 
                                       access, 
                                       errhand, 
                                       errarg, 
                                       ret_dbg, 
                                       error);
}


/*
    Initialize the ELF object access for libdwarf.
 */
static int 
dwarf_elf_init_file_ownership(dwarf_elf_handle elf_file_pointer, 
                              int libdwarf_owns_elf, 
                              Dwarf_Unsigned access, 
                              Dwarf_Handler errhand, 
                              Dwarf_Ptr errarg, 
                              Dwarf_Debug * ret_dbg, 
                              Dwarf_Error * error)
{
    /* ELF is no longer tied to libdwarf. */
    Dwarf_Obj_Access_Interface *binary_interface = 0;
    int res = DW_DLV_OK;
    int err = 0;

    if (access != DW_DLC_READ) {
        DWARF_DBG_ERROR(NULL, DW_DLE_INIT_ACCESS_WRONG, DW_DLV_ERROR);
    }
   
    /* This allocates and fills in *binary_interface. */
    res = dwarf_elf_object_access_init(
        elf_file_pointer, 
        libdwarf_owns_elf,
        &binary_interface,
        &err);
    if(res != DW_DLV_OK){
        DWARF_DBG_ERROR(NULL, err, DW_DLV_ERROR);
    }

    /* This mallocs space and returns pointer thru ret_dbg, 
       saving  the binary interface in 'ret-dbg' */
    res = dwarf_object_init(binary_interface, errhand, errarg, 
                         ret_dbg, error);
    if(res != DW_DLV_OK){
        dwarf_elf_object_access_finish(binary_interface);
    }
    return res;
}


/*
    Frees all memory that was not previously freed
    by dwarf_dealloc.
    Aside from certain categories.

    This is only applicable when dwarf_init() or dwarf_elf_init()
    was used to init 'dbg'.
*/
int
dwarf_finish(Dwarf_Debug dbg, Dwarf_Error * error)
{
    dwarf_elf_object_access_finish(dbg->de_obj_file);

    return dwarf_object_finish(dbg, error);
}

