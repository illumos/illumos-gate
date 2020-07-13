/*
  Copyright (C) 2000-2006 Silicon Graphics, Inc.  All Rights Reserved.
  Portions Copyright 2007-2010 Sun Microsystems, Inc. All rights reserved.
  Portions Copyright 2008-2010 Arxan Technologies, Inc. All rights reserved.
  Portions Copyright 2011-2019 David Anderson. All rights reserved.
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif /* HAVE_STDLIB_H */
#ifdef HAVE_MALLOC_H
/* Useful include for some Windows compilers. */
#include <malloc.h>
#endif /* HAVE_MALLOC_H */
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#elif defined(_WIN32) && defined(_MSC_VER)
#include <io.h>
#endif /* HAVE_UNISTD_H */

#include "dwarf_incl.h"
#include "dwarf_error.h"
#include "dwarf_object_detector.h"
#include "dwarf_elf_access.h" /* Needed while libelf in use */

#ifndef O_BINARY
#define O_BINARY 0
#endif /* O_BINARY */

/*  This is the initialization set intended to
    handle multiple object formats.
    Created September 2018

    The init functions here cannot process archives.
    For archives the libelf-only dwarf_elf_init*()
    functions are used if present, else archives
    cannot be read.
*/


#define DWARF_DBG_ERROR(dbg,errval,retval) \
    _dwarf_error(dbg, error, errval); return(retval);


#define FALSE  0
#define TRUE   1
/*  An original basic dwarf initializer function for consumers.
    Return a libdwarf error code on error, return DW_DLV_OK
    if this succeeds.
    dwarf_init_b() is a better choice where there
    are section groups in an object file. */
int
dwarf_init(int fd,
    Dwarf_Unsigned access,
    Dwarf_Handler errhand,
    Dwarf_Ptr errarg, Dwarf_Debug * ret_dbg, Dwarf_Error * error)
{
    return dwarf_init_b(fd,access, DW_GROUPNUMBER_ANY,
        errhand,errarg,ret_dbg,error);
}

static int
open_a_file(const char * name)
{
    /* Set to a file number that cannot be legal. */
    int fd = -1;

#if HAVE_ELF_OPEN
    /*  It is not possible to share file handles
        between applications or DLLs. Each application has its own
        file-handle table. For two applications to use the same file
        using a DLL, they must both open the file individually.
        Let the 'libelf' dll open and close the file.  */
    fd = elf_open(name, O_RDONLY | O_BINARY);
#else
    fd = open(name, O_RDONLY | O_BINARY);
#endif
    return fd;
}

static int
set_global_paths_init(Dwarf_Debug dbg, Dwarf_Error* error)
{
    int res = 0;

    res = dwarf_add_debuglink_global_path(dbg,
        "/usr/lib/debug",error);
    return res;
}

/* New in December 2018. */
int dwarf_init_path(const char *path,
    char *true_path_out_buffer,
    unsigned true_path_bufferlen,
    Dwarf_Unsigned    access,
    unsigned          groupnumber,
    Dwarf_Handler     errhand,
    Dwarf_Ptr         errarg,
    Dwarf_Debug*      ret_dbg,
    UNUSEDARG const char *       reserved1,
    UNUSEDARG Dwarf_Unsigned     reserved2,
    UNUSEDARG Dwarf_Unsigned  *  reserved3,
    Dwarf_Error*      error)
{
    unsigned       ftype = 0;
    unsigned       endian = 0;
    unsigned       offsetsize = 0;
    Dwarf_Unsigned filesize = 0;
    int res = 0;
    int errcode = 0;
    int fd = -1;
    Dwarf_Debug dbg = 0;
    char *file_path = 0;

    if (!ret_dbg) {
        DWARF_DBG_ERROR(NULL,DW_DLE_DWARF_INIT_DBG_NULL,DW_DLV_ERROR);
    }
    res = dwarf_object_detector_path(path,
        true_path_out_buffer,
        true_path_bufferlen,
        &ftype,&endian,&offsetsize,&filesize,&errcode);
    if (res == DW_DLV_NO_ENTRY) {
        return res;
    }
    if (res == DW_DLV_ERROR) {
        DWARF_DBG_ERROR(NULL, errcode, DW_DLV_ERROR);
    }
    if (true_path_out_buffer) {
        file_path = true_path_out_buffer;
        fd = open_a_file(true_path_out_buffer);
    } else {
        file_path = (char *)path;
        fd = open_a_file(path);
    }
    if(fd == -1) {
        DWARF_DBG_ERROR(NULL, DW_DLE_FILE_UNAVAILABLE,
            DW_DLV_ERROR);
    }
    switch(ftype) {
    case DW_FTYPE_ELF: {
        res = _dwarf_elf_nlsetup(fd,
            file_path,
            ftype,endian,offsetsize,filesize,
            access,groupnumber,errhand,errarg,&dbg,error);
        if (res != DW_DLV_OK) {
            *ret_dbg = dbg;
            close(fd);
            return res;
        }
        dbg->de_path = strdup(file_path);
        dbg->de_fd = fd;
        dbg->de_owns_fd = TRUE;
        res = set_global_paths_init(dbg,error);
        *ret_dbg = dbg;
        return res;
    }
    case DW_FTYPE_MACH_O: {
        res = _dwarf_macho_setup(fd,
            file_path,
            ftype,endian,offsetsize,filesize,
            access,groupnumber,errhand,errarg,&dbg,error);
        if (res != DW_DLV_OK) {
            close(fd);
            *ret_dbg = dbg;
            return res;
        }
        dbg->de_path = strdup(file_path);
        dbg->de_fd = fd;
        dbg->de_owns_fd = TRUE;
        set_global_paths_init(dbg,error);
        *ret_dbg = dbg;
        return res;
    }
    case DW_FTYPE_PE: {
        res = _dwarf_pe_setup(fd,
            file_path,
            ftype,endian,offsetsize,filesize,
            access,groupnumber,errhand,errarg,&dbg,error);
        if (res != DW_DLV_OK) {
            close(fd);
            *ret_dbg = dbg;
        }
        dbg->de_path = strdup(file_path);
        dbg->de_fd = fd;
        dbg->de_owns_fd = TRUE;
        set_global_paths_init(dbg,error);
        *ret_dbg = dbg;
        return res;
    }
    default:
        close(fd);
        DWARF_DBG_ERROR(NULL, DW_DLE_FILE_WRONG_TYPE, DW_DLV_ERROR);
    }
    return DW_DLV_NO_ENTRY; /* placeholder for now */
}


/*  New March 2017, this provides for reading
    object files with multiple elf section groups.  */
int
dwarf_init_b(int fd,
    Dwarf_Unsigned access,
    unsigned  group_number,
    Dwarf_Handler errhand,
    Dwarf_Ptr errarg,
    Dwarf_Debug * ret_dbg,
    Dwarf_Error * error)
{
    unsigned ftype = 0;
    unsigned endian = 0;
    unsigned offsetsize = 0;
    Dwarf_Unsigned   filesize = 0;
    int res = 0;
    int errcode = 0;

    if (!ret_dbg) {
        DWARF_DBG_ERROR(NULL,DW_DLE_DWARF_INIT_DBG_NULL,DW_DLV_ERROR);
    }
    res = dwarf_object_detector_fd(fd, &ftype,
        &endian,&offsetsize,&filesize,&errcode);
    if (res == DW_DLV_NO_ENTRY) {
        return res;
    } else if (res == DW_DLV_ERROR) {
        DWARF_DBG_ERROR(NULL, DW_DLE_FILE_WRONG_TYPE, DW_DLV_ERROR);
    }

    switch(ftype) {
    case DW_FTYPE_ELF: {
        int res2 = 0;

        res2 = _dwarf_elf_nlsetup(fd,"",
            ftype,endian,offsetsize,filesize,
            access,group_number,errhand,errarg,ret_dbg,error);
        if (res2 != DW_DLV_OK) {
            return res2;
        }
        set_global_paths_init(*ret_dbg,error);
        return res2;
        }
    case DW_FTYPE_MACH_O: {
        int resm = 0;

        resm = _dwarf_macho_setup(fd,"",
            ftype,endian,offsetsize,filesize,
            access,group_number,errhand,errarg,ret_dbg,error);
        if (resm != DW_DLV_OK) {
            return resm;
        }
        set_global_paths_init(*ret_dbg,error);
        return resm;
        }

    case DW_FTYPE_PE: {
        int resp = 0;

        resp = _dwarf_pe_setup(fd,
            "",
            ftype,endian,offsetsize,filesize,
            access,group_number,errhand,errarg,ret_dbg,error);
        if (resp != DW_DLV_OK) {
            return resp;
        }
        set_global_paths_init(*ret_dbg,error);
        return resp;
        }
    }
    DWARF_DBG_ERROR(NULL, DW_DLE_FILE_WRONG_TYPE, DW_DLV_ERROR);
    return res;
}

/*
    Frees all memory that was not previously freed
    by dwarf_dealloc.
    Aside from certain categories.

    Applicable when dwarf_init() or dwarf_elf_init()
    or the -b() form was used to init 'dbg'.
*/
int
dwarf_finish(Dwarf_Debug dbg, Dwarf_Error * error)
{
    if(!dbg) {
        DWARF_DBG_ERROR(NULL, DW_DLE_DBG_NULL, DW_DLV_ERROR);
    }
    if (dbg->de_obj_file) {
        /*  The initial character of a valid
            dbg->de_obj_file->object struct is a letter:
            E, F, M, or P */
        char otype  = *(char *)(dbg->de_obj_file->object);

        switch(otype) {
        case 'E':
#ifdef DWARF_WITH_LIBELF
            dwarf_elf_object_access_finish(dbg->de_obj_file);
#endif /* DWARF_WITH_LIBELF */
            break;
        case 'F':
            /* Non-libelf elf access */
            _dwarf_destruct_elf_nlaccess(dbg->de_obj_file);
            break;
        case 'M':
            _dwarf_destruct_macho_access(dbg->de_obj_file);
            break;
        case 'P':
            _dwarf_destruct_pe_access(dbg->de_obj_file);
            break;
        default:
            /*  Do nothing. A serious internal error */
            break;
        }
    }
    if (dbg->de_owns_fd) {
        close(dbg->de_fd);
        dbg->de_owns_fd = FALSE;
    }
    free((void *)dbg->de_path);
    dbg->de_path = 0;
    /*  dwarf_object_finish() also frees de_path,
        but that is safe because we set it to zero
        here so no duplicate free will occur.
        Not all code uses libdwarf exactly as we do
        hence the free() there. */
    return dwarf_object_finish(dbg, error);
}

/*
    tieddbg should be the executable or .o
    that has the .debug_addr section that
    the base dbg refers to. See Split Objects in DWARF5.

    Allows setting to NULL (NULL is the default
    of  de_tied_data.td_tied_object).
    New September 2015.
*/
int
dwarf_set_tied_dbg(Dwarf_Debug dbg, Dwarf_Debug tieddbg,Dwarf_Error*error)
{
    if(!dbg) {
        DWARF_DBG_ERROR(NULL, DW_DLE_DBG_NULL, DW_DLV_ERROR);
    }
    dbg->de_tied_data.td_tied_object = tieddbg;
    if (tieddbg) {
        tieddbg->de_tied_data.td_is_tied_object = TRUE;
    }
    return DW_DLV_OK;
}

/*  Unsure of the use-case of this.
    New September 2015. */
int
dwarf_get_tied_dbg(Dwarf_Debug dbg, Dwarf_Debug *tieddbg_out,
    UNUSEDARG Dwarf_Error*error)
{
    *tieddbg_out = dbg->de_tied_data.td_tied_object;
    return DW_DLV_OK;
}
