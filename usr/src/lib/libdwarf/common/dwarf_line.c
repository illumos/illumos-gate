/*
   Copyright (C) 2000-2006 Silicon Graphics, Inc.  All Rights Reserved.
   Portions Copyright (C) 2007-2019 David Anderson. All Rights Reserved.
   Portions Copyright (C) 2010-2012 SN Systems Ltd. All Rights Reserved.
   Portions Copyright (C) 2015-2015 Google, Inc. All Rights Reserved.

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
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif /* HAVE_STDLIB_H */
#include "dwarf_incl.h"
#include "dwarf_alloc.h"
#include "dwarf_error.h"
#include "dwarf_util.h"
#include "dwarf_line.h"
#include "dwarfstring.h"

/* Line Register Set initial conditions. */
static struct Dwarf_Line_Registers_s _dwarf_line_table_regs_default_values = {
    /* Dwarf_Addr lr_address */ 0,
    /* Dwarf_Unsigned lr_file */ 1,
    /* Dwarf_Unsigned lr_line */  1,
    /* Dwarf_Unsigned lr_column */  0,
    /* Dwarf_Bool lr_is_stmt */  false,
    /* Dwarf_Bool lr_basic_block */  false,
    /* Dwarf_Bool lr_end_sequence */  false,
    /* Dwarf_Bool lr_prologue_end */  false,
    /* Dwarf_Bool lr_epilogue_begin */  false,
    /* Dwarf_Small lr_isa */  0,
    /* Dwarf_Unsigned lr_op_index  */  0,
    /* Dwarf_Unsigned lr_discriminator */  0,
    /* Dwarf_Unsigned lr_call_context */  0,
    /* Dwarf_Unsigned lr_subprogram */  0,
};

void
_dwarf_set_line_table_regs_default_values(Dwarf_Line_Registers regs,
    unsigned lineversion,
    Dwarf_Bool is_stmt)
{
    *regs = _dwarf_line_table_regs_default_values;
    if (lineversion == DW_LINE_VERSION5) {
        /* DWARF5 file base is zero. */
        regs->lr_file = 0;
    }
    regs->lr_is_stmt = is_stmt;
}


static int
is_path_separator(Dwarf_Small s)
{
    if (s == '/') {
        return 1;
    }
#ifdef HAVE_WINDOWS_PATH
    if (s == '\\') {
        return 1;
    }
#endif
    return 0;
}

/*  Return 0 if false, 1 if true.
    If HAVE_WINDOWS_PATH is defined we
    attempt to handle windows full paths:
    \\something   or  C:cwdpath.c
*/
int
_dwarf_file_name_is_full_path(Dwarf_Small  *fname)
{
    Dwarf_Small firstc = *fname;
    if (is_path_separator(firstc)) {
        /* Full path. */
        return 1;
    }
    if (!firstc) {
        return 0;
    }
/*  This is a windows path test, but we do have
    a few windows paths in our regression tests...
    This is extremely unlikely to cause UN*X/POSIX
    users any problems. */
    if ((firstc >= 'A' && firstc <= 'Z') ||
        (firstc >= 'a' && firstc <= 'z')) {

        Dwarf_Small secondc = fname[1];
        if (secondc == ':') {
            return 1;
        }
    }
/* End Windows style */
    return 0;
}
#include "dwarf_line_table_reader_common.h"

static void
special_cat(char *dst,char *src,
    UNUSEDARG int srclen)
{
#if defined (HAVE_WINDOWS_PATH)
    /*  Always '/' instead of '\\', this is a Windows -> Unix
        issue. */
    int i1 = 0;
    int i2 = 0;

    for ( ; dst[i1] ; ++i1) {
    }
    for (; i2 < srclen; ++i2,++i1) {
        dst[i1] = src[i2];
        if (dst[i1] == '\\') {
            dst[i1] = '/';
        }
    }
#else
    strcat(dst, src);
#endif /* HAVE_WINDOWS_PATH */
    return;
}

/*  With this routine we ensure the file full path
    is calculated identically for
    dwarf_srcfiles() and dwarf_filename()

    As of March 14 2020 this *always*
    does an allocation for the string. dwarf_dealloc
    is crucial to do no matter what.
    So we have consistency.

    dwarf_finish() will do the dealloc if nothing else does.
    Unless the calling application did the call
    dwarf_set_de_alloc_flag(0).
*/
static int
create_fullest_file_path(Dwarf_Debug dbg,
    Dwarf_File_Entry fe,
    Dwarf_Line_Context line_context,
    char ** name_ptr_out,
    Dwarf_Error *error)
{
    Dwarf_Unsigned dirno = 0;
    char *full_name = 0;
    char *file_name = 0;

    dirno = fe->fi_dir_index;
    file_name = (char *) fe->fi_file_name;
    if (!file_name) {
        _dwarf_error(dbg, error, DW_DLE_NO_FILE_NAME);
        return (DW_DLV_ERROR);
    }
    if (_dwarf_file_name_is_full_path((Dwarf_Small *)file_name)) {
        {   unsigned len = strlen(file_name);
            char *tmp = (char *) _dwarf_get_alloc(dbg, DW_DLA_STRING,
                len+1);
            if(tmp) {
                tmp[0] = 0;
                special_cat(tmp,file_name,len);
                *name_ptr_out = tmp;
                return DW_DLV_OK;
            }
            _dwarf_error(dbg,error,DW_DLE_ALLOC_FAIL);
            return DW_DLV_ERROR;
        }
    } else {
        char *comp_dir_name = "";
        char *inc_dir_name = "";
        Dwarf_Unsigned incdirnamelen = 0;
        Dwarf_Unsigned filenamelen = strlen(file_name);
        Dwarf_Unsigned compdirnamelen = 0;

        if (line_context->lc_compilation_directory) {
            comp_dir_name =
                (char *)line_context->lc_compilation_directory;
            compdirnamelen = strlen(comp_dir_name);
        }

        if (dirno > line_context->lc_include_directories_count) {
            _dwarf_error(dbg, error, DW_DLE_INCL_DIR_NUM_BAD);
            return (DW_DLV_ERROR);
        }
        if (dirno > 0 && fe->fi_dir_index > 0) {
            inc_dir_name = (char *) line_context->lc_include_directories[
                fe->fi_dir_index - 1];
            if (!inc_dir_name) {
                /*  This should never ever happen except in case
                    of a corrupted object file. */
                inc_dir_name = "<erroneous NULL include dir pointer>";
            }
            incdirnamelen = strlen(inc_dir_name);
        }
        full_name = (char *) _dwarf_get_alloc(dbg, DW_DLA_STRING,
            compdirnamelen + 1 +
            incdirnamelen + 1 +
            filenamelen + 1);
        if (full_name == NULL) {
            _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
            return (DW_DLV_ERROR);
        }
        if (fe->fi_dir_index == 0) {
            /*  Just use comp dir name */
            if (compdirnamelen > 0) {
                special_cat(full_name,comp_dir_name,compdirnamelen);
                strcat(full_name, "/");
            }
            special_cat(full_name,file_name,filenamelen);
            *name_ptr_out =  full_name;
            return DW_DLV_OK;
        }
        if (incdirnamelen > 0 &&
            _dwarf_file_name_is_full_path((Dwarf_Small*)inc_dir_name) ) {
            /*  Just use inc dir. */
            special_cat(full_name,inc_dir_name,incdirnamelen);
            strcat(full_name,"/");
            special_cat(full_name,file_name,filenamelen);
            *name_ptr_out = full_name;
            return DW_DLV_OK;
        }
        /* Concat all three names. */
        if (compdirnamelen > 0) {
            special_cat(full_name,comp_dir_name,compdirnamelen);
            strcat(full_name, "/");
        }
        if (incdirnamelen > 0) {
            special_cat(full_name,inc_dir_name,incdirnamelen);
            strcat(full_name, "/");
        }
        special_cat(full_name,file_name,filenamelen);
    }
    *name_ptr_out = full_name;
    return DW_DLV_OK;
}

/*  Although source files is supposed to return the
    source files in the compilation-unit, it does
    not look for any in the statement program.  In
    other words, it ignores those defined using the
    extended opcode DW_LNE_define_file.
    We do not know of a producer that uses DW_LNE_define_file.

    In DWARF2,3,4 the array of sourcefiles is represented
    differently than DWARF5.
    DWARF 2,3,4,:
        Take the line number from macro information or lines data
        and subtract 1 to  index into srcfiles.  Any with line
        number zero can be assumed to refer to DW_AT_name from the
        CU DIE, but zero really means "no file".
    DWARF 5:
        Just like DW4, but  index 1 refers to the
        same string as DW_AT_name of the CU DIE.
*/
int
dwarf_srcfiles(Dwarf_Die die,
    char ***srcfiles,
    Dwarf_Signed * srcfilecount, Dwarf_Error * error)
{
    /*  This pointer is used to scan the portion of the .debug_line
        section for the current cu. */
    Dwarf_Small *line_ptr = 0;

    /*  Pointer to a DW_AT_stmt_list attribute in case it exists in the
        die. */
    Dwarf_Attribute stmt_list_attr = 0;

    const char * const_comp_name = 0;
    /*  Pointer to name of compilation directory. */
    const char * const_comp_dir = 0;
    Dwarf_Small *comp_dir = 0;

    /*  Offset into .debug_line specified by a DW_AT_stmt_list
        attribute. */
    Dwarf_Unsigned line_offset = 0;

    /*  This points to a block of char *'s, each of which points to a
        file name. */
    char **ret_files = 0;

    /*  The Dwarf_Debug this die belongs to. */
    Dwarf_Debug dbg = 0;
    Dwarf_CU_Context context = 0;
    Dwarf_Line_Context  line_context = 0;

    /*  Used to chain the file names. */
    Dwarf_Chain curr_chain = NULL;
    Dwarf_Chain prev_chain = NULL;
    Dwarf_Chain head_chain = NULL;

    Dwarf_Half attrform = 0;
    int resattr = DW_DLV_ERROR;
    int lres = DW_DLV_ERROR;
    unsigned i = 0;
    int res = DW_DLV_ERROR;
    Dwarf_Small *section_start = 0;

    /*  ***** BEGIN CODE ***** */
    /*  Reset error. */

    if (error != NULL) {
        *error = NULL;
    }

    CHECK_DIE(die, DW_DLV_ERROR);
    context = die->di_cu_context;
    dbg = context->cc_dbg;

    resattr = dwarf_attr(die, DW_AT_stmt_list, &stmt_list_attr, error);
    if (resattr != DW_DLV_OK) {
        return resattr;
    }

    if (dbg->de_debug_line.dss_index == 0) {
        dwarf_dealloc(dbg, stmt_list_attr, DW_DLA_ATTR);
        _dwarf_error(dbg, error, DW_DLE_DEBUG_LINE_NULL);
        return (DW_DLV_ERROR);
    }

    res = _dwarf_load_section(dbg, &dbg->de_debug_line,error);
    if (res != DW_DLV_OK) {
        dwarf_dealloc(dbg, stmt_list_attr, DW_DLA_ATTR);
        return res;
    }
    if (!dbg->de_debug_line.dss_size) {
        dwarf_dealloc(dbg, stmt_list_attr, DW_DLA_ATTR);
        return (DW_DLV_NO_ENTRY);
    }
    section_start = dbg->de_debug_line.dss_data;

    lres = dwarf_whatform(stmt_list_attr,&attrform,error);
    if (lres != DW_DLV_OK) {
        dwarf_dealloc(dbg, stmt_list_attr, DW_DLA_ATTR);
        return lres;
    }
    if (attrform != DW_FORM_data4 && attrform != DW_FORM_data8 &&
        attrform != DW_FORM_sec_offset  &&
        attrform != DW_FORM_GNU_ref_alt) {
        dwarfstring m;
        dwarfstring f;
        const char *formname = 0;

        dwarfstring_constructor(&f);
        dwarf_get_FORM_name(attrform,&formname);
        if (!formname) {
            dwarfstring_append_printf_u(&f,"Invalid Form Code "
                " 0x" DW_PR_DUx,attrform);
        } else {
            dwarfstring_append(&f,(char *)formname);
        }
        dwarf_dealloc(dbg, stmt_list_attr, DW_DLA_ATTR);
        dwarfstring_constructor(&m);
        dwarfstring_append_printf_s(&m,
            "DW_DLE_LINE_OFFSET_WRONG_FORM: form %s "
            "instead of an allowed section offset form.",
            dwarfstring_string(&f));
        _dwarf_error_string(dbg, error, DW_DLE_LINE_OFFSET_WRONG_FORM,
            dwarfstring_string(&m));
        dwarfstring_destructor(&m);
        dwarfstring_destructor(&f);
        return (DW_DLV_ERROR);
    }
    lres = dwarf_global_formref(stmt_list_attr, &line_offset, error);
    if (lres != DW_DLV_OK) {
        dwarf_dealloc(dbg, stmt_list_attr, DW_DLA_ATTR);
        return lres;
    }
    if (line_offset >= dbg->de_debug_line.dss_size) {
        dwarf_dealloc(dbg, stmt_list_attr, DW_DLA_ATTR);
        _dwarf_error(dbg, error, DW_DLE_LINE_OFFSET_BAD);
        return (DW_DLV_ERROR);
    }
    line_ptr = dbg->de_debug_line.dss_data + line_offset;
    {
        Dwarf_Unsigned fission_offset = 0;
        Dwarf_Unsigned fission_size = 0;
        int resl = _dwarf_get_fission_addition_die(die, DW_SECT_LINE,
            &fission_offset,&fission_size,error);
        if(resl != DW_DLV_OK) {
            dwarf_dealloc(dbg, stmt_list_attr, DW_DLA_ATTR);
            return resl;
        }
        line_ptr += fission_offset;
        if (line_ptr > dbg->de_debug_line.dss_data +
            dbg->de_debug_line.dss_size) {
            dwarf_dealloc(dbg, stmt_list_attr, DW_DLA_ATTR);
            _dwarf_error(dbg, error, DW_DLE_FISSION_ADDITION_ERROR);
            return DW_DLV_ERROR;
        }
    }
    dwarf_dealloc(dbg, stmt_list_attr, DW_DLA_ATTR);
    stmt_list_attr = 0;

    resattr = _dwarf_internal_get_die_comp_dir(die, &const_comp_dir,
        &const_comp_name,error);
    if (resattr == DW_DLV_ERROR) {
        return resattr;
    }

    /* Horrible cast away const to match historical interfaces. */
    comp_dir = (Dwarf_Small *)const_comp_dir;
    line_context = (Dwarf_Line_Context)
        _dwarf_get_alloc(dbg, DW_DLA_LINE_CONTEXT, 1);
    if (line_context == NULL) {
        _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return (DW_DLV_ERROR);
    }
    line_context->lc_new_style_access = false;
    /*  We are in dwarf_srcfiles() */
    {
        Dwarf_Small *line_ptr_out = 0;
        int dres = 0;

        dres = _dwarf_read_line_table_header(dbg,
            context,
            section_start,
            line_ptr,
            dbg->de_debug_line.dss_size,
            &line_ptr_out,
            line_context,
            NULL, NULL,error,
            0);

        if (dres == DW_DLV_ERROR) {
            dwarf_dealloc(dbg, line_context, DW_DLA_LINE_CONTEXT);
            line_context = 0;
            return dres;
        }
        if (dres == DW_DLV_NO_ENTRY) {
            dwarf_dealloc(dbg, line_context, DW_DLA_LINE_CONTEXT);
            line_context = 0;
            return dres;
        }
    }
    /*  For DWARF5, use of DW_AT_comp_dir not needed.
        Line table file names and directories
        start with comp_dir and name.  FIXME DWARF5 */
    line_context->lc_compilation_directory = comp_dir;
    /* We are in dwarf_srcfiles() */
    {
        Dwarf_File_Entry fe = 0;
        Dwarf_File_Entry fe2 =line_context->lc_file_entries;
        Dwarf_Signed baseindex = 0;
        Dwarf_Signed file_count = 0;
        Dwarf_Signed endindex = 0;

        res =  dwarf_srclines_files_indexes(line_context, &baseindex,
            &file_count, &endindex, error);
        if (res != DW_DLV_OK) {
            return res;
        }
        for (i = baseindex; i < endindex; ++i,fe2 = fe->fi_next ) {
            int sres = 0;
            char *name_out = 0;

            fe = fe2;
            sres = create_fullest_file_path(dbg,fe,line_context,
                &name_out,error);
            if (sres != DW_DLV_OK) {
                dwarf_dealloc(dbg, line_context, DW_DLA_LINE_CONTEXT);
                /* This can leak some strings */
                return sres;
            }
            curr_chain =
                (Dwarf_Chain) _dwarf_get_alloc(dbg, DW_DLA_CHAIN, 1);
            if (curr_chain == NULL) {
                dwarf_dealloc(dbg, line_context, DW_DLA_LINE_CONTEXT);
                _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
                return (DW_DLV_ERROR);
            }
            curr_chain->ch_item = name_out;
            if (head_chain == NULL) {
                head_chain = prev_chain = curr_chain;
            } else {
                prev_chain->ch_next = curr_chain;
                prev_chain = curr_chain;
            }
        }
    }
    if (!head_chain) {
        dwarf_dealloc(dbg, line_context, DW_DLA_LINE_CONTEXT);
        *srcfiles = NULL;
        *srcfilecount = 0;
        return DW_DLV_NO_ENTRY;
    }

    /* We are in dwarf_srcfiles() */
    if (line_context->lc_file_entry_count == 0) {
        dwarf_dealloc(dbg, line_context, DW_DLA_LINE_CONTEXT);
        *srcfiles = NULL;
        *srcfilecount = 0;
        return DW_DLV_NO_ENTRY;
    }

    ret_files = (char **)
        _dwarf_get_alloc(dbg, DW_DLA_LIST,
        line_context->lc_file_entry_count);
    if (ret_files == NULL) {
        dwarf_dealloc(dbg, line_context, DW_DLA_LINE_CONTEXT);
        _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return (DW_DLV_ERROR);
    }

    curr_chain = head_chain;
    for (i = 0; i < line_context->lc_file_entry_count; i++) {
        *(ret_files + i) = curr_chain->ch_item;
        curr_chain->ch_item = 0;
        prev_chain = curr_chain;
        curr_chain = curr_chain->ch_next;
        dwarf_dealloc(dbg, prev_chain, DW_DLA_CHAIN);
    }
    /*  Our chain is not recorded in the line_context so
        the line_context destructor will not destroy our
        list of strings or our strings.
        Our caller has to do the deallocations.  */
    *srcfiles = ret_files;
    *srcfilecount = line_context->lc_file_entry_count;
    dwarf_dealloc(dbg, line_context, DW_DLA_LINE_CONTEXT);
    return (DW_DLV_OK);
}



/*  Return DW_DLV_OK if ok. else DW_DLV_NO_ENTRY or DW_DLV_ERROR
    doaddrs is true iff this is being called for SGI IRIX rqs processing
    (ie, not a normal libdwarf dwarf_srclines or two-level  user call at all).
    dolines is true iff this is called by a dwarf_srclines call.

    In case of error or NO_ENTRY in this code we use the
    dwarf_srcline_dealloc(line_context)
    and dealloc of DW_DLA_LINE_CONTEXT
    from the new interface for uniformity here.
*/

int
_dwarf_internal_srclines(Dwarf_Die die,
    Dwarf_Bool is_new_interface,
    Dwarf_Unsigned * version,
    Dwarf_Small    * table_count, /* returns 0,1, or 2 */
    Dwarf_Line_Context *line_context_out,
    Dwarf_Line ** linebuf,
    Dwarf_Signed * linecount,
    Dwarf_Line ** linebuf_actuals,
    Dwarf_Signed * linecount_actuals,
    Dwarf_Bool doaddrs,
    Dwarf_Bool dolines,
    Dwarf_Error * error)
{
    /*  This pointer is used to scan the portion of the .debug_line
        section for the current cu. */
    Dwarf_Small *line_ptr = 0;

    /*  This points to the last byte of the .debug_line portion for the
        current cu. */
    Dwarf_Small *line_ptr_end = 0;

    /*  For two-level line tables, this points to the first byte of the
        actuals table (and the end of the logicals table) for the current
        cu. */
    Dwarf_Small *line_ptr_actuals = 0;
    Dwarf_Small *section_start = 0;
    Dwarf_Small *section_end = 0;

    /*  Pointer to a DW_AT_stmt_list attribute in case it exists in the
        die. */
    Dwarf_Attribute stmt_list_attr = 0;

    const char * const_comp_name = 0;
    /*  Pointer to name of compilation directory. */
    const char * const_comp_dir = NULL;
    Dwarf_Small *comp_dir = NULL;

    /*  Offset into .debug_line specified by a DW_AT_stmt_list
        attribute. */
    Dwarf_Unsigned line_offset = 0;

    /*  Pointer to a Dwarf_Line_Context_s structure that contains the
        context such as file names and include directories for the set
        of lines being generated.
        This is always recorded on an
        DW_LNS_end_sequence operator,
        on  all special opcodes, and on DW_LNS_copy.
        */
    Dwarf_Line_Context line_context = 0;
    Dwarf_CU_Context   cu_context = 0;
    Dwarf_Unsigned fission_offset = 0;

    /*  The Dwarf_Debug this die belongs to. */
    Dwarf_Debug dbg = 0;
    int resattr = DW_DLV_ERROR;
    int lres = DW_DLV_ERROR;
    Dwarf_Half address_size = 0;
    Dwarf_Small * orig_line_ptr = 0;

    int res = DW_DLV_ERROR;

    /*  ***** BEGIN CODE ***** */
    if (error != NULL) {
        *error = NULL;
    }

    CHECK_DIE(die, DW_DLV_ERROR);
    cu_context = die->di_cu_context;
    dbg = cu_context->cc_dbg;

    res = _dwarf_load_section(dbg, &dbg->de_debug_line,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    if (!dbg->de_debug_line.dss_size) {
        return (DW_DLV_NO_ENTRY);
    }

    address_size = _dwarf_get_address_size(dbg, die);
    resattr = dwarf_attr(die, DW_AT_stmt_list, &stmt_list_attr, error);
    if (resattr != DW_DLV_OK) {
        return resattr;
    }
    lres = dwarf_global_formref(stmt_list_attr, &line_offset, error);
    if (lres != DW_DLV_OK) {
        dwarf_dealloc(dbg, stmt_list_attr, DW_DLA_ATTR);
        return lres;
    }

    if (line_offset >= dbg->de_debug_line.dss_size) {
        dwarf_dealloc(dbg, stmt_list_attr, DW_DLA_ATTR);
        _dwarf_error(dbg, error, DW_DLE_LINE_OFFSET_BAD);
        return (DW_DLV_ERROR);
    }
    section_start = dbg->de_debug_line.dss_data;
    section_end = section_start  +dbg->de_debug_line.dss_size;
    {
        Dwarf_Unsigned fission_size = 0;
        int resf = _dwarf_get_fission_addition_die(die, DW_SECT_LINE,
            &fission_offset,&fission_size,error);
        if(resf != DW_DLV_OK) {
            dwarf_dealloc(dbg, stmt_list_attr, DW_DLA_ATTR);
            return resf;
        }
        line_ptr += fission_offset;
        if (line_ptr > section_end) {
            _dwarf_error(dbg, error, DW_DLE_FISSION_ADDITION_ERROR);
            return DW_DLV_ERROR;
        }
    }

    section_start = dbg->de_debug_line.dss_data;
    section_end = section_start  +dbg->de_debug_line.dss_size;
    orig_line_ptr = section_start + line_offset + fission_offset;
    line_ptr = orig_line_ptr;
    dwarf_dealloc(dbg, stmt_list_attr, DW_DLA_ATTR);
    if ((line_offset + fission_offset) > dbg->de_debug_line.dss_size) {
        _dwarf_error(dbg, error, DW_DLE_LINE_OFFSET_BAD);
        return DW_DLV_ERROR;
    }
    if (line_ptr > section_end) {
        _dwarf_error(dbg, error, DW_DLE_LINE_OFFSET_BAD);
        return DW_DLV_ERROR;
    }

    /*  If die has DW_AT_comp_dir attribute, get the string that names
        the compilation directory. */
    resattr = _dwarf_internal_get_die_comp_dir(die, &const_comp_dir,
        &const_comp_name,error);
    if (resattr == DW_DLV_ERROR) {
        return resattr;
    }
    /* Horrible cast to match historic interfaces. */
    comp_dir = (Dwarf_Small *)const_comp_dir;
    line_context = (Dwarf_Line_Context)
        _dwarf_get_alloc(dbg, DW_DLA_LINE_CONTEXT, 1);
    if (line_context == NULL) {
        _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return (DW_DLV_ERROR);
    }
    line_context->lc_new_style_access = is_new_interface;
    line_context->lc_compilation_directory = comp_dir;
    /*  We are in dwarf_internal_srclines() */
    {
        Dwarf_Small *newlinep = 0;
        int resp = _dwarf_read_line_table_header(dbg,
            cu_context,
            section_start,
            line_ptr,
            dbg->de_debug_line.dss_size,
            &newlinep,
            line_context,
            NULL,NULL,
            error,
            0);

        if (resp == DW_DLV_ERROR) {
            if(is_new_interface) {
                dwarf_srclines_dealloc_b(line_context);
            } else {
                dwarf_dealloc(dbg,line_context,DW_DLA_LINE_CONTEXT);
            }
            return resp;
        }
        if (resp == DW_DLV_NO_ENTRY) {
            if(is_new_interface) {
                dwarf_srclines_dealloc_b(line_context);
            } else {
                dwarf_dealloc(dbg,line_context,DW_DLA_LINE_CONTEXT);
            }
            return resp;
        }
        line_ptr_end = line_context->lc_line_ptr_end;
        line_ptr = newlinep;
        if (line_context->lc_actuals_table_offset > 0) {
            line_ptr_actuals = line_context->lc_line_prologue_start +
                line_context->lc_actuals_table_offset;
        }
    }


    if (line_ptr_actuals == 0) {
        /* ASSERT: lc_table_count == 1 or lc_table_count == 0 */
        int err_count_out = 0;
        /* Normal style (single level) line table. */
        Dwarf_Bool is_actuals_table = false;
        Dwarf_Bool local_is_single_table = true;
        res = read_line_table_program(dbg,
            line_ptr, line_ptr_end, orig_line_ptr,
            section_start,
            line_context,
            address_size, doaddrs, dolines,
            local_is_single_table,
            is_actuals_table,
            error,
            &err_count_out);
        if (res != DW_DLV_OK) {
            if(is_new_interface) {
                dwarf_srclines_dealloc_b(line_context);
            } else {
                dwarf_dealloc(dbg,line_context,DW_DLA_LINE_CONTEXT);
            }
            return res;
        }
        if (linebuf)
            *linebuf = line_context->lc_linebuf_logicals;
        if (linecount)
            *linecount =  line_context->lc_linecount_logicals;
        if (linebuf_actuals) {
            *linebuf_actuals = NULL;
        }
        if (linecount_actuals) {
            *linecount_actuals = 0;
        }
    } else {
        Dwarf_Bool is_actuals_table = false;
        Dwarf_Bool local2_is_single_table = false;
        int err_count_out = 0;

        line_context->lc_is_single_table  = false;
        /*  Two-level line table.
            First read the logicals table. */
        res = read_line_table_program(dbg,
            line_ptr, line_ptr_actuals, orig_line_ptr,
            section_start,
            line_context,
            address_size, doaddrs, dolines,
            local2_is_single_table,
            is_actuals_table, error,
            &err_count_out);
        if (res != DW_DLV_OK) {
            if(is_new_interface) {
                dwarf_srclines_dealloc_b(line_context);
            } else {
                dwarf_dealloc(dbg,line_context,DW_DLA_LINE_CONTEXT);
            }
            return res;
        }
        if (linebuf) {
            *linebuf = line_context->lc_linebuf_logicals;
        } else {
        }
        if (linecount) {
            *linecount =  line_context->lc_linecount_logicals;
        }
        if (is_new_interface) {
            /* ASSERT: linebuf_actuals == NULL  */
            is_actuals_table = true;
            /* The call requested an actuals table
                and one is present. So now read that one. */
            res = read_line_table_program(dbg,

                line_ptr_actuals, line_ptr_end, orig_line_ptr,
                section_start,
                line_context,
                address_size, doaddrs, dolines,
                local2_is_single_table,
                is_actuals_table, error,
                &err_count_out);
            if (res != DW_DLV_OK) {
                dwarf_srclines_dealloc_b(line_context);
                return res;
            }
            if (linebuf_actuals) {
                *linebuf_actuals = line_context->lc_linebuf_actuals;
            }
            if (linecount_actuals != NULL) {
                *linecount_actuals = line_context->lc_linecount_actuals;
            }
        }
    }
    if (!is_new_interface && linecount &&
        (linecount == 0 ||*linecount == 0) &&
        (linecount_actuals == 0  || *linecount_actuals == 0)) {
        /*  Here we have no actual lines of any kind. In other words,
            it looks like a debugfission line table skeleton or
            a caller not prepared for skeletons or two-level reading..
            In that case there are no line entries so the context
            had nowhere to be recorded. Hence we have to delete it
            else we would leak the context.  */
        dwarf_dealloc(dbg, line_context, DW_DLA_LINE_CONTEXT);
        line_context = 0;
        return DW_DLV_OK;
    }
    *table_count = line_context->lc_table_count;
    if (version != NULL) {
        *version = line_context->lc_version_number;
    }
    *line_context_out = line_context;
    return (DW_DLV_OK);
}

int
dwarf_get_ranges_section_name(Dwarf_Debug dbg,
    const char **section_name_out,
    Dwarf_Error * error)
{
    struct Dwarf_Section_s *sec = 0;
    if (error != NULL) {
        *error = NULL;
    }
    sec = &dbg->de_debug_ranges;
    if (sec->dss_size == 0) {
        /* We don't have such a  section at all. */
        return DW_DLV_NO_ENTRY;
    }
    *section_name_out = sec->dss_name;
    return DW_DLV_OK;
}

int
dwarf_get_aranges_section_name(Dwarf_Debug dbg,
    const char **section_name_out,
    Dwarf_Error * error)
{
    struct Dwarf_Section_s *sec = 0;
    if (error != NULL) {
        *error = NULL;
    }
    sec = &dbg->de_debug_aranges;
    if (sec->dss_size == 0) {
        /* We don't have such a  section at all. */
        return DW_DLV_NO_ENTRY;
    }
    *section_name_out = sec->dss_name;
    return DW_DLV_OK;
}

int
dwarf_get_line_section_name_from_die(Dwarf_Die die,
    const char **section_name_out,
    Dwarf_Error * error)
{
    /*  The Dwarf_Debug this die belongs to. */
    Dwarf_Debug dbg = 0;
    struct Dwarf_Section_s *sec = 0;

    /*  ***** BEGIN CODE ***** */
    if (error) {
        *error = NULL;
    }

    CHECK_DIE(die, DW_DLV_ERROR);
    dbg = die->di_cu_context->cc_dbg;
    sec = &dbg->de_debug_line;
    if (sec->dss_size == 0) {
        /* We don't have such a  section at all. */
        return DW_DLV_NO_ENTRY;
    }
    *section_name_out = sec->dss_name;
    return DW_DLV_OK;
}

int
dwarf_get_string_section_name(Dwarf_Debug dbg,
    const char **section_name_out,
    Dwarf_Error * error)
{
    struct Dwarf_Section_s *sec = 0;

    /*  ***** BEGIN CODE ***** */
    if (error != NULL) {
        *error = NULL;
    }

    sec = &dbg->de_debug_str;
    if (sec->dss_size == 0) {
        /* We don't have such a  section at all. */
        return DW_DLV_NO_ENTRY;
    }
    *section_name_out = sec->dss_name;
    return DW_DLV_OK;
}


int
dwarf_srclines(Dwarf_Die die,
    Dwarf_Line ** linebuf,
    Dwarf_Signed * linecount, Dwarf_Error * error)
{
    Dwarf_Unsigned version = 0;
    Dwarf_Line_Context line_context = 0;
    Dwarf_Small    table_count = 0;
    Dwarf_Bool is_new_interface = false;
    int res  = _dwarf_internal_srclines(die,
        is_new_interface,
        &version,
        &table_count,
        &line_context,
        linebuf,
        linecount,
        /* linebuf_actuals */ 0,
        /*linecount_actuals*/0,
        /* addrlist= */ false,
        /* linelist= */ true,
        error);
    return res;
}

int
dwarf_srclines_two_level(Dwarf_Die die,
    Dwarf_Unsigned * version,
    Dwarf_Line    ** linebuf,
    Dwarf_Signed   * linecount,
    Dwarf_Line    ** linebuf_actuals,
    Dwarf_Signed   * linecount_actuals,
    Dwarf_Error    * error)
{
    Dwarf_Line_Context line_context = 0;
    Dwarf_Small table_count = 0;
    Dwarf_Bool is_new_interface = false;
    int res  = _dwarf_internal_srclines(die,
        is_new_interface,
        version,
        &table_count,
        &line_context,
        linebuf,
        linecount,
        linebuf_actuals,
        linecount_actuals,
        /* addrlist= */ false,
        /* linelist= */ true,
        error);
   return res;
}

/* New October 2015. */
int
dwarf_srclines_b(Dwarf_Die die,
    Dwarf_Unsigned  * version_out,
    Dwarf_Small     * table_count,
    Dwarf_Line_Context * line_context,
    Dwarf_Error * error)
{
    Dwarf_Signed linecount_actuals = 0;
    Dwarf_Line *linebuf = 0;
    Dwarf_Line *linebuf_actuals = 0;
    Dwarf_Signed linecount = 0;
    Dwarf_Bool is_new_interface = true;
    int res = 0;
    Dwarf_Unsigned tcount = 0;

    res  = _dwarf_internal_srclines(die,
        is_new_interface,
        version_out,
        table_count,
        line_context,
        &linebuf,
        &linecount,
        &linebuf_actuals,
        &linecount_actuals,
        /* addrlist= */ false,
        /* linelist= */ true,
        error);
    if (res == DW_DLV_OK) {
        (*line_context)->lc_new_style_access = true;
    }
    if(linecount_actuals ) {
        tcount++;
    }
    if(linecount ) {
        tcount++;
    }
    *table_count = tcount;
    return res;
}


/* New October 2015. */
int
dwarf_srclines_from_linecontext(Dwarf_Line_Context line_context,
    Dwarf_Line**     linebuf,
    Dwarf_Signed *   linecount,
    Dwarf_Error  *    error)
{
    if (!line_context || line_context->lc_magic != DW_CONTEXT_MAGIC) {
        _dwarf_error(NULL, error, DW_DLE_LINE_CONTEXT_BOTCH);
        return (DW_DLV_ERROR);
    }
    if (!line_context->lc_new_style_access) {
        _dwarf_error(NULL, error, DW_DLE_LINE_CONTEXT_BOTCH);
        return (DW_DLV_ERROR);
    }
    *linebuf =           line_context->lc_linebuf_logicals;
    *linecount =         line_context->lc_linecount_logicals;
    return DW_DLV_OK;
}

/* New October 2015. */
int
dwarf_srclines_two_level_from_linecontext(Dwarf_Line_Context line_context,
    Dwarf_Line**     linebuf,
    Dwarf_Signed *   linecount,
    Dwarf_Line**     linebuf_actuals,
    Dwarf_Signed *   linecount_actuals,
    Dwarf_Error  *    error)
{
    if (!line_context || line_context->lc_magic != DW_CONTEXT_MAGIC) {
        _dwarf_error(NULL, error, DW_DLE_LINE_CONTEXT_BOTCH);
        return (DW_DLV_ERROR);
    }
    if (!line_context->lc_new_style_access) {
        _dwarf_error(NULL, error, DW_DLE_LINE_CONTEXT_BOTCH);
        return (DW_DLV_ERROR);
    }
    *linebuf =           line_context->lc_linebuf_logicals;
    *linecount =         line_context->lc_linecount_logicals;
    *linebuf_actuals =    line_context->lc_linebuf_actuals;
    *linecount_actuals = line_context->lc_linecount_actuals;
    return DW_DLV_OK;
}


/* New October 2015. */
int
dwarf_srclines_table_offset(Dwarf_Line_Context line_context,
    Dwarf_Unsigned * offset,
    Dwarf_Error  *    error)
{
    if (!line_context ){
        _dwarf_error(NULL, error, DW_DLE_LINE_CONTEXT_BOTCH);
        return (DW_DLV_ERROR);
    }
    if( line_context->lc_magic != DW_CONTEXT_MAGIC) {
        _dwarf_error(NULL, error, DW_DLE_LINE_CONTEXT_BOTCH);
        return (DW_DLV_ERROR);
    }
    *offset = line_context->lc_section_offset;
    return DW_DLV_OK;
}

/* New October 2015. */
/*  If the CU DIE  has no DW_AT_comp_dir then
    the pointer pushed back to *compilation_directory
    will be NULL.
    Foy DWARF5 the line table header has the compilation
    directory. FIXME DWARF5.
    */
int dwarf_srclines_comp_dir(Dwarf_Line_Context line_context,
    const char **  compilation_directory,
    Dwarf_Error  *  error)
{
    if (!line_context ){
        _dwarf_error(NULL, error, DW_DLE_LINE_CONTEXT_BOTCH);
        return (DW_DLV_ERROR);
    }
    if( line_context->lc_magic != DW_CONTEXT_MAGIC) {
        _dwarf_error(NULL, error, DW_DLE_LINE_CONTEXT_BOTCH);
        return (DW_DLV_ERROR);
    }
    *compilation_directory =
        (const char *)line_context->lc_compilation_directory;
    return DW_DLV_OK;
}




/* New October 2015. */
int
dwarf_srclines_subprog_count(Dwarf_Line_Context line_context,
    Dwarf_Signed * count_out,
    Dwarf_Error * error)
{
    if (!line_context ){
        _dwarf_error(NULL, error, DW_DLE_LINE_CONTEXT_BOTCH);
        return (DW_DLV_ERROR);
    }
    if( line_context->lc_magic != DW_CONTEXT_MAGIC) {
        _dwarf_error(NULL, error, DW_DLE_LINE_CONTEXT_BOTCH);
        return (DW_DLV_ERROR);
    }
    *count_out = line_context->lc_subprogs_count;
    return DW_DLV_OK;
}
/* New October 2015. */
/*  Index says which to return.  Valid indexes are
    1-lc_subprogs_count
    */
int
dwarf_srclines_subprog_data(Dwarf_Line_Context line_context,
    Dwarf_Signed index_in,
    const char ** name,
    Dwarf_Unsigned *decl_file,
    Dwarf_Unsigned *decl_line,
    Dwarf_Error *error)
{
    /*  Negative values not sensible. Leaving traditional
        signed interfaces. */
    Dwarf_Unsigned index = (Dwarf_Unsigned)index_in;
    Dwarf_Subprog_Entry sub = 0;
    if (!line_context || line_context->lc_magic != DW_CONTEXT_MAGIC) {
        _dwarf_error(NULL, error, DW_DLE_LINE_CONTEXT_BOTCH);
        return (DW_DLV_ERROR);
    }
    if (index < 1 || index > line_context->lc_subprogs_count) {
        _dwarf_error(NULL, error, DW_DLE_LINE_CONTEXT_INDEX_WRONG);
        return (DW_DLV_ERROR);
    }
    sub = line_context->lc_subprogs + (index-1);
    *name = (const char *)sub->ds_subprog_name;
    *decl_file = sub->ds_decl_file;
    *decl_line = sub->ds_decl_line;
    return DW_DLV_OK;
}

/*  New October 2015. See also
    dwarf_srclines_files_indexes() */
int
dwarf_srclines_files_count(Dwarf_Line_Context line_context,
    Dwarf_Signed *count_out,
    Dwarf_Error *error)
{
    if (!line_context ||
        line_context->lc_magic != DW_CONTEXT_MAGIC) {
        _dwarf_error(NULL, error, DW_DLE_LINE_CONTEXT_BOTCH);
        return (DW_DLV_ERROR);
    }
    /*  Negative values not sensible. Leaving traditional
        signed interfaces. */
    *count_out = (Dwarf_Signed)line_context->lc_file_entry_count;
    return DW_DLV_OK;
}

/* New October 2015. */
int
dwarf_srclines_files_data(Dwarf_Line_Context line_context,
    Dwarf_Signed     index_in,
    const char **    name,
    Dwarf_Unsigned * directory_index,
    Dwarf_Unsigned * last_mod_time,
    Dwarf_Unsigned * file_length,
    Dwarf_Error    * error)
{
    return dwarf_srclines_files_data_b(
        line_context,index_in,name,directory_index,
        last_mod_time,file_length,0,error);
}


/* New March 2018 making iteration through file names. */
int
dwarf_srclines_files_indexes(Dwarf_Line_Context line_context,
    Dwarf_Signed   *baseindex,
    Dwarf_Signed   *file_count,
    Dwarf_Signed   *endindex,
    Dwarf_Error    * error)
{
    if(line_context->lc_magic != DW_CONTEXT_MAGIC) {
        _dwarf_error(NULL, error, DW_DLE_LINE_CONTEXT_BOTCH);
        return DW_DLV_ERROR;
    }
    *baseindex  = line_context->lc_file_entry_baseindex;
    *file_count = line_context->lc_file_entry_count;
    *endindex   = line_context->lc_file_entry_endindex;
    return DW_DLV_OK;
}

/* New March 2018 adding DWARF5 data. */
int
dwarf_srclines_files_data_b(Dwarf_Line_Context line_context,
    Dwarf_Signed     index_in,
    const char **    name,
    Dwarf_Unsigned * directory_index,
    Dwarf_Unsigned * last_mod_time,
    Dwarf_Unsigned * file_length,
    Dwarf_Form_Data16 ** data16ptr,
    Dwarf_Error    * error)
{
    Dwarf_File_Entry fi = 0;
    Dwarf_Signed i  =0;
    Dwarf_Signed baseindex = 0;
    Dwarf_Signed file_count = 0;
    Dwarf_Signed endindex = 0;
    /*  Negative values not sensible. Leaving traditional
        signed interfaces. */
    Dwarf_Signed index = index_in;
    int res = 0;


    if (!line_context || line_context->lc_magic != DW_CONTEXT_MAGIC) {
        _dwarf_error(NULL, error, DW_DLE_LINE_CONTEXT_BOTCH);
        return (DW_DLV_ERROR);
    }

    /*  Special accomodation of the special gnu experimental
        version number (a high number) so we cannot just
        say '5 or greater'. This is awkward, but at least
        if there is a version 6 or later it still allows
        the experimental table.  */
    res =  dwarf_srclines_files_indexes(line_context, &baseindex,
        &file_count, &endindex, error);
    if (res != DW_DLV_OK) {
        return res;
    }
    fi = line_context->lc_file_entries;
    if (index < baseindex || index >= endindex) {
        _dwarf_error(NULL, error, DW_DLE_LINE_CONTEXT_INDEX_WRONG);
            return DW_DLV_ERROR;
    }
    for ( i = baseindex;i < index; i++) {
        fi = fi->fi_next;
        if(!fi) {
            _dwarf_error(NULL, error, DW_DLE_LINE_HEADER_CORRUPT);
                return DW_DLV_ERROR;
        }
    }

    if(name) {
        *name = (const char *)fi->fi_file_name;
    }
    if (directory_index) {
        *directory_index = fi->fi_dir_index;
    }
    if (last_mod_time) {
        *last_mod_time = fi->fi_time_last_mod;
    }
    if (file_length) {
        *file_length = fi->fi_file_length;
    }
    if (data16ptr) {
        if (fi->fi_md5_present) {
            *data16ptr = &fi->fi_md5_value;
        } else {
            *data16ptr = 0;
        }
    }
    return DW_DLV_OK;
}




/* New October 2015. */
int
dwarf_srclines_include_dir_count(Dwarf_Line_Context line_context,
    Dwarf_Signed * count,
    Dwarf_Error  * error)
{
    if (!line_context || line_context->lc_magic != DW_CONTEXT_MAGIC) {
        _dwarf_error(NULL, error, DW_DLE_LINE_CONTEXT_BOTCH);
        return (DW_DLV_ERROR);
    }
    *count = line_context->lc_include_directories_count;
    return DW_DLV_OK;
}

/* New October 2015. */
int
dwarf_srclines_include_dir_data(Dwarf_Line_Context line_context,
    Dwarf_Signed   index_in,
    const char  ** name,
    Dwarf_Error *  error)
{
    /*  It never made sense that the srclines used a signed count.
        But that cannot be fixed in interfaces for compatibility.
        So we adjust here. */
    Dwarf_Unsigned index = index_in;

    if (!line_context || line_context->lc_magic != DW_CONTEXT_MAGIC) {
        _dwarf_error(NULL, error, DW_DLE_LINE_CONTEXT_BOTCH);
        return (DW_DLV_ERROR);
    }
    if (index < 1 || index > line_context->lc_include_directories_count) {
        _dwarf_error(NULL, error, DW_DLE_LINE_CONTEXT_INDEX_WRONG);
        return (DW_DLV_ERROR);
    }
    *name = (const char *)(line_context->lc_include_directories[index-1]);
    return DW_DLV_OK;
}

/* New October 2015. */
int
dwarf_srclines_version(Dwarf_Line_Context line_context,
    Dwarf_Unsigned *version_out,
    Dwarf_Small    *table_count_out,
    Dwarf_Error *error)
{
    if (!line_context || line_context->lc_magic != DW_CONTEXT_MAGIC) {
        _dwarf_error(NULL, error, DW_DLE_LINE_CONTEXT_BOTCH);
        return (DW_DLV_ERROR);
    }
    *version_out = line_context->lc_version_number;
    *table_count_out = line_context->lc_table_count;
    return DW_DLV_OK;
}



/*  Every line table entry (except DW_DLE_end_sequence,
    which is returned using dwarf_lineendsequence())
    potentially has the begin-statement
    flag marked 'on'.   This returns thru *return_bool,
    the begin-statement flag.  */

int
dwarf_linebeginstatement(Dwarf_Line line,
    Dwarf_Bool * return_bool, Dwarf_Error * error)
{
    if (line == NULL || return_bool == 0) {
        _dwarf_error(NULL, error, DW_DLE_DWARF_LINE_NULL);
        return (DW_DLV_ERROR);
    }

    *return_bool = (line->li_addr_line.li_l_data.li_is_stmt);
    return DW_DLV_OK;
}

/*  At the end of any contiguous line-table there may be
    a DW_LNE_end_sequence operator.
    This returns non-zero thru *return_bool
    if and only if this 'line' entry was a DW_LNE_end_sequence.

    Within a compilation unit or function there may be multiple
    line tables, each ending with a DW_LNE_end_sequence.
    Each table describes a contiguous region.
    Because compilers may split function code up in arbitrary ways
    compilers may need to emit multiple contigous regions (ie
    line tables) for a single function.
    See the DWARF3 spec section 6.2.  */
int
dwarf_lineendsequence(Dwarf_Line line,
    Dwarf_Bool * return_bool, Dwarf_Error * error)
{
    if (line == NULL) {
        _dwarf_error(NULL, error, DW_DLE_DWARF_LINE_NULL);
        return (DW_DLV_ERROR);
    }

    *return_bool = (line->li_addr_line.li_l_data.li_end_sequence);
    return DW_DLV_OK;
}


/*  Each 'line' entry has a line-number.
    If the entry is a DW_LNE_end_sequence the line-number is
    meaningless (see dwarf_lineendsequence(), just above).  */
int
dwarf_lineno(Dwarf_Line line,
    Dwarf_Unsigned * ret_lineno, Dwarf_Error * error)
{
    if (line == NULL || ret_lineno == 0) {
        _dwarf_error(NULL, error, DW_DLE_DWARF_LINE_NULL);
        return (DW_DLV_ERROR);
    }

    *ret_lineno = (line->li_addr_line.li_l_data.li_line);
    return DW_DLV_OK;
}

/*  Each 'line' entry has a file-number, and index into the file table.
    If the entry is a DW_LNE_end_sequence the index is
    meaningless (see dwarf_lineendsequence(), just above).
    The file number returned is an index into the file table
    produced by dwarf_srcfiles(), but care is required: the
    li_file begins with 1 for DWARF2,3,4
    files, so that the li_file returned here
    is 1 greater than its index into the dwarf_srcfiles() output array.

    And entries from DW_LNE_define_file don't appear in
    the dwarf_srcfiles() output so file indexes from here may exceed
    the size of the dwarf_srcfiles() output array size.
*/
int
dwarf_line_srcfileno(Dwarf_Line line,
    Dwarf_Unsigned * ret_fileno, Dwarf_Error * error)
{
    if (line == NULL || ret_fileno == 0) {
        _dwarf_error(NULL, error, DW_DLE_DWARF_LINE_NULL);
        return DW_DLV_ERROR;
    }
    /*  li_file must be <= line->li_context->lc_file_entry_count else
        it is trash. li_file 0 means not attributable to
        any source file per dwarf2/3 spec.
        For DWARF5, li_file < lc_file_entry_count */
    *ret_fileno = (line->li_addr_line.li_l_data.li_file);
    return DW_DLV_OK;
}

/*  Each 'line' entry has an is_addr_set attribute.
    If the entry is a DW_LNE_set_address, return TRUE through
    the *is_addr_set pointer.  */
int
dwarf_line_is_addr_set(Dwarf_Line line,
    Dwarf_Bool *is_addr_set, Dwarf_Error * error)
{
    if (line == NULL) {
        _dwarf_error(NULL, error, DW_DLE_DWARF_LINE_NULL);
        return (DW_DLV_ERROR);
    }

    *is_addr_set = (line->li_addr_line.li_l_data.li_is_addr_set);
    return DW_DLV_OK;
}

/*  Each 'line' entry has a line-address.
    If the entry is a DW_LNE_end_sequence the adddress
    is one-beyond the last address this contigous region
    covers, so the address is not inside the region,
    but is just outside it.  */
int
dwarf_lineaddr(Dwarf_Line line,
    Dwarf_Addr * ret_lineaddr, Dwarf_Error * error)
{
    if (line == NULL || ret_lineaddr == 0) {
        _dwarf_error(NULL, error, DW_DLE_DWARF_LINE_NULL);
        return (DW_DLV_ERROR);
    }

    *ret_lineaddr = (line->li_address);
    return DW_DLV_OK;
}


/*  Obsolete: do not use this function.
    December 2011: For reasons lost in the mists of history,
    this returned -1, not zero (through the pointer
    ret_lineoff), if the column was zero.
    That was always bogus, even in DWARF2.
    It is also bogus that the column value is signed, but
    it is painful to change the argument type in 2011, so leave it.
    */
int
dwarf_lineoff(Dwarf_Line line,
    Dwarf_Signed * ret_lineoff, Dwarf_Error * error)
{
    if (line == NULL || ret_lineoff == 0) {
        _dwarf_error(NULL, error, DW_DLE_DWARF_LINE_NULL);
        return (DW_DLV_ERROR);
    }
    *ret_lineoff = (
        (line->li_addr_line.li_l_data.li_column == 0) ?
            -1 : line->li_addr_line.li_l_data.li_column);
    return DW_DLV_OK;
}
/*  Each 'line' entry has a column-within-line (offset
    within the line) where the
    source text begins.
    If the entry is a DW_LNE_end_sequence the line-number is
    meaningless (see dwarf_lineendsequence(), just above).
    Lines of text begin at column 1.  The value 0
    means the line begins at the left edge of the line.
    (See the DWARF3 spec, section 6.2.2).
    So 0 and 1 mean essentially the same thing.
    dwarf_lineoff_b() is new in December 2011.
    */
int
dwarf_lineoff_b(Dwarf_Line line,
    Dwarf_Unsigned * ret_lineoff, Dwarf_Error * error)
{
    if (line == NULL || ret_lineoff == 0) {
        _dwarf_error(NULL, error, DW_DLE_DWARF_LINE_NULL);
        return (DW_DLV_ERROR);
    }

    *ret_lineoff = line->li_addr_line.li_l_data.li_column;
    return DW_DLV_OK;
}


static int
dwarf_filename(Dwarf_Line_Context context,
    Dwarf_Signed fileno_in,
    char **ret_filename, Dwarf_Error *error)
{
    Dwarf_Signed i = 0;
    Dwarf_File_Entry file_entry = 0;
    Dwarf_Debug dbg = context->lc_dbg;
    int res = 0;
    Dwarf_Signed baseindex = 0;
    Dwarf_Signed file_count = 0;
    Dwarf_Signed endindex = 0;
    /*  Negative values not sensible. Leaving traditional
        signed interfaces in place. */
    Dwarf_Signed fileno = fileno_in;
    unsigned linetab_version = context->lc_version_number;

    res =  dwarf_srclines_files_indexes(context, &baseindex,
        &file_count, &endindex, error);
    if (res != DW_DLV_OK) {
        return res;
    }
    if (fileno >= endindex) {
        dwarfstring m;

        dwarfstring_constructor(&m);
        dwarfstring_append_printf_i(&m,
            "DW_DLE_NO_FILE_NAME: the file number is %d ",
            fileno);
        dwarfstring_append_printf_u(&m,
            "( this is a DWARF 0x%x linetable)",
            linetab_version);
        dwarfstring_append_printf_i(&m,
            " yet the highest allowed file name index is %d.",
            endindex-1);
        _dwarf_error_string(dbg, error, DW_DLE_NO_FILE_NAME,
            dwarfstring_string(&m));
        dwarfstring_destructor(&m);
        return DW_DLV_ERROR;
    } else {
        if (linetab_version <= DW_LINE_VERSION4 ||
            linetab_version == EXPERIMENTAL_LINE_TABLES_VERSION) {
            if (!fileno) {
                return DW_DLV_NO_ENTRY;
            }
            /* else ok */
        }  /* else DWARF 5 line index 0 is fine */
    }

    file_entry = context->lc_file_entries;
    /*  zero fileno allowed for DWARF5 table. For DWARF4,
        zero fileno handled above. */
    for (i =  baseindex; i < fileno ; i++) {
        file_entry = file_entry->fi_next;
    }

    res = create_fullest_file_path(dbg,
        file_entry,context, ret_filename,error);
    return res;
}

int
dwarf_linesrc(Dwarf_Line line, char **ret_linesrc, Dwarf_Error * error)
{
    if (line == NULL) {
        _dwarf_error(NULL, error, DW_DLE_DWARF_LINE_NULL);
        return DW_DLV_ERROR;
    }
    if (line->li_context == NULL) {
        _dwarf_error(NULL, error, DW_DLE_LINE_CONTEXT_NULL);
        return DW_DLV_ERROR;
    }
    return dwarf_filename(line->li_context,
        line->li_addr_line.li_l_data.li_file, ret_linesrc, error);
}

/*  Every line table entry potentially has the basic-block-start
    flag marked 'on'.   This returns thru *return_bool,
    the basic-block-start flag.
*/
int
dwarf_lineblock(Dwarf_Line line,
    Dwarf_Bool * return_bool, Dwarf_Error * error)
{
    if (line == NULL) {
        _dwarf_error(NULL, error, DW_DLE_DWARF_LINE_NULL);
        return (DW_DLV_ERROR);
    }
    *return_bool = (line->li_addr_line.li_l_data.li_basic_block);
    return DW_DLV_OK;
}

/* We gather these into one call as it's likely one
   will want all or none of them.  */
int dwarf_prologue_end_etc(Dwarf_Line  line,
    Dwarf_Bool  *    prologue_end,
    Dwarf_Bool  *    epilogue_begin,
    Dwarf_Unsigned * isa,
    Dwarf_Unsigned * discriminator,
    Dwarf_Error *    error)
{
    if (line == NULL) {
        _dwarf_error(NULL, error, DW_DLE_DWARF_LINE_NULL);
        return (DW_DLV_ERROR);
    }
    *prologue_end = (line->li_addr_line.li_l_data.li_prologue_end);
    *epilogue_begin = (line->li_addr_line.li_l_data.li_epilogue_begin);
    *isa = (line->li_addr_line.li_l_data.li_isa);
    *discriminator = (line->li_addr_line.li_l_data.li_discriminator);
    return DW_DLV_OK;
}

int
dwarf_linelogical(Dwarf_Line line,
    Dwarf_Unsigned * logical,
    Dwarf_Error*     error)
{
    if (line == NULL) {
        _dwarf_error(NULL, error, DW_DLE_DWARF_LINE_NULL);
        return (DW_DLV_ERROR);
    }
    *logical = (line->li_addr_line.li_l_data.li_line);
    return DW_DLV_OK;
}

int
dwarf_linecontext(Dwarf_Line line,
    Dwarf_Unsigned * context,
    Dwarf_Error*     error)
{
    if (line == NULL) {
        _dwarf_error(NULL, error, DW_DLE_DWARF_LINE_NULL);
        return (DW_DLV_ERROR);
    }
    *context = (line->li_addr_line.li_l_data.li_call_context);
    return DW_DLV_OK;
}

int
dwarf_line_subprogno(Dwarf_Line line,
    Dwarf_Unsigned * subprog,
    Dwarf_Error *    error)
{
    if (line == NULL) {
        _dwarf_error(NULL, error, DW_DLE_DWARF_LINE_NULL);
        return (DW_DLV_ERROR);
    }
    *subprog = (line->li_addr_line.li_l_data.li_subprogram);
    return DW_DLV_OK;
}

int
dwarf_line_subprog(Dwarf_Line line,
    char   **        subprog_name,
    char   **        decl_filename,
    Dwarf_Unsigned * decl_line,
    Dwarf_Error *    error)
{
    Dwarf_Unsigned subprog_no;
    Dwarf_Subprog_Entry subprog;
    Dwarf_Debug dbg;
    int res;

    if (line == NULL) {
        _dwarf_error(NULL, error, DW_DLE_DWARF_LINE_NULL);
        return DW_DLV_ERROR;
    }

    if (line->li_context == NULL) {
        _dwarf_error(NULL, error, DW_DLE_LINE_CONTEXT_NULL);
        return DW_DLV_ERROR;
    }

    dbg = line->li_context->lc_dbg;

    subprog_no = line->li_addr_line.li_l_data.li_subprogram;
    if (subprog_no == 0) {
        *subprog_name = NULL;
        *decl_filename = NULL;
        *decl_line = 0;
        return DW_DLV_OK;
    }

    if (subprog_no > line->li_context->lc_subprogs_count) {
        _dwarf_error(dbg, error, DW_DLE_NO_FILE_NAME);
        return DW_DLV_ERROR;
    }

    /*  Adjusting for 1 origin subprog no */
    subprog = &line->li_context->lc_subprogs[subprog_no - 1];

    *subprog_name = (char *)subprog->ds_subprog_name;
    *decl_line = subprog->ds_decl_line;

    res = dwarf_filename(line->li_context,
        subprog->ds_decl_file,
        decl_filename, error);
    if (res != DW_DLV_OK) {
        *decl_filename = NULL;
        return res;
    }
    return DW_DLV_OK;
}

/*  This is another line_context_destructor. */
static void
delete_line_context_itself(Dwarf_Line_Context context)
{


    Dwarf_Debug dbg = 0;
    Dwarf_File_Entry fe = 0;

    if(context->lc_magic != DW_CONTEXT_MAGIC) {
        /* Something is wrong. */
        return;
    }
    dbg = context->lc_dbg;
    fe = context->lc_file_entries;
    while (fe) {
        Dwarf_File_Entry fenext = fe->fi_next;
        fe->fi_next = 0;
        free(fe);
        fe = fenext;
    }
    context->lc_file_entries = 0;
    context->lc_file_entry_count = 0;
    context->lc_file_entry_baseindex = 0;
    context->lc_file_entry_endindex = 0;
    if (context->lc_subprogs) {
        free(context->lc_subprogs);
        context->lc_subprogs = 0;
    }
    free(context->lc_directory_format_values);
    context->lc_directory_format_values = 0;
    free(context->lc_file_format_values);
    context->lc_file_format_values = 0;
    if (context->lc_include_directories) {
        free(context->lc_include_directories);
        context->lc_include_directories = 0;
    }
    context->lc_magic = 0xdead;
    dwarf_dealloc(dbg, context, DW_DLA_LINE_CONTEXT);
}

/*  It's impossible for callers of dwarf_srclines() to get to and
    free all the resources (in particular, the li_context and its
    lc_file_entries).
    So this function, new July 2005, does it.

    As of September 2015 this will now delete either
    table of a two-level line table.
    In the two-level case one calls it once each on
    both the logicals and actuals tables.
    (in either order, the order is not critical).
    Once  the  logicals table is dealloced any
    use of the actuals table will surely result in chaos.
    Just do the two calls one after the other.

    In the standard single-table case (DWARF 2,3,4)
    one calls it just once on the
    linebuf.  Old style dealloc. Should never be used with
    dwarf_srclines_b(), but if it is there
    are no bad consequences..

    Those using standard DWARF should use
    dwarf_srclines_b() and dwarf_srclines_dealloc_b()
    instead of dwarf_srclines and dwarf_srclines_dealloc()
    as that gives access to various bits of useful information.
    */

void
dwarf_srclines_dealloc(Dwarf_Debug dbg, Dwarf_Line * linebuf,
    Dwarf_Signed count)
{
    Dwarf_Signed i = 0;
    /*  alternate_data_count is a failsafe to prevent
        duplicate frees when there is inappropriate mixing
        of new interface and this old routine */
    Dwarf_Bool alternate_data_count = 0;

    struct Dwarf_Line_Context_s *line_context = 0;


    if(!linebuf) {
        return;
    }
    if (count > 0) {
        /*  All these entries share a single line_context, and
            for two-levels tables each table gets it too.
            Hence we will dealloc ONLY if !is_actuals_table
            so for single and two-level tables the space
            is deallocated. */
        line_context = linebuf[0]->li_context;
        if (line_context && line_context->lc_magic != DW_CONTEXT_MAGIC ) {
            /* Something is very wrong. */
            line_context = 0;
        } else if (line_context) {
            if (linebuf == line_context->lc_linebuf_logicals) {
                line_context->lc_linebuf_logicals = 0;
                line_context->lc_linecount_logicals = 0;
                alternate_data_count = line_context->lc_linecount_actuals;
                /* Ok to delete logicals */
            } else if (linebuf == line_context->lc_linebuf_actuals) {
                /* Ok to delete actuals */
                line_context->lc_linebuf_actuals = 0;
                line_context->lc_linecount_actuals = 0;
                alternate_data_count = line_context->lc_linecount_logicals;
            } else {
                /* Something is wrong very wrong. */
                return;
            }
        }  else {
            /*  Else: impossible. Unless the caller
                passed in a bogus linebuf. */
            line_context = 0;
        }
    }

    /*  Here we actually delete a set of lines. */
    for (i = 0; i < count; ++i) {
        dwarf_dealloc(dbg, linebuf[i], DW_DLA_LINE);
    }
    dwarf_dealloc(dbg, linebuf, DW_DLA_LIST);

    if (line_context && !line_context->lc_new_style_access
        && !alternate_data_count ) {
        /*  There is nothing left
            referencing this line_context. */
        dwarf_dealloc(dbg, line_context, DW_DLA_LINE_CONTEXT);
    }
    return;
}

/*  New October 2015.
    This should be used to deallocate all
    lines data that is
    set up by dwarf_srclines_b().
    This and dwarf_srclines_b() are now (October 2015)
    the preferred routine to use.  */
void
dwarf_srclines_dealloc_b(Dwarf_Line_Context line_context)
{
    Dwarf_Line *linestable = 0;
    Dwarf_Signed linescount = 0;
    Dwarf_Signed i = 0;
    Dwarf_Debug dbg = 0;

    if(!line_context) {
        return;
    }
    if(line_context->lc_magic != DW_CONTEXT_MAGIC) {
        /* Something is wrong. */
        return; }
    dbg = line_context->lc_dbg;
    if (!line_context || line_context->lc_magic != DW_CONTEXT_MAGIC) {
        /*  Something is badly wrong here.*/
        return;
    }
    linestable = line_context->lc_linebuf_logicals;
    if (linestable) {
        linescount = line_context->lc_linecount_logicals;
        for (i = 0; i < linescount ; ++i) {
            dwarf_dealloc(dbg, linestable[i], DW_DLA_LINE);
        }
        dwarf_dealloc(dbg, linestable, DW_DLA_LIST);
    }
    line_context->lc_linebuf_logicals = 0;
    line_context->lc_linecount_logicals = 0;

    linestable = line_context->lc_linebuf_actuals;
    if (linestable) {
        linescount = line_context->lc_linecount_actuals;
        for (i = 0; i <linescount ; ++i) {
            dwarf_dealloc(dbg, linestable[i], DW_DLA_LINE);
        }
        dwarf_dealloc(dbg, linestable, DW_DLA_LIST);
    }
    line_context->lc_linebuf_actuals = 0;
    line_context->lc_linecount_actuals = 0;
    delete_line_context_itself(line_context);
}

/* There is an error, so count it. If we are printing
   errors by command line option, print the details.  */
void
_dwarf_print_header_issue(Dwarf_Debug dbg,
    const char *specific_msg,
    Dwarf_Small *data_start,
    Dwarf_Signed value,
    unsigned index,
    unsigned tabv,
    unsigned linetabv,
    int *err_count_out)
{
    if (!err_count_out) {
        return;
    }
    /* Are we in verbose mode */
    if (dwarf_cmdline_options.check_verbose_mode){
        dwarfstring m1;

        dwarfstring_constructor(&m1);
        dwarfstring_append(&m1,
            "\n*** DWARF CHECK: "
            ".debug_line: ");
        dwarfstring_append(&m1,(char *)specific_msg);
        dwarfstring_append_printf_i(&m1,
            " %" DW_PR_DSd,value);
        if (index || tabv || linetabv) {
            dwarfstring_append_printf_u(&m1,
                "; Mismatch index %u",index);
            dwarfstring_append_printf_u(&m1,
                " stdval %u",tabv);
            dwarfstring_append_printf_u(&m1,
                " linetabval %u",linetabv);
        }
        if (data_start >= dbg->de_debug_line.dss_data &&
            (data_start < (dbg->de_debug_line.dss_data +
            dbg->de_debug_line.dss_size))) {
            Dwarf_Unsigned off =
                data_start - dbg->de_debug_line.dss_data;

            dwarfstring_append_printf_u(&m1,
                " at offset 0x%" DW_PR_XZEROS DW_PR_DUx,off);
            dwarfstring_append_printf_u(&m1,
                "  ( %" DW_PR_DUu " ) ",off);
        } else {
            dwarfstring_append(&m1,
                " (unknown section location) ");
        }
        dwarfstring_append(&m1,"***\n");
        _dwarf_printf(dbg,dwarfstring_string(&m1));
        dwarfstring_destructor(&m1);
    }
    *err_count_out += 1;
}


int
_dwarf_decode_line_string_form(Dwarf_Debug dbg,
    Dwarf_Unsigned form,
    Dwarf_Unsigned offset_size,
    Dwarf_Small **line_ptr,
    Dwarf_Small *line_ptr_end,
    char **return_str,
    Dwarf_Error * error)
{
    int res = 0;

    switch (form) {
    case DW_FORM_line_strp: {
        Dwarf_Small *secstart = 0;
        Dwarf_Small *secend = 0;
        Dwarf_Small *strptr = 0;
        Dwarf_Unsigned offset = 0;
        Dwarf_Small *offsetptr = *line_ptr;

        res = _dwarf_load_section(dbg, &dbg->de_debug_line_str,error);
        if (res != DW_DLV_OK) {
            return res;
        }

        secstart = dbg->de_debug_line_str.dss_data;
        secend = secstart + dbg->de_debug_line_str.dss_size;

        READ_UNALIGNED_CK(dbg, offset, Dwarf_Unsigned,offsetptr, offset_size,
            error,line_ptr_end);
        *line_ptr += offset_size;
        strptr = secstart + offset;
        res = _dwarf_check_string_valid(dbg,
            secstart,strptr,secend,
            DW_DLE_LINE_STRP_OFFSET_BAD,error);
        if (res != DW_DLV_OK) {
            return res;
        }
        *return_str = (char *) strptr;
        return DW_DLV_OK;
        }
    case DW_FORM_string: {
        Dwarf_Small *secend = line_ptr_end;
        Dwarf_Small *strptr = *line_ptr;

        res = _dwarf_check_string_valid(dbg,
            strptr ,strptr,secend,DW_DLE_LINE_STRING_BAD,error);
        if (res != DW_DLV_OK) {
            return res;
        }
        *return_str = (char *)strptr;
        *line_ptr += strlen((const char *)strptr) + 1;
        return DW_DLV_OK;
        }
    default:
        _dwarf_error(dbg, error, DW_DLE_ATTR_FORM_BAD);
        return DW_DLV_ERROR;
    }
}

int
_dwarf_decode_line_udata_form(Dwarf_Debug dbg,
    Dwarf_Unsigned form,
    Dwarf_Small **line_ptr,
    Dwarf_Unsigned *return_val,
    Dwarf_Small *line_end_ptr,
    Dwarf_Error * error)
{
    Dwarf_Unsigned val = 0;
    Dwarf_Small * lp = *line_ptr;

    switch (form) {

    case DW_FORM_udata:
        DECODE_LEB128_UWORD_CK(lp, val,dbg,error,line_end_ptr);
        *return_val = val;
        *line_ptr = lp;
        return DW_DLV_OK;

    default:
        _dwarf_error(dbg, error, DW_DLE_ATTR_FORM_BAD);
        return DW_DLV_ERROR;
    }
}


void
_dwarf_update_chain_list( Dwarf_Chain chain_line,
    Dwarf_Chain *head_chain, Dwarf_Chain *curr_chain)
{
    if (*head_chain == NULL) {
        *head_chain = chain_line;
    } else {
        (*curr_chain)->ch_next = chain_line;
    }
    *curr_chain = chain_line;
}

void
_dwarf_free_chain_entries(Dwarf_Debug dbg,Dwarf_Chain head,int count)
{
    int i = 0;
    Dwarf_Chain curr_chain = head;
    for (i = 0; i < count; i++) {
        Dwarf_Chain t = curr_chain;
        void *item = t->ch_item;
        int itype = t->ch_itemtype;

        if (item && itype) { /* valid DW_DLA types are never 0 */
            dwarf_dealloc(dbg,item,itype);
            t->ch_item = 0;
        }
        curr_chain = curr_chain->ch_next;
        dwarf_dealloc(dbg, t, DW_DLA_CHAIN);
    }
}

int
_dwarf_add_to_files_list(Dwarf_Line_Context context, Dwarf_File_Entry fe)
{
    if (!context->lc_file_entries) {
        context->lc_file_entries = fe;
    } else {
        context->lc_last_entry->fi_next = fe;
    }
    context->lc_last_entry = fe;
    context->lc_file_entry_count++;
    /*  Here we attempt to write code to make it easy to interate
        though source file names without having to code specially
        for DWARF2,3,4 vs DWARF5 */
    if (context->lc_version_number >= DW_LINE_VERSION5 &&
        context->lc_version_number != EXPERIMENTAL_LINE_TABLES_VERSION) {
        context->lc_file_entry_baseindex = 0;
        context->lc_file_entry_endindex = context->lc_file_entry_count;
    } else {
        /* DWARF2,3,4 and the EXPERIMENTAL_LINE_TABLES_VERSION. */
        context->lc_file_entry_baseindex = 1;
        context->lc_file_entry_endindex = context->lc_file_entry_count+1;
    }
    return DW_DLV_OK;
}


int
_dwarf_line_context_constructor(Dwarf_Debug dbg, void *m)
{
    Dwarf_Line_Context line_context = (Dwarf_Line_Context)m;
    /*  dwarf_get_alloc ensures the bytes are all zero
        when m is passed to us. */
    line_context->lc_magic = DW_CONTEXT_MAGIC;
    line_context->lc_dbg =  dbg;
    return DW_DLV_OK;
}

/*  This cleans up a contex record.
    The lines tables (actuals and logicals)
    are themselves items that will
    be dealloc'd either manually
    or, at closing the libdwarf dbg,
    automatically.  So we DO NOT
    touch the lines tables here
    See also: delete_line_context_itself()
*/
void
_dwarf_line_context_destructor(void *m)
{
    Dwarf_Line_Context line_context = (Dwarf_Line_Context)m;
    if (line_context->lc_magic != DW_CONTEXT_MAGIC) {
        /* Nothing is safe, do nothing. */
        return;
    }
    if (line_context->lc_include_directories) {
        free(line_context->lc_include_directories);
        line_context->lc_include_directories = 0;
        line_context->lc_include_directories_count = 0;
    }
    if (line_context->lc_file_entries) {
        Dwarf_File_Entry fe = line_context->lc_file_entries;
        while(fe) {
            Dwarf_File_Entry t = fe;
            fe = t->fi_next;
            t->fi_next = 0;
            free(t);
        }
        line_context->lc_file_entries     = 0;
        line_context->lc_last_entry       = 0;
        line_context->lc_file_entry_count = 0;
        line_context->lc_file_entry_baseindex   = 0;
        line_context->lc_file_entry_endindex    = 0;
    }
    free(line_context->lc_directory_format_values);
    line_context->lc_directory_format_values = 0;
    free(line_context->lc_file_format_values);
    line_context->lc_file_format_values = 0;

    if (line_context->lc_subprogs) {
        free(line_context->lc_subprogs);
        line_context->lc_subprogs = 0;
        line_context->lc_subprogs_count = 0;
    }
    line_context->lc_magic = 0;
    return;
}
