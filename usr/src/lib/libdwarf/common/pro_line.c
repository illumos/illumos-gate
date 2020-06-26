/*
  Copyright (C) 2000,2004 Silicon Graphics, Inc.  All Rights Reserved.
  Portions Copyright 2011-2019 David Anderson. All Rights Reserved.

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
#include <string.h>

#include "pro_incl.h"
#include <stddef.h>
#include "dwarf.h"
#include "libdwarf.h"
#include "pro_opaque.h"
#include "pro_error.h"
#include "pro_alloc.h"
#include "pro_encode_nm.h"
#include "pro_line.h"

static int _dwarf_pro_add_line_entry(Dwarf_P_Debug,
    Dwarf_Unsigned file_index,
    Dwarf_Addr code_address,
    Dwarf_Unsigned symidx,
    Dwarf_Unsigned line_no,
    Dwarf_Signed col_no,
    Dwarf_Bool is_stmt_begin,
    Dwarf_Bool is_bb_begin,
    Dwarf_Ubyte opc,
    Dwarf_Bool isepilbeg,
    Dwarf_Bool isprolend,
    Dwarf_Unsigned isa,
    Dwarf_Unsigned discriminator,
    Dwarf_Error * error);

/*  Add a entry to the line information section
    file_index: index of file in file entries, obtained from
    add_file_entry() call.

    This function actually calls _dwarf_pro_add_line_entry(), with
    an extra parameter, the opcode. Done so that interface calls
    dwarf_lne_set_address() and dwarf_lne_end_sequence() can use
    this internal routine.

    The return value of the original
    interfaces is really signed. Bogus interface.
    With dwarf_add_line_entry_c the interface is corrected. */
Dwarf_Unsigned
dwarf_add_line_entry_b(Dwarf_P_Debug dbg,
    Dwarf_Unsigned file_index,
    Dwarf_Addr     code_address,
    Dwarf_Unsigned line_no,
    Dwarf_Signed   col_no,
    Dwarf_Bool     is_stmt_begin,
    Dwarf_Bool     is_bb_begin,
    Dwarf_Bool     isepilbeg,
    Dwarf_Bool     isprolend,
    Dwarf_Unsigned isa,
    Dwarf_Unsigned discriminator,
    Dwarf_Error *  error)
{
    Dwarf_Unsigned retval = 0;
    Dwarf_Ubyte opc = 0;
    Dwarf_Unsigned symidx = 0;

    retval = _dwarf_pro_add_line_entry(dbg, file_index, code_address,
        symidx,
        line_no, col_no, is_stmt_begin,
        is_bb_begin,
        opc,
        isepilbeg,isprolend,isa,discriminator, error);
    if (retval != DW_DLV_OK) {
        return DW_DLV_NOCOUNT;
    }
    return 0;
}
int
dwarf_add_line_entry_c(Dwarf_P_Debug dbg,
    Dwarf_Unsigned file_index,
    Dwarf_Addr     code_address,
    Dwarf_Unsigned line_no,
    Dwarf_Signed   col_no,
    Dwarf_Bool     is_stmt_begin,
    Dwarf_Bool     is_bb_begin,
    Dwarf_Bool     isepilbeg,
    Dwarf_Bool     isprolend,
    Dwarf_Unsigned isa,
    Dwarf_Unsigned discriminator,
    Dwarf_Error *  error)
{
    int retval = 0;
    Dwarf_Ubyte opc = 0;
    Dwarf_Unsigned symidx = 0;

    retval = _dwarf_pro_add_line_entry(dbg, file_index, code_address,
        symidx,
        line_no, col_no, is_stmt_begin,
        is_bb_begin,
        opc,
        isepilbeg,isprolend,isa,discriminator, error);
    return retval;
}



/*  The return value is really signed. Bogus interface.*/
Dwarf_Unsigned
dwarf_add_line_entry(Dwarf_P_Debug dbg,
    Dwarf_Unsigned file_index,
    Dwarf_Addr code_address,
    Dwarf_Unsigned line_no,
    Dwarf_Signed col_no, /* Wrong, should be unsigned. */
    Dwarf_Bool is_stmt_begin,
    Dwarf_Bool is_bb_begin, Dwarf_Error * error)
{
    int retval = 0;
    Dwarf_Ubyte opc = 0;
    Dwarf_Unsigned symidx = 0;
    Dwarf_Bool isepilbeg = 0;
    Dwarf_Bool isprolend  = 0;
    Dwarf_Unsigned isa = 0;
    Dwarf_Unsigned discriminator = 0;

    retval = _dwarf_pro_add_line_entry(dbg, file_index, code_address,
        symidx,
        line_no, col_no, is_stmt_begin,
        is_bb_begin,
        opc,
        isepilbeg, isprolend, isa, discriminator,
        error);
    if (retval != DW_DLV_OK) {
        return DW_DLV_NOCOUNT;
    }
    return 0;
}

void
_dwarf_init_default_line_header_vals(Dwarf_P_Debug dbg)
{
    dbg->de_line_inits.pi_linetable_version = dbg->de_output_version;
    dbg->de_line_inits.pi_default_is_stmt =
        /* is false pro_line.h */
        DEFAULT_IS_STMT;
    dbg->de_line_inits.pi_minimum_instruction_length =
        /* is 1 or 4 depending on ifdefs in pro_line.h */
        MIN_INST_LENGTH;
    dbg->de_line_inits.pi_maximum_operations_per_instruction =
        /*  Assuming the instruction set is not VLIW,
            used in the line table */
        1;
    dbg->de_line_inits.pi_opcode_base =
        /*  is 10 in pro_line.h but should be 13 in DWARF3
            and later. */
        OPCODE_BASE;
    dbg->de_line_inits.pi_line_base =
        /* is -1 in pro_line.h */
        LINE_BASE;
    dbg->de_line_inits.pi_line_range =
        /* is 4 in pro_line.h */
        LINE_RANGE;

    /*  Applies to line table and everywhere else
        for a CU. */
    dbg->de_line_inits.pi_address_size = dbg->de_pointer_size;

    /*  Assuming no segments. */
    dbg->de_line_inits.pi_segment_selector_size = 0;
    dbg->de_line_inits.pi_segment_size = 0;
}


/*  Ask to emit DW_LNE_set_address opcode explicitly. Used by be
    to emit start of a new .text section, or to force a relocated
    address into debug line information entry. */
Dwarf_Unsigned
dwarf_lne_set_address(Dwarf_P_Debug dbg,
    Dwarf_Addr offs,
    Dwarf_Unsigned symidx, Dwarf_Error * error)
{
    int res = 0;

    res = dwarf_lne_set_address_a(dbg,offs,symidx,error);
    if (res != DW_DLV_OK) {
        return DW_DLV_NOCOUNT;
    }
    return 0;

}
int
dwarf_lne_set_address_a(Dwarf_P_Debug dbg,
    Dwarf_Addr offs,
    Dwarf_Unsigned symidx, Dwarf_Error * error)
{
    int            retval = 0;
    Dwarf_Ubyte    opc = 0;
    Dwarf_Unsigned file_index = 0;
    Dwarf_Unsigned line_no = 0;
    Dwarf_Signed   col_no = 0;
    Dwarf_Bool     is_stmt = 0;
    Dwarf_Bool     is_bb = 0;
    Dwarf_Bool     isepilbeg = 0;
    Dwarf_Bool     isprolend  = 0;
    Dwarf_Unsigned isa = 0;
    Dwarf_Unsigned discriminator = 0;


    opc = DW_LNE_set_address;
    retval = _dwarf_pro_add_line_entry(dbg, file_index, offs,
        symidx,
        line_no, col_no, is_stmt,
        is_bb,
        opc,
        isepilbeg, isprolend, isa, discriminator,
        error);
    return retval;
}

/*  Ask to emit end_seqence opcode. Used normally at the end of a
    compilation unit. Can also be used in the middle if there
    are gaps in the region described by the code address.  */
Dwarf_Unsigned
dwarf_lne_end_sequence(Dwarf_P_Debug dbg,
    Dwarf_Addr end_address, Dwarf_Error * error)
{
    int retval = 0;

    retval = dwarf_lne_end_sequence_a(dbg,end_address,error);
    if (retval != DW_DLV_OK) {
        return DW_DLV_NOCOUNT;
    }
    return 0;
}
int
dwarf_lne_end_sequence_a(Dwarf_P_Debug dbg,
    Dwarf_Addr end_address, Dwarf_Error * error)
{
    Dwarf_Ubyte    opc = 0;
    int retval = 0;
    Dwarf_Unsigned file_index = 0;
    Dwarf_Unsigned symidx = 0;
    Dwarf_Unsigned line_no = 0;
    Dwarf_Bool     is_stmt = 0;
    Dwarf_Bool     is_bb = 0;
    Dwarf_Signed   col_no = 0;/* Wrong, should be unsigned. */
    Dwarf_Bool     isepilbeg = 0;
    Dwarf_Bool     isprolend  = 0;
    Dwarf_Unsigned isa = 0;
    Dwarf_Unsigned discriminator = 0;

    opc = DW_LNE_end_sequence;
    retval = _dwarf_pro_add_line_entry(dbg, file_index, end_address,
        symidx,
        line_no, col_no, is_stmt,
        is_bb,
        opc,
        isepilbeg, isprolend, isa, discriminator,
        error);
    return retval;
}

/* As of December 2018 this returns DW_DLV_OK, DW_DLV_ERROR
    not 0, DW_DLV_NOCOUNT*/
/*  Add an entry in the internal list of lines mantained by producer.
    Opc indicates if an opcode needs to be generated, rather than just
    an entry in the matrix. During opcodes generation time, these
    opcodes will be used. */
static int
_dwarf_pro_add_line_entry(Dwarf_P_Debug dbg,
    Dwarf_Unsigned file_index,
    Dwarf_Addr code_address,
    Dwarf_Unsigned symidx,
    Dwarf_Unsigned line_no,
    Dwarf_Signed col_no,
    Dwarf_Bool is_stmt_begin,
    Dwarf_Bool is_bb_begin,
    Dwarf_Ubyte opc,
    Dwarf_Bool isepilbeg,
    Dwarf_Bool isprolend,
    Dwarf_Unsigned isa,
    Dwarf_Unsigned discriminator,
    Dwarf_Error * error)
{
    if (dbg->de_lines == NULL) {
        dbg->de_lines = (Dwarf_P_Line)
            _dwarf_p_get_alloc(dbg, sizeof(struct Dwarf_P_Line_s));
        if (dbg->de_lines == NULL) {
            DWARF_P_DBG_ERROR(dbg, DW_DLE_LINE_ALLOC, DW_DLV_ERROR);
        }
        dbg->de_last_line = dbg->de_lines;
        _dwarf_pro_reg_init(dbg,dbg->de_lines);

    } else {
        dbg->de_last_line->dpl_next = (Dwarf_P_Line)
            _dwarf_p_get_alloc(dbg, sizeof(struct Dwarf_P_Line_s));
        if (dbg->de_last_line->dpl_next == NULL) {
            DWARF_P_DBG_ERROR(dbg, DW_DLE_LINE_ALLOC, DW_DLV_ERROR);
        }
        dbg->de_last_line = dbg->de_last_line->dpl_next;
        _dwarf_pro_reg_init(dbg,dbg->de_last_line);
    }
    dbg->de_last_line->dpl_address = code_address;
    dbg->de_last_line->dpl_file = (unsigned long) file_index;
    dbg->de_last_line->dpl_line = (unsigned long) line_no;
    dbg->de_last_line->dpl_column = (unsigned long) col_no;
    dbg->de_last_line->dpl_is_stmt = is_stmt_begin;
    dbg->de_last_line->dpl_basic_block = is_bb_begin;
    dbg->de_last_line->dpl_opc = opc;
    dbg->de_last_line->dpl_r_symidx = symidx;
    dbg->de_last_line->dpl_prologue_end = isprolend;
    dbg->de_last_line->dpl_epilogue_begin = isepilbeg;
    dbg->de_last_line->dpl_isa = isa;
    dbg->de_last_line->dpl_discriminator = discriminator;
    return DW_DLV_OK;
}

/*  Add a directory declaration to the debug_line section. Stored
    in linked list. */
Dwarf_Unsigned
dwarf_add_directory_decl(Dwarf_P_Debug dbg,
    char *name,
    Dwarf_Error * error)
{
    Dwarf_Unsigned index = 0;
    int res = 0;
    /* DW_DLV_NOCOUNT on error, de_n_inc_dirs on success. */

    res = dwarf_add_directory_decl_a(dbg,name,&index,error);
    if (res != DW_DLV_OK) {
        return (Dwarf_Unsigned)DW_DLV_NOCOUNT;
    }
    return index;
}
int
dwarf_add_directory_decl_a(Dwarf_P_Debug dbg,
    char *name,
    Dwarf_Unsigned *index_in_directories,
    Dwarf_Error * error)
{
    if (dbg->de_inc_dirs == NULL) {
        dbg->de_inc_dirs = (Dwarf_P_F_Entry)
            _dwarf_p_get_alloc(dbg,
            sizeof(struct Dwarf_P_F_Entry_s));
        if (dbg->de_inc_dirs == NULL) {
            DWARF_P_DBG_ERROR(dbg, DW_DLE_INCDIR_ALLOC,
                DW_DLV_ERROR);
        }
        dbg->de_last_inc_dir = dbg->de_inc_dirs;
        dbg->de_n_inc_dirs = 1;
    } else {
        dbg->de_last_inc_dir->dfe_next = (Dwarf_P_F_Entry)
            _dwarf_p_get_alloc(dbg, sizeof(struct Dwarf_P_F_Entry_s));
        if (dbg->de_last_inc_dir->dfe_next == NULL) {
            DWARF_P_DBG_ERROR(dbg, DW_DLE_INCDIR_ALLOC,
                DW_DLV_ERROR);
        }
        dbg->de_last_inc_dir = dbg->de_last_inc_dir->dfe_next;
        dbg->de_n_inc_dirs++;
    }
    dbg->de_last_inc_dir->dfe_name =
        (char *) _dwarf_p_get_alloc(dbg, strlen(name) + 1);
    if (dbg->de_last_inc_dir->dfe_name == NULL) {
        DWARF_P_DBG_ERROR(dbg, DW_DLE_STRING_ALLOC, DW_DLV_ERROR);
    }
    strcpy(dbg->de_last_inc_dir->dfe_name, name);
    dbg->de_last_inc_dir->dfe_next = NULL;

    *index_in_directories = dbg->de_n_inc_dirs;
    return DW_DLV_OK;
}

/*  Add a file entry declaration to the debug_line section. Stored
    in linked list. The data is immediately encoded as leb128
    and stored in Dwarf_P_F_Entry_s struct. */
Dwarf_Unsigned
dwarf_add_file_decl(Dwarf_P_Debug dbg,
    char *name,
    Dwarf_Unsigned dir_idx,
    Dwarf_Unsigned time_mod,
    Dwarf_Unsigned length,
    Dwarf_Error * error)
{
    Dwarf_Unsigned filecount = 0;
    int res = 0;

    res = dwarf_add_file_decl_a(dbg,name,dir_idx,
        time_mod,length,&filecount,error);
    if (res != DW_DLV_OK) {
        return DW_DLV_NOCOUNT;
    }
    return filecount;
}
int
dwarf_add_file_decl_a(Dwarf_P_Debug dbg,
    char *name,
    Dwarf_Unsigned dir_idx,
    Dwarf_Unsigned time_mod,
    Dwarf_Unsigned length,
    Dwarf_Unsigned *file_entry_count_out,
    Dwarf_Error * error)
{
    Dwarf_P_F_Entry cur;
    char *ptr = 0;
    int nbytes_idx, nbytes_time, nbytes_len;
    char buffidx[ENCODE_SPACE_NEEDED];
    char bufftime[ENCODE_SPACE_NEEDED];
    char bufflen[ENCODE_SPACE_NEEDED];
    int res = 0;

    if (dbg->de_file_entries == NULL) {
        dbg->de_file_entries = (Dwarf_P_F_Entry)
            _dwarf_p_get_alloc(dbg, sizeof(struct Dwarf_P_F_Entry_s));
        if (dbg->de_file_entries == NULL) {
            DWARF_P_DBG_ERROR(dbg, DW_DLE_FILE_ENTRY_ALLOC,
                DW_DLV_ERROR);
        }
        cur = dbg->de_file_entries;
        dbg->de_last_file_entry = cur;
        dbg->de_n_file_entries = 1;
    } else {
        cur = dbg->de_last_file_entry;
        cur->dfe_next = (Dwarf_P_F_Entry)
            _dwarf_p_get_alloc(dbg, sizeof(struct Dwarf_P_F_Entry_s));
        if (cur->dfe_next == NULL) {
            DWARF_P_DBG_ERROR(dbg, DW_DLE_FILE_ENTRY_ALLOC,
                DW_DLV_ERROR);
        }
        cur = cur->dfe_next;
        dbg->de_last_file_entry = cur;
        dbg->de_n_file_entries++;
    }
    cur->dfe_name = (char *) _dwarf_p_get_alloc(dbg, strlen(name) + 1);
    if (cur->dfe_name == NULL) {
        DWARF_P_DBG_ERROR(dbg, DW_DLE_ALLOC_FAIL, DW_DLV_ERROR);
    }
    strcpy((char *) cur->dfe_name, name);
    res = _dwarf_pro_encode_leb128_nm(dir_idx, &nbytes_idx,
        buffidx, sizeof(buffidx));
    if (res != DW_DLV_OK) {
        /* DW_DLV_NO_ENTRY impossible */
        DWARF_P_DBG_ERROR(dbg, DW_DLE_LEB_OUT_ERROR, DW_DLV_ERROR);
    }
    res = _dwarf_pro_encode_leb128_nm(time_mod, &nbytes_time,
        bufftime, sizeof(bufftime));
    if (res != DW_DLV_OK) {
        /* DW_DLV_NO_ENTRY impossible */
        DWARF_P_DBG_ERROR(dbg, DW_DLE_LEB_OUT_ERROR, DW_DLV_ERROR);
    }
    res = _dwarf_pro_encode_leb128_nm(length, &nbytes_len,
        bufflen, sizeof(bufflen));
    if (res != DW_DLV_OK) {
        /* DW_DLV_NO_ENTRY impossible */
        DWARF_P_DBG_ERROR(dbg,DW_DLE_LEB_OUT_ERROR,DW_DLV_ERROR);
    }
    cur->dfe_args = (char *)
        _dwarf_p_get_alloc(dbg, nbytes_idx + nbytes_time + nbytes_len);
    if (cur->dfe_args == NULL) {
        DWARF_P_DBG_ERROR(dbg, DW_DLE_ALLOC_FAIL, DW_DLV_ERROR);
    }
    ptr = cur->dfe_args;
    memcpy((void *) ptr, buffidx, nbytes_idx);
    ptr += nbytes_idx;
    memcpy((void *) ptr, bufftime, nbytes_time);
    ptr += nbytes_time;
    memcpy((void *) ptr, bufflen, nbytes_len);
    cur->dfe_nbytes = nbytes_idx + nbytes_time + nbytes_len;
    cur->dfe_next = NULL;
    *file_entry_count_out = dbg->de_n_file_entries;
    return DW_DLV_OK;
}


/*  Initialize a row of the matrix for line numbers, meaning
    initialize the struct corresponding to it */
void
_dwarf_pro_reg_init(Dwarf_P_Debug dbg, Dwarf_P_Line cur_line)
{
    cur_line->dpl_address = 0;
    cur_line->dpl_file = 1;
    cur_line->dpl_line = 1;
    cur_line->dpl_column = 0;
    cur_line->dpl_is_stmt = dbg->de_line_inits.pi_default_is_stmt;
    cur_line->dpl_basic_block = false;
    cur_line->dpl_next = NULL;
    cur_line->dpl_prologue_end = 0;
    cur_line->dpl_epilogue_begin = 0;
    cur_line->dpl_isa = 0;
    cur_line->dpl_discriminator = 0;
    cur_line->dpl_opc = 0;
}
