/*

  Copyright (C) 2000,2002,2004 Silicon Graphics, Inc.  All Rights Reserved.

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
#include <stdio.h>
#include "dwarf_line.h"
#ifdef HAVE_ALLOCA_H
#include <alloca.h>
#endif


/* 
    Although source files is supposed to return the
    source files in the compilation-unit, it does
    not look for any in the statement program.  In
    other words, it ignores those defined using the
    extended opcode DW_LNE_define_file.
*/
int
dwarf_srcfiles(Dwarf_Die die,
	       char ***srcfiles,
	       Dwarf_Signed * srcfilecount, Dwarf_Error * error)
{
    /* 
       This pointer is used to scan the portion of the .debug_line
       section for the current cu. */
    Dwarf_Small *line_ptr;

    /* 
       This points to the last byte of the .debug_line portion for the 
       current cu. */
    Dwarf_Small *line_ptr_end;

    /* 
       This points to the end of the statement program prologue for the 
       current cu, and serves to check that the prologue was correctly 
       decoded. */
    Dwarf_Small *check_line_ptr;

    /* 
       Pointer to a DW_AT_stmt_list attribute in case it exists in the 
       die. */
    Dwarf_Attribute stmt_list_attr;

    /* Pointer to DW_AT_comp_dir attribute in die. */
    Dwarf_Attribute comp_dir_attr;

    /* Pointer to name of compilation directory. */
    Dwarf_Small *comp_dir = 0;

    /* 
       Offset into .debug_line specified by a DW_AT_stmt_list
       attribute. */
    Dwarf_Unsigned line_offset = 0;

    /* Some of the fields of the statement program header. */
    Dwarf_Unsigned total_length = 0;
    Dwarf_Half version = 0;
    Dwarf_Unsigned prologue_length = 0;
    Dwarf_Small special_opcode_base= 0;

    /* File name excluding included directory. */
    char *file_name = 0;

    /* Name of directory that the file is in. */
    char *dir_name = 0;

    /* Name concatenating both directory and file name. */
    char *full_name = 0;

    /* 
       This is the directory index for the file. The compilation
       directory is 0, and the first included directory is 1. */
    Dwarf_Sword dir_index = 0;

    Dwarf_Small *include_directories = 0;

    Dwarf_Sword i = 0; 
    Dwarf_Sword file_count = 0; 
    Dwarf_Sword directories_count = 0;

    /* 
       This is the current opcode read from the statement program. */

    Dwarf_Word leb128_length;

    /* This is the length of an extended opcode instr.  */

    /* 
       This points to a block of char *'s, each of which points to a
       file name. */
    char **ret_files = 0;

    /* The Dwarf_Debug this die belongs to. */
    Dwarf_Debug dbg;

    /* Used to chain the file names. */
    Dwarf_Chain curr_chain, prev_chain, head_chain = NULL;
    int resattr;
    int lres;

    int local_length_size = 0;
    /*REFERENCED*/ /* Not used in this instance of the macro */
    int local_extension_size = 0;

    int res;

    /* ***** BEGIN CODE ***** */

    /* Reset error. */
    if (error != NULL)
	*error = NULL;

    CHECK_DIE(die, DW_DLV_ERROR)
	dbg = die->di_cu_context->cc_dbg;

    resattr = dwarf_attr(die, DW_AT_stmt_list, &stmt_list_attr, error);
    if (resattr != DW_DLV_OK) {
	return resattr;
    }
    
    if (dbg->de_debug_line_index == 0) {
	_dwarf_error(dbg, error, DW_DLE_DEBUG_LINE_NULL);
	return (DW_DLV_ERROR);
    }

    res =
       _dwarf_load_section(dbg,
		           dbg->de_debug_line_index,
			   &dbg->de_debug_line,
			   error);
    if (res != DW_DLV_OK) {
	return res;
    }

    lres = dwarf_formudata(stmt_list_attr, &line_offset, error);
    if (lres != DW_DLV_OK) {
	return lres;
    }
    if (line_offset >= dbg->de_debug_line_size) {
	_dwarf_error(dbg, error, DW_DLE_LINE_OFFSET_BAD);
	return (DW_DLV_ERROR);
    }
    line_ptr = dbg->de_debug_line + line_offset;
    dwarf_dealloc(dbg, stmt_list_attr, DW_DLA_ATTR);

    /* 
       If die has DW_AT_comp_dir attribute, get the string that names
       the compilation directory. */
    resattr = dwarf_attr(die, DW_AT_comp_dir, &comp_dir_attr, error);
    if (resattr == DW_DLV_ERROR) {
	return resattr;
    }
    if (resattr == DW_DLV_OK) {
	int cres;
	char *cdir;

	cres = dwarf_formstring(comp_dir_attr, &cdir, error);
	if (cres == DW_DLV_ERROR) {
	    return cres;
	} else if (cres == DW_DLV_OK) {
	    comp_dir = (Dwarf_Small *) cdir;
	}
    }
    if (resattr == DW_DLV_OK) {
	dwarf_dealloc(dbg, comp_dir_attr, DW_DLA_ATTR);
    }

    /* 
       Following is a straightforward decoding of the statement
       program prologue information. */
    /* READ_AREA_LENGTH updates line_ptr for consumed bytes */
    READ_AREA_LENGTH(dbg, total_length, Dwarf_Unsigned,
		     line_ptr, local_length_size, local_extension_size);


    line_ptr_end = line_ptr + total_length;
    if (line_ptr_end > dbg->de_debug_line + dbg->de_debug_line_size) {
	_dwarf_error(dbg, error, DW_DLE_DEBUG_LINE_LENGTH_BAD);
	return (DW_DLV_ERROR);
    }

    READ_UNALIGNED(dbg, version, Dwarf_Half,
		   line_ptr, sizeof(Dwarf_Half));
    line_ptr += sizeof(Dwarf_Half);
    if (version != CURRENT_VERSION_STAMP) {
	_dwarf_error(dbg, error, DW_DLE_VERSION_STAMP_ERROR);
	return (DW_DLV_ERROR);
    }

    READ_UNALIGNED(dbg, prologue_length, Dwarf_Unsigned,
		   line_ptr, local_length_size);
    line_ptr += local_length_size;
    check_line_ptr = line_ptr;

    /* Skip over minimum instruction length. */
    line_ptr = line_ptr + sizeof(Dwarf_Small);

    /* Skip over default_is_stmt. */
    line_ptr = line_ptr + sizeof(Dwarf_Small);

    /* Skip over line_base. */
    line_ptr = line_ptr + sizeof(Dwarf_Sbyte);

    /* Skip over line_ptr. */
    line_ptr = line_ptr + sizeof(Dwarf_Small);

    special_opcode_base = *(Dwarf_Small *) line_ptr;
    line_ptr = line_ptr + sizeof(Dwarf_Small);

    for (i = 1; i < special_opcode_base; i++) {
	/* Skip over opcode lengths for standard opcodes. */
	line_ptr = line_ptr + sizeof(Dwarf_Small);
    }

    directories_count = 0;
    include_directories = line_ptr;
    while ((*(char *) line_ptr) != '\0') {
	line_ptr = line_ptr + strlen((char *) line_ptr) + 1;
	directories_count++;
    }
    line_ptr++;

    file_count = 0;
    while (*(char *) line_ptr != '\0') {
	Dwarf_Unsigned utmp;

	file_name = (char *) line_ptr;
	line_ptr = line_ptr + strlen((char *) line_ptr) + 1;

	DECODE_LEB128_UWORD(line_ptr, utmp)
	    dir_index = (Dwarf_Sword) utmp;
	if (dir_index > directories_count) {
	    _dwarf_error(dbg, error, DW_DLE_DIR_INDEX_BAD);
	    return (DW_DLV_ERROR);
	}

	if (dir_index == 0)
	    dir_name = (char *) comp_dir;
	else {
	    dir_name = (char *) include_directories;
	    for (i = 1; i < dir_index; i++)
		/* FIX: this is probably very slow: redoing strlen!
		   davea 9/94 */
		dir_name = dir_name + strlen(dir_name) + 1;
	}

	/* dir_name can be NULL if there is no DW_AT_comp_dir */
	if ((*file_name) == '/' || dir_name == 0)
	    full_name = file_name;
	else {
	    full_name = (char *) _dwarf_get_alloc(dbg, DW_DLA_STRING,
						  strlen(dir_name) + 1 +
						  strlen(file_name) +
						  1);
	    if (full_name == NULL) {
		_dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
		return (DW_DLV_ERROR);
	    }

	    strcpy(full_name, dir_name);
	    strcat(full_name, "/");
	    strcat(full_name, file_name);
	}

	/* Skip over time of last modification. */
	_dwarf_decode_u_leb128(line_ptr, &leb128_length);
	line_ptr = line_ptr + leb128_length;

	/* Skip over file length. */
	_dwarf_decode_u_leb128(line_ptr, &leb128_length);
	line_ptr = line_ptr + leb128_length;

	curr_chain =
	    (Dwarf_Chain) _dwarf_get_alloc(dbg, DW_DLA_CHAIN, 1);
	if (curr_chain == NULL) {
	    _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
	    return (DW_DLV_ERROR);
	}

	curr_chain->ch_item = full_name;

	if (head_chain == NULL)
	    head_chain = prev_chain = curr_chain;
	else {
	    prev_chain->ch_next = curr_chain;
	    prev_chain = curr_chain;
	}

	file_count++;
    }
    line_ptr++;

    if (line_ptr != check_line_ptr + prologue_length) {
	_dwarf_error(dbg, error, DW_DLE_LINE_PROLOG_LENGTH_BAD);
	return (DW_DLV_ERROR);
    }

    if (file_count == 0) {
	*srcfiles = NULL;
	*srcfilecount = 0;
	return (DW_DLV_NO_ENTRY);
    }

    ret_files = (char **)
	_dwarf_get_alloc(dbg, DW_DLA_LIST, file_count);
    if (ret_files == NULL) {
	_dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
	return (DW_DLV_ERROR);
    }

    curr_chain = head_chain;
    for (i = 0; i < file_count; i++) {
	*(ret_files + i) = curr_chain->ch_item;
	prev_chain = curr_chain;
	curr_chain = curr_chain->ch_next;
	dwarf_dealloc(dbg, prev_chain, DW_DLA_CHAIN);
    }

    *srcfiles = ret_files;
    *srcfilecount = file_count;
    return (DW_DLV_OK);
}


/*
	return DW_DLV_OK if ok. else DW_DLV_NO_ENTRY or DW_DLV_ERROR
*/
int
_dwarf_internal_srclines(Dwarf_Die die,
			 Dwarf_Line ** linebuf,
			 Dwarf_Signed * count,
			 Dwarf_Bool doaddrs,
			 Dwarf_Bool dolines, Dwarf_Error * error)
{
    /* 
       This pointer is used to scan the portion of the .debug_line
       section for the current cu. */
    Dwarf_Small *line_ptr;

    /* 
       This points to the last byte of the .debug_line portion for the 
       current cu. */
    Dwarf_Small *line_ptr_end;

    /* 
       This points to the end of the statement program prologue for the 
       current cu, and serves to check that the prologue was correctly 
       decoded. */
    Dwarf_Small *check_line_ptr;

    /* 
       Pointer to a DW_AT_stmt_list attribute in case it exists in the 
       die. */
    Dwarf_Attribute stmt_list_attr;

    /* Pointer to DW_AT_comp_dir attribute in die. */
    Dwarf_Attribute comp_dir_attr;

    /* Pointer to name of compilation directory. */
    Dwarf_Small *comp_dir = NULL;

    /* 
       Offset into .debug_line specified by a DW_AT_stmt_list
       attribute. */
    Dwarf_Unsigned line_offset;

    /* These are the fields of the statement program header. */
    Dwarf_Unsigned total_length;
    Dwarf_Half version;
    Dwarf_Unsigned prologue_length;
    Dwarf_Small minimum_instruction_length;
    Dwarf_Small default_is_stmt;
    Dwarf_Sbyte line_base;
    Dwarf_Small line_range;
    Dwarf_Small special_opcode_base;

    Dwarf_Small *opcode_length;
    Dwarf_Small *include_directories;
    Dwarf_File_Entry file_entries;

    /* These are the state machine state variables. */
    Dwarf_Addr address;
    Dwarf_Word file;
    Dwarf_Word line;
    Dwarf_Word column;
    Dwarf_Bool is_stmt;
    Dwarf_Bool basic_block;
    Dwarf_Bool end_sequence;

    /* 
       These pointers are used to build the list of files names by
       this cu.  cur_file_entry points to the file name being added,
       and prev_file_entry to the previous one. */
    Dwarf_File_Entry cur_file_entry, prev_file_entry;

    Dwarf_Sword i, file_entry_count, include_directories_count;

    /* 
       This is the current opcode read from the statement program. */
    Dwarf_Small opcode;

    /* 
       Pointer to a Dwarf_Line_Context_s structure that contains the
       context such as file names and include directories for the set
       of lines being generated. */
    Dwarf_Line_Context line_context;

    /* 
       This is a pointer to the current line being added to the line
       matrix. */
    Dwarf_Line curr_line;

    /* 
       These variables are used to decode leb128 numbers. Leb128_num
       holds the decoded number, and leb128_length is its length in
       bytes. */
    Dwarf_Word leb128_num;
    Dwarf_Word leb128_length;
    Dwarf_Sword advance_line;

    /* 
       This is the operand of the latest fixed_advance_pc extended
       opcode. */
    Dwarf_Half fixed_advance_pc;

    /* 
       Counts the number of lines in the line matrix. */
    Dwarf_Sword line_count = 0;

    /* This is the length of an extended opcode instr.  */
    Dwarf_Word instr_length;
    Dwarf_Small ext_opcode;

    /* 
       Used to chain together pointers to line table entries that are
       later used to create a block of Dwarf_Line entries. */
    Dwarf_Chain chain_line, head_chain = NULL, curr_chain;

    /* 
       This points to a block of Dwarf_Lines, a pointer to which is
       returned in linebuf. */
    Dwarf_Line *block_line;

    /* The Dwarf_Debug this die belongs to. */
    Dwarf_Debug dbg;
    int resattr;
    int lres;
    int local_length_size = 0;
    /*REFERENCED*/ /* Not used in this instance of the macro */
    int local_extension_size = 0;

    int res;

    /* ***** BEGIN CODE ***** */

    if (error != NULL)
	*error = NULL;

    CHECK_DIE(die, DW_DLV_ERROR)
	dbg = die->di_cu_context->cc_dbg;

    res =
       _dwarf_load_section(dbg,
		           dbg->de_debug_line_index,
			   &dbg->de_debug_line,
			   error);
    if (res != DW_DLV_OK) {
	return res;
    }

    resattr = dwarf_attr(die, DW_AT_stmt_list, &stmt_list_attr, error);
    if (resattr != DW_DLV_OK) {
	return resattr;
    }



    lres = dwarf_formudata(stmt_list_attr, &line_offset, error);
    if (lres != DW_DLV_OK) {
	return lres;
    }

    if (line_offset >= dbg->de_debug_line_size) {
	_dwarf_error(dbg, error, DW_DLE_LINE_OFFSET_BAD);
	return (DW_DLV_ERROR);
    }
    line_ptr = dbg->de_debug_line + line_offset;
    dwarf_dealloc(dbg, stmt_list_attr, DW_DLA_ATTR);

    /* 
       If die has DW_AT_comp_dir attribute, get the string that names
       the compilation directory. */
    resattr = dwarf_attr(die, DW_AT_comp_dir, &comp_dir_attr, error);
    if (resattr == DW_DLV_ERROR) {
	return resattr;
    }
    if (resattr == DW_DLV_OK) {
	int cres;
	char *cdir;

	cres = dwarf_formstring(comp_dir_attr, &cdir, error);
	if (cres == DW_DLV_ERROR) {
	    return cres;
	} else if (cres == DW_DLV_OK) {
	    comp_dir = (Dwarf_Small *) cdir;
	}
    }
    if (resattr == DW_DLV_OK) {
	dwarf_dealloc(dbg, comp_dir_attr, DW_DLA_ATTR);
    }

    /* 
       Following is a straightforward decoding of the statement
       program prologue information. */
    /* READ_AREA_LENGTH updates line_ptr for consumed bytes */
    READ_AREA_LENGTH(dbg, total_length, Dwarf_Unsigned,
		     line_ptr, local_length_size, local_extension_size);

    line_ptr_end = line_ptr + total_length;
    if (line_ptr_end > dbg->de_debug_line + dbg->de_debug_line_size) {
	_dwarf_error(dbg, error, DW_DLE_DEBUG_LINE_LENGTH_BAD);
	return (DW_DLV_ERROR);
    }

    READ_UNALIGNED(dbg, version, Dwarf_Half,
		   line_ptr, sizeof(Dwarf_Half));
    line_ptr += sizeof(Dwarf_Half);
    if (version != CURRENT_VERSION_STAMP) {
	_dwarf_error(dbg, error, DW_DLE_VERSION_STAMP_ERROR);
	return (DW_DLV_ERROR);
    }

    READ_UNALIGNED(dbg, prologue_length, Dwarf_Unsigned,
		   line_ptr, local_length_size);
    line_ptr += local_length_size;
    check_line_ptr = line_ptr;

    minimum_instruction_length = *(Dwarf_Small *) line_ptr;
    line_ptr = line_ptr + sizeof(Dwarf_Small);

    default_is_stmt = *(Dwarf_Small *) line_ptr;
    line_ptr = line_ptr + sizeof(Dwarf_Small);

    line_base = *(Dwarf_Sbyte *) line_ptr;
    line_ptr = line_ptr + sizeof(Dwarf_Sbyte);

    line_range = *(Dwarf_Small *) line_ptr;
    line_ptr = line_ptr + sizeof(Dwarf_Small);

    special_opcode_base = *(Dwarf_Small *) line_ptr;
    line_ptr = line_ptr + sizeof(Dwarf_Small);

    opcode_length = (Dwarf_Small *)
	alloca(sizeof(Dwarf_Small) * special_opcode_base);
    for (i = 1; i < special_opcode_base; i++) {
	opcode_length[i] = *(Dwarf_Small *) line_ptr;
	line_ptr = line_ptr + sizeof(Dwarf_Small);
    }

    include_directories_count = 0;
    include_directories = line_ptr;
    while ((*(char *) line_ptr) != '\0') {
	line_ptr = line_ptr + strlen((char *) line_ptr) + 1;
	include_directories_count++;
    }
    line_ptr++;

    file_entry_count = 0;
    file_entries = prev_file_entry = NULL;
    while (*(char *) line_ptr != '\0') {

	cur_file_entry = (Dwarf_File_Entry)
	    _dwarf_get_alloc(dbg, DW_DLA_FILE_ENTRY, 1);
	if (cur_file_entry == NULL) {
	    _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
	    return (DW_DLV_ERROR);
	}

	cur_file_entry->fi_file_name = (Dwarf_Small *) line_ptr;
	line_ptr = line_ptr + strlen((char *) line_ptr) + 1;

	cur_file_entry->fi_dir_index =
	    (Dwarf_Sword) _dwarf_decode_u_leb128(line_ptr,
						 &leb128_length);
	line_ptr = line_ptr + leb128_length;

	cur_file_entry->fi_time_last_mod =
	    _dwarf_decode_u_leb128(line_ptr, &leb128_length);
	line_ptr = line_ptr + leb128_length;

	cur_file_entry->fi_file_length =
	    _dwarf_decode_u_leb128(line_ptr, &leb128_length);
	line_ptr = line_ptr + leb128_length;

	if (file_entries == NULL)
	    file_entries = cur_file_entry;
	else
	    prev_file_entry->fi_next = cur_file_entry;
	prev_file_entry = cur_file_entry;

	file_entry_count++;
    }
    line_ptr++;

    if (line_ptr != check_line_ptr + prologue_length) {
	_dwarf_error(dbg, error, DW_DLE_LINE_PROLOG_LENGTH_BAD);
	return (DW_DLV_ERROR);
    }

    /* Set up context structure for this set of lines. */
    line_context = (Dwarf_Line_Context)
	_dwarf_get_alloc(dbg, DW_DLA_LINE_CONTEXT, 1);
    if (line_context == NULL) {
	_dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
	return (DW_DLV_ERROR);
    }

    /* Initialize the state machine.  */
    address = 0;
    file = 1;
    line = 1;
    column = 0;
    is_stmt = default_is_stmt;
    basic_block = false;
    end_sequence = false;

    /* Start of statement program.  */
    while (line_ptr < line_ptr_end) {
	int type;

	opcode = *(Dwarf_Small *) line_ptr;
	line_ptr++;


	/* 'type' is the output */
	WHAT_IS_OPCODE(type, opcode, special_opcode_base,
		       opcode_length, line_ptr);



	if (type == LOP_DISCARD) {
	    /* do nothing, necessary ops done */
	} else if (type == LOP_SPECIAL) {
	    /* This op code is a special op in the object, no matter
	       that it might fall into the standard op range in this
	       compile Thatis, these are special opcodes between
	       special_opcode_base and MAX_LINE_OP_CODE.  (including
	       special_opcode_base and MAX_LINE_OP_CODE) */

	    opcode = opcode - special_opcode_base;
	    address = address + minimum_instruction_length *
		(opcode / line_range);
	    line = line + line_base + opcode % line_range;

	    if (dolines) {
		curr_line =
		    (Dwarf_Line) _dwarf_get_alloc(dbg, DW_DLA_LINE, 1);
		if (curr_line == NULL) {
		    _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
		    return (DW_DLV_ERROR);
		}

		curr_line->li_address = address;
		curr_line->li_addr_line.li_l_data.li_file =
		    (Dwarf_Sword) file;
		curr_line->li_addr_line.li_l_data.li_line =
		    (Dwarf_Sword) line;
		curr_line->li_addr_line.li_l_data.li_column =
		    (Dwarf_Half) column;
		curr_line->li_addr_line.li_l_data.li_is_stmt = is_stmt;
		curr_line->li_addr_line.li_l_data.li_basic_block =
		    basic_block;
		curr_line->li_addr_line.li_l_data.li_end_sequence =
		    end_sequence;
		curr_line->li_context = line_context;
		line_count++;

		chain_line = (Dwarf_Chain)
		    _dwarf_get_alloc(dbg, DW_DLA_CHAIN, 1);
		if (chain_line == NULL) {
		    _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
		    return (DW_DLV_ERROR);
		}
		chain_line->ch_item = curr_line;

		if (head_chain == NULL)
		    head_chain = curr_chain = chain_line;
		else {
		    curr_chain->ch_next = chain_line;
		    curr_chain = chain_line;
		}
	    }

	    basic_block = false;
	} else if (type == LOP_STANDARD) {
	    switch (opcode) {

	    case DW_LNS_copy:{
		    if (opcode_length[DW_LNS_copy] != 0) {
			_dwarf_error(dbg, error,
				     DW_DLE_LINE_NUM_OPERANDS_BAD);
			return (DW_DLV_ERROR);
		    }

		    if (dolines) {

			curr_line =
			    (Dwarf_Line) _dwarf_get_alloc(dbg,
							  DW_DLA_LINE,
							  1);
			if (curr_line == NULL) {
			    _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
			    return (DW_DLV_ERROR);
			}

			curr_line->li_address = address;
			curr_line->li_addr_line.li_l_data.li_file =
			    (Dwarf_Sword) file;
			curr_line->li_addr_line.li_l_data.li_line =
			    (Dwarf_Sword) line;
			curr_line->li_addr_line.li_l_data.li_column =
			    (Dwarf_Half) column;
			curr_line->li_addr_line.li_l_data.li_is_stmt =
			    is_stmt;
			curr_line->li_addr_line.li_l_data.
			    li_basic_block = basic_block;
			curr_line->li_addr_line.li_l_data.
			    li_end_sequence = end_sequence;
			curr_line->li_context = line_context;
			line_count++;

			chain_line = (Dwarf_Chain)
			    _dwarf_get_alloc(dbg, DW_DLA_CHAIN, 1);
			if (chain_line == NULL) {
			    _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
			    return (DW_DLV_ERROR);
			}
			chain_line->ch_item = curr_line;
			if (head_chain == NULL)
			    head_chain = curr_chain = chain_line;
			else {
			    curr_chain->ch_next = chain_line;
			    curr_chain = chain_line;
			}
		    }

		    basic_block = false;
		    break;
		}

	    case DW_LNS_advance_pc:{
		    Dwarf_Unsigned utmp2;

		    if (opcode_length[DW_LNS_advance_pc] != 1) {
			_dwarf_error(dbg, error,
				     DW_DLE_LINE_NUM_OPERANDS_BAD);
			return (DW_DLV_ERROR);
		    }

		    DECODE_LEB128_UWORD(line_ptr, utmp2)
			leb128_num = (Dwarf_Word) utmp2;
		    address =
			address +
			minimum_instruction_length * leb128_num;
		    break;
		}

	    case DW_LNS_advance_line:{
		    Dwarf_Signed stmp;

		    if (opcode_length[DW_LNS_advance_line] != 1) {
			_dwarf_error(dbg, error,
				     DW_DLE_LINE_NUM_OPERANDS_BAD);
			return (DW_DLV_ERROR);
		    }

		    DECODE_LEB128_SWORD(line_ptr, stmp)
			advance_line = (Dwarf_Sword) stmp;
		    line = line + advance_line;
		    break;
		}

	    case DW_LNS_set_file:{
		    Dwarf_Unsigned utmp2;

		    if (opcode_length[DW_LNS_set_file] != 1) {
			_dwarf_error(dbg, error,
				     DW_DLE_LINE_NUM_OPERANDS_BAD);
			return (DW_DLV_ERROR);
		    }

		    DECODE_LEB128_UWORD(line_ptr, utmp2)
			file = (Dwarf_Word) utmp2;
		    break;
		}

	    case DW_LNS_set_column:{
		    Dwarf_Unsigned utmp2;

		    if (opcode_length[DW_LNS_set_column] != 1) {
			_dwarf_error(dbg, error,
				     DW_DLE_LINE_NUM_OPERANDS_BAD);
			return (DW_DLV_ERROR);
		    }

		    DECODE_LEB128_UWORD(line_ptr, utmp2)
			column = (Dwarf_Word) utmp2;
		    break;
		}

	    case DW_LNS_negate_stmt:{
		    if (opcode_length[DW_LNS_negate_stmt] != 0) {
			_dwarf_error(dbg, error,
				     DW_DLE_LINE_NUM_OPERANDS_BAD);
			return (DW_DLV_ERROR);
		    }

		    is_stmt = !is_stmt;
		    break;
		}

	    case DW_LNS_set_basic_block:{
		    if (opcode_length[DW_LNS_set_basic_block] != 0) {
			_dwarf_error(dbg, error,
				     DW_DLE_LINE_NUM_OPERANDS_BAD);
			return (DW_DLV_ERROR);
		    }

		    basic_block = true;
		    break;
		}

	    case DW_LNS_const_add_pc:{
		    opcode = MAX_LINE_OP_CODE - special_opcode_base;
		    address = address + minimum_instruction_length *
			(opcode / line_range);

		    break;
		}

	    case DW_LNS_fixed_advance_pc:{
		    if (opcode_length[DW_LNS_fixed_advance_pc] != 1) {
			_dwarf_error(dbg, error,
				     DW_DLE_LINE_NUM_OPERANDS_BAD);
			return (DW_DLV_ERROR);
		    }

		    READ_UNALIGNED(dbg, fixed_advance_pc, Dwarf_Half,
				   line_ptr, sizeof(Dwarf_Half));
		    line_ptr += sizeof(Dwarf_Half);
		    address = address + fixed_advance_pc;
		    break;
		}
	    }

	} else if (type == LOP_EXTENDED) {
	    Dwarf_Unsigned utmp3;

	    DECODE_LEB128_UWORD(line_ptr, utmp3)
		instr_length = (Dwarf_Word) utmp3;
	    /* Dwarf_Small is a ubyte and the extended opcode
	       is a ubyte, though not stated as clearly in
	       the 2.0.0 spec as one might hope.
	    */
	    ext_opcode = *(Dwarf_Small *) line_ptr;
	    line_ptr++;
	    switch (ext_opcode) {

	    case DW_LNE_end_sequence:{
		    end_sequence = true;

		    if (dolines) {
			curr_line = (Dwarf_Line)
			    _dwarf_get_alloc(dbg, DW_DLA_LINE, 1);
			if (curr_line == NULL) {
			    _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
			    return (DW_DLV_ERROR);
			}

			curr_line->li_address = address;
			curr_line->li_addr_line.li_l_data.li_file =
			    (Dwarf_Sword) file;
			curr_line->li_addr_line.li_l_data.li_line =
			    (Dwarf_Sword) line;
			curr_line->li_addr_line.li_l_data.li_column =
			    (Dwarf_Half) column;
			curr_line->li_addr_line.li_l_data.li_is_stmt =
			    default_is_stmt;
			curr_line->li_addr_line.li_l_data.
			    li_basic_block = basic_block;
			curr_line->li_addr_line.li_l_data.
			    li_end_sequence = end_sequence;
			curr_line->li_context = line_context;
			line_count++;

			chain_line = (Dwarf_Chain)
			    _dwarf_get_alloc(dbg, DW_DLA_CHAIN, 1);
			if (chain_line == NULL) {
			    _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
			    return (DW_DLV_ERROR);
			}
			chain_line->ch_item = curr_line;

			if (head_chain == NULL)
			    head_chain = curr_chain = chain_line;
			else {
			    curr_chain->ch_next = chain_line;
			    curr_chain = chain_line;
			}
		    }

		    address = 0;
		    file = 1;
		    line = 1;
		    column = 0;
		    is_stmt = default_is_stmt;
		    basic_block = false;
		    end_sequence = false;

		    break;
		}

	    case DW_LNE_set_address:{
		    if (instr_length - 1 == dbg->de_pointer_size) {
			READ_UNALIGNED(dbg, address, Dwarf_Addr,
				       line_ptr, dbg->de_pointer_size);
			if (doaddrs) {
			    curr_line =
				(Dwarf_Line) _dwarf_get_alloc(dbg,
							      DW_DLA_LINE,
							      1);
			    if (curr_line == NULL) {
				_dwarf_error(dbg, error,
					     DW_DLE_ALLOC_FAIL);
				return (DW_DLV_ERROR);
			    }

			    curr_line->li_address = address;
			    curr_line->li_addr_line.li_offset =
				line_ptr - dbg->de_debug_line;

			    line_count++;

			    chain_line = (Dwarf_Chain)
				_dwarf_get_alloc(dbg, DW_DLA_CHAIN, 1);
			    if (chain_line == NULL) {
				_dwarf_error(dbg, error,
					     DW_DLE_ALLOC_FAIL);
				return (DW_DLV_ERROR);
			    }
			    chain_line->ch_item = curr_line;

			    if (head_chain == NULL)
				head_chain = curr_chain = chain_line;
			    else {
				curr_chain->ch_next = chain_line;
				curr_chain = chain_line;
			    }
			}

			line_ptr += dbg->de_pointer_size;
		    } else {
			_dwarf_error(dbg, error,
				     DW_DLE_LINE_SET_ADDR_ERROR);
			return (DW_DLV_ERROR);
		    }

		    break;
		}

	    case DW_LNE_define_file:{

		    if (dolines) {
			cur_file_entry = (Dwarf_File_Entry)
			    _dwarf_get_alloc(dbg, DW_DLA_FILE_ENTRY, 1);
			if (cur_file_entry == NULL) {
			    _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
			    return (DW_DLV_ERROR);
			}

			cur_file_entry->fi_file_name =
			    (Dwarf_Small *) line_ptr;
			line_ptr =
			    line_ptr + strlen((char *) line_ptr) + 1;

			cur_file_entry->fi_dir_index =
			    (Dwarf_Sword)
			    _dwarf_decode_u_leb128(line_ptr,
						   &leb128_length);
			line_ptr = line_ptr + leb128_length;

			cur_file_entry->fi_time_last_mod =
			    _dwarf_decode_u_leb128(line_ptr,
						   &leb128_length);
			line_ptr = line_ptr + leb128_length;

			cur_file_entry->fi_file_length =
			    _dwarf_decode_u_leb128(line_ptr,
						   &leb128_length);
			line_ptr = line_ptr + leb128_length;

			if (file_entries == NULL)
			    file_entries = cur_file_entry;
			else
			    prev_file_entry->fi_next = cur_file_entry;
			prev_file_entry = cur_file_entry;

			file_entry_count++;
		    }
		    break;
		}

	    default:{
		    _dwarf_error(dbg, error,
				 DW_DLE_LINE_EXT_OPCODE_BAD);
		    return (DW_DLV_ERROR);
		}
	    }

	}
    }

    block_line = (Dwarf_Line *)
	_dwarf_get_alloc(dbg, DW_DLA_LIST, line_count);
    if (block_line == NULL) {
	_dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
	return (DW_DLV_ERROR);
    }

    curr_chain = head_chain;
    for (i = 0; i < line_count; i++) {
	*(block_line + i) = curr_chain->ch_item;
	head_chain = curr_chain;
	curr_chain = curr_chain->ch_next;
	dwarf_dealloc(dbg, head_chain, DW_DLA_CHAIN);
    }

    line_context->lc_file_entries = file_entries;
    line_context->lc_file_entry_count = file_entry_count;
    line_context->lc_include_directories = include_directories;
    line_context->lc_include_directories_count =
	include_directories_count;
    line_context->lc_line_count = line_count;
    line_context->lc_compilation_directory = comp_dir;
    line_context->lc_dbg = dbg;
    *count = line_count;

    *linebuf = block_line;
    return (DW_DLV_OK);
}

int
dwarf_srclines(Dwarf_Die die,
	       Dwarf_Line ** linebuf,
	       Dwarf_Signed * linecount, Dwarf_Error * error)
{
    Dwarf_Signed count;
    int res;

    res = _dwarf_internal_srclines(die, linebuf,
				   &count, /* addrlist= */ false,
				   /* linelist= */ true, error);
    if (res != DW_DLV_OK) {
	return res;
    }
    *linecount = count;
    return res;
}





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


int
dwarf_lineoff(Dwarf_Line line,
	      Dwarf_Signed * ret_lineoff, Dwarf_Error * error)
{
    if (line == NULL || ret_lineoff == 0) {
	_dwarf_error(NULL, error, DW_DLE_DWARF_LINE_NULL);
	return (DW_DLV_ERROR);
    }

    *ret_lineoff =
	(line->li_addr_line.li_l_data.li_column ==
	 0 ? -1 : line->li_addr_line.li_l_data.li_column);
    return DW_DLV_OK;
}


int
dwarf_linesrc(Dwarf_Line line, char **ret_linesrc, Dwarf_Error * error)
{
    Dwarf_Signed i;
    Dwarf_File_Entry file_entry;
    Dwarf_Small *name_buffer;
    Dwarf_Small *include_directories;
    Dwarf_Debug dbg;
    unsigned int comp_dir_len;

    if (line == NULL) {
	_dwarf_error(NULL, error, DW_DLE_DWARF_LINE_NULL);
	return (DW_DLV_ERROR);
    }

    if (line->li_context == NULL) {
	_dwarf_error(NULL, error, DW_DLE_LINE_CONTEXT_NULL);
	return (DW_DLV_ERROR);
    }
    dbg = line->li_context->lc_dbg;

    if (line->li_addr_line.li_l_data.li_file >
	line->li_context->lc_file_entry_count) {
	_dwarf_error(dbg, error, DW_DLE_LINE_FILE_NUM_BAD);
	return (DW_DLV_ERROR);
    }

    file_entry = line->li_context->lc_file_entries;
    for (i = line->li_addr_line.li_l_data.li_file - 1; i > 0; i--)
	file_entry = file_entry->fi_next;

    if (file_entry->fi_file_name == NULL) {
	_dwarf_error(dbg, error, DW_DLE_NO_FILE_NAME);
	return (DW_DLV_ERROR);
    }

    if (*(char *) file_entry->fi_file_name == '/') {
	*ret_linesrc = ((char *) file_entry->fi_file_name);
	return DW_DLV_OK;
    }

    if (file_entry->fi_dir_index == 0) {

	/* dir_index of 0 means that the compilation was in the
	   'current directory of compilation' */
	if (line->li_context->lc_compilation_directory == NULL) {
	    /* we don't actually *have* a current directory of
	       compilation: DW_AT_comp_dir was not present Rather than
	       emitting DW_DLE_NO_COMP_DIR lets just make an empty name 
	       here. In other words, do the best we can with what we do 
	       have instead of reporting an error. _dwarf_error(dbg,
	       error, DW_DLE_NO_COMP_DIR); return(DW_DLV_ERROR); */
	    comp_dir_len = 0;
	} else {
	    comp_dir_len = strlen((char *)
				  (line->li_context->
				   lc_compilation_directory));
	}

	name_buffer =
	    _dwarf_get_alloc(line->li_context->lc_dbg, DW_DLA_STRING,
			     comp_dir_len + 1 +
			     strlen((char *) file_entry->fi_file_name) +
			     1);
	if (name_buffer == NULL) {
	    _dwarf_error(line->li_context->lc_dbg, error,
			 DW_DLE_ALLOC_FAIL);
	    return (DW_DLV_ERROR);
	}

	if (comp_dir_len > 0) {
	    /* if comp_dir_len is 0 we do not want to put a / in front
	       of the fi_file_name as we just don't know anything. */
	    strcpy((char *) name_buffer,
		   (char *) (line->li_context->
			     lc_compilation_directory));
	    strcat((char *) name_buffer, "/");
	}
	strcat((char *) name_buffer, (char *) file_entry->fi_file_name);
	*ret_linesrc = ((char *) name_buffer);
	return DW_DLV_OK;
    }

    if (file_entry->fi_dir_index >
	line->li_context->lc_include_directories_count) {
	_dwarf_error(dbg, error, DW_DLE_INCL_DIR_NUM_BAD);
	return (DW_DLV_ERROR);
    }

    include_directories = line->li_context->lc_include_directories;
    for (i = file_entry->fi_dir_index - 1; i > 0; i--)
	include_directories += strlen((char *) include_directories) + 1;

    if (line->li_context->lc_compilation_directory) {
	comp_dir_len = strlen((char *)
			      (line->li_context->
			       lc_compilation_directory));
    } else {
	/* No DW_AT_comp_dir present. Do the best we can without it. */
	comp_dir_len = 0;
    }

    name_buffer = _dwarf_get_alloc(dbg, DW_DLA_STRING,
				   (*include_directories == '/' ?
				    0 : comp_dir_len + 1) +
				   strlen((char *) include_directories)
				   + 1 +
				   strlen((char *) file_entry->
					  fi_file_name) + 1);
    if (name_buffer == NULL) {
	_dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
	return (DW_DLV_ERROR);
    }

    if (*include_directories != '/') {
	if (comp_dir_len > 0) {
	    strcpy((char *) name_buffer,
		   (char *) line->li_context->lc_compilation_directory);
	    /* Who provides the / needed after the compilation
	       directory? */
	    if (name_buffer[comp_dir_len - 1] != '/') {
		/* Here we provide the / separator */
		name_buffer[comp_dir_len] = '/';	/* overwrite
							   previous nul 
							   terminator
							   with needed
							   / */
		name_buffer[comp_dir_len + 1] = 0;
	    }
	}
    } else {
	strcpy((char *) name_buffer, "");
    }
    strcat((char *) name_buffer, (char *) include_directories);
    strcat((char *) name_buffer, "/");
    strcat((char *) name_buffer, (char *) file_entry->fi_file_name);
    *ret_linesrc = ((char *) name_buffer);
    return DW_DLV_OK;
}


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


#if 0				/* Ignore this.  This needs major
				   re-work. */
/* 
    This routine works by looking for exact matches between 
    the current line address and pc, and crossovers from
    from less than pc value to greater than.  At each line
    that satisfies the above, it records a pointer to the
    line, and the difference between the address and pc.
    It then scans these pointers and picks out those with
    the smallest difference between pc and address.         
*/
int
dwarf_pclines(Dwarf_Debug dbg,
	      Dwarf_Addr pc,
	      Dwarf_Line ** linebuf,
	      Dwarf_Signed slide,
	      Dwarf_Signed * linecount, Dwarf_Error * error)
{
    /* 
       Scans the line matrix for the current cu to which a pointer
       exists in dbg. */
    Dwarf_Line line;
    Dwarf_Line prev_line;

    /* 
       These flags are for efficiency reasons. Check_line is true
       initially, but set false when the address of the current line
       is greater than pc.  It is set true only when the address of the 
       current line falls below pc.  This assumes that addresses
       within the same segment increase, and we are only interested in
       the switch from a less than pc address to a greater than.
       First_line is set true initially, but set false after the first
       line is scanned.  This is to prevent looking at the address of
       previous line when slide is DW_DLS_BACKWARD, and the first line
       is being scanned. */
    Dwarf_Bool check_line, first_line;

    /* 
       Diff tracks the smallest difference a line address and the
       input pc value. */
    Dwarf_Signed diff, i;

    /* 
       For the slide = DW_DLS_BACKWARD case, pc_less is the value of
       the address of the line immediately preceding the first line
       that has value greater than pc. For the slide = DW_DLS_FORWARD 
       case, pc_more is the values of address for the first line that
       is greater than pc. Diff is the difference between either of
       the these values and pc. */
    Dwarf_Addr pc_less, pc_more;

    /* 
       Pc_line_buf points to a chain of pointers to lines of which
       those with a diff equal to the smallest difference will be
       returned. */
    Dwarf_Line *pc_line_buf, *pc_line;

    /* 
       Chain_count counts the number of lines in the above chain for
       which the diff is equal to the smallest difference This is the
       number returned by this routine. */
    Dwarf_Signed chain_count;

    chain_head = NULL;

    check_line = true;
    first_line = true;
    diff = MAX_LINE_DIFF;

    for (i = 0; i < dbg->de_cu_line_count; i++) {

	line = *(dbg->de_cu_line_ptr + i);
	prev_line = first_line ? NULL : *(dbg->de_cu_line_ptr + i - 1);

	if (line->li_address == pc) {
	    chain_ptr = (struct chain *)
		_dwarf_get_alloc(dbg, DW_DLA_CHAIN, 1);
	    if (chain_ptr == NULL) {
		_dwarf_error(NULL, error, DW_DLE_ALLOC_FAIL);
		return (DW_DLV_ERROR);
	    }

	    chain_ptr->line = line;
	    chain_ptr->diff = diff = 0;
	    chain_ptr->next = chain_head;
	    chain_head = chain_ptr;
	} else
	    /* 
	       Look for crossover from less than pc address to greater 
	       than. */
	if (check_line && line->li_address > pc &&
		(first_line ? 0 : prev_line->li_address) < pc)

	    if (slide == DW_DLS_BACKWARD && !first_line) {
		pc_less = prev_line->li_address;
		if (pc - pc_less <= diff) {
		    chain_ptr = (struct chain *)
			_dwarf_get_alloc(dbg, DW_DLA_CHAIN, 1);
		    if (chain_ptr == NULL) {
			_dwarf_error(NULL, error, DW_DLE_ALLOC_FAIL);
			return (DW_DLV_ERROR);
		    }

		    chain_ptr->line = prev_line;
		    chain_ptr->diff = diff = pc - pc_less;
		    chain_ptr->next = chain_head;
		    chain_head = chain_ptr;
		}
		check_line = false;
	    } else if (slide == DW_DLS_FORWARD) {
		pc_more = line->li_address;
		if (pc_more - pc <= diff) {
		    chain_ptr = (struct chain *)
			_dwarf_get_alloc(dbg, DW_DLA_CHAIN, 1);
		    if (chain_ptr == NULL) {
			_dwarf_error(NULL, error, DW_DLE_ALLOC_FAIL);
			return (DW_DLV_ERROR);
		    }

		    chain_ptr->line = line;
		    chain_ptr->diff = diff = pc_more - pc;
		    chain_ptr->next = chain_head;
		    chain_head = chain_ptr;
		}
		check_line = false;
	    } else
		/* Check addresses only when they go */
		/* below pc.  */
	    if (line->li_address < pc)
		check_line = true;

	first_line = false;
    }

    chain_count = 0;
    for (chain_ptr = chain_head; chain_ptr != NULL;
	 chain_ptr = chain_ptr->next)
	if (chain_ptr->diff == diff)
	    chain_count++;

    pc_line_buf = pc_line = (Dwarf_Line)
	_dwarf_get_alloc(dbg, DW_DLA_LIST, chain_count);
    for (chain_ptr = chain_head; chain_ptr != NULL;
	 chain_ptr = chain_ptr->next)
	if (chain_ptr->diff == diff) {
	    *pc_line = chain_ptr->line;
	    pc_line++;
	}

    for (chain_ptr = chain_head; chain_ptr != NULL;) {
	chain_head = chain_ptr;
	chain_ptr = chain_ptr->next;
	dwarf_dealloc(dbg, chain_head, DW_DLA_CHAIN);
    }

    *linebuf = pc_line_buf;
    return (chain_count);
}
#endif


/*
	Return DW_DLV_OK or, if error,
	DW_DLV_ERROR.

	Thru pointers, return 2 arrays and a count
	for rqs.
*/
int
_dwarf_line_address_offsets(Dwarf_Debug dbg,
			    Dwarf_Die die,
			    Dwarf_Addr ** addrs,
			    Dwarf_Off ** offs,
			    Dwarf_Unsigned * returncount,
			    Dwarf_Error * err)
{
    Dwarf_Addr *laddrs;
    Dwarf_Off *loffsets;
    Dwarf_Signed lcount;
    Dwarf_Signed i;
    int res;
    Dwarf_Line *linebuf;

    res = _dwarf_internal_srclines(die, &linebuf,
				   &lcount, /* addrlist= */ true,
				   /* linelist= */ false, err);
    if (res != DW_DLV_OK) {
	return res;
    }
    laddrs = (Dwarf_Addr *)
	_dwarf_get_alloc(dbg, DW_DLA_ADDR, lcount);
    if (laddrs == NULL) {
	_dwarf_error(dbg, err, DW_DLE_ALLOC_FAIL);
	return (DW_DLV_ERROR);
    }
    loffsets = (Dwarf_Off *)
	_dwarf_get_alloc(dbg, DW_DLA_ADDR, lcount);
    if (loffsets == NULL) {
	_dwarf_error(dbg, err, DW_DLE_ALLOC_FAIL);
	return (DW_DLV_ERROR);
    }

    for (i = 0; i < lcount; i++) {
	laddrs[i] = linebuf[i]->li_address;
	loffsets[i] = linebuf[i]->li_addr_line.li_offset;
	dwarf_dealloc(dbg, linebuf[i], DW_DLA_LINE);
    }
    dwarf_dealloc(dbg, linebuf, DW_DLA_LIST);
    *returncount = lcount;
    *offs = loffsets;
    *addrs = laddrs;
    return DW_DLV_OK;
}
