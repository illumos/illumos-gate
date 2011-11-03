/*

  Copyright (C) 2000 Silicon Graphics, Inc.  All Rights Reserved.

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



#define DW_EXTENDED_OPCODE	0

/*
    This is used as the starting value for an algorithm
    to get the minimum difference between 2 values.
    UINT_MAX is used as our approximation to infinity.
*/
#define MAX_LINE_DIFF       UINT_MAX


/*
    This structure is used to build a list of all the
    files that are used in the current compilation unit.
    All of the fields execpt fi_next have meanings that
    are obvious from section 6.2.4 of the Libdwarf Doc.
*/
struct Dwarf_File_Entry_s {
    /* Points to string naming the file. */
    Dwarf_Small *fi_file_name;

    /* 
       Index into the list of directories of the directory in which
       this file exits. */
    Dwarf_Sword fi_dir_index;

    /* Time of last modification of the file. */
    Dwarf_Unsigned fi_time_last_mod;

    /* Length in bytes of the file. */
    Dwarf_Unsigned fi_file_length;

    /* Pointer for chaining file entries. */
    Dwarf_File_Entry fi_next;
};


typedef struct Dwarf_Line_Context_s *Dwarf_Line_Context;

/* 
    This structure provides the context in which the fields of 
    a Dwarf_Line structure are interpreted.  They come from the 
    statement program prologue.  **Updated by dwarf_srclines in 
    dwarf_line.c.
*/
struct Dwarf_Line_Context_s {
    /* 
       Points to a chain of entries providing info about source files
       for the current set of Dwarf_Line structures. */
    Dwarf_File_Entry lc_file_entries;
    /* 
       Count of number of source files for this set of Dwarf_Line
       structures. */
    Dwarf_Sword lc_file_entry_count;
    /* 
       Points to the portion of .debug_line section that contains a
       list of strings naming the included directories. */
    Dwarf_Small *lc_include_directories;

    /* Count of the number of included directories. */
    Dwarf_Sword lc_include_directories_count;

    /* Count of the number of lines for this cu. */
    Dwarf_Sword lc_line_count;

    /* Points to name of compilation directory. */
    Dwarf_Small *lc_compilation_directory;

    Dwarf_Debug lc_dbg;
};


/*
    This structure defines a row of the line table.
    All of the fields except li_offset have the exact 
    same meaning that is defined in Section 6.2.2 
    of the Libdwarf Document. 

    li_offset is used by _dwarf_addr_finder() which is called
    by rqs(1), an sgi utility for 'moving' shared libraries
    as if the static linker (ld) had linked the shared library
    at the newly-specified address.  Most libdwarf-using 
    apps will ignore li_offset and _dwarf_addr_finder().
    
*/
struct Dwarf_Line_s {
    Dwarf_Addr li_address;	/* pc value of machine instr */
    union addr_or_line_s {
	struct li_inner_s {
	    Dwarf_Sword li_file;	/* int identifying src file */
	    Dwarf_Sword li_line;	/* source file line number. */
	    Dwarf_Half li_column;	/* source file column number */
	    Dwarf_Small li_is_stmt;	/* indicate start of stmt */
	    Dwarf_Small li_basic_block;	/* indicate start basic block */
	    Dwarf_Small li_end_sequence;	/* first post sequence
						   instr */
	} li_l_data;
	Dwarf_Off li_offset;	/* for rqs */
    } li_addr_line;
    Dwarf_Line_Context li_context;	/* assoc Dwarf_Line_Context_s */
};


int
  _dwarf_line_address_offsets(Dwarf_Debug dbg,
			      Dwarf_Die die,
			      Dwarf_Addr ** addrs,
			      Dwarf_Off ** offs,
			      Dwarf_Unsigned * returncount,
			      Dwarf_Error * err);


/* The LOP, WHAT_IS_OPCODE stuff is here so it can
   be reused in 3 places.  Seemed hard to keep
   the 3 places the same without an inline func or
   a macro.

   Handling the line section where the header and the
    file being process do not match (unusual, but
   planned for in the  design of .debug_line)
   is too tricky to recode this several times and keep
   it right.
*/
#define LOP_EXTENDED 1
#define LOP_DISCARD  2
#define LOP_STANDARD 3
#define LOP_SPECIAL  4

#define HIGHEST_STANDARD_OPCODE  DW_LNS_fixed_advance_pc

#define WHAT_IS_OPCODE(type,opcode,base,opcode_length,line_ptr) \
        if( opcode < base ) {                              \
           /* we know we must treat as a standard op       \
                or a special case.                         \
           */                                              \
           if(opcode == DW_EXTENDED_OPCODE) {              \
                type = LOP_EXTENDED;                       \
           } else  if( (HIGHEST_STANDARD_OPCODE+1) >=      \
                        base) {                            \
                /* == Standard case: compile of            \
                   dwarf_line.c and object                 \
                   have same standard op codes set.        \
                                                           \
                   >  Special case: compile of dwarf_line.c\
                   has things in standard op codes list    \
                   in dwarf.h header not                   \
                   in the object: handle this as a standard\
                   op code in switch below.                \
                   The header special ops overlap the      \
                   object standard ops.                    \
                   The new standard op codes will not      \
                   appear in the object.                   \
                */                                         \
                type = LOP_STANDARD;                       \
           } else  {                                       \
                /* These are standard opcodes in the object\
                ** that were not defined  in the header    \
                ** at the time dwarf_line.c                \
                ** was compiled. Provides the ability of   \
                ** out-of-date dwarf reader to read newer  \
                ** line table data transparently.          \
                */                                         \
                int opcnt =  opcode_length[opcode];        \
                int oc;                                    \
                for(oc = 0; oc < opcnt; oc++)              \
                  {                                         \
                      /*                                    \
                      ** Read and discard operands we don't \
                      ** understand.                        \
                      ** arbitrary choice of unsigned read. \
                      ** signed read would work as well.    \
                      */                                    \
                      Dwarf_Unsigned utmp2;                 \
                      DECODE_LEB128_UWORD(line_ptr, utmp2)  \
                  }                                         \
                /* Done processing this, do not             \
                   do the switch , nor do                   \
                   special op code processing.              \
                */                                          \
                type = LOP_DISCARD;                         \
           }                                                \
                                                            \
        } else {                                            \
	   /* Is  a special op code.                        \
	   */                                               \
           type =  LOP_SPECIAL;                             \
        }

/* The following is from  the dwarf definition of 'ubyte'
   and is specifically  mentioned in section  6.2.5.1, page 54
   of the Rev 2.0.0 dwarf specification.
*/

#define MAX_LINE_OP_CODE  255
