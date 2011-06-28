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



/* The dwarf 2.0 standard dictates that only the following
 * fields can be read when an unexpected augmentation string
 * (in the cie) is encountered: CIE length, CIE_id, version and
 * augmentation; FDE: length, CIE pointer, initial location and
 * address range. Unfortunately, with the above restrictions, it
 * is impossible to read the instruction table from a CIE or a FDE
 * when a new augmentation string is encountered.
 * To fix this problem, the following layout is used, if the
 * augmentation string starts with the string "z".
 *   CIE                        FDE
 *   length                     length
 *   CIE_id                     CIE_pointer
 *   version                    initial_location
 *   augmentation               address_range
 *                              length_of_augmented_fields (*NEW*)
 *   code_alignment_factor      Any new fields as necessary
 *   data_alignment_factor      instruction_table
 *   return_address
 *   length_of_augmented fields
 *   Any new fields as necessary
 *   initial_instructions
 *
 * The type of all the old data items are the same as what is
 * described in dwarf 2.0 standard. The length_of_augmented_fields
 * is an LEB128 data item that denotes the size (in bytes) of
 * the augmented fields (not including the size of
 * "length_of_augmented_fields" itself).
 * This implementation of libdwarf will assume that the length of
 * augmented fields follow the augmenter string when the augmentation
 * starts with the string "z". It will skip over any augmented fields
 * that it does not understand to the start of  initial instructions 
 * (in case of CIE) or the instruction table (in case of FDE).
 * 
 * Future sgi versions of cie or fde should use "z1", "z2" as the
 * augmenter strings and it should guarantee that all the above fields
 * are laid out in the same fashion. Older libraries will continue to be able 
 * to read all the old data, skipping over newly added data items.
 *
 * The fde's augmented by the string "z" have a new field (signed constant, 4
   byte field)
 * called offset_into_exception_tables, following the length_of_augmented field.
 * This field contains an offset into the "_MIPS_eh_region", which describes
 * the exception handling tables.
 */

#define DW_DEBUG_FRAME_VERSION                 	1
#define DW_DEBUG_FRAME_AUGMENTER_STRING     	"mti v1"

/* The value of the offset field for Cie's. */
#define DW_CIE_OFFSET		~(0x0)

/* The augmentation string may be NULL.	*/
#define DW_EMPTY_STRING		""

#define DW_FRAME_INSTR_OPCODE_SHIFT		6
#define DW_FRAME_INSTR_OFFSET_MASK		0x3f

/* 
    This struct denotes the rule for a register in a row of
    the frame table.  In other words, it is one element of 
    the table.
*/
struct Dwarf_Reg_Rule_s {

    /* 
       Is a flag indicating whether the rule includes the offset
       field, ie whether the ru_offset field is valid or not. It is
       important, since reg+offset (offset of 0) is different from
       just 'register' since the former means 'read memory at address
       given by the sum of register contents plus offset to get the
       value'. whereas the latter means 'the value is in the register'.

       The 'register' numbers are either real registers (ie, table
       columns defined as real registers) or defined entries that are
       not really hardware registers, such as DW_FRAME_SAME_VAL or
       DW_FRAME_CFA_COL.

     */
    Dwarf_Sbyte ru_is_off;

    /* Register involved in this rule. */
    Dwarf_Half ru_register;

    /* Offset to add to register, if indicated by ru_is_offset. */
    Dwarf_Addr ru_offset;
};

typedef struct Dwarf_Frame_s *Dwarf_Frame;

/* 
    This structure represents a row of the frame table. 
    Fr_loc is the pc value for this row, and Fr_reg
    contains the rule for each column.
*/
struct Dwarf_Frame_s {

    /* Pc value corresponding to this row of the frame table. */
    Dwarf_Addr fr_loc;

    /* Rules for all the registers in this row. */
    struct Dwarf_Reg_Rule_s fr_reg[DW_FRAME_LAST_REG_NUM];

    Dwarf_Frame fr_next;
};

typedef struct Dwarf_Frame_Op_List_s *Dwarf_Frame_Op_List;

/* This is used to chain together Dwarf_Frame_Op structures. */
struct Dwarf_Frame_Op_List_s {
    Dwarf_Frame_Op *fl_frame_instr;
    Dwarf_Frame_Op_List fl_next;
};

/* 
    This structure contains all the pertinent info for a Cie. Most 
    of the fields are taken straight from the definition of a Cie.  
    Ci_cie_start points to the address (in .debug_frame) where this 
    Cie begins.  Ci_cie_instr_start points to the first byte of the 
    frame instructions for this Cie.  Ci_dbg points to the associated 
    Dwarf_Debug structure.  Ci_initial_table is a pointer to the table 
    row generated by the instructions for this Cie.
*/
struct Dwarf_Cie_s {
    Dwarf_Word ci_length;
    char *ci_augmentation;
    Dwarf_Small ci_code_alignment_factor;
    Dwarf_Sbyte ci_data_alignment_factor;
    Dwarf_Small ci_return_address_register;
    Dwarf_Small *ci_cie_start;
    Dwarf_Small *ci_cie_instr_start;
    Dwarf_Debug ci_dbg;
    Dwarf_Frame ci_initial_table;
    Dwarf_Cie ci_next;
    Dwarf_Small ci_length_size;
    Dwarf_Small ci_extension_size;
};

/*
	This structure contains all the pertinent info for a Fde.
	Most of the fields are taken straight from the definition.
	fd_cie_index is the index of the Cie associated with this
	Fde in the list of Cie's for this debug_frame.  Fd_cie
	points to the corresponsing Dwarf_Cie structure.  Fd_fde_start
	points to the start address of the Fde.  Fd_fde_instr_start
	points to the start of the instructions for this Fde.  Fd_dbg
	points to the associated Dwarf_Debug structure.
*/
struct Dwarf_Fde_s {
    Dwarf_Word fd_length;
    Dwarf_Addr fd_cie_offset;
    Dwarf_Sword fd_cie_index;
    Dwarf_Cie fd_cie;
    Dwarf_Addr fd_initial_location;
    Dwarf_Small *fd_initial_loc_pos;
    Dwarf_Addr fd_address_range;
    Dwarf_Small *fd_fde_start;
    Dwarf_Small *fd_fde_instr_start;
    Dwarf_Debug fd_dbg;
    Dwarf_Signed fd_offset_into_exception_tables;
    Dwarf_Fde fd_next;
    Dwarf_Small fd_length_size;
    Dwarf_Small fd_extension_size;
};


int
  _dwarf_frame_address_offsets(Dwarf_Debug dbg, Dwarf_Addr ** addrlist,
			       Dwarf_Off ** offsetlist,
			       Dwarf_Signed * returncount,
			       Dwarf_Error * err);
