/*

  Copyright (C) 2000, 2002 Silicon Graphics, Inc.  All Rights Reserved.

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
#include <stdlib.h>
#include "dwarf_frame.h"
#include "dwarf_arange.h"	/* using Arange as a way to build a
				   list */


static int
  __dwarf_get_fde_list_internal(Dwarf_Debug dbg,
				Dwarf_Cie ** cie_data,
				Dwarf_Signed * cie_element_count,
				Dwarf_Fde ** fde_data,
				Dwarf_Signed * fde_element_count,
				Dwarf_Small * section_ptr,
				Dwarf_Unsigned section_length,
				Dwarf_Unsigned cie_id_value,
				int use_gnu_cie_calc,
				Dwarf_Error * error);

/* 
    This function is the heart of the debug_frame stuff.  Don't even
    think of reading this without reading both the Libdwarf and 
    consumer API carefully first.  This function basically executes     
    frame instructions contained in a Cie or an Fde, but does in a      
    number of different ways depending on the information sought.       
    Start_instr_ptr points to the first byte of the frame instruction    
    stream, and final_instr_ptr to the to the first byte after the       
    last.                                                                
                                                                        
    The offsets returned in the frame instructions are factored.  That   
    is they need to be multiplied by either the code_alignment_factor    
    or the data_alignment_factor, as appropriate to obtain the actual      
    offset.  This makes it possible to expand an instruction stream      
    without the corresponding Cie.  However, when an Fde frame instr     
    sequence is being expanded there must be a valid Cie with a pointer  
    to an initial table row.                                             
                                                                         

    If successful, returns DW_DLV_OK
		And sets returned_count thru the pointer
		 if make_instr is true.
		If make_instr is false returned_count 
		 should NOT be used by the caller (returned_count
		 is set to 0 thru the pointer by this routine...)
    If unsuccessful, returns DW_DLV_ERROR
		and sets returned_error to the error code

    It does not do a whole lot of input validation being a private 
    function.  Please make sure inputs are valid.
                                                                        
    (1) If make_instr is true, it makes a list of pointers to              
    Dwarf_Frame_Op structures containing the frame instructions          
    executed.  A pointer to this list is returned in ret_frame_instr.    
    Make_instr is true only when a list of frame instructions is to be   
    returned.  In this case since we are not interested in the contents  
    of the table, the input Cie can be NULL.  This is the only case
    where the inpute Cie can be NULL.

    (2) If search_pc is true, frame instructions are executed till       
    either a location is reached that is greater than the search_pc_val
    provided, or all instructions are executed.  At this point the       
    last row of the table generated is returned in a structure.          
    A pointer to this structure is supplied in table.                    
                                                                    
    (3) This function is also used to create the initial table row       
    defined by a Cie.  In this case, the Dwarf_Cie pointer cie, is       
    NULL.  For an FDE, however, cie points to the associated Cie.        
*/
static int
_dwarf_exec_frame_instr(Dwarf_Bool make_instr,	/* Make list of frame
						   instr? */
			Dwarf_Frame_Op ** ret_frame_instr,	/* Ptr
								   to
								   list 
								   of
								   ptrs 
								   to
								   fr
								   instrs 
								 */
			Dwarf_Bool search_pc,	/* Search for a pc
						   value? */
			Dwarf_Addr search_pc_val,	/* Search for
							   this pc
							   value */
			Dwarf_Addr loc,	/* initial location value */
			Dwarf_Small * start_instr_ptr,	/* Ptr to start 
							   of frame
							   instrs.  */
			Dwarf_Small * final_instr_ptr,	/* Ptr just
							   past frame
							   instrs.  */
			Dwarf_Frame table,	/* Ptr to struct with
						   last row.  */
			Dwarf_Cie cie,	/* Ptr to Cie used by the Fde.
					   */
			Dwarf_Debug dbg,	/* Associated
						   Dwarf_Debug */
			Dwarf_Sword * returned_count,
			int *returned_error)
{
    /* Sweeps the frame instructions. */
    Dwarf_Small *instr_ptr;

    /* Obvious from the documents. */
    Dwarf_Small instr, opcode;
    Dwarf_Small reg_no, reg_noA, reg_noB;
    Dwarf_Unsigned factored_N_value;
    Dwarf_Addr new_loc;		/* must be min de_pointer_size bytes */
    Dwarf_Unsigned adv_loc;	/* must be min de_pointer_size bytes
				   and must be at least sizeof
				   Dwarf_ufixed */

    struct Dwarf_Reg_Rule_s reg[DW_FRAME_LAST_REG_NUM];


    /* This is used to end executing frame instructions.  */
    /* Becomes true when search_pc is true and loc */
    /* is greater than search_pc_val.  */
    Dwarf_Bool search_over = false;

    /* Used by the DW_FRAME_advance_loc instr */
    /* to hold the increment in pc value.  */
    Dwarf_Addr adv_pc;

    /* Contains the length in bytes of */
    /* an leb128 encoded number.  */
    Dwarf_Word leb128_length;

    /* Counts the number of frame instructions executed.  */
    Dwarf_Word instr_count = 0;

    /* 
       These contain the current fields of the current frame
       instruction. */
    Dwarf_Small fp_base_op = 0;
    Dwarf_Small fp_extended_op;
    Dwarf_Half fp_register;
    Dwarf_Unsigned fp_offset;
    Dwarf_Off fp_instr_offset;

    /* 
       Stack_table points to the row (Dwarf_Frame ie) being pushed or
       popped by a remember or restore instruction. Top_stack points to 
       the top of the stack of rows. */
    Dwarf_Frame stack_table;
    Dwarf_Frame top_stack = NULL;

    /* 
       These are used only when make_instr is true. Curr_instr is a
       pointer to the current frame instruction executed.
       Curr_instr_ptr, head_instr_list, and curr_instr_list are used
       to form a chain of Dwarf_Frame_Op structs. Dealloc_instr_ptr
       is used to deallocate the structs used to form the chain.
       Head_instr_block points to a contiguous list of pointers to the 
       Dwarf_Frame_Op structs executed. */
    Dwarf_Frame_Op *curr_instr;
    Dwarf_Chain curr_instr_item, dealloc_instr_item;
    Dwarf_Chain head_instr_chain = NULL;
    Dwarf_Chain tail_instr_chain = NULL;
    Dwarf_Frame_Op *head_instr_block;

    /* 
       These are the alignment_factors taken from the Cie provided.
       When no input Cie is provided they are set to 1, because only
       factored offsets are required. */
    Dwarf_Sword code_alignment_factor = 1;
    Dwarf_Sword data_alignment_factor = 1;

    /* 
       This flag indicates when an actual alignment factor is needed.
       So if a frame instruction that computes an offset using an
       alignment factor is encountered when this flag is set, an error
       is returned because the Cie did not have a valid augmentation. */
    Dwarf_Bool need_augmentation = false;

    Dwarf_Word i;

    /* Initialize first row from associated Cie. Using temp regs
       explicity */
    struct Dwarf_Reg_Rule_s *t1reg;
    struct Dwarf_Reg_Rule_s *t1end;
    struct Dwarf_Reg_Rule_s *t2reg;


    t1reg = reg;
    t1end = t1reg + DW_FRAME_LAST_REG_NUM;
    if (cie != NULL && cie->ci_initial_table != NULL) {
	t2reg = cie->ci_initial_table->fr_reg;
	for (; t1reg < t1end; t1reg++, t2reg++) {
	    *t1reg = *t2reg;
	}
    } else {			/* initialize with same_value */
	for (; t1reg < t1end; t1reg++) {
	    t1reg->ru_is_off = 0;
	    t1reg->ru_register = DW_FRAME_SAME_VAL;
	    t1reg->ru_offset = 0;
	}
    }

    /* 
       The idea here is that the code_alignment_factor and
       data_alignment_factor which are needed for certain instructions
       are valid only when the Cie has a proper augmentation string.
       So if the augmentation is not right, only Frame instruction can
       be read. */
    if (cie != NULL && cie->ci_augmentation != NULL) {
	code_alignment_factor = cie->ci_code_alignment_factor;
	data_alignment_factor = cie->ci_data_alignment_factor;
    } else
	need_augmentation = !make_instr;

    instr_ptr = start_instr_ptr;
    while ((instr_ptr < final_instr_ptr) && (!search_over)) {


	fp_instr_offset = instr_ptr - start_instr_ptr;
	instr = *(Dwarf_Small *) instr_ptr;
	instr_ptr += sizeof(Dwarf_Small);

	fp_base_op = (instr & 0xc0) >> 6;
	if ((instr & 0xc0) == 0x00) {
	    opcode = instr;	/* is really extended op */
	    fp_extended_op = (instr & (~(0xc0))) & 0xff;
	} else {
	    opcode = instr & 0xc0;	/* is base op */
	    fp_extended_op = 0;
	}

	fp_register = 0;
	fp_offset = 0;
	switch (opcode) {

	case DW_CFA_advance_loc:{
				/* base op */
		fp_offset = adv_pc = instr & DW_FRAME_INSTR_OFFSET_MASK;

		if (need_augmentation) {

		    *returned_error = (DW_DLE_DF_NO_CIE_AUGMENTATION);
		    return DW_DLV_ERROR;
		}
		adv_pc = adv_pc * code_alignment_factor;

		search_over = search_pc &&
		    (loc + adv_pc > search_pc_val);
		/* If gone past pc needed, retain old pc.  */
		if (!search_over)
		    loc = loc + adv_pc;
		break;
	    }

	case DW_CFA_offset:{	/* base op */
		reg_no = (instr & DW_FRAME_INSTR_OFFSET_MASK);
		if (reg_no > DW_FRAME_LAST_REG_NUM) {
		    *returned_error = DW_DLE_DF_REG_NUM_TOO_HIGH;
		    return DW_DLV_ERROR;
		}

		factored_N_value =
		    _dwarf_decode_u_leb128(instr_ptr, &leb128_length);
		instr_ptr = instr_ptr + leb128_length;

		fp_register = reg_no;
		fp_offset = factored_N_value;

		if (need_augmentation) {
		    *returned_error = (DW_DLE_DF_NO_CIE_AUGMENTATION);
		    return DW_DLV_ERROR;
		}

		reg[reg_no].ru_is_off = 1;
		reg[reg_no].ru_register = DW_FRAME_CFA_COL;
		reg[reg_no].ru_offset = factored_N_value *
		    data_alignment_factor;

		break;
	    }

	case DW_CFA_restore:{	/* base op */
		reg_no = (instr & DW_FRAME_INSTR_OFFSET_MASK);
		if (reg_no > DW_FRAME_LAST_REG_NUM) {
		    *returned_error = (DW_DLE_DF_REG_NUM_TOO_HIGH);
		    return DW_DLV_ERROR;
		}

		fp_register = reg_no;

		if (cie != NULL && cie->ci_initial_table != NULL)
		    reg[reg_no] = cie->ci_initial_table->fr_reg[reg_no];
		else if (!make_instr) {
		    *returned_error = (DW_DLE_DF_MAKE_INSTR_NO_INIT);
		    return DW_DLV_ERROR;
		}

		break;
	    }
	case DW_CFA_set_loc:{
		READ_UNALIGNED(dbg, new_loc, Dwarf_Addr,
			       instr_ptr, dbg->de_pointer_size);
		instr_ptr += dbg->de_pointer_size;
		if (new_loc <= loc) {
		    *returned_error = (DW_DLE_DF_NEW_LOC_LESS_OLD_LOC);
		    return DW_DLV_ERROR;
		}

		search_over = search_pc && (new_loc > search_pc_val);

		/* If gone past pc needed, retain old pc.  */
		if (!search_over)
		    loc = new_loc;
		fp_offset = new_loc;
		break;
	    }

	case DW_CFA_advance_loc1:{
		fp_offset = adv_loc = *(Dwarf_Small *) instr_ptr;
		instr_ptr += sizeof(Dwarf_Small);

		if (need_augmentation) {
		    *returned_error = (DW_DLE_DF_NO_CIE_AUGMENTATION);
		    return DW_DLV_ERROR;
		}
		adv_loc *= code_alignment_factor;

		search_over = search_pc &&
		    (loc + adv_loc > search_pc_val);

		/* If gone past pc needed, retain old pc.  */
		if (!search_over)
		    loc = loc + adv_loc;
		break;
	    }

	case DW_CFA_advance_loc2:{
		READ_UNALIGNED(dbg, adv_loc, Dwarf_Unsigned,
			       instr_ptr, sizeof(Dwarf_Half));
		instr_ptr += sizeof(Dwarf_Half);
		fp_offset = adv_loc;

		if (need_augmentation) {
		    *returned_error = (DW_DLE_DF_NO_CIE_AUGMENTATION);
		    return DW_DLV_ERROR;
		}
		adv_loc *= code_alignment_factor;

		search_over = search_pc &&
		    (loc + adv_loc > search_pc_val);

		/* If gone past pc needed, retain old pc.  */
		if (!search_over)
		    loc = loc + adv_loc;
		break;
	    }

	case DW_CFA_advance_loc4:{
		READ_UNALIGNED(dbg, adv_loc, Dwarf_Unsigned,
			       instr_ptr, sizeof(Dwarf_ufixed));
		instr_ptr += sizeof(Dwarf_ufixed);
		fp_offset = adv_loc;

		if (need_augmentation) {
		    *returned_error = (DW_DLE_DF_NO_CIE_AUGMENTATION);
		    return DW_DLV_ERROR;
		}
		adv_loc *= code_alignment_factor;

		search_over = search_pc &&
		    (loc + adv_loc > search_pc_val);

		/* If gone past pc needed, retain old pc.  */
		if (!search_over)
		    loc = loc + adv_loc;
		break;
	    }

	case DW_CFA_offset_extended:{
		Dwarf_Unsigned lreg;

		DECODE_LEB128_UWORD(instr_ptr, lreg)
		    reg_no = (Dwarf_Small) lreg;
		if (reg_no > DW_FRAME_LAST_REG_NUM) {
		    *returned_error = (DW_DLE_DF_REG_NUM_TOO_HIGH);
		    return DW_DLV_ERROR;
		}
		factored_N_value =
		    _dwarf_decode_u_leb128(instr_ptr, &leb128_length);
		instr_ptr += leb128_length;

		if (need_augmentation) {
		    *returned_error = (DW_DLE_DF_NO_CIE_AUGMENTATION);
		    return DW_DLV_ERROR;
		}
		reg[reg_no].ru_is_off = 1;
		reg[reg_no].ru_register = DW_FRAME_CFA_COL;
		reg[reg_no].ru_offset = factored_N_value *
		    data_alignment_factor;

		fp_register = reg_no;
		fp_offset = factored_N_value;
		break;
	    }

	case DW_CFA_restore_extended:{
		Dwarf_Unsigned lreg;

		DECODE_LEB128_UWORD(instr_ptr, lreg)
		    reg_no = (Dwarf_Small) lreg;

		if (reg_no > DW_FRAME_LAST_REG_NUM) {
		    *returned_error = (DW_DLE_DF_REG_NUM_TOO_HIGH);
		    return DW_DLV_ERROR;
		}

		if (cie != NULL && cie->ci_initial_table != NULL) {
		    reg[reg_no] = cie->ci_initial_table->fr_reg[reg_no];
		} else {
		    if (!make_instr) {
			*returned_error =
			    (DW_DLE_DF_MAKE_INSTR_NO_INIT);
			return DW_DLV_ERROR;
		    }
		}

		fp_register = reg_no;
		break;
	    }

	case DW_CFA_undefined:{
		Dwarf_Unsigned lreg;

		DECODE_LEB128_UWORD(instr_ptr, lreg)
		    reg_no = (Dwarf_Small) lreg;
		if (reg_no > DW_FRAME_LAST_REG_NUM) {
		    *returned_error = (DW_DLE_DF_REG_NUM_TOO_HIGH);
		    return DW_DLV_ERROR;
		}

		reg[reg_no].ru_is_off = 0;
		reg[reg_no].ru_register = DW_FRAME_UNDEFINED_VAL;
		reg[reg_no].ru_offset = 0;

		fp_register = reg_no;
		break;
	    }

	case DW_CFA_same_value:{
		Dwarf_Unsigned lreg;

		DECODE_LEB128_UWORD(instr_ptr, lreg)
		    reg_no = (Dwarf_Small) lreg;
		if (reg_no > DW_FRAME_LAST_REG_NUM) {
		    *returned_error = (DW_DLE_DF_REG_NUM_TOO_HIGH);
		    return DW_DLV_ERROR;
		}

		reg[reg_no].ru_is_off = 0;
		reg[reg_no].ru_register = DW_FRAME_SAME_VAL;
		reg[reg_no].ru_offset = 0;
		fp_register = reg_no;
		break;
	    }

	case DW_CFA_register:{
		Dwarf_Unsigned lreg;

		DECODE_LEB128_UWORD(instr_ptr, lreg)
		    reg_noA = (Dwarf_Small) lreg;

		if (reg_noA > DW_FRAME_LAST_REG_NUM) {
		    *returned_error = (DW_DLE_DF_REG_NUM_TOO_HIGH);
		    return DW_DLV_ERROR;
		}

		DECODE_LEB128_UWORD(instr_ptr, lreg)
		    reg_noB = (Dwarf_Small) lreg;

		if (reg_noB > DW_FRAME_LAST_REG_NUM) {
		    *returned_error = (DW_DLE_DF_REG_NUM_TOO_HIGH);
		    return DW_DLV_ERROR;
		}


		reg[reg_noA].ru_is_off = 0;
		reg[reg_noA].ru_register = reg_noB;

		reg[reg_noA].ru_offset = 0;

		fp_register = reg_noA;
		fp_offset = reg_noB;
		break;
	    }

	case DW_CFA_remember_state:{
		stack_table = (Dwarf_Frame)
		    _dwarf_get_alloc(dbg, DW_DLA_FRAME, 1);
		if (stack_table == NULL) {
		    *returned_error = (DW_DLE_DF_ALLOC_FAIL);
		    return DW_DLV_ERROR;
		}

		for (i = 0; i < DW_FRAME_LAST_REG_NUM; i++)
		    stack_table->fr_reg[i] = reg[i];

		if (top_stack != NULL)
		    stack_table->fr_next = top_stack;
		top_stack = stack_table;

		break;
	    }

	case DW_CFA_restore_state:{
		if (top_stack == NULL) {
		    *returned_error = (DW_DLE_DF_POP_EMPTY_STACK);
		    return DW_DLV_ERROR;
		}
		stack_table = top_stack;
		top_stack = stack_table->fr_next;

		for (i = 0; i < DW_FRAME_LAST_REG_NUM; i++)
		    reg[i] = stack_table->fr_reg[i];

		dwarf_dealloc(dbg, stack_table, DW_DLA_FRAME);
		break;
	    }

	case DW_CFA_def_cfa:{
		Dwarf_Unsigned lreg;

		DECODE_LEB128_UWORD(instr_ptr, lreg)
		    reg_no = (Dwarf_Small) lreg;

		if (reg_no > DW_FRAME_LAST_REG_NUM) {
		    *returned_error = (DW_DLE_DF_REG_NUM_TOO_HIGH);
		    return (DW_DLV_ERROR);
		}

		factored_N_value =
		    _dwarf_decode_u_leb128(instr_ptr, &leb128_length);
		instr_ptr += leb128_length;

		if (need_augmentation) {
		    *returned_error = (DW_DLE_DF_NO_CIE_AUGMENTATION);
		    return DW_DLV_ERROR;
		}
		reg[DW_FRAME_CFA_COL].ru_is_off = 1;
		reg[DW_FRAME_CFA_COL].ru_register = reg_no;
		reg[DW_FRAME_CFA_COL].ru_offset = factored_N_value;

		fp_register = reg_no;
		fp_offset = factored_N_value;
		break;
	    }

	case DW_CFA_def_cfa_register:{
		Dwarf_Unsigned lreg;

		DECODE_LEB128_UWORD(instr_ptr, lreg)
		    reg_no = (Dwarf_Small) lreg;

		if (reg_no > DW_FRAME_LAST_REG_NUM) {
		    *returned_error = (DW_DLE_DF_REG_NUM_TOO_HIGH);
		    return DW_DLV_ERROR;
		}

		reg[DW_FRAME_CFA_COL].ru_is_off = 0;
		reg[DW_FRAME_CFA_COL].ru_register = reg_no;
		reg[DW_FRAME_CFA_COL].ru_offset = 0;
		fp_register = reg_no;
		break;
	    }

	case DW_CFA_def_cfa_offset:{
		factored_N_value =
		    _dwarf_decode_u_leb128(instr_ptr, &leb128_length);
		instr_ptr += leb128_length;

		if (need_augmentation) {
		    *returned_error = (DW_DLE_DF_NO_CIE_AUGMENTATION);
		    return DW_DLV_ERROR;
		}
		reg[DW_FRAME_CFA_COL].ru_offset = factored_N_value;

		fp_offset = factored_N_value;
		break;
	    }

	case DW_CFA_nop:{
		break;
	    }

#ifdef DW_CFA_GNU_window_save
	case DW_CFA_GNU_window_save:{
		/* no information: this just tells unwinder to restore
		   the window registers from the previous frame's
		   window save area */
		break;
	    }
#endif
#ifdef  DW_CFA_GNU_args_size
	    /* single uleb128 is the current arg area size in bytes. No 
	       register exists yet to save this in */
	case DW_CFA_GNU_args_size:{
		Dwarf_Unsigned lreg;

		DECODE_LEB128_UWORD(instr_ptr, lreg)
		    reg_no = (Dwarf_Small) lreg;

		break;
	    }
#endif
	}

	if (make_instr) {
	    instr_count++;

	    curr_instr = (Dwarf_Frame_Op *)
		_dwarf_get_alloc(dbg, DW_DLA_FRAME_OP, 1);
	    if (curr_instr == NULL) {
		*returned_error = (DW_DLE_DF_ALLOC_FAIL);
		return DW_DLV_ERROR;
	    }

	    curr_instr->fp_base_op = fp_base_op;
	    curr_instr->fp_extended_op = fp_extended_op;
	    curr_instr->fp_register = fp_register;
	    curr_instr->fp_offset = fp_offset;
	    curr_instr->fp_instr_offset = fp_instr_offset;

	    curr_instr_item = (Dwarf_Chain)
		_dwarf_get_alloc(dbg, DW_DLA_CHAIN, 1);
	    if (curr_instr_item == NULL) {
		*returned_error = (DW_DLE_DF_ALLOC_FAIL);
		return DW_DLV_ERROR;
	    }

	    curr_instr_item->ch_item = curr_instr;
	    if (head_instr_chain == NULL)
		head_instr_chain = tail_instr_chain = curr_instr_item;
	    else {
		tail_instr_chain->ch_next = curr_instr_item;
		tail_instr_chain = curr_instr_item;
	    }
	}
    }

    /* 
       If frame instruction decoding was right we would stop exactly
       at final_instr_ptr. */
    if (instr_ptr > final_instr_ptr) {
	*returned_error = (DW_DLE_DF_FRAME_DECODING_ERROR);
	return DW_DLV_ERROR;
    }

    /* Create the last row generated.  */
    if (table != NULL) {
	t1reg = reg;
	t1end = t1reg + DW_FRAME_LAST_REG_NUM;
	table->fr_loc = loc;
	t2reg = table->fr_reg;
	for (; t1reg < t1end; t1reg++, t2reg++) {
	    *t2reg = *t1reg;
	}
    }

    /* Dealloc anything remaining on stack. */
    for (; top_stack != NULL;) {
	stack_table = top_stack;
	top_stack = top_stack->fr_next;
	dwarf_dealloc(dbg, stack_table, DW_DLA_FRAME);
    }

    if (make_instr) {
	/* Allocate list of pointers to Dwarf_Frame_Op's.  */
	head_instr_block = (Dwarf_Frame_Op *)
	    _dwarf_get_alloc(dbg, DW_DLA_FRAME_BLOCK, instr_count);
	if (head_instr_block == NULL) {
	    *returned_error = DW_DLE_DF_ALLOC_FAIL;
	    return DW_DLV_ERROR;
	}

	/* 
	   Store pointers to Dwarf_Frame_Op's in this list and
	   deallocate the structs that chain the Dwarf_Frame_Op's. */
	curr_instr_item = head_instr_chain;
	for (i = 0; i < instr_count; i++) {
	    *(head_instr_block + i) =
		*(Dwarf_Frame_Op *) curr_instr_item->ch_item;
	    dealloc_instr_item = curr_instr_item;
	    curr_instr_item = curr_instr_item->ch_next;
	    dwarf_dealloc(dbg, dealloc_instr_item->ch_item,
			  DW_DLA_FRAME_OP);
	    dwarf_dealloc(dbg, dealloc_instr_item, DW_DLA_CHAIN);
	}
	*ret_frame_instr = head_instr_block;

	*returned_count = (Dwarf_Sword) instr_count;
    } else {
	*returned_count = 0;
    }
    return DW_DLV_OK;
}

static int
qsort_compare(const void *elem1, const void *elem2)
{
    Dwarf_Fde fde1 = *(Dwarf_Fde *) elem1;
    Dwarf_Fde fde2 = *(Dwarf_Fde *) elem2;
    Dwarf_Addr addr1 = fde1->fd_initial_location;
    Dwarf_Addr addr2 = fde2->fd_initial_location;

    if (addr1 < addr2) {
	return -1;
    } else if (addr1 > addr2) {
	return 1;
    }
    return 0;
}

/*
 * This function expects as input a pointer to Dwarf_Debug (dbg) and a
 * a pointer to Cie. It finds the augmentation string and returns after 
 * setting *augmentation to point to it.
 */
static int
get_augmentation_string(Dwarf_Debug dbg,
			Dwarf_Small * cie_ptr,
			Dwarf_Unsigned cie_id_value,
			Dwarf_Small ** augmentation,
			Dwarf_Error * error)
{
    Dwarf_Unsigned cie_id;	/* must be min de_length_size bytes in 
				   size */
    Dwarf_Small version;
    int local_length_size;
    Dwarf_Unsigned length;
    /*REFERENCED*/ /* Not used in this instance of the macro */
    int local_extension_size;


    /* READ_AREA_LENGTH updates cie_ptr for consumed bytes */
    READ_AREA_LENGTH(dbg, length, Dwarf_Unsigned,
		     cie_ptr, local_length_size, local_extension_size);



    /* Read the Cie Id field. */
    READ_UNALIGNED(dbg, cie_id, Dwarf_Unsigned,
		   cie_ptr, local_length_size);
    SIGN_EXTEND(cie_id, local_length_size);
    if (cie_id != cie_id_value) {
	/* egcs-1.1.2 .eh_frame uses 0 as the distinguishing id. sgi
	   uses -1 in .debug_frame. .eh_frame not quite identical to
	   .debug_frame */
	_dwarf_error(dbg, error, DW_DLE_FRAME_VERSION_BAD);
	return (DW_DLV_ERROR);
    }
    cie_ptr += local_length_size;


    /* Read the version. */
    version = *(Dwarf_Small *) cie_ptr;
    cie_ptr++;
    if (version != DW_CIE_VERSION) {
	_dwarf_error(dbg, error, DW_DLE_FRAME_VERSION_BAD);
	return (DW_DLV_ERROR);
    }

    /* At this point, cie_ptr is pointing at the augmentation string. */
    *augmentation = cie_ptr;
    return DW_DLV_OK;
}

int
dwarf_get_cie_of_fde(Dwarf_Fde fde,
		     Dwarf_Cie * cie_returned, Dwarf_Error * error)
{
    if (fde == NULL) {
	_dwarf_error(NULL, error, DW_DLE_FDE_NULL);
	return (DW_DLV_ERROR);
    }

    *cie_returned = fde->fd_cie;
    return DW_DLV_OK;

}

/*
  For g++ .eh_frame fde and cie.
  the cie id is different as the
  definition of the cie_id in an fde
	is the distance back from the address of the
	value to the cie.
  Or 0 if this is a true cie.
  Non standard dwarf, designed this way to be
  convenient at run time for an allocated 
  (mapped into memory as part of the running image) section.
*/
int
dwarf_get_fde_list_eh(Dwarf_Debug dbg,
		      Dwarf_Cie ** cie_data,
		      Dwarf_Signed * cie_element_count,
		      Dwarf_Fde ** fde_data,
		      Dwarf_Signed * fde_element_count,
		      Dwarf_Error * error)
{
    int res;

    res =
        _dwarf_load_section(dbg,
			    dbg->de_debug_frame_eh_gnu_index,
			    &dbg->de_debug_frame_eh_gnu,
			    error);

    if (res != DW_DLV_OK) {
      return res;
    }

    res =
	__dwarf_get_fde_list_internal(dbg,
				      cie_data,
				      cie_element_count,
				      fde_data,
				      fde_element_count,
				      dbg->de_debug_frame_eh_gnu,
				      dbg->de_debug_frame_size_eh_gnu,
				      /* cie_id_value */ 0,
				      /* use_gnu_cie_calc= */ 1,
				      error);
    return res;
}



/*
  For standard dwarf .debug_frame
  cie_id is -1  in a cie, and
  is the section offset in the .debug_frame section
  of the cie otherwise.  Standard dwarf
*/
int
dwarf_get_fde_list(Dwarf_Debug dbg,
		   Dwarf_Cie ** cie_data,
		   Dwarf_Signed * cie_element_count,
		   Dwarf_Fde ** fde_data,
		   Dwarf_Signed * fde_element_count,
		   Dwarf_Error * error)
{
    int res;

    res =
        _dwarf_load_section(dbg,
			    dbg->de_debug_frame_index,
			    &dbg->de_debug_frame,
			    error);

    if (res != DW_DLV_OK) {
      return res;
    }

    res =
	__dwarf_get_fde_list_internal(dbg, cie_data,
				      cie_element_count,
				      fde_data,
				      fde_element_count,
				      dbg->de_debug_frame,
				      dbg->de_debug_frame_size,
				      DW_CIE_ID,
				      /* use_gnu_cie_calc= */ 0,
				      error);
    return res;
}

static int
__dwarf_get_fde_list_internal(Dwarf_Debug dbg,
			      Dwarf_Cie ** cie_data,
			      Dwarf_Signed * cie_element_count,
			      Dwarf_Fde ** fde_data,
			      Dwarf_Signed * fde_element_count,
			      Dwarf_Small * section_ptr,
			      Dwarf_Unsigned section_length,
			      Dwarf_Unsigned cie_id_value,
			      int use_gnu_cie_calc, Dwarf_Error * error)
{
    /* Scans the debug_frame section. */
    Dwarf_Small *frame_ptr = 0;

    /* Points to the start of the current Fde or Cie. */
    Dwarf_Small *start_frame_ptr = 0;

    /* Points to the start of the augmented entries of Fde or Cie. */
    Dwarf_Small *saved_frame_ptr = 0;

    /* Fields for the current Cie being read. */
    Dwarf_Unsigned length = 0;	/* READ_UNALIGNED needs min
				   de_length_size byte dest */
    Dwarf_Unsigned cie_base_offset = 0;	/* needs to be min
					   de_length_size byte dest */
    Dwarf_Unsigned cie_id;
    Dwarf_Small version = 0;
    Dwarf_Small *augmentation = 0;
    Dwarf_Word code_alignment_factor = 4;
    Dwarf_Sword data_alignment_factor = -1;
    Dwarf_Small return_address_register = 31;
    Dwarf_Word length_of_augmented_fields = 0;

    /* 
       New_cie points to the Cie being read, and head_cie_ptr and
       cur_cie_ptr are used for chaining them up in sequence. */
    Dwarf_Cie new_cie;
    Dwarf_Cie head_cie_ptr = NULL;
    Dwarf_Cie cur_cie_ptr;
    Dwarf_Word cie_count = 0;

    /* 
       Points to a list of contiguous pointers to Dwarf_Cie
       structures. */
    Dwarf_Cie *cie_list_ptr;

    /* Fields for the current Fde being read.  */
    Dwarf_Addr initial_location;	/* must be min de_pointer_size
					   bytes in size */
    Dwarf_Addr address_range;	/* must be min de_pointer_size bytes in 
				   size */

    /* 
       New_fde points to the current Fde being read, and head_fde_ptr
       and cur_fde_ptr are used to chain them up. */
    Dwarf_Fde new_fde;
    Dwarf_Fde head_fde_ptr = NULL;
    Dwarf_Fde cur_fde_ptr;
    Dwarf_Word fde_count = 0;

    /* 
       Points to a list of contiguous pointers to Dwarf_Fde
       structures. */
    Dwarf_Fde *fde_list_ptr;

    /* 
       Is used to check the offset field in the Fde by checking for a
       Cie at this address. */
    Dwarf_Small *fde_cie_ptr;

    Dwarf_Word leb128_length;
    Dwarf_Word i, j;
    int res;
    Dwarf_Word last_cie_index;


    Dwarf_Small *prev_augmentation_cie_ptr = 0;
    Dwarf_Small *prev_augmentation_ptr = 0;


    frame_ptr = section_ptr;

    if (frame_ptr == 0) {
	return DW_DLV_NO_ENTRY;
    }

    while (frame_ptr < section_ptr + section_length) {
	Dwarf_Small *cie_ptr_addr = 0;
	int local_extension_size = 0;
	int local_length_size = 0;

	start_frame_ptr = frame_ptr;

	/* READ_AREA_LENGTH updates frame_ptr for consumed bytes */
	READ_AREA_LENGTH(dbg, length, Dwarf_Unsigned,
			 frame_ptr, local_length_size,
			 local_extension_size);


	if (length % local_length_size != 0) {
	    _dwarf_error(dbg, error, DW_DLE_DEBUG_FRAME_LENGTH_BAD);
	    return (DW_DLV_ERROR);
	}

	if (length == 0) {
	    /* nul bytes at end of section, seen at end of egcs
	       eh_frame sections (in a.out). Take this as meaning no
	       more CIE/FDE data. We should be very close to end of
	       section. */
	    break;
	}

	cie_ptr_addr = frame_ptr;
	READ_UNALIGNED(dbg, cie_id, Dwarf_Unsigned,
		       frame_ptr, local_length_size);
	SIGN_EXTEND(cie_id, local_length_size);
	cie_base_offset = cie_id;	/* if this is a CIE, this is
					   ignored.  If it is an FDE,
					   this is the section offset
					   that allows us to get to the 
					   cie of this fde. Save it for 
					   the fde part of the 'if'
					   below */

	frame_ptr += local_length_size;

	if (cie_id == cie_id_value) {
	    /* egcs-1.1.2 .eh_frame uses 0 as the distinguishing id.
	       sgi uses -1 (in .debug_frame). .eh_frame not quite
	       identical to .debug_frame */



	    /* this is a CIE, Common Information Entry: See the dwarf
	       spec, section 6.4.1 */
	    version = *(Dwarf_Small *) frame_ptr;
	    frame_ptr++;
	    if (version != DW_CIE_VERSION) {
		_dwarf_error(dbg, error, DW_DLE_FRAME_VERSION_BAD);
		return (DW_DLV_ERROR);
	    }

	    augmentation = frame_ptr;
	    frame_ptr = frame_ptr + strlen((char *) frame_ptr) + 1;
	    if ((strcmp((char *) augmentation,
			DW_DEBUG_FRAME_AUGMENTER_STRING) == 0) ||
		(strcmp((char *) augmentation, DW_EMPTY_STRING) == 0)) {

		Dwarf_Unsigned lreg;

		DECODE_LEB128_UWORD(frame_ptr, lreg)
		    code_alignment_factor = (Dwarf_Word) lreg;


		data_alignment_factor =
		    (Dwarf_Sword) _dwarf_decode_s_leb128(frame_ptr,
							 &leb128_length);

		frame_ptr = frame_ptr + leb128_length;

		return_address_register = *(Dwarf_Small *) frame_ptr;
		if (return_address_register > DW_FRAME_LAST_REG_NUM) {
		    _dwarf_error(dbg, error,
				 DW_DLE_CIE_RET_ADDR_REG_ERROR);
		    return (DW_DLV_ERROR);
		}
		frame_ptr++;
	    } else if (augmentation[0] == 'z') {
		/* The augmentation starts with a known prefix. See the
		   dwarf_frame.h for details on the layout. */

		Dwarf_Unsigned lreg;

		DECODE_LEB128_UWORD(frame_ptr, lreg)
		    code_alignment_factor = (Dwarf_Word) lreg;


		data_alignment_factor =
		    (Dwarf_Sword) _dwarf_decode_s_leb128(frame_ptr,
							 &leb128_length);
		frame_ptr = frame_ptr + leb128_length;

		return_address_register = *(Dwarf_Small *) frame_ptr;
		if (return_address_register > DW_FRAME_LAST_REG_NUM) {
		    _dwarf_error(dbg, error,
				 DW_DLE_CIE_RET_ADDR_REG_ERROR);
		    return (DW_DLV_ERROR);
		}
		frame_ptr++;

		/* Decode the length of augmented fields. */
		DECODE_LEB128_UWORD(frame_ptr, lreg)
		    length_of_augmented_fields = (Dwarf_Word) lreg;


		/* set the frame_ptr to point at the instruction start. 
		 */
		frame_ptr += length_of_augmented_fields;
	    } else if (0 == strcmp((const char *) augmentation, "eh")) {

    	    	/*REFERENCED*/ /* Not used in this instance of the macro */
		Dwarf_Unsigned exception_table_addr;

		/* this is per egcs-1.1.2 as on RH 6.0 */
		READ_UNALIGNED(dbg, exception_table_addr,
			       Dwarf_Unsigned, frame_ptr,
			       local_length_size);
		frame_ptr += local_length_size;

		code_alignment_factor =
		    (Dwarf_Word) _dwarf_decode_s_leb128(frame_ptr,
							&leb128_length);
		frame_ptr = frame_ptr + leb128_length;


		data_alignment_factor =
		    (Dwarf_Sword) _dwarf_decode_s_leb128(frame_ptr,
							 &leb128_length);

		frame_ptr = frame_ptr + leb128_length;

		return_address_register = *(Dwarf_Small *) frame_ptr;
		if (return_address_register > DW_FRAME_LAST_REG_NUM) {
		    _dwarf_error(dbg, error,
				 DW_DLE_CIE_RET_ADDR_REG_ERROR);
		    return (DW_DLV_ERROR);
		}
		frame_ptr++;

	    } else {
		/* We do not understand the augmentation string. No
		   assumption can be made about any fields other than
		   what we have already read. */
		frame_ptr = start_frame_ptr + length + local_length_size
		    + local_extension_size;
		/* FIX -- What are the values of data_alignment_factor,
		   code_alignement_factor, return_address_register and
		   instruction start? They were clearly uninitalized in
		   the previous version and I am leaving them the same
		   way. */
	    }

	    new_cie = (Dwarf_Cie) _dwarf_get_alloc(dbg, DW_DLA_CIE, 1);
	    if (new_cie == NULL) {
		_dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
		return (DW_DLV_ERROR);
	    }

	    new_cie->ci_initial_table = NULL;
	    new_cie->ci_length = (Dwarf_Word) length;
	    new_cie->ci_length_size = local_length_size;
	    new_cie->ci_extension_size = local_extension_size;
	    new_cie->ci_augmentation = (char *) augmentation;

	    new_cie->ci_data_alignment_factor =
		(Dwarf_Sbyte) data_alignment_factor;
	    new_cie->ci_code_alignment_factor =
		(Dwarf_Small) code_alignment_factor;
	    new_cie->ci_return_address_register =
		return_address_register;
	    new_cie->ci_cie_start = start_frame_ptr;
	    new_cie->ci_cie_instr_start = frame_ptr;
	    new_cie->ci_dbg = dbg;

	    cie_count++;
	    if (head_cie_ptr == NULL)
		head_cie_ptr = cur_cie_ptr = new_cie;
	    else {
		cur_cie_ptr->ci_next = new_cie;
		cur_cie_ptr = new_cie;
	    }
	} else {



	    /* this is an FDE, Frame Description Entry, see the Dwarf
	       Spec, section 6.4.1 */
	    Dwarf_Small *cieptr;

	    Dwarf_Small *initloc = frame_ptr;
	    Dwarf_Signed offset_into_exception_tables
		/* must be min dwarf_sfixed in size */
		= (Dwarf_Signed) DW_DLX_NO_EH_OFFSET;

	    READ_UNALIGNED(dbg, initial_location, Dwarf_Addr,
			   frame_ptr, dbg->de_pointer_size);
	    frame_ptr += dbg->de_pointer_size;

	    READ_UNALIGNED(dbg, address_range, Dwarf_Addr,
			   frame_ptr, dbg->de_pointer_size);
	    frame_ptr += dbg->de_pointer_size;
	    /* Get the augmentation string from Cie to identify the
	       layout of this Fde.  */
	    if (use_gnu_cie_calc) {
		/* cie_id value is offset, in section, of the cie_id
		   itself, to use vm ptr of the value, less the value,
		   to get to the cie itself. In addition, munge
		   cie_base_offset to look *as if* it was from real
		   dwarf. */
		cieptr = cie_ptr_addr - cie_base_offset;
		cie_base_offset = cieptr - section_ptr;
	    } else {
		/* Traditional dwarf section offset is in cie_id */
		cieptr =
		    (Dwarf_Small *) (section_ptr + cie_base_offset);
	    }


	    if (prev_augmentation_cie_ptr == cieptr &&
		prev_augmentation_ptr != NULL) {
		augmentation = prev_augmentation_ptr;
	    } else {
		res = get_augmentation_string(dbg,
					      cieptr,
					      cie_id_value,
					      &augmentation, error);
		if (res != DW_DLV_OK) {
		    return res;
		}
		prev_augmentation_cie_ptr = cieptr;
		prev_augmentation_ptr = augmentation;
	    }
	    if ((strcmp((char *) augmentation,
			DW_DEBUG_FRAME_AUGMENTER_STRING) == 0) ||
		(strcmp((char *) augmentation, DW_EMPTY_STRING) == 0)) {
		/* We are pointing at the start of instructions. Do
		   nothing. */
	    } else if (augmentation[0] == 'z') {
		Dwarf_Unsigned lreg;

		DECODE_LEB128_UWORD(frame_ptr, lreg)
		    length_of_augmented_fields = (Dwarf_Word) lreg;

		saved_frame_ptr = frame_ptr;
		if (strcmp((char *) augmentation,
			   DW_CIE_AUGMENTER_STRING_V0) == 0) {
		    /* The first word is an offset into execption
		       tables. */
		    /* ?? THis presumes that the offset is always 32
		       bits */
		    READ_UNALIGNED(dbg, offset_into_exception_tables,
				   Dwarf_Addr, frame_ptr,
				   sizeof(Dwarf_sfixed));
		    SIGN_EXTEND(offset_into_exception_tables,
				sizeof(Dwarf_sfixed));
		    frame_ptr += local_length_size;
		}
		frame_ptr =
		    saved_frame_ptr + length_of_augmented_fields;
	    } else if (strcmp((const char *) augmentation, "eh") == 0) {
		/* gnu eh fde case. we do not need to do anything */
    	    	/*REFERENCED*/ /* Not used in this instance of the macro */
		Dwarf_Unsigned exception_table_addr;

		READ_UNALIGNED(dbg, exception_table_addr,
			       Dwarf_Unsigned, frame_ptr,
			       dbg->de_pointer_size);
		frame_ptr += dbg->de_pointer_size;
	    } else {
		/* We do not understand the augmentation string. No
		   assumption can be made about if the instructions is
		   present. */
		/* FIX -- The old code assumed that the instruction
		   table starts at the location pointed to by
		   frame_ptr, clearly incorrect. */
	    }
	    new_fde = (Dwarf_Fde) _dwarf_get_alloc(dbg, DW_DLA_FDE, 1);
	    if (new_fde == NULL) {
		_dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
		return (DW_DLV_ERROR);
	    }

	    new_fde->fd_length = (Dwarf_Word) length;
	    new_fde->fd_length_size = local_length_size;
	    new_fde->fd_extension_size = local_extension_size;
	    new_fde->fd_cie_offset = cie_base_offset;
	    new_fde->fd_initial_location = initial_location;
	    new_fde->fd_initial_loc_pos = initloc;
	    new_fde->fd_address_range = address_range;
	    new_fde->fd_fde_start = start_frame_ptr;
	    new_fde->fd_fde_instr_start = frame_ptr;
	    new_fde->fd_dbg = dbg;
	    new_fde->fd_offset_into_exception_tables =
		offset_into_exception_tables;

	    fde_count++;
	    if (head_fde_ptr == NULL)
		head_fde_ptr = cur_fde_ptr = new_fde;
	    else {
		cur_fde_ptr->fd_next = new_fde;
		cur_fde_ptr = new_fde;
	    }
	}

	/* Skip over instructions to start of next frame. */
	frame_ptr = start_frame_ptr + length + local_length_size +
	    local_extension_size;
    }

    if (cie_count > 0) {
	cie_list_ptr = (Dwarf_Cie *)
	    _dwarf_get_alloc(dbg, DW_DLA_LIST, cie_count);
    } else {
	return (DW_DLV_NO_ENTRY);
    }
    if (cie_list_ptr == NULL) {
	_dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
	return (DW_DLV_ERROR);
    }
    /* Return arguments. */
    *cie_data = cie_list_ptr;
    *cie_element_count = cie_count;
    dbg->de_cie_data = cie_list_ptr;
    dbg->de_cie_count = cie_count;

    cur_cie_ptr = head_cie_ptr;
    for (i = 0; i < cie_count; i++) {
	*(cie_list_ptr + i) = cur_cie_ptr;
	cur_cie_ptr = cur_cie_ptr->ci_next;
    }

    if (fde_count > 0) {
	fde_list_ptr = (Dwarf_Fde *)
	    _dwarf_get_alloc(dbg, DW_DLA_LIST, fde_count);
    } else {
	return (DW_DLV_NO_ENTRY);
    }
    if (fde_list_ptr == NULL) {
	_dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
	return (DW_DLV_ERROR);
    }
    /* Return arguments. */
    *fde_data = fde_list_ptr;
    *fde_element_count = fde_count;
    dbg->de_fde_data = fde_list_ptr;
    dbg->de_fde_count = fde_count;
    last_cie_index = 0;

    cur_fde_ptr = head_fde_ptr;
    for (i = 0; i < fde_count; i++) {
	Dwarf_Sword new_cie_index = (Dwarf_Sword) cie_count;

	*(fde_list_ptr + i) = cur_fde_ptr;

	fde_cie_ptr = (Dwarf_Small *) (section_ptr +
				       cur_fde_ptr->fd_cie_offset);


	/* we assume that the next fde has the same cie as the ** last
	   fde and resume the search where we left off */
	for (j = last_cie_index; j < cie_count; j++) {
	    Dwarf_Cie ciep = (Dwarf_Cie) * (cie_list_ptr + j);

	    if (ciep->ci_cie_start == fde_cie_ptr) {
		new_cie_index = (Dwarf_Sword) j;
		break;
	    }
	}
	/* did not find it above, start from 0 and try again */
	if (new_cie_index == cie_count) {
	    for (j = 0; j < last_cie_index; ++j) {
		Dwarf_Cie ciep = (Dwarf_Cie) * (cie_list_ptr + j);

		if (ciep->ci_cie_start == fde_cie_ptr) {
		    new_cie_index = (Dwarf_Sword) j;
		    break;
		}
	    }
	}
	j = new_cie_index;
	last_cie_index = new_cie_index;
	if (j == cie_count) {
	    _dwarf_error(dbg, error, DW_DLE_NO_CIE_FOR_FDE);
	    return (DW_DLV_ERROR);
	} else {
	    cur_fde_ptr->fd_cie_index = (Dwarf_Sword) j;
	    cur_fde_ptr->fd_cie = *(cie_list_ptr + j);
	}

	cur_fde_ptr = cur_fde_ptr->fd_next;
    }

    /* sort the list by the address, so that dwarf_get_fde_at_pc() can
       binary search this list. */
    qsort((void *) fde_list_ptr, fde_count, sizeof(Dwarf_Ptr),
	  qsort_compare);

    return (DW_DLV_OK);
}

/*
   Only works on dwarf sections, not eh_frame
*/
int
dwarf_get_fde_for_die(Dwarf_Debug dbg,
		      Dwarf_Die die,
		      Dwarf_Fde * ret_fde, Dwarf_Error * error)
{
    Dwarf_Attribute attr;
    Dwarf_Unsigned fde_offset;
    Dwarf_Signed signdval;
    Dwarf_Unsigned length;	/* must be min de_length_size bytes */
    Dwarf_Signed signed_offset;	/* must be min de_length_size bytes */
    Dwarf_Addr initial_location;	/* must be min de_pointer_size 
					   bytes */
    Dwarf_Addr address_range;	/* must be min de_pointer_size bytes */
    Dwarf_Fde new_fde;
    unsigned char *fde_ptr;
    Dwarf_Small *saved_fde_ptr;
    unsigned char *cie_ptr;
    unsigned char *start_cie_ptr;
    Dwarf_Cie new_cie;

    /* Fields for the current Cie being read. */
    Dwarf_Small version;
    Dwarf_Small *augmentation;
    Dwarf_Word code_alignment_factor;
    Dwarf_Sword data_alignment_factor;
    Dwarf_Small return_address_register;
    Dwarf_Word length_of_augmented_fields;
    Dwarf_Signed offset_into_exception_tables =
	(Dwarf_Signed) DW_DLX_NO_EH_OFFSET;
    int res;
    int resattr;
    int sdatares;
    int fde_local_extension_size = 0;
    int fde_local_length_size = 0;
    int cie_local_extension_size = 0;
    int cie_local_length_size = 0;


    Dwarf_Word leb128_length;

    if (die == NULL) {
	_dwarf_error(NULL, error, DW_DLE_DIE_NULL);
	return (DW_DLV_ERROR);
    }

    resattr = dwarf_attr(die, DW_AT_MIPS_fde, &attr, error);
    if (resattr != DW_DLV_OK) {
	return resattr;
    }

    /* why is this formsdata? FIX */
    sdatares = dwarf_formsdata(attr, &signdval, error);
    if (sdatares != DW_DLV_OK) {
	return sdatares;
    }

    res = 
        _dwarf_load_section(dbg,
			    dbg->de_debug_frame_index,
			    &dbg->de_debug_frame,
			    error);
    if (res != DW_DLV_OK) {
      return res;
    }

    fde_offset = signdval;
    fde_ptr = (dbg->de_debug_frame + fde_offset);

    /* READ_AREA_LENGTH updates fde_ptr for consumed bytes */
    READ_AREA_LENGTH(dbg, length, Dwarf_Unsigned,
		     fde_ptr, fde_local_length_size,
		     fde_local_extension_size);


    if (length % fde_local_length_size != 0) {
	_dwarf_error(dbg, error, DW_DLE_DEBUG_FRAME_LENGTH_BAD);
	return (DW_DLV_ERROR);
    }

    READ_UNALIGNED(dbg, signed_offset, Dwarf_Signed,
		   fde_ptr, fde_local_length_size);
    SIGN_EXTEND(signed_offset, fde_local_length_size);
    fde_ptr += fde_local_length_size;

    READ_UNALIGNED(dbg, initial_location, Dwarf_Addr,
		   fde_ptr, dbg->de_pointer_size);
    fde_ptr += dbg->de_pointer_size;

    READ_UNALIGNED(dbg, address_range, Dwarf_Addr,
		   fde_ptr, dbg->de_pointer_size);
    fde_ptr += dbg->de_pointer_size;

    res = get_augmentation_string(dbg,
				  (Dwarf_Small *) (dbg->de_debug_frame +
						   signed_offset),
				  DW_CIE_ID, &augmentation, error);
    if (res != DW_DLV_OK) {
	return res;
    }

    if ((strcmp((char *) augmentation, DW_DEBUG_FRAME_AUGMENTER_STRING)
	 == 0) ||
	(strcmp((char *) augmentation, DW_EMPTY_STRING) == 0)) {
	/* Do nothing. The fde_ptr is pointing at start of
	   instructions. */
    } else if (augmentation[0] == 'z') {
	/* The augmentation starts with a known prefix. See the
	   dwarf_frame.h for details on the layout. */

	Dwarf_Unsigned lreg;

	DECODE_LEB128_UWORD(fde_ptr, lreg)
	    length_of_augmented_fields = (Dwarf_Word) lreg;

	saved_fde_ptr = fde_ptr;
	if (strcmp((char *) augmentation, DW_CIE_AUGMENTER_STRING_V0) ==
	    0) {
	    /* The first word is an offset into execption tables. */
	    READ_UNALIGNED(dbg, offset_into_exception_tables,
			   Dwarf_Signed, fde_ptr, sizeof(Dwarf_sfixed));
	    SIGN_EXTEND(offset_into_exception_tables,
			sizeof(Dwarf_sfixed));
	    fde_ptr += sizeof(Dwarf_sfixed);
	}
	fde_ptr = saved_fde_ptr + length_of_augmented_fields;
    } else {
	/* We do not understand the augmentation string. No assumption
	   can be made about if the instructions is present. */
	/* FIX -- The old code assumed that the instruction table
	   starts at location pointed to by fde_ptr, clearly incorrect. 
	 */
    }

    new_fde = (Dwarf_Fde) _dwarf_get_alloc(dbg, DW_DLA_FDE, 1);
    if (new_fde == NULL) {
	_dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
	return (DW_DLV_ERROR);
    }

    new_fde->fd_length = (Dwarf_Word) length;
    new_fde->fd_length_size = fde_local_length_size;
    new_fde->fd_extension_size = fde_local_extension_size;
    new_fde->fd_cie_offset = signed_offset;
    new_fde->fd_initial_location = initial_location;
    new_fde->fd_address_range = address_range;
    new_fde->fd_fde_start = dbg->de_debug_frame + fde_offset;
    new_fde->fd_fde_instr_start = (Dwarf_Small *) fde_ptr;
    new_fde->fd_dbg = dbg;
    new_fde->fd_offset_into_exception_tables =
	offset_into_exception_tables;

    /* now read the cie corresponding to the fde */
    cie_ptr = (dbg->de_debug_frame + signed_offset);
    start_cie_ptr = cie_ptr;

    /* READ_AREA_LENGTH updates cie_ptr for consumed bytes */
    READ_AREA_LENGTH(dbg, length, Dwarf_Unsigned,
		     cie_ptr, cie_local_length_size,
		     cie_local_extension_size);


    if (length % cie_local_length_size != 0) {
	_dwarf_error(dbg, error, DW_DLE_DEBUG_FRAME_LENGTH_BAD);
	return (DW_DLV_ERROR);
    }

    READ_UNALIGNED(dbg, signed_offset, Dwarf_Signed,
		   cie_ptr, cie_local_length_size);
    SIGN_EXTEND(signed_offset, cie_local_length_size);
    cie_ptr += cie_local_length_size;

    if (signed_offset == DW_CIE_ID) {

	version = *(Dwarf_Small *) cie_ptr;
	cie_ptr++;
	if (version != DW_CIE_VERSION) {
	    _dwarf_error(dbg, error, DW_DLE_FRAME_VERSION_BAD);
	    return (DW_DLV_ERROR);
	}

	augmentation = cie_ptr;
	cie_ptr = cie_ptr + strlen((char *) cie_ptr) + 1;
	if ((strcmp((char *) augmentation,
		    DW_DEBUG_FRAME_AUGMENTER_STRING) == 0) ||
	    (strcmp((char *) augmentation, DW_EMPTY_STRING) == 0)) {

	    Dwarf_Unsigned lreg;

	    DECODE_LEB128_UWORD(cie_ptr, lreg)
		code_alignment_factor = (Dwarf_Word) lreg;


	    data_alignment_factor = (Dwarf_Sword)
		_dwarf_decode_s_leb128(cie_ptr, &leb128_length);
	    cie_ptr = cie_ptr + leb128_length;

	    return_address_register = *(Dwarf_Small *) cie_ptr;
	    if (return_address_register > DW_FRAME_LAST_REG_NUM) {
		_dwarf_error(dbg, error, DW_DLE_CIE_RET_ADDR_REG_ERROR);
		return (DW_DLV_ERROR);
	    }
	    cie_ptr++;
	} else if (augmentation[0] == 'z') {
	    /* The augmentation starts with a known prefix. We can
	       asssume that the first field is the length of the
	       augmented fields. */

	    Dwarf_Unsigned lreg;

	    DECODE_LEB128_UWORD(cie_ptr, lreg)
		code_alignment_factor = (Dwarf_Word) lreg;
	    data_alignment_factor = (Dwarf_Sword)
		_dwarf_decode_s_leb128(cie_ptr, &leb128_length);
	    cie_ptr = cie_ptr + leb128_length;

	    return_address_register = *(Dwarf_Small *) cie_ptr;
	    if (return_address_register > DW_FRAME_LAST_REG_NUM) {
		_dwarf_error(dbg, error, DW_DLE_CIE_RET_ADDR_REG_ERROR);
		return (DW_DLV_ERROR);
	    }
	    cie_ptr++;
	    /* Decode the length of augmented fields. */
	    DECODE_LEB128_UWORD(cie_ptr, lreg)
		length_of_augmented_fields = (Dwarf_Word) lreg;

	    /* set the cie_ptr to point at the instruction start. */
	    cie_ptr += length_of_augmented_fields;
	} else if (strcmp((const char *) augmentation, "eh") == 0) {
	    Dwarf_Unsigned lreg;

	    DECODE_LEB128_UWORD(cie_ptr, lreg)
		code_alignment_factor = (Dwarf_Word) lreg;


	    data_alignment_factor = (Dwarf_Sword)
		_dwarf_decode_s_leb128(cie_ptr, &leb128_length);
	    cie_ptr = cie_ptr + leb128_length;

	    return_address_register = *(Dwarf_Small *) cie_ptr;
	    if (return_address_register > DW_FRAME_LAST_REG_NUM) {
		_dwarf_error(dbg, error, DW_DLE_CIE_RET_ADDR_REG_ERROR);
		return (DW_DLV_ERROR);
	    }
	    cie_ptr++;

	} else {
	    /* We do not understand the augmentation string. No
	       assumption can be made about any fields other than what
	       we have already read. */
	    cie_ptr = start_cie_ptr + length + cie_local_length_size
		+ cie_local_extension_size;
	    /* FIX -- What are the values of data_alignment_factor,
	       code_alignement_factor, return_address_register and
	       instruction start? They were clearly uninitalized in
	       the previous version and I am leaving them the same way. 
	     */
	}

	new_cie = (Dwarf_Cie) _dwarf_get_alloc(dbg, DW_DLA_CIE, 1);
	if (new_cie == NULL) {
	    _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
	    return (DW_DLV_ERROR);
	}

	new_cie->ci_initial_table = NULL;
	new_cie->ci_length = (Dwarf_Word) length;
	new_cie->ci_length_size = cie_local_length_size;
	new_cie->ci_extension_size = cie_local_extension_size;
	new_cie->ci_augmentation = (char *) augmentation;
	new_cie->ci_data_alignment_factor =
	    (Dwarf_Sbyte) data_alignment_factor;
	new_cie->ci_code_alignment_factor =
	    (Dwarf_Small) code_alignment_factor;
	new_cie->ci_return_address_register = return_address_register;
	new_cie->ci_cie_start = start_cie_ptr;
	new_cie->ci_cie_instr_start = cie_ptr;
	new_cie->ci_dbg = dbg;
    } else {
	_dwarf_error(dbg, error, DW_DLE_NO_CIE_FOR_FDE);
	return (DW_DLV_ERROR);
    }
    new_fde->fd_cie = new_cie;

    *ret_fde = new_fde;
    return DW_DLV_OK;
}


int
dwarf_get_fde_range(Dwarf_Fde fde,
		    Dwarf_Addr * low_pc,
		    Dwarf_Unsigned * func_length,
		    Dwarf_Ptr * fde_bytes,
		    Dwarf_Unsigned * fde_byte_length,
		    Dwarf_Off * cie_offset,
		    Dwarf_Signed * cie_index,
		    Dwarf_Off * fde_offset, Dwarf_Error * error)
{
    int res;
    Dwarf_Debug dbg;

    if (fde == NULL) {
	_dwarf_error(NULL, error, DW_DLE_FDE_NULL);
	return (DW_DLV_ERROR);
    }

    dbg = fde->fd_dbg;
    if (dbg == NULL) {
	_dwarf_error(NULL, error, DW_DLE_FDE_DBG_NULL);
	return (DW_DLV_ERROR);
    }

    res =
        _dwarf_load_section(dbg,
			    dbg->de_debug_frame_index,
			    &dbg->de_debug_frame,
			    error);
    if (res != DW_DLV_OK) {
        return res;
    }

    if (low_pc != NULL)
	*low_pc = fde->fd_initial_location;
    if (func_length != NULL)
	*func_length = fde->fd_address_range;
    if (fde_bytes != NULL)
	*fde_bytes = fde->fd_fde_start;
    if (fde_byte_length != NULL)
	*fde_byte_length = fde->fd_length;
    if (cie_offset != NULL)
	*cie_offset = fde->fd_cie_offset;
    if (cie_index != NULL)
	*cie_index = fde->fd_cie_index;
    if (fde_offset != NULL)
	*fde_offset = fde->fd_fde_start - dbg->de_debug_frame;

    return DW_DLV_OK;
}

int
dwarf_get_fde_exception_info(Dwarf_Fde fde,
			     Dwarf_Signed *
			     offset_into_exception_tables,
			     Dwarf_Error * error)
{
    Dwarf_Debug dbg;

    dbg = fde->fd_dbg;
    if (dbg == NULL) {
	_dwarf_error(NULL, error, DW_DLE_FDE_DBG_NULL);
	return (DW_DLV_ERROR);
    }
    *offset_into_exception_tables =
	fde->fd_offset_into_exception_tables;
    return DW_DLV_OK;
}


int
dwarf_get_cie_info(Dwarf_Cie cie,
		   Dwarf_Unsigned * bytes_in_cie,
		   Dwarf_Small * version,
		   char **augmenter,
		   Dwarf_Unsigned * code_alignment_factor,
		   Dwarf_Signed * data_alignment_factor,
		   Dwarf_Half * return_address_register,
		   Dwarf_Ptr * initial_instructions,
		   Dwarf_Unsigned * initial_instructions_length,
		   Dwarf_Error * error)
{
    Dwarf_Debug dbg;

    if (cie == NULL) {
	_dwarf_error(NULL, error, DW_DLE_CIE_NULL);
	return (DW_DLV_ERROR);
    }

    dbg = cie->ci_dbg;
    if (dbg == NULL) {
	_dwarf_error(NULL, error, DW_DLE_CIE_DBG_NULL);
	return (DW_DLV_ERROR);
    }

    if (version != NULL)
	*version = DW_CIE_VERSION;
    if (augmenter != NULL)
	*augmenter = cie->ci_augmentation;
    if (code_alignment_factor != NULL)
	*code_alignment_factor = cie->ci_code_alignment_factor;
    if (data_alignment_factor != NULL)
	*data_alignment_factor = cie->ci_data_alignment_factor;
    if (return_address_register != NULL)
	*return_address_register = cie->ci_return_address_register;
    if (initial_instructions != NULL)
	*initial_instructions = cie->ci_cie_instr_start;
    if (initial_instructions_length != NULL) {
	*initial_instructions_length = cie->ci_length +
	    cie->ci_length_size +
	    cie->ci_extension_size -
	    (cie->ci_cie_instr_start - cie->ci_cie_start);

    }
    *bytes_in_cie = (cie->ci_length);
    return (DW_DLV_OK);
}

static int
_dwarf_get_fde_info_for_a_pc_row(Dwarf_Fde fde,
				 Dwarf_Addr pc_requested,
				 Dwarf_Frame table, Dwarf_Error * error)
/* Return the register rules for all registers at a given pc. */
{
    Dwarf_Debug dbg;
    Dwarf_Cie cie;
    Dwarf_Sword i;
    int dw_err;
    Dwarf_Sword icount;
    int res;

    if (fde == NULL) {
	_dwarf_error(NULL, error, DW_DLE_FDE_NULL);
	return (DW_DLV_ERROR);
    }

    dbg = fde->fd_dbg;
    if (dbg == NULL) {
	_dwarf_error(NULL, error, DW_DLE_FDE_DBG_NULL);
	return (DW_DLV_ERROR);
    }

    if (pc_requested < fde->fd_initial_location ||
	pc_requested >=
	fde->fd_initial_location + fde->fd_address_range) {
	_dwarf_error(dbg, error, DW_DLE_PC_NOT_IN_FDE_RANGE);
	return (DW_DLV_ERROR);
    }

    cie = fde->fd_cie;
    if (cie->ci_initial_table == NULL) {
	cie->ci_initial_table = _dwarf_get_alloc(dbg, DW_DLA_FRAME, 1);
	if (cie->ci_initial_table == NULL) {
	    _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
	    return (DW_DLV_ERROR);
	}
	for (i = 0; i < DW_FRAME_LAST_REG_NUM; i++) {
	    cie->ci_initial_table->fr_reg[i].ru_is_off = 0;
	    cie->ci_initial_table->fr_reg[i].ru_register =
		DW_FRAME_SAME_VAL;
	    cie->ci_initial_table->fr_reg[i].ru_offset = 0;
	}

	res = _dwarf_exec_frame_instr( /* make_instr= */ false,
				      /* ret_frame_instr= */ NULL,
				      /* search_pc */ false,
				      /* search_pc_val */ 0,
				      /* location */ 0,
				      cie->ci_cie_instr_start,
				      cie->ci_cie_instr_start +
				      (cie->ci_length +
				       cie->ci_length_size +
				       cie->ci_extension_size -
				       (cie->ci_cie_instr_start -
					cie->ci_cie_start)),
				      cie->ci_initial_table, cie, dbg,
				      &icount, &dw_err);
	if (res == DW_DLV_ERROR) {
	    _dwarf_error(dbg, error, dw_err);
	    return (res);
	} else if (res == DW_DLV_NO_ENTRY) {
	    return res;
	}
    }

    res = _dwarf_exec_frame_instr( /* make_instr= */ false,
				  /* ret_frame_instr= */ NULL,
				  /* search_pc */ true,
				  /* search_pc_val */ pc_requested,
				  fde->fd_initial_location,
				  fde->fd_fde_instr_start,
				  fde->fd_fde_start + fde->fd_length +
				  fde->fd_length_size +
				  fde->fd_extension_size,
				  table, cie, dbg, &icount, &dw_err);
    if (res == DW_DLV_ERROR) {
	_dwarf_error(dbg, error, dw_err);
	return (res);
    } else if (res == DW_DLV_NO_ENTRY) {
	return res;
    }

    return DW_DLV_OK;
}

int
dwarf_get_fde_info_for_all_regs(Dwarf_Fde fde,
				Dwarf_Addr pc_requested,
				Dwarf_Regtable * reg_table,
				Dwarf_Addr * row_pc,
				Dwarf_Error * error)
{

    struct Dwarf_Frame_s fde_table;
    Dwarf_Sword i;
    int res;

    /* _dwarf_get_fde_info_for_a_pc_row will perform more sanity checks 
     */
    res = _dwarf_get_fde_info_for_a_pc_row(fde, pc_requested,
					   &fde_table, error);
    if (res != DW_DLV_OK) {
	return res;
    }

    for (i = 0; i < DW_REG_TABLE_SIZE; i++) {
	reg_table->rules[i].dw_offset_relevant =
	    fde_table.fr_reg[i].ru_is_off;
	reg_table->rules[i].dw_regnum = fde_table.fr_reg[i].ru_register;
	reg_table->rules[i].dw_offset = fde_table.fr_reg[i].ru_offset;
    }

    if (row_pc != NULL)
	*row_pc = fde_table.fr_loc;

    return DW_DLV_OK;
}


int
dwarf_get_fde_info_for_reg(Dwarf_Fde fde,
			   Dwarf_Half table_column,
			   Dwarf_Addr pc_requested,
			   Dwarf_Signed * offset_relevant,
			   Dwarf_Signed * register_num,
			   Dwarf_Signed * offset,
			   Dwarf_Addr * row_pc, Dwarf_Error * error)
{
    struct Dwarf_Frame_s fde_table;
    int res;


    if (table_column > DW_FRAME_LAST_REG_NUM) {
	_dwarf_error(NULL, error, DW_DLE_FRAME_TABLE_COL_BAD);
	return (DW_DLV_ERROR);
    }

    /* _dwarf_get_fde_info_for_a_pc_row will perform more sanity checks 
     */
    res =
	_dwarf_get_fde_info_for_a_pc_row(fde, pc_requested, &fde_table,
					 error);
    if (res != DW_DLV_OK) {
	return res;
    }

    if (register_num != NULL)
	*register_num = fde_table.fr_reg[table_column].ru_register;
    if (offset != NULL)
	*offset = fde_table.fr_reg[table_column].ru_offset;
    if (row_pc != NULL)
	*row_pc = fde_table.fr_loc;

    *offset_relevant = (fde_table.fr_reg[table_column].ru_is_off);
    return DW_DLV_OK;
}

/*
	Return pointer to the instructions in the dwarf
	fde.
*/
int
dwarf_get_fde_instr_bytes(Dwarf_Fde inFde, Dwarf_Ptr * outinstraddr,
			  Dwarf_Unsigned * outaddrlen,
			  Dwarf_Error * error)
{
    Dwarf_Unsigned len;
    unsigned char *instrs;
    Dwarf_Debug dbg;

    if (inFde == NULL) {
	_dwarf_error(NULL, error, DW_DLE_FDE_NULL);
	return (DW_DLV_ERROR);
    }

    dbg = inFde->fd_dbg;
    if (dbg == NULL) {
	_dwarf_error(NULL, error, DW_DLE_FDE_DBG_NULL);
	return (DW_DLV_ERROR);
    }

    instrs = inFde->fd_fde_instr_start,
	len = (inFde->fd_fde_start + inFde->fd_length +
	       inFde->fd_length_size + inFde->fd_extension_size)
	- instrs;

    *outinstraddr = instrs;
    *outaddrlen = len;
    return DW_DLV_OK;
}

int
dwarf_get_fde_n(Dwarf_Fde * fde_data,
		Dwarf_Unsigned fde_index,
		Dwarf_Fde * returned_fde, Dwarf_Error * error)
{
    Dwarf_Debug dbg;

    if (fde_data == NULL) {
	_dwarf_error(NULL, error, DW_DLE_FDE_PTR_NULL);
	return (DW_DLV_ERROR);
    }

    if (*fde_data == NULL) {
	_dwarf_error(NULL, error, DW_DLE_FDE_NULL);
	return (DW_DLV_ERROR);
    }

    dbg = (*fde_data)->fd_dbg;
    if (dbg == NULL) {
	_dwarf_error(NULL, error, DW_DLE_FDE_DBG_NULL);
	return (DW_DLV_ERROR);
    }

    if (fde_index >= dbg->de_fde_count) {
	return (DW_DLV_NO_ENTRY);
    }
    *returned_fde = (*(fde_data + fde_index));
    return DW_DLV_OK;
}


/* 
    Lopc and hipc are extensions to the interface to 
    return the range of addresses that are described
    by the returned fde.
*/
int
dwarf_get_fde_at_pc(Dwarf_Fde * fde_data,
		    Dwarf_Addr pc_of_interest,
		    Dwarf_Fde * returned_fde,
		    Dwarf_Addr * lopc,
		    Dwarf_Addr * hipc, Dwarf_Error * error)
{
    Dwarf_Debug dbg;
    Dwarf_Fde fde = NULL;

    if (fde_data == NULL) {
	_dwarf_error(NULL, error, DW_DLE_FDE_PTR_NULL);
	return (DW_DLV_ERROR);
    }

    if (*fde_data == NULL) {
	_dwarf_error(NULL, error, DW_DLE_FDE_NULL);
	return (DW_DLV_ERROR);
    }

    dbg = (*fde_data)->fd_dbg;
    if (dbg == NULL) {
	_dwarf_error(NULL, error, DW_DLE_FDE_DBG_NULL);
	return (DW_DLV_ERROR);
    }
    {
	/* The fde's are sorted by their addresses. Binary search to
	   find correct fde. */
	int low = 0;
	int high = dbg->de_fde_count - 1;
	int middle = 0;
	Dwarf_Fde cur_fde;

	while (low <= high) {
	    middle = (low + high) / 2;
	    cur_fde = fde_data[middle];
	    if (pc_of_interest < cur_fde->fd_initial_location) {
		high = middle - 1;
	    } else if (pc_of_interest >=
		       (cur_fde->fd_initial_location +
			cur_fde->fd_address_range)) {
		low = middle + 1;
	    } else {
		fde = fde_data[middle];
		break;
	    }
	}
    }

    if (fde) {
	if (lopc != NULL)
	    *lopc = fde->fd_initial_location;
	if (hipc != NULL)
	    *hipc = fde->fd_initial_location +
		fde->fd_address_range - 1;
	*returned_fde = fde;
	return (DW_DLV_OK);
    }

    return (DW_DLV_NO_ENTRY);
}


int
dwarf_expand_frame_instructions(Dwarf_Debug dbg,
				Dwarf_Ptr instruction,
				Dwarf_Unsigned i_length,
				Dwarf_Frame_Op ** returned_op_list,
				Dwarf_Signed * returned_op_count,
				Dwarf_Error * error)
{
    Dwarf_Sword instr_count;
    int res;
    int dw_err;

    if (dbg == 0) {
	_dwarf_error(NULL, error, DW_DLE_DBG_NULL);
	return (DW_DLV_ERROR);
    }

    if (returned_op_list == 0 || returned_op_count == 0) {
	_dwarf_error(dbg, error, DW_DLE_RET_OP_LIST_NULL);
	return (DW_DLV_ERROR);
    }

    /* The cast to Dwarf_Ptr may get a compiler warning, but it is safe 
       as it is just an i_length offset from 'instruction' itself. A
       caller has made a big mistake if the result is not a valid
       pointer. */
    res = _dwarf_exec_frame_instr( /* make_instr= */ true,
				  returned_op_list,
				  /* search_pc */ false,
				  /* search_pc_val */ 0,
				  /* location */ 0,
				  instruction,
				  (Dwarf_Ptr)((char *)instruction + i_length),
				  /* Dwarf_Frame */ NULL,
				  /* cie_ptr */ NULL,
				  dbg, &instr_count, &dw_err);
    if (res != DW_DLV_OK) {
	if (res == DW_DLV_ERROR) {
	    _dwarf_error(dbg, error, dw_err);
	}
	return (res);
    }

    *returned_op_count = instr_count;
    return DW_DLV_OK;
}



/*
	Used by rqs.  Returns DW_DLV_OK if returns the arrays.
	Returns DW_DLV_NO_ENTRY if no section. ?? (How do I tell?)
	Returns DW_DLV_ERROR if there is an error.

*/
int
_dwarf_frame_address_offsets(Dwarf_Debug dbg, Dwarf_Addr ** addrlist,
			     Dwarf_Off ** offsetlist,
			     Dwarf_Signed * returncount,
			     Dwarf_Error * err)
{
    int retval = DW_DLV_OK;
    int res;
    Dwarf_Cie *cie_data;
    Dwarf_Signed cie_count;
    Dwarf_Fde *fde_data;
    Dwarf_Signed fde_count;
    Dwarf_Signed i;
    Dwarf_Frame_Op *frame_inst;
    Dwarf_Fde fdep;
    Dwarf_Cie ciep;
    Dwarf_Chain curr_chain = 0;
    Dwarf_Chain head_chain = 0;
    Dwarf_Chain prev_chain = 0;
    Dwarf_Arange arange;
    Dwarf_Unsigned arange_count = 0;
    Dwarf_Addr *arange_addrs = 0;
    Dwarf_Off *arange_offsets = 0;

    res = dwarf_get_fde_list(dbg, &cie_data, &cie_count,
			     &fde_data, &fde_count, err);
    if (res != DW_DLV_OK) {
	return res;
    }

    res =
        _dwarf_load_section(dbg,
			    dbg->de_debug_frame_index,
			    &dbg->de_debug_frame,
			    err);
    if (res != DW_DLV_OK) {
      return res;
    }

    for (i = 0; i < cie_count; i++) {
	Dwarf_Off instoff = 0;
	Dwarf_Signed initial_instructions_length = 0;
	Dwarf_Small *instr_end = 0;
	Dwarf_Sword icount = 0;
	int j;
	int dw_err;

	ciep = cie_data[i];
	instoff = ciep->ci_cie_instr_start - dbg->de_debug_frame;
	initial_instructions_length = ciep->ci_length +
	    ciep->ci_length_size + ciep->ci_extension_size -
	    (ciep->ci_cie_instr_start - ciep->ci_cie_start);
	instr_end = ciep->ci_cie_instr_start +
	    initial_instructions_length;
	res = _dwarf_exec_frame_instr( /* make_instr */ true,
				      &frame_inst,
				      /* search_pc= */ false,
				      /* search_pc_val= */ 0,
				      /* location */ 0,
				      ciep->ci_cie_instr_start,
				      instr_end,
				      /* Dwarf_frame= */ 0,
				      /* cie= */ 0,
				      dbg, &icount, &dw_err);
	if (res == DW_DLV_ERROR) {
	    _dwarf_error(dbg, err, dw_err);
	    return (res);
	} else if (res == DW_DLV_NO_ENTRY) {
	    continue;
	}

	for (j = 0; j < icount; ++j) {
	    Dwarf_Frame_Op *finst = frame_inst + j;

	    if (finst->fp_base_op == 0 && finst->fp_extended_op == 1) {
		/* is DW_CFA_set_loc */
		Dwarf_Addr add = (Dwarf_Addr) finst->fp_offset;
		Dwarf_Off off = finst->fp_instr_offset + instoff;

		arange = (Dwarf_Arange)
		    _dwarf_get_alloc(dbg, DW_DLA_ARANGE, 1);
		if (arange == NULL) {
		    _dwarf_error(dbg, err, DW_DLE_ALLOC_FAIL);
		    return (DW_DLV_ERROR);
		}
		arange->ar_address = add;
		arange->ar_info_offset = off;
		arange_count++;
		curr_chain = (Dwarf_Chain)
		    _dwarf_get_alloc(dbg, DW_DLA_CHAIN, 1);
		if (curr_chain == NULL) {
		    _dwarf_error(dbg, err, DW_DLE_ALLOC_FAIL);
		    return (DW_DLV_ERROR);
		}
		curr_chain->ch_item = arange;
		if (head_chain == NULL)
		    head_chain = prev_chain = curr_chain;
		else {
		    prev_chain->ch_next = curr_chain;
		    prev_chain = curr_chain;
		}
	    }
	}
	dwarf_dealloc(dbg, frame_inst, DW_DLA_FRAME_BLOCK);

    }
    for (i = 0; i < fde_count; i++) {
	Dwarf_Small *instr_end = 0;
	Dwarf_Sword icount = 0;
	Dwarf_Signed instructions_length = 0;
	Dwarf_Off instoff = 0;
	Dwarf_Off off = 0;
	Dwarf_Addr addr = 0;
	int j;
	int dw_err;

	fdep = fde_data[i];
	off = fdep->fd_initial_loc_pos - dbg->de_debug_frame;
	addr = fdep->fd_initial_location;
	arange = (Dwarf_Arange)
	    _dwarf_get_alloc(dbg, DW_DLA_ARANGE, 1);
	if (arange == NULL) {
	    _dwarf_error(dbg, err, DW_DLE_ALLOC_FAIL);
	    return (DW_DLV_ERROR);
	}
	arange->ar_address = addr;
	arange->ar_info_offset = off;
	arange_count++;
	curr_chain = (Dwarf_Chain)
	    _dwarf_get_alloc(dbg, DW_DLA_CHAIN, 1);
	if (curr_chain == NULL) {
	    _dwarf_error(dbg, err, DW_DLE_ALLOC_FAIL);
	    return (DW_DLV_ERROR);
	}
	curr_chain->ch_item = arange;
	if (head_chain == NULL)
	    head_chain = prev_chain = curr_chain;
	else {
	    prev_chain->ch_next = curr_chain;
	    prev_chain = curr_chain;
	}


	instoff = fdep->fd_fde_instr_start - dbg->de_debug_frame;
	instructions_length = fdep->fd_length +
	    fdep->fd_length_size + fdep->fd_extension_size -
	    (fdep->fd_fde_instr_start - fdep->fd_fde_start);
	instr_end = fdep->fd_fde_instr_start + instructions_length;
	res = _dwarf_exec_frame_instr( /* make_instr */ true,
				      &frame_inst,
				      /* search_pc= */ false,
				      /* search_pc_val= */ 0,
				      /* location */ 0,
				      fdep->fd_fde_instr_start,
				      instr_end,
				      /* Dwarf_frame= */ 0,
				      /* cie= */ 0,
				      dbg, &icount, &dw_err);
	if (res == DW_DLV_ERROR) {
	    _dwarf_error(dbg, err, dw_err);
	    return (res);
	} else if (res == DW_DLV_NO_ENTRY) {
	    continue;
	}

	for (j = 0; j < icount; ++j) {
	    Dwarf_Frame_Op *finst2 = frame_inst + j;

	    if (finst2->fp_base_op == 0 && finst2->fp_extended_op == 1) {
		/* is DW_CFA_set_loc */
		Dwarf_Addr add = (Dwarf_Addr) finst2->fp_offset;
		Dwarf_Off off = finst2->fp_instr_offset + instoff;

		arange = (Dwarf_Arange)
		    _dwarf_get_alloc(dbg, DW_DLA_ARANGE, 1);
		if (arange == NULL) {
		    _dwarf_error(dbg, err, DW_DLE_ALLOC_FAIL);
		    return (DW_DLV_ERROR);
		}
		arange->ar_address = add;
		arange->ar_info_offset = off;
		arange_count++;
		curr_chain = (Dwarf_Chain)
		    _dwarf_get_alloc(dbg, DW_DLA_CHAIN, 1);
		if (curr_chain == NULL) {
		    _dwarf_error(dbg, err, DW_DLE_ALLOC_FAIL);
		    return (DW_DLV_ERROR);
		}
		curr_chain->ch_item = arange;
		if (head_chain == NULL)
		    head_chain = prev_chain = curr_chain;
		else {
		    prev_chain->ch_next = curr_chain;
		    prev_chain = curr_chain;
		}

	    }
	}
	dwarf_dealloc(dbg, frame_inst, DW_DLA_FRAME_BLOCK);

    }
    dwarf_dealloc(dbg, fde_data, DW_DLA_LIST);
    dwarf_dealloc(dbg, cie_data, DW_DLA_LIST);
    arange_addrs = (Dwarf_Addr *)
	_dwarf_get_alloc(dbg, DW_DLA_ADDR, arange_count);
    if (arange_addrs == NULL) {
	_dwarf_error(dbg, err, DW_DLE_ALLOC_FAIL);
	return (DW_DLV_ERROR);
    }
    arange_offsets = (Dwarf_Off *)
	_dwarf_get_alloc(dbg, DW_DLA_ADDR, arange_count);
    if (arange_offsets == NULL) {
	_dwarf_error(dbg, err, DW_DLE_ALLOC_FAIL);
	return (DW_DLV_ERROR);
    }

    curr_chain = head_chain;
    for (i = 0; i < arange_count; i++) {
	Dwarf_Arange ar = curr_chain->ch_item;

	arange_addrs[i] = ar->ar_address;
	arange_offsets[i] = ar->ar_info_offset;
	prev_chain = curr_chain;
	curr_chain = curr_chain->ch_next;
	dwarf_dealloc(dbg, ar, DW_DLA_ARANGE);
	dwarf_dealloc(dbg, prev_chain, DW_DLA_CHAIN);
    }
    *returncount = arange_count;
    *offsetlist = arange_offsets;
    *addrlist = arange_addrs;
    return retval;
}

/* Used by dwarfdump -v to print offsets, for debugging
   dwarf info
*/
/* ARGSUSED 4 */
int
_dwarf_fde_section_offset(Dwarf_Debug dbg, Dwarf_Fde in_fde,
			  Dwarf_Off * fde_off, Dwarf_Off * cie_off,
			  Dwarf_Error * err)
{
    int res;
    char *start;
    char *loc;

    res =
        _dwarf_load_section(dbg,
			    dbg->de_debug_frame_index,
			    &dbg->de_debug_frame,
			    err);
    if (res != DW_DLV_OK) {
        return res;
    }

    start = (char *) dbg->de_debug_frame;
    loc = (char *) in_fde->fd_fde_start;

    *fde_off = (loc - start);
    *cie_off = in_fde->fd_cie_offset;
    return DW_DLV_OK;
}

/* Used by dwarfdump -v to print offsets, for debugging
   dwarf info
*/
/* ARGSUSED 4 */
int
_dwarf_cie_section_offset(Dwarf_Debug dbg, Dwarf_Cie in_cie,
			  Dwarf_Off * cie_off, Dwarf_Error * err)
{
    int res;
    char *start;
    char *loc;

    res =
        _dwarf_load_section(dbg,
			    dbg->de_debug_frame_index,
			    &dbg->de_debug_frame,
			    err);
    if (res != DW_DLV_OK) {
        return res;
    }

    start = (char *) dbg->de_debug_frame;
    loc = (char *) in_cie->ci_cie_start;

    *cie_off = (loc - start);
    return DW_DLV_OK;
}
