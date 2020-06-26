/*
  Copyright (C) 2000,2004,2006 Silicon Graphics, Inc.  All Rights Reserved.
  Portions Copyright 2007-2010 Sun Microsystems, Inc. All rights reserved.
  Portions Copyright 2011-2019 David Anderson. All rights reserved.

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
#include <stddef.h>
#ifdef HAVE_STDINT_H
#include <stdint.h> /* For uintptr_t */
#endif /* HAVE_STDINT_H */
#include "pro_incl.h"
#include "dwarf.h"
#include "libdwarf.h"
#include "pro_opaque.h"
#include "pro_error.h"
#include "pro_encode_nm.h"
#include "pro_alloc.h"
#include "pro_expr.h"

#define SIZEOFT16 2
#define SIZEOFT32 4
#define SIZEOFT64 8

/*
    This function creates a new expression
    struct that can be used to build up a
    location expression.
*/
Dwarf_P_Expr
dwarf_new_expr(Dwarf_P_Debug dbg, Dwarf_Error * error)
{
    Dwarf_P_Expr ret_expr;

    if (dbg == NULL) {
        _dwarf_p_error(NULL, error, DW_DLE_DBG_NULL);
        return (NULL);
    }

    ret_expr = (Dwarf_P_Expr)
        _dwarf_p_get_alloc(dbg, sizeof(struct Dwarf_P_Expr_s));
    if (ret_expr == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return (NULL);
    }

    ret_expr->ex_dbg = dbg;

    return (ret_expr);
}

Dwarf_Unsigned
dwarf_add_expr_gen(Dwarf_P_Expr expr,
    Dwarf_Small opcode,
    Dwarf_Unsigned val1,
    Dwarf_Unsigned val2, Dwarf_Error * error)
{
    Dwarf_Unsigned len = 0;
    int res = 0;

    res = dwarf_add_expr_gen_a(expr,opcode,
        val1,val2,&len,error);
    if (res != DW_DLV_OK) {
        return DW_DLV_NOCOUNT;
    }
    return len;

}

int
dwarf_add_expr_gen_a(Dwarf_P_Expr expr,
    Dwarf_Small opcode,
    Dwarf_Unsigned val1,
    Dwarf_Unsigned val2,
    Dwarf_Unsigned *stream_length_out,
    Dwarf_Error * error)
{
    /* 2* since used to concatenate 2 leb's below */
    char encode_buffer[2 * ENCODE_SPACE_NEEDED];

    char encode_buffer2[ENCODE_SPACE_NEEDED];
    int res = 0;
    Dwarf_P_Debug dbg = 0;

    /*  Give the buffer where the operands are first going to be
        assembled the largest alignment. */
    Dwarf_Unsigned operand_buffer[10];

    /* Size of the byte stream buffer that needs to be memcpy-ed. */
    int operand_size = 0;

    /*  Points to the byte stream for the first operand, and finally to
        the buffer that is memcp-ed into the Dwarf_P_Expr_s struct. */
    Dwarf_Small *operand = 0;

    /*  Size of the byte stream for second operand. */
    int operand2_size = 0;

    /*  Points to next byte to be written in Dwarf_P_Expr_s struct. */
    Dwarf_Small *next_byte_ptr = 0;

    /*  Offset past the last byte written into Dwarf_P_Expr_s. */
    int next_byte_offset = 0;

    /* ***** BEGIN CODE ***** */

    if (expr == NULL) {
        _dwarf_p_error(NULL, error, DW_DLE_EXPR_NULL);
        return DW_DLV_ERROR;
    }
    dbg = expr->ex_dbg;

    if (expr->ex_dbg == NULL) {
        _dwarf_p_error(NULL, error, DW_DLE_DBG_NULL);
        return DW_DLV_ERROR;
    }

    operand = NULL;
    operand_size = 0;

    switch (opcode) {
    case DW_OP_reg0:
    case DW_OP_reg1:
    case DW_OP_reg2:
    case DW_OP_reg3:
    case DW_OP_reg4:
    case DW_OP_reg5:
    case DW_OP_reg6:
    case DW_OP_reg7:
    case DW_OP_reg8:
    case DW_OP_reg9:
    case DW_OP_reg10:
    case DW_OP_reg11:
    case DW_OP_reg12:
    case DW_OP_reg13:
    case DW_OP_reg14:
    case DW_OP_reg15:
    case DW_OP_reg16:
    case DW_OP_reg17:
    case DW_OP_reg18:
    case DW_OP_reg19:
    case DW_OP_reg20:
    case DW_OP_reg21:
    case DW_OP_reg22:
    case DW_OP_reg23:
    case DW_OP_reg24:
    case DW_OP_reg25:
    case DW_OP_reg26:
    case DW_OP_reg27:
    case DW_OP_reg28:
    case DW_OP_reg29:
    case DW_OP_reg30:
    case DW_OP_reg31:
        break;

    case DW_OP_breg0:
    case DW_OP_breg1:
    case DW_OP_breg2:
    case DW_OP_breg3:
    case DW_OP_breg4:
    case DW_OP_breg5:
    case DW_OP_breg6:
    case DW_OP_breg7:
    case DW_OP_breg8:
    case DW_OP_breg9:
    case DW_OP_breg10:
    case DW_OP_breg11:
    case DW_OP_breg12:
    case DW_OP_breg13:
    case DW_OP_breg14:
    case DW_OP_breg15:
    case DW_OP_breg16:
    case DW_OP_breg17:
    case DW_OP_breg18:
    case DW_OP_breg19:
    case DW_OP_breg20:
    case DW_OP_breg21:
    case DW_OP_breg22:
    case DW_OP_breg23:
    case DW_OP_breg24:
    case DW_OP_breg25:
    case DW_OP_breg26:
    case DW_OP_breg27:
    case DW_OP_breg28:
    case DW_OP_breg29:
    case DW_OP_breg30:
    case DW_OP_breg31:
        res = _dwarf_pro_encode_signed_leb128_nm(val1,
            &operand_size, encode_buffer, sizeof(encode_buffer));
        if (res != DW_DLV_OK) {
            _dwarf_p_error(expr->ex_dbg, error, DW_DLE_EXPR_LENGTH_BAD);
            return DW_DLV_ERROR;
        }
        operand = (Dwarf_Small *) encode_buffer;
        break;

    case DW_OP_regx:
        res = _dwarf_pro_encode_leb128_nm(val1, &operand_size,
            encode_buffer, sizeof(encode_buffer));
        if (res != DW_DLV_OK) {
            _dwarf_p_error(expr->ex_dbg, error, DW_DLE_EXPR_LENGTH_BAD);
            return DW_DLV_ERROR;
        }
        operand = (Dwarf_Small *) encode_buffer;
        break;

    case DW_OP_lit0:
    case DW_OP_lit1:
    case DW_OP_lit2:
    case DW_OP_lit3:
    case DW_OP_lit4:
    case DW_OP_lit5:
    case DW_OP_lit6:
    case DW_OP_lit7:
    case DW_OP_lit8:
    case DW_OP_lit9:
    case DW_OP_lit10:
    case DW_OP_lit11:
    case DW_OP_lit12:
    case DW_OP_lit13:
    case DW_OP_lit14:
    case DW_OP_lit15:
    case DW_OP_lit16:
    case DW_OP_lit17:
    case DW_OP_lit18:
    case DW_OP_lit19:
    case DW_OP_lit20:
    case DW_OP_lit21:
    case DW_OP_lit22:
    case DW_OP_lit23:
    case DW_OP_lit24:
    case DW_OP_lit25:
    case DW_OP_lit26:
    case DW_OP_lit27:
    case DW_OP_lit28:
    case DW_OP_lit29:
    case DW_OP_lit30:
    case DW_OP_lit31:
        break;

    case DW_OP_addr:
        _dwarf_p_error(expr->ex_dbg, error, DW_DLE_BAD_EXPR_OPCODE);
        return DW_DLV_ERROR;

    case DW_OP_const1u:
    case DW_OP_const1s:
        operand = (Dwarf_Small *) & operand_buffer[0];
        WRITE_UNALIGNED(dbg, operand, &val1, sizeof(val1), 1);
        operand_size = 1;
        break;

    case DW_OP_const2u:
    case DW_OP_const2s:
        operand = (Dwarf_Small *) & operand_buffer[0];
        WRITE_UNALIGNED(dbg, operand, &val1, sizeof(val1), 2);
        operand_size = 2;
        break;

    case DW_OP_const4u:
    case DW_OP_const4s:
        operand = (Dwarf_Small *) & operand_buffer[0];
        WRITE_UNALIGNED(dbg, operand, &val1, sizeof(val1),
            SIZEOFT32);
        operand_size = SIZEOFT32;
        break;

    case DW_OP_const8u:
    case DW_OP_const8s:
        operand = (Dwarf_Small *) & operand_buffer[0];
        WRITE_UNALIGNED(dbg, operand, &val1, sizeof(val1), 8);
        operand_size = 8;
        break;

    case DW_OP_constu:
        res = _dwarf_pro_encode_leb128_nm(val1,
            &operand_size, encode_buffer, sizeof(encode_buffer));
        if (res != DW_DLV_OK) {
            _dwarf_p_error(expr->ex_dbg, error, DW_DLE_EXPR_LENGTH_BAD);
            return DW_DLV_ERROR;
        }
        operand = (Dwarf_Small *) encode_buffer;
        break;

    case DW_OP_consts:
        res = _dwarf_pro_encode_signed_leb128_nm(val1,
            &operand_size,
            encode_buffer,
            sizeof(encode_buffer));
        if (res != DW_DLV_OK) {
            _dwarf_p_error(expr->ex_dbg, error, DW_DLE_EXPR_LENGTH_BAD);
            return DW_DLV_ERROR;
        }
        operand = (Dwarf_Small *) encode_buffer;
        break;

    case DW_OP_fbreg:
        res = _dwarf_pro_encode_signed_leb128_nm(val1,
            &operand_size,
            encode_buffer,
            sizeof(encode_buffer));
        if (res != DW_DLV_OK) {
            _dwarf_p_error(expr->ex_dbg, error, DW_DLE_EXPR_LENGTH_BAD);
            return DW_DLV_ERROR;
        }
        operand = (Dwarf_Small *) encode_buffer;
        break;

    case DW_OP_bregx:
        res = _dwarf_pro_encode_leb128_nm(val1, &operand_size,
            encode_buffer,
            sizeof(encode_buffer));
        if (res != DW_DLV_OK) {
            _dwarf_p_error(expr->ex_dbg, error, DW_DLE_EXPR_LENGTH_BAD);
            return DW_DLV_ERROR;
        }
        operand = (Dwarf_Small *) encode_buffer;
        /* put this one directly into 'operand' at tail of prev value */
        res = _dwarf_pro_encode_signed_leb128_nm(val2, &operand2_size,
            ((char *) operand) +
            operand_size,
            sizeof(encode_buffer2));
        if (res != DW_DLV_OK) {
            _dwarf_p_error(expr->ex_dbg, error, DW_DLE_EXPR_LENGTH_BAD);
            return DW_DLV_ERROR;
        }
        operand_size += operand2_size;

    case DW_OP_dup:
    case DW_OP_drop:
        break;

    case DW_OP_pick:
        operand = (Dwarf_Small *) & operand_buffer[0];
        WRITE_UNALIGNED(dbg, operand, (const void *) &val1,
            sizeof(val1), 1);
        operand_size = 1;
        break;

    case DW_OP_over:
    case DW_OP_swap:
    case DW_OP_rot:
    case DW_OP_deref:
    case DW_OP_xderef:
        break;

    case DW_OP_deref_size:
    case DW_OP_xderef_size:
        operand = (Dwarf_Small *) & operand_buffer[0];
        WRITE_UNALIGNED(dbg, operand, (const void *) &val1,
            sizeof(val1), 1);
        operand_size = 1;
        break;

    case DW_OP_abs:
    case DW_OP_and:
    case DW_OP_div:
    case DW_OP_minus:
    case DW_OP_mod:
    case DW_OP_mul:
    case DW_OP_neg:
    case DW_OP_not:
    case DW_OP_or:
    case DW_OP_plus:
        break;

    case DW_OP_plus_uconst:
        res = _dwarf_pro_encode_leb128_nm(val1, &operand_size,
            encode_buffer,
            sizeof(encode_buffer));
        if (res != DW_DLV_OK) {
            _dwarf_p_error(expr->ex_dbg, error, DW_DLE_EXPR_LENGTH_BAD);
            return DW_DLV_ERROR;
        }
        operand = (Dwarf_Small *) encode_buffer;
        break;

    case DW_OP_shl:
    case DW_OP_shr:
    case DW_OP_shra:
    case DW_OP_xor:
        break;

    case DW_OP_le:
    case DW_OP_ge:
    case DW_OP_eq:
    case DW_OP_lt:
    case DW_OP_gt:
    case DW_OP_ne:
        break;

    case DW_OP_skip:
    case DW_OP_bra:
        /* FIX: unhandled! OP_bra, OP_skip! */
        _dwarf_p_error(expr->ex_dbg, error, DW_DLE_BAD_EXPR_OPCODE);
        return DW_DLV_ERROR;

    case DW_OP_piece:
        res = _dwarf_pro_encode_leb128_nm(val1, &operand_size,
            encode_buffer,
            sizeof(encode_buffer));
        if (res != DW_DLV_OK) {
            _dwarf_p_error(expr->ex_dbg, error, DW_DLE_EXPR_LENGTH_BAD);
            return DW_DLV_ERROR;
        }
        operand = (Dwarf_Small *) encode_buffer;
        break;

    case DW_OP_nop:
        break;
    case DW_OP_push_object_address:     /* DWARF3 */
        break;
    case DW_OP_call2:           /* DWARF3 */
        operand = (Dwarf_Small *) & operand_buffer[0];
        WRITE_UNALIGNED(dbg, operand, &val1, sizeof(val1), SIZEOFT16);
        operand_size = SIZEOFT16;
        break;

    case DW_OP_call4:           /* DWARF3 */
        operand = (Dwarf_Small *) & operand_buffer[0];
        WRITE_UNALIGNED(dbg, operand, &val1, sizeof(val1), SIZEOFT32);
        operand_size = SIZEOFT32;
        break;

    case DW_OP_call_ref:        /* DWARF3 */
        operand = (Dwarf_Small *) & operand_buffer[0];
        WRITE_UNALIGNED(dbg, operand, &val1, sizeof(val1),
            dbg->de_dwarf_offset_size);
        operand_size = dbg->de_dwarf_offset_size;
        break;
    case DW_OP_form_tls_address:        /* DWARF3f */
        break;
    case DW_OP_call_frame_cfa:  /* DWARF3f */
        break;
    case DW_OP_bit_piece:       /* DWARF3f */
        res = _dwarf_pro_encode_leb128_nm(val1, &operand_size,
            encode_buffer,
            sizeof(encode_buffer));
        if (res != DW_DLV_OK) {
            _dwarf_p_error(expr->ex_dbg, error, DW_DLE_EXPR_LENGTH_BAD);
            return DW_DLV_ERROR;
        }
        operand = (Dwarf_Small *) encode_buffer;
        /* put this one directly into 'operand' at tail of prev value */
        res = _dwarf_pro_encode_leb128_nm(val2, &operand2_size,
            ((char *) operand) +
            operand_size,
            sizeof(encode_buffer2));
        if (res != DW_DLV_OK) {
            _dwarf_p_error(expr->ex_dbg, error, DW_DLE_EXPR_LENGTH_BAD);
            return DW_DLV_ERROR;
        }
        operand_size += operand2_size;
        break;
    default:
        _dwarf_p_error(expr->ex_dbg, error, DW_DLE_BAD_EXPR_OPCODE);
        return DW_DLV_ERROR;
    }

    next_byte_offset = expr->ex_next_byte_offset + operand_size + 1;

    if (next_byte_offset > MAXIMUM_LOC_EXPR_LENGTH) {
        _dwarf_p_error(expr->ex_dbg, error, DW_DLE_EXPR_LENGTH_BAD);
        return DW_DLV_ERROR;
    }

    next_byte_ptr =
        &(expr->ex_byte_stream[0]) + expr->ex_next_byte_offset;

    *next_byte_ptr = opcode;
    next_byte_ptr++;
    if (operand) {
        memcpy(next_byte_ptr, operand, operand_size);
    }

    expr->ex_next_byte_offset = next_byte_offset;
    *stream_length_out = next_byte_offset;
    return DW_DLV_OK;
}

Dwarf_Unsigned
dwarf_add_expr_addr_b(Dwarf_P_Expr expr,
    Dwarf_Unsigned addr,
    Dwarf_Unsigned sym_index,
    Dwarf_Error * error)
{
    Dwarf_Unsigned length = 0;
    int res = 0;

    res = dwarf_add_expr_addr_c(expr,addr,sym_index,
        &length,error);
    if (res != DW_DLV_OK) {
        return DW_DLV_NOCOUNT;
    }
    return length;

}
int
dwarf_add_expr_addr_c(Dwarf_P_Expr expr,
    Dwarf_Unsigned addr,
    Dwarf_Unsigned sym_index,
    Dwarf_Unsigned *stream_length_out,
    Dwarf_Error * error)
{
    Dwarf_P_Debug dbg;
    Dwarf_Small *next_byte_ptr;
    Dwarf_Unsigned next_byte_offset;
    int upointer_size;

    if (expr == NULL) {
        _dwarf_p_error(NULL, error, DW_DLE_EXPR_NULL);
        return (DW_DLV_ERROR);
    }

    dbg = expr->ex_dbg;
    if (dbg == NULL) {
        _dwarf_p_error(NULL, error, DW_DLE_DBG_NULL);
        return (DW_DLV_ERROR);
    }

    upointer_size = dbg->de_pointer_size;
    next_byte_offset = expr->ex_next_byte_offset + upointer_size + 1;
    if (next_byte_offset > MAXIMUM_LOC_EXPR_LENGTH) {
        _dwarf_p_error(dbg, error, DW_DLE_EXPR_LENGTH_BAD);
        return (DW_DLV_ERROR);
    }

    next_byte_ptr =
        &(expr->ex_byte_stream[0]) + expr->ex_next_byte_offset;

    *next_byte_ptr = DW_OP_addr;
    next_byte_ptr++;
    WRITE_UNALIGNED(dbg, next_byte_ptr, (const void *) &addr,
        sizeof(addr), upointer_size);

    if (expr->ex_reloc_offset != 0) {
        _dwarf_p_error(dbg, error, DW_DLE_MULTIPLE_RELOC_IN_EXPR);
        return (DW_DLV_ERROR);
    }

    expr->ex_reloc_sym_index = sym_index;
    expr->ex_reloc_offset = expr->ex_next_byte_offset + 1;

    expr->ex_next_byte_offset = next_byte_offset;
    *stream_length_out = next_byte_offset;
    return DW_DLV_OK;
}

Dwarf_Unsigned
dwarf_add_expr_addr(Dwarf_P_Expr expr,
    Dwarf_Unsigned addr,
    Dwarf_Signed sym_index,
    Dwarf_Error * error)
{
    Dwarf_Unsigned length = 0;
    int res = 0;
    Dwarf_P_Debug dbg = 0;

    if (sym_index < 0) {
        _dwarf_p_error(dbg, error,
            DW_DLE_RELOC_SECTION_SYMBOL_INDEX_BAD);
        return DW_DLV_NOCOUNT;
    }
    res = dwarf_add_expr_addr_c(expr,
        (Dwarf_Unsigned)addr,
        (Dwarf_Unsigned)sym_index,
        &length,error);
    if (res != DW_DLV_OK) {
        return (Dwarf_Unsigned)DW_DLV_NOCOUNT;
    }
    return length;
}

Dwarf_Unsigned
dwarf_expr_current_offset(Dwarf_P_Expr expr, Dwarf_Error * error)
{
    Dwarf_Unsigned l = 0;
    int res = 0;

    res = dwarf_expr_current_offset_a(expr,&l,error);
    if (res != DW_DLV_OK) {
        return (DW_DLV_NOCOUNT);
    }
    return l;
}

int
dwarf_expr_current_offset_a(Dwarf_P_Expr expr,
    Dwarf_Unsigned * stream_length_out,
    Dwarf_Error * error)
{
    if (expr == NULL) {
        _dwarf_p_error(NULL, error, DW_DLE_EXPR_NULL);
        return DW_DLV_ERROR;
    }

    if (expr->ex_dbg == NULL) {
        _dwarf_p_error(NULL, error, DW_DLE_DBG_NULL);
        return DW_DLV_ERROR;
    }
    *stream_length_out = expr->ex_next_byte_offset;
    return DW_DLV_OK;
}

void
dwarf_expr_reset(Dwarf_P_Expr expr, Dwarf_Error * error)
{
    if (expr == NULL) {
        _dwarf_p_error(NULL, error, DW_DLE_EXPR_NULL);
        return;
    }
    expr->ex_next_byte_offset=0;
}

Dwarf_Addr
dwarf_expr_into_block(Dwarf_P_Expr expr,
    Dwarf_Unsigned * length,
    Dwarf_Error * error)
{
    Dwarf_Small *addr = 0;
    int res = 0;

    res = dwarf_expr_into_block_a(expr,length,&addr,error);
    if (res != DW_DLV_OK) {
        return (DW_DLV_BADADDR);
    }
    return (Dwarf_Addr)(uintptr_t)addr;
}


int
dwarf_expr_into_block_a(Dwarf_P_Expr expr,
    Dwarf_Unsigned * length,
    Dwarf_Small    ** address,
    Dwarf_Error * error)
{
    if (expr == NULL) {
        _dwarf_p_error(NULL, error, DW_DLE_EXPR_NULL);
        return DW_DLV_ERROR;
    }

    if (expr->ex_dbg == NULL) {
        _dwarf_p_error(NULL, error, DW_DLE_DBG_NULL);
        return DW_DLV_ERROR;
    }

    if (length != NULL)
        *length = expr->ex_next_byte_offset;
    *address = &(expr->ex_byte_stream[0]);
    return DW_DLV_OK;
}
