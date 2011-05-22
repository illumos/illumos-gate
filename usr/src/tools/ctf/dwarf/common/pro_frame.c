/*

  Copyright (C) 2000,2004 Silicon Graphics, Inc.  All Rights Reserved.

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
#include "libdwarfdefs.h"
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include "pro_incl.h"
#include "pro_frame.h"

static void _dwarf_pro_add_to_fde(Dwarf_P_Fde fde,
                                  Dwarf_P_Frame_Pgm inst);

/*-------------------------------------------------------------------------
        This function adds a cie struct to the debug pointer. Its in the
        form of a linked list.
        augmenter: string reps augmentation (implementation defined)
        code_align: alignment of code
        data_align: alignment of data
        init_bytes: byts having initial instructions
        init_n_bytes: number of bytes of initial instructions
--------------------------------------------------------------------------*/
Dwarf_Unsigned
dwarf_add_frame_cie(Dwarf_P_Debug dbg,
                    char *augmenter,
                    Dwarf_Small code_align,
                    Dwarf_Small data_align,
                    Dwarf_Small return_reg,
                    Dwarf_Ptr init_bytes,
                    Dwarf_Unsigned init_n_bytes, Dwarf_Error * error)
{
    Dwarf_P_Cie curcie;

    if (dbg->de_frame_cies == NULL) {
        dbg->de_frame_cies = (Dwarf_P_Cie)
            _dwarf_p_get_alloc(dbg, sizeof(struct Dwarf_P_Cie_s));
        if (dbg->de_frame_cies == NULL) {
            DWARF_P_DBG_ERROR(dbg, DW_DLE_CIE_ALLOC, DW_DLV_NOCOUNT);
        }
        curcie = dbg->de_frame_cies;
        dbg->de_n_cie = 1;
        dbg->de_last_cie = curcie;
    } else {
        curcie = dbg->de_last_cie;
        curcie->cie_next = (Dwarf_P_Cie)
            _dwarf_p_get_alloc(dbg, sizeof(struct Dwarf_P_Cie_s));
        if (curcie->cie_next == NULL) {
            DWARF_P_DBG_ERROR(dbg, DW_DLE_CIE_ALLOC, DW_DLV_NOCOUNT);
        }
        curcie = curcie->cie_next;
        dbg->de_n_cie++;
        dbg->de_last_cie = curcie;
    }
    curcie->cie_version = DW_CIE_VERSION;
    curcie->cie_aug = augmenter;
    curcie->cie_code_align = code_align;
    curcie->cie_data_align = data_align;
    curcie->cie_ret_reg = return_reg;
    curcie->cie_inst = (char *) init_bytes;
    curcie->cie_inst_bytes = (long) init_n_bytes;
    curcie->cie_next = NULL;
    return dbg->de_n_cie;
}


/*-------------------------------------------------------------------------
        This functions adds a fde struct to the debug pointer. Its in the
        form of a linked list.
        die: subprogram/function die corresponding to this fde
        cie: cie referred to by this fde, obtained from call to 
            add_frame_cie() routine.
        virt_addr: beginning address
        code_len: length of code reps by the fde
--------------------------------------------------------------------------*/
 /*ARGSUSED*/                   /* pretend all args used */
    Dwarf_Unsigned
dwarf_add_frame_fde(Dwarf_P_Debug dbg,
                    Dwarf_P_Fde fde,
                    Dwarf_P_Die die,
                    Dwarf_Unsigned cie,
                    Dwarf_Unsigned virt_addr,
                    Dwarf_Unsigned code_len,
                    Dwarf_Unsigned symidx, Dwarf_Error * error)
{
    return dwarf_add_frame_fde_b(dbg, fde, die, cie, virt_addr,
                                 code_len, symidx, 0, 0, error);
}

/*ARGSUSED10*/
Dwarf_Unsigned
dwarf_add_frame_fde_b(Dwarf_P_Debug dbg,
                      Dwarf_P_Fde fde,
                      Dwarf_P_Die die,
                      Dwarf_Unsigned cie,
                      Dwarf_Unsigned virt_addr,
                      Dwarf_Unsigned code_len,
                      Dwarf_Unsigned symidx,
                      Dwarf_Unsigned symidx_of_end,
                      Dwarf_Addr offset_from_end_sym,
                      Dwarf_Error * error)
{
    Dwarf_P_Fde curfde;

    fde->fde_die = die;
    fde->fde_cie = (long) cie;
    fde->fde_initloc = virt_addr;
    fde->fde_r_symidx = symidx;
    fde->fde_addr_range = code_len;
    fde->fde_offset_into_exception_tables = DW_DLX_NO_EH_OFFSET;
    fde->fde_exception_table_symbol = 0;
    fde->fde_end_symbol_offset = offset_from_end_sym;
    fde->fde_end_symbol = symidx_of_end;
    fde->fde_dbg = dbg;

    curfde = dbg->de_last_fde;
    if (curfde == NULL) {
        dbg->de_frame_fdes = fde;
        dbg->de_last_fde = fde;
        dbg->de_n_fde = 1;
    } else {
        curfde->fde_next = fde;
        dbg->de_last_fde = fde;
        dbg->de_n_fde++;
    }
    return dbg->de_n_fde;
}

/*-------------------------------------------------------------------------
        This functions adds information to an fde. The fde is
        linked into the linked list of fde's maintained in the Dwarf_P_Debug
        structure.
        dbg: The debug descriptor.
        fde: The fde to be added.
        die: subprogram/function die corresponding to this fde
        cie: cie referred to by this fde, obtained from call to 
            add_frame_cie() routine.
        virt_addr: beginning address
        code_len: length of code reps by the fde
        symidx: The symbol id of the symbol wrt to which relocation needs
                to be performed for 'virt_addr'.
        offset_into_exception_tables: The start of exception tables for
                this function (indicated as an offset into the exception
                tables). A value of -1 indicates that there is no exception
                table entries associated with this function.
        exception_table_symbol: The symbol id of the section for exception
                tables wrt to which the offset_into_exception_tables will
                be relocated.
--------------------------------------------------------------------------*/
Dwarf_Unsigned
dwarf_add_frame_info(Dwarf_P_Debug dbg,
                     Dwarf_P_Fde fde,
                     Dwarf_P_Die die,
                     Dwarf_Unsigned cie,
                     Dwarf_Unsigned virt_addr,
                     Dwarf_Unsigned code_len,
                     Dwarf_Unsigned symidx,
                     Dwarf_Signed offset_into_exception_tables,
                     Dwarf_Unsigned exception_table_symbol,
                     Dwarf_Error * error)
{

    return dwarf_add_frame_info_b(dbg, fde, die, cie, virt_addr,
                                  code_len, symidx,
                                  /* end_symbol */ 0,
                                  /* offset_from_end */ 0,
                                  offset_into_exception_tables,
                                  exception_table_symbol, error);

}

 /*ARGSUSED*/                   /* pretend all args used */
Dwarf_Unsigned
dwarf_add_frame_info_b(Dwarf_P_Debug dbg,
                       Dwarf_P_Fde fde,
                       Dwarf_P_Die die,
                       Dwarf_Unsigned cie,
                       Dwarf_Unsigned virt_addr,
                       Dwarf_Unsigned code_len,
                       Dwarf_Unsigned symidx,
                       Dwarf_Unsigned end_symidx,
                       Dwarf_Unsigned offset_from_end_symbol,
                       Dwarf_Signed offset_into_exception_tables,
                       Dwarf_Unsigned exception_table_symbol,
                       Dwarf_Error * error)
{
    Dwarf_P_Fde curfde;

    fde->fde_die = die;
    fde->fde_cie = (long) cie;
    fde->fde_initloc = virt_addr;
    fde->fde_r_symidx = symidx;
    fde->fde_addr_range = code_len;
    fde->fde_offset_into_exception_tables =
        offset_into_exception_tables;
    fde->fde_exception_table_symbol = exception_table_symbol;
    fde->fde_end_symbol_offset = offset_from_end_symbol;
    fde->fde_end_symbol = end_symidx;
    fde->fde_dbg = dbg;

    curfde = dbg->de_last_fde;
    if (curfde == NULL) {
        dbg->de_frame_fdes = fde;
        dbg->de_last_fde = fde;
        dbg->de_n_fde = 1;
    } else {
        curfde->fde_next = fde;
        dbg->de_last_fde = fde;
        dbg->de_n_fde++;
    }
    return dbg->de_n_fde;
}

/* This is an alternate to inserting frame instructions
   one instruction at a time.  But use either this
   or instruction level, not both in one fde. */
int
dwarf_insert_fde_inst_bytes(Dwarf_P_Debug dbg,
    Dwarf_P_Fde fde,Dwarf_Unsigned len, Dwarf_Ptr ibytes,
    Dwarf_Error *error)
{
    if( len == 0) {
        return DW_DLV_OK;
    }
    if(fde->fde_block || fde->fde_inst) {
        DWARF_P_DBG_ERROR(dbg, DW_DLE_DUPLICATE_INST_BLOCK,
            (int)DW_DLV_BADADDR);
    }
    fde->fde_block = (Dwarf_Ptr)_dwarf_p_get_alloc(dbg, len);
    memcpy(fde->fde_block,ibytes,len);
    fde->fde_inst_block_size = len;
    fde->fde_n_bytes += len;
    return DW_DLV_OK;
}
    


/*-------------------------------------------------------------------
        Create a new fde.
---------------------------------------------------------------------*/
Dwarf_P_Fde
dwarf_new_fde(Dwarf_P_Debug dbg, Dwarf_Error * error)
{
    Dwarf_P_Fde fde;

    fde = (Dwarf_P_Fde)
        _dwarf_p_get_alloc(dbg, sizeof(struct Dwarf_P_Fde_s));
    if (fde == NULL) {
        DWARF_P_DBG_ERROR(dbg, DW_DLE_FDE_ALLOC,
                          (Dwarf_P_Fde) DW_DLV_BADADDR);
    }
    
    fde->fde_uwordb_size = dbg->de_offset_size;

    return fde;
}


/*------------------------------------------------------------------------
        Add a cfe_offset instruction to the fde passed in.
-------------------------------------------------------------------------*/
Dwarf_P_Fde
dwarf_fde_cfa_offset(Dwarf_P_Fde fde,
                     Dwarf_Unsigned reg,
                     Dwarf_Signed offset, Dwarf_Error * error)
{
    Dwarf_Ubyte opc, regno;
    char *ptr;
    Dwarf_P_Frame_Pgm curinst;
    int nbytes;
    int res;
    char buff1[ENCODE_SPACE_NEEDED];
    Dwarf_P_Debug dbg = fde->fde_dbg;

    curinst = (Dwarf_P_Frame_Pgm)
        _dwarf_p_get_alloc(dbg, sizeof(struct Dwarf_P_Frame_Pgm_s));
    if (curinst == NULL) {
        DWARF_P_DBG_ERROR(dbg, DW_DLE_FPGM_ALLOC,
                          (Dwarf_P_Fde) DW_DLV_BADADDR);
    }
    opc = DW_CFA_offset;
    regno = reg;
    if (regno & 0xc0) {
        DWARF_P_DBG_ERROR(dbg, DW_DLE_REGNO_OVFL,
                          (Dwarf_P_Fde) DW_DLV_BADADDR);
    }
    opc = opc | regno;          /* lower 6 bits are register number */
    curinst->dfp_opcode = opc;
    res = _dwarf_pro_encode_leb128_nm(offset, &nbytes,
                                      buff1, sizeof(buff1));
    if (res != DW_DLV_OK) {
        _dwarf_p_error(dbg, error, DW_DLE_STRING_ALLOC);
        return ((Dwarf_P_Fde) DW_DLV_BADADDR);
    }
    ptr = (char *) _dwarf_p_get_alloc(dbg, nbytes);
    if (ptr == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_STRING_ALLOC);
        return ((Dwarf_P_Fde) DW_DLV_BADADDR);
    }
    memcpy(ptr, buff1, nbytes);

    curinst->dfp_args = ptr;
    curinst->dfp_nbytes = nbytes;
    curinst->dfp_next = NULL;

    _dwarf_pro_add_to_fde(fde, curinst);
    return fde;
}

/*
    Generic routine to add opcode to fde instructions. val1 and
    val2 are parameters whose interpretation depends on the 'op'.

    This does not work properly for  DW_DLC_SYMBOLIC_RELOCATIONS
    for DW_CFA_set_loc or DW_DVA_advance_loc* 'op', as
    these ops normally are addresses or (DW_CFA_set_loc) 
    or code lengths (DW_DVA_advance_loc*) and such must be
    represented with relocations and symbol indices for
    DW_DLC_SYMBOLIC_RELOCATIONS.

    This does not treat all DW_CFA instructions yet.

    For certain operations a val? value must be
    signed (though passed in as unsigned here).

    Currently this does not check that the frame
    version is 3(for dwarf3) or 4 (for dwarf4)
    when applying operations that are only valid for
    dwarf3 or dwarf4.

*/
Dwarf_P_Fde
dwarf_add_fde_inst(Dwarf_P_Fde fde,
                   Dwarf_Small op,
                   Dwarf_Unsigned val1,
                   Dwarf_Unsigned val2, Dwarf_Error * error)
{
    Dwarf_P_Frame_Pgm curinst;
    int nbytes, nbytes1, nbytes2;
    Dwarf_Ubyte db;
    Dwarf_Half dh;
    Dwarf_Word dw;
    Dwarf_Unsigned du;
    char *ptr;
    int res;
    char buff1[ENCODE_SPACE_NEEDED];
    char buff2[ENCODE_SPACE_NEEDED];
    Dwarf_P_Debug dbg = fde->fde_dbg;
    /* This is a hack telling the code when to transform
       a value to a signed leb number. */
    int signed_second = 0;
    int signed_first = 0;


    nbytes = 0;
    ptr = NULL;
    curinst = (Dwarf_P_Frame_Pgm)
        _dwarf_p_get_alloc(dbg, sizeof(struct Dwarf_P_Frame_Pgm_s));
    if (curinst == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_FPGM_ALLOC);
        return ((Dwarf_P_Fde) DW_DLV_BADADDR);
    }

    switch (op) {

    case DW_CFA_advance_loc:
        if (val1 <= 0x3f) {
            db = val1;
            op |= db;
        }
        /* test not portable FIX */
        else if (val1 <= UCHAR_MAX) {
            op = DW_CFA_advance_loc1;
            db = val1;
            ptr = (char *) _dwarf_p_get_alloc(dbg, 1);
            if (ptr == NULL) {
                _dwarf_p_error(dbg, error, DW_DLE_STRING_ALLOC);
                return ((Dwarf_P_Fde) DW_DLV_BADADDR);
            }
            memcpy((void *) ptr, (const void *) &db, 1);
            nbytes = 1;
        }
        /* test not portable FIX */
        else if (val1 <= USHRT_MAX) {
            op = DW_CFA_advance_loc2;
            dh = val1;
            ptr = (char *) _dwarf_p_get_alloc(dbg, 2);
            if (ptr == NULL) {
                _dwarf_p_error(dbg, error, DW_DLE_STRING_ALLOC);
                return ((Dwarf_P_Fde) DW_DLV_BADADDR);
            }
            memcpy((void *) ptr, (const void *) &dh, 2);
            nbytes = 2;
        }
        /* test not portable FIX */
        else if (val1 <= ULONG_MAX) {
            op = DW_CFA_advance_loc4;
            dw = (Dwarf_Word) val1;
            ptr = (char *) _dwarf_p_get_alloc(dbg, 4);
            if (ptr == NULL) {
                _dwarf_p_error(dbg, error, DW_DLE_STRING_ALLOC);
                return ((Dwarf_P_Fde) DW_DLV_BADADDR);
            }
            memcpy((void *) ptr, (const void *) &dw, 4);
            nbytes = 4;
        } else {
            op = DW_CFA_MIPS_advance_loc8;
            du = val1;
            ptr =
                (char *) _dwarf_p_get_alloc(dbg,
                                            sizeof(Dwarf_Unsigned));
            if (ptr == NULL) {
                _dwarf_p_error(dbg, error, DW_DLE_STRING_ALLOC);
                return ((Dwarf_P_Fde) DW_DLV_BADADDR);
            }
            memcpy((void *) ptr, (const void *) &du, 8);
            nbytes = 8;
        }
        break;

    case DW_CFA_offset:
        if (val1 <= MAX_6_BIT_VALUE) {
            db = val1;
            op |= db;
            res = _dwarf_pro_encode_leb128_nm(val2, &nbytes,
                                              buff1, sizeof(buff1));
            if (res != DW_DLV_OK) {
                _dwarf_p_error(dbg, error, DW_DLE_STRING_ALLOC);
                return ((Dwarf_P_Fde) DW_DLV_BADADDR);
            }
            ptr = (char *) _dwarf_p_get_alloc(dbg, nbytes);
            if (ptr == NULL) {
                _dwarf_p_error(dbg, error, DW_DLE_STRING_ALLOC);
                return ((Dwarf_P_Fde) DW_DLV_BADADDR);
            }
            memcpy(ptr, buff1, nbytes);

        } else {
            op = DW_CFA_offset_extended;
            goto two_leb;
        }
        break;
    case DW_CFA_offset_extended_sf: /* DWARF3 */
            signed_second = 1;
            goto two_leb;
    case DW_CFA_offset_extended:
            goto two_leb;

    case DW_CFA_undefined:
    case DW_CFA_same_value:
        goto one_leb;

    case DW_CFA_val_offset:
         goto two_leb;
    case DW_CFA_val_offset_sf:
         signed_second = 1;
         goto two_leb;
    case DW_CFA_def_cfa_sf:
         signed_second = 1;
         goto two_leb;
    case DW_CFA_register:
    case DW_CFA_def_cfa:
    two_leb:
        res = _dwarf_pro_encode_leb128_nm(val1, &nbytes1,
                                          buff1, sizeof(buff1));
        if (res != DW_DLV_OK) {
            _dwarf_p_error(dbg, error, DW_DLE_STRING_ALLOC);
            return ((Dwarf_P_Fde) DW_DLV_BADADDR);
        }
        if (!signed_second) {
                res = _dwarf_pro_encode_leb128_nm(val2, &nbytes2,
                                              buff2, sizeof(buff2));
        } else {
            Dwarf_Signed val2s = val2;
            res = _dwarf_pro_encode_signed_leb128_nm(val2s, &nbytes2,
                                              buff2, sizeof(buff2));
        }

        res = _dwarf_pro_encode_leb128_nm(val2, &nbytes2,
                                          buff2, sizeof(buff2));
        if (res != DW_DLV_OK) {
            _dwarf_p_error(dbg, error, DW_DLE_STRING_ALLOC);
            return ((Dwarf_P_Fde) DW_DLV_BADADDR);
        }

        ptr = (char *) _dwarf_p_get_alloc(dbg, nbytes1 + nbytes2);
        if (ptr == NULL) {
            _dwarf_p_error(dbg, error, DW_DLE_STRING_ALLOC);
            return ((Dwarf_P_Fde) DW_DLV_BADADDR);
        }
        memcpy(ptr, buff1, nbytes1);
        memcpy(ptr + nbytes1, buff2, nbytes2);
        nbytes = nbytes1 + nbytes2;
        break;

    case DW_CFA_def_cfa_offset_sf: /* DWARF3 */
        signed_first = 1;
        goto one_leb;
    case DW_CFA_def_cfa_register:
    case DW_CFA_def_cfa_offset:
    one_leb:
        if(!signed_first) {
            res = _dwarf_pro_encode_leb128_nm(val1, &nbytes,
                                          buff1, sizeof(buff1));
        } else {
            Dwarf_Signed val1s = val1;
            res = _dwarf_pro_encode_signed_leb128_nm(val1s, &nbytes,
                                          buff1, sizeof(buff1));
        }
        if (res != DW_DLV_OK) {
            _dwarf_p_error(dbg, error, DW_DLE_STRING_ALLOC);
            return ((Dwarf_P_Fde) DW_DLV_BADADDR);
        }
        ptr = (char *) _dwarf_p_get_alloc(dbg, nbytes);
        if (ptr == NULL) {
            _dwarf_p_error(dbg, error, DW_DLE_STRING_ALLOC);
            return ((Dwarf_P_Fde) DW_DLV_BADADDR);
        }
        memcpy(ptr, buff1, nbytes);
        break;
    case DW_CFA_def_cfa_expression: /* DWARF3 */
        /* FIXME: argument is dwarf expr, not handled yet. */
    case DW_CFA_expression: /* DWARF3 */
        /* First arg: ULEB reg num. 2nd arg dwarf expr in form block.
           FIXME: not handled yet. */
    case DW_CFA_val_expression: /* DWARF3f */
        /* First arg: ULEB reg num. 2nd arg dwarf expr in form block.
           FIXME: not handled yet. */
    default:
        _dwarf_p_error(dbg, error, DW_DLE_DEBUGFRAME_ERROR);
        return ((Dwarf_P_Fde) DW_DLV_BADADDR);
    }

    curinst->dfp_opcode = op;
    curinst->dfp_args = ptr;
    curinst->dfp_nbytes = nbytes;
    curinst->dfp_next = NULL;

    _dwarf_pro_add_to_fde(fde, curinst);
    return fde;
}


/*------------------------------------------------------------------------
        Instructions are added to an fde in the form of a linked
        list. This function manages the linked list.
-------------------------------------------------------------------------*/
void
_dwarf_pro_add_to_fde(Dwarf_P_Fde fde, Dwarf_P_Frame_Pgm curinst)
{
    if (fde->fde_last_inst) {
        fde->fde_last_inst->dfp_next = curinst;
        fde->fde_last_inst = curinst;
        fde->fde_n_inst++;
        fde->fde_n_bytes +=
            (long) (curinst->dfp_nbytes + sizeof(Dwarf_Ubyte));
    } else {
        fde->fde_last_inst = curinst;
        fde->fde_inst = curinst;
        fde->fde_n_inst = 1;
        fde->fde_n_bytes =
            (long) (curinst->dfp_nbytes + sizeof(Dwarf_Ubyte));
    }
}
