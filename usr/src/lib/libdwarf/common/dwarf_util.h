#ifndef DWARF_UTIL_H
#define DWARF_UTIL_H
/*

  Copyright (C) 2000,2003,2004 Silicon Graphics, Inc.  All Rights Reserved.
  Portions Copyright (C) 2007-2020 David Anderson. All Rights Reserved.
  Portions Copyright (C) 2010-2012 SN Systems Ltd. All Rights Reserved

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

/*
    Decodes unsigned leb128 encoded numbers.
    Make sure ptr is a pointer to a 1-byte type.
    In 2003 and earlier this was a hand-inlined
    version of _dwarf_decode_u_leb128() which did
    not work correctly if Dwarf_Unsigned was 64 bits.

    April 2016: now uses a reader that is careful.
    'return' only in case of error
    else falls through.
*/
#define DECODE_LEB128_UWORD_CK(ptr, value,dbg,errptr,endptr) \
    do {                                              \
        Dwarf_Unsigned lu_leblen = 0;                     \
        Dwarf_Unsigned lu_local = 0;                  \
        int lu_res = 0;                               \
        lu_res = _dwarf_decode_u_leb128_chk(ptr,&lu_leblen,&lu_local,endptr); \
        if (lu_res == DW_DLV_ERROR) {                 \
            _dwarf_error(dbg, errptr, DW_DLE_LEB_IMPROPER);  \
            return DW_DLV_ERROR;                      \
        }                                             \
        value = lu_local;                             \
        ptr += lu_leblen;                             \
    } while (0)

#define DECODE_LEB128_UWORD_LEN_CK(ptr, value,leblen,dbg,errptr,endptr) \
    do {                                              \
        Dwarf_Unsigned lu_leblen = 0;                     \
        Dwarf_Unsigned lu_local = 0;                  \
        int lu_res = 0;                               \
        lu_res = _dwarf_decode_u_leb128_chk(ptr,&lu_leblen,&lu_local,endptr); \
        if (lu_res == DW_DLV_ERROR) {                 \
            _dwarf_error(dbg, errptr, DW_DLE_LEB_IMPROPER);  \
            return DW_DLV_ERROR;                      \
        }                                             \
        value = lu_local;                             \
        ptr += lu_leblen;                             \
        leblen = lu_leblen;                          \
    } while (0)

/*
    Decodes signed leb128 encoded numbers.
    Make sure ptr is a pointer to a 1-byte type.
    In 2003 and earlier this was a hand-inlined
    version of _dwarf_decode_s_leb128() which did
    not work correctly if Dwarf_Unsigned was 64 bits.

*/
#define DECODE_LEB128_SWORD_CK(ptr, value,dbg,errptr,endptr) \
    do {                                              \
        Dwarf_Unsigned uleblen = 0;                       \
        Dwarf_Signed local = 0;                       \
        int lu_res = 0;                               \
        lu_res = _dwarf_decode_s_leb128_chk(ptr,&uleblen,&local,endptr); \
        if (lu_res == DW_DLV_ERROR) {                 \
            _dwarf_error(dbg, errptr, DW_DLE_LEB_IMPROPER);  \
            return DW_DLV_ERROR;                      \
        }                                             \
        value = local;                                \
        ptr += uleblen;                               \
    } while (0)
#define DECODE_LEB128_SWORD_LEN_CK(ptr, value,leblen,dbg,errptr,endptr) \
    do {                                              \
        Dwarf_Unsigned lu_leblen = 0;                     \
        Dwarf_Signed lu_local = 0;                    \
        int lu_res = 0;                               \
        lu_res = _dwarf_decode_s_leb128_chk(ptr,&lu_leblen,\
            &lu_local,endptr); \
        if (lu_res == DW_DLV_ERROR) {                 \
            _dwarf_error(dbg, errptr, DW_DLE_LEB_IMPROPER);  \
            return DW_DLV_ERROR;                      \
        }                                             \
        leblen = lu_leblen;                           \
        value = lu_local;                             \
        ptr += lu_leblen;                             \
    } while (0)


/*
    Skips leb128_encoded numbers that are guaranteed
    to be no more than 4 bytes long.  Same for both
    signed and unsigned numbers.

    These seem bogus as they assume 4 bytes get a 4 byte
    word. Wrong. FIXME

    'return' only in case of error
    else falls through.
*/
#define SKIP_LEB128_WORD_CK(ptr,dbg,errptr,endptr)                     \
    do {                                          \
        if ((*(ptr++) & 0x80) != 0) {             \
            if (ptr >= endptr) {                  \
                _dwarf_error(dbg, errptr, DW_DLE_LEB_IMPROPER); \
                return DW_DLV_ERROR;              \
            }                                     \
            if ((*(ptr++) & 0x80) != 0) {         \
                if (ptr >= endptr) {              \
                    _dwarf_error(dbg, errptr, DW_DLE_LEB_IMPROPER); \
                    return DW_DLV_ERROR;          \
                }                                 \
                if ((*(ptr++) & 0x80) != 0) {     \
                    if (ptr >= endptr) {          \
                        _dwarf_error(dbg, errptr, DW_DLE_LEB_IMPROPER); \
                        return DW_DLV_ERROR;      \
                    }                             \
                    ptr++;                        \
                    if (ptr >= endptr) {          \
                        _dwarf_error(dbg, errptr, DW_DLE_LEB_IMPROPER); \
                        return DW_DLV_ERROR;      \
                    }                             \
                }                                 \
            }                                     \
        }                                         \
    } while (0)


/*  Any error  found here represents a bug that cannot
    be dealloc-d as the caller will not know there was no dbg */
#define CHECK_DIE(die, error_ret_value)                          \
    do {                                                         \
        if (die == NULL) {                                       \
            _dwarf_error(NULL, error, DW_DLE_DIE_NULL);          \
            return(error_ret_value);                             \
        }                                                        \
        if (die->di_cu_context == NULL) {                        \
            _dwarf_error(NULL, error, DW_DLE_DIE_NO_CU_CONTEXT); \
            return(error_ret_value);                             \
        }                                                        \
        if (die->di_cu_context->cc_dbg == NULL) {                \
            _dwarf_error(NULL, error, DW_DLE_DBG_NULL);          \
            return(error_ret_value);                             \
        }                                                        \
    } while (0)


/*
   Reads 'source' for 'length' bytes from unaligned addr.

   Avoids any constant-in-conditional warnings and
   avoids a test in the generated code (for non-const cases,
   which are in the majority.)
   Uses a temp to avoid the test.
   The decl here should avoid any problem of size in the temp.
   This code is ENDIAN DEPENDENT
   The memcpy args are the endian issue.

   Does not update the 'source' field.

   for READ_UNALIGNED_CK the error code refers to host endianness.
*/
typedef Dwarf_Unsigned BIGGEST_UINT;

#ifdef WORDS_BIGENDIAN
#define READ_UNALIGNED_CK(dbg,dest,desttype, source, length,error,endptr) \
    do {                                                         \
        BIGGEST_UINT _ltmp = 0;                                  \
        Dwarf_Byte_Ptr readend = source+length;                  \
        if (readend <  source) {                                 \
            _dwarf_error(dbg, error, DW_DLE_READ_BIGENDIAN_ERROR); \
            return DW_DLV_ERROR;                                 \
        }                                                        \
        if (readend > endptr) {                                  \
            _dwarf_error(dbg, error, DW_DLE_READ_BIGENDIAN_ERROR); \
            return DW_DLV_ERROR;                                 \
        }                                                        \
        dbg->de_copy_word( (((char *)(&_ltmp)) +                 \
            sizeof(_ltmp) - length),source, length) ;            \
        dest = (desttype)_ltmp;                                  \
    } while (0)


/*
    This macro sign-extends a variable depending on the length.
    It fills the bytes between the size of the destination and
    the length with appropriate padding.
    This code is ENDIAN DEPENDENT but dependent only
    on host endianness, not object file endianness.
    The memcpy args are the issue.
*/
#define SIGN_EXTEND(dest, length)                                 \
    do {                                                          \
        if (*(Dwarf_Sbyte *)((char *)&dest +                      \
            sizeof(dest) - length) < 0) {                         \
            memcpy((char *)&dest, "\xff\xff\xff\xff\xff\xff\xff\xff",\
                sizeof(dest) - length);                           \
        }                                                         \
    } while (0)
#else /* LITTLE ENDIAN */
#define READ_UNALIGNED_CK(dbg,dest,desttype, source, length,error,endptr) \
    do  {                                       \
        BIGGEST_UINT _ltmp = 0;                 \
        Dwarf_Byte_Ptr readend = source+length; \
        if (readend < source) {                 \
            _dwarf_error(dbg, error,            \
                DW_DLE_READ_LITTLEENDIAN_ERROR);\
            return DW_DLV_ERROR;                \
        }                                       \
        if (readend > endptr) {                 \
            _dwarf_error(dbg, error,            \
                DW_DLE_READ_LITTLEENDIAN_ERROR);\
            return DW_DLV_ERROR;                \
        }                                       \
        dbg->de_copy_word( (char *)(&_ltmp) ,   \
            source, length) ;                   \
        dest = (desttype)_ltmp;                 \
    } while (0)


/*
    This macro sign-extends a variable depending on the length.
    It fills the bytes between the size of the destination and
    the length with appropriate padding.
    This code is ENDIAN DEPENDENT but dependent only
    on host endianness, not object file endianness.
    The memcpy args are the issue.
*/
#define SIGN_EXTEND(dest, length)                               \
    do {                                                        \
        if (*(Dwarf_Sbyte *)((char *)&dest + (length-1)) < 0) { \
            memcpy((char *)&dest+length,                        \
                "\xff\xff\xff\xff\xff\xff\xff\xff",             \
                sizeof(dest) - length);                         \
        }                                                       \
    } while (0)

#endif /* ! LITTLE_ENDIAN */



/*
    READ_AREA LENGTH reads the length (the older way
    of pure 32 or 64 bit
    or the dwarf v3 64bit-extension way)

    It reads the bits from where rw_src_data_p  points to
    and updates the rw_src_data_p to point past what was just read.

    It updates w_length_size (to the size of an offset, either 4 or 8)
    and w_exten_size (set 0 unless this frame has the DWARF3
    and later  64bit
    extension, in which case w_exten_size is set to 4).

    r_dbg is just the current dbg pointer.
    w_target is the output length field.
    r_targtype is the output type. Always Dwarf_Unsigned so far.

*/
/*  This one handles the v3 64bit extension
    and 32bit (and   SGI/MIPS fixed 64  bit via the
        dwarf_init-set r_dbg->de_length_size)..
    It does not recognize any but the one distingushed value
    (the only one with defined meaning).
    It assumes that no CU will have a length
        0xffffffxx  (32bit length)
        or
        0xffffffxx xxxxxxxx (64bit length)
    which makes possible auto-detection of the extension.

    This depends on knowing that only a non-zero length
    is legitimate (AFAICT), and for IRIX non-standard -64
    dwarf that the first 32 bits of the 64bit offset will be
    zero (because the compiler could not handle a truly large
    value as of Jan 2003 and because no app has that much debug
    info anyway, at least not in the IRIX case).

    At present not testing for '64bit elf' here as that
    does not seem necessary (none of the 64bit length seems
    appropriate unless it's  ident[EI_CLASS] == ELFCLASS64).
*/
/*  The w_target > r_sectionlen compare is done without adding in case
    the w_target value read is so large any addition would overflow.
    A basic value sanity check. */
#define READ_AREA_LENGTH_CK(r_dbg,w_target,r_targtype,         \
    rw_src_data_p,w_length_size,w_exten_size,w_error,          \
    r_sectionlen,r_endptr)                                     \
    do {                                                       \
        READ_UNALIGNED_CK(r_dbg,w_target,r_targtype,           \
            rw_src_data_p, ORIGINAL_DWARF_OFFSET_SIZE,         \
            w_error,r_endptr);                                 \
        if (w_target == DISTINGUISHED_VALUE) {                 \
            /* dwarf3 64bit extension */                       \
            w_length_size  = DISTINGUISHED_VALUE_OFFSET_SIZE;  \
            rw_src_data_p += ORIGINAL_DWARF_OFFSET_SIZE;       \
            w_exten_size   = ORIGINAL_DWARF_OFFSET_SIZE;       \
            READ_UNALIGNED_CK(r_dbg,w_target,r_targtype,       \
                rw_src_data_p, DISTINGUISHED_VALUE_OFFSET_SIZE,\
                w_error,r_endptr);                             \
            if (w_target > r_sectionlen) {                     \
                _dwarf_error(r_dbg,w_error,                    \
                    DW_DLE_HEADER_LEN_BIGGER_THAN_SECSIZE);    \
                return DW_DLV_ERROR;                           \
            }                                                  \
            rw_src_data_p += DISTINGUISHED_VALUE_OFFSET_SIZE;  \
        } else {                                               \
            if (w_target == 0 && r_dbg->de_big_endian_object) {\
                /* Might be IRIX: We have to distinguish between */\
                /* 32-bit DWARF format and IRIX 64-bit         \
                    DWARF format. */                           \
                if (r_dbg->de_length_size == 8) {              \
                    /* IRIX 64 bit, big endian.  This test */  \
                    /* is not a truly precise test, a precise test*/ \
                    /* would check if the target was IRIX.  */  \
                    READ_UNALIGNED_CK(r_dbg,w_target,r_targtype,\
                        rw_src_data_p,                          \
                        DISTINGUISHED_VALUE_OFFSET_SIZE,      \
                        w_error,r_endptr);                     \
                    if (w_target > r_sectionlen) {             \
                        _dwarf_error(r_dbg,w_error,            \
                            DW_DLE_HEADER_LEN_BIGGER_THAN_SECSIZE);\
                        return DW_DLV_ERROR;                   \
                    }                                          \
                    w_length_size  = DISTINGUISHED_VALUE_OFFSET_SIZE;\
                    rw_src_data_p += DISTINGUISHED_VALUE_OFFSET_SIZE;\
                    w_exten_size = 0;                          \
                } else {                                       \
                    /* 32 bit, big endian */                   \
                    w_length_size  = ORIGINAL_DWARF_OFFSET_SIZE;\
                    rw_src_data_p += w_length_size;            \
                    w_exten_size = 0;                          \
                }                                              \
            } else {                                           \
                if (w_target > r_sectionlen) {                 \
                    _dwarf_error(r_dbg,w_error,                \
                        DW_DLE_HEADER_LEN_BIGGER_THAN_SECSIZE);\
                    return DW_DLV_ERROR;                       \
                }                                              \
                /* Standard 32 bit dwarf2/dwarf3 */            \
                w_exten_size   = 0;                            \
                w_length_size  = ORIGINAL_DWARF_OFFSET_SIZE;   \
                rw_src_data_p += w_length_size;                \
            }                                                  \
        }                                                      \
    } while (0)


/* Fuller checking. Returns DW_DLV_ERROR or DW_DLV_OK
   Caller must set Dwarf_Error */
int _dwarf_decode_u_leb128_chk(Dwarf_Small * leb128,
    Dwarf_Unsigned * leb128_length,
    Dwarf_Unsigned *outval,Dwarf_Byte_Ptr endptr);

int _dwarf_format_TAG_err_msg(Dwarf_Debug dbg,
    Dwarf_Unsigned tag,const char *m,
    Dwarf_Error *error);


int _dwarf_decode_s_leb128_chk(Dwarf_Small * leb128,
    Dwarf_Unsigned * leb128_length,
    Dwarf_Signed *outval, Dwarf_Byte_Ptr endptr);

int
_dwarf_get_size_of_val(Dwarf_Debug dbg,
    Dwarf_Unsigned form,
    Dwarf_Half cu_version,
    Dwarf_Half address_size,
    Dwarf_Small * val_ptr,
    int v_length_size,
    Dwarf_Unsigned *size_out,
    Dwarf_Small *section_end_ptr,
    Dwarf_Error *error);

struct Dwarf_Hash_Table_Entry_s;
/* This single struct is the base for the hash table.
   The intent is that once the total_abbrev_count across
   all the entries is greater than  10*current_table_entry_count
   one should build a new Dwarf_Hash_Table_Base_s, rehash
   all the existing entries, and delete the old table and entries.
   (10 is a heuristic, nothing magic about it, but once the
   count gets to 30 or 40 times current_table_entry_count
   things really slow down a lot. One (500MB) application had
   127000 abbreviations in one compilation unit)
   The incoming 'code' is an abbrev number and those simply
   increase linearly so the hashing is perfect always.
*/
struct Dwarf_Hash_Table_s {
    unsigned long       tb_table_entry_count;
    unsigned long       tb_total_abbrev_count;
    /* Each table entry is a list of abbreviations. */
    struct  Dwarf_Hash_Table_Entry_s *tb_entries;
};

/*
    This struct is used to build a hash table for the
    abbreviation codes for a compile-unit.
*/
struct Dwarf_Hash_Table_Entry_s {
    Dwarf_Abbrev_List at_head;
};



int _dwarf_get_abbrev_for_code(Dwarf_CU_Context cu_context,
    Dwarf_Unsigned code,
    Dwarf_Abbrev_List *list_out,Dwarf_Error *error);


/* return 1 if string ends before 'endptr' else
** return 0 meaning string is not properly terminated.
** Presumption is the 'endptr' pts to end of some dwarf section data.
*/
int _dwarf_check_string_valid(Dwarf_Debug dbg,void *areaptr,
    void *startptr, void *endptr,
    int suggested_error, Dwarf_Error *error);

int _dwarf_length_of_cu_header(Dwarf_Debug dbg, Dwarf_Unsigned offset,
    Dwarf_Bool is_info,
    Dwarf_Unsigned *area_length_out,
    Dwarf_Error *error);

Dwarf_Unsigned _dwarf_length_of_cu_header_simple(Dwarf_Debug,Dwarf_Bool dinfo);

int  _dwarf_load_debug_info(Dwarf_Debug dbg, Dwarf_Error *error);
int  _dwarf_load_debug_types(Dwarf_Debug dbg, Dwarf_Error *error);
void _dwarf_free_abbrev_hash_table_contents(Dwarf_Debug dbg,
    struct Dwarf_Hash_Table_s* hash_table);
int _dwarf_get_address_size(Dwarf_Debug dbg, Dwarf_Die die);
int _dwarf_reference_outside_section(Dwarf_Die die,
    Dwarf_Small * startaddr,
    Dwarf_Small * pastend);
void _dwarf_error_mv_s_to_t(Dwarf_Debug dbgs,Dwarf_Error *errs,
    Dwarf_Debug dbgt,Dwarf_Error *errt);

int _dwarf_internal_get_die_comp_dir(Dwarf_Die die, const char **compdir_out,
    const char **comp_name_out,
    Dwarf_Error *error);

int _dwarf_what_section_are_we(Dwarf_Debug dbg,
    Dwarf_Small *our_pointer,
    const char **      section_name_out,
    Dwarf_Small    **sec_start_ptr_out,
    Dwarf_Unsigned *sec_len_out,
    Dwarf_Small    **sec_end_ptr_out,
    Dwarf_Error *error);

/*  wrappers return either DW_DLV_OK or DW_DLV_ERROR.
    Never DW_DLV_NO_ENTRY. */
int
_dwarf_read_unaligned_ck_wrapper(Dwarf_Debug dbg,
    Dwarf_Unsigned *out_value,
    Dwarf_Small *readfrom,
    int          readlength,
    Dwarf_Small *end_arange,
    Dwarf_Error *err);
int
_dwarf_read_area_length_ck_wrapper(Dwarf_Debug dbg,
    Dwarf_Unsigned *out_value,
    Dwarf_Small **readfrom,
    int    *  length_size_out,
    int    *  exten_size_out,
    Dwarf_Unsigned sectionlength,
    Dwarf_Small *endsection,
    Dwarf_Error *err);
int
_dwarf_leb128_uword_wrapper(Dwarf_Debug dbg,
    Dwarf_Small ** startptr,
    Dwarf_Small * endptr,
    Dwarf_Unsigned *out_value,
    Dwarf_Error * error);
int
_dwarf_leb128_sword_wrapper(Dwarf_Debug dbg,
    Dwarf_Small ** startptr,
    Dwarf_Small * endptr,
    Dwarf_Signed *out_value,
    Dwarf_Error * error);



#endif /* DWARF_UTIL_H */
