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
#include "pro_incl.h"
#include "pro_section.h"
#include "pro_macinfo.h"

/*
        I don't much like the error strings this generates, since
        like the rest of libdwarf they are simple strings with
        no useful numbers in them. But that's not something I can
        fix without more work than I have time for
        right now.  davea Nov 94.
*/

/* these are gross overestimates of the number of
** bytes needed to store a number in LEB form.
** Just estimates, and since blocks are reasonable size,
** the end-block waste is small.
** Of course the waste is NOT present on disk.
*/

#define COMMAND_LEN ENCODE_SPACE_NEEDED
#define LINE_LEN    ENCODE_SPACE_NEEDED
#define BASE_MACINFO_MALLOC_LEN 2048

static int
libdwarf_compose_begin(Dwarf_P_Debug dbg, int code,
                       size_t maxlen, int *compose_error_type)
{
    unsigned char *nextchar;
    struct dw_macinfo_block_s *curblk = dbg->de_current_macinfo;

    if (curblk == 0) {
        struct dw_macinfo_block_s *newb;
        size_t len;

        /* initial allocation */
        size_t blen = BASE_MACINFO_MALLOC_LEN;

        if (blen < maxlen) {
            blen = 2 * maxlen;
        }
        len = sizeof(struct dw_macinfo_block_s) + blen;
        newb =
            (struct dw_macinfo_block_s *) _dwarf_p_get_alloc(dbg, len);
        if (!newb) {
            *compose_error_type = DW_DLE_MACINFO_MALLOC_FAIL;
            return DW_DLV_ERROR;
        }
        newb->mb_data =
            (char *) newb + sizeof(struct dw_macinfo_block_s);
        newb->mb_avail_len = blen;
        newb->mb_used_len = 0;
        newb->mb_macinfo_data_space_len = blen;
        dbg->de_first_macinfo = newb;
        dbg->de_current_macinfo = newb;
        curblk = newb;
    } else if (curblk->mb_avail_len < maxlen) {
        struct dw_macinfo_block_s *newb;
        size_t len;

        /* no space left in block: allocate a new block */
        size_t blen =
            dbg->de_current_macinfo->mb_macinfo_data_space_len * 2;
        if (blen < maxlen) {
            blen = 2 * maxlen;
        }
        len = sizeof(struct dw_macinfo_block_s) + blen;
        newb =
            (struct dw_macinfo_block_s *) _dwarf_p_get_alloc(dbg, len);
        if (!newb) {
            *compose_error_type = DW_DLE_MACINFO_MALLOC_FAIL;
            return DW_DLV_ERROR;
        }
        newb->mb_data =
            (char *) newb + sizeof(struct dw_macinfo_block_s);
        newb->mb_avail_len = blen;
        newb->mb_used_len = 0;
        newb->mb_macinfo_data_space_len = blen;
        dbg->de_first_macinfo->mb_next = newb;
        dbg->de_current_macinfo = newb;
        curblk = newb;
    }
    /* now curblk has enough room */
    dbg->de_compose_avail = curblk->mb_avail_len;
    dbg->de_compose_used_len = curblk->mb_used_len;
    nextchar =
        (unsigned char *) (curblk->mb_data + dbg->de_compose_used_len);
    *nextchar = code;
    dbg->de_compose_avail--;
    ++dbg->de_compose_used_len;
    return DW_DLV_OK;
}



static void
libdwarf_compose_add_string(Dwarf_P_Debug dbg, char *string, size_t len)
{
    struct dw_macinfo_block_s *curblk = dbg->de_current_macinfo;
    unsigned char *nextchar;

    nextchar =
        (unsigned char *) (curblk->mb_data + dbg->de_compose_used_len);

    len += 1;                   /* count the null terminator */

    memcpy(nextchar, string, len);
    dbg->de_compose_avail -= len;
    dbg->de_compose_used_len += len;
    return;

}
static int
libdwarf_compose_add_line(Dwarf_P_Debug dbg,
                          Dwarf_Unsigned line, int *compose_error_type)
{
    struct dw_macinfo_block_s *curblk = dbg->de_current_macinfo;
    unsigned char *nextchar;
    int res;
    int nbytes;

    nextchar =
        (unsigned char *) (curblk->mb_data + dbg->de_compose_used_len);

    /* Put the created leb number directly into the macro buffer If
       dbg->de_compose_avail is > INT_MAX this will not work as the
       'int' will look negative to _dwarf_pro_encode_leb128_nm! */

    res = _dwarf_pro_encode_leb128_nm(line, &nbytes,
                                      (char *) nextchar,
                                      (int) dbg->de_compose_avail);
    if (res != DW_DLV_OK) {
        *compose_error_type = DW_DLE_MACINFO_INTERNAL_ERROR_SPACE;
        return DW_DLV_ERROR;
    }

    dbg->de_compose_avail -= nbytes;
    dbg->de_compose_used_len += nbytes;
    return DW_DLV_OK;
}

/*
   This function actually 'commits' the space used by the
   preceeding calls.
*/
static int
libdwarf_compose_complete(Dwarf_P_Debug dbg, int *compose_error_type)
{
    struct dw_macinfo_block_s *curblk = dbg->de_current_macinfo;

    if (dbg->de_compose_used_len > curblk->mb_macinfo_data_space_len) {
        *compose_error_type = DW_DLE_MACINFO_INTERNAL_ERROR_SPACE;
        return DW_DLV_ERROR;
    }
    curblk->mb_avail_len = dbg->de_compose_avail;
    curblk->mb_used_len = dbg->de_compose_used_len;
    return DW_DLV_OK;
}



int
dwarf_def_macro(Dwarf_P_Debug dbg,
                Dwarf_Unsigned line,
                char *macname, char *macvalue, Dwarf_Error * error)
{
    size_t len;
    size_t len2;
    size_t length_est;
    int res;
    int compose_error_type;

    if (dbg == NULL) {
        _dwarf_p_error(NULL, error, DW_DLE_DBG_NULL);
        return (DW_DLV_ERROR);
    }
    if (macname == 0) {
        _dwarf_p_error(NULL, error, DW_DLE_MACINFO_STRING_NULL);
        return (DW_DLV_ERROR);
    }
    len = strlen(macname) + 1;
    if (len == 0) {
        _dwarf_p_error(NULL, error, DW_DLE_MACINFO_STRING_EMPTY);
        return (DW_DLV_ERROR);
    }
    if (macvalue) {
        len2 = strlen(macvalue) + 1;
    } else {
        len2 = 0;
    }
    length_est = COMMAND_LEN + LINE_LEN + len + len2 + 1;       /* 1
                                                                   for
                                                                   space 
                                                                   character 
                                                                   we
                                                                   add */
    res = libdwarf_compose_begin(dbg, DW_MACINFO_define, length_est,
                                 &compose_error_type);
    if (res != DW_DLV_OK) {
        _dwarf_p_error(NULL, error, compose_error_type);
        return (DW_DLV_ERROR);
    }
    res = libdwarf_compose_add_line(dbg, line, &compose_error_type);
    if (res != DW_DLV_OK) {
        _dwarf_p_error(NULL, error, compose_error_type);
        return (DW_DLV_ERROR);
    }
    libdwarf_compose_add_string(dbg, macname, len);
    libdwarf_compose_add_string(dbg, " ", 1);
    if (macvalue) {
        libdwarf_compose_add_string(dbg, " ", 1);
        libdwarf_compose_add_string(dbg, macvalue, len2);
    }
    res = libdwarf_compose_complete(dbg, &compose_error_type);
    if (res != DW_DLV_OK) {
        _dwarf_p_error(NULL, error, compose_error_type);
        return (DW_DLV_ERROR);
    }
    return DW_DLV_OK;
}

int
dwarf_undef_macro(Dwarf_P_Debug dbg,
                  Dwarf_Unsigned line,
                  char *macname, Dwarf_Error * error)
{

    size_t len;
    size_t length_est;
    int res;
    int compose_error_type;

    if (dbg == NULL) {
        _dwarf_p_error(NULL, error, DW_DLE_DBG_NULL);
        return (DW_DLV_ERROR);
    }
    if (macname == 0) {
        _dwarf_p_error(NULL, error, DW_DLE_MACINFO_STRING_NULL);
        return (DW_DLV_ERROR);
    }
    len = strlen(macname) + 1;
    if (len == 0) {
        _dwarf_p_error(NULL, error, DW_DLE_MACINFO_STRING_EMPTY);
        return (DW_DLV_ERROR);
    }
    length_est = COMMAND_LEN + LINE_LEN + len;
    res = libdwarf_compose_begin(dbg, DW_MACINFO_undef, length_est,
                                 &compose_error_type);
    if (res != DW_DLV_OK) {
        _dwarf_p_error(NULL, error, compose_error_type);
        return (DW_DLV_ERROR);
    }
    res = libdwarf_compose_add_line(dbg, line, &compose_error_type);
    if (res != DW_DLV_OK) {
        _dwarf_p_error(NULL, error, compose_error_type);
        return (DW_DLV_ERROR);
    }
    libdwarf_compose_add_string(dbg, macname, len);
    res = libdwarf_compose_complete(dbg, &compose_error_type);
    if (res != DW_DLV_OK) {
        _dwarf_p_error(NULL, error, compose_error_type);
        return (DW_DLV_ERROR);
    }
    return DW_DLV_OK;
}

int
dwarf_start_macro_file(Dwarf_P_Debug dbg,
                       Dwarf_Unsigned fileindex,
                       Dwarf_Unsigned linenumber, Dwarf_Error * error)
{
    size_t length_est;
    int res;
    int compose_error_type;

    if (dbg == NULL) {
        _dwarf_p_error(NULL, error, DW_DLE_DBG_NULL);
        return (DW_DLV_ERROR);
    }
    length_est = COMMAND_LEN + LINE_LEN + LINE_LEN;
    res = libdwarf_compose_begin(dbg, DW_MACINFO_start_file, length_est,
                                 &compose_error_type);
    if (res != DW_DLV_OK) {
        _dwarf_p_error(NULL, error, compose_error_type);
        return (DW_DLV_ERROR);
    }
    res = libdwarf_compose_add_line(dbg, fileindex,
                                    &compose_error_type);
    if (res != DW_DLV_OK) {
        _dwarf_p_error(NULL, error, compose_error_type);
        return (DW_DLV_ERROR);
    }
    res = libdwarf_compose_add_line(dbg, linenumber,
                                    &compose_error_type);
    if (res != DW_DLV_OK) {
        _dwarf_p_error(NULL, error, compose_error_type);
        return (DW_DLV_ERROR);
    }
    return DW_DLV_OK;
}

int
dwarf_end_macro_file(Dwarf_P_Debug dbg, Dwarf_Error * error)
{
    size_t length_est;
    int res;
    int compose_error_type;

    if (dbg == NULL) {
        _dwarf_p_error(NULL, error, DW_DLE_DBG_NULL);
        return (DW_DLV_ERROR);
    }
    length_est = COMMAND_LEN;
    res = libdwarf_compose_begin(dbg, DW_MACINFO_end_file, length_est,
                                 &compose_error_type);
    if (res != DW_DLV_OK) {
        _dwarf_p_error(NULL, error, compose_error_type);
        return (DW_DLV_ERROR);
    }
    res = libdwarf_compose_complete(dbg, &compose_error_type);
    if (res != DW_DLV_OK) {
        _dwarf_p_error(NULL, error, compose_error_type);
        return (DW_DLV_ERROR);
    }
    return DW_DLV_OK;
}

int
dwarf_vendor_ext(Dwarf_P_Debug dbg,
                 Dwarf_Unsigned constant,
                 char *string, Dwarf_Error * error)
{
    size_t len;
    size_t length_est;
    int res;
    int compose_error_type;

    if (dbg == NULL) {
        _dwarf_p_error(NULL, error, DW_DLE_DBG_NULL);
        return (DW_DLV_ERROR);
    }
    if (string == 0) {
        _dwarf_p_error(NULL, error, DW_DLE_MACINFO_STRING_NULL);
        return (DW_DLV_ERROR);
    }
    len = strlen(string) + 1;
    if (len == 0) {
        _dwarf_p_error(NULL, error, DW_DLE_MACINFO_STRING_EMPTY);
        return (DW_DLV_ERROR);
    }
    length_est = COMMAND_LEN + LINE_LEN + len;
    res = libdwarf_compose_begin(dbg, DW_MACINFO_vendor_ext, length_est,
                                 &compose_error_type);
    if (res != DW_DLV_OK) {
        _dwarf_p_error(NULL, error, compose_error_type);
        return (DW_DLV_ERROR);
    }
    res = libdwarf_compose_add_line(dbg, constant, &compose_error_type);
    if (res != DW_DLV_OK) {
        _dwarf_p_error(NULL, error, compose_error_type);
        return (DW_DLV_ERROR);
    }
    libdwarf_compose_add_string(dbg, string, len);
    libdwarf_compose_complete(dbg, &compose_error_type);
    if (res != DW_DLV_OK) {
        _dwarf_p_error(NULL, error, compose_error_type);
        return (DW_DLV_ERROR);
    }
    return DW_DLV_OK;
}



int
_dwarf_pro_transform_macro_info_to_disk(Dwarf_P_Debug dbg,
                                        Dwarf_Error * error)
{
    /* Total num of bytes in .debug_macinfo section. */
    Dwarf_Unsigned mac_num_bytes;

    /* Points to first byte of .debug_macinfo buffer. */
    Dwarf_Small *macinfo;

    /* Fills in the .debug_macinfo buffer. */
    Dwarf_Small *macinfo_ptr;


    /* Used to scan the section data buffers. */
    struct dw_macinfo_block_s *m_prev;
    struct dw_macinfo_block_s *m_sect;


    /* Get the size of the debug_macinfo data */
    mac_num_bytes = 0;
    for (m_sect = dbg->de_first_macinfo; m_sect != NULL;
         m_sect = m_sect->mb_next) {
        mac_num_bytes += m_sect->mb_used_len;
    }
    /* Tthe final entry has a type code of 0 to indicate It is final
       for this CU Takes just 1 byte. */
    mac_num_bytes += 1;

    GET_CHUNK(dbg, dbg->de_elf_sects[DEBUG_MACINFO],
              macinfo, (unsigned long) mac_num_bytes, error);
    if (macinfo == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return (0);
    }

    macinfo_ptr = macinfo;
    m_prev = 0;
    for (m_sect = dbg->de_first_macinfo; m_sect != NULL;
         m_sect = m_sect->mb_next) {
        memcpy(macinfo_ptr, m_sect->mb_data, m_sect->mb_used_len);
        macinfo_ptr += m_sect->mb_used_len;
        if (m_prev) {
            _dwarf_p_dealloc(dbg, (Dwarf_Small *) m_prev);
            m_prev = 0;
        }
        m_prev = m_sect;
    }
    *macinfo_ptr = 0;           /* the type code of 0 as last entry */
    if (m_prev) {
        _dwarf_p_dealloc(dbg, (Dwarf_Small *) m_prev);
        m_prev = 0;
    }

    dbg->de_first_macinfo = NULL;
    dbg->de_current_macinfo = NULL;

    return (int) dbg->de_n_debug_sect;
}
