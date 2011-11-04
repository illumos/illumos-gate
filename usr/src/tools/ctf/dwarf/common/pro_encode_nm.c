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
#include <string.h>
#include "pro_incl.h"

#define MORE_BYTES      0x80
#define DATA_MASK       0x7f
#define DIGIT_WIDTH     7
#define SIGN_BIT        0x40


/*-------------------------------------------------------------
        Encode val as a leb128. This encodes it as an unsigned 
        number.
---------------------------------------------------------------*/
/* return DW_DLV_ERROR or DW_DLV_OK.
** space to write leb number is provided by caller, with caller
** passing length.
** number of bytes used returned thru nbytes arg
*/
int
_dwarf_pro_encode_leb128_nm(Dwarf_Unsigned val, int *nbytes,
                            char *space, int splen)
{
    char *a;
    char *end = space + splen;

    a = space;
    do {
        unsigned char uc;

        if (a >= end) {
            return DW_DLV_ERROR;
        }
        uc = val & DATA_MASK;
        val >>= DIGIT_WIDTH;
        if (val != 0) {
            uc |= MORE_BYTES;
        }
        *a = uc;
        a++;
    } while (val);
    *nbytes = a - space;
    return DW_DLV_OK;
}

/* return DW_DLV_ERROR or DW_DLV_OK.
** space to write leb number is provided by caller, with caller
** passing length.
** number of bytes used returned thru nbytes arg
** encodes a signed number.
*/
int
_dwarf_pro_encode_signed_leb128_nm(Dwarf_Signed value, int *nbytes,
                                   char *space, int splen)
{
    char *str;
    Dwarf_Signed sign = -(value < 0);
    int more = 1;
    char *end = space + splen;

    str = space;

    do {
        unsigned char byte = value & DATA_MASK;

        value >>= DIGIT_WIDTH;

        if (str >= end) {
            return DW_DLV_ERROR;
        }
        /* 
         * Remaining chunks would just contain the sign bit, and this chunk
         * has already captured at least one sign bit.
         */
        if (value == sign && ((byte & SIGN_BIT) == (sign & SIGN_BIT))) {
            more = 0;
        } else {
            byte |= MORE_BYTES;
        }
        *str = byte;
        str++;
    } while (more);
    *nbytes = str - space;
    return DW_DLV_OK;
}
