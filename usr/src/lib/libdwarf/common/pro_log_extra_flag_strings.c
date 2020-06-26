/*  Copyright (c) 2019-2019, David Anderson
    All rights reserved.

    Redistribution and use in source and binary forms, with
    or without modification, are permitted provided that the
    following conditions are met:

    Redistributions of source code must retain the above
    copyright notice, this list of conditions and the following
    disclaimer.

    Redistributions in binary form must reproduce the above
    copyright notice, this list of conditions and the following
    disclaimer in the documentation and/or other materials
    provided with the distribution.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
    CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
    OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
    CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
    SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
    NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
    LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
    HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
    OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
    EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
#include "dwarfstring.h"




/*  in the producer_init extras string.
    Handles hex and decimal. Not octal.
    Used a very small number of times, so performance
    not an issue. */

/*  err will be used...shortly */
static int
translatetosigned(char *s,Dwarf_Signed *v, UNUSEDARG int *err)
{
    unsigned char *cp = (unsigned char *)s;
    unsigned char *digits = (unsigned char *)s;
    int signmult = 1;
    Dwarf_Signed l = 0;

    if (*cp == '0' &&
        (*(cp+1) == 'x'|| (*(cp+1) == 'X'))) {
        digits += 2;
        cp = digits;
        for( ; *cp; cp++) {
            l = l << 4;
            switch (*cp) {
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
                l += (*cp - '0');
                break;
            case 'a':
            case 'A':
                l += 10;
                break;
            case 'b':
            case 'B':
                l += 11;
                break;
            case 'c':
            case 'C':
                l += 12;
                break;
            case 'd':
            case 'D':
                l += 13;
                break;
            case 'e':
            case 'E':
                l += 14;
                break;
            case 'f':
            case 'F':
                l += 15;
                break;
            default:
#ifdef TESTING
                printf("ERROR in hex string \"%s\" "
                    "bad character 0x%x, line %d %s\n",
                    s,*cp,__LINE__,__FILE__);
#endif
                *err = DW_DLE_HEX_STRING_ERROR;
                return DW_DLV_ERROR;
            }
        }
        *v = l;
        return DW_DLV_OK;
    } else if (*cp == '-') {
        signmult = -1;
        digits ++;
    }

    cp = digits;
    for( ; *cp; cp++) {
        l = l * 10;
        switch (*cp) {
        case '9':
        case '8':
        case '7':
        case '6':
        case '5':
        case '4':
        case '3':
        case '2':
        case '1':
        case '0':
            l +=  (*cp - '0');
            break;
        default:
#ifdef TESTING
            printf("ERROR in decimal string \"%s\", "
                "bad character 0x%x, line %d %s\n",
                s,*cp,__LINE__,__FILE__);
#endif
            *err = DW_DLE_DECIMAL_STRING_ERROR;
            return DW_DLV_ERROR;
        }
    }
    *v = signmult * l;
    return DW_DLV_OK;
}

static int
update_named_field(Dwarf_P_Debug dbg, dwarfstring *cmsname,dwarfstring *cmsvalue,
    int *err)
{
    char *name = dwarfstring_string(cmsname);
    char *value = dwarfstring_string(cmsvalue);
    Dwarf_Signed v = 0;
    int res;

    res = translatetosigned(value,&v,err);
    if (res != DW_DLV_OK) {
        return res;
    }
    if ( dwarfstring_strlen(cmsvalue) == 0) {
        return DW_DLV_NO_ENTRY;
    }

    /*  The value in the string is a number,
        but always quite a small number. */
    if (!strcmp(name,"default_is_stmt")) {
        dbg->de_line_inits.pi_default_is_stmt = (unsigned)v;
    } else if (!strcmp(name,"minimum_instruction_length")) {
        dbg->de_line_inits.pi_minimum_instruction_length = (unsigned)v;
    } else if (!strcmp(name,"maximum_operations_per_instruction")) {
        dbg->de_line_inits.pi_maximum_operations_per_instruction = (unsigned)v;
    } else if (!strcmp(name,"opcode_base")) {
        dbg->de_line_inits.pi_opcode_base = (unsigned)v;
    } else if (!strcmp(name,"line_base")) {
        dbg->de_line_inits.pi_line_base = (int)v;
    } else if (!strcmp(name,"line_range")) {
        dbg->de_line_inits.pi_line_range = (int)v;
    } else if (!strcmp(name,"linetable_version")) {
        dbg->de_line_inits.pi_linetable_version = (unsigned)v;
        dbg->de_output_version = (unsigned)v;
    } else if (!strcmp(name,"segment_selector_size")) {
        dbg->de_line_inits.pi_segment_selector_size = (unsigned)v;
    } else if (!strcmp(name,"segment_size")) {
        dbg->de_line_inits.pi_segment_size = (unsigned)v;
    } else if (!strcmp(name,"address_size")) {
        dbg->de_line_inits.pi_address_size = (unsigned)v;
        dbg->de_pointer_size = (unsigned)v;
    } else {
#ifdef TESTING
        printf("ERROR  due to unknown string \"%s\", line %d %s\n",
            name,__LINE__,__FILE__);
#endif
        *err = DW_DLE_PRO_INIT_EXTRAS_UNKNOWN;
        return DW_DLV_ERROR;
    }
    return DW_DLV_OK;
}
static int
update_named_value(Dwarf_P_Debug dbg, dwarfstring*cms,
    int *err)
{
    char * str = dwarfstring_string(cms);
    char *cp = str;
    char * value_start = 0;
    dwarfstring cmsname;
    dwarfstring cmsvalue;
    unsigned slen = 0;
    int res = 0;

    dwarfstring_constructor(&cmsname);
    dwarfstring_constructor(&cmsvalue);
    for ( ; *cp && *cp != '=' && *cp != ' '; cp++) { }
    if (! *cp) {
        /* Ignore this, it's empty or has no =value clause */
        dwarfstring_destructor(&cmsname);
        dwarfstring_destructor(&cmsvalue);
        /* FIXME *err */
        return DW_DLV_NO_ENTRY;
    }
    if (*cp == ' ') {
        /* Trailing spaces, no = is an input bug. */
        dwarfstring_destructor(&cmsname);
        dwarfstring_destructor(&cmsvalue);
#ifdef TESTING
        printf("ERROR due to  trailing spaces before = in \"%s\", line %d %s\n",
            cp,__LINE__,__FILE__);
#endif
        *err = DW_DLE_PRO_INIT_EXTRAS_ERR;
        return DW_DLV_ERROR;
    }
    slen = cp - str;
    dwarfstring_append_length(&cmsname,str,slen);
    cp++;
    value_start = cp;
    for ( ; *cp && *cp != ' '; cp++) { }
    slen = cp - value_start;
    if (slen) {
        dwarfstring_append_length(&cmsvalue,value_start,slen);
    } else {
        dwarfstring_destructor(&cmsname);
        dwarfstring_destructor(&cmsvalue);
        return DW_DLV_NO_ENTRY;
    }
    res = update_named_field(dbg,&cmsname,&cmsvalue,err);
    dwarfstring_destructor(&cmsname);
    dwarfstring_destructor(&cmsvalue);
    return res;
}

static int
find_next_comma(const char *base,const char **nextcomma)
{
    const char *cp = base;
    for( ; *cp ; ++cp) {
        if (*cp == ',') {
            *nextcomma = cp;
            return DW_DLV_OK;
        }
    }
    /*  Encountered end of string, should not happen as
        we ensured a last string. */
    *nextcomma = cp;
    return DW_DLV_OK;
}

/*  Publicly visible in in libdwarf to enable easy testing
    of the code here. */
int
_dwarf_log_extra_flagstrings(Dwarf_P_Debug dbg,
  const char *extra,
  int *err)
{
    int res = 0;
    const char *nextcharloc = 0;
    const char *nextcomma = 0;
    dwarfstring cms;
    dwarfstring input;

    if (!extra || !*extra) {
        /* Nothing to do. */
        return DW_DLV_NO_ENTRY;
    }

    dwarfstring_constructor(&cms);
    dwarfstring_constructor(&input);
    dwarfstring_append(&input,(char *)extra);
    /*  Adding a final , simplifies logic here. */
    dwarfstring_append(&input,(char *)",");
    nextcharloc = dwarfstring_string(&input);
    while (1) {
        dwarfstring_reset(&cms);
        find_next_comma(nextcharloc,&nextcomma);
        {
            unsigned len = nextcomma - nextcharloc;
            if (len > 0) {
                dwarfstring_append_length(&cms,(char *)nextcharloc,
                    len);
                res = update_named_value(dbg,&cms,err);
                if (res == DW_DLV_ERROR) {
                    dwarfstring_destructor(&cms);
                    dwarfstring_destructor(&input);
                    return res;
                }
            }  else {/* else empty, */
            }
            if (!(nextcomma[1])) {
                dwarfstring_destructor(&cms);
                dwarfstring_destructor(&input);
                return DW_DLV_OK;
            }
            nextcharloc = nextcomma+1;
        }
    }
    dwarfstring_destructor(&input);
    dwarfstring_destructor(&cms);
    return DW_DLV_OK;
}

/* ===== end  Initialization using string=value,string2=valu2 (etc) */
