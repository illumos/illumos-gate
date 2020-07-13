/*
  Portions Copyright (C) 2017-2019 David Anderson. All Rights Reserved.

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

*/

/*  This provides access to the DWARF5 .debug_names section. */

#include "config.h"
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif /* HAVE_STDLIB_H */
#include "dwarf_incl.h"
#include "dwarf_alloc.h"
#include "dwarf_error.h"
#include "dwarf_util.h"
#include "dwarf_global.h"
#include "dwarf_dnames.h"
#include "dwarfstring.h"

#define FALSE 0
#define TRUE  1

/*  freedabs attempts to do some cleanup in the face
    of an error. */
static void
freedabs(struct Dwarf_D_Abbrev_s *dab)
{
    struct Dwarf_D_Abbrev_s *tmp = 0;
    for(; dab; dab = tmp) {
        tmp = dab->da_next;
        free(dab);
    }
}

/*  Encapsulates DECODE_LEB128_UWORD_CK
    so the caller can free resources
    in case of problems. */
static int
read_uword_ab(Dwarf_Small **lp,
    Dwarf_Unsigned *out_p,
    Dwarf_Debug dbg,
    Dwarf_Error *err,
    Dwarf_Small *lpend)

{
    Dwarf_Small *inptr = *lp;
    Dwarf_Unsigned out = 0;

    /* The macro updates inptr */
    DECODE_LEB128_UWORD_CK(inptr,
        out, dbg,err,lpend);
    *lp = inptr;
    *out_p = out;
    return DW_DLV_OK;
}


static int
fill_in_abbrevs_table(struct Dwarf_Dnames_index_header_s * dn,
    Dwarf_Error * error)
{
    Dwarf_Small *abdata = dn->din_abbreviations;
    Dwarf_Unsigned ablen =  dn->din_abbrev_table_size;
    Dwarf_Small *tabend = abdata+ablen;
    Dwarf_Small *abcur = 0;
    Dwarf_Unsigned code = 0;
    Dwarf_Unsigned tag = 0;
    int foundabend = FALSE;
    unsigned abcount = 0;
    struct Dwarf_D_Abbrev_s *firstdab = 0;
    struct Dwarf_D_Abbrev_s *lastdab = 0;
    struct Dwarf_D_Abbrev_s *curdab = 0;
    Dwarf_Debug dbg = dn->din_dbg;

    for (abcur = abdata; abcur < tabend; ) {
        Dwarf_Unsigned idx = 0;
        Dwarf_Unsigned form = 0;
        Dwarf_Small *inner = 0;
        unsigned idxcount = 0;
        int res = 0;

        res = read_uword_ab(&abcur,&code,dbg,error,tabend);
        if (res != DW_DLV_OK) {
            freedabs(firstdab);
            return res;
        }
        if (code == 0) {
            foundabend = TRUE;
            break;
        }

        res = read_uword_ab(&abcur,&tag,dbg,error,tabend);
        if (res != DW_DLV_OK) {
            freedabs(firstdab);
            return res;
        }
        inner = abcur;
        curdab = (struct Dwarf_D_Abbrev_s *)calloc(1,
            sizeof(struct Dwarf_D_Abbrev_s));
        if(!curdab) {
            freedabs(firstdab);
            firstdab = 0;
            _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
            return DW_DLV_ERROR;
        }
        curdab->da_tag = tag;
        curdab->da_abbrev_code = code;
        abcount++;
        for(;;) {
            res = read_uword_ab(&inner,&idx,dbg,error,tabend);
            if (res != DW_DLV_OK) {
                free(curdab);
                freedabs(firstdab);
                firstdab = 0;
                return res;
            }
            res = read_uword_ab(&inner,&form,dbg,error,tabend);
            if (res != DW_DLV_OK) {
                free(curdab);
                freedabs(firstdab);
                firstdab = 0;
                return res;
            }
            if (!idx && !form) {
                break;
            }
            if (idxcount >= ABB_PAIRS_MAX) {
                free(curdab);
                freedabs(firstdab);
                firstdab = 0;
                _dwarf_error(dbg, error,
                    DW_DLE_DEBUG_NAMES_ABBREV_OVERFLOW);
                return DW_DLV_ERROR;
            }
            curdab->da_pairs[idxcount].ap_index = idx;
            curdab->da_pairs[idxcount].ap_form = form;
            idxcount++;
        }
        curdab->da_pairs_count = idxcount;
        abcur = inner +1;
        if (!firstdab) {
            firstdab = curdab;
            lastdab  = curdab;
        } else {
            /* Add new on the end, last */
            lastdab->da_next = curdab;
        }
    }
    if (!foundabend) {
        freedabs(firstdab);
        _dwarf_error(dbg, error,
            DW_DLE_DEBUG_NAMES_ABBREV_CORRUPTION);
        return DW_DLV_OK;
    }
    {
        unsigned ct = 0;
        struct Dwarf_D_Abbrev_s *tmpa = 0;

        dn->din_abbrev_list = (struct Dwarf_D_Abbrev_s *)calloc(
            abcount,sizeof(struct Dwarf_D_Abbrev_s));
        if(!dn->din_abbrev_list) {
            freedabs(firstdab);
            _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
            return DW_DLV_ERROR;
        }
        dn->din_abbrev_list_count = abcount;
        tmpa = firstdab;
        for(ct = 0; tmpa && ct < abcount; ++ct) {
            struct Dwarf_D_Abbrev_s *tmpb =tmpa->da_next;
            /*  da_next no longer means anything */
            dn->din_abbrev_list[ct] = *tmpa;
            dn->din_abbrev_list[ct].da_next = 0;
            tmpa = tmpb;
        }
        freedabs(firstdab);
        tmpa = 0;
        firstdab = 0;
        lastdab = 0;
        /*  Now the list has turned into an array. We can ignore
            the list aspect. */
    }
    return DW_DLV_OK;
}

static int
get_inhdr_cur(Dwarf_Dnames_Head dn,
    Dwarf_Unsigned index_number,
    struct Dwarf_Dnames_index_header_s **cur,
    Dwarf_Error *error)
{
    Dwarf_Debug dbg = 0;

    if (!dn) {
        _dwarf_error(NULL, error,DW_DLE_DEBUG_NAMES_NULL_POINTER);
        return DW_DLV_ERROR;
    }
    dbg = dn->dn_dbg;
    if (index_number >= dn->dn_inhdr_count) {
        _dwarf_error(dbg, error, DW_DLE_DEBUG_NAMES_BAD_INDEX_ARG);
        return DW_DLV_ERROR;
    }
    *cur = dn->dn_inhdr_first + index_number;
    return DW_DLV_OK;
}


static int
read_uword_val(Dwarf_Debug dbg,
    Dwarf_Small **ptr_in,
    Dwarf_Small *endptr,
    int   errcode,
    Dwarf_Unsigned *val_out,
    Dwarf_Unsigned area_length,
    Dwarf_Error *error)
{
    Dwarf_Unsigned val = 0;
    Dwarf_Small *ptr = *ptr_in;

    READ_UNALIGNED_CK(dbg, val, Dwarf_Unsigned,
        ptr, DWARF_32BIT_SIZE,
        error,endptr);
    ptr += DWARF_32BIT_SIZE;
    if (ptr >= endptr) {
        _dwarf_error(dbg, error,errcode);
        return DW_DLV_ERROR;
    }
    /*  Some of the fields are not length fields, but
        if non-zero the size will be longer than
        the value, so we do the following
        overall sanity check to avoid overflows. */
    if (val > area_length) {
        _dwarf_error(dbg, error,errcode);
        return DW_DLV_ERROR;
    }
    *val_out = val;
    *ptr_in = ptr;
    return DW_DLV_OK;
}

/*  We do not alter the dn data here. */
static int
read_a_name_index(Dwarf_Dnames_Head dn,
    Dwarf_Unsigned section_offset,
    Dwarf_Small **curptr_in,
    Dwarf_Small *end_section,
    Dwarf_Unsigned remaining_section_size,
    struct Dwarf_Dnames_index_header_s ** index_header_out,
    Dwarf_Error *error)
{
    Dwarf_Unsigned area_length = 0;
    int local_length_size;
    int local_extension_size = 0;
    Dwarf_Small *past_length = 0;
    Dwarf_Small *end_dnames = 0;
    Dwarf_Half version = 0;
    Dwarf_Half padding = 0;
    Dwarf_Unsigned comp_unit_count = 0;
    Dwarf_Unsigned local_type_unit_count = 0;
    Dwarf_Unsigned foreign_type_unit_count = 0;
    Dwarf_Unsigned bucket_count = 0;
    Dwarf_Unsigned name_count = 0;
    Dwarf_Unsigned abbrev_table_size = 0; /* bytes */
    Dwarf_Unsigned augmentation_string_size = 0; /* bytes */
    int res = 0;
    const char *str_utf8 = 0;
    Dwarf_Small *curptr = *curptr_in;
    struct Dwarf_Dnames_index_header_s *di_header = 0;
    Dwarf_Debug dbg = dn->dn_dbg;

    READ_AREA_LENGTH_CK(dbg, area_length, Dwarf_Unsigned,
        curptr, local_length_size,
        local_extension_size,error,
        remaining_section_size,end_section);

    /* curptr now points past the length field */
    past_length = curptr;

    /* Two stage length test so overflow is caught. */
    if (area_length > remaining_section_size) {
        _dwarf_error(dbg, error,DW_DLE_DEBUG_NAMES_HEADER_ERROR);
        return DW_DLV_ERROR;
    }
    if ((area_length + local_length_size + local_extension_size) >
        remaining_section_size) {
        _dwarf_error(dbg, error,DW_DLE_DEBUG_NAMES_HEADER_ERROR);
        return DW_DLV_ERROR;
    }
    end_dnames = curptr + area_length;

    READ_UNALIGNED_CK(dbg, version, Dwarf_Half,
        curptr, DWARF_HALF_SIZE,
        error,end_dnames);
    curptr += DWARF_HALF_SIZE;
    if (curptr >= end_dnames) {
        _dwarf_error(dbg, error,DW_DLE_DEBUG_NAMES_HEADER_ERROR);
        return DW_DLV_ERROR;
    }
    if (version != DWARF_DNAMES_VERSION5) {
        _dwarf_error(dbg, error, DW_DLE_VERSION_STAMP_ERROR);
        return (DW_DLV_ERROR);
    }
    READ_UNALIGNED_CK(dbg, padding, Dwarf_Half,
        curptr, DWARF_HALF_SIZE,
        error,end_dnames);
    curptr += DWARF_HALF_SIZE;
    if (curptr >= end_dnames) {
        _dwarf_error(dbg, error,DW_DLE_DEBUG_NAMES_HEADER_ERROR);
        return DW_DLV_ERROR;
    }
    if (padding) {
        _dwarf_error(dbg, error,DW_DLE_DEBUG_NAMES_HEADER_ERROR);
        return (DW_DLV_ERROR);
    }
    res = read_uword_val(dbg, &curptr,
        end_dnames, DW_DLE_DEBUG_NAMES_HEADER_ERROR,
        &comp_unit_count,area_length,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    res = read_uword_val(dbg, &curptr,
        end_dnames, DW_DLE_DEBUG_NAMES_HEADER_ERROR,
        &local_type_unit_count,area_length,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    res = read_uword_val(dbg, &curptr,
        end_dnames, DW_DLE_DEBUG_NAMES_HEADER_ERROR,
        &foreign_type_unit_count,area_length,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    res = read_uword_val(dbg, &curptr,
        end_dnames, DW_DLE_DEBUG_NAMES_HEADER_ERROR,
        &bucket_count,area_length,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    res = read_uword_val(dbg, &curptr,
        end_dnames, DW_DLE_DEBUG_NAMES_HEADER_ERROR,
        &name_count,area_length,error);
    if (res != DW_DLV_OK) {
        return res;
    }

    res = read_uword_val(dbg, &curptr,
        end_dnames, DW_DLE_DEBUG_NAMES_HEADER_ERROR,
        &abbrev_table_size,area_length,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    res = read_uword_val(dbg, &curptr,
        end_dnames, DW_DLE_DEBUG_NAMES_HEADER_ERROR,
        &augmentation_string_size,area_length,error);
    if (res != DW_DLV_OK) {
        return res;
    }

    str_utf8 = (const char *) curptr;

    curptr+= augmentation_string_size;
    if (curptr >= end_dnames) {
        _dwarf_error(dbg, error,DW_DLE_DEBUG_NAMES_HEADER_ERROR);
        return DW_DLV_ERROR;
    }

    di_header = (struct Dwarf_Dnames_index_header_s *)
        calloc(1,sizeof(*di_header));
    if(!di_header) {
        _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return (DW_DLV_ERROR);
    }

    di_header->din_dbg = dbg;
    di_header->din_section_offset = section_offset;
    di_header->din_indextable_data = past_length;
    di_header->din_indextable_length = area_length;
    di_header->din_version = version;
    di_header->din_comp_unit_count = comp_unit_count;
    di_header->din_local_type_unit_count = local_type_unit_count ;
    di_header->din_foreign_type_unit_count = foreign_type_unit_count ;
    di_header->din_bucket_count = bucket_count ;
    di_header->din_name_count = name_count ;
    di_header->din_abbrev_table_size = abbrev_table_size;
    di_header->din_augmentation_string_size = augmentation_string_size;
    di_header->din_augmentation_string = calloc(1,
        augmentation_string_size +1);
    strncpy(di_header->din_augmentation_string,str_utf8,
        augmentation_string_size);

    {
        /* This deals with a zero length string too. */
        Dwarf_Unsigned len = augmentation_string_size;
        char *cp = 0;
        char *cpend = 0;
        Dwarf_Bool foundnull = FALSE;

        cp = di_header->din_augmentation_string;
        cpend = cp + len;
        for( ; cp<cpend; ++cp) {
            if (!*cp) {
                foundnull = TRUE;
                break;
            }
        }
        if (!foundnull) {
            /*  Force a NUL terminator in the extra byte
                we calloc-d. */
            cp[len] = 0;
        } else {
            /*  Ensure that there is no corruption in
                the padding. */
            for( ; cp < cpend; ++cp) {
                if(*cp) {
                    free(di_header);
                    _dwarf_error(dbg, error,
                        DW_DLE_DEBUG_NAMES_PAD_NON_ZERO);
                    return DW_DLV_ERROR;
                }
            }
        }
    }
    di_header->din_cu_list = curptr;
    curptr +=  dbg->de_length_size * comp_unit_count;
    if(curptr > end_dnames) {
        free(di_header->din_augmentation_string);
        free(di_header);
        _dwarf_error(dbg, error,DW_DLE_DEBUG_NAMES_HEADER_ERROR);
        return DW_DLV_ERROR;
    }
    di_header->din_local_tu_list = curptr;

    curptr +=  dbg->de_length_size * local_type_unit_count;
    if(curptr > end_dnames) {
        free(di_header->din_augmentation_string);
        free(di_header);
        _dwarf_error(dbg, error,DW_DLE_DEBUG_NAMES_HEADER_ERROR);
        return DW_DLV_ERROR;
    }
    di_header->din_foreign_tu_list = curptr;
    curptr +=  sizeof(Dwarf_Sig8) * foreign_type_unit_count;
    if(curptr > end_dnames) {
        free(di_header->din_augmentation_string);
        free(di_header);
        _dwarf_error(dbg, error,DW_DLE_DEBUG_NAMES_HEADER_ERROR);
        return DW_DLV_ERROR;
    }

    di_header->din_buckets = curptr;
    curptr +=  DWARF_32BIT_SIZE * bucket_count;
    if(curptr > end_dnames) {
        free(di_header->din_augmentation_string);
        free(di_header);
        _dwarf_error(dbg, error,DW_DLE_DEBUG_NAMES_HEADER_ERROR);
        return DW_DLV_ERROR;
    }

    di_header->din_hash_table = curptr;
    curptr +=  sizeof(Dwarf_Sig8) * name_count;
    if(curptr > end_dnames) {
        free(di_header->din_augmentation_string);
        free(di_header);
        _dwarf_error(dbg, error,DW_DLE_DEBUG_NAMES_HEADER_ERROR);
        return DW_DLV_ERROR;
    }

    di_header->din_string_offsets = curptr;
    curptr +=  DWARF_32BIT_SIZE * name_count;
    if(curptr > end_dnames) {
        free(di_header->din_augmentation_string);
        free(di_header);
        _dwarf_error(dbg, error,DW_DLE_DEBUG_NAMES_HEADER_ERROR);
        return DW_DLV_ERROR;
    }

    di_header->din_entry_offsets = curptr;
    curptr +=  DWARF_32BIT_SIZE * name_count;
    if(curptr > end_dnames) {
        free(di_header->din_augmentation_string);
        free(di_header);
        _dwarf_error(dbg, error,DW_DLE_DEBUG_NAMES_HEADER_ERROR);
        return DW_DLV_ERROR;
    }
    di_header->din_abbreviations = curptr;
    curptr +=   abbrev_table_size;
    if(curptr > end_dnames) {
        free(di_header->din_augmentation_string);
        free(di_header);
        _dwarf_error(dbg, error,DW_DLE_DEBUG_NAMES_HEADER_ERROR);
        return DW_DLV_ERROR;
    }

    di_header->din_entry_pool = curptr;
    di_header->din_offset_size = local_length_size;

    di_header->din_entry_pool_size = end_dnames - curptr;

    *curptr_in = curptr;
    *index_header_out = di_header;
    res = fill_in_abbrevs_table(di_header,error);
    if (res != DW_DLV_OK) {
        free(di_header->din_augmentation_string);
        free(di_header);
        return res;
    }
    return DW_DLV_OK;
}

#define FAKE_LAST_USED 0xffffffff

static void
free_inhdr_content(struct Dwarf_Dnames_index_header_s *f)
{
    free(f->din_augmentation_string);
    free(f->din_abbrev_list);
}
static void
free_inhdr_list(struct Dwarf_Dnames_index_header_s *f)
{
    struct Dwarf_Dnames_index_header_s *tmp = 0;

    for( ; f ; f = tmp) {
        tmp = f->din_next;
        free_inhdr_content(f);
        free(f);
    }
}

/*  There may be one debug index for an entire object file,
    for multiple CUs or there can be individual indexes
    for some CUs.
    see DWARF5 6.1.1.3 Per_CU versus Per-Module Indexes. */
int
dwarf_debugnames_header(Dwarf_Debug dbg,
    Dwarf_Dnames_Head * dn_out,
    Dwarf_Unsigned    * dn_count_out,
    Dwarf_Error *error)
{
    Dwarf_Unsigned remaining = 0;
    Dwarf_Dnames_Head dn_header = 0;
    Dwarf_Unsigned section_size;
    Dwarf_Small *start_section = 0;
    Dwarf_Small *end_section = 0;
    Dwarf_Small *curptr = 0;
    struct Dwarf_Dnames_index_header_s *inhdr_last = 0;
    struct Dwarf_Dnames_index_header_s *inhdr_first = 0;
    unsigned inhdr_count = 0;
    int res = 0;

    if(!dbg) {
        _dwarf_error(dbg, error,DW_DLE_DBG_NULL);
        return DW_DLV_ERROR;
    }

    res = _dwarf_load_section(dbg, &dbg->de_debug_names, error);
    if (res != DW_DLV_OK) {
        return res;
    }

    section_size = dbg->de_debug_names.dss_size;
    if(!section_size){
        return DW_DLV_NO_ENTRY;
    }
    start_section = dbg->de_debug_names.dss_data;
    curptr = start_section;
    end_section = start_section + section_size;
    remaining = section_size;
    dn_header =  (Dwarf_Dnames_Head)_dwarf_get_alloc(dbg,
        DW_DLA_DNAMES_HEAD, 1);
    if(!dn_header) {
        _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }
    dn_header->dn_section_data = start_section;
    dn_header->dn_section_size = section_size;
    dn_header->dn_section_end = start_section + section_size;
    dn_header->dn_dbg = dbg;
    for( ; curptr < end_section; ) {
        struct Dwarf_Dnames_index_header_s * index_header = 0;
        Dwarf_Small *curptr_start = curptr;
        Dwarf_Unsigned usedspace = 0;
        Dwarf_Unsigned section_offset = curptr - start_section;

        res = read_a_name_index(dn_header,
            section_offset,
            &curptr,
            end_section,
            remaining,
            &index_header,
            error);
        if (res == DW_DLV_ERROR) {
            free_inhdr_list(inhdr_first);
            dwarf_dealloc(dbg,dn_header,DW_DLA_DNAMES_HEAD);
            return res;
        }
        if (res == DW_DLV_NO_ENTRY) {
            /*  Impossible. A bug. Or possibly
                a bunch of zero pad? */
            free_inhdr_list(inhdr_first);
            dwarf_dealloc(dbg,dn_header,DW_DLA_DNAMES_HEAD);
            break;
        }
        /* Add the new one to the list. */
        if(!inhdr_first) {
            inhdr_count = 1;
            inhdr_first = index_header;
            inhdr_last = index_header;
        } else {
            struct Dwarf_Dnames_index_header_s *tmp = inhdr_last;
            inhdr_last = index_header;
            tmp->din_next = index_header;
            inhdr_count++;
        }
        usedspace = curptr - curptr_start;
        remaining -= - usedspace;
        if (remaining < 5) {
            /*  No more in here, just padding. Check for zero
                in padding. */
            if ((curptr +remaining) < end_section) {
                free_inhdr_list(inhdr_first);
                dwarf_dealloc(dbg,dn_header,DW_DLA_DNAMES_HEAD);
                _dwarf_error(dbg, error,DW_DLE_DEBUG_NAMES_OFF_END);
                return DW_DLV_ERROR;
            }
            for ( ; curptr < end_section; ++curptr) {
                if(*curptr) {
                    /*  One could argue this is a harmless error,
                        but for now assume it is real corruption. */
                    free_inhdr_list(inhdr_first);
                    dwarf_dealloc(dbg,dn_header,DW_DLA_DNAMES_HEAD);
                    _dwarf_error(dbg, error,DW_DLE_DEBUG_NAMES_PAD_NON_ZERO);
                    return DW_DLV_ERROR;
                }
            }
        }
    }
    {
        struct Dwarf_Dnames_index_header_s *cur = 0;
        int n = 0;

        dn_header->dn_inhdr_first =
            (struct Dwarf_Dnames_index_header_s *)
            calloc(inhdr_count,sizeof(struct Dwarf_Dnames_index_header_s));
        for(n = 0,cur = inhdr_first; cur; ++n ) {
            /*  We are copying these structs so do not
                free them at this time. */
            struct Dwarf_Dnames_index_header_s *tmp = cur->din_next;
            dn_header->dn_inhdr_first[n] = *cur;
            cur = tmp;
        }
    }
    *dn_out = dn_header;
    *dn_count_out = inhdr_count;
    return DW_DLV_OK;
}


int dwarf_debugnames_sizes(Dwarf_Dnames_Head dn,
    Dwarf_Unsigned   index_number,

    Dwarf_Unsigned * section_offset,
    Dwarf_Unsigned * version,     /* 5 */
    Dwarf_Unsigned * offset_size, /* 4 or 8 */

    /* The counts are entry counts, not bye sizes. */
    Dwarf_Unsigned * comp_unit_count,
    Dwarf_Unsigned * local_type_unit_count,
    Dwarf_Unsigned * foreign_type_unit_count,
    Dwarf_Unsigned * bucket_count,
    Dwarf_Unsigned * name_count,

    /* The following are counted in bytes */
    Dwarf_Unsigned * indextable_overall_length,
    Dwarf_Unsigned * abbrev_table_size,
    Dwarf_Unsigned * entry_pool_size,
    Dwarf_Unsigned * augmentation_string_size,

    Dwarf_Error *    error)
{
    struct Dwarf_Dnames_index_header_s *cur = 0;
    int res = 0;

    res = get_inhdr_cur(dn,index_number,&cur,error);
    if(res != DW_DLV_OK) {
        return res;
    }

    if (section_offset) {
        *section_offset = cur->din_section_offset;
    }
    if (version) {
        *version = cur->din_version;
    }
    if (offset_size) {
        *offset_size = cur->din_offset_size;
    }
    if (comp_unit_count) {
        *comp_unit_count = cur->din_comp_unit_count;
    }
    if (local_type_unit_count) {
        *local_type_unit_count = cur->din_local_type_unit_count;
    }
    if (foreign_type_unit_count) {
        *foreign_type_unit_count = cur->din_foreign_type_unit_count;
    }
    if (bucket_count) {
        *bucket_count = cur->din_bucket_count;
    }
    if (name_count) {
        *name_count = cur->din_name_count;
    }
    if (abbrev_table_size) {
        *abbrev_table_size = cur->din_abbrev_table_size;
    }
    if (entry_pool_size) {
        *entry_pool_size = cur->din_entry_pool_size;
    }
    if (augmentation_string_size) {
        *augmentation_string_size = cur->din_augmentation_string_size;
    }
    if (indextable_overall_length) {
        *indextable_overall_length =  cur->din_indextable_length;
    }
    return DW_DLV_OK;
}

int
dwarf_debugnames_cu_entry(Dwarf_Dnames_Head dn,
    Dwarf_Unsigned      index_number,
    Dwarf_Unsigned      offset_number,
    Dwarf_Unsigned    * offset_count,
    Dwarf_Unsigned    * offset,
    Dwarf_Error *       error)
{
    struct Dwarf_Dnames_index_header_s *cur = 0;
    Dwarf_Debug dbg = 0;
    int res;

    res = get_inhdr_cur(dn,index_number,&cur,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    dbg = dn->dn_dbg;

    if (offset_number >= cur->din_comp_unit_count) {
        if (offset_count) {
            *offset_count = cur->din_comp_unit_count;
        }
        return DW_DLV_NO_ENTRY;
    }


    if (offset) {
        Dwarf_Unsigned offsetval = 0;
        Dwarf_Small *ptr = cur->din_cu_list +
            offset_number *cur->din_offset_size;
        Dwarf_Small *endptr = cur->din_local_tu_list;

        READ_UNALIGNED_CK(dbg, offsetval, Dwarf_Unsigned,
            ptr, cur->din_offset_size,
            error,endptr);
        *offset = offsetval;
    }
    if (offset_count) {
        *offset_count = cur->din_comp_unit_count;
    }
    return DW_DLV_OK;
}

int
dwarf_debugnames_local_tu_entry(Dwarf_Dnames_Head dn,
    Dwarf_Unsigned      index_number,
    Dwarf_Unsigned      offset_number,
    Dwarf_Unsigned    * offset_count,
    Dwarf_Unsigned    * offset,
    Dwarf_Error *       error)
{
    struct Dwarf_Dnames_index_header_s *cur = 0;
    Dwarf_Debug dbg = 0;
    int res;

    res = get_inhdr_cur(dn,index_number,&cur,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    dbg = dn->dn_dbg;

    if (offset_number >= cur->din_local_type_unit_count) {
        if (offset_count) {
            *offset_count = cur->din_local_type_unit_count;
        }
        return DW_DLV_NO_ENTRY;
    }


    if (offset) {
        Dwarf_Unsigned offsetval = 0;
        Dwarf_Small *ptr = cur->din_local_tu_list +
            offset_number *cur->din_offset_size;
        Dwarf_Small *endptr = cur->din_foreign_tu_list;

        READ_UNALIGNED_CK(dbg, offsetval, Dwarf_Unsigned,
            ptr, cur->din_offset_size,
            error,endptr);
        *offset = offsetval;
    }
    if (offset_count) {
        *offset_count = cur->din_local_type_unit_count;
    }
    return DW_DLV_OK;
}



/*  Here the sig_number ranges from
    local_type_unit_count to
    local_type_unit_count+foreign_type_unit_count-1
    because the foreign indices are a continuation
    of the local tu indices.
*/
int
dwarf_debugnames_foreign_tu_entry(Dwarf_Dnames_Head dn,
    Dwarf_Unsigned      index_number,
    Dwarf_Unsigned      sig_number,

    /* these index starting at local_type_unit_count */
    Dwarf_Unsigned    * sig_minimum,
    Dwarf_Unsigned    * sig_count,
    Dwarf_Sig8 *        signature,
    Dwarf_Error *       error)
{
    struct Dwarf_Dnames_index_header_s *cur = 0;
    Dwarf_Debug dbg = 0;
    int res;
    unsigned legal_low = 0;
    unsigned legal_high = 0;

    res = get_inhdr_cur(dn,index_number,&cur,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    dbg = dn->dn_dbg;
    legal_low = cur->din_local_type_unit_count;
    legal_high = legal_low + cur->din_foreign_type_unit_count;
    if (sig_number < legal_low) {
        _dwarf_error(dbg, error, DW_DLE_DEBUG_NAMES_BAD_INDEX_ARG);
        return DW_DLV_ERROR;
    }
    if (sig_number >= legal_high) {
        if (sig_minimum) {
            *sig_minimum = legal_low;
        }
        if (sig_count) {
            *sig_count = cur->din_foreign_type_unit_count;
        }
        return DW_DLV_NO_ENTRY;
    }

    if (signature) {
        Dwarf_Small *ptr = cur->din_foreign_tu_list +
            sig_number *cur->din_offset_size;
        Dwarf_Small *endptr = cur->din_hash_table;
        if((ptr +sizeof(Dwarf_Sig8)) > endptr) {
            _dwarf_error(dbg, error, DW_DLE_DEBUG_NAMES_BAD_INDEX_ARG);
            return DW_DLV_ERROR;
        }
        memcpy(signature,ptr,sizeof(Dwarf_Sig8));
    }
    if (sig_minimum) {
        *sig_minimum = legal_low;
    }
    if (sig_count) {
        *sig_count = cur->din_foreign_type_unit_count;
    }
    return DW_DLV_OK;
}

/*  The hash table is composed of the buckets table
    and the hashes table.
    If there is no buckets table (bucket_count == 0)
    the hashes part still exists. */
int dwarf_debugnames_bucket(Dwarf_Dnames_Head dn,
    Dwarf_Unsigned      index_number,
    Dwarf_Unsigned      bucket_number,
    Dwarf_Unsigned    * bucket_count,
    Dwarf_Unsigned    * index_of_name_entry,
    Dwarf_Error *       error)
{
    struct Dwarf_Dnames_index_header_s *cur = 0;
    Dwarf_Debug dbg = 0;
    int res;

    res = get_inhdr_cur(dn,index_number,&cur,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    dbg = dn->dn_dbg;

    if (bucket_number >= cur->din_bucket_count) {
        if (bucket_count) {
            *bucket_count = cur->din_bucket_count;
        }
        return DW_DLV_NO_ENTRY;
    }

    if (index_of_name_entry) {
        Dwarf_Unsigned offsetval = 0;
        Dwarf_Small *ptr = cur->din_buckets +
            bucket_number * DWARF_32BIT_SIZE;
        Dwarf_Small *endptr = cur->din_hash_table;

        READ_UNALIGNED_CK(dbg, offsetval, Dwarf_Unsigned,
            ptr, DWARF_32BIT_SIZE,
            error,endptr);
        *index_of_name_entry = offsetval;
    }
    if (bucket_count) {
        *bucket_count = cur->din_bucket_count;
    }
    return DW_DLV_OK;
}

/*  Access to the .debug_names name table. */
int
dwarf_debugnames_name(Dwarf_Dnames_Head dn,
    Dwarf_Unsigned      index_number,
    Dwarf_Unsigned      name_entry,
    Dwarf_Unsigned    * names_count,
    Dwarf_Sig8        * signature,
    Dwarf_Unsigned    * offset_to_debug_str,
    Dwarf_Unsigned    * offset_in_entrypool,
    Dwarf_Error *       error)

{
    struct Dwarf_Dnames_index_header_s *cur = 0;
    Dwarf_Debug dbg = 0;
    int res;

    res = get_inhdr_cur(dn,index_number,&cur,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    dbg = dn->dn_dbg;

    if (name_entry >= cur->din_name_count) {
        if (names_count) {
            *names_count = cur->din_bucket_count;
        }
        return DW_DLV_NO_ENTRY;
    }

    if (signature) {
        Dwarf_Small *ptr = cur->din_hash_table +
            name_entry *sizeof(Dwarf_Sig8);
        Dwarf_Small *endptr = cur->din_string_offsets;
        if ((ptr + sizeof(Dwarf_Sig8)) > endptr) {
            _dwarf_error(dbg, error, DW_DLE_DEBUG_NAMES_BAD_INDEX_ARG);
            return DW_DLV_ERROR;
        }
        memcpy(signature,ptr,sizeof(Dwarf_Sig8));
    }

    if (offset_to_debug_str) {
        Dwarf_Unsigned offsetval = 0;
        Dwarf_Small *ptr = cur->din_string_offsets +
            name_entry * DWARF_32BIT_SIZE;
        Dwarf_Small *endptr = cur->din_abbreviations;

        READ_UNALIGNED_CK(dbg, offsetval, Dwarf_Unsigned,
            ptr, DWARF_32BIT_SIZE,
            error,endptr);
        *offset_to_debug_str = offsetval;
    }
    if (offset_in_entrypool) {
        Dwarf_Unsigned offsetval = 0;
        Dwarf_Small *ptr = cur->din_entry_offsets +
            name_entry * DWARF_32BIT_SIZE;
        Dwarf_Small *endptr = cur->din_abbreviations;

        READ_UNALIGNED_CK(dbg, offsetval, Dwarf_Unsigned,
            ptr, DWARF_32BIT_SIZE,
            error,endptr);
        *offset_in_entrypool = offsetval;
    }

    if (names_count) {
        *names_count = cur->din_name_count;
    }
    return DW_DLV_OK;
}






/*  If abbrev_code returned is zero there is no tag returned
    and we are at the end of the entry pool set for this name
    entry.
        abbrev code, tag
        nameindexattr,form
        ...
        0,0
        ... repeat like the above
        0
*/

/*  This provides a way to print the abbrev table by
    indexing from 0.  */
int
dwarf_debugnames_abbrev_by_index(Dwarf_Dnames_Head dn,
    Dwarf_Unsigned   index_number,
    Dwarf_Unsigned   abbrev_entry,
    Dwarf_Unsigned * abbrev_code,
    Dwarf_Unsigned * tag,

    /*  The number of valid abbrev_entry values: 0 to number_of_abbrev-1
        */
    Dwarf_Unsigned *  number_of_abbrev,

    /*  The number of attr/form pairs, not counting the trailing
        0,0 pair. */
    Dwarf_Unsigned *  number_of_attr_form_entries,
    Dwarf_Error *error)
{
    struct Dwarf_Dnames_index_header_s *cur = 0;
    struct Dwarf_D_Abbrev_s * abbrev = 0;
    int res = 0;

    res = get_inhdr_cur(dn,index_number,&cur,error);
    if (res != DW_DLV_OK) {
        return res;
    }

    if (abbrev_entry >= cur->din_abbrev_list_count) {
        if (number_of_abbrev) {
            *number_of_abbrev = cur->din_abbrev_list_count;
        }
        return DW_DLV_NO_ENTRY;
    }
    abbrev = cur->din_abbrev_list + abbrev_entry;
    if(abbrev_code) {
        *abbrev_code = abbrev->da_abbrev_code;
    }
    if(tag) {
        *tag = abbrev->da_tag;
    }
    if(number_of_abbrev) {
        *number_of_abbrev = cur->din_abbrev_list_count;
    }
    if(number_of_attr_form_entries) {
        *number_of_attr_form_entries = abbrev->da_pairs_count;
    }
    return DW_DLV_OK;
}

static int
_dwarf_internal_abbrev_by_code(struct Dwarf_Dnames_index_header_s *cur,
    Dwarf_Unsigned abbrev_code,
    Dwarf_Unsigned *  tag,
    Dwarf_Unsigned *  index_of_abbrev,
    Dwarf_Unsigned *  number_of_attr_form_entries)
{
    unsigned n = 0;
    struct Dwarf_D_Abbrev_s * abbrev = 0;

    abbrev = cur->din_abbrev_list;
    for(n = 0; n < cur->din_abbrev_list_count; ++n,++abbrev) {
        if (abbrev_code == abbrev->da_abbrev_code) {
            if (tag) {
                *tag = abbrev->da_tag;
            }
            if (index_of_abbrev) {
                *index_of_abbrev = n;
            }
            if (number_of_attr_form_entries) {
                *number_of_attr_form_entries = abbrev->da_pairs_count;
            }
            return DW_DLV_OK;
        }
    }
    /*  Something is wrong, not found! */
    return DW_DLV_NO_ENTRY;

}

/* Access the abbrev by abbrev code (instead of index). */
int
dwarf_debugnames_abbrev_by_code(Dwarf_Dnames_Head dn,
    Dwarf_Unsigned    index_number,
    Dwarf_Unsigned    abbrev_code,
    Dwarf_Unsigned *  tag,

    /*  The number of this code/tag as an array index. */
    Dwarf_Unsigned *  index_of_abbrev,

    /*  The number of attr/form pairs, not counting the trailing
        0,0 pair. */
    Dwarf_Unsigned * number_of_attr_form_entries,
    Dwarf_Error *    error)
{
    struct Dwarf_Dnames_index_header_s *cur = 0;
    int res;

    res = get_inhdr_cur(dn,index_number,&cur,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    res = _dwarf_internal_abbrev_by_code(cur,
        abbrev_code,
        tag, index_of_abbrev,
        number_of_attr_form_entries);
    return res;
}


int
dwarf_debugnames_abbrev_form_by_index(Dwarf_Dnames_Head dn,
    Dwarf_Unsigned    index_number,
    Dwarf_Unsigned    abbrev_entry_index,
    Dwarf_Unsigned    abbrev_form_index,
    Dwarf_Unsigned  * name_index_attr,
    Dwarf_Unsigned  * form,
    Dwarf_Unsigned *  number_of_attr_form_entries,
    Dwarf_Error    *  error)
{
    struct Dwarf_Dnames_index_header_s *cur = 0;
    struct Dwarf_D_Abbrev_s * abbrev = 0;
    struct abbrev_pair_s *ap = 0;
    int res;

    res = get_inhdr_cur(dn,index_number,&cur,error);
    if (res != DW_DLV_OK) {
        return res;
    }

    if (abbrev_entry_index >= cur->din_abbrev_list_count) {
        if (number_of_attr_form_entries) {
            *number_of_attr_form_entries = cur->din_bucket_count;
        }
        return DW_DLV_NO_ENTRY;
    }
    abbrev = cur->din_abbrev_list + abbrev_entry_index;
    if (abbrev_form_index >= abbrev->da_pairs_count) {
        return DW_DLV_NO_ENTRY;
    }
    ap = abbrev->da_pairs + abbrev_entry_index;
    if(name_index_attr) {
        *name_index_attr = ap->ap_index;
    }
    if(form) {
        *form = ap->ap_form;
    }
    if(number_of_attr_form_entries) {
        *number_of_attr_form_entries = abbrev->da_pairs_count;
    }
    return DW_DLV_OK;
}

/*  This, combined with dwarf_debugnames_entrypool_values(),
    lets one examine as much or as little of an entrypool
    as one wants to by alternately calling these two
    functions. */

int dwarf_debugnames_entrypool(Dwarf_Dnames_Head dn,
    Dwarf_Unsigned      index_number,
    Dwarf_Unsigned      offset_in_entrypool,
    Dwarf_Unsigned       *    abbrev_code,
    Dwarf_Unsigned       *    tag,
    Dwarf_Unsigned       *    value_count,
    Dwarf_Unsigned       *    index_of_abbrev,
    Dwarf_Unsigned *    offset_of_initial_value,
    Dwarf_Error *       error)
{
    struct Dwarf_Dnames_index_header_s *cur = 0;
    Dwarf_Debug dbg = 0;
    int res = 0;
    Dwarf_Small *entrypool = 0;
    Dwarf_Small *endentrypool = 0;
    Dwarf_Unsigned abcode = 0;
    Dwarf_Unsigned leblen = 0;

    res = get_inhdr_cur(dn,index_number,&cur,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    dbg = dn->dn_dbg;

    if (offset_in_entrypool >= cur->din_entry_pool_size) {
        _dwarf_error(NULL, error,DW_DLE_DEBUG_NAMES_ENTRYPOOL_OFFSET);
        return DW_DLV_ERROR;
    }
    endentrypool = cur->din_entry_pool +cur->din_entry_pool_size;
    entrypool = cur->din_entry_pool + offset_in_entrypool;

    DECODE_LEB128_UWORD_LEN_CK(entrypool,abcode,leblen,
        dbg,error,endentrypool);

    res = _dwarf_internal_abbrev_by_code(cur,
        abcode,
        tag, index_of_abbrev,
        value_count);
    if (res != DW_DLV_OK) {
        /* Never DW_DLV_ERROR (so far) */
        return res;
    }
    *offset_of_initial_value = offset_in_entrypool + leblen;
    *abbrev_code = abcode;
    return DW_DLV_OK;
}


/*  Caller, knowing array size needed, passes in arrays
    it allocates of for idx, form, offset-size-values,
    and signature values.  Caller must examine idx-number
    and form to decide, for each array element, whether
    the offset or the signature contains the value.
    So this returns all the values for the abbrev code.
    And points via offset_of_next to the next abbrev code.

    While an array of structs would be easier for the caller
    to allocate than parallel arrays, public structs have
    turned out to be difficult to work with as interfaces
    (as formats change over time).
    */
int dwarf_debugnames_entrypool_values(Dwarf_Dnames_Head dn,
    Dwarf_Unsigned      index_number,
    Dwarf_Unsigned      index_of_abbrev,
    Dwarf_Unsigned      offset_in_entrypool_of_values,
    Dwarf_Unsigned *    array_dw_idx_number,
    Dwarf_Unsigned *    array_form,
    Dwarf_Unsigned *    array_of_offsets,
    Dwarf_Sig8     *    array_of_signatures,

    /*  offset of the next entrypool entry. */
    Dwarf_Unsigned *    offset_of_next_entrypool,
    Dwarf_Error *       error)
{
    struct Dwarf_Dnames_index_header_s *cur = 0;
    struct Dwarf_D_Abbrev_s * abbrev = 0;
    Dwarf_Debug dbg = 0;
    unsigned n = 0;
    int res = 0;
    Dwarf_Unsigned abcount = 0;
    Dwarf_Unsigned pooloffset = offset_in_entrypool_of_values;
    Dwarf_Small * endpool = 0;
    Dwarf_Small * poolptr = 0;

    res = get_inhdr_cur(dn,index_number,&cur,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    dbg = dn->dn_dbg;
    endpool = cur->din_entry_pool + cur->din_entry_pool_size;

    if (index_of_abbrev >= cur->din_abbrev_list_count) {
        _dwarf_error(dbg,error,DW_DLE_DEBUG_NAMES_ABBREV_CORRUPTION);
        return DW_DLV_ERROR;
    }
    poolptr = cur->din_entry_pool + offset_in_entrypool_of_values;
    abbrev = cur->din_abbrev_list + index_of_abbrev;
    abcount = cur->din_abbrev_list_count;
    for(n = 0; n < abcount ; ++n) {
        struct abbrev_pair_s *abp = abbrev->da_pairs +n;
        unsigned idxtype = abp->ap_index;
        unsigned form = abp->ap_form;
        array_dw_idx_number[n] = idxtype;
        array_form[n] = form;

        if(form == DW_FORM_data8 && idxtype == DW_IDX_type_hash) {
            if ((poolptr + sizeof(Dwarf_Sig8)) > endpool){
                _dwarf_error(dbg,error,
                    DW_DLE_DEBUG_NAMES_ENTRYPOOL_OFFSET);
                return DW_DLV_ERROR;
            }
            memcpy(array_of_signatures+n,
                poolptr,sizeof(Dwarf_Sig8));
            poolptr += sizeof(Dwarf_Sig8);
            pooloffset += sizeof(Dwarf_Sig8);
            continue;
        } else if (_dwarf_allow_formudata(form)) {
            Dwarf_Unsigned val = 0;
            Dwarf_Unsigned bytesread = 0;
            res = _dwarf_formudata_internal(dbg,form,poolptr,
                endpool,&val,&bytesread,error);
            if(res != DW_DLV_OK) {
                return res;
            }
            poolptr += bytesread;
            pooloffset += bytesread;
            array_of_offsets[n] = val;
            continue;
        }
        /*  There is some mistake/omission in our code here or in
            the data. */
        {
        dwarfstring m;
        const char *name = "<unknown form>";

        dwarfstring_constructor(&m);
        dwarfstring_append_printf_u(&m,
            "DW_DLE_DEBUG_NAMES_UNHANDLED_FORM: Form 0x%x",
            form);
        dwarf_get_FORM_name(form,&name);
        dwarfstring_append_printf_s(&m,
            " %s is not currently supported in .debug_names ",
            (char *)name);
        _dwarf_error_string(dbg,error,
            DW_DLE_DEBUG_NAMES_UNHANDLED_FORM,
            dwarfstring_string(&m));
        dwarfstring_destructor(&m);
        }
        return DW_DLV_ERROR;
    }
    *offset_of_next_entrypool = pooloffset;
    return DW_DLV_OK;
}




/*  Frees any Dwarf_Dnames_Head_s data that is directly
    mallocd. */
void
_dwarf_debugnames_destructor(void *m)
{
    struct Dwarf_Dnames_Head_s *h = (struct Dwarf_Dnames_Head_s *)m;

    struct Dwarf_Dnames_index_header_s *cur = 0;
    unsigned n = 0;

    cur = h->dn_inhdr_first;
    for( ;n < h->dn_inhdr_count ; ++n,++cur) {
        free_inhdr_content(cur);
    }
    free(h->dn_inhdr_first);
    h->dn_inhdr_first = 0;
    h->dn_inhdr_count = 0;
}
