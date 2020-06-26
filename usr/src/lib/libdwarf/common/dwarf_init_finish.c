/*
  Copyright (C) 2000,2002,2003,2004,2005 Silicon Graphics, Inc. All Rights Reserved.
  Portions Copyright (C) 2008-2010 Arxan Technologies, Inc. All Rights Reserved.
  Portions Copyright (C) 2009-2019 David Anderson. All Rights Reserved.
  Portions Copyright (C) 2010-2012 SN Systems Ltd. All Rights Reserved.

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

#include "config.h"
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif /* HAVE_STDLIB_H */
#ifdef HAVE_MALLOC_H
/* Useful include for some Windows compilers. */
#include <malloc.h>
#endif /* HAVE_MALLOC_H */
#include "dwarf_incl.h"
#include "dwarf_alloc.h"
#include "dwarf_error.h"
#include "dwarf_util.h"
#include "memcpy_swap.h"
#include "dwarf_harmless.h"
#include "dwarfstring.h"

/* For consistency, use the HAVE_LIBELF_H symbol */
#ifdef HAVE_LIBELF_H
#include <libelf.h>
#else
#ifdef HAVE_LIBELF_LIBELF_H
#include <libelf/libelf.h>
#endif
#endif
#ifdef HAVE_ZLIB
#include "zlib.h"
#endif

#ifndef ELFCOMPRESS_ZLIB
#define ELFCOMPRESS_ZLIB 1
#endif

/*  If your mingw elf.h is missing SHT_RELA and you do not
    need SHT_RELA support
    this define should work for you.
    It is the elf value, hopefully it will
    not cause trouble. If does not work, try -1
    or something else
    and let us know what works.  */
#ifndef SHT_RELA
#define SHT_RELA 4
#endif
#ifndef SHT_REL
#define SHT_REL 9
# endif
/*  For COMDAT GROUPS. Guarantees we can compile. We hope. */
#ifndef SHT_GROUP
#define SHT_GROUP 17
#endif

#ifndef SHF_COMPRESSED
/*  This from ubuntu xenial. Is in top of trunk binutils
    as of February 2016. Elf Section Flag */
#define SHF_COMPRESSED (1 << 11)
#endif


#define DWARF_DBG_ERROR(dbg,errval,retval) \
    _dwarf_error(dbg, error, errval); return(retval);

#define FALSE 0
#define TRUE  1

/*  Global definition of the function pointer type, typedef
    in dwarf_opaque.h */
_dwarf_get_elf_flags_func_ptr_type _dwarf_get_elf_flags_func_ptr;

/* This static is copied to the dbg on dbg init
   so that the static need not be referenced at
   run time, preserving better locality of
   reference.
   Value is 0 means do the string check.
   Value non-zero means do not do the check.
*/
static Dwarf_Small _dwarf_assume_string_in_bounds;
static Dwarf_Small _dwarf_apply_relocs = 1;

/*  Call this after calling dwarf_init but before doing anything else.
    It applies to all objects, not just the current object.  */
int
dwarf_set_reloc_application(int apply)
{
    int oldval = _dwarf_apply_relocs;
    _dwarf_apply_relocs = apply;
    return oldval;
}

int
dwarf_set_stringcheck(int newval)
{
    int oldval = _dwarf_assume_string_in_bounds;

    _dwarf_assume_string_in_bounds = newval;
    return oldval;
}

static int
startswith(const char * input, char* ckfor)
{
    size_t cklen = strlen(ckfor);

    if (! strncmp(input,ckfor,cklen)) {
        return TRUE;
    }
    return FALSE;
}
#if 0
static int
endswith(const char * input, char* ckfor)
{
    size_t inlen = strlen(input);
    size_t endlen = strlen(ckfor);
    const char * endck = 0;

    if (endlen > inlen) {
        return FALSE;
    }
    endck = input+inlen - endlen;

    if (! strcmp(endck,ckfor) ) {
        return TRUE;
    }
    return FALSE;
}
#endif

/* Unifies the basic duplicate/empty testing and section
   data setting to one place. */
static int
get_basic_section_data(Dwarf_Debug dbg,
    struct Dwarf_Section_s *secdata,
    struct Dwarf_Obj_Access_Section_s *doas,
    Dwarf_Half section_index,
    unsigned group_number,
    Dwarf_Error* error,
    int duperr, int emptyerr )
{
    /*  There is an elf convention that section index 0  is reserved,
        and that section is always empty.
        Non-elf object formats must honor that by ensuring that
        (when they assign numbers to 'sections' or 'section-like-things')
        they never assign a real section section-number  0 to dss_index. */
    if (secdata->dss_index != 0) {
        DWARF_DBG_ERROR(dbg, duperr, DW_DLV_ERROR);
    }
    if (doas->size == 0) {
        /*  As of 2018 it seems impossible to detect
            (via dwarfdump) whether emptyerr has any
            practical effect, whether TRUE or FALSE.  */
        if (emptyerr == 0 ) {
            /*  Allow empty section. */
            return DW_DLV_OK;
        }
        /* Know no reason to allow section */
        DWARF_DBG_ERROR(dbg, emptyerr, DW_DLV_ERROR);
    }
    secdata->dss_index = section_index;
    secdata->dss_size = doas->size;
    secdata->dss_group_number = group_number;
    secdata->dss_addr = doas->addr;
    secdata->dss_link = doas->link;
    secdata->dss_entrysize = doas->entrysize;
    if (_dwarf_get_elf_flags_func_ptr) {
        /*  We do this so we do not need to update the public struct
            Dwarf_Obj_Access_Section_s and thereby cause
            binary and source incompatibility. */
        Dwarf_Unsigned flags = 0;
        Dwarf_Unsigned addralign = 0;
        int res = 0;
        int interr = 0;
        struct Dwarf_Obj_Access_Interface_s *o = 0;

        o = dbg->de_obj_file;
        res = _dwarf_get_elf_flags_func_ptr(
            o->object, section_index,
            &flags,&addralign,
            &interr);
        if (res == DW_DLV_ERROR) {
            /*  Should never get here. */
            DWARF_DBG_ERROR(dbg, interr, DW_DLV_ERROR);
        }
        if (res == DW_DLV_NO_ENTRY) {
            return res;
        }
        secdata->dss_flags = flags;
        secdata->dss_addralign = addralign;
        if (flags & SHF_COMPRESSED) {
            secdata->dss_shf_compressed = TRUE;
        }
        /*  We are not looking at section bytes so we
            do not know if the first 4 bytes are ZLIB */
    }
    return DW_DLV_OK;
}


static void
add_relx_data_to_secdata( struct Dwarf_Section_s *secdata,
    struct Dwarf_Obj_Access_Section_s *doas,
    Dwarf_Half section_index,int is_rela)
{
    secdata->dss_reloc_index = section_index;
    secdata->dss_reloc_size = doas->size;
    secdata->dss_reloc_entrysize = doas->entrysize;
    secdata->dss_reloc_addr = doas->addr;
    secdata->dss_reloc_symtab = doas->link;
    secdata->dss_reloc_link = doas->link;
    secdata->dss_is_rela = is_rela;
}



/*  Used to add the specific information for a debug related section
    Called on each section of interest by section name.
    DWARF_MAX_DEBUG_SECTIONS must be large enough to allow
    that all sections of interest fit in the table.
    returns DW_DLV_ERROR or DW_DLV_OK.
    */
static int
add_debug_section_info(Dwarf_Debug dbg,
    /* Name as seen in object file. */
    const char *name,
    const char *standard_section_name,
    unsigned obj_sec_num,
    struct Dwarf_Section_s *secdata,
    unsigned groupnum,
    /*  The have_dwarf flag is a somewhat imprecise
        way to determine if there is at least one 'meaningful'
        DWARF information section present in the object file.
        If not set on some section we claim (later) that there
        is no DWARF info present. see 'foundDwarf' in this file */
    int duperr,int emptyerr,int have_dwarf,
    int havezdebug,
    int *err)
{
    unsigned total_entries = dbg->de_debug_sections_total_entries;
    if (secdata->dss_is_in_use) {
        *err = duperr;
        return DW_DLV_ERROR;
    }
    if (total_entries < DWARF_MAX_DEBUG_SECTIONS) {
        struct Dwarf_dbg_sect_s *debug_section =
            &dbg->de_debug_sections[total_entries];
        secdata->dss_is_in_use = TRUE;
        debug_section->ds_name = name;
        debug_section->ds_number = obj_sec_num;
        debug_section->ds_secdata = secdata;
        debug_section->ds_groupnumber =  groupnum;
        secdata->dss_name = name; /* Actual name from object file. */
        secdata->dss_standard_name = standard_section_name;
        secdata->dss_number = obj_sec_num;
        secdata->dss_zdebug_requires_decompress = havezdebug;
        /* We don't yet know about SHF_COMPRESSED */
        debug_section->ds_duperr = duperr;
        debug_section->ds_emptyerr = emptyerr;
        debug_section->ds_have_dwarf = have_dwarf;
        debug_section->ds_have_zdebug = havezdebug;
        ++dbg->de_debug_sections_total_entries;
        return DW_DLV_OK;
    }
    /*  This represents a bug in libdwarf.
        Mis-setup-DWARF_MAX_DEBUG_SECTIONS.
        Or possibly a use of section groups that is
        not supported.  */
    *err = DW_DLE_TOO_MANY_DEBUG;
    return DW_DLV_ERROR;
}


#if 0
static void
dump_bytes(const char *msg,Dwarf_Small * start, long len)
{
    Dwarf_Small *end = start + len;
    Dwarf_Small *cur = start;

    printf("dump_bytes: %s ",msg);
    for (; cur < end; cur++) {
        printf("%02x",*cur);
    }
    printf("\n");
}

static int
all_sig8_bits_zero(Dwarf_Sig8 *val)
{
    unsigned u = 0;
    for(  ; u < sizeof(*val); ++u) {
        if (val->signature[u] != 0) {
            return FALSE;
        }
    }
    return TRUE;
}
#endif


/* Return DW_DLV_OK etc. */
static int
set_up_section(Dwarf_Debug dbg,
    /*  Section name from object format.
        Might start with .zdebug not .debug if compressed section. */
    const char *secname,
    /*  Standard section name, such as .debug_info */
    const char *sec_standard_name,
    /*  Section number from object format  */
    unsigned obj_sec_num,
    /*  The name associated with this secdata in libdwarf */
    const char *targname,
    /*  DW_GROUPNUMBER_ANY or BASE or DWO or some other group num */
    unsigned  groupnum_of_sec,
    struct Dwarf_Section_s *secdata,
    int duperr,int emptyerr,int have_dwarf,
    int *err)
{
    /*  Here accomodate the .debug or .zdebug version, (and of
        course non- .debug too, but those never zlib) .
        SECNAMEMAX should be a little bigger than any section
        name we care about as possibly compressed, which
        is to say bigger than any standard section name. */
#define SECNAMEMAX 30
    int secnamelen = strlen(secname);
    /* static const char *dprefix = ".debug_"; */
#define DPREFIXLEN 7
    static const char *zprefix = ".zdebug_";
#define ZPREFIXLEN 8
    int havezdebug = FALSE;
    int namesmatch = FALSE;

    /*  For example, if the secname is .zdebug_info
        we update the finaltargname to .debug_info
        to match with the particular (known, predefined)
        object section name.
        We add one character, so check
        to see if it will, in the end, fit.
        See the SET_UP_SECTION macro.  */

    if(secnamelen >= SECNAMEMAX) {
        /*  This is not the target section.
            our caller will keep looking. */
        return DW_DLV_NO_ENTRY;
    }
    if((secnamelen+1) < SECNAMEMAX &&
        !strncmp(secname,zprefix,ZPREFIXLEN) &&
        !strcmp(secname+ZPREFIXLEN,targname+DPREFIXLEN)) {
            /*  zprefix version matches the object section
                name so the section is compressed and is
                the section this targname applies to. */
            havezdebug = TRUE;
            namesmatch = TRUE;
    } else if (!strcmp(secname,targname)) {
        namesmatch = TRUE;
    }
#undef ZPREFIXLEN
#undef DPREFIXLEN
#undef SECNAMEMAX
    if(!namesmatch) {
        /*  This is not the target section.
            our caller will keep looking. */
            return DW_DLV_NO_ENTRY;
    }

    /* SETUP_SECTION. See also BUILDING_SECTIONS, BUILDING_MAP  */
    {
        /*  The section name is a match with targname, or
            the .zdebug version of targname. */
        int sectionerr = 0;

        sectionerr = add_debug_section_info(dbg,secname,
            sec_standard_name,
            obj_sec_num,
            secdata,
            groupnum_of_sec,
            duperr,emptyerr, have_dwarf,
            havezdebug,err);
        if (sectionerr != DW_DLV_OK) {
            /* *err is set already */
            return sectionerr;
        }
    }
    return DW_DLV_OK;
}

#define SET_UP_SECTION(mdbg,mname,mtarg,mgrp,minfo,me1,me2,mdw,mer) \
    {                                           \
    int lerr = 0;                               \
    lerr =  set_up_section(mdbg,                \
        mname,  /* actual section name */       \
        mtarg,    /* std section name */        \
        /* scn_number from macro use context */ \
        scn_number,mtarg,mgrp,                  \
        minfo,                                  \
        me1,me2,mdw,mer);                       \
    if (lerr != DW_DLV_NO_ENTRY) {              \
        return lerr;                            \
    }    /* else fall through. */               \
    }

/*  If running this long set of tests is slow
    enough to matter one could set up a local
    tsearch tree with all this content and search
    it instead of this set of sequential tests.
    Or use a switch(){} here with a search tree
    to to turn name into index for the switch(). */
static int
enter_section_in_de_debug_sections_array(Dwarf_Debug dbg,
    const char *scn_name,
    /* This is the number of the section in the object file. */
    unsigned scn_number,
    unsigned group_number,
    int *err)
{
    /*  Setup the table that contains the basic information about the
        sections that are DWARF related. The entries are very unlikely
        to change very often. */
    SET_UP_SECTION(dbg,scn_name,".debug_info",
        group_number,
        &dbg->de_debug_info,
        DW_DLE_DEBUG_INFO_DUPLICATE,DW_DLE_DEBUG_INFO_NULL,
        TRUE,err);
    SET_UP_SECTION(dbg,scn_name,".debug_info.dwo",
        DW_GROUPNUMBER_DWO,
        &dbg->de_debug_info,
        DW_DLE_DEBUG_INFO_DUPLICATE,DW_DLE_DEBUG_INFO_NULL,
        TRUE,err);
    SET_UP_SECTION(dbg,scn_name,".debug_types",
        group_number,
        &dbg->de_debug_types,
        DW_DLE_DEBUG_TYPES_DUPLICATE,DW_DLE_DEBUG_TYPES_NULL,
        TRUE,err);
    SET_UP_SECTION(dbg,scn_name,".debug_types.dwo",
        DW_GROUPNUMBER_DWO,
        &dbg->de_debug_types,
        DW_DLE_DEBUG_TYPES_DUPLICATE,DW_DLE_DEBUG_TYPES_NULL,
        TRUE,err);
    SET_UP_SECTION(dbg,scn_name,".debug_abbrev",
        group_number,
        &dbg->de_debug_abbrev, /*03*/
        DW_DLE_DEBUG_ABBREV_DUPLICATE,DW_DLE_DEBUG_ABBREV_NULL,
        TRUE,err);
    SET_UP_SECTION(dbg,scn_name,".debug_abbrev.dwo",
        DW_GROUPNUMBER_DWO,
        &dbg->de_debug_abbrev, /*03*/
        DW_DLE_DEBUG_ABBREV_DUPLICATE,DW_DLE_DEBUG_ABBREV_NULL,
        TRUE,err);
    SET_UP_SECTION(dbg,scn_name,".debug_aranges",
        group_number,
        &dbg->de_debug_aranges,
        DW_DLE_DEBUG_ARANGES_DUPLICATE,0,
        FALSE,err);
    SET_UP_SECTION(dbg,scn_name,".debug_line",
        group_number,
        &dbg->de_debug_line,
        DW_DLE_DEBUG_LINE_DUPLICATE,0,
        TRUE,err);
    /* DWARF5 */
    SET_UP_SECTION(dbg,scn_name,".debug_line_str",
        group_number,
        &dbg->de_debug_line_str,
        DW_DLE_DEBUG_LINE_DUPLICATE,0,
        FALSE,err);
    SET_UP_SECTION(dbg,scn_name,".debug_line.dwo",
        DW_GROUPNUMBER_DWO,
        &dbg->de_debug_line,
        DW_DLE_DEBUG_LINE_DUPLICATE,0,
        TRUE,err);
    SET_UP_SECTION(dbg,scn_name,".debug_frame",
        group_number,
        &dbg->de_debug_frame,
        DW_DLE_DEBUG_FRAME_DUPLICATE,0,
        TRUE,err);
    /* gnu egcs-1.1.2 data */
    SET_UP_SECTION(dbg,scn_name,".eh_frame",
        group_number,
        &dbg->de_debug_frame_eh_gnu,
        DW_DLE_DEBUG_FRAME_DUPLICATE,0,
        TRUE,err);
    SET_UP_SECTION(dbg,scn_name,".debug_loc",
        group_number,
        &dbg->de_debug_loc,
        DW_DLE_DEBUG_LOC_DUPLICATE,0,
        FALSE,err);
    SET_UP_SECTION(dbg,scn_name,".debug_loc.dwo",
        DW_GROUPNUMBER_DWO,
        &dbg->de_debug_loc,
        DW_DLE_DEBUG_LOC_DUPLICATE,0,
        FALSE,err);
    SET_UP_SECTION(dbg,scn_name,".debug_pubnames",
        group_number,
        &dbg->de_debug_pubnames,
        DW_DLE_DEBUG_PUBNAMES_DUPLICATE,0,
        FALSE,err);
    SET_UP_SECTION(dbg,scn_name,".debug_str",
        group_number,
        &dbg->de_debug_str,
        DW_DLE_DEBUG_STR_DUPLICATE,0,
        FALSE,err);
    SET_UP_SECTION(dbg,scn_name,".debug_str.dwo",
        DW_GROUPNUMBER_DWO,
        &dbg->de_debug_str,
        DW_DLE_DEBUG_STR_DUPLICATE,0,
        FALSE,err);
    /* Section new in DWARF3.  */
    SET_UP_SECTION(dbg,scn_name,".debug_pubtypes",
        group_number,
        &dbg->de_debug_pubtypes,
        /*13*/ DW_DLE_DEBUG_PUBTYPES_DUPLICATE,0,
        FALSE,err);
    /* DWARF5 */
    SET_UP_SECTION(dbg,scn_name,".debug_names",
        group_number,
        &dbg->de_debug_names,
        /*13*/ DW_DLE_DEBUG_NAMES_DUPLICATE,0,
        FALSE,err);
    /* DWARF5 */
    SET_UP_SECTION(dbg,scn_name,".debug_loclists",
        group_number,
        &dbg->de_debug_loclists,
        /*13*/ DW_DLE_DEBUG_LOClISTS_DUPLICATE,0,
        FALSE,err);
    /* DWARF5 */
    SET_UP_SECTION(dbg,scn_name,".debug_loclists.dwo",
        DW_GROUPNUMBER_DWO,
        &dbg->de_debug_loclists,
        /*13*/ DW_DLE_DEBUG_LOClISTS_DUPLICATE,0,
        FALSE,err);
    /* DWARF5 */
    SET_UP_SECTION(dbg,scn_name,".debug_rnglists",
        group_number,
        &dbg->de_debug_rnglists,
        /*13*/ DW_DLE_DEBUG_RNGLISTS_DUPLICATE,0,
        FALSE,err);
    /* DWARF5 */
    SET_UP_SECTION(dbg,scn_name,".debug_rnglists.dwo",
        DW_GROUPNUMBER_DWO,
        &dbg->de_debug_rnglists,
        /*13*/ DW_DLE_DEBUG_RNGLISTS_DUPLICATE,0,
        FALSE,err);
    /* DWARF5 */
    SET_UP_SECTION(dbg,scn_name,".debug_str_offsets",
        group_number,
        &dbg->de_debug_str_offsets,
        DW_DLE_DEBUG_STR_OFFSETS_DUPLICATE,0,
        FALSE,err);
    /* DWARF5 */
    SET_UP_SECTION(dbg,scn_name,".debug_str_offsets.dwo",
        DW_GROUPNUMBER_DWO,
        &dbg->de_debug_str_offsets,
        DW_DLE_DEBUG_STR_OFFSETS_DUPLICATE,0,
        FALSE,err);

    /* SGI IRIX-only. */
    SET_UP_SECTION(dbg,scn_name,".debug_funcnames",
        group_number,
        &dbg->de_debug_funcnames,
        /*11*/ DW_DLE_DEBUG_FUNCNAMES_DUPLICATE,0,
        FALSE,err);
    /*  SGI IRIX-only, created years before DWARF3. Content
        essentially identical to .debug_pubtypes.  */
    SET_UP_SECTION(dbg,scn_name,".debug_typenames",
        group_number,
        &dbg->de_debug_typenames,
        /*12*/ DW_DLE_DEBUG_TYPENAMES_DUPLICATE,0,
        FALSE,err);
    /* SGI IRIX-only.  */
    SET_UP_SECTION(dbg,scn_name,".debug_varnames",
        group_number,
        &dbg->de_debug_varnames,
        DW_DLE_DEBUG_VARNAMES_DUPLICATE,0,
        FALSE,err);
    /* SGI IRIX-only. */
    SET_UP_SECTION(dbg,scn_name,".debug_weaknames",
        group_number,
        &dbg->de_debug_weaknames,
        DW_DLE_DEBUG_WEAKNAMES_DUPLICATE,0,
        FALSE,err);

    SET_UP_SECTION(dbg,scn_name,".debug_macinfo",
        group_number,
        &dbg->de_debug_macinfo,
        DW_DLE_DEBUG_MACINFO_DUPLICATE,0,
        TRUE,err);
    /*  ".debug_macinfo.dwo" is not allowed.  */


    /* DWARF5 */
    SET_UP_SECTION(dbg,scn_name,".debug_macro",
        group_number,
        &dbg->de_debug_macro,
        DW_DLE_DEBUG_MACRO_DUPLICATE,0,
        TRUE,err);
    /* DWARF5 */
    SET_UP_SECTION(dbg,scn_name,".debug_macro.dwo",
        DW_GROUPNUMBER_DWO,
        &dbg->de_debug_macro,
        DW_DLE_DEBUG_MACRO_DUPLICATE,0,
        TRUE,err);
    SET_UP_SECTION(dbg,scn_name,".debug_ranges",
        group_number,
        &dbg->de_debug_ranges,
        DW_DLE_DEBUG_RANGES_DUPLICATE,0,
        TRUE,err);
    /*  No .debug_ranges.dwo allowed. */

    /* New DWARF5 */
    SET_UP_SECTION(dbg,scn_name,".debug_sup",
        group_number,
        &dbg->de_debug_sup,
        DW_DLE_DEBUG_SUP_DUPLICATE,0,
        TRUE,err);
    /* No .debug_sup.dwo allowed. */

    /*  .symtab and .strtab have to be in any group.  */
    SET_UP_SECTION(dbg,scn_name,".symtab",
        group_number,
        &dbg->de_elf_symtab,
        DW_DLE_DEBUG_SYMTAB_ERR,0,
        FALSE,err);
    SET_UP_SECTION(dbg,scn_name,".strtab",
        group_number,
        &dbg->de_elf_strtab,
        DW_DLE_DEBUG_STRTAB_ERR,0,
        FALSE,err);

    /* New DWARF5 */
    SET_UP_SECTION(dbg,scn_name,".debug_addr",
        group_number,
        &dbg->de_debug_addr,
        DW_DLE_DEBUG_ADDR_DUPLICATE,0,
        TRUE,err);
    /*  No .debug_addr.dwo allowed.  */

    /* gdb added this. */
    SET_UP_SECTION(dbg,scn_name,".gdb_index",
        group_number,
        &dbg->de_debug_gdbindex,
        DW_DLE_DUPLICATE_GDB_INDEX,0,
        FALSE,err);

    /* New DWARF5 */
    SET_UP_SECTION(dbg,scn_name,".debug_names",
        group_number,
        &dbg->de_debug_names,
        DW_DLE_DEBUG_NAMES_DUPLICATE,0,
        FALSE,err);
    /* No .debug_names.dwo allowed. */

    /* gdb added this in DW4. It is in standard DWARF5  */
    SET_UP_SECTION(dbg,scn_name,".debug_cu_index",
        DW_GROUPNUMBER_DWO,
        &dbg->de_debug_cu_index,
        DW_DLE_DUPLICATE_CU_INDEX,0,
        FALSE,err);
    /* gdb added this in DW4. It is in standard DWARF5 */
    SET_UP_SECTION(dbg,scn_name,".debug_tu_index",
        DW_GROUPNUMBER_DWO,
        &dbg->de_debug_tu_index,
        DW_DLE_DUPLICATE_TU_INDEX,0,
        FALSE,err);

    /* GNU added this. It is not part of DWARF */
    SET_UP_SECTION(dbg,scn_name,".gnu_debuglink",
        DW_GROUPNUMBER_DWO,
        &dbg->de_gnu_debuglink,
        DW_DLE_DUPLICATE_GNU_DEBUGLINK,0,
        FALSE,err);

    /* GNU added this. It is not part of DWARF */
    SET_UP_SECTION(dbg,scn_name,".note.gnu.build-id",
        DW_GROUPNUMBER_DWO,
        &dbg->de_note_gnu_buildid,
        DW_DLE_DUPLICATE_GNU_DEBUGLINK,0,
        FALSE,err);
    return DW_DLV_NO_ENTRY;
}
static int
is_section_name_known_already(Dwarf_Debug dbg, const char *scn_name)
{
    unsigned i = 0;
    for ( ; i < dbg->de_debug_sections_total_entries; ++i) {
        struct Dwarf_dbg_sect_s *section = &dbg->de_debug_sections[i];
        if (!strcmp(scn_name, section->ds_name)) {
            /*  The caller will declare this a duplicate, an error. */
            return DW_DLV_OK;
        }
    }
    /* This is normal, we expect we've not accepted scn_name already. */
    return DW_DLV_NO_ENTRY;
}

/*  Given an Elf ptr, set up dbg with pointers
    to all the Dwarf data sections.
    Return NULL on error.

    This function is also responsible for determining
    whether the given object contains Dwarf information
    or not.  The test currently used is that it contains
    either a .debug_info or a .debug_frame section.  If
    not, it returns DW_DLV_NO_ENTRY causing dwarf_init() also to
    return DW_DLV_NO_ENTRY.  Earlier, we had thought of using only
    the presence/absence of .debug_info to test, but we
    added .debug_frame since there could be stripped objects
    that have only a .debug_frame section for exception
    processing.
    DW_DLV_NO_ENTRY or DW_DLV_OK or DW_DLV_ERROR

    This does not allow for section-groups in object files,
    for which many .debug_info (and other DWARF) sections may exist.

    We process. .rela (SHT_RELA) and .rel (SHT_REL)
    sections because with .rela the referencing section
    offset value is zero whereas with .rel the
    referencing section value is already correct for
    the object itself.  In other words, we do it because
    of the definition of .rela relocations in Elf.

    However!  In some cases clang emits  a .rel section (at least
    for .rel.debug_info) where symtab entries have an st_value
    that must be treated like an addend: the compiler did not
    bother to backpatch the DWARF information for these.
*/


/*  These help us ignore some sections that are
    irrelevant to libdwarf.  Maybe should use a hash
    table instead of sequential search? */
int
_dwarf_ignorethissection(const char *scn_name) {
    if(!strcmp(scn_name,".bss")) {
        return TRUE;
    }
    if(!strcmp(scn_name,".comment")) {
        return TRUE;
    }
    if(!strcmp(scn_name,".sbss")) {
        return TRUE;
    }
    if(!strcmp(scn_name,".jcr")) {
        return TRUE;
    }
    if(!strcmp(scn_name,".init")) {
        return TRUE;
    }
    if(!strcmp(scn_name,".fini_array")) {
        return TRUE;
    }
    if(!strcmp(scn_name,".fini")) {
        return TRUE;
    }
    if(!strcmp(scn_name,".fini_array")) {
        return TRUE;
    }
    if(!strcmp(scn_name,".interp")) {
        return TRUE;
    }
    if(!strcmp(scn_name,".text")) {
        return TRUE;
    }
    if(!strcmp(scn_name,".rela.text")) {
        return TRUE;
    }
    if(!strcmp(scn_name,".rel.text")) {
        return TRUE;
    }

    if(!strcmp(scn_name,".plt")) {
        return TRUE;
    }
    if(!strcmp(scn_name,".rela.plt")) {
        return TRUE;
    }
    if(!strcmp(scn_name,".rel.plt")) {
        return TRUE;
    }

    if(!strcmp(scn_name,".data")) {
        return TRUE;
    }
    if(!strcmp(scn_name,".rel.data")) {
        return TRUE;
    }
    if(!strcmp(scn_name,".rela.data")) {
        return TRUE;
    }

    if(!strcmp(scn_name,".got")) {
        return TRUE;
    }
    if(!strcmp(scn_name,".rela.got")) {
        return TRUE;
    }
    if(!strcmp(scn_name,".rel.got")) {
        return TRUE;
    }

    return FALSE;
}
/*  For an object file with an incorrect rela section name,
    readelf prints correct debug information,
    as the tool takes the section type instead
    of the section name. So check the
    section name but test section type. */
static int
is_a_relx_section(const char *scn_name,int type,int *is_rela)
{
    if(startswith(scn_name,".rela.")) {

        *is_rela = TRUE;
        return TRUE;
    }
    if(startswith(scn_name,".rel.")) {
        *is_rela = FALSE;
        return TRUE;
    }
    if (type == SHT_RELA) {
        *is_rela = TRUE;
        return TRUE;
    }
    if (type == SHT_REL) {
        *is_rela = FALSE;
        return TRUE;
    }
    *is_rela = FALSE;
    return FALSE;
}

/*  ASSERT: names like .debug_ or .zdebug_ never passed in here! */
static int
is_a_special_section_semi_dwarf(const char *scn_name)
{
    if (!strcmp(scn_name,".strtab") ||
        !strcmp(scn_name,".symtab")) {
        return TRUE;
    }
    /*  It's not one of these special sections referenced in
        the test. */
    return FALSE;
}

static int
this_section_dwarf_relevant(const char *scn_name,int type, int *is_rela)
{
    /* A small helper function for _dwarf_setup(). */
    if (startswith(scn_name, ".zdebug_") ||
        startswith(scn_name, ".debug_")) {
        /* standard debug */
        return TRUE;
    }
    if (_dwarf_ignorethissection(scn_name)) {
        return FALSE;
    }
    /* Now check if a special section could be
        in a section_group, but though seems unlikely. */
    if (!strcmp(scn_name, ".eh_frame")) {
        /*  This is not really a group related file, but
            it is harmless to consider it such. */
        return TRUE;
    }
    if (!strcmp(scn_name, ".gnu_debuglink")) {
        /*  This is not a group or DWARF related file, but
            it is useful for split dwarf. */
        return TRUE;
    }
    if (!strcmp(scn_name, ".note.gnu.build-id")) {
        /*  This is not a group or DWARF related file, but
            it is useful for split dwarf. */
        return TRUE;
    }
    if(!strcmp(scn_name, ".gdb_index")) {
        return TRUE;
    }
    if(is_a_special_section_semi_dwarf(scn_name)) {
        return TRUE;
    }
    if(is_a_relx_section(scn_name,type,is_rela)) {
        return TRUE;
    }
    /*  All sorts of sections are of no interest: .text
        .rel. and many others. */
    return FALSE;
}

/*  This assumes any non-Elf object files have no SHT_GROUP
    sections. So this code will not be invoked on non-Elf objects.
    One supposes this is unlikely to match any non-Elf
    version of COMDAT. */
static int
insert_sht_list_in_group_map(Dwarf_Debug dbg,
    struct Dwarf_Obj_Access_Section_s *doas,
    unsigned comdat_group_number,
    unsigned section_number,
    Dwarf_Unsigned section_count,
    struct Dwarf_Obj_Access_Interface_s * obj,
    unsigned *did_add_map,
    Dwarf_Error *error)
{
    struct Dwarf_Section_s secdata;
    Dwarf_Small * data = 0;
    int           res = 0;
    Dwarf_Small*  secend = 0;

    memset(&secdata,0,sizeof(secdata));
    secdata.dss_size = doas->size;
    secdata.dss_entrysize = doas->entrysize;
    secdata.dss_group_number = 1; /* arbitrary. */
    secdata.dss_index = section_number;
    secdata.dss_name = ".group";
    secdata.dss_standard_name = ".group";
    secdata.dss_number = section_number;
    secdata.dss_ignore_reloc_group_sec = TRUE;
    res = _dwarf_load_section(dbg,&secdata,error);
    if (res != DW_DLV_OK) {
        if (secdata.dss_data_was_malloc) {
            free(secdata.dss_data);
        }
        return res;
    }
    if (!secdata.dss_data) {
        _dwarf_error(dbg,error,DW_DLE_GROUP_INTERNAL_ERROR);
        return DW_DLV_ERROR;
    }
    if (doas->entrysize != 4) {
        if (secdata.dss_data_was_malloc) {
            free(secdata.dss_data);
        }
        _dwarf_error(dbg,error,DW_DLE_GROUP_INTERNAL_ERROR);
        return DW_DLV_ERROR;
    }
    /*  So now pick up the data in dss_data.
        It is an array of 32 bit fields.
        Entry zero is just a constant 1.
        Each additional is a section number. */
    data = secdata.dss_data;
    secend = data + secdata.dss_size;
    {
        unsigned i = 1;
        unsigned count = doas->size/doas->entrysize;
        Dwarf_Unsigned  fval = 0;

        /*  The fields treatments with  regard
            to endianness is unclear.  In any case a single
            bit should be on, as 0x01000000
            without any endiannes swapping.
            Or so it seems given limited evidence.
            We read with length checking and allow the
            reader to byte swap and then fix things.
            At least one test case has big-endian
            data but little-endian SHT_GROUP data. */
        if ((data+DWARF_32BIT_SIZE) > secend) {
            /* Duplicates the check in READ_UNALIGNED_CK
                so we can free allocated memory bere. */
            free(secdata.dss_data);
            _dwarf_error(dbg,error,DW_DLE_GROUP_INTERNAL_ERROR);
            return DW_DLV_ERROR;
        }
        READ_UNALIGNED_CK(dbg,fval,Dwarf_Unsigned,
            data,
            DWARF_32BIT_SIZE,
            error,
            secend);
        if (fval != 1 && fval != 0x1000000) {
            /*  Could be corrupted elf object. */
            if (secdata.dss_data_was_malloc) {
                free(secdata.dss_data);
            }
            _dwarf_error(dbg,error,DW_DLE_GROUP_INTERNAL_ERROR);
            return DW_DLV_ERROR;
        }

        data = data + doas->entrysize;
        for (i = 1 ; i < count ; ++i) {
            Dwarf_Unsigned  val = 0;

            if ((data+DWARF_32BIT_SIZE) > secend) {
                /* Duplicates the check in READ_UNALIGNED_CK
                    so we can free allocated memory bere. */
                if (secdata.dss_data_was_malloc) {
                    free(secdata.dss_data);
                }
                _dwarf_error(dbg,error,DW_DLE_GROUP_INTERNAL_ERROR);
                return DW_DLV_ERROR;
            }
            READ_UNALIGNED_CK(dbg,val,Dwarf_Unsigned,
                data,
                DWARF_32BIT_SIZE,
                error,
                secend);
            if (val > section_count) {
                /*  Might be confused endianness by
                    the compiler generating the SHT_GROUP.
                    This is pretty horrible. */
                Dwarf_Unsigned valr = 0;
                _dwarf_memcpy_swap_bytes(&valr,&val,
                    DWARF_32BIT_SIZE);
                if (valr > section_count) {
                    if (secdata.dss_data_was_malloc) {
                        free(secdata.dss_data);
                    }
                    _dwarf_error(dbg,error,DW_DLE_GROUP_INTERNAL_ERROR);
                    return DW_DLV_ERROR;
                }
                /* Ok. Yes, ugly. */
                val = valr;
            }
            {
                /*  Ensure this group entry DWARF relevant before
                    adding to group map */
                struct Dwarf_Obj_Access_Section_s doasx;
                int resx = DW_DLV_ERROR;
                int err = 0;
                int is_rela = FALSE;

                memset(&doasx,0,sizeof(doasx));
                resx = obj->methods->get_section_info(obj->object,
                    val,
                    &doasx, &err);
                if (resx == DW_DLV_NO_ENTRY){
                    /*  Should we really ignore this? */
                    continue;
                } else if (resx == DW_DLV_ERROR){
                    if (secdata.dss_data_was_malloc) {
                        free(secdata.dss_data);
                    }
                    _dwarf_error(dbg,error,err);
                    return resx;
                }
                if (!this_section_dwarf_relevant(doasx.name,
                    doasx.type,&is_rela) ) {
                    continue;
                }
                data += DWARF_32BIT_SIZE;
                *did_add_map = TRUE;
                res = _dwarf_insert_in_group_map(dbg,
                    comdat_group_number,val,
                    doasx.name,
                    error);
                if (res != DW_DLV_OK) {
                    free(secdata.dss_data);
                    return res;
                }
            }
        }
    }
    if (secdata.dss_data_was_malloc) {
        free(secdata.dss_data);
    }
    return DW_DLV_OK;
}



/*  Split dwarf CUs can be in an object with non-split
    or split may be in a separate object.
    If all in one object the default is to deal with group_number
    and ignore DW_GROUPNUMBER_DWO.
    If only .dwo the default is DW_GROUPNUMBER_DWO(2).
    Otherwise use DW_GROUP_NUMBER_BASE(1).

    If there are COMDAT SHT_GROUP sections, these
    are assigned group numbers 3-N as needed.

    At present this makes the assumption that COMDAT group
    (ie, SHT_GROUP) sections
    have lower section numbers than the sections COMDAT refers to.
    It is not clear whether this is guaranteed, COMDAT is not
    an official Elf thing and documentation is scarce.
    In the 1990's SGI folks and others formed a committee
    and attempted to get COMDAT and a feature allowing section
    numbers  greater than 16 bits into Elf, but there was no
    group that was able to approve such things.

    This is called once at dbg init  time.
*/

static int
determine_target_group(Dwarf_Unsigned section_count,
    struct Dwarf_Obj_Access_Interface_s * obj,
    unsigned *group_number_out,
    Dwarf_Debug dbg,
    Dwarf_Error *error)
{
    unsigned obj_section_index = 0;
    int found_group_one = 0;
    int found_group_two = 0;
    struct Dwarf_Group_Data_s *grp = 0;
    unsigned comdat_group_next = 3;
    unsigned lowest_comdat_groupnum = 0;

    grp = &dbg->de_groupnumbers;
    grp->gd_number_of_groups = 0;
    grp->gd_number_of_sections = section_count;
    if (grp->gd_map) {
        _dwarf_error(dbg,error,DW_DLE_GROUP_INTERNAL_ERROR);
        return DW_DLV_OK;
    }
    for (obj_section_index = 0; obj_section_index < section_count;
        ++obj_section_index) {

        struct Dwarf_Obj_Access_Section_s doas;
        int res = DW_DLV_ERROR;
        int err = 0;
        const char *scn_name = 0;
        unsigned groupnumber = 0;
        unsigned mapgroupnumber = 0;
        int is_rela = FALSE;

        memset(&doas,0,sizeof(doas));
        res = obj->methods->get_section_info(obj->object,
            obj_section_index,
            &doas, &err);
        if (res == DW_DLV_NO_ENTRY){
            return res;
        } else if (res == DW_DLV_ERROR){
            _dwarf_error(dbg, error,err);
            return res;
        }

        if (doas.type == SHT_GROUP) {
            /*  See assumptions in function comment above. */
            unsigned did_add_map = 0;
            /*  Add to our map. Here we
                are assuming SHT_GROUP records come first.
                Till proven wrong. */
            res = insert_sht_list_in_group_map(dbg,&doas,
                comdat_group_next,
                obj_section_index,
                section_count,
                obj,
                &did_add_map,error);
            if (res != DW_DLV_OK) {
                return res;
            }
            if (!lowest_comdat_groupnum) {
                lowest_comdat_groupnum = comdat_group_next;
            }
            if (did_add_map) {
                ++grp->gd_number_of_groups;
                ++comdat_group_next;
            }
            continue;
        }
        scn_name = doas.name;
        if (!this_section_dwarf_relevant(scn_name,doas.type,&is_rela) ) {
            continue;
        }

        /*  Now at a 'normal' section, though we do not
            quite know what group it is. */

        res = _dwarf_section_get_target_group_from_map(dbg,
            obj_section_index,&groupnumber,error);
        if (res == DW_DLV_OK ) {
            /*  groupnumber is set. Fall through.
                All COMDAT group should get here. */
            mapgroupnumber = groupnumber;
        } else if (res == DW_DLV_ERROR) {
            return res;
        } else { /* DW_DLV_NO_ENTRY */
            /* Normal non-COMDAT. groupnumber is zero.  */
        }


        /* BUILDING_MAP.  See also BUILDING_SECTIONS, SETUP_SECTION */
        if (!groupnumber) {
            res =_dwarf_dwo_groupnumber_given_name(scn_name,
                &groupnumber);
            /* DW_DLV_ERROR impossible here. */
            if (res == DW_DLV_OK) {
                /* groupnumber set 2 */
            } else {
                /*  This is what it has to be.
                    .rela in here too.  */
                groupnumber = DW_GROUPNUMBER_BASE;
            }
        }
        if (is_a_relx_section(scn_name,doas.type,&is_rela)) {
            continue;
        }

        /*  ASSERT: groupnumber non-zero now */
        if (!is_a_special_section_semi_dwarf(scn_name)) {
            if (mapgroupnumber) {
                /* Already in group map */
                continue;
            }
            /* !mapgroupnumber */
            res = _dwarf_insert_in_group_map(dbg,
                groupnumber,obj_section_index,
                scn_name,
                error);
            if (res != DW_DLV_OK) {
                return res;
            }
            if (groupnumber == 1) {
                found_group_one++;
            } else if (groupnumber == 2) {
                found_group_two++;
            }
            continue;
        }
    }
    if (found_group_two) {
        ++grp->gd_number_of_groups;
    }
    if (found_group_one) {
        *group_number_out = DW_GROUPNUMBER_BASE;
        ++grp->gd_number_of_groups;
    } else {
        if (found_group_two) {
            *group_number_out = DW_GROUPNUMBER_DWO;
        } else {
            if (lowest_comdat_groupnum) {
                *group_number_out = lowest_comdat_groupnum;
            } else {
                *group_number_out = DW_GROUPNUMBER_BASE;
            }
        }
    }
    return DW_DLV_OK;
}



static int
_dwarf_setup(Dwarf_Debug dbg, Dwarf_Error * error)
{
    const char *scn_name = 0;
    struct Dwarf_Obj_Access_Interface_s * obj = 0;
    int resn = 0;
    struct Dwarf_Section_s **sections = 0;
    Dwarf_Endianness endianness;
    Dwarf_Unsigned section_count = 0;
    unsigned default_group_number = 0;
    unsigned foundDwarf = FALSE;
    unsigned obj_section_index = 0;

    dbg->de_assume_string_in_bounds =
        _dwarf_assume_string_in_bounds;
    /* First make an arbitrary assumption. */
    dbg->de_same_endian = 1;
    dbg->de_copy_word = _dwarf_memcpy_noswap_bytes;
    obj = dbg->de_obj_file;
    endianness = obj->methods->get_byte_order(obj->object);
    /* Then adjust any changes we need. */
#ifdef WORDS_BIGENDIAN
    dbg->de_big_endian_object = 1;
    if (endianness == DW_OBJECT_LSB ) {
        dbg->de_same_endian = 0;
        dbg->de_big_endian_object = 0;
        dbg->de_copy_word = _dwarf_memcpy_swap_bytes;
    }
#else /* little endian */
    dbg->de_big_endian_object = 0;
    if (endianness == DW_OBJECT_MSB ) {
        dbg->de_same_endian = 0;
        dbg->de_big_endian_object = 1;
        dbg->de_copy_word = _dwarf_memcpy_swap_bytes;
    }
#endif /* !WORDS_BIGENDIAN */


    /*  The following de_length_size is Not Too Significant. Only used
        one calculation, and an approximate one at that. */
    dbg->de_length_size = obj->methods->get_length_size(obj->object);
    dbg->de_pointer_size = obj->methods->get_pointer_size(obj->object);

    section_count = obj->methods->get_section_count(obj->object);
    resn = determine_target_group(section_count,obj,
        &default_group_number,dbg,error);
    if (resn == DW_DLV_ERROR) {
        return DW_DLV_ERROR;
    }
    if (dbg->de_groupnumber == DW_GROUPNUMBER_ANY) {
        dbg->de_groupnumber = default_group_number;
    }
    /*  Allocate space to record references to debug sections, that can
        be referenced by RELA sections in the 'sh_info' field. */
    sections = (struct Dwarf_Section_s **)calloc(section_count + 1,
        sizeof(struct Dwarf_Section_s *));
    if (!sections) {
        /* Impossible case, we hope. Give up. */
        _dwarf_error(dbg, error, DW_DLE_SECTION_ERROR);
        return DW_DLV_ERROR;
    }

    /*  We can skip index 0 when considering ELF files, but not other
        object types.  Indeed regardless of the object type we should
        skip section 0 here.
        This is a convention.  We depend on it.
        Non-elf object access code should
        (in itself) understand we will index beginning at 1 and adjust
        itself to deal with this Elf convention.    Without this
        convention various parts of the code in this file won't work correctly.
        A dss_index of 0 must not be used, even though we start at 0
        here.  So the get_section_info() must adapt to the situation
        (the elf version does automatically as a result of Elf having
        a section zero with zero length and an empty name). */

    /* ASSERT: all group map entries set up. */

    for (obj_section_index = 0; obj_section_index < section_count;
        ++obj_section_index) {

        struct Dwarf_Obj_Access_Section_s doas;
        int res = DW_DLV_ERROR;
        int err = 0;
        unsigned groupnumber = 0;
        unsigned mapgroupnumber = 0;
        int is_rela = FALSE;

        res = _dwarf_section_get_target_group_from_map(dbg,obj_section_index,
            &groupnumber,error);
        if (res == DW_DLV_OK ) {
            /* groupnumber is set. Fall through */
            mapgroupnumber = groupnumber;
        } else if (res == DW_DLV_ERROR) {
            free(sections);
            return res;
        } else { /* DW_DLV_NO_ENTRY */
            /* fall through, a BASE or DWO group, possibly */
        }
        memset(&doas,0,sizeof(doas));
        res = obj->methods->get_section_info(obj->object,
            obj_section_index,
            &doas, &err);
        if (res == DW_DLV_NO_ENTRY){
            free(sections);
            return res;
        } else if (res == DW_DLV_ERROR){
            free(sections);
            DWARF_DBG_ERROR(dbg, err, DW_DLV_ERROR);
        }
        scn_name = doas.name;
        if (!groupnumber) {
            /* This finds dwo sections, group 2 */
            res = _dwarf_dwo_groupnumber_given_name(scn_name,
                &groupnumber);
            if (res == DW_DLV_NO_ENTRY) {
                /* No, must be group 1 */
                groupnumber = DW_GROUPNUMBER_BASE;
            }
        }
        if (!this_section_dwarf_relevant(scn_name,doas.type,&is_rela) ) {
            continue;
        }
        if (!is_a_relx_section(scn_name,doas.type,&is_rela)
            && !is_a_special_section_semi_dwarf(scn_name)) {
            /*  We do these actions only for group-related
                sections.  Do for  .debug_info etc,
                never for .strtab or .rela.*
                We already tested for relevance, so that part
                is not news. */
            if(mapgroupnumber == dbg->de_groupnumber) {
                /*  OK. Mapped. Part of the group.. This will
                    catch the cases where there are versions of
                    a section in multiple COMDATs and in BASE
                    an DWO to get the right one */
            } else {
                /* This section not mapped into this group. */
                if (groupnumber == 1 && dbg->de_groupnumber > 2 &&
                    !_dwarf_section_in_group_by_name(dbg,scn_name,
                        dbg->de_groupnumber)) {
                    /* Load the section (but as group 1) */
                } else {
                    continue;
                }
            }
        }
        /* BUILDING_SECTIONS.  See also BUILDING_MAP, SETUP_SECTION */
        {
            /*  Build up the sections table and the
                de_debug* etc pointers in Dwarf_Debug. */
            struct Dwarf_dbg_sect_s *section;

            int found_match = FALSE;

            res = is_section_name_known_already(dbg,scn_name);
            if (res == DW_DLV_OK) {
                /* DUPLICATE */
                free(sections);
                DWARF_DBG_ERROR(dbg, DW_DLE_SECTION_DUPLICATION,
                    DW_DLV_ERROR);
            } else if (res == DW_DLV_ERROR) {
                free(sections);
                DWARF_DBG_ERROR(dbg, err, DW_DLV_ERROR);
            }
            /* No entry: new-to-us section, the normal case. */
            res = enter_section_in_de_debug_sections_array(dbg,scn_name,
                obj_section_index, groupnumber,&err);
            if (res == DW_DLV_OK) {
                section = &dbg->de_debug_sections[
                    dbg->de_debug_sections_total_entries-1];
                res = get_basic_section_data(dbg,
                    section->ds_secdata, &doas,
                    obj_section_index,
                    groupnumber,
                    error,
                    section->ds_duperr,
                    section->ds_emptyerr);
                if (res != DW_DLV_OK) {
                    free(sections);
                    return res;
                }
                sections[obj_section_index] = section->ds_secdata;
                foundDwarf += section->ds_have_dwarf;
                found_match = TRUE;
                /*  Normal section set up.
                    Fall through. */
            } else if (res == DW_DLV_NO_ENTRY) {
                /*  We get here for relocation sections.
                    Fall through. */
            } else {
                free(sections);
                DWARF_DBG_ERROR(dbg, err, DW_DLV_ERROR);
            }

            if (!found_match) {
                /*  For an object file with incorrect rel[a] section name,
                    the 'readelf' tool, prints correct debug information,
                    as the tool takes the section type instead
                    of the section name. If the current section
                    is a RELA one and the 'sh_info'
                    refers to a debug section, add the relocation data. */
                if (is_a_relx_section(scn_name,doas.type,&is_rela)) {
                    if ( doas.info < section_count) {
                        if (sections[doas.info]) {
                            add_relx_data_to_secdata(sections[doas.info],
                                &doas,
                                obj_section_index,is_rela);
                        }
                    } else {
                        /* Something is wrong with the ELF file. */
                        free(sections);
                        DWARF_DBG_ERROR(dbg, DW_DLE_ELF_SECT_ERR, DW_DLV_ERROR);
                    }
                }
            }
            /* Fetch next section */
        }
    }

    /* Free table with section information. */
    free(sections);
    if (foundDwarf) {
        return DW_DLV_OK;
    }
    return DW_DLV_NO_ENTRY;
}

/*  There is one table per CU and one per TU, and each
    table refers to the associated other DWARF data
    for that CU or TU.
    See DW_SECT_*

    In DWARF4 the type units are in .debug_types
    In DWARF5 the type units are in .debug_info.
*/

static int
load_debugfission_tables(Dwarf_Debug dbg,Dwarf_Error *error)
{
    int i = 0;
    if (dbg->de_debug_cu_index.dss_size ==0 &&
        dbg->de_debug_tu_index.dss_size ==0) {
        /*  This is the normal case.
            No debug fission. Not a .dwp object. */
        return DW_DLV_NO_ENTRY;
    }

    for (i = 0; i < 2; ++i) {
        Dwarf_Xu_Index_Header xuptr = 0;
        struct Dwarf_Section_s* dwsect = 0;
        Dwarf_Unsigned version = 0;
        Dwarf_Unsigned number_of_cols /* L */ = 0;
        Dwarf_Unsigned number_of_CUs /* N */ = 0;
        Dwarf_Unsigned number_of_slots /* M */ = 0;
        const char *secname = 0;
        int res = 0;
        const char *type = 0;

        if (i == 0) {
            dwsect = &dbg->de_debug_cu_index;
            type = "cu";
        } else {
            dwsect = &dbg->de_debug_tu_index;
            type = "tu";
        }
        if ( !dwsect->dss_size ) {
            continue;
        }
        res = dwarf_get_xu_index_header(dbg,type,
            &xuptr,&version,&number_of_cols,
            &number_of_CUs,&number_of_slots,
            &secname,error);
        if (res == DW_DLV_NO_ENTRY) {
            continue;
        }
        if (res != DW_DLV_OK) {
            return res;
        }
        if (i == 0) {
            dbg->de_cu_hashindex_data = xuptr;
        } else {
            dbg->de_tu_hashindex_data = xuptr;
        }
    }
    return DW_DLV_OK;
}

/*
    Use a Dwarf_Obj_Access_Interface to kick things off. All other
    init routines eventually use this one.
    The returned Dwarf_Debug contains a copy of *obj
    the callers copy of *obj may be freed whenever the caller
    wishes.
*/
int
dwarf_object_init(Dwarf_Obj_Access_Interface* obj,
    Dwarf_Handler errhand,
    Dwarf_Ptr errarg, Dwarf_Debug* ret_dbg,
    Dwarf_Error* error)
{
    return dwarf_object_init_b(obj,errhand,errarg,
        DW_GROUPNUMBER_ANY,ret_dbg,error);
}

/*  New March 2017. Enables dealing with DWARF5 split dwarf more fully.  */
int
dwarf_object_init_b(Dwarf_Obj_Access_Interface* obj, Dwarf_Handler errhand,
    Dwarf_Ptr errarg,
    unsigned groupnumber,
    Dwarf_Debug* ret_dbg,
    Dwarf_Error* error)
{
    Dwarf_Debug dbg = 0;
    int setup_result = DW_DLV_OK;

    dbg = _dwarf_get_debug();
    if (dbg == NULL) {
        DWARF_DBG_ERROR(dbg, DW_DLE_DBG_ALLOC, DW_DLV_ERROR);
    }
    dbg->de_errhand = errhand;
    dbg->de_errarg = errarg;
    dbg->de_frame_rule_initial_value = DW_FRAME_REG_INITIAL_VALUE;
    dbg->de_frame_reg_rules_entry_count = DW_FRAME_LAST_REG_NUM;
#ifdef HAVE_OLD_FRAME_CFA_COL
    /*  DW_FRAME_CFA_COL is really only suitable for old libdwarf frame
        interfaces and its value of 0 there is only usable where
        (as in MIPS) register 0 has no value other than 0 so
        we can use the frame table column 0 for the CFA value
        (and rely on client software to know when 'register 0'
        is the cfa and when to just use a value 0 for register 0).
    */
    dbg->de_frame_cfa_col_number = DW_FRAME_CFA_COL;
#else
    dbg->de_frame_cfa_col_number = DW_FRAME_CFA_COL3;
#endif
    dbg->de_frame_same_value_number = DW_FRAME_SAME_VAL;
    dbg->de_frame_undefined_value_number  = DW_FRAME_UNDEFINED_VAL;

    dbg->de_obj_file = obj;
    dbg->de_groupnumber = groupnumber;
    setup_result = _dwarf_setup(dbg, error);
    if (setup_result == DW_DLV_OK) {
        int fission_result = load_debugfission_tables(dbg,error);
        /*  In most cases we get
            setup_result == DW_DLV_NO_ENTRY here
            as having debugfission (.dwp objects)
            is fairly rare. */
        if (fission_result == DW_DLV_ERROR) {
            /*  Something is very wrong. */
            setup_result = fission_result;
        }
    }
    if (setup_result != DW_DLV_OK) {
        int freeresult = 0;
        int myerr = 0;
        dwarfstring msg;

        dwarfstring_constructor(&msg);
        /* We cannot use any _dwarf_setup()
            error here as
            we are freeing dbg, making that error (setup
            as part of dbg) stale.
            Hence we have to make a new error without a dbg.
            But error might be NULL and the init call
            error-handler function might be set.
        */
        if ( (setup_result == DW_DLV_ERROR) && *error ) {
            /*  Preserve our _dwarf_setup error number, but
                this does not apply if error NULL. */
            myerr = dwarf_errno(*error);
            dwarfstring_append(&msg,dwarf_errmsg(*error));
            /*  deallocate the soon-stale error pointer. */
            dwarf_dealloc(dbg,*error,DW_DLA_ERROR);
            *error = 0;
        }
        /*  The status we want to return  here is of _dwarf_setup,
            not of the  _dwarf_free_all_of_one_debug(dbg) call.
            So use a local status variable for the free.  */
        freeresult = _dwarf_free_all_of_one_debug(dbg);
        dbg = 0;
        /* DW_DLV_NO_ENTRY not possible in freeresult */
        if (freeresult == DW_DLV_ERROR) {
            /*  Use the _dwarf_setup error number.
                If error is NULL the following will issue
                a message on stderr and abort(), as without
                dbg there is no error-handler function.
                */
            _dwarf_error_string(dbg,error,DW_DLE_DBG_ALLOC,
                dwarfstring_string(&msg));
            dwarfstring_destructor(&msg);
            return DW_DLV_ERROR;
        }
        if (setup_result == DW_DLV_ERROR) {
            /*  Use the _dwarf_setup error number.
                If error is NULL the following will issue
                a message on stderr and abort(), as without
                dbg there is no error-handler function.
                */
            _dwarf_error_string(dbg,error,myerr,
                dwarfstring_string(&msg));
        }
        dwarfstring_destructor(&msg);
        return setup_result;
    }
    dwarf_harmless_init(&dbg->de_harmless_errors,
        DW_HARMLESS_ERROR_CIRCULAR_LIST_DEFAULT_SIZE);
    *ret_dbg = dbg;
    return DW_DLV_OK;
}

/*  A finish routine that is completely unaware of ELF.

    Frees all memory that was not previously freed by
    dwarf_dealloc.
    Aside from certain categories.  */
int
dwarf_object_finish(Dwarf_Debug dbg, Dwarf_Error * error)
{
    int res = 0;

    res = _dwarf_free_all_of_one_debug(dbg);
    if (res == DW_DLV_ERROR) {
        DWARF_DBG_ERROR(dbg, DW_DLE_DBG_ALLOC, DW_DLV_ERROR);
    }
    return res;
}

#ifdef HAVE_ZLIB
/*  case 1:
    The input stream is assumed to contain
    the four letters
    ZLIB
    Followed by 8 bytes of the size of the
    uncompressed stream. Presented as
    a big-endian binary number.
    Following that is the stream to decompress.

    case 2:
    The section flag bit  SHF_COMPRESSED (1 << 11)
    must be set.
    we then do the eqivalent of reading a
        Elf32_External_Chdr
    or
        Elf64_External_Chdr
    to get the type (which must be 1)
    and the decompressed_length.
    Then what follows the implicit Chdr is decompressed.
    */

/*  ALLOWED_ZLIB_INFLATION is a heuristic, not necessarily right.
    The test case klingler2/compresseddebug.amd64 actually
    inflates about 8 times. */
#define ALLOWED_ZLIB_INFLATION 16
static int
do_decompress_zlib(Dwarf_Debug dbg,
    struct Dwarf_Section_s *section,
    Dwarf_Error * error)
{
    Bytef *basesrc = (Bytef *)section->dss_data;
    Bytef *src = (Bytef *)basesrc;
    uLong srclen = section->dss_size;
    Dwarf_Unsigned flags = section->dss_flags;
    Dwarf_Small *endsection = 0;
    int res = 0;
    Bytef *dest = 0;
    uLongf destlen = 0;
    Dwarf_Unsigned uncompressed_len = 0;

    endsection = basesrc + srclen;
    if ((src + 12) >endsection) {
        DWARF_DBG_ERROR(dbg, DW_DLE_ZLIB_SECTION_SHORT, DW_DLV_ERROR);
    }
    section->dss_compressed_length = section->dss_size;
    if(!strncmp("ZLIB",(const char *)src,4)) {
        unsigned i = 0;
        unsigned l = 8;
        unsigned char *c = src+4;
        for( ; i < l; ++i,c++) {
            uncompressed_len <<= 8;
            uncompressed_len += *c;
        }
        src = src + 12;
        srclen -= 12;
        section->dss_uncompressed_length = uncompressed_len;
        section->dss_ZLIB_compressed = TRUE;
    } else  if (flags & SHF_COMPRESSED) {
        /*  The prefix is a struct:
            unsigned int type; followed by pad if following are 64bit!
            size-of-target-address size
            size-of-target-address
        */
        Dwarf_Small *ptr    = (Dwarf_Small *)src;
        Dwarf_Unsigned type = 0;
        Dwarf_Unsigned size = 0;
        /* Dwarf_Unsigned addralign = 0; */
        unsigned fldsize    = dbg->de_pointer_size;
        unsigned structsize = 3* fldsize;

        READ_UNALIGNED_CK(dbg,type,Dwarf_Unsigned,ptr,
            DWARF_32BIT_SIZE,
            error,endsection);
        ptr += fldsize;
        READ_UNALIGNED_CK(dbg,size,Dwarf_Unsigned,ptr,fldsize,
            error,endsection);
        if (type != ELFCOMPRESS_ZLIB) {
            DWARF_DBG_ERROR(dbg, DW_DLE_ZDEBUG_INPUT_FORMAT_ODD,
                DW_DLV_ERROR);
        }
        uncompressed_len = size;
        section->dss_uncompressed_length = uncompressed_len;
        src    += structsize;
        srclen -= structsize;
        section->dss_shf_compressed = TRUE;
    } else {
        DWARF_DBG_ERROR(dbg, DW_DLE_ZDEBUG_INPUT_FORMAT_ODD,
            DW_DLV_ERROR);
    }
    {
        /*  According to zlib.net zlib essentially never expands
            the data when compressing.  There is no statement
            about  any effective limit in the compression factor
            though we, here, assume  such a limit to check
            for sanity in the object file.
            These tests are heuristics.  */
        Dwarf_Unsigned max_inflated_len = srclen*ALLOWED_ZLIB_INFLATION;

        if (srclen > 50)  {
            /*  If srclen not super tiny lets check the following. */
            if (uncompressed_len < (srclen/2)) {
                /*  Violates the approximate invariant about
                    compression not actually inflating. */
                DWARF_DBG_ERROR(dbg, DW_DLE_ZLIB_UNCOMPRESS_ERROR,
                    DW_DLV_ERROR);
            }
        }
        if (max_inflated_len < srclen) {
            /* The calculation overflowed. */
            DWARF_DBG_ERROR(dbg, DW_DLE_ZLIB_UNCOMPRESS_ERROR, DW_DLV_ERROR);
        }
        if (uncompressed_len > max_inflated_len) {
            DWARF_DBG_ERROR(dbg, DW_DLE_ZLIB_UNCOMPRESS_ERROR, DW_DLV_ERROR);
        }
    }
    if( (src +srclen) > endsection) {
        DWARF_DBG_ERROR(dbg, DW_DLE_ZLIB_SECTION_SHORT, DW_DLV_ERROR);
    }
    destlen = uncompressed_len;
    dest = malloc(destlen);
    if(!dest) {
        DWARF_DBG_ERROR(dbg, DW_DLE_ALLOC_FAIL, DW_DLV_ERROR);
    }
    res = uncompress(dest,&destlen,src,srclen);
    if (res == Z_BUF_ERROR) {
        free(dest);
        DWARF_DBG_ERROR(dbg, DW_DLE_ZLIB_BUF_ERROR, DW_DLV_ERROR);
    } else if (res == Z_MEM_ERROR) {
        free(dest);
        DWARF_DBG_ERROR(dbg, DW_DLE_ALLOC_FAIL, DW_DLV_ERROR);
    } else if (res != Z_OK) {
        free(dest);
        /* Probably Z_DATA_ERROR. */
        DWARF_DBG_ERROR(dbg, DW_DLE_ZLIB_DATA_ERROR, DW_DLV_ERROR);
    }
    /* Z_OK */
    section->dss_data = dest;
    section->dss_size = destlen;
    section->dss_data_was_malloc = TRUE;
    section->dss_did_decompress = TRUE;
    return DW_DLV_OK;
}
#endif /* HAVE_ZLIB */


/*  Load the ELF section with the specified index and set its
    dss_data pointer to the memory where it was loaded.  */
int
_dwarf_load_section(Dwarf_Debug dbg,
    struct Dwarf_Section_s *section,
    Dwarf_Error * error)
{
    int res  = DW_DLV_ERROR;
    int err = 0;
    struct Dwarf_Obj_Access_Interface_s *o = 0;

    /* check to see if the section is already loaded */
    if (section->dss_data !=  NULL) {
        return DW_DLV_OK;
    }
    o = dbg->de_obj_file;
    /*  There is an elf convention that section index 0
        is reserved, and that section is always empty.
        Non-elf object formats must honor
        that by ensuring that (when they
        assign numbers to 'sections' or
        'section-like-things') they never
        assign a real section section-number
        0 to dss_index.

        There is also a convention for 'bss' that that section
        and its like sections have no data but do have a size.
        That is never true of DWARF sections */
    res = o->methods->load_section(
        o->object, section->dss_index,
        &section->dss_data, &err);
    if (res == DW_DLV_ERROR) {
        DWARF_DBG_ERROR(dbg, err, DW_DLV_ERROR);
    }
    /*  For PE and mach-o all section data was always
        malloc'd. We do not need to set dss_data_was_malloc
        though as the o->object data will eventually free
        the original section data.
        The first character of any o->object struct gives the type. */

    if (res == DW_DLV_NO_ENTRY) {
        /*  Gets this for section->dss_index 0.
            Which by ELF definition is a section index
            which is not used (reserved by Elf to
            mean no-section-index).
            Otherwise NULL dss_data gets error.
            BSS would legitimately have no data, but
            no DWARF related section could possbly be bss. */
        return res;
    }
    if (section->dss_ignore_reloc_group_sec) {
        /* Neither zdebug nor reloc apply to .group sections. */
        return res;
    }
    if ((section->dss_zdebug_requires_decompress ||
        section->dss_shf_compressed ||
        section->dss_ZLIB_compressed) &&
        !section->dss_did_decompress) {
        if (!section->dss_data) {
            /*  Impossible. This makes no sense.
                Corrupt object. */
            DWARF_DBG_ERROR(dbg, DW_DLE_COMPRESSED_EMPTY_SECTION, DW_DLV_ERROR);
        }
#ifdef HAVE_ZLIB
        res = do_decompress_zlib(dbg,section,error);
        if (res != DW_DLV_OK) {
            return res;
        }
        section->dss_did_decompress = TRUE;
#else
        DWARF_DBG_ERROR(dbg,DW_DLE_ZDEBUG_REQUIRES_ZLIB, DW_DLV_ERROR);
#endif
    }
    if (_dwarf_apply_relocs == 0) {
        return res;
    }
    if (section->dss_reloc_size == 0) {
        return res;
    }
    if (!o->methods->relocate_a_section) {
        return res;
    }
    /*apply relocations */
    res = o->methods->relocate_a_section( o->object,
        section->dss_index, dbg, &err);
    if (res == DW_DLV_ERROR) {
        DWARF_DBG_ERROR(dbg, err, res);
    }
    return res;
}

/* This is a hack so clients can verify offsets.
   Added April 2005 so that debugger can detect broken offsets
   (which happened in an IRIX  -64 executable larger than 2GB
    using MIPSpro 7.3.1.3 compilers. A couple .debug_pubnames
    offsets were wrong.).
*/
int
dwarf_get_section_max_offsets(Dwarf_Debug dbg,
    Dwarf_Unsigned * debug_info_size,
    Dwarf_Unsigned * debug_abbrev_size,
    Dwarf_Unsigned * debug_line_size,
    Dwarf_Unsigned * debug_loc_size,
    Dwarf_Unsigned * debug_aranges_size,
    Dwarf_Unsigned * debug_macinfo_size,
    Dwarf_Unsigned * debug_pubnames_size,
    Dwarf_Unsigned * debug_str_size,
    Dwarf_Unsigned * debug_frame_size,
    Dwarf_Unsigned * debug_ranges_size,
    Dwarf_Unsigned * debug_typenames_size)
{
    *debug_info_size = dbg->de_debug_info.dss_size;
    *debug_abbrev_size = dbg->de_debug_abbrev.dss_size;
    *debug_line_size = dbg->de_debug_line.dss_size;
    *debug_loc_size = dbg->de_debug_loc.dss_size;
    *debug_aranges_size = dbg->de_debug_aranges.dss_size;
    *debug_macinfo_size = dbg->de_debug_macinfo.dss_size;
    *debug_pubnames_size = dbg->de_debug_pubnames.dss_size;
    *debug_str_size = dbg->de_debug_str.dss_size;
    *debug_frame_size = dbg->de_debug_frame.dss_size;
    *debug_ranges_size = dbg->de_debug_ranges.dss_size;
    *debug_typenames_size = dbg->de_debug_typenames.dss_size;
    return DW_DLV_OK;
}
/*  This adds the new types size (new section) to the output data.
    Oct 27, 2011. */
int
dwarf_get_section_max_offsets_b(Dwarf_Debug dbg,
    Dwarf_Unsigned * debug_info_size,
    Dwarf_Unsigned * debug_abbrev_size,
    Dwarf_Unsigned * debug_line_size,
    Dwarf_Unsigned * debug_loc_size,
    Dwarf_Unsigned * debug_aranges_size,
    Dwarf_Unsigned * debug_macinfo_size,
    Dwarf_Unsigned * debug_pubnames_size,
    Dwarf_Unsigned * debug_str_size,
    Dwarf_Unsigned * debug_frame_size,
    Dwarf_Unsigned * debug_ranges_size,
    Dwarf_Unsigned * debug_typenames_size,
    Dwarf_Unsigned * debug_types_size)
{
    *debug_info_size = dbg->de_debug_info.dss_size;
    *debug_abbrev_size = dbg->de_debug_abbrev.dss_size;
    *debug_line_size = dbg->de_debug_line.dss_size;
    *debug_loc_size = dbg->de_debug_loc.dss_size;
    *debug_aranges_size = dbg->de_debug_aranges.dss_size;
    *debug_macinfo_size = dbg->de_debug_macinfo.dss_size;
    *debug_pubnames_size = dbg->de_debug_pubnames.dss_size;
    *debug_str_size = dbg->de_debug_str.dss_size;
    *debug_frame_size = dbg->de_debug_frame.dss_size;
    *debug_ranges_size = dbg->de_debug_ranges.dss_size;
    *debug_typenames_size = dbg->de_debug_typenames.dss_size;
    *debug_types_size = dbg->de_debug_types.dss_size;
    return DW_DLV_OK;
}

/*  Now with sections new to DWARF5 (unofficial list,preliminary) */
int
dwarf_get_section_max_offsets_c(Dwarf_Debug dbg,
    Dwarf_Unsigned * debug_info_size,
    Dwarf_Unsigned * debug_abbrev_size,
    Dwarf_Unsigned * debug_line_size,
    Dwarf_Unsigned * debug_loc_size,
    Dwarf_Unsigned * debug_aranges_size,
    Dwarf_Unsigned * debug_macinfo_size,
    Dwarf_Unsigned * debug_pubnames_size,
    Dwarf_Unsigned * debug_str_size,
    Dwarf_Unsigned * debug_frame_size,
    Dwarf_Unsigned * debug_ranges_size,
    Dwarf_Unsigned * debug_typenames_size,
    Dwarf_Unsigned * debug_types_size,
    Dwarf_Unsigned * debug_macro_size,
    Dwarf_Unsigned * debug_str_offsets_size,
    Dwarf_Unsigned * debug_sup_size,
    Dwarf_Unsigned * debug_cu_index_size,
    Dwarf_Unsigned * debug_tu_index_size)
{
    *debug_info_size = dbg->de_debug_info.dss_size;
    *debug_abbrev_size = dbg->de_debug_abbrev.dss_size;
    *debug_line_size = dbg->de_debug_line.dss_size;
    *debug_loc_size = dbg->de_debug_loc.dss_size;
    *debug_aranges_size = dbg->de_debug_aranges.dss_size;
    *debug_macinfo_size = dbg->de_debug_macinfo.dss_size;
    *debug_pubnames_size = dbg->de_debug_pubnames.dss_size;
    *debug_str_size = dbg->de_debug_str.dss_size;
    *debug_frame_size = dbg->de_debug_frame.dss_size;
    *debug_ranges_size = dbg->de_debug_ranges.dss_size;
    *debug_typenames_size = dbg->de_debug_typenames.dss_size;
    *debug_types_size = dbg->de_debug_types.dss_size;
    *debug_macro_size = dbg->de_debug_macro.dss_size;
    *debug_str_offsets_size = dbg->de_debug_str_offsets.dss_size;
    *debug_sup_size = dbg->de_debug_sup.dss_size;
    *debug_cu_index_size = dbg->de_debug_cu_index.dss_size;
    *debug_tu_index_size = dbg->de_debug_tu_index.dss_size;
    return DW_DLV_OK;
}

/*  Now with final sections new to DWARF5 (final) */
int
dwarf_get_section_max_offsets_d(Dwarf_Debug dbg,
    Dwarf_Unsigned * debug_info_size,
    Dwarf_Unsigned * debug_abbrev_size,
    Dwarf_Unsigned * debug_line_size,
    Dwarf_Unsigned * debug_loc_size,
    Dwarf_Unsigned * debug_aranges_size,
    Dwarf_Unsigned * debug_macinfo_size,
    Dwarf_Unsigned * debug_pubnames_size,
    Dwarf_Unsigned * debug_str_size,
    Dwarf_Unsigned * debug_frame_size,
    Dwarf_Unsigned * debug_ranges_size,
    Dwarf_Unsigned * debug_typenames_size,
    Dwarf_Unsigned * debug_types_size,
    Dwarf_Unsigned * debug_macro_size,
    Dwarf_Unsigned * debug_str_offsets_size,
    Dwarf_Unsigned * debug_sup_size,
    Dwarf_Unsigned * debug_cu_index_size,
    Dwarf_Unsigned * debug_tu_index_size,
    Dwarf_Unsigned * debug_names_size,
    Dwarf_Unsigned * debug_loclists_size,
    Dwarf_Unsigned * debug_rnglists_size)
{
    *debug_info_size = dbg->de_debug_info.dss_size;
    *debug_abbrev_size = dbg->de_debug_abbrev.dss_size;
    *debug_line_size = dbg->de_debug_line.dss_size;
    *debug_loc_size = dbg->de_debug_loc.dss_size;
    *debug_aranges_size = dbg->de_debug_aranges.dss_size;
    *debug_macinfo_size = dbg->de_debug_macinfo.dss_size;
    *debug_pubnames_size = dbg->de_debug_pubnames.dss_size;
    *debug_str_size = dbg->de_debug_str.dss_size;
    *debug_frame_size = dbg->de_debug_frame.dss_size;
    *debug_ranges_size = dbg->de_debug_ranges.dss_size;
    *debug_typenames_size = dbg->de_debug_typenames.dss_size;
    *debug_types_size = dbg->de_debug_types.dss_size;
    *debug_macro_size = dbg->de_debug_macro.dss_size;
    *debug_str_offsets_size = dbg->de_debug_str_offsets.dss_size;
    *debug_sup_size = dbg->de_debug_sup.dss_size;
    *debug_cu_index_size = dbg->de_debug_cu_index.dss_size;
    *debug_tu_index_size = dbg->de_debug_tu_index.dss_size;
    *debug_names_size = dbg->de_debug_names.dss_size;
    *debug_loclists_size = dbg->de_debug_loclists.dss_size;
    *debug_rnglists_size = dbg->de_debug_rnglists.dss_size;
    return DW_DLV_OK;
}

/*  Given a section name, get its size and address */
int
dwarf_get_section_info_by_name(Dwarf_Debug dbg,
    const char *section_name,
    Dwarf_Addr *section_addr,
    Dwarf_Unsigned *section_size,
    Dwarf_Error * error)
{
    struct Dwarf_Obj_Access_Section_s doas;
    struct Dwarf_Obj_Access_Interface_s * obj = 0;
    Dwarf_Unsigned section_count = 0;
    Dwarf_Half section_index = 0;

    *section_addr = 0;
    *section_size = 0;

    obj = dbg->de_obj_file;
    if (NULL == obj) {
        return DW_DLV_NO_ENTRY;
    }

    section_count = obj->methods->get_section_count(obj->object);

    /*  We can skip index 0 when considering ELF files, but not other
        object types. */
    for (section_index = 0; section_index < section_count;
        ++section_index) {
        int err = 0;
        int res = obj->methods->get_section_info(obj->object,
            section_index, &doas, &err);
        if (res == DW_DLV_ERROR) {
            DWARF_DBG_ERROR(dbg, err, DW_DLV_ERROR);
        }

        if (!strcmp(section_name,doas.name)) {
            *section_addr = doas.addr;
            *section_size = doas.size;
            return DW_DLV_OK;
        }
    }

    return DW_DLV_NO_ENTRY;
}

/*  Given a section index, get its size and address */
int
dwarf_get_section_info_by_index(Dwarf_Debug dbg,
    int section_index,
    const char **section_name,
    Dwarf_Addr *section_addr,
    Dwarf_Unsigned *section_size,
    Dwarf_Error * error)
{
    *section_addr = 0;
    *section_size = 0;
    *section_name = NULL;

    /* Check if we have a valid section index */
    if (section_index >= 0 && section_index < dwarf_get_section_count(dbg)) {
        int res = 0;
        int err = 0;
        struct Dwarf_Obj_Access_Section_s doas;
        struct Dwarf_Obj_Access_Interface_s * obj = dbg->de_obj_file;
        if (NULL == obj) {
            return DW_DLV_NO_ENTRY;
        }
        res = obj->methods->get_section_info(obj->object,
            section_index, &doas, &err);
        if (res == DW_DLV_ERROR){
            DWARF_DBG_ERROR(dbg, err, DW_DLV_ERROR);
        }

        *section_addr = doas.addr;
        *section_size = doas.size;
        *section_name = doas.name;
        return DW_DLV_OK;
    }
    return DW_DLV_NO_ENTRY;
}

/*  Get section count */
int
dwarf_get_section_count(Dwarf_Debug dbg)
{
    struct Dwarf_Obj_Access_Interface_s * obj = dbg->de_obj_file;
    if (NULL == obj) {
        /*  -1  */
        return DW_DLV_NO_ENTRY;
    }
    return obj->methods->get_section_count(obj->object);
}

Dwarf_Cmdline_Options dwarf_cmdline_options = {
    FALSE /* Use quiet mode by default. */
};

/* Lets libdwarf reflect a command line option, so we can get details
   of some errors printed using libdwarf-internal information. */
void
dwarf_record_cmdline_options(Dwarf_Cmdline_Options options)
{
    dwarf_cmdline_options = options;
}
