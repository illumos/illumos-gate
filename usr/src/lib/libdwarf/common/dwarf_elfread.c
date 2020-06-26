/*
Copyright (c) 2019, David Anderson
All rights reserved.
cc
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

/*  This file reads the parts of an Elf
    file appropriate to reading DWARF debugging data.
    Overview:
    _dwarf_elf_nlsetup() Does all elf setup.
        calls _dwarf_elf_access_init()
            calls _dwarf_elf_object_access_internals_init()
                Creates internals record 'M',
                    dwarf_elf_object_access_internals_t
                Sets flags/data in internals record
                Loads elf object data needed later.
                Sets methods struct to access elf object.
        calls _dwarf_object_init_b() Creates Dwarf_Debug, independent
            of any elf code.
        Sets internals record into dbg.
    ----------------------
    _dwarf_destruct_elf_nlaccess(). This frees
        the elf internals record created in
        _dwarf_elf_object_access_internals_init()
        in case of errors during setup or when
        dwarf_finish() is called.  Works safely for
        partially or fully set-up elf internals record.

    Other than in _dwarf_elf_nlsetup() the elf code
    knows nothing about Dwarf_Debug, and the rest of
    libdwarf knows nothing about the content of the
    object-type-specific (for Elf here)
    internals record.
*/

#include "config.h"
#include <stdio.h>
#ifdef HAVE_MALLOC_H
/* Useful include for some Windows compilers. */
#include <malloc.h>
#endif /* HAVE_MALLOC_H */
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif /* HAVE_STDLIB_H */
#include <string.h>
#include <stdlib.h>
#include <sys/types.h> /* open() */
#include <sys/stat.h> /* open() */
#include <fcntl.h> /* open() */
#include <time.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h> /* lseek read close */
#elif defined(_WIN32) && defined(_MSC_VER)
#include <io.h>
#endif /* HAVE_UNISTD_H */

/* Windows specific header files */
#if defined(_WIN32) && defined(HAVE_STDAFX_H)
#include "stdafx.h"
#endif /* HAVE_STDAFX_H */

#include "libdwarf.h"
#include "libdwarfdefs.h"
#include "dwarf_base_types.h"
#include "dwarf_opaque.h"
#include "dwarf_error.h" /* for _dwarf_error() declaration */
#include "dwarf_reading.h"
#include "memcpy_swap.h"
#include "dwarf_object_read_common.h"
#include "dwarf_object_detector.h"
#include "dwarf_elfstructs.h"
#include "dwarf_elf_defines.h"
#include "dwarf_elf_rel_detector.h"
#include "dwarf_elfread.h"


#ifndef TYP
#define TYP(n,l) char n[l]
#endif /* TYPE */

#ifdef WORDS_BIGENDIAN
#define READ_UNALIGNED_SAFE(dbg,dest, source, length) \
    do {                                             \
        Dwarf_Unsigned _ltmp = 0;                    \
        dbg->de_copy_word( (((char *)(&_ltmp)) +     \
            sizeof(_ltmp) - length),source, length); \
        dest = _ltmp;                                \
    } while (0)

#define WRITE_UNALIGNED_LOCAL(dbg,dest,source, srclength,len_out) \
    {                                             \
        dbg->de_copy_word(dest,                   \
            ((char *)source) +srclength-len_out,  \
            len_out) ;                            \
    }
#else /* LITTLE ENDIAN */
#define READ_UNALIGNED_SAFE(dbg,dest, source, srclength) \
    do  {                                     \
        Dwarf_Unsigned _ltmp = 0;             \
        dbg->de_copy_word( (char *)(&_ltmp),  \
            source, srclength) ;              \
        dest = _ltmp;                         \
    } while (0)

#define WRITE_UNALIGNED_LOCAL(dbg,dest,source, srclength,len_out) \
    {                               \
        dbg->de_copy_word( (dest) , \
            ((char *)source) ,      \
            len_out) ;              \
    }
#endif /* *-ENDIAN */


#ifdef WORDS_BIGENDIAN
#define ASNAR(func,t,s)                         \
    do {                                        \
        unsigned tbyte = sizeof(t) - sizeof(s); \
        t = 0;                                  \
        func(((char *)&t)+tbyte ,&s[0],sizeof(s));  \
    } while (0)
#else /* LITTLE ENDIAN */
#define ASNAR(func,t,s)                         \
    do {                                        \
        t = 0;                                  \
        func(&t,&s[0],sizeof(s));               \
    } while (0)
#endif /* end LITTLE- BIG-ENDIAN */


static int
_dwarf_elf_object_access_init(
    int  fd,
    unsigned ftype,
    unsigned endian,
    unsigned offsetsize,
    size_t filesize,
    Dwarf_Unsigned access,
    Dwarf_Obj_Access_Interface **binary_interface,
    int *localerrnum);


static Dwarf_Endianness elf_get_nolibelf_byte_order (void *obj)
{
    dwarf_elf_object_access_internals_t *elf =
        (dwarf_elf_object_access_internals_t*)(obj);
    return elf->f_endian;
}


static Dwarf_Small elf_get_nolibelf_length_size (void *obj)
{
    dwarf_elf_object_access_internals_t *elf =
        (dwarf_elf_object_access_internals_t*)(obj);
    return elf->f_offsetsize/8;
}


static Dwarf_Small elf_get_nolibelf_pointer_size (void *obj)
{
    dwarf_elf_object_access_internals_t *elf =
        (dwarf_elf_object_access_internals_t*)(obj);
    return elf->f_pointersize/8;
}


static Dwarf_Unsigned elf_get_nolibelf_section_count (void *obj)
{
    dwarf_elf_object_access_internals_t *elf =
        (dwarf_elf_object_access_internals_t*)(obj);
    return elf->f_loc_shdr.g_count;
}

static int elf_get_nolibelf_section_info (void *obj,
    Dwarf_Half section_index,
    Dwarf_Obj_Access_Section *return_section,
    UNUSEDARG int *error)
{
    dwarf_elf_object_access_internals_t *elf =
        (dwarf_elf_object_access_internals_t*)(obj);


    if (section_index < elf->f_loc_shdr.g_count) {
        struct generic_shdr *sp = 0;

        sp = elf->f_shdr + section_index;
        return_section->addr      = sp->gh_addr;
        return_section->type      = sp->gh_type;
        return_section->size      = sp->gh_size;
        return_section->name      = sp->gh_namestring;
        return_section->link      = sp->gh_link;
        return_section->info      = sp->gh_info;
        return_section->entrysize = sp->gh_entsize;
        return DW_DLV_OK;
    }
    return DW_DLV_NO_ENTRY;
}

static int
elf_load_nolibelf_section (void *obj, Dwarf_Half section_index,
    Dwarf_Small **return_data, int *error)
{
    dwarf_elf_object_access_internals_t *elf =
        (dwarf_elf_object_access_internals_t*)(obj);

    if (0 < section_index &&
        section_index < elf->f_loc_shdr.g_count) {
        int res = 0;

        struct generic_shdr *sp =
            elf->f_shdr + section_index;
        if (sp->gh_content) {
            *return_data = (Dwarf_Small *)sp->gh_content;
            return DW_DLV_OK;
        }
        if (!sp->gh_size) {
            return DW_DLV_NO_ENTRY;
        }
        if ((sp->gh_size + sp->gh_offset) >
            elf->f_filesize) {
            *error = DW_DLE_ELF_SECTION_ERROR;
            return DW_DLV_ERROR;
        }

        sp->gh_content = malloc((size_t)sp->gh_size);
        if(!sp->gh_content) {
            *error = DW_DLE_ALLOC_FAIL;
            return DW_DLV_ERROR;
        }
        res = RRMOA(elf->f_fd,
            sp->gh_content, (off_t)sp->gh_offset,
            (size_t)sp->gh_size, (off_t)elf->f_filesize, error);
        if (res != DW_DLV_OK) {
            free(sp->gh_content);
            sp->gh_content = 0;
            return res;
        }
        *return_data = (Dwarf_Small *)sp->gh_content;
        return DW_DLV_OK;
    }
    return DW_DLV_NO_ENTRY;
}

static int
_dwarf_get_elf_flags_func_nl(
    void* obj_in,
    Dwarf_Half section_index,
    Dwarf_Unsigned *flags_out,
    Dwarf_Unsigned *addralign_out,
    int *error)
{
    dwarf_elf_object_access_internals_t *ep = 0;
    struct generic_shdr *shp = 0;

    ep = (dwarf_elf_object_access_internals_t *)obj_in;
    if (section_index == 0) {
        /*  Nothing to do. Empty section */
        return DW_DLV_OK;
    }
    if (section_index >= ep->f_loc_shdr.g_count) {
        *error = DW_DLE_SECTION_INDEX_BAD;
        return DW_DLV_ERROR;
    }
    shp = ep->f_shdr + section_index;
    *flags_out = shp->gh_flags;
    *addralign_out = shp->gh_addralign;
    return DW_DLV_OK;
}


#define MATCH_REL_SEC(i_,s_,r_)  \
if (i_ == s_.dss_index) { \
    *r_ = &s_;            \
    return DW_DLV_OK;    \
}

static int
find_section_to_relocate(Dwarf_Debug dbg,Dwarf_Half section_index,
   struct Dwarf_Section_s **relocatablesec, int *error)
{
    MATCH_REL_SEC(section_index,dbg->de_debug_info,relocatablesec);
    MATCH_REL_SEC(section_index,dbg->de_debug_abbrev,relocatablesec);
    MATCH_REL_SEC(section_index,dbg->de_debug_line,relocatablesec);
    MATCH_REL_SEC(section_index,dbg->de_debug_loc,relocatablesec);
    MATCH_REL_SEC(section_index,dbg->de_debug_aranges,relocatablesec);
    MATCH_REL_SEC(section_index,dbg->de_debug_macinfo,relocatablesec);
    MATCH_REL_SEC(section_index,dbg->de_debug_pubnames,relocatablesec);
    MATCH_REL_SEC(section_index,dbg->de_debug_ranges,relocatablesec);
    MATCH_REL_SEC(section_index,dbg->de_debug_frame,relocatablesec);
    MATCH_REL_SEC(section_index,dbg->de_debug_frame_eh_gnu,relocatablesec);
    MATCH_REL_SEC(section_index,dbg->de_debug_pubtypes,relocatablesec);
    MATCH_REL_SEC(section_index,dbg->de_debug_funcnames,relocatablesec);
    MATCH_REL_SEC(section_index,dbg->de_debug_typenames,relocatablesec);
    MATCH_REL_SEC(section_index,dbg->de_debug_varnames,relocatablesec);
    MATCH_REL_SEC(section_index,dbg->de_debug_weaknames,relocatablesec);
    MATCH_REL_SEC(section_index,dbg->de_debug_types,relocatablesec);
    MATCH_REL_SEC(section_index,dbg->de_debug_macro,relocatablesec);
    MATCH_REL_SEC(section_index,dbg->de_debug_rnglists,relocatablesec);
    MATCH_REL_SEC(section_index,dbg->de_debug_loclists,relocatablesec);
    MATCH_REL_SEC(section_index,dbg->de_debug_aranges,relocatablesec);
    MATCH_REL_SEC(section_index,dbg->de_debug_sup,relocatablesec);
    MATCH_REL_SEC(section_index,dbg->de_debug_str_offsets,relocatablesec);
    MATCH_REL_SEC(section_index,dbg->de_debug_addr,relocatablesec);
    /* dbg-> de_debug_tu_index,reloctablesec); */
    /* dbg-> de_debug_cu_index,reloctablesec); */
    /* dbg-> de_debug_gdbindex,reloctablesec); */
    /* dbg-> de_debug_str,syms); */
    /* de_elf_symtab,syms); */
    /* de_elf_strtab,syms); */
    *error = DW_DLE_RELOC_SECTION_MISMATCH;
    return DW_DLV_ERROR;
}


/*  Returns DW_DLV_OK if it works, else DW_DLV_ERROR.
    The caller may decide to ignore the errors or report them. */
static int
update_entry(Dwarf_Debug dbg,
    dwarf_elf_object_access_internals_t*obj,
    struct generic_rela *rela,
    Dwarf_Small *target_section,
    Dwarf_Unsigned target_section_size,
    int *error)
{
    unsigned int type = 0;
    unsigned int sym_idx = 0;
    Dwarf_Unsigned offset = 0;
    Dwarf_Signed addend = 0;
    Dwarf_Unsigned reloc_size = 0;
    Dwarf_Half machine  = obj->f_machine;
    struct generic_symentry *symp = 0;
    int is_rela = rela->gr_is_rela;

    offset = rela->gr_offset;
    addend = rela->gr_addend;
    type = (unsigned int)rela->gr_type;
    sym_idx = (unsigned int)rela->gr_sym;
    if (sym_idx >= obj->f_loc_symtab.g_count) {
        *error = DW_DLE_RELOC_SECTION_SYMBOL_INDEX_BAD;
        return DW_DLV_ERROR;
    }
    symp = obj->f_symtab + sym_idx;
    if (offset >= target_section_size) {
        /*  If offset really big, any add will overflow.
            So lets stop early if offset is corrupt. */
        *error = DW_DLE_RELOC_INVALID;
        return DW_DLV_ERROR;
    }

    /* Determine relocation size */
    if (_dwarf_is_32bit_abs_reloc(type, machine)) {
        reloc_size = 4;
    } else if (_dwarf_is_64bit_abs_reloc(type, machine)) {
        reloc_size = 8;
    } else {
        *error = DW_DLE_RELOC_SECTION_RELOC_TARGET_SIZE_UNKNOWN;
        return DW_DLV_ERROR;
    }
    if ( (offset + reloc_size) < offset) {
        /* Another check for overflow. */
        *error = DW_DLE_RELOC_INVALID;
        return DW_DLV_ERROR;
    }
    if ( (offset + reloc_size) > target_section_size) {
        *error = DW_DLE_RELOC_INVALID;
        return DW_DLV_ERROR;
    }
    /*  Assuming we do not need to do a READ_UNALIGNED here
        at target_section + offset and add its value to
        outval.  Some ABIs say no read (for example MIPS),
        but if some do then which ones? */
    {   /* .rel. (addend is 0), or .rela. */
        Dwarf_Small *targ = target_section+offset;
        Dwarf_Unsigned presentval = 0;
        Dwarf_Unsigned outval = 0;
        /*  See also: READ_UNALIGNED_SAFE in
            dwarf_elf_access.c  */

        if (!is_rela) {
            READ_UNALIGNED_SAFE(dbg,presentval,
                targ,reloc_size);
        }
        /*  There is no addend in .rel.
            Normally presentval is correct
            and st_value will be zero.
            But a few compilers have
            presentval zero and st_value set. */
        outval = presentval + symp->gs_value + addend;
        WRITE_UNALIGNED_LOCAL(dbg,targ,
            &outval,sizeof(outval),reloc_size);
    }
    return DW_DLV_OK;
}



/*  Somewhat arbitrarily, we attempt to apply all the
    relocations we can
    and still notify the caller of at least one error if we found
    any errors.  */

static int
apply_rela_entries(
    Dwarf_Debug dbg,
    /* Section_index of the relocation section, .rela entries  */
    Dwarf_Half r_section_index,
    dwarf_elf_object_access_internals_t*obj,
    /* relocatablesec is the .debug_info(etc)  in Dwarf_Debug */
    struct Dwarf_Section_s * relocatablesec,
    int *error)
{
    int return_res = DW_DLV_OK;
    struct generic_shdr * rels_shp = 0;
    Dwarf_Unsigned relcount;
    Dwarf_Unsigned i = 0;

    if (r_section_index >= obj->f_loc_shdr.g_count) {
        *error = DW_DLE_SECTION_INDEX_BAD;
        return DW_DLV_ERROR;
    }
    rels_shp = obj->f_shdr + r_section_index;
    relcount = rels_shp->gh_relcount;
    if (!relcount) {
        /*  Nothing to do. */
        return DW_DLV_OK;
    }
    if (!rels_shp->gh_rels) {
        /*  something wrong. */
        *error = DW_DLE_RELOCS_ERROR;
        return DW_DLV_ERROR;
    }
    for (i = 0; i < relcount; i++) {
        int res = update_entry(dbg,obj,
            rels_shp->gh_rels+i,
            relocatablesec->dss_data,
            relocatablesec->dss_size,
            error);
        if (res != DW_DLV_OK) {
            /* We try to keep going, not stop. */
            return_res = res;
        }
    }
    return return_res;
}

/*  Find the section data in dbg and find all the relevant
    sections.  Then do relocations.

    section_index is the index of a .debug_info (for example)
    so we have to find the section(s) with relocations
    targeting section_index.
    Normally there is exactly one such, though.
*/
static int
elf_relocations_nolibelf(void* obj_in,
    Dwarf_Half section_index,
    Dwarf_Debug dbg,
    int* error)
{
    int res = DW_DLV_ERROR;
    dwarf_elf_object_access_internals_t*obj = 0;
    struct Dwarf_Section_s * relocatablesec = 0;
    unsigned section_with_reloc_records = 0;

    if (section_index == 0) {
        return DW_DLV_NO_ENTRY;
    }
    obj = (dwarf_elf_object_access_internals_t*)obj_in;

    /*  The section to relocate must already be loaded into memory.
        This just turns section_index into a pointer
        to a de_debug_info or other  section record in
        Dwarf_Debug. */
    res = find_section_to_relocate(dbg, section_index,
        &relocatablesec, error);
    if (res != DW_DLV_OK) {
        return res;
    }
    /*  Now we know the  Dwarf_Section_s section
        we need to relocate.
        So lets find the rela section(s) targeting this.
    */

    /*  Sun and possibly others do not always set
        sh_link in .debug_* sections.
        So we cannot do full  consistency checks.
        FIXME: This approach assumes there is only one
        relocation section applying to section section_index! */
    section_with_reloc_records = relocatablesec->dss_reloc_index;
    if (!section_with_reloc_records) {
        /* Something is wrong. */
        *error = DW_DLE_RELOC_SECTION_MISSING_INDEX;
        return DW_DLV_ERROR;
    }
    /* The relocations, if they exist, have been loaded. */
    /* The symtab was already loaded. */
    if (!obj->f_symtab || !obj->f_symtab_sect_strings) {
        *error = DW_DLE_DEBUG_SYMTAB_ERR;
        return DW_DLV_ERROR;
    }
    if (obj->f_symtab_sect_index != relocatablesec->dss_reloc_link) {
        /* Something is wrong. */
        *error = DW_DLE_RELOC_MISMATCH_RELOC_INDEX;
        return DW_DLV_ERROR;
    }
    /* We have all the data we need in memory. */
    /*  Now we apply the relocs in section_with_reloc_records to the
        target, relocablesec */
    res = apply_rela_entries(dbg,section_with_reloc_records,
        obj, relocatablesec,error);
    return res;
}

void
_dwarf_destruct_elf_nlaccess(
    struct Dwarf_Obj_Access_Interface_s *aip)
{
    dwarf_elf_object_access_internals_t *ep = 0;
    struct generic_shdr *shp = 0;
    Dwarf_Unsigned shcount = 0;
    Dwarf_Unsigned i = 0;

    ep = (dwarf_elf_object_access_internals_t *)aip->object;
    free(ep->f_ehdr);
    shp = ep->f_shdr;
    shcount = ep->f_loc_shdr.g_count;
    for(i = 0; i < shcount; ++i,++shp) {
        free(shp->gh_rels);
        shp->gh_rels = 0;
        free(shp->gh_content);
        shp->gh_content = 0;
        free(shp->gh_sht_group_array);
        shp->gh_sht_group_array = 0;
        shp->gh_sht_group_array_count = 0;
    }
    free(ep->f_shdr);
    ep->f_loc_shdr.g_count = 0;
    free(ep->f_phdr);
    free(ep->f_elf_shstrings_data);
    free(ep->f_dynamic);
    free(ep->f_symtab_sect_strings);
    free(ep->f_dynsym_sect_strings);
    free(ep->f_symtab);
    free(ep->f_dynsym);

    /* if TRUE close f_fd on destruct.*/
    if (ep->f_destruct_close_fd) {
        close(ep->f_fd);
    }
    ep->f_ident[0] = 'X';
    free(ep->f_path);
    free(ep);
    free(aip);
}


int
_dwarf_elf_nlsetup(int fd,
    char *true_path,
    unsigned ftype,
    unsigned endian,
    unsigned offsetsize,
    size_t filesize,
    Dwarf_Unsigned access,
    unsigned groupnumber,
    Dwarf_Handler errhand,
    Dwarf_Ptr errarg,
    Dwarf_Debug *dbg,Dwarf_Error *error)
{
    Dwarf_Obj_Access_Interface *binary_interface = 0;
    dwarf_elf_object_access_internals_t *intfc = 0;
    int res = DW_DLV_OK;
    int localerrnum = 0;

    res = _dwarf_elf_object_access_init(
        fd,
        ftype,endian,offsetsize,filesize,access,
        &binary_interface,
        &localerrnum);
    if (res != DW_DLV_OK) {
        if (res == DW_DLV_NO_ENTRY) {
            return res;
        }
        _dwarf_error(NULL, error, localerrnum);
        return DW_DLV_ERROR;
    }
    /*  allocates and initializes Dwarf_Debug,
        generic code */
    res = dwarf_object_init_b(binary_interface, errhand, errarg,
        groupnumber, dbg, error);
    if (res != DW_DLV_OK){
        _dwarf_destruct_elf_nlaccess(binary_interface);
        return res;
    }
    intfc = binary_interface->object;
    intfc->f_path = strdup(true_path);
    return res;
}

/*  dwarf_elf_access method table for use with non-libelf.
    See also the methods table in dwarf_elf_access.c for libelf.
*/
static Dwarf_Obj_Access_Methods const elf_nlmethods = {
    elf_get_nolibelf_section_info,
    elf_get_nolibelf_byte_order,
    elf_get_nolibelf_length_size,
    elf_get_nolibelf_pointer_size,
    elf_get_nolibelf_section_count,
    elf_load_nolibelf_section,
    elf_relocations_nolibelf
};

/*  On any error this frees internals argument. */
static int
_dwarf_elf_object_access_internals_init(
    dwarf_elf_object_access_internals_t * internals,
    int  fd,
    unsigned ftype,
    unsigned endian,
    unsigned offsetsize,
    size_t filesize,
    UNUSEDARG Dwarf_Unsigned access,
    int *errcode)
{
    dwarf_elf_object_access_internals_t * intfc = internals;
    Dwarf_Unsigned i  = 0;
    struct Dwarf_Obj_Access_Interface_s *localdoas;
    int res = 0;

    /*  Must malloc as _dwarf_destruct_elf_access()
        forces that due to other uses. */
    localdoas = (struct Dwarf_Obj_Access_Interface_s *)
        malloc(sizeof(struct Dwarf_Obj_Access_Interface_s));
    if (!localdoas) {
        free(internals);
        *errcode = DW_DLE_ALLOC_FAIL;
        return DW_DLV_ERROR;
    }
    memset(localdoas,0,sizeof(struct Dwarf_Obj_Access_Interface_s));
    /*  E is used with libelf. F with this elf reader. */
    intfc->f_ident[0]    = 'F';
    intfc->f_ident[1]    = '1';
    intfc->f_fd          = fd;
    intfc->f_is_64bit    = ((offsetsize==64)?TRUE:FALSE);
    intfc->f_offsetsize  = offsetsize;
    intfc->f_pointersize = offsetsize;
    intfc->f_filesize    = filesize;
    intfc->f_ftype       = ftype;
    intfc->f_destruct_close_fd = FALSE;

#ifdef WORDS_BIGENDIAN
    if (endian == DW_ENDIAN_LITTLE ) {
        intfc->f_copy_word = _dwarf_memcpy_swap_bytes;
        intfc->f_endian = DW_OBJECT_LSB;
    } else {
        intfc->f_copy_word = _dwarf_memcpy_noswap_bytes;
        intfc->f_endian = DW_OBJECT_MSB;
    }
#else  /* LITTLE ENDIAN */
    if (endian == DW_ENDIAN_LITTLE ) {
        intfc->f_copy_word = _dwarf_memcpy_noswap_bytes;
        intfc->f_endian = DW_OBJECT_LSB;
    } else {
        intfc->f_copy_word = _dwarf_memcpy_swap_bytes;
        intfc->f_endian = DW_OBJECT_MSB;
    }
#endif /* LITTLE- BIG-ENDIAN */
    _dwarf_get_elf_flags_func_ptr = _dwarf_get_elf_flags_func_nl;
    /*  The following sets f_machine. */
    res = _dwarf_load_elf_header(intfc,errcode);
    if (res != DW_DLV_OK) {
        localdoas->object = intfc;
        localdoas->methods = 0;
        _dwarf_destruct_elf_nlaccess(localdoas);
        localdoas = 0;
        return res;
    }
    /* Not loading progheaders */
    res = _dwarf_load_elf_sectheaders(intfc,errcode);
    if (res != DW_DLV_OK) {
        localdoas->object = intfc;
        localdoas->methods = 0;
        _dwarf_destruct_elf_nlaccess(localdoas);
        localdoas = 0;
        return res;
    }
    /* We are not looking at symbol strings for now. */
    res = _dwarf_load_elf_symstr(intfc,errcode);
    if (res == DW_DLV_ERROR) {
        localdoas->object = intfc;
        localdoas->methods = 0;
        _dwarf_destruct_elf_nlaccess(localdoas);
        localdoas = 0;
        return res;
    }
    res  = _dwarf_load_elf_symtab_symbols(intfc,errcode);
    if (res == DW_DLV_ERROR) {
        localdoas->object = intfc;
        localdoas->methods = 0;
        _dwarf_destruct_elf_nlaccess(localdoas);
        localdoas = 0;
        return res;
    }
    for ( i = 1; i < intfc->f_loc_shdr.g_count; ++i) {
        struct generic_shdr *shp = 0;
        Dwarf_Unsigned section_type = 0;
        enum RelocRela localrel = RelocIsRela;

        shp = intfc->f_shdr +i;
        section_type = shp->gh_type;
        if (section_type == SHT_REL ||
            (!strncmp(".rel.",shp->gh_namestring,5))) {
            localrel = RelocIsRel;
        } else if (section_type == SHT_RELA ||
            (!strncmp(".rela.",shp->gh_namestring,6))) {
            localrel = RelocIsRela;
        } else {
            continue;
        }
        /*  ASSERT: local rel is either RelocIsRel or
            RelocIsRela. Never any other value. */
        /*  Possibly we should check if the target section
            is one we care about before loading rela
            FIXME */
        res = _dwarf_load_elf_relx(intfc,i,localrel,errcode);
        if (res == DW_DLV_ERROR) {
            localdoas->object = intfc;
            localdoas->methods = 0;
            _dwarf_destruct_elf_nlaccess(localdoas);
            localdoas = 0;
            return res;
        }
    }
    free(localdoas);
    localdoas = 0;
    return DW_DLV_OK;
}


static int
_dwarf_elf_object_access_init(
    int  fd,
    unsigned ftype,
    unsigned endian,
    unsigned offsetsize,
    size_t filesize,
    Dwarf_Unsigned access,
    Dwarf_Obj_Access_Interface **binary_interface,
    int *localerrnum)
{

    int res = 0;
    dwarf_elf_object_access_internals_t *internals = 0;
    Dwarf_Obj_Access_Interface *intfc = 0;

    internals = malloc(sizeof(dwarf_elf_object_access_internals_t));
    if (!internals) {
        *localerrnum = DW_DLE_ALLOC_FAIL;
        /* Impossible case, we hope. Give up. */
        return DW_DLV_ERROR;
    }
    memset(internals,0,sizeof(*internals));
    res = _dwarf_elf_object_access_internals_init(internals,
        fd,
        ftype, endian, offsetsize, filesize,
        access,
        localerrnum);
    if (res != DW_DLV_OK){
        return res;
    }

    intfc = malloc(sizeof(Dwarf_Obj_Access_Interface));
    if (!intfc) {
        /* Impossible case, we hope. Give up. */
        free(internals);
        *localerrnum = DW_DLE_ALLOC_FAIL;
        return DW_DLV_ERROR;
    }
    /* Initialize the interface struct */
    intfc->object = internals;
    intfc->methods = &elf_nlmethods;
    *binary_interface = intfc;
    return DW_DLV_OK;
}
