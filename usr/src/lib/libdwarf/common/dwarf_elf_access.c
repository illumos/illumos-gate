/*
  Copyright (C) 2000-2005 Silicon Graphics, Inc.  All Rights Reserved.
  Portions Copyright 2007-2010 Sun Microsystems, Inc. All rights reserved.
  Portions Copyright 2008-2010 Arxan Technologies, Inc. All Rights Reserved.
  Portions Copyright 2009-2019 David Anderson. All rights reserved.
  Portions Copyright 2009-2010 Novell Inc. All rights reserved.
  Portions Copyright 2012 SN Systems Ltd. All rights reserved.

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

/*  This file is ONLY used for libelf and with libelf
    For */

#include "config.h"
#ifdef DWARF_WITH_LIBELF
#include "dwarf_incl.h"
#include "dwarf_error.h"
#include "dwarf_elf_access.h"
#include "dwarf_elf_rel_detector.h"

/* Include the ELF definitions depending on system headers if any. */
#include "dwarf_elf_defines.h"

#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h> /* for close */
#endif /* HAVE_UNISTD_H */
#include <string.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif /* HAVE_STDLIB_H */
#ifdef HAVE_MALLOC_H
/* Useful include for some Windows compilers. */
#include <malloc.h>
#endif /* HAVE_MALLOC_H */

#define FALSE 0
#define TRUE  1

#ifdef HAVE_ELF64_GETEHDR
extern Elf64_Ehdr *elf64_getehdr(Elf *);
#endif
#ifdef HAVE_ELF64_GETSHDR
extern Elf64_Shdr *elf64_getshdr(Elf_Scn *);
#endif

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



/*   ident[0] == 'E' for elf when using libelf. ident[1] = 1 */
typedef struct {
    char             ident[8];
    const char *     path;
    int              is_64bit;
    Dwarf_Small      length_size;
    Dwarf_Small      pointer_size;
    Dwarf_Unsigned   section_count;
    Dwarf_Endianness endianness;
    Dwarf_Small      machine;
    char             libdwarf_owns_elf;
    dwarf_elf_handle elf;

    Elf32_Ehdr *ehdr32;
#ifdef HAVE_ELF64_GETEHDR
    Elf64_Ehdr *ehdr64;
#endif
    /*  Elf symtab and its strtab.  Initialized at first
        call to do relocations, the actual data is in the Dwarf_Debug
        struct, not allocated locally here. */
    struct Dwarf_Section_s *symtab;
    struct Dwarf_Section_s *strtab;

} dwarf_elf_object_access_internals_t;

/*  Using this for rel and rela.
    For Rel, r_addend is left zero and not used.
*/
struct Dwarf_Elf_Rela {
    Dwarf_Unsigned r_offset;
    /*Dwarf_Unsigned r_info; */
    Dwarf_Unsigned r_type;
    Dwarf_Unsigned r_symidx;
    Dwarf_Unsigned r_addend;
    /* if is_rela is non-zero r_addend is meaningless */
    char  r_is_rela;
};


static int dwarf_elf_object_access_load_section(void* obj_in,
    Dwarf_Half section_index,
    Dwarf_Small** section_data,
    int* error);

/*  dwarf_elf_object_access_internals_init()
    On error, set *error with libdwarf error code.
*/
static int
dwarf_elf_object_access_internals_init(void* obj_in,
    dwarf_elf_handle elf,
    int* error)
{
    dwarf_elf_object_access_internals_t*obj =
        (dwarf_elf_object_access_internals_t*)obj_in;
    char *ehdr_ident = 0;
    Dwarf_Half machine = 0;
    obj->elf = elf;

    if ((ehdr_ident = elf_getident(elf, NULL)) == NULL) {
        *error = DW_DLE_ELF_GETIDENT_ERROR;
        return DW_DLV_ERROR;
    }

    obj->is_64bit = (ehdr_ident[EI_CLASS] == ELFCLASS64);


    if (ehdr_ident[EI_DATA] == ELFDATA2LSB){
        obj->endianness = DW_OBJECT_LSB;
    } else if (ehdr_ident[EI_DATA] == ELFDATA2MSB){
        obj->endianness = DW_OBJECT_MSB;
    }

    if (obj->is_64bit) {
#ifdef HAVE_ELF64_GETEHDR
        obj->ehdr64 = elf64_getehdr(elf);
        if (obj->ehdr64 == NULL) {
            *error = DW_DLE_ELF_GETEHDR_ERROR;
            return DW_DLV_ERROR;
        }
        obj->section_count = obj->ehdr64->e_shnum;
        machine = obj->ehdr64->e_machine;
        obj->machine = machine;
#else
        *error = DW_DLE_NO_ELF64_SUPPORT;
        return DW_DLV_ERROR;
#endif
    } else {
        obj->ehdr32 = elf32_getehdr(elf);
        if (obj->ehdr32 == NULL) {
            *error = DW_DLE_ELF_GETEHDR_ERROR;
            return DW_DLV_ERROR;
        }
        obj->section_count = obj->ehdr32->e_shnum;
        machine = obj->ehdr32->e_machine;
        obj->machine = machine;
    }

    /*  The following length_size is Not Too Significant. Only used
        one calculation, and an approximate one at that. */
    obj->length_size = obj->is_64bit ? 8 : 4;
    obj->pointer_size = obj->is_64bit ? 8 : 4;
    obj->ident[0] = 'E';
    obj->ident[1] = 1;

#ifdef _WIN32
    if (obj->is_64bit && machine == EM_PPC64) {
        /*  The SNC compiler generates the EM_PPC64 machine type for the
            PS3 platform, but is a 32 bits pointer size in user mode. */
        obj->pointer_size = 4;
    }
#endif /* _WIN32 */

    if (obj->is_64bit && machine != EM_MIPS) {
        /*  MIPS/IRIX makes pointer size and length size 8 for -64.
            Other platforms make length 4 always. */
        /*  4 here supports 32bit-offset dwarf2, as emitted by cygnus
            tools, and the dwarfv2.1 64bit extension setting.
            This is not the same as the size-of-an-offset, which
            is 4 in 32bit dwarf and 8 in 64bit dwarf.  */
        obj->length_size = 4;
    }
    return DW_DLV_OK;
}

/* dwarf_elf_object_access_get_byte_order */
static
Dwarf_Endianness
dwarf_elf_object_access_get_byte_order(void* obj_in)
{
    dwarf_elf_object_access_internals_t*obj =
        (dwarf_elf_object_access_internals_t*)obj_in;
    return obj->endianness;
}

/* dwarf_elf_object_access_get_section_count() */
static
Dwarf_Unsigned
dwarf_elf_object_access_get_section_count(void * obj_in)
{
    dwarf_elf_object_access_internals_t*obj =
        (dwarf_elf_object_access_internals_t*)obj_in;
    return obj->section_count;
}


static int
_dwarf_get_elf_flags_func(
    void* obj_in,
    Dwarf_Half section_index,
    Dwarf_Unsigned *flags_out,
    Dwarf_Unsigned *addralign_out,
    int *error)
{
   dwarf_elf_object_access_internals_t*obj =
        (dwarf_elf_object_access_internals_t*)obj_in;

    Elf32_Shdr *shdr32 = 0;

#ifdef HAVE_ELF64_GETSHDR
    Elf64_Shdr *shdr64 = 0;
#endif
    Elf_Scn *scn = 0;


    scn = elf_getscn(obj->elf, section_index);
    if (scn == NULL) {
        *error = DW_DLE_MDE;
        return DW_DLV_ERROR;
    }
    if (obj->is_64bit) {
#ifdef HAVE_ELF64_GETSHDR
        shdr64 = elf64_getshdr(scn);
        if (shdr64 == NULL) {
            *error = DW_DLE_ELF_GETSHDR_ERROR;
            return DW_DLV_ERROR;
        }

        /*  Get also section 'sh_type' and sh_info' fields, so the caller
            can use it for additional tasks that require that info. */
        *flags_out = shdr64->sh_flags;
        *addralign_out = shdr64->sh_addralign;
        return DW_DLV_OK;
#else
        *error = DW_DLE_MISSING_ELF64_SUPPORT;
        return DW_DLV_ERROR;
#endif /* HAVE_ELF64_GETSHDR */
    }
    if ((shdr32 = elf32_getshdr(scn)) == NULL) {
        *error = DW_DLE_ELF_GETSHDR_ERROR;
        return DW_DLV_ERROR;
    }

    /*  Get also the section type, so the caller can use it for
        additional tasks that require to know the section type. */
    *flags_out = shdr32->sh_flags;
    *addralign_out = shdr32->sh_addralign;
    return DW_DLV_OK;
}


/*  dwarf_elf_object_access_get_section()

    If writing a function vaguely like this for a non-elf object,
    be sure that when section-index is passed in as zero that
    you set the fields in *ret_scn_doas to reflect an empty section
    with an empty string as the section name.  Adjust your
    section indexes of your non-elf-reading-code
    for all the necessary functions in Dwarf_Obj_Access_Methods_s
    accordingly.

    Should have gotten sh_flags, sh_addralign too.
    But Dwarf_Obj_Access_Section is publically defined so changing
    it is quite painful for everyone.
*/
static
int
dwarf_elf_object_access_get_section_info(
    void* obj_in,
    Dwarf_Half section_index,
    Dwarf_Obj_Access_Section* ret_scn_doas,
    int* error)
{
    dwarf_elf_object_access_internals_t*obj =
        (dwarf_elf_object_access_internals_t*)obj_in;

    Elf32_Shdr *shdr32 = 0;

#ifdef HAVE_ELF64_GETSHDR
    Elf64_Shdr *shdr64 = 0;
#endif
    Elf_Scn *scn = 0;


    scn = elf_getscn(obj->elf, section_index);
    if (scn == NULL) {
        *error = DW_DLE_MDE;
        return DW_DLV_ERROR;
    }
    if (obj->is_64bit) {
#ifdef HAVE_ELF64_GETSHDR
        shdr64 = elf64_getshdr(scn);
        if (shdr64 == NULL) {
            *error = DW_DLE_ELF_GETSHDR_ERROR;
            return DW_DLV_ERROR;
        }

        /*  Get also section 'sh_type' and sh_info' fields, so the caller
            can use it for additional tasks that require that info. */
        ret_scn_doas->type = shdr64->sh_type;
        ret_scn_doas->size = shdr64->sh_size;
        ret_scn_doas->addr = shdr64->sh_addr;
        ret_scn_doas->link = shdr64->sh_link;
        ret_scn_doas->info = shdr64->sh_info;
        ret_scn_doas->entrysize = shdr64->sh_entsize;
        ret_scn_doas->name = elf_strptr(obj->elf, obj->ehdr64->e_shstrndx,
            shdr64->sh_name);
        if (ret_scn_doas->name == NULL) {
            *error = DW_DLE_ELF_STRPTR_ERROR;
            return DW_DLV_ERROR;
        }
        return DW_DLV_OK;
#else
        *error = DW_DLE_MISSING_ELF64_SUPPORT;
        return DW_DLV_ERROR;
#endif /* HAVE_ELF64_GETSHDR */
    }
    if ((shdr32 = elf32_getshdr(scn)) == NULL) {
        *error = DW_DLE_ELF_GETSHDR_ERROR;
        return DW_DLV_ERROR;
    }

    /*  Get also the section type, so the caller can use it for
        additional tasks that require to know the section type. */
    ret_scn_doas->type = shdr32->sh_type;
    ret_scn_doas->size = shdr32->sh_size;
    ret_scn_doas->addr = shdr32->sh_addr;
    ret_scn_doas->link = shdr32->sh_link;
    ret_scn_doas->info = shdr32->sh_info;
    ret_scn_doas->entrysize = shdr32->sh_entsize;
    ret_scn_doas->name = elf_strptr(obj->elf, obj->ehdr32->e_shstrndx,
        shdr32->sh_name);
    if (ret_scn_doas->name == NULL) {
        *error = DW_DLE_ELF_STRPTR_ERROR;
        return DW_DLV_ERROR;
    }
    return DW_DLV_OK;
}

/* dwarf_elf_object_access_get_length_size */
static
Dwarf_Small
dwarf_elf_object_access_get_length_size(void* obj_in)
{
    dwarf_elf_object_access_internals_t*obj =
        (dwarf_elf_object_access_internals_t*)obj_in;
    return obj->length_size;
}

/* dwarf_elf_object_access_get_pointer_size */
static
Dwarf_Small
dwarf_elf_object_access_get_pointer_size(void* obj_in)
{
    dwarf_elf_object_access_internals_t*obj =
        (dwarf_elf_object_access_internals_t*)obj_in;
    return obj->pointer_size;
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
#undef MATCH_REL_SEC

static void
get_rela_elf32(Dwarf_Small *data, unsigned int i,
  UNUSEDARG int endianness,
  UNUSEDARG int machine,
  struct Dwarf_Elf_Rela *relap)
{
    Elf32_Rela *relp = 0;

    relp = (Elf32_Rela*)(data + (i * sizeof(Elf32_Rela)));
    relap->r_offset = relp->r_offset;
    /* relap->r_info = relp->r_info; */
    relap->r_type = ELF32_R_TYPE(relp->r_info);
    relap->r_symidx = ELF32_R_SYM(relp->r_info);
    relap->r_is_rela = TRUE;
    relap->r_addend = relp->r_addend;
}
static void
get_rel_elf32(Dwarf_Small *data, unsigned int i,
  UNUSEDARG int endianness,
  UNUSEDARG int machine,
  struct Dwarf_Elf_Rela *relap)
{
    Elf32_Rel *relp = 0;

    relp = (Elf32_Rel*)(data + (i * sizeof(Elf32_Rel)));
    relap->r_offset = relp->r_offset;
    /* relap->r_info = relp->r_info; */
    relap->r_type = ELF32_R_TYPE(relp->r_info);
    relap->r_symidx = ELF32_R_SYM(relp->r_info);
    relap->r_is_rela = FALSE;
    relap->r_addend = 0;
}


static void
get_rela_elf64(Dwarf_Small *data, unsigned int i,
  int endianness,
  int machine,
  struct Dwarf_Elf_Rela *relap)
{
#ifdef HAVE_ELF64_RELA
    Elf64_Rela * relp = 0;
    relp = (Elf64_Rela*)(data + (i * sizeof(Elf64_Rela)));
    relap->r_offset = relp->r_offset;
    /* relap->r_info = relp->r_info; */
#define ELF64MIPS_REL_SYM(i) ((i) & 0xffffffff)
#define ELF64MIPS_REL_TYPE(i) ((i >> 56) &0xff)
    if (machine == EM_MIPS && endianness == DW_OBJECT_LSB ){
        /*  This is really wierd. Treat this very specially.
            The Elf64 LE MIPS object used for
            testing (that has rela) wants the
            values as  sym  ssym type3 type2 type, treating
            each value as independent value. But libelf xlate
            treats it as something else so we fudge here.
            It is unclear
            how to precisely characterize where these relocations
            were used.
            SGI MIPS on IRIX never used .rela relocations.
            The BE 64bit elf MIPS test object with rela uses traditional
            elf relocation layouts, not this special case.  */
        /*  We ignore the special TYPE2 and TYPE3, they should be
            value R_MIPS_NONE in rela. */
        relap->r_type = ELF64MIPS_REL_TYPE(relp->r_info);
        relap->r_symidx = ELF64MIPS_REL_SYM(relp->r_info);
#undef MIPS64SYM
#undef MIPS64TYPE
    } else
    {
        relap->r_type = ELF64_R_TYPE(relp->r_info);
        relap->r_symidx = ELF64_R_SYM(relp->r_info);
    }
    relap->r_addend = relp->r_addend;
    relap->r_is_rela = TRUE;
#endif
}

static void
get_rel_elf64(Dwarf_Small *data, unsigned int i,
  int endianness,
  int machine,
  struct Dwarf_Elf_Rela *relap)
{
#ifdef HAVE_ELF64_RELA
    Elf64_Rel * relp = 0;
    relp = (Elf64_Rel*)(data + (i * sizeof(Elf64_Rel)));
    relap->r_offset = relp->r_offset;
    /* relap->r_info = relp->r_info; */
#define ELF64MIPS_REL_SYM(i) ((i) & 0xffffffff)
#define ELF64MIPS_REL_TYPE(i) ((i >> 56) &0xff)
    if (machine == EM_MIPS && endianness == DW_OBJECT_LSB ){
        /*  This is really wierd. Treat this very specially.
            The Elf64 LE MIPS object used for
            testing (that has rela) wants the
            values as  sym  ssym type3 type2 type, treating
            each value as independent value. But libelf xlate
            treats it as something else so we fudge here.
            It is unclear
            how to precisely characterize where these relocations
            were used.
            SGI MIPS on IRIX never used .rela relocations.
            The BE 64bit elf MIPS test object with rela uses traditional
            elf relocation layouts, not this special case.  */
        /*  We ignore the special TYPE2 and TYPE3, they should be
            value R_MIPS_NONE in rela. */
        relap->r_type = ELF64MIPS_REL_TYPE(relp->r_info);
        relap->r_symidx = ELF64MIPS_REL_SYM(relp->r_info);
#undef MIPS64SYM
#undef MIPS64TYPE
    } else
    {
        relap->r_type = ELF64_R_TYPE(relp->r_info);
        relap->r_symidx = ELF64_R_SYM(relp->r_info);
    }
    relap->r_addend = 0;
    relap->r_is_rela = FALSE;
#endif
}


static void
get_relocations_array(Dwarf_Bool is_64bit,
    int endianness,
    int machine,
    int is_rela,
    Dwarf_Small *data,
    unsigned int num_relocations,
    struct Dwarf_Elf_Rela *relap)
{
    unsigned int i = 0;
    void (*get_relocations)(Dwarf_Small *data, unsigned int i,
        int endianness,
        int machine,
        struct Dwarf_Elf_Rela *relap);

    /* Handle 32/64 bit issue */
    if (is_64bit) {
        if ( is_rela) {
            get_relocations = get_rela_elf64;
        } else {
            get_relocations = get_rel_elf64;
        }
    } else {
        if ( is_rela) {
            get_relocations = get_rela_elf32;
        } else {
            get_relocations = get_rel_elf32;
        }
    }

    for (i=0; i < num_relocations; i++) {
        get_relocations(data, i,endianness,machine,
            &(relap[i]));
    }

}

static int
get_relocation_entries(Dwarf_Bool is_64bit,
    int endianness,
    int machine,
    Dwarf_Small *relocation_section,
    Dwarf_Unsigned relocation_section_size,
    Dwarf_Unsigned relocation_section_entrysize,
    struct Dwarf_Elf_Rela **relas,
    unsigned int *nrelas,
    int is_rela,
    int *error)
{
    unsigned int relocation_size = 0;

    if (is_64bit) {
#ifdef HAVE_ELF64_RELA
        relocation_size = is_rela?sizeof(Elf64_Rela):sizeof(Elf64_Rel);
#else
        *error = DW_DLE_MISSING_ELF64_SUPPORT;
        return DW_DLV_ERROR;
#endif
    } else {
        relocation_size = is_rela?sizeof(Elf32_Rela):sizeof(Elf32_Rel);
    }
    if (relocation_size != relocation_section_entrysize) {
        /*  Means our struct definition does not match the
            real object. */

        *error = DW_DLE_RELOC_SECTION_LENGTH_ODD;
        return DW_DLV_ERROR;
    }

    if (relocation_section == NULL) {
        *error = DW_DLE_RELOC_SECTION_PTR_NULL;
        return(DW_DLV_ERROR);
    }

    if ((relocation_section_size != 0)) {
        size_t bytescount = 0;
        if (relocation_section_size%relocation_size) {
            *error = DW_DLE_RELOC_SECTION_LENGTH_ODD;
            return DW_DLV_ERROR;
        }
        *nrelas = relocation_section_size/relocation_size;
        bytescount = (*nrelas) * sizeof(struct Dwarf_Elf_Rela);
        *relas = malloc(bytescount);
        if (!*relas) {
            *error = DW_DLE_MAF;
            return(DW_DLV_ERROR);
        }
        memset(*relas,0,bytescount);
        get_relocations_array(is_64bit,endianness,machine,
            is_rela,
            relocation_section,
            *nrelas, *relas);
    }
    return(DW_DLV_OK);
}

/*  Returns DW_DLV_OK if it works, else DW_DLV_ERROR.
    The caller may decide to ignore the errors or report them. */
static int
update_entry(Dwarf_Debug dbg,
    Dwarf_Bool is_64bit,
    UNUSEDARG Dwarf_Endianness endianess,
    UNUSEDARG Dwarf_Half machine,
    struct Dwarf_Elf_Rela *rela,
    Dwarf_Small *target_section,
    Dwarf_Unsigned target_section_size,
    Dwarf_Small *symtab_section_data,
    Dwarf_Unsigned symtab_section_size,
    Dwarf_Unsigned symtab_section_entrysize,
    int is_rela,
    int *error)
{
    unsigned int type = 0;
    unsigned int sym_idx = 0;
#ifdef HAVE_ELF64_SYM
    Elf64_Sym sym_buf;
    Elf64_Sym *sym = 0;
#else
    Elf32_Sym sym_buf;
    Elf32_Sym *sym = 0;
#endif
    Elf32_Sym *sym32 = 0;
    Dwarf_Unsigned offset = 0;
    Dwarf_Signed addend = 0;
    Dwarf_Unsigned reloc_size = 0;
    Dwarf_Unsigned symtab_entry_count = 0;

    if (symtab_section_entrysize == 0) {
        *error = DW_DLE_SYMTAB_SECTION_ENTRYSIZE_ZERO;
        return DW_DLV_ERROR;
    }
    symtab_entry_count = symtab_section_size/symtab_section_entrysize;

    /* Dwarf_Elf_Rela dereferencing */
    offset = rela->r_offset;
    addend = rela->r_addend;
    type = rela->r_type;
    sym_idx = rela->r_symidx;
    if (sym_idx >= symtab_entry_count) {
        *error = DW_DLE_RELOC_SECTION_SYMBOL_INDEX_BAD;
        return DW_DLV_ERROR;
    }
    if (offset >= target_section_size) {
        /*  If offset really big, any add will overflow.
            So lets stop early if offset is corrupt. */
        *error = DW_DLE_RELOC_INVALID;
        return DW_DLV_ERROR;
    }
    if (is_64bit) {
#ifdef HAVE_ELF64_SYM
        sym = &((Elf64_Sym*)symtab_section_data)[sym_idx];
#else
        /* We cannot handle this object without 64_SYMs. */
        *error = DW_DLE_RELOC_SECTION_RELOC_TARGET_SIZE_UNKNOWN;
        return DW_DLV_ERROR;
#endif
    } else {
        sym32 = &((Elf32_Sym*)symtab_section_data)[sym_idx];

        /*  Convert Elf32_Sym struct to Elf64_Sym struct. We point at
            an Elf64_Sym local variable (sym_buf) to allow us to use the
            same pointer (sym) for both 32-bit and 64-bit instances.  */
        sym = &sym_buf;
        sym->st_name = sym32->st_name;
        sym->st_info = sym32->st_info;
        sym->st_other = sym32->st_other;
        sym->st_shndx = sym32->st_shndx;
        sym->st_value = sym32->st_value;
        sym->st_size = sym32->st_size;
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
    { /* .rel. (addend is zero) or .rela */
        Dwarf_Small *targ = target_section+offset;
        Dwarf_Unsigned presentval = 0;
        Dwarf_Unsigned outval = 0;
        /*  See also: READ_UNALIGNED_SAFE in
            dwarf_elfread.c  */

        if (!is_rela) {
            READ_UNALIGNED_SAFE(dbg,presentval,
                targ,reloc_size);
        }
        /*  There is no addend in .rel.
            Normally presentval is correct
            and st_value will be zero.
            But a few compilers have
            presentval zero and st_value set. */
        outval = presentval + sym->st_value + addend ;
        WRITE_UNALIGNED_LOCAL(dbg,targ,
            &outval,sizeof(outval),reloc_size);
    }
    return DW_DLV_OK;
}



/*  Somewhat arbitrarily, we attempt to apply all the relocations we can
    and still notify the caller of at least one error if we found
    any errors.  */
static int
apply_rela_entries(Dwarf_Debug dbg,
    Dwarf_Bool is_64bit,
    Dwarf_Endianness endianess,
    Dwarf_Half machine,
    Dwarf_Small *target_section,
    Dwarf_Unsigned target_section_size,
    Dwarf_Small *symtab_section,
    Dwarf_Unsigned symtab_section_size,
    Dwarf_Unsigned symtab_section_entrysize,
    int   is_rela,
    struct Dwarf_Elf_Rela *relas, unsigned int nrelas,
    int *error)
{
    int return_res = DW_DLV_OK;
    if ((target_section != NULL)  && (relas != NULL)) {
        unsigned int i;
        if (symtab_section_entrysize == 0) {
            *error = DW_DLE_SYMTAB_SECTION_ENTRYSIZE_ZERO;
            return DW_DLV_ERROR;
        }
        if (symtab_section_size%symtab_section_entrysize) {
            *error = DW_DLE_SYMTAB_SECTION_LENGTH_ODD;
            return DW_DLV_ERROR;
        }
        for (i = 0; i < nrelas; i++) {
            int res = update_entry(dbg, is_64bit,
                endianess,
                machine,
                &(relas)[i],
                target_section,
                target_section_size,
                symtab_section,
                symtab_section_size,
                symtab_section_entrysize,
                is_rela,
                error);
            if (res != DW_DLV_OK) {
                return_res = res;
            }
        }
    }
    return return_res;
}


static int
loop_through_relocations(
   Dwarf_Debug dbg,
   dwarf_elf_object_access_internals_t* obj,
   struct Dwarf_Section_s *relocatablesec,
   int *error)
{
    Dwarf_Small *target_section = 0;
    Dwarf_Small *symtab_section = obj->symtab->dss_data;
    Dwarf_Unsigned symtab_section_entrysize = obj->symtab->dss_entrysize;
    Dwarf_Unsigned symtab_section_size = obj->symtab->dss_size;
    Dwarf_Small *relocation_section  = relocatablesec->dss_reloc_data;
    Dwarf_Unsigned relocation_section_size =
        relocatablesec->dss_reloc_size;
    Dwarf_Unsigned relocation_section_entrysize = relocatablesec->dss_reloc_entrysize;
    int ret = DW_DLV_ERROR;
    struct Dwarf_Elf_Rela *relas = 0;
    unsigned int nrelas = 0;
    Dwarf_Small *mspace = 0;
    int is_rela = relocatablesec->dss_is_rela;

    ret = get_relocation_entries(obj->is_64bit,
        obj->endianness,
        obj->machine,
        relocation_section,
        relocation_section_size,
        relocation_section_entrysize,
        &relas, &nrelas, is_rela,error);
    if (ret != DW_DLV_OK) {
        free(relas);
        return ret;
    }

    if(!relocatablesec->dss_data_was_malloc) {
        /*  Some systems read Elf in read-only memory via mmap or the like.
            So the only safe thing is to copy the current data into
            malloc space and refer to the malloc space instead of the
            space returned by the elf library */
        mspace = malloc(relocatablesec->dss_size);
        if (!mspace) {
            free(relas);
            *error = DW_DLE_RELOC_SECTION_MALLOC_FAIL;
            return DW_DLV_ERROR;
        }
        memcpy(mspace,relocatablesec->dss_data,relocatablesec->dss_size);
        relocatablesec->dss_data = mspace;
        relocatablesec->dss_data_was_malloc = TRUE;
    }
    target_section = relocatablesec->dss_data;
    ret = apply_rela_entries(
        dbg,
        obj->is_64bit,
        obj->endianness, obj->machine,
        target_section,
        relocatablesec->dss_size,
        symtab_section,
        symtab_section_size,
        symtab_section_entrysize,
        is_rela,
        relas, nrelas, error);
    free(relas);
    return ret;
}

/*  Find the section data in dbg and find all the relevant
    sections.  Then do relocations.
*/
static int
dwarf_elf_object_relocate_a_section(void* obj_in,
    Dwarf_Half section_index,
    Dwarf_Debug dbg,
    int* error)
{
    int res = DW_DLV_ERROR;
    dwarf_elf_object_access_internals_t*obj = 0;
    struct Dwarf_Section_s * relocatablesec = 0;
    if (section_index == 0) {
        return DW_DLV_NO_ENTRY;
    }
    obj = (dwarf_elf_object_access_internals_t*)obj_in;

    /* The section to relocate must already be loaded into memory. */
    res = find_section_to_relocate(dbg, section_index,&relocatablesec,error);
    if (res != DW_DLV_OK) {
        return res;
    }

    /*  Sun and possibly others do not always set sh_link in .debug_* sections.
        So we cannot do full  consistency checks. */
    if (relocatablesec->dss_reloc_index == 0 ) {
        /* Something is wrong. */
        *error = DW_DLE_RELOC_SECTION_MISSING_INDEX;
        return DW_DLV_ERROR;
    }
    /* Now load the relocations themselves. */
    res =  dwarf_elf_object_access_load_section(obj_in,
        relocatablesec->dss_reloc_index,
        &relocatablesec->dss_reloc_data, error);
    if (res != DW_DLV_OK) {
        return res;
    }

    /* Now get the symtab. */
    if (!obj->symtab) {
        obj->symtab = &dbg->de_elf_symtab;
        obj->strtab = &dbg->de_elf_strtab;
    }
    if (obj->symtab->dss_index != relocatablesec->dss_reloc_link) {
        /* Something is wrong. */
        *error = DW_DLE_RELOC_MISMATCH_RELOC_INDEX;
        return DW_DLV_ERROR;
    }
    if (obj->strtab->dss_index != obj->symtab->dss_link) {
        /* Something is wrong. */
        *error = DW_DLE_RELOC_MISMATCH_STRTAB_INDEX;
        return DW_DLV_ERROR;
    }
    if (!obj->symtab->dss_data) {
        /* Now load the symtab */
        res =  dwarf_elf_object_access_load_section(obj_in,
            obj->symtab->dss_index,
            &obj->symtab->dss_data, error);
        if (res != DW_DLV_OK) {
            return res;
        }
    }
    if (!obj->strtab->dss_data) {
        /* Now load the strtab */
        res = dwarf_elf_object_access_load_section(obj_in,
            obj->strtab->dss_index,
            &obj->strtab->dss_data,error);
        if (res != DW_DLV_OK){
            return res;
        }
    }


    /* We have all the data we need in memory. */
    res = loop_through_relocations(dbg,obj,relocatablesec,error);

    return res;
}

/*  dwarf_elf_object_access_load_section()
    We are only asked to load sections that
    libdwarf really needs.
    It would be much better if a 'user data pointer'
    were passed through these interfaces so one
    part of libdwarf could pass through to this.
    Or even just if a Dwarf_Debug were passed in.
    Sigh. */
static int
dwarf_elf_object_access_load_section(void* obj_in,
    Dwarf_Half section_index,
    Dwarf_Small** section_data,
    int* error)
{
    dwarf_elf_object_access_internals_t*obj =
        (dwarf_elf_object_access_internals_t*)obj_in;
    if (section_index == 0) {
        return DW_DLV_NO_ENTRY;
    }

    {
        Elf_Scn *scn = 0;
        Elf_Data *data = 0;

        scn = elf_getscn(obj->elf, section_index);
        if (scn == NULL) {
            /*  The section_index does not exist or
                obj->elf is NULL. */
            *error = DW_DLE_MDE;
            return DW_DLV_ERROR;
        }

        /*  When using libelf as a producer, section data may be stored
            in multiple buffers. In libdwarf however, we only use libelf
            as a consumer (there is a dwarf producer API, but it doesn't
            use libelf). Because of this, this single call to elf_getdata
            will retrieve the entire section in a single contiguous
            buffer. */
        data = elf_getdata(scn, NULL);
        if (data == NULL) {
            /*  Most likely means that the Elf section header
                is damaged/corrupt and the data is
                impossible to read into
                memory.   The size specified in the
                Elf section is too large to allocate memory
                for so the data could not be loaded. */
            *error = DW_DLE_MDE;
            return DW_DLV_ERROR;
        }
        if (!data->d_buf) {
            /*  If NULL it means 'the section has no data'
                according to libelf documentation.
                No DWARF-related section should ever have
                'no data'.  Happens if a section type is
                SHT_NOBITS and no section libdwarf
                wants to look at should be SHT_NOBITS. */
            *error = DW_DLE_MDE;
            return DW_DLV_ERROR;
        }
        *section_data = data->d_buf;
    }
    return DW_DLV_OK;
}


/*  dwarf_elf_access method table for use with libelf.
    See also the methods table in dwarf_elfread.c for non-libelf.
*/

static const struct Dwarf_Obj_Access_Methods_s dwarf_elf_object_access_methods =
{
    dwarf_elf_object_access_get_section_info,
    dwarf_elf_object_access_get_byte_order,
    dwarf_elf_object_access_get_length_size,
    dwarf_elf_object_access_get_pointer_size,
    dwarf_elf_object_access_get_section_count,
    dwarf_elf_object_access_load_section,
    dwarf_elf_object_relocate_a_section
};


/*  Interface for the ELF object file implementation.
    On error this should set *err with the
    libdwarf error code.
*/
int
dwarf_elf_object_access_init(dwarf_elf_handle elf,
    int libdwarf_owns_elf,
    Dwarf_Obj_Access_Interface** ret_obj,
    int *err)
{
    int res = 0;
    dwarf_elf_object_access_internals_t *internals = 0;
    Dwarf_Obj_Access_Interface *intfc = 0;

    internals = malloc(sizeof(dwarf_elf_object_access_internals_t));
    if (!internals) {
        *err = DW_DLE_ALLOC_FAIL;
        /* Impossible case, we hope. Give up. */
        return DW_DLV_ERROR;
    }
    memset(internals,0,sizeof(*internals));
    res = dwarf_elf_object_access_internals_init(internals, elf, err);
    if (res != DW_DLV_OK){
        /* *err is already set. */
        free(internals);
        return DW_DLV_ERROR;
    }
    internals->libdwarf_owns_elf = libdwarf_owns_elf;

    intfc = malloc(sizeof(Dwarf_Obj_Access_Interface));
    if (!intfc) {
        /* Impossible case, we hope. Give up. */
        *err = DW_DLE_ALLOC_FAIL;
        free(internals);
        return DW_DLV_ERROR;
    }
    /* Initialize the interface struct */
    intfc->object = internals;
    intfc->methods = &dwarf_elf_object_access_methods;

    /*  An access method hidden from non-elf. Needed to
        handle new-ish SHF_COMPRESSED flag in elf.  */
    _dwarf_get_elf_flags_func_ptr = _dwarf_get_elf_flags_func;


    *ret_obj = intfc;
    return DW_DLV_OK;
}



/* Clean up the Dwarf_Obj_Access_Interface returned by elf_access_init.  */
void
dwarf_elf_object_access_finish(Dwarf_Obj_Access_Interface* obj)
{
    if (!obj) {
        return;
    }
    if (obj->object) {
        dwarf_elf_object_access_internals_t *internals =
            (dwarf_elf_object_access_internals_t *)obj->object;
        if (internals->libdwarf_owns_elf){
            /*  Happens with dwarf_init_path(),
                dwarf_init(), or dwarf_init_b()
                interfaces. */
            elf_end(internals->elf);
        }
    }
    free(obj->object);
    free(obj);
}

/*  This function returns the Elf * pointer
    associated with a Dwarf_Debug.

    This function only makes sense if ELF is implied
    and there actually is an Elf * pointer available.
*/
int
dwarf_get_elf(Dwarf_Debug dbg, dwarf_elf_handle * elf,
    Dwarf_Error * error)
{
    struct Dwarf_Obj_Access_Interface_s * obj = 0;
    if (dbg == NULL) {
        _dwarf_error(NULL, error, DW_DLE_DBG_NULL);
        return (DW_DLV_ERROR);
    }

    obj = dbg->de_obj_file;
    if (obj && obj->object) {
        dwarf_elf_object_access_internals_t *internals = 0;
        char typeletter = *(char *)(obj->object);

        if (typeletter != 'E') {
            /* Not libelf Elf */
            return DW_DLV_NO_ENTRY;
        }
        internals = (dwarf_elf_object_access_internals_t*)obj->object;
        if (internals->elf == NULL) {
            _dwarf_error(dbg, error, DW_DLE_FNO);
            return (DW_DLV_ERROR);
        }
        *elf = internals->elf;
        return DW_DLV_OK;
    }
    _dwarf_error(dbg, error, DW_DLE_FNO);
    return DW_DLV_ERROR;
}
#else
int dwarf_elf_access_dummy_var_avoid_warn = 0;
#endif /* DWARF_WITH_LIBELF */
