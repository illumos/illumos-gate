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

/*  This file reads the parts of an Apple mach-o object
    file appropriate to reading DWARF debugging data.
    Overview:
    _dwarf_macho_setup() Does all macho setup.
        calls _dwarf_macho_access_init()
            calls _dwarf_macho_object_access_internals_init()
                Creates internals record 'M',
                    dwarf_macho_object_access_internals_t
                Sets flags/data in internals record
                Loads macho object data needed later.
                Sets methods struct to access macho object.
        calls _dwarf_object_init_b() Creates Dwarf_Debug, independent
            of any macho code.
        Sets internals record into dbg.
    ----------------------
    _dwarf_destruct_macho_access(). This frees
        the macho internals record created in
        _dwarf_macho_object_access_internals_init()
        in case of errors during setup or when
        dwarf_finish() is called.  Works safely for
        partially or fully set-up macho internals record.

    Other than in _dwarf_macho_setup() the macho code
    knows nothing about Dwarf_Debug, and the rest of
    libdwarf knows nothing about the content of the
    macho internals record.

*/

#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#endif /* _WIN32 */

#include "config.h"
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif /* HAVE_STDLIB_H */
#ifdef HAVE_MALLOC_H
/* Useful include for some Windows compilers. */
#include <malloc.h>
#endif /* HAVE_MALLOC_H */
#include <string.h>
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
#include "dwarf_machoread.h"
#include "dwarf_object_detector.h"
#include "dwarf_macho_loader.h"

#ifndef TYP
#define TYP(n,l) char n[l]
#endif /* TYPE */

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


/* MACH-O and dwarf section names */
static struct macho_sect_names_s {
    char const *ms_moname;
    char const *ms_dwname;
} const SectionNames [] = {
    { "", "" },  /* ELF index-0 entry */
    { "__debug_abbrev",         ".debug_abbrev" },
    { "__debug_aranges",        ".debug_aranges" },
    { "__debug_frame",          ".debug_frame" },
    { "__debug_info",           ".debug_info" },
    { "__debug_line",           ".debug_line" },
    { "__debug_macinfo",        ".debug_macinfo" },
    { "__debug_loc",            ".debug_loc" },
    { "__debug_pubnames",       ".debug_pubnames" },
    { "__debug_pubtypes",       ".debug_pubtypes" },
    { "__debug_str",            ".debug_str" },
    { "__debug_ranges",         ".debug_ranges" },
    { "__debug_macro",          ".debug_macro" },
    { "__debug_gdb_scri",       ".debug_gdb_scripts" }
};

static int
_dwarf_macho_object_access_init(
    int  fd,
    unsigned ftype,
    unsigned endian,
    unsigned offsetsize,
    size_t filesize,
    Dwarf_Unsigned access,
    Dwarf_Obj_Access_Interface **binary_interface,
    int *localerrnum);


static Dwarf_Endianness macho_get_byte_order (void *obj)
{
    dwarf_macho_object_access_internals_t *macho =
        (dwarf_macho_object_access_internals_t*)(obj);
    return macho->mo_endian;
}


static Dwarf_Small macho_get_length_size (void *obj)
{
    dwarf_macho_object_access_internals_t *macho =
        (dwarf_macho_object_access_internals_t*)(obj);
    return macho->mo_offsetsize/8;
}


static Dwarf_Small macho_get_pointer_size (void *obj)
{
    dwarf_macho_object_access_internals_t *macho =
        (dwarf_macho_object_access_internals_t*)(obj);
    return macho->mo_pointersize/8;
}


static Dwarf_Unsigned macho_get_section_count (void *obj)
{
    dwarf_macho_object_access_internals_t *macho =
        (dwarf_macho_object_access_internals_t*)(obj);
    return macho->mo_dwarf_sectioncount;
}

static int macho_get_section_info (void *obj,
    Dwarf_Half section_index,
    Dwarf_Obj_Access_Section *return_section,
    UNUSEDARG int *error)
{
    dwarf_macho_object_access_internals_t *macho =
        (dwarf_macho_object_access_internals_t*)(obj);


    if (section_index < macho->mo_dwarf_sectioncount) {
        struct generic_macho_section *sp = 0;

        sp = macho->mo_dwarf_sections + section_index;
        return_section->addr = 0;
        return_section->type = 0;
        return_section->size = sp->size;
        return_section->name = sp->dwarfsectname;
        return_section->link = 0;
        return_section->info = 0;
        return_section->entrysize = 0;
        return DW_DLV_OK;
    }
    return DW_DLV_NO_ENTRY;
}

static int
macho_load_section (void *obj, Dwarf_Half section_index,
    Dwarf_Small **return_data, int *error)
{
    dwarf_macho_object_access_internals_t *macho =
        (dwarf_macho_object_access_internals_t*)(obj);

    if (0 < section_index &&
        section_index < macho->mo_dwarf_sectioncount) {
        int res = 0;

        struct generic_macho_section *sp =
            macho->mo_dwarf_sections + section_index;
        if(sp->loaded_data) {
            *return_data = sp->loaded_data;
            return DW_DLV_OK;
        }
        if (!sp->size) {
            return DW_DLV_NO_ENTRY;
        }
        if ((sp->size + sp->offset) >
            macho->mo_filesize) {
            *error = DW_DLE_FILE_TOO_SMALL;
            return DW_DLV_ERROR;
        }

        sp->loaded_data = malloc((size_t)sp->size);
        if (!sp->loaded_data) {
            *error = DW_DLE_ALLOC_FAIL;
            return DW_DLV_ERROR;
        }
        res = RRMOA(macho->mo_fd,
            sp->loaded_data, (off_t)sp->offset,
            (size_t)sp->size, (off_t)macho->mo_filesize, error);
        if (res != DW_DLV_OK) {
            free(sp->loaded_data);
            sp->loaded_data = 0;
            return res;
        }
        *return_data = sp->loaded_data;
        return DW_DLV_OK;
    }
    return DW_DLV_NO_ENTRY;
}

void
_dwarf_destruct_macho_access(
    struct Dwarf_Obj_Access_Interface_s *aip)
{
    dwarf_macho_object_access_internals_t *mp = 0;
    Dwarf_Unsigned i = 0;

    if(!aip) {
        return;
    }
    mp = (dwarf_macho_object_access_internals_t *)aip->object;
    if (mp->mo_destruct_close_fd) {
        close(mp->mo_fd);
        mp->mo_fd = -1;
    }
    if (mp->mo_commands){
        free(mp->mo_commands);
        mp->mo_commands = 0;
    }
    if (mp->mo_segment_commands){
        free(mp->mo_segment_commands);
        mp->mo_segment_commands = 0;
    }
    free((char *)mp->mo_path);
    if (mp->mo_dwarf_sections) {
        struct generic_macho_section *sp = 0;

        sp = mp->mo_dwarf_sections;
        for( i=0; i < mp->mo_dwarf_sectioncount; ++i,++sp) {
            if (sp->loaded_data) {
                free(sp->loaded_data);
                sp->loaded_data = 0;
            }
        }
        free(mp->mo_dwarf_sections);
        mp->mo_dwarf_sections = 0;
    }
    free(mp);
    free(aip);
    return;
}

/* load_macho_header32(dwarf_macho_object_access_internals_t *mfp)*/
static int
load_macho_header32(dwarf_macho_object_access_internals_t *mfp, int *errcode)
{
    struct mach_header mh32;
    int res = 0;

    if (sizeof(mh32) > mfp->mo_filesize) {
        *errcode = DW_DLE_FILE_TOO_SMALL;
        return DW_DLV_ERROR;
    }
    res = RRMOA(mfp->mo_fd, &mh32, 0, sizeof(mh32),
        (off_t)mfp->mo_filesize, errcode);
    if (res != DW_DLV_OK) {
        return res;
    }
    /* Do not adjust endianness of magic, leave as-is. */
    ASNAR(memcpy,mfp->mo_header.magic,mh32.magic);
    ASNAR(mfp->mo_copy_word,mfp->mo_header.cputype,mh32.cputype);
    ASNAR(mfp->mo_copy_word,mfp->mo_header.cpusubtype,mh32.cpusubtype);
    ASNAR(mfp->mo_copy_word,mfp->mo_header.filetype,mh32.filetype);
    ASNAR(mfp->mo_copy_word,mfp->mo_header.ncmds,mh32.ncmds);
    ASNAR(mfp->mo_copy_word,mfp->mo_header.sizeofcmds,mh32.sizeofcmds);
    ASNAR(mfp->mo_copy_word,mfp->mo_header.flags,mh32.flags);
    mfp->mo_header.reserved = 0;
    mfp->mo_command_count = (unsigned int)mfp->mo_header.ncmds;
    mfp->mo_command_start_offset = sizeof(mh32);
    return DW_DLV_OK;
}

/* load_macho_header64(dwarf_macho_object_access_internals_t *mfp) */
static int
load_macho_header64(dwarf_macho_object_access_internals_t *mfp,
    int *errcode)
{
    struct mach_header_64 mh64;
    int res = 0;

    if (sizeof(mh64) > mfp->mo_filesize) {
        *errcode = DW_DLE_FILE_TOO_SMALL;
        return DW_DLV_ERROR;
    }
    res = RRMOA(mfp->mo_fd, &mh64, 0, sizeof(mh64),
        (off_t)mfp->mo_filesize, errcode);
    if (res != DW_DLV_OK) {
        return res;
    }
    /* Do not adjust endianness of magic, leave as-is. */
    ASNAR(memcpy,mfp->mo_header.magic,mh64.magic);
    ASNAR(mfp->mo_copy_word,mfp->mo_header.cputype,mh64.cputype);
    ASNAR(mfp->mo_copy_word,mfp->mo_header.cpusubtype,mh64.cpusubtype);
    ASNAR(mfp->mo_copy_word,mfp->mo_header.filetype,mh64.filetype);
    ASNAR(mfp->mo_copy_word,mfp->mo_header.ncmds,mh64.ncmds);
    ASNAR(mfp->mo_copy_word,mfp->mo_header.sizeofcmds,mh64.sizeofcmds);
    ASNAR(mfp->mo_copy_word,mfp->mo_header.flags,mh64.flags);
    ASNAR(mfp->mo_copy_word,mfp->mo_header.reserved,mh64.reserved);
    mfp->mo_command_count = (unsigned int)mfp->mo_header.ncmds;
    mfp->mo_command_start_offset = sizeof(mh64);
    return DW_DLV_OK;
}

int
dwarf_load_macho_header(dwarf_macho_object_access_internals_t *mfp,
    int *errcode)
{
    int res = 0;

    if (mfp->mo_offsetsize == 32) {
        res = load_macho_header32(mfp,errcode);
    } else if (mfp->mo_offsetsize == 64) {
        res = load_macho_header64(mfp,errcode);
    } else {
        *errcode = DW_DLE_OFFSET_SIZE;
        return DW_DLV_ERROR;
    }
    return res;
}


static int
load_segment_command_content32(
    dwarf_macho_object_access_internals_t *mfp,
    struct generic_macho_command *mmp,
    struct generic_macho_segment_command *msp,
    Dwarf_Unsigned mmpindex,
    int *errcode)
{
    struct segment_command sc;
    int res = 0;
    Dwarf_Unsigned filesize = mfp->mo_filesize;
    Dwarf_Unsigned segoffset = mmp->offset_this_command;
    Dwarf_Unsigned afterseghdr = segoffset + sizeof(sc);

    if (mmp->offset_this_command > filesize ||
        mmp->cmdsize > filesize ||
        (mmp->cmdsize + mmp->offset_this_command) > filesize ) {
        *errcode = DW_DLE_MACH_O_SEGOFFSET_BAD;
        return DW_DLV_ERROR;
    }
    res = RRMOA(mfp->mo_fd, &sc, (off_t)mmp->offset_this_command, sizeof(sc),
        (off_t)filesize, errcode);
    if (res != DW_DLV_OK) {
        return res;
    }
    ASNAR(mfp->mo_copy_word,msp->cmd,sc.cmd);
    ASNAR(mfp->mo_copy_word,msp->cmdsize,sc.cmdsize);
    strncpy(msp->segname,sc.segname,16);
    msp->segname[15] =0;
    ASNAR(mfp->mo_copy_word,msp->vmaddr,sc.vmaddr);
    ASNAR(mfp->mo_copy_word,msp->vmsize,sc.vmsize);
    ASNAR(mfp->mo_copy_word,msp->fileoff,sc.fileoff);
    ASNAR(mfp->mo_copy_word,msp->filesize,sc.filesize);
    if (msp->fileoff > mfp->mo_filesize ||
        msp->filesize > mfp->mo_filesize) {
        /* corrupt */
        *errcode = DW_DLE_FILE_OFFSET_BAD;
        return DW_DLV_ERROR;
    }
    if ((msp->fileoff+msp->filesize ) > filesize) {
        /* corrupt */
        *errcode = DW_DLE_FILE_OFFSET_BAD;
        return DW_DLV_ERROR;
    }
    ASNAR(mfp->mo_copy_word,msp->maxprot,sc.maxprot);
    ASNAR(mfp->mo_copy_word,msp->initprot,sc.initprot);
    ASNAR(mfp->mo_copy_word,msp->nsects,sc.nsects);
    ASNAR(mfp->mo_copy_word,msp->flags,sc.flags);
    msp->macho_command_index = mmpindex;
    msp->sectionsoffset = afterseghdr;
    return DW_DLV_OK;
}
static int
load_segment_command_content64(
    dwarf_macho_object_access_internals_t *mfp,
    struct generic_macho_command *mmp,
    struct generic_macho_segment_command *msp,
    Dwarf_Unsigned mmpindex,int *errcode)
{
    struct segment_command_64 sc;
    int res = 0;
    Dwarf_Unsigned filesize = mfp->mo_filesize;
    Dwarf_Unsigned segoffset = mmp->offset_this_command;
    Dwarf_Unsigned afterseghdr = segoffset + sizeof(sc);

    if (mmp->offset_this_command > filesize ||
        mmp->cmdsize > filesize ||
        (mmp->cmdsize + mmp->offset_this_command) > filesize ) {
        *errcode = DW_DLE_FILE_OFFSET_BAD;
        return DW_DLV_ERROR;
    }
    res = RRMOA(mfp->mo_fd, &sc, (off_t)mmp->offset_this_command, sizeof(sc),
        (off_t)filesize, errcode);
    if (res != DW_DLV_OK) {
        return res;
    }
    ASNAR(mfp->mo_copy_word,msp->cmd,sc.cmd);
    ASNAR(mfp->mo_copy_word,msp->cmdsize,sc.cmdsize);
    strncpy(msp->segname,sc.segname,16);
    msp->segname[16] =0;
    ASNAR(mfp->mo_copy_word,msp->vmaddr,sc.vmaddr);
    ASNAR(mfp->mo_copy_word,msp->vmsize,sc.vmsize);
    ASNAR(mfp->mo_copy_word,msp->fileoff,sc.fileoff);
    ASNAR(mfp->mo_copy_word,msp->filesize,sc.filesize);
    if (msp->fileoff > filesize ||
        msp->filesize > filesize) {
        /* corrupt */
        *errcode = DW_DLE_FILE_OFFSET_BAD;
        return DW_DLV_ERROR;
    }
    if ((msp->fileoff+msp->filesize ) > filesize) {
        /* corrupt */
        *errcode = DW_DLE_FILE_OFFSET_BAD;
        return DW_DLV_ERROR;
    }
    ASNAR(mfp->mo_copy_word,msp->maxprot,sc.maxprot);
    ASNAR(mfp->mo_copy_word,msp->initprot,sc.initprot);
    ASNAR(mfp->mo_copy_word,msp->nsects,sc.nsects);
    ASNAR(mfp->mo_copy_word,msp->flags,sc.flags);
    msp->macho_command_index = mmpindex;
    msp->sectionsoffset = afterseghdr;
    return DW_DLV_OK;
}

static int
dwarf_macho_load_segment_commands(
    dwarf_macho_object_access_internals_t *mfp,int *errcode)
{
    Dwarf_Unsigned i = 0;
    struct generic_macho_command *mmp = 0;
    struct generic_macho_segment_command *msp = 0;

    if (mfp->mo_segment_count < 1) {
        return DW_DLV_OK;
    }
    mfp->mo_segment_commands =
        (struct generic_macho_segment_command *)
        calloc(sizeof(struct generic_macho_segment_command),
        (size_t)mfp->mo_segment_count);
    if (!mfp->mo_segment_commands) {
        *errcode = DW_DLE_ALLOC_FAIL;
        return DW_DLV_ERROR;
    }

    mmp = mfp->mo_commands;
    msp = mfp->mo_segment_commands;
    for (i = 0 ; i < mfp->mo_command_count; ++i,++mmp) {
        unsigned cmd = (unsigned)mmp->cmd;
        int res = 0;

        if (cmd == LC_SEGMENT) {
            res = load_segment_command_content32(mfp,mmp,msp,i,errcode);
            ++msp;
        } else if (cmd == LC_SEGMENT_64) {
            res = load_segment_command_content64(mfp,mmp,msp,i,errcode);
            ++msp;
        }
        if (res != DW_DLV_OK) {
            return res;
        }
    }
    return DW_DLV_OK;
}

static int
dwarf_macho_load_dwarf_section_details32(
    dwarf_macho_object_access_internals_t *mfp,
    struct generic_macho_segment_command *segp,
    Dwarf_Unsigned segi, int *errcode)
{
    Dwarf_Unsigned seci = 0;
    Dwarf_Unsigned seccount = segp->nsects;
    Dwarf_Unsigned secalloc = seccount+1;
    Dwarf_Unsigned curoff = segp->sectionsoffset;
    Dwarf_Unsigned shdrlen = sizeof(struct section);

    struct generic_macho_section *secs = 0;

    secs = (struct generic_macho_section *)calloc(
        sizeof(struct generic_macho_section),
        (size_t)secalloc);
    if (!secs) {
        *errcode = DW_DLE_ALLOC_FAIL;
        return DW_DLV_OK;
    }
    mfp->mo_dwarf_sections = secs;
    mfp->mo_dwarf_sectioncount = secalloc;
    if ((curoff  > mfp->mo_filesize) ||
        (seccount > mfp->mo_filesize) ||
        (curoff+(seccount*sizeof(struct section)) >
            mfp->mo_filesize)) {
        *errcode = DW_DLE_FILE_TOO_SMALL;
        return DW_DLV_ERROR;
    }
    secs->offset_of_sec_rec = curoff;
    /*  Leave 0 section all zeros except our offset,
        elf-like in a sense */
    secs->dwarfsectname = "";
    ++secs;
    seci = 1;
    for (; seci < secalloc; ++seci,++secs,curoff += shdrlen ) {
        struct section mosec;
        int res = 0;

        res = RRMOA(mfp->mo_fd, &mosec, (off_t)curoff, sizeof(mosec),
            (off_t)mfp->mo_filesize, errcode);
        if (res != DW_DLV_OK) {
            return res;
        }
        strncpy(secs->sectname,mosec.sectname,16);
        secs->sectname[16] = 0;
        strncpy(secs->segname,mosec.segname,16);
        secs->segname[16] = 0;
        ASNAR(mfp->mo_copy_word,secs->addr,mosec.addr);
        ASNAR(mfp->mo_copy_word,secs->size,mosec.size);
        ASNAR(mfp->mo_copy_word,secs->offset,mosec.offset);
        ASNAR(mfp->mo_copy_word,secs->align,mosec.align);
        ASNAR(mfp->mo_copy_word,secs->reloff,mosec.reloff);
        ASNAR(mfp->mo_copy_word,secs->nreloc,mosec.nreloc);
        ASNAR(mfp->mo_copy_word,secs->flags,mosec.flags);
        if (secs->offset > mfp->mo_filesize ||
            secs->size > mfp->mo_filesize ||
            (secs->offset+secs->size) > mfp->mo_filesize) {
            *errcode = DW_DLE_FILE_OFFSET_BAD;
            return DW_DLV_ERROR;
        }
        secs->reserved1 = 0;
        secs->reserved2 = 0;
        secs->reserved3 = 0;
        secs->generic_segment_num  = segi;
        secs->offset_of_sec_rec = curoff;
    }
    return DW_DLV_OK;
}
static int
dwarf_macho_load_dwarf_section_details64(
    dwarf_macho_object_access_internals_t *mfp,
    struct generic_macho_segment_command *segp,
    Dwarf_Unsigned segi,
    int *errcode)
{
    Dwarf_Unsigned seci = 0;
    Dwarf_Unsigned seccount = segp->nsects;
    Dwarf_Unsigned secalloc = seccount+1;
    Dwarf_Unsigned curoff = segp->sectionsoffset;
    Dwarf_Unsigned shdrlen = sizeof(struct section_64);
    struct generic_macho_section *secs = 0;

    secs = (struct generic_macho_section *)calloc(
        sizeof(struct generic_macho_section),
        (size_t)secalloc);
    if (!secs) {
        *errcode = DW_DLE_ALLOC_FAIL;
        return DW_DLV_ERROR;
    }
    mfp->mo_dwarf_sections = secs;
    mfp->mo_dwarf_sectioncount = secalloc;
    secs->offset_of_sec_rec = curoff;
    /*  Leave 0 section all zeros except our offset,
        elf-like in a sense */
    secs->dwarfsectname = "";
    ++secs;
    if ((curoff  > mfp->mo_filesize) ||
        (seccount > mfp->mo_filesize) ||
        (curoff+(seccount*sizeof(struct section_64)) >
            mfp->mo_filesize)) {
        *errcode = DW_DLE_FILE_TOO_SMALL;
        return DW_DLV_ERROR;
    }
    seci = 1;
    for (; seci < secalloc; ++seci,++secs,curoff += shdrlen ) {
        int res = 0;
        struct section_64 mosec;

        res = RRMOA(mfp->mo_fd, &mosec, (off_t)curoff, sizeof(mosec),
            (off_t)mfp->mo_filesize, errcode);
        if (res != DW_DLV_OK) {
            return res;
        }
        strncpy(secs->sectname,mosec.sectname,16);
        secs->sectname[16] = 0;
        strncpy(secs->segname,mosec.segname,16);
        secs->segname[16] = 0;
        ASNAR(mfp->mo_copy_word,secs->addr,mosec.addr);
        ASNAR(mfp->mo_copy_word,secs->size,mosec.size);
        ASNAR(mfp->mo_copy_word,secs->offset,mosec.offset);
        ASNAR(mfp->mo_copy_word,secs->align,mosec.align);
        ASNAR(mfp->mo_copy_word,secs->reloff,mosec.reloff);
        ASNAR(mfp->mo_copy_word,secs->nreloc,mosec.nreloc);
        ASNAR(mfp->mo_copy_word,secs->flags,mosec.flags);
        if (secs->offset > mfp->mo_filesize ||
            secs->size > mfp->mo_filesize ||
            (secs->offset+secs->size) > mfp->mo_filesize) {
            *errcode = DW_DLE_FILE_OFFSET_BAD;
            return DW_DLV_OK;
        }
        secs->reserved1 = 0;
        secs->reserved2 = 0;
        secs->reserved3 = 0;
        secs->offset_of_sec_rec = curoff;
        secs->generic_segment_num  = segi;
    }
    return DW_DLV_OK;
}

static int
dwarf_macho_load_dwarf_section_details(
    dwarf_macho_object_access_internals_t *mfp,
    struct generic_macho_segment_command *segp,
    Dwarf_Unsigned segi,int *errcode)
{
    int res = 0;

    if (mfp->mo_offsetsize == 32) {
        res = dwarf_macho_load_dwarf_section_details32(mfp,
            segp,segi,errcode);
    } else if (mfp->mo_offsetsize == 64) {
        res = dwarf_macho_load_dwarf_section_details64(mfp,
            segp,segi,errcode);
    } else {
        *errcode = DW_DLE_OFFSET_SIZE;
        return DW_DLV_ERROR;
    }
    return res;
}

static int
dwarf_macho_load_dwarf_sections(
    dwarf_macho_object_access_internals_t *mfp,int *errcode)
{
    Dwarf_Unsigned segi = 0;

    struct generic_macho_segment_command *segp =
        mfp->mo_segment_commands;
    for ( ; segi < mfp->mo_segment_count; ++segi,++segp) {
        int res = 0;

        if (strcmp(segp->segname,"__DWARF")) {
            continue;
        }
        /* Found DWARF, for now assume only one such. */
        res = dwarf_macho_load_dwarf_section_details(mfp,segp,segi,errcode);
        return res;
    }
    return DW_DLV_OK;
}

/* Works the same, 32 or 64 bit */
int
dwarf_load_macho_commands(
    dwarf_macho_object_access_internals_t *mfp,int *errcode)
{
    Dwarf_Unsigned cmdi = 0;
    Dwarf_Unsigned curoff = mfp->mo_command_start_offset;
    Dwarf_Unsigned cmdspace = 0;
    struct load_command mc;
    struct generic_macho_command *mcp = 0;
    unsigned segment_command_count = 0;
    int res = 0;

    if (mfp->mo_command_count >= mfp->mo_filesize) {
        /* corrupt object. */
        *errcode = DW_DLE_MACH_O_SEGOFFSET_BAD;
        return DW_DLV_ERROR;
    }
    if ((curoff + mfp->mo_command_count * sizeof(mc)) >=
        mfp->mo_filesize) {
        /* corrupt object. */
        *errcode = DW_DLE_MACH_O_SEGOFFSET_BAD;
        return DW_DLV_ERROR;
    }

    mfp->mo_commands = (struct generic_macho_command *) calloc(
        mfp->mo_command_count,sizeof(struct generic_macho_command));
    if( !mfp->mo_commands) {
        /* out of memory */
        *errcode = DW_DLE_ALLOC_FAIL;
        return DW_DLV_ERROR;
    }
    mcp = mfp->mo_commands;
    for ( ; cmdi < mfp->mo_header.ncmds; ++cmdi,++mcp ) {
        res = RRMOA(mfp->mo_fd, &mc, (off_t)curoff, sizeof(mc),
            (off_t)mfp->mo_filesize, errcode);
        if (res != DW_DLV_OK) {
            return res;
        }
        ASNAR(mfp->mo_copy_word,mcp->cmd,mc.cmd);
        ASNAR(mfp->mo_copy_word,mcp->cmdsize,mc.cmdsize);
        mcp->offset_this_command = curoff;
        curoff += mcp->cmdsize;
        cmdspace += mcp->cmdsize;
        if (mcp->cmdsize > mfp->mo_filesize ||
            curoff > mfp->mo_filesize) {
            /* corrupt object */
            *errcode = DW_DLE_FILE_OFFSET_BAD;
            return DW_DLV_ERROR;
        }
        if (mcp->cmd == LC_SEGMENT || mcp->cmd == LC_SEGMENT_64) {
            segment_command_count++;
        }
    }
    mfp->mo_segment_count = segment_command_count;
    res = dwarf_macho_load_segment_commands(mfp,errcode);
    if (res != DW_DLV_OK) {
        return res;
    }
    res = dwarf_macho_load_dwarf_sections(mfp,errcode);
    return res;
}
int
_dwarf_macho_setup(int fd,
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
    dwarf_macho_object_access_internals_t *intfc = 0;
    int res = DW_DLV_OK;
    int localerrnum = 0;

    res = _dwarf_macho_object_access_init(
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
        _dwarf_destruct_macho_access(binary_interface);
        return res;
    }
    intfc = binary_interface->object;
    intfc->mo_path = strdup(true_path);
    return res;
}


static Dwarf_Obj_Access_Methods const macho_methods = {
    macho_get_section_info,
    macho_get_byte_order,
    macho_get_length_size,
    macho_get_pointer_size,
    macho_get_section_count,
    macho_load_section,
    /*  We do not do macho relocations. dsym files do not require it. */
    NULL
};

/*  On any error this frees internals argument. */
static int
_dwarf_macho_object_access_internals_init(
    dwarf_macho_object_access_internals_t * internals,
    int  fd,
    unsigned ftype,
    unsigned endian,
    unsigned offsetsize,
    size_t filesize,
    UNUSEDARG Dwarf_Unsigned access,
    int *errcode)
{
    dwarf_macho_object_access_internals_t * intfc = internals;
    Dwarf_Unsigned i  = 0;
    struct generic_macho_section *sp = 0;
    struct Dwarf_Obj_Access_Interface_s *localdoas;
    int res = 0;

    /*  Must malloc as _dwarf_destruct_macho_access()
        forces that due to other uses. */
    localdoas = (struct Dwarf_Obj_Access_Interface_s *)
        malloc(sizeof(struct Dwarf_Obj_Access_Interface_s));
    if (!localdoas) {
        free(internals);
        *errcode = DW_DLE_ALLOC_FAIL;
        return DW_DLV_ERROR;
    }
    memset(localdoas,0,sizeof(struct Dwarf_Obj_Access_Interface_s));
    intfc->mo_ident[0]    = 'M';
    intfc->mo_ident[1]    = '1';
    intfc->mo_fd          = fd;
    intfc->mo_is_64bit    = ((offsetsize==64)?TRUE:FALSE);
    intfc->mo_offsetsize  = offsetsize;
    intfc->mo_pointersize = offsetsize;
    intfc->mo_filesize    = filesize;
    intfc->mo_ftype       = ftype;

#ifdef WORDS_BIGENDIAN
    if (endian == DW_ENDIAN_LITTLE ) {
        intfc->mo_copy_word = _dwarf_memcpy_swap_bytes;
        intfc->mo_endian = DW_OBJECT_LSB;
    } else {
        intfc->mo_copy_word = _dwarf_memcpy_noswap_bytes;
        intfc->mo_endian = DW_OBJECT_MSB;
    }
#else  /* LITTLE ENDIAN */
    if (endian == DW_ENDIAN_LITTLE ) {
        intfc->mo_copy_word = _dwarf_memcpy_noswap_bytes;
        intfc->mo_endian = DW_OBJECT_LSB;
    } else {
        intfc->mo_copy_word = _dwarf_memcpy_swap_bytes;
        intfc->mo_endian = DW_OBJECT_MSB;
    }
#endif /* LITTLE- BIG-ENDIAN */
    res = dwarf_load_macho_header(intfc,errcode);
    if (res != DW_DLV_OK) {
        localdoas->object = intfc;
        localdoas->methods = 0;
        _dwarf_destruct_macho_access(localdoas);
        return res;
    }
    /* Load sections */
    res = dwarf_load_macho_commands(intfc,errcode);
    if (res != DW_DLV_OK) {
        localdoas->methods = 0;
        localdoas->object = intfc;
        _dwarf_destruct_macho_access(localdoas);
        return res;
    }
    sp = intfc->mo_dwarf_sections+1;
    for(i = 1; i < intfc->mo_dwarf_sectioncount ; ++i,++sp) {
        int j = 1;
        int lim = sizeof(SectionNames)/sizeof(SectionNames[0]);
        sp->dwarfsectname = "";
        for( ; j < lim; ++j) {
            if(!strcmp(sp->sectname,SectionNames[j].ms_moname)) {
                sp->dwarfsectname = SectionNames[j].ms_dwname;
                break;
            }
        }
    }
    free(localdoas);
    return DW_DLV_OK;
}


static int
_dwarf_macho_object_access_init(
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
    dwarf_macho_object_access_internals_t *internals = 0;
    Dwarf_Obj_Access_Interface *intfc = 0;

    internals = malloc(sizeof(dwarf_macho_object_access_internals_t));
    if (!internals) {
        *localerrnum = DW_DLE_ALLOC_FAIL;
        /* Impossible case, we hope. Give up. */
        return DW_DLV_ERROR;
    }
    memset(internals,0,sizeof(*internals));
    res = _dwarf_macho_object_access_internals_init(internals,
        fd,
        ftype, endian, offsetsize, filesize,
        access,
        localerrnum);
    if (res != DW_DLV_OK){
        /* *err is already set and the call freed internals. */
        return DW_DLV_ERROR;
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
    intfc->methods = &macho_methods;
    *binary_interface = intfc;
    return DW_DLV_OK;
}
