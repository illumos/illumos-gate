/*

  Copyright (C) 2000,2002,2004 Silicon Graphics, Inc.  All Rights Reserved.
  Portions Copyright 2002-2010 Sun Microsystems, Inc. All rights reserved.
  Portions Copyright 2011-2017 David Anderson. All Rights Reserved.

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

#include "libdwarfdefs.h"

#define true                    1
#define false                   0

/*  The DISTINGUISHED VALUE is 4 byte value defined by DWARF
    since DWARF3. */
#define DISTINGUISHED_VALUE_ARRAY(x)  unsigned char x[4] = { 0xff,0xff,0xff,0xff }
#define DISTINGUISHED_VALUE 0xffffffff /* 64bit extension flag */

/* to identify a cie */
#define DW_CIE_ID          ~(0x0)
#define DW_CIE_VERSION     1

typedef signed char Dwarf_Sbyte;
typedef unsigned char Dwarf_Ubyte;
typedef signed short Dwarf_Shalf;

/*
    On any change that makes libdwarf producer
    incompatible, increment this number.
    1->2->3 ...  */
#define  PRO_VERSION_MAGIC 0xdead1


#define DWARF_HALF_SIZE 2
#define DWARF_32BIT_SIZE 4
#define DWARF_64BIT_SIZE 8

/*
    producer:
    This struct is used to hold information about all
    debug* sections. On creating a new section, section
    names and indices are added to this struct
    definition in pro_section.h */
typedef struct Dwarf_P_Section_Data_s *Dwarf_P_Section_Data;

/*
    producer:
    This struct holds file entries or
    include file entries for the statement prologue.
    Defined in pro_line.h
*/
typedef struct Dwarf_P_F_Entry_s *Dwarf_P_F_Entry;

/*
    producer:
    This struct holds information for each cie. Defn in pro_frame.h
*/
typedef struct Dwarf_P_Cie_s *Dwarf_P_Cie;

/*
    producer:
    Struct to hold line number information, different from
    Dwarf_Line opaque type.
*/
typedef struct Dwarf_P_Line_s *Dwarf_P_Line;

/*
    producer:
    Struct to hold information about address ranges.
*/
typedef struct Dwarf_P_Simple_nameentry_s *Dwarf_P_Simple_nameentry;
typedef struct Dwarf_P_Simple_name_header_s *Dwarf_P_Simple_name_header;
typedef struct Dwarf_P_Arange_s *Dwarf_P_Arange;
typedef struct Dwarf_P_Per_Reloc_Sect_s *Dwarf_P_Per_Reloc_Sect;
typedef struct Dwarf_P_Per_Sect_String_Attrs_s *Dwarf_P_Per_Sect_String_Attrs;
typedef struct Dwarf_P_Dnames_s *Dwarf_P_Dnames;

/* Defined to get at the elf section numbers and section name
   indices in symtab for the dwarf sections
   Must match .rel.* names in _dwarf_rel_section_names
   exactly.
*/
#define         DEBUG_INFO      0
#define         DEBUG_LINE      1
#define         DEBUG_ABBREV    2
#define         DEBUG_FRAME     3
#define         DEBUG_ARANGES   4
#define         DEBUG_PUBNAMES  5
#define         DEBUG_FUNCNAMES 6
#define         DEBUG_TYPENAMES 7
#define         DEBUG_VARNAMES  8
#define         DEBUG_WEAKNAMES 9
#define         DEBUG_MACINFO   10 /* DWARF 2,3,4 only */
#define         DEBUG_LOC       11
#define         DEBUG_RANGES    12
#define         DEBUG_TYPES     13
#define         DEBUG_PUBTYPES  14
#define         DEBUG_NAMES     15 /* DWARF5. aka dnames */
#define         DEBUG_STR       16
#define         DEBUG_LINE_STR  17
#define         DEBUG_MACRO     18 /* DWARF 5. */
#define         DEBUG_LOCLISTS  19 /* DWARF 5. */
#define         DEBUG_RNGLISTS  20 /* DWARF 5. */

/* Maximum number of debug_* sections not including the relocations */
#define         NUM_DEBUG_SECTIONS      21

/*  The FORM codes available are defined in DWARF5
    on page 158, DW_LNCT_path  */
struct Dwarf_P_Line_format_s {
    /* DW_LNCT_path etc. */
    unsigned def_content_type;

    /* DW_FORM_string or DW_FORM_strp or DW_FORM_strp
        or DW_FORM_strp_sup or for dwo, some others. */
    unsigned def_form_code;
};

#define DW_LINE_FORMATS_MAX 6
/*  Describes the data needed to generate line table header info
    so we can vary the init at runtime. */
struct Dwarf_P_Line_Inits_s {
    unsigned pi_linetable_version; /* line table version number */
    unsigned pi_default_is_stmt; /* default value for is_stmt */

    /* Size of the smallest instruction, in bytes. */
    unsigned pi_minimum_instruction_length;

    /*  Normally opcode_base is determined by pi_version, but we
        allow manual setting here so we can generate data like
        GNU with a DWARF3 opcode base in a DWARF2 section.
        This determines how much of the header_opcode_lengths
        table is emitted in the line table header */
    unsigned pi_opcode_base;

    int      pi_line_base;   /* For line table header. */
    int      pi_line_range;  /* For line table header. */

    /* Make this >1 for VLIW machines.  DWARF4,DWARF5 */
    unsigned pi_maximum_operations_per_instruction;

    /* DWARF 5  */
    unsigned pi_segment_selector_size;
    unsigned pi_address_size;
    unsigned pi_segment_size;
    unsigned pi_directory_entry_format_count;
    struct Dwarf_P_Line_format_s pi_incformats[DW_LINE_FORMATS_MAX];

    unsigned pi_file_entry_format_count;
    struct Dwarf_P_Line_format_s pi_fileformats[DW_LINE_FORMATS_MAX];
};


struct Dwarf_P_Die_s {
    Dwarf_Unsigned di_offset; /* offset in debug info */
    char *di_abbrev;  /* abbreviation */
    Dwarf_Unsigned di_abbrev_nbytes; /* # of bytes in abbrev */
    Dwarf_Tag di_tag;
    Dwarf_P_Die di_parent; /* parent of current die */
    Dwarf_P_Die di_child; /* first child */
    /*  The last child field makes linking up children an O(1) operation,
        See pro_die.c. */
    Dwarf_P_Die di_last_child;
    Dwarf_P_Die di_left; /* left sibling */
    Dwarf_P_Die di_right; /* right sibling */
    Dwarf_P_Attribute di_attrs; /* list of attributes */
    Dwarf_P_Attribute di_last_attr; /* last attribute */
    int di_n_attr;  /* number of attributes */
    Dwarf_P_Debug di_dbg; /* For memory management */
    Dwarf_Unsigned di_marker;   /* used to attach symbols to dies */
};


/* producer fields */
struct Dwarf_P_Attribute_s {
    Dwarf_Half ar_attribute; /* Attribute Value. */
    Dwarf_Half ar_attribute_form; /* Attribute Form. */
    Dwarf_P_Die ar_ref_die; /* die pointer if form ref */
    char *ar_data; /* data, format given by form */
    Dwarf_Unsigned ar_nbytes; /* no. of bytes of data */
    Dwarf_Unsigned ar_rel_symidx; /* when attribute has a
        relocatable value, holds
        index of symbol in SYMTAB */
    Dwarf_Unsigned ar_debug_str_offset; /* Offset in .debug_str
        if non-zero. Zero offset never assigned a string. */
    Dwarf_Ubyte ar_rel_type;  /* relocation type */
    Dwarf_Unsigned ar_rel_offset; /* Offset of relocation within block */
    char ar_reloc_len; /* Number of bytes that relocation
        applies to. 4 or 8. Unused and may
        be 0 if if ar_rel_type is
        R_MIPS_NONE */
    Dwarf_P_Attribute ar_next;
    /*  set if form = DW_FORM_implicit_const; */
    Dwarf_Signed  ar_implicit_const;
};

/* A block of .debug_macinfo data: this forms a series of blocks.
** Each macinfo input is compressed immediately and put into
** the current block if room, else a newblock allocated.
** The space allocation is such that the block and the macinfo
** data are one malloc block: free with a pointer to this and the
** mb_data is freed automatically.
** Like the struct hack, but legal ANSI C.
*/
struct dw_macinfo_block_s {
    struct dw_macinfo_block_s *mb_next;
    unsigned long mb_avail_len;
    unsigned long mb_used_len;
    unsigned long mb_macinfo_data_space_len;
    char *mb_data;/* original malloc ptr. */
};

/*  dwarf_sn_kind is for the array of similarly-treated
    name -> cu ties
*/
enum dwarf_sn_kind { dwarf_snk_pubname,  /* .debug_pubnames */
    dwarf_snk_funcname,  /* SGI extension. */
    dwarf_snk_weakname,  /* SGI extension. */
    dwarf_snk_typename,  /* SGI extension. */
    dwarf_snk_varname,   /* SGI extension. */
    dwarf_snk_pubtype,   /* .debug_pubtypes */
    dwarf_snk_entrycount /* this one must be last */
};



/* The calls to add a varname etc use a list of
   these as the list.
*/
struct Dwarf_P_Simple_nameentry_s {
    Dwarf_P_Die sne_die;
    char *sne_name;
    int sne_name_len;
    Dwarf_P_Simple_nameentry sne_next;
};

/*  An array of these, each of which heads a list
    of Dwarf_P_Simple_nameentry
*/
struct Dwarf_P_Simple_name_header_s {
    Dwarf_P_Simple_nameentry sn_head;
    Dwarf_P_Simple_nameentry sn_tail;
    Dwarf_Signed sn_count;

    /*  Length that will be generated, not counting fixed header or
        trailer */
    Dwarf_Signed sn_net_len;
};
typedef int (*_dwarf_pro_reloc_name_func_ptr) (Dwarf_P_Debug dbg,
    int sec_index,
    Dwarf_Unsigned offset,/* r_offset */
    Dwarf_Unsigned symidx,
    enum Dwarf_Rel_Type type,
    int reltarget_length);

typedef int (*_dwarf_pro_reloc_length_func_ptr) (Dwarf_P_Debug dbg,
    int sec_index, Dwarf_Unsigned offset,/* r_offset */
    Dwarf_Unsigned start_symidx,
    Dwarf_Unsigned end_symidx,
    enum Dwarf_Rel_Type type,
    int reltarget_length);
typedef int (*_dwarf_pro_transform_relocs_func_ptr) (Dwarf_P_Debug dbg,
    Dwarf_Signed *
    new_sec_count);

/*
    Each slot in a block of slots could be:
    a binary stream relocation entry (32 or 64bit relocation data)
    a SYMBOLIC relocation entry.
    During creation sometimes we create multiple chained blocks,
    but sometimes we create a single long block.
    Before returning reloc data to caller,
    we switch to a single, long-enough,
    block.

    We make counters here Dwarf_Unsigned so that we
    get sufficient alignment. Since we use space after
    the struct (at malloc time) for user data which
    must have Dwarf_Unsigned alignment, this
    struct must have that alignment too.
*/
struct Dwarf_P_Relocation_Block_s {
    Dwarf_Unsigned rb_slots_in_block; /* slots in block, as created */
    Dwarf_Unsigned rb_next_slot_to_use; /* counter, start at 0. */
    struct Dwarf_P_Relocation_Block_s *rb_next;
    char *rb_where_to_add_next; /* pointer to next slot (might be past
        end, depending on
        rb_next_slot_to_use) */
    char *rb_data; /* data area */
};

/* One of these per potential relocation section
   So one per actual dwarf section.
   Left zeroed when not used (some sections have
   no relocations).
*/
struct Dwarf_P_Per_Reloc_Sect_s {
    unsigned long pr_reloc_total_count; /* total number of entries
        across all blocks */

    unsigned long pr_slots_per_block_to_alloc; /* at Block alloc, this
        is the default number of slots to use */

    int pr_sect_num_of_reloc_sect; /* sect number returned by
        de_callback_func() or de_callback_func_b() or_c()
        call, this is the sect
        number of the relocation section. */

    /* singly-linked list. add at and ('last') with count of blocks */
    struct Dwarf_P_Relocation_Block_s *pr_first_block;
    struct Dwarf_P_Relocation_Block_s *pr_last_block;
    unsigned long pr_block_count;
};

#define DEFAULT_SLOTS_PER_BLOCK 3

typedef struct memory_list_s {
  struct memory_list_s *prev;
  struct memory_list_s *next;
} memory_list_t;

struct Dwarf_P_Per_Sect_String_Attrs_s {
    int sect_sa_section_number;
    unsigned sect_sa_n_alloc;
    unsigned sect_sa_n_used;
    Dwarf_P_String_Attr sect_sa_list;
};

struct Dwarf_P_debug_str_entry_s {
    Dwarf_P_Debug  dse_dbg;
    /*  Name used initially with tfind. */
    char *dse_name;

    Dwarf_Unsigned dse_slen; /* includes space for NUL terminator */

    /*  See dse_has_table_offset below. */
    Dwarf_Unsigned dse_table_offset;

    /*  For tsearch a hash table exists and we have a table offset.
        dse_dbg->de_debug_str->ds_data + dse_table_offset
        points to the string iff dse_has_table_offset != 0. */
    unsigned char  dse_has_table_offset;
};

struct Dwarf_P_Str_stats_s {
    Dwarf_Unsigned ps_strp_count_debug_str;
    Dwarf_Unsigned ps_strp_len_debug_str;
    Dwarf_Unsigned ps_strp_len_debug_line_str;
    Dwarf_Unsigned ps_strp_reused_count;
    Dwarf_Unsigned ps_strp_reused_len;
};

struct Dwarf_P_Stats_s {
    Dwarf_Unsigned ps_str_count;
    Dwarf_Unsigned ps_str_total_length;
    struct Dwarf_P_Str_stats_s ps_strp;
    struct Dwarf_P_Str_stats_s ps_line_strp;
};

/* Fields used by producer */
struct Dwarf_P_Debug_s {
    /*  Used to catch dso passing dbg to another DSO with incompatible
        version of libdwarf See PRO_VERSION_MAGIC */
    int de_version_magic_number;

    Dwarf_Handler de_errhand;
    /*  de_user_data is provided so users can use it to readily tie
        a callback to anything they desire.  The contents are not
        used by libdwarf except to pass the data as a callback
        argument.  New in June 2011. Available in
        dwarf_pro_init_c() and its callback function.  */
    void *    de_user_data;
    Dwarf_Ptr de_errarg;

    /*  Call back function, used to create .debug* sections. Provided
        By user.  */
    Dwarf_Callback_Func de_callback_func;

    /*  Flags from producer_init call */
    Dwarf_Unsigned de_flags;

    /*  This holds information on debug info section
        stream output, including the stream data */
    Dwarf_P_Section_Data de_debug_sects;

    /*  Defaults set as DW_FORM_string,
        meaning not using .debug_str by default.
        This intended for the .debug_info section. */
    int de_debug_default_str_form;

    /* If form DW_FORM_strp */
    Dwarf_P_Section_Data de_debug_str;
    void *de_debug_str_hashtab; /* for tsearch */

    /* .debug_line_str section data if form DW_FORM_line_strp */
    Dwarf_P_Section_Data de_debug_line_str;
    void *de_debug_line_str_hashtab; /* for tsearch */

    /*  Pointer to the 'current active' section */
    Dwarf_P_Section_Data de_current_active_section;

    /*  Number of debug data streams globs. */
    Dwarf_Unsigned de_n_debug_sect;

    /*  File entry information, null terminated singly-linked list */
    Dwarf_P_F_Entry de_file_entries;
    Dwarf_P_F_Entry de_last_file_entry;
    Dwarf_Unsigned de_n_file_entries;

    /*  Has the directories used to search for source files */
    Dwarf_P_F_Entry de_inc_dirs;
    Dwarf_P_F_Entry de_last_inc_dir;
    Dwarf_Unsigned de_n_inc_dirs;

    /*  Has all the line number info for the stmt program */
    Dwarf_P_Line de_lines;
    Dwarf_P_Line de_last_line;

    /*  List of cie's for the debug unit */
    Dwarf_P_Cie de_frame_cies;
    Dwarf_P_Cie de_last_cie;
    Dwarf_Unsigned de_n_cie;

    /* Singly-linked list of fde's for the debug unit */
    Dwarf_P_Fde de_frame_fdes;
    Dwarf_P_Fde de_last_fde;
    Dwarf_Unsigned de_n_fde;

    /* First die, leads to all others */
    Dwarf_P_Die de_dies;

    /* Pointer to chain of aranges */
    Dwarf_P_Arange de_arange;
    Dwarf_P_Arange de_last_arange;
    Dwarf_Signed de_arange_count;

    /*  debug_names  de_dnames is base of dnames info
        before disk form */
    Dwarf_P_Dnames de_dnames;
    Dwarf_P_Section_Data de_dnames_sect;

    /* macinfo controls. */
    /* first points to beginning of the list during creation */
    struct dw_macinfo_block_s *de_first_macinfo;

    /* current points to the current, unfilled, block */
    struct dw_macinfo_block_s *de_current_macinfo;

    /* Pointer to the first section, to support reset_section_bytes */
    Dwarf_P_Section_Data de_first_debug_sect;

    /*  Handles pubnames, weaknames, etc. See dwarf_sn_kind in
        pro_opaque.h */
    struct Dwarf_P_Simple_name_header_s
        de_simple_name_headers[dwarf_snk_entrycount];

    /*  Relocation data. not all sections will actally have relocation
        info, of course.  de_reloc_sect, de_elf_sects, and de_sect_name_idx
        arrays are exactly in parallel. Not every de_elf_sect has
        any relocations for it, of course. */
    struct Dwarf_P_Per_Reloc_Sect_s de_reloc_sect[NUM_DEBUG_SECTIONS];
    int de_reloc_next_to_return; /* iterator on reloc sections
        (SYMBOLIC output) */

    /*  Used in remembering sections. See de_reloc_sect above.  */
    int de_elf_sects[NUM_DEBUG_SECTIONS];  /* elf sect number of
        the section itself, DEBUG_LINE for example */

    /*  Section name index or handle for the name of the symbol for
        DEBUG_LINE for example */
    Dwarf_Unsigned de_sect_name_idx[NUM_DEBUG_SECTIONS];

    int de_offset_reloc; /* offset reloc type, R_MIPS_32 for
        example. Specific to the ABI being
        produced. Relocates offset size
        field */
    int de_exc_reloc; /* reloc type specific to exception
        table relocs. */
    int de_ptr_reloc;  /* standard reloc type, R_MIPS_32 for
        example. Specific to the ABI being
        produced. relocates pointer size
        field */
    unsigned char de_irix_exc_augmentation; /* If non-zero means
        that producing an IRIX exception-table offset in a CIE header
        is allowed (depending on the augmentation string). */

    unsigned char de_dwarf_offset_size; /* dwarf  offset size. */
    unsigned char de_elf_offset_size;  /* object section offset size. */
    unsigned char de_pointer_size; /* size of address in target. */

    /*  Added April 19, 2017.  For DWARF5 */
    unsigned char de_segment_selector_size;

    unsigned char de_relocation_record_size; /* reloc record size
        varies by ABI and
        relocation-output
        method (stream or
        symbolic) */

    unsigned char de_64bit_extension;/* non-zero if creating 64 bit
        offsets using dwarf2-99
        extension proposal */

    unsigned char de_output_version; /* 2,3,4, or 5. The version number
        of the output. (not necessarily that of each section,
        which depends on the base version). */

    /*  Defaults will be mostly useless, but such do exist */
    unsigned       de_big_endian; /* if 0 target is little-endian */

    int de_ar_data_attribute_form; /* data8, data4 abi &version dependent */
    int de_ar_ref_attr_form; /* ref8 ref4 , abi dependent */

    /* simple name relocations */
    _dwarf_pro_reloc_name_func_ptr de_relocate_by_name_symbol;

    /* relocations for a length, requiring a pair of symbols */
    _dwarf_pro_reloc_length_func_ptr de_relocate_pair_by_symbol;

    _dwarf_pro_transform_relocs_func_ptr de_transform_relocs_to_disk;

    /* following used for macro buffers */
    unsigned long de_compose_avail;
    unsigned long de_compose_used_len;

    unsigned char de_same_endian;
    void (*de_copy_word) (void *, const void *, unsigned long);

    /*  Add new fields at the END of this struct to preserve some hope
        of sensible behavior on dbg passing between DSOs linked with
        mismatched libdwarf producer versions. */

    Dwarf_P_Marker de_markers;  /* pointer to array of markers */
    unsigned de_marker_n_alloc;
    unsigned de_marker_n_used;
    int de_sect_sa_next_to_return;  /* Iterator on sring attrib sects */
    /* String attributes data of each section. */
    struct Dwarf_P_Per_Sect_String_Attrs_s de_sect_string_attr[NUM_DEBUG_SECTIONS];

    /* Hold data needed to init line output flexibly. */
    struct Dwarf_P_Line_Inits_s de_line_inits;

    struct Dwarf_P_Stats_s de_stats;
};

#define CURRENT_VERSION_STAMP   2

int _dwarf_add_simple_name_entry(Dwarf_P_Debug dbg,
    Dwarf_P_Die die,
    char *entry_name,
    enum dwarf_sn_kind
    entrykind,
    Dwarf_Error * error);

enum dwarf_which_hash {
    _dwarf_hash_debug_str,
    _dwarf_hash_debug_line_str,
    _dwarf_hash_debug_str_sup
};

int
_dwarf_insert_or_find_in_debug_str(Dwarf_P_Debug dbg,
    char *name,
    enum  dwarf_which_hash,
    unsigned slen, /* includes space for trailing NUL */
    Dwarf_Unsigned *offset_in_debug_str,
    Dwarf_Error *error);

int _dwarf_log_extra_flagstrings(Dwarf_P_Debug dbg,
  const char *extra,
  int *err);
