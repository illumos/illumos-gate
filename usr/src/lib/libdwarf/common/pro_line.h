/*

  Copyright (C) 2000,2004 Silicon Graphics, Inc.  All Rights Reserved.
  Portions Copyright 2007-2010 Sun Microsystems, Inc. All rights reserved.
  Portions Copyright 2017  David Anderson  All rights reserved.

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


#define DW_LINE_VERSION2   2
#define DW_LINE_VERSION3   3
#define DW_LINE_VERSION4   4

#if defined(__i386) || defined(__x86_64)
#define MIN_INST_LENGTH			1
#elif defined(__s390__) || defined(__s390x__)
/*  Correct value unknown.  This is temporary
    as we need a better way to set this (in
    dwarfgen). This at least works for dwarfgen testing
    at this point, avoids an error. */
#define MIN_INST_LENGTH			1
#else
/*  1 is not necessarily the most efficient (space-wise) for various
    architectures, but will allow line tables to be generated
    without error if the input expects the min length to be 1.
    When using dwarfgen the setting should be that of the
    output arch, not the host (unless the two essentially match).  */
#define MIN_INST_LENGTH			4
#endif
#define DEFAULT_IS_STMT			false
/*  line base and range are temporarily defines.
    They need to be calculated later. */
#define LINE_BASE   -1
#define LINE_RANGE   4

#define OPCODE_BASE  10 /* DWARF2.  13 in DWARF3, 4, 5  */
#define MAX_OPCODE   255



/* This struct holds file or include_dir
   entries for the statement prologue.
   Defined in pro_line.h */
struct Dwarf_P_F_Entry_s {
    char *dfe_name;
    Dwarf_P_F_Entry dfe_next;

    /* DWARF 2,3,4, files only not inc dirs */
    char *dfe_args;  /* has dir index, time of modification,
        length in bytes. Encodes as leb128 */
    int dfe_nbytes; /* number of bytes in args */

    /*  Dwarf5 Use or not depends on file_name_entry_format
        actually used.  */
    unsigned dfe_index;
    Dwarf_Unsigned dfe_timestamp;
    unsigned dfe_size;
    unsigned char dfe_md5[16];

};


/*
    Struct holding line number information for each of the producer
    line entries
*/
struct Dwarf_P_Line_s {
    /* code address */
    Dwarf_Addr dpl_address;

    /* file index, index into file entry */
    Dwarf_Unsigned dpl_file;

    /* line number */
    Dwarf_Unsigned dpl_line;

    /* column number */
    Dwarf_Unsigned dpl_column;

    /* whether its a beginning of a stmt */
    Dwarf_Ubyte dpl_is_stmt;

    /* whether its a beginning of basic blk */
    Dwarf_Ubyte dpl_basic_block;

    /* used to store opcodes set_address, and end_seq */
    Dwarf_Ubyte dpl_opc;

    /*  Used only for relocations.  Has index of symbol relative to
        which relocation has to be done (the S part in S + A) */
    Dwarf_Unsigned dpl_r_symidx;

    Dwarf_P_Line dpl_next;

    Dwarf_Ubyte    dpl_prologue_end;   /* DWARF3 */
    Dwarf_Ubyte    dpl_epilogue_begin; /* DWARF3 */
    Dwarf_Unsigned dpl_isa;            /* DWARF3 */
    Dwarf_Unsigned dpl_discriminator;  /* DWARF4 */

};

/*
    to initialize state machine registers, definition in
    pro_line.c
*/
void _dwarf_pro_reg_init(Dwarf_P_Debug dbg,Dwarf_P_Line);

void _dwarf_init_default_line_header_vals(Dwarf_P_Debug dbg);
