/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2007-2009 Myricom, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _mcp_gen_header_h
#define _mcp_gen_header_h

/**
   @file
   This file define a standard header used as a first entry point to
   exchange information between firmware/driver and driver. 

   The header structure can be anywhere in the mcp. It will usually be in
   the .data section, because some fields needs to be initialized at
   compile time.

   The 32bit word at offset MX_HEADER_PTR_OFFSET in the mcp must
   contains the location of the header. 

   Typically a MCP will start with the following:
   @code
   .text
     .space 52    ! to help catch MEMORY_INT errors
     bt start     ! jump to real code
     nop
     .long _gen_mcp_header
    @endcode
   
   The source will have a definition like:
   @code
   mcp_gen_header_t gen_mcp_header = {
      .header_length = sizeof(mcp_gen_header_t),
      .mcp_type = MCP_TYPE_XXX,
      .version = "something $Id: mcp_gen_header.h,v 1.9 2009-02-27 16:29:36 loic Exp $",
      .mcp_globals = (unsigned)&Globals
   };
   @endcode
   In most case using the convenience MCP_GEN_HEADER_DECL() macro is simpler than
   doing a full manual declaration.
 
*/


#define MCP_HEADER_PTR_OFFSET  0x3c

#define MCP_TYPE_MX 0x4d582020 /* "MX  " */
#define MCP_TYPE_PCIE 0x70636965 /* "PCIE" pcie-only MCP */
#define MCP_TYPE_ETH 0x45544820 /* "ETH " */
#define MCP_TYPE_MCP0 0x4d435030 /* "MCP0" */
#define MCP_TYPE_DFLT 0x20202020 /* "    " */
#define MCP_TYPE_ETHZ 0x4554485a /* "ETHZ" */

struct mcp_gen_header {
  /* the first 4 fields are filled at compile time */
  unsigned header_length;
  unsigned mcp_type;
  char version[128];
  unsigned mcp_private; /* pointer to mcp-type specific structure */

  /* filled by the MCP at run-time */
  unsigned sram_size;
  unsigned string_specs;  /* either the original STRING_SPECS or a superset */
  unsigned string_specs_len;

  /* Fields above this comment are guaranteed to be present.

     Fields below this comment are extensions added in later versions
     of this struct, drivers should compare the header_length against
     offsetof(field) to check wether a given MCP implements them.

     Never remove any field.  Keep everything naturally align.
  */

  /* Specifies if the running mcp is mcp0, 1, or 2. */
  unsigned char mcp_index;
  unsigned char disable_rabbit;
  unsigned char unaligned_tlp;
  unsigned char pcie_link_algo;
  unsigned counters_addr;
  unsigned copy_block_info; /* for small mcps loaded with "lload -d" */
  unsigned short handoff_id_major; /* must be equal */
  unsigned short handoff_id_caps; /* bitfield: new mcp must have superset */
  unsigned msix_table_addr; /* start address of msix table in firmware */
  unsigned bss_addr; /* start of bss */
  unsigned features;
  unsigned ee_hdr_addr;
  /* 8 */
};
typedef struct mcp_gen_header mcp_gen_header_t;

struct zmcp_info {
  unsigned info_len;
  unsigned zmcp_addr;
  unsigned zmcp_len;
  unsigned mcp_edata;
};


#endif /* _mcp_gen_header_h */
