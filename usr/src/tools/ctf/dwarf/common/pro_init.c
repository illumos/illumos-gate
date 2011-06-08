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
  Foundation, Inc., 59 Temple Place - Suite 330, Boston MA 02111-1307, 
  USA.

  Contact information:  Silicon Graphics, Inc., 1600 Amphitheatre Pky,
  Mountain View, CA 94043, or:

  http://www.sgi.com

  For further information regarding this notice, see:

  http://oss.sgi.com/projects/GenInfo/NoticeExplan

*/



#include "config.h"
#include "libdwarfdefs.h"
#include <stdio.h>
#include <string.h>
#include "pro_incl.h"
#include "pro_section.h"	/* for MAGIC_SECT_NO */
#include "pro_reloc_symbolic.h"
#include "pro_reloc_stream.h"


static void common_init(Dwarf_P_Debug dbg, Dwarf_Unsigned flags);

void *_dwarf_memcpy_swap_bytes(void *s1, const void *s2, size_t len);

/*--------------------------------------------------------------------
	This function sets up a new dwarf producing region. 
	flags: Indicates type of access method, one of DW_DLC* macros
	func(): Used to create a new object file, a call back function
	errhand(): Error Handler provided by user
	errarg: Argument to errhand()
	error: returned error value
--------------------------------------------------------------------*/
    /* We want the following to have an elf section number that matches 
       'nothing' */
static struct Dwarf_P_Section_Data_s init_sect = {
    MAGIC_SECT_NO, 0, 0, 0, 0
};

Dwarf_P_Debug
dwarf_producer_init_b(Dwarf_Unsigned flags,
		      Dwarf_Callback_Func_b func,
		      Dwarf_Handler errhand,
		      Dwarf_Ptr errarg, Dwarf_Error * error)
{
    Dwarf_P_Debug dbg;
    dbg = (Dwarf_P_Debug) _dwarf_p_get_alloc(NULL,
					     sizeof(struct
						    Dwarf_P_Debug_s));
    if (dbg == NULL) {
	DWARF_P_DBG_ERROR(dbg, DW_DLE_DBG_ALLOC,
			  (Dwarf_P_Debug) DW_DLV_BADADDR);
    }
    memset((void *) dbg,0, sizeof(struct Dwarf_P_Debug_s));
    /* For the time being */
    if (func == NULL) {
	DWARF_P_DBG_ERROR(dbg, DW_DLE_NO_CALLBACK_FUNC,
			  (Dwarf_P_Debug) DW_DLV_BADADDR);
    }
    dbg->de_func_b = func;
    dbg->de_errhand = errhand;
    dbg->de_errarg = errarg;
    common_init(dbg, flags);
    return dbg;

}

Dwarf_P_Debug
dwarf_producer_init(Dwarf_Unsigned flags,
		    Dwarf_Callback_Func func,
		    Dwarf_Handler errhand,
		    Dwarf_Ptr errarg, Dwarf_Error * error)
{

    Dwarf_P_Debug dbg;



    dbg = (Dwarf_P_Debug) _dwarf_p_get_alloc(NULL,
					     sizeof(struct
						    Dwarf_P_Debug_s));
    if (dbg == NULL) {
	DWARF_P_DBG_ERROR(dbg, DW_DLE_DBG_ALLOC,
			  (Dwarf_P_Debug) DW_DLV_BADADDR);
    }
    memset((void *) dbg,0, sizeof(struct Dwarf_P_Debug_s));
    /* For the time being */
    if (func == NULL) {
	DWARF_P_DBG_ERROR(dbg, DW_DLE_NO_CALLBACK_FUNC,
			  (Dwarf_P_Debug) DW_DLV_BADADDR);
    }
    dbg->de_func = func;
    dbg->de_errhand = errhand;
    dbg->de_errarg = errarg;
    common_init(dbg, flags);
    return dbg;
}
static void
common_init(Dwarf_P_Debug dbg, Dwarf_Unsigned flags)
{
    unsigned int k;


    dbg->de_version_magic_number = PRO_VERSION_MAGIC;
    dbg->de_n_debug_sect = 0;
    dbg->de_debug_sects = &init_sect;
    dbg->de_current_active_section = &init_sect;
    dbg->de_flags = flags;

    /* Now, with flags set, can use 64bit tests */



#if  defined(HAVE_DWARF2_99_EXTENSION)
    /* Revised 64 bit output, using distingushed values. Per 1999
       dwarf2 revision This produces 64bit extension with ia64 objects.

       Some might want library run time selection of offset size. Not
       provided here at present. */
    dbg->de_64bit_extension = (IS_64BIT(dbg) ? 1 : 0);
    dbg->de_pointer_size = (IS_64BIT(dbg) ? 8 : 4);
    dbg->de_offset_size = (IS_64BIT(dbg) ? 8 : 4);
    dbg->de_ptr_reloc =
	IS_64BIT(dbg) ? Get_REL64_isa(dbg) : Get_REL32_isa(dbg);
    /* Non-MIPS, dwarf lengths and offsets are 32 bits even for 64bit
       pointer environments. */
    /* Get_REL??_isa here supports 64bit-offset dwarf. For 64bit, we
       emit the extension bytes. */

    dbg->de_offset_reloc = IS_64BIT(dbg) ? Get_REL64_isa(dbg)
	: Get_REL32_isa(dbg);
#elif defined(HAVE_OLD_DWARF2_32BIT_OFFSET)
    /* This is cygnus 32bit offset, as specified in pure dwarf2 v2.0.0 */
    dbg->de_64bit_extension = 0;
    dbg->de_pointer_size = (IS_64BIT(dbg) ? 8 : 4);
    dbg->de_offset_size = (IS_64BIT(dbg) ? 4 : 4);
    dbg->de_ptr_reloc =
	IS_64BIT(dbg) ? Get_REL64_isa(dbg) : Get_REL32_isa(dbg);
    /* non-MIPS, dwarf lengths and offsets are 32 bits even for 64bit
       pointer environments. */
    /* Get_REL32_isa here supports 64-bit-pointer dwarf with pure
       dwarf2 v2.0.0 32bit offsets, as emitted by cygnus tools. And
       pure 32 bit offset dwarf for 32bit pointer apps. */

    dbg->de_offset_reloc = Get_REL32_isa(dbg);
#else
    /* MIPS-SGI 32 or 64, where offsets and lengths are both 64 bit for 
       64bit pointer objects and both 32 bit for 32bit pointer
       objects. And a dwarf-reader must check elf info to tell which
       applies. */
    dbg->de_64bit_extension = 0;
    dbg->de_pointer_size = (IS_64BIT(dbg) ? 8 : 4);
    dbg->de_offset_size = (IS_64BIT(dbg) ? 8 : 4);
    dbg->de_ptr_reloc =
	IS_64BIT(dbg) ? Get_REL64_isa(dbg) : Get_REL32_isa(dbg);
    dbg->de_offset_reloc = dbg->de_ptr_reloc;
#endif
    dbg->de_exc_reloc = Get_REL_SEGREL_isa(dbg);

    dbg->de_is_64bit = IS_64BIT(dbg);


    if (flags & DW_DLC_SYMBOLIC_RELOCATIONS) {
	dbg->de_relocation_record_size =
	    sizeof(struct Dwarf_Relocation_Data_s);
    } else {
#if HAVE_ELF64_GETEHDR
	dbg->de_relocation_record_size =
	    IS_64BIT(dbg) ? sizeof(Elf64_Rel) : sizeof(Elf32_Rel);
#else
	dbg->de_relocation_record_size = sizeof(Elf32_Rel);
#endif
    }

    if (dbg->de_offset_size == 8) {
	dbg->de_ar_data_attribute_form = DW_FORM_data8;
	dbg->de_ar_ref_attr_form = DW_FORM_ref8;
    } else {
	dbg->de_ar_data_attribute_form = DW_FORM_data4;
	dbg->de_ar_ref_attr_form = DW_FORM_ref4;
    }

    if (flags & DW_DLC_SYMBOLIC_RELOCATIONS) {
	dbg->de_reloc_name = _dwarf_pro_reloc_name_symbolic;
	dbg->de_reloc_pair = _dwarf_pro_reloc_length_symbolic;
	dbg->de_transform_relocs_to_disk =
	    _dwarf_symbolic_relocs_to_disk;
    } else {
	if (IS_64BIT(dbg)) {
	    dbg->de_reloc_name = _dwarf_pro_reloc_name_stream64;
	} else {
	    dbg->de_reloc_name = _dwarf_pro_reloc_name_stream32;
	}
	dbg->de_reloc_pair = 0;
	dbg->de_transform_relocs_to_disk = _dwarf_stream_relocs_to_disk;
    }
    for (k = 0; k < NUM_DEBUG_SECTIONS; ++k) {

	Dwarf_P_Per_Reloc_Sect prel = &dbg->de_reloc_sect[k];

	prel->pr_slots_per_block_to_alloc = DEFAULT_SLOTS_PER_BLOCK;
    }
    /* First assume host, target same endianness */
    dbg->de_same_endian = 1;
    dbg->de_copy_word = memcpy;
#ifdef WORDS_BIGENDIAN
    /* host is big endian, so what endian is target? */
    if (flags & DW_DLC_TARGET_LITTLEENDIAN) {
	dbg->de_same_endian = 0;
	dbg->de_copy_word = _dwarf_memcpy_swap_bytes;
    }
#else /* little endian */
    /* host is little endian, so what endian is target? */
    if (flags & DW_DLC_TARGET_BIGENDIAN) {
	dbg->de_same_endian = 0;
	dbg->de_copy_word = _dwarf_memcpy_swap_bytes;
    }
#endif /* !WORDS_BIGENDIAN */


    return;

}
