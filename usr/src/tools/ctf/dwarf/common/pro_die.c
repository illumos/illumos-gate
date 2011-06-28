/*

  Copyright (C) 2000 Silicon Graphics, Inc.  All Rights Reserved.

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
#include "pro_die.h"

#ifndef R_MIPS_NONE
#define R_MIPS_NONE 0
#endif

/* adds an attribute to a die */
void _dwarf_pro_add_at_to_die(Dwarf_P_Die die, Dwarf_P_Attribute attr);

/*----------------------------------------------------------------------------
	This function creates a new die. 
	tag: tag of the new die to be created
	parent,child,left,right: specify neighbors of the new die. Only
	    one of these may be non-null
-----------------------------------------------------------------------------*/
Dwarf_P_Die
dwarf_new_die(Dwarf_P_Debug dbg,
	      Dwarf_Tag tag,
	      Dwarf_P_Die parent,
	      Dwarf_P_Die child,
	      Dwarf_P_Die left, Dwarf_P_Die right, Dwarf_Error * error)
{
    Dwarf_P_Die new_die, ret_die;

    new_die = (Dwarf_P_Die)
	_dwarf_p_get_alloc(dbg, sizeof(struct Dwarf_P_Die_s));
    if (new_die == NULL) {
	DWARF_P_DBG_ERROR(dbg, DW_DLE_DIE_ALLOC,
			  (Dwarf_P_Die) DW_DLV_BADADDR);
    }
    new_die->di_parent = NULL;
    new_die->di_left = NULL;
    new_die->di_right = NULL;
    new_die->di_child = NULL;
    new_die->di_tag = tag;
    ret_die =
	dwarf_die_link(new_die, parent, child, left, right, error);
    return ret_die;
}

/*----------------------------------------------------------------------------
	This function links up a die to specified neighbors
	parent,child,left,right: specify neighbors of the new die. Only
	    one of these may be non-null
-----------------------------------------------------------------------------*/
Dwarf_P_Die
dwarf_die_link(Dwarf_P_Die new_die,
	       Dwarf_P_Die parent,
	       Dwarf_P_Die child,
	       Dwarf_P_Die left, Dwarf_P_Die right, Dwarf_Error * error)
{
    int n_nulls;		/* to count # of non null neighbors */

    n_nulls = 0;
    if (parent != NULL) {
	n_nulls++;
	new_die->di_parent = parent;
	if (parent->di_child) {	/* got to traverse the child's siblings 
				 */
	    Dwarf_P_Die curdie;

	    curdie = parent->di_child;
	    while (curdie->di_right)
		curdie = curdie->di_right;
	    curdie->di_right = new_die;	/* attach to sibling list */
	    new_die->di_left = curdie;	/* back pointer */
	} else
	    parent->di_child = new_die;
    }
    if (child != NULL) {
	n_nulls++;
	new_die->di_child = child;
	if (child->di_parent) {
	    DWARF_P_DBG_ERROR(NULL, DW_DLE_PARENT_EXISTS,
			      (Dwarf_P_Die) DW_DLV_BADADDR);
	} else
	    child->di_parent = new_die;
    }
    if (left != NULL) {
	n_nulls++;
	new_die->di_left = left;
	if (left->di_right)	/* there's already a right sibl, lets
				   insert */
	    new_die->di_right = left->di_right;
	left->di_right = new_die;
	/* add parent pointer */
	if (new_die->di_parent) {
	    DWARF_P_DBG_ERROR(NULL, DW_DLE_PARENT_EXISTS,
			      (Dwarf_P_Die) DW_DLV_BADADDR);
	} else
	    new_die->di_parent = left->di_parent;
    }
    if (right != NULL) {
	n_nulls++;
	new_die->di_right = right;
	if (right->di_left)	/* left sibl exists, try inserting */
	    new_die->di_left = right->di_left;
	right->di_left = new_die;
	if (new_die->di_parent) {
	    DWARF_P_DBG_ERROR(NULL, DW_DLE_PARENT_EXISTS,
			      (Dwarf_P_Die) DW_DLV_BADADDR);
	} else
	    new_die->di_parent = right->di_parent;
    }
    if (n_nulls > 1) {		/* multiple neighbors, error */
	DWARF_P_DBG_ERROR(NULL, DW_DLE_EXTRA_NEIGHBORS,
			  (Dwarf_P_Die) DW_DLV_BADADDR);
    }
    return new_die;

}

/*----------------------------------------------------------------------------
	This function adds a die to dbg struct. It should be called using 
	the root of all the dies.
-----------------------------------------------------------------------------*/
Dwarf_Unsigned
dwarf_add_die_to_debug(Dwarf_P_Debug dbg,
		       Dwarf_P_Die first_die, Dwarf_Error * error)
{
    if (first_die == NULL) {
	DWARF_P_DBG_ERROR(dbg, DW_DLE_DIE_NULL, DW_DLV_NOCOUNT);
    }
    if (first_die->di_tag != DW_TAG_compile_unit) {
	DWARF_P_DBG_ERROR(dbg, DW_DLE_WRONG_TAG, DW_DLV_NOCOUNT);
    }
    dbg->de_dies = first_die;
    return 0;
}

int
_dwarf_pro_add_AT_stmt_list(Dwarf_P_Debug dbg,
			    Dwarf_P_Die first_die, Dwarf_Error * error)
{
    Dwarf_P_Attribute new_attr;
    int uwordb_size = dbg->de_offset_size;

    /* Add AT_stmt_list attribute */
    new_attr = (Dwarf_P_Attribute)
	_dwarf_p_get_alloc(NULL, sizeof(struct Dwarf_P_Attribute_s));
    if (new_attr == NULL) {
	DWARF_P_DBG_ERROR(NULL, DW_DLE_ATTR_ALLOC, DW_DLV_NOCOUNT);
    }

    new_attr->ar_attribute = DW_AT_stmt_list;
    new_attr->ar_attribute_form = dbg->de_ar_data_attribute_form;
    new_attr->ar_rel_type = dbg->de_offset_reloc;

    new_attr->ar_nbytes = uwordb_size;
    new_attr->ar_next = NULL;
    new_attr->ar_reloc_len = uwordb_size;
    new_attr->ar_data = (char *)
	_dwarf_p_get_alloc(NULL, uwordb_size);
    if (new_attr->ar_data == NULL) {
	DWARF_P_DBG_ERROR(NULL, DW_DLE_ADDR_ALLOC, DW_DLV_NOCOUNT);
    }
    {
	Dwarf_Unsigned du = 0;

	WRITE_UNALIGNED(dbg, (void *) new_attr->ar_data,
			(const void *) &du, sizeof(du), uwordb_size);
    }

    _dwarf_pro_add_at_to_die(first_die, new_attr);
    return 0;
}

/*-----------------------------------------------------------------------------
	Add AT_name attribute to die
------------------------------------------------------------------------------*/
Dwarf_P_Attribute
dwarf_add_AT_name(Dwarf_P_Die die, char *name, Dwarf_Error * error)
{
    Dwarf_P_Attribute new_attr;

    if (die == NULL) {
	DWARF_P_DBG_ERROR(NULL, DW_DLE_DIE_NULL,
			  (Dwarf_P_Attribute) DW_DLV_BADADDR);
    }
    new_attr = (Dwarf_P_Attribute)
	_dwarf_p_get_alloc(NULL, sizeof(struct Dwarf_P_Attribute_s));
    if (new_attr == NULL) {
	DWARF_P_DBG_ERROR(NULL, DW_DLE_ATTR_ALLOC,
			  (Dwarf_P_Attribute) DW_DLV_BADADDR);
    }

    /* fill in the information */
    new_attr->ar_attribute = DW_AT_name;
    /* assume that form is string, no debug_str yet */
    new_attr->ar_attribute_form = DW_FORM_string;
    new_attr->ar_nbytes = strlen(name) + 1;
    new_attr->ar_next = NULL;
    new_attr->ar_reloc_len = 0;
    new_attr->ar_data = (char *)
	_dwarf_p_get_alloc(NULL, strlen(name) + 1);
    if (new_attr->ar_data == NULL) {
	DWARF_P_DBG_ERROR(NULL, DW_DLE_STRING_ALLOC,
			  (Dwarf_P_Attribute) DW_DLV_BADADDR);
    }
    strcpy(new_attr->ar_data, name);

    new_attr->ar_rel_type = R_MIPS_NONE;

    /* add attribute to the die */
    _dwarf_pro_add_at_to_die(die, new_attr);
    return new_attr;
}


/*-----------------------------------------------------------------------------
	Add AT_comp_dir attribute to die
------------------------------------------------------------------------------*/
Dwarf_P_Attribute
dwarf_add_AT_comp_dir(Dwarf_P_Die ownerdie,
		      char *current_working_directory,
		      Dwarf_Error * error)
{
    Dwarf_P_Attribute new_attr;

    if (ownerdie == NULL) {
	DWARF_P_DBG_ERROR(NULL, DW_DLE_DIE_NULL,
			  (Dwarf_P_Attribute) DW_DLV_BADADDR);
    }
    new_attr = (Dwarf_P_Attribute)
	_dwarf_p_get_alloc(NULL, sizeof(struct Dwarf_P_Attribute_s));
    if (new_attr == NULL) {
	DWARF_P_DBG_ERROR(NULL, DW_DLE_ATTR_ALLOC,
			  (Dwarf_P_Attribute) DW_DLV_BADADDR);
    }

    /* fill in the information */
    new_attr->ar_attribute = DW_AT_comp_dir;
    /* assume that form is string, no debug_str yet */
    new_attr->ar_attribute_form = DW_FORM_string;
    new_attr->ar_nbytes = strlen(current_working_directory) + 1;
    new_attr->ar_next = NULL;
    new_attr->ar_reloc_len = 0;
    new_attr->ar_data = (char *)
	_dwarf_p_get_alloc(NULL, strlen(current_working_directory) + 1);
    if (new_attr->ar_data == NULL) {
	DWARF_P_DBG_ERROR(NULL, DW_DLE_STRING_ALLOC,
			  (Dwarf_P_Attribute) DW_DLV_BADADDR);
    }
    strcpy(new_attr->ar_data, current_working_directory);

    new_attr->ar_rel_type = R_MIPS_NONE;

    /* add attribute to the die */
    _dwarf_pro_add_at_to_die(ownerdie, new_attr);
    return new_attr;
}

int
_dwarf_pro_add_AT_fde(Dwarf_P_Debug dbg,
		      Dwarf_P_Die die,
		      Dwarf_Unsigned offset, Dwarf_Error * error)
{
    Dwarf_P_Attribute new_attr;
    int uwordb_size = dbg->de_offset_size;

    if (die == NULL) {
	DWARF_P_DBG_ERROR(NULL, DW_DLE_DIE_NULL, -1);
    }
    new_attr = (Dwarf_P_Attribute)
	_dwarf_p_get_alloc(NULL, sizeof(struct Dwarf_P_Attribute_s));
    if (new_attr == NULL) {
	DWARF_P_DBG_ERROR(NULL, DW_DLE_ATTR_ALLOC, -1);
    }

    /* fill in the information */
    new_attr->ar_attribute = DW_AT_MIPS_fde;
    new_attr->ar_attribute_form = dbg->de_ar_data_attribute_form;;
    new_attr->ar_rel_type = dbg->de_offset_reloc;
    new_attr->ar_nbytes = uwordb_size;
    new_attr->ar_next = NULL;
    new_attr->ar_reloc_len = uwordb_size;
    new_attr->ar_data = (char *)
	_dwarf_p_get_alloc(NULL, uwordb_size);
    if (new_attr->ar_data == NULL) {
	DWARF_P_DBG_ERROR(NULL, DW_DLE_ADDR_ALLOC, DW_DLV_NOCOUNT);
    }
    {
	Dwarf_Unsigned du = offset;

	WRITE_UNALIGNED(dbg, (void *) new_attr->ar_data,
			(const void *) &du, sizeof(du), uwordb_size);
    }

    _dwarf_pro_add_at_to_die(die, new_attr);

    return 0;
}

int
_dwarf_pro_add_AT_macro_info(Dwarf_P_Debug dbg,
			     Dwarf_P_Die die,
			     Dwarf_Unsigned offset, Dwarf_Error * error)
{
    Dwarf_P_Attribute new_attr;
    int uwordb_size = dbg->de_offset_size;

    if (die == NULL) {
	DWARF_P_DBG_ERROR(NULL, DW_DLE_DIE_NULL, -1);
    }
    new_attr = (Dwarf_P_Attribute)
	_dwarf_p_get_alloc(NULL, sizeof(struct Dwarf_P_Attribute_s));
    if (new_attr == NULL) {
	DWARF_P_DBG_ERROR(NULL, DW_DLE_ATTR_ALLOC, -1);
    }

    /* fill in the information */
    new_attr->ar_attribute = DW_AT_macro_info;
    new_attr->ar_attribute_form = dbg->de_ar_data_attribute_form;
    new_attr->ar_rel_type = dbg->de_offset_reloc;

    new_attr->ar_nbytes = uwordb_size;
    new_attr->ar_next = NULL;
    new_attr->ar_reloc_len = uwordb_size;
    new_attr->ar_data = (char *)
	_dwarf_p_get_alloc(NULL, uwordb_size);
    if (new_attr->ar_data == NULL) {
	DWARF_P_DBG_ERROR(NULL, DW_DLE_ADDR_ALLOC, DW_DLV_NOCOUNT);
    }
    {
	Dwarf_Unsigned du = offset;

	WRITE_UNALIGNED(dbg, (void *) new_attr->ar_data,
			(const void *) &du, sizeof(du), uwordb_size);
    }

    _dwarf_pro_add_at_to_die(die, new_attr);

    return 0;
}


void
_dwarf_pro_add_at_to_die(Dwarf_P_Die die, Dwarf_P_Attribute attr)
{
    if (die->di_last_attr) {
	die->di_last_attr->ar_next = attr;
	die->di_last_attr = attr;
	die->di_n_attr++;
    } else {
	die->di_n_attr = 1;
	die->di_attrs = die->di_last_attr = attr;
    }
}
