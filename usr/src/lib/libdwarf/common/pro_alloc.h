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
  Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston MA 02110-1301,
  USA.

*/


#ifndef PRO_ALLOC_H
#define PRO_ALLOC_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


Dwarf_Ptr _dwarf_p_get_alloc(Dwarf_P_Debug, Dwarf_Unsigned);

void dwarf_p_dealloc(Dwarf_Small * ptr); /* DO NOT USE. */
void _dwarf_p_dealloc(Dwarf_P_Debug,Dwarf_Small * ptr);

void _dwarf_p_dealloc_all(Dwarf_P_Debug dbg);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* PRO_ALLOC_H */
