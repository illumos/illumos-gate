/***************************************************************************
 * CVSID: $Id$
 *
 * ids.h : Lookup names from hardware identifiers
 *
 * Copyright (C) 2004 David Zeuthen, <david@fubar.dk>
 *
 * Licensed under the Academic Free License version 2.1
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 **************************************************************************/

#ifndef IDS_H
#define IDS_H

#include <glib.h>

void ids_init (void);

void
ids_find_pci (int vendor_id, int product_id,
	      int subsys_vendor_id, int subsys_product_id,
	      char **vendor_name, char **product_name,
	      char **subsys_vendor_name, char **subsys_product_name);

void
ids_find_usb (int vendor_id, int product_id,
	      char **vendor_name, char **product_name);

void
ids_find_pnp (const char *pnp_id, char **pnp_description);


#endif /* IDS_H */
