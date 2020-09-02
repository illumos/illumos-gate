/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1999,2000,2001,2002,2003,2004  Free Software Foundation, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2020 RackTop Systems, Inc.
 */

#ifndef	_SYS_DMU_OBJSET_H
#define	_SYS_DMU_OBJSET_H

#define	OBJSET_PHYS_SIZE_V1	1024
#define	OBJSET_PHYS_SIZE_V2	2048
#define	OBJSET_PHYS_SIZE_V3	4096

typedef struct objset_phys {
	dnode_phys_t os_meta_dnode;
	zil_header_t os_zil_header;
	uint64_t os_type;
	uint64_t os_flags;
	uint8_t os_portable_mac[ZIO_OBJSET_MAC_LEN];
	uint8_t os_local_mac[ZIO_OBJSET_MAC_LEN];
	char os_pad0[OBJSET_PHYS_SIZE_V2 - sizeof (dnode_phys_t)*3 -
	    sizeof (zil_header_t) - sizeof (uint64_t)*2 -
	    2*ZIO_OBJSET_MAC_LEN];
	dnode_phys_t os_userused_dnode;
	dnode_phys_t os_groupused_dnode;
	dnode_phys_t os_projectused_dnode;
	char os_pad1[OBJSET_PHYS_SIZE_V3 - OBJSET_PHYS_SIZE_V2 -
	    sizeof (dnode_phys_t)];
} objset_phys_t;

#endif /* _SYS_DMU_OBJSET_H */
