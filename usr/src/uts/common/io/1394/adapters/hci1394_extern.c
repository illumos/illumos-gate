/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * hci1394_extern.c
 *    Central location for externs.  There are two exceptions to this,
 *    hci1394_statep (located in hci1394.c) and hci1394_evts (located in
 *    hci1394_s1394if.c).
 */

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/modctl.h>
#include <sys/stat.h>

#include <sys/1394/h1394.h>

#include <sys/1394/adapters/hci1394.h>



/*
 * The 1394 bus ticks are in 125uS increments.  split_timeout is represented in
 * 1394 bus ticks.  800 bus ticks is 100mS.
 */
uint32_t hci1394_split_timeout = 800;


/*
 * 1394 address map for OpenHCI adapters.
 *
 * This is what is reported to the services layer.  The hci1394 driver does not
 * modify the HW to reflect this.  This should reflect what the OpenHCI 1.0 HW
 * is set to.  The comments below give the actual address ranges where the
 * actual structure has the format of - start address, size, type.
 *
 * physical =>		0x0000000000000000 - 0x00000000FFFFFFFF
 * posted write =>	0x0000000100000000 - 0x0000FFFEFFFFFFFF
 * normal =>		0x0000FFFF00000000 - 0x0000FFFFEFFFFFFF
 * csr =>		0x0000FFFFF0000000 - 0x0000FFFFFFFFFFFF
 */
h1394_addr_map_t hci1394_addr_map[HCI1394_ADDR_MAP_SIZE] = {
	{0x0000000000000000, 0x0000000100000000, H1394_ADDR_PHYSICAL},
	{0x0000000100000000, 0x0000FFFE00000000, H1394_ADDR_POSTED_WRITE},
	{0x0000FFFF00000000, 0x00000000F0000000, H1394_ADDR_NORMAL},
	{0x0000FFFFF0000000, 0x0000000010000000, H1394_ADDR_CSR}
};


/* Max number of uS to wait for phy reads & writes to finish */
uint_t hci1394_phy_delay_uS = 10;

/*
 * Time to wait for PHY to SCLK to be stable. There does not seem to be standard
 * time for how long wait for the PHY to come up. The problem is that the PHY
 * provides a clock to the link layer and if that is not stable, we could get a
 * PCI timeout error when reading/writing a phy register (and maybe an OpenHCI
 * register?)  This used to be set to 10mS which works for just about every
 * adapter we tested on.  We got a new TI adapter which would crash the system
 * once in a while if nothing (1394 device) was plugged into the adapter?
 * Changing this delay to 50mS made that problem go away.
 *
 * NOTE: Do not this delay unless you know what your doing!!!!
 */
uint_t hci1394_phy_stabilization_delay_uS = 50000;
