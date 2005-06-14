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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/promif.h>
#include <sys/promimpl.h>

/*
 * This file contains the implementations of all Starcat-specific promif
 * routines.  Refer to FWARC case 2000/420 for the definitions of the
 * platform-specific interfaces provided by Starcat OBP.
 */

static char *switch_tunnel_cmd	= "SUNW,Starcat,switch-tunnel";
static char *iosram_read_cmd	= "SUNW,Starcat,iosram-read";
static char *iosram_write_cmd	= "SUNW,Starcat,iosram-write";

/*
 * Given the portid of the IOB to which the tunnel should be moved and the type
 * of move that should be performed, ask OBP to switch the IOSRAM tunnel from
 * its current host IOB to a new location.  If the move type is 0, OBP will
 * coordinate the change with SMS and will copy data from the current location
 * to the new location.  If the move type is 1, OBP will simply mark the new
 * location valid and start using it, without doing any data copying and without
 * communicating with SMS.  Return 0 on success, non-zero on failure.
 */
int
prom_starcat_switch_tunnel(uint_t portid, uint_t msgtype)
{
	static uint8_t	warned = 0;
	cell_t		ci[6];
	int		rv;

	/*
	 * Make sure we have the necessary support in OBP.
	 */
	if (prom_test(switch_tunnel_cmd) == 0) {
		ci[0] = p1275_ptr2cell(switch_tunnel_cmd); /* name */
	} else {
		if (!warned) {
			warned = 1;
			prom_printf(
			    "Warning: No prom support for switch-tunnel!\n");
		}
		return (-1);
	}

	/*
	 * Set up the arguments and call into OBP.
	 */
	ci[1] = (cell_t)2;				/* #argument cells */
	ci[2] = (cell_t)1;				/* #result cells */
	ci[3] = p1275_uint2cell(portid);
	ci[4] = p1275_uint2cell(msgtype);

	promif_preprom();
	rv = p1275_cif_handler(&ci);
	promif_postprom();

	/*
	 * p1275_cif_handler will return 0 on success, non-zero on failure.  If
	 * it fails, the return cell from OBP is meaningless, because the OBP
	 * client interface probably wasn't even invoked.  OBP will return 0 on
	 * failure and non-zero on success for this interface.
	 */
	if (rv != 0) {
		return (rv);
	} else if (p1275_cell2int(ci[5]) == 0)	{
		return (-1);
	} else {
		return (0);
	}
}

/*
 * Request that OBP read 'len' bytes, starting at 'offset' in the IOSRAM chunk
 * associated with 'key', into the memory indicated by 'buf'.  Although there is
 * a driver that provides this functionality, there are certain cases where the
 * OS requires access to IOSRAM before the driver is loaded.  Return 0 on
 * success, non-zero on failure.
 */
int
prom_starcat_iosram_read(uint32_t key, uint32_t offset, uint32_t len,
    caddr_t buf)
{
	static uint8_t	warned = 0;
	cell_t		ci[8];
	int		rv;

	/*
	 * Make sure we have the necessary support in OBP.
	 */
	if (prom_test(iosram_read_cmd) == 0) {
		ci[0] = p1275_ptr2cell(iosram_read_cmd); /* name */
	} else {
		if (!warned) {
			warned = 1;
			prom_printf(
			    "Warning: No prom support for iosram-read!\n");
		}
		return (-1);
	}

	/*
	 * Set up the arguments and call into OBP.  Note that the argument order
	 * needs to be reversed to accomodate OBP.  The order must remain as it
	 * is in the function prototype to maintain intercompatibility with the
	 * IOSRAM driver's equivalent routine.
	 */
	ci[1] = (cell_t)4;				/* #argument cells */
	ci[2] = (cell_t)1;				/* #result cells */
	ci[3] = p1275_ptr2cell(buf);
	ci[4] = p1275_uint2cell(len);
	ci[5] = p1275_uint2cell(offset);
	ci[6] = p1275_uint2cell(key);

	promif_preprom();
	rv = p1275_cif_handler(&ci);
	promif_postprom();

	/*
	 * p1275_cif_handler will return 0 on success, non-zero on failure.  If
	 * it fails, the return cell from OBP is meaningless, because the OBP
	 * client interface probably wasn't even invoked.  OBP will return 0 on
	 * success and non-zero on failure for this interface.
	 */
	if (rv != 0) {
		return (rv);
	} else if (p1275_cell2int(ci[7]) == 0)	{
		return (0);
	} else {
		return (-1);
	}
}

/*
 * Request that OBP write 'len' bytes from the memory indicated by 'buf' into
 * the IOSRAM chunk associated with 'key', starting at 'offset'.  Although there
 * is a driver that provides this functionality, there are certain cases where
 * the OS requires access to IOSRAM before the driver is loaded.  Return 0 on
 * success, non-zero on failure.
 */
int
prom_starcat_iosram_write(uint32_t key, uint32_t offset, uint32_t len,
    caddr_t buf)
{
	static uint8_t	warned = 0;
	cell_t 		ci[8];
	int 		rv;

	/*
	 * Make sure we have the necessary support in OBP.
	 */
	if (prom_test(iosram_write_cmd) == 0) {
		ci[0] = p1275_ptr2cell(iosram_write_cmd); /* name */
	} else {
		if (!warned) {
			warned = 1;
			prom_printf(
			    "Warning: No prom support for iosram-write!\n");
		}
		return (-1);
	}

	/*
	 * Set up the arguments and call into OBP.  Note that the argument order
	 * needs to be reversed to accomodate OBP.  The order must remain as it
	 * is in the function prototype to maintain intercompatibility with the
	 * IOSRAM driver's equivalent routine.
	 */
	ci[1] = (cell_t)4;				/* #argument cells */
	ci[2] = (cell_t)1;				/* #result cells */
	ci[3] = p1275_ptr2cell(buf);
	ci[4] = p1275_uint2cell(len);
	ci[5] = p1275_uint2cell(offset);
	ci[6] = p1275_uint2cell(key);

	promif_preprom();
	rv = p1275_cif_handler(&ci);
	promif_postprom();

	/*
	 * p1275_cif_handler will return 0 on success, non-zero on failure.  If
	 * it fails, the return cell from OBP is meaningless, because the OBP
	 * client interface probably wasn't even invoked.  OBP will return 0 on
	 * success and non-zero on failure for this interface.
	 */
	if (rv != 0) {
		return (rv);
	} else if (p1275_cell2int(ci[7]) == 0)	{
		return (0);
	} else {
		return (-1);
	}
}
