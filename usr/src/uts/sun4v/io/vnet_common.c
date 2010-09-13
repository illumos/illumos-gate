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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/ethernet.h>
#include <sys/vnet_common.h>
#include <sys/vlan.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/byteorder.h>

/* convert mac address from string to uint64_t */
uint64_t
vnet_macaddr_strtoul(const uint8_t *macaddr)
{
	uint64_t val = 0;
	int i;

	for (i = 0; i < ETHERADDRL; i++) {
		val <<= 8;
		val |= macaddr[i];
	}

	return (val);
}

/* convert mac address from uint64_t to string */
void
vnet_macaddr_ultostr(uint64_t val, uint8_t *macaddr)
{
	int i;
	uint64_t value;

	value = val;
	for (i = ETHERADDRL - 1; i >= 0; i--) {
		macaddr[i] = value & 0xFF;
		value >>= 8;
	}
}

mblk_t *
vnet_vlan_insert_tag(mblk_t *mp, uint16_t vid)
{
	struct ether_vlan_header	*evhp;
	mblk_t				*nmp;
	size_t				n;
	uint_t				pri = 0;

	if (DB_REF(mp) == 1 && MBLKHEAD(mp) >= VLAN_TAGSZ) {

		/* mblk has space to insert tag */

		/*
		 * move src and dst mac addrs in the header back by VLAN_TAGSZ.
		 */
		ovbcopy(mp->b_rptr, mp->b_rptr - VLAN_TAGSZ, 2 * ETHERADDRL);
		mp->b_rptr -= VLAN_TAGSZ;

		/* now insert tpid and tci */
		evhp = (struct ether_vlan_header *)mp->b_rptr;
		evhp->ether_tpid = htons(ETHERTYPE_VLAN);
		evhp->ether_tci = htons(VLAN_TCI(pri, ETHER_CFI, vid));

	} else { /* no space in the mblk for tag */

		/*
		 * allocate a mblk to create a new frame hdr with the tag
		 */
		nmp = allocb(sizeof (struct  ether_vlan_header),
		    BPRI_MED);
		if (nmp == NULL) {
			freemsg(mp);
			return (NULL);
		}

		/*
		 * copy the src and dst mac addrs in the header to the new mblk
		 */
		n = 2 * ETHERADDRL;
		bcopy(mp->b_rptr, nmp->b_rptr, n);

		/* initialize the vlan tag in the new mblk */
		evhp = (struct ether_vlan_header *)nmp->b_rptr;
		evhp->ether_tpid = htons(ETHERTYPE_VLAN);
		evhp->ether_tci = htons(VLAN_TCI(pri, ETHER_CFI, vid));

		/* copy ethertype to new mblk */
		bcopy(mp->b_rptr + n, nmp->b_rptr + n + VLAN_TAGSZ,
		    sizeof (evhp->ether_type));

		/* skip over the header in the original mblk */
		mp->b_rptr += sizeof (struct ether_header);

		/* fix the end of frame header in the new mblk */
		nmp->b_wptr += sizeof (struct ether_vlan_header);

		/*
		 * now link the new mblk which contains just the frame
		 * header with the original mblk which contains rest of
		 * the frame.
		 */
		nmp->b_cont = mp;
		mp = nmp;

	}

	return (mp);
}

mblk_t *
vnet_vlan_remove_tag(mblk_t *mp)
{
	size_t				n;
	mblk_t				*nmp;

	if (DB_REF(mp) == 1) { /* mblk can be modified to untag(not shared) */

		/* move src & dst addrs in the header forward by VLAN_TAGSZ */
		ovbcopy(mp->b_rptr, mp->b_rptr + VLAN_TAGSZ, 2 * ETHERADDRL);
		mp->b_rptr += VLAN_TAGSZ;

	} else {

		/* allocate a new header */
		nmp = allocb(sizeof (struct  ether_header), BPRI_MED);
		if (nmp == NULL) {
			freemsg(mp);
			return (NULL);
		}

		/*
		 * copy the src and dst mac addrs in the header to the new mblk
		 */
		n = 2 * ETHERADDRL;
		bcopy(mp->b_rptr, nmp->b_rptr, n);

		/* skip over vlan tag and copy ethertype to new mblk */
		bcopy(mp->b_rptr + n + VLAN_TAGSZ, nmp->b_rptr + n,
		    sizeof (uint16_t));

		/* skip over the header in the original mblk */
		mp->b_rptr += sizeof (struct ether_vlan_header);

		/* fix the end of frame header in the new mblk */
		nmp->b_wptr += sizeof (struct ether_header);

		/*
		 * now link the new mblk which contains the frame header
		 * without vlan tag and the original mblk which contains rest
		 * of the frame.
		 */
		nmp->b_cont = mp;
		mp = nmp;

	}

	return (mp);
}

int
vnet_dring_entry_copy(vnet_public_desc_t *from, vnet_public_desc_t *to,
    uint8_t mtype, ldc_dring_handle_t handle, uint64_t start, uint64_t stop)
{
	int rv;
	on_trap_data_t otd;

	if ((rv = VIO_DRING_ACQUIRE(&otd, mtype, handle, start, stop)) != 0)
		return (rv);

	*to = *from;

	rv = VIO_DRING_RELEASE_NOCOPYOUT(mtype);

	return (rv);
}

int
vnet_dring_entry_set_dstate(vnet_public_desc_t *descp, uint8_t mtype,
    ldc_dring_handle_t handle, uint64_t start, uint64_t stop, uint8_t dstate)
{
	int rv;
	on_trap_data_t otd;

	rv = VIO_DRING_ACQUIRE_NOCOPYIN(&otd, mtype);
	if (rv)
		return (rv);

	descp->hdr.dstate = dstate;

	rv = VIO_DRING_RELEASE(mtype, handle, start, stop);

	return (rv);
}
