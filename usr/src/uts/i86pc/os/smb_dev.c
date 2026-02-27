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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2018, Joyent, Inc.
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * Platform-Specific SMBIOS Subroutines
 *
 * The routines in this file form part of <sys/smbios_impl.h> and combine with
 * the usr/src/common/smbios code to form an in-kernel SMBIOS decoding service.
 * The SMBIOS entry point is locating by scanning a range of physical memory
 * assigned to BIOS as described in Section 2 of the DMTF SMBIOS specification.
 */

#include <sys/smbios_impl.h>
#include <sys/sysmacros.h>
#include <sys/errno.h>
#include <sys/psm.h>
#include <sys/smp_impldefs.h>

smbios_hdl_t *ksmbios;
int ksmbios_flags;

smbios_hdl_t *
smb_open_error(smbios_hdl_t *shp, int *errp, int err)
{
	if (shp != NULL)
		smbios_close(shp);

	if (errp != NULL)
		*errp = err;

	if (ksmbios == NULL)
		cmn_err(CE_CONT, "?SMBIOS not loaded (%s)", smbios_errmsg(err));

	return (NULL);
}

smbios_hdl_t *
smbios_open(const char *file, int version, int flags, int *errp)
{
	smbios_hdl_t *shp = NULL;
	smbios_entry_t *ep;
	caddr_t stbuf, bios, p, q;
	caddr_t smb2, smb3;
	uint64_t startaddr, startoff = 0;
	size_t bioslen;
	uint_t smbe_stlen;
	smbios_entry_point_t ep_type;
	uint8_t smbe_major, smbe_minor;
	int err;

	if (file != NULL || (flags & ~SMB_O_MASK))
		return (smb_open_error(shp, errp, ESMB_INVAL));

	if ((startaddr = ddi_prop_get_int64(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_DONTPASS, "smbios-address", 0)) == 0) {
		startaddr = SMB_RANGE_START;
		bioslen = SMB_RANGE_LIMIT - SMB_RANGE_START + 1;
	} else {
		/*
		 * We have smbios address from boot loader, map a page or two.
		 */
		bioslen = MMU_PAGESIZE;
		startoff = startaddr & MMU_PAGEOFFSET;
		startaddr &= MMU_PAGEMASK;
		if (bioslen - startoff <= startoff)
			bioslen += MMU_PAGESIZE;
	}

	bios = psm_map_phys(startaddr, bioslen, PSM_PROT_READ);

	if (bios == NULL)
		return (smb_open_error(shp, errp, ESMB_MAPDEV));

	/*
	 * In case we did map one page, make sure we will not cross
	 * the end of the page.
	 */
	p = bios + startoff;
	q = bios + bioslen - startoff;
	smb2 = smb3 = NULL;
	while (p < q) {
		if (smb2 != NULL && smb3 != NULL)
			break;

		if (smb3 == NULL && strncmp(p, SMB3_ENTRY_EANCHOR,
		    SMB3_ENTRY_EANCHORLEN) == 0) {
			smb3 = p;
		} else if (smb2 == NULL && strncmp(p, SMB_ENTRY_EANCHOR,
		    SMB_ENTRY_EANCHORLEN) == 0) {
			smb2 = p;
		}

		p += SMB_SCAN_STEP;
	}

	if (smb2 == NULL && smb3 == NULL) {
		psm_unmap_phys(bios, bioslen);
		return (smb_open_error(shp, errp, ESMB_NOTFOUND));
	}

	/*
	 * While they're not supposed to (as per the SMBIOS 3.2 spec), some
	 * vendors end up having a newer version in one of the two entry points
	 * than the other. If we found multiple tables then we will prefer the
	 * one with the newer version. If they're equivalent, we prefer the
	 * 32-bit version. If only one is present, then we use that.
	 */
	ep = smb_alloc(SMB_ENTRY_MAXLEN);
	if (smb2 != NULL && smb3 != NULL) {
		uint8_t smb2maj, smb2min, smb3maj, smb3min;

		bcopy(smb2, ep, sizeof (smbios_entry_t));
		smb2maj = ep->ep21.smbe_major;
		smb2min = ep->ep21.smbe_minor;
		bcopy(smb3, ep, sizeof (smbios_entry_t));
		smb3maj = ep->ep30.smbe_major;
		smb3min = ep->ep30.smbe_minor;

		if (smb3maj > smb2maj ||
		    (smb3maj == smb2maj && smb3min > smb2min)) {
			ep_type = SMBIOS_ENTRY_POINT_30;
			p = smb3;
		} else {
			ep_type = SMBIOS_ENTRY_POINT_21;
			p = smb2;
		}
	} else if (smb3 != NULL) {
		ep_type = SMBIOS_ENTRY_POINT_30;
		p = smb3;
	} else {
		ep_type = SMBIOS_ENTRY_POINT_21;
		p = smb2;
	}
	bcopy(p, ep, sizeof (smbios_entry_t));
	if (ep_type == SMBIOS_ENTRY_POINT_21) {
		ep->ep21.smbe_elen = MIN(ep->ep21.smbe_elen, SMB_ENTRY_MAXLEN);
		bcopy(p, ep, ep->ep21.smbe_elen);
	} else if (ep_type == SMBIOS_ENTRY_POINT_30) {
		ep->ep30.smbe_elen = MIN(ep->ep30.smbe_elen, SMB_ENTRY_MAXLEN);
		bcopy(p, ep, ep->ep30.smbe_elen);
	}

	psm_unmap_phys(bios, bioslen);
	switch (ep_type) {
	case SMBIOS_ENTRY_POINT_21:
		smbe_major = ep->ep21.smbe_major;
		smbe_minor = ep->ep21.smbe_minor;
		smbe_stlen = ep->ep21.smbe_stlen;
		bios = psm_map_phys(ep->ep21.smbe_staddr, smbe_stlen,
		    PSM_PROT_READ);
		break;
	case SMBIOS_ENTRY_POINT_30:
		smbe_major = ep->ep30.smbe_major;
		smbe_minor = ep->ep30.smbe_minor;
		smbe_stlen = ep->ep30.smbe_stlen;
		bios = psm_map_phys_new(ep->ep30.smbe_staddr, smbe_stlen,
		    PSM_PROT_READ);
		break;
	default:
		smb_free(ep, SMB_ENTRY_MAXLEN);
		return (smb_open_error(shp, errp, ESMB_VERSION));
	}

	if (bios == NULL) {
		smb_free(ep, SMB_ENTRY_MAXLEN);
		return (smb_open_error(shp, errp, ESMB_MAPDEV));
	}

	stbuf = smb_alloc(smbe_stlen);
	bcopy(bios, stbuf, smbe_stlen);
	psm_unmap_phys(bios, smbe_stlen);
	shp = smbios_bufopen(ep, stbuf, smbe_stlen, version, flags, &err);

	if (shp == NULL) {
		smb_free(stbuf, smbe_stlen);
		smb_free(ep, SMB_ENTRY_MAXLEN);
		return (smb_open_error(shp, errp, err));
	}

	if (ksmbios == NULL) {
		cmn_err(CE_CONT, "?SMBIOS v%u.%u loaded (%u bytes)",
		    smbe_major, smbe_minor, smbe_stlen);
		if (shp->sh_flags & SMB_FL_TRUNC)
			cmn_err(CE_CONT, "?SMBIOS table is truncated");
	}

	shp->sh_flags |= SMB_FL_BUFALLOC;
	smb_free(ep, SMB_ENTRY_MAXLEN);

	return (shp);
}

/*ARGSUSED*/
smbios_hdl_t *
smbios_fdopen(int fd, int version, int flags, int *errp)
{
	return (smb_open_error(NULL, errp, ENOTSUP));
}

/*ARGSUSED*/
int
smbios_write(smbios_hdl_t *shp, int fd)
{
	return (smb_set_errno(shp, ENOTSUP));
}
