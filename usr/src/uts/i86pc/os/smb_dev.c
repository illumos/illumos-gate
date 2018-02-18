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
	uint64_t startaddr, startoff = 0;
	size_t bioslen;
	uint_t smbe_stlen;
	smbios_entry_point_t ep_type = SMBIOS_ENTRY_POINT_21;
	uint8_t smbe_major, smbe_minor;
	int err;

	if (file != NULL || (flags & ~SMB_O_MASK))
		return (smb_open_error(shp, errp, ESMB_INVAL));

	if ((startaddr = ddi_prop_get_int64(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_DONTPASS, "smbios-address", 0)) == 0) {
		startaddr = SMB_RANGE_START;
		bioslen = SMB_RANGE_LIMIT - SMB_RANGE_START + 1;
	} else {
		/* We have smbios address from boot loader, map one page. */
		bioslen = MMU_PAGESIZE;
		startoff = startaddr & MMU_PAGEOFFSET;
		startaddr &= MMU_PAGEMASK;
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
	while (p < q) {
		err = strncmp(p, SMB3_ENTRY_EANCHOR, SMB3_ENTRY_EANCHORLEN);
		if (err == 0) {
			ep_type = SMBIOS_ENTRY_POINT_30;
			break;
		}

		if (strncmp(p, SMB_ENTRY_EANCHOR, SMB_ENTRY_EANCHORLEN) == 0)
			break;
		p += SMB_SCAN_STEP;
	}

	if (p >= q) {
		psm_unmap_phys(bios, bioslen);
		return (smb_open_error(shp, errp, ESMB_NOTFOUND));
	}

	ep = smb_alloc(SMB_ENTRY_MAXLEN);
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
