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
 * Copyright 2015 OmniTI Computer Consulting, Inc.  All rights reserved.
 * Copyright 2019 Joyent, Inc.
 * Copyright 2024 Oxide Computer Company
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * SMBIOS Information Routines
 *
 * The routines in this file are used to convert from the SMBIOS data format to
 * a more reasonable and stable set of structures offered as part of our ABI.
 * These functions take the general form:
 *
 *	stp = smb_lookup_type(shp, foo);
 *	smb_foo_t foo;
 *
 *	smb_info_bcopy(stp->smbst_hdr, &foo, sizeof (foo));
 *      bzero(caller's struct);
 *
 *	copy/convert foo members into caller's struct
 *
 * We copy the internal structure on to an automatic variable so as to avoid
 * checks everywhere for structures that the BIOS has improperly truncated, and
 * also to automatically handle the case of a structure that has been extended.
 * When necessary, this code can use smb_gteq() to determine whether the SMBIOS
 * data is of a particular revision that is supposed to contain a new field.
 *
 * Note, when trying to bzero the caller's struct you have to be careful about
 * versions. One can only bzero the initial version that existed in illumos. In
 * other words, if someone passes an older library handle that doesn't support a
 * version you cannot assume that their structures have those additional members
 * in them. Instead, a 'base' version is introduced for such types that have
 * differences and instead we only bzero out the base version and then handle
 * the additional members. In general, because all additional members will be
 * assigned, there's no reason to zero them out unless they are arrays that
 * won't be entirely filled in.
 *
 * Due to history, anything added after the update from version 2.4, in other
 * words additions from or after '5094 Update libsmbios with recent items'
 * (4e901881) is currently being used for this. While we don't allow software
 * compiling against this to get an older form, this was the first major update
 * and a good starting point for us to enforce this behavior which is useful for
 * moving forward to making this more public.
 */

#include <sys/smbios_impl.h>
#include <sys/byteorder.h>
#include <sys/debug.h>

#ifdef _KERNEL
#include <sys/sunddi.h>
#else
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#endif

#define	SMB_CONT_WORD	2		/* contained elements are word size */

/*
 * A large number of SMBIOS structures contain a set of common strings used to
 * describe a h/w component's serial number, manufacturer, etc.  These fields
 * helpfully have different names and offsets and sometimes aren't consistent.
 * To simplify life for our clients, we factor these common things out into
 * smbios_info_t, which can be retrieved for any structure.  The following
 * table describes the mapping from a given structure to the smbios_info_t.
 * Multiple SMBIOS stuctures' contained objects are also handled here.
 */
static const struct smb_infospec {
	uint8_t is_type;		/* structure type */
	uint8_t is_manu;		/* manufacturer offset */
	uint8_t is_product;		/* product name offset */
	uint8_t is_version;		/* version offset */
	uint8_t is_serial;		/* serial number offset */
	uint8_t is_asset;		/* asset tag offset */
	uint8_t is_location;		/* location string offset */
	uint8_t is_part;		/* part number offset */
	uint8_t is_contc;		/* contained count */
	uint8_t is_contsz;		/* contained size */
	uint8_t is_contv;		/* contained objects */
} _smb_infospecs[] = {
	{ SMB_TYPE_SYSTEM,
		offsetof(smb_system_t, smbsi_manufacturer),
		offsetof(smb_system_t, smbsi_product),
		offsetof(smb_system_t, smbsi_version),
		offsetof(smb_system_t, smbsi_serial),
		0,
		0,
		0,
		0,
		0,
		0 },
	{ SMB_TYPE_BASEBOARD,
		offsetof(smb_bboard_t, smbbb_manufacturer),
		offsetof(smb_bboard_t, smbbb_product),
		offsetof(smb_bboard_t, smbbb_version),
		offsetof(smb_bboard_t, smbbb_serial),
		offsetof(smb_bboard_t, smbbb_asset),
		offsetof(smb_bboard_t, smbbb_location),
		0,
		offsetof(smb_bboard_t, smbbb_cn),
		SMB_CONT_WORD,
		offsetof(smb_bboard_t, smbbb_cv) },
	{ SMB_TYPE_CHASSIS,
		offsetof(smb_chassis_t, smbch_manufacturer),
		0,
		offsetof(smb_chassis_t, smbch_version),
		offsetof(smb_chassis_t, smbch_serial),
		offsetof(smb_chassis_t, smbch_asset),
		0,
		0,
		0,
		0,
		0 },
	{ SMB_TYPE_PROCESSOR,
		offsetof(smb_processor_t, smbpr_manufacturer),
		0,
		offsetof(smb_processor_t, smbpr_version),
		offsetof(smb_processor_t, smbpr_serial),
		offsetof(smb_processor_t, smbpr_asset),
		offsetof(smb_processor_t, smbpr_socket),
		offsetof(smb_processor_t, smbpr_part),
		0,
		0,
		0 },
	{ SMB_TYPE_CACHE,
		0,
		0,
		0,
		0,
		0,
		offsetof(smb_cache_t, smbca_socket),
		0,
		0,
		0,
		0 },
	{ SMB_TYPE_PORT,
		0,
		0,
		0,
		0,
		0,
		offsetof(smb_port_t, smbpo_iref),
		0,
		0,
		0,
		0 },
	{ SMB_TYPE_SLOT,
		0,
		0,
		0,
		0,
		0,
		offsetof(smb_slot_t, smbsl_name),
		0,
		0,
		0,
		0 },
	{ SMB_TYPE_MEMDEVICE,
		offsetof(smb_memdevice_t, smbmdev_manufacturer),
		0,
		0,
		offsetof(smb_memdevice_t, smbmdev_serial),
		offsetof(smb_memdevice_t, smbmdev_asset),
		offsetof(smb_memdevice_t, smbmdev_dloc),
		offsetof(smb_memdevice_t, smbmdev_part),
		0,
		0,
		0 },
	{ SMB_TYPE_POWERSUP,
		offsetof(smb_powersup_t, smbpsup_manufacturer),
		offsetof(smb_powersup_t, smbpsup_devname),
		offsetof(smb_powersup_t, smbpsup_rev),
		offsetof(smb_powersup_t, smbpsup_serial),
		offsetof(smb_powersup_t, smbpsup_asset),
		offsetof(smb_powersup_t, smbpsup_loc),
		offsetof(smb_powersup_t, smbpsup_part),
		0,
		0,
		0 },
	{ SMB_TYPE_BATTERY,
		offsetof(smb_battery_t, smbbat_manufacturer),
		offsetof(smb_battery_t, smbbat_devname),
		0,
		/*
		 * While the serial number is a part of the device, because of
		 * the fact that the battery has two different serial numbers,
		 * we don't include it here.
		 */
		0,
		0,
		offsetof(smb_battery_t, smbbat_loc),
		0,
		0,
		0,
		0
	},
	{ SMB_TYPE_FWINFO,
		offsetof(smb_fwinfo_t, smbfwii_mfg),
		0,
		offsetof(smb_fwinfo_t, smbfwii_vers),
		0,
		0,
		0,
		0,
		0,
		0,
		0
	},
	{ SMB_TYPE_EOT }
};

static const char *
smb_info_strptr(const smb_struct_t *stp, uint8_t off, int *n)
{
	const uint8_t *sp = (const uint8_t *)(uintptr_t)stp->smbst_hdr;

	if (off != 0 && sp + off < stp->smbst_end) {
		(*n)++; /* indicate success for caller */
		return (smb_strptr(stp, sp[off]));
	}

	return (smb_strptr(stp, 0));
}

static void
smb_info_bcopy_offset(const smb_header_t *hp, void *dst, size_t dstlen,
    size_t offset)
{
	if (offset >= hp->smbh_len) {
		bzero(dst, dstlen);
	} else if (offset + dstlen > hp->smbh_len) {
		size_t nvalid = MIN(hp->smbh_len - offset, dstlen);
		bcopy((char *)hp + offset, dst, nvalid);
		bzero((char *)dst + nvalid, dstlen - nvalid);
	} else {
		bcopy((char *)hp + offset, dst, dstlen);
	}
}

static void
smb_info_bcopy(const smb_header_t *hp, void *dst, size_t dstlen)
{
	return (smb_info_bcopy_offset(hp, dst, dstlen, 0));
}

smbios_entry_point_t
smbios_info_smbios(smbios_hdl_t *shp, smbios_entry_t *ep)
{
	bcopy(&shp->sh_ent, ep, sizeof (smbios_entry_t));
	return (shp->sh_ent_type);
}

void
smbios_info_smbios_version(smbios_hdl_t *shp, smbios_version_t *v)
{
	v->smbv_major = SMB_MAJOR(shp->sh_smbvers);
	v->smbv_minor = SMB_MINOR(shp->sh_smbvers);
}

#ifndef _KERNEL
static char smbios_product_override[256];
static boolean_t smbios_product_checked;
#endif

int
smbios_info_common(smbios_hdl_t *shp, id_t id, smbios_info_t *ip)
{
	const smb_struct_t *stp = smb_lookup_id(shp, id);
	const struct smb_infospec *isp;
	int n = 0;

	if (stp == NULL)
		return (-1); /* errno is set for us */

	for (isp = _smb_infospecs; isp->is_type != SMB_TYPE_EOT; isp++) {
		if (isp->is_type == stp->smbst_hdr->smbh_type)
			break;
	}

	ip->smbi_manufacturer = smb_info_strptr(stp, isp->is_manu, &n);
	ip->smbi_product = smb_info_strptr(stp, isp->is_product, &n);
	ip->smbi_version = smb_info_strptr(stp, isp->is_version, &n);
	ip->smbi_serial = smb_info_strptr(stp, isp->is_serial, &n);
	ip->smbi_asset = smb_info_strptr(stp, isp->is_asset, &n);
	ip->smbi_location = smb_info_strptr(stp, isp->is_location, &n);
	ip->smbi_part = smb_info_strptr(stp, isp->is_part, &n);

	/*
	 * This private file allows developers to experiment with reporting
	 * different platform strings from SMBIOS.  It is not a supported
	 * mechanism in the long term, and does not work in the kernel.
	 */
#ifndef _KERNEL
	if (isp->is_type == SMB_TYPE_SYSTEM) {
		if (!smbios_product_checked) {
			int fd = open("/etc/smbios_product", O_RDONLY);
			if (fd >= 0) {
				(void) read(fd, smbios_product_override,
				    sizeof (smbios_product_override) - 1);
				(void) close(fd);
			}
			smbios_product_checked = B_TRUE;
		}

		if (smbios_product_override[0] != '\0')
			ip->smbi_product = smbios_product_override;
	}
#endif

	/*
	 * If we have a port with an empty internal reference designator string
	 * try using the external reference designator string instead.
	 */
	if (isp->is_type == SMB_TYPE_PORT && ip->smbi_location[0] == '\0') {
		ip->smbi_location = smb_info_strptr(stp,
		    offsetof(smb_port_t, smbpo_eref), &n);
	}

	return (n ? 0 : smb_set_errno(shp, ESMB_NOINFO));
}

/*
 * Returns the actual number of contained objects.
 *
 * idc - number of contained objects
 * idv - returned array of contained objects
 */
int
smbios_info_contains(smbios_hdl_t *shp, id_t id, uint_t idc, id_t *idv)
{
	const smb_struct_t *stp = smb_lookup_id(shp, id);
	const struct smb_infospec *isp;
	id_t *cp;
	uint_t size;
	uint8_t cnt;
	int i, n;

	if (stp == NULL) {
		return (-1); /* errno is set for us */
	}

	for (isp = _smb_infospecs; isp->is_type != SMB_TYPE_EOT; isp++) {
		if (isp->is_type == stp->smbst_hdr->smbh_type)
			break;
	}
	if (isp->is_type == SMB_TYPE_EOT)
		return (smb_set_errno(shp, ESMB_TYPE));

	size = isp->is_contsz;
	cnt = *((uint8_t *)(uintptr_t)stp->smbst_hdr + isp->is_contc);
	cp = (id_t *)((uintptr_t)stp->smbst_hdr + isp->is_contv);

	n = MIN(cnt, idc);
	for (i = 0; i < n; i++) {
		if (size == SMB_CONT_WORD)
			idv[i] = *((uint16_t *)(uintptr_t)cp + (i * 2));
		else
			return (smb_set_errno(shp, ESMB_INVAL));
	}

	return (cnt);
}

id_t
smbios_info_bios(smbios_hdl_t *shp, smbios_bios_t *bp)
{
	const smb_struct_t *stp = smb_lookup_type(shp, SMB_TYPE_BIOS);
	const smb_bios_t *bip;

	if (stp == NULL)
		return (-1); /* errno is set for us */

	if (stp->smbst_hdr->smbh_len < sizeof (smb_bios_t) - sizeof (uint8_t))
		return (smb_set_errno(shp, ESMB_CORRUPT));

	bip = (smb_bios_t *)(uintptr_t)stp->smbst_hdr;
	bzero(bp, sizeof (smb_base_bios_t));
	if (smb_libgteq(shp, SMB_VERSION_31)) {
		bp->smbb_extromsize = 0;
	}

	bp->smbb_vendor = smb_strptr(stp, bip->smbbi_vendor);
	bp->smbb_version = smb_strptr(stp, bip->smbbi_version);
	bp->smbb_segment = bip->smbbi_segment;
	bp->smbb_reldate = smb_strptr(stp, bip->smbbi_reldate);
	bp->smbb_romsize = 64 * 1024 * ((uint32_t)bip->smbbi_romsize + 1);
	bp->smbb_runsize = 16 * (0x10000 - (uint32_t)bip->smbbi_segment);
	bp->smbb_cflags = bip->smbbi_cflags;

	/*
	 * If one or more extension bytes are present, reset smbb_xcflags to
	 * point to them.  Otherwise leave this member set to NULL.
	 */
	if (stp->smbst_hdr->smbh_len >= sizeof (smb_bios_t)) {
		bp->smbb_xcflags = bip->smbbi_xcflags;
		bp->smbb_nxcflags = stp->smbst_hdr->smbh_len -
		    sizeof (smb_bios_t) + 1;

		if (bp->smbb_nxcflags > SMB_BIOSXB_ECFW_MIN &&
		    smb_gteq(shp, SMB_VERSION_24)) {
			bp->smbb_biosv.smbv_major =
			    bip->smbbi_xcflags[SMB_BIOSXB_BIOS_MAJ];
			bp->smbb_biosv.smbv_minor =
			    bip->smbbi_xcflags[SMB_BIOSXB_BIOS_MIN];
			bp->smbb_ecfwv.smbv_major =
			    bip->smbbi_xcflags[SMB_BIOSXB_ECFW_MAJ];
			bp->smbb_ecfwv.smbv_minor =
			    bip->smbbi_xcflags[SMB_BIOSXB_ECFW_MIN];
		}

		if (bp->smbb_nxcflags > SMB_BIOSXB_EXTROM + 1 &&
		    smb_gteq(shp, SMB_VERSION_31)) {
			uint16_t val;
			uint64_t rs;

			/*
			 * Because of the fact that the extended size is a
			 * uint16_t and we'd need to define an explicit
			 * endian-aware way to access it, we don't include it in
			 * the number of extended flags below and thus subtract
			 * its size.
			 */
			bp->smbb_nxcflags -= sizeof (uint16_t);
			bcopy(&bip->smbbi_xcflags[SMB_BIOSXB_EXTROM], &val,
			    sizeof (val));
			val = LE_16(val);

			/*
			 * The upper two bits of the extended rom size are used
			 * to indicate whether the other 14 bits are in MB or
			 * GB.
			 */
			rs = SMB_BIOS_EXTROM_VALUE_MASK(val);
			switch (SMB_BIOS_EXTROM_SHIFT_MASK(val)) {
			case 0:
				rs *= 1024ULL * 1024ULL;
				break;
			case 1:
				rs *= 1024ULL * 1024ULL * 1024ULL;
				break;
			default:
				rs = 0;
				break;
			}

			if (smb_libgteq(shp, SMB_VERSION_31)) {
				bp->smbb_extromsize = rs;
			}
		}
	}

	if (smb_libgteq(shp, SMB_VERSION_31) && bp->smbb_extromsize == 0) {
		bp->smbb_extromsize = bp->smbb_romsize;
	}

	return (stp->smbst_hdr->smbh_hdl);
}

id_t
smbios_info_system(smbios_hdl_t *shp, smbios_system_t *sip)
{
	const smb_struct_t *stp = smb_lookup_type(shp, SMB_TYPE_SYSTEM);
	smb_system_t si;

	if (stp == NULL)
		return (-1); /* errno is set for us */

	smb_info_bcopy(stp->smbst_hdr, &si, sizeof (si));
	bzero(sip, sizeof (smbios_system_t));

	sip->smbs_uuid = ((smb_system_t *)stp->smbst_hdr)->smbsi_uuid;
	sip->smbs_uuidlen = sizeof (si.smbsi_uuid);
	sip->smbs_wakeup = si.smbsi_wakeup;
	sip->smbs_sku = smb_strptr(stp, si.smbsi_sku);
	sip->smbs_family = smb_strptr(stp, si.smbsi_family);

	return (stp->smbst_hdr->smbh_hdl);
}

int
smbios_info_bboard(smbios_hdl_t *shp, id_t id, smbios_bboard_t *bbp)
{
	const smb_struct_t *stp = smb_lookup_id(shp, id);
	smb_bboard_t bb;

	if (stp == NULL)
		return (-1); /* errno is set for us */

	if (stp->smbst_hdr->smbh_type != SMB_TYPE_BASEBOARD)
		return (smb_set_errno(shp, ESMB_TYPE));

	smb_info_bcopy(stp->smbst_hdr, &bb, sizeof (bb));
	bzero(bbp, sizeof (smbios_bboard_t));

	bbp->smbb_chassis = bb.smbbb_chassis;
	bbp->smbb_flags = bb.smbbb_flags;
	bbp->smbb_type = bb.smbbb_type;
	bbp->smbb_contn = bb.smbbb_cn;

	return (0);
}

int
smbios_info_chassis(smbios_hdl_t *shp, id_t id, smbios_chassis_t *chp)
{
	const smb_struct_t *stp = smb_lookup_id(shp, id);
	smb_chassis_t ch;

	if (stp == NULL) {
		return (-1); /* errno is set for us */
	}

	if (stp->smbst_hdr->smbh_type != SMB_TYPE_CHASSIS) {
		return (smb_set_errno(shp, ESMB_TYPE));
	}

	if (stp->smbst_hdr->smbh_len < sizeof (ch)) {
		return (smb_set_errno(shp, ESMB_SHORT));
	}

	smb_info_bcopy(stp->smbst_hdr, &ch, sizeof (ch));
	bzero(chp, sizeof (smb_base_chassis_t));

	/*
	 * See the comments for the smb_chassis_pre35_t in sys/smbios_impl.h for
	 * an explanation as to why this is here. The use of smb_strptr with
	 * index 0 below ensures that we initialize this to an empty string.
	 */
	if (smb_libgteq(shp, SMB_VERSION_35)) {
		chp->smbc_sku = smb_strptr(stp, 0);
	} else if (smb_libgteq(shp, SMB_VERSION_27)) {
		smb_chassis_pre35_t *p35 = (smb_chassis_pre35_t *)chp;
		bzero(p35->smbc_sku, sizeof (p35->smbc_sku));
	}

	chp->smbc_oemdata = ch.smbch_oemdata;
	chp->smbc_lock = (ch.smbch_type & SMB_CHT_LOCK) != 0;
	chp->smbc_type = ch.smbch_type & ~SMB_CHT_LOCK;
	chp->smbc_bustate = ch.smbch_bustate;
	chp->smbc_psstate = ch.smbch_psstate;
	chp->smbc_thstate = ch.smbch_thstate;
	chp->smbc_security = ch.smbch_security;
	chp->smbc_uheight = ch.smbch_uheight;
	chp->smbc_cords = ch.smbch_cords;
	chp->smbc_elems = ch.smbch_cn;
	chp->smbc_elemlen = ch.smbch_cm;

	/*
	 * If the table is older than version 2.7 which added support for the
	 * chassis SKU, there's no reason to proceed.
	 */
	if (!smb_gteq(shp, SMB_VERSION_27)) {
		return (0);
	}

	if (smb_libgteq(shp, SMB_VERSION_27)) {
		uint8_t strno;
		const char *str;
		off_t off = sizeof (ch) + ch.smbch_cn * ch.smbch_cm;
		if (stp->smbst_hdr->smbh_len < off + 1) {
			return (smb_set_errno(shp, ESMB_SHORT));
		}
		smb_info_bcopy_offset(stp->smbst_hdr, &strno, sizeof (strno),
		    off);
		str = smb_strptr(stp, strno);
		if (smb_libgteq(shp, SMB_VERSION_35)) {
			chp->smbc_sku = str;
		} else {
			smb_chassis_pre35_t *p35 = (smb_chassis_pre35_t *)chp;
			(void) strlcpy(p35->smbc_sku, str,
			    sizeof (p35->smbc_sku));
		}
	}

	return (0);
}

int
smbios_info_chassis_elts(smbios_hdl_t *shp, id_t id, uint_t *nentsp,
    smbios_chassis_entry_t **entsp)
{
	const smb_struct_t *stp = smb_lookup_id(shp, id);
	smbios_chassis_entry_t *entry;
	smb_chassis_t ch;
	size_t entlen;
	uint_t i;

	if (stp == NULL) {
		return (-1); /* errno is set for us */
	}

	if (stp->smbst_hdr->smbh_type != SMB_TYPE_CHASSIS) {
		return (smb_set_errno(shp, ESMB_TYPE));
	}

	if (stp->smbst_hdr->smbh_len < sizeof (ch)) {
		return (smb_set_errno(shp, ESMB_SHORT));
	}

	smb_info_bcopy(stp->smbst_hdr, &ch, sizeof (ch));
	if (ch.smbch_cm != sizeof (smb_chassis_entry_t)) {
		return (smb_set_errno(shp, ESMB_CORRUPT));
	}

	if (ch.smbch_cn == 0) {
		*nentsp = 0;
		*entsp = NULL;
		return (0);
	}

	entlen = ch.smbch_cm * ch.smbch_cn;
	if (stp->smbst_hdr->smbh_len < sizeof (ch) + entlen) {
		return (smb_set_errno(shp, ESMB_SHORT));
	}

	if ((entry = smb_alloc(entlen)) == NULL) {
		return (smb_set_errno(shp, ESMB_NOMEM));
	}

	for (i = 0; i < ch.smbch_cn; i++) {
		smb_chassis_entry_t e;
		size_t off = sizeof (ch) + i * sizeof (e);

		smb_info_bcopy_offset(stp->smbst_hdr, &e, sizeof (e), off);
		/*
		 * The top bit is used to indicate what type of record this is,
		 * while the lower 7-bits indicate the actual type.
		 */
		entry[i].smbce_type = e.smbce_type & 0x80 ?
		    SMB_CELT_SMBIOS : SMB_CELT_BBOARD;
		entry[i].smbce_elt = e.smbce_type & 0x7f;
		entry[i].smbce_min = e.smbce_min;
		entry[i].smbce_max = e.smbce_max;
	}

	*entsp = entry;
	*nentsp = ch.smbch_cn;

	return (0);
}

void
smbios_info_chassis_elts_free(smbios_hdl_t *shp, uint_t nents,
    smbios_chassis_entry_t *ent)
{
	size_t sz = nents * sizeof (smbios_chassis_entry_t);

	if (nents == 0) {
		ASSERT3P(ent, ==, NULL);
		return;
	}

	smb_free(ent, sz);
}

int
smbios_info_processor(smbios_hdl_t *shp, id_t id, smbios_processor_t *pp)
{
	const smb_struct_t *stp = smb_lookup_id(shp, id);
	smb_processor_t p;

	if (stp == NULL)
		return (-1); /* errno is set for us */

	if (stp->smbst_hdr->smbh_type != SMB_TYPE_PROCESSOR)
		return (smb_set_errno(shp, ESMB_TYPE));

	smb_info_bcopy(stp->smbst_hdr, &p, sizeof (p));
	bzero(pp, sizeof (smb_base_processor_t));

	pp->smbp_cpuid = p.smbpr_cpuid;
	pp->smbp_type = p.smbpr_type;
	pp->smbp_family = p.smbpr_family;
	pp->smbp_voltage = p.smbpr_voltage;
	pp->smbp_clkspeed = p.smbpr_clkspeed;
	pp->smbp_maxspeed = p.smbpr_maxspeed;
	pp->smbp_curspeed = p.smbpr_curspeed;
	pp->smbp_status = p.smbpr_status;
	pp->smbp_upgrade = p.smbpr_upgrade;
	pp->smbp_l1cache = p.smbpr_l1cache;
	pp->smbp_l2cache = p.smbpr_l2cache;
	pp->smbp_l3cache = p.smbpr_l3cache;

	if (smb_libgteq(shp, SMB_VERSION_25)) {
		pp->smbp_corecount = p.smbpr_corecount;
		pp->smbp_coresenabled = p.smbpr_coresenabled;
		pp->smbp_threadcount = p.smbpr_threadcount;
		pp->smbp_cflags = p.smbpr_cflags;
	}

	if (smb_libgteq(shp, SMB_VERSION_26)) {
		if (pp->smbp_family == 0xfe) {
			pp->smbp_family = p.smbpr_family2;
		}
	}

	if (smb_libgteq(shp, SMB_VERSION_30)) {
		if (pp->smbp_corecount == 0xff) {
			pp->smbp_corecount = p.smbpr_corecount2;
		}
		if (pp->smbp_coresenabled == 0xff) {
			pp->smbp_coresenabled = p.smbpr_coresenabled2;
		}
		if (pp->smbp_threadcount == 0xff) {
			pp->smbp_threadcount = p.smbpr_threadcount2;
		}
	}

	if (smb_libgteq(shp, SMB_VERSION_36)) {
		pp->smbp_threadsenabled = p.smpbr_threaden;
	}

	return (0);
}

int
smbios_info_cache(smbios_hdl_t *shp, id_t id, smbios_cache_t *cap)
{
	const smb_struct_t *stp = smb_lookup_id(shp, id);
	smb_cache_t c;

	if (stp == NULL)
		return (-1); /* errno is set for us */

	if (stp->smbst_hdr->smbh_type != SMB_TYPE_CACHE)
		return (smb_set_errno(shp, ESMB_TYPE));

	smb_info_bcopy(stp->smbst_hdr, &c, sizeof (c));
	bzero(cap, sizeof (smb_base_cache_t));

	cap->smba_maxsize = SMB_CACHE_SIZE(c.smbca_maxsize);
	cap->smba_size = SMB_CACHE_SIZE(c.smbca_size);
	cap->smba_stype = c.smbca_stype;
	cap->smba_ctype = c.smbca_ctype;
	cap->smba_speed = c.smbca_speed;
	cap->smba_etype = c.smbca_etype;
	cap->smba_ltype = c.smbca_ltype;
	cap->smba_assoc = c.smbca_assoc;
	cap->smba_level = SMB_CACHE_CFG_LEVEL(c.smbca_config);
	cap->smba_mode = SMB_CACHE_CFG_MODE(c.smbca_config);
	cap->smba_location = SMB_CACHE_CFG_LOCATION(c.smbca_config);

	if (SMB_CACHE_CFG_ENABLED(c.smbca_config))
		cap->smba_flags |= SMB_CAF_ENABLED;

	if (SMB_CACHE_CFG_SOCKETED(c.smbca_config))
		cap->smba_flags |= SMB_CAF_SOCKETED;

	if (smb_libgteq(shp, SMB_VERSION_31)) {
		cap->smba_maxsize2 = SMB_CACHE_EXT_SIZE(c.smbca_maxsize2);
		cap->smba_size2 = SMB_CACHE_EXT_SIZE(c.smbca_size2);

		if (cap->smba_maxsize2 == 0) {
			cap->smba_maxsize2 = cap->smba_maxsize;
		}

		if (cap->smba_size2 == 0) {
			cap->smba_size2 = cap->smba_size;
		}
	}

	return (0);
}

int
smbios_info_port(smbios_hdl_t *shp, id_t id, smbios_port_t *pop)
{
	const smb_struct_t *stp = smb_lookup_id(shp, id);
	smb_port_t p;

	if (stp == NULL)
		return (-1); /* errno is set for us */

	if (stp->smbst_hdr->smbh_type != SMB_TYPE_PORT)
		return (smb_set_errno(shp, ESMB_TYPE));

	smb_info_bcopy(stp->smbst_hdr, &p, sizeof (p));
	bzero(pop, sizeof (smbios_port_t));

	pop->smbo_iref = smb_strptr(stp, p.smbpo_iref);
	pop->smbo_eref = smb_strptr(stp, p.smbpo_eref);

	pop->smbo_itype = p.smbpo_itype;
	pop->smbo_etype = p.smbpo_etype;
	pop->smbo_ptype = p.smbpo_ptype;

	return (0);
}

int
smbios_info_slot(smbios_hdl_t *shp, id_t id, smbios_slot_t *sp)
{
	const smb_struct_t *stp = smb_lookup_id(shp, id);
	smb_slot_t s;
	smb_slot_cont_t cont;
	size_t off;

	if (stp == NULL)
		return (-1); /* errno is set for us */

	if (stp->smbst_hdr->smbh_type != SMB_TYPE_SLOT)
		return (smb_set_errno(shp, ESMB_TYPE));

	smb_info_bcopy(stp->smbst_hdr, &s, sizeof (s));
	bzero(sp, sizeof (smb_base_slot_t));

	sp->smbl_name = smb_strptr(stp, s.smbsl_name);
	sp->smbl_type = s.smbsl_type;
	sp->smbl_width = s.smbsl_width;
	sp->smbl_usage = s.smbsl_usage;
	sp->smbl_length = s.smbsl_length;
	sp->smbl_id = s.smbsl_id;
	sp->smbl_ch1 = s.smbsl_ch1;
	sp->smbl_ch2 = s.smbsl_ch2;
	sp->smbl_sg = s.smbsl_sg;
	sp->smbl_bus = s.smbsl_bus;
	sp->smbl_df = s.smbsl_df;

	if (smb_libgteq(shp, SMB_VERSION_32)) {
		sp->smbl_dbw = s.smbsl_dbw;
		sp->smbl_npeers = s.smbsl_npeers;
	}

	if (!smb_libgteq(shp, SMB_VERSION_34)) {
		return (0);
	}

	/*
	 * In SMBIOS 3.4, several members were added to follow the variable
	 * number of peers. These are defined to start at byte 0x14 + 5 *
	 * npeers. If the table is from before 3.4, we simple zero things out.
	 * Otherwise we check if the length covers the peers and this addendum
	 * to include it as the table length is allowed to be less than this and
	 * not include it.
	 */
	off = SMB_SLOT_CONT_START + 5 * s.smbsl_npeers;
	smb_info_bcopy_offset(stp->smbst_hdr, &cont, sizeof (cont), off);
	sp->smbl_info = cont.smbsl_info;
	sp->smbl_pwidth = cont.smbsl_pwidth;
	sp->smbl_pitch = cont.smbsl_pitch;

	if (smb_libgteq(shp, SMB_VERSION_35)) {
		sp->smbl_height = cont.smbsl_height;
	}

	return (0);
}

void
smbios_info_slot_peers_free(smbios_hdl_t *shp, uint_t npeers,
    smbios_slot_peer_t *peer)
{
	size_t sz = npeers * sizeof (smbios_slot_peer_t);

	if (npeers == 0) {
		ASSERT3P(peer, ==, NULL);
		return;
	}

	smb_free(peer, sz);
}

int
smbios_info_slot_peers(smbios_hdl_t *shp, id_t id, uint_t *npeers,
    smbios_slot_peer_t **peerp)
{
	const smb_struct_t *stp = smb_lookup_id(shp, id);
	const smb_slot_t *slotp;
	smbios_slot_peer_t *peer;
	size_t minlen;
	uint_t i;

	if (stp == NULL)
		return (-1); /* errno is set for us */

	slotp = (const smb_slot_t *)stp->smbst_hdr;

	if (stp->smbst_hdr->smbh_type != SMB_TYPE_SLOT)
		return (smb_set_errno(shp, ESMB_TYPE));

	if (stp->smbst_hdr->smbh_len <= offsetof(smb_slot_t, smbsl_npeers) ||
	    slotp->smbsl_npeers == 0) {
		*npeers = 0;
		*peerp = NULL;
		return (0);
	}

	/*
	 * Make sure that the size of the structure makes sense for the number
	 * of peers reported.
	 */
	minlen = slotp->smbsl_npeers * sizeof (smb_slot_peer_t) +
	    offsetof(smb_slot_t, smbsl_npeers);
	if (stp->smbst_hdr->smbh_len < minlen) {
		return (smb_set_errno(shp, ESMB_SHORT));
	}

	if ((peer = smb_alloc(slotp->smbsl_npeers *
	    sizeof (smbios_slot_peer_t))) == NULL) {
		return (smb_set_errno(shp, ESMB_NOMEM));
	}

	for (i = 0; i < slotp->smbsl_npeers; i++) {
		peer[i].smblp_group = slotp->smbsl_peers[i].smbspb_group_no;
		peer[i].smblp_bus = slotp->smbsl_peers[i].smbspb_bus;
		peer[i].smblp_device = slotp->smbsl_peers[i].smbspb_df >> 3;
		peer[i].smblp_function = slotp->smbsl_peers[i].smbspb_df & 0x7;
		peer[i].smblp_data_width = slotp->smbsl_peers[i].smbspb_width;
	}

	*npeers = slotp->smbsl_npeers;
	*peerp = peer;

	return (0);
}

int
smbios_info_obdevs_ext(smbios_hdl_t *shp, id_t id, smbios_obdev_ext_t *oep)
{
	const smb_struct_t *stp = smb_lookup_id(shp, id);
	smb_obdev_ext_t obe;

	if (stp == NULL)
		return (-1); /* errno is set for us */

	if (stp->smbst_hdr->smbh_type != SMB_TYPE_OBDEVEXT)
		return (smb_set_errno(shp, ESMB_TYPE));

	smb_info_bcopy(stp->smbst_hdr, &obe, sizeof (obe));
	bzero(oep, sizeof (smbios_obdev_ext_t));

	oep->smboe_name = smb_strptr(stp, obe.smbobe_name);
	oep->smboe_dtype = obe.smbobe_dtype;
	oep->smboe_dti = obe.smbobe_dti;
	oep->smboe_sg = obe.smbobe_sg;
	oep->smboe_bus = obe.smbobe_bus;
	oep->smboe_df = obe.smbobe_df;

	return (0);
}

int
smbios_info_obdevs(smbios_hdl_t *shp, id_t id, int obc, smbios_obdev_t *obp)
{
	const smb_struct_t *stp = smb_lookup_id(shp, id);
	const smb_obdev_t *op;
	int i, m, n;

	if (stp == NULL)
		return (-1); /* errno is set for us */

	if (stp->smbst_hdr->smbh_type != SMB_TYPE_OBDEVS)
		return (smb_set_errno(shp, ESMB_TYPE));

	op = (smb_obdev_t *)((uintptr_t)stp->smbst_hdr + sizeof (smb_header_t));
	m = (stp->smbst_hdr->smbh_len - sizeof (smb_header_t)) / sizeof (*op);
	n = MIN(m, obc);

	for (i = 0; i < n; i++, op++, obp++) {
		obp->smbd_name = smb_strptr(stp, op->smbob_name);
		obp->smbd_type = op->smbob_type & ~SMB_OBT_ENABLED;
		obp->smbd_enabled = (op->smbob_type & SMB_OBT_ENABLED) != 0;
	}

	return (m);
}

/*
 * The implementation structures for OEMSTR, SYSCONFSTR, and LANG all use the
 * first byte to indicate the size of a string table at the end of the record.
 * Therefore, smbios_info_strtab() can be used to retrieve the table size and
 * strings for any of these underlying record types.
 */
int
smbios_info_strtab(smbios_hdl_t *shp, id_t id, int argc, const char *argv[])
{
	const smb_struct_t *stp = smb_lookup_id(shp, id);
	smb_strtab_t s;
	int i, n;

	if (stp == NULL)
		return (-1); /* errno is set for us */

	if (stp->smbst_hdr->smbh_type != SMB_TYPE_OEMSTR &&
	    stp->smbst_hdr->smbh_type != SMB_TYPE_SYSCONFSTR &&
	    stp->smbst_hdr->smbh_type != SMB_TYPE_LANG)
		return (smb_set_errno(shp, ESMB_TYPE));

	smb_info_bcopy(stp->smbst_hdr, &s, sizeof (s));
	n = MIN(s.smbtb_count, argc);

	for (i = 0; i < n; i++)
		argv[i] = smb_strptr(stp, i + 1);

	return (s.smbtb_count);
}

id_t
smbios_info_lang(smbios_hdl_t *shp, smbios_lang_t *lp)
{
	const smb_struct_t *stp = smb_lookup_type(shp, SMB_TYPE_LANG);
	smb_lang_t l;

	if (stp == NULL)
		return (-1); /* errno is set for us */

	smb_info_bcopy(stp->smbst_hdr, &l, sizeof (l));
	bzero(lp, sizeof (smbios_lang_t));

	lp->smbla_cur = smb_strptr(stp, l.smblang_cur);
	lp->smbla_fmt = l.smblang_flags & 1;
	lp->smbla_num = l.smblang_num;

	return (stp->smbst_hdr->smbh_hdl);
}

id_t
smbios_info_eventlog(smbios_hdl_t *shp, smbios_evlog_t *evp)
{
	const smb_struct_t *stp = smb_lookup_type(shp, SMB_TYPE_EVENTLOG);
	const smb_sel_t *sel;
	size_t len;

	if (stp == NULL)
		return (-1); /* errno is set for us */

	if (stp->smbst_hdr->smbh_len < sizeof (smb_sel_t) - sizeof (uint8_t))
		return (smb_set_errno(shp, ESMB_CORRUPT));

	sel = (smb_sel_t *)(uintptr_t)stp->smbst_hdr;
	len = stp->smbst_hdr->smbh_len - sizeof (smb_sel_t) + sizeof (uint8_t);
	bzero(evp, sizeof (smbios_evlog_t));

	if (len < sel->smbsel_typec * sel->smbsel_typesz)
		return (smb_set_errno(shp, ESMB_CORRUPT));

	evp->smbev_size = sel->smbsel_len;
	evp->smbev_hdr = sel->smbsel_hdroff;
	evp->smbev_data = sel->smbsel_dataoff;
	evp->smbev_method = sel->smbsel_method;
	evp->smbev_flags = sel->smbsel_status;
	evp->smbev_format = sel->smbsel_format;
	evp->smbev_token = sel->smbsel_token;
	evp->smbev_addr.eva_addr = sel->smbsel_addr;

	if (sel->smbsel_typesz == sizeof (smbios_evtype_t)) {
		evp->smbev_typec = sel->smbsel_typec;
		evp->smbev_typev = (void *)(uintptr_t)sel->smbsel_typev;
	}

	return (stp->smbst_hdr->smbh_hdl);
}

int
smbios_info_memarray(smbios_hdl_t *shp, id_t id, smbios_memarray_t *map)
{
	const smb_struct_t *stp = smb_lookup_id(shp, id);
	smb_memarray_t m;

	if (stp == NULL)
		return (-1); /* errno is set for us */

	if (stp->smbst_hdr->smbh_type != SMB_TYPE_MEMARRAY)
		return (smb_set_errno(shp, ESMB_TYPE));

	smb_info_bcopy(stp->smbst_hdr, &m, sizeof (m));
	bzero(map, sizeof (smbios_memarray_t));

	map->smbma_location = m.smbmarr_loc;
	map->smbma_use = m.smbmarr_use;
	map->smbma_ecc = m.smbmarr_ecc;
	map->smbma_ndevs = m.smbmarr_ndevs;
	map->smbma_err = m.smbmarr_err;

	if (m.smbmarr_cap != 0x80000000)
		map->smbma_size = (uint64_t)m.smbmarr_cap * 1024;
	else if (m.smbmarr_extcap != 0)
		map->smbma_size = m.smbmarr_extcap;
	else
		map->smbma_size = 0; /* unknown */

	return (0);
}

int
smbios_info_memarrmap(smbios_hdl_t *shp, id_t id, smbios_memarrmap_t *map)
{
	const smb_struct_t *stp = smb_lookup_id(shp, id);
	smb_memarrmap_t m;

	if (stp == NULL)
		return (-1); /* errno is set for us */

	if (stp->smbst_hdr->smbh_type != SMB_TYPE_MEMARRAYMAP)
		return (smb_set_errno(shp, ESMB_TYPE));

	smb_info_bcopy(stp->smbst_hdr, &m, sizeof (m));
	bzero(map, sizeof (smbios_memarrmap_t));

	map->smbmam_array = m.smbamap_array;
	map->smbmam_width = m.smbamap_width;

	if (m.smbamap_start != 0xFFFFFFFF && m.smbamap_end != 0xFFFFFFFF) {
		map->smbmam_addr = (uint64_t)m.smbamap_start * 1024;
		map->smbmam_size = (uint64_t)
		    (m.smbamap_end - m.smbamap_start + 1) * 1024;
	} else if (m.smbamap_extstart != 0 && m.smbamap_extend != 0) {
		map->smbmam_addr = m.smbamap_extstart;
		map->smbmam_size = m.smbamap_extend - m.smbamap_extstart + 1;
	}

	return (0);
}

int
smbios_info_memdevice(smbios_hdl_t *shp, id_t id, smbios_memdevice_t *mdp)
{
	const smb_struct_t *stp = smb_lookup_id(shp, id);
	smb_memdevice_t m;

	if (stp == NULL)
		return (-1); /* errno is set for us */

	if (stp->smbst_hdr->smbh_type != SMB_TYPE_MEMDEVICE)
		return (smb_set_errno(shp, ESMB_TYPE));

	smb_info_bcopy(stp->smbst_hdr, &m, sizeof (m));
	bzero(mdp, sizeof (smb_base_memdevice_t));

	mdp->smbmd_array = m.smbmdev_array;
	mdp->smbmd_error = m.smbmdev_error;
	mdp->smbmd_twidth = m.smbmdev_twidth == 0xFFFF ? -1U : m.smbmdev_twidth;
	mdp->smbmd_dwidth = m.smbmdev_dwidth == 0xFFFF ? -1U : m.smbmdev_dwidth;

	if (m.smbmdev_size == 0x7FFF) {
		mdp->smbmd_size = (uint64_t)m.smbmdev_extsize;
		mdp->smbmd_size *= 1024 * 1024; /* convert MB to bytes */
	} else if (m.smbmdev_size != 0xFFFF) {
		mdp->smbmd_size = (uint64_t)(m.smbmdev_size & ~SMB_MDS_KBYTES);
		if (m.smbmdev_size & SMB_MDS_KBYTES)
			mdp->smbmd_size *= 1024;
		else
			mdp->smbmd_size *= 1024 * 1024;
	} else
		mdp->smbmd_size = -1ULL; /* size unknown */

	mdp->smbmd_form = m.smbmdev_form;
	mdp->smbmd_set = m.smbmdev_set;
	mdp->smbmd_type = m.smbmdev_type;
	mdp->smbmd_speed = m.smbmdev_speed;
	mdp->smbmd_flags = m.smbmdev_flags;
	mdp->smbmd_dloc = smb_strptr(stp, m.smbmdev_dloc);
	mdp->smbmd_bloc = smb_strptr(stp, m.smbmdev_bloc);

	if (smb_libgteq(shp, SMB_VERSION_26)) {
		mdp->smbmd_rank = m.smbmdev_attrs & 0x0F;
	}

	if (smb_libgteq(shp, SMB_VERSION_27)) {
		mdp->smbmd_clkspeed = m.smbmdev_clkspeed;
	}

	if (smb_libgteq(shp, SMB_VERSION_28)) {
		mdp->smbmd_minvolt = m.smbmdev_minvolt;
		mdp->smbmd_maxvolt = m.smbmdev_maxvolt;
		mdp->smbmd_confvolt = m.smbmdev_confvolt;
	}

	if (smb_libgteq(shp, SMB_VERSION_32)) {
		mdp->smbmd_memtech = m.smbmdev_memtech;
		mdp->smbmd_opcap_flags = m.smbmdev_opmode;
		mdp->smbmd_firmware_rev = smb_strptr(stp,
		    m.smbmdev_fwver);
		mdp->smbmd_modmfg_id = m.smbmdev_modulemfgid;
		mdp->smbmd_modprod_id = m.smbmdev_moduleprodid;
		mdp->smbmd_cntrlmfg_id = m.smbmdev_memsysmfgid;
		mdp->smbmd_cntrlprod_id = m.smbmdev_memsysprodid;
		mdp->smbmd_nvsize = m.smbmdev_nvsize;
		mdp->smbmd_volatile_size = m.smbmdev_volsize;
		mdp->smbmd_cache_size = m.smbmdev_cachesize;
		mdp->smbmd_logical_size = m.smbmdev_logicalsize;
	}

	if (smb_libgteq(shp, SMB_VERSION_33)) {
		if (m.smbmdev_speed == 0xffff) {
			mdp->smbmd_extspeed = m.smbmdev_extspeed;
		} else {
			mdp->smbmd_extspeed = m.smbmdev_speed;
		}

		if (m.smbmdev_clkspeed == 0xffff) {
			mdp->smbmd_extclkspeed = m.smbmdev_extclkspeed;
		} else {
			mdp->smbmd_extclkspeed = m.smbmdev_clkspeed;
		}
	}

	/*
	 * The unknown key for missing revision information for the RCD and
	 * PMIC0 is not all zeros. As such, we need to look if the device SMBIOS
	 * table is not 3.7 then we need to fix up the bits that we copied.
	 * After that we need to go back and check the consumer's version to
	 * actually place this data there.
	 */
	if (!smb_gteq(shp, SMB_VERSION_37)) {
		m.smbmdev_pmic0mfgid = SMB_MD_MFG_UNKNOWN;
		m.smbmdev_pmic0rev = SMB_MD_REV_UNKNOWN;
		m.smbmdev_rcdmfgid = SMB_MD_MFG_UNKNOWN;
		m.smbmdev_rcdrev = SMB_MD_REV_UNKNOWN;
	}

	if (smb_libgteq(shp, SMB_VERSION_37)) {
		mdp->smbmd_pmic0_mfgid = m.smbmdev_pmic0mfgid;
		mdp->smbmd_pmic0_rev = m.smbmdev_pmic0rev;
		mdp->smbmd_rcd_mfgid = m.smbmdev_rcdmfgid;
		mdp->smbmd_rcd_rev = m.smbmdev_rcdrev;
	}

	return (0);
}

int
smbios_info_memdevmap(smbios_hdl_t *shp, id_t id, smbios_memdevmap_t *mdp)
{
	const smb_struct_t *stp = smb_lookup_id(shp, id);
	smb_memdevmap_t m;

	if (stp == NULL)
		return (-1); /* errno is set for us */

	if (stp->smbst_hdr->smbh_type != SMB_TYPE_MEMDEVICEMAP)
		return (smb_set_errno(shp, ESMB_TYPE));

	smb_info_bcopy(stp->smbst_hdr, &m, sizeof (m));
	bzero(mdp, sizeof (smbios_memdevmap_t));

	mdp->smbmdm_device = m.smbdmap_device;
	mdp->smbmdm_arrmap = m.smbdmap_array;
	mdp->smbmdm_rpos = m.smbdmap_rpos;
	mdp->smbmdm_ipos = m.smbdmap_ipos;
	mdp->smbmdm_idepth = m.smbdmap_idepth;

	if (m.smbdmap_start != 0xFFFFFFFF && m.smbdmap_end != 0xFFFFFFFF) {
		mdp->smbmdm_addr = (uint64_t)m.smbdmap_start * 1024;
		mdp->smbmdm_size = (uint64_t)
		    (m.smbdmap_end - m.smbdmap_start + 1) * 1024;
	} else if (m.smbdmap_extstart != 0 && m.smbdmap_extend != 0) {
		mdp->smbmdm_addr = m.smbdmap_extstart;
		mdp->smbmdm_size = m.smbdmap_extend - m.smbdmap_extstart + 1;
	}

	return (0);
}

id_t
smbios_info_hwsec(smbios_hdl_t *shp, smbios_hwsec_t *hsp)
{
	const smb_struct_t *stp = smb_lookup_type(shp, SMB_TYPE_SECURITY);
	smb_hwsec_t hs;

	if (stp == NULL)
		return (-1); /* errno is set for us */

	smb_info_bcopy(stp->smbst_hdr, &hs, sizeof (hs));
	bzero(hsp, sizeof (smbios_hwsec_t));

	hsp->smbh_pwr_ps = SMB_HWS_PWR_PS(hs.smbhs_settings);
	hsp->smbh_kbd_ps = SMB_HWS_KBD_PS(hs.smbhs_settings);
	hsp->smbh_adm_ps = SMB_HWS_ADM_PS(hs.smbhs_settings);
	hsp->smbh_pan_ps = SMB_HWS_PAN_PS(hs.smbhs_settings);

	return (stp->smbst_hdr->smbh_hdl);
}

id_t
smbios_info_boot(smbios_hdl_t *shp, smbios_boot_t *bp)
{
	const smb_struct_t *stp = smb_lookup_type(shp, SMB_TYPE_BOOT);
	const smb_boot_t *b;

	if (stp == NULL)
		return (-1); /* errno is set for us */

	bzero(bp, sizeof (smbios_boot_t));

	b = (smb_boot_t *)(uintptr_t)stp->smbst_hdr;

	bp->smbt_status = b->smbbo_status[0];
	bp->smbt_size = stp->smbst_hdr->smbh_len - sizeof (smb_boot_t);
	bp->smbt_data = bp->smbt_size ? &b->smbbo_status[1] : NULL;

	return (stp->smbst_hdr->smbh_hdl);
}

id_t
smbios_info_ipmi(smbios_hdl_t *shp, smbios_ipmi_t *ip)
{
	const smb_struct_t *stp = smb_lookup_type(shp, SMB_TYPE_IPMIDEV);
	smb_ipmi_t i;

	if (stp == NULL)
		return (-1); /* errno is set for us */

	smb_info_bcopy(stp->smbst_hdr, &i, sizeof (i));
	bzero(ip, sizeof (smbios_ipmi_t));

	ip->smbip_type = i.smbipm_type;
	ip->smbip_vers.smbv_major = SMB_IPM_SPEC_MAJOR(i.smbipm_spec);
	ip->smbip_vers.smbv_minor = SMB_IPM_SPEC_MINOR(i.smbipm_spec);
	ip->smbip_i2c = i.smbipm_i2c;
	ip->smbip_addr = i.smbipm_addr & ~SMB_IPM_ADDR_IO;
	ip->smbip_intr = i.smbipm_intr;

	if (i.smbipm_bus != (uint8_t)-1)
		ip->smbip_bus = i.smbipm_bus;
	else
		ip->smbip_bus = -1u;

	if (SMB_IPM_INFO_LSB(i.smbipm_info))
		ip->smbip_addr |= 1; /* turn on least-significant bit of addr */

	if (i.smbipm_addr & SMB_IPM_ADDR_IO) {
		switch (SMB_IPM_INFO_REGS(i.smbipm_info)) {
		case SMB_IPM_REGS_1B:
			ip->smbip_regspacing = 1;
			break;
		case SMB_IPM_REGS_4B:
			ip->smbip_regspacing = 4;
			break;
		case SMB_IPM_REGS_16B:
			ip->smbip_regspacing = 16;
			break;
		default:
			ip->smbip_regspacing = 1;
		}
		ip->smbip_flags |= SMB_IPMI_F_IOADDR;
	}

	if (SMB_IPM_INFO_ISPEC(i.smbipm_info))
		ip->smbip_flags |= SMB_IPMI_F_INTRSPEC;

	if (SMB_IPM_INFO_IPOL(i.smbipm_info) == SMB_IPM_IPOL_HI)
		ip->smbip_flags |= SMB_IPMI_F_INTRHIGH;

	if (SMB_IPM_INFO_IMODE(i.smbipm_info) == SMB_IPM_IMODE_EDGE)
		ip->smbip_flags |= SMB_IPMI_F_INTREDGE;

	return (stp->smbst_hdr->smbh_hdl);
}

static boolean_t
smbios_has_oemstr(smbios_hdl_t *shp, const char *oemstr)
{
	const smb_struct_t *stp = shp->sh_structs;
	smb_strtab_t s;
	int i, j;

	for (i = 0; i < shp->sh_nstructs; i++, stp++) {
		if (stp->smbst_hdr->smbh_type != SMB_TYPE_OEMSTR)
			continue;

		smb_info_bcopy(stp->smbst_hdr, &s, sizeof (s));
		for (j = 0; j < s.smbtb_count; j++)
			if (strcmp(smb_strptr(stp, j + 1), oemstr) == 0)
				return (B_TRUE);
	}

	return (B_FALSE);
}

static const char *
smb_serial_valid(const char *serial)
{
	char buf[MAXNAMELEN];
	int i = 0;

	if (serial == NULL)
		return (NULL);

	(void) strlcpy(buf, serial, sizeof (buf));

	while (buf[i] != '\0' && buf[i] == ' ')
		i++;

	if (buf[i] == '\0' || strstr(buf, SMB_DEFAULT1) != NULL ||
	    strstr(buf, SMB_DEFAULT2) != NULL)
		return (NULL);

	return (serial);
}

/*
 * Get chassis SN or product SN
 */
static int
smb_get_sn(smbios_hdl_t *shp, const char **psnp, const char **csnp)
{
	const smb_struct_t *stp;
	smbios_info_t s1, s3;

	if (psnp == NULL || csnp == NULL)
		return (smb_set_errno(shp, ESMB_INVAL));

	*psnp = *csnp = NULL;

	/*
	 * If SMBIOS meets Sun's PRMS requirements, retrieve product SN
	 * from type 1 structure, and chassis SN from type 3 structure.
	 * Otherwise return SN in type 1 structure as chassis SN.
	 */

	/* Get type 1 SN */
	if ((stp = smb_lookup_type(shp, SMB_TYPE_SYSTEM)) == NULL ||
	    smbios_info_common(shp, stp->smbst_hdr->smbh_hdl, &s1) == SMB_ERR)
		s1.smbi_serial = NULL;

	/* Get type 3 SN */
	if ((stp = smb_lookup_type(shp, SMB_TYPE_CHASSIS)) == NULL ||
	    smbios_info_common(shp, stp->smbst_hdr->smbh_hdl, &s3) == SMB_ERR)
		s3.smbi_serial = NULL;

	if (smbios_has_oemstr(shp, SMB_PRMS1)) {
		*psnp = smb_serial_valid(s1.smbi_serial);
		*csnp = smb_serial_valid(s3.smbi_serial);
	} else {
		*csnp = smb_serial_valid(s1.smbi_serial);
	}

	return (0);
}

const char *
smbios_psn(smbios_hdl_t *shp)
{
	const char *psn, *csn;

	return (smb_get_sn(shp, &psn, &csn) == SMB_ERR ? NULL : psn);
}

const char *
smbios_csn(smbios_hdl_t *shp)
{
	const char *psn, *csn;

	return (smb_get_sn(shp, &psn, &csn) == SMB_ERR ? NULL : csn);
}

int
smbios_info_extprocessor(smbios_hdl_t *shp, id_t id,
    smbios_processor_ext_t *epp)
{
	const smb_struct_t *stp = smb_lookup_id(shp, id);
	smb_processor_ext_t *exp;

	if (stp == NULL)
		return (-1); /* errno is set for us */

	if (stp->smbst_hdr->smbh_type != SUN_OEM_EXT_PROCESSOR)
		return (smb_set_errno(shp, ESMB_TYPE));

	exp = (smb_processor_ext_t *)(uintptr_t)stp->smbst_hdr;
	bzero(epp, sizeof (smbios_processor_ext_t));

	epp->smbpe_processor = exp->smbpre_processor;
	epp->smbpe_fru = exp->smbpre_fru;
	epp->smbpe_n = exp->smbpre_n;
	epp->smbpe_apicid = exp->smbpre_apicid;

	return (0);
}

int
smbios_info_extport(smbios_hdl_t *shp, id_t id, smbios_port_ext_t *eportp)
{
	const smb_struct_t *stp = smb_lookup_id(shp, id);
	smb_port_ext_t *ep;

	if (stp == NULL)
		return (-1); /* errno is set for us */

	if (stp->smbst_hdr->smbh_type != SUN_OEM_EXT_PORT)
		return (smb_set_errno(shp, ESMB_TYPE));

	ep = (smb_port_ext_t *)(uintptr_t)stp->smbst_hdr;
	bzero(eportp, sizeof (smbios_port_ext_t));

	eportp->smbporte_chassis = ep->smbpoe_chassis;
	eportp->smbporte_port = ep->smbpoe_port;
	eportp->smbporte_dtype = ep->smbpoe_dtype;
	eportp->smbporte_devhdl = ep->smbpoe_devhdl;
	eportp->smbporte_phy = ep->smbpoe_phy;

	return (0);
}

int
smbios_info_pciexrc(smbios_hdl_t *shp, id_t id,
    smbios_pciexrc_t *rcp)
{
	const smb_struct_t *stp = smb_lookup_id(shp, id);
	smb_pciexrc_t rc;

	if (stp == NULL)
		return (-1); /* errno is set for us */

	if (stp->smbst_hdr->smbh_type != SUN_OEM_PCIEXRC)
		return (smb_set_errno(shp, ESMB_TYPE));

	smb_info_bcopy(stp->smbst_hdr, &rc, sizeof (rc));
	bzero(rcp, sizeof (smbios_pciexrc_t));

	rcp->smbpcie_bb = rc.smbpciexrc_bboard;
	rcp->smbpcie_bdf = rc.smbpciexrc_bdf;

	return (0);
}

int
smbios_info_extmemarray(smbios_hdl_t *shp, id_t id, smbios_memarray_ext_t *emap)
{
	const smb_struct_t *stp = smb_lookup_id(shp, id);
	smb_memarray_ext_t exma;

	if (stp == NULL)
		return (-1); /* errno is set for us */

	if (stp->smbst_hdr->smbh_type != SUN_OEM_EXT_MEMARRAY)
		return (smb_set_errno(shp, ESMB_TYPE));

	smb_info_bcopy(stp->smbst_hdr, &exma, sizeof (exma));
	bzero(emap, sizeof (smbios_memarray_ext_t));

	emap->smbmae_ma = exma.smbmarre_ma;
	emap->smbmae_comp = exma.smbmarre_component;
	emap->smbmae_bdf = exma.smbmarre_bdf;

	return (0);
}

int
smbios_info_extmemdevice(smbios_hdl_t *shp, id_t id,
    smbios_memdevice_ext_t *emdp)
{
	const smb_struct_t *stp = smb_lookup_id(shp, id);
	smb_memdevice_ext_t exmd;

	if (stp == NULL)
		return (-1); /* errno is set for us */

	if (stp->smbst_hdr->smbh_type != SUN_OEM_EXT_MEMDEVICE)
		return (smb_set_errno(shp, ESMB_TYPE));

	smb_info_bcopy(stp->smbst_hdr, &exmd, sizeof (exmd));
	bzero(emdp, sizeof (smbios_memdevice_ext_t));

	emdp->smbmdeve_md = exmd.smbmdeve_mdev;
	emdp->smbmdeve_drch = exmd.smbmdeve_dchan;
	emdp->smbmdeve_ncs = exmd.smbmdeve_ncs;

	return (0);
}

int
smbios_info_extmemdevice_cs(smbios_hdl_t *shp, id_t id, uint_t *ncsp,
    uint8_t **csp)
{
	const smb_struct_t *stp = smb_lookup_id(shp, id);
	smb_memdevice_ext_t exmd;
	size_t size;
	void *buf;

	if (stp == NULL)
		return (-1); /* errno is set for us */

	if (stp->smbst_hdr->smbh_type != SUN_OEM_EXT_MEMDEVICE)
		return (smb_set_errno(shp, ESMB_TYPE));

	smb_info_bcopy(stp->smbst_hdr, &exmd, sizeof (exmd));
	if (exmd.smbmdeve_ncs == 0) {
		*ncsp = 0;
		*csp = NULL;
		return (0);
	}

	size = exmd.smbmdeve_ncs * sizeof (*exmd.smbmdeve_cs);

	if (stp->smbst_hdr->smbh_len < sizeof (exmd) + size)
		return (smb_set_errno(shp, ESMB_SHORT));

	buf = smb_alloc(size);
	if (buf == NULL)
		return (smb_set_errno(shp, ESMB_NOMEM));
	smb_info_bcopy_offset(stp->smbst_hdr, buf, size, sizeof (exmd));

	*ncsp = exmd.smbmdeve_ncs;
	*csp = buf;
	return (0);
}

void
smbios_info_extmemdevice_cs_free(smbios_hdl_t *shp __unused, uint_t ncs,
    uint8_t *csp)
{
	size_t size = ncs * sizeof (uint8_t);

	if (size == 0) {
		ASSERT3P(csp, ==, NULL);
		return;
	}
	smb_free(csp, size);
}

int
smbios_info_powersup(smbios_hdl_t *shp, id_t id, smbios_powersup_t *psup)
{
	const smb_struct_t *stp = smb_lookup_id(shp, id);
	smb_powersup_t psu;

	if (stp == NULL)
		return (-1); /* errno is set for us */

	if (stp->smbst_hdr->smbh_type != SMB_TYPE_POWERSUP)
		return (smb_set_errno(shp, ESMB_TYPE));

	/* The minimum length required by the spec is 0x10. */
	if (stp->smbst_hdr->smbh_len < 0x10)
		return (smb_set_errno(shp, ESMB_SHORT));

	bzero(psup, sizeof (*psup));
	smb_info_bcopy(stp->smbst_hdr, &psu, sizeof (psu));
	psup->smbps_group = psu.smbpsup_group;
	psup->smbps_maxout = psu.smbpsup_max;

	if (SMB_PSU_CHARS_ISHOT(psu.smbpsup_char))
		psup->smbps_flags |= SMB_POWERSUP_F_HOT;
	if (SMB_PSU_CHARS_ISPRES(psu.smbpsup_char))
		psup->smbps_flags |= SMB_POWERSUP_F_PRESENT;
	if (SMB_PSU_CHARS_ISUNPLUG(psu.smbpsup_char))
		psup->smbps_flags |= SMB_POWERSUP_F_UNPLUG;

	psup->smbps_ivrs = SMB_PSU_CHARS_IVRS(psu.smbpsup_char);
	psup->smbps_status = SMB_PSU_CHARS_STATUS(psu.smbpsup_char);
	psup->smbps_pstype = SMB_PSU_CHARS_TYPE(psu.smbpsup_char);

	if (stp->smbst_hdr->smbh_len >= 0x12) {
		psup->smbps_vprobe = psu.smbpsup_vprobe;
	} else {
		psup->smbps_vprobe = 0xffff;
	}

	if (stp->smbst_hdr->smbh_len >= 0x14) {
		psup->smbps_cooldev = psu.smbpsup_cooldev;
	} else {
		psup->smbps_cooldev = 0xffff;
	}

	if (stp->smbst_hdr->smbh_len >= 0x16) {
		psup->smbps_iprobe = psu.smbpsup_iprobe;
	} else {
		psup->smbps_iprobe = 0xffff;
	}

	return (0);
}

int
smbios_info_vprobe(smbios_hdl_t *shp, id_t id, smbios_vprobe_t *vprobe)
{
	const smb_struct_t *stp = smb_lookup_id(shp, id);
	smb_vprobe_t vp;

	if (stp == NULL)
		return (-1); /* errno is set for us */

	if (stp->smbst_hdr->smbh_type != SMB_TYPE_VPROBE)
		return (smb_set_errno(shp, ESMB_TYPE));

	if (stp->smbst_hdr->smbh_len < SMB_VPROBE_MINLEN)
		return (smb_set_errno(shp, ESMB_SHORT));

	bzero(vprobe, sizeof (*vprobe));
	smb_info_bcopy(stp->smbst_hdr, &vp, sizeof (vp));
	vprobe->smbvp_description = smb_strptr(stp, vp.smbvpr_descr);
	vprobe->smbvp_location = SMB_VPROBE_LOCATION(vp.smbvpr_locstat);
	vprobe->smbvp_status = SMB_VPROBE_STATUS(vp.smbvpr_locstat);
	vprobe->smbvp_maxval = vp.smbvpr_maxval;
	vprobe->smbvp_minval = vp.smbvpr_minval;
	vprobe->smbvp_resolution = vp.smbvpr_resolution;
	vprobe->smbvp_tolerance	= vp.smbvpr_tolerance;
	vprobe->smbvp_accuracy = vp.smbvpr_accuracy;

	if (stp->smbst_hdr->smbh_len >= SMB_VPROBE_NOMINAL_MINLEN) {
		vprobe->smbvp_nominal = vp.smbvpr_nominal;
	} else {
		vprobe->smbvp_nominal = SMB_PROBE_UNKNOWN_VALUE;
	}

	return (0);
}

int
smbios_info_cooldev(smbios_hdl_t *shp, id_t id, smbios_cooldev_t *cooldev)
{
	const smb_struct_t *stp = smb_lookup_id(shp, id);
	smb_cooldev_t cd;

	if (stp == NULL)
		return (-1); /* errno is set for us */

	if (stp->smbst_hdr->smbh_type != SMB_TYPE_COOLDEV)
		return (smb_set_errno(shp, ESMB_TYPE));

	if (stp->smbst_hdr->smbh_len < SMB_COOLDEV_MINLEN)
		return (smb_set_errno(shp, ESMB_SHORT));

	bzero(cooldev, sizeof (*cooldev));
	smb_info_bcopy(stp->smbst_hdr, &cd, sizeof (cd));
	cooldev->smbcd_tprobe = cd.smbcdev_tprobe;
	cooldev->smbcd_type = SMB_COOLDEV_TYPE(cd.smbcdev_typstat);
	cooldev->smbcd_status = SMB_COOLDEV_STATUS(cd.smbcdev_typstat);
	cooldev->smbcd_group = cd.smbcdev_group;
	cooldev->smbcd_oem = cd.smbcdev_oem;

	if (stp->smbst_hdr->smbh_len >= SMB_COOLDEV_NOMINAL_MINLEN) {
		cooldev->smbcd_nominal = cd.smbcdev_nominal;
	} else {
		cooldev->smbcd_nominal = SMB_PROBE_UNKNOWN_VALUE;
	}

	/*
	 * The description field was added in SMBIOS version 2.7. The
	 * SMB_TYPE_COOLDEV support was only added after all of the 2.7+ fields
	 * were added in the spec. So while a user may request an older version,
	 * we don't have to worry about old structures and just simply skip it
	 * if they're not asking for it.
	 */
	if (smb_libgteq(shp, SMB_VERSION_27) &&
	    smb_gteq(shp, SMB_VERSION_27) &&
	    stp->smbst_hdr->smbh_len >= SMB_COOLDEV_DESCR_MINLEN) {
		cooldev->smbcd_descr = smb_strptr(stp, cd.smbcdev_descr);
	} else {
		cooldev->smbcd_descr = NULL;
	}

	return (0);
}

int
smbios_info_tprobe(smbios_hdl_t *shp, id_t id, smbios_tprobe_t *tprobe)
{
	const smb_struct_t *stp = smb_lookup_id(shp, id);
	smb_tprobe_t tp;

	if (stp == NULL)
		return (-1); /* errno is set for us */

	if (stp->smbst_hdr->smbh_type != SMB_TYPE_TPROBE)
		return (smb_set_errno(shp, ESMB_TYPE));

	if (stp->smbst_hdr->smbh_len < SMB_TPROBE_MINLEN)
		return (smb_set_errno(shp, ESMB_SHORT));

	bzero(tprobe, sizeof (*tprobe));
	smb_info_bcopy(stp->smbst_hdr, &tp, sizeof (tp));
	tprobe->smbtp_description = smb_strptr(stp, tp.smbtpr_descr);
	tprobe->smbtp_location = SMB_TPROBE_LOCATION(tp.smbtpr_locstat);
	tprobe->smbtp_status = SMB_TPROBE_STATUS(tp.smbtpr_locstat);
	tprobe->smbtp_maxval = tp.smbtpr_maxval;
	tprobe->smbtp_minval = tp.smbtpr_minval;
	tprobe->smbtp_resolution = tp.smbtpr_resolution;
	tprobe->smbtp_tolerance	= tp.smbtpr_tolerance;
	tprobe->smbtp_accuracy = tp.smbtpr_accuracy;

	if (stp->smbst_hdr->smbh_len >= SMB_TPROBE_NOMINAL_MINLEN) {
		tprobe->smbtp_nominal = tp.smbtpr_nominal;
	} else {
		tprobe->smbtp_nominal = SMB_PROBE_UNKNOWN_VALUE;
	}

	return (0);
}

int
smbios_info_iprobe(smbios_hdl_t *shp, id_t id, smbios_iprobe_t *iprobe)
{
	const smb_struct_t *sip = smb_lookup_id(shp, id);
	smb_iprobe_t ip;

	if (sip == NULL)
		return (-1); /* errno is set for us */

	if (sip->smbst_hdr->smbh_type != SMB_TYPE_IPROBE)
		return (smb_set_errno(shp, ESMB_TYPE));

	if (sip->smbst_hdr->smbh_len < SMB_IPROBE_MINLEN)
		return (smb_set_errno(shp, ESMB_SHORT));

	bzero(iprobe, sizeof (*iprobe));
	smb_info_bcopy(sip->smbst_hdr, &ip, sizeof (ip));
	iprobe->smbip_description = smb_strptr(sip, ip.smbipr_descr);
	iprobe->smbip_location = SMB_IPROBE_LOCATION(ip.smbipr_locstat);
	iprobe->smbip_status = SMB_IPROBE_STATUS(ip.smbipr_locstat);
	iprobe->smbip_maxval = ip.smbipr_maxval;
	iprobe->smbip_minval = ip.smbipr_minval;
	iprobe->smbip_resolution = ip.smbipr_resolution;
	iprobe->smbip_tolerance	= ip.smbipr_tolerance;
	iprobe->smbip_accuracy = ip.smbipr_accuracy;

	if (sip->smbst_hdr->smbh_len >= SMB_IPROBE_NOMINAL_MINLEN) {
		iprobe->smbip_nominal = ip.smbipr_nominal;
	} else {
		iprobe->smbip_nominal = SMB_PROBE_UNKNOWN_VALUE;
	}

	return (0);
}

int
smbios_info_processor_info(smbios_hdl_t *shp, id_t id,
    smbios_processor_info_t *proc)
{
	const smb_struct_t *stp = smb_lookup_id(shp, id);
	smb_processor_info_t pi;

	if (stp == NULL)
		return (-1); /* errno is set for us */

	if (stp->smbst_hdr->smbh_type != SMB_TYPE_PROCESSOR_INFO)
		return (smb_set_errno(shp, ESMB_TYPE));

	if (stp->smbst_hdr->smbh_len < sizeof (pi))
		return (smb_set_errno(shp, ESMB_SHORT));

	bzero(proc, sizeof (*proc));
	smb_info_bcopy(stp->smbst_hdr, &pi, sizeof (pi));

	if (sizeof (pi) + pi.smbpai_len > stp->smbst_hdr->smbh_len)
		return (smb_set_errno(shp, ESMB_CORRUPT));

	proc->smbpi_processor = pi.smbpai_proc;
	proc->smbpi_ptype = pi.smbpai_type;

	return (0);
}

int
smbios_info_processor_riscv(smbios_hdl_t *shp, id_t id,
    smbios_processor_info_riscv_t *riscv)
{
	const smb_struct_t *stp = smb_lookup_id(shp, id);
	const smb_processor_info_t *proc;
	const smb_processor_info_riscv_t *rv;

	if (stp == NULL) {
		return (-1); /* errno is set for us */
	}

	if (stp->smbst_hdr->smbh_type != SMB_TYPE_PROCESSOR_INFO) {
		return (smb_set_errno(shp, ESMB_TYPE));
	}

	if (stp->smbst_hdr->smbh_len < sizeof (*proc)) {
		return (smb_set_errno(shp, ESMB_SHORT));
	}

	proc = (const smb_processor_info_t *)stp->smbst_hdr;
	if (sizeof (*proc) + proc->smbpai_len > stp->smbst_hdr->smbh_len) {
		return (smb_set_errno(shp, ESMB_CORRUPT));
	}

	switch (proc->smbpai_type) {
	case SMB_PROCINFO_T_RV32:
	case SMB_PROCINFO_T_RV64:
	case SMB_PROCINFO_T_RV128:
		break;
	default:
		return (smb_set_errno(shp, ESMB_TYPE));
	}

	if (stp->smbst_hdr->smbh_len < sizeof (*proc) + sizeof (*rv)) {
		return (smb_set_errno(shp, ESMB_SHORT));
	}
	rv = (const smb_processor_info_riscv_t *)&proc->smbpai_data[0];
	if (rv->smbpairv_len != sizeof (*rv)) {
		return (smb_set_errno(shp, ESMB_CORRUPT));
	}

	bcopy(rv->smbpairv_hartid, riscv->smbpirv_hartid,
	    sizeof (riscv->smbpirv_hartid));
	bcopy(rv->smbpairv_vendid, riscv->smbpirv_vendid,
	    sizeof (riscv->smbpirv_vendid));
	bcopy(rv->smbpairv_archid, riscv->smbpirv_archid,
	    sizeof (riscv->smbpirv_archid));
	bcopy(rv->smbpairv_machid, riscv->smbpirv_machid,
	    sizeof (riscv->smbpirv_machid));
	bcopy(rv->smbpairv_metdi, riscv->smbpirv_metdi,
	    sizeof (riscv->smbpirv_metdi));
	bcopy(rv->smbpairv_mitdi, riscv->smbpirv_mitdi,
	    sizeof (riscv->smbpirv_mitdi));
	riscv->smbpirv_isa = rv->smbpairv_isa;
	riscv->smbpirv_privlvl = rv->smbpairv_privlvl;
	riscv->smbpirv_boothart = rv->smbpairv_boot;
	riscv->smbpirv_xlen = rv->smbpairv_xlen;
	riscv->smbpirv_mxlen = rv->smbpairv_mxlen;
	riscv->smbpirv_sxlen = rv->smbpairv_sxlen;
	riscv->smbpirv_uxlen = rv->smbpairv_uxlen;

	return (0);
}

int
smbios_info_pointdev(smbios_hdl_t *shp, id_t id, smbios_pointdev_t *pd)
{
	const smb_struct_t *stp = smb_lookup_id(shp, id);
	smb_pointdev_t point;

	if (stp == NULL) {
		return (-1); /* errno is set for us */
	}

	if (stp->smbst_hdr->smbh_type != SMB_TYPE_POINTDEV) {
		return (smb_set_errno(shp, ESMB_TYPE));
	}

	if (stp->smbst_hdr->smbh_len < sizeof (point)) {
		return (smb_set_errno(shp, ESMB_SHORT));
	}

	bzero(pd, sizeof (*pd));
	smb_info_bcopy(stp->smbst_hdr, &point, sizeof (point));

	pd->smbpd_type = point.smbpdev_type;
	pd->smbpd_iface = point.smbpdev_iface;
	pd->smbpd_nbuttons = point.smbpdev_nbuttons;

	return (0);
}

int
smbios_info_battery(smbios_hdl_t *shp, id_t id, smbios_battery_t *bp)
{
	const smb_struct_t *stp = smb_lookup_id(shp, id);
	smb_battery_t bat;

	if (stp == NULL) {
		return (-1); /* errno is set for us */
	}

	if (stp->smbst_hdr->smbh_type != SMB_TYPE_BATTERY) {
		return (smb_set_errno(shp, ESMB_TYPE));
	}

	if (stp->smbst_hdr->smbh_len < sizeof (bat)) {
		return (smb_set_errno(shp, ESMB_SHORT));
	}

	bzero(bp, sizeof (*bp));
	smb_info_bcopy(stp->smbst_hdr, &bat, sizeof (bat));

	/*
	 * This may be superseded by the SBDS data.
	 */
	if (bat.smbbat_date != 0) {
		bp->smbb_date = smb_strptr(stp, bat.smbbat_date);
	} else {
		bp->smbb_date = NULL;
	}

	/*
	 * This may be superseded by the SBDS data.
	 */
	if (bat.smbbat_serial != 0) {
		bp->smbb_serial = smb_strptr(stp, bat.smbbat_serial);
	} else {
		bp->smbb_serial = NULL;
	}

	bp->smbb_chem = bat.smbbat_chem;
	bp->smbb_cap = bat.smbbat_cap;
	if (bat.smbbat_mult > 0) {
		bp->smbb_cap *= bat.smbbat_mult;
	}
	bp->smbb_volt = bat.smbbat_volt;
	bp->smbb_version = smb_strptr(stp, bat.smbbat_version);
	bp->smbb_err = bat.smbbat_err;
	bp->smbb_ssn = bat.smbbat_ssn;
	bp->smbb_syear = 1980 + (bat.smbbat_sdate >> 9);
	bp->smbb_smonth = (bat.smbbat_sdate >> 5) & 0xf;
	bp->smbb_sday = bat.smbbat_sdate & 0x1f;
	bp->smbb_schem = smb_strptr(stp, bat.smbbat_schem);
	bp->smbb_oemdata = bat.smbbat_oemdata;

	return (0);
}

int
smbios_info_strprop(smbios_hdl_t *shp, id_t id, smbios_strprop_t *str)
{
	const smb_struct_t *stp = smb_lookup_id(shp, id);
	smb_strprop_t prop;

	if (stp == NULL) {
		return (-1); /* errno is set for us */
	}

	if (stp->smbst_hdr->smbh_type != SMB_TYPE_STRPROP) {
		return (smb_set_errno(shp, ESMB_TYPE));
	}

	if (stp->smbst_hdr->smbh_len < sizeof (prop)) {
		return (smb_set_errno(shp, ESMB_SHORT));
	}

	if (stp->smbst_hdr->smbh_len > sizeof (prop)) {
		return (smb_set_errno(shp, ESMB_CORRUPT));
	}

	bzero(str, sizeof (*str));
	smb_info_bcopy(stp->smbst_hdr, &prop, sizeof (prop));

	str->smbsp_parent = prop.smbstrp_phdl;
	str->smbsp_prop_id = prop.smbstrp_prop_id;
	str->smbsp_prop_val = smb_strptr(stp, prop.smbstrp_prop_val);

	return (0);
}

int
smbios_info_fwinfo(smbios_hdl_t *shp, id_t id, smbios_fwinfo_t *fwinfo)
{
	const smb_struct_t *stp = smb_lookup_id(shp, id);
	smb_fwinfo_t fw;

	if (stp == NULL) {
		return (-1); /* errno is set for us */
	}

	if (stp->smbst_hdr->smbh_type != SMB_TYPE_FWINFO) {
		return (smb_set_errno(shp, ESMB_TYPE));
	}

	if (stp->smbst_hdr->smbh_len < sizeof (fw)) {
		return (smb_set_errno(shp, ESMB_SHORT));
	}

	/*
	 * The verion and manufacturer are part of smbios_info_common().
	 */
	bzero(fwinfo, sizeof (*fwinfo));
	smb_info_bcopy(stp->smbst_hdr, &fw, sizeof (fw));
	fwinfo->smbfw_name = smb_strptr(stp, fw.smbfwii_name);
	fwinfo->smbfw_id = smb_strptr(stp, fw.smbfwii_id);
	fwinfo->smbfw_reldate = smb_strptr(stp, fw.smbfwii_reldate);
	fwinfo->smbfw_lsv = smb_strptr(stp, fw.smbfwii_lsv);
	fwinfo->smbfw_imgsz = fw.smbfwii_imgsz;
	fwinfo->smbfw_chars = fw.smbfwii_chars;
	fwinfo->smbfw_state = fw.smbfwii_state;
	fwinfo->smbfw_ncomps = fw.smbfwii_ncomps;
	fwinfo->smbfw_vers_fmt = fw.smbfwii_vers_fmt;
	fwinfo->smbfw_id_fmt = fw.smbfwii_id_fmt;

	return (0);
}

int
smbios_info_fwinfo_comps(smbios_hdl_t *shp, id_t id, uint_t *ncompsp,
    smbios_fwinfo_comp_t **compsp)
{
	const smb_struct_t *stp = smb_lookup_id(shp, id);
	smbios_fwinfo_comp_t *comps;
	smb_fwinfo_t fw;
	size_t need;
	uint_t i;

	if (stp == NULL) {
		return (-1); /* errno is set for us */
	}

	if (stp->smbst_hdr->smbh_type != SMB_TYPE_FWINFO) {
		return (smb_set_errno(shp, ESMB_TYPE));
	}

	if (stp->smbst_hdr->smbh_len < sizeof (fw)) {
		return (smb_set_errno(shp, ESMB_SHORT));
	}

	smb_info_bcopy(stp->smbst_hdr, &fw, sizeof (fw));
	if (fw.smbfwii_ncomps == 0) {
		*ncompsp = 0;
		*compsp = NULL;
		return (0);
	}

	need = fw.smbfwii_ncomps * sizeof (uint16_t) + sizeof (smb_fwinfo_t);
	if (stp->smbst_hdr->smbh_len < need) {
		return (smb_set_errno(shp, ESMB_SHORT));
	}

	comps = smb_alloc(fw.smbfwii_ncomps * sizeof (smbios_fwinfo_comp_t));
	if (comps == NULL) {
		return (smb_set_errno(shp, ESMB_NOMEM));
	}

	for (i = 0; i < fw.smbfwii_ncomps; i++) {
		uint16_t id;
		size_t off = sizeof (smb_fwinfo_t) + sizeof (uint16_t) * i;
		smb_info_bcopy_offset(stp->smbst_hdr, &id, sizeof (id), off);
		comps[i].smbfwe_id = id;
	}

	*ncompsp = fw.smbfwii_ncomps;
	*compsp = comps;

	return (0);
}

void
smbios_info_fwinfo_comps_free(smbios_hdl_t *shp, uint_t ncomps,
    smbios_fwinfo_comp_t *comps)
{
	size_t sz = ncomps * sizeof (smbios_fwinfo_comp_t);

	if (ncomps == 0) {
		ASSERT3P(comps, ==, NULL);
		return;
	}

	smb_free(comps, sz);
}

int
smbios_info_addinfo_nents(smbios_hdl_t *shp, id_t id, uint_t *nentsp)
{
	const smb_struct_t *stp = smb_lookup_id(shp, id);
	smb_addinfo_t add;

	if (stp == NULL) {
		return (-1); /* errno is set for us */
	}

	if (stp->smbst_hdr->smbh_type != SMB_TYPE_ADDINFO) {
		return (smb_set_errno(shp, ESMB_TYPE));
	}

	if (stp->smbst_hdr->smbh_len < sizeof (add)) {
		return (smb_set_errno(shp, ESMB_SHORT));
	}

	smb_info_bcopy(stp->smbst_hdr, &add, sizeof (add));
	*nentsp = add.smbai_nents;

	return (0);
}

void
smbios_info_addinfo_ent_free(smbios_hdl_t *hdl, smbios_addinfo_ent_t *ent)
{
	if (ent->smbai_dlen > 0) {
		ASSERT3P(ent->smbai_data, !=, NULL);
		smb_free(ent->smbai_data, ent->smbai_dlen);
	}

	smb_free(ent, sizeof (smbios_addinfo_ent_t));
}

int
smbios_info_addinfo_ent(smbios_hdl_t *shp, id_t id, uint_t entno,
    smbios_addinfo_ent_t **entp)
{
	const smb_struct_t *stp = smb_lookup_id(shp, id);
	size_t off;
	smb_addinfo_t add;
	smb_addinfo_ent_t ent;
	smbios_addinfo_ent_t *entry;
	uint_t i;

	if (stp == NULL) {
		return (-1); /* errno is set for us */
	}

	if (stp->smbst_hdr->smbh_type != SMB_TYPE_ADDINFO) {
		return (smb_set_errno(shp, ESMB_TYPE));
	}

	if (stp->smbst_hdr->smbh_len < sizeof (add)) {
		return (smb_set_errno(shp, ESMB_SHORT));
	}

	smb_info_bcopy(stp->smbst_hdr, &add, sizeof (add));
	if (entno >= add.smbai_nents) {
		return (smb_set_errno(shp, ESMB_REQVAL));
	}

	off = sizeof (add);
	for (i = 0; i <= entno; i++) {
		if (off + sizeof (ent) > stp->smbst_hdr->smbh_len) {
			return (smb_set_errno(shp, ESMB_SHORT));
		}

		smb_info_bcopy_offset(stp->smbst_hdr, &ent, sizeof (ent), off);
		if (ent.smbaie_len < sizeof (ent)) {
			return (smb_set_errno(shp, ESMB_SHORT));
		}

		if (ent.smbaie_len + off > stp->smbst_hdr->smbh_len) {
			return (smb_set_errno(shp, ESMB_CORRUPT));
		}

		if (i != entno) {
			off += ent.smbaie_len;
		}
	}

	entry = smb_alloc(sizeof (smbios_addinfo_ent_t));
	if (entry == NULL) {
		return (smb_set_errno(shp, ESMB_NOMEM));
	}

	entry->smbai_ref = ent.smbaie_rhdl;
	entry->smbai_ref_off = ent.smbaie_off;
	if (ent.smbaie_str != 0) {
		entry->smbai_str = smb_strptr(stp, ent.smbaie_str);
	} else {
		entry->smbai_str = NULL;
	}
	entry->smbai_dlen = ent.smbaie_len - sizeof (ent);
	if (entry->smbai_dlen > 0) {
		entry->smbai_data = smb_alloc(entry->smbai_dlen);
		if (entry->smbai_data == NULL) {
			smb_free(entry, sizeof (smbios_addinfo_ent_t));
			return (smb_set_errno(shp, ESMB_NOMEM));
		}
		smb_info_bcopy_offset(stp->smbst_hdr, entry->smbai_data,
		    entry->smbai_dlen, off + offsetof(smb_addinfo_ent_t,
		    smbaie_val));
	} else {
		entry->smbai_data = NULL;
	}

	*entp = entry;
	return (0);
}
