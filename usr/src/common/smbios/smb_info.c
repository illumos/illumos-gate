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
 */

#include <sys/smbios_impl.h>

#ifndef _KERNEL
#include <fcntl.h>
#include <unistd.h>
#endif

/*
 * A large number of SMBIOS structures contain a set of common strings used to
 * describe a h/w component's serial number, manufacturer, etc.  These fields
 * helpfully have different names and offsets and sometimes aren't consistent.
 * To simplify life for our clients, we factor these common things out into
 * smbios_info_t, which can be retrieved for any structure.  The following
 * table describes the mapping from a given structure to the smbios_info_t.
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
} _smb_infospecs[] = {
	{ SMB_TYPE_SYSTEM,
		offsetof(smb_system_t, smbsi_manufacturer),
		offsetof(smb_system_t, smbsi_product),
		offsetof(smb_system_t, smbsi_version),
		offsetof(smb_system_t, smbsi_serial),
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
		0 },
	{ SMB_TYPE_CHASSIS,
		offsetof(smb_chassis_t, smbch_manufacturer),
		0,
		offsetof(smb_chassis_t, smbch_version),
		offsetof(smb_chassis_t, smbch_serial),
		offsetof(smb_chassis_t, smbch_asset),
		0,
		0 },
	{ SMB_TYPE_PROCESSOR,
		offsetof(smb_processor_t, smbpr_manufacturer),
		0,
		offsetof(smb_processor_t, smbpr_version),
		offsetof(smb_processor_t, smbpr_serial),
		offsetof(smb_processor_t, smbpr_asset),
		offsetof(smb_processor_t, smbpr_socket),
		offsetof(smb_processor_t, smbpr_part) },
	{ SMB_TYPE_CACHE,
		0,
		0,
		0,
		0,
		0,
		offsetof(smb_cache_t, smbca_socket),
		0 },
	{ SMB_TYPE_PORT,
		0,
		0,
		0,
		0,
		0,
		offsetof(smb_port_t, smbpo_iref),
		0 },
	{ SMB_TYPE_SLOT,
		0,
		0,
		0,
		0,
		0,
		offsetof(smb_slot_t, smbsl_name),
		0 },
	{ SMB_TYPE_MEMDEVICE,
		offsetof(smb_memdevice_t, smbmdev_manufacturer),
		0,
		0,
		offsetof(smb_memdevice_t, smbmdev_serial),
		offsetof(smb_memdevice_t, smbmdev_asset),
		offsetof(smb_memdevice_t, smbmdev_dloc),
		offsetof(smb_memdevice_t, smbmdev_part) },
	{ SMB_TYPE_POWERSUP,
		offsetof(smb_powersup_t, smbpsup_manufacturer),
		offsetof(smb_powersup_t, smbpsup_devname),
		offsetof(smb_powersup_t, smbpsup_rev),
		offsetof(smb_powersup_t, smbpsup_serial),
		offsetof(smb_powersup_t, smbpsup_asset),
		offsetof(smb_powersup_t, smbpsup_loc),
		offsetof(smb_powersup_t, smbpsup_part) },
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
smb_info_bcopy(const smb_header_t *hp, void *dst, size_t dstlen)
{
	if (dstlen > hp->smbh_len) {
		bcopy(hp, dst, hp->smbh_len);
		bzero((char *)dst + hp->smbh_len, dstlen - hp->smbh_len);
	} else
		bcopy(hp, dst, dstlen);
}

void
smbios_info_smbios(smbios_hdl_t *shp, smbios_entry_t *ep)
{
	bcopy(&shp->sh_ent, ep, sizeof (smbios_entry_t));
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
	bzero(bp, sizeof (smbios_bios_t));

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

	/*
	 * At present, we do not provide support for the contained object
	 * handles portion of the Base Board structure, as none of the 2.3+
	 * BIOSes commonly in use appear to implement it at present.
	 */
	bbp->smbb_chassis = bb.smbbb_chassis;
	bbp->smbb_flags = bb.smbbb_flags;
	bbp->smbb_type = bb.smbbb_type;

	return (0);
}

int
smbios_info_chassis(smbios_hdl_t *shp, id_t id, smbios_chassis_t *chp)
{
	const smb_struct_t *stp = smb_lookup_id(shp, id);
	smb_chassis_t ch;

	if (stp == NULL)
		return (-1); /* errno is set for us */

	if (stp->smbst_hdr->smbh_type != SMB_TYPE_CHASSIS)
		return (smb_set_errno(shp, ESMB_TYPE));

	smb_info_bcopy(stp->smbst_hdr, &ch, sizeof (ch));
	bzero(chp, sizeof (smbios_chassis_t));

	/*
	 * At present, we do not provide support for the contained object
	 * handles portion of the Chassis structure, as none of the 2.3+
	 * BIOSes commonly in use appear to implement it at present.
	 */
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

	return (0);
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
	bzero(pp, sizeof (smbios_processor_t));

	pp->smbp_cpuid = p.smbpr_cpuid;
	pp->smbp_type = p.smbpr_type;
	pp->smbp_family = p.smbpr_family;
	pp->smbp_voltage = p.smbpr_voltage;
	pp->smbp_maxspeed = p.smbpr_maxspeed;
	pp->smbp_curspeed = p.smbpr_curspeed;
	pp->smbp_status = p.smbpr_status;
	pp->smbp_upgrade = p.smbpr_upgrade;
	pp->smbp_l1cache = p.smbpr_l1cache;
	pp->smbp_l2cache = p.smbpr_l2cache;
	pp->smbp_l3cache = p.smbpr_l3cache;

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
	bzero(cap, sizeof (smbios_cache_t));

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

	if (stp == NULL)
		return (-1); /* errno is set for us */

	if (stp->smbst_hdr->smbh_type != SMB_TYPE_SLOT)
		return (smb_set_errno(shp, ESMB_TYPE));

	smb_info_bcopy(stp->smbst_hdr, &s, sizeof (s));
	bzero(sp, sizeof (smbios_slot_t));

	sp->smbl_name = smb_strptr(stp, s.smbsl_name);
	sp->smbl_type = s.smbsl_type;
	sp->smbl_width = s.smbsl_width;
	sp->smbl_usage = s.smbsl_usage;
	sp->smbl_length = s.smbsl_length;
	sp->smbl_id = s.smbsl_id;
	sp->smbl_ch1 = s.smbsl_ch1;
	sp->smbl_ch2 = s.smbsl_ch2;

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
	map->smbmam_addr = (uint64_t)m.smbamap_start * 1024;
	map->smbmam_size = (uint64_t)
	    (m.smbamap_end - m.smbamap_start + 1) * 1024;

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
	bzero(mdp, sizeof (smbios_memdevice_t));

	mdp->smbmd_array = m.smbmdev_array;
	mdp->smbmd_error = m.smbmdev_error;
	mdp->smbmd_twidth = m.smbmdev_twidth == 0xFFFF ? -1U : m.smbmdev_twidth;
	mdp->smbmd_dwidth = m.smbmdev_dwidth == 0xFFFF ? -1U : m.smbmdev_dwidth;

	if (mdp->smbmd_size != 0xFFFF) {
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
	mdp->smbmd_flags = m.smbmdev_flags;
	mdp->smbmd_dloc = smb_strptr(stp, m.smbmdev_dloc);
	mdp->smbmd_bloc = smb_strptr(stp, m.smbmdev_bloc);

	if (m.smbmdev_speed != 0)
		mdp->smbmd_speed = 1000 / m.smbmdev_speed; /* MHz -> nsec */

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
	mdp->smbmdm_addr = (uint64_t)m.smbdmap_start * 1024;
	mdp->smbmdm_size = (uint64_t)
	    (m.smbdmap_end - m.smbdmap_start + 1) * 1024;
	mdp->smbmdm_rpos = m.smbdmap_rpos;
	mdp->smbmdm_ipos = m.smbdmap_ipos;
	mdp->smbmdm_idepth = m.smbdmap_idepth;

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
	const smb_boot_t *b = (smb_boot_t *)(uintptr_t)stp->smbst_hdr;

	if (stp == NULL)
		return (-1); /* errno is set for us */

	bzero(bp, sizeof (smbios_boot_t));

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
