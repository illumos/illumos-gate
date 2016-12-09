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
 * Copyright 2016 Joyent, Inc.
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/smbios_impl.h>

static const uint_t _smb_hashlen = 64;		/* hash length (must be Pof2) */
static const char _smb_emptystr[] = "";		/* empty string to return */
int _smb_debug = 0;				/* default debug mode */

/*
 * Strip out identification information for you privacy weenies.  This is quite
 * simple using our smbios_info_common() abstraction: we just locate any serial
 * numbers and asset tags for each record, and then zero out those strings.
 * Then we must handle two special cases: SMB_TYPE_SYSTEM holds a 16-byte UUID
 * and SMB_TYPE_BATTERY stores a Smart Battery Data Spec 16-bit serial number.
 * We use a literal '0' rather than '\0' for zeroing strings because \0\0 in
 * the SMBIOS string table has a special meaning (denotes end-of-record).
 */
static void
smb_strip(smbios_hdl_t *shp)
{
	uint_t i;

	for (i = 0; i < shp->sh_nstructs; i++) {
		const smb_header_t *hp = shp->sh_structs[i].smbst_hdr;
		smbios_info_t info;
		char *p;

		if (hp->smbh_type == SMB_TYPE_SYSTEM &&
		    hp->smbh_len >= offsetof(smb_system_t, smbsi_wakeup)) {
			smb_system_t *sp = (smb_system_t *)(uintptr_t)hp;
			bzero(sp->smbsi_uuid, sizeof (sp->smbsi_uuid));
		}

		if (hp->smbh_type == SMB_TYPE_BATTERY &&
		    hp->smbh_len >= offsetof(smb_battery_t, smbbat_sdate)) {
			smb_battery_t *bp = (smb_battery_t *)(uintptr_t)hp;
			bp->smbbat_ssn = 0;
		}

		if (smbios_info_common(shp, hp->smbh_hdl, &info) != SMB_ERR) {
			for (p = (char *)info.smbi_serial; *p != '\0'; p++)
				*p = '0';
			for (p = (char *)info.smbi_asset; *p != '\0'; p++)
				*p = '0';
		}
	}
}

static int
smbios_bufopen_21(smbios_hdl_t *shp, const smbios_21_entry_t *ep, size_t len,
    int flags)
{
	if (strncmp(ep->smbe_eanchor, SMB_ENTRY_EANCHOR, SMB_ENTRY_EANCHORLEN))
		return (ESMB_HEADER);

	if (strncmp(ep->smbe_ianchor, SMB_ENTRY_IANCHOR, SMB_ENTRY_IANCHORLEN))
		return (ESMB_HEADER);

	smb_dprintf(shp, "opening SMBIOS version %u.%u bcdrev 0x%x\n",
	    ep->smbe_major, ep->smbe_minor, ep->smbe_bcdrev);

	if (!(flags & SMB_O_NOVERS)) {
		if (ep->smbe_major > SMB_MAJOR(SMB_VERSION))
			return (ESMB_NEW);

		if (ep->smbe_major < SMB_MAJOR(SMB_VERSION_23) || (
		    ep->smbe_major == SMB_MAJOR(SMB_VERSION_23) &&
		    ep->smbe_minor < SMB_MINOR(SMB_VERSION_23)))
			return (ESMB_OLD);
	}

	if (len < sizeof (smb_header_t) ||
	    ep->smbe_stlen < sizeof (smb_header_t) || len < ep->smbe_stlen)
		return (ESMB_SHORT);

	if (!(flags & SMB_O_NOCKSUM)) {
		uint8_t esum = 0, isum = 0;
		const uchar_t *p, *q;
		q = (uchar_t *)ep;

		for (p = q; p < q + ep->smbe_elen; p++)
			esum += *p;

		for (p = (uchar_t *)ep->smbe_ianchor; p < q + sizeof (*ep); p++)
			isum += *p;

		if (esum != 0 || isum != 0) {
			smb_dprintf(shp, "bad cksum: e=%x i=%x\n", esum, isum);
			return (ESMB_CKSUM);
		}
	}

	/*
	 * Copy the entry point into our handle.  The underlying entry point
	 * may be larger than our structure definition, so reset smbe_elen
	 * to our internal size and recompute good checksums for our copy.
	 */
	shp->sh_ent_type = SMBIOS_ENTRY_POINT_21;
	bcopy(ep, &shp->sh_ent, sizeof (smbios_entry_t));
	shp->sh_ent.ep21.smbe_elen = sizeof (smbios_entry_t);
	smbios_checksum(shp, &shp->sh_ent);

	shp->sh_ent_stnum = ep->smbe_stnum;
	shp->sh_smbvers = SMB_MAJMIN(ep->smbe_major, ep->smbe_minor);
	return (0);
}

static int
smbios_bufopen_30(smbios_hdl_t *shp, const smbios_30_entry_t *ep, size_t len,
    int flags)
{
	if (strncmp(ep->smbe_eanchor, SMB3_ENTRY_EANCHOR,
	    SMB3_ENTRY_EANCHORLEN))
		return (ESMB_HEADER);

	smb_dprintf(shp, "opening SMBIOS version %u.%u\n",
	    ep->smbe_major, ep->smbe_minor);

	if (!(flags & SMB_O_NOVERS)) {
		if (ep->smbe_major > SMB_MAJOR(SMB_VERSION))
			return (ESMB_NEW);

		if (ep->smbe_major < SMB_MAJOR(SMB_VERSION_23) || (
		    ep->smbe_major == SMB_MAJOR(SMB_VERSION_23) &&
		    ep->smbe_minor < SMB_MINOR(SMB_VERSION_23)))
			return (ESMB_OLD);
	}

	if (len < sizeof (smb_header_t) ||
	    ep->smbe_stlen < sizeof (smb_header_t) || len < ep->smbe_stlen)
		return (ESMB_SHORT);

	if (!(flags & SMB_O_NOCKSUM)) {
		uint8_t esum = 0;
		const uchar_t *p, *q;
		q = (uchar_t *)ep;

		for (p = q; p < q + ep->smbe_elen; p++)
			esum += *p;

		if (esum != 0) {
			smb_dprintf(shp, "bad cksum: e=%x\n", esum);
			return (ESMB_CKSUM);
		}
	}

	/*
	 * Copy the entry point into our handle.  The underlying entry point
	 * may be larger than our structure definition, so reset smbe_elen
	 * to our internal size and recompute good checksums for our copy.
	 */
	shp->sh_ent_type = SMBIOS_ENTRY_POINT_30;
	bcopy(ep, &shp->sh_ent, sizeof (smbios_entry_t));
	shp->sh_ent.ep30.smbe_elen = sizeof (smbios_entry_t);
	smbios_checksum(shp, &shp->sh_ent);

	shp->sh_smbvers = SMB_MAJMIN(ep->smbe_major, ep->smbe_minor);

	return (0);
}

static uint_t
smbios_table_nentries(const char *smbe_staddr, uint32_t smbe_stlen)
{
	uint_t i = 0;
	char *dmi;
	smb_header_t *hdr;

	if (smbe_staddr == NULL)
		return (i);

	for (dmi = (char *)smbe_staddr; dmi < smbe_staddr + smbe_stlen; i++) {
		hdr = (smb_header_t *)dmi;
		dmi += hdr->smbh_len;
		/*
		 * Search for the end of the string area.
		 */
		while (dmi + 1 < smbe_staddr + smbe_stlen &&
		    dmi[0] != '\0' && dmi[1] != '\0') {
			dmi++;
		}
		dmi += 2;
	}
	return (i);
}

smbios_hdl_t *
smbios_bufopen(const smbios_entry_t *ep, const void *buf, size_t len,
    int version, int flags, int *errp)
{
	smbios_hdl_t *shp = smb_zalloc(sizeof (smbios_hdl_t));
	const smb_header_t *hp, *nhp;
	const uchar_t *p, *q, *s;
	uint_t i, h;
	int err;

	switch (version) {
	case SMB_VERSION_23:
	case SMB_VERSION_24:
	case SMB_VERSION_25:
	case SMB_VERSION_26:
	case SMB_VERSION_27:
	case SMB_VERSION_28:
	case SMB_VERSION_30:
	case SMB_VERSION_31:
		break;
	default:
		return (smb_open_error(shp, errp, ESMB_VERSION));
	}

	if (ep == NULL || buf == NULL || len == 0 || (flags & ~SMB_O_MASK))
		return (smb_open_error(shp, errp, ESMB_INVAL));

	if (shp == NULL)
		return (smb_open_error(shp, errp, ESMB_NOMEM));

	if (_smb_debug)
		shp->sh_flags |= SMB_FL_DEBUG;

	err = smbios_bufopen_21(shp, &ep->ep21, len, flags);
	if (err != 0) {
		err = smbios_bufopen_30(shp, &ep->ep30, len, flags);
		if (err != 0)
			return (smb_open_error(shp, errp, err));
		shp->sh_ent_stnum =
		    smbios_table_nentries(buf, ep->ep30.smbe_stlen);
	}

	shp->sh_buf = buf;
	shp->sh_buflen = len;
	shp->sh_structs = smb_alloc(sizeof (smb_struct_t) * shp->sh_ent_stnum);
	shp->sh_nstructs = 0;
	shp->sh_hashlen = _smb_hashlen;
	shp->sh_hash = smb_zalloc(sizeof (smb_struct_t *) * shp->sh_hashlen);
	shp->sh_libvers = version;

	if (shp->sh_structs == NULL || shp->sh_hash == NULL)
		return (smb_open_error(shp, errp, ESMB_NOMEM));

	hp = shp->sh_buf;
	switch (shp->sh_ent_type) {
	case SMBIOS_ENTRY_POINT_21:
		q = (const uchar_t *)buf + MIN(ep->ep21.smbe_stlen, len);
		break;
	case SMBIOS_ENTRY_POINT_30:
		q = (const uchar_t *)buf + MIN(ep->ep30.smbe_stlen, len);
		break;
	default:
		return (smb_open_error(shp, errp, ESMB_VERSION));
	}

	for (i = 0; i < shp->sh_ent_stnum; i++, hp = nhp) {
		smb_struct_t *stp = &shp->sh_structs[i];
		uint_t n = 0;

		if ((const uchar_t *)hp + sizeof (smb_header_t) > q) {
			shp->sh_flags |= SMB_FL_TRUNC;
			break;
		}

		smb_dprintf(shp, "struct [%u] type %u len %u hdl %u at %p\n",
		    i, hp->smbh_type, hp->smbh_len, hp->smbh_hdl, (void *)hp);

		if (hp->smbh_type == SMB_TYPE_EOT)
			break; /* ignore any entries beyond end-of-table */

		if ((const uchar_t *)hp + hp->smbh_len > q - 2) {
			shp->sh_flags |= SMB_FL_TRUNC;
			break;
		}

		h = hp->smbh_hdl & (shp->sh_hashlen - 1);
		p = s = (const uchar_t *)hp + hp->smbh_len;

		while (p <= q - 2 && (p[0] != '\0' || p[1] != '\0')) {
			if (*p++ == '\0')
				n++; /* count strings until \0\0 delimiter */
		}

		if (p > q - 2) {
			shp->sh_flags |= SMB_FL_TRUNC;
			break;
		}

		if (p > s)
			n++; /* add one for final string in string table */

		stp->smbst_hdr = hp;
		stp->smbst_str = s;
		stp->smbst_end = p;
		stp->smbst_next = shp->sh_hash[h];
		stp->smbst_strtab = smb_alloc(sizeof (uint16_t) * n);
		stp->smbst_strtablen = n;

		if (n != 0 && stp->smbst_strtab == NULL)
			return (smb_open_error(shp, errp, ESMB_NOMEM));

		shp->sh_hash[h] = stp;
		nhp = (void *)(p + 2);
		shp->sh_nstructs++;

		for (n = 0, p = s; n < stp->smbst_strtablen; p++) {
			if (*p == '\0') {
				stp->smbst_strtab[n++] =
				    (uint16_t)(s - stp->smbst_str);
				s = p + 1;
			}
		}
	}

	/* error out if we couldn't find any complete entries in the table */
	if ((shp->sh_flags & SMB_FL_TRUNC) && i == 0)
		return (smb_open_error(shp, errp, ESMB_CORRUPT));

	if (flags & SMB_O_ZIDS)
		smb_strip(shp);

	return (shp);
}

void
smbios_close(smbios_hdl_t *shp)
{
	uint_t i;

	for (i = 0; i < shp->sh_nstructs; i++) {
		smb_free(shp->sh_structs[i].smbst_strtab,
		    sizeof (uint16_t) * shp->sh_structs[i].smbst_strtablen);
	}

	smb_free(shp->sh_structs, sizeof (smb_struct_t) * shp->sh_ent_stnum);
	smb_free(shp->sh_hash, sizeof (smb_struct_t *) * shp->sh_hashlen);

	if (shp->sh_flags & SMB_FL_BUFALLOC)
		smb_free((void *)shp->sh_buf, shp->sh_buflen);

	smb_free(shp, sizeof (smbios_hdl_t));
}

/*
 * Recompute the values of the entry point checksums based upon the content
 * of the specified SMBIOS entry point.  We don't need 'shp' but require it
 * anyway in case future versioning requires variations in the algorithm.
 */
/*ARGSUSED*/
void
smbios_checksum(smbios_hdl_t *shp, smbios_entry_t *ep)
{
	uchar_t *p, *q = (uchar_t *)ep;
	uint8_t esum = 0, isum = 0;

	switch (shp->sh_ent_type) {
	case SMBIOS_ENTRY_POINT_21:
		ep->ep21.smbe_ecksum = ep->ep21.smbe_icksum = 0;

		for (p = (uchar_t *)ep->ep21.smbe_ianchor;
		    p < q + sizeof (*ep); p++) {
			isum += *p;
		}

		ep->ep21.smbe_icksum = -isum;

		for (p = q; p < q + ep->ep21.smbe_elen; p++)
			esum += *p;

		ep->ep21.smbe_ecksum = -esum;
		break;
	case SMBIOS_ENTRY_POINT_30:
		ep->ep30.smbe_ecksum = 0;
		for (p = q; p < q + ep->ep30.smbe_elen; p++)
			esum += *p;

		ep->ep30.smbe_ecksum = -esum;
		break;
	default:
		break;
	}
}

const void *
smbios_buf(smbios_hdl_t *shp)
{
	return (shp->sh_buf);
}

size_t
smbios_buflen(smbios_hdl_t *shp)
{
	return (shp->sh_buflen);
}

static smbios_struct_t *
smb_export(const smb_struct_t *stp, smbios_struct_t *sp)
{
	const smb_header_t *hdr = stp->smbst_hdr;

	sp->smbstr_id = hdr->smbh_hdl;
	sp->smbstr_type = hdr->smbh_type;
	sp->smbstr_data = hdr;
	sp->smbstr_size = (size_t)(stp->smbst_end - (uchar_t *)hdr);

	return (sp);
}

int
smbios_lookup_id(smbios_hdl_t *shp, id_t id, smbios_struct_t *sp)
{
	const smb_struct_t *stp = smb_lookup_id(shp, id);

	if (stp == NULL)
		return (-1); /* errno is set for us */

	if (sp != NULL)
		(void) smb_export(stp, sp);

	return (0);
}

int
smbios_lookup_type(smbios_hdl_t *shp, uint_t type, smbios_struct_t *sp)
{
	const smb_struct_t *stp = smb_lookup_type(shp, type);

	if (stp == NULL)
		return (-1); /* errno is set for us */

	if (sp != NULL)
		(void) smb_export(stp, sp);

	return (0);
}

int
smbios_iter(smbios_hdl_t *shp, smbios_struct_f *func, void *data)
{
	const smb_struct_t *sp = shp->sh_structs;
	smbios_struct_t s;
	int i, rv = 0;

	for (i = 0; i < shp->sh_nstructs; i++, sp++) {
		if (sp->smbst_hdr->smbh_type != SMB_TYPE_INACTIVE &&
		    (rv = func(shp, smb_export(sp, &s), data)) != 0)
			break;
	}

	return (rv);
}

const smb_struct_t *
smb_lookup_type(smbios_hdl_t *shp, uint_t type)
{
	uint_t i;

	for (i = 0; i < shp->sh_nstructs; i++) {
		if (shp->sh_structs[i].smbst_hdr->smbh_type == type)
			return (&shp->sh_structs[i]);
	}

	(void) smb_set_errno(shp, ESMB_NOENT);
	return (NULL);
}

const smb_struct_t *
smb_lookup_id(smbios_hdl_t *shp, uint_t id)
{
	const smb_struct_t *stp = shp->sh_hash[id & (shp->sh_hashlen - 1)];

	switch (id) {
	case SMB_ID_NOTSUP:
		(void) smb_set_errno(shp, ESMB_NOTSUP);
		return (NULL);
	case SMB_ID_NONE:
		(void) smb_set_errno(shp, ESMB_NOENT);
		return (NULL);
	}

	for (; stp != NULL; stp = stp->smbst_next) {
		if (stp->smbst_hdr->smbh_hdl == id)
			break;
	}

	if (stp == NULL)
		(void) smb_set_errno(shp, ESMB_NOENT);

	return (stp);
}

const char *
smb_strptr(const smb_struct_t *stp, uint_t i)
{
	if (i == 0 || i > stp->smbst_strtablen)
		return (_smb_emptystr);
	else
		return ((char *)stp->smbst_str + stp->smbst_strtab[i - 1]);
}

int
smb_libgteq(smbios_hdl_t *shp, int version)
{
	return (SMB_MAJOR(shp->sh_libvers) > SMB_MAJOR(version) || (
	    SMB_MAJOR(shp->sh_libvers) == SMB_MAJOR(version) &&
	    SMB_MINOR(shp->sh_libvers) >= SMB_MINOR(version)));
}

int
smb_gteq(smbios_hdl_t *shp, int version)
{
	return (SMB_MAJOR(shp->sh_smbvers) > SMB_MAJOR(version) || (
	    SMB_MAJOR(shp->sh_smbvers) == SMB_MAJOR(version) &&
	    SMB_MINOR(shp->sh_smbvers) >= SMB_MINOR(version)));
}

boolean_t
smbios_truncated(smbios_hdl_t *shp)
{
	return ((shp->sh_flags & SMB_FL_TRUNC) != 0);
}
