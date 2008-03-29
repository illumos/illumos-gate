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

#include <scsi/libses.h>
#include "ses_impl.h"

int
enc_parse_td(ses2_td_hdr_impl_t *tip, const char *tp, nvlist_t *nvl)
{
	int nverr;

	if (tp != NULL)
		SES_NV_ADD(fixed_string, nverr, nvl, SES_PROP_CLASS_DESCRIPTION,
		    tp, tip->sthi_text_len);

	return (0);
}

static int
enc_eid(const ses2_ed_impl_t *tp, nvlist_t *nvl, const char *name)
{
	int nverr;

	SES_NV_ADD(uint64, nverr, nvl, name, tp->st_hdr.sehi_subenclosure_id);

	return (0);
}

static int
enc_espid(const ses2_ed_impl_t *tp, nvlist_t *nvl, const char *name)
{
	int nverr;

	SES_NV_ADD(uint64, nverr, nvl, name, tp->st_hdr.sehi_rel_esp_id);

	return (0);
}

static int
enc_nesp(const ses2_ed_impl_t *tp, nvlist_t *nvl, const char *name)
{
	int nverr;

	SES_NV_ADD(uint64, nverr, nvl, name, tp->st_hdr.sehi_n_esps);

	return (0);
}

static int
enc_lid(const ses2_ed_impl_t *tp, nvlist_t *nvl, const char *name)
{
	nvlist_t *lid;
	int nverr;

	if ((nverr = nvlist_alloc(&lid, NV_UNIQUE_NAME, 0)) != 0)
		return (ses_set_nverrno(nverr, NULL));

	SES_NV_ADD_OR_FREE(uint64, nverr, lid, SPC3_NAA_INT,
	    SCSI_READ64(&tp->st_logical_id));

	switch (tp->st_logical_id.sni8i_naa) {
	case NAA_IEEE_EXT:
		SES_NV_ADD_OR_FREE(uint64, nverr, lid, SPC3_NAA_ID_TYPE,
		    NAA_IEEE_EXT);
		SES_NV_ADD_OR_FREE(uint64, nverr, lid, SPC3_NAA_COMPANY_ID,
		    NAA_IEEE_EXT_COMPANY_ID(&tp->st_logical_id.sni8i_ext_id));
		SES_NV_ADD_OR_FREE(uint64, nverr, lid, SPC3_NAA_VS_A,
		    NAA_IEEE_EXT_VENDOR_A(&tp->st_logical_id.sni8i_ext_id));
		SES_NV_ADD_OR_FREE(uint64, nverr, lid, SPC3_NAA_VS_B,
		    NAA_IEEE_EXT_VENDOR_B(&tp->st_logical_id.sni8i_ext_id));
		break;
	case NAA_IEEE_REG:
		SES_NV_ADD_OR_FREE(uint64, nverr, lid, SPC3_NAA_ID_TYPE,
		    NAA_IEEE_REG);
		SES_NV_ADD_OR_FREE(uint64, nverr, lid, SPC3_NAA_COMPANY_ID,
		    NAA_IEEE_REG_COMPANY_ID(&tp->st_logical_id.sni8i_reg_id));
		SES_NV_ADD_OR_FREE(uint64, nverr, lid, SPC3_NAA_VS_A,
		    NAA_IEEE_REG_VENDOR_ID(&tp->st_logical_id.sni8i_reg_id));
		break;
	default:
		break;
	}

	if ((nverr = nvlist_add_nvlist(nvl, name, lid)) != 0) {
		nvlist_free(lid);
		return (ses_set_nverrno(nverr, name));
	}

	nvlist_free(lid);

	return (0);
}

static int
enc_vid(const ses2_ed_impl_t *tp, nvlist_t *nvl,
    const char *name)
{
	int nverr;

	SES_NV_ADD_FS_TRUNC(nverr, nvl, name, tp->st_vendor_id);

	return (0);
}

static int
enc_pid(const ses2_ed_impl_t *tp, nvlist_t *nvl,
    const char *name)
{
	int nverr;

	SES_NV_ADD_FS_TRUNC(nverr, nvl, name, tp->st_product_id);

	return (0);
}

static int
enc_rev(const ses2_ed_impl_t *tp, nvlist_t *nvl,
    const char *name)
{
	int nverr;

	SES_NV_ADD_FS_TRUNC(nverr, nvl, name, tp->st_product_revision);

	return (0);
}

static int
enc_vs(const ses2_ed_impl_t *tp, nvlist_t *nvl, const char *name)
{
	int nverr;

	SES_NV_ADD(byte_array, nverr, nvl, name, (uchar_t *)tp->st_priv,
	    tp->st_hdr.sehi_ed_len - offsetof(ses2_ed_impl_t, st_priv[0]));

	return (0);
}

/* LINTED - unused */
static const ses2_ed_impl_t __ed = { 0 };

#define	ED_REQ_LEN(member)	\
	(offsetof(ses2_ed_impl_t, member) - sizeof (ses2_ed_hdr_impl_t) + \
	    sizeof (__ed.member))

static const struct config_member {
	const char *name;
	size_t minsz;
	int (*func)(const ses2_ed_impl_t *, nvlist_t *, const char *);
} config_members[] = {
	{ SES_EN_PROP_EID, 0, enc_eid },
	{ SES_EN_PROP_ESPID, 0, enc_espid },
	{ SES_EN_PROP_NESP, 0, enc_nesp },
	{ SES_EN_PROP_LID, ED_REQ_LEN(st_logical_id), enc_lid },
	{ SES_EN_PROP_VID, ED_REQ_LEN(st_vendor_id), enc_vid },
	{ SES_EN_PROP_PID, ED_REQ_LEN(st_product_id), enc_pid },
	{ SES_EN_PROP_REV, ED_REQ_LEN(st_product_revision), enc_rev },
	{ SES_EN_PROP_VS, ED_REQ_LEN(st_priv), enc_vs },
	{ NULL, 0, NULL }
};

int
enc_parse_ed(ses2_ed_impl_t *tp, nvlist_t *nvl)
{
	const struct config_member *mp;
	int err;

	if (tp == NULL)
		return (0);

	for (mp = &config_members[0]; mp->name != NULL; mp++) {
		if (mp->func != NULL && tp->st_hdr.sehi_ed_len >= mp->minsz) {
			err = mp->func(tp, nvl, mp->name);
			if (err != 0)
				return (err);
		}
	}

	return (0);
}

ses_target_t *
ses_open_scsi(uint_t version, libscsi_target_t *stp)
{
	ses_target_t *tp;
	ses_snap_t *sp;

	if (version != LIBSES_VERSION) {
		(void) ses_set_errno(ESES_VERSION);
		return (NULL);
	}

	if ((tp = ses_zalloc(sizeof (ses_target_t))) == NULL)
		return (NULL);

	tp->st_target = stp;
	tp->st_scsi_hdl = libscsi_get_handle(stp);
	tp->st_truncate = (getenv("LIBSES_TRUNCATE") != NULL);
	if (tp->st_truncate)
		srand48(gethrtime());

	(void) pthread_mutex_init(&tp->st_lock, NULL);

	if (ses_plugin_load(tp) != 0) {
		ses_close(tp);
		return (NULL);
	}

	if ((sp = ses_snap_new(tp)) == NULL) {
		ses_close(tp);
		return (NULL);
	}

	ses_snap_rele(sp);

	return (tp);
}

ses_target_t *
ses_open(uint_t version, const char *target)
{
	ses_target_t *tp;
	libscsi_errno_t serr;
	libscsi_target_t *stp;
	libscsi_hdl_t *hp;

	if ((hp = libscsi_init(LIBSCSI_VERSION, &serr)) == NULL) {
		(void) ses_error(ESES_LIBSCSI, "failed to initialize "
		    "libscsi: %s", libscsi_strerror(serr));
		return (NULL);
	}

	if ((stp = libscsi_open(hp, NULL, target)) == NULL) {
		(void) ses_libscsi_error(hp, "failed to open SES target");
		libscsi_fini(hp);
		return (NULL);
	}

	if ((tp = ses_open_scsi(version, stp)) == NULL) {
		libscsi_close(hp, stp);
		libscsi_fini(hp);
		return (NULL);
	}

	tp->st_closescsi = B_TRUE;

	return (tp);
}

libscsi_target_t *
ses_scsi_target(ses_target_t *tp)
{
	return (tp->st_target);
}

void
ses_close(ses_target_t *tp)
{
	if (tp->st_snapshots != NULL)
		ses_snap_rele(tp->st_snapshots);
	if (tp->st_snapshots != NULL)
		ses_panic("attempt to close SES target with active snapshots");
	ses_plugin_unload(tp);
	if (tp->st_closescsi) {
		libscsi_close(tp->st_scsi_hdl, tp->st_target);
		libscsi_fini(tp->st_scsi_hdl);
	}
	ses_free(tp);
}
