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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Library of support routines for UDFS data structures and conversions.
 */
#include	<stdio.h>
#include	<string.h>
#include	<strings.h>
#include	<sys/time.h>
#include	<sys/mutex.h>
#include	<sys/vnode.h>
#include	<sys/fs/udf_volume.h>
#include	"udfs.h"

char *tagerrs[] = {
	"no error",
	"invalid checksum",	/* TAGERR_CKSUM */
	"unknown tag id",	/* TAGERR_ID */
	"invalid version",	/* TAGERR_VERSION */
	"CRC length too large",	/* TAGERR_TOOBIG */
	"invalid CRC",		/* TAGERR_CRC */
	"location mismatch"	/* TAGERR_LOC */
};

#ifdef sparc
#define	SWAP16(x) (((x) & 0xff) << 8 | ((x) >> 8) & 0xff)
#define	SWAP32(x) (((x) & 0xff) << 24 | ((x) & 0xff00) << 8 | \
	((x) & 0xff0000) >> 8 | ((x) >> 24) & 0xff)
#define	SWAP64(x) (SWAP32((x) >> 32) & 0xffffffff | SWAP32(x) << 32)
#else
#define	SWAP16(x) (x)
#define	SWAP32(x) (x)
#define	SWAP64(x) (x)
#endif

static void ud_swap_ext_ad(struct extent_ad *);
static void ud_swap_tstamp(struct tstamp *);
static void ud_swap_icb_tag(struct icb_tag *);
void ud_swap_short_ad(struct short_ad *);
void ud_swap_long_ad(struct long_ad *);
static void ud_swap_pri_vol_desc(struct pri_vol_desc *);
static void ud_swap_vdp(struct vol_desc_ptr *);
static void ud_swap_iuvd(struct iuvd_desc *);
static void ud_swap_avdp(struct anch_vol_desc_ptr *);
static void ud_swap_part_desc(struct part_desc *);
static void ud_swap_log_desc(struct log_vol_desc *);
static void ud_swap_unall_desc(struct unall_spc_desc *);
static void ud_swap_lvint(struct log_vol_int_desc *);
static void ud_swap_fileset_desc(struct file_set_desc *);
static void ud_swap_term_desc(struct term_desc *);
static void ud_swap_file_id(struct file_id *);
static void ud_swap_file_entry(struct file_entry *, int);
static void ud_swap_alloc_ext(struct alloc_ext_desc *);
static void ud_swap_tstamp(tstamp_t *);
static void ud_swap_space_bitmap(struct space_bmap_desc *);
static uint16_t crc16(uint8_t *, int32_t, int32_t);

extern uint32_t ecma_version;

void
maketag(struct tag *itp, struct tag *otp)
{
	int32_t sum, i;
	uint8_t *cp;

	if (itp != otp) {
		bcopy((unsigned char *)(itp + 1), (unsigned char *)(otp + 1),
			itp->tag_crc_len);
	}

	/* Swap fields */
	switch (itp->tag_id) {
		case UD_PRI_VOL_DESC:
			ud_swap_pri_vol_desc((struct pri_vol_desc *)otp);
			break;
		case UD_ANCH_VOL_DESC:
			ud_swap_avdp((struct anch_vol_desc_ptr *)otp);
			break;
		case UD_VOL_DESC_PTR:
			ud_swap_vdp((struct vol_desc_ptr *)otp);
			break;
		case UD_IMPL_USE_DESC:
			ud_swap_iuvd((struct iuvd_desc *)otp);
			break;
		case UD_PART_DESC:
			ud_swap_part_desc((struct part_desc *)otp);
			break;
		case UD_LOG_VOL_DESC:
			ud_swap_log_desc((struct log_vol_desc *)otp);
			break;
		case UD_UNALL_SPA_DESC:
			ud_swap_unall_desc((struct unall_spc_desc *)otp);
			break;
		case UD_TERM_DESC:
			ud_swap_term_desc((struct term_desc *)otp);
			break;
		case UD_LOG_VOL_INT:
			/* LINTED */
			ud_swap_lvint((struct log_vol_int_desc *)otp);
			break;
		case UD_FILE_SET_DESC:
			ud_swap_fileset_desc((struct file_set_desc *)otp);
			break;
		case UD_FILE_ID_DESC:
			ud_swap_file_id((struct file_id *)otp);
			break;
		case UD_ALLOC_EXT_DESC:
			break;
		case UD_INDIRECT_ENT:
			break;
		case UD_TERMINAL_ENT:
			break;
		case UD_FILE_ENTRY:
			/* LINTED */
			ud_swap_file_entry((struct file_entry *)otp, 0);
			break;
		case UD_EXT_ATTR_HDR:
			break;
		case UD_UNALL_SPA_ENT:
			break;
		case UD_SPA_BMAP_DESC:
			ud_swap_space_bitmap((struct space_bmap_desc *)otp);
			break;
		case UD_PART_INT_DESC:
			break;
	}
	otp->tag_id = SWAP16(itp->tag_id);
	otp->tag_desc_ver = SWAP16(itp->tag_desc_ver);
	otp->tag_cksum = otp->tag_res = 0;
	otp->tag_sno = SWAP16(itp->tag_sno);
	otp->tag_crc = SWAP16(crc16((unsigned char *)(otp+1),
		itp->tag_crc_len, 0));
	otp->tag_crc_len = SWAP16(itp->tag_crc_len);
	otp->tag_loc = SWAP32(itp->tag_loc);

	/*
	 * Now do checksum on tag itself
	 */
	cp = (unsigned char *)otp;
	sum = 0;
	for (i = 0; i < sizeof (*otp); i++)
		sum += *cp++;
	otp->tag_cksum = sum;
}


int32_t
verifytag(struct tag *tp, uint32_t loc, struct tag *otp, int expect)
{
	uint8_t *cp;
	uint32_t id, vers, length, tloc;
	int sum, i;

	sum = -tp->tag_cksum;
	cp = (unsigned char *)tp;
	for (i = 0; i < sizeof (*tp); i++)
		sum += *cp++;
	if ((sum & 0xff) != tp->tag_cksum)
		return (TAGERR_CKSUM);
	id = SWAP16(tp->tag_id);
	if (id > 9 && id < 256 || id > 266 || (expect > 0 && id != expect))
		return (TAGERR_ID);
	vers = SWAP16(tp->tag_desc_ver);
	if (vers > ecma_version)
		return (TAGERR_VERSION);
	length = SWAP16(tp->tag_crc_len);
	if (length > MAXBSIZE)
		return (TAGERR_TOOBIG);
	if (crc16((unsigned char *)(tp+1), length, SWAP16(tp->tag_crc)) != 0)
		return (TAGERR_CRC);
	tloc = SWAP32(tp->tag_loc);
	if ((int)loc != -1 && tloc != loc)
		return (TAGERR_LOC);
	if (!otp)
		return (0);
	otp->tag_id = id;
	otp->tag_desc_ver = vers;
	otp->tag_cksum = tp->tag_cksum;
	otp->tag_res = 0;
	otp->tag_sno = SWAP16(tp->tag_sno);
	otp->tag_crc = SWAP16(tp->tag_crc);
	otp->tag_crc_len = length;
	otp->tag_loc = tloc;

	if (tp != otp)
		bcopy((unsigned char *)(tp + 1), (unsigned char *)(otp + 1),
			otp->tag_crc_len);
	/* Swap fields */
	switch (otp->tag_id) {
	case UD_PRI_VOL_DESC:
		ud_swap_pri_vol_desc((struct pri_vol_desc *)otp);
		break;
	case UD_ANCH_VOL_DESC:
		ud_swap_avdp((struct anch_vol_desc_ptr *)otp);
		break;
	case UD_VOL_DESC_PTR:
		ud_swap_vdp((struct vol_desc_ptr *)otp);
		break;
	case UD_IMPL_USE_DESC:
		ud_swap_iuvd((struct iuvd_desc *)otp);
		break;
	case UD_PART_DESC:
		ud_swap_part_desc((struct part_desc *)otp);
		break;
	case UD_LOG_VOL_DESC:
		ud_swap_log_desc((struct log_vol_desc *)otp);
		break;
	case UD_UNALL_SPA_DESC:
		ud_swap_unall_desc((struct unall_spc_desc *)otp);
		break;
	case UD_TERM_DESC:
		ud_swap_term_desc((struct term_desc *)otp);
		break;
	case UD_LOG_VOL_INT:
		/* LINTED */
		ud_swap_lvint((struct log_vol_int_desc *)otp);
		break;
	case UD_FILE_SET_DESC:
		ud_swap_fileset_desc((struct file_set_desc *)otp);
		break;
	case UD_FILE_ID_DESC:
		ud_swap_file_id((struct file_id *)otp);
		break;
	case UD_ALLOC_EXT_DESC:
		ud_swap_alloc_ext((struct alloc_ext_desc *)otp);
		break;
	case UD_INDIRECT_ENT:
		break;
	case UD_TERMINAL_ENT:
		break;
	case UD_FILE_ENTRY:
		/* LINTED */
		ud_swap_file_entry((struct file_entry *)otp, 1);
		break;
	case UD_EXT_ATTR_HDR:
		break;
	case UD_UNALL_SPA_ENT:
		break;
	case UD_SPA_BMAP_DESC:
		ud_swap_space_bitmap((struct space_bmap_desc *)otp);
		break;
	case UD_PART_INT_DESC:
		break;
	}
	return (0);
}

static void
ud_swap_ext_ad(struct extent_ad *p)
{
	p->ext_len = SWAP32(p->ext_len);
	p->ext_loc = SWAP32(p->ext_loc);
}


/* ARGSUSED */
static void
ud_swap_regid(struct regid *p)
{
}

static void
ud_swap_icb_tag(struct icb_tag *p)
{
	p->itag_prnde = SWAP32(p->itag_prnde);
	p->itag_strategy = SWAP16(p->itag_strategy);
	p->itag_param = SWAP16(p->itag_param);
	p->itag_max_ent = SWAP16(p->itag_max_ent);
	p->itag_lb_loc = SWAP32(p->itag_lb_loc);
	p->itag_lb_prn = SWAP16(p->itag_lb_prn);
	p->itag_flags = SWAP16(p->itag_flags);
}

void
ud_swap_short_ad(struct short_ad *p)
{
	p->sad_ext_len = SWAP32(p->sad_ext_len);
	p->sad_ext_loc = SWAP32(p->sad_ext_loc);
}

void
ud_swap_long_ad(struct long_ad *p)
{
	p->lad_ext_len = SWAP32(p->lad_ext_len);
	p->lad_ext_loc = SWAP32(p->lad_ext_loc);
	p->lad_ext_prn = SWAP16(p->lad_ext_prn);
}

static void
ud_swap_pri_vol_desc(struct pri_vol_desc *p)
{
	p->pvd_vdsn = SWAP32(p->pvd_vdsn);
	p->pvd_pvdn = SWAP32(p->pvd_pvdn);
	p->pvd_vsn = SWAP16(p->pvd_vsn);
	p->pvd_mvsn = SWAP16(p->pvd_mvsn);
	p->pvd_il = SWAP16(p->pvd_il);
	p->pvd_mil = SWAP16(p->pvd_mil);
	p->pvd_csl = SWAP32(p->pvd_csl);
	p->pvd_mcsl = SWAP32(p->pvd_mcsl);
	ud_swap_ext_ad(&p->pvd_vol_abs);
	ud_swap_ext_ad(&p->pvd_vcn);
	ud_swap_regid(&p->pvd_appl_id);
	ud_swap_tstamp(&p->pvd_time);
	ud_swap_regid(&p->pvd_ii);
	p->pvd_pvdsl = SWAP32(p->pvd_pvdsl);
	p->pvd_flags = SWAP16(p->pvd_flags);
}

static void
ud_swap_iuvd(struct iuvd_desc *p)
{
	p->iuvd_vdsn = SWAP32(p->iuvd_vdsn);
	ud_swap_regid(&p->iuvd_ii);
	ud_swap_regid(&p->iuvd_iid);
}

static void
ud_swap_vdp(struct vol_desc_ptr *p)
{
	p->vdp_vdsn = SWAP32(p->vdp_vdsn);
	ud_swap_ext_ad(&p->vdp_nvdse);
}

static void
ud_swap_avdp(struct anch_vol_desc_ptr *p)
{
	ud_swap_ext_ad(&p->avd_main_vdse);
	ud_swap_ext_ad(&p->avd_res_vdse);
}

static void
ud_swap_part_desc(struct part_desc *p)
{
	struct phdr_desc *php;

	p->pd_vdsn = SWAP32(p->pd_vdsn);
	p->pd_pflags = SWAP16(p->pd_pflags);
	p->pd_pnum = SWAP16(p->pd_pnum);
	ud_swap_regid(&p->pd_pcontents);
	p->pd_acc_type = SWAP32(p->pd_acc_type);
	p->pd_part_start = SWAP32(p->pd_part_start);
	p->pd_part_length = SWAP32(p->pd_part_length);
	ud_swap_regid(&p->pd_ii);
	if (strncmp(p->pd_pcontents.reg_id, "+NSR", 4) == 0) {
		/* LINTED */
		php = (struct phdr_desc *)p->pd_pc_use;
		ud_swap_short_ad(&php->phdr_ust);
		ud_swap_short_ad(&php->phdr_usb);
		ud_swap_short_ad(&php->phdr_it);
		ud_swap_short_ad(&php->phdr_fst);
		ud_swap_short_ad(&php->phdr_fsb);
	}
}

static void
ud_swap_log_desc(struct log_vol_desc *p)
{
	p->lvd_vdsn = SWAP32(p->lvd_vdsn);
	p->lvd_log_bsize = SWAP32(p->lvd_log_bsize);
	ud_swap_regid(&p->lvd_dom_id);
	ud_swap_long_ad(&p->lvd_lvcu);
	p->lvd_mtbl_len = SWAP32(p->lvd_mtbl_len);
	p->lvd_num_pmaps = SWAP32(p->lvd_num_pmaps);
	ud_swap_regid(&p->lvd_ii);
	ud_swap_ext_ad(&p->lvd_int_seq_ext);
}

static void
ud_swap_unall_desc(struct unall_spc_desc *p)
{
	p->ua_vdsn = SWAP32(p->ua_vdsn);
	p->ua_nad = SWAP32(p->ua_nad);
}

static void
ud_swap_lvint(struct log_vol_int_desc *p)
{
	struct lvid_iu *lvup;

	ud_swap_tstamp(&p->lvid_tstamp);
	p->lvid_int_type = SWAP32(p->lvid_int_type);
	ud_swap_ext_ad(&p->lvid_nie);
	p->lvid_npart = SWAP32(p->lvid_npart);
	p->lvid_liu = SWAP32(p->lvid_liu);
	p->lvid_uniqid = SWAP64(p->lvid_uniqid);
	p->lvid_fst[0] = SWAP32(p->lvid_fst[0]);
	p->lvid_fst[1] = SWAP32(p->lvid_fst[1]);

	lvup = (struct lvid_iu *)&p->lvid_fst[2];
	ud_swap_regid(&lvup->lvidiu_regid);
	lvup->lvidiu_nfiles = SWAP32(lvup->lvidiu_nfiles);
	lvup->lvidiu_ndirs = SWAP32(lvup->lvidiu_ndirs);
	lvup->lvidiu_mread = SWAP16(lvup->lvidiu_mread);
	lvup->lvidiu_mwrite = SWAP16(lvup->lvidiu_mwrite);
	lvup->lvidiu_maxwr = SWAP16(lvup->lvidiu_maxwr);
}

static void
ud_swap_fileset_desc(struct file_set_desc *p)
{
	ud_swap_tstamp(&p->fsd_time);
	p->fsd_ilevel = SWAP16(p->fsd_ilevel);
	p->fsd_mi_level = SWAP16(p->fsd_mi_level);
	p->fsd_cs_list = SWAP32(p->fsd_cs_list);
	p->fsd_mcs_list = SWAP32(p->fsd_mcs_list);
	p->fsd_fs_no = SWAP32(p->fsd_fs_no);
	p->fsd_fsd_no = SWAP32(p->fsd_fsd_no);
	ud_swap_long_ad(&p->fsd_root_icb);
	ud_swap_regid(&p->fsd_did);
	ud_swap_long_ad(&p->fsd_next);
}

/* ARGSUSED */
static void
ud_swap_term_desc(struct term_desc *p)
{
}

static void
ud_swap_file_id(struct file_id *p)
{
	p->fid_ver = SWAP16(p->fid_ver);
	ud_swap_long_ad(&p->fid_icb);
	p->fid_iulen = SWAP16(p->fid_iulen);
}

static void
ud_swap_alloc_ext(struct alloc_ext_desc *p)
{
	p->aed_rev_ael = SWAP32(p->aed_rev_ael);
	p->aed_len_aed = SWAP32(p->aed_len_aed);
}

static void
ud_swap_space_bitmap(struct space_bmap_desc *p)
{
	p->sbd_nbits = SWAP32(p->sbd_nbits);
	p->sbd_nbytes = SWAP32(p->sbd_nbytes);
}

static void
ud_swap_file_entry(struct file_entry *p, int32_t rdflag)
{
	int32_t i;
	short_ad_t *sap;
	long_ad_t *lap;

	/* Do Extended Attributes and Allocation Descriptors */
	if (rdflag) {
		p->fe_len_adesc = SWAP32(p->fe_len_adesc);
		p->fe_len_ear = SWAP32(p->fe_len_ear);
		ud_swap_icb_tag(&p->fe_icb_tag);
	}
	switch (p->fe_icb_tag.itag_flags & 0x3) {
	case ICB_FLAG_SHORT_AD:
		/* LINTED */
		sap = (short_ad_t *)(p->fe_spec + p->fe_len_ear);
		for (i = 0; i < p->fe_len_adesc / sizeof (short_ad_t);
			i++, sap++)
			ud_swap_short_ad(sap);
		break;
	case ICB_FLAG_LONG_AD:
		/* LINTED */
		lap = (long_ad_t *)(p->fe_spec + p->fe_len_ear);
		for (i = 0; i < p->fe_len_adesc / sizeof (long_ad_t);
			i++, lap++)
			ud_swap_long_ad(lap);
		break;
	case ICB_FLAG_EXT_AD:
		break;
	case ICB_FLAG_ONE_AD:
		break;
	}
	p->fe_uid = SWAP32(p->fe_uid);
	p->fe_gid = SWAP32(p->fe_gid);
	p->fe_perms = SWAP32(p->fe_perms);
	p->fe_lcount = SWAP16(p->fe_lcount);
	p->fe_rec_len = SWAP32(p->fe_rec_len);
	p->fe_info_len = SWAP64(p->fe_info_len);
	p->fe_lbr = SWAP64(p->fe_lbr);
	ud_swap_tstamp(&p->fe_acc_time);
	ud_swap_tstamp(&p->fe_mod_time);
	ud_swap_tstamp(&p->fe_attr_time);
	p->fe_ckpoint = SWAP32(p->fe_ckpoint);
	ud_swap_long_ad(&p->fe_ea_icb);
	ud_swap_regid(&p->fe_impl_id);
	p->fe_uniq_id = SWAP64(p->fe_uniq_id);
	if (!rdflag) {
		p->fe_len_adesc = SWAP32(p->fe_len_adesc);
		p->fe_len_ear = SWAP32(p->fe_len_ear);
		ud_swap_icb_tag(&p->fe_icb_tag);
	}
}

static void
ud_swap_tstamp(tstamp_t *tp)
{
	tp->ts_tzone = SWAP16(tp->ts_tzone);
	tp->ts_year = SWAP16(tp->ts_year);
}

void
setcharspec(struct charspec *cp, int32_t type, uint8_t *info)
{
	cp->cs_type = type;
	bzero(cp->cs_info, sizeof (cp->cs_info));
	(void) strncpy(cp->cs_info, (int8_t *)info, sizeof (cp->cs_info));
}

static unsigned short crctab[] = {
	0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
	0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
	0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
	0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
	0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485,
	0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
	0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
	0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
	0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
	0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
	0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12,
	0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
	0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41,
	0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
	0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
	0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
	0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f,
	0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
	0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e,
	0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
	0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
	0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
	0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c,
	0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
	0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab,
	0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
	0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
	0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
	0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9,
	0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
	0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8,
	0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0
};

static uint16_t
crc16(uint8_t *buf, int32_t size, int32_t rem)
{
	uint16_t crc = 0;

	while (size-- > 0)
		crc = (crc << 8) ^ crctab[((crc >> 8) ^ *buf++) & 0xff];
	return ((crc ^ rem) & 0xffff);
}
