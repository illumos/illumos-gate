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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_UD_LIB_H
#define	_UD_LIB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	UD_VOL_REC_START	(32 * 1024)
#define	UD_VOL_REC_BSZ		2048
#define	UD_VOL_REC_END		(256 * UD_VOL_REC_BSZ)

#define	UD_ECMA_VER2		0x00000002
#define	UD_ECMA_VER3		0x00000003
#define	UD_ECMA_UNKN		0xFFFFFFFF

#define	MAX_PARTS	10
#define	MAX_MAPS	10
#define	MAX_SPM		4

#define	lb_roundup(sz, lbsz)	\
	(((sz) + (lbsz - 1)) & (~(lbsz - 1)))

struct vds {
	uint32_t	pvd_loc;
	uint32_t	pvd_len;
	uint32_t	pvd_vdsn;

	uint32_t	iud_loc;
	uint32_t	iud_len;

	uint32_t	part_loc[MAX_PARTS];
	uint32_t	part_len[MAX_PARTS];

	uint32_t	lvd_loc;
	uint32_t	lvd_len;
	uint32_t	lvd_vdsn;

	uint32_t	usd_loc;
	uint32_t	usd_len;
};

/*
 * All addresses are the lbsize block numbers
 * offseted into the partition
 */
struct udf {
	uint32_t	flags;
#define	INVALID_UDFS	0x0000
#define	VALID_UDFS	0x0001
#define	VALID_MVDS	0x0002
#define	VALID_RVDS	0x0004

	uint32_t	ecma_version;
	uint8_t		ecma_id[5];

	uint16_t	mi_read;
	uint16_t	ma_read;
	uint16_t	ma_write;

	uint32_t	lbsize;

	uint32_t	avdp_loc;	/* First Readable avdp */
	uint32_t	avdp_len;

	uint32_t	mvds_loc;
	uint32_t	mvds_len;
	uint32_t	rvds_len;
	uint32_t	rvds_loc;

	struct	vds	mvds;
	struct	vds	rvds;

	/*
	 * location of the latest lvid
	 */
	uint32_t	lvid_loc;
	uint32_t	lvid_len;

	uint16_t	fsds_prn;
	uint32_t	fsds_loc;
	uint32_t	fsds_len;
	/*
	 * Location of the most usable fsd
	 * on WORM we have to follow till the
	 * end of the chain
	 * FSD location is absolute disk location
	 * after translating using maps and partitions
	 */
	uint32_t	fsd_loc;
	uint32_t	fsd_len;

	uint16_t	ricb_prn;
	uint32_t	ricb_loc;
	uint32_t	ricb_len;

	uint32_t	vat_icb_loc;
	uint32_t	vat_icb_len;
};

struct ud_part {
	uint16_t	udp_flags;	/* See below */
#define	UDP_BITMAPS	0x00
#define	UDP_SPACETBLS	0x01

	uint16_t	udp_number;	/* partition Number */
	uint32_t	udp_seqno;	/* to find the prevailaing desc */
	uint32_t	udp_access;	/* access type */
	uint32_t	udp_start;	/* Starting block no of partition */
	uint32_t	udp_length;	/* Lenght of the partition */
	uint32_t	udp_unall_loc;	/* unall space tbl or bitmap loc */
	uint32_t	udp_unall_len;	/* unall space tbl or bitmap length */
	uint32_t	udp_freed_loc;	/* freed space tbl or bitmap loc */
	uint32_t	udp_freed_len;	/* freed space tbl or bitmap length */
					/* From part desc */

	uint32_t	udp_nfree;	/* No of free blocks in the partition */
	uint32_t	udp_nblocks;	/* Total no of blks in the partition */
					/* From lvid */
};


struct ud_map {
	uint16_t	udm_flags;
#define	UDM_MAP_NORM	0x00
#define	UDM_MAP_VPM	0x01
#define	UDM_MAP_SPM	0x02

	uint16_t	udm_vsn;
	uint16_t	udm_pn;

	uint32_t	udm_vat_icb_loc;
	uint32_t	udm_nent;
	uint32_t	*udm_count;
	struct buf	**udm_bp;
	uint32_t	**udm_addr;

	int32_t		udm_plen;
	int32_t		udm_nspm;
	uint32_t	udm_spsz;
	uint32_t	udm_loc[MAX_SPM];
	struct buf	*udm_sbp[MAX_SPM];
	caddr_t		udm_spaddr[MAX_SPM];
};



#define	REG_DOM_ID	0x1
#define	REG_UDF_ID	0x2
#define	REG_UDF_II	0x4

#define	EI_FLG_DIRTY	0x01
#define	EI_FLG_PROT	0x02

struct dom_id_suffix {
	uint16_t	dis_udf_revison;
	uint8_t		dis_domain_flags;
	uint8_t		dis_pad[5];
};

#define	PROTECT_SOFT_WRITE	0x01
#define	PROTECT_HARD_WRITE	0x02

struct udf_id_suffix {
	uint16_t	uis_udf_revision;
	uint8_t		uis_os_class;
	uint8_t		uis_os_identifier;
	uint8_t		uis_pad[4];
};

struct impl_id_suffix {
	uint8_t		iis_os_class;
	uint8_t		iis_os_identifier;
	uint8_t		iis_pad[6];
};

#define	OS_CLASS_UNDEFINED	0x00
#define	OS_CLASS_DOS_WIN3x	0x01
#define	OS_CLASS_OS_2		0x02
#define	OS_CLASS_MAC_OS_7	0x02
#define	OS_CLASS_UNIX		0x04
#define	OS_CLASS_WIN_95		0x05
#define	OS_CLASS_WIN_NT		0x06

#define	OS_IDENTIFIER_GENERIC	0x00
#define	OS_IDENTIFIER_IBM_AIX	0x01
#define	OS_IDENTIFIER_SOLARIS	0x02
#define	OS_IDENTIFIER_HP_UX	0x03
#define	OS_IDENTIFIER_SG_IRIX	0x04
#define	OS_IDENTIFIER_LINUX	0x05
#define	OS_IDENTIFIER_MK_LINUX	0x06
#define	OS_IDENTIFIER_FREE_BSD	0x07

struct ud_handle {
	int		fd;
	struct udf	udfs;
	struct ud_part	part[MAX_PARTS];
	int32_t		n_parts;
	struct ud_map	maps[MAX_MAPS];
	int32_t		n_maps;
};

typedef struct ud_handle *ud_handle_t;


int	ud_init(int, ud_handle_t *);
void	ud_fini(ud_handle_t);
int32_t	ud_open_dev(ud_handle_t, char *, uint32_t);
void	ud_close_dev(ud_handle_t);
int32_t	ud_read_dev(ud_handle_t, uint64_t, uint8_t *, uint32_t);
int32_t	ud_write_dev(ud_handle_t, uint64_t, uint8_t *, uint32_t);

int32_t	ud_fill_udfs_info(ud_handle_t);
int32_t ud_get_num_blks(ud_handle_t, uint32_t *);

int32_t ud_verify_tag(ud_handle_t, struct tag *,
	uint16_t, uint32_t, int32_t, int32_t);
void	ud_make_tag(ud_handle_t, struct tag *, uint16_t, uint32_t, uint16_t);
uint32_t ud_xlate_to_daddr(ud_handle_t, uint16_t, uint32_t);
void	ud_convert2local(int8_t *, int8_t *, int32_t);

void	print_charspec(FILE *, char *, struct charspec *);
void	print_dstring(FILE *, char *, uint16_t, char *, uint8_t);
void	set_dstring(dstring_t *, char *, int32_t);
void	print_tstamp(FILE *, char *, tstamp_t *);
void	print_regid(FILE *, char *, struct regid *, int32_t);

void	print_ext_ad(FILE *, char *, struct extent_ad *);
void	print_tag(FILE *, struct tag *);
void	print_pvd(FILE *, struct pri_vol_desc *);
void	print_avd(FILE *, struct anch_vol_desc_ptr *);
void	print_vdp(FILE *, struct vol_desc_ptr *);
void	print_iuvd(FILE *, struct iuvd_desc *);
void	print_part(FILE *, struct part_desc *);
void	print_lvd(FILE *, struct log_vol_desc *);
void	print_usd(FILE *, struct unall_spc_desc *);
void	print_lvid(FILE *, struct log_vol_int_desc *);
void	print_part(FILE *, struct part_desc *);

void	print_fsd(FILE *, ud_handle_t h, struct file_set_desc *);
void	print_phdr(FILE *, struct phdr_desc *);
void	print_fid(FILE *, struct file_id *);
void	print_aed(FILE *, struct alloc_ext_desc *);
void	print_icb_tag(FILE *, struct icb_tag *);
void	print_ie(FILE *, struct indirect_entry *);
void	print_td(FILE *, struct term_desc *);
void	print_fe(FILE *, struct file_entry *);
void	print_pmaps(FILE *, uint8_t *, int32_t);
void	print_short_ad(FILE *, char *, struct short_ad *);
void	print_long_ad(FILE *, char *, struct long_ad *);

#ifdef	__cplusplus
}
#endif

#endif	/* _UD_LIB_H */
