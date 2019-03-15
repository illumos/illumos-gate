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

#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <unistd.h>
#include <strings.h>
#include <errno.h>
#include <libintl.h>
#include <libgen.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/int_types.h>
#include <sys/dkio.h>
#include <sys/cdio.h>
#include <sys/vtoc.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/fs/udf_volume.h>
#include "ud_lib.h"

extern char *getfullrawname(char *);

static int32_t ud_get_ecma_ver(ud_handle_t, uint32_t);
static int32_t ud_get_fs_bsize(ud_handle_t, uint32_t, uint32_t *);
static int32_t ud_parse_fill_vds(ud_handle_t, struct vds *, uint32_t, uint32_t);
static int32_t	ud_read_and_translate_lvd(ud_handle_t, uint32_t, uint32_t);
static int32_t ud_get_latest_lvid(ud_handle_t, uint32_t, uint32_t);
static int32_t	ud_get_latest_fsd(ud_handle_t, uint16_t, uint32_t, uint32_t);

static uint16_t ud_crc(uint8_t *, int32_t);
static int32_t UdfTxName(uint16_t *, int32_t);
static int32_t UncompressUnicode(int32_t, uint8_t *, uint16_t *);
static int32_t ud_compressunicode(int32_t, int32_t, uint16_t *, uint8_t *);
static int32_t ud_convert2utf8(uint8_t *, uint8_t *, int32_t);
static int32_t ud_convert2utf16(uint8_t *, uint8_t *, int32_t);


int
ud_init(int fd, ud_handle_t *hp)
{
	struct ud_handle *h;

	if ((h = calloc(1, sizeof (struct ud_handle))) == NULL) {
		return (ENOMEM);
	}
	h->fd = fd;
	*hp = h;
	return (0);
}

void
ud_fini(ud_handle_t h)
{
	free(h);
}

/* ARGSUSED */
int32_t
ud_open_dev(ud_handle_t h, char *special, uint32_t flags)
{
	char *temp;
	struct stat i_stat, r_stat;

	(void) bzero(&i_stat, sizeof (struct stat));
	(void) bzero(&r_stat, sizeof (struct stat));

	/*
	 * Get the stat structure
	 */
	if (stat(special, &i_stat) < 0) {
		temp = special;
	} else {

		if ((i_stat.st_mode & S_IFMT) == S_IFCHR) {

			/*
			 * If Raw deivce is given use it as it is
			 */

			temp = special;
		} else if ((i_stat.st_mode & S_IFMT) == S_IFBLK) {

			/*
			 * Block device try to convert to raw device
			 */

			temp = getfullrawname(special);

			/*
			 * Stat the converted device name and verify
			 * both the raw and block device belong to
			 * the same device
			 */
			if (stat(temp, &r_stat) < 0) {
				temp = special;
			} else {
				if (((r_stat.st_mode & S_IFMT) == S_IFBLK) ||
					(r_stat.st_rdev != i_stat.st_rdev)) {
					temp = special;
				}
			}
		}
	}

	/*
	 * Now finally open the device
	 */
	h->fd = open(temp, flags);

	return (h->fd);
}

/* ARGSUSED */
void
ud_close_dev(ud_handle_t h)
{
	/*
	 * Too simple Just close it
	 */
	(void) close(h->fd);
}

int32_t
ud_read_dev(ud_handle_t h, uint64_t offset, uint8_t *buf, uint32_t count)
{
	/*
	 * Seek to the given offset
	 */
	if (lseek(h->fd, offset, SEEK_SET) == -1) {
		return (1);
	}

	/*
	 * Read the required number of bytes
	 */
	if (read(h->fd, buf, count) != count) {
		return (1);
	}
	return (0);
}

int32_t
ud_write_dev(ud_handle_t h, uint64_t offset, uint8_t *buf, uint32_t count)
{
	/*
	 * Seek to the given offset
	 */
	if (lseek(h->fd, offset, SEEK_SET) == -1) {
		return (1);
	}

	/*
	 * Read the appropriate number of bytes
	 */
	if (write(h->fd, buf, count) != count) {
		return (1);
	}
	return (0);
}

/* ----- BEGIN Read and translate the on disk VDS to IN CORE format -------- */

int32_t
ud_fill_udfs_info(ud_handle_t h)
{
	struct	anch_vol_desc_ptr	*avdp = NULL;
	uint32_t			offset = 0;

	if (ioctl(h->fd, CDROMREADOFFSET, &offset) == -1) {
		offset = 0;
	}

	h->udfs.flags = INVALID_UDFS;

	h->udfs.ecma_version = ud_get_ecma_ver(h, offset);
	if (h->udfs.ecma_version == UD_ECMA_UNKN) {
		return (1);
	}

	h->udfs.lbsize = ud_get_fs_bsize(h, offset, &h->udfs.avdp_loc);
	if (h->udfs.lbsize == 0) {
		return (2);
	}

	h->udfs.avdp_len = lb_roundup(512, h->udfs.lbsize);


	if ((avdp = (struct anch_vol_desc_ptr *)
			malloc(h->udfs.lbsize)) == NULL) {
		return (3);
	}
	if (ud_read_dev(h, h->udfs.avdp_loc * h->udfs.lbsize,
			(uint8_t *)avdp, h->udfs.lbsize) != 0) {
		free(avdp);
		return (4);
	}
	if (ud_verify_tag(h, &avdp->avd_tag, UD_ANCH_VOL_DESC,
			h->udfs.avdp_loc, 1, 0) != 0) {
		free(avdp);
		return (5);
	}

	h->udfs.mvds_loc = SWAP_32(avdp->avd_main_vdse.ext_loc);
	h->udfs.mvds_len = SWAP_32(avdp->avd_main_vdse.ext_len);

	h->udfs.rvds_loc = SWAP_32(avdp->avd_res_vdse.ext_loc);
	h->udfs.rvds_len = SWAP_32(avdp->avd_res_vdse.ext_len);

	free(avdp);

	/*
	 * get information from mvds and rvds
	 */
	if (ud_parse_fill_vds(h, &h->udfs.mvds,
			h->udfs.mvds_loc, h->udfs.mvds_len) == 0) {
		h->udfs.flags |= VALID_MVDS;
	}
	if (ud_parse_fill_vds(h, &h->udfs.rvds,
			h->udfs.rvds_loc, h->udfs.rvds_len) == 0) {
		h->udfs.flags |= VALID_RVDS;
	}

	if ((h->udfs.flags & (VALID_MVDS | VALID_RVDS)) == 0) {
		return (6);
	}

	/*
	 * If we are here we have
	 * a valid Volume Descriptor Seqence
	 * Read and understand lvd
	 */
	if (h->udfs.flags & VALID_MVDS) {
		if (ud_read_and_translate_lvd(h, h->udfs.mvds.lvd_loc,
				h->udfs.mvds.lvd_len) != 0) {
			return (7);
		}
	} else {
		if (ud_read_and_translate_lvd(h, h->udfs.rvds.lvd_loc,
				h->udfs.rvds.lvd_len) != 0) {
			return (8);
		}
	}

	h->udfs.flags |= VALID_UDFS;

	return (0);
}

static int32_t
ud_get_ecma_ver(ud_handle_t h, uint32_t offset)
{
	uint8_t *buf;
	uint64_t off;
	uint64_t end_off;
	struct nsr_desc *ndsc;
	uint32_t ecma_ver = UD_ECMA_UNKN;

	/*
	 * Allocate a buffer of size UD_VOL_REC_BSZ
	 */
	if ((buf = (uint8_t *)malloc(UD_VOL_REC_BSZ)) == NULL) {

		/*
		 * Uh could not even allocate this much
		 */
		goto end;
	}

	/*
	 * Start from 32k and keep reading 2k blocks we
	 * should be able to find NSR if we have one by 256 * 2k bytes
	 */
	off = offset * 2048 + UD_VOL_REC_START;
	end_off = offset * 2048 + UD_VOL_REC_END;
	for (; off < end_off; off += UD_VOL_REC_BSZ) {

		if (ud_read_dev(h, off, buf, UD_VOL_REC_BSZ) == 0) {

			ndsc = (struct nsr_desc *)buf;
			/*
			 * Is this either NSR02 or NSR03
			 */
			if ((ndsc->nsr_str_type == 0) &&
				(ndsc->nsr_ver == 1) &&
				(ndsc->nsr_id[0] == 'N') &&
				(ndsc->nsr_id[1] == 'S') &&
				(ndsc->nsr_id[2] == 'R') &&
				(ndsc->nsr_id[3] == '0') &&
					((ndsc->nsr_id[4] == '2') ||
					(ndsc->nsr_id[4] == '3'))) {

				(void) strncpy((char *)h->udfs.ecma_id,
					(char *)ndsc->nsr_id, 5);

				switch (ndsc->nsr_id[4]) {
				case '2' :

					/*
					 * ECMA 167/2
					 */
					ecma_ver = UD_ECMA_VER2;
					goto end;
				case '3' :

					/*
					 * ECMA 167/3
					 */
					ecma_ver = UD_ECMA_VER3;
					goto end;
				}
			}
		}
	}

end:
	/*
	 * Cleanup
	 */
	free(buf);
	return (ecma_ver);
}

static uint32_t last_block_index[] = {0, 0, 256, 2, 2 + 256,
		150, 150 + 256, 152, 152 + 256};

static int32_t
ud_get_fs_bsize(ud_handle_t h, uint32_t offset, uint32_t *avd_loc)
{
	uint64_t off;
	int32_t index, bsize, shift, end_index;
	uint32_t num_blocks, sub_blk;
	uint8_t *buf = NULL;
	struct anch_vol_desc_ptr *avdp;

	if ((buf = (uint8_t *)malloc(MAXBSIZE)) == NULL) {
		return (0);
	}

	/*
	 * If we could figure out the last block
	 * search at 256, N, N - 256 blocks
	 * otherwise just check at 256
	 */
	if (ud_get_num_blks(h, &num_blocks) != 0) {
		end_index = 1;
		num_blocks = 0;
	} else {
		end_index = sizeof (last_block_index) / 4;
	}

	for (index = 0; index < end_index; index++) {
		sub_blk = last_block_index[index];

		/*
		 * Start guessing from DEV_BSIZE to MAXBSIZE
		 */
		for (bsize = DEV_BSIZE, shift = 0;
			bsize <= MAXBSIZE; bsize <<= 1, shift++) {

			if (index == 0) {

				/*
				 * Check if we atleast have 256 of bsize
				 * blocks on the device
				 */
				if ((end_index == 0) ||
					(num_blocks > (256 << shift))) {
					*avd_loc = 256;
					if (bsize <= 2048) {
						*avd_loc +=
							offset * 2048 / bsize;
					} else {
						*avd_loc +=
							offset / (bsize / 2048);
					}
				} else {
					continue;
				}
			} else {
				/*
				 * Calculate the bsize avd block
				 */
				if ((num_blocks) &&
					(num_blocks > (sub_blk << shift))) {
					*avd_loc = (num_blocks >> shift) -
						sub_blk;
				} else {
					continue;
				}
			}

			off = (uint64_t)*avd_loc * bsize;

			/*
			 * Read bsize bytes at off
			 */
			if (ud_read_dev(h, off, buf, bsize) != 0) {
				continue;
			}

			/*
			 * Check if we have a Anchor Volume Descriptor here
			 */

			/* LINTED */
			avdp = (struct anch_vol_desc_ptr *)buf;
			if (ud_verify_tag(h, &avdp->avd_tag,
				UD_ANCH_VOL_DESC, *avd_loc, 1, 0) != 0) {
				continue;
			}
			goto end;
		}
	}

end:
	if (bsize > MAXBSIZE) {
		bsize = 0;
		*avd_loc = 0;
	}
	free(buf);
	return (bsize);
}

static int32_t
ud_parse_fill_vds(ud_handle_t h, struct vds *v,
	uint32_t vds_loc, uint32_t vds_len)
{
	uint8_t *addr, *taddr, *eaddr;
	uint16_t id;
	int32_t i;
	uint64_t off;
	struct tag *tag;
	struct pri_vol_desc *pvd;
	struct log_vol_desc *lvd;
	struct vol_desc_ptr *vds;
	struct unall_spc_desc *usd;

begin:
	if ((addr = (uint8_t *)malloc(vds_len)) == NULL) {
		return (1);
	}

	off = vds_loc * h->udfs.lbsize;
	if (ud_read_dev(h, off, addr, vds_len) != 0) {
		goto end;
	}

	for (taddr = addr, eaddr = addr + h->udfs.mvds_len; taddr < eaddr;
			taddr += h->udfs.lbsize, vds_loc ++) {

		/* LINTED */
		tag = (struct tag *)taddr;
		id = SWAP_16(tag->tag_id);
		/*
		 * If you cannot verify the tag just skip it
		 * This is not a fatal error
		 */
		if (ud_verify_tag(h, tag, id, vds_loc, 1, 0) != 0) {
			continue;
		}
		switch (id) {
		case UD_PRI_VOL_DESC :

			/*
			 * Primary Volume Descriptor
			 */
			/* LINTED */
			pvd = (struct pri_vol_desc *)taddr;
			if ((v->pvd_len == 0) ||
				(SWAP_32(pvd->pvd_vdsn) > v->pvd_vdsn)) {
				v->pvd_vdsn = SWAP_32(pvd->pvd_vdsn);
				v->pvd_loc = vds_loc;
				v->pvd_len = h->udfs.lbsize;
			}
			break;
		case UD_VOL_DESC_PTR :

			/*
			 * Curent sequence is continued from
			 * the location pointed by vdp
			 */
			/* LINTED */
			vds = (struct vol_desc_ptr *)taddr;

			if (SWAP_32(vds->vdp_nvdse.ext_len) != 0) {
				vds_loc = SWAP_32(vds->vdp_nvdse.ext_loc);
				vds_len = SWAP_32(vds->vdp_nvdse.ext_len);
				free(addr);
				goto begin;
			}
			break;
		case UD_IMPL_USE_DESC :

			/*
			 * Implementation Use Volume Descriptor
			 */
			v->iud_loc = vds_loc;
			v->iud_len = lb_roundup(512, h->udfs.lbsize);
			break;
		case UD_PART_DESC :
			{
				struct ud_part *p;
				struct phdr_desc *ph;
				struct part_desc *pd;

				/*
				 * Partition Descriptor
				 */
				/* LINTED */
				pd = (struct part_desc *)taddr;

				for (i = 0; i < h->n_parts; i++) {
					p = &h->part[i];

					if ((SWAP_16(pd->pd_pnum) ==
							p->udp_number) &&
						(SWAP_32(pd->pd_vdsn) >
							p->udp_seqno)) {
						break;
					}
				}

				v->part_loc[i] = vds_loc;
				v->part_len[i] =
					lb_roundup(512, h->udfs.lbsize);

				p = &h->part[i];
				p->udp_number = SWAP_16(pd->pd_pnum);
				p->udp_seqno = SWAP_32(pd->pd_vdsn);
				p->udp_access = SWAP_32(pd->pd_acc_type);
				p->udp_start = SWAP_32(pd->pd_part_start);
				p->udp_length = SWAP_32(pd->pd_part_length);

				/* LINTED */
				ph = (struct phdr_desc *)pd->pd_pc_use;
				if (ph->phdr_ust.sad_ext_len) {
			p->udp_flags = UDP_SPACETBLS;
			p->udp_unall_loc = SWAP_32(ph->phdr_ust.sad_ext_loc);
			p->udp_unall_len = SWAP_32(ph->phdr_ust.sad_ext_len);
			p->udp_freed_loc = SWAP_32(ph->phdr_fst.sad_ext_loc);
			p->udp_freed_len = SWAP_32(ph->phdr_fst.sad_ext_len);
				} else {
			p->udp_flags = UDP_BITMAPS;
			p->udp_unall_loc = SWAP_32(ph->phdr_usb.sad_ext_loc);
			p->udp_unall_len = SWAP_32(ph->phdr_usb.sad_ext_len);
			p->udp_freed_loc = SWAP_32(ph->phdr_fsb.sad_ext_loc);
			p->udp_freed_len = SWAP_32(ph->phdr_fsb.sad_ext_len);
				}

				if (i == h->n_parts) {
					h->n_parts ++;
				}
			}
			break;
		case UD_LOG_VOL_DESC :

			/*
			 * Logical Volume Descriptor
			 */
			/* LINTED */
			lvd = (struct log_vol_desc *)taddr;
			if ((v->lvd_len == 0) ||
				(SWAP_32(lvd->lvd_vdsn) > v->lvd_vdsn)) {
				v->lvd_vdsn = SWAP_32(lvd->lvd_vdsn);
				v->lvd_loc = vds_loc;
				v->lvd_len = ((uint32_t)
					&((struct log_vol_desc *)0)->lvd_pmaps);
				v->lvd_len =
					lb_roundup(v->lvd_len, h->udfs.lbsize);
			}
			break;
		case UD_UNALL_SPA_DESC :

			/*
			 * Unallocated Space Descriptor
			 */
			/* LINTED */
			usd = (struct unall_spc_desc *)taddr;
			v->usd_loc = vds_loc;
			v->usd_len = ((uint32_t)
			&((unall_spc_desc_t *)0)->ua_al_dsc) +
				SWAP_32(usd->ua_nad) *
				sizeof (struct extent_ad);
			v->usd_len = lb_roundup(v->usd_len, h->udfs.lbsize);
			break;
		case UD_TERM_DESC :
			/*
			 * Success fully completed
			 */
			goto end;
		default :
			/*
			 * If you donot undetstand any tag just skip
			 * it. This is not a fatal error
			 */
			break;
		}
	}

end:
	free(addr);
	if ((v->pvd_len == 0) ||
		(v->part_len[0] == 0) ||
		(v->lvd_len == 0)) {
		return (1);
	}

	return (0);
}

static int32_t
ud_read_and_translate_lvd(ud_handle_t h, uint32_t lvd_loc, uint32_t lvd_len)
{
	caddr_t addr;
	uint16_t fsd_prn;
	uint32_t fsd_loc, fsd_len;
	uint32_t lvds_loc, lvds_len;
	uint64_t off;
	struct log_vol_desc *lvd = NULL;

	int32_t max_maps, i, mp_sz, index;
	struct ud_map *m;
	struct pmap_hdr *ph;
	struct pmap_typ1 *typ1;
	struct pmap_typ2 *typ2;

	if (lvd_len == 0) {
		return (1);
	}

	if ((lvd = (struct log_vol_desc *)
			malloc(lvd_len)) == NULL) {
		return (1);
	}

	off = lvd_loc * h->udfs.lbsize;
	if (ud_read_dev(h, off, (uint8_t *)lvd, lvd_len) != 0) {
		free(lvd);
		return (1);
	}

	if (ud_verify_tag(h, &lvd->lvd_tag, UD_LOG_VOL_DESC,
			lvd_loc, 1, 0) != 0) {
		free(lvd);
		return (1);
	}

	/*
	 * Take care of maps
	 */
	max_maps = SWAP_32(lvd->lvd_num_pmaps);
	ph = (struct pmap_hdr *)lvd->lvd_pmaps;
	for (h->n_maps = index = 0; index < max_maps; index++) {
		m = &h->maps[h->n_maps];
		switch (ph->maph_type) {
		case MAP_TYPE1 :

			/* LINTED */
			typ1 = (struct pmap_typ1 *)ph;

			m->udm_flags = UDM_MAP_NORM;
			m->udm_vsn = SWAP_16(typ1->map1_vsn);
			m->udm_pn = SWAP_16(typ1->map1_pn);
			h->n_maps++;
			break;

		case MAP_TYPE2 :

			/* LINTED */
			typ2 = (struct pmap_typ2 *)ph;

			if (strncmp(typ2->map2_pti.reg_id,
					UDF_VIRT_PART, 23) == 0) {

				m->udm_flags = UDM_MAP_VPM;
				m->udm_vsn = SWAP_16(typ2->map2_vsn);
				m->udm_pn = SWAP_16(typ2->map2_pn);
			} else if (strncmp(typ2->map2_pti.reg_id,
					UDF_SPAR_PART, 23) == 0) {

				if ((SWAP_16(typ2->map2_pl) != 32) ||
						(typ2->map2_nst < 1) ||
						(typ2->map2_nst > 4)) {
					break;
				}
				m->udm_flags = UDM_MAP_SPM;
				m->udm_vsn = SWAP_16(typ2->map2_vsn);
				m->udm_pn = SWAP_16(typ2->map2_pn);

				m->udm_plen = SWAP_16(typ2->map2_pl);
				m->udm_nspm = typ2->map2_nst;
				m->udm_spsz = SWAP_32(typ2->map2_sest);

				mp_sz = lb_roundup(m->udm_spsz, h->udfs.lbsize);

				if ((addr = malloc(mp_sz * m->udm_nspm)) ==
						NULL) {
					break;
				}

				for (i = 0; i < m->udm_nspm; i++) {
					m->udm_loc[i] =
						SWAP_32(typ2->map2_st[index]);
					m->udm_spaddr[i] = addr + i * mp_sz;

					off = m->udm_loc[i] * h->udfs.lbsize;
					if (ud_read_dev(h, off,
						(uint8_t *)m->udm_spaddr[i],
							mp_sz) != 0) {
						m->udm_spaddr[i] = NULL;
						continue;
					}
				}
			}
			h->n_maps++;
		default :
			break;
		}
		ph = (struct pmap_hdr *)(((uint8_t *)h) + ph->maph_length);
	}

	lvds_loc = SWAP_32(lvd->lvd_int_seq_ext.ext_loc);
	lvds_len = SWAP_32(lvd->lvd_int_seq_ext.ext_len);

	fsd_prn = SWAP_16(lvd->lvd_lvcu.lad_ext_prn);
	fsd_loc = SWAP_32(lvd->lvd_lvcu.lad_ext_loc);
	fsd_len = SWAP_32(lvd->lvd_lvcu.lad_ext_len);

	free(lvd);

	/*
	 * Get the latest LVID
	 */
	if (ud_get_latest_lvid(h, lvds_loc, lvds_len) != 0) {
		return (1);
	}

	if (ud_get_latest_fsd(h, fsd_prn, fsd_loc, fsd_len) != 0) {
		return (1);
	}

	return (0);
}

static int32_t
ud_get_latest_lvid(ud_handle_t h, uint32_t lvds_loc, uint32_t lvds_len)
{
	uint8_t *addr, *taddr, *eaddr;
	uint16_t id;
	uint64_t off;
	struct tag *tag;
	struct log_vol_int_desc *lvid;

begin:
	if ((addr = (uint8_t *)malloc(lvds_len)) == NULL) {
		return (1);
	}

	off = lvds_loc * h->udfs.lbsize;
	if (ud_read_dev(h, off, addr, lvds_len) != 0) {
		goto end;
	}

	for (taddr = addr, eaddr = addr + h->udfs.mvds_len; taddr < eaddr;
			taddr += h->udfs.lbsize, lvds_loc ++) {

		/* LINTED */
		tag = (struct tag *)taddr;
		id = SWAP_16(tag->tag_id);
		/*
		 * If you cannot verify the tag just skip it
		 * This is not a fatal error
		 */
		if (ud_verify_tag(h, tag, id, lvds_loc, 1, 0) != 0) {
			continue;
		}
		switch (id) {
		case UD_LOG_VOL_INT :

			/*
			 * Logical Volume Integrity Descriptor
			 */
			/* LINTED */
			lvid = (struct log_vol_int_desc *)taddr;
			h->udfs.lvid_loc = lvds_loc;
			h->udfs.lvid_len = ((uint32_t)
			&((struct log_vol_int_desc *)0)->lvid_fst) +
				SWAP_32(lvid->lvid_npart) * 8 +
				SWAP_32(lvid->lvid_liu);
			h->udfs.lvid_len = lb_roundup(h->udfs.lvid_len,
				h->udfs.lbsize);

			/*
			 * It seems we have a next integrity
			 * sequence
			 */
			if (SWAP_32(lvid->lvid_nie.ext_len) != 0) {
				free(addr);
				lvds_loc = SWAP_32(lvid->lvid_nie.ext_loc);
				lvds_len = SWAP_32(lvid->lvid_nie.ext_len);
				goto begin;
			}
			goto end;
		case UD_TERM_DESC :

			/*
			 * Success fully completed
			 */
				goto end;
		default :
			/*
			 * If you donot undetstand any tag just skip
			 * it. This is not a fatal error
			 */
			break;
		}
	}
end:
	free(addr);
	if (h->udfs.lvid_len == 0) {
		return (1);
	}
	return (0);
}

static int32_t
ud_get_latest_fsd(ud_handle_t h, uint16_t fsd_prn,
	uint32_t fsd_loc, uint32_t fsd_len)
{
	uint8_t *addr, *taddr, *eaddr;
	uint16_t id;
	uint64_t off;
	uint32_t fsds_loc, fsds_len;
	struct tag *tag;
	struct file_set_desc *fsd;
	uint32_t old_fsn = 0;

begin:
	h->udfs.fsds_prn = fsd_prn;
	h->udfs.fsds_loc = fsd_loc;
	h->udfs.fsds_len = fsd_len;

	fsds_loc = ud_xlate_to_daddr(h, fsd_prn, fsd_loc);
	fsds_len = lb_roundup(fsd_len, h->udfs.lbsize);

	if ((addr = (uint8_t *)malloc(fsds_len)) == NULL) {
		return (1);
	}

	off = fsds_loc * h->udfs.lbsize;
	if (ud_read_dev(h, off, addr, fsds_len) != 0) {
		goto end;
	}

	for (taddr = addr, eaddr = addr + h->udfs.mvds_len; taddr < eaddr;
			taddr += h->udfs.lbsize, fsds_loc ++) {

		/* LINTED */
		tag = (struct tag *)taddr;
		id = SWAP_16(tag->tag_id);
		/*
		 * If you cannot verify the tag just skip it
		 * This is not a fatal error
		 */
		if (ud_verify_tag(h, tag, id, fsds_loc, 1, 0) != 0) {
			continue;
		}
		switch (id) {
		case UD_FILE_SET_DESC :
			/* LINTED */
			fsd = (struct file_set_desc *)taddr;
			if ((h->udfs.fsd_len == 0) ||
				(SWAP_32(fsd->fsd_fs_no) > old_fsn)) {
				old_fsn = SWAP_32(fsd->fsd_fs_no);
				h->udfs.fsd_loc = fsds_loc;
				h->udfs.fsd_len = lb_roundup(512,
					h->udfs.lbsize);
				h->udfs.ricb_prn =
					SWAP_16(fsd->fsd_root_icb.lad_ext_prn);
				h->udfs.ricb_loc =
					SWAP_32(fsd->fsd_root_icb.lad_ext_loc);
				h->udfs.ricb_len =
					SWAP_32(fsd->fsd_root_icb.lad_ext_len);
			}
			if (SWAP_32(fsd->fsd_next.lad_ext_len) != 0) {
				fsd_prn = SWAP_16(fsd->fsd_next.lad_ext_prn);
				fsd_loc = SWAP_32(fsd->fsd_next.lad_ext_loc);
				fsd_len = SWAP_32(fsd->fsd_next.lad_ext_len);
				goto begin;
			}
			break;
		case UD_TERM_DESC :

			/*
			 * Success fully completed
			 */
			goto end;
		default :
			/*
			 * If you donot undetstand any tag just skip
			 * it. This is not a fatal error
			 */
			break;
		}
	}

end:
	free(addr);
	if (h->udfs.fsd_len == 0) {
		return (1);
	}
	return (0);
}

int32_t
ud_get_num_blks(ud_handle_t h, uint32_t *blkno)
{
	struct vtoc vtoc;
	struct dk_cinfo dki_info;
	int32_t error;

	/*
	 * Get VTOC from driver
	 */
	if ((error = ioctl(h->fd, DKIOCGVTOC, (intptr_t)&vtoc)) != 0) {
		return (error);
	}

	/*
	 * Verify if is proper
	 */
	if (vtoc.v_sanity != VTOC_SANE) {
		return (EINVAL);
	}

	/*
	 * Get dk_cinfo from driver
	 */
	if ((error = ioctl(h->fd, DKIOCINFO, (intptr_t)&dki_info)) != 0) {
		return (error);
	}

	if (dki_info.dki_partition >= V_NUMPAR) {
		return (EINVAL);
	}

	/*
	 * Return the size of the partition
	 */
	*blkno = vtoc.v_part[dki_info.dki_partition].p_size;

	return (0);
}

uint32_t
ud_xlate_to_daddr(ud_handle_t h, uint16_t prn, uint32_t blkno)
{
	int32_t i;
	struct ud_map *m;
	struct ud_part *p;


	if (prn < h->n_maps) {
		m = &h->maps[prn];
		for (i = 0; i < h->n_parts; i++) {
			p = &h->part[i];
			if (m->udm_pn == p->udp_number) {
				return (p->udp_start + blkno);
			}
		}
	}
	return (0);
}

/* ------ END Read and translate the on disk VDS to IN CORE format -------- */

int32_t
ud_verify_tag(ud_handle_t h, struct tag *tag, uint16_t id,
	uint32_t blockno, int32_t do_crc, int32_t print_msg)
{
	int32_t i;
	uint8_t *addr, cksum = 0;
	uint16_t crc;


	/*
	 * Verify Tag Identifier
	 */
	if (tag->tag_id != SWAP_16(id)) {
		if (print_msg != 0) {
			(void) fprintf(stderr,
				gettext("tag does not verify tag %x req %x\n"),
				SWAP_16(tag->tag_id), id);
		}
		return (1);
	}

	/*
	 * Verify Tag Descriptor Version
	 */
	if (SWAP_16(tag->tag_desc_ver) != h->udfs.ecma_version) {
		if (print_msg != 0) {
			(void) fprintf(stderr,
				gettext("tag version does not match with "
				"NSR descriptor version TAG %x NSR %x\n"),
				SWAP_16(tag->tag_desc_ver),
				h->udfs.ecma_version);
		}
		return (1);
	}

	/*
	 * Caliculate Tag Checksum
	 */
	addr = (uint8_t *)tag;
	for (i = 0; i <= 15; i++) {
		if (i != 4) {
			cksum += addr[i];
		}
	}

	/*
	 * Verify Tag Checksum
	 */
	if (cksum != tag->tag_cksum) {
		if (print_msg != 0) {
			(void) fprintf(stderr,
				gettext("Checksum Does not Verify TAG"
				" %x CALC %x\n"), tag->tag_cksum, cksum);
		}
		return (1);
	}


	/*
	 * Do we want to do crc
	 */
	if (do_crc) {
		if (tag->tag_crc_len) {

			/*
			 * Caliculate CRC for the descriptor
			 */
			crc = ud_crc(addr + 0x10, SWAP_16(tag->tag_crc_len));

			/*
			 * Verify CRC
			 */
			if (crc != SWAP_16(tag->tag_crc)) {
				if (print_msg != 0) {
					(void) fprintf(stderr,
						gettext("CRC Does not verify"
						" TAG %x CALC %x %x\n"),
						SWAP_16(tag->tag_crc),
						crc, addr);
				}
			}
		}

		/*
		 * Verify Tag Location
		 */
		if (SWAP_32(blockno) != tag->tag_loc) {
			if (print_msg != 0) {
				(void) fprintf(stderr,
					gettext("Tag Location Does not verify"
					" blockno %x tag_blockno %x\n"),
					blockno, SWAP_32(tag->tag_loc));
			}
		}
	}

	return (0);
}


/* ARGSUSED1 */
void
ud_make_tag(ud_handle_t h, struct tag *tag, uint16_t tag_id,
	uint32_t blkno, uint16_t crc_len)
{
	int32_t i;
	uint16_t crc;
	uint8_t *addr, cksum = 0;

	tag->tag_id = SWAP_16(tag_id);
	tag->tag_desc_ver = SWAP_16(h->udfs.ecma_version);
	tag->tag_cksum = 0;
	tag->tag_res = 0;

	/*
	 * Calicualte and assign CRC, CRC_LEN
	 */
	addr = (uint8_t *)tag;
	crc = ud_crc(addr + 0x10, crc_len);
	tag->tag_crc = SWAP_16(crc);
	tag->tag_crc_len = SWAP_16(crc_len);
	tag->tag_loc = SWAP_32(blkno);

	/*
	 * Caliculate Checksum
	 */
	for (i = 0; i <= 15; i++) {
		cksum += addr[i];
	}

	/*
	 * Assign Checksum
	 */
	tag->tag_cksum = cksum;
}

/* **************** udf specific subroutines *********************** */

static uint16_t ud_crc_table[256] = {
	0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7,
	0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF,
	0x1231, 0x0210, 0x3273, 0x2252, 0x52B5, 0x4294, 0x72F7, 0x62D6,
	0x9339, 0x8318, 0xB37B, 0xA35A, 0xD3BD, 0xC39C, 0xF3FF, 0xE3DE,
	0x2462, 0x3443, 0x0420, 0x1401, 0x64E6, 0x74C7, 0x44A4, 0x5485,
	0xA56A, 0xB54B, 0x8528, 0x9509, 0xE5EE, 0xF5CF, 0xC5AC, 0xD58D,
	0x3653, 0x2672, 0x1611, 0x0630, 0x76D7, 0x66F6, 0x5695, 0x46B4,
	0xB75B, 0xA77A, 0x9719, 0x8738, 0xF7DF, 0xE7FE, 0xD79D, 0xC7BC,
	0x48C4, 0x58E5, 0x6886, 0x78A7, 0x0840, 0x1861, 0x2802, 0x3823,
	0xC9CC, 0xD9ED, 0xE98E, 0xF9AF, 0x8948, 0x9969, 0xA90A, 0xB92B,
	0x5AF5, 0x4AD4, 0x7AB7, 0x6A96, 0x1A71, 0x0A50, 0x3A33, 0x2A12,
	0xDBFD, 0xCBDC, 0xFBBF, 0xEB9E, 0x9B79, 0x8B58, 0xBB3B, 0xAB1A,
	0x6CA6, 0x7C87, 0x4CE4, 0x5CC5, 0x2C22, 0x3C03, 0x0C60, 0x1C41,
	0xEDAE, 0xFD8F, 0xCDEC, 0xDDCD, 0xAD2A, 0xBD0B, 0x8D68, 0x9D49,
	0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13, 0x2E32, 0x1E51, 0x0E70,
	0xFF9F, 0xEFBE, 0xDFDD, 0xCFFC, 0xBF1B, 0xAF3A, 0x9F59, 0x8F78,
	0x9188, 0x81A9, 0xB1CA, 0xA1EB, 0xD10C, 0xC12D, 0xF14E, 0xE16F,
	0x1080, 0x00A1, 0x30C2, 0x20E3, 0x5004, 0x4025, 0x7046, 0x6067,
	0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C, 0xE37F, 0xF35E,
	0x02B1, 0x1290, 0x22F3, 0x32D2, 0x4235, 0x5214, 0x6277, 0x7256,
	0xB5EA, 0xA5CB, 0x95A8, 0x8589, 0xF56E, 0xE54F, 0xD52C, 0xC50D,
	0x34E2, 0x24C3, 0x14A0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
	0xA7DB, 0xB7FA, 0x8799, 0x97B8, 0xE75F, 0xF77E, 0xC71D, 0xD73C,
	0x26D3, 0x36F2, 0x0691, 0x16B0, 0x6657, 0x7676, 0x4615, 0x5634,
	0xD94C, 0xC96D, 0xF90E, 0xE92F, 0x99C8, 0x89E9, 0xB98A, 0xA9AB,
	0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882, 0x28A3,
	0xCB7D, 0xDB5C, 0xEB3F, 0xFB1E, 0x8BF9, 0x9BD8, 0xABBB, 0xBB9A,
	0x4A75, 0x5A54, 0x6A37, 0x7A16, 0x0AF1, 0x1AD0, 0x2AB3, 0x3A92,
	0xFD2E, 0xED0F, 0xDD6C, 0xCD4D, 0xBDAA, 0xAD8B, 0x9DE8, 0x8DC9,
	0x7C26, 0x6C07, 0x5C64, 0x4C45, 0x3CA2, 0x2C83, 0x1CE0, 0x0CC1,
	0xEF1F, 0xFF3E, 0xCF5D, 0xDF7C, 0xAF9B, 0xBFBA, 0x8FD9, 0x9FF8,
	0x6E17, 0x7E36, 0x4E55, 0x5E74, 0x2E93, 0x3EB2, 0x0ED1, 0x1EF0
};

static uint16_t
ud_crc(uint8_t *addr, int32_t len)
{
	uint16_t crc = 0;

	while (len-- > 0) {
		crc = ud_crc_table[(crc >> 8 ^ *addr++) & 0xff] ^ (crc<<8);
	}

	return (crc);
}

#define	MAXNAMLEN	0x200


#define	POUND		0x0023
#define	DOT		0x002E
#define	SLASH		0x002F
#define	UNDERBAR	0x005F


static uint16_t htoc[16] = {'0', '1', '2', '3',
	'4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
/*
 * unicode is the string of 16-bot characters
 * length is the number of 16-bit characters
 */
static int32_t
UdfTxName(uint16_t *unicode, int32_t count)
{
	int32_t i, j, k, lic, make_crc, dot_loc;
	uint16_t crc;

	if ((unicode[0] == DOT) &&
		((count == 1) || ((count == 2) && (unicode[1] == DOT)))) {
		crc = DOT;
		if (count == 2) {
			crc += DOT;
		}
		unicode[0] = UNDERBAR;
		unicode[1] = POUND;
		unicode[2] = htoc[(uint16_t)(crc & 0xf000) >> 12];
		unicode[3] = htoc[(uint16_t)(crc & 0xf00) >> 8];
		unicode[4] = htoc[(uint16_t)(crc & 0xf0) >> 4];
		unicode[5] = htoc[crc & 0xf];
		return (6);
	}
	crc = 0;
	j = make_crc = 0;
	lic = dot_loc = -1;
	for (i = 0; i < count; i++) {
		if (make_crc) {
			crc += unicode[i];
		}
		if (unicode[i] == DOT) {
			dot_loc = j;
		}
		if ((unicode[i] == SLASH) ||
			(unicode[i] == 0)) {
			if (make_crc == 0) {
				for (k = 0; k <= i; k++) {
					crc += unicode[k];
				}
				make_crc = 1;
			}
			if (lic != (i - 1)) {
				unicode[j++] = UNDERBAR;
			}
			lic = i;
		} else {
			unicode[j++] = unicode[i];
		}
	}

	if (make_crc) {
		if (dot_loc != -1) {
			if ((j + 5) > MAXNAMLEN) {
				if ((j - dot_loc + 5) > MAXNAMLEN) {
					j = MAXNAMLEN - 5 + dot_loc;
					for (k = MAXNAMLEN;
						j >= dot_loc; k --, j--) {
						unicode[k] = unicode[j];
					}
					k = 0;
				} else {
					for (k = MAXNAMLEN;
						j >= dot_loc; k--, j--) {
						unicode[k] = unicode[j];
					}
					k -= 4;
				}
				j = MAXNAMLEN;
			} else {
				for (k = j; k >= dot_loc; k--) {
					unicode[k + 5] = unicode[k];
				}
				k = dot_loc;
				j += 5;
			}
		} else {
			if ((j + 5) > MAXNAMLEN) {
				j = MAXNAMLEN;
				k = MAXNAMLEN - 5;
			} else {
				k = j;
				j += 5;
			}
		}
		unicode[k++] = POUND;
		unicode[k++] = htoc[(uint16_t)(crc & 0xf000) >> 12];
		unicode[k++] = htoc[(uint16_t)(crc & 0xf00) >> 8];
		unicode[k++] = htoc[(uint16_t)(crc & 0xf0) >> 4];
		unicode[k++] = htoc[crc & 0xf];
	}
	return (j);
}

/*
 * Assumes the output buffer is large
 * enough to hold the uncompressed
 * code
 */
static int32_t
UncompressUnicode(
	int32_t numberOfBytes,	/* (Input) number of bytes read from media. */
	uint8_t *UDFCompressed,	/* (Input) bytes read from media. */
	uint16_t *unicode)	/* (Output) uncompressed unicode characters. */
{
	int32_t compID;
	int32_t returnValue, unicodeIndex, byteIndex;


	/*
	 * Use UDFCompressed to store current byte being read.
	 */
	compID = UDFCompressed[0];

	/* First check for valid compID. */
	if (compID != 8 && compID != 16) {
		returnValue = -1;
	} else {
		unicodeIndex = 0;
		byteIndex = 1;

		/* Loop through all the bytes. */
		while (byteIndex < numberOfBytes) {
			if (compID == 16) {
				/*
				 * Move the first byte to the
				 * high bits of the unicode char.
				 */
				unicode[unicodeIndex] =
					UDFCompressed[byteIndex++] << 8;
			} else {
				unicode[unicodeIndex] = 0;
			}
			if (byteIndex < numberOfBytes) {
				/*
				 * Then the next byte to the low bits.
				 */
				unicode[unicodeIndex] |=
					UDFCompressed[byteIndex++];
			}
			unicodeIndex++;
		}
		returnValue = unicodeIndex;
	}
	return (returnValue);
}





static int32_t
ud_compressunicode(
	int32_t numberOfChars,	/* (Input) number of unicode characters. */
	int32_t compID,		/* (Input) compression ID to be used. */
	uint16_t *unicode,	/* (Input) unicode characters to compress. */
	uint8_t *UDFCompressed) /* (Output) compressed string, as bytes. */
{
	int32_t byteIndex;

	if (compID != 8 && compID != 16) {
		/*
		 * Unsupported compression ID !
		 */
		byteIndex = -1;
	} else {
		/*
		 * Place compression code in first byte.
		 */
		UDFCompressed[0] = (uint8_t)compID;
		(void) strncpy((caddr_t)&UDFCompressed[1],
			(caddr_t)unicode, numberOfChars);
		byteIndex = numberOfChars + 1;
	}
	return (byteIndex);
}


static int32_t
ud_convert2utf8(uint8_t *ibuf, uint8_t *obuf, int32_t length)
{
	int i, size;
	uint16_t *buf;

	/* LINTED */
	buf = (uint16_t *)obuf;

	size = UncompressUnicode(length, ibuf, buf);

	size = UdfTxName(buf, size);

	for (i = 0; i < size; i++) {
		obuf[i] = (uint8_t)buf[i];
	}
	obuf[i] = '\0';

	return (size);
}

static int32_t
ud_convert2utf16(uint8_t *ibuf, uint8_t *obuf, int32_t length)
{
	int32_t comp_len;
	uint16_t *ptr;

	/* LINTED */
	ptr = (uint16_t *)ibuf;
	comp_len = ud_compressunicode(length, 8, ptr, obuf);

	return (comp_len);
}

/*
 * Assumption code set is zero in udfs
 */
void
ud_convert2local(int8_t *ibuf, int8_t *obuf, int32_t length)
{
	wchar_t buf4c[128];
	int32_t i, comp, index;

	/*
	 * Special uncompress code
	 * written to accomodate solaris wchar_t
	 */
	comp = ibuf[0];
	for (i = 0, index = 1; i < length; i++) {
		if (comp == 16) {
			buf4c[i] = ibuf[index++] << 8;
		} else {
			buf4c[i] = 0;
		}
		if (index < length) {
			buf4c[i] |= ibuf[index++];
		}
	}
	(void) wcstombs((char *)obuf, buf4c, 128);
}


/* ------------ Routines to print basic structures Part 1 ---------------- */



void
print_charspec(FILE *fout, char *name, struct charspec *cspec)
{
	int i = 0;

	(void) fprintf(fout,
		"%s : %x - \"", name, cspec->cs_type);
	for (i = 0; i < 63; i++) {
		(void) fprintf(fout,
			"%c", cspec->cs_info[i]);
	}
	(void) fprintf(fout, "\n");
}

/* ARGSUSED */
void
print_dstring(FILE *fout, char *name, uint16_t cset, char *bufc, uint8_t length)
{
	int8_t bufmb[1024];

	ud_convert2local(bufc, bufmb, length);

	(void) fprintf(fout,
		"%s %s\n", name, bufmb);
}

void
set_dstring(dstring_t *dp, char *cp, int32_t len)
{
	int32_t length;

	bzero(dp, len);
	length = strlen(cp);
	if (length > len - 1) {
		length = len - 1;
	}
	(void) strncpy(dp, cp, length);
	dp[len - 1] = length;
}

void
print_tstamp(FILE *fout, char *name, tstamp_t *ts)
{
	(void) fprintf(fout, "%s tz : %d yr : %d mo : %d da : %d "
		"Time : %d : %d : %d : %d : %d : %d\n", name,
		SWAP_16(ts->ts_tzone), SWAP_16(ts->ts_year), ts->ts_month,
		ts->ts_day, ts->ts_hour, ts->ts_min, ts->ts_sec, ts->ts_csec,
		ts->ts_husec, ts->ts_usec);
}



void
make_regid(ud_handle_t h, struct regid *reg, char *id, int32_t type)
{
	reg->reg_flags = 0;
	(void) strncpy(reg->reg_id, id, 23);

	if (type == REG_DOM_ID) {
		struct dom_id_suffix *dis;

		/* LINTED */
		dis = (struct dom_id_suffix *)reg->reg_ids;
		dis->dis_udf_revison = SWAP_16(h->udfs.ma_write);
		dis->dis_domain_flags = 0;

	} else if (type == REG_UDF_ID) {
		struct udf_id_suffix *uis;

		/* LINTED */
		uis = (struct udf_id_suffix *)reg->reg_ids;
		uis->uis_udf_revision = SWAP_16(h->udfs.ma_write);
		uis->uis_os_class = OS_CLASS_UNIX;
		uis->uis_os_identifier = OS_IDENTIFIER_SOLARIS;
	} else if (type == REG_UDF_II) {
		struct impl_id_suffix *iis;

		iis = (struct impl_id_suffix *)reg->reg_ids;
		iis->iis_os_class = OS_CLASS_UNIX;
		iis->iis_os_identifier = OS_IDENTIFIER_SOLARIS;
	}
}

void
print_regid(FILE *fout, char *name, struct regid *reg, int32_t type)
{
	(void) fprintf(fout, "%s : 0x%x : \"%s\" :",
		name, reg->reg_flags, reg->reg_id);

	if (type == REG_DOM_ID) {
		struct dom_id_suffix *dis;

		/* LINTED */
		dis = (struct dom_id_suffix *)reg->reg_ids;
		(void) fprintf(fout, " 0x%x : %s : %s\n",
			SWAP_16(dis->dis_udf_revison),
			(dis->dis_domain_flags & PROTECT_SOFT_WRITE) ?
				"HW Protect" : "No HW Write Protect",
			(dis->dis_domain_flags & PROTECT_HARD_WRITE) ?
				"SW Protect" : "No SW Protect");
	} else if (type == REG_UDF_ID) {
		struct udf_id_suffix *uis;

		/* LINTED */
		uis = (struct udf_id_suffix *)reg->reg_ids;
		(void) fprintf(fout,
			" 0x%x : OS Class 0x%x : OS Identifier 0x%x\n",
			SWAP_16(uis->uis_udf_revision),
			uis->uis_os_class, uis->uis_os_identifier);
	} else {
		struct impl_id_suffix *iis;

		iis = (struct impl_id_suffix *)reg->reg_ids;
		(void) fprintf(fout,
			" OS Class 0x%x : OS Identifier 0x%x\n",
			iis->iis_os_class, iis->iis_os_identifier);
	}
}

#ifdef	OLD
void
print_regid(FILE *fout, char *name, struct regid *reg)
{
	(void) fprintf(fout, "%s : 0x%x : \"%s\" :",
		name, reg->reg_flags, reg->reg_id);

	if (strncmp(reg->reg_id, "*OSTA UDF Compliant", 19) == 0) {
		(void) fprintf(fout, " 0x%x : %s : %s\n",
			reg->reg_ids[0] | (reg->reg_ids[1] << 8),
			(reg->reg_ids[2] & 1) ?
				"HW Protect" : "No HW Write Protect",
			(reg->reg_ids[2] & 2) ?
				"SW Protect" : "No SW Protect");
	} else if ((strncmp(reg->reg_id, "*UDF Virtual Partition", 22) == 0) ||
		(strncmp(reg->reg_id, "*UDF Sparable Partition", 23) == 0) ||
		(strncmp(reg->reg_id, "*UDF Virtual Alloc Tbl", 22) == 0) ||
		(strncmp(reg->reg_id, "*UDF Sparing Table", 18) == 0)) {
		(void) fprintf(fout,
			" 0x%x : OS Class 0x%x : OS Identifier 0x%x\n",
			reg->reg_ids[0] | (reg->reg_ids[1] << 8),
			reg->reg_ids[2], reg->reg_ids[3]);
	} else {
		(void) fprintf(fout,
			" OS Class 0x%x : OS Identifier 0x%x\n",
			reg->reg_ids[0], reg->reg_ids[1]);
	}
}
#endif


/* ------------ Routines to print basic structures Part 2 ---------------- */
/*
 * Part 2
 * This part is OS specific and is currently
 * not supported
 */

/* ------------ Routines to print basic structures Part 3 ---------------- */

void
print_ext_ad(FILE *fout, char *name, struct extent_ad *ead)
{
	(void) fprintf(fout,
		"%s EAD Len %x Loc %x\n",
		name, SWAP_32(ead->ext_len), SWAP_32(ead->ext_loc));
}

void
print_tag(FILE *fout, struct tag *tag)
{
	(void) fprintf(fout,
		"tag_id : %x ver : %x cksum : %x "
		"sno : %x crc : %x crc_len : %x loc : %x\n",
		SWAP_16(tag->tag_id), SWAP_16(tag->tag_desc_ver),
		tag->tag_cksum, SWAP_16(tag->tag_sno),
		SWAP_16(tag->tag_crc), SWAP_16(tag->tag_crc_len),
		SWAP_32(tag->tag_loc));
}


void
print_pvd(FILE *fout, struct pri_vol_desc *pvd)
{
	(void) fprintf(fout,
		"\n\t\t\tPrimary Volume Descriptor\n");
	print_tag(fout, &pvd->pvd_tag);
	(void) fprintf(fout, "vdsn : %x vdn : %x\n",
		SWAP_32(pvd->pvd_vdsn), SWAP_32(pvd->pvd_pvdn));
	print_dstring(fout, "volid : ", pvd->pvd_desc_cs.cs_type,
			pvd->pvd_vol_id, 32);
	(void) fprintf(fout,
		"vsn : %x mvsn : %x il : %x mil :"
		" %x csl : %x mcsl %x\n",
		SWAP_16(pvd->pvd_vsn), SWAP_16(pvd->pvd_mvsn),
		SWAP_16(pvd->pvd_il), SWAP_16(pvd->pvd_mil),
		SWAP_32(pvd->pvd_csl), SWAP_32(pvd->pvd_mcsl));
	print_dstring(fout, "vsid :", pvd->pvd_desc_cs.cs_type,
			pvd->pvd_vsi, 128);
	print_charspec(fout, "desc_cs", &pvd->pvd_desc_cs);
	print_charspec(fout, "exp_cs", &pvd->pvd_exp_cs);
	print_ext_ad(fout, "val ", &pvd->pvd_vol_abs);
	print_ext_ad(fout, "vcnl ", &pvd->pvd_vcn);
	print_regid(fout, "ai", &pvd->pvd_appl_id, REG_UDF_II);
	print_regid(fout, "ii", &pvd->pvd_ii, REG_UDF_II);
	(void) fprintf(fout, "pvdsl : %x flags : %x\n",
		SWAP_32(pvd->pvd_pvdsl),
		SWAP_16(pvd->pvd_flags));
}

void
print_avd(FILE *fout, struct anch_vol_desc_ptr *avdp)
{
	(void) fprintf(fout,
		"\n\t\t\tAnchor Volume Descriptor\n");
	print_tag(fout, &avdp->avd_tag);
	print_ext_ad(fout, "Main Volume Descriptor Sequence : ",
			&avdp->avd_main_vdse);
	print_ext_ad(fout, "Reserve Volume Descriptor Sequence : ",
			&avdp->avd_res_vdse);
}

void
print_vdp(FILE *fout, struct vol_desc_ptr *vdp)
{
	(void) fprintf(fout,
		"\n\t\t\tVolume Descriptor Pointer\n");
	print_tag(fout, &vdp->vdp_tag);
	(void) fprintf(fout, "vdsn : %x ",
		SWAP_32(vdp->vdp_vdsn));
	print_ext_ad(fout, "vdse ", &vdp->vdp_nvdse);
}

void
print_iuvd(FILE *fout, struct iuvd_desc *iuvd)
{
	(void) fprintf(fout,
		"\n\t\t\tImplementation Use Volume Descriptor\n");
	print_tag(fout, &iuvd->iuvd_tag);
	(void) fprintf(fout,
		"vdsn : %x ", SWAP_32(iuvd->iuvd_vdsn));
	print_regid(fout, "Impl Id : ", &iuvd->iuvd_ii, REG_UDF_ID);
	print_charspec(fout, "cset ", &iuvd->iuvd_cset);
	print_dstring(fout, "lvi : ", iuvd->iuvd_cset.cs_type,
			iuvd->iuvd_lvi, 128);
	print_dstring(fout, "ifo1 : ", iuvd->iuvd_cset.cs_type,
			iuvd->iuvd_ifo1, 36);
	print_dstring(fout, "ifo2 : ", iuvd->iuvd_cset.cs_type,
			iuvd->iuvd_ifo2, 36);
	print_dstring(fout, "ifo3 : ", iuvd->iuvd_cset.cs_type,
			iuvd->iuvd_ifo3, 36);

	print_regid(fout, "iid ", &iuvd->iuvd_iid, REG_UDF_II);
}

void
print_part(FILE *fout, struct part_desc *pd)
{
	(void) fprintf(fout,
		"\n\t\t\tPartition Descriptor\n");
	print_tag(fout, &pd->pd_tag);
	(void) fprintf(fout,
		"vdsn : %x flags : %x num : %x ",
		SWAP_32(pd->pd_vdsn),
		SWAP_16(pd->pd_pflags),
		SWAP_16(pd->pd_pnum));
	print_regid(fout, "contents ", &pd->pd_pcontents, REG_UDF_II);
	/* LINTED */
	print_phdr(fout, (struct phdr_desc *)(&pd->pd_pc_use));
	(void) fprintf(fout,
		"acc : %x start : %x length : %x ",
		SWAP_32(pd->pd_acc_type),
		SWAP_32(pd->pd_part_start),
		SWAP_32(pd->pd_part_length));
	print_regid(fout, "Impl Id : ", &pd->pd_ii, REG_UDF_II);
}

void
print_lvd(FILE *fout, struct log_vol_desc *lvd)
{
	(void) fprintf(fout,
		"\n\t\t\tLogical Volume Descriptor\n");
	print_tag(fout, &lvd->lvd_tag);
	(void) fprintf(fout,
		"vdsn : %x ", SWAP_32(lvd->lvd_vdsn));
	print_charspec(fout, "Desc Char Set ", &lvd->lvd_desc_cs);
	print_dstring(fout, "lvid : ", lvd->lvd_desc_cs.cs_type,
			lvd->lvd_lvid, 28);
	(void) fprintf(fout,
		"lbsize : %x ",
		SWAP_32(lvd->lvd_log_bsize));
	print_regid(fout, "Dom Id", &lvd->lvd_dom_id, REG_DOM_ID);
	print_long_ad(fout, "lvcu", &lvd->lvd_lvcu);
	(void) fprintf(fout,
		"mtlen : %x nmaps : %x ",
		SWAP_32(lvd->lvd_mtbl_len),
		SWAP_32(lvd->lvd_num_pmaps));
	print_regid(fout, "Impl Id : ", &lvd->lvd_ii, REG_UDF_II);
	print_ext_ad(fout, "Int Seq", &lvd->lvd_int_seq_ext);
	print_pmaps(fout, lvd->lvd_pmaps, SWAP_32(lvd->lvd_num_pmaps));
}

void
print_usd(FILE *fout, struct unall_spc_desc *ua)
{
	int32_t i, count;

	(void) fprintf(fout,
		"\n\t\t\tUnallocated Space Descriptor\n");
	print_tag(fout, &ua->ua_tag);
	count = SWAP_32(ua->ua_nad);
	(void) fprintf(fout,
		"vdsn : %x nad : %x\n",
		SWAP_32(ua->ua_vdsn), count);
	for (i = 0; i < count; i++) {
		(void) fprintf(fout,
			"loc : %x len : %x\n",
			SWAP_32(ua->ua_al_dsc[i * 2]),
			SWAP_32(ua->ua_al_dsc[i * 2 + 1]));
	}
}

void
print_lvid(FILE *fout, struct log_vol_int_desc *lvid)
{
	int32_t i, count;
	caddr_t addr;
	struct lvid_iu *liu;

	(void) fprintf(fout,
		"\n\t\t\tLogical Volume Integrity Descriptor\n");
	print_tag(fout, &lvid->lvid_tag);
	print_tstamp(fout, "Rec TM ", &lvid->lvid_tstamp);
	if (SWAP_32(lvid->lvid_int_type) == 0) {
		(void) fprintf(fout,
			"int_typ : Open\n");
	} else if (SWAP_32(lvid->lvid_int_type) == 1) {
		(void) fprintf(fout, "int_typ : Closed\n");
	} else {
		(void) fprintf(fout, "int_typ : Unknown\n");
	}
	print_ext_ad(fout, "Nie ", &lvid->lvid_nie);
	count = SWAP_32(lvid->lvid_npart);
	(void) fprintf(fout,
		"Uniq : %llx npart : %x liu : %x\n",
		SWAP_64(lvid->lvid_lvcu.lvhd_uniqid),
		count, SWAP_32(lvid->lvid_liu));
	for (i = 0; i < count; i++) {
		(void) fprintf(fout,
			"Part : %x Free : %x Size : %x\n",
			i, SWAP_32(lvid->lvid_fst[i]),
			SWAP_32(lvid->lvid_fst[count + i]));
	}

	addr = (caddr_t)lvid->lvid_fst;
	/* LINTED */
	liu = (struct lvid_iu *)(addr + 2 * count * 4);
	print_regid(fout, "Impl Id :", &liu->lvidiu_regid, REG_UDF_II);
	(void) fprintf(fout,
		"nfiles : %x ndirs : %x miread : %x"
		" miwrite : %x mawrite : %x\n",
		SWAP_32(liu->lvidiu_nfiles), SWAP_32(liu->lvidiu_ndirs),
		SWAP_16(liu->lvidiu_mread), SWAP_16(liu->lvidiu_mwrite),
		SWAP_16(liu->lvidiu_maxwr));
}


/* ------------ Routines to print basic structures Part 4 ---------------- */

void
print_fsd(FILE *fout, ud_handle_t h, struct file_set_desc *fsd)
{
	(void) fprintf(fout,
		"\n\t\t\tFile Set Descriptor\n");

	print_tag(fout, &fsd->fsd_tag);
	print_tstamp(fout, "Rec TM ", &fsd->fsd_time);
	(void) fprintf(fout,
		"ilvl : %x milvl : %x csl : %x"
		" mcsl : %x fsn : %x fsdn : %x\n",
		SWAP_16(fsd->fsd_ilevel), SWAP_16(fsd->fsd_mi_level),
		SWAP_32(fsd->fsd_cs_list), SWAP_32(fsd->fsd_mcs_list),
		SWAP_32(fsd->fsd_fs_no), SWAP_32(fsd->fsd_fsd_no));
	print_charspec(fout, "ID CS ", &fsd->fsd_lvidcs);
	print_dstring(fout, "lvi : ", fsd->fsd_lvidcs.cs_type,
			fsd->fsd_lvid, 128);
	print_charspec(fout, "ID CS ", &fsd->fsd_fscs);
	print_dstring(fout, "fsi : ", fsd->fsd_lvidcs.cs_type,
			fsd->fsd_fsi, 32);
	print_dstring(fout, "cfi : ", fsd->fsd_lvidcs.cs_type,
			fsd->fsd_cfi, 32);
	print_dstring(fout, "afi : ", fsd->fsd_lvidcs.cs_type,
			fsd->fsd_afi, 32);
	print_long_ad(fout, "Ricb ", &fsd->fsd_root_icb);
	print_regid(fout, "DI ", &fsd->fsd_did, REG_DOM_ID);
	print_long_ad(fout, "Next Fsd ", &fsd->fsd_next);
	if (h->udfs.ecma_version == UD_ECMA_VER3) {
		print_long_ad(fout, "System Stream Directory ICB ",
				&fsd->fsd_next);
	}
}

void
print_phdr(FILE *fout, struct phdr_desc *ph)
{
	print_short_ad(fout, "ust ", &ph->phdr_ust);
	print_short_ad(fout, "usb ", &ph->phdr_usb);
	print_short_ad(fout, "int ", &ph->phdr_it);
	print_short_ad(fout, "fst ", &ph->phdr_fst);
	print_short_ad(fout, "fsh ", &ph->phdr_fsb);
}

void
print_fid(FILE *fout, struct file_id *fid)
{
	int32_t i;
	uint8_t *addr;

	(void) fprintf(fout,
		"File Identifier Descriptor\n");
	print_tag(fout, &fid->fid_tag);
	(void) fprintf(fout, "fvn : %x fc : %x length : %x ",
		fid->fid_ver, fid->fid_flags, fid->fid_idlen);
	print_long_ad(fout, "ICB", &fid->fid_icb);
	addr = &fid->fid_spec[SWAP_16(fid->fid_iulen)];
	(void) fprintf(fout, "iulen : %x comp : %x name : ",
		SWAP_16(fid->fid_iulen), *addr);
	addr++;
	for (i = 0; i < fid->fid_idlen; i++) {
		(void) fprintf(fout, "%c", *addr++);
	}
	(void) fprintf(fout, "\n");
}

void
print_aed(FILE *fout, struct alloc_ext_desc *aed)
{
	(void) fprintf(fout,
		"Allocation Extent Descriptor\n");
	print_tag(fout, &aed->aed_tag);
	(void) fprintf(fout, "prev ael loc : %x laed : %x\n",
		SWAP_32(aed->aed_rev_ael), SWAP_32(aed->aed_len_aed));
}

static char *ftype[] = {
	"NON",  "USE",  "PIE",  "IE",
	"DIR",  "REG",  "BDEV", "CDEV",
	"EATT", "FIFO", "SOCK", "TERM",
	"SYML", "SDIR"
};

void
print_icb_tag(FILE *fout, struct icb_tag *itag)
{
	(void) fprintf(fout,
		"prnde : %x strat : %x param : %x max_ent %x\n",
		SWAP_32(itag->itag_prnde), SWAP_16(itag->itag_strategy),
		SWAP_16(itag->itag_param), SWAP_16(itag->itag_max_ent));
	(void) fprintf(fout,
		"ftype : %s prn : %x loc : %x flags : %x\n",
		(itag->itag_ftype >= 14) ? ftype[0] : ftype[itag->itag_ftype],
		SWAP_16(itag->itag_lb_prn),
		SWAP_32(itag->itag_lb_loc), SWAP_16(itag->itag_flags));
}


void
print_ie(FILE *fout, struct indirect_entry *ie)
{
	(void) fprintf(fout,
		"Indirect Entry\n");
	print_tag(fout, &ie->ie_tag);
	print_icb_tag(fout, &ie->ie_icb_tag);
	print_long_ad(fout, "ICB", &ie->ie_indirecticb);
}

void
print_td(FILE *fout, struct term_desc *td)
{
	(void) fprintf(fout,
		"Terminating Descriptor\n");
	print_tag(fout, &td->td_tag);
}

void
print_fe(FILE *fout, struct file_entry *fe)
{
	(void) fprintf(fout,
		"File Entry\n");
	print_tag(fout, &fe->fe_tag);
	print_icb_tag(fout, &fe->fe_icb_tag);
	(void) fprintf(fout,
		"uid : %x gid : %x perms : %x nlnk : %x\n",
		SWAP_32(fe->fe_uid), SWAP_32(fe->fe_gid),
		SWAP_32(fe->fe_perms), SWAP_16(fe->fe_lcount));
	(void) fprintf(fout,
		"rec_for : %x rec_dis : %x rec_len : %x "
		"sz : %llx blks : %llx\n",
		fe->fe_rec_for, fe->fe_rec_dis, SWAP_32(fe->fe_rec_len),
		SWAP_64(fe->fe_info_len), SWAP_64(fe->fe_lbr));
	print_tstamp(fout, "ctime ", &fe->fe_acc_time);
	print_tstamp(fout, "mtime ", &fe->fe_mod_time);
	print_tstamp(fout, "atime ", &fe->fe_attr_time);
	(void) fprintf(fout,
		"ckpoint : %x ", SWAP_32(fe->fe_ckpoint));
	print_long_ad(fout, "ICB", &fe->fe_ea_icb);
	print_regid(fout, "impl", &fe->fe_impl_id, REG_UDF_II);
	(void) fprintf(fout,
		"uniq_id : %llx len_ear : %x len_adesc %x\n",
		SWAP_64(fe->fe_uniq_id), SWAP_32(fe->fe_len_ear),
		SWAP_32(fe->fe_len_adesc));
}

void
print_pmaps(FILE *fout, uint8_t *addr, int32_t count)
{
	struct pmap_hdr *hdr;
	struct pmap_typ1 *map1;
	struct pmap_typ2 *map2;

	while (count--) {
		hdr = (struct pmap_hdr *)addr;
		switch (hdr->maph_type) {
		case 1 :
			/* LINTED */
			map1 = (struct pmap_typ1 *)hdr;
			(void) fprintf(fout, "Map type 1 ");
			(void) fprintf(fout, "VSN %x prn %x\n",
					SWAP_16(map1->map1_vsn),
					SWAP_16(map1->map1_pn));
			break;
		case 2 :
			/* LINTED */
			map2 = (struct pmap_typ2 *)hdr;
			(void) fprintf(fout, "Map type 2 ");
			(void) fprintf(fout, "VSN %x prn %x\n",
					SWAP_16(map2->map2_vsn),
					SWAP_16(map2->map2_pn));
			print_regid(fout, "Partition Type Identifier",
					&map2->map2_pti, REG_UDF_ID);
			break;
		default :
			(void) fprintf(fout, "unknown map type\n");
		}
		addr += hdr->maph_length;
	}
}



void
print_short_ad(FILE *fout, char *name, struct short_ad *sad)
{
	(void) fprintf(fout,
		"%s loc : %x len : %x\n", name,
		SWAP_32(sad->sad_ext_loc), SWAP_32(sad->sad_ext_len));
}

void
print_long_ad(FILE *fout, char *name, struct long_ad *lad)
{
	(void) fprintf(fout,
		"%s prn : %x loc : %x len : %x\n", name,
		SWAP_16(lad->lad_ext_prn), SWAP_32(lad->lad_ext_loc),
		SWAP_32(lad->lad_ext_len));
}
