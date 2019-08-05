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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include <signal.h>
#include <setjmp.h>
#include <errno.h>
#include <inttypes.h>
#include <libgen.h>
#include <locale.h>

#include <sys/param.h>
#include <sys/signal.h>
#include <sys/file.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/vnode.h>
#include <sys/mntent.h>
#include <sys/wait.h>
#include <sys/vtoc.h>
#include <sys/dkio.h>

#include <sys/fs/udf_volume.h>
#include "ud_lib.h"
#include "y.tab.h"

typedef unsigned short unicode_t;
#define	MAXNAMLEN	0x200

extern uint32_t i_number;

extern int32_t run_fsdb();

void usage();
void init_buffers();
char *getblk(u_offset_t);
int32_t parse_udfs(uint32_t);
int32_t parse_vds(uint32_t, uint32_t);
int32_t parse_part(struct part_desc *);
int32_t parse_lvd(struct log_vol_desc *);
int32_t parse_fsds();
int32_t get_vat_loc();
int32_t get_fid(uint32_t, uint8_t *, uint64_t);


char *progname;
char prompt[256] = "fsdb>";

#define	ARG_OVERRIDE	0
#define	ARG_NEW_PROMPT	1
#define	ARG_WR_ENABLED	2
#define	ARG_USAGE	3

char *subopt_v[] = {
	"o",
	"p",
	"w",
	"?",
	NULL
};
int32_t override = 0;
int32_t openflg = O_RDONLY;

#define	MAX_PARTS	10

/*
 * udp_flags
 */
#define	UDP_BITMAPS	0x00
#define	UDP_SPACETBLS	0x01

ud_handle_t udh;
int32_t fd, nparts, nmaps;
int32_t bmask, l2d, l2b;


uint16_t ricb_prn;
uint32_t ricb_loc, ricb_len;
extern int value;


int32_t
main(int argc, char *argv[])
{
	int opt, ret;
	uint32_t bsize;
	char *subopts, *optval;

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	progname = argv[0];

	while ((opt = getopt(argc, argv, "o:")) != EOF) {
		switch (opt) {
		case 'o' :
			subopts = optarg;
			while (*subopts != '\0') {
				switch (getsubopt(&subopts,
					subopt_v, &optval)) {
				case ARG_OVERRIDE :
					override = 1;
					(void) fprintf(stdout,
					gettext("error checking off\n"));
					break;
				case ARG_NEW_PROMPT :
					if (optval == NULL) {
						usage();
					}
					if (strlen(optval) > 255) {
						(void) fprintf(stdout,
						gettext("prompt should be less"
						"than 255 bytes\n"));
						exit(1);
					}
					(void) strcpy(prompt, optval);
					break;
				case ARG_WR_ENABLED :
					openflg = O_RDWR;
					break;
				case ARG_USAGE :
				default :
					usage();
				}
			}
			break;
		default :
			usage();
		}
	}

	if ((argc - optind) != 1) {	/* Should just have "special" left */
		usage();
	}

	if (ud_init(-1, &udh) != 0) {
		(void) fprintf(stderr,
		gettext("udfs labelit: cannot initialize ud_lib\n"));
		exit(1);
	}

	if ((fd = ud_open_dev(udh, argv[optind], openflg)) < 0) {
		perror("open");
		exit(1);
	}

	if ((ret = ud_fill_udfs_info(udh)) != 0) {
		return (ret);
	}

	if ((udh->udfs.flags & VALID_UDFS) == 0) {
		return (1);
	}

	bsize = udh->udfs.lbsize;
	bmask = bsize - 1;
	l2d = 0;
	while ((bsize >> l2d) > DEV_BSIZE) {
		l2d++;
	}
	l2b = l2d + 9;

	ricb_prn = udh->udfs.ricb_prn;
	ricb_loc = udh->udfs.ricb_loc;
	ricb_len = udh->udfs.ricb_len;

	value = i_number = ud_xlate_to_daddr(udh, ricb_prn, ricb_loc);

	init_buffers();

	run_fsdb();

	ud_fini(udh);
	(void) close(fd);

	return (0);
}

/*
 * usage - print usage and exit
 */
void
usage()
{
	(void) fprintf(stdout,
		gettext("usage:   %s [options] special\n"), progname);
	(void) fprintf(stdout,
		gettext("options:\n"));
	(void) fprintf(stdout,
		gettext("\t-o\tSpecify udfs filesystem sepcific options\n"));
	(void) fprintf(stdout,
		gettext("\t\tAvailable suboptions are:\n"));
	(void) fprintf(stdout,
		gettext("\t\t?\tdisplay usage\n"));
	(void) fprintf(stdout,
		gettext("\t\to\toverride some error conditions\n"));
	(void) fprintf(stdout,
		gettext("\t\tp\t\"string\" set prompt to string\n"));
	(void) fprintf(stdout,
		gettext("\t\tw\topen for write\n"));
	exit(1);
}

#define	NBUF	10
static struct lbuf {
	struct lbuf	*fwd;
	struct lbuf	*back;
	int32_t		valid;
	char		*blkaddr;
	u_offset_t	blkno;
} lbuf[NBUF], bhdr;

#define	INSERT(bp)	\
	{ \
		bp->back = &bhdr; \
		bp->fwd = bhdr.fwd; \
		bhdr.fwd->back = bp; \
		bhdr.fwd = bp; \
	}

void
init_buffers()
{
	int32_t i;
	char *addr;
	struct lbuf *bp;

	addr = malloc(NBUF * udh->udfs.lbsize);
	bhdr.fwd = bhdr.back = &bhdr;
	for (i = 0; i < NBUF; i++) {
		bp = &lbuf[i];
		bp->blkaddr = addr + i * udh->udfs.lbsize;
		bp->valid = 0;
		INSERT(bp);
	}
}

char *
getblk(u_offset_t address)
{
	u_offset_t off, block;
	struct lbuf *bp;

	off = address & ~bmask;
	block = address >> l2b;
	for (bp = bhdr.fwd; bp != &bhdr; bp = bp->fwd) {
		if (bp->valid && bp->blkno == block) {
			goto found;
		}
	}
	bp = bhdr.back;
	bp->blkno = block;
	bp->valid = 0;
	errno = 0;
	if (llseek(fd, off, SEEK_SET) != off) {
		(void) fprintf(stdout,
			gettext("Seek failed fd %x off %llx errno %x\n"),
			fd, off, errno);
		return (NULL);
	}
	errno = 0;
	if (read(fd, bp->blkaddr, udh->udfs.lbsize) != udh->udfs.lbsize) {
		(void) fprintf(stdout,
			gettext("Read failed fd %x off %llx errno %x\n"),
			fd, off, errno);
		return (NULL);
	}
	bp->valid = 1;
found:
	bp->back->fwd = bp->fwd;
	bp->fwd->back = bp->back;
	INSERT(bp);
	return (bp->blkaddr);
}


int32_t
putblk(caddr_t address)
{
	u_offset_t off;
	struct lbuf *bp;

	if (openflg == O_RDONLY) {
		(void) fprintf(stdout,
			gettext("Not run with -w flag\n"));
		return (1);
	}

	for (bp = bhdr.fwd; bp != &bhdr; bp = bp->fwd) {
		if (bp->valid && bp->blkaddr == address) {
			goto found;
		}
	}
	(void) fprintf(stdout,
		gettext("Could not find the buffer\n"));
	return (1);

found:
	off = bp->blkno << l2b;
	if (llseek(fd, off, SEEK_SET) == off) {
		if (write(fd, bp->blkaddr, udh->udfs.lbsize) ==
			udh->udfs.lbsize) {
			return (0);
		}
		(void) fprintf(stdout,
			gettext("Write failed fd %x off %llx errno %x\n"),
			fd, off, errno);
	} else {
		(void) fprintf(stdout,
			gettext("Seek failed fd %x off %llx errno %x\n"),
			fd, off, errno);
	}
	return (1);
}

void
inval_bufs()
{
	struct lbuf *bp;

	for (bp = bhdr.fwd; bp != &bhdr; bp = bp->fwd) {
		bp->valid = 0;
	}
}

/*
 * If addr == NULL then use id to print the desc
 * other wise use addr to self identify the type of desc
 */
void
print_desc(uint32_t addr, int32_t id)
{
	struct tag *tag;
	caddr_t baddr;

	/*
	 * Read the block at addr
	 * find out the type of tag
	 * and print the descriptor
	 */
	if (addr != 0) {
		if ((baddr = getblk(addr & (~bmask))) == NULL) {
			(void) fprintf(stdout,
				gettext("Could not read block %x\n"),
				addr >> l2b);
		}
		/* LINTED */
		tag = (struct tag *)(baddr + (addr & bmask));
	} else {
		switch (id) {
			case AVD :
				/* LINTED */
				if ((tag = (struct tag *)getblk(
					udh->udfs.avdp_loc << l2b)) == NULL) {
					(void) fprintf(stdout,
					gettext("Could not read AVDP\n"));
				}
				break;
			case MVDS :
			case RVDS :
			case INTS :
				{
					uint32_t i, end;

					if (id == MVDS) {
						i = udh->udfs.mvds_loc;
						end = i +
						(udh->udfs.mvds_len >> l2b);
					} else if (id == RVDS) {
						i = udh->udfs.rvds_loc;
						end = i +
						(udh->udfs.rvds_len >> l2b);
					} else {
						i = udh->udfs.lvid_loc;
						end = i +
						(udh->udfs.lvid_len >> l2b);
					}

					for (; i < end; i++) {
						print_desc(i << l2b, 0);
					}
				}
				return;
			case FSDS :
			case ROOT :
				{
					uint16_t prn;
					uint32_t i, end, block;

					if (id == FSDS) {
						prn = udh->udfs.fsds_prn;
						i = udh->udfs.fsds_loc;
						end = i +
						(udh->udfs.fsds_len >> l2b);
					} else {
						prn = ricb_prn;
						i = ricb_loc;
						end = i + (ricb_len >> l2b);
					}

					for (; i < end; i++) {
						if ((block = ud_xlate_to_daddr(
							udh, prn, i)) == 0) {
							(void) fprintf(stdout,
							gettext("Cannot xlate "
							"prn %x loc %x\n"),
							prn, i);
							continue;
						}
						print_desc(block << l2b, 0);
					}
				}
				/* FALLTHROUGH */
			default :
				return;
		}
	}

	switch (SWAP_16(tag->tag_id)) {
		case UD_PRI_VOL_DESC :
			print_pvd(stdout, (struct pri_vol_desc *)tag);
			break;
		case UD_ANCH_VOL_DESC :
			print_avd(stdout, (struct anch_vol_desc_ptr *)tag);
			break;
		case UD_VOL_DESC_PTR :
			print_vdp(stdout, (struct vol_desc_ptr *)tag);
			break;
		case UD_IMPL_USE_DESC :
			print_iuvd(stdout, (struct iuvd_desc *)tag);
			break;
		case UD_PART_DESC :
			print_part(stdout, (struct part_desc *)tag);
			break;
		case UD_LOG_VOL_DESC :
			print_lvd(stdout, (struct log_vol_desc *)tag);
			break;
		case UD_UNALL_SPA_DESC :
			print_usd(stdout, (struct unall_spc_desc *)tag);
			break;
		case UD_TERM_DESC :
			(void) fprintf(stdout, "TERM DESC\n");
			print_tag(stdout, tag);
			break;
		case UD_LOG_VOL_INT :
			print_lvid(stdout, (struct log_vol_int_desc *)tag);
			break;
		case UD_FILE_SET_DESC :
			print_fsd(stdout, udh, (struct file_set_desc *)tag);
			break;
		case UD_FILE_ID_DESC :
			print_fid(stdout, (struct file_id *)tag);
			break;
		case UD_ALLOC_EXT_DESC :
			print_aed(stdout, (struct alloc_ext_desc *)tag);
			break;
		case UD_INDIRECT_ENT :
			print_ie(stdout, (struct indirect_entry *)tag);
			break;
		case UD_TERMINAL_ENT :
			print_td(stdout, (struct term_desc *)tag);
			break;
		case UD_FILE_ENTRY :
			print_fe(stdout, (struct file_entry *)tag);
			break;
		case UD_EXT_ATTR_HDR :
		case UD_UNALL_SPA_ENT :
		case UD_SPA_BMAP_DESC :
		case UD_PART_INT_DESC :
		case UD_EXT_FILE_ENT :
			break;
		default :
			(void) fprintf(stdout,
				gettext("unknown descriptor\n"));
			print_tag(stdout, tag);
			break;
	}
}

void
set_file(int32_t id, uint32_t iloc, uint64_t value)
{
	uint8_t i8;
	uint16_t i16;
	uint32_t i32, block, ea_len, ea_off;
	uint64_t i64;
	struct file_entry *fe;
	struct dev_spec_ear *ds;
	struct attr_hdr *ah;
	struct ext_attr_hdr *eah;

	/* LINTED */
	if ((fe = (struct file_entry *)getblk(iloc)) == NULL) {
		return;
	}
	if (ud_verify_tag(udh, &fe->fe_tag, UD_FILE_ENTRY,
			SWAP_32(fe->fe_tag.tag_loc), 1, 1) != 0) {
		return;
	}
	i8 = (uint8_t)value;
	i16 = SWAP_16(((uint16_t)value));
	i32 = SWAP_32(((uint32_t)value));
	i64 = SWAP_64(value);
	switch (id) {
		case ATTZ :
			fe->fe_acc_time.ts_tzone = i16;
			break;
		case ATYE  :
			fe->fe_acc_time.ts_year = i16;
			break;
		case ATMO  :
			fe->fe_acc_time.ts_month = i8;
			break;
		case ATDA  :
			fe->fe_acc_time.ts_day = i8;
			break;
		case ATHO  :
			fe->fe_acc_time.ts_hour = i8;
			break;
		case ATMI  :
			fe->fe_acc_time.ts_min = i8;
			break;
		case ATSE  :
			fe->fe_acc_time.ts_sec = i8;
			break;
		case ATCE  :
			fe->fe_acc_time.ts_csec = i8;
			break;
		case ATHU  :
			fe->fe_acc_time.ts_husec = i8;
			break;
		case ATMIC :
			fe->fe_acc_time.ts_usec = i8;
			break;
		case CTTZ  :
			fe->fe_attr_time.ts_tzone = i16;
			break;
		case CTYE  :
			fe->fe_attr_time.ts_year = i16;
			break;
		case CTMO  :
			fe->fe_attr_time.ts_month = i8;
			break;
		case CTDA  :
			fe->fe_attr_time.ts_day = i8;
			break;
		case CTHO  :
			fe->fe_attr_time.ts_hour = i8;
			break;
		case CTMI  :
			fe->fe_attr_time.ts_min = i8;
			break;
		case CTSE  :
			fe->fe_attr_time.ts_sec = i8;
			break;
		case CTCE  :
			fe->fe_attr_time.ts_csec = i8;
			break;
		case CTHU  :
			fe->fe_attr_time.ts_husec = i8;
			break;
		case CTMIC :
			fe->fe_attr_time.ts_usec = i8;
			break;
		case MTTZ  :
			fe->fe_mod_time.ts_tzone = i16;
			break;
		case MTYE  :
			fe->fe_mod_time.ts_year = i16;
			break;
		case MTMO  :
			fe->fe_mod_time.ts_month = i8;
			break;
		case MTDA  :
			fe->fe_mod_time.ts_day = i8;
			break;
		case MTHO  :
			fe->fe_mod_time.ts_hour = i8;
			break;
		case MTMI  :
			fe->fe_mod_time.ts_min = i8;
			break;
		case MTSE  :
			fe->fe_mod_time.ts_sec = i8;
			break;
		case MTCE  :
			fe->fe_mod_time.ts_csec = i8;
			break;
		case MTHU  :
			fe->fe_mod_time.ts_husec = i8;
			break;
		case MTMIC :
			fe->fe_mod_time.ts_usec = i8;
			break;
		case GID  :
			fe->fe_gid = i32;
			break;
		case LN  :
			fe->fe_lcount = i16;
			break;
		case MD  :
			fe->fe_perms = i32;
			break;
		case MAJ  :
		case MIO  :
			if ((fe->fe_icb_tag.itag_ftype != VBLK) &&
				(fe->fe_icb_tag.itag_ftype != VCHR)) {
				(void) fprintf(stdout,
					gettext("Not a device\n"));
				break;
			}
			/* LINTED */
			eah = (struct ext_attr_hdr *)fe->fe_spec;
			ea_off = SWAP_32(eah->eah_ial);
			ea_len = SWAP_32(fe->fe_len_ear);
			block = SWAP_32(eah->eah_tag.tag_loc);
			if (ea_len && (ud_verify_tag(udh, &eah->eah_tag,
				UD_EXT_ATTR_HDR, block, 1, 1) == 0)) {
				while (ea_off < ea_len) {
					/* LINTED */
					ah = (struct attr_hdr *)
						&fe->fe_spec[ea_off];
					if ((ah->ahdr_atype == SWAP_32(12)) &&
						(ah->ahdr_astype == 1)) {

						ds = (struct dev_spec_ear *)ah;
						if (id == MAJ) {
							ds->ds_major_id = i32;
						} else {
							ds->ds_minor_id = i32;
						}
						ud_make_tag(udh, &eah->eah_tag,
							UD_EXT_ATTR_HDR, block,
						eah->eah_tag.tag_crc_len);
						break;
					}
				}
			}
			(void) fprintf(stdout,
			gettext("does not have a Device Specification EA\n"));
			break;
		case NM  :
			break;
		case SZ  :
			fe->fe_info_len = i64;
			break;
		case UID  :
			fe->fe_uid = i32;
			break;
		case UNIQ :
			fe->fe_uniq_id = i32;
			break;
		default :
			(void) fprintf(stdout,
				gettext("Unknown set\n"));
	}
	ud_make_tag(udh, &fe->fe_tag, UD_FILE_ENTRY,
		SWAP_32(fe->fe_tag.tag_loc), fe->fe_tag.tag_crc_len);
	(void) putblk((caddr_t)fe);
}

caddr_t
verify_inode(uint32_t addr, uint32_t type)
{
	struct file_entry *fe;
	struct tag *tag;

	/* LINTED */
	if ((tag = (struct tag *)getblk(addr & (~bmask))) == NULL) {
		(void) fprintf(stdout,
			gettext("Could not read block %x\n"),
			addr >> l2b);
	} else {
		if (ud_verify_tag(udh, tag, UD_FILE_ENTRY,
			addr >> l2b, 0, 1) != 0) {
			(void) fprintf(stdout,
				gettext("Not a file entry(inode) at %x\n"),
				addr >> l2b);
		} else {
			if (ud_verify_tag(udh, tag, UD_FILE_ENTRY,
				SWAP_32(tag->tag_loc), 1, 1) != 0) {
				(void) fprintf(stdout,
					gettext("CRC failed\n"));
			} else {
				fe = (struct file_entry *)tag;
				if ((type == 0) ||
					(type == fe->fe_icb_tag.itag_ftype)) {
					return ((caddr_t)tag);
				}
			}
		}
	}
	return (0);
}

void
print_inode(uint32_t addr)
{
	if (verify_inode(addr, 0) != NULL) {
		print_desc(addr, 0);
	}
}

int32_t
verify_dent(uint32_t i_addr, uint32_t nent)
{
	uint32_t ent = 0;
	uint64_t off = 0;
	uint8_t buf[1024];
	struct file_id *fid;

	/* LINTED */
	fid = (struct file_id *)buf;

	if (verify_inode(i_addr, 4) == 0) {
		(void) fprintf(stdout,
			gettext("Inode is not a directory\n"));
		return (1);
	}

	while (get_fid(i_addr >> l2b, buf, off) == 0) {
		off += FID_LEN(fid);
		if (ent == nent) {
			return (0);
		}
		ent++;
	}
	(void) fprintf(stdout,
		gettext("Reached EOF\n"));
	return (1);
}

void
print_dent(uint32_t i_addr, uint32_t nent)
{
	uint32_t ent = 0;
	uint64_t off = 0;
	uint8_t buf[1024];
	struct file_id *fid;

	/* LINTED */
	fid = (struct file_id *)buf;

	if (verify_dent(i_addr, nent) == 0) {
		while (get_fid(i_addr >> l2b, buf, off) == 0) {
			off += FID_LEN(fid);
			if (ent == nent) {
				print_fid(stdout, fid);
				return;
			}
			ent++;
		}
	}
}

uint32_t in;
uint32_t de_count, ie_count;
struct ext {
	uint16_t prn;
	uint16_t flags;
	uint32_t blkno;
	uint32_t len;
} *de, *ie;

int32_t
get_blkno(uint32_t inode, uint32_t *blkno, uint64_t off)
{
	struct file_entry *fe;
	int32_t i, d, nent;
	uint16_t prn, flags, elen;
	uint32_t desc_type, bno, len;
	struct short_ad *sad;
	struct long_ad *lad;
	uint64_t b_off, e_off;

	if (inode != in) {
		/* LINTED */
		if ((fe = (struct file_entry *)
				getblk(inode << l2b)) == NULL) {
			(void) fprintf(stdout,
				gettext("Could not read block %x\n"),
				off & (~bmask));
			return (1);
		}
		desc_type = SWAP_16(fe->fe_icb_tag.itag_flags) & 0x7;
		if (desc_type == ICB_FLAG_SHORT_AD) {
			elen = sizeof (struct short_ad);
			/* LINTED */
			sad = (struct short_ad *)
				(fe->fe_spec + SWAP_32(fe->fe_len_ear));
		} else if (desc_type == ICB_FLAG_LONG_AD) {
			elen = sizeof (struct long_ad);
			/* LINTED */
			lad = (struct long_ad *)
				(fe->fe_spec + SWAP_32(fe->fe_len_ear));
		} else if (desc_type == ICB_FLAG_ONE_AD) {
			*blkno = inode;
			return (0);
		} else {
			/* This cannot happen return */
			return (EINVAL);
		}

		nent = SWAP_32(fe->fe_len_adesc) / elen;
		de = malloc(nent * sizeof (struct ext));
		if (de == NULL) {
			(void) fprintf(stdout,
				gettext("could not allocate memeory\n"));
			return (1);
		}
		in = inode;
		de_count = nent;
		for (d = 0, i = 0; i < nent; i++) {
			if (desc_type == ICB_FLAG_SHORT_AD) {
				prn = 0;
				bno = SWAP_32(sad->sad_ext_loc);
				len = SWAP_32(sad->sad_ext_len);
			} else if (desc_type == ICB_FLAG_LONG_AD) {
				prn = SWAP_16(lad->lad_ext_prn);
				bno = SWAP_32(lad->lad_ext_loc);
				len = SWAP_32(lad->lad_ext_len);
			}
			flags = len >> 30;
			if (flags == 0x3) {
				(void) fprintf(stdout,
					gettext("Handle IE\n"));
			} else {
				de[d].prn = prn;
				de[d].flags = flags;
				de[d].blkno = bno;
				de[d].len = len & 0x3FFFFFFF;
				d++;
			}
		}
	}

	b_off = 0;
	for (i = 0; i < de_count; i++) {
		e_off = b_off + de[i].len;
		if (off < e_off) {
			bno = de[i].blkno + ((off - b_off) >> l2b);
			if ((*blkno = ud_xlate_to_daddr(
					udh, de[i].prn, bno)) == 0) {
				return (1);
			}
			return (0);
		}
		b_off = e_off;
	}
	return (1);
}

/*
 * assume the buffer is big enough
 * for the entire request
 */
int32_t
read_file(uint32_t inode, uint8_t *buf, uint32_t count, uint64_t off)
{
	caddr_t addr;
	uint32_t bno, tcount;


	while (count) {
		if (get_blkno(inode, &bno, off) != 0) {
			return (1);
		}
		if ((addr = getblk(bno << l2b)) == NULL) {
			return (1);
		}
		if (bno == inode) {
			struct file_entry *fe;
			/*
			 * embedded file
			 */
			/* LINTED */
			fe = (struct file_entry *)addr;
			addr += 0xB0 + SWAP_32(fe->fe_len_ear);
			if (off >= SWAP_64(fe->fe_info_len)) {
				return (1);
			}
		}
		tcount = udh->udfs.lbsize - (off & bmask);
		if (tcount > count) {
			tcount = count;
		}
		addr += off & bmask;
		(void) memcpy(buf, addr, tcount);
		count -= tcount;
		buf += tcount;
		off += tcount;
	}
	return (0);
}

int32_t
get_fid(uint32_t inode, uint8_t *buf, uint64_t off)
{
	struct file_id *fid;

	/* LINTED */
	fid = (struct file_id *)buf;
	if ((read_file(inode, buf, sizeof (struct file_id), off)) != 0) {
		return (1);
	}

	if (ud_verify_tag(udh, &fid->fid_tag, UD_FILE_ID_DESC, 0, 0, 1) != 0) {
		(void) fprintf(stdout,
			gettext("file_id tag does not verify off %llx\n"),
			off);
		return (1);
	}

	if ((read_file(inode, buf, FID_LEN(fid), off)) != 0) {
		return (1);
	}

	return (0);
}

/*
 * Path is absolute path
 */
int32_t
inode_from_path(char *path, uint32_t *in, uint8_t *fl)
{
	char dname[1024];
	char fname[256];
	int32_t err;
	uint32_t dinode;
	struct tag *tag;
	uint8_t flags;

	uint8_t buf[1024];
	uint64_t off;
	struct file_id *fid;
	uint8_t *addr;

	if (strcmp(path, "/") == 0) {
		*fl = FID_DIR;
		if ((*in = ud_xlate_to_daddr(udh, ricb_prn, ricb_loc)) == 0) {
			return (1);
		}
		return (0);
	}

	(void) strcpy(dname, path);
	(void) strcpy(fname, basename(dname));
	(void) dirname(dname);

	if ((err = inode_from_path(dname, &dinode, &flags))  != 0) {
		return (1);
	}


	/*
	 * Check if dname is a directory
	 */
	if ((flags & FID_DIR) == 0) {
		(void) fprintf(stdout,
			gettext("Path %s is not a directory\n"), path);
	}

	/*
	 * Search for the fname in the directory now
	 */


	off = 0;
	/* LINTED */
	fid = (struct file_id *)buf;
	while (get_fid(dinode, buf, off) == 0) {
		off += FID_LEN(fid);
		if (fid->fid_flags & FID_DELETED) {
			continue;
		}
		addr = &fid->fid_spec[SWAP_16((fid)->fid_iulen) + 1];
		if (fid->fid_flags & FID_PARENT) {
			addr[0] = '.';
			addr[1] = '.';
			addr[2] = '\0';
		} else {
			addr[fid->fid_idlen] = '\0';
		}
		if (strcmp((caddr_t)addr, fname) == 0) {
			*fl = fid->fid_flags;
			if ((*in = ud_xlate_to_daddr(udh,
				SWAP_16(fid->fid_icb.lad_ext_prn),
				SWAP_32(fid->fid_icb.lad_ext_loc))) == 0) {
				return (1);
			}
			/* LINTED */
			if ((tag = (struct tag *)getblk(*in << l2b)) == NULL) {
				(void) fprintf(stdout,
					gettext("Could not read block %x\n"),
					*in);
				return (1);
			}
			if (ud_verify_tag(udh, tag, UD_FILE_ENTRY,
					0, 0, 1) != 0) {
				(void) fprintf(stdout,
					gettext("Not a file entry(inode)"
					" at %x\n"), *in);
				return (1);
			}
			if (ud_verify_tag(udh, tag, UD_FILE_ENTRY,
					SWAP_32(tag->tag_loc), 1, 1) != 0) {
				(void) fprintf(stdout,
					gettext("CRC failed\n"));
				return (1);
			}

			return (0);
		}
	}
	return (err);
}

struct recu_dir {
	struct recu_dir *next;
	uint32_t inode;
	char *nm;
};

void
list(char *nm, uint32_t in, uint32_t fl)
{
	uint8_t buf[1024];
	uint64_t off;
	struct file_id *fid;
	struct recu_dir *rd, *erd, *temp;
	uint32_t iloc;

	rd = erd = temp = NULL;
	if (verify_inode(in << l2b, 4) == 0) {
		(void) fprintf(stdout,
			gettext("Inode is not a directory\n"));
		return;
	}

	if (fl & 2) {
		(void) printf("\n");
		if (fl & 1) {
			(void) fprintf(stdout,
				gettext("i#: %x\t"), in);
		}
		(void) printf("%s\n", nm);
	}

	off = 0;
	/* LINTED */
	fid = (struct file_id *)buf;
	while (get_fid(in, buf, off) == 0) {
		off += FID_LEN(fid);
		if (fid->fid_flags & FID_DELETED) {
			continue;
		}
		iloc = ud_xlate_to_daddr(udh, SWAP_16(fid->fid_icb.lad_ext_prn),
				SWAP_32(fid->fid_icb.lad_ext_loc));
		if (fl & 1) {
			(void) fprintf(stdout,
				gettext("i#: %x\t"), iloc);
		}
		if (fid->fid_flags & FID_PARENT) {
			(void) fprintf(stdout,
				gettext("..\n"));
		} else {
			int32_t i;
			uint8_t *addr;

			addr = &fid->fid_spec[SWAP_16((fid)->fid_iulen) + 1];
			for (i = 0; i < fid->fid_idlen - 1; i++)
				(void) fprintf(stdout, "%c", addr[i]);
			(void) fprintf(stdout, "\n");
			if ((fid->fid_flags & FID_DIR) &&
				(fl & 2)) {
				temp = (struct recu_dir *)
					malloc(sizeof (struct recu_dir));
				if (temp == NULL) {
					(void) fprintf(stdout,
					gettext("Could not allocate memory\n"));
				} else {
					temp->next = NULL;
					temp->inode = iloc;
					temp->nm = malloc(strlen(nm) + 1 +
						fid->fid_idlen + 1);
					if (temp->nm != NULL) {
						(void) strcpy(temp->nm, nm);
						(void) strcat(temp->nm, "/");
						(void) strncat(temp->nm,
							(char *)addr,
							fid->fid_idlen);
					}
					if (rd == NULL) {
						erd = rd = temp;
					} else {
						erd->next = temp;
						erd = temp;
					}
				}
			}
		}
	}

	while (rd != NULL) {
		if (rd->nm != NULL) {
			list(rd->nm, rd->inode, fl);
		} else {
			list(".", rd->inode, fl);
		}
		temp = rd;
		rd = rd->next;
		if (temp->nm) {
			free(temp->nm);
		}
		free(temp);
	}
}

void
fill_pattern(uint32_t addr, uint32_t count, char *pattern)
{
	uint32_t beg, end, soff, lcount;
	int32_t len = strlen(pattern);
	caddr_t buf, p;

	if (openflg == O_RDONLY) {
		(void) fprintf(stdout,
			gettext("Not run with -w flag\n"));
		return;
	}

	if (count == 0) {
		count = 1;
	}
	beg = addr;
	end = addr + count * len;
	soff = beg & (~bmask);
	lcount = ((end + bmask) & (~bmask)) - soff;

	inval_bufs();

	buf = malloc(lcount);

	if (llseek(fd, soff, SEEK_SET) != soff) {
		(void) fprintf(stdout,
			gettext("Seek failed fd %x off %llx errno %x\n"),
			fd, soff, errno);
		goto end;
	}

	if (read(fd, buf, lcount) != lcount) {
		(void) fprintf(stdout,
			gettext("Read failed fd %x off %llx errno %x\n"),
			fd, soff, errno);
		goto end;
	}

	p = buf + (addr & bmask);
	while (count--) {
		(void) strncpy(p, pattern, len);
		p += len;
	}

	if (write(fd, buf, lcount) != lcount) {
		(void) fprintf(stdout,
			gettext("Write failed fd %x off %llx errno %x\n"),
			fd, soff, errno);
		goto end;
	}
end:
	free(buf);
}

void
dump_disk(uint32_t addr, uint32_t count, char *format)
{
	uint32_t beg, end, soff, lcount;
	int32_t len, prperline, n;
	uint8_t *buf, *p;
	uint16_t *p_16;
	uint32_t *p_32;

	if (strlen(format) != 1) {
		(void) fprintf(stdout,
			gettext("Invalid command\n"));
		return;
	}
	if (count == 0) {
		count = 1;
	}
	switch (*format) {
		case 'b' :
			/* FALLTHROUGH */
		case 'c' :
			/* FALLTHROUGH */
		case 'd' :
			/* FALLTHROUGH */
		case 'o' :
			len = 1;
			prperline = 16;
			break;
		case 'x' :
			len = 2;
			prperline = 8;
			break;
		case 'D' :
			/* FALLTHROUGH */
		case 'O' :
			/* FALLTHROUGH */
		case 'X' :
			len = 4;
			prperline = 4;
			break;
		default :
			(void) fprintf(stdout,
				gettext("Invalid format\n"));
			return;
	}

	beg = addr;
	end = addr + count * len;
	soff = beg & (~bmask);
	lcount = ((end + bmask) & (~bmask)) - soff;

	inval_bufs();

	buf = malloc(lcount);
	if (llseek(fd, soff, SEEK_SET) != soff) {
		(void) fprintf(stdout,
			gettext("Seek failed fd %x off %llx errno %x\n"),
			fd, soff, errno);
		goto end;
	}

	if (read(fd, buf, lcount) != lcount) {
		(void) fprintf(stdout,
			gettext("Read failed fd %x off %llx errno %x\n"),
			fd, soff, errno);
		goto end;
	}
	p = buf + (addr & bmask);
	/* LINTED */
	p_16 = (uint16_t *)p;
	/* LINTED */
	p_32 = (uint32_t *)p;
	n = 0;
	while (n < count) {
		switch (*format) {
			case 'b' :
				(void) fprintf(stdout,
					"%4x ", *((uint8_t *)p));
				break;
			case 'c' :
				(void) fprintf(stdout,
					"%4c ", *((uint8_t *)p));
				break;
			case 'd' :
				(void) fprintf(stdout,
					"%4d ", *((uint8_t *)p));
				break;
			case 'o' :
				(void) fprintf(stdout,
					"%4o ", *((uint8_t *)p));
				break;
			case 'x' :
				(void) fprintf(stdout,
					"%8x ", *p_16);
				break;
			case 'D' :
				(void) fprintf(stdout,
					"%16d ", *p_32);
				break;
			case 'O' :
				(void) fprintf(stdout,
					"%16o ", *p_32);
				break;
			case 'X' :
				(void) fprintf(stdout,
					"%16x ", *p_32);
				break;
		}
		p += len;
		n++;
		if ((n % prperline) == 0) {
			(void) fprintf(stdout, "\n");
		}
	}
	if (n % prperline) {
		(void) fprintf(stdout, "\n");
	}
end:
	free(buf);
}

void
find_it(char *dir, char *name, uint32_t in, uint32_t fl)
{
	uint8_t buf[1024], *addr;
	uint64_t off;
	struct file_id *fid;
	uint32_t iloc, d_in;
	uint8_t d_fl;
	struct recu_dir *rd, *erd, *temp;

	rd = erd = temp = NULL;

	if (inode_from_path(dir, &d_in, &d_fl) != 0) {
		(void) fprintf(stdout,
			gettext("Could not find directory %s"), dir);
		return;
	}

	if ((d_fl & FID_DIR) == 0) {
		(void) fprintf(stdout,
			gettext("Path %s is not a directory\n"), dir);
		return;
	}

	if (verify_inode(d_in << l2b, 4) == 0) {
		(void) fprintf(stdout,
			gettext("Inode is not a directory\n"));
		return;
	}

	off = 0;
	/* LINTED */
	fid = (struct file_id *)buf;
	while (get_fid(d_in, buf, off) == 0) {
		off += FID_LEN(fid);
		if ((fid->fid_flags & FID_DELETED) ||
			(fid->fid_flags & FID_PARENT)) {
			continue;
		}

		iloc = ud_xlate_to_daddr(udh, SWAP_16(fid->fid_icb.lad_ext_prn),
				SWAP_32(fid->fid_icb.lad_ext_loc));
		addr = &fid->fid_spec[SWAP_16((fid)->fid_iulen) + 1];
		if (((fl & 4) && (in == iloc)) ||
		((fl & 2) && (strcmp(name, (char *)addr) == 0))) {
			(void) printf("%s %x %s\n", dir, iloc, addr);
		}

		if (fid->fid_flags & FID_DIR) {
			temp = (struct recu_dir *)
				malloc(sizeof (struct recu_dir));
			if (temp == NULL) {
				(void) fprintf(stdout,
				gettext("Could not allocate memory\n"));
			} else {
				temp->next = NULL;
				temp->inode = iloc;
				temp->nm = malloc(strlen(dir) + 1 +
					fid->fid_idlen + 1);
				if (temp->nm != NULL) {
					(void) strcpy(temp->nm, dir);
					(void) strcat(temp->nm, "/");
					(void) strncat(temp->nm, (char *)addr,
						fid->fid_idlen);
				} else {
					(void) fprintf(stdout, gettext(
					"Could not allocate memory\n"));
				}
				if (rd == NULL) {
					erd = rd = temp;
				} else {
					erd->next = temp;
					erd = temp;
				}
			}
		}
	}

	while (rd != NULL) {
		if (rd->nm != NULL) {
			find_it(rd->nm, name, in, fl);
		}
		temp = rd;
		rd = rd->next;
		if (temp->nm) {
			free(temp->nm);
		}
		free(temp);
	}
}
