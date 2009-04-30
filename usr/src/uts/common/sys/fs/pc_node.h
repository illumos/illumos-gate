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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_FS_PC_NODE_H
#define	_SYS_FS_PC_NODE_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <vm/page.h>
#include <sys/buf.h>
#include <sys/vnode.h>

#ifdef _KERNEL
#include <sys/vfs_opreg.h>
#endif

/*
 * This overlays the fid structure (see vfs.h)
 *
 * 10 bytes max.
 */
struct pc_fid {
	ushort_t	pcfid_len;
	uint32_t	pcfid_block;	/* dblock containing directory entry */
	uint16_t	pcfid_offset;	/* offset within block of entry */
	uint16_t	pcfid_ctime;	/* creation time of entry (~= i_gen) */
};

struct pcnode {
	struct pcnode	*pc_forw;	/* active list ptrs, must be first */
	struct pcnode	*pc_back;
	int pc_flags;			/* see below */
	struct vnode	*pc_vn;		/* vnode for pcnode */
	uint_t pc_size;			/* size of file */
	pc_cluster32_t	pc_scluster;	/* starting cluster of file */
	daddr_t pc_eblkno;		/* disk blkno for entry */
	int pc_eoffset;			/* offset in disk block of entry */
	struct pcdir pc_entry;		/* directory entry of file */
	pc_cluster32_t	pc_lcluster;	/* last cluster visited */
	daddr_t		pc_lindex;	/* index of last cluster visited */
};

/*
 * flags
 */
#define	PC_MOD		0x01		/* file data has been modified */
#define	PC_CHG		0x02		/* node data has been changed */
#define	PC_INVAL	0x04		/* node is invalid */
#define	PC_EXTERNAL	0x08		/* vnode ref is held externally */
#define	PC_ACC		0x10		/* file data has been accessed */
#define	PC_RELEHOLD	0x80		/* node is being released */

#define	PCTOV(PCP)	((PCP)->pc_vn)
#define	VTOPC(VP)	((struct pcnode *)((VP)->v_data))

/*
 * Make a unique integer for a file
 */
#define	pc_makenodeid(BN, OFF, ATTR, SCLUSTER, ENTPS) \
	(ino_t)((ATTR) & PCA_DIR ? \
		(uint32_t)(-(SCLUSTER) - 1) : \
		((BN) * (ENTPS)) + ((OFF) / sizeof (struct pcdir)))

#define	NPCHASH 1

#if NPCHASH == 1
#define	PCFHASH(FSP, BN, O)	0
#define	PCDHASH(FSP, SC)	0
#else
#define	PCFHASH(FSP, BN, O)	(((unsigned)FSP + BN + O) % NPCHASH)
#define	PCDHASH(FSP, SC)	(((unsigned)FSP + SC) % NPCHASH)
#endif

struct pchead {
	struct pcnode *pch_forw;
	struct pcnode *pch_back;
};

/*
 * pcnode file and directory operations vectors
 */
extern struct vnodeops *pcfs_fvnodeops;
extern struct vnodeops *pcfs_dvnodeops;

#ifdef _KERNEL
extern const struct fs_operation_def pcfs_fvnodeops_template[];
extern const struct fs_operation_def pcfs_dvnodeops_template[];
#endif

extern struct pchead pcfhead[];
extern struct pchead pcdhead[];

/*
 * pcnode routines
 */
extern void pc_init(void);
extern struct pcnode *pc_getnode(struct pcfs *, daddr_t, int, struct pcdir *);
extern void pc_rele(struct pcnode *);
extern void pc_mark_mod(struct pcfs *, struct pcnode *);
extern void pc_mark_acc(struct pcfs *, struct pcnode *);
extern int pc_nodesync(struct pcnode *);
extern int pc_nodeupdate(struct pcnode *);
extern int pc_bmap(struct pcnode *, daddr_t, daddr_t *, uint_t *);

extern int pc_balloc(struct pcnode *, daddr_t, int, daddr_t *);
extern int pc_bfree(struct pcnode *, pc_cluster32_t);
extern int pc_verify(struct pcfs *);
extern void pc_diskchanged(struct pcfs *);
extern void pc_mark_irrecov(struct pcfs *);

extern int pc_dirlook(struct pcnode *, char *, struct pcnode **);
extern int pc_direnter(struct pcnode *, char *, struct vattr *,
	struct pcnode **);
extern int pc_dirremove(struct pcnode *, char *, struct vnode *, enum vtype,
		caller_context_t *);
extern int pc_rename(struct pcnode *, struct pcnode *, char *, char *,
		caller_context_t *);
extern int pc_blkatoff(struct pcnode *, offset_t, struct buf **,
	struct pcdir **);
extern int pc_truncate(struct pcnode *, uint_t);
extern int pc_fileclsize(struct pcfs *, pc_cluster32_t, pc_cluster32_t *);
extern int pcfs_putapage(struct vnode *, page_t *, u_offset_t *, size_t *, int,
	struct cred *);
extern void pc_badfs(struct pcfs *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_PC_NODE_H */
