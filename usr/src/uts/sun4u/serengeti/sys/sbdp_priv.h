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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SBDP_PRIV_H
#define	_SBDP_PRIV_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/sbd.h>
#include <sys/sbdp_mbox.h>
#include <sys/conf.h>
#include <sys/ddi_impldefs.h>
#include <sys/serengeti.h>

#ifdef DEBUG
#define	SBDPDBG_STATE	0x00000001
#define	SBDPDBG_QR	0x00000002
#define	SBDPDBG_CPU	0x00000004
#define	SBDPDBG_MEM	0x00000008
#define	SBDPDBG_IO	0x00000010
#define	SBDPDBG_MBOX	0x00000020
#define	SBDPDBG_ERR	0x00000040
#define	SBDPDBG_MISC	0x00000080
#define	SBDPDBG_FUNC	0x00000100

extern uint_t sbdp_debug;

#define	SBDP_DBG_ALL	if (sbdp_debug)				prom_printf
#define	SBDP_DBG_STATE	if (sbdp_debug & SBDPDBG_STATE)		prom_printf
#define	SBDP_DBG_QR	if (sbdp_debug & SBDPDBG_QR)		prom_printf
#define	SBDP_DBG_CPU	if (sbdp_debug & SBDPDBG_CPU)		prom_printf
#define	SBDP_DBG_MEM	if (sbdp_debug & SBDPDBG_MEM)		prom_printf
#define	SBDP_DBG_IO	if (sbdp_debug & SBDPDBG_IO)		prom_printf
#define	SBDP_DBG_MBOX	if (sbdp_debug & SBDPDBG_MBOX)		prom_printf
#define	SBDP_DBG_ERR	if (sbdp_debug & SBDPDBG_ERR)		prom_printf
#define	SBDP_DBG_MISC	if (sbdp_debug & SBDPDBG_MISC)		prom_printf
#define	SBDP_DBG_FUNC	if (sbdp_debug & SBDPDBG_FUNC)		prom_printf

#else /* DEBUG */

#define	SBDP_DBG_ALL
#define	SBDP_DBG_STATE
#define	SBDP_DBG_QR
#define	SBDP_DBG_CPU
#define	SBDP_DBG_MEM
#define	SBDP_DBG_IO
#define	SBDP_DBG_MBOX
#define	SBDP_DBG_ERR
#define	SBDP_DBG_MISC
#define	SBDP_DBG_FUNC
#endif /* DEBUG */

#define	PORTID_BAD	-1
#define	OBP_PORTID	"portid"
#define	SBDP_MAX_BOARDS  plat_max_boards()
#define	SBDP_MAX_MEM_NODES_PER_BOARD	4
#define	SBDP_MAX_NODES	32
#define	SBDP_MAX_WNODES	16

/*
 * CPU present macros
 */
#define	SBDP_SET_CPU_PRESENT(bdp, unit)\
			((bdp)->cpus_present |= (1 << (unit)))

#define	SBDP_IS_CPU_PRESENT(bdp, unit)\
			(((bdp)->cpus_present & (1 << (unit))) != 0)

/*
 * CPU reset macros
 */
#define	SBDP_SET_CPU_IN_RESET(bdp, unit)\
			((bdp)->cpus_in_reset |= (1 << (unit)))
#define	SBDP_UNSET_CPU_IN_RESET(bdp, unit)\
			((bdp)->cpus_in_reset &= ~(1 << (unit)))
#define	SBDP_IS_CPU_IN_RESET(bdp, unit)\
			(((bdp)->cpus_in_reset & (1 << (unit))) != 0)
#define	SBDP_SET_ALL_CPUS_IN_RESET(bdp)\
			((bdp)->cpus_in_reset |= 0xf)
#define	SBDP_UNSET_ALL_CPUS_IN_RESET(bdp)\
			((bdp)->cpus_in_reset = 0x0)
#define	SBDP_ALL_CPUS	-1

/*
 * These definitions come from the SC. Should the SC change them
 * then we need to changed them
 */
#define	SBDP_DIAG_OFF		0x00
#define	SBDP_DIAG_INIT		0x07
#define	SBDP_DIAG_QUICK		0x10
#define	SBDP_DIAG_MIN		0x20
#define	SBDP_DIAG_DEFAULT	0x40
#define	SBDP_DIAG_MEM1		0x60
#define	SBDP_DIAG_MEM2		0x7f
#define	SBDP_DIAG_NVCI		0xffff	/* Use stored value in nvci */

int		*slices;

#define	SBDP_INIT_PLATOPTS	(uint_t)-1
#define	SBDP_PLATFORM_OPTS(s_platopts)  ((s_platopts) = SBDP_INIT_PLATOPTS, \
		SBD_SET_PLATOPTS(SBD_CMD_TEST, (s_platopts)), \
		SBD_SET_PLATOPTS(SBD_CMD_PASSTHRU, (s_platopts)))

typedef struct sbdp_bank {
	int			id;
	ushort_t		valid;
	ushort_t		uk;
	uint_t			um;
	uchar_t			lk;
	uchar_t			lm;
	struct sbdp_bank	*bd_next;	/* in the board */
	struct sbdp_bank	*seg_next;	/* in the segment */
} sbdp_bank_t;

typedef struct sbdp_segs {
	int			id;
	int			intlv;	/* interleave for this segment */
	uint64_t		base;	/* base address for this segment */
	uint64_t		size;	/* size of this segment */
	int			nbanks;	/* number of banks in this segment */
	sbdp_bank_t		*banks;	/* pointer to the banks of this seg */
	struct sbdp_segs	*next;
} sbdp_seg_t;

typedef struct {
	int		bd;
	int		wnode;
	uint64_t	bpa;	/* base physical addr for this board */
	int		nnum;	/* number of nodes */
	struct memlist	*ml;	/* memlist for this board */
	pnode_t		nodes[SBDP_MAX_MEM_NODES_PER_BOARD];
	kmutex_t	bd_mutex; /* mutex for this board */
	show_board_t	*bd_sc;	/* info obtained from the SC */
	int		valid_cp; /* Is this a valid copy of show_board */
	sbdp_bank_t	*banks;	/* Banks for this board */
	int		cpus_in_reset;
	int		cpus_present;
} sbdp_bd_t;

typedef struct sbdp_wnode {
	int			wnode;	/* wildcat node */
	int			nbds;	/* number of bds for this node */
	sbdp_bd_t		*bds;	/* pointer to the list of bds */
	struct sbdp_wnode	*next;	/* ptr to nex wnode */
	struct sbdp_wnode	*prev;	/* ptr to prev node */
} sbdp_wnode_t;

typedef struct {
	uint_t  regspec_addr_hi;
	uint_t  regspec_addr_lo;
	uint_t  regspec_size_hi;
	uint_t  regspec_size_lo;
} regspace_t;

/*
 * Suspend states used internally by sbdp_suspend and
 * sbdp_resume
 */
typedef enum sbd_suspend_state {
	SBDP_SRSTATE_BEGIN = 0,
	SBDP_SRSTATE_USER,
	SBDP_SRSTATE_DRIVER,
	SBDP_SRSTATE_FULL
} suspend_state_t;

/*
 * specific suspend/resume interface handle
 */
typedef struct {
	sbd_error_t		sep;
	dev_info_t		*sr_failed_dip;
	suspend_state_t		sr_suspend_state;
	uint_t			sr_flags;
	uint_t			sh_ndi;
} sbdp_sr_handle_t;

typedef struct sbdp_shutdown {
	uint64_t	estack;
	uint64_t	flushaddr;
	uint32_t	size;
	uint32_t	linesize;
	uint64_t	physaddr;
} sbdp_shutdown_t;

extern int plat_max_boards();

typedef struct {
	int		node;		/* wildcat node */
	int		board;
	pnode_t		nodes[SBDP_MAX_NODES];
	int		num_of_nodes;
	int		flags;
	int		error;
	dev_info_t	*top_node;
	char		*errstr;
} attach_pkt_t;

extern uint64_t *sbdp_valp;

sbdp_sr_handle_t *sbdp_get_sr_handle(void);
void sbdp_release_sr_handle(sbdp_sr_handle_t *);
int sbdp_suspend(sbdp_sr_handle_t *);
void sbdp_resume(sbdp_sr_handle_t *);
void sbdp_set_err(sbd_error_t *ep, int ecode, char *rsc);
int sbdp_is_node_bad(pnode_t);
void sbdp_walk_prom_tree(pnode_t, int(*)(pnode_t, void *, uint_t), void *);
int sbdp_detach_bd(int node, int board, sbd_error_t *sep);
void sbdp_attach_bd(int, int);
int sbdp_get_bd_and_wnode_num(pnode_t, int *, int *);
void sbdp_update_bd_info(sbdp_bd_t *);
sbdp_bd_t *sbdp_get_bd_info(int, int);
int sbdp_make_bd_mem_contigous(int);
sbd_cond_t sbdp_get_comp_status(pnode_t);
void sbdp_init_bd_banks(sbdp_bd_t *);
void sbdp_swap_list_of_banks(sbdp_bd_t *, sbdp_bd_t *);
void sbdp_fini_bd_banks(sbdp_bd_t *);
void sbdp_print_bd_banks(sbdp_bd_t *);
void sbdp_add_new_bd_info(int, int);
void sbdp_cleanup_bd(int, int);
void sbdp_cpu_in_reset(int, int, int, int);
int sbdp_is_cpu_in_reset(int, int, int);
int sbdp_set_cpu_present(int, int, int);
int sbdp_is_cpu_present(int, int, int);
int sbdp_swap_slices(int, int);
#ifdef DEBUG
void sbdp_print_all_segs(void);
int sbdp_passthru_test_quiesce(sbdp_handle_t *hp, void *);
#endif
int sbdp_select_top_nodes(pnode_t, void *, uint_t);
pnode_t sbdp_find_nearby_cpu_by_portid(pnode_t, processorid_t);
int sbdp_board_non_panther_cpus(int, int);

#ifdef	__cplusplus
}
#endif

#endif	/* _SBDP_PRIV_H */
