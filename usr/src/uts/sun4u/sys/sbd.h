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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SBD_H
#define	_SBD_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/dditypes.h>
/*
 * SBD LOWER STRUCTURES AND INTERFACES
 */

typedef uint32_t	sbd_flags_t;

/*
 * Flag definitions
 */
#define	SBDP_IOCTL_FLAG_FORCE	0x1

typedef struct {
	int		size;	/* length of the options */
	char		*copts;	/* pointer to the platform options */
} sbdp_opts_t;

typedef struct {
	sbd_error_t	*h_err;		/* error reporting from lower layer */
	int		h_board;	/* board number */
	int		h_wnode;	/* node ID */
	sbd_flags_t	h_flags;
	sbdp_opts_t	*h_opts;	/* points to the platform options */
} sbdp_handle_t;

/* struct for device name to type mapping */
typedef struct {
	char		*s_devname;	/* OBP name */
	char		*s_obp_type;	/* OBP type */
	sbd_comp_type_t	s_dnodetype;	/* SBD type */
} sbd_devattr_t;

typedef struct {
	pnode_t		dnodeid;
	uint64_t	*basepa;
} sbd_basephys_t;

typedef struct {
	dev_t		h_dev;		/* dev_t of opened device */
	int		h_cmd;		/* ioctl argument */
	int		h_mode;
	intptr_t	h_iap;	/* points to kernel copy of ioargs */
} sbdp_ioctl_arg_t;


struct sbd_mem_unit;		/* forward decl */

int sbdp_setup_instance(caddr_t arg);
int sbdp_teardown_instance(caddr_t arg);
int sbdp_assign_board(sbdp_handle_t *hp);
int sbdp_connect_board(sbdp_handle_t *hp);
int sbdp_disconnect_board(sbdp_handle_t *hp);
int sbdp_get_board_num(sbdp_handle_t *hp, dev_info_t *dip);
int sbdp_get_board_status(sbdp_handle_t *, sbd_stat_t *);
int sbdp_cancel_component_release(sbdp_handle_t *hp);
processorid_t sbdp_get_cpuid(sbdp_handle_t *hp, dev_info_t *dip);
int sbdp_connect_cpu(sbdp_handle_t *, dev_info_t *, processorid_t);
int sbdp_disconnect_cpu(sbdp_handle_t *, dev_info_t *, processorid_t);
sbd_devattr_t  *sbdp_get_devattr(void);
int sbdp_get_mem_alignment(sbdp_handle_t *hp, dev_info_t *dip, uint64_t *align);
struct memlist *sbdp_get_memlist(sbdp_handle_t *hp, dev_info_t *dip);
int sbdp_del_memlist(sbdp_handle_t *hp, struct memlist *mlist);
int sbdp_get_unit_num(sbdp_handle_t *hp, dev_info_t *dip);
int sbdp_portid_to_cpu_unit(int cmp, int core);
int sbdp_move_memory(sbdp_handle_t *, int t_bd);
int sbdp_mem_add_span(sbdp_handle_t *hp, uint64_t address, uint64_t size);
int sbdp_get_mem_size(sbdp_handle_t *hp);
int sbdp_mem_del_span(sbdp_handle_t *hp, uint64_t address, uint64_t size);
int sbdp_poweroff_board(sbdp_handle_t *hp);
int sbdp_poweron_board(sbdp_handle_t *hp);
int sbdp_release_component(sbdp_handle_t *hp, dev_info_t *dip);
int sbdp_test_board(sbdp_handle_t *hp, sbdp_opts_t *opts);
int sbdp_unassign_board(sbdp_handle_t *hp);
int sbdphw_disable_memctrl(sbdp_handle_t *hp, dev_info_t *dip);
int sbdphw_enable_memctrl(sbdp_handle_t *hp, dev_info_t *dip);
int sbdphw_get_base_physaddr(sbdp_handle_t *hp, dev_info_t *dip, uint64_t *pa);
int sbdp_isbootproc(processorid_t cpuid);
int sbdp_ioctl(sbdp_handle_t *, sbdp_ioctl_arg_t *);
int sbdp_isinterleaved(sbdp_handle_t *, dev_info_t *);
void sbdp_check_devices(dev_info_t *, int *refcount, sbd_error_t *, int *);
int sbdp_dr_avail(void);

extern int sbdp_cpu_get_impl(sbdp_handle_t *hp, dev_info_t *dip);

#ifdef	__cplusplus
}
#endif

#endif	/* _SBD_H */
