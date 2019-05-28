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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2019 Peter Tribble.
 */

#ifndef _SYS_PLATFORM_MODULE_H
#define	_SYS_PLATFORM_MODULE_H

#include <sys/async.h>
#include <sys/sunddi.h>
#include <sys/memlist_plat.h>

#ifdef	__cplusplus
extern "C" {
#endif


#ifdef _KERNEL

/*
 * The functions that are expected of the platform modules.
 */

#pragma	weak	startup_platform
#pragma	weak	set_platform_tsb_spares
#pragma	weak	set_platform_defaults
#pragma	weak	load_platform_drivers
#pragma	weak	plat_cpu_poweron
#pragma	weak	plat_cpu_poweroff
#pragma	weak	plat_freelist_process
#pragma	weak	plat_lpkmem_is_supported

extern void startup_platform(void);
extern int set_platform_tsb_spares(void);
extern void set_platform_defaults(void);
extern void load_platform_drivers(void);
extern void load_platform_modules(void);
extern int plat_cpu_poweron(struct cpu *cp);	/* power on CPU */
extern int plat_cpu_poweroff(struct cpu *cp);	/* power off CPU */
extern void plat_freelist_process(int mnode);
extern void plat_build_mem_nodes(prom_memlist_t *, size_t);
extern void plat_slice_add(pfn_t, pfn_t);
extern void plat_slice_del(pfn_t, pfn_t);
extern int plat_lpkmem_is_supported(void);

/*
 * Data structures expected of the platform modules.
 */
extern char *platform_module_list[];

#pragma	weak	plat_get_cpu_unum
#pragma	weak	plat_get_mem_unum

extern int plat_get_cpu_unum(int cpuid, char *buf, int buflen, int *len);
extern int plat_get_mem_unum(int synd_code, uint64_t flt_addr, int flt_bus_id,
    int flt_in_memory, ushort_t flt_status, char *buf, int buflen, int *len);

#pragma	weak	plat_get_mem_sid
#pragma	weak	plat_get_mem_offset
#pragma	weak	plat_get_mem_addr

extern int plat_get_mem_sid(char *unum, char *buf, int buflen, int *len);
extern int plat_get_mem_offset(uint64_t paddr, uint64_t *offp);
extern int plat_get_mem_addr(char *unum, char *sid, uint64_t offset,
    uint64_t *paddr);

#pragma weak	plat_log_fruid_error

extern void plat_log_fruid_error(int synd_code, struct async_flt *ecc,
    char *unum, uint64_t afsr_bit);

#pragma	weak	plat_log_fruid_error2

struct plat_ecc_ch_async_flt;
struct rmc_comm_msg;

extern void plat_log_fruid_error2(int msg_type, char *unum,
    struct async_flt *aflt, struct plat_ecc_ch_async_flt *plat_ecc_ch_flt);

#pragma weak plat_ecc_capability_sc_get

extern int plat_ecc_capability_sc_get(int type);

#pragma weak	plat_blacklist

extern int plat_blacklist(int cmd, const char *scheme, nvlist_t *fmri,
    const char *class);

extern caddr_t plat_startup_memlist(caddr_t alloc_base);

#pragma	weak	plat_setprop_enter
#pragma	weak	plat_setprop_exit
#pragma	weak	plat_shared_i2c_enter
#pragma	weak	plat_shared_i2c_exit
#pragma weak	plat_fan_blast
#pragma weak    plat_rmc_comm_req

extern	void plat_setprop_enter(void);
extern	void plat_setprop_exit(void);
extern	void plat_shared_i2c_enter(dev_info_t *);
extern	void plat_shared_i2c_exit(dev_info_t *);
extern	void plat_fan_blast(void);
extern  void plat_rmc_comm_req(struct rmc_comm_msg *);

/*
 * Used to communicate DR updates to platform lgroup framework
 */
typedef struct {
	int		u_board;
	uint64_t	u_base;
	uint64_t	u_len;
} update_membounds_t;

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_PLATFORM_MODULE_H */
