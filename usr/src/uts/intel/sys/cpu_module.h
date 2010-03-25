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

#ifndef _SYS_CPU_MODULE_H
#define	_SYS_CPU_MODULE_H

#include <sys/types.h>
#include <sys/cpuvar.h>
#include <sys/nvpair.h>
#include <sys/mc.h>
#include <sys/sunddi.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _KERNEL

#define	CMIERR_BASE	0xc000

typedef enum cmi_errno {
	CMI_SUCCESS = 0,
	/*
	 * CPU Module Interface API error return values/
	 */
	CMIERR_UNKNOWN = CMIERR_BASE,	/* no specific error reason reported */
	CMIERR_API,			/* API usage error caught */
	CMIERR_NOTSUP,			/* Unsupported operation */
	CMIERR_HDL_CLASS,		/* Inappropriate handle class */
	CMIERR_HDL_NOTFOUND,		/* Can't find handle for resource */
	CMIERR_MSRGPF,			/* #GP during cmi_hdl_{wr,rd}msr */
	CMIERR_INTERPOSE,		/* MSR/PCICFG interposition error */
	CMIERR_DEADLOCK,		/* Deadlock avoidance */
	/*
	 * Memory-controller related errors
	 */
	CMIERR_MC_ABSENT,		/* No, or not yet registered, MC ops */
	CMIERR_MC_NOTSUP,		/* Requested functionality unimpld */
	CMIERR_MC_NOMEMSCRUB,		/* No dram scrubber, or disabled */
	CMIERR_MC_SYNDROME,		/* Invalid syndrome or syndrome type */
	CMIERR_MC_BADSTATE,		/* MC driver state is invalid */
	CMIERR_MC_NOADDR,		/* Address not found */
	CMIERR_MC_RSRCNOTPRESENT,	/* Resource not present in system */
	CMIERR_MC_ADDRBITS,		/* Too few valid addr bits */
	CMIERR_MC_INVALUNUM,		/* Invalid input unum */
	CMIERR_MC_PARTIALUNUMTOPA	/* unum to pa reflected physaddr */
} cmi_errno_t;

/*
 * All access to cpu information is made via a handle, in order to get
 * the desired info even when running non-natively.
 *
 * A CMI_HDL_NATIVE handle is used when we believe we are running on
 * bare-metal.  If we *are* on bare metal then this handle type will
 * get us through to the real hardware, and there will be a 1:1 correspondence
 * between handles and cpu_t structures; if not, say we are a domU to
 * some unknown/undetected/unannounced hypervisor then chances are the
 * hypervisor is not exposing much hardware detail to us so we should
 * be prepared for some operations that "cannot fail" to fail or return
 * odd data.
 *
 * A CMI_HDL_SOLARIS_xVM_MCA handle is used when we are running
 * in i86xpv architecture - dom0 to a Solaris xVM hypervisor - and want to
 * use a handle on each real execution core (as opposed to vcpu)
 * to perform MCA related activities.  The model for this handle type
 * is that the hypervisor continues to own the real hardware and
 * includes a polling service and #MC handler which forward error
 * telemetry to dom0 for logging and diagnosis.  As such, the operations
 * such as RDMSR and WRMSR for this handle type do *not* read and write
 * real MSRs via hypercalls- instead they should provide the values from
 * already-read MCA bank telemetry, and writes are discarded.
 *
 * If some application requires real MSR read and write access another
 * handle class should be introduced.
 */

typedef struct cmi_hdl *cmi_hdl_t;	/* opaque chip/core/strand handle */

enum cmi_hdl_class {
	CMI_HDL_NATIVE,
	CMI_HDL_SOLARIS_xVM_MCA,
	CMI_HDL_NEUTRAL
};

struct regs;

typedef struct cmi_mc_ops {
	cmi_errno_t (*cmi_mc_patounum)(void *, uint64_t, uint8_t, uint8_t,
	    uint32_t, int, mc_unum_t *);
	cmi_errno_t (*cmi_mc_unumtopa)(void *, mc_unum_t *, nvlist_t *,
	    uint64_t *);
	void (*cmi_mc_logout)(cmi_hdl_t, boolean_t, boolean_t);
} cmi_mc_ops_t;

extern cmi_hdl_t cmi_init(enum cmi_hdl_class, uint_t, uint_t, uint_t);
extern void cmi_post_startup(void);
extern void cmi_post_mpstartup(void);
extern void cmi_fini(cmi_hdl_t);

extern void cmi_hdl_hold(cmi_hdl_t);
extern void cmi_hdl_rele(cmi_hdl_t);
extern void *cmi_hdl_getcmidata(cmi_hdl_t);
extern void cmi_hdl_setspecific(cmi_hdl_t, void *);
extern void *cmi_hdl_getspecific(cmi_hdl_t);
extern const struct cmi_mc_ops *cmi_hdl_getmcops(cmi_hdl_t);
extern void *cmi_hdl_getmcdata(cmi_hdl_t);
extern enum cmi_hdl_class cmi_hdl_class(cmi_hdl_t);

extern cmi_hdl_t cmi_hdl_lookup(enum cmi_hdl_class, uint_t, uint_t, uint_t);
extern cmi_hdl_t cmi_hdl_any(void);

#define	CMI_HDL_WALK_NEXT	0
#define	CMI_HDL_WALK_DONE	1
extern void cmi_hdl_walk(int (*)(cmi_hdl_t, void *, void *, void *),
    void *, void *, void *);

extern void cmi_hdlconf_rdmsr_nohw(cmi_hdl_t);
extern void cmi_hdlconf_wrmsr_nohw(cmi_hdl_t);
extern cmi_errno_t cmi_hdl_rdmsr(cmi_hdl_t, uint_t, uint64_t *);
extern cmi_errno_t cmi_hdl_wrmsr(cmi_hdl_t, uint_t, uint64_t);

extern void cmi_hdl_enable_mce(cmi_hdl_t);
extern uint_t cmi_hdl_vendor(cmi_hdl_t);
extern const char *cmi_hdl_vendorstr(cmi_hdl_t);
extern uint_t cmi_hdl_family(cmi_hdl_t);
extern uint_t cmi_hdl_model(cmi_hdl_t);
extern uint_t cmi_hdl_stepping(cmi_hdl_t);
extern uint_t cmi_hdl_chipid(cmi_hdl_t);
extern uint_t cmi_hdl_procnodeid(cmi_hdl_t);
extern uint_t cmi_hdl_coreid(cmi_hdl_t);
extern uint_t cmi_hdl_strandid(cmi_hdl_t);
extern uint_t cmi_hdl_strand_apicid(cmi_hdl_t);
extern uint_t cmi_hdl_procnodes_per_pkg(cmi_hdl_t);
extern boolean_t cmi_hdl_is_cmt(cmi_hdl_t);
extern uint32_t cmi_hdl_chiprev(cmi_hdl_t);
extern const char *cmi_hdl_chiprevstr(cmi_hdl_t);
extern uint32_t cmi_hdl_getsockettype(cmi_hdl_t);
extern const char *cmi_hdl_getsocketstr(cmi_hdl_t);
extern id_t cmi_hdl_logical_id(cmi_hdl_t);
extern uint16_t cmi_hdl_smbiosid(cmi_hdl_t);
extern uint_t cmi_hdl_smb_chipid(cmi_hdl_t);
extern nvlist_t *cmi_hdl_smb_bboard(cmi_hdl_t);

extern int cmi_hdl_online(cmi_hdl_t, int, int *);

#ifndef	__xpv
extern uint_t cmi_ntv_hwchipid(cpu_t *);
extern uint_t cmi_ntv_hwprocnodeid(cpu_t *);
extern uint_t cmi_ntv_hwcoreid(cpu_t *);
extern uint_t cmi_ntv_hwstrandid(cpu_t *);
extern void cmi_ntv_hwdisable_mce(cmi_hdl_t);
#endif	/* __xpv */

typedef struct cmi_mca_regs {
	uint_t cmr_msrnum;
	uint64_t cmr_msrval;
} cmi_mca_regs_t;

extern cmi_errno_t cmi_hdl_msrinject(cmi_hdl_t, cmi_mca_regs_t *, uint_t,
    int);
extern void cmi_hdl_msrinterpose(cmi_hdl_t, cmi_mca_regs_t *, uint_t);
extern void cmi_hdl_msrforward(cmi_hdl_t, cmi_mca_regs_t *, uint_t);
extern boolean_t cmi_inj_tainted(void);

extern void cmi_faulted_enter(cmi_hdl_t);
extern void cmi_faulted_exit(cmi_hdl_t);

extern void cmi_pcird_nohw(void);
extern void cmi_pciwr_nohw(void);
extern uint8_t cmi_pci_getb(int, int, int, int, int *, ddi_acc_handle_t);
extern uint16_t cmi_pci_getw(int, int, int, int, int *, ddi_acc_handle_t);
extern uint32_t cmi_pci_getl(int, int, int, int, int *, ddi_acc_handle_t);
extern void cmi_pci_interposeb(int, int, int, int, uint8_t);
extern void cmi_pci_interposew(int, int, int, int, uint16_t);
extern void cmi_pci_interposel(int, int, int, int, uint32_t);
extern void cmi_pci_putb(int, int, int, int, ddi_acc_handle_t, uint8_t);
extern void cmi_pci_putw(int, int, int, int, ddi_acc_handle_t, uint16_t);
extern void cmi_pci_putl(int, int, int, int, ddi_acc_handle_t, uint32_t);

extern void cmi_mca_init(cmi_hdl_t);

extern void cmi_hdl_poke(cmi_hdl_t);
extern void cmi_hdl_int(cmi_hdl_t, int);

extern void cmi_mca_trap(struct regs *);

extern boolean_t cmi_panic_on_ue(void);

extern void cmi_mc_register(cmi_hdl_t, const struct cmi_mc_ops *, void *);
extern cmi_errno_t cmi_mc_register_global(const struct cmi_mc_ops *, void *);
extern void cmi_mc_sw_memscrub_disable(void);
extern cmi_errno_t cmi_mc_patounum(uint64_t, uint8_t, uint8_t, uint32_t, int,
    mc_unum_t *);
extern cmi_errno_t cmi_mc_unumtopa(mc_unum_t *, nvlist_t *, uint64_t *);
extern void cmi_mc_logout(cmi_hdl_t, boolean_t, boolean_t);

extern void cmi_panic_callback(void);

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_CPU_MODULE_H */
