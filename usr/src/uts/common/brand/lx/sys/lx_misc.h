/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2017 Joyent, Inc.
 */

#ifndef _SYS__LX_MISC_H
#define	_SYS__LX_MISC_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <inet/ip.h>
#include <inet/ip6.h>
#include <sys/siginfo.h>
#include <sys/lx_brand.h>

#ifdef _KERNEL

extern void lx_setrval(klwp_t *, int, int);
extern void lx_exec();
extern void lx_exitlwp(klwp_t *);
extern void lx_freelwp(klwp_t *);
extern void *lx_lwpdata_alloc(proc_t *);
extern void lx_lwpdata_free(void *);
extern void lx_initlwp(klwp_t *, void *);
extern void lx_initlwp_post(klwp_t *);
extern void lx_forklwp(klwp_t *, klwp_t *);

extern void lx_affinity_forklwp(klwp_t *, klwp_t *);

extern void lx_set_gdt(int, user_desc_t *);
extern void lx_clear_gdt(int);

extern longlong_t lx_nosys();

extern void lx_clone_grp_create(uint_t);
extern void lx_clone_grp_enter(uint_t, proc_t *, proc_t *);
extern void lx_clone_grp_exit(proc_t *, boolean_t);
extern boolean_t lx_clone_grp_member(lx_proc_data_t *, uint_t);
extern int lx_clone_grp_walk(lx_proc_data_t *, uint_t,
    int (*)(proc_t *, void *), void *);

extern greg_t lx_fixsegreg(greg_t, model_t);
extern uintptr_t lx_fsbase(klwp_t *, uintptr_t);
extern void lx_exit_with_sig(proc_t *, sigqueue_t *);
extern boolean_t lx_wait_filter(proc_t *, proc_t *);
extern void lx_sigfd_translate(k_siginfo_t *);
extern int stol_ksiginfo_copyout(k_siginfo_t *, void *);

extern int ltos_at_flag(int, int, boolean_t);
#if defined(_SYSCALL32_IMPL)
extern int stol_ksiginfo32_copyout(k_siginfo_t *, void *);
#endif
extern void lx_read_argv_bounds(proc_t *p);

typedef enum lx_regs_location {
	LX_REG_LOC_UNAVAIL,
	LX_REG_LOC_LWP,
	LX_REG_LOC_UCP
} lx_regs_location_t;

extern lx_regs_location_t lx_regs_location(lx_lwp_data_t *, void **, boolean_t);


typedef enum lx_if_action {
	LX_IF_FROMNATIVE,
	LX_IF_TONATIVE
} lx_if_action_t;

/* Linux ARP protocol hardware identifiers */
#define	LX_ARPHRD_ETHER		1	/* Ethernet */
#define	LX_ARPHRD_LOOPBACK	772	/* Loopback */
#define	LX_ARPHRD_VOID		0xffff	/* Unknown */

/* IPv6 address scope values used in /proc/net/if_inet6 */
#define	LX_IPV6_ADDR_LOOPBACK	0x0010U
#define	LX_IPV6_ADDR_LINKLOCAL	0x0020U
#define	LX_IPV6_ADDR_SITELOCAL	0x0040U
#define	LX_IPV6_ADDR_COMPATv4	0x0080U

/* Maximum length of a thread name, including the NUL terminator */
#define	LX_PR_SET_NAME_NAMELEN	16

extern void lx_ifname_convert(char *, lx_if_action_t);
extern void lx_ifflags_convert(uint64_t *, lx_if_action_t);
extern unsigned int lx_ipv6_scope_convert(const in6_addr_t *);
extern void lx_stol_hwaddr(const struct sockaddr_dl *, struct sockaddr *,
    int *);

extern boolean_t lx_ptrace_stop(ushort_t);
extern void lx_stop_notify(proc_t *, klwp_t *, ushort_t, ushort_t);
extern void lx_ptrace_init(void);
extern void lx_ptrace_fini(void);
extern int lx_waitid_helper(idtype_t, id_t, k_siginfo_t *, int, boolean_t *,
    int *);
extern void lx_ptrace_exit(proc_t *, klwp_t *);
extern void lx_ptrace_inherit_tracer(lx_lwp_data_t *, lx_lwp_data_t *);
extern int lx_ptrace_stop_for_option(int, boolean_t, ulong_t, uintptr_t);
extern int lx_ptrace_set_clone_inherit(int, boolean_t);
extern int lx_sigcld_repost(proc_t *, sigqueue_t *);
extern int lx_ptrace_issig_stop(proc_t *, klwp_t *);
extern boolean_t lx_ptrace_sig_ignorable(proc_t *, klwp_t *, int);

extern int lx_helper_clone(int64_t *, int, void *, void *, void *);
extern int lx_helper_setgroups(int, gid_t *);
extern int lx_helper_rt_sigqueueinfo(pid_t, int, siginfo_t *);
extern int lx_helper_rt_tgsigqueueinfo(pid_t, pid_t, int, siginfo_t *);

extern boolean_t lx_vsyscall_iscall(klwp_t *, uintptr_t, int *);
extern void lx_vsyscall_enter(proc_t *, klwp_t *, int);

extern void lx_check_strict_failure(lx_lwp_data_t *);

extern boolean_t lx_is_eventfd(file_t *);

extern int lx_read_common(file_t *, uio_t *, size_t *, boolean_t);
extern int lx_write_common(file_t *, uio_t *, size_t *, boolean_t);

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS__LX_MISC_H */
