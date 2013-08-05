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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013, Joyent, Inc. All rights reserved.
 */

#ifndef	_SYS_POLICY_H
#define	_SYS_POLICY_H

#include <sys/types.h>
#include <sys/cred.h>
#include <sys/vnode.h>
#include <sys/fs/snode.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

#ifndef _IN_PORT_T
#define	_IN_PORT_T
typedef uint16_t in_port_t;
#endif

/*
 * Policy routines; in case we check privileges in-line.
 *
 * priv_policy
 *		privilege debugging
 *		audits success & failure
 *		returns 0 on success, error on failure
 *
 * priv_policy_choice
 *		determines extend of operation
 *		audit on success
 * 		returns a boolean_t indicating success (B_TRUE) or failure.
 *
 * priv_policy_only
 *		when auditing is in appropriate (interrupt context)
 *		to determine context of operation
 * 		returns a boolean_t indicating success (B_TRUE) or failure.
 *
 */
int priv_policy(const cred_t *, int, boolean_t, int, const char *);
boolean_t priv_policy_only(const cred_t *, int, boolean_t);
boolean_t priv_policy_choice(const cred_t *, int, boolean_t);

struct kipc_perm;
struct vfs;
struct proc;
struct priv_set;

int secpolicy_acct(const cred_t *);
int secpolicy_require_privs(const cred_t *, const struct priv_set *);
int secpolicy_allow_setid(const cred_t *, uid_t, boolean_t);
int secpolicy_audit_config(const cred_t *);
int secpolicy_audit_getattr(const cred_t *, boolean_t);
int secpolicy_audit_modify(const cred_t *);
int secpolicy_blacklist(const cred_t *);
int secpolicy_chroot(const cred_t *);
int secpolicy_clock_highres(const cred_t *);
int secpolicy_console(const cred_t *);
int secpolicy_contract_identity(const cred_t *);
int secpolicy_contract_observer(const cred_t *, struct contract *);
boolean_t secpolicy_contract_observer_choice(const cred_t *);
int secpolicy_contract_event(const cred_t *);
boolean_t secpolicy_contract_event_choice(const cred_t *);
int secpolicy_coreadm(const cred_t *);
int secpolicy_cpc_cpu(const cred_t *);
int secpolicy_dispadm(const cred_t *);
int secpolicy_error_inject(const cred_t *);
int secpolicy_excl_open(const cred_t *);
int secpolicy_fs_allowed_mount(const char *);
int secpolicy_fs_config(const cred_t *, const struct vfs *);
int secpolicy_fs_linkdir(const cred_t *, const struct vfs *);
int secpolicy_fs_minfree(const cred_t *, const struct vfs *);
int secpolicy_fs_mount(cred_t *, vnode_t *, struct vfs *);
int secpolicy_fs_quota(const cred_t *, const struct vfs *);
int secpolicy_fs_unmount(cred_t *, struct vfs *);
int secpolicy_idmap(const cred_t *);
int secpolicy_ip(const cred_t *, int, boolean_t);
int secpolicy_ip_config(const cred_t *, boolean_t);
int secpolicy_dl_config(const cred_t *);
int secpolicy_iptun_config(const cred_t *);
int secpolicy_ipc_access(const cred_t *, const struct kipc_perm *, mode_t);
int secpolicy_ipc_config(const cred_t *);
int secpolicy_ipc_owner(const cred_t *, const struct kipc_perm *);
int secpolicy_kmdb(const cred_t *);
int secpolicy_lock_memory(const cred_t *);
int secpolicy_modctl(const cred_t *, int);
int secpolicy_net(const cred_t *, int, boolean_t);
int secpolicy_net_bindmlp(const cred_t *);
int secpolicy_net_config(const cred_t *, boolean_t);
int secpolicy_net_icmpaccess(const cred_t *);
int secpolicy_net_mac_aware(const cred_t *);
int secpolicy_net_mac_implicit(const cred_t *);
int secpolicy_net_observability(const cred_t *);
int secpolicy_net_privaddr(const cred_t *, in_port_t, int proto);
int secpolicy_net_rawaccess(const cred_t *);
boolean_t secpolicy_net_reply_equal(const cred_t *);
int secpolicy_newproc(const cred_t *);
int secpolicy_nfs(const cred_t *);
int secpolicy_pbind(const cred_t *);
int secpolicy_pcfs_modify_bootpartition(const cred_t *);
int secpolicy_pfexec_register(const cred_t *);
int secpolicy_ponline(const cred_t *);
int secpolicy_pool(const cred_t *);
int secpolicy_power_mgmt(const cred_t *);
int secpolicy_ppp_config(const cred_t *);
int secpolicy_proc_access(const cred_t *);
int secpolicy_proc_excl_open(const cred_t *);
int secpolicy_proc_owner(const cred_t *, const cred_t *, int);
int secpolicy_proc_zone(const cred_t *);
int secpolicy_pset(const cred_t *);
int secpolicy_rctlsys(const cred_t *, boolean_t);
int secpolicy_resource(const cred_t *);
int secpolicy_resource_anon_mem(const cred_t *);
int secpolicy_rpcmod_open(const cred_t *);
int secpolicy_rsm_access(const cred_t *, uid_t, mode_t);
int secpolicy_raisepriority(const cred_t *);
int secpolicy_setpriority(const cred_t *);
int secpolicy_settime(const cred_t *);
int secpolicy_smb(const cred_t *);
int secpolicy_smbfs_login(const cred_t *, uid_t);
int secpolicy_spec_open(const cred_t *, struct vnode *, int);
int secpolicy_sti(const cred_t *);
int secpolicy_swapctl(const cred_t *);
int secpolicy_sys_config(const cred_t *, boolean_t);
int secpolicy_zone_admin(const cred_t *, boolean_t);
int secpolicy_zone_config(const cred_t *);
int secpolicy_sys_devices(const cred_t *);
int secpolicy_systeminfo(const cred_t *);
int secpolicy_tasksys(const cred_t *);
int secpolicy_vnode_access(const cred_t *, vnode_t *, uid_t, mode_t);
int secpolicy_vnode_access2(const cred_t *, vnode_t *, uid_t, mode_t, mode_t);
int secpolicy_vnode_any_access(const cred_t *, vnode_t *, uid_t);
int secpolicy_vnode_chown(const cred_t *, uid_t);
int secpolicy_vnode_create_gid(const cred_t *);
int secpolicy_vnode_owner(const cred_t *, uid_t);
int secpolicy_vnode_remove(const cred_t *);
int secpolicy_vnode_setdac(const cred_t *, uid_t);
int secpolicy_vnode_setid_retain(const cred_t *, boolean_t);
int secpolicy_vnode_setids_setgids(const cred_t *, gid_t);
int secpolicy_vnode_stky_modify(const cred_t *);
int secpolicy_vscan(const cred_t *);
int secpolicy_zinject(const cred_t *);
int secpolicy_zfs(const cred_t *);
int secpolicy_ucode_update(const cred_t *);
int secpolicy_sadopen(const cred_t *);
void secpolicy_setid_clear(vattr_t *, cred_t *);
void secpolicy_fs_mount_clearopts(cred_t *, struct vfs *);
int secpolicy_setid_setsticky_clear(vnode_t *, vattr_t *,
    const vattr_t *, cred_t *);
int secpolicy_xvattr(xvattr_t *, uid_t, cred_t *, vtype_t);
int secpolicy_xvm_control(const cred_t *);

int secpolicy_basic_exec(const cred_t *, vnode_t *);
int secpolicy_basic_fork(const cred_t *);
int secpolicy_basic_link(const cred_t *);
int secpolicy_basic_file_read(const cred_t *, vnode_t *, const char *);
int secpolicy_basic_file_write(const cred_t *, vnode_t *, const char *);
int secpolicy_basic_net_access(const cred_t *);
int secpolicy_basic_proc(const cred_t *);
int secpolicy_basic_procinfo(const cred_t *, struct proc *, struct proc *);

int secpolicy_gart_access(const cred_t *);
int secpolicy_gart_map(const cred_t *);
/*
 * This function to be called from xxfs_setattr().
 * Must be called with the node's attributes read-write locked.
 *
 *		cred_t *		- acting credentials
 *		struct vnode *		- vnode we're operating on
 *		struct vattr *va	- new attributes, va_mask may be
 *					  changed on return from a call
 *		struct vattr *oldva	- old attributes, need include owner
 *					  and mode only
 *		int flags		- setattr flags
 *		int iaccess(void *node, int mode, cred_t *cr)
 *					- non-locking internal access function
 *						mode be checked
 *						w/ VREAD|VWRITE|VEXEC, not fs
 *						internal mode encoding.
 *
 *		void *node		- internal node (inode, tmpnode) to
 *					  pass as arg to iaccess
 */
int secpolicy_vnode_setattr(cred_t *, struct vnode *, struct vattr *,
    const struct vattr *, int, int (void *, int, cred_t *), void *);

/*
 * Test privilege. Audit success or failure, allow privilege debugging.
 * Returns 0 for success, err for failure.
 */
#define	PRIV_POLICY(cred, priv, all, err, reason) \
		priv_policy((cred), (priv), (all), (err), (reason))

/*
 * Test privilege. Audit success only, no privilege debugging.
 * Returns 1 for success, and 0 for failure.
 */
#define	PRIV_POLICY_CHOICE(cred, priv, all) \
		priv_policy_choice((cred), (priv), (all))

/*
 * Test privilege. No priv_debugging, no auditing.
 * Returns 1 for success, and 0 for failure.
 */

#define	PRIV_POLICY_ONLY(cred, priv, all) \
		priv_policy_only((cred), (priv), (all))


#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_POLICY_H */
