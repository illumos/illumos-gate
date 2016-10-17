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
 * Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2015, Joyent, Inc. All rights reserved.
 */

#if !defined(lint)
#include "assym.h"
#endif /* !lint */

#include <sys/asm_linkage.h>

#if defined(lint)

char stubs_base[1], stubs_end[1];

#else	/* lint */

/*
 * WARNING: there is no check for forgetting to write END_MODULE,
 * and if you do, the kernel will most likely crash.  Be careful
 *
 * This file assumes that all of the contributions to the data segment
 * will be contiguous in the output file, even though they are separated
 * by pieces of text.  This is safe for all assemblers I know of now...
 */

/*
 * This file uses ansi preprocessor features:
 *
 * 1. 	#define mac(a) extra_ ## a     -->   mac(x) expands to extra_a
 * The old version of this is
 *      #define mac(a) extra_/.*.*./a
 * but this fails if the argument has spaces "mac ( x )"
 * (Ignore the dots above, I had to put them in to keep this a comment.)
 *
 * 2.   #define mac(a) #a             -->    mac(x) expands to "x"
 * The old version is
 *      #define mac(a) "a"
 *
 * For some reason, the 5.0 preprocessor isn't happy with the above usage.
 * For now, we're not using these ansi features.
 *
 * The reason is that "the 5.0 ANSI preprocessor" is built into the compiler
 * and is a tokenizing preprocessor. This means, when confronted by something
 * other than C token generation rules, strange things occur. In this case,
 * when confronted by an assembly file, it would turn the token ".globl" into
 * two tokens "." and "globl". For this reason, the traditional, non-ANSI
 * preprocessor is used on assembly files.
 *
 * It would be desirable to have a non-tokenizing cpp (accp?) to use for this.
 */

/*
 * This file contains the stubs routines for modules which can be autoloaded.
 */


/*
 * See the 'struct mod_modinfo' definition to see what this structure
 * is trying to achieve here.
 */
/*
 * XX64 - This still needs some repair.
 * (a) define 'pointer alignment' and use it
 * (b) define '.pword' or equivalent, and use it (to mean .word or .xword).
 */
#define	MODULE(module,namespace)	\
	.seg	".data";		\
module/**/_modname:			\
	.ascii	"namespace/module";	\
	.byte	0;			\
	.align	CPTRSIZE;		\
	.global	module/**/_modinfo;	\
	.type	module/**/_modinfo, #object;	\
	.size	module/**/_modinfo, 16;	\
module/**/_modinfo:			\
	.word 0;			\
	.word module/**/_modname;	\
	.word 0;			\
	.word 0;

#define	END_MODULE(module)		\
	.align 8; .word 0; .word 0	/* FIXME: .xword 0 */


#define STUB(module, fcnname, retfcn)	\
    STUB_COMMON(module, fcnname, mod_hold_stub, retfcn, 0)

/*
 * "weak stub", don't load on account of this call
 */
#define WSTUB(module, fcnname, retfcn)	\
    STUB_COMMON(module, fcnname, retfcn, retfcn, MODS_WEAK)

/*
 * "non-unloadable stub", don't bother 'holding' module if it's already loaded
 * since the module cannot be unloaded.
 *
 * User *MUST* guarantee the module is not unloadable (no _fini routine).
 */
#define NO_UNLOAD_STUB(module, fcnname, retfcn)	\
    STUB_UNLOADABLE(module, fcnname, retfcn, retfcn, MODS_NOUNLOAD)

/*
 * Macro for modstubbed system calls whose modules are not unloadable.
 *
 * System call modstubs needs special handling for the case where
 * the modstub is a system call, because %fp comes from user frame.
 */
#define	SCALL_NU_STUB(module, fcnname, retfcn)	\
    SCALL_UNLOADABLE(module, fcnname, retfcn, retfcn, MODS_NOUNLOAD)
/* "weak stub" for non-unloadable module, don't load on account of this call */
#define NO_UNLOAD_WSTUB(module, fcnname, retfcn) \
    STUB_UNLOADABLE(module, fcnname, retfcn, retfcn, MODS_NOUNLOAD|MODS_WEAK)

#define	STUB_DATA(module, fcnname, install_fcn, retfcn, weak)		\
	.seg	".data";						\
	.align	8;							\
fcnname/**/_info:							\
	.word	0;			/* 0 */				\
	.word	install_fcn;		/* 4 */				\
	.word	0;			/* 8 */				\
	.word	module/**/_modinfo;	/* c */				\
	.word	0;			/* 10 */			\
	.word	fcnname;		/* 14 */			\
	.word	0;			/* 18 */			\
	.word	retfcn;			/* 1c */			\
	.word   weak			/* 20 */

/*	
 * The flag MODS_INSTALLED is stored in the stub data and is used to
 * indicate if a module is installed and initialized.  This flag is used
 * instead of the mod_stub_info->mods_modinfo->mod_installed flag
 * to minimize the number of pointer de-references for each function
 * call (and also to avoid possible TLB misses which could be induced
 * by dereferencing these pointers.)
 */	

#define STUB_COMMON(module, fcnname, install_fcn, retfcn, weak)		\
	ENTRY_NP(fcnname);						\
	save	%sp, -SA(MINFRAME), %sp;/* new window */		\
	set	fcnname/**/_info, %l5;					\
	ld	[%l5 + MODS_FLAG], %l1;	/* weak?? */			\
	cmp	%l1, 0;							\
	be,a	1f;			/* not weak */			\
	restore;							\
	btst	MODS_INSTALLED, %l1;	/* installed?? */		\
 	bne,a,pt %xcc, 1f;		/* yes, do mod_hold thing */	\
 	restore;							\
 	ldn	[%l5 + MODS_RETFCN], %g1;				\
	jmp	%g1;			/* no, just jump to retfcn */	\
	restore;							\
1:	sub	%sp, %fp, %g1;	/* get (-)size of callers stack */	\
	save	%sp, %g1, %sp;	/* create new frame same size */	\
	sub	%g0, %g1, %l4;  /* size of stack frame */		\
	sethi	%hi(fcnname/**/_info), %l5;				\
	b	stubs_common_code;					\
	or	%l5, %lo(fcnname/**/_info), %l5;			\
	SET_SIZE(fcnname);						\
	STUB_DATA(module, fcnname, install_fcn, retfcn, weak)

#define STUB_UNLOADABLE(module, fcnname, install_fcn, retfcn, weak)	\
	ENTRY_NP(fcnname);						\
	save	%sp, -SA(MINFRAME), %sp;	/* new window */	\
	set	fcnname/**/_info, %l5;					\
	ld	[%l5 + MODS_FLAG], %l1;					\
	btst	MODS_INSTALLED, %l1;		/* installed?? */	\
	bne,a	%xcc, 1f;			/* yes */		\
	ldn	[%l5], %g1;						\
	btst	MODS_WEAK, %l1;			/* weak?? */		\
	be,a	2f;				/* no, load module */	\
	restore;							\
	ldn	[%l5 + MODS_RETFCN], %g1;				\
1:	jmp	%g1;				/* off we go */		\
	restore;							\
2:	sub	%sp, %fp, %g1;	/* get (-)size of callers frame */	\
	save	%sp, %g1, %sp;	/* create new frame same size */	\
	sub	%g0, %g1, %l4;  /* size of stack frame */		\
	sethi	%hi(fcnname/**/_info), %l5;				\
	b	stubs_common_code;					\
	or	%l5, %lo(fcnname/**/_info), %l5;			\
	SET_SIZE(fcnname);						\
	STUB_DATA(module, fcnname, install_fcn, retfcn, weak)

#define SCALL_UNLOADABLE(module, fcnname, install_fcn, retfcn, weak)	\
	ENTRY_NP(fcnname);						\
	save	%sp, -SA(MINFRAME), %sp;	/* new window */	\
	set	fcnname/**/_info, %l5;					\
	ld	[%l5 + MODS_FLAG], %l1;		/* installed?? */	\
	btst	MODS_INSTALLED, %l1;					\
	be,a	%xcc, 1f;			/* no, load module */	\
	restore;							\
 	ldn	[%l5], %g1;						\
	jmp	%g1;				/* yes, off we go */	\
	restore;							\
1:	save	%sp, -SA(MINFRAME), %sp;/* new frame */			\
	sub	%g0, -SA(MINFRAME), %l4;/* size of stack frame */	\
	sethi	%hi(fcnname/**/_info), %l5;				\
	b	stubs_common_code;					\
	or	%l5, %lo(fcnname/**/_info), %l5;			\
	SET_SIZE(fcnname);						\
	STUB_DATA(module, fcnname, install_fcn, retfcn, weak)

	.section	".text"

	/*
	 * We branch here with the fcnname_info pointer in l5
	 * and the frame size in %l4.
	 */
	ENTRY_NP(stubs_common_code)
	cmp	%l4, SA(MINFRAME)
	ble,a,pn %xcc, 2f
	nop

	sub	%l4, 0x80, %l4		/* skip locals and outs */
	add	%sp, 0x80, %l0
	add	%fp, 0x80, %l1		/* get original sp before save */
1:
	/* Copy stack frame */
	ldn	[%l1 + STACK_BIAS], %l2
	inc	8, %l1
	stn	%l2, [%l0 + STACK_BIAS]
	deccc	8, %l4
	bg,a	1b
	inc	8, %l0
2:
	call	mod_hold_stub		/* Hold the module */
	mov	%l5, %o0
	cmp	%o0, -1			/* if error then return error */
	bne,a	1f
	nop
	ldn	[%l5 + MODS_RETFCN], %i0
	call	%i0
	nop
	ret
	restore	%o0, 0, %o0
1:
	ldn	[%l5], %g1
	mov	%i0, %o0	/* copy over incoming args, if number of */
	mov	%i1, %o1	/* args is > 6 then we copied them above */
	mov	%i2, %o2
	mov	%i3, %o3
	mov	%i4, %o4
	call	%g1		/* jump to the stub function */
	mov	%i5, %o5
	mov	%o0, %i0	/* copy any return values */
	mov	%o1, %i1
	call	mod_release_stub	/* release hold on module */
	mov	%l5, %o0
	ret			/* return to caller */
	restore
	SET_SIZE(stubs_common_code)

! this is just a marker for the area of text that contains stubs 
	.seg ".text"
	.global stubs_base
stubs_base:
	nop

/*
 * WARNING WARNING WARNING!!!!!!
 * 
 * On the MODULE macro you MUST NOT use any spaces!!! They are
 * significant to the preprocessor.  With ansi c there is a way around this
 * but for some reason (yet to be investigated) ansi didn't work for other
 * reasons!  
 *
 * When zero is used as the return function, the system will call
 * panic if the stub can't be resolved.
 */

/*
 * Stubs for devfs. A non-unloadable module.
 */
#ifndef DEVFS_MODULE
	MODULE(devfs,fs);
	NO_UNLOAD_STUB(devfs, devfs_clean,		nomod_minus_one);
	NO_UNLOAD_STUB(devfs, devfs_lookupname,		nomod_minus_one);
	NO_UNLOAD_STUB(devfs, devfs_walk,		nomod_minus_one);
	NO_UNLOAD_STUB(devfs, devfs_devpolicy,		nomod_minus_one);
	NO_UNLOAD_STUB(devfs, devfs_reset_perm,		nomod_minus_one);
	NO_UNLOAD_STUB(devfs, devfs_remdrv_cleanup,	nomod_minus_one);
	END_MODULE(devfs);
#endif

/*
 * Stubs for /dev fs.
 */
#ifndef DEV_MODULE
	MODULE(dev, fs);
	NO_UNLOAD_STUB(dev, sdev_modctl_readdir,	nomod_minus_one);
	NO_UNLOAD_STUB(dev, sdev_modctl_readdir_free,	nomod_minus_one);
	NO_UNLOAD_STUB(dev, devname_filename_register,	nomod_minus_one);
	NO_UNLOAD_STUB(dev, sdev_modctl_devexists,	nomod_minus_one);
	NO_UNLOAD_STUB(dev, devname_profile_update,	nomod_minus_one);
	NO_UNLOAD_STUB(dev, sdev_devstate_change,	nomod_minus_one);
	NO_UNLOAD_STUB(dev, devvt_getvnodeops,		nomod_minus_one);
	NO_UNLOAD_STUB(dev, devpts_getvnodeops,		nomod_zero);
	END_MODULE(dev);
#endif

/*
 * Stubs for specfs. A non-unloadable module.
 */

#ifndef SPEC_MODULE
	MODULE(specfs,fs);
	NO_UNLOAD_STUB(specfs, common_specvp,  	nomod_zero);
	NO_UNLOAD_STUB(specfs, makectty,		nomod_zero);
	NO_UNLOAD_STUB(specfs, makespecvp,      	nomod_zero);
	NO_UNLOAD_STUB(specfs, smark,           	nomod_zero);
	NO_UNLOAD_STUB(specfs, spec_segmap,     	nomod_einval);
	NO_UNLOAD_STUB(specfs, specfind,        	nomod_zero);
	NO_UNLOAD_STUB(specfs, specvp,          	nomod_zero);
	NO_UNLOAD_STUB(specfs, devi_stillreferenced,	nomod_zero);
	NO_UNLOAD_STUB(specfs, spec_getvnodeops,	nomod_zero);
	NO_UNLOAD_STUB(specfs, spec_char_map,		nomod_zero);
	NO_UNLOAD_STUB(specfs, specvp_devfs,  		nomod_zero);
	NO_UNLOAD_STUB(specfs, spec_assoc_vp_with_devi,	nomod_void);
	NO_UNLOAD_STUB(specfs, spec_hold_devi_by_vp,	nomod_zero);
	NO_UNLOAD_STUB(specfs, spec_snode_walk,		nomod_void);
	NO_UNLOAD_STUB(specfs, spec_devi_open_count,	nomod_minus_one);
	NO_UNLOAD_STUB(specfs, spec_is_clone,		nomod_zero);
	NO_UNLOAD_STUB(specfs, spec_is_selfclone,	nomod_zero);
	NO_UNLOAD_STUB(specfs, spec_fence_snode,	nomod_minus_one);
	NO_UNLOAD_STUB(specfs, spec_unfence_snode,	nomod_minus_one);
	END_MODULE(specfs);
#endif


/*
 * Stubs for sockfs. A non-unloadable module.
 */
#ifndef SOCK_MODULE
	MODULE(sockfs, fs);
	SCALL_NU_STUB(sockfs, so_socket,  	nomod_zero);
	SCALL_NU_STUB(sockfs, so_socketpair,	nomod_zero);
	SCALL_NU_STUB(sockfs, bind,  		nomod_zero);
	SCALL_NU_STUB(sockfs, listen,  		nomod_zero);
	SCALL_NU_STUB(sockfs, accept,  		nomod_zero);
	SCALL_NU_STUB(sockfs, connect,  	nomod_zero);
	SCALL_NU_STUB(sockfs, shutdown,  	nomod_zero);
	SCALL_NU_STUB(sockfs, recv,  		nomod_zero);
	SCALL_NU_STUB(sockfs, recvfrom,  	nomod_zero);
	SCALL_NU_STUB(sockfs, recvmsg,  	nomod_zero);
	SCALL_NU_STUB(sockfs, send,  		nomod_zero);
	SCALL_NU_STUB(sockfs, sendmsg,  	nomod_zero);
	SCALL_NU_STUB(sockfs, sendto, 		nomod_zero);
#ifdef _SYSCALL32_IMPL
	SCALL_NU_STUB(sockfs, recv32,  		nomod_zero);
	SCALL_NU_STUB(sockfs, recvfrom32,  	nomod_zero);
	SCALL_NU_STUB(sockfs, send32,  		nomod_zero);
	SCALL_NU_STUB(sockfs, sendto32, 	nomod_zero);
#endif /* _SYSCALL32_IMPL */
	SCALL_NU_STUB(sockfs, getpeername,  	nomod_zero);
	SCALL_NU_STUB(sockfs, getsockname,  	nomod_zero);
	SCALL_NU_STUB(sockfs, getsockopt,  	nomod_zero);
	SCALL_NU_STUB(sockfs, setsockopt,  	nomod_zero);
	SCALL_NU_STUB(sockfs, sockconfig,  	nomod_zero);
	NO_UNLOAD_STUB(sockfs, sock_getmsg,  	nomod_zero);
	NO_UNLOAD_STUB(sockfs, sock_putmsg,  	nomod_zero);
	NO_UNLOAD_STUB(sockfs, sosendfile64,  	nomod_zero);
	NO_UNLOAD_STUB(sockfs, snf_segmap,  	nomod_einval);
	NO_UNLOAD_STUB(sockfs, sock_getfasync,  nomod_zero);
	NO_UNLOAD_STUB(sockfs, nl7c_sendfilev,  nomod_zero);
	NO_UNLOAD_STUB(sockfs, sotpi_sototpi,  nomod_zero);
	NO_UNLOAD_STUB(sockfs, socket_sendmblk,	nomod_zero);
	NO_UNLOAD_STUB(sockfs, socket_setsockopt,	nomod_zero);
	END_MODULE(sockfs);
#endif

/*
 * IPsec stubs.
 */

#ifndef	IPSECAH_MODULE
	MODULE(ipsecah,drv);
	WSTUB(ipsecah,	ipsec_construct_inverse_acquire,	nomod_zero);
	WSTUB(ipsecah,	sadb_acquire,		nomod_zero);
	WSTUB(ipsecah,	ipsecah_algs_changed,	nomod_zero);
	WSTUB(ipsecah,	sadb_alg_update,	nomod_zero);
	WSTUB(ipsecah,	sadb_unlinkassoc,	nomod_zero);
	WSTUB(ipsecah,	sadb_insertassoc,	nomod_zero);
	WSTUB(ipsecah,	ipsecah_in_assocfailure,	nomod_zero);
	WSTUB(ipsecah,	sadb_set_lpkt,		nomod_zero);
	WSTUB(ipsecah,	ipsecah_icmp_error,	nomod_zero);
	END_MODULE(ipsecah);
#endif

#ifndef	IPSECESP_MODULE
	MODULE(ipsecesp,drv);
	WSTUB(ipsecesp,	ipsecesp_fill_defs,	nomod_zero);
	WSTUB(ipsecesp,	ipsecesp_algs_changed,	nomod_zero);
	WSTUB(ipsecesp, ipsecesp_in_assocfailure,	nomod_zero);
	WSTUB(ipsecesp, ipsecesp_init_funcs,	nomod_zero);
	WSTUB(ipsecesp,	ipsecesp_icmp_error,	nomod_zero);
	WSTUB(ipsecesp,	ipsecesp_send_keepalive,	nomod_zero);
	END_MODULE(ipsecesp);
#endif

#ifndef KEYSOCK_MODULE
	MODULE(keysock,drv);
	WSTUB(keysock,	keysock_plumb_ipsec,	nomod_zero);
	WSTUB(keysock,	keysock_extended_reg,	nomod_zero);
	WSTUB(keysock,	keysock_next_seq,	nomod_zero);
	END_MODULE(keysock);
#endif

#ifndef SPDSOCK_MODULE
	MODULE(spdsock,drv);
	WSTUB(spdsock,	spdsock_update_pending_algs,	nomod_zero);
	END_MODULE(spdsock);
#endif

/*
 * Stubs for nfs common code.
 * XXX nfs_getvnodeops should go away with removal of kludge in vnode.c
 */
#ifndef NFS_MODULE
	MODULE(nfs,fs);
	WSTUB(nfs,	nfs_getvnodeops,	nomod_zero);
	WSTUB(nfs,	nfs_perror,		nomod_zero);
	WSTUB(nfs,	nfs_cmn_err,		nomod_zero);
	WSTUB(nfs,	clcleanup_zone,		nomod_zero);
	WSTUB(nfs,	clcleanup4_zone,	nomod_zero);
	END_MODULE(nfs);
#endif

/*
 * Stubs for nfs_dlboot (diskless booting).
 */
#ifndef NFS_DLBOOT_MODULE
	MODULE(nfs_dlboot,misc);
	STUB(nfs_dlboot,	mount_root,	nomod_minus_one);
	STUB(nfs_dlboot,        dhcpinit,       nomod_minus_one);
	END_MODULE(nfs_dlboot);
#endif

/*
 * Stubs for nfs server-only code.
 */
#ifndef NFSSRV_MODULE
	MODULE(nfssrv,misc);
	STUB(nfssrv,		exportfs,	nomod_minus_one);
	STUB(nfssrv,		nfs_getfh,	nomod_minus_one);
	STUB(nfssrv,		nfsl_flush,	nomod_minus_one);
	STUB(nfssrv,		rfs4_check_delegated, nomod_zero);
	STUB(nfssrv,		mountd_args,	nomod_minus_one);
	NO_UNLOAD_STUB(nfssrv,	rdma_start,	nomod_zero);
	NO_UNLOAD_STUB(nfssrv,	nfs_svc,	nomod_zero);
	END_MODULE(nfssrv);
#endif

/*
 * Stubs for kernel lock manager.
 */
#ifndef KLM_MODULE
	MODULE(klmmod,misc);
	NO_UNLOAD_STUB(klmmod, lm_svc,		nomod_zero);
	NO_UNLOAD_STUB(klmmod, lm_shutdown,	nomod_zero);
	NO_UNLOAD_STUB(klmmod, lm_unexport,	nomod_zero);
	NO_UNLOAD_STUB(klmmod, lm_cprresume,	nomod_zero);
	NO_UNLOAD_STUB(klmmod, lm_cprsuspend,	nomod_zero); 
	NO_UNLOAD_STUB(klmmod, lm_safelock, nomod_zero);
	NO_UNLOAD_STUB(klmmod, lm_safemap, nomod_zero);
	NO_UNLOAD_STUB(klmmod, lm_has_sleep, nomod_zero);
	NO_UNLOAD_STUB(klmmod, lm_free_config, nomod_zero);
	NO_UNLOAD_STUB(klmmod, lm_vp_active, nomod_zero);
	NO_UNLOAD_STUB(klmmod, lm_get_sysid, nomod_zero);
	NO_UNLOAD_STUB(klmmod, lm_rel_sysid, nomod_zero);
	NO_UNLOAD_STUB(klmmod, lm_alloc_sysidt, nomod_minus_one); 
	NO_UNLOAD_STUB(klmmod, lm_free_sysidt, nomod_zero); 
	NO_UNLOAD_STUB(klmmod, lm_sysidt, nomod_minus_one);
	END_MODULE(klmmod);
#endif

#ifndef KLMOPS_MODULE
	MODULE(klmops,misc);
	NO_UNLOAD_STUB(klmops, lm_frlock,	nomod_zero);
	NO_UNLOAD_STUB(klmops, lm4_frlock,	nomod_zero);
	NO_UNLOAD_STUB(klmops, lm_shrlock,	nomod_zero);
	NO_UNLOAD_STUB(klmops, lm4_shrlock,	nomod_zero);
	NO_UNLOAD_STUB(klmops, lm_nlm_dispatch,	nomod_zero);
	NO_UNLOAD_STUB(klmops, lm_nlm4_dispatch,	nomod_zero);
	NO_UNLOAD_STUB(klmops, lm_nlm_reclaim,	nomod_zero);
	NO_UNLOAD_STUB(klmops, lm_nlm4_reclaim,	nomod_zero);
	NO_UNLOAD_STUB(klmops, lm_register_lock_locally, nomod_zero);
	END_MODULE(klmops);
#endif

/*
 * Stubs for kernel TLI module
 *   XXX currently we never allow this to unload
 */
#ifndef TLI_MODULE
	MODULE(tlimod,misc);
	NO_UNLOAD_STUB(tlimod, t_kopen,		nomod_minus_one);
	NO_UNLOAD_STUB(tlimod, t_kunbind,  	nomod_zero);
	NO_UNLOAD_STUB(tlimod, t_kadvise,  	nomod_zero);
	NO_UNLOAD_STUB(tlimod, t_krcvudata,  	nomod_zero);
	NO_UNLOAD_STUB(tlimod, t_ksndudata,  	nomod_zero);
	NO_UNLOAD_STUB(tlimod, t_kalloc,  	nomod_zero);
	NO_UNLOAD_STUB(tlimod, t_kbind,  	nomod_zero);
	NO_UNLOAD_STUB(tlimod, t_kclose,  	nomod_zero);
	NO_UNLOAD_STUB(tlimod, t_kspoll,  	nomod_zero);
	NO_UNLOAD_STUB(tlimod, t_kfree,  	nomod_zero);
	END_MODULE(tlimod);
#endif

/*
 * Stubs for kernel RPC module
 *   XXX currently we never allow this to unload
 */
#ifndef RPC_MODULE
	MODULE(rpcmod,strmod);
	NO_UNLOAD_STUB(rpcmod, clnt_tli_kcreate,	nomod_minus_one);
	NO_UNLOAD_STUB(rpcmod, svc_tli_kcreate,		nomod_minus_one);
	NO_UNLOAD_STUB(rpcmod, bindresvport,		nomod_minus_one);
	NO_UNLOAD_STUB(rpcmod, rdma_register_mod,	nomod_minus_one);
	NO_UNLOAD_STUB(rpcmod, rdma_unregister_mod,	nomod_minus_one);
	NO_UNLOAD_STUB(rpcmod, svc_queuereq,		nomod_minus_one);
	NO_UNLOAD_STUB(rpcmod, clist_add,		nomod_minus_one);
	END_MODULE(rpcmod);
#endif

/*
 * Stubs for des
 */
#ifndef DES_MODULE
	MODULE(des,misc);
	STUB(des, cbc_crypt, 	 	nomod_zero);
	STUB(des, ecb_crypt, 		nomod_zero);
	STUB(des, _des_crypt,		nomod_zero);
	END_MODULE(des);
#endif

/*
 * Stubs for procfs. A non-unloadable module.
 */
#ifndef PROC_MODULE
	MODULE(procfs,fs);
	NO_UNLOAD_STUB(procfs, prfree,		nomod_zero);
	NO_UNLOAD_STUB(procfs, prexit,		nomod_zero);
	NO_UNLOAD_STUB(procfs, prlwpfree,	nomod_zero);
	NO_UNLOAD_STUB(procfs, prlwpexit,	nomod_zero);
	NO_UNLOAD_STUB(procfs, prinvalidate,	nomod_zero);
	NO_UNLOAD_STUB(procfs, prnsegs,		nomod_zero);
	NO_UNLOAD_STUB(procfs, prgetcred,	nomod_zero);
	NO_UNLOAD_STUB(procfs, prgetpriv,	nomod_zero);
	NO_UNLOAD_STUB(procfs, prgetprivsize,	nomod_zero);
	NO_UNLOAD_STUB(procfs, prgetsecflags,	nomod_zero);        
	NO_UNLOAD_STUB(procfs, prgetstatus,	nomod_zero);
	NO_UNLOAD_STUB(procfs, prgetlwpstatus,	nomod_zero);
	NO_UNLOAD_STUB(procfs, prgetpsinfo,	nomod_zero);
	NO_UNLOAD_STUB(procfs, prgetlwpsinfo,	nomod_zero);
	NO_UNLOAD_STUB(procfs, oprgetstatus,	nomod_zero);
	NO_UNLOAD_STUB(procfs, oprgetpsinfo,	nomod_zero);
#ifdef _SYSCALL32_IMPL
	NO_UNLOAD_STUB(procfs, prgetstatus32,	nomod_zero);
	NO_UNLOAD_STUB(procfs, prgetlwpstatus32, nomod_zero);
	NO_UNLOAD_STUB(procfs, prgetpsinfo32,	nomod_zero);
	NO_UNLOAD_STUB(procfs, prgetlwpsinfo32,	nomod_zero);
	NO_UNLOAD_STUB(procfs, oprgetstatus32,	nomod_zero);
	NO_UNLOAD_STUB(procfs, oprgetpsinfo32,	nomod_zero);
	NO_UNLOAD_STUB(procfs, psinfo_kto32,	nomod_zero);
	NO_UNLOAD_STUB(procfs, lwpsinfo_kto32,	nomod_zero);
#endif	/* _SYSCALL32_IMPL */
	NO_UNLOAD_STUB(procfs, prnotify,	nomod_zero);
	NO_UNLOAD_STUB(procfs, prexecstart,	nomod_zero);
	NO_UNLOAD_STUB(procfs, prexecend,	nomod_zero);
	NO_UNLOAD_STUB(procfs, prrelvm,		nomod_zero);
	NO_UNLOAD_STUB(procfs, prbarrier,	nomod_zero);
	NO_UNLOAD_STUB(procfs, estimate_msacct,	nomod_zero);
	NO_UNLOAD_STUB(procfs, pr_getprot,	nomod_zero);
	NO_UNLOAD_STUB(procfs, pr_getprot_done,	nomod_zero);
	NO_UNLOAD_STUB(procfs, pr_getsegsize,	nomod_zero);
	NO_UNLOAD_STUB(procfs, pr_isobject,	nomod_zero);
	NO_UNLOAD_STUB(procfs, pr_isself,	nomod_zero);
	NO_UNLOAD_STUB(procfs, pr_allstopped,	nomod_zero);
	NO_UNLOAD_STUB(procfs, pr_free_watched_pages, nomod_zero);
	END_MODULE(procfs);
#endif

/*
 * Stubs for fifofs
 */
#ifndef FIFO_MODULE
	MODULE(fifofs,fs);
	STUB(fifofs, fifovp,      	0);
	STUB(fifofs, fifo_getinfo,	0);
	STUB(fifofs, fifo_vfastoff,	0);
	END_MODULE(fifofs);
#endif

/*
 * Stubs for ufs
 *
 * This is needed to support the old quotactl system call.
 * When the old sysent stuff goes away, this will need to be revisited.
 */
#ifndef UFS_MODULE
	MODULE(ufs,fs);
	STUB(ufs, quotactl, nomod_minus_one);
	STUB(ufs, ufs_remountroot, 0);
	END_MODULE(ufs);
#endif

/*
 * Stubs for zfs
 */
#ifndef ZFS_MODULE
	MODULE(zfs,fs);
	STUB(zfs, dsl_prop_get, nomod_minus_one);
	STUB(zfs, spa_boot_init, nomod_minus_one);
	STUB(zfs, zfs_prop_to_name, nomod_zero);
	END_MODULE(zfs);
#endif

/*
 * Stubs for dcfs
 */
#ifndef DCFS_MODULE
	MODULE(dcfs,fs);
	STUB(dcfs, decompvp, 0);
	END_MODULE(dcfs);
#endif

/*
 * Stubs for namefs
 */
#ifndef NAMEFS_MODULE
	MODULE(namefs,fs);
	STUB(namefs, nm_unmountall, 	0);
	END_MODULE(namefs);
#endif

/*
 * Stubs for sysdc
 */
#ifndef SDC_MODULE
	MODULE(SDC,sched);
	NO_UNLOAD_STUB(SDC, sysdc_thread_enter,		nomod_zero);
	END_MODULE(SDC);
#endif

/*
 * Stubs for ts_dptbl
 */
#ifndef TS_DPTBL_MODULE
	MODULE(TS_DPTBL,sched);
	STUB(TS_DPTBL, ts_getdptbl,		0);
	STUB(TS_DPTBL, ts_getkmdpris,		0);
	STUB(TS_DPTBL, ts_getmaxumdpri,	0);
	END_MODULE(TS_DPTBL);
#endif

/*
 * Stubs for rt_dptbl
 */
#ifndef RT_DPTBL_MODULE
	MODULE(RT_DPTBL,sched);
	STUB(RT_DPTBL, rt_getdptbl,		0);
	END_MODULE(RT_DPTBL);
#endif

/*
 * Stubs for ia_dptbl
 */
#ifndef IA_DPTBL_MODULE
	MODULE(IA_DPTBL,sched);
	STUB(IA_DPTBL, ia_getdptbl,		0);
	STUB(IA_DPTBL, ia_getkmdpris,		0);
	STUB(IA_DPTBL, ia_getmaxumdpri,	0);
	END_MODULE(IA_DPTBL);
#endif

/*
 * Stubs for FSS scheduler
 */
#ifndef	FSS_MODULE
	MODULE(FSS,sched);
	WSTUB(FSS, fss_allocbuf,		nomod_zero);
	WSTUB(FSS, fss_freebuf,			nomod_zero);
	WSTUB(FSS, fss_changeproj,		nomod_zero);
	WSTUB(FSS, fss_changepset,		nomod_zero);
	END_MODULE(FSS);
#endif	

/*
 * Stubs for fx_dptbl
 */
#ifndef FX_DPTBL_MODULE
	MODULE(FX_DPTBL,sched);
	STUB(FX_DPTBL, fx_getdptbl,		0);
	STUB(FX_DPTBL, fx_getmaxumdpri,		0);
	END_MODULE(FX_DPTBL);
#endif

/*
 * Stubs for kb (only needed for 'win')
 */
#ifndef KB_MODULE
	MODULE(kb,strmod);
	STUB(kb, strsetwithdecimal,	0);
	END_MODULE(kb);
#endif

/*
 * Stubs for swapgeneric
 */
#ifndef SWAPGENERIC_MODULE
	MODULE(swapgeneric,misc);
	STUB(swapgeneric, rootconf,     0);
	STUB(swapgeneric, svm_rootconf, 0);
	STUB(swapgeneric, getrootdev,   0);
	STUB(swapgeneric, getfsname,    0);
	STUB(swapgeneric, loadrootmodules, 0);
	END_MODULE(swapgeneric);
#endif

/*
 * Stubs for bootdev
 */
#ifndef BOOTDEV_MODULE
	MODULE(bootdev,misc);
	STUB(bootdev, i_devname_to_promname, 0);
	STUB(bootdev, i_promname_to_devname, 0);
	STUB(bootdev, i_convert_boot_device_name, 0);
	END_MODULE(bootdev);
#endif

/*
 * stubs for strplumb...
 */
#ifndef STRPLUMB_MODULE
	MODULE(strplumb,misc);
	STUB(strplumb, strplumb,     0);
	STUB(strplumb, strplumb_load, 0);
	STUB(strplumb, strplumb_get_netdev_path, 0)
	END_MODULE(strplumb);
#endif

/*
 * Stubs for console configuration module
 */
#ifndef CONSCONFIG_MODULE
	MODULE(consconfig,misc);
	STUB(consconfig, consconfig,	0);
	STUB(consconfig, consconfig_get_usb_kb_path,	0);
	STUB(consconfig, consconfig_get_usb_ms_path,	0);
	STUB(consconfig, consconfig_console_is_ready,	0);
	END_MODULE(consconfig);
#endif

/*
 * Stubs for zs (uart) module
 */
#ifndef ZS_MODULE
	MODULE(zs,drv);
	STUB(zs, zsgetspeed,		0);
	END_MODULE(zs);
#endif

/* 
 * Stubs for accounting.
 */
#ifndef SYSACCT_MODULE
	MODULE(sysacct,sys);
	WSTUB(sysacct, acct,  		nomod_zero);
	WSTUB(sysacct, acct_fs_in_use,	nomod_zero);
	END_MODULE(sysacct);
#endif

/*
 * Stubs for semaphore routines. sem.c
 */
#ifndef SEMSYS_MODULE
	MODULE(semsys,sys);
	WSTUB(semsys, semexit,		nomod_zero);
	END_MODULE(semsys);
#endif

/*
 * Stubs for shmem routines. shm.c
 */
#ifndef SHMSYS_MODULE
	MODULE(shmsys,sys);
	WSTUB(shmsys, shmexit,		nomod_zero);
	WSTUB(shmsys, shmfork,		nomod_zero);
	WSTUB(shmsys, shmgetid,		nomod_minus_one);
	END_MODULE(shmsys);
#endif

/*
 * Stubs for doors
 */
#ifndef DOORFS_MODULE
	MODULE(doorfs,sys);
	WSTUB(doorfs, door_slam,			nomod_zero);
	WSTUB(doorfs, door_exit,			nomod_zero);
	WSTUB(doorfs, door_revoke_all,			nomod_zero);
	WSTUB(doorfs, door_fork,			nomod_zero);
	NO_UNLOAD_STUB(doorfs, door_upcall,		nomod_einval);
	NO_UNLOAD_STUB(doorfs, door_ki_create,		nomod_einval);
	NO_UNLOAD_STUB(doorfs, door_ki_open,		nomod_einval);
	NO_UNLOAD_STUB(doorfs, door_ki_lookup,		nomod_zero);
	WSTUB(doorfs, door_ki_upcall,			nomod_einval);
	WSTUB(doorfs, door_ki_upcall_limited,		nomod_einval);
	WSTUB(doorfs, door_ki_hold,			nomod_zero);
	WSTUB(doorfs, door_ki_rele,			nomod_zero);
	WSTUB(doorfs, door_ki_info,			nomod_einval);
	END_MODULE(doorfs);
#endif

/*
 * Stubs for idmap
 */
#ifndef IDMAP_MODULE
	MODULE(idmap,misc);
	STUB(idmap, kidmap_batch_getgidbysid,	nomod_zero);
	STUB(idmap, kidmap_batch_getpidbysid,	nomod_zero);
	STUB(idmap, kidmap_batch_getsidbygid,	nomod_zero);
	STUB(idmap, kidmap_batch_getsidbyuid,	nomod_zero);
	STUB(idmap, kidmap_batch_getuidbysid,	nomod_zero);
	STUB(idmap, kidmap_get_create,		nomod_zero);
	STUB(idmap, kidmap_get_destroy,		nomod_zero);
	STUB(idmap, kidmap_get_mappings,	nomod_zero);
	STUB(idmap, kidmap_getgidbysid,		nomod_zero);
	STUB(idmap, kidmap_getpidbysid,		nomod_zero);
	STUB(idmap, kidmap_getsidbygid,		nomod_zero);
	STUB(idmap, kidmap_getsidbyuid,		nomod_zero);
	STUB(idmap, kidmap_getuidbysid,		nomod_zero);
	STUB(idmap, idmap_get_door,		nomod_einval);
	STUB(idmap, idmap_unreg_dh,		nomod_einval);
	STUB(idmap, idmap_reg_dh,		nomod_einval);
	STUB(idmap, idmap_purge_cache,		nomod_einval);
	END_MODULE(idmap);
#endif

/*
 * Stubs for dma routines. dmaga.c
 * (These are only needed for cross-checks, not autoloading)
 */
#ifndef DMA_MODULE
	MODULE(dma,drv);
	WSTUB(dma, dma_alloc,		nomod_zero); /* (DMAGA *)0 */
	WSTUB(dma, dma_free,		nomod_zero); /* (DMAGA *)0 */
	END_MODULE(dma);
#endif

/*
 * Stubs for auditing.
 */
#ifndef C2AUDIT_MODULE
	MODULE(c2audit,sys);
	NO_UNLOAD_STUB(c2audit, audit_init_module,	nomod_zero);
	NO_UNLOAD_STUB(c2audit, audit_start, 		nomod_zero);
	NO_UNLOAD_STUB(c2audit, audit_finish,		nomod_zero);
	NO_UNLOAD_STUB(c2audit, audit,			nomod_zero);
	NO_UNLOAD_STUB(c2audit, auditdoor,		nomod_zero);
	NO_UNLOAD_STUB(c2audit, audit_closef,		nomod_zero);
	NO_UNLOAD_STUB(c2audit, audit_core_start,	nomod_zero);
	NO_UNLOAD_STUB(c2audit, audit_core_finish,	nomod_zero);
	NO_UNLOAD_STUB(c2audit, audit_strputmsg,	nomod_zero);
	NO_UNLOAD_STUB(c2audit, audit_savepath,		nomod_zero);
	NO_UNLOAD_STUB(c2audit, audit_anchorpath,	nomod_zero);
	NO_UNLOAD_STUB(c2audit, audit_exit,		nomod_zero);
	NO_UNLOAD_STUB(c2audit, audit_exec,		nomod_zero);
	NO_UNLOAD_STUB(c2audit, audit_symlink,		nomod_zero);
	NO_UNLOAD_STUB(c2audit, audit_symlink_create,	nomod_zero);
	NO_UNLOAD_STUB(c2audit, audit_vncreate_start,	nomod_zero);
	NO_UNLOAD_STUB(c2audit, audit_vncreate_finish,	nomod_zero);
	NO_UNLOAD_STUB(c2audit, audit_enterprom,	nomod_zero);
	NO_UNLOAD_STUB(c2audit, audit_exitprom,		nomod_zero);
	NO_UNLOAD_STUB(c2audit, audit_chdirec,		nomod_zero);
	NO_UNLOAD_STUB(c2audit, audit_setf,		nomod_zero);
	NO_UNLOAD_STUB(c2audit, audit_sock,		nomod_zero);
	NO_UNLOAD_STUB(c2audit, audit_strgetmsg,	nomod_zero);
	NO_UNLOAD_STUB(c2audit, audit_ipc,		nomod_zero);
	NO_UNLOAD_STUB(c2audit, audit_ipcget,		nomod_zero);
	NO_UNLOAD_STUB(c2audit, audit_fdsend,		nomod_zero);
	NO_UNLOAD_STUB(c2audit, audit_fdrecv,		nomod_zero);
	NO_UNLOAD_STUB(c2audit, audit_priv,		nomod_zero);
	NO_UNLOAD_STUB(c2audit, audit_setppriv,		nomod_zero);
	NO_UNLOAD_STUB(c2audit, audit_psecflags,	nomod_zero);
	NO_UNLOAD_STUB(c2audit, audit_devpolicy,	nomod_zero);
	NO_UNLOAD_STUB(c2audit, audit_setfsat_path,	nomod_zero);
	NO_UNLOAD_STUB(c2audit, audit_cryptoadm,	nomod_zero);
	NO_UNLOAD_STUB(c2audit, audit_kssl,		nomod_zero);
	NO_UNLOAD_STUB(c2audit, audit_pf_policy,	nomod_zero);
	NO_UNLOAD_STUB(c2audit, au_doormsg,		nomod_zero);
	NO_UNLOAD_STUB(c2audit, au_uwrite,		nomod_zero);
	NO_UNLOAD_STUB(c2audit, au_to_arg32,		nomod_zero);
	NO_UNLOAD_STUB(c2audit, au_free_rec,		nomod_zero);
	END_MODULE(c2audit);
#endif

/*
 * Stubs for kernel rpc security service module
 */
#ifndef RPCSEC_MODULE
	MODULE(rpcsec,misc);
	NO_UNLOAD_STUB(rpcsec, sec_clnt_revoke,		nomod_zero);
	NO_UNLOAD_STUB(rpcsec, authkern_create,		nomod_zero);
	NO_UNLOAD_STUB(rpcsec, sec_svc_msg,		nomod_zero);
	NO_UNLOAD_STUB(rpcsec, sec_svc_control,		nomod_zero);
	END_MODULE(rpcsec);
#endif

/*
 * Stubs for rpc RPCSEC_GSS security service module
 */
#ifndef RPCSEC_GSS_MODULE
	MODULE(rpcsec_gss,misc);
	NO_UNLOAD_STUB(rpcsec_gss, __svcrpcsec_gss,		nomod_zero);
	NO_UNLOAD_STUB(rpcsec_gss, rpc_gss_getcred,		nomod_zero);
	NO_UNLOAD_STUB(rpcsec_gss, rpc_gss_set_callback,	nomod_zero);
	NO_UNLOAD_STUB(rpcsec_gss, rpc_gss_secget,		nomod_zero);
	NO_UNLOAD_STUB(rpcsec_gss, rpc_gss_secfree,		nomod_zero);
	NO_UNLOAD_STUB(rpcsec_gss, rpc_gss_seccreate,		nomod_zero);
	NO_UNLOAD_STUB(rpcsec_gss, rpc_gss_set_defaults,	nomod_zero);
	NO_UNLOAD_STUB(rpcsec_gss, rpc_gss_revauth,		nomod_zero);
	NO_UNLOAD_STUB(rpcsec_gss, rpc_gss_secpurge,		nomod_zero);
	NO_UNLOAD_STUB(rpcsec_gss, rpc_gss_cleanup,		nomod_zero);
	NO_UNLOAD_STUB(rpcsec_gss, rpc_gss_get_versions,	nomod_zero);
	NO_UNLOAD_STUB(rpcsec_gss, rpc_gss_max_data_length,	nomod_zero);
	NO_UNLOAD_STUB(rpcsec_gss, rpc_gss_svc_max_data_length,	nomod_zero);
	NO_UNLOAD_STUB(rpcsec_gss, rpc_gss_get_service_type,	nomod_zero);
	END_MODULE(rpcsec_gss);
#endif

#ifndef IWSCN_MODULE
	MODULE(iwscn,drv);
	STUB(iwscn, srpop, 0);
	END_MODULE(iwscn);
#endif

/*
 * Stubs for checkpoint-resume module
 */
#ifndef CPR_MODULE
        MODULE(cpr,misc);
        STUB(cpr, cpr, 0);
        END_MODULE(cpr);
#endif

/*
 * Stubs for VIS module
 */
#ifndef VIS_MODULE
        MODULE(vis,misc);
        STUB(vis, vis_fpu_simulator, 0);
        STUB(vis, vis_fldst, 0);
        STUB(vis, vis_rdgsr, 0);
        STUB(vis, vis_wrgsr, 0);
        END_MODULE(vis);
#endif

/*
 * Stubs for kernel probes (tnf module).  Not unloadable.
 */
#ifndef TNF_MODULE
	MODULE(tnf,drv);
	NO_UNLOAD_STUB(tnf, tnf_ref32_1,	nomod_zero);
	NO_UNLOAD_STUB(tnf, tnf_string_1,	nomod_zero);
	NO_UNLOAD_STUB(tnf, tnf_opaque_array_1,	nomod_zero);
	NO_UNLOAD_STUB(tnf, tnf_opaque32_array_1, nomod_zero);
	NO_UNLOAD_STUB(tnf, tnf_struct_tag_1,	nomod_zero);
	NO_UNLOAD_STUB(tnf, tnf_allocate,	nomod_zero);
	END_MODULE(tnf);
#endif

/*
 * Clustering: stubs for bootstrapping.
 */
#ifndef CL_BOOTSTRAP
	MODULE(cl_bootstrap,misc);
	NO_UNLOAD_WSTUB(cl_bootstrap, clboot_modload, nomod_minus_one);
	NO_UNLOAD_WSTUB(cl_bootstrap, clboot_loadrootmodules, nomod_zero);
	NO_UNLOAD_WSTUB(cl_bootstrap, clboot_rootconf, nomod_zero);
	NO_UNLOAD_WSTUB(cl_bootstrap, clboot_mountroot, nomod_zero);
	NO_UNLOAD_WSTUB(cl_bootstrap, clconf_init, nomod_zero);
	NO_UNLOAD_WSTUB(cl_bootstrap, clconf_get_nodeid, nomod_zero);
	NO_UNLOAD_WSTUB(cl_bootstrap, clconf_maximum_nodeid, nomod_zero);
	NO_UNLOAD_WSTUB(cl_bootstrap, cluster, nomod_zero);
	END_MODULE(cl_bootstrap);
#endif

/*
 * Clustering: stubs for cluster infrastructure.
 */	
#ifndef CL_COMM_MODULE
	MODULE(cl_comm,misc);
	NO_UNLOAD_STUB(cl_comm, cladmin, nomod_minus_one);
	END_MODULE(cl_comm);
#endif

/*
 * Clustering: stubs for global file system operations.
 */
#ifndef PXFS_MODULE
	MODULE(pxfs,fs);
	NO_UNLOAD_WSTUB(pxfs, clpxfs_aio_read, nomod_zero);
	NO_UNLOAD_WSTUB(pxfs, clpxfs_aio_write, nomod_zero);
	NO_UNLOAD_WSTUB(pxfs, cl_flk_state_transition_notify, nomod_zero);
	END_MODULE(pxfs);
#endif

/*
 * Stubs for PCI configurator module (misc/pcicfg).
 */
#ifndef	PCICFG_MODULE
	MODULE(pcicfg,misc);
	STUB(pcicfg, pcicfg_configure, 0);
	STUB(pcicfg, pcicfg_unconfigure, 0);
	END_MODULE(pcicfg);
#endif

#ifndef PCIHP_MODULE
	MODULE(pcihp,misc);
	WSTUB(pcihp, pcihp_init, nomod_minus_one);
	WSTUB(pcihp, pcihp_uninit, nomod_minus_one);
	WSTUB(pcihp, pcihp_info, nomod_minus_one);
	WSTUB(pcihp, pcihp_get_cb_ops, nomod_zero);
	END_MODULE(pcihp); 
#endif

/*
 * Stubs for kernel cryptographic framework module (misc/kcf).
 */
#ifndef KCF_MODULE
	MODULE(kcf,misc);
	NO_UNLOAD_STUB(kcf, crypto_mech2id, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_register_provider, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_unregister_provider, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_provider_notification, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_op_notification, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_kmflag, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_digest, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_digest_prov, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_digest_init, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_digest_init_prov, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_digest_update, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_digest_final, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_digest_key_prov, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_encrypt, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_encrypt_prov, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_encrypt_init, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_encrypt_init_prov, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_encrypt_update, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_encrypt_final, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_decrypt, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_decrypt_prov, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_decrypt_init, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_decrypt_init_prov, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_decrypt_update, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_decrypt_final, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_get_all_mech_info, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_key_check, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_key_check_prov, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_key_derive, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_key_generate, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_key_generate_pair, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_key_unwrap, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_key_wrap, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_mac, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_mac_prov, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_mac_verify, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_mac_verify_prov, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_mac_init, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_mac_init_prov, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_mac_update, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_mac_final, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_mac_decrypt, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_mac_decrypt_prov, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_mac_verify_decrypt, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_mac_verify_decrypt_prov, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_mac_decrypt_init, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_mac_decrypt_init_prov, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_mac_decrypt_update, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_mac_decrypt_final, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_object_copy, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_object_create, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_object_destroy, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_object_find_final, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_object_find_init, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_object_find, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_object_get_attribute_value, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_object_get_size, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_object_set_attribute_value, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_session_close, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_session_login, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_session_logout, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_session_open, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_encrypt_mac, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_encrypt_mac_prov, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_encrypt_mac_init, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_encrypt_mac_init_prov, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_encrypt_mac_update, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_encrypt_mac_final, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_create_ctx_template, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_destroy_ctx_template, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_get_mech_list, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_free_mech_list, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_cancel_req, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_cancel_ctx, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_bufcall_alloc, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_bufcall_free, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_bufcall, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_unbufcall, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_notify_events, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_unnotify_events, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_get_provider, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_get_provinfo, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_release_provider, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_sign, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_sign_prov, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_sign_init, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_sign_init_prov, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_sign_update, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_sign_final, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_sign_recover, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_sign_recover_prov, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_sign_recover_init_prov, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_verify, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_verify_prov, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_verify_init, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_verify_init_prov, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_verify_update, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_verify_final, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_verify_recover, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_verify_recover_prov, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, crypto_verify_recover_init_prov, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, random_add_entropy, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, random_add_pseudo_entropy, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, random_get_blocking_bytes, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, random_get_bytes, nomod_minus_one);
	NO_UNLOAD_STUB(kcf, random_get_pseudo_bytes, nomod_minus_one);
	END_MODULE(kcf);
#endif

/*
 * Stubs for sha1. A non-unloadable module.
 */
#ifndef SHA1_MODULE
	MODULE(sha1,crypto);
	NO_UNLOAD_STUB(sha1, SHA1Init, nomod_void);
	NO_UNLOAD_STUB(sha1, SHA1Update, nomod_void);
	NO_UNLOAD_STUB(sha1, SHA1Final,	nomod_void);
	END_MODULE(sha1);
#endif

/*
 * The following stubs are used by the mac module.
 * Since dld already depends on mac, these
 * stubs are needed to avoid circular dependencies.
 */
#ifndef	DLD_MODULE
	MODULE(dld,drv);
	STUB(dld, dld_init_ops, nomod_void);
	STUB(dld, dld_fini_ops, nomod_void);
	STUB(dld, dld_autopush, nomod_minus_one);
	STUB(dld, dld_devt_to_instance, nomod_minus_one);
	STUB(dld, dld_ioc_register, nomod_einval);
	STUB(dld, dld_ioc_unregister, nomod_void);
	END_MODULE(dld);
#endif

/*
 * The following stubs are used by the mac module.
 * Since dls already depends on mac, these
 * stubs are needed to avoid circular dependencies.
 */
#ifndef	DLS_MODULE
	MODULE(dls,misc);
	STUB(dls, dls_devnet_mac, nomod_zero);
	STUB(dls, dls_devnet_hold_tmp, nomod_einval);
	STUB(dls, dls_devnet_rele_tmp, nomod_void);
	STUB(dls, dls_devnet_hold_link, nomod_einval);
	STUB(dls, dls_devnet_rele_link, nomod_void);
	STUB(dls, dls_devnet_prop_task_wait, nomod_void);
	STUB(dls, dls_mgmt_get_linkid, nomod_einval);
	STUB(dls, dls_devnet_macname2linkid, nomod_einval);
	STUB(dls, dls_mgmt_get_linkinfo, nomod_einval);
	END_MODULE(dls);
#endif

#ifndef SOFTMAC_MODULE
	MODULE(softmac,drv);
	STUB(softmac, softmac_hold_device, nomod_einval);
	STUB(softmac, softmac_rele_device, nomod_void);
	STUB(softmac, softmac_recreate, nomod_void);
	END_MODULE(softmac);
#endif

#ifndef IPTUN_MODULE
	MODULE(iptun,drv);
	STUB(iptun, iptun_create, nomod_einval);
	STUB(iptun, iptun_delete, nomod_einval);
	STUB(iptun, iptun_set_policy, nomod_einval);
	END_MODULE(iptun);
#endif

/*
 * Stubs for dcopy, for Intel IOAT KAPIs
 */
#ifndef DCOPY_MODULE
	MODULE(dcopy,misc);
	NO_UNLOAD_STUB(dcopy, dcopy_query, nomod_minus_one);
	NO_UNLOAD_STUB(dcopy, dcopy_query_channel, nomod_minus_one);
	NO_UNLOAD_STUB(dcopy, dcopy_alloc, nomod_minus_one);
	NO_UNLOAD_STUB(dcopy, dcopy_free, nomod_minus_one);
	NO_UNLOAD_STUB(dcopy, dcopy_cmd_alloc, nomod_minus_one);
	NO_UNLOAD_STUB(dcopy, dcopy_cmd_free, nomod_void);
	NO_UNLOAD_STUB(dcopy, dcopy_cmd_post, nomod_minus_one);
	NO_UNLOAD_STUB(dcopy, dcopy_cmd_poll, nomod_minus_one);
	END_MODULE(dcopy);
#endif

#ifndef IPNET_MODULE
	MODULE(ipnet,drv);
	STUB(ipnet, ipnet_if_getdev, nomod_zero);
	STUB(ipnet, ipnet_walk_if, nomod_zero);
	END_MODULE(ipnet);
#endif

/*
 * Stubs for kernel socket, for iscsi
 */
#ifndef KSOCKET_MODULE
	MODULE(ksocket, misc);
	NO_UNLOAD_STUB(ksocket, ksocket_setsockopt, nomod_minus_one);
	NO_UNLOAD_STUB(ksocket, ksocket_getsockopt, nomod_minus_one);
	NO_UNLOAD_STUB(ksocket, ksocket_getpeername, nomod_minus_one);
	NO_UNLOAD_STUB(ksocket, ksocket_getsockname, nomod_minus_one);
	NO_UNLOAD_STUB(ksocket, ksocket_socket, nomod_minus_one);
	NO_UNLOAD_STUB(ksocket, ksocket_bind, nomod_minus_one);
	NO_UNLOAD_STUB(ksocket, ksocket_listen, nomod_minus_one);
	NO_UNLOAD_STUB(ksocket, ksocket_accept, nomod_minus_one);
	NO_UNLOAD_STUB(ksocket, ksocket_connect, nomod_minus_one);
	NO_UNLOAD_STUB(ksocket, ksocket_recv, nomod_minus_one);
	NO_UNLOAD_STUB(ksocket, ksocket_recvfrom, nomod_minus_one);
	NO_UNLOAD_STUB(ksocket, ksocket_recvmsg, nomod_minus_one);
	NO_UNLOAD_STUB(ksocket, ksocket_send, nomod_minus_one);
	NO_UNLOAD_STUB(ksocket, ksocket_sendto, nomod_minus_one);
	NO_UNLOAD_STUB(ksocket, ksocket_sendmsg, nomod_minus_one);
	NO_UNLOAD_STUB(ksocket, ksocket_ioctl, nomod_minus_one);
	NO_UNLOAD_STUB(ksocket, ksocket_setcallbacks, nomod_minus_one);
	NO_UNLOAD_STUB(ksocket, ksocket_hold, nomod_minus_one);
	NO_UNLOAD_STUB(ksocket, ksocket_rele, nomod_minus_one);
	NO_UNLOAD_STUB(ksocket, ksocket_shutdown, nomod_minus_one);
	NO_UNLOAD_STUB(ksocket, ksocket_close, nomod_minus_one);
	END_MODULE(ksocket);
#endif

/*
 * Stubs for elfexec
 */
#ifndef ELFEXEC_MODULE
	MODULE(elfexec,exec);
	STUB(elfexec, elfexec,      	nomod_einval);
	STUB(elfexec, elf32exec,	nomod_einval);
	STUB(elfexec, mapexec_brand,	nomod_einval);
	STUB(elfexec, mapexec32_brand,	nomod_einval);
	END_MODULE(elfexec);
#endif

! this is just a marker for the area of text that contains stubs
	.seg ".text"
	.global stubs_end
stubs_end:
	nop

#endif	/* lint */
