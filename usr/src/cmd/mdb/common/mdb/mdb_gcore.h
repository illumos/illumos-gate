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
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

#ifndef	_MDB_GCORE_H
#define	_MDB_GCORE_H

/*
 * The kernel has its own definition of exit which has a different signature
 * than the user space definition.  This seems to be the standard way to deal
 * with this.
 */
#define	exit kern_exit

#include <sys/cpuvar.h>
#include <sys/cred_impl.h>
#include <sys/procfs.h>
#include <vm/anon.h>

#undef exit

/* mdb versions of kernel structures used for ctf read calls */
typedef struct mdb_proc {
	uintptr_t	p_as;
	uintptr_t	p_brkbase;
	size_t		p_brksize;
	uintptr_t	p_usrstack;
	size_t		p_stksize;
	user_t		p_user;
	uintptr_t	p_agenttp;
	uintptr_t	p_tlist;
	uintptr_t	p_zone;
	uintptr_t	p_ldt;
	kcondvar_t	p_holdlwps;
	int		p_lwpcnt;
	uintptr_t	p_lwpdir;
	uint_t		p_lwpdir_sz;
	uintptr_t	p_cred;
	uint_t		p_flag;
	int		p_zombcnt;
	uintptr_t	p_pidp;
	pid_t		p_ppid;
	uintptr_t	p_pgidp;
	uintptr_t	p_sessp;
	uintptr_t	p_task;
	uintptr_t	p_pool;
	model_t		p_model;
	char		p_wcode;
	ushort_t	p_ldtlimit;
	uintptr_t	p_exec;
	uint_t		p_proc_flag;
	ushort_t	p_pidflag;
	k_sigset_t	p_ignore;
	k_sigset_t	p_siginfo;
	k_sigset_t	p_sig;
	k_sigset_t	p_sigmask;
	k_fltset_t	p_fltmask;
	int		p_wdata;
} mdb_proc_t;

typedef struct mdb_kthread {
	ushort_t	t_proc_flag;
	uint_t		t_state;
	lwpchan_t	t_lwpchan;
	ushort_t	t_whystop;
	uint8_t		t_dtrace_stop;
	uintptr_t	t_forw;
	uintptr_t	t_lwp;
	id_t		t_tid;
	short		t_sysnum;
	pri_t		t_pri;
	time_t		t_start;
	id_t		t_cid;
	uintptr_t	t_cpu;
	int		t_bind_pset;
	short		t_bind_cpu;
	uintptr_t	t_lpl;
	ushort_t	t_schedflag;
	ushort_t	t_whatstop;
	k_sigset_t	t_sig;
	uintptr_t	t_schedctl;
	k_sigset_t	t_hold;
	hrtime_t	t_stoptime;
} mdb_kthread_t;

typedef struct mdb_seg {
	uintptr_t	s_base;
	size_t		s_size;
	uintptr_t	s_ops;
	uintptr_t	s_data;
	uintptr_t	s_as;
} mdb_seg_t;

typedef struct mdb_as {
	uintptr_t	a_proc;
} mdb_as_t;

typedef struct mdb_segvn_data {
	uintptr_t	vp;
	uint64_t	offset;
	uint16_t	flags;
	uint8_t		pageprot;
	uint8_t		prot;
	uintptr_t	amp;
	struct vpage	*vpage;
	uint64_t	anon_index;
	uint8_t		type;
} mdb_segvn_data_t;

typedef struct mdb_vnode {
	enum vtype	v_type;
	uintptr_t	v_data;
	uintptr_t	v_op;
	uintptr_t	v_path;
} mdb_vnode_t;

typedef struct mdb_znode {
	uint64_t	z_size;
} mdb_znode_t;

typedef struct mdb_tmpnode {
	vattr_t		tn_attr;
} mdb_tmpnode_t;

typedef struct mdb_vnodeops {
	uintptr_t	vnop_name;
} mdb_vnodeops_t;

typedef struct mdb_shm_data {
	uintptr_t	shm_sptseg;
} mdb_shm_data_t;

typedef struct mdb_watched_page {
	uintptr_t	wp_vaddr;
	uint8_t		wp_oprot;
} mdb_watched_page_t;

typedef struct mdb_pid {
	pid_t		pid_id;
} mdb_pid_t;

typedef struct mdb_sess {
	uintptr_t	s_sidp;
} mdb_sess_t;

typedef struct mdb_task {
	taskid_t	tk_tkid;
	uintptr_t	tk_proj;
} mdb_task_t;

typedef struct mdb_kproject {
	projid_t	kpj_id;
} mdb_kproject_t;

typedef struct mdb_zone {
	zoneid_t	zone_id;
	uintptr_t	zone_name;
} mdb_zone_t;

typedef struct mdb_sc_shared {
	char		sc_sigblock;
} mdb_sc_shared_t;

typedef struct mdb_klwp {
	uintptr_t	lwp_regs;
	struct pcb	lwp_pcb;
	uchar_t		lwp_asleep;
	uchar_t		lwp_cursig;
	uintptr_t	lwp_curinfo;
	k_siginfo_t	lwp_siginfo;
	stack_t		lwp_sigaltstack;
	uintptr_t	lwp_oldcontext;
	short		lwp_badpriv;
	uintptr_t	lwp_ustack;
	char		lwp_eosys;
} mdb_klwp_t;

typedef struct mdb_cpu {
	processorid_t	cpu_id;
} mdb_cpu_t;

typedef struct mdb_lpl {
	lgrp_id_t	lpl_lgrpid;
} mdb_lpl_t;

typedef struct mdb_sigqueue {
	k_siginfo_t	sq_info;
} mdb_sigqueue_t;

typedef struct mdb_pool {
	poolid_t	pool_id;
} mdb_pool_t;

typedef struct mdb_amp {
	uintptr_t	ahp;
} mdb_amp_t;

typedef struct mdb_anon_hdr {
	pgcnt_t		size;
	uintptr_t	array_chunk;
	int		flags;
} mdb_anon_hdr_t;

typedef struct mdb_anon {
	uintptr_t	an_vp;
	anoff_t		an_off;
} mdb_anon_t;

/* Used to construct a linked list of prmap_ts */
typedef struct prmap_node {
	struct prmap_node *next;
	prmap_t		m;
} prmap_node_t;

/* Fields common to psinfo_t and pstatus_t */
typedef struct pcommon {
	int		pc_nlwp;
	int		pc_nzomb;
	pid_t		pc_pid;
	pid_t		pc_ppid;
	pid_t		pc_pgid;
	pid_t		pc_sid;
	taskid_t	pc_taskid;
	projid_t	pc_projid;
	zoneid_t	pc_zoneid;
	char		pc_dmodel;
} pcommon_t;

/* AVL walk callback structures */
typedef struct read_maps_cbarg {
	mdb_proc_t	*p;
	uintptr_t	brkseg;
	uintptr_t	stkseg;
	prmap_node_t	*map_head;
	prmap_node_t	*map_tail;
	int		map_len;
} read_maps_cbarg_t;

typedef struct as_segat_cbarg {
	uintptr_t	addr;
	uintptr_t	res;
} as_segat_cbarg_t;

typedef struct getwatchprot_cbarg {
	uintptr_t	wp_vaddr;
	mdb_watched_page_t wp;
	boolean_t	found;
} getwatchprot_cbarg_t;

struct gcore_segops;
typedef struct gcore_seg {
	mdb_seg_t	*gs_seg;
	void		*gs_data;
	struct gcore_segops *gs_ops;
} gcore_seg_t;

/*
 * These are the ISA-dependent functions that need to be
 * implemented for ::gcore.
 */
extern uintptr_t gcore_prgetstackbase(mdb_proc_t *);
extern int gcore_prfetchinstr(mdb_klwp_t *, ulong_t *);
extern int gcore_prisstep(mdb_klwp_t *);
extern void gcore_getgregs(mdb_klwp_t *, gregset_t);
extern int gcore_prgetrvals(mdb_klwp_t *, long *, long *);

#endif	/* _MDB_GCORE_H */
