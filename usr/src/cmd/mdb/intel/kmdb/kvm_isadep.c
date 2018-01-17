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
 *
 * Copyright 2018 Joyent, Inc.
 */

/*
 * isa-dependent portions of the kmdb target
 */

#include <kmdb/kvm.h>
#include <kmdb/kmdb_kdi.h>
#include <kmdb/kmdb_asmutil.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_list.h>
#include <mdb/mdb_target_impl.h>
#include <mdb/mdb_isautil.h>
#include <mdb/mdb_kreg_impl.h>
#include <mdb/mdb.h>

#include <sys/types.h>
#include <sys/frame.h>
#include <sys/trap.h>
#include <sys/bitmap.h>
#include <sys/pci_impl.h>

/* Higher than the highest trap number for which we have a defined specifier */
#define	KMT_MAXTRAPNO	0x20

#define	IOPORTLIMIT	0xffff	/* XXX find a new home for this */

const char *
kmt_def_dismode(void)
{
#ifdef	__amd64
	return ("amd64");
#else
	return ("ia32");
#endif
}

int
kmt_step_out_validate(mdb_tgt_t *t, uintptr_t pc)
{
	kmt_data_t *kmt = t->t_data;
	int i;

	for (i = 0; i < sizeof (kmt->kmt_intrsyms) / sizeof (GElf_Sym); i++) {
		GElf_Sym *sym = (GElf_Sym *)&kmt->kmt_intrsyms + i;

		if (pc >= sym->st_value && pc < sym->st_value + sym->st_size)
			return (0);
	}

	return (1);
}

/*
 * Determine the return address for the current frame.
 */
int
kmt_step_out(mdb_tgt_t *t, uintptr_t *p)
{
	mdb_instr_t instr;
	kreg_t pc, sp, fp;

	(void) kmdb_dpi_get_register("pc", &pc);
	(void) kmdb_dpi_get_register("sp", &sp);
	(void) kmdb_dpi_get_register("fp", &fp);

	if (mdb_tgt_vread(t, &instr, sizeof (mdb_instr_t), pc) !=
	    sizeof (mdb_instr_t))
		return (-1); /* errno is set for us */

	if (!kmt_step_out_validate(t, pc))
		return (set_errno(EMDB_TGTNOTSUP));

	return (mdb_isa_step_out(t, p, pc, fp, sp, instr));
}

/*
 * Return the address of the next instruction following a call, or return -1
 * and set errno to EAGAIN if the target should just single-step.
 */
int
kmt_next(mdb_tgt_t *t, uintptr_t *p)
{
	kreg_t pc;
	mdb_instr_t instr;

	(void) kmdb_dpi_get_register("pc", &pc);

	if (mdb_tgt_vread(t, &instr, sizeof (mdb_instr_t), pc) !=
	    sizeof (mdb_instr_t))
		return (-1); /* errno is set for us */

	return (mdb_isa_next(t, p, pc, instr));
}

/*ARGSUSED*/
static int
kmt_stack_common(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv,
    int cpuid, mdb_tgt_stack_f *func)
{
	const mdb_tgt_gregset_t *grp = NULL;
	mdb_tgt_gregset_t gregs;
	void *arg = (void *)(uintptr_t)mdb.m_nargs;

	if (flags & DCMD_ADDRSPEC) {
		bzero(&gregs, sizeof (gregs));
		gregs.kregs[KREG_FP] = addr;
		grp = &gregs;
	} else
		grp = kmdb_dpi_get_gregs(cpuid);

	if (grp == NULL) {
		warn("failed to retrieve registers for cpu %d", cpuid);
		return (DCMD_ERR);
	}

	if (argc != 0) {
		if (argv->a_type == MDB_TYPE_CHAR || argc > 1)
			return (DCMD_USAGE);

		if (argv->a_type == MDB_TYPE_STRING)
			arg = (void *)(uintptr_t)mdb_strtoull(argv->a_un.a_str);
		else
			arg = (void *)(uintptr_t)argv->a_un.a_val;
	}

	(void) mdb_isa_kvm_stack_iter(mdb.m_target, grp, func, arg);

	return (DCMD_OK);
}

int
kmt_cpustack(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv,
    int cpuid, int verbose)
{
	return (kmt_stack_common(addr, flags, argc, argv, cpuid,
	    (verbose ? mdb_isa_kvm_framev : mdb_isa_kvm_frame)));
}

int
kmt_stack(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (kmt_stack_common(addr, flags, argc, argv, DPI_MASTER_CPUID,
	    mdb_isa_kvm_frame));
}

int
kmt_stackv(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (kmt_stack_common(addr, flags, argc, argv, DPI_MASTER_CPUID,
	    mdb_isa_kvm_framev));
}

int
kmt_stackr(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (kmt_stack_common(addr, flags, argc, argv, DPI_MASTER_CPUID,
	    mdb_isa_kvm_framev));
}

/*ARGSUSED*/
void
kmt_printregs(const mdb_tgt_gregset_t *gregs)
{
	mdb_isa_printregs(gregs);
}

#define	IOCHECK_NOWARN	0
#define	IOCHECK_WARN	1

static int
kmt_io_check(uint64_t nbytes, uintptr_t addr, int dowarn)
{
	if (addr > IOPORTLIMIT) {
		if (dowarn)
			warn("port address must be 0-%#x\n", IOPORTLIMIT);
		return (set_errno(EINVAL));
	}

	if (nbytes != 1 && nbytes != 2 && nbytes != 4) {
		if (dowarn)
			warn("port access must be 1, 2, or 4 bytes\n");
		return (set_errno(EINVAL));
	}

	if ((addr & (nbytes - 1)) != 0) {
		if (dowarn) {
			warn("address for %llu-byte access must be %llu-byte "
			    "aligned\n", (u_longlong_t)nbytes,
			    (u_longlong_t)nbytes);
		}
		return (set_errno(EINVAL));
	}

	return (0);
}

/*ARGSUSED1*/
int
kmt_in_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint64_t len = 0;
	uint32_t buf;

	if (mdb_getopts(argc, argv,
	    'L', MDB_OPT_UINT64, &len,
	    NULL) != argc)
		return (DCMD_USAGE);

	if (len == 0)
		len = mdb.m_dcount;

	if (kmt_io_check(len, addr, IOCHECK_WARN) < 0)
		return (DCMD_ERR);

	if (mdb_tgt_ioread(mdb.m_target, &buf, len, addr) < 0) {
		warn("failed to read from port 0x%llx", (u_longlong_t)addr);
		return (DCMD_ERR);
	}

	mdb_printf("%x\n", buf);

	return (DCMD_OK);
}

static uint64_t
kmt_numarg(const mdb_arg_t *arg)
{
	if (arg->a_type == MDB_TYPE_STRING)
		return (mdb_strtoull(arg->a_un.a_str));
	else
		return (arg->a_un.a_val);
}

/*ARGSUSED1*/
int
kmt_out_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint64_t len = 0;
	uint64_t val;

	if (mdb_getopts(argc, argv,
	    'L', MDB_OPT_UINT64, &len,
	    NULL) != argc - 1)
		return (DCMD_USAGE);

	if (len == 0)
		len = mdb.m_dcount;

	argv += argc - 1;
	val = kmt_numarg(argv);

	if (kmt_io_check(len, addr, IOCHECK_WARN) < 0)
		return (DCMD_ERR);

	if (val > (1ULL << (len * NBBY)) - 1) {
		warn("value is out of range for port size\n");
		return (DCMD_ERR);
	}

	if (mdb_tgt_iowrite(mdb.m_target, &val, len, addr) < 0) {
		warn("failed to write to port %llx", (u_longlong_t)addr);
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

static int
kmt_rwmsr(uint32_t addr, uint64_t *valp, void (*rw)(uint32_t, uint64_t *))
{
	jmp_buf pcb, *oldpcb = NULL;

	if (setjmp(pcb) != 0) {
		kmdb_dpi_restore_fault_hdlr(oldpcb);
		return (-1); /* errno is set for us */
	}

	oldpcb = kmdb_dpi_set_fault_hdlr(&pcb);
	rw(addr, valp);
	kmdb_dpi_restore_fault_hdlr(oldpcb);

	return (0);
}

/*ARGSUSED*/
int
kmt_rdmsr(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint64_t val;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (kmt_rwmsr(addr, &val, rdmsr) < 0) {
		warn("rdmsr failed");
		return (DCMD_ERR);
	}

	mdb_printf("%llx\n", (u_longlong_t)val);

	return (DCMD_OK);
}

/*ARGSUSED*/
int
kmt_wrmsr(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint64_t val;

	if (!(flags & DCMD_ADDRSPEC) || argc != 1)
		return (DCMD_USAGE);

	val = kmt_numarg(argv);

	if (kmt_rwmsr(addr, &val, wrmsr)) {
		warn("wrmsr failed");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/*ARGSUSED*/
ssize_t
kmt_write(mdb_tgt_t *t, const void *buf, size_t nbytes, uintptr_t addr)
{
	if (!(t->t_flags & MDB_TGT_F_ALLOWIO) &&
	    (nbytes = kmdb_kdi_range_is_nontoxic(addr, nbytes, 1)) == 0)
		return (set_errno(EMDB_NOMAP));

	/*
	 * No writes to user space are allowed.  If we were to allow it, we'd
	 * be in the unfortunate situation where kmdb could place a breakpoint
	 * on a userspace executable page; this dirty page would end up being
	 * flushed back to disk, incurring sadness when it's next executed.
	 * Besides, we can't allow trapping in from userspace anyway.
	 */
	if (addr < kmdb_kdi_get_userlimit())
		return (set_errno(EMDB_TGTNOTSUP));

	return (kmt_rw(t, (void *)buf, nbytes, addr, kmt_writer));
}

/*ARGSUSED*/
static ssize_t
kmt_iorw(mdb_tgt_t *t, void *buf, size_t nbytes, uint64_t addr,
    void (*iorw)(void *, size_t, uintptr_t))
{
	jmp_buf pcb, *oldpcb = NULL;

	if (kmt_io_check(nbytes, addr, IOCHECK_NOWARN) < 0)
		return (-1); /* errno is set for us */

	if (setjmp(pcb) != 0) {
		kmdb_dpi_restore_fault_hdlr(oldpcb);
		return (-1); /* errno is set for us */
	}

	oldpcb = kmdb_dpi_set_fault_hdlr(&pcb);
	iorw(buf, nbytes, addr);
	kmdb_dpi_restore_fault_hdlr(oldpcb);

	return (nbytes);
}

/*ARGSUSED*/
ssize_t
kmt_ioread(mdb_tgt_t *t, void *buf, size_t nbytes, uintptr_t addr)
{
	return (kmt_iorw(t, buf, nbytes, addr, kmt_in));
}

/*ARGSUSED*/
ssize_t
kmt_iowrite(mdb_tgt_t *t, const void *buf, size_t nbytes, uintptr_t addr)
{
	return (kmt_iorw(t, (void *)buf, nbytes, addr, kmt_out));
}

static int
kmt_pcicfg_common(uintptr_t off, uint32_t *valp, const mdb_arg_t *argv,
    void (*rw)(void *, size_t, uintptr_t))
{
	uint32_t bus, dev, func;
	uint32_t addr;

	bus = kmt_numarg(&argv[0]);
	dev = kmt_numarg(&argv[1]);
	func = kmt_numarg(&argv[2]);

	if ((bus & 0xffff) != bus) {
		warn("invalid bus number (must be 0-0xffff)\n");
		return (DCMD_ERR);
	}

	if ((dev & 0x1f) != dev) {
		warn("invalid device number (must be 0-0x1f)\n");
		return (DCMD_ERR);
	}

	if ((func & 0x7) != func) {
		warn("invalid function number (must be 0-7)\n");
		return (DCMD_ERR);
	}

	if ((off & 0xfc) != off) {
		warn("invalid register number (must be 0-0xff, and 4-byte "
		    "aligned\n");
		return (DCMD_ERR);
	}

	addr = PCI_CADDR1(bus, dev, func, off);

	if (kmt_iowrite(mdb.m_target, &addr, sizeof (addr), PCI_CONFADD) !=
	    sizeof (addr)) {
		warn("write of PCI_CONFADD failed");
		return (DCMD_ERR);
	}

	if (kmt_iorw(mdb.m_target, valp, sizeof (*valp), PCI_CONFDATA, rw) !=
	    sizeof (*valp)) {
		warn("access to PCI_CONFDATA failed");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/*ARGSUSED*/
int
kmt_rdpcicfg(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint32_t val;

	if (argc != 3 || !(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (kmt_pcicfg_common(addr, &val, argv, kmt_in) != DCMD_OK)
		return (DCMD_ERR);

	mdb_printf("%llx\n", (u_longlong_t)val);

	return (DCMD_OK);
}

/*ARGSUSED*/
int
kmt_wrpcicfg(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint32_t val;

	if (argc != 4 || !(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	val = (uint32_t)kmt_numarg(&argv[3]);

	if (kmt_pcicfg_common(addr, &val, argv, kmt_out) != DCMD_OK)
		return (DCMD_ERR);

	return (DCMD_OK);
}

const char *
kmt_trapname(int trapnum)
{
	static char trapname[11];

	switch (trapnum) {
	case T_ZERODIV:
		return ("division by zero (#de) trap");
	case T_SGLSTP:
		return ("single-step (#db) trap");
	case T_NMIFLT:
		return ("NMI");
	case T_BPTFLT:
		return ("breakpoint (#bp) trap");
	case T_ILLINST:
		return ("illegal instruction (#ud) trap");
	case T_SEGFLT:
		return ("segment not present (#np) trap");
	case T_STKFLT:
		return ("stack (#ss) trap");
	case T_GPFLT:
		return ("general protection (#gp) trap");
	case T_PGFLT:
		return ("page fault (#pf) trap");
	case T_ALIGNMENT:
		return ("alignment check (#ac) trap");
	case T_MCE:
		return ("machine check (#mc) trap");
	case T_SIMDFPE:
		return ("SSE/SSE2 (#xm) trap");
	case T_DBGENTR:
		return ("debugger entry trap");
	default:
		(void) mdb_snprintf(trapname, sizeof (trapname), "trap %#x",
		    trapnum);
		return (trapname);
	}
}

void
kmt_init_isadep(mdb_tgt_t *t)
{
	kmt_data_t *kmt = t->t_data;

	kmt->kmt_rds = mdb_isa_kregs;

	kmt->kmt_trapmax = KMT_MAXTRAPNO;
	kmt->kmt_trapmap = mdb_zalloc(BT_SIZEOFMAP(kmt->kmt_trapmax), UM_SLEEP);

	/* Traps for which we want to provide an explicit message */
	(void) mdb_tgt_add_fault(t, T_ZERODIV, MDB_TGT_SPEC_INTERNAL,
	    no_se_f, NULL);
	(void) mdb_tgt_add_fault(t, T_ILLINST, MDB_TGT_SPEC_INTERNAL,
	    no_se_f, NULL);
	(void) mdb_tgt_add_fault(t, T_SEGFLT, MDB_TGT_SPEC_INTERNAL,
	    no_se_f, NULL);
	(void) mdb_tgt_add_fault(t, T_STKFLT, MDB_TGT_SPEC_INTERNAL,
	    no_se_f, NULL);
	(void) mdb_tgt_add_fault(t, T_GPFLT, MDB_TGT_SPEC_INTERNAL,
	    no_se_f, NULL);
	(void) mdb_tgt_add_fault(t, T_PGFLT, MDB_TGT_SPEC_INTERNAL,
	    no_se_f, NULL);
	(void) mdb_tgt_add_fault(t, T_ALIGNMENT, MDB_TGT_SPEC_INTERNAL,
	    no_se_f, NULL);
	(void) mdb_tgt_add_fault(t, T_MCE, MDB_TGT_SPEC_INTERNAL,
	    no_se_f, NULL);
	(void) mdb_tgt_add_fault(t, T_SIMDFPE, MDB_TGT_SPEC_INTERNAL,
	    no_se_f, NULL);

	/*
	 * Traps which will be handled elsewhere, and which therefore don't
	 * need the trap-based message.
	 */
	BT_SET(kmt->kmt_trapmap, T_SGLSTP);
	BT_SET(kmt->kmt_trapmap, T_BPTFLT);
	BT_SET(kmt->kmt_trapmap, T_DBGENTR);

	/* Catch-all for traps not explicitly listed here */
	(void) mdb_tgt_add_fault(t, KMT_TRAP_NOTENUM, MDB_TGT_SPEC_INTERNAL,
	    no_se_f, NULL);
}

void
kmt_startup_isadep(mdb_tgt_t *t)
{
	kmt_data_t *kmt = t->t_data;

	/*
	 * The stack trace and ::step out code need to detect "interrupt"
	 * frames.  The heuristic they use to detect said frames requires the
	 * addresses of routines that can generate them.
	 */
	(void) mdb_tgt_lookup_by_name(t, MDB_TGT_OBJ_EXEC,
	    "cmnint", &kmt->kmt_intrsyms._kmt_cmnint, NULL);
	(void) mdb_tgt_lookup_by_name(t, MDB_TGT_OBJ_EXEC,
	    "cmntrap", &kmt->kmt_intrsyms._kmt_cmntrap, NULL);
	(void) mdb_tgt_lookup_by_name(t, MDB_TGT_OBJ_EXEC,
	    "sys_sysenter", &kmt->kmt_intrsyms._kmt_sysenter, NULL);
	(void) mdb_tgt_lookup_by_name(t, MDB_TGT_OBJ_EXEC,
	    "brand_sys_sysenter", &kmt->kmt_intrsyms._kmt_brand_sysenter, NULL);
#if defined(__amd64)
	(void) mdb_tgt_lookup_by_name(t, MDB_TGT_OBJ_EXEC,
	    "sys_syscall", &kmt->kmt_intrsyms._kmt_syscall, NULL);
	(void) mdb_tgt_lookup_by_name(t, MDB_TGT_OBJ_EXEC,
	    "brand_sys_syscall", &kmt->kmt_intrsyms._kmt_brand_syscall, NULL);
#endif
}
