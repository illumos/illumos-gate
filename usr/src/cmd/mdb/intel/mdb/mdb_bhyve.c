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
 * Copyright 2018 Joyent, Inc.
 */

/*
 * bhyve target
 *
 * The bhyve target is used to examine and manipulate a bhyve VM. Access to
 * a bhyve VM is provided by libvmm, which itself uses libvmmapi, which uses
 * the vmm driver's ioctl interface to carry out requests.
 *
 * The bhyve target does not know about threads or processes, but it handles
 * multiple vCPUs and can switch between them. Execution control is currently
 * limited to completely stopping or resuming all vCPUs of a VM, or single-
 * stepping a particular vCPU while all other vCPUs remain stopped. Breakpoints
 * are not implemented yet, and as such step-out and step-over don't work yet.
 * All known x86 instruction sets are support, legacy IA-16, IA-32 and AMD64.
 * The current CPU instruction set is automatically determined by parsing the
 * code segment (CS) attributes in the current vCPU.
 *
 * All of the VMs physical memory and device memory segments are mapped R/W
 * into mdb's address space by libvmm. All accesses to those memory are
 * facilitated through libvmm calls, which may include virtual address
 * translation according to the current vCPU mode. Both real-mode and protected-
 * mode segmentation are understood and used for translating virtual addresses
 * into linear addresses, which may further be translated using 2-level, 3-level
 * or 4-level paging.
 *
 * To handle disassembly and stack tracing properly when segmentation is used by
 * a vCPU (always in real mode, sometimes in protected mode) the bhyve target
 * has a notion of three virtual address spaces used for reading/writing memory:
 *   - MDB_TGT_AS_VIRT, the default virtual address space uses the DS segment
 *     by default, but this default can be changed with the ::defseg dcmd.
 *   - MDB_TGT_AS_VIRT_I, the virtual address space for instructions always
 *     uses the code segment (CS) for translation
 *   - MDB_TGT_AS_VIRT_S, the virtual address space for the stack always uses
 *     the stack segment (SS) for translation
 *
 * Register printing and stack tracing is using the common x86 ISA-specific code
 * in IA-32 and AMD64 modes. There is no stack tracing for IA-16 mode yet.
 *
 * Todo:
 *   - support for breakpoint, step-out, and step-over
 *   - support for x86 stack tracing
 */
#include <mdb/mdb_conf.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_signal.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_io_impl.h>
#include <mdb/mdb_kreg_impl.h>
#include <mdb/mdb_target_impl.h>
#include <mdb/mdb_isautil.h>
#include <mdb/mdb_amd64util.h>
#include <mdb/mdb_ia32util.h>
#include <mdb/mdb.h>

#include <sys/controlregs.h>
#include <sys/debugreg.h>
#include <sys/sysmacros.h>
#include <sys/note.h>
#include <unistd.h>
#include <inttypes.h>

#include <libvmm.h>

#define	MDB_DEF_PROMPT	"[%<_cpuid>]> "

#define	MMU_PAGESHIFT	12
#define	MMU_PAGESIZE	(1 << MMU_PAGESHIFT)
#define	MMU_PAGEOFFSET	(MMU_PAGESIZE - 1)
#define	MMU_PAGEMASK	(~MMU_PAGEOFFSET)

typedef struct bhyve_data {
	vmm_t *bd_vmm;
	uint_t bd_curcpu;
	int bd_defseg;

	/* must be last */
	char bd_name[];
} bhyve_data_t;


const mdb_tgt_regdesc_t bhyve_kregs[] = {
	{ "rdi",	KREG_RDI,	MDB_TGT_R_EXPORT },
	{ "edi",	KREG_RDI,	MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "di",		KREG_RDI,	MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "dil",	KREG_RDI,	MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "rsi",	KREG_RSI,	MDB_TGT_R_EXPORT },
	{ "esi",	KREG_RSI,	MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "si",		KREG_RSI,	MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "sil",	KREG_RSI,	MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "rdx",	KREG_RDX,	MDB_TGT_R_EXPORT },
	{ "edx",	KREG_RDX,	MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "dx",		KREG_RDX,	MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "dh",		KREG_RDX,	MDB_TGT_R_EXPORT | MDB_TGT_R_8H },
	{ "dl",		KREG_RDX,	MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "rcx",	KREG_RCX,	MDB_TGT_R_EXPORT },
	{ "ecx",	KREG_RCX,	MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "cx",		KREG_RCX,	MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "ch",		KREG_RCX,	MDB_TGT_R_EXPORT | MDB_TGT_R_8H },
	{ "cl",		KREG_RCX,	MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "r8",		KREG_R8,	MDB_TGT_R_EXPORT },
	{ "r8d",	KREG_R8,	MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r8w",	KREG_R8,	MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "r8l",	KREG_R8,	MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "r9",		KREG_R9,	MDB_TGT_R_EXPORT },
	{ "r9d",	KREG_R8,	MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r9w",	KREG_R8,	MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "r9l",	KREG_R8,	MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "rax",	KREG_RAX,	MDB_TGT_R_EXPORT },
	{ "eax",	KREG_RAX,	MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "ax",		KREG_RAX,	MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "ah",		KREG_RAX,	MDB_TGT_R_EXPORT | MDB_TGT_R_8H },
	{ "al",		KREG_RAX,	MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "rbx",	KREG_RBX,	MDB_TGT_R_EXPORT },
	{ "ebx",	KREG_RBX,	MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "bx",		KREG_RBX,	MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "bh",		KREG_RBX,	MDB_TGT_R_EXPORT | MDB_TGT_R_8H },
	{ "bl",		KREG_RBX,	MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "rbp",	KREG_RBP,	MDB_TGT_R_EXPORT },
	{ "ebp",	KREG_RBP,	MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "bp",		KREG_RBP,	MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "bpl",	KREG_RBP,	MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "r10",	KREG_R10,	MDB_TGT_R_EXPORT },
	{ "r10d",	KREG_R10,	MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r10w",	KREG_R10,	MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "r10l",	KREG_R10,	MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "r11",	KREG_R11,	MDB_TGT_R_EXPORT },
	{ "r11d",	KREG_R11,	MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r11w",	KREG_R11,	MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "r11l",	KREG_R11,	MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "r12",	KREG_R12,	MDB_TGT_R_EXPORT },
	{ "r12d",	KREG_R12,	MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r12w",	KREG_R12,	MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "r12l",	KREG_R12,	MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "r13",	KREG_R13,	MDB_TGT_R_EXPORT },
	{ "r13d",	KREG_R13,	MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r13w",	KREG_R13,	MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "r13l",	KREG_R13,	MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "r14",	KREG_R14,	MDB_TGT_R_EXPORT },
	{ "r14d",	KREG_R14,	MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r14w",	KREG_R14,	MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "r14l",	KREG_R14,	MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "r15",	KREG_R15,	MDB_TGT_R_EXPORT },
	{ "r15d",	KREG_R15,	MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "r15w",	KREG_R15,	MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "r15l",	KREG_R15,	MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "ds",		KREG_DS,	MDB_TGT_R_EXPORT },
	{ "es",		KREG_ES,	MDB_TGT_R_EXPORT },
	{ "fs",		KREG_FS,	MDB_TGT_R_EXPORT },
	{ "gs",		KREG_GS,	MDB_TGT_R_EXPORT },
	{ "rip",	KREG_RIP,	MDB_TGT_R_EXPORT },
	{ "cs",		KREG_CS,	MDB_TGT_R_EXPORT },
	{ "rflags",	KREG_RFLAGS,	MDB_TGT_R_EXPORT },
	{ "eflags",	KREG_RFLAGS,	MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "rsp",	KREG_RSP,	MDB_TGT_R_EXPORT },
	{ "esp",	KREG_RSP,	MDB_TGT_R_EXPORT | MDB_TGT_R_32 },
	{ "sp",		KREG_RSP,	MDB_TGT_R_EXPORT | MDB_TGT_R_16 },
	{ "spl",	KREG_RSP,	MDB_TGT_R_EXPORT | MDB_TGT_R_8L },
	{ "ss",		KREG_SS,	MDB_TGT_R_EXPORT },
	{ "cr2",	KREG_CR2,	MDB_TGT_R_EXPORT },
	{ "cr3",	KREG_CR3,	MDB_TGT_R_EXPORT },
	{ NULL, 0, 0 }
};

static const char *segments[] = { "CS", "DS", "ES", "FS", "GS", "SS" };


/*ARGSUSED*/
static uintmax_t
bhyve_cpuid_get(const mdb_var_t *v)
{
	bhyve_data_t *bd = mdb.m_target->t_data;

	return (bd->bd_curcpu);
}

static const mdb_nv_disc_t bhyve_cpuid_disc = {
	.disc_get = bhyve_cpuid_get
};


static uintmax_t
bhyve_reg_get(const mdb_var_t *v)
{
	mdb_tgt_reg_t r = 0;

	if (mdb_tgt_getareg(MDB_NV_COOKIE(v), 0, mdb_nv_get_name(v), &r) == -1)
		mdb_warn("failed to get %%%s register", mdb_nv_get_name(v));

	return (r);
}

static void
bhyve_reg_set(mdb_var_t *v, uintmax_t r)
{
	if (mdb_tgt_putareg(MDB_NV_COOKIE(v), 0, mdb_nv_get_name(v), r) == -1)
		mdb_warn("failed to modify %%%s register", mdb_nv_get_name(v));
}

static const mdb_nv_disc_t bhyve_reg_disc = {
	.disc_set = bhyve_reg_set,
	.disc_get = bhyve_reg_get
};

static int
bhyve_get_gregset(bhyve_data_t *bd, int cpu, mdb_tgt_gregset_t *gregs)
{
	vmm_desc_t fs, gs;

	/*
	 * Register numbers to get, the order must match the definitions of
	 * KREG_* in mdb_kreg.h so that we get a proper mdb_tgt_gregset_t
	 * that the register printing functions will understand.
	 *
	 * There are a few fields in mdb_tgt_gregset_t that can't be accessed
	 * with vmm_get_regset(), either because they don't exist in bhyve or
	 * or because they need to be accessed with vmm_get_desc(). For these
	 * cases we ask for RAX instead and fill it with 0 or the real value,
	 * respectively.
	 */
	static const int regnums[] = {
		KREG_RAX, /* dummy for SAVFP */
		KREG_RAX, /* dummy for SAVFP */
		KREG_RDI,
		KREG_RSI,
		KREG_RDX,
		KREG_RCX,
		KREG_R8,
		KREG_R9,
		KREG_RAX,
		KREG_RBX,
		KREG_RBP,
		KREG_R10,
		KREG_R11,
		KREG_R12,
		KREG_R13,
		KREG_R14,
		KREG_R15,
		KREG_RAX, /* dummy for FSBASE */
		KREG_RAX, /* dummy for GSBASE */
		KREG_RAX, /* dummy for KGSBASE */
		KREG_CR2,
		KREG_CR3,
		KREG_DS,
		KREG_ES,
		KREG_FS,
		KREG_GS,
		KREG_RAX, /* dummy for TRAPNO */
		KREG_RAX, /* dummy for ERR */
		KREG_RIP,
		KREG_CS,
		KREG_RFLAGS,
		KREG_RSP,
		KREG_SS
	};

	if (vmm_get_regset(bd->bd_vmm, cpu, KREG_NGREG, regnums,
	    &gregs->kregs[0]) != 0) {
		mdb_warn("failed to get general-purpose registers for CPU %d",
		    cpu);
		return (-1);
	}

	if (vmm_get_desc(bd->bd_vmm, cpu, VMM_DESC_FS, &fs) != 0 ||
	    vmm_get_desc(bd->bd_vmm, cpu, VMM_DESC_GS, &gs) != 0) {
		mdb_warn("failed to get FS/GS descriptors for CPU %d", cpu);
		return (-1);
	}

	gregs->kregs[KREG_SAVFP] = 0;
	gregs->kregs[KREG_SAVPC] = 0;
	gregs->kregs[KREG_KGSBASE] = 0;
	gregs->kregs[KREG_TRAPNO] = 0;
	gregs->kregs[KREG_ERR] = 0;

	gregs->kregs[KREG_FSBASE] = fs.vd_base;
	gregs->kregs[KREG_GSBASE] = gs.vd_base;

	return (0);
}

static int
bhyve_cpuregs_dcmd(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	bhyve_data_t *bd = mdb.m_target->t_data;
	uint64_t cpu = bd->bd_curcpu;
	mdb_tgt_gregset_t gregs;
	int i;


	if (flags & DCMD_ADDRSPEC) {
		if (argc != 0)
			return (DCMD_USAGE);

		cpu = (uint64_t)addr;
	}

	i = mdb_getopts(argc, argv, 'c', MDB_OPT_UINT64, &cpu, NULL);

	argc -= i;
	argv += i;

	if (argc != 0)
		return (DCMD_USAGE);

	if (cpu >= vmm_ncpu(bd->bd_vmm)) {
		mdb_warn("no such CPU\n");
		return (DCMD_ERR);
	}

	if (bhyve_get_gregset(bd, cpu, &gregs) != 0)
		return (DCMD_ERR);


	switch (vmm_vcpu_isa(bd->bd_vmm, cpu)) {
	case VMM_ISA_64:
		mdb_amd64_printregs(&gregs);
		break;
	case VMM_ISA_32:
	case VMM_ISA_16:
		mdb_ia32_printregs(&gregs);
		break;
	default:
		mdb_warn("CPU %d mode unknown", cpu);
		return (DCMD_ERR);
	}

	return (0);
}

static int
bhyve_regs_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if ((flags & DCMD_ADDRSPEC) || argc != 0)
		return (DCMD_USAGE);

	return (bhyve_cpuregs_dcmd(addr, flags, argc, argv));
}

static int
bhyve_stack_common(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv, int vcpu, boolean_t verbose)
{
	bhyve_data_t *bd = mdb.m_target->t_data;
	void *arg = (void *)(uintptr_t)mdb.m_nargs;

	mdb_tgt_gregset_t gregs;
	mdb_tgt_stack_f *func;

	if (vcpu == -1)
		vcpu = bd->bd_curcpu;

	if (flags & DCMD_ADDRSPEC) {
		bzero(&gregs, sizeof (gregs));
		gregs.kregs[KREG_RBP] = addr;
	} else if (bhyve_get_gregset(bd, vcpu, &gregs) != 0)
		return (DCMD_ERR);

	switch (vmm_vcpu_isa(bd->bd_vmm, vcpu)) {
	case VMM_ISA_64:
		func = verbose ? mdb_amd64_kvm_framev : mdb_amd64_kvm_frame;
		(void) mdb_amd64_kvm_stack_iter(mdb.m_target, &gregs, func,
		    arg);
		break;
	case VMM_ISA_32:
		func = verbose ? mdb_ia32_kvm_framev : mdb_amd64_kvm_frame;
		(void) mdb_ia32_kvm_stack_iter(mdb.m_target, &gregs, func, arg);
		break;
	case VMM_ISA_16:
		mdb_warn("IA16 stack tracing not implemented\n");
		return (DCMD_ERR);
	default:
		mdb_warn("CPU %d mode unknown", vcpu);
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

static int
bhyve_cpustack_dcmd(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	bhyve_data_t *bd = mdb.m_target->t_data;
	uint64_t cpu = bd->bd_curcpu;
	boolean_t verbose;
	int i;

	if (flags & DCMD_ADDRSPEC) {
		if (argc != 0)
			return (DCMD_USAGE);

		if (addr < vmm_ncpu(bd->bd_vmm)) {
			cpu = (uint64_t)addr;
			flags &= ~DCMD_ADDRSPEC;
		}
	}

	i = mdb_getopts(argc, argv,
	    'c', MDB_OPT_UINT64, &cpu,
	    'v', MDB_OPT_SETBITS, 1, &verbose);

	argc -= i;
	argv += i;

	if (argc != 0)
		return (DCMD_USAGE);

	return (bhyve_stack_common(addr, flags, argc, argv, cpu, verbose));
}

static int
bhyve_stack_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (bhyve_stack_common(addr, flags, argc, argv, -1, B_FALSE));
}

static int
bhyve_stackv_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (bhyve_stack_common(addr, flags, argc, argv, -1, B_TRUE));
}

static int
bhyve_stackr_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (bhyve_stack_common(addr, flags, argc, argv, -1, B_TRUE));
}

static int
bhyve_status_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	bhyve_data_t *bd = mdb.m_target->t_data;
	vmm_mode_t mode;
	vmm_isa_t isa;

	static const char *modes[] = {
		"unknown mode",
		"real mode",
		"protected mode, no PAE",
		"protected mode, PAE",
		"long mode"
	};
	static const char *isas[] = {
		"unknown ISA",
		"IA16",
		"IA32",
		"AMD64"
	};

	if ((flags & DCMD_ADDRSPEC) || argc != 0)
		return (DCMD_USAGE);

	mode = vmm_vcpu_mode(bd->bd_vmm, bd->bd_curcpu);
	isa = vmm_vcpu_isa(bd->bd_vmm, bd->bd_curcpu);

	mdb_printf("debugging live VM '%s'\n", bd->bd_name);
	mdb_printf("VM memory size: %d MB\n",
	    vmm_memsize(bd->bd_vmm) / 1024 / 1024);
	mdb_printf("vCPUs: %d\n", vmm_ncpu(bd->bd_vmm));
	mdb_printf("current CPU: %d (%s, %s)\n", bd->bd_curcpu, modes[mode],
	    isas[isa]);
	mdb_printf("default segment: %s",
	    segments[bd->bd_defseg - VMM_DESC_CS]);

	return (DCMD_OK);
}

static void
bhyve_print_desc(const char *name, const vmm_desc_t *desc, int width)
{
	const char *type;
	const mdb_bitmask_t *bits;

	static const mdb_bitmask_t mem_desc_flag_bits[] = {
		{ "P",		0x80,	0x80 },
		{ "16b",	0x6000, 0x0 },
		{ "32b",	0x6000, 0x4000 },
		{ "64b",	0x6000,	0x2000 },
		{ "G",		0x8000,	0x8000 },
		{ "A",		0x1,	0x1 },
		{ NULL,		0,	0 },
	};

	static const char *mem_desc_types[] = {
		"data, up, read-only",
		"data, up, read-write",
		"data, down, read-only",
		"data, down, read-write",
		"code, non-conforming, execute-only",
		"code, non-conforming, execute-read",
		"code, conforming, execute-only",
		"code, conforming, execute-read"
	};

	static const mdb_bitmask_t sys_desc_flag_bits[] = {
		{ "P",		0x80,	0x80 },
		{ "16b",	0x6000, 0x0 },
		{ "32b",	0x6000, 0x4000 },
		{ "64b",	0x6000,	0x2000 },
		{ "G",		0x8000,	0x8000 },
		{ NULL,		0,	0 },
	};

	static const char *sys_desc_types[] = {
		"reserved",
		"16b TSS, available",
		"LDT",
		"16b TSS, busy",
		"16b call gate",
		"task gate",
		"16b interrupt gate",
		"16b trap gate",
		"reserved",
		"32b/64b TSS, available",
		"reserved",
		"32b/64b TSS, busy",
		"32b/64b call gate",
		"reserved",
		"32b/64b interrupt gate"
		"32b/64b trap gate",
	};

	if (desc->vd_acc & 0x10) {
		type = mem_desc_types[(desc->vd_acc >> 1) & 7];
		bits = mem_desc_flag_bits;
	} else {
		type = sys_desc_types[desc->vd_acc & 0xf];
		bits = sys_desc_flag_bits;
	}

	mdb_printf("%%%s = 0x%0*p/0x%0*x 0x%05x "
	    "<%susable, %s, dpl %d, flags: %b>\n",
	    name, width, desc->vd_base, width / 2, desc->vd_lim, desc->vd_acc,
	    (desc->vd_acc >> 16) & 1 ? "un" : "", type,
	    (desc->vd_acc >> 5) & 3, desc->vd_acc, bits);
}

static int
bhyve_sysregs_dcmd(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	bhyve_data_t *bd = mdb.m_target->t_data;
	uint64_t cpu = bd->bd_curcpu;
	int ret = DCMD_ERR;
	vmm_desc_t gdtr, ldtr, idtr, tr, cs, ds, es, fs, gs, ss;
	uint64_t *regvals;
	int i;
	int width = sizeof (uint64_t) * 2;

	if (vmm_vcpu_mode(bd->bd_vmm, cpu) != VMM_MODE_LONG)
		width /= 2;

	/*
	 * This array must use the order of definitions set in libvmm.h
	 * to make GETREG() work.
	 */
#define	GETREG(r)	(regvals[r - VMM_REG_OFFSET])
	static const int regnums[] = {
		VMM_REG_CR0,
		VMM_REG_CR2,
		VMM_REG_CR3,
		VMM_REG_CR4,
		VMM_REG_DR0,
		VMM_REG_DR1,
		VMM_REG_DR2,
		VMM_REG_DR3,
		VMM_REG_DR6,
		VMM_REG_DR7,
		VMM_REG_EFER,
		VMM_REG_PDPTE0,
		VMM_REG_PDPTE1,
		VMM_REG_PDPTE2,
		VMM_REG_PDPTE3,
		VMM_REG_INTR_SHADOW
	};

	static const mdb_bitmask_t efer_flag_bits[] = {
		{ "SCE",	AMD_EFER_SCE,	AMD_EFER_SCE },
		{ "LME",	AMD_EFER_LME,	AMD_EFER_LME },
		{ "LMA",	AMD_EFER_LMA,	AMD_EFER_LMA },
		{ "NXE",	AMD_EFER_NXE,	AMD_EFER_NXE },
		{ "SVME",	AMD_EFER_SVME,	AMD_EFER_SVME },
		{ "LMSLE",	AMD_EFER_LMSLE,	AMD_EFER_LMSLE },
		{ "FFXSR",	AMD_EFER_FFXSR,	AMD_EFER_FFXSR },
		{ "TCE",	AMD_EFER_TCE,	AMD_EFER_TCE },
		{ NULL,		0,		0 }
	};

	static const mdb_bitmask_t cr0_flag_bits[] = {
		{ "PE",		CR0_PE,		CR0_PE },
		{ "MP",		CR0_MP,		CR0_MP },
		{ "EM",		CR0_EM,		CR0_EM },
		{ "TS",		CR0_TS,		CR0_TS },
		{ "ET",		CR0_ET,		CR0_ET },
		{ "NE",		CR0_NE,		CR0_NE },
		{ "WP",		CR0_WP,		CR0_WP },
		{ "AM",		CR0_AM,		CR0_AM },
		{ "NW",		CR0_NW,		CR0_NW },
		{ "CD",		CR0_CD,		CR0_CD },
		{ "PG",		CR0_PG,		CR0_PG },
		{ NULL,		0,		0 }
	};

	static const mdb_bitmask_t cr3_flag_bits[] = {
		{ "PCD",	CR3_PCD,	CR3_PCD },
		{ "PWT",	CR3_PWT,	CR3_PWT },
		{ NULL,		0,		0, }
	};

	static const mdb_bitmask_t cr4_flag_bits[] = {
		{ "VME",	CR4_VME,	CR4_VME },
		{ "PVI",	CR4_PVI,	CR4_PVI },
		{ "TSD",	CR4_TSD,	CR4_TSD },
		{ "DE",		CR4_DE,		CR4_DE },
		{ "PSE",	CR4_PSE,	CR4_PSE },
		{ "PAE",	CR4_PAE,	CR4_PAE },
		{ "MCE",	CR4_MCE,	CR4_MCE },
		{ "PGE",	CR4_PGE,	CR4_PGE },
		{ "PCE",	CR4_PCE,	CR4_PCE },
		{ "OSFXSR",	CR4_OSFXSR,	CR4_OSFXSR },
		{ "OSXMMEXCPT",	CR4_OSXMMEXCPT,	CR4_OSXMMEXCPT },
		{ "UMIP",	CR4_UMIP,	CR4_UMIP },
		{ "VMXE",	CR4_VMXE,	CR4_VMXE },
		{ "SMXE",	CR4_SMXE,	CR4_SMXE },
		{ "FSGSBASE",	CR4_FSGSBASE,	CR4_FSGSBASE },
		{ "PCIDE",	CR4_PCIDE,	CR4_PCIDE },
		{ "OSXSAVE",	CR4_OSXSAVE,	CR4_OSXSAVE },
		{ "SMEP",	CR4_SMEP,	CR4_SMEP },
		{ "SMAP",	CR4_SMAP,	CR4_SMAP },
		{ "PKE",	CR4_PKE,	CR4_PKE },
		{ NULL,		0,		0 }
	};


	if (flags & DCMD_ADDRSPEC) {
		if (argc != 0)
			return (DCMD_USAGE);

		cpu = (uint64_t)addr;
	}

	i = mdb_getopts(argc, argv, 'c', MDB_OPT_UINT64, &cpu, NULL);

	argc -= i;
	argv += i;

	if (argc != 0)
		return (DCMD_USAGE);

	if (cpu >= vmm_ncpu(bd->bd_vmm)) {
		mdb_warn("no such CPU\n");
		return (DCMD_ERR);
	}

	regvals = mdb_zalloc(ARRAY_SIZE(regnums) * sizeof (uint64_t), UM_SLEEP);

	if (vmm_get_regset(bd->bd_vmm, cpu, ARRAY_SIZE(regnums), regnums,
	    regvals) != 0)
		goto fail;

	if (vmm_get_desc(bd->bd_vmm, cpu, VMM_DESC_GDTR, &gdtr) != 0 ||
	    vmm_get_desc(bd->bd_vmm, cpu, VMM_DESC_IDTR, &idtr) != 0 ||
	    vmm_get_desc(bd->bd_vmm, cpu, VMM_DESC_LDTR, &ldtr) != 0 ||
	    vmm_get_desc(bd->bd_vmm, cpu, VMM_DESC_TR, &tr) != 0 ||
	    vmm_get_desc(bd->bd_vmm, cpu, VMM_DESC_CS, &cs) != 0 ||
	    vmm_get_desc(bd->bd_vmm, cpu, VMM_DESC_DS, &ds) != 0 ||
	    vmm_get_desc(bd->bd_vmm, cpu, VMM_DESC_ES, &es) != 0 ||
	    vmm_get_desc(bd->bd_vmm, cpu, VMM_DESC_FS, &fs) != 0 ||
	    vmm_get_desc(bd->bd_vmm, cpu, VMM_DESC_GS, &gs) != 0 ||
	    vmm_get_desc(bd->bd_vmm, cpu, VMM_DESC_SS, &ss) != 0)
		goto fail;

	mdb_printf("%%efer = 0x%0lx <%b>\n",
	    GETREG(VMM_REG_EFER), GETREG(VMM_REG_EFER), efer_flag_bits);
	mdb_printf("%%cr0 = 0x%0lx <%b>\n",
	    GETREG(VMM_REG_CR0), GETREG(VMM_REG_CR0), cr0_flag_bits);
	mdb_printf("%%cr2 = 0x%0*p %A\n", width,
	    GETREG(VMM_REG_CR2), GETREG(VMM_REG_CR2));
	mdb_printf("%%cr3 = 0x%0lx <pfn:0x%lx ",
	    GETREG(VMM_REG_CR3), GETREG(VMM_REG_CR3) >> MMU_PAGESHIFT);
	if (GETREG(VMM_REG_CR4) & CR4_PCIDE)
		mdb_printf("pcid:%lu>\n", GETREG(VMM_REG_CR3) & MMU_PAGEOFFSET);
	else
		mdb_printf("flags:%b>\n", GETREG(VMM_REG_CR3), cr3_flag_bits);
	mdb_printf("%%cr4 = 0x%0lx <%b>\n\n",
	    GETREG(VMM_REG_CR4), GETREG(VMM_REG_CR4), cr4_flag_bits);

	mdb_printf("%%pdpte0 = 0x%0?p\t%%pdpte2 = 0x%0?p\n",
	    GETREG(VMM_REG_PDPTE0), GETREG(VMM_REG_PDPTE2));
	mdb_printf("%%pdpte1 = 0x%0?p\t%%pdpte3 = 0x%0?p\n\n",
	    GETREG(VMM_REG_PDPTE1), GETREG(VMM_REG_PDPTE3));

	mdb_printf("%%gdtr = 0x%0*x/0x%hx\n",
	    width, gdtr.vd_base, gdtr.vd_lim);
	mdb_printf("%%idtr = 0x%0*x/0x%hx\n",
	    width, idtr.vd_base, idtr.vd_lim);
	bhyve_print_desc("ldtr", &ldtr, width);
	bhyve_print_desc("tr  ", &tr, width);
	bhyve_print_desc("cs  ", &cs, width);
	bhyve_print_desc("ss  ", &ss, width);
	bhyve_print_desc("ds  ", &ds, width);
	bhyve_print_desc("es  ", &es, width);
	bhyve_print_desc("fs  ", &fs, width);
	bhyve_print_desc("gs  ", &gs, width);

	mdb_printf("%%intr_shadow = 0x%lx\n\n",
	    GETREG(VMM_REG_INTR_SHADOW));
#undef GETREG
	ret = DCMD_OK;

fail:
	if (ret != DCMD_OK)
		mdb_warn("failed to get system registers for CPU %d\n", cpu);
	mdb_free(regvals, ARRAY_SIZE(regnums) * sizeof (uint64_t));
	return (ret);
}

static int
bhyve_dbgregs_dcmd(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	bhyve_data_t *bd = mdb.m_target->t_data;
	uint64_t cpu = bd->bd_curcpu;
	int ret = DCMD_ERR;
	vmm_desc_t gdtr, ldtr, idtr, tr, cs, ds, es, fs, gs, ss;
	uint64_t *regvals;
	int i;

	/*
	 * This array must use the order of definitions set in libvmm.h
	 * to make GETREG() work.
	 */
#define	GETREG(r)	(regvals[r - VMM_REG_DR0])
	static const int regnums[] = {
		VMM_REG_DR0,
		VMM_REG_DR1,
		VMM_REG_DR2,
		VMM_REG_DR3,
		VMM_REG_DR6,
		VMM_REG_DR7,
	};

	static const mdb_bitmask_t dr6_flag_bits[] = {
		{ "DR0",	DR_TRAP0,	DR_TRAP0 },
		{ "DR1",	DR_TRAP1,	DR_TRAP1 },
		{ "DR2",	DR_TRAP2,	DR_TRAP2 },
		{ "DR3",	DR_TRAP3,	DR_TRAP3 },
		{ "debug reg",	DR_ICEALSO,	DR_ICEALSO },
		{ "single step", DR_SINGLESTEP,	DR_SINGLESTEP },
		{ "task switch", DR_TASKSWITCH,	DR_TASKSWITCH },
		{ NULL,		0,		0 }
	};

#define	DR_RW(x, m)	\
	((DR_RW_MASK & (m)) << (DR_CONTROL_SHIFT + (x) * DR_CONTROL_SIZE))
#define	DR_LEN(x, m)	\
	((DR_LEN_MASK & (m)) << (DR_CONTROL_SHIFT + (x) * DR_CONTROL_SIZE))

	static const mdb_bitmask_t dr7_flag_bits[] = {
		{ "L0",   DR_ENABLE0,	DR_LOCAL_ENABLE_MASK & DR_ENABLE0 },
		{ "G0",   DR_ENABLE0,	DR_GLOBAL_ENABLE_MASK & DR_ENABLE0 },
		{ "L1",   DR_ENABLE1,	DR_LOCAL_ENABLE_MASK & DR_ENABLE1 },
		{ "G1",   DR_ENABLE1,	DR_GLOBAL_ENABLE_MASK & DR_ENABLE1 },
		{ "L2",   DR_ENABLE2,	DR_LOCAL_ENABLE_MASK & DR_ENABLE2 },
		{ "G2",   DR_ENABLE2,	DR_GLOBAL_ENABLE_MASK & DR_ENABLE2 },
		{ "L3",   DR_ENABLE3,	DR_LOCAL_ENABLE_MASK & DR_ENABLE3 },
		{ "G3",   DR_ENABLE3,	DR_GLOBAL_ENABLE_MASK & DR_ENABLE3 },
		{ "LE",   DR_LOCAL_SLOWDOWN,	DR_LOCAL_SLOWDOWN },
		{ "GE",   DR_GLOBAL_SLOWDOWN,	DR_GLOBAL_SLOWDOWN },
		{ "RTM",  DR_RTM,		DR_RTM },
		{ "GD",   DR_GENERAL_DETECT,	DR_GENERAL_DETECT },
		{ "0:X",  DR_RW(0, DR_RW_MASK),   DR_RW(0, DR_RW_EXECUTE) },
		{ "0:W",  DR_RW(0, DR_RW_MASK),   DR_RW(0, DR_RW_WRITE) },
		{ "0:IO", DR_RW(0, DR_RW_MASK),   DR_RW(0, DR_RW_IO_RW) },
		{ "0:RW", DR_RW(0, DR_RW_MASK),   DR_RW(0, DR_RW_READ) },
		{ "1:X",  DR_RW(1, DR_RW_MASK),   DR_RW(1, DR_RW_EXECUTE) },
		{ "1:W",  DR_RW(1, DR_RW_MASK),   DR_RW(1, DR_RW_WRITE) },
		{ "1:IO", DR_RW(1, DR_RW_MASK),   DR_RW(1, DR_RW_IO_RW) },
		{ "1:RW", DR_RW(1, DR_RW_MASK),   DR_RW(1, DR_RW_READ) },
		{ "2:X",  DR_RW(2, DR_RW_MASK),   DR_RW(2, DR_RW_EXECUTE) },
		{ "2:W",  DR_RW(2, DR_RW_MASK),   DR_RW(2, DR_RW_WRITE) },
		{ "2:IO", DR_RW(2, DR_RW_MASK),   DR_RW(2, DR_RW_IO_RW) },
		{ "2:RW", DR_RW(2, DR_RW_MASK),   DR_RW(2, DR_RW_READ) },
		{ "3:X",  DR_RW(3, DR_RW_MASK),   DR_RW(3, DR_RW_EXECUTE) },
		{ "3:W",  DR_RW(3, DR_RW_MASK),   DR_RW(3, DR_RW_WRITE) },
		{ "3:IO", DR_RW(3, DR_RW_MASK),   DR_RW(3, DR_RW_IO_RW) },
		{ "3:RW", DR_RW(3, DR_RW_MASK),   DR_RW(3, DR_RW_READ) },
		{ "0:1",  DR_LEN(0, DR_LEN_MASK), DR_LEN(0, DR_LEN_1) },
		{ "0:2",  DR_LEN(0, DR_LEN_MASK), DR_LEN(0, DR_LEN_2) },
		{ "0:4",  DR_LEN(0, DR_LEN_MASK), DR_LEN(0, DR_LEN_4) },
		{ "0:8",  DR_LEN(0, DR_LEN_MASK), DR_LEN(0, DR_LEN_8) },
		{ "1:1",  DR_LEN(1, DR_LEN_MASK), DR_LEN(1, DR_LEN_1) },
		{ "1:2",  DR_LEN(1, DR_LEN_MASK), DR_LEN(1, DR_LEN_2) },
		{ "1:4",  DR_LEN(1, DR_LEN_MASK), DR_LEN(1, DR_LEN_4) },
		{ "1:8",  DR_LEN(1, DR_LEN_MASK), DR_LEN(1, DR_LEN_8) },
		{ "2:1",  DR_LEN(2, DR_LEN_MASK), DR_LEN(2, DR_LEN_1) },
		{ "2:2",  DR_LEN(2, DR_LEN_MASK), DR_LEN(2, DR_LEN_2) },
		{ "2:4",  DR_LEN(2, DR_LEN_MASK), DR_LEN(2, DR_LEN_4) },
		{ "2:8",  DR_LEN(2, DR_LEN_MASK), DR_LEN(2, DR_LEN_8) },
		{ "3:1",  DR_LEN(3, DR_LEN_MASK), DR_LEN(3, DR_LEN_1) },
		{ "3:2",  DR_LEN(3, DR_LEN_MASK), DR_LEN(3, DR_LEN_2) },
		{ "3:4",  DR_LEN(3, DR_LEN_MASK), DR_LEN(3, DR_LEN_4) },
		{ "3:8",  DR_LEN(3, DR_LEN_MASK), DR_LEN(3, DR_LEN_8) },
		{ NULL, 0, 0 },
	};


	if (flags & DCMD_ADDRSPEC) {
		if (argc != 0)
			return (DCMD_USAGE);

		cpu = (uint64_t)addr;
	}

	i = mdb_getopts(argc, argv, 'c', MDB_OPT_UINT64, &cpu, NULL);

	argc -= i;
	argv += i;

	if (argc != 0)
		return (DCMD_USAGE);

	if (cpu >= vmm_ncpu(bd->bd_vmm)) {
		mdb_warn("no such CPU\n");
		return (DCMD_ERR);
	}

	regvals = mdb_zalloc(ARRAY_SIZE(regnums) * sizeof (uint64_t), UM_SLEEP);

	if (vmm_get_regset(bd->bd_vmm, cpu, ARRAY_SIZE(regnums), regnums,
	    regvals) != 0)
		goto fail;

	mdb_printf("%%dr0 = 0x%0?p %A\n",
	    GETREG(VMM_REG_DR0), GETREG(VMM_REG_DR0));
	mdb_printf("%%dr1 = 0x%0?p %A\n",
	    GETREG(VMM_REG_DR1), GETREG(VMM_REG_DR1));
	mdb_printf("%%dr2 = 0x%0?p %A\n",
	    GETREG(VMM_REG_DR2), GETREG(VMM_REG_DR2));
	mdb_printf("%%dr3 = 0x%0?p %A\n",
	    GETREG(VMM_REG_DR3), GETREG(VMM_REG_DR3));
	mdb_printf("%%dr6 = 0x%0lx <%b>\n",
	    GETREG(VMM_REG_DR6), GETREG(VMM_REG_DR6), dr6_flag_bits);
	mdb_printf("%%dr7 = 0x%0lx <%b>\n",
	    GETREG(VMM_REG_DR7), GETREG(VMM_REG_DR7), dr7_flag_bits);
#undef GETREG

	ret = DCMD_OK;

fail:
	if (ret != DCMD_OK)
		mdb_warn("failed to get debug registers for CPU %d\n", cpu);
	mdb_free(regvals, ARRAY_SIZE(regnums) * sizeof (uint64_t));
	return (ret);
}

static int
bhyve_switch_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	bhyve_data_t *bd = mdb.m_target->t_data;
	size_t cpu = (int)addr;

	if (!(flags & DCMD_ADDRSPEC) || argc != 0)
		return (DCMD_USAGE);

	if (cpu >= vmm_ncpu(bd->bd_vmm)) {
		mdb_warn("no such CPU\n");
		return (DCMD_ERR);
	}

	bd->bd_curcpu = cpu;
	return (DCMD_OK);

}

static int
bhyve_seg2reg(const char *seg)
{
	if (strcasecmp(seg, "cs") == 0)
		return(VMM_DESC_CS);
	else if (strcasecmp(seg, "ds") == 0)
		return(VMM_DESC_DS);
	else if (strcasecmp(seg, "es") == 0)
		return(VMM_DESC_ES);
	else if (strcasecmp(seg, "fs") == 0)
		return(VMM_DESC_FS);
	else if (strcasecmp(seg, "gs") == 0)
		return (VMM_DESC_GS);
	else if (strcasecmp(seg, "ss") == 0)
		return (VMM_DESC_SS);
	else
		return (-1);
}

static int
bhyve_vtol_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	bhyve_data_t *bd = mdb.m_target->t_data;
	int segreg = bd->bd_defseg;
	char *seg = "";
	uint64_t laddr;
	int i;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	i = mdb_getopts(argc, argv, 's', MDB_OPT_STR, &seg, NULL);

	argc -= i;
	argv += i;

	if (i != 0) {
		if (argc != 0)
			return (DCMD_USAGE);

		segreg = bhyve_seg2reg(seg);
		if (segreg == -1)
			return (DCMD_USAGE);
	}

	if (vmm_vtol(bd->bd_vmm, bd->bd_curcpu, segreg, addr, &laddr) != 0) {
		if (errno == EFAULT)
			set_errno(EMDB_NOMAP);
		return (DCMD_ERR);
	}

	if (flags & DCMD_PIPE_OUT)
		mdb_printf("%llr\n", laddr);
	else
		mdb_printf("virtual %lr mapped to linear %llr\n", addr, laddr);

	return (DCMD_OK);
}

static int
bhyve_vtop_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	bhyve_data_t *bd = mdb.m_target->t_data;
	int segreg = bd->bd_defseg;
	char *seg = "";
	physaddr_t pa;
	int i;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	i = mdb_getopts(argc, argv, 's', MDB_OPT_STR, &seg, NULL);

	argc -= i;
	argv += i;

	if (i != 0) {
		segreg = bhyve_seg2reg(seg);
		if (segreg == -1)
			return (DCMD_USAGE);
	}

	if (vmm_vtop(bd->bd_vmm, bd->bd_curcpu, segreg, addr, &pa) == -1) {
		mdb_warn("failed to get physical mapping");
		return (DCMD_ERR);
	}

	if (flags & DCMD_PIPE_OUT)
		mdb_printf("%llr\n", pa);
	else
		mdb_printf("virtual %lr mapped to physical %llr\n", addr, pa);
	return (DCMD_OK);
}

static int
bhyve_defseg_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	bhyve_data_t *bd = mdb.m_target->t_data;
	int segreg = bd->bd_defseg;
	char *seg = "";
	int i;

	if (flags & DCMD_ADDRSPEC)
		return (DCMD_USAGE);

	i = mdb_getopts(argc, argv, 's', MDB_OPT_STR, &seg, NULL);

	argc -= i;
	argv += i;

	if (i != 0) {
		if (argc != 0)
			return (DCMD_USAGE);

		segreg = bhyve_seg2reg(seg);
		if (segreg == -1)
			return (DCMD_USAGE);

		bd->bd_defseg = segreg;
	}

	mdb_printf("using segment %s for virtual to linear address translation",
	    segments[bd->bd_defseg - VMM_DESC_CS]);

	return (DCMD_OK);
}

static const mdb_dcmd_t bhyve_dcmds[] = {
	{ "$c", NULL, "print stack backtrace", bhyve_stack_dcmd },
	{ "$C", NULL, "print stack backtrace", bhyve_stackv_dcmd },
	{ "$r", NULL, "print general-purpose registers", bhyve_regs_dcmd },
	{ "$?", NULL, "print status and registers", bhyve_regs_dcmd },
	{ ":x", ":", "change the active CPU", bhyve_switch_dcmd },
	{ "cpustack", "?[-v] [-c cpuid] [cnt]", "print stack backtrace for a "
	    "specific CPU", bhyve_cpustack_dcmd },
	{ "cpuregs", "?[-c cpuid]", "print general-purpose registers for a "
	    "specific CPU", bhyve_cpuregs_dcmd },
	{ "dbgregs", "?[-c cpuid]", "print debug registers for a specific CPU",
	    bhyve_dbgregs_dcmd },
	{ "defseg", "?[-s segment]", "change the default segment used to "
	    "translate addresses", bhyve_defseg_dcmd },
	{ "regs", NULL, "print general-purpose registers", bhyve_regs_dcmd },
	{ "stack", NULL, "print stack backtrace", bhyve_stack_dcmd },
	{ "stackregs", NULL, "print stack backtrace and registers",
	    bhyve_stackr_dcmd },
	{ "status", NULL, "print summary of current target",
	    bhyve_status_dcmd },
	{ "sysregs", "?[-c cpuid]", "print system registers for a specific CPU",
	    bhyve_sysregs_dcmd },
	{ "switch", ":", "change the active CPU", bhyve_switch_dcmd },
	{ "vtol", ":[-s segment]", "print linear mapping of virtual address",
	    bhyve_vtol_dcmd },
	{ "vtop", ":[-s segment]", "print physical mapping of virtual "
	    "address", bhyve_vtop_dcmd },
	{ NULL }
};


/*
 * t_setflags: change target flags
 */
static int
bhyve_setflags(mdb_tgt_t *tgt, int flags)
{
	bhyve_data_t *bd = tgt->t_data;

	if (((tgt->t_flags ^ flags) & MDB_TGT_F_RDWR) != 0) {
		boolean_t writable = (flags & MDB_TGT_F_RDWR) != 0;

		vmm_unmap(bd->bd_vmm);
		if (vmm_map(bd->bd_vmm, writable)!= 0) {
			mdb_warn("failed to map guest memory");
			return (set_errno(EMDB_TGT));
		}
	}

	tgt->t_flags = flags;

	return (0);
}

/*
 * t_activate: activate target
 */
static void
bhyve_activate(mdb_tgt_t *tgt)
{
	bhyve_data_t *bd = tgt->t_data;
	mdb_tgt_status_t tsp;
	const char *format;
	char buf[BUFSIZ];

	(void) mdb_set_prompt(MDB_DEF_PROMPT);

	(void) mdb_tgt_register_dcmds(tgt, bhyve_dcmds, MDB_MOD_FORCE);
	mdb_tgt_register_regvars(tgt, bhyve_kregs, &bhyve_reg_disc, 0);

	vmm_stop(bd->bd_vmm);

	if (mdb_tgt_status(tgt, &tsp) != 0)
		return;

	if (tsp.st_pc != 0) {
		if (mdb_dis_ins2str(mdb.m_disasm, mdb.m_target,
		    MDB_TGT_AS_VIRT_I, buf, sizeof (buf), tsp.st_pc) !=
		    tsp.st_pc)
			format = "target stopped at:\n%-#16a%8T%s\n";
		else
			format = "target stopped at %a:\n";
		mdb_warn(format, tsp.st_pc, buf);
	}
}

/*
 * t_deactivate: deactivate target
 */
static void
bhyve_deactivate(mdb_tgt_t *tgt)
{
	bhyve_data_t *bd = tgt->t_data;
	const mdb_tgt_regdesc_t *rd;
	const mdb_dcmd_t *dc;

	for (rd = bhyve_kregs; rd->rd_name != NULL; rd++) {
		mdb_var_t *var;

		if (!(rd->rd_flags & MDB_TGT_R_EXPORT))
			continue; /* didn't export register as variable */

		if ((var = mdb_nv_lookup(&mdb.m_nv, rd->rd_name)) != NULL) {
			var->v_flags &= ~MDB_NV_PERSIST;
			mdb_nv_remove(&mdb.m_nv, var);
		}
	}

	for (dc = bhyve_dcmds; dc->dc_name != NULL; dc++)
		if (mdb_module_remove_dcmd(tgt->t_module, dc->dc_name) == -1)
			mdb_warn("failed to remove dcmd %s", dc->dc_name);

	vmm_cont(bd->bd_vmm);
}

/*
 * t_name: return name of target
 */
static const char *
bhyve_name(mdb_tgt_t *tgt)
{
	_NOTE(ARGUNUSED(tgt));

	return ("bhyve");
}

/*
 * t_destroy: cleanup target private resources
 */
static void
bhyve_destroy(mdb_tgt_t *tgt)
{
	bhyve_data_t *bd = tgt->t_data;

	vmm_cont(bd->bd_vmm);
	vmm_unmap(bd->bd_vmm);
	vmm_close_vm(bd->bd_vmm);
	mdb_free(bd, sizeof (bhyve_data_t));
	tgt->t_data = NULL;
}

/*
 * t_isa: return name of target ISA
 */
const char *
bhyve_isa(mdb_tgt_t *tgt)
{
	_NOTE(ARGUNUSED(tgt));

	return ("amd64");
}

/*
 * t_dmodel: return target data model
 */
static int
bhyve_dmodel(mdb_tgt_t *tgt)
{
	_NOTE(ARGUNUSED(tgt));

	return (MDB_TGT_MODEL_LP64);
}

/*ARGSUSED*/
static ssize_t
bhyve_aread(mdb_tgt_t *tgt, mdb_tgt_as_t as, void *buf, size_t nbytes,
    mdb_tgt_addr_t addr)
{
	bhyve_data_t *bd = tgt->t_data;
	ssize_t cnt;

	switch ((uintptr_t)as) {
	case (uintptr_t)MDB_TGT_AS_VIRT:
		cnt = vmm_vread(bd->bd_vmm, bd->bd_curcpu, bd->bd_defseg, buf,
		    nbytes, addr);
		break;

	case (uintptr_t)MDB_TGT_AS_VIRT_I:
		cnt = vmm_vread(bd->bd_vmm, bd->bd_curcpu, VMM_DESC_CS, buf,
		    nbytes, addr);
		break;

	case (uintptr_t)MDB_TGT_AS_VIRT_S:
		cnt = vmm_vread(bd->bd_vmm, bd->bd_curcpu, VMM_DESC_SS, buf,
		    nbytes, addr);
		break;

	case (uintptr_t)MDB_TGT_AS_PHYS:
		cnt = vmm_pread(bd->bd_vmm, buf, nbytes, addr);
		break;

	case (uintptr_t)MDB_TGT_AS_FILE:
	case (uintptr_t)MDB_TGT_AS_IO:
		return (set_errno(EMDB_TGTNOTSUP));
	}

	if (errno == EFAULT)
		return (set_errno(EMDB_NOMAP));

	return (cnt);
}

/*ARGSUSED*/
static ssize_t
bhyve_awrite(mdb_tgt_t *tgt, mdb_tgt_as_t as, const void *buf, size_t nbytes,
    mdb_tgt_addr_t addr)
{
	bhyve_data_t *bd = tgt->t_data;
	ssize_t cnt;

	switch ((uintptr_t)as) {
	case (uintptr_t)MDB_TGT_AS_VIRT:
		cnt = vmm_vwrite(bd->bd_vmm, bd->bd_curcpu, bd->bd_defseg, buf,
		    nbytes, addr);
		break;

	case (uintptr_t)MDB_TGT_AS_VIRT_I:
		cnt = vmm_vwrite(bd->bd_vmm, bd->bd_curcpu, VMM_DESC_CS, buf,
		    nbytes, addr);
		break;

	case (uintptr_t)MDB_TGT_AS_VIRT_S:
		cnt = vmm_vwrite(bd->bd_vmm, bd->bd_curcpu, VMM_DESC_SS, buf,
		    nbytes, addr);
		break;

	case (uintptr_t)MDB_TGT_AS_PHYS:
		cnt = vmm_pwrite(bd->bd_vmm, buf, nbytes, addr);
		break;

	case (uintptr_t)MDB_TGT_AS_FILE:
	case (uintptr_t)MDB_TGT_AS_IO:
		return (set_errno(EMDB_TGTNOTSUP));
	}

	if (errno == EFAULT)
		return (set_errno(EMDB_NOMAP));

	return (cnt);
}

/*
 * t_vread: read from virtual memory
 */
/*ARGSUSED*/
static ssize_t
bhyve_vread(mdb_tgt_t *tgt, void *buf, size_t nbytes, uintptr_t addr)
{
	return (bhyve_aread(tgt, MDB_TGT_AS_VIRT, buf, nbytes, addr));
}

/*
 * t_vwrite: write to virtual memory
 */
/*ARGSUSED*/
static ssize_t
bhyve_vwrite(mdb_tgt_t *tgt, const void *buf, size_t nbytes, uintptr_t addr)
{
	return (bhyve_awrite(tgt, MDB_TGT_AS_VIRT, buf, nbytes, addr));
}

/*
 * t_pread: read from physical memory
 */
/*ARGSUSED*/
static ssize_t
bhyve_pread(mdb_tgt_t *tgt, void *buf, size_t nbytes, physaddr_t addr)
{
	return (bhyve_aread(tgt, MDB_TGT_AS_PHYS, buf, nbytes, addr));
}

/*
 * t_pwrite: write to physical memory
 */
/*ARGSUSED*/
static ssize_t
bhyve_pwrite(mdb_tgt_t *tgt, const void *buf, size_t nbytes, physaddr_t addr)
{
	return (bhyve_awrite(tgt, MDB_TGT_AS_PHYS, buf, nbytes, addr));
}

/*
 * t_fread: read from core/object file
 */
/*ARGSUSED*/
static ssize_t
bhyve_fread(mdb_tgt_t *tgt, void *buf, size_t nbytes, uintptr_t addr)
{
	return (bhyve_aread(tgt, MDB_TGT_AS_FILE, buf, nbytes, addr));
}

/*
 * t_fwrite: write to core/object file
 */
/*ARGSUSED*/
static ssize_t
bhyve_fwrite(mdb_tgt_t *tgt, const void *buf, size_t nbytes, uintptr_t addr)
{
	return (bhyve_awrite(tgt, MDB_TGT_AS_FILE, buf, nbytes, addr));
}

/*
 * t_ioread: read from I/O space
 */
/*ARGSUSED*/
static ssize_t
bhyve_ioread(mdb_tgt_t *tgt, void *buf, size_t nbytes, uintptr_t addr)
{
	return (bhyve_aread(tgt, MDB_TGT_AS_IO, buf, nbytes, addr));
}

/*
 * t_iowrite: write to I/O space
 */
/*ARGSUSED*/
static ssize_t
bhyve_iowrite(mdb_tgt_t *tgt, const void *buf, size_t nbytes, uintptr_t addr)
{
	return (bhyve_awrite(tgt, MDB_TGT_AS_IO, buf, nbytes, addr));
}

/*
 * t_vtop: translate virtual to physical address
 */
static int
bhyve_vtop(mdb_tgt_t *tgt, mdb_tgt_as_t as, uintptr_t va, physaddr_t *pa)
{
	bhyve_data_t *bd = tgt->t_data;
	int seg;

	switch ((uintptr_t)as) {
	case (uintptr_t)MDB_TGT_AS_VIRT:
		seg = bd->bd_defseg;
		break;

	case (uintptr_t)MDB_TGT_AS_VIRT_I:
		seg = VMM_DESC_CS;
		break;

	case (uintptr_t)MDB_TGT_AS_VIRT_S:
		seg = VMM_DESC_SS;
		break;

	default:
		return (set_errno(EINVAL));
	}

	if (vmm_vtop(bd->bd_vmm, bd->bd_curcpu, seg, va, pa) != 0) {
		if (errno == EFAULT)
			return (set_errno(EMDB_NOMAP));
		else
			return (-1);
	}

	return (0);
}

/*
 * t_status: get target status
 */
static int
bhyve_status(mdb_tgt_t *tgt, mdb_tgt_status_t *tsp)
{
	bhyve_data_t *bd = tgt->t_data;
	mdb_tgt_reg_t rip;
	vmm_desc_t cs;
	int ret;

	bzero(tsp, sizeof (mdb_tgt_status_t));

	ret = vmm_getreg(bd->bd_vmm, bd->bd_curcpu, KREG_RIP, &rip);
	if (ret != 0) {
		tsp->st_state = MDB_TGT_UNDEAD;
	} else {
		tsp->st_state = MDB_TGT_STOPPED;
		tsp->st_pc = rip;
	}

	switch (vmm_vcpu_isa(bd->bd_vmm, bd->bd_curcpu)) {
	case VMM_ISA_16:
		mdb_dis_select("ia16");
		break;
	case VMM_ISA_32:
		mdb_dis_select("ia32");
		break;
	case VMM_ISA_64:
		mdb_dis_select("amd64");
		break;
	default:
		break;
	}

	return (0);
}

static void
bhyve_sighdl(int sig, siginfo_t *sip, ucontext_t *ucp, mdb_tgt_t *tgt)
{
	bhyve_data_t *bd = tgt->t_data;

	switch (sig) {
	case SIGINT:
		vmm_stop(bd->bd_vmm);
		break;
	}
}

/*
 * t_step: single-step target
 */
static int
bhyve_step(mdb_tgt_t *tgt, mdb_tgt_status_t *tsp)
{
	bhyve_data_t *bd = tgt->t_data;
	int ret;

	ret = vmm_step(bd->bd_vmm, bd->bd_curcpu);
	(void) mdb_tgt_status(tgt, tsp);

	return (ret);
}

/*
 * t_cont: continue target execution
 *
 * Catch SIGINT so that the target can be stopped with Ctrl-C.
 */
static int
bhyve_cont(mdb_tgt_t *tgt, mdb_tgt_status_t *tsp)
{
	bhyve_data_t *bd = tgt->t_data;
	mdb_signal_f *intf;
	void *intd;
	int ret;

	intf = mdb_signal_gethandler(SIGINT, &intd);
	(void) mdb_signal_sethandler(SIGINT, (mdb_signal_f *)bhyve_sighdl, tgt);

	vmm_cont(bd->bd_vmm);

	tsp->st_state = MDB_TGT_RUNNING;
	pause();

	(void) mdb_signal_sethandler(SIGINT, intf, intd);
	(void) mdb_tgt_status(tgt, tsp);

	return (ret);
}

static int
bhyve_lookup_reg(mdb_tgt_t *tgt, const char *rname)
{
	bhyve_data_t *bd = tgt->t_data;
	const mdb_tgt_regdesc_t *rd;

	for (rd = bhyve_kregs; rd->rd_name != NULL; rd++)
		if (strcmp(rd->rd_name, rname) == 0)
			return (rd->rd_num);

	return (-1);
}

/*
 * t_getareg: get the value of a single register
 */
static int
bhyve_getareg(mdb_tgt_t *tgt, mdb_tgt_tid_t tid, const char *rname,
    mdb_tgt_reg_t *rp)
{
	bhyve_data_t *bd = tgt->t_data;
	int reg = bhyve_lookup_reg(tgt, rname);
	int ret;

	if (reg == -1)
		return (set_errno(EMDB_BADREG));

	ret = vmm_getreg(bd->bd_vmm, bd->bd_curcpu, reg, rp);
	if (ret == -1)
		return (set_errno(EMDB_BADREG));

	return (0);
}

/*
 * t_putareg: set the value of a single register
 */
static int
bhyve_putareg(mdb_tgt_t *tgt, mdb_tgt_tid_t tid, const char *rname,
    mdb_tgt_reg_t r)
{
	bhyve_data_t *bd = tgt->t_data;
	int reg = bhyve_lookup_reg(tgt, rname);
	int ret;

	if ((tgt->t_flags & MDB_TGT_F_RDWR) == 0)
		return (set_errno(EMDB_TGTRDONLY));

	if (reg == -1)
		return (set_errno(EMDB_BADREG));

	ret = vmm_setreg(bd->bd_vmm, bd->bd_curcpu, reg, r);
	if (ret == -1)
		return (set_errno(EMDB_BADREG));

	return (0);
}

static const mdb_tgt_ops_t bhyve_ops = {
	.t_setflags =		bhyve_setflags,
	.t_setcontext =		(int (*)()) mdb_tgt_notsup,
	.t_activate =		bhyve_activate,
	.t_deactivate =		bhyve_deactivate,
	.t_periodic =		(void (*)()) mdb_tgt_nop,
	.t_destroy =		bhyve_destroy,
	.t_name =		bhyve_name,
	.t_isa =		bhyve_isa,
	.t_platform =		(const char *(*)()) mdb_conf_platform,
	.t_uname =		(int (*)()) mdb_tgt_notsup,
	.t_dmodel =		bhyve_dmodel,
	.t_aread =		bhyve_aread,
	.t_awrite =		bhyve_awrite,
	.t_vread =		bhyve_vread,
	.t_vwrite =		bhyve_vwrite,
	.t_pread =		bhyve_pread,
	.t_pwrite =		bhyve_pwrite,
	.t_fread =		bhyve_fread,
	.t_fwrite =		bhyve_fwrite,
	.t_ioread =		bhyve_ioread,
	.t_iowrite =		bhyve_iowrite,
	.t_vtop =		bhyve_vtop,
	.t_lookup_by_name =	(int (*)()) mdb_tgt_notsup,
	.t_lookup_by_addr =	(int (*)()) mdb_tgt_notsup,
	.t_symbol_iter =	(int (*)()) mdb_tgt_notsup,
	.t_mapping_iter =	(int (*)()) mdb_tgt_notsup,
	.t_object_iter =	(int (*)()) mdb_tgt_notsup,
	.t_addr_to_map =	(const mdb_map_t *(*)()) mdb_tgt_null,
	.t_name_to_map =	(const mdb_map_t *(*)()) mdb_tgt_null,
	.t_addr_to_ctf =	(struct ctf_file *(*)()) mdb_tgt_null,
	.t_name_to_ctf =	(struct ctf_file *(*)()) mdb_tgt_null,
	.t_status =		bhyve_status,
	.t_run =		(int (*)()) mdb_tgt_notsup,
	.t_step =		bhyve_step,
	.t_step_out =		(int (*)()) mdb_tgt_notsup,
	.t_next =		(int (*)()) mdb_tgt_notsup,
	.t_cont =		bhyve_cont,
	.t_signal =		(int (*)()) mdb_tgt_notsup,
	.t_add_vbrkpt =		(int (*)()) mdb_tgt_null,
	.t_add_sbrkpt =		(int (*)()) mdb_tgt_null,
	.t_add_pwapt =		(int (*)()) mdb_tgt_null,
	.t_add_vwapt =		(int (*)()) mdb_tgt_null,
	.t_add_iowapt =		(int (*)()) mdb_tgt_null,
	.t_add_sysenter =	(int (*)()) mdb_tgt_null,
	.t_add_sysexit =	(int (*)()) mdb_tgt_null,
	.t_add_signal =		(int (*)()) mdb_tgt_null,
	.t_add_fault =		(int (*)()) mdb_tgt_null,
	.t_getareg =		bhyve_getareg,
	.t_putareg =		bhyve_putareg,
	.t_stack_iter =		(int (*)()) mdb_tgt_notsup,
	.t_auxv =		(int (*)()) mdb_tgt_notsup
};

int
mdb_bhyve_tgt_create(mdb_tgt_t *tgt, int argc, const char *argv[])
{
	bhyve_data_t *bd;
	vmm_t *vmm = NULL;
	boolean_t writable = (tgt->t_flags & MDB_TGT_F_RDWR) != 0;

	if (argc != 1)
		return (set_errno(EINVAL));

	vmm = vmm_open_vm(argv[0]);
	if (vmm == NULL) {
		mdb_warn("failed to open %s", argv[0]);
		return (set_errno(EMDB_TGT));
	}

	if (vmm_map(vmm, writable) != 0) {
		mdb_warn("failed to map %s", argv[0]);
		vmm_close_vm(vmm);
		return (set_errno(EMDB_TGT));
	}

	bd = mdb_zalloc(sizeof (bhyve_data_t) + strlen(argv[0]) + 1, UM_SLEEP);
	strcpy(bd->bd_name, argv[0]);
	bd->bd_vmm = vmm;
	bd->bd_curcpu = 0;
	bd->bd_defseg = VMM_DESC_DS;

	tgt->t_ops = &bhyve_ops;
	tgt->t_data = bd;
	tgt->t_flags |= MDB_TGT_F_ASIO;

	(void) mdb_nv_insert(&mdb.m_nv, "cpuid", &bhyve_cpuid_disc, 0,
	    MDB_NV_PERSIST | MDB_NV_RDONLY);

	return (0);
}
