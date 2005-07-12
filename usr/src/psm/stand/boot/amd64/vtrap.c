/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Contains the set of routines that implement the bootops and bsyscall
 * vectors for a 64-bit client program.
 */

#include <sys/types.h>
#include <sys/controlregs.h>
#include <sys/trap.h>
#include <sys/bootsvcs.h>

#include <amd64/print.h>
#include <amd64/bootops64.h>
#include <amd64/bootsvcs64.h>
#include <amd64/machregs.h>
#include <amd64/alloc.h>
#include <amd64/amd64_page.h>
#include <amd64/cpu.h>
#include <amd64/debug.h>
#include <amd64/amd64.h>

uint_t bop64_trace =
#if defined(DEBUG)
	/* AMD64_TRACE_BOP_VM | XX64 - also too chatty */
	/* AMD64_TRACE_BOP_PROP | XX64 - also too chatty */
	/* AMD64_TRACE_BOP_BIOS | XX64 - final vestiges of chattyness */
#endif
	0;

static struct bsys_mem64 *amd64_update_ml64(struct bootops *);

/*
 * Memory page set aside for translation of boot's memory lists into
 * "struct memlist64" format
 */
struct memlist64 *amd64_memlistpage;

static void
return_int(struct amd64_machregs *rp, int rval)
{
	rp->r_rax = (int64_t)rval;
}

static void
return_paddr(struct amd64_machregs *rp, void *rval)
{
	rp->r_rax = (caddr64_t)(uint32_t)rval;
}

static void
return_addr(struct amd64_machregs *rp, void *rval)
{
	rp->r_rax = (caddr64_t)ADDR_XTND(rval);
}

static const char *
trap_type_name(uint_t type)
{
	switch (type) {
	case T_ZERODIV:		return ("Divide error (#de)");
	case T_SGLSTP:		return ("Debug (#db)");
	case T_NMIFLT:		return ("NMI interrupt");
	case T_BPTFLT:		return ("Breakpoint (#bp)");
	case T_OVFLW:		return ("Overflow (#of)");
	case T_BOUNDFLT:	return ("BOUND range exceeded (#br)");
	case T_ILLINST:		return ("Invalid opcode (#ud)");
	case T_NOEXTFLT:	return ("Device not available (#nm)");
	case T_DBLFLT:		return ("Double fault (#df)");
	case T_EXTOVRFLT:	return ("(i386 only reserved trap (9))");
	case T_TSSFLT:		return ("Invalid TSS (#ts)");
	case T_SEGFLT:		return ("Segment not present (#np)");
	case T_STKFLT:		return ("Stack segment fault (#ss)");
	case T_GPFLT:		return ("General protection (#gp)");
	case T_PGFLT:		return ("Page fault (#pf)");
	case 15:		return ("Intel reserved trap (15)");
	case T_EXTERRFLT:	return ("x87 floating point error (#mf)");
	case T_ALIGNMENT:	return ("Alignment check (#ac)");
	case T_MCE:		return ("Machine check (#mc)");
	case T_SIMDFPE:		return ("SIMD floating point exception (#xf)");
	default:
				/*
				 * see r_trapno for type. Sorry but amd64
				 * does not support sprtintf().
				 */
				return ("reserved, external or soft int");
	}
}

/*
 * (When we need to get more ambitious with this, we
 * can climb the long-mode stack to see how we got here..)
 */
/*PRINTFLIKE2*/
static void
traceback64(struct amd64_machregs *rp, const char *fmt, ...)
{
	va_list ap;

	printf("%%rip: entry 0x%16" PRIx64 " return 0x%16" PRIx64 "\n",
	    rp->r_trapno, rp->r_rip);
	printf("%%rsp: 0x%16" PRIx64 "\n", rp->r_rsp);

	va_start(ap, fmt);
	amd64_vpanic(fmt, ap);
	va_end(ap);
}

/*
 * We took a real exception thru amd64's IDT.
 * Dump state and reset machine.
 */
static void
idt_exception(struct amd64_machregs *rp)
{
	printf("AMD64_BAD_TRAP: %s error=0x%llx\n\n",
	    trap_type_name(rp->r_trapno), rp->r_err);

	amd64_dump_amd64_machregs(rp);
	printf("resetting ...");
	amd64_system_reset();
	/*NOTREACHED*/
}

extern uintptr_t bsys64_first, bsys64_last, bop64_first, bop64_last;
extern struct boot_syscalls *entry_boot_syscalls;

#ifdef	DEBUG
static void
amd64_assert_addr(caddr_t addr, int64_t arg_64, char *caller_name, char *type)
{
	if ((int64_t)ADDR_XTND(addr) != arg_64)
		amd64_panic("%s(): unexpected address for %s\n"
		    "    (expected 0x%llx, passed 0x%llx)\n", caller_name,
		    type, (int64_t)ADDR_XTND(addr), arg_64);
}

static int
amd64_check_mapped_32(uint64_t addr, char *caller_name, char *type)
{
	if (!(amd64_legacy_lookup((uint64_t)(uintptr_t)addr, (uint32_t *)0,
	    amd64_get_cr3()))) {
		printf("ERROR: %s(): called with unmapped 32-bit %s @ "
		"0x%llx\n       failing operation...\n", caller_name, type,
		addr);
	    return (0);
	}

	return (1);
}

static int
amd64_check_arg(caddr_t addr, int64_t arg_64, char *caller_name, char *type)
{
	amd64_assert_addr(addr, arg_64, caller_name, type);
	return (amd64_check_mapped_32((uint64_t)(uintptr_t)addr, caller_name,
	    type));
}
#endif	/* DEBUG */

static void
amd64_invoke_bootop(
	struct amd64_machregs *rp,
	struct bootops64 *bop64,
	struct bootops *bop)
{
	extern uint64_t amd64_boot_pml4;

	fnaddr64_t this = (fnaddr64_t)rp->r_rip;
	enum tracetype {
		TRACE_NONE_RETURN,
		TRACE_INT_RETURN,
		TRACE_ADDR_RETURN,
		TRACE_VOID_RETURN
	} trace = TRACE_NONE_RETURN;

	if (this == bop64->bsys_alloc) {

		caddr_t vahint = ADDR_TRUNC(_ARG2(rp));
		size_t size = (size_t)_ARG3(rp);
		int align = (int)_ARG4(rp);
		void *retval;

		if (rp->r_cr3 != amd64_boot_pml4)
			amd64_panic("bop64_alloc() called with wrong 64-bit "
			    "page table start address\n  (caller's cr3: "
			    "0x%llx, should be: 0x%llx)\n", rp->r_cr3,
			    amd64_boot_pml4);

		if (bop64_trace & AMD64_TRACE_BOP_VM) {
			printf("+alloc(vahint 0x%p/0x%" PRIx64
			    " size %lu/%" PRIu64 " align %d) ",
			    (void *)vahint, _ARG2(rp),
			    size, _ARG3(rp), align);
			trace = TRACE_ADDR_RETURN;
		}

#ifdef	DEBUG
		amd64_assert_addr(vahint, _ARG2(rp), "BOP_ALLOC", "vahint");
#endif	/* DEBUG */

		retval = BOP_ALLOC(bop, vahint, size, align);

		if (retval != 0)
			amd64_xlate_legacy_va((uint32_t)retval, size,
			    amd64_get_cr3(), amd64_boot_pml4);

		return_addr(rp, retval);

	} else if (this == bop64->bsys_free) {

		caddr_t va = ADDR_TRUNC(_ARG2(rp));
		size_t size = (size_t)_ARG3(rp);

		if (rp->r_cr3 != amd64_boot_pml4)
			amd64_panic("bop64_free() called with wrong 64-bit "
			    "page table start address\n  (caller's cr3: "
			    "0x%llx, should be: 0x%llx)\n", rp->r_cr3,
			    amd64_boot_pml4);

		if (bop64_trace & AMD64_TRACE_BOP_VM) {
			printf("+free(va 0x%p/0x%" PRIx64
			    " size %lu/%" PRIu64 ") ",
			    (void *)va, _ARG2(rp), size, _ARG3(rp));
			trace = TRACE_VOID_RETURN;
		}

#ifdef	DEBUG
		amd64_assert_addr(va, _ARG2(rp), "BOP_FREE", "va");
#endif	/* DEBUG */

		BOP_FREE(bop, va, size);

	} else if (this == bop64->bsys_getproplen) {

		/*
		 * The property routines are mostly pass-through, but
		 * we take steps to hide our existence, so that the
		 * 64-bit kernel really does think it's talking to
		 * a native booter
		 *
		 * XX64	The "real" version of 'whoami' handling should be
		 *	done in boot -- if that booter is asked to boot an
		 *	EM_AMD64 file, it should know to put stretch into
		 *	memory, then tell stretch and the kernel to boot
		 *	that program, then we wouldn't need to fib here,
		 *	because boot would be fibbing for us.
		 */

		char *name = ADDR_TRUNC(_ARG2(rp));

		if (bop64_trace & AMD64_TRACE_BOP_PROP) {
			printf("+getproplen(name 0x%p/0x%" PRIx64
			    " '%s') ", (void *)name, _ARG2(rp), name);
			trace = TRACE_INT_RETURN;
		}

#ifdef	DEBUG
		if (!amd64_check_arg((caddr_t)name, _ARG2(rp), "BOP_GETPROPLEN",
		    "property name")) {
			return_int(rp, 0);
			return;
		}
#endif	/* DEBUG */

		if (strcmp(name, "mmu-modlist") == 0) {
			return_int(rp, strlen(amd64_getmmulist()) + 1);
		} else
			return_int(rp, BOP_GETPROPLEN(bop, name));

	} else if (this == bop64->bsys_getprop) {

		char *name = ADDR_TRUNC(_ARG2(rp));
		caddr_t value = ADDR_TRUNC(_ARG3(rp));

		if (bop64_trace & AMD64_TRACE_BOP_PROP) {
			printf("+getprop(name 0x%p/0x%" PRIx64
			    " '%s' value 0x%p/0x%" PRIx64 " ",
			    (void *)name, _ARG2(rp), name, (void *)value,
			    _ARG3(rp));
		}

#ifdef	DEBUG
		if (!amd64_check_arg((caddr_t)name, _ARG2(rp), "BOP_GETPROP",
		    "property name")) {
			return_int(rp, -1);
			return;
		}

		/*
		 * amd64_check_arg() can't be used here because krtld
		 * does a bop_getprop("whoami") with a buffer that is in stack
		 * space allocated just above AMD64 in memory, typically on the
		 * page mapped at 0x100f000), so just check to make sure the
		 * destination buffer is mapped in a way we can access.
		 */
		if (!amd64_check_mapped_32((uint64_t)(uintptr_t)value,
		    "BOP_GETPROP", "property value buffer")) {
			return_int(rp, -1);
			return;
		}
#endif	/* DEBUG */

		if (strcmp(name, "memory-update") == 0) {
			int retval;

			retval = BOP_GETPROP(bop, name, value);
			(void) amd64_update_ml64(bop);
			return_int(rp, retval);
		} else if (strcmp(name, "mmu-modlist") == 0) {
			(void) strcpy(value, amd64_getmmulist());
			return_int(rp, 0);
		} else
			return_int(rp, BOP_GETPROP(bop, name, value));

		if (bop64_trace & AMD64_TRACE_BOP_PROP) {
			static const char *string_props[] = {
				"backfs-fstype",
				"backfs-path",
				"bootargs",
				"bootpath",
				"boot-path",
				"boot-message",
				"default-name",
				"extent",
				"frontfs-fstype",
				"frontfs-path",
				"fstype",
				"impl-arch-name",
				"mfg-name",
				"whoami",
				0
			};
			const char * const *sp;

			printf(" = %" PRId64, rp->r_rax);

			/*
			 * (Sigh. This is a rather tawdry hack so that
			 * we can print out various "well-known" string
			 * properties as strings.)
			 */
			for (sp = string_props; *sp; sp++)
				if (strcmp(*sp, name) == 0) {
					printf(" [= '%s']", value);
					break;
				}

			printf("\n");
		}

	} else if (this == bop64->bsys_nextprop) {

		char *prevprop = ADDR_TRUNC(_ARG2(rp));

		if (bop64_trace & AMD64_TRACE_BOP_PROP) {
			printf("+nextprop(prevprop 0x%p/0x%" PRIx64
			    "/'%s') ", (void *)prevprop, _ARG2(rp), prevprop);
			trace = TRACE_ADDR_RETURN;
		}

#ifdef	DEBUG
		if (!amd64_check_arg((caddr_t)prevprop, _ARG2(rp),
		    "BOP_NEXTPROP", "previous property")) {
			return_addr(rp, 0);
			return;
		}
#endif	/* DEBUG */

		return_addr(rp, BOP_NEXTPROP(bop, prevprop));

	} else if (this == bop64->bsys_printf) {

		char lnbuf[128];
		char *fmt = ADDR_TRUNC(_ARG2(rp));
		int lnlen;

#if 0	/* correct code */
		ASSERT((uint16_t)rp->r_rax <= 8);	/* no SSE regs! */
#else	/* XX64 */
		/*
		 * Technically an ABI violation, gcc 3.2.3 currently
		 * only does a "mov $0, al" before calling printf, with
		 * the result that we tripped over this assert due to garbage
		 * in the upper 8 bytes of what would be ax.
		 */
		ASSERT((uint8_t)rp->r_rax <= 8);	/* no SSE regs! */
#endif

#ifdef	DEBUG
		if (!amd64_check_mapped_32((uint64_t)(uintptr_t)fmt,
		    "BOP_PRINTF", "fmt string"))
			return;
#endif	/* DEBUG */

		lnlen = amd64_snprintf64(lnbuf, sizeof (lnbuf), fmt,
		    _ARG3(rp), _ARG4(rp), _ARG5(rp), _ARG6(rp));

		printf("%s%s", lnbuf,
		    (lnlen > sizeof (lnbuf)) ? " [truncated]\n" : "");

	} else if (this == bop64->bsys_doint) {

		int intnum = (int)_ARG2(rp);
		struct bop_regs *regs = ADDR_TRUNC(_ARG3(rp));

		/*
		 * (Looks like the -kernel- only does this for pci_check()
		 */

		if (bop64_trace & AMD64_TRACE_BOP_BIOS) {
			printf("+doint(intnum %d "
			    "regs 0x%p/0x%" PRIx64 ") ",
			    intnum, (void *)regs, _ARG3(rp));
			trace = TRACE_VOID_RETURN;
		}

#ifdef	DEBUG
		if (!amd64_check_arg((caddr_t)regs, _ARG3(rp), "BOP_DOINT",
		    "regs"))
			return;
#endif	/* DEBUG */

		BOP_DOINT(bop, intnum, regs);

	} else if (this == bop64->bsys_ealloc) {

		caddr_t vahint = ADDR_TRUNC(_ARG2(rp));
		size_t size = (size_t)_ARG3(rp);
		int align = (int)_ARG4(rp);
		int flags = (int)_ARG5(rp);
		void *retval;

		if (rp->r_cr3 != amd64_boot_pml4)
			amd64_panic("bop64_ealloc() called with wrong 64-bit "
			    "page table start address\n  (caller's cr3: "
			    "0x%llx, should be: 0x%llx)\n", rp->r_cr3,
			    amd64_boot_pml4);

		if (bop64_trace & AMD64_TRACE_BOP_VM) {
			printf("+ealloc(vahint 0x%p/0x%" PRIx64
			    " size %lu/%" PRIu64 " align %d flags 0x%x) ",
			    (void *)vahint, _ARG2(rp), size, _ARG3(rp), align,
			    flags);
			trace = TRACE_ADDR_RETURN;
		}

#ifdef	DEBUG
		if (vahint)
			amd64_assert_addr(vahint, _ARG2(rp), "BOP_EALLOC",
			    "vahint");
#endif	/* DEBUG */

		retval = BOP_EALLOC(bop, vahint, size, align, flags);

		/*
		 * Don't attempt to create 64-bit mappings for purely physical
		 * memory reservations or for failed allocations,
		 */
		if (flags & BOPF_X86_ALLOC_PHYS)
			return_paddr(rp, retval);
		else {
			if (retval != 0)
				amd64_xlate_legacy_va((uint32_t)retval, size,
				    amd64_get_cr3(), amd64_boot_pml4);

			return_addr(rp, retval);
		}
	} else
		traceback64(rp, "BOP_xxx (@ 0x%" PRIx64 ") unimp", this);

	switch (trace) {
	case TRACE_NONE_RETURN:
		break;
	case TRACE_INT_RETURN:
		printf(" = %" PRId64 "\n", rp->r_rax);
		break;
	case TRACE_ADDR_RETURN:
		printf(" = 0x%p/0x%" PRIx64 "\n",
		    ADDR_TRUNC(rp->r_rax), rp->r_rax);
		break;
	case TRACE_VOID_RETURN:
		printf(" = (void)\n");
		break;
	}
}

static struct bsys_mem64 *
amd64_update_ml64(struct bootops *bop)
{
	extern struct memlist64 *amd64_convert_memlist(struct memlist *,
	    struct memlist64 *);

	static struct bsys_mem64 __memlist64, *bop_ml64 = &__memlist64;

	struct memlist64 *ml64 = amd64_memlistpage;

	/*
	 * amd64_convert_memlist() returns a pointer to the entry one past the
	 * previous translated list, suitable for the start of the next new
	 * memlist64, so the assignments below may seem a bit non-intuitive
	 * at first...
	 */
	bop_ml64->physinstalled = UINT64_FROMPTR32(ml64);
	ml64 = amd64_convert_memlist(bop->boot_mem->physinstalled, ml64);

	bop_ml64->physavail = UINT64_FROMPTR32(ml64);
	ml64 = amd64_convert_memlist(bop->boot_mem->physavail, ml64);

	bop_ml64->pcimem = UINT64_FROMPTR32(ml64);
	ml64 = amd64_convert_memlist(bop->boot_mem->pcimem, ml64);
	return (bop_ml64);
}

static struct bootops *saved_bootops;

/*
 * This is the 64-bit bootops vector that we hand to the 64-bit standalone
 */
struct bootops64 *
init_bootops64(struct bootops *bop)
{
	static struct bootops64 __bootops64, *bop64 = &__bootops64;

#define	SET_BOP64(bop, opname)	\
	{								\
		extern uintptr_t bop64_##opname;			\
		(bop)->bsys_##opname =					\
			(fnaddr64_t)(uintptr_t)&bop64_##opname;		\
	}

	/* move to main.c or to startup */

	ASSERT(bop->bsys_version >= BO_VERSION);

	amd64_memlistpage = (struct memlist64 *)
	    amd64_zalloc_identity(2 * AMD64_PAGESIZE);

	saved_bootops = bop;
	bop64->bsys_version = BO_VERSION;
	bop64->boot_mem = (caddr64_t)(uintptr_t)amd64_update_ml64(bop);

	SET_BOP64(bop64, alloc)
	SET_BOP64(bop64, free)
	SET_BOP64(bop64, getproplen)
	SET_BOP64(bop64, getprop)
	SET_BOP64(bop64, nextprop)
	SET_BOP64(bop64, printf)
	SET_BOP64(bop64, doint)
	SET_BOP64(bop64, ealloc)

#undef SET_BOP64

	return (bop64);
}

static void
amd64_invoke_boot_syscall(
	struct amd64_machregs *rp,
	struct boot_syscalls *bsys,
	struct boot_syscalls64 *bsys64)
{
	fnaddr64_t this = (fnaddr64_t)rp->r_rip;

	if (this == bsys64->getchar) {
		rp->r_rax = BSVC_GETCHAR(bsys);
	} else if (this == bsys64->putchar) {
		BSVC_PUTCHAR(bsys, (uchar_t)rp->r_rdi);
	} else if (this == bsys64->ischar) {
		rp->r_rax = BSVC_ISCHAR(bsys);
	} else
		traceback64(rp, "bsys_xxx (type 0x%" PRIx64 ") unimp", this);
}

static struct boot_syscalls64 __boot_syscalls64;	/* XXX - global scope */
static struct boot_syscalls *saved_boot_syscallp;

/*
 * Return the 64-bit bsyscall vector that we hand to the 64-bit standalone
 */
struct boot_syscalls64 *
init_boot_syscalls64(struct boot_syscalls *bsys)
{
	struct boot_syscalls64 *bsys64 = &__boot_syscalls64;

	/*
	 * This variable is awful; the 'bsys' pointer should be
	 * the first argument to every bsys handler .. but in the
	 * meantime, this'll do.
	 */
	saved_boot_syscallp = bsys;

	bzero(bsys64, sizeof (*bsys64));

#define	SET_BSYS64(bsys, opname)					\
	{								\
		extern uintptr_t bsys64_##opname;			\
		(bsys)->opname =					\
			(fnaddr64_t)(uintptr_t)&bsys64_##opname;	\
	}

	SET_BSYS64(bsys64, getchar)
	SET_BSYS64(bsys64, putchar)
	SET_BSYS64(bsys64, ischar)

#undef SET_BSYS64

	return (bsys64);
}

static void dump_desctbr(const char *, desctbr_t *);
static void dump_desctbr64(const char *, desctbr64_t *);

/*
 * After stashing machine state we must convert the tss gdt entry from
 * busy to available type.
 */
/*ARGSUSED*/
void
amd64_i386_clrtss(struct i386_machregs *rp)
{
#if 0
	system_desc_t	*ssd;

	if (rp->r_tr != 0) {
		ASSERT(SELTOIDX(rp->r_tr) < SELTOIDX(rp->r_gdt.dtr_limit));
		ASSERT((rp->r_tr & CPL_MASK) == 0);
		ssd = (system_desc_t *)(rp->r_gdt.dtr_base + rp->r_tr);

		ASSERT(ssd->ssd_type == SDT_SYSTSSBSY);
		ssd->ssd_type = SDT_SYSTSS;
		ASSERT(rp->r_gdt.dtr_limit != 0);
	}
#endif
}

static void
amd64_clrtss(struct amd64_machregs *rp)
{
	system_desc64_t	*ssd;

	if (rp->r_tr != 0) {

		ASSERT(SELTOIDX(rp->r_tr) < SELTOIDX(rp->r_gdt.dtr_limit));
		ASSERT((rp->r_tr & CPL_MASK) == 0);
		ssd = (system_desc64_t *)(uintptr_t)
		    (rp->r_gdt.dtr_base + rp->r_tr);

		ssd->ssd_type = SDT_SYSTSS;
		ASSERT(rp->r_gdt.dtr_limit != 0);
	}
}

void
amd64_vtrap(struct amd64_machregs *rp)
{
	uintptr_t addr = (uintptr_t)rp->r_rip;

	/*
	 * __vtrap_common always sets r_trapno to -1
	 */
	if (rp->r_trapno == -1) {
		if ((addr - (uintptr_t)&bsys64_first) <=
		    ((uintptr_t)&bsys64_last - (uintptr_t)&bsys64_first)) {
			amd64_invoke_boot_syscall(rp,
			saved_boot_syscallp, &__boot_syscalls64);
		} else if ((addr - (uintptr_t)&bop64_first) <=
		    ((uintptr_t)&bop64_last - (uintptr_t)&bop64_first)) {
			struct bootops64 *bop64 = ADDR_TRUNC(_ARG1(rp));
			amd64_invoke_bootop(rp, bop64, saved_bootops);
		}
	} else {
		/*
		 * we took a real exception.
		 */
		idt_exception(rp);
	}

	amd64_clrtss(rp);
}

static const char *
desc_type_name(uint_t type)
{
	switch (type) {
		case SDT_SYSNULL:
		case SDT_SYSNULL2:
		case SDT_SYSNULL3:
		case SDT_SYSNULL4:	return ("illegal");
		case SDT_SYS286TSS:	return ("16-bit tss");
		case SDT_SYSLDT:	return ("ldt");
		case SDT_SYS286BSY:	return ("16-bit tss busy");
		case SDT_SYS286CGT:	return ("16-bit call gate");
		case SDT_SYSTASKGT:	return ("task gate");
		case SDT_SYS286IGT:	return ("16-bit intr gate");
		case SDT_SYS286TGT:	return ("16-bit trap gate");
		case SDT_SYSTSS:	return ("32-bit tss");
		case SDT_SYSTSSBSY:	return ("32-bit tss busy");
		case SDT_SYSCGT:	return ("32-bit call gate");
		case SDT_SYSIGT:	return ("32-bit intr gate");
		case SDT_SYSTGT:	return ("32-bit trap gate");

		case SDT_MEMRO:		return ("r-- --");
		case SDT_MEMROA:	return ("r-- -a");
		case SDT_MEMRW:		return ("rw- --");
		case SDT_MEMRWA:	return ("rw- -a");
		case SDT_MEMROD:	return ("r-- d-");
		case SDT_MEMRODA:	return ("r-- da");
		case SDT_MEMRWD:	return ("rw- d-");
		case SDT_MEMRWDA:	return ("rw- da");
		case SDT_MEME:		return ("--x --");
		case SDT_MEMEA:		return ("--x -a");
		case SDT_MEMER:		return ("r-x --");
		case SDT_MEMERA:	return ("r-x -a");
		case SDT_MEMEC:		return ("--x c-");
		case SDT_MEMEAC:	return ("--x ca");
		case SDT_MEMERC:	return ("r-x c-");
		case SDT_MEMERAC:	return ("r-x ca");
		default:		return ("(unknown)");
	}
}

static size_t
dump_ssd(void *desc)
{
	uint_t type = ((struct user_segment_descriptor *)desc)->usd_type;

	printf("type %2d (%s) ", type, desc_type_name(type));

	switch (type) {

		case SDT_SYSTASKGT: {
			struct gate_segment_descriptor *sgd = desc;

			printf("tss sel 0x%x dpl %d %spresent\n",
			    sgd->sgd_selector, sgd->sgd_dpl,
			    sgd->sgd_p ? "" : "NOT ");
			return (sizeof (*sgd));
		}

		case SDT_SYSLDT:
		case SDT_SYSTSS:
		case SDT_SYSTSSBSY: {
			struct system_segment_descriptor *ssd = desc;
			uint32_t base = ssd->ssd_lobase |
			    (ssd->ssd_midbase << 16) | (ssd->ssd_hibase << 24);
			uint32_t lim = ssd->ssd_lolimit |
			    (ssd->ssd_hilimit << 16);

			printf("base 0x%x lim 0x%x dpl %d %spresent\n",
			    base, ssd->ssd_gran ? lim * 4096 : lim,
			    ssd->ssd_dpl, ssd->ssd_p ? "" : "NOT ");
			return (sizeof (*ssd));
		}

		case SDT_SYSCGT:
		case SDT_SYSIGT:
		case SDT_SYSTGT: {
			struct gate_segment_descriptor *sgd = desc;

			printf("target 0x%x:0x%x dpl %d %spresent",
			    sgd->sgd_selector, sgd->sgd_looffset |
			    (sgd->sgd_hioffset << 16),
			    sgd->sgd_dpl, sgd->sgd_p ? "" : "NOT ");
			if (type == SDT_SYSCGT)
				printf(" %d parms", sgd->sgd_stkcpy);
			printf("\n");
			return (sizeof (*sgd));
		}

		case SDT_MEMRO:
		case SDT_MEMROA:
		case SDT_MEMRW:
		case SDT_MEMRWA:
		case SDT_MEMROD:
		case SDT_MEMRODA:
		case SDT_MEMRWD:
		case SDT_MEMRWDA:
		case SDT_MEME:
		case SDT_MEMEA:
		case SDT_MEMER:
		case SDT_MEMERA:
		case SDT_MEMEC:
		case SDT_MEMEAC:
		case SDT_MEMERC:
		case SDT_MEMERAC: {
			struct user_segment_descriptor *usd = desc;
			uint32_t base = usd->usd_lobase |
			    (usd->usd_midbase << 16) | (usd->usd_hibase << 24);
			uint32_t lim = usd->usd_lolimit |
			    (usd->usd_hilimit << 16);

			printf("base 0x%x lim 0x%x dpl %d %spresent\n",
			    base, usd->usd_gran ? lim * 4096 : lim,
			    usd->usd_dpl, usd->usd_p ? "" : "NOT ");
			return (sizeof (*usd));
		}

		default: {
			uint16_t *u16 = desc;
			struct system_segment_descriptor *ssd = desc;

			printf("0x%x.%x.%x.%x dpl %d %spresent\n",
			    u16[0], u16[1], u16[2], u16[3],
			    ssd->ssd_dpl, ssd->ssd_p ? "" : "NOT ");
			return (sizeof (*ssd));
		}

	}
}

static void
dump_desctbr(const char *name, desctbr_t *dtr)
{
	uintptr_t entry, theend;

	printf("    %s [limit %x base %x]\n",
	    name, dtr->dtr_limit, dtr->dtr_base);

	theend = (uintptr_t)(dtr->dtr_base + dtr->dtr_limit);

	for (entry = dtr->dtr_base; entry < theend; ) {
		printf("    %6lu: ", entry - (uintptr_t)dtr->dtr_base);
		entry += dump_ssd((void *)entry);
		/*
		 * Hack to print only the hardware entries in the idt
		 */
		if (entry - (uintptr_t)dtr->dtr_base > 19 &&
		    strcmp(name, "idt") == 0)
			return;
	}
}

static void
dump_user_descriptor(desctbr_t *gdt, const char *name, uint16_t sel)
{
	uint_t index;
	static const char fmt1[] = "    %8s %16x\n            ";

	printf(fmt1, name, sel);

	if ((index = SELTOIDX(sel)) == 0)
		printf("<null selector>\n");
	else if (index > gdt->dtr_limit)
		printf("<selector out of range?>\n");
	else {
		uintptr_t entry =
			(uintptr_t)gdt->dtr_base + IDXTOSEL(index);

		(void) dump_ssd((void *)entry);
	}
}

void
amd64_dump_i386_machregs(struct i386_machregs *rp)
{
	static const char fmt1[] = "    %8s %16x\n";
	static const char fmt2[] = "    %8s %16x %8s %16x\n";
	static const char fmtb[] = "    %8s %16b\n";

	printf("struct i386_machregs @0x%p = {\n", (void *)rp);

#if defined(__GNUC__)
	printf(fmt1, "cr0", rp->r_cr0);
	printf(fmt1, "cr2", rp->r_cr2);
	printf(fmt1, "cr3", rp->r_cr3);
	printf(fmt1, "cr4", rp->r_cr4);
#else
	printf(fmtb, "cr0", rp->r_cr0, FMT_CR0);
	printf(fmt1, "cr2", rp->r_cr2);
	printf(fmtb, "cr3", rp->r_cr3, FMT_CR3);
	printf(fmtb, "cr4", rp->r_cr4, FMT_CR4);
#endif
	dump_desctbr("gdt", &rp->r_gdt);
	dump_desctbr("idt", &rp->r_idt);

	dump_user_descriptor(&rp->r_gdt, "ldt", rp->r_ldt);
	dump_user_descriptor(&rp->r_gdt, "tr",  rp->r_tr);

	printf(fmt2, "edi", rp->r_edi, "esi", rp->r_esi);
	printf(fmt2, "ebp", rp->r_ebp, "esp", rp->r_esp);
	printf(fmt2, "ebx", rp->r_ebx, "ecx", rp->r_ecx);

	printf(fmt2, "eip", rp->r_eip, "efl", rp->r_efl);
	printf(fmt1, "uesp", rp->r_uesp);

	dump_user_descriptor(&rp->r_gdt, "cs", (uint16_t)rp->r_cs);
	dump_user_descriptor(&rp->r_gdt, "ds", (uint16_t)rp->r_ds);
	dump_user_descriptor(&rp->r_gdt, "es", (uint16_t)rp->r_es);
	dump_user_descriptor(&rp->r_gdt, "fs", (uint16_t)rp->r_fs);
	dump_user_descriptor(&rp->r_gdt, "gs", (uint16_t)rp->r_gs);
	dump_user_descriptor(&rp->r_gdt, "ss", (uint16_t)rp->r_ss);

	printf(fmt2, "trapno", rp->r_trapno, "err", rp->r_err);

	printf("}\n");
}

static const char *
desc64_type_name(uint_t type)
{
	switch (type) {
		case SDT_SYSNULL:
		case SDT_SYS286TSS:
		case SDT_SYS286BSY:
		case SDT_SYS286CGT:
		case SDT_SYSTASKGT:
		case SDT_SYS286IGT:
		case SDT_SYS286TGT:
		case SDT_SYSNULL2:
		case SDT_SYSNULL3:
		case SDT_SYSNULL4:	return ("illegal");

		case SDT_SYSLDT:	return ("64-bit ldt");
		case SDT_SYSTSS:	return ("64-bit tss");
		case SDT_SYSTSSBSY:	return ("64-bit tss busy");
		case SDT_SYSCGT:	return ("64-bit call gate");
		case SDT_SYSIGT:	return ("64-bit intr gate");
		case SDT_SYSTGT:	return ("64-bit trap gate");

		case SDT_MEMRO:		return ("r-- --");
		case SDT_MEMROA:	return ("r-- -a");
		case SDT_MEMRW:		return ("rw- --");
		case SDT_MEMRWA:	return ("rw- -a");
		case SDT_MEMROD:	return ("r-- d-");
		case SDT_MEMRODA:	return ("r-- da");
		case SDT_MEMRWD:	return ("rw- d-");
		case SDT_MEMRWDA:	return ("rw- da");
		case SDT_MEME:		return ("--x --");
		case SDT_MEMEA:		return ("--x -a");
		case SDT_MEMER:		return ("r-x --");
		case SDT_MEMERA:	return ("r-x -a");
		case SDT_MEMEC:		return ("--x c-");
		case SDT_MEMEAC:	return ("--x ca");
		case SDT_MEMERC:	return ("r-x c-");
		case SDT_MEMERAC:	return ("r-x ca");
		default:		return ("(unknown)");
	}
}

static size_t
dump_ssd64(void *desc)
{
	uint_t type = ((struct user_segment_descriptor64 *)desc)->usd_type;

	printf("type %d (%s) ", type, desc64_type_name(type));

	switch (type) {
		case SDT_SYSLDT:
		case SDT_SYSTSS:
		case SDT_SYSTSSBSY: {
			struct system_segment_descriptor64 *ssd = desc;
			uint64_t base = (uint64_t)ssd->ssd_lobase |
			    ((uint64_t)ssd->ssd_midbase << 16) |
			    ((uint64_t)ssd->ssd_hibase << 24) |
			    ((uint64_t)ssd->ssd_hi64base << 32);
			uint32_t lim = ssd->ssd_lolimit |
			    (ssd->ssd_hilimit << 16);

			printf("base 0x%" PRIx64
			    " lim 0x%x dpl %d %spresent\n",
			    base, ssd->ssd_gran ? lim * 4096 : lim,
			    ssd->ssd_dpl, ssd->ssd_p ? "" : "NOT ");

			if (ssd->ssd_zero1 != 0 || ssd->ssd_zero2)
				amd64_warning("zero1 field 0x%x zero2 field "
				    "0x%x", ssd->ssd_zero1, ssd->ssd_zero2);
			return (sizeof (*ssd));
		}

		case SDT_SYSCGT:
		case SDT_SYSIGT:
		case SDT_SYSTGT: {
			struct gate_segment_descriptor64 *sgd = desc;

			printf("target 0x%x:0x%" PRIx64 " dpl %d "
			    "%spresent\n", sgd->sgd_selector,
			    (uint64_t)sgd->sgd_looffset |
			    ((uint64_t)sgd->sgd_hioffset) << 16 |
			    ((uint64_t)sgd->sgd_hi64offset),
			    sgd->sgd_dpl, sgd->sgd_p ? "" : "NOT ");

			if (type == SDT_SYSCGT && sgd->sgd_zero != 0)
				amd64_warning("zero field 0x%x\n",
				    sgd->sgd_zero);
			return (sizeof (*sgd));
		}

		case SDT_MEMRO:
		case SDT_MEMROA:
		case SDT_MEMRW:
		case SDT_MEMRWA:
		case SDT_MEMROD:
		case SDT_MEMRODA:
		case SDT_MEMRWD:
		case SDT_MEMRWDA: {
			struct user_segment_descriptor64 *usd = desc;

			printf("%spresent\n", usd->usd_p ? "" : "NOT ");
			return (sizeof (*usd));
		}

		case SDT_MEME:
		case SDT_MEMEA:
		case SDT_MEMER:
		case SDT_MEMERA:
		case SDT_MEMEC:
		case SDT_MEMEAC:
		case SDT_MEMERC:
		case SDT_MEMERAC: {
			struct user_segment_descriptor64 *usd = desc;

			printf("%sconforming, dpl %d, %spresent, "
			    "long %d, defopsz %d\n",
			    BITX(usd->usd_type, 2, 2) ? "" : "non-",
			    usd->usd_dpl,
			    usd->usd_p ? "" : "NOT ",
			    usd->usd_long, usd->usd_def32);
			if (usd->usd_long && usd->usd_def32)
				amd64_warning("both the L and D bit are "
				    "set!\n");
			return (sizeof (*usd));
		}

		default:
			printf("\n");
			return (sizeof (struct user_segment_descriptor64));
	}
}

static void
dump_desctbr64(const char *name, desctbr64_t *dtr)
{
	uintptr_t entry, theend;

	printf("    %s [limit 0x%x base 0x%" PRIx64 "]\n",
	    name, dtr->dtr_limit, dtr->dtr_base);

	theend = (uintptr_t)(dtr->dtr_base + dtr->dtr_limit);

	for (entry = (uintptr_t)dtr->dtr_base; entry < theend; ) {
		printf("    %6lu: ", entry - (uintptr_t)dtr->dtr_base);
		entry += dump_ssd64((void *)entry);

		/*
		 * Hack to print only the hardware entries in the idt
		 */
		if (entry - (uintptr_t)dtr->dtr_base > 19 &&
		    strcmp(name, "idt") == 0)
			return;
	}
}

static void
dump_user_descriptor64(desctbr64_t *gdt, const char *name, uint16_t sel)
{
	uint_t index;
	static const char fmt1[] = "    %8s %16x\n            ";

	printf(fmt1, name, sel);

	if ((index = SELTOIDX(sel)) == 0)
		printf("<null selector>\n");
	else if (index > gdt->dtr_limit)
		printf("<selector out of range?>\n");
	else {
		uintptr_t entry =
		    (uintptr_t)gdt->dtr_base + IDXTOSEL(index);

		(void) dump_ssd((void *)entry);
	}
}

void
amd64_dump_amd64_machregs(struct amd64_machregs *rp)
{
	static const char fmt1[] = "    %8s %16" PRIx64 "\n";
	static const char fmt2[] = "    %8s %16" PRIx64 " %8s %16" PRIx64 "\n";
	static const char fmtb[] = "    %8s %16b\n";

	printf("struct amd64_machregs @0x%p = {\n", (void *)rp);

	printf(fmt1, "kgsbase", rp->r_kgsbase);
	printf(fmt2, "gsbase", rp->r_gsbase, "fsbase", rp->r_fsbase);

	printf(fmt2, "cr0", rp->r_cr0, "cr2", rp->r_cr2);
	printf(fmt2, "cr3", rp->r_cr3, "cr4", rp->r_cr4);
	printf(fmt1, "cr8", rp->r_cr8);

#if !defined(__GNUC__)
	printf(fmtb, "cr0", (uint_t)rp->r_cr0, FMT_CR0);
	printf(fmtb, "cr3", (uint_t)rp->r_cr3, FMT_CR3);
	printf(fmtb, "cr4", (uint_t)rp->r_cr4, FMT_CR4);
#endif

	dump_desctbr64("gdt", &rp->r_gdt);
	dump_desctbr64("idt", &rp->r_idt);

	dump_user_descriptor64(&rp->r_gdt, "ldt", (uint16_t)rp->r_ldt);
	dump_user_descriptor64(&rp->r_gdt, "tr", (uint16_t)rp->r_tr);

	printf(fmt2, "rdi", rp->r_rdi, "rsi", rp->r_rsi);
	printf(fmt2, "rdx", rp->r_rdx, "rcx", rp->r_rcx);
	printf(fmt2, "r8", rp->r_r8, "r9", rp->r_r9);
	printf(fmt2, "rax", rp->r_rax, "rbx", rp->r_rbx);
	printf(fmt2, "rbp", rp->r_rbp, "r10", rp->r_r10);
	printf(fmt2, "r11", rp->r_r11, "r12", rp->r_r12);
	printf(fmt2, "r13", rp->r_r13, "r14", rp->r_r14);
	printf(fmt2, "r15", rp->r_r15, "rsp", rp->r_rsp);
	printf(fmt2, "rip", rp->r_rip, "rfl", rp->r_rfl);

	dump_user_descriptor64(&rp->r_gdt, "cs", (uint16_t)rp->r_cs);
	dump_user_descriptor64(&rp->r_gdt, "ds", (uint16_t)rp->r_ds);
	dump_user_descriptor64(&rp->r_gdt, "es", (uint16_t)rp->r_es);
	dump_user_descriptor64(&rp->r_gdt, "fs", (uint16_t)rp->r_fs);
	dump_user_descriptor64(&rp->r_gdt, "gs", (uint16_t)rp->r_gs);
	dump_user_descriptor64(&rp->r_gdt, "ss", (uint16_t)rp->r_ss);

	printf(fmt2, "trapno", rp->r_trapno, "err", rp->r_err);

	printf("}\n");
}
