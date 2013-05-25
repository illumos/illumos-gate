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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

#include <kmdb/kmdb_kvm.h>
#include <kmdb/kvm.h>
#include <kmdb/kmdb_kdi.h>
#include <kmdb/kmdb_promif.h>
#include <kmdb/kmdb_module.h>
#include <kmdb/kmdb_asmutil.h>
#include <mdb/mdb_types.h>
#include <mdb/mdb_conf.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_target_impl.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_string.h>
#include <mdb/mdb_ctf.h>
#include <mdb/mdb_kreg_impl.h>
#include <mdb/mdb_ks.h>
#include <mdb/mdb.h>

#include <strings.h>
#include <dlfcn.h>
#include <sys/isa_defs.h>
#include <sys/kobj.h>
#include <sys/kobj_impl.h>
#include <sys/bitmap.h>
#include <vm/as.h>

static const char KMT_RTLD_NAME[] = "krtld";
static const char KMT_MODULE[] = "mdb_ks";
static const char KMT_CTFPARENT[] = "genunix";

static mdb_list_t kmt_defbp_list;	/* List of current deferred bp's */
static int kmt_defbp_lock;		/* For list, running kernel holds */
static uint_t kmt_defbp_modchg_isload;	/* Whether mod change is load/unload */
static struct modctl *kmt_defbp_modchg_modctl; /* modctl for defbp checking */
static uint_t kmt_defbp_num;		/* Number of referenced def'd bp's */
static int kmt_defbp_bpspec;		/* vespec for def'd bp activation bp */

static const mdb_se_ops_t kmt_brkpt_ops;
static const mdb_se_ops_t kmt_wapt_ops;

static void kmt_sync(mdb_tgt_t *);

typedef struct kmt_symarg {
	mdb_tgt_sym_f *sym_cb;		/* Caller's callback function */
	void *sym_data;			/* Callback function argument */
	uint_t sym_type;		/* Symbol type/binding filter */
	mdb_syminfo_t sym_info;		/* Symbol id and table id */
	const char *sym_obj;		/* Containing object */
} kmt_symarg_t;

typedef struct kmt_maparg {
	mdb_tgt_t *map_target;		/* Target used for mapping iter */
	mdb_tgt_map_f *map_cb;		/* Caller's callback function */
	void *map_data;			/* Callback function argument */
} kmt_maparg_t;

/*ARGSUSED*/
int
kmt_setflags(mdb_tgt_t *t, int flags)
{
	/*
	 * We only handle one flag (ALLOWIO), and we can't fail to set or clear
	 * it, so we just blindly replace the t_flags version with the one
	 * passed.
	 */
	t->t_flags = (t->t_flags & ~MDB_TGT_F_ALLOWIO) |
	    (flags & MDB_TGT_F_ALLOWIO);

	return (0);
}

/*ARGSUSED*/
const char *
kmt_name(mdb_tgt_t *t)
{
	return ("kmdb_kvm");
}

/*ARGSUSED*/
static const char *
kmt_platform(mdb_tgt_t *t)
{
	static char platform[SYS_NMLN];

	if (kmdb_dpi_get_state(NULL) == DPI_STATE_INIT)
		return (mdb_conf_platform());

	if (mdb_tgt_readsym(mdb.m_target, MDB_TGT_AS_VIRT, platform,
	    sizeof (platform), "unix", "platform") != sizeof (platform)) {
		warn("'platform' symbol is missing from kernel\n");
		return ("unknown");
	}

	return (platform);
}

static int
kmt_uname(mdb_tgt_t *t, struct utsname *utsp)
{
	return (mdb_tgt_readsym(t, MDB_TGT_AS_VIRT, utsp,
	    sizeof (struct utsname), MDB_TGT_OBJ_EXEC, "utsname"));
}

/*ARGSUSED*/
static int
kmt_dmodel(mdb_tgt_t *t)
{
	return (MDB_TGT_MODEL_NATIVE);
}

/*ARGSUSED*/
ssize_t
kmt_rw(mdb_tgt_t *t, void *buf, size_t nbytes, uint64_t addr,
    ssize_t (*rw)(void *, size_t, uint64_t))
{
	/*
	 * chunksz needs to be volatile because of the use of setjmp() in this
	 * function.
	 */
	volatile size_t chunksz;
	size_t n, ndone;
	jmp_buf *oldpcb = NULL;
	jmp_buf pcb;
	ssize_t res;

	kmdb_prom_check_interrupt();

	if (nbytes == 0)
		return (0);

	/*
	 * Try to process the entire buffer, as requested.  If we catch a fault,
	 * try smaller chunks.  This allows us to handle regions that cross
	 * mapping boundaries.
	 */
	chunksz = nbytes;
	ndone = 0;
	if (setjmp(pcb) != 0) {
		if (chunksz == 1) {
			/* We failed with the smallest chunk - give up */
			kmdb_dpi_restore_fault_hdlr(oldpcb);
			return (ndone > 0 ? ndone : -1); /* errno set for us */
		} else if (chunksz > 4)
			chunksz = 4;
		else
			chunksz = 1;
	}

	oldpcb = kmdb_dpi_set_fault_hdlr(&pcb);
	while (nbytes > 0) {
		n = MIN(chunksz, nbytes);

		if ((res = rw(buf, n, addr)) != n)
			return (res < 0 ? res : ndone + res);

		addr += n;
		nbytes -= n;
		ndone += n;
		buf = ((caddr_t)buf + n);
	}

	kmdb_dpi_restore_fault_hdlr(oldpcb);

	return (ndone);
}

static void
kmt_bcopy(const void *s1, void *s2, size_t n)
{
	/*
	 * We need to guarantee atomic accesses for certain sizes.  bcopy won't
	 * make that guarantee, so we need to do it ourselves.
	 */
#ifdef	_LP64
	if (n == 8 && ((uintptr_t)s1 & 7) == 0 && ((uintptr_t)s2 & 7) == 0)
		*(uint64_t *)s2 = *(uint64_t *)s1;
	else
#endif
	if (n == 4 && ((uintptr_t)s1 & 3) == 0 && ((uintptr_t)s2 & 3) == 0)
		*(uint32_t *)s2 = *(uint32_t *)s1;
	else if (n == 2 && ((uintptr_t)s1 & 1) == 0 && ((uintptr_t)s2 & 1) == 0)
		*(uint16_t *)s2 = *(uint16_t *)s1;
	else if (n == 1)
		*(uint8_t *)s2 = *(uint8_t *)s1;
	else
		bcopy(s1, s2, n);
}

static ssize_t
kmt_reader(void *buf, size_t nbytes, uint64_t addr)
{
	kmt_bcopy((void *)(uintptr_t)addr, buf, nbytes);
	return (nbytes);
}

ssize_t
kmt_writer(void *buf, size_t nbytes, uint64_t addr)
{
	kmt_bcopy(buf, (void *)(uintptr_t)addr, nbytes);
	return (nbytes);
}

/*ARGSUSED*/
static ssize_t
kmt_read(mdb_tgt_t *t, void *buf, size_t nbytes, uintptr_t addr)
{
	/*
	 * We don't want to allow reads of I/O-mapped memory.  Multi-page reads
	 * that cross into I/O-mapped memory should be restricted to the initial
	 * non-I/O region.  Reads that begin in I/O-mapped memory are failed
	 * outright.
	 */
	if (!(t->t_flags & MDB_TGT_F_ALLOWIO) &&
	    (nbytes = kmdb_kdi_range_is_nontoxic(addr, nbytes, 0)) == 0)
		return (set_errno(EMDB_NOMAP));

	return (kmt_rw(t, buf, nbytes, addr, kmt_reader));
}

/*ARGSUSED*/
static ssize_t
kmt_pread(mdb_tgt_t *t, void *buf, size_t nbytes, physaddr_t addr)
{
	return (kmt_rw(t, buf, nbytes, addr, kmdb_kdi_pread));
}

/*ARGSUSED*/
ssize_t
kmt_pwrite(mdb_tgt_t *t, const void *buf, size_t nbytes, physaddr_t addr)
{
	return (kmt_rw(t, (void *)buf, nbytes, addr, kmdb_kdi_pwrite));
}

static uintptr_t
kmt_read_kas(mdb_tgt_t *t)
{
	GElf_Sym sym;

	if (mdb_tgt_lookup_by_name(t, "unix", "kas", &sym, NULL) < 0) {
		warn("'kas' symbol is missing from kernel\n");
		(void) set_errno(EMDB_NOSYM);
		return (0);
	}

	return ((uintptr_t)sym.st_value);
}

static int
kmt_vtop(mdb_tgt_t *t, mdb_tgt_as_t as, uintptr_t va, physaddr_t *pap)
{
	mdb_module_t *mod;
	struct as *asp;
	mdb_var_t *v;

	switch ((uintptr_t)as) {
	case (uintptr_t)MDB_TGT_AS_PHYS:
	case (uintptr_t)MDB_TGT_AS_FILE:
	case (uintptr_t)MDB_TGT_AS_IO:
		return (set_errno(EINVAL));
	case (uintptr_t)MDB_TGT_AS_VIRT:
		if ((asp = (struct as *)kmt_read_kas(t)) == NULL)
			return (-1); /* errno is set for us */
		break;
	default:
		asp = (struct as *)as;

		/* We don't support non-kas vtop */
		if (asp != (struct as *)kmt_read_kas(t))
			return (set_errno(EMDB_TGTNOTSUP));
	}

	if (kmdb_prom_vtop(va, pap) == 0)
		return (0);

	if ((v = mdb_nv_lookup(&mdb.m_modules, "unix")) != NULL &&
	    (mod = mdb_nv_get_cookie(v)) != NULL) {
		int (*fptr)(uintptr_t, struct as *, physaddr_t *);

		fptr = (int (*)(uintptr_t, struct as *, physaddr_t *))
		    dlsym(mod->mod_hdl, "platform_vtop");

		if ((fptr != NULL) && ((*fptr)(va, asp, pap) == 0))
			return (0);
	}

	return (set_errno(EMDB_NOMAP));
}

/*ARGSUSED*/
static int
kmt_cpuregs(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	const mdb_tgt_gregset_t *gregs;
	intptr_t cpuid = DPI_MASTER_CPUID;
	int i;

	if (flags & DCMD_ADDRSPEC) {
		if (argc != 0)
			return (DCMD_USAGE);
		if ((cpuid = mdb_cpu2cpuid(addr)) < 0) {
			(void) set_errno(EMDB_NOMAP);
			mdb_warn("failed to find cpuid for cpu at %p", addr);
			return (DCMD_ERR);
		}
	}

	i = mdb_getopts(argc, argv,
	    'c', MDB_OPT_UINTPTR, &cpuid,
	    NULL);

	argc -= i;
	argv += i;

	if (argc != 0)
		return (DCMD_USAGE);

	if ((gregs = kmdb_dpi_get_gregs(cpuid)) == NULL) {
		warn("failed to retrieve registers for cpu %d", (int)cpuid);
		return (DCMD_ERR);
	}

	kmt_printregs(gregs);

	return (DCMD_OK);
}

static int
kmt_regs(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (flags & DCMD_ADDRSPEC)
		return (DCMD_USAGE);

	return (kmt_cpuregs(addr, flags, argc, argv));
}

static int
kmt_cpustack_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	intptr_t cpuid = DPI_MASTER_CPUID;
	uint_t verbose = 0;
	int i;

	if (flags & DCMD_ADDRSPEC) {
		if ((cpuid = mdb_cpu2cpuid(addr)) < 0) {
			(void) set_errno(EMDB_NOMAP);
			mdb_warn("failed to find cpuid for cpu at %p", addr);
			return (DCMD_ERR);
		}
		flags &= ~DCMD_ADDRSPEC;
	}

	i = mdb_getopts(argc, argv,
	    'c', MDB_OPT_UINTPTR, &cpuid,
	    'v', MDB_OPT_SETBITS, 1, &verbose,
	    NULL);

	argc -= i;
	argv += i;

	return (kmt_cpustack(addr, flags, argc, argv, cpuid, verbose));
}

/*
 * Lasciate ogne speranza, voi ch'intrate.
 */
static int
kmt_call(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uintptr_t *call_argv, rval;
	int parse_strings = 1;
	GElf_Sym sym;
	jmp_buf *oldpcb = NULL;
	jmp_buf pcb;
	int i;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_tgt_lookup_by_addr(mdb.m_target, addr, MDB_TGT_SYM_EXACT,
	    NULL, 0, &sym, NULL) == 0 && GELF_ST_TYPE(sym.st_info) !=
	    STT_FUNC) {
		warn("%a is not a function\n", addr);
		return (DCMD_ERR);
	}

	if (argc > 1 && argv[0].a_type == MDB_TYPE_STRING &&
	    strcmp(argv[0].a_un.a_str, "-s") == 0) {
		parse_strings = 0;
		argc--;
		argv++;
	}

	call_argv = mdb_alloc(sizeof (uintptr_t) * argc, UM_SLEEP);

	for (i = 0; i < argc; i++) {
		switch (argv[i].a_type) {
		case MDB_TYPE_STRING:
			/*
			 * mdb_strtoull doesn't return on error, so we have to
			 * pre-check strings suspected to contain numbers.
			 */
			if (parse_strings && strisbasenum(argv[i].a_un.a_str)) {
				call_argv[i] = (uintptr_t)mdb_strtoull(
				    argv[i].a_un.a_str);
			} else
				call_argv[i] = (uintptr_t)argv[i].a_un.a_str;

			break;

		case MDB_TYPE_IMMEDIATE:
			call_argv[i] = argv[i].a_un.a_val;
			break;

		default:
			mdb_free(call_argv,
			    sizeof (uintptr_t) * argc);
			return (DCMD_USAGE);
		}
	}

	if (setjmp(pcb) != 0) {
		warn("call failed: caught a trap\n");

		kmdb_dpi_restore_fault_hdlr(oldpcb);
		mdb_free(call_argv, sizeof (uintptr_t) * argc);
		return (DCMD_ERR);
	}

	oldpcb = kmdb_dpi_set_fault_hdlr(&pcb);
	rval = kmdb_dpi_call(addr, argc, call_argv);
	kmdb_dpi_restore_fault_hdlr(oldpcb);

	if (flags & DCMD_PIPE_OUT) {
		mdb_printf("%p\n", rval);
	} else {
		/* pretty-print the results */
		mdb_printf("%p = %a(", rval, addr);
		for (i = 0; i < argc; i++) {
			if (i > 0)
				mdb_printf(", ");
			if (argv[i].a_type == MDB_TYPE_STRING) {
				/* I'm ashamed but amused */
				char *quote = &("\""[parse_strings &&
				    strisbasenum(argv[i].a_un.a_str)]);

				mdb_printf("%s%s%s", quote, argv[i].a_un.a_str,
				    quote);
			} else
				mdb_printf("%p", argv[i].a_un.a_val);
		}
		mdb_printf(");\n");
	}

	mdb_free(call_argv, sizeof (uintptr_t) * argc);

	return (DCMD_OK);
}

/*ARGSUSED*/
int
kmt_dump_crumbs(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	intptr_t cpu = -1;

	if (flags & DCMD_ADDRSPEC) {
		if (argc != 0)
			return (DCMD_USAGE);
	} else {
		addr = 0;

		if (mdb_getopts(argc, argv,
		    'c', MDB_OPT_UINTPTR, &cpu,
		    NULL) != argc)
			return (DCMD_USAGE);
	}

	kmdb_dpi_dump_crumbs(addr, cpu);

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
kmt_noducttape(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int a = 0;

	return (a/a);
}

static int
kmt_dmod_status(char *msg, int state)
{
	kmdb_modctl_t *kmc;
	mdb_var_t *v;
	int first = 1, n = 0;

	mdb_nv_rewind(&mdb.m_dmodctl);
	while ((v = mdb_nv_advance(&mdb.m_dmodctl)) != NULL) {
		kmc = MDB_NV_COOKIE(v);

		if (kmc->kmc_state != state)
			continue;

		n++;

		if (msg != NULL) {
			if (first) {
				mdb_printf(msg, NULL);
				first = 0;
			}

			mdb_printf(" %s", kmc->kmc_modname);
		}
	}

	if (!first && msg != NULL)
		mdb_printf("\n");

	return (n);
}

/*ARGSUSED*/
static int
kmt_status_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	kmt_data_t *kmt = mdb.m_target->t_data;
	struct utsname uts;
	char uuid[37];
	kreg_t tt;

	if (mdb_tgt_readsym(mdb.m_target, MDB_TGT_AS_VIRT, &uts, sizeof (uts),
	    "unix", "utsname") != sizeof (uts)) {
		warn("failed to read 'utsname' struct from kernel\n");
		bzero(&uts, sizeof (uts));
		(void) strcpy(uts.nodename, "unknown machine");
	}

	mdb_printf("debugging live kernel (%d-bit) on %s\n",
	    (int)(sizeof (void *) * NBBY),
	    (*uts.nodename == '\0' ? "(not set)" : uts.nodename));
	mdb_printf("operating system: %s %s (%s)\n",
	    uts.release, uts.version, uts.machine);

	if (mdb_tgt_readsym(mdb.m_target, MDB_TGT_AS_VIRT, uuid, sizeof (uuid),
	    "genunix", "dump_osimage_uuid") != sizeof (uuid)) {
		warn("failed to read 'dump_osimage_uuid' string from kernel\n");
		(void) strcpy(uuid, "(error)");
	} else if (*uuid == '\0') {
		(void) strcpy(uuid, "(not set)");
	} else if (uuid[36] != '\0') {
		(void) strcpy(uuid, "(invalid)");
	}
	mdb_printf("image uuid: %s\n", uuid);

	if (kmt->kmt_cpu != NULL) {
		mdb_printf("CPU-specific support: %s\n",
		    kmt_cpu_name(kmt->kmt_cpu));
	}

	mdb_printf("DTrace state: %s\n", (kmdb_kdi_dtrace_get_state() ==
	    KDI_DTSTATE_DTRACE_ACTIVE ? "active (debugger breakpoints cannot "
	    "be armed)" : "inactive"));

	(void) kmdb_dpi_get_register("tt", &tt);
	mdb_printf("stopped on: %s\n", kmt_trapname(tt));

	(void) kmt_dmod_status("pending dmod loads:", KMDB_MC_STATE_LOADING);
	(void) kmt_dmod_status("pending dmod unloads:",
	    KMDB_MC_STATE_UNLOADING);

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
kmt_switch(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (!(flags & DCMD_ADDRSPEC) || argc != 0)
		return (DCMD_USAGE);

	if (kmdb_dpi_switch_master((int)addr) < 0) {
		warn("failed to switch to CPU %d", (int)addr);
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

static const mdb_dcmd_t kmt_dcmds[] = {
	{ "$c", "?[cnt]", "print stack backtrace", kmt_stack },
	{ "$C", "?[cnt]", "print stack backtrace", kmt_stackv },
	{ "$r", NULL, "print general-purpose registers", kmt_regs },
	{ "$?", NULL, "print status and registers", kmt_regs },
	{ ":x", ":", "change the active CPU", kmt_switch },
	{ "call", ":[arg ...]", "call a kernel function", kmt_call },
	{ "cpustack", "?[-v] [-c cpuid] [cnt]", "print stack backtrace for a "
	    "specific CPU", kmt_cpustack_dcmd },
	{ "cpuregs", "?[-c cpuid]", "print general-purpose registers for a "
	    "specific CPU", kmt_cpuregs },
	{ "crumbs", NULL, NULL, kmt_dump_crumbs },
#if defined(__i386) || defined(__amd64)
	{ "in", ":[-L len]", "read from I/O port", kmt_in_dcmd },
	{ "out", ":[-L len] val", "write to I/O port", kmt_out_dcmd },
	{ "rdmsr", ":", "read an MSR", kmt_rdmsr },
	{ "wrmsr", ": val", "write an MSR", kmt_wrmsr },
	{ "rdpcicfg", ": bus dev func", "read a register in PCI config space",
	kmt_rdpcicfg },
	{ "wrpcicfg", ": bus dev func val", "write a register in PCI config "
	"space", kmt_wrpcicfg },
#endif
	{ "noducttape", NULL, NULL, kmt_noducttape },
	{ "regs", NULL, "print general-purpose registers", kmt_regs },
	{ "stack", "?[cnt]", "print stack backtrace", kmt_stack },
	{ "stackregs", "?", "print stack backtrace and registers", kmt_stackr },
	{ "status", NULL, "print summary of current target", kmt_status_dcmd },
	{ "switch", ":", "change the active CPU", kmt_switch },
	{ NULL }
};

static uintmax_t
kmt_reg_disc_get(const mdb_var_t *v)
{
	mdb_tgt_reg_t r = 0;

	(void) mdb_tgt_getareg(MDB_NV_COOKIE(v), 0, mdb_nv_get_name(v), &r);

	return (r);
}

static void
kmt_reg_disc_set(mdb_var_t *v, uintmax_t r)
{
	if (mdb_tgt_putareg(MDB_NV_COOKIE(v), 0, mdb_nv_get_name(v), r) == -1)
		warn("failed to modify %%%s register", mdb_nv_get_name(v));
}

static const mdb_nv_disc_t kmt_reg_disc = {
	kmt_reg_disc_set,
	kmt_reg_disc_get
};

/*ARGSUSED*/
static int
kmt_getareg(mdb_tgt_t *t, mdb_tgt_tid_t tid, const char *rname,
    mdb_tgt_reg_t *rp)
{
	kreg_t val;

	if (kmdb_dpi_get_register(rname, &val) < 0)
		return (set_errno(EMDB_BADREG));

	*rp = val;
	return (0);
}

/*ARGSUSED*/
static int
kmt_putareg(mdb_tgt_t *t, mdb_tgt_tid_t tid, const char *rname, mdb_tgt_reg_t r)
{
	if (kmdb_dpi_set_register(rname, r) < 0)
		return (set_errno(EMDB_BADREG));

	return (0);
}

static void
kmt_mod_destroy(kmt_module_t *km)
{
	if (km->km_name != NULL)
		strfree(km->km_name);
	if (km->km_symtab != NULL)
		mdb_gelf_symtab_destroy(km->km_symtab);
	if (km->km_ctfp != NULL)
		mdb_ctf_close(km->km_ctfp);
}

static kmt_module_t *
kmt_mod_create(mdb_tgt_t *t, struct modctl *ctlp, char *name)
{
	kmt_module_t *km = mdb_zalloc(sizeof (kmt_module_t), UM_SLEEP);
	struct module *mod;

	km->km_name = mdb_alloc(strlen(name) + 1, UM_SLEEP);
	(void) strcpy(km->km_name, name);

	bcopy(ctlp, &km->km_modctl, sizeof (struct modctl));

	if (mdb_tgt_vread(t, &km->km_module, sizeof (struct module),
	    (uintptr_t)km->km_modctl.mod_mp) != sizeof (struct module))
		goto create_module_cleanup;
	mod = &km->km_module;

	if (mod->symhdr != NULL && mod->strhdr != NULL && mod->symtbl != NULL &&
	    mod->strings != NULL) {
		mdb_gelf_ehdr_to_gehdr(&mod->hdr, &km->km_ehdr);

		km->km_symtab = mdb_gelf_symtab_create_raw(&km->km_ehdr,
		    mod->symhdr, mod->symtbl, mod->strhdr, mod->strings,
		    MDB_TGT_SYMTAB);

		km->km_symtab_va = mod->symtbl;
		km->km_strtab_va = mod->strings;

		if (mdb_tgt_vread(t, &km->km_symtab_hdr, sizeof (Shdr),
		    (uintptr_t)mod->symhdr) != sizeof (Shdr) ||
		    mdb_tgt_vread(t, &km->km_strtab_hdr, sizeof (Shdr),
		    (uintptr_t)mod->strhdr) != sizeof (Shdr))
			goto create_module_cleanup;
	}

	/*
	 * We don't want everyone rooting around in the module structure, so we
	 * make copies of the interesting members.
	 */
	km->km_text_va = (uintptr_t)mod->text;
	km->km_text_size = mod->text_size;
	km->km_data_va = (uintptr_t)mod->data;
	km->km_data_size = mod->data_size;
	km->km_bss_va = (uintptr_t)mod->bss;
	km->km_bss_size = mod->bss_size;
	km->km_ctf_va = mod->ctfdata;
	km->km_ctf_size = mod->ctfsize;

	if (mod->flags & KOBJ_PRIM)
		km->km_flags |= KM_F_PRIMARY;

	return (km);

create_module_cleanup:
	warn("failed to read module %s\n", name);
	kmt_mod_destroy(km);
	return (NULL);
}

static void
kmt_mod_remove(kmt_data_t *kmt, kmt_module_t *km)
{
	mdb_var_t *v = mdb_nv_lookup(&kmt->kmt_modules, km->km_name);

	ASSERT(v != NULL);

	mdb_dprintf(MDB_DBG_KMOD, "removing module %s\n", km->km_name);

	mdb_list_delete(&kmt->kmt_modlist, km);
	mdb_nv_remove(&kmt->kmt_modules, v);
	kmt_mod_destroy(km);
}

static int
kmt_modlist_update_cb(struct modctl *modp, void *arg)
{
	mdb_tgt_t *t = arg;
	kmt_data_t *kmt = t->t_data;
	kmt_module_t *km;
	mdb_var_t *v;
	char name[MAXNAMELEN];

	if (mdb_tgt_readstr(t, MDB_TGT_AS_VIRT, name, MAXNAMELEN,
	    (uintptr_t)modp->mod_modname) <= 0) {
		warn("failed to read module name at %p",
		    (void *)modp->mod_modname);
	}

	/* We only care about modules that are actually loaded */
	if (!kmdb_kdi_mod_isloaded(modp))
		return (0);

	/*
	 * Skip the modules we already know about and that haven't
	 * changed since last time we were here.
	 */
	if ((v = mdb_nv_lookup(&kmt->kmt_modules, name)) != NULL) {
		km = MDB_NV_COOKIE(v);

		if (kmdb_kdi_mod_haschanged(&km->km_modctl, &km->km_module,
		    modp, modp->mod_mp)) {
			/*
			 * The module has changed since last we saw it.  For
			 * safety, remove our old version, and treat it as a
			 * new module.
			 */
			mdb_dprintf(MDB_DBG_KMOD, "stutter module %s\n", name);
			kmt_mod_remove(kmt, km);
		} else {
			km->km_seen = 1;
			return (0);
		}
	}

	mdb_dprintf(MDB_DBG_KMOD, "found new module %s\n", name);

	if ((km = kmt_mod_create(t, modp, name)) != NULL) {
		mdb_list_append(&kmt->kmt_modlist, km);
		(void) mdb_nv_insert(&kmt->kmt_modules, name, NULL,
		    (uintptr_t)km, 0);
		km->km_seen = 1;
	}

	return (0);
}

static void
kmt_modlist_update(mdb_tgt_t *t)
{
	kmt_data_t *kmt = t->t_data;
	kmt_module_t *km, *kmn;

	if (kmdb_kdi_mod_iter(kmt_modlist_update_cb, t) < 0) {
		warn("failed to complete update of kernel module list\n");
		return;
	}

	km = mdb_list_next(&kmt->kmt_modlist);
	while (km != NULL) {
		kmn = mdb_list_next(km);

		if (km->km_seen == 1) {
			/* Reset the mark for next time */
			km->km_seen = 0;
		} else {
			/*
			 * We didn't see it on the kernel's module list, so
			 * remove it from our view of the world.
			 */
			kmt_mod_remove(kmt, km);
		}

		km = kmn;
	}
}

static void
kmt_periodic(mdb_tgt_t *t)
{
	(void) mdb_tgt_status(t, &t->t_status);
}

int
kmt_lookup_by_addr(mdb_tgt_t *t, uintptr_t addr, uint_t flags,
    char *buf, size_t nbytes, GElf_Sym *symp, mdb_syminfo_t *sip)
{
	kmt_data_t *kmt = t->t_data;
	kmt_module_t *km = mdb_list_next(&kmt->kmt_modlist);
	kmt_module_t *sym_km = NULL;
	kmt_module_t prmod;
	GElf_Sym sym;
	uint_t symid;
	const char *name;

	/*
	 * We look through the private symbols (if any), then through the module
	 * symbols.  We can simplify the loop if we pretend the private symbols
	 * come from a module.
	 */
	if (mdb.m_prsym != NULL) {
		bzero(&prmod, sizeof (kmt_module_t));
		prmod.km_name = "<<<prmod>>>";
		prmod.km_symtab = mdb.m_prsym;
		prmod.km_list.ml_next = (mdb_list_t *)km;
		km = &prmod;
	}

	/* Symbol resolution isn't available during initialization */
	if (kmdb_dpi_get_state(NULL) == DPI_STATE_INIT)
		return (set_errno(EMDB_NOSYM));

	for (; km != NULL; km = mdb_list_next(km)) {
		if (km != &prmod && !kmt->kmt_symavail)
			continue;

		if (km->km_symtab == NULL)
			continue;

		if (mdb_gelf_symtab_lookup_by_addr(km->km_symtab, addr, flags,
		    buf, nbytes, symp, &sip->sym_id) != 0 ||
		    symp->st_value == 0)
			continue;

		if (flags & MDB_TGT_SYM_EXACT) {
			sym_km = km;
			goto found;
		}

		/*
		 * If this is the first match we've found, or if this symbol is
		 * closer to the specified address than the last one we found,
		 * use it.
		 */
		if (sym_km == NULL || mdb_gelf_sym_closer(symp, &sym, addr)) {
			sym_km = km;
			sym = *symp;
			symid = sip->sym_id;
		}
	}

	/*
	 * kmdb dmods are normal kernel modules, loaded by krtld as such.  To
	 * avoid polluting modinfo, and to keep from confusing the module
	 * subsystem (many dmods have the same names as real kernel modules),
	 * kmdb keeps their modctls separate, and doesn't allow their loading
	 * to be broadcast via the krtld module load/unload mechanism.  As a
	 * result, kmdb_kvm doesn't find out about them, and can't turn their
	 * addresses into symbols.  This can be most inconvenient during
	 * debugger faults, as the dmod frames will show up without names.
	 * We weren't able to turn the requested address into a symbol, so we'll
	 * take a spin through the dmods, trying to match our address against
	 * their symbols.
	 */
	if (sym_km == NULL) {
		return (kmdb_module_lookup_by_addr(addr, flags, buf, nbytes,
		    symp, sip));
	}

	*symp = sym;
	sip->sym_id = symid;

found:
	/*
	 * Once we've found something, copy the final name into the caller's
	 * buffer and prefix it with the load object name if appropriate.
	 */
	name = mdb_gelf_sym_name(sym_km->km_symtab, symp);

	if (sym_km == &prmod) {
		if (buf != NULL) {
			(void) strncpy(buf, name, nbytes);
			buf[nbytes - 1] = '\0';
		}
		sip->sym_table = MDB_TGT_PRVSYM;
	} else {
		if (buf != NULL) {
			if (sym_km->km_flags & KM_F_PRIMARY) {
				(void) strncpy(buf, name, nbytes);
				buf[nbytes - 1] = '\0';
			} else {
				(void) mdb_snprintf(buf, nbytes, "%s`%s",
				    sym_km->km_name, name);
			}
		}
		sip->sym_table = MDB_TGT_SYMTAB;
	}

	return (0);
}

static int
kmt_lookup_by_name(mdb_tgt_t *t, const char *obj, const char *name,
    GElf_Sym *symp, mdb_syminfo_t *sip)
{
	kmt_data_t *kmt = t->t_data;
	kmt_module_t *km;
	mdb_var_t *v;
	GElf_Sym sym;
	uint_t symid;
	int n;

	if (!kmt->kmt_symavail)
		return (set_errno(EMDB_NOSYM));

	switch ((uintptr_t)obj) {
	case (uintptr_t)MDB_TGT_OBJ_EXEC:
	case (uintptr_t)MDB_TGT_OBJ_EVERY:
		km = mdb_list_next(&kmt->kmt_modlist);
		n = mdb_nv_size(&kmt->kmt_modules);
		break;

	case (uintptr_t)MDB_TGT_OBJ_RTLD:
		obj = kmt->kmt_rtld_name;
		/*FALLTHROUGH*/

	default:
		/*
		 * If this is a request for a dmod symbol, let kmdb_module
		 * handle it.
		 */
		if (obj != NULL && strncmp(obj, "DMOD`", 5) == 0) {
			return (kmdb_module_lookup_by_name(obj + 5, name,
			    symp, sip));
		}

		if ((v = mdb_nv_lookup(&kmt->kmt_modules, obj)) == NULL)
			return (set_errno(EMDB_NOOBJ));

		km = mdb_nv_get_cookie(v);
		n = 1;
	}

	/*
	 * kmdb's kvm target is at a bit of a disadvantage compared to mdb's
	 * kvm target when it comes to global symbol lookups.  mdb has ksyms,
	 * which hides pesky things like symbols that are undefined in unix,
	 * but which are defined in genunix.  We don't have such a facility -
	 * we simply iterate through the modules, looking for a given symbol
	 * in each.  Unless we're careful, we'll return the undef in the
	 * aforementioned case.
	 */
	for (; n > 0; n--, km = mdb_list_next(km)) {
		if (mdb_gelf_symtab_lookup_by_name(km->km_symtab, name,
		    &sym, &symid) == 0 && sym.st_shndx != SHN_UNDEF)
			break;
	}

	if (n == 0)
		return (set_errno(EMDB_NOSYM));

found:
	bcopy(&sym, symp, sizeof (GElf_Sym));
	sip->sym_id = symid;
	sip->sym_table = MDB_TGT_SYMTAB;

	return (0);
}

static int
kmt_symtab_func(void *data, const GElf_Sym *sym, const char *name, uint_t id)
{
	kmt_symarg_t *arg = data;

	if (mdb_tgt_sym_match(sym, arg->sym_type)) {
		arg->sym_info.sym_id = id;

		return (arg->sym_cb(arg->sym_data, sym, name, &arg->sym_info,
		    arg->sym_obj));
	}

	return (0);
}

static void
kmt_symtab_iter(mdb_gelf_symtab_t *gst, uint_t type, const char *obj,
    mdb_tgt_sym_f *cb, void *p)
{
	kmt_symarg_t arg;

	arg.sym_cb = cb;
	arg.sym_data = p;
	arg.sym_type = type;
	arg.sym_info.sym_table = gst->gst_tabid;
	arg.sym_obj = obj;

	mdb_gelf_symtab_iter(gst, kmt_symtab_func, &arg);
}

static int
kmt_symbol_iter(mdb_tgt_t *t, const char *obj, uint_t which, uint_t type,
    mdb_tgt_sym_f *cb, void *data)
{
	kmt_data_t *kmt = t->t_data;
	kmt_module_t *km;

	mdb_gelf_symtab_t *symtab = NULL;
	mdb_var_t *v;

	if (which == MDB_TGT_DYNSYM)
		return (set_errno(EMDB_TGTNOTSUP));

	switch ((uintptr_t)obj) {
	case (uintptr_t)MDB_TGT_OBJ_EXEC:
	case (uintptr_t)MDB_TGT_OBJ_EVERY:
		mdb_nv_rewind(&kmt->kmt_modules);
		while ((v = mdb_nv_advance(&kmt->kmt_modules)) != NULL) {
			km = mdb_nv_get_cookie(v);

			if (km->km_symtab != NULL) {
				kmt_symtab_iter(km->km_symtab, type,
				    km->km_name, cb, data);
			}
		}
		return (0);

	case (uintptr_t)MDB_TGT_OBJ_RTLD:
		obj = kmt->kmt_rtld_name;
		/*FALLTHROUGH*/

	default:
		if (strncmp(obj, "DMOD`", 5) == 0) {
			return (kmdb_module_symbol_iter(obj + 5, type,
			    cb, data));
		}

		if ((v = mdb_nv_lookup(&kmt->kmt_modules, obj)) == NULL)
			return (set_errno(EMDB_NOOBJ));
		km = mdb_nv_get_cookie(v);

		symtab = km->km_symtab;
	}

	if (symtab != NULL)
		kmt_symtab_iter(symtab, type, obj, cb, data);

	return (0);
}

static int
kmt_mapping_walk(uintptr_t addr, const void *data, kmt_maparg_t *marg)
{
	/*
	 * This is a bit sketchy but avoids problematic compilation of this
	 * target against the current VM implementation.  Now that we have
	 * vmem, we can make this less broken and more informative by changing
	 * this code to invoke the vmem walker in the near future.
	 */
	const struct kmt_seg {
		caddr_t s_base;
		size_t s_size;
	} *segp = (const struct kmt_seg *)data;

	mdb_map_t map;
	GElf_Sym sym;
	mdb_syminfo_t info;

	map.map_base = (uintptr_t)segp->s_base;
	map.map_size = segp->s_size;
	map.map_flags = MDB_TGT_MAP_R | MDB_TGT_MAP_W | MDB_TGT_MAP_X;

	if (kmt_lookup_by_addr(marg->map_target, addr, MDB_TGT_SYM_EXACT,
	    map.map_name, MDB_TGT_MAPSZ, &sym, &info) == -1) {

		(void) mdb_iob_snprintf(map.map_name, MDB_TGT_MAPSZ,
		    "%lr", addr);
	}

	return (marg->map_cb(marg->map_data, &map, map.map_name));
}

static int
kmt_mapping_iter(mdb_tgt_t *t, mdb_tgt_map_f *func, void *private)
{
	kmt_maparg_t m;
	uintptr_t kas;

	m.map_target = t;
	m.map_cb = func;
	m.map_data = private;

	if ((kas = kmt_read_kas(t)) == NULL)
		return (-1); /* errno is set for us */

	return (mdb_pwalk("seg", (mdb_walk_cb_t)kmt_mapping_walk, &m, kas));
}

static const mdb_map_t *
kmt_mod_to_map(kmt_module_t *km, mdb_map_t *map)
{
	(void) strncpy(map->map_name, km->km_name, MDB_TGT_MAPSZ);
	map->map_name[MDB_TGT_MAPSZ - 1] = '\0';
	map->map_base = km->km_text_va;
	map->map_size = km->km_text_size;
	map->map_flags = MDB_TGT_MAP_R | MDB_TGT_MAP_W | MDB_TGT_MAP_X;

	return (map);
}

static int
kmt_object_iter(mdb_tgt_t *t, mdb_tgt_map_f *func, void *private)
{
	kmt_data_t *kmt = t->t_data;
	kmt_module_t *km;
	mdb_map_t m;

	for (km = mdb_list_next(&kmt->kmt_modlist); km != NULL;
	    km = mdb_list_next(km)) {
		if (func(private, kmt_mod_to_map(km, &m), km->km_name) == -1)
			break;
	}

	return (0);
}

static const mdb_map_t *
kmt_addr_to_map(mdb_tgt_t *t, uintptr_t addr)
{
	kmt_data_t *kmt = t->t_data;
	kmt_module_t *km;

	for (km = mdb_list_next(&kmt->kmt_modlist); km != NULL;
	    km = mdb_list_next(km)) {
		if (addr - km->km_text_va < km->km_text_size ||
		    addr - km->km_data_va < km->km_data_size ||
		    addr - km->km_bss_va < km->km_bss_size)
			return (kmt_mod_to_map(km, &kmt->kmt_map));
	}

	(void) set_errno(EMDB_NOMAP);
	return (NULL);
}

static kmt_module_t *
kmt_module_by_name(kmt_data_t *kmt, const char *name)
{
	kmt_module_t *km;

	for (km = mdb_list_next(&kmt->kmt_modlist); km != NULL;
	    km = mdb_list_next(km)) {
		if (strcmp(name, km->km_name) == 0)
			return (km);
	}

	return (NULL);
}

static const mdb_map_t *
kmt_name_to_map(mdb_tgt_t *t, const char *name)
{
	kmt_data_t *kmt = t->t_data;
	kmt_module_t *km;
	mdb_map_t m;

	/*
	 * If name is MDB_TGT_OBJ_EXEC, return the first module on the list,
	 * which will be unix since we keep kmt_modlist in load order.
	 */
	if (name == MDB_TGT_OBJ_EXEC) {
		return (kmt_mod_to_map(mdb_list_next(&kmt->kmt_modlist),
		    &m));
	}

	if (name == MDB_TGT_OBJ_RTLD)
		name = kmt->kmt_rtld_name;

	if ((km = kmt_module_by_name(kmt, name)) != NULL)
		return (kmt_mod_to_map(km, &m));

	(void) set_errno(EMDB_NOOBJ);
	return (NULL);
}

static ctf_file_t *
kmt_load_ctfdata(mdb_tgt_t *t, kmt_module_t *km)
{
	kmt_data_t *kmt = t->t_data;
	int err;

	if (km->km_ctfp != NULL)
		return (km->km_ctfp);

	if (km->km_ctf_va == NULL || km->km_symtab == NULL) {
		(void) set_errno(EMDB_NOCTF);
		return (NULL);
	}

	if ((km->km_ctfp = mdb_ctf_bufopen(km->km_ctf_va, km->km_ctf_size,
	    km->km_symtab_va, &km->km_symtab_hdr, km->km_strtab_va,
	    &km->km_strtab_hdr, &err)) == NULL) {
		(void) set_errno(ctf_to_errno(err));
		return (NULL);
	}

	mdb_dprintf(MDB_DBG_KMOD, "loaded %lu bytes of CTF data for %s\n",
	    (ulong_t)km->km_ctf_size, km->km_name);

	if (ctf_parent_name(km->km_ctfp) != NULL) {
		mdb_var_t *v;

		if ((v = mdb_nv_lookup(&kmt->kmt_modules,
		    ctf_parent_name(km->km_ctfp))) != NULL) {
			kmt_module_t *pm = mdb_nv_get_cookie(v);

			if (pm->km_ctfp == NULL)
				(void) kmt_load_ctfdata(t, pm);

			if (pm->km_ctfp != NULL && ctf_import(km->km_ctfp,
			    pm->km_ctfp) == CTF_ERR) {
				warn("failed to import parent types into "
				    "%s: %s\n", km->km_name,
				    ctf_errmsg(ctf_errno(km->km_ctfp)));
			}
		} else {
			warn("failed to load CTF data for %s - parent %s not "
			    "loaded\n", km->km_name,
			    ctf_parent_name(km->km_ctfp));
		}
	}

	return (km->km_ctfp);
}

ctf_file_t *
kmt_addr_to_ctf(mdb_tgt_t *t, uintptr_t addr)
{
	kmt_data_t *kmt = t->t_data;
	kmt_module_t *km;

	for (km = mdb_list_next(&kmt->kmt_modlist); km != NULL;
	    km = mdb_list_next(km)) {
		if (addr - km->km_text_va < km->km_text_size ||
		    addr - km->km_data_va < km->km_data_size ||
		    addr - km->km_bss_va < km->km_bss_size)
			return (kmt_load_ctfdata(t, km));
	}

	return (kmdb_module_addr_to_ctf(addr));
}

ctf_file_t *
kmt_name_to_ctf(mdb_tgt_t *t, const char *name)
{
	kmt_data_t *kt = t->t_data;
	kmt_module_t *km;

	if (name == MDB_TGT_OBJ_EXEC) {
		name = KMT_CTFPARENT;
	} else if (name == MDB_TGT_OBJ_RTLD) {
		name = kt->kmt_rtld_name;
	} else if (strncmp(name, "DMOD`", 5) == 0) {
		/* Request for CTF data for a DMOD symbol */
		return (kmdb_module_name_to_ctf(name + 5));
	}

	if ((km = kmt_module_by_name(kt, name)) != NULL)
		return (kmt_load_ctfdata(t, km));

	(void) set_errno(EMDB_NOOBJ);
	return (NULL);
}

/*ARGSUSED*/
static int
kmt_status(mdb_tgt_t *t, mdb_tgt_status_t *tsp)
{
	int state;

	bzero(tsp, sizeof (mdb_tgt_status_t));

	switch ((state = kmdb_dpi_get_state(NULL))) {
	case DPI_STATE_INIT:
		tsp->st_state = MDB_TGT_RUNNING;
		tsp->st_pc = 0;
		break;

	case DPI_STATE_STOPPED:
		tsp->st_state = MDB_TGT_STOPPED;

		(void) kmdb_dpi_get_register("pc", &tsp->st_pc);
		break;

	case DPI_STATE_FAULTED:
		tsp->st_state = MDB_TGT_STOPPED;

		(void) kmdb_dpi_get_register("pc", &tsp->st_pc);

		tsp->st_flags |= MDB_TGT_ISTOP;
		break;

	case DPI_STATE_LOST:
		tsp->st_state = MDB_TGT_LOST;

		(void) kmdb_dpi_get_register("pc", &tsp->st_pc);
		break;
	}

	mdb_dprintf(MDB_DBG_KMOD, "kmt_status, dpi: %d tsp: %d, pc = %p %A\n",
	    state, tsp->st_state, (void *)tsp->st_pc, tsp->st_pc);

	return (0);
}

/*
 * Invoked when kmt_defbp_enter_debugger is called, this routine activates and
 * deactivates deferred breakpoints in response to module load and unload
 * events.
 */
/*ARGSUSED*/
static void
kmt_defbp_event(mdb_tgt_t *t, int vid, void *private)
{
	if (kmt_defbp_modchg_isload) {
		if (!mdb_tgt_sespec_activate_all(t) &&
		    (mdb.m_flags & MDB_FL_BPTNOSYMSTOP)) {
			/*
			 * We weren't able to activate the breakpoints.
			 * If so requested, we'll return without calling
			 * continue, thus throwing the user into the debugger.
			 */
			return;
		}

	} else {
		mdb_sespec_t *sep, *nsep;
		const mdb_map_t *map, *bpmap;
		mdb_map_t modmap;

		if ((map = kmt_addr_to_map(t,
		    (uintptr_t)kmt_defbp_modchg_modctl->mod_text)) == NULL) {
			warn("module unload notification for unknown module %s",
			    kmt_defbp_modchg_modctl->mod_modname);
			return; /* drop into the debugger */
		}

		bcopy(map, &modmap, sizeof (mdb_map_t));

		for (sep = mdb_list_next(&t->t_active); sep; sep = nsep) {
			nsep = mdb_list_next(sep);

			if (sep->se_ops == &kmt_brkpt_ops) {
				kmt_brkpt_t *kb = sep->se_data;

				if ((bpmap = kmt_addr_to_map(t,
				    kb->kb_addr)) == NULL ||
				    (bpmap->map_base == modmap.map_base &&
				    bpmap->map_size == modmap.map_size)) {
					mdb_tgt_sespec_idle_one(t, sep,
					    EMDB_NOMAP);
				}
			}
		}
	}

	(void) mdb_tgt_continue(t, NULL);
}

static void
kmt_defbp_enter_debugger(void)
{
	/*
	 * The debugger places a breakpoint here.  We can't have a simple
	 * nop function here, because GCC knows much more than we do, and
	 * will optimize away the call to it.
	 */
	(void) get_fp();
}

/*
 * This routine is called while the kernel is running.  It attempts to determine
 * whether any deferred breakpoints exist for the module being changed (loaded
 * or unloaded).  If any such breakpoints exist, the debugger will be entered to
 * process them.
 */
static void
kmt_defbp_modchg(struct modctl *mctl, int isload)
{
	kmt_defbp_t *dbp;

	kmt_defbp_lock = 1;

	for (dbp = mdb_list_next(&kmt_defbp_list); dbp;
	    dbp = mdb_list_next(dbp)) {
		if (!dbp->dbp_ref)
			continue;

		if (strcmp(mctl->mod_modname, dbp->dbp_objname) == 0) {
			/*
			 * Activate the breakpoint
			 */
			kmt_defbp_modchg_isload = isload;
			kmt_defbp_modchg_modctl = mctl;

			kmt_defbp_enter_debugger();
			break;
		}
	}

	kmt_defbp_lock = 0;
}

/*ARGSUSED*/
static int
kmt_continue(mdb_tgt_t *t, mdb_tgt_status_t *tsp)
{
	int n;

	kmdb_dpi_resume();

	/*
	 * The order of the following two calls is important.  If there are
	 * load acks on the work queue, we'll initialize the dmods they
	 * represent.  This will involve a call to _mdb_init, which may very
	 * well result in a symbol lookup.  If we haven't resynced our view
	 * of symbols with the current state of the world, this lookup could
	 * end very badly.  We therefore make sure to sync before processing
	 * the work queue.
	 */
	kmt_sync(t);
	kmdb_dpi_process_work_queue();

	if (kmdb_kdi_get_unload_request())
		t->t_flags |= MDB_TGT_F_UNLOAD;

	(void) mdb_tgt_status(t, &t->t_status);

	if ((n = kmt_dmod_status(NULL, KMDB_MC_STATE_LOADING) +
	    kmt_dmod_status(NULL, KMDB_MC_STATE_UNLOADING)) != 0) {
		mdb_warn("%d dmod load%c/unload%c pending\n", n,
		    "s"[n == 1], "s"[n == 1]);
	}

	return (0);
}

/*ARGSUSED*/
static int
kmt_step(mdb_tgt_t *t, mdb_tgt_status_t *tsp)
{
	int rc;

	if ((rc = kmdb_dpi_step()) == 0)
		(void) mdb_tgt_status(t, &t->t_status);

	return (rc);
}

static int
kmt_defbp_activate(mdb_tgt_t *t)
{
	kmdb_dpi_modchg_register(kmt_defbp_modchg);

	/*
	 * The routines that add and arm breakpoints will check for the proper
	 * DTrace state, but they'll just put this breakpoint on the idle list
	 * if DTrace is active.  It'll correctly move to the active list when
	 * DTrace deactivates, but that's insufficient for our purposes -- we
	 * need to do extra processing at that point.  We won't get to do said
	 * processing with with a normal idle->active transition, so we just
	 * won't add it add it until we're sure that it'll stick.
	 */

	if (kmdb_kdi_dtrace_get_state() == KDI_DTSTATE_DTRACE_ACTIVE)
		return (set_errno(EMDB_DTACTIVE));

	kmt_defbp_bpspec = mdb_tgt_add_vbrkpt(t,
	    (uintptr_t)kmt_defbp_enter_debugger,
	    MDB_TGT_SPEC_HIDDEN, kmt_defbp_event, NULL);

	return (0);
}

static void
kmt_defbp_deactivate(mdb_tgt_t *t)
{
	kmdb_dpi_modchg_cancel();

	if (kmt_defbp_bpspec != 0) {
		if (t != NULL)
			(void) mdb_tgt_vespec_delete(t, kmt_defbp_bpspec);

		kmt_defbp_bpspec = 0;
	}
}

static kmt_defbp_t *
kmt_defbp_create(mdb_tgt_t *t, const char *objname, const char *symname)
{
	kmt_defbp_t *dbp = mdb_alloc(sizeof (kmt_defbp_t), UM_SLEEP);

	mdb_dprintf(MDB_DBG_KMOD, "defbp_create %s`%s\n", objname, symname);

	dbp->dbp_objname = strdup(objname);
	dbp->dbp_symname = strdup(symname);
	dbp->dbp_ref = 1;

	kmt_defbp_num++;

	if (kmt_defbp_num == 1 || kmt_defbp_bpspec == 0) {
		if (kmt_defbp_activate(t) < 0)
			warn("failed to activate deferred breakpoints");
	}

	mdb_list_append(&kmt_defbp_list, dbp);

	return (dbp);
}

static void
kmt_defbp_destroy(kmt_defbp_t *dbp)
{
	mdb_dprintf(MDB_DBG_KMOD, "defbp_destroy %s`%s\n", dbp->dbp_objname,
	    dbp->dbp_symname);

	mdb_list_delete(&kmt_defbp_list, dbp);

	strfree(dbp->dbp_objname);
	strfree(dbp->dbp_symname);
	mdb_free(dbp, sizeof (kmt_defbp_t));
}

static void
kmt_defbp_prune_common(int all)
{
	kmt_defbp_t *dbp, *ndbp;

	/* We can't remove items from the list while the driver is using it. */
	if (kmt_defbp_lock)
		return;

	for (dbp = mdb_list_next(&kmt_defbp_list); dbp != NULL; dbp = ndbp) {
		ndbp = mdb_list_next(dbp);

		if (!all && dbp->dbp_ref)
			continue;

		kmt_defbp_destroy(dbp);
	}
}

static void
kmt_defbp_prune(void)
{
	kmt_defbp_prune_common(0);
}

static void
kmt_defbp_destroy_all(void)
{
	kmt_defbp_prune_common(1);
}

static void
kmt_defbp_delete(mdb_tgt_t *t, kmt_defbp_t *dbp)
{
	dbp->dbp_ref = 0;

	ASSERT(kmt_defbp_num > 0);
	kmt_defbp_num--;

	if (kmt_defbp_num == 0)
		kmt_defbp_deactivate(t);

	kmt_defbp_prune();
}

static int
kmt_brkpt_ctor(mdb_tgt_t *t, mdb_sespec_t *sep, void *args)
{
	mdb_tgt_status_t tsp;
	kmt_bparg_t *ka = args;
	kmt_brkpt_t *kb;
	GElf_Sym s;
	mdb_instr_t instr;

	(void) mdb_tgt_status(t, &tsp);
	if (tsp.st_state != MDB_TGT_RUNNING && tsp.st_state != MDB_TGT_STOPPED)
		return (set_errno(EMDB_NOPROC));

	if (ka->ka_symbol != NULL) {
		if (mdb_tgt_lookup_by_scope(t, ka->ka_symbol, &s, NULL) == -1) {
			if (errno != EMDB_NOOBJ && !(errno == EMDB_NOSYM &&
			    !(mdb.m_flags & MDB_FL_BPTNOSYMSTOP))) {
				warn("breakpoint %s activation failed",
				    ka->ka_symbol);
			}
			return (-1); /* errno is set for us */
		}

		ka->ka_addr = (uintptr_t)s.st_value;
	}

#ifdef __sparc
	if (ka->ka_addr & 3)
		return (set_errno(EMDB_BPALIGN));
#endif

	if (mdb_vread(&instr, sizeof (instr), ka->ka_addr) != sizeof (instr))
		return (-1); /* errno is set for us */

	if (kmdb_kdi_dtrace_get_state() == KDI_DTSTATE_DTRACE_ACTIVE)
		warn("breakpoint will not arm until DTrace is inactive\n");

	kb = mdb_zalloc(sizeof (kmt_brkpt_t), UM_SLEEP);
	kb->kb_addr = ka->ka_addr;
	sep->se_data = kb;

	return (0);
}

/*ARGSUSED*/
static void
kmt_brkpt_dtor(mdb_tgt_t *t, mdb_sespec_t *sep)
{
	mdb_free(sep->se_data, sizeof (kmt_brkpt_t));
}

/*ARGSUSED*/
static char *
kmt_brkpt_info(mdb_tgt_t *t, mdb_sespec_t *sep, mdb_vespec_t *vep,
    mdb_tgt_spec_desc_t *sp, char *buf, size_t nbytes)
{
	uintptr_t addr = NULL;

	if (vep != NULL) {
		kmt_bparg_t *ka = vep->ve_args;

		if (ka->ka_symbol != NULL) {
			(void) mdb_iob_snprintf(buf, nbytes, "stop at %s",
			    ka->ka_symbol);
		} else {
			(void) mdb_iob_snprintf(buf, nbytes, "stop at %a",
			    ka->ka_addr);
			addr = ka->ka_addr;
		}

	} else {
		addr = ((kmt_brkpt_t *)sep->se_data)->kb_addr;
		(void) mdb_iob_snprintf(buf, nbytes, "stop at %a", addr);
	}

	sp->spec_base = addr;
	sp->spec_size = sizeof (mdb_instr_t);

	return (buf);
}

static int
kmt_brkpt_secmp(mdb_tgt_t *t, mdb_sespec_t *sep, void *args)
{
	kmt_brkpt_t *kb = sep->se_data;
	kmt_bparg_t *ka = args;
	GElf_Sym sym;

	if (ka->ka_symbol != NULL) {
		return (mdb_tgt_lookup_by_scope(t, ka->ka_symbol,
		    &sym, NULL) == 0 && sym.st_value == kb->kb_addr);
	}

	return (ka->ka_addr == kb->kb_addr);
}

/*ARGSUSED*/
static int
kmt_brkpt_vecmp(mdb_tgt_t *t, mdb_vespec_t *vep, void *args)
{
	kmt_bparg_t *ka1 = vep->ve_args;
	kmt_bparg_t *ka2 = args;

	if (ka1->ka_symbol != NULL && ka2->ka_symbol != NULL)
		return (strcmp(ka1->ka_symbol, ka2->ka_symbol) == 0);

	if (ka1->ka_symbol == NULL && ka2->ka_symbol == NULL)
		return (ka1->ka_addr == ka2->ka_addr);

	return (0); /* fail if one is symbolic, other is an explicit address */
}

static int
kmt_brkpt_arm(mdb_tgt_t *t, mdb_sespec_t *sep)
{
	kmt_data_t *kmt = t->t_data;
	kmt_brkpt_t *kb = sep->se_data;
	int rv;

	if (kmdb_kdi_dtrace_get_state() == KDI_DTSTATE_DTRACE_ACTIVE)
		return (set_errno(EMDB_DTACTIVE));

	if ((rv = kmdb_dpi_brkpt_arm(kb->kb_addr, &kb->kb_oinstr)) != 0)
		return (rv);

	if (kmt->kmt_narmedbpts++ == 0)
		(void) kmdb_kdi_dtrace_set(KDI_DTSET_KMDB_BPT_ACTIVATE);

	return (0);
}

static int
kmt_brkpt_disarm(mdb_tgt_t *t, mdb_sespec_t *sep)
{
	kmt_data_t *kmt = t->t_data;
	kmt_brkpt_t *kb = sep->se_data;
	int rv;

	ASSERT(kmdb_kdi_dtrace_get_state() == KDI_DTSTATE_KMDB_BPT_ACTIVE);

	if ((rv = kmdb_dpi_brkpt_disarm(kb->kb_addr, kb->kb_oinstr)) != 0)
		return (rv);

	if (--kmt->kmt_narmedbpts == 0)
		(void) kmdb_kdi_dtrace_set(KDI_DTSET_KMDB_BPT_DEACTIVATE);

	return (0);
}

/*
 * Determine whether the specified sespec is an armed watchpoint that overlaps
 * with the given breakpoint and has the given flags set.  We use this to find
 * conflicts with breakpoints, below.
 */
static int
kmt_wp_overlap(mdb_sespec_t *sep, kmt_brkpt_t *kb, int flags)
{
	const kmdb_wapt_t *wp = sep->se_data;

	return (sep->se_state == MDB_TGT_SPEC_ARMED &&
	    sep->se_ops == &kmt_wapt_ops && (wp->wp_wflags & flags) &&
	    kb->kb_addr - wp->wp_addr < wp->wp_size);
}

/*
 * We step over breakpoints using our single-stepper.  If a conflicting
 * watchpoint is present, we must temporarily remove it before stepping over the
 * breakpoint so we don't immediately re-trigger the watchpoint.  We know the
 * watchpoint has already triggered on our trap instruction as part of fetching
 * it.  Before we return, we must re-install any disabled watchpoints.
 */
static int
kmt_brkpt_cont(mdb_tgt_t *t, mdb_sespec_t *sep, mdb_tgt_status_t *tsp)
{
	kmt_brkpt_t *kb = sep->se_data;
	int status = -1;
	int error;

	for (sep = mdb_list_next(&t->t_active); sep; sep = mdb_list_next(sep)) {
		if (kmt_wp_overlap(sep, kb, MDB_TGT_WA_X))
			(void) kmdb_dpi_wapt_disarm(sep->se_data);
	}

	if (kmdb_dpi_brkpt_disarm(kb->kb_addr, kb->kb_oinstr) == 0 &&
	    kmt_step(t, tsp) == 0)
		status = kmt_status(t, tsp);

	error = errno; /* save errno from disarm, step, or status */

	for (sep = mdb_list_next(&t->t_active); sep; sep = mdb_list_next(sep)) {
		if (kmt_wp_overlap(sep, kb, MDB_TGT_WA_X))
			kmdb_dpi_wapt_arm(sep->se_data);
	}

	(void) set_errno(error);
	return (status);
}

/*ARGSUSED*/
static int
kmt_brkpt_match(mdb_tgt_t *t, mdb_sespec_t *sep, mdb_tgt_status_t *tsp)
{
	kmt_brkpt_t *kb = sep->se_data;
	int state, why;
	kreg_t pc;

	state = kmdb_dpi_get_state(&why);
	(void) kmdb_dpi_get_register("pc", &pc);

	return (state == DPI_STATE_FAULTED && why == DPI_STATE_WHY_BKPT &&
	    pc == kb->kb_addr);
}

static const mdb_se_ops_t kmt_brkpt_ops = {
	kmt_brkpt_ctor,		/* se_ctor */
	kmt_brkpt_dtor,		/* se_dtor */
	kmt_brkpt_info,		/* se_info */
	kmt_brkpt_secmp,	/* se_secmp */
	kmt_brkpt_vecmp,	/* se_vecmp */
	kmt_brkpt_arm,		/* se_arm */
	kmt_brkpt_disarm,	/* se_disarm */
	kmt_brkpt_cont,		/* se_cont */
	kmt_brkpt_match		/* se_match */
};

static int
kmt_wapt_ctor(mdb_tgt_t *t, mdb_sespec_t *sep, void *args)
{
	mdb_tgt_status_t tsp;
	kmdb_wapt_t *vwp = args;
	kmdb_wapt_t *swp;

	(void) mdb_tgt_status(t, &tsp);
	if (tsp.st_state != MDB_TGT_RUNNING && tsp.st_state != MDB_TGT_STOPPED)
		return (set_errno(EMDB_NOPROC));

	swp = mdb_alloc(sizeof (kmdb_wapt_t), UM_SLEEP);
	bcopy(vwp, swp, sizeof (kmdb_wapt_t));

	if (kmdb_dpi_wapt_reserve(swp) < 0) {
		mdb_free(swp, sizeof (kmdb_wapt_t));
		return (-1); /* errno is set for us */
	}

	sep->se_data = swp;

	return (0);
}

/*ARGSUSED*/
static void
kmt_wapt_dtor(mdb_tgt_t *t, mdb_sespec_t *sep)
{
	kmdb_wapt_t *wp = sep->se_data;

	kmdb_dpi_wapt_release(wp);
	mdb_free(wp, sizeof (kmdb_wapt_t));
}

/*ARGSUSED*/
static char *
kmt_wapt_info(mdb_tgt_t *t, mdb_sespec_t *sep, mdb_vespec_t *vep,
    mdb_tgt_spec_desc_t *sp, char *buf, size_t nbytes)
{
	kmdb_wapt_t *wp = vep != NULL ? vep->ve_args : sep->se_data;
	const char *fmt;
	char desc[24];

	ASSERT(wp->wp_wflags != 0);
	desc[0] = '\0';

	switch (wp->wp_wflags) {
	case MDB_TGT_WA_R:
		(void) strcat(desc, "/read");
		break;
	case MDB_TGT_WA_W:
		(void) strcat(desc, "/write");
		break;
	case MDB_TGT_WA_X:
		(void) strcat(desc, "/exec");
		break;
	default:
		if (wp->wp_wflags & MDB_TGT_WA_R)
			(void) strcat(desc, "/r");
		if (wp->wp_wflags & MDB_TGT_WA_W)
			(void) strcat(desc, "/w");
		if (wp->wp_wflags & MDB_TGT_WA_X)
			(void) strcat(desc, "/x");
	}

	switch (wp->wp_type) {
	case DPI_WAPT_TYPE_PHYS:
		fmt = "stop on %s of phys [%p, %p)";
		break;

	case DPI_WAPT_TYPE_VIRT:
		fmt = "stop on %s of [%la, %la)";
		break;

	case DPI_WAPT_TYPE_IO:
		if (wp->wp_size == 1)
			fmt = "stop on %s of I/O port %p";
		else
			fmt = "stop on %s of I/O port [%p, %p)";
		break;
	}

	(void) mdb_iob_snprintf(buf, nbytes, fmt, desc + 1, wp->wp_addr,
	    wp->wp_addr + wp->wp_size);

	sp->spec_base = wp->wp_addr;
	sp->spec_size = wp->wp_size;

	return (buf);
}

/*ARGSUSED*/
static int
kmt_wapt_secmp(mdb_tgt_t *t, mdb_sespec_t *sep, void *args)
{
	kmdb_wapt_t *wp1 = sep->se_data;
	kmdb_wapt_t *wp2 = args;

	return (wp1->wp_addr == wp2->wp_addr && wp1->wp_size == wp2->wp_size &&
	    wp1->wp_wflags == wp2->wp_wflags);
}

/*ARGSUSED*/
static int
kmt_wapt_vecmp(mdb_tgt_t *t, mdb_vespec_t *vep, void *args)
{
	kmdb_wapt_t *wp1 = vep->ve_args;
	kmdb_wapt_t *wp2 = args;

	return (wp1->wp_addr == wp2->wp_addr && wp1->wp_size == wp2->wp_size &&
	    wp1->wp_wflags == wp2->wp_wflags);
}

/*ARGSUSED*/
static int
kmt_wapt_arm(mdb_tgt_t *t, mdb_sespec_t *sep)
{
	kmdb_dpi_wapt_arm(sep->se_data);

	return (0);
}

/*ARGSUSED*/
static int
kmt_wapt_disarm(mdb_tgt_t *t, mdb_sespec_t *sep)
{
	kmdb_dpi_wapt_disarm(sep->se_data);

	return (0);
}

/*
 * Determine whether the specified sespec is an armed breakpoint at the given
 * %pc.  We use this to find conflicts with watchpoints below.
 */
static int
kmt_bp_overlap(mdb_sespec_t *sep, uintptr_t pc)
{
	kmt_brkpt_t *kb = sep->se_data;

	return (sep->se_state == MDB_TGT_SPEC_ARMED &&
	    sep->se_ops == &kmt_brkpt_ops && kb->kb_addr == pc);
}

/*
 * We step over watchpoints using our single-stepper.  If a conflicting
 * breakpoint is present, we must temporarily disarm it before stepping over
 * the watchpoint so we do not immediately re-trigger the breakpoint.  This is
 * similar to the case handled in kmt_brkpt_cont(), above.
 */
static int
kmt_wapt_cont(mdb_tgt_t *t, mdb_sespec_t *sep, mdb_tgt_status_t *tsp)
{
	mdb_sespec_t *bep = NULL;
	int status = -1;
	int error, why;

	/*
	 * If we stopped for anything other than a watchpoint, check to see
	 * if there's a breakpoint here.
	 */
	if (!(kmdb_dpi_get_state(&why) == DPI_STATE_FAULTED &&
	    (why == DPI_STATE_WHY_V_WAPT || why == DPI_STATE_WHY_P_WAPT))) {
		kreg_t pc;

		(void) kmdb_dpi_get_register("pc", &pc);

		for (bep = mdb_list_next(&t->t_active); bep != NULL;
		    bep = mdb_list_next(bep)) {
			if (kmt_bp_overlap(bep, pc)) {
				(void) bep->se_ops->se_disarm(t, bep);
				bep->se_state = MDB_TGT_SPEC_ACTIVE;
				break;
			}
		}
	}

	kmdb_dpi_wapt_disarm(sep->se_data);
	if (kmt_step(t, tsp) == 0)
		status = kmt_status(t, tsp);

	error = errno; /* save errno from step or status */

	if (bep != NULL)
		mdb_tgt_sespec_arm_one(t, bep);

	(void) set_errno(error);
	return (status);
}

/*ARGSUSED*/
static int
kmt_wapt_match(mdb_tgt_t *t, mdb_sespec_t *sep, mdb_tgt_status_t *tsp)
{
	return (kmdb_dpi_wapt_match(sep->se_data));
}

static const mdb_se_ops_t kmt_wapt_ops = {
	kmt_wapt_ctor,		/* se_ctor */
	kmt_wapt_dtor,		/* se_dtor */
	kmt_wapt_info,		/* se_info */
	kmt_wapt_secmp,		/* se_secmp */
	kmt_wapt_vecmp,		/* se_vecmp */
	kmt_wapt_arm,		/* se_arm */
	kmt_wapt_disarm,	/* se_disarm */
	kmt_wapt_cont,		/* se_cont */
	kmt_wapt_match		/* se_match */
};

/*ARGSUSED*/
static int
kmt_trap_ctor(mdb_tgt_t *t, mdb_sespec_t *sep, void *args)
{
	sep->se_data = args; /* trap number */

	return (0);
}

/*ARGSUSED*/
static char *
kmt_trap_info(mdb_tgt_t *t, mdb_sespec_t *sep, mdb_vespec_t *vep,
    mdb_tgt_spec_desc_t *sp, char *buf, size_t nbytes)
{
	const char *name;
	int trapnum;

	if (vep != NULL)
		trapnum = (intptr_t)vep->ve_args;
	else
		trapnum = (intptr_t)sep->se_data;

	if (trapnum == KMT_TRAP_ALL)
		name = "any trap";
	else if (trapnum == KMT_TRAP_NOTENUM)
		name = "miscellaneous trap";
	else
		name = kmt_trapname(trapnum);

	(void) mdb_iob_snprintf(buf, nbytes, "single-step stop on %s", name);

	return (buf);
}

/*ARGSUSED2*/
static int
kmt_trap_match(mdb_tgt_t *t, mdb_sespec_t *sep, mdb_tgt_status_t *tsp)
{
	int spectt = (intptr_t)sep->se_data;
	kmt_data_t *kmt = t->t_data;
	kreg_t tt;

	(void) kmdb_dpi_get_register("tt", &tt);

	switch (spectt) {
	case KMT_TRAP_ALL:
		return (1);
	case KMT_TRAP_NOTENUM:
		return (tt > kmt->kmt_trapmax ||
		    !BT_TEST(kmt->kmt_trapmap, tt));
	default:
		return (tt == spectt);
	}
}

static const mdb_se_ops_t kmt_trap_ops = {
	kmt_trap_ctor,		/* se_ctor */
	no_se_dtor,		/* se_dtor */
	kmt_trap_info,		/* se_info */
	no_se_secmp,		/* se_secmp */
	no_se_vecmp,		/* se_vecmp */
	no_se_arm,		/* se_arm */
	no_se_disarm,		/* se_disarm */
	no_se_cont,		/* se_cont */
	kmt_trap_match		/* se_match */
};

static void
kmt_bparg_dtor(mdb_vespec_t *vep)
{
	kmt_bparg_t *ka = vep->ve_args;

	if (ka->ka_symbol != NULL)
		strfree(ka->ka_symbol);

	if (ka->ka_defbp != NULL)
		kmt_defbp_delete(mdb.m_target, ka->ka_defbp);

	mdb_free(ka, sizeof (kmt_bparg_t));
}

static int
kmt_add_vbrkpt(mdb_tgt_t *t, uintptr_t addr,
    int spec_flags, mdb_tgt_se_f *func, void *data)
{
	kmt_bparg_t *ka = mdb_alloc(sizeof (kmt_bparg_t), UM_SLEEP);

	ka->ka_addr = addr;
	ka->ka_symbol = NULL;
	ka->ka_defbp = NULL;

	return (mdb_tgt_vespec_insert(t, &kmt_brkpt_ops, spec_flags,
	    func, data, ka, kmt_bparg_dtor));
}

static int
kmt_add_sbrkpt(mdb_tgt_t *t, const char *fullname,
    int spec_flags, mdb_tgt_se_f *func, void *data)
{
	kmt_bparg_t *ka;
	kmt_defbp_t *dbp;
	GElf_Sym sym;
	char *tick, *objname, *symname;
	int serrno;

	if ((tick = strchr(fullname, '`')) == fullname) {
		(void) set_errno(EMDB_NOOBJ);
		return (0);
	}

	/*
	 * Deferred breakpoints are always scoped.  If we didn't find a tick,
	 * there's no scope.  We'll create a vbrkpt, but only if we can turn the
	 * provided string into an address.
	 */
	if (tick == NULL) {
		uintptr_t addr;

		if (strisbasenum(fullname)) {
			addr = mdb_strtoull(fullname); /* a bare address */
		} else if (mdb_tgt_lookup_by_name(t, MDB_TGT_OBJ_EVERY,
		    fullname, &sym, NULL) < 0) {
			(void) set_errno(EMDB_NOSYM);
			return (0);
		} else {
			addr = (uintptr_t)sym.st_value; /* unscoped sym name */
		}

		return (kmt_add_vbrkpt(t, addr, spec_flags, func, data));
	}

	if (*(tick + 1) == '\0') {
		(void) set_errno(EMDB_NOSYM);
		return (0);
	}

	objname = strndup(fullname, tick - fullname);
	symname = tick + 1;

	if (mdb_tgt_lookup_by_name(t, objname, symname, NULL, NULL) < 0 &&
	    errno != EMDB_NOOBJ) {
		serrno = errno;
		strfree(objname);

		(void) set_errno(serrno);
		return (0); /* errno is set for us */
	}

	dbp = kmt_defbp_create(t, objname, symname);
	strfree(objname);

	ka = mdb_alloc(sizeof (kmt_bparg_t), UM_SLEEP);
	ka->ka_symbol = strdup(fullname);
	ka->ka_addr = NULL;
	ka->ka_defbp = dbp;

	return (mdb_tgt_vespec_insert(t, &kmt_brkpt_ops, spec_flags,
	    func, data, ka, kmt_bparg_dtor));
}

static int
kmt_wparg_overlap(const kmdb_wapt_t *wp1, const kmdb_wapt_t *wp2)
{
	/* Assume the watchpoint spaces don't overlap */
	if (wp1->wp_type != wp2->wp_type)
		return (0);

	if (wp2->wp_addr + wp2->wp_size <= wp1->wp_addr)
		return (0); /* no range overlap */

	if (wp1->wp_addr + wp1->wp_size <= wp2->wp_addr)
		return (0); /* no range overlap */

	return (wp1->wp_addr != wp2->wp_addr || wp1->wp_size != wp2->wp_size ||
	    wp1->wp_wflags != wp2->wp_wflags);
}

static void
kmt_wparg_dtor(mdb_vespec_t *vep)
{
	mdb_free(vep->ve_args, sizeof (kmdb_wapt_t));
}

static int
kmt_add_wapt_common(mdb_tgt_t *t, uintptr_t addr, size_t len, uint_t wflags,
    int spec_flags, mdb_tgt_se_f *func, void *data, int type)
{
	kmdb_wapt_t *wp = mdb_alloc(sizeof (kmdb_wapt_t), UM_SLEEP);
	mdb_sespec_t *sep;

	wp->wp_addr = addr;
	wp->wp_size = len;
	wp->wp_type = type;
	wp->wp_wflags = wflags;

	if (kmdb_dpi_wapt_validate(wp) < 0)
		return (0); /* errno is set for us */

	for (sep = mdb_list_next(&t->t_active); sep; sep = mdb_list_next(sep)) {
		if (sep->se_ops == &kmt_wapt_ops &&
		    mdb_list_next(&sep->se_velist) != NULL &&
		    kmt_wparg_overlap(wp, sep->se_data))
			goto wapt_dup;
	}

	for (sep = mdb_list_next(&t->t_idle); sep; sep = mdb_list_next(sep)) {
		if (sep->se_ops == &kmt_wapt_ops && kmt_wparg_overlap(wp,
		    ((mdb_vespec_t *)mdb_list_next(&sep->se_velist))->ve_args))
			goto wapt_dup;
	}

	return (mdb_tgt_vespec_insert(t, &kmt_wapt_ops, spec_flags,
	    func, data, wp, kmt_wparg_dtor));

wapt_dup:
	mdb_free(wp, sizeof (kmdb_wapt_t));
	(void) set_errno(EMDB_WPDUP);
	return (0);
}

static int
kmt_add_pwapt(mdb_tgt_t *t, physaddr_t addr, size_t len, uint_t wflags,
    int spec_flags, mdb_tgt_se_f *func, void *data)
{
	return (kmt_add_wapt_common(t, (uintptr_t)addr, len, wflags, spec_flags,
	    func, data, DPI_WAPT_TYPE_PHYS));
}

static int
kmt_add_vwapt(mdb_tgt_t *t, uintptr_t addr, size_t len, uint_t wflags,
    int spec_flags, mdb_tgt_se_f *func, void *data)
{
	return (kmt_add_wapt_common(t, addr, len, wflags, spec_flags, func,
	    data, DPI_WAPT_TYPE_VIRT));
}

static int
kmt_add_iowapt(mdb_tgt_t *t, uintptr_t addr, size_t len, uint_t wflags,
    int spec_flags, mdb_tgt_se_f *func, void *data)
{
	return (kmt_add_wapt_common(t, addr, len, wflags, spec_flags, func,
	    data, DPI_WAPT_TYPE_IO));
}

static int
kmt_add_trap(mdb_tgt_t *t, int trapnum, int spec_flags, mdb_tgt_se_f *func,
    void *data)
{
	kmt_data_t *kmt = t->t_data;

	if (trapnum != KMT_TRAP_ALL && trapnum != KMT_TRAP_NOTENUM) {
		if (trapnum < 0 || trapnum > kmt->kmt_trapmax) {
			(void) set_errno(EMDB_BADFLTNUM);
			return (0);
		}

		BT_SET(kmt->kmt_trapmap, trapnum);
	}

	return (mdb_tgt_vespec_insert(t, &kmt_trap_ops, spec_flags, func, data,
	    (void *)(uintptr_t)trapnum, no_ve_dtor));
}

/*ARGSUSED*/
static uintmax_t
kmt_cpuid_disc_get(const mdb_var_t *v)
{
	return (kmdb_dpi_get_master_cpuid());
}

static const mdb_nv_disc_t kmt_cpuid_disc = {
	NULL,
	kmt_cpuid_disc_get
};

/*
 * This routine executes while the kernel is running.
 */
void
kmt_activate(mdb_tgt_t *t)
{
	kmt_data_t *kmt = t->t_data;

	mdb_prop_postmortem = FALSE;
	mdb_prop_kernel = TRUE;

	(void) mdb_tgt_register_dcmds(t, &kmt_dcmds[0], MDB_MOD_FORCE);
	mdb_tgt_register_regvars(t, kmt->kmt_rds, &kmt_reg_disc, 0);

	/*
	 * Force load of the MDB krtld module, in case it's been rolled into
	 * unix.
	 */
	(void) mdb_module_load(KMT_RTLD_NAME, MDB_MOD_SILENT | MDB_MOD_DEFER);
}

static void
kmt_destroy(mdb_tgt_t *t)
{
	kmt_data_t *kmt = t->t_data;
	kmt_module_t *km, *pkm;

	mdb_nv_destroy(&kmt->kmt_modules);
	for (km = mdb_list_prev(&kmt->kmt_modlist); km != NULL; km = pkm) {
		pkm = mdb_list_prev(km);
		mdb_free(km, sizeof (kmt_module_t));
	}

	if (!kmt_defbp_lock)
		kmt_defbp_destroy_all();

	if (kmt->kmt_trapmap != NULL)
		mdb_free(kmt->kmt_trapmap, BT_SIZEOFMAP(kmt->kmt_trapmax));

	if (kmt->kmt_cpu != NULL)
		kmt_cpu_destroy(kmt->kmt_cpu);

	if (kmt != NULL)
		mdb_free(kmt, sizeof (kmt_data_t));
}

static const mdb_tgt_ops_t kmt_ops = {
	kmt_setflags,				/* t_setflags */
	(int (*)()) mdb_tgt_notsup,		/* t_setcontext */
	kmt_activate,				/* t_activate */
	(void (*)()) mdb_tgt_nop,		/* t_deactivate */
	kmt_periodic,				/* t_periodic */
	kmt_destroy,				/* t_destroy */
	kmt_name,				/* t_name */
	(const char *(*)()) mdb_conf_isa,	/* t_isa */
	kmt_platform,				/* t_platform */
	kmt_uname,				/* t_uname */
	kmt_dmodel,				/* t_dmodel */
	(ssize_t (*)()) mdb_tgt_notsup,		/* t_aread */
	(ssize_t (*)()) mdb_tgt_notsup,		/* t_awrite */
	kmt_read,				/* t_vread */
	kmt_write,				/* t_vwrite */
	kmt_pread,				/* t_pread */
	kmt_pwrite,				/* t_pwrite */
	kmt_read,				/* t_fread */
	kmt_write,				/* t_fwrite */
	kmt_ioread,				/* t_ioread */
	kmt_iowrite,				/* t_iowrite */
	kmt_vtop,				/* t_vtop */
	kmt_lookup_by_name,			/* t_lookup_by_name */
	kmt_lookup_by_addr,			/* t_lookup_by_addr */
	kmt_symbol_iter,			/* t_symbol_iter */
	kmt_mapping_iter,			/* t_mapping_iter */
	kmt_object_iter,			/* t_object_iter */
	kmt_addr_to_map,			/* t_addr_to_map */
	kmt_name_to_map,			/* t_name_to_map */
	kmt_addr_to_ctf,			/* t_addr_to_ctf */
	kmt_name_to_ctf,			/* t_name_to_ctf */
	kmt_status,				/* t_status */
	(int (*)()) mdb_tgt_notsup,		/* t_run */
	kmt_step,				/* t_step */
	kmt_step_out,				/* t_step_out */
	kmt_step_branch,			/* t_step_branch */
	kmt_next,				/* t_next */
	kmt_continue,				/* t_cont */
	(int (*)()) mdb_tgt_notsup,		/* t_signal */
	kmt_add_vbrkpt,				/* t_add_vbrkpt */
	kmt_add_sbrkpt,				/* t_add_sbrkpt */
	kmt_add_pwapt,				/* t_add_pwapt */
	kmt_add_vwapt,				/* t_add_vwapt */
	kmt_add_iowapt,				/* t_add_iowapt */
	(int (*)()) mdb_tgt_null,		/* t_add_sysenter */
	(int (*)()) mdb_tgt_null,		/* t_add_sysexit */
	(int (*)()) mdb_tgt_null,		/* t_add_signal */
	kmt_add_trap,				/* t_add_fault */
	kmt_getareg,				/* t_getareg */
	kmt_putareg,				/* t_putareg */
	(int (*)()) mdb_tgt_nop,		/* XXX t_stack_iter */
	(int (*)()) mdb_tgt_notsup		/* t_auxv */
};

/*
 * Called immediately upon resumption of the system after a step or continue.
 * Allows us to synchronize kmt's view of the world with reality.
 */
/*ARGSUSED*/
static void
kmt_sync(mdb_tgt_t *t)
{
	kmt_data_t *kmt = t->t_data;
	int symavail;

	mdb_dprintf(MDB_DBG_KMOD, "synchronizing with kernel\n");

	symavail = kmt->kmt_symavail;
	kmt->kmt_symavail = FALSE;

	/*
	 * Resync our view of the world if the modules have changed, or if we
	 * didn't have any symbols coming into this function.  The latter will
	 * only happen on startup.
	 */
	if (kmdb_kdi_mods_changed() || !symavail)
		kmt_modlist_update(t);

	/*
	 * It would be nice if we could run this less frequently, perhaps
	 * after a dvec-initiated trigger.
	 */
	kmdb_module_sync();

	kmt->kmt_symavail = TRUE;

	mdb_dprintf(MDB_DBG_KMOD, "synchronization complete\n");

	kmt_defbp_prune();

	if (kmt_defbp_num > 0 && kmt_defbp_bpspec == 0 &&
	    kmdb_kdi_dtrace_get_state() != KDI_DTSTATE_DTRACE_ACTIVE) {
		/*
		 * Deferred breakpoints were created while DTrace was active,
		 * and consequently the deferred breakpoint enabling mechanism
		 * wasn't activated.  Activate it now, and then try to activate
		 * the deferred breakpoints.  We do this so that we can catch
		 * the ones which may apply to modules that have been loaded
		 * while they were waiting for DTrace to deactivate.
		 */
		(void) kmt_defbp_activate(t);
		(void) mdb_tgt_sespec_activate_all(t);
	}

	if (kmt->kmt_cpu_retry && ((kmt->kmt_cpu = kmt_cpu_create(t)) !=
	    NULL || errno != EAGAIN))
		kmt->kmt_cpu_retry = FALSE;

	(void) mdb_tgt_status(t, &t->t_status);
}

/*
 * This routine executes while the kernel is running.
 */
/*ARGSUSED*/
int
kmdb_kvm_create(mdb_tgt_t *t, int argc, const char *argv[])
{
	kmt_data_t *kmt;

	if (argc != 0)
		return (set_errno(EINVAL));

	kmt = mdb_zalloc(sizeof (kmt_data_t), UM_SLEEP);
	t->t_data = kmt;
	t->t_ops = &kmt_ops;
	t->t_flags |= MDB_TGT_F_RDWR;	/* kmdb is always r/w */

	(void) mdb_nv_insert(&mdb.m_nv, "cpuid", &kmt_cpuid_disc, 0,
	    MDB_NV_PERSIST | MDB_NV_RDONLY);

	(void) mdb_nv_create(&kmt->kmt_modules, UM_SLEEP);

	kmt_init_isadep(t);

	kmt->kmt_symavail = FALSE;
	kmt->kmt_cpu_retry = TRUE;

	bzero(&kmt_defbp_list, sizeof (mdb_list_t));

	return (0);

create_err:
	kmt_destroy(t);

	return (-1);
}

/*
 * This routine is called once, when kmdb first has control of the world.
 */
void
kmdb_kvm_startup(void)
{
	kmt_data_t *kmt = mdb.m_target->t_data;

	mdb_dprintf(MDB_DBG_KMOD, "kmdb_kvm startup\n");

	kmt_sync(mdb.m_target);
	(void) mdb_module_load_builtin(KMT_MODULE);
	kmt_startup_isadep(mdb.m_target);

	/*
	 * This is here because we need to write the deferred breakpoint
	 * breakpoint when the debugger starts.  Our normal r/o write routines
	 * don't work when the kernel is running, so we have to do it during
	 * startup.
	 */
	(void) mdb_tgt_sespec_activate_all(mdb.m_target);

	kmt->kmt_rtld_name = KMT_RTLD_NAME;

	if (kmt_module_by_name(kmt, KMT_RTLD_NAME) == NULL)
		kmt->kmt_rtld_name = "unix";
}

/*
 * This routine is called after kmdb has loaded its initial set of modules.
 */
void
kmdb_kvm_poststartup(void)
{
	mdb_dprintf(MDB_DBG_KMOD, "kmdb_kvm post-startup\n");

	(void) mdb_dis_select(kmt_def_dismode());
}
