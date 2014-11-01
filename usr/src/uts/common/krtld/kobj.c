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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2011 Bayard G. Bell <buffer.g.overflow@gmail.com>.
 * All rights reserved. Use is subject to license terms.
 */

/*
 * Kernel's linker/loader
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/kmem.h>
#include <sys/reboot.h>
#include <sys/bootconf.h>
#include <sys/debug.h>
#include <sys/uio.h>
#include <sys/file.h>
#include <sys/vnode.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <vm/as.h>
#include <vm/seg_kp.h>
#include <vm/seg_kmem.h>
#include <sys/elf.h>
#include <sys/elf_notes.h>
#include <sys/vmsystm.h>
#include <sys/kdi.h>
#include <sys/atomic.h>
#include <sys/kmdb.h>

#include <sys/link.h>
#include <sys/kobj.h>
#include <sys/ksyms.h>
#include <sys/disp.h>
#include <sys/modctl.h>
#include <sys/varargs.h>
#include <sys/kstat.h>
#include <sys/kobj_impl.h>
#include <sys/fs/decomp.h>
#include <sys/callb.h>
#include <sys/cmn_err.h>
#include <sys/tnf_probe.h>
#include <sys/zmod.h>

#include <krtld/reloc.h>
#include <krtld/kobj_kdi.h>
#include <sys/sha1.h>
#include <sys/crypto/elfsign.h>

#if !defined(_OBP)
#include <sys/bootvfs.h>
#endif

/*
 * do_symbols() error codes
 */
#define	DOSYM_UNDEF		-1	/* undefined symbol */
#define	DOSYM_UNSAFE		-2	/* MT-unsafe driver symbol */

#if !defined(_OBP)
static void synthetic_bootaux(char *, val_t *);
#endif

static struct module *load_exec(val_t *, char *);
static void load_linker(val_t *);
static struct modctl *add_primary(const char *filename, int);
static int bind_primary(val_t *, int);
static int load_primary(struct module *, int);
static int load_kmdb(val_t *);
static int get_progbits(struct module *, struct _buf *);
static int get_syms(struct module *, struct _buf *);
static int get_ctf(struct module *, struct _buf *);
static void get_signature(struct module *, struct _buf *);
static int do_common(struct module *);
static void add_dependent(struct module *, struct module *);
static int do_dependents(struct modctl *, char *, size_t);
static int do_symbols(struct module *, Elf64_Addr);
static void module_assign(struct modctl *, struct module *);
static void free_module_data(struct module *);
static char *depends_on(struct module *);
static char *getmodpath(const char *);
static char *basename(char *);
static void attr_val(val_t *);
static char *find_libmacro(char *);
static char *expand_libmacro(char *, char *, char *);
static int read_bootflags(void);
static int kobj_comp_setup(struct _buf *, struct compinfo *);
static int kobj_uncomp_blk(struct _buf *, caddr_t, uint_t);
static int kobj_read_blks(struct _buf *, caddr_t, uint_t, uint_t);
static int kobj_boot_open(char *, int);
static int kobj_boot_close(int);
static int kobj_boot_seek(int, off_t, off_t);
static int kobj_boot_read(int, caddr_t, size_t);
static int kobj_boot_fstat(int, struct bootstat *);
static int kobj_boot_compinfo(int, struct compinfo *);

static Sym *lookup_one(struct module *, const char *);
static void sym_insert(struct module *, char *, symid_t);
static Sym *sym_lookup(struct module *, Sym *);

static struct kobjopen_tctl *kobjopen_alloc(char *filename);
static void kobjopen_free(struct kobjopen_tctl *ltp);
static void kobjopen_thread(struct kobjopen_tctl *ltp);
static int kobj_is_compressed(intptr_t);

extern int kcopy(const void *, void *, size_t);
extern int elf_mach_ok(Ehdr *);
extern int alloc_gottable(struct module *, caddr_t *, caddr_t *);

#if !defined(_OBP)
extern int kobj_boot_mountroot(void);
#endif

static void tnf_unsplice_probes(uint_t, struct modctl *);
extern tnf_probe_control_t *__tnf_probe_list_head;
extern tnf_tag_data_t *__tnf_tag_list_head;

extern int modrootloaded;
extern int swaploaded;
extern int bop_io_quiesced;
extern int last_module_id;

extern char stubs_base[];
extern char stubs_end[];

#ifdef KOBJ_DEBUG
/*
 * Values that can be or'd in to kobj_debug and their effects:
 *
 *	D_DEBUG		- misc. debugging information.
 *	D_SYMBOLS	- list symbols and their values as they are entered
 *			  into the hash table
 *	D_RELOCATIONS	- display relocation processing information
 *	D_LOADING	- display information about each module as it
 *			  is loaded.
 */
int kobj_debug = 0;

#define	KOBJ_MARK(s)	if (kobj_debug & D_DEBUG)	\
	(_kobj_printf(ops, "%d", __LINE__), _kobj_printf(ops, ": %s\n", s))
#else
#define	KOBJ_MARK(s)	/* discard */
#endif

#define	MODPATH_PROPNAME	"module-path"

#ifdef MODDIR_SUFFIX
static char slash_moddir_suffix_slash[] = MODDIR_SUFFIX "/";
#else
#define	slash_moddir_suffix_slash	""
#endif

#define	_moddebug	get_weakish_int(&moddebug)
#define	_modrootloaded	get_weakish_int(&modrootloaded)
#define	_swaploaded	get_weakish_int(&swaploaded)
#define	_ioquiesced	get_weakish_int(&bop_io_quiesced)

#define	mod(X)		(struct module *)((X)->modl_modp->mod_mp)

void	*romp;		/* rom vector (opaque to us) */
struct bootops *ops;	/* bootops vector */
void *dbvec;		/* debug vector */

/*
 * kobjopen thread control structure
 */
struct kobjopen_tctl {
	ksema_t		sema;
	char		*name;		/* name of file */
	struct vnode	*vp;		/* vnode return from vn_open() */
	int		Errno;		/* error return from vnopen    */
};

/*
 * Structure for defining dynamically expandable library macros
 */

struct lib_macro_info {
	char	*lmi_list;		/* ptr to list of possible choices */
	char	*lmi_macroname;		/* pointer to macro name */
	ushort_t lmi_ba_index;		/* index into bootaux vector */
	ushort_t lmi_macrolen;		/* macro length */
} libmacros[] = {
	{ NULL, "CPU", BA_CPU, 0 },
	{ NULL, "MMU", BA_MMU, 0 }
};

#define	NLIBMACROS	sizeof (libmacros) / sizeof (struct lib_macro_info)

char *boot_cpu_compatible_list;			/* make $CPU available */

char *kobj_module_path;				/* module search path */
vmem_t	*text_arena;				/* module text arena */
static vmem_t *data_arena;			/* module data & bss arena */
static vmem_t *ctf_arena;			/* CTF debug data arena */
static struct modctl *kobj_modules = NULL;	/* modules loaded */
int kobj_mmu_pagesize;				/* system pagesize */
static int lg_pagesize;				/* "large" pagesize */
static int kobj_last_module_id = 0;		/* id assignment */
static kmutex_t kobj_lock;			/* protects mach memory list */

/*
 * The following functions have been implemented by the kernel.
 * However, many 3rd party drivers provide their own implementations
 * of these functions.  When such drivers are loaded, messages
 * indicating that these symbols have been multiply defined will be
 * emitted to the console.  To avoid alarming customers for no good
 * reason, we simply suppress such warnings for the following set of
 * functions.
 */
static char *suppress_sym_list[] =
{
	"strstr",
	"strncat",
	"strlcat",
	"strlcpy",
	"strspn",
	"memcpy",
	"memset",
	"memmove",
	"memcmp",
	"memchr",
	"__udivdi3",
	"__divdi3",
	"__umoddi3",
	"__moddi3",
	NULL		/* This entry must exist */
};

/* indexed by KOBJ_NOTIFY_* */
static kobj_notify_list_t *kobj_notifiers[KOBJ_NOTIFY_MAX + 1];

/*
 * TNF probe management globals
 */
tnf_probe_control_t	*__tnf_probe_list_head = NULL;
tnf_tag_data_t		*__tnf_tag_list_head = NULL;
int			tnf_changed_probe_list = 0;

/*
 * Prefix for statically defined tracing (SDT) DTrace probes.
 */
const char		*sdt_prefix = "__dtrace_probe_";

/*
 * Beginning and end of the kernel's dynamic text/data segments.
 */
static caddr_t _text;
static caddr_t _etext;
static caddr_t _data;

/*
 * The sparc linker doesn't create a memory location
 * for a variable named _edata, so _edata can only be
 * referred to, not modified.  krtld needs a static
 * variable to modify it - within krtld, of course -
 * outside of krtld, e_data is used in all kernels.
 */
#if defined(__sparc)
static caddr_t _edata;
#else
extern caddr_t _edata;
#endif

Addr dynseg = 0;	/* load address of "dynamic" segment */
size_t dynsize;		/* "dynamic" segment size */


int standalone = 1;			/* an unwholey kernel? */
int use_iflush;				/* iflush after relocations */

/*
 * _kobj_printf()
 *
 * Common printf function pointer. Can handle only one conversion
 * specification in the format string. Some of the functions invoked
 * through this function pointer cannot handle more that one conversion
 * specification in the format string.
 */
void (*_kobj_printf)(void *, const char *, ...);	/* printf routine */

/*
 * Standalone function pointers for use within krtld.
 * Many platforms implement optimized platmod versions of
 * utilities such as bcopy and any such are not yet available
 * until the kernel is more completely stitched together.
 * See kobj_impl.h
 */
void (*kobj_bcopy)(const void *, void *, size_t);
void (*kobj_bzero)(void *, size_t);
size_t (*kobj_strlcat)(char *, const char *, size_t);

static kobj_stat_t kobj_stat;

#define	MINALIGN	8	/* at least a double-word */

int
get_weakish_int(int *ip)
{
	if (standalone)
		return (0);
	return (ip == NULL ? 0 : *ip);
}

static void *
get_weakish_pointer(void **ptrp)
{
	if (standalone)
		return (0);
	return (ptrp == NULL ? 0 : *ptrp);
}

/*
 * XXX fix dependencies on "kernel"; this should work
 * for other standalone binaries as well.
 *
 * XXX Fix hashing code to use one pointer to
 * hash entries.
 *	|----------|
 *	| nbuckets |
 *	|----------|
 *	| nchains  |
 *	|----------|
 *	| bucket[] |
 *	|----------|
 *	| chain[]  |
 *	|----------|
 */

/*
 * Load, bind and relocate all modules that
 * form the primary kernel. At this point, our
 * externals have not been relocated.
 */
void
kobj_init(
	void *romvec,
	void *dvec,
	struct bootops *bootvec,
	val_t *bootaux)
{
	struct module *mp;
	struct modctl *modp;
	Addr entry;
	char filename[MAXPATHLEN];

	/*
	 * Save these to pass on to
	 * the booted standalone.
	 */
	romp = romvec;
	dbvec = dvec;

	ops = bootvec;
	kobj_setup_standalone_vectors();

	KOBJ_MARK("Entered kobj_init()");

	(void) BOP_GETPROP(ops, "whoami", filename);

	/*
	 * We don't support standalone debuggers anymore.  The use of kadb
	 * will interfere with the later use of kmdb.  Let the user mend
	 * their ways now.  Users will reach this message if they still
	 * have the kadb binary on their system (perhaps they used an old
	 * bfu, or maybe they intentionally copied it there) and have
	 * specified its use in a way that eluded our checking in the boot
	 * program.
	 */
	if (dvec != NULL) {
		_kobj_printf(ops, "\nWARNING: Standalone debuggers such as "
		    "kadb are no longer supported\n\n");
		goto fail;
	}

#if defined(_OBP)
	/*
	 * OBP allows us to read both the ramdisk and
	 * the underlying root fs when root is a disk.
	 * This can lower incidences of unbootable systems
	 * when the archive is out-of-date with the /etc
	 * state files.
	 */
	if (BOP_MOUNTROOT() != BOOT_SVC_OK) {
		_kobj_printf(ops, "can't mount boot fs\n");
		goto fail;
	}
#else
	{
		/* on x86, we always boot with a ramdisk */
		(void) kobj_boot_mountroot();

		/*
		 * Now that the ramdisk is mounted, finish boot property
		 * initialization.
		 */
		boot_prop_finish();
	}

#if !defined(_UNIX_KRTLD)
	/*
	 * 'unix' is linked together with 'krtld' into one executable and
	 * the early boot code does -not- hand us any of the dynamic metadata
	 * about the executable. In particular, it does not read in, map or
	 * otherwise look at the program headers. We fake all that up now.
	 *
	 * We do this early as DTrace static probes and tnf probes both call
	 * undefined references.  We have to process those relocations before
	 * calling any of them.
	 *
	 * OBP tells kobj_start() where the ELF image is in memory, so it
	 * synthesized bootaux before kobj_init() was called
	 */
	if (bootaux[BA_PHDR].ba_ptr == NULL)
		synthetic_bootaux(filename, bootaux);

#endif	/* !_UNIX_KRTLD */
#endif	/* _OBP */

	/*
	 * Save the interesting attribute-values
	 * (scanned by kobj_boot).
	 */
	attr_val(bootaux);

	/*
	 * Set the module search path.
	 */
	kobj_module_path = getmodpath(filename);

	boot_cpu_compatible_list = find_libmacro("CPU");

	/*
	 * These two modules have actually been
	 * loaded by boot, but we finish the job
	 * by introducing them into the world of
	 * loadable modules.
	 */

	mp = load_exec(bootaux, filename);
	load_linker(bootaux);

	/*
	 * Load all the primary dependent modules.
	 */
	if (load_primary(mp, KOBJ_LM_PRIMARY) == -1)
		goto fail;

	/*
	 * Glue it together.
	 */
	if (bind_primary(bootaux, KOBJ_LM_PRIMARY) == -1)
		goto fail;

	entry = bootaux[BA_ENTRY].ba_val;

	/*
	 * Get the boot flags
	 */
	bootflags(ops);

	if (boothowto & RB_VERBOSE)
		kobj_lm_dump(KOBJ_LM_PRIMARY);

	kobj_kdi_init();

	if (boothowto & RB_KMDB) {
		if (load_kmdb(bootaux) < 0)
			goto fail;
	}

	/*
	 * Post setup.
	 */
	s_text = _text;
	e_text = _etext;
	s_data = _data;
	e_data = _edata;

	kobj_sync_instruction_memory(s_text, e_text - s_text);

#ifdef	KOBJ_DEBUG
	if (kobj_debug & D_DEBUG)
		_kobj_printf(ops,
		    "krtld: transferring control to: 0x%p\n", entry);
#endif

	/*
	 * Make sure the mod system knows about the modules already loaded.
	 */
	last_module_id = kobj_last_module_id;
	bcopy(kobj_modules, &modules, sizeof (modules));
	modp = &modules;
	do {
		if (modp->mod_next == kobj_modules)
			modp->mod_next = &modules;
		if (modp->mod_prev == kobj_modules)
			modp->mod_prev = &modules;
	} while ((modp = modp->mod_next) != &modules);

	standalone = 0;

#ifdef	KOBJ_DEBUG
	if (kobj_debug & D_DEBUG)
		_kobj_printf(ops,
		    "krtld: really transferring control to: 0x%p\n", entry);
#endif

	/* restore printf/bcopy/bzero vectors before returning */
	kobj_restore_vectors();

#if defined(_DBOOT)
	/*
	 * krtld was called from a dboot ELF section, the embedded
	 * dboot code contains the real entry via bootaux
	 */
	exitto((caddr_t)entry);
#else
	/*
	 * krtld was directly called from startup
	 */
	return;
#endif

fail:

	_kobj_printf(ops, "krtld: error during initial load/link phase\n");

#if !defined(_UNIX_KRTLD)
	_kobj_printf(ops, "\n");
	_kobj_printf(ops, "krtld could neither locate nor resolve symbols"
	    " for:\n");
	_kobj_printf(ops, "    %s\n", filename);
	_kobj_printf(ops, "in the boot archive. Please verify that this"
	    " file\n");
	_kobj_printf(ops, "matches what is found in the boot archive.\n");
	_kobj_printf(ops, "You may need to boot using the Solaris failsafe to"
	    " fix this.\n");
	bop_panic("Unable to boot");
#endif
}

#if !defined(_UNIX_KRTLD) && !defined(_OBP)
/*
 * Synthesize additional metadata that describes the executable if
 * krtld's caller didn't do it.
 *
 * (When the dynamic executable has an interpreter, the boot program
 * does all this for us.  Where we don't have an interpreter, (or a
 * even a boot program, perhaps) we have to do this for ourselves.)
 */
static void
synthetic_bootaux(char *filename, val_t *bootaux)
{
	Ehdr ehdr;
	caddr_t phdrbase;
	struct _buf *file;
	int i, n;

	/*
	 * Elf header
	 */
	KOBJ_MARK("synthetic_bootaux()");
	KOBJ_MARK(filename);
	file = kobj_open_file(filename);
	if (file == (struct _buf *)-1) {
		_kobj_printf(ops, "krtld: failed to open '%s'\n", filename);
		return;
	}
	KOBJ_MARK("reading program headers");
	if (kobj_read_file(file, (char *)&ehdr, sizeof (ehdr), 0) < 0) {
		_kobj_printf(ops, "krtld: %s: failed to read ehder\n",
		    filename);
		return;
	}

	/*
	 * Program headers
	 */
	bootaux[BA_PHNUM].ba_val = ehdr.e_phnum;
	bootaux[BA_PHENT].ba_val = ehdr.e_phentsize;
	n = ehdr.e_phentsize * ehdr.e_phnum;

	phdrbase = kobj_alloc(n, KM_WAIT | KM_TMP);

	if (kobj_read_file(file, phdrbase, n, ehdr.e_phoff) < 0) {
		_kobj_printf(ops, "krtld: %s: failed to read phdrs\n",
		    filename);
		return;
	}
	bootaux[BA_PHDR].ba_ptr = phdrbase;
	kobj_close_file(file);
	KOBJ_MARK("closed file");

	/*
	 * Find the dynamic section address
	 */
	for (i = 0; i < ehdr.e_phnum; i++) {
		Phdr *phdr = (Phdr *)(phdrbase + ehdr.e_phentsize * i);

		if (phdr->p_type == PT_DYNAMIC) {
			bootaux[BA_DYNAMIC].ba_ptr = (void *)phdr->p_vaddr;
			break;
		}
	}
	KOBJ_MARK("synthetic_bootaux() done");
}
#endif	/* !_UNIX_KRTLD && !_OBP */

/*
 * Set up any global information derived
 * from attribute/values in the boot or
 * aux vector.
 */
static void
attr_val(val_t *bootaux)
{
	Phdr *phdr;
	int phnum, phsize;
	int i;

	KOBJ_MARK("attr_val()");
	kobj_mmu_pagesize = bootaux[BA_PAGESZ].ba_val;
	lg_pagesize = bootaux[BA_LPAGESZ].ba_val;
	use_iflush = bootaux[BA_IFLUSH].ba_val;

	phdr = (Phdr *)bootaux[BA_PHDR].ba_ptr;
	phnum = bootaux[BA_PHNUM].ba_val;
	phsize = bootaux[BA_PHENT].ba_val;
	for (i = 0; i < phnum; i++) {
		phdr = (Phdr *)(bootaux[BA_PHDR].ba_val + i * phsize);

		if (phdr->p_type != PT_LOAD) {
			continue;
		}
		/*
		 * Bounds of the various segments.
		 */
		if (!(phdr->p_flags & PF_X)) {
#if defined(_RELSEG)
			/*
			 * sparc kernel puts the dynamic info
			 * into a separate segment, which is
			 * free'd in bop_fini()
			 */
			ASSERT(phdr->p_vaddr != 0);
			dynseg = phdr->p_vaddr;
			dynsize = phdr->p_memsz;
#else
			ASSERT(phdr->p_vaddr == 0);
#endif
		} else {
			if (phdr->p_flags & PF_W) {
				_data = (caddr_t)phdr->p_vaddr;
				_edata = _data + phdr->p_memsz;
			} else {
				_text = (caddr_t)phdr->p_vaddr;
				_etext = _text + phdr->p_memsz;
			}
		}
	}

	/* To do the kobj_alloc, _edata needs to be set. */
	for (i = 0; i < NLIBMACROS; i++) {
		if (bootaux[libmacros[i].lmi_ba_index].ba_ptr != NULL) {
			libmacros[i].lmi_list = kobj_alloc(
			    strlen(bootaux[libmacros[i].lmi_ba_index].ba_ptr) +
			    1, KM_WAIT);
			(void) strcpy(libmacros[i].lmi_list,
			    bootaux[libmacros[i].lmi_ba_index].ba_ptr);
		}
		libmacros[i].lmi_macrolen = strlen(libmacros[i].lmi_macroname);
	}
}

/*
 * Set up the booted executable.
 */
static struct module *
load_exec(val_t *bootaux, char *filename)
{
	struct modctl *cp;
	struct module *mp;
	Dyn *dyn;
	Sym *sp;
	int i, lsize, osize, nsize, allocsize;
	char *libname, *tmp;
	char path[MAXPATHLEN];

#ifdef KOBJ_DEBUG
	if (kobj_debug & D_DEBUG)
		_kobj_printf(ops, "module path '%s'\n", kobj_module_path);
#endif

	KOBJ_MARK("add_primary");
	cp = add_primary(filename, KOBJ_LM_PRIMARY);

	KOBJ_MARK("struct module");
	mp = kobj_zalloc(sizeof (struct module), KM_WAIT);
	cp->mod_mp = mp;

	/*
	 * We don't have the following information
	 * since this module is an executable and not
	 * a relocatable .o.
	 */
	mp->symtbl_section = 0;
	mp->shdrs = NULL;
	mp->strhdr = NULL;

	/*
	 * Since this module is the only exception,
	 * we cons up some section headers.
	 */
	KOBJ_MARK("symhdr");
	mp->symhdr = kobj_zalloc(sizeof (Shdr), KM_WAIT);

	KOBJ_MARK("strhdr");
	mp->strhdr = kobj_zalloc(sizeof (Shdr), KM_WAIT);

	mp->symhdr->sh_type = SHT_SYMTAB;
	mp->strhdr->sh_type = SHT_STRTAB;
	/*
	 * Scan the dynamic structure.
	 */
	for (dyn = (Dyn *) bootaux[BA_DYNAMIC].ba_ptr;
	    dyn->d_tag != DT_NULL; dyn++) {
		switch (dyn->d_tag) {
		case DT_SYMTAB:
			mp->symspace = mp->symtbl = (char *)dyn->d_un.d_ptr;
			mp->symhdr->sh_addr = dyn->d_un.d_ptr;
			break;
		case DT_HASH:
			mp->nsyms = *((uint_t *)dyn->d_un.d_ptr + 1);
			mp->hashsize = *(uint_t *)dyn->d_un.d_ptr;
			break;
		case DT_STRTAB:
			mp->strings = (char *)dyn->d_un.d_ptr;
			mp->strhdr->sh_addr = dyn->d_un.d_ptr;
			break;
		case DT_STRSZ:
			mp->strhdr->sh_size = dyn->d_un.d_val;
			break;
		case DT_SYMENT:
			mp->symhdr->sh_entsize = dyn->d_un.d_val;
			break;
		}
	}

	/*
	 * Collapse any DT_NEEDED entries into one string.
	 */
	nsize = osize = 0;
	allocsize = MAXPATHLEN;

	KOBJ_MARK("depends_on");
	mp->depends_on = kobj_alloc(allocsize, KM_WAIT);

	for (dyn = (Dyn *) bootaux[BA_DYNAMIC].ba_ptr;
	    dyn->d_tag != DT_NULL; dyn++)
		if (dyn->d_tag == DT_NEEDED) {
			char *_lib;

			libname = mp->strings + dyn->d_un.d_val;
			if (strchr(libname, '$') != NULL) {
				if ((_lib = expand_libmacro(libname,
				    path, path)) != NULL)
					libname = _lib;
				else
					_kobj_printf(ops, "krtld: "
					    "load_exec: fail to "
					    "expand %s\n", libname);
			}
			lsize = strlen(libname);
			nsize += lsize;
			if (nsize + 1 > allocsize) {
				KOBJ_MARK("grow depends_on");
				tmp = kobj_alloc(allocsize + MAXPATHLEN,
				    KM_WAIT);
				bcopy(mp->depends_on, tmp, osize);
				kobj_free(mp->depends_on, allocsize);
				mp->depends_on = tmp;
				allocsize += MAXPATHLEN;
			}
			bcopy(libname, mp->depends_on + osize, lsize);
			*(mp->depends_on + nsize) = ' '; /* separate */
			nsize++;
			osize = nsize;
		}
	if (nsize) {
		mp->depends_on[nsize - 1] = '\0'; /* terminate the string */
		/*
		 * alloc with exact size and copy whatever it got over
		 */
		KOBJ_MARK("realloc depends_on");
		tmp = kobj_alloc(nsize, KM_WAIT);
		bcopy(mp->depends_on, tmp, nsize);
		kobj_free(mp->depends_on, allocsize);
		mp->depends_on = tmp;
	} else {
		kobj_free(mp->depends_on, allocsize);
		mp->depends_on = NULL;
	}

	mp->flags = KOBJ_EXEC|KOBJ_PRIM;	/* NOT a relocatable .o */
	mp->symhdr->sh_size = mp->nsyms * mp->symhdr->sh_entsize;
	/*
	 * We allocate our own table since we don't
	 * hash undefined references.
	 */
	KOBJ_MARK("chains");
	mp->chains = kobj_zalloc(mp->nsyms * sizeof (symid_t), KM_WAIT);
	KOBJ_MARK("buckets");
	mp->buckets = kobj_zalloc(mp->hashsize * sizeof (symid_t), KM_WAIT);

	mp->text = _text;
	mp->data = _data;

	mp->text_size = _etext - _text;
	mp->data_size = _edata - _data;

	cp->mod_text = mp->text;
	cp->mod_text_size = mp->text_size;

	mp->filename = cp->mod_filename;

#ifdef	KOBJ_DEBUG
	if (kobj_debug & D_LOADING) {
		_kobj_printf(ops, "krtld: file=%s\n", mp->filename);
		_kobj_printf(ops, "\ttext: 0x%p", mp->text);
		_kobj_printf(ops, " size: 0x%x\n", mp->text_size);
		_kobj_printf(ops, "\tdata: 0x%p", mp->data);
		_kobj_printf(ops, " dsize: 0x%x\n", mp->data_size);
	}
#endif /* KOBJ_DEBUG */

	/*
	 * Insert symbols into the hash table.
	 */
	for (i = 0; i < mp->nsyms; i++) {
		sp = (Sym *)(mp->symtbl + i * mp->symhdr->sh_entsize);

		if (sp->st_name == 0 || sp->st_shndx == SHN_UNDEF)
			continue;
#if defined(__sparc)
		/*
		 * Register symbols are ignored in the kernel
		 */
		if (ELF_ST_TYPE(sp->st_info) == STT_SPARC_REGISTER)
			continue;
#endif	/* __sparc */

		sym_insert(mp, mp->strings + sp->st_name, i);
	}

	KOBJ_MARK("load_exec done");
	return (mp);
}

/*
 * Set up the linker module (if it's compiled in, LDNAME is NULL)
 */
static void
load_linker(val_t *bootaux)
{
	struct module *kmp = (struct module *)kobj_modules->mod_mp;
	struct module *mp;
	struct modctl *cp;
	int i;
	Shdr *shp;
	Sym *sp;
	int shsize;
	char *dlname = (char *)bootaux[BA_LDNAME].ba_ptr;

	/*
	 * On some architectures, krtld is compiled into the kernel.
	 */
	if (dlname == NULL)
		return;

	cp = add_primary(dlname, KOBJ_LM_PRIMARY);

	mp = kobj_zalloc(sizeof (struct module), KM_WAIT);

	cp->mod_mp = mp;
	mp->hdr = *(Ehdr *)bootaux[BA_LDELF].ba_ptr;
	shsize = mp->hdr.e_shentsize * mp->hdr.e_shnum;
	mp->shdrs = kobj_alloc(shsize, KM_WAIT);
	bcopy(bootaux[BA_LDSHDR].ba_ptr, mp->shdrs, shsize);

	for (i = 1; i < (int)mp->hdr.e_shnum; i++) {
		shp = (Shdr *)(mp->shdrs + (i * mp->hdr.e_shentsize));

		if (shp->sh_flags & SHF_ALLOC) {
			if (shp->sh_flags & SHF_WRITE) {
				if (mp->data == NULL)
					mp->data = (char *)shp->sh_addr;
			} else if (mp->text == NULL) {
				mp->text = (char *)shp->sh_addr;
			}
		}
		if (shp->sh_type == SHT_SYMTAB) {
			mp->symtbl_section = i;
			mp->symhdr = shp;
			mp->symspace = mp->symtbl = (char *)shp->sh_addr;
		}
	}
	mp->nsyms = mp->symhdr->sh_size / mp->symhdr->sh_entsize;
	mp->flags = KOBJ_INTERP|KOBJ_PRIM;
	mp->strhdr = (Shdr *)
	    (mp->shdrs + mp->symhdr->sh_link * mp->hdr.e_shentsize);
	mp->strings = (char *)mp->strhdr->sh_addr;
	mp->hashsize = kobj_gethashsize(mp->nsyms);

	mp->symsize = mp->symhdr->sh_size + mp->strhdr->sh_size + sizeof (int) +
	    (mp->hashsize + mp->nsyms) * sizeof (symid_t);

	mp->chains = kobj_zalloc(mp->nsyms * sizeof (symid_t), KM_WAIT);
	mp->buckets = kobj_zalloc(mp->hashsize * sizeof (symid_t), KM_WAIT);

	mp->bss = bootaux[BA_BSS].ba_val;
	mp->bss_align = 0;	/* pre-aligned during allocation */
	mp->bss_size = (uintptr_t)_edata - mp->bss;
	mp->text_size = _etext - mp->text;
	mp->data_size = _edata - mp->data;
	mp->filename = cp->mod_filename;
	cp->mod_text = mp->text;
	cp->mod_text_size = mp->text_size;

	/*
	 * Now that we've figured out where the linker is,
	 * set the limits for the booted object.
	 */
	kmp->text_size = (size_t)(mp->text - kmp->text);
	kmp->data_size = (size_t)(mp->data - kmp->data);
	kobj_modules->mod_text_size = kmp->text_size;

#ifdef	KOBJ_DEBUG
	if (kobj_debug & D_LOADING) {
		_kobj_printf(ops, "krtld: file=%s\n", mp->filename);
		_kobj_printf(ops, "\ttext:0x%p", mp->text);
		_kobj_printf(ops, " size: 0x%x\n", mp->text_size);
		_kobj_printf(ops, "\tdata:0x%p", mp->data);
		_kobj_printf(ops, " dsize: 0x%x\n", mp->data_size);
	}
#endif /* KOBJ_DEBUG */

	/*
	 * Insert the symbols into the hash table.
	 */
	for (i = 0; i < mp->nsyms; i++) {
		sp = (Sym *)(mp->symtbl + i * mp->symhdr->sh_entsize);

		if (sp->st_name == 0 || sp->st_shndx == SHN_UNDEF)
			continue;
		if (ELF_ST_BIND(sp->st_info) == STB_GLOBAL) {
			if (sp->st_shndx == SHN_COMMON)
				sp->st_shndx = SHN_ABS;
		}
		sym_insert(mp, mp->strings + sp->st_name, i);
	}

}

static kobj_notify_list_t **
kobj_notify_lookup(uint_t type)
{
	ASSERT(type != 0 && type < sizeof (kobj_notifiers) /
	    sizeof (kobj_notify_list_t *));

	return (&kobj_notifiers[type]);
}

int
kobj_notify_add(kobj_notify_list_t *knp)
{
	kobj_notify_list_t **knl;

	knl = kobj_notify_lookup(knp->kn_type);

	knp->kn_next = NULL;
	knp->kn_prev = NULL;

	mutex_enter(&kobj_lock);

	if (*knl != NULL) {
		(*knl)->kn_prev = knp;
		knp->kn_next = *knl;
	}
	(*knl) = knp;

	mutex_exit(&kobj_lock);
	return (0);
}

int
kobj_notify_remove(kobj_notify_list_t *knp)
{
	kobj_notify_list_t **knl = kobj_notify_lookup(knp->kn_type);
	kobj_notify_list_t *tknp;

	mutex_enter(&kobj_lock);

	/* LINTED */
	if (tknp = knp->kn_next)
		tknp->kn_prev = knp->kn_prev;

	/* LINTED */
	if (tknp = knp->kn_prev)
		tknp->kn_next = knp->kn_next;
	else
		*knl = knp->kn_next;

	mutex_exit(&kobj_lock);

	return (0);
}

/*
 * Notify all interested callbacks of a specified change in module state.
 */
static void
kobj_notify(int type, struct modctl *modp)
{
	kobj_notify_list_t *knp;

	if (modp->mod_loadflags & MOD_NONOTIFY || standalone)
		return;

	mutex_enter(&kobj_lock);

	for (knp = *(kobj_notify_lookup(type)); knp != NULL; knp = knp->kn_next)
		knp->kn_func(type, modp);

	/*
	 * KDI notification must be last (it has to allow for work done by the
	 * other notification callbacks), so we call it manually.
	 */
	kobj_kdi_mod_notify(type, modp);

	mutex_exit(&kobj_lock);
}

/*
 * Create the module path.
 */
static char *
getmodpath(const char *filename)
{
	char *path = kobj_zalloc(MAXPATHLEN, KM_WAIT);

	/*
	 * Platform code gets first crack, then add
	 * the default components
	 */
	mach_modpath(path, filename);
	if (*path != '\0')
		(void) strcat(path, " ");
	return (strcat(path, MOD_DEFPATH));
}

static struct modctl *
add_primary(const char *filename, int lmid)
{
	struct modctl *cp;

	cp = kobj_zalloc(sizeof (struct modctl), KM_WAIT);

	cp->mod_filename = kobj_alloc(strlen(filename) + 1, KM_WAIT);

	/*
	 * For symbol lookup, we assemble our own
	 * modctl list of the primary modules.
	 */

	(void) strcpy(cp->mod_filename, filename);
	cp->mod_modname = basename(cp->mod_filename);

	/* set values for modinfo assuming that the load will work */
	cp->mod_prim = 1;
	cp->mod_loaded = 1;
	cp->mod_installed = 1;
	cp->mod_loadcnt = 1;
	cp->mod_loadflags = MOD_NOAUTOUNLOAD;

	cp->mod_id = kobj_last_module_id++;

	/*
	 * Link the module in. We'll pass this info on
	 * to the mod squad later.
	 */
	if (kobj_modules == NULL) {
		kobj_modules = cp;
		cp->mod_prev = cp->mod_next = cp;
	} else {
		cp->mod_prev = kobj_modules->mod_prev;
		cp->mod_next = kobj_modules;
		kobj_modules->mod_prev->mod_next = cp;
		kobj_modules->mod_prev = cp;
	}

	kobj_lm_append(lmid, cp);

	return (cp);
}

static int
bind_primary(val_t *bootaux, int lmid)
{
	struct modctl_list *linkmap = kobj_lm_lookup(lmid);
	struct modctl_list *lp;
	struct module *mp;

	/*
	 * Do common symbols.
	 */
	for (lp = linkmap; lp; lp = lp->modl_next) {
		mp = mod(lp);

		/*
		 * Don't do common section relocations for modules that
		 * don't need it.
		 */
		if (mp->flags & (KOBJ_EXEC|KOBJ_INTERP))
			continue;

		if (do_common(mp) < 0)
			return (-1);
	}

	/*
	 * Resolve symbols.
	 */
	for (lp = linkmap; lp; lp = lp->modl_next) {
		mp = mod(lp);

		if (do_symbols(mp, 0) < 0)
			return (-1);
	}

	/*
	 * Do relocations.
	 */
	for (lp = linkmap; lp; lp = lp->modl_next) {
		mp = mod(lp);

		if (mp->flags & KOBJ_EXEC) {
			Dyn *dyn;
			Word relasz = 0, relaent = 0;
			Word shtype;
			char *rela = NULL;

			for (dyn = (Dyn *)bootaux[BA_DYNAMIC].ba_ptr;
			    dyn->d_tag != DT_NULL; dyn++) {
				switch (dyn->d_tag) {
				case DT_RELASZ:
				case DT_RELSZ:
					relasz = dyn->d_un.d_val;
					break;
				case DT_RELAENT:
				case DT_RELENT:
					relaent = dyn->d_un.d_val;
					break;
				case DT_RELA:
					shtype = SHT_RELA;
					rela = (char *)dyn->d_un.d_ptr;
					break;
				case DT_REL:
					shtype = SHT_REL;
					rela = (char *)dyn->d_un.d_ptr;
					break;
				}
			}
			if (relasz == 0 ||
			    relaent == 0 || rela == NULL) {
				_kobj_printf(ops, "krtld: bind_primary(): "
				    "no relocation information found for "
				    "module %s\n", mp->filename);
				return (-1);
			}
#ifdef	KOBJ_DEBUG
			if (kobj_debug & D_RELOCATIONS)
				_kobj_printf(ops, "krtld: relocating: file=%s "
				    "KOBJ_EXEC\n", mp->filename);
#endif
			if (do_relocate(mp, rela, shtype, relasz/relaent,
			    relaent, (Addr)mp->text) < 0)
				return (-1);
		} else {
			if (do_relocations(mp) < 0)
				return (-1);
		}

		kobj_sync_instruction_memory(mp->text, mp->text_size);
	}

	for (lp = linkmap; lp; lp = lp->modl_next) {
		mp = mod(lp);

		/*
		 * We need to re-read the full symbol table for the boot file,
		 * since we couldn't use the full one before.  We also need to
		 * load the CTF sections of both the boot file and the
		 * interpreter (us).
		 */
		if (mp->flags & KOBJ_EXEC) {
			struct _buf *file;
			int n;

			file = kobj_open_file(mp->filename);
			if (file == (struct _buf *)-1)
				return (-1);
			if (kobj_read_file(file, (char *)&mp->hdr,
			    sizeof (mp->hdr), 0) < 0)
				return (-1);
			n = mp->hdr.e_shentsize * mp->hdr.e_shnum;
			mp->shdrs = kobj_alloc(n, KM_WAIT);
			if (kobj_read_file(file, mp->shdrs, n,
			    mp->hdr.e_shoff) < 0)
				return (-1);
			if (get_syms(mp, file) < 0)
				return (-1);
			if (get_ctf(mp, file) < 0)
				return (-1);
			kobj_close_file(file);
			mp->flags |= KOBJ_RELOCATED;

		} else if (mp->flags & KOBJ_INTERP) {
			struct _buf *file;

			/*
			 * The interpreter path fragment in mp->filename
			 * will already have the module directory suffix
			 * in it (if appropriate).
			 */
			file = kobj_open_path(mp->filename, 1, 0);
			if (file == (struct _buf *)-1)
				return (-1);
			if (get_ctf(mp, file) < 0)
				return (-1);
			kobj_close_file(file);
			mp->flags |= KOBJ_RELOCATED;
		}
	}

	return (0);
}

static struct modctl *
mod_already_loaded(char *modname)
{
	struct modctl *mctl = kobj_modules;

	do {
		if (strcmp(modname, mctl->mod_filename) == 0)
			return (mctl);
		mctl = mctl->mod_next;

	} while (mctl != kobj_modules);

	return (NULL);
}

/*
 * Load all the primary dependent modules.
 */
static int
load_primary(struct module *mp, int lmid)
{
	struct modctl *cp;
	struct module *dmp;
	char *p, *q;
	char modname[MODMAXNAMELEN];

	if ((p = mp->depends_on) == NULL)
		return (0);

	/* CONSTANTCONDITION */
	while (1) {
		/*
		 * Skip space.
		 */
		while (*p && (*p == ' ' || *p == '\t'))
			p++;
		/*
		 * Get module name.
		 */
		q = modname;
		while (*p && *p != ' ' && *p != '\t')
			*q++ = *p++;

		if (q == modname)
			break;

		*q = '\0';
		/*
		 * Check for dup dependencies.
		 */
		if (strcmp(modname, "dtracestubs") == 0 ||
		    mod_already_loaded(modname) != NULL)
			continue;

		cp = add_primary(modname, lmid);
		cp->mod_busy = 1;
		/*
		 * Load it.
		 */
		(void) kobj_load_module(cp, 1);
		cp->mod_busy = 0;

		if ((dmp = cp->mod_mp) == NULL) {
			cp->mod_loaded = 0;
			cp->mod_installed = 0;
			cp->mod_loadcnt = 0;
			return (-1);
		}

		add_dependent(mp, dmp);
		dmp->flags |= KOBJ_PRIM;

		/*
		 * Recurse.
		 */
		if (load_primary(dmp, lmid) == -1) {
			cp->mod_loaded = 0;
			cp->mod_installed = 0;
			cp->mod_loadcnt = 0;
			return (-1);
		}
	}
	return (0);
}

static int
console_is_usb_serial(void)
{
	char *console;
	int len, ret;

	if ((len = BOP_GETPROPLEN(ops, "console")) == -1)
		return (0);

	console = kobj_zalloc(len, KM_WAIT|KM_TMP);
	(void) BOP_GETPROP(ops, "console", console);
	ret = (strcmp(console, "usb-serial") == 0);
	kobj_free(console, len);

	return (ret);
}

static int
load_kmdb(val_t *bootaux)
{
	struct modctl *mctl;
	struct module *mp;
	Sym *sym;

	if (console_is_usb_serial()) {
		_kobj_printf(ops, "kmdb not loaded "
		    "(unsupported on usb serial console)\n");
		return (0);
	}

	_kobj_printf(ops, "Loading kmdb...\n");

	if ((mctl = add_primary("misc/kmdbmod", KOBJ_LM_DEBUGGER)) == NULL)
		return (-1);

	mctl->mod_busy = 1;
	(void) kobj_load_module(mctl, 1);
	mctl->mod_busy = 0;

	if ((mp = mctl->mod_mp) == NULL)
		return (-1);

	mp->flags |= KOBJ_PRIM;

	if (load_primary(mp, KOBJ_LM_DEBUGGER) < 0)
		return (-1);

	if (boothowto & RB_VERBOSE)
		kobj_lm_dump(KOBJ_LM_DEBUGGER);

	if (bind_primary(bootaux, KOBJ_LM_DEBUGGER) < 0)
		return (-1);

	if ((sym = lookup_one(mctl->mod_mp, "kctl_boot_activate")) == NULL)
		return (-1);

#ifdef	KOBJ_DEBUG
	if (kobj_debug & D_DEBUG) {
		_kobj_printf(ops, "calling kctl_boot_activate() @ 0x%lx\n",
		    sym->st_value);
		_kobj_printf(ops, "\tops 0x%p\n", ops);
		_kobj_printf(ops, "\tromp 0x%p\n", romp);
	}
#endif

	if (((kctl_boot_activate_f *)sym->st_value)(ops, romp, 0,
	    (const char **)kobj_kmdb_argv) < 0)
		return (-1);

	return (0);
}

/*
 * Return a string listing module dependencies.
 */
static char *
depends_on(struct module *mp)
{
	Sym *sp;
	char *depstr, *q;

	/*
	 * The module doesn't have a depends_on value, so let's try it the
	 * old-fashioned way - via "_depends_on"
	 */
	if ((sp = lookup_one(mp, "_depends_on")) == NULL)
		return (NULL);

	q = (char *)sp->st_value;

#ifdef KOBJ_DEBUG
	/*
	 * _depends_on is a deprecated interface, so we warn about its use
	 * irrespective of subsequent processing errors. How else are we going
	 * to be able to deco this interface completely?
	 * Changes initially limited to DEBUG because third-party modules
	 * should be flagged to developers before general use base.
	 */
	_kobj_printf(ops,
	    "Warning: %s uses deprecated _depends_on interface.\n",
	    mp->filename);
	_kobj_printf(ops, "Please notify module developer or vendor.\n");
#endif

	/*
	 * Idiot checks. Make sure it's
	 * in-bounds and NULL terminated.
	 */
	if (kobj_addrcheck(mp, q) || q[sp->st_size - 1] != '\0') {
		_kobj_printf(ops, "Error processing dependency for %s\n",
		    mp->filename);
		return (NULL);
	}

	depstr = (char *)kobj_alloc(strlen(q) + 1, KM_WAIT);
	(void) strcpy(depstr, q);

	return (depstr);
}

void
kobj_getmodinfo(void *xmp, struct modinfo *modinfo)
{
	struct module *mp;
	mp = (struct module *)xmp;

	modinfo->mi_base = mp->text;
	modinfo->mi_size = mp->text_size + mp->data_size;
}

/*
 * kobj_export_ksyms() performs the following services:
 *
 * (1) Migrates the symbol table from boot/kobj memory to the ksyms arena.
 * (2) Removes unneeded symbols to save space.
 * (3) Reduces memory footprint by using VM_BESTFIT allocations.
 * (4) Makes the symbol table visible to /dev/ksyms.
 */
static void
kobj_export_ksyms(struct module *mp)
{
	Sym *esp = (Sym *)(mp->symtbl + mp->symhdr->sh_size);
	Sym *sp, *osp;
	char *name;
	size_t namelen;
	struct module *omp;
	uint_t nsyms;
	size_t symsize = mp->symhdr->sh_entsize;
	size_t locals = 1;
	size_t strsize;

	/*
	 * Make a copy of the original module structure.
	 */
	omp = kobj_alloc(sizeof (struct module), KM_WAIT);
	bcopy(mp, omp, sizeof (struct module));

	/*
	 * Compute the sizes of the new symbol table sections.
	 */
	for (nsyms = strsize = 1, osp = (Sym *)omp->symtbl; osp < esp; osp++) {
		if (osp->st_value == 0)
			continue;
		if (sym_lookup(omp, osp) == NULL)
			continue;
		name = omp->strings + osp->st_name;
		namelen = strlen(name);
		if (ELF_ST_BIND(osp->st_info) == STB_LOCAL)
			locals++;
		nsyms++;
		strsize += namelen + 1;
	}

	mp->nsyms = nsyms;
	mp->hashsize = kobj_gethashsize(mp->nsyms);

	/*
	 * ksyms_lock must be held as writer during any operation that
	 * modifies ksyms_arena, including allocation from same, and
	 * must not be dropped until the arena is vmem_walk()able.
	 */
	rw_enter(&ksyms_lock, RW_WRITER);

	/*
	 * Allocate space for the new section headers (symtab and strtab),
	 * symbol table, buckets, chains, and strings.
	 */
	mp->symsize = (2 * sizeof (Shdr)) + (nsyms * symsize) +
	    (mp->hashsize + mp->nsyms) * sizeof (symid_t) + strsize;

	if (mp->flags & KOBJ_NOKSYMS) {
		mp->symspace = kobj_alloc(mp->symsize, KM_WAIT);
	} else {
		mp->symspace = vmem_alloc(ksyms_arena, mp->symsize,
		    VM_BESTFIT | VM_SLEEP);
	}
	bzero(mp->symspace, mp->symsize);

	/*
	 * Divvy up symspace.
	 */
	mp->shdrs = mp->symspace;
	mp->symhdr = (Shdr *)mp->shdrs;
	mp->strhdr = (Shdr *)(mp->symhdr + 1);
	mp->symtbl = (char *)(mp->strhdr + 1);
	mp->buckets = (symid_t *)(mp->symtbl + (nsyms * symsize));
	mp->chains = (symid_t *)(mp->buckets + mp->hashsize);
	mp->strings = (char *)(mp->chains + nsyms);

	/*
	 * Fill in the new section headers (symtab and strtab).
	 */
	mp->hdr.e_shnum = 2;
	mp->symtbl_section = 0;

	mp->symhdr->sh_type = SHT_SYMTAB;
	mp->symhdr->sh_addr = (Addr)mp->symtbl;
	mp->symhdr->sh_size = nsyms * symsize;
	mp->symhdr->sh_link = 1;
	mp->symhdr->sh_info = locals;
	mp->symhdr->sh_addralign = sizeof (Addr);
	mp->symhdr->sh_entsize = symsize;

	mp->strhdr->sh_type = SHT_STRTAB;
	mp->strhdr->sh_addr = (Addr)mp->strings;
	mp->strhdr->sh_size = strsize;
	mp->strhdr->sh_addralign = 1;

	/*
	 * Construct the new symbol table.
	 */
	for (nsyms = strsize = 1, osp = (Sym *)omp->symtbl; osp < esp; osp++) {
		if (osp->st_value == 0)
			continue;
		if (sym_lookup(omp, osp) == NULL)
			continue;
		name = omp->strings + osp->st_name;
		namelen = strlen(name);
		sp = (Sym *)(mp->symtbl + symsize * nsyms);
		bcopy(osp, sp, symsize);
		bcopy(name, mp->strings + strsize, namelen);
		sp->st_name = strsize;
		sym_insert(mp, name, nsyms);
		nsyms++;
		strsize += namelen + 1;
	}

	rw_exit(&ksyms_lock);

	/*
	 * Free the old section headers -- we'll never need them again.
	 */
	if (!(mp->flags & KOBJ_PRIM)) {
		uint_t	shn;
		Shdr	*shp;

		for (shn = 1; shn < omp->hdr.e_shnum; shn++) {
			shp = (Shdr *)(omp->shdrs + shn * omp->hdr.e_shentsize);
			switch (shp->sh_type) {
			case SHT_RELA:
			case SHT_REL:
				if (shp->sh_addr != 0) {
					kobj_free((void *)shp->sh_addr,
					    shp->sh_size);
				}
				break;
			}
		}
		kobj_free(omp->shdrs, omp->hdr.e_shentsize * omp->hdr.e_shnum);
	}
	/*
	 * Discard the old symbol table and our copy of the module strucure.
	 */
	if (!(mp->flags & KOBJ_PRIM))
		kobj_free(omp->symspace, omp->symsize);
	kobj_free(omp, sizeof (struct module));
}

static void
kobj_export_ctf(struct module *mp)
{
	char *data = mp->ctfdata;
	size_t size = mp->ctfsize;

	if (data != NULL) {
		if (_moddebug & MODDEBUG_NOCTF) {
			mp->ctfdata = NULL;
			mp->ctfsize = 0;
		} else {
			mp->ctfdata = vmem_alloc(ctf_arena, size,
			    VM_BESTFIT | VM_SLEEP);
			bcopy(data, mp->ctfdata, size);
		}

		if (!(mp->flags & KOBJ_PRIM))
			kobj_free(data, size);
	}
}

void
kobj_export_module(struct module *mp)
{
	kobj_export_ksyms(mp);
	kobj_export_ctf(mp);

	mp->flags |= KOBJ_EXPORTED;
}

static int
process_dynamic(struct module *mp, char *dyndata, char *strdata)
{
	char *path = NULL, *depstr = NULL;
	int allocsize = 0, osize = 0, nsize = 0;
	char *libname, *tmp;
	int lsize;
	Dyn *dynp;

	for (dynp = (Dyn *)dyndata; dynp && dynp->d_tag != DT_NULL; dynp++) {
		switch (dynp->d_tag) {
		case DT_NEEDED:
			/*
			 * Read the DT_NEEDED entries, expanding the macros they
			 * contain (if any), and concatenating them into a
			 * single space-separated dependency list.
			 */
			libname = (ulong_t)dynp->d_un.d_ptr + strdata;

			if (strchr(libname, '$') != NULL) {
				char *_lib;

				if (path == NULL)
					path = kobj_alloc(MAXPATHLEN, KM_WAIT);
				if ((_lib = expand_libmacro(libname, path,
				    path)) != NULL)
					libname = _lib;
				else {
					_kobj_printf(ops, "krtld: "
					    "process_dynamic: failed to expand "
					    "%s\n", libname);
				}
			}

			lsize = strlen(libname);
			nsize += lsize;
			if (nsize + 1 > allocsize) {
				tmp = kobj_alloc(allocsize + MAXPATHLEN,
				    KM_WAIT);
				if (depstr != NULL) {
					bcopy(depstr, tmp, osize);
					kobj_free(depstr, allocsize);
				}
				depstr = tmp;
				allocsize += MAXPATHLEN;
			}
			bcopy(libname, depstr + osize, lsize);
			*(depstr + nsize) = ' '; /* separator */
			nsize++;
			osize = nsize;
			break;

		case DT_FLAGS_1:
			if (dynp->d_un.d_val & DF_1_IGNMULDEF)
				mp->flags |= KOBJ_IGNMULDEF;
			if (dynp->d_un.d_val & DF_1_NOKSYMS)
				mp->flags |= KOBJ_NOKSYMS;

			break;
		}
	}

	/*
	 * finish up the depends string (if any)
	 */
	if (depstr != NULL) {
		*(depstr + nsize - 1) = '\0'; /* overwrite separator w/term */
		if (path != NULL)
			kobj_free(path, MAXPATHLEN);

		tmp = kobj_alloc(nsize, KM_WAIT);
		bcopy(depstr, tmp, nsize);
		kobj_free(depstr, allocsize);
		depstr = tmp;

		mp->depends_on = depstr;
	}

	return (0);
}

static int
do_dynamic(struct module *mp, struct _buf *file)
{
	Shdr *dshp, *dstrp, *shp;
	char *dyndata, *dstrdata;
	int dshn, shn, rc;

	/* find and validate the dynamic section (if any) */

	for (dshp = NULL, shn = 1; shn < mp->hdr.e_shnum; shn++) {
		shp = (Shdr *)(mp->shdrs + shn * mp->hdr.e_shentsize);
		switch (shp->sh_type) {
		case SHT_DYNAMIC:
			if (dshp != NULL) {
				_kobj_printf(ops, "krtld: get_dynamic: %s, ",
				    mp->filename);
				_kobj_printf(ops,
				    "multiple dynamic sections\n");
				return (-1);
			} else {
				dshp = shp;
				dshn = shn;
			}
			break;
		}
	}

	if (dshp == NULL)
		return (0);

	if (dshp->sh_link > mp->hdr.e_shnum) {
		_kobj_printf(ops, "krtld: get_dynamic: %s, ", mp->filename);
		_kobj_printf(ops, "no section for sh_link %d\n", dshp->sh_link);
		return (-1);
	}
	dstrp = (Shdr *)(mp->shdrs + dshp->sh_link * mp->hdr.e_shentsize);

	if (dstrp->sh_type != SHT_STRTAB) {
		_kobj_printf(ops, "krtld: get_dynamic: %s, ", mp->filename);
		_kobj_printf(ops, "sh_link not a string table for section %d\n",
		    dshn);
		return (-1);
	}

	/* read it from disk */

	dyndata = kobj_alloc(dshp->sh_size, KM_WAIT|KM_TMP);
	if (kobj_read_file(file, dyndata, dshp->sh_size, dshp->sh_offset) < 0) {
		_kobj_printf(ops, "krtld: get_dynamic: %s, ", mp->filename);
		_kobj_printf(ops, "error reading section %d\n", dshn);

		kobj_free(dyndata, dshp->sh_size);
		return (-1);
	}

	dstrdata = kobj_alloc(dstrp->sh_size, KM_WAIT|KM_TMP);
	if (kobj_read_file(file, dstrdata, dstrp->sh_size,
	    dstrp->sh_offset) < 0) {
		_kobj_printf(ops, "krtld: get_dynamic: %s, ", mp->filename);
		_kobj_printf(ops, "error reading section %d\n", dshp->sh_link);

		kobj_free(dyndata, dshp->sh_size);
		kobj_free(dstrdata, dstrp->sh_size);
		return (-1);
	}

	/* pull the interesting pieces out */

	rc = process_dynamic(mp, dyndata, dstrdata);

	kobj_free(dyndata, dshp->sh_size);
	kobj_free(dstrdata, dstrp->sh_size);

	return (rc);
}

void
kobj_set_ctf(struct module *mp, caddr_t data, size_t size)
{
	if (!standalone) {
		if (mp->ctfdata != NULL) {
			if (vmem_contains(ctf_arena, mp->ctfdata,
			    mp->ctfsize)) {
				vmem_free(ctf_arena, mp->ctfdata, mp->ctfsize);
			} else {
				kobj_free(mp->ctfdata, mp->ctfsize);
			}
		}
	}

	/*
	 * The order is very important here.  We need to make sure that
	 * consumers, at any given instant, see a consistent state.  We'd
	 * rather they see no CTF data than the address of one buffer and the
	 * size of another.
	 */
	mp->ctfdata = NULL;
	membar_producer();
	mp->ctfsize = size;
	mp->ctfdata = data;
	membar_producer();
}

int
kobj_load_module(struct modctl *modp, int use_path)
{
	char *filename = modp->mod_filename;
	char *modname = modp->mod_modname;
	int i;
	int n;
	struct _buf *file;
	struct module *mp = NULL;
#ifdef MODDIR_SUFFIX
	int no_suffixdir_drv = 0;
#endif

	mp = kobj_zalloc(sizeof (struct module), KM_WAIT);

	/*
	 * We need to prevent kmdb's symbols from leaking into /dev/ksyms.
	 * kmdb contains a bunch of symbols with well-known names, symbols
	 * which will mask the real versions, thus causing no end of trouble
	 * for mdb.
	 */
	if (strcmp(modp->mod_modname, "kmdbmod") == 0)
		mp->flags |= KOBJ_NOKSYMS;

	file = kobj_open_path(filename, use_path, 1);
	if (file == (struct _buf *)-1) {
#ifdef MODDIR_SUFFIX
		file = kobj_open_path(filename, use_path, 0);
#endif
		if (file == (struct _buf *)-1) {
			kobj_free(mp, sizeof (*mp));
			goto bad;
		}
#ifdef MODDIR_SUFFIX
		/*
		 * There is no driver module in the ISA specific (suffix)
		 * subdirectory but there is a module in the parent directory.
		 */
		if (strncmp(filename, "drv/", 4) == 0) {
			no_suffixdir_drv = 1;
		}
#endif
	}

	mp->filename = kobj_alloc(strlen(file->_name) + 1, KM_WAIT);
	(void) strcpy(mp->filename, file->_name);

	if (kobj_read_file(file, (char *)&mp->hdr, sizeof (mp->hdr), 0) < 0) {
		_kobj_printf(ops, "kobj_load_module: %s read header failed\n",
		    modname);
		kobj_free(mp->filename, strlen(file->_name) + 1);
		kobj_free(mp, sizeof (*mp));
		goto bad;
	}
	for (i = 0; i < SELFMAG; i++) {
		if (mp->hdr.e_ident[i] != ELFMAG[i]) {
			if (_moddebug & MODDEBUG_ERRMSG)
				_kobj_printf(ops, "%s not an elf module\n",
				    modname);
			kobj_free(mp->filename, strlen(file->_name) + 1);
			kobj_free(mp, sizeof (*mp));
			goto bad;
		}
	}
	/*
	 * It's ELF, but is it our ISA?  Interpreting the header
	 * from a file for a byte-swapped ISA could cause a huge
	 * and unsatisfiable value to be passed to kobj_alloc below
	 * and therefore hang booting.
	 */
	if (!elf_mach_ok(&mp->hdr)) {
		if (_moddebug & MODDEBUG_ERRMSG)
			_kobj_printf(ops, "%s not an elf module for this ISA\n",
			    modname);
		kobj_free(mp->filename, strlen(file->_name) + 1);
		kobj_free(mp, sizeof (*mp));
#ifdef MODDIR_SUFFIX
		/*
		 * The driver mod is not in the ISA specific subdirectory
		 * and the module in the parent directory is not our ISA.
		 * If it is our ISA, for now we will silently succeed.
		 */
		if (no_suffixdir_drv == 1) {
			cmn_err(CE_CONT, "?NOTICE: %s: 64-bit driver module"
			    " not found\n", modname);
		}
#endif
		goto bad;
	}

	/*
	 * All modules, save for unix, should be relocatable (as opposed to
	 * dynamic).  Dynamic modules come with PLTs and GOTs, which can't
	 * currently be processed by krtld.
	 */
	if (mp->hdr.e_type != ET_REL) {
		if (_moddebug & MODDEBUG_ERRMSG)
			_kobj_printf(ops, "%s isn't a relocatable (ET_REL) "
			    "module\n", modname);
		kobj_free(mp->filename, strlen(file->_name) + 1);
		kobj_free(mp, sizeof (*mp));
		goto bad;
	}

	n = mp->hdr.e_shentsize * mp->hdr.e_shnum;
	mp->shdrs = kobj_alloc(n, KM_WAIT);

	if (kobj_read_file(file, mp->shdrs, n, mp->hdr.e_shoff) < 0) {
		_kobj_printf(ops, "kobj_load_module: %s error reading "
		    "section headers\n", modname);
		kobj_free(mp->shdrs, n);
		kobj_free(mp->filename, strlen(file->_name) + 1);
		kobj_free(mp, sizeof (*mp));
		goto bad;
	}

	kobj_notify(KOBJ_NOTIFY_MODLOADING, modp);
	module_assign(modp, mp);

	/* read in sections */
	if (get_progbits(mp, file) < 0) {
		_kobj_printf(ops, "%s error reading sections\n", modname);
		goto bad;
	}

	if (do_dynamic(mp, file) < 0) {
		_kobj_printf(ops, "%s error reading dynamic section\n",
		    modname);
		goto bad;
	}

	modp->mod_text = mp->text;
	modp->mod_text_size = mp->text_size;

	/* read in symbols; adjust values for each section's real address */
	if (get_syms(mp, file) < 0) {
		_kobj_printf(ops, "%s error reading symbols\n",
		    modname);
		goto bad;
	}

	/*
	 * If we didn't dependency information from the dynamic section, look
	 * for it the old-fashioned way.
	 */
	if (mp->depends_on == NULL)
		mp->depends_on = depends_on(mp);

	if (get_ctf(mp, file) < 0) {
		_kobj_printf(ops, "%s debug information will not "
		    "be available\n", modname);
	}

	/* primary kernel modules do not have a signature section */
	if (!(mp->flags & KOBJ_PRIM))
		get_signature(mp, file);

#ifdef	KOBJ_DEBUG
	if (kobj_debug & D_LOADING) {
		_kobj_printf(ops, "krtld: file=%s\n", mp->filename);
		_kobj_printf(ops, "\ttext:0x%p", mp->text);
		_kobj_printf(ops, " size: 0x%x\n", mp->text_size);
		_kobj_printf(ops, "\tdata:0x%p", mp->data);
		_kobj_printf(ops, " dsize: 0x%x\n", mp->data_size);
	}
#endif /* KOBJ_DEBUG */

	/*
	 * For primary kernel modules, we defer
	 * symbol resolution and relocation until
	 * all primary objects have been loaded.
	 */
	if (!standalone) {
		int ddrval, dcrval;
		char *dependent_modname;
		/* load all dependents */
		dependent_modname = kobj_zalloc(MODMAXNAMELEN, KM_WAIT);
		ddrval = do_dependents(modp, dependent_modname, MODMAXNAMELEN);

		/*
		 * resolve undefined and common symbols,
		 * also allocates common space
		 */
		if ((dcrval = do_common(mp)) < 0) {
			switch (dcrval) {
			case DOSYM_UNSAFE:
				_kobj_printf(ops, "WARNING: mod_load: "
				    "MT-unsafe module '%s' rejected\n",
				    modname);
				break;
			case DOSYM_UNDEF:
				_kobj_printf(ops, "WARNING: mod_load: "
				    "cannot load module '%s'\n",
				    modname);
				if (ddrval == -1) {
					_kobj_printf(ops, "WARNING: %s: ",
					    modname);
					_kobj_printf(ops,
					    "unable to resolve dependency, "
					    "module '%s' not found\n",
					    dependent_modname);
				}
				break;
			}
		}
		kobj_free(dependent_modname, MODMAXNAMELEN);
		if (dcrval < 0)
			goto bad;

		/* process relocation tables */
		if (do_relocations(mp) < 0) {
			_kobj_printf(ops, "%s error doing relocations\n",
			    modname);
			goto bad;
		}

		if (mp->destination) {
			off_t	off = (uintptr_t)mp->destination & PAGEOFFSET;
			caddr_t	base = (caddr_t)mp->destination - off;
			size_t	size = P2ROUNDUP(mp->text_size + off, PAGESIZE);

			hat_unload(kas.a_hat, base, size, HAT_UNLOAD_UNLOCK);
			vmem_free(heap_arena, base, size);
		}

		/* sync_instruction_memory */
		kobj_sync_instruction_memory(mp->text, mp->text_size);
		kobj_export_module(mp);
		kobj_notify(KOBJ_NOTIFY_MODLOADED, modp);
	}
	kobj_close_file(file);
	return (0);
bad:
	if (file != (struct _buf *)-1)
		kobj_close_file(file);
	if (modp->mod_mp != NULL)
		free_module_data(modp->mod_mp);

	module_assign(modp, NULL);
	return ((file == (struct _buf *)-1) ? ENOENT : EINVAL);
}

int
kobj_load_primary_module(struct modctl *modp)
{
	struct modctl *dep;
	struct module *mp;

	if (kobj_load_module(modp, 0) != 0)
		return (-1);

	mp = modp->mod_mp;
	mp->flags |= KOBJ_PRIM;

	/* Bind new module to its dependents */
	if (mp->depends_on != NULL && (dep =
	    mod_already_loaded(mp->depends_on)) == NULL) {
#ifdef	KOBJ_DEBUG
		if (kobj_debug & D_DEBUG) {
			_kobj_printf(ops, "krtld: failed to resolve deps "
			    "for primary %s\n", modp->mod_modname);
		}
#endif
		return (-1);
	}

	add_dependent(mp, dep->mod_mp);

	/*
	 * Relocate it.  This module may not be part of a link map, so we
	 * can't use bind_primary.
	 */
	if (do_common(mp) < 0 || do_symbols(mp, 0) < 0 ||
	    do_relocations(mp) < 0) {
#ifdef	KOBJ_DEBUG
		if (kobj_debug & D_DEBUG) {
			_kobj_printf(ops, "krtld: failed to relocate "
			    "primary %s\n", modp->mod_modname);
		}
#endif
		return (-1);
	}

	return (0);
}

static void
module_assign(struct modctl *cp, struct module *mp)
{
	if (standalone) {
		cp->mod_mp = mp;
		return;
	}
	mutex_enter(&mod_lock);
	cp->mod_mp = mp;
	cp->mod_gencount++;
	mutex_exit(&mod_lock);
}

void
kobj_unload_module(struct modctl *modp)
{
	struct module *mp = modp->mod_mp;

	if ((_moddebug & MODDEBUG_KEEPTEXT) && mp) {
		_kobj_printf(ops, "text for %s ", mp->filename);
		_kobj_printf(ops, "was at %p\n", mp->text);
		mp->text = NULL;	/* don't actually free it */
	}

	kobj_notify(KOBJ_NOTIFY_MODUNLOADING, modp);

	/*
	 * Null out mod_mp first, so consumers (debuggers) know not to look
	 * at the module structure any more.
	 */
	mutex_enter(&mod_lock);
	modp->mod_mp = NULL;
	mutex_exit(&mod_lock);

	kobj_notify(KOBJ_NOTIFY_MODUNLOADED, modp);
	free_module_data(mp);
}

static void
free_module_data(struct module *mp)
{
	struct module_list *lp, *tmp;
	int ksyms_exported = 0;

	lp = mp->head;
	while (lp) {
		tmp = lp;
		lp = lp->next;
		kobj_free((char *)tmp, sizeof (*tmp));
	}

	rw_enter(&ksyms_lock, RW_WRITER);
	if (mp->symspace) {
		if (vmem_contains(ksyms_arena, mp->symspace, mp->symsize)) {
			vmem_free(ksyms_arena, mp->symspace, mp->symsize);
			ksyms_exported = 1;
		} else {
			if (mp->flags & KOBJ_NOKSYMS)
				ksyms_exported = 1;
			kobj_free(mp->symspace, mp->symsize);
		}
	}
	rw_exit(&ksyms_lock);

	if (mp->ctfdata) {
		if (vmem_contains(ctf_arena, mp->ctfdata, mp->ctfsize))
			vmem_free(ctf_arena, mp->ctfdata, mp->ctfsize);
		else
			kobj_free(mp->ctfdata, mp->ctfsize);
	}

	if (mp->sigdata)
		kobj_free(mp->sigdata, mp->sigsize);

	/*
	 * We did not get far enough into kobj_export_ksyms() to free allocated
	 * buffers because we encounted error conditions. Free the buffers.
	 */
	if ((ksyms_exported == 0) && (mp->shdrs != NULL)) {
		uint_t shn;
		Shdr *shp;

		for (shn = 1; shn < mp->hdr.e_shnum; shn++) {
			shp = (Shdr *)(mp->shdrs + shn * mp->hdr.e_shentsize);
			switch (shp->sh_type) {
			case SHT_RELA:
			case SHT_REL:
				if (shp->sh_addr != 0)
					kobj_free((void *)shp->sh_addr,
					    shp->sh_size);
				break;
			}
		}
err_free_done:
		if (!(mp->flags & KOBJ_PRIM)) {
			kobj_free(mp->shdrs,
			    mp->hdr.e_shentsize * mp->hdr.e_shnum);
		}
	}

	if (mp->bss)
		vmem_free(data_arena, (void *)mp->bss, mp->bss_size);

	if (mp->fbt_tab)
		kobj_texthole_free(mp->fbt_tab, mp->fbt_size);

	if (mp->textwin_base)
		kobj_textwin_free(mp);

	if (mp->sdt_probes != NULL) {
		sdt_probedesc_t *sdp = mp->sdt_probes, *next;

		while (sdp != NULL) {
			next = sdp->sdpd_next;
			kobj_free(sdp->sdpd_name, strlen(sdp->sdpd_name) + 1);
			kobj_free(sdp, sizeof (sdt_probedesc_t));
			sdp = next;
		}
	}

	if (mp->sdt_tab)
		kobj_texthole_free(mp->sdt_tab, mp->sdt_size);
	if (mp->text)
		vmem_free(text_arena, mp->text, mp->text_size);
	if (mp->data)
		vmem_free(data_arena, mp->data, mp->data_size);
	if (mp->depends_on)
		kobj_free(mp->depends_on, strlen(mp->depends_on)+1);
	if (mp->filename)
		kobj_free(mp->filename, strlen(mp->filename)+1);

	kobj_free((char *)mp, sizeof (*mp));
}

static int
get_progbits(struct module *mp, struct _buf *file)
{
	struct proginfo *tp, *dp, *sdp;
	Shdr *shp;
	reloc_dest_t dest = NULL;
	uintptr_t bits_ptr;
	uintptr_t text = 0, data, textptr;
	uint_t shn;
	int err = -1;

	tp = kobj_zalloc(sizeof (struct proginfo), KM_WAIT|KM_TMP);
	dp = kobj_zalloc(sizeof (struct proginfo), KM_WAIT|KM_TMP);
	sdp = kobj_zalloc(sizeof (struct proginfo), KM_WAIT|KM_TMP);
	/*
	 * loop through sections to find out how much space we need
	 * for text, data, (also bss that is already assigned)
	 */
	if (get_progbits_size(mp, tp, dp, sdp) < 0)
		goto done;

	mp->text_size = tp->size;
	mp->data_size = dp->size;

	if (standalone) {
		caddr_t limit = _data;

		if (lg_pagesize && _text + lg_pagesize < limit)
			limit = _text + lg_pagesize;

		mp->text = kobj_segbrk(&_etext, mp->text_size,
		    tp->align, limit);
		/*
		 * If we can't grow the text segment, try the
		 * data segment before failing.
		 */
		if (mp->text == NULL) {
			mp->text = kobj_segbrk(&_edata, mp->text_size,
			    tp->align, 0);
		}

		mp->data = kobj_segbrk(&_edata, mp->data_size, dp->align, 0);

		if (mp->text == NULL || mp->data == NULL)
			goto done;

	} else {
		if (text_arena == NULL)
			kobj_vmem_init(&text_arena, &data_arena);

		/*
		 * some architectures may want to load the module on a
		 * page that is currently read only. It may not be
		 * possible for those architectures to remap their page
		 * on the fly. So we provide a facility for them to hang
		 * a private hook where the memory they assign the module
		 * is not the actual place where the module loads.
		 *
		 * In this case there are two addresses that deal with the
		 * modload.
		 * 1) the final destination of the module
		 * 2) the address that is used to view the newly
		 * loaded module until all the relocations relative to 1
		 * above are completed.
		 *
		 * That is what dest is used for below.
		 */
		mp->text_size += tp->align;
		mp->data_size += dp->align;

		mp->text = kobj_text_alloc(text_arena, mp->text_size);

		/*
		 * a remap is taking place. Align the text ptr relative
		 * to the secondary mapping. That is where the bits will
		 * be read in.
		 */
		if (kvseg.s_base != NULL && !vmem_contains(heaptext_arena,
		    mp->text, mp->text_size)) {
			off_t	off = (uintptr_t)mp->text & PAGEOFFSET;
			size_t	size = P2ROUNDUP(mp->text_size + off, PAGESIZE);
			caddr_t	map = vmem_alloc(heap_arena, size, VM_SLEEP);
			caddr_t orig = mp->text - off;
			pgcnt_t pages = size / PAGESIZE;

			dest = (reloc_dest_t)(map + off);
			text = ALIGN((uintptr_t)dest, tp->align);

			while (pages--) {
				hat_devload(kas.a_hat, map, PAGESIZE,
				    hat_getpfnum(kas.a_hat, orig),
				    PROT_READ | PROT_WRITE | PROT_EXEC,
				    HAT_LOAD_NOCONSIST | HAT_LOAD_LOCK);
				map += PAGESIZE;
				orig += PAGESIZE;
			}
			/*
			 * Since we set up a non-cacheable mapping, we need
			 * to flush any old entries in the cache that might
			 * be left around from the read-only mapping.
			 */
			dcache_flushall();
		}
		if (mp->data_size)
			mp->data = vmem_alloc(data_arena, mp->data_size,
			    VM_SLEEP | VM_BESTFIT);
	}
	textptr = (uintptr_t)mp->text;
	textptr = ALIGN(textptr, tp->align);
	mp->destination = dest;

	/*
	 * This is the case where a remap is not being done.
	 */
	if (text == 0)
		text = ALIGN((uintptr_t)mp->text, tp->align);
	data = ALIGN((uintptr_t)mp->data, dp->align);

	/* now loop though sections assigning addresses and loading the data */
	for (shn = 1; shn < mp->hdr.e_shnum; shn++) {
		shp = (Shdr *)(mp->shdrs + shn * mp->hdr.e_shentsize);
		if (!(shp->sh_flags & SHF_ALLOC))
			continue;

		if ((shp->sh_flags & SHF_WRITE) == 0)
			bits_ptr = text;
		else
			bits_ptr = data;

		bits_ptr = ALIGN(bits_ptr, shp->sh_addralign);

		if (shp->sh_type == SHT_NOBITS) {
			/*
			 * Zero bss.
			 */
			bzero((caddr_t)bits_ptr, shp->sh_size);
			shp->sh_type = SHT_PROGBITS;
		} else {
			if (kobj_read_file(file, (char *)bits_ptr,
			    shp->sh_size, shp->sh_offset) < 0)
				goto done;
		}

		if (shp->sh_flags & SHF_WRITE) {
			shp->sh_addr = bits_ptr;
		} else {
			textptr = ALIGN(textptr, shp->sh_addralign);
			shp->sh_addr = textptr;
			textptr += shp->sh_size;
		}

		bits_ptr += shp->sh_size;
		if ((shp->sh_flags & SHF_WRITE) == 0)
			text = bits_ptr;
		else
			data = bits_ptr;
	}

	err = 0;
done:
	/*
	 * Free and mark as freed the section headers here so that
	 * free_module_data() does not have to worry about this buffer.
	 *
	 * This buffer is freed here because one of the possible reasons
	 * for error is a section with non-zero sh_addr and in that case
	 * free_module_data() would have no way of recognizing that this
	 * buffer was unallocated.
	 */
	if (err != 0) {
		kobj_free(mp->shdrs, mp->hdr.e_shentsize * mp->hdr.e_shnum);
		mp->shdrs = NULL;
	}

	(void) kobj_free(tp, sizeof (struct proginfo));
	(void) kobj_free(dp, sizeof (struct proginfo));
	(void) kobj_free(sdp, sizeof (struct proginfo));

	return (err);
}

/*
 * Go through suppress_sym_list to see if "multiply defined"
 * warning of this symbol should be suppressed.  Return 1 if
 * warning should be suppressed, 0 otherwise.
 */
static int
kobj_suppress_warning(char *symname)
{
	int	i;

	for (i = 0; suppress_sym_list[i] != NULL; i++) {
		if (strcmp(suppress_sym_list[i], symname) == 0)
			return (1);
	}

	return (0);
}

static int
get_syms(struct module *mp, struct _buf *file)
{
	uint_t		shn;
	Shdr	*shp;
	uint_t		i;
	Sym	*sp, *ksp;
	char		*symname;
	int		dosymtab = 0;

	/*
	 * Find the interesting sections.
	 */
	for (shn = 1; shn < mp->hdr.e_shnum; shn++) {
		shp = (Shdr *)(mp->shdrs + shn * mp->hdr.e_shentsize);
		switch (shp->sh_type) {
		case SHT_SYMTAB:
			mp->symtbl_section = shn;
			mp->symhdr = shp;
			dosymtab++;
			break;

		case SHT_RELA:
		case SHT_REL:
			/*
			 * Already loaded.
			 */
			if (shp->sh_addr)
				continue;

			/* KM_TMP since kobj_free'd in do_relocations */
			shp->sh_addr = (Addr)
			    kobj_alloc(shp->sh_size, KM_WAIT|KM_TMP);

			if (kobj_read_file(file, (char *)shp->sh_addr,
			    shp->sh_size, shp->sh_offset) < 0) {
				_kobj_printf(ops, "krtld: get_syms: %s, ",
				    mp->filename);
				_kobj_printf(ops, "error reading section %d\n",
				    shn);
				return (-1);
			}
			break;
		}
	}

	/*
	 * This is true for a stripped executable.  In the case of
	 * 'unix' it can be stripped but it still contains the SHT_DYNSYM,
	 * and since that symbol information is still present everything
	 * is just fine.
	 */
	if (!dosymtab) {
		if (mp->flags & KOBJ_EXEC)
			return (0);
		_kobj_printf(ops, "krtld: get_syms: %s ",
		    mp->filename);
		_kobj_printf(ops, "no SHT_SYMTAB symbol table found\n");
		return (-1);
	}

	/*
	 * get the associated string table header
	 */
	if ((mp->symhdr == 0) || (mp->symhdr->sh_link >= mp->hdr.e_shnum))
		return (-1);
	mp->strhdr = (Shdr *)
	    (mp->shdrs + mp->symhdr->sh_link * mp->hdr.e_shentsize);

	mp->nsyms = mp->symhdr->sh_size / mp->symhdr->sh_entsize;
	mp->hashsize = kobj_gethashsize(mp->nsyms);

	/*
	 * Allocate space for the symbol table, buckets, chains, and strings.
	 */
	mp->symsize = mp->symhdr->sh_size +
	    (mp->hashsize + mp->nsyms) * sizeof (symid_t) + mp->strhdr->sh_size;
	mp->symspace = kobj_zalloc(mp->symsize, KM_WAIT|KM_SCRATCH);

	mp->symtbl = mp->symspace;
	mp->buckets = (symid_t *)(mp->symtbl + mp->symhdr->sh_size);
	mp->chains = mp->buckets + mp->hashsize;
	mp->strings = (char *)(mp->chains + mp->nsyms);

	if (kobj_read_file(file, mp->symtbl,
	    mp->symhdr->sh_size, mp->symhdr->sh_offset) < 0 ||
	    kobj_read_file(file, mp->strings,
	    mp->strhdr->sh_size, mp->strhdr->sh_offset) < 0)
		return (-1);

	/*
	 * loop through the symbol table adjusting values to account
	 * for where each section got loaded into memory.  Also
	 * fill in the hash table.
	 */
	for (i = 1; i < mp->nsyms; i++) {
		sp = (Sym *)(mp->symtbl + i * mp->symhdr->sh_entsize);
		if (sp->st_shndx < SHN_LORESERVE) {
			if (sp->st_shndx >= mp->hdr.e_shnum) {
				_kobj_printf(ops, "%s bad shndx ",
				    file->_name);
				_kobj_printf(ops, "in symbol %d\n", i);
				return (-1);
			}
			shp = (Shdr *)
			    (mp->shdrs +
			    sp->st_shndx * mp->hdr.e_shentsize);
			if (!(mp->flags & KOBJ_EXEC))
				sp->st_value += shp->sh_addr;
		}

		if (sp->st_name == 0 || sp->st_shndx == SHN_UNDEF)
			continue;
		if (sp->st_name >= mp->strhdr->sh_size)
			return (-1);

		symname = mp->strings + sp->st_name;

		if (!(mp->flags & KOBJ_EXEC) &&
		    ELF_ST_BIND(sp->st_info) == STB_GLOBAL) {
			ksp = kobj_lookup_all(mp, symname, 0);

			if (ksp && ELF_ST_BIND(ksp->st_info) == STB_GLOBAL &&
			    !kobj_suppress_warning(symname) &&
			    sp->st_shndx != SHN_UNDEF &&
			    sp->st_shndx != SHN_COMMON &&
			    ksp->st_shndx != SHN_UNDEF &&
			    ksp->st_shndx != SHN_COMMON) {
				/*
				 * Unless this symbol is a stub, it's multiply
				 * defined.  Multiply-defined symbols are
				 * usually bad, but some objects (kmdb) have
				 * a legitimate need to have their own
				 * copies of common functions.
				 */
				if ((standalone ||
				    ksp->st_value < (uintptr_t)stubs_base ||
				    ksp->st_value >= (uintptr_t)stubs_end) &&
				    !(mp->flags & KOBJ_IGNMULDEF)) {
					_kobj_printf(ops,
					    "%s symbol ", file->_name);
					_kobj_printf(ops,
					    "%s multiply defined\n", symname);
				}
			}
		}

		sym_insert(mp, symname, i);
	}

	return (0);
}

static int
get_ctf(struct module *mp, struct _buf *file)
{
	char *shstrtab, *ctfdata;
	size_t shstrlen;
	Shdr *shp;
	uint_t i;

	if (_moddebug & MODDEBUG_NOCTF)
		return (0); /* do not attempt to even load CTF data */

	if (mp->hdr.e_shstrndx >= mp->hdr.e_shnum) {
		_kobj_printf(ops, "krtld: get_ctf: %s, ",
		    mp->filename);
		_kobj_printf(ops, "corrupt e_shstrndx %u\n",
		    mp->hdr.e_shstrndx);
		return (-1);
	}

	shp = (Shdr *)(mp->shdrs + mp->hdr.e_shstrndx * mp->hdr.e_shentsize);
	shstrlen = shp->sh_size;
	shstrtab = kobj_alloc(shstrlen, KM_WAIT|KM_TMP);

	if (kobj_read_file(file, shstrtab, shstrlen, shp->sh_offset) < 0) {
		_kobj_printf(ops, "krtld: get_ctf: %s, ",
		    mp->filename);
		_kobj_printf(ops, "error reading section %u\n",
		    mp->hdr.e_shstrndx);
		kobj_free(shstrtab, shstrlen);
		return (-1);
	}

	for (i = 0; i < mp->hdr.e_shnum; i++) {
		shp = (Shdr *)(mp->shdrs + i * mp->hdr.e_shentsize);

		if (shp->sh_size != 0 && shp->sh_name < shstrlen &&
		    strcmp(shstrtab + shp->sh_name, ".SUNW_ctf") == 0) {
			ctfdata = kobj_alloc(shp->sh_size, KM_WAIT|KM_SCRATCH);

			if (kobj_read_file(file, ctfdata, shp->sh_size,
			    shp->sh_offset) < 0) {
				_kobj_printf(ops, "krtld: get_ctf: %s, error "
				    "reading .SUNW_ctf data\n", mp->filename);
				kobj_free(ctfdata, shp->sh_size);
				kobj_free(shstrtab, shstrlen);
				return (-1);
			}

			mp->ctfdata = ctfdata;
			mp->ctfsize = shp->sh_size;
			break;
		}
	}

	kobj_free(shstrtab, shstrlen);
	return (0);
}

#define	SHA1_DIGEST_LENGTH	20	/* SHA1 digest length in bytes */

/*
 * Return the hash of the ELF sections that are memory resident.
 * i.e. text and data.  We skip a SHT_NOBITS section since it occupies
 * no space in the file. We use SHA1 here since libelfsign uses
 * it and both places need to use the same algorithm.
 */
static void
crypto_es_hash(struct module *mp, char *hash, char *shstrtab)
{
	uint_t shn;
	Shdr *shp;
	SHA1_CTX ctx;

	SHA1Init(&ctx);

	for (shn = 1; shn < mp->hdr.e_shnum; shn++) {
		shp = (Shdr *)(mp->shdrs + shn * mp->hdr.e_shentsize);
		if (!(shp->sh_flags & SHF_ALLOC) || shp->sh_size == 0)
			continue;

		/*
		 * The check should ideally be shp->sh_type == SHT_NOBITS.
		 * However, we can't do that check here as get_progbits()
		 * resets the type.
		 */
		if (strcmp(shstrtab + shp->sh_name, ".bss") == 0)
			continue;
#ifdef	KOBJ_DEBUG
		if (kobj_debug & D_DEBUG)
			_kobj_printf(ops,
			    "krtld: crypto_es_hash: updating hash with"
			    " %s data size=%d\n", shstrtab + shp->sh_name,
			    shp->sh_size);
#endif
		ASSERT(shp->sh_addr != NULL);
		SHA1Update(&ctx, (const uint8_t *)shp->sh_addr, shp->sh_size);
	}

	SHA1Final((uchar_t *)hash, &ctx);
}

/*
 * Get the .SUNW_signature section for the module, it it exists.
 *
 * This section exists only for crypto modules. None of the
 * primary modules have this section currently.
 */
static void
get_signature(struct module *mp, struct _buf *file)
{
	char *shstrtab, *sigdata = NULL;
	size_t shstrlen;
	Shdr *shp;
	uint_t i;

	if (mp->hdr.e_shstrndx >= mp->hdr.e_shnum) {
		_kobj_printf(ops, "krtld: get_signature: %s, ",
		    mp->filename);
		_kobj_printf(ops, "corrupt e_shstrndx %u\n",
		    mp->hdr.e_shstrndx);
		return;
	}

	shp = (Shdr *)(mp->shdrs + mp->hdr.e_shstrndx * mp->hdr.e_shentsize);
	shstrlen = shp->sh_size;
	shstrtab = kobj_alloc(shstrlen, KM_WAIT|KM_TMP);

	if (kobj_read_file(file, shstrtab, shstrlen, shp->sh_offset) < 0) {
		_kobj_printf(ops, "krtld: get_signature: %s, ",
		    mp->filename);
		_kobj_printf(ops, "error reading section %u\n",
		    mp->hdr.e_shstrndx);
		kobj_free(shstrtab, shstrlen);
		return;
	}

	for (i = 0; i < mp->hdr.e_shnum; i++) {
		shp = (Shdr *)(mp->shdrs + i * mp->hdr.e_shentsize);
		if (shp->sh_size != 0 && shp->sh_name < shstrlen &&
		    strcmp(shstrtab + shp->sh_name,
		    ELF_SIGNATURE_SECTION) == 0) {
			filesig_vers_t filesig_version;
			size_t sigsize = shp->sh_size + SHA1_DIGEST_LENGTH;
			sigdata = kobj_alloc(sigsize, KM_WAIT|KM_SCRATCH);

			if (kobj_read_file(file, sigdata, shp->sh_size,
			    shp->sh_offset) < 0) {
				_kobj_printf(ops, "krtld: get_signature: %s,"
				    " error reading .SUNW_signature data\n",
				    mp->filename);
				kobj_free(sigdata, sigsize);
				kobj_free(shstrtab, shstrlen);
				return;
			}
			filesig_version = ((struct filesignatures *)sigdata)->
			    filesig_sig.filesig_version;
			if (!(filesig_version == FILESIG_VERSION1 ||
			    filesig_version == FILESIG_VERSION3)) {
				/* skip versions we don't understand */
				kobj_free(sigdata, sigsize);
				kobj_free(shstrtab, shstrlen);
				return;
			}

			mp->sigdata = sigdata;
			mp->sigsize = sigsize;
			break;
		}
	}

	if (sigdata != NULL) {
		crypto_es_hash(mp, sigdata + shp->sh_size, shstrtab);
	}

	kobj_free(shstrtab, shstrlen);
}

static void
add_dependent(struct module *mp, struct module *dep)
{
	struct module_list *lp;

	for (lp = mp->head; lp; lp = lp->next) {
		if (lp->mp == dep)
			return;	/* already on the list */
	}

	if (lp == NULL) {
		lp = kobj_zalloc(sizeof (*lp), KM_WAIT);

		lp->mp = dep;
		lp->next = NULL;
		if (mp->tail)
			mp->tail->next = lp;
		else
			mp->head = lp;
		mp->tail = lp;
	}
}

static int
do_dependents(struct modctl *modp, char *modname, size_t modnamelen)
{
	struct module *mp;
	struct modctl *req;
	char *d, *p, *q;
	int c;
	char *err_modname = NULL;

	mp = modp->mod_mp;

	if ((p = mp->depends_on) == NULL)
		return (0);

	for (;;) {
		/*
		 * Skip space.
		 */
		while (*p && (*p == ' ' || *p == '\t'))
			p++;
		/*
		 * Get module name.
		 */
		d = p;
		q = modname;
		c = 0;
		while (*p && *p != ' ' && *p != '\t') {
			if (c < modnamelen - 1) {
				*q++ = *p;
				c++;
			}
			p++;
		}

		if (q == modname)
			break;

		if (c == modnamelen - 1) {
			char *dep = kobj_alloc(p - d + 1, KM_WAIT|KM_TMP);

			(void) strncpy(dep, d,  p - d + 1);
			dep[p - d] = '\0';

			_kobj_printf(ops, "%s: dependency ", modp->mod_modname);
			_kobj_printf(ops, "'%s' too long ", dep);
			_kobj_printf(ops, "(max %d chars)\n", modnamelen);

			kobj_free(dep, p - d + 1);

			return (-1);
		}

		*q = '\0';
		if ((req = mod_load_requisite(modp, modname)) == NULL) {
#ifndef	KOBJ_DEBUG
			if (_moddebug & MODDEBUG_LOADMSG) {
#endif	/* KOBJ_DEBUG */
				_kobj_printf(ops,
				    "%s: unable to resolve dependency, ",
				    modp->mod_modname);
				_kobj_printf(ops, "cannot load module '%s'\n",
				    modname);
#ifndef	KOBJ_DEBUG
			}
#endif	/* KOBJ_DEBUG */
			if (err_modname == NULL) {
				/*
				 * This must be the same size as the modname
				 * one.
				 */
				err_modname = kobj_zalloc(MODMAXNAMELEN,
				    KM_WAIT);

				/*
				 * We can use strcpy() here without fearing
				 * the NULL terminator because the size of
				 * err_modname is the same as one of modname,
				 * and it's filled with zeros.
				 */
				(void) strcpy(err_modname, modname);
			}
			continue;
		}

		add_dependent(mp, req->mod_mp);
		mod_release_mod(req);

	}

	if (err_modname != NULL) {
		/*
		 * Copy the first module name where you detect an error to keep
		 * its behavior the same as before.
		 * This way keeps minimizing the memory use for error
		 * modules, and this might be important at boot time because
		 * the memory usage is a crucial factor for booting in most
		 * cases. You can expect more verbose messages when using
		 * a debug kernel or setting a bit in moddebug.
		 */
		bzero(modname, MODMAXNAMELEN);
		(void) strcpy(modname, err_modname);
		kobj_free(err_modname, MODMAXNAMELEN);
		return (-1);
	}

	return (0);
}

static int
do_common(struct module *mp)
{
	int err;

	/*
	 * first time through, assign all symbols defined in other
	 * modules, and count up how much common space will be needed
	 * (bss_size and bss_align)
	 */
	if ((err = do_symbols(mp, 0)) < 0)
		return (err);
	/*
	 * increase bss_size by the maximum delta that could be
	 * computed by the ALIGN below
	 */
	mp->bss_size += mp->bss_align;
	if (mp->bss_size) {
		if (standalone)
			mp->bss = (uintptr_t)kobj_segbrk(&_edata, mp->bss_size,
			    MINALIGN, 0);
		else
			mp->bss = (uintptr_t)vmem_alloc(data_arena,
			    mp->bss_size, VM_SLEEP | VM_BESTFIT);
		bzero((void *)mp->bss, mp->bss_size);
		/* now assign addresses to all common symbols */
		if ((err = do_symbols(mp, ALIGN(mp->bss, mp->bss_align))) < 0)
			return (err);
	}
	return (0);
}

static int
do_symbols(struct module *mp, Elf64_Addr bss_base)
{
	int bss_align;
	uintptr_t bss_ptr;
	int err;
	int i;
	Sym *sp, *sp1;
	char *name;
	int assign;
	int resolved = 1;

	/*
	 * Nothing left to do (optimization).
	 */
	if (mp->flags & KOBJ_RESOLVED)
		return (0);

	assign = (bss_base) ? 1 : 0;
	bss_ptr = bss_base;
	bss_align = 0;
	err = 0;

	for (i = 1; i < mp->nsyms; i++) {
		sp = (Sym *)(mp->symtbl + mp->symhdr->sh_entsize * i);
		/*
		 * we know that st_name is in bounds, since get_sections
		 * has already checked all of the symbols
		 */
		name = mp->strings + sp->st_name;
		if (sp->st_shndx != SHN_UNDEF && sp->st_shndx != SHN_COMMON)
			continue;
#if defined(__sparc)
		/*
		 * Register symbols are ignored in the kernel
		 */
		if (ELF_ST_TYPE(sp->st_info) == STT_SPARC_REGISTER) {
			if (*name != '\0') {
				_kobj_printf(ops, "%s: named REGISTER symbol ",
				    mp->filename);
				_kobj_printf(ops, "not supported '%s'\n",
				    name);
				err = DOSYM_UNDEF;
			}
			continue;
		}
#endif	/* __sparc */
		/*
		 * TLS symbols are ignored in the kernel
		 */
		if (ELF_ST_TYPE(sp->st_info) == STT_TLS) {
			_kobj_printf(ops, "%s: TLS symbol ",
			    mp->filename);
			_kobj_printf(ops, "not supported '%s'\n",
			    name);
			err = DOSYM_UNDEF;
			continue;
		}

		if (ELF_ST_BIND(sp->st_info) != STB_LOCAL) {
			if ((sp1 = kobj_lookup_all(mp, name, 0)) != NULL) {
				sp->st_shndx = SHN_ABS;
				sp->st_value = sp1->st_value;
				continue;
			}
		}

		if (sp->st_shndx == SHN_UNDEF) {
			resolved = 0;

			if (strncmp(name, sdt_prefix, strlen(sdt_prefix)) == 0)
				continue;

			/*
			 * If it's not a weak reference and it's
			 * not a primary object, it's an error.
			 * (Primary objects may take more than
			 * one pass to resolve)
			 */
			if (!(mp->flags & KOBJ_PRIM) &&
			    ELF_ST_BIND(sp->st_info) != STB_WEAK) {
				_kobj_printf(ops, "%s: undefined symbol",
				    mp->filename);
				_kobj_printf(ops, " '%s'\n", name);
				/*
				 * Try to determine whether this symbol
				 * represents a dependency on obsolete
				 * unsafe driver support.  This is just
				 * to make the warning more informative.
				 */
				if (strcmp(name, "sleep") == 0 ||
				    strcmp(name, "unsleep") == 0 ||
				    strcmp(name, "wakeup") == 0 ||
				    strcmp(name, "bsd_compat_ioctl") == 0 ||
				    strcmp(name, "unsafe_driver") == 0 ||
				    strncmp(name, "spl", 3) == 0 ||
				    strncmp(name, "i_ddi_spl", 9) == 0)
					err = DOSYM_UNSAFE;
				if (err == 0)
					err = DOSYM_UNDEF;
			}
			continue;
		}
		/*
		 * It's a common symbol - st_value is the
		 * required alignment.
		 */
		if (sp->st_value > bss_align)
			bss_align = sp->st_value;
		bss_ptr = ALIGN(bss_ptr, sp->st_value);
		if (assign) {
			sp->st_shndx = SHN_ABS;
			sp->st_value = bss_ptr;
		}
		bss_ptr += sp->st_size;
	}
	if (err)
		return (err);
	if (assign == 0 && mp->bss == NULL) {
		mp->bss_align = bss_align;
		mp->bss_size = bss_ptr;
	} else if (resolved) {
		mp->flags |= KOBJ_RESOLVED;
	}

	return (0);
}

uint_t
kobj_hash_name(const char *p)
{
	uint_t g;
	uint_t hval;

	hval = 0;
	while (*p) {
		hval = (hval << 4) + *p++;
		if ((g = (hval & 0xf0000000)) != 0)
			hval ^= g >> 24;
		hval &= ~g;
	}
	return (hval);
}

/* look for name in all modules */
uintptr_t
kobj_getsymvalue(char *name, int kernelonly)
{
	Sym		*sp;
	struct modctl	*modp;
	struct module	*mp;
	uintptr_t	value = 0;

	if ((sp = kobj_lookup_kernel(name)) != NULL)
		return ((uintptr_t)sp->st_value);

	if (kernelonly)
		return (0);	/* didn't find it in the kernel so give up */

	mutex_enter(&mod_lock);
	modp = &modules;
	do {
		mp = (struct module *)modp->mod_mp;
		if (mp && !(mp->flags & KOBJ_PRIM) && modp->mod_loaded &&
		    (sp = lookup_one(mp, name))) {
			value = (uintptr_t)sp->st_value;
			break;
		}
	} while ((modp = modp->mod_next) != &modules);
	mutex_exit(&mod_lock);
	return (value);
}

/* look for a symbol near value. */
char *
kobj_getsymname(uintptr_t value, ulong_t *offset)
{
	char *name = NULL;
	struct modctl *modp;

	struct modctl_list *lp;
	struct module *mp;

	/*
	 * Loop through the primary kernel modules.
	 */
	for (lp = kobj_lm_lookup(KOBJ_LM_PRIMARY); lp; lp = lp->modl_next) {
		mp = mod(lp);

		if ((name = kobj_searchsym(mp, value, offset)) != NULL)
			return (name);
	}

	mutex_enter(&mod_lock);
	modp = &modules;
	do {
		mp = (struct module *)modp->mod_mp;
		if (mp && !(mp->flags & KOBJ_PRIM) && modp->mod_loaded &&
		    (name = kobj_searchsym(mp, value, offset)))
			break;
	} while ((modp = modp->mod_next) != &modules);
	mutex_exit(&mod_lock);
	return (name);
}

/* return address of symbol and size */

uintptr_t
kobj_getelfsym(char *name, void *mp, int *size)
{
	Sym *sp;

	if (mp == NULL)
		sp = kobj_lookup_kernel(name);
	else
		sp = lookup_one(mp, name);

	if (sp == NULL)
		return (0);

	*size = (int)sp->st_size;
	return ((uintptr_t)sp->st_value);
}

uintptr_t
kobj_lookup(struct module *mod, const char *name)
{
	Sym *sp;

	sp = lookup_one(mod, name);

	if (sp == NULL)
		return (0);

	return ((uintptr_t)sp->st_value);
}

char *
kobj_searchsym(struct module *mp, uintptr_t value, ulong_t *offset)
{
	Sym *symtabptr;
	char *strtabptr;
	int symnum;
	Sym *sym;
	Sym *cursym;
	uintptr_t curval;

	*offset = (ulong_t)-1l;		/* assume not found */
	cursym  = NULL;

	if (kobj_addrcheck(mp, (void *)value) != 0)
		return (NULL);		/* not in this module */

	strtabptr  = mp->strings;
	symtabptr  = (Sym *)mp->symtbl;

	/*
	 * Scan the module's symbol table for a symbol <= value
	 */
	for (symnum = 1, sym = symtabptr + 1;
	    symnum < mp->nsyms; symnum++, sym = (Sym *)
	    ((uintptr_t)sym + mp->symhdr->sh_entsize)) {
		if (ELF_ST_BIND(sym->st_info) != STB_GLOBAL) {
			if (ELF_ST_BIND(sym->st_info) != STB_LOCAL)
				continue;
			if (ELF_ST_TYPE(sym->st_info) != STT_OBJECT &&
			    ELF_ST_TYPE(sym->st_info) != STT_FUNC)
				continue;
		}

		curval = (uintptr_t)sym->st_value;

		if (curval > value)
			continue;

		/*
		 * If one or both are functions...
		 */
		if (ELF_ST_TYPE(sym->st_info) == STT_FUNC || (cursym != NULL &&
		    ELF_ST_TYPE(cursym->st_info) == STT_FUNC)) {
			/* Ignore if the address is out of the bounds */
			if (value - sym->st_value >= sym->st_size)
				continue;

			if (cursym != NULL &&
			    ELF_ST_TYPE(cursym->st_info) == STT_FUNC) {
				/* Prefer the function to the non-function */
				if (ELF_ST_TYPE(sym->st_info) != STT_FUNC)
					continue;

				/* Prefer the larger of the two functions */
				if (sym->st_size <= cursym->st_size)
					continue;
			}
		} else if (value - curval >= *offset) {
			continue;
		}

		*offset = (ulong_t)(value - curval);
		cursym = sym;
	}
	if (cursym == NULL)
		return (NULL);

	return (strtabptr + cursym->st_name);
}

Sym *
kobj_lookup_all(struct module *mp, char *name, int include_self)
{
	Sym *sp;
	struct module_list *mlp;
	struct modctl_list *clp;
	struct module *mmp;

	if (include_self && (sp = lookup_one(mp, name)) != NULL)
		return (sp);

	for (mlp = mp->head; mlp; mlp = mlp->next) {
		if ((sp = lookup_one(mlp->mp, name)) != NULL &&
		    ELF_ST_BIND(sp->st_info) != STB_LOCAL)
			return (sp);
	}

	/*
	 * Loop through the primary kernel modules.
	 */
	for (clp = kobj_lm_lookup(KOBJ_LM_PRIMARY); clp; clp = clp->modl_next) {
		mmp = mod(clp);

		if (mmp == NULL || mp == mmp)
			continue;

		if ((sp = lookup_one(mmp, name)) != NULL &&
		    ELF_ST_BIND(sp->st_info) != STB_LOCAL)
			return (sp);
	}
	return (NULL);
}

Sym *
kobj_lookup_kernel(const char *name)
{
	struct modctl_list *lp;
	struct module *mp;
	Sym *sp;

	/*
	 * Loop through the primary kernel modules.
	 */
	for (lp = kobj_lm_lookup(KOBJ_LM_PRIMARY); lp; lp = lp->modl_next) {
		mp = mod(lp);

		if (mp == NULL)
			continue;

		if ((sp = lookup_one(mp, name)) != NULL)
			return (sp);
	}
	return (NULL);
}

static Sym *
lookup_one(struct module *mp, const char *name)
{
	symid_t *ip;
	char *name1;
	Sym *sp;

	for (ip = &mp->buckets[kobj_hash_name(name) % mp->hashsize]; *ip;
	    ip = &mp->chains[*ip]) {
		sp = (Sym *)(mp->symtbl +
		    mp->symhdr->sh_entsize * *ip);
		name1 = mp->strings + sp->st_name;
		if (strcmp(name, name1) == 0 &&
		    ELF_ST_TYPE(sp->st_info) != STT_FILE &&
		    sp->st_shndx != SHN_UNDEF &&
		    sp->st_shndx != SHN_COMMON)
			return (sp);
	}
	return (NULL);
}

/*
 * Lookup a given symbol pointer in the module's symbol hash.  If the symbol
 * is hashed, return the symbol pointer; otherwise return NULL.
 */
static Sym *
sym_lookup(struct module *mp, Sym *ksp)
{
	char *name = mp->strings + ksp->st_name;
	symid_t *ip;
	Sym *sp;

	for (ip = &mp->buckets[kobj_hash_name(name) % mp->hashsize]; *ip;
	    ip = &mp->chains[*ip]) {
		sp = (Sym *)(mp->symtbl + mp->symhdr->sh_entsize * *ip);
		if (sp == ksp)
			return (ksp);
	}
	return (NULL);
}

static void
sym_insert(struct module *mp, char *name, symid_t index)
{
	symid_t *ip;

#ifdef KOBJ_DEBUG
		if (kobj_debug & D_SYMBOLS) {
			static struct module *lastmp = NULL;
			Sym *sp;
			if (lastmp != mp) {
				_kobj_printf(ops,
				    "krtld: symbol entry: file=%s\n",
				    mp->filename);
				_kobj_printf(ops,
				    "krtld:\tsymndx\tvalue\t\t"
				    "symbol name\n");
				lastmp = mp;
			}
			sp = (Sym *)(mp->symtbl +
			    index * mp->symhdr->sh_entsize);
			_kobj_printf(ops, "krtld:\t[%3d]", index);
			_kobj_printf(ops, "\t0x%lx", sp->st_value);
			_kobj_printf(ops, "\t%s\n", name);
		}

#endif
	for (ip = &mp->buckets[kobj_hash_name(name) % mp->hashsize]; *ip;
	    ip = &mp->chains[*ip]) {
		;
	}
	*ip = index;
}

struct modctl *
kobj_boot_mod_lookup(const char *modname)
{
	struct modctl *mctl = kobj_modules;

	do {
		if (strcmp(modname, mctl->mod_modname) == 0)
			return (mctl);
	} while ((mctl = mctl->mod_next) != kobj_modules);

	return (NULL);
}

/*
 * Determine if the module exists.
 */
int
kobj_path_exists(char *name, int use_path)
{
	struct _buf *file;

	file = kobj_open_path(name, use_path, 1);
#ifdef	MODDIR_SUFFIX
	if (file == (struct _buf *)-1)
		file = kobj_open_path(name, use_path, 0);
#endif	/* MODDIR_SUFFIX */
	if (file == (struct _buf *)-1)
		return (0);
	kobj_close_file(file);
	return (1);
}

/*
 * fullname is dynamically allocated to be able to hold the
 * maximum size string that can be constructed from name.
 * path is exactly like the shell PATH variable.
 */
struct _buf *
kobj_open_path(char *name, int use_path, int use_moddir_suffix)
{
	char *p, *q;
	char *pathp;
	char *pathpsave;
	char *fullname;
	int maxpathlen;
	struct _buf *file;

#if !defined(MODDIR_SUFFIX)
	use_moddir_suffix = B_FALSE;
#endif

	if (!use_path)
		pathp = "";		/* use name as specified */
	else
		pathp = kobj_module_path;
					/* use configured default path */

	pathpsave = pathp;		/* keep this for error reporting */

	/*
	 * Allocate enough space for the largest possible fullname.
	 * since path is of the form <directory> : <directory> : ...
	 * we're potentially allocating a little more than we need to
	 * but we'll allocate the exact amount when we find the right directory.
	 * (The + 3 below is one for NULL terminator and one for the '/'
	 * we might have to add at the beginning of path and one for
	 * the '/' between path and name.)
	 */
	maxpathlen = strlen(pathp) + strlen(name) + 3;
	/* sizeof includes null */
	maxpathlen += sizeof (slash_moddir_suffix_slash) - 1;
	fullname = kobj_zalloc(maxpathlen, KM_WAIT);

	for (;;) {
		p = fullname;
		if (*pathp != '\0' && *pathp != '/')
			*p++ = '/';	/* path must start with '/' */
		while (*pathp && *pathp != ':' && *pathp != ' ')
			*p++ = *pathp++;
		if (p != fullname && p[-1] != '/')
			*p++ = '/';
		if (use_moddir_suffix) {
			char *b = basename(name);
			char *s;

			/* copy everything up to the base name */
			q = name;
			while (q != b && *q)
				*p++ = *q++;
			s = slash_moddir_suffix_slash;
			while (*s)
				*p++ = *s++;
			/* copy the rest */
			while (*b)
				*p++ = *b++;
		} else {
			q = name;
			while (*q)
				*p++ = *q++;
		}
		*p = 0;
		if ((file = kobj_open_file(fullname)) != (struct _buf *)-1) {
			kobj_free(fullname, maxpathlen);
			return (file);
		}
		while (*pathp == ' ' || *pathp == ':')
			pathp++;
		if (*pathp == 0)
			break;

	}
	kobj_free(fullname, maxpathlen);
	if (_moddebug & MODDEBUG_ERRMSG) {
		_kobj_printf(ops, "can't open %s,", name);
		_kobj_printf(ops, " path is %s\n", pathpsave);
	}
	return ((struct _buf *)-1);
}

intptr_t
kobj_open(char *filename)
{
	struct vnode *vp;
	int fd;

	if (_modrootloaded) {
		struct kobjopen_tctl *ltp = kobjopen_alloc(filename);
		int Errno;

		/*
		 * Hand off the open to a thread who has a
		 * stack size capable handling the request.
		 */
		if (curthread != &t0) {
			(void) thread_create(NULL, DEFAULTSTKSZ * 2,
			    kobjopen_thread, ltp, 0, &p0, TS_RUN, maxclsyspri);
			sema_p(&ltp->sema);
			Errno = ltp->Errno;
			vp = ltp->vp;
		} else {
			/*
			 * 1098067: module creds should not be those of the
			 * caller
			 */
			cred_t *saved_cred = curthread->t_cred;
			curthread->t_cred = kcred;
			Errno = vn_openat(filename, UIO_SYSSPACE, FREAD, 0, &vp,
			    0, 0, rootdir, -1);
			curthread->t_cred = saved_cred;
		}
		kobjopen_free(ltp);

		if (Errno) {
			if (_moddebug & MODDEBUG_ERRMSG) {
				_kobj_printf(ops,
				    "kobj_open: vn_open of %s fails, ",
				    filename);
				_kobj_printf(ops, "Errno = %d\n", Errno);
			}
			return (-1);
		} else {
			if (_moddebug & MODDEBUG_ERRMSG) {
				_kobj_printf(ops, "kobj_open: '%s'", filename);
				_kobj_printf(ops, " vp = %p\n", vp);
			}
			return ((intptr_t)vp);
		}
	} else {
		fd = kobj_boot_open(filename, 0);

		if (_moddebug & MODDEBUG_ERRMSG) {
			if (fd < 0)
				_kobj_printf(ops,
				    "kobj_open: can't open %s\n", filename);
			else {
				_kobj_printf(ops, "kobj_open: '%s'", filename);
				_kobj_printf(ops, " descr = 0x%x\n", fd);
			}
		}
		return ((intptr_t)fd);
	}
}

/*
 * Calls to kobj_open() are handled off to this routine as a separate thread.
 */
static void
kobjopen_thread(struct kobjopen_tctl *ltp)
{
	kmutex_t	cpr_lk;
	callb_cpr_t	cpr_i;

	mutex_init(&cpr_lk, NULL, MUTEX_DEFAULT, NULL);
	CALLB_CPR_INIT(&cpr_i, &cpr_lk, callb_generic_cpr, "kobjopen");
	ltp->Errno = vn_open(ltp->name, UIO_SYSSPACE, FREAD, 0, &(ltp->vp),
	    0, 0);
	sema_v(&ltp->sema);
	mutex_enter(&cpr_lk);
	CALLB_CPR_EXIT(&cpr_i);
	mutex_destroy(&cpr_lk);
	thread_exit();
}

/*
 * allocate and initialize a kobjopen thread structure
 */
static struct kobjopen_tctl *
kobjopen_alloc(char *filename)
{
	struct kobjopen_tctl *ltp = kmem_zalloc(sizeof (*ltp), KM_SLEEP);

	ASSERT(filename != NULL);

	ltp->name = kmem_alloc(strlen(filename) + 1, KM_SLEEP);
	bcopy(filename, ltp->name, strlen(filename) + 1);
	sema_init(&ltp->sema, 0, NULL, SEMA_DEFAULT, NULL);
	return (ltp);
}

/*
 * free a kobjopen thread control structure
 */
static void
kobjopen_free(struct kobjopen_tctl *ltp)
{
	sema_destroy(&ltp->sema);
	kmem_free(ltp->name, strlen(ltp->name) + 1);
	kmem_free(ltp, sizeof (*ltp));
}

int
kobj_read(intptr_t descr, char *buf, uint_t size, uint_t offset)
{
	int stat;
	ssize_t resid;

	if (_modrootloaded) {
		if ((stat = vn_rdwr(UIO_READ, (struct vnode *)descr, buf, size,
		    (offset_t)offset, UIO_SYSSPACE, 0, (rlim64_t)0, CRED(),
		    &resid)) != 0) {
			_kobj_printf(ops,
			    "vn_rdwr failed with error 0x%x\n", stat);
			return (-1);
		}
		return (size - resid);
	} else {
		int count = 0;

		if (kobj_boot_seek((int)descr, (off_t)0, offset) != 0) {
			_kobj_printf(ops,
			    "kobj_read: seek 0x%x failed\n", offset);
			return (-1);
		}

		count = kobj_boot_read((int)descr, buf, size);
		if (count < size) {
			if (_moddebug & MODDEBUG_ERRMSG) {
				_kobj_printf(ops,
				    "kobj_read: req %d bytes, ", size);
				_kobj_printf(ops, "got %d\n", count);
			}
		}
		return (count);
	}
}

void
kobj_close(intptr_t descr)
{
	if (_moddebug & MODDEBUG_ERRMSG)
		_kobj_printf(ops, "kobj_close: 0x%lx\n", descr);

	if (_modrootloaded) {
		struct vnode *vp = (struct vnode *)descr;
		(void) VOP_CLOSE(vp, FREAD, 1, (offset_t)0, CRED(), NULL);
		VN_RELE(vp);
	} else
		(void) kobj_boot_close((int)descr);
}

int
kobj_fstat(intptr_t descr, struct bootstat *buf)
{
	if (buf == NULL)
		return (-1);

	if (_modrootloaded) {
		vattr_t vattr;
		struct vnode *vp = (struct vnode *)descr;
		if (VOP_GETATTR(vp, &vattr, 0, kcred, NULL) != 0)
			return (-1);

		/*
		 * The vattr and bootstat structures are similar, but not
		 * identical.  We do our best to fill in the bootstat structure
		 * from the contents of vattr (transfering only the ones that
		 * are obvious.
		 */

		buf->st_mode = (uint32_t)vattr.va_mode;
		buf->st_nlink = (uint32_t)vattr.va_nlink;
		buf->st_uid = (int32_t)vattr.va_uid;
		buf->st_gid = (int32_t)vattr.va_gid;
		buf->st_rdev = (uint64_t)vattr.va_rdev;
		buf->st_size = (uint64_t)vattr.va_size;
		buf->st_atim.tv_sec = (int64_t)vattr.va_atime.tv_sec;
		buf->st_atim.tv_nsec = (int64_t)vattr.va_atime.tv_nsec;
		buf->st_mtim.tv_sec = (int64_t)vattr.va_mtime.tv_sec;
		buf->st_mtim.tv_nsec = (int64_t)vattr.va_mtime.tv_nsec;
		buf->st_ctim.tv_sec = (int64_t)vattr.va_ctime.tv_sec;
		buf->st_ctim.tv_nsec = (int64_t)vattr.va_ctime.tv_nsec;
		buf->st_blksize = (int32_t)vattr.va_blksize;
		buf->st_blocks = (int64_t)vattr.va_nblocks;

		return (0);
	}

	return (kobj_boot_fstat((int)descr, buf));
}


struct _buf *
kobj_open_file(char *name)
{
	struct _buf *file;
	struct compinfo cbuf;
	intptr_t fd;

	if ((fd = kobj_open(name)) == -1) {
		return ((struct _buf *)-1);
	}

	file = kobj_zalloc(sizeof (struct _buf), KM_WAIT|KM_TMP);
	file->_fd = fd;
	file->_name = kobj_alloc(strlen(name)+1, KM_WAIT|KM_TMP);
	file->_cnt = file->_size = file->_off = 0;
	file->_ln = 1;
	file->_ptr = file->_base;
	(void) strcpy(file->_name, name);

	/*
	 * Before root is mounted, we must check
	 * for a compressed file and do our own
	 * buffering.
	 */
	if (_modrootloaded) {
		file->_base = kobj_zalloc(MAXBSIZE, KM_WAIT);
		file->_bsize = MAXBSIZE;

		/* Check if the file is compressed */
		file->_iscmp = kobj_is_compressed(fd);
	} else {
		if (kobj_boot_compinfo(fd, &cbuf) != 0) {
			kobj_close_file(file);
			return ((struct _buf *)-1);
		}
		file->_iscmp = cbuf.iscmp;
		if (file->_iscmp) {
			if (kobj_comp_setup(file, &cbuf) != 0) {
				kobj_close_file(file);
				return ((struct _buf *)-1);
			}
		} else {
			file->_base = kobj_zalloc(cbuf.blksize, KM_WAIT|KM_TMP);
			file->_bsize = cbuf.blksize;
		}
	}
	return (file);
}

static int
kobj_comp_setup(struct _buf *file, struct compinfo *cip)
{
	struct comphdr *hdr;

	/*
	 * read the compressed image into memory,
	 * so we can deompress from there
	 */
	file->_dsize = cip->fsize;
	file->_dbuf = kobj_alloc(cip->fsize, KM_WAIT|KM_TMP);
	if (kobj_read(file->_fd, file->_dbuf, cip->fsize, 0) != cip->fsize) {
		kobj_free(file->_dbuf, cip->fsize);
		return (-1);
	}

	hdr = kobj_comphdr(file);
	if (hdr->ch_magic != CH_MAGIC_ZLIB || hdr->ch_version != CH_VERSION ||
	    hdr->ch_algorithm != CH_ALG_ZLIB || hdr->ch_fsize == 0 ||
	    !ISP2(hdr->ch_blksize)) {
		kobj_free(file->_dbuf, cip->fsize);
		return (-1);
	}
	file->_base = kobj_alloc(hdr->ch_blksize, KM_WAIT|KM_TMP);
	file->_bsize = hdr->ch_blksize;
	return (0);
}

void
kobj_close_file(struct _buf *file)
{
	kobj_close(file->_fd);
	if (file->_base != NULL)
		kobj_free(file->_base, file->_bsize);
	if (file->_dbuf != NULL)
		kobj_free(file->_dbuf, file->_dsize);
	kobj_free(file->_name, strlen(file->_name)+1);
	kobj_free(file, sizeof (struct _buf));
}

int
kobj_read_file(struct _buf *file, char *buf, uint_t size, uint_t off)
{
	int b_size, c_size;
	int b_off;	/* Offset into buffer for start of bcopy */
	int count = 0;
	int page_addr;

	if (_moddebug & MODDEBUG_ERRMSG) {
		_kobj_printf(ops, "kobj_read_file: size=%x,", size);
		_kobj_printf(ops, " offset=%x at", off);
		_kobj_printf(ops, " buf=%x\n", buf);
	}

	/*
	 * Handle compressed (gzip for now) file here. First get the
	 * compressed size, then read the image into memory and finally
	 * call zlib to decompress the image at the supplied memory buffer.
	 */
	if (file->_iscmp == CH_MAGIC_GZIP) {
		ulong_t dlen;
		vattr_t vattr;
		struct vnode *vp = (struct vnode *)file->_fd;
		ssize_t resid;
		int err = 0;

		if (VOP_GETATTR(vp, &vattr, 0, kcred, NULL) != 0)
			return (-1);

		file->_dbuf = kobj_alloc(vattr.va_size, KM_WAIT|KM_TMP);
		file->_dsize = vattr.va_size;

		/* Read the compressed file into memory */
		if ((err = vn_rdwr(UIO_READ, vp, file->_dbuf, vattr.va_size,
		    (offset_t)(0), UIO_SYSSPACE, 0, (rlim64_t)0, CRED(),
		    &resid)) != 0) {

			_kobj_printf(ops, "kobj_read_file :vn_rdwr() failed, "
			    "error code 0x%x\n", err);
			return (-1);
		}

		dlen = size;

		/* Decompress the image at the supplied memory buffer */
		if ((err = z_uncompress(buf, &dlen, file->_dbuf,
		    vattr.va_size)) != Z_OK) {
			_kobj_printf(ops, "kobj_read_file: z_uncompress "
			    "failed, error code : 0x%x\n", err);
			return (-1);
		}

		if (dlen != size) {
			_kobj_printf(ops, "kobj_read_file: z_uncompress "
			    "failed to uncompress (size returned 0x%x , "
			    "expected size: 0x%x)\n", dlen, size);
			return (-1);
		}

		return (0);
	}

	while (size) {
		page_addr = F_PAGE(file, off);
		b_size = file->_size;
		/*
		 * If we have the filesystem page the caller's referring to
		 * and we have something in the buffer,
		 * satisfy as much of the request from the buffer as we can.
		 */
		if (page_addr == file->_off && b_size > 0) {
			b_off = B_OFFSET(file, off);
			c_size = b_size - b_off;
			/*
			 * If there's nothing to copy, we're at EOF.
			 */
			if (c_size <= 0)
				break;
			if (c_size > size)
				c_size = size;
			if (buf) {
				if (_moddebug & MODDEBUG_ERRMSG)
					_kobj_printf(ops, "copying %x bytes\n",
					    c_size);
				bcopy(file->_base+b_off, buf, c_size);
				size -= c_size;
				off += c_size;
				buf += c_size;
				count += c_size;
			} else {
				_kobj_printf(ops, "kobj_read: system error");
				count = -1;
				break;
			}
		} else {
			/*
			 * If the caller's offset is page aligned and
			 * the caller want's at least a filesystem page and
			 * the caller provided a buffer,
			 * read directly into the caller's buffer.
			 */
			if (page_addr == off &&
			    (c_size = F_BLKS(file, size)) && buf) {
				c_size = kobj_read_blks(file, buf, c_size,
				    page_addr);
				if (c_size < 0) {
					count = -1;
					break;
				}
				count += c_size;
				if (c_size != F_BLKS(file, size))
					break;
				size -= c_size;
				off += c_size;
				buf += c_size;
			/*
			 * Otherwise, read into our buffer and copy next time
			 * around the loop.
			 */
			} else {
				file->_off = page_addr;
				c_size = kobj_read_blks(file, file->_base,
				    file->_bsize, page_addr);
				file->_ptr = file->_base;
				file->_cnt = c_size;
				file->_size = c_size;
				/*
				 * If a _filbuf call or nothing read, break.
				 */
				if (buf == NULL || c_size <= 0) {
					count = c_size;
					break;
				}
			}
			if (_moddebug & MODDEBUG_ERRMSG)
				_kobj_printf(ops, "read %x bytes\n", c_size);
		}
	}
	if (_moddebug & MODDEBUG_ERRMSG)
		_kobj_printf(ops, "count = %x\n", count);

	return (count);
}

static int
kobj_read_blks(struct _buf *file, char *buf, uint_t size, uint_t off)
{
	int ret;

	ASSERT(B_OFFSET(file, size) == 0 && B_OFFSET(file, off) == 0);
	if (file->_iscmp) {
		uint_t blks;
		int nret;

		ret = 0;
		for (blks = size / file->_bsize; blks != 0; blks--) {
			nret = kobj_uncomp_blk(file, buf, off);
			if (nret == -1)
				return (-1);
			buf += nret;
			off += nret;
			ret += nret;
			if (nret < file->_bsize)
				break;
		}
	} else
		ret = kobj_read(file->_fd, buf, size, off);
	return (ret);
}

static int
kobj_uncomp_blk(struct _buf *file, char *buf, uint_t off)
{
	struct comphdr *hdr = kobj_comphdr(file);
	ulong_t dlen, slen;
	caddr_t src;
	int i;

	dlen = file->_bsize;
	i = off / file->_bsize;
	src = file->_dbuf + hdr->ch_blkmap[i];
	if (i == hdr->ch_fsize / file->_bsize)
		slen = file->_dsize - hdr->ch_blkmap[i];
	else
		slen = hdr->ch_blkmap[i + 1] - hdr->ch_blkmap[i];
	if (z_uncompress(buf, &dlen, src, slen) != Z_OK)
		return (-1);
	return (dlen);
}

int
kobj_filbuf(struct _buf *f)
{
	if (kobj_read_file(f, NULL, f->_bsize, f->_off + f->_size) > 0)
		return (kobj_getc(f));
	return (-1);
}

void
kobj_free(void *address, size_t size)
{
	if (standalone)
		return;

	kmem_free(address, size);
	kobj_stat.nfree_calls++;
	kobj_stat.nfree += size;
}

void *
kobj_zalloc(size_t size, int flag)
{
	void *v;

	if ((v = kobj_alloc(size, flag)) != 0) {
		bzero(v, size);
	}

	return (v);
}

void *
kobj_alloc(size_t size, int flag)
{
	/*
	 * If we are running standalone in the
	 * linker, we ask boot for memory.
	 * Either it's temporary memory that we lose
	 * once boot is mapped out or we allocate it
	 * permanently using the dynamic data segment.
	 */
	if (standalone) {
#if defined(_OBP)
		if (flag & (KM_TMP | KM_SCRATCH))
			return (bop_temp_alloc(size, MINALIGN));
#else
		if (flag & (KM_TMP | KM_SCRATCH))
			return (BOP_ALLOC(ops, 0, size, MINALIGN));
#endif
		return (kobj_segbrk(&_edata, size, MINALIGN, 0));
	}

	kobj_stat.nalloc_calls++;
	kobj_stat.nalloc += size;

	return (kmem_alloc(size, (flag & KM_NOWAIT) ? KM_NOSLEEP : KM_SLEEP));
}

/*
 * Allow the "mod" system to sync up with the work
 * already done by kobj during the initial loading
 * of the kernel.  This also gives us a chance
 * to reallocate memory that belongs to boot.
 */
void
kobj_sync(void)
{
	struct modctl_list *lp, **lpp;

	/*
	 * The module path can be set in /etc/system via 'moddir' commands
	 */
	if (default_path != NULL)
		kobj_module_path = default_path;
	else
		default_path = kobj_module_path;

	ksyms_arena = vmem_create("ksyms", NULL, 0, sizeof (uint64_t),
	    segkmem_alloc, segkmem_free, heap_arena, 0, VM_SLEEP);

	ctf_arena = vmem_create("ctf", NULL, 0, sizeof (uint_t),
	    segkmem_alloc, segkmem_free, heap_arena, 0, VM_SLEEP);

	/*
	 * Move symbol tables from boot memory to ksyms_arena.
	 */
	for (lpp = kobj_linkmaps; *lpp != NULL; lpp++) {
		for (lp = *lpp; lp != NULL; lp = lp->modl_next)
			kobj_export_module(mod(lp));
	}
}

caddr_t
kobj_segbrk(caddr_t *spp, size_t size, size_t align, caddr_t limit)
{
	uintptr_t va, pva;
	size_t alloc_pgsz = kobj_mmu_pagesize;
	size_t alloc_align = BO_NO_ALIGN;
	size_t alloc_size;

	/*
	 * If we are using "large" mappings for the kernel,
	 * request aligned memory from boot using the
	 * "large" pagesize.
	 */
	if (lg_pagesize) {
		alloc_align = lg_pagesize;
		alloc_pgsz = lg_pagesize;
	}

#if defined(__sparc)
	/* account for redzone */
	if (limit)
		limit -= alloc_pgsz;
#endif	/* __sparc */

	va = ALIGN((uintptr_t)*spp, align);
	pva = P2ROUNDUP((uintptr_t)*spp, alloc_pgsz);
	/*
	 * Need more pages?
	 */
	if (va + size > pva) {
		uintptr_t npva;

		alloc_size = P2ROUNDUP(size - (pva - va), alloc_pgsz);
		/*
		 * Check for overlapping segments.
		 */
		if (limit && limit <= *spp + alloc_size) {
			return ((caddr_t)0);
		}

		npva = (uintptr_t)BOP_ALLOC(ops, (caddr_t)pva,
		    alloc_size, alloc_align);

		if (npva == NULL) {
			_kobj_printf(ops, "BOP_ALLOC failed, 0x%lx bytes",
			    alloc_size);
			_kobj_printf(ops, " aligned %lx", alloc_align);
			_kobj_printf(ops, " at 0x%lx\n", pva);
			return (NULL);
		}
	}
	*spp = (caddr_t)(va + size);

	return ((caddr_t)va);
}

/*
 * Calculate the number of output hash buckets.
 * We use the next prime larger than n / 4,
 * so the average hash chain is about 4 entries.
 * More buckets would just be a waste of memory.
 */
uint_t
kobj_gethashsize(uint_t n)
{
	int f;
	int hsize = MAX(n / 4, 2);

	for (f = 2; f * f <= hsize; f++)
		if (hsize % f == 0)
			hsize += f = 1;

	return (hsize);
}

/*
 * Get the file size.
 *
 * Before root is mounted, files are compressed in the boot_archive ramdisk
 * (in the memory). kobj_fstat would return the compressed file size.
 * In order to get the uncompressed file size, read the file to the end and
 * count its size.
 */
int
kobj_get_filesize(struct _buf *file, uint64_t *size)
{
	int err = 0;
	ssize_t resid;
	uint32_t buf;

	if (_modrootloaded) {
		struct bootstat bst;

		if (kobj_fstat(file->_fd, &bst) != 0)
			return (EIO);
		*size = bst.st_size;

		if (file->_iscmp == CH_MAGIC_GZIP) {
			/*
			 * Read the last 4 bytes of the compressed (gzip)
			 * image to get the size of its uncompressed
			 * version.
			 */
			if ((err = vn_rdwr(UIO_READ, (struct vnode *)file->_fd,
			    (char *)(&buf), 4, (offset_t)(*size - 4),
			    UIO_SYSSPACE, 0, (rlim64_t)0, CRED(), &resid))
			    != 0) {
				_kobj_printf(ops, "kobj_get_filesize: "
				    "vn_rdwr() failed with error 0x%x\n", err);
				return (-1);
			}

			*size =  (uint64_t)buf;
		}
	} else {

#if defined(_OBP)
		struct bootstat bsb;

		if (file->_iscmp) {
			struct comphdr *hdr = kobj_comphdr(file);

			*size = hdr->ch_fsize;
		} else if (kobj_boot_fstat(file->_fd, &bsb) != 0)
			return (EIO);
		else
			*size = bsb.st_size;
#else
		char *buf;
		int count;
		uint64_t offset = 0;

		buf = kmem_alloc(MAXBSIZE, KM_SLEEP);
		do {
			count = kobj_read_file(file, buf, MAXBSIZE, offset);
			if (count < 0) {
				kmem_free(buf, MAXBSIZE);
				return (EIO);
			}
			offset += count;
		} while (count == MAXBSIZE);
		kmem_free(buf, MAXBSIZE);

		*size = offset;
#endif
	}

	return (0);
}

static char *
basename(char *s)
{
	char *p, *q;

	q = NULL;
	p = s;
	do {
		if (*p == '/')
			q = p;
	} while (*p++);
	return (q ? q + 1 : s);
}

void
kobj_stat_get(kobj_stat_t *kp)
{
	*kp = kobj_stat;
}

int
kobj_getpagesize()
{
	return (lg_pagesize);
}

void
kobj_textwin_alloc(struct module *mp)
{
	ASSERT(MUTEX_HELD(&mod_lock));

	if (mp->textwin != NULL)
		return;

	/*
	 * If the text is not contained in the heap, then it is not contained
	 * by a writable mapping.  (Specifically, it's on the nucleus page.)
	 * We allocate a read/write mapping for this module's text to allow
	 * the text to be patched without calling hot_patch_kernel_text()
	 * (which is quite slow).
	 */
	if (!vmem_contains(heaptext_arena, mp->text, mp->text_size)) {
		uintptr_t text = (uintptr_t)mp->text;
		uintptr_t size = (uintptr_t)mp->text_size;
		uintptr_t i;
		caddr_t va;
		size_t sz = ((text + size + PAGESIZE - 1) & PAGEMASK) -
		    (text & PAGEMASK);

		va = mp->textwin_base = vmem_alloc(heap_arena, sz, VM_SLEEP);

		for (i = text & PAGEMASK; i < text + size; i += PAGESIZE) {
			hat_devload(kas.a_hat, va, PAGESIZE,
			    hat_getpfnum(kas.a_hat, (caddr_t)i),
			    PROT_READ | PROT_WRITE,
			    HAT_LOAD_LOCK | HAT_LOAD_NOCONSIST);
			va += PAGESIZE;
		}

		mp->textwin = mp->textwin_base + (text & PAGEOFFSET);
	} else {
		mp->textwin = mp->text;
	}
}

void
kobj_textwin_free(struct module *mp)
{
	uintptr_t text = (uintptr_t)mp->text;
	uintptr_t tsize = (uintptr_t)mp->text_size;
	size_t size = (((text + tsize + PAGESIZE - 1) & PAGEMASK) -
	    (text & PAGEMASK));

	mp->textwin = NULL;

	if (mp->textwin_base == NULL)
		return;

	hat_unload(kas.a_hat, mp->textwin_base, size, HAT_UNLOAD_UNLOCK);
	vmem_free(heap_arena, mp->textwin_base, size);
	mp->textwin_base = NULL;
}

static char *
find_libmacro(char *name)
{
	int lmi;

	for (lmi = 0; lmi < NLIBMACROS; lmi++) {
		if (strcmp(name, libmacros[lmi].lmi_macroname) == 0)
			return (libmacros[lmi].lmi_list);
	}
	return (NULL);
}

/*
 * Check for $MACRO in tail (string to expand) and expand it in path at pathend
 * returns path if successful, else NULL
 * Support multiple $MACROs expansion and the first valid path will be returned
 * Caller's responsibility to provide enough space in path to expand
 */
char *
expand_libmacro(char *tail, char *path, char *pathend)
{
	char c, *p, *p1, *p2, *path2, *endp;
	int diff, lmi, macrolen, valid_macro, more_macro;
	struct _buf *file;

	/*
	 * check for $MACROS between nulls or slashes
	 */
	p = strchr(tail, '$');
	if (p == NULL)
		return (NULL);
	for (lmi = 0; lmi < NLIBMACROS; lmi++) {
		macrolen = libmacros[lmi].lmi_macrolen;
		if (strncmp(p + 1, libmacros[lmi].lmi_macroname, macrolen) == 0)
			break;
	}

	valid_macro = 0;
	if (lmi < NLIBMACROS) {
		/*
		 * The following checks are used to restrict expansion of
		 * macros to those that form a full directory/file name
		 * and to keep the behavior same as before.  If this
		 * restriction is removed or no longer valid in the future,
		 * the checks below can be deleted.
		 */
		if ((p == tail) || (*(p - 1) == '/')) {
			c = *(p + macrolen + 1);
			if (c == '/' || c == '\0')
				valid_macro = 1;
		}
	}

	if (!valid_macro) {
		p2 = strchr(p, '/');
		/*
		 * if no more macro to expand, then just copy whatever left
		 * and check whether it exists
		 */
		if (p2 == NULL || strchr(p2, '$') == NULL) {
			(void) strcpy(pathend, tail);
			if ((file = kobj_open_path(path, 1, 1)) !=
			    (struct _buf *)-1) {
				kobj_close_file(file);
				return (path);
			} else
				return (NULL);
		} else {
			/*
			 * copy all chars before '/' and call expand_libmacro()
			 * again
			 */
			diff = p2 - tail;
			bcopy(tail, pathend, diff);
			pathend += diff;
			*(pathend) = '\0';
			return (expand_libmacro(p2, path, pathend));
		}
	}

	more_macro = 0;
	if (c != '\0') {
		endp = p + macrolen + 1;
		if (strchr(endp, '$') != NULL)
			more_macro = 1;
	} else
		endp = NULL;

	/*
	 * copy lmi_list and split it into components.
	 * then put the part of tail before $MACRO into path
	 * at pathend
	 */
	diff = p - tail;
	if (diff > 0)
		bcopy(tail, pathend, diff);
	path2 = pathend + diff;
	p1 = libmacros[lmi].lmi_list;
	while (p1 && (*p1 != '\0')) {
		p2 = strchr(p1, ':');
		if (p2) {
			diff = p2 - p1;
			bcopy(p1, path2, diff);
			*(path2 + diff) = '\0';
		} else {
			diff = strlen(p1);
			bcopy(p1, path2, diff + 1);
		}
		/* copy endp only if there isn't any more macro to expand */
		if (!more_macro && (endp != NULL))
			(void) strcat(path2, endp);
		file = kobj_open_path(path, 1, 1);
		if (file != (struct _buf *)-1) {
			kobj_close_file(file);
			/*
			 * if more macros to expand then call expand_libmacro(),
			 * else return path which has the whole path
			 */
			if (!more_macro || (expand_libmacro(endp, path,
			    path2 + diff) != NULL)) {
				return (path);
			}
		}
		if (p2)
			p1 = ++p2;
		else
			return (NULL);
	}
	return (NULL);
}

static void
tnf_add_notifyunload(kobj_notify_f *fp)
{
	kobj_notify_list_t *entry;

	entry = kobj_alloc(sizeof (kobj_notify_list_t), KM_WAIT);
	entry->kn_type = KOBJ_NOTIFY_MODUNLOADING;
	entry->kn_func = fp;
	(void) kobj_notify_add(entry);
}

/* ARGSUSED */
static void
tnf_unsplice_probes(uint_t what, struct modctl *mod)
{
	tnf_probe_control_t **p;
	tnf_tag_data_t **q;
	struct module *mp = mod->mod_mp;

	if (!(mp->flags & KOBJ_TNF_PROBE))
		return;

	for (p = &__tnf_probe_list_head; *p; )
		if (kobj_addrcheck(mp, (char *)*p) == 0)
			*p = (*p)->next;
		else
			p = &(*p)->next;

	for (q = &__tnf_tag_list_head; *q; )
		if (kobj_addrcheck(mp, (char *)*q) == 0)
			*q = (tnf_tag_data_t *)(*q)->tag_version;
		else
			q = (tnf_tag_data_t **)&(*q)->tag_version;

	tnf_changed_probe_list = 1;
}

int
tnf_splice_probes(int boot_load, tnf_probe_control_t *plist,
    tnf_tag_data_t *tlist)
{
	int result = 0;
	static int add_notify = 1;

	if (plist) {
		tnf_probe_control_t *pl;

		for (pl = plist; pl->next; )
			pl = pl->next;

		if (!boot_load)
			mutex_enter(&mod_lock);
		tnf_changed_probe_list = 1;
		pl->next = __tnf_probe_list_head;
		__tnf_probe_list_head = plist;
		if (!boot_load)
			mutex_exit(&mod_lock);
		result = 1;
	}

	if (tlist) {
		tnf_tag_data_t *tl;

		for (tl = tlist; tl->tag_version; )
			tl = (tnf_tag_data_t *)tl->tag_version;

		if (!boot_load)
			mutex_enter(&mod_lock);
		tl->tag_version = (tnf_tag_version_t *)__tnf_tag_list_head;
		__tnf_tag_list_head = tlist;
		if (!boot_load)
			mutex_exit(&mod_lock);
		result = 1;
	}
	if (!boot_load && result && add_notify) {
		tnf_add_notifyunload(tnf_unsplice_probes);
		add_notify = 0;
	}
	return (result);
}

char *kobj_file_buf;
int kobj_file_bufsize;

/*
 * This code is for the purpose of manually recording which files
 * needs to go into the boot archive on any given system.
 *
 * To enable the code, set kobj_file_bufsize in /etc/system
 * and reboot the system, then use mdb to look at kobj_file_buf.
 */
static void
kobj_record_file(char *filename)
{
	static char *buf;
	static int size = 0;
	int n;

	if (kobj_file_bufsize == 0)	/* don't bother */
		return;

	if (kobj_file_buf == NULL) {	/* allocate buffer */
		size = kobj_file_bufsize;
		buf = kobj_file_buf = kobj_alloc(size, KM_WAIT|KM_TMP);
	}

	n = snprintf(buf, size, "%s\n", filename);
	if (n > size)
		n = size;
	size -= n;
	buf += n;
}

static int
kobj_boot_fstat(int fd, struct bootstat *stp)
{
#if defined(_OBP)
	if (!standalone && _ioquiesced)
		return (-1);
	return (BOP_FSTAT(ops, fd, stp));
#else
	return (BRD_FSTAT(bfs_ops, fd, stp));
#endif
}

static int
kobj_boot_open(char *filename, int flags)
{
#if defined(_OBP)

	/*
	 * If io via bootops is quiesced, it means boot is no longer
	 * available to us.  We make it look as if we can't open the
	 * named file - which is reasonably accurate.
	 */
	if (!standalone && _ioquiesced)
		return (-1);

	kobj_record_file(filename);
	return (BOP_OPEN(filename, flags));
#else /* x86 */
	kobj_record_file(filename);
	return (BRD_OPEN(bfs_ops, filename, flags));
#endif
}

static int
kobj_boot_close(int fd)
{
#if defined(_OBP)
	if (!standalone && _ioquiesced)
		return (-1);

	return (BOP_CLOSE(fd));
#else /* x86 */
	return (BRD_CLOSE(bfs_ops, fd));
#endif
}

/*ARGSUSED*/
static int
kobj_boot_seek(int fd, off_t hi, off_t lo)
{
#if defined(_OBP)
	return (BOP_SEEK(fd, lo) == -1 ? -1 : 0);
#else
	return (BRD_SEEK(bfs_ops, fd, lo, SEEK_SET));
#endif
}

static int
kobj_boot_read(int fd, caddr_t buf, size_t size)
{
#if defined(_OBP)
	return (BOP_READ(fd, buf, size));
#else
	return (BRD_READ(bfs_ops, fd, buf, size));
#endif
}

static int
kobj_boot_compinfo(int fd, struct compinfo *cb)
{
	return (boot_compinfo(fd, cb));
}

/*
 * Check if the file is compressed (for now we handle only gzip).
 * It returns CH_MAGIC_GZIP if the file is compressed and 0 otherwise.
 */
static int
kobj_is_compressed(intptr_t fd)
{
	struct vnode *vp = (struct vnode *)fd;
	ssize_t resid;
	uint16_t magic_buf;
	int err = 0;

	if ((err = vn_rdwr(UIO_READ, vp, (caddr_t)((intptr_t)&magic_buf),
	    sizeof (magic_buf), (offset_t)(0),
	    UIO_SYSSPACE, 0, (rlim64_t)0, CRED(), &resid)) != 0) {

		_kobj_printf(ops, "kobj_is_compressed: vn_rdwr() failed, "
		    "error code 0x%x\n", err);
		return (0);
	}

	if (magic_buf == CH_MAGIC_GZIP)
		return (CH_MAGIC_GZIP);

	return (0);
}
