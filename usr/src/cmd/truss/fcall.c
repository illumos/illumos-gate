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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#define	_SYSCALL32

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stack.h>
#include <signal.h>
#include <limits.h>
#include <sys/isa_defs.h>
#include <proc_service.h>
#include <dlfcn.h>
#include <fnmatch.h>
#include <libproc.h>
#include "ramdata.h"
#include "systable.h"
#include "print.h"
#include "proto.h"
#include "htbl.h"

/*
 * Functions supporting library function call tracing.
 */

typedef struct {
	prmap_t	*pmap;
	int	nmap;
} ph_map_t;

/*
 * static functions in this file.
 */
void function_entry(private_t *, struct bkpt *, struct callstack *);
void function_return(private_t *, struct callstack *);
int object_iter(void *, const prmap_t *, const char *);
int object_present(void *, const prmap_t *, const char *);
int symbol_iter(void *, const GElf_Sym *, const char *);
uintptr_t get_return_address(uintptr_t *);
int get_arguments(long *argp);
uintptr_t previous_fp(uintptr_t, uintptr_t *);
int lwp_stack_traps(void *cd, const lwpstatus_t *Lsp);
int thr_stack_traps(const td_thrhandle_t *Thp, void *cd);
struct bkpt *create_bkpt(uintptr_t, int, int);
void set_deferred_breakpoints(void);

#define	DEF_MAXCALL	16	/* initial value of Stk->maxcall */

#define	FAULT_ADDR	((uintptr_t)(0-8))

#define	HASHSZ	2048
#define	bpt_hash(addr)	((((addr) >> 13) ^ ((addr) >> 2)) & 0x7ff)

static void
setup_thread_agent(void)
{
	struct bkpt *Bp;
	td_notify_t notify;
	td_thr_events_t events;

	if (Thr_agent != NULL)	/* only once */
		return;
	if (td_init() != TD_OK || td_ta_new(Proc, &Thr_agent) != TD_OK)
		Thr_agent = NULL;
	else {
		td_event_emptyset(&events);
		td_event_addset(&events, TD_CREATE);
		if (td_ta_event_addr(Thr_agent, TD_CREATE, &notify) == TD_OK &&
		    notify.type == NOTIFY_BPT &&
		    td_ta_set_event(Thr_agent, &events) == TD_OK &&
		    (Bp = create_bkpt(notify.u.bptaddr, 0, 1)) != NULL)
			Bp->flags |= BPT_TD_CREATE;
	}
}

/*
 * Delete all breakpoints in the range [base .. base+size)
 * from the breakpoint hash table.
 */
static void
delete_breakpoints(uintptr_t base, size_t size)
{
	struct bkpt **Bpp;
	struct bkpt *Bp;
	int i;

	if (bpt_hashtable == NULL)
		return;
	for (i = 0; i < HASHSZ; i++) {
		Bpp = &bpt_hashtable[i];
		while ((Bp = *Bpp) != NULL) {
			if (Bp->addr < base || Bp->addr >= base + size) {
				Bpp = &Bp->next;
				continue;
			}
			*Bpp = Bp->next;
			if (Bp->sym_name)
				free(Bp->sym_name);
			free(Bp);
		}
	}
}

/*
 * Establishment of breakpoints on traced library functions.
 */
void
establish_breakpoints(void)
{
	if (Dynpat == NULL)
		return;

	/* allocate the breakpoint hash table */
	if (bpt_hashtable == NULL) {
		bpt_hashtable = my_malloc(HASHSZ * sizeof (struct bkpt *),
		    NULL);
		(void) memset(bpt_hashtable, 0,
		    HASHSZ * sizeof (struct bkpt *));
	}

	/*
	 * Set special rtld_db event breakpoints, first time only.
	 */
	if (Rdb_agent == NULL &&
	    (Rdb_agent = Prd_agent(Proc)) != NULL) {
		rd_notify_t notify;
		struct bkpt *Bp;

		(void) rd_event_enable(Rdb_agent, 1);
		if (rd_event_addr(Rdb_agent, RD_PREINIT, &notify) == RD_OK &&
		    (Bp = create_bkpt(notify.u.bptaddr, 0, 1)) != NULL)
			Bp->flags |= BPT_PREINIT;
		if (rd_event_addr(Rdb_agent, RD_POSTINIT, &notify) == RD_OK &&
		    (Bp = create_bkpt(notify.u.bptaddr, 0, 1)) != NULL)
			Bp->flags |= BPT_POSTINIT;
		if (rd_event_addr(Rdb_agent, RD_DLACTIVITY, &notify) == RD_OK &&
		    (Bp = create_bkpt(notify.u.bptaddr, 0, 1)) != NULL)
			Bp->flags |= BPT_DLACTIVITY;
	}

	/*
	 * Set special thread event breakpoint, first time libc is seen.
	 */
	if (Thr_agent == NULL)
		setup_thread_agent();

	/*
	 * Tell libproc to update its mappings.
	 */
	Pupdate_maps(Proc);

	/*
	 * If rtld_db told us a library was being deleted,
	 * first mark all of the dynlibs as not present, then
	 * iterate over the shared objects, marking only those
	 * present that really are present, and finally delete
	 * all of the not-present dynlibs.
	 */
	if (delete_library) {
		struct dynlib **Dpp;
		struct dynlib *Dp;

		for (Dp = Dynlib; Dp != NULL; Dp = Dp->next)
			Dp->present = FALSE;
		(void) Pobject_iter(Proc, object_present, NULL);
		Dpp = &Dynlib;
		while ((Dp = *Dpp) != NULL) {
			if (Dp->present) {
				Dpp = &Dp->next;
				continue;
			}
			delete_breakpoints(Dp->base, Dp->size);
			*Dpp = Dp->next;
			free(Dp->lib_name);
			free(Dp->match_name);
			free(Dp->prt_name);
			free(Dp);
		}
		delete_library = FALSE;
	}

	/*
	 * Iterate over the shared objects, creating breakpoints.
	 */
	(void) Pobject_iter(Proc, object_iter, NULL);

	/*
	 * Now actually set all the breakpoints we just created.
	 */
	set_deferred_breakpoints();
}

/*
 * Initial establishment of stacks in a newly-grabbed process.
 * establish_breakpoints() has already been called.
 */
void
establish_stacks(void)
{
	const pstatus_t *Psp = Pstatus(Proc);
	char mapfile[64];
	int mapfd;
	struct stat statb;
	prmap_t *Pmap = NULL;
	int nmap = 0;
	ph_map_t ph_map;

	(void) sprintf(mapfile, "/proc/%d/rmap", (int)Psp->pr_pid);
	if ((mapfd = open(mapfile, O_RDONLY)) < 0 ||
	    fstat(mapfd, &statb) != 0 ||
	    statb.st_size < sizeof (prmap_t) ||
	    (Pmap = my_malloc(statb.st_size, NULL)) == NULL ||
	    (nmap = pread(mapfd, Pmap, statb.st_size, 0L)) <= 0 ||
	    (nmap /= sizeof (prmap_t)) == 0) {
		if (Pmap != NULL)
			free(Pmap);
		Pmap = NULL;
		nmap = 0;
	}
	if (mapfd >= 0)
		(void) close(mapfd);

	/*
	 * Iterate over lwps, establishing stacks.
	 */
	ph_map.pmap = Pmap;
	ph_map.nmap = nmap;
	(void) Plwp_iter(Proc, lwp_stack_traps, &ph_map);
	if (Pmap != NULL)
		free(Pmap);

	if (Thr_agent == NULL)
		return;

	/*
	 * Iterate over unbound threads, establishing stacks.
	 */
	(void) td_ta_thr_iter(Thr_agent, thr_stack_traps, NULL,
	    TD_THR_ANY_STATE, TD_THR_LOWEST_PRIORITY,
	    TD_SIGNO_MASK, TD_THR_ANY_USER_FLAGS);
}

void
do_symbol_iter(const char *object_name, struct dynpat *Dyp)
{
	if (*Dyp->Dp->prt_name == '\0')
		object_name = PR_OBJ_EXEC;

	/*
	 * Always search the dynamic symbol table.
	 */
	(void) Psymbol_iter(Proc, object_name,
	    PR_DYNSYM, BIND_WEAK|BIND_GLOBAL|TYPE_FUNC,
	    symbol_iter, Dyp);

	/*
	 * Search the static symbol table if this is the
	 * executable file or if we are being asked to
	 * report internal calls within the library.
	 */
	if (object_name == PR_OBJ_EXEC || Dyp->internal)
		(void) Psymbol_iter(Proc, object_name,
		    PR_SYMTAB, BIND_ANY|TYPE_FUNC,
		    symbol_iter, Dyp);
}

/* ARGSUSED */
int
object_iter(void *cd, const prmap_t *pmp, const char *object_name)
{
	char name[100];
	struct dynpat *Dyp;
	struct dynlib *Dp;
	const char *str;
	char *s;
	int i;

	if ((pmp->pr_mflags & MA_WRITE) || !(pmp->pr_mflags & MA_EXEC))
		return (0);

	/*
	 * Set special thread event breakpoint, first time libc is seen.
	 */
	if (Thr_agent == NULL && strstr(object_name, "/libc.so.") != NULL)
		setup_thread_agent();

	for (Dp = Dynlib; Dp != NULL; Dp = Dp->next)
		if (strcmp(object_name, Dp->lib_name) == 0 ||
		    (strcmp(Dp->lib_name, "a.out") == 0 &&
		    strcmp(pmp->pr_mapname, "a.out") == 0))
			break;

	if (Dp == NULL) {
		Dp = my_malloc(sizeof (struct dynlib), NULL);
		(void) memset(Dp, 0, sizeof (struct dynlib));
		if (strcmp(pmp->pr_mapname, "a.out") == 0) {
			Dp->lib_name = strdup(pmp->pr_mapname);
			Dp->match_name = strdup(pmp->pr_mapname);
			Dp->prt_name = strdup("");
		} else {
			Dp->lib_name = strdup(object_name);
			if ((str = strrchr(object_name, '/')) != NULL)
				str++;
			else
				str = object_name;
			(void) strncpy(name, str, sizeof (name) - 2);
			name[sizeof (name) - 2] = '\0';
			if ((s = strstr(name, ".so")) != NULL)
				*s = '\0';
			Dp->match_name = strdup(name);
			(void) strcat(name, ":");
			Dp->prt_name = strdup(name);
		}
		Dp->next = Dynlib;
		Dynlib = Dp;
	}

	if (Dp->built ||
	    (not_consist && strcmp(Dp->prt_name, "ld:") != 0))	/* kludge */
		return (0);

	if (hflag && not_consist)
		(void) fprintf(stderr, "not_consist is TRUE, building %s\n",
		    Dp->lib_name);

	Dp->base = pmp->pr_vaddr;
	Dp->size = pmp->pr_size;

	/*
	 * For every dynlib pattern that matches this library's name,
	 * iterate through all of the library's symbols looking for
	 * matching symbol name patterns.
	 */
	for (Dyp = Dynpat; Dyp != NULL; Dyp = Dyp->next) {
		if (interrupt|sigusr1)
			break;
		for (i = 0; i < Dyp->nlibpat; i++) {
			if (interrupt|sigusr1)
				break;
			if (fnmatch(Dyp->libpat[i], Dp->match_name, 0) != 0)
				continue;	/* no match */

			/*
			 * Require an exact match for the executable (a.out)
			 * and for the dynamic linker (ld.so.1).
			 */
			if ((strcmp(Dp->match_name, "a.out") == 0 ||
			    strcmp(Dp->match_name, "ld") == 0) &&
			    strcmp(Dyp->libpat[i], Dp->match_name) != 0)
				continue;

			/*
			 * Set Dyp->Dp to Dp so symbol_iter() can use it.
			 */
			Dyp->Dp = Dp;
			do_symbol_iter(object_name, Dyp);
			Dyp->Dp = NULL;
		}
	}

	Dp->built = TRUE;
	return (interrupt | sigusr1);
}

/* ARGSUSED */
int
object_present(void *cd, const prmap_t *pmp, const char *object_name)
{
	struct dynlib *Dp;

	for (Dp = Dynlib; Dp != NULL; Dp = Dp->next) {
		if (Dp->base == pmp->pr_vaddr)
			Dp->present = TRUE;
	}

	return (0);
}

/*
 * Search for an existing breakpoint at the 'pc' location.
 */
struct bkpt *
get_bkpt(uintptr_t pc)
{
	struct bkpt *Bp;

	for (Bp = bpt_hashtable[bpt_hash(pc)]; Bp != NULL; Bp = Bp->next)
		if (pc == Bp->addr)
			break;

	return (Bp);
}

/*
 * Create a breakpoint at 'pc', if one is not there already.
 * 'ret' is true when creating a function return breakpoint, in which case
 * fail and return NULL if the breakpoint would be created in writeable data.
 * If 'set' it true, set the breakpoint in the process now.
 */
struct bkpt *
create_bkpt(uintptr_t pc, int ret, int set)
{
	uint_t hix = bpt_hash(pc);
	struct bkpt *Bp;
	const prmap_t *pmp;

	for (Bp = bpt_hashtable[hix]; Bp != NULL; Bp = Bp->next)
		if (pc == Bp->addr)
			return (Bp);

	/*
	 * Don't set return breakpoints on writeable data
	 * or on any space other than executable text.
	 * Don't set breakpoints in the child of a vfork()
	 * because that would modify the parent's address space.
	 */
	if (is_vfork_child ||
	    (ret &&
	    ((pmp = Paddr_to_text_map(Proc, pc)) == NULL ||
	    !(pmp->pr_mflags & MA_EXEC) ||
	    (pmp->pr_mflags & MA_WRITE))))
		return (NULL);

	/* create a new unnamed breakpoint */
	Bp = my_malloc(sizeof (struct bkpt), NULL);
	Bp->sym_name = NULL;
	Bp->dyn = NULL;
	Bp->addr = pc;
	Bp->instr = 0;
	Bp->flags = 0;
	if (set && Psetbkpt(Proc, Bp->addr, &Bp->instr) == 0)
		Bp->flags |= BPT_ACTIVE;
	Bp->next = bpt_hashtable[hix];
	bpt_hashtable[hix] = Bp;

	return (Bp);
}

/*
 * Set all breakpoints that haven't been set yet.
 * Deactivate all breakpoints from modules that are not present any more.
 */
void
set_deferred_breakpoints(void)
{
	struct bkpt *Bp;
	int i;

	if (is_vfork_child)
		return;

	for (i = 0; i < HASHSZ; i++) {
		for (Bp = bpt_hashtable[i]; Bp != NULL; Bp = Bp->next) {
			if (!(Bp->flags & BPT_ACTIVE)) {
				if (!(Bp->flags & BPT_EXCLUDE) &&
				    Psetbkpt(Proc, Bp->addr, &Bp->instr) == 0)
					Bp->flags |= BPT_ACTIVE;
			} else if (Paddr_to_text_map(Proc, Bp->addr) == NULL) {
				Bp->flags &= ~BPT_ACTIVE;
			}
		}
	}
}

int
symbol_iter(void *cd, const GElf_Sym *sym, const char *sym_name)
{
	struct dynpat *Dyp = cd;
	struct dynlib *Dp = Dyp->Dp;
	uintptr_t pc = sym->st_value;
	struct bkpt *Bp;
	int i;

	/* ignore any undefined symbols */
	if (sym->st_shndx == SHN_UNDEF)
		return (0);

	/*
	 * Arbitrarily omit "_start" from the executable.
	 * (Avoid indentation before main().)
	 */
	if (*Dp->prt_name == '\0' && strcmp(sym_name, "_start") == 0)
		return (0);

	/*
	 * Arbitrarily omit "_rt_boot" from the dynamic linker.
	 * (Avoid indentation before main().)
	 */
	if (strcmp(Dp->match_name, "ld") == 0 &&
	    strcmp(sym_name, "_rt_boot") == 0)
		return (0);

	/*
	 * Arbitrarily omit any symbols whose name starts with '.'.
	 * Apparantly putting a breakpoint on .umul causes a
	 * fatal error in libthread (%y is not restored correctly
	 * when a single step is taken).  Looks like a /proc bug.
	 */
	if (*sym_name == '.')
		return (0);

	/*
	 * For each pattern in the array of symbol patterns,
	 * if the pattern matches the symbol name, then
	 * create a breakpoint at the function in question.
	 */
	for (i = 0; i < Dyp->nsympat; i++) {
		if (interrupt|sigusr1)
			break;
		if (fnmatch(Dyp->sympat[i], sym_name, 0) != 0)
			continue;

		if ((Bp = create_bkpt(pc, 0, 0)) == NULL)	/* can't fail */
			return (0);

		/*
		 * New breakpoints receive a name now.
		 * For existing breakpoints, prefer the subset name if possible,
		 * else prefer the shorter name.
		 */
		if (Bp->sym_name == NULL) {
			Bp->sym_name = strdup(sym_name);
		} else if (strstr(Bp->sym_name, sym_name) != NULL ||
		    strlen(Bp->sym_name) > strlen(sym_name)) {
			free(Bp->sym_name);
			Bp->sym_name = strdup(sym_name);
		}
		Bp->dyn = Dp;
		Bp->flags |= Dyp->flag;
		if (Dyp->exclude)
			Bp->flags |= BPT_EXCLUDE;
		else if (Dyp->internal || *Dp->prt_name == '\0')
			Bp->flags |= BPT_INTERNAL;
		return (0);
	}

	return (interrupt | sigusr1);
}

/* For debugging only ---- */
void
report_htable_stats(void)
{
	const pstatus_t *Psp = Pstatus(Proc);
	struct callstack *Stk;
	struct bkpt *Bp;
	uint_t Min = 1000000;
	uint_t Max = 0;
	uint_t Avg = 0;
	uint_t Total = 0;
	uint_t i, j;
	uint_t bucket[HASHSZ];

	if (Dynpat == NULL || !hflag)
		return;

	hflag = FALSE;
	(void) memset(bucket, 0, sizeof (bucket));

	for (i = 0; i < HASHSZ; i++) {
		j = 0;
		for (Bp = bpt_hashtable[i]; Bp != NULL; Bp = Bp->next)
			j++;
		if (j < Min)
			Min = j;
		if (j > Max)
			Max = j;
		if (j < HASHSZ)
			bucket[j]++;
		Total += j;
	}
	Avg = (Total + HASHSZ / 2) / HASHSZ;
	(void) fprintf(stderr, "truss hash table statistics --------\n");
	(void) fprintf(stderr, "    Total = %u\n", Total);
	(void) fprintf(stderr, "      Min = %u\n", Min);
	(void) fprintf(stderr, "      Max = %u\n", Max);
	(void) fprintf(stderr, "      Avg = %u\n", Avg);
	for (i = 0; i < HASHSZ; i++)
		if (bucket[i])
			(void) fprintf(stderr, "    %3u buckets of size %d\n",
			    bucket[i], i);

	(void) fprintf(stderr, "truss-detected stacks --------\n");
	for (Stk = callstack; Stk != NULL; Stk = Stk->next) {
		(void) fprintf(stderr,
		    "    base = 0x%.8lx  end = 0x%.8lx  size = %ld\n",
		    (ulong_t)Stk->stkbase,
		    (ulong_t)Stk->stkend,
		    (ulong_t)(Stk->stkend - Stk->stkbase));
	}
	(void) fprintf(stderr, "primary unix stack --------\n");
	(void) fprintf(stderr,
	    "    base = 0x%.8lx  end = 0x%.8lx  size = %ld\n",
	    (ulong_t)Psp->pr_stkbase,
	    (ulong_t)(Psp->pr_stkbase + Psp->pr_stksize),
	    (ulong_t)Psp->pr_stksize);
	(void) fprintf(stderr, "nthr_create = %u\n", nthr_create);
}

void
make_lwp_stack(const lwpstatus_t *Lsp, prmap_t *Pmap, int nmap)
{
	const pstatus_t *Psp = Pstatus(Proc);
	uintptr_t sp = Lsp->pr_reg[R_SP];
	id_t lwpid = Lsp->pr_lwpid;
	struct callstack *Stk;
	td_thrhandle_t th;
	td_thrinfo_t thrinfo;

	if (data_model != PR_MODEL_LP64)
		sp = (uint32_t)sp;

	/* check to see if we already have this stack */
	if (sp == 0)
		return;
	for (Stk = callstack; Stk != NULL; Stk = Stk->next)
		if (sp >= Stk->stkbase && sp < Stk->stkend)
			return;

	Stk = my_malloc(sizeof (struct callstack), NULL);
	Stk->next = callstack;
	callstack = Stk;
	nstack++;
	Stk->tref = 0;
	Stk->tid = 0;
	Stk->nthr_create = 0;
	Stk->ncall = 0;
	Stk->maxcall = DEF_MAXCALL;
	Stk->stack = my_malloc(DEF_MAXCALL * sizeof (*Stk->stack), NULL);

	/* primary stack */
	if (sp >= Psp->pr_stkbase && sp < Psp->pr_stkbase + Psp->pr_stksize) {
		Stk->stkbase = Psp->pr_stkbase;
		Stk->stkend = Stk->stkbase + Psp->pr_stksize;
		return;
	}

	/* alternate stack */
	if ((Lsp->pr_altstack.ss_flags & SS_ONSTACK) &&
	    sp >= (uintptr_t)Lsp->pr_altstack.ss_sp &&
	    sp < (uintptr_t)Lsp->pr_altstack.ss_sp
	    + Lsp->pr_altstack.ss_size) {
		Stk->stkbase = (uintptr_t)Lsp->pr_altstack.ss_sp;
		Stk->stkend = Stk->stkbase + Lsp->pr_altstack.ss_size;
		return;
	}

	/* thread stacks? */
	if (Thr_agent != NULL &&
	    td_ta_map_lwp2thr(Thr_agent, lwpid, &th) == TD_OK &&
	    td_thr_get_info(&th, &thrinfo) == TD_OK &&
	    sp >= (uintptr_t)thrinfo.ti_stkbase - thrinfo.ti_stksize &&
	    sp < (uintptr_t)thrinfo.ti_stkbase) {
		/* The bloody fools got this backwards! */
		Stk->stkend = (uintptr_t)thrinfo.ti_stkbase;
		Stk->stkbase = Stk->stkend - thrinfo.ti_stksize;
		return;
	}

	/* last chance -- try the raw memory map */
	for (; nmap; nmap--, Pmap++) {
		if (sp >= Pmap->pr_vaddr &&
		    sp < Pmap->pr_vaddr + Pmap->pr_size) {
			Stk->stkbase = Pmap->pr_vaddr;
			Stk->stkend = Pmap->pr_vaddr + Pmap->pr_size;
			return;
		}
	}

	callstack = Stk->next;
	nstack--;
	free(Stk->stack);
	free(Stk);
}

void
make_thr_stack(const td_thrhandle_t *Thp, prgregset_t reg)
{
	const pstatus_t *Psp = Pstatus(Proc);
	td_thrinfo_t thrinfo;
	uintptr_t sp = reg[R_SP];
	struct callstack *Stk;

	if (data_model != PR_MODEL_LP64)
		sp = (uint32_t)sp;

	/* check to see if we already have this stack */
	if (sp == 0)
		return;
	for (Stk = callstack; Stk != NULL; Stk = Stk->next)
		if (sp >= Stk->stkbase && sp < Stk->stkend)
			return;

	Stk = my_malloc(sizeof (struct callstack), NULL);
	Stk->next = callstack;
	callstack = Stk;
	nstack++;
	Stk->tref = 0;
	Stk->tid = 0;
	Stk->nthr_create = 0;
	Stk->ncall = 0;
	Stk->maxcall = DEF_MAXCALL;
	Stk->stack = my_malloc(DEF_MAXCALL * sizeof (*Stk->stack), NULL);

	/* primary stack */
	if (sp >= Psp->pr_stkbase && sp < Psp->pr_stkbase + Psp->pr_stksize) {
		Stk->stkbase = Psp->pr_stkbase;
		Stk->stkend = Stk->stkbase + Psp->pr_stksize;
		return;
	}

	if (td_thr_get_info(Thp, &thrinfo) == TD_OK &&
	    sp >= (uintptr_t)thrinfo.ti_stkbase - thrinfo.ti_stksize &&
	    sp < (uintptr_t)thrinfo.ti_stkbase) {
		/* The bloody fools got this backwards! */
		Stk->stkend = (uintptr_t)thrinfo.ti_stkbase;
		Stk->stkbase = Stk->stkend - thrinfo.ti_stksize;
		return;
	}

	callstack = Stk->next;
	nstack--;
	free(Stk->stack);
	free(Stk);
}

struct callstack *
find_lwp_stack(uintptr_t sp)
{
	const pstatus_t *Psp = Pstatus(Proc);
	char mapfile[64];
	int mapfd;
	struct stat statb;
	prmap_t *Pmap = NULL;
	prmap_t *pmap = NULL;
	int nmap = 0;
	struct callstack *Stk = NULL;

	/*
	 * Get the address space map.
	 */
	(void) sprintf(mapfile, "/proc/%d/rmap", (int)Psp->pr_pid);
	if ((mapfd = open(mapfile, O_RDONLY)) < 0 ||
	    fstat(mapfd, &statb) != 0 ||
	    statb.st_size < sizeof (prmap_t) ||
	    (Pmap = my_malloc(statb.st_size, NULL)) == NULL ||
	    (nmap = pread(mapfd, Pmap, statb.st_size, 0L)) <= 0 ||
	    (nmap /= sizeof (prmap_t)) == 0) {
		if (Pmap != NULL)
			free(Pmap);
		if (mapfd >= 0)
			(void) close(mapfd);
		return (NULL);
	}
	(void) close(mapfd);

	for (pmap = Pmap; nmap--; pmap++) {
		if (sp >= pmap->pr_vaddr &&
		    sp < pmap->pr_vaddr + pmap->pr_size) {
			Stk = my_malloc(sizeof (struct callstack), NULL);
			Stk->next = callstack;
			callstack = Stk;
			nstack++;
			Stk->stkbase = pmap->pr_vaddr;
			Stk->stkend = pmap->pr_vaddr + pmap->pr_size;
			Stk->tref = 0;
			Stk->tid = 0;
			Stk->nthr_create = 0;
			Stk->ncall = 0;
			Stk->maxcall = DEF_MAXCALL;
			Stk->stack = my_malloc(
			    DEF_MAXCALL * sizeof (*Stk->stack), NULL);
			break;
		}
	}

	free(Pmap);
	return (Stk);
}

struct callstack *
find_stack(uintptr_t sp)
{
	const pstatus_t *Psp = Pstatus(Proc);
	private_t *pri = get_private();
	const lwpstatus_t *Lsp = pri->lwpstat;
	id_t lwpid = Lsp->pr_lwpid;
#if defined(__sparc)
	prgreg_t tref = Lsp->pr_reg[R_G7];
#elif defined(__amd64)
	prgreg_t tref = Lsp->pr_reg[REG_FS];
#elif defined(__i386)
	prgreg_t tref = Lsp->pr_reg[GS];
#endif
	struct callstack *Stk = NULL;
	td_thrhandle_t th;
	td_thrinfo_t thrinfo;
	td_err_e error;

	/* primary stack */
	if (sp >= Psp->pr_stkbase && sp < Psp->pr_stkbase + Psp->pr_stksize) {
		Stk = my_malloc(sizeof (struct callstack), NULL);
		Stk->next = callstack;
		callstack = Stk;
		nstack++;
		Stk->stkbase = Psp->pr_stkbase;
		Stk->stkend = Stk->stkbase + Psp->pr_stksize;
		Stk->tref = 0;
		Stk->tid = 0;
		Stk->nthr_create = 0;
		Stk->ncall = 0;
		Stk->maxcall = DEF_MAXCALL;
		Stk->stack = my_malloc(DEF_MAXCALL * sizeof (*Stk->stack),
		    NULL);
		return (Stk);
	}

	/* alternate stack */
	if ((Lsp->pr_altstack.ss_flags & SS_ONSTACK) &&
	    sp >= (uintptr_t)Lsp->pr_altstack.ss_sp &&
	    sp < (uintptr_t)Lsp->pr_altstack.ss_sp
	    + Lsp->pr_altstack.ss_size) {
		Stk = my_malloc(sizeof (struct callstack), NULL);
		Stk->next = callstack;
		callstack = Stk;
		nstack++;
		Stk->stkbase = (uintptr_t)Lsp->pr_altstack.ss_sp;
		Stk->stkend = Stk->stkbase + Lsp->pr_altstack.ss_size;
		Stk->tref = 0;
		Stk->tid = 0;
		Stk->nthr_create = 0;
		Stk->ncall = 0;
		Stk->maxcall = DEF_MAXCALL;
		Stk->stack = my_malloc(DEF_MAXCALL * sizeof (*Stk->stack),
		    NULL);
		return (Stk);
	}

	if (Thr_agent == NULL)
		return (find_lwp_stack(sp));

	/* thread stacks? */
	if ((error = td_ta_map_lwp2thr(Thr_agent, lwpid, &th)) != TD_OK) {
		if (hflag)
			(void) fprintf(stderr,
			    "cannot get thread handle for "
			    "lwp#%d, error=%d, tref=0x%.8lx\n",
			    (int)lwpid, error, (long)tref);
		return (NULL);
	}

	if ((error = td_thr_get_info(&th, &thrinfo)) != TD_OK) {
		if (hflag)
			(void) fprintf(stderr,
			    "cannot get thread info for "
			    "lwp#%d, error=%d, tref=0x%.8lx\n",
			    (int)lwpid, error, (long)tref);
		return (NULL);
	}

	if (sp >= (uintptr_t)thrinfo.ti_stkbase - thrinfo.ti_stksize &&
	    sp < (uintptr_t)thrinfo.ti_stkbase) {
		Stk = my_malloc(sizeof (struct callstack), NULL);
		Stk->next = callstack;
		callstack = Stk;
		nstack++;
		/* The bloody fools got this backwards! */
		Stk->stkend = (uintptr_t)thrinfo.ti_stkbase;
		Stk->stkbase = Stk->stkend - thrinfo.ti_stksize;
		Stk->tref = tref;
		Stk->tid = thrinfo.ti_tid;
		Stk->nthr_create = nthr_create;
		Stk->ncall = 0;
		Stk->maxcall = DEF_MAXCALL;
		Stk->stack = my_malloc(DEF_MAXCALL * sizeof (*Stk->stack),
		    NULL);
		return (Stk);
	}

	/* stack bounds failure -- complain bitterly */
	if (hflag) {
		(void) fprintf(stderr,
		    "sp not within thread stack: "
		    "sp=0x%.8lx stkbase=0x%.8lx stkend=0x%.8lx\n",
		    (ulong_t)sp,
		    /* The bloody fools got this backwards! */
		    (ulong_t)thrinfo.ti_stkbase - thrinfo.ti_stksize,
		    (ulong_t)thrinfo.ti_stkbase);
	}

	return (NULL);
}

void
get_tid(struct callstack *Stk)
{
	private_t *pri = get_private();
	const lwpstatus_t *Lsp = pri->lwpstat;
	id_t lwpid = Lsp->pr_lwpid;
#if defined(__sparc)
	prgreg_t tref = Lsp->pr_reg[R_G7];
#elif defined(__amd64)
	prgreg_t tref = (data_model == PR_MODEL_LP64) ?
	    Lsp->pr_reg[REG_FS] : Lsp->pr_reg[REG_GS];
#elif defined(__i386)
	prgreg_t tref = Lsp->pr_reg[GS];
#endif
	td_thrhandle_t th;
	td_thrinfo_t thrinfo;
	td_err_e error;

	if (Thr_agent == NULL) {
		Stk->tref = 0;
		Stk->tid = 0;
		Stk->nthr_create = 0;
		return;
	}

	/*
	 * Shortcut here --
	 * If we have a matching tref and no new threads have
	 * been created since the last time we encountered this
	 * stack, then we don't have to go through the overhead
	 * of calling td_ta_map_lwp2thr() to get the thread-id.
	 */
	if (tref == Stk->tref && Stk->nthr_create == nthr_create)
		return;

	if ((error = td_ta_map_lwp2thr(Thr_agent, lwpid, &th)) != TD_OK) {
		if (hflag)
			(void) fprintf(stderr,
			    "cannot get thread handle for "
			    "lwp#%d, error=%d, tref=0x%.8lx\n",
			    (int)lwpid, error, (long)tref);
		Stk->tref = 0;
		Stk->tid = 0;
		Stk->nthr_create = 0;
	} else if ((error = td_thr_get_info(&th, &thrinfo)) != TD_OK) {
		if (hflag)
			(void) fprintf(stderr,
			    "cannot get thread info for "
			    "lwp#%d, error=%d, tref=0x%.8lx\n",
			    (int)lwpid, error, (long)tref);
		Stk->tref = 0;
		Stk->tid = 0;
		Stk->nthr_create = 0;
	} else {
		Stk->tref = tref;
		Stk->tid = thrinfo.ti_tid;
		Stk->nthr_create = nthr_create;
	}
}

struct callstack *
callstack_info(uintptr_t sp, uintptr_t fp, int makeid)
{
	struct callstack *Stk;
	uintptr_t trash;

	if (sp == 0 ||
	    Pread(Proc, &trash, sizeof (trash), sp) != sizeof (trash))
		return (NULL);

	for (Stk = callstack; Stk != NULL; Stk = Stk->next)
		if (sp >= Stk->stkbase && sp < Stk->stkend)
			break;

	/*
	 * If we didn't find the stack, do it the hard way.
	 */
	if (Stk == NULL) {
		uintptr_t stkbase = sp;
		uintptr_t stkend;
		uint_t minsize;

#if defined(i386) || defined(__amd64)
		if (data_model == PR_MODEL_LP64)
			minsize = 2 * sizeof (uintptr_t);	/* fp + pc */
		else
			minsize = 2 * sizeof (uint32_t);
#else
		if (data_model != PR_MODEL_LP64)
			minsize = SA32(MINFRAME32);
		else
			minsize = SA64(MINFRAME64);
#endif	/* i386 */
		stkend = sp + minsize;

		while (Stk == NULL && fp != 0 && fp >= sp) {
			stkend = fp + minsize;
			for (Stk = callstack; Stk != NULL; Stk = Stk->next)
				if ((fp >= Stk->stkbase && fp < Stk->stkend) ||
				    (stkend > Stk->stkbase &&
				    stkend <= Stk->stkend))
					break;
			if (Stk == NULL)
				fp = previous_fp(fp, NULL);
		}

		if (Stk != NULL)	/* the stack grew */
			Stk->stkbase = stkbase;
	}

	if (Stk == NULL && makeid)	/* new stack */
		Stk = find_stack(sp);

	if (Stk == NULL)
		return (NULL);

	/*
	 * Ensure that there is room for at least one more entry.
	 */
	if (Stk->ncall == Stk->maxcall) {
		Stk->maxcall *= 2;
		Stk->stack = my_realloc(Stk->stack,
		    Stk->maxcall * sizeof (*Stk->stack), NULL);
	}

	if (makeid)
		get_tid(Stk);

	return (Stk);
}

/*
 * Reset the breakpoint information (called on successful exec()).
 */
void
reset_breakpoints(void)
{
	struct dynlib *Dp;
	struct bkpt *Bp;
	struct callstack *Stk;
	int i;

	if (Dynpat == NULL)
		return;

	/* destroy all previous dynamic library information */
	while ((Dp = Dynlib) != NULL) {
		Dynlib = Dp->next;
		free(Dp->lib_name);
		free(Dp->match_name);
		free(Dp->prt_name);
		free(Dp);
	}

	/* destroy all previous breakpoint trap information */
	if (bpt_hashtable != NULL) {
		for (i = 0; i < HASHSZ; i++) {
			while ((Bp = bpt_hashtable[i]) != NULL) {
				bpt_hashtable[i] = Bp->next;
				if (Bp->sym_name)
					free(Bp->sym_name);
				free(Bp);
			}
		}
	}

	/* destroy all the callstack information */
	while ((Stk = callstack) != NULL) {
		callstack = Stk->next;
		free(Stk->stack);
		free(Stk);
	}

	/* we are not a multi-threaded process anymore */
	if (Thr_agent != NULL)
		(void) td_ta_delete(Thr_agent);
	Thr_agent = NULL;

	/* tell libproc to clear out its mapping information */
	Preset_maps(Proc);
	Rdb_agent = NULL;

	/* Reestablish the symbols from the executable */
	(void) establish_breakpoints();
}

/*
 * Clear breakpoints from the process (called before Prelease()).
 * Don't actually destroy the breakpoint table;
 * threads currently fielding breakpoints will need it.
 */
void
clear_breakpoints(void)
{
	struct bkpt *Bp;
	int i;

	if (Dynpat == NULL)
		return;

	/*
	 * Change all breakpoint traps back to normal instructions.
	 * We attempt to remove a breakpoint from every address which
	 * may have ever contained a breakpoint to protect our victims.
	 */
	report_htable_stats();	/* report stats first */
	for (i = 0; i < HASHSZ; i++) {
		for (Bp = bpt_hashtable[i]; Bp != NULL; Bp = Bp->next) {
			if (Bp->flags & BPT_ACTIVE)
				(void) Pdelbkpt(Proc, Bp->addr, Bp->instr);
			Bp->flags &= ~BPT_ACTIVE;
		}
	}

	if (Thr_agent != NULL) {
		td_thr_events_t events;

		td_event_fillset(&events);
		(void) td_ta_clear_event(Thr_agent, &events);
		(void) td_ta_delete(Thr_agent);
	}
	Thr_agent = NULL;
}

/*
 * Reestablish the breakpoint traps in the process.
 * Called after resuming from a vfork() in the parent.
 */
void
reestablish_traps(void)
{
	struct bkpt *Bp;
	ulong_t instr;
	int i;

	if (Dynpat == NULL || is_vfork_child)
		return;

	for (i = 0; i < HASHSZ; i++) {
		for (Bp = bpt_hashtable[i]; Bp != NULL; Bp = Bp->next) {
			if ((Bp->flags & BPT_ACTIVE) &&
			    Psetbkpt(Proc, Bp->addr, &instr) != 0)
				Bp->flags &= ~BPT_ACTIVE;
		}
	}
}

void
show_function_call(private_t *pri,
    struct callstack *Stk, struct dynlib *Dp, struct bkpt *Bp)
{
	long arg[8];
	int narg;
	int i;

	narg = get_arguments(arg);
	make_pname(pri, (Stk != NULL)? Stk->tid : 0);
	putpname(pri);
	timestamp(pri);
	if (Stk != NULL) {
		for (i = 1; i < Stk->ncall; i++) {
			(void) fputc(' ', stdout);
			(void) fputc(' ', stdout);
		}
	}
	(void) printf("-> %s%s(", Dp->prt_name, Bp->sym_name);
	for (i = 0; i < narg; i++) {
		(void) printf("0x%lx", arg[i]);
		if (i < narg-1) {
			(void) fputc(',', stdout);
			(void) fputc(' ', stdout);
		}
	}
	(void) printf(")\n");
	Flush();
}

/* ARGSUSED */
void
show_function_return(private_t *pri, long rval, int stret,
    struct callstack *Stk, struct dynlib *Dp, struct bkpt *Bp)
{
	int i;

	make_pname(pri, Stk->tid);
	putpname(pri);
	timestamp(pri);
	for (i = 0; i < Stk->ncall; i++) {
		(void) fputc(' ', stdout);
		(void) fputc(' ', stdout);
	}
	(void) printf("<- %s%s() = ", Dp->prt_name, Bp->sym_name);
	if (stret) {
		(void) printf("struct return\n");
	} else if (data_model == PR_MODEL_LP64) {
		if (rval >= (64 * 1024) || -rval >= (64 * 1024))
			(void) printf("0x%lx\n", rval);
		else
			(void) printf("%ld\n", rval);
	} else {
		int rval32 = (int)rval;
		if (rval32 >= (64 * 1024) || -rval32 >= (64 * 1024))
			(void) printf("0x%x\n", rval32);
		else
			(void) printf("%d\n", rval32);
	}
	Flush();
}

/*
 * Called to deal with function-call tracing.
 * Return 0 on normal success, 1 to indicate a BPT_HANG success,
 * and -1 on failure (not tracing functions or unknown breakpoint).
 */
int
function_trace(private_t *pri, int first, int clear, int dotrace)
{
	struct ps_lwphandle *Lwp = pri->Lwp;
	const lwpstatus_t *Lsp = pri->lwpstat;
	uintptr_t pc = Lsp->pr_reg[R_PC];
	uintptr_t sp = Lsp->pr_reg[R_SP];
	uintptr_t fp = Lsp->pr_reg[R_FP];
	struct bkpt *Bp;
	struct dynlib *Dp;
	struct callstack *Stk;
	ulong_t instr;
	int active;
	int rval = 0;

	if (Dynpat == NULL)
		return (-1);

	if (data_model != PR_MODEL_LP64) {
		pc = (uint32_t)pc;
		sp = (uint32_t)sp;
		fp = (uint32_t)fp;
	}

	if ((Bp = get_bkpt(pc)) == NULL) {
		if (hflag)
			(void) fprintf(stderr,
			    "function_trace(): "
			    "cannot find breakpoint for pc: 0x%.8lx\n",
			    (ulong_t)pc);
		return (-1);
	}

	if ((Bp->flags & (BPT_PREINIT|BPT_POSTINIT|BPT_DLACTIVITY)) && !clear) {
		rd_event_msg_t event_msg;

		if (hflag) {
			if (Bp->flags & BPT_PREINIT)
				(void) fprintf(stderr, "function_trace(): "
				    "RD_PREINIT breakpoint\n");
			if (Bp->flags & BPT_POSTINIT)
				(void) fprintf(stderr, "function_trace(): "
				    "RD_POSTINIT breakpoint\n");
			if (Bp->flags & BPT_DLACTIVITY)
				(void) fprintf(stderr, "function_trace(): "
				    "RD_DLACTIVITY breakpoint\n");
		}
		if (rd_event_getmsg(Rdb_agent, &event_msg) == RD_OK) {
			if (event_msg.type == RD_DLACTIVITY) {
				switch (event_msg.u.state) {
				case RD_CONSISTENT:
					establish_breakpoints();
					break;
				case RD_ADD:
					not_consist = TRUE;	/* kludge */
					establish_breakpoints();
					not_consist = FALSE;
					break;
				case RD_DELETE:
					delete_library = TRUE;
					break;
				default:
					break;
				}
			}
			if (hflag) {
				const char *et;
				char buf[32];

				switch (event_msg.type) {
				case RD_NONE:
					et = "RD_NONE";
					break;
				case RD_PREINIT:
					et = "RD_PREINIT";
					break;
				case RD_POSTINIT:
					et = "RD_POSTINIT";
					break;
				case RD_DLACTIVITY:
					et = "RD_DLACTIVITY";
					break;
				default:
					(void) sprintf(buf, "0x%x",
					    event_msg.type);
					et = buf;
					break;
				}
				(void) fprintf(stderr,
				    "event_msg.type = %s ", et);
				switch (event_msg.u.state) {
				case RD_NOSTATE:
					et = "RD_NOSTATE";
					break;
				case RD_CONSISTENT:
					et = "RD_CONSISTENT";
					break;
				case RD_ADD:
					et = "RD_ADD";
					break;
				case RD_DELETE:
					et = "RD_DELETE";
					break;
				default:
					(void) sprintf(buf, "0x%x",
					    event_msg.u.state);
					et = buf;
					break;
				}
				(void) fprintf(stderr,
				    "event_msg.u.state = %s\n", et);
			}
		}
	}

	if ((Bp->flags & BPT_TD_CREATE) && !clear) {
		nthr_create++;
		if (hflag)
			(void) fprintf(stderr, "function_trace(): "
			    "BPT_TD_CREATE breakpoint\n");
		/* we don't care about the event message */
	}

	Dp = Bp->dyn;

	if (dotrace) {
		if ((Stk = callstack_info(sp, fp, 1)) == NULL) {
			if (Dp != NULL && !clear) {
				if (cflag) {
					add_fcall(fcall_tbl, Dp->prt_name,
					    Bp->sym_name, (unsigned long)1);
				}
				else
					show_function_call(pri, NULL, Dp, Bp);
				if ((Bp->flags & BPT_HANG) && !first)
					rval = 1;
			}
		} else if (!clear) {
			if (Dp != NULL) {
				function_entry(pri, Bp, Stk);
				if ((Bp->flags & BPT_HANG) && !first)
					rval = 1;
			} else {
				function_return(pri, Stk);
			}
		}
	}

	/*
	 * Single-step the traced instruction. Since it's possible that
	 * another thread has deactivated this breakpoint, we indicate
	 * that we have reactivated it by virtue of executing it.
	 *
	 * To avoid a deadlock with some other thread in the process
	 * performing a fork() or a thr_suspend() operation, we must
	 * drop and later reacquire truss_lock.  Some fancy dancing here.
	 */
	active = (Bp->flags & BPT_ACTIVE);
	Bp->flags |= BPT_ACTIVE;
	instr = Bp->instr;
	(void) mutex_unlock(&truss_lock);
	(void) Lxecbkpt(Lwp, instr);
	(void) mutex_lock(&truss_lock);

	if (rval || clear) {	/* leave process stopped and abandoned */
#if defined(__i386)
		/*
		 * Leave it stopped in a state that a stack trace is reasonable.
		 */
		/* XX64 needs to be updated for amd64 & gcc */
		if (rval && instr == 0x55) {	/* pushl %ebp */
			/* step it over the movl %esp,%ebp */
			(void) mutex_unlock(&truss_lock);
			(void) Lsetrun(Lwp, 0, PRCFAULT|PRSTEP);
			/* we're wrapping up; wait one second at most */
			(void) Lwait(Lwp, MILLISEC);
			(void) mutex_lock(&truss_lock);
		}
#endif
		if (get_bkpt(pc) != Bp)
			abend("function_trace: lost breakpoint", NULL);
		(void) Pdelbkpt(Proc, Bp->addr, Bp->instr);
		Bp->flags &= ~BPT_ACTIVE;
		(void) mutex_unlock(&truss_lock);
		(void) Lsetrun(Lwp, 0, PRCFAULT|PRSTOP);
		/* we're wrapping up; wait one second at most */
		(void) Lwait(Lwp, MILLISEC);
		(void) mutex_lock(&truss_lock);
	} else {
		if (get_bkpt(pc) != Bp)
			abend("function_trace: lost breakpoint", NULL);
		if (!active || !(Bp->flags & BPT_ACTIVE)) {
			(void) Pdelbkpt(Proc, Bp->addr, Bp->instr);
			Bp->flags &= ~BPT_ACTIVE;
		}
	}
	return (rval);
}

void
function_entry(private_t *pri, struct bkpt *Bp, struct callstack *Stk)
{
	const lwpstatus_t *Lsp = pri->lwpstat;
	uintptr_t sp = Lsp->pr_reg[R_SP];
	uintptr_t rpc = get_return_address(&sp);
	struct dynlib *Dp = Bp->dyn;
	int oldframe = FALSE;
	int i;

	if (data_model != PR_MODEL_LP64) {
		sp = (uint32_t)sp;
		rpc = (uint32_t)rpc;
	}

	/*
	 * If the sp is not within the stack bounds, forget it.
	 * If the symbol's 'internal' flag is false,
	 * don't report internal calls within the library.
	 */
	if (!(sp >= Stk->stkbase && sp < Stk->stkend) ||
	    (!(Bp->flags & BPT_INTERNAL) &&
	    rpc >= Dp->base && rpc < Dp->base + Dp->size))
		return;

	for (i = 0; i < Stk->ncall; i++) {
		if (sp >= Stk->stack[i].sp) {
			Stk->ncall = i;
			if (sp == Stk->stack[i].sp)
				oldframe = TRUE;
			break;
		}
	}

	/*
	 * Breakpoints for function returns are set here
	 * If we're counting function calls, there is no need to set
	 * a breakpoint upon return
	 */

	if (!oldframe && !cflag) {
		(void) create_bkpt(rpc, 1, 1); /* may or may not be set */
		Stk->stack[Stk->ncall].sp = sp;	/* record it anyeay */
		Stk->stack[Stk->ncall].pc = rpc;
		Stk->stack[Stk->ncall].fcn = Bp;
	}
	Stk->ncall++;
	if (cflag) {
		add_fcall(fcall_tbl, Dp->prt_name, Bp->sym_name,
		    (unsigned long)1);
	} else {
		show_function_call(pri, Stk, Dp, Bp);
	}
}

/*
 * We are here because we hit an unnamed breakpoint.
 * Attempt to match this up with a return pc on the stack
 * and report the function return.
 */
void
function_return(private_t *pri, struct callstack *Stk)
{
	const lwpstatus_t *Lsp = pri->lwpstat;
	uintptr_t sp = Lsp->pr_reg[R_SP];
	uintptr_t fp = Lsp->pr_reg[R_FP];
	int i;

	if (data_model != PR_MODEL_LP64) {
		sp = (uint32_t)sp;
		fp = (uint32_t)fp;
	}

	if (fp < sp + 8)
		fp = sp + 8;

	for (i = Stk->ncall - 1; i >= 0; i--) {
		if (sp <= Stk->stack[i].sp && fp > Stk->stack[i].sp) {
			Stk->ncall = i;
			break;
		}
	}

#if defined(i386) || defined(__amd64)
	if (i < 0) {
		/* probably __mul64() or friends -- try harder */
		int j;
		for (j = 0; i < 0 && j < 8; j++) {	/* up to 8 args */
			sp -= 4;
			for (i = Stk->ncall - 1; i >= 0; i--) {
				if (sp <= Stk->stack[i].sp &&
				    fp > Stk->stack[i].sp) {
					Stk->ncall = i;
					break;
				}
			}
		}
	}
#endif

	if ((i >= 0) && (!cflag)) {
		show_function_return(pri, Lsp->pr_reg[R_R0], 0,
		    Stk, Stk->stack[i].fcn->dyn, Stk->stack[i].fcn);
	}
}

#if defined(__sparc)
#define	FPADJUST	0
#elif defined(__amd64)
#define	FPADJUST	8
#elif defined(__i386)
#define	FPADJUST	4
#endif

void
trap_one_stack(prgregset_t reg)
{
	struct dynlib *Dp;
	struct bkpt *Bp;
	struct callstack *Stk;
	GElf_Sym sym;
	char sym_name[32];
	uintptr_t sp = reg[R_SP];
	uintptr_t pc = reg[R_PC];
	uintptr_t fp;
	uintptr_t rpc;
	uint_t nframe = 0;
	uint_t maxframe = 8;
	struct {
		uintptr_t sp;		/* %sp within called function */
		uintptr_t pc;		/* %pc within called function */
		uintptr_t rsp;		/* the return sp */
		uintptr_t rpc;		/* the return pc */
	} *frame = my_malloc(maxframe * sizeof (*frame), NULL);

	/*
	 * Gather stack frames bottom to top.
	 */
	while (sp != 0) {
		fp = sp;	/* remember higest non-null sp */
		frame[nframe].sp = sp;
		frame[nframe].pc = pc;
		sp = previous_fp(sp, &pc);
		frame[nframe].rsp = sp;
		frame[nframe].rpc = pc;
		if (++nframe == maxframe) {
			maxframe *= 2;
			frame = my_realloc(frame, maxframe * sizeof (*frame),
			    NULL);
		}
	}

	/*
	 * Scan for function return breakpoints top to bottom.
	 */
	while (nframe--) {
		/* lookup the called function in the symbol tables */
		if (Plookup_by_addr(Proc, frame[nframe].pc, sym_name,
		    sizeof (sym_name), &sym) != 0)
			continue;

		pc = sym.st_value;	/* entry point of the function */
		rpc = frame[nframe].rpc;	/* caller's return pc */

		/* lookup the function in the breakpoint table */
		if ((Bp = get_bkpt(pc)) == NULL || (Dp = Bp->dyn) == NULL)
			continue;

		if (!(Bp->flags & BPT_INTERNAL) &&
		    rpc >= Dp->base && rpc < Dp->base + Dp->size)
			continue;

		sp = frame[nframe].rsp + FPADJUST;  /* %sp at time of call */
		if ((Stk = callstack_info(sp, fp, 0)) == NULL)
			continue;	/* can't happen? */

		if (create_bkpt(rpc, 1, 1) != NULL) {
			Stk->stack[Stk->ncall].sp = sp;
			Stk->stack[Stk->ncall].pc = rpc;
			Stk->stack[Stk->ncall].fcn = Bp;
			Stk->ncall++;
		}
	}

	free(frame);
}

int
lwp_stack_traps(void *cd, const lwpstatus_t *Lsp)
{
	ph_map_t *ph_map = (ph_map_t *)cd;
	prgregset_t reg;

	(void) memcpy(reg, Lsp->pr_reg, sizeof (prgregset_t));
	make_lwp_stack(Lsp, ph_map->pmap, ph_map->nmap);
	trap_one_stack(reg);

	return (interrupt | sigusr1);
}

/* ARGSUSED */
int
thr_stack_traps(const td_thrhandle_t *Thp, void *cd)
{
	prgregset_t reg;

	/*
	 * We have already dealt with all the lwps.
	 * We only care about unbound threads here (TD_PARTIALREG).
	 */
	if (td_thr_getgregs(Thp, reg) != TD_PARTIALREG)
		return (0);

	make_thr_stack(Thp, reg);
	trap_one_stack(reg);

	return (interrupt | sigusr1);
}

#if defined(__sparc)

uintptr_t
previous_fp(uintptr_t sp, uintptr_t *rpc)
{
	uintptr_t fp = 0;
	uintptr_t pc = 0;

	if (data_model == PR_MODEL_LP64) {
		struct rwindow64 rwin;
		if (Pread(Proc, &rwin, sizeof (rwin), sp + STACK_BIAS)
		    == sizeof (rwin)) {
			fp = (uintptr_t)rwin.rw_fp;
			pc = (uintptr_t)rwin.rw_rtn;
		}
		if (fp != 0 &&
		    Pread(Proc, &rwin, sizeof (rwin), fp + STACK_BIAS)
		    != sizeof (rwin))
			fp = pc = 0;
	} else {
		struct rwindow32 rwin;
		if (Pread(Proc, &rwin, sizeof (rwin), sp) == sizeof (rwin)) {
			fp = (uint32_t)rwin.rw_fp;
			pc = (uint32_t)rwin.rw_rtn;
		}
		if (fp != 0 &&
		    Pread(Proc, &rwin, sizeof (rwin), fp) != sizeof (rwin))
			fp = pc = 0;
	}
	if (rpc)
		*rpc = pc;
	return (fp);
}

/* ARGSUSED */
uintptr_t
get_return_address(uintptr_t *psp)
{
	instr_t inst;
	private_t *pri = get_private();
	const lwpstatus_t *Lsp = pri->lwpstat;
	uintptr_t rpc;

	rpc = (uintptr_t)Lsp->pr_reg[R_O7] + 8;
	if (data_model != PR_MODEL_LP64)
		rpc = (uint32_t)rpc;

	/* check for structure return (bletch!) */
	if (Pread(Proc, &inst, sizeof (inst), rpc) == sizeof (inst) &&
	    inst < 0x1000)
		rpc += sizeof (instr_t);

	return (rpc);
}

int
get_arguments(long *argp)
{
	private_t *pri = get_private();
	const lwpstatus_t *Lsp = pri->lwpstat;
	int i;

	if (data_model != PR_MODEL_LP64)
		for (i = 0; i < 4; i++)
			argp[i] = (uint_t)Lsp->pr_reg[R_O0+i];
	else
		for (i = 0; i < 4; i++)
			argp[i] = (long)Lsp->pr_reg[R_O0+i];
	return (4);
}

#endif	/* __sparc */

#if defined(__i386) || defined(__amd64)

uintptr_t
previous_fp(uintptr_t fp, uintptr_t *rpc)
{
	uintptr_t frame[2];
	uintptr_t trash[2];

	if (Pread(Proc, frame, sizeof (frame), fp) != sizeof (frame) ||
	    (frame[0] != 0 &&
	    Pread(Proc, trash, sizeof (trash), frame[0]) != sizeof (trash)))
		frame[0] = frame[1] = 0;

	if (rpc)
		*rpc = frame[1];
	return (frame[0]);
}

#endif

#if defined(__amd64) || defined(__i386)

/*
 * Examine the instruction at the return location of a function call
 * and return the byte count by which the stack is adjusted on return.
 * It the instruction at the return location is an addl, as expected,
 * then adjust the return pc by the size of that instruction so that
 * we will place the return breakpoint on the following instruction.
 * This allows programs that interrogate their own stacks and record
 * function calls and arguments to work correctly even while we interfere.
 * Return the count on success, -1 on failure.
 */
int
return_count32(uint32_t *ppc)
{
	uintptr_t pc = *ppc;
	struct bkpt *Bp;
	int count;
	uchar_t instr[6];	/* instruction at pc */

	if ((count = Pread(Proc, instr, sizeof (instr), pc)) < 0)
		return (-1);

	/* find the replaced instruction at pc (if any) */
	if ((Bp = get_bkpt(pc)) != NULL && (Bp->flags & BPT_ACTIVE))
		instr[0] = (uchar_t)Bp->instr;

	if (count != sizeof (instr) &&
	    (count < 3 || instr[0] != 0x83))
		return (-1);

	/*
	 * A bit of disassembly of the instruction is required here.
	 */
	if (instr[1] != 0xc4) {	/* not an addl mumble,%esp inctruction */
		count = 0;
	} else if (instr[0] == 0x81) {	/* count is a longword */
		count = instr[2]+(instr[3]<<8)+(instr[4]<<16)+(instr[5]<<24);
		*ppc += 6;
	} else if (instr[0] == 0x83) {	/* count is a byte */
		count = instr[2];
		*ppc += 3;
	} else {		/* not an addl inctruction */
		count = 0;
	}

	return (count);
}

uintptr_t
get_return_address32(uintptr_t *psp)
{
	uint32_t sp = *psp;
	uint32_t rpc;
	int count;

	*psp += 4;	/* account for popping the stack on return */
	if (Pread(Proc, &rpc, sizeof (rpc), sp) != sizeof (rpc))
		return (0);
	if ((count = return_count32(&rpc)) < 0)
		count = 0;
	*psp += count;		/* expected sp on return */
	return (rpc);
}

uintptr_t
get_return_address(uintptr_t *psp)
{
	uintptr_t rpc;
	uintptr_t sp = *psp;

	if (data_model == PR_MODEL_LP64) {
		if (Pread(Proc, &rpc, sizeof (rpc), sp) != sizeof (rpc))
			return (0);
		/*
		 * Ignore arguments pushed on the stack.  See comments in
		 * get_arguments().
		 */
		return (rpc);
	} else
		return (get_return_address32(psp));
}


int
get_arguments32(long *argp)
{
	private_t *pri = get_private();
	const lwpstatus_t *Lsp = pri->lwpstat;
	uint32_t frame[5];	/* return pc + 4 args */
	int narg;
	int count;
	int i;

	narg = Pread(Proc, frame, sizeof (frame),
	    (uintptr_t)Lsp->pr_reg[R_SP]);
	narg -= sizeof (greg32_t);
	if (narg <= 0)
		return (0);
	narg /= sizeof (greg32_t); /* no more than 4 */

	/*
	 * Given the return PC, determine the number of arguments.
	 */
	if ((count = return_count32(&frame[0])) < 0)
		narg = 0;
	else {
		count /= sizeof (greg32_t);
		if (narg > count)
			narg = count;
	}

	for (i = 0; i < narg; i++)
		argp[i] = (long)frame[i+1];

	return (narg);
}

int
get_arguments(long *argp)
{
	private_t *pri = get_private();
	const lwpstatus_t *Lsp = pri->lwpstat;

	if (data_model == PR_MODEL_LP64) {
		/*
		 * On amd64, we do not know how many arguments are passed to
		 * each function.  While it may be possible to detect if we
		 * have more than 6 arguments, it is of marginal value.
		 * Instead, assume that we always have 6 arguments, which are
		 * passed via registers.
		 */
		argp[0] = Lsp->pr_reg[REG_RDI];
		argp[1] = Lsp->pr_reg[REG_RSI];
		argp[2] = Lsp->pr_reg[REG_RDX];
		argp[3] = Lsp->pr_reg[REG_RCX];
		argp[4] = Lsp->pr_reg[REG_R8];
		argp[5] = Lsp->pr_reg[REG_R9];
		return (6);
	} else
		return (get_arguments32(argp));
}

#endif	/* __amd64 || __i386 */
