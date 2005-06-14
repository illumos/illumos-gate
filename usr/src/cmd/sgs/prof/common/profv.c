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
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * All routines in this file are for processing new-style, *versioned*
 * mon.out format. Together with rdelf.c, lookup.c and profv.h, these
 * form the complete set of files to profile new-style mon.out files.
 */

#include "profv.h"

bool		time_in_ticks = FALSE;
size_t		n_pcsamples, n_accounted_ticks, n_zeros, total_funcs;
unsigned char	sort_flag;

mod_info_t	modules;
size_t		n_modules = 1;	/* always include the aout object */

struct stat	aout_stat, monout_stat;
profrec_t	*profsym;

int
cmp_by_name(profrec_t *a, profrec_t *b)
{
	return (strcmp(a->demangled_name, b->demangled_name));
}

static void
setup_demangled_names()
{
	char		*p, *nbp, *nbe, *namebuf;
	size_t		cur_len = 0, namebuf_sz = BUCKET_SZ;
	register size_t	i, namelen;

	if ((namebuf = (char *) malloc(namebuf_sz)) == NULL) {
		fprintf(stderr, "%s: can't allocate %lld bytes\n",
						    cmdname, namebuf_sz);
		exit(ERR_MEMORY);
	}

	nbp = namebuf;
	nbe = namebuf + namebuf_sz;

	for (i = 0; i < total_funcs; i++) {
		if ((p = sgs_demangle(profsym[i].name)) == NULL)
			continue;

		namelen = strlen(p);
		if ((nbp + namelen + 1) > nbe) {
			namebuf_sz += BUCKET_SZ;
			namebuf = (char *) realloc(namebuf, namebuf_sz);
			if (namebuf == NULL) {
				fprintf(stderr, "%s: can't alloc %lld bytes\n",
							    cmdname, BUCKET_SZ);
				exit(ERR_MEMORY);
			}

			nbp = namebuf + cur_len;
			nbe = namebuf + namebuf_sz;
		}

		strcpy(nbp, p);
		profsym[i].demangled_name = nbp;

		nbp += namelen + 1;
		cur_len += namelen + 1;
	}
}

int
cmp_by_time(profrec_t *a, profrec_t *b)
{
	if (a->percent_time > b->percent_time)
		return (-1);
	else if (a->percent_time < b->percent_time)
		return (1);
	else
		return (0);
}

int
cmp_by_ncalls(profrec_t *a, profrec_t *b)
{
	if (a->ncalls > b->ncalls)
		return (-1);
	else if (a->ncalls < b->ncalls)
		return (1);
	else
		return (0);

}

static void
print_profile_data()
{
	int		i;
	int		(*sort_func)();
	mod_info_t	*mi;
	double		cumsecs = 0;
	char		filler[20];

	/*
	 * Sort the compiled data; the sort flags are mutually exclusive.
	 */
	switch (sort_flag) {
		case BY_NCALLS:
			sort_func = cmp_by_ncalls;
			break;

		case BY_NAME:
			if (Cflag)
				setup_demangled_names();
			sort_func = cmp_by_name;
			break;

		case BY_ADDRESS:
			sort_flag |= BY_ADDRESS;
			sort_func = NULL;	/* already sorted by addr */
			break;

		case BY_TIME:		/* default is to sort by time */
		default:
			sort_func = cmp_by_time;
	}


	if (sort_func) {
		qsort(profsym, total_funcs, sizeof (profrec_t),
			(int (*)(const void *, const void *)) sort_func);
	}

	/*
	 * If we're sorting by name, and if it is a verbose print, we wouldn't
	 * have set up the print_mid fields yet.
	 */
	if ((flags & F_VERBOSE) && (sort_flag == BY_NAME)) {
		for (i = 0; i < total_funcs; i++) {
			/*
			 * same as previous or next (if there's one) ?
			 */
			if (i && (strcmp(profsym[i].demangled_name,
					profsym[i-1].demangled_name) == 0)) {
				profsym[i].print_mid = TRUE;
			} else if ((i < (total_funcs - 1)) &&
					(strcmp(profsym[i].demangled_name,
					profsym[i+1].demangled_name) == 0)) {
				profsym[i].print_mid = TRUE;
			}
		}
	}

	/*
	 * The actual printing part.
	 */
	if (!(flags & F_NHEAD)) {
		if (flags & F_PADDR)
			printf("        %s", atitle);

		if (time_in_ticks)
		    puts(" %Time   Tiks  Cumtiks  #Calls   tiks/call  Name");
		else
		    puts(" %Time Seconds Cumsecs  #Calls   msec/call  Name");
	}

	mi = NULL;
	for (i = 0; i < total_funcs; i++) {
		/*
		 * Since the same value may denote different symbols in
		 * different shared objects, it is debatable if it is
		 * meaningful to print addresses at all. Especially so
		 * if we were asked to sort by symbol addresses.
		 *
		 * If we've to sort by address, I think it is better to sort
		 * it on a per-module basis and if verbose mode is on too,
		 * print a newline to separate out modules.
		 */
		if ((flags & F_VERBOSE) && (sort_flag == BY_ADDRESS)) {
			if (mi != profsym[i].module) {
				printf("\n");
				mi = profsym[i].module;
			}
		}

		if (flags & F_PADDR) {
			if (aformat[2] == 'x')
				printf("%16llx ", profsym[i].addr);
			else
				printf("%16llo ", profsym[i].addr);
		}

		cumsecs += profsym[i].seconds;
		printf("%6.1f%8.2f%8.2f", profsym[i].percent_time,
						profsym[i].seconds, cumsecs);

		printf("%8ld%12.4f  ",
				profsym[i].ncalls, profsym[i].msecs_per_call);

		if (profsym[i].print_mid)
			printf("%d:", (profsym[i].module)->id);

		printf("%s\n", profsym[i].demangled_name);
	}

	if (flags & F_PADDR)
		sprintf(filler, "%16s", "");
	else
		filler[0] = 0;

	if (flags & F_VERBOSE) {
		puts("\n");
		printf("%s   Total Object Modules     %7d\n",
						filler, n_modules);
		printf("%s   Qualified Symbols        %7d\n",
						filler, total_funcs);
		printf("%s   Symbols with zero usage  %7d\n",
						filler, n_zeros);
		printf("%s   Total pc-hits            %7d\n",
						filler, n_pcsamples);
		printf("%s   Accounted pc-hits        %7d\n",
						filler, n_accounted_ticks);
		if ((!gflag) && (n_pcsamples - n_accounted_ticks)) {
			printf("%s   Missed pc-hits (try -g)  %7d\n\n",
				    filler, n_pcsamples - n_accounted_ticks);
		} else {
			printf("%s   Missed pc-hits           %7d\n\n",
				    filler, n_pcsamples - n_accounted_ticks);
		}
		printf("%s   Module info\n", filler);
		for (mi = &modules; mi; mi = mi->next)
			printf("%s      %d: `%s'\n", filler, mi->id, mi->path);
	}
}

int
name_cmp(profnames_t *a, profnames_t *b)
{
	return (strcmp(a->name, b->name));
}

static void
check_dupnames()
{
	int		i;
	profnames_t	*pn;

	pn = (profnames_t *) calloc(total_funcs, sizeof (profnames_t));
	if (pn == NULL) {
		fprintf(stderr, "%s: no room for %ld bytes\n", cmdname,
					total_funcs * sizeof (profnames_t));
		exit(ERR_MEMORY);
	}

	for (i = 0; i < total_funcs; i++) {
		pn[i].name = profsym[i].demangled_name;
		pn[i].pfrec = &profsym[i];
	}

	qsort(pn, total_funcs, sizeof (profnames_t),
			(int (*)(const void *, const void *)) name_cmp);

	for (i = 0; i < total_funcs; i++) {
		/*
		 * same as previous or next (if there's one) ?
		 */
		if (i && (strcmp(pn[i].name, pn[i-1].name) == 0))
			(pn[i].pfrec)->print_mid = TRUE;
		else if ((i < (total_funcs - 1)) &&
				    (strcmp(pn[i].name, pn[i+1].name) == 0)) {
			(pn[i].pfrec)->print_mid = TRUE;
		}
	}

	free(pn);
}

static void
compute_times(nltype *nl, profrec_t *psym)
{
	static int	first_time = TRUE;
	static long	hz;

	if (first_time) {
		if ((hz = sysconf(_SC_CLK_TCK)) == -1)
			time_in_ticks = TRUE;
		first_time = FALSE;
	}

	if (time_in_ticks) {
		psym->seconds = (double) nl->nticks;
		if (nl->ncalls) {
		    psym->msecs_per_call = (double) nl->nticks /
							(double) nl->ncalls;
		} else
		    psym->msecs_per_call = (double) 0.0;
	} else {
		psym->seconds = (double) nl->nticks / (double) hz;
		if (nl->ncalls) {
			psym->msecs_per_call = ((double) psym->seconds *
						1000.0) / (double) nl->ncalls;
		} else
			psym->msecs_per_call = (double) 0.0;
	}

	if (n_pcsamples) {
		psym->percent_time = ((double) nl->nticks /
						(double) n_pcsamples) * 100;
	}
}

static void
collect_profsyms()
{
	mod_info_t	*mi;
	nltype		*nl;
	size_t		i, ndx;


	for (mi = &modules; mi; mi = mi->next)
		total_funcs += mi->nfuncs;

	profsym = (profrec_t *) calloc(total_funcs, sizeof (profrec_t));
	if (profsym == NULL) {
		fprintf(stderr, "%s: no room for %ld bytes\n", cmdname,
					total_funcs * sizeof (profrec_t));
		exit(ERR_MEMORY);
	}

	ndx = 0;
	for (mi = &modules; mi; mi = mi->next) {
		nl = mi->nl;
		for (i = 0; i < mi->nfuncs; i++) {
			/*
			 * I think F_ZSYMS doesn't make sense for the new
			 * mon.out format, since we don't have a profiling
			 * *range*, per se. But the man page demands it,
			 * so...
			 */
			if ((nl[i].ncalls == 0) && (nl[i].nticks == 0)) {
				n_zeros++;
				if (!(flags & F_ZSYMS))
					continue;
			}

			/*
			 * Initially, we set demangled_name to be
			 * the same as name. If Cflag is set, we later
			 * change this to be the demangled name ptr.
			 */
			profsym[ndx].addr = nl[i].value;
			profsym[ndx].ncalls = nl[i].ncalls;
			profsym[ndx].name = nl[i].name;
			profsym[ndx].demangled_name = nl[i].name;
			profsym[ndx].module = mi;
			profsym[ndx].print_mid = FALSE;
			compute_times(&nl[i], &profsym[ndx]);
			ndx++;
		}
	}

	/*
	 * Adjust total_funcs to actual printable funcs
	 */
	total_funcs = ndx;
}

static void
assign_pcsamples(module, pcsmpl, n_samples)
mod_info_t	*module;
Address		*pcsmpl;
size_t		n_samples;
{
	Address		*pcptr, *pcse = pcsmpl + n_samples;
	Address		nxt_func;
	nltype		*nl;
	size_t		nticks;

	/* Locate the first pc-hit for this module */
	if ((pcptr = locate(pcsmpl, n_samples, module->load_base)) == NULL)
		return;			/* no pc-hits in this module */

	/* Assign all pc-hits in this module to appropriate functions */
	while ((pcptr < pcse) && (*pcptr < module->load_end)) {

		/* Update the corresponding function's time */
		if (nl = nllookup(module, *pcptr, &nxt_func)) {
			/*
			 * Collect all pc-hits in this function. Each
			 * pc-hit counts as 1 tick.
			 */
			nticks = 0;
			while ((pcptr < pcse) && (*pcptr < nxt_func)) {
				nticks++;
				pcptr++;
			}

			nl->nticks += nticks;
			n_accounted_ticks += nticks;
		} else {
			/*
			 * pc sample could not be assigned to function;
			 * probably in a PLT
			 */
			pcptr++;
		}
	}
}

int
pc_cmp(Address *pc1, Address *pc2)
{
	if (*pc1 > *pc2)
		return (1);

	if (*pc1 < *pc2)
		return (-1);

	return (0);
}

static void
process_pcsamples(bufp)
ProfBuffer	*bufp;
{
	Address		*pc_samples;
	mod_info_t	*mi;
	size_t		nelem = bufp->bufsize;

	/* buffer with no pc samples ? */
	if (nelem == 0)
		return;

	/* Allocate for the pcsample chunk */
	pc_samples = (Address *) calloc(nelem, sizeof (Address));
	if (pc_samples == NULL) {
		fprintf(stderr, "%s: no room for %ld sample pc's\n",
							    cmdname, nelem);
		exit(ERR_MEMORY);
	}

	memcpy((void *) pc_samples, (caddr_t) bufp + bufp->buffer,
						    nelem * sizeof (Address));

	/* Sort the pc samples */
	qsort(pc_samples, nelem, sizeof (Address),
			(int (*)(const void *, const void *)) pc_cmp);

	/*
	 * Assign pcsamples to functions in the currently active
	 * module list
	 */
	for (mi = &modules; mi; mi = mi->next) {
		if (mi->active == FALSE)
			continue;
		assign_pcsamples(mi, pc_samples, nelem);
	}

	free(pc_samples);

	/* Update total number of pcsamples read so far */
	n_pcsamples += nelem;
}

static void
process_cgraph(cgp)
ProfCallGraph	*cgp;
{
	mod_info_t	*mi;
	Address		f_end;
	Index		callee_off;
	ProfFunction	*calleep;
	nltype		*nl;

	for (callee_off = cgp->functions; callee_off;
					    callee_off = calleep->next_to) {

		calleep = (ProfFunction *) ((char *) cgp + callee_off);
		if (calleep->count == 0)
			continue;

		/*
		 * If we cannot identify a callee with a module, we
		 * cannot get to its namelist, just skip it.
		 */
		for (mi = &modules; mi; mi = mi->next) {
			if (mi->active == FALSE)
				continue;

			if (calleep->topc >= mi->load_base &&
					    calleep->topc < mi->load_end) {
				/*
				 * nllookup() returns the next lower entry
				 * point on a miss. So just make sure the
				 * callee's pc is not outside this function
				 */
				if (nl = nllookup(mi, calleep->topc, 0)) {
					f_end = mi->load_base + (nl->value -
						    mi->txt_origin) + nl->size;
					if (calleep->topc < f_end)
						nl->ncalls += calleep->count;
				}
			}
		}
	}
}

static mod_info_t *
get_shobj_syms(char *pathname, GElf_Addr ld_base, GElf_Addr ld_end)
{
	mod_info_t	*mi;

	/* Create a new module element */
	if ((mi = (mod_info_t *) malloc(sizeof (mod_info_t))) == NULL) {
		fprintf(stderr, "%s: no room for %ld bytes\n",
					    cmdname, sizeof (mod_info_t));
		exit(ERR_MEMORY);
	}

	mi->path = (char *) malloc(strlen(pathname) + 1);
	if (mi->path == NULL) {
		fprintf(stderr, "%s: can't allocate %ld bytes\n",
						    strlen(pathname) + 1);
		exit(ERR_MEMORY);
	}
	strcpy(mi->path, pathname);
	mi->next = NULL;

	get_syms(pathname, mi);

	/* and fill in info... */
	mi->id = n_modules + 1;
	mi->load_base = ld_base;
	mi->load_end = ld_end;
	mi->active = TRUE;

	n_modules++;

	return (mi);
}

/*
 * Two modules overlap each other if they don't lie completely *outside*
 * each other.
 */
static bool
does_overlap(new, old)
ProfModule	*new;
mod_info_t	*old;
{
	/* case 1: new module lies completely *before* the old one */
	if (new->startaddr < old->load_base && new->endaddr <= old->load_base)
		return (FALSE);

	/* case 2: new module lies completely *after* the old one */
	if (new->startaddr >= old->load_end && new->endaddr >= old->load_end)
		return (FALSE);

	/* probably a dlopen: the modules overlap each other */
	return (TRUE);
}

static bool
is_same_as_aout(modpath, buf)
char		*modpath;
struct stat	*buf;
{
	if (stat(modpath, buf) == -1) {
		perror(modpath);
		exit(ERR_SYSCALL);
	}

	if ((buf->st_dev == aout_stat.st_dev) &&
				    (buf->st_ino == aout_stat.st_ino)) {
		return (TRUE);
	} else
		return (FALSE);
}

static void
process_modules(modlp)
ProfModuleList	*modlp;
{
	ProfModule	*newmodp;
	mod_info_t	*mi, *last, *new_module;
	char		*so_path;
	bool		more_modules = TRUE;
	struct stat	so_statbuf;

	/* Check version of module type object */
	if (modlp->version > PROF_MODULES_VER) {
		fprintf(stderr, "%s: unsupported version %d for modules\n",
						cmdname, modlp->version);
		exit(ERR_INPUT);
	}


	/*
	 * Scan the PROF_MODULES_T list and add modules to current list
	 * of modules, if they're not present already
	 */
	newmodp = (ProfModule *) ((caddr_t) modlp + modlp->modules);
	do {
		/*
		 * Since the aout could've been renamed after its run, we
		 * should see if current module overlaps aout. If it does, it
		 * is probably the renamed aout. We should also skip any other
		 * non-sharedobj's that we see (or should we report an error ?)
		 */
		so_path = (caddr_t) modlp + newmodp->path;
		if (does_overlap(newmodp, &modules) ||
				    is_same_as_aout(so_path, &so_statbuf) ||
						(!is_shared_obj(so_path))) {
			if (!newmodp->next)
				more_modules = FALSE;

			newmodp = (ProfModule *)
					((caddr_t) modlp + newmodp->next);
			continue;
		}

		/*
		 * Check all modules (leave the first one, 'cos that
		 * is the program executable info). If this module is already
		 * there in the list, skip it.
		 */
		last = &modules;
		while (mi = last->next) {
			/*
			 * We expect the full pathname for all shared objects
			 * needed by the program executable. In this case, we
			 * simply need to compare the paths to see if they are
			 * the same file.
			 */
			if (strcmp(mi->path, so_path) == 0)
				break;

			/*
			 * Check if this new shared object will overlap any
			 * existing module. If yes, deactivate the old one.
			 */
			if (does_overlap(newmodp, mi))
				mi->active = FALSE;

			last = mi;
		}

		/* Module already there, skip it */
		if (mi != NULL) {
			mi->load_base = newmodp->startaddr;
			mi->load_end = newmodp->endaddr;
			mi->active = TRUE;
			if (!newmodp->next)
				more_modules = FALSE;

			newmodp = (ProfModule *)
					((caddr_t) modlp + newmodp->next);
			continue;
		}

		/*
		 * Check if mon.out is outdated with respect to the new
		 * module we want to add
		 */
		if (monout_stat.st_mtime < so_statbuf.st_mtime) {
			fprintf(stderr, "%s: newer shared obj %s outdates "
					"profile info\n", cmdname, so_path);
			exit(ERR_INPUT);
		}

		/* Create this module's nameslist */
		new_module = get_shobj_syms(so_path,
					newmodp->startaddr, newmodp->endaddr);

		/* Add it to the tail of active module list */
		last->next = new_module;

		/*
		 * Move to the next module in the PROF_MODULES_T list
		 * (if present)
		 */
		if (!newmodp->next)
			more_modules = FALSE;

		newmodp = (ProfModule *) ((caddr_t) modlp + newmodp->next);

	} while (more_modules);
}

static void
process_mon_out(caddr_t memp, size_t fsz)
{
	ProfObject	*objp;
	caddr_t		file_end;
	bool		found_pcsamples = FALSE, found_cgraph = FALSE;

	/*
	 * Save file end pointer and start after header
	 */
	file_end = memp + fsz;
	objp = (ProfObject *) (memp + ((ProfHeader *) memp)->size);
	while ((caddr_t) objp < file_end) {
		switch (objp->type) {
			case PROF_MODULES_T :
				process_modules((ProfModuleList *) objp);
				break;

			case PROF_CALLGRAPH_T :
				process_cgraph((ProfCallGraph *) objp);
				found_cgraph = TRUE;
				break;

			case PROF_BUFFER_T :
				process_pcsamples((ProfBuffer *) objp);
				found_pcsamples = TRUE;
				break;

			default :
				fprintf(stderr,
					"%s: unknown prof object type=%d\n",
							cmdname, objp->type);
				exit(ERR_INPUT);
		}
		objp = (ProfObject *) ((caddr_t) objp + objp->size);
	}

	if (!found_cgraph || !found_pcsamples) {
		fprintf(stderr, "%s: missing callgraph/pcsamples in `%s'\n",
							    cmdname, mon_fn);
		exit(ERR_INPUT);
	}

	if ((caddr_t) objp > file_end) {
		fprintf(stderr, "%s: malformed file `%s'\n", cmdname, mon_fn);
		exit(ERR_INPUT);
	}
}

static void
get_aout_syms(char *pathname, mod_info_t *mi)
{
	mi->path = (char *) malloc(strlen(pathname) + 1);
	if (mi->path == NULL) {
		fprintf(stderr, "%s: can't allocate %ld bytes\n",
						    strlen(pathname) + 1);
		exit(ERR_MEMORY);
	}

	strcpy(mi->path, pathname);
	mi->next = NULL;

	get_syms(pathname, mi);

	mi->id = 1;
	mi->load_base = mi->txt_origin;
	mi->load_end = mi->data_end;
	mi->active = TRUE;
}

void
profver()
{
	int		fd;
	unsigned int	magic_num;
	bool		invalid_version;
	caddr_t		fmem;
	ProfHeader	prof_hdr;

	/*
	 * Check the magic and see if this is versioned or *old-style*
	 * mon.out.
	 */
	if ((fd = open(mon_fn, O_RDONLY)) == -1) {
		perror(mon_fn);
		exit(ERR_SYSCALL);
	}
	if (read(fd, (char *) &magic_num, sizeof (unsigned int)) == -1) {
		perror("read");
		exit(ERR_SYSCALL);
	}
	if (magic_num != (unsigned int) PROF_MAGIC) {
		close(fd);
		return;
	}



	/*
	 * Check versioning info. For now, let's say we provide
	 * backward compatibility, so we accept all older versions.
	 */
	lseek(fd, 0L, SEEK_SET);
	if (read(fd, (char *) &prof_hdr, sizeof (ProfHeader)) == -1) {
		perror("read");
		exit(ERR_SYSCALL);
	}
	invalid_version = FALSE;
	if (prof_hdr.h_major_ver > PROF_MAJOR_VERSION)
		invalid_version = TRUE;
	else if (prof_hdr.h_major_ver == PROF_MAJOR_VERSION) {
		if (prof_hdr.h_minor_ver > PROF_MINOR_VERSION)
		invalid_version = FALSE;
	}
	if (invalid_version) {
		fprintf(stderr, "%s: mon.out version %d.%d not supported\n",
		cmdname, prof_hdr.h_major_ver, prof_hdr.h_minor_ver);
		exit(ERR_INPUT);
	}



	/*
	 * Map mon.out onto memory.
	 */
	if (stat(mon_fn, &monout_stat) == -1) {
		perror(mon_fn);
		exit(ERR_SYSCALL);
	}
	if ((fmem = mmap(0, monout_stat.st_size,
			PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED) {
		perror("mmap");
		exit(ERR_SYSCALL);
	}
	close(fd);


	/*
	 * Now, read program executable's symbol table. Also save it's
	 * stat in aout_stat for use while processing mon.out
	 */
	if (stat(sym_fn, &aout_stat) == -1) {
		perror(sym_fn);
		exit(ERR_SYSCALL);
	}
	get_aout_syms(sym_fn, &modules);

	/*
	 * Process the mon.out, all shared objects it references
	 * and collect statistics on ticks spent in each function,
	 * number of calls, etc.
	 */
	process_mon_out(fmem, monout_stat.st_size);

	/*
	 * Based on the flags and the statistics we've got, create
	 * a list of relevant symbols whose profiling details should
	 * be printed
	 */
	collect_profsyms();

	/*
	 * Check for duplicate names in output. We need to print the
	 * module id's if verbose. Also, if we are sorting by name anyway,
	 * we don't need to check for duplicates here. We'll do that later.
	 */
	if ((flags & F_VERBOSE) && (sort_flag != BY_NAME))
		check_dupnames();

	/*
	 * Print output
	 */
	print_profile_data();


	munmap(fmem, monout_stat.st_size);
	exit(0);
}
