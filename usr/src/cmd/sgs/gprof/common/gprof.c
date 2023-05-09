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

#include	<sysexits.h>
#include	<stdlib.h>
#include	<stdio.h>
#include	<unistd.h>
#include	"gprof.h"
#include	"profile.h"

bool		aflag;
bool		bflag;
bool		Bflag;
bool		cflag;
bool		Cflag;
bool		dflag;
bool		Dflag;
bool		eflag;
bool		Eflag;
bool		fflag;
bool		Fflag;
bool		lflag;
bool		sflag;
bool		zflag;
bool		nflag;
bool		rflag;
bool		first_file;
bool		old_style;
double		scale;
double		totime;
Size		n_pcsamples;
mod_info_t	modules;
pctype		s_lowpc;
pctype		s_highpc;
sztype		n_modules;
sztype		sampbytes;
sztype		nsamples;
unsigned short	*samples;
fl_info_t	aout_info;
fl_info_t	gmonout_info;
long		hz;
struct hdr	h;
unsigned char	*textspace;
int		debug;
int		number_funcs_toprint;
char		*a_outname;
char		*prog_name;
char		*gmonname;
char		*whoami = "gprof";
static pctype	lowpc, highpc;		/* range profiled, in UNIT's */

/*
 *	things which get -E excluded by default.
 */
static char *defaultEs[] = {
	"mcount",
	"__mcleanup",
	NULL
};

#ifdef DEBUG

static char *objname[] = {
	"<invalid object>",
	"PROF_BUFFER_T",
	"PROF_CALLGRAPH_T",
	"PROF_MODULES_T",
	NULL
};
#define	MAX_OBJTYPES	3

#endif /* DEBUG */

void
done(void)
{

	exit(EX_OK);
}

static pctype
max(pctype a, pctype b)
{
	if (a > b)
		return (a);
	return (b);
}

static pctype
min(pctype a, pctype b)
{
	if (a < b)
		return (a);
	return (b);
}

/*
 *	calculate scaled entry point addresses (to save time in asgnsamples),
 *	and possibly push the scaled entry points over the entry mask,
 *	if it turns out that the entry point is in one bucket and the code
 *	for a routine is in the next bucket.
 *
 */
static void
alignentries(void)
{
	struct nl *nlp;
#ifdef DEBUG
	pctype			bucket_of_entry;
	pctype			bucket_of_code;
#endif /* DEBUG */

	/* for old-style gmon.out, nameslist is only in modules.nl */

	for (nlp = modules.nl; nlp < modules.npe; nlp++) {
		nlp->svalue = nlp->value / sizeof (UNIT);
#ifdef DEBUG
		bucket_of_entry = (nlp->svalue - lowpc) / scale;
		bucket_of_code = (nlp->svalue + UNITS_TO_CODE - lowpc) / scale;
		if (bucket_of_entry < bucket_of_code) {
			if (debug & SAMPLEDEBUG) {
				(void) printf(
				    "[alignentries] pushing svalue 0x%llx "
				    "to 0x%llx\n", nlp->svalue,
				    nlp->svalue + UNITS_TO_CODE);
			}
		}
#endif /* DEBUG */
	}
}

/*
 *	old-style gmon.out
 *	------------------
 *
 *	Assign samples to the procedures to which they belong.
 *
 *	There are three cases as to where pcl and pch can be
 *	with respect to the routine entry addresses svalue0 and svalue1
 *	as shown in the following diagram.  overlap computes the
 *	distance between the arrows, the fraction of the sample
 *	that is to be credited to the routine which starts at svalue0.
 *
 *	    svalue0                                         svalue1
 *	       |                                               |
 *	       v                                               v
 *
 *	       +-----------------------------------------------+
 *	       |					       |
 *	  |  ->|    |<-		->|         |<-		->|    |<-  |
 *	  |         |		  |         |		  |         |
 *	  +---------+		  +---------+		  +---------+
 *
 *	  ^         ^		  ^         ^		  ^         ^
 *	  |         |		  |         |		  |         |
 *	 pcl       pch		 pcl       pch		 pcl       pch
 *
 *	For the vax we assert that samples will never fall in the first
 *	two bytes of any routine, since that is the entry mask,
 *	thus we give call alignentries() to adjust the entry points if
 *	the entry mask falls in one bucket but the code for the routine
 *	doesn't start until the next bucket.  In conjunction with the
 *	alignment of routine addresses, this should allow us to have
 *	only one sample for every four bytes of text space and never
 *	have any overlap (the two end cases, above).
 */
static void
asgnsamples(void)
{
	sztype		i, j;
	unsigned_UNIT	ccnt;
	double		time;
	pctype		pcl, pch;
	pctype		overlap;
	pctype		svalue0, svalue1;

	extern mod_info_t	modules;
	nltype		*nl = modules.nl;
	sztype		nname = modules.nname;

	/* read samples and assign to namelist symbols */
	scale = highpc - lowpc;
	scale /= nsamples;
	alignentries();
	for (i = 0, j = 1; i < nsamples; i++) {
		ccnt = samples[i];
		if (ccnt == 0)
			continue;
		/*LINTED: E_ASSIGMENT_CAUSE_LOSS_PREC*/
		pcl = lowpc + scale * i;
		/*LINTED: E_ASSIGMENT_CAUSE_LOSS_PREC*/
		pch = lowpc + scale * (i + 1);
		time = ccnt;
#ifdef DEBUG
		if (debug & SAMPLEDEBUG) {
			(void) printf(
			    "[asgnsamples] pcl 0x%llx pch 0x%llx ccnt %d\n",
			    pcl, pch, ccnt);
		}
#endif /* DEBUG */
		totime += time;
		for (j = (j ? j - 1 : 0); j < nname; j++) {
			svalue0 = nl[j].svalue;
			svalue1 = nl[j+1].svalue;
			/*
			 *	if high end of tick is below entry address,
			 *	go for next tick.
			 */
			if (pch < svalue0)
				break;
			/*
			 *	if low end of tick into next routine,
			 *	go for next routine.
			 */
			if (pcl >= svalue1)
				continue;
			overlap = min(pch, svalue1) - max(pcl, svalue0);
			if (overlap != 0) {
#ifdef DEBUG
				if (debug & SAMPLEDEBUG) {
					(void) printf("[asgnsamples] "
					    "(0x%llx->0x%llx-0x%llx) %s gets "
					    "%f ticks %lld overlap\n",
					    nl[j].value/sizeof (UNIT), svalue0,
					    svalue1, nl[j].name,
					    overlap * time / scale, overlap);
				}
#endif /* DEBUG */
				nl[j].time += overlap * time / scale;
			}
		}
	}
#ifdef DEBUG
	if (debug & SAMPLEDEBUG) {
		(void) printf("[asgnsamples] totime %f\n", totime);
	}
#endif /* DEBUG */
}


static void
dump_callgraph(FILE *fp, char *filename, unsigned long tarcs,
    unsigned long ncallees)
{
	ProfCallGraph		prof_cgraph;
	ProfFunction		prof_func;
	arctype	*arcp;
	mod_info_t		*mi;
	nltype			*nlp;
	size_t			cur_offset;
	unsigned long		caller_id = 0, callee_id = 0;

	/*
	 * Write the callgraph header
	 */
	prof_cgraph.type = PROF_CALLGRAPH_T;
	prof_cgraph.version = PROF_CALLGRAPH_VER;
	prof_cgraph.functions = PROFCGRAPH_SZ;
	prof_cgraph.size = PROFCGRAPH_SZ + tarcs * PROFFUNC_SZ;
	if (fwrite(&prof_cgraph, sizeof (ProfCallGraph), 1, fp) != 1) {
		perror(filename);
		exit(EX_IOERR);
	}
	/* CONSTCOND */
	if (CGRAPH_FILLER)
		(void) fseek(fp, CGRAPH_FILLER, SEEK_CUR);

	/* Current offset inside the callgraph object */
	cur_offset = prof_cgraph.functions;

	for (mi = &modules; mi; mi = mi->next) {
		for (nlp = mi->nl; nlp < mi->npe; nlp++) {
			if (nlp->ncallers == 0)
				continue;

			/* If this is the last callee, set next_to to 0 */
			callee_id++;
			if (callee_id == ncallees)
				prof_func.next_to = 0;
			else {
				prof_func.next_to = cur_offset +
				    nlp->ncallers * PROFFUNC_SZ;
			}

			/*
			 * Dump this callee's raw arc information with all
			 * its callers
			 */
			caller_id = 1;
			for (arcp = nlp->parents; arcp;
			    arcp = arcp->arc_parentlist) {
				/*
				 * If no more callers for this callee, set
				 * next_from to 0
				 */
				if (caller_id == nlp->ncallers)
					prof_func.next_from = 0;
				else {
					prof_func.next_from = cur_offset +
					    PROFFUNC_SZ;
				}

				prof_func.frompc =
				    arcp->arc_parentp->module->load_base +
				    (arcp->arc_parentp->value -
				    arcp->arc_parentp->module->txt_origin);
				prof_func.topc = mi->load_base +
				    (nlp->value - mi->txt_origin);
				prof_func.count = arcp->arc_count;


				if (fwrite(&prof_func, sizeof (ProfFunction),
				    1, fp) != 1) {
					perror(filename);
					exit(EX_IOERR);
				}
				/* CONSTCOND */
				if (FUNC_FILLER)
					(void) fseek(fp, FUNC_FILLER, SEEK_CUR);

				cur_offset += PROFFUNC_SZ;
				caller_id++;
			}
		} /* for nlp... */
	} /* for mi... */
}

/*
 * To save all pc-hits in all the gmon.out's is infeasible, as this
 * may become quite huge even with a small number of files to sum.
 * Instead, we'll dump *fictitious hits* to correct functions
 * by scanning module namelists. Again, since this is summing
 * pc-hits, we may have to dump the pcsamples out in chunks if the
 * number of pc-hits is high.
 */
static void
dump_hits(FILE *fp, char *filename, nltype *nlp)
{
	Address		*p, hitpc;
	size_t		i, nelem, ntowrite;

	if ((nelem = nlp->nticks) > PROF_BUFFER_SIZE)
		nelem = PROF_BUFFER_SIZE;

	if ((p = (Address *) calloc(nelem, sizeof (Address))) == NULL) {
		(void) fprintf(stderr, "%s: no room for %d pcsamples\n",
		    whoami, nelem);
		exit(EX_OSERR);
	}

	/*
	 * Set up *fictitious* hits (to function entry) buffer
	 */
	hitpc = nlp->module->load_base + (nlp->value - nlp->module->txt_origin);
	for (i = 0; i < nelem; i++)
		p[i] = hitpc;

	for (ntowrite = nlp->nticks; ntowrite >= nelem; ntowrite -= nelem) {
		if (fwrite(p, nelem * sizeof (Address), 1, fp) != 1) {
			perror(filename);
			exit(EX_IOERR);
		}
	}

	if (ntowrite) {
		if (fwrite(p, ntowrite * sizeof (Address), 1, fp) != 1) {
			perror(filename);
			exit(EX_IOERR);
		}
	}

	free(p);
}

static void
dump_pcsamples(FILE *fp, char *filename, unsigned long *tarcs,
    unsigned long *ncallees)
{
	ProfBuffer		prof_buffer;
	arctype	*arcp;
	mod_info_t		*mi;
	nltype			*nlp;

	prof_buffer.type = PROF_BUFFER_T;
	prof_buffer.version = PROF_BUFFER_VER;
	prof_buffer.buffer = PROFBUF_SZ;
	prof_buffer.bufsize = n_pcsamples;
	prof_buffer.size = PROFBUF_SZ + n_pcsamples * sizeof (Address);
	if (fwrite(&prof_buffer, sizeof (ProfBuffer), 1, fp) != 1) {
		perror(filename);
		exit(EX_IOERR);
	}
	/* CONSTCOND */
	if (BUF_FILLER)
		(void) fseek(fp, BUF_FILLER, SEEK_CUR);

	*tarcs = 0;
	*ncallees = 0;
	for (mi = &modules; mi; mi = mi->next) {
		for (nlp = mi->nl; nlp < mi->npe; nlp++) {
			if (nlp->nticks)
				dump_hits(fp, filename, nlp);

			nlp->ncallers = 0;
			for (arcp = nlp->parents; arcp;
			    arcp = arcp->arc_parentlist) {
				(nlp->ncallers)++;
			}

			if (nlp->ncallers) {
				(*tarcs) += nlp->ncallers;
				(*ncallees)++;
			}
		}
	}
}

static void
dump_modules(FILE *fp, char *filename, size_t pbuf_sz)
{
	char		*pbuf, *p;
	size_t		namelen;
	Index		off_nxt, off_path;
	mod_info_t	*mi;

	ProfModuleList	prof_modlist;
	ProfModule	prof_mod;

	/* Allocate for path strings buffer */
	pbuf_sz = CEIL(pbuf_sz, STRUCT_ALIGN);
	if ((p = pbuf = calloc(pbuf_sz, sizeof (char))) == NULL) {
		(void) fprintf(stderr, "%s: no room for %d bytes\n",
		    whoami, pbuf_sz * sizeof (char));
		exit(EX_OSERR);
	}

	/* Dump out PROF_MODULE_T info for all non-aout modules */
	prof_modlist.type = PROF_MODULES_T;
	prof_modlist.version = PROF_MODULES_VER;
	prof_modlist.modules = PROFMODLIST_SZ;
	prof_modlist.size = PROFMODLIST_SZ + (n_modules - 1) * PROFMOD_SZ +
	    pbuf_sz;
	if (fwrite(&prof_modlist, sizeof (ProfModuleList), 1, fp) != 1) {
		perror(filename);
		exit(EX_IOERR);
	}
	/* CONSTCOND */
	if (MODLIST_FILLER)
		(void) fseek(fp, MODLIST_FILLER, SEEK_CUR);

	/*
	 * Initialize offsets for ProfModule elements.
	 */
	off_nxt = PROFMODLIST_SZ + PROFMOD_SZ;
	off_path = PROFMODLIST_SZ + (n_modules - 1) * PROFMOD_SZ;

	for (mi = modules.next; mi; mi = mi->next) {
		if (mi->next)
			prof_mod.next = off_nxt;
		else
			prof_mod.next = 0;
		prof_mod.path = off_path;
		prof_mod.startaddr = mi->load_base;
		prof_mod.endaddr = mi->load_end;

		if (fwrite(&prof_mod, sizeof (ProfModule), 1, fp) != 1) {
			perror(filename);
			exit(EX_IOERR);
		}

		/* CONSTCOND */
		if (MOD_FILLER)
			(void) fseek(fp, MOD_FILLER, SEEK_CUR);

		(void) strcpy(p, mi->name);
		namelen = strlen(mi->name);
		p += namelen + 1;

		/* Note that offset to every path str need not be aligned */
		off_nxt += PROFMOD_SZ;
		off_path += namelen + 1;
	}

	/* Write out the module path strings */
	if (pbuf_sz) {
		if (fwrite(pbuf, pbuf_sz, 1, fp) != 1) {
			perror(filename);
			exit(EX_IOERR);
		}

		free(pbuf);
	}
}

/*
 * If we have inactive modules, their current load addresses may overlap with
 * active ones, and so we've to assign fictitious, non-overlapping addresses
 * to all modules before we dump them.
 */
static void
fixup_maps(size_t *pathsz)
{
	unsigned int	n_inactive = 0;
	Address		lbase = 0, lend;
	mod_info_t	*mi;

	/* Pick the lowest load address among modules */
	*pathsz = 0;
	for (mi = &modules; mi; mi = mi->next) {

		if (mi->active == FALSE)
			n_inactive++;

		if (mi == &modules || mi->load_base < lbase)
			lbase = mi->load_base;

		/*
		 * Return total path size of non-aout modules only
		 */
		if (mi != &modules)
			*pathsz = (*pathsz) + strlen(mi->name) + 1;
	}

	/*
	 * All module info is in fine shape already if there are no
	 * inactive modules
	 */
	if (n_inactive == 0)
		return;

	/*
	 * Assign fictitious load addresses to all (non-aout) modules so
	 * that sum info can be dumped out.
	 */
	for (mi = modules.next; mi; mi = mi->next) {
		lend = lbase + (mi->data_end - mi->txt_origin);
		if ((lbase < modules.load_base && lend < modules.load_base) ||
		    (lbase > modules.load_end && lend > modules.load_end)) {

			mi->load_base = lbase;
			mi->load_end = lend;

			/* just to give an appearance of reality */
			lbase = CEIL(lend + PGSZ, PGSZ);
		} else {
			/*
			 * can't use this lbase & lend pair, as it
			 * overlaps with aout's addresses
			 */
			mi->load_base = CEIL(modules.load_end + PGSZ, PGSZ);
			mi->load_end = mi->load_base + (lend - lbase);

			lbase = CEIL(mi->load_end + PGSZ, PGSZ);
		}
	}
}

static void
dump_gprofhdr(FILE *fp, char *filename)
{
	ProfHeader	prof_hdr;

	prof_hdr.h_magic = PROF_MAGIC;
	prof_hdr.h_major_ver = PROF_MAJOR_VERSION;
	prof_hdr.h_minor_ver = PROF_MINOR_VERSION;
	prof_hdr.size = PROFHDR_SZ;
	if (fwrite(&prof_hdr, sizeof (prof_hdr), 1, fp) != 1) {
		perror(filename);
		exit(EX_IOERR);
	}

	/* CONSTCOND */
	if (HDR_FILLER)
		(void) fseek(fp, HDR_FILLER, SEEK_CUR);
}

static void
dumpsum_ostyle(char *sumfile)
{
	nltype *nlp;
	arctype *arcp;
	struct rawarc arc;
	struct rawarc32 arc32;
	FILE *sfile;

	if ((sfile = fopen(sumfile, "w")) == NULL) {
		perror(sumfile);
		exit(EX_IOERR);
	}
	/*
	 * dump the header; use the last header read in
	 */
	if (Bflag) {
		if (fwrite(&h, sizeof (h), 1, sfile) != 1) {
			perror(sumfile);
			exit(EX_IOERR);
		}
	} else {
		struct hdr32 hdr;
		hdr.lowpc  = (pctype32)h.lowpc;
		hdr.highpc = (pctype32)h.highpc;
		hdr.ncnt   = (pctype32)h.ncnt;
		if (fwrite(&hdr, sizeof (hdr), 1, sfile) != 1) {
			perror(sumfile);
			exit(EX_IOERR);
		}
	}
	/*
	 * dump the samples
	 */
	if (fwrite(samples, sizeof (unsigned_UNIT), nsamples, sfile) !=
	    nsamples) {
		perror(sumfile);
		exit(EX_IOERR);
	}
	/*
	 * dump the normalized raw arc information. For old-style dumping,
	 * the only namelist is in modules.nl
	 */
	for (nlp = modules.nl; nlp < modules.npe; nlp++) {
		for (arcp = nlp->children; arcp;
		    arcp = arcp->arc_childlist) {
			if (Bflag) {
				arc.raw_frompc = arcp->arc_parentp->value;
				arc.raw_selfpc = arcp->arc_childp->value;
				arc.raw_count = arcp->arc_count;
				if (fwrite(&arc, sizeof (arc), 1, sfile) != 1) {
					perror(sumfile);
					exit(EX_IOERR);
				}
			} else {
				arc32.raw_frompc =
				    (pctype32)arcp->arc_parentp->value;
				arc32.raw_selfpc =
				    (pctype32)arcp->arc_childp->value;
				arc32.raw_count = (actype32)arcp->arc_count;
				if (fwrite(&arc32, sizeof (arc32), 1, sfile) !=
				    1) {
					perror(sumfile);
					exit(EX_IOERR);
				}
			}
#ifdef DEBUG
			if (debug & SAMPLEDEBUG) {
				(void) printf(
				    "[dumpsum_ostyle] frompc 0x%llx selfpc "
				    "0x%llx count %lld\n", arc.raw_frompc,
				    arc.raw_selfpc, arc.raw_count);
			}
#endif /* DEBUG */
		}
	}
	(void) fclose(sfile);
}

/*
 * dump out the gmon.sum file
 */
static void
dumpsum(char *sumfile)
{
	FILE		*sfile;
	size_t		pathbuf_sz;
	unsigned long	total_arcs;	/* total number of arcs in all */
	unsigned long	ncallees;	/* no. of callees with parents */

	if (old_style) {
		dumpsum_ostyle(sumfile);
		return;
	}

	if ((sfile = fopen(sumfile, "w")) == NULL) {
		perror(sumfile);
		exit(EX_IOERR);
	}

	/*
	 * Dump the new-style gprof header. Even if one of the original
	 * profiled-files was of a older version, the summed file is of
	 * current version only.
	 */
	dump_gprofhdr(sfile, sumfile);

	/*
	 * Fix up load-maps and dump out modules info
	 *
	 * Fix up module load maps so inactive modules get *some* address
	 * (and btw, could you get the total size of non-aout module path
	 * strings please ?)
	 */
	fixup_maps(&pathbuf_sz);
	dump_modules(sfile, sumfile, pathbuf_sz);


	/*
	 * Dump out the summ'd pcsamples
	 *
	 * For dumping call graph information later, we need certain
	 * statistics (like total arcs, number of callers for each node);
	 * collect these also while we are at it.
	 */
	dump_pcsamples(sfile, sumfile, &total_arcs, &ncallees);

	/*
	 * Dump out the summ'd call graph information
	 */
	dump_callgraph(sfile, sumfile, total_arcs, ncallees);


	(void) fclose(sfile);
}

static void
tally(mod_info_t *caller_mod, mod_info_t *callee_mod, struct rawarc *rawp)
{
	nltype		*parentp;
	nltype		*childp;

	/*
	 * if count == 0 this is a null arc and
	 * we don't need to tally it.
	 */
	if (rawp->raw_count == 0)
		return;

	/*
	 * Lookup the caller and callee pcs in namelists of
	 * appropriate modules
	 */
	parentp = nllookup(caller_mod, rawp->raw_frompc, NULL);
	childp = nllookup(callee_mod, rawp->raw_selfpc, NULL);
	if (childp && parentp) {
		if (!Dflag)
			childp->ncall += rawp->raw_count;
		else {
			if (first_file)
				childp->ncall += rawp->raw_count;
			else {
				childp->ncall -= rawp->raw_count;
				if (childp->ncall < 0)
					childp->ncall = 0;
			}
		}

#ifdef DEBUG
		if (debug & TALLYDEBUG) {
			(void) printf("[tally] arc from %s to %s traversed "
			    "%lld times\n", parentp->name,
			    childp->name, rawp->raw_count);
		}
#endif /* DEBUG */
		addarc(parentp, childp, rawp->raw_count);
	}
}

/*
 * Look up a module's base address in a sorted list of pc-hits. Unlike
 * nllookup(), this deals with misses by mapping them to the next *higher*
 * pc-hit. This is so that we get into the module's first pc-hit rightaway,
 * even if the module's entry-point (load_base) itself is not a hit.
 */
static Address *
locate(Address	*pclist, size_t nelem, Address keypc)
{
	size_t	low = 0, middle, high = nelem - 1;

	if (keypc <= pclist[low])
		return (pclist);

	if (keypc > pclist[high])
		return (NULL);

	while (low != high) {
		middle = (high + low) >> 1;

		if ((pclist[middle] < keypc) && (pclist[middle + 1] >= keypc))
			return (&pclist[middle + 1]);

		if (pclist[middle] >= keypc)
			high = middle;
		else
			low = middle + 1;
	}

	/* must never reach here! */
	return (NULL);
}

static void
assign_pcsamples(mod_info_t *module, Address *pcsmpl, size_t n_samples)
{
	Address		*pcptr, *pcse = pcsmpl + n_samples;
	pctype		nxt_func;
	nltype		*fnl;
	size_t		func_nticks;
#ifdef DEBUG
	size_t		n_hits_in_module = 0;
#endif /* DEBUG */

	/* Locate the first pc-hit for this module */
	if ((pcptr = locate(pcsmpl, n_samples, module->load_base)) == NULL) {
#ifdef DEBUG
		if (debug & PCSMPLDEBUG) {
			(void) printf("[assign_pcsamples] no pc-hits in\n");
			(void) printf(
			    "                   `%s'\n", module->name);
		}
#endif /* DEBUG */
		return;			/* no pc-hits in this module */
	}

	/* Assign all pc-hits in this module to appropriate functions */
	while ((pcptr < pcse) && (*pcptr < module->load_end)) {

		/* Update the corresponding function's time */
		fnl = nllookup(module, (pctype) *pcptr, &nxt_func);
		if (fnl != NULL) {
			/*
			 * Collect all pc-hits in this function. Each
			 * pc-hit counts as 1 tick.
			 */
			func_nticks = 0;
			while ((pcptr < pcse) && (*pcptr < nxt_func)) {
				func_nticks++;
				pcptr++;
			}

			if (func_nticks == 0)
				pcptr++;
			else {
				fnl->nticks += func_nticks;
				fnl->time += func_nticks;
				totime += func_nticks;
			}

#ifdef DEBUG
			n_hits_in_module += func_nticks;
#endif /* DEBUG */
		} else {
			/*
			 * pc sample could not be assigned to function;
			 * probably in a PLT
			 */
			pcptr++;
		}
	}

#ifdef DEBUG
	if (debug & PCSMPLDEBUG) {
		(void) printf(
		    "[assign_pcsamples] %ld hits in\n", n_hits_in_module);
		(void) printf("                   `%s'\n", module->name);
	}
#endif /* DEBUG */
}

int
pc_cmp(const void *arg1, const void *arg2)
{
	Address *pc1 = (Address *)arg1;
	Address *pc2 = (Address *)arg2;

	if (*pc1 > *pc2)
		return (1);

	if (*pc1 < *pc2)
		return (-1);

	return (0);
}

static void
process_pcsamples(ProfBuffer *bufp)
{
	Address		*pc_samples;
	mod_info_t	*mi;
	caddr_t		p;
	size_t		chunk_size, nelem_read, nelem_to_read;

#ifdef DEBUG
	if (debug & PCSMPLDEBUG) {
		(void) printf(
		    "[process_pcsamples] number of pcsamples = %lld\n",
		    bufp->bufsize);
	}
#endif /* DEBUG */

	/* buffer with no pc samples ? */
	if (bufp->bufsize == 0)
		return;

	/*
	 * If we're processing pcsamples of a profile sum, we could have
	 * more than PROF_BUFFER_SIZE number of samples. In such a case,
	 * we must read the pcsamples in chunks.
	 */
	if ((chunk_size = bufp->bufsize) > PROF_BUFFER_SIZE)
		chunk_size = PROF_BUFFER_SIZE;

	/* Allocate for the pcsample chunk */
	pc_samples = (Address *) calloc(chunk_size, sizeof (Address));
	if (pc_samples == NULL) {
		(void) fprintf(stderr, "%s: no room for %d sample pc's\n",
		    whoami, chunk_size);
		exit(EX_OSERR);
	}

	/* Copy the current set of pcsamples */
	nelem_read = 0;
	nelem_to_read = bufp->bufsize;
	p = (char *)bufp + bufp->buffer;

	while (nelem_read < nelem_to_read) {
		(void) memcpy((void *) pc_samples, p,
		    chunk_size * sizeof (Address));

		/* Sort the pc samples */
		qsort(pc_samples, chunk_size, sizeof (Address), pc_cmp);

		/*
		 * Assign pcsamples to functions in the currently active
		 * module list
		 */
		for (mi = &modules; mi; mi = mi->next) {
			if (mi->active == FALSE)
				continue;
			assign_pcsamples(mi, pc_samples, chunk_size);
		}

		p += (chunk_size * sizeof (Address));
		nelem_read += chunk_size;

		if ((nelem_to_read - nelem_read) < chunk_size)
			chunk_size = nelem_to_read - nelem_read;
	}

	free(pc_samples);

	/* Update total number of pcsamples read so far */
	n_pcsamples += bufp->bufsize;
}

static mod_info_t *
find_module(Address addr)
{
	mod_info_t	*mi;

	for (mi = &modules; mi; mi = mi->next) {
		if (mi->active == FALSE)
			continue;

		if (addr >= mi->load_base && addr < mi->load_end)
			return (mi);
	}

	return (NULL);
}

static void
process_cgraph(ProfCallGraph *cgp)
{
	struct rawarc	arc;
	mod_info_t	*callee_mi, *caller_mi;
	ProfFunction	*calleep, *callerp;
	Index		caller_off, callee_off;

	/*
	 * Note that *callee_off* increment in the for loop below
	 * uses *calleep* and *calleep* doesn't get set until the for loop
	 * is entered. We don't expect the increment to be executed before
	 * the loop body is executed atleast once, so this should be ok.
	 */
	for (callee_off = cgp->functions; callee_off;
	    callee_off = calleep->next_to) {

		/* LINTED: pointer cast */
		calleep = (ProfFunction *)((char *)cgp + callee_off);

		/*
		 * We could choose either to sort the {caller, callee}
		 * list twice and assign callee/caller to modules or inspect
		 * each callee/caller in the active modules list. Since
		 * the modules list is usually very small, we'l choose the
		 * latter.
		 */

		/*
		 * If we cannot identify a callee with a module, there's
		 * no use worrying about who called it.
		 */
		if ((callee_mi = find_module(calleep->topc)) == NULL) {
#ifdef DEBUG
			if (debug & CGRAPHDEBUG) {
				(void) printf(
				    "[process_cgraph] callee %#llx missed\n",
				    calleep->topc);
			}
#endif /* DEBUG */
			continue;
		} else
			arc.raw_selfpc = calleep->topc;

		for (caller_off = callee_off; caller_off;
		    caller_off = callerp->next_from)  {

			/* LINTED: pointer cast */
			callerp = (ProfFunction *)((char *)cgp + caller_off);
			if ((caller_mi = find_module(callerp->frompc)) ==
			    NULL) {
#ifdef DEBUG
				if (debug & CGRAPHDEBUG) {
					(void) printf(
					    "[process_cgraph] caller %#llx "
					    "missed\n", callerp->frompc);
				}
#endif /* DEBUG */
				continue;
			}

			arc.raw_frompc = callerp->frompc;
			arc.raw_count = callerp->count;

#ifdef DEBUG
			if (debug & CGRAPHDEBUG) {
				(void) printf(
				    "[process_cgraph] arc <%#llx, %#llx, "
				    "%lld>\n", arc.raw_frompc, arc.raw_selfpc,
				    arc.raw_count);
			}
#endif /* DEBUG */
			tally(caller_mi, callee_mi, &arc);
		}
	}

#ifdef DEBUG
	(void) puts("\n");
#endif /* DEBUG */
}

/*
 * Two modules overlap each other if they don't lie completely *outside*
 * each other.
 */
static bool
does_overlap(ProfModule *new, mod_info_t *old)
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
is_same_as_aout(char *modpath, struct stat *buf)
{
	if (stat(modpath, buf) == -1) {
		(void) fprintf(stderr, "%s: can't get info on `%s'\n",
		    whoami, modpath);
		exit(EX_NOINPUT);
	}

	if ((buf->st_dev == aout_info.dev) && (buf->st_ino == aout_info.ino))
		return (TRUE);
	else
		return (FALSE);
}

static void
process_modules(ProfModuleList *modlp)
{
	ProfModule	*newmodp;
	mod_info_t	*mi, *last, *new_module;
	char		*so_path;
	bool		more_modules = TRUE;
	struct stat	so_statbuf;

#ifdef DEBUG
	if (debug & MODULEDEBUG) {
		(void) printf("[process_modules] module obj version %u\n",
		    modlp->version);
	}
#endif /* DEBUG */

	/* Check version of module type object */
	if (modlp->version > PROF_MODULES_VER) {
		(void) fprintf(stderr, "%s: version %d for module type objects"
		    "is not supported\n", whoami, modlp->version);
		exit(EX_SOFTWARE);
	}


	/*
	 * Scan the PROF_MODULES_T list and add modules to current list
	 * of modules, if they're not present already
	 */
	/* LINTED: pointer cast */
	newmodp = (ProfModule *)((char *)modlp + modlp->modules);
	do {
		/*
		 * Since the prog could've been renamed after its run, we
		 * should see if this overlaps a.out. If it does, it is
		 * probably the renamed aout. We should also skip any other
		 * non-sharedobj's that we see (or should we report an error ?)
		 */
		so_path = (caddr_t)modlp + newmodp->path;
		if (does_overlap(newmodp, &modules) ||
		    is_same_as_aout(so_path, &so_statbuf) ||
		    (!is_shared_obj(so_path))) {

			if (!newmodp->next)
				more_modules = FALSE;

			/* LINTED: pointer cast */
			newmodp = (ProfModule *)
			    ((caddr_t)modlp + newmodp->next);
#ifdef DEBUG
			if (debug & MODULEDEBUG) {
				(void) printf(
				    "[process_modules] `%s'\n", so_path);
				(void) printf("                  skipped\n");
			}
#endif /* DEBUG */
			continue;
		}
#ifdef DEBUG
		if (debug & MODULEDEBUG)
			(void) printf("[process_modules] `%s'...\n", so_path);
#endif /* DEBUG */

		/*
		 * Check all modules (leave the first one, 'cos that
		 * is the program executable info). If this module is already
		 * there in the list, update the load addresses and proceed.
		 */
		last = &modules;
		while ((mi = last->next) != NULL) {
			/*
			 * We expect the full pathname for all shared objects
			 * needed by the program executable. In this case, we
			 * simply need to compare the paths to see if they are
			 * the same file.
			 */
			if (strcmp(mi->name, so_path) == 0)
				break;

			/*
			 * Check if this new shared object will overlap
			 * any existing module. If yes, remove the old one
			 * from the linked list (but don't free it, 'cos
			 * there may be symbols referring to this module
			 * still)
			 */
			if (does_overlap(newmodp, mi)) {
#ifdef DEBUG
				if (debug & MODULEDEBUG) {
					(void) printf(
					    "[process_modules] `%s'\n",
					    so_path);
					(void) printf(
					    "                  overlaps\n");
					(void) printf(
					    "                  `%s'\n",
					    mi->name);
				}
#endif /* DEBUG */
				mi->active = FALSE;
			}

			last = mi;
		}

		/* Module already there, skip it */
		if (mi != NULL) {
			mi->load_base = newmodp->startaddr;
			mi->load_end = newmodp->endaddr;
			mi->active = TRUE;
			if (!newmodp->next)
				more_modules = FALSE;

			/* LINTED: pointer cast */
			newmodp = (ProfModule *)
			    ((caddr_t)modlp + newmodp->next);

#ifdef DEBUG
			if (debug & MODULEDEBUG) {
				(void) printf("[process_modules] base=%#llx, "
				    "end=%#llx\n", mi->load_base, mi->load_end);
			}
#endif /* DEBUG */
			continue;
		}

		/*
		 * Check if gmon.out is outdated with respect to the new
		 * module we want to add
		 */
		if (gmonout_info.mtime < so_statbuf.st_mtime) {
			(void) fprintf(stderr,
			    "%s: shared obj outdates prof info\n", whoami);
			(void) fprintf(stderr, "\t(newer %s)\n", so_path);
			exit(EX_NOINPUT);
		}

		/* Create a new module element */
		new_module = malloc(sizeof (mod_info_t));
		if (new_module == NULL) {
			(void) fprintf(stderr, "%s: no room for %d bytes\n",
			    whoami, sizeof (mod_info_t));
			exit(EX_OSERR);
		}

		/* and fill in info... */
		new_module->id = n_modules + 1;
		new_module->load_base = newmodp->startaddr;
		new_module->load_end = newmodp->endaddr;
		new_module->name = malloc(strlen(so_path) + 1);
		if (new_module->name == NULL) {
			(void) fprintf(stderr, "%s: no room for %d bytes\n",
			    whoami, strlen(so_path) + 1);
			exit(EX_OSERR);
		}
		(void) strcpy(new_module->name, so_path);
#ifdef DEBUG
		if (debug & MODULEDEBUG) {
			(void) printf(
			    "[process_modules] base=%#llx, end=%#llx\n",
			    new_module->load_base, new_module->load_end);
		}
#endif /* DEBUG */

		/* Create this module's nameslist */
		process_namelist(new_module);

		/* Add it to the tail of active module list */
		last->next = new_module;
		n_modules++;

#ifdef DEBUG
		if (debug & MODULEDEBUG) {
			(void) printf(
			    "[process_modules] total shared objects = %ld\n",
			    n_modules - 1);
		}
#endif /* DEBUG */
		/*
		 * Move to the next module in the PROF_MODULES_T list
		 * (if present)
		 */
		if (!newmodp->next)
			more_modules = FALSE;

		/* LINTED: pointer cast */
		newmodp = (ProfModule *)((caddr_t)modlp + newmodp->next);

	} while (more_modules);
}

static void
reset_active_modules(void)
{
	mod_info_t	*mi;

	/* Except the executable, no other module should remain active */
	for (mi = modules.next; mi; mi = mi->next)
		mi->active = FALSE;
}

static void
getpfiledata(caddr_t memp, size_t fsz)
{
	ProfObject	*objp;
	caddr_t		file_end;
	bool		found_pcsamples = FALSE, found_cgraph = FALSE;

	/*
	 * Before processing a new gmon.out, all modules except the
	 * program executable must be made inactive, so that symbols
	 * are searched only in the program executable, if we don't
	 * find a MODULES_T object. Don't do it *after* we read a gmon.out,
	 * because we need the active module data after we're done with
	 * the last gmon.out, if we're doing summing.
	 */
	reset_active_modules();

	file_end = memp + fsz;
	/* LINTED: pointer cast */
	objp = (ProfObject *)(memp + ((ProfHeader *)memp)->size);
	while ((caddr_t)objp < file_end) {
#ifdef DEBUG
		{
			unsigned int	type = 0;

			if (debug & MONOUTDEBUG) {
				if (objp->type <= MAX_OBJTYPES)
					type = objp->type;

				(void) printf(
				    "\n[getpfiledata] object %s [%#lx]\n",
				    objname[type], objp->type);
			}
		}
#endif /* DEBUG */
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
				(void) fprintf(stderr,
				    "%s: unknown prof object type=%d\n",
				    whoami, objp->type);
				exit(EX_SOFTWARE);
		}
		/* LINTED: pointer cast */
		objp = (ProfObject *)((caddr_t)objp + objp->size);
	}

	if (!found_cgraph || !found_pcsamples) {
		(void) fprintf(stderr,
		    "%s: missing callgraph/pcsamples object\n", whoami);
		exit(EX_SOFTWARE);
	}

	if ((caddr_t)objp > file_end) {
		(void) fprintf(stderr, "%s: malformed profile file.\n", whoami);
		exit(EX_SOFTWARE);
	}

	if (first_file)
		first_file = FALSE;
}

static void
readarcs(FILE *pfile)
{
	/*
	 *	the rest of the file consists of
	 *	a bunch of <from,self,count> tuples.
	 */
	/* CONSTCOND */
	while (1) {
		struct rawarc	arc;

		if (rflag) {
			if (Bflag) {
				L_cgarc64		rtld_arc64;

				/*
				 * If rflag is set then this is an profiled
				 * image generated by rtld.  It needs to be
				 * 'converted' to the standard data format.
				 */
				if (fread(&rtld_arc64,
				    sizeof (L_cgarc64), 1, pfile) != 1)
					break;

				if (rtld_arc64.cg_from == PRF_OUTADDR64)
					arc.raw_frompc = s_highpc + 0x10;
				else
					arc.raw_frompc =
					    (pctype)rtld_arc64.cg_from;
				arc.raw_selfpc = (pctype)rtld_arc64.cg_to;
				arc.raw_count = (actype)rtld_arc64.cg_count;
			} else {
				L_cgarc		rtld_arc;

				/*
				 * If rflag is set then this is an profiled
				 * image generated by rtld.  It needs to be
				 * 'converted' to the standard data format.
				 */
				if (fread(&rtld_arc,
				    sizeof (L_cgarc), 1, pfile) != 1)
					break;

				if (rtld_arc.cg_from == PRF_OUTADDR)
					arc.raw_frompc = s_highpc + 0x10;
				else
					arc.raw_frompc = (pctype)
					    (uintptr_t)rtld_arc.cg_from;
				arc.raw_selfpc = (pctype)
				    (uintptr_t)rtld_arc.cg_to;
				arc.raw_count = (actype)rtld_arc.cg_count;
			}
		} else {
			if (Bflag) {
				if (fread(&arc, sizeof (struct rawarc), 1,
				    pfile) != 1) {
					break;
				}
			} else {
				/*
				 * If these aren't big %pc's, we need to read
				 * into the 32-bit raw arc structure, and
				 * assign the members into the actual arc.
				 */
				struct rawarc32 arc32;
				if (fread(&arc32, sizeof (struct rawarc32),
				    1, pfile) != 1)
					break;
				arc.raw_frompc = (pctype)arc32.raw_frompc;
				arc.raw_selfpc = (pctype)arc32.raw_selfpc;
				arc.raw_count  = (actype)arc32.raw_count;
			}
		}

#ifdef DEBUG
		if (debug & SAMPLEDEBUG) {
			(void) printf("[getpfile] frompc 0x%llx selfpc "
			    "0x%llx count %lld\n", arc.raw_frompc,
			    arc.raw_selfpc, arc.raw_count);
		}
#endif /* DEBUG */
		/*
		 *	add this arc
		 */
		tally(&modules, &modules, &arc);
	}
	if (first_file)
		first_file = FALSE;
}

static void
readsamples(FILE *pfile)
{
	sztype		i;
	unsigned_UNIT	sample;

	if (samples == 0) {
		samples = (unsigned_UNIT *) calloc(nsamples,
		    sizeof (unsigned_UNIT));
		if (samples == 0) {
			(void) fprintf(stderr,
			    "%s: No room for %d sample pc's\n",
			    whoami, sampbytes / sizeof (unsigned_UNIT));
			exit(EX_OSERR);
		}
	}

	for (i = 0; i < nsamples; i++) {
		(void) fread(&sample, sizeof (unsigned_UNIT), 1, pfile);
		if (feof(pfile))
			break;
		samples[i] += sample;
	}
	if (i != nsamples) {
		(void) fprintf(stderr,
		    "%s: unexpected EOF after reading %d/%d samples\n",
		    whoami, --i, nsamples);
		exit(EX_IOERR);
	}
}

static void *
handle_versioned(FILE *pfile, char *filename, size_t *fsz)
{
	int		fd;
	bool		invalid_version;
	caddr_t		fmem;
	struct stat	buf;
	ProfHeader	prof_hdr;
	off_t		lret;

	/*
	 * Check versioning info. For now, let's say we provide
	 * backward compatibility, so we accept all older versions.
	 */
	if (fread(&prof_hdr, sizeof (ProfHeader), 1, pfile) == 0) {
		perror("fread()");
		exit(EX_IOERR);
	}

	invalid_version = FALSE;
	if (prof_hdr.h_major_ver > PROF_MAJOR_VERSION)
		invalid_version = TRUE;
	else if (prof_hdr.h_major_ver == PROF_MAJOR_VERSION) {
		if (prof_hdr.h_minor_ver > PROF_MINOR_VERSION)
			invalid_version = FALSE;
	}

	if (invalid_version) {
		(void) fprintf(stderr, "%s: version %d.%d not supported\n",
		    whoami, prof_hdr.h_major_ver, prof_hdr.h_minor_ver);
		exit(EX_SOFTWARE);
	}

	/*
	 * Map gmon.out onto memory.
	 */
	(void) fclose(pfile);
	if ((fd = open(filename, O_RDONLY)) == -1) {
		perror(filename);
		exit(EX_IOERR);
	}

	if ((lret = lseek(fd, 0, SEEK_END)) == -1) {
		perror(filename);
		exit(EX_IOERR);
	}
	*fsz = lret;

	fmem = mmap(0, *fsz, PROT_READ, MAP_PRIVATE, fd, 0);
	if (fmem == MAP_FAILED) {
		(void) fprintf(stderr, "%s: can't map %s\n", whoami, filename);
		exit(EX_IOERR);
	}

	/*
	 * Before we close this fd, save this gmon.out's info to later verify
	 * if the shared objects it references have changed since the time
	 * they were used to generate this gmon.out
	 */
	if (fstat(fd, &buf) == -1) {
		(void) fprintf(stderr, "%s: can't get info on `%s'\n",
		    whoami, filename);
		exit(EX_NOINPUT);
	}
	gmonout_info.dev = buf.st_dev;
	gmonout_info.ino = buf.st_ino;
	gmonout_info.mtime = buf.st_mtime;
	gmonout_info.size = buf.st_size;

	(void) close(fd);

	return ((void *) fmem);
}

static void *
openpfile(char *filename, size_t *fsz)
{
	struct hdr	tmp;
	FILE		*pfile;
	unsigned long	magic_num;
	size_t		hdrsize;
	static bool	first_time = TRUE;
	extern bool	old_style;

	if ((pfile = fopen(filename, "r")) == NULL) {
		perror(filename);
		exit(EX_IOERR);
	}

	/*
	 * Read in the magic. Note that we changed the cast "unsigned long"
	 * to "unsigned int" because that's how h_magic is defined in the
	 * new format ProfHeader.
	 */
	if (fread(&magic_num, sizeof (unsigned int), 1, pfile) == 0) {
		perror("fread()");
		exit(EX_IOERR);
	}

	rewind(pfile);

	/*
	 * First check if this is versioned or *old-style* gmon.out
	 */
	if (magic_num == (unsigned int)PROF_MAGIC) {
		if ((!first_time) && (old_style == TRUE)) {
			(void) fprintf(stderr, "%s: can't mix old & new format "
			    "profiled files\n", whoami);
			exit(EX_SOFTWARE);
		}
		first_time = FALSE;
		old_style = FALSE;
		return (handle_versioned(pfile, filename, fsz));
	}

	if ((!first_time) && (old_style == FALSE)) {
		(void) fprintf(stderr, "%s: can't mix old & new format "
		    "profiled files\n", whoami);
		exit(EX_SOFTWARE);
	}

	first_time = FALSE;
	old_style = TRUE;
	fsz = 0;

	/*
	 * Now, we need to determine if this is a run-time linker
	 * profiled file or if it is a standard gmon.out.
	 *
	 * We do this by checking if magic matches PRF_MAGIC. If it
	 * does, then this is a run-time linker profiled file, if it
	 * doesn't, it must be a gmon.out file.
	 */
	if (magic_num == (unsigned long)PRF_MAGIC)
		rflag = TRUE;
	else
		rflag = FALSE;

	hdrsize = Bflag ? sizeof (struct hdr) : sizeof (struct hdr32);

	if (rflag) {
		if (Bflag) {
			L_hdr64		l_hdr64;

			/*
			 * If the rflag is set then the input file is
			 * rtld profiled data, we'll read it in and convert
			 * it to the standard format (ie: make it look like
			 * a gmon.out file).
			 */
			if (fread(&l_hdr64, sizeof (L_hdr64), 1, pfile) == 0) {
				perror("fread()");
				exit(EX_IOERR);
			}
			if (l_hdr64.hd_version != PRF_VERSION_64) {
				(void) fprintf(stderr,
				    "%s: expected version %d, "
				    "got version %d when processing 64-bit "
				    "run-time linker profiled file.\n",
				    whoami, PRF_VERSION_64, l_hdr64.hd_version);
				exit(EX_SOFTWARE);
			}
			tmp.lowpc = 0;
			tmp.highpc = (pctype)l_hdr64.hd_hpc;
			tmp.ncnt = hdrsize + l_hdr64.hd_psize;
		} else {
			L_hdr		l_hdr;

			/*
			 * If the rflag is set then the input file is
			 * rtld profiled data, we'll read it in and convert
			 * it to the standard format (ie: make it look like
			 * a gmon.out file).
			 */
			if (fread(&l_hdr, sizeof (L_hdr), 1, pfile) == 0) {
				perror("fread()");
				exit(EX_IOERR);
			}
			if (l_hdr.hd_version != PRF_VERSION) {
				(void) fprintf(stderr,
				    "%s: expected version %d, "
				    "got version %d when processing "
				    "run-time linker profiled file.\n",
				    whoami, PRF_VERSION, l_hdr.hd_version);
				exit(EX_SOFTWARE);
			}
			tmp.lowpc = 0;
			tmp.highpc = (pctype)(uintptr_t)l_hdr.hd_hpc;
			tmp.ncnt = hdrsize + l_hdr.hd_psize;
		}
	} else {
		if (Bflag) {
			if (fread(&tmp, sizeof (struct hdr), 1, pfile) == 0) {
				perror("fread()");
				exit(EX_IOERR);
			}
		} else {
			/*
			 * If we're not reading big %pc's, we need to read
			 * the 32-bit header, and assign the members to
			 * the actual header.
			 */
			struct hdr32 hdr32;
			if (fread(&hdr32, sizeof (hdr32), 1, pfile) == 0) {
				perror("fread()");
				exit(EX_IOERR);
			}
			tmp.lowpc = hdr32.lowpc;
			tmp.highpc = hdr32.highpc;
			tmp.ncnt = hdr32.ncnt;
		}
	}

	/*
	 * perform sanity check on profiled file we've opened.
	 */
	if (tmp.lowpc >= tmp.highpc) {
		if (rflag)
			(void) fprintf(stderr,
			    "%s: badly formed profiled data.\n",
			    filename);
		else
			(void) fprintf(stderr,
			    "%s: badly formed gmon.out file.\n",
			    filename);
		exit(EX_SOFTWARE);
	}

	if (s_highpc != 0 && (tmp.lowpc != h.lowpc ||
	    tmp.highpc != h.highpc || tmp.ncnt != h.ncnt)) {
		(void) fprintf(stderr,
		    "%s: incompatible with first gmon file\n",
		    filename);
		exit(EX_IOERR);
	}
	h = tmp;
	s_lowpc = h.lowpc;
	s_highpc = h.highpc;
	lowpc = h.lowpc / sizeof (UNIT);
	highpc = h.highpc / sizeof (UNIT);
	sampbytes = h.ncnt > hdrsize ? h.ncnt - hdrsize : 0;
	nsamples = sampbytes / sizeof (unsigned_UNIT);

#ifdef DEBUG
	if (debug & SAMPLEDEBUG) {
		(void) printf("[openpfile] hdr.lowpc 0x%llx hdr.highpc "
		    "0x%llx hdr.ncnt %lld\n",
		    h.lowpc, h.highpc, h.ncnt);
		(void) printf(
		    "[openpfile]   s_lowpc 0x%llx   s_highpc 0x%llx\n",
		    s_lowpc, s_highpc);
		(void) printf(
		    "[openpfile]     lowpc 0x%llx     highpc 0x%llx\n",
		    lowpc, highpc);
		(void) printf("[openpfile] sampbytes %d nsamples %d\n",
		    sampbytes, nsamples);
	}
#endif /* DEBUG */

	return ((void *) pfile);
}

/*
 * Information from a gmon.out file depends on whether it's versioned
 * or non-versioned, *old style* gmon.out. If old-style, it is in two
 * parts : an array of sampling hits within pc ranges, and the arcs. If
 * versioned, it contains a header, followed by any number of
 * modules/callgraph/pcsample_buffer objects.
 */
static void
getpfile(char *filename)
{
	void		*handle;
	size_t		fsz;

	handle = openpfile(filename, &fsz);

	if (old_style) {
		readsamples((FILE *)handle);
		readarcs((FILE *)handle);
		(void) fclose((FILE *)handle);
		return;
	}

	getpfiledata((caddr_t)handle, fsz);
	(void) munmap(handle, fsz);
}

int
main(int argc, char **argv)
{
	char	**sp;
	nltype	**timesortnlp;
	int		c;
	int		errflg;

	prog_name = *argv;  /* preserve program name */
	debug = 0;
	nflag = FALSE;
	bflag = TRUE;
	lflag = FALSE;
	Cflag = FALSE;
	first_file = TRUE;
	rflag = FALSE;
	Bflag = FALSE;
	errflg = FALSE;

	while ((c = getopt(argc, argv, "abd:CcDE:e:F:f:ln:sz")) != EOF)
		switch (c) {
		case 'a':
			aflag = TRUE;
			break;
		case 'b':
			bflag = FALSE;
			break;
		case 'c':
			cflag = TRUE;
			break;
		case 'C':
			Cflag = TRUE;
			break;
		case 'd':
			dflag = TRUE;
			debug |= atoi(optarg);
			(void) printf("[main] debug = 0x%x\n", debug);
			break;
		case 'D':
			Dflag = TRUE;
			break;
		case 'E':
			addlist(Elist, optarg);
			Eflag = TRUE;
			addlist(elist, optarg);
			eflag = TRUE;
			break;
		case 'e':
			addlist(elist, optarg);
			eflag = TRUE;
			break;
		case 'F':
			addlist(Flist, optarg);
			Fflag = TRUE;
			addlist(flist, optarg);
			fflag = TRUE;
			break;
		case 'f':
			addlist(flist, optarg);
			fflag = TRUE;
			break;
		case 'l':
			lflag = TRUE;
			break;
		case 'n':
			nflag = TRUE;
			number_funcs_toprint = atoi(optarg);
			break;
		case 's':
			sflag = TRUE;
			break;
		case 'z':
			zflag = TRUE;
			break;
		case '?':
			errflg++;

		}

	if (errflg) {
		(void) fprintf(stderr,
		    "usage: gprof [ -abcCDlsz ] [ -e function-name ] "
		    "[ -E function-name ]\n\t[ -f function-name ] "
		    "[ -F function-name  ]\n\t[  image-file  "
		    "[ profile-file ... ] ]\n");
		exit(EX_USAGE);
	}

	if (optind < argc) {
		a_outname  = argv[optind++];
	} else {
		a_outname  = A_OUTNAME;
	}
	if (optind < argc) {
		gmonname = argv[optind++];
	} else {
		gmonname = GMONNAME;
	}
	/*
	 *	turn off default functions
	 */
	for (sp = &defaultEs[0]; *sp; sp++) {
		Eflag = TRUE;
		addlist(Elist, *sp);
		eflag = TRUE;
		addlist(elist, *sp);
	}
	/*
	 *	how many ticks per second?
	 *	if we can't tell, report time in ticks.
	 */
	hz = sysconf(_SC_CLK_TCK);
	if (hz == -1) {
		hz = 1;
		(void) fprintf(stderr, "time is in ticks, not seconds\n");
	}

	getnfile(a_outname);

	/*
	 *	get information about mon.out file(s).
	 */
	do {
		getpfile(gmonname);
		if (optind < argc)
			gmonname = argv[optind++];
		else
			optind++;
	} while (optind <= argc);
	/*
	 *	dump out a gmon.sum file if requested
	 */
	if (sflag || Dflag)
		dumpsum(GMONSUM);

	if (old_style) {
		/*
		 *	assign samples to procedures
		 */
		asgnsamples();
	}

	/*
	 *	assemble the dynamic profile
	 */
	timesortnlp = doarcs();

	/*
	 *	print the dynamic profile
	 */
#ifdef DEBUG
	if (debug & ANYDEBUG) {
		/* raw output of all symbols in all their glory */
		int i;
		(void) printf(" Name, pc_entry_pt, svalue, tix_in_routine, "
		    "#calls, selfcalls, index \n");
		for (i = 0; i < modules.nname; i++) {	/* Print each symbol */
			if (timesortnlp[i]->name)
				(void) printf(" %s ", timesortnlp[i]->name);
			else
				(void) printf(" <cycle> ");
			(void) printf(" %lld ", timesortnlp[i]->value);
			(void) printf(" %lld ", timesortnlp[i]->svalue);
			(void) printf(" %f ", timesortnlp[i]->time);
			(void) printf(" %lld ", timesortnlp[i]->ncall);
			(void) printf(" %lld ", timesortnlp[i]->selfcalls);
			(void) printf(" %d ", timesortnlp[i]->index);
			(void) printf(" \n");
		}
	}
#endif /* DEBUG */

	printgprof(timesortnlp);
	/*
	 *	print the flat profile
	 */
	printprof();
	/*
	 *	print the index
	 */
	printindex();

	/*
	 * print the modules
	 */
	printmodules();

	done();
	/* NOTREACHED */
	return (0);
}
