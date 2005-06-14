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
 *	Copyright 2001-2003 Sun Microsystems, Inc.  All rights reserved.
 *	Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <stdio.h>
#include <strings.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <libc_int.h>
#include <_rtld.h>
#include <_elf.h>
#include <conv.h>
#include <msg.h>
#include <debug.h>


static void (*	fptr_tls_modadd)(TLS_modinfo *) = 0;
static void (*	fptr_tls_modrem)(TLS_modinfo *) = 0;
static void (*	fptr_tls_statmods)(TLS_modinfo **, unsigned long) = 0;

static int	tlsinitialized = 0;
static unsigned long tls_static_size = 0;	/* static TLS buffer size */

#define	TLSBLOCKCNT	16	/* number of blocks of tmi_bits to allocate */
				/* at a time. */
typedef struct {
	uint_t	*tmi_bits;
	ulong_t	tmi_lowfree;
	ulong_t	tmi_cnt;
} Tlsmodid;

static Tlsmodid	tmid = {0, 0, 0};

unsigned long
tls_getmodid()
{
	ulong_t		ndx;
	ulong_t		i;

	if (tmid.tmi_bits == 0) {
		if ((tmid.tmi_bits =
		    (uint_t *)calloc(TLSBLOCKCNT, sizeof (uint_t))) == 0)
			return ((unsigned long)-1);
		tmid.tmi_bits[0] = 1;
		tmid.tmi_lowfree = 1;
		tmid.tmi_cnt = TLSBLOCKCNT;
		return (0);
	}

	for (i = tmid.tmi_lowfree / (sizeof (uint_t) * 8);
	    i < tmid.tmi_cnt; i++) {
		uint_t	j;
		/*
		 * If all bits are assigned - move on.
		 */
		if ((tmid.tmi_bits[i] ^ ~((uint_t)0)) == 0)
			continue;
		for (ndx = 0, j = 1; j; j = j << 1, ndx++) {
			if ((tmid.tmi_bits[i] & j) == 0) {
				tmid.tmi_bits[i] |= j;
				ndx = (i * (sizeof (uint_t)) * 8) + ndx;
				tmid.tmi_lowfree = ndx + 1;
				return (ndx);
			}
		}
	}

	/*
	 * All bits taken - must allocate a new block
	 */
	if ((tmid.tmi_bits = (uint_t *)realloc(tmid.tmi_bits,
	    ((tmid.tmi_cnt * sizeof (uint_t)) +
	    (TLSBLOCKCNT * sizeof (uint_t))))) == 0)
		return ((unsigned long)-1);
	/*
	 * clear out the tail of the new allocation
	 */
	bzero(&(tmid.tmi_bits[tmid.tmi_cnt]), TLSBLOCKCNT * sizeof (uint_t));
	tmid.tmi_bits[tmid.tmi_cnt] = 1;
	ndx = (tmid.tmi_cnt * sizeof (uint_t)) * 8;
	tmid.tmi_lowfree = ndx + 1;
	tmid.tmi_cnt += TLSBLOCKCNT;

	return (ndx);
}


void
tls_freemodid(unsigned long modid)
{
	ulong_t	i;
	uint_t	j;

	i = modid / (sizeof (uint_t) * 8);
	/* LINTED */
	j = modid % (sizeof (uint_t) * 8);
	j = ~(1 << j);
	tmid.tmi_bits[i] &= j;
	if (modid < tmid.tmi_lowfree)
		tmid.tmi_lowfree = modid;
}


void
tls_setroutines(Lm_list *lml, void * modadd, void * modrem, void * statmod)
{
	/*
	 * If a version of libc/libthread gives us only a subset
	 * of the TLS interfaces - it's confused and we discard
	 * the whole lot.
	 */
	if (!modadd || !modrem || !statmod)
		return;

	if ((fptr_tls_modadd == 0) || (lml->lm_flags & LML_FLG_BASELM))
		fptr_tls_modadd = (void(*)(TLS_modinfo *)) modadd;
	if ((fptr_tls_modrem == 0) || (lml->lm_flags & LML_FLG_BASELM))
		fptr_tls_modrem = (void(*)(TLS_modinfo *)) modrem;
	/*
	 * The 'statmods' interface is only relevent for the
	 * primary link-map - ignore all other instances.
	 */
	if (lml->lm_flags & LML_FLG_BASELM)
		fptr_tls_statmods =
			(void(*)(TLS_modinfo **, unsigned long)) statmod;
}


void
tls_modactivity(Rt_map * lmp, uint_t flag)
{
	TLS_modinfo	tmi;
	Phdr *		tlsphdr;
	void (*		fptr)(TLS_modinfo *);

	if (flag & TM_FLG_MODADD)
		fptr = fptr_tls_modadd;
	else
		fptr = fptr_tls_modrem;

	/*
	 * We only report TLS modactivity for the primary link-map
	 * after all the objects have been loaded and we've reported
	 * the STATIC tls modlist (see tls_report_modules()).
	 */
	if (((tlsinitialized == 0) &&
	    (LIST(lmp)->lm_flags & LML_FLG_BASELM)) ||
	    (fptr == 0) || (lmp == 0) || (FCT(lmp) != &elf_fct) ||
	    (PTTLS(lmp) == 0))
		return;

	tlsphdr = PTTLS(lmp);

	bzero(&tmi, sizeof (tmi));
	tmi.tm_modname = PATHNAME(lmp);
	tmi.tm_modid = TLSMODID(lmp);
	tmi.tm_tlsblock = (void *)(tlsphdr->p_vaddr);
	if (!(FLAGS(lmp) & FLG_RT_FIXED))
		tmi.tm_tlsblock = (void *)((uintptr_t)tmi.tm_tlsblock +
			ADDR(lmp));
	tmi.tm_filesz = tlsphdr->p_filesz;
	tmi.tm_memsz = tlsphdr->p_memsz;
	tmi.tm_flags = 0;
	tmi.tm_stattlsoffset = 0;

	DBG_CALL(Dbg_tls_modactivity(&tmi, flag));
	fptr(&tmi);

	/*
	 * Free up the moduleid
	 */
	if (flag & TM_FLG_MODREM)
		tls_freemodid(TLSMODID(lmp));
}


void
tls_assign_soffset(Rt_map * lmp)
{
	if (PTTLS(lmp) == 0)
		return;

	/*
	 * Only objects on the primary link-map list are associated
	 * with the STATIC tls block.
	 */
	if (LIST(lmp)->lm_flags & LML_FLG_BASELM) {
		tls_static_size += S_ROUND(PTTLS(lmp)->p_memsz, M_TLSSTATALIGN);
		TLSSTATOFF(lmp) = tls_static_size;
	}

	/*
	 * Everyone get's a dynamic TLS modid
	 */
	TLSMODID(lmp) = tls_getmodid();
}

int
tls_report_modules()
{
	Rt_map *	lmp;
	uint_t		tlsmodcnt;
	uint_t		tlsmodndx;
	TLS_modinfo **	tlsmodlist;
	TLS_modinfo *	tlsbuflist;
	Phdr *		tlsphdr;

	tlsinitialized++;
	/*
	 * Scan through all objects to determine how many have TLS
	 * storage.
	 */
	tlsmodcnt = 0;
	for (lmp = lml_main.lm_head; lmp; lmp = (Rt_map *)NEXT(lmp)) {
		if ((FCT(lmp) != &elf_fct) ||
		    (PTTLS(lmp) == 0) || (PTTLS(lmp)->p_memsz == 0))
			continue;
		tlsmodcnt++;

		if (fptr_tls_statmods)
			continue;

		/*
		 * If a module has TLS - but the TLS interfaces
		 * are not present (no libthread?). Then this is
		 * a fatal condition.
		 */
		eprintf(ERR_FATAL, MSG_INTL(MSG_ERR_TLS_NOTLS),
		    NAME(lmp));
		return (0);
	}

	/*
	 * If we don't have any TLS modules - report that and return.
	 */
	if (tlsmodcnt == 0) {
		if (fptr_tls_statmods != 0)
			fptr_tls_statmods(0, 0);
		return (1);
	}

	/*
	 * Allocate a buffer to report the TLS modules, the buffer consists of:
	 *
	 *	TLS_modinfo *	ptrs[tlsmodcnt + 1]
	 *	TLS_modinfo	bufs[tlsmodcnt]
	 *
	 * The ptrs are initialized to the bufs - except the last
	 * one which null terminates the array.
	 */
	if ((tlsmodlist = calloc((sizeof (TLS_modinfo *) * tlsmodcnt + 1) +
	    (sizeof (TLS_modinfo) * tlsmodcnt), 1)) == 0)
		return (0);

	tlsbuflist = (TLS_modinfo *)((uintptr_t)tlsmodlist +
		((tlsmodcnt + 1) * sizeof (TLS_modinfo *)));
	for (tlsmodndx = 0; tlsmodndx < tlsmodcnt; tlsmodndx++)
		tlsmodlist[tlsmodndx] = &tlsbuflist[tlsmodndx];

	/*
	 * Account for the initial dtv ptr in the TLSSIZE calculation.
	 */
	tlsmodndx = 0;
	for (lmp = lml_main.lm_head; lmp; lmp = (Rt_map *)NEXT(lmp)) {
		if ((FCT(lmp) != &elf_fct) ||
		    (PTTLS(lmp) == 0) || (PTTLS(lmp)->p_memsz == 0))
			continue;

		tlsphdr = PTTLS(lmp);

		tlsmodlist[tlsmodndx]->tm_modname = PATHNAME(lmp);
		tlsmodlist[tlsmodndx]->tm_modid = TLSMODID(lmp);
		tlsmodlist[tlsmodndx]->tm_tlsblock =
			(void *)(tlsphdr->p_vaddr);
		if (!(FLAGS(lmp) & FLG_RT_FIXED))
			tlsmodlist[tlsmodndx]->tm_tlsblock =
				(void *)((uintptr_t)tlsmodlist[
				tlsmodndx]->tm_tlsblock + ADDR(lmp));
		tlsmodlist[tlsmodndx]->tm_filesz = tlsphdr->p_filesz;
		tlsmodlist[tlsmodndx]->tm_memsz = tlsphdr->p_memsz;
		tlsmodlist[tlsmodndx]->tm_flags = TM_FLG_STATICTLS;
		tlsmodlist[tlsmodndx]->tm_stattlsoffset =
			TLSSTATOFF(lmp);
		tlsmodndx++;
	}

	DBG_CALL(Dbg_tls_static_block((void *)tlsmodlist, tls_static_size));
	fptr_tls_statmods(tlsmodlist, tls_static_size);

	/*
	 * We're done with the list - clean it up.
	 */
	free(tlsmodlist);
	return (1);
}
