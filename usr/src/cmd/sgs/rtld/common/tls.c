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

#include <stdio.h>
#include <strings.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <libc_int.h>
#include <_rtld.h>
#include <_elf.h>
#include <msg.h>
#include <debug.h>

#define	TLSBLOCKCNT	16	/* number of blocks of tmi_bits to allocate */
				/* at a time. */
typedef struct {
	uint_t	*tmi_bits;
	ulong_t	tmi_lowfree;
	ulong_t	tmi_cnt;
} Tlsmodid;

static Tlsmodid	tmid = {0, 0, 0};

static ulong_t
tls_getmodid()
{
	ulong_t	ndx, cnt;

	if (tmid.tmi_bits == 0) {
		if ((tmid.tmi_bits =
		    calloc(TLSBLOCKCNT, sizeof (uint_t))) == NULL)
			return ((ulong_t)-1);
		tmid.tmi_bits[0] = 1;
		tmid.tmi_lowfree = 1;
		tmid.tmi_cnt = TLSBLOCKCNT;
		return (0);
	}

	for (cnt = tmid.tmi_lowfree / (sizeof (uint_t) * 8);
	    cnt < tmid.tmi_cnt; cnt++) {
		uint_t	bits;

		/*
		 * If all bits are assigned - move on.
		 */
		if ((tmid.tmi_bits[cnt] ^ ~((uint_t)0)) == 0)
			continue;

		for (ndx = 0, bits = 1; bits; bits = bits << 1, ndx++) {
			if ((tmid.tmi_bits[cnt] & bits) == 0) {
				tmid.tmi_bits[cnt] |= bits;
				ndx = (cnt * (sizeof (uint_t)) * 8) + ndx;
				tmid.tmi_lowfree = ndx + 1;
				return (ndx);
			}
		}
	}

	/*
	 * All bits taken - must allocate a new block
	 */
	if ((tmid.tmi_bits = realloc(tmid.tmi_bits,
	    ((tmid.tmi_cnt * sizeof (uint_t)) +
	    (TLSBLOCKCNT * sizeof (uint_t))))) == NULL)
		return ((ulong_t)-1);

	/*
	 * Clear out the tail of the new allocation.
	 */
	bzero(&(tmid.tmi_bits[tmid.tmi_cnt]), TLSBLOCKCNT * sizeof (uint_t));
	tmid.tmi_bits[tmid.tmi_cnt] = 1;
	ndx = (tmid.tmi_cnt * sizeof (uint_t)) * 8;
	tmid.tmi_lowfree = ndx + 1;
	tmid.tmi_cnt += TLSBLOCKCNT;

	return (ndx);
}

void
tls_freemodid(ulong_t modid)
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
tls_modaddrem(Rt_map *lmp, uint_t flag)
{
	Lm_list		*lml = LIST(lmp);
	TLS_modinfo	tmi;
	Phdr		*tlsphdr;
	int		(*fptr)(TLS_modinfo *);

	if (flag & TM_FLG_MODADD) {
		fptr = lml->lm_lcs[CI_TLS_MODADD].lc_un.lc_func;
	} else if (FLAGS1(lmp) & FL1_RT_TLSADD) {
		fptr = lml->lm_lcs[CI_TLS_MODREM].lc_un.lc_func;
	} else {
		return;
	}

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

	DBG_CALL(Dbg_tls_modactivity(LIST(lmp), &tmi, flag));
	(void) (*fptr)(&tmi);

	/*
	 * Tag that this link-map has registered its TLS, and, if this object
	 * is being removed, free up the module id.
	 */
	FLAGS1(lmp) |= FL1_RT_TLSADD;

	if (flag & TM_FLG_MODREM)
		tls_freemodid(TLSMODID(lmp));
}

static ulong_t	tls_static_size = 0;	/* static TLS buffer size */
static ulong_t	tls_static_resv = 512;	/* (extra) static TLS reservation */

/*
 * Track any static TLS use, retain the TLS header, and assign a TLS module
 * identifier.
 */
int
tls_assign(Lm_list *lml, Rt_map *lmp, Phdr *phdr)
{
	ulong_t	memsz = S_ROUND(phdr->p_memsz, M_TLSSTATALIGN);
	ulong_t	filesz = phdr->p_filesz;
	ulong_t	resv = tls_static_resv;

	/*
	 * If this object explicitly references static TLS, then there are some
	 * limitations.
	 */
	if (FLAGS1(lmp) & FL1_RT_TLSSTAT) {
		/*
		 * Static TLS is only available to objects on the primary
		 * link-map list.
		 */
		if (((lml->lm_flags & LML_FLG_BASELM) == 0) ||
		    ((rtld_flags2 & RT_FL2_NOPLM) != 0)) {
			eprintf(lml, ERR_FATAL, MSG_INTL(MSG_TLS_STATBASE),
			    NAME(lmp));
			return (0);
		}

		/*
		 * All TLS blocks that are processed before thread
		 * initialization, are registered with libc.  This
		 * initialization is carried out through a handshake with libc
		 * prior to executing any user code (ie. before the first .init
		 * sections are called).  As part of this initialization, a
		 * small backup TLS reservation is added (tls_static_resv).
		 * Only explicit static TLS references that can be satisfied by
		 * this TLS backup reservation can be satisfied.
		 */
		if (rtld_flags2 & RT_FL2_PLMSETUP) {
			/*
			 * Initialized static TLS can not be satisfied from the
			 * TLS backup reservation.
			 */
			if (filesz) {
				eprintf(lml, ERR_FATAL,
				    MSG_INTL(MSG_TLS_STATINIT), NAME(lmp));
				return (0);
			}

			/*
			 * Make sure the backup reservation is sufficient.
			 */
			if (memsz > tls_static_resv) {
				eprintf(lml, ERR_FATAL,
				    MSG_INTL(MSG_TLS_STATSIZE), NAME(lmp),
				    EC_XWORD(memsz), EC_XWORD(tls_static_resv));
				return (0);
			}

			tls_static_resv -= memsz;
		}
	}

	/*
	 * If we haven't yet initialized threads, or this static reservation can
	 * be satisfied from the TLS backup reservation, determine the total
	 * static TLS size, and assign this object a static TLS offset.
	 */
	if (((rtld_flags2 & RT_FL2_PLMSETUP) == 0) ||
	    (FLAGS1(lmp) & FL1_RT_TLSSTAT)) {
		tls_static_size += memsz;
		TLSSTATOFF(lmp) = tls_static_size;
	}

	/*
	 * Retain the PT_TLS header, obtain a new module identifier, and
	 * indicate that this link-map list contains a new TLS object.
	 */
	PTTLS(lmp) = phdr;
	TLSMODID(lmp) = tls_getmodid();

	/*
	 * Now that we have a TLS module id, generate any static TLS reservation
	 * diagnostic.
	 */
	if (resv != tls_static_resv)
		DBG_CALL(Dbg_tls_static_resv(lmp, memsz, tls_static_resv));

	return (++lml->lm_tls);
}

int
tls_statmod(Lm_list *lml, Rt_map *lmp)
{
	uint_t		tlsmodndx, tlsmodcnt = lml->lm_tls;
	TLS_modinfo	**tlsmodlist, *tlsbuflist;
	Phdr		*tlsphdr;
	int		(*fptr)(TLS_modinfo **, ulong_t);

	fptr = lml->lm_lcs[CI_TLS_STATMOD].lc_un.lc_func;

	/*
	 * Allocate a buffer to report the TLS modules, the buffer consists of:
	 *
	 *	TLS_modinfo *	ptrs[tlsmodcnt + 1]
	 *	TLS_modinfo	bufs[tlsmodcnt]
	 *
	 * The ptrs are initialized to the bufs - except the last one which
	 * null terminates the array.
	 *
	 * Note, even if no TLS has yet been observed, we still supply a
	 * TLS buffer with a single null entry.  This allows us to initialize
	 * the backup TLS reservation.
	 */
	if ((tlsmodlist = calloc(1, (sizeof (TLS_modinfo *) * (tlsmodcnt + 1)) +
	    (sizeof (TLS_modinfo) * tlsmodcnt))) == NULL)
		return (0);

	lml->lm_tls = 0;

	/*
	 * If we don't have any TLS modules - report that and return.
	 */
	if (tlsmodcnt == 0) {
		if (fptr != NULL)
			(void) (*fptr)(tlsmodlist, tls_static_resv);
		DBG_CALL(Dbg_tls_static_block(&lml_main, 0, 0,
		    tls_static_resv));
		return (1);
	}

	/*
	 * Initialize the TLS buffer.
	 */
	tlsbuflist = (TLS_modinfo *)((uintptr_t)tlsmodlist +
	    ((tlsmodcnt + 1) * sizeof (TLS_modinfo *)));

	for (tlsmodndx = 0; tlsmodndx < tlsmodcnt; tlsmodndx++)
		tlsmodlist[tlsmodndx] = &tlsbuflist[tlsmodndx];

	/*
	 * Account for the initial dtv ptr in the TLSSIZE calculation.
	 */
	tlsmodndx = 0;
	for (lmp = lml->lm_head; lmp; lmp = NEXT_RT_MAP(lmp)) {
		if (THIS_IS_NOT_ELF(lmp) ||
		    (PTTLS(lmp) == 0) || (PTTLS(lmp)->p_memsz == 0))
			continue;

		tlsphdr = PTTLS(lmp);

		tlsmodlist[tlsmodndx]->tm_modname = PATHNAME(lmp);
		tlsmodlist[tlsmodndx]->tm_modid = TLSMODID(lmp);
		tlsmodlist[tlsmodndx]->tm_tlsblock = (void *)(tlsphdr->p_vaddr);

		if (!(FLAGS(lmp) & FLG_RT_FIXED)) {
			tlsmodlist[tlsmodndx]->tm_tlsblock = (void *)
			    ((uintptr_t)tlsmodlist[tlsmodndx]->tm_tlsblock +
			    ADDR(lmp));
		}
		tlsmodlist[tlsmodndx]->tm_filesz = tlsphdr->p_filesz;
		tlsmodlist[tlsmodndx]->tm_memsz = tlsphdr->p_memsz;
		tlsmodlist[tlsmodndx]->tm_flags = TM_FLG_STATICTLS;
		tlsmodlist[tlsmodndx]->tm_stattlsoffset = TLSSTATOFF(lmp);
		tlsmodndx++;
	}

	DBG_CALL(Dbg_tls_static_block(&lml_main, (void *)tlsmodlist,
	    tls_static_size, tls_static_resv));
	(void) (*fptr)(tlsmodlist, (tls_static_size + tls_static_resv));

	/*
	 * We're done with the list - clean it up.
	 */
	free(tlsmodlist);
	return (1);
}
