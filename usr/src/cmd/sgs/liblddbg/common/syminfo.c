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
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<sgs.h>
#include	<stdio.h>
#include	<debug.h>
#include	<msg.h>

void
Elf_syminfo_title(Lm_list *lml)
{
	dbg_print(lml, MSG_INTL(MSG_SYMINFO_TITLE));
}

#define	FLAGSZ	16
#define	NDXSZ	10

void
Elf_syminfo_entry(Lm_list *lml, Word ndx, Syminfo *sip, const char *name,
    const char *needed)
{
	const char	*bndstr, *str;
	char		flagstr[FLAGSZ], sndxstr[NDXSZ], dndxstr[NDXSZ];
	int		flgndx = 0;
	Half		flags = sip->si_flags;

	if (flags & SYMINFO_FLG_DIRECT) {
		if (sip->si_boundto == SYMINFO_BT_SELF)
			bndstr = MSG_INTL(MSG_SYMINFO_SELF);
		else if (sip->si_boundto == SYMINFO_BT_PARENT)
			bndstr = MSG_INTL(MSG_SYMINFO_PARENT);
		else
			bndstr = needed;

		flagstr[flgndx++] = 'D';
		flags &= ~SYMINFO_FLG_DIRECT;

	} else if (flags & SYMINFO_FLG_FILTER) {
		bndstr = needed;
		flagstr[flgndx++] = 'F';
		flags &= ~SYMINFO_FLG_FILTER;

	} else if (flags & SYMINFO_FLG_AUXILIARY) {
		bndstr = needed;
		flagstr[flgndx++] = 'A';
		flags &= ~SYMINFO_FLG_AUXILIARY;

	} else if (sip->si_boundto == SYMINFO_BT_EXTERN)
		bndstr = MSG_INTL(MSG_SYMINFO_EXTERN);
	else
		bndstr = MSG_ORIG(MSG_STR_EMPTY);

	if (flags & SYMINFO_FLG_DIRECTBIND) {
		flagstr[flgndx++] = 'B';
		flags &= ~SYMINFO_FLG_DIRECTBIND;
	}
	if (flags & SYMINFO_FLG_COPY) {
		flagstr[flgndx++] = 'C';
		flags &= ~SYMINFO_FLG_COPY;
	}
	if (flags & SYMINFO_FLG_LAZYLOAD) {
		flagstr[flgndx++] = 'L';
		flags &= ~SYMINFO_FLG_LAZYLOAD;
	}
	if (flags & SYMINFO_FLG_NOEXTDIRECT) {
		flagstr[flgndx++] = 'N';
		flags &= ~SYMINFO_FLG_NOEXTDIRECT;
	}
	if (flags & SYMINFO_FLG_INTERPOSE) {
		flagstr[flgndx++] = 'I';
		flags &= ~SYMINFO_FLG_INTERPOSE;
	}

	/*
	 * Did we account for all of the flags?
	 */
	if (flags)
		(void) snprintf(&flagstr[flgndx], FLAGSZ - flgndx,
		    MSG_ORIG(MSG_SYMINFO_UNKFLAG), flags);
	else
		flagstr[flgndx] = '\0';

	/*
	 * If we've bound to a dependency, determine the dynamic entry index.
	 */
	if (bndstr == needed) {
		(void) snprintf(dndxstr, NDXSZ, MSG_ORIG(MSG_FMT_INDEX),
		    sip->si_boundto);
		str = dndxstr;
	} else
		str = MSG_ORIG(MSG_STR_EMPTY);

	(void) snprintf(sndxstr, NDXSZ, MSG_ORIG(MSG_FMT_INDEX), ndx);

	dbg_print(lml, MSG_INTL(MSG_SYMINFO_ENTRY), sndxstr, flagstr, str,
	    bndstr, Elf_demangle_name(name));
}
