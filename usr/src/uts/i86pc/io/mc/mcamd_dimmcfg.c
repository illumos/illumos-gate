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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <mcamd_dimmcfg_impl.h>

/*
 * We have built a list of the active csbase/csmask pairs, and now we want
 * to associate those active chip-selects with actual dimms.  To achieve this
 * we must map the csbase/csmask pair to an associated logical DIMM and
 * chip-select line.
 *
 * A logical DIMM comprises up to 2 physical dimms as follows:
 *
 *	- in 64-bit mode without mismatched dimm support logical DIMMs are
 *	  made up of just one physical dimm situated in a "lodimm" slot
 *	  on channel A;  the corresponding slot on channel B (if there is
 *	  a channel B) must be empty or will be disabled if populated.
 *
 *	- in 64-bit mode with mismatched dimm support a logical DIMM may
 *	  be made up of 1 or 2 physical dimms - one on channel A and another
 *	  in the corresponding slot on channel B.  They are accessed
 *	  independently.
 *
 *	- in 128 bit mode a logical DIMM is made up of two physical dimms -
 *	  a pair of one slot on channel A and its partner on channel B.
 *	  The lodimm on channel A provides data [63:0] while the updimm
 *	  on channel B provides data [127:64].  The two dimms must be
 *	  identical in size and organisation (number of ranks etc).
 *
 * For our dimm numbering purposes we need go no further than deriving
 * the logical DIMM number for a given csbase/csmask pair and presence
 * of quadrank support and mismatched dimms.  For logical DIMM number N
 * (N = 0, 1, 2, or 3):
 *
 *	- the lodimm, if present, is numbered N * 2
 *	- the updimm, if present, is numbered N * 2 + 1
 *
 * Presence is deduced by observed configuration, as above.  This numbering
 * scheme, however, often bears little or no resemblance to how the dimm slots
 * are physically labelled/silkscreened (which in turn often bears little
 * resemblance to how SMBIOS data, if available, describes the slot).  To
 * determine slot labels we will map chip-select *line* to slot name in
 * some hand-crafted tables (which live in the libtopo enumerator and are
 * built after consulting the board schematics for a platform).  To provide
 * the chip-select line name we will perform some additional gymnastics here
 * to derive the chip-select line or lines (in 128 bit mode) associated
 * with a chip-select rank.  This is achieved via matching against the
 * "DRAM CS Base and DRAM CS Mask Registers" with and without mismatched
 * dimm support tables of the BKDG (tables 5 and 6 of BKDG 3.31 for rev E
 * and earlier; tables 8 and 9 of BKDG 3.01 for rev F and G).
 *
 * The following tables could be implemented programtically, but are more
 * readily reviewed for correctness presented as tables.
 */

/* BEGIN CSTYLED */

/*
 * Revision E and earlier mapping with mismatched dimm support disabled.
 */
static const struct mcdcfg_csmapline csmap_nomod64mux_preF[] = {
    /*
     * Pkgs   base dramconfig	     ldimm   cs A              cs B
     *
     * Base reg 0 (mask 0)
     */
    { SKT_ALL,	0, DCFG_ALL,		0, { { CH_A, 0, 0 }, { CH_B, 0, 0 } } },
    /*
     * Base reg 1 (mask 1)
     */
    { SKT_ALL,	1, DCFG_ALL,		0, { { CH_A, 0, 1 }, { CH_B, 0, 1 } } },
    /*
     * Base reg 2 (mask 2)
     */
    { SKT_ALL,	2, DCFG_ALL,		1, { { CH_A, 1, 0 }, { CH_B, 1, 0 } } },
    /*
     * Base reg 3 (mask 3)
     */
    { SKT_ALL,	3, DCFG_ALL,		1, { { CH_A, 1, 1 }, { CH_B, 1, 1 } } },
    /*
     * Base reg 4 (mask 4)
     */
    { SKT_940,	4, DCFG_N,		2, { { CH_A, 2, 0 }, { CH_B, 2, 0 } } },
    { SKT_940,	4, DCFG_R4,		0, { { CH_A, 2, 0 }, { CH_B, 2, 0 } } },
    /*
     * Base reg 5 (mask 5)
     */
    { SKT_940,	5, DCFG_N,		2, { { CH_A, 2, 1 }, { CH_B, 2, 1 } } },
    { SKT_940,	5, DCFG_R4,		0, { { CH_A, 2, 1 }, { CH_B, 2, 1 } } },
    /*
     * Base reg 6 (mask 6)
     */
    { SKT_940,	6, DCFG_N,		3, { { CH_A, 3, 0 }, { CH_B, 3, 0 } } },
    { SKT_940,	6, DCFG_R4,		1, { { CH_A, 3, 0 }, { CH_B, 3, 0 } } },
    /*
     * Base reg 7 (mask 7)
     */
    { SKT_940,	7, DCFG_N,		3, { { CH_A, 3, 1 }, { CH_B, 3, 1 } } },
    { SKT_940,	7, DCFG_R4,		1, { { CH_A, 3, 1 }, { CH_B, 3, 1 } } }
};

/*
 * Revision E and earlier mapping with mismatched dimm support.
 * Mismatched dimm support applies only to the socket 939 package.
 * Socket 939 does not support registered dimms, so quadrank RDIMMs are
 * not an issue here.
 */
static const struct mcdcfg_csmapline csmap_mod64mux_preF[] = {
    /*
     * Pkgs   base dramconfig	     ldimm   cs A              cs B
     *
     * Base reg 0 (mask 0)
     */
    { SKT_939,	0, DCFG_N,		0, { { CH_A, 0, 0 } } },
    /*
     * Base reg 1 (mask 1)
     */
    { SKT_939,	1, DCFG_N,		0, { { CH_A, 0, 1 } } },
    /*
     * Base reg 2 (mask 2)
     */
    { SKT_939,	2, DCFG_N,		1, { { CH_A, 1, 0 } } },
    /*
     * Base reg 3 (mask 3)
     */
    { SKT_939,	3, DCFG_N,		1, { { CH_A, 1, 1 } } },
    /*
     * Base reg 4 (mask 4)
     */
    { SKT_939,	4, DCFG_N,		0, { { CH_B, 0, 0 } } },
    /*
     * Base reg 5 (mask 5)
     */
    { SKT_939,	5, DCFG_N,		0, { { CH_B, 0, 1 } } },
    /*
     * Base reg 6 (mask 6)
     */
    { SKT_939,	6, DCFG_N,		1, { { CH_B, 1, 0 } } },
    /*
     * Base reg 7 (mask 7)
     */
    { SKT_939,	7, DCFG_N,		1, { { CH_B, 1, 1 } } }
};

/*
 * Rev F and G csbase/csmask to logical DIMM and cs line mappings.
 *
 * We can reduce the tables by a few lines by taking into account which
 * DIMM types are supported by the different package types:
 *
 *		Number of dimms of given type supported per dram channel
 * Package	Reg'd DIMM	4-rank reg'd	Unbuffered	SO-DIMMs
 * F(1207)	4		2		0		0
 * AM2		0		0		2		1
 * S1g1		0		0		0		1
 */

/*
 * NPT (rev F & G) mapping with mismatched dimm support disabled.
 */
static const struct mcdcfg_csmapline csmap_nomod64mux_fg[] = {
    /*
     * Pkgs   base dramconfig	     ldimm   cs A              cs B
     *
     * Base reg 0 (mask 0)
     */
    { SKT_NPT,	0, DCFG_ALLNPT,		0, { { CH_A, 0, 0 }, { CH_B, 0, 0 } } },
    /*
     * Base reg 1 (mask 0)
     */
    { SKT_NPT,	1, DCFG_ALLNPT,		0, { { CH_A, 0, 1 }, { CH_B, 0, 1 } } },
    /*
     * Base reg 2 (mask 1)
     */
    { AM2F1207,	2, DCFG_N | DCFG_R4,	1, { { CH_A, 1, 0 }, { CH_B, 1, 0 } } },
    { AM2,	2, DCFG_S4,		0, { { CH_A, 1, 0 }, { CH_B, 1, 0 } } },
    { S1g1,	2, DCFG_N,		1, { { CH_A, 0, 2 }, { CH_B, 0, 2 } } },
    { S1g1,	2, DCFG_S4,		0, { { CH_A, 0, 2 }, { CH_B, 0, 2 } } },
    /*
     * Base reg 3 (mask 1)
     */
    { AM2F1207,	3, DCFG_N | DCFG_R4,	1, { { CH_A, 1, 1 }, { CH_B, 1, 1 } } },
    { AM2,	3, DCFG_S4,		0, { { CH_A, 0, 3 }, { CH_B, 0, 3 } } },
    { S1g1,	3, DCFG_N,		1, { { CH_A, 1, 1 }, { CH_B, 1, 1 } } },
    { S1g1,	3, DCFG_S4,		0, { { CH_A, 0, 3 }, { CH_B, 0, 3 } } },
    /*
     * Base reg 4 (mask 2)
     */
    { F1207,	4, DCFG_N,		2, { { CH_A, 2, 0 }, { CH_B, 2, 0 } } },
    { F1207,	4, DCFG_R4,		0, { { CH_A, 2, 0 }, { CH_B, 2, 0 } } },
    /*
     * Base reg 5 (mask 2)
     */
    { F1207,	5, DCFG_N,		2, { { CH_A, 2, 1 }, { CH_B, 2, 1 } } },
    { F1207,	5, DCFG_R4,		0, { { CH_A, 2, 1 }, { CH_B, 2, 1 } } },
    /*
     * Base reg 6 (mask 3)
     */
    { F1207,	6, DCFG_N,		3, { { CH_A, 3, 0 }, { CH_B, 3, 0 } } },
    { F1207,	6, DCFG_R4,		1, { { CH_A, 3, 0 }, { CH_B, 3, 0 } } },
    /*
     * Base reg 7 (mask 3)
     */
    { F1207,	7, DCFG_N,		3, { { CH_A, 3, 1 }, { CH_B, 3, 1 } } },
    { F1207,	7, DCFG_R4,		1, { { CH_A, 3, 1 }, { CH_B, 3, 1 } } }
};

/*
 * NPT (rev F & G) mapping with mismatched dimm support.
 * Mismatched dimm support applies only to the AM2 and S1g1 packages.
 * AM2 and S1g1 do not support registered dimms.
 */
static const struct mcdcfg_csmapline csmap_mod64mux_fg[] = {
    /*
     * Pkgs   base dramconfig	     ldimm   cs A              cs B
     *
     * Base reg 0 (mask 0)
     */
    { AM2S1g1,	0, DCFG_N | DCFG_S4,	0, { { CH_A, 0, 0 } } },
    /*
     * Base reg 1 (mask 0)
     */
    { AM2S1g1,	1, DCFG_N | DCFG_S4,	0, { { CH_A, 0, 1 } } },
    /*
     * Base reg 2 (mask 1)
     */
    { AM2,	2, DCFG_N,		1, { { CH_A, 1, 0 } } },
    { AM2,	2, DCFG_S4,		0, { { CH_A, 1, 0 } } },
    { S1g1,	2, DCFG_N,		1, { { CH_A, 0, 2 } } },
    { S1g1,	2, DCFG_S4,		0, { { CH_A, 0, 2 } } },
    /*
     * Base reg 3 (mask 1)
     */
    { AM2,	3, DCFG_N,		1, { { CH_A, 1, 1 } } },
    { AM2,	3, DCFG_S4,		0, { { CH_A, 1, 1 } } },
    { S1g1,	3, DCFG_N,		1, { { CH_A, 0, 3 } } },
    { S1g1,	3, DCFG_S4,		0, { { CH_A, 0, 3 } } },
    /*
     * Base reg 4 (mask 2)
     */
    { AM2S1g1,	4, DCFG_N,		2, { { CH_B, 0, 0 } } },
    { AM2S1g1,	4, DCFG_S4,		1, { { CH_B, 0, 0 } } },
    /*
     * Base reg 5 (mask 2)
     */
    { AM2S1g1,	5, DCFG_N,		2, { { CH_B, 0, 1 } } },
    { AM2S1g1,	5, DCFG_S4,		1, { { CH_B, 0, 1 } } },
    /*
     * Base reg 6 (mask 3)
     */
    { AM2,	6, DCFG_N,		3, { { CH_B, 1, 0 } } },
    { AM2,	6, DCFG_S4,		1, { { CH_B, 1, 0 } } },
    { S1g1,	6, DCFG_N,		3, { { CH_B, 0, 2 } } },
    { S1g1,	6, DCFG_S4,		1, { { CH_B, 0, 2 } } },
    /*
     * Base reg 7 (mask 3)
     */
    { AM2,	7, DCFG_N,		3, { { CH_B, 1, 1 } } },
    { AM2,	7, DCFG_S4,		1, { { CH_B, 1, 1 } } },
    { S1g1,	7, DCFG_N,		3, { { CH_B, 0, 3 } } },
    { S1g1,	7, DCFG_S4,		1, { { CH_B, 0, 3 } } }
};

/* END CSTYLED */

#define	DCFG_NTBL	4

static const struct {
	uint32_t revmask;		/* applicable chip revs */
	int mod64mux;			/* mismatched support or not */
	const struct mcdcfg_csmapline *map;
	int nmapents;
} csmap_tbls[DCFG_NTBL] = {
	{ MC_REVS_BCDE, 0, &csmap_nomod64mux_preF[0],
	    sizeof (csmap_nomod64mux_preF) / sizeof (struct mcdcfg_csmapline) },
	{ MC_REVS_BCDE, 1, &csmap_mod64mux_preF[0],
	    sizeof (csmap_mod64mux_preF) / sizeof (struct mcdcfg_csmapline) },
	{ MC_REVS_FG, 0, &csmap_nomod64mux_fg[0],
	    sizeof (csmap_nomod64mux_fg) / sizeof (struct mcdcfg_csmapline) },
	{ MC_REVS_FG, 1, &csmap_mod64mux_fg[0],
	    sizeof (csmap_mod64mux_fg) / sizeof (struct mcdcfg_csmapline) }
};

int
mcdcfg_lookup(uint32_t rev, int mod64mux, int accwidth, int basenum,
    uint32_t pkg, int r4, int s4, mcdcfg_rslt_t *rsltp)
{
	const struct mcdcfg_csmapline *csm = NULL;
	int ismux = (mod64mux != 0);
	int nmapents;
	int ndimm = (accwidth == 128) ? 2 : 1;
	int dcfg;
	int i;

	/*
	 * Validate aspects that the table lookup won't.
	 */
	if ((accwidth != 64 && accwidth != 128) || (r4 != 0 && s4 != 0))
		return (-1);

	for (i = 0; i < DCFG_NTBL; i++) {
		if (MC_REV_MATCH(rev, csmap_tbls[i].revmask) &&
		    ismux == csmap_tbls[i].mod64mux) {
			csm = csmap_tbls[i].map;
			nmapents = csmap_tbls[i].nmapents;
			break;
		}
	}
	if (csm == NULL)
		return (-1);

	if (r4)
		dcfg = DCFG_R4;
	else if (s4)
		dcfg = DCFG_S4;
	else
		dcfg = DCFG_N;

	for (i = 0; i < nmapents; i++, csm++) {
		if (X86_SOCKET_MATCH(pkg, csm->csm_pkg) &&
		    basenum == csm->csm_basereg &&
		    (dcfg & csm->csm_dimmcfg) != 0)
			break;
	}
	if (i == nmapents)
		return (-1);

	/*
	 * We return the dimm instance number here for the topology, based
	 * on the AMD Motherboard Design Guide.
	 *
	 * The lodimm/updimm (channel A/B) dimms in a pair are numbered
	 * 0/1, 2/3, 4/5, 6/7 - ie 2 * pairnum and 2 * pairnum + 1 for
	 * pairnum = 0, 1, 2, 3.  But we can't use logical dimm number
	 * for pairnum in that calculation, since in the presence of
	 * mismtached dimms logicial dimms 2 and 3 are used for those
	 * dimm modules on the B channel.  Instead we number using the
	 * slot number on that dram channel, offsetting those on the B
	 * channel by 1.
	 */
	rsltp->ldimm = csm->csm_ldimm;
	rsltp->ndimm = ndimm;
	for (i = 0; i < ndimm; i++) {
		rsltp->dimm[i].toponum = 2 * csm->csm_cs[i].csl_slot +
		    (csm->csm_cs[i].csl_chan == CH_B);
		rsltp->dimm[i].cslp = &csm->csm_cs[i];
	}

	return (0);
}

/*
 * Given a chip-select line and package type return the chip-select line
 * pin label for that package type.
 */
void
mcdcfg_csname(uint32_t pkg, const mcdcfg_csl_t *cslp, char *buf, int buflen)
{
	int csnum;

	switch (pkg) {
	case X86_SOCKET_754:
	case X86_SOCKET_940:
		/*
		 * Format is: MEMCS_L[{0..7}].  That does not identify
		 * a single dimm (since a single chip-select is shared
		 * by both members of a dimm pair in socket 940) so
		 * we tack on some channel identification.
		 */
		csnum = 2 * cslp->csl_slot + cslp->csl_rank;
		(void) snprintf(buf, buflen, "MEMCS_L%d (channel %s)", csnum,
		    cslp->csl_chan == 0 ? "A" : "B");

		break;

	case X86_SOCKET_939:
		/*
		 * Format is: MEMCS_{1,2}{L,H}_L[{1,0}]
		 *		{1,2} - dimm pair
		 *		{L,H} - lodimm or updimm
		 *		{1,0} - rank
		 */
		(void) snprintf(buf, buflen, "MEMCS_%d%s_L[%d]",
		    cslp->csl_slot + 1,
		    cslp->csl_chan == 0 ? "A" : "B",
		    cslp->csl_rank);
		break;

	case X86_SOCKET_F1207:
	case X86_SOCKET_AM2:
	case X86_SOCKET_S1g1:
		/*
		 * Format is: M{B,A}{0,1,2,3}_CS_L[{0,1,2,3}]
		 *		{B,A} - channel
		 *		{0,1,2,3} - slot on channel
		 *		{0,1,2,3} - rank
		 */
		(void) snprintf(buf, buflen, "M%s%d_CS_L[%d]",
		    cslp->csl_chan == 0 ? "A" : "B",
		    cslp->csl_slot,
		    cslp->csl_rank);
		break;

	default:
		(void) snprintf(buf, buflen, "Unknown");
		break;
	}
}
