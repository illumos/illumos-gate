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

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/systm.h>

#include <sys/fm/protocol.h>
#include <sys/devfm.h>

extern int cpu_get_mem_addr(char *, char *, uint64_t, uint64_t *);

int
fm_get_paddr(nvlist_t *nvl, uint64_t *paddr)
{
	uint8_t version;
	uint64_t pa;
	char *scheme;
	int err;
	uint64_t offset;
	char *unum;
	char **serids;
	uint_t nserids;

	/* Verify FMRI scheme name and version number */
	if ((nvlist_lookup_string(nvl, FM_FMRI_SCHEME, &scheme) != 0) ||
	    (strcmp(scheme, FM_FMRI_SCHEME_MEM) != 0) ||
	    (nvlist_lookup_uint8(nvl, FM_VERSION, &version) != 0) ||
	    version > FM_MEM_SCHEME_VERSION) {
		return (EINVAL);
	}

	/*
	 * There are two ways a physical address can be  obtained from a mem
	 * scheme FMRI.  One way is to use the "offset" and  "serial"
	 * members, if they are present, together with the "unum" member to
	 * calculate a physical address.  This is the preferred way since
	 * it is independent of possible changes to the programming of
	 * underlying hardware registers that may change the physical address.
	 * If the "offset" member is not present, then the address is
	 * retrieved from the "physaddr" member.
	 */
	if (nvlist_lookup_uint64(nvl, FM_FMRI_MEM_OFFSET, &offset) != 0) {
		if (nvlist_lookup_uint64(nvl, FM_FMRI_MEM_PHYSADDR, &pa) !=
		    0) {
			return (EINVAL);
		}
	} else if (nvlist_lookup_string(nvl, FM_FMRI_MEM_UNUM, &unum) != 0 ||
	    nvlist_lookup_string_array(nvl, FM_FMRI_MEM_SERIAL_ID, &serids,
	    &nserids) != 0) {
		return (EINVAL);
	} else {
		err = cpu_get_mem_addr(unum, serids[0], offset, &pa);
		if (err != 0) {
			if (err == ENOTSUP) {
				/* Fall back to physaddr */
				if (nvlist_lookup_uint64(nvl,
				    FM_FMRI_MEM_PHYSADDR, &pa) != 0)
					return (EINVAL);
			} else
				return (err);
		}
	}

	*paddr = pa;
	return (0);
}
