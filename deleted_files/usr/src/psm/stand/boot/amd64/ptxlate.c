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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#include <amd64/amd64.h>
#include <amd64/print.h>
#include <amd64/debug.h>
#include <amd64/amd64_page.h>

/*
 * NOTE: ALL these routines assume that page tables are identity mapped (1:1,
 *	 VA == PA).  If they cannot access a given physical address by
 *	 dereferencing the equivalent virtual address, they will fail due to
 *	 the inability of the x86 to easily access any given physical address
 *	 without explicitly mapping a special page specifically to do so.
 *
 *	 Since boot already maps the 32-bit page tables this way and we control
 *	 creation of the 64-bit page tables, we can assure that this remains
 *	 the case unless a callback is made from 64-bit mode that references a
 *	 kernel-mapped page; doing THAT will likely cause a crash as the
 *	 routines try to dereference an unmapped or wrong address.
 */

/*
 * Routines to manage legacy 32-bit and long mode 64-bit page mappings
 */

void
amd64_xlate_legacy_va(uint32_t va, uint32_t len, uint32_t legacy_ptbase,
    uint32_t long_ptbase)
{
	uint64_t map_pa, map_va, entry, offset;
	uint32_t pagesize, map_pagesize;

	uint64_t maplen = 0;

	/*
	 * If passed VA is not page aligned, make it so
	 * and add the offset to the length we need to map,
	 * so a map of va 0x3100, len 0x1000 becomes a map
	 * of va 0x3000, len 0x1100.
	 */
	if (!(AMD64_PAGEALIGNED(va, AMD64_PAGESIZE))) {
		len += va & AMD64_PAGEOFFSET(AMD64_PAGESIZE);
		va &= AMD64_PAGEMASK(AMD64_PAGESIZE);
	}

	while (len) {
		uint64_t check_pa, entry_64;

		entry = amd64_legacy_lookup((uint64_t)(va), &map_pagesize,
			legacy_ptbase);

		if (entry_64 = amd64_long_lookup((uint64_t)(va), &pagesize,
		    long_ptbase)) {
			/*
			 * We can skip the next map_pagesize bytes since
			 * they've already been mapped.
			 */

#ifdef	DEBUG
			if ((amd64_physaddr(entry_64, AMD64_MODE_LONG64)) !=
			    (amd64_physaddr((uint64_t)entry,
			    AMD64_MODE_LEGACY))) {
				printf("WARNING: 64-bit va 0x%llx already "
				    "mapped, pa 0x%llx, len 0x%x!\n",
				    (uint64_t)va, amd64_physaddr(entry_64,
				    AMD64_MODE_LONG64),
				    pagesize);
				printf("         Will not remap address to pa "
				    "0x%llx as requested.\n",
				    amd64_physaddr((uint64_t)entry,
				    AMD64_MODE_LEGACY));
			}
#endif	/* DEBUG */
#ifdef	lint
			entry_64 = entry_64;
#endif	/* lint */
			map_pagesize = pagesize;
			entry = 0;
		}

		pagesize = (map_pagesize > len) ? AMD64_PAGESIZE : map_pagesize;

		if (entry) {
			/*
			 * Valid page mapping for va found, so either add
			 * it to the current page range or map what we have
			 * and start a new range.
			 */
			check_pa = amd64_legacy_physaddr(entry);

			if ((map_pagesize == AMD64_PAGESIZE4M) &&
			    (!(AMD64_PAGEALIGNED(va, map_pagesize)))) {
				offset = va & AMD64_PAGEMASK(map_pagesize);
				check_pa += offset;
				pagesize = AMD64_PAGESIZE;
			}

			if (!maplen) {
				map_va = (uint64_t)(va);

				map_pa = check_pa;
				maplen = pagesize;

				if (!(AMD64_PAGEALIGNED(va, pagesize))) {
					offset = va &
					    AMD64_PAGEOFFSET(pagesize);
					map_pa += offset;
					maplen -= offset;
				}
			} else {
				if (check_pa != (map_pa + maplen)) {
					/*
					 * Range of mapped entries ends,
					 * so map what we've got and start
					 * a new range.
					 */
					amd64_map_mem(map_va, map_pa,
					    maplen, AMD64_MODE_LONG64,
					    long_ptbase,
					    amd64_modbits((uint64_t)entry));

					/*
					 * Use current mapping as start of
					 * new range.
					 */
					map_va = (uint64_t)(va);
					map_pa = check_pa;
					maplen = pagesize;

					if (!(AMD64_PAGEALIGNED(va,
					    pagesize))) {
						offset = va &
						    AMD64_PAGEOFFSET(pagesize);
						map_pa += offset;
						maplen -= offset;
					}
				} else {
					/*
					 * Just increment mapping range
					 * by mapped pagesize.
					 */
					maplen += pagesize;
				}
			}
		} else if (maplen) {
			/*
			 * Found a bad map entry, so end the mapping range and
			 * translate the address range we have.
			 */
			amd64_map_mem(map_va, map_pa, maplen, AMD64_MODE_LONG64,
			    long_ptbase, amd64_modbits((uint64_t)entry));

			maplen = 0;
		}

		va += pagesize;
		len -= (pagesize > len) ? len : pagesize;
	}

	/*
	 * If we ended with an outstanding range left to map, be sure to map it
	 * now.
	 */
	if (maplen)
		amd64_map_mem(map_va, map_pa, maplen, AMD64_MODE_LONG64,
		    long_ptbase, amd64_modbits((uint64_t)entry));
}

void
amd64_xlate_long_va(uint64_t va, uint32_t len, uint32_t long_ptbase,
    uint32_t legacy_ptbase)
{
	uint32_t map_pagesize, pagesize;
	uint64_t map_pa, map_va, entry, offset;
	uint64_t maplen = 0;

	/*
	 * If passed VA is not page aligned, make it so
	 * and add the offset to the length we need to map,
	 * so a map of va 0x3100, len 0x1000 becomes a map
	 * of va 0x3000, len 0x1100.
	 */
	if (!(AMD64_PAGEALIGNED(va, AMD64_PAGESIZE))) {
		len += va & AMD64_PAGEOFFSET(AMD64_PAGESIZE);
		va &= AMD64_PAGEMASK(AMD64_PAGESIZE);
	}

	while (len) {
		uint64_t check_pa;
		uint32_t entry_32;

		entry = amd64_long_lookup(va, &map_pagesize, long_ptbase);

		if (entry_32 = amd64_legacy_lookup((uint32_t)ADDR_TRUNC(va),
		    &pagesize, legacy_ptbase)) {
			/*
			 * We can skip the next map_pagesize bytes since
			 * they've already been mapped.
			 */
#ifdef	DEBUG
			if ((amd64_physaddr((uint64_t)entry_32,
			    AMD64_MODE_LEGACY)) != (amd64_physaddr(entry,
			    AMD64_MODE_LONG64))) {
				printf("WARNING: 32-bit va 0x%llx already "
				    "mapped, pa 0x%llx, len 0x%x!\n",
				    (uint64_t)va, amd64_physaddr(entry_32,
				    AMD64_MODE_LEGACY), pagesize);
				printf("         Will not remap address to "
				    "pa 0x%llx as requested.\n",
				    amd64_physaddr(entry, AMD64_MODE_LONG64));
			}

#endif	/* DEBUG */
#ifdef lint
			entry_32 = entry_32;
#endif	/* lint */
			map_pagesize = pagesize;
			entry = 0;
		}

		pagesize = (map_pagesize > len) ? AMD64_PAGESIZE
		    : map_pagesize;

		if (entry) {
			/*
			 * Valid page mapping for va found, so either add
			 * it to the current page range or map what we have
			 * and start a new range.
			 */
			check_pa = amd64_long_physaddr(entry);

			if ((map_pagesize == AMD64_PAGESIZE2M) &&
			    (!(AMD64_PAGEALIGNED(va, map_pagesize)))) {
				offset = va & AMD64_PAGEMASK(map_pagesize);
				check_pa += offset;
				pagesize = AMD64_PAGESIZE;
			}

			if (!maplen) {
				map_va = va;
				map_pa = check_pa;
				maplen = pagesize;

				if (!(AMD64_PAGEALIGNED(va, pagesize))) {
					offset = va &
					    AMD64_PAGEOFFSET(pagesize);

					map_pa += offset;
					maplen -= offset;
				}
			} else {
				if (check_pa != (map_pa + maplen)) {
					/*
					 * Range of mapped entries ends,
					 * so map what we've got and start
					 * a new range.
					 */
					amd64_map_mem(map_va, map_pa, maplen,
					    AMD64_MODE_LEGACY, legacy_ptbase,
					    amd64_modbits(entry));

					/*
					 * Use current mapping as start of
					 * new range.
					 */
					map_va = va;
					map_pa = check_pa;
					maplen = pagesize;

					if (!(AMD64_PAGEALIGNED(va,
					    pagesize))) {
						offset = va &
						    AMD64_PAGEOFFSET(pagesize);
						map_pa += offset;
						maplen -= offset;
					}
				} else {
					/*
					 * Just increment mapping range
					 * by mapped pagesize.
					 */
					maplen += pagesize;
				}
			}
		} else if (maplen) {
			/*
			 * Found a bad map entry, so end the mapping range and
			 * translate the address range we have.
			 */
			amd64_map_mem(map_va, map_pa, maplen, AMD64_MODE_LEGACY,
			    legacy_ptbase, amd64_modbits(entry));
			maplen = 0;
		}

		va += pagesize;
		len -= (pagesize > len) ? len : pagesize;
	}

	/*
	 * If we ended with an outstanding range left to map, be sure to map it
	 * now.
	 */
	if (maplen)
		amd64_map_mem(map_va, map_pa, maplen, AMD64_MODE_LEGACY,
		    legacy_ptbase, amd64_modbits(entry));
}

void
amd64_xlate_boot_tables(uint32_t boot_ptbase, uint32_t long_ptbase)
{
	extern uint_t magic_phys;

	/*
	 * The initial 64-bit page tables are setup with 0x200000:0x600000
	 * already identity mapped, so we can skip that range.
	 */

	/*
	 * Copy first 2M of boot's pages but SKIP PAGE ZERO.
	 */
	amd64_xlate_legacy_va(0x1000ULL, 0x1ff000, boot_ptbase, long_ptbase);

	/*
	 * Now copy balance of boot's pages.
	 *
	 * The initial 64-bit page tables are setup with 0x200000:0x400000
	 * already identity mapped, so we can skip that range...
	 */
	amd64_xlate_legacy_va((magic_phys / 0x200000) * 0x200000,
	    0xffc00000, boot_ptbase, long_ptbase);
}
