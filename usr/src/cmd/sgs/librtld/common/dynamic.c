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
 *
 * Update any dynamic entry offsets.  One issue with dynamic entries is that
 * you only know whether they refer to a value or an offset if you know each
 * type.  Thus we check for all types we know about, it a type is found that
 * we don't know about then return and error as we have no idea what to do.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<libelf.h>
#include	<link.h>
#include	"libld.h"
#include	"msg.h"
#include	"rtld.h"
#include	"_librtld.h"

int
update_dynamic(Cache *cache, Cache *_cache, Rt_map *lmp, int flags,
    Addr addr, Off off, const char *file, Xword null, Xword data, Xword func,
    Xword entsize, Xword checksum)
{
	Dyn		*dyn = (Dyn *)_cache->c_data->d_buf, *posdyn = 0;
	const char	*strs;
	Cache		*__cache;

	/*
	 * If we're dealing with an object that might have bound to an external
	 * dependency establish our string table for possible NEEDED processing.
	 */
	if (flags & RTLD_REL_DEPENDS) {
		__cache = &cache[_cache->c_shdr->sh_link];
		strs = (const char *)__cache->c_data->d_buf;
	}

	/*
	 * Loop through the dynamic table updating all offsets.
	 */
	while (dyn->d_tag != DT_NULL) {
		switch ((Xword)dyn->d_tag) {
		case DT_NEEDED:
			if (posdyn) {
				Rt_map	*dlmp;

				/*
				 * Determine whether this dependency has been
				 * loaded (this is the most generic way to check
				 * any alias names), and if it has been bound
				 * to, undo any lazy-loading position flag.
				 */
				if (dlmp = is_so_loaded(LIST(lmp),
				    (strs + dyn->d_un.d_val), NULL)) {
					Bnd_desc	*bdp;
					Aliste		idx;

					for (APLIST_TRAVERSE(DEPENDS(lmp), idx,
					    bdp)) {
						if (dlmp == bdp->b_depend) {
							posdyn->d_un.d_val &=
							    ~DF_P1_LAZYLOAD;
							break;
						}
					}
				}
			}
			break;

		case DT_RELAENT:
		case DT_STRSZ:
		case DT_SYMENT:
		case DT_SONAME:
		case DT_RPATH:
		case DT_SYMBOLIC:
		case DT_RELENT:
		case DT_PLTREL:
		case DT_TEXTREL:
		case DT_VERDEFNUM:
		case DT_VERNEEDNUM:
		case DT_AUXILIARY:
		case DT_USED:
		case DT_FILTER:
		case DT_DEPRECATED_SPARC_REGISTER:
		case M_DT_REGISTER:
		case DT_BIND_NOW:
		case DT_INIT_ARRAYSZ:
		case DT_FINI_ARRAYSZ:
		case DT_RUNPATH:
		case DT_FLAGS:
		case DT_CONFIG:
		case DT_DEPAUDIT:
		case DT_AUDIT:
		case DT_SUNW_SYMSZ:
			break;
		case DT_PLTGOT:
		case DT_HASH:
		case DT_STRTAB:
		case DT_SYMTAB:
		case DT_SUNW_SYMTAB:
		case DT_INIT:
		case DT_FINI:
		case DT_VERSYM:
		case DT_VERDEF:
		case DT_VERNEED:
		case DT_INIT_ARRAY:
		case DT_FINI_ARRAY:
			dyn->d_un.d_ptr += addr;
			break;

		/*
		 * If the memory image is being used, this element would have
		 * been initialized to the runtime linkers internal link-map
		 * list.  Clear it.
		 */
		case DT_DEBUG:
			dyn->d_un.d_val = 0;
			break;

		/*
		 * The number of relocations may have been reduced if
		 * relocations have been saved in the new image.  Thus we
		 * compute the new relocation size and start.
		 */
		case DT_RELASZ:
		case DT_RELSZ:
			dyn->d_un.d_val = ((data + func) * entsize);
			break;

		case DT_RELA:
		case DT_REL:
			dyn->d_un.d_ptr = (addr + off + (null * entsize));
			break;

		/*
		 * If relative relocations have been processed clear the count.
		 */
		case DT_RELACOUNT:
		case DT_RELCOUNT:
			if (flags & RTLD_REL_RELATIVE)
				dyn->d_un.d_val = 0;
			break;

		case DT_PLTRELSZ:
			dyn->d_un.d_val = (func * entsize);
			break;

		case DT_JMPREL:
			dyn->d_un.d_ptr = (addr + off +
			    ((null + data) * entsize));
			break;

		/*
		 * Recompute the images elf checksum.
		 */
		case DT_CHECKSUM:
			dyn->d_un.d_val = checksum;
			break;

		/*
		 * If a flag entry is available, indicate if this image has
		 * been generated via the configuration process (crle(1)).
		 * Because we only started depositing DT_FLAGS_1 entries in all
		 * objects starting with Solaris 8, set a feature flag if it
		 * is present (these got added in Solaris 7).
		 * The runtime linker may use this flag to search for a local
		 * configuration file - this is only meaningful in executables
		 * but the flag has value for identifying images regardless.
		 *
		 * If this file is acting as a filter, and dependency
		 * relocations have been processed (a filter is thought of as a
		 * dependency in terms of symbol binding), we may have bound to
		 * the filtee, and hence carried out the relocation.  Indicate
		 * that the filtee must be preloaded, as the .plt won't get
		 * exercised to cause its normal loading.
		 */
		case DT_FLAGS_1:
			if (flags & RTLD_CONFSET)
				dyn->d_un.d_val |= DF_1_CONFALT;
			if ((flags & RTLD_REL_DEPENDS) &&
			    (FLAGS1(lmp)) & MSK_RT_FILTER)
				dyn->d_un.d_val |= DF_1_LOADFLTR;
			break;

		case DT_FEATURE_1:
			if (flags & RTLD_CONFSET)
				dyn->d_un.d_val |= DTF_1_CONFEXP;
			break;

		/*
		 * If a position flag is available save it for possible update
		 * when processing the next NEEDED tag.
		 */
		case DT_POSFLAG_1:
			if (flags & RTLD_REL_DEPENDS) {
				posdyn = dyn++;
				continue;
			}
			break;

		/*
		 * Collect the defaults.
		 */
		default:
			/*
			 * If d_val is used, don't touch.
			 */
			if ((dyn->d_tag >= DT_VALRNGLO) &&
			    (dyn->d_tag <= DT_VALRNGHI))
				break;

			/*
			 * If d_ptr is used, adjust.  Note, some entries that
			 * fell into this range are offsets into the dynamic
			 * string table.  Although these would need modifying
			 * if the section itself were resized, there is no
			 * resizing with dldump().  Entries that correspond to
			 * offsets are picked off in the initial DT_ loop
			 * above.
			 */
			if ((dyn->d_tag >= DT_ADDRRNGLO) &&
			    (dyn->d_tag <= DT_ADDRRNGHI)) {
				dyn->d_un.d_ptr += addr;
				break;
			}

			/*
			 * Check to see if this DT_ entry conforms
			 * to the DT_ENCODING rules.
			 */
			if ((dyn->d_tag >= DT_ENCODING) &&
			    (dyn->d_tag <= DT_HIOS)) {
				/*
				 * Even tag values are ADDRESS encodings
				 */
				if ((dyn->d_tag % 2) == 0) {
					dyn->d_un.d_ptr += addr;
				}
				break;
			}
			eprintf(LIST(lmp), ERR_WARNING,
			    MSG_INTL(MSG_DT_UNKNOWN), file,
			    EC_XWORD(dyn->d_tag));
			return (1);
		}
		posdyn = 0;
		dyn++;
	}
	return (0);
}
