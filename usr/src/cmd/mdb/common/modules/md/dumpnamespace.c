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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mdinclude.h"
#include <sys/lvm/md_names.h>

/*
 * work out the offset size
 */
#define	MY_DID_SHR_NAMSIZ(n) \
	(((sizeof (struct did_shr_name) - 1) + \
	n + (sizeof (uint_t) - 1)) & ~(sizeof (uint_t) - 1))
#define	MY_SHR_NAMSIZ(n) \
	(((sizeof (struct nm_shared_name) - 1) + \
	n + (sizeof (uint_t) - 1)) & ~(sizeof (uint_t) - 1))
#define	MY_DID_NAMSIZ(n) \
	(((sizeof (struct did_min_name) - 1) + \
	n + (sizeof (uint_t) - 1)) & ~(sizeof (uint_t) - 1))
#define	MY_NAMSIZ(n) \
	(((sizeof (struct nm_name) - 1) + \
	n + (sizeof (uint_t) - 1)) & ~(sizeof (uint_t) - 1))

static uintptr_t
print_did_shared_name(uintptr_t addr, int i)
{
	struct did_shr_name	shn;
	uintptr_t		sn_name_addr;
	void			*sn_name;
	uintptr_t		next_addr = addr;

	if (mdb_vread(&shn, sizeof (struct did_shr_name), addr) !=
	    sizeof (struct did_shr_name)) {
		mdb_warn("failed to read did_shr_name at %p\n", addr);
		return (NULL);
	}
	if (shn.did_size == 0)
		return (NULL);
	mdb_printf("device_id[%d] at %p\n", i, addr);
	mdb_inc_indent(2);
	mdb_printf("did_key:    %d\n", shn.did_key);
	mdb_printf("did_count:  %u\n", shn.did_count);
	mdb_printf("did_data:   0x%x \n", shn.did_data);
	mdb_printf("did_size: %u\n", shn.did_size);
	sn_name_addr = addr + ((uintptr_t)&shn.did_devid - (uintptr_t)&shn);
	if (shn.did_size > 0) {
		sn_name = mdb_alloc(shn.did_size + 1, UM_SLEEP | UM_GC);
		if (mdb_readstr((char *)sn_name, shn.did_size + 1,
		    sn_name_addr) <= 0) {
			mdb_warn("failed to read sn_name at %p\n",
			    sn_name_addr);
			return (NULL);
		}
		mdb_printf("did_devid:   %s at %p\n", (char *)sn_name,
		    sn_name_addr);
		next_addr = addr + MY_DID_SHR_NAMSIZ(shn.did_size);
	}
	mdb_dec_indent(2);
	return (next_addr);
}

static uintptr_t
print_nm_shared_name(uintptr_t addr, int i)
{
	struct nm_shared_name	shn;
	uintptr_t		sn_name_addr;
	void			*sn_name;
	uintptr_t		next_addr = addr;

	if (mdb_vread(&shn, sizeof (struct nm_shared_name), addr) !=
	    sizeof (struct nm_shared_name)) {
		mdb_warn("failed to read nm_shared_name at %p\n", addr);
		return (NULL);
	}
	if (shn.sn_namlen == 0)
		return (NULL);
	mdb_printf("sr_name[%d] at %p\n", i, addr);
	mdb_inc_indent(2);
	mdb_printf("sn_key:    %d \n", shn.sn_key);
	mdb_printf("sn_count:  %u\n", shn.sn_count);
	mdb_printf("sn_data:   0x%x \n", shn.sn_data);
	mdb_printf("sn_namlen: %u\n", shn.sn_namlen);
	sn_name_addr = addr + ((uintptr_t)&shn.sn_name - (uintptr_t)&shn);
	if (shn.sn_namlen > 0) {
		sn_name = mdb_alloc(shn.sn_namlen + 1, UM_SLEEP | UM_GC);
		if (mdb_readstr((char *)sn_name, shn.sn_namlen + 1,
		    sn_name_addr) <= 0) {
			mdb_warn("failed to read sn_name at %p\n",
			    sn_name_addr);
		}
		mdb_printf("sn_name:   %s at %p\n", (char *)sn_name,
		    sn_name_addr);
		next_addr = addr + MY_SHR_NAMSIZ(shn.sn_namlen);
	}
	mdb_dec_indent(2);
	return (next_addr);
}

static uintptr_t
print_devid_name(uintptr_t addr, int i)
{
	struct did_min_name	didmn;
	uintptr_t		did_name_addr;
	void			*min_name;
	uintptr_t		next_addr = addr;

	if (mdb_vread(&didmn, sizeof (struct did_min_name), addr) !=
	    sizeof (struct did_min_name)) {
		mdb_warn("failed to read did_min_name at %p\n", addr);
		return (NULL);
	}
	if (didmn.min_namlen == 0)
		return (NULL);
	mdb_printf("minor_name[%d] at %p\n", i, addr);
	mdb_inc_indent(2);
	mdb_printf("min_key:    %d \n", didmn.min_key);
	mdb_printf("min_count:  %u\n", didmn.min_count);
	mdb_printf("min_devid_key:    %d \n", didmn.min_devid_key);
	mdb_printf("min_namlen: %u\n", didmn.min_namlen);
	did_name_addr = addr + ((uintptr_t)&didmn.min_name - (uintptr_t)&didmn);
	if (didmn.min_namlen > 0) {
		min_name = mdb_alloc(didmn.min_namlen + 1, UM_SLEEP | UM_GC);
		if (mdb_readstr((char *)min_name, didmn.min_namlen + 1,
		    did_name_addr) <= 0) {
			mdb_warn("failed to read min_name at %p\n",
			    did_name_addr);
		}
		mdb_printf("min_name:   %s at %p\n", (char *)min_name,
		    did_name_addr);
		next_addr = addr + MY_DID_NAMSIZ(didmn.min_namlen);
	}
	mdb_dec_indent(2);
	return (next_addr);
}

static uintptr_t
print_nm_name(uintptr_t addr, int i)
{
	struct nm_name	nm;
	uintptr_t	nm_name_addr;
	void		*n_name;
	uintptr_t	next_addr = addr;

	if (mdb_vread(&nm, sizeof (struct nm_name), addr) !=
	    sizeof (struct nm_name)) {
		mdb_warn("failed to read nm_name at %p\n", addr);
		return (NULL);
	}
	if (nm.n_namlen == 0)
		return (NULL);
	mdb_printf("r_name[%d] at %p\n", i, addr);
	mdb_inc_indent(2);
	mdb_printf("n_key:    %d \n", nm.n_key);
	mdb_printf("n_count:  %u\n", nm.n_count);
	mdb_printf("n_minor:  %x\n", nm.n_minor);
	mdb_printf("n_drv_key:    %d \n", nm.n_drv_key);
	mdb_printf("n_dir_key:    %d \n", nm.n_dir_key);
	mdb_printf("n_namlen: %u\n", nm.n_namlen);
	nm_name_addr = addr + ((uintptr_t)&nm.n_name - (uintptr_t)&nm);
	if (nm.n_namlen > 0) {
		n_name = mdb_alloc(nm.n_namlen + 1, UM_SLEEP | UM_GC);
		if (mdb_readstr((char *)n_name, nm.n_namlen + 1,
		    nm_name_addr) <= 0) {
			mdb_warn("failed to read n_name at %p\n", nm_name_addr);
		}
		mdb_printf("n_name:   %s at %p\n", (char *)n_name,
		    nm_name_addr);
		next_addr = addr + MY_NAMSIZ(nm.n_namlen);
	}

	mdb_dec_indent(2);
	return (next_addr);
}

static uint_t
process_nmn_record_hdr(uintptr_t addr)
{
	struct nm_rec_hdr	rhdr;

	/*
	 * we read this anyway as the first part of nm_rec, devid_min_rec,
	 * nm_shr_rec, and devid_shr_rec record is a nm_rec_hdr
	 */
	if (mdb_vread(&rhdr, sizeof (struct nm_rec_hdr), addr) !=
	    sizeof (struct nm_rec_hdr)) {
		mdb_warn("failed to read nm_rec_hdr at %p\n", addr);
		return (0);
	}

	mdb_printf("nmn_record: %p\n", addr);
	mdb_inc_indent(2);
	mdb_printf("r_revision:     %4u\n", rhdr.r_revision);
	mdb_printf("r_alloc_size:   %4u\n", rhdr.r_alloc_size);
	mdb_printf("r_used_size:    %4u\n", rhdr.r_used_size);
	mdb_printf("r_next_recid:   %4x\n", rhdr.r_next_recid);
	mdb_printf("xr_next_rec:    %4u\n", rhdr.xr_next_rec);
	mdb_printf("r_next_key:     %4d\n", rhdr.r_next_key);
	mdb_dec_indent(2);
	return (rhdr.r_used_size);
}

static void
process_nmn_record(uintptr_t addr, int shared, int devid)
{
	struct nm_shr_rec	srhdr;
	struct devid_shr_rec	didsrhdr;
	struct nm_rec		nm_record;
	struct devid_min_rec	devid_record;
	uintptr_t		shn_addr;
	int			i;
	uintptr_t		next_addr, start_addr;
	uint_t			used_size;

	used_size = process_nmn_record_hdr(addr);

	if (devid) {
		if (shared) {
			if (mdb_vread(&didsrhdr, sizeof (struct devid_shr_rec),
			    addr) != sizeof (struct devid_shr_rec)) {
				mdb_warn("failed to read devid_shr_rec at %p\n",
				    addr);
				return;
			}
		} else {
			if (mdb_vread(&devid_record,
			    sizeof (struct devid_min_rec), addr)
			    != sizeof (struct devid_min_rec)) {
				mdb_warn("failed to read devid_min_rec at %p\n",
				    addr);
				return;
			}
		}
	} else {
		if (shared) {
			if (mdb_vread(&srhdr, sizeof (struct nm_shr_rec), addr)
			    != sizeof (struct nm_shr_rec)) {
				mdb_warn("failed to read nm_shr_rec at %p\n",
				    addr);
				return;
			}
		} else {
			if (mdb_vread(&nm_record, sizeof (struct nm_rec), addr)
			    != sizeof (struct nm_rec)) {
				mdb_warn("failed to read nm_rec at %p\n", addr);
				return;
			}
		}
	}
	mdb_inc_indent(2);
	if (devid) {
		if (shared) {
			/*
			 * Do the rest of the device_id records.
			 */
			next_addr = addr + ((uintptr_t)&didsrhdr.device_id[0] -
			    (uintptr_t)&didsrhdr);
			start_addr = next_addr;
			for (i = 0; ; i++) {
				shn_addr = next_addr;
				next_addr = print_did_shared_name(shn_addr, i);
				if (next_addr == NULL) {
					mdb_dec_indent(2);
					return;
				}
				/*
				 * Causes us to print one extra record.
				 */
				if ((next_addr - start_addr > used_size) ||
				    (next_addr == shn_addr)) {
					break;
				}
			}
		} else {
			/*
			 * Now do the rest of the record.
			 */
			next_addr = addr +
			    ((uintptr_t)&devid_record.minor_name[0] -
			    (uintptr_t)&devid_record);
			start_addr = next_addr;
			for (i = 0; ; i++) {
				shn_addr = next_addr;
				next_addr = print_devid_name(shn_addr, i);
				if (next_addr == NULL) {
					mdb_dec_indent(2);
					return;
				}
				if ((next_addr - start_addr > used_size) ||
				    (next_addr == shn_addr)) {
					break;
				}
			}
		}
	} else {
		if (shared) {
			/*
			 * Now do the rest of the sr_name records.
			 */
			next_addr = addr + ((uintptr_t)&srhdr.sr_name[0] -
			    (uintptr_t)&srhdr);
			start_addr = next_addr;
			for (i = 0; ; i++) {
				shn_addr = next_addr;
				next_addr = print_nm_shared_name(shn_addr, i);
				if (next_addr == NULL) {
					mdb_dec_indent(2);
					return;
				}
				/*
				 * Causes us to print one extra record
				 */
				if ((next_addr - start_addr > used_size) ||
				    (next_addr == shn_addr)) {
					break;
				}
			}
		} else {
			/*
			 * Now do the rest of the record
			 */
			next_addr = addr + ((uintptr_t)&nm_record.r_name[0] -
			    (uintptr_t)&nm_record);
			start_addr = next_addr;
			for (i = 0; ; i++) {
				shn_addr = next_addr;
				next_addr = print_nm_name(shn_addr, i);
				if (next_addr == NULL) {
					mdb_dec_indent(2);
					return;
				}
				if ((next_addr - start_addr > used_size) ||
				    (next_addr == shn_addr)) {
					break;
				}
			}
		}
	}
	mdb_dec_indent(2);
}

static void
process_nm_next_hdr(uintptr_t addr, int shared, int devid)
{
	uintptr_t	next = addr;
	struct nm_next_hdr	nhdr;

	mdb_inc_indent(2);
	mdb_printf("%p\n", next);
	if (mdb_vread(&nhdr, sizeof (struct nm_next_hdr), next) !=
	    sizeof (struct nm_next_hdr)) {
		mdb_warn("failed to read nm_next_hdr at %p", next);
		return;
	}
	(void) process_nmn_record_hdr((uintptr_t)nhdr.nmn_record);
	next = (uintptr_t)nhdr.nmn_nextp;
	while (next != (uintptr_t)0) {

		mdb_printf("\n");
		mdb_printf("nmn_nextp %p\n", nhdr.nmn_nextp);
		if (mdb_vread(&nhdr, sizeof (struct nm_next_hdr), next) !=
		    sizeof (struct nm_next_hdr)) {
			mdb_warn("failed to read nm_next_hdr at %p\n", next);
			break;
		}
		process_nmn_record((uintptr_t)nhdr.nmn_record, shared, devid);
		next = (uintptr_t)nhdr.nmn_nextp;
	}
	mdb_printf("\n");
	mdb_dec_indent(2);
}
/*
 * Start the processing of a nominated set
 */
static void
process_set(int setno)
{
	uintptr_t	addr = (uintptr_t)mdset[setno].s_nm;
	uintptr_t	did_addr = (uintptr_t)mdset[setno].s_did_nm;
	uintptr_t	shared_addr, names_addr;
	uintptr_t	did_names_addr, did_shared_addr;
	struct nm_header_hdr	hdr, did_hdr;

	mdb_printf("------ Name Space for setno %d ------\n", setno);

	if (mdb_vread(&hdr, sizeof (struct nm_header_hdr), addr) !=
	    sizeof (struct nm_header_hdr)) {
		mdb_warn("failed to read nm_header_hdr at %p\n", addr);
		return;
	}
	mdb_printf("hh_header: %p  \n", hdr.hh_header);
	if (did_addr != NULL) {	/* device id's exist */
		if (mdb_vread(&did_hdr, sizeof (struct nm_header_hdr),
		    did_addr) != sizeof (struct nm_header_hdr)) {
			mdb_warn("failed to read nm_header_hdr at %p\n",
			    did_addr);
			return;
		}
		mdb_printf("did hh_header: %p \n", did_hdr.hh_header);
	did_names_addr =
	    (uintptr_t)&(((struct nm_header_hdr *)did_addr)->hh_names);
	did_shared_addr =
	    (uintptr_t)&(((struct nm_header_hdr *)did_addr)->hh_shared);
	}

	names_addr = (uintptr_t)&(((struct nm_header_hdr *)addr)->hh_names);
	shared_addr = (uintptr_t)&(((struct nm_header_hdr *)addr)->hh_shared);
	mdb_printf("hh_names: %p \n", names_addr);
	mdb_printf("hh_shared: %p\n", shared_addr);

	if (did_addr != NULL) {
		mdb_printf("did hh_names: %p \n", did_names_addr);
		mdb_printf("did hh_shared: %p\n", did_shared_addr);
	}

	mdb_printf("hh_names:");
	process_nm_next_hdr(names_addr, 0, 0);
	mdb_printf("\nhh_shared:");
	process_nm_next_hdr(shared_addr, 1, 0);

	if (did_addr != NULL) {
		mdb_printf("did hh_names:");
		process_nm_next_hdr(did_names_addr, 0, 1);
		mdb_printf("\ndid hh_shared:");
		process_nm_next_hdr(did_shared_addr, 1, 1);
	}
}
/*
 * Dump the name space for all sets or specified set (-s option)
 * usage: ::dumpnamespace [-s setname]
 */
/* ARGSUSED */
int
dumpnamespace(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	char	*s_opt = NULL;
	int	j;
	int	setno;

	if (mdb_getopts(argc, argv, 's', MDB_OPT_STR, &s_opt,
	    NULL) != argc) {
		/* left over arguments ?? */
		return (DCMD_USAGE);
	}

	snarf_sets();

	if (argc == 0) {
		for (j = 0; j < md_nsets; j++) {
			if (mdset[j].s_status & MD_SET_NM_LOADED) {
				process_set(j);
			}
		}
	} else {
		setno = findset(s_opt);
		if (setno == -1) {
			mdb_warn("no such set: %s\n", s_opt);
			return (DCMD_ERR);
		}
		if (mdset[setno].s_status & MD_SET_NM_LOADED) {
			process_set(setno);
		}
	}
	return (DCMD_OK);
}
