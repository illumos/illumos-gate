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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <libproc.h>
#include <proc_service.h>
#include <synch.h>
#include <sys/types.h>
#include <sys/link.h>
#include <rtld_db.h>

#include <sn1_brand.h>

/*
 * ATTENTION:
 *	Librtl_db brand plugin libraries should NOT directly invoke any
 *	libproc.so interfaces or be linked against libproc.  If a librtl_db
 *	brand plugin library uses libproc.so interfaces then it may break
 *	any other librtld_db consumers (like mdb) that tries to attach
 *	to a branded process.  The only safe interfaces that the a librtld_db
 *	brand plugin library can use to access a target process are the
 *	proc_service(3PROC) apis.
 */

/*
 * M_DATA comes from some streams header file but is also redifined in
 * _rtld_db.h, so nuke the old streams definition here.
 */
#ifdef M_DATA
#undef M_DATA
#endif /* M_DATA */

/*
 * For 32-bit versions of this library, this file get's compiled once.
 * For 64-bit versions of this library, this file get's compiled twice,
 * once with _ELF64 defined and once without.  The expectation is that
 * the 64-bit version of the library can properly deal with both 32-bit
 * and 64-bit elf files, hence in the 64-bit library there are two copies
 * of all the interfaces in this file, one set named *32 and one named *64.
 *
 * This also means that we need to be careful when declaring local pointers
 * that point to objects in another processes address space, since these
 * pointers may not match the current processes pointer width.  Basically,
 * we should not use any objects that change size between 32 and 64 bit
 * modes like: long, void *, uintprt_t, caddr_t, psaddr_t, size_t, etc.
 * Instead we should declare all pointers as uint32_t.  Then when we
 * are compiled to deal with 64-bit targets we'll re-define uing32_t
 * to be a uint64_t.
 */
#ifdef _LP64
#ifdef _ELF64
#define	uint32_t			uint64_t
#define	Elf32_Dyn			Elf64_Dyn
#define	validate_rdebug32		validate_rdebug64
#define	_rd_loadobj_iter32		_rd_loadobj_iter64
#define	_rd_get_dyns32			_rd_get_dyns64
#define	dummy_ldb32			dummy_ldb64
#define	dummy_ldb_init32		dummy_ldb_init64
#define	dummy_ldb_fini32		dummy_ldb_fini64
#define	dummy_ldb_loadobj_iter32	dummy_ldb_loadobj_iter64
#define	dummy_ldb_get_dyns32		dummy_ldb_get_dyns64
#define	sn1_ldb_init32			sn1_ldb_init64
#define	sn1_ldb_fini32			sn1_ldb_fini64
#define	sn1_ldb_loadobj_iter32		sn1_ldb_loadobj_iter64
#define	sn1_ldb_get_dyns32		sn1_ldb_get_dyns64
#endif /* _ELF64 */
#endif /* _LP64 */

/* Included from usr/src/cmd/sgs/librtld_db/common */
#include <_rtld_db.h>

/*ARGSUSED*/
static rd_helper_data_t
dummy_ldb_init32(rd_agent_t *rap, struct ps_prochandle *php)
{
	return (NULL);
}

/*ARGSUSED*/
static void
dummy_ldb_fini32(rd_helper_data_t rhd)
{
}

/*ARGSUSED*/
static int
dummy_ldb_loadobj_iter32(rd_helper_data_t rhd, rl_iter_f *cb, void *client_data)
{
	return (RD_OK);
}

/*ARGSUSED*/
static rd_err_e
dummy_ldb_get_dyns32(rd_helper_data_t rhd,
    psaddr_t addr, void **dynpp, size_t *dynpp_sz)
{
	*dynpp = NULL;
	*dynpp_sz = 0;
	return (RD_OK);
}

static rd_helper_ops_t dummy_ldb32 = {
	LM_ID_BRAND,
	dummy_ldb_init32,
	dummy_ldb_fini32,
	dummy_ldb_loadobj_iter32,
	dummy_ldb_get_dyns32
};

static uint32_t
sn1_ldb_getauxval32(struct ps_prochandle *php, int type)
{
	const auxv_t		*auxvp = NULL;

	if (ps_pauxv(php, &auxvp) != PS_OK)
		return ((uint32_t)-1);

	while (auxvp->a_type != AT_NULL) {
		if (auxvp->a_type == type)
			return ((uint32_t)(uintptr_t)auxvp->a_un.a_ptr);
		auxvp++;
	}
	return ((uint32_t)-1);
}

/*
 * Normally, the native Solaris librtldb_db plugin uses a bunch of different
 * methods to try and find the rdebug structure associated with the target
 * process we're debugging.  For details on the different methods see
 * _rd_reset32().  Thankfully our job is easier.  We know that the brand
 * library is always linked against the native linker, and when the
 * process was first executed we saved off a pointer to the brand linkers
 * rdebug structure in one of our brand specific aux vectors,
 * AT_SUN_BRAND_SN1_LDDATA.  So we'll just look that up here.
 */
/*ARGSUSED*/
static rd_helper_data_t
sn1_ldb_init32(rd_agent_t *rap, struct ps_prochandle *php)
{
	struct rd_agent	*rap_new;
	uint32_t	lddata_addr;
	int		rd_dmodel;

	if (ps_pdmodel(php, &rd_dmodel) != PS_OK) {
		ps_plog("sn1_ldb_init: lookup of data model failed");
		return (NULL);
	}
#ifdef _ELF64
	assert(rd_dmodel == PR_MODEL_LP64);
#else /* !_ELF64 */
	assert(rd_dmodel == PR_MODEL_ILP32);
#endif /* !_ELF64 */

	lddata_addr = sn1_ldb_getauxval32(php, AT_SUN_BRAND_SN1_LDDATA);
	if (lddata_addr == (uint32_t)-1) {
		ps_plog("sn1_ldb_init: no LDDATA found in aux vector");
		return (NULL);
	}
	ps_plog("sn1_ldb_init: found LDDATA auxv ld.so.1 data seg "
	    "at: 0x%p", lddata_addr);

	/*
	 * Ok.  So this is kinda ugly.  Basically we know that we're going to
	 * be parsing data from link maps that are generated by a Solaris
	 * linker.  As it turns out, that's exactly what the default
	 * Solaris librtld_db library is designed to do.  So rather than
	 * duplicate all that link map parsing code here we'll simply
	 * invoke the native librtld_db that normally does this, and when
	 * we do we'll point them at our emulation libraries link map.
	 *
	 * Of course these interfacess aren't really public interfaces
	 * and they take a "struct rd_agent" as a parameter.  So here
	 * we'll allocate and initialize a new "struct rd_agent", point
	 * it at our emulation libraries link map, and initialize just
	 * enough of the structure to make the librtld_db interfaces
	 * that we want to use happy.
	 */
	if ((rap_new = calloc(sizeof (*rap_new), 1)) == NULL) {
		ps_plog("sn1_ldb_init: can't allocate memory");
		return (NULL);
	}
	rap_new->rd_dmodel = rd_dmodel;
	rap_new->rd_psp = php;
	rap_new->rd_rdebug = lddata_addr;
	(void) mutex_init(&rap_new->rd_mutex, USYNC_THREAD, 0);

	/*
	 * When we get invoked from librtld_db, and we call back into it,
	 * librtld_db will once again check if there is a plugin and
	 * invoke it.  Since we don't want to enter a recursive loop
	 * we're going to specify a different plugin interface for
	 * our linkmap, and these new plugin interfaces won't actually
	 * do anything other than return.
	 */
	rap_new->rd_helper.rh_ops = &dummy_ldb32;

	/*
	 * validate_rdebug32() requires the following "struct rd_agent"
	 * members to be initialized:
	 *	rd_psp, rd_rdebug
	 *
	 * validate_rdebug32() initializes the following "struct rd_agent"
	 * members:
	 *	rd_flags, rd_rdebugvers, rd_rtlddbpriv
	 */
	if (validate_rdebug32(rap_new) != RD_OK) {
		ps_plog("sn1_ldb_init: can't find valid r_debug data");
		free(rap_new);
		return (NULL);
	}

	ps_plog("sn1_ldb_init: finished, helper_data=0x%p", rap_new);
	return ((rd_helper_data_t)rap_new);
}

static void
sn1_ldb_fini32(rd_helper_data_t rhd)
{
	struct rd_agent	*rap = (struct rd_agent *)rhd;
	ps_plog("lx_ldb_fini: cleaning up sn1 helper");
	free(rap);
}

/*ARGSUSED*/
static int
sn1_ldb_loadobj_iter32(rd_helper_data_t rhd, rl_iter_f *cb, void *client_data)
{
	struct rd_agent	*rap = (struct rd_agent *)rhd;
	int		err;

	ps_plog("sn1_ldb_loadobj_iter(helper_data=0x%p)", rhd);
	assert(rap->rd_psp == php);
	RDAGLOCK(rap);
	/*
	 * _rd_loadobj_iter32() requires the following "struct rd_agent"
	 * members to be initialized:
	 * 	rd_rtlddbpriv, rd_rdebugvers, rd_flags,
	 * 	rd_helper.rh_ops, rd_dmodel
	 */
	err = _rd_loadobj_iter32(rap, cb, client_data);
	RDAGUNLOCK(rap);
	ps_plog("sn1_ldb_loadobj_iter: finished, err = %d", err);
	return (err);
}

/*ARGSUSED*/
static rd_err_e
sn1_ldb_get_dyns32(rd_helper_data_t rhd,
    psaddr_t addr, void **dynpp, size_t *dynpp_sz)
{
	struct rd_agent	*rap = (struct rd_agent *)rhd;
	int		err;

	ps_plog("sn1_ldb_get_dyns(helper_data=0x%p)", rhd);
	err = _rd_get_dyns32(rap, addr, (Elf32_Dyn **)dynpp, dynpp_sz);
	ps_plog("sn1_ldb_get_dyns: finished, err = %d", err);
	return (err);
}

/*
 * Librtld_db plugin linkage struct.
 *
 * When we get loaded by librtld_db, it will look for the symbol below
 * to find our plugin entry points.
 */
rd_helper_ops_t RTLD_DB_BRAND_OPS = {
	LM_ID_NONE,
	sn1_ldb_init32,
	sn1_ldb_fini32,
	sn1_ldb_loadobj_iter32,
	sn1_ldb_get_dyns32
};
