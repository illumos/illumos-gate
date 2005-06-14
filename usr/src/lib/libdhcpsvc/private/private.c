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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This module contains the private layer API.
 */

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/param.h>
#include <libelf.h>
#include <gelf.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <glob.h>
#include <fcntl.h>
#include <libinetutil.h>
#include <dhcp_svc_public.h>
#include <dhcp_svc_private.h>

/*
 * Threading notes for private layer consumers:
 *
 * The handles returned from open_dd() may be shared across multiple
 * threads with no adverse side effects.  However, it's up to that consumer
 * to ensure that all threads have finished using an instance before
 * closing the instance or removing the container it's referencing.
 * Phrased differently:
 *
 *	* Consumers must ensure all threads sharing a handle are
 *	  finished before calling close_dd().
 *
 *	* Consumers must ensure all threads referencing a container are
 *	  closed before calling remove_dd().
 */

static boolean_t validate_dd_entry(dsvc_handle_t, const void *, boolean_t);
static int  synch_init(dsvc_handle_t, const char *, uint_t);
static void synch_fini(dsvc_handle_t);

/*
 * Order here should match the function array in <dhcp_svc_private.h>
 */
static char	*funcnames[] = {
	"status",	"version",	"mklocation",
	"list_dt",	"open_dt",	"close_dt",	"remove_dt",
	"lookup_dt",	"add_dt",	"modify_dt",	"delete_dt",
	"list_dn",	"open_dn",	"close_dn",	"remove_dn",
	"lookup_dn",	"add_dn",	"modify_dn",	"delete_dn"
};

extern dsvc_synch_ops_t dsvcd_synch_ops;

/*
 * Retrieve the current version associated with the datastore named by
 * `resource' and store in `converp'.  One might think we could do this via
 * a simple readlink(2), but on internal release builds $(ROOTLINKS)
 * installs using hardlinks, not symlinks.  For this reason and to make it
 * harder for us to be fooled, we'll dredge up the actual soname through
 * ELF.  Close your eyes, it's gonna get ugly.
 */
static int
get_conver(const char *resource, int *converp)
{
	int		elf_fd;
	int		i;
	GElf_Shdr	gelf_shdr;
	GElf_Dyn	gelf_dyn;
	Elf_Scn		*elf_scn = NULL;
	Elf		*elf_file;
	Elf_Data	*elf_data;
	char		*soname = NULL;
	char		path[MAXPATHLEN];

	(void) snprintf(path, sizeof (path), "%s%s/%s_%s.so", DHCP_CONFOPT_ROOT,
	    DSVC_MODULE_DIR, DSVC_PUBLIC_PREFIX, resource);

	elf_fd = open(path, O_RDONLY);
	if (elf_fd == -1)
		return (DSVC_MODULE_ERR);

	if (elf_version(EV_CURRENT) == EV_NONE) {
		(void) close(elf_fd);
		return (DSVC_INTERNAL);
	}

	elf_file = elf_begin(elf_fd, ELF_C_READ, NULL);
	if (elf_file == NULL || elf_kind(elf_file) != ELF_K_ELF) {
		(void) close(elf_fd);
		return (DSVC_INTERNAL);
	}

	while ((elf_scn = elf_nextscn(elf_file, elf_scn)) != NULL) {
		if (gelf_getshdr(elf_scn, &gelf_shdr) == 0)
			continue;

		if (gelf_shdr.sh_type != SHT_DYNAMIC)
			continue;

		elf_data = elf_getdata(elf_scn, NULL);
		if (elf_data == NULL)
			continue;

		i = 0;
		do {
			(void) gelf_getdyn(elf_data, i++, &gelf_dyn);
			if (gelf_dyn.d_tag == DT_SONAME)
				soname = elf_strptr(elf_file, gelf_shdr.sh_link,
				    gelf_dyn.d_un.d_ptr);
		} while (gelf_dyn.d_tag != DT_NULL && soname == NULL);
	}
	if (soname == NULL || sscanf(soname, "%*[^.].so.%d", converp) != 1) {
		(void) elf_end(elf_file);
		(void) close(elf_fd);
		return (DSVC_MODULE_ERR);
	}
	(void) elf_end(elf_file);
	(void) close(elf_fd);

	return (DSVC_SUCCESS);
}

/*
 * Unload a public datastore module.
 */
static int
unload_public_module(void **instance, dsvc_splapi_t *api)
{
	static dsvc_splapi_t	null_api;

	if (dlclose(*instance) != 0)
		return (DSVC_MODULE_UNLOAD_ERR);

	*instance = NULL;
	*api = null_api;

	return (DSVC_SUCCESS);
}

/*
 * Load public datastore module.  Validates version of module.  Returns
 * instance of opened module, and populates the api argument with the
 * function addresses exporting the API.
 */
static int
load_public_module(dsvc_datastore_t *ddp, void **instance, dsvc_splapi_t *api)
{
	int		i, v;
	dsvc_splfuncp_t	configure;
	char		path[MAXPATHLEN];

	(void) snprintf(path, sizeof (path), "%s%s/%s_%s.so", DHCP_CONFOPT_ROOT,
	    DSVC_MODULE_DIR, DSVC_PUBLIC_PREFIX, ddp->d_resource);

	if (ddp->d_conver != DSVC_CUR_CONVER)
		(void) snprintf(path, sizeof (path), "%s.%d", path,
		    ddp->d_conver);

	*instance = dlopen(path, RTLD_LAZY|RTLD_GROUP|RTLD_WORLD);
	if (*instance == NULL)
		return (DSVC_MODULE_LOAD_ERR);

	/*
	 * No requirement to duplicate the names - we can always reference
	 * the same set.
	 */
	api->version = (dsvc_splfuncp_t)dlsym(*instance, "version");
	if (api->version == NULL || api->version(&v) != DSVC_SUCCESS ||
	    v != DSVC_PUBLIC_VERSION) {
		(void) unload_public_module(instance, api);
		return (DSVC_MODULE_VERSION);
	}

	configure = (dsvc_splfuncp_t)dlsym(*instance, "configure");
	if (configure != NULL) {
		if (configure(ddp->d_config) != DSVC_SUCCESS) {
			(void) unload_public_module(instance, api);
			return (DSVC_MODULE_CFG_ERR);
		}
	}

	for (i = 0; i < DSVC_NSPLFUNCS; i++) {
		if ((((dsvc_splfuncp_t *)api)[i] =
		    (dsvc_splfuncp_t)dlsym(*instance, funcnames[i])) == NULL) {
			(void) unload_public_module(instance, api);
			return (DSVC_MODULE_ERR);
		}
	}

	/*
	 * Caller requested the current version; fill in what that current
	 * version is.
	 */
	if (ddp->d_conver == DSVC_CUR_CONVER) {
		int	error;
		error = get_conver(ddp->d_resource, &ddp->d_conver);
		if (error != DSVC_SUCCESS) {
			(void) unload_public_module(instance, api);
			return (error);
		}
	}

	return (DSVC_SUCCESS);
}

/*
 * Return a dynamically-allocated null-terminated list of the available
 * modules stored in the module directory.  A count of the available
 * modules is stored in the num argument.  Caller is responsible for
 * freeing the list.
 */
int
enumerate_dd(char ***modules, int *nump)
{
	int	i, retval;
	char	*ptr;
	glob_t	globbuf;
	char	globpat[MAXPATHLEN];

	if (modules == NULL || nump == NULL)
		return (DSVC_INVAL);

	(void) snprintf(globpat, sizeof (globpat), "%s%s/%s_*\\.so",
	    DHCP_CONFOPT_ROOT, DSVC_MODULE_DIR, DSVC_PUBLIC_PREFIX);

	retval = glob(globpat, GLOB_NOSORT, NULL, &globbuf);
	if (retval != 0) {
		globfree(&globbuf);
		switch (retval) {
		case GLOB_NOMATCH:
			*nump = 0;
			*modules = NULL;
			return (DSVC_SUCCESS);
		case GLOB_NOSPACE:
			return (DSVC_NO_MEMORY);
		default:
			return (DSVC_INTERNAL);
		}
	}

	*modules = calloc(globbuf.gl_pathc, sizeof (char **));
	if (*modules == NULL) {
		globfree(&globbuf);
		return (DSVC_NO_MEMORY);
	}

	for (i = 0; i < globbuf.gl_pathc; i++) {
		ptr = strrchr(globbuf.gl_pathv[i], '/');
		if (ptr == NULL)
			ptr = globbuf.gl_pathv[i];
		else
			ptr++;
		(*modules)[i] = malloc(strlen(ptr) + 1);
		if ((*modules)[i] == NULL) {
			while (i--)
				free((*modules)[i]);
			free(modules);
			globfree(&globbuf);
			return (DSVC_NO_MEMORY);
		}

		(void) sscanf(ptr, "%*[^_]_%[^.]", (*modules)[i]);
	}

	globfree(&globbuf);
	*nump = i;
	return (DSVC_SUCCESS);
}

/*
 * Check the status of the underlying service supporting the data store.
 * Caller is responsible for freeing any dynamically allocated arguments.
 */
int
status_dd(dsvc_datastore_t *ddp)
{
	void		*instance;
	dsvc_splapi_t	api;
	int		error;

	error = load_public_module(ddp, &instance, &api);
	if (error != DSVC_SUCCESS)
		return (error);

	error = api.status(ddp->d_location);

	(void) unload_public_module(&instance, &api);

	return (error);
}

/*
 * Create within the data store the "location" where containers will be
 * stored.
 */
int
mklocation_dd(dsvc_datastore_t *ddp)
{
	void		*instance;
	dsvc_splapi_t	api;
	int		error;

	error = load_public_module(ddp, &instance, &api);
	if (error != DSVC_SUCCESS)
		return (error);

	error = api.mklocation(ddp->d_location);

	(void) unload_public_module(&instance, &api);

	return (error);
}

/*
 * Return a list of the current container objects of type 'type' located at
 * 'location' in listppp.  Return the number of list elements in 'count'.
 */
int
list_dd(dsvc_datastore_t *ddp, dsvc_contype_t type, char ***listppp,
    uint_t *count)
{
	void		*instance;
	dsvc_splapi_t	api;
	int		error;

	error = load_public_module(ddp, &instance, &api);
	if (error != DSVC_SUCCESS)
		return (error);

	if (type == DSVC_DHCPTAB)
		error = api.list_dt(ddp->d_location, listppp, count);
	else
		error = api.list_dn(ddp->d_location, listppp, count);

	(void) unload_public_module(&instance, &api);

	return (error);
}

/*
 * Creates or opens the DHCP container of type called name within the
 * specific datastore referenced by ddp, and returns a handle to this
 * container in the handp argument.  New containers are created with
 * the identity of the caller.  Caller is responsible for freeing any
 * dynamically allocated arguments.  The returned handle instance must
 * be released by calling close_dd().
 */
int
open_dd(dsvc_handle_t *handp, dsvc_datastore_t *ddp, dsvc_contype_t type,
    const char *name, uint_t flags)
{
	int			error;
	dsvc_handle_t		hp;

	*handp = NULL;

	if (type == DSVC_DHCPNETWORK && name == NULL)
		return (DSVC_INVAL);

	if (flags & DSVC_CREATE && (flags & DSVC_WRITE) == 0)
		return (DSVC_INVAL);

	if ((hp = calloc(1, sizeof (struct dsvc_handle))) == NULL)
		return (DSVC_NO_MEMORY);

	if (type == DSVC_DHCPNETWORK) {
		hp->d_conid.c_net.s_addr = ntohl(inet_addr(name));
		if (hp->d_conid.c_net.s_addr == INADDR_BROADCAST) {
			free(hp);
			return (DSVC_INVAL);
		}
		get_netmask4(&hp->d_conid.c_net, &hp->d_conid.c_mask);
	}

	error = load_public_module(ddp, &hp->d_instance, &hp->d_api);
	if (error != DSVC_SUCCESS) {
		free(hp);
		return (error);
	}

	hp->d_type = type;
	hp->d_desc.d_conver = ddp->d_conver;
	hp->d_desc.d_resource = strdup(ddp->d_resource);
	hp->d_desc.d_location = strdup(ddp->d_location);
	if (hp->d_desc.d_resource == NULL || hp->d_desc.d_location == NULL) {
		error = DSVC_NO_MEMORY;
		goto error;
	}

	/*
	 * Initialize the synchronization strategy (may not be any).
	 */
	error = synch_init(hp, name, flags);
	if (error != DSVC_SUCCESS)
		goto error;

	if (type == DSVC_DHCPTAB)
		error = hp->d_api.open_dt(&hp->d_hand, ddp->d_location, flags);
	else
		error = hp->d_api.open_dn(&hp->d_hand, ddp->d_location, flags,
		    &hp->d_conid.c_net, &hp->d_conid.c_mask);

	if (error != DSVC_SUCCESS) {
		if (hp->d_synch != NULL)
			synch_fini(hp);
		goto error;
	}

	*handp = hp;
	return (DSVC_SUCCESS);
error:
	(void) unload_public_module(&hp->d_instance, &hp->d_api);
	free(hp->d_desc.d_resource);
	free(hp->d_desc.d_location);
	free(hp);
	return (error);
}

/*
 * Remove DHCP container called name of type within the specific datastore
 * referenced by ddp.  Caller is responsible for freeing any dynamically
 * allocated arguments.
 */
int
remove_dd(dsvc_datastore_t *ddp, dsvc_contype_t type, const char *name)
{
	void		*instance;
	int		error;
	dsvc_splapi_t	api;
	struct in_addr	ip, mask;

	if (type != DSVC_DHCPTAB) {
		if ((ip.s_addr = inet_addr(name)) == INADDR_BROADCAST)
			return (DSVC_INVAL);
		ip.s_addr = ntohl(ip.s_addr);
		get_netmask4(&ip, &mask);
	}

	error = load_public_module(ddp, &instance, &api);
	if (error != DSVC_SUCCESS)
		return (error);

	/* remove the DHCP container */
	if (type == DSVC_DHCPTAB)
		error = api.remove_dt(ddp->d_location);
	else
		error = api.remove_dn(ddp->d_location, &ip, &mask);

	(void) unload_public_module(&instance, &api);

	return (error);
}

/*
 * Delete the handle instance referenced by hand. Frees hand if the close
 * operation was successful.  NOTE: Caller is responsible for synchronizing
 * multiple threads such that close_dd() is called when all consuming
 * threads have exited.
 */
int
close_dd(dsvc_handle_t *handp)
{
	int	error;

	if (handp == NULL || DSVC_HANDLE_INVAL(*handp))
		return (DSVC_INVAL);

	if ((*handp)->d_type == DSVC_DHCPTAB)
		error = (*handp)->d_api.close_dt(&((*handp)->d_hand));
	else
		error = (*handp)->d_api.close_dn(&((*handp)->d_hand));

	if (error == DSVC_SUCCESS) {
		error = unload_public_module(&(*handp)->d_instance,
		    &(*handp)->d_api);
		if ((*handp)->d_synch != NULL)
			synch_fini(*handp);
		free((*handp)->d_desc.d_resource);
		free((*handp)->d_desc.d_location);
		free(*handp);
		*handp = NULL;
	}

	return (error);
}

/*
 * Searches hand container for records that match the query described by
 * the combination of query and targetp. If the partial field is true, then
 * lookup operations that have located some records but are unable to
 * complete entirely are allowed.  The query argument consists of 2 fields,
 * each 16 bits long. The lower 16 bits selects which fields in the targetp
 * record are to be considered in the query. The upper 16 bits identifies
 * whether a particular field value must match (bit set) or not match (bit
 * clear). Unused bits in both 16 bit fields must be 0. The count argument
 * specifies the maximum number of matching records to return. A count
 * value of -1 requests that all matching records be returned. recordsp is
 * set to point to the resulting list of records; if recordsp is NULL then
 * no records are actually returned. Note that these records are
 * dynamically allocated, thus the caller is responsible for freeing them.
 * The number of records found is returned in nrecordsp; a value of 0 means
 * that no records matched the query.
 */
int
lookup_dd(dsvc_handle_t hand, boolean_t partial, uint_t query,
    int count, const void *targetp, void **recordsp, uint_t *nrecordsp)
{
	uint_t	mask = 0;
	int	error;
	void	*unlock_cookie;
	int	(*lookup)();

	if (targetp == NULL || nrecordsp == NULL || DSVC_HANDLE_INVAL(hand))
		return (DSVC_INVAL);

	if (hand->d_type == DSVC_DHCPTAB) {
		mask = (uint_t)~DT_QALL;
		lookup = hand->d_api.lookup_dt;
	} else {
		mask = (uint_t)~DN_QALL;
		lookup = hand->d_api.lookup_dn;
	}

	/* validate query */
	if (((query & 0xffff) & mask) || ((query >> 16) & mask))
		return (DSVC_INVAL);

	/*
	 * XXX: need to validate the `targetp' -- what a mess cuz only the
	 *	fields lit in `query' need to be valid.
	 */

	if (hand->d_synch != NULL) {
		error = DSVC_SYNCH_RDLOCK(hand->d_synch, &unlock_cookie);
		if (error != DSVC_SUCCESS)
			return (error);
	}

	error = lookup(hand->d_hand, partial, query, count, targetp, recordsp,
	    nrecordsp);

	if (hand->d_synch != NULL)
		(void) DSVC_SYNCH_UNLOCK(hand->d_synch, unlock_cookie);

	return (error);
}

/*
 * Frees the record pointed to by entryp.
 */
void
free_dd(dsvc_handle_t hand, void *entryp)
{
	if (DSVC_HANDLE_INVAL(hand) || entryp == NULL)
		return;

	if (hand->d_type == DSVC_DHCPTAB)
		free_dtrec((dt_rec_t *)entryp);
	else
		free_dnrec((dn_rec_t *)entryp);
}

/*
 * Frees the list of records pointed to by listp.
 */
void
free_dd_list(dsvc_handle_t hand, void *listp)
{
	if (DSVC_HANDLE_INVAL(hand) || listp == NULL)
		return;

	if (hand->d_type == DSVC_DHCPTAB)
		free_dtrec_list((dt_rec_list_t *)listp);
	else
		free_dnrec_list((dn_rec_list_t *)listp);
}

/*
 * Add the record newp to the DHCP container hand. newp's update signature
 * will be updated by the public layer module doing the update. Caller is
 * responsible for freeing newp if it was dynamically allocated.
 */
int
add_dd_entry(dsvc_handle_t hand, void *newp)
{
	int	error;
	void	*unlock_cookie;

	if (DSVC_HANDLE_INVAL(hand))
		return (DSVC_INVAL);

	if (!validate_dd_entry(hand, newp, B_FALSE))
		return (DSVC_INVAL);

	if (hand->d_synch != NULL) {
		error = DSVC_SYNCH_WRLOCK(hand->d_synch, &unlock_cookie);
		if (error != DSVC_SUCCESS)
			return (error);
	}

	if (hand->d_type == DSVC_DHCPTAB)
		error = hand->d_api.add_dt(hand->d_hand, newp);
	else
		error = hand->d_api.add_dn(hand->d_hand, newp);

	if (hand->d_synch != NULL)
		(void) DSVC_SYNCH_UNLOCK(hand->d_synch, unlock_cookie);

	return (error);
}

/*
 * Modify the record origp with the record newp in the DHCP container hand.
 * newp's update signature will be updated by the public layer module doing
 * the update. Caller is responsible for freeing origp and/or newp if they
 * were dynamically allocated.
 */
int
modify_dd_entry(dsvc_handle_t hand, const void *origp, void *newp)
{
	int	error;
	void 	*unlock_cookie;

	if (DSVC_HANDLE_INVAL(hand))
		return (DSVC_INVAL);

	if (!validate_dd_entry(hand, origp, B_TRUE))
		return (DSVC_INVAL);

	if (!validate_dd_entry(hand, newp, B_FALSE))
		return (DSVC_INVAL);

	if (hand->d_synch != NULL) {
		error = DSVC_SYNCH_WRLOCK(hand->d_synch, &unlock_cookie);
		if (error != DSVC_SUCCESS)
			return (error);
	}

	if (hand->d_type == DSVC_DHCPTAB)
		error = hand->d_api.modify_dt(hand->d_hand, origp, newp);
	else
		error = hand->d_api.modify_dn(hand->d_hand, origp, newp);

	if (hand->d_synch != NULL)
		(void) DSVC_SYNCH_UNLOCK(hand->d_synch, unlock_cookie);

	return (error);
}

/*
 * Deletes the record referred to by entryp from the DHCP container hand.
 * Caller is responsible for freeing entryp if it was dynamically
 * allocated.
 */
int
delete_dd_entry(dsvc_handle_t hand, void *entryp)
{
	int	error;
	void	*unlock_cookie;

	if (DSVC_HANDLE_INVAL(hand))
		return (DSVC_INVAL);

	if (!validate_dd_entry(hand, entryp, B_TRUE))
		return (DSVC_INVAL);

	if (hand->d_synch != NULL) {
		error = DSVC_SYNCH_WRLOCK(hand->d_synch, &unlock_cookie);
		if (error != DSVC_SUCCESS)
			return (error);
	}

	if (hand->d_type == DSVC_DHCPTAB)
		error = hand->d_api.delete_dt(hand->d_hand, entryp);
	else
		error = hand->d_api.delete_dn(hand->d_hand, entryp);

	if (hand->d_synch != NULL)
		(void) DSVC_SYNCH_UNLOCK(hand->d_synch, unlock_cookie);

	return (error);
}

/*
 * Validate that the DHCP network record `dn' is correctly formed; returns
 * B_TRUE if it is, B_FALSE if it's not.  If `justkey' is set, then only
 * validate the key.
 */
static boolean_t
validate_dnrec(dsvc_handle_t hand, const dn_rec_t *dn, boolean_t justkey)
{
	/* CIP must be on container's network */
	if (hand->d_conid.c_net.s_addr !=
	    (dn->dn_cip.s_addr & hand->d_conid.c_mask.s_addr))
		return (B_FALSE);

	if (justkey)
		return (B_TRUE);

	if (dn->dn_cid_len < 1 || dn->dn_cid_len > DN_MAX_CID_LEN)
		return (B_FALSE);

	if ((dn->dn_flags & ~DN_FALL) != 0)
		return (B_FALSE);

	return (B_TRUE);
}

/*
 * Validate that the dhcptab record `dt' is correctly formed; returns
 * B_TRUE if it is, B_FALSE if it's not.  If `justkey' is set, then only
 * validate the key.
 */
/* ARGSUSED */
static boolean_t
validate_dtrec(dsvc_handle_t hand, const dt_rec_t *dt, boolean_t justkey)
{
	return (dt->dt_type == DT_SYMBOL || dt->dt_type == DT_MACRO);
}

/*
 * Validate that a DHCP record of type `hand->d_type' is correctly formed;
 * returns B_TRUE if it is, B_FALSE if it's not.  If `justkey' is set, then
 * only validate the key.
 */
static boolean_t
validate_dd_entry(dsvc_handle_t hand, const void *entryp, boolean_t justkey)
{
	if (entryp == NULL)
		return (B_FALSE);

	if (hand->d_type == DSVC_DHCPTAB)
		return (validate_dtrec(hand, (dt_rec_t *)entryp, justkey));
	else if (hand->d_type == DSVC_DHCPNETWORK)
		return (validate_dnrec(hand, (dn_rec_t *)entryp, justkey));

	return (B_FALSE);
}

/*
 * Get the type of synchronization needed for this module and store in
 * `synchtypep'.  Returns a DSVC_* code.  This function is exported so that
 * dsvclockd(1M) can use it.
 */
int
module_synchtype(dsvc_datastore_t *ddp, dsvc_synchtype_t *synchtypep)
{
	void			*instance;
	dsvc_splapi_t		api;
	dsvc_synchtype_t	*dsvc_synchtypep;

	if (load_public_module(ddp, &instance, &api) != DSVC_SUCCESS)
		return (DSVC_INTERNAL);

	dsvc_synchtypep = dlsym(instance, "dsvc_synchtype");
	if (dsvc_synchtypep != NULL)
		*synchtypep = *dsvc_synchtypep;
	else
		*synchtypep = DSVC_SYNCH_NONE;

	(void) unload_public_module(&instance, &api);

	return (DSVC_SUCCESS);
}

/*
 * Initialize private-layer synchronization on handle `hand' for container
 * `conname'; `flags' is the same flags passed into open_dd().  If there's
 * no synchronization needed, always succeeds.  Returns a DSVC_* code.
 */
int
synch_init(dsvc_handle_t hand, const char *conname, uint_t flags)
{
	dsvc_synchtype_t	synchtype;
	dsvc_synch_t		*sp;
	int 			error;
	int			(*mkloctoken)(const char *, char *, size_t);

	error = module_synchtype(&hand->d_desc, &synchtype);
	if (error != DSVC_SUCCESS)
		return (error);

	if (synchtype == DSVC_SYNCH_NONE)
		return (DSVC_SUCCESS);

	sp = malloc(sizeof (dsvc_synch_t));
	if (sp == NULL)
		return (DSVC_NO_MEMORY);

	sp->s_conname = strdup(conname);
	if (sp->s_conname == NULL) {
		free(sp);
		return (DSVC_NO_MEMORY);
	}
	sp->s_nonblock	= flags & DSVC_NONBLOCK;
	sp->s_datastore = &hand->d_desc;

	mkloctoken = (int (*)())dlsym(hand->d_instance, "mkloctoken");
	if (mkloctoken == NULL) {
		(void) strlcpy(sp->s_loctoken, sp->s_datastore->d_location,
		    sizeof (sp->s_loctoken));
	} else {
		error = mkloctoken(sp->s_datastore->d_location, sp->s_loctoken,
		    sizeof (sp->s_loctoken));
		if (error != DSVC_SUCCESS) {
			free(sp->s_conname);
			free(sp);
			return (error);
		}
	}

	/*
	 * The only synchtype supported is DSVC_SYNCH_DSVCD; if this
	 * changes, we'll need to enhance this.
	 */
	assert((synchtype & DSVC_SYNCH_STRATMASK) == DSVC_SYNCH_DSVCD);
	sp->s_ops = &dsvcd_synch_ops;

	error = DSVC_SYNCH_INIT(sp, synchtype & DSVC_SYNCH_FLAGMASK);
	if (error != DSVC_SUCCESS) {
		free(sp->s_conname);
		free(sp);
		return (error);
	}

	hand->d_synch = sp;
	return (DSVC_SUCCESS);
}

/*
 * Finish using private-layer synchronization on handle `hand'.
 */
void
synch_fini(dsvc_handle_t hand)
{
	DSVC_SYNCH_FINI(hand->d_synch);
	free(hand->d_synch->s_conname);
	free(hand->d_synch);
	hand->d_synch = NULL;
}
