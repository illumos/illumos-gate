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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <fcntl.h>
#include <uuid/uuid.h>
#include <errno.h>
#include <unistd.h>
#include <strings.h>
#include <libintl.h>
#include <libscf.h>
#include <assert.h>

#include <libstmf.h>
#include <libiscsit.h>
#include <sys/iscsi_protocol.h>
#include <sys/iscsit/isns_protocol.h>

/* From iscsitgtd */
#define	TARGET_NAME_VERS	2

/* this should be defined someplace central... */
#define	ISCSI_NAME_LEN_MAX	223

/* max length of a base64 encoded secret */
#define	MAX_BASE64_LEN		341

/* Default RADIUS server port */
#define	DEFAULT_RADIUS_PORT	1812

/* The iscsit SMF service FMRI */
#define	ISCSIT_FMRI		"svc:/network/iscsi/target:default"
/*
 * The kernel reserves target portal group tag value 1 as the default.
 */
#define	ISCSIT_DEFAULT_TPGT	1
#define	MAXTAG			0xffff

/* helper for property list validation */
#define	PROPERR(lst, key, value) { \
	if (lst) { \
		(void) nvlist_add_string(lst, key, value); \
	} \
}

/* helper function declarations */
static int
it_iqn_generate(char *iqn_buf, int iqn_buf_len, char *opt_iqn_suffix);

static int
it_val_pass(char *name, char *val, nvlist_t *e);

/* consider making validate funcs public */
static int
it_validate_configprops(nvlist_t *nvl, nvlist_t *errs);

static int
it_validate_tgtprops(nvlist_t *nvl, nvlist_t *errs);

static int
it_validate_iniprops(nvlist_t *nvl, nvlist_t *errs);

static boolean_t
is_iscsit_enabled(void);

static void
iqnstr(char *s);

static void
euistr(char *s);

static void
free_empty_errlist(nvlist_t **errlist);

/*
 * Function:  it_config_load()
 *
 * Allocate and create an it_config_t structure representing the
 * current iSCSI configuration.  This structure is compiled using
 * the 'provider' data returned by stmfGetProviderData().  If there
 * is no provider data associated with iscsit, the it_config_t
 * structure will be set to a default configuration.
 *
 * Parameters:
 *    cfg	A C representation of the current iSCSI configuration
 *
 * Return Values:
 *    0		Success
 *    ENOMEM	Could not allocate resources
 *    EINVAL	Invalid parameter
 */
int
it_config_load(it_config_t **cfg)
{
	int		ret = 0;
	nvlist_t	*cfg_nv = NULL;
	it_config_t	*newcfg = NULL;
	uint64_t	stmf_token = 0;

	if (!cfg) {
		return (EINVAL);
	}

	*cfg = NULL;

	ret = stmfGetProviderDataProt(ISCSIT_MODNAME, &cfg_nv,
	    STMF_PORT_PROVIDER_TYPE, &stmf_token);

	if ((ret == STMF_STATUS_SUCCESS) ||
	    (ret == STMF_ERROR_NOT_FOUND)) {
		/*
		 * If not initialized yet, return empty it_config_t
		 * Else, convert nvlist to struct
		 */
		ret = it_nv_to_config(cfg_nv, &newcfg);
	}

	if (ret == 0) {
		newcfg->stmf_token = stmf_token;
		*cfg = newcfg;
	}

	if (cfg_nv) {
		nvlist_free(cfg_nv);
	}

	return (ret);
}

/*
 * Function:  it_config_commit()
 *
 * Informs the iscsit service that the configuration has changed and
 * commits the new configuration to persistent store by calling
 * stmfSetProviderData.  This function can be called multiple times
 * during a configuration sequence if necessary.
 *
 * Parameters:
 *    cfg	A C representation of the current iSCSI configuration
 *
 * Return Values:
 *    0		Success
 *    ENOMEM	Could not allocate resources
 *    EINVAL	Invalid it_config_t structure
 *    TBD	ioctl() failed
 *    TBD	could not save config to STMF
 */
int
it_config_commit(it_config_t *cfg)
{
	int			ret;
	nvlist_t		*cfgnv = NULL;
	char			*packednv = NULL;
	int			iscsit_fd = -1;
	size_t			pnv_size;
	iscsit_ioc_set_config_t	iop;
	it_tgt_t		*tgtp;

	if (!cfg) {
		return (EINVAL);
	}

	ret = it_config_to_nv(cfg, &cfgnv);
	if (ret == 0) {
		ret = nvlist_size(cfgnv, &pnv_size, NV_ENCODE_NATIVE);
	}

	/*
	 * If the iscsit service is enabled, send the changes to the
	 * kernel first.  Kernel will be the final sanity check before
	 * the config is saved persistently.
	 *
	 * This somewhat leaves open the simultaneous-change hole
	 * that STMF was trying to solve, but is a better sanity
	 * check and allows for graceful handling of target renames.
	 */
	if ((ret == 0) && is_iscsit_enabled()) {
		packednv = malloc(pnv_size);
		if (!packednv) {
			ret = ENOMEM;
		} else {
			ret = nvlist_pack(cfgnv, &packednv, &pnv_size,
			    NV_ENCODE_NATIVE, 0);
		}

		if (ret == 0) {
			iscsit_fd = open(ISCSIT_NODE, O_RDWR|O_EXCL);
			if (iscsit_fd != -1) {
				iop.set_cfg_vers = ISCSIT_API_VERS0;
				iop.set_cfg_pnvlist = packednv;
				iop.set_cfg_pnvlist_len = pnv_size;
				if ((ioctl(iscsit_fd, ISCSIT_IOC_SET_CONFIG,
				    &iop)) != 0) {
					ret = errno;
				}

				(void) close(iscsit_fd);
			} else {
				ret = errno;
			}
		}

		if (packednv != NULL) {
			free(packednv);
		}
	}

	/*
	 * Before saving the config persistently, remove any
	 * PROP_OLD_TARGET_NAME entries.  This is only interesting to
	 * the active service.
	 */
	if (ret == 0) {
		boolean_t	changed = B_FALSE;

		tgtp = cfg->config_tgt_list;
		for (; tgtp != NULL; tgtp = tgtp->tgt_next) {
			if (!tgtp->tgt_properties) {
				continue;
			}
			if (nvlist_exists(tgtp->tgt_properties,
			    PROP_OLD_TARGET_NAME)) {
				(void) nvlist_remove_all(tgtp->tgt_properties,
				    PROP_OLD_TARGET_NAME);
				changed = B_TRUE;
			}
		}

		if (changed) {
			/* rebuild the config nvlist */
			nvlist_free(cfgnv);
			cfgnv = NULL;
			ret = it_config_to_nv(cfg, &cfgnv);
		}
	}

	/*
	 * stmfGetProviderDataProt() checks to ensure
	 * that the config data hasn't changed since we fetched it.
	 *
	 * The kernel now has a version we need to save persistently.
	 * CLI will 'do the right thing' and warn the user if it
	 * gets STMF_ERROR_PROV_DATA_STALE.  We'll try once to revert
	 * the kernel to the persistently saved data, but ultimately,
	 * it's up to the administrator to validate things are as they
	 * want them to be.
	 */
	if (ret == 0) {
		ret = stmfSetProviderDataProt(ISCSIT_MODNAME, cfgnv,
		    STMF_PORT_PROVIDER_TYPE, &(cfg->stmf_token));

		if (ret == STMF_STATUS_SUCCESS) {
			ret = 0;
		} else if (ret == STMF_ERROR_NOMEM) {
			ret = ENOMEM;
		} else if (ret == STMF_ERROR_PROV_DATA_STALE) {
			int		st;
			it_config_t	*rcfg = NULL;

			st = it_config_load(&rcfg);
			if (st == 0) {
				(void) it_config_commit(rcfg);
				it_config_free(rcfg);
			}
		}
	}

	if (cfgnv) {
		nvlist_free(cfgnv);
	}

	return (ret);
}

/*
 * Function:  it_config_setprop()
 *
 * Validate the provided property list and set the global properties
 * for iSCSI Target.  If errlist is not NULL, returns detailed
 * errors for each property that failed.  The format for errorlist
 * is key = property, value = error string.
 *
 * Parameters:
 *
 *    cfg		The current iSCSI configuration obtained from
 *			it_config_load()
 *    proplist		nvlist_t containing properties for this target.
 *    errlist		(optional)  nvlist_t of errors encountered when
 *                      validating the properties.
 *
 * Return Values:
 *    0			Success
 *    EINVAL		Invalid property
 *
 */
int
it_config_setprop(it_config_t *cfg, nvlist_t *proplist, nvlist_t **errlist)
{
	int		ret;
	nvlist_t	*errs = NULL;
	it_portal_t	*isns = NULL;
	it_portal_t	*pnext = NULL;
	it_portal_t	*newisnslist = NULL;
	char		**arr;
	uint32_t	count;
	uint32_t	newcount;
	nvlist_t	*cprops = NULL;
	char		*val = NULL;

	if (!cfg || !proplist) {
		return (EINVAL);
	}

	if (errlist) {
		(void) nvlist_alloc(&errs, 0, 0);
		*errlist = errs;
	}

	/*
	 * copy the existing properties, merge, then validate
	 * the merged properties before committing them.
	 */
	if (cfg->config_global_properties) {
		ret = nvlist_dup(cfg->config_global_properties, &cprops, 0);
	} else {
		ret = nvlist_alloc(&cprops, NV_UNIQUE_NAME, 0);
	}

	if (ret != 0) {
		return (ret);
	}

	ret = nvlist_merge(cprops, proplist, 0);
	if (ret != 0) {
		nvlist_free(cprops);
		return (ret);
	}

	/*
	 * base64 encode the radius secret, if it's changed.
	 */
	val = NULL;
	(void) nvlist_lookup_string(proplist, PROP_RADIUS_SECRET, &val);
	if (val) {
		char		bsecret[MAX_BASE64_LEN];

		ret = it_val_pass(PROP_RADIUS_SECRET, val, errs);

		if (ret == 0) {
			(void) memset(bsecret, 0, MAX_BASE64_LEN);

			ret = iscsi_binary_to_base64_str((uint8_t *)val,
			    strlen(val), bsecret, MAX_BASE64_LEN);

			if (ret == 0) {
				/* replace the value in the nvlist */
				ret = nvlist_add_string(cprops,
				    PROP_RADIUS_SECRET, bsecret);
			}
		}
	}

	if (ret != 0) {
		nvlist_free(cprops);
		return (ret);
	}

	/* see if we need to remove the radius server setting */
	val = NULL;
	(void) nvlist_lookup_string(cprops, PROP_RADIUS_SERVER, &val);
	if (val && (strcasecmp(val, "none") == 0)) {
		(void) nvlist_remove_all(cprops, PROP_RADIUS_SERVER);
	}

	/* and/or remove the alias */
	val = NULL;
	(void) nvlist_lookup_string(cprops, PROP_ALIAS, &val);
	if (val && (strcasecmp(val, "none") == 0)) {
		(void) nvlist_remove_all(cprops, PROP_ALIAS);
	}

	ret = it_validate_configprops(cprops, errs);
	if (ret != 0) {
		if (cprops) {
			nvlist_free(cprops);
		}
		return (ret);
	}

	/*
	 * Update iSNS server list, if exists in provided property list.
	 */
	ret = nvlist_lookup_string_array(proplist, PROP_ISNS_SERVER,
	    &arr, &count);

	if (ret == 0) {
		/* special case:  if "none", remove all defined */
		if (strcasecmp(arr[0], "none") != 0) {
			ret = it_array_to_portallist(arr, count,
			    ISNS_DEFAULT_SERVER_PORT, &newisnslist, &newcount);
		} else {
			newisnslist = NULL;
			newcount = 0;
			(void) nvlist_remove_all(cprops, PROP_ISNS_SERVER);
		}

		if (ret == 0) {
			isns = cfg->config_isns_svr_list;
			while (isns) {
				pnext = isns->portal_next;
				free(isns);
				isns = pnext;
			}

			cfg->config_isns_svr_list = newisnslist;
			cfg->config_isns_svr_count = newcount;

			/*
			 * Replace the array in the nvlist to ensure
			 * duplicates are properly removed & port numbers
			 * are added.
			 */
			if (newcount > 0) {
				int	i = 0;
				char	**newarray;

				newarray = malloc(sizeof (char *) * newcount);
				if (newarray == NULL) {
					ret = ENOMEM;
				} else {
					for (isns = newisnslist; isns != NULL;
					    isns = isns->portal_next) {
						(void) sockaddr_to_str(
						    &(isns->portal_addr),
						    &(newarray[i++]));
					}
					(void) nvlist_add_string_array(cprops,
					    PROP_ISNS_SERVER, newarray,
					    newcount);

					for (i = 0; i < newcount; i++) {
						if (newarray[i]) {
							free(newarray[i]);
						}
					}
					free(newarray);
				}
			}
		}
	} else if (ret == ENOENT) {
		/* not an error */
		ret = 0;
	}

	if (ret == 0) {
		/* replace the global properties list */
		nvlist_free(cfg->config_global_properties);
		cfg->config_global_properties = cprops;
	} else {
		if (cprops) {
			nvlist_free(cprops);
		}
	}

	if (ret == 0)
		free_empty_errlist(errlist);

	return (ret);
}

/*
 * Function:  it_config_free()
 *
 * Free any resources associated with the it_config_t structure.
 *
 * Parameters:
 *    cfg	A C representation of the current iSCSI configuration
 */
void
it_config_free(it_config_t *cfg)
{
	it_config_free_cmn(cfg);
}

/*
 * Function:  it_tgt_create()
 *
 * Allocate and create an it_tgt_t structure representing a new iSCSI
 * target node.  If tgt_name is NULL, then a unique target node name will
 * be generated automatically.  Otherwise, the value of tgt_name will be
 * used as the target node name.  The new it_tgt_t structure is added to
 * the target list (cfg_tgt_list) in the configuration structure, and the
 * new target will not be instantiated until the modified configuration
 * is committed by calling it_config_commit().
 *
 * Parameters:
 *    cfg		The current iSCSI configuration obtained from
 *			it_config_load()
 *    tgt		Pointer to an iSCSI target structure
 *    tgt_name		The target node name for the target to be created.
 *			The name must be in either IQN or EUI format.  If
 *			this value is NULL, a node name will be generated
 *			automatically in IQN format.
 *
 * Return Values:
 *    0			Success
 *    ENOMEM		Could not allocated resources
 *    EINVAL		Invalid parameter
 *    EFAULT		Invalid iSCSI name specified
 *    E2BIG		Too many already exist
 */
int
it_tgt_create(it_config_t *cfg, it_tgt_t **tgt, char *tgt_name)
{
	int		ret = 0;
	it_tgt_t	*ptr;
	it_tgt_t	*cfgtgt;
	char		*namep;
	char		buf[ISCSI_NAME_LEN_MAX + 1];

	if (!cfg || !tgt) {
		return (EINVAL);
	}

	if (!tgt_name) {
		/* generate a name */
		ret = it_iqn_generate(buf, sizeof (buf), NULL);
		if (ret != 0) {
			return (ret);
		}
	} else {
		/* validate the passed-in name */
		if (!validate_iscsi_name(tgt_name)) {
			return (EFAULT);
		}
		(void) strlcpy(buf, tgt_name, sizeof (buf));
		canonical_iscsi_name(buf);
	}
	namep = buf;

	/* make sure this name isn't already on the list */
	cfgtgt = cfg->config_tgt_list;
	while (cfgtgt != NULL) {
		if (strcasecmp(namep, cfgtgt->tgt_name) == 0) {
			return (EEXIST);
		}
		cfgtgt = cfgtgt->tgt_next;
	}

	/* Too many targets? */
	if (cfg->config_tgt_count >= MAX_TARGETS) {
		return (E2BIG);
	}

	ptr = calloc(1, sizeof (it_tgt_t));
	if (ptr == NULL) {
		return (ENOMEM);
	}

	(void) strlcpy(ptr->tgt_name, namep, sizeof (ptr->tgt_name));
	ptr->tgt_generation = 1;
	ptr->tgt_next = cfg->config_tgt_list;
	cfg->config_tgt_list = ptr;
	cfg->config_tgt_count++;

	*tgt = ptr;

	return (0);
}

/*
 * Function:  it_tgt_setprop()
 *
 * Validate the provided property list and set the properties for
 * the specified target.  If errlist is not NULL, returns detailed
 * errors for each property that failed.  The format for errorlist
 * is key = property, value = error string.
 *
 * Parameters:
 *
 *    cfg		The current iSCSI configuration obtained from
 *			it_config_load()
 *    tgt		Pointer to an iSCSI target structure
 *    proplist		nvlist_t containing properties for this target.
 *    errlist		(optional)  nvlist_t of errors encountered when
 *			validating the properties.
 *
 * Return Values:
 *    0			Success
 *    EINVAL		Invalid property
 *
 */
int
it_tgt_setprop(it_config_t *cfg, it_tgt_t *tgt, nvlist_t *proplist,
    nvlist_t **errlist)
{
	int		ret;
	nvlist_t	*errs = NULL;
	nvlist_t	*tprops = NULL;
	char		*val = NULL;

	if (!cfg || !tgt || !proplist) {
		return (EINVAL);
	}

	/* verify the target name in case the target node is renamed */
	if (!validate_iscsi_name(tgt->tgt_name)) {
		return (EINVAL);
	}
	canonical_iscsi_name(tgt->tgt_name);

	if (errlist) {
		(void) nvlist_alloc(&errs, 0, 0);
		*errlist = errs;
	}

	/*
	 * copy the existing properties, merge, then validate
	 * the merged properties before committing them.
	 */
	if (tgt->tgt_properties) {
		ret = nvlist_dup(tgt->tgt_properties, &tprops, 0);
	} else {
		ret = nvlist_alloc(&tprops, NV_UNIQUE_NAME, 0);
	}

	if (ret != 0) {
		return (ret);
	}

	ret = nvlist_merge(tprops, proplist, 0);
	if (ret != 0) {
		nvlist_free(tprops);
		return (ret);
	}

	/* unset chap username or alias if requested */
	val = NULL;
	(void) nvlist_lookup_string(proplist, PROP_TARGET_CHAP_USER, &val);
	if (val && (strcasecmp(val, "none") == 0)) {
		(void) nvlist_remove_all(tprops, PROP_TARGET_CHAP_USER);
	}

	val = NULL;
	(void) nvlist_lookup_string(proplist, PROP_ALIAS, &val);
	if (val && (strcasecmp(val, "none") == 0)) {
		(void) nvlist_remove_all(tprops, PROP_ALIAS);
	}

	/* base64 encode the CHAP secret, if it's changed */
	val = NULL;
	(void) nvlist_lookup_string(proplist, PROP_TARGET_CHAP_SECRET, &val);
	if (val) {
		char		bsecret[MAX_BASE64_LEN];

		ret = it_val_pass(PROP_TARGET_CHAP_SECRET, val, errs);

		if (ret == 0) {
			(void) memset(bsecret, 0, MAX_BASE64_LEN);

			ret = iscsi_binary_to_base64_str((uint8_t *)val,
			    strlen(val), bsecret, MAX_BASE64_LEN);

			if (ret == 0) {
				/* replace the value in the nvlist */
				ret = nvlist_add_string(tprops,
				    PROP_TARGET_CHAP_SECRET, bsecret);
			}
		}
	}

	if (ret == 0) {
		ret = it_validate_tgtprops(tprops, errs);
	}

	if (ret != 0) {
		if (tprops) {
			nvlist_free(tprops);
		}
		return (ret);
	}

	if (tgt->tgt_properties) {
		nvlist_free(tgt->tgt_properties);
	}
	tgt->tgt_properties = tprops;

	free_empty_errlist(errlist);

	return (0);
}


/*
 * Function:  it_tgt_delete()
 *
 * Delete target represented by 'tgt', where 'tgt' is an existing
 * it_tgt_structure within the configuration 'cfg'.  The target removal
 * will not take effect until the modified configuration is committed
 * by calling it_config_commit().
 *
 * Parameters:
 *    cfg		The current iSCSI configuration obtained from
 *			it_config_load()
 *    tgt		Pointer to an iSCSI target structure
 *
 *    force		Set the target to offline before removing it from
 *			the config.  If not specified, the operation will
 *			fail if the target is determined to be online.
 * Return Values:
 *    0			Success
 *    EBUSY		Target is online
 */
int
it_tgt_delete(it_config_t *cfg, it_tgt_t *tgt, boolean_t force)
{
	int			ret;
	it_tgt_t		*ptgt;
	it_tgt_t		*prev = NULL;
	stmfDevid		devid;
	stmfTargetProperties	props;

	if (!cfg || !tgt) {
		return (0);
	}

	ptgt = cfg->config_tgt_list;
	while (ptgt != NULL) {
		if (strcasecmp(tgt->tgt_name, ptgt->tgt_name) == 0) {
			break;
		}
		prev = ptgt;
		ptgt = ptgt->tgt_next;
	}

	if (!ptgt) {
		return (0);
	}

	/*
	 * check to see if this target is offline.  If it is not,
	 * and the 'force' flag is TRUE, tell STMF to offline it
	 * before removing from the configuration.
	 */
	ret = stmfDevidFromIscsiName(ptgt->tgt_name, &devid);
	if (ret != STMF_STATUS_SUCCESS) {
		/* can't happen? */
		return (EINVAL);
	}

	ret = stmfGetTargetProperties(&devid, &props);
	if (ret == STMF_STATUS_SUCCESS) {
		/*
		 * only other return is STMF_ERROR_NOT_FOUND, which
		 * means we don't have to offline it.
		 */
		if (props.status == STMF_TARGET_PORT_ONLINE) {
			if (!force) {
				return (EBUSY);
			}
			ret = stmfOfflineTarget(&devid);
			if (ret != 0) {
				return (EBUSY);
			}
		}
	}

	if (prev) {
		prev->tgt_next = ptgt->tgt_next;
	} else {
		/* first one on the list */
		cfg->config_tgt_list = ptgt->tgt_next;
	}

	ptgt->tgt_next = NULL; /* Only free this target */

	cfg->config_tgt_count--;
	it_tgt_free(ptgt);

	return (0);
}

/*
 * Function:  it_tgt_free()
 *
 * Frees an it_tgt_t structure.  If tgt_next is not NULL, frees
 * all structures in the list.
 */
void
it_tgt_free(it_tgt_t *tgt)
{
	it_tgt_free_cmn(tgt);
}

/*
 * Function:  it_tpgt_create()
 *
 * Allocate and create an it_tpgt_t structure representing a new iSCSI
 * target portal group tag.  The new it_tpgt_t structure is added to the
 * target tpgt list (tgt_tpgt_list) in the it_tgt_t structure.  The new
 * target portal group tag will not be instantiated until the modified
 * configuration is committed by calling it_config_commit().
 *
 * Parameters:
 *    cfg		The current iSCSI configuration obtained from
 *			it_config_load()
 *    tgt		Pointer to the iSCSI target structure associated
 *			with the target portal group tag
 *    tpgt		Pointer to a target portal group tag structure
 *    tpg_name		The name of the TPG to be associated with this TPGT
 *    tpgt_tag		16-bit numerical identifier for this TPGT.  If
 *			tpgt_tag is '0', this function will choose the
 *			tag number.  If tpgt_tag is >0, and the requested
 *			tag is determined to be in use, another value
 *			will be chosen.
 *
 * Return Values:
 *    0			Success
 *    ENOMEM		Could not allocate resources
 *    EINVAL		Invalid parameter
 *    EEXIST		Specified tag name is already used.
 *    E2BIG		No available tag numbers
 */
int
it_tpgt_create(it_config_t *cfg, it_tgt_t *tgt, it_tpgt_t **tpgt,
    char *tpg_name, uint16_t tpgt_tag)
{
	it_tpgt_t	*ptr = NULL;
	it_tpgt_t	*cfgt;
	char		tagid_used[MAXTAG + 1];
	uint16_t	tagid = ISCSIT_DEFAULT_TPGT;

	if (!cfg || !tgt || !tpgt || !tpg_name) {
		return (EINVAL);
	}

	(void) memset(&(tagid_used[0]), 0, sizeof (tagid_used));

	/*
	 * Make sure this name and/or tag isn't already on the list
	 * At the same time, capture all tag ids in use for this target
	 *
	 * About tag numbering -- since tag numbers are used by
	 * the iSCSI protocol, we should be careful about reusing
	 * them too quickly.  Start with a value greater than the
	 * highest one currently defined.  If current == MAXTAG,
	 * just find an unused tag.
	 */
	cfgt = tgt->tgt_tpgt_list;
	while (cfgt != NULL) {
		tagid_used[cfgt->tpgt_tag] = 1;

		if (strcmp(tpg_name, cfgt->tpgt_tpg_name) == 0) {
			return (EEXIST);
		}

		if (cfgt->tpgt_tag > tagid) {
			tagid = cfgt->tpgt_tag;
		}

		cfgt = cfgt->tpgt_next;
	}

	if ((tpgt_tag > ISCSIT_DEFAULT_TPGT) && (tpgt_tag < MAXTAG) &&
	    (tagid_used[tpgt_tag] == 0)) {
		/* ok to use requested */
		tagid = tpgt_tag;
	} else if (tagid == MAXTAG) {
		/*
		 * The highest value is used, find an available id.
		 */
		tagid = ISCSIT_DEFAULT_TPGT + 1;
		for (; tagid < MAXTAG; tagid++) {
			if (tagid_used[tagid] == 0) {
				break;
			}
		}
		if (tagid >= MAXTAG) {
			return (E2BIG);
		}
	} else {
		/* next available ID */
		tagid++;
	}

	ptr = calloc(1, sizeof (it_tpgt_t));
	if (!ptr) {
		return (ENOMEM);
	}

	(void) strlcpy(ptr->tpgt_tpg_name, tpg_name,
	    sizeof (ptr->tpgt_tpg_name));
	ptr->tpgt_generation = 1;
	ptr->tpgt_tag = tagid;

	ptr->tpgt_next = tgt->tgt_tpgt_list;
	tgt->tgt_tpgt_list = ptr;
	tgt->tgt_tpgt_count++;
	tgt->tgt_generation++;

	*tpgt = ptr;

	return (0);
}

/*
 * Function:  it_tpgt_delete()
 *
 * Delete the target portal group tag represented by 'tpgt', where
 * 'tpgt' is an existing is_tpgt_t structure within the target 'tgt'.
 * The target portal group tag removal will not take effect until the
 * modified configuration is committed by calling it_config_commit().
 *
 * Parameters:
 *    cfg		The current iSCSI configuration obtained from
 *			it_config_load()
 *    tgt		Pointer to the iSCSI target structure associated
 *			with the target portal group tag
 *    tpgt		Pointer to a target portal group tag structure
 */
void
it_tpgt_delete(it_config_t *cfg, it_tgt_t *tgt, it_tpgt_t *tpgt)
{
	it_tpgt_t	*ptr;
	it_tpgt_t	*prev = NULL;

	if (!cfg || !tgt || !tpgt) {
		return;
	}

	ptr = tgt->tgt_tpgt_list;
	while (ptr) {
		if (ptr->tpgt_tag == tpgt->tpgt_tag) {
			break;
		}
		prev = ptr;
		ptr = ptr->tpgt_next;
	}

	if (!ptr) {
		return;
	}

	if (prev) {
		prev->tpgt_next = ptr->tpgt_next;
	} else {
		tgt->tgt_tpgt_list = ptr->tpgt_next;
	}
	ptr->tpgt_next = NULL;

	tgt->tgt_tpgt_count--;
	tgt->tgt_generation++;

	it_tpgt_free(ptr);
}

/*
 * Function:  it_tpgt_free()
 *
 * Deallocates resources of an it_tpgt_t structure.  If tpgt->next
 * is not NULL, frees all members of the list.
 */
void
it_tpgt_free(it_tpgt_t *tpgt)
{
	it_tpgt_free_cmn(tpgt);
}

/*
 * Function:  it_tpg_create()
 *
 * Allocate and create an it_tpg_t structure representing a new iSCSI
 * target portal group.  The new it_tpg_t structure is added to the global
 * tpg list (cfg_tgt_list) in the it_config_t structure.  The new target
 * portal group will not be instantiated until the modified configuration
 * is committed by calling it_config_commit().
 *
 * Parameters:
 *    cfg		The current iSCSI configuration obtained from
 *			it_config_load()
 *    tpg		Pointer to the it_tpg_t structure representing
 *			the target portal group
 *    tpg_name		Identifier for the target portal group
 *    portal_ip_port	A string containing an appropriatedly formatted
 *			IP address:port.  Both IPv4 and IPv6 addresses are
 *			permitted.  This value becomes the first portal in
 *			the TPG -- applications can add additional values
 *			using it_portal_create() before committing the TPG.
 * Return Values:
 *    0			Success
 *    ENOMEM		Cannot allocate resources
 *    EINVAL		Invalid parameter
 *    EEXIST		Requested portal in use by another target portal
 *			group
 */
int
it_tpg_create(it_config_t *cfg, it_tpg_t **tpg, char *tpg_name,
    char *portal_ip_port)
{
	int		ret;
	it_tpg_t	*ptr;
	it_portal_t	*portal = NULL;

	if (!cfg || !tpg || !tpg_name || !portal_ip_port) {
		return (EINVAL);
	}

	*tpg = NULL;

	ptr = cfg->config_tpg_list;
	while (ptr) {
		if (strcmp(tpg_name, ptr->tpg_name) == 0) {
			break;
		}
		ptr = ptr->tpg_next;
	}

	if (ptr) {
		return (EEXIST);
	}

	ptr = calloc(1, sizeof (it_tpg_t));
	if (!ptr) {
		return (ENOMEM);
	}

	ptr->tpg_generation = 1;
	(void) strlcpy(ptr->tpg_name, tpg_name, sizeof (ptr->tpg_name));

	/* create the portal */
	ret = it_portal_create(cfg, ptr, &portal, portal_ip_port);
	if (ret != 0) {
		free(ptr);
		return (ret);
	}

	ptr->tpg_next = cfg->config_tpg_list;
	cfg->config_tpg_list = ptr;
	cfg->config_tpg_count++;

	*tpg = ptr;

	return (0);
}

/*
 * Function:  it_tpg_delete()
 *
 * Delete target portal group represented by 'tpg', where 'tpg' is an
 * existing it_tpg_t structure within the global configuration 'cfg'.
 * The target portal group removal will not take effect until the
 * modified configuration is committed by calling it_config_commit().
 *
 * Parameters:
 *    cfg		The current iSCSI configuration obtained from
 *			it_config_load()
 *    tpg		Pointer to the it_tpg_t structure representing
 *			the target portal group
 *    force		Remove this target portal group even if it's
 *			associated with one or more targets.
 *
 * Return Values:
 *    0			Success
 *    EINVAL		Invalid parameter
 *    EBUSY		Portal group associated with one or more targets.
 */
int
it_tpg_delete(it_config_t *cfg, it_tpg_t *tpg, boolean_t force)
{
	it_tpg_t	*ptr;
	it_tpg_t	*prev = NULL;
	it_tgt_t	*tgt;
	it_tpgt_t	*tpgt;
	it_tpgt_t	*ntpgt;

	if (!cfg || !tpg) {
		return (EINVAL);
	}

	ptr = cfg->config_tpg_list;
	while (ptr) {
		if (strcmp(ptr->tpg_name, tpg->tpg_name) == 0) {
			break;
		}
		prev = ptr;
		ptr = ptr->tpg_next;
	}

	if (!ptr) {
		return (0);
	}

	/*
	 * See if any targets are using this portal group.
	 * If there are, and the force flag is not set, fail.
	 */
	tgt = cfg->config_tgt_list;
	while (tgt) {
		tpgt = tgt->tgt_tpgt_list;
		while (tpgt) {
			ntpgt = tpgt->tpgt_next;

			if (strcmp(tpgt->tpgt_tpg_name, tpg->tpg_name)
			    == 0) {
				if (!force) {
					return (EBUSY);
				}
				it_tpgt_delete(cfg, tgt, tpgt);
			}

			tpgt = ntpgt;
		}
		tgt = tgt->tgt_next;
	}

	/* Now that it's not in use anywhere, remove the TPG */
	if (prev) {
		prev->tpg_next = ptr->tpg_next;
	} else {
		cfg->config_tpg_list = ptr->tpg_next;
	}
	ptr->tpg_next = NULL;

	cfg->config_tpg_count--;

	it_tpg_free(ptr);

	return (0);
}

/*
 * Function:  it_tpg_free()
 *
 * Deallocates resources associated with an it_tpg_t structure.
 * If tpg->next is not NULL, frees all members of the list.
 */
void
it_tpg_free(it_tpg_t *tpg)
{
	it_tpg_free_cmn(tpg);
}

/*
 * Function:  it_portal_create()
 *
 * Add an it_portal_t structure presenting a new portal to the specified
 * target portal group.  The change to the target portal group will not take
 * effect until the modified configuration is committed by calling
 * it_config_commit().
 *
 * Parameters:
 *    cfg		The current iSCSI configration obtained from
 *			it_config_load()
 *    tpg		Pointer to the it_tpg_t structure representing the
 *			target portal group
 *    portal		Pointer to the it_portal_t structure representing
 *			the portal
 *    portal_ip_port	A string containing an appropriately formatted
 *			IP address or IP address:port in either IPv4 or
 *			IPv6 format.
 * Return Values:
 *    0			Success
 *    ENOMEM		Could not allocate resources
 *    EINVAL		Invalid parameter
 *    EEXIST		Portal already configured for another portal group
 */
int
it_portal_create(it_config_t *cfg, it_tpg_t *tpg, it_portal_t **portal,
    char *portal_ip_port)
{
	struct sockaddr_storage		sa;
	it_portal_t			*ptr;
	it_tpg_t			*ctpg = NULL;

	if (!cfg || !tpg || !portal || !portal_ip_port) {
		return (EINVAL);
	}

	if ((it_common_convert_sa(portal_ip_port, &sa, ISCSI_LISTEN_PORT))
	    == NULL) {
		return (EINVAL);
	}

	/* Check that this portal doesn't appear in any other tag */
	ctpg = cfg->config_tpg_list;
	while (ctpg) {
		ptr = ctpg->tpg_portal_list;
		for (; ptr != NULL; ptr = ptr->portal_next) {
			if (it_sa_compare(&(ptr->portal_addr), &sa) != 0) {
				continue;
			}

			/*
			 * Existing in the same group is not an error,
			 * but don't add it again.
			 */
			if (strcmp(ctpg->tpg_name, tpg->tpg_name) == 0) {
				return (0);
			} else {
				/* Not allowed */
				return (EEXIST);
			}
		}
		ctpg = ctpg->tpg_next;
	}

	ptr = calloc(1, sizeof (it_portal_t));
	if (!ptr) {
		return (ENOMEM);
	}

	(void) memcpy(&(ptr->portal_addr), &sa,
	    sizeof (struct sockaddr_storage));
	ptr->portal_next = tpg->tpg_portal_list;
	tpg->tpg_portal_list = ptr;
	tpg->tpg_portal_count++;
	tpg->tpg_generation++;

	return (0);
}

/*
 * Function:  it_portal_delete()
 *
 * Remove the specified portal from the specified target portal group.
 * The portal removal will not take effect until the modified configuration
 * is committed by calling it_config_commit().
 *
 * Parameters:
 *    cfg		The current iSCSI configration obtained from
 *			it_config_load()
 *    tpg		Pointer to the it_tpg_t structure representing the
 *			target portal group
 *    portal		Pointer to the it_portal_t structure representing
 *			the portal
 */
void
it_portal_delete(it_config_t *cfg, it_tpg_t *tpg, it_portal_t *portal)
{
	it_portal_t	*ptr;
	it_portal_t	*prev = NULL;

	if (!cfg || !tpg || !portal) {
		return;
	}

	ptr = tpg->tpg_portal_list;
	while (ptr) {
		if (memcmp(&(ptr->portal_addr), &(portal->portal_addr),
		    sizeof (ptr->portal_addr)) == 0) {
			break;
		}
		prev = ptr;
		ptr = ptr->portal_next;
	}

	if (!ptr) {
		return;
	}

	if (prev) {
		prev->portal_next = ptr->portal_next;
	} else {
		tpg->tpg_portal_list = ptr->portal_next;
	}
	tpg->tpg_portal_count--;
	tpg->tpg_generation++;

	free(ptr);
}

/*
 * Function:  it_ini_create()
 *
 * Add an initiator context to the global configuration. The new
 * initiator context will not be instantiated until the modified
 * configuration is committed by calling it_config_commit().
 *
 * Parameters:
 *    cfg		The current iSCSI configration obtained from
 *			it_config_load()
 *    ini		Pointer to the it_ini_t structure representing
 *			the initiator context.
 *    ini_node_name	The iSCSI node name of the remote initiator.
 *
 * Return Values:
 *    0			Success
 *    ENOMEM		Could not allocate resources
 *    EINVAL		Invalid parameter.
 *    EFAULT		Invalid initiator name
 */
int
it_ini_create(it_config_t *cfg, it_ini_t **ini, char *ini_node_name)
{
	it_ini_t	*ptr;

	if (!cfg || !ini || !ini_node_name) {
		return (EINVAL);
	}

	/*
	 * Ensure this is a valid ini name
	 */
	if (!validate_iscsi_name(ini_node_name)) {
		return (EFAULT);
	}

	ptr = cfg->config_ini_list;
	while (ptr) {
		if (strcasecmp(ptr->ini_name, ini_node_name) == 0) {
			break;
		}
		ptr = ptr->ini_next;
	}

	if (ptr) {
		return (EEXIST);
	}

	ptr = calloc(1, sizeof (it_ini_t));
	if (!ptr) {
		return (ENOMEM);
	}

	(void) strlcpy(ptr->ini_name, ini_node_name, sizeof (ptr->ini_name));
	ptr->ini_generation = 1;
	/* nvlist for props? */

	ptr->ini_next = cfg->config_ini_list;
	cfg->config_ini_list = ptr;
	cfg->config_ini_count++;

	*ini = ptr;

	return (0);
}

/*
 * Function:  it_ini_setprop()
 *
 * Validate the provided property list and set the initiator properties.
 * If errlist is not NULL, returns detailed errors for each property
 * that failed.  The format for errorlist is key = property,
 * value = error string.
 *
 * Parameters:
 *
 *    ini		The initiator being updated.
 *    proplist		nvlist_t containing properties for this target.
 *    errlist		(optional)  nvlist_t of errors encountered when
 *			validating the properties.
 *
 * Return Values:
 *    0			Success
 *    EINVAL		Invalid property
 *
 */
int
it_ini_setprop(it_ini_t *ini, nvlist_t *proplist, nvlist_t **errlist)
{
	int		ret;
	nvlist_t	*errs = NULL;
	nvlist_t	*iprops = NULL;
	char		*val = NULL;

	if (!ini || !proplist) {
		return (EINVAL);
	}

	if (errlist) {
		(void) nvlist_alloc(&errs, 0, 0);
		*errlist = errs;
	}

	/*
	 * copy the existing properties, merge, then validate
	 * the merged properties before committing them.
	 */
	if (ini->ini_properties) {
		ret = nvlist_dup(ini->ini_properties, &iprops, 0);
	} else {
		ret = nvlist_alloc(&iprops, NV_UNIQUE_NAME, 0);
	}

	if (ret != 0) {
		return (ret);
	}

	ret = nvlist_merge(iprops, proplist, 0);
	if (ret != 0) {
		nvlist_free(iprops);
		return (ret);
	}

	/* unset chap username if requested */
	if ((nvlist_lookup_string(proplist, PROP_CHAP_USER, &val)) == 0) {
		if (strcasecmp(val, "none") == 0) {
			(void) nvlist_remove_all(iprops, PROP_CHAP_USER);
		}
	}

	/* base64 encode the CHAP secret, if it's changed */
	if ((nvlist_lookup_string(proplist, PROP_CHAP_SECRET, &val)) == 0) {
		char		bsecret[MAX_BASE64_LEN];

		ret = it_val_pass(PROP_CHAP_SECRET, val, errs);
		if (ret == 0) {
			(void) memset(bsecret, 0, MAX_BASE64_LEN);

			ret = iscsi_binary_to_base64_str((uint8_t *)val,
			    strlen(val), bsecret, MAX_BASE64_LEN);

			if (ret == 0) {
				/* replace the value in the nvlist */
				ret = nvlist_add_string(iprops,
				    PROP_CHAP_SECRET, bsecret);
			}
		}
	}

	if (ret == 0) {
		ret = it_validate_iniprops(iprops, errs);
	}

	if (ret != 0) {
		if (iprops) {
			nvlist_free(iprops);
		}
		return (ret);
	}

	if (ini->ini_properties) {
		nvlist_free(ini->ini_properties);
	}
	ini->ini_properties = iprops;

	free_empty_errlist(errlist);

	return (0);
}

/*
 * Function:  it_ini_delete()
 *
 * Remove the specified initiator context from the global configuration.
 * The removal will not take effect until the modified configuration is
 * committed by calling it_config_commit().
 *
 * Parameters:
 *    cfg		The current iSCSI configration obtained from
 *			it_config_load()
 *    ini		Pointer to the it_ini_t structure representing
 *			the initiator context.
 */
void
it_ini_delete(it_config_t *cfg, it_ini_t *ini)
{
	it_ini_t	*ptr;
	it_ini_t	*prev = NULL;

	if (!cfg || !ini) {
		return;
	}

	ptr = cfg->config_ini_list;
	while (ptr) {
		if (strcasecmp(ptr->ini_name, ini->ini_name) == 0) {
			break;
		}
		prev = ptr;
		ptr = ptr->ini_next;
	}

	if (!ptr) {
		return;
	}

	if (prev) {
		prev->ini_next = ptr->ini_next;
	} else {
		cfg->config_ini_list = ptr->ini_next;
	}

	ptr->ini_next = NULL; /* Only free this initiator */

	cfg->config_ini_count--;

	it_ini_free(ptr);
}

/*
 * Function:  it_ini_free()
 *
 * Deallocates resources of an it_ini_t structure. If ini->next is
 * not NULL, frees all members of the list.
 */
void
it_ini_free(it_ini_t *ini)
{
	it_ini_free_cmn(ini);
}

/*
 * Goes through the target property list and validates
 * each entry.  If errs is non-NULL, will return explicit errors
 * for each property that fails validation.
 */
static int
it_validate_tgtprops(nvlist_t *nvl, nvlist_t *errs)
{
	int		errcnt = 0;
	nvpair_t	*nvp = NULL;
	data_type_t	nvtype;
	char		*name;
	char		*val;
	char		*auth = NULL;

	if (!nvl) {
		return (0);
	}

	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {
		name = nvpair_name(nvp);
		nvtype = nvpair_type(nvp);

		if (!name) {
			continue;
		}

		val = NULL;
		if (strcmp(name, PROP_TARGET_CHAP_USER) == 0) {
			if (nvtype != DATA_TYPE_STRING) {
				PROPERR(errs, name,
				    gettext("must be a string value"));
				errcnt++;
				continue;
			}
		} else if (strcmp(name, PROP_TARGET_CHAP_SECRET) == 0) {
			/*
			 * must be between 12 and 255 chars in cleartext.
			 * will be base64 encoded when it's set.
			 */
			if (nvtype == DATA_TYPE_STRING) {
				(void) nvpair_value_string(nvp, &val);
			}

			if (!val) {
				PROPERR(errs, name,
				    gettext("must be a string value"));
				errcnt++;
				continue;
			}
		} else if (strcmp(name, PROP_ALIAS) == 0) {
			if (nvtype != DATA_TYPE_STRING) {
				PROPERR(errs, name,
				    gettext("must be a string value"));
				errcnt++;
				continue;
			}
		} else if (strcmp(name, PROP_AUTH) == 0) {
			if (nvtype == DATA_TYPE_STRING) {
				val = NULL;
				(void) nvpair_value_string(nvp, &val);
			}

			if (!val) {
				PROPERR(errs, name,
				    gettext("must be a string value"));
				errcnt++;
				continue;
			}
			if ((strcmp(val, PA_AUTH_NONE) != 0) &&
			    (strcmp(val, PA_AUTH_CHAP) != 0) &&
			    (strcmp(val, PA_AUTH_RADIUS) != 0) &&
			    (strcmp(val, "default") != 0)) {
				PROPERR(errs, val, gettext(
				    "must be none, chap, radius or default"));
				errcnt++;
			}
			auth = val;
			continue;
		} else if (strcmp(name, PROP_OLD_TARGET_NAME) == 0) {
			continue;
		} else {
			/* unrecognized property */
			PROPERR(errs, name, gettext("unrecognized property"));
			errcnt++;
		}
	}

	if (errcnt) {
		return (EINVAL);
	}

	/* if auth is being set to default, remove from this nvlist */
	if (auth && (strcmp(auth, "default") == 0)) {
		(void) nvlist_remove_all(nvl, PROP_AUTH);
	}

	return (0);
}

/*
 * Goes through the config property list and validates
 * each entry.  If errs is non-NULL, will return explicit errors
 * for each property that fails validation.
 */
static int
it_validate_configprops(nvlist_t *nvl, nvlist_t *errs)
{
	int				errcnt = 0;
	nvpair_t			*nvp = NULL;
	data_type_t			nvtype;
	char				*name;
	char				*val;
	struct sockaddr_storage		sa;
	boolean_t			update_rad_server = B_FALSE;
	char				*rad_server;
	char				*auth = NULL;

	if (!nvl) {
		return (0);
	}

	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {
		name = nvpair_name(nvp);
		nvtype = nvpair_type(nvp);

		if (!name) {
			continue;
		}

		val = NULL;

		/* prefetch string value as we mostly need it */
		if (nvtype == DATA_TYPE_STRING) {
			(void) nvpair_value_string(nvp, &val);
		}

		if (strcmp(name, PROP_ALIAS) == 0) {
			if (!val) {
				PROPERR(errs, name,
				    gettext("must be a string value"));
				errcnt++;
			}
		} else if (strcmp(name, PROP_AUTH) == 0) {
			if (!val) {
				PROPERR(errs, name,
				    gettext("must be a string value"));
				errcnt++;
				continue;
			}

			if ((strcmp(val, PA_AUTH_NONE) != 0) &&
			    (strcmp(val, PA_AUTH_CHAP) != 0) &&
			    (strcmp(val, PA_AUTH_RADIUS) != 0)) {
				PROPERR(errs, PROP_AUTH,
				    gettext("must be none, chap or radius"));
				errcnt++;
			}

			auth = val;

		} else if (strcmp(name, PROP_ISNS_ENABLED) == 0) {
			if (nvtype != DATA_TYPE_BOOLEAN_VALUE) {
				PROPERR(errs, name,
				    gettext("must be a boolean value"));
				errcnt++;
			}
		} else if (strcmp(name, PROP_ISNS_SERVER) == 0) {
			char		**arr = NULL;
			uint32_t	acount = 0;

			(void) nvlist_lookup_string_array(nvl, name,
			    &arr, &acount);

			while (acount > 0) {
				if (strcasecmp(arr[acount - 1], "none") == 0) {
					break;
				}
				if ((it_common_convert_sa(arr[acount - 1],
				    &sa, 0)) == NULL) {
					PROPERR(errs, arr[acount - 1],
					    gettext("invalid address"));
					errcnt++;
				}
				acount--;
			}

		} else if (strcmp(name, PROP_RADIUS_SECRET) == 0) {
			if (!val) {
				PROPERR(errs, name,
				    gettext("must be a string value"));
				errcnt++;
				continue;
			}
		} else if (strcmp(name, PROP_RADIUS_SERVER) == 0) {
			struct sockaddr_storage		sa;
			if (!val) {
				PROPERR(errs, name,
				    gettext("must be a string value"));
				errcnt++;
				continue;
			}

			if ((it_common_convert_sa(val, &sa,
			    DEFAULT_RADIUS_PORT)) == NULL) {
				PROPERR(errs, name,
				    gettext("invalid address"));
				errcnt++;
			} else {
				/*
				 * rewrite this property to ensure port
				 * number is added.
				 */

				if (sockaddr_to_str(&sa, &rad_server) == 0) {
					update_rad_server = B_TRUE;
				}
			}
		} else {
			/* unrecognized property */
			PROPERR(errs, name, gettext("unrecognized property"));
			errcnt++;
		}
	}

	/*
	 * If we successfully reformatted the radius server to add the port
	 * number then update the nvlist
	 */
	if (update_rad_server) {
		(void) nvlist_add_string(nvl, PROP_RADIUS_SERVER, rad_server);
		free(rad_server);
	}

	/*
	 * if auth = radius, ensure radius server & secret are set.
	 */
	if (auth) {
		if (strcmp(auth, PA_AUTH_RADIUS) == 0) {
			/* need server & secret for radius */
			if (!nvlist_exists(nvl, PROP_RADIUS_SERVER)) {
				PROPERR(errs, PROP_RADIUS_SERVER,
				    gettext("missing required property"));
				errcnt++;
			}
			if (!nvlist_exists(nvl, PROP_RADIUS_SECRET)) {
				PROPERR(errs, PROP_RADIUS_SECRET,
				    gettext("missing required property"));
				errcnt++;
			}
		}
	}

	if (errcnt) {
		return (EINVAL);
	}

	return (0);
}

/*
 * Goes through the ini property list and validates
 * each entry.  If errs is non-NULL, will return explicit errors
 * for each property that fails validation.
 */
static int
it_validate_iniprops(nvlist_t *nvl, nvlist_t *errs)
{
	int				errcnt = 0;
	nvpair_t			*nvp = NULL;
	data_type_t			nvtype;
	char				*name;
	char				*val;

	if (!nvl) {
		return (0);
	}

	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {
		name = nvpair_name(nvp);
		nvtype = nvpair_type(nvp);

		if (!name) {
			continue;
		}

		if (strcmp(name, PROP_CHAP_USER) == 0) {
			if (nvtype != DATA_TYPE_STRING) {
				PROPERR(errs, name,
				    gettext("must be a string value"));
				errcnt++;
				continue;
			}
		} else if (strcmp(name, PROP_CHAP_SECRET) == 0) {
			/*
			 * must be between 12 and 255 chars in cleartext.
			 * will be base64 encoded when it's set.
			 */
			if (nvtype == DATA_TYPE_STRING) {
				val = NULL;
				(void) nvpair_value_string(nvp, &val);
			}

			if (!val) {
				PROPERR(errs, name,
				    gettext("must be a string value"));
				errcnt++;
				continue;
			}
		} else {
			/* unrecognized property */
			PROPERR(errs, name, gettext("unrecognized property"));
			errcnt++;
		}
	}

	if (errcnt) {
		return (EINVAL);
	}

	return (0);
}

static int
it_iqn_generate(char *iqn_buf, int iqn_buf_len, char *opt_iqn_suffix)
{
	int		ret;
	uuid_t		id;
	char		id_str[UUID_PRINTABLE_STRING_LENGTH];

	uuid_generate_random(id);
	uuid_unparse(id, id_str);

	if (opt_iqn_suffix) {
		ret = snprintf(iqn_buf, iqn_buf_len, DEFAULT_IQN
		    "%02d:%s.%s", TARGET_NAME_VERS, id_str, opt_iqn_suffix);
	} else {
		ret = snprintf(iqn_buf, iqn_buf_len, DEFAULT_IQN
		    "%02d:%s", TARGET_NAME_VERS, id_str);
	}

	if (ret > iqn_buf_len) {
		return (1);
	}

	return (0);
}

static int
it_val_pass(char *name, char *val, nvlist_t *e)
{
	size_t		sz;

	if (!name || !val) {
		return (EINVAL);
	}

	/*
	 * must be at least 12 chars and less than 256 chars cleartext.
	 */
	sz = strlen(val);

	/*
	 * Since we will be automatically encoding secrets we don't really
	 * need the prefix anymore.
	 */
	if (sz < 12) {
		PROPERR(e, name, gettext("secret too short"));
	} else if (sz > 255) {
		PROPERR(e, name, gettext("secret too long"));
	} else {
		/* all is well */
		return (0);
	}

	return (1);
}

/*
 * Function:  validate_iscsi_name()
 *
 * Ensures the passed-in string is a valid IQN or EUI iSCSI name
 *
 */
boolean_t
validate_iscsi_name(char *in_name)
{
	size_t		in_len;
	int		i;
	char		month[3];

	if (in_name == NULL) {
		return (B_FALSE);
	}

	in_len = strlen(in_name);
	if (in_len < 12) {
		return (B_FALSE);
	}

	if (IS_IQN_NAME(in_name)) {
		/*
		 * IQN names are iqn.yyyy-mm.<xxx>
		 */
		if ((!isdigit(in_name[4])) ||
		    (!isdigit(in_name[5])) ||
		    (!isdigit(in_name[6])) ||
		    (!isdigit(in_name[7])) ||
		    (in_name[8] != '-') ||
		    (!isdigit(in_name[9])) ||
		    (!isdigit(in_name[10])) ||
		    (in_name[11] != '.')) {
			return (B_FALSE);
		}

		(void) strncpy(month, &(in_name[9]), 2);
		month[2] = '\0';

		i = atoi(month);
		if ((i < 0) || (i > 12)) {
			return (B_FALSE);
		}

		/*
		 * RFC 3722: if using only ASCII chars, only the following
		 * chars are allowed: dash, dot, colon, lower case a-z, 0-9.
		 * We allow upper case names, which should be folded
		 * to lower case names later.
		 */
		for (i = 12; i < in_len; i++) {
			char c = in_name[i];

			if ((c != '-') && (c != '.') && (c != ':') &&
			    !isalpha(c) && !isdigit(c)) {
				return (B_FALSE);
			}
		}

		/* Finally, validate the overall length, in wide chars */
		in_len = mbstowcs(NULL, in_name, 0);
		if (in_len > ISCSI_NAME_LEN_MAX) {
			return (B_FALSE);
		}
	} else if (IS_EUI_NAME(in_name)) {
		/*
		 * EUI names are "eui." + 16 hex chars
		 */
		if (in_len != 20) {
			return (B_FALSE);
		}

		for (i = 4; i < in_len; i++) {
			if (!isxdigit(in_name[i])) {
				return (B_FALSE);
			}
		}
	} else {
		return (B_FALSE);
	}

	return (B_TRUE);
}

static boolean_t
is_iscsit_enabled(void)
{
	char		*state;

	state = smf_get_state(ISCSIT_FMRI);
	if (state != NULL) {
		if (strcmp(state, SCF_STATE_STRING_ONLINE) == 0) {
			free(state);
			return (B_TRUE);
		}
		free(state);
	}

	return (B_FALSE);
}

/*
 * Function:  canonical_iscsi_name()
 *
 * Fold the iqn iscsi name to lower-case and the EUI-64 identifier of
 * the eui iscsi name to upper-case.
 * Ensures the passed-in string is a valid IQN or EUI iSCSI name
 */
void
canonical_iscsi_name(char *tgt)
{
	if (IS_IQN_NAME(tgt)) {
		/* lowercase iqn names */
		iqnstr(tgt);
	} else {
		/* uppercase EUI-64 identifier */
		euistr(tgt);
	}
}

/*
 * Fold an iqn name to lower-case.
 */
static void
iqnstr(char *s)
{
	if (s != NULL) {
		while (*s) {
			*s = tolower(*s);
			s++;
		}
	}
}

/*
 * Fold the EUI-64 identifier of a eui name to upper-case.
 */
static void
euistr(char *s)
{
	if (s != NULL) {
		char *l = s + 4;
		while (*l) {
			*l = toupper(*l);
			l++;
		}
	}
}

static void
free_empty_errlist(nvlist_t **errlist)
{
	if (errlist != NULL && *errlist != NULL) {
		assert(fnvlist_num_pairs(*errlist) == 0);
		nvlist_free(*errlist);
		*errlist = NULL;
	}
}
