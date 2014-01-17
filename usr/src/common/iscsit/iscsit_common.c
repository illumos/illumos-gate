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
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/time.h>

#if defined(_KERNEL)
#include <sys/ddi.h>
#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/socket.h>
#include <inet/ip.h>
#include <inet/tcp.h>
#else
#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <sys/iscsit/iscsit_common.h>
#include <sys/iscsi_protocol.h>
#include <sys/iscsit/isns_protocol.h>

void *
iscsit_zalloc(size_t size)
{
#if defined(_KERNEL)
	return (kmem_zalloc(size, KM_SLEEP));
#else
	return (calloc(1, size));
#endif
}

void
iscsit_free(void *buf, size_t size)	/* ARGSUSED */
{
#if defined(_KERNEL)
	kmem_free(buf, size);
#else
	free(buf);
#endif
}

/*
 * default_port should be the port to be used, if not specified
 * as part of the supplied string 'arg'.
 */

#define	NI_MAXHOST	1025
#define	NI_MAXSERV	32


struct sockaddr_storage *
it_common_convert_sa(char *arg, struct sockaddr_storage *buf,
    uint32_t default_port)
{
	/* Why does addrbuf need to be this big!??! XXX */
	char		addrbuf[NI_MAXHOST + NI_MAXSERV + 1];
	char		*addr_str;
	char		*port_str;
#ifndef _KERNEL
	char		*errchr;
#endif
	long		tmp_port = 0;
	sa_family_t	af;

	struct sockaddr_in	*sin;
	struct sockaddr_in6	*sin6;
	struct sockaddr_storage	*sa = buf;

	if (!arg || !buf) {
		return (NULL);
	}

	bzero(buf, sizeof (struct sockaddr_storage));

	/* don't modify the passed-in string */
	(void) strlcpy(addrbuf, arg, sizeof (addrbuf));

	addr_str = addrbuf;

	if (*addr_str == '[') {
		/*
		 * An IPv6 address must be inside square brackets
		 */
		port_str = strchr(addr_str, ']');
		if (!port_str) {
			/* No closing bracket */
			return (NULL);
		}

		/* strip off the square brackets so we can convert */
		addr_str++;
		*port_str = '\0';
		port_str++;

		if (*port_str == ':') {
			/* TCP port to follow */
			port_str++;
		} else if (*port_str == '\0') {
			/* No port specified */
			port_str = NULL;
		} else {
			/* malformed */
			return (NULL);
		}
		af = AF_INET6;
	} else {
		port_str = strchr(addr_str, ':');
		if (port_str) {
			*port_str = '\0';
			port_str++;
		}
		af = AF_INET;
	}

	if (port_str) {
#if defined(_KERNEL)
		if (ddi_strtol(port_str, NULL, 10, &tmp_port) != 0) {
			return (NULL);
		}
#else
		tmp_port = strtol(port_str, &errchr, 10);
#endif
		if (tmp_port < 0 || tmp_port > 65535) {
			return (NULL);
		}
	} else {
		tmp_port = default_port;
	}

	sa->ss_family = af;

	sin = (struct sockaddr_in *)sa;
	if (af == AF_INET) {
		if (inet_pton(af, addr_str,
		    (void *)&(sin->sin_addr.s_addr)) != 1) {
			return (NULL);
		}
		sin->sin_port = htons(tmp_port);
	} else {
		sin6 = (struct sockaddr_in6 *)sa;
		if (inet_pton(af, addr_str,
		    (void *)&(sin6->sin6_addr.s6_addr)) != 1) {
			return (NULL);
		}
		sin6->sin6_port = htons(tmp_port);
	}

	/* successful */
	return (sa);
}


/*  Functions to convert iSCSI target structures to/from nvlists. */

#ifndef _KERNEL
int
it_config_to_nv(it_config_t *cfg, nvlist_t **nvl)
{
	int		ret;
	nvlist_t	*nv;
	nvlist_t	*lnv = NULL;

	if (!nvl) {
		return (EINVAL);
	}

	*nvl = NULL;

	ret = nvlist_alloc(&nv, NV_UNIQUE_NAME_TYPE, 0);
	if (ret != 0) {
		return (ret);
	}

	/* if there's no config, store an empty list */
	if (!cfg) {
		*nvl = nv;
		return (0);
	}

	ret = nvlist_add_uint32(nv, "cfgVersion", cfg->config_version);
	if (ret == 0) {
		ret = it_tgtlist_to_nv(cfg->config_tgt_list, &lnv);
	}

	if ((ret == 0) && (lnv != NULL)) {
		ret = nvlist_add_nvlist(nv, "targetList", lnv);
		nvlist_free(lnv);
		lnv = NULL;
	}

	if (ret == 0) {
		ret = it_tpglist_to_nv(cfg->config_tpg_list, &lnv);
	}

	if ((ret == 0) && (lnv != NULL)) {
		ret = nvlist_add_nvlist(nv, "tpgList", lnv);
		nvlist_free(lnv);
		lnv = NULL;
	}

	if (ret == 0) {
		ret = it_inilist_to_nv(cfg->config_ini_list, &lnv);
	}

	if ((ret == 0) && (lnv != NULL)) {
		ret = nvlist_add_nvlist(nv, "iniList", lnv);
		nvlist_free(lnv);
		lnv = NULL;
	}

	if (ret == 0) {
		ret = nvlist_add_nvlist(nv, "globalProperties",
		    cfg->config_global_properties);
	}

	if (ret == 0) {
		*nvl = nv;
	} else {
		nvlist_free(nv);
	}

	return (ret);
}
#endif /* !_KERNEL */

/*
 * nvlist version of config is 3 list-of-list, + 1 proplist.  arrays
 * are interesting, but lists-of-lists are more useful when doing
 * individual lookups when we later add support for it.  Also, no
 * need to store name in individual struct representation.
 */
int
it_nv_to_config(nvlist_t *nvl, it_config_t **cfg)
{
	int		ret;
	uint32_t	intval;
	nvlist_t	*listval;
	it_config_t	*tmpcfg;

	if (!cfg) {
		return (EINVAL);
	}

	/* initialize output */
	*cfg = NULL;

	tmpcfg = iscsit_zalloc(sizeof (it_config_t));
	if (tmpcfg == NULL) {
		return (ENOMEM);
	}

	if (!nvl) {
		/* nothing to decode, but return the empty cfg struct */
		ret = nvlist_alloc(&tmpcfg->config_global_properties,
		    NV_UNIQUE_NAME, 0);
		if (ret != 0) {
			iscsit_free(tmpcfg, sizeof (it_config_t));
			return (ret);
		}
		*cfg = tmpcfg;
		return (0);
	}

	ret = nvlist_lookup_uint32(nvl, "cfgVersion", &intval);
	if (ret != 0) {
		iscsit_free(tmpcfg, sizeof (it_config_t));
		return (ret);
	}

	tmpcfg->config_version = intval;

	ret = nvlist_lookup_nvlist(nvl, "targetList", &listval);
	if (ret == 0) {
		/* decode list of it_tgt_t */
		ret = it_nv_to_tgtlist(listval, &(tmpcfg->config_tgt_count),
		    &(tmpcfg->config_tgt_list));
	}

	ret = nvlist_lookup_nvlist(nvl, "tpgList", &listval);
	if (ret == 0) {
		/* decode list of it_tpg_t */
		ret = it_nv_to_tpglist(listval, &(tmpcfg->config_tpg_count),
		    &(tmpcfg->config_tpg_list));
	}

	ret = nvlist_lookup_nvlist(nvl, "iniList", &listval);
	if (ret == 0) {
		/* decode list of initiators */
		ret = it_nv_to_inilist(listval, &(tmpcfg->config_ini_count),
		    &(tmpcfg->config_ini_list));
	}

	ret = nvlist_lookup_nvlist(nvl, "globalProperties", &listval);
	if (ret == 0) {
		/*
		 * don't depend on the original nvlist staying in-scope,
		 * duplicate the nvlist
		 */
		ret = nvlist_dup(listval, &(tmpcfg->config_global_properties),
		    0);
	} else if (ret == ENOENT) {
		/*
		 * No global properties defined, make an empty list
		 */
		ret = nvlist_alloc(&tmpcfg->config_global_properties,
		    NV_UNIQUE_NAME, 0);
	}

	if (ret == 0) {
		char		**isnsArray = NULL;
		uint32_t	numisns = 0;

		/*
		 * decode the list of iSNS server information to make
		 * references from the kernel simpler.
		 */
		if (tmpcfg->config_global_properties) {
			ret = nvlist_lookup_string_array(
			    tmpcfg->config_global_properties,
			    PROP_ISNS_SERVER,
			    &isnsArray, &numisns);
			if (ret == 0) {
				ret = it_array_to_portallist(isnsArray,
				    numisns, ISNS_DEFAULT_SERVER_PORT,
				    &tmpcfg->config_isns_svr_list,
				    &tmpcfg->config_isns_svr_count);
			} else if (ret == ENOENT) {
				/* It's OK if we don't have any iSNS servers */
				ret = 0;
			}
		}
	}

	if (ret == 0) {
		*cfg = tmpcfg;
	} else {
		it_config_free_cmn(tmpcfg);
	}

	return (ret);
}

it_tgt_t *
it_tgt_lookup(it_config_t *cfg, char *tgt_name)
{
	it_tgt_t *cfg_tgt = NULL;

	for (cfg_tgt = cfg->config_tgt_list;
	    cfg_tgt != NULL;
	    cfg_tgt = cfg_tgt->tgt_next) {
		if (strncmp(cfg_tgt->tgt_name, tgt_name,
		    MAX_ISCSI_NODENAMELEN) == 0) {
			return (cfg_tgt);
		}
	}

	return (NULL);
}

int
it_nv_to_tgtlist(nvlist_t *nvl, uint32_t *count, it_tgt_t **tgtlist)
{
	int		ret = 0;
	it_tgt_t	*tgt;
	it_tgt_t	*prev = NULL;
	nvpair_t	*nvp = NULL;
	nvlist_t	*nvt;
	char		*name;

	if (!tgtlist || !count) {
		return (EINVAL);
	}

	*tgtlist = NULL;
	*count = 0;

	if (!nvl) {
		/* nothing to do */
		return (0);
	}

	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {
		name = nvpair_name(nvp);

		ret = nvpair_value_nvlist(nvp, &nvt);
		if (ret != 0) {
			/* invalid entry? */
			continue;
		}

		ret = it_nv_to_tgt(nvt, name, &tgt);
		if (ret != 0) {
			break;
		}

		(*count)++;

		if (*tgtlist == NULL) {
			*tgtlist = tgt;
		} else {
			prev->tgt_next = tgt;
		}
		prev = tgt;
	}

	if (ret != 0) {
		it_tgt_free_cmn(*tgtlist);
		*tgtlist = NULL;
	}

	return (ret);
}

int
it_tgtlist_to_nv(it_tgt_t *tgtlist, nvlist_t **nvl)
{
	int		ret;
	it_tgt_t	*tgtp = tgtlist;
	nvlist_t	*pnv = NULL;
	nvlist_t	*tnv;

	if (!nvl) {
		return (EINVAL);
	}

	if (!tgtlist) {
		/* nothing to do */
		return (0);
	}

	/* create the target list if required */
	if (*nvl == NULL) {
		ret = nvlist_alloc(&pnv, NV_UNIQUE_NAME, 0);
		if (ret != 0) {
			return (ret);
		}
		*nvl = pnv;
	}

	while (tgtp) {
		ret = it_tgt_to_nv(tgtp, &tnv);

		if (ret != 0) {
			break;
		}

		ret = nvlist_add_nvlist(*nvl, tgtp->tgt_name, tnv);

		if (ret != 0) {
			break;
		}

		nvlist_free(tnv);

		tgtp = tgtp->tgt_next;
	}

	if (ret != 0) {
		if (pnv) {
			nvlist_free(pnv);
			*nvl = NULL;
		}
	}

	return (ret);
}

int
it_tgt_to_nv(it_tgt_t *tgt, nvlist_t **nvl)
{
	int		ret;
	nvlist_t	*tnv = NULL;

	if (!nvl) {
		return (EINVAL);
	}

	if (!tgt) {
		/* nothing to do */
		return (0);
	}

	ret = nvlist_alloc(nvl, NV_UNIQUE_NAME, 0);
	if (ret != 0) {
		return (ret);
	}

	if (tgt->tgt_properties) {
		ret = nvlist_add_nvlist(*nvl, "properties",
		    tgt->tgt_properties);
	}

	if (ret == 0) {
		ret = nvlist_add_uint64(*nvl, "generation",
		    tgt->tgt_generation);
	}

	if (ret == 0) {
		ret = it_tpgtlist_to_nv(tgt->tgt_tpgt_list, &tnv);
	}

	if ((ret == 0) && tnv) {
		ret = nvlist_add_nvlist(*nvl, "tpgtList", tnv);
		nvlist_free(tnv);
	}

	if (ret != 0) {
		nvlist_free(*nvl);
		*nvl = NULL;
	}

	return (ret);
}

int
it_nv_to_tgt(nvlist_t *nvl, char *name, it_tgt_t **tgt)
{
	int		ret;
	it_tgt_t	*ttgt;
	nvlist_t	*listval;
	uint32_t	intval;

	if (!nvl || !tgt || !name) {
		return (EINVAL);
	}

	*tgt = NULL;

	ttgt = iscsit_zalloc(sizeof (it_tgt_t));
	if (!ttgt) {
		return (ENOMEM);
	}

	(void) strlcpy(ttgt->tgt_name, name, sizeof (ttgt->tgt_name));

	ret = nvlist_lookup_nvlist(nvl, "properties", &listval);
	if (ret == 0) {
		/* duplicate list so it does not go out of context */
		ret = nvlist_dup(listval, &(ttgt->tgt_properties), 0);
	} else if (ret == ENOENT) {
		ret = 0;
	}

	if (ret == 0) {
		ret = nvlist_lookup_uint64(nvl, "generation",
		    &(ttgt->tgt_generation));
	} else if (ret == ENOENT) {
		ret = 0;
	}

	if (ret == 0) {
		ret = nvlist_lookup_nvlist(nvl, "tpgtList", &listval);
	}

	if (ret == 0) {
		ret = it_nv_to_tpgtlist(listval, &intval,
		    &(ttgt->tgt_tpgt_list));
		ttgt->tgt_tpgt_count = intval;
	} else if (ret == ENOENT) {
		ret = 0;
	}

	if (ret == 0) {
		*tgt = ttgt;
	} else {
		it_tgt_free_cmn(ttgt);
	}

	return (ret);
}

int
it_tpgt_to_nv(it_tpgt_t *tpgt, nvlist_t **nvl)
{
	int		ret;

	if (!nvl) {
		return (EINVAL);
	}

	if (!tpgt) {
		/* nothing to do */
		return (0);
	}

	ret = nvlist_alloc(nvl, NV_UNIQUE_NAME, 0);
	if (ret != 0) {
		return (ret);
	}

	ret = nvlist_add_uint16(*nvl, "tag", tpgt->tpgt_tag);
	if (ret == 0) {
		ret = nvlist_add_uint64(*nvl, "generation",
		    tpgt->tpgt_generation);
	}

	if (ret != 0) {
		nvlist_free(*nvl);
		*nvl = NULL;
	}

	return (ret);
}

int
it_nv_to_tpgt(nvlist_t *nvl, char *name, it_tpgt_t **tpgt)
{
	int		ret;
	it_tpgt_t	*ptr;

	if (!tpgt || !name) {
		return (EINVAL);
	}

	*tpgt = NULL;

	if (!nvl) {
		return (0);
	}

	ptr = iscsit_zalloc(sizeof (it_tpgt_t));
	if (!ptr) {
		return (ENOMEM);
	}

	(void) strlcpy(ptr->tpgt_tpg_name, name, sizeof (ptr->tpgt_tpg_name));

	ret = nvlist_lookup_uint16(nvl, "tag", &(ptr->tpgt_tag));
	if (ret == 0) {
		ret = nvlist_lookup_uint64(nvl, "generation",
		    &(ptr->tpgt_generation));
	}

	if (ret == 0) {
		*tpgt = ptr;
	} else {
		iscsit_free(ptr, sizeof (it_tpgt_t));
	}

	return (ret);
}

int
it_tpgtlist_to_nv(it_tpgt_t *tpgtlist, nvlist_t **nvl)
{
	int		ret;
	nvlist_t	*pnv = NULL;
	nvlist_t	*tnv;
	it_tpgt_t	*ptr = tpgtlist;

	if (!nvl) {
		return (EINVAL);
	}

	if (!tpgtlist) {
		/* nothing to do */
		return (0);
	}

	/* create the target list if required */
	if (*nvl == NULL) {
		ret = nvlist_alloc(&pnv, NV_UNIQUE_NAME, 0);
		if (ret != 0) {
			return (ret);
		}
		*nvl = pnv;
	}

	while (ptr) {
		ret = it_tpgt_to_nv(ptr, &tnv);

		if (ret != 0) {
			break;
		}

		ret = nvlist_add_nvlist(*nvl, ptr->tpgt_tpg_name, tnv);

		if (ret != 0) {
			break;
		}

		nvlist_free(tnv);

		ptr = ptr->tpgt_next;
	}

	if (ret != 0) {
		if (pnv) {
			nvlist_free(pnv);
			*nvl = NULL;
		}
	}

	return (ret);
}

int
it_nv_to_tpgtlist(nvlist_t *nvl, uint32_t *count, it_tpgt_t **tpgtlist)
{
	int		ret = 0;
	it_tpgt_t	*tpgt;
	it_tpgt_t	*prev = NULL;
	nvpair_t	*nvp = NULL;
	nvlist_t	*nvt;
	char		*name;

	if (!tpgtlist || !count) {
		return (EINVAL);
	}

	*tpgtlist = NULL;
	*count = 0;

	if (!nvl) {
		/* nothing to do */
		return (0);
	}

	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {
		name = nvpair_name(nvp);

		ret = nvpair_value_nvlist(nvp, &nvt);
		if (ret != 0) {
			/* invalid entry? */
			continue;
		}

		ret = it_nv_to_tpgt(nvt, name, &tpgt);
		if (ret != 0) {
			break;
		}

		(*count)++;

		if (*tpgtlist == NULL) {
			*tpgtlist = tpgt;
		} else {
			prev->tpgt_next = tpgt;
		}

		prev = tpgt;
	}

	if (ret != 0) {
		it_tpgt_free_cmn(*tpgtlist);
		*tpgtlist = NULL;
	}

	return (ret);
}

#ifndef _KERNEL
int
it_tpg_to_nv(it_tpg_t *tpg, nvlist_t **nvl)
{
	int		ret;
	char		**portalArray = NULL;
	int		i;
	it_portal_t	*ptr;

	if (!nvl) {
		return (EINVAL);
	}

	if (!tpg) {
		/* nothing to do */
		return (0);
	}

	ret = nvlist_alloc(nvl, NV_UNIQUE_NAME, 0);
	if (ret != 0) {
		return (ret);
	}

	ret = nvlist_add_uint64(*nvl, "generation", tpg->tpg_generation);

	if ((ret == 0) && tpg->tpg_portal_list) {
		/* add the portals */
		portalArray = iscsit_zalloc(tpg->tpg_portal_count *
		    sizeof (it_portal_t));
		if (portalArray == NULL) {
			nvlist_free(*nvl);
			*nvl = NULL;
			return (ENOMEM);
		}

		i = 0;
		ptr = tpg->tpg_portal_list;

		while (ptr && (i < tpg->tpg_portal_count)) {
			ret = sockaddr_to_str(&(ptr->portal_addr),
			    &(portalArray[i]));
			if (ret != 0) {
				break;
			}
			ptr = ptr->portal_next;
			i++;
		}
	}

	if ((ret == 0) && portalArray) {
		ret = nvlist_add_string_array(*nvl, "portalList",
		    portalArray, i);
	}


	if (portalArray) {
		while (--i >= 0) {
			if (portalArray[i]) {
				iscsit_free(portalArray[i],
				    strlen(portalArray[i] + 1));
			}
		}
		iscsit_free(portalArray,
		    tpg->tpg_portal_count * sizeof (it_portal_t));
	}

	if (ret != 0) {
		nvlist_free(*nvl);
		*nvl = NULL;
	}

	return (ret);
}
#endif /* !_KERNEL */

int
it_nv_to_tpg(nvlist_t *nvl, char *name, it_tpg_t **tpg)
{
	int		ret;
	it_tpg_t	*ptpg;
	char		**portalArray = NULL;
	uint32_t	count = 0;

	if (!name || !tpg) {
		return (EINVAL);
	}

	*tpg = NULL;

	ptpg = iscsit_zalloc(sizeof (it_tpg_t));
	if (ptpg == NULL) {
		return (ENOMEM);
	}

	(void) strlcpy(ptpg->tpg_name, name, sizeof (ptpg->tpg_name));

	ret = nvlist_lookup_uint64(nvl, "generation",
	    &(ptpg->tpg_generation));

	if (ret == 0) {
		ret = nvlist_lookup_string_array(nvl, "portalList",
		    &portalArray, &count);
	}

	if (ret == 0) {
		/* set the portals */
		ret = it_array_to_portallist(portalArray, count,
		    ISCSI_LISTEN_PORT, &ptpg->tpg_portal_list,
		    &ptpg->tpg_portal_count);
	} else if (ret == ENOENT) {
		ret = 0;
	}

	if (ret == 0) {
		*tpg = ptpg;
	} else {
		it_tpg_free_cmn(ptpg);
	}

	return (ret);
}




#ifndef _KERNEL
int
it_tpglist_to_nv(it_tpg_t *tpglist, nvlist_t **nvl)
{
	int		ret;
	nvlist_t	*pnv = NULL;
	nvlist_t	*tnv;
	it_tpg_t	*ptr = tpglist;

	if (!nvl) {
		return (EINVAL);
	}

	if (!tpglist) {
		/* nothing to do */
		return (0);
	}

	/* create the target portal group list if required */
	if (*nvl == NULL) {
		ret = nvlist_alloc(&pnv, NV_UNIQUE_NAME, 0);
		if (ret != 0) {
			return (ret);
		}
		*nvl = pnv;
	}

	while (ptr) {
		ret = it_tpg_to_nv(ptr, &tnv);

		if (ret != 0) {
			break;
		}

		ret = nvlist_add_nvlist(*nvl, ptr->tpg_name, tnv);

		if (ret != 0) {
			break;
		}

		nvlist_free(tnv);

		ptr = ptr->tpg_next;
	}

	if (ret != 0) {
		if (pnv) {
			nvlist_free(pnv);
			*nvl = NULL;
		}
	}

	return (ret);
}
#endif /* !_KERNEL */

it_tpg_t *
it_tpg_lookup(it_config_t *cfg, char *tpg_name)
{
	it_tpg_t *cfg_tpg = NULL;

	for (cfg_tpg = cfg->config_tpg_list;
	    cfg_tpg != NULL;
	    cfg_tpg = cfg_tpg->tpg_next) {
		if (strncmp(&cfg_tpg->tpg_name[0], tpg_name,
		    MAX_TPG_NAMELEN) == 0) {
			return (cfg_tpg);
		}
	}

	return (NULL);
}

int
it_sa_compare(struct sockaddr_storage *sa1, struct sockaddr_storage *sa2)
{
	struct sockaddr_in	*sin1, *sin2;
	struct sockaddr_in6	*sin6_1, *sin6_2;

	/*
	 * XXX - should we check here for IPv4 addrs mapped to v6?
	 * see also iscsit_is_v4_mapped in iscsit_login.c
	 */

	if (sa1->ss_family != sa2->ss_family) {
		return (1);
	}

	/*
	 * sockaddr_in has padding which may not be initialized.
	 * be more specific in the comparison, and don't trust the
	 * caller has fully initialized the structure.
	 */
	if (sa1->ss_family == AF_INET) {
		sin1 = (struct sockaddr_in *)sa1;
		sin2 = (struct sockaddr_in *)sa2;
		if ((bcmp(&sin1->sin_addr, &sin2->sin_addr,
		    sizeof (struct in_addr)) == 0) &&
		    (sin1->sin_port == sin2->sin_port)) {
			return (0);
		}
	} else if (sa1->ss_family == AF_INET6) {
		sin6_1 = (struct sockaddr_in6 *)sa1;
		sin6_2 = (struct sockaddr_in6 *)sa2;
		if (bcmp(sin6_1, sin6_2, sizeof (struct sockaddr_in6)) == 0) {
			return (0);
		}
	}

	return (1);
}

it_portal_t *
it_portal_lookup(it_tpg_t *tpg, struct sockaddr_storage *sa)
{
	it_portal_t *cfg_portal;

	for (cfg_portal = tpg->tpg_portal_list;
	    cfg_portal != NULL;
	    cfg_portal = cfg_portal->portal_next) {
		if (it_sa_compare(sa, &cfg_portal->portal_addr) == 0)
			return (cfg_portal);
	}

	return (NULL);
}

it_portal_t *
it_sns_svr_lookup(it_config_t *cfg, struct sockaddr_storage *sa)
{
	it_portal_t *cfg_portal;

	for (cfg_portal = cfg->config_isns_svr_list;
	    cfg_portal != NULL;
	    cfg_portal = cfg_portal->portal_next) {
		if (it_sa_compare(sa, &cfg_portal->portal_addr) == 0)
			return (cfg_portal);
	}

	return (NULL);
}

int
it_nv_to_tpglist(nvlist_t *nvl, uint32_t *count, it_tpg_t **tpglist)
{
	int		ret = 0;
	it_tpg_t	*tpg;
	it_tpg_t	*prev = NULL;
	nvpair_t	*nvp = NULL;
	nvlist_t	*nvt;
	char		*name;

	if (!tpglist || !count) {
		return (EINVAL);
	}

	*tpglist = NULL;
	*count = 0;

	if (!nvl) {
		/* nothing to do */
		return (0);
	}

	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {
		name = nvpair_name(nvp);

		ret = nvpair_value_nvlist(nvp, &nvt);
		if (ret != 0) {
			/* invalid entry? */
			continue;
		}

		ret = it_nv_to_tpg(nvt, name, &tpg);
		if (ret != 0) {
			break;
		}

		(*count)++;

		if (*tpglist == NULL) {
			*tpglist = tpg;
		} else {
			prev->tpg_next = tpg;
		}
		prev = tpg;
	}

	if (ret != 0) {
		it_tpg_free_cmn(*tpglist);
		*tpglist = NULL;
	}

	return (ret);
}

int
it_ini_to_nv(it_ini_t *ini, nvlist_t **nvl)
{
	int		ret;

	if (!nvl) {
		return (EINVAL);
	}

	if (!ini) {
		return (0);
	}

	ret = nvlist_alloc(nvl, NV_UNIQUE_NAME, 0);
	if (ret != 0) {
		return (ret);
	}

	if (ini->ini_properties) {
		ret = nvlist_add_nvlist(*nvl, "properties",
		    ini->ini_properties);
	}

	if (ret == 0) {
		ret = nvlist_add_uint64(*nvl, "generation",
		    ini->ini_generation);
	} else if (ret == ENOENT) {
		ret = 0;
	}

	if (ret != 0) {
		nvlist_free(*nvl);
		*nvl = NULL;
	}

	return (ret);
}

int
it_nv_to_ini(nvlist_t *nvl, char *name, it_ini_t **ini)
{
	int		ret;
	it_ini_t	*inip;
	nvlist_t	*listval;

	if (!name || !ini) {
		return (EINVAL);
	}

	*ini = NULL;

	if (!nvl) {
		return (0);
	}

	inip = iscsit_zalloc(sizeof (it_ini_t));
	if (!inip) {
		return (ENOMEM);
	}

	(void) strlcpy(inip->ini_name, name, sizeof (inip->ini_name));

	ret = nvlist_lookup_nvlist(nvl, "properties", &listval);
	if (ret == 0) {
		ret = nvlist_dup(listval, &(inip->ini_properties), 0);
	} else if (ret == ENOENT) {
		ret = 0;
	}

	if (ret == 0) {
		ret = nvlist_lookup_uint64(nvl, "generation",
		    &(inip->ini_generation));
	}

	if (ret == 0) {
		*ini = inip;
	} else {
		it_ini_free_cmn(inip);
	}

	return (ret);
}

int
it_inilist_to_nv(it_ini_t *inilist, nvlist_t **nvl)
{
	int		ret;
	nvlist_t	*pnv = NULL;
	nvlist_t	*tnv;
	it_ini_t	*ptr = inilist;

	if (!nvl) {
		return (EINVAL);
	}

	if (!inilist) {
		return (0);
	}

	/* create the target list if required */
	if (*nvl == NULL) {
		ret = nvlist_alloc(&pnv, NV_UNIQUE_NAME, 0);
		if (ret != 0) {
			return (ret);
		}
		*nvl = pnv;
	}

	while (ptr) {
		ret = it_ini_to_nv(ptr, &tnv);

		if (ret != 0) {
			break;
		}

		ret = nvlist_add_nvlist(*nvl, ptr->ini_name, tnv);

		if (ret != 0) {
			break;
		}

		nvlist_free(tnv);

		ptr = ptr->ini_next;
	}

	if (ret != 0) {
		if (pnv) {
			nvlist_free(pnv);
			*nvl = NULL;
		}
	}

	return (ret);
}

int
it_nv_to_inilist(nvlist_t *nvl, uint32_t *count, it_ini_t **inilist)
{
	int		ret = 0;
	it_ini_t	*inip;
	it_ini_t	*prev = NULL;
	nvpair_t	*nvp = NULL;
	nvlist_t	*nvt;
	char		*name;

	if (!inilist || !count) {
		return (EINVAL);
	}

	*inilist = NULL;
	*count = 0;

	if (!nvl) {
		/* nothing to do */
		return (0);
	}

	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {
		name = nvpair_name(nvp);

		ret = nvpair_value_nvlist(nvp, &nvt);
		if (ret != 0) {
			/* invalid entry? */
			continue;
		}

		ret = it_nv_to_ini(nvt, name, &inip);
		if (ret != 0) {
			break;
		}

		(*count)++;

		if (*inilist == NULL) {
			*inilist = inip;
		} else {
			prev->ini_next = inip;
		}
		prev = inip;
	}

	if (ret != 0) {
		it_ini_free_cmn(*inilist);
		*inilist = NULL;
	}

	return (ret);
}

/*
 * Convert a sockaddr to the string representation, suitable for
 * storing in an nvlist or printing out in a list.
 */
#ifndef _KERNEL
int
sockaddr_to_str(struct sockaddr_storage *sa, char **addr)
{
	int			ret;
	char			buf[INET6_ADDRSTRLEN + 7]; /* addr : port */
	char			pbuf[7];
	const char		*bufp;
	struct sockaddr_in	*sin;
	struct sockaddr_in6	*sin6;
	uint16_t		port;

	if (!sa || !addr) {
		return (EINVAL);
	}

	buf[0] = '\0';

	if (sa->ss_family == AF_INET) {
		sin = (struct sockaddr_in *)sa;
		bufp = inet_ntop(AF_INET,
		    (const void *)&(sin->sin_addr.s_addr),
		    buf, sizeof (buf));
		if (bufp == NULL) {
			ret = errno;
			return (ret);
		}
		port = ntohs(sin->sin_port);
	} else if (sa->ss_family == AF_INET6) {
		(void) strlcat(buf, "[", sizeof (buf));
		sin6 = (struct sockaddr_in6 *)sa;
		bufp = inet_ntop(AF_INET6,
		    (const void *)&sin6->sin6_addr.s6_addr,
		    &buf[1], (sizeof (buf) - 1));
		if (bufp == NULL) {
			ret = errno;
			return (ret);
		}
		(void) strlcat(buf, "]", sizeof (buf));
		port = ntohs(sin6->sin6_port);
	} else {
		return (EINVAL);
	}


	(void) snprintf(pbuf, sizeof (pbuf), ":%u", port);
	(void) strlcat(buf, pbuf, sizeof (buf));

	*addr = strdup(buf);
	if (*addr == NULL) {
		return (ENOMEM);
	}

	return (0);
}
#endif /* !_KERNEL */

int
it_array_to_portallist(char **arr, uint32_t count, uint32_t default_port,
    it_portal_t **portallist, uint32_t *list_count)
{
	int		ret = 0;
	int		i;
	it_portal_t	*portal;
	it_portal_t	*prev = NULL;
	it_portal_t	*tmp;

	if (!arr || !portallist || !list_count) {
		return (EINVAL);
	}

	*list_count = 0;
	*portallist = NULL;

	for (i = 0; i < count; i++) {
		if (!arr[i]) {
			/* should never happen */
			continue;
		}
		portal = iscsit_zalloc(sizeof (it_portal_t));
		if (!portal) {
			ret = ENOMEM;
			break;
		}
		if (it_common_convert_sa(arr[i],
		    &(portal->portal_addr), default_port) == NULL) {
			iscsit_free(portal, sizeof (it_portal_t));
			ret = EINVAL;
			break;
		}

		/* make sure no duplicates */
		tmp = *portallist;
		while (tmp) {
			if (it_sa_compare(&(tmp->portal_addr),
			    &(portal->portal_addr)) == 0) {
				iscsit_free(portal, sizeof (it_portal_t));
				portal = NULL;
				break;
			}
			tmp = tmp->portal_next;
		}

		if (!portal) {
			continue;
		}

		/*
		 * The first time through the loop, *portallist == NULL
		 * because we assigned it to NULL above.  Subsequently
		 * prev will have been set.  Therefor it's OK to put
		 * lint override before prev->portal_next assignment.
		 */
		if (*portallist == NULL) {
			*portallist = portal;
		} else {
			prev->portal_next = portal;
		}

		prev = portal;
		(*list_count)++;
	}

	return (ret);
}

/*
 * Function:  it_config_free_cmn()
 *
 * Free any resources associated with the it_config_t structure.
 *
 * Parameters:
 *    cfg       A C representation of the current iSCSI configuration
 */
void
it_config_free_cmn(it_config_t *cfg)
{
	if (!cfg) {
		return;
	}

	if (cfg->config_tgt_list) {
		it_tgt_free_cmn(cfg->config_tgt_list);
	}

	if (cfg->config_tpg_list) {
		it_tpg_free_cmn(cfg->config_tpg_list);
	}

	if (cfg->config_ini_list) {
		it_ini_free_cmn(cfg->config_ini_list);
	}

	if (cfg->config_global_properties) {
		nvlist_free(cfg->config_global_properties);
	}

	if (cfg->config_isns_svr_list) {
		it_portal_t	*pp = cfg->config_isns_svr_list;
		it_portal_t	*pp_next;

		while (pp) {
			pp_next = pp->portal_next;
			iscsit_free(pp, sizeof (it_portal_t));
			pp = pp_next;
		}
	}

	iscsit_free(cfg, sizeof (it_config_t));
}

/*
 * Function:  it_tgt_free_cmn()
 *
 * Frees an it_tgt_t structure.  If tgt_next is not NULL, frees
 * all structures in the list.
 */
void
it_tgt_free_cmn(it_tgt_t *tgt)
{
	it_tgt_t	*tgtp = tgt;
	it_tgt_t	*next;

	if (!tgt) {
		return;
	}

	while (tgtp) {
		next = tgtp->tgt_next;

		if (tgtp->tgt_tpgt_list) {
			it_tpgt_free_cmn(tgtp->tgt_tpgt_list);
		}

		if (tgtp->tgt_properties) {
			nvlist_free(tgtp->tgt_properties);
		}

		iscsit_free(tgtp, sizeof (it_tgt_t));

		tgtp = next;
	}
}

/*
 * Function:  it_tpgt_free_cmn()
 *
 * Deallocates resources of an it_tpgt_t structure.  If tpgt->next
 * is not NULL, frees all members of the list.
 */
void
it_tpgt_free_cmn(it_tpgt_t *tpgt)
{
	it_tpgt_t	*tpgtp = tpgt;
	it_tpgt_t	*next;

	if (!tpgt) {
		return;
	}

	while (tpgtp) {
		next = tpgtp->tpgt_next;

		iscsit_free(tpgtp, sizeof (it_tpgt_t));

		tpgtp = next;
	}
}

/*
 * Function:  it_tpg_free_cmn()
 *
 * Deallocates resources associated with an it_tpg_t structure.
 * If tpg->next is not NULL, frees all members of the list.
 */
void
it_tpg_free_cmn(it_tpg_t *tpg)
{
	it_tpg_t	*tpgp = tpg;
	it_tpg_t	*next;
	it_portal_t	*portalp;
	it_portal_t	*pnext;

	while (tpgp) {
		next = tpgp->tpg_next;

		portalp = tpgp->tpg_portal_list;

		while (portalp) {
			pnext = portalp->portal_next;
			iscsit_free(portalp, sizeof (it_portal_t));
			portalp = pnext;
		}

		iscsit_free(tpgp, sizeof (it_tpg_t));

		tpgp = next;
	}
}

/*
 * Function:  it_ini_free_cmn()
 *
 * Deallocates resources of an it_ini_t structure. If ini->next is
 * not NULL, frees all members of the list.
 */
void
it_ini_free_cmn(it_ini_t *ini)
{
	it_ini_t	*inip = ini;
	it_ini_t	*next;

	if (!ini) {
		return;
	}

	while (inip) {
		next = inip->ini_next;

		if (inip->ini_properties) {
			nvlist_free(inip->ini_properties);
		}

		iscsit_free(inip, sizeof (it_ini_t));

		inip = next;
	}
}
