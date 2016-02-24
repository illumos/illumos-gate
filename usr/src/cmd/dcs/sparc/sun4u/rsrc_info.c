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

/*
 * Routines for traversing and packing/unpacking the handle
 * returned from ri_init.
 */

#include <stdlib.h>
#include <strings.h>
#include "rsrc_info.h"
#include "rsrc_info_impl.h"

static int ap_list_pack(ri_ap_t *, char **, size_t *, int);
static int ap_list_unpack(char *, size_t, ri_ap_t **);
static int ap_pack(ri_ap_t *, char **, size_t *, int);
static int ap_unpack(char *, size_t, ri_ap_t *);
static int dev_list_pack(ri_dev_t *, char **, size_t *, int);
static int dev_list_unpack(char *, size_t, ri_dev_t **);
static int dev_pack(ri_dev_t *, char **, size_t *, int);
static int dev_unpack(char *, size_t, ri_dev_t *);
static int client_list_pack(ri_client_t *, char **, size_t *, int);
static int client_list_unpack(char *, size_t, ri_client_t **);
static int client_pack(ri_client_t *, char **, size_t *, int);
static int client_unpack(char *, size_t, ri_client_t *);
static int pack_add_byte_array(nvlist_t *, char *, nvlist_t *, int);
static int lookup_unpack_byte_array(nvlist_t *, char *, nvlist_t **);
static void ri_ap_free(ri_ap_t *);

void
ri_fini(ri_hdl_t *hdl)
{
	ri_ap_t		*ap;
	ri_client_t	*client;

	if (hdl == NULL)
		return;

	while ((ap = hdl->aps) != NULL) {
		hdl->aps = ap->next;
		ri_ap_free(ap);
	}
	while ((client = hdl->cpu_cap_clients) != NULL) {
		hdl->cpu_cap_clients = client->next;
		ri_client_free(client);
	}
	while ((client = hdl->mem_cap_clients) != NULL) {
		hdl->mem_cap_clients = client->next;
		ri_client_free(client);
	}
	free(hdl);
}

static void
ri_ap_free(ri_ap_t *ap)
{
	ri_dev_t	*dev;

	assert(ap != NULL);

	nvlist_free(ap->conf_props);

	while ((dev = ap->cpus) != NULL) {
		ap->cpus = dev->next;
		ri_dev_free(dev);
	}
	while ((dev = ap->mems) != NULL) {
		ap->mems = dev->next;
		ri_dev_free(dev);
	}
	while ((dev = ap->ios) != NULL) {
		ap->ios = dev->next;
		ri_dev_free(dev);
	}
	free(ap);
}

void
ri_dev_free(ri_dev_t *dev)
{
	ri_client_t	*client;

	assert(dev != NULL);

	nvlist_free(dev->conf_props);
	while ((client = dev->rcm_clients) != NULL) {
		dev->rcm_clients = client->next;
		ri_client_free(client);
	}
	free(dev);
}

void
ri_client_free(ri_client_t *client)
{
	assert(client != NULL);

	nvlist_free(client->usg_props);
	nvlist_free(client->v_props);
	free(client);
}

/*
 * Pack everything contained in the handle up inside out.
 */
int
ri_pack(ri_hdl_t *hdl, caddr_t *bufp, size_t *sizep, int encoding)
{
	nvlist_t	*nvl = NULL;
	char		*buf = NULL;
	size_t		size = 0;

	if (bufp == NULL || sizep == NULL)
		return (RI_INVAL);

	*sizep = 0;
	*bufp = NULL;

	/*
	 * Check the handle. If it is NULL, there
	 * is nothing to pack, so we are done.
	 */
	if (hdl == NULL) {
		return (RI_SUCCESS);
	}

	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0) {
		dprintf((stderr, "nvlist_alloc fail\n", errno));
		goto fail;
	}

	if (nvlist_add_int32(nvl, RI_HDL_FLAGS, hdl->flags) != 0) {
		dprintf((stderr, "nvlist_add_int32 fail\n"));
		goto fail;
	}

	if (ap_list_pack(hdl->aps, &buf, &size, encoding) != 0 ||
	    nvlist_add_byte_array(nvl, RI_HDL_APS, (uchar_t *)buf, size) != 0) {
		goto fail;
	}

	s_free(buf);
	if (client_list_pack(hdl->cpu_cap_clients, &buf, &size,
	    encoding) != 0 ||
	    nvlist_add_byte_array(nvl, RI_HDL_CPU_CAPS, (uchar_t *)buf,
	    size) != 0) {
		goto fail;
	}

	s_free(buf);
	if (client_list_pack(hdl->mem_cap_clients, &buf, &size,
	    encoding) != 0 ||
	    nvlist_add_byte_array(nvl, RI_HDL_MEM_CAPS, (uchar_t *)buf,
	    size) != 0) {
		goto fail;
	}

	s_free(buf);
	if (nvlist_pack(nvl, &buf, &size, encoding, 0) != 0) {
		dprintf((stderr, "nvlist_pack fail\n"));
		goto fail;
	}

	nvlist_free(nvl);
	*bufp = buf;
	*sizep = size;

	return (RI_SUCCESS);

fail:
	s_free(buf);
	nvlist_free(nvl);

	return (RI_FAILURE);
}

/*
 * Pack a list of attachment point handles.
 */
static int
ap_list_pack(ri_ap_t *aplist, char **bufp, size_t *sizep, int encoding)
{
	nvlist_t	*nvl = NULL;
	char		*buf = NULL;
	size_t		size;

	assert(bufp != NULL && sizep != NULL);

	*sizep = 0;
	*bufp = NULL;

	if (nvlist_alloc(&nvl, 0, 0) != 0) {
		dprintf((stderr, "nvlist_alloc fail\n"));
		return (-1);
	}

	while (aplist != NULL) {
		s_free(buf);
		if (ap_pack(aplist, &buf, &size, encoding) != 0)
			goto fail;

		if (nvlist_add_byte_array(nvl, RI_AP_T, (uchar_t *)buf,
		    size) != 0) {
			dprintf((stderr, "nvlist_add_byte_array fail "
			    "(%s)\n", RI_AP_T));
			goto fail;
		}
		aplist = aplist->next;
	}

	s_free(buf);
	if (nvlist_pack(nvl, &buf, &size, encoding, 0) != 0) {
		dprintf((stderr, "nvlist_pack fail\n"));
		goto fail;
	}

	nvlist_free(nvl);
	*bufp = buf;
	*sizep = size;

	return (0);

fail:
	s_free(buf);
	nvlist_free(nvl);

	return (-1);
}

/*
 * Pack a list of ri_dev_t's.
 */
static int
dev_list_pack(ri_dev_t *devlist, char **bufp, size_t *sizep, int encoding)
{
	nvlist_t	*nvl = NULL;
	char		*buf = NULL;
	size_t		size = 0;

	assert(bufp != NULL && sizep != NULL);

	*sizep = 0;
	*bufp = NULL;

	if (nvlist_alloc(&nvl, 0, 0) != 0) {
		dprintf((stderr, "nvlist_alloc fail\n"));
		return (-1);
	}

	while (devlist != NULL) {
		s_free(buf);
		if (dev_pack(devlist, &buf, &size, encoding) != 0)
			goto fail;

		if (nvlist_add_byte_array(nvl, RI_DEV_T, (uchar_t *)buf,
		    size) != 0) {
			dprintf((stderr, "nvlist_add_byte_array fail "
			    "(%s)\n", RI_DEV_T));
			goto fail;
		}
		devlist = devlist->next;
	}

	s_free(buf);
	if (nvlist_pack(nvl, &buf, &size, encoding, 0) != 0) {
		dprintf((stderr, "nvlist_pack fail\n"));
		goto fail;
	}

	nvlist_free(nvl);
	*bufp = buf;
	*sizep = size;

	return (0);

fail:
	s_free(buf);
	nvlist_free(nvl);

	return (-1);
}

/*
 * Pack a list of ri_client_t's.
 */
static int
client_list_pack(ri_client_t *client_list, char **bufp, size_t *sizep,
    int encoding)
{
	nvlist_t	*nvl = NULL;
	char		*buf = NULL;
	size_t		size = 0;

	assert(bufp != NULL && sizep != NULL);

	*sizep = 0;
	*bufp = NULL;

	if (nvlist_alloc(&nvl, 0, 0) != 0) {
		dprintf((stderr, "nvlist_alloc fail\n"));
		return (-1);
	}

	while (client_list != NULL) {
		s_free(buf);
		if (client_pack(client_list, &buf, &size, encoding) != 0)
			goto fail;

		if (nvlist_add_byte_array(nvl, RI_CLIENT_T, (uchar_t *)buf,
		    size) != 0) {
			dprintf((stderr, "nvlist_add_byte_array fail "
			    "(%s)\n", RI_CLIENT_T));
			goto fail;
		}
		client_list = client_list->next;
	}

	s_free(buf);
	if (nvlist_pack(nvl, &buf, &size, encoding, 0) != 0) {
		dprintf((stderr, "nvlist_pack fail\n"));
		goto fail;
	}

	nvlist_free(nvl);
	*bufp = buf;
	*sizep = size;

	return (0);

fail:
	s_free(buf);
	nvlist_free(nvl);

	return (-1);
}

static int
ap_pack(ri_ap_t *ap, char **bufp, size_t *sizep, int encoding)
{
	nvlist_t	*nvl = NULL;
	char		*buf = NULL;
	size_t		size = 0;

	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0) {
		dprintf((stderr, "nvlist_alloc fail\n"));
		return (-1);
	}

	if (pack_add_byte_array(ap->conf_props, RI_AP_PROPS, nvl,
	    encoding) != 0)
		goto fail;

	if (dev_list_pack(ap->cpus, &buf, &size, encoding) != 0)
		goto fail;

	if (nvlist_add_byte_array(nvl, RI_AP_CPUS, (uchar_t *)buf,
	    size) != 0) {
		dprintf((stderr, "nvlist_add_byte_array (%s)\n", RI_AP_CPUS));
		goto fail;
	}

	s_free(buf);
	if (dev_list_pack(ap->mems, &buf, &size, encoding) != 0)
		goto fail;

	if (nvlist_add_byte_array(nvl, RI_AP_MEMS, (uchar_t *)buf,
	    size) != 0) {
		dprintf((stderr, "nvlist_add_byte_array (%s)n", RI_AP_MEMS));
		goto fail;
	}

	s_free(buf);
	if (dev_list_pack(ap->ios, &buf, &size, encoding) != 0)
		goto fail;

	if (nvlist_add_byte_array(nvl, RI_AP_IOS, (uchar_t *)buf,
	    size) != 0) {
		dprintf((stderr, "nvlist_add_byte_array (%s)n", RI_AP_IOS));
		goto fail;
	}

	s_free(buf);
	if (nvlist_pack(nvl, &buf, &size, encoding, 0) != 0) {
		dprintf((stderr, "nvlist_pack fail\n"));
		goto fail;
	}

	nvlist_free(nvl);
	*bufp = buf;
	*sizep = size;

	return (0);

fail:
	s_free(buf);
	nvlist_free(nvl);

	return (-1);
}

static int
dev_pack(ri_dev_t *dev, char **bufp, size_t *sizep, int encoding)
{
	nvlist_t	*nvl = NULL;
	char		*buf = NULL;
	size_t		size = 0;

	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0) {
		dprintf((stderr, "nvlist_alloc fail\n"));
		return (-1);
	}

	if (pack_add_byte_array(dev->conf_props, RI_DEV_PROPS, nvl,
	    encoding) != 0)
		goto fail;

	if (client_list_pack(dev->rcm_clients, &buf, &size, encoding) != 0)
		goto fail;

	if (nvlist_add_byte_array(nvl, RI_DEV_CLIENTS, (uchar_t *)buf,
	    size) != 0) {
		dprintf((stderr, "nvlist_add_byte_array (%s)n",
		    RI_DEV_CLIENTS));
		goto fail;
	}

	s_free(buf);
	if (nvlist_pack(nvl, &buf, &size, encoding, 0) != 0) {
		dprintf((stderr, "nvlist_pack fail\n"));
		goto fail;
	}

	nvlist_free(nvl);
	*bufp = buf;
	*sizep = size;

	return (0);

fail:
	s_free(buf);
	nvlist_free(nvl);

	return (-1);
}

static int
client_pack(ri_client_t *client, char **bufp, size_t *sizep, int encoding)
{
	nvlist_t	*nvl = NULL;
	char		*buf = NULL;
	size_t		size = 0;

	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0) {
		dprintf((stderr, "nvlist_alloc fail\n"));
		return (-1);
	}

	if (pack_add_byte_array(client->usg_props, RI_CLIENT_USAGE_PROPS,
	    nvl, encoding) != 0) {
		goto fail;
	}

	/*
	 * This will only be present if RI_VERBOSE was specified
	 * in the call to ri_init.
	 */
	if (client->v_props != NULL && pack_add_byte_array(client->v_props,
	    RI_CLIENT_VERB_PROPS, nvl, encoding) != 0) {
		goto fail;
	}

	if (nvlist_pack(nvl, &buf, &size, encoding, 0) != 0) {
		dprintf((stderr, "nvlist_pack fail\n"));
		goto fail;
	}

	nvlist_free(nvl);
	*bufp = buf;
	*sizep = size;

	return (0);

fail:
	s_free(buf);
	nvlist_free(nvl);

	return (-1);
}

/*
 * Pack nvlist_t and add as byte array to another nvlist_t.
 */
static int
pack_add_byte_array(nvlist_t *nvl_packme, char *name, nvlist_t *nvl,
    int encoding)
{
	char	*buf = NULL;
	size_t	size = 0;

	if (nvlist_pack(nvl_packme, &buf, &size, encoding, 0) != 0) {
		dprintf((stderr, "nvlist_pack fail (%s)\n", name));
		s_free(buf);
		return (-1);
	}

	if (nvlist_add_byte_array(nvl, name, (uchar_t *)buf, size) != 0) {
		dprintf((stderr, "nvlist_add_byte_array fail (%s)\n", name));
		return (-1);
	}

	s_free(buf);
	return (0);
}

/*
 * Unpack buf into ri_hdl_t.
 */
int
ri_unpack(caddr_t buf, size_t size, ri_hdl_t **hdlp)
{
	ri_hdl_t	*ri_hdl = NULL;
	nvlist_t	*nvl = NULL;

	if (hdlp == NULL)
		return (RI_INVAL);

	*hdlp = NULL;
	if ((ri_hdl = calloc(1, sizeof (*ri_hdl))) == NULL) {
		dprintf((stderr, "calloc: %s\n", strerror(errno)));
		return (RI_FAILURE);
	}

	if (nvlist_unpack(buf, size, &nvl, 0) != 0) {
		dprintf((stderr, "nvlist_unpack fail\n"));
		goto fail;
	}

	if (nvlist_lookup_int32(nvl, RI_HDL_FLAGS, &ri_hdl->flags) != 0) {
		dprintf((stderr, "nvlist_lookup_int32 fail (%s)\n",
		    RI_HDL_FLAGS));
		goto fail;
	}

	buf = NULL;
	size = 0;
	if (nvlist_lookup_byte_array(nvl, RI_HDL_APS, (uchar_t **)&buf,
	    (uint_t *)&size) != 0) {
		dprintf((stderr, "nvlist_lookup_int32 fail (%s)\n",
		    RI_HDL_APS));
		goto fail;
	}

	if (ap_list_unpack(buf, size, &ri_hdl->aps) != 0)
		goto fail;

	buf = NULL;
	size = 0;
	if (nvlist_lookup_byte_array(nvl, RI_HDL_CPU_CAPS, (uchar_t **)&buf,
	    (uint_t *)&size) != 0) {
		dprintf((stderr, "nvlist_lookup_byte_array fail (%s)\n",
		    RI_HDL_CPU_CAPS));
		goto fail;
	}

	if (client_list_unpack(buf, size, &ri_hdl->cpu_cap_clients) != 0)
		goto fail;

	buf = NULL;
	size = 0;
	if (nvlist_lookup_byte_array(nvl, RI_HDL_MEM_CAPS, (uchar_t **)&buf,
	    (uint_t *)&size) != 0) {
		dprintf((stderr, "nvlist_lookup_byte_array fail (%s)\n",
		    RI_HDL_MEM_CAPS));
		goto fail;
	}

	if (client_list_unpack(buf, size, &ri_hdl->mem_cap_clients) != 0)
		goto fail;

	*hdlp = ri_hdl;

	return (0);

fail:
	free(ri_hdl);
	nvlist_free(nvl);

	return (-1);
}

static int
ap_list_unpack(char *buf, size_t size, ri_ap_t **aps)
{
	nvpair_t	*nvp = NULL;
	nvlist_t	*nvl;
	ri_ap_t		*aplist = NULL;
	ri_ap_t		*prev = NULL;
	ri_ap_t		*tmp = NULL;

	if (nvlist_unpack(buf, size, &nvl, 0) != 0) {
		dprintf((stderr, "nvlist_unpack fail\n"));
		return (-1);
	}

	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {
		assert(strcmp(nvpair_name(nvp), RI_AP_T) == 0 &&
		    nvpair_type(nvp) == DATA_TYPE_BYTE_ARRAY);

		if ((tmp = calloc(1, sizeof (*tmp))) == NULL) {
			dprintf((stderr, "calloc: %s\n", strerror(errno)));
			goto fail;
		}

		buf = NULL;
		size = 0;
		if (nvpair_value_byte_array(nvp, (uchar_t **)&buf,
		    (uint_t *)&size) != 0) {
			dprintf((stderr, "nvpair_value_byte_array fail\n"));
			goto fail;
		}

		if (ap_unpack(buf, size, tmp) != 0)
			goto fail;

		if (aplist == NULL) {
			prev = aplist = tmp;
		} else {
			prev->next = tmp;
			prev = tmp;
		}
	}

	nvlist_free(nvl);
	*aps = aplist;

	return (0);

fail:
	nvlist_free(nvl);
	if (aplist != NULL) {
		while ((tmp = aplist) != NULL) {
			aplist = aplist->next;
			ri_ap_free(tmp);
		}
	}

	return (-1);
}

static int
dev_list_unpack(char *buf, size_t size, ri_dev_t **devs)
{
	nvpair_t	*nvp = NULL;
	nvlist_t	*nvl;
	ri_dev_t	*devlist = NULL;
	ri_dev_t	*prev = NULL;
	ri_dev_t	*tmp = NULL;

	if (nvlist_unpack(buf, size, &nvl, 0) != 0) {
		dprintf((stderr, "nvlist_unpack fail\n"));
		return (-1);
	}

	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {
		assert(strcmp(nvpair_name(nvp), RI_DEV_T) == 0 &&
		    nvpair_type(nvp) == DATA_TYPE_BYTE_ARRAY);

		if ((tmp = calloc(1, sizeof (*tmp))) == NULL) {
			dprintf((stderr, "calloc: %s\n", strerror(errno)));
			goto fail;
		}

		if (nvpair_value_byte_array(nvp, (uchar_t **)&buf,
		    (uint_t *)&size) != 0) {
			dprintf((stderr, "nvpair_value_byte_array fail\n"));
			goto fail;
		}

		if (dev_unpack(buf, size, tmp) != 0)
			goto fail;

		if (devlist == NULL) {
			prev = devlist = tmp;
		} else {
			prev->next = tmp;
			prev = tmp;
		}
	}

	nvlist_free(nvl);
	*devs = devlist;

	return (0);

fail:
	nvlist_free(nvl);
	if (devlist != NULL) {
		while ((tmp = devlist) != NULL) {
			devlist = devlist->next;
			ri_dev_free(tmp);
		}
	}

	return (-1);
}

static int
client_list_unpack(char *buf, size_t size, ri_client_t **clients)
{
	nvpair_t	*nvp = NULL;
	nvlist_t	*nvl;
	ri_client_t	*client_list = NULL;
	ri_client_t	*prev = NULL;
	ri_client_t	*tmp = NULL;

	if (nvlist_unpack(buf, size, &nvl, 0) != 0) {
		dprintf((stderr, "nvlist_unpack fail\n"));
		return (-1);
	}

	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {
		assert(strcmp(nvpair_name(nvp), RI_CLIENT_T) == 0);
		assert(nvpair_type(nvp) == DATA_TYPE_BYTE_ARRAY);

		if ((tmp = calloc(1, sizeof (*tmp))) == NULL) {
			dprintf((stderr, "calloc: %s\n", strerror(errno)));
			goto fail;
		}

		buf = NULL;
		size = 0;
		if (nvpair_value_byte_array(nvp, (uchar_t **)&buf,
		    (uint_t *)&size) != 0) {
			dprintf((stderr, "nvpair_value_byte_array fail\n"));
			goto fail;
		}

		if (client_unpack(buf, size, tmp) != 0)
			goto fail;

		if (client_list == NULL) {
			prev = client_list = tmp;
		} else {
			prev->next = tmp;
			prev = tmp;
		}
	}

	nvlist_free(nvl);
	*clients = client_list;

	return (0);

fail:
	nvlist_free(nvl);
	if (client_list != NULL) {
		while ((tmp = client_list) != NULL) {
			client_list = client_list->next;
			ri_client_free(tmp);
		}
	}

	return (-1);
}

static int
client_unpack(char *buf, size_t size, ri_client_t *client)
{
	nvlist_t	*nvl;

	if (nvlist_unpack(buf, size, &nvl, 0) != 0) {
		dprintf((stderr, "nvlist_unpack fail\n"));
		return (-1);
	}

	if (lookup_unpack_byte_array(nvl, RI_CLIENT_USAGE_PROPS,
	    &client->usg_props) != 0) {
		nvlist_free(nvl);
		return (-1);
	}

#ifdef DEBUG
	nvlist_print(stderr, client->usg_props);
#endif /* DEBUG */

	/*
	 * Verbose properties for RCM clients only present if
	 * RI_VERBOSE was specified for ri_init.
	 */
	buf = NULL;
	size = 0;
	if (nvlist_lookup_byte_array(nvl, RI_CLIENT_VERB_PROPS,
	    (uchar_t **)&buf, (uint_t *)&size) == 0) {
		if (nvlist_unpack(buf, size, &client->v_props, 0) != 0) {
			dprintf((stderr, "nvlist_unpack fail (%s)\n",
			    RI_CLIENT_VERB_PROPS));
			nvlist_free(nvl);
			return (-1);
		}
	}

	nvlist_free(nvl);

	return (0);
}

static int
dev_unpack(char *buf, size_t size, ri_dev_t *dev)
{
	nvlist_t	*nvl;

	if (nvlist_unpack(buf, size, &nvl, 0) != 0) {
		dprintf((stderr, "nvlist_unpack fail\n"));
		return (-1);
	}

	if (lookup_unpack_byte_array(nvl, RI_DEV_PROPS,
	    &dev->conf_props) != 0) {
		nvlist_free(nvl);
		return (-1);
	}

#ifdef DEBUG
	nvlist_print(stderr, dev->conf_props);
#endif /* DEBUG */

	if (nvlist_lookup_byte_array(nvl, RI_DEV_CLIENTS, (uchar_t **)&buf,
	    (uint_t *)&size) != 0) {
		dprintf((stderr, "nvlist_lookup_byte_array fail (%s)\n",
		    RI_DEV_CLIENTS));
		nvlist_free(nvl);
		return (-1);
	}

	if (client_list_unpack(buf, size, &dev->rcm_clients) != 0) {
		nvlist_free(nvl);
		return (-1);
	}

	nvlist_free(nvl);

	return (0);
}

static int
ap_unpack(char *buf, size_t size, ri_ap_t *ap)
{
	nvlist_t	*nvl;

	if (nvlist_unpack(buf, size, &nvl, 0) != 0) {
		dprintf((stderr, "nvlist_unpack fail\n"));
		return (-1);
	}

	if (lookup_unpack_byte_array(nvl, RI_AP_PROPS, &ap->conf_props) != 0) {
		nvlist_free(nvl);
		return (-1);
	}

#ifdef DEBUG
	nvlist_print(stderr, ap->conf_props);
#endif /* DEBUG */

	if (nvlist_lookup_byte_array(nvl, RI_AP_CPUS, (uchar_t **)&buf,
	    (uint_t *)&size) != 0) {
		dprintf((stderr, "nvlist_lookup_byte_array fail (%s)\n",
		    RI_AP_CPUS));
		nvlist_free(nvl);
		return (-1);
	}

	if (dev_list_unpack(buf, size, &ap->cpus) != 0) {
		nvlist_free(nvl);
		return (-1);
	}

	if (nvlist_lookup_byte_array(nvl, RI_AP_MEMS, (uchar_t **)&buf,
	    (uint_t *)&size) != 0) {
		dprintf((stderr, "nvlist_lookup_byte_array fail (%s)\n",
		    RI_AP_MEMS));
		nvlist_free(nvl);
		return (-1);
	}

	if (dev_list_unpack(buf, size, &ap->mems) != 0) {
		nvlist_free(nvl);
		return (-1);
	}

	if (nvlist_lookup_byte_array(nvl, RI_AP_IOS, (uchar_t **)&buf,
	    (uint_t *)&size) != 0) {
		dprintf((stderr, "nvlist_lookup_byte_array fail (%s)\n",
		    RI_AP_IOS));
		nvlist_free(nvl);
		return (-1);
	}

	if (dev_list_unpack(buf, size, &ap->ios) != 0) {
		nvlist_free(nvl);
		return (-1);
	}

	nvlist_free(nvl);

	return (0);
}

/*
 * Lookup byte array in old nvlist_t and unpack into new nvlist_t.
 */
static int
lookup_unpack_byte_array(nvlist_t *old_nvl, char *name, nvlist_t **new_nvl)
{
	char	*buf = NULL;
	size_t	size = 0;

	if (nvlist_lookup_byte_array(old_nvl, name, (uchar_t **)&buf,
	    (uint_t *)&size) != 0) {
		dprintf((stderr, "nvlist_lookup_byte_array fail (%s)\n",
		    name));
		return (-1);
	}

	if (nvlist_unpack(buf, size, new_nvl, 0) != 0) {
		dprintf((stderr, "nvlist_unpack fail (%s)\n", name));
		return (-1);
	}

	return (0);
}

ri_ap_t *
ri_ap_next(ri_hdl_t *hdl, ri_ap_t *ap)
{
	if (hdl == NULL) {
		errno = EINVAL;
		return (NULL);
	}
	return ((ap == NULL) ? hdl->aps : ap->next);
}

nvlist_t *
ri_ap_conf_props(ri_ap_t *ap)
{
	if (ap == NULL) {
		errno = EINVAL;
		return (NULL);
	}
	return (ap->conf_props);
}

ri_dev_t *
ri_cpu_next(ri_ap_t *ap, ri_dev_t *cpu)
{
	if (ap == NULL) {
		errno = EINVAL;
		return (NULL);
	}
	return ((cpu == NULL) ? ap->cpus : cpu->next);
}

ri_dev_t *
ri_mem_next(ri_ap_t *ap, ri_dev_t *mem)
{
	if (ap == NULL) {
		errno = EINVAL;
		return (NULL);
	}
	return ((mem == NULL) ? ap->mems : mem->next);
}

ri_dev_t *
ri_io_next(ri_ap_t *ap, ri_dev_t *io)
{
	if (ap == NULL) {
		errno = EINVAL;
		return (NULL);
	}
	return ((io == NULL) ? ap->ios : io->next);
}

ri_client_t *
ri_client_next(ri_dev_t *dev, ri_client_t *rcm_client)
{
	if (dev == NULL) {
		errno = EINVAL;
		return (NULL);
	}
	return ((rcm_client == NULL) ? dev->rcm_clients : rcm_client->next);
}

nvlist_t *
ri_dev_conf_props(ri_dev_t *dev)
{
	if (dev == NULL) {
		errno = EINVAL;
		return (NULL);
	}
	return (dev->conf_props);
}

nvlist_t *
ri_client_usage_props(ri_client_t *rcm_client)
{
	if (rcm_client == NULL) {
		errno = EINVAL;
		return (NULL);
	}
	return (rcm_client->usg_props);
}

nvlist_t *
ri_client_verbose_props(ri_client_t *rcm_client)
{
	if (rcm_client == NULL) {
		errno = EINVAL;
		return (NULL);
	}
	return (rcm_client->v_props);
}

ri_client_t *
ri_cpu_cap_client_next(ri_hdl_t *hdl, ri_client_t *rcm_client)
{
	if (hdl == NULL) {
		errno = EINVAL;
		return (NULL);
	}
	return ((rcm_client == NULL) ? hdl->cpu_cap_clients : rcm_client->next);
}

ri_client_t *
ri_mem_cap_client_next(ri_hdl_t *hdl, ri_client_t *rcm_client)
{
	if (hdl == NULL) {
		errno = EINVAL;
		return (NULL);
	}
	return ((rcm_client == NULL) ? hdl->mem_cap_clients : rcm_client->next);
}
