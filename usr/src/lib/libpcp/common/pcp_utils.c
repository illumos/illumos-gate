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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Implements auxiliary routines declared in pcp_utils.h to facilitate
 * finding the appropriate communication transport & device path for a
 * given service.  This supports the transition from the legacy service channel
 * transport (glvc) to the logical domain channel (vldc) transport native
 * to platforms running Logical Domains (LDoms).
 */

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <strings.h>
#include <stdlib.h>
#include <libgen.h>
#include <unistd.h>
#include <stdio.h>
#include <libdevinfo.h>

#include "pcp_utils.h"

typedef enum { false = 0, true = 1 } bool_t;

#define	SERVICE_PREFIX	"SUNW,sun4v-"
#define	DEVICES_DIR "/devices"
#define	GLVC	":glvc"
#define	VCHAN	"virtual-channel@"
#define	VCHAN_C	"virtual-channel-client@"

/*
 * The mechanism to relate a service to a device path is different for
 * vldc and glvc, due to the way the device pathnames are encoded:
 * Sample service: sunvts
 * Service Name: SUNW,sun4v-sunvts
 * GLVC device path:
 * "/devices/virtual-devices@100/sunvts@a:glvc"
 * VLDC device path:
 * "/devices/virtual-devices@100/channel-devices@200/virtual-channel@3:sunvts"
 *
 * As VLDC is the communication mechanism used in an LDoms environment, it is
 * the preferred channel, and its existence is checked for first.
 */

/*
 * Extract from dev_path the "service name" portion.
 * For vldc, the service corresponds to the minor name of the device path
 * (e.g. virtual-channel@3:sunvts for sunvts).  If service is non-NULL, it must
 * match the extracted service name for the function to succeed.
 * The service name is returned in match (if non-NULL), and the function
 * itself returns true on success; false on failure.
 */
static bool_t
get_vldc_svc_name(char *dev_path, char *service, char **match)
{
	bool_t ret = false;
	char *pathname = strdup(dev_path);
	char *devname, *s;

	if (NULL == pathname)
		return (false);

	devname = basename(pathname);
	s = strrchr(devname, ':');

	if (s++ == NULL) {
		goto end;
	}

	if ((strncmp(devname, VCHAN, strlen(VCHAN)) == 0) ||
	    (strncmp(devname, VCHAN_C, strlen(VCHAN_C)) == 0)) {
		/*
		 * If in addition, a service string is specified to
		 * be matched, do a comparison
		 */
		if (service != NULL) {
			if (strcmp(s, service) == 0) {
				if (match)
					*match = strdup(s);
				ret = true;
				goto end;
			} else {
				ret = false;
				goto end;
			}
		} else if (match) {
			*match = strdup(s);
		}

		ret = true;
		goto end;
	}
end:

	free(pathname);
	return (ret);
}

/*
 * Extract from dev_path the "service name" portion.
 * For glvc, the service corresponds to the node name of the device path
 * (e.g. sunvts@a:glvc for sunvts).  If service is non-NULL, it must
 * match the extracted service name for the function to succeed.
 * The service name is returned in match (if non-NULL), and the function
 * itself returns true on success; false on failure.
 */
static bool_t
get_glvc_svc_name(char *dev_path, char *service, char **match)
{
	bool_t ret = true;
	char *pathname = strdup(dev_path);
	char *devname, *substr, *t;
	int len;

	if (NULL == pathname)
		return (false);

	devname = basename(pathname);
	substr = strstr(devname, GLVC);

	if (!((substr != NULL) && (strcmp(substr, GLVC) == 0))) {
		ret = false;
		goto end;
	}

	if ((t = strrchr(devname, '@')) == NULL) {
		ret = false;
		goto end;
	}

	len = t - devname;

	/*
	 * If a service string is specified, check if there
	 * is a match
	 */
	if ((service != NULL) && (strncmp(devname, service, len) != 0))
		ret = false;

	if ((ret == true) && (match != NULL)) {
		*match = calloc(len + 1, 1);
		if (*match)
			(void) strncpy(*match, devname, len);
	}

end:
	free(pathname);
	return (ret);
}

/*
 * This routine accepts either a prefixed service name or a legacy full
 * pathname (which might not even exist in the filesystem), and in either case
 * returns a canonical service name.  If the parameter is neither a service
 * name (i.e. with a "SUNW,sun4v-" prefix), nor a path to a legacy glvc or
 * vldc device, NULL is returned.
 */
char *
platsvc_extract_svc_name(char *devname)
{
	char *sname = NULL;
	char *vldc_path, *glvc_path;

	/*
	 * First check whether a service name
	 */
	if (strncmp(devname, SERVICE_PREFIX, strlen(SERVICE_PREFIX)) == 0) {
		sname = strdup(devname + strlen(SERVICE_PREFIX));
		return (sname);
	}

	/*
	 * Not a service name, check if it's a valid pathname
	 */
	if (!(devname[0] == '/' || devname[0] == '.')) {
		return (NULL);
	}

	/*
	 * Ideally, we should only check for a valid glvc pathname,
	 * requiring all vldc access to be only via service names.  But
	 * to prevent a flag day with code that's already passing in
	 * vldc full pathnames (e.g. sunMC), we allow them here.
	 */
	if (get_vldc_svc_name(devname, NULL, &vldc_path) == true) {
		return (vldc_path);
	} else if (get_glvc_svc_name(devname, NULL, &glvc_path) == true) {
		return (glvc_path);
	}

	return (NULL);
}

/*
 * Walk all "service" device nodes to find the one with the
 * matching glvc minor name
 */
static char *
svc_name_to_glvc_dev_path(char *service)
{
	di_node_t root_node, service_node;
	char *glvc_path;
	char *minor_name;
	di_minor_t minor;
	char *dev_path = NULL;

	if (service == NULL)
		return (NULL);

	/* Ensure that the 'glvc' driver is loaded */
	root_node = di_init_driver("glvc", DINFOCPYALL);
	if (root_node == DI_NODE_NIL) {
		return (dev_path);
	}

	service_node = di_drv_first_node("glvc", root_node);

	while (service_node != DI_NODE_NIL) {
		/* Make sure node name matches service name */
		if (strcmp(service, di_node_name(service_node)) == 0) {
			/* Walk minor nodes */
			minor = di_minor_next(service_node, DI_NODE_NIL);

			while (minor != DI_NODE_NIL) {
				glvc_path = di_devfs_minor_path(minor);
				minor_name = di_minor_name(minor);

				if (strcmp(minor_name, "glvc") == 0) {
					dev_path = malloc(strlen(glvc_path) +
					    strlen(DEVICES_DIR) + 1);
					(void) strcpy(dev_path, DEVICES_DIR);
					(void) strcat(dev_path, glvc_path);
					di_devfs_path_free(glvc_path);
					break;
				}

				di_devfs_path_free(glvc_path);
				minor = di_minor_next(service_node, minor);
			}
		}
		if (dev_path != NULL)
			break;

		service_node = di_drv_next_node(service_node);
	}

	di_fini(root_node);
	return (dev_path);
}

/*
 * Walk all vldc device nodes to find the one with the
 * matching minor name
 */
static char *
svc_name_to_vldc_dev_path(char *service)
{
	di_node_t root_node, vldc_node;
	char *vldc_path;
	char *minor_name;
	di_minor_t minor;
	char *dev_path = NULL;

	/* Ensure that the 'vldc' driver is loaded */
	root_node = di_init_driver("vldc", DINFOCPYALL);
	if (root_node == DI_NODE_NIL) {
		return (dev_path);
	}

	vldc_node = di_drv_first_node("vldc", root_node);

	while (vldc_node != DI_NODE_NIL) {
		/* Walk minor nodes */
		minor = di_minor_next(vldc_node, DI_NODE_NIL);

		while (minor != DI_NODE_NIL) {
			vldc_path = di_devfs_minor_path(minor);
			minor_name = di_minor_name(minor);

			if (strcmp(minor_name, service) == 0) {
				dev_path = malloc(strlen(vldc_path) +
				    strlen(DEVICES_DIR) + 1);
				(void) strcpy(dev_path, DEVICES_DIR);
				(void) strcat(dev_path, vldc_path);
				di_devfs_path_free(vldc_path);
				break;
			}

			di_devfs_path_free(vldc_path);
			minor = di_minor_next(vldc_node, minor);
		}
		if (dev_path != NULL)
			break;

		vldc_node = di_drv_next_node(vldc_node);
	}

	di_fini(root_node);
	return (dev_path);
}

/*
 * Given a service name or a full legacy pathname, return
 * the full pathname to the appropriate vldc or glvc device.
 */
char *
platsvc_name_to_path(char *svc_or_path, pcp_xport_t *type)
{
	char		*pathn_p;
	char		*service;

	if ((service = platsvc_extract_svc_name(svc_or_path)) == NULL)
		return (NULL);

	/*
	 * First lookup vldc nodes
	 */
	pathn_p = svc_name_to_vldc_dev_path(service);
	if (pathn_p != NULL) {
		*type = VLDC_STREAMING;
	} else {
		/*
		 * If no vldc, try to find a glvc node
		 */
		pathn_p = svc_name_to_glvc_dev_path(service);
		if (pathn_p != NULL) {
			*type = GLVC_NON_STREAM;
		}
	}

	free(service);
	return (pathn_p);
}
