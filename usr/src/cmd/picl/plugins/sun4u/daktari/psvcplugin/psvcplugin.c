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
 * Copyright 2000, 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * PICL Daktari platform plug-in to create environment tree nodes.
 */

#include	<poll.h>
#include	<picl.h>
#include	<picltree.h>
#include	<stdio.h>
#include	<time.h>
#include	<fcntl.h>
#include	<unistd.h>
#include	<stdlib.h>
#include	<libintl.h>
#include	<limits.h>
#include 	<ctype.h>
#include	<pthread.h>
#include	<errno.h>
#include	<syslog.h>
#include	<sys/types.h>
#include	<sys/systeminfo.h>
#include	<psvc_objects.h>
#include	<strings.h>

/*LINTLIBRARY*/

#define	BUFSZ	512

static psvc_opaque_t hdlp;

#define	PSVC_PLUGIN_VERSION	PICLD_PLUGIN_VERSION_1

#pragma init(psvc_psr_plugin_register)	/* place in .init section */


struct proj_prop {	/* projected property */
	picl_prophdl_t	handle;
	picl_nodehdl_t  dst_node;
	char		name[32];
};

typedef struct {
	char		name[32];
	picl_nodehdl_t	node;
} picl_psvc_t;

extern struct handle {
	uint32_t	obj_count;
	picl_psvc_t *objects;
	FILE *fp;
} psvc_hdl;

extern struct proj_prop *prop_list;
extern uint32_t proj_prop_count;

void psvc_psr_plugin_init(void);
void psvc_psr_plugin_fini(void);

picld_plugin_reg_t psvc_psr_reg = {
	PSVC_PLUGIN_VERSION,
	PICLD_PLUGIN_CRITICAL,
	"PSVC_PSR",
	psvc_psr_plugin_init,
	psvc_psr_plugin_fini
};


#define	PSVC_INIT_MSG		gettext("%s: Error in psvc_init(): %s\n")
#define	PTREE_DELETE_NODE_MSG	gettext("%s: ptree_delete_node() failed: %s\n")
#define	PTREE_GET_NODE_MSG			\
	gettext("%s: ptree_get_node_by_path() failed for %s: %s\n")
#define	INVALID_FILE_FORMAT_MSG		gettext("%s: Invalid file format\n")
#define	ID_NOT_FOUND_MSG	gettext("%s: Can't determine id of %s\n")
#define	NODE_NOT_FOUND_MSG	gettext("%s: Can't determine node of %s\n")
#define	SIZE_NOT_FOUND_MSG	gettext("%s: Couldn't determine size of %s\n")
#define	PTREE_CREATE_PROP_FAILED_MSG		\
	gettext("%s: ptree_create_prop failed, %s\n")
#define	PTREE_ADD_PROP_FAILED_MSG gettext("%s: ptree_add_prop: %s\n")
#define	FANSPEED_PROP_NOT_FOUND_MSG		\
	gettext("%s: Can't find property fan-speed\n")
#define	FANSPEED_PROP_DELETE_FAILED_MSG		\
	gettext("%s: Can't delete property fan-speed\n")

static int32_t count_records(FILE *fp, char *end, uint32_t *countp)
{
	long first_record;
	char *ret;
	char buf[BUFSZ];
	uint32_t count = 0;

	first_record = ftell(fp);

	while ((ret = fgets(buf, BUFSZ, fp)) != NULL) {
		if (strncmp(end, buf, strlen(end)) == 0)
			break;
		++count;
	}

	if (ret == NULL) {
		errno = EINVAL;
		return (-1);
	}

	fseek(fp, first_record, SEEK_SET);
	*countp = count;
	return (0);
}

/*
 * Find start of a section within the config file,
 * Returns number of records in the section.
 * FILE *fd is set to first data record within section.
 */
static int32_t
find_file_section(FILE *fd, char *start)
{
	char *ret;
	char buf[BUFSZ];
	char name[32];
	int found;

	fseek(fd, 0, SEEK_SET);
	while ((ret = fgets(buf, BUFSZ, fd)) != NULL) {
		if (strncmp(start, buf, strlen(start)) == 0)
			break;
	}

	if (ret == NULL) {
		errno = EINVAL;
		return (-1);
	}

	found = sscanf(buf, "%s", name);
	if (found != 1) {
		errno = EINVAL;
		return (-1);
	} else {
		return (0);
	}

}

static int32_t name_compare_bsearch(char *s1, picl_psvc_t *s2)
{
	return (strcmp(s1, s2->name));
}

static void init_err(char *fmt, char *arg1, char *arg2)
{
	char msg[256];

	sprintf(msg, fmt, arg1, arg2);
	syslog(LOG_ERR, msg);
}

static int
projected_lookup(picl_prophdl_t proph, struct proj_prop **dstp)
{
	int i;

	for (i = 0; i < proj_prop_count; ++i) {
		if (prop_list[i].handle == proph) {
			*dstp = &prop_list[i];
			return (PICL_SUCCESS);
		}
	}

	return (PICL_INVALIDHANDLE);
}

int
fan_speed_read(ptree_rarg_t *rarg, void *buf)
{
	struct proj_prop *dstinfo;
	int err;
	ptree_propinfo_t propinfo;
	picl_prophdl_t assoctbl;

	err = projected_lookup(rarg->proph, &dstinfo);
	if (err != PSVC_SUCCESS) {
		return (PICL_FAILURE);
	}


	/* see if there's a tach switch */
	err = ptree_get_propval_by_name(rarg->nodeh,
	    "PSVC_FAN_PRIM_SEC_SELECTOR", &assoctbl, sizeof (assoctbl));

	if (err != PICL_SUCCESS) {
		return (err);
	} else {
		char switch_state[32], temp_state[32];
		uint64_t features;
		picl_prophdl_t entry;
		picl_nodehdl_t tach_switch;
		char id[PICL_PROPNAMELEN_MAX];
		char name[PICL_PROPNAMELEN_MAX];

		err = ptree_get_next_by_row(assoctbl, &entry);
		if (err != PICL_SUCCESS) {
			return (err);
		}
		err = ptree_get_propval(entry, &tach_switch,
			sizeof (tach_switch));
		if (err != PICL_SUCCESS) {
			return (err);
		}

		err = ptree_get_propval_by_name(rarg->nodeh, PICL_PROP_NAME,
			&id, PICL_PROPNAMELEN_MAX);

		err = psvc_get_attr(hdlp, id, PSVC_FEATURES_ATTR, &features);

		if (err != PSVC_SUCCESS) {
			return (err);
		}
		if (features & PSVC_DEV_PRIMARY) {
			strlcpy(switch_state, PSVC_SWITCH_ON,
			    sizeof (switch_state));
		} else {
			strlcpy(switch_state, PSVC_SWITCH_OFF,
			    sizeof (switch_state));
		}

		pthread_mutex_lock(&fan_mutex);

		err = ptree_get_propval_by_name(tach_switch, PICL_PROP_NAME,
			&name, PICL_PROPNAMELEN_MAX);

		err = ptree_get_propval_by_name(tach_switch, "State",
			&temp_state, sizeof (temp_state));

		err = psvc_set_attr(hdlp, name, PSVC_SWITCH_STATE_ATTR,
			&switch_state);

		if (err != PSVC_SUCCESS) {
			pthread_mutex_unlock(&fan_mutex);
			return (err);
		}
		(void) poll(NULL, 0, 250);
	}


	err = ptree_get_propinfo(rarg->proph, &propinfo);

	if (err != PICL_SUCCESS) {
		pthread_mutex_unlock(&fan_mutex);
		return (err);
	}

	err = ptree_get_propval_by_name(dstinfo->dst_node,
		dstinfo->name, buf, propinfo.piclinfo.size);
	if (err != PICL_SUCCESS) {
		pthread_mutex_unlock(&fan_mutex);
		return (err);
	}

	pthread_mutex_unlock(&fan_mutex);

	return (PICL_SUCCESS);
}


/* Load projected properties */
/*
 * This Routine Searches through the projected properties section of the conf
 * file and replaces the currently set up values in the CPU and IO Fan Objects
 * Fan-Speed property to Daktari specific values
 */
static void
load_projected_properties(FILE *fp)
{
	int32_t found;
	ptree_propinfo_t propinfo;
	ptree_propinfo_t dstinfo;
	picl_prophdl_t src_prophdl, dst_prophdl;
	picl_nodehdl_t src_node, dst_node;
	int err, i;
	picl_psvc_t *srcobjp, *dstobjp;
	char src[32], dst[256];
	char src_prop[32], dst_prop[32];
	char buf[BUFSZ];
	char *funcname = "load_projected_properties";

	if (find_file_section(fp, "PROJECTED_PROPERTIES") != 0)
		return;

	if (count_records(fp, "PROJECTED_PROPERTIES_END",
		&proj_prop_count) != 0) {
		init_err(INVALID_FILE_FORMAT_MSG, funcname, 0);
		return;
	}


	for (i = 0; i < proj_prop_count; ++i) {
		fgets(buf, BUFSZ, fp);
		found = sscanf(buf, "%s %s %s %s", src, src_prop, dst,
			dst_prop);
		if (found != 4) {
			init_err(INVALID_FILE_FORMAT_MSG, funcname, 0);
			return;
		}
		if (strcmp(src_prop, "Fan-speed") != 0)
			continue;

		if ((strcmp(src, "IO_BRIDGE_PRIM_FAN") == 0) ||
			(strcmp(src, "IO_BRIDGE_SEC_FAN") == 0))
			continue;

		/* find src node */
		if (src[0] == '/') {
			/* picl node name, outside psvc subtree */
			err = ptree_get_node_by_path(src, &src_node);
			if (err != 0) {
				init_err(NODE_NOT_FOUND_MSG, funcname, src);
				return;
			}
		} else {
			srcobjp = (picl_psvc_t *)bsearch(src, psvc_hdl.objects,
				psvc_hdl.obj_count, sizeof (picl_psvc_t),
				(int (*)(const void *, const void *))
				name_compare_bsearch);
			if (srcobjp == NULL) {
				init_err(ID_NOT_FOUND_MSG, funcname, src);
				return;
			}
			src_node = srcobjp->node;
		}

		/*
		 * Get the property Handle for the property names "Fan-Speed"
		 * from the source node
		 */
		err = ptree_get_prop_by_name(src_node, "Fan-speed",
		    &src_prophdl);
		if (err != 0) {
			init_err(FANSPEED_PROP_NOT_FOUND_MSG, funcname, 0);
			return;
		}

		/*
		 * Delete the current property Handle as we are going to replace
		 * it's values
		 */
		err = ptree_delete_prop(src_prophdl);
		if (err != 0) {
			init_err(FANSPEED_PROP_DELETE_FAILED_MSG, funcname, 0);
			return;
		}

		/* destroy property created by generic plugin */
		ptree_delete_prop(prop_list[i].handle);
		ptree_destroy_prop(prop_list[i].handle);

		/* find dest node */
		if (dst[0] == '/') {
			/* picl node name, outside psvc subtree */
			err = ptree_get_node_by_path(dst, &dst_node);
			if (err != 0) {
				init_err(NODE_NOT_FOUND_MSG, funcname, dst);
				return;
			}
			prop_list[i].dst_node = dst_node;
		} else {
			dstobjp = (picl_psvc_t *)bsearch(dst, psvc_hdl.objects,
				psvc_hdl.obj_count, sizeof (picl_psvc_t),
				(int (*)(const void *, const void *))
				name_compare_bsearch);
			if (dstobjp == NULL) {
				init_err(ID_NOT_FOUND_MSG, funcname, dst);
				return;
			}
			prop_list[i].dst_node = dstobjp->node;
			dst_node = dstobjp->node;
		}

		/* determine destination property size */
		err = ptree_get_first_prop(dst_node, &dst_prophdl);
		while (err == 0) {
			err = ptree_get_propinfo(dst_prophdl, &dstinfo);
			if (err != 0)
				break;
			if (strcmp(dst_prop, dstinfo.piclinfo.name) == 0)
				break;
			err = ptree_get_next_prop(dst_prophdl, &dst_prophdl);
		}
		if (err != 0) {
			init_err(SIZE_NOT_FOUND_MSG, funcname, dst_prop);
			return;
		}

		propinfo.version = PSVC_PLUGIN_VERSION;
		propinfo.read = fan_speed_read;
		propinfo.write = 0;
		propinfo.piclinfo.type = dstinfo.piclinfo.type;
		propinfo.piclinfo.accessmode = PICL_READ | PICL_VOLATILE;
		propinfo.piclinfo.size = dstinfo.piclinfo.size;
		strcpy(propinfo.piclinfo.name, src_prop);

		err = ptree_create_prop(&propinfo, 0, &src_prophdl);
		if (err != 0) {
			init_err(PTREE_CREATE_PROP_FAILED_MSG, funcname,
				picl_strerror(err));
			return;
		}

		err = ptree_add_prop(src_node, src_prophdl);
		if (err != 0) {
			init_err(PTREE_ADD_PROP_FAILED_MSG, funcname,
				picl_strerror(err));
			return;
		}

		prop_list[i].handle = src_prophdl;
		strcpy(prop_list[i].name, dst_prop);
	}
}


void
psvc_psr_plugin_init(void)
{
	char *funcname = "psvc_psr_plugin_init";
	int32_t i;
	int err;
	boolean_t present;

	/*
	 * So the volatile read/write routines can retrieve data from
	 * psvc or picl
	 */
	err = psvc_init(&hdlp);
	if (err != 0) {
		init_err(PSVC_INIT_MSG, funcname, strerror(errno));
	}

	load_projected_properties(psvc_hdl.fp);

	/*
	 * Remove nodes whose devices aren't present from the picl tree.
	 */
	for (i = 0; i < psvc_hdl.obj_count; ++i) {
		picl_psvc_t *objp;
		uint64_t features;

		objp = &psvc_hdl.objects[i];

		err = psvc_get_attr(hdlp, objp->name, PSVC_PRESENCE_ATTR,
			&present);
		if (err != PSVC_SUCCESS)
			continue;
		err = psvc_get_attr(hdlp, objp->name, PSVC_FEATURES_ATTR,
			&features);
		if (err != PSVC_SUCCESS)
			continue;
		if ((features & (PSVC_DEV_HOTPLUG | PSVC_DEV_OPTION)) &&
			(present == PSVC_ABSENT)) {
			err = ptree_delete_node(objp->node);
			if (err != 0) {
				init_err(PTREE_DELETE_NODE_MSG, funcname,
					picl_strerror(err));
				return;
			}
		}
	}

	free(psvc_hdl.objects);

}

void
psvc_psr_plugin_fini(void)
{
	psvc_fini(hdlp);
}

void
psvc_psr_plugin_register(void)
{
	picld_plugin_register(&psvc_psr_reg);
}
