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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <meta.h>
#include <libsysevent.h>
#include <libnvpair.h>
#include <sys/sysevent/svm.h>
#include <sys/sysevent/eventdefs.h>
#include <dlfcn.h>

char *
obj2devname(uint32_t tag, set_t setno, md_dev64_t dev)
{
	char		*setname;
	char		*uname;
	char		name[MD_MAX_CTDLEN];
	mdsetname_t	*sp;
	md_error_t	status = mdnullerror;
	md_set_record	*md_sr;
	minor_t		mnum = meta_getminor(dev);
	int		rtn = 0;

	setname = NULL;
	if ((setno != MD_SET_BAD) &&
		((sp = metasetnosetname(setno, &status)) != NULL)) {
		setname = sp->setname;
	}

	name[0] = '\0';
	switch (tag) {
	case SVM_TAG_HS:
	case SVM_TAG_METADEVICE:
	case SVM_TAG_MIRROR:
	case SVM_TAG_RAID5:
	case SVM_TAG_STRIPE:
	case SVM_TAG_TRANS:
		uname = get_mdname(sp, mnum);
		if (uname == NULL)
			return (NULL);

		(void) strcpy(name, uname);
		break;
	case SVM_TAG_HSP:
		uname = get_hspname(sp, mnum);
		if (uname == NULL)
			return (NULL);

		(void) strcpy(name, uname);
		break;
	case SVM_TAG_DRIVE:
		(void) sprintf(name, "drive");
		break;
	case SVM_TAG_HOST:
		md_sr = NULL;
		if (setname != NULL) {
			md_sr = getsetbyname(setname, &status);
		}
		if ((md_sr != NULL) && (md_sr->sr_nodes[mnum] != NULL)) {
			/*
			 * Get the host data from the node array.
			 */
			rtn = snprintf(name, sizeof (name), "%s",
			    md_sr->sr_nodes[mnum]);
		}
		if ((name[0] == '\0') || (rtn >= sizeof (name))) {
			(void) sprintf(name, "host");
			rtn = 0;
		}
		break;
	case SVM_TAG_SET:
		if (setname == NULL) {
			(void) sprintf(name, "diskset");
		} else {
			rtn = snprintf(name, sizeof (name), "%s", setname);
		}
		break;
	default:
		if ((setname = get_devname(setno, dev)) != NULL) {
			rtn = snprintf(name, sizeof (name), "%s", setname);
		}
		break;
	}
	mdclrerror(&status);

	/* Check if we got any rubbish for any of the snprintf's */
	if ((name[0] == '\0') || (rtn >= sizeof (name))) {
		return (NULL);
	}

	return (strdup(name));
}

/* Sysevent subclass and mdnotify event type pairs */
struct node {
	char	*se_ev;
	evid_t	md_ev;
};

/* Table must be sorted in ascending order */
static struct node ev_table[] = {
	{ ESC_SVM_ADD,			EV_ADD },
	{ ESC_SVM_ATTACH,		EV_ATTACH },
	{ ESC_SVM_ATTACHING,		EV_ATTACHING },
	{ ESC_SVM_CHANGE,		EV_CHANGE },
	{ ESC_SVM_CREATE,		EV_CREATE },
	{ ESC_SVM_DELETE,		EV_DELETE },
	{ ESC_SVM_DETACH,		EV_DETACH },
	{ ESC_SVM_DETACHING,		EV_DETACHING },
	{ ESC_SVM_DRIVE_ADD,		EV_DRIVE_ADD },
	{ ESC_SVM_DRIVE_DELETE,		EV_DRIVE_DELETE },
	{ ESC_SVM_ENABLE,		EV_ENABLE },
	{ ESC_SVM_ERRED,		EV_ERRED },
	{ ESC_SVM_EXCHANGE,		EV_EXCHANGE },
	{ ESC_SVM_GROW,			EV_GROW },
	{ ESC_SVM_HS_CHANGED,		EV_HS_CHANGED },
	{ ESC_SVM_HS_FREED,		EV_HS_FREED },
	{ ESC_SVM_HOST_ADD,		EV_HOST_ADD },
	{ ESC_SVM_HOST_DELETE,		EV_HOST_DELETE },
	{ ESC_SVM_HOTSPARED,		EV_HOTSPARED },
	{ ESC_SVM_INIT_FAILED,		EV_INIT_FAILED },
	{ ESC_SVM_INIT_FATAL,		EV_INIT_FATAL },
	{ ESC_SVM_INIT_START,		EV_INIT_START },
	{ ESC_SVM_INIT_SUCCESS,		EV_INIT_SUCCESS },
	{ ESC_SVM_IOERR,		EV_IOERR },
	{ ESC_SVM_LASTERRED,		EV_LASTERRED },
	{ ESC_SVM_MEDIATOR_ADD,		EV_MEDIATOR_ADD },
	{ ESC_SVM_MEDIATOR_DELETE,	EV_MEDIATOR_DELETE },
	{ ESC_SVM_OFFLINE,		EV_OFFLINE },
	{ ESC_SVM_OK,			EV_OK },
	{ ESC_SVM_ONLINE,		EV_ONLINE },
	{ ESC_SVM_OPEN_FAIL,		EV_OPEN_FAIL },
	{ ESC_SVM_REGEN_DONE,		EV_REGEN_DONE },
	{ ESC_SVM_REGEN_FAILED,		EV_REGEN_FAILED },
	{ ESC_SVM_REGEN_START,		EV_REGEN_START },
	{ ESC_SVM_RELEASE,		EV_RELEASE },
	{ ESC_SVM_REMOVE,		EV_REMOVE },
	{ ESC_SVM_RENAME_DST,		EV_RENAME_DST },
	{ ESC_SVM_RENAME_SRC,		EV_RENAME_SRC },
	{ ESC_SVM_REPLACE,		EV_REPLACE },
	{ ESC_SVM_RESYNC_DONE,		EV_RESYNC_DONE },
	{ ESC_SVM_RESYNC_FAILED,	EV_RESYNC_FAILED },
	{ ESC_SVM_RESYNC_START,		EV_RESYNC_START },
	{ ESC_SVM_RESYNC_SUCCESS,	EV_RESYNC_SUCCESS },
	{ ESC_SVM_TAKEOVER,		EV_TAKEOVER }
};

static ev_obj_t md_tags[] = {
	EVO_UNSPECIFIED,
	EVO_METADEV,
	EVO_MIRROR,
	EVO_STRIPE,
	EVO_RAID5,
	EVO_TRANS,
	EVO_REPLICA,
	EVO_HSP,
	EVO_HS,
	EVO_SET,
	EVO_DRIVE,
	EVO_HOST,
	EVO_MEDIATOR
};

static int
ev_compare(const void *node1, const void *node2)
{
	return (strcmp((const char *)node1,
	    ((const struct node *)node2)->se_ev));
}

/*
 * Log mdnotify event
 */
void
do_mdnotify(char *se_subclass, uint32_t tag, set_t setno, md_dev64_t devid)
{
	evid_t		ev_type;
	ev_obj_t	md_tag;
	struct node	*node_ptr;

	/* Translate sysevent into mdnotify event */
	node_ptr = bsearch(se_subclass, ev_table, (sizeof (ev_table) /
	    sizeof (ev_table[0])), sizeof (ev_table[0]), ev_compare);

	if (node_ptr == NULL) {
		ev_type = EV_EMPTY;
	} else {
		ev_type = node_ptr->md_ev;
	}

	if (tag >= (sizeof (md_tags) / sizeof (md_tags[0]))) {
		md_tag = EVO_UNSPECIFIED;
	} else {
		md_tag = md_tags[tag];
	}

	NOTIFY_MD(md_tag, setno, devid, ev_type);
}

/*
 * External symbols from libsysevent and libnvpair which are not
 * available in static forms
 */
static void	*se_handle = NULL, *nv_handle = NULL;
static int	(*_sysevent_post_event)(char *, char *, char *, char *,
		    nvlist_t *, sysevent_id_t *) = NULL;
static int	(*_nvlist_alloc)(nvlist_t **, uint_t, int) = NULL;
static void	(*_nvlist_free)(nvlist_t *) = NULL;
static int	(*_nvlist_add_uint32)(nvlist_t *, char *, uint32_t) = NULL;
static int	(*_nvlist_add_uint64)(nvlist_t *, char *, uint64_t) = NULL;
static int	(*_nvlist_add_string)(nvlist_t *, char *, char *) = NULL;

/*
 * Load nvpair and sysevent symbols
 */
static int
load_sev_lib()
{
	/* Try to load the sysevent symbol */
	if (se_handle == NULL) {
		se_handle = dlopen("/usr/lib/libsysevent.so.1", RTLD_LAZY);
	}
	if (se_handle != NULL) {
		if ((_sysevent_post_event == NULL) &&
			(_sysevent_post_event = (int (*)(char *, char *, char *,
			    char *, nvlist_t *, sysevent_id_t *))
			    dlsym(se_handle, "sysevent_post_event")) == NULL) {
			goto out;
		}
	} else {
		return (1);
	}

	/* Try to load the nvpair symbols */
	if (nv_handle == NULL) {
		nv_handle = dlopen("/usr/lib/libnvpair.so.1", RTLD_LAZY);
	}
	if (nv_handle != NULL) {
		if ((_nvlist_alloc == NULL) &&
			(_nvlist_alloc = (int (*)(nvlist_t **, uint_t, int))
			    dlsym(nv_handle, "nvlist_alloc")) == NULL) {
			goto out;
		}
		if ((_nvlist_free == NULL) &&
			(_nvlist_free = (void (*)(nvlist_t *))dlsym(nv_handle,
			    "nvlist_free")) == NULL) {
			goto out;
		}
		if ((_nvlist_add_uint32 == NULL) &&
			(_nvlist_add_uint32 = (int (*)(nvlist_t *, char *,
			    uint32_t))dlsym(nv_handle,
			    "nvlist_add_uint32")) == NULL) {
			goto out;
		}
		if ((_nvlist_add_uint64 == NULL) &&
			(_nvlist_add_uint64 = (int (*)(nvlist_t *, char *,
			    uint64_t))dlsym(nv_handle,
			    "nvlist_add_uint64")) == NULL) {
			goto out;
		}
		if ((_nvlist_add_string == NULL) &&
			(_nvlist_add_string = (int (*)(nvlist_t *, char *,
			    char *))dlsym(nv_handle,
			    "nvlist_add_string")) == NULL) {
			goto out;
		}

		return (0);
	}

out:
	if ((se_handle != NULL) && (dlclose(se_handle) == 0)) {
		se_handle = NULL;
	}

	if ((nv_handle != NULL) && (dlclose(nv_handle) == 0)) {
		nv_handle = NULL;
	}

	_sysevent_post_event = NULL;
	_nvlist_alloc = NULL;
	_nvlist_free = NULL;
	_nvlist_add_uint32 = NULL;
	_nvlist_add_uint64 = NULL;
	_nvlist_add_string = NULL;

	return (1);
}

/*
 * Log SVM sys events
 */
void
meta_svm_sysevent(
	char		*se_class,
	char		*se_subclass,
	uint32_t	tag,
	set_t		setno,
	md_dev64_t	devid
)
{
	sysevent_id_t	eid;
	nvlist_t	*attr_list;
	int		err = 0;
	char		*devname;

	/* Raise the mdnotify event before anything else */
	do_mdnotify(se_subclass, tag, setno, devid);

	/* Just get out if the sysevent symbol can't be loaded */
	if (load_sev_lib()) {
		return;
	}

	err = (*_nvlist_alloc)(&attr_list, NV_UNIQUE_NAME, 0);

	if (err == 0) {
		/* Add the version number */
		err = (*_nvlist_add_uint32)(attr_list, SVM_VERSION_NO,
		    (uint32_t)SVM_VERSION);
		if (err != 0) {
			goto fail;
		}

		/* Add the tag attribute */
		err = (*_nvlist_add_uint32)(attr_list, SVM_TAG, (uint32_t)tag);
		if (err != 0) {
			goto fail;
		}

		/* Add the set number attribute */
		err = (*_nvlist_add_uint32)(attr_list, SVM_SET_NO,
		    (uint32_t)setno);
		if (err != 0) {
			goto fail;
		}

		/* Add the device id attribute */
		err = (*_nvlist_add_uint64)(attr_list, SVM_DEV_ID,
		    (uint64_t)devid);
		if (err != 0) {
			goto fail;
		}

		/* Add the device name attribute */
		devname = obj2devname(tag, setno, devid);
		if (devname != NULL) {
			err = (*_nvlist_add_string)(attr_list, SVM_DEV_NAME,
			    devname);
			free(devname);
		} else {
			err = (*_nvlist_add_string)(attr_list, SVM_DEV_NAME,
			    "unspecified");
		}
		if (err != 0) {
			goto fail;
		}

		/* Attempt to post event */
		(void) (*_sysevent_post_event)(se_class, se_subclass,
		    SUNW_VENDOR, EP_SVM, attr_list, &eid);

		(*_nvlist_free)(attr_list);
	}

	return;

fail:
	(*_nvlist_free)(attr_list);
}
