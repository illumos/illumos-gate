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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <assert.h>
#include <string.h>
#include <libintl.h>

#include "volume_error.h"
#include "volume_defaults.h"
#include "volume_dlist.h"
#include "volume_output.h"
#include "volume_request.h"

#include "layout_device_cache.h"
#include "layout_discovery.h"
#include "layout_dlist_util.h"
#include "layout_request.h"
#include "layout_slice.h"
#include "layout_validate.h"

#define	_LAYOUT_REQUEST_C

static char *_request_diskset = NULL;
static devconfig_t *_toplevel_request = NULL;
static defaults_t *_defaults = NULL;

/*
 * This file contains code which handles various aspects of the
 * request and defaults devconfig_t structs passed to the layout
 * module.
 *
 * Functions are provided which determine what devices are available
 * for use by the various volume layout mechanisms. These are based
 * on the user specified available/unavailable devices included in
 * a request or in the defaults associated with the destination diskset.
 */

/*
 * A struct to hold device "specifications" extracted from a user
 * specified device name.  This struct is used to compare the user's
 * available and unavailable device specifications against physical
 * devices attached to the system.
 *
 * The spec struct holds one of two different specifications: if the
 * user supplied device name is parsable as a CTD name, it is parsed
 * into the component ids.  Otherwise, it is stored as is.
 *
 * The CTD name space implies a device hierarchy and metassist
 * supports an implied wildcarding scheme for the CTD name space.
 * A CTD specification from the user is of the form cX, cXdX,
 * cXdXsX, cXtX, cXtXdX, or cXtXdXsX, so it may or may nor
 * correspond to an individual physical device depending on
 * the context.
 *
 * For example, "c1" can mean the controller/HBA with the
 * name "c1" or it can mean all devices attached to the
 * controller named "c1".
 *
 * The ctd specs make matching physical devices against a
 * user specification easier since the matching is based on
 * the numeric values extracted from the cXtXdXsX string
 * and not on the strings themselves.  The strings are
 * troublesome because of situations like "c1" being
 * compared to "c11t1d0s0" and getting false matches.
 *
 * The ID_UNSPECIFIED value is used to flag components
 * that were not in the CTD name:
 *
 * "c3" -> { ctrl=3, target=ID_UNSPECIFIED,
 *		lun=ID_UNSPECIFIED, slice=ID_UNSPECIFIED }
 *
 * "c3t2" -> { ctrl=3, target=2,
 *		lun=ID_UNSPECIFIED, slice=ID_UNSPECIFIED }
 */

#define	ID_UNSPECIFIED	-1
typedef struct {
	int	ctrl;
	int	target;
	int	lun;
	int	slice;
	boolean_t is_ide;
} ctd_spec_t;

typedef enum {
	SPEC_TYPE_CTD = 0,
	SPEC_TYPE_RAW,
	SPEC_TYPE_OTHER
} spec_type_t;

typedef struct {
	spec_type_t type;
	union {
		ctd_spec_t *ctd;
		char	*raw;
	} data;
} device_spec_t;

static int get_spec_for_name(
	char	*name,
	device_spec_t **id);

static int create_device_spec(
	char	*name,
	device_spec_t **spec);

static int create_device_ctd_spec(
	char	*name,
	device_spec_t **spec);

static int create_device_raw_spec(
	char	*name,
	device_spec_t **spec);

static void destroy_device_spec(
	device_spec_t *spec);

static boolean_t ctd_spec_includes_device(
	device_spec_t *spec,
	device_spec_t *device);

static boolean_t raw_spec_includes_device(
	device_spec_t *spec,
	device_spec_t *device);

/*
 * get_spec_for_name builds up a cached mapping of device
 * names to the corresponding device_spec_t structs.
 *
 * This saves repeatedly converting the device names, which
 * could get expensive since devices are checked against the
 * user specified available/unavailable devices a lot.
 *
 * The cache is implemented as a list of these structs:
 */
typedef struct {

	char		*name;
	device_spec_t	*device_spec;

} spec_cache_t;

static dlist_t	*_spec_cache = NULL;

static int destroy_spec_cache();
static int compare_name_to_spec_cache_name(
	void *name, void *list_item);

/*
 * The user specified available/unavailable devices are
 * accessed frequently during layout. To make this more
 * efficient, the char *arrays of available/unavailable
 * specifications for a request or defaults devconfig_t
 * object are converted to device_spec_ts the first time
 * they're accessed and then cached using this struct:
 */
typedef struct {

	devconfig_t	*request;

	/*
	 * avail_specs_list is a list of device spec_t
	 * corresponding to available devices specified
	 * in the request object
	 */
	dlist_t *avail_specs_list;

	/*
	 * unavail_specs_list is a list of device spec_t
	 * corresponding to unavailable devices specified
	 * in the request object
	 */
	dlist_t *unavail_specs_list;

} request_spec_list_t;

dlist_t *_request_spec_list_cache = NULL;

static int destroy_request_spec_list_cache();
static void destroy_request_spec_list_entry(void *obj);

static int compare_request_to_request_spec_list_request(
	void *object,
	void *list_item);

static int convert_usernames_to_specs(
	char **specs,
	dlist_t **list);

/* other private functions */
static int is_device_avail(
	dm_descriptor_t	desc,
	devconfig_t	*request,
	boolean_t	*avail);

static int is_named_device_avail(
	devconfig_t	*request,
	char		*device_name,
	boolean_t	check_aliases,
	boolean_t	*avail);

static int avail_list_includes_device_name(
	dlist_t		*list,
	char		*device_name,
	boolean_t	check_aliases,
	boolean_t	*includes);

static int unavail_list_includes_device_name(
	dlist_t		*list,
	char		*device_name,
	boolean_t	check_aliases,
	boolean_t	*includes);

static int spec_includes_device_name(
	device_spec_t *spec,
	char		 *device_name,
	boolean_t	check_aliases,
	boolean_t	*includes);

static boolean_t spec_includes_device(
	device_spec_t *spec,
	device_spec_t *device);

static int disk_get_avail_space(
	devconfig_t	*request,
	dm_descriptor_t disk,
	uint64_t	*avail);

static int compare_hba_n_avail_disks(
	void		*obj1,
	void		*obj2);

/*
 * FUNCTION:	release_request_caches()
 *
 * RETURNS:	0
 *
 * PURPOSE:	cleanup the module private caches.
 */
int
release_request_caches()
{
	(void) destroy_request_spec_list_cache();
	(void) destroy_spec_cache();

	return (0);
}
/*
 * FUNCTION:	int set_request_diskset(char *)
 *
 * INPUT:	char * - pointer to the diskset name
 * OUTPUT:	0 - success
 *		!0 - validation failure
 * RETURNS:
 *
 * PURPOSE:	set the module global diskset name.
 */
int
set_request_diskset(
	char	*dsname)
{
	_request_diskset = dsname;

	if (dsname == NULL || dsname[0] == '\0') {
	    volume_set_error(
		    gettext("No disk set specified in request\n"));
	    return (-1);
	}

	return (0);
}

/*
 * FUNCTION:	char *get_request_diskset()
 *
 * INPUT:	none   -
 * OUTPUT:	none   -
 * RETURNS:	char * - pointer to the currently set diskset name
 *
 * PURPOSE:	get the global name of the current diskset.
 */
char *
get_request_diskset()
{
	return (_request_diskset);
}

/*
 * FUNCTION:	void unset_request_diskset()
 *
 * PURPOSE:	unset the module global diskset name.
 */
void
unset_request_diskset(
	char	*dsname)
{
	_request_diskset = NULL;
}

/*
 * FUNCTION:	int set_toplevel_request(devconfig_t *)
 *
 * INPUT:	devconfig_t * - pointer to the diskset request
 * OUTPUT:	0 - success
 *		!0 - validation failure
 * RETURNS:
 *
 * PURPOSE:	set the module global toplevel request struct.
 *		this will be set within the only public entry
 *		point to the module -- get_layout()
 *
 * SIDEEFFECT:	The devconfig_t's list of available and unavailable
 * 		devices will be validated.
 */
int
set_toplevel_request(
	devconfig_t	*req)
{
	_toplevel_request = req;

	return (validate_request_avail_unavail(req));
}

/*
 * FUNCTION:	void unset_toplevel_request()
 *
 * PURPOSE:	unset the layout module global toplevel request struct.
 *
 */
void
unset_toplevel_request()
{
	_toplevel_request = NULL;
}

/*
 * FUNCTION:	int set_defaults(devconfig_t *)
 *
 * INPUT:	devconfig_t * - pointer to the global defaults devconfig_t
 * OUTPUT:	0 - success
 *		!0 - validation failure
 * RETURNS:
 *
 * PURPOSE:	set the module global defaults struct.
 *		this will be set within the only public entry
 *		point to the module -- get_layout()
 *
 * SIDEEFFECT:	The devconfig_t's list of available and unavailable
 * 		devices will be validated.
 */
int
set_request_defaults(
	defaults_t *defaults)
{
	int	error = 0;
	devconfig_t *diskset = NULL;

	_defaults = defaults;

	if ((error = defaults_get_diskset_by_name(
	    _defaults, get_request_diskset(), &diskset)) == 0) {

	    error = validate_request_avail_unavail(diskset);

	} else if (error == ENOENT) {
	    /* no defaults to verify */
	    error = 0;
	}

	return (error);
}

/*
 * FUNCTION:	void unset_request_defaults()
 *
 * PURPOSE:	unset the layout module global defaults struct.
 *
 */
void
unset_request_defaults()
{
	_defaults = NULL;
}

/*
 * FUNCTION:	get_stripe_min_comp(devconfig_t *req, uint16_t *val)
 * INPUT:	req	- a devconfig_t pointer to the current request
 *		val	- pointer to a uint64_t to hold the result
 *
 * RETURNS:	int	-  0 - on success
 *			  !0 - otherwise
 *
 * PURPOSE:	helper which determines the minimum of components
 *		for striped volumes satisfying the input request.
 *
 *		The value to use is taken from the input request, the
 *		toplevel diskset request, the diskset defaults or the
 *		global defaults.
 */
int
get_stripe_min_comp(
	devconfig_t	*req,
	uint16_t	*val)
{
	int		error = 0;

	*val = 0;

	if ((error = devconfig_get_stripe_mincomp(req, val)) != 0) {
	    if (error != ERR_ATTR_UNSET) {
		return (error);
	    }
	}

	if (*val == 0) {
	    if ((error = defaults_get_stripe_mincomp(
		_defaults, get_request_diskset(), val)) != 0) {
		if (error != ERR_ATTR_UNSET) {
		    return (error);
		}
	    }
	}

	return (error);
}

/*
 * FUNCTION:	get_stripe_max_comp(devconfig_t *req, uint16_t *val)
 * INPUT:	req	- a devconfig_t pointer to the current request
 *		val	- pointer to a uint64_t to hold the result
 *
 * RETURNS:	int	-  0 - on success
 *			  !0 - otherwise
 *
 * PURPOSE:	helper which determines the maximum number of components
 *		for striped volumes satisfying the input request.
 *
 *		The value to use is taken from the input request, the
 *		toplevel diskset request, the diskset defaults or the
 *		global defaults.
 */
int
get_stripe_max_comp(
	devconfig_t	*req,
	uint16_t	*val)
{
	int		error = 0;

	*val = 0;

	if ((error = devconfig_get_stripe_maxcomp(req, val)) != 0) {
	    if (error != ERR_ATTR_UNSET) {
		return (error);
	    }
	}

	if (*val == 0) {
	    if ((error = defaults_get_stripe_maxcomp(
		_defaults, get_request_diskset(), val)) != 0) {
		if (error != ERR_ATTR_UNSET) {
		    return (error);
		}
	    }
	}

	return (error);
}

/*
 * FUNCTION:	get_stripe_interlace(devconfig_t *req, uint64_t *val)
 * INPUT:	req	- a devconfig_t pointer to the current request
 *		val	- pointer to a uint64_t to hold the result
 *
 * RETURNS:	int	-  0 - on success
 *			  !0 - otherwise
 *
 * PURPOSE:	helper which determines the interlace value for striped
 *		volumes satisfying the input request.
 *
 *		The value to use is taken from the input request, the
 *		toplevel diskset request, the diskset defaults or the
 *		global defaults.
 *
 *		If no value is explictly specified, ERR_ATTR_UNSET is
 *		returned.
 */
int
get_stripe_interlace(
	devconfig_t	*req,
	uint64_t	*val)
{
	int		error = 0;

	*val = 0;

	if ((error = devconfig_get_stripe_interlace(req, val)) != 0) {
	    if (error != ERR_ATTR_UNSET) {
		return (error);
	    }
	    error = 0;
	}

	if (*val == 0) {
	    if ((error = defaults_get_stripe_interlace(
		_defaults, get_request_diskset(), val)) != 0) {
		if (error != ERR_ATTR_UNSET) {
		    return (error);
		}
	    }
	}

	return (error);
}

/*
 * FUNCTION:	get_mirror_read_strategy(devconfig_t *req,
 *			mirror_read_strategy_t *val)
 * INPUT:	req	- a devconfig_t pointer to the current request
 *		val	- pointer to a mirror_read_strategy_t to hold the result
 *
 * RETURNS:	int	-  0 - on success
 *			  !0 - otherwise
 *
 * PURPOSE:	helper which determines the write strategy mirrored volumes
 *		should have for volumes satisfying the input request.
 *
 *		The value to use is taken from the input request, the
 *		toplevel diskset request, the diskset defaults or the
 *		global defaults.
 *
 *		If no value is explictly specified, ERR_ATTR_UNSET is
 *		returned.
 */
int
get_mirror_read_strategy(
	devconfig_t	*req,
	mirror_read_strategy_t	*val)
{
	int		error = 0;

	*val = 0;

	if ((error = devconfig_get_mirror_read(req, val)) != 0) {
	    if (error != ERR_ATTR_UNSET) {
		return (error);
	    }
	}

	if (*val == 0) {
	    if ((error = defaults_get_mirror_read(
		_defaults, get_request_diskset(), val)) != 0) {
		if (error != ERR_ATTR_UNSET) {
		    return (error);
		}
	    }
	}

	return (error);
}

/*
 * FUNCTION:	get_mirror_write_strategy(devconfig_t *req,
 *			mirror_write_strategy_t *val)
 * INPUT:	req	- a devconfig_t pointer to the current request
 *		val	- pointer to a mirror_write_strategy_t to hold result
 *
 * RETURNS:	int	-  0 - on success
 *			  !0 - otherwise
 *
 * PURPOSE:	helper which determines the write strategy mirrored volumes
 *		should have for volumes satisfying the input request.
 *
 *		The value to use is taken from the input request, the
 *		toplevel diskset request, the diskset defaults or the
 *		global defaults.
 *
 *		If no value is explictly specified, ERR_ATTR_UNSET is
 *		returned.
 */
int
get_mirror_write_strategy(
	devconfig_t	*req,
	mirror_write_strategy_t	*val)
{
	int		error = 0;

	*val = 0;

	if ((error = devconfig_get_mirror_write(req, val)) != 0) {
	    if (error != ERR_ATTR_UNSET) {
		return (error);
	    }
	}

	if (*val == 0) {
	    if ((error = defaults_get_mirror_write(
		_defaults, get_request_diskset(), val)) != 0) {
		if (error != ERR_ATTR_UNSET) {
		    return (error);
		}
	    }
	}

	return (error);
}

/*
 * FUNCTION:	get_mirror_pass(devconfig_t *req, uint16_t *val)
 * INPUT:	req	- a devconfig_t pointer to the current request
 *		val	- pointer to a uint16_t to hold the result
 *
 * RETURNS:	int	-  0 - on success
 *			  !0 - otherwise
 *
 * PURPOSE:	helper which determines the resync pass mirrored volumes
 *		should have for volumes satisfying the input request.
 *
 *		The value to use is taken from the input request, the
 *		toplevel diskset request, the diskset defaults or the
 *		global defaults.
 *
 *		If no value is explictly specified, ERR_ATTR_UNSET is
 *		returned.
 */
int
get_mirror_pass(
	devconfig_t	*req,
	uint16_t	*val)
{
	int		error = 0;

	*val = 0;

	if ((error = devconfig_get_mirror_pass(req, val)) != 0) {
	    if (error != ERR_ATTR_UNSET) {
		return (error);
	    }
	}

	if (*val == 0) {
	    if ((error = defaults_get_mirror_pass(
		_defaults, get_request_diskset(), val)) != 0) {
		if (error != ERR_ATTR_UNSET) {
		    return (error);
		}
	    }
	}

	return (error);
}

/*
 * FUNCTION:	get_mirror_nsubs(devconfig_t *req, uint16_t *val)
 * INPUT:	req	- a devconfig_t pointer to the current request
 *		val	- pointer to a uint16_t to hold the result
 *
 * RETURNS:	int	-  0 - on success
 *			  !0 - otherwise
 *
 * PURPOSE:	helper which determines how many submirrors mirrored
 *		volumes should have for volumes satisfying the input
 *		request.
 *
 *		The value to use is taken from the input request, the
 *		toplevel diskset request, the diskset defaults or the
 *		global defaults.
 */
int
get_mirror_nsubs(
	devconfig_t	*req,
	uint16_t	*val)
{
	int		error = 0;

	*val = 0;

	if ((error = devconfig_get_mirror_nsubs(req, val)) != 0) {
	    if (error != ERR_ATTR_UNSET) {
		return (error);
	    }
	}

	if (*val == 0) {
	    if ((error = defaults_get_mirror_nsubs(
		_defaults, get_request_diskset(), val)) != 0) {
		if (error != ERR_ATTR_UNSET) {
		    return (error);
		}
	    }
	}

	return (error);
}

/*
 * FUNCTION:	get_volume_faultrecov(devconfig_t *req, boolean_t *val)
 * INPUT:	req	- a devconfig_t pointer to the current request
 *		val	- pointer to a boolean_t to hold the result
 *
 * RETURNS:	int	-  0 - on success
 *			  !0 - otherwise
 *
 * PURPOSE:	helper which determines whether data redundant volumes
 *		should also have fault recovery (e.g., HSPs) for volumes
 *		satisfying the input request.
 *
 *		The value to use is taken from the input request, the
 *		toplevel diskset request, the diskset defaults or the
 *		global defaults.
 */
int
get_volume_faultrecov(
	devconfig_t	*req,
	boolean_t	*val)
{
	int		error = 0;

	*val = B_FALSE;

	if ((error = devconfig_get_volume_usehsp(req, val)) != 0) {
	    if (error == ERR_ATTR_UNSET) {
		component_type_t	type = TYPE_UNKNOWN;
		(void) devconfig_get_type(req, &type);

		switch (type) {
		case TYPE_MIRROR:
		    error = defaults_get_mirror_usehsp(
			    _defaults, get_request_diskset(), val);
		    break;

		case TYPE_STRIPE:
		    error = defaults_get_stripe_usehsp(
			    _defaults, get_request_diskset(), val);
		    break;

		case TYPE_CONCAT:
		    error = defaults_get_concat_usehsp(
			    _defaults, get_request_diskset(), val);
		    break;

		case TYPE_VOLUME:
		    error = defaults_get_volume_usehsp(
			    _defaults, get_request_diskset(), val);
		    break;
		}
	    }
	}

	return (error);
}

/*
 * FUNCTION:	get_volume_redundancy_level(devconfig_t *req, uint16_t val)
 * INPUT:	req	- a devconfig_t pointer to the current request
 *		val	- pointer to a uint16-t to hold the result
 *
 * RETURNS:	int	-  0 - on success
 *			  !0 - otherwise
 *
 * PURPOSE:	helper which determines the appropriate level of data
 *		redundancy a volume should have for volumes satisfying
 *		the input request.
 *
 *		The value to use is taken from the input request, the
 *		toplevel diskset request, the diskset defaults or the
 *		global defaults.
 */
int
get_volume_redundancy_level(
	devconfig_t	*req,
	uint16_t	*val)
{
	int		error = 0;

	*val = 0;

	if ((error = devconfig_get_volume_redundancy_level(req, val)) != 0) {
	    if (error != ERR_ATTR_UNSET) {
		return (error);
	    }
	}

	if (*val == 0) {
	    if ((error = defaults_get_volume_redundancy_level(
		_defaults, get_request_diskset(), val)) != 0) {
		if (error != ERR_ATTR_UNSET) {
		    return (error);
		}
	    }
	}

	return (error);
}

/*
 * FUNCTION:	get_volume_npaths(devconfig_t *req, uint16_t val)
 * INPUT:	req	- a devconfig_t pointer to the current request
 *		val	- pointer to a uint16-t to hold the result
 *
 * RETURNS:	int	-  0 - on success
 *			  !0 - otherwise
 *
 * PURPOSE:	helper which determines the appropriate level of datapath
 *		redundancy a slice component should have for volumes
 *		satisfying the input request.
 *
 *		The value to use is taken from the input request, the
 *		toplevel diskset request, the diskset defaults or the
 *		global defaults.
 */
int
get_volume_npaths(
	devconfig_t	*req,
	uint16_t	*val)
{
	int		error = 0;

	*val = 0;

	if ((error = devconfig_get_volume_npaths(req, val)) != 0) {
	    if (error != ERR_ATTR_UNSET) {
		return (error);
	    }
	}

	if (*val == 0) {
	    if ((error = defaults_get_volume_npaths(
		_defaults, get_request_diskset(), val)) != 0) {
		if (error != ERR_ATTR_UNSET) {
		    return (error);
		}
	    }
	}

	return (error);
}

/*
 * FUNCTION:	get_default_hsp_name(devconfig_t *req, char **hspname)
 * INPUT:	req	- a devconfig_t pointer to the current request
 *		hspname	- pointer to a char * to hold the result, if any
 *
 * RETURNS:	int	-  0 - on success
 *			  !0 - otherwise
 *
 * PURPOSE:	helper which determines the default HSP name for the
 *		input request.
 *
 *		The value to use is taken from the input request, the
 *		toplevel diskset request, the diskset defaults or the
 *		global defaults.
 */
int
get_default_hsp_name(
	devconfig_t	*req,
	char		**name)
{
	int		error = 0;

	*name = NULL;

	if ((error = defaults_get_hsp_name(_defaults,
	    get_request_diskset(), name)) != 0) {
	    if (error != ENOENT) {
		return (error);
	    }
	    error = 0;
	}

	return (error);
}

/*
 * FUNCTION:	slice_is_available(char *sname, devconfig_t *request,
 *			boolean_t bool)
 * INPUT:	sname	- a slice name
 *		request	- pointer to a devconfig_t struct representing
 *				the current layout request being processed
 * 		bool	- pointer to a boolean to hold the result
 *
 * RETURNS:	int	-  0 - on success
 *			  !0 - otherwise
 *
 * PURPOSE:	Validation helper which determines if the named slice can
 *		be used as a volume component when satisfying the input
 *		request.
 *
 *		Check if the slice appears in the known slice list,
 *		then check the request's available and unavailable
 *		device specifications.
 */
int
slice_is_available(
	char		*sname,
	devconfig_t	*request,
	boolean_t	*bool)
{
	dm_descriptor_t	slice = (dm_descriptor_t)0;
	int		error = 0;

	*bool = B_FALSE;

	if ((error = slice_get_by_name(sname, &slice)) != 0) {
	    return (error);
	}

	if (slice == (dm_descriptor_t)0) {
	    /* no slice found */
	    return (ENODEV);
	}

	if (error == 0) {
	    error = is_named_device_avail(request, sname, B_TRUE, bool);
	}

	return (error);
}

/*
 * FUNCTION:	get_disks_for_target(char *name, dlist_t **disks)
 *
 * INPUT:	name	- a char* device CTD name
 *
 * OUTPUT:	disks	- disks matching the input target name
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Validation helper function which finds all disks "on" the
 *		input target.
 *
 *		The input name is assumed to be a target name, cXtX, and
 *		the list of known disks is searched to find any disk that
 *		looks to be "on" that target.
 *
 *		"On" is determined by comparing a disk's name and
 *		aliases to the target to see if they match.
 */
int
get_disks_for_target(
	char *name,
	dlist_t **disks)
{
	int error = 0;
	device_spec_t *targetid = NULL;

	error = get_spec_for_name(name, &targetid);
	if (error == 0) {
	    dlist_t *known_disks = NULL;
	    dlist_t *iter = NULL;

	    get_known_disks(&known_disks);
	    for (iter = known_disks;
		(iter != NULL) && (error == 0);
		iter = iter->next) {

		dm_descriptor_t disk = (uintptr_t)iter->obj;
		device_spec_t *diskid = NULL;
		char	*diskname = NULL;
		dlist_t *diskaliases = NULL;
		dlist_t *item;

		((error = get_display_name(disk, &diskname)) != 0) ||
		(error = get_aliases(disk, &diskaliases)) ||
		(error = get_spec_for_name(diskname, &diskid));

		if (error == 0) {
		    if (spec_includes_device(targetid, diskid) == B_TRUE) {
			/* add disk */
			if ((item = dlist_new_item((void *)(uintptr_t)disk)) ==
			    NULL) {
			    error = ENOMEM;
			} else {
			    *disks = dlist_append(item, *disks, AT_HEAD);
			}
		    } else {
			/* check disk's aliases */
			dlist_t *iter2;
			for (iter2 = diskaliases;
			    (iter2 != NULL) && (error == 0);
			    iter2 = iter2->next) {

			    char *aliasname = NULL;
			    device_spec_t *aliasid = NULL;
			    error = get_display_name(disk, &aliasname);
			    error = get_spec_for_name(aliasname, &aliasid);

			    if (spec_includes_device(
					targetid, aliasid) == B_TRUE) {

				/* alias matched, add disk */
				item = dlist_new_item((void *)(uintptr_t)disk);
				if (item == NULL) {
				    error = ENOMEM;
				} else {
				    *disks =
					dlist_append(item, *disks, AT_HEAD);
				}
			    }
			}
		    }
		}
	    }
	}

	return (error);
}

/*
 * FUNCTION:	select_hbas_with_n_disks(devconfig_t *request,
 *			dlist_t	*hbas, int mindisks, dlist_t **selhbas,
 *			dlist_t **seldisks)
 *
 * INPUT:	request	- pointer to a devconfig_t struct representing
 *				the current layout request being processed
 * 		hbas	- pointer to a list of HBAs
 *		mindisks - minimum number of disks required on the HBAs
 *
 * OUTPUT:	selhbas	- pointer to a list containing the HBAs with at
 *				least mindisks available disks.
 *		seldisks - pointer to a list containing the available disks
 *				for the HBAs in selhbas
 *
 * RETURNS:	int	-  0 - on success
 *			  !0 - otherwise
 *
 * PURPOSE:	helper which counts the number of available disks associated
 *		with each of the input HBAs and adds those that have at
 *		least mindisks to the output list.
 *
 *		Only available disks that have available space are counted.
 *
 *		Disks connected thru multiple HBAs are only counted for
 *		the first HBA they're accessed through.
 *
 *		The list of HBAs returned will be in descending order,
 *		i.e., HBAs with more disks come before those with fewer.
 *
 *		The returned lists of HBAs and disks must be passed to
 *		dlist_free_items() to recover the space allocated to hold
 *		each list item.
 *
 *		for (each HBA) {
 *
 *		    select HBA
 *		    get available disks on HBA
 *
 *		    for (each disk) {
 *			if (disk is not in selected disk list)
 *			    add it to the list
 *			else
 *			    count it as a distinct disk on this HBA
 *		    }
 *
 *		    if (this HBA has >= mindisks distinct disks)
 *			add this HBA to the list of returned HBAs
 *
 *		}
 */
int
select_hbas_with_n_disks(
	devconfig_t	*request,
	dlist_t		*hbas,
	int		mindisks,
	dlist_t		**selhbas,
	dlist_t		**seldisks)
{
	dlist_t		*iter = NULL;
	int		error = 0;

	*selhbas = NULL;
	*seldisks = NULL;

	/* for each input HBA */
	for (iter = hbas; (error == 0) && (iter != NULL); iter = iter->next) {

	    dm_descriptor_t hba = (uintptr_t)iter->obj;
	    dlist_t *iter2 = NULL;
	    dlist_t *disks = NULL;
	    uint64_t space = 0;
	    uint16_t ndistinct = 0;

	    error = hba_get_avail_disks_and_space(request, hba, &disks, &space);

	    /* for each of this HBA's disks */
	    for (iter2 = disks;
		(iter2 != NULL) && (error == 0);
		iter2 = iter2->next) {

		dm_descriptor_t disk = (uintptr_t)iter2->obj;

		/* unique disk? has it been seen thru some other HBA? */
		if (dlist_contains(*seldisks, (void *)(uintptr_t)disk,
		    compare_descriptor_names) != B_TRUE) {

		    /* distinct, add to list of all_distinct */
		    dlist_t *item = dlist_new_item((void *)(uintptr_t)disk);
		    if (item == NULL) {
			error = ENOMEM;
		    } else {

			*seldisks =
			    dlist_append(item, *seldisks, AT_HEAD);

			/* increment this HBA's distinct disk count */
			++ndistinct;
		    }
		}
	    }

	    if (ndistinct >= mindisks) {

		/* this HBA has minimum # of disks, add to output list */
		dlist_t	*item = dlist_new_item((void *)(uintptr_t)hba);
		if (item == NULL) {
		    error = ENOMEM;
		} else {
		    *selhbas =
			dlist_insert_ordered(
				item, *selhbas, DESCENDING,
				compare_hba_n_avail_disks);

		    /* save # of disks for ordering the list */
		    hba_set_n_avail_disks(hba, ndistinct);
		}
	    }

	    dlist_free_items(disks, NULL);
	}

	if (error != 0) {
	    oprintf(OUTPUT_TERSE,
		    gettext("failed selecting HBAs with n disks: %d\n"),
		    error);

	    dlist_free_items(*selhbas, NULL);
	    *selhbas = NULL;
	    dlist_free_items(*seldisks, NULL);
	    *seldisks = NULL;
	}

	return (error);
}

/*
 * FUNCTION:	hba_get_avail_disks_and_space(devconfig_t *request,
 *			dm_descriptor_t hba, dlist_t **disks, uint64_t *space)
 *
 * INPUT:	request	- pointer to a devconfig_t struct representing
 *				the current layout request being processed
 * 		hba	- dm_descriptor_t handle for an HBA
 *
 * OUTPUT:	disks	- pointer to a list to hold the computed available
 *				disks
 * 		avail	- pointer to a uint64_t to hold the aggregate
 *				available space on the available disks
 *
 * RETURNS:	int	-  0 - on success
 *			  !0 - otherwise
 *
 * PURPOSE:	helper which examines the disks associated with the
 *		input HBA and assembles a list of those that are available.
 *
 *		Available is defined as being in the usable list, having
 *		unused space and not specifically excluded by the request's
 *		list of unavailable devices.
 *
 *		The returned list must be passed to dlist_free_items()
 *		to recover the memory allocated to hold each list item.
 */
int
hba_get_avail_disks_and_space(
	devconfig_t	*request,
	dm_descriptor_t	hba,
	dlist_t		**disks,
	uint64_t	*space)
{
	dlist_t		*usable_disks = NULL;
	dlist_t		*iter = NULL;
	int		error = 0;

	*disks = NULL;

	/* for each usable disk */
	error = get_usable_disks(&usable_disks);
	for (iter = usable_disks;
	    (error == 0) && (iter != NULL);
	    iter = iter->next) {

	    dm_descriptor_t disk = (uintptr_t)iter->obj;
	    boolean_t	avail = B_FALSE;
	    dlist_t	*hbas = NULL;

	    /* is disk attached to HBA in question? */
	    error = disk_get_hbas(disk, &hbas);
	    if (error != 0) {
		continue;
	    }

	    if (dlist_contains(hbas, (void *)(uintptr_t)hba,
			compare_descriptor_names) == B_TRUE) {

		/* is disk available? */
		error = is_device_avail(disk, request, &avail);
		if ((error == 0) && (avail == B_TRUE)) {
		    uint64_t disk_space = 0;

		    /* does disk have available space? */
		    error = disk_get_avail_space(request, disk, &disk_space);
		    if ((error == 0) && (disk_space > 0)) {

			dlist_t *item = dlist_new_item((void *)(uintptr_t)disk);
			if (item == NULL) {
			    error = ENOMEM;
			} else {
			    *disks = dlist_append(item, *disks, AT_HEAD);
			}

			*space += disk_space;
		    }
		}
	    }

	    dlist_free_items(hbas, NULL);
	}

	if (error != 0) {
	    dlist_free_items(*disks, NULL);
	    *disks = NULL;
	}

	return (error);
}

/*
 * FUNCTION:	disk_get_avail_space(devconfig_t *request,
 *			dlist_t *disks, uint64_t space)
 *
 * INPUT:	request	- pointer to a devconfig_t struct representing
 *				the current layout request being processed
 * 		disks	- pointer to a list of disks
 * 		space	- pointer to a uint64_t to hold the computed available
 *				space
 *
 * RETURNS:	int	-  0 - on success
 *			  !0 - otherwise
 *
 * PURPOSE:	helper which iterates the input list of disks and determines
 *		the aggregate amount of available space they represent.
 *
 *		Only disk slices that are in the usable slice list and not
 *		specifically excluded by the request's list of unavailable
 *		devices	will contribute to the aggregate space computation.
 */
static int
disk_get_avail_space(
	devconfig_t	*request,
	dm_descriptor_t	disk,
	uint64_t	*space)
{
	dlist_t		*usable_slices = NULL;
	dlist_t		*iter = NULL;
	int		error = 0;

	*space = 0;

	/* for each usable slice */
	error = get_usable_slices(&usable_slices);
	for (iter = usable_slices;
	    (error == 0) && (iter != NULL);
	    iter = iter->next) {

	    dm_descriptor_t slice = (uintptr_t)iter->obj;
	    dm_descriptor_t slice_disk;
	    boolean_t	avail = B_FALSE;
	    boolean_t	reserved = B_FALSE;
	    boolean_t	used = B_FALSE;

	    /* is slice on disk in question? */
	    if (((error = slice_get_disk(slice, &slice_disk)) != 0) ||
		(compare_descriptor_names((void *)(uintptr_t)slice_disk,
			(void *)(uintptr_t)disk) != 0)) {
		continue;
	    }

	    /* is slice reserved by an explicit layout request? */
	    if (((error = is_reserved_slice(slice, &reserved)) != 0) ||
		(reserved == B_TRUE)) {
		continue;
	    }

	    /* is slice used by a pending layout request? */
	    if (((error = is_used_slice(slice, &used)) != 0) ||
		(used == B_TRUE)) {
		continue;
	    }

	    /* is slice available? */
	    if (((error = is_device_avail(slice, request, &avail)) == 0) &&
		(avail == B_TRUE)) {

		/* does slice have usable space? */
		uint64_t size = 0;
		if ((error = slice_get_size(slice, &size)) == 0) {
		    *space += size;
		}
	    }
	}

	return (error);
}

/*
 * FUNCTION:	disks_get_avail_slices(devconfig_t *request,
 *			dlist_t *disks, dlist_t **slices)
 *
 * INPUT:	request	- pointer to a devconfig_t struct representing
 *				the current layout request being processed
 * 		disks	- pointer to a list of disks
 * 		slices	- pointer to an output list of disks
 *
 * RETURNS:	int	-  0 - on success
 *			  !0 - otherwise
 *
 * PURPOSE:	helper which iterates the input list of disks and builds a
 *		new list which contains disks that are determined to be
 * 		available for satisfying the input request.
 *
 *		A disk must contain at least one slice in the available
 * 		slice list as well as have available space in order
 *		to be available.
 */
int
disks_get_avail_slices(
	devconfig_t	*request,
	dlist_t		*disks,
	dlist_t		**slices)
{
	dlist_t		*usable_slices = NULL;
	dlist_t		*iter = NULL;
	int		error = 0;

	*slices = NULL;

	/* for each usable slice */
	error = get_usable_slices(&usable_slices);
	for (iter = usable_slices;
	    (error == 0) && (iter != NULL);
	    iter = iter->next) {

	    dm_descriptor_t slice = (uintptr_t)iter->obj;
	    dm_descriptor_t disk = (dm_descriptor_t)0;
	    boolean_t	avail = B_FALSE;
	    boolean_t	reserved = B_FALSE;
	    boolean_t	used = B_FALSE;

	    /* is slice on a disk in the input list? */
	    if (((error = slice_get_disk(slice, &disk)) != 0) ||
		(dlist_contains(disks, (void *)(uintptr_t)disk,
			compare_descriptor_names) != B_TRUE)) {
		continue;
	    }

	    /* is slice reserved by an explicit layout request? */
	    if (((error = is_reserved_slice(slice, &reserved)) != 0) ||
		(reserved == B_TRUE)) {
		continue;
	    }

	    /* is slice used by a pending layout request? */
	    if (((error = is_used_slice(slice, &used)) != 0) ||
		(used == B_TRUE)) {
		continue;
	    }

	    /* is slice available? */
	    if (((error = is_device_avail(slice, request, &avail)) == 0) &&
		(avail == B_TRUE)) {

		/* does slice have available space? */
		uint64_t size = 0;
		error = slice_get_size(slice, &size);
		if ((error == 0) && (size > 0)) {
		    dlist_t *item = dlist_new_item((void *)(uintptr_t)slice);
		    if (item == NULL) {
			error = ENOMEM;
		    } else {
			*slices = dlist_append(item, *slices, AT_TAIL);
		    }
		}
	    }
	}

	if (error != 0) {
	    dlist_free_items(*slices, NULL);
	    *slices = NULL;
	}

	return (error);
}


/*
 * FUNCTION:	get_hbas_and_disks_used_by_volumes(dlist_t *volumes,
 *			dlist_t **hbas,	dlist_t **disks)
 *
 * INPUT:	volumes	- pointer to a list of devconfig_t volumes
 *
 * OUTPUT:	hbas - a list of HBAs utilized by the input volumes
 *		disks - a list of disks utilized by the input volumes
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	An aggregate list of HBAs and disks used by the input volumes
 *		is built up by iterating the list of volumes and calling
 *		get_hbas_disks_used_by_volume() to determine the HBAs and disk
 *		used by each volume.
 *
 *		The returned lists of HBAs and disks may contain duplicates.
 */
int
get_hbas_and_disks_used_by_volumes(
	dlist_t		*volumes,
	dlist_t		**hbas,
	dlist_t		**disks)
{
	dlist_t		*iter = NULL;
	int		error = 0;

	for (iter = volumes;
	    (iter != NULL) && (error == 0);
	    iter = iter->next) {
	    error = get_hbas_and_disks_used_by_volume(
		    (devconfig_t *)iter->obj, hbas, disks);
	}

	return (error);
}

/*
 * FUNCTION:	get_hbas_and_disks_used_by_volume(devconfig_t *volume,
 *			dlist_t **hbas, dlist_t **disks)
 *
 * INPUT:	volume	- pointer to a devconfig_t volume
 *
 * OUTPUT:	hbas - a list of HBAs updated to include those utilized
 *			by the input volume
 *		disks - a list of disks updated to inlclude those utilized
 *			by the input volume
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	The volume's components are iterated and the disks and HBAs
 *		for each component are determined and appended to the input
 *		lists of HBAs and disks.
 *
 *		The returned lists of HBAs and disks may contain duplicates.
 */
int
get_hbas_and_disks_used_by_volume(
	devconfig_t	*volume,
	dlist_t		**hbas,
	dlist_t		**disks)
{
	dlist_t		*iter = NULL;
	int		error = 0;

	for (iter = devconfig_get_components(volume);
	    (iter != NULL) && (error == 0);
	    iter = iter->next) {

	    devconfig_t	*dev = (devconfig_t *)iter->obj;
	    if (devconfig_isA(dev, TYPE_SLICE)) {

		dm_descriptor_t	disk = NULL;
		char		*name = NULL;

		/* get disk for component slice */
		((error = devconfig_get_name(dev, &name)) != 0) ||
		(error = get_disk_for_named_slice(name, &disk));
		if (error == 0) {
		    dlist_t *item = dlist_new_item((void *)(uintptr_t)disk);
		    if (item == NULL) {
			error = ENOMEM;
		    } else {
			*disks = dlist_append(item, *disks, AT_HEAD);
		    }
		}

		/* get HBAs for disk */
		if (error == 0) {
		    dlist_t *disk_hbas = NULL;
		    if ((error = disk_get_hbas(disk, &disk_hbas)) == 0) {
			/* the hba list may contain dups, but that's ok */
			*hbas = dlist_append(disk_hbas, *hbas, AT_HEAD);
		    }
		}

	    } else if (devconfig_isA(dev, TYPE_MIRROR)) {

		/* collect info for submirrors */
		dlist_t *iter1;
		for (iter1 = devconfig_get_components(dev);
		    (iter1 != NULL) && (error == 0);
		    iter1 = iter1->next) {
		    error = get_hbas_and_disks_used_by_volume(
			    (devconfig_t *)iter1->obj, hbas, disks);
		}

	    }
	}

	return (error);
}

/*
 * FUNCTION:	compare_hba_n_avail_disks(void *obj1, void *obj2)
 *
 * INPUT:	obj1	- opaque pointer
 * 		obj2	- opaque pointer
 *
 * RETURNS:	int	- <0 - if obj1 has fewer available disks than obj2
 *			   0 - if obj1 has the same # of available disks as obj2
 *			  >0 - if obj1 has more available disks than obj2
 *
 * PURPOSE:	dlist_t helper which compares the number of available disks
 *		for two HBAs represented as dm_descriptor_t handles.
 *
 *		Both input objects are assumed to be dm_descriptor_t handles.
 *
 *		The number of available disks associated with the HBAs was
 *		computed and saved in select_hbas_with_n_disks(), this
 *		function just checks the saved values.
 */
static int
compare_hba_n_avail_disks(
	void		*obj1,
	void		*obj2)
{
	uint16_t	n1 = 0;
	uint16_t	n2 = 0;

	assert(obj1 != NULL);
	assert(obj2 != NULL);

	(void) hba_get_n_avail_disks((uintptr_t)obj1, &n1);
	(void) hba_get_n_avail_disks((uintptr_t)obj2, &n2);

	return ((int)n1 - n2);
}

/*
 * FUNCTION:	is_device_avail(dm_descriptor_t desc,
 *			devconfig_t *request, boolean_t *avail)
 *
 * INPUT:	desc	- a dm_descriptor_t device handle
 *		request	- pointer to a devconfig_t struct representing
 *				the current layout request being processed
 * 		avail	- pointer to a boolean to hold the result
 *
 * RETURNS:	int	-  0 - on success
 *			  !0 - otherwise
 *
 * PURPOSE:	Internal helper which determines if the input device can
 *		be used as a volume component when satisfying the input
 *		request.
 *
 *		The device is assumed to be a known valid device.
 *
 *		The function checks if the device passes the request's
 *		available and unavailable device specifications.
 *
 *		The input device name may be either a DID name or a CTD
 *		name.  All name comparisons are done using the CTD name.
 */
static int
is_device_avail(
	dm_descriptor_t	desc,
	devconfig_t	*request,
	boolean_t	*avail)
{
	char		*name = NULL;
	int		error = 0;

	*avail = B_FALSE;

	if ((error = get_display_name(desc, &name)) == 0) {
	    error = is_named_device_avail(request, name, B_TRUE, avail);
	}

	return (error);
}

/*
 * FUNCTION:	compare_request_to_request_spec_list_request(
 *			void *request, void *list_item)
 *
 * INPUT:	request	- opaque pointer to a devconfig_t
 * 		list_item - opaque pointer to a request_spec_list_t
 *
 * RETURNS:	int	- 0 - if request is the same as list_item->request
 *			  !0 - otherwise
 *
 * PURPOSE:	dlist_t helper which compares the input request pointer
 *		to the list_item's request pointer for equality.
 *
 *		This function is the lookup mechanism for the lists of
 *		cached device_spec_ts representing available/unavailable
 *		devices for a given defaults_t request/defaults struct.
 *
 *		The defaults_t struct pointer is the lookup key.
 */
static int
compare_request_to_request_spec_list_request(
	void *request,
	void *list_item)
{
	request_spec_list_t *entry =
	    (request_spec_list_t *)list_item;

	assert(request != NULL);
	assert(entry != NULL);

	/* compare two devconfig_t pointers, if identical, return 0 */
	return ((devconfig_t *)request != entry->request);
}

/*
 * FUNCTION:	compare_device_spec_specificity(void *spec1, void *spec2)
 *
 * INPUT:	spec1	- opaque pointer to a device_spec_t
 * 		spec2	- opaque pointer to a device_spec_t
 *
 * RETURNS:	int	- <0 - if spec1 is less specific than spec2
 *			   0 - if spec1 is as specific than spec2
 *			  >0 - if spec1 is more specific than spec2
 *
 * PURPOSE:	dlist_t helper which compares the level of specificity
 *		in the two input device_spec_t structs.  The one
 *		which specifies more "components" of a cXtXdXsX device
 *		name is considered more specific.
 */
static int
compare_device_spec_specificity(
	void	*spec1,
	void	*spec2)
{
	if (spec1 == NULL || spec2 == NULL) {
	    return (-1);
	}

	if ((((device_spec_t *)spec1)->data.ctd->slice != ID_UNSPECIFIED) &&
	    (((device_spec_t *)spec2)->data.ctd->slice == ID_UNSPECIFIED)) {
	    /* spec1 has slice, spec2 does not, spec1 more specific */
	    return (1);
	}

	if ((((device_spec_t *)spec2)->data.ctd->slice != ID_UNSPECIFIED) &&
	    (((device_spec_t *)spec1)->data.ctd->slice == ID_UNSPECIFIED)) {
	    /* spec2 has slice, spec1 does not, spec2 more specific */
	    return (-1);
	}

	if ((((device_spec_t *)spec2)->data.ctd->slice != ID_UNSPECIFIED) &&
	    (((device_spec_t *)spec1)->data.ctd->slice != ID_UNSPECIFIED)) {
	    /* both spec1 and spec2 have slice */
	    return (0);
	}

	if ((((device_spec_t *)spec1)->data.ctd->lun != ID_UNSPECIFIED) &&
	    (((device_spec_t *)spec2)->data.ctd->lun == ID_UNSPECIFIED)) {
	    /* spec1 has lun, spec2 does not, spec1 more specific */
	    return (1);
	}

	if ((((device_spec_t *)spec2)->data.ctd->lun != ID_UNSPECIFIED) &&
	    (((device_spec_t *)spec1)->data.ctd->lun == ID_UNSPECIFIED)) {
	    /* spec2 has lun, spec1 does not, spec2 more specific */
	    return (-1);
	}

	if ((((device_spec_t *)spec2)->data.ctd->lun != ID_UNSPECIFIED) &&
	    (((device_spec_t *)spec1)->data.ctd->lun != ID_UNSPECIFIED)) {
	    /* both spec1 and spec2 have lun */
	    return (0);
	}

	if ((((device_spec_t *)spec1)->data.ctd->target != ID_UNSPECIFIED) &&
	    (((device_spec_t *)spec2)->data.ctd->target == ID_UNSPECIFIED)) {
	    /* spec1 has target, spec2 does not, spec1 more specific */
	    return (1);
	}

	if ((((device_spec_t *)spec2)->data.ctd->target != ID_UNSPECIFIED) &&
	    (((device_spec_t *)spec1)->data.ctd->target == ID_UNSPECIFIED)) {
	    /* spec2 has target, spec1 does not, spec2 more specific */
	    return (-1);
	}

	if ((((device_spec_t *)spec2)->data.ctd->target != ID_UNSPECIFIED) &&
	    (((device_spec_t *)spec1)->data.ctd->target != ID_UNSPECIFIED)) {
	    /* both spec1 and spec2 have target */
	    return (0);
	}

	/* both specify just ctrl */
	return (0);
}

/*
 * FUNCTION:	find_request_spec_list_entry(devconfig_t *request)
 *
 * INPUT:	request	- pointer to a devconfig_t struct
 *
 * RETURNS:	request_spec_list_entry - pointer to a
 *			request_spec_list_entry struct
 *
 * PURPOSE:	Lookup function which encapsulates the details of locating
 *		the device_spec_list_t cache entry for the input request.
 */
static request_spec_list_t *
find_request_spec_list_entry(
	devconfig_t *request)
{
	dlist_t *list_item = NULL;
	request_spec_list_t *entry = NULL;

	list_item = dlist_find(
		_request_spec_list_cache,
		(void *)request,
		compare_request_to_request_spec_list_request);

	if (list_item != NULL) {
	    entry = (request_spec_list_t *)list_item->obj;
	}

	return (entry);
}

/*
 * FUNCTION:	add_request_spec_list_entry(devconfig_t *request,
 *			char **avail_device_specs, char **unavail_device_specs,
 *			request_spec_list_entry_t **entry)
 *
 * INPUT:	entry - pointer to the request_spec_list_entry struct to be
 *			added to the cache.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Function which encapsulates the details of adding a
 *		device_spec_list_t cache entry.
 */
static int
add_request_spec_list_entry(
	request_spec_list_t *entry)
{
	dlist_t *list_item = dlist_new_item((void *)entry);

	if (list_item == NULL) {
	    return (ENOMEM);
	}

	_request_spec_list_cache = dlist_append(list_item,
		_request_spec_list_cache, AT_HEAD);

	return (0);
}

/*
 * FUNCTION:	make_request_spec_list_entry(devconfig_t *request,
 *			char **avail_device_specs, char **unavail_device_specs,
 *			request_spec_list_entry_t **entry)
 *
 * INPUT:	request	- pointer to a devconfig_t struct
 *		avail_device_specs - char * array of user specified available
 *			devices associated with the input request
 *		unavail_device_specs - char * array of user specified
 *			unavailable devices associated with the input
 *			request
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Function which encapsulates the details of generating a new
 *		the device_spec_list_t cache entry for the input request
 *		and its lists of avail/unavail devices.
 *
 *		Converts the input arrays of (un)available device names into
 *		equivalent lists of device_spec_t structs.
 *
 *		Creates a new cache entry, populates it and adds it to the
 *		cache.
 */
static int
make_request_spec_list_entry(
	devconfig_t *request,
	char	**avail_device_specs,
	char	**unavail_device_specs,
	request_spec_list_t **entry)
{
	int error = 0;
	dlist_t *list = NULL;

	*entry = calloc(1, sizeof (request_spec_list_t));
	if (*entry == NULL) {
	    return (ENOMEM);
	}

	(*entry)->request = request;

	/*
	 * map the avail_device_name array into a list of device_spec_t
	 * and save the list as the entry's available list
	 */
	error = convert_usernames_to_specs(
		avail_device_specs, &list);

	if (error == 0) {
	    (*entry)->avail_specs_list = list;
	}

	/*
	 * map the unavail_device_name array into a list of device_spec_t
	 * and save the list as the entry's unavailable list
	 */
	list = NULL;
	error = convert_usernames_to_specs(
		unavail_device_specs, &list);

	if (error == 0) {
	    (*entry)->unavail_specs_list = list;
	}

	if (error != 0) {
	    /* delete the partial entry */
	    destroy_request_spec_list_entry((void *)*entry);
	    *entry = NULL;
	}

	return (error);
}

/*
 * FUNCTION:	convert_usernames_to_specs(char **specs, dlist_t **list)
 *
 * INPUT:	specs	- char * array of device CTD names
 *
 * OUTPUT:	list	- pointer to a list of device_spec_t corresponding
 *				to each name in the input array
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Function which converts the input CTD device names to the
 *		equivalent device_spec_t structs.
 *
 *		Iterates the input array and converts each CTD name to a
 *		device_spec_t using get_spec_for_name().
 */
static int
convert_usernames_to_specs(
	char	**specs,
	dlist_t **list)
{
	int i = 0;
	int error = 0;

	/*
	 * For each spec in the array, get the corresponding
	 * device_spec_t and add it to the list.
	 *
	 * Any spec in the array that looks to be a DID name
	 * is first converted to its equivalent CTD name.
	 */
	for (i = 0;
	    (specs != NULL) && (specs[i] != NULL) && (error == 0);
	    i++) {

	    device_spec_t *spec = NULL;
	    char *userspec = specs[i];

	    error = get_spec_for_name(userspec, &spec);
	    if ((error == 0) && (spec != NULL)) {
		dlist_t *list_item = dlist_new_item((void *)spec);
		if (spec == NULL) {
		    error = ENOMEM;
		} else {
		    *list = dlist_insert_ordered
			(list_item, *list, DESCENDING,
				compare_device_spec_specificity);
		}
	    }
	}

	if (error != 0) {
	    /* the device_spec_t in the list items are maintained */
	    /* in a cache elsewhere, so don't free them here. */
	    dlist_free_items(*list, NULL);
	    *list = NULL;
	}

	return (error);
}

/*
 * FUNCTION:	destroy_request_spec_list_entry(void *entry)
 *
 * INPUT:	entry	- opaque pointer to a request_spec_list_t
 *
 * RETURNS:	nothing
 *
 * PURPOSE:	Function which reclaims memory allocated to a
 *		request_spec_list_t.
 *
 *		Frees memory allocated to the avail_spec_list and
 *		unavail_spec_list.  Entries in the list are not freed,
 *		since they are owned by the device_spec cache.
 */
static void
destroy_request_spec_list_entry(
	void *obj)
{
	request_spec_list_t *entry = (request_spec_list_t *)obj;

	if (entry != NULL) {
	    /* items in the list are in the spec_cache and will */
	    /* be cleaned up when it is destroyed. */
	    dlist_free_items(entry->avail_specs_list, NULL);
	    dlist_free_items(entry->unavail_specs_list, NULL);
	    free(entry);
	}
}

/*
 * FUNCTION:	destroy_request_spec_list_cache()
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Function which destroys all entries in the request_spec_list
 *		cache.
 */
static int
destroy_request_spec_list_cache()
{
	dlist_free_items(_request_spec_list_cache,
		destroy_request_spec_list_entry);
	_request_spec_list_cache = NULL;

	return (0);
}

/*
 * FUNCTION:	get_request_avail_spec_list(devconfig_t *request,
 *			dlist_t **list)
 *
 * INPUT:	request	- a pointer to a devconfig_t
 *
 * OUTPUT:	list	- pointer to a list of device_spec_t corresponding
 *				to the devices specified as available by the
 *				input request.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Function which locates or builds the list of device_spec_t
 *		for the available devices specified in the input request.
 *
 *		Looks up the input request in the request_spec_list cache.
 *		If there is currently no entry in the cache for the request,
 *		an entry is built and added.
 *
 *		The entry's list of available device_spec_t is returned.
 */
static int
get_request_avail_spec_list(
	devconfig_t *request,
	dlist_t	    **list)
{
	request_spec_list_t *entry = NULL;
	int error = 0;

	if ((entry = find_request_spec_list_entry(request)) == NULL) {

	    /* create cache entry for this request */
	    error = make_request_spec_list_entry(
		    request,
		    devconfig_get_available(request),
		    devconfig_get_unavailable(request),
		    &entry);

	    if ((error == 0) && (entry != NULL)) {
		if ((error = add_request_spec_list_entry(entry)) != 0) {
		    destroy_request_spec_list_entry(entry);
		    entry = NULL;
		}
	    }
	}

	if ((error == 0) && (entry != NULL)) {
	    *list = entry->avail_specs_list;
	}

	return (error);
}

/*
 * FUNCTION:	get_request_unavail_spec_list(devconfig_t *request,
 *			dlist_t **list)
 *
 * INPUT:	request	- a pointer to a devconfig_t
 *
 * OUTPUT:	list	- pointer to a list of device_spec_t corresponding
 *				to the devices specified as unavailable by the
 *				input request.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Function which locates or builds the list of device_spec_t
 *		for the unavailable devices specified in the input request.
 *
 *		Looks up the input request in the request_spec_list cache.
 *		If there is currently no entry in the cache for the request,
 *		an entry is built and added.
 *
 *		The entry's list of unavailable device_spec_t is returned.
 */
static int
get_request_unavail_spec_list(
	devconfig_t *request,
	dlist_t	    **list)
{
	request_spec_list_t *entry = NULL;
	int error = 0;

	if ((entry = find_request_spec_list_entry(request)) == NULL) {

	    /* create new entry for this request */
	    error = make_request_spec_list_entry(
		    request,
		    devconfig_get_available(request),
		    devconfig_get_unavailable(request),
		    &entry);

	    if ((error == 0) && (entry != NULL)) {
		if ((error = add_request_spec_list_entry(entry)) != 0) {
		    destroy_request_spec_list_entry(entry);
		    entry = NULL;
		}
	    }
	}

	if ((error == 0) && (entry != NULL)) {
	    *list = entry->unavail_specs_list;
	}

	return (error);
}

/*
 * FUNCTION:	get_default_avail_spec_list(defaults_t *defaults,
 *			char *dsname, dlist_t **list)
 *
 * INPUT:	defaults - a pointer to a defaults_t struct
 *		dsname	- the name of the diskset whose defaults should be used
 *
 * OUTPUT:	list	- pointer to a list of device_spec_t corresponding
 *				to the devices specified as available by the
 *				defaults for the named diskset, or the global
 *				defaults for all disksets.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Function which locates or builds the list of device_spec_t
 *		for the available devices for the named diskset.
 *
 *		Locates the defaults for the named diskset, if there are none,
 *		locates the global defaults for all disksets.
 *
 *		The defaults devconfig_t struct is then used to look up the
 *		the corresponding entry in the request_spec_list cache.
 *
 *		If there is currently no entry in the cache for the defaults,
 *		an entry is built and added.
 *
 *		The entry's list of available device_spec_t is returned.
 */
static int
get_default_avail_spec_list(
	defaults_t *alldefaults,
	char	*dsname,
	dlist_t	    **list)
{
	request_spec_list_t *entry = NULL;
	devconfig_t *defaults = NULL;
	int error = 0;

	/* Get diskset defaults, or global if none for diskset */
	error = defaults_get_diskset_by_name(
		alldefaults, dsname, &defaults);

	if (error != 0) {
	    if (error == ENOENT) {
		/* to get global defaults, pass a NULL diskset name */
		error = defaults_get_diskset_by_name(
			alldefaults, NULL, &defaults);
	    }

	    if (error != 0) {
		if (error != ENOENT) {
		    oprintf(OUTPUT_DEBUG,
			    gettext("get defaults for %s returned %d\n"),
			    dsname, error);
		} else {
		    error = 0;
		}
	    }
	}

	if ((entry = find_request_spec_list_entry(defaults)) == NULL) {

	    /* create new entry for these defaults */
	    error = make_request_spec_list_entry(
		    defaults,
		    devconfig_get_available(defaults),
		    devconfig_get_unavailable(defaults),
		    &entry);

	    if ((error == 0) && (entry != NULL)) {
		if ((error = add_request_spec_list_entry(entry)) != 0) {
		    destroy_request_spec_list_entry(entry);
		    entry = NULL;
		}
	    }
	}

	if ((error == 0) && (entry != NULL)) {
	    *list = entry->avail_specs_list;
	}

	return (error);
}

/*
 * FUNCTION:	get_default_unavail_spec_list(defaults_t *defaults,
 *			char *dsname, dlist_t **list)
 *
 * INPUT:	defaults - a pointer to a defaults_t struct
 *		dsname	- the name of the diskset whose defaults should be used
 *
 * OUTPUT:	list	- pointer to a list of device_spec_t corresponding
 *				to the devices specified as unavailable by the
 *				defaults for the named diskset, or the global
 *				defaults for all disksets.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Function which locates or builds the list of device_spec_t
 *		for the unavailable devices for the named diskset.
 *
 *		Locates the defaults for the named diskset, if there are none,
 *		locates the global defaults for all disksets.
 *
 *		The defaults devconfig_t struct is then used to look up the
 *		the corresponding entry in the request_spec_list cache.
 *
 *		If there is currently no entry in the cache for the defaults,
 *		an entry is built and added.
 *
 *		The entry's list of unavailable device_spec_t is returned.
 */
static int
get_default_unavail_spec_list(
	defaults_t *alldefaults,
	char	*dsname,
	dlist_t	    **list)
{
	request_spec_list_t *entry = NULL;
	devconfig_t *defaults = NULL;
	int error = 0;

	/* Get diskset defaults, or global if none for diskset */
	error = defaults_get_diskset_by_name(
		alldefaults, dsname, &defaults);

	if (error != 0) {

	    if (error == ENOENT) {
		/* to get global defaults, pass a NULL diskset name */
		error = defaults_get_diskset_by_name(
			alldefaults, NULL, &defaults);
	    }

	    if (error != 0) {
		if (error != ENOENT) {
		    oprintf(OUTPUT_DEBUG,
			    gettext("get defaults for %s returned %d\n"),
			    dsname, error);
		} else {
		    error = 0;
		}
	    }
	}

	if ((entry = find_request_spec_list_entry(defaults)) == NULL) {

	    /* create new entry for these defaults */
	    error = make_request_spec_list_entry(
		    defaults,
		    devconfig_get_available(defaults),
		    devconfig_get_unavailable(defaults),
		    &entry);

	    if ((error == 0) && (entry != NULL)) {
		if ((error = add_request_spec_list_entry(entry)) != 0) {
		    destroy_request_spec_list_entry(entry);
		    entry = NULL;
		}
	    }
	}

	if ((error == 0) && (entry != NULL)) {
	    *list = entry->unavail_specs_list;
	}

	return (error);
}

/*
 * FUNCTION:	is_named_device_avail(devconfig_t *request, char *device_name,
 *			boolean_t check_aliases, boolean_t *avail)
 *
 * INPUT:	request - the current request devconfig_t
 *		device_name - char * device name
 *		check_aliases - boolean_t which indicates whether the device's
 *			aliases should be considered by the availability checks.
 *
 * OUTPUT:	avail	- a boolean_t * to hold the result
 *
 * RETURNS:	int	- !0 on error
 *
 *		avail is set to B_TRUE if the named device is available for
 * 		the input request, B_FALSE otherwise.
 *
 * PURPOSE:	Determine if the named device can be used to satisfy the
 *		input request.
 *
 *		There are several levels at which device availabiity or
 *		unavailability may be specifed:
 *
 *		1. the volume subrequest,
 *		2. the toplevel (diskset) request,
 *		3. the diskset-specific defaults
 *		4. the global defaults
 *
 *		If the diskset-specific defaults exist, only they are checked.
 *
 *		The precedence ordering that is enforced:
 *
 *		1. if request has an avail list, the name must be in it
 * 			and not in the request's unavail list.
 *		2. if request has an unavail list, the name must not be in it.
 *		3. if toplevel request has an avail list, the name must be
 *			in it and not in the toplevel request's unavailable
 *			list.
 *		4. if toplevel request has an unavail list, the name must
 *			not be in it.
 *		5. if defaults have an avail list, the name must be in it
 *			and not in the defaults unavailable list.
 *		6. if defaults have an unavail list, the name must not be
 *			in it.
 */
static int
is_named_device_avail(
	devconfig_t	*request,
	char		*device_name,
	boolean_t	check_aliases,
	boolean_t	*avail)
{
	typedef enum check_types {
		DEVICE_REQUEST = 0,
		DISKSET_REQUEST,
		DEFAULTS,
		N_CHECKS
	} check_type_t;

	check_type_t	check_type;

	typedef enum list_types {
		AVAIL = 0,
		UNAVAIL,
		N_LISTS
	} list_type_t;

	dlist_t		*lists[N_CHECKS][N_LISTS];
	boolean_t	includes;
	int		error = 0;

	memset(lists, 0, (N_CHECKS * N_LISTS) * sizeof (dlist_t *));

	if (request != NULL) {
	    /* get avail/unavail specs for request */
	    ((error = get_request_avail_spec_list(
		    request, &lists[DEVICE_REQUEST][AVAIL])) != 0) ||
	    (error = get_request_unavail_spec_list(
		    request, &lists[DEVICE_REQUEST][UNAVAIL]));
	}

	if ((error == 0) && (_toplevel_request != NULL)) {
	    /* diskset request */
	    ((error = get_request_avail_spec_list(
		    _toplevel_request, &lists[DISKSET_REQUEST][AVAIL])) != 0) ||
	    (error = get_request_unavail_spec_list(
		    _toplevel_request, &lists[DISKSET_REQUEST][UNAVAIL]));
	}

	if ((error == 0) && (_defaults != NULL)) {
	    /* and diskset/global defaults */
	    ((error = get_default_avail_spec_list(_defaults,
		    get_request_diskset(), &lists[DEFAULTS][AVAIL])) != 0) ||
	    (error = get_default_unavail_spec_list(_defaults,
		    get_request_diskset(), &lists[DEFAULTS][UNAVAIL]));
	}

	if (error != 0) {
	    return (error);
	}

	*avail = B_TRUE;

	for (check_type = DEVICE_REQUEST;
	    (check_type < N_CHECKS) && (error == 0);
	    check_type++) {

	    if (lists[check_type][AVAIL] != NULL) {

		/* does avail spec list include named device? */
		if ((error = avail_list_includes_device_name(
		    lists[check_type][AVAIL], device_name, check_aliases,
		    &includes)) == 0) {

		    if (includes != B_TRUE) {
			*avail = B_FALSE;
		    }

		    if ((includes == B_TRUE) &&
			(lists[check_type][UNAVAIL] != NULL)) {

			/* device is available, is it in the unavail list? */
			if ((error = unavail_list_includes_device_name(
			    lists[check_type][UNAVAIL], device_name,
			    check_aliases, &includes)) == 0) {

			    if (includes == B_TRUE) {
				*avail = B_FALSE;
			    }
			}
		    }
		}

		/* lists at this level checked, skip remainder */
		break;

	    } else if (lists[check_type][UNAVAIL] != NULL) {

		/* does unavail spec list include named device? */
		if ((error = unavail_list_includes_device_name(
		    lists[check_type][UNAVAIL], device_name,
		    check_aliases, &includes)) == 0) {

		    if (includes == B_TRUE) {
			*avail = B_FALSE;
		    }
		}

		/* list at this level checked, skip remainder */
		break;
	    }
	}

	return (error);
}

/*
 * FUNCTION:	avail_list_includes_device_name(dlist_t *list,
 *			char *device_name, boolean_t check_aliases,
 *			boolean_t *includes)
 *
 * INPUT:	list	- a dlist_t list of available device_spec_t
 *		device_name  - a char * device CTD name
 *		check_aliases - boolean_t which indicates if the device's
 *			aliases	should be considered in the availability
 *			checking.
 *
 * OUTPUT:	includes - B_TRUE - if named device is "included" by any
 *				specification in the input list
 *			   B_FALSE - otherwise
 *
 * RETURNS:	int	- 0 on success
 *			- !0 otherwise
 *
 * PURPOSE:	Helper used by is_named_device_avail that determines
 *		if the input list of device specifications "includes"
 *		a specific device.
 *
 *		Iterates the elements of the input array and searches
 *		for a match using spec_includes_device_name().
 */
static int
avail_list_includes_device_name(
	dlist_t	*list,
	char	*device_name,
	boolean_t check_aliases,
	boolean_t *includes)
{
	dlist_t *iter = NULL;
	int	error = 0;

	*includes = B_FALSE;

	for (iter = list;
	    (*includes == B_FALSE) && (iter != NULL) && (error == 0);
	    iter = iter->next) {

	    device_spec_t *spec = (device_spec_t *)iter->obj;
	    error = spec_includes_device_name(spec, device_name,
		    check_aliases, includes);
	}

	return (0);
}

/*
 * FUNCTION:	unavail_list_includes_device_name(dlist_t *list,
 *			char *device_name, boolean_t check_aliases,
 *			boolean_t *includes)
 *
 * INPUT:	list	- a dlist_t list of unavailable device_spec_t
 *		device_name  - a char * device CTD name
 *		check_aliases - boolean_t which indicates if the device's
 *			aliases	should be considered in the availability
 *			checking.
 *
 * OUTPUT:	includes - B_TRUE - if named device is "included" by any
 *				specification in the input list
 *			   B_FALSE - otherwise
 *
 * RETURNS:	int	- 0 on success
 *			- !0 otherwise
 *
 * PURPOSE:	Helper used by is_named_device_avail that determines
 *		if the input list of device specifications "includes"
 *		a specific device.
 *
 *		Iterates the elements of the input array and searches
 *		for a match using spec_includes_device_name_or_alias().
 */
static int
unavail_list_includes_device_name(
	dlist_t	*list,
	char	*device_name,
	boolean_t check_aliases,
	boolean_t *includes)
{
	dlist_t *iter = NULL;
	int	error = 0;
	device_spec_t *unavail_spec;
	boolean_t	check_for_alternate_hba = B_FALSE;

	*includes = B_FALSE;

	/*
	 * the specs in the list are in descending order of specificity.
	 * so a more exact spec will rule the device out before a less
	 * exact spec.
	 *
	 * Meaning: if the list has { "c3t0d0", ..., "c3", ... } and the
	 * input device name is "c3t0d0s0", it will match "c3t0d0"
	 * before "c3".
	 *
	 * This is important for the multi-path alias checking below.
	 * If the input device name is ruled out by a non-controller
	 * specification, it is really unavailable.
	 */
	for (iter = list;
	    (*includes == B_FALSE) && (iter != NULL);
	    iter = iter->next) {

	    unavail_spec = (device_spec_t *)iter->obj;
	    error = spec_includes_device_name(
		    unavail_spec, device_name, check_aliases, includes);

	}

	if ((error == 0) && (*includes == B_TRUE)) {

	    /* matched an unavailable spec, was it a controller/HBA? */
	    oprintf(OUTPUT_DEBUG,
		    "device \"%s\" is unavailable, "
		    "it matched \"c(%d)t(%d)d(%d)s(%d)\"\n",
		    device_name,
		    unavail_spec->data.ctd->ctrl,
		    unavail_spec->data.ctd->target,
		    unavail_spec->data.ctd->lun,
		    unavail_spec->data.ctd->slice);

	    if ((unavail_spec->data.ctd->ctrl != ID_UNSPECIFIED) &&
		(unavail_spec->data.ctd->target == ID_UNSPECIFIED) &&
		(unavail_spec->data.ctd->lun == ID_UNSPECIFIED) &&
		(unavail_spec->data.ctd->slice == ID_UNSPECIFIED)) {

		/*
		 * Need to see if the named device is a disk or slice,
		 * and if so check to see if the it is multipathed
		 * and possibly accessible thru another controller/HBA.
		 */
		check_for_alternate_hba = B_TRUE;
	    }
	}

	if ((error == 0) && (check_for_alternate_hba == B_TRUE)) {

	    dm_descriptor_t slice = (dm_descriptor_t)0;
	    dm_descriptor_t disk = (dm_descriptor_t)0;

	    ((error = slice_get_by_name(device_name, &slice)) != 0) ||
	    (error = disk_get_by_name(device_name, &disk));
	    if (error != 0) {
		return (error);
	    }

	    /* if it is a slice, get its disk */
	    if ((error == 0) && (slice != (dm_descriptor_t)0)) {
		error = slice_get_disk(slice, &disk);
	    }

	    if ((error == 0) && (disk != (dm_descriptor_t)0)) {

		/* see if all the disk's HBAs are unavailable */
		dlist_t *hbas = NULL;
		dlist_t *iter = NULL;

		error = disk_get_hbas(disk, &hbas);

		if (hbas != NULL) {
		    oprintf(OUTPUT_DEBUG,
			    gettext("    checking alternate paths for %s\n"),
			    device_name);
		} else {
		    oprintf(OUTPUT_DEBUG,
			    gettext("    no alternate paths for %s\n"),
			    device_name);
		}

		/* for each of the disk's HBAs */
		for (iter = hbas;
		    (iter != NULL) && (*includes == B_TRUE) && (error == 0);
		    iter = iter->next) {

		    dm_descriptor_t hba = (uintptr_t)iter->obj;
		    device_spec_t *hbaspec;
		    char *hbaname = NULL;
		    dlist_t *iter2 = NULL;

		    *includes = B_FALSE;

		    ((error = get_display_name(hba, &hbaname)) != 0) ||
		    (error = get_spec_for_name(hbaname, &hbaspec));

		    /* is HBA unavailable? */
		    for (iter2 = list;
			(iter2 != NULL) && (error == 0) &&
				(*includes == B_FALSE);
			iter2 = iter2->next) {

			device_spec_t *spec =
			    (device_spec_t *)iter2->obj;

			*includes = spec_includes_device(spec, hbaspec);
		    }
		}
		dlist_free_items(hbas, NULL);

		/* if *includes==B_TRUE here, all HBAs are unavailable */
	    }
	}

	return (error);
}

/*
 * FUNCTION:	spec_includes_device_name(device_spec_t *spec,
 *			char *device_name, boolean_t check_aliases,
 *			boolean_t *includes)
 *
 * INPUT:	spec	- a device_spec_t CTD specification.
 *		device_name  - a char * device CTD name
 *		check_aliases - boolean_t which indicates if the device's
 *			aliases	should be considered in the checking.
 *
 * OUTPUT:	includes - B_TRUE - if device is "included" by the input
 *				specification
 *			    B_FALSE - otherwise
 *
 * RETURNS:	int	- 0 on success
 *			- !0 otherwise
 *
 * PURPOSE:	Helper used by (un)avail_specs_includes_device_name() that
 *		determines if the input device specification "includes"
 *		the named device.
 *
 *		If check_aliases is true and the named device is a slice or
 *		a disk drive, its multi-pathed aliases are also checked
 *		against the spec.
 */
static int
spec_includes_device_name(
	device_spec_t *spec,
	char		 *device_name,
	boolean_t	check_aliases,
	boolean_t	*includes)
{
	device_spec_t *device_spec;
	int error = 0;

	error = get_spec_for_name(device_name, &device_spec);
	if (error == 0) {

	    *includes = spec_includes_device(spec, device_spec);

	    if ((*includes == B_FALSE) && (check_aliases == B_TRUE)) {

		/* spec doesn't include name, check aliases */

		dm_descriptor_t device = (dm_descriptor_t)0;
		dlist_t *aliases = NULL;

		/* only slices and disks have aliases */
		error = slice_get_by_name(device_name, &device);
		if (device != (dm_descriptor_t)0) {
		    error = get_aliases(device, &aliases);
		} else if (error == 0) {
		    error = disk_get_by_name(device_name, &device);
		    if (device != (dm_descriptor_t)0) {
			error = get_aliases(device, &aliases);
		    }
		}

		if ((error == 0) && (aliases != NULL)) {

		    dlist_t *iter;
		    for (iter = aliases;
			(iter != NULL) && (*includes == B_FALSE) &&
				(error == 0);
			iter = iter->next) {

			char *alias = (char *)iter->obj;
			device_spec_t *alias_spec;

			error = get_spec_for_name(alias, &alias_spec);
			if (error == 0) {
			    /* does spec include alias? */
			    *includes =	spec_includes_device(spec, alias_spec);
			}
		    }
		}
		dlist_free_items(aliases, free);
	    }
	}

	return (error);
}

/*
 * FUNCTION:	destroy_device_spec(device_spec_t *spec)
 *
 * INPUT:	spec	- pointer to a device_spec_t
 *
 * RETURNS:	nothing
 *
 * PURPOSE:	Function which reclaims memory allocated to a device_spec_t.
 *
 *		Frees memory allocated to hold the specific data in the spec.
 */
static void
destroy_device_spec(
	device_spec_t *spec)
{
	if (spec != NULL) {
	    if (spec->type == SPEC_TYPE_CTD) {
		free(spec->data.ctd);
	    } else if (spec->type == SPEC_TYPE_RAW) {
		free(spec->data.raw);
	    }
	    free(spec);
	}
}

/*
 * FUNCTION:	create_device_spec(char *name, device_spec_t **spec);
 *
 * INPUT:	name	- pointer to a char* device name
 *
 * OUTPUT:	spec	- pointer to a device_spec_t to hold the result
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Function which creates a device_spec_t for the input
 *		device name.
 *
 */
static int
create_device_spec(
	char	*name,
	device_spec_t **spec)
{
	int error = 0;

	/* allocate the device spec and try various parsing schemes */
	*spec = (device_spec_t *)calloc(1, sizeof (device_spec_t));
	if (*spec == NULL) {
	    error = ENOMEM;
	} else {
	    if (((error = create_device_ctd_spec(name, spec)) != 0) &&
		    (error != ENOMEM)) {
		/* CTD failed, try other parsing schemes */
		error = create_device_raw_spec(name, spec);
	    }
	}

	return (error);
}

/*
 * FUNCTION:	create_device_ctd_spec(char *name, device_spec_t **spec);
 *
 * INPUT:	name	- pointer to a char* device name
 *
 * OUTPUT:	spec	- pointer to a device_spec_t updated with the parsed
 *				CTD spec, if successful
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Function which atttempts to parse the input device name into
 *		cXtXdXsX component ids. The ids are the integer values of each
 *		specified segment of the input name.
 *
 *		If the name doesn't contain a segment, the id is set to
 *		ID_UNSPECIFIED.
 *
 *		The input name must be well-formed.
 *
 *		These are the acceptable forms:
 *
 *		cXtXdXsX
 *		cXtXdX
 *		cXtX
 *		cXdXsX
 *		cXdX
 *		cX
 */
static int
create_device_ctd_spec(
	char	*name,
	device_spec_t **spec)
{
	uint_t	ctrl;
	uint_t	target;
	uint_t	lun;
	uint_t	slice;

	uint_t	nscan;
	uint_t	nchars;

	char	*device_str;
	char	*target_str;
	char	*ctd_str;
	char	*t_ptr;
	char	*d_ptr;
	char	*s_ptr;

	boolean_t is_ide = B_FALSE;
	boolean_t got_slice = B_FALSE;
	boolean_t got_lun = B_FALSE;
	boolean_t got_target = B_FALSE;
	boolean_t got_ctrl = B_FALSE;

	int 	error = 0;

	ctd_str = strdup(name);
	if (ctd_str == NULL) {
	    return (ENOMEM);
	}

	/* trim any leading path (/dev/dsk/cXtXdXsX) */
	if ((device_str = strrchr(ctd_str, '/')) != NULL) {
	    ++device_str;
	} else {
	    device_str = ctd_str;
	}

	/* find each segment start position */
	t_ptr = strrchr(device_str, 't');
	d_ptr = strrchr(device_str, 'd');
	s_ptr = strrchr(device_str, 's');

	/*
	 * scan ids from each existing segment working backwards
	 * so as to leave the device_str in the correct state
	 * for the next expected segment
	 */
	if (s_ptr != NULL) {

	    /* found 's', try to get slice */
	    nchars = strlen(s_ptr);
	    if ((sscanf(s_ptr, "s%u%n", &slice, &nscan) != 1) ||
		(nscan != nchars)) {

		error = -1;
		oprintf(OUTPUT_DEBUG,
			gettext("no slice component in device "
				"name \"%s\".\n"),
			name);

	    } else {
		got_slice = B_TRUE;
		*s_ptr = '\0';
	    }
	}

	if ((error == 0) && (d_ptr != NULL)) {

	    /* found 'd', try to get disk/lun */
	    nchars = strlen(d_ptr);
	    if ((sscanf(d_ptr, "d%u%n", &lun, &nscan) != 1) ||
		(nscan != nchars)) {

		error = -1;
		oprintf(OUTPUT_DEBUG,
			gettext("no disk/lun component "
				"in device name \"%s\".\n"),
			name);

	    } else {
		got_lun = B_TRUE;
		*d_ptr = '\0';
	    }
	}

	if ((error == 0) && (t_ptr != NULL)) {

	    /* found 't', try to get target, it may be a hex WWN id */

	    /* skip leading 't' and add two for the 'OX' */
	    nchars = strlen(t_ptr + 1) + 2;
	    if ((target_str = (char *)malloc(nchars+1)) == NULL) {

		error = ENOMEM;

	    } else {

		strcpy(target_str, "0X");
		strcpy(target_str+2, t_ptr + 1);
		target_str[nchars] = '\0';

		if ((sscanf(target_str, "%x%n", &target, &nscan) != 1) ||
		    (nscan != nchars)) {

		    error = -1;
		    oprintf(OUTPUT_DEBUG,
			    gettext("no target/WWN component "
				    "in device name \"%s\".\n"),
			    name);

		} else {
		    got_target = B_TRUE;
		    *t_ptr = '\0';
		}

		free(target_str);
	    }

	} else {
	    is_ide = B_TRUE;
	}

	if ((error == 0) && (device_str != NULL)) {

	    /* get controller/hba/channel */
	    nchars = strlen(device_str);
	    if ((sscanf(device_str, "c%u%n", &ctrl, &nscan) != 1) ||
		    (nscan != nchars)) {

		error = -1;
		oprintf(OUTPUT_DEBUG,
			gettext("no channel/HBA component "
				"in device name \"%s\".\n"),
			name);

	    } else {
		got_ctrl = B_TRUE;
	    }
	}

	free(ctd_str);

	if (error == 0) {

	    /* allocate the ctd_spec_t struct and store the ids */
	    (*spec)->type = SPEC_TYPE_CTD;
	    (*spec)->data.ctd = (ctd_spec_t *)calloc(1, sizeof (ctd_spec_t));

	    if ((*spec)->data.ctd == NULL) {
		error = ENOMEM;
	    }

	    (*spec)->data.ctd->slice = ID_UNSPECIFIED;
	    (*spec)->data.ctd->lun = ID_UNSPECIFIED;
	    (*spec)->data.ctd->target = ID_UNSPECIFIED;
	    (*spec)->data.ctd->ctrl = ID_UNSPECIFIED;

	    if (got_slice == B_TRUE) {
		(*spec)->data.ctd->slice = slice;
	    }

	    if (got_lun == B_TRUE) {
		(*spec)->data.ctd->lun = lun;
	    }

	    if (got_target == B_TRUE) {
		(*spec)->data.ctd->target = target;
	    }

	    if (got_ctrl == B_TRUE) {
		(*spec)->data.ctd->ctrl = ctrl;
	    }

	    (*spec)->data.ctd->is_ide = is_ide;
	}

	return (error);
}

/*
 * FUNCTION:	create_device_raw_spec(char *name, device_spec_t **spec);
 *
 * INPUT:	name	- pointer to a char* device name
 *
 * OUTPUT:	spec	- pointer to a device_spec_t updated with the raw spec
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Function which creates a "raw" spec for the input name.
 *
 *		This is a last resort if all other spec parsing schemes failed,
 *		the "raw" spec is just the input device name.
 */
static int
create_device_raw_spec(
	char	*name,
	device_spec_t **spec)
{
	int 	error = 0;
	char	*ctd_str = strdup(name);

	if (ctd_str == NULL) {
	    return (ENOMEM);
	}

	(*spec)->type = SPEC_TYPE_RAW;
	(*spec)->data.raw = ctd_str;

	oprintf(OUTPUT_DEBUG,
		gettext("made raw device spec for \"%s\"\n"), ctd_str);

	return (error);
}

/*
 * FUNCTION:	get_spec_for_name(char *name, device_spec_t **id);
 *
 * INPUT:	name	- pointer to a char* device name
 *
 * OUTPUT:	id	- pointer to a device_spec_t to hold the result
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Function which finds the device_spec_t that already
 *		exists for the input name or creates it.
 *
 *		The returned struct should not be freed, it is maintained
 *		in a cache that will be purged when the layout process
 *		is complete.
 */
int
get_spec_for_name(
	char	*name,
	device_spec_t **id)
{
	dlist_t *item;
	int	error = 0;

	item = dlist_find(_spec_cache, (void *)name,
		compare_name_to_spec_cache_name);

	if (item == NULL) {
	    if ((error = create_device_spec(name, id)) == 0) {

		spec_cache_t *entry = (spec_cache_t *)
		    calloc(1, sizeof (spec_cache_t));

		if (entry == NULL) {
		    destroy_device_spec(*id);
		    error = ENOMEM;
		} else {
		    char *dup = strdup(name);
		    if (dup == NULL) {
			free(entry);
			destroy_device_spec(*id);
			*id = NULL;
			error = ENOMEM;
		    } else {
			entry->name = dup;
			entry->device_spec = *id;
		    }

		    if (error == 0) {
			dlist_t *item = dlist_new_item((void *)entry);
			if (item == NULL) {
			    free(entry);
			    destroy_device_spec(*id);
			    *id = NULL;
			    error = ENOMEM;
			} else {
			    _spec_cache =
				dlist_append(item, _spec_cache, AT_HEAD);
			}
		    }
		}
	    }
	} else {
	    *id = ((spec_cache_t *)item->obj)->device_spec;
	}

	return (error);
}

/*
 * FUNCTION:	spec_includes_device(device_spec_t *spec,
 *			device_spec_t *device)
 *
 * INPUT:	spec	- pointer to a device_spec struct
 *		device	- pointer to a device_spec struct
 *
 * RETURNS:	boolean_t - B_TRUE if the device is included in the spec
 *			 B_FALSE otherwise
 *
 * PURPOSE:	Function which determines if the input device matches the
 *		input spec.
 *
 *		If both specs are of the same type, the appropriate
 *		comparison function is called.
 *
 *		If the two specs are of different types, no comparison
 *		is done and B_FALSE is returned.
 */
boolean_t
spec_includes_device(
	device_spec_t *spec,
	device_spec_t *device)
{
	if ((spec->type == SPEC_TYPE_CTD) && (device->type == SPEC_TYPE_CTD)) {
	    return (ctd_spec_includes_device(spec, device));
	} else if ((spec->type == SPEC_TYPE_RAW) &&
	    (device->type == SPEC_TYPE_RAW)) {
	    return (raw_spec_includes_device(spec, device));
	}

	return (B_FALSE);
}

/*
 * FUNCTION:	ctd_spec_includes_device(device_spec_t *spec,
 *			device_spec_t *device)
 *
 * INPUT:	spec	- pointer to a device_spec struct
 *		device	- pointer to a device_spec struct
 *
 * RETURNS:	boolean_t - B_TRUE if the device is included in the spec
 *			 B_FALSE otherwise
 *
 * PURPOSE:	Function which determines if the input CTD device spec
 *		matches the input CTD spec.
 *
 *		The device_spec_t structs contain component "ids" for
 *		both the specification and the device.
 *
 *		The device must match each of the ids in the spec that
 *		are specified.
 *
 *		spec		devices matched
 *		--------------------------------------------------------
 *		cX		cX, cXtX, cXtXdX, cXtXdXsX, cXdX, cXdXsX
 *		cXtX		cXtX, cXtXdX, cXtXdXsX
 *		cXtXdX		cXtXdX, cXtXdXsX
 *		cXtXdXsX	cXtXdXsX
 *		cXdX		cXdX, cXdXsX
 *		cXdXsX		cXdXsX
 */
static boolean_t
ctd_spec_includes_device(
	device_spec_t *spec,
	device_spec_t *device)
{
	boolean_t match = B_FALSE;

	if (spec->data.ctd->is_ide) {

	    /* valid IDE names are cX, cXdX, cXdXsX, no target */

	    if ((spec->data.ctd->ctrl != ID_UNSPECIFIED) &&
		(spec->data.ctd->lun != ID_UNSPECIFIED) &&
		(spec->data.ctd->slice != ID_UNSPECIFIED)) {

		match = (spec->data.ctd->ctrl == device->data.ctd->ctrl) &&
		    (spec->data.ctd->lun == device->data.ctd->lun) &&
		    (spec->data.ctd->slice == device->data.ctd->slice);

	    } else if ((spec->data.ctd->ctrl != ID_UNSPECIFIED) &&
		(spec->data.ctd->lun != ID_UNSPECIFIED)) {

		match = (spec->data.ctd->ctrl == device->data.ctd->ctrl) &&
		    (spec->data.ctd->lun == device->data.ctd->lun);

	    } else if (spec->data.ctd->ctrl != ID_UNSPECIFIED) {

		match = (spec->data.ctd->ctrl == device->data.ctd->ctrl);

	    }

	} else {

	    /* valid names are cX, cXtX, cXtXdX, cXtXdXsX */

	    if ((spec->data.ctd->ctrl != ID_UNSPECIFIED) &&
		(spec->data.ctd->target != ID_UNSPECIFIED) &&
		(spec->data.ctd->lun != ID_UNSPECIFIED) &&
		(spec->data.ctd->slice != ID_UNSPECIFIED)) {

		match = (spec->data.ctd->ctrl == device->data.ctd->ctrl) &&
		    (spec->data.ctd->target == device->data.ctd->target) &&
		    (spec->data.ctd->lun == device->data.ctd->lun) &&
		    (spec->data.ctd->slice == device->data.ctd->slice);

	    } else if ((spec->data.ctd->ctrl != ID_UNSPECIFIED) &&
		(spec->data.ctd->target != ID_UNSPECIFIED) &&
		(spec->data.ctd->lun != ID_UNSPECIFIED)) {

		match = (spec->data.ctd->ctrl == device->data.ctd->ctrl) &&
		    (spec->data.ctd->target == device->data.ctd->target) &&
		    (spec->data.ctd->lun == device->data.ctd->lun);

	    } else if ((spec->data.ctd->ctrl != ID_UNSPECIFIED) &&
		(spec->data.ctd->target != ID_UNSPECIFIED)) {

		match = (spec->data.ctd->ctrl == device->data.ctd->ctrl) &&
		    (spec->data.ctd->target == device->data.ctd->target);

	    } else if (spec->data.ctd->ctrl != ID_UNSPECIFIED) {

		match = (spec->data.ctd->ctrl == device->data.ctd->ctrl);

	    }
	}

	oprintf(OUTPUT_DEBUG,
		gettext("spec: c(%d) t(%d) d(%d) s(%d) "
			"%s: c(%d) t(%d) d(%d) s(%d)\n"),
		spec->data.ctd->ctrl, spec->data.ctd->target,
		spec->data.ctd->lun, spec->data.ctd->slice,
		(match ? gettext("includes") : gettext("does not include")),
		device->data.ctd->ctrl, device->data.ctd->target,
		device->data.ctd->lun, device->data.ctd->slice);

	return (match);
}

/*
 * FUNCTION:	raw_spec_includes_device(device_spec_t *spec,
 *			device_spec_t *device)
 *
 * INPUT:	spec	- pointer to a device_spec struct
 *		device	- pointer to a device_spec struct
 *
 * RETURNS:	boolean_t - B_TRUE if the device is included in the spec
 *			 B_FALSE otherwise
 *
 * PURPOSE:	Function which determines if the input raw device spec
 *		matches the input spec.
 *
 *		The device_spec_t raw elements are checked.
 *
 *		If the spec's raw device name is exactly contained at the
 *		beginning of the device spec's raw name, then the function
 *		evaluates to true.
 */
static boolean_t
raw_spec_includes_device(
	device_spec_t *spec,
	device_spec_t *device)
{
	return (strncasecmp(spec->data.raw,
			device->data.raw, strlen(spec->data.raw)) == 0);
}

/*
 * FUNCTION:	compare_name_to_spec_cache_name(void *name, void *list_item)
 *
 * INPUT:	name	- opaque pointer to a char * device name
 * 		list_item - opaque pointer to a spec_cache_t entry
 *
 * RETURNS:	int	- 0 - if request is the same as list_item->request
 *			  !0 - otherwise
 *
 * PURPOSE:	dlist_t helper which compares the input device name
 *		to the list_item's device name for equality.
 *
 *		This function is the lookup mechanism for the device_spec
 *		associated with the name.
 */
static int
compare_name_to_spec_cache_name(
	void *name,
	void *list_item)
{
	spec_cache_t *entry = (spec_cache_t *)list_item;

	assert(name != NULL);
	assert(entry != NULL);

	return (string_case_compare((char *)name, entry->name));
}

/*
 * FUNCTION:	destroy_spec_cache_entry(void *entry)
 *
 * INPUT:	entry	- opaque pointer to a spec_cache_t
 *
 * RETURNS:	nothing
 *
 * PURPOSE:	Function which reclaims memory allocated to a
 *		spec_cache_t entry.
 *
 *		Frees memory allocated to hold the CTD name and the
 *		corresponding device_spec_t.
 */
static void
destroy_spec_cache_entry(
	void *obj)
{
	spec_cache_t *entry = (spec_cache_t *)obj;

	if (entry != NULL) {
	    free(entry->name);
	    destroy_device_spec(entry->device_spec);
	    free(entry);
	}
}

/*
 * FUNCTION:	destroy_spec_cache()
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise.
 *
 * PURPOSE:	Function which destroys all entries in the device_spec
 *		cache.
 */
static int
destroy_spec_cache()
{
	dlist_free_items(_spec_cache, destroy_spec_cache_entry);
	_spec_cache = NULL;

	return (0);
}

/*
 * FUNCTION:	get_device_access_name(devconfig_t *request,
 *			dm_descriptor_t desc, char **name)
 *
 * INPUT:	request	- a devconfig_t request
 *		desc	- a dm_descriptor_t device handle
 *
 * OUTPUT:	name	- a char * pointer to hold the preferred name
 *
 * RETURNS:	int	- 0 - if request is the same as list_item->request
 *			  !0 - otherwise
 *
 * PURPOSE:	Utility function to determine which of the possible device
 *		names should be used to access a known available device.
 *
 *		Devices handled are slices and disks.
 *
 *		If the input device is a multipathed disk or slice, it
 *		can have several possible names.  Determine which of the
 *		names should be used based on the input request's available
 *		or unavailable device specifications.
 *
 */
int
get_device_access_name(
	devconfig_t	*request,
	dm_descriptor_t desc,
	char		**name)
{
	int		error = 0;
	boolean_t	avail = B_FALSE;
	dlist_t		*aliases = NULL;

	assert(desc != (dm_descriptor_t)0);

	*name = NULL;

	if ((error = get_display_name(desc, name)) != 0) {
	    return (error);
	}

	if (is_did_name(*name) == B_TRUE) {
	    oprintf(OUTPUT_DEBUG,
		    gettext("device DID name %s is preferred\n"),
		    *name);
	    return (0);
	}

	error = is_named_device_avail(request, *name, B_FALSE, &avail);
	if (error != 0) {
	    return (error);
	}

	if (avail == B_TRUE) {
	    oprintf(OUTPUT_DEBUG,
		    gettext("device name %s is accessible\n"),
		    *name);
	    return (0);
	}

	/* search aliases for an 'available' name, prefer DID names */
	if ((error = get_aliases(desc, &aliases)) == 0) {

	    dlist_t *iter = aliases;
	    char *availname = NULL;
	    char *didname = NULL;

	    for (; (iter != NULL) && (error == 0); iter = iter->next) {

		char *alias = (char *)iter->obj;
		error = is_named_device_avail(request, alias, B_FALSE, &avail);

		if ((error == 0) && (avail == B_TRUE)) {
		    oprintf(OUTPUT_DEBUG,
			    gettext("device alias %s is accessible for %s\n"),
			    alias, *name);

		    availname = alias;

		    if (is_did_name(availname) == B_TRUE) {
			didname = alias;
			break;
		    }
		}
	    }

	    if (error == 0) {
		if (didname != NULL) {
		    *name = didname;
		} else if (availname != NULL) {
		    *name = availname;
		}
	    }
	}

	return (error);
}
