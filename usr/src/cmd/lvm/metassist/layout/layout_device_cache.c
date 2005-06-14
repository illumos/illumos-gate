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

#include <assert.h>
#include <libintl.h>

#include <string.h>
#include <sys/param.h>
#include <sys/types.h>
#include <errno.h>
#include <search.h>

#include "volume_dlist.h"
#include "volume_error.h"
#include "volume_output.h"

#include "layout_device_cache.h"
#include "layout_dlist_util.h"
#include "layout_request.h"

/*
 * Implementation note:
 * The current caches are implemented as linked lists of data
 * structures described below. Cached object lookup uses hsearch()
 * where possible to minimize the inefficiency of linear search.
 */

/*
 * The name and attribute maps use hesarch() for faster lookup
 */
static const uint32_t	MAX_CACHED_OBJECTS = 50000;

/*
 * The attribute cache is maintained as a list of these
 * structs which map a device name to attributes.  The
 * device name is the unique device name returned from
 * the device library, typically a devfs path.  It should
 * not be confused with the "display" name of the device
 * which is typically a CTD or DID name.
 */
typedef struct {
	char		*name;
	nvlist_t	*attrs;
} attr_cache_t;

static dlist_t	*_attr_cache = NULL;

/*
 * The name cache is maintained via a list of these structs
 * which map a descriptor to its name.
 * The descriptor is saved as a string for hsearch()
 */
typedef struct {
	char		*desc;
	char		*name;
} name_cache_t;
static dlist_t *_name_cache = NULL;

/*
 * The desc cache is maintained as a list of these
 * structs which map a device display name (CTD or DID)
 * or alias to a descriptor.
 */
typedef struct {
	char		*name;
	dm_descriptor_t desc;
} desc_cache_t;

static dlist_t	*_desc_cache = NULL;

/*
 * Since each of the lookup caches shares the same hsearch()
 * hash table, the names used as lookup keys for the desc_cache_t
 * and attr_cache_t may cause collisions.
 *
 * The desc_cache_t map alters the device name by prepending
 * this string to avoid collisions.
 */
static const char *DESC_CACHE_KEY_PREFIX = "desc_cache";

/*
 * The set of descriptors to be returned to libdiskmgt is
 * maintained via a list of dm_descriptor_t handles.
 * descriptors are added by new_descriptor() and
 * cache_descriptor_to_free().
 */
typedef struct {
	dm_descriptor_t desc;
	boolean_t	virtual;
} desc_free_t;
static dlist_t	*_desc_to_free = NULL;

static char	*find_cached_name(dm_descriptor_t desc);
static nvlist_t *find_cached_attrs(char *name);

static int	add_descriptor_to_free(dm_descriptor_t desc);

static void	release_name_cache();
static void	release_desc_to_free_cache();
static void	release_attribute_cache();
static void	release_descriptor_cache();

static uint32_t interal_name_count = 0;

/*
 * FUNCTION:	create_device_caches()
 *
 * PURPOSE:	Helper which initializes the module's private data
 *		structures.
 */
int
create_device_caches()
{
	if (hcreate(MAX_CACHED_OBJECTS) == 0) {
	    return (ENOMEM);
	}

	return (0);
}

/*
 * FUNCTION:	release_device_caches()
 *
 * PURPOSE:	Helper which cleans up memory allocated to the module's
 *		private data structures.
 */
int
release_device_caches()
{
	release_name_cache();
	release_desc_to_free_cache();
	release_attribute_cache();
	release_descriptor_cache();

	return (0);
}

/*
 * FUNCTION:	free_desc_cache_object(void *obj)
 *
 * INPUT:	obj	- opaque pointer
 *
 * PURPOSE:	Frees memory associated with an entry in the
 *		desc cache.
 *
 *		Assumes that the input object is a pointer
 *		to a desc_cache_t struct.
 */
static void
free_desc_cache_object(
	void	*obj)
{
	if (obj == NULL) {
	    return;
	}

	free(((desc_cache_t *)obj)->name);
	free(obj);
}
/*
 * FUNCTION:	release_descriptor_cache()
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Frees all entries in the name cache.
 */
static void
release_descriptor_cache()
{
	oprintf(OUTPUT_DEBUG,
		gettext("  destroying descriptor cache (%d items)\n"),
		dlist_length(_desc_cache));

	dlist_free_items(_desc_cache, free_desc_cache_object);
	_desc_cache = NULL;
}

/*
 * FUNCTION:	add_cached_descriptor(char *name, dm_descriptor_t desc)
 *
 * INPUT:	name	- a device name
 *		desc	- a dm_descriptor_t handle
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Adds an entry to the descriptor cache using the input
 *		descriptor and name.
 *
 * 		Note that all of the lookup caches shares the same hsearch()
 *		hash table and that the names used as lookup keys for the
 *		desc_cache_t and attr_cache_t cause collisions.
 *
 *		The desc_cache_t map alters the device name to avoid collisions.
 */
int
add_cached_descriptor(
	char		*name,
	dm_descriptor_t	desc)
{
	desc_cache_t	*dcp;
	char		buf[MAXNAMELEN+1];
	dlist_t		*item;
	ENTRY		entry;

	if ((dcp = (desc_cache_t *)
	    calloc(1, sizeof (desc_cache_t))) == NULL) {
	    return (ENOMEM);
	}

	dcp->desc = desc;

	(void) snprintf(buf, MAXNAMELEN, "%s-%s", DESC_CACHE_KEY_PREFIX, name);
	dcp->name = strdup(buf);
	if (dcp->name == NULL) {
	    free(dcp);
	    return (ENOMEM);
	}

	/*
	 * insert into the hashtable... ignore the return from hsearch(),
	 * there is no existing entry corresponding to desc since the
	 * map was already searched just before this function is called,
	 * see get_name() below
	 */
	entry.key  = dcp->name;
	entry.data = (void *)dcp;
	(void) hsearch(entry, ENTER);

	/* insert into the list cache... */
	if ((item = dlist_new_item((void *)dcp)) == NULL) {
	    free(dcp);
	    return (ENOMEM);
	}

	_desc_cache = dlist_append(item, _desc_cache, AT_HEAD);

	return (0);
}

/*
 * FUNCTION:	dm_descriptor_t find_cached_descriptor(char *name)
 *
 * INPUT:	char * - pointer to a name or alias.
 *
 * RETURNS:	dm_descriptor_t - dm_descriptor_t handle cached under the
 *			input name if a match is found.  A null descriptor
 *			is returned if no match is found.
 *
 * PURPOSE:	Searches for the desc that has been cached for
 *		the input device name.
 *
 * 		Note that all of the lookup caches shares the same hsearch()
 *		hash table and that the names used as lookup keys for the
 *		desc_cache_t and attr_cache_t cause collisions.
 *
 *		The desc_cache_t map alters the device name to avoid collisions.
 */
dm_descriptor_t
find_cached_descriptor(
	char		*name)
{
	ENTRY		item;
	ENTRY		*cached_item = NULL;
	char		buf[MAXNAMELEN+1];
	dm_descriptor_t	desc = (dm_descriptor_t)0;

	(void) snprintf(buf, MAXNAMELEN, "%s-%s", DESC_CACHE_KEY_PREFIX, name);
	item.key = buf;

	/* get descriptor associated with this name */
	if ((cached_item = hsearch(item, FIND)) != NULL) {
	    /* LINTED */
	    desc = ((desc_cache_t *)cached_item->data)->desc;
	}

	return (desc);
}

/*
 * FUNCTION:	free_name_cache_object(void *obj)
 *
 * INPUT:	obj	- opaque pointer
 *
 * PURPOSE:	Frees memory associated with an entry in the
 *		name cache.
 *
 *		Assumes that the input object is a pointer
 *		to a name_cache_t struct.
 */
static void
free_name_cache_object(
	void	*obj)
{
	if (obj == NULL) {
	    return;
	}

	free(((name_cache_t *)obj)->desc);
	free(((name_cache_t *)obj)->name);
	free(obj);
}

/*
 * FUNCTION:	release_name_cache()
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Frees all entries in the name cache.
 */
static void
release_name_cache()
{
	oprintf(OUTPUT_DEBUG,
		gettext("  destroying name cache (%d items)\n"),
		dlist_length(_name_cache));

	dlist_free_items(_name_cache, free_name_cache_object);
	_name_cache = NULL;
}

/*
 * FUNCTION:	add_cached_name(dm_descriptor_t desc, char *name)
 *
 * INPUT:	desc	- a dm_descriptor_t handle
 *		name	- a device name
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Adds an entry to the name cache using the input
 *		descriptor and name.
 */
int
add_cached_name(
	dm_descriptor_t	desc,
	char		*name)
{
	name_cache_t	*ncp;
	char		buf[MAXNAMELEN+1];
	dlist_t		*item;
	ENTRY		entry;

	if ((ncp = (name_cache_t *)
	    calloc(1, sizeof (name_cache_t))) == NULL) {
	    return (ENOMEM);
	}

	(void) snprintf(buf, MAXNAMELEN, "%llu", desc);
	ncp->desc = strdup(buf);
	if (ncp->desc == NULL) {
	    free(ncp);
	    return (ENOMEM);
	}

	ncp->name = strdup(name);
	if (ncp->name == NULL) {
	    free(ncp->desc);
	    free(ncp);
	    return (ENOMEM);
	}

	/*
	 * insert into the hashtable... ignore the return from hsearch(),
	 * there is no existing entry corresponding to desc since the
	 * map was already searched just before this function is called,
	 * see get_name() below
	 */
	entry.key  = ncp->desc;
	entry.data = (void *)ncp;
	(void) hsearch(entry, ENTER);

	/* insert into the list cache... */
	if ((item = dlist_new_item((void *)ncp)) == NULL) {
	    free(ncp->desc);
	    free(ncp->name);
	    free(ncp);
	    return (ENOMEM);
	}

	_name_cache = dlist_append(item, _name_cache, AT_HEAD);

	return (0);
}

/*
 * FUNCTION:	char *find_cached_name(dm_descriptor_t desc)
 *
 * INPUT:	desc	- a dm_descriptor_t handle
 *
 * RETURNS:	char * - pointer to the name cached for the descriptor.
 *			 Null otherwise.
 *
 * PURPOSE:	Searches for the name that has been cached for
 *		the input dm_descriptor_t.
 *
 *		Search linked list.
 */
static char *
find_cached_name(
	dm_descriptor_t	desc)
{
	char		buf[MAXNAMELEN+1];
	ENTRY		item;
	ENTRY		*cached_item = NULL;
	char		*name = NULL;

	(void) snprintf(buf, MAXNAMELEN, "%llu", desc);
	item.key = buf;

	/* get name associated with this descriptor */
	if ((cached_item = hsearch(item, FIND)) != NULL) {
	    /* LINTED */
	    name = ((name_cache_t *)cached_item->data)->name;
	}

	return (name);
}

/*
 * FUNCTION:	get_name(dm_descriptor_t desc,
 *			char_t **name)
 *
 * INPUT:	desc	- a dm_descriptor_t handle
 *
 * OUTPUT:	name	- pointer to char * to hold the name
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Searches for the name that has been cached for the
 *		input dm_descriptor_t.
 *
 *		Names are cached using the dm_descriptor.
 *		If no name has yet been cached, it is retrieved from
 *		libdiskmgt and added to the cache.
 *
 *		Names are cached so that all name strings obtained from
 *		libdiskmgt will get properly released when layout completes.
 */
int
get_name(
	dm_descriptor_t	desc,
	char		**name)
{

	int		dm_free = 1;
	int		error = 0;

	if ((desc != (dm_descriptor_t)0) &&
	    (*name = find_cached_name(desc)) == NULL) {

	    /* not in descriptor->name cache/map, add it */

	    if (is_virtual_slice(desc) != B_TRUE) {

		dm_desc_type_t	type;

		*name = dm_get_name(desc, &error);
		if (error != 0) {
		    volume_set_error(
			    gettext("failed to get name for descriptor: %d\n"),
			    error);
		    return (-1);
		}

		/*
		 * some devices can be unnamed...
		 * assign a unique internal name if necessary
		 */
		if (*name == NULL) {
		    char buf[MAXNAMELEN];

		    dm_free = 0;
		    (void) snprintf(buf, MAXNAMELEN-1, "temp-name-%lu",
			    interal_name_count++);
		    *name = strdup(buf);
		    if (*name == NULL) {
			volume_set_error(
			    gettext("failed to get name for descriptor: %d\n"),
			    errno);
			return (-1);
		    }
		    oprintf(OUTPUT_DEBUG,
			    gettext("unnamed descriptor %llu assigned %s\n"),
			    desc, *name);
		}

		/*
		 * media can have the same name as the associated drive
		 * which hoses the attribute caching scheme, so unique-ify
		 */
		if ((type = dm_get_type(desc)) == DM_MEDIA) {
		    char buf[MAXNAMELEN];
		    (void) snprintf(buf, MAXNAMELEN-1, "%s-%d", *name, type);
		    error = add_cached_name(desc, buf);
		} else {
		    error = add_cached_name(desc, *name);
		}
		if (dm_free)
		    dm_free_name(*name);
		else
		    free(*name);

		if (error == 0) {
		    /* return copied name */
		    *name = find_cached_name(desc);
		} else {
		    *name = NULL;
		}
	    }
	}

	return (error);
}

/*
 * FUNCTION:	free_attr_cache_object(void *obj)
 *
 * INPUT:	obj	- opaque pointer
 *
 * PURPOSE:	Frees memory associated with an entry in the
 *		attribute cache.
 *
 *		Assumes that the input object is a pointer
 *		to a attr_cache_t struct.
 */
static void
free_attr_cache_object(
	void		*obj)
{
	if (obj == NULL) {
	    return;
	}

	nvlist_free(((attr_cache_t *)obj)->attrs);
	free(obj);
}

/*
 * FUNCTION:	release_attribute_cache()
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Frees all entries in the attribute cache.
 */
void
release_attribute_cache()
{
	oprintf(OUTPUT_DEBUG,
		gettext("  destroying attribute cache (%d items)\n"),
		dlist_length(_attr_cache));

	dlist_free_items(_attr_cache, free_attr_cache_object);
	_attr_cache = NULL;

	/* cleanup attribute cache lookup hashtable */
	hdestroy();
}

/*
 * FUNCTION:	add_cached_attributes(char *name, nvlist_t *attrs)
 *
 * INPUT:	name	- a device name
 *		attrs	- pointer to an nvlist_t attribute structure
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Adds an entry to the attribute cache using the input
 *		name and attributes.
 *
 *		Uses a linked list to cache attributes.
 *		Keeps a parallel hash table for faster lookup.
 */
int
add_cached_attributes(
	char		*name,
	nvlist_t 	*attrs)
{
	attr_cache_t	*acp = NULL;
	dlist_t		*item = NULL;
	ENTRY		*exist = NULL;
	ENTRY		entry;

	/* insert into the hashtable... */
	entry.key  = name;
	entry.data = (void *)attrs;

	if ((exist = hsearch(entry, ENTER)) != NULL) {
	    /* replace the existing attrs entry */
	    exist->data = (void *)attrs;
	}

	if ((acp = (attr_cache_t *)calloc(1, sizeof (attr_cache_t))) == NULL) {
	    return (ENOMEM);
	}

	acp->name = name;
	acp->attrs = attrs;

	/* and cache of attr structs to be freed */
	if ((item = dlist_new_item((void *)acp)) == NULL) {
	    free(acp);
	    return (ENOMEM);
	}

	_attr_cache = dlist_append(item, _attr_cache, AT_HEAD);

	return (0);
}

/*
 * FUNCTION:	nvlist_t *find_cached_attrs(char *name)
 *
 * INPUT:	name	- a device name
 *
 * RETURNS:	nvlist_t * - pointer to an nvlist_t attribute structure
 *			cached under 'name'.  Null otherwise.
 *
 * PURPOSE:	Searches for the nvlist attributes that have been
 *		cached for the input name.
 */
static nvlist_t *
find_cached_attrs(
	char		*name)
{
	ENTRY		item;
	ENTRY		*cached_item = NULL;
	nvlist_t	*attrs = NULL;

	item.key = name;

	/* get attributes cached under this name */
	if ((cached_item = hsearch(item, FIND)) != NULL) {
	    /* LINTED */
	    attrs = (nvlist_t *)cached_item->data;
	}

	return (attrs);
}

/*
 * FUNCTION:	get_cached_attributes(dm_descriptor_t desc,
 *			nvlist_t **attrs)
 *
 * INPUT:	desc	- a dm_descriptor_t handle
 *
 * OUTPUT:	attrs	- pointer to an nvlist_t attribute structure
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Searches for the nvlist attributes that have been
 *		cached for the input dm_descriptor_t.
 *
 *		Attributes are cached using the name associated with
 *		the descriptor.  If no attributes have yet been cached
 *		they are retrieved from libdiskmgt and added to the
 *		cache.
 *
 *		Attributes are cached so that layout may store transient
 *		data relevant to the layout process.
 */
int
get_cached_attributes(
	dm_descriptor_t	desc,
	nvlist_t 	**attrs)
{
	int		error = 0;
	char		*name = NULL;

	if ((desc != (dm_descriptor_t)0) &&
	    (error = get_name(desc, &name)) == 0) {

	    if ((*attrs = find_cached_attrs(name)) == NULL) {
		/* get attrs and cache them */
		*attrs = dm_get_attributes(desc, &error);
		if (error == 0) {
		    error = add_cached_attributes(name, *attrs);
		}
	    }
	}

	return (error);
}

/*
 * FUNCTION:	new_descriptor(dm_descriptor_t *desc)
 *
 * INPUT:	desc	- a pointer to a dm_descriptor_t to hold
 *				the result.
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Allocates a new dm_descriptor_t handle.
 *
 *		This is necessary because the process may have to
 *		create "virtual" objects to represent devices that
 *		do not yet exist on the system and hence are unknown
 *		to libdiskmgt and diskmgtd.
 *
 *		A unique handle is created for such objects and may
 *		be used by layout to access the virtual devices as
 *		if they were obtained from libdiskmgt.
 */
int
new_descriptor(
	dm_descriptor_t	*desc)
{
	desc_free_t	*dfp;
	dlist_t		*item;

	*desc = NULL;

	if ((dfp = (desc_free_t *)
	    calloc(1, sizeof (desc_free_t))) == NULL) {
	    return (ENOMEM);
	}

	dfp->desc = (uintptr_t)dfp;
	dfp->virtual = B_TRUE;

	if ((item = dlist_new_item((void *)dfp)) == NULL) {
	    free(dfp);
	    return (ENOMEM);
	}

	_desc_to_free = dlist_append(item, _desc_to_free, AT_HEAD);

	*desc = (uintptr_t)dfp;

	return (0);
}

/*
 * FUNCTION:	add_descriptors_to_free(dm_descriptor_t *desc)
 *
 * INPUT:	desc	- an array of dm_descriptor_t handles from
 *				libdiskmgt
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Function which accepts an array of dm_descriptor_t handles
 *		that need to be returned to libdiskmgt.
 *
 *		The array is iterated and each handle is passed to
 *		add_descriptor_to_free.
 */
int
add_descriptors_to_free(
	dm_descriptor_t *desc_list)
{
	int i = 0;

	if (desc_list != NULL) {
	    for (i = 0; desc_list[i] != NULL; i++) {
		(void) add_descriptor_to_free(desc_list[i]);
	    }
	}

	return (0);
}

/*
 * FUNCTION:	add_descriptor_to_free(dm_descriptor_t desc)
 *
 * INPUT:	desc	- dm_descriptor_t handle from libdiskmgt
 *
 * RETURNS:	int	- 0 on success
 *			 !0 otherwise
 *
 * PURPOSE:	Remembers a dm_descriptor_t handle which needs to be
 *		returned to libdiskmgt. These handles represent memory
 *		allocated by the the diskmgtd and must be returned in
 *		order for that memory to be released.
 *
 *		The handles are cached for the duration of layout
 *	        processing so that layout is guaranteed to have
 *		unique handles for all objects received from
 *		libdiskmgt.
 *
 *		The caching is accomplished by adding the handle to
 *		a list of desc_free_t structs.
 */
static int
add_descriptor_to_free(
	dm_descriptor_t desc)
{
	desc_free_t	*dfp = NULL;
	dlist_t		*item = NULL;

	if (desc == (dm_descriptor_t)0) {
	    return (0);
	}

	if (is_virtual_slice(desc) == B_TRUE) {
	    /* don't return virtual slice descriptors to libdiskmgt */
	    return (0);
	}

	if ((dfp = calloc(1, sizeof (desc_free_t))) == NULL) {
	    return (ENOMEM);
	}

	dfp->desc = desc;
	dfp->virtual = B_FALSE;

	if ((item = dlist_new_item((void *)dfp)) == NULL) {
	    free(dfp);
	    return (ENOMEM);
	}

	_desc_to_free = dlist_append(item, _desc_to_free, AT_HEAD);

	return (0);
}

/*
 * FUNCTION:	release_desc_to_free_cache()
 *
 * PURPOSE:	Frees all entries in the desc_to_free cache.
 *
 *		Iterates the _desc_to_free list and builds an
 *		array with all dm_descriptor_t handles that were
 *		obtained from libdiskmgt.  Passing this array to
 *		dm_free_descriptors() is faster than calling
 *		dm_free_descriptor() to free individual	handles.
 */
void
release_desc_to_free_cache()
{
	dlist_t *iter;
	dm_descriptor_t *array;
	int i = 0;

	oprintf(OUTPUT_DEBUG,
		gettext("  destroying desc_to_free cache (%d items)\n"),
		dlist_length(_desc_to_free));

	array = (dm_descriptor_t *)calloc(
		dlist_length(_desc_to_free) + 1, sizeof (dm_descriptor_t));

	if (array != NULL) {
	    for (iter = _desc_to_free; iter != NULL; iter = iter->next) {
		desc_free_t *dfp = (desc_free_t *)iter->obj;
		if (dfp->virtual == B_FALSE) {
		    array[i++] = dfp->desc;
		}
	    }
	    array[i] = (dm_descriptor_t)0;
	    dm_free_descriptors(array);
	}

	/*
	 * If the calloc failed, the descriptors aren't explicitly freed,
	 * but the libdiskmgt daemon will eventually reclaim them after
	 * a period of inactivity.
	 */
	dlist_free_items(_desc_to_free, free);

	_desc_to_free = NULL;
}
