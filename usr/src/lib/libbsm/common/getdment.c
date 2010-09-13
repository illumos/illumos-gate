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
 * Copyright (c) 1996, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 */

#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <bsm/devices.h>
#include <bsm/devalloc.h>

char *strtok_r(char *, const char *, char **);

/* externs from getdaent.c */
extern char *trim_white(char *);
extern int pack_white(char *);
extern char *getdadmfield(char *, char *);
extern int getdadmline(char *, int, FILE *);

static struct _dmapbuff {
	FILE		*_dmapf;	/* for /etc/security/device_maps */
	devmap_t	_interpdevmap;
	char		_interpdmline[DA_BUFSIZE + 1];
	char		*_DEVMAP;
} *__dmapbuff;

#define	dmapf	(_dmap->_dmapf)
#define	interpdevmap	(_dmap->_interpdevmap)
#define	interpdmline	(_dmap->_interpdmline)
#define	DEVMAPS_FILE	(_dmap->_DEVMAP)

devmap_t	*dmap_interpret(char *, devmap_t *);
static devmap_t	*dmap_interpretf(char *, devmap_t *);
static devmap_t *dmap_dlexpand(devmap_t *);
static int dmap_resolve_link(char *devpath, char **devfs_path);

int	dmap_matchdev(devmap_t *, char *);
int	dmap_matchname(devmap_t *, char *);


/*
 * _dmapalloc -
 *	allocates common buffers and structures.
 *	returns pointer to the new structure, else returns NULL on error.
 */
static struct _dmapbuff *
_dmapalloc(void)
{
	struct _dmapbuff *_dmap = __dmapbuff;

	if (_dmap == NULL) {
		_dmap = (struct _dmapbuff *)calloc((unsigned)1,
		    (unsigned)sizeof (*__dmapbuff));
		if (_dmap == NULL)
			return (NULL);
		DEVMAPS_FILE = "/etc/security/device_maps";
		dmapf = NULL;
		__dmapbuff = _dmap;
	}

	return (_dmap);
}

/*
 * setdmapent -
 *	rewinds the device_maps file to the beginning.
 */
void
setdmapent(void)
{
	struct _dmapbuff *_dmap = _dmapalloc();

	if (_dmap == NULL)
		return;
	if (dmapf == NULL)
		dmapf = fopen(DEVMAPS_FILE, "rF");
	else
		rewind(dmapf);
}

/*
 * enddmapent -
 *	closes device_maps file.
 */
void
enddmapent(void)
{
	struct _dmapbuff *_dmap = _dmapalloc();

	if (_dmap == NULL)
		return;
	if (dmapf != NULL) {
		(void) fclose(dmapf);
		dmapf = NULL;
	}
}

void
freedmapent(devmap_t *dmap)
{
	char	**darp;

	if ((darp = dmap->dmap_devarray) != NULL) {
		while (*darp != NULL)
			free(*darp++);
		free(dmap->dmap_devarray);
		dmap->dmap_devarray = NULL;
	}
}

/*
 * setdmapfile -
 *	changes the default device_maps file to the one specified.
 *	It does not close the previous file. If this is desired, enddmapent
 *	should be called prior to setdampfile.
 */
void
setdmapfile(char *file)
{
	struct _dmapbuff *_dmap = _dmapalloc();

	if (_dmap == NULL)
		return;
	if (dmapf != NULL) {
		(void) fclose(dmapf);
		dmapf = NULL;
	}
	DEVMAPS_FILE = file;
}

/*
 * getdmapent -
 * 	When first called, returns a pointer to the first devmap_t structure
 * 	in device_maps; thereafter, it returns a pointer to the next devmap_t
 *	structure in the file. Thus successive calls can be used to read the
 *	entire file.
 *	call to getdmapent should be bracketed by setdmapent and enddmapent.
 * 	returns pointer to devmap_t found, else returns NULL if no entry found
 * 	or on error.
 */
devmap_t *
getdmapent(void)
{
	devmap_t		*dmap;
	struct _dmapbuff 	*_dmap = _dmapalloc();

	if ((_dmap == 0) || (dmapf == NULL))
		return (NULL);

	while (getdadmline(interpdmline, (int)sizeof (interpdmline),
	    dmapf) != 0) {
		if ((dmap = dmap_interpret(interpdmline,
		    &interpdevmap)) == NULL)
			continue;
		return (dmap);
	}

	return (NULL);
}

/*
 * getdmapnam -
 *	searches from the beginning of device_maps for the device specified by
 *	its name.
 *	call to getdmapnam should be bracketed by setdmapent and enddmapent.
 * 	returns pointer to devmapt_t for the device if it is found, else
 * 	returns NULL if device not found or in case of error.
 */
devmap_t *
getdmapnam(char *name)
{
	devmap_t		*dmap;
	struct _dmapbuff	*_dmap = _dmapalloc();

	if ((name == NULL) || (_dmap == 0) || (dmapf == NULL))
		return (NULL);

	while (getdadmline(interpdmline, (int)sizeof (interpdmline),
	    dmapf) != 0) {
		if (strstr(interpdmline, name) == NULL)
			continue;
		if ((dmap = dmap_interpretf(interpdmline,
		    &interpdevmap)) == NULL)
			continue;
		if (dmap_matchname(dmap, name)) {
			if ((dmap = dmap_dlexpand(dmap)) == NULL)
				continue;
			enddmapent();
			return (dmap);
		}
		freedmapent(dmap);
	}

	return (NULL);
}

/*
 * getdmapdev -
 *	searches from the beginning of device_maps for the device specified by
 *	its logical name.
 *	call to getdmapdev should be bracketed by setdmapent and enddmapent.
 * 	returns  pointer to the devmap_t for the device if device is found,
 *	else returns NULL if device not found or on error.
 */
devmap_t *
getdmapdev(char *dev)
{
	devmap_t		*dmap;
	struct _dmapbuff	*_dmap = _dmapalloc();

	if ((dev == NULL) || (_dmap == 0) || (dmapf == NULL))
		return (NULL);

	while (getdadmline(interpdmline, (int)sizeof (interpdmline),
	    dmapf) != 0) {
		if ((dmap = dmap_interpret(interpdmline,
		    &interpdevmap)) == NULL)
			continue;
		if (dmap_matchdev(dmap, dev)) {
			enddmapent();
			return (dmap);
		}
		freedmapent(dmap);
	}

	return (NULL);
}

/*
 * getdmaptype -
 *	searches from the beginning of device_maps for the device specified by
 *	its type.
 *	call to getdmaptype should be bracketed by setdmapent and enddmapent.
 * 	returns pointer to devmap_t found, else returns NULL if no entry found
 * 	or on error.
 */
devmap_t *
getdmaptype(char *type)
{
	devmap_t		*dmap;
	struct _dmapbuff	*_dmap = _dmapalloc();

	if ((type == NULL) || (_dmap == 0) || (dmapf == NULL))
		return (NULL);

	while (getdadmline(interpdmline, (int)sizeof (interpdmline),
	    dmapf) != 0) {
		if ((dmap = dmap_interpretf(interpdmline,
		    &interpdevmap)) == NULL)
			continue;
		if (dmap->dmap_devtype != NULL &&
		    strcmp(type, dmap->dmap_devtype) == 0) {
			if ((dmap = dmap_dlexpand(dmap)) == NULL)
				continue;
			return (dmap);
		}
		freedmapent(dmap);
	}

	return (NULL);
}

/*
 * dmap_match_one_dev -
 *    Checks if the specified devmap_t contains strings
 *    for the same link as the device specified.
 *
 *    Returns 1 for a match, else returns 0.
 */
static int
dmap_match_one_dev(devmap_t *dmap, char *dev)
{
	char **dva;
	char *dv;
	char *dmap_link;
	char *dev_link;
	char stage_link[PATH_MAX + 1];

	if (dmap->dmap_devarray == NULL)
		return (0);

	for (dva = dmap->dmap_devarray; (dv = *dva) != NULL; dva++) {
		if (strstr(dev, dv) != NULL)
			return (1);
	}
	/* check if both refer to same physical device */
	(void) strncpy(stage_link, dmap->dmap_devarray[0], sizeof (stage_link));
	if (dmap_resolve_link(stage_link, &dmap_link) != 0)
		return (0);
	(void) strncpy(stage_link, dev, sizeof (stage_link));
	if (dmap_resolve_link(stage_link, &dev_link) != 0) {
		free(dmap_link);
		return (0);
	}
	if (strcmp(dev_link, dmap_link) == 0) {
		free(dmap_link);
		free(dev_link);
		return (1);
	}
	free(dmap_link);
	free(dev_link);
	return (0);
}

/*
 * dmap_matchdev -
 * 	checks if the specified devmap_t is for the device specified.
 *	returns 1 if it is, else returns 0.
 */
int
dmap_matchdev(devmap_t *dmap, char *dev)
{
	char **dva;
	char *dv;

	if (dmap->dmap_devarray == NULL)
		return (0);
	for (dva = dmap->dmap_devarray; (dv = *dva) != NULL; dva ++) {
		if (strcmp(dv, dev) == 0)
			return (1);
	}

	return (0);
}

/*
 * Requires a match of the /dev/? links, not just the logical devname
 * Returns 1 for match found, 0 for match not found, 2 for invalid arguments.
 *
 * Also looks for an instance number at the end of the logical name, and
 * puts instance or -1 into *num.
 */
int
dmap_exact_dev(devmap_t *dmap, char *dev, int *num)
{
	char *dv;

	if ((dev == NULL) || (dmap->dmap_devname == NULL))
		return (2);
	dv = dmap->dmap_devname;
	dv +=  strcspn(dmap->dmap_devname, "0123456789");
	if (sscanf(dv, "%d", num) != 1)
		*num = -1;
	/* during some add processes, dev can be shorter than dmap */
	return (dmap_match_one_dev(dmap, dev));
}

/*
 * dmap_matchtype -
 *	checks if the specified devmap_t is for the device specified.
 *	returns 1 if it is, else returns 0.
 */
int
dmap_matchtype(devmap_t *dmap, char *type)
{
	if ((dmap->dmap_devtype == NULL) || (type == NULL))
		return (0);

	return ((strcmp(dmap->dmap_devtype, type) == 0));
}

/*
 * dmap_matchname -
 * 	checks if the specified devmap_t is for the device specified.
 * 	returns 1 if it is, else returns 0.
 */
int
dmap_matchname(devmap_t *dmap, char *name)
{
	if (dmap->dmap_devname == NULL)
		return (0);

	return ((strcmp(dmap->dmap_devname, name) == 0));
}

/*
 * Temporarily duplicated directly from libdevinfo's is_minor_node(),
 * and renamed, because we cannot link this from libdevinfo.
 *
 * To be resolved in a couple of builds.
 *
 * The real fix is to move device allocation out of libbsm.
 *
 * returns 1 if contents is a minor node in /devices.
 * If mn_root is not NULL, mn_root is set to:
 *	if contents is a /dev node, mn_root = contents
 *			OR
 *	if contents is a /devices node, mn_root set to the '/'
 *	following /devices.
 */
static int
dmap_minor_root(const char *contents, const char **mn_root)
{
	char *ptr, *prefix;

	prefix = "../devices/";

	if ((ptr = strstr(contents, prefix)) != NULL) {

		/* mn_root should point to the / following /devices */
		if (mn_root != NULL) {
			*mn_root = ptr += strlen(prefix) - 1;
		}
		return (1);
	}

	prefix = "/devices/";

	if (strncmp(contents, prefix, strlen(prefix)) == 0) {

		/* mn_root should point to the / following /devices/ */
		if (mn_root != NULL) {
			*mn_root = contents + strlen(prefix) - 1;
		}
		return (1);
	}

	if (mn_root != NULL) {
		*mn_root = contents;
	}
	return (0);
}

/*
 * Temporarily duplicated directly from libdevinfo's devfs_resolve_link(),
 * and renamed, because we cannot link this from libdevinfo now, and will
 * create a sensible solution in the near future.
 *
 * returns 0 if resolved, -1 otherwise.
 * devpath: Absolute path to /dev link
 * devfs_path: Returns malloced string: /devices path w/out "/devices"
 */
static int
dmap_resolve_link(char *devpath, char **devfs_path)
{
	char contents[PATH_MAX + 1];
	char stage_link[PATH_MAX + 1];
	char *ptr;
	int linksize;
	char *slashdev = "/dev/";

	if (devfs_path) {
		*devfs_path = NULL;
	}

	linksize = readlink(devpath, contents, PATH_MAX);

	if (linksize <= 0) {
		return (-1);
	} else {
		contents[linksize] = '\0';
	}

	/*
	 * if the link contents is not a minor node assume
	 * that link contents is really a pointer to another
	 * link, and if so recurse and read its link contents.
	 */
	if (dmap_minor_root((const char *)contents, (const char **)&ptr) !=
	    1) {
		if (strncmp(contents, slashdev, strlen(slashdev)) == 0)  {
			/* absolute path, starting with /dev */
			(void) strcpy(stage_link, contents);
		} else {
			/* relative path, prefix devpath */
			if ((ptr = strrchr(devpath, '/')) == NULL) {
				/* invalid link */
				return (-1);
			}
			*ptr = '\0';
			(void) strcpy(stage_link, devpath);
			*ptr = '/';
			(void) strcat(stage_link, "/");
			(void) strcat(stage_link, contents);

		}
		return (dmap_resolve_link(stage_link, devfs_path));
	}

	if (devfs_path) {
		*devfs_path = strdup(ptr);
		if (*devfs_path == NULL) {
			return (-1);
		}
	}

	return (0);
}

/*
 * dmap_physname: path to /devices device
 * Returns:
 *	strdup'd (i.e. malloc'd) real device file if successful
 *      NULL on error
 */
char *
dmap_physname(devmap_t *dmap)
{
	char *oldlink;
	char stage_link[PATH_MAX + 1];

	if ((dmap == NULL) || (dmap->dmap_devarray == NULL) ||
	    (dmap->dmap_devarray[0] == NULL))
		return (NULL);

	(void) strncpy(stage_link, dmap->dmap_devarray[0], sizeof (stage_link));

	if (dmap_resolve_link(stage_link, &oldlink) == 0)
		return (oldlink);
	return (NULL);
}

/*
 * dm_match -
 *	calls dmap_matchname or dmap_matchtype as appropriate.
 */
int
dm_match(devmap_t *dmap, da_args *dargs)
{
	if (dargs->devinfo->devname)
		return (dmap_matchname(dmap, dargs->devinfo->devname));
	else if (dargs->devinfo->devtype)
		return (dmap_matchtype(dmap, dargs->devinfo->devtype));

	return (0);
}

/*
 * dmap_interpret -
 *	calls dmap_interpretf and dmap_dlexpand to parse devmap_t line.
 *	returns  pointer to parsed devmapt_t entry, else returns NULL on error.
 */
devmap_t  *
dmap_interpret(char *val, devmap_t *dm)
{
	if (dmap_interpretf(val, dm) == NULL)
		return (NULL);

	return (dmap_dlexpand(dm));
}

/*
 * dmap_interpretf -
 * 	parses string "val" and initializes pointers in the given devmap_t to
 * 	fields in "val".
 * 	returns pointer to updated devmap_t.
 */
static devmap_t  *
dmap_interpretf(char *val, devmap_t *dm)
{
	dm->dmap_devname = getdadmfield(val, KV_TOKEN_DELIMIT);
	dm->dmap_devtype = getdadmfield(NULL, KV_TOKEN_DELIMIT);
	dm->dmap_devlist = getdadmfield(NULL, KV_TOKEN_DELIMIT);
	dm->dmap_devarray = NULL;
	if (dm->dmap_devname == NULL ||
	    dm->dmap_devtype == NULL ||
	    dm->dmap_devlist == NULL)
		return (NULL);

	return (dm);
}

/*
 * dmap_dlexpand -
 * 	expands dmap_devlist of the form `devlist_generate`
 *	returns unexpanded form if there is no '\`' or in case of error.
 */
static devmap_t *
dmap_dlexpand(devmap_t *dmp)
{
	char	tmplist[DA_BUFSIZE + 1];
	char	*cp, *cpl, **darp;
	int	count;
	FILE	*expansion;

	dmp->dmap_devarray = NULL;
	if (dmp->dmap_devlist == NULL)
		return (NULL);
	if (*(dmp->dmap_devlist) != '`') {
		(void) strcpy(tmplist, dmp->dmap_devlist);
	} else {
		(void) strcpy(tmplist, dmp->dmap_devlist + 1);
		if ((cp = strchr(tmplist, '`')) != NULL)
			*cp = '\0';
		if ((expansion = popen(tmplist, "rF")) == NULL)
			return (NULL);
		count = fread(tmplist, 1, sizeof (tmplist) - 1, expansion);
		(void) pclose(expansion);
		tmplist[count] = '\0';
	}

	/* cleanup the list */
	count = pack_white(tmplist);
	dmp->dmap_devarray = darp =
	    (char **)malloc((count + 2) * sizeof (char *));
	if (darp == NULL)
		return (NULL);
	cp = tmplist;
	while ((cp = strtok_r(cp, " ", &cpl)) != NULL) {
		*darp = strdup(cp);
		if (*darp == NULL) {
			freedmapent(dmp);
			return (NULL);
		}
		darp++;
		cp = NULL;
	}
	*darp = NULL;

	return (dmp);
}

/*
 * dmapskip -
 * 	scans input string to find next colon or end of line.
 *	returns pointer to next char.
 */
static char *
dmapskip(char *p)
{
	while (*p && *p != ':' && *p != '\n')
		++p;
	if (*p == '\n')
		*p = '\0';
	else if (*p != '\0')
		*p++ = '\0';

	return (p);
}

/*
 * dmapdskip -
 * 	scans input string to find next space or end of line.
 *	returns pointer to next char.
 */
static char *
dmapdskip(p)
	register char *p;
{
	while (*p && *p != ' ' && *p != '\n')
		++p;
	if (*p != '\0')
		*p++ = '\0';

	return (p);
}

char *
getdmapfield(char *ptr)
{
	static	char	*tptr;

	if (ptr == NULL)
		ptr = tptr;
	if (ptr == NULL)
		return (NULL);
	tptr = dmapskip(ptr);
	ptr = trim_white(ptr);
	if (ptr == NULL)
		return (NULL);
	if (*ptr == NULL)
		return (NULL);

	return (ptr);
}

char *
getdmapdfield(char *ptr)
{
	static	char	*tptr;
	if (ptr != NULL) {
		ptr = trim_white(ptr);
	} else {
		ptr = tptr;
	}
	if (ptr == NULL)
		return (NULL);
	tptr = dmapdskip(ptr);
	if (ptr == NULL)
		return (NULL);
	if (*ptr == NULL)
		return (NULL);

	return (ptr);
}
