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
#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * common routines for parallelization (used by both fsck and quotacheck)
 */
#include <stdio.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <macros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mntent.h>
#include <sys/dkio.h>

/*
 * data structures for parallelization
 */
struct driver {
	char 	*name;			/* driver name (from DKIOCINFO) */
	uint_t	mapsize;		/* size of `busymap' */
	uint_t	*busymap;		/* bitmask of active units */
	int	(*choosefunc)();	/* driver specific chooser */
	void	*data;			/* driver private data */
};

struct onedev {
	int	drvid;			/* index in driver array */
	uint_t	mapsize;		/* size of `unitmap' */
	uint_t	*unitmap;		/* unit #'s (from DKIOCINFO) */
	struct onedev *nxtdev;
};

struct rawdev {
	char	*devname;		/* name passed to preen_addev */
	struct	onedev *alldevs;	/* info about each component device */
	struct rawdev *nxtrd;		/* next entry in list */
};

static int debug = 0;

/*
 * defines used in building shared object names
 */

/* the directory where we find shared objects */
#define	OBJECT_DIRECTORY	"/usr/lib/drv"

/* a shared object name is OBJECT_PREFIX || driver_name */
#define	OBJECT_PREFIX		"preen_"

/* the version of the driver interface we support */
#define	OBJECT_VERSION		1

/* the "build" entry point for a driver specific object is named this */
#define	BUILD_ENTRY		preen_build_devs
#define	BUILD_NAME		"preen_build_devs"

#define	DRIVER_ALLOC	10
static int ndrivers, ndalloc;
static struct driver *dlist;

static struct rawdev *unchecked, *active, *get_runnable();
static struct onedev *alloc_dev();
static int chooseone();

#define	WORDSIZE	(NBBY * sizeof (uint_t))

void 	preen_addunit(void *, char *, int (*)(), void *, uint_t);
int 	preen_subdev(char *, struct dk_cinfo *, void *);

static int 	alloc_driver(char *, int (*)(), void *);
static void 	addunit(struct onedev *, uint_t);
static void	makebusy(struct onedev *);
static void	notbusy(struct rawdev *);

/*
 * add the given device to the list of devices to be checked
 */
int
preen_addev(char *devnm)
{
	struct rawdev *rdp;
	int fd;
	struct dk_cinfo dki;
	extern char *strdup();

	if ((fd = open64(devnm, O_RDONLY)) == -1) {
		perror(devnm);
		return (-1);
	}
	if (ioctl(fd, DKIOCINFO, &dki) == -1) {
		perror("DKIOCINFO");
		fprintf(stderr, "device: `%s'\n", devnm);
		(void) close(fd);
		return (-1);
	}
	(void) close(fd);
	if ((rdp = (struct rawdev *)malloc(sizeof (struct rawdev))) == NULL) {
		(void) fprintf(stderr, "out of memory in preenlib\n");
		return (-1);
	}
	if ((rdp->devname = strdup(devnm)) == NULL) {
		(void) fprintf(stderr, "out of memory in preenlib\n");
		return (-1);
	}
	rdp->alldevs = NULL;
	rdp->nxtrd = NULL;

	if (preen_subdev(devnm, &dki, (void *)rdp)) {
		preen_addunit(rdp, dki.dki_dname, NULL, NULL, dki.dki_unit);
	}

	rdp->nxtrd = unchecked;
	unchecked = rdp;
	return (0);
}

int
preen_subdev(char *name, struct dk_cinfo *dkiop, void *dp)
{
	char modname[255];
	void *dlhandle;
	int (*fptr)();

	(void) sprintf(modname, "%s/%s%s.so.%d",
	    OBJECT_DIRECTORY, OBJECT_PREFIX, dkiop->dki_dname, OBJECT_VERSION);
	dlhandle = dlopen(modname, RTLD_LAZY);
	if (dlhandle == NULL) {
		if (debug)
			(void) fprintf(stderr, "preen_subdev: %s\n", dlerror());
		return (1);
	}
	fptr = (int (*)())dlsym(dlhandle, BUILD_NAME);
	if (fptr == NULL) {
		if (debug)
			(void) fprintf(stderr, "preen_subdev: %s\n", dlerror());
		return (1);
	}
	(*fptr)(name, dkiop, dp);
	return (0);
}

/*
 * select a device from the "unchecked" list, and add it to the
 * active list.
 */
int
preen_getdev(char *devnm)
{
	struct rawdev *rdp;
	struct onedev *dp;

	if (unchecked == NULL)
		return (0);

	rdp = get_runnable(&unchecked);

	if (rdp) {
		for (dp = rdp->alldevs; dp; dp = dp->nxtdev) {
			makebusy(dp);
		}
		rdp->nxtrd = active;
		active = rdp;
		(void) strcpy(devnm, rdp->devname);
		return (1);
	} else {
		return (2);
	}
}

int
preen_releasedev(char *name)
{
	struct rawdev *dp, *ldp;

	for (ldp = NULL, dp = active; dp != NULL; ldp = dp, dp = dp->nxtrd) {
		if (strcmp(dp->devname, name) == 0)
			break;
	}

	if (dp == NULL)
		return (-1);
	if (ldp != NULL) {
		ldp->nxtrd = dp->nxtrd;
	} else {
		active = dp->nxtrd;
	}

	notbusy(dp);
	/*
	 * free(dp->devname);
	 * free(dp);
	 */
	return (0);
}

static
struct rawdev *
get_runnable(struct rawdev **devlist)
{
	struct rawdev *last, *rdp;
	struct onedev *devp;
	struct driver *drvp;
	int rc = 1;

	for (last = NULL, rdp = *devlist; rdp; last = rdp, rdp = rdp->nxtrd) {
		for (devp = rdp->alldevs; devp != NULL; devp = devp->nxtdev) {
			drvp = &dlist[devp->drvid];
			rc = (*drvp->choosefunc)(devp->mapsize, devp->unitmap,
			    drvp->mapsize, drvp->busymap);
			if (rc != 0)
				break;
		}
		if (rc == 0)
			break;
	}

	/*
	 * remove from list...
	 */
	if (rdp) {
		if (last) {
			last->nxtrd = rdp->nxtrd;
		} else {
			*devlist = rdp->nxtrd;
		}
	}

	return (rdp);
}

/*
 * add the given driver/unit reference to the `rawdev' structure identified
 * by `cookie'
 * If a new `driver' structure needs to be created, associate the given
 * choosing function and driver private data with it.
 */
void
preen_addunit(
	void    *cookie,
	char	*dname,		/* driver name */
	int	(*cf)(),	/* candidate choosing function */
	void	*datap,		/* driver private data */
	uint_t	unit)		/* unit number */
{
	int drvid;
	struct driver *dp;
	struct onedev *devp;
	struct rawdev *rdp = (struct rawdev *)cookie;

	/*
	 * locate the driver struct
	 */
	dp = NULL;
	for (drvid = 0; drvid < ndrivers; drvid++) {
		if (strcmp(dlist[drvid].name, dname) == 0) {
			dp = &dlist[drvid];
			break;
		}
	}

	if (dp == NULL) {
		/*
		 * driver struct doesn't exist yet -- create one
		 */
		if (cf == NULL)
			cf = chooseone;
		drvid = alloc_driver(dname, cf, datap);
		dp = &dlist[drvid];
	}

	for (devp = rdp->alldevs; devp != NULL; devp = devp->nxtdev) {
		/*
		 * see if this device already references the given driver
		 */
		if (devp->drvid == drvid)
			break;
	}

	if (devp == NULL) {
		/*
		 * allocate a new `struct onedev' and chain it in
		 * rdp->alldevs...
		 */
		devp = alloc_dev(drvid);
		devp->nxtdev = rdp->alldevs;
		rdp->alldevs = devp;
	}

	/*
	 * add `unit' to the unitmap in devp
	 */
	addunit(devp, unit);
}

static
int
alloc_driver(char *name, int (*cf)(), void *datap)
{
	struct driver *dp;
	extern char *strdup();

	if (ndrivers == ndalloc) {
		dlist = ndalloc ?
		    (struct driver *)
		    realloc(dlist, sizeof (struct driver) * DRIVER_ALLOC) :
		    (struct driver *)
		    malloc(sizeof (struct driver) * DRIVER_ALLOC);
		if (dlist == NULL) {
			(void) fprintf(stderr, "out of memory in preenlib\n");
			exit(1);
		}
		ndalloc += DRIVER_ALLOC;
	}

	dp = &dlist[ndrivers];
	dp->name = strdup(name);
	if (dp->name == NULL) {
		(void) fprintf(stderr, "out of memory in preenlib\n");
		exit(1);
	}
	dp->choosefunc = cf;
	dp->data = datap;
	dp->mapsize = 0;
	dp->busymap = NULL;
	return (ndrivers++);
}

static
struct onedev *
alloc_dev(int did)
{
	struct onedev *devp;

	devp = (struct onedev *)malloc(sizeof (struct onedev));
	if (devp == NULL) {
		(void) fprintf(stderr, "out of memory in preenlib\n");
		exit(1);
	}
	devp->drvid = did;
	devp->mapsize = 0;
	devp->unitmap = NULL;
	devp->nxtdev = NULL;
	return (devp);
}

static
void
addunit(struct onedev *devp, uint_t unit)
{
	uint_t newsize;

	newsize = howmany(unit+1, WORDSIZE);
	if (devp->mapsize < newsize) {
		devp->unitmap = devp->mapsize ?
		    (uint_t *)realloc(devp->unitmap,
		    newsize * sizeof (uint_t)) :
		    (uint_t *)malloc(newsize * sizeof (uint_t));
		if (devp->unitmap == NULL) {
			(void) fprintf(stderr, "out of memory in preenlib\n");
			exit(1);
		}
		(void) memset((char *)&devp->unitmap[devp->mapsize], 0,
		    (uint_t)((newsize - devp->mapsize) * sizeof (uint_t)));
		devp->mapsize = newsize;
	}
	devp->unitmap[unit / WORDSIZE] |= (1 << (unit % WORDSIZE));
}

static int
chooseone(int devmapsize, ulong_t *devmap, int drvmapsize, ulong_t *drvmap)
{
	int i;

	for (i = 0; i < min(devmapsize, drvmapsize); i++) {
		if (devmap[i] & drvmap[i])
			return (1);
	}
	return (0);
}

/*
 * mark the given driver/unit pair as busy.  This is called from
 * preen_getdev.
 */
static
void
makebusy(struct onedev *dev)
{
	struct driver *drvp = &dlist[dev->drvid];
	int newsize = dev->mapsize;
	int i;

	if (drvp->mapsize < newsize) {
		drvp->busymap = drvp->mapsize ?
		    (uint_t *)realloc(drvp->busymap,
		    newsize * sizeof (uint_t)) :
		    (uint_t *)malloc(newsize * sizeof (uint_t));
		if (drvp->busymap == NULL) {
			(void) fprintf(stderr, "out of memory in preenlib\n");
			exit(1);
		}
		(void) memset((char *)&drvp->busymap[drvp->mapsize], 0,
		    (uint_t)((newsize - drvp->mapsize) * sizeof (uint_t)));
		drvp->mapsize = newsize;
	}

	for (i = 0; i < newsize; i++)
		drvp->busymap[i] |= dev->unitmap[i];
}

/*
 * make each device in the given `rawdev' un-busy.
 * Called from preen_releasedev
 */
static
void
notbusy(struct rawdev *rd)
{
	struct onedev *devp;
	struct driver *drvp;
	int i;

	for (devp = rd->alldevs; devp; devp = devp->nxtdev) {
		drvp = &dlist[devp->drvid];
		for (i = 0; i < devp->mapsize; i++)
			drvp->busymap[i] &= ~(devp->unitmap[i]);
	}
}
