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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include "benv.h"
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/openpromio.h>
#include <stdio.h>

static int getpropval(struct openpromio *opp, char *prop);

static char *promdev = "/dev/openprom";
static int prom_fd;
static char *mfail = "malloc";

/*
 * 128 is the size of the largest (currently) property name
 * 16384 - MAXPROPSIZE - sizeof (int) is the size of the largest
 * (currently) property value that is allowed.
 * the sizeof (u_int) is from struct openpromio
 */

#define	MAXPROPSIZE	128
#define	MAXVALSIZE	(16384 - MAXPROPSIZE - sizeof (u_int))
#define	BUFSIZE		(MAXPROPSIZE + MAXVALSIZE + sizeof (u_int))
#define	MINVALSIZE	(4 * sizeof (u_long))
#define	MINBUFSIZE	(MINVALSIZE + sizeof (u_long))

typedef union {
	char buf[BUFSIZE];
	struct openpromio opp;
} Oppbuf;

typedef union {
	char buf[MINVALSIZE + sizeof (u_int)];
	struct openpromio opp;
} Oppbuf_small;

static Oppbuf	oppbuf;

static unsigned long
next(unsigned long id)
{
	Oppbuf_small	oppbuf;
	struct openpromio *opp = &(oppbuf.opp);
	unsigned long *ip = (unsigned long *)(opp->oprom_array);

	memset(oppbuf.buf, 0, MINBUFSIZE);
	opp->oprom_size = MINVALSIZE;
	*ip = id;
	if (ioctl(prom_fd, OPROMNEXT, opp) < 0)
		return (0);
	return (*(unsigned long *)opp->oprom_array);
}

static unsigned long
child(unsigned long id)
{
	Oppbuf_small	oppbuf;
	struct openpromio *opp = &(oppbuf.opp);
	unsigned long *ip = (unsigned long *)(opp->oprom_array);

	memset(oppbuf.buf, 0, MINBUFSIZE);
	opp->oprom_size = MINVALSIZE;
	*ip = id;
	if (ioctl(prom_fd, OPROMCHILD, opp) < 0)
		return (0);
	return (*(unsigned long *)opp->oprom_array);
}

/*
 * Find a node by name from the prom device tree.
 * Return the id or 0 if it is not found.
 */
static unsigned long
prom_findnode_byname(unsigned long id, char *name)
{
	struct openpromio *opp = &(oppbuf.opp);
	unsigned long nid;

	if (id == 0)
		return (0);
	if (!getpropval(opp, "name"))
		return (0);
	if (strcmp(opp->oprom_array, name) == 0)
		return (id);
	if (nid = prom_findnode_byname(child(id), name))
		return (nid);
	if (nid = prom_findnode_byname(next(id), name))
		return (nid);
	return (0);
}

/*
 * Make the current prom node be the rootnode and return its id.
 */
static unsigned long
prom_rootnode()
{
	return (next(0));
}

static int
getpropval(struct openpromio *opp, char *prop)
{
	opp->oprom_size = MAXVALSIZE;

	(void) strlcpy(opp->oprom_array, prop, MAXPROPSIZE);
	if (ioctl(prom_fd, OPROMGETPROP, opp) < 0)
		return (0);
	if (opp->oprom_size == 0)
		return (0);
	return (1);
}

static int
getnextprop(struct openpromio *opp, char *prop)
{
	opp->oprom_size = MAXVALSIZE;

	(void) strlcpy(opp->oprom_array, prop, MAXPROPSIZE);
	if (ioctl(prom_fd, OPROMNXTPROP, opp) < 0)
		return (0);
	if (opp->oprom_size == 0)
		return (0);
	return (1);
}

char *
getbootcmd(void)
{
	struct openpromio *opp = &(oppbuf.opp);
	opp->oprom_size = MAXVALSIZE;
	if (ioctl(prom_fd, OPROMGETBOOTPATH, opp) < 0)
		return (NULL);
	return (opp->oprom_array);
}

/*
 * Get a pointer to the requested property from the current node.
 * The property is stored in static storage and the returned pointer
 * points into the static storage.  The property length is placed in
 * the location pointed to by the third argument.
 */
static unsigned char *
prom_getprop(char *prop, int *lenp)
{
	struct openpromio *opp = &(oppbuf.opp);

	if (!getpropval(opp, prop))
		return (NULL);
	*lenp = opp->oprom_size;
	return ((unsigned char *)opp->oprom_array);
}

static unsigned char *
prom_nextprop(char *prop)
{
	struct openpromio *opp = &(oppbuf.opp);

	if (!getnextprop(opp, prop))
		return ((unsigned char *)0);
	return ((unsigned char *)opp->oprom_array);
}

ddi_prop_t *
get_proplist(char *name)
{
	ddi_prop_t *plist, *npp, *plast;
	char *curprop, *newprop;
	unsigned char *propval;
	unsigned long id;

	plist = NULL;
	plast = NULL;
	id = prom_findnode_byname(prom_rootnode(), name);
	if (id == 0)
		return (plist);
	curprop = "";
	while (newprop = (char *)prom_nextprop(curprop)) {
		curprop = strdup(newprop);
		npp = (ddi_prop_t *)malloc(sizeof (ddi_prop_t));
		if (npp == 0)
			exit(_error(PERROR, mfail));
		propval = prom_getprop(curprop, &npp->prop_len);
		npp->prop_name = curprop;
		if (propval != NULL) {
			npp->prop_val = (char *)malloc(npp->prop_len);
			if (npp->prop_val == 0)
				exit(_error(PERROR, mfail));
			memcpy(npp->prop_val, propval, npp->prop_len);
		} else
			npp->prop_val = NULL;
		npp->prop_next = NULL;
		if (plast == NULL) {
			plist = npp;
		} else {
			plast->prop_next = npp;
		}
		plast = npp;
	}
	return (plist);
}

caddr_t
get_propval(char *name, char *node)
{
	ddi_prop_t *prop, *plist;

	if ((plist = get_proplist(node)) == NULL)
		return (NULL);

	for (prop = plist; prop != NULL; prop = prop->prop_next)
		if (strcmp(prop->prop_name, name) == 0)
			return (prop->prop_val);

	return (NULL);
}

void
get_kbenv(void)
{
	if ((prom_fd = open(promdev, O_RDONLY)) < 0) {
		exit(_error(PERROR, "prom open failed"));
	}
}

void
close_kbenv(void)
{
	(void) close(prom_fd);
}
