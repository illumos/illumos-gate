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
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 * Copyright 2021 Oxide Computer Company
 */

/*
 * This library exists to understand and parse the pci.ids database that is
 * maintained at http://pci-ids.ucw.cz/ and in the gate at cmd/hwdata. This
 * database provides a way to map the PCI device, vendor, and subsystem ids to
 * a human understandable name.
 *
 * This library exports this data in a similar way to a tree. The handle that
 * is returned from pcidb_open is the root of the tree. The next level are the
 * vendors. Each vendor has a unique set of devices and each device has a unique
 * set of subvendor and subdevice pairs.
 *
 * Parsing information:
 *
 * The database is formatted in the following basic format:
 * vendor_id<two spaces>vendor_name
 * <tab>device_id<two spaces>device_name
 * <tab><tab>subvendor<space>subdevice<two spaces>subsystem_name
 *
 * For any given vendor, there can be multiple devices. And for any given device
 * there will be multiple subsystems. In addition, there can be comments that
 * start a line which use the '#' character.
 *
 * At the end of the file, there are a series of PCI classes. Those will start
 * with a single C<space>. Once we hit those, we stop all parsing. We currently
 * don't care about consuming or presenting those.
 */

#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/list.h>

#include "pcidb.h"

#define	PCI_NAME_MAX	256
#define	PCI_READLINE	1024

struct pcidb_progif {
	char		pp_name[PCI_NAME_MAX];
	list_node_t	pp_link;
	pcidb_subclass_t *pp_subclass;
	uint8_t		pp_code;
};

struct pcidb_subclass {
	char		psc_name[PCI_NAME_MAX];
	list_node_t	psc_link;
	list_t		psc_progifs;
	pcidb_class_t	*psc_class;
	uint8_t		psc_code;
};

struct pcidb_class {
	char		pc_name[PCI_NAME_MAX];
	list_node_t	pc_link;
	list_t		pc_subclass;
	pcidb_hdl_t	*pc_hdl;
	uint8_t		pc_code;
};

struct pcidb_subvd {
	uint16_t	ps_vid;
	uint16_t	ps_did;
	char		ps_name[PCI_NAME_MAX];
	list_node_t	ps_link;
	pcidb_device_t	*ps_dev;
	pcidb_vendor_t	*ps_vend;
};

struct pcidb_device {
	uint16_t	pd_id;
	char		pd_name[PCI_NAME_MAX];
	list_t		pd_subs;
	list_node_t	pd_link;
	pcidb_vendor_t	*pd_vend;
};

struct pcidb_vendor {
	uint16_t	pv_id;
	char		pv_name[PCI_NAME_MAX];
	list_t		pv_devs;
	list_node_t	pv_link;
	pcidb_hdl_t	*pv_hdl;
};

struct pcidb_hdl {
	list_t ph_vendors;
	list_t ph_classes;
};

typedef enum pcidb_parse {
	PDB_INIT,
	PDB_VENDOR,
	PDB_DEVICE,
	PDB_SUBDEV,
	PDB_CLASS,
	PDB_SUBCLASS,
	PDB_PROGIF
} pcidb_parse_t;

static const char *pci_db = "/usr/share/hwdata/pci.ids";

static pcidb_vendor_t *
parse_vendor(char *buf, pcidb_hdl_t *hdl)
{
	pcidb_vendor_t *vend;

	vend = malloc(sizeof (pcidb_vendor_t));
	if (vend == NULL)
		return (NULL);

	list_create(&vend->pv_devs, sizeof (pcidb_device_t),
	    offsetof(pcidb_device_t, pd_link));
	vend->pv_hdl = hdl;
	list_insert_tail(&hdl->ph_vendors, vend);

	buf[4] = '\0';
	vend->pv_id = strtol(buf, NULL, 16);
	buf += 6;

	(void) strlcpy(vend->pv_name, buf, PCI_NAME_MAX);

	return (vend);
}

static pcidb_device_t *
parse_device(char *buf, pcidb_vendor_t *vend)
{
	pcidb_device_t *dev;

	dev = malloc(sizeof (pcidb_device_t));
	if (dev == NULL)
		return (dev);

	list_create(&dev->pd_subs, sizeof (pcidb_subvd_t),
	    offsetof(pcidb_subvd_t, ps_link));
	dev->pd_vend = vend;
	list_insert_tail(&vend->pv_devs, dev);

	buf++;
	buf[4] = '\0';
	dev->pd_id = strtol(buf, NULL, 16);
	buf += 6;

	(void) strlcpy(dev->pd_name, buf, PCI_NAME_MAX);
	return (dev);
}

static pcidb_subvd_t *
parse_subdev(char *buf, pcidb_device_t *dev)
{
	pcidb_subvd_t *sub;

	sub = malloc(sizeof (pcidb_subvd_t));
	if (sub == NULL)
		return (NULL);

	sub->ps_dev = dev;
	sub->ps_vend = dev->pd_vend;
	list_insert_tail(&dev->pd_subs, sub);

	buf += 2;
	buf[4] = '\0';
	sub->ps_vid = strtol(buf, NULL, 16);
	buf += 5;
	buf[4] = '\0';
	sub->ps_did = strtol(buf, NULL, 16);
	buf += 6;

	(void) strlcpy(sub->ps_name, buf, PCI_NAME_MAX);

	return (sub);
}

static pcidb_class_t *
pcidb_parse_class(char *buf, pcidb_hdl_t *hdl)
{
	pcidb_class_t *class;

	class = malloc(sizeof (pcidb_class_t));
	if (class == NULL)
		return (NULL);

	list_create(&class->pc_subclass, sizeof (pcidb_subclass_t),
	    offsetof(pcidb_subclass_t, psc_link));
	class->pc_hdl = hdl;
	list_insert_tail(&hdl->ph_classes, class);

	buf += 2;
	buf[3] = '\0';
	class->pc_code = strtol(buf, NULL, 16);
	buf += 4;
	(void) strlcpy(class->pc_name, buf, PCI_NAME_MAX);

	return (class);
}

static pcidb_subclass_t *
pcidb_parse_subclass(char *buf, pcidb_class_t *class)
{
	pcidb_subclass_t *sub;

	sub = malloc(sizeof (pcidb_subclass_t));
	if (sub == NULL)
		return (NULL);

	list_create(&sub->psc_progifs, sizeof (pcidb_progif_t),
	    offsetof(pcidb_progif_t, pp_link));
	sub->psc_class = class;
	list_insert_tail(&class->pc_subclass, sub);

	buf++;
	buf[3] = '\0';
	sub->psc_code = strtol(buf, NULL, 16);
	buf += 4;
	(void) strlcpy(sub->psc_name, buf, PCI_NAME_MAX);

	return (sub);
}

static pcidb_progif_t *
pcidb_parse_progif(char *buf, pcidb_subclass_t *sub)
{
	pcidb_progif_t *prog;

	prog = malloc(sizeof (pcidb_progif_t));
	if (prog == NULL) {
		return (NULL);
	}

	prog->pp_subclass = sub;
	list_insert_tail(&sub->psc_progifs, prog);

	buf += 2;
	buf[3] = '\0';
	prog->pp_code = strtol(buf, NULL, 16);
	buf += 4;
	(void) strlcpy(prog->pp_name, buf, PCI_NAME_MAX);

	return (prog);
}

static int
readline(FILE *f, char *buf, size_t len)
{
	for (;;) {
		char *c;

		if (fgets(buf, len, f) == NULL)
			return (-1);

		if ((c = strchr(buf, '\n')) != NULL)
			*c = '\0';

		if (buf[0] != '#' && buf[0] != '\0')
			return (0);
	}
}

static int
parse_db(FILE *f, pcidb_hdl_t *hdl)
{
	pcidb_vendor_t *vend = NULL;
	pcidb_device_t *dev = NULL;
	pcidb_class_t *class = NULL;
	pcidb_subclass_t *sub = NULL;
	pcidb_parse_t state = PDB_INIT;

	for (;;) {
		char buf[1024];

		errno = 0;
		if (readline(f, buf, sizeof (buf)) != 0) {
			if (errno != 0)
				return (-1);
			else
				return (0);
		}

newstate:
		switch (state) {
		case PDB_INIT:
			vend = NULL;
			dev = NULL;
			class = NULL;
			sub = NULL;
			if (buf[0] == 'C') {
				state = PDB_CLASS;
			} else {
				state = PDB_VENDOR;
			}
			goto newstate;
		case PDB_VENDOR:
			vend = parse_vendor(buf, hdl);
			if (vend == NULL)
				return (-1);
			state = PDB_DEVICE;
			break;
		case PDB_DEVICE:
			if (buf[0] != '\t') {
				state = PDB_INIT;
				goto newstate;
			}

			if (buf[1] == '\t') {
				state = PDB_SUBDEV;
				goto newstate;
			}

			assert(vend != NULL);
			dev = parse_device(buf, vend);
			if (dev == NULL)
				return (0);
			break;
		case PDB_SUBDEV:
			if (buf[0] != '\t') {
				state = PDB_INIT;
				goto newstate;
			}

			if (buf[0] == '\t' && buf[1] != '\t') {
				state = PDB_DEVICE;
				goto newstate;
			}

			assert(buf[0] == '\t' && buf[1] == '\t');
			assert(dev != NULL);
			if (parse_subdev(buf, dev) == NULL) {
				return (-1);
			}
			break;
		case PDB_CLASS:
			class = pcidb_parse_class(buf, hdl);
			state = PDB_SUBCLASS;
			break;
		case PDB_SUBCLASS:
			if (buf[0] != '\t') {
				state = PDB_INIT;
				goto newstate;
			}

			if (buf[1] == '\t') {
				state = PDB_PROGIF;
				goto newstate;
			}

			assert(class != NULL);
			sub = pcidb_parse_subclass(buf, class);
			if (sub == NULL) {
				return (-1);
			}
			break;
		case PDB_PROGIF:
			if (buf[0] != '\t') {
				state = PDB_INIT;
				goto newstate;
			}

			if (buf[0] == '\t' && buf[1] != '\t') {
				state = PDB_SUBCLASS;
				goto newstate;
			}

			assert(sub != NULL);
			if (pcidb_parse_progif(buf, sub) == NULL) {
				return (-1);
			}
			break;
		}
	}
}

pcidb_hdl_t *
pcidb_open(int version)
{
	pcidb_hdl_t *h;
	FILE *f;

	if (version != PCIDB_VERSION) {
		errno = EINVAL;
		return (NULL);
	}

	h = malloc(sizeof (pcidb_hdl_t));
	if (h == NULL)
		return (NULL);

	list_create(&h->ph_vendors, sizeof (pcidb_vendor_t),
	    offsetof(pcidb_vendor_t, pv_link));
	list_create(&h->ph_classes, sizeof (pcidb_class_t),
	    offsetof(pcidb_class_t, pc_link));

	f = fopen(pci_db, "rF");
	if (f == NULL) {
		free(h);
		return (NULL);
	}

	if (parse_db(f, h) < 0) {
		(void) fclose(f);
		pcidb_close(h);
		return (NULL);
	}

	(void) fclose(f);

	return (h);
}

void
pcidb_close(pcidb_hdl_t *hdl)
{
	pcidb_vendor_t *vend;
	pcidb_class_t *class;

	if (hdl == NULL)
		return;

	while ((vend = list_remove_head(&hdl->ph_vendors)) != NULL) {
		pcidb_device_t *dev;

		while ((dev = list_remove_head(&vend->pv_devs)) != NULL) {
			pcidb_subvd_t *sub;

			while ((sub = list_remove_head(&dev->pd_subs)) !=
			    NULL) {
				free(sub);
			}
			list_destroy(&dev->pd_subs);
			free(dev);
		}
		list_destroy(&vend->pv_devs);
		free(vend);
	}
	list_destroy(&hdl->ph_vendors);

	while ((class = list_remove_head(&hdl->ph_classes)) != NULL) {
		pcidb_subclass_t *sub;

		while ((sub = list_remove_head(&class->pc_subclass)) != NULL) {
			pcidb_progif_t *prog;

			while ((prog = list_remove_head(&sub->psc_progifs)) !=
			    NULL) {
				free(prog);
			}
			list_destroy(&sub->psc_progifs);
			free(sub);
		}
		list_destroy(&class->pc_subclass);
		free(class);
	}
	list_destroy(&hdl->ph_classes);

	free(hdl);
}

pcidb_vendor_t *
pcidb_lookup_vendor(pcidb_hdl_t *hdl, uint16_t id)
{
	pcidb_vendor_t *v;

	for (v = list_head(&hdl->ph_vendors); v != NULL;
	    v = list_next(&hdl->ph_vendors, v)) {
		if (v->pv_id == id)
			return (v);
	}

	return (NULL);
}

const char *
pcidb_vendor_name(pcidb_vendor_t *vend)
{
	return (vend->pv_name);
}

uint16_t
pcidb_vendor_id(pcidb_vendor_t *vend)
{
	return (vend->pv_id);
}

pcidb_vendor_t *
pcidb_vendor_iter(pcidb_hdl_t *hdl)
{
	return (list_head(&hdl->ph_vendors));
}

pcidb_vendor_t *
pcidb_vendor_iter_next(pcidb_vendor_t *vend)
{
	assert(vend != NULL);
	return (list_next(&vend->pv_hdl->ph_vendors, vend));
}

pcidb_device_t *
pcidb_lookup_device_by_vendor(pcidb_vendor_t *vend, uint16_t id)
{
	assert(vend != NULL);

	for (pcidb_device_t *dev = list_head(&vend->pv_devs); dev != NULL;
	    dev = list_next(&vend->pv_devs, dev)) {
		if (dev->pd_id == id)
			return (dev);
	}

	return (NULL);
}

pcidb_device_t *
pcidb_lookup_device(pcidb_hdl_t *hdl, uint16_t vid, uint16_t did)
{
	pcidb_vendor_t *vend;

	vend = pcidb_lookup_vendor(hdl, vid);
	if (vend == NULL)
		return (NULL);

	return (pcidb_lookup_device_by_vendor(vend, did));
}

pcidb_device_t *
pcidb_device_iter(pcidb_vendor_t *vend)
{
	return (list_head(&vend->pv_devs));
}

pcidb_device_t *
pcidb_device_iter_next(pcidb_device_t *dev)
{
	return (list_next(&dev->pd_vend->pv_devs, dev));
}

const char *
pcidb_device_name(pcidb_device_t *dev)
{
	return (dev->pd_name);
}

uint16_t
pcidb_device_id(pcidb_device_t *dev)
{
	return (dev->pd_id);
}

pcidb_vendor_t *
pcidb_device_vendor(pcidb_device_t *dev)
{
	return (dev->pd_vend);
}

pcidb_subvd_t *
pcidb_lookup_subvd_by_device(pcidb_device_t *dev, uint16_t svid, uint16_t sdid)
{
	pcidb_subvd_t *sub;

	assert(dev != NULL);

	for (sub = list_head(&dev->pd_subs); sub != NULL;
	    sub = list_next(&dev->pd_subs, sub)) {
		if (sub->ps_vid == svid && sub->ps_did == sdid)
			return (sub);
	}

	return (NULL);
}

pcidb_subvd_t *
pcidb_lookup_subvd_by_vendor(pcidb_vendor_t *vend, uint16_t devid,
    uint16_t svid, uint16_t sdid)
{
	pcidb_device_t *dev;

	assert(vend != NULL);
	dev = pcidb_lookup_device_by_vendor(vend, devid);
	if (dev == NULL)
		return (NULL);

	return (pcidb_lookup_subvd_by_device(dev, svid, sdid));
}

pcidb_subvd_t *
pcidb_lookup_subvd(pcidb_hdl_t *hdl, uint16_t vid, uint16_t did, uint16_t svid,
    uint16_t sdid)
{
	pcidb_device_t *dev;

	assert(hdl != NULL);
	dev = pcidb_lookup_device(hdl, vid, did);
	if (dev == NULL)
		return (NULL);

	return (pcidb_lookup_subvd_by_device(dev, svid, sdid));
}

pcidb_subvd_t *
pcidb_subvd_iter(pcidb_device_t *dev)
{
	return (list_head(&dev->pd_subs));
}

pcidb_subvd_t *
pcidb_subvd_iter_next(pcidb_subvd_t *sub)
{
	return (list_next(&sub->ps_dev->pd_subs, sub));
}

const char *
pcidb_subvd_name(pcidb_subvd_t *sub)
{
	return (sub->ps_name);
}

uint16_t
pcidb_subvd_svid(pcidb_subvd_t *sub)
{
	return (sub->ps_vid);
}

uint16_t
pcidb_subvd_sdid(pcidb_subvd_t *sub)
{
	return (sub->ps_did);
}

pcidb_device_t *
pcidb_subvd_device(pcidb_subvd_t *sub)
{
	return (sub->ps_dev);
}

pcidb_vendor_t *
pcidb_subvd_vendor(pcidb_subvd_t *sub)
{
	return (sub->ps_vend);
}


pcidb_class_t *
pcidb_lookup_class(pcidb_hdl_t *hdl, uint8_t code)
{
	for (pcidb_class_t *class = list_head(&hdl->ph_classes); class != NULL;
	    class = list_next(&hdl->ph_classes, class)) {
		if (class->pc_code == code) {
			return (class);
		}
	}

	return (NULL);
}

pcidb_class_t *
pcidb_class_iter(pcidb_hdl_t *hdl)
{
	return (list_head(&hdl->ph_classes));
}

pcidb_class_t *
pcidb_class_iter_next(pcidb_class_t *class)
{
	return (list_next(&class->pc_hdl->ph_classes, class));
}

const char *
pcidb_class_name(pcidb_class_t *class)
{
	return (class->pc_name);
}

uint8_t
pcidb_class_code(pcidb_class_t *class)
{
	return (class->pc_code);
}

pcidb_subclass_t *
pcidb_lookup_subclass(pcidb_hdl_t *hdl, uint8_t ccode, uint8_t subcode)
{
	pcidb_class_t *class;

	class = pcidb_lookup_class(hdl, ccode);
	if (class == NULL) {
		return (NULL);
	}

	return (pcidb_lookup_subclass_by_class(class, subcode));
}

pcidb_subclass_t *
pcidb_lookup_subclass_by_class(pcidb_class_t *class, uint8_t code)
{
	for (pcidb_subclass_t *sub = list_head(&class->pc_subclass);
	    sub != NULL; sub = list_next(&class->pc_subclass, sub)) {
		if (sub->psc_code == code) {
			return (sub);
		}
	}

	return (NULL);
}

pcidb_subclass_t *
pcidb_subclass_iter(pcidb_class_t *class)
{
	return (list_head(&class->pc_subclass));
}

pcidb_subclass_t *
pcidb_subclass_iter_next(pcidb_subclass_t *sub)
{
	return (list_next(&sub->psc_class->pc_subclass, sub));
}

const char *
pcidb_subclass_name(pcidb_subclass_t *sub)
{
	return (sub->psc_name);
}

uint8_t
pcidb_subclass_code(pcidb_subclass_t *sub)
{
	return (sub->psc_code);
}

pcidb_progif_t *
pcidb_lookup_progif(pcidb_hdl_t *hdl, uint8_t ccode, uint8_t scode,
    uint8_t pcode)
{
	pcidb_subclass_t *sub;

	sub = pcidb_lookup_subclass(hdl, ccode, scode);
	if (sub == NULL) {
		return (NULL);
	}

	return (pcidb_lookup_progif_by_subclass(sub, pcode));
}

pcidb_progif_t *
pcidb_lookup_progif_by_subclass(pcidb_subclass_t *sub, uint8_t code)
{
	for (pcidb_progif_t *prog = list_head(&sub->psc_progifs); prog != NULL;
	    prog = list_next(&sub->psc_progifs, prog)) {
		if (prog->pp_code == code) {
			return (prog);
		}
	}

	return (NULL);
}

pcidb_progif_t *
pcidb_progif_iter(pcidb_subclass_t *sub)
{
	return (list_head(&sub->psc_progifs));
}

pcidb_progif_t *
pcidb_progif_iter_next(pcidb_progif_t *prog)
{
	return (list_next(&prog->pp_subclass->psc_progifs, prog));
}

const char *
pcidb_progif_name(pcidb_progif_t *prog)
{
	return (prog->pp_name);
}

uint8_t
pcidb_progif_code(pcidb_progif_t *prog)
{
	return (prog->pp_code);
}
