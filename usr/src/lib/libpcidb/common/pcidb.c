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

#include "pcidb.h"

#define	PCI_NAME_MAX	256
#define	PCI_READLINE	1024

/* Forward declarations */
struct pcidb_vendor;
struct pcidb_device;
struct pcidb_subvd;

struct pcidb_subvd {
	uint16_t		ps_vid;
	uint16_t		ps_did;
	char			ps_name[PCI_NAME_MAX];
	struct pcidb_subvd	*ps_prev;
	struct pcidb_subvd	*ps_next;
	struct pcidb_device	*ps_dev;
	struct pcidb_vendor	*ps_vend;
};

struct pcidb_device {
	uint16_t		pd_id;
	char			pd_name[PCI_NAME_MAX];
	struct pcidb_subvd	*pd_sstart;
	struct pcidb_subvd	*pd_send;
	struct pcidb_device	*pd_next;
	struct pcidb_device	*pd_prev;
	struct pcidb_vendor	*pd_vend;
};

struct pcidb_vendor {
	uint16_t		pv_id;
	char 			pv_name[PCI_NAME_MAX];
	struct pcidb_device	*pv_dstart;
	struct pcidb_device	*pv_dend;
	struct pcidb_vendor	*pv_prev;
	struct pcidb_vendor	*pv_next;
};

struct pcidb_hdl {
	pcidb_vendor_t	*ph_vstart;
	pcidb_vendor_t	*ph_vend;
};

typedef enum pcidb_parse {
	PDB_VENDOR,
	PDB_DEVICE,
	PDB_SUBDEV
} pcidb_parse_t;

static const char *pci_db = "/usr/share/hwdata/pci.ids";

static void
pcihdl_add_vendor(pcidb_hdl_t *hdl, pcidb_vendor_t *v)
{
	if (hdl->ph_vstart == NULL && hdl->ph_vend == NULL) {
		hdl->ph_vstart = v;
		hdl->ph_vend = v;
		v->pv_prev = NULL;
		v->pv_next = NULL;
	} else {
		v->pv_prev = hdl->ph_vend;
		v->pv_next = NULL;
		hdl->ph_vend->pv_next = v;
		hdl->ph_vend = v;
	}
}

static pcidb_vendor_t *
parse_vendor(char *buf, pcidb_hdl_t *hdl)
{
	pcidb_vendor_t *v;
	size_t len;

	v = malloc(sizeof (pcidb_vendor_t));
	if (v == NULL)
		return (NULL);

	pcihdl_add_vendor(hdl, v);
	v->pv_dstart = NULL;
	v->pv_dend = NULL;

	buf[4] = '\0';
	v->pv_id = strtol(buf, NULL, 16);
	buf += 6;
	len = strlen(buf);
	if (buf[len-1] == '\n')
		buf[len-1] = '\0';

	(void) strlcpy(v->pv_name, buf, PCI_NAME_MAX);

	return (v);
}

static void
insert_device(pcidb_vendor_t *v, pcidb_device_t *d)
{
	d->pd_vend = v;
	if (v->pv_dstart == NULL && v->pv_dend == NULL) {
		v->pv_dstart = d;
		v->pv_dend = d;
		d->pd_next = NULL;
		d->pd_prev = NULL;
	} else {
		d->pd_prev = v->pv_dend;
		d->pd_next = NULL;
		v->pv_dend->pd_next = d;
		v->pv_dend = d;
	}
}

static pcidb_device_t *
parse_device(char *buf, pcidb_vendor_t *v)
{
	pcidb_device_t *d;
	size_t len;

	d = malloc(sizeof (pcidb_device_t));
	if (d == NULL)
		return (d);

	d->pd_sstart = NULL;
	d->pd_send = NULL;
	insert_device(v, d);

	buf++;
	buf[4] = '\0';
	d->pd_id = strtol(buf, NULL, 16);
	buf += 6;
	len = strlen(buf);
	if (buf[len-1] == '\n')
		buf[len-1] = '\0';

	(void) strlcpy(d->pd_name, buf, PCI_NAME_MAX);
	return (d);
}

static void
insert_subdev(pcidb_device_t *d, pcidb_subvd_t *s)
{
	s->ps_dev = d;
	s->ps_vend = d->pd_vend;
	if (d->pd_sstart == NULL) {
		d->pd_sstart = s;
		d->pd_send = s;
		s->ps_prev = NULL;
		s->ps_next = NULL;
	} else {
		s->ps_prev = d->pd_send;
		s->ps_next = NULL;
		d->pd_send->ps_next = s;
		d->pd_send = s;
	}
}

static pcidb_subvd_t *
parse_subdev(char *buf, pcidb_device_t *d)
{
	pcidb_subvd_t *s;
	size_t len;

	s = malloc(sizeof (pcidb_subvd_t));
	if (s == NULL)
		return (NULL);
	insert_subdev(d, s);

	buf += 2;
	buf[4] = '\0';
	s->ps_vid = strtol(buf, NULL, 16);
	buf += 5;
	buf[4] = '\0';
	s->ps_did = strtol(buf, NULL, 16);
	buf += 6;

	len = strlen(buf);
	if (buf[len-1] == '\n')
		buf[len-1] = '\0';

	(void) strlcpy(s->ps_name, buf, PCI_NAME_MAX);

	return (s);
}

static int
readline(FILE *f, char *buf, size_t len)
{
	for (;;) {
		if (fgets(buf, len, f) == NULL)
			return (-1);

		if (buf[0] == 'C')
			return (-1);

		if (buf[0] != '#' && buf[0] != '\n')
			return (0);
	}
}

static int
parse_db(FILE *f, pcidb_hdl_t *hdl)
{
	char buf[1024];
	pcidb_vendor_t *v = NULL;
	pcidb_device_t *d = NULL;
	pcidb_parse_t state = PDB_VENDOR;

	for (;;) {
		errno = 0;
		if (readline(f, buf, sizeof (buf)) != 0) {
			if (errno != 0)
				return (-1);
			else
				return (0);
		}

newstate:
		switch (state) {
		case PDB_VENDOR:
			v = parse_vendor(buf, hdl);
			if (v == NULL)
				return (NULL);
			state = PDB_DEVICE;
			continue;
		case PDB_DEVICE:
			if (buf[0] != '\t') {
				state = PDB_VENDOR;
				goto newstate;
			}

			if (buf[1] == '\t') {
				state = PDB_SUBDEV;
				goto newstate;
			}

			assert(v != NULL);
			d = parse_device(buf, v);
			if (d == NULL)
				return (NULL);
			continue;
		case PDB_SUBDEV:
			if (buf[0] != '\t') {
				state = PDB_VENDOR;
				goto newstate;
			}

			if (buf[0] == '\t' && buf[1] != '\t') {
				state = PDB_DEVICE;
				goto newstate;
			}

			assert(buf[0] == '\t' && buf[1] == '\t');
			assert(d != NULL);
			(void) parse_subdev(buf, d);
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

	h->ph_vstart = NULL;
	h->ph_vend = NULL;

	f = fopen(pci_db, "rF");
	if (f == NULL) {
		free(h);
		return (NULL);
	}

	if (parse_db(f, h) < 0) {
		pcidb_close(h);
		free(h);
		return (NULL);
	}

	return (h);
}

void
pcidb_close(pcidb_hdl_t *h)
{
	pcidb_vendor_t *v, *tv;

	pcidb_device_t *d, *td;
	pcidb_subvd_t *s, *ts;

	if (h == NULL)
		return;

	v = h->ph_vstart;
	while (v != NULL) {
		d = v->pv_dstart;
		while (d != NULL) {
			s = d->pd_sstart;
			while (s != NULL) {
				ts = s;
				s = s->ps_next;
				free(ts);
			}
			td = d;
			d = d->pd_next;
			free(td);
		}
		tv = v;
		v = v->pv_next;
		free(tv);
	}

	free(h);
}

pcidb_vendor_t *
pcidb_lookup_vendor(pcidb_hdl_t *hdl, uint16_t id)
{
	pcidb_vendor_t *v;

	for (v = hdl->ph_vstart; v != NULL; v = v->pv_next) {
		if (v->pv_id == id)
			return (v);
	}

	return (NULL);
}

const char *
pcidb_vendor_name(pcidb_vendor_t *v)
{
	return (v->pv_name);
}

uint16_t
pcidb_vendor_id(pcidb_vendor_t *v)
{
	return (v->pv_id);
}

pcidb_vendor_t *
pcidb_vendor_iter(pcidb_hdl_t *h)
{
	return (h->ph_vstart);
}

pcidb_vendor_t *
pcidb_vendor_iter_next(pcidb_vendor_t *v)
{
	assert(v != NULL);
	return (v->pv_next);
}

pcidb_device_t *
pcidb_lookup_device_by_vendor(pcidb_vendor_t *v, uint16_t id)
{
	pcidb_device_t *d;
	assert(v != NULL);

	for (d = v->pv_dstart; d != NULL; d = d->pd_next)
		if (d->pd_id == id)
			return (d);

	return (NULL);
}

pcidb_device_t *
pcidb_lookup_device(pcidb_hdl_t *h, uint16_t vid, uint16_t did)
{
	pcidb_vendor_t *v;

	v = pcidb_lookup_vendor(h, vid);
	if (v == NULL)
		return (NULL);

	return (pcidb_lookup_device_by_vendor(v, did));
}

pcidb_device_t *
pcidb_device_iter(pcidb_vendor_t *v)
{
	return (v->pv_dstart);
}

pcidb_device_t *
pcidb_device_iter_next(pcidb_device_t *d)
{
	return (d->pd_next);
}

const char *
pcidb_device_name(pcidb_device_t *d)
{
	return (d->pd_name);
}

uint16_t
pcidb_device_id(pcidb_device_t *d)
{
	return (d->pd_id);
}

pcidb_vendor_t *
pcidb_device_vendor(pcidb_device_t *d)
{
	return (d->pd_vend);
}

pcidb_subvd_t *
pcidb_lookup_subvd_by_device(pcidb_device_t *d, uint16_t svid, uint16_t sdid)
{
	pcidb_subvd_t *s;

	assert(d != NULL);

	for (s = d->pd_sstart; s != NULL; s = s->ps_next)
		if (s->ps_vid == svid && s->ps_did == sdid)
			return (s);

	return (NULL);
}

pcidb_subvd_t *
pcidb_lookup_subvd_by_vendor(pcidb_vendor_t *v, uint16_t devid, uint16_t svid,
    uint16_t sdid)
{
	pcidb_device_t *d;

	assert(v != NULL);
	d = pcidb_lookup_device_by_vendor(v, devid);
	if (d == NULL)
		return (NULL);

	return (pcidb_lookup_subvd_by_device(d, svid, sdid));
}

pcidb_subvd_t *
pcidb_lookup_subvd(pcidb_hdl_t *h, uint16_t vid, uint16_t did, uint16_t svid,
    uint16_t sdid)
{
	pcidb_device_t *d;

	assert(h != NULL);
	d = pcidb_lookup_device(h, vid, did);
	if (d == NULL)
		return (NULL);

	return (pcidb_lookup_subvd_by_device(d, svid, sdid));
}

pcidb_subvd_t *
pcidb_subvd_iter(pcidb_device_t *d)
{
	return (d->pd_sstart);
}

pcidb_subvd_t *
pcidb_subvd_iter_next(pcidb_subvd_t *s)
{
	return (s->ps_next);
}

const char *
pcidb_subvd_name(pcidb_subvd_t *s)
{
	return (s->ps_name);
}

uint16_t
pcidb_subvd_svid(pcidb_subvd_t *s)
{
	return (s->ps_vid);
}

uint16_t
pcidb_subvd_sdid(pcidb_subvd_t *s)
{
	return (s->ps_did);
}

pcidb_device_t *
pcidb_subvd_device(pcidb_subvd_t *s)
{
	return (s->ps_dev);
}

pcidb_vendor_t *
pcidb_subvd_vendor(pcidb_subvd_t *s)
{
	return (s->ps_vend);
}
