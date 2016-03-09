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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <fmadm.h>
#include <errno.h>
#include <limits.h>
#include <strings.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <fm/fmd_log.h>
#include <sys/fm/protocol.h>
#include <fm/libtopo.h>
#include <fm/fmd_adm.h>
#include <fm/fmd_msg.h>
#include <dlfcn.h>
#include <sys/systeminfo.h>
#include <sys/utsname.h>
#include <libintl.h>
#include <locale.h>
#include <sys/smbios.h>
#include <libdevinfo.h>
#include <stdlib.h>
#include <stddef.h>

/*
 * Fault records are added to catalog by calling add_fault_record_to_catalog()
 * records are stored in order of importance to the system.
 * If -g flag is set or not_suppressed is not set and the class fru, fault,
 * type are the same then details are merged into an existing record, with uuid
 * records are stored in time order.
 * For each record information is extracted from nvlist and merged into linked
 * list each is checked for identical records for which percentage certainty are
 * added together.
 * print_catalog() is called to print out catalog and release external resources
 *
 *                         /---------------\
 *	status_rec_list -> |               | -|
 *                         \---------------/
 *                                \/
 *                         /---------------\    /-------\    /-------\
 *      status_fru_list    | status_record | -> | uurec | -> | uurec | -|
 *            \/           |               | |- |       | <- |       |
 *      /-------------\    |               |    \-------/    \-------/
 *      |             | -> |               |       \/           \/
 *      \-------------/    |               |    /-------\    /-------\
 *            \/           |               | -> | asru  | -> | asru  |
 *            ---          |               |    |       | <- |       |
 *                         |               |    \-------/    \-------/
 *      status_asru_list   |  class        |
 *            \/           |  resource     |    /-------\    /-------\
 *      /-------------\    |  fru          | -> | list  | -> | list  |
 *      |             | -> |  serial       |    |       | <- |       |
 *      \-------------/    |               |    \-------/    \-------/
 *            \/           \---------------/
 *            ---               \/    /\
 *                         /---------------\
 *                         | status_record |
 *                         \---------------/
 *
 * Fmadm faulty takes a number of options which affect the format of the
 * output displayed. By default, the display reports the FRU and ASRU along
 * with other information on per-case basis as in the example below.
 *
 * --------------- ------------------------------------  -------------- -------
 * TIME            EVENT-ID                              MSG-ID         SEVERITY
 * --------------- ------------------------------------  -------------- -------
 * Sep 21 10:01:36 d482f935-5c8f-e9ab-9f25-d0aaafec1e6c  AMD-8000-2F    Major
 *
 * Fault class	: fault.memory.dimm_sb
 * Affects	: mem:///motherboard=0/chip=0/memory-controller=0/dimm=0/rank=0
 *		    faulted but still in service
 * FRU		: "CPU 0 DIMM 0" (hc://.../memory-controller=0/dimm=0)
 *		    faulty
 *
 * Description	: The number of errors associated with this memory module has
 *		exceeded acceptable levels.  Refer to
 *		http://illumos.org/msg/AMD-8000-2F for more information.
 *
 * Response	: Pages of memory associated with this memory module are being
 *		removed from service as errors are reported.
 *
 * Impact	: Total system memory capacity will be reduced as pages are
 *		retired.
 *
 * Action	: Schedule a repair procedure to replace the affected memory
 *		module.  Use fmdump -v -u <EVENT_ID> to identify the module.
 *
 * The -v flag is similar, but adds some additonal information such as the
 * resource. The -s flag is also similar but just gives the top line summary.
 * All these options (ie without the -f or -r flags) use the print_catalog()
 * function to do the display.
 *
 * The -f flag changes the output so that it appears sorted on a per-fru basis.
 * The output is somewhat cut down compared to the default output. If -f is
 * used, then print_fru() is used to print the output.
 *
 * -----------------------------------------------------------------------------
 * "SLOT 2" (hc://.../hostbridge=3/pciexrc=3/pciexbus=4/pciexdev=0) faulty
 * 5ca4aeb3-36...f6be-c2e8166dc484 2 suspects in this FRU total certainty 100%
 *
 * Description	: A problem was detected for a PCI device.
 *		Refer to http://illumos.org/msg/PCI-8000-7J
 *		for more information.
 *
 * Response	: One or more device instances may be disabled
 *
 * Impact	: Possible loss of services provided by the device instances
 *		associated with this fault
 *
 * Action	: Schedule a repair procedure to replace the affected device.
 * 		Use fmdump -v -u <EVENT_ID> to identify the device or contact
 *		Sun for support.
 *
 * The -r flag changes the output so that it appears sorted on a per-asru basis.
 * The output is very much cut down compared to the default output, just giving
 * the asru fmri and state. Here print_asru() is used to print the output.
 *
 * mem:///motherboard=0/chip=0/memory-controller=0/dimm=0/rank=0	degraded
 *
 * For all fmadm faulty options, the sequence of events is
 *
 * 1) Walk through all the cases in the system using fmd_adm_case_iter() and
 * for each case call dfault_rec(). This will call add_fault_record_to_catalog()
 * This will extract the data from the nvlist and call catalog_new_record() to
 * save the data away in various linked lists in the catalogue.
 *
 * 2) Once this is done, the data can be supplemented by using
 * fmd_adm_rsrc_iter(). However this is now only necessary for the -i option.
 *
 * 3) Finally print_catalog(), print_fru() or print_asru() are called as
 * appropriate to display the information from the catalogue sorted in the
 * requested way.
 *
 */

typedef struct name_list {
	struct name_list *next;
	struct name_list *prev;
	char *name;
	uint8_t pct;
	uint8_t max_pct;
	ushort_t count;
	int status;
	char *label;
} name_list_t;

typedef struct ari_list {
	char *ari_uuid;
	struct ari_list *next;
} ari_list_t;

typedef struct uurec {
	struct uurec *next;
	struct uurec *prev;
	char *uuid;
	ari_list_t *ari_uuid_list;
	name_list_t *asru;
	uint64_t sec;
	nvlist_t *event;
} uurec_t;

typedef struct uurec_select {
	struct uurec_select *next;
	char *uuid;
} uurec_select_t;

typedef struct host_id {
	char *chassis;
	char *server;
	char *platform;
	char *domain;
	char *product_sn;
} hostid_t;

typedef struct host_id_list {
	hostid_t hostid;
	struct host_id_list *next;
} host_id_list_t;

typedef struct status_record {
	hostid_t *host;
	int nrecs;
	uurec_t *uurec;
	char *severity;			/* in C locale */
	char *msgid;
	name_list_t *class;
	name_list_t *resource;
	name_list_t *asru;
	name_list_t *fru;
	name_list_t *serial;
	uint8_t not_suppressed;
	uint8_t injected;
} status_record_t;

typedef struct sr_list {
	struct sr_list *next;
	struct sr_list *prev;
	struct status_record *status_record;
} sr_list_t;

typedef struct resource_list {
	struct resource_list *next;
	struct resource_list *prev;
	sr_list_t *status_rec_list;
	char *resource;
	uint8_t not_suppressed;
	uint8_t injected;
	uint8_t max_pct;
} resource_list_t;

sr_list_t *status_rec_list;
resource_list_t *status_fru_list;
resource_list_t *status_asru_list;

static int max_display;
static int max_fault = 0;
static topo_hdl_t *topo_handle;
static host_id_list_t *host_list;
static int n_server;
static int opt_g;
static fmd_msg_hdl_t *fmadm_msghdl = NULL; /* handle for libfmd_msg calls */

static char *
format_date(char *buf, size_t len, uint64_t sec)
{
	if (sec > LONG_MAX) {
		(void) fprintf(stderr,
		    "record time is too large for 32-bit utility\n");
		(void) snprintf(buf, len, "0x%llx", sec);
	} else {
		time_t tod = (time_t)sec;
		time_t now = time(NULL);
		if (tod > now+60 ||
		    tod < now - 6L*30L*24L*60L*60L) { /* 6 months ago */
			(void) strftime(buf, len, "%b %d %Y    ",
			    localtime(&tod));
		} else {
			(void) strftime(buf, len, "%b %d %T", localtime(&tod));
		}
	}

	return (buf);
}

static hostid_t *
find_hostid_in_list(char *platform, char *chassis, char *server, char *domain,
    char *product_sn)
{
	hostid_t *rt = NULL;
	host_id_list_t *hostp;

	if (platform == NULL)
		platform = "-";
	if (server == NULL)
		server = "-";
	hostp = host_list;
	while (hostp) {
		if (hostp->hostid.platform &&
		    strcmp(hostp->hostid.platform, platform) == 0 &&
		    hostp->hostid.server &&
		    strcmp(hostp->hostid.server, server) == 0 &&
		    (chassis == NULL || hostp->hostid.chassis == NULL ||
		    strcmp(chassis, hostp->hostid.chassis) == 0) &&
		    (product_sn == NULL || hostp->hostid.product_sn == NULL ||
		    strcmp(product_sn, hostp->hostid.product_sn) == 0) &&
		    (domain == NULL || hostp->hostid.domain == NULL ||
		    strcmp(domain, hostp->hostid.domain) == 0)) {
			rt = &hostp->hostid;
			break;
		}
		hostp = hostp->next;
	}
	if (rt == NULL) {
		hostp = malloc(sizeof (host_id_list_t));
		hostp->hostid.platform = strdup(platform);
		hostp->hostid.product_sn =
		    product_sn ? strdup(product_sn) : NULL;
		hostp->hostid.server = strdup(server);
		hostp->hostid.chassis = chassis ? strdup(chassis) : NULL;
		hostp->hostid.domain = domain ? strdup(domain) : NULL;
		hostp->next = host_list;
		host_list = hostp;
		rt = &hostp->hostid;
		n_server++;
	}
	return (rt);
}

static hostid_t *
find_hostid(nvlist_t *nvl)
{
	char *platform = NULL, *chassis = NULL, *server = NULL, *domain = NULL;
	char *product_sn = NULL;
	nvlist_t *auth, *fmri;
	hostid_t *rt = NULL;

	if (nvlist_lookup_nvlist(nvl, FM_SUSPECT_DE, &fmri) == 0 &&
	    nvlist_lookup_nvlist(fmri, FM_FMRI_AUTHORITY, &auth) == 0) {
		(void) nvlist_lookup_string(auth, FM_FMRI_AUTH_PRODUCT,
		    &platform);
		(void) nvlist_lookup_string(auth, FM_FMRI_AUTH_PRODUCT_SN,
		    &product_sn);
		(void) nvlist_lookup_string(auth, FM_FMRI_AUTH_SERVER, &server);
		(void) nvlist_lookup_string(auth, FM_FMRI_AUTH_CHASSIS,
		    &chassis);
		(void) nvlist_lookup_string(auth, FM_FMRI_AUTH_DOMAIN, &domain);
		rt = find_hostid_in_list(platform, chassis, server,
		    domain, product_sn);
	}
	return (rt);
}

static char *
get_nvl2str_topo(nvlist_t *nvl)
{
	char *name = NULL;
	char *tname;
	int err;
	char *scheme = NULL;
	char *mod_name = NULL;
	char buf[128];

	if (topo_handle == NULL)
		topo_handle = topo_open(TOPO_VERSION, 0, &err);
	if (topo_fmri_nvl2str(topo_handle, nvl, &tname, &err) == 0) {
		name = strdup(tname);
		topo_hdl_strfree(topo_handle, tname);
	} else {
		(void) nvlist_lookup_string(nvl, FM_FMRI_SCHEME, &scheme);
		(void) nvlist_lookup_string(nvl, FM_FMRI_MOD_NAME, &mod_name);
		if (scheme && strcmp(scheme, FM_FMRI_SCHEME_FMD) == 0 &&
		    mod_name) {
			(void) snprintf(buf, sizeof (buf), "%s:///module/%s",
			    scheme, mod_name);
			name = strdup(buf);
		}
	}
	return (name);
}

static int
set_priority(char *s)
{
	int rt = 0;

	if (s) {
		if (strcmp(s, "Minor") == 0)
			rt = 1;
		else if (strcmp(s, "Major") == 0)
			rt = 10;
		else if (strcmp(s, "Critical") == 0)
			rt = 100;
	}
	return (rt);
}

static int
cmp_priority(char *s1, char *s2, uint64_t t1, uint64_t t2, uint8_t p1,
    uint8_t p2)
{
	int r1, r2;
	int rt;

	r1 = set_priority(s1);
	r2 = set_priority(s2);
	rt = r1 - r2;
	if (rt == 0) {
		if (t1 > t2)
			rt = 1;
		else if (t1 < t2)
			rt = -1;
		else
			rt = p1 - p2;
	}
	return (rt);
}

/*
 * merge two lists into one, by comparing enties in new and moving into list if
 * name is not there or free off memory for names which are already there
 * add_pct indicates if pct is the sum or highest pct
 */
static name_list_t *
merge_name_list(name_list_t **list, name_list_t *new, int add_pct)
{
	name_list_t *lp, *np, *sp, *rt = NULL;
	int max_pct;

	rt = *list;
	np = new;
	while (np) {
		lp = *list;
		while (lp) {
			if (strcmp(lp->name, np->name) == 0)
				break;
			lp = lp->next;
			if (lp == *list)
				lp = NULL;
		}
		if (np->next == new)
			sp = NULL;
		else
			sp = np->next;
		if (lp) {
			lp->status |= (np->status & FM_SUSPECT_FAULTY);
			if (add_pct) {
				lp->pct += np->pct;
				lp->count += np->count;
			} else if (np->pct > lp->pct) {
				lp->pct = np->pct;
			}
			max_pct = np->max_pct;
			if (np->label)
				free(np->label);
			free(np->name);
			free(np);
			np = NULL;
			if (max_pct > lp->max_pct) {
				lp->max_pct = max_pct;
				if (lp->max_pct > lp->prev->max_pct &&
				    lp != *list) {
					lp->prev->next = lp->next;
					lp->next->prev = lp->prev;
					np = lp;
				}
			}
		}
		if (np) {
			lp = *list;
			if (lp) {
				if (np->max_pct > lp->max_pct) {
					np->next = lp;
					np->prev = lp->prev;
					lp->prev->next = np;
					lp->prev = np;
					*list = np;
					rt = np;
				} else {
					lp = lp->next;
					while (lp != *list &&
					    np->max_pct < lp->max_pct) {
						lp = lp->next;
					}
					np->next = lp;
					np->prev = lp->prev;
					lp->prev->next = np;
					lp->prev = np;
				}
			} else {
				*list = np;
				np->next = np;
				np->prev = np;
				rt = np;
			}
		}
		np = sp;
	}
	return (rt);
}

static name_list_t *
alloc_name_list(char *name, uint8_t pct)
{
	name_list_t *nlp;

	nlp = malloc(sizeof (*nlp));
	nlp->name = strdup(name);
	nlp->pct = pct;
	nlp->max_pct = pct;
	nlp->count = 1;
	nlp->next = nlp;
	nlp->prev = nlp;
	nlp->status = 0;
	nlp->label = NULL;
	return (nlp);
}

static status_record_t *
new_record_init(uurec_t *uurec_p, char *msgid, name_list_t *class,
    name_list_t *fru, name_list_t *asru, name_list_t *resource,
    name_list_t *serial, boolean_t not_suppressed,
    hostid_t *hostid, boolean_t injected)
{
	status_record_t *status_rec_p;

	status_rec_p = (status_record_t *)malloc(sizeof (status_record_t));
	status_rec_p->nrecs = 1;
	status_rec_p->host = hostid;
	status_rec_p->uurec = uurec_p;
	uurec_p->next = NULL;
	uurec_p->prev = NULL;
	uurec_p->asru = asru;
	if ((status_rec_p->severity = fmd_msg_getitem_id(fmadm_msghdl, NULL,
	    msgid, FMD_MSG_ITEM_SEVERITY)) == NULL)
		status_rec_p->severity = strdup("unknown");
	status_rec_p->class = class;
	status_rec_p->fru = fru;
	status_rec_p->asru = asru;
	status_rec_p->resource = resource;
	status_rec_p->serial = serial;
	status_rec_p->msgid = strdup(msgid);
	status_rec_p->not_suppressed = not_suppressed;
	status_rec_p->injected = injected;
	return (status_rec_p);
}

/*
 * add record to given list maintaining order higher priority first.
 */
static void
add_rec_list(status_record_t *status_rec_p, sr_list_t **list_pp)
{
	sr_list_t *tp, *np, *sp;
	int order;
	uint64_t sec;

	np = malloc(sizeof (sr_list_t));
	np->status_record = status_rec_p;
	sec = status_rec_p->uurec->sec;
	if ((sp = *list_pp) == NULL) {
		*list_pp = np;
		np->next = np;
		np->prev = np;
	} else {
		/* insert new record in front of lower priority */
		tp = sp;
		order = cmp_priority(status_rec_p->severity,
		    sp->status_record->severity, sec,
		    tp->status_record->uurec->sec, 0, 0);
		if (order > 0) {
			*list_pp = np;
		} else {
			tp = sp->next;
			while (tp != sp &&
			    cmp_priority(status_rec_p->severity,
			    tp->status_record->severity, sec,
			    tp->status_record->uurec->sec, 0, 0)) {
				tp = tp->next;
			}
		}
		np->next = tp;
		np->prev = tp->prev;
		tp->prev->next = np;
		tp->prev = np;
	}
}

static void
add_resource(status_record_t *status_rec_p, resource_list_t **rp,
    resource_list_t *np)
{
	int order;
	uint64_t sec;
	resource_list_t *sp, *tp;
	status_record_t *srp;
	char *severity = status_rec_p->severity;

	add_rec_list(status_rec_p, &np->status_rec_list);
	if ((sp = *rp) == NULL) {
		np->next = np;
		np->prev = np;
		*rp = np;
	} else {
		/*
		 * insert new record in front of lower priority
		 */
		tp = sp->next;
		srp = sp->status_rec_list->status_record;
		sec = status_rec_p->uurec->sec;
		order = cmp_priority(severity, srp->severity, sec,
		    srp->uurec->sec, np->max_pct, sp->max_pct);
		if (order > 0) {
			*rp = np;
		} else {
			srp = tp->status_rec_list->status_record;
			while (tp != sp &&
			    cmp_priority(severity, srp->severity, sec,
			    srp->uurec->sec, np->max_pct, sp->max_pct) < 0) {
				tp = tp->next;
				srp = tp->status_rec_list->status_record;
			}
		}
		np->next = tp;
		np->prev = tp->prev;
		tp->prev->next = np;
		tp->prev = np;
	}
}

static void
add_resource_list(status_record_t *status_rec_p, name_list_t *fp,
    resource_list_t **rpp)
{
	int order;
	resource_list_t *np, *end;
	status_record_t *srp;

	np = *rpp;
	end = np;
	while (np) {
		if (strcmp(fp->name, np->resource) == 0) {
			np->not_suppressed |= status_rec_p->not_suppressed;
			np->injected |= status_rec_p->injected;
			srp = np->status_rec_list->status_record;
			order = cmp_priority(status_rec_p->severity,
			    srp->severity, status_rec_p->uurec->sec,
			    srp->uurec->sec, fp->max_pct, np->max_pct);
			if (order > 0 && np != end) {
				/*
				 * remove from list and add again using
				 * new priority
				 */
				np->prev->next = np->next;
				np->next->prev = np->prev;
				add_resource(status_rec_p,
				    rpp, np);
			} else {
				add_rec_list(status_rec_p,
				    &np->status_rec_list);
			}
			break;
		}
		np = np->next;
		if (np == end) {
			np = NULL;
			break;
		}
	}
	if (np == NULL) {
		np = malloc(sizeof (resource_list_t));
		np->resource = fp->name;
		np->not_suppressed = status_rec_p->not_suppressed;
		np->injected = status_rec_p->injected;
		np->status_rec_list = NULL;
		np->max_pct = fp->max_pct;
		add_resource(status_rec_p, rpp, np);
	}
}

static void
add_list(status_record_t *status_rec_p, name_list_t *listp,
    resource_list_t **glistp)
{
	name_list_t *fp, *end;

	fp = listp;
	end = fp;
	while (fp) {
		add_resource_list(status_rec_p, fp, glistp);
		fp = fp->next;
		if (fp == end)
			break;
	}
}

/*
 * add record to rec, fru and asru lists.
 */
static void
catalog_new_record(uurec_t *uurec_p, char *msgid, name_list_t *class,
    name_list_t *fru, name_list_t *asru, name_list_t *resource,
    name_list_t *serial, boolean_t not_suppressed,
    hostid_t *hostid, boolean_t injected, boolean_t dummy_fru)
{
	status_record_t *status_rec_p;

	status_rec_p = new_record_init(uurec_p, msgid, class, fru, asru,
	    resource, serial, not_suppressed, hostid, injected);
	add_rec_list(status_rec_p, &status_rec_list);
	if (status_rec_p->fru && !dummy_fru)
		add_list(status_rec_p, status_rec_p->fru, &status_fru_list);
	if (status_rec_p->asru)
		add_list(status_rec_p, status_rec_p->asru, &status_asru_list);
}

static void
get_serial_no(nvlist_t *nvl, name_list_t **serial_p, uint8_t pct)
{
	char *name;
	char *serial = NULL;
	char **lserial = NULL;
	uint64_t serint;
	name_list_t *nlp;
	int j;
	uint_t nelem;
	char buf[64];

	if (nvlist_lookup_string(nvl, FM_FMRI_SCHEME, &name) == 0) {
		if (strcmp(name, FM_FMRI_SCHEME_CPU) == 0) {
			if (nvlist_lookup_uint64(nvl, FM_FMRI_CPU_SERIAL_ID,
			    &serint) == 0) {
				(void) snprintf(buf, sizeof (buf), "%llX",
				    serint);
				nlp = alloc_name_list(buf, pct);
				(void) merge_name_list(serial_p, nlp, 1);
			}
		} else if (strcmp(name, FM_FMRI_SCHEME_MEM) == 0) {
			if (nvlist_lookup_string_array(nvl,
			    FM_FMRI_MEM_SERIAL_ID, &lserial, &nelem) == 0) {
				nlp = alloc_name_list(lserial[0], pct);
				for (j = 1; j < nelem; j++) {
					name_list_t *n1lp;
					n1lp = alloc_name_list(lserial[j], pct);
					(void) merge_name_list(&nlp, n1lp, 1);
				}
				(void) merge_name_list(serial_p, nlp, 1);
			}
		} else if (strcmp(name, FM_FMRI_SCHEME_HC) == 0) {
			if (nvlist_lookup_string(nvl, FM_FMRI_HC_SERIAL_ID,
			    &serial) == 0) {
				nlp = alloc_name_list(serial, pct);
				(void) merge_name_list(serial_p, nlp, 1);
			}
		}
	}
}

static void
extract_record_info(nvlist_t *nvl, name_list_t **class_p,
    name_list_t **fru_p, name_list_t **serial_p, name_list_t **resource_p,
    name_list_t **asru_p, boolean_t *dummy_fru, uint8_t status)
{
	nvlist_t *lfru, *lasru, *rsrc;
	name_list_t *nlp;
	char *name;
	uint8_t lpct = 0;
	char *lclass = NULL;
	char *label;

	(void) nvlist_lookup_uint8(nvl, FM_FAULT_CERTAINTY, &lpct);
	if (nvlist_lookup_string(nvl, FM_CLASS, &lclass) == 0) {
		nlp = alloc_name_list(lclass, lpct);
		(void) merge_name_list(class_p, nlp, 1);
	}
	if (nvlist_lookup_nvlist(nvl, FM_FAULT_FRU, &lfru) == 0) {
		name = get_nvl2str_topo(lfru);
		if (name != NULL) {
			nlp = alloc_name_list(name, lpct);
			nlp->status = status & ~(FM_SUSPECT_UNUSABLE |
			    FM_SUSPECT_DEGRADED);
			free(name);
			if (nvlist_lookup_string(nvl, FM_FAULT_LOCATION,
			    &label) == 0)
				nlp->label = strdup(label);
			(void) merge_name_list(fru_p, nlp, 1);
		}
		get_serial_no(lfru, serial_p, lpct);
	} else if (nvlist_lookup_nvlist(nvl, FM_FAULT_RESOURCE, &rsrc) != 0) {
		/*
		 * No FRU or resource. But we want to display the repair status
		 * somehow, so create a dummy FRU field.
		 */
		*dummy_fru = 1;
		nlp = alloc_name_list(dgettext("FMD", "None"), lpct);
		nlp->status = status & ~(FM_SUSPECT_UNUSABLE |
		    FM_SUSPECT_DEGRADED);
		(void) merge_name_list(fru_p, nlp, 1);
	}
	if (nvlist_lookup_nvlist(nvl, FM_FAULT_ASRU, &lasru) == 0) {
		name = get_nvl2str_topo(lasru);
		if (name != NULL) {
			nlp = alloc_name_list(name, lpct);
			nlp->status = status & ~(FM_SUSPECT_NOT_PRESENT |
			    FM_SUSPECT_REPAIRED | FM_SUSPECT_REPLACED |
			    FM_SUSPECT_ACQUITTED);
			free(name);
			(void) merge_name_list(asru_p, nlp, 1);
		}
		get_serial_no(lasru, serial_p, lpct);
	}
	if (nvlist_lookup_nvlist(nvl, FM_FAULT_RESOURCE, &rsrc) == 0) {
		name = get_nvl2str_topo(rsrc);
		if (name != NULL) {
			nlp = alloc_name_list(name, lpct);
			nlp->status = status;
			free(name);
			if (nvlist_lookup_string(nvl, FM_FAULT_LOCATION,
			    &label) == 0)
				nlp->label = strdup(label);
			(void) merge_name_list(resource_p, nlp, 1);
		}
	}
}

static void
add_fault_record_to_catalog(nvlist_t *nvl, uint64_t sec, char *uuid)
{
	char *msgid = "-";
	uint_t i, size = 0;
	name_list_t *class = NULL, *resource = NULL;
	name_list_t *asru = NULL, *fru = NULL, *serial = NULL;
	nvlist_t **nva;
	uint8_t *ba;
	uurec_t *uurec_p;
	hostid_t *host;
	boolean_t not_suppressed = 1;
	boolean_t any_present = 0;
	boolean_t injected = 0;
	boolean_t dummy_fru = 0;

	(void) nvlist_lookup_string(nvl, FM_SUSPECT_DIAG_CODE, &msgid);
	(void) nvlist_lookup_uint32(nvl, FM_SUSPECT_FAULT_SZ, &size);
	(void) nvlist_lookup_boolean_value(nvl, FM_SUSPECT_MESSAGE,
	    &not_suppressed);
	(void) nvlist_lookup_boolean_value(nvl, FM_SUSPECT_INJECTED, &injected);

	if (size != 0) {
		(void) nvlist_lookup_nvlist_array(nvl, FM_SUSPECT_FAULT_LIST,
		    &nva, &size);
		(void) nvlist_lookup_uint8_array(nvl, FM_SUSPECT_FAULT_STATUS,
		    &ba, &size);
		for (i = 0; i < size; i++) {
			extract_record_info(nva[i], &class, &fru, &serial,
			    &resource, &asru, &dummy_fru, ba[i]);
			if (!(ba[i] & FM_SUSPECT_NOT_PRESENT) &&
			    (ba[i] & FM_SUSPECT_FAULTY))
				any_present = 1;
		}
		/*
		 * also suppress if no resources present
		 */
		if (any_present == 0)
			not_suppressed = 0;
	}

	uurec_p = (uurec_t *)malloc(sizeof (uurec_t));
	uurec_p->uuid = strdup(uuid);
	uurec_p->sec = sec;
	uurec_p->ari_uuid_list = NULL;
	uurec_p->event = NULL;
	(void) nvlist_dup(nvl, &uurec_p->event, 0);
	host = find_hostid(nvl);
	catalog_new_record(uurec_p, msgid, class, fru, asru,
	    resource, serial, not_suppressed, host, injected, dummy_fru);
}

static void
update_asru_state_in_catalog(const char *uuid, const char *ari_uuid)
{
	sr_list_t *srp;
	uurec_t *uurp;
	ari_list_t *ari_list;

	srp = status_rec_list;
	if (srp) {
		for (;;) {
			uurp = srp->status_record->uurec;
			while (uurp) {
				if (strcmp(uuid, uurp->uuid) == 0) {
					ari_list = (ari_list_t *)
					    malloc(sizeof (ari_list_t));
					ari_list->ari_uuid = strdup(ari_uuid);
					ari_list->next = uurp->ari_uuid_list;
					uurp->ari_uuid_list = ari_list;
					return;
				}
				uurp = uurp->next;
			}
			if (srp->next == status_rec_list)
				break;
			srp = srp->next;
		}
	}
}

static void
print_line(char *label, char *buf)
{
	char *cp, *ep, *wp;
	char c;
	int i;
	int lsz;
	char *padding;

	lsz = strlen(label);
	padding = malloc(lsz + 1);
	for (i = 0; i < lsz; i++)
		padding[i] = ' ';
	padding[i] = 0;
	cp = buf;
	ep = buf;
	c = *ep;
	(void) printf("\n");
	while (c) {
		i = lsz;
		wp = NULL;
		while ((c = *ep) != NULL && (wp == NULL || i < 80)) {
			if (c == ' ')
				wp = ep;
			else if (c == '\n') {
				i = 0;
				*ep = 0;
				do {
					ep++;
				} while ((c = *ep) != NULL && c == ' ');
				break;
			}
			ep++;
			i++;
		}
		if (i >= 80 && wp) {
			*wp = 0;
			ep = wp + 1;
			c = *ep;
		}
		(void) printf("%s%s\n", label, cp);
		cp = ep;
		label = padding;
	}
	free(padding);
}

static void
print_dict_info_line(nvlist_t *e, fmd_msg_item_t what, const char *linehdr)
{
	char *cp = fmd_msg_getitem_nv(fmadm_msghdl, NULL, e, what);

	if (cp) {
		print_line(dgettext("FMD", linehdr), cp);
		free(cp);
	}
}

static void
print_dict_info(nvlist_t *nvl)
{
	print_dict_info_line(nvl, FMD_MSG_ITEM_DESC, "Description : ");
	print_dict_info_line(nvl, FMD_MSG_ITEM_RESPONSE, "Response    : ");
	print_dict_info_line(nvl, FMD_MSG_ITEM_IMPACT, "Impact      : ");
	print_dict_info_line(nvl, FMD_MSG_ITEM_ACTION, "Action      : ");
}

static void
print_name(name_list_t *list, char *padding, int *np, int pct, int full)
{
	char *name;

	name = list->name;
	if (list->label) {
		(void) printf("%s \"%s\" (%s)", padding, list->label, name);
		*np += 1;
	} else {
		(void) printf("%s %s", padding, name);
		*np += 1;
	}
	if (list->pct && pct > 0 && pct < 100) {
		if (list->count > 1) {
			if (full) {
				(void) printf(" %d @ %s %d%%\n", list->count,
				    dgettext("FMD", "max"),
				    list->max_pct);
			} else {
				(void) printf(" %s %d%%\n",
				    dgettext("FMD", "max"),
				    list->max_pct);
			}
		} else {
			(void) printf(" %d%%\n", list->pct);
		}
	} else {
		(void) printf("\n");
	}
}

static void
print_asru_status(int status, char *label)
{
	char *msg = NULL;

	switch (status) {
	case 0:
		msg = dgettext("FMD", "ok and in service");
		break;
	case FM_SUSPECT_DEGRADED:
		msg = dgettext("FMD", "service degraded, "
		    "but associated components no longer faulty");
		break;
	case FM_SUSPECT_FAULTY | FM_SUSPECT_DEGRADED:
		msg = dgettext("FMD", "faulted but still "
		    "providing degraded service");
		break;
	case FM_SUSPECT_FAULTY:
		msg = dgettext("FMD", "faulted but still in service");
		break;
	case FM_SUSPECT_UNUSABLE:
		msg = dgettext("FMD", "out of service, "
		    "but associated components no longer faulty");
		break;
	case FM_SUSPECT_FAULTY | FM_SUSPECT_UNUSABLE:
		msg = dgettext("FMD", "faulted and taken out of service");
		break;
	default:
		break;
	}
	if (msg) {
		(void) printf("%s     %s\n", label, msg);
	}
}

static void
print_fru_status(int status, char *label)
{
	char *msg = NULL;

	if (status & FM_SUSPECT_NOT_PRESENT)
		msg = dgettext("FMD", "not present");
	else if (status & FM_SUSPECT_FAULTY)
		msg = dgettext("FMD", "faulty");
	else if (status & FM_SUSPECT_REPLACED)
		msg = dgettext("FMD", "replaced");
	else if (status & FM_SUSPECT_REPAIRED)
		msg = dgettext("FMD", "repair attempted");
	else if (status & FM_SUSPECT_ACQUITTED)
		msg = dgettext("FMD", "acquitted");
	else
		msg = dgettext("FMD", "removed");
	(void) printf("%s     %s\n", label, msg);
}

static void
print_rsrc_status(int status, char *label)
{
	char *msg = "";

	if (status & FM_SUSPECT_NOT_PRESENT)
		msg = dgettext("FMD", "not present");
	else if (status & FM_SUSPECT_FAULTY) {
		if (status & FM_SUSPECT_DEGRADED)
			msg = dgettext("FMD",
			    "faulted but still providing degraded service");
		else if (status & FM_SUSPECT_UNUSABLE)
			msg = dgettext("FMD",
			    "faulted and taken out of service");
		else
			msg = dgettext("FMD", "faulted but still in service");
	} else if (status & FM_SUSPECT_REPLACED)
		msg = dgettext("FMD", "replaced");
	else if (status & FM_SUSPECT_REPAIRED)
		msg = dgettext("FMD", "repair attempted");
	else if (status & FM_SUSPECT_ACQUITTED)
		msg = dgettext("FMD", "acquitted");
	else
		msg = dgettext("FMD", "removed");
	(void) printf("%s     %s\n", label, msg);
}

static void
print_name_list(name_list_t *list, char *label,
    int limit, int pct, void (func1)(int, char *), int full)
{
	char *name;
	char *padding;
	int i, j, l, n;
	name_list_t *end = list;

	l = strlen(label);
	padding = malloc(l + 1);
	for (i = 0; i < l; i++)
		padding[i] = ' ';
	padding[l] = 0;
	(void) printf("%s", label);
	name = list->name;
	if (list->label)
		(void) printf(" \"%s\" (%s)", list->label, name);
	else
		(void) printf(" %s", name);
	if (list->pct && pct > 0 && pct < 100) {
		if (list->count > 1) {
			if (full) {
				(void) printf(" %d @ %s %d%%\n", list->count,
				    dgettext("FMD", "max"), list->max_pct);
			} else {
				(void) printf(" %s %d%%\n",
				    dgettext("FMD", "max"), list->max_pct);
			}
		} else {
			(void) printf(" %d%%\n", list->pct);
		}
	} else {
		(void) printf("\n");
	}
	if (func1)
		func1(list->status, padding);
	n = 1;
	j = 0;
	while ((list = list->next) != end) {
		if (limit == 0 || n < limit) {
			print_name(list, padding, &n, pct, full);
			if (func1)
				func1(list->status, padding);
		} else
			j++;
	}
	if (j == 1) {
		print_name(list->prev, padding, &n, pct, full);
	} else if (j > 1) {
		(void) printf("%s... %d %s\n", padding, j,
		    dgettext("FMD", "more entries suppressed,"
		    " use -v option for full list"));
	}
	free(padding);
}

static int
asru_same_status(name_list_t *list)
{
	name_list_t *end = list;
	int status = list->status;

	while ((list = list->next) != end) {
		if (status == -1) {
			status = list->status;
			continue;
		}
		if (list->status != -1 && status != list->status) {
			status = -1;
			break;
		}
	}
	return (status);
}

static int
serial_in_fru(name_list_t *fru, name_list_t *serial)
{
	name_list_t *sp = serial;
	name_list_t *fp;
	int nserial = 0;
	int found = 0;
	char buf[128];

	while (sp) {
		fp = fru;
		nserial++;
		(void) snprintf(buf, sizeof (buf), "serial=%s", sp->name);
		buf[sizeof (buf) - 1] = 0;
		while (fp) {
			if (strstr(fp->name, buf) != NULL) {
				found++;
				break;
			}
			fp = fp->next;
			if (fp == fru)
				break;
		}
		sp = sp->next;
		if (sp == serial)
			break;
	}
	return (found == nserial ? 1 : 0);
}

static void
print_sup_record(status_record_t *srp, int opt_i, int full)
{
	char buf[32];
	uurec_t *uurp = srp->uurec;
	int n, j, k, max;
	int status;
	ari_list_t *ari_list;

	n = 0;
	max = max_fault;
	if (max < 0) {
		max = 0;
	}
	j = max / 2;
	max -= j;
	k = srp->nrecs - max;
	while ((uurp = uurp->next) != NULL) {
		if (full || n < j || n >= k || max_fault == 0 ||
		    srp->nrecs == max_fault+1) {
			if (opt_i) {
				ari_list = uurp->ari_uuid_list;
				while (ari_list) {
					(void) printf("%-15s %s\n",
					    format_date(buf, sizeof (buf),
					    uurp->sec), ari_list->ari_uuid);
					ari_list = ari_list->next;
				}
			} else {
				(void) printf("%-15s %s\n",
				    format_date(buf, sizeof (buf), uurp->sec),
				    uurp->uuid);
			}
		} else if (n == j)
			(void) printf("... %d %s\n", srp->nrecs - max_fault,
			    dgettext("FMD", "more entries suppressed"));
		n++;
	}
	(void) printf("\n");
	(void) printf("%s %s", dgettext("FMD", "Host        :"),
	    srp->host->server);
	if (srp->host->domain)
		(void) printf("\t%s %s", dgettext("FMD", "Domain      :"),
		    srp->host->domain);
	(void) printf("\n%s %s", dgettext("FMD", "Platform    :"),
	    srp->host->platform);
	(void) printf("\t%s %s", dgettext("FMD", "Chassis_id  :"),
	    srp->host->chassis ? srp->host->chassis : "");
	(void) printf("\n%s %s\n\n", dgettext("FMD", "Product_sn  :"),
	    srp->host->product_sn? srp->host->product_sn : "");
	if (srp->class)
		print_name_list(srp->class,
		    dgettext("FMD", "Fault class :"), 0, srp->class->pct,
		    NULL, full);
	if (srp->asru) {
		status = asru_same_status(srp->asru);
		if (status != -1) {
			print_name_list(srp->asru,
			    dgettext("FMD", "Affects     :"),
			    full ? 0 : max_display, 0, NULL, full);
			print_asru_status(status, "             ");
		} else
			print_name_list(srp->asru,
			    dgettext("FMD", "Affects     :"),
			    full ? 0 : max_display, 0, print_asru_status, full);
	}
	if (full || srp->fru == NULL || srp->asru == NULL) {
		if (srp->resource) {
			status = asru_same_status(srp->resource);
			if (status != -1) {
				print_name_list(srp->resource,
				    dgettext("FMD", "Problem in  :"),
				    full ? 0 : max_display, 0, NULL, full);
				print_rsrc_status(status, "             ");
			} else
				print_name_list(srp->resource,
				    dgettext("FMD", "Problem in  :"),
				    full ? 0 : max_display, 0,
				    print_rsrc_status, full);
		}
	}
	if (srp->fru) {
		status = asru_same_status(srp->fru);
		if (status != -1) {
			print_name_list(srp->fru, dgettext("FMD",
			    "FRU         :"), 0,
			    srp->fru->pct == 100 ? 100 : srp->fru->max_pct,
			    NULL, full);
			print_fru_status(status, "             ");
		} else
			print_name_list(srp->fru, dgettext("FMD",
			    "FRU         :"), 0,
			    srp->fru->pct == 100 ? 100 : srp->fru->max_pct,
			    print_fru_status, full);
	}
	if (srp->serial && !serial_in_fru(srp->fru, srp->serial) &&
	    !serial_in_fru(srp->asru, srp->serial)) {
		print_name_list(srp->serial, dgettext("FMD", "Serial ID.  :"),
		    0, 0, NULL, full);
	}
	print_dict_info(srp->uurec->event);
	(void) printf("\n");
}

static void
print_status_record(status_record_t *srp, int summary, int opt_i, int full)
{
	char buf[32];
	uurec_t *uurp = srp->uurec;
	static int header = 0;
	char *head;
	ari_list_t *ari_list;

	if (!summary || !header) {
		if (opt_i) {
			head = "--------------- "
			    "------------------------------------  "
			    "-------------- ---------\n"
			    "TIME            CACHE-ID"
			    "                              MSG-ID"
			    "         SEVERITY\n--------------- "
			    "------------------------------------ "
			    " -------------- ---------";
		} else {
			head = "--------------- "
			    "------------------------------------  "
			    "-------------- ---------\n"
			    "TIME            EVENT-ID"
			    "                              MSG-ID"
			    "         SEVERITY\n--------------- "
			    "------------------------------------ "
			    " -------------- ---------";
		}
		(void) printf("%s\n", dgettext("FMD", head));
		header = 1;
	}
	if (opt_i) {
		ari_list = uurp->ari_uuid_list;
		while (ari_list) {
			(void) printf("%-15s %-37s %-14s %-9s %s\n",
			    format_date(buf, sizeof (buf), uurp->sec),
			    ari_list->ari_uuid, srp->msgid, srp->severity,
			    srp->injected ? dgettext("FMD", "injected") : "");
			ari_list = ari_list->next;
		}
	} else {
		(void) printf("%-15s %-37s %-14s %-9s %s\n",
		    format_date(buf, sizeof (buf), uurp->sec),
		    uurp->uuid, srp->msgid, srp->severity,
		    srp->injected ? dgettext("FMD", "injected") : "");
	}

	if (!summary)
		print_sup_record(srp, opt_i, full);
}

static void
print_catalog(int summary, int opt_a, int full, int opt_i, int page_feed)
{
	status_record_t *srp;
	sr_list_t *slp;

	slp = status_rec_list;
	if (slp) {
		for (;;) {
			srp = slp->status_record;
			if (opt_a || srp->not_suppressed) {
				if (page_feed)
					(void) printf("\f\n");
				print_status_record(srp, summary, opt_i, full);
			}
			if (slp->next == status_rec_list)
				break;
			slp = slp->next;
		}
	}
}

static name_list_t *
find_fru(status_record_t *srp, char *resource)
{
	name_list_t *rt = NULL;
	name_list_t *fru = srp->fru;

	while (fru) {
		if (strcmp(resource, fru->name) == 0) {
			rt = fru;
			break;
		}
		fru = fru->next;
		if (fru == srp->fru)
			break;
	}
	return (rt);
}

static void
print_fru_line(name_list_t *fru, char *uuid)
{
	if (fru->pct == 100) {
		(void) printf("%s %d %s %d%%\n", uuid, fru->count,
		    dgettext("FMD", "suspects in this FRU total certainty"),
		    100);
	} else {
		(void) printf("%s %d %s %d%%\n", uuid, fru->count,
		    dgettext("FMD", "suspects in this FRU max certainty"),
		    fru->max_pct);
	}
}

static void
print_fru(int summary, int opt_a, int opt_i, int page_feed)
{
	resource_list_t *tp = status_fru_list;
	status_record_t *srp;
	sr_list_t *slp, *end;
	uurec_t *uurp;
	name_list_t *fru;
	int status;
	ari_list_t *ari_list;

	while (tp) {
		if (opt_a || tp->not_suppressed) {
			if (page_feed)
				(void) printf("\f\n");
			if (!summary)
				(void) printf("-----------------------------"
				    "---------------------------------------"
				    "----------\n");
			slp = tp->status_rec_list;
			end = slp;
			do {
				srp = slp->status_record;
				if (!srp->not_suppressed) {
					slp = slp->next;
					continue;
				}
				fru = find_fru(srp, tp->resource);
				if (fru) {
					if (fru->label)
						(void) printf("\"%s\" (%s) ",
						    fru->label, fru->name);
					else
						(void) printf("%s ",
						    fru->name);
					break;
				}
				slp = slp->next;
			} while (slp != end);

			slp = tp->status_rec_list;
			end = slp;
			status = 0;
			do {
				srp = slp->status_record;
				if (!srp->not_suppressed) {
					slp = slp->next;
					continue;
				}
				fru = srp->fru;
				while (fru) {
					if (strcmp(tp->resource,
					    fru->name) == 0)
						status |= fru->status;
					fru = fru->next;
					if (fru == srp->fru)
						break;
				}
				slp = slp->next;
			} while (slp != end);
			if (status & FM_SUSPECT_NOT_PRESENT)
				(void) printf(dgettext("FMD", "not present"));
			else if (status & FM_SUSPECT_FAULTY)
				(void) printf(dgettext("FMD", "faulty"));
			else if (status & FM_SUSPECT_REPLACED)
				(void) printf(dgettext("FMD", "replaced"));
			else if (status & FM_SUSPECT_REPAIRED)
				(void) printf(dgettext("FMD",
				    "repair attempted"));
			else if (status & FM_SUSPECT_ACQUITTED)
				(void) printf(dgettext("FMD", "acquitted"));
			else
				(void) printf(dgettext("FMD", "removed"));

			if (tp->injected)
				(void) printf(dgettext("FMD", " injected\n"));
			else
				(void) printf(dgettext("FMD", "\n"));

			slp = tp->status_rec_list;
			end = slp;
			do {
				srp = slp->status_record;
				if (!srp->not_suppressed) {
					slp = slp->next;
					continue;
				}
				uurp = srp->uurec;
				fru = find_fru(srp, tp->resource);
				if (fru) {
					if (opt_i) {
						ari_list = uurp->ari_uuid_list;
						while (ari_list) {
							print_fru_line(fru,
							    ari_list->ari_uuid);
							ari_list =
							    ari_list->next;
						}
					} else {
						print_fru_line(fru, uurp->uuid);
					}
				}
				slp = slp->next;
			} while (slp != end);
			if (!summary) {
				slp = tp->status_rec_list;
				end = slp;
				do {
					srp = slp->status_record;
					if (!srp->not_suppressed) {
						slp = slp->next;
						continue;
					}
					if (srp->serial &&
					    !serial_in_fru(srp->fru,
					    srp->serial)) {
						print_name_list(srp->serial,
						    dgettext("FMD",
						    "Serial ID.  :"),
						    0, 0, NULL, 1);
						break;
					}
					slp = slp->next;
				} while (slp != end);
			}
		}
		tp = tp->next;
		if (tp == status_fru_list)
			break;
	}
}

static void
print_asru(int opt_a)
{
	resource_list_t *tp = status_asru_list;
	status_record_t *srp;
	sr_list_t *slp, *end;
	char *msg;
	int status;
	name_list_t *asru;

	while (tp) {
		if (opt_a || tp->not_suppressed) {
			status = 0;
			slp = tp->status_rec_list;
			end = slp;
			do {
				srp = slp->status_record;
				if (!srp->not_suppressed) {
					slp = slp->next;
					continue;
				}
				asru = srp->asru;
				while (asru) {
					if (strcmp(tp->resource,
					    asru->name) == 0)
						status |= asru->status;
					asru = asru->next;
					if (asru == srp->asru)
						break;
				}
				slp = slp->next;
			} while (slp != end);
			switch (status) {
			case 0:
				msg = dgettext("FMD", "ok");
				break;
			case FM_SUSPECT_DEGRADED:
				msg = dgettext("FMD", "degraded");
				break;
			case FM_SUSPECT_FAULTY | FM_SUSPECT_DEGRADED:
				msg = dgettext("FMD", "degraded");
				break;
			case FM_SUSPECT_FAULTY:
				msg = dgettext("FMD", "degraded");
				break;
			case FM_SUSPECT_UNUSABLE:
				msg = dgettext("FMD", "unknown");
				break;
			case FM_SUSPECT_FAULTY | FM_SUSPECT_UNUSABLE:
				msg = dgettext("FMD", "faulted");
				break;
			default:
				msg = "";
				break;
			}
			(void) printf("%-69s %s", tp->resource, msg);
			if (tp->injected)
				(void) printf(dgettext("FMD", " injected\n"));
			else
				(void) printf(dgettext("FMD", "\n"));
		}
		tp = tp->next;
		if (tp == status_asru_list)
			break;
	}
}

static int
uuid_in_list(char *uuid, uurec_select_t *uurecp)
{
	while (uurecp) {
		if (strcmp(uuid, uurecp->uuid) == 0)
			return (1);
		uurecp = uurecp->next;
	}
	return (0);
}

static int
dfault_rec(const fmd_adm_caseinfo_t *acp, void *arg)
{
	int64_t *diag_time;
	uint_t nelem;
	int rt = 0;
	char *uuid = "-";
	uurec_select_t *uurecp = (uurec_select_t *)arg;

	if (nvlist_lookup_int64_array(acp->aci_event, FM_SUSPECT_DIAG_TIME,
	    &diag_time, &nelem) == 0 && nelem >= 2) {
		(void) nvlist_lookup_string(acp->aci_event, FM_SUSPECT_UUID,
		    &uuid);
		if (uurecp == NULL || uuid_in_list(uuid, uurecp))
			add_fault_record_to_catalog(acp->aci_event, *diag_time,
			    uuid);
	} else {
		rt = -1;
	}
	return (rt);
}

/*ARGSUSED*/
static int
dstatus_rec(const fmd_adm_rsrcinfo_t *ari, void *unused)
{
	update_asru_state_in_catalog(ari->ari_case, ari->ari_uuid);
	return (0);
}

static int
get_cases_from_fmd(fmd_adm_t *adm, uurec_select_t *uurecp, int opt_i)
{
	int rt = FMADM_EXIT_SUCCESS;

	/*
	 * These calls may fail with Protocol error if message payload is
	 * too big
	 */
	if (fmd_adm_case_iter(adm, NULL, dfault_rec, uurecp) != 0)
		die("failed to get case list from fmd");
	if (opt_i && fmd_adm_rsrc_iter(adm, 1, dstatus_rec, NULL) != 0)
		die("failed to get case status from fmd");
	return (rt);
}

/*
 * fmadm faulty command
 *
 *	-a		show hidden fault records
 *	-f		show faulty fru's
 *	-g		force grouping of similar faults on the same fru
 *	-n		number of fault records to display
 *	-p		pipe output through pager
 *	-r		show faulty asru's
 *	-s		print summary of first fault
 *	-u		print listed uuid's only
 *	-v		full output
 */

int
cmd_faulty(fmd_adm_t *adm, int argc, char *argv[])
{
	int opt_a = 0, opt_v = 0, opt_p = 0, opt_s = 0, opt_r = 0, opt_f = 0;
	int opt_i = 0;
	char *pager;
	FILE *fp;
	int rt, c, stat;
	uurec_select_t *tp;
	uurec_select_t *uurecp = NULL;

	while ((c = getopt(argc, argv, "afgin:prsu:v")) != EOF) {
		switch (c) {
		case 'a':
			opt_a++;
			break;
		case 'f':
			opt_f++;
			break;
		case 'g':
			opt_g++;
			break;
		case 'i':
			opt_i++;
			break;
		case 'n':
			max_fault = atoi(optarg);
			break;
		case 'p':
			opt_p++;
			break;
		case 'r':
			opt_r++;
			break;
		case 's':
			opt_s++;
			break;
		case 'u':
			tp = (uurec_select_t *)malloc(sizeof (uurec_select_t));
			tp->uuid = optarg;
			tp->next = uurecp;
			uurecp = tp;
			opt_a = 1;
			break;
		case 'v':
			opt_v++;
			break;
		default:
			return (FMADM_EXIT_USAGE);
		}
	}
	if (optind < argc)
		return (FMADM_EXIT_USAGE);

	if ((fmadm_msghdl = fmd_msg_init(NULL, FMD_MSG_VERSION)) == NULL)
		return (FMADM_EXIT_ERROR);
	rt = get_cases_from_fmd(adm, uurecp, opt_i);
	if (opt_p) {
		if ((pager = getenv("PAGER")) == NULL)
			pager = "/usr/bin/more";
		fp = popen(pager, "w");
		if (fp == NULL) {
			rt = FMADM_EXIT_ERROR;
			opt_p = 0;
		} else {
			(void) dup2(fileno(fp), 1);
			setbuf(stdout, NULL);
			(void) fclose(fp);
		}
	}
	max_display = max_fault;
	if (opt_f)
		print_fru(opt_s, opt_a, opt_i, opt_p && !opt_s);
	if (opt_r)
		print_asru(opt_a);
	if (opt_f == 0 && opt_r == 0)
		print_catalog(opt_s, opt_a, opt_v, opt_i, opt_p && !opt_s);
	fmd_msg_fini(fmadm_msghdl);
	if (topo_handle)
		topo_close(topo_handle);
	if (opt_p) {
		(void) fclose(stdout);
		(void) wait(&stat);
	}
	return (rt);
}

int
cmd_flush(fmd_adm_t *adm, int argc, char *argv[])
{
	int i, status = FMADM_EXIT_SUCCESS;

	if (argc < 2 || (i = getopt(argc, argv, "")) != EOF)
		return (FMADM_EXIT_USAGE);

	for (i = 1; i < argc; i++) {
		if (fmd_adm_rsrc_flush(adm, argv[i]) != 0) {
			warn("failed to flush %s", argv[i]);
			status = FMADM_EXIT_ERROR;
		} else
			note("flushed resource history for %s\n", argv[i]);
	}

	return (status);
}

int
cmd_repair(fmd_adm_t *adm, int argc, char *argv[])
{
	int err;

	if (getopt(argc, argv, "") != EOF)
		return (FMADM_EXIT_USAGE);

	if (argc - optind != 1)
		return (FMADM_EXIT_USAGE);

	/*
	 * argument could be a uuid, an fmri (asru, fru or resource)
	 * or a label. Try uuid first, If that fails try the others.
	 */
	err = fmd_adm_case_repair(adm, argv[optind]);
	if (err != 0)
		err = fmd_adm_rsrc_repaired(adm, argv[optind]);

	if (err != 0)
		die("failed to record repair to %s", argv[optind]);

	note("recorded repair to %s\n", argv[optind]);
	return (FMADM_EXIT_SUCCESS);
}

int
cmd_repaired(fmd_adm_t *adm, int argc, char *argv[])
{
	int err;

	if (getopt(argc, argv, "") != EOF)
		return (FMADM_EXIT_USAGE);

	if (argc - optind != 1)
		return (FMADM_EXIT_USAGE);

	/*
	 * argument could be an fmri (asru, fru or resource) or a label.
	 */
	err = fmd_adm_rsrc_repaired(adm, argv[optind]);
	if (err != 0)
		die("failed to record repair to %s", argv[optind]);

	note("recorded repair to of %s\n", argv[optind]);
	return (FMADM_EXIT_SUCCESS);
}

int
cmd_replaced(fmd_adm_t *adm, int argc, char *argv[])
{
	int err;

	if (getopt(argc, argv, "") != EOF)
		return (FMADM_EXIT_USAGE);

	if (argc - optind != 1)
		return (FMADM_EXIT_USAGE);

	/*
	 * argument could be an fmri (asru, fru or resource) or a label.
	 */
	err = fmd_adm_rsrc_replaced(adm, argv[optind]);
	if (err != 0)
		die("failed to record replacement of %s", argv[optind]);

	note("recorded replacement of %s\n", argv[optind]);
	return (FMADM_EXIT_SUCCESS);
}

int
cmd_acquit(fmd_adm_t *adm, int argc, char *argv[])
{
	int err;

	if (getopt(argc, argv, "") != EOF)
		return (FMADM_EXIT_USAGE);

	if (argc - optind != 1 && argc - optind != 2)
		return (FMADM_EXIT_USAGE);

	/*
	 * argument could be a uuid, an fmri (asru, fru or resource)
	 * or a label. Or it could be a uuid and an fmri or label.
	 */
	if (argc - optind == 2) {
		err = fmd_adm_rsrc_acquit(adm, argv[optind], argv[optind + 1]);
		if (err != 0)
			err = fmd_adm_rsrc_acquit(adm, argv[optind + 1],
			    argv[optind]);
	} else {
		err = fmd_adm_case_acquit(adm, argv[optind]);
		if (err != 0)
			err = fmd_adm_rsrc_acquit(adm, argv[optind], "");
	}

	if (err != 0)
		die("failed to record acquital of %s", argv[optind]);

	note("recorded acquital of %s\n", argv[optind]);
	return (FMADM_EXIT_SUCCESS);
}
