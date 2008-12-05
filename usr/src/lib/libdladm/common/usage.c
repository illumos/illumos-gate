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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <fcntl.h>
#include <stdlib.h>
#include <strings.h>
#include <exacct.h>
#include <libdladm.h>

#define	TIMEBUFLEN	20
#define	GBIT		1000000000
#define	MBIT		1000000
#define	KBIT		1000

#define	NET_RESET_TOT(tbytes, ttime, tibytes, tobytes, step) {	\
	(step) = 1;						\
	(tbytes) = 0;						\
	(ttime) = 0;						\
	(tibytes) = 0;						\
	(tobytes) = 0;						\
	}

/* Flow/Link Descriptor */
typedef struct net_desc_s {
	char		net_desc_name[LIFNAMSIZ];
	char		net_desc_devname[LIFNAMSIZ];
	uchar_t		net_desc_ehost[ETHERADDRL];
	uchar_t		net_desc_edest[ETHERADDRL];
	ushort_t	net_desc_vlan_tpid;
	ushort_t	net_desc_vlan_tci;
	ushort_t	net_desc_sap;
	ushort_t	net_desc_cpuid;
	ushort_t	net_desc_priority;
	uint64_t	net_desc_bw_limit;
	in6_addr_t	net_desc_saddr;
	in6_addr_t	net_desc_daddr;
	boolean_t	net_desc_isv4;
	in_port_t	net_desc_sport;
	in_port_t	net_desc_dport;
	uint8_t		net_desc_protocol;
	uint8_t		net_desc_dsfield;
	boolean_t	net_desc_newrec;
} net_desc_t;

/* Time structure: Year, Month, Day, Hour, Min, Sec */
typedef struct net_time_s {
	int	net_time_yr;
	int	net_time_mon;
	int	net_time_day;
	int	net_time_hr;
	int	net_time_min;
	int	net_time_sec;
} net_time_t;

/* Flow/Link Stats */
typedef struct net_stat_s {
	char			net_stat_name[LIFNAMSIZ];
	uint64_t		net_stat_ibytes;
	uint64_t		net_stat_obytes;
	uint64_t		net_stat_ipackets;
	uint64_t		net_stat_opackets;
	uint64_t		net_stat_ierrors;
	uint64_t		net_stat_oerrors;
	uint64_t		net_stat_tibytes;
	uint64_t		net_stat_tobytes;
	uint64_t		net_stat_tipackets;
	uint64_t		net_stat_topackets;
	uint64_t		net_stat_tierrors;
	uint64_t		net_stat_toerrors;
	uint64_t		net_stat_ctime;
	uint64_t		net_stat_tdiff;
	net_time_t		net_stat_time;
	struct net_stat_s	*net_stat_next;
	net_desc_t		*net_stat_desc;
	boolean_t		net_stat_isref;
} net_stat_t;

/* Used to create the [gnu]plot file */
typedef struct net_plot_entry_s {
	char		*net_pe_name;
	uint64_t	net_pe_tottime;
	uint64_t	net_pe_totbytes;
	uint64_t	net_pe_totibytes;
	uint64_t	net_pe_totobytes;
	uint64_t	net_pe_lasttime;
} net_plot_entry_t;

/* Stats entry */
typedef struct net_entry_s {
	net_desc_t		*net_entry_desc;
	net_stat_t		*net_entry_shead;
	net_stat_t		*net_entry_stail;
	int			net_entry_scount;
	net_stat_t		*net_entry_sref;
	net_stat_t		*net_entry_tstats;
	uint64_t		net_entry_ttime;
	struct net_entry_s	*net_entry_next;
} net_entry_t;

/* Time sorted list */
typedef struct net_time_entry_s {
	net_stat_t	*my_time_stat;
	struct net_time_entry_s *net_time_entry_next;
	struct net_time_entry_s *net_time_entry_prev;
} net_time_entry_t;

/* The parsed table */
typedef	struct net_table_s {
	/* List of stats */
	net_entry_t		*net_table_head;
	net_entry_t		*net_table_tail;
	int			net_entries;

	/*
	 * Optimization I : List sorted by time, i.e:
	 * Time		Resource	..
	 * -------------------------------
	 * 11.15.10	bge0
	 * 11.15.10	ce0
	 * 11.15.10	vnic1
	 * 11.15.15	bge0
	 * 11.15.15	ce0
	 * 11.15.15	vnic1
	 */
	net_time_entry_t	*net_time_head;
	net_time_entry_t	*net_time_tail;

	/*
	 * Optimization II : List sorted by resources
	 * Time		Resource	..
	 * -------------------------------
	 * 11.15.10	bge0
	 * 11.15.15	bge0
	 * 11.15.10	ce0
	 * 11.15.15	ce0
	 * 11.15.10	vnic1
	 * 11.15.15	vnic1
	 */
	net_time_entry_t	*net_ctime_head;
	net_time_entry_t	*net_ctime_tail;

	/* Common to both the above (sorted) lists. */
	int			net_time_entries;
} net_table_t;

#define	NET_DATE_GREATER	0
#define	NET_DATE_LESSER		1
#define	NET_DATE_EQUAL		2

#define	NET_TIME_GREATER	0
#define	NET_TIME_LESSER		1
#define	NET_TIME_EQUAL		2

#ifndef _LP64
#define	FMT_UINT64	"%-15llu"
#else
#define	FMT_UINT64	"%-15lu"
#endif

/*
 * Given a timebuf of the form M/D/Y,H:M:S break it into individual elements.
 */
static void
dissect_time(char *tbuf, net_time_t *nt)
{
	char	*d;
	char	*t;
	char	*dd;
	char	*h;
	char	*endp;

	if (tbuf == NULL || nt == NULL)
		return;

	d = strtok(tbuf, ",");	/* Date */
	t = strtok(NULL, ",");	/* Time */

	/* Month */
	dd = strtok(d, "/");
	if (dd == NULL)
		return;
	nt->net_time_mon = strtol(dd, &endp, 10);

	/* Day */
	dd = strtok(NULL, "/");
	if (dd == NULL)
		return;
	nt->net_time_day = strtol(dd, &endp, 10);

	/* Year */
	dd = strtok(NULL, "/");
	if (dd == NULL)
		return;
	nt->net_time_yr = strtol(dd, &endp, 10);
	if (strlen(dd) <= 2)
		nt->net_time_yr += 2000;

	if (t == NULL)
		return;

	/* Hour */
	h = strtok(t, ":");
	if (h == NULL)
		return;
	nt->net_time_hr = strtol(h, &endp, 10);

	/* Min */
	h = strtok(NULL, ":");
	if (h == NULL)
		return;
	nt->net_time_min = strtol(h, &endp, 10);

	/* Sec */
	h = strtok(NULL, ":");
	if (h == NULL)
		return;
	nt->net_time_sec = strtol(h, &endp, 10);
}

/* Get a stat item from an object in the exacct file */
static void
add_stat_item(ea_object_t *o, net_stat_t *ns)
{
	switch (o->eo_catalog & EXT_TYPE_MASK) {
	case EXT_STRING:
		if ((o->eo_catalog & EXD_DATA_MASK) == EXD_NET_STATS_NAME) {
			(void) strncpy(ns->net_stat_name, o->eo_item.ei_string,
			    strlen(o->eo_item.ei_string));
		}
		break;
	case EXT_UINT64:
		if ((o->eo_catalog & EXD_DATA_MASK) == EXD_NET_STATS_CURTIME) {
			time_t	_time;
			char	timebuf[TIMEBUFLEN];

			ns->net_stat_ctime = o->eo_item.ei_uint64;
			_time = ns->net_stat_ctime;
			(void) strftime(timebuf, sizeof (timebuf),
			    "%m/%d/%Y,%T\n", localtime(&_time));
			dissect_time(timebuf, &ns->net_stat_time);
		} else if ((o->eo_catalog & EXD_DATA_MASK) ==
		    EXD_NET_STATS_IBYTES) {
			ns->net_stat_ibytes = o->eo_item.ei_uint64;
		} else if ((o->eo_catalog & EXD_DATA_MASK) ==
		    EXD_NET_STATS_OBYTES) {
			ns->net_stat_obytes = o->eo_item.ei_uint64;
		} else if ((o->eo_catalog & EXD_DATA_MASK) ==
		    EXD_NET_STATS_IPKTS) {
			ns->net_stat_ipackets = o->eo_item.ei_uint64;
		} else if ((o->eo_catalog & EXD_DATA_MASK) ==
		    EXD_NET_STATS_OPKTS) {
			ns->net_stat_opackets = o->eo_item.ei_uint64;
		} else if ((o->eo_catalog & EXD_DATA_MASK) ==
		    EXD_NET_STATS_IERRPKTS) {
			ns->net_stat_ierrors = o->eo_item.ei_uint64;
		} else if ((o->eo_catalog & EXD_DATA_MASK) ==
		    EXD_NET_STATS_OERRPKTS) {
			ns->net_stat_oerrors = o->eo_item.ei_uint64;
		}
		break;
	default:
		break;
	}
}

/* Get a description item from an object in the exacct file */
static void
add_desc_item(ea_object_t *o, net_desc_t *nd)
{
	switch (o->eo_catalog & EXT_TYPE_MASK) {
	case EXT_STRING:
		if ((o->eo_catalog & EXD_DATA_MASK) == EXD_NET_DESC_NAME) {
			(void) strncpy(nd->net_desc_name, o->eo_item.ei_string,
			    strlen(o->eo_item.ei_string));
		} else if ((o->eo_catalog & EXD_DATA_MASK) ==
		    EXD_NET_DESC_DEVNAME) {
			(void) strncpy(nd->net_desc_devname,
			    o->eo_item.ei_string, strlen(o->eo_item.ei_string));
		}
		break;
	case EXT_UINT8:
		if ((o->eo_catalog & EXD_DATA_MASK) == EXD_NET_DESC_PROTOCOL) {
			nd->net_desc_protocol = o->eo_item.ei_uint8;
		} else if ((o->eo_catalog & EXD_DATA_MASK) ==
		    EXD_NET_DESC_DSFIELD) {
			nd->net_desc_dsfield = o->eo_item.ei_uint8;
		}
		break;
	case EXT_UINT16:
		if ((o->eo_catalog & EXD_DATA_MASK) == EXD_NET_DESC_SPORT) {
			nd->net_desc_sport = o->eo_item.ei_uint16;
		} else if ((o->eo_catalog & EXD_DATA_MASK) ==
		    EXD_NET_DESC_DPORT) {
			nd->net_desc_dport = o->eo_item.ei_uint16;
		} else if ((o->eo_catalog & EXD_DATA_MASK) ==
		    EXD_NET_DESC_SAP) {
			nd->net_desc_sap = o->eo_item.ei_uint16;
		} else if ((o->eo_catalog & EXD_DATA_MASK) ==
		    EXD_NET_DESC_VLAN_TPID) {
			nd->net_desc_vlan_tpid = o->eo_item.ei_uint16;
		} else if ((o->eo_catalog & EXD_DATA_MASK) ==
		    EXD_NET_DESC_VLAN_TCI) {
			nd->net_desc_vlan_tci = o->eo_item.ei_uint16;
		} else if ((o->eo_catalog & EXD_DATA_MASK) ==
		    EXD_NET_DESC_PRIORITY) {
			nd->net_desc_priority = o->eo_item.ei_uint16;
		}
		break;
	case EXT_UINT32:
		if ((o->eo_catalog & EXD_DATA_MASK) == EXD_NET_DESC_V4SADDR ||
		    (o->eo_catalog & EXD_DATA_MASK) == EXD_NET_DESC_V4DADDR) {
				struct in_addr	addr;

				addr.s_addr = htonl(o->eo_item.ei_uint32);

				if ((o->eo_catalog & EXD_DATA_MASK) ==
				    EXD_NET_DESC_V4SADDR) {
					IN6_INADDR_TO_V4MAPPED(&addr,
					    &nd->net_desc_saddr);
				} else {
					IN6_INADDR_TO_V4MAPPED(&addr,
					    &nd->net_desc_daddr);
				}
		}
		break;
	case EXT_UINT64:
		if ((o->eo_catalog & EXD_DATA_MASK) == EXD_NET_DESC_BWLIMIT)
			nd->net_desc_bw_limit = o->eo_item.ei_uint64;
		break;
	case EXT_RAW:
		if ((o->eo_catalog & EXD_DATA_MASK) == EXD_NET_DESC_V6SADDR ||
		    (o->eo_catalog & EXD_DATA_MASK) == EXD_NET_DESC_V6DADDR) {
			in6_addr_t	addr;

			addr = *(in6_addr_t *)o->eo_item.ei_raw;
			if ((o->eo_catalog & EXD_DATA_MASK) ==
			    EXD_NET_DESC_V6SADDR) {
				nd->net_desc_saddr = addr;
			} else {
				nd->net_desc_daddr = addr;
			}
		} else if ((o->eo_catalog & EXD_DATA_MASK) ==
		    EXD_NET_DESC_EHOST) {
			bcopy((uchar_t *)o->eo_item.ei_raw, nd->net_desc_ehost,
			    ETHERADDRL);
		} else if ((o->eo_catalog & EXD_DATA_MASK) ==
		    EXD_NET_DESC_EDEST) {
			bcopy((uchar_t *)o->eo_item.ei_raw, nd->net_desc_edest,
			    ETHERADDRL);
		}
		break;
	default:
		break;
	}
}

/* Add a description item to the table */
static dladm_status_t
add_desc_to_tbl(net_table_t *net_table, net_desc_t *nd)
{
	net_entry_t	*ne;

	if ((ne = calloc(1, sizeof (net_entry_t))) == NULL)
		return (DLADM_STATUS_NOMEM);

	if ((ne->net_entry_tstats = calloc(1, sizeof (net_stat_t))) == NULL) {
		free(ne);
		return (DLADM_STATUS_NOMEM);
	}

	ne->net_entry_desc = nd;
	ne->net_entry_shead = NULL;
	ne->net_entry_stail = NULL;
	ne->net_entry_scount = 0;

	if (net_table->net_table_head == NULL) {
		net_table->net_table_head = ne;
		net_table->net_table_tail = ne;
	} else {
		net_table->net_table_tail->net_entry_next = ne;
		net_table->net_table_tail = ne;
	}
	net_table->net_entries++;
	return (DLADM_STATUS_OK);
}

/* Compare dates and return if t1 is equal, greater or lesser than t2 */
static int
compare_date(net_time_t *t1, net_time_t *t2)
{
	if (t1->net_time_yr == t2->net_time_yr &&
	    t1->net_time_mon == t2->net_time_mon &&
	    t1->net_time_day == t2->net_time_day) {
		return (NET_DATE_EQUAL);
	}
	if (t1->net_time_yr > t2->net_time_yr ||
	    (t1->net_time_yr == t2->net_time_yr &&
	    t1->net_time_mon > t2->net_time_mon) ||
	    (t1->net_time_yr == t2->net_time_yr &&
	    t1->net_time_mon == t2->net_time_mon &&
	    t1->net_time_day > t2->net_time_day)) {
		return (NET_DATE_GREATER);
	}
	return (NET_DATE_LESSER);
}

/* Compare times and return if t1 is equal, greater or lesser than t2 */
static int
compare_time(net_time_t *t1, net_time_t *t2)
{
	int	cd;

	cd = compare_date(t1, t2);

	if (cd == NET_DATE_GREATER) {
		return (NET_TIME_GREATER);
	} else if (cd == NET_DATE_LESSER) {
		return (NET_TIME_LESSER);
	} else {
		if (t1->net_time_hr == t2->net_time_hr &&
		    t1->net_time_min == t2->net_time_min &&
		    t1->net_time_sec == t2->net_time_sec) {
			return (NET_TIME_EQUAL);
		}
		if (t1->net_time_hr > t2->net_time_hr ||
		    (t1->net_time_hr == t2->net_time_hr &&
		    t1->net_time_min > t2->net_time_min) ||
		    (t1->net_time_hr == t2->net_time_hr &&
		    t1->net_time_min == t2->net_time_min &&
		    t1->net_time_sec > t2->net_time_sec)) {
			return (NET_TIME_GREATER);
		}
	}
	return (NET_TIME_LESSER);
}

/*
 * Given a start and end time and start and end entries check if the
 * times are within the range, and adjust, if needed.
 */
static dladm_status_t
chk_time_bound(net_time_t *s, net_time_t *e,  net_time_t *sns,
    net_time_t *ens)
{
	if (s != NULL && e != NULL) {
		if (compare_time(s, e) == NET_TIME_GREATER)
			return (DLADM_STATUS_BADTIMEVAL);
	}
	if (s != NULL) {
		if (compare_time(s, sns) == NET_TIME_LESSER) {
			s->net_time_yr = sns->net_time_yr;
			s->net_time_mon = sns->net_time_mon;
			s->net_time_day = sns->net_time_day;
			s->net_time_hr = sns->net_time_hr;
			s->net_time_min = sns->net_time_min;
			s->net_time_sec = sns->net_time_sec;
		}
	}
	if (e != NULL) {
		if (compare_time(e, ens) == NET_TIME_GREATER) {
			e->net_time_yr = ens->net_time_yr;
			e->net_time_mon = ens->net_time_mon;
			e->net_time_day = ens->net_time_day;
			e->net_time_hr = ens->net_time_hr;
			e->net_time_min = ens->net_time_min;
			e->net_time_sec = ens->net_time_sec;
		}
	}
	return (DLADM_STATUS_OK);
}

/*
 * Given a start and end time (strings), convert them into net_time_t
 * and also check for the range given the head and tail of the list.
 * If stime is lower then head or etime is greated than tail, adjust.
 */
static dladm_status_t
get_time_range(net_time_entry_t *head, net_time_entry_t *tail,
    net_time_t *st, net_time_t *et, char *stime, char *etime)
{
	bzero(st, sizeof (net_time_t));
	bzero(et, sizeof (net_time_t));

	if (stime == NULL && etime == NULL)
		return (0);

	if (stime != NULL)
		dissect_time(stime, st);
	if (etime != NULL)
		dissect_time(etime, et);

	if (stime != NULL || etime != NULL) {
		return (chk_time_bound(stime == NULL ? NULL : st,
		    etime == NULL ? NULL : et,
		    &head->my_time_stat->net_stat_time,
		    &tail->my_time_stat->net_stat_time));
	}
	return (0);
}

/*
 * Walk the list from a given starting point and return when we find
 * an entry that is greater or equal to st. lasttime will point to the
 * previous time entry.
 */
static void
get_starting_point(net_time_entry_t *head, net_time_entry_t **start,
    net_time_t *st, char *stime, uint64_t *lasttime)
{
	net_time_entry_t	*next = head;

	if (head == NULL) {
		*start = NULL;
		return;
	}
	if (stime == NULL) {
		*start = head;
		*lasttime = head->my_time_stat->net_stat_ctime;
		return;
	}
	*start = NULL;
	while (next != NULL) {
		if (compare_time(st,
		    &next->my_time_stat->net_stat_time) != NET_TIME_LESSER) {
			*lasttime = next->my_time_stat->net_stat_ctime;
			next = next->net_time_entry_next;
			continue;
		}
		*start = next;
		break;
	}
}

/*
 * Point entry (pe) functions
 */
/* Clear all the counters. Done after the contents are written to the file */
static void
clear_pe(net_plot_entry_t *pe, int entries, int *pentries)
{
	int	count;

	for (count = 0; count < entries; count++) {
		pe[count].net_pe_totbytes = 0;
		pe[count].net_pe_totibytes = 0;
		pe[count].net_pe_totobytes = 0;
		pe[count].net_pe_tottime = 0;
	}
	*pentries = 0;
}

/* Update an entry in the point entry table */
static void
update_pe(net_plot_entry_t *pe, net_stat_t *nns, int nentries,
    int *pentries, uint64_t lasttime)
{
	int	count;

	for (count = 0; count < nentries; count++) {
		if ((strlen(nns->net_stat_name) ==
		    strlen(pe[count].net_pe_name)) &&
		    (strncmp(pe[count].net_pe_name, nns->net_stat_name,
		    strlen(nns->net_stat_name)) == 0)) {
			break;
		}
	}
	if (count == nentries)
		return;

	if (pe[count].net_pe_totbytes == 0)
		pe[count].net_pe_lasttime = lasttime;

	pe[count].net_pe_totbytes += nns->net_stat_ibytes +
	    nns->net_stat_obytes;
	pe[count].net_pe_tottime += nns->net_stat_tdiff;
	pe[count].net_pe_totibytes += nns->net_stat_ibytes;
	pe[count].net_pe_totobytes += nns->net_stat_obytes;
	(*pentries)++;
}

/* Flush the contents of the point entry table to the file. */
static void
add_pe_to_file(int (*fn)(dladm_usage_t *, void *), net_plot_entry_t *pe,
    net_stat_t *ns, int entries, void *arg)
{
	int		count;
	dladm_usage_t	usage;
	uint64_t	tottime;

	bcopy(&ns->net_stat_ctime, &usage.du_etime, sizeof (usage.du_etime));
	for (count = 0; count < entries; count++) {
		bcopy(pe[count].net_pe_name, &usage.du_name,
		    sizeof (usage.du_name));
		bcopy(&pe[count].net_pe_lasttime, &usage.du_stime,
		    sizeof (usage.du_stime));
		usage.du_rbytes = pe[count].net_pe_totibytes;
		usage.du_obytes = pe[count].net_pe_totobytes;
		tottime = pe[count].net_pe_tottime;
		usage.du_bandwidth = (tottime > 0) ?
		    ((pe[count].net_pe_totbytes * 8) / tottime) : 0;
		usage.du_last = (count == entries-1);
		fn(&usage, arg);
	}
}

/*
 * Net entry functions
 */
static net_entry_t *
get_ne_from_table(net_table_t *net_table, char *name)
{
	int		count;
	net_desc_t	*nd;
	net_entry_t	*ne = net_table->net_table_head;

	for (count = 0; count < net_table->net_entries; count++) {
		nd = ne->net_entry_desc;
		if ((strlen(name) == strlen(nd->net_desc_name)) &&
		    (strncmp(name, nd->net_desc_name, strlen(name)) == 0)) {
			return (ne);
		}
		ne = ne->net_entry_next;
	}
	return (NULL);
}

/*  Get the entry for the descriptor, if it exists */
static net_desc_t *
get_ndesc(net_table_t *net_table, net_desc_t *nd)
{
	int		count;
	net_desc_t	*nd1;
	net_entry_t	*ne = net_table->net_table_head;

	for (count = 0; count < net_table->net_entries; count++) {
		nd1 = ne->net_entry_desc;
		if (strlen(nd1->net_desc_name) == strlen(nd->net_desc_name) &&
		    strlen(nd1->net_desc_devname) ==
		    strlen(nd->net_desc_devname) &&
		    strncmp(nd1->net_desc_name, nd->net_desc_name,
		    strlen(nd1->net_desc_name)) == 0 &&
		    strncmp(nd1->net_desc_devname, nd->net_desc_devname,
		    strlen(nd1->net_desc_devname)) == 0 &&
		    bcmp(nd1->net_desc_ehost, nd->net_desc_ehost,
		    ETHERADDRL) == 0 &&
		    bcmp(nd1->net_desc_edest, nd->net_desc_edest,
		    ETHERADDRL) == 0 &&
		    nd1->net_desc_vlan_tpid == nd->net_desc_vlan_tpid &&
		    nd1->net_desc_vlan_tci == nd->net_desc_vlan_tci &&
		    nd1->net_desc_sap == nd->net_desc_sap &&
		    nd1->net_desc_cpuid == nd->net_desc_cpuid &&
		    nd1->net_desc_priority == nd->net_desc_priority &&
		    nd1->net_desc_bw_limit == nd->net_desc_bw_limit &&
		    nd1->net_desc_sport == nd->net_desc_sport &&
		    nd1->net_desc_dport == nd->net_desc_dport &&
		    nd1->net_desc_protocol == nd->net_desc_protocol &&
		    nd1->net_desc_dsfield == nd->net_desc_dsfield &&
		    IN6_ARE_ADDR_EQUAL(&nd1->net_desc_saddr,
		    &nd->net_desc_saddr) &&
		    IN6_ARE_ADDR_EQUAL(&nd1->net_desc_daddr,
		    &nd->net_desc_daddr)) {
			return (nd1);
		}
		ne = ne->net_entry_next;
	}
	return (NULL);
}

/*
 * Update the stat entries. The stats in the file are cumulative, so in order
 * to have increments, we maintain a reference stat entry, which contains
 * the stats when the record was first written and a total stat entry, which
 * maintains the running count. When we want to add a stat entry, if it
 * the reference stat entry, we don't come here. For subsequent entries,
 * we get the increment by subtracting the current value from the reference
 * stat and the total stat.
 */
static void
update_stats(net_stat_t *ns1, net_entry_t *ne, net_stat_t *ref)
{

	/* get the increment */
	ns1->net_stat_ibytes -= (ref->net_stat_ibytes + ref->net_stat_tibytes);
	ns1->net_stat_obytes -= (ref->net_stat_obytes + ref->net_stat_tobytes);
	ns1->net_stat_ipackets -= (ref->net_stat_ipackets +
	    ref->net_stat_tipackets);
	ns1->net_stat_opackets -= (ref->net_stat_opackets +
	    ref->net_stat_topackets);
	ns1->net_stat_ierrors -= (ref->net_stat_ierrors +
	    ref->net_stat_tierrors);
	ns1->net_stat_oerrors -= (ref->net_stat_oerrors +
	    ref->net_stat_toerrors);

	/* update total bytes */
	ref->net_stat_tibytes += ns1->net_stat_ibytes;
	ref->net_stat_tobytes += ns1->net_stat_obytes;
	ref->net_stat_tipackets += ns1->net_stat_ipackets;
	ref->net_stat_topackets += ns1->net_stat_opackets;
	ref->net_stat_tierrors += ns1->net_stat_ierrors;
	ref->net_stat_toerrors  += ns1->net_stat_oerrors;

	ne->net_entry_tstats->net_stat_ibytes += ns1->net_stat_ibytes;
	ne->net_entry_tstats->net_stat_obytes += ns1->net_stat_obytes;
	ne->net_entry_tstats->net_stat_ipackets += ns1->net_stat_ipackets;
	ne->net_entry_tstats->net_stat_opackets += ns1->net_stat_opackets;
	ne->net_entry_tstats->net_stat_ierrors += ns1->net_stat_ierrors;
	ne->net_entry_tstats->net_stat_oerrors += ns1->net_stat_oerrors;
}

/* Add the stat entry into the table */
static dladm_status_t
add_stat_to_tbl(net_table_t *net_table, net_stat_t *ns)
{
	net_entry_t	*ne;

	ne = get_ne_from_table(net_table, ns->net_stat_name);
	if (ne == NULL)
		return (DLADM_STATUS_NOMEM);

	/* Ptr to flow desc */
	ns->net_stat_desc = ne->net_entry_desc;
	if (ns->net_stat_desc->net_desc_newrec) {
		ns->net_stat_desc->net_desc_newrec = B_FALSE;
		ns->net_stat_isref = B_TRUE;
		ne->net_entry_sref = ns;
	} else if (ns->net_stat_ibytes < ne->net_entry_sref->net_stat_tibytes ||
	    (ns->net_stat_obytes < ne->net_entry_sref->net_stat_tobytes)) {
		ns->net_stat_isref = B_TRUE;
		ne->net_entry_sref = ns;
	} else {
		ns->net_stat_isref = B_FALSE;
		update_stats(ns, ne, ne->net_entry_sref);
	}
	if (ne->net_entry_shead == NULL) {
		ne->net_entry_shead = ns;
		ne->net_entry_stail = ns;
	} else {
		if (!ns->net_stat_isref) {
			ne->net_entry_ttime += (ns->net_stat_ctime -
			    ne->net_entry_stail->net_stat_ctime);
			ns->net_stat_tdiff = ns->net_stat_ctime -
			    ne->net_entry_stail->net_stat_ctime;
		}
		ne->net_entry_stail->net_stat_next = ns;
		ne->net_entry_stail = ns;
	}

	ne->net_entry_scount++;
	return (DLADM_STATUS_OK);
}

/* Add a flow/link descriptor record to the table */
static dladm_status_t
add_desc(net_table_t *net_table, ea_file_t *ef, int nobjs)
{
	net_desc_t	*nd;
	net_desc_t	*dnd;
	int		count;
	ea_object_t	scratch;

	if ((nd = calloc(1, sizeof (net_desc_t))) == NULL)
		return (DLADM_STATUS_NOMEM);
	nd->net_desc_newrec = B_TRUE;

	for (count = 0; count < nobjs; count++) {
		if (ea_get_object(ef, &scratch) == -1) {
			free(nd);
			return (DLADM_STATUS_NOMEM);
		}
		add_desc_item(&scratch, nd);
	}
	if ((dnd = get_ndesc(net_table, nd)) != NULL) {
		dnd->net_desc_newrec = B_TRUE;
		free(nd);
		return (DLADM_STATUS_OK);
	}
	if (add_desc_to_tbl(net_table, nd) != 0) {
		free(nd);
		return (DLADM_STATUS_NOMEM);
	}
	return (DLADM_STATUS_OK);
}

/* Make an entry into the time sorted list */
static void
addto_time_list(net_table_t *net_table, net_time_entry_t *nt,
    net_time_entry_t *ntc)
{
	net_stat_t		*ns = nt->my_time_stat;
	net_stat_t		*ns1;
	net_time_entry_t	*end;
	net_time_t		*t1;
	int			count;

	t1 = &ns->net_stat_time;

	net_table->net_time_entries++;

	if (net_table->net_time_head == NULL) {
		net_table->net_time_head = nt;
		net_table->net_time_tail = nt;
	} else {
		net_table->net_time_tail->net_time_entry_next = nt;
		nt->net_time_entry_prev = net_table->net_time_tail;
		net_table->net_time_tail = nt;
	}

	if (net_table->net_ctime_head == NULL) {
		net_table->net_ctime_head = ntc;
		net_table->net_ctime_tail = ntc;
	} else {
		end = net_table->net_ctime_tail;
		count = 0;
		while (count < net_table->net_time_entries - 1) {
			ns1 = end->my_time_stat;
			/* Just add it to the tail */
			if (compare_date(t1, &ns1->net_stat_time) ==
			    NET_DATE_GREATER) {
				break;
			}
			if ((strlen(ns1->net_stat_name) ==
			    strlen(ns->net_stat_name)) &&
			    (strncmp(ns1->net_stat_name, ns->net_stat_name,
			    strlen(ns1->net_stat_name)) == 0)) {
				ntc->net_time_entry_next =
				    end->net_time_entry_next;
				if (end->net_time_entry_next != NULL) {
					end->net_time_entry_next->
					    net_time_entry_prev = ntc;
				} else {
					net_table->net_ctime_tail = ntc;
				}
				end->net_time_entry_next = ntc;
				ntc->net_time_entry_prev = end;
				return;
			}
			count++;
			end = end->net_time_entry_prev;
		}
		net_table->net_ctime_tail->net_time_entry_next = ntc;
		ntc->net_time_entry_prev = net_table->net_ctime_tail;
		net_table->net_ctime_tail = ntc;
	}
}

/* Add stat entry into the lists */
static dladm_status_t
add_stats(net_table_t *net_table, ea_file_t *ef, int nobjs)
{
	net_stat_t		*ns;
	int			count;
	ea_object_t		scratch;
	net_time_entry_t	*nt;
	net_time_entry_t	*ntc;

	if ((ns = calloc(1, sizeof (net_stat_t))) == NULL)
		return (DLADM_STATUS_NOMEM);

	if ((nt = calloc(1, sizeof (net_time_entry_t))) == NULL) {
		free(ns);
		return (DLADM_STATUS_NOMEM);
	}
	if ((ntc = calloc(1, sizeof (net_time_entry_t))) == NULL) {
		free(ns);
		free(nt);
		return (DLADM_STATUS_NOMEM);
	}

	nt->my_time_stat = ns;
	ntc->my_time_stat = ns;

	for (count = 0; count < nobjs; count++) {
		if (ea_get_object(ef, &scratch) == -1) {
			free(ns);
			free(nt);
			free(ntc);
			return (DLADM_STATUS_NOMEM);
		}
		add_stat_item(&scratch, ns);
	}
	if (add_stat_to_tbl(net_table, ns) != 0) {
		free(ns);
		free(nt);
		free(ntc);
		return (DLADM_STATUS_NOMEM);
	}
	addto_time_list(net_table, nt, ntc);
	return (DLADM_STATUS_OK);
}

/* Free the entire table */
static void
free_logtable(net_table_t *net_table)
{
	net_entry_t		*head;
	net_entry_t		*next;
	net_stat_t		*ns;
	net_stat_t		*ns1;
	net_time_entry_t	*thead;
	net_time_entry_t	*tnext;

	thead = net_table->net_time_head;
	while (thead != NULL) {
		thead->my_time_stat = NULL;
		tnext = thead->net_time_entry_next;
		thead->net_time_entry_next = NULL;
		thead->net_time_entry_prev = NULL;
		free(thead);
		thead = tnext;
	}
	net_table->net_time_head = NULL;
	net_table->net_time_tail = NULL;

	thead = net_table->net_ctime_head;
	while (thead != NULL) {
		thead->my_time_stat = NULL;
		tnext = thead->net_time_entry_next;
		thead->net_time_entry_next = NULL;
		thead->net_time_entry_prev = NULL;
		free(thead);
		thead = tnext;
	}
	net_table->net_ctime_head = NULL;
	net_table->net_ctime_tail = NULL;

	net_table->net_time_entries = 0;

	head = net_table->net_table_head;
	while (head != NULL) {
		next = head->net_entry_next;
		head->net_entry_next = NULL;
		ns = head->net_entry_shead;
		while (ns != NULL) {
			ns1 = ns->net_stat_next;
			free(ns);
			ns = ns1;
		}
		head->net_entry_scount = 0;
		head->net_entry_sref = NULL;
		free(head->net_entry_desc);
		free(head->net_entry_tstats);
		free(head);
		head = next;
	}
	net_table->net_table_head = NULL;
	net_table->net_table_tail = NULL;
	net_table->net_time_entries = 0;
	free(net_table);
}

/* Parse the exacct file, and return the parsed table. */
static void *
parse_logfile(char *file, int logtype, dladm_status_t *status)
{
	ea_file_t	ef;
	ea_object_t	scratch;
	net_table_t	*net_table;

	*status = DLADM_STATUS_OK;
	if ((net_table = calloc(1, sizeof (net_table_t))) == NULL) {
		*status = DLADM_STATUS_NOMEM;
		return (NULL);
	}
	if (ea_open(&ef, file, NULL, 0, O_RDONLY, 0) == -1) {
		*status = DLADM_STATUS_BADARG;
		free(net_table);
		return (NULL);
	}
	bzero(&scratch, sizeof (ea_object_t));
	while (ea_get_object(&ef, &scratch) != -1) {
		if (scratch.eo_type != EO_GROUP) {
			(void) ea_free_item(&scratch, EUP_ALLOC);
			(void) bzero(&scratch, sizeof (ea_object_t));
			continue;
		}
		/* Read Link Desc/Stat records */
		if (logtype == DLADM_LOGTYPE_FLOW) {
			/* Flow Descriptor */
			if ((scratch.eo_catalog &
			    EXD_DATA_MASK) == EXD_GROUP_NET_FLOW_DESC) {
				(void) add_desc(net_table, &ef,
				    scratch.eo_group.eg_nobjs - 1);
			/* Flow Stats */
			} else if ((scratch.eo_catalog &
			    EXD_DATA_MASK) == EXD_GROUP_NET_FLOW_STATS) {
				(void) add_stats(net_table, &ef,
				    scratch.eo_group.eg_nobjs - 1);
			}
		} else if (logtype == DLADM_LOGTYPE_LINK) {
			/* Link Descriptor */
			if ((scratch.eo_catalog &
			    EXD_DATA_MASK) == EXD_GROUP_NET_LINK_DESC) {
				(void) add_desc(net_table, &ef,
				    scratch.eo_group.eg_nobjs - 1);
			/* Link Stats */
			} else if ((scratch.eo_catalog &
			    EXD_DATA_MASK) == EXD_GROUP_NET_LINK_STATS) {
				(void) add_stats(net_table, &ef,
				    scratch.eo_group.eg_nobjs - 1);
			}
		} else {
			if (((scratch.eo_catalog & EXD_DATA_MASK) ==
			    EXD_GROUP_NET_LINK_DESC) || ((scratch.eo_catalog &
			    EXD_DATA_MASK) == EXD_GROUP_NET_FLOW_DESC)) {
				(void) add_desc(net_table, &ef,
				    scratch.eo_group.eg_nobjs - 1);
			} else if (((scratch.eo_catalog & EXD_DATA_MASK) ==
			    EXD_GROUP_NET_LINK_STATS) || ((scratch.eo_catalog &
			    EXD_DATA_MASK) == EXD_GROUP_NET_FLOW_STATS)) {
				(void) add_stats(net_table, &ef,
				    scratch.eo_group.eg_nobjs - 1);
			}
		}
		(void) ea_free_item(&scratch, EUP_ALLOC);
		(void) bzero(&scratch, sizeof (ea_object_t));
	}

	(void) ea_close(&ef);
	return ((void *)net_table);
}

/*
 * Walk the ctime list.  This is used when looking for usage records
 * based on a "resource" name.
 */
dladm_status_t
dladm_walk_usage_res(int (*fn)(dladm_usage_t *, void *), int logtype,
    char *logfile, char *resource, char *stime, char *etime, void *arg)
{
	net_table_t		*net_table;
	net_time_t		st, et;
	net_time_entry_t	*start;
	net_stat_t		*ns = NULL;
	net_stat_t		*nns;
	uint64_t		tot_time = 0;
	uint64_t		last_time;
	uint64_t		tot_bytes = 0;
	uint64_t		tot_ibytes = 0;
	uint64_t		tot_obytes = 0;
	boolean_t		gotstart = B_FALSE;
	dladm_status_t		status;
	dladm_usage_t		usage;
	int			step = 1;

	/* Parse the log file */
	net_table = parse_logfile(logfile, logtype, &status);
	if (net_table == NULL)
		return (status);

	if (net_table->net_entries == 0)
		return (DLADM_STATUS_OK);
	start = net_table->net_ctime_head;

	/* Time range */
	status = get_time_range(net_table->net_ctime_head,
	    net_table->net_ctime_tail, &st, &et, stime, etime);
	if (status != DLADM_STATUS_OK)
		return (status);

	while (start != NULL) {
		nns = start->my_time_stat;

		/* Get to the resource we are interested in */
		if ((strlen(resource) != strlen(nns->net_stat_name)) ||
		    (strncmp(resource, nns->net_stat_name,
		    strlen(nns->net_stat_name)) != 0)) {
			start = start->net_time_entry_next;
			continue;
		}

		/* Find the first record */
		if (!gotstart) {
			get_starting_point(start, &start, &st, stime,
			    &last_time);
			if (start == NULL)
				break;
			nns = start->my_time_stat;
			gotstart = B_TRUE;
		}

		/* Write one entry and return if we are out of the range */
		if (etime != NULL && compare_time(&nns->net_stat_time, &et)
		    == NET_TIME_GREATER) {
			if (tot_bytes != 0) {
				bcopy(ns->net_stat_name, &usage.du_name,
				    sizeof (usage.du_name));
				bcopy(&last_time, &usage.du_stime,
				    sizeof (usage.du_stime));
				bcopy(&ns->net_stat_ctime, &usage.du_etime,
				    sizeof (usage.du_etime));
				usage.du_rbytes = tot_ibytes;
				usage.du_obytes = tot_obytes;
				usage.du_bandwidth = tot_bytes*8/tot_time;
				usage.du_last = B_TRUE;
				fn(&usage, arg);
			}
			return (DLADM_STATUS_OK);
		}

		/*
		 * If this is a reference entry, just print what we have
		 * and proceed.
		 */
		if (nns->net_stat_isref) {
			if (tot_bytes != 0) {
				bcopy(&nns->net_stat_name, &usage.du_name,
				    sizeof (usage.du_name));
				bcopy(&nns->net_stat_ctime, &usage.du_stime,
				    sizeof (usage.du_stime));
				usage.du_rbytes = tot_ibytes;
				usage.du_obytes = tot_obytes;
				usage.du_bandwidth = tot_bytes*8/tot_time;
				usage.du_last = B_TRUE;
				fn(&usage, arg);
				NET_RESET_TOT(tot_bytes, tot_time, tot_ibytes,
				    tot_obytes, step);
			}
			last_time = nns->net_stat_ctime;
			start = start->net_time_entry_next;
			continue;
		}

		ns = nns;
		if (--step == 0) {
			tot_bytes += ns->net_stat_ibytes + ns->net_stat_obytes;
			tot_ibytes += ns->net_stat_ibytes;
			tot_obytes += ns->net_stat_obytes;
			tot_time += ns->net_stat_tdiff;
			bcopy(&ns->net_stat_name, &usage.du_name,
			    sizeof (usage.du_name));
			bcopy(&last_time, &usage.du_stime,
			    sizeof (usage.du_stime));
			bcopy(&ns->net_stat_ctime, &usage.du_etime,
			    sizeof (usage.du_etime));
			usage.du_rbytes = tot_ibytes;
			usage.du_obytes = tot_obytes;
			usage.du_bandwidth = tot_bytes*8/tot_time;
			usage.du_last = B_TRUE;
			fn(&usage, arg);

			NET_RESET_TOT(tot_bytes, tot_time, tot_ibytes,
			    tot_obytes, step);
			last_time = ns->net_stat_ctime;
		} else {
			tot_bytes += ns->net_stat_ibytes + ns->net_stat_obytes;
			tot_ibytes += ns->net_stat_ibytes;
			tot_obytes += ns->net_stat_obytes;
			tot_time += ns->net_stat_tdiff;
		}
		start = start->net_time_entry_next;
	}

	if (tot_bytes != 0) {
		bcopy(&ns->net_stat_name, &usage.du_name,
		    sizeof (usage.du_name));
		bcopy(&last_time, &usage.du_stime,
		    sizeof (usage.du_stime));
		bcopy(&ns->net_stat_ctime, &usage.du_etime,
		    sizeof (usage.du_etime));
		usage.du_rbytes = tot_ibytes;
		usage.du_obytes = tot_obytes;
		usage.du_bandwidth = tot_bytes*8/tot_time;
		usage.du_last = B_TRUE;
		fn(&usage, arg);
	}

	free_logtable(net_table);
	return (status);
}

/*
 * Walk the time sorted list if a resource is not specified.
 */
dladm_status_t
dladm_walk_usage_time(int (*fn)(dladm_usage_t *, void *), int logtype,
    char *logfile, char *stime, char *etime, void *arg)
{
	net_table_t		*net_table;
	net_time_entry_t	*start;
	net_stat_t		*ns = NULL, *nns;
	net_time_t		st, et, *t1;
	net_desc_t		*nd;
	net_entry_t		*ne;
	net_plot_entry_t	*pe;
	int			count;
	int			step = 1;
	int			nentries = 0, pentries = 0;
	uint64_t		last_time;
	dladm_status_t		status;

	/* Parse the log file */
	net_table = parse_logfile(logfile, logtype, &status);
	if (net_table == NULL)
		return (status);

	if (net_table->net_entries == 0)
		return (DLADM_STATUS_OK);
	start = net_table->net_time_head;

	/* Find the first and last records and starting point */
	status = get_time_range(net_table->net_time_head,
	    net_table->net_time_tail, &st, &et, stime, etime);
	if (status != DLADM_STATUS_OK)
		return (status);
	get_starting_point(start, &start, &st, stime, &last_time);
	/*
	 * Could assert to be non-null, since get_time_range()
	 * would have adjusted.
	 */
	if (start == NULL)
		return (DLADM_STATUS_BADTIMEVAL);

	/*
	 * Collect entries for all resources in a time slot before
	 * writing to the file.
	 */
	nentries = net_table->net_entries;

	pe = malloc(sizeof (net_plot_entry_t) * net_table->net_entries + 1);
	if (pe == NULL)
		return (DLADM_STATUS_NOMEM);

	ne = net_table->net_table_head;
	for (count = 0; count < nentries; count++) {
		nd = ne->net_entry_desc;
		pe[count].net_pe_name = nd->net_desc_name;
		ne = ne->net_entry_next;
	}

	clear_pe(pe, nentries, &pentries);

	/* Write header to file */
	/* add_pe_to_file(fn, pe, ns, nentries, arg); */

	t1 = &start->my_time_stat->net_stat_time;

	while (start != NULL) {

		nns = start->my_time_stat;
		/*
		 * We have crossed the time boundary, check if we need to
		 * print out now.
		 */
		if (compare_time(&nns->net_stat_time, t1) ==
		    NET_TIME_GREATER) {
			/* return if we are out of the range */
			if (etime != NULL &&
			    compare_time(&nns->net_stat_time, &et) ==
			    NET_TIME_GREATER) {
				if (pentries > 0) {
					add_pe_to_file(fn, pe, ns, nentries,
					    arg);
					clear_pe(pe, nentries, &pentries);
				}
				free(pe);
				return (DLADM_STATUS_OK);
			}
			/* update the stats from the ns. */
			t1 = &nns->net_stat_time;
			last_time = ns->net_stat_ctime;
			if (--step == 0) {
				if (pentries > 0) {
					add_pe_to_file(fn, pe, ns, nentries,
					    arg);
					clear_pe(pe, nentries, &pentries);
				}
				step = 1;
			}
		}

		/*
		 * if this is a reference entry, just print what we have
		 * for this resource and proceed. We will end up writing
		 * the stats for all the entries when we hit a ref element,
		 * which means 'steps' for some might not be accurate, but
		 * that is fine, the alternative is to write only the
		 * resource for which we hit a reference entry.
		 */
		if (nns->net_stat_isref) {
			if (pentries > 0) {
				add_pe_to_file(fn, pe, ns, nentries, arg);
				clear_pe(pe, nentries, &pentries);
			}
			step = 1;
		} else {
			update_pe(pe, nns, nentries, &pentries, last_time);
		}
		ns = nns;
		start = start->net_time_entry_next;
	}

	if (pentries > 0)
		add_pe_to_file(fn, pe, ns, nentries, arg);

	free(pe);
	free_logtable(net_table);

	return (DLADM_STATUS_OK);
}

dladm_status_t
dladm_usage_summary(int (*fn)(dladm_usage_t *, void *), int logtype,
    char *logfile, void *arg)
{
	net_table_t		*net_table;
	net_entry_t		*ne;
	net_desc_t		*nd;
	net_stat_t		*ns;
	int			count;
	dladm_usage_t		usage;
	dladm_status_t		status;

	/* Parse the log file */
	net_table = parse_logfile(logfile, logtype, &status);
	if (net_table == NULL)
		return (status);

	if (net_table->net_entries == 0)
		return (DLADM_STATUS_OK);

	ne = net_table->net_table_head;
	for (count = 0; count < net_table->net_entries; count++) {
		ns = ne->net_entry_tstats;
		nd = ne->net_entry_desc;

		if (ns->net_stat_ibytes + ns->net_stat_obytes == 0)
			continue;
		bcopy(&nd->net_desc_name, &usage.du_name,
		    sizeof (usage.du_name));
		usage.du_duration = ne->net_entry_ttime;
		usage.du_ipackets = ns->net_stat_ipackets;
		usage.du_rbytes = ns->net_stat_ibytes;
		usage.du_opackets = ns->net_stat_opackets;
		usage.du_obytes = ns->net_stat_obytes;
		usage.du_bandwidth =
		    (ns->net_stat_ibytes + ns->net_stat_obytes) * 8 /
		    usage.du_duration;
		usage.du_last = (count == net_table->net_entries-1);
		fn(&usage, arg);

		ne = ne->net_entry_next;
	}

	free_logtable(net_table);
	return (DLADM_STATUS_OK);
}

/*
 * Walk the ctime list and display the dates of the records.
 */
dladm_status_t
dladm_usage_dates(int (*fn)(dladm_usage_t *, void *), int logtype,
    char *logfile, char *resource, void *arg)
{
	net_table_t		*net_table;
	net_time_entry_t	*start;
	net_stat_t		*nns;
	net_time_t		st;
	net_time_t		*lasttime = NULL;
	uint64_t		last_time;
	boolean_t		gotstart = B_FALSE;
	dladm_status_t		status;
	dladm_usage_t		usage;

	/* Parse the log file */
	net_table = parse_logfile(logfile, logtype, &status);
	if (net_table == NULL)
		return (status);

	if (net_table->net_entries == 0)
		return (DLADM_STATUS_OK);

	start = net_table->net_ctime_head;

	while (start != NULL) {
		nns = start->my_time_stat;

		/* get to the resource we are interested in */
		if (resource != NULL) {
			if ((strlen(resource) != strlen(nns->net_stat_name)) ||
			    (strncmp(resource, nns->net_stat_name,
			    strlen(nns->net_stat_name)) != 0)) {
				start = start->net_time_entry_next;
				continue;
			}
		}

		/* get the starting point in the logfile */
		if (!gotstart) {
			get_starting_point(start, &start, &st, NULL,
			    &last_time);
			if (start == NULL)
				break;
			nns = start->my_time_stat;
			gotstart = B_TRUE;
		}

		if (lasttime == NULL ||
		    compare_date(&nns->net_stat_time, lasttime) ==
		    NET_DATE_GREATER) {
			bzero(&usage, sizeof (dladm_usage_t));
			bcopy(&nns->net_stat_ctime, &usage.du_stime,
			    sizeof (usage.du_stime));
			fn(&usage, arg);
			lasttime = &nns->net_stat_time;
		}

		start = start->net_time_entry_next;
		continue;
	}

	free_logtable(net_table);
	return (status);
}
