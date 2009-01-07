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
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <alloca.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <ipmp_admin.h>
#include <ipmp_query.h>
#include <libintl.h>
#include <libnvpair.h>
#include <libsysevent.h>
#include <locale.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/ipmp.h>
#include <sys/sysmacros.h>
#include <sys/termios.h>
#include <sys/types.h>

/*
 * ipmpstat -- display IPMP subsystem status.
 *
 * This utility makes extensive use of libipmp and IPMP sysevents to gather
 * and pretty-print the status of the IPMP subsystem.  All output formats
 * except for -p (probe) use libipmp to create a point-in-time snapshot of the
 * IPMP subsystem (unless the test-special -L flag is used), and then output
 * the contents of that snapshot in a user-specified manner.  Because the
 * output format and requested fields aren't known until run-time, three sets
 * of function pointers and two core data structures are used. Specifically:
 *
 *      * The ipmpstat_walker_t function pointers (walk_*) iterate through
 *	  all instances of a given IPMP object (group, interface, or address).
 *	  At most one ipmpstat_walker_t is used per ipmpstat invocation.
 *	  Since target information is included with the interface information,
 *	  both -i and -t use the interface walker (walk_if()).
 *
 *      * The ipmpstat_sfunc_t function pointers (sfunc_*) obtain a given
 *	  value for a given IPMP object.  Each ipmpstat_sunc_t is passed a
 *	  buffer to write its result into, the buffer's size, and an
 *	  ipmpstat_sfunc_arg_t state structure.  The state structure consists
 *	  of a pointer to the IPMP object to obtain information from
 *	  (sa_data), and an open libipmp handle (sa_ih) which can be used to
 *	  do additional libipmp queries, if necessary (e.g., because the
 *	  object does not have all of the needed information).
 *
 *	* The ipmpstat_field_t structure provides the list of supported fields
 *	  for a given output format, along with output formatting information
 *	  (e.g., field width), and a pointer to an ipmpstat_sfunc_t function
 *	  that can obtain the value for a IPMP given object.  For a given
 *	  ipmpstat output format, there's a corresponding array of
 *	  ipmpstat_field_t structures.  Thus, one ipmpstat_field_t array is
 *	  used per ipmpstat invocation.
 *
 *	* The ipmpstat_ofmt_t provides an ordered list of the requested
 *	  ipmpstat_field_t's (e.g., via -o) for a given ipmpstat invocation.
 *	  It is built at runtime from the command-line arguments.  This
 *	  structure (and a given IPMP object) is used by ofmt_output() to
 *	  output a single line of information about that IPMP object.
 *
 *	* The ipmpstat_cbfunc_t function pointers (*_cbfunc) are called back
 *	  by the walkers.  They are used both internally to implement nested
 *	  walks, and by the ipmpstat output logic to provide the glue between
 *	  the IPMP object walkers and the ofmt_output() logic.  Usually, a
 *	  single line is output for each IPMP object, and thus ofmt_output()
 *	  can be directly invoked (see info_output_cbfunc()).  However, if
 *	  multiple lines need to be output, then a more complex cbfunc is
 *	  needed (see targinfo_output_cbfunc()).  At most one cbfunc is used
 *	  per ipmpstat invocation.
 */

/*
 * Data type used by the sfunc callbacks to obtain the requested information
 * from the agreed-upon object.
 */
typedef struct ipmpstat_sfunc_arg {
	ipmp_handle_t		sa_ih;
	void			*sa_data;
} ipmpstat_sfunc_arg_t;

typedef void ipmpstat_sfunc_t(ipmpstat_sfunc_arg_t *, char *, uint_t);

/*
 * Data type that describes how to output a field; used by ofmt_output*().
 */
typedef struct ipmpstat_field {
	const char		*f_name;	/* field name */
	uint_t			f_width;	/* output width */
	ipmpstat_sfunc_t	*f_sfunc;	/* value->string function */
} ipmpstat_field_t;

/*
 * Data type that specifies the output field order; used by ofmt_output*()
 */
typedef struct ipmpstat_ofmt {
	const ipmpstat_field_t	*o_field;	/* current field info */
	struct ipmpstat_ofmt	*o_next;	/* next field */
} ipmpstat_ofmt_t;

/*
 * Function pointers used to iterate through IPMP objects.
 */
typedef void ipmpstat_cbfunc_t(ipmp_handle_t, void *, void *);
typedef void ipmpstat_walker_t(ipmp_handle_t, ipmpstat_cbfunc_t *, void *);

/*
 * Data type used to implement nested walks.
 */
typedef struct ipmpstat_walkdata {
	ipmpstat_cbfunc_t	*iw_func; 	/* caller-specified callback */
	void			*iw_funcarg; 	/* caller-specified arg */
} ipmpstat_walkdata_t;

/*
 * Data type used by enum2str() to map an enumerated value to a string.
 */
typedef struct ipmpstat_enum {
	const char		*e_name;	/* string */
	int			e_val;		/* value */
} ipmpstat_enum_t;

/*
 * Data type used to pass state between probe_output() and probe_event().
 */
typedef struct ipmpstat_probe_state {
	ipmp_handle_t	ps_ih;			/* open IPMP handle */
	ipmpstat_ofmt_t	*ps_ofmt; 		/* requested ofmt string */
} ipmpstat_probe_state_t;

/*
 * Options that modify the output mode; more than one may be lit.
 */
typedef enum {
	IPMPSTAT_OPT_NUMERIC	= 0x1,
	IPMPSTAT_OPT_PARSABLE 	= 0x2
} ipmpstat_opt_t;

/*
 * Indices for the FLAGS field of the `-i' output format.
 */
enum {
	IPMPSTAT_IFLAG_INDEX,	IPMPSTAT_SFLAG_INDEX,	IPMPSTAT_M4FLAG_INDEX,
	IPMPSTAT_BFLAG_INDEX,	IPMPSTAT_M6FLAG_INDEX,	IPMPSTAT_DFLAG_INDEX,
	IPMPSTAT_HFLAG_INDEX,	IPMPSTAT_NUM_FLAGS
};

#define	IPMPSTAT_NCOL	80
#define	NS2FLOATMS(ns)	((float)(ns) / (NANOSEC / MILLISEC))
#define	MS2FLOATSEC(ms)	((float)(ms) / 1000)

static const char	*progname;
static hrtime_t		probe_output_start;
static struct winsize	winsize;
static ipmpstat_opt_t	opt;
static ipmpstat_enum_t	addr_state[], group_state[], if_state[], if_link[];
static ipmpstat_enum_t	if_probe[], targ_mode[];
static ipmpstat_field_t addr_fields[], group_fields[], if_fields[];
static ipmpstat_field_t probe_fields[], targ_fields[];
static ipmpstat_cbfunc_t walk_addr_cbfunc, walk_if_cbfunc;
static ipmpstat_cbfunc_t info_output_cbfunc, targinfo_output_cbfunc;
static ipmpstat_walker_t walk_addr, walk_if, walk_group;

static int probe_event(sysevent_t *, void *);
static void probe_output(ipmp_handle_t, ipmpstat_ofmt_t *);
static ipmpstat_field_t *field_find(ipmpstat_field_t *, const char *);
static ipmpstat_ofmt_t *ofmt_create(const char *, ipmpstat_field_t []);
static void ofmt_output(const ipmpstat_ofmt_t *, ipmp_handle_t, void *);
static void ofmt_destroy(ipmpstat_ofmt_t *);
static void enum2str(const ipmpstat_enum_t *, int, char *, uint_t);
static void sockaddr2str(const struct sockaddr_storage *, char *, uint_t);
static void sighandler(int);
static void usage(void);
static void die(const char *, ...);
static void die_ipmperr(int, const char *, ...);
static void warn(const char *, ...);
static void warn_ipmperr(int, const char *, ...);

int
main(int argc, char **argv)
{
	int c;
	int err;
	const char *ofields = NULL;
	ipmp_handle_t ih;
	ipmp_qcontext_t qcontext = IPMP_QCONTEXT_SNAP;
	ipmpstat_ofmt_t *ofmt;
	ipmpstat_field_t *fields = NULL;
	ipmpstat_cbfunc_t *cbfunc;
	ipmpstat_walker_t *walker;

	if ((progname = strrchr(argv[0], '/')) == NULL)
		progname = argv[0];
	else
		progname++;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "nLPo:agipt")) != EOF) {
		if (fields != NULL && strchr("agipt", c) != NULL)
			die("only one output format may be specified\n");

		switch (c) {
		case 'n':
			opt |= IPMPSTAT_OPT_NUMERIC;
			break;
		case 'L':
			/* Undocumented option: for testing use ONLY */
			qcontext = IPMP_QCONTEXT_LIVE;
			break;
		case 'P':
			opt |= IPMPSTAT_OPT_PARSABLE;
			break;
		case 'o':
			ofields = optarg;
			break;
		case 'a':
			walker = walk_addr;
			cbfunc = info_output_cbfunc;
			fields = addr_fields;
			break;
		case 'g':
			walker = walk_group;
			cbfunc = info_output_cbfunc;
			fields = group_fields;
			break;
		case 'i':
			walker = walk_if;
			cbfunc = info_output_cbfunc;
			fields = if_fields;
			break;
		case 'p':
			fields = probe_fields;
			break;
		case 't':
			walker = walk_if;
			cbfunc = targinfo_output_cbfunc;
			fields = targ_fields;
			break;
		default:
			usage();
			break;
		}
	}

	if (argc > optind || fields == NULL)
		usage();

	if (opt & IPMPSTAT_OPT_PARSABLE) {
		if (ofields == NULL) {
			die("output field list (-o) required in parsable "
			    "output mode\n");
		} else if (strcasecmp(ofields, "all") == 0) {
			die("\"all\" not allowed in parsable output mode\n");
		}
	}

	/*
	 * Obtain the window size and monitor changes to the size.  This data
	 * is used to redisplay the output headers when necessary.
	 */
	(void) sigset(SIGWINCH, sighandler);
	sighandler(SIGWINCH);

	if ((err = ipmp_open(&ih)) != IPMP_SUCCESS)
		die_ipmperr(err, "cannot create IPMP handle");

	if (ipmp_ping_daemon(ih) != IPMP_SUCCESS)
		die("cannot contact in.mpathd(1M) -- is IPMP in use?\n");

	/*
	 * Create the ofmt linked list that will eventually be passed to
	 * to ofmt_output() to output the fields.
	 */
	ofmt = ofmt_create(ofields, fields);

	/*
	 * If we've been asked to display probes, then call the probe output
	 * function.  Otherwise, snapshot IPMP state (or use live state) and
	 * invoke the specified walker with the specified callback function.
	 */
	if (fields == probe_fields) {
		probe_output(ih, ofmt);
	} else {
		if ((err = ipmp_setqcontext(ih, qcontext)) != IPMP_SUCCESS) {
			if (qcontext == IPMP_QCONTEXT_SNAP)
				die_ipmperr(err, "cannot snapshot IPMP state");
			else
				die_ipmperr(err, "cannot use live IPMP state");
		}
		(*walker)(ih, cbfunc, ofmt);
	}

	ofmt_destroy(ofmt);
	ipmp_close(ih);

	return (EXIT_SUCCESS);
}

/*
 * Walks all IPMP groups on the system and invokes `cbfunc' on each, passing
 * it `ih', the ipmp_groupinfo_t pointer, and `arg'.
 */
static void
walk_group(ipmp_handle_t ih, ipmpstat_cbfunc_t *cbfunc, void *arg)
{
	int err;
	uint_t i;
	ipmp_groupinfo_t *grinfop;
	ipmp_grouplist_t *grlistp;

	if ((err = ipmp_getgrouplist(ih, &grlistp)) != IPMP_SUCCESS)
		die_ipmperr(err, "cannot get IPMP group list");

	for (i = 0; i < grlistp->gl_ngroup; i++) {
		err = ipmp_getgroupinfo(ih, grlistp->gl_groups[i], &grinfop);
		if (err != IPMP_SUCCESS) {
			warn_ipmperr(err, "cannot get info for group `%s'",
			    grlistp->gl_groups[i]);
			continue;
		}
		(*cbfunc)(ih, grinfop, arg);
		ipmp_freegroupinfo(grinfop);
	}

	ipmp_freegrouplist(grlistp);
}

/*
 * Walks all IPMP interfaces on the system and invokes `cbfunc' on each,
 * passing it `ih', the ipmp_ifinfo_t pointer, and `arg'.
 */
static void
walk_if(ipmp_handle_t ih, ipmpstat_cbfunc_t *cbfunc, void *arg)
{
	ipmpstat_walkdata_t iw = { cbfunc, arg };

	walk_group(ih, walk_if_cbfunc, &iw);
}

/*
 * Walks all IPMP data addresses on the system and invokes `cbfunc' on each.
 * passing it `ih', the ipmp_addrinfo_t pointer, and `arg'.
 */
static void
walk_addr(ipmp_handle_t ih, ipmpstat_cbfunc_t *cbfunc, void *arg)
{
	ipmpstat_walkdata_t iw = { cbfunc, arg };

	walk_group(ih, walk_addr_cbfunc, &iw);
}

/*
 * Nested walker callback function for walk_if().
 */
static void
walk_if_cbfunc(ipmp_handle_t ih, void *infop, void *arg)
{
	int err;
	uint_t i;
	ipmp_groupinfo_t *grinfop = infop;
	ipmp_ifinfo_t *ifinfop;
	ipmp_iflist_t *iflistp = grinfop->gr_iflistp;
	ipmpstat_walkdata_t *iwp = arg;

	for (i = 0; i < iflistp->il_nif; i++) {
		err = ipmp_getifinfo(ih, iflistp->il_ifs[i], &ifinfop);
		if (err != IPMP_SUCCESS) {
			warn_ipmperr(err, "cannot get info for interface `%s'",
			    iflistp->il_ifs[i]);
			continue;
		}
		(*iwp->iw_func)(ih, ifinfop, iwp->iw_funcarg);
		ipmp_freeifinfo(ifinfop);
	}
}

/*
 * Nested walker callback function for walk_addr().
 */
static void
walk_addr_cbfunc(ipmp_handle_t ih, void *infop, void *arg)
{
	int err;
	uint_t i;
	ipmp_groupinfo_t *grinfop = infop;
	ipmp_addrinfo_t *adinfop;
	ipmp_addrlist_t *adlistp = grinfop->gr_adlistp;
	ipmpstat_walkdata_t *iwp = arg;
	char addr[INET6_ADDRSTRLEN];
	struct sockaddr_storage *addrp;

	for (i = 0; i < adlistp->al_naddr; i++) {
		addrp = &adlistp->al_addrs[i];
		err = ipmp_getaddrinfo(ih, grinfop->gr_name, addrp, &adinfop);
		if (err != IPMP_SUCCESS) {
			sockaddr2str(addrp, addr, sizeof (addr));
			warn_ipmperr(err, "cannot get info for `%s'", addr);
			continue;
		}
		(*iwp->iw_func)(ih, adinfop, iwp->iw_funcarg);
		ipmp_freeaddrinfo(adinfop);
	}
}

static void
sfunc_nvwarn(const char *nvname, char *buf, uint_t bufsize)
{
	warn("cannot retrieve %s\n", nvname);
	(void) strlcpy(buf, "?", bufsize);
}

static void
sfunc_addr_address(ipmpstat_sfunc_arg_t *arg, char *buf, uint_t bufsize)
{
	ipmp_addrinfo_t *adinfop = arg->sa_data;

	sockaddr2str(&adinfop->ad_addr, buf, bufsize);
}

static void
sfunc_addr_group(ipmpstat_sfunc_arg_t *arg, char *buf, uint_t bufsize)
{
	int err;
	ipmp_addrinfo_t *adinfop = arg->sa_data;
	ipmp_groupinfo_t *grinfop;

	err = ipmp_getgroupinfo(arg->sa_ih, adinfop->ad_group, &grinfop);
	if (err != IPMP_SUCCESS) {
		warn_ipmperr(err, "cannot get info for group `%s'",
		    adinfop->ad_group);
		(void) strlcpy(buf, "?", bufsize);
		return;
	}
	(void) strlcpy(buf, grinfop->gr_ifname, bufsize);
	ipmp_freegroupinfo(grinfop);
}

static void
sfunc_addr_state(ipmpstat_sfunc_arg_t *arg, char *buf, uint_t bufsize)
{
	ipmp_addrinfo_t *adinfop = arg->sa_data;

	enum2str(addr_state, adinfop->ad_state, buf, bufsize);
}

static void
sfunc_addr_inbound(ipmpstat_sfunc_arg_t *arg, char *buf, uint_t bufsize)
{
	ipmp_addrinfo_t *adinfop = arg->sa_data;

	(void) strlcpy(buf, adinfop->ad_binding, bufsize);
}

static void
sfunc_addr_outbound(ipmpstat_sfunc_arg_t *arg, char *buf, uint_t bufsize)
{
	int err;
	uint_t i, nactive = 0;
	ipmp_ifinfo_t *ifinfop;
	ipmp_iflist_t *iflistp;
	ipmp_addrinfo_t *adinfop = arg->sa_data;
	ipmp_groupinfo_t *grinfop;

	if (adinfop->ad_state == IPMP_ADDR_DOWN)
		return;

	/*
	 * If there's no inbound interface for this address, there can't
	 * be any outbound traffic.
	 */
	if (adinfop->ad_binding[0] == '\0')
		return;

	/*
	 * The address can use any active interface in the group, so
	 * obtain all of those.
	 */
	err = ipmp_getgroupinfo(arg->sa_ih, adinfop->ad_group, &grinfop);
	if (err != IPMP_SUCCESS) {
		warn_ipmperr(err, "cannot get info for group `%s'",
		    adinfop->ad_group);
		(void) strlcpy(buf, "?", bufsize);
		return;
	}

	iflistp = grinfop->gr_iflistp;
	for (i = 0; i < iflistp->il_nif; i++) {
		err = ipmp_getifinfo(arg->sa_ih, iflistp->il_ifs[i], &ifinfop);
		if (err != IPMP_SUCCESS) {
			warn_ipmperr(err, "cannot get info for interface `%s'",
			    iflistp->il_ifs[i]);
			continue;
		}

		if (ifinfop->if_flags & IPMP_IFFLAG_ACTIVE) {
			if (nactive++ != 0)
				(void) strlcat(buf, " ", bufsize);
			(void) strlcat(buf, ifinfop->if_name, bufsize);
		}
		ipmp_freeifinfo(ifinfop);
	}
	ipmp_freegroupinfo(grinfop);
}

static void
sfunc_group_name(ipmpstat_sfunc_arg_t *arg, char *buf, uint_t bufsize)
{
	ipmp_groupinfo_t *grinfop = arg->sa_data;

	(void) strlcpy(buf, grinfop->gr_name, bufsize);
}

static void
sfunc_group_ifname(ipmpstat_sfunc_arg_t *arg, char *buf, uint_t bufsize)
{
	ipmp_groupinfo_t *grinfop = arg->sa_data;

	(void) strlcpy(buf, grinfop->gr_ifname, bufsize);
}

static void
sfunc_group_state(ipmpstat_sfunc_arg_t *arg, char *buf, uint_t bufsize)
{
	ipmp_groupinfo_t *grinfop = arg->sa_data;

	enum2str(group_state, grinfop->gr_state, buf, bufsize);
}

static void
sfunc_group_fdt(ipmpstat_sfunc_arg_t *arg, char *buf, uint_t bufsize)
{
	ipmp_groupinfo_t *grinfop = arg->sa_data;

	if (grinfop->gr_fdt == 0)
		return;

	(void) snprintf(buf, bufsize, "%.2fs", MS2FLOATSEC(grinfop->gr_fdt));
}

static void
sfunc_group_interfaces(ipmpstat_sfunc_arg_t *arg, char *buf, uint_t bufsize)
{
	int err;
	uint_t i;
	char *active, *inactive, *unusable;
	uint_t nactive = 0, ninactive = 0, nunusable = 0;
	ipmp_groupinfo_t *grinfop = arg->sa_data;
	ipmp_iflist_t *iflistp = grinfop->gr_iflistp;
	ipmp_ifinfo_t *ifinfop;

	active = alloca(bufsize);
	active[0] = '\0';
	inactive = alloca(bufsize);
	inactive[0] = '\0';
	unusable = alloca(bufsize);
	unusable[0] = '\0';

	for (i = 0; i < iflistp->il_nif; i++) {
		err = ipmp_getifinfo(arg->sa_ih, iflistp->il_ifs[i], &ifinfop);
		if (err != IPMP_SUCCESS) {
			warn_ipmperr(err, "cannot get info for interface `%s'",
			    iflistp->il_ifs[i]);
			continue;
		}

		if (ifinfop->if_flags & IPMP_IFFLAG_ACTIVE) {
			if (nactive++ != 0)
				(void) strlcat(active, " ", bufsize);
			(void) strlcat(active, ifinfop->if_name, bufsize);
		} else if (ifinfop->if_flags & IPMP_IFFLAG_INACTIVE) {
			if (ninactive++ != 0)
				(void) strlcat(inactive, " ", bufsize);
			(void) strlcat(inactive, ifinfop->if_name, bufsize);
		} else {
			if (nunusable++ != 0)
				(void) strlcat(unusable, " ", bufsize);
			(void) strlcat(unusable, ifinfop->if_name, bufsize);
		}

		ipmp_freeifinfo(ifinfop);
	}

	(void) strlcpy(buf, active, bufsize);

	if (ninactive > 0) {
		if (nactive != 0)
			(void) strlcat(buf, " ", bufsize);

		(void) strlcat(buf, "(", bufsize);
		(void) strlcat(buf, inactive, bufsize);
		(void) strlcat(buf, ")", bufsize);
	}

	if (nunusable > 0) {
		if (nactive + ninactive != 0)
			(void) strlcat(buf, " ", bufsize);

		(void) strlcat(buf, "[", bufsize);
		(void) strlcat(buf, unusable, bufsize);
		(void) strlcat(buf, "]", bufsize);
	}
}

static void
sfunc_if_name(ipmpstat_sfunc_arg_t *arg, char *buf, uint_t bufsize)
{
	ipmp_ifinfo_t *ifinfop = arg->sa_data;

	(void) strlcpy(buf, ifinfop->if_name, bufsize);
}

static void
sfunc_if_active(ipmpstat_sfunc_arg_t *arg, char *buf, uint_t bufsize)
{
	ipmp_ifinfo_t *ifinfop = arg->sa_data;

	if (ifinfop->if_flags & IPMP_IFFLAG_ACTIVE)
		(void) strlcpy(buf, "yes", bufsize);
	else
		(void) strlcpy(buf, "no", bufsize);
}

static void
sfunc_if_group(ipmpstat_sfunc_arg_t *arg, char *buf, uint_t bufsize)
{
	int err;
	ipmp_ifinfo_t *ifinfop = arg->sa_data;
	ipmp_groupinfo_t *grinfop;

	err = ipmp_getgroupinfo(arg->sa_ih, ifinfop->if_group, &grinfop);
	if (err != IPMP_SUCCESS) {
		warn_ipmperr(err, "cannot get info for group `%s'",
		    ifinfop->if_group);
		(void) strlcpy(buf, "?", bufsize);
		return;
	}

	(void) strlcpy(buf, grinfop->gr_ifname, bufsize);
	ipmp_freegroupinfo(grinfop);
}

static void
sfunc_if_flags(ipmpstat_sfunc_arg_t *arg, char *buf, uint_t bufsize)
{
	int err;
	ipmp_ifinfo_t *ifinfop = arg->sa_data;
	ipmp_groupinfo_t *grinfop;

	assert(bufsize > IPMPSTAT_NUM_FLAGS);

	(void) memset(buf, '-', IPMPSTAT_NUM_FLAGS);
	buf[IPMPSTAT_NUM_FLAGS] = '\0';

	if (ifinfop->if_type == IPMP_IF_STANDBY)
		buf[IPMPSTAT_SFLAG_INDEX] = 's';

	if (ifinfop->if_flags & IPMP_IFFLAG_INACTIVE)
		buf[IPMPSTAT_IFLAG_INDEX] = 'i';

	if (ifinfop->if_flags & IPMP_IFFLAG_DOWN)
		buf[IPMPSTAT_DFLAG_INDEX] = 'd';

	if (ifinfop->if_flags & IPMP_IFFLAG_HWADDRDUP)
		buf[IPMPSTAT_HFLAG_INDEX] = 'h';

	err = ipmp_getgroupinfo(arg->sa_ih, ifinfop->if_group, &grinfop);
	if (err != IPMP_SUCCESS) {
		warn_ipmperr(err, "cannot get broadcast/multicast info for "
		    "group `%s'", ifinfop->if_group);
		return;
	}

	if (strcmp(grinfop->gr_m4ifname, ifinfop->if_name) == 0)
		buf[IPMPSTAT_M4FLAG_INDEX] = 'm';

	if (strcmp(grinfop->gr_m6ifname, ifinfop->if_name) == 0)
		buf[IPMPSTAT_M6FLAG_INDEX] = 'M';

	if (strcmp(grinfop->gr_bcifname, ifinfop->if_name) == 0)
		buf[IPMPSTAT_BFLAG_INDEX] = 'b';

	ipmp_freegroupinfo(grinfop);
}

static void
sfunc_if_link(ipmpstat_sfunc_arg_t *arg, char *buf, uint_t bufsize)
{
	ipmp_ifinfo_t *ifinfop = arg->sa_data;

	enum2str(if_link, ifinfop->if_linkstate, buf, bufsize);
}

static void
sfunc_if_probe(ipmpstat_sfunc_arg_t *arg, char *buf, uint_t bufsize)
{
	ipmp_ifinfo_t *ifinfop = arg->sa_data;

	enum2str(if_probe, ifinfop->if_probestate, buf, bufsize);
}

static void
sfunc_if_state(ipmpstat_sfunc_arg_t *arg, char *buf, uint_t bufsize)
{
	ipmp_ifinfo_t *ifinfop = arg->sa_data;

	enum2str(if_state, ifinfop->if_state, buf, bufsize);
}

static void
sfunc_probe_id(ipmpstat_sfunc_arg_t *arg, char *buf, uint_t bufsize)
{
	uint32_t probe_id;
	nvlist_t *nvl = arg->sa_data;

	if (nvlist_lookup_uint32(nvl, IPMP_PROBE_ID, &probe_id) != 0) {
		sfunc_nvwarn("IPMP_PROBE_ID", buf, bufsize);
		return;
	}

	(void) snprintf(buf, bufsize, "%u", probe_id);
}

static void
sfunc_probe_ifname(ipmpstat_sfunc_arg_t *arg, char *buf, uint_t bufsize)
{
	char *ifname;
	nvlist_t *nvl = arg->sa_data;

	if (nvlist_lookup_string(nvl, IPMP_IF_NAME, &ifname) != 0) {
		sfunc_nvwarn("IPMP_IF_NAME", buf, bufsize);
		return;
	}

	(void) strlcpy(buf, ifname, bufsize);
}

static void
sfunc_probe_time(ipmpstat_sfunc_arg_t *arg, char *buf, uint_t bufsize)
{
	hrtime_t start;
	nvlist_t *nvl = arg->sa_data;

	if (nvlist_lookup_hrtime(nvl, IPMP_PROBE_START_TIME, &start) != 0) {
		sfunc_nvwarn("IPMP_PROBE_START_TIME", buf, bufsize);
		return;
	}

	(void) snprintf(buf, bufsize, "%.2fs",
	    (float)(start - probe_output_start) / NANOSEC);
}

static void
sfunc_probe_target(ipmpstat_sfunc_arg_t *arg, char *buf, uint_t bufsize)
{
	uint_t nelem;
	struct sockaddr_storage *target;
	nvlist_t *nvl = arg->sa_data;

	if (nvlist_lookup_byte_array(nvl, IPMP_PROBE_TARGET,
	    (uchar_t **)&target, &nelem) != 0) {
		sfunc_nvwarn("IPMP_PROBE_TARGET", buf, bufsize);
		return;
	}

	sockaddr2str(target, buf, bufsize);
}

static void
sfunc_probe_rtt(ipmpstat_sfunc_arg_t *arg, char *buf, uint_t bufsize)
{
	hrtime_t start, ackproc;
	nvlist_t *nvl = arg->sa_data;
	uint32_t state;

	if (nvlist_lookup_uint32(nvl, IPMP_PROBE_STATE, &state) != 0) {
		sfunc_nvwarn("IPMP_PROBE_STATE", buf, bufsize);
		return;
	}

	if (state != IPMP_PROBE_ACKED)
		return;

	if (nvlist_lookup_hrtime(nvl, IPMP_PROBE_START_TIME, &start) != 0) {
		sfunc_nvwarn("IPMP_PROBE_START_TIME", buf, bufsize);
		return;
	}

	if (nvlist_lookup_hrtime(nvl, IPMP_PROBE_ACKPROC_TIME, &ackproc) != 0) {
		sfunc_nvwarn("IPMP_PROBE_ACKPROC_TIME", buf, bufsize);
		return;
	}

	(void) snprintf(buf, bufsize, "%.2fms", NS2FLOATMS(ackproc - start));
}

static void
sfunc_probe_netrtt(ipmpstat_sfunc_arg_t *arg, char *buf, uint_t bufsize)
{
	hrtime_t sent, ackrecv;
	nvlist_t *nvl = arg->sa_data;
	uint32_t state;

	if (nvlist_lookup_uint32(nvl, IPMP_PROBE_STATE, &state) != 0) {
		sfunc_nvwarn("IPMP_PROBE_STATE", buf, bufsize);
		return;
	}

	if (state != IPMP_PROBE_ACKED)
		return;

	if (nvlist_lookup_hrtime(nvl, IPMP_PROBE_SENT_TIME, &sent) != 0) {
		sfunc_nvwarn("IPMP_PROBE_SENT_TIME", buf, bufsize);
		return;
	}

	if (nvlist_lookup_hrtime(nvl, IPMP_PROBE_ACKRECV_TIME, &ackrecv) != 0) {
		sfunc_nvwarn("IPMP_PROBE_ACKRECV_TIME", buf, bufsize);
		return;
	}

	(void) snprintf(buf, bufsize, "%.2fms", NS2FLOATMS(ackrecv - sent));
}

static void
sfunc_probe_rttavg(ipmpstat_sfunc_arg_t *arg, char *buf, uint_t bufsize)
{
	int64_t rttavg;
	nvlist_t *nvl = arg->sa_data;

	if (nvlist_lookup_int64(nvl, IPMP_PROBE_TARGET_RTTAVG, &rttavg) != 0) {
		sfunc_nvwarn("IPMP_PROBE_TARGET_RTTAVG", buf, bufsize);
		return;
	}

	if (rttavg != 0)
		(void) snprintf(buf, bufsize, "%.2fms", NS2FLOATMS(rttavg));
}

static void
sfunc_probe_rttdev(ipmpstat_sfunc_arg_t *arg, char *buf, uint_t bufsize)
{
	int64_t rttdev;
	nvlist_t *nvl = arg->sa_data;

	if (nvlist_lookup_int64(nvl, IPMP_PROBE_TARGET_RTTDEV, &rttdev) != 0) {
		sfunc_nvwarn("IPMP_PROBE_TARGET_RTTDEV", buf, bufsize);
		return;
	}

	if (rttdev != 0)
		(void) snprintf(buf, bufsize, "%.2fms", NS2FLOATMS(rttdev));
}

/* ARGSUSED */
static void
probe_enabled_cbfunc(ipmp_handle_t ih, void *infop, void *arg)
{
	uint_t *nenabledp = arg;
	ipmp_ifinfo_t *ifinfop = infop;

	if (ifinfop->if_probestate != IPMP_PROBE_DISABLED)
		(*nenabledp)++;
}

static void
probe_output(ipmp_handle_t ih, ipmpstat_ofmt_t *ofmt)
{
	char sub[MAX_SUBID_LEN];
	evchan_t *evch;
	ipmpstat_probe_state_t ps = { ih, ofmt };
	uint_t nenabled = 0;

	/*
	 * Check if any interfaces are enabled for probe-based failure
	 * detection.  If not, immediately fail.
	 */
	walk_if(ih, probe_enabled_cbfunc, &nenabled);
	if (nenabled == 0)
		die("probe-based failure detection is disabled\n");

	probe_output_start = gethrtime();

	/*
	 * Unfortunately, until 4791900 is fixed, only privileged processes
	 * can bind and thus receive sysevents.
	 */
	errno = sysevent_evc_bind(IPMP_EVENT_CHAN, &evch, EVCH_CREAT);
	if (errno != 0) {
		if (errno == EPERM)
			die("insufficient privileges for -p\n");
		die("sysevent_evc_bind to channel %s failed", IPMP_EVENT_CHAN);
	}

	/*
	 * The subscriber must be unique in order for sysevent_evc_subscribe()
	 * to succeed, so combine our name and pid.
	 */
	(void) snprintf(sub, sizeof (sub), "%d-%s", getpid(), progname);

	errno = sysevent_evc_subscribe(evch, sub, EC_IPMP, probe_event, &ps, 0);
	if (errno != 0)
		die("sysevent_evc_subscribe for class %s failed", EC_IPMP);

	for (;;)
		(void) pause();
}

static int
probe_event(sysevent_t *ev, void *arg)
{
	nvlist_t *nvl;
	uint32_t state;
	uint32_t version;
	ipmpstat_probe_state_t *psp = arg;

	if (strcmp(sysevent_get_subclass_name(ev), ESC_IPMP_PROBE_STATE) != 0)
		return (0);

	if (sysevent_get_attr_list(ev, &nvl) != 0) {
		warn("sysevent_get_attr_list failed; dropping event");
		return (0);
	}

	if (nvlist_lookup_uint32(nvl, IPMP_EVENT_VERSION, &version) != 0) {
		warn("dropped event with no IPMP_EVENT_VERSION\n");
		goto out;
	}

	if (version != IPMP_EVENT_CUR_VERSION) {
		warn("dropped event with unsupported IPMP_EVENT_VERSION %d\n",
		    version);
		goto out;
	}

	if (nvlist_lookup_uint32(nvl, IPMP_PROBE_STATE, &state) != 0) {
		warn("dropped event with no IPMP_PROBE_STATE\n");
		goto out;
	}

	if (state == IPMP_PROBE_ACKED || state == IPMP_PROBE_LOST)
		ofmt_output(psp->ps_ofmt, psp->ps_ih, nvl);
out:
	nvlist_free(nvl);
	return (0);
}

static void
sfunc_targ_ifname(ipmpstat_sfunc_arg_t *arg, char *buf, uint_t bufsize)
{
	ipmp_targinfo_t *targinfop = arg->sa_data;

	(void) strlcpy(buf, targinfop->it_name, bufsize);
}

static void
sfunc_targ_mode(ipmpstat_sfunc_arg_t *arg, char *buf, uint_t bufsize)
{
	ipmp_targinfo_t *targinfop = arg->sa_data;

	enum2str(targ_mode, targinfop->it_targmode, buf, bufsize);
}

static void
sfunc_targ_testaddr(ipmpstat_sfunc_arg_t *arg, char *buf, uint_t bufsize)
{
	ipmp_targinfo_t *targinfop = arg->sa_data;

	if (targinfop->it_targmode != IPMP_TARG_DISABLED)
		sockaddr2str(&targinfop->it_testaddr, buf, bufsize);
}

static void
sfunc_targ_targets(ipmpstat_sfunc_arg_t *arg, char *buf, uint_t bufsize)
{
	uint_t i;
	char *targname = alloca(bufsize);
	ipmp_targinfo_t *targinfop = arg->sa_data;
	ipmp_addrlist_t *targlistp = targinfop->it_targlistp;

	for (i = 0; i < targlistp->al_naddr; i++) {
		sockaddr2str(&targlistp->al_addrs[i], targname, bufsize);
		(void) strlcat(buf, targname, bufsize);
		if ((i + 1) < targlistp->al_naddr)
			(void) strlcat(buf, " ", bufsize);
	}
}

static void
info_output_cbfunc(ipmp_handle_t ih, void *infop, void *arg)
{
	ofmt_output(arg, ih, infop);
}

static void
targinfo_output_cbfunc(ipmp_handle_t ih, void *infop, void *arg)
{
	ipmp_ifinfo_t *ifinfop = infop;
	ipmp_if_targmode_t targmode4 = ifinfop->if_targinfo4.it_targmode;
	ipmp_if_targmode_t targmode6 = ifinfop->if_targinfo6.it_targmode;

	/*
	 * Usually, either IPv4 or IPv6 probing will be enabled, but the admin
	 * may enable both.  If only one is enabled, omit the other one so as
	 * to not encourage the admin to enable both.  If neither is enabled,
	 * we still print one just so the admin can see a MODE of "disabled".
	 */
	if (targmode4 != IPMP_TARG_DISABLED || targmode6 == IPMP_TARG_DISABLED)
		ofmt_output(arg, ih, &ifinfop->if_targinfo4);
	if (targmode6 != IPMP_TARG_DISABLED)
		ofmt_output(arg, ih, &ifinfop->if_targinfo6);
}

/*
 * Creates an ipmpstat_ofmt_t field list from the comma-separated list of
 * user-specified fields passed via `ofields'.  The table of known fields
 * (and their attributes) is passed via `fields'.
 */
static ipmpstat_ofmt_t *
ofmt_create(const char *ofields, ipmpstat_field_t fields[])
{
	char *token, *lasts, *ofields_dup;
	const char *fieldname;
	ipmpstat_ofmt_t *ofmt, *ofmt_head = NULL, *ofmt_tail;
	ipmpstat_field_t *fieldp;
	uint_t cols = 0;

	/*
	 * If "-o" was omitted or "-o all" was specified, build a list of
	 * field names.  If "-o" was omitted, stop building the list when
	 * we run out of columns.
	 */
	if (ofields == NULL || strcasecmp(ofields, "all") == 0) {
		for (fieldp = fields; fieldp->f_name != NULL; fieldp++) {
			cols += fieldp->f_width;
			if (ofields == NULL && cols > IPMPSTAT_NCOL)
				break;

			if ((ofmt = calloc(sizeof (*ofmt), 1)) == NULL)
				die("cannot allocate output format list");

			ofmt->o_field = fieldp;
			if (ofmt_head == NULL) {
				ofmt_head = ofmt;
				ofmt_tail = ofmt;
			} else {
				ofmt_tail->o_next = ofmt;
				ofmt_tail = ofmt;
			}
		}
		return (ofmt_head);
	}

	if ((ofields_dup = strdup(ofields)) == NULL)
		die("cannot allocate output format list");

	token = ofields_dup;
	while ((fieldname = strtok_r(token, ",", &lasts)) != NULL) {
		token = NULL;

		if ((fieldp = field_find(fields, fieldname)) == NULL) {
			/*
			 * Since machine parsers are unlikely to be able to
			 * gracefully handle missing fields, die if we're in
			 * parsable mode.  Otherwise, just print a warning.
			 */
			if (opt & IPMPSTAT_OPT_PARSABLE)
				die("unknown output field `%s'\n", fieldname);

			warn("ignoring unknown output field `%s'\n", fieldname);
			continue;
		}

		if ((ofmt = calloc(sizeof (*ofmt), 1)) == NULL)
			die("cannot allocate output format list");

		ofmt->o_field = fieldp;
		if (ofmt_head == NULL) {
			ofmt_head = ofmt;
			ofmt_tail = ofmt;
		} else {
			ofmt_tail->o_next = ofmt;
			ofmt_tail = ofmt;
		}
	}

	free(ofields_dup);
	if (ofmt_head == NULL)
		die("no valid output fields specified\n");

	return (ofmt_head);
}

/*
 * Destroys the provided `ofmt' field list.
 */
static void
ofmt_destroy(ipmpstat_ofmt_t *ofmt)
{
	ipmpstat_ofmt_t *ofmt_next;

	for (; ofmt != NULL; ofmt = ofmt_next) {
		ofmt_next = ofmt->o_next;
		free(ofmt);
	}
}

/*
 * Outputs a header for the fields named by `ofmt'.
 */
static void
ofmt_output_header(const ipmpstat_ofmt_t *ofmt)
{
	const ipmpstat_field_t *fieldp;

	for (; ofmt != NULL; ofmt = ofmt->o_next) {
		fieldp = ofmt->o_field;

		if (ofmt->o_next == NULL)
			(void) printf("%s", fieldp->f_name);
		else
			(void) printf("%-*s", fieldp->f_width, fieldp->f_name);
	}
	(void) printf("\n");
}

/*
 * Outputs one row of values for the fields named by `ofmt'.  The values to
 * output are obtained through the `ofmt' function pointers, which are
 * indirectly passed the `ih' and `arg' structures for state; see the block
 * comment at the start of this file for details.
 */
static void
ofmt_output(const ipmpstat_ofmt_t *ofmt, ipmp_handle_t ih, void *arg)
{
	int i;
	char buf[1024];
	boolean_t escsep;
	static int nrow;
	const char *value;
	uint_t width, valwidth;
	uint_t compress, overflow = 0;
	const ipmpstat_field_t *fieldp;
	ipmpstat_sfunc_arg_t sfunc_arg;

	/*
	 * For each screenful of data, display the header.
	 */
	if ((nrow++ % winsize.ws_row) == 0 && !(opt & IPMPSTAT_OPT_PARSABLE)) {
		ofmt_output_header(ofmt);
		nrow++;
	}

	/*
	 * Check if we'll be displaying multiple fields per line, and thus
	 * need to escape the field separator.
	 */
	escsep = (ofmt != NULL && ofmt->o_next != NULL);

	for (; ofmt != NULL; ofmt = ofmt->o_next) {
		fieldp = ofmt->o_field;

		sfunc_arg.sa_ih = ih;
		sfunc_arg.sa_data = arg;

		buf[0] = '\0';
		(*fieldp->f_sfunc)(&sfunc_arg, buf, sizeof (buf));

		if (opt & IPMPSTAT_OPT_PARSABLE) {
			for (i = 0; buf[i] != '\0'; i++) {
				if (escsep && (buf[i] == ':' || buf[i] == '\\'))
					(void) putchar('\\');
				(void) putchar(buf[i]);
			}
			if (ofmt->o_next != NULL)
				(void) putchar(':');
		} else {
			value = (buf[0] == '\0') ? "--" : buf;

			/*
			 * To avoid needless line-wraps, for the last field,
			 * don't include any trailing whitespace.
			 */
			if (ofmt->o_next == NULL) {
				(void) printf("%s", value);
				continue;
			}

			/*
			 * For other fields, grow the width as necessary to
			 * ensure the value completely fits.  However, if
			 * there's unused whitespace in subsequent fields,
			 * then "compress" that whitespace to attempt to get
			 * the columns to line up again.
			 */
			width = fieldp->f_width;
			valwidth = strlen(value);

			if (valwidth + overflow >= width) {
				overflow += valwidth - width + 1;
				(void) printf("%s ", value);
				continue;
			}

			if (overflow > 0) {
				compress = MIN(overflow, width - valwidth);
				overflow -= compress;
				width -= compress;
			}
			(void) printf("%-*s", width, value);
		}
	}
	(void) printf("\n");

	/*
	 * In case stdout has been redirected to e.g. a pipe, flush stdout so
	 * that commands can act on our output immediately.
	 */
	(void) fflush(stdout);
}

/*
 * Searches the `fields' array for a field matching `fieldname'.  Returns
 * a pointer to that field on success, or NULL on failure.
 */
static ipmpstat_field_t *
field_find(ipmpstat_field_t *fields, const char *fieldname)
{
	ipmpstat_field_t *fieldp;

	for (fieldp = fields; fieldp->f_name != NULL; fieldp++) {
		if (strcasecmp(fieldp->f_name, fieldname) == 0)
			return (fieldp);
	}
	return (NULL);
}

/*
 * Uses `enums' to map `enumval' to a string, and stores at most `bufsize'
 * bytes of that string into `buf'.
 */
static void
enum2str(const ipmpstat_enum_t *enums, int enumval, char *buf, uint_t bufsize)
{
	const ipmpstat_enum_t *enump;

	for (enump = enums; enump->e_name != NULL; enump++) {
		if (enump->e_val == enumval) {
			(void) strlcpy(buf, enump->e_name, bufsize);
			return;
		}
	}
	(void) snprintf(buf, bufsize, "<%d>", enumval);
}

/*
 * Stores the stringified value of the sockaddr_storage pointed to by `ssp'
 * into at most `bufsize' bytes of `buf'.
 */
static void
sockaddr2str(const struct sockaddr_storage *ssp, char *buf, uint_t bufsize)
{
	int flags = NI_NOFQDN;
	socklen_t socklen;
	struct sockaddr *sp = (struct sockaddr *)ssp;

	/*
	 * Sadly, getnameinfo() does not allow the socklen to be oversized for
	 * a given family -- so we must determine the exact size to pass to it.
	 */
	switch (ssp->ss_family) {
	case AF_INET:
		socklen = sizeof (struct sockaddr_in);
		break;
	case AF_INET6:
		socklen = sizeof (struct sockaddr_in6);
		break;
	default:
		(void) strlcpy(buf, "?", bufsize);
		return;
	}

	if (opt & IPMPSTAT_OPT_NUMERIC)
		flags |= NI_NUMERICHOST;

	(void) getnameinfo(sp, socklen, buf, bufsize, NULL, 0, flags);
}

static void
sighandler(int sig)
{
	assert(sig == SIGWINCH);

	if (ioctl(1, TIOCGWINSZ, &winsize) == -1 ||
	    winsize.ws_col == 0 || winsize.ws_row == 0) {
		winsize.ws_col = 80;
		winsize.ws_row = 24;
	}
}

static void
usage(void)
{
	const char *argstr = gettext("[-n] [-o <field> [-P]] -a|-g|-i|-p|-t");

	(void) fprintf(stderr, gettext("usage: %s %s\n"), progname, argstr);
	exit(EXIT_FAILURE);
}

/* PRINTFLIKE1 */
static void
warn(const char *format, ...)
{
	va_list alist;
	int error = errno;

	format = gettext(format);
	(void) fprintf(stderr, gettext("%s: warning: "), progname);

	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);

	if (strchr(format, '\n') == NULL)
		(void) fprintf(stderr, ": %s\n", strerror(error));
}

/* PRINTFLIKE2 */
static void
warn_ipmperr(int ipmperr, const char *format, ...)
{
	va_list alist;

	format = gettext(format);
	(void) fprintf(stderr, gettext("%s: warning: "), progname);

	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);

	(void) fprintf(stderr, ": %s\n", ipmp_errmsg(ipmperr));
}

/* PRINTFLIKE1 */
static void
die(const char *format, ...)
{
	va_list alist;
	int error = errno;

	format = gettext(format);
	(void) fprintf(stderr, "%s: ", progname);

	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);

	if (strchr(format, '\n') == NULL)
		(void) fprintf(stderr, ": %s\n", strerror(error));

	exit(EXIT_FAILURE);
}

/* PRINTFLIKE2 */
static void
die_ipmperr(int ipmperr, const char *format, ...)
{
	va_list alist;

	format = gettext(format);
	(void) fprintf(stderr, "%s: ", progname);

	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);
	(void) fprintf(stderr, ": %s\n", ipmp_errmsg(ipmperr));

	exit(EXIT_FAILURE);
}

static ipmpstat_field_t addr_fields[] = {
	{ "ADDRESS",    26,	sfunc_addr_address	},
	{ "STATE",	7,	sfunc_addr_state	},
	{ "GROUP",	12,	sfunc_addr_group	},
	{ "INBOUND",	12,	sfunc_addr_inbound	},
	{ "OUTBOUND",	23,	sfunc_addr_outbound	},
	{ NULL,		0, 	NULL			}
};

static ipmpstat_field_t group_fields[] = {
	{ "GROUP",	12, 	sfunc_group_ifname	},
	{ "GROUPNAME",	12,	sfunc_group_name 	},
	{ "STATE",	10,	sfunc_group_state	},
	{ "FDT",	10,	sfunc_group_fdt		},
	{ "INTERFACES",	30,	sfunc_group_interfaces	},
	{ NULL,		0, 	NULL			}
};

static ipmpstat_field_t if_fields[] = {
	{ "INTERFACE",	12,	sfunc_if_name		},
	{ "ACTIVE",	8, 	sfunc_if_active		},
	{ "GROUP",	12,	sfunc_if_group		},
	{ "FLAGS",	10,	sfunc_if_flags		},
	{ "LINK",	10,	sfunc_if_link		},
	{ "PROBE",	10,	sfunc_if_probe		},
	{ "STATE",	10, 	sfunc_if_state		},
	{ NULL,		0, 	NULL			}
};

static ipmpstat_field_t probe_fields[] = {
	{ "TIME",	10,	sfunc_probe_time	},
	{ "INTERFACE",	12,	sfunc_probe_ifname	},
	{ "PROBE",	7,	sfunc_probe_id		},
	{ "NETRTT",	10,	sfunc_probe_netrtt	},
	{ "RTT",	10,	sfunc_probe_rtt		},
	{ "RTTAVG",	10,	sfunc_probe_rttavg	},
	{ "TARGET",	20,	sfunc_probe_target	},
	{ "RTTDEV",	10,	sfunc_probe_rttdev	},
	{ NULL,		0, 	NULL			}
};

static ipmpstat_field_t targ_fields[] = {
	{ "INTERFACE",	12,	sfunc_targ_ifname	},
	{ "MODE",	10,	sfunc_targ_mode		},
	{ "TESTADDR",	20,	sfunc_targ_testaddr	},
	{ "TARGETS",	38,	sfunc_targ_targets	},
	{ NULL,		0, 	NULL			}
};

static ipmpstat_enum_t	addr_state[] = {
	{ "up",		IPMP_ADDR_UP			},
	{ "down",	IPMP_ADDR_DOWN			},
	{ NULL,		0 				}
};

static ipmpstat_enum_t	group_state[] = {
	{ "ok",		IPMP_GROUP_OK 			},
	{ "failed",	IPMP_GROUP_FAILED		},
	{ "degraded",	IPMP_GROUP_DEGRADED		},
	{ NULL,		0 				}
};

static ipmpstat_enum_t	if_link[] = {
	{ "up",		IPMP_LINK_UP 			},
	{ "down",	IPMP_LINK_DOWN			},
	{ "unknown",	IPMP_LINK_UNKNOWN		},
	{ NULL,		0 				}
};

static ipmpstat_enum_t	if_probe[] = {
	{ "ok",		IPMP_PROBE_OK 			},
	{ "failed",	IPMP_PROBE_FAILED		},
	{ "unknown",	IPMP_PROBE_UNKNOWN		},
	{ "disabled",	IPMP_PROBE_DISABLED		},
	{ NULL,		0 				}
};

static ipmpstat_enum_t	if_state[] = {
	{ "ok",		IPMP_IF_OK 			},
	{ "failed",	IPMP_IF_FAILED			},
	{ "unknown",	IPMP_IF_UNKNOWN			},
	{ "offline",	IPMP_IF_OFFLINE			},
	{ NULL,		0 				}
};

static ipmpstat_enum_t	targ_mode[] = {
	{ "disabled",	IPMP_TARG_DISABLED		},
	{ "routes",	IPMP_TARG_ROUTES		},
	{ "multicast",	IPMP_TARG_MULTICAST		},
	{ NULL,		0 				}
};
