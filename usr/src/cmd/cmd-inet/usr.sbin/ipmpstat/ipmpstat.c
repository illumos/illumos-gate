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
#include <ofmt.h>
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
 *      * The ofmt_sfunc_t function pointers (sfunc_*) obtain a given value
 *	  for a given IPMP object.  Each ofmt_sfunc_t is passed a buffer to
 *	  write its result into, the buffer's size, and an ipmpstat_sfunc_arg_t
 *	  state structure.  The state structure consists of a pointer to the
 *	  IPMP object to obtain information from (sa_data), and an open libipmp
 *	  handle (sa_ih) which can be used to do additional libipmp queries, if
 *	  necessary (e.g., because the object does not have all of the needed
 *	  information).
 *
 *	* The ofmt_field_t arrays (*_fields[]) provide the supported fields for
 *	  a given output format, along with output formatting information
 *	  (e.g., field width) and a pointer to an ofmt_sfunc_t function that
 *	  can obtain the value for a given IPMP object.  One ofmt_field_t array
 *	  is used per ipmpstat invocation, and is passed to ofmt_open() (along
 *	  with the output fields and modes requested by the user) to create an
 *	  ofmt_t.
 *
 *      * The ofmt_t structure is a handle that tracks all information
 *        related to output formatting and is used by libinetutil`ofmt_print()
 *	  (indirectly through our local ofmt_output() utility routine) to
 *	  output a single line of information about the provided IPMP object.
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
	ipmp_handle_t	ps_ih;		/* open IPMP handle */
	ofmt_handle_t	ps_ofmt;	/* open formatted-output handle */
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
#define	NS2FLOATMS(ns)	(NSEC2MSEC((float)(ns)))
#define	MS2FLOATSEC(ms)	((float)(ms) / 1000)

static const char	*progname;
static hrtime_t		probe_output_start;
static ipmpstat_opt_t	opt;
static ofmt_handle_t	ofmt;
static ipmpstat_enum_t	addr_state[], group_state[], if_state[], if_link[];
static ipmpstat_enum_t	if_probe[], targ_mode[];
static ofmt_field_t	addr_fields[], group_fields[], if_fields[];
static ofmt_field_t	probe_fields[], targ_fields[];
static ipmpstat_cbfunc_t walk_addr_cbfunc, walk_if_cbfunc;
static ipmpstat_cbfunc_t info_output_cbfunc, targinfo_output_cbfunc;
static ipmpstat_walker_t walk_addr, walk_if, walk_group;

static int probe_event(sysevent_t *, void *);
static void probe_output(ipmp_handle_t, ofmt_handle_t);
static void ofmt_output(ofmt_handle_t, ipmp_handle_t, void *);
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
	ofmt_status_t ofmterr;
	ofmt_field_t *fields = NULL;
	uint_t ofmtflags = 0;
	ipmp_handle_t ih;
	ipmp_qcontext_t qcontext = IPMP_QCONTEXT_SNAP;
	ipmpstat_cbfunc_t *cbfunc;
	ipmpstat_walker_t *walker;
	char errbuf[OFMT_BUFSIZE];

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
			ofmtflags |= OFMT_PARSABLE;
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

	/*
	 * Open a handle to the formatted output engine.
	 */
	ofmterr = ofmt_open(ofields, fields, ofmtflags, IPMPSTAT_NCOL, &ofmt);
	if (ofmterr != OFMT_SUCCESS) {
		/*
		 * If some fields were badly formed in human-friendly mode, we
		 * emit a warning and continue.  Otherwise exit immediately.
		 */
		(void) ofmt_strerror(ofmt, ofmterr, errbuf, sizeof (errbuf));
		if (ofmterr != OFMT_EBADFIELDS || (opt & IPMPSTAT_OPT_PARSABLE))
			die("%s\n", errbuf);
		else
			warn("%s\n", errbuf);
	}

	/*
	 * Obtain the window size and monitor changes to the size.  This data
	 * is used to redisplay the output headers when necessary.
	 */
	(void) sigset(SIGWINCH, sighandler);

	if ((err = ipmp_open(&ih)) != IPMP_SUCCESS)
		die_ipmperr(err, "cannot create IPMP handle");

	if (ipmp_ping_daemon(ih) != IPMP_SUCCESS)
		die("cannot contact in.mpathd(1M) -- is IPMP in use?\n");

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

	ofmt_close(ofmt);
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

static boolean_t
sfunc_nvwarn(const char *nvname)
{
	warn("cannot retrieve %s\n", nvname);
	return (B_FALSE);
}

static boolean_t
sfunc_addr_address(ofmt_arg_t *ofmtarg, char *buf, uint_t bufsize)
{
	ipmpstat_sfunc_arg_t *arg = ofmtarg->ofmt_cbarg;
	ipmp_addrinfo_t *adinfop = arg->sa_data;

	sockaddr2str(&adinfop->ad_addr, buf, bufsize);
	return (B_TRUE);
}

static boolean_t
sfunc_addr_group(ofmt_arg_t *ofmtarg, char *buf, uint_t bufsize)
{
	ipmpstat_sfunc_arg_t *arg = ofmtarg->ofmt_cbarg;
	int err;
	ipmp_addrinfo_t *adinfop = arg->sa_data;
	ipmp_groupinfo_t *grinfop;

	err = ipmp_getgroupinfo(arg->sa_ih, adinfop->ad_group, &grinfop);
	if (err != IPMP_SUCCESS) {
		warn_ipmperr(err, "cannot get info for group `%s'",
		    adinfop->ad_group);
		return (B_FALSE);
	}
	(void) strlcpy(buf, grinfop->gr_ifname, bufsize);
	ipmp_freegroupinfo(grinfop);
	return (B_TRUE);
}

static boolean_t
sfunc_addr_state(ofmt_arg_t *ofmtarg, char *buf, uint_t bufsize)
{
	ipmpstat_sfunc_arg_t *arg = ofmtarg->ofmt_cbarg;
	ipmp_addrinfo_t *adinfop = arg->sa_data;

	enum2str(addr_state, adinfop->ad_state, buf, bufsize);
	return (B_TRUE);
}

static boolean_t
sfunc_addr_inbound(ofmt_arg_t *ofmtarg, char *buf, uint_t bufsize)
{
	ipmpstat_sfunc_arg_t *arg = ofmtarg->ofmt_cbarg;
	ipmp_addrinfo_t *adinfop = arg->sa_data;

	(void) strlcpy(buf, adinfop->ad_binding, bufsize);
	return (B_TRUE);
}

static boolean_t
sfunc_addr_outbound(ofmt_arg_t *ofmtarg, char *buf, uint_t bufsize)
{
	ipmpstat_sfunc_arg_t *arg = ofmtarg->ofmt_cbarg;
	int err;
	uint_t i, nactive = 0;
	ipmp_ifinfo_t *ifinfop;
	ipmp_iflist_t *iflistp;
	ipmp_addrinfo_t *adinfop = arg->sa_data;
	ipmp_groupinfo_t *grinfop;

	if (adinfop->ad_state == IPMP_ADDR_DOWN)
		return (B_TRUE);

	/*
	 * If there's no inbound interface for this address, there can't
	 * be any outbound traffic.
	 */
	if (adinfop->ad_binding[0] == '\0')
		return (B_TRUE);

	/*
	 * The address can use any active interface in the group, so
	 * obtain all of those.
	 */
	err = ipmp_getgroupinfo(arg->sa_ih, adinfop->ad_group, &grinfop);
	if (err != IPMP_SUCCESS) {
		warn_ipmperr(err, "cannot get info for group `%s'",
		    adinfop->ad_group);
		return (B_FALSE);
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
	return (B_TRUE);
}

static boolean_t
sfunc_group_name(ofmt_arg_t *ofmtarg, char *buf, uint_t bufsize)
{
	ipmpstat_sfunc_arg_t *arg = ofmtarg->ofmt_cbarg;
	ipmp_groupinfo_t *grinfop = arg->sa_data;

	(void) strlcpy(buf, grinfop->gr_name, bufsize);
	return (B_TRUE);
}

static boolean_t
sfunc_group_ifname(ofmt_arg_t *ofmtarg, char *buf, uint_t bufsize)
{
	ipmpstat_sfunc_arg_t *arg = ofmtarg->ofmt_cbarg;
	ipmp_groupinfo_t *grinfop = arg->sa_data;

	(void) strlcpy(buf, grinfop->gr_ifname, bufsize);
	return (B_TRUE);
}

static boolean_t
sfunc_group_state(ofmt_arg_t *ofmtarg, char *buf, uint_t bufsize)
{
	ipmpstat_sfunc_arg_t *arg = ofmtarg->ofmt_cbarg;
	ipmp_groupinfo_t *grinfop = arg->sa_data;

	enum2str(group_state, grinfop->gr_state, buf, bufsize);
	return (B_TRUE);
}

static boolean_t
sfunc_group_fdt(ofmt_arg_t *ofmtarg, char *buf, uint_t bufsize)
{
	ipmpstat_sfunc_arg_t *arg = ofmtarg->ofmt_cbarg;
	ipmp_groupinfo_t *grinfop = arg->sa_data;

	if (grinfop->gr_fdt == 0)
		return (B_TRUE);

	(void) snprintf(buf, bufsize, "%.2fs", MS2FLOATSEC(grinfop->gr_fdt));
	return (B_TRUE);
}

static boolean_t
sfunc_group_interfaces(ofmt_arg_t *ofmtarg, char *buf, uint_t bufsize)
{
	ipmpstat_sfunc_arg_t *arg = ofmtarg->ofmt_cbarg;
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
	return (B_TRUE);
}

static boolean_t
sfunc_if_name(ofmt_arg_t *ofmtarg, char *buf, uint_t bufsize)
{
	ipmpstat_sfunc_arg_t *arg = ofmtarg->ofmt_cbarg;
	ipmp_ifinfo_t *ifinfop = arg->sa_data;

	(void) strlcpy(buf, ifinfop->if_name, bufsize);
	return (B_TRUE);
}

static boolean_t
sfunc_if_active(ofmt_arg_t *ofmtarg, char *buf, uint_t bufsize)
{
	ipmpstat_sfunc_arg_t *arg = ofmtarg->ofmt_cbarg;
	ipmp_ifinfo_t *ifinfop = arg->sa_data;

	if (ifinfop->if_flags & IPMP_IFFLAG_ACTIVE)
		(void) strlcpy(buf, "yes", bufsize);
	else
		(void) strlcpy(buf, "no", bufsize);
	return (B_TRUE);
}

static boolean_t
sfunc_if_group(ofmt_arg_t *ofmtarg, char *buf, uint_t bufsize)
{
	ipmpstat_sfunc_arg_t *arg = ofmtarg->ofmt_cbarg;
	int err;
	ipmp_ifinfo_t *ifinfop = arg->sa_data;
	ipmp_groupinfo_t *grinfop;

	err = ipmp_getgroupinfo(arg->sa_ih, ifinfop->if_group, &grinfop);
	if (err != IPMP_SUCCESS) {
		warn_ipmperr(err, "cannot get info for group `%s'",
		    ifinfop->if_group);
		return (B_TRUE);
	}

	(void) strlcpy(buf, grinfop->gr_ifname, bufsize);
	ipmp_freegroupinfo(grinfop);
	return (B_TRUE);
}

static boolean_t
sfunc_if_flags(ofmt_arg_t *ofmtarg, char *buf, uint_t bufsize)
{
	ipmpstat_sfunc_arg_t *arg = ofmtarg->ofmt_cbarg;
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
		return (B_TRUE);
	}

	if (strcmp(grinfop->gr_m4ifname, ifinfop->if_name) == 0)
		buf[IPMPSTAT_M4FLAG_INDEX] = 'm';

	if (strcmp(grinfop->gr_m6ifname, ifinfop->if_name) == 0)
		buf[IPMPSTAT_M6FLAG_INDEX] = 'M';

	if (strcmp(grinfop->gr_bcifname, ifinfop->if_name) == 0)
		buf[IPMPSTAT_BFLAG_INDEX] = 'b';

	ipmp_freegroupinfo(grinfop);
	return (B_TRUE);
}

static boolean_t
sfunc_if_link(ofmt_arg_t *ofmtarg, char *buf, uint_t bufsize)
{
	ipmpstat_sfunc_arg_t *arg = ofmtarg->ofmt_cbarg;
	ipmp_ifinfo_t *ifinfop = arg->sa_data;

	enum2str(if_link, ifinfop->if_linkstate, buf, bufsize);
	return (B_TRUE);
}

static boolean_t
sfunc_if_probe(ofmt_arg_t *ofmtarg, char *buf, uint_t bufsize)
{
	ipmpstat_sfunc_arg_t *arg = ofmtarg->ofmt_cbarg;
	ipmp_ifinfo_t *ifinfop = arg->sa_data;

	enum2str(if_probe, ifinfop->if_probestate, buf, bufsize);
	return (B_TRUE);
}

static boolean_t
sfunc_if_state(ofmt_arg_t *ofmtarg, char *buf, uint_t bufsize)
{
	ipmpstat_sfunc_arg_t *arg = ofmtarg->ofmt_cbarg;
	ipmp_ifinfo_t *ifinfop = arg->sa_data;

	enum2str(if_state, ifinfop->if_state, buf, bufsize);
	return (B_TRUE);
}

static boolean_t
sfunc_probe_id(ofmt_arg_t *ofmtarg, char *buf, uint_t bufsize)
{
	ipmpstat_sfunc_arg_t *arg = ofmtarg->ofmt_cbarg;
	uint32_t probe_id;
	nvlist_t *nvl = arg->sa_data;

	if (nvlist_lookup_uint32(nvl, IPMP_PROBE_ID, &probe_id) != 0)
		return (sfunc_nvwarn("IPMP_PROBE_ID"));

	(void) snprintf(buf, bufsize, "%u", probe_id);
	return (B_TRUE);
}

static boolean_t
sfunc_probe_ifname(ofmt_arg_t *ofmtarg, char *buf, uint_t bufsize)
{
	ipmpstat_sfunc_arg_t *arg = ofmtarg->ofmt_cbarg;
	char *ifname;
	nvlist_t *nvl = arg->sa_data;

	if (nvlist_lookup_string(nvl, IPMP_IF_NAME, &ifname) != 0)
		return (sfunc_nvwarn("IPMP_IF_NAME"));

	(void) strlcpy(buf, ifname, bufsize);
	return (B_TRUE);
}

static boolean_t
sfunc_probe_time(ofmt_arg_t *ofmtarg, char *buf, uint_t bufsize)
{
	ipmpstat_sfunc_arg_t *arg = ofmtarg->ofmt_cbarg;
	hrtime_t start;
	nvlist_t *nvl = arg->sa_data;

	if (nvlist_lookup_hrtime(nvl, IPMP_PROBE_START_TIME, &start) != 0)
		return (sfunc_nvwarn("IPMP_PROBE_START_TIME"));

	(void) snprintf(buf, bufsize, "%.2fs",
	    (float)(start - probe_output_start) / NANOSEC);
	return (B_TRUE);
}

static boolean_t
sfunc_probe_target(ofmt_arg_t *ofmtarg, char *buf, uint_t bufsize)
{
	ipmpstat_sfunc_arg_t *arg = ofmtarg->ofmt_cbarg;
	uint_t nelem;
	struct sockaddr_storage *target;
	nvlist_t *nvl = arg->sa_data;

	if (nvlist_lookup_byte_array(nvl, IPMP_PROBE_TARGET,
	    (uchar_t **)&target, &nelem) != 0)
		return (sfunc_nvwarn("IPMP_PROBE_TARGET"));

	sockaddr2str(target, buf, bufsize);
	return (B_TRUE);
}

static boolean_t
sfunc_probe_rtt(ofmt_arg_t *ofmtarg, char *buf, uint_t bufsize)
{
	ipmpstat_sfunc_arg_t *arg = ofmtarg->ofmt_cbarg;
	hrtime_t start, ackproc;
	nvlist_t *nvl = arg->sa_data;
	uint32_t state;

	if (nvlist_lookup_uint32(nvl, IPMP_PROBE_STATE, &state) != 0)
		return (sfunc_nvwarn("IPMP_PROBE_STATE"));

	if (state != IPMP_PROBE_ACKED)
		return (B_TRUE);

	if (nvlist_lookup_hrtime(nvl, IPMP_PROBE_START_TIME, &start) != 0)
		return (sfunc_nvwarn("IPMP_PROBE_START_TIME"));

	if (nvlist_lookup_hrtime(nvl, IPMP_PROBE_ACKPROC_TIME, &ackproc) != 0)
		return (sfunc_nvwarn("IPMP_PROBE_ACKPROC_TIME"));

	(void) snprintf(buf, bufsize, "%.2fms", NS2FLOATMS(ackproc - start));
	return (B_TRUE);
}

static boolean_t
sfunc_probe_netrtt(ofmt_arg_t *ofmtarg, char *buf, uint_t bufsize)
{
	ipmpstat_sfunc_arg_t *arg = ofmtarg->ofmt_cbarg;
	hrtime_t sent, ackrecv;
	nvlist_t *nvl = arg->sa_data;
	uint32_t state;

	if (nvlist_lookup_uint32(nvl, IPMP_PROBE_STATE, &state) != 0)
		return (sfunc_nvwarn("IPMP_PROBE_STATE"));

	if (state != IPMP_PROBE_ACKED)
		return (B_TRUE);

	if (nvlist_lookup_hrtime(nvl, IPMP_PROBE_SENT_TIME, &sent) != 0)
		return (sfunc_nvwarn("IPMP_PROBE_SENT_TIME"));

	if (nvlist_lookup_hrtime(nvl, IPMP_PROBE_ACKRECV_TIME, &ackrecv) != 0)
		return (sfunc_nvwarn("IPMP_PROBE_ACKRECV_TIME"));

	(void) snprintf(buf, bufsize, "%.2fms", NS2FLOATMS(ackrecv - sent));
	return (B_TRUE);
}

static boolean_t
sfunc_probe_rttavg(ofmt_arg_t *ofmtarg, char *buf, uint_t bufsize)
{
	ipmpstat_sfunc_arg_t *arg = ofmtarg->ofmt_cbarg;
	int64_t rttavg;
	nvlist_t *nvl = arg->sa_data;

	if (nvlist_lookup_int64(nvl, IPMP_PROBE_TARGET_RTTAVG, &rttavg) != 0)
		return (sfunc_nvwarn("IPMP_PROBE_TARGET_RTTAVG"));

	if (rttavg != 0)
		(void) snprintf(buf, bufsize, "%.2fms", NS2FLOATMS(rttavg));
	return (B_TRUE);
}

static boolean_t
sfunc_probe_rttdev(ofmt_arg_t *ofmtarg, char *buf, uint_t bufsize)
{
	ipmpstat_sfunc_arg_t *arg = ofmtarg->ofmt_cbarg;
	int64_t rttdev;
	nvlist_t *nvl = arg->sa_data;

	if (nvlist_lookup_int64(nvl, IPMP_PROBE_TARGET_RTTDEV, &rttdev) != 0)
		return (sfunc_nvwarn("IPMP_PROBE_TARGET_RTTDEV"));

	if (rttdev != 0)
		(void) snprintf(buf, bufsize, "%.2fms", NS2FLOATMS(rttdev));
	return (B_TRUE);
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
probe_output(ipmp_handle_t ih, ofmt_handle_t ofmt)
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

static boolean_t
sfunc_targ_ifname(ofmt_arg_t *ofmtarg, char *buf, uint_t bufsize)
{
	ipmpstat_sfunc_arg_t *arg = ofmtarg->ofmt_cbarg;
	ipmp_targinfo_t *targinfop = arg->sa_data;

	(void) strlcpy(buf, targinfop->it_name, bufsize);
	return (B_TRUE);
}

static boolean_t
sfunc_targ_mode(ofmt_arg_t *ofmtarg, char *buf, uint_t bufsize)
{
	ipmpstat_sfunc_arg_t *arg = ofmtarg->ofmt_cbarg;
	ipmp_targinfo_t *targinfop = arg->sa_data;

	enum2str(targ_mode, targinfop->it_targmode, buf, bufsize);
	return (B_TRUE);
}

static boolean_t
sfunc_targ_testaddr(ofmt_arg_t *ofmtarg, char *buf, uint_t bufsize)
{
	ipmpstat_sfunc_arg_t *arg = ofmtarg->ofmt_cbarg;
	ipmp_targinfo_t *targinfop = arg->sa_data;

	if (targinfop->it_targmode != IPMP_TARG_DISABLED)
		sockaddr2str(&targinfop->it_testaddr, buf, bufsize);
	return (B_TRUE);
}

static boolean_t
sfunc_targ_targets(ofmt_arg_t *ofmtarg, char *buf, uint_t bufsize)
{
	ipmpstat_sfunc_arg_t *arg = ofmtarg->ofmt_cbarg;
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
	return (B_TRUE);
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
 * Outputs one row of values.  The values to output are obtained through the
 * callback function pointers.  The actual values are computed from the `ih'
 * and `arg' structures passed to the callback function.
 */
static void
ofmt_output(const ofmt_handle_t ofmt, ipmp_handle_t ih, void *arg)
{
	ipmpstat_sfunc_arg_t	sfunc_arg;

	sfunc_arg.sa_ih = ih;
	sfunc_arg.sa_data = arg;
	ofmt_print(ofmt, &sfunc_arg);
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

	ofmt_update_winsize(ofmt);
}

static void
usage(void)
{
	const char *argstr = gettext("[-n] [-o <field> [-P]] -a|-g|-i|-p|-t");

	(void) fprintf(stderr, gettext("usage: %s %s\n"), progname, argstr);
	(void) fprintf(stderr, gettext("\n"
	    "  output modes:\t -a  display IPMP data address information\n"
	    "\t\t -g  display IPMP group information\n"
	    "\t\t -i  display IPMP-related IP interface information\n"
	    "\t\t -p  display IPMP probe information\n"
	    "\t\t -t  display IPMP target information\n\n"
	    "       options:\t -n  display IP addresses numerically\n"
	    "\t\t -o  display only the specified fields, in order\n"
	    "\t\t -P  display using parsable output mode\n"));

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

static ofmt_field_t addr_fields[] = {
	{ "ADDRESS",    26,	0, sfunc_addr_address		},
	{ "STATE",	7,	0, sfunc_addr_state		},
	{ "GROUP",	12,	0, sfunc_addr_group		},
	{ "INBOUND",	12,	0, sfunc_addr_inbound		},
	{ "OUTBOUND",	23,	0, sfunc_addr_outbound		},
	{ NULL,		0, 	0, NULL				}
};

static ofmt_field_t group_fields[] = {
	{ "GROUP",	12, 	0, sfunc_group_ifname		},
	{ "GROUPNAME",	12,	0, sfunc_group_name 		},
	{ "STATE",	10,	0, sfunc_group_state		},
	{ "FDT",	10,	0, sfunc_group_fdt		},
	{ "INTERFACES",	30,	0, sfunc_group_interfaces	},
	{ NULL,		0, 	0, NULL				}
};

static ofmt_field_t if_fields[] = {
	{ "INTERFACE",	12,	0, sfunc_if_name		},
	{ "ACTIVE",	8, 	0, sfunc_if_active		},
	{ "GROUP",	12,	0, sfunc_if_group		},
	{ "FLAGS",	10,	0, sfunc_if_flags		},
	{ "LINK",	10,	0, sfunc_if_link		},
	{ "PROBE",	10,	0, sfunc_if_probe		},
	{ "STATE",	10, 	0, sfunc_if_state		},
	{ NULL,		0, 	0, NULL				}
};

static ofmt_field_t probe_fields[] = {
	{ "TIME",	10,	0, sfunc_probe_time		},
	{ "INTERFACE",	12,	0, sfunc_probe_ifname		},
	{ "PROBE",	7,	0, sfunc_probe_id		},
	{ "NETRTT",	10,	0, sfunc_probe_netrtt		},
	{ "RTT",	10,	0, sfunc_probe_rtt		},
	{ "RTTAVG",	10,	0, sfunc_probe_rttavg		},
	{ "TARGET",	20,	0, sfunc_probe_target		},
	{ "RTTDEV",	10,	0, sfunc_probe_rttdev		},
	{ NULL,		0, 	0, NULL				}
};

static ofmt_field_t targ_fields[] = {
	{ "INTERFACE",	12,	0, sfunc_targ_ifname		},
	{ "MODE",	10,	0, sfunc_targ_mode		},
	{ "TESTADDR",	20,	0, sfunc_targ_testaddr		},
	{ "TARGETS",	38,	0, sfunc_targ_targets		},
	{ NULL,		0, 	0, NULL				}
};

static ipmpstat_enum_t	addr_state[] = {
	{ "up",		IPMP_ADDR_UP				},
	{ "down",	IPMP_ADDR_DOWN				},
	{ NULL,		0 					}
};

static ipmpstat_enum_t	group_state[] = {
	{ "ok",		IPMP_GROUP_OK 				},
	{ "failed",	IPMP_GROUP_FAILED			},
	{ "degraded",	IPMP_GROUP_DEGRADED			},
	{ NULL,		0 					}
};

static ipmpstat_enum_t	if_link[] = {
	{ "up",		IPMP_LINK_UP 				},
	{ "down",	IPMP_LINK_DOWN				},
	{ "unknown",	IPMP_LINK_UNKNOWN			},
	{ NULL,		0 					}
};

static ipmpstat_enum_t	if_probe[] = {
	{ "ok",		IPMP_PROBE_OK 				},
	{ "failed",	IPMP_PROBE_FAILED			},
	{ "unknown",	IPMP_PROBE_UNKNOWN			},
	{ "disabled",	IPMP_PROBE_DISABLED			},
	{ NULL,		0 					}
};

static ipmpstat_enum_t	if_state[] = {
	{ "ok",		IPMP_IF_OK 				},
	{ "failed",	IPMP_IF_FAILED				},
	{ "unknown",	IPMP_IF_UNKNOWN				},
	{ "offline",	IPMP_IF_OFFLINE				},
	{ NULL,		0 					}
};

static ipmpstat_enum_t	targ_mode[] = {
	{ "disabled",	IPMP_TARG_DISABLED			},
	{ "routes",	IPMP_TARG_ROUTES			},
	{ "multicast",	IPMP_TARG_MULTICAST			},
	{ NULL,		0 					}
};
