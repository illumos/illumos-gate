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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2017 Nexenta Systems, Inc.
 * Copyright 2017 Gary Mills
 */

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <inet/ip.h>
#include <inet/iptun.h>
#include <inet/tunables.h>
#include <libdladm.h>
#include <libdliptun.h>
#include <libdllink.h>
#include <libinetutil.h>
#include <libipadm.h>
#include <locale.h>
#include <netdb.h>
#include <netinet/in.h>
#include <ofmt.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <zone.h>

#define	STR_UNKNOWN_VAL	"?"
#define	LIFC_DEFAULT	(LIFC_NOXMIT | LIFC_TEMPORARY | LIFC_ALLZONES |\
			LIFC_UNDER_IPMP)

typedef void cmdfunc_t(int, char **, const char *);
static cmdfunc_t do_create_if, do_delete_if, do_enable_if, do_disable_if;
static cmdfunc_t do_show_if;
static cmdfunc_t do_set_prop, do_show_prop, do_set_ifprop;
static cmdfunc_t do_show_ifprop, do_reset_ifprop, do_reset_prop;
static cmdfunc_t do_show_addrprop, do_set_addrprop, do_reset_addrprop;
static cmdfunc_t do_create_addr, do_delete_addr, do_show_addr;
static cmdfunc_t do_enable_addr, do_disable_addr;
static cmdfunc_t do_up_addr, do_down_addr, do_refresh_addr;

typedef struct	cmd {
	char		*c_name;
	cmdfunc_t	*c_fn;
	const char	*c_usage;
} cmd_t;

static cmd_t	cmds[] = {
	/* interface management related sub-commands */
	{ "create-if",	do_create_if,	"\tcreate-if\t[-t] <interface>"	},
	{ "disable-if",	do_disable_if,	"\tdisable-if\t-t <interface>"	},
	{ "enable-if",	do_enable_if,	"\tenable-if\t-t <interface>"	},
	{ "delete-if",	do_delete_if,	"\tdelete-if\t<interface>"	},
	{ "show-if",	do_show_if,
	    "\tshow-if\t\t[[-p] -o <field>,...] [<interface>]\n"	},
	{ "set-ifprop",	do_set_ifprop,
	    "\tset-ifprop\t[-t] -p <prop>=<value[,...]> -m <protocol> "
	    "<interface>" 						},
	{ "reset-ifprop", do_reset_ifprop,
	    "\treset-ifprop\t[-t] -p <prop> -m <protocol> <interface>"	},
	{ "show-ifprop", do_show_ifprop,
	    "\tshow-ifprop\t[[-c] -o <field>,...] [-p <prop>,...]\n"
	    "\t\t\t[-m <protocol>] [interface]\n" 			},

	/* address management related sub-commands */
	{ "create-addr", do_create_addr,
	    "\tcreate-addr\t[-t] -T static [-d] "
	    "-a{local|remote}=addr[/prefixlen]\n\t\t\t<addrobj>\n"
	    "\tcreate-addr\t[-t] -T dhcp [-w <seconds> | forever] <addrobj>\n"
	    "\tcreate-addr\t[-t] -T addrconf [-i interface-id]\n"
	    "\t\t\t[-p {stateful|stateless}={yes|no}] <addrobj>" },
	{ "down-addr",	do_down_addr,	"\tdown-addr\t[-t] <addrobj>"	},
	{ "up-addr",	do_up_addr,	"\tup-addr\t\t[-t] <addrobj>"	},
	{ "disable-addr", do_disable_addr, "\tdisable-addr\t-t <addrobj>" },
	{ "enable-addr", do_enable_addr, "\tenable-addr\t-t <addrobj>"	},
	{ "refresh-addr", do_refresh_addr, "\trefresh-addr\t[-i] <addrobj>" },
	{ "delete-addr", do_delete_addr, "\tdelete-addr\t[-r] <addrobj>" },
	{ "show-addr",	do_show_addr,
	    "\tshow-addr\t[[-p] -o <field>,...] [<addrobj>]\n"		},
	{ "set-addrprop", do_set_addrprop,
	    "\tset-addrprop\t[-t] -p <prop>=<value[,...]> <addrobj>"	},
	{ "reset-addrprop", do_reset_addrprop,
	    "\treset-addrprop\t[-t] -p <prop> <addrobj>"		},
	{ "show-addrprop", do_show_addrprop,
	    "\tshow-addrprop\t[[-c] -o <field>,...] [-p <prop>,...] "
	    "<addrobj>\n" 						},

	/* protocol properties related sub-commands */
	{ "set-prop",	do_set_prop,
	    "\tset-prop\t[-t] -p <prop>[+|-]=<value[,...]> <protocol>"	},
	{ "reset-prop",	do_reset_prop,
	    "\treset-prop\t[-t] -p <prop> <protocol>"			},
	{ "show-prop",	do_show_prop,
	    "\tshow-prop\t[[-c] -o <field>,...] [-p <prop>,...]"
	    " [protocol]"						}
};

static const struct option if_longopts[] = {
	{"temporary",	no_argument,		0, 't'	},
	{ 0, 0, 0, 0 }
};

static const struct option show_prop_longopts[] = {
	{"parsable",	no_argument,		0, 'c'	},
	{"prop",	required_argument,	0, 'p'	},
	{"output",	required_argument,	0, 'o'	},
	{ 0, 0, 0, 0 }
};

static const struct option show_ifprop_longopts[] = {
	{"module",	required_argument,	0, 'm'	},
	{"parsable",	no_argument,		0, 'c'	},
	{"prop",	required_argument,	0, 'p'	},
	{"output",	required_argument,	0, 'o'	},
	{ 0, 0, 0, 0 }
};

static const struct option set_prop_longopts[] = {
	{"prop",	required_argument,	0, 'p'	},
	{"temporary",	no_argument,		0, 't'	},
	{ 0, 0, 0, 0 }
};

static const struct option set_ifprop_longopts[] = {
	{"module",	required_argument,	0, 'm'	},
	{"prop",	required_argument,	0, 'p'	},
	{"temporary",	no_argument,		0, 't'	},
	{ 0, 0, 0, 0 }
};

static const struct option addr_misc_longopts[] = {
	{"inform",	no_argument,		0, 'i'	},
	{"release",	no_argument,		0, 'r'	},
	{"temporary",	no_argument,		0, 't'	},
	{ 0, 0, 0, 0 }
};

static const struct option addr_longopts[] = {
	{"address",	required_argument,	0, 'a'	},
	{"down",	no_argument,		0, 'd'	},
	{"interface-id", required_argument,	0, 'i'	},
	{"prop",	required_argument,	0, 'p'	},
	{"temporary",	no_argument,		0, 't'	},
	{"type",	required_argument,	0, 'T'	},
	{"wait",	required_argument,	0, 'w'	},
	{ 0, 0, 0, 0 }
};

static const struct option show_addr_longopts[] = {
	{"parsable",	no_argument,		0, 'p'	},
	{"output",	required_argument,	0, 'o'	},
	{ 0, 0, 0, 0 }
};

static const struct option show_if_longopts[] = {
	{"parsable",	no_argument,		0, 'p'	},
	{"output",	required_argument,	0, 'o'	},
	{ 0, 0, 0, 0 }
};

/* callback functions to print show-* subcommands output */
static ofmt_cb_t print_prop_cb;
static ofmt_cb_t print_sa_cb;
static ofmt_cb_t print_si_cb;

/* structures for 'ipadm show-*' subcommands */
typedef enum {
	IPADM_PROPFIELD_IFNAME,
	IPADM_PROPFIELD_PROTO,
	IPADM_PROPFIELD_ADDROBJ,
	IPADM_PROPFIELD_PROPERTY,
	IPADM_PROPFIELD_PERM,
	IPADM_PROPFIELD_CURRENT,
	IPADM_PROPFIELD_PERSISTENT,
	IPADM_PROPFIELD_DEFAULT,
	IPADM_PROPFIELD_POSSIBLE
} ipadm_propfield_index_t;

static ofmt_field_t intfprop_fields[] = {
/* name,	field width,	index,			callback */
{ "IFNAME",	12,	IPADM_PROPFIELD_IFNAME,		print_prop_cb},
{ "PROPERTY",	16,	IPADM_PROPFIELD_PROPERTY,	print_prop_cb},
{ "PROTO",	6,	IPADM_PROPFIELD_PROTO,		print_prop_cb},
{ "PERM",	5,	IPADM_PROPFIELD_PERM,		print_prop_cb},
{ "CURRENT",	11,	IPADM_PROPFIELD_CURRENT,	print_prop_cb},
{ "PERSISTENT",	11,	IPADM_PROPFIELD_PERSISTENT,	print_prop_cb},
{ "DEFAULT",	11,	IPADM_PROPFIELD_DEFAULT,	print_prop_cb},
{ "POSSIBLE",	16,	IPADM_PROPFIELD_POSSIBLE,	print_prop_cb},
{ NULL,		0,	0,				NULL}
};


static ofmt_field_t modprop_fields[] = {
/* name,	field width,	index,			callback */
{ "PROTO",	6,	IPADM_PROPFIELD_PROTO,		print_prop_cb},
{ "PROPERTY",	22,	IPADM_PROPFIELD_PROPERTY,	print_prop_cb},
{ "PERM",	5,	IPADM_PROPFIELD_PERM,		print_prop_cb},
{ "CURRENT",	13,	IPADM_PROPFIELD_CURRENT,	print_prop_cb},
{ "PERSISTENT",	13,	IPADM_PROPFIELD_PERSISTENT,	print_prop_cb},
{ "DEFAULT",	13,	IPADM_PROPFIELD_DEFAULT,	print_prop_cb},
{ "POSSIBLE",	15,	IPADM_PROPFIELD_POSSIBLE,	print_prop_cb},
{ NULL,		0,	0,				NULL}
};

static ofmt_field_t addrprop_fields[] = {
/* name,	field width,	index,			callback */
{ "ADDROBJ",	18,	IPADM_PROPFIELD_ADDROBJ,	print_prop_cb},
{ "PROPERTY",	11,	IPADM_PROPFIELD_PROPERTY,	print_prop_cb},
{ "PERM",	5,	IPADM_PROPFIELD_PERM,		print_prop_cb},
{ "CURRENT",	16,	IPADM_PROPFIELD_CURRENT,	print_prop_cb},
{ "PERSISTENT",	16,	IPADM_PROPFIELD_PERSISTENT,	print_prop_cb},
{ "DEFAULT",	16,	IPADM_PROPFIELD_DEFAULT,	print_prop_cb},
{ "POSSIBLE",	15,	IPADM_PROPFIELD_POSSIBLE,	print_prop_cb},
{ NULL,		0,	0,				NULL}
};

typedef struct show_prop_state {
	char		sps_ifname[LIFNAMSIZ];
	char		sps_aobjname[IPADM_AOBJSIZ];
	const char	*sps_pname;
	uint_t		sps_proto;
	char		*sps_propval;
	nvlist_t	*sps_proplist;
	boolean_t	sps_parsable;
	boolean_t	sps_addrprop;
	boolean_t	sps_ifprop;
	boolean_t	sps_modprop;
	ipadm_status_t	sps_status;
	ipadm_status_t	sps_retstatus;
	ofmt_handle_t	sps_ofmt;
} show_prop_state_t;

typedef struct show_addr_state {
	boolean_t	sa_parsable;
	boolean_t	sa_persist;
	ofmt_handle_t	sa_ofmt;
} show_addr_state_t;

typedef struct show_if_state {
	boolean_t	si_parsable;
	ofmt_handle_t	si_ofmt;
} show_if_state_t;

typedef struct show_addr_args_s {
	show_addr_state_t	*sa_state;
	ipadm_addr_info_t	*sa_info;
} show_addr_args_t;

typedef struct show_if_args_s {
	show_if_state_t *si_state;
	ipadm_if_info_t *si_info;
} show_if_args_t;

typedef enum {
	SA_ADDROBJ,
	SA_TYPE,
	SA_STATE,
	SA_CURRENT,
	SA_PERSISTENT,
	SA_ADDR
} sa_field_index_t;

typedef enum {
	SI_IFNAME,
	SI_STATE,
	SI_CURRENT,
	SI_PERSISTENT
} si_field_index_t;

static ofmt_field_t show_addr_fields[] = {
/* name,	field width,	id,		callback */
{ "ADDROBJ",	18,		SA_ADDROBJ,	print_sa_cb},
{ "TYPE",	9,		SA_TYPE,	print_sa_cb},
{ "STATE",	13,		SA_STATE,	print_sa_cb},
{ "CURRENT",	8,		SA_CURRENT,	print_sa_cb},
{ "PERSISTENT",	11,		SA_PERSISTENT,	print_sa_cb},
{ "ADDR",	46,		SA_ADDR,	print_sa_cb},
{ NULL,		0,		0,		NULL}
};

static ofmt_field_t show_if_fields[] = {
/* name,	field width,	id,		callback */
{ "IFNAME",	11,		SI_IFNAME,	print_si_cb},
{ "STATE",	9,		SI_STATE,	print_si_cb},
{ "CURRENT",	13,		SI_CURRENT,	print_si_cb},
{ "PERSISTENT",	11,		SI_PERSISTENT,	print_si_cb},
{ NULL,		0,		0,		NULL}
};

#define	IPADM_ALL_BITS	((uint_t)-1)
typedef struct intf_mask {
	char		*name;
	uint64_t	bits;
	uint64_t	mask;
} fmask_t;

/*
 * Handle to libipadm. Opened in main() before the sub-command specific
 * function is called and is closed before the program exits.
 */
ipadm_handle_t	iph = NULL;

/*
 * Opaque ipadm address object. Used by all the address management subcommands.
 */
ipadm_addrobj_t	ipaddr = NULL;

static char *progname;

static void	die(const char *, ...);
static void	die_opterr(int, int, const char *);
static void	warn_ipadmerr(ipadm_status_t, const char *, ...);
static void 	ipadm_ofmt_check(ofmt_status_t, boolean_t, ofmt_handle_t);
static void 	ipadm_check_propstr(const char *, boolean_t, const char *);
static void 	process_misc_addrargs(int, char **, const char *, int *,
		    uint32_t *);

static void
usage(void)
{
	int	i;
	cmd_t	*cmdp;

	(void) fprintf(stderr,
	    gettext("usage:  ipadm <subcommand> <args> ...\n"));
	for (i = 0; i < sizeof (cmds) / sizeof (cmds[0]); i++) {
		cmdp = &cmds[i];
		if (cmdp->c_usage != NULL)
			(void) fprintf(stderr, "%s\n", gettext(cmdp->c_usage));
	}

	ipadm_destroy_addrobj(ipaddr);
	ipadm_close(iph);
	exit(1);
}

int
main(int argc, char *argv[])
{
	int	i;
	cmd_t	*cmdp;
	ipadm_status_t status;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	if ((progname = strrchr(argv[0], '/')) == NULL)
		progname = argv[0];
	else
		progname++;

	if (argc < 2)
		usage();

	status = ipadm_open(&iph, 0);
	if (status != IPADM_SUCCESS) {
		die("Could not open handle to library - %s",
		    ipadm_status2str(status));
	}

	for (i = 0; i < sizeof (cmds) / sizeof (cmds[0]); i++) {
		cmdp = &cmds[i];
		if (strcmp(argv[1], cmdp->c_name) == 0) {
			cmdp->c_fn(argc - 1, &argv[1], gettext(cmdp->c_usage));
			ipadm_destroy_addrobj(ipaddr);
			ipadm_close(iph);
			exit(0);
		}
	}

	(void) fprintf(stderr, gettext("%s: unknown subcommand '%s'\n"),
	    progname, argv[1]);
	usage();

	return (0);
}

/*
 * Create an IP interface for which no saved configuration exists in the
 * persistent store.
 */
static void
do_create_if(int argc, char *argv[], const char *use)
{
	ipadm_status_t	status;
	int		option;
	uint32_t	flags = IPADM_OPT_PERSIST|IPADM_OPT_ACTIVE;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":t", if_longopts,
	    NULL)) != -1) {
		switch (option) {
		case 't':
			/*
			 * "ifconfig" mode - plumb interface, but do not
			 * restore settings that may exist in db.
			 */
			flags &= ~IPADM_OPT_PERSIST;
			break;
		default:
			die_opterr(optopt, option, use);
		}
	}
	if (optind != (argc - 1))
		die("Usage: %s", use);
	status = ipadm_create_if(iph, argv[optind], AF_UNSPEC, flags);
	if (status != IPADM_SUCCESS) {
		die("Could not create %s : %s",
		    argv[optind], ipadm_status2str(status));
	}
}

/*
 * Enable an IP interface based on the persistent configuration for
 * that interface.
 */
static void
do_enable_if(int argc, char *argv[], const char *use)
{
	ipadm_status_t	status;
	int		index;
	uint32_t 	flags = IPADM_OPT_ACTIVE|IPADM_OPT_PERSIST;

	process_misc_addrargs(argc, argv, use, &index, &flags);
	if (flags & IPADM_OPT_PERSIST)
		die("persistent operation not supported for enable-if");
	status = ipadm_enable_if(iph, argv[index], flags);
	if (status == IPADM_ALL_ADDRS_NOT_ENABLED) {
		warn_ipadmerr(status, "");
	} else if (status != IPADM_SUCCESS) {
		die("Could not enable %s : %s",
		    argv[optind], ipadm_status2str(status));
	}
}

/*
 * Remove an IP interface from both active and persistent configuration.
 */
static void
do_delete_if(int argc, char *argv[], const char *use)
{
	ipadm_status_t	status;
	uint32_t	flags = IPADM_OPT_ACTIVE|IPADM_OPT_PERSIST;

	if (argc != 2)
		die("Usage: %s", use);

	status = ipadm_delete_if(iph, argv[1], AF_UNSPEC, flags);
	if (status != IPADM_SUCCESS) {
		die("Could not delete %s: %s",
		    argv[optind], ipadm_status2str(status));
	}
}

/*
 * Disable an IP interface by removing it from active configuration.
 */
static void
do_disable_if(int argc, char *argv[], const char *use)
{
	ipadm_status_t	status;
	int		index;
	uint32_t 	flags = IPADM_OPT_ACTIVE|IPADM_OPT_PERSIST;

	process_misc_addrargs(argc, argv, use, &index, &flags);
	if (flags & IPADM_OPT_PERSIST)
		die("persistent operation not supported for disable-if");
	status = ipadm_disable_if(iph, argv[index], flags);
	if (status != IPADM_SUCCESS) {
		die("Could not disable %s: %s",
		    argv[optind], ipadm_status2str(status));
	}
}

/*
 * Print individual columns for the show-*prop subcommands.
 */
static void
print_prop(show_prop_state_t *statep, uint_t flags, char *buf, size_t bufsize)
{
	const char		*prop_name = statep->sps_pname;
	char			*ifname = statep->sps_ifname;
	char			*propval = statep->sps_propval;
	uint_t			proto = statep->sps_proto;
	size_t			propsize = MAXPROPVALLEN;
	ipadm_status_t		status;

	if (statep->sps_ifprop) {
		status = ipadm_get_ifprop(iph, ifname, prop_name, propval,
		    &propsize, proto, flags);
	} else if (statep->sps_modprop) {
		status = ipadm_get_prop(iph, prop_name, propval, &propsize,
		    proto, flags);
	} else {
		status = ipadm_get_addrprop(iph, prop_name, propval, &propsize,
		    statep->sps_aobjname, flags);
	}

	if (status != IPADM_SUCCESS) {
		if ((status == IPADM_NOTFOUND && (flags & IPADM_OPT_PERSIST)) ||
		    status == IPADM_ENXIO) {
			propval[0] = '\0';
			goto cont;
		}
		statep->sps_status = status;
		statep->sps_retstatus = status;
		return;
	}
cont:
	statep->sps_status = IPADM_SUCCESS;
	(void) snprintf(buf, bufsize, "%s", propval);
}

/*
 * Callback function for show-*prop subcommands.
 */
static boolean_t
print_prop_cb(ofmt_arg_t *ofarg, char *buf, size_t bufsize)
{
	show_prop_state_t	*statep = ofarg->ofmt_cbarg;
	const char		*propname = statep->sps_pname;
	uint_t			proto = statep->sps_proto;
	boolean_t		cont = _B_TRUE;

	/*
	 * Fail retrieving remaining fields, if you fail
	 * to retrieve a field.
	 */
	if (statep->sps_status != IPADM_SUCCESS)
		return (_B_FALSE);

	switch (ofarg->ofmt_id) {
	case IPADM_PROPFIELD_IFNAME:
		(void) snprintf(buf, bufsize, "%s", statep->sps_ifname);
		break;
	case IPADM_PROPFIELD_PROTO:
		(void) snprintf(buf, bufsize, "%s", ipadm_proto2str(proto));
		break;
	case IPADM_PROPFIELD_ADDROBJ:
		(void) snprintf(buf, bufsize, "%s", statep->sps_aobjname);
		break;
	case IPADM_PROPFIELD_PROPERTY:
		(void) snprintf(buf, bufsize, "%s", propname);
		break;
	case IPADM_PROPFIELD_PERM:
		print_prop(statep, IPADM_OPT_PERM, buf, bufsize);
		break;
	case IPADM_PROPFIELD_CURRENT:
		print_prop(statep, IPADM_OPT_ACTIVE, buf, bufsize);
		break;
	case IPADM_PROPFIELD_PERSISTENT:
		print_prop(statep, IPADM_OPT_PERSIST, buf, bufsize);
		break;
	case IPADM_PROPFIELD_DEFAULT:
		print_prop(statep, IPADM_OPT_DEFAULT, buf, bufsize);
		break;
	case IPADM_PROPFIELD_POSSIBLE:
		print_prop(statep, IPADM_OPT_POSSIBLE, buf, bufsize);
		break;
	}
	if (statep->sps_status != IPADM_SUCCESS)
		cont = _B_FALSE;
	return (cont);
}

/*
 * Callback function called by the property walker (ipadm_walk_prop() or
 * ipadm_walk_proptbl()), for every matched property. This function in turn
 * calls ofmt_print() to print property information.
 */
boolean_t
show_property(void *arg, const char *pname, uint_t proto)
{
	show_prop_state_t	*statep = arg;

	statep->sps_pname = pname;
	statep->sps_proto = proto;
	statep->sps_status = IPADM_SUCCESS;
	ofmt_print(statep->sps_ofmt, arg);

	/*
	 * if an object is not found or operation is not supported then
	 * stop the walker.
	 */
	if (statep->sps_status == IPADM_NOTFOUND ||
	    statep->sps_status == IPADM_NOTSUP)
		return (_B_FALSE);
	return (_B_TRUE);
}

/*
 * Properties to be displayed is in `statep->sps_proplist'. If it is NULL,
 * for all the properties for the specified object, relavant information, will
 * be displayed. Otherwise, for the selected property set, display relevant
 * information
 */
static void
show_properties(void *arg, int prop_class)
{
	show_prop_state_t	*statep = arg;
	nvlist_t 		*nvl = statep->sps_proplist;
	uint_t			proto = statep->sps_proto;
	nvpair_t		*curr_nvp;
	char 			*buf, *name;
	ipadm_status_t		status;

	/* allocate sufficient buffer to hold a property value */
	if ((buf = malloc(MAXPROPVALLEN)) == NULL)
		die("insufficient memory");
	statep->sps_propval = buf;

	/* if no properties were specified, display all the properties */
	if (nvl == NULL) {
		(void) ipadm_walk_proptbl(proto, prop_class, show_property,
		    statep);
	} else {
		for (curr_nvp = nvlist_next_nvpair(nvl, NULL); curr_nvp;
		    curr_nvp = nvlist_next_nvpair(nvl, curr_nvp)) {
			name = nvpair_name(curr_nvp);
			status = ipadm_walk_prop(name, proto, prop_class,
			    show_property, statep);
			if (status == IPADM_PROP_UNKNOWN)
				(void) show_property(statep, name, proto);
		}
	}

	free(buf);
}

/*
 * Display information for all or specific interface properties, either for a
 * given interface or for all the interfaces in the system.
 */
static void
do_show_ifprop(int argc, char **argv, const char *use)
{
	int 		option;
	nvlist_t 	*proplist = NULL;
	char		*fields_str = NULL;
	char 		*ifname;
	ofmt_handle_t	ofmt;
	ofmt_status_t	oferr;
	uint_t		ofmtflags = 0;
	uint_t		proto;
	boolean_t	m_arg = _B_FALSE;
	char		*protostr;
	ipadm_if_info_t	*ifinfo, *ifp;
	ipadm_status_t	status;
	show_prop_state_t state;

	opterr = 0;
	bzero(&state, sizeof (state));
	state.sps_propval = NULL;
	state.sps_parsable = _B_FALSE;
	state.sps_ifprop = _B_TRUE;
	state.sps_status = state.sps_retstatus = IPADM_SUCCESS;
	while ((option = getopt_long(argc, argv, ":p:m:co:",
	    show_ifprop_longopts, NULL)) != -1) {
		switch (option) {
		case 'p':
			if (ipadm_str2nvlist(optarg, &proplist,
			    IPADM_NORVAL) != 0)
				die("invalid interface properties specified");
			break;
		case 'c':
			state.sps_parsable = _B_TRUE;
			break;
		case 'o':
			fields_str = optarg;
			break;
		case 'm':
			if (m_arg)
				die("cannot specify more than one -m");
			m_arg = _B_TRUE;
			protostr = optarg;
			break;
		default:
			die_opterr(optopt, option, use);
			break;
		}
	}

	if (optind == argc - 1)
		ifname = argv[optind];
	else if (optind != argc)
		die("Usage: %s", use);
	else
		ifname = NULL;

	if (!m_arg)
		protostr = "ip";
	if ((proto = ipadm_str2proto(protostr)) == MOD_PROTO_NONE)
		die("invalid protocol '%s' specified", protostr);

	state.sps_proto = proto;
	state.sps_proplist = proplist;

	if (state.sps_parsable)
		ofmtflags |= OFMT_PARSABLE;
	oferr = ofmt_open(fields_str, intfprop_fields, ofmtflags, 0, &ofmt);
	ipadm_ofmt_check(oferr, state.sps_parsable, ofmt);
	state.sps_ofmt = ofmt;

	/* retrieve interface(s) and print the properties */
	status = ipadm_if_info(iph, ifname, &ifinfo, 0, LIFC_DEFAULT);
	if (ifname != NULL && status == IPADM_ENXIO)
		die("no such object '%s': %s", ifname,
		    ipadm_status2str(status));
	if (status != IPADM_SUCCESS)
		die("Error retrieving interface(s): %s",
		    ipadm_status2str(status));
	for (ifp = ifinfo; ifp; ifp = ifp->ifi_next) {
		(void) strlcpy(state.sps_ifname, ifp->ifi_name, LIFNAMSIZ);
		state.sps_proto = proto;
		show_properties(&state, IPADMPROP_CLASS_IF);
	}
	if (ifinfo)
		ipadm_free_if_info(ifinfo);

	nvlist_free(proplist);
	ofmt_close(ofmt);

	if (state.sps_retstatus != IPADM_SUCCESS) {
		ipadm_close(iph);
		exit(EXIT_FAILURE);
	}
}

/*
 * set/reset the interface property for a given interface.
 */
static void
set_ifprop(int argc, char **argv, boolean_t reset, const char *use)
{
	int 			option;
	ipadm_status_t 		status = IPADM_SUCCESS;
	boolean_t 		p_arg = _B_FALSE;
	boolean_t		m_arg = _B_FALSE;
	char 			*ifname, *nv, *protostr;
	char			*prop_name, *prop_val;
	uint_t			flags = IPADM_OPT_PERSIST;
	uint_t			proto;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":m:p:t",
	    set_ifprop_longopts, NULL)) != -1) {
		switch (option) {
		case 'p':
			if (p_arg)
				die("-p must be specified once only");
			p_arg = _B_TRUE;

			ipadm_check_propstr(optarg, reset, use);
			nv = optarg;
			break;
		case 'm':
			if (m_arg)
				die("-m must be specified once only");
			m_arg = _B_TRUE;
			protostr = optarg;
			break;
		case 't':
			flags &= ~IPADM_OPT_PERSIST;
			break;
		default:
			die_opterr(optopt, option, use);
		}
	}

	if (!m_arg || !p_arg || optind != argc - 1)
		die("Usage: %s", use);

	ifname = argv[optind];

	prop_name = nv;
	prop_val = strchr(nv, '=');
	if (prop_val != NULL)
		*prop_val++ = '\0';

	if ((proto = ipadm_str2proto(protostr)) == MOD_PROTO_NONE)
		die("invalid protocol '%s' specified", protostr);

	if (reset)
		flags |= IPADM_OPT_DEFAULT;
	else
		flags |= IPADM_OPT_ACTIVE;
	status = ipadm_set_ifprop(iph, ifname, prop_name, prop_val, proto,
	    flags);

done:
	if (status != IPADM_SUCCESS) {
		if (reset)
			die("reset-ifprop: %s: %s",
			    prop_name, ipadm_status2str(status));
		else
			die("set-ifprop: %s: %s",
			    prop_name, ipadm_status2str(status));
	}
}

static void
do_set_ifprop(int argc, char **argv, const char *use)
{
	set_ifprop(argc, argv, _B_FALSE, use);
}

static void
do_reset_ifprop(int argc, char **argv, const char *use)
{
	set_ifprop(argc, argv, _B_TRUE, use);
}

/*
 * Display information for all or specific protocol properties, either for a
 * given protocol or for supported protocols (IP/IPv4/IPv6/TCP/UDP/SCTP)
 */
static void
do_show_prop(int argc, char **argv, const char *use)
{
	char 			option;
	nvlist_t 		*proplist = NULL;
	char			*fields_str = NULL;
	char 			*protostr;
	show_prop_state_t 	state;
	ofmt_handle_t		ofmt;
	ofmt_status_t		oferr;
	uint_t			ofmtflags = 0;
	uint_t			proto;
	boolean_t		p_arg = _B_FALSE;

	opterr = 0;
	bzero(&state, sizeof (state));
	state.sps_propval = NULL;
	state.sps_parsable = _B_FALSE;
	state.sps_modprop = _B_TRUE;
	state.sps_status = state.sps_retstatus = IPADM_SUCCESS;
	while ((option = getopt_long(argc, argv, ":p:co:", show_prop_longopts,
	    NULL)) != -1) {
		switch (option) {
		case 'p':
			if (p_arg)
				die("-p must be specified once only");
			p_arg = _B_TRUE;
			if (ipadm_str2nvlist(optarg, &proplist,
			    IPADM_NORVAL) != 0)
				die("invalid protocol properties specified");
			break;
		case 'c':
			state.sps_parsable = _B_TRUE;
			break;
		case 'o':
			fields_str = optarg;
			break;
		default:
			die_opterr(optopt, option, use);
			break;
		}
	}
	if (optind == argc - 1) {
		protostr =  argv[optind];
		if ((proto = ipadm_str2proto(protostr)) == MOD_PROTO_NONE)
			die("invalid protocol '%s' specified", protostr);
		state.sps_proto = proto;
	} else if (optind != argc) {
		die("Usage: %s", use);
	} else {
		if (p_arg)
			die("protocol must be specified when "
			    "property name is used");
		state.sps_proto = MOD_PROTO_NONE;
	}

	state.sps_proplist = proplist;

	if (state.sps_parsable)
		ofmtflags |= OFMT_PARSABLE;
	else
		ofmtflags |= OFMT_WRAP;
	oferr = ofmt_open(fields_str, modprop_fields, ofmtflags, 0, &ofmt);
	ipadm_ofmt_check(oferr, state.sps_parsable, ofmt);
	state.sps_ofmt = ofmt;

	/* handles all the errors */
	show_properties(&state, IPADMPROP_CLASS_MODULE);

	nvlist_free(proplist);
	ofmt_close(ofmt);

	if (state.sps_retstatus != IPADM_SUCCESS) {
		ipadm_close(iph);
		exit(EXIT_FAILURE);
	}
}

/*
 * Checks to see if there are any modifiers, + or -. If there are modifiers
 * then sets IPADM_OPT_APPEND or IPADM_OPT_REMOVE, accordingly.
 */
static void
parse_modifiers(const char *pstr, uint_t *flags, const char *use)
{
	char *p;

	if ((p = strchr(pstr, '=')) == NULL)
		return;

	if (p == pstr)
		die("Invalid prop=val specified\n%s", use);

	--p;
	if (*p == '+')
		*flags |= IPADM_OPT_APPEND;
	else if (*p == '-')
		*flags |= IPADM_OPT_REMOVE;
}

/*
 * set/reset the protocol property for a given protocol.
 */
static void
set_prop(int argc, char **argv, boolean_t reset, const char *use)
{
	int 			option;
	ipadm_status_t 		status = IPADM_SUCCESS;
	char 			*protostr, *nv, *prop_name, *prop_val;
	boolean_t 		p_arg = _B_FALSE;
	uint_t 			proto;
	uint_t			flags = IPADM_OPT_PERSIST;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":p:t", set_prop_longopts,
	    NULL)) != -1) {
		switch (option) {
		case 'p':
			if (p_arg)
				die("-p must be specified once only");
			p_arg = _B_TRUE;

			ipadm_check_propstr(optarg, reset, use);
			nv = optarg;
			break;
		case 't':
			flags &= ~IPADM_OPT_PERSIST;
			break;
		default:
			die_opterr(optopt, option, use);
		}
	}

	if (!p_arg || optind != argc - 1)
		die("Usage: %s", use);

	parse_modifiers(nv, &flags, use);
	prop_name = nv;
	prop_val = strchr(nv, '=');
	if (prop_val != NULL) {
		if (flags & (IPADM_OPT_APPEND|IPADM_OPT_REMOVE))
			*(prop_val - 1) = '\0';
		*prop_val++ = '\0';
	}
	protostr = argv[optind];
	if ((proto = ipadm_str2proto(protostr)) == MOD_PROTO_NONE)
		die("invalid protocol '%s' specified", protostr);

	if (reset)
		flags |= IPADM_OPT_DEFAULT;
	else
		flags |= IPADM_OPT_ACTIVE;
	status = ipadm_set_prop(iph, prop_name, prop_val, proto, flags);
done:
	if (status != IPADM_SUCCESS) {
		if (reset)
			die("reset-prop: %s: %s",
			    prop_name, ipadm_status2str(status));
		else
			die("set-prop: %s: %s",
			    prop_name, ipadm_status2str(status));
	}
}

static void
do_set_prop(int argc, char **argv, const char *use)
{
	set_prop(argc, argv, _B_FALSE, use);
}

static void
do_reset_prop(int argc, char **argv, const char *use)
{
	set_prop(argc, argv,  _B_TRUE, use);
}

/* PRINTFLIKE1 */
static void
warn(const char *format, ...)
{
	va_list alist;

	format = gettext(format);
	(void) fprintf(stderr, gettext("%s: warning: "), progname);

	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);

	(void) fprintf(stderr, "\n");
}

/* PRINTFLIKE1 */
static void
die(const char *format, ...)
{
	va_list alist;

	format = gettext(format);
	(void) fprintf(stderr, "%s: ", progname);

	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);

	(void) putchar('\n');

	ipadm_destroy_addrobj(ipaddr);
	ipadm_close(iph);
	exit(EXIT_FAILURE);
}

static void
die_opterr(int opt, int opterr, const char *usage)
{
	switch (opterr) {
	case ':':
		die("option '-%c' requires a value\nusage: %s", opt,
		    gettext(usage));
		break;
	case '?':
	default:
		die("unrecognized option '-%c'\nusage: %s", opt,
		    gettext(usage));
		break;
	}
}

/* PRINTFLIKE2 */
static void
warn_ipadmerr(ipadm_status_t err, const char *format, ...)
{
	va_list alist;

	format = gettext(format);
	(void) fprintf(stderr, gettext("%s: warning: "), progname);

	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);

	(void) fprintf(stderr, "%s\n", ipadm_status2str(err));
}

static void
process_static_addrargs(const char *use, char *addrarg, const char *aobjname)
{
	int		option;
	char		*val;
	char		*laddr = NULL;
	char		*raddr = NULL;
	char		*save_input_arg = addrarg;
	boolean_t	found_mismatch = _B_FALSE;
	ipadm_status_t	status;
	enum		{ A_LOCAL, A_REMOTE };
	static char	*addr_optstr[] = {
		"local",
		"remote",
		NULL,
	};

	while (*addrarg != '\0') {
		option = getsubopt(&addrarg, addr_optstr, &val);
		switch (option) {
		case A_LOCAL:
			if (laddr != NULL)
				die("Multiple local addresses provided");
			laddr = val;
			break;
		case A_REMOTE:
			if (raddr != NULL)
				die("Multiple remote addresses provided");
			raddr = val;
			break;
		default:
			if (found_mismatch)
				die("Invalid address provided\nusage: %s", use);
			found_mismatch = _B_TRUE;
			break;
		}
	}
	if (raddr != NULL && laddr == NULL)
		die("Missing local address\nusage: %s", use);

	/* If only one address is provided, it is assumed a local address. */
	if (laddr == NULL) {
		if (found_mismatch)
			laddr = save_input_arg;
		else
			die("Missing local address\nusage: %s", use);
	}

	/* Initialize the addrobj for static addresses. */
	status = ipadm_create_addrobj(IPADM_ADDR_STATIC, aobjname, &ipaddr);
	if (status != IPADM_SUCCESS) {
		die("Error in creating address object: %s",
		    ipadm_status2str(status));
	}

	/* Set the local and remote addresses */
	status = ipadm_set_addr(ipaddr, laddr, AF_UNSPEC);
	if (status != IPADM_SUCCESS) {
		die("Error in setting local address: %s",
		    ipadm_status2str(status));
	}
	if (raddr != NULL) {
		status = ipadm_set_dst_addr(ipaddr, raddr, AF_UNSPEC);
		if (status != IPADM_SUCCESS) {
			die("Error in setting remote address: %s",
			    ipadm_status2str(status));
		}
	}
}

static void
process_addrconf_addrargs(const char *use, char *addrarg)
{
	int		option;
	char		*val;
	enum		{ P_STATELESS, P_STATEFUL };
	static char	*addr_optstr[] = {
		"stateless",
		"stateful",
		NULL,
	};
	boolean_t	stateless;
	boolean_t	stateless_arg = _B_FALSE;
	boolean_t	stateful;
	boolean_t	stateful_arg = _B_FALSE;
	ipadm_status_t	status;

	while (*addrarg != '\0') {
		option = getsubopt(&addrarg, addr_optstr, &val);
		switch (option) {
		case P_STATELESS:
			if (stateless_arg)
				die("Duplicate option");
			if (val == NULL)
				die("Invalid argument");
			if (strcmp(val, "yes") == 0)
				stateless = _B_TRUE;
			else if (strcmp(val, "no") == 0)
				stateless = _B_FALSE;
			else
				die("Invalid argument");
			stateless_arg = _B_TRUE;
			break;
		case P_STATEFUL:
			if (stateful_arg)
				die("Duplicate option");
			if (val == NULL)
				die("Invalid argument");
			if (strcmp(val, "yes") == 0)
				stateful = _B_TRUE;
			else if (strcmp(val, "no") == 0)
				stateful = _B_FALSE;
			else
				die("Invalid argument");
			stateful_arg = _B_TRUE;
			break;
		default:
			die_opterr(optopt, option, use);
		}
	}

	if (!stateless_arg && !stateful_arg)
		die("Invalid arguments for option -p");

	/* Set the addrobj fields for addrconf */
	if (stateless_arg) {
		status = ipadm_set_stateless(ipaddr, stateless);
		if (status != IPADM_SUCCESS) {
			die("Error in setting stateless option: %s",
			    ipadm_status2str(status));
		}
	}
	if (stateful_arg) {
		status = ipadm_set_stateful(ipaddr, stateful);
		if (status != IPADM_SUCCESS) {
			die("Error in setting stateful option: %s",
			    ipadm_status2str(status));
		}
	}
}

/*
 * Creates static, dhcp or addrconf addresses and associates the created
 * addresses with the specified address object name.
 */
static void
do_create_addr(int argc, char *argv[], const char *use)
{
	ipadm_status_t	status;
	int		option;
	uint32_t	flags =
	    IPADM_OPT_PERSIST|IPADM_OPT_ACTIVE|IPADM_OPT_UP|IPADM_OPT_V46;
	char		*cp;
	char		*atype = NULL;
	char		*static_arg = NULL;
	char		*addrconf_arg = NULL;
	char		*interface_id = NULL;
	char		*wait = NULL;
	boolean_t	s_opt = _B_FALSE;	/* static addr options */
	boolean_t	auto_opt = _B_FALSE;	/* Addrconf options */
	boolean_t	dhcp_opt = _B_FALSE;	/* dhcp options */

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":T:a:di:p:w:t",
	    addr_longopts, NULL)) != -1) {
		switch (option) {
		case 'T':
			atype = optarg;
			break;
		case 'a':
			static_arg = optarg;
			s_opt = _B_TRUE;
			break;
		case 'd':
			flags &= ~IPADM_OPT_UP;
			s_opt = _B_TRUE;
			break;
		case 'i':
			interface_id = optarg;
			auto_opt = _B_TRUE;
			break;
		case 'p':
			addrconf_arg = optarg;
			auto_opt = _B_TRUE;
			break;
		case 'w':
			wait = optarg;
			dhcp_opt = _B_TRUE;
			break;
		case 't':
			flags &= ~IPADM_OPT_PERSIST;
			break;
		default:
			die_opterr(optopt, option, use);
		}
	}
	if (atype == NULL || optind != (argc - 1)) {
		die("Invalid arguments\nusage: %s", use);
	} else if ((cp = strchr(argv[optind], '/')) == NULL ||
	    strlen(++cp) == 0) {
		die("invalid address object name: %s\nusage: %s",
		    argv[optind], use);
	}

	/*
	 * Allocate and initialize the addrobj based on the address type.
	 */
	if (strcmp(atype, "static") == 0) {
		if (static_arg == NULL || auto_opt || dhcp_opt) {
			die("Invalid arguments for type %s\nusage: %s",
			    atype, use);
		}
		process_static_addrargs(use, static_arg, argv[optind]);
	} else if (strcmp(atype, "dhcp") == 0) {
		if (auto_opt || s_opt) {
			die("Invalid arguments for type %s\nusage: %s",
			    atype, use);
		}

		/* Initialize the addrobj for dhcp addresses. */
		status = ipadm_create_addrobj(IPADM_ADDR_DHCP, argv[optind],
		    &ipaddr);
		if (status != IPADM_SUCCESS) {
			die("Error in creating address object: %s",
			    ipadm_status2str(status));
		}
		if (wait != NULL) {
			int32_t ipadm_wait;

			if (strcmp(wait, "forever") == 0) {
				ipadm_wait = IPADM_DHCP_WAIT_FOREVER;
			} else {
				char *end;
				long timeout = strtol(wait, &end, 10);

				if (*end != '\0' || timeout < 0)
					die("Invalid argument");
				ipadm_wait = (int32_t)timeout;
			}
			status = ipadm_set_wait_time(ipaddr, ipadm_wait);
			if (status != IPADM_SUCCESS) {
				die("Error in setting wait time: %s",
				    ipadm_status2str(status));
			}
		}
	} else if (strcmp(atype, "addrconf") == 0) {
		if (dhcp_opt || s_opt) {
			die("Invalid arguments for type %s\nusage: %s",
			    atype, use);
		}

		/* Initialize the addrobj for dhcp addresses. */
		status = ipadm_create_addrobj(IPADM_ADDR_IPV6_ADDRCONF,
		    argv[optind], &ipaddr);
		if (status != IPADM_SUCCESS) {
			die("Error in creating address object: %s",
			    ipadm_status2str(status));
		}
		if (interface_id != NULL) {
			status = ipadm_set_interface_id(ipaddr, interface_id);
			if (status != IPADM_SUCCESS) {
				die("Error in setting interface ID: %s",
				    ipadm_status2str(status));
			}
		}
		if (addrconf_arg)
			process_addrconf_addrargs(use, addrconf_arg);
	} else {
		die("Invalid address type %s", atype);
	}

	status = ipadm_create_addr(iph, ipaddr, flags);
	if (status == IPADM_DHCP_IPC_TIMEOUT)
		warn_ipadmerr(status, "");
	else if (status != IPADM_SUCCESS)
		die("Could not create address: %s", ipadm_status2str(status));
}

/*
 * Used by some address management functions to parse the command line
 * arguments and create `ipaddr' address object.
 */
static void
process_misc_addrargs(int argc, char *argv[], const char *use, int *index,
    uint32_t *flags)
{
	int		option;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":t", addr_misc_longopts,
	    NULL)) != -1) {
		switch (option) {
		case 't':
			*flags &= ~IPADM_OPT_PERSIST;
			break;
		default:
			die_opterr(optopt, option, use);
		}
	}
	if (optind != (argc - 1))
		die("Usage: %s", use);

	*index = optind;
}

/*
 * Remove an addrobj from both active and persistent configuration.
 */
static void
do_delete_addr(int argc, char *argv[], const char *use)
{
	ipadm_status_t	status;
	uint32_t 	flags = IPADM_OPT_ACTIVE|IPADM_OPT_PERSIST;
	int		option;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":r", addr_misc_longopts,
	    NULL)) != -1) {
		switch (option) {
		case 'r':
			flags |= IPADM_OPT_RELEASE;
			break;
		default:
			die_opterr(optopt, option, use);
		}
	}
	if (optind != (argc - 1))
		die("Usage: %s", use);

	status = ipadm_delete_addr(iph, argv[optind], flags);
	if (status != IPADM_SUCCESS) {
		die("could not delete address: %s",
		    ipadm_status2str(status));
	}
}

/*
 * Enable an IP address based on the persistent configuration for that
 * IP address
 */
static void
do_enable_addr(int argc, char *argv[], const char *use)
{
	ipadm_status_t	status;
	int		index;
	uint32_t 	flags = IPADM_OPT_ACTIVE|IPADM_OPT_PERSIST;

	process_misc_addrargs(argc, argv, use, &index, &flags);
	if (flags & IPADM_OPT_PERSIST)
		die("persistent operation not supported for enable-addr");

	status = ipadm_enable_addr(iph, argv[index], flags);
	if (status != IPADM_SUCCESS)
		die("could not enable address: %s", ipadm_status2str(status));
}

/*
 * Mark the address identified by addrobj 'up'
 */
static void
do_up_addr(int argc, char *argv[], const char *use)
{
	ipadm_status_t	status;
	int		index;
	uint32_t 	flags = IPADM_OPT_ACTIVE|IPADM_OPT_PERSIST;

	process_misc_addrargs(argc, argv, use, &index, &flags);
	status = ipadm_up_addr(iph, argv[index], flags);
	if (status != IPADM_SUCCESS) {
		die("Could not mark the address up: %s",
		    ipadm_status2str(status));
	}
}

/*
 * Disable the specified addrobj by removing it from active cofiguration
 */
static void
do_disable_addr(int argc, char *argv[], const char *use)
{
	ipadm_status_t	status;
	int		index;
	uint32_t 	flags = IPADM_OPT_ACTIVE|IPADM_OPT_PERSIST;

	process_misc_addrargs(argc, argv, use, &index, &flags);
	if (flags & IPADM_OPT_PERSIST)
		die("persistent operation not supported for disable-addr");

	status = ipadm_disable_addr(iph, argv[index], flags);
	if (status != IPADM_SUCCESS) {
		die("could not disable address: %s",
		    ipadm_status2str(status));
	}
}

/*
 * Mark the address identified by addrobj 'down'
 */
static void
do_down_addr(int argc, char *argv[], const char *use)
{
	ipadm_status_t	status;
	int		index;
	uint32_t 	flags = IPADM_OPT_ACTIVE|IPADM_OPT_PERSIST;

	process_misc_addrargs(argc, argv, use, &index, &flags);
	status = ipadm_down_addr(iph, argv[index], flags);
	if (status != IPADM_SUCCESS)
		die("Could not mark the address down: %s",
		    ipadm_status2str(status));
}

/*
 * Restart DAD for static address. Extend lease duration for DHCP addresses
 */
static void
do_refresh_addr(int argc, char *argv[], const char *use)
{
	ipadm_status_t	status;
	int		option;
	uint32_t	flags = 0;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":i", addr_misc_longopts,
	    NULL)) != -1) {
		switch (option) {
		case 'i':
			flags |= IPADM_OPT_INFORM;
			break;
		default:
			die_opterr(optopt, option, use);
		}
	}
	if (optind != (argc - 1))
		die("Usage: %s", use);

	status = ipadm_refresh_addr(iph, argv[optind], flags);
	if (status == IPADM_DHCP_IPC_TIMEOUT)
		warn_ipadmerr(status, "");
	else if (status != IPADM_SUCCESS)
		die("could not refresh address %s", ipadm_status2str(status));
}

static void
sockaddr2str(const struct sockaddr_storage *ssp, char *buf, uint_t bufsize)
{
	socklen_t socklen;
	struct sockaddr *sp = (struct sockaddr *)ssp;

	switch (ssp->ss_family) {
	case AF_INET:
		socklen = sizeof (struct sockaddr_in);
		break;
	case AF_INET6:
		socklen = sizeof (struct sockaddr_in6);
		break;
	default:
		(void) strlcpy(buf, STR_UNKNOWN_VAL, bufsize);
		return;
	}

	(void) getnameinfo(sp, socklen, buf, bufsize, NULL, 0,
	    (NI_NOFQDN | NI_NUMERICHOST));
}

static void
flags2str(uint64_t flags, fmask_t *tbl, boolean_t is_bits,
    char *buf, uint_t bufsize)
{
	int		i;
	boolean_t	first = _B_TRUE;

	if (is_bits) {
		for (i = 0;  tbl[i].name; i++) {
			if ((flags & tbl[i].mask) == tbl[i].bits)
				(void) strlcat(buf, tbl[i].name, bufsize);
			else
				(void) strlcat(buf, "-", bufsize);
		}
	} else {
		for (i = 0; tbl[i].name; i++) {
			if ((flags & tbl[i].mask) == tbl[i].bits) {
				if (!first)
					(void) strlcat(buf, ",", bufsize);
				(void) strlcat(buf, tbl[i].name, bufsize);
				first = _B_FALSE;
			}
		}
	}
}

/*
 * return true if the address for lifname comes to us from the global zone
 * with 'allowed-ips' constraints.
 */
static boolean_t
is_from_gz(const char *lifname)
{
	ipadm_if_info_t		*if_info;
	char			phyname[LIFNAMSIZ], *cp;
	boolean_t		ret = _B_FALSE;
	ipadm_status_t		status;
	zoneid_t		zoneid;
	ushort_t		zflags;

	if ((zoneid = getzoneid()) == GLOBAL_ZONEID)
		return (_B_FALSE); /* from-gz only  makes sense in a NGZ */

	if (zone_getattr(zoneid, ZONE_ATTR_FLAGS, &zflags, sizeof (zflags)) < 0)
		return (_B_FALSE);

	if (!(zflags & ZF_NET_EXCL))
		return (_B_TRUE);  /* everything is from the GZ for shared-ip */

	(void) strncpy(phyname, lifname, sizeof (phyname));
	if ((cp = strchr(phyname, ':')) != NULL)
		*cp = '\0';
	status = ipadm_if_info(iph, phyname, &if_info, 0, LIFC_DEFAULT);
	if (status != IPADM_SUCCESS)
		return (ret);

	if (if_info->ifi_cflags & IFIF_L3PROTECT)
		ret = _B_TRUE;
	if (if_info)
		ipadm_free_if_info(if_info);
	return (ret);
}

static boolean_t
print_sa_cb(ofmt_arg_t *ofarg, char *buf, uint_t bufsize)
{
	show_addr_args_t	*arg = ofarg->ofmt_cbarg;
	ipadm_addr_info_t	*ainfo = arg->sa_info;
	char			interface[LIFNAMSIZ];
	char			addrbuf[MAXPROPVALLEN];
	char			dstbuf[MAXPROPVALLEN];
	char			prefixlenstr[MAXPROPVALLEN];
	int			prefixlen;
	struct sockaddr_in	*sin;
	struct sockaddr_in6	*sin6;
	sa_family_t		af;
	char			*phyname = NULL;
	struct ifaddrs		*ifa = &ainfo->ia_ifa;
	fmask_t cflags_mask[] = {
		{ "U",	IA_UP,			IA_UP		},
		{ "u",	IA_UNNUMBERED,		IA_UNNUMBERED	},
		{ "p",	IA_PRIVATE,		IA_PRIVATE	},
		{ "t",	IA_TEMPORARY,		IA_TEMPORARY	},
		{ "d",	IA_DEPRECATED,		IA_DEPRECATED	},
		{ NULL,		0,			0	}
	};
	fmask_t pflags_mask[] = {
		{ "U",	IA_UP,			IA_UP		},
		{ "p",	IA_PRIVATE,		IA_PRIVATE	},
		{ "d",	IA_DEPRECATED,		IA_DEPRECATED	},
		{ NULL,		0,			0	}
	};
	fmask_t type[] = {
		{ "static",	IPADM_ADDR_STATIC,	IPADM_ALL_BITS},
		{ "addrconf",	IPADM_ADDR_IPV6_ADDRCONF, IPADM_ALL_BITS},
		{ "dhcp",	IPADM_ADDR_DHCP,	IPADM_ALL_BITS},
		{ NULL,		0,			0	}
	};
	fmask_t addr_state[] = {
		{ "disabled",	IFA_DISABLED,	IPADM_ALL_BITS},
		{ "duplicate",	IFA_DUPLICATE,	IPADM_ALL_BITS},
		{ "down",	IFA_DOWN,	IPADM_ALL_BITS},
		{ "tentative",	IFA_TENTATIVE,	IPADM_ALL_BITS},
		{ "ok",		IFA_OK,		IPADM_ALL_BITS},
		{ "inaccessible", IFA_INACCESSIBLE, IPADM_ALL_BITS},
		{ NULL,		0,		0	}
	};

	buf[0] = '\0';
	switch (ofarg->ofmt_id) {
	case SA_ADDROBJ:
		if (ainfo->ia_aobjname[0] == '\0') {
			(void) strncpy(interface, ifa->ifa_name, LIFNAMSIZ);
			phyname = strrchr(interface, ':');
			if (phyname)
				*phyname = '\0';
			(void) snprintf(buf, bufsize, "%s/%s", interface,
			    STR_UNKNOWN_VAL);
		} else {
			(void) snprintf(buf, bufsize, "%s", ainfo->ia_aobjname);
		}
		break;
	case SA_STATE:
		flags2str(ainfo->ia_state, addr_state, _B_FALSE,
		    buf, bufsize);
		break;
	case SA_TYPE:
		if (is_from_gz(ifa->ifa_name))
			(void) snprintf(buf, bufsize, "from-gz");
		else
			flags2str(ainfo->ia_atype, type, _B_FALSE, buf,
			    bufsize);
		break;
	case SA_CURRENT:
		flags2str(ainfo->ia_cflags, cflags_mask, _B_TRUE, buf, bufsize);
		break;
	case SA_PERSISTENT:
		flags2str(ainfo->ia_pflags, pflags_mask, _B_TRUE, buf, bufsize);
		break;
	case SA_ADDR:
		af = ifa->ifa_addr->sa_family;
		/*
		 * If the address is 0.0.0.0 or :: and the origin is DHCP,
		 * print STR_UNKNOWN_VAL.
		 */
		if (ainfo->ia_atype == IPADM_ADDR_DHCP) {
			sin = (struct sockaddr_in *)ifa->ifa_addr;
			sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
			if ((af == AF_INET &&
			    sin->sin_addr.s_addr == INADDR_ANY) ||
			    (af == AF_INET6 &&
			    IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr))) {
				(void) snprintf(buf, bufsize, STR_UNKNOWN_VAL);
				break;
			}
		}
		if (ifa->ifa_netmask == NULL)
			prefixlen = 0;
		else
			prefixlen = mask2plen(ifa->ifa_netmask);
		bzero(prefixlenstr, sizeof (prefixlenstr));
		if (prefixlen > 0) {
			(void) snprintf(prefixlenstr, sizeof (prefixlenstr),
			    "/%d", prefixlen);
		}
		bzero(addrbuf, sizeof (addrbuf));
		bzero(dstbuf, sizeof (dstbuf));
		if (ainfo->ia_atype == IPADM_ADDR_STATIC) {
			/*
			 * Print the hostname fields if the address is not
			 * in active configuration.
			 */
			if (ainfo->ia_state == IFA_DISABLED) {
				(void) snprintf(buf, bufsize, "%s",
				    ainfo->ia_sname);
				if (ainfo->ia_dname[0] != '\0') {
					(void) snprintf(dstbuf, sizeof (dstbuf),
					    "->%s", ainfo->ia_dname);
					(void) strlcat(buf, dstbuf, bufsize);
				} else {
					(void) strlcat(buf, prefixlenstr,
					    bufsize);
				}
				break;
			}
		}
		/*
		 * For the non-persistent case, we need to show the
		 * currently configured addresses for source and
		 * destination.
		 */
		sockaddr2str((struct sockaddr_storage *)ifa->ifa_addr,
		    addrbuf, sizeof (addrbuf));
		if (ifa->ifa_flags & IFF_POINTOPOINT) {
			sockaddr2str(
			    (struct sockaddr_storage *)ifa->ifa_dstaddr,
			    dstbuf, sizeof (dstbuf));
			(void) snprintf(buf, bufsize, "%s->%s", addrbuf,
			    dstbuf);
		} else {
			(void) snprintf(buf, bufsize, "%s%s", addrbuf,
			    prefixlenstr);
		}
		break;
	default:
		die("invalid input");
		break;
	}

	return (_B_TRUE);
}

/*
 * Display address information, either for the given address or
 * for all the addresses managed by ipadm.
 */
static void
do_show_addr(int argc, char *argv[], const char *use)
{
	ipadm_status_t		status;
	show_addr_state_t	state;
	char			*def_fields_str = "addrobj,type,state,addr";
	char			*fields_str = NULL;
	ipadm_addr_info_t	*ainfo;
	ipadm_addr_info_t	*ptr;
	show_addr_args_t	sargs;
	int			option;
	ofmt_handle_t		ofmt;
	ofmt_status_t		oferr;
	uint_t			ofmtflags = 0;
	char			*aname;
	char			*ifname = NULL;
	char			*cp;
	boolean_t		found = _B_FALSE;

	opterr = 0;
	state.sa_parsable = _B_FALSE;
	state.sa_persist = _B_FALSE;
	while ((option = getopt_long(argc, argv, "po:", show_addr_longopts,
	    NULL)) != -1) {
		switch (option) {
		case 'p':
			state.sa_parsable = _B_TRUE;
			break;
		case 'o':
			fields_str = optarg;
			break;
		default:
			die_opterr(optopt, option, use);
			break;
		}
	}
	if (state.sa_parsable && fields_str == NULL)
		die("-p requires -o");

	if (optind == argc - 1) {
		aname = argv[optind];
		if ((cp = strchr(aname, '/')) == NULL)
			die("Invalid address object name provided");
		if (*(cp + 1) == '\0') {
			ifname = aname;
			*cp = '\0';
			aname = NULL;
		}
	} else if (optind == argc) {
		aname = NULL;
	} else {
		die("Usage: %s", use);
	}

	if (state.sa_parsable)
		ofmtflags |= OFMT_PARSABLE;
	if (fields_str == NULL)
		fields_str = def_fields_str;
	oferr = ofmt_open(fields_str, show_addr_fields, ofmtflags, 0, &ofmt);

	ipadm_ofmt_check(oferr, state.sa_parsable, ofmt);
	state.sa_ofmt = ofmt;

	status = ipadm_addr_info(iph, ifname, &ainfo, 0, LIFC_DEFAULT);
	/*
	 * Return without printing any error, if no addresses were found,
	 * for the case where all addresses are requested.
	 */
	if (status != IPADM_SUCCESS)
		die("Could not get address: %s", ipadm_status2str(status));
	if (ainfo == NULL) {
		ofmt_close(ofmt);
		return;
	}

	bzero(&sargs, sizeof (sargs));
	sargs.sa_state = &state;
	for (ptr = ainfo; ptr != NULL; ptr = IA_NEXT(ptr)) {
		sargs.sa_info = ptr;
		if (aname != NULL) {
			if (strcmp(sargs.sa_info->ia_aobjname, aname) != 0)
				continue;
			found = _B_TRUE;
		}
		ofmt_print(state.sa_ofmt, &sargs);
	}
	if (ainfo)
		ipadm_free_addr_info(ainfo);
	if (aname != NULL && !found)
		die("Address object not found");
}

static boolean_t
print_si_cb(ofmt_arg_t *ofarg, char *buf, uint_t bufsize)
{
	show_if_args_t		*arg = ofarg->ofmt_cbarg;
	ipadm_if_info_t		*ifinfo = arg->si_info;
	char			*ifname = ifinfo->ifi_name;
	fmask_t intf_state[] = {
		{ "ok",		IFIS_OK,	IPADM_ALL_BITS},
		{ "down",	IFIS_DOWN,	IPADM_ALL_BITS},
		{ "disabled",	IFIS_DISABLED,	IPADM_ALL_BITS},
		{ "failed",	IFIS_FAILED,	IPADM_ALL_BITS},
		{ "offline",	IFIS_OFFLINE,	IPADM_ALL_BITS},
		{ NULL,		0,		0	}
	};
	fmask_t intf_pflags[] = {
		{ "s",	IFIF_STANDBY,		IFIF_STANDBY	},
		{ "4",	IFIF_IPV4,		IFIF_IPV4	},
		{ "6",	IFIF_IPV6,		IFIF_IPV6	},
		{ NULL,	0,			0		}
	};
	fmask_t intf_cflags[] = {
		{ "b",	IFIF_BROADCAST,		IFIF_BROADCAST	},
		{ "m",	IFIF_MULTICAST,		IFIF_MULTICAST	},
		{ "p",	IFIF_POINTOPOINT,	IFIF_POINTOPOINT},
		{ "v",	IFIF_VIRTUAL,		IFIF_VIRTUAL	},
		{ "I",	IFIF_IPMP,		IFIF_IPMP	},
		{ "s",	IFIF_STANDBY,		IFIF_STANDBY	},
		{ "i",	IFIF_INACTIVE,		IFIF_INACTIVE	},
		{ "V",	IFIF_VRRP,		IFIF_VRRP	},
		{ "a",	IFIF_NOACCEPT,		IFIF_NOACCEPT	},
		{ "Z",	IFIF_L3PROTECT,		IFIF_L3PROTECT	},
		{ "4",	IFIF_IPV4,		IFIF_IPV4	},
		{ "6",	IFIF_IPV6,		IFIF_IPV6	},
		{ NULL,	0,			0		}
	};

	buf[0] = '\0';
	switch (ofarg->ofmt_id) {
	case SI_IFNAME:
		(void) snprintf(buf, bufsize, "%s", ifname);
		break;
	case SI_STATE:
		flags2str(ifinfo->ifi_state, intf_state, _B_FALSE,
		    buf, bufsize);
		break;
	case SI_CURRENT:
		flags2str(ifinfo->ifi_cflags, intf_cflags, _B_TRUE,
		    buf, bufsize);
		break;
	case SI_PERSISTENT:
		flags2str(ifinfo->ifi_pflags, intf_pflags, _B_TRUE,
		    buf, bufsize);
		break;
	default:
		die("invalid input");
		break;
	}

	return (_B_TRUE);
}

/*
 * Display interface information, either for the given interface or
 * for all the interfaces in the system.
 */
static void
do_show_if(int argc, char *argv[], const char *use)
{
	ipadm_status_t		status;
	show_if_state_t		state;
	char			*fields_str = NULL;
	ipadm_if_info_t		*if_info, *ptr;
	show_if_args_t		sargs;
	int			option;
	ofmt_handle_t		ofmt;
	ofmt_status_t		oferr;
	uint_t			ofmtflags = 0;
	char			*ifname = NULL;

	opterr = 0;
	state.si_parsable = _B_FALSE;

	while ((option = getopt_long(argc, argv, "po:", show_if_longopts,
	    NULL)) != -1) {
		switch (option) {
		case 'p':
			state.si_parsable = _B_TRUE;
			break;
		case 'o':
			fields_str = optarg;
			break;
		default:
			die_opterr(optopt, option, use);
			break;
		}
	}
	if (optind == argc - 1)
		ifname = argv[optind];
	else if (optind != argc)
		die("Usage: %s", use);
	if (state.si_parsable)
		ofmtflags |= OFMT_PARSABLE;
	oferr = ofmt_open(fields_str, show_if_fields, ofmtflags, 0, &ofmt);
	ipadm_ofmt_check(oferr, state.si_parsable, ofmt);
	state.si_ofmt = ofmt;
	bzero(&sargs, sizeof (sargs));
	sargs.si_state = &state;
	status = ipadm_if_info(iph, ifname, &if_info, 0, LIFC_DEFAULT);
	/*
	 * Return without printing any error, if no addresses were found.
	 */
	if (status != IPADM_SUCCESS) {
		die("Could not get interface(s): %s",
		    ipadm_status2str(status));
	}

	for (ptr = if_info; ptr; ptr = ptr->ifi_next) {
		sargs.si_info = ptr;
		ofmt_print(state.si_ofmt, &sargs);
	}
	if (if_info)
		ipadm_free_if_info(if_info);
}

/*
 * set/reset the address property for a given address
 */
static void
set_addrprop(int argc, char **argv, boolean_t reset, const char *use)
{
	int 			option;
	ipadm_status_t 		status = IPADM_SUCCESS;
	boolean_t 		p_arg = _B_FALSE;
	char 			*nv, *aobjname;
	char			*prop_name, *prop_val;
	uint_t			flags = IPADM_OPT_ACTIVE|IPADM_OPT_PERSIST;

	opterr = 0;
	while ((option = getopt_long(argc, argv, ":i:p:t", set_ifprop_longopts,
	    NULL)) != -1) {
		switch (option) {
		case 'p':
			if (p_arg)
				die("-p must be specified once only");
			p_arg = _B_TRUE;

			ipadm_check_propstr(optarg, reset, use);
			nv = optarg;
			break;
		case 't':
			flags &= ~IPADM_OPT_PERSIST;
			break;
		default:
			die_opterr(optopt, option, use);
		}
	}

	if (!p_arg || optind != (argc - 1))
		die("Usage: %s", use);

	prop_name = nv;
	prop_val = strchr(nv, '=');
	if (prop_val != NULL)
		*prop_val++ = '\0';
	aobjname = argv[optind];
	if (reset)
		flags |= IPADM_OPT_DEFAULT;
	status = ipadm_set_addrprop(iph, prop_name, prop_val, aobjname, flags);
	if (status != IPADM_SUCCESS) {
		if (reset)
			die("reset-addrprop: %s: %s", prop_name,
			    ipadm_status2str(status));
		else
			die("set-addrprop: %s: %s", prop_name,
			    ipadm_status2str(status));
	}
}

/*
 * Sets a property on an address object.
 */
static void
do_set_addrprop(int argc, char **argv, const char *use)
{
	set_addrprop(argc, argv, _B_FALSE, use);
}

/*
 * Resets a property to its default value on an address object.
 */
static void
do_reset_addrprop(int argc, char **argv, const char *use)
{
	set_addrprop(argc, argv,  _B_TRUE, use);
}

/*
 * Display information for all or specific address properties, either for a
 * given address or for all the addresses in the system.
 */
static void
do_show_addrprop(int argc, char *argv[], const char *use)
{
	int 			option;
	nvlist_t 		*proplist = NULL;
	char			*fields_str = NULL;
	show_prop_state_t 	state;
	ofmt_handle_t		ofmt;
	ofmt_status_t		oferr;
	uint_t			ofmtflags = 0;
	char			*aobjname = NULL;
	char			*ifname = NULL;
	char			*cp;
	ipadm_addr_info_t	*ainfop = NULL;
	ipadm_addr_info_t	*ptr;
	ipadm_status_t		status;
	boolean_t		found = _B_FALSE;

	opterr = 0;
	bzero(&state, sizeof (state));
	state.sps_propval = NULL;
	state.sps_parsable = _B_FALSE;
	state.sps_addrprop = _B_TRUE;
	state.sps_proto = MOD_PROTO_NONE;
	state.sps_status = state.sps_retstatus = IPADM_SUCCESS;
	while ((option = getopt_long(argc, argv, ":p:i:cPo:",
	    show_prop_longopts, NULL)) != -1) {
		switch (option) {
		case 'p':
			if (ipadm_str2nvlist(optarg, &proplist,
			    IPADM_NORVAL) != 0)
				die("invalid addrobj properties specified");
			break;
		case 'c':
			state.sps_parsable = _B_TRUE;
			break;
		case 'o':
			fields_str = optarg;
			break;
		default:
			die_opterr(optopt, option, use);
			break;
		}
	}
	if (optind == argc - 1) {
		aobjname = argv[optind];
		cp = strchr(aobjname, '/');
		if (cp == NULL)
			die("invalid addrobj name provided");
		if (*(cp + 1) == '\0') {
			ifname = aobjname;
			*cp = '\0';
			aobjname = NULL;
		}
	} else if (optind != argc) {
		die("Usage: %s", use);
	}
	state.sps_proplist = proplist;
	if (state.sps_parsable)
		ofmtflags |= OFMT_PARSABLE;
	oferr = ofmt_open(fields_str, addrprop_fields, ofmtflags, 0, &ofmt);
	ipadm_ofmt_check(oferr, state.sps_parsable, ofmt);
	state.sps_ofmt = ofmt;

	status = ipadm_addr_info(iph, ifname, &ainfop, 0, LIFC_DEFAULT);
	/* Return without printing any error, if no addresses were found */
	if (status == IPADM_NOTFOUND)
		return;
	if (status != IPADM_SUCCESS)
		die("error retrieving address: %s", ipadm_status2str(status));

	for (ptr = ainfop; ptr != NULL; ptr = IA_NEXT(ptr)) {
		char	*taobjname = ptr->ia_aobjname;

		if (taobjname[0] == '\0')
			continue;
		if (aobjname != NULL) {
			if (strcmp(aobjname, taobjname) == 0)
				found = _B_TRUE;
			else
				continue;
		}
		if (ptr->ia_atype == IPADM_ADDR_IPV6_ADDRCONF) {
			if (found)
				break;
			else
				continue;
		}
		(void) strlcpy(state.sps_aobjname, taobjname,
		    sizeof (state.sps_aobjname));
		show_properties(&state, IPADMPROP_CLASS_ADDR);
		if (found)
			break;
	}
	ipadm_free_addr_info(ainfop);

	if (aobjname != NULL && !found)
		die("addrobj not found: %s", aobjname);

	nvlist_free(proplist);
	ofmt_close(ofmt);
	if (state.sps_retstatus != IPADM_SUCCESS) {
		ipadm_close(iph);
		exit(EXIT_FAILURE);
	}
}

static void
ipadm_ofmt_check(ofmt_status_t oferr, boolean_t parsable,
    ofmt_handle_t ofmt)
{
	char buf[OFMT_BUFSIZE];

	if (oferr == OFMT_SUCCESS)
		return;
	(void) ofmt_strerror(ofmt, oferr, buf, sizeof (buf));
	/*
	 * All errors are considered fatal in parsable mode.
	 * NOMEM errors are always fatal, regardless of mode.
	 * For other errors, we print diagnostics in human-readable
	 * mode and processs what we can.
	 */
	if (parsable || oferr == OFMT_ENOFIELDS) {
		ofmt_close(ofmt);
		die(buf);
	} else {
		warn(buf);
	}
}

/*
 * check if the `pstr' adheres to following syntax
 *	- prop=<value[,...]>	(for set)
 *	- prop			(for reset)
 */
static void
ipadm_check_propstr(const char *pstr, boolean_t reset, const char *use)
{
	char	*nv;

	nv = strchr(pstr, '=');
	if (reset) {
		if (nv != NULL)
			die("incorrect syntax used for -p.\n%s", use);
	} else {
		if (nv == NULL || *++nv == '\0')
			die("please specify the value to be set.\n%s", use);
		nv = strchr(nv, '=');
		/* cannot have multiple 'prop=val' for single -p */
		if (nv != NULL)
			die("cannot specify more than one prop=val at "
			    "a time.\n%s", use);
	}
}
