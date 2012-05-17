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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 Joyent, Inc.  All rights reserved.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <ctype.h>
#include <stropts.h>
#include <errno.h>
#include <libintl.h>
#include <locale.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <inet/ip.h>
#include <inet/nd.h>
#include <net/if.h>
#include <libscf.h>
#include <libscf_priv.h>
#include <libuutil.h>
#include <ifaddrs.h>

/*
 * This program moves routing management under SMF.  We do this by giving
 * routeadm options that allow interaction with SMF services.  These include:
 * - setting the routing services routeadm will enable
 *	# routeadm -s routing-svcs="fmri [fmri...]"
 * where each fmri is an SMF routing service.
 * - changing properties of routing services
 *	# routeadm -m fmri key=value [key=value...]
 * - listing routing daemon properties
 *	# routeadm -l fmri
 * where all properties in the "routing" property group are listed.
 *
 * By providing legacy routing services (legacy-routing:ipv4 and ipv6), we
 * can also support running of routing daemons with no SMF service under SMF.
 * Specifying a routing daemon with no SMF counterpart results in the
 * daemon, it`s arguments and stop command being set in the appropriate instance
 * to be picked up by start/stop methods.
 *
 * Internally, routeadm keeps track of routing services by setting the
 * "current-routing-svc" property to "true" in the services it manages.
 * So for example, running
 *	# routeadm -s routing-svcs="route:default ripng:default"
 * sets this variable in each instance specified. If the user specifies a
 * non-SMF routing daemon via
 * 	# routeadm -s ipv4-routing-daemon=/usr/sbin/mydaemon
 * the variable will be set for the legacy-routing:ipv4 instance.
 *
 * In order to ensure that the SMF versions of routing daemons are used
 * where possible, routeadm will check the daemons specified in
 * ipv4-routing-daemon/ipv6-routing-daemon to determine if there is an
 * SMF counterpart.  If so, rather than running the legacy service
 * we move configuration, specifically the associated daemon arguments
 * to the SMF counterpart.  From there,  when the daemon is enabled,  it
 * will pick up the daemon arguments setting,  transfer the argument string
 * to the appropriate properties and run the service.
 *
 * To support the semantics of routeadm -e (enable at next boot) through SMF,
 * we make use of temporary state changes,  which last only until reboot.
 * For example, if a service is disabled,  and it is to be enabled via
 * routeadm -e,  we simply change the disable to a temporary disable,
 * and set the persistent enabled value to true.  This ensures the daemon
 * will run at next boot,  but not now.  The reverse is true for disabling
 * enabled instances  (and if the daemon is enabled when we issue the enable,
 * we do nothing since it is already in the desired state).
 *
 * Since the code is quite involved,  we provide a guide to the more complex
 * actions taken in response to user commands.
 *
 * routeadm -e[d] ipv4[6]-routing[forwarding]
 *
 * 	In this case,  the goal is to prepare the configured routing daemons
 * 	(specified through routeadm -s routing-svcs="...") or forwarding
 *	services to switch on (-e) or of (-d) at next boot.
 *
 *	Since this operation must be applied to multiple services in the
 *	routing daemon case (as opposed to the single ipv4[6]-forwarding
 *	service),  we make use of the scf_walk_fmri() function,  which
 *	applies a callback function to all matching functions.  In the case
 *	of the routing daemons,  we pass in a NULL signifying that all
 *	instances should be walked  (we then weed out the relevant routing
 *	services through presence of the routeadm/protocol property).  In
 *	the case of enable, a routing service is enabled IFF it has the
 *	previously-mentioned property - with an appropriate value (i.e. ipv4
 *	for "routeadm -e ipv4-routing") - and it has routeadm/curr-routing-svc
 *	property set to true  (this is set by other operations such as
 *	routeadm -s routing-svcs="...").  Then,  smf_enable_instance() or
 *	smf_disable_instance() is called,  setting the temporary state to
 *	the current state of the service.  This then allows setting of
 *	general/enabled value to next-boot value.  In the case of disabling
 *	ipv4[6]-routing,  all valid ipv4[6] routing daemons are prepared
 *	for next-boot disable, not just those specified via routing-svcs (this
 *	means that if the user enables routing daemons with "svcadm enable",
 *	disabling global routing does really switch off all routing daemons).
 *
 *	This is implemented through the ra_get_set_opt_common_cb() function,
 *	called by the ra_set_persistent_opt_cb() function.  The same
 *	function can be used for both routing and forwarding options,  in the
 *	latter case we simply provide the specific FMRI of the forwarding
 *	service in question (ipv4-forwarding or ipv6-forwarding),  and dispense
 *	with the eligibility tests we need to weed out the routing services
 *	from the rest.
 *
 *	Before we initiate the "enable" however, we must check routing daemons
 *	specified via the legacy variables (ipv4-routing-daemon etc).
 *	If they map to SMF routing services,  we wish to transfer their
 *	configuration to the corresponding services and use them instead of
 *	the legacy services.  To do this,  we need to match the daemon program
 *	against the routeadm/daemon property of each routing daemon (we use
 *	scf_walk_fmri() and the routeadm/protocol property again to identify
 *	daemons).  If a match is found,  the daemon arguments are transferred
 *	to the appropriate service`s daemon-args property, to be picked up
 *	by it`s start method and converted into appropriate property values.
 *	This is accomplished by ra_check_legacy_daemons(), and the callback
 *	operation is carried out by ra_upgrade_legacy_daemons_cb().  If the
 *	daemon was not upgraded,  we need to mark the legacy-routing:ipv4[6]
 *	instance to be enabled (by routeadm -e),  since it now must run the
 *	un-upgradeable legacy daemon.
 *
 * routeadm -l fmri
 *
 *	Lists all properties and values in the routing property group associated
 *	with instance fmri.  We simply walk through the composed property
 *	group, displaying all values.  See ra_list_props_cb().
 *
 * routeadm -m fmri key=value ...
 *
 *	Modify property values in the routing property group.  If the same
 *	key is used more than once,  multiple property values are set for that
 *	property.  Properties must exist in the composed property group,  but
 *	will only ever be set at the instance level to prevent multiple
 *	instances inheriting the property in error.  See ra_modify_props_cb().
 *
 * routeadm -s var=value
 *
 *	In all cases bar the routing-svcs variable,  this simply involves
 *	setting the appropriate SMF property value for the variable.  The
 *	routing-svcs case is more complex,  since we would like operations
 *	like the following to have intuitive effects:
 *		# routeadm -s routing-svcs=route -e ipv4-routing -u
 *		# routeadm -s routing-svcs=rdisc -u
 *	i.e., in the end, rdisc is the only routing service running.  To
 *	accomplish this switchover,  we need to disable the old routing-svcs
 *	and enable the new, marking the latter with the curr-routing-svc
 *	property so that routeadm -e will pick them up.  This is carried
 *	out by the ra_update_routing_svcs() function.
 *
 * routeadm -R alt_root ...
 *
 *	Used to support use of routeadm in Custom Jumpstart scripts,  this
 *	option causes all subsequent commands to be appended to the
 *	/var/svc/profile/upgrade file,  which is run on the subsequent boot.
 *	This is done because the SMF repository is not available to make
 *	the modifications to property values required in routeadm operations.
 *
 * routeadm -u
 *
 *	Update applies the "next boot" state to the current system.  Here
 *	we simply take the persistent state (general/enabled value) and
 *	make it the current state through smf_enable_instance() or
 *	smf_disable_instance() as appropriate (these calls,  without the
 *	temporary flag set,  delete the general_ovr/enabled property).
 */

#define	RA_OPT_IPV4_ROUTING	"ipv4-routing"
#define	RA_OPT_IPV6_ROUTING	"ipv6-routing"
#define	RA_OPT_IPV4_FORWARDING	"ipv4-forwarding"
#define	RA_OPT_IPV6_FORWARDING	"ipv6-forwarding"

#define	IS_ROUTING_OPT(opt)	(strcmp(opt, RA_OPT_IPV4_ROUTING) == 0 || \
				strcmp(opt, RA_OPT_IPV6_ROUTING) == 0)

#define	RA_VAR_IPV4_ROUTING_DAEMON	"ipv4-routing-daemon"
#define	RA_VAR_IPV4_ROUTING_DAEMON_ARGS	"ipv4-routing-daemon-args"
#define	RA_VAR_IPV4_ROUTING_STOP_CMD	"ipv4-routing-stop-cmd"
#define	RA_VAR_IPV6_ROUTING_DAEMON	"ipv6-routing-daemon"
#define	RA_VAR_IPV6_ROUTING_DAEMON_ARGS	"ipv6-routing-daemon-args"
#define	RA_VAR_IPV6_ROUTING_STOP_CMD	"ipv6-routing-stop-cmd"
#define	RA_VAR_ROUTING_SVCS		"routing-svcs"


#define	RA_INSTANCE_ALL			NULL
#define	RA_INSTANCE_ROUTING_SETUP	"svc:/network/routing-setup:default"
#define	RA_INSTANCE_IPV4_FORWARDING	"svc:/network/ipv4-forwarding:default"
#define	RA_INSTANCE_IPV6_FORWARDING	"svc:/network/ipv6-forwarding:default"
#define	RA_INSTANCE_LEGACY_ROUTING_IPV4 \
	"svc:/network/routing/legacy-routing:ipv4"
#define	RA_INSTANCE_LEGACY_ROUTING_IPV6 \
	"svc:/network/routing/legacy-routing:ipv6"
#define	RA_INSTANCE_NDP			"svc:/network/routing/ndp:default"

#define	RA_PG_ROUTEADM			"routeadm"
#define	RA_PROP_CURR_ROUTING_SVC	"current-routing-svc"
#define	RA_PROP_ROUTING_SVCS		"routing-svcs"
#define	RA_PROP_DEFAULT_ROUTING_SVCS	"default-routing-svcs"
#define	RA_PROP_PROTO			"protocol"
#define	RA_PROP_DAEMON			"daemon"
#define	RA_PROP_DEFAULT_DAEMON		"default-daemon"
#define	RA_PROP_DAEMON_ARGS		"daemon-args"
#define	RA_PROP_DEFAULT_DAEMON_ARGS	"default-daemon-args"
#define	RA_PROP_DAEMON_STOP_CMD		"daemon-stop-cmd"
#define	RA_PROP_DEFAULT_STOP_CMD	"default-daemon"
#define	RA_PROP_LEGACY_DAEMON		"legacy-daemon"
#define	RA_PROP_DEFAULT_IPV4_ROUTING	"default-ipv4-routing"
#define	RA_PROP_DEFAULT_IPV6_ROUTING	"default-ipv6-routing"
#define	RA_PROP_DEFAULT_IPV4_FORWARDING	"default-ipv4-forwarding"
#define	RA_PROP_DEFAULT_IPV6_FORWARDING	"default-ipv6-forwarding"
#define	RA_PROP_IPV4_ROUTING_SET	"ipv4-routing-set"
#define	RA_PROP_IPV6_ROUTING_SET	"ipv6-routing-set"
#define	RA_PROP_ROUTING_CONF_READ	"routing-conf-read"

#define	RA_PG_ROUTING			"routing"

#define	RA_PROPVAL_BOOLEAN_TRUE		"true"
#define	RA_PROPVAL_BOOLEAN_FALSE	"false"
#define	RA_PROPVAL_PROTO_IPV4		"ipv4"
#define	RA_PROPVAL_PROTO_IPV6		"ipv6"

#define	RA_SVC_FLAG_NONE		0x0
#define	RA_SVC_FLAG_IPV4_ROUTING	0x1
#define	RA_SVC_FLAG_IPV6_ROUTING	0x2

#define	RA_SMF_UPGRADE_FILE		"/var/svc/profile/upgrade"
#define	RA_SMF_UPGRADE_MSG		" # added by routeadm(1M)"
#define	RA_CONF_FILE			"/etc/inet/routing.conf"
#define	RA_CONF_FILE_OLD		"/etc/inet/routing.conf.old"
#define	RA_MAX_CONF_LINE		256

/*
 * Option value.  Each option requires an FMRI identifying which services
 * to run the get_current/persistent scf_walk_fmri() function with,  and
 * associated flags (to ensure that in the case that multiple services
 * match, we select the correct ones). In addition, we specify the FMRI
 * and property used to set default option value.  The opt_enabled field
 * is used to hold retrieved state from get_*_opt_() callbacks and to specify
 * desired state for set_*_opt() operations.
 */

typedef struct raopt {
	const char	*opt_name;
	const char	*opt_fmri;
	int		opt_flags;
	boolean_t	opt_enabled;
	const char	*opt_default_fmri;
	const char	*opt_default_prop;
	boolean_t	opt_default_enabled;
} raopt_t;


raopt_t ra_opts[] = {
	{ RA_OPT_IPV4_ROUTING, RA_INSTANCE_ALL, RA_SVC_FLAG_IPV4_ROUTING,
	B_FALSE, RA_INSTANCE_ROUTING_SETUP, RA_PROP_DEFAULT_IPV4_ROUTING,
	B_FALSE },
	{ RA_OPT_IPV6_ROUTING, RA_INSTANCE_ALL, RA_SVC_FLAG_IPV6_ROUTING,
	B_FALSE, RA_INSTANCE_ROUTING_SETUP, RA_PROP_DEFAULT_IPV6_ROUTING,
	B_FALSE },
	{ RA_OPT_IPV4_FORWARDING, RA_INSTANCE_IPV4_FORWARDING, RA_SVC_FLAG_NONE,
	B_FALSE, RA_INSTANCE_IPV4_FORWARDING, RA_PROP_DEFAULT_IPV4_FORWARDING,
	B_FALSE },
	{ RA_OPT_IPV6_FORWARDING, RA_INSTANCE_IPV6_FORWARDING, RA_SVC_FLAG_NONE,
	B_FALSE, RA_INSTANCE_IPV6_FORWARDING, RA_PROP_DEFAULT_IPV6_FORWARDING,
	B_FALSE },
	{ NULL, NULL, RA_SVC_FLAG_NONE, B_FALSE, NULL, NULL, B_FALSE }
};

typedef enum option_values {
	OPT_INVALID, OPT_ENABLED, OPT_DISABLED, OPT_DEFAULT, OPT_UNKNOWN
} oval_t;

typedef struct ra_var {
	const char	*var_name;
	const char	*var_fmri;
	const char	*var_prop;
	char		*var_value;
	const char	*var_default_fmri;
	const char	*var_default_prop;
	char		*var_default_value;
} ravar_t;

ravar_t ra_vars[] = {
	{ RA_VAR_IPV4_ROUTING_DAEMON, RA_INSTANCE_LEGACY_ROUTING_IPV4,
	RA_PROP_DAEMON, NULL, RA_INSTANCE_LEGACY_ROUTING_IPV4,
	RA_PROP_DEFAULT_DAEMON, NULL},
	{ RA_VAR_IPV4_ROUTING_DAEMON_ARGS, RA_INSTANCE_LEGACY_ROUTING_IPV4,
	RA_PROP_DAEMON_ARGS, NULL, RA_INSTANCE_LEGACY_ROUTING_IPV4,
	RA_PROP_DEFAULT_DAEMON_ARGS, NULL },
	{ RA_VAR_IPV4_ROUTING_STOP_CMD, RA_INSTANCE_LEGACY_ROUTING_IPV4,
	RA_PROP_DAEMON_STOP_CMD, NULL, RA_INSTANCE_LEGACY_ROUTING_IPV4,
	RA_PROP_DEFAULT_STOP_CMD, NULL },
	{ RA_VAR_IPV6_ROUTING_DAEMON, RA_INSTANCE_LEGACY_ROUTING_IPV6,
	RA_PROP_DAEMON, NULL, RA_INSTANCE_LEGACY_ROUTING_IPV6,
	RA_PROP_DEFAULT_DAEMON, NULL },
	{ RA_VAR_IPV6_ROUTING_DAEMON_ARGS, RA_INSTANCE_LEGACY_ROUTING_IPV6,
	RA_PROP_DAEMON_ARGS, NULL, RA_INSTANCE_LEGACY_ROUTING_IPV6,
	RA_PROP_DEFAULT_DAEMON_ARGS, NULL },
	{ RA_VAR_IPV6_ROUTING_STOP_CMD, RA_INSTANCE_LEGACY_ROUTING_IPV6,
	RA_PROP_DAEMON_STOP_CMD, NULL, RA_INSTANCE_LEGACY_ROUTING_IPV6,
	RA_PROP_DEFAULT_STOP_CMD, NULL },
	{ RA_VAR_ROUTING_SVCS, RA_INSTANCE_ROUTING_SETUP,
	RA_PROP_ROUTING_SVCS, NULL, RA_INSTANCE_ROUTING_SETUP,
	RA_PROP_DEFAULT_ROUTING_SVCS, NULL },
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL }
};

char *v_opt[] = {
#define	IPV4_ROUTING_DAEMON			0
	RA_VAR_IPV4_ROUTING_DAEMON,
#define	IPV4_ROUTING_DAEMON_ARGS		1
	RA_VAR_IPV4_ROUTING_DAEMON_ARGS,
#define	IPV4_ROUTING_STOP_CMD			2
	RA_VAR_IPV4_ROUTING_STOP_CMD,
#define	IPV6_ROUTING_DAEMON			3
	RA_VAR_IPV6_ROUTING_DAEMON,
#define	IPV6_ROUTING_DAEMON_ARGS		4
	RA_VAR_IPV6_ROUTING_DAEMON_ARGS,
#define	IPV6_ROUTING_STOP_CMD			5
	RA_VAR_IPV6_ROUTING_STOP_CMD,
#define	ROUTING_SVCS				6
	RA_VAR_ROUTING_SVCS,
	NULL
};

#define	IS_IPV4_VAR(varname)	(strncmp(varname, "ipv4", 4) == 0)
#define	IS_IPV6_VAR(varname)	(strncmp(varname, "ipv6", 4) == 0)
#define	VAR_PROTO_MATCH(varname, proto)	(strncmp(varname, proto, 4) == 0)
#define	IPV4_VARS_UNSET \
	(strtok(ra_vars[IPV4_ROUTING_DAEMON].var_value, " \t") == NULL && \
	strtok(ra_vars[IPV4_ROUTING_DAEMON_ARGS].var_value, " \t") == NULL && \
	strtok(ra_vars[IPV4_ROUTING_STOP_CMD].var_value, " \t") == NULL)

#define	IPV6_VARS_UNSET	\
	(strtok(ra_vars[IPV6_ROUTING_DAEMON].var_value, " \t") == NULL && \
	strtok(ra_vars[IPV6_ROUTING_DAEMON_ARGS].var_value, " \t") == NULL && \
	strtok(ra_vars[IPV6_ROUTING_STOP_CMD].var_value, " \t") == NULL)

/*
 * Structure used in modify operations to tie property name and multiple values
 * together.
 */
typedef struct ra_prop {
	char	*prop_name;
	char	**prop_values;
	int	prop_numvalues;
} ra_prop_t;

typedef int (*ra_smf_cb_t)(void *, scf_walkinfo_t *);

/* Used to store program name */
static const char	*myname;

static void usage(void);

static int ra_check_legacy_daemons(void);
static int ra_upgrade_legacy_daemons(void);
static int ra_upgrade_cmd(char, int, char **);
static int ra_update(void);
static int ra_update_routing_svcs(char *);
static int ra_report(boolean_t, const char *);
static int ra_smf_cb(ra_smf_cb_t, const char *, void *);
static int ra_upgrade_from_legacy_conf(void);
static int ra_numv6intfs(void);
static int ra_parseconf(void);
static int ra_parseopt(char *, int, raopt_t *);
static int ra_parsevar(char *, ravar_t *);
static oval_t ra_str2oval(const char *);
static raopt_t *ra_str2opt(const char *);
static void ra_resetopts(void);
static ravar_t *ra_str2var(const char *);
static void ra_resetvars(const char *);
static char *ra_intloptname(const char *);

/* Callback for upgrade of legacy daemons */
static int ra_upgrade_legacy_daemons_cb(void *, scf_walkinfo_t *);

/* Callbacks used to set/retieve routing options */
static int ra_set_current_opt_cb(void *, scf_walkinfo_t *);
static int ra_set_persistent_opt_cb(void *, scf_walkinfo_t *);
static int ra_set_default_opt_cb(void *, scf_walkinfo_t *);
static int ra_get_current_opt_cb(void *, scf_walkinfo_t *);
static int ra_get_persistent_opt_cb(void *, scf_walkinfo_t *);
static int ra_get_default_opt_cb(void *, scf_walkinfo_t *);
static int ra_get_set_opt_common_cb(raopt_t *, scf_walkinfo_t *, boolean_t,
    boolean_t);
static int ra_routing_opt_set_cb(void *, scf_walkinfo_t *);
static int ra_routing_opt_unset_cb(void *, scf_walkinfo_t *);
static int ra_routing_opt_set_unset_cb(raopt_t *, scf_walkinfo_t *, boolean_t);

/* Callbacks used to set/retrieve routing variables */
static int ra_set_persistent_var_cb(void *, scf_walkinfo_t *);
static int ra_get_persistent_var_cb(void *, scf_walkinfo_t *);
static int ra_get_default_var_cb(void *, scf_walkinfo_t *);
static int ra_mark_routing_svcs_cb(void *, scf_walkinfo_t *);

/* Callbacks used to list/set daemon properties and list daemons and states. */
static int ra_list_props_cb(void *, scf_walkinfo_t *);
static int ra_modify_props_cb(void *, scf_walkinfo_t *);
static int ra_print_state_cb(void *, scf_walkinfo_t *);

/* Utility functions for SMF operations */
static int ra_get_pg(scf_handle_t *, scf_instance_t *, const char *,
    boolean_t, boolean_t, scf_propertygroup_t **);
static int ra_get_boolean_prop(scf_handle_t *, scf_instance_t *,
    const char *, const char *,  boolean_t, boolean_t, boolean_t *);
static int ra_get_single_prop_as_string(scf_handle_t *, scf_instance_t *,
    const char *, const char *, boolean_t, boolean_t, scf_type_t *, char **);
static int ra_get_prop_as_string(scf_handle_t *, scf_instance_t *,
    const char *, const char *, boolean_t, boolean_t, scf_type_t *, int *,
    char ***);
static void ra_free_prop_values(int, char **);
static int ra_set_boolean_prop(scf_handle_t *, scf_instance_t *,
    const char *, const char *, boolean_t, boolean_t);
static int ra_set_prop_from_string(scf_handle_t *, scf_instance_t *,
    const char *, const char *, scf_type_t, boolean_t, int,
    const char **);

static void
usage(void)
{
	(void) fprintf(stderr, gettext(
	    "usage: %1$s [-p] [-R <root-dir>]\n"
	    "       %1$s [-e <option>] [-d <option>] [-r <option>]\n"
	    "           [-l <FMRI>] [-m <FMRI> key=value [...]]\n"
	    "           [-s <var>=<val>] [-R <root-dir>]\n"
	    "       %1$s -u\n\n"
	    "       <option> is one of:\n"
	    "       ipv4-forwarding\n"
	    "       ipv4-routing\n"
	    "       ipv6-forwarding\n"
	    "       ipv6-routing\n\n"
	    "       <var> is one of:\n"
	    "       ipv4-routing-daemon\n"
	    "       ipv4-routing-daemon-args\n"
	    "       ipv4-routing-stop-cmd\n"
	    "       ipv6-routing-daemon\n"
	    "       ipv6-routing-daemon-args\n"
	    "       ipv6-routing-stop-cmd\n"
	    "       routing-svcs\n"), myname);
}

int
main(int argc, char *argv[])
{
	int		opt, opt_index, numargs, status = 0;
	int		numvalues, i;
	ssize_t		keylen;
	boolean_t	modify = B_FALSE, report = B_TRUE, update = B_FALSE;
	boolean_t	booting = B_FALSE, alt_root_set = B_FALSE;
	boolean_t	parseable = B_FALSE;
	char		*key, *nk, *keyend, *val, **vals, *options, *fmri;
	char		*parseopt = NULL;
	raopt_t		*raopt;
	ravar_t		*ravar;
	ra_prop_t	raprop;

	myname = argv[0];

	(void) setlocale(LC_ALL, "");

#if	!defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

	(void) textdomain(TEXT_DOMAIN);

	/*
	 * Before processing any options, we parse /etc/inet/routing.conf
	 * (if present) and transfer values to SMF.
	 */
	if (ra_upgrade_from_legacy_conf() == -1)
		exit(EXIT_FAILURE);
	while ((opt = getopt(argc, argv, ":bd:e:l:m:p:R:r:s:u")) != EOF) {
		switch (opt) {
		case 'b':
			/*
			 * Project-private option that tells us enable/disable
			 * operations should not set ipv4(6)-routing-set
			 * property.  Used in routing-setup service method
			 * to change default routing state, and, if
			 * no explicit enable/disable operations have been
			 * carried out, change current ipv4 routing state.
			 */
			booting = B_TRUE;
			break;
		case 'd':
		case 'e':
		case 'r':
			if (alt_root_set) {
				if (ra_upgrade_cmd(opt, 1, &optarg) != 0)
					exit(EXIT_FAILURE);
				modify = B_TRUE;
				break;
			}
			if ((raopt = ra_str2opt(optarg)) != NULL) {
				/* Set current value appropriately */
				switch (opt) {
				case 'd':
					raopt->opt_enabled = B_FALSE;
					break;
				case 'e':
					/*
					 * Check legacy daemons, mark
					 * routing-svcs.
					 */
					if (IS_ROUTING_OPT(optarg) &&
					    ra_check_legacy_daemons() == -1)
						exit(EXIT_FAILURE);
					raopt->opt_enabled = B_TRUE;
					break;
				case 'r':
					/*
					 * This callback sets opt_enabled to
					 * the default value.
					 */
					ra_resetopts();
					if (ra_smf_cb(ra_get_default_opt_cb,
					    raopt->opt_default_fmri, raopt)
					    == -1)
						exit(EXIT_FAILURE);
					if (raopt->opt_enabled &&
					    IS_ROUTING_OPT(optarg) &&
					    ra_check_legacy_daemons() == -1)
						exit(EXIT_FAILURE);
					/* set value to default */
					raopt->opt_enabled =
					    raopt->opt_default_enabled;
					break;
				}
				if (ra_smf_cb(ra_set_persistent_opt_cb,
				    raopt->opt_fmri, raopt) == -1)
					exit(EXIT_FAILURE);
				/*
				 * ipv4(6)-routing explicitly enabled/disabled,
				 * need to set ipv4(6)-routing-set property
				 * for routing-setup service.  Once this
				 * is set, routing-setup will not override
				 * administrator action and will not enable
				 * ipv4-routing in the case that no default
				 * route can be determined.  If ipv4(6)-routing
				 * is reverted to its default value,  set
				 * ipv4(6)-routing-set back to false.
				 */
				if (!booting && (raopt->opt_flags &
				    (RA_SVC_FLAG_IPV4_ROUTING |
				    RA_SVC_FLAG_IPV6_ROUTING))) {
					if (ra_smf_cb(opt == 'r' ?
					    ra_routing_opt_unset_cb :
					    ra_routing_opt_set_cb,
					    raopt->opt_default_fmri, raopt)
					    == -1)
						exit(EXIT_FAILURE);
				}
			} else if ((ravar = ra_str2var(optarg)) != NULL) {
				if (opt != 'r') {
					usage();
					exit(EXIT_FAILURE);
				}
				/* set current value to default */
				ra_resetopts();
				if (ra_smf_cb(ra_get_default_var_cb,
				    ravar->var_default_fmri, ravar) == -1)
					exit(EXIT_FAILURE);
				/* Need special case for routing-svcs var */
				if (strcmp(ravar->var_name, RA_VAR_ROUTING_SVCS)
				    == 0) {
					if (ra_update_routing_svcs(
					    ravar->var_default_value) == -1)
						exit(EXIT_FAILURE);
				} else if (ra_smf_cb(ra_set_persistent_var_cb,
				    ravar->var_fmri, ravar) == -1)
					exit(EXIT_FAILURE);
			} else {
				(void) fprintf(stderr, gettext(
				    "%1$s: invalid option: %2$s\n"), myname,
				    optarg);
				usage();
				exit(EXIT_FAILURE);
			}
			modify = B_TRUE;
			break;
		case 'l':
			if (ra_smf_cb(ra_list_props_cb, optarg, NULL) == -1)
				exit(EXIT_FAILURE);
			report = B_FALSE;
			break;
		case 'm':
			fmri = optarg;
			modify = B_TRUE;
			/*
			 * Argument list of key=value pairs, we need to
			 * collate all matching keys to set multiple values.
			 */
			numargs = 1;
			i = optind;
			for (numargs = 1; argv[i] != NULL && argv[i][0] != '-';
			    numargs++)
				i++;
			if (numargs == 1) {
				(void) fprintf(stderr, gettext(
				    "%s: key=value required for "
				    "property change\n"), myname);
				usage();
				exit(EXIT_FAILURE);
			}
			if (alt_root_set) {
				if (ra_upgrade_cmd(opt, numargs,
				    &argv[optind - 1]) == -1)
					exit(EXIT_FAILURE);
				optind += numargs - 1;
				break;
			}
			/*
			 * Collect all key=value pairs which use same key
			 * so we can add multiple property values.
			 */
			for (key = argv[optind]; key != NULL && key[0] != '-';
			    key = argv[++optind]) {
				if (key[0] == '\0')
					continue;
				vals = malloc(sizeof (char *));
				if ((vals[0] = strchr(key, '=')) == NULL) {
					(void) fprintf(stderr, gettext(
					    "%s: Malformed name=value "
					    "pair %s\n"), myname, key);
					exit(EXIT_FAILURE);
				}
				numvalues = 1;
				*(vals[0]) = '\0';
				(vals[0])++;
				i = optind + 1;
				for (nk = argv[i];
				    nk != NULL && nk[0] != '-';
				    nk = argv[++i]) {
					if (nk[0] == '\0')
						continue;
					if ((keyend = strchr(nk, '='))
					    == NULL) {
						(void) fprintf(stderr, gettext(
						    "%s: Malformed name=value "
						    " pair %s\n"), myname, nk);
						exit(EXIT_FAILURE);
					}
					if ((keylen = keyend - nk) !=
					    strlen(key))
						continue;
					if (strncmp(key, nk, keylen) == 0) {
						vals = realloc(vals, ++numvalues
						    * sizeof (char *));
						vals[numvalues - 1] = ++keyend;
						nk[0] = '\0';
						optind++;
					}
				}
				raprop.prop_name = key;
				raprop.prop_values = vals;
				raprop.prop_numvalues = numvalues;
				if (ra_smf_cb(ra_modify_props_cb, fmri,
				    &raprop) == -1)
					exit(EXIT_FAILURE);
			}
			break;
		case 'p':
			parseable = B_TRUE;
			parseopt = optarg;
			break;
		case 'R':
			if (chroot(optarg) == -1) {
				(void) fprintf(stderr, gettext(
				    "%1$s: failed to chroot to %2$s: %3$s\n"),
				    myname, optarg, strerror(errno));
				exit(EXIT_FAILURE);
			}
			alt_root_set = B_TRUE;
			report = B_FALSE;
			break;
		case 's':
			if (alt_root_set) {
				if (ra_upgrade_cmd(opt, 1, &optarg) == -1)
					exit(EXIT_FAILURE);
				modify = B_TRUE;
				break;
			}
			options = optarg;
			while (*options != '\0') {
				opt_index = getsubopt(&options, v_opt, &val);
				if (val == NULL) {
					usage();
					exit(EXIT_FAILURE);
				}
				if (opt_index == -1) {
					(void) fprintf(stderr, gettext(
					    "%1$s: invalid variable: %2$s\n"),
					    myname, optarg);
					usage();
					exit(EXIT_FAILURE);
				}
				ravar = &ra_vars[opt_index];
				/* Need special case for routing-svcs var */
				if (strcmp(ravar->var_name, RA_VAR_ROUTING_SVCS)
				    == 0) {
					if (ra_update_routing_svcs(val) == -1)
						return (-1);
				} else {
					ravar->var_value = strdup(val);
					if (ra_smf_cb(ra_set_persistent_var_cb,
					    ravar->var_fmri, ravar) == -1)
						exit(EXIT_FAILURE);
				}
			}
			modify = B_TRUE;
			break;
		case 'u':
			update = B_TRUE;
			break;
		case ':':
			/* if not 'p', usage failure */
			if (strcmp(argv[optind - 1], "-p") != 0) {
				(void) fprintf(stderr, gettext(
				    "%s: option requires an argument -%s\n"),
				    myname, argv[optind - 1]);
				usage();
				exit(EXIT_FAILURE);
			}
			parseable = B_TRUE;
			break;
		case '?':
			usage();
			exit(EXIT_FAILURE);
		}
	}

	if (argc > optind) {
		/* There shouldn't be any extra args. */
		usage();
		exit(EXIT_FAILURE);
	}

	if (parseable && (update || modify)) {
		(void) fprintf(stderr, gettext("%s: the -p option cannot be "
		    "used with any of -demrsu\n"), myname);
		usage();
		exit(EXIT_FAILURE);
	}

	if (update && ! alt_root_set)
		status = ra_update();

	if (report && !modify && !update)
		status = ra_report(parseable, parseopt);

	return (status == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

/*
 * Upgrade legacy daemons,  mark to-be-enabled routing services.
 */
static int
ra_check_legacy_daemons(void)
{
	ravar_t		*routing_svcs = ra_str2var(RA_VAR_ROUTING_SVCS);
	ravar_t		*v4d = ra_str2var(RA_VAR_IPV4_ROUTING_DAEMON);
	ravar_t		*v6d = ra_str2var(RA_VAR_IPV6_ROUTING_DAEMON);
	char		*fmri, *nextfmri;
	boolean_t	mark = B_FALSE;

	if (ra_smf_cb(ra_get_persistent_var_cb, routing_svcs->var_fmri,
	    routing_svcs) == -1)
		return (-1);

	/* First unmark all services */
	if (ra_smf_cb(ra_mark_routing_svcs_cb, NULL, &mark) == -1)
		return (-1);

	mark = B_TRUE;
	if (routing_svcs->var_value != NULL) {
		/*
		 * For routing-svcs variable, mark each named
		 * service as a current-routing-svc.
		 */
		if ((fmri = strdup(routing_svcs->var_value)) == NULL) {
			(void) fprintf(stderr, gettext(
			    "%s: out of memory\n"), myname);
			return (-1);
		}
		/* Now, mark each service named in routing-svcs. */
		for (nextfmri = strtok(fmri, " \t");
		    nextfmri != NULL;
		    nextfmri = strtok(NULL, " \t")) {
			if (ra_smf_cb(ra_mark_routing_svcs_cb, nextfmri,
			    &mark) == -1) {
				free(fmri);
				return (-1);
			}
		}
		free(fmri);
	}

	/*
	 * Now check if legacy variables (if specified) map to SMF routing
	 * daemons.  If so, transfer associated daemon arguments.
	 */
	if (ra_upgrade_legacy_daemons() == -1)
		return (-1);

	ra_resetvars(NULL);
	/*
	 * At this point, if the legacy services still have ipv4/ipv6
	 * routing daemons specified, we know they weren`t upgraded, so
	 * we mark them also.
	 */
	if (ra_smf_cb(ra_get_persistent_var_cb, v4d->var_fmri, v4d) == -1 ||
	    ra_smf_cb(ra_get_persistent_var_cb, v6d->var_fmri, v6d) == -1)
		return (-1);

	if (v4d->var_value != NULL && strtok(v4d->var_value, " \t") != NULL &&
	    ra_smf_cb(ra_mark_routing_svcs_cb, RA_INSTANCE_LEGACY_ROUTING_IPV4,
	    &mark) == -1)
		return (-1);
	if (v6d->var_value != NULL && strtok(v6d->var_value, " \t") != NULL &&
	    ra_smf_cb(ra_mark_routing_svcs_cb, RA_INSTANCE_LEGACY_ROUTING_IPV6,
	    &mark) == -1)
		return (-1);

	return (0);
}

/*
 * Retrieve legacy daemon variables,  and check if any SMF routing daemons
 * run the daemons specified.  If so, the legacy configuration (arguments
 * to the daemon) is transferred to the routeadm/daemon-args property
 * of the corresponding instance.  From there,  the instance picks up the
 * value and will transfer the daemon arguments to individiual properties
 * when enabled.
 */
static int
ra_upgrade_legacy_daemons(void)
{
	ravar_t	*v4d = ra_str2var(RA_VAR_IPV4_ROUTING_DAEMON);
	ravar_t	*v6d = ra_str2var(RA_VAR_IPV6_ROUTING_DAEMON);
	ravar_t	*v4args = ra_str2var(RA_VAR_IPV4_ROUTING_DAEMON_ARGS);
	ravar_t	*v6args = ra_str2var(RA_VAR_IPV6_ROUTING_DAEMON_ARGS);
	ravar_t	*v4stop = ra_str2var(RA_VAR_IPV4_ROUTING_STOP_CMD);
	ravar_t	*v6stop = ra_str2var(RA_VAR_IPV6_ROUTING_STOP_CMD);

	if (ra_smf_cb(ra_get_persistent_var_cb, v4d->var_fmri, v4d) == -1 ||
	    ra_smf_cb(ra_get_persistent_var_cb, v6d->var_fmri, v6d) == -1 ||
	    ra_smf_cb(ra_get_persistent_var_cb, v4args->var_fmri, v4args)
	    == -1 ||
	    ra_smf_cb(ra_get_persistent_var_cb, v6args->var_fmri, v6args)
	    == -1 ||
	    ra_smf_cb(ra_get_persistent_var_cb, v4stop->var_fmri, v4stop)
	    == -1 ||
	    ra_smf_cb(ra_get_persistent_var_cb, v6stop->var_fmri, v6stop)
	    == -1)
		return (-1);

	return (ra_smf_cb(ra_upgrade_legacy_daemons_cb, NULL, NULL));
}

/*
 * Determine if service runs the same daemon as that which is specified
 * in ipv4-routing-daemon or ipv6-routing-daemon.  If so, the associated
 * daemon arguments are transferred to the service.
 */

/* ARGSUSED0 */
static int
ra_upgrade_legacy_daemons_cb(void *data, scf_walkinfo_t *wip)
{
	const char	*inst_fmri = wip->fmri;
	scf_instance_t	*inst = wip->inst;
	scf_handle_t	*h = scf_instance_handle(inst);
	char		*daemon, *l_daemon = NULL;
	ravar_t		*v4d = ra_str2var(RA_VAR_IPV4_ROUTING_DAEMON);
	ravar_t		*v6d = ra_str2var(RA_VAR_IPV6_ROUTING_DAEMON);
	ravar_t		*v4args = ra_str2var(RA_VAR_IPV4_ROUTING_DAEMON_ARGS);
	ravar_t		*v6args = ra_str2var(RA_VAR_IPV6_ROUTING_DAEMON_ARGS);
	ravar_t		*v4stop = ra_str2var(RA_VAR_IPV4_ROUTING_STOP_CMD);
	ravar_t		*v6stop = ra_str2var(RA_VAR_IPV6_ROUTING_STOP_CMD);
	ravar_t		*routing_svcs = ra_str2var(RA_VAR_ROUTING_SVCS);
	boolean_t	mark, marked;
	char		*new_routing_svcs;

	/*
	 * Ensure instance is a routing service, and not one of the
	 * legacy instances - if it is, the daemon property is already
	 * set to the legacy daemon.
	 */
	if (ra_get_single_prop_as_string(h, inst, RA_PG_ROUTEADM,
	    RA_PROP_DAEMON, B_TRUE, B_FALSE, NULL, &daemon) == -1 ||
	    strcmp(RA_INSTANCE_LEGACY_ROUTING_IPV4, inst_fmri) == 0 ||
	    strcmp(RA_INSTANCE_LEGACY_ROUTING_IPV6, inst_fmri) == 0)
		return (0);

	/* A legacy daemon may be defined */
	(void) ra_get_single_prop_as_string(h, inst, RA_PG_ROUTEADM,
	    RA_PROP_LEGACY_DAEMON, B_TRUE, B_FALSE, NULL, &l_daemon);

	/*
	 * If we match daemon/legacy_daemon with ipv4-routing-daemon or
	 * ipv6-routing-daemon values, transfer daemon-args value
	 * to the matching service.
	 */
	if (v4d->var_value != NULL && (strcmp(v4d->var_value, daemon) == 0 ||
	    (l_daemon != NULL && strcmp(v4d->var_value, l_daemon) == 0))) {
		(void) printf(gettext("%s: migrating daemon configuration "
		    "for %s to %s\n"), myname, l_daemon != NULL ?
		    l_daemon : daemon, inst_fmri);
		/* Transfer daemon-args value, clear legacy v4 values */
		if (ra_set_prop_from_string(h, inst, RA_PG_ROUTEADM,
		    RA_PROP_DAEMON_ARGS, SCF_TYPE_ASTRING, B_TRUE, 1,
		    (const char **)&(v4args->var_value)) == -1)
			return (-1);
		ra_resetvars(RA_PROPVAL_PROTO_IPV4);
		if (ra_smf_cb(ra_set_persistent_var_cb,
		    RA_INSTANCE_LEGACY_ROUTING_IPV4, v4d) == -1 ||
		    ra_smf_cb(ra_set_persistent_var_cb,
		    RA_INSTANCE_LEGACY_ROUTING_IPV4, v4args) == -1 ||
		    ra_smf_cb(ra_set_persistent_var_cb,
		    RA_INSTANCE_LEGACY_ROUTING_IPV4, v4stop) == -1)
			return (-1);
	} else if (v6d->var_value != NULL && (strcmp(v6d->var_value, daemon)
	    == 0 ||
	    (l_daemon != NULL && strcmp(v6d->var_value, l_daemon) == 0))) {
		(void) printf(gettext("%s: migrating daemon configuration "
		    "for %s to %s\n"), myname, l_daemon != NULL ?
		    l_daemon : daemon, inst_fmri);
		/* Transfer daemon-args value, clear legacy v6 values */
		if (ra_set_prop_from_string(h, inst, RA_PG_ROUTEADM,
		    RA_PROP_DAEMON_ARGS, SCF_TYPE_ASTRING, B_TRUE, 1,
		    (const char **)&(v6args->var_value)) == -1)
			return (-1);
		ra_resetvars(RA_PROPVAL_PROTO_IPV6);
		if (ra_smf_cb(ra_set_persistent_var_cb,
		    RA_INSTANCE_LEGACY_ROUTING_IPV6, v6d) == -1 ||
		    ra_smf_cb(ra_set_persistent_var_cb,
		    RA_INSTANCE_LEGACY_ROUTING_IPV6, v6args) == -1 ||
		    ra_smf_cb(ra_set_persistent_var_cb,
		    RA_INSTANCE_LEGACY_ROUTING_IPV6, v6stop) == -1)
			return (-1);
	} else
		return (0);

	/*
	 * If service is unmarked at this point, add it to routing-svcs and
	 * mark it.
	 */
	if (ra_get_boolean_prop(h, inst, RA_PG_ROUTEADM,
	    RA_PROP_CURR_ROUTING_SVC, B_FALSE, B_FALSE, &marked) == -1 ||
	    marked == B_FALSE) {
		mark = B_TRUE;
		if (ra_smf_cb(ra_mark_routing_svcs_cb, inst_fmri, &mark)
		    == -1 ||
		    ra_smf_cb(ra_get_persistent_var_cb, routing_svcs->var_fmri,
		    routing_svcs) == -1)
			return (-1);
		if ((new_routing_svcs =
		    malloc(strlen(routing_svcs->var_value) +
		    strlen(inst_fmri) + 2)) == NULL) {
			(void) fprintf(stderr, gettext(
			    "%s: out of memory"), myname);
			return (-1);
		}
		if (strlen(routing_svcs->var_value) == 0)
			(void) snprintf(new_routing_svcs,
			    strlen(inst_fmri) + 1, "%s", inst_fmri);
		else
			(void) snprintf(new_routing_svcs,
			    strlen(routing_svcs->var_value) +
			    strlen(inst_fmri) + 2, "%s %s",
			    routing_svcs->var_value, inst_fmri);
		free(routing_svcs->var_value);
		routing_svcs->var_value = new_routing_svcs;
		(void) smf_refresh_instance(inst_fmri);
		return (ra_smf_cb(ra_set_persistent_var_cb,
		    routing_svcs->var_fmri, routing_svcs));
	}
	(void) smf_refresh_instance(inst_fmri);
	return (0);
}

/*
 * If we are upgrading,  append operation to <alt_root>/var/svc/profile/upgrade.
 */
static int
ra_upgrade_cmd(char opt, int argc, char **argv)
{
	FILE	*fp;
	int	i;

	if ((fp = fopen(RA_SMF_UPGRADE_FILE, "a+")) == NULL) {
		(void) fprintf(stderr, gettext(
		    "%1$s: failed to open %2$s: %3$s\n"),
		    myname, RA_SMF_UPGRADE_FILE, strerror(errno));
		return (-1);
	}
	(void) fprintf(fp, "/sbin/routeadm -%c ", opt);
	if (argv != NULL) {
		for (i = 0; i < argc; i++)
			(void) fprintf(fp, "%s ", argv[i]);
	}
	(void) fprintf(fp, "%s\n", RA_SMF_UPGRADE_MSG);
	(void) fclose(fp);
	return (0);
}

/*
 * Set current state to "next boot" state, i.e. if general/enabled
 * value is overlaid by a general_ovr/enabled value, set the current state
 * to the value of the latter.  Doing this applies "next boot" changes to
 * the current setup.  If any IPv6 interfaces are present, also start in.ndpd.
 */
static int
ra_update(void)
{
	int	i;

	if (ra_check_legacy_daemons() == -1)
		return (-1);
	for (i = 0; ra_opts[i].opt_name != NULL; i++) {
		if (ra_smf_cb(ra_set_current_opt_cb, ra_opts[i].opt_fmri,
		    &ra_opts[i]) == -1) {
			return (-1);
		}
	}
	/*
	 * If in.ndpd isn't already running, then we start it here, regardless
	 * of global IPv6 routing status (provided there are IPv6 interfaces
	 * present).
	 */
	if (ra_numv6intfs() > 0)
		return (smf_enable_instance(RA_INSTANCE_NDP, SMF_TEMPORARY));
	return (0);
}

/*
 * Here we catch the special case where ipv4/ipv6 routing was enabled,
 * and the user updates the routing-svcs list.  The problem is that
 * the enabled state is the result of services on the old routing-svcs list
 * being enabled, and we want to support users doing something like this:
 *
 * # routeadm -s routing-svcs=route -e ipv4-routing -u
 *
 * followed by
 *
 * # routeadm -s routing-svcs=rdisc -u
 *
 * To do this, we need to:
 *	- cache the old ipv4-routing/ipv6-routing values.
 *	- persistently disable the old routing-svcs list.
 *	- if ipv4-routing was enabled, mark and persistently enable all the new
 *	v4 routing-svcs
 *	- if ipv6-routing was enabled, mark and persistently enable all the new
 *	v6 routing-svcs.
 * This will result in the next "-u" switching on the new routing-svcs, and
 * switching off the old ones,  as the user would expect.
 */
static int
ra_update_routing_svcs(char *routing_svcs_new)
{
	raopt_t		*v4opt = ra_str2opt(RA_OPT_IPV4_ROUTING);
	raopt_t		*v6opt = ra_str2opt(RA_OPT_IPV6_ROUTING);
	ravar_t		*routing_svcs = ra_str2var(RA_VAR_ROUTING_SVCS);
	char		*routing_svcs_old, *fmri;
	boolean_t	v4_old, v6_old, mark = B_FALSE;

	ra_resetopts();
	if (ra_smf_cb(ra_get_persistent_opt_cb, v4opt->opt_fmri, v4opt) == -1 ||
	    ra_smf_cb(ra_get_persistent_opt_cb, v6opt->opt_fmri, v6opt) == -1 ||
	    ra_smf_cb(ra_get_persistent_var_cb, routing_svcs->var_fmri,
	    routing_svcs) == -1)
		return (-1);
	v4_old = v4opt->opt_enabled;
	v6_old = v6opt->opt_enabled;
	routing_svcs_old = routing_svcs->var_value;
	routing_svcs->var_value = routing_svcs_new;

	if (ra_smf_cb(ra_set_persistent_var_cb, routing_svcs->var_fmri,
	    routing_svcs) == -1) {
		free(routing_svcs_old);
		return (-1);
	}

	if (!v4_old && !v6_old) {
		/* We don`t need to do anything, since services were disabled */
		free(routing_svcs_old);
		return (0);
	}
	v4opt->opt_enabled = B_FALSE;
	v6opt->opt_enabled = B_FALSE;

	/* Persistently disable each old v4/v6 "routing-svc" */
	for (fmri = strtok(routing_svcs_old, " \t"); fmri != NULL;
	    fmri = strtok(NULL, " \t")) {
		if (ra_smf_cb(ra_mark_routing_svcs_cb, fmri, &mark) == -1) {
			free(routing_svcs_old);
			return (-1);
		}
		if (v4_old &&
		    ra_smf_cb(ra_set_persistent_opt_cb, fmri, v4opt) == -1) {
			free(routing_svcs_old);
			return (-1);
		}
		if (v6_old &&
		    ra_smf_cb(ra_set_persistent_opt_cb, fmri, v6opt) == -1) {
			free(routing_svcs_old);
			return (-1);
		}
	}
	free(routing_svcs_old);
	v4opt->opt_enabled = v4_old;
	v6opt->opt_enabled = v6_old;

	/* Persistently enable each new v4/v6 "routing-svc" */
	mark = B_TRUE;
	for (fmri = strtok(routing_svcs_new, " \t"); fmri != NULL;
	    fmri = strtok(NULL, " \t")) {
		if (ra_smf_cb(ra_mark_routing_svcs_cb, fmri, &mark) == -1)
			return (-1);
		if (v4_old &&
		    ra_smf_cb(ra_set_persistent_opt_cb, fmri, v4opt) == -1)
			return (-1);
		if (v6_old &&
		    ra_smf_cb(ra_set_persistent_opt_cb, fmri, v6opt) == -1)
			return (-1);
	}
	return (0);
}

/*
 * Display status,  in parseable form if required.  If param is
 * specified,  only the named option/variable is displayed  (this option is
 * for parseable display only).
 */
static int
ra_report(boolean_t parseable, const char *param)
{
	int		i;
	char		*c_state, *d_state, *p_state, *p_var, *d_var;
	char		*enabled = "enabled";
	char		*disabled = "disabled";
	boolean_t	param_found = B_FALSE;

	if (!parseable) {
		(void) printf(gettext(
		    "              Configuration   Current              "
		    "Current\n"
		    "                     Option   Configuration        "
		    "System State\n"
		    "---------------------------------------------------"
		    "------------\n"));
	}
	for (i = 0; ra_opts[i].opt_name != NULL; i++) {
		if (param != NULL) {
			if (strcmp(ra_opts[i].opt_name, param) == 0)
				param_found = B_TRUE;
			else
				continue;
		}
		if (ra_smf_cb(ra_get_current_opt_cb,
		    ra_opts[i].opt_fmri, &ra_opts[i]) == -1)
			return (-1);
		c_state = ra_opts[i].opt_enabled ? enabled : disabled;
		ra_resetopts();
		if (ra_smf_cb(ra_get_persistent_opt_cb,
		    ra_opts[i].opt_fmri, &ra_opts[i]) == -1)
			return (-1);
		p_state = ra_opts[i].opt_enabled ? enabled : disabled;
		ra_resetopts();
		if (ra_smf_cb(ra_get_default_opt_cb,
		    ra_opts[i].opt_default_fmri, &ra_opts[i]) == -1)
			return (-1);
		d_state = ra_opts[i].opt_default_enabled ? enabled : disabled;
		ra_resetopts();
		if (parseable) {
			if (param == NULL)
				(void) printf("%s ", ra_opts[i].opt_name);
			(void) printf("persistent=%s default=%s "
			    "current=%s\n", p_state, d_state, c_state);
		} else {
			(void) printf(gettext("%1$27s   %2$-21s%3$s\n"),
			    ra_intloptname(ra_opts[i].opt_name),
			    p_state, c_state);
		}
	}
	if (!parseable)
		(void) printf("\n");

	ra_resetvars(NULL);

	/* Gather persistent/default variable values */
	for (i = 0; ra_vars[i].var_name != NULL; i++) {
		if (ra_smf_cb(ra_get_persistent_var_cb,
		    ra_vars[i].var_fmri, &ra_vars[i]) == -1 ||
		    ra_smf_cb(ra_get_default_var_cb,
		    ra_vars[i].var_default_fmri, &ra_vars[i]) == -1)
			return (-1);

	}
	for (i = 0; ra_vars[i].var_name != NULL; i++) {
		if (param != NULL) {
			if (strcmp(ra_vars[i].var_name, param) == 0)
				param_found = B_TRUE;
			else
				continue;
		}
		p_var = ra_vars[i].var_value == NULL ? "":
		    ra_vars[i].var_value;
		d_var = ra_vars[i].var_default_value == NULL ?
		    "": ra_vars[i].var_default_value;
		if (parseable) {
			if (param == NULL)
				(void) printf("%s ", ra_vars[i].var_name);
			(void) printf("persistent=\"%s\" "
			    "default=\"%s\" \n", p_var, d_var);
		} else {
			/* If daemon variables are not set, do not display. */
			if ((IS_IPV4_VAR(ra_vars[i].var_name) &&
			    IPV4_VARS_UNSET) ||
			    (IS_IPV6_VAR(ra_vars[i].var_name) &&
			    IPV6_VARS_UNSET))
				continue;
			(void) printf(gettext("%1$27s   \"%2$s\"\n"),
			    ra_intloptname(ra_vars[i].var_name), p_var);
		}
	}

	if (param != NULL && !param_found) {
		(void) fprintf(stderr, gettext(
		    "%s: no such option/variable %s\n"), myname, param);
		return (-1);
	}
	if (parseable)
		return (0);
	(void) printf(gettext("\nRouting daemons:\n"));
	(void) printf("\n                      %s   %s\n", "STATE", "FMRI");
	if (ra_smf_cb(ra_print_state_cb, NULL, NULL) == -1)
		return (-1);
	return (0);
}

/*
 * Call scf_walk_fmri() with appropriate function, fmri, and data.
 * A NULL fmri causes scf_walk_fmri() to run on all instances.  We make
 * use of this many times in applying changes to the routing services.
 */
static int
ra_smf_cb(ra_smf_cb_t cbfunc, const char *fmri, void *data)
{
	scf_handle_t	*h;
	int		exit_status = 0;

	if ((h = scf_handle_create(SCF_VERSION)) == NULL ||
	    scf_handle_bind(h) == -1) {
		(void) fprintf(stderr, gettext(
		    "%s: cannot connect to SMF repository\n"), myname);
		return (-1);
	}
	return (scf_walk_fmri(h, fmri == NULL ? 0 : 1,
	    fmri == NULL ? NULL : (char **)&fmri, 0,
	    cbfunc, data, &exit_status, uu_die));
}

/*
 * Applies persistent configuration settings to current setup.
 */
static int
ra_set_current_opt_cb(void *data, scf_walkinfo_t *wip)
{
	return (ra_get_set_opt_common_cb(data, wip, B_FALSE, B_FALSE));
}

/*
 * Sets persistent value for option,  to be applied on next boot
 * or by "routeadm -u".
 */
static int
ra_set_persistent_opt_cb(void *data, scf_walkinfo_t *wip)
{
	return (ra_get_set_opt_common_cb(data, wip, B_TRUE, B_FALSE));
}

static int
ra_get_current_opt_cb(void *data, scf_walkinfo_t *wip)
{
	return (ra_get_set_opt_common_cb(data, wip, B_FALSE, B_TRUE));
}

static int
ra_get_persistent_opt_cb(void *data, scf_walkinfo_t *wip)
{
	return (ra_get_set_opt_common_cb(data, wip, B_TRUE, B_TRUE));
}

static int
ra_routing_opt_set_cb(void *data, scf_walkinfo_t *wip)
{
	return (ra_routing_opt_set_unset_cb(data, wip, B_TRUE));
}

static int
ra_routing_opt_unset_cb(void *data, scf_walkinfo_t *wip)
{
	return (ra_routing_opt_set_unset_cb(data, wip, B_FALSE));
}

/*
 * Notify network/routing-setup service that administrator has explicitly
 * set/reset ipv4(6)-routing value.  If no explicit setting of this value is
 * done,  ipv4-routing can be enabled in the situation when no default route can
 * be determined.
 */
static int
ra_routing_opt_set_unset_cb(raopt_t *raopt, scf_walkinfo_t *wip, boolean_t set)
{
	scf_instance_t	*inst = wip->inst;
	scf_handle_t	*h = scf_instance_handle(inst);

	return (ra_set_boolean_prop(h, inst, RA_PG_ROUTEADM,
	    raopt->opt_flags & RA_SVC_FLAG_IPV4_ROUTING ?
	    RA_PROP_IPV4_ROUTING_SET : RA_PROP_IPV6_ROUTING_SET,
	    B_FALSE, set));
}

/*
 * Shared function that either sets or determines persistent or current
 * state. Setting persistent state (for next boot) involves setting
 * the general_ovr/enabled value to the current service state, and
 * the general/enabled value to the desired (next-boot) state.
 * Setting current state involves removing the temporary state
 * setting so the persistent state has effect.
 *
 * Persistent state is reported as being enabled if any of the
 * candidate services have a general/enabled value set to true,
 * while current state is reported as being enabled if any of the
 * candidate services has a general_ovr/enabled or general/enabled
 * value set to true.
 */
static int
ra_get_set_opt_common_cb(raopt_t *raopt, scf_walkinfo_t *wip,
    boolean_t persistent, boolean_t get)
{
	const char		*inst_fmri = wip->fmri;
	scf_instance_t		*inst = wip->inst;
	scf_handle_t		*h = scf_instance_handle(inst);
	scf_propertygroup_t	*routeadm_pg;
	boolean_t		persistent_state_enabled;
	boolean_t		temporary_state_enabled;
	boolean_t		current_state_enabled;
	boolean_t		curr_svc = B_TRUE;
	boolean_t		found_proto;
	char			**protolist = NULL;
	int			i, ret, numvalues = 0;

	/*
	 * Ensure we are dealing with a routeadm-managed service.  If
	 * the FMRI used for walking instances is NULL,  it is reasonable
	 * that a service not have a routeadm property group as we will
	 * check all services in this case.
	 */
	if (ra_get_pg(h, inst, RA_PG_ROUTEADM, B_TRUE, raopt->opt_fmri != NULL,
	    &routeadm_pg) == -1) {
			/* Not a routing service, not an error. */
			if (scf_error() == SCF_ERROR_NOT_FOUND &&
			    raopt->opt_fmri == NULL)
				return (0);
			return (-1);
	}
	scf_pg_destroy(routeadm_pg);

	/* Services with no "protocol" property are not routing daemons */
	if (raopt->opt_fmri == NULL && ra_get_prop_as_string(h, inst,
	    RA_PG_ROUTEADM, RA_PROP_PROTO, B_TRUE, B_FALSE, NULL, &numvalues,
	    &protolist) == -1) {
		if (scf_error() == SCF_ERROR_NOT_FOUND)
			return (0);
		return (-1);
	}

	/*
	 * Skip invalid services based on flag settings.  Flags are used when
	 * we run callback functions on all instances to identify
	 * the correct instances to operate on.
	 */
	if (raopt->opt_flags & RA_SVC_FLAG_IPV4_ROUTING) {
		found_proto = B_FALSE;
		if (protolist != NULL) {
			/* Check if protolist contains "ipv4" */
			for (i = 0; i < numvalues; i++) {
				if (protolist[i] != NULL && strcmp(
				    protolist[i], RA_PROPVAL_PROTO_IPV4) == 0)
					found_proto = B_TRUE;
			}
		}
		/* If not an ipv4 routing service, skip. */
		if (protolist == NULL || !found_proto) {
			ra_free_prop_values(numvalues, protolist);
			return (0);
		}
	}
	if (raopt->opt_flags & RA_SVC_FLAG_IPV6_ROUTING) {
		found_proto = B_FALSE;
		if (protolist != NULL) {
			/* Check if protolist contains "ipv6" */
			for (i = 0; i < numvalues; i++) {
				if (protolist[i] != NULL && strcmp(
				    protolist[i], RA_PROPVAL_PROTO_IPV6) == 0)
					found_proto = B_TRUE;
			}
		}
		/* If not an ipv6 routing service, skip. */
		if (protolist == NULL || !found_proto) {
			ra_free_prop_values(numvalues, protolist);
			return (0);
		}
		/*
		 * If no IPv6 interfaces are configured, do not apply
		 * the "enable" state change to this IPv6 routing service.
		 */
		if (raopt->opt_enabled && ra_numv6intfs() < 1)
			return (0);
	}
	ra_free_prop_values(numvalues, protolist);

	/* If enabling routing services, select only current routing services */
	if (raopt->opt_fmri == NULL && !get && raopt->opt_enabled) {
		if (ra_get_boolean_prop(h, inst, RA_PG_ROUTEADM,
		    RA_PROP_CURR_ROUTING_SVC, B_FALSE, B_FALSE,
		    &curr_svc) == -1)
			return (0);
		else if (!curr_svc && persistent) {
			/*
			 * We apply "current" routing changes to all routing
			 * daemons, whether current or not, so bail if
			 * we are trying to make a persistent update to a
			 * non-"routing-svc".
			 */
			return (0);
		}
	}
	if (ra_get_boolean_prop(h, inst, SCF_PG_GENERAL, SCF_PROPERTY_ENABLED,
	    B_FALSE, B_TRUE, &persistent_state_enabled) == -1)
		return (-1);

	current_state_enabled = persistent_state_enabled;

	if (ra_get_boolean_prop(h, inst, SCF_PG_GENERAL_OVR,
	    SCF_PROPERTY_ENABLED, B_FALSE, B_FALSE, &temporary_state_enabled)
	    == 0)
		current_state_enabled = temporary_state_enabled;

	if (get) {
		/*
		 * Persistent state is enabled if any services are
		 * persistently enabled, i.e. general/enabled == true).
		 * current state is enabled if any services
		 * services are currently enabled, i.e. if defined,
		 * general_ovr/enabled == true, if not, general/enabled == true.
		 */
		if (persistent)
			raopt->opt_enabled = raopt->opt_enabled ||
			    persistent_state_enabled;
		else
			raopt->opt_enabled = raopt->opt_enabled ||
			    current_state_enabled;
	} else {
		if (persistent) {
			/*
			 * For peristent state changes, from -e/-d,
			 * we set the general_ovr/enabled value to the
			 * current state (to ensure it is preserved),
			 * while setting the general/enabled value to
			 * the desired value.  This has the effect of
			 * the desired value coming into effect on next boot.
			 */
			ret = current_state_enabled ?
			    smf_enable_instance(inst_fmri, SMF_TEMPORARY) :
			    smf_disable_instance(inst_fmri, SMF_TEMPORARY);
			if (ret != 0) {
				(void) fprintf(stderr, gettext(
				    "%s: unexpected libscf error: %s\n"),
				    myname, scf_strerror(scf_error()));
				return (-1);
			}
			/*
			 * Refresh here so general_ovr/enabled state overrides
			 * general/enabled state.
			 */
			(void) smf_refresh_instance(inst_fmri);
			/*
			 * Now we can safely set the general/enabled value
			 * to the value we require on next boot (or
			 * "routeadm -u").
			 */
			ret = ra_set_boolean_prop(h, inst, SCF_PG_GENERAL,
			    SCF_PROPERTY_ENABLED, B_FALSE, raopt->opt_enabled);
			if (ret != 0)
				return (-1);
			/*
			 * Refresh here so general/enabled value is set.
			 */
			(void) smf_refresh_instance(inst_fmri);
			if (raopt->opt_fmri != NULL)
				return (0);
			(void) smf_refresh_instance(RA_INSTANCE_ROUTING_SETUP);
		} else {
			/*
			 * Refresh here to get latest property values prior
			 * to starting daemon.
			 */
			(void) smf_refresh_instance(inst_fmri);
			/*
			 * For current changes (result of -u), we
			 * enable/disable depending on persistent value
			 * stored in general/enabled.  Here we disable
			 * old routing-svcs (identified by a current-routing-svc
			 * value of false) also.
			 */
			ret = persistent_state_enabled && curr_svc ?
			    smf_enable_instance(inst_fmri, 0) :
			    smf_disable_instance(inst_fmri, 0);
			if (ret != 0) {
				(void) fprintf(stderr, gettext(
				    "%s: unexpected libscf error: %s\n"),
				    myname, scf_strerror(scf_error()));
				return (-1);
			}
			if (current_state_enabled && persistent_state_enabled) {
				/*
				 * Instance was already enabled, so we restart
				 * to get latest property values.  This covers
				 * the case where users update properties
				 * via routeadm -m, and issue an update.  The
				 * daemon should be running with the latest
				 * property values.
				 */
				(void) smf_restart_instance(inst_fmri);
			}
		}
	}
	return (0);
}

static int
ra_set_default_opt_cb(void *data, scf_walkinfo_t *wip)
{
	scf_instance_t		*inst = wip->inst;
	scf_handle_t		*h = scf_instance_handle(inst);
	raopt_t			*raopt = data;

	return (ra_set_boolean_prop(h, inst, RA_PG_ROUTEADM,
	    raopt->opt_default_prop, B_FALSE, raopt->opt_default_enabled));
}

static int
ra_get_default_opt_cb(void *data, scf_walkinfo_t *wip)
{
	scf_instance_t		*inst = wip->inst;
	scf_handle_t		*h = scf_instance_handle(inst);
	raopt_t			*raopt = data;

	return (ra_get_boolean_prop(h, inst, RA_PG_ROUTEADM,
	    raopt->opt_default_prop, B_TRUE, B_TRUE,
	    &(raopt->opt_default_enabled)));
}

/*
 * Callbacks to set/retrieve persistent/default routing variable values.
 * The set functions use the value stored in the var_value/var_default_value
 * field of the associated ra_var_t, while the retrieval functions store
 * the value retrieved in that field.
 */
static int
ra_get_persistent_var_cb(void *data, scf_walkinfo_t *wip)
{
	scf_instance_t		*inst = wip->inst;
	scf_handle_t		*h = scf_instance_handle(inst);
	ravar_t			*ravar = data;

	return (ra_get_single_prop_as_string(h, inst, RA_PG_ROUTEADM,
	    ravar->var_prop, B_TRUE, B_TRUE, NULL, &ravar->var_value));
}

static int
ra_set_persistent_var_cb(void *data, scf_walkinfo_t *wip)
{
	scf_instance_t		*inst = wip->inst;
	scf_handle_t		*h = scf_instance_handle(inst);
	ravar_t			*ravar = data;

	return (ra_set_prop_from_string(h, inst, RA_PG_ROUTEADM,
	    ravar->var_prop, SCF_TYPE_INVALID, B_FALSE, 1,
	    (const char **)&ravar->var_value));
}

static int
ra_get_default_var_cb(void *data, scf_walkinfo_t *wip)
{
	scf_instance_t		*inst = wip->inst;
	scf_handle_t		*h = scf_instance_handle(inst);
	ravar_t			*ravar = data;

	return (ra_get_single_prop_as_string(h, inst, RA_PG_ROUTEADM,
	    ravar->var_default_prop, B_TRUE, B_TRUE, NULL,
	    &ravar->var_default_value));
}

/*
 * Depending on the value of the boolean_t * passed in,  this callback
 * either marks the relevant service(s) as current-routing-svcs (or unmarking)
 * by setting that property to true or false.  When routing services
 * are to be enabled,  the a current-routing-svc value of true flags the
 * service as one to be enabled.
 */
static int
ra_mark_routing_svcs_cb(void *data, scf_walkinfo_t *wip)
{
	scf_instance_t		*inst = wip->inst;
	scf_handle_t		*h = scf_instance_handle(inst);
	boolean_t		*mark = data;
	boolean_t		marked;
	int			numvalues = 0;
	char			**protolist = NULL;

	/* Check we are dealing with a routing daemon service */
	if (ra_get_prop_as_string(h, inst, RA_PG_ROUTEADM, RA_PROP_PROTO,
	    B_TRUE, B_FALSE, NULL, &numvalues, &protolist) == -1)
		return (0);
	ra_free_prop_values(numvalues, protolist);
	if (*mark)
		return (ra_set_boolean_prop(h, inst, RA_PG_ROUTEADM,
		    RA_PROP_CURR_ROUTING_SVC, B_TRUE, B_TRUE));
	/* Unmark service. */
	if (ra_get_boolean_prop(h, inst, RA_PG_ROUTEADM,
	    RA_PROP_CURR_ROUTING_SVC, B_TRUE, B_FALSE, &marked) == 0 && marked)
		return (ra_set_boolean_prop(h, inst, RA_PG_ROUTEADM,
		    RA_PROP_CURR_ROUTING_SVC, B_TRUE, B_FALSE));
	return (0);
}

/*
 * List property values for all properties in the "routing" property
 * group of the routing service instance.
 */

/* ARGSUSED0 */
static int
ra_list_props_cb(void *data, scf_walkinfo_t *wip)
{
	const char		*inst_fmri = wip->fmri;
	scf_instance_t		*inst = wip->inst;
	scf_handle_t		*h = scf_instance_handle(inst);
	scf_iter_t		*propiter, *valiter;
	scf_propertygroup_t	*pg;
	scf_property_t		*prop;
	scf_value_t		*val;
	char			**protolist = NULL, *pnamebuf, *valbuf;
	ssize_t			pnamelen, vallen;
	int			numvalues = 0;
	int			propiterret, valiterret, retval = 0;

	/* Services with no "protocol" property are not routing daemons */
	if (ra_get_prop_as_string(h, inst, RA_PG_ROUTEADM, RA_PROP_PROTO,
	    B_TRUE, B_FALSE, NULL, &numvalues, &protolist) == -1) {
		if (scf_error() == SCF_ERROR_NOT_FOUND)
			(void) fprintf(stderr,
			    gettext("%s: %s is not a routing daemon service\n"),
			    myname, inst_fmri);
		else
			(void) fprintf(stderr,
			    gettext("%s: unexpected libscf error: %s\n"),
			    myname, scf_strerror(scf_error()));
		ra_free_prop_values(numvalues, protolist);
		return (-1);
	}
	ra_free_prop_values(numvalues, protolist);

	if (ra_get_pg(h, inst, RA_PG_ROUTING, B_TRUE, B_FALSE, &pg) == -1) {
		if (scf_error() == SCF_ERROR_NOT_FOUND) {
			(void) printf("%s: no %s property group for %s\n",
			    myname, RA_PG_ROUTING, inst_fmri);
			return (0);
		}
		(void) fprintf(stderr,
		    gettext("%s: unexpected libscf error: %s\n"),
		    myname, scf_strerror(scf_error()));
		return (-1);
	}

	(void) printf("%s:\n", inst_fmri);

	/* Create an iterator to walk through all properties */
	if ((propiter = scf_iter_create(h)) == NULL ||
	    (prop = scf_property_create(h)) == NULL ||
	    scf_iter_pg_properties(propiter, pg) != 0) {
		(void) fprintf(stderr, gettext
		    ("%s: could not iterate through properties for %s: %s\n"),
		    myname, inst_fmri, scf_strerror(scf_error()));
	}
	while ((propiterret = scf_iter_next_property(propiter, prop)) == 1) {
		if ((pnamelen = scf_property_get_name(prop, NULL, 0) + 1)
		    == 0) {
			(void) fprintf(stderr, gettext("%s: could not retrieve "
			    "property name for instance %s: %s\n"), myname,
			    inst_fmri, scf_strerror(scf_error()));
			retval = -1;
			break;
		}
		if ((pnamebuf = malloc(pnamelen)) == NULL) {
			(void) fprintf(stderr,
			    gettext("%s: out of memory\n"), myname);
			retval = -1;
			break;
		}
		(void) scf_property_get_name(prop, pnamebuf,
		    pnamelen);
		(void) printf("\t%s = ", pnamebuf);
		if ((valiter = scf_iter_create(h)) == NULL ||
		    (val = scf_value_create(h)) == NULL ||
		    scf_iter_property_values(valiter, prop)
		    != 0) {
			(void) fprintf(stderr, gettext
			    ("%s: could not iterate through "
			    "properties for %s: %s\n"), myname, inst_fmri,
			    scf_strerror(scf_error()));
			scf_value_destroy(val);
			scf_iter_destroy(valiter);
			free(pnamebuf);
			retval = -1;
			break;
		}
		while ((valiterret = scf_iter_next_value(valiter, val)) == 1) {
			if ((vallen = scf_value_get_as_string
			    (val, NULL, 0) + 1) == 0) {
				(void) fprintf(stderr, gettext
				    ("%s: could not retrieve "
				    "property value for instance %s, "
				    "property %s: %s\n"), myname, inst_fmri,
				    pnamebuf, scf_strerror(scf_error()));
				retval = -1;
			} else if ((valbuf = malloc(vallen)) == NULL) {
				(void) fprintf(stderr,
				    gettext("%s: out of memory\n"), myname);
				retval = -1;
			}
			if (retval == -1) {
				scf_iter_destroy(valiter);
				scf_value_destroy(val);
				free(pnamebuf);
				goto out;
			}
			(void) scf_value_get_as_string(val, valbuf, vallen);
			(void) printf("%s ", valbuf);
			free(valbuf);
		}
		(void) printf("\n");
		scf_iter_destroy(valiter);
		scf_value_destroy(val);
		free(pnamebuf);
		if (valiterret == -1) {
			(void) fprintf(stderr,
			    gettext("%s: could not iterate through"
			    "properties for %s: %s\n"), myname, inst_fmri,
			    scf_strerror(scf_error()));
			retval = -1;
			break;
		}
	}
out:
	scf_iter_destroy(propiter);
	scf_property_destroy(prop);
	scf_pg_destroy(pg);
	if (propiterret == -1)
		(void) fprintf(stderr, gettext
		    ("%s: could not iterate through properties for %s: %s\n"),
		    myname, inst_fmri, scf_strerror(scf_error()));
	return (retval);
}

/*
 * Modify property with name stored in passed-in ra_prop_t to have
 * the assocatied values.  Only works for existing properties in
 * the "routing" property group for routing daemon services,  so all
 * routing daemons should place configurable options in that group.
 */
static int
ra_modify_props_cb(void *data, scf_walkinfo_t *wip)
{
	const char		*inst_fmri = wip->fmri;
	scf_instance_t		*inst = wip->inst;
	scf_handle_t		*h = scf_instance_handle(inst);
	ra_prop_t		*raprop = data;
	int			numvalues = 0;
	char			**protolist = NULL;

	/* Services with no "protocol" property are not routing daemons */
	if (ra_get_prop_as_string(h, inst, RA_PG_ROUTEADM, RA_PROP_PROTO,
	    B_TRUE, B_FALSE, NULL, &numvalues, &protolist) == -1) {
		if (scf_error() == SCF_ERROR_NOT_FOUND)
			(void) fprintf(stderr,
			    gettext("%s: %s is not a routing daemon service\n"),
			    myname, inst_fmri);
		else
			(void) fprintf(stderr,
			    gettext("%s: unexpected libscf error: %s\n"),
			    myname, scf_strerror(scf_error()));
		ra_free_prop_values(numvalues, protolist);
		return (-1);
	}
	ra_free_prop_values(numvalues, protolist);

	if (ra_set_prop_from_string(h, inst, RA_PG_ROUTING, raprop->prop_name,
	    SCF_TYPE_INVALID, B_FALSE, raprop->prop_numvalues,
	    (const char **)raprop->prop_values) == -1)
		return (-1);

	(void) smf_refresh_instance(inst_fmri);
	return (0);
}

/*
 * Display FMRI, state for each routing daemon service.
 */

/* ARGSUSED0 */
static int
ra_print_state_cb(void *data, scf_walkinfo_t *wip)
{
	const char		*inst_fmri = wip->fmri;
	scf_instance_t		*inst = wip->inst;
	scf_handle_t		*h = scf_instance_handle(inst);
	char			*inst_state, **protolist = NULL;
	int			numvalues = 0;

	/* Ensure service is a routing daemon */
	if (ra_get_prop_as_string(h, inst, RA_PG_ROUTEADM, RA_PROP_PROTO,
	    B_TRUE, B_FALSE, NULL, &numvalues, &protolist) == -1)
		return (0);
	ra_free_prop_values(numvalues, protolist);

	if ((inst_state = smf_get_state(inst_fmri)) == NULL) {
		(void) fprintf(stderr,
		    gettext("%s: could not retrieve state for %s: %s\n"),
		    myname, inst_fmri, scf_strerror(scf_error()));
		return (-1);
	}
	(void) printf("%27s   %2s\n", inst_state, inst_fmri);
	free(inst_state);

	return (0);
}

static int
ra_get_pg(scf_handle_t *h, scf_instance_t *inst, const char *pgname,
    boolean_t composed, boolean_t required, scf_propertygroup_t **pg)
{
	/* Retrieve (possibly composed) property group for instance */
	if ((*pg = scf_pg_create(h)) == NULL || (composed &&
	    scf_instance_get_pg_composed(inst, NULL, pgname, *pg) != 0) ||
	    (!composed && scf_instance_get_pg(inst, pgname, *pg) != 0)) {
		if (scf_error() == SCF_ERROR_NOT_FOUND) {
			if (required)
				(void) fprintf(stderr, gettext(
				    "%s: no such property group %s\n"),
				    myname, pgname);
			return (-1);
		}
		if (required)
			(void) fprintf(stderr, gettext(
			    "%s: unexpected libscf error: %s\n"), myname,
			    scf_strerror(scf_error()));
		return (-1);
	}
	return (0);
}

static int
ra_get_boolean_prop(scf_handle_t *h, scf_instance_t *inst,
    const char *pgname, const char *propname, boolean_t composed,
    boolean_t required, boolean_t *val)
{
	char	*valstr;

	if (ra_get_single_prop_as_string(h, inst, pgname, propname,
	    composed, required, NULL, &valstr) != 0)
		return (-1);
	*val = strcmp(valstr, RA_PROPVAL_BOOLEAN_TRUE) == 0;
	free(valstr);
	return (0);
}

static int
ra_get_single_prop_as_string(scf_handle_t *h, scf_instance_t *inst,
    const char *pgname, const char *propname, boolean_t composed,
    boolean_t required, scf_type_t *type, char **value)
{
	char	**values;
	int	numvalues = 1;

	if (ra_get_prop_as_string(h, inst, pgname, propname, composed, required,
	    type, &numvalues, &values) == -1)
		return (-1);
	*value = values[0];
	free(values);
	return (0);
}

/*
 * Retrieve property named in propname,  possibly using the composed
 * property group view (union of instance and service-level properties,
 * where instance-level properties override service-level values).
 */
static int
ra_get_prop_as_string(scf_handle_t *h, scf_instance_t *inst,
    const char *pgname, const char *propname, boolean_t composed,
    boolean_t required, scf_type_t *type, int *numvalues, char ***values)
{
	scf_propertygroup_t	*pg = NULL;
	scf_property_t		*prop = NULL;
	scf_iter_t		*valiter = NULL;
	scf_value_t		*val = NULL;
	ssize_t			vallen = 0;
	int			valiterret, i, numvalues_retrieved, ret = 0;

	if (ra_get_pg(h, inst, pgname, composed, required, &pg) == -1)
		return (-1);

	*values = NULL;
	/*
	 * Retrieve values. All values routeadm needs to retrieve
	 * (bar those gathered by routeadm -l), are known to be single-valued.
	 */
	if ((prop = scf_property_create(h)) == NULL)
		goto error;
	if (scf_pg_get_property(pg, propname, prop) != 0) {
		*numvalues = 0;
		if (scf_error() == SCF_ERROR_NOT_FOUND) {
			if (required)
				(void) fprintf(stderr, gettext(
				    "%s: property %s/%s not found\n"),
				    myname, pgname, propname);
			ret = -1;
			goto out;
		}
		goto error;
	}
	if ((val = scf_value_create(h)) == NULL &&
	    scf_property_get_value(prop, val) != 0 ||
	    (valiter = scf_iter_create(h)) == NULL ||
	    scf_iter_property_values(valiter, prop) != 0)
		goto error;
	/* retrieve each value */
	for (numvalues_retrieved = 0;
	    (valiterret = scf_iter_next_value(valiter, val)) == 1;
	    numvalues_retrieved++) {
		if ((vallen = scf_value_get_as_string
		    (val, NULL, 0) + 1) == 0)
			goto error;
		if ((*values = realloc(*values,
		    sizeof (*values) + sizeof (char *))) == NULL ||
		    ((*values)[numvalues_retrieved] = malloc(vallen)) == NULL) {
			(void) fprintf(stderr, gettext(
			    "%s: out of memory\n"), myname);
			ret = -1;
			goto out;
		}
		(void) scf_value_get_as_string(val,
		    (*values)[numvalues_retrieved], vallen);
	}
	if (valiterret == -1)
		goto error;
	/*
	 * if *numvalues != 0, it holds expected number of values.  If a
	 * different number are found, it is an error.
	 */
	if (*numvalues != 0 && *numvalues != numvalues_retrieved) {
		(void) fprintf(stderr, gettext(
		    "%s: got %d values for property %s/%s, expected %d\n"),
		    myname, numvalues_retrieved, pgname, propname, *numvalues);
		ret = -1;
		goto out;
	}
	*numvalues = numvalues_retrieved;

	/* Retrieve property type if required. */
	if (type != NULL)
		(void) scf_property_type(prop, type);

	goto out;
error:
	if (scf_error() == SCF_ERROR_NOT_FOUND) {
		(void) fprintf(stderr, gettext(
		    "%s: property %s not found"), myname, propname);
	} else {
		(void) fprintf(stderr, gettext(
		    "%s: unexpected libscf error: %s, "), myname);
	}
	for (i = 0; i < numvalues_retrieved; i++)
		free((*values)[i]);
	if (*values != NULL)
		free(*values);

	ret = -1;
out:
	if (val != NULL)
		scf_value_destroy(val);
	if (valiter != NULL)
		scf_iter_destroy(valiter);
	if (prop != NULL)
		scf_property_destroy(prop);
	if (pg != NULL)
		scf_pg_destroy(pg);
	return (ret);
}

static void
ra_free_prop_values(int numvalues, char **values)
{
	int	i;
	if (values != NULL) {
		for (i = 0; i < numvalues; i++)
			free(values[i]);
		free(values);
	}
}

static int
ra_set_boolean_prop(scf_handle_t *h, scf_instance_t *inst, const char *pgname,
    const char *prop, boolean_t create, boolean_t propval)
{
	const char	*val = propval ? RA_PROPVAL_BOOLEAN_TRUE :
	    RA_PROPVAL_BOOLEAN_FALSE;

	return (ra_set_prop_from_string(h, inst, pgname, prop, SCF_TYPE_BOOLEAN,
	    create, 1, &val));
}

/*
 * Set the property named in propname to the values passed in in the propvals
 * array.  Only create a new property if "create" is true.
 */
static int
ra_set_prop_from_string(scf_handle_t *h, scf_instance_t *inst,
    const char *pgname, const char *propname, scf_type_t proptype,
    boolean_t create, int numpropvals, const char **propvals)
{
	scf_propertygroup_t	*instpg = NULL, *cpg = NULL;
	scf_type_t		oldproptype, newproptype = proptype;
	scf_property_t		*prop = NULL;
	scf_value_t		**values = NULL;
	scf_transaction_t	*tx = NULL;
	scf_transaction_entry_t	*ent = NULL;
	boolean_t		new = B_FALSE;
	int			i, retval, numvalues = 0, ret = 0;
	char			*pgtype = NULL, **ovalues;
	ssize_t			typelen;

	/* Firstly, does property exist? If not, and create is false, bail */
	if (ra_get_prop_as_string(h, inst, pgname, propname, B_TRUE,
	    B_FALSE, &oldproptype, &numvalues, &ovalues) == -1) {
		if (scf_error() != SCF_ERROR_NOT_FOUND)
			goto error;
		if (!create) {
			(void) fprintf(stderr, gettext(
			    "%s: no such property %s/%s\n"), myname, pgname,
			    propname);
			return (-1);
		}
	} else
		ra_free_prop_values(numvalues, ovalues);

	/* Use old property type */
	if (proptype == SCF_TYPE_INVALID)
		newproptype = oldproptype;

	/*
	 * Does property group exist at instance level?  If not, we need to
	 * create it,  since the composed view of the property group did
	 * contain the property.  We never modify properties at the service
	 * level,  as it`s possible that multiple instances will inherit those
	 * settings.
	 */
	if (ra_get_pg(h, inst, pgname, B_FALSE, B_FALSE, &instpg) == -1) {
		if (scf_error() != SCF_ERROR_NOT_FOUND)
			goto error;
		/* Ensure pg exists at service level, get composed pg */
		if (ra_get_pg(h, inst, pgname, B_TRUE, B_FALSE, &cpg) == -1)
			goto error;

		/* Create instance-level property group */
		if ((typelen = scf_pg_get_type(cpg, NULL, 0) + 1) == 0)
			goto error;
		if ((pgtype = malloc(typelen)) == NULL) {
			(void) fprintf(stderr, gettext(
			    "%s: out of memory\n"), myname);
			goto error;
		}
		(void) scf_pg_get_type(cpg, pgtype, typelen);
		if ((instpg = scf_pg_create(h)) == NULL ||
		    scf_instance_add_pg(inst, pgname, pgtype, 0, instpg)
		    == -1) {
			(void) fprintf(stderr, gettext(
			    "%s: could not create property group %s\n"),
			    myname, pgname);
			goto error;
		}
	}
	if ((prop = scf_property_create(h)) == NULL)
		goto error;
	if ((values = calloc(numpropvals, sizeof (scf_value_t *))) == NULL) {
		(void) fprintf(stderr, gettext("%s: out of memory"), myname);
		goto error;
	}
	if (scf_pg_get_property(instpg, propname, prop) != 0) {
		/* New property? */
		if (scf_error() == SCF_ERROR_NOT_FOUND)
			new = B_TRUE;
		else
			goto error;
	}
	if ((tx = scf_transaction_create(h)) == NULL ||
	    (ent = scf_entry_create(h)) == NULL)
		goto error;
retry:
	if (scf_transaction_start(tx, instpg) == -1)
		goto error;
	if (new) {
		if (scf_transaction_property_new(tx, ent, propname,
		    newproptype) == -1)
			goto error;
	} else if (scf_transaction_property_change(tx, ent, propname,
	    newproptype) == -1)
		goto error;
	for (i = 0; i < numpropvals; i++) {
		if ((values[i] = scf_value_create(h)) == NULL ||
		    scf_value_set_from_string(values[i], newproptype,
		    propvals[i] == NULL ? "": propvals[i]) == -1 ||
		    scf_entry_add_value(ent, values[i]) != 0)
			goto error;
	}
	retval = scf_transaction_commit(tx);
	if (retval == 0) {
		scf_transaction_reset(tx);
		if (scf_pg_update(instpg) == -1)
			goto error;
		goto retry;
	}
	if (retval == -1)
		goto error;
	goto out;
error:
	switch (scf_error()) {
	case SCF_ERROR_INVALID_ARGUMENT:
		(void) fprintf(stderr, gettext(
		    "%s: invalid value for property %s/%s\n"), myname,
		    pgname, propname);
		break;
	case SCF_ERROR_NOT_FOUND:
		(void) fprintf(stderr, gettext(
		    "%s: no such property %s/%s\n"), myname,
		    pgname, propname);
		break;
	default:
		(void) fprintf(stderr, gettext(
		    "%s: unexpected libscf error: %s\n"), myname,
		    scf_strerror(scf_error()));
		break;
	}
	ret = -1;
out:
	if (tx != NULL)
		scf_transaction_destroy(tx);
	if (ent != NULL)
		scf_entry_destroy(ent);
	if (values != NULL) {
		for (i = 0; i < numpropvals; i++) {
			if (values[i] != NULL)
				scf_value_destroy(values[i]);
		}
		free(values);
	}
	if (prop != NULL)
		scf_property_destroy(prop);
	if (cpg != NULL)
		scf_pg_destroy(cpg);
	if (instpg != NULL)
		scf_pg_destroy(instpg);
	if (pgtype != NULL)
		free(pgtype);
	return (ret);
}

/*
 * This function gathers configuration from the legacy /etc/inet/routing.conf,
 * if any, and sets the appropriate variable values accordingly.  Once
 * these are set,  the legacy daemons are checked to see if they have
 * SMF counterparts (ra_check_legacy_daemons()).  If they do, the
 * configuration is upgraded.  Finally,  the legacy option settings are
 * applied,  enabling/disabling the routing/forwarding services as
 * appropriate.
 */
static int
ra_upgrade_from_legacy_conf(void)
{
	scf_handle_t	*h = NULL;
	scf_instance_t	*inst = NULL;
	int		ret = 0, i, r;
	boolean_t	old_conf_read;
	ravar_t		*routing_svcs = ra_str2var(RA_VAR_ROUTING_SVCS);

	/*
	 * First, determine if we have already upgraded - if "routing-conf-read"
	 * is true, we bail.  The use of a boolean property indicating if
	 * routing.conf has been read and applied might seem a lot more
	 * work than simply copying routing.conf aside,  but leaving the
	 * file in place allows users to downgrade and have their old
	 * routing configuration still in place.
	 */
	if ((h = scf_handle_create(SCF_VERSION)) == NULL ||
	    scf_handle_bind(h) == -1) {
		(void) fprintf(stderr, gettext(
		    "%s: cannot connect to SMF repository\n"), myname);
		ret = -1;
		goto out;
	}
	if ((inst = scf_instance_create(h)) == NULL ||
	    scf_handle_decode_fmri(h, RA_INSTANCE_ROUTING_SETUP,
	    NULL, NULL, inst, NULL, NULL, SCF_DECODE_FMRI_EXACT) == -1) {
		(void) fprintf(stderr, gettext(
		    "%s: unexpected libscf error: %s\n"), myname,
		    scf_strerror(scf_error()));
		ret = -1;
		goto out;
	}
	if (ra_get_boolean_prop(h, inst, RA_PG_ROUTEADM,
	    RA_PROP_ROUTING_CONF_READ, B_TRUE, B_TRUE, &old_conf_read) == -1) {
		ret = -1;
		goto out;
	}

	if (old_conf_read)
		goto out;

	/*
	 * Now set "routing-conf-read" to true so we don`t reimport legacy
	 * configuration again.
	 */
	if (ra_set_boolean_prop(h, inst, RA_PG_ROUTEADM,
	    RA_PROP_ROUTING_CONF_READ, B_FALSE, B_TRUE) == -1)
		return (-1);
	(void) smf_refresh_instance(RA_INSTANCE_ROUTING_SETUP);

	ra_resetvars(NULL);

	/* First, gather values from routing.conf */
	if ((r = ra_parseconf()) == -1) {
		ret = -1;
		goto out;
	}
	/* No routing.conf file found */
	if (r == 0)
		goto out;
	/*
	 * Now, set the options/variables gathered.  We set variables first,
	 * as we cannot enable routing before we determine the daemons
	 * to enable.
	 */

	for (i = 0; ra_vars[i].var_name != NULL; i++) {
		/* Skip routing-svcs var, not featured in legacy config */
		if (strcmp(ra_vars[i].var_name, RA_VAR_ROUTING_SVCS) == 0)
			continue;
		if (ra_smf_cb(ra_set_persistent_var_cb, ra_vars[i].var_fmri,
		    &(ra_vars[i])) == -1) {
			ret = -1;
			goto out;
		}
	}
	/* Clear routing-svcs value */
	if (ra_smf_cb(ra_set_persistent_var_cb, routing_svcs->var_fmri,
	    routing_svcs) == -1) {
		ret = -1;
		goto out;
	}

	if (ra_check_legacy_daemons() == -1) {
		ret = -1;
		goto out;
	}

	for (i = 0; ra_opts[i].opt_name != NULL; i++) {
		if (ra_smf_cb(ra_set_persistent_opt_cb, ra_opts[i].opt_fmri,
		    &(ra_opts[i])) == -1 ||
		    ra_smf_cb(ra_set_default_opt_cb,
		    ra_opts[i].opt_default_fmri, &(ra_opts[i])) == -1) {
			ret = -1;
			break;
		}
	}
out:
	if (inst != NULL)
		scf_instance_destroy(inst);
	if (h != NULL)
		scf_handle_destroy(h);

	return (ret);
}

/*
 *
 * Return the number of non-loopback IPv6 addresses configured.  This answers
 * the generic question, "is IPv6 configured?".  We only start in.ndpd if IPv6
 * is configured, and we also only enable IPv6 routing daemons if IPv6 is
 * enabled.
 */
static int
ra_numv6intfs(void)
{
	static int	num = -1;
	int		cnt;
	struct ifaddrs *ifp_head, *ifp;

	if (num != -1)
		return (num);

	if (getifaddrs(&ifp_head) < 0)
		return (0);

	cnt = 0;
	for (ifp = ifp_head; ifp; ifp = ifp->ifa_next) {
		if (!(ifp->ifa_flags & IFF_LOOPBACK) &&
		    (ifp->ifa_flags & IFF_IPV6))
			cnt++;
	}

	freeifaddrs(ifp_head);
	return (num = cnt);
}

/*
 * Parse the configuration file and fill the ra_opts array with opt_value
 * and opt_default_value values, and the ra_vars array with var_value and
 * var_default_value values.  Then copy aside routing.conf so it will not
 * be read by future invokations of routeadm.
 */
static int
ra_parseconf(void)
{
	FILE	*fp;
	uint_t	lineno;
	char	line[RA_MAX_CONF_LINE];
	char	*cp, *confstr;
	raopt_t	*raopt;
	ravar_t *ravar;

	if ((fp = fopen(RA_CONF_FILE, "r")) == NULL) {
		/*
		 * There's no config file, so we simply return as there
		 * is no work to do.
		 */
		return (0);
	}

	for (lineno = 1; fgets(line, sizeof (line), fp) != NULL; lineno++) {
		if (line[strlen(line) - 1] == '\n')
			line[strlen(line) - 1] = '\0';

		cp = line;

		/* Skip leading whitespace */
		while (isspace(*cp))
			cp++;

		/* Skip comment lines and empty lines */
		if (*cp == '#' || *cp == '\0')
			continue;

		/*
		 * Anything else must be of the form:
		 * <option> <value> <default_value>
		 */
		if ((confstr = strtok(cp, " ")) == NULL) {
			(void) fprintf(stderr,
			    gettext("%1$s: %2$s: invalid entry on line %3$d\n"),
			    myname, RA_CONF_FILE, lineno);
			continue;
		}

		if ((raopt = ra_str2opt(confstr)) != NULL) {
			if (ra_parseopt(confstr, lineno, raopt) != 0) {
				(void) fclose(fp);
				return (-1);
			}
		} else if ((ravar = ra_str2var(confstr)) != NULL) {
			if (ra_parsevar(confstr, ravar) != 0) {
				(void) fclose(fp);
				return (-1);
			}
		} else {
			(void) fprintf(stderr,
			    gettext("%1$s: %2$s: invalid option name on "
				"line %3$d\n"),
			    myname, RA_CONF_FILE, lineno);
			continue;
		}
	}

	(void) fclose(fp);

	return (1);
}

static int
ra_parseopt(char *confstr, int lineno, raopt_t *raopt)
{
	oval_t oval, d_oval;

	if ((confstr = strtok(NULL, " ")) == NULL) {
		(void) fprintf(stderr,
		    gettext("%1$s: %2$s: missing value on line %3$d\n"),
		    myname, RA_CONF_FILE, lineno);
		return (0);
	}
	if ((oval = ra_str2oval(confstr)) == OPT_INVALID) {
		(void) fprintf(stderr,
		    gettext("%1$s: %2$s: invalid option "
			"value on line %3$d\n"),
		    myname, RA_CONF_FILE, lineno);
		return (0);
	}
	if (oval != OPT_DEFAULT)
		raopt->opt_enabled = oval == OPT_ENABLED;

	if ((confstr = strtok(NULL, " ")) == NULL) {
		(void) fprintf(stderr,
		    gettext("%1$s: %2$s: missing revert "
			"value on line %3$d\n"),
		    myname, RA_CONF_FILE, lineno);
		return (0);
	}
	if ((d_oval = ra_str2oval(confstr)) == OPT_INVALID) {
		(void) fprintf(stderr,
		    gettext("%1$s: %2$s: invalid revert "
			"value on line %3$d\n"),
		    myname, RA_CONF_FILE, lineno, confstr);
		return (0);
	}
	raopt->opt_default_enabled = d_oval == OPT_ENABLED;
	if (oval == OPT_DEFAULT)
		raopt->opt_enabled = d_oval == OPT_ENABLED;

	/*
	 * Set ipv4(6)-routing-set property as appropriate on upgrading
	 * routing.conf.  If option was default, set this value to false,
	 * as this indicates the administrator has not explicitly enabled
	 * or disabled ipv4(6)-routing.  The ipv4-routing-set value is used
	 * in the routing-setup service, and if it is false, ipv4-routing
	 * is enabled in the case where no default route can be determined.
	 */
	if (raopt->opt_flags & (RA_SVC_FLAG_IPV4_ROUTING |
	    RA_SVC_FLAG_IPV6_ROUTING)) {
		if (ra_smf_cb(oval == OPT_DEFAULT ? ra_routing_opt_unset_cb :
		    ra_routing_opt_set_cb, raopt->opt_default_fmri, raopt)
		    == -1)
			return (-1);
	}
	return (0);
}

static int
ra_parsevar(char *confstr, ravar_t *ravar)
{
	confstr = strtok(NULL, "=");
	if (confstr == NULL) {
		/*
		 * This isn't an error condition, it simply means that the
		 * variable has no value.
		 */
		ravar->var_value = NULL;
		return (0);
	}

	if ((ravar->var_value = strdup(confstr)) == NULL) {
		(void) fprintf(stderr, gettext("%s: "
		    "unable to allocate memory\n"), myname);
		return (-1);
	}
	return (0);
}

/* Convert a string to an option value. */
static oval_t
ra_str2oval(const char *valstr)
{
	if (strcmp(valstr, "enabled") == 0)
		return (OPT_ENABLED);
	else if (strcmp(valstr, "disabled") == 0)
		return (OPT_DISABLED);
	else if (strcmp(valstr, "default") == 0)
		return (OPT_DEFAULT);
	return (OPT_INVALID);
}

static raopt_t *
ra_str2opt(const char *optnamestr)
{
	int	i;

	for (i = 0; ra_opts[i].opt_name != NULL; i++) {
		if (strcmp(optnamestr, ra_opts[i].opt_name) == 0)
			break;
	}
	if (ra_opts[i].opt_name == NULL)
		return (NULL);
	return (&ra_opts[i]);
}

/*
 * Reset all option values previously gathered to B_FALSE.
 */
static void
ra_resetopts(void)
{
	int	i;

	for (i = 0; ra_opts[i].opt_name != NULL; i++) {
		ra_opts[i].opt_enabled = B_FALSE;
		ra_opts[i].opt_default_enabled = B_FALSE;
	}
}

static ravar_t *
ra_str2var(const char *varnamestr)
{
	int	i;
	for (i = 0; ra_vars[i].var_name != NULL; i++) {
		if (strcmp(varnamestr, ra_vars[i].var_name) == 0)
			break;
	}
	if (ra_vars[i].var_name == NULL)
		return (NULL);
	return (&ra_vars[i]);
}

/*
 * Reset variable values previously gathered to NULL.
 */
static void
ra_resetvars(const char *proto)
{
	int	i;
	for (i = 0; ra_vars[i].var_name != NULL; i++) {
		if (proto != NULL &&
		    !VAR_PROTO_MATCH(ra_vars[i].var_name, proto))
			continue;
		if (ra_vars[i].var_value != NULL)
			free(ra_vars[i].var_value);
		ra_vars[i].var_value = NULL;
		if (ra_vars[i].var_default_value != NULL)
			free(ra_vars[i].var_default_value);
		ra_vars[i].var_default_value = NULL;
	}
}

/*
 * Given an option name, this function provides an internationalized, human
 * readable version of the option name.
 */
static char *
ra_intloptname(const char *optname)
{
	if (strcmp(optname, RA_OPT_IPV4_FORWARDING) == 0)
		return (gettext("IPv4 forwarding"));
	else if (strcmp(optname, RA_OPT_IPV4_ROUTING) == 0)
		return (gettext("IPv4 routing"));
	else if (strcmp(optname, RA_OPT_IPV6_FORWARDING) == 0)
		return (gettext("IPv6 forwarding"));
	else if (strcmp(optname, RA_OPT_IPV6_ROUTING) == 0)
		return (gettext("IPv6 routing"));
	else if (strcmp(optname, RA_VAR_IPV4_ROUTING_DAEMON) == 0)
		return (gettext("IPv4 routing daemon"));
	else if (strcmp(optname, RA_VAR_IPV4_ROUTING_DAEMON_ARGS) == 0)
		return (gettext("IPv4 routing daemon args"));
	else if (strcmp(optname, RA_VAR_IPV4_ROUTING_STOP_CMD) == 0)
		return (gettext("IPv4 routing daemon stop"));
	else if (strcmp(optname, RA_VAR_IPV6_ROUTING_DAEMON) == 0)
		return (gettext("IPv6 routing daemon"));
	else if (strcmp(optname, RA_VAR_IPV6_ROUTING_DAEMON_ARGS) == 0)
		return (gettext("IPv6 routing daemon args"));
	else if (strcmp(optname, RA_VAR_IPV6_ROUTING_STOP_CMD) == 0)
		return (gettext("IPv6 routing daemon stop"));
	else if (strcmp(optname, RA_VAR_ROUTING_SVCS) == 0)
		return (gettext("Routing services"));
	/*
	 * If we get here, there's a bug and someone should trip over this
	 * NULL pointer.
	 */
	return (NULL);
}
