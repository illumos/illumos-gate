/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2023 Oxide Computer Company
 */

/*
 * This facility provider works with libhotplug to use its private properties to
 * try and provide LED functionality. To work with libhotplug's bus-specific
 * private options (which really here is all about PCIe) we require that the
 * caller give us the name of the slot as cfgadm and others know about it. This
 * varies on the system.
 *
 * Our assumption is that the name of this is the name of the 'connector' in
 * libhotplug parlance and that by reading the /dev/cfg/<name> link, we'll
 * figure out where in the tree it is.
 *
 * The LED method on this facility does not attempt to prescribe meaning to the
 * actual logical topology facility type. The assumption we have is that the
 * caller has set up what makes sense. That means if they want to use the power
 * LED for attention or something else entirely, that is their prerogative. For
 * all of this to work, the members of the 'libhp' property group defined below
 * are required.
 *
 * "connector" (string): This is the name of the connector to look for.
 *
 * "option" (string): This is the name of the libhotplug option to actually look
 * for. For a PCI class device this is generally something like "attn_led",
 * "power_led", etc. or similar.
 *
 * "opt_on" (string): This indicates the value of the option that should be set
 * when we are turning it on. This must be one of the supported option strings.
 * Currently there is no validation of the option string. When querying for
 * whether the indicator is on or off in libtopo, if we get a value that is not
 * this string, then we will consider the indicator off.
 *
 * "opt_off" (string): This indicates the value of the option that should be set
 * when we are turning it off. This should generally by the 'default' option for
 * cases where the indicator is otherwise used.
 */

#include <sys/fm/protocol.h>
#include <fm/topo_mod.h>
#include <libhotplug.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

/*
 * The following are the members of the libhp property group that we expect to
 * exist. These values are defined above.
 */
#define	TOPO_PGROUP_LIBHP	"libhp"
#define	TOPO_PGROUP_LIBHP_CONNECTOR	"connector"
#define	TOPO_PGROUP_LIBHP_OPTION	"option"
#define	TOPO_PGROUP_LIBHP_OPT_ON	"opt_on"
#define	TOPO_PGROUP_LIBHP_OPT_OFF	"opt_off"
#define	LIBHP_OFF_MODE_VALUE		"value"
#define	LIBHP_OFF_MODE_CONN_POWER	"conn_power"

/*
 * This is the approximate buffer size we expect to use construct the
 * opt_name=opt_val buffers in here.
 */
#define	FAC_PROV_LIBHP_OPTLEN	128

/*
 * Given the name for a connector, attempt to find the corresponding hp_node_t.
 * As mentioned in the introduction to this module, the connector name is
 * expected to be something in the form of a /dev/cfg/<name> link that'll point
 * back to a /devices minor node. This link will have a fair bit of data before
 * it gets back to a /devices part. So we'll find that and move past that.
 */
static hp_node_t
fac_prov_libhp_find_node(topo_mod_t *mod, const char *conn)
{
	char cfg[PATH_MAX], link[PATH_MAX];
	ssize_t ret;
	const char *prefix = "/devices";
	char *start, *end;
	hp_node_t node;

	if (snprintf(cfg, sizeof (cfg), "/dev/cfg/%s", conn) >= sizeof (cfg)) {
		topo_mod_dprintf(mod, "failed to construct /dev/cfg path");
		return (NULL);
	}

	ret = readlink(cfg, link, sizeof (link));
	if (ret < 0) {
		topo_mod_dprintf(mod, "failed to readlink %s: %s", cfg,
		    strerror(errno));
		return (NULL);
	}

	if ((size_t)ret >= sizeof (link)) {
		topo_mod_dprintf(mod, "cannot process readlink of %s: link "
		    "did not fit in buffer", cfg);
		return (NULL);
	}
	link[ret] = '\0';

	start = strstr(link, prefix);
	if (start == NULL) {
		topo_mod_dprintf(mod, "failed to find %s in %s", prefix, link);
		return (NULL);
	}

	start += strlen(prefix);
	end = strchr(start, ':');
	if (end == NULL) {
		topo_mod_dprintf(mod, "failed to find ':' to indicate start of "
		    "minor node in %s", start);
		return (NULL);
	}
	*end = '\0';

	topo_mod_dprintf(mod, "attempting to hp_init %s %s", start, conn);
	node = hp_init(start, conn, 0);
	if (node == NULL) {
		topo_mod_dprintf(mod, "failed to init hp node: %s\n",
		    strerror(errno));
		return (NULL);
	}

	return (node);
}

static int
fac_prov_libhp_set_val(topo_mod_t *mod, hp_node_t hp, const char *opt_name,
    const char *val)
{
	int ret;
	char buf[FAC_PROV_LIBHP_OPTLEN];
	char *res = NULL;

	if (snprintf(buf, sizeof (buf), "%s=%s", opt_name, val) >=
	    sizeof (buf)) {
		topo_mod_dprintf(mod, "failed to construct option buf");
		return (topo_mod_seterrno(mod, EMOD_UNKNOWN));
	}

	ret = hp_set_private(hp, buf, &res);
	if (ret != 0) {
		topo_mod_dprintf(mod, "failed to set prop %s: %s", buf,
		    strerror(ret));
		return (topo_mod_seterrno(mod, EMOD_UNKNOWN));
	}
	free(res);

	return (0);
}

static int
fac_prov_libhp_get_opt(topo_mod_t *mod, hp_node_t hp, const char *opt_name,
    const char *opt_on, nvlist_t **nvout)
{
	int ret;
	char *val;
	uint32_t state;
	nvlist_t *nvl;
	char buf[FAC_PROV_LIBHP_OPTLEN];

	if (snprintf(buf, sizeof (buf), "%s=%s", opt_name, opt_on) >=
	    sizeof (buf)) {
		topo_mod_dprintf(mod, "failed to construct option buf");
		return (topo_mod_seterrno(mod, EMOD_UNKNOWN));
	}

	ret = hp_get_private(hp, opt_name, &val);
	if (ret != 0) {
		topo_mod_dprintf(mod, "failed to get hp node private prop "
		    "%s: %s", opt_name, strerror(ret));
		return (topo_mod_seterrno(mod, EMOD_UNKNOWN));
	}

	topo_mod_dprintf(mod, "got hp node opt %s", val);
	if (strcmp(val, buf) == 0) {
		state = TOPO_LED_STATE_ON;
	} else {
		state = TOPO_LED_STATE_OFF;
	}
	free(val);

	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0 ||
	    nvlist_add_string(nvl, TOPO_PROP_VAL_NAME, TOPO_LED_MODE) != 0 ||
	    nvlist_add_uint32(nvl, TOPO_PROP_VAL_TYPE, TOPO_TYPE_UINT32) != 0 ||
	    nvlist_add_uint32(nvl, TOPO_PROP_VAL_VAL, state) != 0) {
		topo_mod_dprintf(mod, "failed to construct output nvl for "
		    "libhp node state");
		nvlist_free(nvl);
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	*nvout = nvl;
	return (0);
}

static int
fac_prov_libhp_opt_set(topo_mod_t *mod, tnode_t *tn, topo_version_t vers,
    nvlist_t *in, nvlist_t **nvout)
{
	int err, ret = -1;
	char *conn = NULL, *opt_name = NULL, *opt_on = NULL, *opt_off = NULL;
	hp_node_t hp = NULL;
	nvlist_t *pargs;

	if (vers != 0) {
		return (topo_mod_seterrno(mod, ETOPO_METHOD_VERNEW));
	}

	if (topo_prop_get_string(tn, TOPO_PGROUP_LIBHP,
	    TOPO_PGROUP_LIBHP_CONNECTOR, &conn, &err) != 0 ||
	    topo_prop_get_string(tn, TOPO_PGROUP_LIBHP,
	    TOPO_PGROUP_LIBHP_OPTION, &opt_name, &err) != 0 ||
	    topo_prop_get_string(tn, TOPO_PGROUP_LIBHP,
	    TOPO_PGROUP_LIBHP_OPT_ON, &opt_on, &err) != 0 ||
	    topo_prop_get_string(tn, TOPO_PGROUP_LIBHP,
	    TOPO_PGROUP_LIBHP_OPT_OFF, &opt_off, &err) != 0) {
		topo_mod_dprintf(mod, "failed to get required libhp props: %s",
		    topo_strerror(err));
		(void) topo_mod_seterrno(mod, err);
		goto out;
	}

	hp = fac_prov_libhp_find_node(mod, conn);
	if (hp == NULL) {
		(void) topo_mod_seterrno(mod, EMOD_UNKNOWN);
		goto out;
	}

	if ((nvlist_lookup_nvlist(in, TOPO_PROP_PARGS, &pargs) == 0) &&
	    nvlist_exists(pargs, TOPO_PROP_VAL_VAL)) {
		uint32_t val;

		err = nvlist_lookup_uint32(pargs, TOPO_PROP_VAL_VAL, &val);
		if (err != 0) {
			ret = topo_mod_seterrno(mod, EMOD_NVL_INVAL);
			goto out;
		}

		switch (val) {
		case TOPO_LED_STATE_ON:
			ret = fac_prov_libhp_set_val(mod, hp, opt_name, opt_on);
			break;
		case TOPO_LED_STATE_OFF:
			ret = fac_prov_libhp_set_val(mod, hp, opt_name,
			    opt_off);
			break;
		default:
			topo_mod_dprintf(mod, "unknown LED mode: 0x%x\n", val);
			ret = topo_mod_seterrno(mod, EMOD_NVL_INVAL);
			break;
		}
	} else {
		ret = fac_prov_libhp_get_opt(mod, hp, opt_name, opt_on, nvout);
	}

out:
	topo_mod_strfree(mod, conn);
	topo_mod_strfree(mod, opt_name);
	topo_mod_strfree(mod, opt_on);
	topo_mod_strfree(mod, opt_off);
	if (hp != NULL) {
		hp_fini(hp);
	}
	return (ret);
}

static const topo_method_t fac_prov_libhp_methods[] = {
	{ "libhp_opt_set", TOPO_PROP_METH_DESC, 0,
	    TOPO_STABILITY_INTERNAL, fac_prov_libhp_opt_set },
	{ NULL }
};

static int
topo_fac_prov_libhp_enum(topo_mod_t *mod, tnode_t *tn, const char *name,
    topo_instance_t min, topo_instance_t max, void *modarg, void *data)
{
	const char *tname = topo_node_name(tn);
	topo_instance_t inst = topo_node_instance(tn);
	int flags = topo_node_flags(tn);

	topo_mod_dprintf(mod, "asked to enum %s [%" PRIu64 ", %" PRIu64 "] on "
	    "%s[%" PRIu64 "]", name, min, max, tname, inst);

	if (flags != TOPO_NODE_FACILITY) {
		topo_mod_dprintf(mod, "node %s[%" PRIu64 "] has unexpected "
		    "flags: 0x%x", tname, inst, flags);
		return (-1);
	}

	if (topo_method_register(mod, tn, fac_prov_libhp_methods) != 0) {
		topo_mod_dprintf(mod, "failed to register libhp facility "
		    "methods: %s", topo_mod_errmsg(mod));
		return (-1);
	}

	return (0);
}

static const topo_modops_t fac_prov_libhp_ops = {
	topo_fac_prov_libhp_enum, NULL
};

static const topo_modinfo_t fac_prov_libhp_mod = {
	"libhotplug facility provider", FM_FMRI_SCHEME_HC, TOPO_VERSION,
	&fac_prov_libhp_ops
};

int
_topo_init(topo_mod_t *mod, topo_version_t version)
{
	if (getenv("TOPOFACLIBHPDEBUG") != NULL)
		topo_mod_setdebug(mod);

	return (topo_mod_register(mod, &fac_prov_libhp_mod, TOPO_VERSION));
}

void
_topo_fini(topo_mod_t *mod)
{
	topo_mod_unregister(mod);
}
