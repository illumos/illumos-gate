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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * SATA libtopo enumerator plugin
 */

#include <sys/types.h>
#include <sys/bitmap.h>
#include <sys/param.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include <alloca.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <libnvpair.h>
#include <sys/fm/protocol.h>
#include <fm/topo_mod.h>
#include <libdevinfo.h>
#include <config_admin.h>
#include <smbios.h>
#include <dirent.h>
#include <libgen.h>
#include <assert.h>
#include <sys/dkio.h>
#include <pthread.h>
#include <fm/libdiskstatus.h>
#include <sys/fm/io/scsi.h>
#include <devid.h>

#include "sata.h"
#include "sfx4500_props.h"

#define	MAX_SATA_DEV_PROPS		48 + 1 /* the terminator */
#define	MAX_ACTION_RULES		10

#define	MAX_MACHNAMELEN			256

/*
 * Given a /devices path for a whole disk, appending this extension gives the
 * path to a raw device that can be opened.
 */
#if defined(__i386) || defined(__amd64)
#define	PHYS_EXTN	":q,raw"
#elif defined(__sparc) || defined(__sparcv9)
#define	PHYS_EXTN	":c,raw"
#else
#error	Unknown architecture
#endif

struct sata_machine_specific_properties *machprops[] = {
	&SFX4500_machprops, NULL
};

static const topo_pgroup_info_t io_pgroup =
	{ TOPO_PGROUP_IO, TOPO_STABILITY_PRIVATE, TOPO_STABILITY_PRIVATE, 1 };

static const topo_pgroup_info_t storage_pgroup = {
	TOPO_STORAGE_PGROUP,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

int _topo_init(topo_mod_t *mod);
void _topo_fini(topo_mod_t *mod);

static char *devpath_from_asru(topo_mod_t *mp, tnode_t *pnode, int *dpathlen);
static tnode_t *node_create(topo_mod_t *mod, tnode_t *pnode, const char *name,
    int instance, boolean_t add_fru, nvlist_t *fru, nvlist_t *asru,
    char *label, cfga_list_data_t *, int *err);
static char *trimdup(const char *s, int *slen, topo_mod_t *mod);
static boolean_t get_machine_name(char **name, int *namelen, topo_mod_t *mod);
static int sata_minorname_to_ap(char *minorname, char **ap, int *apbuflen,
    cfga_list_data_t **list_array, topo_mod_t *mod);
static sata_dev_prop_t *lookup_sdp_by_minor(char *minorpath);
static boolean_t find_physical_disk_node(char *physpath, int pathbuflen,
    int portnum, topo_mod_t *mod);
static char *devpath_to_devid(char *devpath);
static int sata_maximum_port(char *dpath, topo_mod_t *mod);
static void sata_add_port_props(tnode_t *cnode, sata_dev_prop_t *sdp, int *err);
static void sata_port_add_private_props(tnode_t *cnode, char *minorpath,
    int *err);
static void sata_info_to_fru(char *info, char **model, int *modlen,
    char **manuf, int *manulen, char **serial, int *serlen, char **firm,
    int *firmlen, topo_mod_t *mod);
static void sata_add_disk_props(tnode_t *cnode, const char *physpath,
    cfga_list_data_t *cfgap, int *err, topo_mod_t *mod);
static boolean_t is_sata_controller(char *dpath);
static int sata_disks_create(topo_mod_t *mod, tnode_t *pnode, const char *name,
    int portnum, cfga_list_data_t *cfglist, int ndisks, int *err);
static int sata_port_create(topo_mod_t *mod, tnode_t *pnode, const char *name,
    topo_instance_t min, topo_instance_t max);
static int sata_enum(topo_mod_t *mod, tnode_t *pnode, const char *name,
    topo_instance_t min, topo_instance_t max, void *notused1, void *notused2);
static int sata_disk_status(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
static void sata_release(topo_mod_t *mod, tnode_t *nodep);

/*
 * Methods for SATA disks.  This is used by the disk-transport module to
 * generate ereports based off SCSI disk status.  Unlike the present method,
 * this can only function when we have a /devices path (i.e. the disk is
 * configured) and so must be a function of the disk itself.
 */
static const topo_method_t sata_disk_methods[] = {
	{ TOPO_METH_DISK_STATUS, TOPO_METH_DISK_STATUS_DESC,
	    TOPO_METH_DISK_STATUS_VERSION, TOPO_STABILITY_INTERNAL,
	    sata_disk_status },
	{ NULL }
};

/*
 * Since the global data is only initialized ONCE in _topo_init
 * and multiple threads that use libtopo can cause _topo_init to
 * be called, the flag and lock here enable only the first to enter
 * _topo_init to initialize the global data.  After that, it's all
 * read-only.  The global data used here could have been stored in
 * the node-private data area, but that's overkill, because all data
 * items will not change once they are set -- they depend only on
 * the machine on which this module executes.
 */
static boolean_t global_data_initted = B_FALSE;
static pthread_mutex_t global_data_mutex = PTHREAD_MUTEX_INITIALIZER;
static char machname[MAX_MACHNAMELEN];
static action_ruleset_t *ruleset = NULL;
static sata_dev_prop_t *sata_dev_props = NULL;
static const char *pgroupname = NULL;


static const topo_modops_t sata_ops =
	{ sata_enum, sata_release };

static const topo_modinfo_t sata_info =
	{ "sata", FM_FMRI_SCHEME_HC, SATA_VERSION, &sata_ops };


static void
sata_release(topo_mod_t *mod, tnode_t *nodep)
{
	topo_method_unregister_all(mod, nodep);
	topo_node_unbind(nodep);
}

static char *
tp_strdup(topo_mod_t *mp, const char *str, int *slen)
{
	char *rv;
	int len = strlen(str) + 1;

	rv = topo_mod_alloc(mp, len);

	if (rv != NULL) {
		bcopy(str, rv, len);
		*slen = len;
	}

	return (rv);
}

static char *
devpath_from_asru(topo_mod_t *mp, tnode_t *pnode, int *dpathlen)
{
	nvlist_t *asru;
	char *scheme;
	char *dpath;
	int e;

	if (topo_node_asru(pnode, &asru, NULL, &e) != 0) {
		topo_mod_dprintf(mp, "Parent has no ASRU?\n");
		return (NULL);
	}

	if (nvlist_lookup_string(asru, FM_FMRI_SCHEME, &scheme) != 0 ||
	    strcasecmp(scheme, FM_FMRI_SCHEME_DEV) != 0 ||
	    nvlist_lookup_string(asru, FM_FMRI_DEV_PATH, &dpath) != 0) {
		nvlist_free(asru);
		topo_mod_dprintf(mp,
		    "Bad or missing %s in ASRU?\n", FM_FMRI_DEV_PATH);
		return (NULL);
	}
	/*
	 * dup the string before the nvlist_free() to get a copy before it's
	 * freed
	 */
	dpath = tp_strdup(mp, dpath, dpathlen);
	nvlist_free(asru);
	topo_mod_dprintf(mp, "%s\n", dpath);
	return (dpath);
}

/*
 * If add_fru is B_TRUE, and fru is NULL, the node's FMRI will be used as
 * the FRU, otherwise the FMRI specified in the fru nvlist is used.
 *
 * If asru is NULL, no ASRU will be added.
 *
 * If label is NULL, no label will be added.
 */
static tnode_t *
node_create(topo_mod_t *mod, tnode_t *pnode, const char *name, int instance,
    boolean_t add_fru, nvlist_t *fru, nvlist_t *asru, char *label,
    cfga_list_data_t *cfgap, int *err)
{
	int len = 0;
	nvlist_t *fmri = NULL;
	nvlist_t *auth = NULL;
	tnode_t *cnode = NULL;
	char *mm = NULL, *model = NULL, *manuf = NULL, *serial = NULL;
	char *firm = NULL;
	int manuf_len, model_len, serial_len, firm_len;

	if (cfgap != NULL) {
		char *s;

		sata_info_to_fru(cfgap->ap_info, &model, &model_len, &manuf,
		    &manuf_len, &serial, &serial_len, &firm, &firm_len, mod);
		if ((s = strchr(model, ' ')) != NULL)
			*s = '-';
		len = manuf_len + model_len + 1;
		if ((mm = topo_mod_alloc(mod, len)) != NULL)
			(void) snprintf(mm, len, "%s-%s", manuf, model);
		else
			mm = model;
	}

	auth = topo_mod_auth(mod, pnode);
	if ((fmri = topo_mod_hcfmri(mod, pnode, FM_HC_SCHEME_VERSION, name,
	    instance, NULL, auth, mm, serial, firm))
	    != NULL && (cnode = topo_node_bind(mod, pnode, name, instance,
	    fmri)) != NULL) {

		/* Set the FRU to the node's FMRI if caller didn't specify it */
		if (add_fru)
			(void) topo_node_fru_set(cnode, fru ? fru : fmri, 0,
			    err);

		if (!*err && asru)
			(void) topo_node_asru_set(cnode, asru, 0, err);

		if (!*err && label)
			(void) topo_node_label_set(cnode, label, err);
	}

	if (len != 0)
		topo_mod_free(mod, mm, len);
	if (model)
		topo_mod_free(mod, model, model_len);
	if (manuf)
		topo_mod_free(mod, manuf, manuf_len);
	if (serial)
		topo_mod_free(mod, serial, serial_len);
	if (firm)
		topo_mod_free(mod, firm, firm_len);
	if (fmri)
		nvlist_free(fmri);
	if (auth)
		nvlist_free(auth);

	return (cnode);
}

static char *
trimdup(const char *s, int *slen, topo_mod_t *mod)
{
	char *rs = tp_strdup(mod, s, slen);
	int i;

	while (isspace(*s) && *s != 0)
		s++;

	i = strlen(s) - 1;

	while (i >= 0 && isspace(s[i]))
		i--;

	strncpy(rs, s, i + 1);
	rs[i + 1] = 0;

	return (rs);
}

static boolean_t
get_machine_name(char **name, int *namelen, topo_mod_t *mod)
{
	smbios_hdl_t *shp;
	smbios_system_t s1;
	smbios_info_t s2;
	id_t id;
	boolean_t retval = B_FALSE;

	if ((shp = smbios_open(NULL, SMB_VERSION, 0, NULL)) != NULL) {
		if ((id = smbios_info_system(shp, &s1)) != SMB_ERR &&
		    smbios_info_common(shp, id, &s2) != SMB_ERR) {
			*name = trimdup(s2.smbi_product, namelen, mod);
			retval = B_TRUE;
		}
		smbios_close(shp);
	}
	return (retval);
}

int
_topo_init(topo_mod_t *mod)
{
	int i;
	int mnamelen;
	char *mname;

	if (getenv("SATADBG"))
		topo_mod_setdebug(mod);
	topo_mod_dprintf(mod, "initializing sata enumerator\n");

	(void) pthread_mutex_lock(&global_data_mutex);
	if (!global_data_initted) {
		if (get_machine_name(&mname, &mnamelen, mod)) {

			bzero(machname, MAX_MACHNAMELEN);
			(void) strncpy(machname, mname,
			    MIN(mnamelen, MAX_MACHNAMELEN - 1));
			topo_mod_free(mod, mname, mnamelen);

			i = 0;
			/* Initialize the sata_dev_props and ruleset globals */
			while (machprops[i] != NULL &&
			    strcmp(machprops[i]->machname, machname) != 0) {
				i++;
			}
			if (machprops[i] != NULL) {
				sata_dev_props = machprops[i]->sata_dev_props;
				ruleset = machprops[i]->action_rules;
				pgroupname = machprops[i]->pgroup;
			}
		}

		global_data_initted = B_TRUE;
	}
	(void) pthread_mutex_unlock(&global_data_mutex);

	if (topo_mod_register(mod, &sata_info, TOPO_VERSION) != 0) {
		topo_mod_dprintf(mod, "failed to register sata module: "
		    "%s\n", topo_mod_errmsg(mod));
		return (-1); /* mod errno set */
	}
	return (0);
}

void
_topo_fini(topo_mod_t *mod)
{
	topo_mod_unregister(mod);
}

static int
config_list_ext_poll(int num, char * const *path,
    cfga_list_data_t **list_array, int *nlist)
{
	boolean_t done = B_FALSE;
	boolean_t timedout = B_FALSE;
	boolean_t interrupted = B_FALSE;
	int timeout = 0;
	int e;
#define	TIMEOUT_MAX 60

	/*
	 * This timeout mechanism handles attachment points that are
	 * temporarily BUSY while the device is initialized.
	 */

	do {
		switch ((e = config_list_ext(num, path, list_array,
		    nlist, NULL, NULL, NULL, CFGA_FLAG_LIST_ALL))) {

		case CFGA_OK:

			return (CFGA_OK);

		case CFGA_BUSY:
		case CFGA_SYSTEM_BUSY:

			if (timeout++ >= TIMEOUT_MAX)
				timedout = B_TRUE;
			else {
				(void) sleep(1);
				interrupted = (errno == EINTR);
			}
			break;

		default:
			done = B_TRUE;
			break;

		}
	} while (!done && !timedout && !interrupted);

	return (e);
}

/*
 * Translates a device minor name into an attachment point (`sataX/Y`)
 * Allocates memory and returns the attachment point name in *ap.
 * (Caller is responsible for deallocating *ap.)
 */
static int
sata_minorname_to_ap(char *minorname, char **ap, int *apbuflen,
    cfga_list_data_t **list_array, topo_mod_t *mod)
{
	char *p;
	int nlist;

	if (config_list_ext_poll(1, (char * const *)&minorname, list_array,
	    &nlist) == CFGA_OK) {

		assert(nlist == 1);
		*apbuflen = PATH_MAX;
		*ap = topo_mod_alloc(mod, *apbuflen);
		strncpy(*ap, (*list_array)[0].ap_log_id, PATH_MAX);
		/*
		 * The logical id is:
		 * <attachmentpoint>[::<logicaldisknode>],
		 * so remove the portion we're not interested in.
		 */
		if ((p = strstr(*ap, "::")) != NULL)
			*p = 0;

		return (0);
	}
	return (-1);
}

static sata_dev_prop_t *
lookup_sdp_by_minor(char *minorpath)
{
	int i;

	if (sata_dev_props == NULL)
		return (NULL);

	for (i = 0; sata_dev_props[i].ap_node != NULL; i++) {
		if (strcmp(minorpath, sata_dev_props[i].ap_node) == 0)
			return (&sata_dev_props[i]);
	}

	return (NULL);
}

/*
 * Look for disk nodes of the form {physpath}/<whatever>@{portnum},0
 * and return the path to that node in physpath
 */
static boolean_t
find_physical_disk_node(char *physpath, int pathbuflen, int portnum,
    topo_mod_t *mod)
{
	DIR *dp;
	struct dirent *dep, *dent;
	char matchstr[32];
	char finalpath[PATH_MAX];
	char *p;
	int dentlen;
	boolean_t found = B_FALSE;

	if ((dp = opendir(physpath)) == NULL)
		return (-1);

	(void) snprintf(matchstr, sizeof (matchstr), "@%d,0", portnum);

	/*
	 * Allocate a dirent structure large enough to hold the longest path
	 * in the devfs filesystem.  The NUL byte is accounted-for in the
	 * 1 byte already allocated as part of d_name in the dirent structure.
	 */
	dentlen = pathconf(physpath, _PC_NAME_MAX);
	dentlen = ((dentlen <= 0) ? MAXNAMELEN : dentlen) +
	    sizeof (struct dirent);
	dent = topo_mod_alloc(mod, dentlen);

	errno = 0;
	while (!found && readdir_r(dp, dent, &dep) == 0 && dep != NULL) {
		/* Skip entries that we don't care about */
		if ((p = strchr(dep->d_name, '@')) == NULL)
			continue;
		else if (strcmp(p, matchstr) == 0) {
			(void) snprintf(finalpath, PATH_MAX, "%s/%s",
			    physpath, dep->d_name);
			(void) strncpy(physpath, finalpath, pathbuflen);
			found = B_TRUE;
		}

		/* Set errno to 0 before next call to readdir_r */
		errno = 0;
	}

	topo_mod_free(mod, dent, dentlen);
	closedir(dp);
	return (found);
}

static char *
devpath_to_devid(char *devpath)
{
	di_node_t node;
	ddi_devid_t devid;
	char *devidstr = NULL;

	if ((node = di_init(devpath, DINFOCPYONE)) == DI_NODE_NIL)
		return (NULL);

	if ((devid = di_devid(node)) == NULL) {
		di_fini(node);
		return (NULL);
	}

	devidstr = devid_str_encode(devid, NULL);
	di_fini(node);

	return (devidstr);
}

static int
sata_maximum_port(char *dpath, topo_mod_t *mod)
{
	DIR *dp;
	struct dirent *dep, *dent;
	char devpath[PATH_MAX], lastdev[PATH_MAX];
	char *dup_dpath, *p, *lastelem;
	int nodemax = -1, lastdevlen, dentlen, dup_dplen;

	(void) snprintf(devpath, PATH_MAX, "/devices%s/..", dpath);

	if ((dp = opendir(devpath)) == NULL)
		return (-1);

	/* basename() may modify its argument, so dup the string first: */
	dup_dpath = tp_strdup(mod, dpath, &dup_dplen);
	lastelem = basename(dup_dpath);
	if (lastelem == NULL) {
		topo_mod_free(mod, dup_dpath, dup_dplen);
		closedir(dp);
		return (-1);
	}
	(void) snprintf(lastdev, PATH_MAX, "%s:", lastelem);
	lastdevlen = strlen(lastdev);
	topo_mod_free(mod, dup_dpath, dup_dplen);

	/*
	 * Allocate a dirent structure large enough to hold the longest path
	 * in the devfs filesystem.  The NUL byte is accounted-for in the
	 * 1 byte already allocated as part of d_name in the dirent structure.
	 */
	dentlen = pathconf(devpath, _PC_NAME_MAX);
	dentlen = ((dentlen <= 0) ? MAXNAMELEN : dentlen) +
	    sizeof (struct dirent);
	dentlen = sizeof (struct dirent) + pathconf(devpath, _PC_NAME_MAX);
	dent = topo_mod_alloc(mod, dentlen);

	/*
	 * Open the directory at "/devices" + dpath + "/.." and scan for the
	 * minor node names (of minor nodes whose name portion is == to the
	 * last path element of dpath) with the largest number
	 */

	errno = 0;
	while (readdir_r(dp, dent, &dep) == 0 && dep != NULL) {
		/* Skip entries that we don't care about */
		if (strncmp(dep->d_name, lastdev, lastdevlen) != 0)
			continue;

		/* Update the largest minor # by pulling it out of the dirent */
		if ((p = strchr(dep->d_name, ':')) != NULL) {
			nodemax = MAX(nodemax, strtol(p + 1, NULL, 0));
		}
		/* Set errno to 0 before next call to readdir_r */
		errno = 0;
	}

	if (errno != 0)
		nodemax = -1;

	topo_mod_free(mod, dent, dentlen);
	closedir(dp);
	return (nodemax);
}

static void
sata_add_port_props(tnode_t *cnode, sata_dev_prop_t *sdp, int *err)
{
	int i;
#define	MAX_PNAME_LEN	128
	char pname[MAX_PNAME_LEN];
	topo_pgroup_info_t pgroup;

	/*
	 * Save the attachment point physical path
	 */
	(void) topo_pgroup_create(cnode, &io_pgroup, err);
	(void) topo_prop_set_string(cnode, TOPO_PGROUP_IO,
	    TOPO_IO_AP_PATH, TOPO_PROP_IMMUTABLE,
	    sdp->ap_node, err);

	/*
	 * The private properties are the core of the configuration
	 * mechanism for the sfx4500-disk Diagnosis Engine.
	 */
	pgroup.tpi_name = pgroupname;
	pgroup.tpi_namestab = TOPO_STABILITY_PRIVATE;
	pgroup.tpi_datastab = TOPO_STABILITY_PRIVATE;
	pgroup.tpi_version = 1;
	(void) topo_pgroup_create(cnode, &pgroup, err);

	for (i = 0; sdp->properties[i].name != NULL; i++) {
		(void) topo_prop_set_string(cnode, pgroupname,
		    sdp->properties[i].name, TOPO_PROP_IMMUTABLE,
		    (char *)sdp->properties[i].value, err);
	}

	/* Add the indicators: */
	for (i = 0; sdp->indicators[i].indicator != NULL; i++) {
		/*
		 * Since topo node properties can't contain nvlists,
		 * the indicators and their actions will go into two
		 * separate properties
		 */
		(void) snprintf(pname, MAX_PNAME_LEN, SATA_IND_NAME "-%d",
		    i);
		(void) topo_prop_set_string(cnode, pgroupname, pname,
		    TOPO_PROP_IMMUTABLE, (char *)sdp->indicators[i].indicator,
		    err);

		(void) snprintf(pname, MAX_PNAME_LEN, SATA_IND_ACTION "-%d",
		    i);
		(void) topo_prop_set_string(cnode, pgroupname, pname,
		    TOPO_PROP_IMMUTABLE, (char *)sdp->indicators[i].action,
		    err);
	}

	/* Now, the (global) indicator rules */
	for (i = 0; ruleset[i].states != NULL; i++) {
		(void) snprintf(pname, MAX_PNAME_LEN, SATA_INDRULE_STATES "-%d",
		    i);
		(void) topo_prop_set_string(cnode, pgroupname, pname,
		    TOPO_PROP_IMMUTABLE, (char *)ruleset[i].states,
		    err);

		(void) snprintf(pname, MAX_PNAME_LEN,
		    SATA_INDRULE_ACTIONS "-%d", i);
		(void) topo_prop_set_string(cnode, pgroupname, pname,
		    TOPO_PROP_IMMUTABLE, (char *)ruleset[i].actions,
		    err);
	}
}

/*
 * minorpath is the path to the minor node for this port (/devices/...:<n>)
 */
static void
sata_port_add_private_props(tnode_t *cnode, char *minorpath, int *err)
{
	sata_dev_prop_t *sdp;

	/* Try to match the minorpath to one of the sata_dev_prop_t's */
	if ((sdp = lookup_sdp_by_minor(minorpath)) != NULL) {
		sata_add_port_props(cnode, sdp, err);
	}
}

static void
sata_info_to_fru(char *info, char **model, int *modlen, char **manuf,
    int *manulen, char **serial, int *serlen, char **firm, int *firmlen,
    topo_mod_t *mod)
{
	int infolen;
	char *sata_info = tp_strdup(mod, info, &infolen);
	char *modlp, *revp, *snp, *manup;

	/*
	 * The information string from the SATA cfgadm plugin has the
	 * following form:
	 *
	 * Mod: <model> FRev: <revision> SN: <serialno>
	 */

	if ((modlp = strstr(sata_info, "Mod: ")) == NULL ||
	    (revp = strstr(sata_info, " FRev: ")) == NULL ||
	    (snp = strstr(sata_info, " SN: ")) == NULL) {
		*model = *manuf = *serial = *firm = NULL;
		topo_mod_free(mod, sata_info, infolen);
		return;
	}

	modlp += 5;	/* strlen("Mod: ") */
	*revp = 0;	/* terminate model string */
	revp += 7;	/* strlen(" FRev: ") */
	*snp = 0;	/* terminate revision string */
	snp += 5;	/* strlen(" SN: ") */

	/*
	 * The model string is broken into 2 fields --
	 * manufacturer and model string (separated by one space)
	 * If there is no space, then there's just a model number
	 * with no manufacturer.
	 */
	manup = modlp;
	modlp = strchr(modlp, ' ');
	if (modlp == NULL) {
		*manuf = tp_strdup(mod, "", manulen);
		*model = tp_strdup(mod, manup, modlen);
	} else {
		*modlp = 0;
		modlp += 1;
		*manuf = tp_strdup(mod, manup, manulen);
		*model = tp_strdup(mod, modlp, modlen);
	}
	*firm = tp_strdup(mod, revp, firmlen);
	*serial = tp_strdup(mod, snp, serlen);


	topo_mod_free(mod, sata_info, infolen);
}

static void
sata_add_disk_props(tnode_t *cnode, const char *physpath,
    cfga_list_data_t *cfgap, int *err, topo_mod_t *mod)
{
	char *ldev, *p;
	char *model = NULL, *manuf = NULL, *serial = NULL, *firm = NULL;
	int manuf_len, model_len, serial_len, firm_len;

	(void) topo_pgroup_create(cnode, &storage_pgroup, err);

	if (physpath) {
		(void) topo_pgroup_create(cnode, &io_pgroup,
		    err);

		(void) topo_prop_set_string(cnode, TOPO_PGROUP_IO,
		    TOPO_IO_DEV_PATH, TOPO_PROP_IMMUTABLE,
		    physpath + 8 /* strlen("/devices") */,
		    err);
	}

	if ((ldev = strstr(cfgap->ap_log_id, "::")) != NULL) {
		ldev += 2 /* strlen("::") */;
		if ((p = strchr(ldev, '/')) != NULL) {
			ldev = p + 1;
		}
		(void) topo_prop_set_string(cnode, TOPO_STORAGE_PGROUP,
		    TOPO_STORAGE_LOGICAL_DISK_NAME, TOPO_PROP_IMMUTABLE,
		    ldev, err);
	}

	sata_info_to_fru(cfgap->ap_info, &model, &model_len, &manuf, &manuf_len,
	    &serial, &serial_len, &firm, &firm_len, mod);
	if (model) {
		(void) topo_prop_set_string(cnode, TOPO_STORAGE_PGROUP,
		    TOPO_STORAGE_MODEL, TOPO_PROP_IMMUTABLE, model, err);
		topo_mod_free(mod, model, model_len);
	}
	if (manuf) {
		(void) topo_prop_set_string(cnode, TOPO_STORAGE_PGROUP,
		    TOPO_STORAGE_MANUFACTURER, TOPO_PROP_IMMUTABLE, manuf, err);
		topo_mod_free(mod, manuf, manuf_len);
	}
	if (serial) {
		(void) topo_prop_set_string(cnode, TOPO_STORAGE_PGROUP,
		    TOPO_STORAGE_SERIAL_NUM, TOPO_PROP_IMMUTABLE, serial, err);
		topo_mod_free(mod, serial, serial_len);
	}
	if (firm) {
		(void) topo_prop_set_string(cnode, TOPO_STORAGE_PGROUP,
		    TOPO_STORAGE_FIRMWARE_REV, TOPO_PROP_IMMUTABLE, firm, err);
		topo_mod_free(mod, firm, firm_len);
	}

	/*
	 * Try to get the disk capacity and store it in a property if the
	 * device is accessible
	 */
	if (physpath) {
		int fd;
		struct dk_minfo dkmi;
		uint64_t capacity = 0;
		char capstr[32];
		char buf[PATH_MAX];

		(void) snprintf(buf, sizeof (buf), "%s%s", physpath,
		    PHYS_EXTN);

		if ((fd = open(buf, O_RDONLY)) >= 0) {
			if (ioctl(fd, DKIOCGMEDIAINFO, &dkmi) == 0) {
				capacity = dkmi.dki_capacity *
				    (uint64_t)dkmi.dki_lbsize;
			}
			(void) close(fd);
		}
		if (capacity > 0) {
			(void) snprintf(capstr, sizeof (capstr), "%llu",
			    capacity);
			(void) topo_prop_set_string(cnode, TOPO_STORAGE_PGROUP,
			    TOPO_STORAGE_CAPACITY, TOPO_PROP_IMMUTABLE, capstr,
			    err);
		}
	}
}

static boolean_t
is_sata_controller(char *dpath)
{
	di_node_t devnode = di_init(dpath, DINFOPROP);
	boolean_t satactrlr = B_FALSE;
	int *sataprops;

	/*
	 * SATA controllers have a `sata' property on their nodes with
	 * a value of 1.
	 */
	if (devnode != DI_NODE_NIL) {
		if (di_prop_lookup_ints(DDI_DEV_T_ANY, devnode, "sata",
		    &sataprops) == 1 && *sataprops == 1)
			satactrlr = B_TRUE;
		di_fini(devnode);
	}
	return (satactrlr);
}

static int
sata_disks_create(topo_mod_t *mod, tnode_t *pnode, const char *name,
    int portnum, cfga_list_data_t *cfglist, int ndisks, int *err)
{
	tnode_t *cnode;
	sata_dev_prop_t *sdp;
	nvlist_t *fru = NULL;
	int i, nerrs = 0;
	char physpath_buf[PATH_MAX];
	char *physpath, *devpath;
	char *devid;
	nvlist_t *asru;

	if (topo_node_range_create(mod, pnode, name, 0, ndisks - 1) < 0) {
		topo_mod_dprintf(mod, "Unable to create "
		    SATA_DISK " range [%d..%d]: %s\n",
		    0, ndisks - 1, topo_mod_errmsg(mod));
		return (-1);
	}

	for (i = 0; i < ndisks; i++) {
		/*
		 * Check to see if there's a disk inserted in this port
		 */
		if (cfglist[i].ap_r_state == CFGA_STAT_CONNECTED &&
		    (cfglist[i].ap_o_state == CFGA_STAT_CONFIGURED ||
		    cfglist[i].ap_o_state == CFGA_STAT_UNCONFIGURED)) {

			sdp = lookup_sdp_by_minor(cfglist[i].ap_phys_id);

			/*
			 * The physical path to the drive can be derived by
			 * taking the attachment point physical path, chopping
			 * off the minor portion, and looking for the target
			 * node of the form <nodename>@<X>,0 (where <X> is the
			 * port number)
			 */
			strncpy(physpath_buf, cfglist[i].ap_phys_id, PATH_MAX);

			/* The AP phys path MUST have a colon: */
			*strchr(physpath_buf, ':') = 0;

			/*
			 * Create the ASRU.  If the device is attached to the
			 * system but unconfigured, then it will have no
			 * associated ASRU.
			 */
			if (find_physical_disk_node(physpath_buf, PATH_MAX,
			    portnum, mod)) {
				physpath = physpath_buf;
				devpath = physpath_buf +
				    sizeof ("/devices") - 1;
				/*
				 * Given the /devices path, attempt to find an
				 * associated devid.
				 */
				devid = devpath_to_devid(devpath);
				asru = topo_mod_devfmri(mod,
				    FM_DEV_SCHEME_VERSION, devpath, devid);
				devid_str_free(devid);
			} else {
				physpath = NULL;
				asru = NULL;
			}

			if ((cnode = node_create(mod, pnode, name, i,
			    B_TRUE, fru, asru, sdp ? (char *)sdp->label : NULL,
			    &cfglist[i], err)) != NULL) {

				sata_add_disk_props(cnode, physpath,
				    &cfglist[i], err, mod);

				if (topo_method_register(mod, cnode,
				    sata_disk_methods) < 0) {
					topo_mod_dprintf(mod,
					    "topo_method_register failed: %s\n",
					    topo_strerror(topo_mod_errno(mod)));
					++nerrs;
				}
			} else {
				topo_mod_dprintf(mod, "Error creating disk "
				    "node for port %d: %s\n", portnum,
				    topo_strerror(*err));
				++nerrs;
			}

			nvlist_free(fru);
			nvlist_free(asru);
		}
	}

	if (nerrs) {
		topo_node_range_destroy(pnode, name);
		return (-1);
	}

	return (0);
}

static int
sata_port_create(topo_mod_t *mod, tnode_t *pnode, const char *name,
    topo_instance_t min, topo_instance_t max)
{
	nvlist_t *asru;
	tnode_t *cnode;
	int err = 0, nerr = 0;
	int i;
	char *dpath;
	char *ap = NULL;
	char minorname[PATH_MAX];
	int apbuflen;
	int dpathlen;
	cfga_list_data_t *cfglist = NULL;

	if (min < 0)
		min = 0;

	if (min > max)
		return (0);

	/* Get the device path from the parent node's properties: */
	if ((dpath = devpath_from_asru(mod, pnode, &dpathlen)) == NULL)
		return (0);

	if (!is_sata_controller(dpath)) {
		topo_mod_dprintf(mod, "%s is not a sata controller\n", dpath);
		topo_mod_free(mod, dpath, dpathlen);
		return (0);
	}

	if ((max = sata_maximum_port(dpath, mod)) < 0) {
		topo_mod_dprintf(mod, "Could not discover the number of ports "
		    "on SATA controller at %s\n", dpath);
		topo_mod_free(mod, dpath, dpathlen);
		return (-1);
	}

	for (i = min; i <= max; i++) {

		/* The minor node name = "/devices" + dpath + ":" + i */
		(void) snprintf(minorname, PATH_MAX, "/devices%s:%x", dpath, i);

		if (sata_minorname_to_ap(minorname, &ap, &apbuflen, &cfglist,
		    mod) != 0) {
			topo_mod_dprintf(mod, "Could not translate minor node "
			    "into an attachment point: ignoring sata-port=%d\n",
			    i);
			continue;
		}

		/* Create the ASRU - a dev:// FMRI */
		if ((asru = topo_mod_devfmri(mod, FM_DEV_SCHEME_VERSION,
		    dpath, NULL)) == NULL) {
			free(cfglist);
			topo_mod_free(mod, ap, apbuflen);
			topo_mod_dprintf(mod, "failed to make ASRU FMRI: "
			    "%s\n", topo_strerror(err));
			++nerr;
			continue;
		}

		/*
		 * The ASRU is the devices path
		 * The FRU is a the component FRMI
		 */
		if ((cnode = node_create(mod, pnode, name, i, B_TRUE, NULL,
		    asru, ap, NULL, &err)) == NULL) {
			nvlist_free(asru);
			free(cfglist);
			topo_mod_free(mod, ap, apbuflen);
			topo_mod_dprintf(mod, "failed to create instance %d of "
			    "node %s: %s\n", i, name, strerror(err));
			++nerr;
			continue;
		}

		topo_mod_free(mod, ap, apbuflen);

		/* For now, ignore errors from private property creation */
		sata_port_add_private_props(cnode, minorname, &err);

		/* Create the disk node(s) under this sata-port: */
		if (sata_disks_create(mod, cnode, SATA_DISK, i, cfglist,
		    1 /* one disk for now */, &err) != 0) {
			topo_mod_dprintf(mod, "Error while creating " SATA_DISK
			    " node(s): %s\n", topo_strerror(err));
			++nerr;
			topo_node_unbind(cnode);
		}

		free(cfglist);
		nvlist_free(asru);
	}

	topo_mod_free(mod, dpath, dpathlen);

	if (nerr != 0) {
		topo_node_range_destroy(pnode, name);
		return (-1);
	} else
		return (0);
}

/*ARGSUSED*/
static int
sata_enum(topo_mod_t *mod, tnode_t *pnode, const char *name,
    topo_instance_t min, topo_instance_t max, void *notused1, void *notused2)
{
	if (strcmp(name, SATA_PORT) == 0)
		return (sata_port_create(mod, pnode, name, min, max));

	return (0);
}

/*
 * Query the current disk status.  If successful, the disk status is returned as
 * an nvlist consisting of at least the following members:
 *
 *	protocol	string		Supported protocol (currently "scsi")
 *
 *	status		nvlist		Arbitrary protocol-specific information
 *					about the current state of the disk.
 *
 *	faults		nvlist		A list of supported faults.  Each
 *					element of this list is a boolean value.
 *					An element's existence indicates that
 *					the drive supports detecting this fault,
 *					and the value indicates the current
 *					state of the fault.
 *
 *	<fault-name>	nvlist		For each fault named in 'faults', a
 *					nvlist describing protocol-specific
 *					attributes of the fault.
 *
 * This method relies on the libdiskstatus library to query this information.
 */
static int
sata_disk_status(topo_mod_t *mod, tnode_t *nodep, topo_version_t vers,
    nvlist_t *in_nvl, nvlist_t **out_nvl)
{
	disk_status_t *dsp;
	char *devpath, *fullpath;
	size_t pathlen;
	int err;
	nvlist_t *status;
	*out_nvl = NULL;

	if (vers != TOPO_METH_DISK_STATUS_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	/*
	 * If the caller specifies the "path" parameter, then this indicates
	 * that we should use this instead of deriving it from the topo node
	 * itself.
	 */
	if (nvlist_lookup_string(in_nvl, "path", &fullpath) == 0) {
		devpath = NULL;
	} else {
		/*
		 * Get the /devices path and attempt to open the disk status
		 * handle.
		 */
		if (topo_prop_get_string(nodep, TOPO_PGROUP_IO,
		    TOPO_IO_DEV_PATH, &devpath, &err) != 0)
			return (topo_mod_seterrno(mod, EMOD_METHOD_NOTSUP));

		/*
		 * Note that sizeof(string) includes the terminating NULL byte
		 */
		pathlen = strlen(devpath) + sizeof ("/devices") +
		    sizeof (PHYS_EXTN) - 1;

		if ((fullpath = topo_mod_alloc(mod, pathlen)) == NULL)
			return (topo_mod_seterrno(mod, EMOD_NOMEM));

		(void) snprintf(fullpath, pathlen, "/devices%s%s", devpath,
		    PHYS_EXTN);

		topo_mod_strfree(mod, devpath);
	}

	if ((dsp = disk_status_open(fullpath, &err)) == NULL) {
		topo_mod_free(mod, fullpath, pathlen);
		return (topo_mod_seterrno(mod, err == EDS_NOMEM ?
		    EMOD_NOMEM : EMOD_METHOD_NOTSUP));
	}

	if (devpath)
		topo_mod_free(mod, fullpath, pathlen);

	if ((status = disk_status_get(dsp)) == NULL) {
		err = (disk_status_errno(dsp) == EDS_NOMEM ?
		    EMOD_NOMEM : EMOD_METHOD_NOTSUP);
		disk_status_close(dsp);
		return (topo_mod_seterrno(mod, err));
	}

	*out_nvl = status;
	disk_status_close(dsp);
	return (0);
}
