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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libsysevent.h>
#include <pthread.h>
#include <stdlib.h>
#include <errno.h>
#include <fnmatch.h>
#include <strings.h>
#include <unistd.h>
#include <assert.h>
#include <libgen.h>
#include <libintl.h>
#include <alloca.h>
#include <ctype.h>
#include <sys/acl.h>
#include <sys/stat.h>
#include <sys/brand.h>
#include <sys/mntio.h>
#include <sys/mnttab.h>
#include <sys/nvpair.h>
#include <sys/types.h>
#include <sys/sockio.h>
#include <ftw.h>
#include <pool.h>
#include <libscf.h>
#include <libproc.h>
#include <sys/priocntl.h>
#include <libuutil.h>

#include <arpa/inet.h>
#include <netdb.h>

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include <libdevinfo.h>
#include <uuid/uuid.h>
#include <dirent.h>
#include <libbrand.h>

#include <libzonecfg.h>
#include "zonecfg_impl.h"

#define	_PATH_TMPFILE	"/zonecfg.XXXXXX"
#define	ZONE_CB_RETRY_COUNT		10
#define	ZONE_EVENT_PING_SUBCLASS	"ping"
#define	ZONE_EVENT_PING_PUBLISHER	"solaris"

/* Hard-code the DTD element/attribute/entity names just once, here. */
#define	DTD_ELEM_ATTR		(const xmlChar *) "attr"
#define	DTD_ELEM_COMMENT	(const xmlChar *) "comment"
#define	DTD_ELEM_DEVICE		(const xmlChar *) "device"
#define	DTD_ELEM_FS		(const xmlChar *) "filesystem"
#define	DTD_ELEM_FSOPTION	(const xmlChar *) "fsoption"
#define	DTD_ELEM_IPD		(const xmlChar *) "inherited-pkg-dir"
#define	DTD_ELEM_NET		(const xmlChar *) "network"
#define	DTD_ELEM_RCTL		(const xmlChar *) "rctl"
#define	DTD_ELEM_RCTLVALUE	(const xmlChar *) "rctl-value"
#define	DTD_ELEM_ZONE		(const xmlChar *) "zone"
#define	DTD_ELEM_DATASET	(const xmlChar *) "dataset"
#define	DTD_ELEM_TMPPOOL	(const xmlChar *) "tmp_pool"
#define	DTD_ELEM_PSET		(const xmlChar *) "pset"
#define	DTD_ELEM_MCAP		(const xmlChar *) "mcap"
#define	DTD_ELEM_PACKAGE	(const xmlChar *) "package"
#define	DTD_ELEM_PATCH		(const xmlChar *) "patch"
#define	DTD_ELEM_OBSOLETES	(const xmlChar *) "obsoletes"
#define	DTD_ELEM_DEV_PERM	(const xmlChar *) "dev-perm"

#define	DTD_ATTR_ACTION		(const xmlChar *) "action"
#define	DTD_ATTR_ADDRESS	(const xmlChar *) "address"
#define	DTD_ATTR_AUTOBOOT	(const xmlChar *) "autoboot"
#define	DTD_ATTR_IPTYPE		(const xmlChar *) "ip-type"
#define	DTD_ATTR_DIR		(const xmlChar *) "directory"
#define	DTD_ATTR_LIMIT		(const xmlChar *) "limit"
#define	DTD_ATTR_LIMITPRIV	(const xmlChar *) "limitpriv"
#define	DTD_ATTR_BOOTARGS	(const xmlChar *) "bootargs"
#define	DTD_ATTR_SCHED		(const xmlChar *) "scheduling-class"
#define	DTD_ATTR_MATCH		(const xmlChar *) "match"
#define	DTD_ATTR_NAME		(const xmlChar *) "name"
#define	DTD_ATTR_PHYSICAL	(const xmlChar *) "physical"
#define	DTD_ATTR_POOL		(const xmlChar *) "pool"
#define	DTD_ATTR_PRIV		(const xmlChar *) "priv"
#define	DTD_ATTR_RAW		(const xmlChar *) "raw"
#define	DTD_ATTR_SPECIAL	(const xmlChar *) "special"
#define	DTD_ATTR_TYPE		(const xmlChar *) "type"
#define	DTD_ATTR_VALUE		(const xmlChar *) "value"
#define	DTD_ATTR_ZONEPATH	(const xmlChar *) "zonepath"
#define	DTD_ATTR_NCPU_MIN	(const xmlChar *) "ncpu_min"
#define	DTD_ATTR_NCPU_MAX	(const xmlChar *) "ncpu_max"
#define	DTD_ATTR_IMPORTANCE	(const xmlChar *) "importance"
#define	DTD_ATTR_PHYSCAP	(const xmlChar *) "physcap"
#define	DTD_ATTR_VERSION	(const xmlChar *) "version"
#define	DTD_ATTR_ID		(const xmlChar *) "id"
#define	DTD_ATTR_UID		(const xmlChar *) "uid"
#define	DTD_ATTR_GID		(const xmlChar *) "gid"
#define	DTD_ATTR_MODE		(const xmlChar *) "mode"
#define	DTD_ATTR_ACL		(const xmlChar *) "acl"
#define	DTD_ATTR_BRAND		(const xmlChar *) "brand"

#define	DTD_ENTITY_BOOLEAN	"boolean"
#define	DTD_ENTITY_DEVPATH	"devpath"
#define	DTD_ENTITY_DRIVER	"driver"
#define	DTD_ENTITY_DRVMIN	"drv_min"
#define	DTD_ENTITY_FALSE	"false"
#define	DTD_ENTITY_INT		"int"
#define	DTD_ENTITY_STRING	"string"
#define	DTD_ENTITY_TRUE		"true"
#define	DTD_ENTITY_UINT		"uint"

#define	DTD_ENTITY_BOOL_LEN	6	/* "false" */

#define	DETACHED	"SUNWdetached.xml"
#define	ATTACH_FORCED	"SUNWattached.xml"
#define	PKG_PATH	"/var/sadm/pkg"
#define	CONTENTS_FILE	"/var/sadm/install/contents"
#define	SUNW_PKG_ALL_ZONES	"SUNW_PKG_ALLZONES=true\n"
#define	SUNW_PKG_THIS_ZONE	"SUNW_PKG_THISZONE=true\n"
#define	VERSION		"VERSION="
#define	PATCHLIST	"PATCHLIST="
#define	PATCHINFO	"PATCH_INFO_"
#define	PKGINFO_RD_LEN	128

#define	TMP_POOL_NAME	"SUNWtmp_%s"
#define	MAX_TMP_POOL_NAME	(ZONENAME_MAX + 9)
#define	RCAP_SERVICE	"system/rcap:default"
#define	POOLD_SERVICE	"system/pools/dynamic:default"

enum zn_ipd_fs {ZONE_IPD, ZONE_FS};

/*
 * rctl alias definitions
 *
 * This holds the alias, the full rctl name, the default priv value, action
 * and lower limit.  The functions that handle rctl aliases step through
 * this table, matching on the alias, and using the full values for setting
 * the rctl entry as well the limit for validation.
 */
static struct alias {
	char *shortname;
	char *realname;
	char *priv;
	char *action;
	uint64_t low_limit;
} aliases[] = {
	{ALIAS_MAXLWPS, "zone.max-lwps", "privileged", "deny", 100},
	{ALIAS_MAXSHMMEM, "zone.max-shm-memory", "privileged", "deny", 0},
	{ALIAS_MAXSHMIDS, "zone.max-shm-ids", "privileged", "deny", 0},
	{ALIAS_MAXMSGIDS, "zone.max-msg-ids", "privileged", "deny", 0},
	{ALIAS_MAXSEMIDS, "zone.max-sem-ids", "privileged", "deny", 0},
	{ALIAS_MAXLOCKEDMEM, "zone.max-locked-memory", "privileged", "deny", 0},
	{ALIAS_MAXSWAP, "zone.max-swap", "privileged", "deny", 0},
	{ALIAS_SHARES, "zone.cpu-shares", "privileged", "none", 0},
	{ALIAS_CPUCAP, "zone.cpu-cap", "privileged", "deny", 0},
	{NULL, NULL, NULL, NULL, 0}
};

/*
 * Structure for applying rctls to a running zone.  It allows important
 * process values to be passed together easily.
 */
typedef struct pr_info_handle {
	struct ps_prochandle *pr;
	pid_t pid;
} pr_info_handle_t;

struct zone_dochandle {
	char		*zone_dh_rootdir;
	xmlDocPtr	zone_dh_doc;
	xmlNodePtr	zone_dh_cur;
	xmlNodePtr	zone_dh_top;
	boolean_t	zone_dh_newzone;
	boolean_t	zone_dh_snapshot;
	boolean_t	zone_dh_sw_inv;
	char		zone_dh_delete_name[ZONENAME_MAX];
};

struct znotify {
	void * zn_private;
	evchan_t *zn_eventchan;
	int (*zn_callback)(const  char *zonename, zoneid_t zid,
	    const char *newstate, const char *oldstate, hrtime_t when, void *p);
	pthread_mutex_t zn_mutex;
	pthread_cond_t zn_cond;
	pthread_mutex_t zn_bigmutex;
	volatile enum {ZN_UNLOCKED, ZN_LOCKED, ZN_PING_INFLIGHT,
	    ZN_PING_RECEIVED} zn_state;
	char zn_subscriber_id[MAX_SUBID_LEN];
	volatile boolean_t zn_failed;
	int zn_failure_count;
};

struct zone_pkginfo {
	boolean_t	zpi_all_zones;
	boolean_t	zpi_this_zone;
	int		zpi_patch_cnt;
	char		*zpi_version;
	char		**zpi_patchinfo;
};

typedef struct {
	uu_avl_node_t	patch_node;
	char		*patch_num;
	char		*patch_vers;
	uu_list_t	*obs_patches;
} patch_node_t;

typedef struct {
	uu_list_node_t	link;
	char		*patch_num;
} obs_patch_node_t;

typedef struct {
	uu_avl_t	*obs_patches_avl;
	zone_dochandle_t handle;
	int		res;
} patch_parms_t;

char *zonecfg_root = "";

/*
 * For functions which return int, which is most of the functions herein,
 * the return values should be from the Z_foo set defined in <libzonecfg.h>.
 * In some instances, we take pains mapping some libc errno values to Z_foo
 * values from this set.
 */

/*
 * Set the root (/) path for all zonecfg configuration files.  This is a
 * private interface used by Live Upgrade extensions to access zone
 * configuration inside mounted alternate boot environments.
 */
void
zonecfg_set_root(const char *rootpath)
{
	if (*zonecfg_root != '\0')
		free(zonecfg_root);
	if (rootpath == NULL || rootpath[0] == '\0' || rootpath[1] == '\0' ||
	    (zonecfg_root = strdup(rootpath)) == NULL)
		zonecfg_root = "";
}

const char *
zonecfg_get_root(void)
{
	return (zonecfg_root);
}

boolean_t
zonecfg_in_alt_root(void)
{
	return (*zonecfg_root != '\0');
}

/*
 * Callers of the _file_path() functions are expected to have the second
 * parameter be a (char foo[MAXPATHLEN]).
 */

static boolean_t
config_file_path(const char *zonename, char *answer)
{
	return (snprintf(answer, MAXPATHLEN, "%s%s/%s.xml", zonecfg_root,
	    ZONE_CONFIG_ROOT, zonename) < MAXPATHLEN);
}

static boolean_t
snap_file_path(const char *zonename, char *answer)
{
	return (snprintf(answer, MAXPATHLEN, "%s%s/%s.snapshot.xml",
	    zonecfg_root, ZONE_SNAPSHOT_ROOT, zonename) < MAXPATHLEN);
}

/*ARGSUSED*/
static void
zonecfg_error_func(void *ctx, const char *msg, ...)
{
	/*
	 * This function does nothing by design.  Its purpose is to prevent
	 * libxml from dumping unwanted messages to stdout/stderr.
	 */
}

zone_dochandle_t
zonecfg_init_handle(void)
{
	zone_dochandle_t handle = calloc(1, sizeof (struct zone_dochandle));
	if (handle == NULL) {
		errno = Z_NOMEM;
		return (NULL);
	}

	/* generic libxml initialization */
	xmlLineNumbersDefault(1);
	xmlLoadExtDtdDefaultValue |= XML_DETECT_IDS;
	xmlDoValidityCheckingDefaultValue = 1;
	(void) xmlKeepBlanksDefault(0);
	xmlGetWarningsDefaultValue = 0;
	xmlSetGenericErrorFunc(NULL, zonecfg_error_func);

	return (handle);
}

int
zonecfg_check_handle(zone_dochandle_t handle)
{
	if (handle == NULL || handle->zone_dh_doc == NULL)
		return (Z_BAD_HANDLE);
	return (Z_OK);
}

void
zonecfg_fini_handle(zone_dochandle_t handle)
{
	if (zonecfg_check_handle(handle) == Z_OK)
		xmlFreeDoc(handle->zone_dh_doc);
	if (handle != NULL)
		free(handle);
}

static int
zonecfg_destroy_impl(char *filename)
{
	if (unlink(filename) == -1) {
		if (errno == EACCES)
			return (Z_ACCES);
		if (errno == ENOENT)
			return (Z_NO_ZONE);
		return (Z_MISC_FS);
	}
	return (Z_OK);
}

int
zonecfg_destroy(const char *zonename, boolean_t force)
{
	char path[MAXPATHLEN];
	struct zoneent ze;
	int err, state_err;
	zone_state_t state;

	if (!config_file_path(zonename, path))
		return (Z_MISC_FS);

	state_err = zone_get_state((char *)zonename, &state);
	err = access(path, W_OK);

	/*
	 * If there is no file, and no index entry, reliably indicate that no
	 * such zone exists.
	 */
	if ((state_err == Z_NO_ZONE) && (err == -1) && (errno == ENOENT))
		return (Z_NO_ZONE);

	/*
	 * Handle any other filesystem related errors (except if the XML
	 * file is missing, which we treat silently), unless we're forcing,
	 * in which case we plow on.
	 */
	if (err == -1 && errno != ENOENT) {
		if (errno == EACCES)
			return (Z_ACCES);
		else if (!force)
			return (Z_MISC_FS);
	}

	if (state > ZONE_STATE_INSTALLED)
		return (Z_BAD_ZONE_STATE);

	if (!force && state > ZONE_STATE_CONFIGURED)
		return (Z_BAD_ZONE_STATE);

	/*
	 * Index deletion succeeds even if the entry doesn't exist.  So this
	 * will fail only if we've had some more severe problem.
	 */
	bzero(&ze, sizeof (ze));
	(void) strlcpy(ze.zone_name, zonename, sizeof (ze.zone_name));
	if ((err = putzoneent(&ze, PZE_REMOVE)) != Z_OK)
		if (!force)
			return (err);

	err = zonecfg_destroy_impl(path);

	/*
	 * Treat failure to find the XML file silently, since, well, it's
	 * gone, and with the index file cleaned up, we're done.
	 */
	if (err == Z_OK || err == Z_NO_ZONE)
		return (Z_OK);
	return (err);
}

int
zonecfg_destroy_snapshot(const char *zonename)
{
	char path[MAXPATHLEN];

	if (!snap_file_path(zonename, path))
		return (Z_MISC_FS);
	return (zonecfg_destroy_impl(path));
}

static int
getroot(zone_dochandle_t handle, xmlNodePtr *root)
{
	if (zonecfg_check_handle(handle) == Z_BAD_HANDLE)
		return (Z_BAD_HANDLE);

	*root = xmlDocGetRootElement(handle->zone_dh_doc);

	if (*root == NULL)
		return (Z_EMPTY_DOCUMENT);

	if (xmlStrcmp((*root)->name, DTD_ELEM_ZONE))
		return (Z_WRONG_DOC_TYPE);

	return (Z_OK);
}

static int
operation_prep(zone_dochandle_t handle)
{
	xmlNodePtr root;
	int err;

	if ((err = getroot(handle, &root)) != 0)
		return (err);

	handle->zone_dh_cur = root;
	handle->zone_dh_top = root;
	return (Z_OK);
}

static int
fetchprop(xmlNodePtr cur, const xmlChar *propname, char *dst, size_t dstsize)
{
	xmlChar *property;
	size_t srcsize;

	if ((property = xmlGetProp(cur, propname)) == NULL)
		return (Z_BAD_PROPERTY);
	srcsize = strlcpy(dst, (char *)property, dstsize);
	xmlFree(property);
	if (srcsize >= dstsize)
		return (Z_TOO_BIG);
	return (Z_OK);
}

static int
fetch_alloc_prop(xmlNodePtr cur, const xmlChar *propname, char **dst)
{
	xmlChar *property;

	if ((property = xmlGetProp(cur, propname)) == NULL)
		return (Z_BAD_PROPERTY);
	if ((*dst = strdup((char *)property)) == NULL) {
		xmlFree(property);
		return (Z_NOMEM);
	}
	xmlFree(property);
	return (Z_OK);
}

static int
getrootattr(zone_dochandle_t handle, const xmlChar *propname,
    char *propval, size_t propsize)
{
	xmlNodePtr root;
	int err;

	if ((err = getroot(handle, &root)) != 0)
		return (err);

	return (fetchprop(root, propname, propval, propsize));
}

static int
get_alloc_rootattr(zone_dochandle_t handle, const xmlChar *propname,
    char **propval)
{
	xmlNodePtr root;
	int err;

	if ((err = getroot(handle, &root)) != 0)
		return (err);

	return (fetch_alloc_prop(root, propname, propval));
}

static int
setrootattr(zone_dochandle_t handle, const xmlChar *propname,
    const char *propval)
{
	int err;
	xmlNodePtr root;

	if ((err = getroot(handle, &root)) != Z_OK)
		return (err);

	/*
	 * If we get a null propval remove the property (ignore return since it
	 * may not be set to begin with).
	 */
	if (propval == NULL) {
		(void) xmlUnsetProp(root, propname);
	} else {
		if (xmlSetProp(root, propname, (const xmlChar *) propval)
		    == NULL)
			return (Z_INVAL);
	}
	return (Z_OK);
}

static void
addcomment(zone_dochandle_t handle, const char *comment)
{
	xmlNodePtr node;
	node = xmlNewComment((xmlChar *) comment);

	if (node != NULL)
		(void) xmlAddPrevSibling(handle->zone_dh_top, node);
}

static void
stripcomments(zone_dochandle_t handle)
{
	xmlDocPtr top;
	xmlNodePtr child, next;

	top = handle->zone_dh_doc;
	for (child = top->xmlChildrenNode; child != NULL; child = next) {
		next = child->next;
		if (child->name == NULL)
			continue;
		if (xmlStrcmp(child->name, DTD_ELEM_COMMENT) == 0) {
			next = child->next;
			xmlUnlinkNode(child);
			xmlFreeNode(child);
		}
	}
}

static void
strip_sw_inv(zone_dochandle_t handle)
{
	xmlNodePtr root, child, next;

	root = xmlDocGetRootElement(handle->zone_dh_doc);
	for (child = root->xmlChildrenNode; child != NULL; child = next) {
		next = child->next;
		if (child->name == NULL)
			continue;
		if (xmlStrcmp(child->name, DTD_ELEM_PACKAGE) == 0 ||
		    xmlStrcmp(child->name, DTD_ELEM_PATCH) == 0) {
			next = child->next;
			xmlUnlinkNode(child);
			xmlFreeNode(child);
		}
	}
}

static int
zonecfg_get_handle_impl(const char *zonename, const char *filename,
    zone_dochandle_t handle)
{
	xmlValidCtxtPtr cvp;
	struct stat statbuf;
	int valid;

	if (zonename == NULL)
		return (Z_NO_ZONE);

	if ((handle->zone_dh_doc = xmlParseFile(filename)) == NULL) {
		/* distinguish file not found vs. found but not parsed */
		if (stat(filename, &statbuf) == 0)
			return (Z_INVALID_DOCUMENT);
		return (Z_NO_ZONE);
	}
	if ((cvp = xmlNewValidCtxt()) == NULL)
		return (Z_NOMEM);
	cvp->error = zonecfg_error_func;
	cvp->warning = zonecfg_error_func;
	valid = xmlValidateDocument(cvp, handle->zone_dh_doc);
	xmlFreeValidCtxt(cvp);
	if (valid == 0)
		return (Z_INVALID_DOCUMENT);

	/* delete any comments such as inherited Sun copyright / ident str */
	stripcomments(handle);
	return (Z_OK);
}

int
zonecfg_get_handle(const char *zonename, zone_dochandle_t handle)
{
	char path[MAXPATHLEN];

	if (!config_file_path(zonename, path))
		return (Z_MISC_FS);
	handle->zone_dh_newzone = B_FALSE;

	return (zonecfg_get_handle_impl(zonename, path, handle));
}

int
zonecfg_get_attach_handle(const char *path, const char *zonename,
    boolean_t preserve_sw, zone_dochandle_t handle)
{
	char		migpath[MAXPATHLEN];
	int		err;
	struct stat	buf;

	if (snprintf(migpath, sizeof (migpath), "%s/root", path) >=
	    sizeof (migpath))
		return (Z_NOMEM);

	if (stat(migpath, &buf) == -1 || !S_ISDIR(buf.st_mode))
		return (Z_NO_ZONE);

	if (snprintf(migpath, sizeof (migpath), "%s/%s", path, DETACHED) >=
	    sizeof (migpath))
		return (Z_NOMEM);

	if ((err = zonecfg_get_handle_impl(zonename, migpath, handle)) != Z_OK)
		return (err);

	if (!preserve_sw)
		strip_sw_inv(handle);

	handle->zone_dh_newzone = B_TRUE;
	if ((err = setrootattr(handle, DTD_ATTR_ZONEPATH, path)) != Z_OK)
		return (err);

	return (setrootattr(handle, DTD_ATTR_NAME, zonename));
}

int
zonecfg_get_snapshot_handle(const char *zonename, zone_dochandle_t handle)
{
	char path[MAXPATHLEN];

	if (!snap_file_path(zonename, path))
		return (Z_MISC_FS);
	handle->zone_dh_newzone = B_FALSE;
	return (zonecfg_get_handle_impl(zonename, path, handle));
}

int
zonecfg_get_template_handle(const char *template, const char *zonename,
    zone_dochandle_t handle)
{
	char path[MAXPATHLEN];
	int err;

	if (!config_file_path(template, path))
		return (Z_MISC_FS);

	if ((err = zonecfg_get_handle_impl(template, path, handle)) != Z_OK)
		return (err);
	handle->zone_dh_newzone = B_TRUE;
	return (setrootattr(handle, DTD_ATTR_NAME, zonename));
}

int
zonecfg_get_xml_handle(const char *path, zone_dochandle_t handle)
{
	struct stat buf;
	int err;

	if (stat(path, &buf) == -1)
		return (Z_MISC_FS);

	if ((err = zonecfg_get_handle_impl("xml", path, handle)) != Z_OK)
		return (err);
	handle->zone_dh_newzone = B_TRUE;
	return (Z_OK);
}

/*
 * Initialize two handles from the manifest read on fd.  The rem_handle
 * is initialized from the input file, including the sw inventory.  The
 * local_handle is initialized with the same zone configuration but with
 * no sw inventory.
 */
int
zonecfg_attach_manifest(int fd, zone_dochandle_t local_handle,
    zone_dochandle_t rem_handle)
{
	xmlValidCtxtPtr cvp;
	int valid;

	/* load the manifest into the handle for the remote system */
	if ((rem_handle->zone_dh_doc = xmlReadFd(fd, NULL, NULL, 0)) == NULL) {
		return (Z_INVALID_DOCUMENT);
	}
	if ((cvp = xmlNewValidCtxt()) == NULL)
		return (Z_NOMEM);
	cvp->error = zonecfg_error_func;
	cvp->warning = zonecfg_error_func;
	valid = xmlValidateDocument(cvp, rem_handle->zone_dh_doc);
	xmlFreeValidCtxt(cvp);
	if (valid == 0)
		return (Z_INVALID_DOCUMENT);

	/* delete any comments such as inherited Sun copyright / ident str */
	stripcomments(rem_handle);

	rem_handle->zone_dh_newzone = B_TRUE;
	rem_handle->zone_dh_sw_inv = B_TRUE;

	/*
	 * Now use the remote system handle to generate a local system handle
	 * with an identical zones configuration but no sw inventory.
	 */
	if ((local_handle->zone_dh_doc = xmlCopyDoc(rem_handle->zone_dh_doc,
	    1)) == NULL) {
		return (Z_INVALID_DOCUMENT);
	}

	/*
	 * We need to re-run xmlValidateDocument on local_handle to properly
	 * update the in-core representation of the configuration.
	 */
	if ((cvp = xmlNewValidCtxt()) == NULL)
		return (Z_NOMEM);
	cvp->error = zonecfg_error_func;
	cvp->warning = zonecfg_error_func;
	valid = xmlValidateDocument(cvp, local_handle->zone_dh_doc);
	xmlFreeValidCtxt(cvp);
	if (valid == 0)
		return (Z_INVALID_DOCUMENT);

	strip_sw_inv(local_handle);

	local_handle->zone_dh_newzone = B_TRUE;
	local_handle->zone_dh_sw_inv = B_FALSE;

	return (Z_OK);
}

static boolean_t
is_renaming(zone_dochandle_t handle)
{
	if (handle->zone_dh_newzone)
		return (B_FALSE);
	if (strlen(handle->zone_dh_delete_name) > 0)
		return (B_TRUE);
	return (B_FALSE);
}

static boolean_t
is_new(zone_dochandle_t handle)
{
	return (handle->zone_dh_newzone || handle->zone_dh_snapshot);
}

static boolean_t
is_snapshot(zone_dochandle_t handle)
{
	return (handle->zone_dh_snapshot);
}

/*
 * It would be great to be able to use libc's ctype(3c) macros, but we
 * can't, as they are locale sensitive, and it would break our limited thread
 * safety if this routine had to change the app locale on the fly.
 */
int
zonecfg_validate_zonename(const char *zone)
{
	int i;

	if (strcmp(zone, GLOBAL_ZONENAME) == 0)
		return (Z_BOGUS_ZONE_NAME);

	if (strlen(zone) >= ZONENAME_MAX)
		return (Z_BOGUS_ZONE_NAME);

	if (!((zone[0] >= 'a' && zone[0] <= 'z') ||
	    (zone[0] >= 'A' && zone[0] <= 'Z') ||
	    (zone[0] >= '0' && zone[0] <= '9')))
		return (Z_BOGUS_ZONE_NAME);

	for (i = 1; zone[i] != '\0'; i++) {
		if (!((zone[i] >= 'a' && zone[i] <= 'z') ||
		    (zone[i] >= 'A' && zone[i] <= 'Z') ||
		    (zone[i] >= '0' && zone[i] <= '9') ||
		    (zone[i] == '-') || (zone[i] == '_') || (zone[i] == '.')))
			return (Z_BOGUS_ZONE_NAME);
	}

	return (Z_OK);
}

/*
 * Changing the zone name requires us to track both the old and new
 * name of the zone until commit time.
 */
int
zonecfg_get_name(zone_dochandle_t handle, char *name, size_t namesize)
{
	return (getrootattr(handle, DTD_ATTR_NAME, name, namesize));
}

int
zonecfg_set_name(zone_dochandle_t handle, char *name)
{
	zone_state_t state;
	char curname[ZONENAME_MAX], old_delname[ZONENAME_MAX];
	int err;

	if ((err = getrootattr(handle, DTD_ATTR_NAME, curname,
	    sizeof (curname))) != Z_OK)
		return (err);

	if (strcmp(name, curname) == 0)
		return (Z_OK);

	/*
	 * Switching zone names to one beginning with SUNW is not permitted.
	 */
	if (strncmp(name, "SUNW", 4) == 0)
		return (Z_BOGUS_ZONE_NAME);

	if ((err = zonecfg_validate_zonename(name)) != Z_OK)
		return (err);

	/*
	 * Setting the name back to the original name (effectively a revert of
	 * the name) is fine.  But if we carry on, we'll falsely identify the
	 * name as "in use," so special case here.
	 */
	if (strcmp(name, handle->zone_dh_delete_name) == 0) {
		err = setrootattr(handle, DTD_ATTR_NAME, name);
		handle->zone_dh_delete_name[0] = '\0';
		return (err);
	}

	/* Check to see if new name chosen is already in use */
	if (zone_get_state(name, &state) != Z_NO_ZONE)
		return (Z_NAME_IN_USE);

	/*
	 * If this isn't already "new" or in a renaming transition, then
	 * we're initiating a rename here; so stash the "delete name"
	 * (i.e. the name of the zone we'll be removing) for the rename.
	 */
	(void) strlcpy(old_delname, handle->zone_dh_delete_name,
	    sizeof (old_delname));
	if (!is_new(handle) && !is_renaming(handle)) {
		/*
		 * Name change is allowed only when the zone we're altering
		 * is not ready or running.
		 */
		err = zone_get_state(curname, &state);
		if (err == Z_OK) {
			if (state > ZONE_STATE_INSTALLED)
				return (Z_BAD_ZONE_STATE);
		} else if (err != Z_NO_ZONE) {
			return (err);
		}

		(void) strlcpy(handle->zone_dh_delete_name, curname,
		    sizeof (handle->zone_dh_delete_name));
		assert(is_renaming(handle));
	} else if (is_renaming(handle)) {
		err = zone_get_state(handle->zone_dh_delete_name, &state);
		if (err == Z_OK) {
			if (state > ZONE_STATE_INSTALLED)
				return (Z_BAD_ZONE_STATE);
		} else if (err != Z_NO_ZONE) {
			return (err);
		}
	}

	if ((err = setrootattr(handle, DTD_ATTR_NAME, name)) != Z_OK) {
		/*
		 * Restore the deletename to whatever it was at the
		 * top of the routine, since we've had a failure.
		 */
		(void) strlcpy(handle->zone_dh_delete_name, old_delname,
		    sizeof (handle->zone_dh_delete_name));
		return (err);
	}

	return (Z_OK);
}

int
zonecfg_get_zonepath(zone_dochandle_t handle, char *path, size_t pathsize)
{
	size_t len;

	if ((len = strlcpy(path, zonecfg_root, pathsize)) >= pathsize)
		return (Z_TOO_BIG);
	return (getrootattr(handle, DTD_ATTR_ZONEPATH, path + len,
	    pathsize - len));
}

int
zonecfg_set_zonepath(zone_dochandle_t handle, char *zonepath)
{
	size_t len;

	/*
	 * The user deals in absolute paths in the running global zone, but the
	 * internal configuration files deal with boot environment relative
	 * paths.  Strip out the alternate root when specified.
	 */
	len = strlen(zonecfg_root);
	if (strncmp(zonepath, zonecfg_root, len) != 0 || zonepath[len] != '/')
		return (Z_BAD_PROPERTY);
	zonepath += len;
	return (setrootattr(handle, DTD_ATTR_ZONEPATH, zonepath));
}

int
zonecfg_get_brand(zone_dochandle_t handle, char *brand, size_t brandsize)
{
	int ret, sz;

	ret = getrootattr(handle, DTD_ATTR_BRAND, brand, brandsize);

	/* If the zone has no brand, it is native. */
	if (ret == Z_OK && brand[0] == '\0') {
		sz = strlcpy(brand, NATIVE_BRAND_NAME, brandsize);
		if (sz >= brandsize)
			ret = Z_TOO_BIG;
		else
			ret = Z_OK;
	}

	return (ret);
}

int
zonecfg_set_brand(zone_dochandle_t handle, char *brand)
{
	return (setrootattr(handle, DTD_ATTR_BRAND, brand));
}

int
zonecfg_get_autoboot(zone_dochandle_t handle, boolean_t *autoboot)
{
	char autobootstr[DTD_ENTITY_BOOL_LEN];
	int ret;

	if ((ret = getrootattr(handle, DTD_ATTR_AUTOBOOT, autobootstr,
	    sizeof (autobootstr))) != Z_OK)
		return (ret);

	if (strcmp(autobootstr, DTD_ENTITY_TRUE) == 0)
		*autoboot = B_TRUE;
	else if (strcmp(autobootstr, DTD_ENTITY_FALSE) == 0)
		*autoboot = B_FALSE;
	else
		ret = Z_BAD_PROPERTY;
	return (ret);
}

int
zonecfg_set_autoboot(zone_dochandle_t handle, boolean_t autoboot)
{
	return (setrootattr(handle, DTD_ATTR_AUTOBOOT,
	    autoboot ? DTD_ENTITY_TRUE : DTD_ENTITY_FALSE));
}

int
zonecfg_get_pool(zone_dochandle_t handle, char *pool, size_t poolsize)
{
	return (getrootattr(handle, DTD_ATTR_POOL, pool, poolsize));
}

int
zonecfg_set_pool(zone_dochandle_t handle, char *pool)
{
	return (setrootattr(handle, DTD_ATTR_POOL, pool));
}

int
zonecfg_get_limitpriv(zone_dochandle_t handle, char **limitpriv)
{
	return (get_alloc_rootattr(handle, DTD_ATTR_LIMITPRIV, limitpriv));
}

int
zonecfg_set_limitpriv(zone_dochandle_t handle, char *limitpriv)
{
	return (setrootattr(handle, DTD_ATTR_LIMITPRIV, limitpriv));
}

int
zonecfg_get_bootargs(zone_dochandle_t handle, char *bargs, size_t bargssize)
{
	return (getrootattr(handle, DTD_ATTR_BOOTARGS, bargs, bargssize));
}

int
zonecfg_set_bootargs(zone_dochandle_t handle, char *bargs)
{
	return (setrootattr(handle, DTD_ATTR_BOOTARGS, bargs));
}

int
zonecfg_get_sched_class(zone_dochandle_t handle, char *sched, size_t schedsize)
{
	return (getrootattr(handle, DTD_ATTR_SCHED, sched, schedsize));
}

int
zonecfg_set_sched(zone_dochandle_t handle, char *sched)
{
	return (setrootattr(handle, DTD_ATTR_SCHED, sched));
}

/*
 * /etc/zones/index caches a vital piece of information which is also
 * in the <zonename>.xml file: the path to the zone.  This is for performance,
 * since we need to walk all zonepath's in order to be able to detect conflicts
 * (see crosscheck_zonepaths() in the zoneadm command).
 *
 * An additional complexity is that when doing a rename, we'd like the entire
 * index update operation (rename, and potential state changes) to be atomic.
 * In general, the operation of this function should succeed or fail as
 * a unit.
 */
int
zonecfg_refresh_index_file(zone_dochandle_t handle)
{
	char name[ZONENAME_MAX], zonepath[MAXPATHLEN];
	struct zoneent ze;
	int err;
	int opcode;
	char *zn;

	bzero(&ze, sizeof (ze));
	ze.zone_state = -1;	/* Preserve existing state in index */

	if ((err = zonecfg_get_name(handle, name, sizeof (name))) != Z_OK)
		return (err);
	(void) strlcpy(ze.zone_name, name, sizeof (ze.zone_name));

	if ((err = zonecfg_get_zonepath(handle, zonepath,
	    sizeof (zonepath))) != Z_OK)
		return (err);
	(void) strlcpy(ze.zone_path, zonepath + strlen(zonecfg_root),
	    sizeof (ze.zone_path));

	if (is_renaming(handle)) {
		opcode = PZE_MODIFY;
		(void) strlcpy(ze.zone_name, handle->zone_dh_delete_name,
		    sizeof (ze.zone_name));
		(void) strlcpy(ze.zone_newname, name, sizeof (ze.zone_newname));
	} else if (is_new(handle)) {
		FILE *cookie;
		/*
		 * Be tolerant of the zone already existing in the index file,
		 * since we might be forcibly overwriting an existing
		 * configuration with a new one (for example 'create -F'
		 * in zonecfg).
		 */
		opcode = PZE_ADD;
		cookie = setzoneent();
		while ((zn = getzoneent(cookie)) != NULL) {
			if (strcmp(zn, name) == 0) {
				opcode = PZE_MODIFY;
				free(zn);
				break;
			}
			free(zn);
		}
		endzoneent(cookie);
		ze.zone_state = ZONE_STATE_CONFIGURED;
	} else {
		opcode = PZE_MODIFY;
	}

	if ((err = putzoneent(&ze, opcode)) != Z_OK)
		return (err);

	return (Z_OK);
}

/*
 * The goal of this routine is to cause the index file update and the
 * document save to happen as an atomic operation.  We do the document
 * first, saving a backup copy using a hard link; if that succeeds, we go
 * on to the index.  If that fails, we roll the document back into place.
 *
 * Strategy:
 *
 * New zone 'foo' configuration:
 * 	Create tmpfile (zonecfg.xxxxxx)
 * 	Write XML to tmpfile
 * 	Rename tmpfile to xmlfile (zonecfg.xxxxxx -> foo.xml)
 * 	Add entry to index file
 * 	If it fails, delete foo.xml, leaving nothing behind.
 *
 * Save existing zone 'foo':
 * 	Make backup of foo.xml -> .backup
 * 	Create tmpfile (zonecfg.xxxxxx)
 * 	Write XML to tmpfile
 * 	Rename tmpfile to xmlfile (zonecfg.xxxxxx -> foo.xml)
 * 	Modify index file as needed
 * 	If it fails, recover from .backup -> foo.xml
 *
 * Rename 'foo' to 'bar':
 * 	Create tmpfile (zonecfg.xxxxxx)
 * 	Write XML to tmpfile
 * 	Rename tmpfile to xmlfile (zonecfg.xxxxxx -> bar.xml)
 * 	Add entry for 'bar' to index file, Remove entry for 'foo' (refresh)
 * 	If it fails, delete bar.xml; foo.xml is left behind.
 */
static int
zonecfg_save_impl(zone_dochandle_t handle, char *filename)
{
	char tmpfile[MAXPATHLEN];
	char bakdir[MAXPATHLEN], bakbase[MAXPATHLEN], bakfile[MAXPATHLEN];
	int tmpfd, err, valid;
	xmlValidCtxt cvp = { NULL };
	boolean_t backup;

	(void) strlcpy(tmpfile, filename, sizeof (tmpfile));
	(void) dirname(tmpfile);
	(void) strlcat(tmpfile, _PATH_TMPFILE, sizeof (tmpfile));

	tmpfd = mkstemp(tmpfile);
	if (tmpfd == -1) {
		(void) unlink(tmpfile);
		return (Z_TEMP_FILE);
	}
	(void) close(tmpfd);

	cvp.error = zonecfg_error_func;
	cvp.warning = zonecfg_error_func;

	/*
	 * We do a final validation of the document.  Since the library has
	 * malfunctioned if it fails to validate, we follow-up with an
	 * assert() that the doc is valid.
	 */
	valid = xmlValidateDocument(&cvp, handle->zone_dh_doc);
	assert(valid != 0);

	if (xmlSaveFormatFile(tmpfile, handle->zone_dh_doc, 1) <= 0)
		goto err;

	(void) chmod(tmpfile, 0644);

	/*
	 * In the event we are doing a standard save, hard link a copy of the
	 * original file in .backup.<pid>.filename so we can restore it if
	 * something goes wrong.
	 */
	if (!is_new(handle) && !is_renaming(handle)) {
		backup = B_TRUE;

		(void) strlcpy(bakdir, filename, sizeof (bakdir));
		(void) strlcpy(bakbase, filename, sizeof (bakbase));
		(void) snprintf(bakfile, sizeof (bakfile), "%s/.backup.%d.%s",
		    dirname(bakdir), getpid(), basename(bakbase));

		if (link(filename, bakfile) == -1) {
			err = errno;
			(void) unlink(tmpfile);
			if (errno == EACCES)
				return (Z_ACCES);
			return (Z_MISC_FS);
		}
	}

	/*
	 * Move the new document over top of the old.
	 * i.e.:   zonecfg.XXXXXX  ->  myzone.xml
	 */
	if (rename(tmpfile, filename) == -1) {
		err = errno;
		(void) unlink(tmpfile);
		if (backup)
			(void) unlink(bakfile);
		if (err == EACCES)
			return (Z_ACCES);
		return (Z_MISC_FS);
	}

	/*
	 * If this is a snapshot, we're done-- don't add an index entry.
	 */
	if (is_snapshot(handle))
		return (Z_OK);

	/* now update the index file to reflect whatever we just did */
	if ((err = zonecfg_refresh_index_file(handle)) != Z_OK) {
		if (backup) {
			/*
			 * Try to restore from our backup.
			 */
			(void) unlink(filename);
			(void) rename(bakfile, filename);
		} else {
			/*
			 * Either the zone is new, in which case we can delete
			 * new.xml, or we're doing a rename, so ditto.
			 */
			assert(is_new(handle) || is_renaming(handle));
			(void) unlink(filename);
		}
		return (Z_UPDATING_INDEX);
	}

	if (backup)
		(void) unlink(bakfile);

	return (Z_OK);

err:
	(void) unlink(tmpfile);
	return (Z_SAVING_FILE);
}

int
zonecfg_save(zone_dochandle_t handle)
{
	char zname[ZONENAME_MAX], path[MAXPATHLEN];
	char delpath[MAXPATHLEN];
	int err = Z_SAVING_FILE;

	if (zonecfg_check_handle(handle) != Z_OK)
		return (Z_BAD_HANDLE);

	/*
	 * We don't support saving snapshots or a tree containing a sw
	 * inventory at this time.
	 */
	if (handle->zone_dh_snapshot || handle->zone_dh_sw_inv)
		return (Z_INVAL);

	if ((err = zonecfg_get_name(handle, zname, sizeof (zname))) != Z_OK)
		return (err);

	if (!config_file_path(zname, path))
		return (Z_MISC_FS);

	addcomment(handle, "\n    DO NOT EDIT THIS "
	    "FILE.  Use zonecfg(1M) instead.\n");

	err = zonecfg_save_impl(handle, path);

	stripcomments(handle);

	if (err != Z_OK)
		return (err);

	handle->zone_dh_newzone = B_FALSE;

	if (is_renaming(handle)) {
		if (config_file_path(handle->zone_dh_delete_name, delpath))
			(void) unlink(delpath);
		handle->zone_dh_delete_name[0] = '\0';
	}

	return (Z_OK);
}

int
zonecfg_verify_save(zone_dochandle_t handle, char *filename)
{
	int valid;

	xmlValidCtxt cvp = { NULL };

	if (zonecfg_check_handle(handle) != Z_OK)
		return (Z_BAD_HANDLE);

	cvp.error = zonecfg_error_func;
	cvp.warning = zonecfg_error_func;

	/*
	 * We do a final validation of the document.  Since the library has
	 * malfunctioned if it fails to validate, we follow-up with an
	 * assert() that the doc is valid.
	 */
	valid = xmlValidateDocument(&cvp, handle->zone_dh_doc);
	assert(valid != 0);

	if (xmlSaveFormatFile(filename, handle->zone_dh_doc, 1) <= 0)
		return (Z_SAVING_FILE);

	return (Z_OK);
}

int
zonecfg_detach_save(zone_dochandle_t handle, uint_t flags)
{
	char zname[ZONENAME_MAX];
	char path[MAXPATHLEN];
	char migpath[MAXPATHLEN];
	xmlValidCtxt cvp = { NULL };
	int err = Z_SAVING_FILE;
	int valid;

	if (zonecfg_check_handle(handle) != Z_OK)
		return (Z_BAD_HANDLE);

	/*
	 * We can only detach if we have taken a sw inventory.
	 */
	if (!handle->zone_dh_sw_inv)
		return (Z_INVAL);

	if (flags & ZONE_DRY_RUN) {
		(void) strlcpy(migpath, "-", sizeof (migpath));
	} else {
		if ((err = zonecfg_get_name(handle, zname, sizeof (zname)))
		    != Z_OK)
			return (err);

		if ((err = zone_get_zonepath(zname, path, sizeof (path)))
		    != Z_OK)
			return (err);

		if (snprintf(migpath, sizeof (migpath), "%s/%s", path, DETACHED)
		    >= sizeof (migpath))
			return (Z_NOMEM);
	}

	if ((err = operation_prep(handle)) != Z_OK)
		return (err);

	addcomment(handle, "\n    DO NOT EDIT THIS FILE.  "
	    "Use zonecfg(1M) and zoneadm(1M) attach.\n");

	cvp.error = zonecfg_error_func;
	cvp.warning = zonecfg_error_func;

	/*
	 * We do a final validation of the document.  Since the library has
	 * malfunctioned if it fails to validate, we follow-up with an
	 * assert() that the doc is valid.
	 */
	valid = xmlValidateDocument(&cvp, handle->zone_dh_doc);
	assert(valid != 0);

	if (xmlSaveFormatFile(migpath, handle->zone_dh_doc, 1) <= 0)
		return (Z_SAVING_FILE);

	if (!(flags & ZONE_DRY_RUN))
		(void) chmod(migpath, 0644);

	stripcomments(handle);

	handle->zone_dh_newzone = B_FALSE;

	return (Z_OK);
}

boolean_t
zonecfg_detached(const char *path)
{
	char		migpath[MAXPATHLEN];
	struct stat	buf;

	if (snprintf(migpath, sizeof (migpath), "%s/%s", path, DETACHED) >=
	    sizeof (migpath))
		return (B_FALSE);

	if (stat(migpath, &buf) != -1)
		return (B_TRUE);

	return (B_FALSE);
}

void
zonecfg_rm_detached(zone_dochandle_t handle, boolean_t forced)
{
	char zname[ZONENAME_MAX];
	char path[MAXPATHLEN];
	char detached[MAXPATHLEN];
	char attached[MAXPATHLEN];

	if (zonecfg_check_handle(handle) != Z_OK)
		return;

	if (zonecfg_get_name(handle, zname, sizeof (zname)) != Z_OK)
		return;

	if (zone_get_zonepath(zname, path, sizeof (path)) != Z_OK)
		return;

	(void) snprintf(detached, sizeof (detached), "%s/%s", path, DETACHED);
	(void) snprintf(attached, sizeof (attached), "%s/%s", path,
	    ATTACH_FORCED);

	if (forced) {
		(void) rename(detached, attached);
	} else {
		(void) unlink(attached);
		(void) unlink(detached);
	}
}

/*
 * Special case: if access(2) fails with ENOENT, then try again using
 * ZONE_CONFIG_ROOT instead of config_file_path(zonename).  This is how we
 * work around the case of a config file which has not been created yet:
 * the user will need access to the directory so use that as a heuristic.
 */

int
zonecfg_access(const char *zonename, int amode)
{
	char path[MAXPATHLEN];

	if (!config_file_path(zonename, path))
		return (Z_INVAL);
	if (access(path, amode) == 0)
		return (Z_OK);
	if (errno == ENOENT) {
		if (snprintf(path, sizeof (path), "%s%s", zonecfg_root,
		    ZONE_CONFIG_ROOT) >= sizeof (path))
			return (Z_INVAL);
		if (access(path, amode) == 0)
			return (Z_OK);
	}
	if (errno == EACCES)
		return (Z_ACCES);
	if (errno == EINVAL)
		return (Z_INVAL);
	return (Z_MISC_FS);
}

int
zonecfg_create_snapshot(const char *zonename)
{
	zone_dochandle_t handle;
	char path[MAXPATHLEN], zonepath[MAXPATHLEN], rpath[MAXPATHLEN];
	int error = Z_OK, res;

	if ((handle = zonecfg_init_handle()) == NULL) {
		return (Z_NOMEM);
	}

	handle->zone_dh_newzone = B_TRUE;
	handle->zone_dh_snapshot = B_TRUE;

	if ((error = zonecfg_get_handle(zonename, handle)) != Z_OK)
		goto out;
	if ((error = operation_prep(handle)) != Z_OK)
		goto out;
	error = zonecfg_get_zonepath(handle, zonepath, sizeof (zonepath));
	if (error != Z_OK)
		goto out;
	if ((res = resolvepath(zonepath, rpath, sizeof (rpath))) == -1) {
		error = Z_RESOLVED_PATH;
		goto out;
	}
	/*
	 * If the resolved path is not the same as the original path, then
	 * save the resolved path in the snapshot, thus preventing any
	 * potential problems down the line when zoneadmd goes to unmount
	 * file systems and depends on initial string matches with resolved
	 * paths.
	 */
	rpath[res] = '\0';
	if (strcmp(zonepath, rpath) != 0) {
		if ((error = zonecfg_set_zonepath(handle, rpath)) != Z_OK)
			goto out;
	}
	if (snprintf(path, sizeof (path), "%s%s", zonecfg_root,
	    ZONE_SNAPSHOT_ROOT) >= sizeof (path)) {
		error = Z_MISC_FS;
		goto out;
	}
	if ((mkdir(path, S_IRWXU) == -1) && (errno != EEXIST)) {
		error = Z_MISC_FS;
		goto out;
	}

	if (!snap_file_path(zonename, path)) {
		error = Z_MISC_FS;
		goto out;
	}

	addcomment(handle, "\n    DO NOT EDIT THIS FILE.  "
	    "It is a snapshot of running zone state.\n");

	error = zonecfg_save_impl(handle, path);

	stripcomments(handle);

out:
	zonecfg_fini_handle(handle);
	return (error);
}

int
zonecfg_get_iptype(zone_dochandle_t handle, zone_iptype_t *iptypep)
{
	char property[10]; /* 10 is big enough for "shared"/"exclusive" */
	int err;

	err = getrootattr(handle, DTD_ATTR_IPTYPE, property, sizeof (property));
	if (err == Z_BAD_PROPERTY) {
		/* Return default value */
		*iptypep = ZS_SHARED;
		return (Z_OK);
	} else if (err != Z_OK) {
		return (err);
	}

	if (strlen(property) == 0 ||
	    strcmp(property, "shared") == 0)
		*iptypep = ZS_SHARED;
	else if (strcmp(property, "exclusive") == 0)
		*iptypep = ZS_EXCLUSIVE;
	else
		return (Z_INVAL);

	return (Z_OK);
}

int
zonecfg_set_iptype(zone_dochandle_t handle, zone_iptype_t iptype)
{
	xmlNodePtr cur;

	if (handle == NULL)
		return (Z_INVAL);

	cur = xmlDocGetRootElement(handle->zone_dh_doc);
	if (cur == NULL) {
		return (Z_EMPTY_DOCUMENT);
	}

	if (xmlStrcmp(cur->name, DTD_ELEM_ZONE) != 0) {
		return (Z_WRONG_DOC_TYPE);
	}
	switch (iptype) {
	case ZS_SHARED:
		/*
		 * Since "shared" is the default, we don't write it to the
		 * configuration file, so that it's easier to migrate those
		 * zones elsewhere, eg., to systems which are not IP-Instances
		 * aware.
		 * xmlUnsetProp only fails when the attribute doesn't exist,
		 * which we don't care.
		 */
		(void) xmlUnsetProp(cur, DTD_ATTR_IPTYPE);
		break;
	case ZS_EXCLUSIVE:
		if (xmlSetProp(cur, DTD_ATTR_IPTYPE,
		    (const xmlChar *) "exclusive") == NULL)
			return (Z_INVAL);
		break;
	}
	return (Z_OK);
}

static int
newprop(xmlNodePtr node, const xmlChar *attrname, char *src)
{
	xmlAttrPtr newattr;

	newattr = xmlNewProp(node, attrname, (xmlChar *)src);
	if (newattr == NULL) {
		xmlUnlinkNode(node);
		xmlFreeNode(node);
		return (Z_BAD_PROPERTY);
	}
	return (Z_OK);
}

static int
zonecfg_add_filesystem_core(zone_dochandle_t handle, struct zone_fstab *tabptr)
{
	xmlNodePtr newnode, cur = handle->zone_dh_cur, options_node;
	zone_fsopt_t *ptr;
	int err;

	newnode = xmlNewTextChild(cur, NULL, DTD_ELEM_FS, NULL);
	if ((err = newprop(newnode, DTD_ATTR_SPECIAL,
	    tabptr->zone_fs_special)) != Z_OK)
		return (err);
	if (tabptr->zone_fs_raw[0] != '\0' &&
	    (err = newprop(newnode, DTD_ATTR_RAW, tabptr->zone_fs_raw)) != Z_OK)
		return (err);
	if ((err = newprop(newnode, DTD_ATTR_DIR, tabptr->zone_fs_dir)) != Z_OK)
		return (err);
	if ((err = newprop(newnode, DTD_ATTR_TYPE,
	    tabptr->zone_fs_type)) != Z_OK)
		return (err);
	if (tabptr->zone_fs_options != NULL) {
		for (ptr = tabptr->zone_fs_options; ptr != NULL;
		    ptr = ptr->zone_fsopt_next) {
			options_node = xmlNewTextChild(newnode, NULL,
			    DTD_ELEM_FSOPTION, NULL);
			if ((err = newprop(options_node, DTD_ATTR_NAME,
			    ptr->zone_fsopt_opt)) != Z_OK)
				return (err);
		}
	}
	return (Z_OK);
}

int
zonecfg_add_filesystem(zone_dochandle_t handle, struct zone_fstab *tabptr)
{
	int err;

	if (tabptr == NULL)
		return (Z_INVAL);

	if ((err = operation_prep(handle)) != Z_OK)
		return (err);

	if ((err = zonecfg_add_filesystem_core(handle, tabptr)) != Z_OK)
		return (err);

	return (Z_OK);
}

static int
zonecfg_add_ipd_core(zone_dochandle_t handle, struct zone_fstab *tabptr)
{
	xmlNodePtr newnode, cur = handle->zone_dh_cur;
	int err;

	newnode = xmlNewTextChild(cur, NULL, DTD_ELEM_IPD, NULL);
	if ((err = newprop(newnode, DTD_ATTR_DIR, tabptr->zone_fs_dir)) != Z_OK)
		return (err);
	return (Z_OK);
}

int
zonecfg_add_ipd(zone_dochandle_t handle, struct zone_fstab *tabptr)
{
	int err;

	if (tabptr == NULL)
		return (Z_INVAL);

	if ((err = operation_prep(handle)) != Z_OK)
		return (err);

	if ((err = zonecfg_add_ipd_core(handle, tabptr)) != Z_OK)
		return (err);

	return (Z_OK);
}

int
zonecfg_add_fs_option(struct zone_fstab *tabptr, char *option)
{
	zone_fsopt_t *last, *old, *new;

	last = tabptr->zone_fs_options;
	for (old = last; old != NULL; old = old->zone_fsopt_next)
		last = old;	/* walk to the end of the list */
	new = (zone_fsopt_t *)malloc(sizeof (zone_fsopt_t));
	if (new == NULL)
		return (Z_NOMEM);
	(void) strlcpy(new->zone_fsopt_opt, option,
	    sizeof (new->zone_fsopt_opt));
	new->zone_fsopt_next = NULL;
	if (last == NULL)
		tabptr->zone_fs_options = new;
	else
		last->zone_fsopt_next = new;
	return (Z_OK);
}

int
zonecfg_remove_fs_option(struct zone_fstab *tabptr, char *option)
{
	zone_fsopt_t *last, *this, *next;

	last = tabptr->zone_fs_options;
	for (this = last; this != NULL; this = this->zone_fsopt_next) {
		if (strcmp(this->zone_fsopt_opt, option) == 0) {
			next = this->zone_fsopt_next;
			if (this == tabptr->zone_fs_options)
				tabptr->zone_fs_options = next;
			else
				last->zone_fsopt_next = next;
			free(this);
			return (Z_OK);
		} else
			last = this;
	}
	return (Z_NO_PROPERTY_ID);
}

void
zonecfg_free_fs_option_list(zone_fsopt_t *list)
{
	zone_fsopt_t *this, *next;

	for (this = list; this != NULL; this = next) {
		next = this->zone_fsopt_next;
		free(this);
	}
}

void
zonecfg_free_rctl_value_list(struct zone_rctlvaltab *valtab)
{
	if (valtab == NULL)
		return;
	zonecfg_free_rctl_value_list(valtab->zone_rctlval_next);
	free(valtab);
}

static boolean_t
match_prop(xmlNodePtr cur, const xmlChar *attr, char *user_prop)
{
	xmlChar *gotten_prop;
	int prop_result;

	gotten_prop = xmlGetProp(cur, attr);
	if (gotten_prop == NULL)	/* shouldn't happen */
		return (B_FALSE);
	prop_result = xmlStrcmp(gotten_prop, (const xmlChar *) user_prop);
	xmlFree(gotten_prop);
	return ((prop_result == 0));
}

static int
zonecfg_delete_filesystem_core(zone_dochandle_t handle,
    struct zone_fstab *tabptr)
{
	xmlNodePtr cur = handle->zone_dh_cur;
	boolean_t dir_match, spec_match, raw_match, type_match;

	for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next) {
		if (xmlStrcmp(cur->name, DTD_ELEM_FS))
			continue;
		dir_match = match_prop(cur, DTD_ATTR_DIR, tabptr->zone_fs_dir);
		spec_match = match_prop(cur, DTD_ATTR_SPECIAL,
		    tabptr->zone_fs_special);
		raw_match = match_prop(cur, DTD_ATTR_RAW,
		    tabptr->zone_fs_raw);
		type_match = match_prop(cur, DTD_ATTR_TYPE,
		    tabptr->zone_fs_type);
		if (dir_match && spec_match && raw_match && type_match) {
			xmlUnlinkNode(cur);
			xmlFreeNode(cur);
			return (Z_OK);
		}
	}
	return (Z_NO_RESOURCE_ID);
}

int
zonecfg_delete_filesystem(zone_dochandle_t handle, struct zone_fstab *tabptr)
{
	int err;

	if (tabptr == NULL)
		return (Z_INVAL);

	if ((err = operation_prep(handle)) != Z_OK)
		return (err);

	if ((err = zonecfg_delete_filesystem_core(handle, tabptr)) != Z_OK)
		return (err);

	return (Z_OK);
}

int
zonecfg_modify_filesystem(
	zone_dochandle_t handle,
	struct zone_fstab *oldtabptr,
	struct zone_fstab *newtabptr)
{
	int err;

	if (oldtabptr == NULL || newtabptr == NULL)
		return (Z_INVAL);

	if ((err = operation_prep(handle)) != Z_OK)
		return (err);

	if ((err = zonecfg_delete_filesystem_core(handle, oldtabptr)) != Z_OK)
		return (err);

	if ((err = zonecfg_add_filesystem_core(handle, newtabptr)) != Z_OK)
		return (err);

	return (Z_OK);
}

static int
zonecfg_delete_ipd_core(zone_dochandle_t handle, struct zone_fstab *tabptr)
{
	xmlNodePtr cur = handle->zone_dh_cur;

	for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next) {
		if (xmlStrcmp(cur->name, DTD_ELEM_IPD))
			continue;
		if (match_prop(cur, DTD_ATTR_DIR, tabptr->zone_fs_dir)) {
			xmlUnlinkNode(cur);
			xmlFreeNode(cur);
			return (Z_OK);
		}
	}
	return (Z_NO_RESOURCE_ID);
}

int
zonecfg_delete_ipd(zone_dochandle_t handle, struct zone_fstab *tabptr)
{
	int err;

	if (tabptr == NULL)
		return (Z_INVAL);

	if ((err = operation_prep(handle)) != Z_OK)
		return (err);

	if ((err = zonecfg_delete_ipd_core(handle, tabptr)) != Z_OK)
		return (err);

	return (Z_OK);
}

int
zonecfg_modify_ipd(zone_dochandle_t handle, struct zone_fstab *oldtabptr,
    struct zone_fstab *newtabptr)
{
	int err;

	if (oldtabptr == NULL || newtabptr == NULL)
		return (Z_INVAL);

	if ((err = operation_prep(handle)) != Z_OK)
		return (err);

	if ((err = zonecfg_delete_ipd_core(handle, oldtabptr)) != Z_OK)
		return (err);

	if ((err = zonecfg_add_ipd_core(handle, newtabptr)) != Z_OK)
		return (err);

	return (Z_OK);
}

int
zonecfg_lookup_filesystem(
	zone_dochandle_t handle,
	struct zone_fstab *tabptr)
{
	xmlNodePtr cur, options, firstmatch;
	int err;
	char dirname[MAXPATHLEN], special[MAXPATHLEN], raw[MAXPATHLEN];
	char type[FSTYPSZ];
	char options_str[MAX_MNTOPT_STR];

	if (tabptr == NULL)
		return (Z_INVAL);

	if ((err = operation_prep(handle)) != Z_OK)
		return (err);

	/*
	 * Walk the list of children looking for matches on any properties
	 * specified in the fstab parameter.  If more than one resource
	 * matches, we return Z_INSUFFICIENT_SPEC; if none match, we return
	 * Z_NO_RESOURCE_ID.
	 */
	cur = handle->zone_dh_cur;
	firstmatch = NULL;
	for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next) {
		if (xmlStrcmp(cur->name, DTD_ELEM_FS))
			continue;
		if (strlen(tabptr->zone_fs_dir) > 0) {
			if ((fetchprop(cur, DTD_ATTR_DIR, dirname,
			    sizeof (dirname)) == Z_OK) &&
			    (strcmp(tabptr->zone_fs_dir, dirname) == 0)) {
				if (firstmatch == NULL)
					firstmatch = cur;
				else
					return (Z_INSUFFICIENT_SPEC);
			}
		}
		if (strlen(tabptr->zone_fs_special) > 0) {
			if ((fetchprop(cur, DTD_ATTR_SPECIAL, special,
			    sizeof (special)) == Z_OK)) {
				if (strcmp(tabptr->zone_fs_special,
				    special) == 0) {
					if (firstmatch == NULL)
						firstmatch = cur;
					else if (firstmatch != cur)
						return (Z_INSUFFICIENT_SPEC);
				} else {
					/*
					 * If another property matched but this
					 * one doesn't then reset firstmatch.
					 */
					if (firstmatch == cur)
						firstmatch = NULL;
				}
			}
		}
		if (strlen(tabptr->zone_fs_raw) > 0) {
			if ((fetchprop(cur, DTD_ATTR_RAW, raw,
			    sizeof (raw)) == Z_OK)) {
				if (strcmp(tabptr->zone_fs_raw, raw) == 0) {
					if (firstmatch == NULL)
						firstmatch = cur;
					else if (firstmatch != cur)
						return (Z_INSUFFICIENT_SPEC);
				} else {
					/*
					 * If another property matched but this
					 * one doesn't then reset firstmatch.
					 */
					if (firstmatch == cur)
						firstmatch = NULL;
				}
			}
		}
		if (strlen(tabptr->zone_fs_type) > 0) {
			if ((fetchprop(cur, DTD_ATTR_TYPE, type,
			    sizeof (type)) == Z_OK)) {
				if (strcmp(tabptr->zone_fs_type, type) == 0) {
					if (firstmatch == NULL)
						firstmatch = cur;
					else if (firstmatch != cur)
						return (Z_INSUFFICIENT_SPEC);
				} else {
					/*
					 * If another property matched but this
					 * one doesn't then reset firstmatch.
					 */
					if (firstmatch == cur)
						firstmatch = NULL;
				}
			}
		}
	}

	if (firstmatch == NULL)
		return (Z_NO_RESOURCE_ID);

	cur = firstmatch;

	if ((err = fetchprop(cur, DTD_ATTR_DIR, tabptr->zone_fs_dir,
	    sizeof (tabptr->zone_fs_dir))) != Z_OK)
		return (err);

	if ((err = fetchprop(cur, DTD_ATTR_SPECIAL, tabptr->zone_fs_special,
	    sizeof (tabptr->zone_fs_special))) != Z_OK)
		return (err);

	if ((err = fetchprop(cur, DTD_ATTR_RAW, tabptr->zone_fs_raw,
	    sizeof (tabptr->zone_fs_raw))) != Z_OK)
		return (err);

	if ((err = fetchprop(cur, DTD_ATTR_TYPE, tabptr->zone_fs_type,
	    sizeof (tabptr->zone_fs_type))) != Z_OK)
		return (err);

	/* options are optional */
	tabptr->zone_fs_options = NULL;
	for (options = cur->xmlChildrenNode; options != NULL;
	    options = options->next) {
		if ((fetchprop(options, DTD_ATTR_NAME, options_str,
		    sizeof (options_str)) != Z_OK))
			break;
		if (zonecfg_add_fs_option(tabptr, options_str) != Z_OK)
			break;
	}
	return (Z_OK);
}

int
zonecfg_lookup_ipd(zone_dochandle_t handle, struct zone_fstab *tabptr)
{
	xmlNodePtr cur, match;
	int err;
	char dirname[MAXPATHLEN];

	if (tabptr == NULL)
		return (Z_INVAL);

	if ((err = operation_prep(handle)) != Z_OK)
		return (err);

	/*
	 * General algorithm:
	 * Walk the list of children looking for matches on any properties
	 * specified in the fstab parameter.  If more than one resource
	 * matches, we return Z_INSUFFICIENT_SPEC; if none match, we return
	 * Z_NO_RESOURCE_ID.
	 */
	cur = handle->zone_dh_cur;
	match = NULL;
	for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next) {
		if (xmlStrcmp(cur->name, DTD_ELEM_IPD))
			continue;
		if (strlen(tabptr->zone_fs_dir) > 0) {
			if ((fetchprop(cur, DTD_ATTR_DIR, dirname,
			    sizeof (dirname)) == Z_OK) &&
			    (strcmp(tabptr->zone_fs_dir, dirname) == 0)) {
				if (match == NULL)
					match = cur;
				else
					return (Z_INSUFFICIENT_SPEC);
			}
		}
	}

	if (match == NULL)
		return (Z_NO_RESOURCE_ID);

	cur = match;

	if ((err = fetchprop(cur, DTD_ATTR_DIR, tabptr->zone_fs_dir,
	    sizeof (tabptr->zone_fs_dir))) != Z_OK)
		return (err);

	return (Z_OK);
}

/*
 * Compare two IP addresses in string form.  Allow for the possibility that
 * one might have "/<prefix-length>" at the end: allow a match on just the
 * IP address (or host name) part.
 */

boolean_t
zonecfg_same_net_address(char *a1, char *a2)
{
	char *slashp, *slashp1, *slashp2;
	int result;

	if (strcmp(a1, a2) == 0)
		return (B_TRUE);

	/*
	 * If neither has a slash or both do, they need to match to be
	 * considered the same, but they did not match above, so fail.
	 */
	slashp1 = strchr(a1, '/');
	slashp2 = strchr(a2, '/');
	if ((slashp1 == NULL && slashp2 == NULL) ||
	    (slashp1 != NULL && slashp2 != NULL))
		return (B_FALSE);

	/*
	 * Only one had a slash: pick that one, zero out the slash, compare
	 * the "address only" strings, restore the slash, and return the
	 * result of the comparison.
	 */
	slashp = (slashp1 == NULL) ? slashp2 : slashp1;
	*slashp = '\0';
	result = strcmp(a1, a2);
	*slashp = '/';
	return ((result == 0));
}

int
zonecfg_valid_net_address(char *address, struct lifreq *lifr)
{
	struct sockaddr_in *sin4;
	struct sockaddr_in6 *sin6;
	struct addrinfo hints, *result;
	char *slashp = strchr(address, '/');

	bzero(lifr, sizeof (struct lifreq));
	sin4 = (struct sockaddr_in *)&lifr->lifr_addr;
	sin6 = (struct sockaddr_in6 *)&lifr->lifr_addr;
	if (slashp != NULL)
		*slashp = '\0';
	if (inet_pton(AF_INET, address, &sin4->sin_addr) == 1) {
		sin4->sin_family = AF_INET;
	} else if (inet_pton(AF_INET6, address, &sin6->sin6_addr) == 1) {
		if (slashp == NULL)
			return (Z_IPV6_ADDR_PREFIX_LEN);
		sin6->sin6_family = AF_INET6;
	} else {
		/* "address" may be a host name */
		(void) memset(&hints, 0, sizeof (hints));
		hints.ai_family = PF_INET;
		if (getaddrinfo(address, NULL, &hints, &result) != 0)
			return (Z_BOGUS_ADDRESS);
		sin4->sin_family = result->ai_family;

		(void) memcpy(&sin4->sin_addr,
		    /* LINTED E_BAD_PTR_CAST_ALIGN */
		    &((struct sockaddr_in *)result->ai_addr)->sin_addr,
		    sizeof (struct in_addr));

		freeaddrinfo(result);
	}
	return (Z_OK);
}

boolean_t
zonecfg_ifname_exists(sa_family_t af, char *ifname)
{
	struct lifreq lifr;
	int so;
	int save_errno;

	(void) memset(&lifr, 0, sizeof (lifr));
	(void) strlcpy(lifr.lifr_name, ifname, sizeof (lifr.lifr_name));
	lifr.lifr_addr.ss_family = af;
	if ((so = socket(af, SOCK_DGRAM, 0)) < 0) {
		/* Odd - can't tell if the ifname exists */
		return (B_FALSE);
	}
	if (ioctl(so, SIOCGLIFFLAGS, (caddr_t)&lifr) < 0) {
		save_errno = errno;
		(void) close(so);
		errno = save_errno;
		return (B_FALSE);
	}
	(void) close(so);
	return (B_TRUE);
}

int
zonecfg_lookup_nwif(zone_dochandle_t handle, struct zone_nwiftab *tabptr)
{
	xmlNodePtr cur, firstmatch;
	int err;
	char address[INET6_ADDRSTRLEN], physical[LIFNAMSIZ];

	if (tabptr == NULL)
		return (Z_INVAL);

	if ((err = operation_prep(handle)) != Z_OK)
		return (err);

	cur = handle->zone_dh_cur;
	firstmatch = NULL;
	for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next) {
		if (xmlStrcmp(cur->name, DTD_ELEM_NET))
			continue;
		if (strlen(tabptr->zone_nwif_physical) > 0) {
			if ((fetchprop(cur, DTD_ATTR_PHYSICAL, physical,
			    sizeof (physical)) == Z_OK) &&
			    (strcmp(tabptr->zone_nwif_physical,
			    physical) == 0)) {
				if (firstmatch == NULL)
					firstmatch = cur;
				else
					return (Z_INSUFFICIENT_SPEC);
			}
		}
		if (strlen(tabptr->zone_nwif_address) > 0) {
			if ((fetchprop(cur, DTD_ATTR_ADDRESS, address,
			    sizeof (address)) == Z_OK)) {
				if (zonecfg_same_net_address(
				    tabptr->zone_nwif_address, address)) {
					if (firstmatch == NULL)
						firstmatch = cur;
					else if (firstmatch != cur)
						return (Z_INSUFFICIENT_SPEC);
				} else {
					/*
					 * If another property matched but this
					 * one doesn't then reset firstmatch.
					 */
					if (firstmatch == cur)
						firstmatch = NULL;
				}
			}
		}
	}
	if (firstmatch == NULL)
		return (Z_NO_RESOURCE_ID);

	cur = firstmatch;

	if ((err = fetchprop(cur, DTD_ATTR_PHYSICAL, tabptr->zone_nwif_physical,
	    sizeof (tabptr->zone_nwif_physical))) != Z_OK)
		return (err);

	if ((err = fetchprop(cur, DTD_ATTR_ADDRESS, tabptr->zone_nwif_address,
	    sizeof (tabptr->zone_nwif_address))) != Z_OK)
		return (err);

	return (Z_OK);
}

static int
zonecfg_add_nwif_core(zone_dochandle_t handle, struct zone_nwiftab *tabptr)
{
	xmlNodePtr newnode, cur = handle->zone_dh_cur;
	int err;

	newnode = xmlNewTextChild(cur, NULL, DTD_ELEM_NET, NULL);
	if ((err = newprop(newnode, DTD_ATTR_ADDRESS,
	    tabptr->zone_nwif_address)) != Z_OK)
		return (err);
	if ((err = newprop(newnode, DTD_ATTR_PHYSICAL,
	    tabptr->zone_nwif_physical)) != Z_OK)
		return (err);
	return (Z_OK);
}

int
zonecfg_add_nwif(zone_dochandle_t handle, struct zone_nwiftab *tabptr)
{
	int err;

	if (tabptr == NULL)
		return (Z_INVAL);

	if ((err = operation_prep(handle)) != Z_OK)
		return (err);

	if ((err = zonecfg_add_nwif_core(handle, tabptr)) != Z_OK)
		return (err);

	return (Z_OK);
}

static int
zonecfg_delete_nwif_core(zone_dochandle_t handle, struct zone_nwiftab *tabptr)
{
	xmlNodePtr cur = handle->zone_dh_cur;
	boolean_t addr_match, phys_match;

	for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next) {
		if (xmlStrcmp(cur->name, DTD_ELEM_NET))
			continue;

		addr_match = match_prop(cur, DTD_ATTR_ADDRESS,
		    tabptr->zone_nwif_address);
		phys_match = match_prop(cur, DTD_ATTR_PHYSICAL,
		    tabptr->zone_nwif_physical);

		if (addr_match && phys_match) {
			xmlUnlinkNode(cur);
			xmlFreeNode(cur);
			return (Z_OK);
		}
	}
	return (Z_NO_RESOURCE_ID);
}

int
zonecfg_delete_nwif(zone_dochandle_t handle, struct zone_nwiftab *tabptr)
{
	int err;

	if (tabptr == NULL)
		return (Z_INVAL);

	if ((err = operation_prep(handle)) != Z_OK)
		return (err);

	if ((err = zonecfg_delete_nwif_core(handle, tabptr)) != Z_OK)
		return (err);

	return (Z_OK);
}

int
zonecfg_modify_nwif(
	zone_dochandle_t handle,
	struct zone_nwiftab *oldtabptr,
	struct zone_nwiftab *newtabptr)
{
	int err;

	if (oldtabptr == NULL || newtabptr == NULL)
		return (Z_INVAL);

	if ((err = operation_prep(handle)) != Z_OK)
		return (err);

	if ((err = zonecfg_delete_nwif_core(handle, oldtabptr)) != Z_OK)
		return (err);

	if ((err = zonecfg_add_nwif_core(handle, newtabptr)) != Z_OK)
		return (err);

	return (Z_OK);
}

int
zonecfg_lookup_dev(zone_dochandle_t handle, struct zone_devtab *tabptr)
{
	xmlNodePtr cur, firstmatch;
	int err;
	char match[MAXPATHLEN];

	if (tabptr == NULL)
		return (Z_INVAL);

	if ((err = operation_prep(handle)) != Z_OK)
		return (err);

	cur = handle->zone_dh_cur;
	firstmatch = NULL;
	for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next) {
		if (xmlStrcmp(cur->name, DTD_ELEM_DEVICE))
			continue;
		if (strlen(tabptr->zone_dev_match) == 0)
			continue;

		if ((fetchprop(cur, DTD_ATTR_MATCH, match,
		    sizeof (match)) == Z_OK)) {
			if (strcmp(tabptr->zone_dev_match,
			    match) == 0) {
				if (firstmatch == NULL)
					firstmatch = cur;
				else if (firstmatch != cur)
					return (Z_INSUFFICIENT_SPEC);
			} else {
				/*
				 * If another property matched but this
				 * one doesn't then reset firstmatch.
				 */
				if (firstmatch == cur)
					firstmatch = NULL;
			}
		}
	}
	if (firstmatch == NULL)
		return (Z_NO_RESOURCE_ID);

	cur = firstmatch;

	if ((err = fetchprop(cur, DTD_ATTR_MATCH, tabptr->zone_dev_match,
	    sizeof (tabptr->zone_dev_match))) != Z_OK)
		return (err);

	return (Z_OK);
}

static int
zonecfg_add_dev_core(zone_dochandle_t handle, struct zone_devtab *tabptr)
{
	xmlNodePtr newnode, cur = handle->zone_dh_cur;
	int err;

	newnode = xmlNewTextChild(cur, NULL, DTD_ELEM_DEVICE, NULL);

	if ((err = newprop(newnode, DTD_ATTR_MATCH,
	    tabptr->zone_dev_match)) != Z_OK)
		return (err);

	return (Z_OK);
}

int
zonecfg_add_dev(zone_dochandle_t handle, struct zone_devtab *tabptr)
{
	int err;

	if (tabptr == NULL)
		return (Z_INVAL);

	if ((err = operation_prep(handle)) != Z_OK)
		return (err);

	if ((err = zonecfg_add_dev_core(handle, tabptr)) != Z_OK)
		return (err);

	return (Z_OK);
}

static int
zonecfg_delete_dev_core(zone_dochandle_t handle, struct zone_devtab *tabptr)
{
	xmlNodePtr cur = handle->zone_dh_cur;
	int match_match;

	for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next) {
		if (xmlStrcmp(cur->name, DTD_ELEM_DEVICE))
			continue;

		match_match = match_prop(cur, DTD_ATTR_MATCH,
		    tabptr->zone_dev_match);

		if (match_match) {
			xmlUnlinkNode(cur);
			xmlFreeNode(cur);
			return (Z_OK);
		}
	}
	return (Z_NO_RESOURCE_ID);
}

int
zonecfg_delete_dev(zone_dochandle_t handle, struct zone_devtab *tabptr)
{
	int err;

	if (tabptr == NULL)
		return (Z_INVAL);

	if ((err = operation_prep(handle)) != Z_OK)
		return (err);

	if ((err = zonecfg_delete_dev_core(handle, tabptr)) != Z_OK)
		return (err);

	return (Z_OK);
}

int
zonecfg_modify_dev(
	zone_dochandle_t handle,
	struct zone_devtab *oldtabptr,
	struct zone_devtab *newtabptr)
{
	int err;

	if (oldtabptr == NULL || newtabptr == NULL)
		return (Z_INVAL);

	if ((err = operation_prep(handle)) != Z_OK)
		return (err);

	if ((err = zonecfg_delete_dev_core(handle, oldtabptr)) != Z_OK)
		return (err);

	if ((err = zonecfg_add_dev_core(handle, newtabptr)) != Z_OK)
		return (err);

	return (Z_OK);
}

/* Lock to serialize all zonecfg_devwalks */
static pthread_mutex_t zonecfg_devwalk_lock = PTHREAD_MUTEX_INITIALIZER;
/*
 * Global variables used to pass data from zonecfg_devwalk to the nftw
 * call-back (zonecfg_devwalk_cb).  g_devwalk_data is really the void*
 * parameter and g_devwalk_cb is really the *cb parameter from zonecfg_devwalk.
 */
static void *g_devwalk_data;
static int (*g_devwalk_cb)(const char *, uid_t, gid_t, mode_t, const char *,
    void *);
static size_t g_devwalk_skip_prefix;

/*
 * This is the nftw call-back function used by zonecfg_devwalk.  It is
 * responsible for calling the actual call-back that is passed in to
 * zonecfg_devwalk as the *cb argument.
 */
/* ARGSUSED2 */
static int
zonecfg_devwalk_cb(const char *path, const struct stat *st, int f,
    struct FTW *ftw)
{
	acl_t *acl;
	char *acl_txt = NULL;

	/* skip all but character and block devices */
	if (!S_ISBLK(st->st_mode) && !S_ISCHR(st->st_mode))
		return (0);

	if ((acl_get(path, ACL_NO_TRIVIAL, &acl) == 0) &&
	    acl != NULL) {
		acl_txt = acl_totext(acl, ACL_NORESOLVE);
		acl_free(acl);
	}

	if (strlen(path) <= g_devwalk_skip_prefix)
		return (0);

	g_devwalk_cb(path + g_devwalk_skip_prefix, st->st_uid, st->st_gid,
	    st->st_mode & S_IAMB, acl_txt != NULL ? acl_txt : "",
	    g_devwalk_data);
	free(acl_txt);
	return (0);
}

/*
 * Walk the dev tree for the zone specified by hdl and call the call-back (cb)
 * function for each entry in the tree.  The call-back will be passed the
 * name, uid, gid, mode, acl string and the void *data input parameter
 * for each dev entry.
 *
 * Data is passed to the zonecfg_devwalk_cb through the global variables
 * g_devwalk_data, *g_devwalk_cb, and g_devwalk_skip_prefix.  The
 * zonecfg_devwalk_cb function will actually call *cb.
 */
int
zonecfg_devwalk(zone_dochandle_t hdl,
    int (*cb)(const char *, uid_t, gid_t, mode_t, const char *, void *),
    void *data)
{
	char path[MAXPATHLEN];
	int ret;

	if ((ret = zonecfg_get_zonepath(hdl, path, sizeof (path))) != Z_OK)
		return (ret);

	if (strlcat(path, "/dev", sizeof (path)) >= sizeof (path))
		return (Z_TOO_BIG);
	g_devwalk_skip_prefix = strlen(path) + 1;

	/*
	 * We have to serialize all zonecfg_devwalks in the same process
	 * (which should be fine), since nftw() is so badly designed.
	 */
	(void) pthread_mutex_lock(&zonecfg_devwalk_lock);

	g_devwalk_data = data;
	g_devwalk_cb = cb;
	(void) nftw(path, zonecfg_devwalk_cb, 0, FTW_PHYS);

	(void) pthread_mutex_unlock(&zonecfg_devwalk_lock);
	return (Z_OK);
}

/*
 * Update the owner, group, mode and acl on the specified dev (inpath) for
 * the zone (hdl).  This function can be used to fix up the dev tree after
 * attaching a migrated zone.
 */
int
zonecfg_devperms_apply(zone_dochandle_t hdl, const char *inpath, uid_t owner,
    gid_t group, mode_t mode, const char *acltxt)
{
	int ret;
	char path[MAXPATHLEN];
	struct stat st;
	acl_t *aclp;

	if ((ret = zonecfg_get_zonepath(hdl, path, sizeof (path))) != Z_OK)
		return (ret);

	if (strlcat(path, "/dev/", sizeof (path)) >= sizeof (path))
		return (Z_TOO_BIG);
	if (strlcat(path, inpath, sizeof (path)) >= sizeof (path))
		return (Z_TOO_BIG);

	if (stat(path, &st) == -1)
		return (Z_INVAL);

	/* make sure we're only touching device nodes */
	if (!S_ISCHR(st.st_mode) && !S_ISBLK(st.st_mode))
		return (Z_INVAL);

	if (chown(path, owner, group) == -1)
		return (Z_SYSTEM);

	if (chmod(path, mode) == -1)
		return (Z_SYSTEM);

	if ((acltxt == NULL) || (strcmp(acltxt, "") == 0))
		return (Z_OK);

	if (acl_fromtext(acltxt, &aclp) != 0)
		return (Z_SYSTEM);

	errno = 0;
	if (acl_set(path, aclp) == -1) {
		free(aclp);
		return (Z_SYSTEM);
	}

	free(aclp);
	return (Z_OK);
}

/*
 * This function finds everything mounted under a zone's rootpath.
 * This returns the number of mounts under rootpath, or -1 on error.
 * callback is called once per mount found with the first argument
 * pointing to the  mount point.
 *
 * If the callback function returns non-zero zonecfg_find_mounts
 * aborts with an error.
 */
int
zonecfg_find_mounts(char *rootpath, int (*callback)(const char *, void *),
    void *priv) {
	FILE *mnttab;
	struct mnttab m;
	size_t l;
	int zfsl;
	int rv = 0;
	char zfs_path[MAXPATHLEN];

	assert(rootpath != NULL);

	if ((zfsl = snprintf(zfs_path, sizeof (zfs_path), "%s/.zfs/", rootpath))
	    >= sizeof (zfs_path))
		return (-1);

	l = strlen(rootpath);

	mnttab = fopen("/etc/mnttab", "r");

	if (mnttab == NULL)
		return (-1);

	if (ioctl(fileno(mnttab), MNTIOC_SHOWHIDDEN, NULL) < 0)  {
		rv = -1;
		goto out;
	}

	while (!getmntent(mnttab, &m)) {
		if ((strncmp(rootpath, m.mnt_mountp, l) == 0) &&
		    (m.mnt_mountp[l] == '/') &&
		    (strncmp(zfs_path, m.mnt_mountp, zfsl) != 0)) {
			rv++;
			if (callback == NULL)
				continue;
			if (callback(m.mnt_mountp, priv)) {
				rv = -1;
				goto out;

			}
		}
	}

out:
	(void) fclose(mnttab);
	return (rv);
}

int
zonecfg_lookup_attr(zone_dochandle_t handle, struct zone_attrtab *tabptr)
{
	xmlNodePtr cur, firstmatch;
	int err;
	char name[MAXNAMELEN], type[MAXNAMELEN], value[MAXNAMELEN];

	if (tabptr == NULL)
		return (Z_INVAL);

	if ((err = operation_prep(handle)) != Z_OK)
		return (err);

	cur = handle->zone_dh_cur;
	firstmatch = NULL;
	for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next) {
		if (xmlStrcmp(cur->name, DTD_ELEM_ATTR))
			continue;
		if (strlen(tabptr->zone_attr_name) > 0) {
			if ((fetchprop(cur, DTD_ATTR_NAME, name,
			    sizeof (name)) == Z_OK) &&
			    (strcmp(tabptr->zone_attr_name, name) == 0)) {
				if (firstmatch == NULL)
					firstmatch = cur;
				else
					return (Z_INSUFFICIENT_SPEC);
			}
		}
		if (strlen(tabptr->zone_attr_type) > 0) {
			if ((fetchprop(cur, DTD_ATTR_TYPE, type,
			    sizeof (type)) == Z_OK)) {
				if (strcmp(tabptr->zone_attr_type, type) == 0) {
					if (firstmatch == NULL)
						firstmatch = cur;
					else if (firstmatch != cur)
						return (Z_INSUFFICIENT_SPEC);
				} else {
					/*
					 * If another property matched but this
					 * one doesn't then reset firstmatch.
					 */
					if (firstmatch == cur)
						firstmatch = NULL;
				}
			}
		}
		if (strlen(tabptr->zone_attr_value) > 0) {
			if ((fetchprop(cur, DTD_ATTR_VALUE, value,
			    sizeof (value)) == Z_OK)) {
				if (strcmp(tabptr->zone_attr_value, value) ==
				    0) {
					if (firstmatch == NULL)
						firstmatch = cur;
					else if (firstmatch != cur)
						return (Z_INSUFFICIENT_SPEC);
				} else {
					/*
					 * If another property matched but this
					 * one doesn't then reset firstmatch.
					 */
					if (firstmatch == cur)
						firstmatch = NULL;
				}
			}
		}
	}
	if (firstmatch == NULL)
		return (Z_NO_RESOURCE_ID);

	cur = firstmatch;

	if ((err = fetchprop(cur, DTD_ATTR_NAME, tabptr->zone_attr_name,
	    sizeof (tabptr->zone_attr_name))) != Z_OK)
		return (err);

	if ((err = fetchprop(cur, DTD_ATTR_TYPE, tabptr->zone_attr_type,
	    sizeof (tabptr->zone_attr_type))) != Z_OK)
		return (err);

	if ((err = fetchprop(cur, DTD_ATTR_VALUE, tabptr->zone_attr_value,
	    sizeof (tabptr->zone_attr_value))) != Z_OK)
		return (err);

	return (Z_OK);
}

static int
zonecfg_add_attr_core(zone_dochandle_t handle, struct zone_attrtab *tabptr)
{
	xmlNodePtr newnode, cur = handle->zone_dh_cur;
	int err;

	newnode = xmlNewTextChild(cur, NULL, DTD_ELEM_ATTR, NULL);
	err = newprop(newnode, DTD_ATTR_NAME, tabptr->zone_attr_name);
	if (err != Z_OK)
		return (err);
	err = newprop(newnode, DTD_ATTR_TYPE, tabptr->zone_attr_type);
	if (err != Z_OK)
		return (err);
	err = newprop(newnode, DTD_ATTR_VALUE, tabptr->zone_attr_value);
	if (err != Z_OK)
		return (err);
	return (Z_OK);
}

int
zonecfg_add_attr(zone_dochandle_t handle, struct zone_attrtab *tabptr)
{
	int err;

	if (tabptr == NULL)
		return (Z_INVAL);

	if ((err = operation_prep(handle)) != Z_OK)
		return (err);

	if ((err = zonecfg_add_attr_core(handle, tabptr)) != Z_OK)
		return (err);

	return (Z_OK);
}

static int
zonecfg_delete_attr_core(zone_dochandle_t handle, struct zone_attrtab *tabptr)
{
	xmlNodePtr cur = handle->zone_dh_cur;
	int name_match, type_match, value_match;

	for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next) {
		if (xmlStrcmp(cur->name, DTD_ELEM_ATTR))
			continue;

		name_match = match_prop(cur, DTD_ATTR_NAME,
		    tabptr->zone_attr_name);
		type_match = match_prop(cur, DTD_ATTR_TYPE,
		    tabptr->zone_attr_type);
		value_match = match_prop(cur, DTD_ATTR_VALUE,
		    tabptr->zone_attr_value);

		if (name_match && type_match && value_match) {
			xmlUnlinkNode(cur);
			xmlFreeNode(cur);
			return (Z_OK);
		}
	}
	return (Z_NO_RESOURCE_ID);
}

int
zonecfg_delete_attr(zone_dochandle_t handle, struct zone_attrtab *tabptr)
{
	int err;

	if (tabptr == NULL)
		return (Z_INVAL);

	if ((err = operation_prep(handle)) != Z_OK)
		return (err);

	if ((err = zonecfg_delete_attr_core(handle, tabptr)) != Z_OK)
		return (err);

	return (Z_OK);
}

int
zonecfg_modify_attr(
	zone_dochandle_t handle,
	struct zone_attrtab *oldtabptr,
	struct zone_attrtab *newtabptr)
{
	int err;

	if (oldtabptr == NULL || newtabptr == NULL)
		return (Z_INVAL);

	if ((err = operation_prep(handle)) != Z_OK)
		return (err);

	if ((err = zonecfg_delete_attr_core(handle, oldtabptr)) != Z_OK)
		return (err);

	if ((err = zonecfg_add_attr_core(handle, newtabptr)) != Z_OK)
		return (err);

	return (Z_OK);
}

int
zonecfg_get_attr_boolean(const struct zone_attrtab *attr, boolean_t *value)
{
	if (attr == NULL)
		return (Z_INVAL);

	if (strcmp(attr->zone_attr_type, DTD_ENTITY_BOOLEAN) != 0)
		return (Z_INVAL);

	if (strcmp(attr->zone_attr_value, DTD_ENTITY_TRUE) == 0) {
		*value = B_TRUE;
		return (Z_OK);
	}
	if (strcmp(attr->zone_attr_value, DTD_ENTITY_FALSE) == 0) {
		*value = B_FALSE;
		return (Z_OK);
	}
	return (Z_INVAL);
}

int
zonecfg_get_attr_int(const struct zone_attrtab *attr, int64_t *value)
{
	long long result;
	char *endptr;

	if (attr == NULL)
		return (Z_INVAL);

	if (strcmp(attr->zone_attr_type, DTD_ENTITY_INT) != 0)
		return (Z_INVAL);

	errno = 0;
	result = strtoll(attr->zone_attr_value, &endptr, 10);
	if (errno != 0 || *endptr != '\0')
		return (Z_INVAL);
	*value = result;
	return (Z_OK);
}

int
zonecfg_get_attr_string(const struct zone_attrtab *attr, char *value,
    size_t val_sz)
{
	if (attr == NULL)
		return (Z_INVAL);

	if (strcmp(attr->zone_attr_type, DTD_ENTITY_STRING) != 0)
		return (Z_INVAL);

	if (strlcpy(value, attr->zone_attr_value, val_sz) >= val_sz)
		return (Z_TOO_BIG);
	return (Z_OK);
}

int
zonecfg_get_attr_uint(const struct zone_attrtab *attr, uint64_t *value)
{
	unsigned long long result;
	long long neg_result;
	char *endptr;

	if (attr == NULL)
		return (Z_INVAL);

	if (strcmp(attr->zone_attr_type, DTD_ENTITY_UINT) != 0)
		return (Z_INVAL);

	errno = 0;
	result = strtoull(attr->zone_attr_value, &endptr, 10);
	if (errno != 0 || *endptr != '\0')
		return (Z_INVAL);
	errno = 0;
	neg_result = strtoll(attr->zone_attr_value, &endptr, 10);
	/*
	 * Incredibly, strtoull("<negative number>", ...) will not fail but
	 * return whatever (negative) number cast as a u_longlong_t, so we
	 * need to look for this here.
	 */
	if (errno == 0 && neg_result < 0)
		return (Z_INVAL);
	*value = result;
	return (Z_OK);
}

int
zonecfg_lookup_rctl(zone_dochandle_t handle, struct zone_rctltab *tabptr)
{
	xmlNodePtr cur, val;
	char savedname[MAXNAMELEN];
	struct zone_rctlvaltab *valptr;
	int err;

	if (tabptr->zone_rctl_name == NULL ||
	    strlen(tabptr->zone_rctl_name) == 0)
		return (Z_INVAL);

	if ((err = operation_prep(handle)) != Z_OK)
		return (err);

	cur = handle->zone_dh_cur;
	for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next) {
		if (xmlStrcmp(cur->name, DTD_ELEM_RCTL))
			continue;
		if ((fetchprop(cur, DTD_ATTR_NAME, savedname,
		    sizeof (savedname)) == Z_OK) &&
		    (strcmp(savedname, tabptr->zone_rctl_name) == 0)) {
			tabptr->zone_rctl_valptr = NULL;
			for (val = cur->xmlChildrenNode; val != NULL;
			    val = val->next) {
				valptr = (struct zone_rctlvaltab *)malloc(
				    sizeof (struct zone_rctlvaltab));
				if (valptr == NULL)
					return (Z_NOMEM);
				if ((fetchprop(val, DTD_ATTR_PRIV,
				    valptr->zone_rctlval_priv,
				    sizeof (valptr->zone_rctlval_priv)) !=
				    Z_OK))
					break;
				if ((fetchprop(val, DTD_ATTR_LIMIT,
				    valptr->zone_rctlval_limit,
				    sizeof (valptr->zone_rctlval_limit)) !=
				    Z_OK))
					break;
				if ((fetchprop(val, DTD_ATTR_ACTION,
				    valptr->zone_rctlval_action,
				    sizeof (valptr->zone_rctlval_action)) !=
				    Z_OK))
					break;
				if (zonecfg_add_rctl_value(tabptr, valptr) !=
				    Z_OK)
					break;
			}
			return (Z_OK);
		}
	}
	return (Z_NO_RESOURCE_ID);
}

static int
zonecfg_add_rctl_core(zone_dochandle_t handle, struct zone_rctltab *tabptr)
{
	xmlNodePtr newnode, cur = handle->zone_dh_cur, valnode;
	struct zone_rctlvaltab *valptr;
	int err;

	newnode = xmlNewTextChild(cur, NULL, DTD_ELEM_RCTL, NULL);
	err = newprop(newnode, DTD_ATTR_NAME, tabptr->zone_rctl_name);
	if (err != Z_OK)
		return (err);
	for (valptr = tabptr->zone_rctl_valptr; valptr != NULL;
	    valptr = valptr->zone_rctlval_next) {
		valnode = xmlNewTextChild(newnode, NULL,
		    DTD_ELEM_RCTLVALUE, NULL);
		err = newprop(valnode, DTD_ATTR_PRIV,
		    valptr->zone_rctlval_priv);
		if (err != Z_OK)
			return (err);
		err = newprop(valnode, DTD_ATTR_LIMIT,
		    valptr->zone_rctlval_limit);
		if (err != Z_OK)
			return (err);
		err = newprop(valnode, DTD_ATTR_ACTION,
		    valptr->zone_rctlval_action);
		if (err != Z_OK)
			return (err);
	}
	return (Z_OK);
}

int
zonecfg_add_rctl(zone_dochandle_t handle, struct zone_rctltab *tabptr)
{
	int err;

	if (tabptr == NULL || tabptr->zone_rctl_name == NULL)
		return (Z_INVAL);

	if ((err = operation_prep(handle)) != Z_OK)
		return (err);

	if ((err = zonecfg_add_rctl_core(handle, tabptr)) != Z_OK)
		return (err);

	return (Z_OK);
}

static int
zonecfg_delete_rctl_core(zone_dochandle_t handle, struct zone_rctltab *tabptr)
{
	xmlNodePtr cur = handle->zone_dh_cur;
	xmlChar *savedname;
	int name_result;

	for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next) {
		if (xmlStrcmp(cur->name, DTD_ELEM_RCTL))
			continue;

		savedname = xmlGetProp(cur, DTD_ATTR_NAME);
		if (savedname == NULL)	/* shouldn't happen */
			continue;
		name_result = xmlStrcmp(savedname,
		    (const xmlChar *) tabptr->zone_rctl_name);
		xmlFree(savedname);

		if (name_result == 0) {
			xmlUnlinkNode(cur);
			xmlFreeNode(cur);
			return (Z_OK);
		}
	}
	return (Z_NO_RESOURCE_ID);
}

int
zonecfg_delete_rctl(zone_dochandle_t handle, struct zone_rctltab *tabptr)
{
	int err;

	if (tabptr == NULL || tabptr->zone_rctl_name == NULL)
		return (Z_INVAL);

	if ((err = operation_prep(handle)) != Z_OK)
		return (err);

	if ((err = zonecfg_delete_rctl_core(handle, tabptr)) != Z_OK)
		return (err);

	return (Z_OK);
}

int
zonecfg_modify_rctl(
	zone_dochandle_t handle,
	struct zone_rctltab *oldtabptr,
	struct zone_rctltab *newtabptr)
{
	int err;

	if (oldtabptr == NULL || oldtabptr->zone_rctl_name == NULL ||
	    newtabptr == NULL || newtabptr->zone_rctl_name == NULL)
		return (Z_INVAL);

	if ((err = operation_prep(handle)) != Z_OK)
		return (err);

	if ((err = zonecfg_delete_rctl_core(handle, oldtabptr)) != Z_OK)
		return (err);

	if ((err = zonecfg_add_rctl_core(handle, newtabptr)) != Z_OK)
		return (err);

	return (Z_OK);
}

int
zonecfg_add_rctl_value(
	struct zone_rctltab *tabptr,
	struct zone_rctlvaltab *valtabptr)
{
	struct zone_rctlvaltab *last, *old, *new;
	rctlblk_t *rctlblk = alloca(rctlblk_size());

	last = tabptr->zone_rctl_valptr;
	for (old = last; old != NULL; old = old->zone_rctlval_next)
		last = old;	/* walk to the end of the list */
	new = valtabptr;	/* alloc'd by caller */
	new->zone_rctlval_next = NULL;
	if (zonecfg_construct_rctlblk(valtabptr, rctlblk) != Z_OK)
		return (Z_INVAL);
	if (!zonecfg_valid_rctlblk(rctlblk))
		return (Z_INVAL);
	if (last == NULL)
		tabptr->zone_rctl_valptr = new;
	else
		last->zone_rctlval_next = new;
	return (Z_OK);
}

int
zonecfg_remove_rctl_value(
	struct zone_rctltab *tabptr,
	struct zone_rctlvaltab *valtabptr)
{
	struct zone_rctlvaltab *last, *this, *next;

	last = tabptr->zone_rctl_valptr;
	for (this = last; this != NULL; this = this->zone_rctlval_next) {
		if (strcmp(this->zone_rctlval_priv,
		    valtabptr->zone_rctlval_priv) == 0 &&
		    strcmp(this->zone_rctlval_limit,
		    valtabptr->zone_rctlval_limit) == 0 &&
		    strcmp(this->zone_rctlval_action,
		    valtabptr->zone_rctlval_action) == 0) {
			next = this->zone_rctlval_next;
			if (this == tabptr->zone_rctl_valptr)
				tabptr->zone_rctl_valptr = next;
			else
				last->zone_rctlval_next = next;
			free(this);
			return (Z_OK);
		} else
			last = this;
	}
	return (Z_NO_PROPERTY_ID);
}

char *
zonecfg_strerror(int errnum)
{
	switch (errnum) {
	case Z_OK:
		return (dgettext(TEXT_DOMAIN, "OK"));
	case Z_EMPTY_DOCUMENT:
		return (dgettext(TEXT_DOMAIN, "Empty document"));
	case Z_WRONG_DOC_TYPE:
		return (dgettext(TEXT_DOMAIN, "Wrong document type"));
	case Z_BAD_PROPERTY:
		return (dgettext(TEXT_DOMAIN, "Bad document property"));
	case Z_TEMP_FILE:
		return (dgettext(TEXT_DOMAIN,
		    "Problem creating temporary file"));
	case Z_SAVING_FILE:
		return (dgettext(TEXT_DOMAIN, "Problem saving file"));
	case Z_NO_ENTRY:
		return (dgettext(TEXT_DOMAIN, "No such entry"));
	case Z_BOGUS_ZONE_NAME:
		return (dgettext(TEXT_DOMAIN, "Bogus zone name"));
	case Z_REQD_RESOURCE_MISSING:
		return (dgettext(TEXT_DOMAIN, "Required resource missing"));
	case Z_REQD_PROPERTY_MISSING:
		return (dgettext(TEXT_DOMAIN, "Required property missing"));
	case Z_BAD_HANDLE:
		return (dgettext(TEXT_DOMAIN, "Bad handle"));
	case Z_NOMEM:
		return (dgettext(TEXT_DOMAIN, "Out of memory"));
	case Z_INVAL:
		return (dgettext(TEXT_DOMAIN, "Invalid argument"));
	case Z_ACCES:
		return (dgettext(TEXT_DOMAIN, "Permission denied"));
	case Z_TOO_BIG:
		return (dgettext(TEXT_DOMAIN, "Argument list too long"));
	case Z_MISC_FS:
		return (dgettext(TEXT_DOMAIN,
		    "Miscellaneous file system error"));
	case Z_NO_ZONE:
		return (dgettext(TEXT_DOMAIN, "No such zone configured"));
	case Z_NO_RESOURCE_TYPE:
		return (dgettext(TEXT_DOMAIN, "No such resource type"));
	case Z_NO_RESOURCE_ID:
		return (dgettext(TEXT_DOMAIN, "No such resource with that id"));
	case Z_NO_PROPERTY_TYPE:
		return (dgettext(TEXT_DOMAIN, "No such property type"));
	case Z_NO_PROPERTY_ID:
		return (dgettext(TEXT_DOMAIN, "No such property with that id"));
	case Z_BAD_ZONE_STATE:
		return (dgettext(TEXT_DOMAIN,
		    "Zone state is invalid for the requested operation"));
	case Z_INVALID_DOCUMENT:
		return (dgettext(TEXT_DOMAIN, "Invalid document"));
	case Z_NAME_IN_USE:
		return (dgettext(TEXT_DOMAIN, "Zone name already in use"));
	case Z_NO_SUCH_ID:
		return (dgettext(TEXT_DOMAIN, "No such zone ID"));
	case Z_UPDATING_INDEX:
		return (dgettext(TEXT_DOMAIN, "Problem updating index file"));
	case Z_LOCKING_FILE:
		return (dgettext(TEXT_DOMAIN, "Locking index file"));
	case Z_UNLOCKING_FILE:
		return (dgettext(TEXT_DOMAIN, "Unlocking index file"));
	case Z_INSUFFICIENT_SPEC:
		return (dgettext(TEXT_DOMAIN, "Insufficient specification"));
	case Z_RESOLVED_PATH:
		return (dgettext(TEXT_DOMAIN, "Resolved path mismatch"));
	case Z_IPV6_ADDR_PREFIX_LEN:
		return (dgettext(TEXT_DOMAIN,
		    "IPv6 address missing required prefix length"));
	case Z_BOGUS_ADDRESS:
		return (dgettext(TEXT_DOMAIN,
		    "Neither an IPv4 nor an IPv6 address nor a host name"));
	case Z_PRIV_PROHIBITED:
		return (dgettext(TEXT_DOMAIN,
		    "Specified privilege is prohibited"));
	case Z_PRIV_REQUIRED:
		return (dgettext(TEXT_DOMAIN,
		    "Required privilege is missing"));
	case Z_PRIV_UNKNOWN:
		return (dgettext(TEXT_DOMAIN,
		    "Specified privilege is unknown"));
	case Z_BRAND_ERROR:
		return (dgettext(TEXT_DOMAIN,
		    "Brand-specific error"));
	case Z_INCOMPATIBLE:
		return (dgettext(TEXT_DOMAIN, "Incompatible settings"));
	case Z_ALIAS_DISALLOW:
		return (dgettext(TEXT_DOMAIN,
		    "An incompatible rctl already exists for this property"));
	case Z_CLEAR_DISALLOW:
		return (dgettext(TEXT_DOMAIN,
		    "Clearing this property is not allowed"));
	case Z_POOL:
		return (dgettext(TEXT_DOMAIN, "libpool(3LIB) error"));
	case Z_POOLS_NOT_ACTIVE:
		return (dgettext(TEXT_DOMAIN, "Pools facility not active; "
		    "zone will not be bound to pool"));
	case Z_POOL_ENABLE:
		return (dgettext(TEXT_DOMAIN,
		    "Could not enable pools facility"));
	case Z_NO_POOL:
		return (dgettext(TEXT_DOMAIN,
		    "Pool not found; using default pool"));
	case Z_POOL_CREATE:
		return (dgettext(TEXT_DOMAIN,
		    "Could not create a temporary pool"));
	case Z_POOL_BIND:
		return (dgettext(TEXT_DOMAIN, "Could not bind zone to pool"));
	default:
		return (dgettext(TEXT_DOMAIN, "Unknown error"));
	}
}

/*
 * Note that the zonecfg_setXent() and zonecfg_endXent() calls are all the
 * same, as they just turn around and call zonecfg_setent() / zonecfg_endent().
 */

static int
zonecfg_setent(zone_dochandle_t handle)
{
	xmlNodePtr cur;
	int err;

	if (handle == NULL)
		return (Z_INVAL);

	if ((err = operation_prep(handle)) != Z_OK) {
		handle->zone_dh_cur = NULL;
		return (err);
	}
	cur = handle->zone_dh_cur;
	cur = cur->xmlChildrenNode;
	handle->zone_dh_cur = cur;
	return (Z_OK);
}

static int
zonecfg_endent(zone_dochandle_t handle)
{
	if (handle == NULL)
		return (Z_INVAL);

	handle->zone_dh_cur = handle->zone_dh_top;
	return (Z_OK);
}

/*
 * Do the work required to manipulate a process through libproc.
 * If grab_process() returns no errors (0), then release_process()
 * must eventually be called.
 *
 * Return values:
 *      0 Successful creation of agent thread
 *      1 Error grabbing
 *      2 Error creating agent
 */
static int
grab_process(pr_info_handle_t *p)
{
	int ret;

	if ((p->pr = Pgrab(p->pid, 0, &ret)) != NULL) {

		if (Psetflags(p->pr, PR_RLC) != 0) {
			Prelease(p->pr, 0);
			return (1);
		}
		if (Pcreate_agent(p->pr) == 0) {
			return (0);

		} else {
			Prelease(p->pr, 0);
			return (2);
		}
	} else {
		return (1);
	}
}

/*
 * Release the specified process. This destroys the agent
 * and releases the process. If the process is NULL, nothing
 * is done. This function should only be called if grab_process()
 * has previously been called and returned success.
 *
 * This function is Pgrab-safe.
 */
static void
release_process(struct ps_prochandle *Pr)
{
	if (Pr == NULL)
		return;

	Pdestroy_agent(Pr);
	Prelease(Pr, 0);
}

static boolean_t
grab_zone_proc(char *zonename, pr_info_handle_t *p)
{
	DIR *dirp;
	struct dirent *dentp;
	zoneid_t zoneid;
	int pid_self;
	psinfo_t psinfo;

	if (zone_get_id(zonename, &zoneid) != 0)
		return (B_FALSE);

	pid_self = getpid();

	if ((dirp = opendir("/proc")) == NULL)
		return (B_FALSE);

	while (dentp = readdir(dirp)) {
		p->pid = atoi(dentp->d_name);

		/* Skip self */
		if (p->pid == pid_self)
			continue;

		if (proc_get_psinfo(p->pid, &psinfo) != 0)
			continue;

		if (psinfo.pr_zoneid != zoneid)
			continue;

		/* attempt to grab process */
		if (grab_process(p) != 0)
			continue;

		if (pr_getzoneid(p->pr) != zoneid) {
			release_process(p->pr);
			continue;
		}

		(void) closedir(dirp);
		return (B_TRUE);
	}

	(void) closedir(dirp);
	return (B_FALSE);
}

static boolean_t
get_priv_rctl(struct ps_prochandle *pr, char *name, rctlblk_t *rblk)
{
	if (pr_getrctl(pr, name, NULL, rblk, RCTL_FIRST))
		return (B_FALSE);

	if (rctlblk_get_privilege(rblk) == RCPRIV_PRIVILEGED)
		return (B_TRUE);

	while (pr_getrctl(pr, name, rblk, rblk, RCTL_NEXT) == 0) {
		if (rctlblk_get_privilege(rblk) == RCPRIV_PRIVILEGED)
			return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * Apply the current rctl settings to the specified, running zone.
 */
int
zonecfg_apply_rctls(char *zone_name, zone_dochandle_t handle)
{
	int err;
	int res = Z_OK;
	rctlblk_t *rblk;
	pr_info_handle_t p;
	struct zone_rctltab rctl;

	if ((err = zonecfg_setrctlent(handle)) != Z_OK)
		return (err);

	if ((rblk = (rctlblk_t *)malloc(rctlblk_size())) == NULL) {
		(void) zonecfg_endrctlent(handle);
		return (Z_NOMEM);
	}

	if (!grab_zone_proc(zone_name, &p)) {
		(void) zonecfg_endrctlent(handle);
		free(rblk);
		return (Z_SYSTEM);
	}

	while (zonecfg_getrctlent(handle, &rctl) == Z_OK) {
		char *rname;
		struct zone_rctlvaltab *valptr;

		rname = rctl.zone_rctl_name;

		/* first delete all current privileged settings for this rctl */
		while (get_priv_rctl(p.pr, rname, rblk)) {
			if (pr_setrctl(p.pr, rname, NULL, rblk, RCTL_DELETE) !=
			    0) {
				res = Z_SYSTEM;
				goto done;
			}
		}

		/* now set each new value for the rctl */
		for (valptr = rctl.zone_rctl_valptr; valptr != NULL;
		    valptr = valptr->zone_rctlval_next) {
			if ((err = zonecfg_construct_rctlblk(valptr, rblk))
			    != Z_OK) {
				res = errno = err;
				goto done;
			}

			if (pr_setrctl(p.pr, rname, NULL, rblk, RCTL_INSERT)) {
				res = Z_SYSTEM;
				goto done;
			}
		}
	}

done:
	release_process(p.pr);
	free(rblk);
	(void) zonecfg_endrctlent(handle);

	return (res);
}

static const xmlChar *
nm_to_dtd(char *nm)
{
	if (strcmp(nm, "device") == 0)
		return (DTD_ELEM_DEVICE);
	if (strcmp(nm, "fs") == 0)
		return (DTD_ELEM_FS);
	if (strcmp(nm, "inherit-pkg-dir") == 0)
		return (DTD_ELEM_IPD);
	if (strcmp(nm, "net") == 0)
		return (DTD_ELEM_NET);
	if (strcmp(nm, "attr") == 0)
		return (DTD_ELEM_ATTR);
	if (strcmp(nm, "rctl") == 0)
		return (DTD_ELEM_RCTL);
	if (strcmp(nm, "dataset") == 0)
		return (DTD_ELEM_DATASET);

	return (NULL);
}

int
zonecfg_num_resources(zone_dochandle_t handle, char *rsrc)
{
	int num = 0;
	const xmlChar *dtd;
	xmlNodePtr cur;

	if ((dtd = nm_to_dtd(rsrc)) == NULL)
		return (num);

	if (zonecfg_setent(handle) != Z_OK)
		return (num);

	for (cur = handle->zone_dh_cur; cur != NULL; cur = cur->next)
		if (xmlStrcmp(cur->name, dtd) == 0)
			num++;

	(void) zonecfg_endent(handle);

	return (num);
}

int
zonecfg_del_all_resources(zone_dochandle_t handle, char *rsrc)
{
	int err;
	const xmlChar *dtd;
	xmlNodePtr cur;

	if ((dtd = nm_to_dtd(rsrc)) == NULL)
		return (Z_NO_RESOURCE_TYPE);

	if ((err = zonecfg_setent(handle)) != Z_OK)
		return (err);

	cur = handle->zone_dh_cur;
	while (cur != NULL) {
		xmlNodePtr tmp;

		if (xmlStrcmp(cur->name, dtd)) {
			cur = cur->next;
			continue;
		}

		tmp = cur->next;
		xmlUnlinkNode(cur);
		xmlFreeNode(cur);
		cur = tmp;
	}

	(void) zonecfg_endent(handle);
	return (Z_OK);
}

static boolean_t
valid_uint(char *s, uint64_t *n)
{
	char *endp;

	/* strtoull accepts '-'?! so we want to flag that as an error */
	if (strchr(s, '-') != NULL)
		return (B_FALSE);

	errno = 0;
	*n = strtoull(s, &endp, 10);

	if (errno != 0 || *endp != '\0')
		return (B_FALSE);
	return (B_TRUE);
}

/*
 * Convert a string representing a number (possibly a fraction) into an integer.
 * The string can have a modifier (K, M, G or T).   The modifiers are treated
 * as powers of two (not 10).
 */
int
zonecfg_str_to_bytes(char *str, uint64_t *bytes)
{
	long double val;
	char *unitp;
	uint64_t scale;

	if ((val = strtold(str, &unitp)) < 0)
		return (-1);

	/* remove any leading white space from units string */
	while (isspace(*unitp) != 0)
		++unitp;

	/* if no units explicitly set, error */
	if (unitp == NULL || *unitp == '\0') {
		scale = 1;
	} else {
		int i;
		char *units[] = {"K", "M", "G", "T", NULL};

		scale = 1024;

		/* update scale based on units */
		for (i = 0; units[i] != NULL; i++) {
			if (strcasecmp(unitp, units[i]) == 0)
				break;
			scale <<= 10;
		}

		if (units[i] == NULL)
			return (-1);
	}

	*bytes = (uint64_t)(val * scale);
	return (0);
}

boolean_t
zonecfg_valid_ncpus(char *lowstr, char *highstr)
{
	uint64_t low, high;

	if (!valid_uint(lowstr, &low) || !valid_uint(highstr, &high) ||
	    low < 1 || low > high)
		return (B_FALSE);

	return (B_TRUE);
}

boolean_t
zonecfg_valid_importance(char *impstr)
{
	uint64_t num;

	if (!valid_uint(impstr, &num))
		return (B_FALSE);

	return (B_TRUE);
}

boolean_t
zonecfg_valid_alias_limit(char *name, char *limitstr, uint64_t *limit)
{
	int i;

	for (i = 0; aliases[i].shortname != NULL; i++)
		if (strcmp(name, aliases[i].shortname) == 0)
			break;

	if (aliases[i].shortname == NULL)
		return (B_FALSE);

	if (!valid_uint(limitstr, limit) || *limit < aliases[i].low_limit)
		return (B_FALSE);

	return (B_TRUE);
}

boolean_t
zonecfg_valid_memlimit(char *memstr, uint64_t *mem_val)
{
	if (zonecfg_str_to_bytes(memstr, mem_val) != 0)
		return (B_FALSE);

	return (B_TRUE);
}

static int
zerr_pool(char *pool_err, int err_size, int res)
{
	(void) strlcpy(pool_err, pool_strerror(pool_error()), err_size);
	return (res);
}

static int
create_tmp_pset(char *pool_err, int err_size, pool_conf_t *pconf, pool_t *pool,
    char *name, int min, int max)
{
	pool_resource_t *res;
	pool_elem_t *elem;
	pool_value_t *val;

	if ((res = pool_resource_create(pconf, "pset", name)) == NULL)
		return (zerr_pool(pool_err, err_size, Z_POOL));

	if (pool_associate(pconf, pool, res) != PO_SUCCESS)
		return (zerr_pool(pool_err, err_size, Z_POOL));

	if ((elem = pool_resource_to_elem(pconf, res)) == NULL)
		return (zerr_pool(pool_err, err_size, Z_POOL));

	if ((val = pool_value_alloc()) == NULL)
		return (zerr_pool(pool_err, err_size, Z_POOL));

	/* set the maximum number of cpus for the pset */
	pool_value_set_uint64(val, (uint64_t)max);

	if (pool_put_property(pconf, elem, "pset.max", val) != PO_SUCCESS) {
		pool_value_free(val);
		return (zerr_pool(pool_err, err_size, Z_POOL));
	}

	/* set the minimum number of cpus for the pset */
	pool_value_set_uint64(val, (uint64_t)min);

	if (pool_put_property(pconf, elem, "pset.min", val) != PO_SUCCESS) {
		pool_value_free(val);
		return (zerr_pool(pool_err, err_size, Z_POOL));
	}

	pool_value_free(val);

	return (Z_OK);
}

static int
create_tmp_pool(char *pool_err, int err_size, pool_conf_t *pconf, char *name,
    struct zone_psettab *pset_tab)
{
	pool_t *pool;
	int res = Z_OK;

	/* create a temporary pool configuration */
	if (pool_conf_open(pconf, NULL, PO_TEMP) != PO_SUCCESS) {
		res = zerr_pool(pool_err, err_size, Z_POOL);
		return (res);
	}

	if ((pool = pool_create(pconf, name)) == NULL) {
		res = zerr_pool(pool_err, err_size, Z_POOL_CREATE);
		goto done;
	}

	/* set pool importance */
	if (pset_tab->zone_importance[0] != '\0') {
		pool_elem_t *elem;
		pool_value_t *val;

		if ((elem = pool_to_elem(pconf, pool)) == NULL) {
			res = zerr_pool(pool_err, err_size, Z_POOL);
			goto done;
		}

		if ((val = pool_value_alloc()) == NULL) {
			res = zerr_pool(pool_err, err_size, Z_POOL);
			goto done;
		}

		pool_value_set_int64(val,
		    (int64_t)atoi(pset_tab->zone_importance));

		if (pool_put_property(pconf, elem, "pool.importance", val)
		    != PO_SUCCESS) {
			res = zerr_pool(pool_err, err_size, Z_POOL);
			pool_value_free(val);
			goto done;
		}

		pool_value_free(val);
	}

	if ((res = create_tmp_pset(pool_err, err_size, pconf, pool, name,
	    atoi(pset_tab->zone_ncpu_min),
	    atoi(pset_tab->zone_ncpu_max))) != Z_OK)
		goto done;

	/* validation */
	if (pool_conf_status(pconf) == POF_INVALID) {
		res = zerr_pool(pool_err, err_size, Z_POOL);
		goto done;
	}

	/*
	 * This validation is the one we expect to fail if the user specified
	 * an invalid configuration (too many cpus) for this system.
	 */
	if (pool_conf_validate(pconf, POV_RUNTIME) != PO_SUCCESS) {
		res = zerr_pool(pool_err, err_size, Z_POOL_CREATE);
		goto done;
	}

	/*
	 * Commit the dynamic configuration but not the pool configuration
	 * file.
	 */
	if (pool_conf_commit(pconf, 1) != PO_SUCCESS)
		res = zerr_pool(pool_err, err_size, Z_POOL);

done:
	(void) pool_conf_close(pconf);
	return (res);
}

static int
get_running_tmp_pset(pool_conf_t *pconf, pool_t *pool, pool_resource_t *pset,
    struct zone_psettab *pset_tab)
{
	int nfound = 0;
	pool_elem_t *pe;
	pool_value_t *pv = pool_value_alloc();
	uint64_t val_uint;

	if (pool != NULL) {
		pe = pool_to_elem(pconf, pool);
		if (pool_get_property(pconf, pe, "pool.importance", pv)
		    != POC_INVAL) {
			int64_t val_int;

			(void) pool_value_get_int64(pv, &val_int);
			(void) snprintf(pset_tab->zone_importance,
			    sizeof (pset_tab->zone_importance), "%d", val_int);
			nfound++;
		}
	}

	if (pset != NULL) {
		pe = pool_resource_to_elem(pconf, pset);
		if (pool_get_property(pconf, pe, "pset.min", pv) != POC_INVAL) {
			(void) pool_value_get_uint64(pv, &val_uint);
			(void) snprintf(pset_tab->zone_ncpu_min,
			    sizeof (pset_tab->zone_ncpu_min), "%u", val_uint);
			nfound++;
		}

		if (pool_get_property(pconf, pe, "pset.max", pv) != POC_INVAL) {
			(void) pool_value_get_uint64(pv, &val_uint);
			(void) snprintf(pset_tab->zone_ncpu_max,
			    sizeof (pset_tab->zone_ncpu_max), "%u", val_uint);
			nfound++;
		}
	}

	pool_value_free(pv);

	if (nfound == 3)
		return (PO_SUCCESS);

	return (PO_FAIL);
}

/*
 * Determine if a tmp pool is configured and if so, if the configuration is
 * still valid or if it has been changed since the tmp pool was created.
 * If the tmp pool configuration is no longer valid, delete the tmp pool.
 *
 * Set *valid=B_TRUE if there is an existing, valid tmp pool configuration.
 */
static int
verify_del_tmp_pool(pool_conf_t *pconf, char *tmp_name, char *pool_err,
    int err_size, struct zone_psettab *pset_tab, boolean_t *exists)
{
	int res = Z_OK;
	pool_t *pool;
	pool_resource_t *pset;
	struct zone_psettab pset_current;

	*exists = B_FALSE;

	if (pool_conf_open(pconf, pool_dynamic_location(), PO_RDWR)
	    != PO_SUCCESS) {
		res = zerr_pool(pool_err, err_size, Z_POOL);
		return (res);
	}

	pool = pool_get_pool(pconf, tmp_name);
	pset = pool_get_resource(pconf, "pset", tmp_name);

	if (pool == NULL && pset == NULL) {
		/* no tmp pool configured */
		goto done;
	}

	/*
	 * If an existing tmp pool for this zone is configured with the proper
	 * settings, then the tmp pool is valid.
	 */
	if (get_running_tmp_pset(pconf, pool, pset, &pset_current)
	    == PO_SUCCESS &&
	    strcmp(pset_tab->zone_ncpu_min,
	    pset_current.zone_ncpu_min) == 0 &&
	    strcmp(pset_tab->zone_ncpu_max,
	    pset_current.zone_ncpu_max) == 0 &&
	    strcmp(pset_tab->zone_importance,
	    pset_current.zone_importance) == 0) {
		*exists = B_TRUE;

	} else {
		/*
		 * An out-of-date tmp pool configuration exists.  Delete it
		 * so that we can create the correct tmp pool config.
		 */
		if (pset != NULL &&
		    pool_resource_destroy(pconf, pset) != PO_SUCCESS) {
			res = zerr_pool(pool_err, err_size, Z_POOL);
			goto done;
		}

		if (pool != NULL &&
		    pool_destroy(pconf, pool) != PO_SUCCESS) {
			res = zerr_pool(pool_err, err_size, Z_POOL);
			goto done;
		}

		/* commit dynamic config */
		if (pool_conf_commit(pconf, 0) != PO_SUCCESS)
			res = zerr_pool(pool_err, err_size, Z_POOL);
	}

done:
	(void) pool_conf_close(pconf);

	return (res);
}

/*
 * Destroy any existing tmp pool.
 */
int
zonecfg_destroy_tmp_pool(char *zone_name, char *pool_err, int err_size)
{
	int status;
	int res = Z_OK;
	pool_conf_t *pconf;
	pool_t *pool;
	pool_resource_t *pset;
	char tmp_name[MAX_TMP_POOL_NAME];

	/* if pools not enabled then nothing to do */
	if (pool_get_status(&status) != PO_SUCCESS || status != POOL_ENABLED)
		return (Z_OK);

	if ((pconf = pool_conf_alloc()) == NULL)
		return (zerr_pool(pool_err, err_size, Z_POOL));

	(void) snprintf(tmp_name, sizeof (tmp_name), TMP_POOL_NAME, zone_name);

	if (pool_conf_open(pconf, pool_dynamic_location(), PO_RDWR)
	    != PO_SUCCESS) {
		res = zerr_pool(pool_err, err_size, Z_POOL);
		pool_conf_free(pconf);
		return (res);
	}

	pool = pool_get_pool(pconf, tmp_name);
	pset = pool_get_resource(pconf, "pset", tmp_name);

	if (pool == NULL && pset == NULL) {
		/* nothing to destroy, we're done */
		goto done;
	}

	if (pset != NULL && pool_resource_destroy(pconf, pset) != PO_SUCCESS) {
		res = zerr_pool(pool_err, err_size, Z_POOL);
		goto done;
	}

	if (pool != NULL && pool_destroy(pconf, pool) != PO_SUCCESS) {
		res = zerr_pool(pool_err, err_size, Z_POOL);
		goto done;
	}

	/* commit dynamic config */
	if (pool_conf_commit(pconf, 0) != PO_SUCCESS)
		res = zerr_pool(pool_err, err_size, Z_POOL);

done:
	(void) pool_conf_close(pconf);
	pool_conf_free(pconf);

	return (res);
}

/*
 * Attempt to bind to a tmp pool for this zone.  If there is no tmp pool
 * configured, we just return Z_OK.
 *
 * We either attempt to create the tmp pool for this zone or rebind to an
 * existing tmp pool for this zone.
 *
 * Rebinding is used when a zone with a tmp pool reboots so that we don't have
 * to recreate the tmp pool.  To do this we need to be sure we work correctly
 * for the following cases:
 *
 *	- there is an existing, properly configured tmp pool.
 *	- zonecfg added tmp pool after zone was booted, must now create.
 *	- zonecfg updated tmp pool config after zone was booted, in this case
 *	  we destroy the old tmp pool and create a new one.
 */
int
zonecfg_bind_tmp_pool(zone_dochandle_t handle, zoneid_t zoneid, char *pool_err,
    int err_size)
{
	struct zone_psettab pset_tab;
	int err;
	int status;
	pool_conf_t *pconf;
	boolean_t exists;
	char zone_name[ZONENAME_MAX];
	char tmp_name[MAX_TMP_POOL_NAME];

	(void) getzonenamebyid(zoneid, zone_name, sizeof (zone_name));

	err = zonecfg_lookup_pset(handle, &pset_tab);

	/* if no temporary pool configured, we're done */
	if (err == Z_NO_ENTRY)
		return (Z_OK);

	/*
	 * importance might not have a value but we need to validate it here,
	 * so set the default.
	 */
	if (pset_tab.zone_importance[0] == '\0')
		(void) strlcpy(pset_tab.zone_importance, "1",
		    sizeof (pset_tab.zone_importance));

	/* if pools not enabled, enable them now */
	if (pool_get_status(&status) != PO_SUCCESS || status != POOL_ENABLED) {
		if (pool_set_status(POOL_ENABLED) != PO_SUCCESS)
			return (Z_POOL_ENABLE);
	}

	if ((pconf = pool_conf_alloc()) == NULL)
		return (zerr_pool(pool_err, err_size, Z_POOL));

	(void) snprintf(tmp_name, sizeof (tmp_name), TMP_POOL_NAME, zone_name);

	/*
	 * Check if a valid tmp pool/pset already exists.  If so, we just
	 * reuse it.
	 */
	if ((err = verify_del_tmp_pool(pconf, tmp_name, pool_err, err_size,
	    &pset_tab, &exists)) != Z_OK) {
		pool_conf_free(pconf);
		return (err);
	}

	if (!exists)
		err = create_tmp_pool(pool_err, err_size, pconf, tmp_name,
		    &pset_tab);

	pool_conf_free(pconf);

	if (err != Z_OK)
		return (err);

	/* Bind the zone to the pool. */
	if (pool_set_binding(tmp_name, P_ZONEID, zoneid) != PO_SUCCESS)
		return (zerr_pool(pool_err, err_size, Z_POOL_BIND));

	return (Z_OK);
}

/*
 * Attempt to bind to a permanent pool for this zone.  If there is no
 * permanent pool configured, we just return Z_OK.
 */
int
zonecfg_bind_pool(zone_dochandle_t handle, zoneid_t zoneid, char *pool_err,
    int err_size)
{
	pool_conf_t *poolconf;
	pool_t *pool;
	char poolname[MAXPATHLEN];
	int status;
	int error;

	/*
	 * Find the pool mentioned in the zone configuration, and bind to it.
	 */
	error = zonecfg_get_pool(handle, poolname, sizeof (poolname));
	if (error == Z_NO_ENTRY || (error == Z_OK && strlen(poolname) == 0)) {
		/*
		 * The property is not set on the zone, so the pool
		 * should be bound to the default pool.  But that's
		 * already done by the kernel, so we can just return.
		 */
		return (Z_OK);
	}
	if (error != Z_OK) {
		/*
		 * Not an error, even though it shouldn't be happening.
		 */
		return (Z_OK);
	}
	/*
	 * Don't do anything if pools aren't enabled.
	 */
	if (pool_get_status(&status) != PO_SUCCESS || status != POOL_ENABLED)
		return (Z_POOLS_NOT_ACTIVE);

	/*
	 * Try to provide a sane error message if the requested pool doesn't
	 * exist.
	 */
	if ((poolconf = pool_conf_alloc()) == NULL)
		return (zerr_pool(pool_err, err_size, Z_POOL));

	if (pool_conf_open(poolconf, pool_dynamic_location(), PO_RDONLY) !=
	    PO_SUCCESS) {
		pool_conf_free(poolconf);
		return (zerr_pool(pool_err, err_size, Z_POOL));
	}
	pool = pool_get_pool(poolconf, poolname);
	(void) pool_conf_close(poolconf);
	pool_conf_free(poolconf);
	if (pool == NULL)
		return (Z_NO_POOL);

	/*
	 * Bind the zone to the pool.
	 */
	if (pool_set_binding(poolname, P_ZONEID, zoneid) != PO_SUCCESS) {
		/* if bind fails, return poolname for the error msg */
		(void) strlcpy(pool_err, poolname, err_size);
		return (Z_POOL_BIND);
	}

	return (Z_OK);
}


static boolean_t
svc_enabled(char *svc_name)
{
	scf_simple_prop_t	*prop;
	boolean_t		found = B_FALSE;

	prop = scf_simple_prop_get(NULL, svc_name, SCF_PG_GENERAL,
	    SCF_PROPERTY_ENABLED);

	if (scf_simple_prop_numvalues(prop) == 1 &&
	    *scf_simple_prop_next_boolean(prop) != 0)
		found = B_TRUE;

	scf_simple_prop_free(prop);

	return (found);
}

/*
 * If the zone has capped-memory, make sure the rcap service is enabled.
 */
int
zonecfg_enable_rcapd(char *err, int size)
{
	if (!svc_enabled(RCAP_SERVICE) &&
	    smf_enable_instance(RCAP_SERVICE, 0) == -1) {
		(void) strlcpy(err, scf_strerror(scf_error()), size);
		return (Z_SYSTEM);
	}

	return (Z_OK);
}

/*
 * Return true if pset has cpu range specified and poold is not enabled.
 */
boolean_t
zonecfg_warn_poold(zone_dochandle_t handle)
{
	struct zone_psettab pset_tab;
	int min, max;
	int err;

	err = zonecfg_lookup_pset(handle, &pset_tab);

	/* if no temporary pool configured, we're done */
	if (err == Z_NO_ENTRY)
		return (B_FALSE);

	min = atoi(pset_tab.zone_ncpu_min);
	max = atoi(pset_tab.zone_ncpu_max);

	/* range not specified, no need for poold */
	if (min == max)
		return (B_FALSE);

	/* we have a range, check if poold service is enabled */
	if (svc_enabled(POOLD_SERVICE))
		return (B_FALSE);

	return (B_TRUE);
}

static int
get_pool_sched_class(char *poolname, char *class, int clsize)
{
	int status;
	pool_conf_t *poolconf;
	pool_t *pool;
	pool_elem_t *pe;
	pool_value_t *pv = pool_value_alloc();
	const char *sched_str;

	if (pool_get_status(&status) != PO_SUCCESS || status != POOL_ENABLED)
		return (Z_NO_POOL);

	if ((poolconf = pool_conf_alloc()) == NULL)
		return (Z_NO_POOL);

	if (pool_conf_open(poolconf, pool_dynamic_location(), PO_RDONLY) !=
	    PO_SUCCESS) {
		pool_conf_free(poolconf);
		return (Z_NO_POOL);
	}

	if ((pool = pool_get_pool(poolconf, poolname)) == NULL) {
		(void) pool_conf_close(poolconf);
		pool_conf_free(poolconf);
		return (Z_NO_POOL);
	}

	pe = pool_to_elem(poolconf, pool);
	if (pool_get_property(poolconf, pe, "pool.scheduler", pv)
	    != POC_INVAL) {
		(void) pool_value_get_string(pv, &sched_str);
		if (strlcpy(class, sched_str, clsize) >= clsize)
			return (Z_TOO_BIG);
	}

	(void) pool_conf_close(poolconf);
	pool_conf_free(poolconf);
	return (Z_OK);
}

/*
 * Get the default scheduling class for the zone.  This will either be the
 * class set on the zone's pool or the system default scheduling class.
 */
int
zonecfg_get_dflt_sched_class(zone_dochandle_t handle, char *class, int clsize)
{
	char poolname[MAXPATHLEN];

	if (zonecfg_get_pool(handle, poolname, sizeof (poolname)) == Z_OK) {
		/* check if the zone's pool specified a sched class */
		if (get_pool_sched_class(poolname, class, clsize) == Z_OK)
			return (Z_OK);
	}

	if (priocntl(0, 0, PC_GETDFLCL, class, (uint64_t)clsize) == -1)
		return (Z_TOO_BIG);

	return (Z_OK);
}

int
zonecfg_setfsent(zone_dochandle_t handle)
{
	return (zonecfg_setent(handle));
}

int
zonecfg_getfsent(zone_dochandle_t handle, struct zone_fstab *tabptr)
{
	xmlNodePtr cur, options;
	char options_str[MAX_MNTOPT_STR];
	int err;

	if (handle == NULL)
		return (Z_INVAL);

	if ((cur = handle->zone_dh_cur) == NULL)
		return (Z_NO_ENTRY);

	for (; cur != NULL; cur = cur->next)
		if (!xmlStrcmp(cur->name, DTD_ELEM_FS))
			break;
	if (cur == NULL) {
		handle->zone_dh_cur = handle->zone_dh_top;
		return (Z_NO_ENTRY);
	}

	if ((err = fetchprop(cur, DTD_ATTR_SPECIAL, tabptr->zone_fs_special,
	    sizeof (tabptr->zone_fs_special))) != Z_OK) {
		handle->zone_dh_cur = handle->zone_dh_top;
		return (err);
	}

	if ((err = fetchprop(cur, DTD_ATTR_RAW, tabptr->zone_fs_raw,
	    sizeof (tabptr->zone_fs_raw))) != Z_OK) {
		handle->zone_dh_cur = handle->zone_dh_top;
		return (err);
	}

	if ((err = fetchprop(cur, DTD_ATTR_DIR, tabptr->zone_fs_dir,
	    sizeof (tabptr->zone_fs_dir))) != Z_OK) {
		handle->zone_dh_cur = handle->zone_dh_top;
		return (err);
	}

	if ((err = fetchprop(cur, DTD_ATTR_TYPE, tabptr->zone_fs_type,
	    sizeof (tabptr->zone_fs_type))) != Z_OK) {
		handle->zone_dh_cur = handle->zone_dh_top;
		return (err);
	}

	/* OK for options to be NULL */
	tabptr->zone_fs_options = NULL;
	for (options = cur->xmlChildrenNode; options != NULL;
	    options = options->next) {
		if (fetchprop(options, DTD_ATTR_NAME, options_str,
		    sizeof (options_str)) != Z_OK)
			break;
		if (zonecfg_add_fs_option(tabptr, options_str) != Z_OK)
			break;
	}

	handle->zone_dh_cur = cur->next;
	return (Z_OK);
}

int
zonecfg_endfsent(zone_dochandle_t handle)
{
	return (zonecfg_endent(handle));
}

int
zonecfg_setipdent(zone_dochandle_t handle)
{
	return (zonecfg_setent(handle));
}

int
zonecfg_getipdent(zone_dochandle_t handle, struct zone_fstab *tabptr)
{
	xmlNodePtr cur;
	int err;

	if (handle == NULL)
		return (Z_INVAL);

	if ((cur = handle->zone_dh_cur) == NULL)
		return (Z_NO_ENTRY);

	for (; cur != NULL; cur = cur->next)
		if (!xmlStrcmp(cur->name, DTD_ELEM_IPD))
			break;
	if (cur == NULL) {
		handle->zone_dh_cur = handle->zone_dh_top;
		return (Z_NO_ENTRY);
	}

	if ((err = fetchprop(cur, DTD_ATTR_DIR, tabptr->zone_fs_dir,
	    sizeof (tabptr->zone_fs_dir))) != Z_OK) {
		handle->zone_dh_cur = handle->zone_dh_top;
		return (err);
	}

	handle->zone_dh_cur = cur->next;
	return (Z_OK);
}

int
zonecfg_endipdent(zone_dochandle_t handle)
{
	return (zonecfg_endent(handle));
}

int
zonecfg_setnwifent(zone_dochandle_t handle)
{
	return (zonecfg_setent(handle));
}

int
zonecfg_getnwifent(zone_dochandle_t handle, struct zone_nwiftab *tabptr)
{
	xmlNodePtr cur;
	int err;

	if (handle == NULL)
		return (Z_INVAL);

	if ((cur = handle->zone_dh_cur) == NULL)
		return (Z_NO_ENTRY);

	for (; cur != NULL; cur = cur->next)
		if (!xmlStrcmp(cur->name, DTD_ELEM_NET))
			break;
	if (cur == NULL) {
		handle->zone_dh_cur = handle->zone_dh_top;
		return (Z_NO_ENTRY);
	}

	if ((err = fetchprop(cur, DTD_ATTR_ADDRESS, tabptr->zone_nwif_address,
	    sizeof (tabptr->zone_nwif_address))) != Z_OK) {
		handle->zone_dh_cur = handle->zone_dh_top;
		return (err);
	}

	if ((err = fetchprop(cur, DTD_ATTR_PHYSICAL, tabptr->zone_nwif_physical,
	    sizeof (tabptr->zone_nwif_physical))) != Z_OK) {
		handle->zone_dh_cur = handle->zone_dh_top;
		return (err);
	}

	handle->zone_dh_cur = cur->next;
	return (Z_OK);
}

int
zonecfg_endnwifent(zone_dochandle_t handle)
{
	return (zonecfg_endent(handle));
}

int
zonecfg_setdevent(zone_dochandle_t handle)
{
	return (zonecfg_setent(handle));
}

int
zonecfg_getdevent(zone_dochandle_t handle, struct zone_devtab *tabptr)
{
	xmlNodePtr cur;
	int err;

	if (handle == NULL)
		return (Z_INVAL);

	if ((cur = handle->zone_dh_cur) == NULL)
		return (Z_NO_ENTRY);

	for (; cur != NULL; cur = cur->next)
		if (!xmlStrcmp(cur->name, DTD_ELEM_DEVICE))
			break;
	if (cur == NULL) {
		handle->zone_dh_cur = handle->zone_dh_top;
		return (Z_NO_ENTRY);
	}

	if ((err = fetchprop(cur, DTD_ATTR_MATCH, tabptr->zone_dev_match,
	    sizeof (tabptr->zone_dev_match))) != Z_OK) {
		handle->zone_dh_cur = handle->zone_dh_top;
		return (err);
	}

	handle->zone_dh_cur = cur->next;
	return (Z_OK);
}

int
zonecfg_enddevent(zone_dochandle_t handle)
{
	return (zonecfg_endent(handle));
}

int
zonecfg_setrctlent(zone_dochandle_t handle)
{
	return (zonecfg_setent(handle));
}

int
zonecfg_getrctlent(zone_dochandle_t handle, struct zone_rctltab *tabptr)
{
	xmlNodePtr cur, val;
	struct zone_rctlvaltab *valptr;
	int err;

	if (handle == NULL)
		return (Z_INVAL);

	if ((cur = handle->zone_dh_cur) == NULL)
		return (Z_NO_ENTRY);

	for (; cur != NULL; cur = cur->next)
		if (!xmlStrcmp(cur->name, DTD_ELEM_RCTL))
			break;
	if (cur == NULL) {
		handle->zone_dh_cur = handle->zone_dh_top;
		return (Z_NO_ENTRY);
	}

	if ((err = fetchprop(cur, DTD_ATTR_NAME, tabptr->zone_rctl_name,
	    sizeof (tabptr->zone_rctl_name))) != Z_OK) {
		handle->zone_dh_cur = handle->zone_dh_top;
		return (err);
	}

	tabptr->zone_rctl_valptr = NULL;
	for (val = cur->xmlChildrenNode; val != NULL; val = val->next) {
		valptr = (struct zone_rctlvaltab *)malloc(
		    sizeof (struct zone_rctlvaltab));
		if (valptr == NULL)
			return (Z_NOMEM);
		if (fetchprop(val, DTD_ATTR_PRIV, valptr->zone_rctlval_priv,
		    sizeof (valptr->zone_rctlval_priv)) != Z_OK)
			break;
		if (fetchprop(val, DTD_ATTR_LIMIT, valptr->zone_rctlval_limit,
		    sizeof (valptr->zone_rctlval_limit)) != Z_OK)
			break;
		if (fetchprop(val, DTD_ATTR_ACTION, valptr->zone_rctlval_action,
		    sizeof (valptr->zone_rctlval_action)) != Z_OK)
			break;
		if (zonecfg_add_rctl_value(tabptr, valptr) != Z_OK)
			break;
	}

	handle->zone_dh_cur = cur->next;
	return (Z_OK);
}

int
zonecfg_endrctlent(zone_dochandle_t handle)
{
	return (zonecfg_endent(handle));
}

int
zonecfg_setattrent(zone_dochandle_t handle)
{
	return (zonecfg_setent(handle));
}

int
zonecfg_getattrent(zone_dochandle_t handle, struct zone_attrtab *tabptr)
{
	xmlNodePtr cur;
	int err;

	if (handle == NULL)
		return (Z_INVAL);

	if ((cur = handle->zone_dh_cur) == NULL)
		return (Z_NO_ENTRY);

	for (; cur != NULL; cur = cur->next)
		if (!xmlStrcmp(cur->name, DTD_ELEM_ATTR))
			break;
	if (cur == NULL) {
		handle->zone_dh_cur = handle->zone_dh_top;
		return (Z_NO_ENTRY);
	}

	if ((err = fetchprop(cur, DTD_ATTR_NAME, tabptr->zone_attr_name,
	    sizeof (tabptr->zone_attr_name))) != Z_OK) {
		handle->zone_dh_cur = handle->zone_dh_top;
		return (err);
	}

	if ((err = fetchprop(cur, DTD_ATTR_TYPE, tabptr->zone_attr_type,
	    sizeof (tabptr->zone_attr_type))) != Z_OK) {
		handle->zone_dh_cur = handle->zone_dh_top;
		return (err);
	}

	if ((err = fetchprop(cur, DTD_ATTR_VALUE, tabptr->zone_attr_value,
	    sizeof (tabptr->zone_attr_value))) != Z_OK) {
		handle->zone_dh_cur = handle->zone_dh_top;
		return (err);
	}

	handle->zone_dh_cur = cur->next;
	return (Z_OK);
}

int
zonecfg_endattrent(zone_dochandle_t handle)
{
	return (zonecfg_endent(handle));
}

/*
 * The privileges available on the system and described in privileges(5)
 * fall into four categories with respect to non-global zones:
 *
 *      Default set of privileges considered safe for all non-global
 *      zones.  These privileges are "safe" in the sense that a
 *      privileged process in the zone cannot affect processes in any
 *      other zone on the system.
 *
 *      Set of privileges not currently permitted within a non-global
 *      zone.  These privileges are considered by default, "unsafe,"
 *      and include ones which affect global resources (such as the
 *      system clock or physical memory) or are overly broad and cover
 *      more than one mechanism in the system.  In other cases, there
 *      has not been sufficient virtualization in the parts of the
 *      system the privilege covers to allow its use within a
 *      non-global zone.
 *
 *      Set of privileges required in order to get a zone booted and
 *      init(1M) started.  These cannot be removed from the zone's
 *      privilege set.
 *
 * All other privileges are optional and are potentially useful for
 * processes executing inside a non-global zone.
 *
 * When privileges are added to the system, a determination needs to be
 * made as to which category the privilege belongs to.  Ideally,
 * privileges should be fine-grained enough and the mechanisms they cover
 * virtualized enough so that they can be made available to non-global
 * zones.
 */

/*
 * Define some of the tokens that priv_str_to_set(3C) recognizes.  Since
 * the privilege string separator can be any character, although it is
 * usually a comma character, define these here as well in the event that
 * they change or are augmented in the future.
 */
#define	BASIC_TOKEN		"basic"
#define	DEFAULT_TOKEN		"default"
#define	ZONE_TOKEN		"zone"
#define	TOKEN_PRIV_CHAR		','
#define	TOKEN_PRIV_STR		","

typedef struct priv_node {
	struct priv_node	*pn_next;	/* Next privilege */
	char			*pn_priv;	/* Privileges name */
} priv_node_t;

/* Privileges lists can differ across brands */
typedef struct priv_lists {
	/* Privileges considered safe for all non-global zones of a brand */
	struct priv_node	*pl_default;

	/* Privileges not permitted for all non-global zones of a brand */
	struct priv_node	*pl_prohibited;

	/* Privileges required for all non-global zones of a brand */
	struct priv_node	*pl_required;

	/*
	 * ip-type of the zone these privileges lists apply to.
	 * It is used to pass ip-type to the callback function,
	 * priv_lists_cb, which has no way of getting the ip-type.
	 */
	const char		*pl_iptype;
} priv_lists_t;

static int
priv_lists_cb(void *data, priv_iter_t *priv_iter)
{
	priv_lists_t *plp = (priv_lists_t *)data;
	priv_node_t *pnp;

	/* Skip this privilege if ip-type does not match */
	if ((strcmp(priv_iter->pi_iptype, "all") != 0) &&
	    (strcmp(priv_iter->pi_iptype, plp->pl_iptype) != 0))
		return (0);

	/* Allocate a new priv list node. */
	if ((pnp = malloc(sizeof (*pnp))) == NULL)
		return (-1);
	if ((pnp->pn_priv = strdup(priv_iter->pi_name)) == NULL) {
		free(pnp);
		return (-1);
	}

	/* Insert the new priv list node into the right list */
	if (strcmp(priv_iter->pi_set, "default") == 0) {
		pnp->pn_next = plp->pl_default;
		plp->pl_default = pnp;
	} else if (strcmp(priv_iter->pi_set, "prohibited") == 0) {
		pnp->pn_next = plp->pl_prohibited;
		plp->pl_prohibited = pnp;
	} else if (strcmp(priv_iter->pi_set, "required") == 0) {
		pnp->pn_next = plp->pl_required;
		plp->pl_required = pnp;
	} else {
		free(pnp->pn_priv);
		free(pnp);
		return (-1);
	}
	return (0);
}

static void
priv_lists_destroy(priv_lists_t *plp)
{
	priv_node_t *pnp;

	assert(plp != NULL);

	while ((pnp = plp->pl_default) != NULL) {
		plp->pl_default = pnp->pn_next;
		free(pnp->pn_priv);
		free(pnp);
	}
	while ((pnp = plp->pl_prohibited) != NULL) {
		plp->pl_prohibited = pnp->pn_next;
		free(pnp->pn_priv);
		free(pnp);
	}
	while ((pnp = plp->pl_required) != NULL) {
		plp->pl_required = pnp->pn_next;
		free(pnp->pn_priv);
		free(pnp);
	}
	free(plp);
}

static int
priv_lists_create(zone_dochandle_t handle, priv_lists_t **plpp,
    const char *curr_iptype)
{
	priv_lists_t *plp;
	brand_handle_t bh;
	char brand[MAXNAMELEN];

	if (handle != NULL) {
		if (zonecfg_get_brand(handle, brand, sizeof (brand)) != 0)
			return (Z_BRAND_ERROR);
	} else {
		(void) strlcpy(brand, NATIVE_BRAND_NAME, MAXNAMELEN);
	}

	if ((bh = brand_open(brand)) == NULL)
		return (Z_BRAND_ERROR);

	if ((plp = calloc(1, sizeof (priv_lists_t))) == NULL) {
		brand_close(bh);
		return (Z_NOMEM);
	}

	plp->pl_iptype = curr_iptype;

	/* construct the privilege lists */
	if (brand_config_iter_privilege(bh, priv_lists_cb, plp) != 0) {
		priv_lists_destroy(plp);
		brand_close(bh);
		return (Z_BRAND_ERROR);
	}

	brand_close(bh);
	*plpp = plp;
	return (Z_OK);
}

static int
get_default_privset(priv_set_t *privs, priv_lists_t *plp)
{
	priv_node_t *pnp;
	priv_set_t *basic;

	basic = priv_str_to_set(BASIC_TOKEN, TOKEN_PRIV_STR, NULL);
	if (basic == NULL)
		return (errno == ENOMEM ? Z_NOMEM : Z_INVAL);

	priv_union(basic, privs);
	priv_freeset(basic);

	for (pnp = plp->pl_default; pnp != NULL; pnp = pnp->pn_next) {
		if (priv_addset(privs, pnp->pn_priv) != 0)
			return (Z_INVAL);
	}

	return (Z_OK);
}

int
zonecfg_default_privset(priv_set_t *privs, const char *curr_iptype)
{
	priv_lists_t *plp;
	int ret;

	if ((ret = priv_lists_create(NULL, &plp, curr_iptype)) != Z_OK)
		return (ret);
	ret = get_default_privset(privs, plp);
	priv_lists_destroy(plp);
	return (ret);
}

void
append_priv_token(char *priv, char *str, size_t strlen)
{
	if (*str != '\0')
		(void) strlcat(str, TOKEN_PRIV_STR, strlen);
	(void) strlcat(str, priv, strlen);
}

/*
 * Verify that the supplied string is a valid privilege limit set for a
 * non-global zone.  This string must not only be acceptable to
 * priv_str_to_set(3C) which parses it, but it also must resolve to a
 * privilege set that includes certain required privileges and lacks
 * certain prohibited privileges.
 */
static int
verify_privset(char *privbuf, priv_set_t *privs, char **privname,
    boolean_t add_default, priv_lists_t *plp)
{
	priv_node_t *pnp;
	char *tmp, *cp, *lasts;
	size_t len;
	priv_set_t *mergeset;
	const char *token;

	/*
	 * The verification of the privilege string occurs in several
	 * phases.  In the first phase, the supplied string is scanned for
	 * the ZONE_TOKEN token which is not support as part of the
	 * "limitpriv" property.
	 *
	 * Duplicate the supplied privilege string since strtok_r(3C)
	 * tokenizes its input by null-terminating the tokens.
	 */
	if ((tmp = strdup(privbuf)) == NULL)
		return (Z_NOMEM);
	for (cp = strtok_r(tmp, TOKEN_PRIV_STR, &lasts); cp != NULL;
	    cp = strtok_r(NULL, TOKEN_PRIV_STR, &lasts)) {
		if (strcmp(cp, ZONE_TOKEN) == 0) {
			free(tmp);
			if ((*privname = strdup(ZONE_TOKEN)) == NULL)
				return (Z_NOMEM);
			else
				return (Z_PRIV_UNKNOWN);
		}
	}
	free(tmp);

	if (add_default) {
		/*
		 * If DEFAULT_TOKEN was specified, a string needs to be
		 * built containing the privileges from the default, safe
		 * set along with those of the "limitpriv" property.
		 */
		len = strlen(privbuf) + sizeof (BASIC_TOKEN) + 2;

		for (pnp = plp->pl_default; pnp != NULL; pnp = pnp->pn_next)
			len += strlen(pnp->pn_priv) + 1;
		tmp = alloca(len);
		*tmp = '\0';

		append_priv_token(BASIC_TOKEN, tmp, len);
		for (pnp = plp->pl_default; pnp != NULL; pnp = pnp->pn_next)
			append_priv_token(pnp->pn_priv, tmp, len);
		(void) strlcat(tmp, TOKEN_PRIV_STR, len);
		(void) strlcat(tmp, privbuf, len);
	} else {
		tmp = privbuf;
	}


	/*
	 * In the next phase, attempt to convert the merged privilege
	 * string into a privilege set.  In the case of an error, either
	 * there was a memory allocation failure or there was an invalid
	 * privilege token in the string.  In either case, return an
	 * appropriate error code but in the event of an invalid token,
	 * allocate a string containing its name and return that back to
	 * the caller.
	 */
	mergeset = priv_str_to_set(tmp, TOKEN_PRIV_STR, &token);
	if (mergeset == NULL) {
		if (token == NULL)
			return (Z_NOMEM);
		if ((cp = strchr(token, TOKEN_PRIV_CHAR)) != NULL)
			*cp = '\0';
		if ((*privname = strdup(token)) == NULL)
			return (Z_NOMEM);
		else
			return (Z_PRIV_UNKNOWN);
	}

	/*
	 * Next, verify that none of the prohibited zone privileges are
	 * present in the merged privilege set.
	 */
	for (pnp = plp->pl_prohibited; pnp != NULL; pnp = pnp->pn_next) {
		if (priv_ismember(mergeset, pnp->pn_priv)) {
			priv_freeset(mergeset);
			if ((*privname = strdup(pnp->pn_priv)) == NULL)
				return (Z_NOMEM);
			else
				return (Z_PRIV_PROHIBITED);
		}
	}

	/*
	 * Finally, verify that all of the required zone privileges are
	 * present in the merged privilege set.
	 */
	for (pnp = plp->pl_required; pnp != NULL; pnp = pnp->pn_next) {
		if (!priv_ismember(mergeset, pnp->pn_priv)) {
			priv_freeset(mergeset);
			if ((*privname = strdup(pnp->pn_priv)) == NULL)
				return (Z_NOMEM);
			else
				return (Z_PRIV_REQUIRED);
		}
	}

	priv_copyset(mergeset, privs);
	priv_freeset(mergeset);
	return (Z_OK);
}

/*
 * Fill in the supplied privilege set with either the default, safe set of
 * privileges suitable for a non-global zone, or one based on the
 * "limitpriv" property in the zone's configuration.
 *
 * In the event of an invalid privilege specification in the
 * configuration, a string is allocated and returned containing the
 * "privilege" causing the issue.  It is the caller's responsibility to
 * free this memory when it is done with it.
 */
int
zonecfg_get_privset(zone_dochandle_t handle, priv_set_t *privs,
    char **privname)
{
	priv_lists_t *plp;
	char *cp, *limitpriv = NULL;
	int err, limitlen;
	zone_iptype_t iptype;
	const char *curr_iptype;

	/*
	 * Attempt to lookup the "limitpriv" property.  If it does not
	 * exist or matches the string DEFAULT_TOKEN exactly, then the
	 * default, safe privilege set is returned.
	 */
	if ((err = zonecfg_get_limitpriv(handle, &limitpriv)) != Z_OK)
		return (err);

	if ((err = zonecfg_get_iptype(handle, &iptype)) != Z_OK)
		return (err);

	switch (iptype) {
	case ZS_SHARED:
		curr_iptype = "shared";
		break;
	case ZS_EXCLUSIVE:
		curr_iptype = "exclusive";
		break;
	}

	if ((err = priv_lists_create(handle, &plp, curr_iptype)) != Z_OK)
		return (err);

	limitlen = strlen(limitpriv);
	if (limitlen == 0 || strcmp(limitpriv, DEFAULT_TOKEN) == 0) {
		free(limitpriv);
		err = get_default_privset(privs, plp);
		priv_lists_destroy(plp);
		return (err);
	}

	/*
	 * Check if the string DEFAULT_TOKEN is the first token in a list
	 * of privileges.
	 */
	cp = strchr(limitpriv, TOKEN_PRIV_CHAR);
	if (cp != NULL &&
	    strncmp(limitpriv, DEFAULT_TOKEN, cp - limitpriv) == 0)
		err = verify_privset(cp + 1, privs, privname, B_TRUE, plp);
	else
		err = verify_privset(limitpriv, privs, privname, B_FALSE, plp);

	free(limitpriv);
	priv_lists_destroy(plp);
	return (err);
}

int
zone_get_zonepath(char *zone_name, char *zonepath, size_t rp_sz)
{
	zone_dochandle_t handle;
	boolean_t found = B_FALSE;
	struct zoneent *ze;
	FILE *cookie;
	int err;
	char *cp;

	if (zone_name == NULL)
		return (Z_INVAL);

	(void) strlcpy(zonepath, zonecfg_root, rp_sz);
	cp = zonepath + strlen(zonepath);
	while (cp > zonepath && cp[-1] == '/')
		*--cp = '\0';

	if (strcmp(zone_name, GLOBAL_ZONENAME) == 0) {
		if (zonepath[0] == '\0')
			(void) strlcpy(zonepath, "/", rp_sz);
		return (Z_OK);
	}

	/*
	 * First check the index file.  Because older versions did not have
	 * a copy of the zone path, allow for it to be zero length, in which
	 * case we ignore this result and fall back to the XML files.
	 */
	cookie = setzoneent();
	while ((ze = getzoneent_private(cookie)) != NULL) {
		if (strcmp(ze->zone_name, zone_name) == 0) {
			found = B_TRUE;
			if (ze->zone_path[0] != '\0')
				(void) strlcpy(cp, ze->zone_path,
				    rp_sz - (cp - zonepath));
		}
		free(ze);
		if (found)
			break;
	}
	endzoneent(cookie);
	if (found && *cp != '\0')
		return (Z_OK);

	/* Fall back to the XML files. */
	if ((handle = zonecfg_init_handle()) == NULL)
		return (Z_NOMEM);

	/*
	 * Check the snapshot first: if a zone is running, its zonepath
	 * may have changed.
	 */
	if (zonecfg_get_snapshot_handle(zone_name, handle) != Z_OK) {
		if ((err = zonecfg_get_handle(zone_name, handle)) != Z_OK) {
			zonecfg_fini_handle(handle);
			return (err);
		}
	}
	err = zonecfg_get_zonepath(handle, zonepath, rp_sz);
	zonecfg_fini_handle(handle);
	return (err);
}

int
zone_get_rootpath(char *zone_name, char *rootpath, size_t rp_sz)
{
	int err;

	/* This function makes sense for non-global zones only. */
	if (strcmp(zone_name, GLOBAL_ZONENAME) == 0)
		return (Z_BOGUS_ZONE_NAME);
	if ((err = zone_get_zonepath(zone_name, rootpath, rp_sz)) != Z_OK)
		return (err);
	if (strlcat(rootpath, "/root", rp_sz) >= rp_sz)
		return (Z_TOO_BIG);
	return (Z_OK);
}

int
zone_get_brand(char *zone_name, char *brandname, size_t rp_sz)
{
	int err;
	zone_dochandle_t handle;
	char myzone[MAXNAMELEN];
	int myzoneid = getzoneid();

	/*
	 * If we are not in the global zone, then we don't have the zone
	 * .xml files with the brand name available.  Thus, we are going to
	 * have to ask the kernel for the information.
	 */
	if (myzoneid != GLOBAL_ZONEID) {
		if (is_system_labeled()) {
			(void) strlcpy(brandname, NATIVE_BRAND_NAME, rp_sz);
			return (Z_OK);
		}
		if (zone_getattr(myzoneid, ZONE_ATTR_NAME, myzone,
		    sizeof (myzone)) < 0)
			return (Z_NO_ZONE);
		if (strncmp(zone_name, myzone, MAXNAMELEN) != NULL)
			return (Z_NO_ZONE);
		err = zone_getattr(myzoneid, ZONE_ATTR_BRAND, brandname, rp_sz);
		if (err < 0)
			return ((errno == EFAULT) ? Z_TOO_BIG : Z_INVAL);
		return (Z_OK);
	}

	if (strcmp(zone_name, "global") == NULL) {
		(void) strlcpy(brandname, NATIVE_BRAND_NAME, rp_sz);
		return (Z_OK);
	}
	if ((handle = zonecfg_init_handle()) == NULL)
		return (Z_NOMEM);

	err = zonecfg_get_handle((char *)zone_name, handle);
	if (err == Z_OK)
		err = zonecfg_get_brand(handle, brandname, rp_sz);

	zonecfg_fini_handle(handle);
	return (err);
}

/*
 * Return the appropriate root for the active /dev.
 * For normal zone, the path is $ZONEPATH/root;
 * for scratch zone, the dev path is $ZONEPATH/lu.
 */
int
zone_get_devroot(char *zone_name, char *devroot, size_t rp_sz)
{
	int err;
	char *suffix;
	zone_state_t state;

	/* This function makes sense for non-global zones only. */
	if (strcmp(zone_name, GLOBAL_ZONENAME) == 0)
		return (Z_BOGUS_ZONE_NAME);
	if ((err = zone_get_zonepath(zone_name, devroot, rp_sz)) != Z_OK)
		return (err);

	if (zone_get_state(zone_name, &state) == Z_OK &&
	    state == ZONE_STATE_MOUNTED)
		suffix = "/lu";
	else
		suffix = "/root";
	if (strlcat(devroot, suffix, rp_sz) >= rp_sz)
		return (Z_TOO_BIG);
	return (Z_OK);
}

static zone_state_t
kernel_state_to_user_state(zoneid_t zoneid, zone_status_t kernel_state)
{
	char zoneroot[MAXPATHLEN];
	size_t zlen;

	assert(kernel_state <= ZONE_MAX_STATE);
	switch (kernel_state) {
		case ZONE_IS_UNINITIALIZED:
		case ZONE_IS_INITIALIZED:
			/* The kernel will not return these two states */
			return (ZONE_STATE_READY);
		case ZONE_IS_READY:
			/*
			 * If the zone's root is mounted on $ZONEPATH/lu, then
			 * it's a mounted scratch zone.
			 */
			if (zone_getattr(zoneid, ZONE_ATTR_ROOT, zoneroot,
			    sizeof (zoneroot)) >= 0) {
				zlen = strlen(zoneroot);
				if (zlen > 3 &&
				    strcmp(zoneroot + zlen - 3, "/lu") == 0)
					return (ZONE_STATE_MOUNTED);
			}
			return (ZONE_STATE_READY);
		case ZONE_IS_BOOTING:
		case ZONE_IS_RUNNING:
			return (ZONE_STATE_RUNNING);
		case ZONE_IS_SHUTTING_DOWN:
		case ZONE_IS_EMPTY:
			return (ZONE_STATE_SHUTTING_DOWN);
		case ZONE_IS_DOWN:
		case ZONE_IS_DYING:
		case ZONE_IS_DEAD:
		default:
			return (ZONE_STATE_DOWN);
	}
	/* NOTREACHED */
}

int
zone_get_state(char *zone_name, zone_state_t *state_num)
{
	zone_status_t status;
	zoneid_t zone_id;
	struct zoneent *ze;
	boolean_t found = B_FALSE;
	FILE *cookie;
	char kernzone[ZONENAME_MAX];
	FILE *fp;

	if (zone_name == NULL)
		return (Z_INVAL);

	/*
	 * If we're looking at an alternate root, then we need to query the
	 * kernel using the scratch zone name.
	 */
	zone_id = -1;
	if (*zonecfg_root != '\0' && !zonecfg_is_scratch(zone_name)) {
		if ((fp = zonecfg_open_scratch("", B_FALSE)) != NULL) {
			if (zonecfg_find_scratch(fp, zone_name, zonecfg_root,
			    kernzone, sizeof (kernzone)) == 0)
				zone_id = getzoneidbyname(kernzone);
			zonecfg_close_scratch(fp);
		}
	} else {
		zone_id = getzoneidbyname(zone_name);
	}

	/* check to see if zone is running */
	if (zone_id != -1 &&
	    zone_getattr(zone_id, ZONE_ATTR_STATUS, &status,
	    sizeof (status)) >= 0) {
		*state_num = kernel_state_to_user_state(zone_id, status);
		return (Z_OK);
	}

	cookie = setzoneent();
	while ((ze = getzoneent_private(cookie)) != NULL) {
		if (strcmp(ze->zone_name, zone_name) == 0) {
			found = B_TRUE;
			*state_num = ze->zone_state;
		}
		free(ze);
		if (found)
			break;
	}
	endzoneent(cookie);
	return ((found) ? Z_OK : Z_NO_ZONE);
}

int
zone_set_state(char *zone, zone_state_t state)
{
	struct zoneent ze;

	if (state != ZONE_STATE_CONFIGURED && state != ZONE_STATE_INSTALLED &&
	    state != ZONE_STATE_INCOMPLETE)
		return (Z_INVAL);

	bzero(&ze, sizeof (ze));
	(void) strlcpy(ze.zone_name, zone, sizeof (ze.zone_name));
	ze.zone_state = state;
	(void) strlcpy(ze.zone_path, "", sizeof (ze.zone_path));
	return (putzoneent(&ze, PZE_MODIFY));
}

/*
 * Get id (if any) for specified zone.  There are four possible outcomes:
 * - If the string corresponds to the numeric id of an active (booted)
 *   zone, sets *zip to the zone id and returns 0.
 * - If the string corresponds to the name of an active (booted) zone,
 *   sets *zip to the zone id and returns 0.
 * - If the string is a name in the configuration but is not booted,
 *   sets *zip to ZONE_ID_UNDEFINED and returns 0.
 * - Otherwise, leaves *zip unchanged and returns -1.
 *
 * This function acts as an auxiliary filter on the function of the same
 * name in libc; the linker binds to this version if libzonecfg exists,
 * and the libc version if it doesn't.  Any changes to this version of
 * the function should probably be reflected in the libc version as well.
 */
int
zone_get_id(const char *str, zoneid_t *zip)
{
	zone_dochandle_t hdl;
	zoneid_t zoneid;
	char *cp;
	int err;

	/* first try looking for active zone by id */
	errno = 0;
	zoneid = (zoneid_t)strtol(str, &cp, 0);
	if (errno == 0 && cp != str && *cp == '\0' &&
	    getzonenamebyid(zoneid, NULL, 0) != -1) {
		*zip = zoneid;
		return (0);
	}

	/* then look for active zone by name */
	if ((zoneid = getzoneidbyname(str)) != -1) {
		*zip = zoneid;
		return (0);
	}

	/* if in global zone, try looking up name in configuration database */
	if (getzoneid() != GLOBAL_ZONEID ||
	    (hdl = zonecfg_init_handle()) == NULL)
		return (-1);

	if (zonecfg_get_handle(str, hdl) == Z_OK) {
		/* zone exists but isn't active */
		*zip = ZONE_ID_UNDEFINED;
		err = 0;
	} else {
		err = -1;
	}

	zonecfg_fini_handle(hdl);
	return (err);
}

char *
zone_state_str(zone_state_t state_num)
{
	switch (state_num) {
	case ZONE_STATE_CONFIGURED:
		return (ZONE_STATE_STR_CONFIGURED);
	case ZONE_STATE_INCOMPLETE:
		return (ZONE_STATE_STR_INCOMPLETE);
	case ZONE_STATE_INSTALLED:
		return (ZONE_STATE_STR_INSTALLED);
	case ZONE_STATE_READY:
		return (ZONE_STATE_STR_READY);
	case ZONE_STATE_MOUNTED:
		return (ZONE_STATE_STR_MOUNTED);
	case ZONE_STATE_RUNNING:
		return (ZONE_STATE_STR_RUNNING);
	case ZONE_STATE_SHUTTING_DOWN:
		return (ZONE_STATE_STR_SHUTTING_DOWN);
	case ZONE_STATE_DOWN:
		return (ZONE_STATE_STR_DOWN);
	default:
		return ("unknown");
	}
}

/*
 * Given a UUID value, find an associated zone name.  This is intended to be
 * used by callers who set up some 'default' name (corresponding to the
 * expected name for the zone) in the zonename buffer, and thus the function
 * doesn't touch this buffer on failure.
 */
int
zonecfg_get_name_by_uuid(const uuid_t uuidin, char *zonename, size_t namelen)
{
	FILE *fp;
	struct zoneent *ze;
	uchar_t *uuid;

	/*
	 * A small amount of subterfuge via casts is necessary here because
	 * libuuid doesn't use const correctly, but we don't want to export
	 * this brokenness to our clients.
	 */
	uuid = (uchar_t *)uuidin;
	if (uuid_is_null(uuid))
		return (Z_NO_ZONE);
	if ((fp = setzoneent()) == NULL)
		return (Z_NO_ZONE);
	while ((ze = getzoneent_private(fp)) != NULL) {
		if (uuid_compare(uuid, ze->zone_uuid) == 0)
			break;
		free(ze);
	}
	endzoneent(fp);
	if (ze != NULL) {
		(void) strlcpy(zonename, ze->zone_name, namelen);
		free(ze);
		return (Z_OK);
	} else {
		return (Z_NO_ZONE);
	}
}

/*
 * Given a zone name, get its UUID.  Returns a "NULL" UUID value if the zone
 * exists but the file doesn't have a value set yet.  Returns an error if the
 * zone cannot be located.
 */
int
zonecfg_get_uuid(const char *zonename, uuid_t uuid)
{
	FILE *fp;
	struct zoneent *ze;

	if ((fp = setzoneent()) == NULL)
		return (Z_NO_ZONE);
	while ((ze = getzoneent_private(fp)) != NULL) {
		if (strcmp(ze->zone_name, zonename) == 0)
			break;
		free(ze);
	}
	endzoneent(fp);
	if (ze != NULL) {
		uuid_copy(uuid, ze->zone_uuid);
		free(ze);
		return (Z_OK);
	} else {
		return (Z_NO_ZONE);
	}
}

/*
 * File-system convenience functions.
 */
boolean_t
zonecfg_valid_fs_type(const char *type)
{
	/*
	 * We already know which FS types don't work.
	 */
	if (strcmp(type, "proc") == 0 ||
	    strcmp(type, "mntfs") == 0 ||
	    strcmp(type, "autofs") == 0 ||
	    strncmp(type, "nfs", sizeof ("nfs") - 1) == 0 ||
	    strcmp(type, "cachefs") == 0)
		return (B_FALSE);
	/*
	 * The caller may do more detailed verification to make sure other
	 * aspects of this filesystem type make sense.
	 */
	return (B_TRUE);
}

/*
 * Generally uninteresting rctl convenience functions.
 */

int
zonecfg_construct_rctlblk(const struct zone_rctlvaltab *rctlval,
    rctlblk_t *rctlblk)
{
	unsigned long long ull;
	char *endp;
	rctl_priv_t priv;
	rctl_qty_t limit;
	uint_t action;

	/* Get the privilege */
	if (strcmp(rctlval->zone_rctlval_priv, "basic") == 0) {
		priv = RCPRIV_BASIC;
	} else if (strcmp(rctlval->zone_rctlval_priv, "privileged") == 0) {
		priv = RCPRIV_PRIVILEGED;
	} else {
		/* Invalid privilege */
		return (Z_INVAL);
	}

	/* deal with negative input; strtoull(3c) doesn't do what we want */
	if (rctlval->zone_rctlval_limit[0] == '-')
		return (Z_INVAL);
	/* Get the limit */
	errno = 0;
	ull = strtoull(rctlval->zone_rctlval_limit, &endp, 0);
	if (errno != 0 || *endp != '\0') {
		/* parse failed */
		return (Z_INVAL);
	}
	limit = (rctl_qty_t)ull;

	/* Get the action */
	if (strcmp(rctlval->zone_rctlval_action, "none") == 0) {
		action = RCTL_LOCAL_NOACTION;
	} else if (strcmp(rctlval->zone_rctlval_action, "signal") == 0) {
		action = RCTL_LOCAL_SIGNAL;
	} else if (strcmp(rctlval->zone_rctlval_action, "deny") == 0) {
		action = RCTL_LOCAL_DENY;
	} else {
		/* Invalid Action */
		return (Z_INVAL);
	}
	rctlblk_set_local_action(rctlblk, action, 0);
	rctlblk_set_privilege(rctlblk, priv);
	rctlblk_set_value(rctlblk, limit);
	return (Z_OK);
}

static int
rctl_check(const char *rctlname, void *arg)
{
	const char *attrname = arg;

	/*
	 * Returning 1 here is our signal to zonecfg_is_rctl() that it is
	 * indeed an rctl name recognized by the system.
	 */
	return (strcmp(rctlname, attrname) == 0 ? 1 : 0);
}

boolean_t
zonecfg_is_rctl(const char *name)
{
	return (rctl_walk(rctl_check, (void *)name) == 1);
}

boolean_t
zonecfg_valid_rctlname(const char *name)
{
	const char *c;

	if (strncmp(name, "zone.", sizeof ("zone.") - 1) != 0)
		return (B_FALSE);
	if (strlen(name) == sizeof ("zone.") - 1)
		return (B_FALSE);
	for (c = name + sizeof ("zone.") - 1; *c != '\0'; c++) {
		if (!isalpha(*c) && *c != '-')
			return (B_FALSE);
	}
	return (B_TRUE);
}

boolean_t
zonecfg_valid_rctlblk(const rctlblk_t *rctlblk)
{
	rctl_priv_t priv = rctlblk_get_privilege((rctlblk_t *)rctlblk);
	uint_t action = rctlblk_get_local_action((rctlblk_t *)rctlblk, NULL);

	if (priv != RCPRIV_PRIVILEGED)
		return (B_FALSE);
	if (action != RCTL_LOCAL_NOACTION && action != RCTL_LOCAL_DENY)
		return (B_FALSE);
	return (B_TRUE);
}

boolean_t
zonecfg_valid_rctl(const char *name, const rctlblk_t *rctlblk)
{
	rctlblk_t *current, *next;
	rctl_qty_t limit = rctlblk_get_value((rctlblk_t *)rctlblk);
	uint_t action = rctlblk_get_local_action((rctlblk_t *)rctlblk, NULL);
	uint_t global_flags;

	if (!zonecfg_valid_rctlblk(rctlblk))
		return (B_FALSE);
	if (!zonecfg_valid_rctlname(name))
		return (B_FALSE);

	current = alloca(rctlblk_size());
	if (getrctl(name, NULL, current, RCTL_FIRST) != 0)
		return (B_TRUE);	/* not an rctl on this system */
	/*
	 * Make sure the proposed value isn't greater than the current system
	 * value.
	 */
	next = alloca(rctlblk_size());
	while (rctlblk_get_privilege(current) != RCPRIV_SYSTEM) {
		rctlblk_t *tmp;

		if (getrctl(name, current, next, RCTL_NEXT) != 0)
			return (B_FALSE);	/* shouldn't happen */
		tmp = current;
		current = next;
		next = tmp;
	}
	if (limit > rctlblk_get_value(current))
		return (B_FALSE);

	/*
	 * Make sure the proposed action is allowed.
	 */
	global_flags = rctlblk_get_global_flags(current);
	if ((global_flags & RCTL_GLOBAL_DENY_NEVER) &&
	    action == RCTL_LOCAL_DENY)
		return (B_FALSE);
	if ((global_flags & RCTL_GLOBAL_DENY_ALWAYS) &&
	    action == RCTL_LOCAL_NOACTION)
		return (B_FALSE);

	return (B_TRUE);
}

/*
 * There is always a race condition between reading the initial copy of
 * a zones state and its state changing.  We address this by providing
 * zonecfg_notify_critical_enter and zonecfg_noticy_critical_exit functions.
 * When zonecfg_critical_enter is called, sets the state field to LOCKED
 * and aquires biglock. Biglock protects against other threads executing
 * critical_enter and the state field protects against state changes during
 * the critical period.
 *
 * If any state changes occur, zn_cb will set the failed field of the znotify
 * structure.  This will cause the critical_exit function to re-lock the
 * channel and return an error. Since evsnts may be delayed, the critical_exit
 * function "flushes" the queue by putting an event on the queue and waiting for
 * zn_cb to notify critical_exit that it received the ping event.
 */
static const char *
string_get_tok(const char *in, char delim, int num)
{
	int i = 0;

	for (; i < num; in++) {
		if (*in == delim)
			i++;
		if (*in == 0)
			return (NULL);
	}
	return (in);
}

static boolean_t
is_ping(sysevent_t *ev)
{
	if (strcmp(sysevent_get_subclass_name(ev),
	    ZONE_EVENT_PING_SUBCLASS) == 0) {
		return (B_TRUE);
	} else {
		return (B_FALSE);
	}
}

static boolean_t
is_my_ping(sysevent_t *ev)
{
	const char *sender;
	char mypid[sizeof (pid_t) * 3 + 1];

	(void) snprintf(mypid, sizeof (mypid), "%i", getpid());
	sender = string_get_tok(sysevent_get_pub(ev), ':', 3);
	if (sender == NULL)
		return (B_FALSE);
	if (strcmp(sender, mypid) != 0)
		return (B_FALSE);
	return (B_TRUE);
}

static int
do_callback(struct znotify *zevtchan, sysevent_t *ev)
{
	nvlist_t *l;
	int zid;
	char *zonename;
	char *newstate;
	char *oldstate;
	int ret;
	hrtime_t when;

	if (strcmp(sysevent_get_subclass_name(ev),
	    ZONE_EVENT_STATUS_SUBCLASS) == 0) {

		if (sysevent_get_attr_list(ev, &l) != 0) {
			if (errno == ENOMEM) {
				zevtchan->zn_failure_count++;
				return (EAGAIN);
			}
			return (0);
		}
		ret = 0;

		if ((nvlist_lookup_string(l, ZONE_CB_NAME, &zonename) == 0) &&
		    (nvlist_lookup_string(l, ZONE_CB_NEWSTATE, &newstate)
		    == 0) &&
		    (nvlist_lookup_string(l, ZONE_CB_OLDSTATE, &oldstate)
		    == 0) &&
		    (nvlist_lookup_uint64(l, ZONE_CB_TIMESTAMP,
		    (uint64_t *)&when) == 0) &&
		    (nvlist_lookup_int32(l, ZONE_CB_ZONEID, &zid) == 0)) {
			ret = zevtchan->zn_callback(zonename, zid, newstate,
			    oldstate, when, zevtchan->zn_private);
		}

		zevtchan->zn_failure_count = 0;
		nvlist_free(l);
		return (ret);
	} else {
		/*
		 * We have received an event in an unknown subclass. Ignore.
		 */
		zevtchan->zn_failure_count = 0;
		return (0);
	}
}

static int
zn_cb(sysevent_t *ev, void *p)
{
	struct znotify *zevtchan = p;
	int error;

	(void) pthread_mutex_lock(&(zevtchan->zn_mutex));

	if (is_ping(ev) && !is_my_ping(ev)) {
		(void) pthread_mutex_unlock((&zevtchan->zn_mutex));
		return (0);
	}

	if (zevtchan->zn_state == ZN_LOCKED) {
		assert(!is_ping(ev));
		zevtchan->zn_failed = B_TRUE;
		(void) pthread_mutex_unlock(&(zevtchan->zn_mutex));
		return (0);
	}

	if (zevtchan->zn_state == ZN_PING_INFLIGHT) {
		if (is_ping(ev)) {
			zevtchan->zn_state = ZN_PING_RECEIVED;
			(void) pthread_cond_signal(&(zevtchan->zn_cond));
			(void) pthread_mutex_unlock(&(zevtchan->zn_mutex));
			return (0);
		} else {
			zevtchan->zn_failed = B_TRUE;
			(void) pthread_mutex_unlock(&(zevtchan->zn_mutex));
			return (0);
		}
	}

	if (zevtchan->zn_state == ZN_UNLOCKED) {

		error = do_callback(zevtchan, ev);
		(void) pthread_mutex_unlock(&(zevtchan->zn_mutex));
		/*
		 * Every ENOMEM failure causes do_callback to increment
		 * zn_failure_count and every success causes it to
		 * set zn_failure_count to zero.  If we got EAGAIN,
		 * we will sleep for zn_failure_count seconds and return
		 * EAGAIN to gpec to try again.
		 *
		 * After 55 seconds, or 10 try's we give up and drop the
		 * event.
		 */
		if (error == EAGAIN) {
			if (zevtchan->zn_failure_count > ZONE_CB_RETRY_COUNT) {
				return (0);
			}
			(void) sleep(zevtchan->zn_failure_count);
		}
		return (error);
	}

	if (zevtchan->zn_state == ZN_PING_RECEIVED) {
		(void) pthread_mutex_unlock(&(zevtchan->zn_mutex));
		return (0);
	}

	abort();
	return (0);
}

void
zonecfg_notify_critical_enter(void *h)
{
	struct znotify *zevtchan = h;

	(void) pthread_mutex_lock(&(zevtchan->zn_bigmutex));
	zevtchan->zn_state = ZN_LOCKED;
}

int
zonecfg_notify_critical_exit(void * h)
{

	struct znotify *zevtchan = h;

	if (zevtchan->zn_state == ZN_UNLOCKED)
		return (0);

	(void) pthread_mutex_lock(&(zevtchan->zn_mutex));
	zevtchan->zn_state = ZN_PING_INFLIGHT;

	(void) sysevent_evc_publish(zevtchan->zn_eventchan,
	    ZONE_EVENT_STATUS_CLASS,
	    ZONE_EVENT_PING_SUBCLASS, ZONE_EVENT_PING_PUBLISHER,
	    zevtchan->zn_subscriber_id, NULL, EVCH_SLEEP);

	while (zevtchan->zn_state != ZN_PING_RECEIVED) {
		(void) pthread_cond_wait(&(zevtchan->zn_cond),
		    &(zevtchan->zn_mutex));
	}

	if (zevtchan->zn_failed == B_TRUE) {
		zevtchan->zn_state = ZN_LOCKED;
		zevtchan->zn_failed = B_FALSE;
		(void) pthread_mutex_unlock(&(zevtchan->zn_mutex));
		return (1);
	}

	zevtchan->zn_state = ZN_UNLOCKED;
	(void) pthread_mutex_unlock(&(zevtchan->zn_mutex));
	(void) pthread_mutex_unlock(&(zevtchan->zn_bigmutex));
	return (0);
}

void
zonecfg_notify_critical_abort(void *h)
{
	struct znotify *zevtchan = h;

	zevtchan->zn_state = ZN_UNLOCKED;
	zevtchan->zn_failed = B_FALSE;
	/*
	 * Don't do anything about zn_lock. If it is held, it could only be
	 * held by zn_cb and it will be unlocked soon.
	 */
	(void) pthread_mutex_unlock(&(zevtchan->zn_bigmutex));
}

void *
zonecfg_notify_bind(int(*func)(const char *zonename, zoneid_t zid,
    const char *newstate, const char *oldstate, hrtime_t when, void *p),
    void *p)
{
	struct znotify *zevtchan;
	int i = 1;
	int r;

	zevtchan = malloc(sizeof (struct znotify));

	if (zevtchan == NULL)
		return (NULL);

	zevtchan->zn_private = p;
	zevtchan->zn_callback = func;
	zevtchan->zn_state = ZN_UNLOCKED;
	zevtchan->zn_failed = B_FALSE;

	if (pthread_mutex_init(&(zevtchan->zn_mutex), NULL))
		goto out3;
	if (pthread_cond_init(&(zevtchan->zn_cond), NULL)) {
		(void) pthread_mutex_destroy(&(zevtchan->zn_mutex));
		goto out3;
	}
	if (pthread_mutex_init(&(zevtchan->zn_bigmutex), NULL)) {
		(void) pthread_mutex_destroy(&(zevtchan->zn_mutex));
		(void) pthread_cond_destroy(&(zevtchan->zn_cond));
		goto out3;
	}

	if (sysevent_evc_bind(ZONE_EVENT_CHANNEL, &(zevtchan->zn_eventchan),
	    0) != 0)
		goto out2;

	do {
		/*
		 * At 4 digits the subscriber ID gets too long and we have
		 * no chance of successfully registering.
		 */
		if (i > 999)
			goto out1;

		(void) sprintf(zevtchan->zn_subscriber_id, "zone_%li_%i",
		    getpid() % 999999l, i);

		r = sysevent_evc_subscribe(zevtchan->zn_eventchan,
		    zevtchan->zn_subscriber_id, ZONE_EVENT_STATUS_CLASS, zn_cb,
		    zevtchan, 0);

		i++;

	} while (r);

	return (zevtchan);
out1:
	sysevent_evc_unbind(zevtchan->zn_eventchan);
out2:
	(void) pthread_mutex_destroy(&zevtchan->zn_mutex);
	(void) pthread_cond_destroy(&zevtchan->zn_cond);
	(void) pthread_mutex_destroy(&(zevtchan->zn_bigmutex));
out3:
	free(zevtchan);

	return (NULL);
}

void
zonecfg_notify_unbind(void *handle)
{

	int ret;

	sysevent_evc_unbind(((struct znotify *)handle)->zn_eventchan);
	/*
	 * Check that all evc threads have gone away. This should be
	 * enforced by sysevent_evc_unbind.
	 */
	ret = pthread_mutex_trylock(&((struct znotify *)handle)->zn_mutex);

	if (ret)
		abort();

	(void) pthread_mutex_unlock(&((struct znotify *)handle)->zn_mutex);
	(void) pthread_mutex_destroy(&((struct znotify *)handle)->zn_mutex);
	(void) pthread_cond_destroy(&((struct znotify *)handle)->zn_cond);
	(void) pthread_mutex_destroy(&((struct znotify *)handle)->zn_bigmutex);

	free(handle);
}

static int
zonecfg_add_ds_core(zone_dochandle_t handle, struct zone_dstab *tabptr)
{
	xmlNodePtr newnode, cur = handle->zone_dh_cur;
	int err;

	newnode = xmlNewTextChild(cur, NULL, DTD_ELEM_DATASET, NULL);
	if ((err = newprop(newnode, DTD_ATTR_NAME,
	    tabptr->zone_dataset_name)) != Z_OK)
		return (err);
	return (Z_OK);
}

int
zonecfg_add_ds(zone_dochandle_t handle, struct zone_dstab *tabptr)
{
	int err;

	if (tabptr == NULL)
		return (Z_INVAL);

	if ((err = operation_prep(handle)) != Z_OK)
		return (err);

	if ((err = zonecfg_add_ds_core(handle, tabptr)) != Z_OK)
		return (err);

	return (Z_OK);
}

static int
zonecfg_delete_ds_core(zone_dochandle_t handle, struct zone_dstab *tabptr)
{
	xmlNodePtr cur = handle->zone_dh_cur;

	for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next) {
		if (xmlStrcmp(cur->name, DTD_ELEM_DATASET))
			continue;

		if (match_prop(cur, DTD_ATTR_NAME,
		    tabptr->zone_dataset_name)) {
			xmlUnlinkNode(cur);
			xmlFreeNode(cur);
			return (Z_OK);
		}
	}
	return (Z_NO_RESOURCE_ID);
}

int
zonecfg_delete_ds(zone_dochandle_t handle, struct zone_dstab *tabptr)
{
	int err;

	if (tabptr == NULL)
		return (Z_INVAL);

	if ((err = operation_prep(handle)) != Z_OK)
		return (err);

	if ((err = zonecfg_delete_ds_core(handle, tabptr)) != Z_OK)
		return (err);

	return (Z_OK);
}

int
zonecfg_modify_ds(
	zone_dochandle_t handle,
	struct zone_dstab *oldtabptr,
	struct zone_dstab *newtabptr)
{
	int err;

	if (oldtabptr == NULL || newtabptr == NULL)
		return (Z_INVAL);

	if ((err = operation_prep(handle)) != Z_OK)
		return (err);

	if ((err = zonecfg_delete_ds_core(handle, oldtabptr)) != Z_OK)
		return (err);

	if ((err = zonecfg_add_ds_core(handle, newtabptr)) != Z_OK)
		return (err);

	return (Z_OK);
}

int
zonecfg_lookup_ds(zone_dochandle_t handle, struct zone_dstab *tabptr)
{
	xmlNodePtr cur, firstmatch;
	int err;
	char dataset[MAXNAMELEN];

	if (tabptr == NULL)
		return (Z_INVAL);

	if ((err = operation_prep(handle)) != Z_OK)
		return (err);

	cur = handle->zone_dh_cur;
	firstmatch = NULL;
	for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next) {
		if (xmlStrcmp(cur->name, DTD_ELEM_DATASET))
			continue;
		if (strlen(tabptr->zone_dataset_name) > 0) {
			if ((fetchprop(cur, DTD_ATTR_NAME, dataset,
			    sizeof (dataset)) == Z_OK) &&
			    (strcmp(tabptr->zone_dataset_name,
			    dataset) == 0)) {
				if (firstmatch == NULL)
					firstmatch = cur;
				else
					return (Z_INSUFFICIENT_SPEC);
			}
		}
	}
	if (firstmatch == NULL)
		return (Z_NO_RESOURCE_ID);

	cur = firstmatch;

	if ((err = fetchprop(cur, DTD_ATTR_NAME, tabptr->zone_dataset_name,
	    sizeof (tabptr->zone_dataset_name))) != Z_OK)
		return (err);

	return (Z_OK);
}

int
zonecfg_setdsent(zone_dochandle_t handle)
{
	return (zonecfg_setent(handle));
}

int
zonecfg_getdsent(zone_dochandle_t handle, struct zone_dstab *tabptr)
{
	xmlNodePtr cur;
	int err;

	if (handle == NULL)
		return (Z_INVAL);

	if ((cur = handle->zone_dh_cur) == NULL)
		return (Z_NO_ENTRY);

	for (; cur != NULL; cur = cur->next)
		if (!xmlStrcmp(cur->name, DTD_ELEM_DATASET))
			break;
	if (cur == NULL) {
		handle->zone_dh_cur = handle->zone_dh_top;
		return (Z_NO_ENTRY);
	}

	if ((err = fetchprop(cur, DTD_ATTR_NAME, tabptr->zone_dataset_name,
	    sizeof (tabptr->zone_dataset_name))) != Z_OK) {
		handle->zone_dh_cur = handle->zone_dh_top;
		return (err);
	}

	handle->zone_dh_cur = cur->next;
	return (Z_OK);
}

int
zonecfg_enddsent(zone_dochandle_t handle)
{
	return (zonecfg_endent(handle));
}

/*
 * Support for aliased rctls; that is, rctls that have simplified names in
 * zonecfg.  For example, max-lwps is an alias for a well defined zone.max-lwps
 * rctl.  If there are multiple existing values for one of these rctls or if
 * there is a single value that does not match the well defined template (i.e.
 * it has a different action) then we cannot treat the rctl as having an alias
 * so we return Z_ALIAS_DISALLOW.  That means that the rctl cannot be
 * managed in zonecfg via an alias and that the standard rctl syntax must be
 * used.
 *
 * The possible return values are:
 *	Z_NO_PROPERTY_ID - invalid alias name
 *	Z_ALIAS_DISALLOW - pre-existing, incompatible rctl definition
 *	Z_NO_ENTRY - no rctl is configured for this alias
 *	Z_OK - we got a valid rctl for the specified alias
 */
int
zonecfg_get_aliased_rctl(zone_dochandle_t handle, char *name, uint64_t *rval)
{
	boolean_t found = B_FALSE;
	boolean_t found_val = B_FALSE;
	xmlNodePtr cur, val;
	char savedname[MAXNAMELEN];
	struct zone_rctlvaltab rctl;
	int i;
	int err;

	for (i = 0; aliases[i].shortname != NULL; i++)
		if (strcmp(name, aliases[i].shortname) == 0)
			break;

	if (aliases[i].shortname == NULL)
		return (Z_NO_PROPERTY_ID);

	if ((err = operation_prep(handle)) != Z_OK)
		return (err);

	cur = handle->zone_dh_cur;
	for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next) {
		if (xmlStrcmp(cur->name, DTD_ELEM_RCTL) != 0)
			continue;
		if ((fetchprop(cur, DTD_ATTR_NAME, savedname,
		    sizeof (savedname)) == Z_OK) &&
		    (strcmp(savedname, aliases[i].realname) == 0)) {

			/*
			 * If we already saw one of these, we can't have an
			 * alias since we just found another.
			 */
			if (found)
				return (Z_ALIAS_DISALLOW);
			found = B_TRUE;

			for (val = cur->xmlChildrenNode; val != NULL;
			    val = val->next) {
				/*
				 * If we already have one value, we can't have
				 * an alias since we just found another.
				 */
				if (found_val)
					return (Z_ALIAS_DISALLOW);
				found_val = B_TRUE;

				if ((fetchprop(val, DTD_ATTR_PRIV,
				    rctl.zone_rctlval_priv,
				    sizeof (rctl.zone_rctlval_priv)) != Z_OK))
					break;
				if ((fetchprop(val, DTD_ATTR_LIMIT,
				    rctl.zone_rctlval_limit,
				    sizeof (rctl.zone_rctlval_limit)) != Z_OK))
					break;
				if ((fetchprop(val, DTD_ATTR_ACTION,
				    rctl.zone_rctlval_action,
				    sizeof (rctl.zone_rctlval_action)) != Z_OK))
					break;
			}

			/* check priv and action match the expected vals */
			if (strcmp(rctl.zone_rctlval_priv,
			    aliases[i].priv) != 0 ||
			    strcmp(rctl.zone_rctlval_action,
			    aliases[i].action) != 0)
				return (Z_ALIAS_DISALLOW);
		}
	}

	if (found) {
		*rval = strtoull(rctl.zone_rctlval_limit, NULL, 10);
		return (Z_OK);
	}

	return (Z_NO_ENTRY);
}

int
zonecfg_rm_aliased_rctl(zone_dochandle_t handle, char *name)
{
	int i;
	uint64_t val;
	struct zone_rctltab rctltab;

	/*
	 * First check that we have a valid aliased rctl to remove.
	 * This will catch an rctl entry with non-standard values or
	 * multiple rctl values for this name.  We need to ignore those
	 * rctl entries.
	 */
	if (zonecfg_get_aliased_rctl(handle, name, &val) != Z_OK)
		return (Z_OK);

	for (i = 0; aliases[i].shortname != NULL; i++)
		if (strcmp(name, aliases[i].shortname) == 0)
			break;

	if (aliases[i].shortname == NULL)
		return (Z_NO_RESOURCE_ID);

	(void) strlcpy(rctltab.zone_rctl_name, aliases[i].realname,
	    sizeof (rctltab.zone_rctl_name));

	return (zonecfg_delete_rctl(handle, &rctltab));
}

boolean_t
zonecfg_aliased_rctl_ok(zone_dochandle_t handle, char *name)
{
	uint64_t tmp_val;

	switch (zonecfg_get_aliased_rctl(handle, name, &tmp_val)) {
	case Z_OK:
		/*FALLTHRU*/
	case Z_NO_ENTRY:
		return (B_TRUE);
	default:
		return (B_FALSE);
	}
}

int
zonecfg_set_aliased_rctl(zone_dochandle_t handle, char *name, uint64_t val)
{
	int i;
	int err;
	struct zone_rctltab rctltab;
	struct zone_rctlvaltab *rctlvaltab;
	char buf[128];

	if (!zonecfg_aliased_rctl_ok(handle, name))
		return (Z_ALIAS_DISALLOW);

	for (i = 0; aliases[i].shortname != NULL; i++)
		if (strcmp(name, aliases[i].shortname) == 0)
			break;

	if (aliases[i].shortname == NULL)
		return (Z_NO_RESOURCE_ID);

	/* remove any pre-existing definition for this rctl */
	(void) zonecfg_rm_aliased_rctl(handle, name);

	(void) strlcpy(rctltab.zone_rctl_name, aliases[i].realname,
	    sizeof (rctltab.zone_rctl_name));

	rctltab.zone_rctl_valptr = NULL;

	if ((rctlvaltab = calloc(1, sizeof (struct zone_rctlvaltab))) == NULL)
		return (Z_NOMEM);

	(void) snprintf(buf, sizeof (buf), "%llu", (long long)val);

	(void) strlcpy(rctlvaltab->zone_rctlval_priv, aliases[i].priv,
	    sizeof (rctlvaltab->zone_rctlval_priv));
	(void) strlcpy(rctlvaltab->zone_rctlval_limit, buf,
	    sizeof (rctlvaltab->zone_rctlval_limit));
	(void) strlcpy(rctlvaltab->zone_rctlval_action, aliases[i].action,
	    sizeof (rctlvaltab->zone_rctlval_action));

	rctlvaltab->zone_rctlval_next = NULL;

	if ((err = zonecfg_add_rctl_value(&rctltab, rctlvaltab)) != Z_OK)
		return (err);

	return (zonecfg_add_rctl(handle, &rctltab));
}

static int
delete_tmp_pool(zone_dochandle_t handle)
{
	int err;
	xmlNodePtr cur = handle->zone_dh_cur;

	if ((err = operation_prep(handle)) != Z_OK)
		return (err);

	for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next) {
		if (xmlStrcmp(cur->name, DTD_ELEM_TMPPOOL) == 0) {
			xmlUnlinkNode(cur);
			xmlFreeNode(cur);
			return (Z_OK);
		}
	}

	return (Z_NO_RESOURCE_ID);
}

static int
modify_tmp_pool(zone_dochandle_t handle, char *pool_importance)
{
	int err;
	xmlNodePtr cur = handle->zone_dh_cur;
	xmlNodePtr newnode;

	err = delete_tmp_pool(handle);
	if (err != Z_OK && err != Z_NO_RESOURCE_ID)
		return (err);

	if (*pool_importance != '\0') {
		if ((err = operation_prep(handle)) != Z_OK)
			return (err);

		newnode = xmlNewTextChild(cur, NULL, DTD_ELEM_TMPPOOL, NULL);
		if ((err = newprop(newnode, DTD_ATTR_IMPORTANCE,
		    pool_importance)) != Z_OK)
			return (err);
	}

	return (Z_OK);
}

static int
add_pset_core(zone_dochandle_t handle, struct zone_psettab *tabptr)
{
	xmlNodePtr newnode, cur = handle->zone_dh_cur;
	int err;

	newnode = xmlNewTextChild(cur, NULL, DTD_ELEM_PSET, NULL);
	if ((err = newprop(newnode, DTD_ATTR_NCPU_MIN,
	    tabptr->zone_ncpu_min)) != Z_OK)
		return (err);
	if ((err = newprop(newnode, DTD_ATTR_NCPU_MAX,
	    tabptr->zone_ncpu_max)) != Z_OK)
		return (err);

	if ((err = modify_tmp_pool(handle, tabptr->zone_importance)) != Z_OK)
		return (err);

	return (Z_OK);
}

int
zonecfg_add_pset(zone_dochandle_t handle, struct zone_psettab *tabptr)
{
	int err;

	if (tabptr == NULL)
		return (Z_INVAL);

	if ((err = operation_prep(handle)) != Z_OK)
		return (err);

	if ((err = add_pset_core(handle, tabptr)) != Z_OK)
		return (err);

	return (Z_OK);
}

int
zonecfg_delete_pset(zone_dochandle_t handle)
{
	int err;
	int res = Z_NO_RESOURCE_ID;
	xmlNodePtr cur = handle->zone_dh_cur;

	if ((err = operation_prep(handle)) != Z_OK)
		return (err);

	for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next) {
		if (xmlStrcmp(cur->name, DTD_ELEM_PSET) == 0) {
			xmlUnlinkNode(cur);
			xmlFreeNode(cur);
			res = Z_OK;
			break;
		}
	}

	/*
	 * Once we have msets, we should check that a mset
	 * do not exist before we delete the tmp_pool data.
	 */
	err = delete_tmp_pool(handle);
	if (err != Z_OK && err != Z_NO_RESOURCE_ID)
		return (err);

	return (res);
}

int
zonecfg_modify_pset(zone_dochandle_t handle, struct zone_psettab *tabptr)
{
	int err;

	if (tabptr == NULL)
		return (Z_INVAL);

	if ((err = zonecfg_delete_pset(handle)) != Z_OK)
		return (err);

	if ((err = add_pset_core(handle, tabptr)) != Z_OK)
		return (err);

	return (Z_OK);
}

int
zonecfg_lookup_pset(zone_dochandle_t handle, struct zone_psettab *tabptr)
{
	xmlNodePtr cur;
	int err;
	int res = Z_NO_ENTRY;

	if (tabptr == NULL)
		return (Z_INVAL);

	if ((err = operation_prep(handle)) != Z_OK)
		return (err);

	/* this is an optional component */
	tabptr->zone_importance[0] = '\0';

	cur = handle->zone_dh_cur;
	for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next) {
		if (xmlStrcmp(cur->name, DTD_ELEM_PSET) == 0) {
			if ((err = fetchprop(cur, DTD_ATTR_NCPU_MIN,
			    tabptr->zone_ncpu_min,
			    sizeof (tabptr->zone_ncpu_min))) != Z_OK) {
				handle->zone_dh_cur = handle->zone_dh_top;
				return (err);
			}

			if ((err = fetchprop(cur, DTD_ATTR_NCPU_MAX,
			    tabptr->zone_ncpu_max,
			    sizeof (tabptr->zone_ncpu_max))) != Z_OK) {
				handle->zone_dh_cur = handle->zone_dh_top;
				return (err);
			}

			res = Z_OK;

		} else if (xmlStrcmp(cur->name, DTD_ELEM_TMPPOOL) == 0) {
			if ((err = fetchprop(cur, DTD_ATTR_IMPORTANCE,
			    tabptr->zone_importance,
			    sizeof (tabptr->zone_importance))) != Z_OK) {
				handle->zone_dh_cur = handle->zone_dh_top;
				return (err);
			}
		}
	}

	return (res);
}

int
zonecfg_getpsetent(zone_dochandle_t handle, struct zone_psettab *tabptr)
{
	int err;

	if ((err = zonecfg_setent(handle)) != Z_OK)
		return (err);

	err = zonecfg_lookup_pset(handle, tabptr);

	(void) zonecfg_endent(handle);

	return (err);
}

static int
add_mcap(zone_dochandle_t handle, struct zone_mcaptab *tabptr)
{
	xmlNodePtr newnode, cur = handle->zone_dh_cur;
	int err;

	newnode = xmlNewTextChild(cur, NULL, DTD_ELEM_MCAP, NULL);
	if ((err = newprop(newnode, DTD_ATTR_PHYSCAP, tabptr->zone_physmem_cap))
	    != Z_OK)
		return (err);

	return (Z_OK);
}

int
zonecfg_delete_mcap(zone_dochandle_t handle)
{
	int err;
	xmlNodePtr cur = handle->zone_dh_cur;

	if ((err = operation_prep(handle)) != Z_OK)
		return (err);

	for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next) {
		if (xmlStrcmp(cur->name, DTD_ELEM_MCAP) != 0)
			continue;

		xmlUnlinkNode(cur);
		xmlFreeNode(cur);
		return (Z_OK);
	}
	return (Z_NO_RESOURCE_ID);
}

int
zonecfg_modify_mcap(zone_dochandle_t handle, struct zone_mcaptab *tabptr)
{
	int err;

	if (tabptr == NULL)
		return (Z_INVAL);

	err = zonecfg_delete_mcap(handle);
	/* it is ok if there is no mcap entry */
	if (err != Z_OK && err != Z_NO_RESOURCE_ID)
		return (err);

	if ((err = add_mcap(handle, tabptr)) != Z_OK)
		return (err);

	return (Z_OK);
}

int
zonecfg_lookup_mcap(zone_dochandle_t handle, struct zone_mcaptab *tabptr)
{
	xmlNodePtr cur;
	int err;

	if (tabptr == NULL)
		return (Z_INVAL);

	if ((err = operation_prep(handle)) != Z_OK)
		return (err);

	cur = handle->zone_dh_cur;
	for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next) {
		if (xmlStrcmp(cur->name, DTD_ELEM_MCAP) != 0)
			continue;
		if ((err = fetchprop(cur, DTD_ATTR_PHYSCAP,
		    tabptr->zone_physmem_cap,
		    sizeof (tabptr->zone_physmem_cap))) != Z_OK) {
			handle->zone_dh_cur = handle->zone_dh_top;
			return (err);
		}

		return (Z_OK);
	}

	return (Z_NO_ENTRY);
}

static int
getmcapent_core(zone_dochandle_t handle, struct zone_mcaptab *tabptr)
{
	xmlNodePtr cur;
	int err;

	if (handle == NULL)
		return (Z_INVAL);

	if ((cur = handle->zone_dh_cur) == NULL)
		return (Z_NO_ENTRY);

	for (; cur != NULL; cur = cur->next)
		if (xmlStrcmp(cur->name, DTD_ELEM_MCAP) == 0)
			break;
	if (cur == NULL) {
		handle->zone_dh_cur = handle->zone_dh_top;
		return (Z_NO_ENTRY);
	}

	if ((err = fetchprop(cur, DTD_ATTR_PHYSCAP, tabptr->zone_physmem_cap,
	    sizeof (tabptr->zone_physmem_cap))) != Z_OK) {
		handle->zone_dh_cur = handle->zone_dh_top;
		return (err);
	}

	handle->zone_dh_cur = cur->next;
	return (Z_OK);
}

int
zonecfg_getmcapent(zone_dochandle_t handle, struct zone_mcaptab *tabptr)
{
	int err;

	if ((err = zonecfg_setent(handle)) != Z_OK)
		return (err);

	err = getmcapent_core(handle, tabptr);

	(void) zonecfg_endent(handle);

	return (err);
}

/*
 * Get the full tree of pkg/patch metadata in a set of nested AVL trees.
 * pkgs_avl is an AVL tree of pkgs.  Each pkg element contains a
 * zpe_patches_avl member which holds an AVL tree of patches for that pkg.
 * The patch elements have the same zpe_patches_avl member, each of which can
 * hold an AVL tree of patches that are obsoleted by the patch.
 *
 * The zone xml data contains DTD_ELEM_PACKAGE elements, followed by
 * DTD_ELEM_PATCH elements.  The DTD_ELEM_PATCH patch element applies to the
 * DTD_ELEM_PACKAGE that precedes it.  The DTD_ELEM_PATCH element may have
 * child DTD_ELEM_OBSOLETES nodes associated with it.  The DTD_ELEM_PACKAGE
 * really should have had the DTD_ELEM_PATCH elements as children but it
 * was not defined that way initially so we are stuck with the DTD definition
 * now.  However, we can safely assume the ordering for compatibility.
 */
int
zonecfg_getpkgdata(zone_dochandle_t handle, uu_avl_pool_t *pkg_pool,
    uu_avl_t *pkgs_avl)
{
	xmlNodePtr cur;
	int res;
	zone_pkg_entry_t *pkg;
	char name[MAXNAMELEN];
	char version[ZONE_PKG_VERSMAX];

	if (handle == NULL)
		return (Z_INVAL);

	if ((res = zonecfg_setent(handle)) != Z_OK)
		return (res);

	if ((cur = handle->zone_dh_cur) == NULL) {
		res = Z_NO_ENTRY;
		goto done;
	}

	for (; cur != NULL; cur = cur->next) {
		if (xmlStrcmp(cur->name, DTD_ELEM_PACKAGE) == 0) {
			uu_avl_index_t where;

			if ((res = fetchprop(cur, DTD_ATTR_NAME, name,
			    sizeof (name))) != Z_OK)
				goto done;

			if ((res = fetchprop(cur, DTD_ATTR_VERSION, version,
			    sizeof (version))) != Z_OK)
				goto done;

			if ((pkg = (zone_pkg_entry_t *)
			    malloc(sizeof (zone_pkg_entry_t))) == NULL) {
				res = Z_NOMEM;
				goto done;
			}

			if ((pkg->zpe_name = strdup(name)) == NULL) {
				free(pkg);
				res = Z_NOMEM;
				goto done;
			}

			if ((pkg->zpe_vers = strdup(version)) == NULL) {
				free(pkg->zpe_name);
				free(pkg);
				res = Z_NOMEM;
				goto done;
			}

			pkg->zpe_patches_avl = NULL;

			uu_avl_node_init(pkg, &pkg->zpe_entry, pkg_pool);
			if (uu_avl_find(pkgs_avl, pkg, NULL, &where) != NULL) {
				free(pkg->zpe_name);
				free(pkg->zpe_vers);
				free(pkg);
			} else {
				uu_avl_insert(pkgs_avl, pkg, where);
			}

		} else if (xmlStrcmp(cur->name, DTD_ELEM_PATCH) == 0) {
			zone_pkg_entry_t *patch;
			uu_avl_index_t where;
			char *p;
			char *dashp = NULL;
			xmlNodePtr child;

			if ((res = fetchprop(cur, DTD_ATTR_ID, name,
			    sizeof (name))) != Z_OK)
				goto done;

			if ((patch = (zone_pkg_entry_t *)
			    malloc(sizeof (zone_pkg_entry_t))) == NULL) {
				res = Z_NOMEM;
				goto done;
			}

			if ((p = strchr(name, '-')) != NULL) {
				dashp = p;
				*p++ = '\0';
			} else {
				p = "";
			}

			if ((patch->zpe_name = strdup(name)) == NULL) {
				free(patch);
				res = Z_NOMEM;
				goto done;
			}

			if ((patch->zpe_vers = strdup(p)) == NULL) {
				free(patch->zpe_name);
				free(patch);
				res = Z_NOMEM;
				goto done;
			}

			if (dashp != NULL)
				*dashp = '-';

			patch->zpe_patches_avl = NULL;

			if (pkg->zpe_patches_avl == NULL) {
				pkg->zpe_patches_avl = uu_avl_create(pkg_pool,
				    NULL, UU_DEFAULT);
				if (pkg->zpe_patches_avl == NULL) {
					free(patch->zpe_name);
					free(patch->zpe_vers);
					free(patch);
					res = Z_NOMEM;
					goto done;
				}
			}

			uu_avl_node_init(patch, &patch->zpe_entry, pkg_pool);
			if (uu_avl_find(pkg->zpe_patches_avl, patch, NULL,
			    &where) != NULL) {
				free(patch->zpe_name);
				free(patch->zpe_vers);
				free(patch);
			} else {
				uu_avl_insert(pkg->zpe_patches_avl, patch,
				    where);
			}

			/* Add any patches this patch obsoletes. */
			for (child = cur->xmlChildrenNode; child != NULL;
			    child = child->next) {
				zone_pkg_entry_t *obs;

				if (xmlStrcmp(child->name, DTD_ELEM_OBSOLETES)
				    != 0)
					continue;

				if ((res = fetchprop(child, DTD_ATTR_ID,
				    name, sizeof (name))) != Z_OK)
					goto done;

				if ((obs = (zone_pkg_entry_t *)malloc(
				    sizeof (zone_pkg_entry_t))) == NULL) {
					res = Z_NOMEM;
					goto done;
				}

				if ((obs->zpe_name = strdup(name)) == NULL) {
					free(obs);
					res = Z_NOMEM;
					goto done;
				}
				/*
				 * The version doesn't matter for obsoleted
				 * patches.
				 */
				obs->zpe_vers = NULL;
				obs->zpe_patches_avl = NULL;

				/*
				 * If this is the first obsolete patch, add an
				 * AVL tree to the parent patch element.
				 */
				if (patch->zpe_patches_avl == NULL) {
					patch->zpe_patches_avl =
					    uu_avl_create(pkg_pool, NULL,
					    UU_DEFAULT);
					if (patch->zpe_patches_avl == NULL) {
						free(obs->zpe_name);
						free(obs);
						res = Z_NOMEM;
						goto done;
					}
				}

				/* Insert obsolete patch into the AVL tree. */
				uu_avl_node_init(obs, &obs->zpe_entry,
				    pkg_pool);
				if (uu_avl_find(patch->zpe_patches_avl, obs,
				    NULL, &where) != NULL) {
					free(obs->zpe_name);
					free(obs);
				} else {
					uu_avl_insert(patch->zpe_patches_avl,
					    obs, where);
				}
			}
		}
	}

done:
	(void) zonecfg_endent(handle);
	return (res);
}

int
zonecfg_setdevperment(zone_dochandle_t handle)
{
	return (zonecfg_setent(handle));
}

int
zonecfg_getdevperment(zone_dochandle_t handle, struct zone_devpermtab *tabptr)
{
	xmlNodePtr cur;
	int err;
	char buf[128];

	tabptr->zone_devperm_acl = NULL;

	if (handle == NULL)
		return (Z_INVAL);

	if ((cur = handle->zone_dh_cur) == NULL)
		return (Z_NO_ENTRY);

	for (; cur != NULL; cur = cur->next)
		if (!xmlStrcmp(cur->name, DTD_ELEM_DEV_PERM))
			break;
	if (cur == NULL) {
		handle->zone_dh_cur = handle->zone_dh_top;
		return (Z_NO_ENTRY);
	}

	if ((err = fetchprop(cur, DTD_ATTR_NAME, tabptr->zone_devperm_name,
	    sizeof (tabptr->zone_devperm_name))) != Z_OK) {
		handle->zone_dh_cur = handle->zone_dh_top;
		return (err);
	}

	if ((err = fetchprop(cur, DTD_ATTR_UID, buf, sizeof (buf))) != Z_OK) {
		handle->zone_dh_cur = handle->zone_dh_top;
		return (err);
	}
	tabptr->zone_devperm_uid = (uid_t)atol(buf);

	if ((err = fetchprop(cur, DTD_ATTR_GID, buf, sizeof (buf))) != Z_OK) {
		handle->zone_dh_cur = handle->zone_dh_top;
		return (err);
	}
	tabptr->zone_devperm_gid = (gid_t)atol(buf);

	if ((err = fetchprop(cur, DTD_ATTR_MODE, buf, sizeof (buf))) != Z_OK) {
		handle->zone_dh_cur = handle->zone_dh_top;
		return (err);
	}
	tabptr->zone_devperm_mode = (mode_t)strtol(buf, (char **)NULL, 8);

	if ((err = fetch_alloc_prop(cur, DTD_ATTR_ACL,
	    &(tabptr->zone_devperm_acl))) != Z_OK) {
		handle->zone_dh_cur = handle->zone_dh_top;
		return (err);
	}

	handle->zone_dh_cur = cur->next;
	return (Z_OK);
}

int
zonecfg_enddevperment(zone_dochandle_t handle)
{
	return (zonecfg_endent(handle));
}

/*
 * Maintain a space separated list of unique pkg names.  PATH_MAX is used in
 * the pkg code as the maximum size for a pkg name.
 */
static int
add_pkg_to_str(char **str, char *pkg)
{
	int len, newlen;
	char tstr[PATH_MAX + 3];
	char *tmp;

	len = strlen(pkg);
	if (*str == NULL) {
		/* space for str + 2 spaces + NULL */
		if ((*str = (char *)malloc(len + 3)) == NULL)
			return (Z_NOMEM);
		(void) snprintf(*str, len + 3, " %s ", pkg);
		return (Z_OK);
	}

	(void) snprintf(tstr, sizeof (tstr), " %s ", pkg);
	if (strstr(*str, tstr) != NULL)
		return (Z_OK);

	/* space for str + 1 space + NULL */
	newlen = strlen(*str) + len + 2;
	if ((tmp = (char *)realloc(*str, newlen)) == NULL)
		return (Z_NOMEM);
	*str = tmp;
	(void) strlcat(*str, pkg, newlen);
	(void) strlcat(*str, " ", newlen);
	return (Z_OK);
}

/*
 * Process a list of pkgs from an entry in the contents file, adding each pkg
 * name to the list of pkgs.
 *
 * It is possible for the pkg name to be preceeded by a special character
 * which indicates some bookkeeping information for pkging.  Check if the
 * first char is not an Alpha char.  If so, skip over it.
 */
static int
add_pkg_list(char *lastp, char ***plist, int *pcnt, char **pkg_warn)
{
	char	*p;
	int	pkg_cnt = *pcnt;
	char	**pkgs = *plist;
	int	res = Z_OK;

	while ((p = strtok_r(NULL, " ", &lastp)) != NULL) {
		char	**tmpp;
		int	i;

		/* skip over any special pkg bookkeeping char */
		if (!isalpha(*p)) {
			p++;
			if ((res = add_pkg_to_str(pkg_warn, p)) != Z_OK)
				break;
		}

		/* Check if the pkg is already in the list */
		for (i = 0; i < pkg_cnt; i++) {
			if (strcmp(p, pkgs[i]) == 0)
				break;
		}

		if (i < pkg_cnt)
			continue;

		/* The pkg is not in the list; add it. */
		if ((tmpp = (char **)realloc(pkgs,
		    sizeof (char *) * (pkg_cnt + 1))) == NULL) {
			res = Z_NOMEM;
			break;
		}
		pkgs = tmpp;

		if ((pkgs[pkg_cnt] = strdup(p)) == NULL) {
			res = Z_NOMEM;
			break;
		}
		pkg_cnt++;
	}

	*plist = pkgs;
	*pcnt = pkg_cnt;

	return (res);
}

/*
 * Process an entry from the contents file (type "directory").  If the
 * directory path is in the list of ipds and is not under a lofs mount within
 * the ipd then add the associated list of pkgs to the pkg list.  The input
 * parameter "entry" will be broken up by the parser within this function so
 * its value will be modified when this function exits.
 *
 * The entries we are looking for will look something like:
 *	/usr d none 0755 root sys SUNWctpls SUNWidnl SUNWlibCf ....
 */
static int
get_path_pkgs(char *entry, char **ipds, char **fss, char ***pkgs, int *pkg_cnt,
    char **pkg_warn)
{
	char	*f1;
	char	*f2;
	char	*lastp;
	int	i;
	char	*nlp;

	if ((f1 = strtok_r(entry, " ", &lastp)) == NULL ||
	    (f2 = strtok_r(NULL, " ", &lastp)) == NULL || strcmp(f2, "d") != 0)
		return (Z_OK);

	/* Check if this directory entry is in the list of ipds. */
	for (i = 0; ipds[i] != NULL; i++) {
		char wildcard[MAXPATHLEN];

		/*
		 * We want to match on the path and any other directory
		 * entries under this path.  When we use FNM_PATHNAME then
		 * that means '/' will not be matched by a wildcard (*) so
		 * we omit FNM_PATHNAME on the call with the wildcard matching.
		 */
		(void) snprintf(wildcard, sizeof (wildcard), "%s/*", ipds[i]);
		if (fnmatch(ipds[i], f1, FNM_PATHNAME) == 0 ||
		    fnmatch(wildcard, f1, 0) == 0) {
			/* It looks like we do want the pkgs for this path. */
			break;
		}
	}

	/* This entry did not match any of the ipds. */
	if (ipds[i] == NULL)
		return (Z_OK);

	/*
	 * Check if there is a fs mounted under the ipd.  If so, ignore this
	 * entry.
	 */
	for (i = 0; fss[i] != NULL; i++) {
		char wildcard[MAXPATHLEN];

		(void) snprintf(wildcard, sizeof (wildcard), "%s/*", fss[i]);
		if (fnmatch(fss[i], f1, FNM_PATHNAME) == 0 ||
		    fnmatch(wildcard, f1, 0) == 0) {
			/* We should ignore this path. */
			break;
		}
	}

	/* If not null, then we matched an fs mount point so ignore entry. */
	if (fss[i] != NULL)
		return (Z_OK);

	/*
	 * We do want the pkgs for this entry.  First, skip over the next 4
	 * fields in the entry so that we call add_pkg_list starting with the
	 * pkg names.
	 */
	for (i = 0; i < 4 && strtok_r(NULL, " ", &lastp) != NULL; i++)
		;
	/* If there are < 4 fields this entry is corrupt, just skip it. */
	if (i < 4)
		return (Z_OK);

	/* strip newline from the line */
	nlp = (lastp + strlen(lastp) - 1);
	if (*nlp == '\n')
		*nlp = '\0';

	return (add_pkg_list(lastp, pkgs, pkg_cnt, pkg_warn));
}

/*
 * Read an entry from a pkginfo or contents file.  Some of these lines can
 * either be arbitrarily long or be continued by a backslash at the end of
 * the line.  This function coalesces lines that are longer than the read
 * buffer, and lines that are continued, into one buffer which is returned.
 * The caller must free this memory.  NULL is returned when we hit EOF or
 * if we run out of memory (errno is set to ENOMEM).
 */
static char *
read_pkg_data(FILE *fp)
{
	char *start;
	char *inp;
	char *p;
	int char_cnt = 0;

	errno = 0;
	if ((start = (char *)malloc(PKGINFO_RD_LEN)) == NULL) {
		errno = ENOMEM;
		return (NULL);
	}

	inp = start;
	while ((p = fgets(inp, PKGINFO_RD_LEN, fp)) != NULL) {
		int len;

		len = strlen(inp);
		if (inp[len - 1] == '\n' &&
		    (len == 1 || inp[len - 2] != '\\')) {
			char_cnt = len;
			break;
		}

		if (inp[len - 2] == '\\')
			char_cnt += len - 2;
		else
			char_cnt += PKGINFO_RD_LEN - 1;

		if ((p = realloc(start, char_cnt + PKGINFO_RD_LEN)) == NULL) {
			errno = ENOMEM;
			break;
		}

		start = p;
		inp = start + char_cnt;
	}

	if (errno == ENOMEM || (p == NULL && char_cnt == 0)) {
		free(start);
		start = NULL;
	}

	return (start);
}

static void
free_ipd_pkgs(char **pkgs, int cnt)
{
	int i;

	for (i = 0; i < cnt; i++)
		free(pkgs[i]);
	free(pkgs);
}

/*
 * Get a list of the inherited pkg dirs or fs entries configured for the
 * zone.  The type parameter will be either ZONE_IPD or ZONE_FS.
 */
static int
get_ipd_fs_list(zone_dochandle_t handle, enum zn_ipd_fs type, char ***list)
{
	int	res;
	struct zone_fstab fstab;
	int	cnt = 0;
	char	**entries = NULL;
	int	i;
	int	(*fp)(zone_dochandle_t, struct zone_fstab *);

	if (type == ZONE_IPD) {
		fp = zonecfg_getipdent;
		res = zonecfg_setipdent(handle);
	} else {
		fp = zonecfg_getfsent;
		res = zonecfg_setfsent(handle);
	}

	if (res != Z_OK)
		return (res);

	while (fp(handle, &fstab) == Z_OK) {
		char	**p;

		if ((p = (char **)realloc(entries,
		    sizeof (char *) * (cnt + 1))) == NULL) {
			res = Z_NOMEM;
			break;
		}
		entries = p;

		if ((entries[cnt] = strdup(fstab.zone_fs_dir)) == NULL) {
			res = Z_NOMEM;
			break;
		}

		cnt++;
	}

	if (type == ZONE_IPD)
		(void) zonecfg_endipdent(handle);
	else
		(void) zonecfg_endfsent(handle);

	/* Add a NULL terminating element. */
	if (res == Z_OK) {
		char	**p;

		if ((p = (char **)realloc(entries,
		    sizeof (char *) * (cnt + 1))) == NULL) {
			res = Z_NOMEM;
		} else {
			entries = p;
			entries[cnt] = NULL;
		}
	}

	if (res != Z_OK) {
		if (entries != NULL) {
			for (i = 0; i < cnt; i++)
				free(entries[i]);
			free(entries);
		}
		return (res);
	}

	*list = entries;
	return (Z_OK);
}

/*
 * Get the list of inherited-pkg-dirs (ipd) for the zone and then get the
 * list of pkgs that deliver into those dirs.
 */
static int
get_ipd_pkgs(zone_dochandle_t handle, char ***pkg_list, int *cnt)
{
	int	res;
	char	**ipds;
	char	**fss;
	int	pkg_cnt = 0;
	char	**pkgs = NULL;
	int	i;

	if ((res = get_ipd_fs_list(handle, ZONE_IPD, &ipds)) != Z_OK)
		return (res);

	if ((res = get_ipd_fs_list(handle, ZONE_FS, &fss)) != Z_OK) {
		for (i = 0; ipds[i] != NULL; i++)
			free(ipds[i]);
		free(ipds);
		return (res);
	}

	/* We only have to process the contents file if we have ipds. */
	if (ipds != NULL) {
		FILE	*fp;

		if ((fp = fopen(CONTENTS_FILE, "r")) != NULL) {
			char	*buf;
			char	*pkg_warn = NULL;

			while ((buf = read_pkg_data(fp)) != NULL) {
				res = get_path_pkgs(buf, ipds, fss, &pkgs,
				    &pkg_cnt, &pkg_warn);
				free(buf);
				if (res != Z_OK)
					break;
			}

			(void) fclose(fp);

			if (pkg_warn != NULL) {
				(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
				    "WARNING: package operation in progress "
				    "on the following packages:\n   %s\n"),
				    pkg_warn);
				free(pkg_warn);
			}
		}
	}

	for (i = 0; ipds[i] != NULL; i++)
		free(ipds[i]);
	free(ipds);

	for (i = 0; fss[i] != NULL; i++)
		free(fss[i]);
	free(fss);

	if (res != Z_OK) {
		free_ipd_pkgs(pkgs, pkg_cnt);
	} else {
		*pkg_list = pkgs;
		*cnt = pkg_cnt;
	}

	return (res);
}

/*
 * Return true if pkg_name is in the list of pkgs that deliver into an
 * inherited pkg directory for the zone.
 */
static boolean_t
dir_pkg(char *pkg_name, char **pkg_list, int cnt)
{
	int i;

	for (i = 0; i < cnt; i++) {
		if (strcmp(pkg_name, pkg_list[i]) == 0)
			return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * Keep track of obsoleted patches for this specific patch.  We don't need to
 * keep track of the patch version since once a patch is obsoleted, all prior
 * versions are also obsolete and there won't be any new versions.
 */
static int
add_obs_patch(patch_node_t *patch, char *num, uu_list_pool_t *patches_pool)
{
	obs_patch_node_t *obs;

	if (patch->obs_patches == NULL) {
		if ((patch->obs_patches = uu_list_create(patches_pool, NULL,
		    0)) == NULL)
			return (Z_NOMEM);
	}

	if ((obs = (obs_patch_node_t *)malloc(sizeof (obs_patch_node_t)))
	    == NULL)
		return (Z_NOMEM);

	if ((obs->patch_num = strdup(num)) == NULL) {
		free(obs);
		return (Z_NOMEM);
	}

	uu_list_node_init(obs, &obs->link, patches_pool);
	(void) uu_list_insert_before(patch->obs_patches, NULL, obs);

	return (Z_OK);
}

/*
 * Keep track of obsoleted patches.  We don't need to keep track of the patch
 * version since once a patch is obsoleted, all prior versions are also
 * obsolete and there won't be any new versions.
 */
static int
save_obs_patch(char *num, uu_avl_pool_t *patches_pool, uu_avl_t *obs_patches)
{
	patch_node_t	*patch;
	uu_avl_index_t where;

	if ((patch = (patch_node_t *)malloc(sizeof (patch_node_t))) == NULL)
		return (Z_NOMEM);

	if ((patch->patch_num = strdup(num)) == NULL) {
		free(patch);
		return (Z_NOMEM);
	}

	patch->patch_vers = NULL;
	patch->obs_patches = NULL;

	uu_avl_node_init(patch, &patch->patch_node, patches_pool);

	if (uu_avl_find(obs_patches, patch, NULL, &where) != NULL) {
		free(patch->patch_num);
		free(patch);
		return (Z_OK);
	}

	uu_avl_insert(obs_patches, patch, where);
	return (Z_OK);
}

/*
 * Keep a list of patches for a pkg.  If we see a newer version of a patch,
 * we only keep track of the newer version.
 */
static void
save_patch(patch_node_t *patch, uu_avl_t *patches_avl)
{
	patch_node_t *existing;
	uu_avl_index_t where;

	/* Check if this is a newer version of a patch we already have. */
	if ((existing = (patch_node_t *)uu_avl_find(patches_avl, patch, NULL,
	    &where)) != NULL) {
		char *endptr;
		ulong_t pvers, evers;

		pvers = strtoul(patch->patch_vers, &endptr, 10);
		evers = strtoul(existing->patch_vers, &endptr, 10);

		if (pvers > evers) {
			free(existing->patch_vers);
			existing->patch_vers = patch->patch_vers;
			free(patch->patch_num);
			free(patch);
			return;
		}
	}

	uu_avl_insert(patches_avl, patch, where);
}

/*
 * Check if a patch is on the list of obsoleted patches.  We don't need to
 * check the patch version since once a patch is obsoleted, all prior versions
 * are also obsolete and there won't be any new versions.
 */
static boolean_t
obsolete_patch(patch_node_t *patch, uu_avl_t *obs_patches)
{
	uu_avl_index_t	where;

	if (uu_avl_find(obs_patches, patch, NULL, &where) != NULL)
		return (B_TRUE);

	return (B_FALSE);
}

/* ARGSUSED */
static int
patch_node_compare(const void *l_arg, const void *r_arg, void *private)
{
	patch_node_t *l = (patch_node_t *)l_arg;
	patch_node_t *r = (patch_node_t *)r_arg;
	char *endptr;
	ulong_t lnum, rnum;

	lnum = strtoul(l->patch_num, &endptr, 10);
	rnum = strtoul(r->patch_num, &endptr, 10);

	if (lnum > rnum)
		return (1);
	if (lnum < rnum)
		return (-1);
	return (0);
}

/*
 * Parse the patchinfo string for the patch.
 *
 * We are parsing entries of the form:
 * PATCH_INFO_121454-02=Installed: Wed Dec  7 07:13:51 PST 2005 From: mum \
 *	Obsoletes: 120777-03 121087-02 119108-07 Requires: 119575-02 \
 *	119255-06 Incompatibles:
 *
 * A backed out patch will have "backed out\n" as the status.  We should
 * skip these patches.  We also ignore any entries that seem to be
 * corrupted.  Obsolete patches are saved in the obs_patches parameter
 * AVL list.
 */
static int
parse_info(char *patchinfo, uu_avl_pool_t *patches_pool, uu_avl_t *patches_avl,
    uu_avl_t *obs_patches, uu_list_pool_t *list_pool)
{
	char		*p;
	char		*lastp;
	char		*ep;
	char		*pvers;
	boolean_t	add_info = B_FALSE;
	patch_node_t	*patch;

	if (strlen(patchinfo) < (sizeof (PATCHINFO) - 1))
		return (Z_OK);

	/* Skip over "PATCH_INFO_" to get the patch id. */
	p = patchinfo + sizeof (PATCHINFO) - 1;
	if ((ep = strchr(p, '=')) == NULL)
		return (Z_OK);

	*ep++ = '\0';

	/* Ignore all but installed patches. */
	if (strncmp(ep, "Installed:", 10) != 0)
		return (Z_OK);

	/* remove newline */
	lastp = (ep + strlen(ep) - 1);
	if (*lastp == '\n')
		*lastp = '\0';

	if ((patch = (patch_node_t *)malloc(sizeof (patch_node_t))) == NULL)
		return (Z_NOMEM);

	if ((pvers = strchr(p, '-')) != NULL)
		*pvers++ = '\0';
	else
		pvers = "";

	if ((patch->patch_num = strdup(p)) == NULL) {
		free(patch);
		return (Z_NOMEM);
	}
	if ((patch->patch_vers = strdup(pvers)) == NULL) {
		free(patch->patch_num);
		free(patch);
		return (Z_NOMEM);
	}
	patch->obs_patches = NULL;

	uu_avl_node_init(patch, &patch->patch_node, patches_pool);
	save_patch(patch, patches_avl);

	/*
	 * Start with the first token.  This will probably be "Installed:".
	 * If we can't tokenize this entry, just return.
	 */
	if ((p = strtok_r(ep, " ", &lastp)) == NULL)
		return (Z_OK);

	do {
		if (strcmp(p, "Installed:") == 0 ||
		    strcmp(p, "Requires:") == 0 ||
		    strcmp(p, "From:") == 0 ||
		    strcmp(p, "Incompatibles:") == 0) {
			add_info = B_FALSE;
			continue;
		} else if (strcmp(p, "Obsoletes:") == 0) {
			add_info = B_TRUE;
			continue;
		}

		if (!add_info)
			continue;

		if ((pvers = strchr(p, '-')) != NULL)
			*pvers = '\0';

		/*
		 * We save all of the obsolete patches in one big list in the
		 * obs_patches AVL tree so that we know not to output those as
		 * part of the sw dependencies.  However, we also need to save
		 * the obsolete patch information for this sepcific patch so
		 * so that we can do the cross manifest patch checking
		 * correctly.
		 */
		if (save_obs_patch(p, patches_pool, obs_patches) != Z_OK)
			return (Z_NOMEM);
		if (add_obs_patch(patch, p, list_pool) != Z_OK)
			return (Z_NOMEM);
	} while ((p = strtok_r(NULL, " ", &lastp)) != NULL);

	return (Z_OK);
}

/*
 * AVL walker callback used to add patch to XML manifest.
 *
 * PATH_MAX is used in the pkg/patch code as the maximum size for the patch
 * number/version string.
 */
static int
add_patch(void *e, void *p)
{
	xmlNodePtr	node;
	xmlNodePtr	cur;
	char		id[PATH_MAX];
	patch_node_t	*patch;
	patch_parms_t	*args;

	patch = e;
	args = p;

	/* skip this patch if it has been obsoleted */
	if (obsolete_patch(patch, args->obs_patches_avl))
		return (UU_WALK_NEXT);

	if (patch->patch_vers[0] == '\0')
		(void) snprintf(id, sizeof (id), "%s", patch->patch_num);
	else
		(void) snprintf(id, sizeof (id), "%s-%s", patch->patch_num,
		    patch->patch_vers);

	if ((args->res = operation_prep(args->handle)) != Z_OK)
		return (UU_WALK_DONE);

	cur = args->handle->zone_dh_cur;
	node = xmlNewTextChild(cur, NULL, DTD_ELEM_PATCH, NULL);
	if ((args->res = newprop(node, DTD_ATTR_ID, id)) != Z_OK)
		return (UU_WALK_DONE);

	if (patch->obs_patches != NULL) {
		obs_patch_node_t *op;
		xmlNodePtr	node2;

		for (op = uu_list_first(patch->obs_patches); op != NULL;
		    op = uu_list_next(patch->obs_patches, op)) {
			(void) snprintf(id, sizeof (id), "%s", op->patch_num);
			node2 = xmlNewTextChild(node, NULL, DTD_ELEM_OBSOLETES,
			    NULL);
			if ((args->res = newprop(node2, DTD_ATTR_ID, id))
			    != Z_OK)
				return (UU_WALK_DONE);
		}
	}

	return (UU_WALK_NEXT);
}

static void
patch_avl_delete(uu_avl_t *patches_avl)
{
	if (patches_avl != NULL) {
		patch_node_t *p;
		void *cookie = NULL;

		while ((p = (patch_node_t *)uu_avl_teardown(patches_avl,
		    &cookie)) != NULL) {
			free(p->patch_num);
			free(p->patch_vers);

			if (p->obs_patches != NULL) {
				obs_patch_node_t *op;
				void *cookie2 = NULL;

				while ((op = uu_list_teardown(p->obs_patches,
				    &cookie2)) != NULL) {
					free(op->patch_num);
					free(op);
				}
				uu_list_destroy(p->obs_patches);
			}

			free(p);
		}

		uu_avl_destroy(patches_avl);
	}
}

/*
 * Add the unique, highest version patches that are associated with this pkg
 * to the sw inventory on the handle.
 */
static int
add_patches(zone_dochandle_t handle, struct zone_pkginfo *infop,
    uu_avl_pool_t *patches_pool, uu_avl_t *obs_patches,
    uu_list_pool_t *list_pool)
{
	int		i;
	int		res;
	uu_avl_t 	*patches_avl;
	patch_parms_t	args;

	if ((patches_avl = uu_avl_create(patches_pool, NULL, UU_DEFAULT))
	    == NULL)
		return (Z_NOMEM);

	for (i = 0; i < infop->zpi_patch_cnt; i++) {
		if ((res = parse_info(infop->zpi_patchinfo[i], patches_pool,
		    patches_avl, obs_patches, list_pool)) != Z_OK) {
			patch_avl_delete(patches_avl);
			return (res);
		}
	}

	args.obs_patches_avl = obs_patches;
	args.handle = handle;
	args.res = Z_OK;

	(void) uu_avl_walk(patches_avl, add_patch, &args, 0);

	patch_avl_delete(patches_avl);
	return (args.res);
}

/*
 * Keep track of the pkgs we have already processed so that we can quickly
 * skip those pkgs while recursively doing dependents.
 */
static boolean_t
pkg_in_manifest(uu_avl_t *saw_pkgs, char *pname, uu_avl_pool_t *pkgs_pool)
{
	uu_avl_index_t where;

	if (uu_avl_find(saw_pkgs, pname, NULL, &where) == NULL) {
		zone_pkg_entry_t *pkg;

		/*
		 * We need to add it.  If we don't have memory we just skip
		 * this pkg since this routine improves performance but the
		 * algorithm is still correct without it.
		 */
		if ((pkg = (zone_pkg_entry_t *)
		    malloc(sizeof (zone_pkg_entry_t))) == NULL)
			return (B_FALSE);

		if ((pkg->zpe_name = strdup(pname)) == NULL) {
			free(pkg);
			return (B_FALSE);
		}

		pkg->zpe_vers = NULL;
		pkg->zpe_patches_avl = NULL;

		/* Insert pkg into the AVL tree. */
		uu_avl_node_init(pkg, &pkg->zpe_entry, pkgs_pool);
		uu_avl_insert(saw_pkgs, pkg, where);
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Add the pkg to the sw inventory on the handle.
 */
static int
add_pkg(zone_dochandle_t handle, char *name, char *version)
{
	xmlNodePtr newnode;
	xmlNodePtr cur;
	int err;

	if ((err = operation_prep(handle)) != Z_OK)
		return (err);

	cur = handle->zone_dh_cur;
	newnode = xmlNewTextChild(cur, NULL, DTD_ELEM_PACKAGE, NULL);
	if ((err = newprop(newnode, DTD_ATTR_NAME, name)) != Z_OK)
		return (err);
	if ((err = newprop(newnode, DTD_ATTR_VERSION, version)) != Z_OK)
		return (err);
	return (Z_OK);
}

static void
free_pkginfo(struct zone_pkginfo *infop)
{
	free(infop->zpi_version);
	if (infop->zpi_patch_cnt > 0) {
		int i;

		for (i = 0; i < infop->zpi_patch_cnt; i++)
			free(infop->zpi_patchinfo[i]);
		free(infop->zpi_patchinfo);
	}
}

/*
 * Read the pkginfo file and populate the structure with the data we need
 * from this pkg for a sw inventory.
 */
static int
get_pkginfo(char *pkginfo, struct zone_pkginfo *infop)
{
	FILE	*fp;
	char	*buf;
	int	err = 0;

	infop->zpi_all_zones = B_FALSE;
	infop->zpi_this_zone = B_FALSE;
	infop->zpi_version = NULL;
	infop->zpi_patch_cnt = 0;
	infop->zpi_patchinfo = NULL;

	if ((fp = fopen(pkginfo, "r")) == NULL)
		return (errno);

	while ((buf = read_pkg_data(fp)) != NULL) {
		if (strncmp(buf, VERSION, sizeof (VERSION) - 1) == 0) {
			int len;

			if ((infop->zpi_version =
			    strdup(buf + sizeof (VERSION) - 1)) == NULL) {
				err = ENOMEM;
				break;
			}

			/* remove trailing newline */
			len = strlen(infop->zpi_version);
			*(infop->zpi_version + len - 1) = 0;

		} else if (strcmp(buf, SUNW_PKG_ALL_ZONES) == 0) {
			infop->zpi_all_zones = B_TRUE;

		} else if (strcmp(buf, SUNW_PKG_THIS_ZONE) == 0) {
			infop->zpi_this_zone = B_TRUE;

		} else if (strncmp(buf, PATCHINFO, sizeof (PATCHINFO) - 1)
		    == 0) {
			char **p;

			if ((p = (char **)realloc(infop->zpi_patchinfo,
			    sizeof (char *) * (infop->zpi_patch_cnt + 1)))
			    == NULL) {
				err = ENOMEM;
				break;
			}
			infop->zpi_patchinfo = p;

			if ((infop->zpi_patchinfo[infop->zpi_patch_cnt] =
			    strdup(buf)) == NULL) {
				err = ENOMEM;
				break;
			}
			infop->zpi_patch_cnt++;
		}

		free(buf);
	}

	free(buf);

	if (errno == ENOMEM) {
		err = ENOMEM;
		/* Clean up anything we did manage to allocate. */
		free_pkginfo(infop);
	}

	(void) fclose(fp);

	return (err);
}

/*
 * Add any dependent pkgs to the list.  The pkg depend file lists pkg
 * dependencies, one per line with an entry that looks like:
 *	P SUNWcar       Core Architecture, (Root)
 * See the depend(4) man page.
 */
static int
add_dependents(zone_dochandle_t handle, char *pname,
    uu_avl_pool_t *patches_pool, uu_avl_t *obs_patches,
    uu_list_pool_t *list_pool, uu_avl_t *saw_pkgs, uu_avl_pool_t *pkgs_pool)
{
	int		res = Z_OK;
	FILE		*fp;
	char		depend[MAXPATHLEN];
	char		*buf;
	struct stat	sbuf;

	(void) snprintf(depend, sizeof (depend), "%s/%s/install/depend",
	    PKG_PATH, pname);

	if (stat(depend, &sbuf) == -1 || !S_ISREG(sbuf.st_mode))
		return (Z_OK);

	if ((fp = fopen(depend, "r")) == NULL)
		return (Z_OK);

	while ((buf = read_pkg_data(fp)) != NULL) {
		char *deppkg;
		char *delims = " \t";
		char pkginfo[MAXPATHLEN];
		struct zone_pkginfo info;

		if (*buf != 'P') {
			free(buf);
			continue;
		}

		/* Skip past the leading 'P '. */
		if ((deppkg = strtok(buf + 2, delims)) == NULL) {
			free(buf);
			continue;
		}

		/* If the pkg is already in the manifest don't add it again. */
		if (pkg_in_manifest(saw_pkgs, deppkg, pkgs_pool)) {
			free(buf);
			continue;
		}

		(void) snprintf(pkginfo, sizeof (pkginfo), "%s/%s/pkginfo",
		    PKG_PATH, deppkg);

		if (stat(pkginfo, &sbuf) == -1 || !S_ISREG(sbuf.st_mode)) {
			free(buf);
			continue;
		}

		if (get_pkginfo(pkginfo, &info) != 0) {
			res = Z_NOMEM;
			free(buf);
			break;
		}

		if ((res = add_dependents(handle, deppkg, patches_pool,
		    obs_patches, list_pool, saw_pkgs, pkgs_pool)) == Z_OK &&
		    (res = add_pkg(handle, deppkg, info.zpi_version)) == Z_OK) {
			if (info.zpi_patch_cnt > 0)
				res = add_patches(handle, &info, patches_pool,
				    obs_patches, list_pool);
		}

		free(buf);
		free_pkginfo(&info);

		if (res != Z_OK)
			break;
	}

	(void) fclose(fp);
	return (res);
}

/* ARGSUSED */
static int
pkg_entry_compare(const void *l_arg, const void *r_arg, void *private)
{
	zone_pkg_entry_t *pkg = (zone_pkg_entry_t *)l_arg;
	char *name = (char *)r_arg;

	return (strcmp(pkg->zpe_name, name));
}

static void
pkg_avl_delete(uu_avl_t *pavl)
{
	if (pavl != NULL) {
		zone_pkg_entry_t *p;
		void *cookie = NULL;

		while ((p = uu_avl_teardown(pavl, &cookie)) != NULL) {
			free(p->zpe_name);
			free(p);
		}

		uu_avl_destroy(pavl);
	}
}

/*
 * Take a software inventory of the global zone.  We need to get the set of
 * packages and patches that are on the global zone that the specified
 * non-global zone depends on.  The packages we need in the inventory are:
 *
 * - skip the package if SUNW_PKG_THISZONE is 'true'
 * otherwise,
 * - add the package if
 * a) SUNW_PKG_ALLZONES is 'true',
 * or
 * b) any file delivered by the package is in a file system that is inherited
 * from the global zone.
 * If the zone does not inherit any file systems (whole root)
 * then (b) will be skipped.
 *
 * For each of the packages that is being added to the inventory, we will also
 * add its dependent packages to the inventory.
 *
 * For each of the packages that is being added to the inventory, we will also
 * add all of the associated, unique patches to the inventory.
 *
 * See the comment for zonecfg_getpkgdata() for compatability restrictions on
 * how we must save the XML representation of the software inventory.
 */
static int
zonecfg_sw_inventory(zone_dochandle_t handle)
{
	char		pkginfo[MAXPATHLEN];
	int		res;
	struct dirent	*dp;
	DIR		*dirp;
	struct stat	buf;
	struct zone_pkginfo	info;
	int		pkg_cnt = 0;
	char		**pkgs = NULL;
	uu_avl_pool_t 	*pkgs_pool = NULL;
	uu_avl_pool_t 	*patches_pool = NULL;
	uu_list_pool_t 	*list_pool = NULL;
	uu_avl_t	*saw_pkgs = NULL;
	uu_avl_t 	*obs_patches = NULL;

	if ((pkgs_pool = uu_avl_pool_create("pkgs_pool",
	    sizeof (zone_pkg_entry_t), offsetof(zone_pkg_entry_t, zpe_entry),
	    pkg_entry_compare, UU_DEFAULT)) == NULL) {
		res = Z_NOMEM;
		goto done;
	}

	if ((saw_pkgs = uu_avl_create(pkgs_pool, NULL, UU_DEFAULT)) == NULL) {
		res = Z_NOMEM;
		goto done;
	}

	if ((patches_pool = uu_avl_pool_create("patches_pool",
	    sizeof (patch_node_t), offsetof(patch_node_t, patch_node),
	    patch_node_compare, UU_DEFAULT)) == NULL) {
		res = Z_NOMEM;
		goto done;
	}

	if ((list_pool = uu_list_pool_create("list_pool",
	    sizeof (obs_patch_node_t), offsetof(obs_patch_node_t, link), NULL,
	    UU_DEFAULT)) == NULL) {
		res = Z_NOMEM;
		goto done;
	}

	/*
	 * The obs_patches AVL tree saves all of the obsolete patches so
	 * that we know not to output those as part of the sw dependencies.
	 */
	if ((obs_patches = uu_avl_create(patches_pool, NULL, UU_DEFAULT))
	    == NULL) {
		res = Z_NOMEM;
		goto done;
	}

	if ((res = get_ipd_pkgs(handle, &pkgs, &pkg_cnt)) != Z_OK) {
		res = Z_NOMEM;
		goto done;
	}

	if ((dirp = opendir(PKG_PATH)) == NULL) {
		res = Z_NOMEM;
		goto done;
	}

	while ((dp = readdir(dirp)) != (struct dirent *)0) {
		if (strcmp(dp->d_name, ".") == 0 ||
		    strcmp(dp->d_name, "..") == 0)
			continue;

		(void) snprintf(pkginfo, sizeof (pkginfo), "%s/%s/pkginfo",
		    PKG_PATH, dp->d_name);

		if (stat(pkginfo, &buf) == -1 || !S_ISREG(buf.st_mode))
			continue;

		if (get_pkginfo(pkginfo, &info) != 0) {
			res = Z_NOMEM;
			break;
		}

		if (!info.zpi_this_zone &&
		    (info.zpi_all_zones ||
		    dir_pkg(dp->d_name, pkgs, pkg_cnt)) &&
		    !pkg_in_manifest(saw_pkgs, dp->d_name, pkgs_pool)) {
			/*
			 * Add dependents first so any patches will get
			 * associated with the right pkg in the xml file.
			 */
			if ((res = add_dependents(handle, dp->d_name,
			    patches_pool, obs_patches, list_pool, saw_pkgs,
			    pkgs_pool)) == Z_OK &&
			    (res = add_pkg(handle, dp->d_name,
			    info.zpi_version)) == Z_OK) {
				if (info.zpi_patch_cnt > 0)
					res = add_patches(handle, &info,
					    patches_pool, obs_patches,
					    list_pool);
			}
		}

		free_pkginfo(&info);

		if (res != Z_OK)
			break;
	}

	(void) closedir(dirp);

done:
	pkg_avl_delete(saw_pkgs);
	patch_avl_delete(obs_patches);
	if (pkgs_pool != NULL)
		uu_avl_pool_destroy(pkgs_pool);
	if (patches_pool != NULL)
		uu_avl_pool_destroy(patches_pool);
	if (list_pool != NULL)
		uu_list_pool_destroy(list_pool);
	free_ipd_pkgs(pkgs, pkg_cnt);

	if (res == Z_OK)
		handle->zone_dh_sw_inv = B_TRUE;

	return (res);
}

/*
 * zonecfg_devwalk call-back function used during detach to generate the
 * dev info in the manifest.
 */
static int
get_detach_dev_entry(const char *name, uid_t uid, gid_t gid, mode_t mode,
    const char *acl, void *hdl)
{
	zone_dochandle_t handle = (zone_dochandle_t)hdl;
	xmlNodePtr newnode;
	xmlNodePtr cur;
	int err;
	char buf[128];

	if ((err = operation_prep(handle)) != Z_OK)
		return (err);

	cur = handle->zone_dh_cur;
	newnode = xmlNewTextChild(cur, NULL, DTD_ELEM_DEV_PERM, NULL);
	if ((err = newprop(newnode, DTD_ATTR_NAME, (char *)name)) != Z_OK)
		return (err);
	(void) snprintf(buf, sizeof (buf), "%lu", uid);
	if ((err = newprop(newnode, DTD_ATTR_UID, buf)) != Z_OK)
		return (err);
	(void) snprintf(buf, sizeof (buf), "%lu", gid);
	if ((err = newprop(newnode, DTD_ATTR_GID, buf)) != Z_OK)
		return (err);
	(void) snprintf(buf, sizeof (buf), "%o", mode);
	if ((err = newprop(newnode, DTD_ATTR_MODE, buf)) != Z_OK)
		return (err);
	if ((err = newprop(newnode, DTD_ATTR_ACL, (char *)acl)) != Z_OK)
		return (err);
	return (Z_OK);
}

/*
 * Get the information required to support detaching a zone.  This is
 * called on the source system when detaching (the detaching parameter should
 * be set to true) and on the destination system before attaching (the
 * detaching parameter should be false).
 *
 * For native Solaris zones, the detach/attach process involves validating
 * that the software on the global zone can support the zone when we attach.
 * To do this we take a software inventory of the global zone.  We also
 * have to keep track of the device configuration so that we can properly
 * recreate it on the destination.
 */
int
zonecfg_get_detach_info(zone_dochandle_t handle, boolean_t detaching)
{
	int		res;

	if ((res = zonecfg_sw_inventory(handle)) != Z_OK)
		return (res);

	if (detaching)
		res = zonecfg_devwalk(handle, get_detach_dev_entry, handle);

	return (res);
}
