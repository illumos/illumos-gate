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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2015, Joyent, Inc.
 * Copyright 2014 Nexenta Systems, Inc. All rights reserved.
 */

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fnmatch.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <synch.h>
#include <sys/brand.h>
#include <sys/fcntl.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/systeminfo.h>
#include <sys/types.h>
#include <thread.h>
#include <zone.h>

#include <libbrand_impl.h>
#include <libbrand.h>

#define	DTD_ELEM_ATTACH		((const xmlChar *) "attach")
#define	DTD_ELEM_BOOT		((const xmlChar *) "boot")
#define	DTD_ELEM_BRAND		((const xmlChar *) "brand")
#define	DTD_ELEM_CLONE		((const xmlChar *) "clone")
#define	DTD_ELEM_COMMENT	((const xmlChar *) "comment")
#define	DTD_ELEM_DETACH		((const xmlChar *) "detach")
#define	DTD_ELEM_DEVICE		((const xmlChar *) "device")
#define	DTD_ELEM_GLOBAL_MOUNT	((const xmlChar *) "global_mount")
#define	DTD_ELEM_HALT		((const xmlChar *) "halt")
#define	DTD_ELEM_INITNAME	((const xmlChar *) "initname")
#define	DTD_ELEM_INSTALL	((const xmlChar *) "install")
#define	DTD_ELEM_INSTALLOPTS	((const xmlChar *) "installopts")
#define	DTD_ELEM_LOGIN_CMD	((const xmlChar *) "login_cmd")
#define	DTD_ELEM_FORCELOGIN_CMD	((const xmlChar *) "forcedlogin_cmd")
#define	DTD_ELEM_MODNAME	((const xmlChar *) "modname")
#define	DTD_ELEM_MOUNT		((const xmlChar *) "mount")
#define	DTD_ELEM_RESTARTINIT	((const xmlChar *) "restartinit")
#define	DTD_ELEM_POSTATTACH	((const xmlChar *) "postattach")
#define	DTD_ELEM_POSTCLONE	((const xmlChar *) "postclone")
#define	DTD_ELEM_POSTINSTALL	((const xmlChar *) "postinstall")
#define	DTD_ELEM_POSTSNAP	((const xmlChar *) "postsnap")
#define	DTD_ELEM_POSTSTATECHG	((const xmlChar *) "poststatechange")
#define	DTD_ELEM_PREDETACH	((const xmlChar *) "predetach")
#define	DTD_ELEM_PRESNAP	((const xmlChar *) "presnap")
#define	DTD_ELEM_PRESTATECHG	((const xmlChar *) "prestatechange")
#define	DTD_ELEM_PREUNINSTALL	((const xmlChar *) "preuninstall")
#define	DTD_ELEM_PRIVILEGE	((const xmlChar *) "privilege")
#define	DTD_ELEM_QUERY		((const xmlChar *) "query")
#define	DTD_ELEM_SHUTDOWN	((const xmlChar *) "shutdown")
#define	DTD_ELEM_SYMLINK	((const xmlChar *) "symlink")
#define	DTD_ELEM_SYSBOOT	((const xmlChar *) "sysboot")
#define	DTD_ELEM_UNINSTALL	((const xmlChar *) "uninstall")
#define	DTD_ELEM_USER_CMD	((const xmlChar *) "user_cmd")
#define	DTD_ELEM_VALIDSNAP	((const xmlChar *) "validatesnap")
#define	DTD_ELEM_VERIFY_CFG	((const xmlChar *) "verify_cfg")
#define	DTD_ELEM_VERIFY_ADM	((const xmlChar *) "verify_adm")

#define	DTD_ATTR_ALLOWEXCL	((const xmlChar *) "allow-exclusive-ip")
#define	DTD_ATTR_ARCH		((const xmlChar *) "arch")
#define	DTD_ATTR_DIRECTORY	((const xmlChar *) "directory")
#define	DTD_ATTR_IPTYPE		((const xmlChar *) "ip-type")
#define	DTD_ATTR_MATCH		((const xmlChar *) "match")
#define	DTD_ATTR_MODE		((const xmlChar *) "mode")
#define	DTD_ATTR_NAME		((const xmlChar *) "name")
#define	DTD_ATTR_OPT		((const xmlChar *) "opt")
#define	DTD_ATTR_PATH		((const xmlChar *) "path")
#define	DTD_ATTR_SET		((const xmlChar *) "set")
#define	DTD_ATTR_SOURCE		((const xmlChar *) "source")
#define	DTD_ATTR_SPECIAL	((const xmlChar *) "special")
#define	DTD_ATTR_TARGET		((const xmlChar *) "target")
#define	DTD_ATTR_TYPE		((const xmlChar *) "type")

#define	DTD_ENTITY_TRUE		"true"

static volatile boolean_t	libbrand_initialized = B_FALSE;
static char			i_curr_arch[MAXNAMELEN];
static char			i_curr_zone[ZONENAME_MAX];

/*ARGSUSED*/
static void
brand_error_func(void *ctx, const char *msg, ...)
{
	/*
	 * Ignore error messages from libxml
	 */
}

static boolean_t
libbrand_initialize()
{
	static mutex_t initialize_lock = DEFAULTMUTEX;

	(void) mutex_lock(&initialize_lock);

	if (libbrand_initialized) {
		(void) mutex_unlock(&initialize_lock);
		return (B_TRUE);
	}

	if (sysinfo(SI_ARCHITECTURE, i_curr_arch, sizeof (i_curr_arch)) < 0) {
		(void) mutex_unlock(&initialize_lock);
		return (B_FALSE);
	}

	if (getzonenamebyid(getzoneid(), i_curr_zone,
	    sizeof (i_curr_zone)) < 0) {
		(void) mutex_unlock(&initialize_lock);
		return (B_FALSE);
	}

	/*
	 * Note that here we're initializing per-process libxml2
	 * state.  By doing so we're implicitly assuming that
	 * no other code in this process is also trying to
	 * use libxml2.  But in most case we know this not to
	 * be true since we're almost always used in conjunction
	 * with libzonecfg, which also uses libxml2.  Lucky for
	 * us, libzonecfg initializes libxml2 to essentially
	 * the same defaults as we're using below.
	 */
	(void) xmlLineNumbersDefault(1);
	xmlLoadExtDtdDefaultValue |= XML_DETECT_IDS;
	xmlDoValidityCheckingDefaultValue = 1;
	(void) xmlKeepBlanksDefault(0);
	xmlGetWarningsDefaultValue = 0;
	xmlSetGenericErrorFunc(NULL, brand_error_func);

	libbrand_initialized = B_TRUE;
	(void) mutex_unlock(&initialize_lock);
	return (B_TRUE);
}

static const char *
get_curr_arch(void)
{
	if (!libbrand_initialize())
		return (NULL);

	return (i_curr_arch);
}

static const char *
get_curr_zone(void)
{
	if (!libbrand_initialize())
		return (NULL);

	return (i_curr_zone);
}

/*
 * Internal function to open an XML file
 *
 * Returns the XML doc pointer, or NULL on failure.  It will validate the
 * document, as well as removing any comments from the document structure.
 */
static xmlDocPtr
open_xml_file(const char *file)
{
	xmlDocPtr doc;
	xmlValidCtxtPtr cvp;
	int valid;

	if (!libbrand_initialize())
		return (NULL);

	/*
	 * Parse the file
	 */
	if ((doc = xmlParseFile(file)) == NULL)
		return (NULL);

	/*
	 * Validate the file
	 */
	if ((cvp = xmlNewValidCtxt()) == NULL) {
		xmlFreeDoc(doc);
		return (NULL);
	}
	cvp->error = brand_error_func;
	cvp->warning = brand_error_func;
	valid = xmlValidateDocument(cvp, doc);
	xmlFreeValidCtxt(cvp);
	if (valid == 0) {
		xmlFreeDoc(doc);
		return (NULL);
	}

	return (doc);
}
/*
 * Open a handle to the named brand.
 *
 * Returns a handle to the named brand, which is used for all subsequent brand
 * interaction, or NULL if unable to open or initialize the brand.
 */
brand_handle_t
brand_open(const char *name)
{
	struct brand_handle *bhp;
	char path[MAXPATHLEN];
	xmlNodePtr node;
	xmlChar *property;
	struct stat statbuf;

	/*
	 * Make sure brand name isn't too long
	 */
	if (strlen(name) >= MAXNAMELEN)
		return (NULL);

	/*
	 * Check that the brand exists
	 */
	(void) snprintf(path, sizeof (path), "%s/%s", BRAND_DIR, name);

	if (stat(path, &statbuf) != 0)
		return (NULL);

	/*
	 * Allocate brand handle
	 */
	if ((bhp = malloc(sizeof (struct brand_handle))) == NULL)
		return (NULL);
	bzero(bhp, sizeof (struct brand_handle));

	(void) strcpy(bhp->bh_name, name);

	/*
	 * Open the configuration file
	 */
	(void) snprintf(path, sizeof (path), "%s/%s/%s", BRAND_DIR, name,
	    BRAND_CONFIG);
	if ((bhp->bh_config = open_xml_file(path)) == NULL) {
		brand_close((brand_handle_t)bhp);
		return (NULL);
	}

	/*
	 * Verify that the name of the brand matches the directory in which it
	 * is installed.
	 */
	if ((node = xmlDocGetRootElement(bhp->bh_config)) == NULL) {
		brand_close((brand_handle_t)bhp);
		return (NULL);
	}

	if (xmlStrcmp(node->name, DTD_ELEM_BRAND) != 0) {
		brand_close((brand_handle_t)bhp);
		return (NULL);
	}

	if ((property = xmlGetProp(node, DTD_ATTR_NAME)) == NULL) {
		brand_close((brand_handle_t)bhp);
		return (NULL);
	}

	if (strcmp((char *)property, name) != 0) {
		xmlFree(property);
		brand_close((brand_handle_t)bhp);
		return (NULL);
	}
	xmlFree(property);

	/*
	 * Open handle to platform configuration file.
	 */
	(void) snprintf(path, sizeof (path), "%s/%s/%s", BRAND_DIR, name,
	    BRAND_PLATFORM);
	if ((bhp->bh_platform = open_xml_file(path)) == NULL) {
		brand_close((brand_handle_t)bhp);
		return (NULL);
	}

	return ((brand_handle_t)bhp);
}

/*
 * Closes the given brand handle
 */
void
brand_close(brand_handle_t bh)
{
	struct brand_handle *bhp = (struct brand_handle *)bh;
	if (bhp->bh_platform != NULL)
		xmlFreeDoc(bhp->bh_platform);
	if (bhp->bh_config != NULL)
		xmlFreeDoc(bhp->bh_config);
	free(bhp);
}

static int
i_substitute_tokens(const char *sbuf, char *dbuf, int dbuf_size,
    const char *zonename, const char *zonepath, const char *username,
    const char *curr_zone)
{
	int dst, src;

	/*
	 * Walk through the characters, substituting values as needed.
	 */
	dbuf[0] = '\0';
	dst = 0;
	for (src = 0; src < strlen((char *)sbuf) && dst < dbuf_size; src++) {
		if (sbuf[src] != '%') {
			dbuf[dst++] = sbuf[src];
			continue;
		}

		switch (sbuf[++src]) {
		case '%':
			dst += strlcpy(dbuf + dst, "%", dbuf_size - dst);
			break;
		case 'R':
			if (zonepath == NULL)
				break;
			dst += strlcpy(dbuf + dst, zonepath, dbuf_size - dst);
			break;
		case 'u':
			if (username == NULL)
				break;
			dst += strlcpy(dbuf + dst, username, dbuf_size - dst);
			break;
		case 'Z':
			if (curr_zone == NULL)
				break;
			/* name of the zone we're running in */
			dst += strlcpy(dbuf + dst, curr_zone, dbuf_size - dst);
			break;
		case 'z':
			/* name of the zone we're operating on */
			if (zonename == NULL)
				break;
			dst += strlcpy(dbuf + dst, zonename, dbuf_size - dst);
			break;
		}
	}

	if (dst >= dbuf_size)
		return (-1);

	dbuf[dst] = '\0';
	return (0);
}

/*
 * Retrieve the given tag from the brand.
 * Perform the following substitutions as necessary:
 *
 *	%%	%
 *	%u	Username
 *	%z	Name of target zone
 *	%Z	Name of current zone
 *	%R	Zonepath of zone
 *
 * Returns 0 on success, -1 on failure.
 */
static int
brand_get_value(struct brand_handle *bhp, const char *zonename,
    const char *zonepath, const char *username, const char *curr_zone,
    char *buf, size_t len, const xmlChar *tagname,
    boolean_t substitute, boolean_t optional)
{
	xmlNodePtr node;
	xmlChar *content;
	int err = 0;

	/*
	 * Retrieve the specified value from the XML doc
	 */
	if ((node = xmlDocGetRootElement(bhp->bh_config)) == NULL)
		return (-1);

	if (xmlStrcmp(node->name, DTD_ELEM_BRAND) != 0)
		return (-1);

	for (node = node->xmlChildrenNode; node != NULL;
	    node = node->next) {
		if (xmlStrcmp(node->name, tagname) == 0)
			break;
	}

	if (node == NULL) {
		if (optional) {
			buf[0] = '\0';
			return (0);
		} else {
			return (-1);
		}
	}

	if ((content = xmlNodeGetContent(node)) == NULL)
		return (-1);

	if (strlen((char *)content) == 0) {
		/*
		 * If the entry in the config file is empty, check to see
		 * whether this is an optional field.  If so, we return the
		 * empty buffer.  If not, we return an error.
		 */
		if (optional) {
			buf[0] = '\0';
		} else {
			err = -1;
		}
	} else {
		/* Substitute token values as needed. */
		if (substitute) {
			if (i_substitute_tokens((char *)content, buf, len,
			    zonename, zonepath, username, curr_zone) != 0)
				err = -1;
		} else {
			if (strlcpy(buf, (char *)content, len) >= len)
				err = -1;
		}
	}

	xmlFree(content);

	return (err);
}

int
brand_get_attach(brand_handle_t bh, const char *zonename,
    const char *zonepath, char *buf, size_t len)
{
	struct brand_handle *bhp = (struct brand_handle *)bh;
	return (brand_get_value(bhp, zonename, zonepath, NULL, NULL,
	    buf, len, DTD_ELEM_ATTACH, B_TRUE, B_TRUE));
}

int
brand_get_boot(brand_handle_t bh, const char *zonename,
    const char *zonepath, char *buf, size_t len)
{
	struct brand_handle *bhp = (struct brand_handle *)bh;
	return (brand_get_value(bhp, zonename, zonepath, NULL, NULL,
	    buf, len, DTD_ELEM_BOOT, B_TRUE, B_TRUE));
}

int
brand_get_brandname(brand_handle_t bh, char *buf, size_t len)
{
	struct brand_handle *bhp = (struct brand_handle *)bh;
	if (len <= strlen(bhp->bh_name))
		return (-1);

	(void) strcpy(buf, bhp->bh_name);

	return (0);
}

int
brand_get_clone(brand_handle_t bh, const char *zonename,
    const char *zonepath, char *buf, size_t len)
{
	struct brand_handle *bhp = (struct brand_handle *)bh;
	return (brand_get_value(bhp, zonename, zonepath, NULL, NULL,
	    buf, len, DTD_ELEM_CLONE, B_TRUE, B_TRUE));
}

int
brand_get_detach(brand_handle_t bh, const char *zonename,
    const char *zonepath, char *buf, size_t len)
{
	struct brand_handle *bhp = (struct brand_handle *)bh;
	return (brand_get_value(bhp, zonename, zonepath, NULL, NULL,
	    buf, len, DTD_ELEM_DETACH, B_TRUE, B_TRUE));
}

int
brand_get_halt(brand_handle_t bh, const char *zonename,
    const char *zonepath, char *buf, size_t len)
{
	struct brand_handle *bhp = (struct brand_handle *)bh;
	return (brand_get_value(bhp, zonename, zonepath, NULL, NULL,
	    buf, len, DTD_ELEM_HALT, B_TRUE, B_TRUE));
}

int
brand_get_shutdown(brand_handle_t bh, const char *zonename,
    const char *zonepath, char *buf, size_t len)
{
	struct brand_handle *bhp = (struct brand_handle *)bh;
	return (brand_get_value(bhp, zonename, zonepath, NULL, NULL,
	    buf, len, DTD_ELEM_SHUTDOWN, B_TRUE, B_TRUE));
}

int
brand_get_initname(brand_handle_t bh, char *buf, size_t len)
{
	struct brand_handle *bhp = (struct brand_handle *)bh;
	return (brand_get_value(bhp, NULL, NULL, NULL, NULL,
	    buf, len, DTD_ELEM_INITNAME, B_FALSE, B_FALSE));
}

boolean_t
brand_restartinit(brand_handle_t bh)
{
	struct brand_handle *bhp = (struct brand_handle *)bh;
	char val[80];

	if (brand_get_value(bhp, NULL, NULL, NULL, NULL,
	    val, sizeof (val), DTD_ELEM_RESTARTINIT, B_FALSE, B_FALSE) != 0)
		return (B_TRUE);

	if (strcmp(val, "false") == 0)
		return (B_FALSE);
	return (B_TRUE);
}

int
brand_get_login_cmd(brand_handle_t bh, const char *username,
    char *buf, size_t len)
{
	struct brand_handle *bhp = (struct brand_handle *)bh;
	const char *curr_zone = get_curr_zone();
	return (brand_get_value(bhp, NULL, NULL, username, curr_zone,
	    buf, len, DTD_ELEM_LOGIN_CMD, B_TRUE, B_FALSE));
}

int
brand_get_forcedlogin_cmd(brand_handle_t bh, const char *username,
    char *buf, size_t len)
{
	struct brand_handle *bhp = (struct brand_handle *)bh;
	const char *curr_zone = get_curr_zone();
	return (brand_get_value(bhp, NULL, NULL, username, curr_zone,
	    buf, len, DTD_ELEM_FORCELOGIN_CMD, B_TRUE, B_FALSE));
}

int
brand_get_user_cmd(brand_handle_t bh, const char *username,
    char *buf, size_t len)
{
	struct brand_handle *bhp = (struct brand_handle *)bh;

	return (brand_get_value(bhp, NULL, NULL, username, NULL,
	    buf, len, DTD_ELEM_USER_CMD, B_TRUE, B_FALSE));
}

int
brand_get_install(brand_handle_t bh, const char *zonename,
    const char *zonepath, char *buf, size_t len)
{
	struct brand_handle *bhp = (struct brand_handle *)bh;
	return (brand_get_value(bhp, zonename, zonepath, NULL, NULL,
	    buf, len, DTD_ELEM_INSTALL, B_TRUE, B_FALSE));
}

int
brand_get_installopts(brand_handle_t bh, char *buf, size_t len)
{
	struct brand_handle *bhp = (struct brand_handle *)bh;
	return (brand_get_value(bhp, NULL, NULL, NULL, NULL,
	    buf, len, DTD_ELEM_INSTALLOPTS, B_FALSE, B_TRUE));
}

int
brand_get_modname(brand_handle_t bh, char *buf, size_t len)
{
	struct brand_handle *bhp = (struct brand_handle *)bh;
	return (brand_get_value(bhp, NULL, NULL, NULL, NULL,
	    buf, len, DTD_ELEM_MODNAME, B_FALSE, B_TRUE));
}

int
brand_get_postattach(brand_handle_t bh, const char *zonename,
    const char *zonepath, char *buf, size_t len)
{
	struct brand_handle *bhp = (struct brand_handle *)bh;
	return (brand_get_value(bhp, zonename, zonepath, NULL, NULL,
	    buf, len, DTD_ELEM_POSTATTACH, B_TRUE, B_TRUE));
}

int
brand_get_postclone(brand_handle_t bh, const char *zonename,
    const char *zonepath, char *buf, size_t len)
{
	struct brand_handle *bhp = (struct brand_handle *)bh;
	return (brand_get_value(bhp, zonename, zonepath, NULL, NULL,
	    buf, len, DTD_ELEM_POSTCLONE, B_TRUE, B_TRUE));
}

int
brand_get_postinstall(brand_handle_t bh, const char *zonename,
    const char *zonepath, char *buf, size_t len)
{
	struct brand_handle *bhp = (struct brand_handle *)bh;
	return (brand_get_value(bhp, zonename, zonepath, NULL, NULL,
	    buf, len, DTD_ELEM_POSTINSTALL, B_TRUE, B_TRUE));
}

int
brand_get_postsnap(brand_handle_t bh, const char *zonename,
    const char *zonepath, char *buf, size_t len)
{
	struct brand_handle *bhp = (struct brand_handle *)bh;
	return (brand_get_value(bhp, zonename, zonepath, NULL, NULL,
	    buf, len, DTD_ELEM_POSTSNAP, B_TRUE, B_TRUE));
}

int
brand_get_poststatechange(brand_handle_t bh, const char *zonename,
    const char *zonepath, char *buf, size_t len)
{
	struct brand_handle *bhp = (struct brand_handle *)bh;
	return (brand_get_value(bhp, zonename, zonepath, NULL, NULL,
	    buf, len, DTD_ELEM_POSTSTATECHG, B_TRUE, B_TRUE));
}

int
brand_get_predetach(brand_handle_t bh, const char *zonename,
    const char *zonepath, char *buf, size_t len)
{
	struct brand_handle *bhp = (struct brand_handle *)bh;
	return (brand_get_value(bhp, zonename, zonepath, NULL, NULL,
	    buf, len, DTD_ELEM_PREDETACH, B_TRUE, B_TRUE));
}

int
brand_get_presnap(brand_handle_t bh, const char *zonename,
    const char *zonepath, char *buf, size_t len)
{
	struct brand_handle *bhp = (struct brand_handle *)bh;
	return (brand_get_value(bhp, zonename, zonepath, NULL, NULL,
	    buf, len, DTD_ELEM_PRESNAP, B_TRUE, B_TRUE));
}

int
brand_get_prestatechange(brand_handle_t bh, const char *zonename,
    const char *zonepath, char *buf, size_t len)
{
	struct brand_handle *bhp = (struct brand_handle *)bh;
	return (brand_get_value(bhp, zonename, zonepath, NULL, NULL,
	    buf, len, DTD_ELEM_PRESTATECHG, B_TRUE, B_TRUE));
}

int
brand_get_preuninstall(brand_handle_t bh, const char *zonename,
    const char *zonepath, char *buf, size_t len)
{
	struct brand_handle *bhp = (struct brand_handle *)bh;
	return (brand_get_value(bhp, zonename, zonepath, NULL, NULL,
	    buf, len, DTD_ELEM_PREUNINSTALL, B_TRUE, B_TRUE));
}

int
brand_get_query(brand_handle_t bh, const char *zonename,
    const char *zonepath, char *buf, size_t len)
{
	struct brand_handle *bhp = (struct brand_handle *)bh;
	return (brand_get_value(bhp, zonename, zonepath, NULL, NULL,
	    buf, len, DTD_ELEM_QUERY, B_TRUE, B_TRUE));
}

int
brand_get_uninstall(brand_handle_t bh, const char *zonename,
    const char *zonepath, char *buf, size_t len)
{
	struct brand_handle *bhp = (struct brand_handle *)bh;
	return (brand_get_value(bhp, zonename, zonepath, NULL, NULL,
	    buf, len, DTD_ELEM_UNINSTALL, B_TRUE, B_TRUE));
}

int
brand_get_validatesnap(brand_handle_t bh, const char *zonename,
    const char *zonepath, char *buf, size_t len)
{
	struct brand_handle *bhp = (struct brand_handle *)bh;
	return (brand_get_value(bhp, zonename, zonepath, NULL, NULL,
	    buf, len, DTD_ELEM_VALIDSNAP, B_TRUE, B_TRUE));
}

int
brand_get_verify_cfg(brand_handle_t bh, char *buf, size_t len)
{
	struct brand_handle *bhp = (struct brand_handle *)bh;
	return (brand_get_value(bhp, NULL, NULL, NULL, NULL,
	    buf, len, DTD_ELEM_VERIFY_CFG, B_FALSE, B_TRUE));
}

int
brand_get_verify_adm(brand_handle_t bh, const char *zonename,
    const char *zonepath, char *buf, size_t len)
{
	struct brand_handle *bhp = (struct brand_handle *)bh;
	return (brand_get_value(bhp, zonename, zonepath, NULL, NULL,
	    buf, len, DTD_ELEM_VERIFY_ADM, B_TRUE, B_TRUE));
}

int
brand_get_sysboot(brand_handle_t bh, const char *zonename,
    const char *zonepath, char *buf, size_t len)
{
	struct brand_handle *bhp = (struct brand_handle *)bh;
	return (brand_get_value(bhp, zonename, zonepath, NULL, NULL,
	    buf, len, DTD_ELEM_SYSBOOT, B_TRUE, B_TRUE));
}

boolean_t
brand_allow_exclusive_ip(brand_handle_t bh)
{
	struct brand_handle	*bhp = (struct brand_handle *)bh;
	xmlNodePtr		node;
	xmlChar			*allow_excl;
	boolean_t		ret;

	assert(bhp != NULL);

	if ((node = xmlDocGetRootElement(bhp->bh_platform)) == NULL)
		return (B_FALSE);

	allow_excl = xmlGetProp(node, DTD_ATTR_ALLOWEXCL);
	if (allow_excl == NULL)
		return (B_FALSE);

	/* Note: only return B_TRUE if it's "true" */
	if (strcmp((char *)allow_excl, DTD_ENTITY_TRUE) == 0)
		ret = B_TRUE;
	else
		ret = B_FALSE;

	xmlFree(allow_excl);

	return (ret);
}

/*
 * Iterate over brand privileges
 *
 * Walks the brand config, searching for <privilege> elements, calling the
 * specified callback for each.  Returns 0 on success, or -1 on failure.
 */
int
brand_config_iter_privilege(brand_handle_t bh,
    int (*func)(void *, priv_iter_t *), void *data)
{
	struct brand_handle	*bhp = (struct brand_handle *)bh;
	xmlNodePtr		node;
	xmlChar			*name, *set, *iptype;
	priv_iter_t		priv_iter;
	int			ret;

	if ((node = xmlDocGetRootElement(bhp->bh_config)) == NULL)
		return (-1);

	for (node = node->xmlChildrenNode; node != NULL; node = node->next) {

		if (xmlStrcmp(node->name, DTD_ELEM_PRIVILEGE) != 0)
			continue;

		name = xmlGetProp(node, DTD_ATTR_NAME);
		set = xmlGetProp(node, DTD_ATTR_SET);
		iptype = xmlGetProp(node, DTD_ATTR_IPTYPE);

		if (name == NULL || set == NULL || iptype == NULL) {
			if (name != NULL)
				xmlFree(name);
			if (set != NULL)
				xmlFree(set);
			if (iptype != NULL)
				xmlFree(iptype);
			return (-1);
		}

		priv_iter.pi_name = (char *)name;
		priv_iter.pi_set = (char *)set;
		priv_iter.pi_iptype = (char *)iptype;

		ret = func(data, &priv_iter);

		xmlFree(name);
		xmlFree(set);
		xmlFree(iptype);

		if (ret != 0)
			return (-1);
	}

	return (0);
}

static int
i_brand_platform_iter_mounts(struct brand_handle *bhp, const char *zonename,
    const char *zonepath, int (*func)(void *, const char *, const char *,
    const char *, const char *), void *data, const xmlChar *mount_type)
{
	xmlNodePtr node;
	xmlChar *special, *dir, *type, *opt;
	char special_exp[MAXPATHLEN];
	char opt_exp[MAXPATHLEN];
	int ret;

	if ((node = xmlDocGetRootElement(bhp->bh_platform)) == NULL)
		return (-1);

	for (node = node->xmlChildrenNode; node != NULL; node = node->next) {

		if (xmlStrcmp(node->name, mount_type) != 0)
			continue;

		special = xmlGetProp(node, DTD_ATTR_SPECIAL);
		dir = xmlGetProp(node, DTD_ATTR_DIRECTORY);
		type = xmlGetProp(node, DTD_ATTR_TYPE);
		opt = xmlGetProp(node, DTD_ATTR_OPT);
		if ((special == NULL) || (dir == NULL) || (type == NULL) ||
		    (opt == NULL)) {
			ret = -1;
			goto next;
		}

		/* Substitute token values as needed. */
		if ((ret = i_substitute_tokens((char *)special,
		    special_exp, sizeof (special_exp),
		    zonename, zonepath, NULL, NULL)) != 0)
			goto next;

		/* opt might not be defined */
		if (strlen((const char *)opt) == 0) {
			xmlFree(opt);
			opt = NULL;
		} else {
			if ((ret = i_substitute_tokens((char *)opt,
			    opt_exp, sizeof (opt_exp),
			    zonename, zonepath, NULL, NULL)) != 0)
				goto next;
		}

		ret = func(data, (char *)special_exp, (char *)dir,
		    (char *)type, ((opt != NULL) ? opt_exp : NULL));

next:
		if (special != NULL)
			xmlFree(special);
		if (dir != NULL)
			xmlFree(dir);
		if (type != NULL)
			xmlFree(type);
		if (opt != NULL)
			xmlFree(opt);
		if (ret != 0)
			return (-1);
	}
	return (0);
}


/*
 * Iterate over global platform filesystems
 *
 * Walks the platform, searching for <global_mount> elements, calling the
 * specified callback for each.  Returns 0 on success, or -1 on failure.
 *
 * Perform the following substitutions as necessary:
 *
 *	%R	Zonepath of zone
 */
int
brand_platform_iter_gmounts(brand_handle_t bh, const char *zonename,
    const char *zonepath, int (*func)(void *, const char *, const char *,
    const char *, const char *), void *data)
{
	struct brand_handle *bhp = (struct brand_handle *)bh;
	return (i_brand_platform_iter_mounts(bhp, zonename, zonepath, func,
	    data, DTD_ELEM_GLOBAL_MOUNT));
}

/*
 * Iterate over non-global zone platform filesystems
 *
 * Walks the platform, searching for <mount> elements, calling the
 * specified callback for each.  Returns 0 on success, or -1 on failure.
 */
int
brand_platform_iter_mounts(brand_handle_t bh, int (*func)(void *,
    const char *, const char *, const char *, const char *), void *data)
{
	struct brand_handle *bhp = (struct brand_handle *)bh;
	return (i_brand_platform_iter_mounts(bhp, NULL, NULL, func, data,
	    DTD_ELEM_MOUNT));
}

/*
 * Iterate over platform symlinks
 *
 * Walks the platform, searching for <symlink> elements, calling the
 * specified callback for each.  Returns 0 on success, or -1 on failure.
 */
int
brand_platform_iter_link(brand_handle_t bh,
    int (*func)(void *, const char *, const char *), void *data)
{
	struct brand_handle *bhp = (struct brand_handle *)bh;
	xmlNodePtr node;
	xmlChar *source, *target;
	int ret;

	if ((node = xmlDocGetRootElement(bhp->bh_platform)) == NULL)
		return (-1);

	for (node = node->xmlChildrenNode; node != NULL; node = node->next) {

		if (xmlStrcmp(node->name, DTD_ELEM_SYMLINK) != 0)
			continue;

		source = xmlGetProp(node, DTD_ATTR_SOURCE);
		target = xmlGetProp(node, DTD_ATTR_TARGET);

		if (source == NULL || target == NULL) {
			if (source != NULL)
				xmlFree(source);
			if (target != NULL)
				xmlFree(target);
			return (-1);
		}

		ret = func(data, (char *)source, (char *)target);

		xmlFree(source);
		xmlFree(target);

		if (ret != 0)
			return (-1);
	}

	return (0);
}

/*
 * Iterate over platform devices
 *
 * Walks the platform, searching for <device> elements, calling the
 * specified callback for each.  Returns 0 on success, or -1 on failure.
 */
int
brand_platform_iter_devices(brand_handle_t bh, const char *zonename,
    int (*func)(void *, const char *, const char *), void *data,
    const char *curr_iptype)
{
	struct brand_handle	*bhp = (struct brand_handle *)bh;
	const char		*curr_arch = get_curr_arch();
	xmlNodePtr		node;
	xmlChar			*match, *name, *arch, *iptype;
	char			match_exp[MAXPATHLEN];
	boolean_t		err = B_FALSE;
	int			ret = 0;


	assert(bhp != NULL);
	assert(zonename != NULL);
	assert(func != NULL);
	assert(curr_iptype != NULL);

	if ((node = xmlDocGetRootElement(bhp->bh_platform)) == NULL)
		return (-1);

	for (node = node->xmlChildrenNode; node != NULL; node = node->next) {

		if (xmlStrcmp(node->name, DTD_ELEM_DEVICE) != 0)
			continue;

		match = xmlGetProp(node, DTD_ATTR_MATCH);
		name = xmlGetProp(node, DTD_ATTR_NAME);
		arch = xmlGetProp(node, DTD_ATTR_ARCH);
		iptype = xmlGetProp(node, DTD_ATTR_IPTYPE);
		if ((match == NULL) || (name == NULL) || (arch == NULL) ||
		    (iptype == NULL)) {
			err = B_TRUE;
			goto next;
		}

		/* check if the arch matches */
		if ((strcmp((char *)arch, "all") != 0) &&
		    (strcmp((char *)arch, curr_arch) != 0))
			goto next;

		/* check if the iptype matches */
		if ((strcmp((char *)iptype, "all") != 0) &&
		    (strcmp((char *)iptype, curr_iptype) != 0))
			goto next;

		/* Substitute token values as needed. */
		if ((ret = i_substitute_tokens((char *)match,
		    match_exp, sizeof (match_exp),
		    zonename, NULL, NULL, NULL)) != 0) {
			err = B_TRUE;
			goto next;
		}

		/* name might not be defined */
		if (strlen((const char *)name) == 0) {
			xmlFree(name);
			name = NULL;
		}

		/* invoke the callback */
		ret = func(data, (const char *)match_exp, (const char *)name);

next:
		if (match != NULL)
			xmlFree(match);
		if (name != NULL)
			xmlFree(name);
		if (arch != NULL)
			xmlFree(arch);
		if (iptype != NULL)
			xmlFree(iptype);
		if (err)
			return (-1);
		if (ret != 0)
			return (-1);
	}

	return (0);
}
