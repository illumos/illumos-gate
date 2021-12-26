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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This contains miscellaneous functions moved from commands to the library.
 */

#include "mt.h"
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <unistd.h>
#include <gssapi/gssapi.h>
#include <rpc/rpc.h>
#include <rpcsvc/nis.h>
#include <rpcsvc/nis_dhext.h>
#include <rpc/auth.h>
#include <rpc/auth_sys.h>
#include <rpc/auth_des.h>
#include <rpc/key_prot.h>
#include <netdir.h>
#include <netconfig.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <dlfcn.h>
#include <gssapi/gssapi.h>

extern int bin2hex(int len, unsigned char *binnum, char *hexnum);
extern int hex2bin(int len, char *hexnum, char *binnum);

#define	MECH_LIB_PREFIX1	"/usr/lib/"

#ifdef  _LP64

#define	MECH_LIB_PREFIX2	"64/"

#else   /* _LP64 */

#define	MECH_LIB_PREFIX2	""

#endif  /* _LP64 */

#define	MECH_LIB_DIR		"gss/"

#define	MECH_LIB_PREFIX MECH_LIB_PREFIX1 MECH_LIB_PREFIX2

#define	MECHDH		MECH_LIB_PREFIX MECH_LIB_DIR "mech_dh.so.1"
#define	LIBGSS		MECH_LIB_PREFIX "libgss.so.1"

static gss_OID_desc __dh_gss_c_nt_netname = {
	9,  "\053\006\004\001\052\002\032\001\001"
};

mutex_t gss_load_lock = DEFAULTMUTEX;
static gss_OID GSS_EXPORT_NAME = 0;
static gss_OID DH_NETNAME = &__dh_gss_c_nt_netname;

typedef OM_uint32 (*gss_fptr)();
OM_uint32 (*g_import_name)();
OM_uint32 (*g_display_name)();
OM_uint32 (*g_release_name)();
OM_uint32 (*g_release_buffer)();
OM_uint32 (*g_release_oid)();

/*
 * gss_OID_load()
 *
 * This routine is called by __nis_gssprin2netname to define values for
 * the gss-api-export-name OID, the Diffie-Hellman netname OID, and
 * the gss support routines that it needs.
 * The reason for this support routine is that libnsl cannot have an
 * explicit dependency on libgss. Callers of __nisgssprin2netname are
 * expected to have loaded libgss through the rpcsec layer. The work around
 * is to dlopen the needed shared objects and grab the symbols with dlsym.
 * This routine opens libgss RTLD_NOLOAD. If this fails then libgss.so.1
 * is not loaded and we return error. Otherwise it uses dlsym to
 * defines GSS_EXPORT_NAME to have the value of GSS_C_NT_EXPORT_NAME and
 * to assign the above fuction pointers.
 * If this succeeds then the routine will attempt to load mech_dh.so.1
 * and over ride DH_NETNAME with the value of __DH_GSS_C_NT_NETNAME from
 * that shared object. We don't consider it an error if this fails because
 * its conceivable that another mechanism backend will support the netname
 * name type and mech_dh.so.1 not be available.
 *
 * Return 0 on failer, 1 on success.
 */

static int
gss_OID_load()
{
	void *dh;
	gss_OID *OIDptr;
	int stat = 0;

	(void) mutex_lock(&gss_load_lock);
	if (GSS_EXPORT_NAME) {
		(void) mutex_unlock(&gss_load_lock);
		return (0);
	}

	/* if LIBGSS is not loaded return an error */
	if ((dh = dlopen(LIBGSS, RTLD_NOLOAD)) == NULL) {
		(void) mutex_unlock(&gss_load_lock);
		return (0);
	}

	OIDptr = (gss_OID *)dlsym(dh, "GSS_C_NT_EXPORT_NAME");
	if (OIDptr)
		GSS_EXPORT_NAME = *OIDptr;
	else
		goto Done;

	g_import_name = (gss_fptr)dlsym(dh, "gss_import_name");
	if (g_import_name == 0)
		goto Done;

	g_display_name = (gss_fptr)dlsym(dh, "gss_display_name");
	if (g_display_name == 0)
		goto Done;

	g_release_name = (gss_fptr)dlsym(dh, "gss_release_name");
	if (g_release_name == 0)
		goto Done;

	g_release_buffer = (gss_fptr)dlsym(dh, "gss_release_buffer");
	if (g_release_buffer == 0)
		goto Done;

	g_release_oid = (gss_fptr)dlsym(dh, "gss_release_oid");
	if (g_release_oid == 0)
		goto Done;

	stat = 1;
	/*
	 * Try and get the official netname oid from mech_dh.so.
	 * If this fails will just keep our default from above.
	 */

	if ((dh = dlopen(MECHDH, RTLD_LAZY)) != NULL) {

		OIDptr = (gss_OID *)dlsym(dh, "__DH_GSS_C_NT_NETNAME");
		if (OIDptr)
			DH_NETNAME = *OIDptr;
	}

Done:
	(void) mutex_unlock(&gss_load_lock);

	if (stat == 0)
		GSS_EXPORT_NAME = 0;

	return (stat);
}


/*
 * int
 * __nis_gssprin2netname(rpc_gss_principal_t prin,
 *			 char netname[MAXNETNAMELEN+1])
 *
 * This routine attempts to extract the netname from an rpc_gss_principal_t
 * which is in { gss-api-exorted-name } format. Return 0 if a netname was
 * found, else return -1.
 */

/*
 * This routine has a dependency on libgss.so. So we will pragma weak
 * the interfaces that we need. When this routine is called libgss
 * should have been loaded by the rpcsec layer. We will call gss_OID_load
 * to get the value for GSS_EXPORT_NAME. If gss_OID_load failes return -1.
 */

#define	OID_IS_EQUAL(o1, o2) ((o1) && (o2) && \
	((o1)->length == (o2)->length) && \
	(memcmp((o1)->elements, (o2)->elements, (o1)->length) == 0))

int
__nis_gssprin2netname(rpc_gss_principal_t prin, char netname[])
{
	gss_buffer_desc display_name;
	gss_name_t name;
	gss_OID name_type;
	gss_buffer_desc expName;
	int stat = -1;
	OM_uint32 major, minor;

	/* See if we already got the OID */
	if (GSS_EXPORT_NAME == 0) {
		/* Nope. See if GSS is loaded and get the OIDs */
		if (!gss_OID_load())
			return (-1);	/* if libgss.so.1 isn't loaded */
	}

	expName.length = prin->len;
	expName.value = prin->name;

	major = (*g_import_name)(&minor, &expName,
	    (gss_OID) GSS_EXPORT_NAME, &name);

	if (major == GSS_S_COMPLETE) {
		major = (*g_display_name)(&minor, name,
		    &display_name, &name_type);

		/* We're done with the gss_internal name */
		(void) (*g_release_name)(&minor, &name);

		if (major == GSS_S_COMPLETE) {
			/*
			 * Check if we've got a netname. If we do we copy it
			 * and make sure that its null terminated.
			 */
			if (OID_IS_EQUAL(DH_NETNAME, name_type)) {
				(void) strncpy(netname,
				    (char *)display_name.value,
				    MAXNETNAMELEN);
				netname[MAXNETNAMELEN] = '\0';
				stat = 0;
			}
			/*
			 * If there are other display formats that can
			 * be converted to netnames easily, insert here.
			 *
			 * else if (OID_IS_EQUAL(OTHER_NT_OID, name_type)) {
			 *	convert2netname(display_name.value, netname);
			 * } ...
			 */

			/* Release temporty storage */
			(void) (*g_release_buffer)(&minor, &display_name);
			(void) (*g_release_oid)(&minor, &name_type);
		}
	}

	if (stat == 0)
		return (stat);

	return (stat);
}

/*
 * Extract a public key given a key length and alg. type from a packed
 * netobj containing extended Diffie-Hellman keys.
 */
char *
__nis_dhext_extract_pkey(netobj *no, keylen_t keylen, algtype_t algtype)
{
	char		*hexkey;
	/* LINTED pointer cast */
	extdhkey_t	*keyent = (extdhkey_t *)no->n_bytes;

	/* LINTED pointer cast */
	while (keyent < (extdhkey_t *)(no->n_bytes + no->n_len)) {
		char	*keyoffset;
		size_t	binlen = (ntohs(keyent->keylen) + 7) / 8;
		size_t	binpadlen = ((binlen + 3) / 4) * 4;
		size_t	hexkeylen = binlen * 2 + 1;

		if (keylen == ntohs(keyent->keylen) &&
		    algtype == ntohs(keyent->algtype)) {

			if (!(hexkey = malloc(hexkeylen)))
				return (NULL);

			(void) bin2hex(binlen, keyent->key, hexkey);
			return (hexkey);
		}
		keyoffset = (char *)keyent + (sizeof (ushort_t) * 2) +
		    binpadlen;
		/* LINTED pointer cast */
		keyent = (extdhkey_t *)keyoffset;
	}
	return (NULL);
}
