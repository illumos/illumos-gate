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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#include "nis_local.h"

extern int bin2hex(int len, unsigned char *binnum, char *hexnum);
extern int hex2bin(int len, char *hexnum, char *binnum);

/*
 * Returns the NIS principal name of the person making the request
 * XXX This is set up to use Secure RPC only at the moment, it should
 * be possible for any authentication scheme to be incorporated if it
 * has a "full name" that we can return as the principal name.
 */
static const nis_name nobody = "nobody";

static NIS_HASH_TABLE credtbl;
struct creditem {
	NIS_HASH_ITEM	item;
	char	pname[1024];
};

static void
add_cred_item(char *netname, char *pname)
{
	struct creditem *foo = NULL, *old = NULL;

	if (strlen(pname) >= sizeof (foo->pname)) {
		syslog(LOG_ERR,
		"add_cred_item: principal name too long '%s'",
				pname);
		return;
	}

	old = (struct creditem *)nis_find_item(netname, &credtbl);
	if (old != NULL)
		return;

	foo = calloc(1, sizeof (struct creditem));
	if (foo == NULL)
		return;

	foo->item.name = strdup(netname);
	if (foo->item.name == NULL) {
		free(foo);
		return;
	}

	(void) strcpy(foo->pname, pname);
	(void) nis_insert_item((NIS_HASH_ITEM *)foo, &credtbl);
}

static bool_t
find_cred_item(char *netname, char *pname)
{
	struct creditem	*old = NULL;

	if (strlen(pname) >= sizeof (old->pname))
		return (FALSE);

	old = (struct creditem *)nis_find_item(netname, &credtbl);
	if (old == NULL)
		return (FALSE);
	(void) strcpy(pname, old->pname);
	return (TRUE);
}

static bool_t
delete_cred_item(char *netname)
{
	struct creditem *toremove = NULL;

	if (toremove = (struct creditem *)nis_remove_item(netname,
	    &credtbl)) {
		free(toremove->item.name);
		free(toremove);
		return (TRUE);
	} else
		return (FALSE);
}

void
__nis_auth2princ(
	char *name,
	int flavor,
	caddr_t auth,
	bool_t refresh,
	int verbose)
{
	struct authsys_parms	*au;
	struct authdes_cred	*ad;
	char			*rmtdomain;
	char			srch[2048]; /* search criteria */
	nis_result		*res;

	srch[0] = '\0';

	(void) strcpy(name, nobody); /* default is "nobody" */
	if (flavor == AUTH_NONE) {
		if (verbose) {
			syslog(LOG_INFO,
		    "__nis_auth2princ: flavor = NONE: returning '%s'", nobody);
		}
		return;
	} else if (flavor == AUTH_SYS) { /* XXX ifdef this for 4.1 */
		/* LINTED pointer cast */
		au = (struct authsys_parms *)(auth);
		rmtdomain = nis_domain_of(au->aup_machname);
		if (au->aup_uid == 0) {
			(void) snprintf(name, MAX_MACHINE_NAME,
							"%s", au->aup_machname);
			if (!rmtdomain)
				(void) strcat(name, __nis_rpc_domain());
			if (name[strlen(name) - 1] != '.')
				(void) strcat(name, ".");
			if (verbose) {
				syslog(LOG_INFO,
		    "__nis_auth2princ: flavor = SYS: returning '%s'", name);
			}
			return;
		}
		(void) snprintf(srch,
				sizeof (srch) - 1,
		    "[auth_name=\"%d\", auth_type=LOCAL], cred.org_dir.%s",
				(int)au->aup_uid, (*rmtdomain == '.') ?
				(char *)nis_local_directory() : rmtdomain);
		if (srch[strlen(srch) - 1] != '.') {
			(void) strcat(srch, ".");
		}
	} else if (flavor == AUTH_DES) {
		/* LINTED pointer cast */
		ad = (struct authdes_cred *)(auth);
		if (refresh)
			(void) delete_cred_item(ad->adc_fullname.name);
		else
			if (find_cred_item(ad->adc_fullname.name, name)) {
				if (verbose)
					syslog(LOG_INFO,
		"__nis_auth2princ: flavor = DES: returning from cache '%s'",
					name);
				return;
			}

		rmtdomain = strchr(ad->adc_fullname.name, '@');
		if (rmtdomain) {
			rmtdomain++;
			(void) snprintf(srch,
					sizeof (srch) - 1,
			    "[auth_name=%s, auth_type=DES], cred.org_dir.%s",
					ad->adc_fullname.name, rmtdomain);
			if (srch[strlen(srch) - 1] != '.') {
				(void) strcat(srch, ".");
			}
		} else {
			if (verbose) {
				syslog(LOG_INFO,
			    "__nis_auth2princ: flavor = DES: returning '%s'",
					nobody);
			}
			return;
		}
	} else {
		syslog(LOG_WARNING,
		"__nis_auth2princ: flavor = %d(unknown): returning '%s'",
							flavor, nobody);
		return;
	}
	if (verbose)
		syslog(LOG_INFO,
			"__nis_auth2princ: calling list with name '%s'",
							name);
	res = nis_list(srch, NO_AUTHINFO+USE_DGRAM+FOLLOW_LINKS, NULL, NULL);
	if (res->status != NIS_SUCCESS) {
		if (verbose)
			syslog(LOG_INFO,
				"__nis_auth2princ: error doing nis_list: %s",
						nis_sperrno(res->status));
	} else {
		if (strlcpy(name,
		    ENTRY_VAL(res->objects.objects_val, 0), 1024) >= 1024) {
			(void) strcpy(name, nobody); /* default is "nobody" */
			syslog(LOG_ERR,
		"__nis_auth2princ: buffer overflow, returning '%s'", nobody);
			nis_freeresult(res);
			return;
		}
		if (flavor == AUTH_DES)
			add_cred_item(ad->adc_fullname.name, name);
	}

	nis_freeresult(res);
	if (verbose)
		syslog(LOG_INFO,
		"__nis_auth2princ: flavor = %s: returning : '%s'",
			flavor == AUTH_SYS? "SYS" : "DES", name);
}

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
__nis_gssprin2netname(rpc_gss_principal_t prin, char netname[MAXNETNAMELEN+1])
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

	/*
	 * If we got here then prin is not a gss netname type. Currently
	 * other types are not supported. To support the general case the
	 * prin type needs to be looked up in a table that will map an
	 * gss-api-export-name to a netname. The guts of the routine to do
	 * this, would look like this:
	 *
	 * char xport[NIS_MAXNAMELEN];
	 * char query[NIS_MAXNAMELEN];
	 * stat = -1;
	 * nis_result *r;
	 *
	 * bin2hex(expName.length, expName.value, xport);
	 * sprintf(query, "[gssprincipal=%s],gssprin.org_dir.%s", xport,
	 *		nis_local_directory());
	 * r = nis_list(query, 0, 0, 0);
	 * if (r->status == NIS_SUCCESS) {
	 *	stat = 0;
	 *	strcpy(netname, ENTRY_VAL(r->objects.object_val, 1);
	 * }
	 * nis_freeresult(r);
	 * return (stat);
	 *
	 * Here it is assumed that the gssprin table containes two columns.
	 * The first, gssprincipal, contains the exported gss principal name
	 * in hex format. And the second, netname, that contains the secure
	 * rpc netname.
	 */

	return (stat);
}

static char *
flavor2str(int flavor)
{
	switch (flavor) {
	case AUTH_NONE:
		return ("NONE");
	case AUTH_SYS:
		return ("SYS");
	case AUTH_DES:
		return ("DES");
	case RPCSEC_GSS:
		return ("GSS");
	default:
		return ("unknown");
	}
}

/*
 * Based on __nis_auth2princ but this one has RPCSEC_GSS support.
 */
void
__nis_auth2princ_rpcgss(
	char	*name,		/* out */
	struct svc_req *req,	/* in */
	bool_t	refresh,	/* in */
	int	verbose)	/* in */
{
	struct authsys_parms	*au;
	struct authdes_cred	*ad;
	char			*rmtdomain;
	char			srch[2048]; /* search criteria */
	nis_result		*res;
	caddr_t			auth;
	char			auth_type[MECH_MAXATNAME]; /* cred tbl field */
	char			netname[MAXNETNAMELEN+1] = {0}; /* RPC netnm */
	int			flavor;	/* secure RPC flavor */

	srch[0] = '\0';

	if (req) {
		flavor = req->rq_cred.oa_flavor;
		auth = req->rq_clntcred;
	} else {
		if (verbose)
			syslog(LOG_ERR,
			"_auth2princ_rpcgss: req = NULL: returning '%s'",
				nobody);
		return;
	}
	(void) strcpy(name, nobody); /* default is "nobody" */
	if (flavor == AUTH_NONE) {
		if (verbose) {
			syslog(LOG_INFO,
		    "__nis_auth2princ_rpcgss: flavor = NONE: returning '%s'",
				nobody);
		}
		return;
	} else if (flavor == AUTH_SYS) { /* XXX ifdef this for 4.1 */
		/* LINTED pointer cast */
		au = (struct authsys_parms *)(auth);
		rmtdomain = nis_domain_of(au->aup_machname);
		if (au->aup_uid == 0) {
			(void) snprintf(name, MAX_MACHINE_NAME,
						"%s", au->aup_machname);
			if (!rmtdomain)
				(void) strcat(name, __nis_rpc_domain());
			if (name[strlen(name) - 1] != '.')
				(void) strcat(name, ".");
			if (verbose) {
				syslog(LOG_INFO,
	"__nis_auth2princ_rpcgss: flavor = SYS: returning '%s'", name);
			}
			return;
		}
		(void) snprintf(srch,
				sizeof (srch) - 1,
		    "[auth_name=\"%ld\", auth_type=LOCAL], cred.org_dir.%s",
				au->aup_uid, (*rmtdomain == '.') ?
				(char *)nis_local_directory() : rmtdomain);
		if (srch[strlen(srch) - 1] != '.') {
			(void) strcat(srch, ".");
		}
	} else if (flavor == AUTH_DES) {
		/* LINTED pointer cast */
		ad = (struct authdes_cred *)(auth);
		if (refresh)
			(void) delete_cred_item(ad->adc_fullname.name);
		else
			if (find_cred_item(ad->adc_fullname.name, name)) {
				if (verbose)
					syslog(LOG_INFO,
	"__nis_auth2princ_rpcgss: flavor = DES: returning from cache '%s'",
					name);
				return;
			}

		rmtdomain = strchr(ad->adc_fullname.name, '@');
		if (rmtdomain) {
			rmtdomain++;
			(void) snprintf(srch,
					sizeof (srch) - 1,
			    "[auth_name=%s, auth_type=DES], cred.org_dir.%s",
					ad->adc_fullname.name, rmtdomain);
			if (srch[strlen(srch) - 1] != '.') {
				(void) strcat(srch, ".");
				(void) strncpy(netname, ad->adc_fullname.name,
						sizeof (netname));
				netname[sizeof (netname) - 1] = '\0';
			}
		} else {
			if (verbose) {
				syslog(LOG_INFO,
		"__nis_auth2princ_rpcgss: flavor = DES: returning '%s'",
					nobody);
			}
			return;
		}
	} else if (flavor == RPCSEC_GSS) {
		rpc_gss_rawcred_t	*rcred;
		void			*cookie;

		if (!rpc_gss_getcred(req, &rcred, NULL, &cookie)) {
			if (verbose) {
				syslog(LOG_WARNING,
	"__nis_auth2princ_rpcgss: GSS getcred failure:  returning '%s'",
					nobody);
			}
			return;
		}

		if (__nis_gssprin2netname(rcred->client_principal, netname)
					< 0) {
			syslog(LOG_ERR,
"__nis_auth2princ_rpcgss: can't extract netname from gss cred: returning '%s'",
				nobody);
			return;
		}

		if (refresh)
			(void) delete_cred_item(netname);
		else
			if (find_cred_item(netname, name)) {
				if (verbose)
					syslog(LOG_INFO,
"__nis_auth2princ_rpcgss: flavor = RPCSEC_GSS: returning from cache '%s'",
					name);
				return;
			}

		rmtdomain = strchr(netname, '@');
		if (rmtdomain) {
			char alias[MECH_MAXALIASNAME+1] = { 0 };

			rmtdomain++;
			if (!__nis_mechname2alias(rcred->mechanism, alias,
			    sizeof (alias))) {
				syslog(LOG_ERR,
	"__nis_auth2princ_rpcgss: mechname '%s' not found: returning 'nobody'",
					rcred->mechanism);
				return;
			}

			if (alias[0] != '\0') {
				(void) __nis_mechalias2authtype(alias,
						auth_type, sizeof (auth_type));

				(void) snprintf(srch, sizeof (srch) - 1,
			    "[auth_name=%s, auth_type=%s], cred.org_dir.%s",
					netname, auth_type, rmtdomain);

				if (srch[strlen(srch) - 1] != '.') {
					(void) strcat(srch, ".");
				}
			} else {
				syslog(LOG_ERR,
"__nis_auth2princ_rpcgss: no alias found for mechname '%s': returning 'nobody'",
					rcred->mechanism);
				return;
			}
		} else {
			if (verbose) {
				syslog(LOG_INFO,
		"__nis_auth2princ_rpcgss: flavor = RPCSEC_GSS: returning '%s'",
				nobody);
			}
			return;
		}
	} else {
		syslog(LOG_WARNING,
		"__nis_auth2princ_rpcgss: flavor = %d(unknown): returning '%s'",
							flavor, nobody);
		return;
	}
	if (verbose)
		if (flavor == AUTH_DES || flavor == RPCSEC_GSS)
			syslog(LOG_INFO,
	"__nis_auth2princ_rpcgss: calling list with name '%s' and type '%s'",
							netname,
				flavor == AUTH_DES ? "DES" : auth_type);
		else /* AUTH_SYS */
			syslog(LOG_INFO,
		"__nis_auth2princ_rpcgss: calling list with uid (LOCAL) '%d'",
				au->aup_uid);

	res = nis_list(srch, NO_AUTHINFO+USE_DGRAM+FOLLOW_LINKS, NULL, NULL);
	if (res->status != NIS_SUCCESS) {
		if (verbose)
			syslog(LOG_INFO,
			"__nis_auth2princ_rpcgss: error doing nis_list: %s",
						nis_sperrno(res->status));
	} else {
		if (strlcpy(name,
		    ENTRY_VAL(res->objects.objects_val, 0), 1024) >= 1024) {
			(void) strcpy(name, nobody); /* default is "nobody" */
			syslog(LOG_ERR,
		"__nis_auth2princ_rpcgss: buffer overflow, returning '%s'",
		nobody);
			nis_freeresult(res);
			return;
		}
		if (flavor == AUTH_DES || flavor == RPCSEC_GSS) {
			if (verbose)
				syslog(LOG_INFO,
				"__nis_auth2princ_rpcgss: caching '%s'/'%s'\n",
					netname, name);
			add_cred_item(netname, name);
		}
	}

	nis_freeresult(res);
	if (verbose)
		syslog(LOG_INFO,
		"__nis_auth2princ_rpcgss: flavor = %s: returning : '%s'",
			flavor2str(flavor), name);

}

/*
 * This function returns true if the given principal has the right to
 * do the requested function on the given object. It could be a define
 * if that would save time. At the moment it is a function.
 * NOTE: It recursively calls NIS by doing the lookup on the group if
 * the conditional gets that far.
 *
 * N.B. If the principal passed is 'null' then we're recursing and don't
 * need to check it. (we always let ourselves look at the data)
 */
bool_t
__nis_ck_perms(
	unsigned int	right,	/* The Access right we desire 		*/
	unsigned int	mask,	/* The mask for World/Group/Owner 	*/
	nis_object	*obj,	/* A pointer to the object		*/
	nis_name	pr,	/* Principal making the request		*/
	int		level)	/* security level server is running at	*/
{
	if ((level == 0) || (*pr == 0))
		return (TRUE);

	return (NIS_NOBODY(mask, right) ||
		(NIS_WORLD(mask, right) && (strcmp(pr, "nobody") != 0)) ||
		(NIS_OWNER(mask, right) &&
			(nis_dir_cmp(pr, obj->zo_owner) == SAME_NAME)) ||
		(NIS_GROUP(mask, right) &&
			(strlen(obj->zo_group) > (size_t)(1)) &&
			__do_ismember(pr, obj, nis_lookup)));
}

/*
 * is 'host' the master server for "org_dir."'domain' ?
 */
bool_t
__nis_ismaster(char *host, char *domain)
{
	nis_server	**srvs;		/* servers that serve 'domain' */
	nis_server	*master_srv;
	char		buf[NIS_MAXNAMELEN];
	bool_t		res;

	if (domain == NULL) {
		syslog(LOG_ERR, "__nis_ismaster(): null domain");
		return (FALSE);
	}
	/* strlen(".org_dir") + null + "." = 10 */
	if ((strlen(domain) + 10) > (size_t)NIS_MAXNAMELEN)
		return (FALSE);

	(void) snprintf(buf, sizeof (buf), "org_dir.%s", domain);
	if (buf[strlen(buf) - 1] != '.')
		(void) strcat(buf, ".");

	srvs = nis_getservlist(buf);
	if (srvs == NULL) {
		/* can't find any of the servers that serve this domain */
		/* something is very wrong ! */
		syslog(LOG_ERR,
			"cannot get a list of servers that serve '%s'",
			buf);
		return (FALSE);
	}
	master_srv = srvs[0];	/* the first one is always the master */

	if (strcasecmp(host, master_srv->name) == 0)
		res = TRUE;
	else
		res = FALSE;

	/* done with server list */
	nis_freeservlist(srvs);

	return (res);
}

/*
 * check if this principal is the owner of the table
 * or is a member of the table group owner
 */
bool_t
__nis_isadmin(char *princ, char *table, char *domain)
{
	char	buf[NIS_MAXNAMELEN];
	struct	nis_result	*res;
	struct	nis_object	*obj;
	bool_t	ans = FALSE;

	if ((princ == NULL || *princ == '\0') ||
		(table == NULL || *table == '\0') ||
		(domain == NULL || *domain == '\0'))
		return (FALSE);

	/* strlen(".org_dir.") + null + "." = 11 */
	if ((strlen(table) + strlen(domain) + 11) >
			(size_t)NIS_MAXNAMELEN) {
		syslog(LOG_ERR, "__nis_isadmin: buffer too small");
		return (FALSE);
	}
	(void) snprintf(buf, sizeof (buf), "%s.org_dir.%s", table, domain);
	if (buf[strlen(buf) - 1] != '.')
		(void) strcat(buf, ".");

	/* get the table object */
	res = nis_lookup(buf, FOLLOW_LINKS);
	if (res->status != NIS_SUCCESS) {
		syslog(LOG_ERR,
			"__nis_isadmin: could not lookup '%s' table",
			table);
		nis_freeresult(res);
		return (FALSE);
	}
	obj = NIS_RES_OBJECT(res);
	if (obj->zo_data.zo_type != NIS_TABLE_OBJ) {
		syslog(LOG_ERR, "__nis_isadmin: not a table object");
		nis_freeresult(res);
		return (FALSE);
	}
	if ((strcasecmp(obj->zo_owner, princ) == 0) ||
		((obj->zo_group) && (*(obj->zo_group)) &&
			nis_ismember(princ, obj->zo_group)))
		ans = TRUE;

	nis_freeresult(res);
	return (ans);
}

#define	NIS_NOHOSTNAME	48
#define	NIS_NOHOSTADDR	49

nis_server *
__nis_host2nis_server(
	char	*host,		/* host name */
	bool_t	addpubkey,	/* add pub key info */
	int	*errcode)	/* error code */
{
	return (__nis_host2nis_server_g(host, addpubkey, TRUE,
						    errcode));
}

static void
nis_free_endpoints(endpoint *ep, int n)
{
	int i;

	if (ep != NULL) {
		for (i = 0; i < n; i++) {
			if (ep[i].uaddr != NULL)
				free(ep[i].uaddr);
			if (ep[i].family != NULL)
				free(ep[i].family);
			if (ep[i].proto != NULL)
				free(ep[i].proto);
		}
		free(ep);
	}
}

void
__free_nis_server(nis_server *server)
{
	if (server != NULL) {
		free(server->name);
		nis_free_endpoints(server->ep.ep_val,
			server->ep.ep_len);
		free(server->pkey.n_bytes);
		free(server);
	}
}

/*
 * This function constructs a server description of the host
 * given (or the local host) and returns it as a nis_server
 * structure.
 * Returns NULL on error, and sets the errcode.
 */
nis_server *
__nis_host2nis_server_g(const char *host,
			bool_t	addpubkey,
			bool_t	loopback,
			int	*errcode)
{
#define	INC_SIZE 512
	int			addr_size = 0;
	endpoint		*addr, *oldaddr;
	nis_server		*hostinfo;
	int			num_ep = 0, i;
	struct netconfig	*nc;
	void			*nch;
	struct nd_hostserv	hs;
	struct nd_addrlist	*addrlist;
	char			hostnetname[NIS_MAXPATH];
	struct hostent		*he;
	char			netname[MAXNETNAMELEN];
	char			hostname[MAXHOSTNAMELEN+1];
	char			pkey[HEXKEYBYTES+1];
	mechanism_t		**mechlist;
	size_t			hlen;

	if (host) {
		he = gethostbyname(host);
		if (!he) {
			if (errcode)
				*errcode = NIS_BADNAME;
			return (NULL);
		}

		hlen = strlen(host);
		if (hlen + 1 >= sizeof (hostnetname) ||
				hlen >= sizeof (hostname)) {
			if (errcode)
				*errcode = NIS_BADNAME;
			return (NULL);
		}
		(void) strcpy(hostname, host);
		hs.h_host = hostname;

		/*
		 * Make attempt to fully qualify hostname.  If hostname
		 * contains a dot, then assume it is already fully
		 * qualified and just add a trailing dot.  Otherwise,
		 * append local domain name.
		 */

		(void) strcpy(hostnetname, host);
		if (strchr(hostnetname, '.') == 0) {
			char *localDir = nis_local_directory();
			size_t reqlen = hlen + strlen(localDir);
			if (*localDir != '.') {
				(void) strcat(hostnetname, ".");
				reqlen += 1;
			}
			if (reqlen >= sizeof (hostnetname)) {
				if (errcode)
					*errcode = NIS_BADNAME;
				return (NULL);
			}
			(void) strcat(hostnetname, localDir);
		}
		if (hostnetname[strlen(hostnetname)-1] != '.')
			(void) strcat(hostnetname, ".");
	} else {
		if (gethostname(hostname, sizeof (hostname)) != 0) {
			if (errcode)
				*errcode = NIS_NOHOSTNAME;
			return (NULL);
		}
		hs.h_host = HOST_SELF_CONNECT;
	}

	if (!(nch = setnetconfig()))
		return (NULL);

	hs.h_serv = "rpcbind";

	addr = NULL;
	while (nc = getnetconfig(nch)) {
		if (!loopback && (strcmp(nc->nc_protofmly, NC_LOOPBACK) == 0))
			continue;
		if (netdir_getbyname(nc, &hs, &addrlist))
			continue;
		for (i = 0; i < addrlist->n_cnt; i++, num_ep++) {
			if (num_ep == addr_size) {
				addr_size += INC_SIZE;
				oldaddr = addr;
				addr = realloc(addr,
					addr_size * sizeof (endpoint));
				if (addr == NULL) {
				    if (errcode)
					*errcode = NIS_NOMEMORY;
				    (void) endnetconfig(nch);
				    nis_free_endpoints(oldaddr, num_ep);
				    netdir_free((char *)addrlist, ND_ADDRLIST);
				    return (NULL);
				}
			}
			addr[num_ep].uaddr =
				taddr2uaddr(nc, &(addrlist->n_addrs[i]));
			if (!addr[num_ep].uaddr) {
				if (errcode)
					*errcode = NIS_NOMEMORY;
				(void) endnetconfig(nch);
				nis_free_endpoints(addr, num_ep);
				netdir_free((char *)addrlist, ND_ADDRLIST);
				return (NULL);
			}
			__nis_netconfig2ep(nc, &(addr[num_ep]));
		}
		netdir_free((char *)addrlist, ND_ADDRLIST);
	}
	(void) endnetconfig(nch);

	if ((hostinfo = calloc(1, sizeof (nis_server))) == NULL) {
		nis_free_endpoints(addr, num_ep);
		if (errcode)
			*errcode = NIS_NOMEMORY;
		return (NULL);
	}

	hostinfo->ep.ep_len = num_ep;
	hostinfo->ep.ep_val = addr;

	hostinfo->name = (host) ?
		strdup(hostnetname) : strdup(nis_local_host());
	if (hostinfo->name == NULL) {
		__free_nis_server(hostinfo);
		if (errcode)
			*errcode = NIS_NOMEMORY;
		return (NULL);
	}

	if (addpubkey) {
		if (!host2netname(netname, hostinfo->name, NULL))
			goto nocred;

		if (mechlist = __nis_get_mechanisms(0)) {
			bool_t		got192 = FALSE, gotothers = FALSE;
			extdhkey_t	*keylist = NULL;
			size_t		keylistsize = 0;
			int		i;

			for (i = 0; mechlist[i]; i++) {
				size_t		binlen, binpadlen, hexkeylen,
						keyoffset;
				char		*hexkey, *entryoffset;
				extdhkey_t	*curentry, *oldkeylist;
				keylen_t	keylen = mechlist[i]->keylen;
				algtype_t	algtype = mechlist[i]->algtype;

				binlen = (keylen + 7) / 8;
				binpadlen = ((binlen + 3) / 4) * 4;
				hexkeylen = binlen * 2 + 1;

				if (!(hexkey = malloc(hexkeylen))) {
					__nis_release_mechanisms(mechlist);
					__free_nis_server(hostinfo);
					free(keylist);
					if (errcode)
						*errcode = NIS_NOMEMORY;
					return (NULL);
				}

				if (getpublickey_g(netname, keylen, algtype,
							hexkey,
							hexkeylen) == 0) {
					free(hexkey);
					continue;
				} else {
					if (keylen == 192)
						got192 = TRUE;
					else
						gotothers = TRUE;
				}

				keyoffset = keylistsize;
				keylistsize += sizeof (ushort_t) * 2 +
					binpadlen;
				oldkeylist = keylist;
				if (!(keylist = realloc(keylist,
							    keylistsize))) {
					free(oldkeylist);
					free(hexkey);
					__nis_release_mechanisms(mechlist);
					__free_nis_server(hostinfo);
					if (errcode)
						*errcode = NIS_NOMEMORY;
					return (NULL);
				}

				entryoffset = (char *)keylist + keyoffset;
				/* LINTED pointer cast */
				curentry = (extdhkey_t *)entryoffset;

				curentry->keylen = htons(keylen);
				curentry->algtype = htons(algtype);
				hex2bin(binlen, hexkey, (char *)curentry->key);

				free(hexkey);
			}
			__nis_release_mechanisms(mechlist);

			/*
			 * If there is only keys for DH192, then we pretend
			 * that DHEXT doesn't exist.
			 *
			 * If no keys are returned, then we no nuthin'.
			 */
			if (!gotothers) {
				free(keylist);
				if (got192)
					goto only192;
				else
					goto nocred;
			}

			hostinfo->key_type = NIS_PK_DHEXT;
			hostinfo->pkey.n_len = (ushort_t)keylistsize;
			hostinfo->pkey.n_bytes = (char *)keylist;
		} else {
			if (getpublickey(netname, pkey)) {
only192:			hostinfo->key_type = NIS_PK_DH;
				hostinfo->pkey.n_len = strlen(pkey)+1;
				hostinfo->pkey.n_bytes = (char *)strdup(pkey);
				if (hostinfo->pkey.n_bytes == NULL) {
					__free_nis_server(hostinfo);
					if (errcode)
						*errcode = NIS_NOMEMORY;
					return (NULL);
				}
			} else {
nocred:				hostinfo->key_type = NIS_PK_NONE;
				hostinfo->pkey.n_bytes = NULL;
				hostinfo->pkey.n_len = 0;
			}
		}
	} else
		goto nocred;

	return (hostinfo);
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


/*
 * Returns a list of key lengths and alg. types for a given nis_server
 * structure.
 */
int
__nis_dhext_extract_keyinfo(nis_server *ns, extdhkey_t **retdat)
{
	extdhkey_t	*keyinfolist = NULL, *tmplist = NULL;
	int		count = 0;
	/* LINTED pointer cast */
	extdhkey_t	*keyent = (extdhkey_t *)ns->pkey.n_bytes;

	switch (ns->key_type) {
	case	NIS_PK_DH:
		if (!(keyinfolist = malloc(sizeof (extdhkey_t))))
			return (0);
		keyinfolist[0].keylen = 192;
		keyinfolist[0].algtype = 0;

		*retdat = keyinfolist;
		return (1);

	case	NIS_PK_DHEXT:
		/* LINTED pointer cast */
		while (keyent < (extdhkey_t *)(ns->pkey.n_bytes +
			ns->pkey.n_len)) {
			size_t	binlen = (keyent->keylen + 7) / 8;
			size_t	binpadlen = ((binlen + 3) / 4) * 4;
			char	*keyoffset;

			tmplist = keyinfolist;

			if (!(keyinfolist = realloc(keyinfolist,
						    (count + 1) *
						    sizeof (extdhkey_t)))) {
				free(tmplist);
				return (0);
			}
			keyinfolist[count].keylen = ntohs(keyent->keylen);
			keyinfolist[count].algtype = ntohs(keyent->algtype);

			keyoffset = (char *)keyent + (sizeof (ushort_t) * 2) +
				binpadlen;
			/* LINTED pointer cast */
			keyent = (extdhkey_t *)keyoffset;
			count++;
		}
		*retdat = keyinfolist;
		return (count);

		default:
			return (0);
	}
}
