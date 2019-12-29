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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <syslog.h>
#include <errno.h>
#include <pwd.h>
#include <libintl.h>
#include <netdb.h>	/* for rcmd() */

#include <ns.h>
#include <list.h>

#define	LDAP_REFERRALS
#include <lber.h>
#include <ldap.h>
#include <sys/systeminfo.h>


/*
 * This modules contains the code required to manipulate printer objects in
 * a LDAP directory for the Naming Service (NS) switch.
 * It can "add", "modify" and "delete" the objects on the given ldap server
 * and in the given NS domain DN, eg. "dc=mkg,dc=sun,dc=com".
 * Note: printers known to the naming service are contained in the RDN
 * "ou=printers" under the NS domain DN
 */

#define	PCONTAINER	"ou=printers"

/* attribute keywords */
#define	ATTR_DN		"dn"
#define	ATTR_OCLASS	"objectClass"
#define	ATTR_URI	"printer-uri"
#define	ATTR_PNAME	"printer-name"
#define	ATTR_XRISUP	"printer-xri-supported"
#define	ATTR_BSDADDR	"sun-printer-bsdaddr"
#define	ATTR_KVP	"sun-printer-kvp"

/* objectClass values */
#define	OCV_TOP		"top"
#define	OCV_PSERVICE	"printerService"
#define	OCV_SUNPRT	"sunPrinter"
#define	OCV_PABSTRACT	"printerAbstract"

/* xri-supported attribute value */
#define	AV_UNKNOWN	"unknown"


/*
 * LDAP objectclass atributes that the user can explicity change
 */

static const char *nsl_attr_printerService[] = {
	"printer-uri",
	"printer-xri-supported",
	/* Not allowed "printer-name", */
	"printer-natural-language-configured",
	"printer-location",
	"printer-info",
	"printer-more-info",
	"printer-make-and-model",
	"printer-charset-configured",
	"printer-charset-supported",
	"printer-generated-natural-language-supported",
	"printer-document-format-supported",
	"printer-color-supported",
	"printer-compression-supported",
	"printer-pages-per-minute",
	"printer-pages-per-minute-color",
	"printer-finishings-supported",
	"printer-number-up-supported",
	"printer-sides-supported",
	"printer-media-supported",
	"printer-media-local-supported",
	"printer-resolution-supported",
	"printer-print-quality-supported",
	"printer-job-priority-supported",
	"printer-copies-supported",
	"printer-job-k-octets-supported",
	"printer-current-operator",
	"printer-service-person",
	"printer-delivery-orientation-supported",
	"printer-stacking-order-supported",
	"printer-output-features-supported",
	(char *)NULL
};


static const char *nsl_attr_printerIPP[] = {
	"printer-ipp-versions-supported",
	"printer-multiple-document-jobs-supported",
	(char *)NULL
};

static const char *nsl_attr_sunPrinter[] = {
	/* Not allowed "sun-printer-bsdaddr", */
	/* Not allowed "sun-printer-kvp", */
	(char *)NULL
};


/*
 * List of LDAP attributes that user is not allowed to explicitly change
 */
static const char *nsl_attr_notAllowed[] = {
	ATTR_DN,
	ATTR_OCLASS,		/* objectclass */
	ATTR_PNAME,		/* printer-name */
	ATTR_BSDADDR,
	ATTR_KVP,
	(char *)NULL
};


static NSL_RESULT _connectToLDAP(ns_cred_t *cred, LDAP **ld);
static uchar_t *_constructPrinterDN(uchar_t *printerName,
				uchar_t *domainDN, char **attrList);
static NSL_RESULT _checkPrinterExists(LDAP *ld, uchar_t *printerName,
			uchar_t *domainDN, uchar_t **printerDN);
static NSL_RESULT _checkPrinterDNExists(LDAP *ld, uchar_t *objectDN);
static NSL_RESULT _checkSunPrinter(LDAP *ld, uchar_t *printerDN);
static NSL_RESULT _addNewPrinterObject(LDAP *ld, uchar_t *printerName,
					uchar_t *domainDN, char **attrList);
static NSL_RESULT _modifyPrinterObject(LDAP *ld, uchar_t *printerDN,
		uchar_t *printerName, uchar_t *domainDN, char **attrList);
static NSL_RESULT _checkAttributes(char **list);
static NSL_RESULT _addLDAPmodValue(LDAPMod ***attrs, char *type, char *value);
static NSL_RESULT _modLDAPmodValue(LDAPMod ***attrs, char *type, char *value);
static NSL_RESULT _constructAddLDAPMod(uchar_t *printerName,
					char **attrList,  LDAPMod ***attrs);
static NSL_RESULT _constructModLDAPMod(uchar_t *printerName, int sunPrinter,
			char **attrList, char ***oldKVPList, LDAPMod ***attrs);
static NSL_RESULT _compareURIinDNs(uchar_t *dn1, uchar_t *dn2);
static uchar_t *_getThisNSDomainDN(void);
static int _popen(char *cmd, char *results, int size);
static int _attrInList(char *attr, const char **list);
static int _attrInLDAPList(char *attr);
static NSL_RESULT _getCurrentKVPValues(LDAP *ld,
					uchar_t *objectDN, char ***list);
static void _freeList(char ***list);
static NSL_RESULT _modAttrKVP(char *value, char ***kvpList);
static NSL_RESULT _attrAddKVP(LDAPMod ***attrs, char **kvpList, int kvpExists);
static int _manageReferralCredentials(LDAP *ld, char **dn, char **credp,
	int *methodp, int freeit, void *);

/*
 * *****************************************************************************
 *
 * Function:    ldap_put_printer()
 *
 * Description: Action the request to change a printer object in the LDAP
 *              directory DIT. The object is either added, modified or deleted
 *              depending on the request's attribute list. A null list indicates
 *              the request is a delete.
 *              The object's DN is constructed from the supplied domain DN and
 *              a check is done to see if the object exists already, if it
 *              doesn't exist then this is a request to add a new object
 *              If a URI is given in the attribute list and it is different to
 *              the existing printing object's DN then the request will be
 *              rejected.
 *
 *
 * Parameters:
 * Input:       const ns_printer_t *printer
 *                - this structure contains the following :
 *                  char *printerName - name of the printer
 *                  ns_cred_t *cred - structure containing the ldap host and
 *                                port, user, password and NS domain DN for the
 *                                directory server to be updated.
 *                  char **attrList - pointer to a list of attribute key values
 *                                for the printer object. If the object does
 *                                not already exist then this list contains the
 *                                values for the new object, otherwise this list
 *                                is a list of attributes to modify. For modify
 *                                a null attribute value is a attribute delete
 *                                request. A NULL ptr = delete the object.
 * Output:      None
 *
 * Returns:     int - 0 = request actioned okay
 *                   !0 = error - see NSL_RESULT codes
 *
 * *****************************************************************************
 */

int
ldap_put_printer(const ns_printer_t *printer)

{
	NSL_RESULT result = NSL_OK;
	NSL_RESULT printerExists = NSL_ERR_UNKNOWN_PRINTER;
	LDAP *ld = NULL;
	uchar_t *printerDN = NULL;
	uchar_t *domainDN = NULL;
	char *printerName = NULL;
	ns_cred_t *cred = NULL;
	char **attrList = NULL;

	/* -------- */

	/*
	 * Note: the "attributes" list should be null for ldap as the attribute
	 * values are passed in the nsdata field
	 */

	if ((printer != NULL) &&
	    (printer->attributes == NULL) && (printer->name != NULL))
	{
		/* extract required pointer values from structure */

		printerName = printer->name;
		cred = printer->cred;
		if (printer->nsdata != NULL)
		{
			attrList = ((NS_LDAPDATA *)(printer->nsdata))->attrList;
		}

		/* connect and bind to the ldap directory server */

		result = _connectToLDAP(cred, &ld);
		if ((result == NSL_OK) && (ld != NULL))
		{
			/*
			 * check if the NS domain DN was given, if not use the
			 * current NS domain
			 */

			if (cred->domainDN != NULL)
			{
				domainDN = (uchar_t *)
					strdup((char *)cred->domainDN);
			}
			else
			{
				/* get DN of current domain */
				domainDN = _getThisNSDomainDN();
			}

			printerExists =
				_checkPrinterExists(ld, (uchar_t *)printerName,
							domainDN, &printerDN);
			if (printerExists != LDAP_SUCCESS)
			{
				/*
				 * could not find the printer by printer-name,
				 * but there could be a non sunPrinter object
				 * so if the printer-uri was given check if
				 * an object for that exists
				 */
				printerDN =
				    _constructPrinterDN(NULL,
							domainDN, attrList);
				if (printerDN != NULL)
				{
					printerExists = _checkPrinterDNExists(
								ld, printerDN);
				}
			}
#ifdef DEBUG
if (printerExists == NSL_OK)
{
printf("DN found = '%s' for '%s'\n", printerDN, printerName);
}
#endif

			if (attrList == NULL)
			{
				/*
				 * a null list indicates that this is a DELETE
				 * object request, so if object exists delete
				 * it, otherwise report an error.
				 */
				if (printerExists == LDAP_SUCCESS)
				{
				    result = ldap_delete_s(ld,
						(char *)printerDN);
				    if (result != LDAP_SUCCESS)
				    {
					result = NSL_ERR_DEL_FAILED;
#ifdef DEBUG
ldap_perror(ld, "ldap_delete_s failed");
#endif
				    }
				}
				else
				{
				    result = NSL_ERR_UNKNOWN_PRINTER;
				}
			}
			else
			{
				/*
				 * if object exists then this is a
				 * modify request otherwise is is an add request
				 */

				if (printerExists == LDAP_SUCCESS)
				{
					/*
					 * Modify the printer object to
					 * give it the new attribute values
					 * specified by the user
					 */
					result =
					_modifyPrinterObject(ld, printerDN,
						(uchar_t *)printerName,
						domainDN, attrList);
				}
				else
				{
					/*
					 * add new printer object into the
					 * ldap directory with the user
					 * specified attribute values
					 */
					result =
					    _addNewPrinterObject(ld,
						(uchar_t *)printerName,
						domainDN, attrList);
				}
			}

			if (printerDN != NULL)
			{
				free(printerDN);
			}
			if (domainDN != NULL)
			{
				free(domainDN);
			}

			/* disconnect from LDAP server */

			(void) ldap_unbind(ld);
		}
	}

	else
	{
		/* no printerName given */
		result = NSL_ERR_INTERNAL;
	}

	return ((int)result);
} /* ldap_put_printer */




/*
 * *****************************************************************************
 *
 * Function:    _connectToLDAP()
 *
 * Description: Setup the connection and bind to the LDAP directory server.
 *              The function returns the ldap connection descriptor
 *
 * Note:        Currently the native ldap functions do not support secure
 *              passwords, when this is supported this function will require
 *              updating to allow the type passed in cred->passwdType to
 *              be used with the ldap_simple_bind()
 *
 * Parameters:
 * Input:       ns_cred_t *cred - structure containing the credentials (host,
 *                                port, user and password) required to bind
 *                                to the directory server to be updated.
 *              char *printerName - printer name used only for error messages
 * Output:      LDAP** - ldap connection descriptor pointer. NULL = failed
 *
 * Returns:     NSL_RESULT - NSL_OK = connected okay
 *
 * *****************************************************************************
 */

static NSL_RESULT
_connectToLDAP(ns_cred_t *cred, LDAP **ld)

{
	NSL_RESULT result = NSL_OK;
	int lresult = 0;
	int ldapPort = LDAP_PORT;	/* default LDAP port number */
	int protoVersion = LDAP_VERSION3;
	int derefOption = LDAP_DEREF_NEVER;
	int referrals = 1;
	char hostname[MAXHOSTNAMELEN];
	int tmpMethod = LDAP_AUTH_SIMPLE; /* temp - until its passed in */

	/* -------- */

	if ((ld == NULL) || (cred == NULL) ||
		((cred->passwd == NULL) || (cred->binddn == NULL)))
	{
		result = NSL_ERR_CREDENTIALS;
	}

	else
	{
		*ld = NULL;

		/* if host was not given then bind to local host */

		if (cred->host != NULL)
		{
			(void) strlcpy(hostname, cred->host, sizeof (hostname));
		}
		else
		{
			(void) sysinfo(SI_HOSTNAME,
					hostname, sizeof (hostname));
		}

		/* initialise the connection to the ldap server */

		if (cred->port != 0)
		{
			ldapPort = cred->port;
		}
		*ld = ldap_init(hostname, ldapPort);
		if (*ld == NULL)
		{
			/* connection setup failed */
			result = NSL_ERR_CONNECT;
#ifdef DEBUG
(void) perror("ldap_init");
#endif
		}
		else
		{
			/* set ldap options */

			(void) ldap_set_option(*ld, LDAP_OPT_DEREF,
						&derefOption);
			(void) ldap_set_option(*ld, LDAP_OPT_PROTOCOL_VERSION,
						&protoVersion);
			(void) ldap_set_option(*ld, LDAP_OPT_REFERRALS,
						&referrals);

			/* bind to the user DN in the directory */

			/* cred->passwdType is currently not supported */

			lresult = ldap_simple_bind_s(*ld,
						cred->binddn, cred->passwd);

			/*
			 * before doing anything else, set up the function to
			 * call to get authentication details if the
			 * ldap update function calls (eg. ldap_add_s()) get a
			 * "referral" (to another ldap server) from the
			 * original ldap server, eg. if we are trying to do
			 * a update on a LDAP replica server.
			 */
			(void) _manageReferralCredentials(*ld,
					&(cred->binddn), &(cred->passwd),
					&tmpMethod, -1, NULL);
			ldap_set_rebind_proc(*ld,
				_manageReferralCredentials, NULL);

			if (lresult != LDAP_SUCCESS)
			{
				result = NSL_ERR_BIND;
				*ld = NULL;
#ifdef DEBUG
(void) ldap_perror(*ld, "ldap_simple_bind_s");
#endif
			}
		}
	}

	return (result);
} /* _connectToLDAP */





/*
 * *****************************************************************************
 *
 * Function:    _constructPrinterDN()
 *
 * Description: Construct the DN for the printer object from its name and NS
 *              domain DN. If the printer-uri is given in the attrList then
 *              that is used instead of the printerName.
 *
 * Parameters:
 * Input:       uchar_t *printerName
 *              uchar_t *domainDN
 *              char **attrList - this list is searched for printer-uri
 * Output:      None
 *
 * Returns:     uchar_t* - pointer to the DN, this memory is malloced so
 *                         must be freed using free() when finished with.
 *
 * *****************************************************************************
 */

static uchar_t *
_constructPrinterDN(uchar_t *printerName, uchar_t *domainDN, char **attrList)

{
	uchar_t *dn = NULL;
	uchar_t *uri = NULL;
	char **p = NULL;
	int len = 0;

	/* ------- */

	/* first search for printer-uri in the attribute list */

	for (p = attrList; (p != NULL) && (*p != NULL) && (uri == NULL); p++)
	{
		/* get length of this key word */

		for (len = 0; ((*p)[len] != '=') && ((*p)[len] != '\0'); len++);

		if ((strncasecmp(*p, ATTR_URI, len) == 0) &&
		    (strlen(*p) > len+1))
		{
			uri = (uchar_t *)&((*p)[len+1]);
		}
	}


	if (domainDN != NULL) {
		size_t size;

		/* malloc memory for the DN and then construct it */

		if ((uri == NULL) && (printerName != NULL))
		{
			/* use the printerName for the RDN */

			size = strlen(ATTR_URI) +
			    strlen((char *)printerName) +
			    strlen((char *)domainDN) +
			    strlen(PCONTAINER) +
			    10; /* plus a few extra */

			if ((dn = malloc(size)) != NULL)
				(void) snprintf((char *)dn, size, "%s=%s,%s,%s",
				ATTR_URI, printerName, PCONTAINER, domainDN);
		}
		else
		if (uri != NULL)
		{
			/* use the URI for the RDN */

			size = strlen(ATTR_URI) +
			    strlen((char *)uri) +
			    strlen((char *)domainDN) +
			    strlen(PCONTAINER) +
			    10; /* plus a few extra */

			if ((dn = malloc(size)) != NULL)
				(void) snprintf((char *)dn, size, "%s=%s,%s,%s",
				ATTR_URI, uri, PCONTAINER, domainDN);
		}

		/*
		 * else
		 * {
		 *    printName not given so return null
		 * }
		 */

	}

	return (dn);	/* caller must free this memory */
} /* _constructPrinterDN */



/*
 * *****************************************************************************
 *
 * Function:    _checkPrinterExists()
 *
 * Description: Check that the printer object for the printerName exists in the
 *              directory DIT and then extract the object's DN
 *              The function uses an exiting ldap connection and does a
 *              search for the printerName in the supplied domain DN.
 *
 * Parameters:
 * Input:       LDAP *ld             - existing ldap connection descriptor
 *              uchar_t *printerName - printer name
 *              uchar_t *domainDN    - DN of domain to search in
 * Output:      uchar_t **printerDN  - DN of the printer - the caller should
 *                                     free this memory using free()
 *
 * Result:      NSL_RESULT - NSL_OK = object exists
 *
 * *****************************************************************************
 */

static NSL_RESULT
_checkPrinterExists(LDAP *ld, uchar_t *printerName, uchar_t *domainDN,
			uchar_t **printerDN)

{
	NSL_RESULT result = NSL_ERR_UNKNOWN_PRINTER;
	int sresult = LDAP_NO_SUCH_OBJECT;
	LDAPMessage *ldapMsg = NULL;
	char *requiredAttrs[2] = { ATTR_PNAME, NULL };
	LDAPMessage *ldapEntry = NULL;
	uchar_t *filter = NULL;
	uchar_t *baseDN = NULL;

	/* ---------- */

	if ((printerName != NULL) && (domainDN != NULL) && (printerDN != NULL))
	{
		size_t size;

		if (printerDN != NULL)
		{
			*printerDN = NULL;
		}

		/* search for this Printer in the directory */

		size = (3 + strlen((char *)printerName) + strlen(ATTR_PNAME) +
			2);

		if ((filter = malloc(size)) != NULL)
			(void) snprintf((char *)filter, size, "(%s=%s)",
			    ATTR_PNAME, (char *)printerName);

		size = (strlen((char *)domainDN) + strlen(PCONTAINER) + 5);

		if ((baseDN = malloc(size)) != NULL)
			(void) snprintf((char *)baseDN, size, "%s,%s",
			    PCONTAINER, (char *)domainDN);

		sresult = ldap_search_s(ld, (char *)baseDN, LDAP_SCOPE_SUBTREE,
				(char *)filter, requiredAttrs, 0, &ldapMsg);
		if (sresult == LDAP_SUCCESS)
		{
			/* check that the object exists and extract its DN */

			ldapEntry = ldap_first_entry(ld, ldapMsg);
			if (ldapEntry != NULL)
			{
				/* object found - there should only be one */
				result = NSL_OK;

				if (printerDN != NULL)
				{
					*printerDN = (uchar_t *)
						ldap_get_dn(ld, ldapEntry);
				}
			}

			(void) ldap_msgfree(ldapMsg);
		}
	}

	else
	{
		result = NSL_ERR_INTERNAL;
	}

	return (result);
} /* _checkPrinterExists */




/*
 * *****************************************************************************
 *
 * Function:    _checkPrinterDNExists()
 *
 * Description: Check that the printer object for the DN exists in the
 *              directory DIT.
 *              The function uses an exiting ldap connection and does a
 *              search for the DN supplied.
 *
 * Parameters:  LDAP *ld       - existing ldap connection descriptor
 *              char *objectDN - DN to search for
 *
 * Result:      NSL_RESULT - NSL_OK = object exists
 *
 * *****************************************************************************
 */

static NSL_RESULT
_checkPrinterDNExists(LDAP *ld, uchar_t *objectDN)

{
	NSL_RESULT result = NSL_ERR_UNKNOWN_PRINTER;
	int sresult = LDAP_NO_SUCH_OBJECT;
	LDAPMessage *ldapMsg;
	char *requiredAttrs[2] = { ATTR_PNAME, NULL };
	LDAPMessage *ldapEntry;

	/* ---------- */

	if ((ld != NULL) && (objectDN != NULL))
	{
		/* search for this Printer in the directory */

		sresult = ldap_search_s(ld, (char *)objectDN, LDAP_SCOPE_BASE,
				"(objectclass=*)", requiredAttrs, 0, &ldapMsg);
		if (sresult == LDAP_SUCCESS)
		{
			/* check that the object exists */
			ldapEntry = ldap_first_entry(ld, ldapMsg);
			if (ldapEntry != NULL)
			{
				/* object found */
				result = NSL_OK;
			}

			(void) ldap_msgfree(ldapMsg);
		}
	}

	else
	{
		result = NSL_ERR_INTERNAL;
	}

	return (result);
} /* _checkPrinterDNExists */





/*
 * *****************************************************************************
 *
 * Function:    _checkSunPrinter()
 *
 * Description: Check that the printer object for the printerDN is a sunPrinter
 *              ie. it has the required objectclass attribute value.
 *
 * Parameters:
 * Input:       LDAP *ld            - existing ldap connection descriptor
 * Output:      uchar_t *printerDN  - DN of the printer
 *
 * Result:      NSL_RESULT - NSL_OK = object exists and is a sunPrinter
 *
 * *****************************************************************************
 */

static NSL_RESULT
_checkSunPrinter(LDAP *ld, uchar_t *printerDN)

{
	NSL_RESULT result = NSL_ERR_UNKNOWN_PRINTER;
	int sresult = LDAP_NO_SUCH_OBJECT;
	char *requiredAttrs[2] = { ATTR_PNAME, NULL };
	LDAPMessage *ldapMsg = NULL;
	LDAPMessage *ldapEntry = NULL;
	char *filter = NULL;

	/* ---------- */

	if ((ld != NULL) && (printerDN != NULL))
	{
		size_t size;

		/* search for this Printer in the directory */

		size = (3 + strlen(OCV_SUNPRT) + strlen(ATTR_OCLASS) + 2);
		if ((filter = malloc(size)) != NULL)
			(void) snprintf(filter, size, "(%s=%s)",
					ATTR_OCLASS, OCV_SUNPRT);

		sresult = ldap_search_s(ld, (char *)printerDN,
						LDAP_SCOPE_SUBTREE, filter,
						requiredAttrs, 0, &ldapMsg);
		if (sresult == LDAP_SUCCESS)
		{
			/* check that the printer object exists */

			ldapEntry = ldap_first_entry(ld, ldapMsg);
			if (ldapEntry != NULL)
			{
				/* object is a sunPrinter */
				result = NSL_OK;
			}

			(void) ldap_msgfree(ldapMsg);
		}
	}

	else
	{
		result = NSL_ERR_INTERNAL;
	}

	return (result);
} /* _checkSunPrinter */





/*
 * *****************************************************************************
 *
 * Function:    _addNewPrinterObject()
 *
 * Description: For the given printerName add a printer object into the
 *              LDAP directory NS domain. The object is created with the
 *              supplied attribute values. Note: if the printer's uri is
 *              given that is used as the RDN otherwise the printer's
 *              name is used as the RDN
 *
 * Parameters:
 * Input:       LDAP    *ld        - existing ldap connection descriptor
 *              uchar_t *printerName - Name of printer to be added
 *              uchar_t *domainDN    - DN of the domain to add the printer
 *              char    **attrList - user specified attribute values list
 * Output:      None
 *
 * Returns:     NSL_RESULT - NSL_OK  = request actioned okay
 *                           !NSL_OK = error
 *
 * *****************************************************************************
 */

static NSL_RESULT
_addNewPrinterObject(LDAP *ld, uchar_t *printerName,
			uchar_t *domainDN, char **attrList)

{
	NSL_RESULT result = NSL_ERR_ADD_FAILED;
	int lresult = 0;
	uchar_t *printerDN = NULL;
	LDAPMod **attrs = NULL;

	/* ---------- */

	if ((ld != NULL) && (printerName != NULL) && (domainDN != NULL) &&
		(attrList != NULL) && (attrList[0] != NULL))
	{
		result = _checkAttributes(attrList);

		if (result == NSL_OK)
		{
			/*
			 * construct a DN for the printer from the
			 * printerName and printer-uri if given.
			 */
			printerDN = _constructPrinterDN(printerName,
						domainDN, attrList);
			if (printerDN != NULL)
			{
				/*
				 * setup attribute values in an LDAPMod
				 * structure and then add the object
				 */
				result = _constructAddLDAPMod(printerName,
							attrList, &attrs);
				if (result == NSL_OK)
				{
					lresult = ldap_add_s(ld,
						    (char *)printerDN, attrs);
					if (lresult == LDAP_SUCCESS)
					{
						result = NSL_OK;
					}
					else
					{
						result = NSL_ERR_ADD_FAILED;
#ifdef DEBUG
(void) ldap_perror(ld, "ldap_add_s");
#endif
					}

					(void) ldap_mods_free(attrs, 1);
				}
				free(printerDN);
			}

			else
			{
				result = NSL_ERR_INTERNAL;
			}
		}
	}

	else
	{
		result = NSL_ERR_INTERNAL;
	}

	return (result);
} /* _addNewPrinterObject */






/*
 * *****************************************************************************
 *
 * Function:    _modifyPrinterObject()
 *
 * Description: Modify the given LDAP printer object to set the new attributes
 *              in the attribute list. If the printer's URI (specified in the
 *              attrList) changes the URI of the object the request is rejected.
 *
 * Parameters:
 * Input:       LDAP    *ld        - existing ldap connection descriptor
 *              uchar_t *printerDN - DN of printer object to modify
 *              uchar_t *printerName - Name of printer to be modified
 *              uchar_t *domainDN    - DN of the domain the printer is in
 *              char    **attrList - user specified attribute values list
 * Output:      None
 *
 * Returns:     NSL_RESULT - NSL_OK = object modified okay
 *
 * *****************************************************************************
 */

static NSL_RESULT
_modifyPrinterObject(LDAP *ld, uchar_t *printerDN,
		uchar_t *printerName, uchar_t *domainDN, char **attrList)

{
	NSL_RESULT result = NSL_ERR_INTERNAL;
	int lresult = 0;
	int sunPrinter = 0;
	uchar_t *uriDN = NULL;
	LDAPMod **attrs = NULL;
	char **kvpList = NULL;

	/* ---------- */

	if ((ld != NULL) && (printerDN != NULL) && (printerName != NULL) &&
	    (domainDN != NULL) && (attrList != NULL) && (attrList[0] != NULL))
	{
		result = _checkAttributes(attrList);

		if (result == NSL_OK)
		{
			/*
			 * The user may have requested that the printer object
			 * be given a new URI RDN, so construct a DN for the
			 * printer from the printerName or the printer-uri (if
			 * given).
			 */
			uriDN = _constructPrinterDN(NULL, domainDN, attrList);

			/*
			 * compare the 2 DNs to see if the URI has changed,
			 * if uriDN is null then the DN hasn't changed
			 */
			if ((uriDN == NULL) || ((uriDN != NULL) &&
			    (_compareURIinDNs(printerDN, uriDN) == NSL_OK)))
			{
				/*
				 * setup the modify object LDAPMod
				 * structure and then do the modify
				 */

				if (_checkSunPrinter(ld, printerDN) == NSL_OK)
				{
					sunPrinter = 1;
				}

				(void) _getCurrentKVPValues(ld,
							printerDN, &kvpList);

				result = _constructModLDAPMod(printerName,
							sunPrinter, attrList,
							&kvpList, &attrs);
				_freeList(&kvpList);

				if ((result == NSL_OK) && (attrs != NULL))
				{
					lresult = ldap_modify_s(
						ld, (char *)printerDN, attrs);
					if (lresult == LDAP_SUCCESS)
					{
						result = NSL_OK;
					}
					else
					{
						result = NSL_ERR_MOD_FAILED;
#ifdef DEBUG
(void) ldap_perror(ld, "ldap_modify_s");
#endif
					}

					(void) ldap_mods_free(attrs, 1);
				}
			}
			else
			{
				/*
				 * printer-uri name change has been requested
				 * this is NOT allowed as it requires that
				 * a new printer object is created
				 */
				result = NSL_ERR_RENAME;  /* NOT ALLOWED */
			}

			if (uriDN != NULL)
			{
				free(uriDN);
			}
		}
	}

	return (result);
} /* _modifyPrinterObject */




/*
 * *****************************************************************************
 *
 * Function:    _checkAttributes()
 *
 * Description: Check that the given attribute lists does not contain any
 *              key words that are not allowed.
 *
 * Parameters:
 * Input:       char **list - attribute list to check
 * Output:      None
 *
 * Returns:     NSL_RESULT - NSL_OK = checked okay
 *
 * *****************************************************************************
 */

static NSL_RESULT
_checkAttributes(char **list)

{
	NSL_RESULT result = NSL_OK;
	int len = 0;
	char *attr = NULL;
	char **p = NULL;

	/* ------ */

	for (p = list; (p != NULL) && (*p != NULL) && (result == NSL_OK); p++)
	{
		/* get length of this key word */

		for (len = 0; ((*p)[len] != '=') && ((*p)[len] != '\0'); len++);

		/* check if the key word is allowed */

		if (strncasecmp(*p, ATTR_KVP, len) == 0)
		{
			/* not supported through this interface */
			result = NSL_ERR_KVP;
		}
		else
		if (strncasecmp(*p, ATTR_BSDADDR, len) == 0)
		{
			/* not supported through this interface */
			result = NSL_ERR_BSDADDR;
		}
		else
		if (strncasecmp(*p, ATTR_PNAME, len) == 0)
		{
			/* not supported through this interface */
			result = NSL_ERR_PNAME;
		}
		else
		{
			/* check for any others */

			attr = strdup(*p);
			attr[len] = '\0'; /* terminate the key */

			if (_attrInList(attr, nsl_attr_notAllowed))
			{
				result = NSL_ERR_NOTALLOWED;
			}
		}

	}

	return (result);
} /* _checkAttributes */




/*
 * *****************************************************************************
 *
 * Function:    _addLDAPmodValue()
 *
 * Description: Add the given attribute and its value to the LDAPMod array.
 *              If this is the first entry in the array then create it.
 *
 * Parameters:
 * Input:       LDAPMod ***attrs  - array to update
 *              char *type        - attribute to add into array
 *              char *value       - attribute value
 * Output:      None
 *
 * Returns:     NSL_RESULT - NSL_OK = added okay
 *
 * *****************************************************************************
 */

static NSL_RESULT
_addLDAPmodValue(LDAPMod ***attrs, char *type, char *value)

{
	int i = 0;
	int j = 0;
	NSL_RESULT result = NSL_OK;

	/* ---------- */

	if ((attrs != NULL) && (type != NULL) && (value != NULL))
	{
#ifdef DEBUG
printf("_addLDAPmodValue() type='%s', value='%s'\n", type, value);
#endif
		/* search the existing LDAPMod array for the attribute */

		for (i = 0; *attrs != NULL && (*attrs)[i] != NULL; i++)
		{
			if (strcasecmp((*attrs)[i]->mod_type, type) == 0)
			{
				break;
			}
		}

		if (*attrs == NULL)
		{
			/* array empty so create it */

			*attrs = (LDAPMod **)calloc(1, 2 * sizeof (LDAPMod *));
			if (*attrs != NULL)
			{
				i = 0;
			}
			else
			{
				result = NSL_ERR_MEMORY;
			}

		}
		else
		if ((*attrs)[i] == NULL)
		{
			*attrs = (LDAPMod **)
				realloc(*attrs, (i+2) * sizeof (LDAPMod *));
			if (*attrs == NULL)
			{
				result = NSL_ERR_MEMORY;
			}
		}
	}
	else
	{
		result = NSL_ERR_INTERNAL;
	}

	if (result == NSL_OK)
	{
		if ((*attrs)[i] == NULL)
		{
			/* We've got a new slot. Create the new mod. */

			(*attrs)[i] = (LDAPMod *) malloc(sizeof (LDAPMod));
			if ((*attrs)[i] != NULL)
			{
				(*attrs)[i]->mod_op = LDAP_MOD_ADD;
				(*attrs)[i]->mod_type = strdup(type);
				(*attrs)[i]->mod_values = (char **)
						malloc(2 * sizeof (char *));
				if ((*attrs)[i]->mod_values  != NULL)
				{
					(*attrs)[i]->mod_values[0] =
								strdup(value);
					(*attrs)[i]->mod_values[1] = NULL;
					(*attrs)[i+1] = NULL;
				}
				else
				{
					result = NSL_ERR_MEMORY;
				}
			}
			else
			{
				result = NSL_ERR_MEMORY;
			}
		}

		else
		{
			/* Found an existing entry so add value to it */

			for (j = 0; (*attrs)[i]->mod_values[j] != NULL; j++);

			(*attrs)[i]->mod_values =
				(char **)realloc((*attrs)[i]->mod_values,
						(j + 2) * sizeof (char *));
			if ((*attrs)[i]->mod_values != NULL)
			{
				(*attrs)[i]->mod_values[j] = strdup(value);
				(*attrs)[i]->mod_values[j+1] = NULL;
			}
			else
			{
				result = NSL_ERR_MEMORY;
			}
		}
	}

	return (result);
} /* _addLDAPmodValue */




/*
 * *****************************************************************************
 *
 * Function:    _modLDAPmodValue()
 *
 * Description: Add the given attribute modify operation and its value into
 *              the LDAPMod array. This will either be a "replace" or a
 *              "delete"; value = null implies a "delete".
 *              If this is the first entry in the array then create it.
 *
 * Parameters:
 * Input:       LDAPMod ***attrs  - array to update
 *              char *type        - attribute to modify
 *              char *value       - attribute value, null implies "delete"
 * Output:      None
 *
 * Returns:     NSL_RESULT - NSL_OK = added okay
 *
 * *****************************************************************************
 */

static NSL_RESULT
_modLDAPmodValue(LDAPMod ***attrs, char *type, char *value)

{
	int i = 0;
	int j = 0;
	NSL_RESULT result = NSL_OK;

	/* ---------- */

	if ((attrs != NULL) && (type != NULL))
	{
#ifdef DEBUG
if (value != NULL)
printf("_modLDAPmodValue() REPLACE type='%s', value='%s'\n", type, value);
else
printf("_modLDAPmodValue() DELETE type='%s'\n", type);
#endif
		/* search the existing LDAPMod array for the attribute */

		for (i = 0; *attrs != NULL && (*attrs)[i] != NULL; i++)
		{
			if (strcasecmp((*attrs)[i]->mod_type, type) == 0)
			{
				break;
			}
		}

		if (*attrs == NULL)
		{
			/* array empty so create it */

			*attrs = (LDAPMod **)calloc(1, 2 * sizeof (LDAPMod *));
			if (*attrs != NULL)
			{
				i = 0;
			}
			else
			{
				result = NSL_ERR_MEMORY;
			}

		}
		else
		if ((*attrs)[i] == NULL)
		{
			/* attribute not found in array so add slot for it */

			*attrs = (LDAPMod **)
				realloc(*attrs, (i+2) * sizeof (LDAPMod *));
			if (*attrs == NULL)
			{
				result = NSL_ERR_MEMORY;
			}
		}
	}
	else
	{
		result = NSL_ERR_INTERNAL;
	}

	if (result == NSL_OK)
	{
		if ((*attrs)[i] == NULL)
		{
			/* We've got a new slot. Create the new mod entry */

			(*attrs)[i] = (LDAPMod *) malloc(sizeof (LDAPMod));
			if (((*attrs)[i] != NULL) && (value != NULL))
			{
				/* Do an attribute replace */

				(*attrs)[i]->mod_op = LDAP_MOD_REPLACE;
				(*attrs)[i]->mod_type = strdup(type);
				(*attrs)[i]->mod_values = (char **)
						malloc(2 * sizeof (char *));
				if ((*attrs)[i]->mod_values  != NULL)
				{
					(*attrs)[i]->mod_values[0] =
								strdup(value);
					(*attrs)[i]->mod_values[1] = NULL;
					(*attrs)[i+1] = NULL;
				}
				else
				{
					result = NSL_ERR_MEMORY;
				}
			}
			else
			if ((*attrs)[i] != NULL)
			{
				/* value is null so do an attribute delete */

				(*attrs)[i]->mod_op = LDAP_MOD_DELETE;
				(*attrs)[i]->mod_type = strdup(type);
				(*attrs)[i]->mod_values = NULL;
				(*attrs)[i+1] = NULL;
			}
			else
			{
				result = NSL_ERR_MEMORY; /* malloc failed */
			}
		}

		else
		{
			/* Found an existing entry so add value to it */

			if (value != NULL)
			{
			    /* add value to attribute's replace list */

			    if ((*attrs)[i]->mod_op == LDAP_MOD_REPLACE)
			    {
				for (j = 0;
				    (*attrs)[i]->mod_values[j] != NULL; j++);

				(*attrs)[i]->mod_values =
				(char **)realloc((*attrs)[i]->mod_values,
						(j + 2) * sizeof (char *));
				if ((*attrs)[i]->mod_values != NULL)
				{
					(*attrs)[i]->mod_values[j] =
								strdup(value);
					(*attrs)[i]->mod_values[j+1] = NULL;
				}
				else
				{
					result = NSL_ERR_MEMORY;
				}
			    }
			    else
			    {
				/* Delete and replace not allowed */
				result = NSL_ERR_MULTIOP;
			    }
			}

			else
			{
				/*
				 * attribute delete - so free any existing
				 * entries in the value array
				 */

				(*attrs)[i]->mod_op = LDAP_MOD_DELETE;

				if ((*attrs)[i]->mod_values != NULL)
				{
					for (j = 0;
					    (*attrs)[i]->mod_values[j] != NULL;
					    j++)
					{
					    free((*attrs)[i]->mod_values[j]);
					}

					free((*attrs)[i]->mod_values);
					(*attrs)[i]->mod_values = NULL;
				}
			}
		}
	}

	return (result);
} /* _modLDAPmodValue */





/*
 * *****************************************************************************
 *
 * Function:    _constructAddLDAPMod()
 *
 * Description: For the given attribute list construct an
 *              LDAPMod array for the printer object to be added. Default
 *              attribute values are included.
 *
 * Parameters:
 * Input:
 *              uchar_t *printerName - Name of printer to be added
 *              char    **attrList - user specified attribute values list
 * Output:      LDAPMod ***attrs  - pointer to the constructed array
 *
 * Returns:     NSL_RESULT - NSL_OK = constructed okay
 *
 * *****************************************************************************
 */

static NSL_RESULT
_constructAddLDAPMod(uchar_t *printerName, char **attrList,  LDAPMod ***attrs)

{
	NSL_RESULT result = NSL_ERROR;
	int len = 0;
	char **p = NULL;
	char *value = NULL;
	char *attr = NULL;

	/* ---------- */

	if ((printerName != NULL) &&
	    ((attrList != NULL) && (attrList[0] != NULL)) && (attrs != NULL))
	{
		*attrs = NULL;

		/*
		 * setup printer object attribute values in an LDAPMod structure
		 */
		result = _addLDAPmodValue(attrs, ATTR_OCLASS, OCV_TOP);
		if (result == NSL_OK)
		{
			/* Structural Objectclass */
			result =
			    _addLDAPmodValue(attrs, ATTR_OCLASS, OCV_PSERVICE);
		}
		if (result == NSL_OK)
		{
			result = _addLDAPmodValue(attrs,
						ATTR_OCLASS, OCV_PABSTRACT);
		}
		if (result == NSL_OK)
		{
			result = _addLDAPmodValue(attrs,
						ATTR_OCLASS, OCV_SUNPRT);
		}
		if (result == NSL_OK)
		{
			result = _addLDAPmodValue(attrs,
					ATTR_PNAME, (char *)printerName);
		}

		/*
		 * Now work through the user supplied attribute
		 * values list and add them into the LDAPMod array
		 */

		for (p = attrList;
			(p != NULL) && (*p != NULL) && (result == NSL_OK); p++)
		{
			/* get length of this key word */

			for (len = 0;
			    ((*p)[len] != '=') && ((*p)[len] != '\0'); len++);

			if ((strlen(*p) > len+1))
			{
				attr = strdup(*p);
				attr[len] = '\0';
				value = strdup(&attr[len+1]);

				/* handle specific Key Value Pairs (KVP) */

				if (strcasecmp(attr, NS_KEY_BSDADDR) == 0)
				{
					/* use LDAP attribute name */
					free(attr);
					attr = strdup(ATTR_BSDADDR);
				}
				else
				if (_attrInLDAPList(attr) == 0)
				{
					/*
					 * Non-LDAP attribute so use LDAP
					 * KVP attribute and the given KVP
					 * as the value, ie.
					 * sun-printer-kvp=description=printer
					 */
					free(attr);
					attr = strdup(ATTR_KVP);
					value = strdup(*p);
				}

				/* add it into the LDAPMod array */

				result = _addLDAPmodValue(attrs, attr, value);

				free(attr);
				free(value);
			}
		} /* for */

		if ((result != NSL_OK) && (*attrs != NULL))
		{
			(void) ldap_mods_free(*attrs, 1);
			attrs = NULL;
		}
	}
	else
	{
		result = NSL_ERR_INTERNAL;
	}

	return (result);
} /* _constructAddLDAPMod */







/*
 * *****************************************************************************
 *
 * Function:    _constructModLDAPMod()
 *
 * Description: For the given modify attribute list, construct an
 *              LDAPMod array for the printer object to be modified
 *
 * Parameters:
 * Input:       uchar_t *printerName - name of printer to be modified
 *              int     sunPrinter - Boolean; object is a sunPrinter
 *              char    **attrList - user specified attribute values list
 *              char    ***oldKVPList - current list of KVP values on object
 * Output:      LDAPMod ***attrs  - pointer to the constructed array
 *
 * Returns:     NSL_RESULT - NSL_OK = constructed okay
 *
 * *****************************************************************************
 */

static NSL_RESULT
_constructModLDAPMod(uchar_t *printerName, int sunPrinter, char **attrList,
			char ***oldKVPList, LDAPMod ***attrs)

{
	NSL_RESULT result = NSL_OK;
	int len = 0;
	int kvpUpdated = 0;
	int kvpExists = 0;
	char **p = NULL;
	char *value = NULL;
	char *attr = NULL;

	/* ---------- */

	if ((printerName != NULL) &&
	    ((attrList != NULL) && (attrList[0] != NULL)) && (attrs != NULL))
	{
		*attrs = NULL;

		if ((oldKVPList != NULL) && (*oldKVPList != NULL))
		{
			kvpExists = 1;
		}

		if (!sunPrinter)
		{
			/*
			 * The object was previously not a sunPrinter, so
			 * add the required objectclass attribute value, and
			 * ensure it has the printername attribute.
			 */
			result = _addLDAPmodValue(attrs,
						ATTR_OCLASS, OCV_SUNPRT);
			if (result == NSL_OK)
			{
				result = _modLDAPmodValue(attrs,
					    ATTR_PNAME, (char *)printerName);
			}
		}

		/*
		 * work through the user supplied attribute
		 * values list and add them into the LDAPMod array depending
		 * on if they are a replace or delete attribute operation,
		 * a "null value" means delete.
		 */

		for (p = attrList;
			(p != NULL) && (*p != NULL) && (result == NSL_OK); p++)
		{
			/* get length of this key word */

			for (len = 0;
			    ((*p)[len] != '=') && ((*p)[len] != '\0'); len++);

			if ((strlen(*p) > len+1))
			{
				attr = strdup(*p);
				attr[len] = '\0';
				value = strdup(&attr[len+1]);

				/* handle specific Key Value Pairs (KVP) */

				if ((_attrInLDAPList(attr) == 0) &&
					(strcasecmp(attr, NS_KEY_BSDADDR) != 0))
				{
					/*
					 * Non-LDAP attribute so use LDAP
					 * KVP attribute and the given KVP as
					 * the value, ie.
					 * sun-printer-kvp=description=printer
					 */
					result = _modAttrKVP(*p, oldKVPList);
					kvpUpdated = 1;
				}

				else
				{
					if (strcasecmp(attr, NS_KEY_BSDADDR) ==
									0)
					{
						/*
						 * use LDAP bsdaddr attribute
						 * name
						 */
						free(attr);
						attr = strdup(ATTR_BSDADDR);
					}

					/*
					 * else
					 *   use the supplied attribute name
					 */

					/* add it into the LDAPMod array */

					result = _modLDAPmodValue(attrs,
								attr, value);
				}

				free(attr);
				free(value);
			}

			else
			if (strlen(*p) >= 1)
			{
				/* handle attribute DELETE request */

				attr = strdup(*p);
				if (attr[len] == '=')
				{
					/* terminate "attribute=" */
					attr[len] = '\0';
				}

				/* handle specific Key Value Pairs (KVP) */

				if (strcasecmp(attr, NS_KEY_BSDADDR) == 0)
				{
					/* use LDAP bsdaddr attribute name */
					result = _modLDAPmodValue(attrs,
							ATTR_BSDADDR, NULL);
				}
				else
				if (_attrInLDAPList(attr) == 0)
				{
					/*
					 * Non-LDAP kvp, so sort items
					 * in the kvp list
					 */
					result = _modAttrKVP(*p, oldKVPList);
					kvpUpdated = 1;
				}
				else
				{
					result = _modLDAPmodValue(attrs,
							attr, NULL);
				}

				free(attr);
			}
		} /* for */

		if ((result == NSL_OK) && (kvpUpdated))
		{
			result = _attrAddKVP(attrs, *oldKVPList, kvpExists);
		}

		if ((result != NSL_OK) && (*attrs != NULL))
		{
			(void) ldap_mods_free(*attrs, 1);
			*attrs = NULL;
		}
	}
	else
	{
		result = NSL_ERR_INTERNAL;
	}

	return (result);
} /* _constructModLDAPMod */






/*
 * *****************************************************************************
 *
 * Function:    _compareURIinDNs()
 *
 * Description: For the 2 given printer object DNs compare the naming part
 *              part of the DN (printer-uri) to see if they are the same.
 *
 * Note:        This function only returns "compare failed" if their URI don't
 *              compare. Problems with the dn etc., return a good compare
 *              because I don't want us to create a new object for these
 *
 * Parameters:
 * Input:       uchar_t *dn1
 *              uchar_t *dn2
 * Output:      None
 *
 * Returns:     NSL_RESULT - NSL_OK = URIs are the same
 *
 * *****************************************************************************
 */

static NSL_RESULT
_compareURIinDNs(uchar_t *dn1, uchar_t *dn2)

{
	NSL_RESULT result = NSL_OK;
	uchar_t *DN1 = NULL;
	uchar_t *DN2 = NULL;
	char *p1 = NULL;
	char *p2 = NULL;

	/* --------- */

	if ((dn1 != NULL) && (dn2 != NULL))
	{
		DN1 = (uchar_t *)strdup((char *)dn1);
		DN2 = (uchar_t *)strdup((char *)dn2);

		/* terminate each string after the printer-uri */

		p1 = strstr((char *)DN1, PCONTAINER);
		/* move back to the comma */
		while ((p1 != NULL) && (*p1 != ',') && (p1 >= (char *)DN1))
		{
			p1--;
		}

		p2 = strstr((char *)DN2, PCONTAINER);
		/* move back to the comma */
		while ((p2 != NULL) && (*p2 != ',') && (p2 >= (char *)DN2))
		{
			p2--;
		}

		if ((*p1 == ',') && (*p2 == ','))
		{
			*p1 = '\0';	/* re-terminate it */
			*p2 = '\0';	/* re-terminate it */

			/* do the compare */

			/*
			 * Note: SHOULD really normalise the 2 DNs before
			 * doing the compare
			 */
#ifdef DEBUG
printf("_compareURIinDNs() @1 (%s) (%s)\n", DN1, DN2);
#endif
			if (strcasecmp((char *)DN1, (char *)DN2) != 0)
			{
				result = NSL_ERROR;
			}

		}

		free(DN1);
		free(DN2);
	}

	return (result);
} /* _compareURIinDNs */







/*
 * *****************************************************************************
 *
 * Function:    _getThisNSDomainDN()
 *
 * Description: Get the current Name Service Domain DN
 *              This is extracted from the result of executing ldaplist.
 *
 * Note:        Do it this way until the NS LDAP library interface is
 *              made public.
 *
 * Parameters:
 * Input:       None
 * Output:      None
 *
 * Returns:     uchar_t*  - pointer to NS Domain DN (The caller should free this
 *                          returned memory).
 *
 * *****************************************************************************
 */

#define	LDAPLIST_D	"/usr/bin/ldaplist -d 2>&1"
#define	DNID		"dn: "

static uchar_t *
_getThisNSDomainDN(void)

{
	uchar_t *domainDN = NULL;
	char *cp = NULL;
	char buf[BUFSIZ] = "";

	/* --------- */

	if (_popen(LDAPLIST_D, buf, sizeof (buf)) == 0)
	{
		if ((cp = strstr(buf, DNID)) != NULL)
		{
			cp += strlen(DNID);  /* increment past "dn: " label */
			domainDN = (uchar_t *)strdup(cp);

			if ((cp = strchr((char *)domainDN, '\n')) != NULL)
			{
				*cp = '\0'; /* terminate it */
			}
		}
	}

	return (domainDN);
} /* _getThisNSDomainDN */





/*
 * *****************************************************************************
 *
 * Function:    _popen()
 *
 * Description: General popen function. The caller should always use a full
 *              path cmd.
 *
 * Parameters:
 * Input:       char *cmd - command line to execute
 *              char *buffer - ptr to buffer to put result in
 *              int  size - size of result buffer
 * Output:      None
 *
 * Returns:     int - 0 = opened okay
 *
 * *****************************************************************************
 */

static int
_popen(char *cmd, char *buffer, int size)

{
	int result = -1;
	int rsize = 0;
	FILE *fptr;
	char safe_cmd[BUFSIZ];
	char linebuf[BUFSIZ];

	/* -------- */

	if ((cmd != NULL) && (buffer != NULL) && (size != 0))
	{
		(void) strcpy(buffer, "");
		(void) strcpy(linebuf, "");
		(void) snprintf(safe_cmd, BUFSIZ, "IFS=' \t'; %s", cmd);

		if ((fptr = popen(safe_cmd, "r")) != NULL)
		{
			while ((fgets(linebuf, BUFSIZ, fptr) != NULL) &&
							(rsize  < size))
			{
				rsize = strlcat(buffer, linebuf, size);
				if (rsize >= size)
				{
					/* result is too long */
					(void) memset(buffer, '\0', size);
				}
			}

			if (strlen(buffer) > 0)
			{
				result = 0;
			}

			(void) pclose(fptr);
		}
	}

	return (result);
} /* popen */


/*
 * *****************************************************************************
 *
 * Function:    _attrInList()
 *
 * Description: For the given list check if the attribute is it
 *
 * Parameters:
 * Input:       char *attr   - attribute to check
 *              char **list  - list of attributes to check against
 * Output:      None
 *
 * Returns:     int - TRUE = attr found in list
 *
 * *****************************************************************************
 */

static int
_attrInList(char *attr, const char **list)

{
	int result = 0;
	int j;

	/* ------- */

	if ((attr != NULL) && (list != NULL))
	{
		for (j = 0; (list[j] != NULL) && (result != 1); j++)
		{
			if (strcasecmp(list[j], attr) == 0)
			{
				result = 1; /* found */
			}
		}
	}

	return (result);
} /* _attrInList */




/*
 * *****************************************************************************
 *
 * Function:    _attrInLDAPList()
 *
 * Description: Checks to see if the given attribute is an LDAP printing
 *              attribute, ie. is either in an IPP objectclass or the
 *              sun printer objectclass. Note: some attributes are handled
 *              specifically outside this function, so are excluded from
 *              the lists that are checked.
 *
 * Parameters:
 * Input:       char *attr    - attribute to check
 * Output:      None
 *
 * Returns:     int - TRUE = attr found in list
 *
 * *****************************************************************************
 */

static int
_attrInLDAPList(char *attr)

{
	int result = 0;

	/* ------- */

	if (_attrInList(attr, nsl_attr_printerService))
	{
		result = 1;	/* in list */
	}
	else
	if (_attrInList(attr, nsl_attr_printerIPP))
	{
		result = 1;	/* in list */
	}
	else
	if (_attrInList(attr, nsl_attr_sunPrinter))
	{
		result = 1;	/* in list */
	}

	return (result);
} /* _attrInLDAPList */




/*
 * *****************************************************************************
 *
 * Function:    _getCurrentKVPValues()
 *
 * Description: For the given printer object read the current set of values
 *              the object has for the sun-printer-kvp (Key Value pair)
 *
 * Parameters:
 * Input:       LDAP *ld       - existing ldap connection descriptor
 *              char *objectDN - DN to search for
 * Output:      char ***list   - returned set of kvp values
 *
 * Result:      NSL_RESULT - NSL_OK = object exists
 *
 * *****************************************************************************
 */

static NSL_RESULT
_getCurrentKVPValues(LDAP *ld, uchar_t *objectDN, char ***list)

{
	NSL_RESULT result = NSL_ERR_UNKNOWN_PRINTER;
	int sresult = LDAP_NO_SUCH_OBJECT;
	int i = 0;
	LDAPMessage *ldapMsg;
	char *requiredAttrs[2] = { ATTR_KVP, NULL };
	LDAPMessage *ldapEntry = NULL;
	char *entryAttrib = NULL;
	char **attribValues = NULL;
	BerElement *berElement = NULL;

	/* ---------- */

	if ((list != NULL) && (ld != NULL) && (objectDN != NULL))
	{
		/* search for this Printer in the directory */

		sresult = ldap_search_s(ld, (char *)objectDN, LDAP_SCOPE_BASE,
				"(objectclass=*)", requiredAttrs, 0, &ldapMsg);
		if (sresult == LDAP_SUCCESS)
		{
			/*
			 * check that the object exists and extract its
			 * KVP attribute values
			 */
			ldapEntry = ldap_first_entry(ld, ldapMsg);
			if (ldapEntry != NULL)
			{
				entryAttrib = ldap_first_attribute(ld,
							ldapEntry, &berElement);
				if ((entryAttrib != NULL) &&
				    (strcasecmp(entryAttrib, ATTR_KVP) == 0))

				{
#ifdef DEBUG
printf("Attribute: %s, its values are:\n", entryAttrib);
#endif
					/*
					 * add each KVP value to the list
					 * that we will return
					 */
					attribValues = ldap_get_values(
						ld, ldapEntry, entryAttrib);
					for (i = 0;
						attribValues[i] != NULL; i++)
					{
					    *list = (char **)
						list_append((void **)*list,
						    strdup(attribValues[i]));
#ifdef DEBUG
printf("\t%s\n", attribValues[i]);
#endif
					}
					(void) ldap_value_free(attribValues);
				}

				if ((entryAttrib != NULL) &&
				    (berElement != NULL))
				{
					ber_free(berElement, 0);
				}


				/* object found */
				result = NSL_OK;
			}

			(void) ldap_msgfree(ldapMsg);
		}
	}

	else
	{
		result = NSL_ERR_INTERNAL;
	}

	return (result);
} /* _getCurrentKVPValues */



/*
 * *****************************************************************************
 *
 * Function:    _freeList()
 *
 * Description: Free the list created by list_append() where the items in
 *              the list have been strdup'ed.
 *
 * Parameters:
 * Input:       char ***list   - returned set of kvp values
 *
 * Result:      void
 *
 * *****************************************************************************
 */

static void
_freeList(char ***list)

{
	int i = 0;

	/* ------ */

	if (list != NULL)
	{
		if (*list != NULL)
		{
			for (i = 0; (*list)[i] != NULL; i++)
			{
				free((*list)[i]);
			}
			free(*list);
		}

		*list = NULL;
	}
} /* _freeList */



/*
 * *****************************************************************************
 *
 * Function:    _modAttrKVP()
 *
 * Description: Sort out the KVP attribute value list, such that this new
 *              value takes precidence over any existing value in the list.
 *              The current list is updated to remove this key, and the new
 *              key "value" is added to the list, eg. for
 *                  value: bbb=ddddd
 *                  and kvpList:
 *                         aaa=yyyy
 *                         bbb=zzzz
 *                         ccc=xxxx
 *                  the resulting kvpList is:
 *                         aaa=yyyy
 *                         ccc=xxxx
 *                         bbb=ddddd
 *
 * Note:        When all new values have been handled the function _attrAddKVP()
 *              must be called to add the "new list" values into the
 *              LDAPMod array.
 *
 * Parameters:
 * Input:       char *value       - Key Value Pair to process,
 *                                  eg. aaaaa=hhhhh, where aaaaa is the key
 *              char ***kvpList   - list of current KVP values
 * Output:      char ***kvpList   - updated list of KVP values
 *
 * Returns:     NSL_RESULT - NSL_OK = done okay
 *
 * *****************************************************************************
 */

static NSL_RESULT
_modAttrKVP(char *value, char ***kvpList)

{
	NSL_RESULT result = NSL_ERR_INTERNAL;
	int i = 0;
	int inList = 0;
	int keyDelete = 0;
	char *key = NULL;
	char **p = NULL;
	char **newList = NULL;

	/* ------- */

	if ((value != NULL) && (kvpList != NULL))
	{
		result = NSL_OK;

		/* extract "key" from value */

		key = strdup(value);

		for (i = 0; ((key)[i] != '=') && ((key)[i] != '\0'); i++);
		key[i] = '\0'; /* terminate the key */

		/* Is this a request to delete a "key" value */

		if ((value[i] == '\0') || (value[i+1] == '\0'))
		{
			/* this is a request to delete the key */
			keyDelete = 1;
		}

		if ((*kvpList != NULL) && (**kvpList != NULL))
		{
			/*
			 * for each item in the list remove it if the keys match
			 */
			for (p = *kvpList; *p != NULL; p++)
			{
				for (i = 0;
				    ((*p)[i] != '=') && ((*p)[i] != '\0'); i++);

				if ((strlen(key) == i) &&
					(strncasecmp(*p, key, i) == 0))
				{
					inList = 1;
				}
				else
				{
					/* no match so add value to new list */
					newList = (char **)list_append(
							(void **)newList,
							strdup(*p));
				}
			}
		}

		/*
		 * if it was not a DELETE request add the new key value into
		 * the newList, otherwise we have already removed the key
		 */

		if (!keyDelete)
		{
			newList = (char **)list_append((void **)newList,
							strdup(value));
		}

		if ((newList != NULL) || (inList))
		{
			/* replace old list with the newList */
			_freeList(kvpList);
			*kvpList = newList;
		}

		free(key);
	}

	return (result);
} /* modAttrKVP */




/*
 * *****************************************************************************
 *
 * Function:    _attrAddKVP()
 *
 * Description: Process KVP items in the kvpList adding them to the
 *              LDAPMod modify array. If the list is empty but there were
 *              previously LDAP KVP values delete them.
 *
 * Note:        This function should only be called when all the new KVP
 *              items have been processed by _modAttrKVP()
 *
 * Parameters:
 * Input:       LDAPMod ***attrs - array to update
 *              char **kvpList   - list KVP values
 *              int  kvpExists   - object currently has LDAP KVP values
 * Output:      None
 *
 * Returns:     NSL_RESULT - NSL_OK = done okay
 *
 * *****************************************************************************
 */

static NSL_RESULT
_attrAddKVP(LDAPMod ***attrs, char **kvpList, int kvpExists)

{
	NSL_RESULT result = NSL_OK;

	/* ------- */

	if (attrs != NULL)
	{
		if (kvpList != NULL)
		{
			while ((kvpList != NULL) && (*kvpList != NULL))
			{
				/* add item to LDAPMod array */

				result =
				    _modLDAPmodValue(attrs, ATTR_KVP, *kvpList);

				kvpList++;
			}
		}
		else
		if (kvpExists)
		{
			/*
			 * We now have no LDAP KVP values but there were
			 * some previously, so delete them
			 */
			result = _modLDAPmodValue(attrs, ATTR_KVP, NULL);
		}
	}

	else
	{
		result = NSL_ERR_INTERNAL;
	}

	return (result);
} /* _attrAddKVP */




/*
 * *****************************************************************************
 *
 * Function:    _manageReferralCredentials()
 *
 * Description: This function is called if a referral request is returned by
 *              the origonal LDAP server during the ldap update request call,
 *              eg. ldap_add_s(), ldap_modify_s() or ldap_delete_s().
 * Parameters:
 * Input:       LDAP *ld      - LDAP descriptor
 *              int freeit    - 0 = first call to get details
 *                            - 1 = second call to free details
 *                            - -1 = initial store of authentication details
 * Input/Output: char **dn    - returns DN to bind to on master
 *               char **credp - returns password for DN
 *               int *methodp - returns authentication type, eg. simple
 *
 * Returns:     int - 0 = okay
 *
 * *****************************************************************************
 */
static int _manageReferralCredentials(LDAP *ld, char **dn, char **credp,
    int *methodp, int freeit, void *arg __unused)
{
	int result = 0;
	static char *sDN = NULL;
	static char *sPasswd = NULL;
	static int  sMethod = LDAP_AUTH_SIMPLE;

	/* -------- */

	if (freeit == 1)
	{
		/* second call - free memory */

		if ((dn != NULL) && (*dn != NULL))
		{
			free(*dn);
		}

		if ((credp != NULL) && (*credp != NULL))
		{
			free(*credp);
		}
	}

	else
	if ((ld != NULL) &&
	    (dn != NULL) && (credp != NULL) && (methodp != NULL))
	{
		if ((freeit == 0) && (sDN != NULL) && (sPasswd != NULL))
		{
			/* first call - get the saved bind credentials */

			*dn = strdup(sDN);
			*credp = strdup(sPasswd);
			*methodp = sMethod;
		}
		else
		if (freeit == -1)
		{
			/* initial call - save the saved bind credentials */

			sDN = *dn;
			sPasswd = *credp;
			sMethod = *methodp;
		}
		else
		{
			result = 1;	/* error */
		}
	}
	else
	{
		result = 1;	/* error */
	}

	return (result);
} /* _manageReferralCredentials */
