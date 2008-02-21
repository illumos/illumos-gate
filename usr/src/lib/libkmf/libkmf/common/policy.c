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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <ctype.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <kmfapiP.h>
#include <libxml/tree.h>
#include <libxml/parser.h>

typedef struct {
	char	*ekuname;
	KMF_OID	*oid;
} EKUName2OID;

static EKUName2OID EKUList[] = {
	{"serverAuth",		(KMF_OID *)&KMFOID_PKIX_KP_ServerAuth},
	{"clientAuth",		(KMF_OID *)&KMFOID_PKIX_KP_ClientAuth},
	{"codeSigning",		(KMF_OID *)&KMFOID_PKIX_KP_CodeSigning},
	{"emailProtection",	(KMF_OID *)&KMFOID_PKIX_KP_EmailProtection},
	{"ipsecEndSystem",	(KMF_OID *)&KMFOID_PKIX_KP_IPSecEndSystem},
	{"ipsecTunnel",		(KMF_OID *)&KMFOID_PKIX_KP_IPSecTunnel},
	{"ipsecUser",		(KMF_OID *)&KMFOID_PKIX_KP_IPSecUser},
	{"timeStamping",	(KMF_OID *)&KMFOID_PKIX_KP_TimeStamping},
	{"OCSPSigning", 	(KMF_OID *)&KMFOID_PKIX_KP_OCSPSigning}
};

static int num_ekus = sizeof (EKUList) / sizeof (EKUName2OID);

static void
addFormatting(xmlNodePtr parent, char *text)
{
	xmlNodePtr snode;

	if (parent == NULL || text == NULL)
		return;

	snode = xmlNewText((const xmlChar *)text);
	if (snode != NULL) {
		xmlAddChild(parent, snode);
	}
}

static void
parseOCSPValidation(xmlNodePtr node, KMF_VALIDATION_POLICY *vinfo)
{
	xmlNodePtr n;
	char *c;
	n = node->children;
	while (n != NULL) {
		if (!xmlStrcmp((const xmlChar *)n->name,
		    (const xmlChar *)KMF_OCSP_BASIC_ELEMENT)) {

			vinfo->ocsp_info.basic.responderURI =
			    (char *)xmlGetProp(n,
			    (const xmlChar *)KMF_OCSP_RESPONDER_ATTR);

			vinfo->ocsp_info.basic.proxy = (char *)xmlGetProp(n,
			    (const xmlChar *)KMF_OCSP_PROXY_ATTR);

			c = (char *)xmlGetProp(n,
			    (const xmlChar *)KMF_OCSP_URI_ATTR);
			if (c != NULL && !strcasecmp(c, "true")) {
				vinfo->ocsp_info.basic.uri_from_cert = 1;
				xmlFree(c);
			}

			vinfo->ocsp_info.basic.response_lifetime =
			    (char *)xmlGetProp(n,
			    (const xmlChar *)KMF_OCSP_RESPONSE_LIFETIME_ATTR);

			c = (char *)xmlGetProp(n,
			    (const xmlChar *)KMF_OCSP_IGNORE_SIGN_ATTR);
			if (c != NULL && !strcasecmp(c, "true")) {
				vinfo->ocsp_info.basic.ignore_response_sign = 1;
				xmlFree(c);
			}

		} else if (!xmlStrcmp((const xmlChar *)n->name,
		    (const xmlChar *)KMF_OCSP_RESPONDER_CERT_ELEMENT)) {

			vinfo->ocsp_info.resp_cert.name =
			    (char *)xmlGetProp(n,
			    (const xmlChar *)KMF_CERT_NAME_ATTR);
			vinfo->ocsp_info.resp_cert.serial =
			    (char *)xmlGetProp(n,
			    (const xmlChar *)KMF_CERT_SERIAL_ATTR);
			vinfo->ocsp_info.has_resp_cert = 1;
		}

		n = n->next;
	}

}

/*
 * Parse the "validation-methods" section of the policy.
 */
static void
parseValidation(xmlNodePtr node, KMF_VALIDATION_POLICY *vinfo,
	KMF_POLICY_RECORD *policy)
{
	xmlNodePtr n;
	char *c;
	n = node->children;
	while (n != NULL) {
		if (!xmlStrcmp((const xmlChar *)n->name,
		    (const xmlChar *)KMF_OCSP_ELEMENT)) {

			parseOCSPValidation(n, &policy->validation_info);
			policy->revocation |= KMF_REVOCATION_METHOD_OCSP;


		} else if (!xmlStrcmp((const xmlChar *)n->name,
		    (const xmlChar *)KMF_CRL_ELEMENT)) {

			vinfo->crl_info.basefilename = (char *)xmlGetProp(n,
			    (const xmlChar *)KMF_CRL_BASENAME_ATTR);

			vinfo->crl_info.directory = (char *)xmlGetProp(n,
			    (const xmlChar *)KMF_CRL_DIRECTORY_ATTR);

			c = (char *)xmlGetProp(n,
			    (const xmlChar *)KMF_CRL_GET_URI_ATTR);
			if (c != NULL && !strcasecmp(c, "true")) {
				vinfo->crl_info.get_crl_uri = 1;
			} else {
				vinfo->crl_info.get_crl_uri = 0;
			}
			xmlFree(c);

			vinfo->crl_info.proxy = (char *)xmlGetProp(n,
			    (const xmlChar *)KMF_CRL_PROXY_ATTR);

			c = (char *)xmlGetProp(n,
			    (const xmlChar *)KMF_CRL_IGNORE_SIGN_ATTR);
			if (c != NULL && !strcasecmp(c, "true")) {
				vinfo->crl_info.ignore_crl_sign = 1;
			} else {
				vinfo->crl_info.ignore_crl_sign = 0;
			}
			xmlFree(c);

			c = (char *)xmlGetProp(n,
			    (const xmlChar *)KMF_CRL_IGNORE_DATE_ATTR);
			if (c != NULL && !strcasecmp(c, "true")) {
				vinfo->crl_info.ignore_crl_date = 1;
			} else {
				vinfo->crl_info.ignore_crl_date = 0;
			}
			xmlFree(c);

			policy->revocation |= KMF_REVOCATION_METHOD_CRL;
		}

		n = n->next;
	}
}

char *
kmf_ku_to_string(uint32_t bitfield)
{
	if (bitfield & KMF_digitalSignature)
		return ("digitalSignature");

	if (bitfield & KMF_nonRepudiation)
		return ("nonRepudiation");

	if (bitfield & KMF_keyEncipherment)
		return ("keyEncipherment");

	if (bitfield & KMF_dataEncipherment)
		return ("dataEncipherment");

	if (bitfield & KMF_keyAgreement)
		return ("keyAgreement");

	if (bitfield & KMF_keyCertSign)
		return ("keyCertSign");

	if (bitfield & KMF_cRLSign)
		return ("cRLSign");

	if (bitfield & KMF_encipherOnly)
		return ("encipherOnly");

	if (bitfield & KMF_decipherOnly)
		return ("decipherOnly");

	return (NULL);
}

uint32_t
kmf_string_to_ku(char *kustring)
{
	if (kustring == NULL || !strlen(kustring))
		return (0);
	if (strcasecmp(kustring, "digitalSignature") == 0)
		return (KMF_digitalSignature);
	if (strcasecmp(kustring, "nonRepudiation") == 0)
		return (KMF_nonRepudiation);
	if (strcasecmp(kustring, "keyEncipherment") == 0)
		return (KMF_keyEncipherment);
	if (strcasecmp(kustring, "dataEncipherment") == 0)
		return (KMF_dataEncipherment);
	if (strcasecmp(kustring, "keyAgreement") == 0)
		return (KMF_keyAgreement);
	if (strcasecmp(kustring, "keyCertSign") == 0)
		return (KMF_keyCertSign);
	if (strcasecmp(kustring, "cRLSign") == 0)
		return (KMF_cRLSign);
	if (strcasecmp(kustring, "encipherOnly") == 0)
		return (KMF_encipherOnly);
	if (strcasecmp(kustring, "decipherOnly") == 0)
		return (KMF_decipherOnly);

	return (0);
}

static void
parseKeyUsageSet(xmlNodePtr node, uint32_t *kubits)
{
	xmlNodePtr n;
	char *c;

	n = node->children;
	while (n != NULL) {
		if (!xmlStrcmp((const xmlChar *)n->name,
		    (const xmlChar *)KMF_KEY_USAGE_ELEMENT)) {
			c = (char *)xmlGetProp(n,
			    (const xmlChar *)KMF_KEY_USAGE_USE_ATTR);
			if (c) {
				*kubits |= kmf_string_to_ku(c);
				xmlFree(c);
			}
		}

		n = n->next;
	}
}

static KMF_OID *
dup_oid(KMF_OID *oldoid)
{
	KMF_OID *oid;

	oid = malloc(sizeof (KMF_OID));
	if (oid == NULL)
		return (NULL);

	oid->Length = oldoid->Length;
	oid->Data = malloc(oid->Length);
	if (oid->Data == NULL) {
		free(oid);
		return (NULL);
	}
	(void) memcpy(oid->Data, oldoid->Data, oid->Length);

	return (oid);
}

KMF_OID *
kmf_ekuname_to_oid(char *ekuname)
{
	KMF_OID *oid;
	int i;

	if (ekuname == NULL)
		return (NULL);

	for (i = 0; i < num_ekus; i++) {
		if (strcasecmp(EKUList[i].ekuname, ekuname) == 0) {
			oid = dup_oid(EKUList[i].oid);
			return (oid);
		}
	}

	return (NULL);
}

char *
kmf_oid_to_ekuname(KMF_OID *oid)
{
	int i;
	for (i = 0; i < num_ekus; i++) {
		if (oid->Length == EKUList[i].oid->Length &&
		    !memcmp(oid->Data, EKUList[i].oid->Data, oid->Length)) {
			return (EKUList[i].ekuname);
		}
	}
	return (NULL);
}

static KMF_RETURN
parseExtKeyUsage(xmlNodePtr node, KMF_EKU_POLICY *ekus)
{
	xmlNodePtr n;
	char *c;
	KMF_RETURN ret = KMF_OK;
	boolean_t found = FALSE;

	n = node->children;
	while (n != NULL && ret == KMF_OK) {
		KMF_OID newoid, *oidptr;

		oidptr = NULL;
		newoid.Data = NULL;
		newoid.Length = 0;

		if (!xmlStrcmp((const xmlChar *)n->name,
		    (const xmlChar *)KMF_EKU_NAME_ELEMENT)) {
			c = (char *)xmlGetProp(n,
			    (const xmlChar *)KMF_EKU_NAME_ATTR);
			if (c != NULL) {
				oidptr = kmf_ekuname_to_oid(c);
				xmlFree(c);
				found = TRUE;
				if (oidptr != NULL)
					newoid = *oidptr;
			}
		} else if (!xmlStrcmp((const xmlChar *)n->name,
		    (const xmlChar *)KMF_EKU_OID_ELEMENT)) {
			c = (char *)xmlGetProp(n,
			    (const xmlChar *)KMF_EKU_OID_ATTR);
			if (c != NULL) {
				(void) kmf_string_to_oid(c, &newoid);
				xmlFree(c);
				found = TRUE;
			}
		} else {
			n = n->next;
			if ((n == NULL) && (!found))
				ret = KMF_ERR_POLICY_DB_FORMAT;
			continue;
		}

		if (newoid.Data != NULL) {
			ekus->eku_count++;
			ekus->ekulist = realloc(ekus->ekulist,
			    ekus->eku_count * sizeof (KMF_OID));
			if (ekus->ekulist != NULL) {
				ekus->ekulist[ekus->eku_count-1].Length =
				    newoid.Length;
				ekus->ekulist[ekus->eku_count-1].Data =
				    newoid.Data;
			} else {
				ret = KMF_ERR_MEMORY;
			}
		} else {
			ret = KMF_ERR_POLICY_DB_FORMAT;
		}

		n = n->next;
	}

	return (ret);
}

int
parsePolicyElement(xmlNodePtr node, KMF_POLICY_RECORD *policy)
{
	int ret = 0;
	xmlNodePtr n = node->xmlChildrenNode;
	char *c;

	if (node->type == XML_ELEMENT_NODE) {
		if (node->properties != NULL) {
			policy->name = (char *)xmlGetProp(node,
			    (const xmlChar *)KMF_POLICY_NAME_ATTR);

			c = (char *)xmlGetProp(node,
			    (const xmlChar *)KMF_OPTIONS_IGNORE_DATE_ATTR);
			if (c && !strcasecmp(c, "true")) {
				policy->ignore_date = 1;
				xmlFree((xmlChar *)c);
			}

			c = (char *)xmlGetProp(node,
			    (const xmlChar *)KMF_OPTIONS_IGNORE_UNKNOWN_EKUS);
			if (c && !strcasecmp(c, "true")) {
				policy->ignore_unknown_ekus = 1;
				xmlFree(c);
			}

			c = (char *)xmlGetProp(node,
			    (const xmlChar *)KMF_OPTIONS_IGNORE_TRUST_ANCHOR);
			if (c && !strcasecmp(c, "true")) {
				policy->ignore_trust_anchor = 1;
				xmlFree(c);
			}

			c = (char *)xmlGetProp(node,
			    (const xmlChar *)KMF_OPTIONS_VALIDITY_ADJUSTTIME);
			if (c) {
				policy->validity_adjusttime = c;
			} else {
				policy->validity_adjusttime = NULL;
			}

			policy->ta_name = (char *)xmlGetProp(node,
			    (const xmlChar *)KMF_POLICY_TA_NAME_ATTR);

			policy->ta_serial = (char *)xmlGetProp(node,
			    (const xmlChar *)KMF_POLICY_TA_SERIAL_ATTR);
		}

		n = node->children;
		while (n != NULL) {
			if (!xmlStrcmp((const xmlChar *)n->name,
			    (const xmlChar *)KMF_VALIDATION_METHODS_ELEMENT))
				parseValidation(n, &policy->validation_info,
				    policy);
			else if (!xmlStrcmp((const xmlChar *)n->name,
			    (const xmlChar *)KMF_KEY_USAGE_SET_ELEMENT))
				parseKeyUsageSet(n, &policy->ku_bits);
			else if (!xmlStrcmp((const xmlChar *)n->name,
			    (const xmlChar *)KMF_EKU_ELEMENT)) {
				ret = parseExtKeyUsage(n, &policy->eku_set);
				if (ret != KMF_OK)
					return (ret);
			}

			n = n->next;
		}
	}

	return (ret);
}

static int
newprop(xmlNodePtr node, char *attrname, char *src)
{
	xmlAttrPtr newattr;

	if (src != NULL && strlen(src)) {
		newattr = xmlNewProp(node, (const xmlChar *)attrname,
		    (xmlChar *)src);
		if (newattr == NULL) {
			xmlUnlinkNode(node);
			xmlFreeNode(node);
			return (-1);
		}
	}
	return (0);
}

/*
 * Add CRL policy information to the XML tree.
 * Return non-zero on any failure, else 0 for success.
 *
 * This function is called only when the KMF_REVOCATION_METHOD_CRL flag is on.
 */
static int
AddCRLNodes(xmlNodePtr node, KMF_CRL_POLICY *crlinfo)
{
	xmlNodePtr n;

	addFormatting(node, "\t\t");
	n = xmlNewChild(node, NULL, (const xmlChar *)"crl", NULL);
	if (n == NULL)
		return (-1);

	if (crlinfo->basefilename &&
	    newprop(n, KMF_CRL_BASENAME_ATTR, crlinfo->basefilename))
		return (-1);

	if (crlinfo->directory &&
	    newprop(n, KMF_CRL_DIRECTORY_ATTR, crlinfo->directory))
		return (-1);

	if (crlinfo->get_crl_uri &&
	    newprop(n, KMF_CRL_GET_URI_ATTR, "TRUE")) {
		return (-1);
	}

	if (crlinfo->proxy &&
	    newprop(n, KMF_CRL_PROXY_ATTR, crlinfo->proxy))
		return (-1);

	if (crlinfo->ignore_crl_sign &&
	    newprop(n, KMF_CRL_IGNORE_SIGN_ATTR, "TRUE")) {
		return (-1);
	}

	if (crlinfo->ignore_crl_date &&
	    newprop(n, KMF_CRL_IGNORE_DATE_ATTR, "TRUE")) {
		return (-1);
	}

	addFormatting(node, "\n");
	return (0);
}

/*
 * Add OCSP information to the policy tree.
 * Return non-zero on any failure, else 0 for success.
 *
 * This function is called only when the KMF_REVOCATION_METHOD_OCSP flag is on.
 */
static int
AddOCSPNodes(xmlNodePtr parent, KMF_OCSP_POLICY *ocsp)
{
	int ret = 0;
	xmlNodePtr n_ocsp, n_basic, n_resp;
	KMF_OCSP_BASIC_POLICY *basic;
	KMF_RESP_CERT_POLICY *resp_cert;

	basic = &(ocsp->basic);
	resp_cert = &(ocsp->resp_cert);

	if (basic->responderURI != NULL || basic->uri_from_cert == B_TRUE) {

		addFormatting(parent, "\t\t");

		/* basic node */
		n_ocsp = xmlNewChild(parent, NULL,
		    (const xmlChar *)KMF_OCSP_ELEMENT, NULL);
		if (n_ocsp == NULL)
			return (-1);
		addFormatting(n_ocsp, "\n\t\t\t");

		n_basic = xmlNewChild(n_ocsp, NULL,
		    (const xmlChar *)KMF_OCSP_BASIC_ELEMENT, NULL);
		if (n_basic == NULL)
			return (-1);
		if (basic->responderURI && newprop(n_basic,
		    KMF_OCSP_RESPONDER_ATTR, basic->responderURI))
			return (-1);
		if (basic->proxy &&
		    newprop(n_basic, KMF_OCSP_PROXY_ATTR, basic->proxy))
			return (-1);
		if (basic->uri_from_cert &&
		    newprop(n_basic, KMF_OCSP_URI_ATTR, "TRUE"))
			return (-1);
		if (basic->response_lifetime &&
		    newprop(n_basic, KMF_OCSP_RESPONSE_LIFETIME_ATTR,
		    basic->response_lifetime))
			return (-1);
		if (basic->ignore_response_sign &&
		    newprop(n_basic, KMF_OCSP_IGNORE_SIGN_ATTR, "TRUE"))
			return (-1);

		addFormatting(n_ocsp, "\n\t\t\t");

		/* responder cert node */
		if (ocsp->has_resp_cert) {
			n_resp = xmlNewChild(n_ocsp, NULL,
			    (const xmlChar *)KMF_OCSP_RESPONDER_CERT_ELEMENT,
			    NULL);
			if (n_resp == NULL)
				return (-1);
			if (newprop(n_resp, KMF_CERT_NAME_ATTR,
			    resp_cert->name))
				return (-1);
			if (newprop(n_resp, KMF_CERT_SERIAL_ATTR,
			    resp_cert->serial))
				return (-1);
		}
		addFormatting(n_ocsp, "\n\t\t");
	}

	addFormatting(parent, "\n");
	return (ret);
}

/*
 * Add validation method information to the policy tree.
 * Return non-zero on any failure, else 0 for success.
 */
static int
AddValidationNodes(xmlNodePtr parent, KMF_POLICY_RECORD *policy)
{
	xmlNodePtr mnode;
	int ret = 0;

	addFormatting(parent, "\t");
	mnode = xmlNewChild(parent, NULL,
	    (const xmlChar *)KMF_VALIDATION_METHODS_ELEMENT, NULL);
	if (mnode == NULL)
		return (-1);

	addFormatting(mnode, "\n");

	if (policy->revocation & KMF_REVOCATION_METHOD_OCSP) {
		ret = AddOCSPNodes(mnode, &(policy->validation_info.ocsp_info));
		if (ret != KMF_OK)
			goto end;
	}

	if (policy->revocation & KMF_REVOCATION_METHOD_CRL) {
		ret = AddCRLNodes(mnode, &(policy->validation_info.crl_info));
		if (ret != KMF_OK)
			goto end;
	}

	addFormatting(mnode, "\t");
	addFormatting(parent, "\n");

end:
	if (ret != 0) {
		xmlUnlinkNode(mnode);
		xmlFreeNode(mnode);
	}
	return (ret);

}

/*
 * Add Key Usage information to the policy tree.
 * Return non-zero on any failure, else 0 for success.
 */
static KMF_RETURN
AddKeyUsageNodes(xmlNodePtr parent, uint32_t kubits)
{
	int ret = KMF_OK;
	int i;

	xmlNodePtr kuset, kunode;

	if (kubits == 0)
		return (0);

	addFormatting(parent, "\n\t");
	kuset = xmlNewChild(parent, NULL,
	    (const xmlChar *)KMF_KEY_USAGE_SET_ELEMENT, NULL);
	if (kuset == NULL)
		return (KMF_ERR_POLICY_ENGINE);

	for (i = KULOWBIT; i <= KUHIGHBIT && ret == KMF_OK; i++) {
		char *s = kmf_ku_to_string((kubits & (1<<i)));
		if (s != NULL) {
			addFormatting(kuset, "\n\t\t");

			kunode = xmlNewChild(kuset, NULL,
			    (const xmlChar *)KMF_KEY_USAGE_ELEMENT, NULL);
			if (kunode == NULL)
				ret = KMF_ERR_POLICY_ENGINE;

			else if (newprop(kunode, KMF_KEY_USAGE_USE_ATTR, s))
				ret = KMF_ERR_POLICY_ENGINE;
		}
	}
	addFormatting(kuset, "\n\t");
	addFormatting(parent, "\n");

	if (ret != KMF_OK) {
		xmlUnlinkNode(kuset);
		xmlFreeNode(kuset);
	}

	return (ret);
}

/*
 * Add Extended-Key-Usage information to the policy tree.
 * Return non-zero on any failure, else 0 for success.
 */
static KMF_RETURN
AddExtKeyUsageNodes(xmlNodePtr parent, KMF_EKU_POLICY *ekus)
{
	KMF_RETURN ret = KMF_OK;
	xmlNodePtr n, kunode;
	int i;

	if (ekus != NULL && ekus->eku_count > 0) {
		addFormatting(parent, "\n\t");
		n = xmlNewChild(parent, NULL,
		    (const xmlChar *)KMF_EKU_ELEMENT, NULL);
		if (n == NULL)
			return (KMF_ERR_POLICY_ENGINE);

		for (i = 0; i < ekus->eku_count; i++) {
			char *s = kmf_oid_to_string(&ekus->ekulist[i]);
			if (s != NULL) {
				addFormatting(n, "\n\t\t");
				kunode = xmlNewChild(n, NULL,
				    (const xmlChar *)KMF_EKU_OID_ELEMENT,
				    NULL);
				if (kunode == NULL)
					ret = KMF_ERR_POLICY_ENGINE;

				else if (newprop(kunode, KMF_EKU_OID_ATTR, s))
					ret = KMF_ERR_POLICY_ENGINE;
				free(s);
			} else {
				ret = KMF_ERR_POLICY_ENGINE;
			}
		}
		addFormatting(n, "\n\t");
		addFormatting(parent, "\n");
	}

	if (ret != KMF_OK) {
		xmlUnlinkNode(n);
		xmlFreeNode(n);
	}
	return (ret);
}

void
kmf_free_eku_policy(KMF_EKU_POLICY *ekus)
{
	if (ekus->eku_count > 0) {
		int i;
		for (i = 0; i < ekus->eku_count; i++) {
			kmf_free_data(&ekus->ekulist[i]);
		}
		free(ekus->ekulist);
	}
}

#define	FREE_POLICY_STR(s) if (s != NULL) free(s);

void
kmf_free_policy_record(KMF_POLICY_RECORD *policy)
{
	if (policy == NULL)
		return;

	FREE_POLICY_STR(policy->name)
	FREE_POLICY_STR(policy->VAL_OCSP_BASIC.responderURI)
	FREE_POLICY_STR(policy->VAL_OCSP_BASIC.proxy)
	FREE_POLICY_STR(policy->VAL_OCSP_BASIC.response_lifetime)
	FREE_POLICY_STR(policy->VAL_OCSP_RESP_CERT.name)
	FREE_POLICY_STR(policy->VAL_OCSP_RESP_CERT.serial)
	FREE_POLICY_STR(policy->validation_info.crl_info.basefilename)
	FREE_POLICY_STR(policy->validation_info.crl_info.directory)
	FREE_POLICY_STR(policy->validation_info.crl_info.proxy)
	FREE_POLICY_STR(policy->validity_adjusttime)
	FREE_POLICY_STR(policy->ta_name)
	FREE_POLICY_STR(policy->ta_serial)

	kmf_free_eku_policy(&policy->eku_set);

	(void) memset(policy, 0, sizeof (KMF_POLICY_RECORD));
}

/*
 * kmf_get_policy
 *
 * Find a policy record in the database.
 */
KMF_RETURN
kmf_get_policy(char *filename, char *policy_name, KMF_POLICY_RECORD *plc)
{
	KMF_RETURN ret = KMF_OK;
	xmlParserCtxtPtr ctxt;
	xmlDocPtr doc = NULL;
	xmlNodePtr cur, node;
	int found = 0;

	if (filename == NULL || policy_name == NULL || plc == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	(void) memset(plc, 0, sizeof (KMF_POLICY_RECORD));

	/* Create a parser context */
	ctxt = xmlNewParserCtxt();
	if (ctxt == NULL)
		return (KMF_ERR_POLICY_DB_FORMAT);

	/* Read the policy DB and verify it against the schema. */
	doc = xmlCtxtReadFile(ctxt, filename, NULL,
	    XML_PARSE_DTDVALID | XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
	if (doc == NULL || ctxt->valid == 0) {
		ret = KMF_ERR_POLICY_DB_FORMAT;
		goto out;
	}

	cur = xmlDocGetRootElement(doc);
	if (cur == NULL) {
		ret = KMF_ERR_POLICY_DB_FORMAT;
		goto out;
	}

	node = cur->xmlChildrenNode;
	while (node != NULL && !found) {
		char *c;
		/*
		 * Search for the policy that matches the given name.
		 */
		if (!xmlStrcmp((const xmlChar *)node->name,
		    (const xmlChar *)KMF_POLICY_ELEMENT)) {
			/* Check the name attribute */
			c = (char *)xmlGetProp(node,
			    (const xmlChar *)KMF_POLICY_NAME_ATTR);

			/* If a match, parse the rest of the data */
			if (c != NULL) {
				if (strcmp(c, policy_name) == 0) {
					ret = parsePolicyElement(node, plc);
					found = (ret == KMF_OK);
				}
				xmlFree(c);
			}
		}
		node = node->next;
	}

	if (!found) {
		ret = KMF_ERR_POLICY_NOT_FOUND;
		goto out;
	}

out:
	if (ctxt != NULL)
		xmlFreeParserCtxt(ctxt);

	if (doc != NULL)
		xmlFreeDoc(doc);

	return (ret);
}

/*
 * kmf_set_policy
 *
 * Set the policy record in the handle.  This searches
 * the policy DB for the named policy.  If it is not found
 * or an error occurred in processing, the existing policy
 * is kept and an error code is returned.
 */
KMF_RETURN
kmf_set_policy(KMF_HANDLE_T handle, char *policyfile, char *policyname)
{
	KMF_RETURN ret = KMF_OK;
	KMF_POLICY_RECORD *newpolicy = NULL;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	newpolicy = malloc(sizeof (KMF_POLICY_RECORD));
	if (newpolicy == NULL)
		return (KMF_ERR_MEMORY);
	(void) memset(newpolicy, 0, sizeof (KMF_POLICY_RECORD));

	ret = kmf_get_policy(
	    policyfile == NULL ? KMF_DEFAULT_POLICY_FILE : policyfile,
	    policyname == NULL ? KMF_DEFAULT_POLICY_NAME : policyname,
	    newpolicy);
	if (ret != KMF_OK)
		goto out;

	ret = kmf_verify_policy(newpolicy);
	if (ret != KMF_OK)
		goto out;

	/* release the existing policy data (if any). */
	if (handle->policy != NULL) {
		kmf_free_policy_record(handle->policy);
		free(handle->policy);
	}

	handle->policy = newpolicy;

out:
	/* Cleanup any data allocated before the error occurred */
	if (ret != KMF_OK) {
		kmf_free_policy_record(newpolicy);
		free(newpolicy);
	}

	return (ret);
}


static KMF_RETURN
deletePolicyNode(xmlNodePtr node, char *policy_name)
{
	KMF_RETURN ret = KMF_OK;
	int found = 0;
	xmlNodePtr dnode = NULL;

	while (node != NULL && !found) {
		char *c;
		/*
		 * Search for the policy that matches the given name.
		 */
		if (!xmlStrcmp((const xmlChar *)node->name,
		    (const xmlChar *)KMF_POLICY_ELEMENT)) {
			/* Check the name attribute */
			c = (char *)xmlGetProp(node,
			    (const xmlChar *)KMF_POLICY_NAME_ATTR);

			/* If a match, parse the rest of the data */
			if (c != NULL) {
				if (strcmp(c, policy_name) == 0) {
					found = 1;
					dnode = node;
				}
				xmlFree(c);
			}
		}
		if (!found)
			node = node->next;
	}

	if (found && dnode != NULL) {
		/* Unlink the node */
		xmlUnlinkNode(dnode);

		/* Delete it from the document tree */
		xmlFreeNode(dnode);
	} else {
		ret = KMF_ERR_POLICY_NOT_FOUND;
	}

	return (ret);
}

/*
 * update_policyfile
 *
 * Attempt to do a "safe" file update as follows:
 *  1. Lock the original file.
 *  2. Create and write to a temporary file
 *  3. Replace the original file with the temporary file.
 */
static KMF_RETURN
update_policyfile(xmlDocPtr doc, char *filename)
{
	KMF_RETURN ret = KMF_OK;
	FILE *pfile, *tmpfile;
	char tmpfilename[MAXPATHLEN];
	char *p;
	int prefix_len, tmpfd;
	mode_t old_mode;

	/*
	 * Open and lock the DB file. First try to open an existing file,
	 * if that fails, open it as if it were new.
	 */
	if ((pfile = fopen(filename, "r+")) == NULL && errno == ENOENT)
		pfile = fopen(filename, "w+");

	if (pfile == NULL)
		return (KMF_ERR_POLICY_DB_FILE);

	if (lockf(fileno(pfile), F_TLOCK, 0) == -1) {
		(void) fclose(pfile);
		return (KMF_ERR_POLICY_DB_FILE);
	}

	/*
	 * Create a temporary file to hold the new data.
	 */
	(void) memset(tmpfilename, 0, sizeof (tmpfilename));
	p = (char *)strrchr(filename, '/');
	if (p == NULL) {
		/*
		 * filename contains basename only so we
		 * create a temp file in current directory.
		 */
		if (strlcpy(tmpfilename, TMPFILE_TEMPLATE,
		    sizeof (tmpfilename)) >= sizeof (tmpfilename))
			return (KMF_ERR_INTERNAL);
	} else {
		/*
		 * create a temp file in the same directory
		 * as the policy file.
		 */
		prefix_len = p - filename;
		(void) strncpy(tmpfilename, filename, prefix_len);
		(void) strncat(tmpfilename, "/", 1);
		(void) strncat(tmpfilename, TMPFILE_TEMPLATE,
		    sizeof (TMPFILE_TEMPLATE));
	}

	old_mode = umask(077);
	tmpfd = mkstemp(tmpfilename);
	(void) umask(old_mode);
	if (tmpfd == -1) {
		return (KMF_ERR_POLICY_DB_FILE);
	}

	if ((tmpfile = fdopen(tmpfd, "w")) == NULL) {
		(void) close(tmpfd);
		(void) unlink(tmpfilename);
		(void) fclose(pfile);
		return (KMF_ERR_POLICY_DB_FILE);
	}

	/*
	 * Write the new info to the temporary file.
	 */
	if (xmlDocFormatDump(tmpfile, doc, 1) == -1) {
		(void) fclose(pfile);
		(void) fclose(tmpfile);
		(void) unlink(tmpfilename);
		return (KMF_ERR_POLICY_ENGINE);
	}

	(void) fclose(pfile);

	if (fchmod(tmpfd, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) == -1) {
		(void) close(tmpfd);
		(void) unlink(tmpfilename);
		return (KMF_ERR_POLICY_DB_FILE);
	}
	if (fclose(tmpfile) != 0)
		return (KMF_ERR_POLICY_DB_FILE);

	/*
	 * Replace the original file with the updated tempfile.
	 */
	if (rename(tmpfilename, filename) == -1) {
		ret = KMF_ERR_POLICY_DB_FILE;
	}

	if (ret != KMF_OK) {
		/* try to remove the tmp file */
		(void) unlink(tmpfilename);
	}

	return (ret);
}

/*
 * kmf_delete_policy_from_db
 *
 * Find a policy by name and remove it from the policy DB file.
 * If the policy is not found, return an error.
 */
KMF_RETURN
kmf_delete_policy_from_db(char *policy_name, char *dbfilename)
{
	KMF_RETURN ret;
	xmlParserCtxtPtr ctxt = NULL;
	xmlDocPtr doc = NULL;
	xmlNodePtr cur, node;

	if (policy_name == NULL || dbfilename == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/*
	 * Cannot delete the default policy record from the system
	 * default policy database (/etc/security/kmfpolicy.xml).
	 */
	if (strcmp(dbfilename, KMF_DEFAULT_POLICY_FILE) == 0 &&
	    strcmp(policy_name, KMF_DEFAULT_POLICY_NAME) == 0)
		return (KMF_ERR_BAD_PARAMETER);

	/* Make sure the policy file exists */
	if (access(dbfilename, R_OK | W_OK))
		return (KMF_ERR_BAD_PARAMETER);

	/* Read the policy DB and verify it against the schema. */
	ctxt = xmlNewParserCtxt();
	if (ctxt == NULL)
		return (KMF_ERR_POLICY_DB_FORMAT);

	doc = xmlCtxtReadFile(ctxt, dbfilename, NULL,
	    XML_PARSE_DTDVALID | XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
	if (doc == NULL || ctxt->valid == 0) {
		ret = KMF_ERR_POLICY_DB_FORMAT;
		goto end;
	}

	cur = xmlDocGetRootElement(doc);
	if (cur == NULL) {
		xmlFreeDoc(doc);
		return (KMF_ERR_POLICY_DB_FORMAT);
	}
	node = cur->xmlChildrenNode;

	ret = deletePolicyNode(node, policy_name);

	if (ret == KMF_OK)
		ret = update_policyfile(doc, dbfilename);

end:
	if (ctxt != NULL)
		xmlFreeParserCtxt(ctxt);

	if (doc != NULL)
		xmlFreeDoc(doc);

	return (ret);
}

/*
 * Add a new policy node to the Policy DB XML tree.
 */
static KMF_RETURN
addPolicyNode(xmlNodePtr pnode, KMF_POLICY_RECORD *policy)
{
	KMF_RETURN ret = KMF_OK;

	if (pnode != NULL && policy != NULL) {
		if (newprop(pnode, KMF_POLICY_NAME_ATTR, policy->name) != 0) {
			ret = KMF_ERR_POLICY_ENGINE;
			goto out;
		}
		if (policy->ignore_date) {
			if (newprop(pnode, KMF_OPTIONS_IGNORE_DATE_ATTR,
			    "TRUE")) {
				ret = KMF_ERR_POLICY_ENGINE;
				goto out;
			}
		}

		if (policy->ignore_unknown_ekus) {
			if (newprop(pnode, KMF_OPTIONS_IGNORE_UNKNOWN_EKUS,
			    "TRUE")) {
				ret = KMF_ERR_POLICY_ENGINE;
				goto out;
			}
		}

		if (policy->ignore_trust_anchor) {
			if (newprop(pnode, KMF_OPTIONS_IGNORE_TRUST_ANCHOR,
			    "TRUE")) {
				ret = KMF_ERR_POLICY_ENGINE;
				goto out;
			}
		}

		if (policy->validity_adjusttime) {
			if (newprop(pnode, KMF_OPTIONS_VALIDITY_ADJUSTTIME,
			    policy->validity_adjusttime)) {
				ret = KMF_ERR_POLICY_ENGINE;
				goto out;
			}
		}

		if (newprop(pnode, KMF_POLICY_TA_NAME_ATTR,
		    policy->ta_name) != 0) {
			ret = KMF_ERR_POLICY_ENGINE;
			goto out;
		}

		if (newprop(pnode, KMF_POLICY_TA_SERIAL_ATTR,
		    policy->ta_serial) != 0) {
			ret = KMF_ERR_POLICY_ENGINE;
			goto out;
		}

		/* Add a text node for readability */
		addFormatting(pnode, "\n");

		if (ret = AddValidationNodes(pnode, policy)) {
			goto out;
		}

		if ((ret = AddKeyUsageNodes(pnode, policy->ku_bits))) {
			goto out;
		}

		if ((ret = AddExtKeyUsageNodes(pnode, &policy->eku_set))) {
			goto out;
		}
	} else {
		ret = KMF_ERR_BAD_PARAMETER;
	}
out:
	if (ret != KMF_OK && pnode != NULL) {
		xmlUnlinkNode(pnode);
		xmlFreeNode(pnode);
	}

	return (ret);
}


KMF_RETURN
kmf_verify_policy(KMF_POLICY_RECORD *policy)
{
	KMF_RETURN ret = KMF_OK;
	boolean_t has_ta;

	if (policy->name == NULL || !strlen(policy->name))
		return (KMF_ERR_POLICY_NAME);

	/* Check the TA related policy */
	if (policy->ta_name != NULL && policy->ta_serial != NULL) {
		has_ta = B_TRUE;
	} else if (policy->ta_name == NULL && policy->ta_serial == NULL) {
		has_ta = B_FALSE;
	} else {
		/*
		 * If the TA cert is set, then both name and serial number
		 * need to be specified.
		 */
		return (KMF_ERR_TA_POLICY);
	}

	if (has_ta == B_FALSE && policy->ignore_trust_anchor == B_FALSE)
		return (KMF_ERR_TA_POLICY);

	if (policy->revocation & KMF_REVOCATION_METHOD_OCSP) {
		/*
		 * For OCSP, either use a fixed responder or use the
		 * value from the cert, but not both.
		 */
		if ((policy->VAL_OCSP_BASIC.responderURI == NULL &&
		    policy->VAL_OCSP_BASIC.uri_from_cert == B_FALSE) ||
		    (policy->VAL_OCSP_BASIC.responderURI != NULL &&
		    policy->VAL_OCSP_BASIC.uri_from_cert == B_TRUE))
			return (KMF_ERR_OCSP_POLICY);

		/*
		 * If the OCSP responder cert is set, then both name and serial
		 * number need to be specified.
		 */
		if ((policy->VAL_OCSP_RESP_CERT.name != NULL &&
		    policy->VAL_OCSP_RESP_CERT.serial == NULL) ||
		    (policy->VAL_OCSP_RESP_CERT.name == NULL &&
		    policy->VAL_OCSP_RESP_CERT.serial != NULL))
			return (KMF_ERR_OCSP_POLICY);
	}

	return (ret);
}

/*
 * Update the KMF policy file by creating a new XML Policy doc tree
 * from the data in the KMF_POLICY_RECORD structure. If "check_policy"
 * is true, then we check the policy sanity also.
 */
KMF_RETURN
kmf_add_policy_to_db(KMF_POLICY_RECORD *policy, char *dbfilename,
    boolean_t check_policy)
{
	KMF_RETURN ret = KMF_OK;
	xmlDocPtr doc = NULL;
	xmlNodePtr root, node;
	xmlParserCtxtPtr ctxt = NULL;

	if (policy == NULL || dbfilename == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	if (check_policy == B_TRUE) {
		if (ret = kmf_verify_policy(policy))
			return (ret);
	}

	/* If the policyDB exists, load it into memory */
	if (!access(dbfilename, R_OK)) {

		/* Create a parser context */
		ctxt = xmlNewParserCtxt();
		if (ctxt == NULL)
			return (KMF_ERR_POLICY_DB_FORMAT);

		doc = xmlCtxtReadFile(ctxt, dbfilename, NULL,
		    XML_PARSE_DTDVALID | XML_PARSE_NOERROR |
		    XML_PARSE_NOWARNING);
		if (doc == NULL || ctxt->valid == 0) {
			ret = KMF_ERR_POLICY_DB_FORMAT;
			goto out;
		}

		root = xmlDocGetRootElement(doc);
		if (root == NULL) {
			ret = KMF_ERR_POLICY_DB_FORMAT;
			goto out;
		}

		node = root->xmlChildrenNode;
		/*
		 * If the DB has an existing policy of the
		 * same name, delete it from the tree.
		 */
		ret = deletePolicyNode(node, policy->name);
		if (ret == KMF_ERR_POLICY_NOT_FOUND)
			ret = KMF_OK;
	} else {
		/* Initialize a new DB tree */
		doc = xmlNewDoc((const xmlChar *)"1.0");
		if (doc == NULL)
			return (KMF_ERR_POLICY_ENGINE);

		/*
		 * Add the DOCTYPE header to the tree so the
		 * DTD link is embedded
		 */
		doc->intSubset = xmlCreateIntSubset(doc,
		    (const xmlChar *)KMF_POLICY_ROOT,
		    NULL, (const xmlChar *)KMF_POLICY_DTD);

		root = xmlNewDocNode(doc, NULL,
		    (const xmlChar *)KMF_POLICY_ROOT, NULL);
		if (root != NULL) {
			xmlDocSetRootElement(doc, root);
		}
	}

	/* Append the new policy info to the root node. */
	if (root != NULL) {
		xmlNodePtr pnode;

		pnode = xmlNewChild(root, NULL,
		    (const xmlChar *)KMF_POLICY_ELEMENT, NULL);

		ret = addPolicyNode(pnode, policy);
		/* If that worked, update the DB file. */
		if (ret == KMF_OK)
			ret = update_policyfile(doc, dbfilename);
	} else {
		ret = KMF_ERR_POLICY_ENGINE;
	}


out:
	if (ctxt != NULL)
		xmlFreeParserCtxt(ctxt);

	if (doc != NULL)
		xmlFreeDoc(doc);

	return (ret);
}
