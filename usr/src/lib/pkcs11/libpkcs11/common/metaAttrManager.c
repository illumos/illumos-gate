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
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

#include <string.h>
#include <stdlib.h>
#include <strings.h>
#include "metaGlobal.h"
#include "metaAttrMasters.h"

static void
find_attribute(CK_ATTRIBUTE_TYPE attrtype, generic_attr_t *attributes,
	size_t num_attributes, generic_attr_t **found_attribute);

/*
 * get_master_attributes_by_object
 *
 * Returns an (statically allocated) set of object attributes, as determined by
 * class and keytype of the supplied object.  The attributes are only
 * initialized to default values.
 */
CK_RV
get_master_attributes_by_object(slot_session_t *session,
    slot_object_t *slot_object, generic_attr_t **attributes,
    size_t *num_attributes)
{
	CK_RV rv;
	CK_ATTRIBUTE attr;
	CK_OBJECT_CLASS class;
	CK_ULONG subtype = CK_UNAVAILABLE_INFORMATION;

	/* first get the class */
	attr.type = CKA_CLASS;
	attr.pValue = &class;
	attr.ulValueLen = sizeof (class);
	rv = FUNCLIST(session->fw_st_id)->C_GetAttributeValue(
	    session->hSession, slot_object->hObject, &attr, 1);
	if (rv != CKR_OK) {
		return (rv);
	}

	attr.pValue = &subtype;
	attr.ulValueLen = sizeof (subtype);
	switch (class) {
		case CKO_CERTIFICATE:
			attr.type = CKA_CERTIFICATE_TYPE;
			break;
		case CKO_HW_FEATURE:
			attr.type = CKA_HW_FEATURE_TYPE;
			break;
		case CKO_PUBLIC_KEY:
		case CKO_PRIVATE_KEY:
		case CKO_SECRET_KEY:
		case CKO_DOMAIN_PARAMETERS:
			attr.type = CKA_KEY_TYPE;
			break;
		case CKO_DATA:
			goto get_attr;
		default:
			/* should never be here */
			return (CKR_ATTRIBUTE_VALUE_INVALID);
	}
	rv = FUNCLIST(session->fw_st_id)->C_GetAttributeValue(
	    session->hSession, slot_object->hObject, &attr, 1);
	if (rv != CKR_OK) {
		return (rv);
	}

get_attr:
	rv = get_master_attributes_by_type(class, subtype,
	    attributes, num_attributes);

	return (rv);
}

/*
 * get_master_attributes_by_template
 *
 * Returns an (statically allocated) set of object attributes, as determined by
 * the supplied object template. The template is only used to determine the
 * class/subclass of the object. The attributes are only initialized to
 * default values.
 */
CK_RV
get_master_attributes_by_template(
	CK_ATTRIBUTE *template, CK_ULONG template_size,
	generic_attr_t **attributes, size_t *num_attributes)
{
	CK_OBJECT_CLASS class;
	CK_ULONG subtype = CK_UNAVAILABLE_INFORMATION;
	boolean_t found;

	found = get_template_ulong(CKA_CLASS, template, template_size, &class);
	if (!found) {
		return (CKR_TEMPLATE_INCOMPLETE);
	}

	switch (class) {
		case CKO_CERTIFICATE:
			found = get_template_ulong(CKA_CERTIFICATE_TYPE,
			    template, template_size, &subtype);
			break;
		case CKO_HW_FEATURE:
			found = get_template_ulong(CKA_HW_FEATURE_TYPE,
			    template, template_size, &subtype);
			break;
		case CKO_PUBLIC_KEY:
		case CKO_PRIVATE_KEY:
		case CKO_SECRET_KEY:
		case CKO_DOMAIN_PARAMETERS:
			found = get_template_ulong(CKA_KEY_TYPE,
			    template, template_size, &subtype);
			break;
		case CKO_DATA:
			/* CKO_DATA has no subtype, just pretend it is found  */
			found = B_TRUE;
			break;
		default:
			/* unknown object class */
			return (CKR_ATTRIBUTE_VALUE_INVALID);
	}

	if (!found) {
		return (CKR_TEMPLATE_INCOMPLETE);
	}

	return (get_master_attributes_by_type(class, subtype,
	    attributes, num_attributes));
}

/*
 * get_master_template_by_type
 *
 * Returns an (statically allocated) set of object attributes, as determined
 * by the specified class and subtype. The attributes are initialized to default
 * values.
 */
CK_RV
get_master_template_by_type(CK_OBJECT_CLASS class, CK_ULONG subtype,
    generic_attr_t **attributes, size_t *num_attributes)
{
	generic_attr_t *master_template = NULL;
	size_t master_template_size = 0;

	switch (class) {
	case CKO_HW_FEATURE:
		switch (subtype) {
		case CKO_HW_FEATURE:
			master_template = (generic_attr_t *)OBJ_HW_CLOCK;
			master_template_size = sizeof (OBJ_HW_CLOCK);
			break;

		case CKH_MONOTONIC_COUNTER:
			master_template = (generic_attr_t *)OBJ_HW_MONOTONIC;
			master_template_size = sizeof (OBJ_HW_MONOTONIC);
			break;

		default:
			/* Unsupported. */
			break;
		}
		break;

	case CKO_DATA:
		/* Objects of this class have no subtype. */
		master_template = (generic_attr_t *)OBJ_DATA;
		master_template_size = sizeof (OBJ_DATA);
		break;

	case CKO_CERTIFICATE:
		switch (subtype) {
		case CKC_X_509:
			master_template = (generic_attr_t *)OBJ_CERT_X509;
			master_template_size = sizeof (OBJ_CERT_X509);
			break;

		case CKC_X_509_ATTR_CERT:
			master_template = (generic_attr_t *)OBJ_CERT_X509ATTR;
			master_template_size = sizeof (OBJ_CERT_X509ATTR);
			break;

		default:
			/* Unsupported. */
			break;
		}
		break;

	case CKO_PUBLIC_KEY:
		switch (subtype) {
		case CKK_RSA:
			master_template = (generic_attr_t *)OBJ_PUBKEY_RSA;
			master_template_size = sizeof (OBJ_PUBKEY_RSA);
			break;

		case CKK_DSA:
			master_template = (generic_attr_t *)OBJ_PUBKEY_DSA;
			master_template_size = sizeof (OBJ_PUBKEY_DSA);
			break;

		case CKK_EC:
			master_template = (generic_attr_t *)OBJ_PUBKEY_EC;
			master_template_size = sizeof (OBJ_PUBKEY_EC);
			break;

		case CKK_DH:
			master_template = (generic_attr_t *)OBJ_PUBKEY_DH;
			master_template_size = sizeof (OBJ_PUBKEY_DH);
			break;

		case CKK_X9_42_DH:
			master_template = (generic_attr_t *)OBJ_PUBKEY_X942DH;
			master_template_size = sizeof (OBJ_PUBKEY_X942DH);
			break;

		case CKK_KEA:
			master_template = (generic_attr_t *)OBJ_PUBKEY_KEA;
			master_template_size = sizeof (OBJ_PUBKEY_KEA);
			break;

		default:
			/* Unsupported. */
			break;
		}
		break;

	case CKO_PRIVATE_KEY:
		switch (subtype) {
		case CKK_RSA:
			master_template = (generic_attr_t *)OBJ_PRIVKEY_RSA;
			master_template_size = sizeof (OBJ_PRIVKEY_RSA);
			break;

		case CKK_DSA:
			master_template = (generic_attr_t *)OBJ_PRIVKEY_DSA;
			master_template_size = sizeof (OBJ_PRIVKEY_DSA);
			break;

		case CKK_EC:
			master_template = (generic_attr_t *)OBJ_PRIVKEY_EC;
			master_template_size = sizeof (OBJ_PRIVKEY_EC);
			break;

		case CKK_DH:
			master_template = (generic_attr_t *)OBJ_PRIVKEY_DH;
			master_template_size = sizeof (OBJ_PRIVKEY_DH);
			break;

		case CKK_X9_42_DH:
			master_template = (generic_attr_t *)OBJ_PRIVKEY_X942DH;
			master_template_size = sizeof (OBJ_PRIVKEY_X942DH);
			break;

		case CKK_KEA:
			master_template = (generic_attr_t *)OBJ_PRIVKEY_KEA;
			master_template_size = sizeof (OBJ_PRIVKEY_KEA);
			break;

		default:
			/* Unsupported. */
			break;
		}
		break;

	case CKO_SECRET_KEY:
		/*
		 * The only difference between secret keys is that some
		 * are valiable length (eg CKK_AES), while others are not
		 * (eg CKK_DES) -- and do not have a CKA_VALUE_LEN attribute.
		 *
		 * FUTURE(?): Consider using obj_seckey_withlen for unknown
		 * keytypes. This is the most likely choice, as new algorithms
		 * seem to support variable length keys. That's not the default
		 * now, because if people have implemented new key types with
		 * different attribute sets (like the mess of public/private
		 * key types), then incorrect behaviour would result. It's
		 * easier to relax this restriction than to tighten it (which
		 * would introduce a regression to anyone relying on this
		 * working for unknown key types).
		 *
		 */
		switch (subtype) {
		case CKK_DES:
		case CKK_DES2:
		case CKK_DES3:
		case CKK_IDEA:
		case CKK_CDMF:
		case CKK_SKIPJACK:
		case CKK_BATON:
		case CKK_JUNIPER:
			master_template = (generic_attr_t *)OBJ_SECKEY;
			master_template_size = sizeof (OBJ_SECKEY);
			break;

		case CKK_GENERIC_SECRET:
		case CKK_RC2:
		case CKK_RC4:
		case CKK_RC5:
		case CKK_AES:
		case CKK_BLOWFISH:
		case CKK_CAST:
		case CKK_CAST3:
		case CKK_CAST128:
			master_template = (generic_attr_t *)OBJ_SECKEY_WITHLEN;
			master_template_size = sizeof (OBJ_SECKEY_WITHLEN);
			break;

		default:
			/* Unsupported. */
			break;
		}
		break;

	case CKO_DOMAIN_PARAMETERS:
		switch (subtype) {
		case CKK_DSA:
			master_template = (generic_attr_t *)OBJ_DOM_DSA;
			master_template_size = sizeof (OBJ_DOM_DSA);
			break;

		case CKK_DH:
			master_template = (generic_attr_t *)OBJ_DOM_DH;
			master_template_size = sizeof (OBJ_DOM_DH);
			break;

		case CKK_X9_42_DH:
			master_template = (generic_attr_t *)OBJ_DOM_X942DH;
			master_template_size = sizeof (OBJ_DOM_X942DH);
			break;

		default:
			/* Unsupported. */
			break;
		}
		break;

	default:
		/* Unsupported. */
		break;
	}

	/* Requested object is unknown or invalid. */
	if (master_template == NULL)
		return (CKR_ATTRIBUTE_VALUE_INVALID);
	else {
		*attributes = master_template;
		*num_attributes = master_template_size;
		return (CKR_OK);
	}
}


/*
 * get_master_attributes_by_type
 *
 * Returns an (statically allocated) set of object attributes, as determined by
 * the specified class and subtype. The attributes are initialized to default
 * values.
 */
CK_RV
get_master_attributes_by_type(CK_OBJECT_CLASS class, CK_ULONG subtype,
	generic_attr_t **attributes, size_t *num_attributes)
{
	CK_RV rv;
	generic_attr_t *master_template = NULL;
	generic_attr_t *new_attributes;
	size_t i, num_new_attributes, master_template_size = 0;

	/* Determine the appropriate master template needed. */
	rv = get_master_template_by_type(class, subtype,
	    &master_template, &master_template_size);
	if (rv != CKR_OK)
		return (rv);

	/* Duplicate the master template. */
	new_attributes = malloc(master_template_size);
	if (new_attributes == NULL)
		return (CKR_HOST_MEMORY);

	(void) memcpy(new_attributes, master_template, master_template_size);
	num_new_attributes = master_template_size / sizeof (generic_attr_t);

	/* Set the pointer in the appropriate storage area. */
	for (i = 0; i < num_new_attributes; i++) {
		generic_attr_t *attr;

		attr = new_attributes + i;

		switch (attr->attribute.ulValueLen) {
			case (sizeof (CK_ULONG)):
				attr->attribute.pValue = &attr->generic_ulong;
				break;
			case (sizeof (CK_BBOOL)):
				attr->attribute.pValue = &attr->generic_bbool;
				break;
			default:
				attr->attribute.pValue = attr->generic_data;
				break;
		}

	}

	/* Secret keys share a common template, so set the key type here. */
	if (class == CKO_SECRET_KEY) {
		/* Keytype / subtype is always the second attribute. */
		new_attributes[1].generic_ulong = subtype;
	}

	*attributes = new_attributes;
	*num_attributes = num_new_attributes;

	return (CKR_OK);
}


/*
 * get_master_attributes_by_duplication
 *
 * Returns an (statically allocated) set of object attributes, as copied from an
 * existing set of attributes. The new attributes inherit the values from
 * the old attributes.
 */
CK_RV
get_master_attributes_by_duplication(
	generic_attr_t *src_attrs, size_t num_src_attrs,
	generic_attr_t **dst_attrs, size_t *num_dst_attrs)
{
	CK_RV rv = CKR_OK;
	generic_attr_t *new_attrs, *src, *dst;
	size_t i;

	new_attrs = malloc(sizeof (generic_attr_t) * num_src_attrs);
	if (new_attrs == NULL)
		return (CKR_HOST_MEMORY);

	for (i = 0; i < num_src_attrs; i++) {
		src = src_attrs + i;
		dst = new_attrs + i;

		*dst = *src;

		/* Adjust pointers in dst so that they don't point to src. */

		if (src->isMalloced) {
			dst->attribute.pValue =
			    malloc(src->attribute.ulValueLen);

			if (dst->attribute.pValue == NULL) {
				/*
				 * Continue on error, so that the cleanup
				 * routine doesn't see pointers to src_attrs.
				 */
				dst->attribute.ulValueLen = 0;
				rv = CKR_HOST_MEMORY;
				continue;
			}
		} else if (src->attribute.pValue == &src->generic_bbool) {
			dst->attribute.pValue = &dst->generic_bbool;
		} else if (src->attribute.pValue == &src->generic_ulong) {
			dst->attribute.pValue = &dst->generic_ulong;
		} else if (src->attribute.pValue == &src->generic_data) {
			dst->attribute.pValue = &dst->generic_data;
		} else {
			/* This shouldn't happen. */
			dst->attribute.pValue = NULL;
			dst->attribute.ulValueLen = 0;
			rv = CKR_GENERAL_ERROR;
			num_src_attrs = i + 1;
			break;
		}

		(void) memcpy(dst->attribute.pValue, src->attribute.pValue,
		    src->attribute.ulValueLen);
	}

	if (rv != CKR_OK) {
		dealloc_attributes(new_attrs, num_src_attrs);
	} else {
		*dst_attrs = new_attrs;
		*num_dst_attrs = num_src_attrs;
	}

	return (rv);
}


/*
 * dealloc_attributes
 *
 * Deallocates the storage used for a set of attributes. The attribute
 * values are zeroed out before being free'd.
 */
void
dealloc_attributes(generic_attr_t *attributes, size_t num_attributes)
{
	size_t i;
	generic_attr_t *attr;

	for (i = 0; i < num_attributes; i++) {
		attr = attributes + i;

		/*
		 * Zero-out any attribute values. We could do this just for
		 * attributes with isSensitive == True, but it's not much
		 * extra work to just do them all. [Most attributes are just
		 * 1 or 4 bytes]
		 */
		bzero(attr->attribute.pValue, attr->attribute.ulValueLen);

		if (attr->isMalloced)
			free(attr->attribute.pValue);
	}

	free(attributes);
}


/*
 * attribute_set_value
 *
 * Sets the value of the specified attribute. Any portion of the old value
 * which will not be overwritten by the new value is zeroed out.
 */
CK_RV
attribute_set_value(CK_ATTRIBUTE *new_attr,
	generic_attr_t *attributes, size_t num_attributes)
{
	generic_attr_t *attr = NULL;

	if (new_attr == NULL)
		return (CKR_TEMPLATE_INCOMPLETE);
	else if (new_attr->pValue == NULL) {
		return (CKR_ATTRIBUTE_VALUE_INVALID);
	}

	find_attribute(new_attr->type, attributes, num_attributes, &attr);
	if (attr == NULL) {
		return (CKR_ATTRIBUTE_TYPE_INVALID);
	}

	/* Store the new value. */
	if (attr->attribute.ulValueLen >= new_attr->ulValueLen) {
		/* Existing storage is sufficient to store new value. */

		/* bzero() out any data that won't be overwritten. */
		bzero((char *)attr->attribute.pValue + new_attr->ulValueLen,
		    attr->attribute.ulValueLen - new_attr->ulValueLen);

	} else if (new_attr->ulValueLen <= sizeof (attr->generic_data)) {
		/* Use generic storage to avoid a malloc. */

		bzero(attr->attribute.pValue, attr->attribute.ulValueLen);
		if (attr->isMalloced) {
			/*
			 * If app sets a large value (triggering a malloc),
			 * then sets a tiny value, and finally again sets
			 * a large value (phew!) we could end up here.
			 *
			 * FUTURE?: Store the original malloc size, so that
			 * we can regrow the value up to the original size.
			 * This might avoid some heap churn for pathalogic
			 * applications.
			 */
			free(attr->attribute.pValue);
			attr->isMalloced = B_FALSE;
		}

		attr->attribute.pValue = attr->generic_data;

	} else {
		/* Need to allocate storage for the new value. */
		void *newStorage;

		newStorage = malloc(new_attr->ulValueLen);
		if (newStorage == NULL)
			return (CKR_HOST_MEMORY);
		bzero(attr->attribute.pValue, attr->attribute.ulValueLen);
		attr->attribute.pValue = newStorage;
		attr->isMalloced = B_TRUE;
	}

	(void) memcpy(attr->attribute.pValue, new_attr->pValue,
	    new_attr->ulValueLen);
	attr->attribute.ulValueLen = new_attr->ulValueLen;
	attr->hasValueForClone = B_TRUE;

	return (CKR_OK);
}


/*
 * find_attribute
 *
 * Passes a pointer to the requested attribute, or NULL if not found.
 */
static void
find_attribute(CK_ATTRIBUTE_TYPE attrtype, generic_attr_t *attributes,
	size_t num_attributes, generic_attr_t **found_attribute)
{
	generic_attr_t *attr;
	boolean_t found = B_FALSE;
	size_t i;

	/* Find the requested attribute. */
	for (i = 0, attr = attributes; i < num_attributes; i++, attr++) {
		if (attr->attribute.type == attrtype) {
			found = B_TRUE;
			break;
		}
	}

	*found_attribute = found ? attr : NULL;
}


/*
 * get_template_ulong
 *
 * Look for the specified ulong-size attribute, and retrieve its value. The
 * return value specifies if the attribute was found (or not).
 */
boolean_t
get_template_ulong(CK_ATTRIBUTE_TYPE type, CK_ATTRIBUTE *attributes,
	CK_ULONG num_attributes, CK_ULONG *result)
{
	boolean_t found = B_FALSE;
	CK_ULONG i;

	for (i = 0; i < num_attributes; i++) {
		if (attributes[i].type == type) {
			CK_ULONG *value = attributes[i].pValue;

			*result = *value;
			found = B_TRUE;
			break;
		}
	}

	return (found);
}


/*
 * get_template_boolean
 *
 * Look for the specified boolean attribute, and retrieve its value. The
 * return value specifies if the attribute was found (or not).
 */
boolean_t
get_template_boolean(CK_ATTRIBUTE_TYPE type, CK_ATTRIBUTE *attributes,
	CK_ULONG num_attributes, boolean_t *result)
{
	boolean_t found = B_FALSE;
	CK_ULONG i;

	for (i = 0; i < num_attributes; i++) {
		if (attributes[i].type == type) {
			CK_BBOOL *value = attributes[i].pValue;

			if (*value == CK_FALSE)
				*result = B_FALSE;
			else
				*result = B_TRUE;

			found = B_TRUE;
			break;
		}
	}

	return (found);
}

/*
 * set_template_boolean
 *
 * Look for the specified boolean attribute, and set its value.
 *
 * if 'local' is true, it sets the pointer to the value in the template a new
 * location.  There should be no memory leak created by this because we are
 * only doing this to booleans which should not be malloc'ed.
 *
 * if 'local' is false, it sets its value.
 *
 * The return value specifies if the attribute was found (or not).
 */
int
set_template_boolean(CK_ATTRIBUTE_TYPE type, CK_ATTRIBUTE *attributes,
	CK_ULONG num_attributes, boolean_t local, CK_BBOOL *value)
{
	int i;

	for (i = 0; i < num_attributes; i++) {
		if (attributes[i].type == type) {
			if (local)
				attributes[i].pValue = value;
			else
				*((CK_BBOOL *)attributes[i].pValue) = *value;

			return (i);
		}
	}

	return (-1);
}
