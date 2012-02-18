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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Milan Jurik. All rights reserved.
 */
#include <stdlib.h>
#include <string.h>
#include <security/cryptoki.h>
#include <sys/crypto/common.h>
#include <aes_impl.h>
#include "kmsGlobal.h"
#include "kmsObject.h"
#include "kmsSession.h"
#include "kmsSlot.h"

/*
 * This attribute table is used by the kms_lookup_attr()
 * to validate the attributes.
 */
CK_ATTRIBUTE_TYPE attr_map[] = {
	CKA_PRIVATE,
	CKA_LABEL,
	CKA_APPLICATION,
	CKA_OBJECT_ID,
	CKA_CERTIFICATE_TYPE,
	CKA_ISSUER,
	CKA_SERIAL_NUMBER,
	CKA_AC_ISSUER,
	CKA_OWNER,
	CKA_ATTR_TYPES,
	CKA_SUBJECT,
	CKA_ID,
	CKA_SENSITIVE,
	CKA_START_DATE,
	CKA_END_DATE,
	CKA_MODULUS,
	CKA_MODULUS_BITS,
	CKA_PUBLIC_EXPONENT,
	CKA_PRIVATE_EXPONENT,
	CKA_PRIME_1,
	CKA_PRIME_2,
	CKA_EXPONENT_1,
	CKA_EXPONENT_2,
	CKA_COEFFICIENT,
	CKA_PRIME,
	CKA_SUBPRIME,
	CKA_BASE,
	CKA_EXTRACTABLE,
	CKA_LOCAL,
	CKA_NEVER_EXTRACTABLE,
	CKA_ALWAYS_SENSITIVE,
	CKA_MODIFIABLE,
	CKA_ECDSA_PARAMS,
	CKA_EC_POINT,
	CKA_SECONDARY_AUTH,
	CKA_AUTH_PIN_FLAGS,
	CKA_HW_FEATURE_TYPE,
	CKA_RESET_ON_INIT,
	CKA_HAS_RESET
};

/*
 * attributes that exists only in secret key objects
 * Note: some attributes may also exist in one or two
 *       other object classes, but they are also listed
 *       because not all object have them.
 */
CK_ATTRIBUTE_TYPE SECRET_KEY_ATTRS[] =
{
	CKA_VALUE_LEN,
	CKA_ENCRYPT,
	CKA_DECRYPT,
	CKA_WRAP,
	CKA_UNWRAP,
	CKA_SIGN,
	CKA_VERIFY,
	CKA_SENSITIVE,
	CKA_EXTRACTABLE,
	CKA_NEVER_EXTRACTABLE,
	CKA_ALWAYS_SENSITIVE
};

/*
 * Validate the attribute by using binary search algorithm.
 */
CK_RV
kms_lookup_attr(CK_ATTRIBUTE_TYPE type)
{
	size_t lower, middle, upper;

	lower = 0;
	upper = (sizeof (attr_map) / sizeof (CK_ATTRIBUTE_TYPE)) - 1;

	while (lower <= upper) {
		/* Always starts from middle. */
		middle = (lower + upper) / 2;

		if (type > attr_map[middle]) {
			/* Adjust the lower bound to upper half. */
			lower = middle + 1;
			continue;
		}

		if (type == attr_map[middle]) {
			/* Found it. */
			return (CKR_OK);
		}

		if (type < attr_map[middle]) {
			/* Adjust the upper bound to lower half. */
			upper = middle - 1;
			continue;
		}
	}

	/* Failed to find the matching attribute from the attribute table. */
	return (CKR_ATTRIBUTE_TYPE_INVALID);
}


/*
 * Validate the attribute by using the following search algorithm:
 *
 * 1) Search for the most frequently used attributes first.
 * 2) If not found, search for the usage-purpose attributes - these
 *    attributes have dense set of values, therefore compiler will
 *    optimize it with a branch table and branch to the appropriate
 *    case.
 * 3) If still not found, use binary search for the rest of the
 *    attributes in the attr_map[] table.
 */
CK_RV
kms_validate_attr(CK_ATTRIBUTE_PTR template, CK_ULONG ulAttrNum,
	CK_OBJECT_CLASS *class)
{

	CK_ULONG i;
	CK_RV rv = CKR_OK;

	for (i = 0; i < ulAttrNum; i++) {
		/* First tier search */
		switch (template[i].type) {
		case CKA_CLASS:
			*class = *((CK_OBJECT_CLASS*)template[i].pValue);
			break;
		case CKA_TOKEN:
			break;
		case CKA_KEY_TYPE:
			break;
		case CKA_VALUE:
			break;
		case CKA_VALUE_LEN:
			break;
		case CKA_VALUE_BITS:
			break;
		default:
			/* Second tier search */
			switch (template[i].type) {
			case CKA_ENCRYPT:
				break;
			case CKA_DECRYPT:
				break;
			case CKA_WRAP:
				break;
			case CKA_UNWRAP:
				break;
			case CKA_SIGN:
				break;
			case CKA_SIGN_RECOVER:
				break;
			case CKA_VERIFY:
				break;
			case CKA_VERIFY_RECOVER:
				break;
			case CKA_DERIVE:
				break;
			default:
				/* Third tier search */
				rv = kms_lookup_attr(template[i].type);
				if (rv != CKR_OK)
					return (rv);
				break;
			}
			break;
		}
	}
	return (rv);
}


/*
 * Clean up and release all the storage in the extra attribute list
 * of an object.
 */
void
kms_cleanup_extra_attr(kms_object_t *object_p)
{

	CK_ATTRIBUTE_INFO_PTR extra_attr;
	CK_ATTRIBUTE_INFO_PTR tmp;

	if (object_p == NULL)
		return;

	extra_attr = object_p->extra_attrlistp;
	while (extra_attr) {
		tmp = extra_attr->next;
		if (extra_attr->attr.pValue)
			/*
			 * All extra attributes in the extra attribute
			 * list have pValue points to the value of the
			 * attribute (with simple byte array type).
			 * Free the storage for the value of the attribute.
			 */
			free(extra_attr->attr.pValue);

		/* Free the storage for the attribute_info struct. */
		free(extra_attr);
		extra_attr = tmp;
	}

	object_p->extra_attrlistp = NULL;
}

/*
 * Create the attribute_info struct to hold the object's attribute,
 * and add it to the extra attribute list of an object.
 */
CK_RV
kms_add_extra_attr(CK_ATTRIBUTE_PTR template, kms_object_t *object_p)
{

	CK_ATTRIBUTE_INFO_PTR attrp;

	/* Allocate the storage for the attribute_info struct. */
	attrp = calloc(1, sizeof (attribute_info_t));
	if (attrp == NULL) {
		return (CKR_HOST_MEMORY);
	}

	/* Set up attribute_info struct. */
	attrp->attr.type = template->type;
	attrp->attr.ulValueLen = template->ulValueLen;

	if ((template->pValue != NULL) &&
	    (template->ulValueLen > 0)) {
		/* Allocate storage for the value of the attribute. */
		attrp->attr.pValue = malloc(template->ulValueLen);
		if (attrp->attr.pValue == NULL) {
			free(attrp);
			return (CKR_HOST_MEMORY);
		}

		(void) memcpy(attrp->attr.pValue, template->pValue,
		    template->ulValueLen);
	} else {
		attrp->attr.pValue = NULL;
	}

	/* Insert the new attribute in front of extra attribute list. */
	if (object_p->extra_attrlistp == NULL) {
		object_p->extra_attrlistp = attrp;
		attrp->next = NULL;
	} else {
		attrp->next = object_p->extra_attrlistp;
		object_p->extra_attrlistp = attrp;
	}

	return (CKR_OK);
}

/*
 * Copy the attribute_info struct from the old object to a new attribute_info
 * struct, and add that new struct to the extra attribute list of the new
 * object.
 */
CK_RV
kms_copy_extra_attr(CK_ATTRIBUTE_INFO_PTR old_attrp,
    kms_object_t *object_p)
{
	CK_ATTRIBUTE_INFO_PTR attrp;

	/* Allocate attribute_info struct. */
	attrp = calloc(1, sizeof (attribute_info_t));
	if (attrp == NULL) {
		return (CKR_HOST_MEMORY);
	}

	attrp->attr.type = old_attrp->attr.type;
	attrp->attr.ulValueLen = old_attrp->attr.ulValueLen;

	if ((old_attrp->attr.pValue != NULL) &&
	    (old_attrp->attr.ulValueLen > 0)) {
		attrp->attr.pValue = malloc(old_attrp->attr.ulValueLen);
		if (attrp->attr.pValue == NULL) {
			free(attrp);
			return (CKR_HOST_MEMORY);
		}

		(void) memcpy(attrp->attr.pValue, old_attrp->attr.pValue,
		    old_attrp->attr.ulValueLen);
	} else {
		attrp->attr.pValue = NULL;
	}

	/* Insert the new attribute in front of extra attribute list */
	if (object_p->extra_attrlistp == NULL) {
		object_p->extra_attrlistp = attrp;
		attrp->next = NULL;
	} else {
		attrp->next = object_p->extra_attrlistp;
		object_p->extra_attrlistp = attrp;
	}

	return (CKR_OK);
}

/*
 * Get the attribute triple from the extra attribute list in the object
 * (if the specified attribute type is found), and copy it to a template.
 * Note the type of the attribute to be copied is specified by the template,
 * and the storage is pre-allocated for the atrribute value in the template
 * for doing the copy.
 */
CK_RV
get_extra_attr_from_object(kms_object_t *object_p, CK_ATTRIBUTE_PTR template)
{
	CK_ATTRIBUTE_INFO_PTR extra_attr;
	CK_ATTRIBUTE_TYPE type = template->type;

	extra_attr = object_p->extra_attrlistp;

	while (extra_attr) {
		if (type == extra_attr->attr.type) {
			/* Found it. */
			break;
		} else {
			/* Does not match, try next one. */
			extra_attr = extra_attr->next;
		}
	}

	if (extra_attr == NULL) {
		/* A valid but un-initialized attribute. */
		template->ulValueLen = 0;
		return (CKR_OK);
	}

	/*
	 * We found the attribute in the extra attribute list.
	 */
	if (template->pValue == NULL) {
		template->ulValueLen = extra_attr->attr.ulValueLen;
		return (CKR_OK);
	}

	if (template->ulValueLen >= extra_attr->attr.ulValueLen) {
		/*
		 * The buffer provided by the application is large
		 * enough to hold the value of the attribute.
		 */
		(void) memcpy(template->pValue, extra_attr->attr.pValue,
		    extra_attr->attr.ulValueLen);
		template->ulValueLen = extra_attr->attr.ulValueLen;
		return (CKR_OK);
	} else {
		/*
		 * The buffer provided by the application does
		 * not have enough space to hold the value.
		 */
		template->ulValueLen = (CK_ULONG)-1;
		return (CKR_BUFFER_TOO_SMALL);
	}
}

/*
 * Modify the attribute triple in the extra attribute list of the object
 * if the specified attribute type is found. Otherwise, just add it to
 * list.
 */
CK_RV
set_extra_attr_to_object(kms_object_t *object_p, CK_ATTRIBUTE_TYPE type,
	CK_ATTRIBUTE_PTR template)
{
	CK_ATTRIBUTE_INFO_PTR extra_attr;

	extra_attr = object_p->extra_attrlistp;

	while (extra_attr) {
		if (type == extra_attr->attr.type) {
			/* Found it. */
			break;
		} else {
			/* Does not match, try next one. */
			extra_attr = extra_attr->next;
		}
	}

	if (extra_attr == NULL) {
		/*
		 * This attribute is a new one, go ahead adding it to
		 * the extra attribute list.
		 */
		return (kms_add_extra_attr(template, object_p));
	}

	/* We found the attribute in the extra attribute list. */
	if ((template->pValue != NULL) &&
	    (template->ulValueLen > 0)) {
		if (template->ulValueLen > extra_attr->attr.ulValueLen) {
			/* The old buffer is too small to hold the new value. */
			if (extra_attr->attr.pValue != NULL)
				/* Free storage for the old attribute value. */
				free(extra_attr->attr.pValue);

			/* Allocate storage for the new attribute value. */
			extra_attr->attr.pValue = malloc(template->ulValueLen);
			if (extra_attr->attr.pValue == NULL) {
				return (CKR_HOST_MEMORY);
			}
		}

		/* Replace the attribute with new value. */
		extra_attr->attr.ulValueLen = template->ulValueLen;
		(void) memcpy(extra_attr->attr.pValue, template->pValue,
		    template->ulValueLen);
	} else {
		extra_attr->attr.pValue = NULL;
	}

	return (CKR_OK);
}

/*
 * Copy the boolean data type attribute value from an object for the
 * specified attribute to the template.
 */
CK_RV
get_bool_attr_from_object(kms_object_t *object_p, CK_ULONG bool_flag,
	CK_ATTRIBUTE_PTR template)
{

	if (template->pValue == NULL) {
		template->ulValueLen = sizeof (CK_BBOOL);
		return (CKR_OK);
	}

	if (template->ulValueLen >= sizeof (CK_BBOOL)) {
		/*
		 * The buffer provided by the application is large
		 * enough to hold the value of the attribute.
		 */
		if (object_p->bool_attr_mask & bool_flag) {
			*((CK_BBOOL *)template->pValue) = B_TRUE;
		} else {
			*((CK_BBOOL *)template->pValue) = B_FALSE;
		}

		template->ulValueLen = sizeof (CK_BBOOL);
		return (CKR_OK);
	} else {
		/*
		 * The buffer provided by the application does
		 * not have enough space to hold the value.
		 */
		template->ulValueLen = (CK_ULONG)-1;
		return (CKR_BUFFER_TOO_SMALL);
	}
}

/*
 * Set the boolean data type attribute value in the object.
 */
CK_RV
set_bool_attr_to_object(kms_object_t *object_p, CK_ULONG bool_flag,
	CK_ATTRIBUTE_PTR template)
{

	if (*(CK_BBOOL *)template->pValue)
		object_p->bool_attr_mask |= bool_flag;
	else
		object_p->bool_attr_mask &= ~bool_flag;

	return (CKR_OK);
}


/*
 * Copy the CK_ULONG data type attribute value from an object to the
 * template.
 */
CK_RV
get_ulong_attr_from_object(CK_ULONG value, CK_ATTRIBUTE_PTR template)
{

	if (template->pValue == NULL) {
		template->ulValueLen = sizeof (CK_ULONG);
		return (CKR_OK);
	}

	if (template->ulValueLen >= sizeof (CK_ULONG)) {
		/*
		 * The buffer provided by the application is large
		 * enough to hold the value of the attribute.
		 */
		*(CK_ULONG_PTR)template->pValue = value;
		template->ulValueLen = sizeof (CK_ULONG);
		return (CKR_OK);
	} else {
		/*
		 * The buffer provided by the application does
		 * not have enough space to hold the value.
		 */
		template->ulValueLen = (CK_ULONG)-1;
		return (CKR_BUFFER_TOO_SMALL);
	}
}

CK_RV
get_string_from_template(CK_ATTRIBUTE_PTR dest, CK_ATTRIBUTE_PTR src)
{
	if ((src->pValue != NULL) &&
	    (src->ulValueLen > 0)) {
		/* Allocate storage for the value of the attribute. */
		dest->pValue = malloc(src->ulValueLen);
		if (dest->pValue == NULL) {
			return (CKR_HOST_MEMORY);
		}

		(void) memcpy(dest->pValue, src->pValue,
		    src->ulValueLen);
		dest->ulValueLen = src->ulValueLen;
		dest->type = src->type;
	} else {
		dest->pValue = NULL;
		dest->ulValueLen = 0;
		dest->type = src->type;
	}

	return (CKR_OK);

}

void
string_attr_cleanup(CK_ATTRIBUTE_PTR template)
{

	if (template->pValue) {
		free(template->pValue);
		template->pValue = NULL;
		template->ulValueLen = 0;
	}
}

/*
 * Parse the common attributes. Return to caller with appropriate return
 * value to indicate if the supplied template specifies a valid attribute
 * with a valid value.
 */
static CK_RV
kms_parse_common_attrs(CK_ATTRIBUTE_PTR template, uint64_t *attr_mask_p)
{
	CK_RV rv = CKR_OK;
	kms_slot_t *pslot = get_slotinfo();

	switch (template->type) {
	case CKA_CLASS:
		break;
	case CKA_TOKEN:
		if ((*(CK_BBOOL *)template->pValue) == TRUE)
			*attr_mask_p |= TOKEN_BOOL_ON;
		break;

	case CKA_PRIVATE:
		if ((*(CK_BBOOL *)template->pValue) == TRUE) {
			/*
			 * Cannot create a private object if the token
			 * has a keystore and the user isn't logged in.
			 */
			if (pslot->sl_state != CKU_USER) {
				rv = CKR_ATTRIBUTE_VALUE_INVALID;
			} else {
				*attr_mask_p |= PRIVATE_BOOL_ON;
			}
		}
		break;

	case CKA_MODIFIABLE:
		if ((*(CK_BBOOL *)template->pValue) == FALSE) {
			*attr_mask_p &= ~MODIFIABLE_BOOL_ON;
		}
		break;

	case CKA_LABEL:
		break;

	default:
		rv = CKR_TEMPLATE_INCONSISTENT;
	}

	return (rv);
}

/*
 * Build a Secret Key Object.
 *
 * - Parse the object's template, and when an error is detected such as
 *   invalid attribute type, invalid attribute value, etc., return
 *   with appropriate return value.
 * - Set up attribute mask field in the object for the supplied common
 *   attributes that have boolean type.
 * - Build the attribute_info struct to hold the value of each supplied
 *   attribute that has byte array type. Link attribute_info structs
 *   together to form the extra attribute list of the object.
 * - Allocate storage for the Secret Key object.
 * - Build the Secret Key object. Allocate storage to hold the big integer
 *   value for the attribute CKA_VALUE that is required for all the key
 *   types supported by secret key object.
 *
 */
CK_RV
kms_build_secret_key_object(CK_ATTRIBUTE_PTR template,
    CK_ULONG ulAttrNum,	kms_object_t *new_object)
{
	int		i;
	CK_KEY_TYPE	keytype = (CK_KEY_TYPE)~0UL;
	uint64_t	attr_mask;
	CK_RV 		rv = CKR_OK;
	int		isLabel = 0;
	/* Must not set flags */
	int		isValueLen = 0;
	CK_ATTRIBUTE	string_tmp;
	secret_key_obj_t  *sck;

	string_tmp.pValue = NULL;

	/*
	 * If the object was pulled from the KMS, the
	 * attributes are encoded in the object record
	 * before this function is called, we don't
	 * want to overwrite them unless the attribute
	 * template says differently.
	 */
	if (new_object->bool_attr_mask != 0)
		attr_mask = new_object->bool_attr_mask;
	else
		attr_mask = SECRET_KEY_DEFAULT;

	/* Allocate storage for Secret Key Object. */
	sck = calloc(1, sizeof (secret_key_obj_t));
	if (sck == NULL) {
		rv = CKR_HOST_MEMORY;
		goto fail_cleanup;
	}

	new_object->object_class_u.secret_key = sck;
	new_object->class = CKO_SECRET_KEY;

	for (i = 0; i < ulAttrNum; i++) {

		/* Secret Key Object Attributes */
		switch (template[i].type) {

		/* common key attributes */
		case CKA_KEY_TYPE:
		keytype = *((CK_KEY_TYPE*)template[i].pValue);
			break;

		case CKA_ID:
		case CKA_START_DATE:
		case CKA_END_DATE:
			/*
			 * Allocate storage to hold the attribute
			 * value with byte array type, and add it to
			 * the extra attribute list of the object.
			 */
			rv = kms_add_extra_attr(&template[i],
			    new_object);
			if (rv != CKR_OK) {
				goto fail_cleanup;
			}
			break;

		/*
		 * The following key related attribute types must
		 * not be specified by C_CreateObject.
		 */
		case CKA_LOCAL:
		case CKA_KEY_GEN_MECHANISM:
		case CKA_ALWAYS_SENSITIVE:
		case CKA_NEVER_EXTRACTABLE:
			rv = CKR_TEMPLATE_INCONSISTENT;
			goto fail_cleanup;

		/* Key related boolean attributes */
		case CKA_DERIVE:
			if (*(CK_BBOOL *)template[i].pValue)
				attr_mask |= DERIVE_BOOL_ON;
			break;

		case CKA_SENSITIVE:
			if (*(CK_BBOOL *)template[i].pValue)
				attr_mask |= SENSITIVE_BOOL_ON;
			break;

		case CKA_ENCRYPT:
			if (*(CK_BBOOL *)template[i].pValue)
				attr_mask |= ENCRYPT_BOOL_ON;
			else
				attr_mask &= ~ENCRYPT_BOOL_ON;
			break;

		case CKA_DECRYPT:
			if (*(CK_BBOOL *)template[i].pValue)
				attr_mask |= DECRYPT_BOOL_ON;
			else
				attr_mask &= ~DECRYPT_BOOL_ON;
			break;

		case CKA_SIGN:
			if (*(CK_BBOOL *)template[i].pValue)
				attr_mask |= SIGN_BOOL_ON;
			else
				attr_mask &= ~SIGN_BOOL_ON;
			break;

		case CKA_VERIFY:
			if (*(CK_BBOOL *)template[i].pValue)
				attr_mask |= VERIFY_BOOL_ON;
			else
				attr_mask &= ~VERIFY_BOOL_ON;
			break;

		case CKA_WRAP:
			if (*(CK_BBOOL *)template[i].pValue)
				attr_mask |= WRAP_BOOL_ON;
			break;

		case CKA_UNWRAP:
			if (*(CK_BBOOL *)template[i].pValue)
				attr_mask |= UNWRAP_BOOL_ON;
			break;

		case CKA_EXTRACTABLE:
			if (*(CK_BBOOL *)template[i].pValue)
				attr_mask |= EXTRACTABLE_BOOL_ON;
			else
				attr_mask &= ~EXTRACTABLE_BOOL_ON;
			break;

		case CKA_VALUE:
			if ((template[i].ulValueLen == 0) ||
			    (template[i].pValue == NULL)) {
				rv = CKR_ATTRIBUTE_VALUE_INVALID;
				goto fail_cleanup;
			}
			/*
			 * Copyin attribute from template
			 * to a local variable.
			 */
			sck->sk_value = malloc(template[i].ulValueLen);
			if (sck->sk_value == NULL) {
				rv = CKR_HOST_MEMORY;
				goto fail_cleanup;
			}
			(void) memcpy(sck->sk_value, template[i].pValue,
			    template[i].ulValueLen);
			sck->sk_value_len = template[i].ulValueLen;
			break;

		case CKA_VALUE_LEN:
			isValueLen = 1;
			if (template[i].pValue != NULL)
				sck->sk_value_len =
				    *(CK_ULONG_PTR)template[i].pValue;
			else
				sck->sk_value_len = 0;
			break;

		case CKA_LABEL:
			isLabel = 1;
			rv = get_string_from_template(&string_tmp,
			    &template[i]);
			if (rv != CKR_OK)
				goto fail_cleanup;
			break;

		default:
			rv = kms_parse_common_attrs(&template[i], &attr_mask);
			if (rv != CKR_OK)
				goto fail_cleanup;
			break;

		}
	} /* For */

	if (keytype == (CK_KEY_TYPE)~0UL) {
		rv = CKR_TEMPLATE_INCOMPLETE;
		goto fail_cleanup;
	}

	new_object->key_type = keytype;

	/* Supported key types of the Secret Key Object */
	switch (keytype) {

	case CKK_AES:
		if (!isValueLen) {
			rv = CKR_TEMPLATE_INCOMPLETE;
			goto fail_cleanup;
		}
		if (sck->sk_value_len != AES_MIN_KEY_BYTES &&
		    sck->sk_value_len != AES_192_KEY_BYTES &&
		    sck->sk_value_len != AES_MAX_KEY_BYTES) {
			rv = CKR_ATTRIBUTE_VALUE_INVALID;
			goto fail_cleanup;
		}
		break;

	case CKK_RC4:
	case CKK_GENERIC_SECRET:
	case CKK_BLOWFISH:
	case CKK_DES:
	case CKK_DES2:
	case CKK_DES3:
	default:
		rv = CKR_TEMPLATE_INCONSISTENT;
		goto fail_cleanup;
	}

	/* Set up object. */
	new_object->bool_attr_mask = attr_mask;
	if (isLabel) {
		rv = kms_add_extra_attr(&string_tmp, new_object);
		if (rv != CKR_OK)
			goto fail_cleanup;
		string_attr_cleanup(&string_tmp);
	}

	return (rv);

fail_cleanup:
	/*
	 * cleanup the storage allocated to the local variables.
	 */
	string_attr_cleanup(&string_tmp);

	/*
	 * cleanup the storage allocated inside the object itself.
	 */
	kms_cleanup_object(new_object);

	return (rv);
}

/*
 * Validate the attribute types in the object's template. Then,
 * call the appropriate build function according to the class of
 * the object specified in the template.
 *
 * Note: The following classes of objects are supported:
 * - CKO_SECRET_KEY
 */
CK_RV
kms_build_object(CK_ATTRIBUTE_PTR template, CK_ULONG ulAttrNum,
    kms_object_t *new_object)
{
	CK_OBJECT_CLASS class = (CK_OBJECT_CLASS)~0UL;
	CK_RV 		rv = CKR_OK;

	if (template == NULL) {
		return (CKR_ARGUMENTS_BAD);
	}

	/* Validate the attribute type in the template. */
	rv = kms_validate_attr(template, ulAttrNum, &class);
	if (rv != CKR_OK)
		return (rv);

	if (class == (CK_OBJECT_CLASS)~0UL)
		return (CKR_TEMPLATE_INCOMPLETE);

	/*
	 * Call the appropriate function based on the supported class
	 * of the object.
	 */
	switch (class) {

	case CKO_SECRET_KEY:
		rv = kms_build_secret_key_object(template, ulAttrNum,
		    new_object);
		break;

	case CKO_DOMAIN_PARAMETERS:
	case CKO_DATA:
	case CKO_CERTIFICATE:
	case CKO_HW_FEATURE:
	case CKO_VENDOR_DEFINED:
	case CKO_PUBLIC_KEY:
	case CKO_PRIVATE_KEY:
	default:
		return (CKR_ATTRIBUTE_VALUE_INVALID);
	}

	return (rv);
}


/*
 * Get the value of a requested attribute that is common to all supported
 * classes (i.e. public key, private key, secret key classes).
 */
CK_RV
kms_get_common_attrs(kms_object_t *object_p, CK_ATTRIBUTE_PTR template)
{

	CK_RV rv = CKR_OK;

	switch (template->type) {

	case CKA_CLASS:
		return (get_ulong_attr_from_object(object_p->class,
		    template));

	/* default boolean attributes */
	case CKA_TOKEN:
		template->ulValueLen = sizeof (CK_BBOOL);
		if (template->pValue == NULL) {
			return (CKR_OK);
		}

		*((CK_BBOOL *)template->pValue) = B_FALSE;
		break;

	case CKA_PRIVATE:

		template->ulValueLen = sizeof (CK_BBOOL);
		if (template->pValue == NULL) {
			return (CKR_OK);
		}
		if (object_p->bool_attr_mask & PRIVATE_BOOL_ON) {
			*((CK_BBOOL *)template->pValue) = B_TRUE;
		} else {
			*((CK_BBOOL *)template->pValue) = B_FALSE;
		}
		break;

	case CKA_MODIFIABLE:
		template->ulValueLen = sizeof (CK_BBOOL);
		if (template->pValue == NULL) {
			return (CKR_OK);
		}
		if ((object_p->bool_attr_mask) & MODIFIABLE_BOOL_ON)
			*((CK_BBOOL *)template->pValue) = B_TRUE;
		else
			*((CK_BBOOL *)template->pValue) = B_FALSE;
		break;

	case CKA_LABEL:
		return (get_extra_attr_from_object(object_p,
		    template));

	default:
		/*
		 * The specified attribute for the object is invalid.
		 * (the object does not possess such an attribute.)
		 */
		template->ulValueLen = (CK_ULONG)-1;
		return (CKR_ATTRIBUTE_TYPE_INVALID);
	}

	return (rv);
}

/*
 * Get the value of a requested attribute that is common to all key objects
 * (i.e. public key, private key and secret key).
 */
CK_RV
kms_get_common_key_attrs(kms_object_t *object_p,
    CK_ATTRIBUTE_PTR template)
{

	switch (template->type) {

	case CKA_KEY_TYPE:
		return (get_ulong_attr_from_object(object_p->key_type,
		    template));

	case CKA_ID:
	case CKA_START_DATE:
	case CKA_END_DATE:
		/*
		 * The above extra attributes have byte array type.
		 */
		return (get_extra_attr_from_object(object_p,
		    template));

	/* Key related boolean attributes */
	case CKA_LOCAL:
		return (get_bool_attr_from_object(object_p,
		    LOCAL_BOOL_ON, template));

	case CKA_DERIVE:
		return (get_bool_attr_from_object(object_p,
		    DERIVE_BOOL_ON, template));

	case CKA_KEY_GEN_MECHANISM:
		return (get_ulong_attr_from_object(object_p->mechanism,
		    template));

	default:
		return (CKR_ATTRIBUTE_TYPE_INVALID);
	}
}

/*
 * Get the value of a requested attribute of a Secret Key Object.
 *
 * Rule: All the attributes in the secret key object can be revealed
 *       except those marked with footnote number "7" when the object
 *       has its CKA_SENSITIVE attribute set to TRUE or its
 *       CKA_EXTRACTABLE attribute set to FALSE.
 */
CK_RV
kms_get_secret_key_attribute(kms_object_t *object_p,
    CK_ATTRIBUTE_PTR template)
{

	CK_RV		rv = CKR_OK;
	CK_KEY_TYPE	keytype = object_p->key_type;

	switch (template->type) {

	/* Key related boolean attributes */
	case CKA_SENSITIVE:
		return (get_bool_attr_from_object(object_p,
		    SENSITIVE_BOOL_ON, template));

	case CKA_ENCRYPT:
		return (get_bool_attr_from_object(object_p,
		    ENCRYPT_BOOL_ON, template));

	case CKA_DECRYPT:
		return (get_bool_attr_from_object(object_p,
		    DECRYPT_BOOL_ON, template));

	case CKA_SIGN:
		return (get_bool_attr_from_object(object_p,
		    SIGN_BOOL_ON, template));

	case CKA_VERIFY:
		return (get_bool_attr_from_object(object_p,
		    VERIFY_BOOL_ON, template));

	case CKA_WRAP:
		return (get_bool_attr_from_object(object_p,
		    WRAP_BOOL_ON, template));

	case CKA_UNWRAP:
		return (get_bool_attr_from_object(object_p,
		    UNWRAP_BOOL_ON, template));

	case CKA_EXTRACTABLE:
		return (get_bool_attr_from_object(object_p,
		    EXTRACTABLE_BOOL_ON, template));

	case CKA_ALWAYS_SENSITIVE:
		return (get_bool_attr_from_object(object_p,
		    ALWAYS_SENSITIVE_BOOL_ON, template));

	case CKA_NEVER_EXTRACTABLE:
		return (get_bool_attr_from_object(object_p,
		    NEVER_EXTRACTABLE_BOOL_ON, template));

	case CKA_VALUE:
		/*
		 * If the specified attribute for the secret key object
		 * cannot be revealed because the object is sensitive
		 * or unextractable, then the ulValueLen is set to -1.
		 */
		if ((object_p->bool_attr_mask & SENSITIVE_BOOL_ON) ||
		    !(object_p->bool_attr_mask & EXTRACTABLE_BOOL_ON)) {
			template->ulValueLen = (CK_ULONG)-1;
			return (CKR_ATTRIBUTE_SENSITIVE);
		}

		switch (keytype) {
		case CKK_AES:
			/*
			 * Copy secret key object attributes to template.
			 */
			if (template->pValue == NULL) {
				template->ulValueLen =
				    OBJ_SEC_VALUE_LEN(object_p);
				return (CKR_OK);
			}

			if (OBJ_SEC_VALUE(object_p) == NULL) {
				template->ulValueLen = 0;
				return (CKR_OK);
			}

			if (template->ulValueLen >=
			    OBJ_SEC_VALUE_LEN(object_p)) {
				(void) memcpy(template->pValue,
				    OBJ_SEC_VALUE(object_p),
				    OBJ_SEC_VALUE_LEN(object_p));
				template->ulValueLen =
				    OBJ_SEC_VALUE_LEN(object_p);
				return (CKR_OK);
			} else {
				template->ulValueLen = (CK_ULONG)-1;
				return (CKR_BUFFER_TOO_SMALL);
			}

		case CKK_RC4:
		case CKK_GENERIC_SECRET:
		case CKK_RC5:
		case CKK_DES:
		case CKK_DES2:
		case CKK_DES3:
		case CKK_CDMF:
		case CKK_BLOWFISH:
		default:
			template->ulValueLen = (CK_ULONG)-1;
			rv = CKR_ATTRIBUTE_TYPE_INVALID;
			break;
		}
		break;

	case CKA_VALUE_LEN:
		return (get_ulong_attr_from_object(OBJ_SEC_VALUE_LEN(object_p),
		    template));

	default:
		/*
		 * First, get the value of the request attribute defined
		 * in the list of common key attributes. If the request
		 * attribute is not found in that list, then get the
		 * attribute from the list of common attributes.
		 */
		rv = kms_get_common_key_attrs(object_p, template);
		if (rv == CKR_ATTRIBUTE_TYPE_INVALID) {
			rv = kms_get_common_attrs(object_p, template);
		}
		break;
	}

	return (rv);

}

/*
 * Call the appropriate get attribute function according to the class
 * of object.
 *
 * The caller of this function holds the lock on the object.
 */
CK_RV
kms_get_attribute(kms_object_t *object_p, CK_ATTRIBUTE_PTR template)
{

	CK_RV		rv = CKR_OK;
	CK_OBJECT_CLASS class = object_p->class;

	switch (class) {
	case CKO_SECRET_KEY:
		rv = kms_get_secret_key_attribute(object_p, template);
		break;

	case CKO_PRIVATE_KEY:
	case CKO_PUBLIC_KEY:
	default:
		/*
		 * If the specified attribute for the object is invalid
		 * (the object does not possess such as attribute), then
		 * the ulValueLen is modified to hold the value -1.
		 */
		template->ulValueLen = (CK_ULONG)-1;
		return (CKR_ATTRIBUTE_TYPE_INVALID);
	}

	return (rv);

}

/*
 * Set the value of an attribute that is common to all key objects
 * (i.e. public key, private key and secret key).
 */
static CK_RV
kms_set_common_key_attribute(kms_object_t *object_p,
    CK_ATTRIBUTE_PTR template, boolean_t copy)
{

	kms_slot_t *pslot = get_slotinfo();
	CK_RV rv = CKR_OK;

	switch (template->type) {

	case CKA_LABEL:
		/*
		 * Only the LABEL can be modified in the common storage
		 * object attributes after the object is created.
		 */
		return (set_extra_attr_to_object(object_p,
		    CKA_LABEL, template));

	case CKA_ID:
		return (set_extra_attr_to_object(object_p,
		    CKA_ID, template));

	case CKA_START_DATE:
		return (set_extra_attr_to_object(object_p,
		    CKA_START_DATE, template));

	case CKA_END_DATE:
		return (set_extra_attr_to_object(object_p,
		    CKA_END_DATE, template));

	case CKA_DERIVE:
		return (set_bool_attr_to_object(object_p,
		    DERIVE_BOOL_ON, template));

	case CKA_CLASS:
	case CKA_KEY_TYPE:
	case CKA_LOCAL:
		return (CKR_ATTRIBUTE_READ_ONLY);

	case CKA_PRIVATE:
		if (!copy) {
			/* called from C_SetAttributeValue() */
			return (CKR_ATTRIBUTE_READ_ONLY);
		}

		/* called from C_CopyObject() */
		if ((*(CK_BBOOL *)template->pValue) != B_TRUE) {
			return (CKR_OK);
		}

		(void) pthread_mutex_lock(&pslot->sl_mutex);
		/*
		 * Cannot create a private object if the token
		 * has a keystore and the user isn't logged in.
		 */
		if (pslot->sl_state != CKU_USER) {
			rv = CKR_USER_NOT_LOGGED_IN;
		} else {
			rv = set_bool_attr_to_object(object_p,
			    PRIVATE_BOOL_ON, template);
		}
		(void) pthread_mutex_unlock(&pslot->sl_mutex);
		return (rv);

	case CKA_MODIFIABLE:
		if (copy) {
			rv = set_bool_attr_to_object(object_p,
			    MODIFIABLE_BOOL_ON, template);
		} else {
			rv = CKR_ATTRIBUTE_READ_ONLY;
		}
		return (rv);

	default:
		return (CKR_TEMPLATE_INCONSISTENT);
	}

}

/*
 * Set the value of an attribute of a Secret Key Object.
 *
 * Rule: The attributes marked with footnote number "8" in the PKCS11
 *       spec may be modified (p.88 in PKCS11 spec.).
 */
static CK_RV
kms_set_secret_key_attribute(kms_object_t *object_p,
    CK_ATTRIBUTE_PTR template, boolean_t copy)
{
	CK_KEY_TYPE	keytype = object_p->key_type;

	switch (template->type) {

	case CKA_SENSITIVE:
		/*
		 * Cannot set SENSITIVE to FALSE if it is already ON.
		 */
		if (((*(CK_BBOOL *)template->pValue) == B_FALSE) &&
		    (object_p->bool_attr_mask & SENSITIVE_BOOL_ON)) {
			return (CKR_ATTRIBUTE_READ_ONLY);
		}

		if (*(CK_BBOOL *)template->pValue)
			object_p->bool_attr_mask |= SENSITIVE_BOOL_ON;
		return (CKR_OK);

	case CKA_ENCRYPT:
		return (set_bool_attr_to_object(object_p,
		    ENCRYPT_BOOL_ON, template));

	case CKA_DECRYPT:
		return (set_bool_attr_to_object(object_p,
		    DECRYPT_BOOL_ON, template));

	case CKA_SIGN:
		return (set_bool_attr_to_object(object_p,
		    SIGN_BOOL_ON, template));

	case CKA_VERIFY:
		return (set_bool_attr_to_object(object_p,
		    VERIFY_BOOL_ON, template));

	case CKA_WRAP:
		return (set_bool_attr_to_object(object_p,
		    WRAP_BOOL_ON, template));

	case CKA_UNWRAP:
		return (set_bool_attr_to_object(object_p,
		    UNWRAP_BOOL_ON, template));

	case CKA_EXTRACTABLE:
		/*
		 * Cannot set EXTRACTABLE to TRUE if it is already OFF.
		 */
		if ((*(CK_BBOOL *)template->pValue) &&
		    !(object_p->bool_attr_mask & EXTRACTABLE_BOOL_ON)) {
			return (CKR_ATTRIBUTE_READ_ONLY);
		}

		if ((*(CK_BBOOL *)template->pValue) == B_FALSE)
			object_p->bool_attr_mask &= ~EXTRACTABLE_BOOL_ON;
		return (CKR_OK);

	case CKA_VALUE:
		return (CKR_ATTRIBUTE_READ_ONLY);

	case CKA_VALUE_LEN:
		if ((keytype == CKK_RC4) ||
		    (keytype == CKK_GENERIC_SECRET) ||
		    (keytype == CKK_AES) ||
		    (keytype == CKK_BLOWFISH))
			return (CKR_ATTRIBUTE_READ_ONLY);
		break;

	default:
		/*
		 * Set the value of a common key attribute.
		 */
		return (kms_set_common_key_attribute(object_p,
		    template, copy));
	}

	/*
	 * If we got this far, then the combination of key type
	 * and requested attribute is invalid.
	 */
	return (CKR_ATTRIBUTE_TYPE_INVALID);
}

/*
 * Call the appropriate set attribute function according to the class
 * of object.
 *
 * The caller of this function does not hold the lock on the original
 * object, since this function is setting the attribute on the new object
 * that is being modified.
 *
 */
CK_RV
kms_set_attribute(kms_object_t *object_p, CK_ATTRIBUTE_PTR template,
    boolean_t copy)
{

	CK_RV		rv = CKR_OK;
	CK_OBJECT_CLASS	class = object_p->class;

	switch (class) {

	case CKO_SECRET_KEY:
		rv = kms_set_secret_key_attribute(object_p, template,
		    copy);
		break;

	case CKO_PUBLIC_KEY:
	case CKO_PRIVATE_KEY:
	default:
		/*
		 * If the template specifies a value of an attribute
		 * which is incompatible with other existing attributes
		 * of the object, then fails with return code
		 * CKR_TEMPLATE_INCONSISTENT.
		 */
		rv = CKR_TEMPLATE_INCONSISTENT;
		break;
	}

	return (rv);
}

CK_RV
kms_copy_secret_key_attr(secret_key_obj_t *old_secret_key_obj_p,
    secret_key_obj_t **new_secret_key_obj_p)
{
	secret_key_obj_t *sk;

	sk = malloc(sizeof (secret_key_obj_t));
	if (sk == NULL) {
		return (CKR_HOST_MEMORY);
	}
	(void) memcpy(sk, old_secret_key_obj_p, sizeof (secret_key_obj_t));

	/* copy the secret key value */
	sk->sk_value = malloc((sizeof (CK_BYTE) * sk->sk_value_len));
	if (sk->sk_value == NULL) {
		free(sk);
		return (CKR_HOST_MEMORY);
	}
	(void) memcpy(sk->sk_value, old_secret_key_obj_p->sk_value,
	    (sizeof (CK_BYTE) * sk->sk_value_len));

	*new_secret_key_obj_p = sk;

	return (CKR_OK);
}



/*
 * If CKA_CLASS not given, guess CKA_CLASS using
 * attributes on template.
 *
 * Some attributes are specific to an object class.  If one or more
 * of these attributes are in the template, make a list of classes
 * that can have these attributes.  This would speed up the search later,
 * because we can immediately skip an object if the class of that
 * object can not possibly contain one of the attributes.
 *
 */
void
kms_process_find_attr(CK_OBJECT_CLASS *pclasses,
    CK_ULONG *num_result_pclasses, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount)
{
	ulong_t i;
	int j;
	boolean_t secret_found = B_FALSE;
	int num_secret_key_attrs;
	int num_pclasses = 0;

	for (i = 0; i < ulCount; i++) {
		if (pTemplate[i].type == CKA_CLASS) {
			/*
			 * don't need to guess the class, it is specified.
			 * Just record the class, and return.
			 */
			pclasses[0] =
			    (*((CK_OBJECT_CLASS *)pTemplate[i].pValue));
			*num_result_pclasses = 1;
			return;
		}
	}

	num_secret_key_attrs =
	    sizeof (SECRET_KEY_ATTRS) / sizeof (CK_ATTRIBUTE_TYPE);

	/*
	 * Get the list of objects class that might contain
	 * some attributes.
	 */
	for (i = 0; i < ulCount; i++) {
		if (!secret_found) {
			for (j = 0; j < num_secret_key_attrs; j++) {
				if (pTemplate[i].type == SECRET_KEY_ATTRS[j]) {
					secret_found = B_TRUE;
					pclasses[num_pclasses++] =
					    CKO_SECRET_KEY;
					break;
				}
			}
		}
	}
	*num_result_pclasses = num_pclasses;
}


boolean_t
kms_find_match_attrs(kms_object_t *obj, CK_OBJECT_CLASS *pclasses,
    CK_ULONG num_pclasses, CK_ATTRIBUTE *template, CK_ULONG num_attr)
{
	ulong_t i;
	CK_ATTRIBUTE *tmpl_attr, *obj_attr;
	uint64_t attr_mask;
	boolean_t compare_attr, compare_boolean;

	/*
	 * Check if the class of this object match with any
	 * of object classes that can possibly contain the
	 * requested attributes.
	 */
	if (num_pclasses > 0) {
		for (i = 0; i < num_pclasses; i++) {
			if (obj->class == pclasses[i]) {
				break;
			}
		}
		if (i == num_pclasses) {
			/*
			 * this object can't possibly contain one or
			 * more attributes, don't need to check this object
			 */
			return (B_FALSE);
		}
	}

	/* need to examine everything */
	for (i = 0; i < num_attr; i++) {
		tmpl_attr = &(template[i]);
		compare_attr = B_FALSE;
		compare_boolean = B_FALSE;
		switch (tmpl_attr->type) {
		/* First, check the most common attributes */
		case CKA_CLASS:
			if (*((CK_OBJECT_CLASS *)tmpl_attr->pValue) !=
			    obj->class) {
				return (B_FALSE);
			}
			break;
		case CKA_KEY_TYPE:
			if (*((CK_KEY_TYPE *)tmpl_attr->pValue) !=
			    obj->key_type) {
				return (B_FALSE);
			}
			break;
		case CKA_ENCRYPT:
			attr_mask = (obj->bool_attr_mask) & ENCRYPT_BOOL_ON;
			compare_boolean = B_TRUE;
			break;
		case CKA_DECRYPT:
			attr_mask = (obj->bool_attr_mask) & DECRYPT_BOOL_ON;
			compare_boolean = B_TRUE;
			break;
		case CKA_WRAP:
			attr_mask = (obj->bool_attr_mask) & WRAP_BOOL_ON;
			compare_boolean = B_TRUE;
			break;
		case CKA_UNWRAP:
			attr_mask = (obj->bool_attr_mask) & UNWRAP_BOOL_ON;
			compare_boolean = B_TRUE;
			break;
		case CKA_SIGN:
			attr_mask = (obj->bool_attr_mask) & SIGN_BOOL_ON;
			compare_boolean = B_TRUE;
			break;
		case CKA_SIGN_RECOVER:
			attr_mask = (obj->bool_attr_mask) &
			    SIGN_RECOVER_BOOL_ON;
			compare_boolean = B_TRUE;
			break;
		case CKA_VERIFY:
			attr_mask = (obj->bool_attr_mask) & VERIFY_BOOL_ON;
			compare_boolean = B_TRUE;
			break;
		case CKA_VERIFY_RECOVER:
			attr_mask = (obj->bool_attr_mask) &
			    VERIFY_RECOVER_BOOL_ON;
			compare_boolean = B_TRUE;
			break;
		case CKA_DERIVE:
			attr_mask = (obj->bool_attr_mask) & DERIVE_BOOL_ON;
			compare_boolean = B_TRUE;
			break;
		case CKA_LOCAL:
			attr_mask = (obj->bool_attr_mask) & LOCAL_BOOL_ON;
			compare_boolean = B_TRUE;
			break;
		case CKA_SENSITIVE:
			attr_mask = (obj->bool_attr_mask) & SENSITIVE_BOOL_ON;
			compare_boolean = B_TRUE;
			break;
		case CKA_SECONDARY_AUTH:
			attr_mask = (obj->bool_attr_mask) &
			    SECONDARY_AUTH_BOOL_ON;
			compare_boolean = B_TRUE;
			break;
		case CKA_TRUSTED:
			attr_mask = (obj->bool_attr_mask) & TRUSTED_BOOL_ON;
			compare_boolean = B_TRUE;
			break;
		case CKA_EXTRACTABLE:
			attr_mask = (obj->bool_attr_mask) &
			    EXTRACTABLE_BOOL_ON;
			compare_boolean = B_TRUE;
			break;
		case CKA_ALWAYS_SENSITIVE:
			attr_mask = (obj->bool_attr_mask) &
			    ALWAYS_SENSITIVE_BOOL_ON;
			compare_boolean = B_TRUE;
			break;
		case CKA_NEVER_EXTRACTABLE:
			attr_mask = (obj->bool_attr_mask) &
			    NEVER_EXTRACTABLE_BOOL_ON;
			compare_boolean = B_TRUE;
			break;
		case CKA_TOKEN:
			attr_mask = (obj->bool_attr_mask) & TOKEN_BOOL_ON;
			compare_boolean = B_TRUE;
			break;
		case CKA_PRIVATE:
			attr_mask = (obj->bool_attr_mask) & PRIVATE_BOOL_ON;
			compare_boolean = B_TRUE;
			break;
		case CKA_MODIFIABLE:
			attr_mask = (obj->bool_attr_mask) & MODIFIABLE_BOOL_ON;
			compare_boolean = B_TRUE;
			break;
		case CKA_SUBJECT:
		case CKA_ID:
		case CKA_START_DATE:
		case CKA_END_DATE:
		case CKA_KEY_GEN_MECHANISM:
		case CKA_LABEL:
			/* find these attributes from extra_attrlistp */
			obj_attr = get_extra_attr(tmpl_attr->type, obj);
			compare_attr = B_TRUE;
			break;
		case CKA_VALUE_LEN:
			/* only secret key has this attribute */
			if (obj->class == CKO_SECRET_KEY) {
				if (*((CK_ULONG *)tmpl_attr->pValue) !=
				    OBJ_SEC_VALUE_LEN(obj)) {
					return (B_FALSE);
				}
			} else {
				return (B_FALSE);
			}
			break;
		case CKA_VALUE:
			switch (obj->class) {
			case CKO_SECRET_KEY:
				break;
			default:
				return (B_FALSE);
			}
			break;
		case CKA_VALUE_BITS:
		case CKA_PRIME_BITS:
		case CKA_SUBPRIME_BITS:
		default:
			/*
			 * any other attributes are currently not supported.
			 * so, it's not possible for them to be in the
			 * object
			 */
			return (B_FALSE);
		}
		if (compare_boolean) {
			CK_BBOOL bval;

			if (attr_mask) {
				bval = TRUE;
			} else {
				bval = FALSE;
			}
			if (bval != *((CK_BBOOL *)tmpl_attr->pValue)) {
				return (B_FALSE);
			}
		} else if (compare_attr) {
			if (obj_attr == NULL) {
				/*
				 * The attribute type is valid, and its value
				 * has not been initialized in the object. In
				 * this case, it only matches the template's
				 * attribute if the template's value length
				 * is 0.
				 */
				if (tmpl_attr->ulValueLen != 0)
					return (B_FALSE);
			} else {
				if (tmpl_attr->ulValueLen !=
				    obj_attr->ulValueLen) {
					return (B_FALSE);
				}
				if (memcmp(tmpl_attr->pValue, obj_attr->pValue,
				    tmpl_attr->ulValueLen) != 0) {
					return (B_FALSE);
				}
			}
		}
	}
	return (B_TRUE);
}

CK_ATTRIBUTE_PTR
get_extra_attr(CK_ATTRIBUTE_TYPE type, kms_object_t *obj)
{
	CK_ATTRIBUTE_INFO_PTR tmp;

	tmp = obj->extra_attrlistp;
	while (tmp != NULL) {
		if (tmp->attr.type == type) {
			return (&(tmp->attr));
		}
		tmp = tmp->next;
	}
	/* if get there, the specified attribute is not found */
	return (NULL);
}
