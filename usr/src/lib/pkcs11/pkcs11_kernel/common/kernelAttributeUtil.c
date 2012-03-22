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
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

#include <stdlib.h>
#include <string.h>
#include <security/cryptoki.h>
#include <sys/crypto/common.h>
#include <aes_impl.h>
#include <blowfish_impl.h>
#include <arcfour.h>
#include <des_impl.h>
#include "kernelGlobal.h"
#include "kernelObject.h"
#include "kernelSession.h"
#include "kernelSlot.h"


/*
 * This attribute table is used by the kernel_lookup_attr()
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
 * attributes that exists only in public key objects
 * Note: some attributes may also exist in one or two
 *       other object classes, but they are also listed
 *       because not all object have them.
 */
CK_ATTRIBUTE_TYPE PUB_KEY_ATTRS[] =
{
	CKA_SUBJECT,
	CKA_ENCRYPT,
	CKA_WRAP,
	CKA_VERIFY,
	CKA_VERIFY_RECOVER,
	CKA_MODULUS,
	CKA_MODULUS_BITS,
	CKA_PUBLIC_EXPONENT,
	CKA_PRIME,
	CKA_SUBPRIME,
	CKA_BASE,
	CKA_TRUSTED,
	CKA_ECDSA_PARAMS,
	CKA_EC_PARAMS,
	CKA_EC_POINT
};

/*
 * attributes that exists only in private key objects
 * Note: some attributes may also exist in one or two
 *       other object classes, but they are also listed
 *       because not all object have them.
 */
CK_ATTRIBUTE_TYPE PRIV_KEY_ATTRS[] =
{
	CKA_DECRYPT,
	CKA_UNWRAP,
	CKA_SIGN,
	CKA_SIGN_RECOVER,
	CKA_MODULUS,
	CKA_PUBLIC_EXPONENT,
	CKA_PRIVATE_EXPONENT,
	CKA_PRIME,
	CKA_SUBPRIME,
	CKA_BASE,
	CKA_PRIME_1,
	CKA_PRIME_2,
	CKA_EXPONENT_1,
	CKA_EXPONENT_2,
	CKA_COEFFICIENT,
	CKA_VALUE_BITS,
	CKA_SUBJECT,
	CKA_SENSITIVE,
	CKA_EXTRACTABLE,
	CKA_NEVER_EXTRACTABLE,
	CKA_ALWAYS_SENSITIVE,
	CKA_ECDSA_PARAMS,
	CKA_EC_PARAMS
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
 * attributes that exists only in domain parameter objects
 * Note: some attributes may also exist in one or two
 *       other object classes, but they are also listed
 *       because not all object have them.
 */
CK_ATTRIBUTE_TYPE DOMAIN_ATTRS[] =
{
	CKA_PRIME,
	CKA_SUBPRIME,
	CKA_BASE,
	CKA_PRIME_BITS,
	CKA_SUBPRIME_BITS,
	CKA_SUB_PRIME_BITS
};

/*
 * attributes that exists only in hardware feature objects
 */
CK_ATTRIBUTE_TYPE HARDWARE_ATTRS[] =
{
	CKA_HW_FEATURE_TYPE,
	CKA_RESET_ON_INIT,
	CKA_HAS_RESET
};

/*
 * attributes that exists only in certificate objects
 */
CK_ATTRIBUTE_TYPE CERT_ATTRS[] =
{
	CKA_CERTIFICATE_TYPE,
	CKA_SUBJECT,
	CKA_ID,
	CKA_ISSUER,
	CKA_AC_ISSUER,
	CKA_SERIAL_NUMBER,
	CKA_OWNER,
	CKA_ATTR_TYPES
};


/*
 * Validate the attribute by using binary search algorithm.
 */
CK_RV
kernel_lookup_attr(CK_ATTRIBUTE_TYPE type)
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
kernel_validate_attr(CK_ATTRIBUTE_PTR template, CK_ULONG ulAttrNum,
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
				rv = kernel_lookup_attr(template[i].type);
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
kernel_cleanup_extra_attr(kernel_object_t *object_p)
{

	CK_ATTRIBUTE_INFO_PTR extra_attr;
	CK_ATTRIBUTE_INFO_PTR tmp;

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
kernel_add_extra_attr(CK_ATTRIBUTE_PTR template, kernel_object_t *object_p)
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
kernel_copy_extra_attr(CK_ATTRIBUTE_INFO_PTR old_attrp,
    kernel_object_t *object_p)
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
get_extra_attr_from_object(kernel_object_t *object_p, CK_ATTRIBUTE_PTR template)
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
set_extra_attr_to_object(kernel_object_t *object_p, CK_ATTRIBUTE_TYPE type,
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
		return (kernel_add_extra_attr(template, object_p));
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
 * Copy the big integer attribute value from template to a biginteger_t struct.
 */
CK_RV
get_bigint_attr_from_template(biginteger_t *big, CK_ATTRIBUTE_PTR template)
{

	if ((template->pValue != NULL) &&
	    (template->ulValueLen > 0)) {
		/* Allocate storage for the value of the attribute. */
		big->big_value = malloc(template->ulValueLen);
		if (big->big_value == NULL) {
			return (CKR_HOST_MEMORY);
		}

		(void) memcpy(big->big_value, template->pValue,
		    template->ulValueLen);
		big->big_value_len = template->ulValueLen;
	} else {
		big->big_value = NULL;
		big->big_value_len = 0;
	}

	return (CKR_OK);
}


/*
 * Copy the big integer attribute value from a biginteger_t struct in the
 * object to a template.
 */
CK_RV
get_bigint_attr_from_object(biginteger_t *big, CK_ATTRIBUTE_PTR template)
{

	if (template->pValue == NULL) {
		template->ulValueLen = big->big_value_len;
		return (CKR_OK);
	}

	if (big->big_value == NULL) {
		template->ulValueLen = 0;
		return (CKR_OK);
	}

	if (template->ulValueLen >= big->big_value_len) {
		/*
		 * The buffer provided by the application is large
		 * enough to hold the value of the attribute.
		 */
		(void) memcpy(template->pValue, big->big_value,
		    big->big_value_len);
		template->ulValueLen = big->big_value_len;
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
 * Copy the boolean data type attribute value from an object for the
 * specified attribute to the template.
 */
CK_RV
get_bool_attr_from_object(kernel_object_t *object_p, CK_ULONG bool_flag,
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
set_bool_attr_to_object(kernel_object_t *object_p, CK_ULONG bool_flag,
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


/*
 * Copy the CK_ULONG data type attribute value from a template to the
 * object.
 */
void
get_ulong_attr_from_template(CK_ULONG *value, CK_ATTRIBUTE_PTR template)
{

	if (template->pValue != NULL) {
		*value = *(CK_ULONG_PTR)template->pValue;
	} else {
		*value = 0;
	}

}

/*
 * Copy the big integer attribute value from source's biginteger_t to
 * destination's biginteger_t.
 */
void
copy_bigint_attr(biginteger_t *src, biginteger_t *dst)
{

	if ((src->big_value != NULL) &&
	    (src->big_value_len > 0)) {
		/*
		 * To do the copy, just have dst's big_value points
		 * to src's.
		 */
		dst->big_value = src->big_value;
		dst->big_value_len = src->big_value_len;

		/*
		 * After the copy, nullify the src's big_value pointer.
		 * It prevents any double freeing the value.
		 */
		src->big_value = NULL;
		src->big_value_len = 0;
	} else {
		dst->big_value = NULL;
		dst->big_value_len = 0;
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
 * Release the storage allocated for object attribute with big integer
 * value.
 */
void
bigint_attr_cleanup(biginteger_t *big)
{

	if (big == NULL)
		return;

	if (big->big_value) {
		(void) memset(big->big_value, 0, big->big_value_len);
		free(big->big_value);
		big->big_value = NULL;
		big->big_value_len = 0;
	}
}


/*
 * Clean up and release all the storage allocated to hold the big integer
 * attributes associated with the type (i.e. class) of the object. Also,
 * release the storage allocated to the type of the object.
 */
void
kernel_cleanup_object_bigint_attrs(kernel_object_t *object_p)
{

	CK_OBJECT_CLASS class = object_p->class;
	CK_KEY_TYPE	keytype = object_p->key_type;


	switch (class) {
	case CKO_PUBLIC_KEY:
		if (OBJ_PUB(object_p)) {
			switch (keytype) {
			case CKK_RSA:
				bigint_attr_cleanup(OBJ_PUB_RSA_MOD(
				    object_p));
				bigint_attr_cleanup(OBJ_PUB_RSA_PUBEXPO(
				    object_p));
				break;

			case CKK_DSA:
				bigint_attr_cleanup(OBJ_PUB_DSA_PRIME(
				    object_p));
				bigint_attr_cleanup(OBJ_PUB_DSA_SUBPRIME(
				    object_p));
				bigint_attr_cleanup(OBJ_PUB_DSA_BASE(
				    object_p));
				bigint_attr_cleanup(OBJ_PUB_DSA_VALUE(
				    object_p));
				break;

			case CKK_DH:
				bigint_attr_cleanup(OBJ_PUB_DH_PRIME(object_p));
				bigint_attr_cleanup(OBJ_PUB_DH_BASE(object_p));
				bigint_attr_cleanup(OBJ_PUB_DH_VALUE(object_p));
				break;

			case CKK_EC:
				bigint_attr_cleanup(OBJ_PUB_EC_POINT(object_p));
				break;
			}

			/* Release Public Key Object struct */
			free(OBJ_PUB(object_p));
			OBJ_PUB(object_p) = NULL;
		}
		break;

	case CKO_PRIVATE_KEY:
		if (OBJ_PRI(object_p)) {
			switch (keytype) {
			case CKK_RSA:
				bigint_attr_cleanup(OBJ_PRI_RSA_MOD(
				    object_p));
				bigint_attr_cleanup(OBJ_PRI_RSA_PUBEXPO(
				    object_p));
				bigint_attr_cleanup(OBJ_PRI_RSA_PRIEXPO(
				    object_p));
				bigint_attr_cleanup(OBJ_PRI_RSA_PRIME1(
				    object_p));
				bigint_attr_cleanup(OBJ_PRI_RSA_PRIME2(
				    object_p));
				bigint_attr_cleanup(OBJ_PRI_RSA_EXPO1(
				    object_p));
				bigint_attr_cleanup(OBJ_PRI_RSA_EXPO2(
				    object_p));
				bigint_attr_cleanup(OBJ_PRI_RSA_COEF(
				    object_p));
				break;

			case CKK_DSA:
				bigint_attr_cleanup(OBJ_PRI_DSA_PRIME(
				    object_p));
				bigint_attr_cleanup(OBJ_PRI_DSA_SUBPRIME(
				    object_p));
				bigint_attr_cleanup(OBJ_PRI_DSA_BASE(
				    object_p));
				bigint_attr_cleanup(OBJ_PRI_DSA_VALUE(
				    object_p));
				break;

			case CKK_DH:
				bigint_attr_cleanup(OBJ_PRI_DH_PRIME(object_p));
				bigint_attr_cleanup(OBJ_PRI_DH_BASE(object_p));
				bigint_attr_cleanup(OBJ_PRI_DH_VALUE(object_p));
				break;

			case CKK_EC:
				bigint_attr_cleanup(OBJ_PRI_EC_VALUE(object_p));
				break;
			}

			/* Release Private Key Object struct. */
			free(OBJ_PRI(object_p));
			OBJ_PRI(object_p) = NULL;
		}
		break;
	}
}


/*
 * Parse the common attributes. Return to caller with appropriate return
 * value to indicate if the supplied template specifies a valid attribute
 * with a valid value.
 */
CK_RV
kernel_parse_common_attrs(CK_ATTRIBUTE_PTR template, kernel_session_t *sp,
    uint64_t *attr_mask_p)
{

	CK_RV rv = CKR_OK;
	kernel_slot_t *pslot = slot_table[sp->ses_slotid];

	switch (template->type) {
	case CKA_CLASS:
		break;

	/* default boolean attributes */
	case CKA_TOKEN:
		if ((*(CK_BBOOL *)template->pValue) == TRUE) {
			rv = CKR_ATTRIBUTE_VALUE_INVALID;
		}
		break;

	case CKA_PRIVATE:
		if ((*(CK_BBOOL *)template->pValue) == TRUE) {
			/*
			 * Cannot create a private object if the token
			 * has a keystore and the user isn't logged in.
			 */
			if (pslot->sl_func_list.fl_object_create &&
			    pslot->sl_state != CKU_USER) {
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
 * Build a Public Key Object.
 *
 * - Parse the object's template, and when an error is detected such as
 *   invalid attribute type, invalid attribute value, etc., return
 *   with appropriate return value.
 * - Set up attribute mask field in the object for the supplied common
 *   attributes that have boolean type.
 * - Build the attribute_info struct to hold the value of each supplied
 *   attribute that has byte array type. Link attribute_info structs
 *   together to form the extra attribute list of the object.
 * - Allocate storage for the Public Key object.
 * - Build the Public Key object according to the key type. Allocate
 *   storage to hold the big integer value for the supplied attributes
 *   that are required for a certain key type.
 *
 */
CK_RV
kernel_build_public_key_object(CK_ATTRIBUTE_PTR template,
    CK_ULONG ulAttrNum,	kernel_object_t *new_object, kernel_session_t *sp,
    uint_t mode)
{

	int		i;
	CK_KEY_TYPE	keytype = (CK_KEY_TYPE)~0UL;
	uint64_t	attr_mask = PUBLIC_KEY_DEFAULT;
	CK_RV 		rv = CKR_OK;
	int		isLabel = 0;
	/* Must set flags */
	int		isModulus = 0;
	int		isPubExpo = 0;
	int		isPrime = 0;
	int		isSubprime = 0;
	int		isBase = 0;
	int		isValue = 0;
	int		isPoint = 0;
	int		isParams = 0;
	/* Must not set flags */
	int		isModulusBits = 0;
	CK_ULONG	modulus_bits = 0;

	biginteger_t	modulus;
	biginteger_t	pubexpo;
	biginteger_t	prime;
	biginteger_t	subprime;
	biginteger_t	base;
	biginteger_t	value;
	biginteger_t	point;
	CK_ATTRIBUTE	string_tmp;
	CK_ATTRIBUTE	param_tmp;

	public_key_obj_t  *pbk;

	/* prevent bigint_attr_cleanup from freeing invalid attr value */
	(void) memset(&modulus, 0x0, sizeof (biginteger_t));
	(void) memset(&pubexpo, 0x0, sizeof (biginteger_t));
	(void) memset(&prime, 0x0, sizeof (biginteger_t));
	(void) memset(&subprime, 0x0, sizeof (biginteger_t));
	(void) memset(&base, 0x0, sizeof (biginteger_t));
	(void) memset(&value, 0x0, sizeof (biginteger_t));
	(void) memset(&point, 0x0, sizeof (biginteger_t));
	string_tmp.pValue = NULL;
	param_tmp.pValue = NULL;

	for (i = 0; i < ulAttrNum; i++) {

		/* Public Key Object Attributes */
		switch (template[i].type) {

		/* common key attributes */
		case CKA_KEY_TYPE:
			keytype = *((CK_KEY_TYPE*)template[i].pValue);
			break;

		case CKA_ID:
		case CKA_START_DATE:
		case CKA_END_DATE:

		/* common public key attribute */
		case CKA_SUBJECT:
			/*
			 * Allocate storage to hold the attribute
			 * value with byte array type, and add it to
			 * the extra attribute list of the object.
			 */
			rv = kernel_add_extra_attr(&template[i],
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
			rv = CKR_TEMPLATE_INCONSISTENT;
			goto fail_cleanup;

		/* Key related boolean attributes */
		case CKA_DERIVE:
			if (*(CK_BBOOL *)template[i].pValue)
				attr_mask |= DERIVE_BOOL_ON;
			break;

		case CKA_ENCRYPT:
			if (*(CK_BBOOL *)template[i].pValue)
				attr_mask |= ENCRYPT_BOOL_ON;
			else
				attr_mask &= ~ENCRYPT_BOOL_ON;
			break;

		case CKA_VERIFY:
			if (*(CK_BBOOL *)template[i].pValue)
				attr_mask |= VERIFY_BOOL_ON;
			else
				attr_mask &= ~VERIFY_BOOL_ON;
			break;

		case CKA_VERIFY_RECOVER:
			if (*(CK_BBOOL *)template[i].pValue)
				attr_mask |= VERIFY_RECOVER_BOOL_ON;
			else
				attr_mask &= ~VERIFY_RECOVER_BOOL_ON;
			break;

		case CKA_WRAP:
			if (*(CK_BBOOL *)template[i].pValue)
				attr_mask |= WRAP_BOOL_ON;
			break;

		case CKA_TRUSTED:
			if (*(CK_BBOOL *)template[i].pValue)
				attr_mask |= TRUSTED_BOOL_ON;
			break;

		/*
		 * The following key related attribute types must
		 * be specified according to the key type by
		 * C_CreateObject.
		 */
		case CKA_MODULUS:
			isModulus = 1;
			/*
			 * Copyin big integer attribute from template
			 * to a local variable.
			 */
			rv = get_bigint_attr_from_template(&modulus,
			    &template[i]);
			if (rv != CKR_OK)
				goto fail_cleanup;
			break;

		case CKA_PUBLIC_EXPONENT:
			isPubExpo = 1;
			rv = get_bigint_attr_from_template(&pubexpo,
			    &template[i]);
			if (rv != CKR_OK)
				goto fail_cleanup;
			break;

		case CKA_PRIME:
			isPrime = 1;
			rv = get_bigint_attr_from_template(&prime,
			    &template[i]);
			if (rv != CKR_OK)
				goto fail_cleanup;
			break;

		case CKA_SUBPRIME:
			isSubprime = 1;
			rv = get_bigint_attr_from_template(&subprime,
			    &template[i]);
			if (rv != CKR_OK)
				goto fail_cleanup;
			break;

		case CKA_BASE:
			isBase = 1;
			rv = get_bigint_attr_from_template(&base,
			    &template[i]);
			if (rv != CKR_OK)
				goto fail_cleanup;
			break;

		case CKA_VALUE:
			isValue = 1;
			rv = get_bigint_attr_from_template(&value,
			    &template[i]);
			if (rv != CKR_OK)
				goto fail_cleanup;
			break;

		case CKA_MODULUS_BITS:
			isModulusBits = 1;
			get_ulong_attr_from_template(&modulus_bits,
			    &template[i]);
			break;

		case CKA_LABEL:
			isLabel = 1;
			rv = get_string_from_template(&string_tmp,
			    &template[i]);
			if (rv != CKR_OK)
				goto fail_cleanup;
			break;

		case CKA_EC_POINT:
			isPoint = 1;
			rv = get_bigint_attr_from_template(&point,
			    &template[i]);
			if (rv != CKR_OK)
				goto fail_cleanup;
			break;

		case CKA_EC_PARAMS:
			isParams = 1;
			rv = get_string_from_template(&param_tmp,
			    &template[i]);
			if (rv != CKR_OK)
				goto fail_cleanup;
			break;

		default:
			rv = kernel_parse_common_attrs(&template[i], sp,
			    &attr_mask);
			if (rv != CKR_OK)
				goto fail_cleanup;
			break;
		}
	} /* For */

	/* Allocate storage for Public Key Object. */
	pbk = calloc(1, sizeof (public_key_obj_t));
	if (pbk == NULL) {
		rv = CKR_HOST_MEMORY;
		goto fail_cleanup;
	}

	new_object->object_class_u.public_key = pbk;
	new_object->class = CKO_PUBLIC_KEY;

	if (keytype == (CK_KEY_TYPE)~0UL) {
		rv = CKR_TEMPLATE_INCOMPLETE;
		goto fail_cleanup;
	}
	new_object->key_type = keytype;

	/* Supported key types of the Public Key Object */
	switch (keytype) {
	case CKK_RSA:
		if (mode == KERNEL_CREATE_OBJ) {
			if (isModulusBits || isPrime || isSubprime ||
			    isBase|| isValue) {
				rv = CKR_TEMPLATE_INCONSISTENT;
				goto fail_cleanup;
			}
		}

		if (isModulus && isPubExpo) {
			/*
			 * Copy big integer attribute value to the
			 * designated place in the public key object.
			 */
			copy_bigint_attr(&modulus,
			    KEY_PUB_RSA_MOD(pbk));

			copy_bigint_attr(&pubexpo,
			    KEY_PUB_RSA_PUBEXPO(pbk));
		} else {
			rv = CKR_TEMPLATE_INCOMPLETE;
			goto fail_cleanup;
		}

		/* must be generating a RSA key pair by value */
		if (isModulusBits) {
			KEY_PUB_RSA_MOD_BITS(pbk) = modulus_bits;
		}
		break;

	case CKK_DSA:
		if (isModulusBits || isModulus || isPubExpo) {
			rv = CKR_TEMPLATE_INCONSISTENT;
			goto fail_cleanup;
		}

		if (!(isPrime && isSubprime && isBase && isValue)) {
			rv = CKR_TEMPLATE_INCOMPLETE;
			goto fail_cleanup;
		}

		copy_bigint_attr(&prime, KEY_PUB_DSA_PRIME(pbk));

		copy_bigint_attr(&subprime, KEY_PUB_DSA_SUBPRIME(pbk));

		copy_bigint_attr(&base, KEY_PUB_DSA_BASE(pbk));

		copy_bigint_attr(&value, KEY_PUB_DSA_VALUE(pbk));

		break;

	case CKK_DH:
		if (!(isPrime && isBase && isValue)) {
			rv = CKR_TEMPLATE_INCOMPLETE;
			goto fail_cleanup;
		}

		copy_bigint_attr(&prime, KEY_PUB_DH_PRIME(pbk));

		copy_bigint_attr(&base, KEY_PUB_DH_BASE(pbk));

		copy_bigint_attr(&value, KEY_PUB_DH_VALUE(pbk));

		break;

	case CKK_EC:
		if (!isPoint || !isParams) {
			rv = CKR_TEMPLATE_INCOMPLETE;
			goto fail_cleanup;
		}

		copy_bigint_attr(&point, KEY_PUB_EC_POINT(pbk));
		rv = kernel_add_extra_attr(&param_tmp, new_object);
		if (rv != CKR_OK)
			goto fail_cleanup;
		string_attr_cleanup(&param_tmp);
		break;
	default:
		rv = CKR_TEMPLATE_INCONSISTENT;
		goto fail_cleanup;
	}

	/* Set up object. */
	new_object->bool_attr_mask = attr_mask;
	if (isLabel) {
		rv = kernel_add_extra_attr(&string_tmp, new_object);
		if (rv != CKR_OK)
			goto fail_cleanup;
		string_attr_cleanup(&string_tmp);
	}

	return (rv);

fail_cleanup:
	/*
	 * cleanup the storage allocated to the local variables.
	 */
	bigint_attr_cleanup(&modulus);
	bigint_attr_cleanup(&pubexpo);
	bigint_attr_cleanup(&prime);
	bigint_attr_cleanup(&subprime);
	bigint_attr_cleanup(&base);
	bigint_attr_cleanup(&value);
	bigint_attr_cleanup(&point);
	string_attr_cleanup(&string_tmp);
	string_attr_cleanup(&param_tmp);

	/*
	 * cleanup the storage allocated inside the object itself.
	 */
	kernel_cleanup_object(new_object);

	return (rv);
}


/*
 * Build a Private Key Object.
 *
 * - Parse the object's template, and when an error is detected such as
 *   invalid attribute type, invalid attribute value, etc., return
 *   with appropriate return value.
 * - Set up attribute mask field in the object for the supplied common
 *   attributes that have boolean type.
 * - Build the attribute_info struct to hold the value of each supplied
 *   attribute that has byte array type. Link attribute_info structs
 *   together to form the extra attribute list of the object.
 * - Allocate storage for the Private Key object.
 * - Build the Private Key object according to the key type. Allocate
 *   storage to hold the big integer value for the supplied attributes
 *   that are required for a certain key type.
 *
 */
CK_RV
kernel_build_private_key_object(CK_ATTRIBUTE_PTR template,
    CK_ULONG ulAttrNum,	kernel_object_t *new_object, kernel_session_t *sp,
    uint_t mode)
{
	ulong_t		i;
	CK_KEY_TYPE	keytype = (CK_KEY_TYPE)~0UL;
	uint64_t	attr_mask = PRIVATE_KEY_DEFAULT;
	CK_RV 		rv = CKR_OK;
	int		isLabel = 0;
	/* Must set flags */
	int		isModulus = 0;
	int		isPriExpo = 0;
	int		isPrime = 0;
	int		isSubprime = 0;
	int		isBase = 0;
	int		isValue = 0;
	int		isParams = 0;
	/* Must not set flags */
	int		isValueBits = 0;
	CK_ULONG	value_bits = 0;

	/* Private Key RSA optional */
	int		isPubExpo = 0;
	int		isPrime1 = 0;
	int		isPrime2 = 0;
	int		isExpo1 = 0;
	int		isExpo2 = 0;
	int		isCoef = 0;

	biginteger_t	modulus;
	biginteger_t	priexpo;
	biginteger_t	prime;
	biginteger_t	subprime;
	biginteger_t	base;
	biginteger_t	value;

	biginteger_t	pubexpo;
	biginteger_t	prime1;
	biginteger_t	prime2;
	biginteger_t	expo1;
	biginteger_t	expo2;
	biginteger_t	coef;
	CK_ATTRIBUTE	string_tmp;
	CK_ATTRIBUTE	param_tmp;

	private_key_obj_t *pvk;

	/* prevent bigint_attr_cleanup from freeing invalid attr value */
	(void) memset(&modulus, 0x0, sizeof (biginteger_t));
	(void) memset(&priexpo, 0x0, sizeof (biginteger_t));
	(void) memset(&prime, 0x0, sizeof (biginteger_t));
	(void) memset(&subprime, 0x0, sizeof (biginteger_t));
	(void) memset(&base, 0x0, sizeof (biginteger_t));
	(void) memset(&value, 0x0, sizeof (biginteger_t));
	(void) memset(&pubexpo, 0x0, sizeof (biginteger_t));
	(void) memset(&prime1, 0x0, sizeof (biginteger_t));
	(void) memset(&prime2, 0x0, sizeof (biginteger_t));
	(void) memset(&expo1, 0x0, sizeof (biginteger_t));
	(void) memset(&expo2, 0x0, sizeof (biginteger_t));
	(void) memset(&coef, 0x0, sizeof (biginteger_t));
	string_tmp.pValue = NULL;
	param_tmp.pValue = NULL;

	for (i = 0; i < ulAttrNum; i++) {

		/* Private Key Object Attributes */
		switch (template[i].type) {

		/* common key attributes */
		case CKA_KEY_TYPE:
			keytype = *((CK_KEY_TYPE*)template[i].pValue);
			break;

		case CKA_ID:
		case CKA_START_DATE:
		case CKA_END_DATE:

		/* common private key attribute */
		case CKA_SUBJECT:
			/*
			 * Allocate storage to hold the attribute
			 * value with byte array type, and add it to
			 * the extra attribute list of the object.
			 */
			rv = kernel_add_extra_attr(&template[i],
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
		case CKA_AUTH_PIN_FLAGS:
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

		case CKA_SECONDARY_AUTH:
			if (*(CK_BBOOL *)template[i].pValue) {
				rv = CKR_ATTRIBUTE_VALUE_INVALID;
				goto fail_cleanup;
			}
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

		case CKA_SIGN_RECOVER:
			if (*(CK_BBOOL *)template[i].pValue)
				attr_mask |= SIGN_RECOVER_BOOL_ON;
			else
				attr_mask &= ~SIGN_RECOVER_BOOL_ON;
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

		/*
		 * The following key related attribute types must
		 * be specified according to the key type by
		 * C_CreateObject.
		 */
		case CKA_MODULUS:
			isModulus = 1;
			/*
			 * Copyin big integer attribute from template
			 * to a local variable.
			 */
			rv = get_bigint_attr_from_template(&modulus,
			    &template[i]);
			if (rv != CKR_OK)
				goto fail_cleanup;
			break;

		case CKA_PUBLIC_EXPONENT:
			isPubExpo = 1;
			rv = get_bigint_attr_from_template(&pubexpo,
			    &template[i]);
			if (rv != CKR_OK)
				goto fail_cleanup;
			break;

		case CKA_PRIVATE_EXPONENT:
			isPriExpo = 1;
			rv = get_bigint_attr_from_template(&priexpo,
			    &template[i]);
			if (rv != CKR_OK)
				goto fail_cleanup;
			break;

		case CKA_PRIME_1:
			isPrime1 = 1;
			rv = get_bigint_attr_from_template(&prime1,
			    &template[i]);
			if (rv != CKR_OK)
				goto fail_cleanup;
			break;

		case CKA_PRIME_2:
			isPrime2 = 1;
			rv = get_bigint_attr_from_template(&prime2,
			    &template[i]);
			if (rv != CKR_OK)
				goto fail_cleanup;
			break;

		case CKA_EXPONENT_1:
			isExpo1 = 1;
			rv = get_bigint_attr_from_template(&expo1,
			    &template[i]);
			if (rv != CKR_OK)
				goto fail_cleanup;
			break;

		case CKA_EXPONENT_2:
			isExpo2 = 1;
			rv = get_bigint_attr_from_template(&expo2,
			    &template[i]);
			if (rv != CKR_OK)
				goto fail_cleanup;
			break;

		case CKA_COEFFICIENT:
			isCoef = 1;
			rv = get_bigint_attr_from_template(&coef,
			    &template[i]);
			if (rv != CKR_OK)
				goto fail_cleanup;
			break;

		case CKA_PRIME:
			isPrime = 1;
			rv = get_bigint_attr_from_template(&prime,
			    &template[i]);
			if (rv != CKR_OK)
				goto fail_cleanup;
			break;

		case CKA_SUBPRIME:
			isSubprime = 1;
			rv = get_bigint_attr_from_template(&subprime,
			    &template[i]);
			if (rv != CKR_OK)
				goto fail_cleanup;
			break;

		case CKA_BASE:
			isBase = 1;
			rv = get_bigint_attr_from_template(&base,
			    &template[i]);
			if (rv != CKR_OK)
				goto fail_cleanup;
			break;

		case CKA_VALUE:
			isValue = 1;
			rv = get_bigint_attr_from_template(&value,
			    &template[i]);
			if (rv != CKR_OK)
				goto fail_cleanup;
			break;

		case CKA_VALUE_BITS:
			isValueBits = 1;
			get_ulong_attr_from_template(&value_bits,
			    &template[i]);
			break;

		case CKA_LABEL:
			isLabel = 1;
			rv = get_string_from_template(&string_tmp,
			    &template[i]);
			if (rv != CKR_OK)
				goto fail_cleanup;
			break;

		case CKA_EC_PARAMS:
			isParams = 1;
			rv = get_string_from_template(&param_tmp,
			    &template[i]);
			if (rv != CKR_OK)
				goto fail_cleanup;
			break;

		default:
			rv = kernel_parse_common_attrs(&template[i], sp,
			    &attr_mask);
			if (rv != CKR_OK)
				goto fail_cleanup;
			break;

		}
	} /* For */

	/* Allocate storage for Private Key Object. */
	pvk = calloc(1, sizeof (private_key_obj_t));
	if (pvk == NULL) {
		rv = CKR_HOST_MEMORY;
		goto fail_cleanup;
	}

	new_object->object_class_u.private_key = pvk;
	new_object->class = CKO_PRIVATE_KEY;

	if (keytype == (CK_KEY_TYPE)~0UL) {
		rv = CKR_TEMPLATE_INCOMPLETE;
		goto fail_cleanup;
	}

	new_object->key_type = keytype;

	/* Supported key types of the Private Key Object */
	switch (keytype) {
	case CKK_RSA:
		if (isPrime || isSubprime || isBase || isValue ||
		    isValueBits) {
			rv = CKR_TEMPLATE_INCONSISTENT;
			goto fail_cleanup;
		}

		if (isModulus && isPriExpo) {
			/*
			 * Copy big integer attribute value to the
			 * designated place in the Private Key object.
			 */
			copy_bigint_attr(&modulus, KEY_PRI_RSA_MOD(pvk));

			copy_bigint_attr(&priexpo, KEY_PRI_RSA_PRIEXPO(pvk));

		} else {
			rv = CKR_TEMPLATE_INCOMPLETE;
			goto fail_cleanup;
		}

		/* The following attributes are optional. */
		if (isPubExpo) {
			copy_bigint_attr(&pubexpo, KEY_PRI_RSA_PUBEXPO(pvk));
		}

		if (isPrime1) {
			copy_bigint_attr(&prime1, KEY_PRI_RSA_PRIME1(pvk));
		}

		if (isPrime2) {
			copy_bigint_attr(&prime2, KEY_PRI_RSA_PRIME2(pvk));
		}

		if (isExpo1) {
			copy_bigint_attr(&expo1, KEY_PRI_RSA_EXPO1(pvk));
		}

		if (isExpo2) {
			copy_bigint_attr(&expo2, KEY_PRI_RSA_EXPO2(pvk));
		}

		if (isCoef) {
			copy_bigint_attr(&coef, KEY_PRI_RSA_COEF(pvk));
		}
		break;

	case CKK_DSA:
		if (isModulus || isPubExpo || isPriExpo || isPrime1 ||
		    isPrime2 || isExpo1 || isExpo2 || isCoef ||
		    isValueBits) {
			rv = CKR_TEMPLATE_INCONSISTENT;
			goto fail_cleanup;
		}

		if (!(isPrime && isSubprime && isBase && isValue)) {
			rv = CKR_TEMPLATE_INCOMPLETE;
			goto fail_cleanup;
		}

		copy_bigint_attr(&prime, KEY_PRI_DSA_PRIME(pvk));

		copy_bigint_attr(&subprime, KEY_PRI_DSA_SUBPRIME(pvk));

		copy_bigint_attr(&base, KEY_PRI_DSA_BASE(pvk));

		copy_bigint_attr(&value, KEY_PRI_DSA_VALUE(pvk));

		break;

	case CKK_DH:
		if (mode == KERNEL_CREATE_OBJ && isValueBits) {
			rv = CKR_TEMPLATE_INCONSISTENT;
			goto fail_cleanup;
		}
		if (!(isPrime && isBase && isValue)) {
			rv = CKR_TEMPLATE_INCOMPLETE;
			goto fail_cleanup;
		}

		copy_bigint_attr(&prime, KEY_PRI_DH_PRIME(pvk));

		copy_bigint_attr(&base, KEY_PRI_DH_BASE(pvk));

		copy_bigint_attr(&value, KEY_PRI_DH_VALUE(pvk));

		KEY_PRI_DH_VAL_BITS(pvk) = (isValueBits) ? value_bits : 0;

		break;

	case CKK_EC:
		if (!isValue || !isParams) {
			rv = CKR_TEMPLATE_INCOMPLETE;
			goto fail_cleanup;
		}

		copy_bigint_attr(&value, KEY_PRI_EC_VALUE(pvk));
		rv = kernel_add_extra_attr(&param_tmp, new_object);
		if (rv != CKR_OK)
			goto fail_cleanup;
		string_attr_cleanup(&param_tmp);
		break;
	default:
		rv = CKR_TEMPLATE_INCONSISTENT;
		goto fail_cleanup;
	}

	/* Set up object. */
	new_object->bool_attr_mask = attr_mask;
	if (isLabel) {
		rv = kernel_add_extra_attr(&string_tmp, new_object);
		if (rv != CKR_OK)
			goto fail_cleanup;
		string_attr_cleanup(&string_tmp);
	}

	return (rv);

fail_cleanup:
	/*
	 * cleanup the storage allocated to the local variables.
	 */
	bigint_attr_cleanup(&modulus);
	bigint_attr_cleanup(&priexpo);
	bigint_attr_cleanup(&prime);
	bigint_attr_cleanup(&subprime);
	bigint_attr_cleanup(&base);
	bigint_attr_cleanup(&value);
	bigint_attr_cleanup(&pubexpo);
	bigint_attr_cleanup(&prime1);
	bigint_attr_cleanup(&prime2);
	bigint_attr_cleanup(&expo1);
	bigint_attr_cleanup(&expo2);
	bigint_attr_cleanup(&coef);
	string_attr_cleanup(&string_tmp);
	string_attr_cleanup(&param_tmp);

	/*
	 * cleanup the storage allocated inside the object itself.
	 */
	kernel_cleanup_object(new_object);

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
kernel_build_secret_key_object(CK_ATTRIBUTE_PTR template,
    CK_ULONG ulAttrNum,	kernel_object_t *new_object, kernel_session_t *sp)
{

	int		i;
	CK_KEY_TYPE	keytype = (CK_KEY_TYPE)~0UL;
	uint64_t	attr_mask = SECRET_KEY_DEFAULT;
	CK_RV 		rv = CKR_OK;
	int		isLabel = 0;
	/* Must set flags */
	int		isValue = 0;
	/* Must not set flags */
	int		isValueLen = 0;

	CK_ATTRIBUTE	string_tmp;

	secret_key_obj_t  *sck;

	string_tmp.pValue = NULL;

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
			rv = kernel_add_extra_attr(&template[i],
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
			isValue = 1;
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
			break;

		case CKA_LABEL:
			isLabel = 1;
			rv = get_string_from_template(&string_tmp,
			    &template[i]);
			if (rv != CKR_OK)
				goto fail_cleanup;
			break;

		default:
			rv = kernel_parse_common_attrs(&template[i], sp,
			    &attr_mask);
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
	case CKK_RC4:
		if (!isValue) {
			rv = CKR_TEMPLATE_INCOMPLETE;
			goto fail_cleanup;
		}
		if ((sck->sk_value_len < ARCFOUR_MIN_KEY_BYTES) ||
		    (sck->sk_value_len > ARCFOUR_MAX_KEY_BYTES)) {
			rv = CKR_ATTRIBUTE_VALUE_INVALID;
			goto fail_cleanup;
		}
		break;

	case CKK_GENERIC_SECRET:
		if (!isValue) {
			rv = CKR_TEMPLATE_INCOMPLETE;
			goto fail_cleanup;
		}
		break;

	case CKK_AES:
		if (!isValue) {
			rv = CKR_TEMPLATE_INCOMPLETE;
			goto fail_cleanup;
		}
		if (sck->sk_value_len < AES_MIN_KEY_BYTES) {
			rv = CKR_ATTRIBUTE_VALUE_INVALID;
			goto fail_cleanup;
		}
		break;

	case CKK_BLOWFISH:
		if (!isValue) {
			rv = CKR_TEMPLATE_INCOMPLETE;
			goto fail_cleanup;
		}
		if (sck->sk_value_len < BLOWFISH_MINBYTES) {
			rv = CKR_ATTRIBUTE_VALUE_INVALID;
			goto fail_cleanup;
		}
		break;

	case CKK_DES:
		if (!isValue) {
			rv = CKR_TEMPLATE_INCOMPLETE;
			goto fail_cleanup;
		}
		if (sck->sk_value_len != DES_KEYSIZE) {
			rv = CKR_ATTRIBUTE_VALUE_INVALID;
			goto fail_cleanup;
		}
		break;

	case CKK_DES2:
		if (!isValue) {
			rv = CKR_TEMPLATE_INCOMPLETE;
			goto fail_cleanup;
		}
		if (sck->sk_value_len != DES2_KEYSIZE) {
			rv = CKR_ATTRIBUTE_VALUE_INVALID;
			goto fail_cleanup;
		}
		break;

	case CKK_DES3:
		if (!isValue) {
			rv = CKR_TEMPLATE_INCOMPLETE;
			goto fail_cleanup;
		}
		if (sck->sk_value_len != DES3_KEYSIZE) {
			rv = CKR_ATTRIBUTE_VALUE_INVALID;
			goto fail_cleanup;
		}
		break;

	default:
		rv = CKR_TEMPLATE_INCONSISTENT;
		goto fail_cleanup;
	}

	if (isValueLen) {
		rv = CKR_TEMPLATE_INCONSISTENT;
		goto fail_cleanup;
	}

	/* Set up object. */
	new_object->bool_attr_mask = attr_mask;
	if (isLabel) {
		rv = kernel_add_extra_attr(&string_tmp, new_object);
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
	kernel_cleanup_object(new_object);

	return (rv);
}


/*
 * Validate the attribute types in the object's template. Then,
 * call the appropriate build function according to the class of
 * the object specified in the template.
 *
 * Note: The following classes of objects are supported:
 * - CKO_SECRET_KEY
 * - CKO_PUBLIC_KEY
 * - CKO_PRIVATE_KEY
 */
CK_RV
kernel_build_object(CK_ATTRIBUTE_PTR template, CK_ULONG ulAttrNum,
    kernel_object_t *new_object, kernel_session_t *sp, uint_t mode)
{

	CK_OBJECT_CLASS class = (CK_OBJECT_CLASS)~0UL;
	CK_RV 		rv = CKR_OK;

	if (template == NULL) {
		return (CKR_ARGUMENTS_BAD);
	}

	/* Validate the attribute type in the template. */
	rv = kernel_validate_attr(template, ulAttrNum, &class);
	if (rv != CKR_OK)
		return (rv);

	if (class == (CK_OBJECT_CLASS)~0UL)
		return (CKR_TEMPLATE_INCOMPLETE);

	/*
	 * Call the appropriate function based on the supported class
	 * of the object.
	 */
	switch (class) {
	case CKO_PUBLIC_KEY:
		rv = kernel_build_public_key_object(template, ulAttrNum,
		    new_object, sp, mode);
		break;

	case CKO_PRIVATE_KEY:
		rv = kernel_build_private_key_object(template, ulAttrNum,
		    new_object, sp, mode);
		break;

	case CKO_SECRET_KEY:
		rv = kernel_build_secret_key_object(template, ulAttrNum,
		    new_object, sp);
		break;

	case CKO_DOMAIN_PARAMETERS:
	case CKO_DATA:
	case CKO_CERTIFICATE:
	case CKO_HW_FEATURE:
	case CKO_VENDOR_DEFINED:
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
kernel_get_common_attrs(kernel_object_t *object_p, CK_ATTRIBUTE_PTR template)
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

		/*
		 * A token object will not be created in the library, so we
		 * return FALSE.
		 */
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
kernel_get_common_key_attrs(kernel_object_t *object_p,
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
 * Get the value of a requested attribute of a Public Key Object.
 *
 * Rule: All the attributes in the public key object can be revealed.
 */
CK_RV
kernel_get_public_key_attribute(kernel_object_t *object_p,
    CK_ATTRIBUTE_PTR template)
{

	CK_RV		rv = CKR_OK;
	CK_KEY_TYPE	keytype = object_p->key_type;

	switch (template->type) {

	case CKA_SUBJECT:
	case CKA_EC_PARAMS:
		/*
		 * The above extra attributes have byte array type.
		 */
		return (get_extra_attr_from_object(object_p,
		    template));

	/* Key related boolean attributes */
	case CKA_ENCRYPT:
		return (get_bool_attr_from_object(object_p,
		    ENCRYPT_BOOL_ON, template));

	case CKA_VERIFY:
		return (get_bool_attr_from_object(object_p,
		    VERIFY_BOOL_ON, template));

	case CKA_VERIFY_RECOVER:
		return (get_bool_attr_from_object(object_p,
		    VERIFY_RECOVER_BOOL_ON, template));

	case CKA_WRAP:
		return (get_bool_attr_from_object(object_p,
		    WRAP_BOOL_ON, template));

	case CKA_TRUSTED:
		return (get_bool_attr_from_object(object_p,
		    TRUSTED_BOOL_ON, template));

	case CKA_MODULUS:
		/*
		 * This attribute is valid only for RSA public key
		 * object.
		 */
		if (keytype == CKK_RSA) {
			return (get_bigint_attr_from_object(
			    OBJ_PUB_RSA_MOD(object_p), template));
		} else {
			template->ulValueLen = (CK_ULONG)-1;
			return (CKR_ATTRIBUTE_TYPE_INVALID);
		}

	case CKA_PUBLIC_EXPONENT:
		if (keytype == CKK_RSA) {
			return (get_bigint_attr_from_object(
			    OBJ_PUB_RSA_PUBEXPO(object_p), template));
		} else {
			template->ulValueLen = (CK_ULONG)-1;
			return (CKR_ATTRIBUTE_TYPE_INVALID);
		}

	case CKA_MODULUS_BITS:
		if (keytype == CKK_RSA) {
			return (get_ulong_attr_from_object(
			    OBJ_PUB_RSA_MOD_BITS(object_p), template));
		} else {
			template->ulValueLen = (CK_ULONG)-1;
			return (CKR_ATTRIBUTE_TYPE_INVALID);
		}

	case CKA_PRIME:
		switch (keytype) {
		case CKK_DSA:
			return (get_bigint_attr_from_object(
			    OBJ_PUB_DSA_PRIME(object_p), template));
		case CKK_DH:
			return (get_bigint_attr_from_object(
			    OBJ_PUB_DH_PRIME(object_p), template));
		default:
			template->ulValueLen = (CK_ULONG)-1;
			return (CKR_ATTRIBUTE_TYPE_INVALID);
		}

	case CKA_SUBPRIME:
		switch (keytype) {
		case CKK_DSA:
			return (get_bigint_attr_from_object(
			    OBJ_PUB_DSA_SUBPRIME(object_p), template));
		default:
			template->ulValueLen = (CK_ULONG)-1;
			return (CKR_ATTRIBUTE_TYPE_INVALID);
		}

	case CKA_BASE:
		switch (keytype) {
		case CKK_DSA:
			return (get_bigint_attr_from_object(
			    OBJ_PUB_DSA_BASE(object_p), template));
		case CKK_DH:
			return (get_bigint_attr_from_object(
			    OBJ_PUB_DH_BASE(object_p), template));
		default:
			template->ulValueLen = (CK_ULONG)-1;
			return (CKR_ATTRIBUTE_TYPE_INVALID);
		}

	case CKA_VALUE:
		switch (keytype) {
		case CKK_DSA:
			return (get_bigint_attr_from_object(
			    OBJ_PUB_DSA_VALUE(object_p), template));
		case CKK_DH:
			return (get_bigint_attr_from_object(
			    OBJ_PUB_DH_VALUE(object_p), template));
		default:
			template->ulValueLen = (CK_ULONG)-1;
			return (CKR_ATTRIBUTE_TYPE_INVALID);
		}

	case CKA_EC_POINT:
		switch (keytype) {
		case CKK_EC:
			return (get_bigint_attr_from_object(
			    OBJ_PUB_EC_POINT(object_p), template));
		default:
			template->ulValueLen = (CK_ULONG)-1;
			return (CKR_ATTRIBUTE_TYPE_INVALID);
		}
	default:
		/*
		 * First, get the value of the request attribute defined
		 * in the list of common key attributes. If the request
		 * attribute is not found in that list, then get the
		 * attribute from the list of common attributes.
		 */
		rv = kernel_get_common_key_attrs(object_p, template);
		if (rv == CKR_ATTRIBUTE_TYPE_INVALID) {
			rv = kernel_get_common_attrs(object_p, template);
		}
		break;
	}

	return (rv);
}


/*
 * Get the value of a requested attribute of a Private Key Object.
 *
 * Rule: All the attributes in the private key object can be revealed
 *       except those marked with footnote number "7" when the object
 *       has its CKA_SENSITIVE attribute set to TRUE or its
 *       CKA_EXTRACTABLE attribute set to FALSE (p.88 in PKCS11 spec.).
 */
CK_RV
kernel_get_private_key_attribute(kernel_object_t *object_p,
    CK_ATTRIBUTE_PTR template)
{

	CK_RV		rv = CKR_OK;
	CK_KEY_TYPE	keytype = object_p->key_type;


	/*
	 * If the following specified attributes for the private key
	 * object cannot be revealed because the object is sensitive
	 * or unextractable, then the ulValueLen is set to -1.
	 */
	if ((object_p->bool_attr_mask & SENSITIVE_BOOL_ON) ||
	    !(object_p->bool_attr_mask & EXTRACTABLE_BOOL_ON)) {

		switch (template->type) {
		case CKA_PRIVATE_EXPONENT:
		case CKA_PRIME_1:
		case CKA_PRIME_2:
		case CKA_EXPONENT_1:
		case CKA_EXPONENT_2:
		case CKA_COEFFICIENT:
		case CKA_VALUE:
			template->ulValueLen = (CK_ULONG)-1;
			return (CKR_ATTRIBUTE_SENSITIVE);
		}
	}

	switch (template->type) {

	case CKA_SUBJECT:
	case CKA_EC_PARAMS:
		/*
		 * The above extra attributes have byte array type.
		 */
		return (get_extra_attr_from_object(object_p,
		    template));

	/* Key related boolean attributes */
	case CKA_SENSITIVE:
		return (get_bool_attr_from_object(object_p,
		    SENSITIVE_BOOL_ON, template));

	case CKA_SECONDARY_AUTH:
		return (get_bool_attr_from_object(object_p,
		    SECONDARY_AUTH_BOOL_ON, template));

	case CKA_DECRYPT:
		return (get_bool_attr_from_object(object_p,
		    DECRYPT_BOOL_ON, template));

	case CKA_SIGN:
		return (get_bool_attr_from_object(object_p,
		    SIGN_BOOL_ON, template));

	case CKA_SIGN_RECOVER:
		return (get_bool_attr_from_object(object_p,
		    SIGN_RECOVER_BOOL_ON, template));

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

	case CKA_MODULUS:
		if (keytype == CKK_RSA) {
			return (get_bigint_attr_from_object(
			    OBJ_PRI_RSA_MOD(object_p), template));
		} else {
			template->ulValueLen = (CK_ULONG)-1;
			rv = CKR_ATTRIBUTE_TYPE_INVALID;
			break;
		}

	case CKA_PUBLIC_EXPONENT:
		if (keytype == CKK_RSA) {
			return (get_bigint_attr_from_object(
			    OBJ_PRI_RSA_PUBEXPO(object_p), template));
		} else {
			template->ulValueLen = (CK_ULONG)-1;
			rv = CKR_ATTRIBUTE_TYPE_INVALID;
			break;
		}

	case CKA_PRIVATE_EXPONENT:
		if (keytype == CKK_RSA) {
			return (get_bigint_attr_from_object(
			    OBJ_PRI_RSA_PRIEXPO(object_p), template));
		} else {
			template->ulValueLen = (CK_ULONG)-1;
			rv = CKR_ATTRIBUTE_TYPE_INVALID;
			break;
		}

	case CKA_PRIME_1:
		if (keytype == CKK_RSA) {
			return (get_bigint_attr_from_object(
			    OBJ_PRI_RSA_PRIME1(object_p), template));
		} else {
			template->ulValueLen = (CK_ULONG)-1;
			rv = CKR_ATTRIBUTE_TYPE_INVALID;
			break;
		}

	case CKA_PRIME_2:
		if (keytype == CKK_RSA) {
			return (get_bigint_attr_from_object(
			    OBJ_PRI_RSA_PRIME2(object_p), template));
		} else {
			template->ulValueLen = (CK_ULONG)-1;
			rv = CKR_ATTRIBUTE_TYPE_INVALID;
			break;
		}

	case CKA_EXPONENT_1:
		if (keytype == CKK_RSA) {
			return (get_bigint_attr_from_object(
			    OBJ_PRI_RSA_EXPO1(object_p), template));
		} else {
			template->ulValueLen = (CK_ULONG)-1;
			rv = CKR_ATTRIBUTE_TYPE_INVALID;
			break;
		}

	case CKA_EXPONENT_2:
		if (keytype == CKK_RSA) {
			return (get_bigint_attr_from_object(
			    OBJ_PRI_RSA_EXPO2(object_p), template));
		} else {
			template->ulValueLen = (CK_ULONG)-1;
			rv = CKR_ATTRIBUTE_TYPE_INVALID;
			break;
		}

	case CKA_COEFFICIENT:
		if (keytype == CKK_RSA) {
			return (get_bigint_attr_from_object(
			    OBJ_PRI_RSA_COEF(object_p), template));
		} else {
			template->ulValueLen = (CK_ULONG)-1;
			rv = CKR_ATTRIBUTE_TYPE_INVALID;
			break;
		}

	case CKA_VALUE_BITS:
		if (keytype == CKK_DH) {
			return (get_ulong_attr_from_object(
			    OBJ_PRI_DH_VAL_BITS(object_p), template));
		} else {
			template->ulValueLen = (CK_ULONG)-1;
			rv = CKR_ATTRIBUTE_TYPE_INVALID;
			break;
		}

	case CKA_PRIME:
		switch (keytype) {
		case CKK_DSA:
			return (get_bigint_attr_from_object(
			    OBJ_PRI_DSA_PRIME(object_p), template));
		case CKK_DH:
			return (get_bigint_attr_from_object(
			    OBJ_PRI_DH_PRIME(object_p), template));
		default:
			template->ulValueLen = (CK_ULONG)-1;
			return (CKR_ATTRIBUTE_TYPE_INVALID);
		}

	case CKA_SUBPRIME:
		switch (keytype) {
		case CKK_DSA:
			return (get_bigint_attr_from_object(
			    OBJ_PRI_DSA_SUBPRIME(object_p), template));
		default:
			template->ulValueLen = (CK_ULONG)-1;
			return (CKR_ATTRIBUTE_TYPE_INVALID);
		}

	case CKA_BASE:
		switch (keytype) {
		case CKK_DSA:
			return (get_bigint_attr_from_object(
			    OBJ_PRI_DSA_BASE(object_p), template));
		case CKK_DH:
			return (get_bigint_attr_from_object(
			    OBJ_PRI_DH_BASE(object_p), template));
		default:
			template->ulValueLen = (CK_ULONG)-1;
			return (CKR_ATTRIBUTE_TYPE_INVALID);
		}

	case CKA_VALUE:
		switch (keytype) {
		case CKK_DSA:
			return (get_bigint_attr_from_object(
			    OBJ_PRI_DSA_VALUE(object_p), template));
		case CKK_DH:
			return (get_bigint_attr_from_object(
			    OBJ_PRI_DH_VALUE(object_p), template));
		case CKK_EC:
			return (get_bigint_attr_from_object(
			    OBJ_PRI_EC_VALUE(object_p), template));
		default:
			template->ulValueLen = (CK_ULONG)-1;
			return (CKR_ATTRIBUTE_TYPE_INVALID);
		}

	default:
		/*
		 * First, get the value of the request attribute defined
		 * in the list of common key attributes. If the request
		 * attribute is not found in that list, then get the
		 * attribute from the list of common attributes.
		 */
		rv = kernel_get_common_key_attrs(object_p, template);
		if (rv == CKR_ATTRIBUTE_TYPE_INVALID) {
			rv = kernel_get_common_attrs(object_p, template);
		}
		break;
	}

	return (rv);
}


/*
 * Get the value of a requested attribute of a Secret Key Object.
 *
 * Rule: All the attributes in the secret key object can be revealed
 *       except those marked with footnote number "7" when the object
 *       has its CKA_SENSITIVE attribute set to TRUE or its
 *       CKA_EXTRACTABLE attribute set to FALSE (p.88 in PKCS11 spec.).
 */
CK_RV
kernel_get_secret_key_attribute(kernel_object_t *object_p,
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
		case CKK_RC4:
		case CKK_GENERIC_SECRET:
		case CKK_RC5:
		case CKK_DES:
		case CKK_DES2:
		case CKK_DES3:
		case CKK_CDMF:
		case CKK_AES:
		case CKK_BLOWFISH:
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
		rv = kernel_get_common_key_attrs(object_p, template);
		if (rv == CKR_ATTRIBUTE_TYPE_INVALID) {
			rv = kernel_get_common_attrs(object_p, template);
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
kernel_get_attribute(kernel_object_t *object_p, CK_ATTRIBUTE_PTR template)
{

	CK_RV		rv = CKR_OK;
	CK_OBJECT_CLASS class = object_p->class;

	switch (class) {

	case CKO_PUBLIC_KEY:
		rv =  kernel_get_public_key_attribute(object_p, template);
		break;

	case CKO_PRIVATE_KEY:
		rv = kernel_get_private_key_attribute(object_p, template);
		break;

	case CKO_SECRET_KEY:
		rv = kernel_get_secret_key_attribute(object_p, template);
		break;

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
CK_RV
kernel_set_common_key_attribute(kernel_object_t *object_p,
    CK_ATTRIBUTE_PTR template, boolean_t copy, kernel_session_t *sp)
{

	kernel_slot_t *pslot = slot_table[sp->ses_slotid];
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
		if (pslot->sl_func_list.fl_object_create &&
		    pslot->sl_state != CKU_USER) {
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
 * Set the value of an attribute of a Public Key Object.
 *
 * Rule: The attributes marked with footnote number "8" in the PKCS11
 *       spec may be modified (p.88 in PKCS11 spec.).
 */
CK_RV
kernel_set_public_key_attribute(kernel_object_t *object_p,
    CK_ATTRIBUTE_PTR template, boolean_t copy, kernel_session_t *sp)
{
	CK_KEY_TYPE	keytype = object_p->key_type;

	switch (template->type) {

	case CKA_SUBJECT:
		return (set_extra_attr_to_object(object_p,
		    CKA_SUBJECT, template));

	case CKA_ENCRYPT:
		return (set_bool_attr_to_object(object_p,
		    ENCRYPT_BOOL_ON, template));

	case CKA_VERIFY:
		return (set_bool_attr_to_object(object_p,
		    VERIFY_BOOL_ON, template));

	case CKA_VERIFY_RECOVER:
		return (set_bool_attr_to_object(object_p,
		    VERIFY_RECOVER_BOOL_ON, template));

	case CKA_WRAP:
		return (set_bool_attr_to_object(object_p,
		    WRAP_BOOL_ON, template));

	case CKA_MODULUS:
	case CKA_MODULUS_BITS:
	case CKA_PUBLIC_EXPONENT:
		if (keytype == CKK_RSA)
			return (CKR_ATTRIBUTE_READ_ONLY);
		break;

	case CKA_SUBPRIME:
	case CKA_PRIME:
	case CKA_BASE:
	case CKA_VALUE:
		if (keytype == CKK_DSA)
			return (CKR_ATTRIBUTE_READ_ONLY);
		break;

	default:
		/*
		 * Set the value of a common key attribute.
		 */
		return (kernel_set_common_key_attribute(object_p,
		    template, copy, sp));

	}

	/*
	 * If we got this far, then the combination of key type
	 * and requested attribute is invalid.
	 */
	return (CKR_ATTRIBUTE_TYPE_INVALID);
}


/*
 * Set the value of an attribute of a Private Key Object.
 *
 * Rule: The attributes marked with footnote number "8" in the PKCS11
 *       spec may be modified (p.88 in PKCS11 spec.).
 */
CK_RV
kernel_set_private_key_attribute(kernel_object_t *object_p,
    CK_ATTRIBUTE_PTR template, boolean_t copy, kernel_session_t *sp)
{
	CK_KEY_TYPE	keytype = object_p->key_type;

	switch (template->type) {

	case CKA_SUBJECT:
		return (set_extra_attr_to_object(object_p,
		    CKA_SUBJECT, template));

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

	case CKA_DECRYPT:
		return (set_bool_attr_to_object(object_p,
		    DECRYPT_BOOL_ON, template));

	case CKA_SIGN:
		return (set_bool_attr_to_object(object_p,
		    SIGN_BOOL_ON, template));

	case CKA_SIGN_RECOVER:
		return (set_bool_attr_to_object(object_p,
		    SIGN_RECOVER_BOOL_ON, template));

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

	case CKA_MODULUS:
	case CKA_PUBLIC_EXPONENT:
	case CKA_PRIVATE_EXPONENT:
	case CKA_PRIME_1:
	case CKA_PRIME_2:
	case CKA_EXPONENT_1:
	case CKA_EXPONENT_2:
	case CKA_COEFFICIENT:
		if (keytype == CKK_RSA) {
			return (CKR_ATTRIBUTE_READ_ONLY);
		}
		break;

	case CKA_SUBPRIME:
	case CKA_PRIME:
	case CKA_BASE:
	case CKA_VALUE:
		if (keytype == CKK_DSA)
			return (CKR_ATTRIBUTE_READ_ONLY);
		break;

	default:
		/*
		 * Set the value of a common key attribute.
		 */
		return (kernel_set_common_key_attribute(object_p,
		    template, copy, sp));
	}

	/*
	 * If we got this far, then the combination of key type
	 * and requested attribute is invalid.
	 */
	return (CKR_ATTRIBUTE_TYPE_INVALID);
}



/*
 * Set the value of an attribute of a Secret Key Object.
 *
 * Rule: The attributes marked with footnote number "8" in the PKCS11
 *       spec may be modified (p.88 in PKCS11 spec.).
 */
CK_RV
kernel_set_secret_key_attribute(kernel_object_t *object_p,
    CK_ATTRIBUTE_PTR template, boolean_t copy, kernel_session_t *sp)
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
		return (kernel_set_common_key_attribute(object_p,
		    template, copy, sp));
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
kernel_set_attribute(kernel_object_t *object_p, CK_ATTRIBUTE_PTR template,
    boolean_t copy, kernel_session_t *sp)
{

	CK_RV		rv = CKR_OK;
	CK_OBJECT_CLASS	class = object_p->class;

	switch (class) {

	case CKO_PUBLIC_KEY:
		rv = kernel_set_public_key_attribute(object_p, template,
		    copy, sp);
		break;

	case CKO_PRIVATE_KEY:
		rv = kernel_set_private_key_attribute(object_p, template,
		    copy, sp);
		break;

	case CKO_SECRET_KEY:
		rv = kernel_set_secret_key_attribute(object_p, template,
		    copy, sp);
		break;

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


static CK_RV
copy_bigint(biginteger_t *new_bigint, biginteger_t *old_bigint)
{
	new_bigint->big_value =
	    malloc((sizeof (CK_BYTE) * new_bigint->big_value_len));

	if (new_bigint->big_value == NULL) {
		return (CKR_HOST_MEMORY);
	}

	(void) memcpy(new_bigint->big_value, old_bigint->big_value,
	    (sizeof (CK_BYTE) * new_bigint->big_value_len));

	return (CKR_OK);
}

static void
free_public_key_attr(public_key_obj_t *pbk, CK_KEY_TYPE key_type)
{
	if (pbk == NULL) {
		return;
	}

	switch (key_type) {
		case CKK_RSA:
			bigint_attr_cleanup(KEY_PUB_RSA_MOD(pbk));
			bigint_attr_cleanup(KEY_PUB_RSA_PUBEXPO(pbk));
			break;
		case CKK_DSA:
			bigint_attr_cleanup(KEY_PUB_DSA_PRIME(pbk));
			bigint_attr_cleanup(KEY_PUB_DSA_SUBPRIME(pbk));
			bigint_attr_cleanup(KEY_PUB_DSA_BASE(pbk));
			bigint_attr_cleanup(KEY_PUB_DSA_VALUE(pbk));
			break;
		default:
			break;
	}
	free(pbk);
}


CK_RV
kernel_copy_public_key_attr(public_key_obj_t *old_pub_key_obj_p,
    public_key_obj_t **new_pub_key_obj_p, CK_KEY_TYPE key_type)
{

	public_key_obj_t *pbk;
	CK_RV rv = CKR_OK;

	pbk = calloc(1, sizeof (public_key_obj_t));
	if (pbk == NULL) {
		return (CKR_HOST_MEMORY);
	}

	switch (key_type) {
		case CKK_RSA:
			(void) memcpy(KEY_PUB_RSA(pbk),
			    KEY_PUB_RSA(old_pub_key_obj_p),
			    sizeof (rsa_pub_key_t));
			/* copy modulus */
			rv = copy_bigint(KEY_PUB_RSA_MOD(pbk),
			    KEY_PUB_RSA_MOD(old_pub_key_obj_p));
			if (rv != CKR_OK) {
				free_public_key_attr(pbk, key_type);
				return (rv);
			}
			/* copy public exponent */
			rv = copy_bigint(KEY_PUB_RSA_PUBEXPO(pbk),
			    KEY_PUB_RSA_PUBEXPO(old_pub_key_obj_p));
			if (rv != CKR_OK) {
				free_public_key_attr(pbk, key_type);
				return (rv);
			}
			break;
		case CKK_DSA:
			(void) memcpy(KEY_PUB_DSA(pbk),
			    KEY_PUB_DSA(old_pub_key_obj_p),
			    sizeof (dsa_pub_key_t));

			/* copy prime */
			rv = copy_bigint(KEY_PUB_DSA_PRIME(pbk),
			    KEY_PUB_DSA_PRIME(old_pub_key_obj_p));
			if (rv != CKR_OK) {
				free_public_key_attr(pbk, key_type);
				return (rv);
			}

			/* copy subprime */
			rv = copy_bigint(KEY_PUB_DSA_SUBPRIME(pbk),
			    KEY_PUB_DSA_SUBPRIME(old_pub_key_obj_p));
			if (rv != CKR_OK) {
				free_public_key_attr(pbk, key_type);
				return (rv);
			}

			/* copy base */
			rv = copy_bigint(KEY_PUB_DSA_BASE(pbk),
			    KEY_PUB_DSA_BASE(old_pub_key_obj_p));
			if (rv != CKR_OK) {
				free_public_key_attr(pbk, key_type);
				return (rv);
			}

			/* copy value */
			rv = copy_bigint(KEY_PUB_DSA_VALUE(pbk),
			    KEY_PUB_DSA_VALUE(old_pub_key_obj_p));
			if (rv != CKR_OK) {
				free_public_key_attr(pbk, key_type);
				return (rv);
			}
			break;
		default:
			break;
	}
	*new_pub_key_obj_p = pbk;
	return (rv);
}


static void
free_private_key_attr(private_key_obj_t *pbk, CK_KEY_TYPE key_type)
{
	if (pbk == NULL) {
		return;
	}

	switch (key_type) {
		case CKK_RSA:
			bigint_attr_cleanup(KEY_PRI_RSA_MOD(pbk));
			bigint_attr_cleanup(KEY_PRI_RSA_PUBEXPO(pbk));
			bigint_attr_cleanup(KEY_PRI_RSA_PRIEXPO(pbk));
			bigint_attr_cleanup(KEY_PRI_RSA_PRIME1(pbk));
			bigint_attr_cleanup(KEY_PRI_RSA_PRIME2(pbk));
			bigint_attr_cleanup(KEY_PRI_RSA_EXPO1(pbk));
			bigint_attr_cleanup(KEY_PRI_RSA_EXPO2(pbk));
			bigint_attr_cleanup(KEY_PRI_RSA_COEF(pbk));
			break;
		case CKK_DSA:
			bigint_attr_cleanup(KEY_PRI_DSA_PRIME(pbk));
			bigint_attr_cleanup(KEY_PRI_DSA_SUBPRIME(pbk));
			bigint_attr_cleanup(KEY_PRI_DSA_BASE(pbk));
			bigint_attr_cleanup(KEY_PRI_DSA_VALUE(pbk));
			break;
		default:
			break;
	}
	free(pbk);
}

CK_RV
kernel_copy_private_key_attr(private_key_obj_t *old_pri_key_obj_p,
    private_key_obj_t **new_pri_key_obj_p, CK_KEY_TYPE key_type)
{
	CK_RV rv = CKR_OK;
	private_key_obj_t *pbk;

	pbk = calloc(1, sizeof (private_key_obj_t));
	if (pbk == NULL) {
		return (CKR_HOST_MEMORY);
	}

	switch (key_type) {
		case CKK_RSA:
			(void) memcpy(KEY_PRI_RSA(pbk),
			    KEY_PRI_RSA(old_pri_key_obj_p),
			    sizeof (rsa_pri_key_t));
			/* copy modulus */
			rv = copy_bigint(KEY_PRI_RSA_MOD(pbk),
			    KEY_PRI_RSA_MOD(old_pri_key_obj_p));
			if (rv != CKR_OK) {
				free_private_key_attr(pbk, key_type);
				return (rv);
			}
			/* copy public exponent */
			rv = copy_bigint(KEY_PRI_RSA_PUBEXPO(pbk),
			    KEY_PRI_RSA_PUBEXPO(old_pri_key_obj_p));
			if (rv != CKR_OK) {
				free_private_key_attr(pbk, key_type);
				return (rv);
			}
			/* copy private exponent */
			rv = copy_bigint(KEY_PRI_RSA_PRIEXPO(pbk),
			    KEY_PRI_RSA_PRIEXPO(old_pri_key_obj_p));
			if (rv != CKR_OK) {
				free_private_key_attr(pbk, key_type);
				return (rv);
			}
			/* copy prime_1 */
			rv = copy_bigint(KEY_PRI_RSA_PRIME1(pbk),
			    KEY_PRI_RSA_PRIME1(old_pri_key_obj_p));
			if (rv != CKR_OK) {
				free_private_key_attr(pbk, key_type);
				return (rv);
			}
			/* copy prime_2 */
			rv = copy_bigint(KEY_PRI_RSA_PRIME2(pbk),
			    KEY_PRI_RSA_PRIME2(old_pri_key_obj_p));
			if (rv != CKR_OK) {
				free_private_key_attr(pbk, key_type);
				return (rv);
			}
			/* copy exponent_1 */
			rv = copy_bigint(KEY_PRI_RSA_EXPO1(pbk),
			    KEY_PRI_RSA_EXPO1(old_pri_key_obj_p));
			if (rv != CKR_OK) {
				free_private_key_attr(pbk, key_type);
				return (rv);
			}
			/* copy exponent_2 */
			rv = copy_bigint(KEY_PRI_RSA_EXPO2(pbk),
			    KEY_PRI_RSA_EXPO2(old_pri_key_obj_p));
			if (rv != CKR_OK) {
				free_private_key_attr(pbk, key_type);
				return (rv);
			}
			/* copy coefficient */
			rv = copy_bigint(KEY_PRI_RSA_COEF(pbk),
			    KEY_PRI_RSA_COEF(old_pri_key_obj_p));
			if (rv != CKR_OK) {
				free_private_key_attr(pbk, key_type);
				return (rv);
			}
			break;
		case CKK_DSA:
			(void) memcpy(KEY_PRI_DSA(pbk),
			    KEY_PRI_DSA(old_pri_key_obj_p),
			    sizeof (dsa_pri_key_t));

			/* copy prime */
			rv = copy_bigint(KEY_PRI_DSA_PRIME(pbk),
			    KEY_PRI_DSA_PRIME(old_pri_key_obj_p));
			if (rv != CKR_OK) {
				free_private_key_attr(pbk, key_type);
				return (rv);
			}

			/* copy subprime */
			rv = copy_bigint(KEY_PRI_DSA_SUBPRIME(pbk),
			    KEY_PRI_DSA_SUBPRIME(old_pri_key_obj_p));
			if (rv != CKR_OK) {
				free_private_key_attr(pbk, key_type);
				return (rv);
			}

			/* copy base */
			rv = copy_bigint(KEY_PRI_DSA_BASE(pbk),
			    KEY_PRI_DSA_BASE(old_pri_key_obj_p));
			if (rv != CKR_OK) {
				free_private_key_attr(pbk, key_type);
				return (rv);
			}

			/* copy value */
			rv = copy_bigint(KEY_PRI_DSA_VALUE(pbk),
			    KEY_PRI_DSA_VALUE(old_pri_key_obj_p));
			if (rv != CKR_OK) {
				free_private_key_attr(pbk, key_type);
				return (rv);
			}
			break;
		default:
			break;
	}
	*new_pri_key_obj_p = pbk;
	return (rv);
}


CK_RV
kernel_copy_secret_key_attr(secret_key_obj_t *old_secret_key_obj_p,
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
 * attributes on template .
 *
 * Some attributes are specific to an object class.  If one or more
 * of these attributes are in the template, make a list of classes
 * that can have these attributes.  This would speed up the search later,
 * because we can immediately skip an object if the class of that
 * object can not possibly contain one of the attributes.
 *
 */
void
kernel_process_find_attr(CK_OBJECT_CLASS *pclasses,
    CK_ULONG *num_result_pclasses, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount)
{
	ulong_t i;
	int j;
	boolean_t pub_found = B_FALSE,
	    priv_found = B_FALSE,
	    secret_found = B_FALSE,
	    domain_found = B_FALSE,
	    hardware_found = B_FALSE,
	    cert_found = B_FALSE;
	int num_pub_key_attrs, num_priv_key_attrs,
	    num_secret_key_attrs, num_domain_attrs,
	    num_hardware_attrs, num_cert_attrs;
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

	num_pub_key_attrs =
	    sizeof (PUB_KEY_ATTRS) / sizeof (CK_ATTRIBUTE_TYPE);
	num_priv_key_attrs =
	    sizeof (PRIV_KEY_ATTRS) / sizeof (CK_ATTRIBUTE_TYPE);
	num_secret_key_attrs =
	    sizeof (SECRET_KEY_ATTRS) / sizeof (CK_ATTRIBUTE_TYPE);
	num_domain_attrs =
	    sizeof (DOMAIN_ATTRS) / sizeof (CK_ATTRIBUTE_TYPE);
	num_hardware_attrs =
	    sizeof (HARDWARE_ATTRS) / sizeof (CK_ATTRIBUTE_TYPE);
	num_cert_attrs =
	    sizeof (CERT_ATTRS) / sizeof (CK_ATTRIBUTE_TYPE);

	/*
	 * Get the list of objects class that might contain
	 * some attributes.
	 */
	for (i = 0; i < ulCount; i++) {
		/*
		 * only check if this attribute can belong to public key object
		 * class if public key object isn't already in the list
		 */
		if (!pub_found) {
			for (j = 0; j < num_pub_key_attrs; j++) {
				if (pTemplate[i].type == PUB_KEY_ATTRS[j]) {
					pub_found = B_TRUE;
					pclasses[num_pclasses++] =
					    CKO_PUBLIC_KEY;
					break;
				}
			}
		}

		if (!priv_found) {
			for (j = 0; j < num_priv_key_attrs; j++) {
				if (pTemplate[i].type == PRIV_KEY_ATTRS[j]) {
					priv_found = B_TRUE;
					pclasses[num_pclasses++] =
					    CKO_PRIVATE_KEY;
					break;
				}
			}
		}

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

		if (!domain_found) {
			for (j = 0; j < num_domain_attrs; j++) {
				if (pTemplate[i].type == DOMAIN_ATTRS[j]) {
					domain_found = B_TRUE;
					pclasses[num_pclasses++] =
					    CKO_DOMAIN_PARAMETERS;
					break;
				}
			}
		}

		if (!hardware_found) {
			for (j = 0; j < num_hardware_attrs; j++) {
				if (pTemplate[i].type == HARDWARE_ATTRS[j]) {
					hardware_found = B_TRUE;
					pclasses[num_pclasses++] =
					    CKO_HW_FEATURE;
					break;
				}
			}
		}

		if (!cert_found) {
			for (j = 0; j < num_cert_attrs; j++) {
				if (pTemplate[i].type == CERT_ATTRS[j]) {
					cert_found = B_TRUE;
					pclasses[num_pclasses++] =
					    CKO_CERTIFICATE;
					break;
				}
			}
		}
	}
	*num_result_pclasses = num_pclasses;
}


boolean_t
kernel_find_match_attrs(kernel_object_t *obj, CK_OBJECT_CLASS *pclasses,
    CK_ULONG num_pclasses, CK_ATTRIBUTE *template, CK_ULONG num_attr)
{
	ulong_t i;
	CK_ATTRIBUTE *tmpl_attr, *obj_attr;
	uint64_t attr_mask;
	biginteger_t *bigint;
	boolean_t compare_attr, compare_bigint, compare_boolean;

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
		compare_bigint = B_FALSE;
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
			/*
			 * CKA_TOKEN value is not applicable to an object
			 * created in the library, it should only contain
			 * the default value FALSE
			 */
			attr_mask = 0;
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
				/*
				 * secret_key_obj_t is the same as
				 * biginteger_t
				 */
				bigint = (biginteger_t *)OBJ_SEC(obj);
				break;
			case CKO_PRIVATE_KEY:
				if (obj->key_type == CKK_DSA) {
					bigint = OBJ_PRI_DSA_VALUE(obj);
				} else {
					return (B_FALSE);
				}
				break;
			case CKO_PUBLIC_KEY:
				if (obj->key_type == CKK_DSA) {
					bigint = OBJ_PUB_DSA_VALUE(obj);
				} else {
					return (B_FALSE);
				}
				break;
			default:
				return (B_FALSE);
			}
			compare_bigint = B_TRUE;
			break;
		case CKA_MODULUS:
			/* only RSA public and private key have this attr */
			if (obj->key_type == CKK_RSA) {
				if (obj->class == CKO_PUBLIC_KEY) {
					bigint = OBJ_PUB_RSA_MOD(obj);
				} else if (obj->class == CKO_PRIVATE_KEY) {
					bigint = OBJ_PRI_RSA_MOD(obj);
				} else {
					return (B_FALSE);
				}
				compare_bigint = B_TRUE;
			} else {
				return (B_FALSE);
			}
			break;
		case CKA_MODULUS_BITS:
			/* only RSA public key has this attribute */
			if ((obj->key_type == CKK_RSA) &&
			    (obj->class == CKO_PUBLIC_KEY)) {
				CK_ULONG mod_bits = OBJ_PUB_RSA_MOD_BITS(obj);
				if (mod_bits !=
				    *((CK_ULONG *)tmpl_attr->pValue)) {
					return (B_FALSE);
				}
			} else {
				return (B_FALSE);
			}
			break;
		case CKA_PUBLIC_EXPONENT:
			/* only RSA public and private key have this attr */
			if (obj->key_type == CKK_RSA) {
				if (obj->class == CKO_PUBLIC_KEY) {
					bigint = OBJ_PUB_RSA_PUBEXPO(obj);
				} else if (obj->class == CKO_PRIVATE_KEY) {
					bigint = OBJ_PRI_RSA_PUBEXPO(obj);
				} else {
					return (B_FALSE);
				}
				compare_bigint = B_TRUE;
			} else {
				return (B_FALSE);
			}
			break;
		case CKA_PRIVATE_EXPONENT:
			/* only RSA private key has this attribute */
			if ((obj->key_type == CKK_RSA) &&
			    (obj->class == CKO_PRIVATE_KEY)) {
				bigint = OBJ_PRI_RSA_PRIEXPO(obj);
				compare_bigint = B_TRUE;
			} else {
				return (B_FALSE);
			}
			break;
		case CKA_PRIME_1:
			/* only RSA private key has this attribute */
			if ((obj->key_type == CKK_RSA) &&
			    (obj->class == CKO_PRIVATE_KEY)) {
				bigint = OBJ_PRI_RSA_PRIME1(obj);
				compare_bigint = B_TRUE;
			} else {
				return (B_FALSE);
			}
			break;
		case CKA_PRIME_2:
			/* only RSA private key has this attribute */
			if ((obj->key_type == CKK_RSA) &&
			    (obj->class == CKO_PRIVATE_KEY)) {
				bigint = OBJ_PRI_RSA_PRIME2(obj);
				compare_bigint = B_TRUE;
			} else {
				return (B_FALSE);
			}
			break;
		case CKA_EXPONENT_1:
			/* only RSA private key has this attribute */
			if ((obj->key_type == CKK_RSA) &&
			    (obj->class == CKO_PRIVATE_KEY)) {
				bigint = OBJ_PRI_RSA_EXPO1(obj);
				compare_bigint = B_TRUE;
			} else {
				return (B_FALSE);
			}
			break;
		case CKA_EXPONENT_2:
			/* only RSA private key has this attribute */
			if ((obj->key_type == CKK_RSA) &&
			    (obj->class == CKO_PRIVATE_KEY)) {
				bigint = OBJ_PRI_RSA_EXPO2(obj);
				compare_bigint = B_TRUE;
			} else {
				return (B_FALSE);
			}
			break;
		case CKA_COEFFICIENT:
			/* only RSA private key has this attribute */
			if ((obj->key_type == CKK_RSA) &&
			    (obj->class == CKO_PRIVATE_KEY)) {
				bigint = OBJ_PRI_RSA_COEF(obj);
				compare_bigint = B_TRUE;
			} else {
				return (B_FALSE);
			}
			break;
		case CKA_VALUE_BITS:
			return (B_FALSE);
		case CKA_PRIME:
			if (obj->class == CKO_PUBLIC_KEY) {
				switch (obj->key_type) {
				case CKK_DSA:
					bigint = OBJ_PUB_DSA_PRIME(obj);
					break;
				default:
					return (B_FALSE);
				}
			} else if (obj->class == CKO_PRIVATE_KEY) {
				switch (obj->key_type) {
				case CKK_DSA:
					bigint = OBJ_PRI_DSA_PRIME(obj);
					break;
				default:
					return (B_FALSE);
				}
			} else {
				return (B_FALSE);
			}
			compare_bigint = B_TRUE;
			break;
		case CKA_SUBPRIME:
			if (obj->class == CKO_PUBLIC_KEY) {
				switch (obj->key_type) {
				case CKK_DSA:
					bigint = OBJ_PUB_DSA_SUBPRIME(obj);
					break;
				default:
					return (B_FALSE);
				}
			} else if (obj->class == CKO_PRIVATE_KEY) {
				switch (obj->key_type) {
				case CKK_DSA:
					bigint = OBJ_PRI_DSA_SUBPRIME(obj);
					break;
				default:
					return (B_FALSE);
				}
			} else {
				return (B_FALSE);
			}
			compare_bigint = B_TRUE;
			break;
		case CKA_BASE:
			if (obj->class == CKO_PUBLIC_KEY) {
				switch (obj->key_type) {
				case CKK_DSA:
					bigint = OBJ_PUB_DSA_BASE(obj);
					break;
				default:
					return (B_FALSE);
				}
			} else if (obj->class == CKO_PRIVATE_KEY) {
				switch (obj->key_type) {
				case CKK_DSA:
					bigint = OBJ_PRI_DSA_BASE(obj);
					break;
				default:
					return (B_FALSE);
				}
			} else {
				return (B_FALSE);
			}
			compare_bigint = B_TRUE;
			break;
		case CKA_PRIME_BITS:
			return (B_FALSE);
		case CKA_SUBPRIME_BITS:
			return (B_FALSE);
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
		} else if (compare_bigint) {
			if (bigint == NULL) {
				return (B_FALSE);
			}
			if (tmpl_attr->ulValueLen != bigint->big_value_len) {
				return (B_FALSE);
			}
			if (memcmp(tmpl_attr->pValue, bigint->big_value,
			    tmpl_attr->ulValueLen) != 0) {
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
get_extra_attr(CK_ATTRIBUTE_TYPE type, kernel_object_t *obj)
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
