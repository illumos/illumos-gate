/*
 * COPYRIGHT (C) 2006,2007
 * THE REGENTS OF THE UNIVERSITY OF MICHIGAN
 * ALL RIGHTS RESERVED
 *
 * Permission is granted to use, copy, create derivative works
 * and redistribute this software and such derivative works
 * for any purpose, so long as the name of The University of
 * Michigan is not used in any advertising or publicity
 * pertaining to the use of distribution of this software
 * without specific, written prior authorization.  If the
 * above copyright notice or any other identification of the
 * University of Michigan is included in any copy of any
 * portion of this software, then the disclaimer below must
 * also be included.
 *
 * THIS SOFTWARE IS PROVIDED AS IS, WITHOUT REPRESENTATION
 * FROM THE UNIVERSITY OF MICHIGAN AS TO ITS FITNESS FOR ANY
 * PURPOSE, AND WITHOUT WARRANTY BY THE UNIVERSITY OF
 * MICHIGAN OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING
 * WITHOUT LIMITATION THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE
 * REGENTS OF THE UNIVERSITY OF MICHIGAN SHALL NOT BE LIABLE
 * FOR ANY DAMAGES, INCLUDING SPECIAL, INDIRECT, INCIDENTAL, OR
 * CONSEQUENTIAL DAMAGES, WITH RESPECT TO ANY CLAIM ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OF THE SOFTWARE, EVEN
 * IF IT HAS BEEN OR IS HEREAFTER ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGES.
 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012, OmniTI Computer Consulting, Inc. All rights reserved.
 * Copyright 2018 OmniOS Community Edition (OmniOSce) Association.
 * Copyright 2018 RackTop Systems.
 */

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <dirent.h>


/* Solaris Kerberos */
#include <libintl.h>
#include <assert.h>
#include <security/pam_appl.h>
#include <ctype.h>
#include "k5-int.h"
#include <ctype.h>

/*
 * Q: What is this SILLYDECRYPT stuff about?
 * A: When using the ActivCard Linux pkcs11 library (v2.0.1),
 *    the decrypt function fails.  By inserting an extra
 *    function call, which serves nothing but to change the
 *    stack, we were able to work around the issue.  If the
 *    ActivCard library is fixed in the future, this
 *    definition and related code can be removed.
 */
#define SILLYDECRYPT

#include "pkinit_crypto_openssl.h"

/*
 * Solaris Kerberos:
 * Changed to a switch statement so gettext() can be used
 * for internationization.
 * Use defined constants rather than raw numbers for error codes.
 */
static char *
pkcs11_error_table(short code) {
	switch (code) {
	    case CKR_OK:
		return (gettext("ok"));
	    case CKR_CANCEL:
		return (gettext("cancel"));
	    case CKR_HOST_MEMORY:
		return (gettext("host memory"));
	    case CKR_SLOT_ID_INVALID:
		return (gettext("slot id invalid"));
	    case CKR_GENERAL_ERROR:
		return (gettext("general error"));
	    case CKR_FUNCTION_FAILED:
		return (gettext("function failed"));
	    case CKR_ARGUMENTS_BAD:
		return (gettext("arguments bad"));
	    case CKR_NO_EVENT:
		return (gettext("no event"));
	    case CKR_NEED_TO_CREATE_THREADS:
		return (gettext("need to create threads"));
	    case CKR_CANT_LOCK:
		return (gettext("cant lock"));
	    case CKR_ATTRIBUTE_READ_ONLY:
		return (gettext("attribute read only"));
	    case CKR_ATTRIBUTE_SENSITIVE:
		return (gettext("attribute sensitive"));
	    case CKR_ATTRIBUTE_TYPE_INVALID:
		return (gettext("attribute type invalid"));
	    case CKR_ATTRIBUTE_VALUE_INVALID:
		return (gettext("attribute value invalid"));
	    case CKR_DATA_INVALID:
		return (gettext("data invalid"));
	    case CKR_DATA_LEN_RANGE:
		return (gettext("data len range"));
	    case CKR_DEVICE_ERROR:
		return (gettext("device error"));
	    case CKR_DEVICE_MEMORY:
		return (gettext("device memory"));
	    case CKR_DEVICE_REMOVED:
		return (gettext("device removed"));
	    case CKR_ENCRYPTED_DATA_INVALID:
		return (gettext("encrypted data invalid"));
	    case CKR_ENCRYPTED_DATA_LEN_RANGE:
		return (gettext("encrypted data len range"));
	    case CKR_FUNCTION_CANCELED:
		return (gettext("function canceled"));
	    case CKR_FUNCTION_NOT_PARALLEL:
		return (gettext("function not parallel"));
	    case CKR_FUNCTION_NOT_SUPPORTED:
		return (gettext("function not supported"));
	    case CKR_KEY_HANDLE_INVALID:
		return (gettext("key handle invalid"));
	    case CKR_KEY_SIZE_RANGE:
		return (gettext("key size range"));
	    case CKR_KEY_TYPE_INCONSISTENT:
		return (gettext("key type inconsistent"));
	    case CKR_KEY_NOT_NEEDED:
		return (gettext("key not needed"));
	    case CKR_KEY_CHANGED:
		return (gettext("key changed"));
	    case CKR_KEY_NEEDED:
		return (gettext("key needed"));
	    case CKR_KEY_INDIGESTIBLE:
		return (gettext("key indigestible"));
	    case CKR_KEY_FUNCTION_NOT_PERMITTED:
		return (gettext("key function not permitted"));
	    case CKR_KEY_NOT_WRAPPABLE:
		return (gettext("key not wrappable"));
	    case CKR_KEY_UNEXTRACTABLE:
		return (gettext("key unextractable"));
	    case CKR_MECHANISM_INVALID:
		return (gettext("mechanism invalid"));
	    case CKR_MECHANISM_PARAM_INVALID:
		return (gettext("mechanism param invalid"));
	    case CKR_OBJECT_HANDLE_INVALID:
		return (gettext("object handle invalid"));
	    case CKR_OPERATION_ACTIVE:
		return (gettext("operation active"));
	    case CKR_OPERATION_NOT_INITIALIZED:
		return (gettext("operation not initialized"));
	    case CKR_PIN_INCORRECT:
		return (gettext("pin incorrect"));
	    case CKR_PIN_INVALID:
		return (gettext("pin invalid"));
	    case CKR_PIN_LEN_RANGE:
		return (gettext("pin len range"));
	    case CKR_PIN_EXPIRED:
		return (gettext("pin expired"));
	    case CKR_PIN_LOCKED:
		return (gettext("pin locked"));
	    case CKR_SESSION_CLOSED:
		return (gettext("session closed"));
	    case CKR_SESSION_COUNT:
		return (gettext("session count"));
	    case CKR_SESSION_HANDLE_INVALID:
		return (gettext("session handle invalid"));
	    case CKR_SESSION_PARALLEL_NOT_SUPPORTED:
		return (gettext("session parallel not supported"));
	    case CKR_SESSION_READ_ONLY:
		return (gettext("session read only"));
	    case CKR_SESSION_EXISTS:
		return (gettext("session exists"));
	    case CKR_SESSION_READ_ONLY_EXISTS:
		return (gettext("session read only exists"));
	    case CKR_SESSION_READ_WRITE_SO_EXISTS:
		return (gettext("session read write so exists"));
	    case CKR_SIGNATURE_INVALID:
		return (gettext("signature invalid"));
	    case CKR_SIGNATURE_LEN_RANGE:
		return (gettext("signature len range"));
	    case CKR_TEMPLATE_INCOMPLETE:
		return (gettext("template incomplete"));
	    case CKR_TEMPLATE_INCONSISTENT:
		return (gettext("template inconsistent"));
	    case CKR_TOKEN_NOT_PRESENT:
		return (gettext("token not present"));
	    case CKR_TOKEN_NOT_RECOGNIZED:
		return (gettext("token not recognized"));
	    case CKR_TOKEN_WRITE_PROTECTED:
		return (gettext("token write protected"));
	    case CKR_UNWRAPPING_KEY_HANDLE_INVALID:
		return (gettext("unwrapping key handle invalid"));
	    case CKR_UNWRAPPING_KEY_SIZE_RANGE:
		return (gettext("unwrapping key size range"));
	    case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT:
		return (gettext("unwrapping key type inconsistent"));
	    case CKR_USER_ALREADY_LOGGED_IN:
		return (gettext("user already logged in"));
	    case CKR_USER_NOT_LOGGED_IN:
		return (gettext("user not logged in"));
	    case CKR_USER_PIN_NOT_INITIALIZED:
		return (gettext("user pin not initialized"));
	    case CKR_USER_TYPE_INVALID:
		return (gettext("user type invalid"));
	    case CKR_USER_ANOTHER_ALREADY_LOGGED_IN:
		return (gettext("user another already logged in"));
	    case CKR_USER_TOO_MANY_TYPES:
		return (gettext("user too many types"));
	    case CKR_WRAPPED_KEY_INVALID:
		return (gettext("wrapped key invalid"));
	    case CKR_WRAPPED_KEY_LEN_RANGE:
		return (gettext("wrapped key len range"));
	    case CKR_WRAPPING_KEY_HANDLE_INVALID:
		return (gettext("wrapping key handle invalid"));
	    case CKR_WRAPPING_KEY_SIZE_RANGE:
		return (gettext("wrapping key size range"));
	    case CKR_WRAPPING_KEY_TYPE_INCONSISTENT:
		return (gettext("wrapping key type inconsistent"));
	    case CKR_RANDOM_SEED_NOT_SUPPORTED:
		return (gettext("random seed not supported"));
	    case CKR_RANDOM_NO_RNG:
		return (gettext("random no rng"));
	    case CKR_DOMAIN_PARAMS_INVALID:
		return (gettext("domain params invalid"));
	    case CKR_BUFFER_TOO_SMALL:
		return (gettext("buffer too small"));
	    case CKR_SAVED_STATE_INVALID:
		return (gettext("saved state invalid"));
	    case CKR_INFORMATION_SENSITIVE:
		return (gettext("information sensitive"));
	    case CKR_STATE_UNSAVEABLE:
		return (gettext("state unsaveable"));
	    case CKR_CRYPTOKI_NOT_INITIALIZED:
		return (gettext("cryptoki not initialized"));
	    case CKR_CRYPTOKI_ALREADY_INITIALIZED:
		return (gettext("cryptoki already initialized"));
	    case CKR_MUTEX_BAD:
		return (gettext("mutex bad"));
	    case CKR_MUTEX_NOT_LOCKED:
		return (gettext("mutex not locked"));
	    case CKR_FUNCTION_REJECTED:
		return (gettext("function rejected"));
	    default:
		return (gettext("unknown error"));
	}
}

/* DH parameters */
unsigned char pkinit_1024_dhprime[128] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
    0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
    0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
    0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
    0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

unsigned char pkinit_2048_dhprime[2048/8] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
    0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
    0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
    0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
    0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
    0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
    0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A,
    0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96,
    0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
    0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
    0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
    0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C,
    0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
    0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03,
    0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
    0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
    0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
    0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5,
    0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
    0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

unsigned char pkinit_4096_dhprime[4096/8] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
    0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
    0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
    0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
    0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
    0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
    0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A,
    0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96,
    0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
    0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
    0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
    0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C,
    0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
    0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03,
    0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
    0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
    0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
    0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5,
    0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
    0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D,
    0xAD, 0x33, 0x17, 0x0D, 0x04, 0x50, 0x7A, 0x33,
    0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64,
    0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB, 0xEF, 0x0A,
    0x8A, 0xEA, 0x71, 0x57, 0x5D, 0x06, 0x0C, 0x7D,
    0xB3, 0x97, 0x0F, 0x85, 0xA6, 0xE1, 0xE4, 0xC7,
    0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7,
    0x1E, 0x8C, 0x94, 0xE0, 0x4A, 0x25, 0x61, 0x9D,
    0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B,
    0xF1, 0x2F, 0xFA, 0x06, 0xD9, 0x8A, 0x08, 0x64,
    0xD8, 0x76, 0x02, 0x73, 0x3E, 0xC8, 0x6A, 0x64,
    0x52, 0x1F, 0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C,
    0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C,
    0x77, 0x09, 0x88, 0xC0, 0xBA, 0xD9, 0x46, 0xE2,
    0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31,
    0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E,
    0x4B, 0x82, 0xD1, 0x20, 0xA9, 0x21, 0x08, 0x01,
    0x1A, 0x72, 0x3C, 0x12, 0xA7, 0x87, 0xE6, 0xD7,
    0x88, 0x71, 0x9A, 0x10, 0xBD, 0xBA, 0x5B, 0x26,
    0x99, 0xC3, 0x27, 0x18, 0x6A, 0xF4, 0xE2, 0x3C,
    0x1A, 0x94, 0x68, 0x34, 0xB6, 0x15, 0x0B, 0xDA,
    0x25, 0x83, 0xE9, 0xCA, 0x2A, 0xD4, 0x4C, 0xE8,
    0xDB, 0xBB, 0xC2, 0xDB, 0x04, 0xDE, 0x8E, 0xF9,
    0x2E, 0x8E, 0xFC, 0x14, 0x1F, 0xBE, 0xCA, 0xA6,
    0x28, 0x7C, 0x59, 0x47, 0x4E, 0x6B, 0xC0, 0x5D,
    0x99, 0xB2, 0x96, 0x4F, 0xA0, 0x90, 0xC3, 0xA2,
    0x23, 0x3B, 0xA1, 0x86, 0x51, 0x5B, 0xE7, 0xED,
    0x1F, 0x61, 0x29, 0x70, 0xCE, 0xE2, 0xD7, 0xAF,
    0xB8, 0x1B, 0xDD, 0x76, 0x21, 0x70, 0x48, 0x1C,
    0xD0, 0x06, 0x91, 0x27, 0xD5, 0xB0, 0x5A, 0xA9,
    0x93, 0xB4, 0xEA, 0x98, 0x8D, 0x8F, 0xDD, 0xC1,
    0x86, 0xFF, 0xB7, 0xDC, 0x90, 0xA6, 0xC0, 0x8F,
    0x4D, 0xF4, 0x35, 0xC9, 0x34, 0x06, 0x31, 0x99,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
/*
 * Many things have changed in OpenSSL 1.1. The code in this file has been
 * updated to use the v1.1 APIs but some are new and require emulation
 * for older OpenSSL versions.
 */

/* EVP_MD_CTX construct and destructor names have changed */

#define EVP_MD_CTX_new EVP_MD_CTX_create
#define EVP_MD_CTX_free EVP_MD_CTX_destroy

/* ASN1_STRING_data is deprecated */
#define ASN1_STRING_get0_data ASN1_STRING_data

/* X509_STORE_CTX_trusted_stack is deprecated */
#define X509_STORE_CTX_set0_trusted_stack X509_STORE_CTX_trusted_stack

/* get_rfc2409_prime_1024() has been renamed. */
#define BN_get_rfc2409_prime_1024 get_rfc2409_prime_1024

#define OBJ_get0_data(o) ((o)->data)
#define OBJ_length(o) ((o)->length)

/* Some new DH functions that aren't in OpenSSL 1.0.x */
#define DH_bits(dh) BN_num_bits((dh)->p);

#define DH_set0_pqg(dh, p, q, g) __DH_set0_pqg(dh, p, q, g)
static int
__DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
    if ((dh->p == NULL && p == NULL) || (dh->g == NULL && g == NULL))
        return 0;

    if (p != NULL) {
        BN_free(dh->p);
        dh->p = p;
    }
    if (q != NULL) {
        BN_free(dh->q);
        dh->q = q;
    }
    if (g != NULL) {
        BN_free(dh->g);
        dh->g = g;
    }

    if (q != NULL) {
        dh->length = BN_num_bits(q);
    }

    return 1;
}

#define DH_get0_pqg(dh, p, q, g) __DH_get0_pqg(dh, p, q, g)
static void
__DH_get0_pqg(const DH *dh, const BIGNUM **p, const BIGNUM **q,
    const BIGNUM **g)
{
    if (p != NULL)
        *p = dh->p;
    if (q != NULL)
        *q = dh->q;
    if (g != NULL)
        *g = dh->g;
}

#define DH_set0_key(dh, pub, priv) __DH_set0_key(dh, pub, priv)
static int
__DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key)
{
    if (pub_key != NULL) {
        BN_free(dh->pub_key);
        dh->pub_key = pub_key;
    }
    if (priv_key != NULL) {
        BN_free(dh->priv_key);
        dh->priv_key = priv_key;
    }

    return 1;
}

#define DH_get0_key(dh, pub, priv) __DH_get0_key(dh, pub, priv)
static void
__DH_get0_key(const DH *dh, const BIGNUM **pub, const BIGNUM **priv)
{
    if (pub != NULL)
        *pub = dh->pub_key;
    if (priv != NULL)
        *priv = dh->priv_key;
}

#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L || LIBRESSL_VERSION_NUMBER */

krb5_error_code
pkinit_init_plg_crypto(pkinit_plg_crypto_context *cryptoctx) {

    krb5_error_code retval = ENOMEM;
    pkinit_plg_crypto_context ctx = NULL;

    /* initialize openssl routines */
    /* Solaris Kerberos */
    retval = openssl_init();
    if (retval != 0)
	goto out;

    ctx = (pkinit_plg_crypto_context)malloc(sizeof(*ctx));
    if (ctx == NULL)
	goto out;
    (void) memset(ctx, 0, sizeof(*ctx));

    pkiDebug("%s: initializing openssl crypto context at %p\n",
	     __FUNCTION__, ctx);
    retval = pkinit_init_pkinit_oids(ctx);
    if (retval)
	goto out;

    retval = pkinit_init_dh_params(ctx);
    if (retval)
	goto out;

    *cryptoctx = ctx;

out:
    if (retval && ctx != NULL)
	    pkinit_fini_plg_crypto(ctx);

    return retval;
}

void
pkinit_fini_plg_crypto(pkinit_plg_crypto_context cryptoctx)
{
    pkiDebug("%s: freeing context at %p\n", __FUNCTION__, cryptoctx);

    if (cryptoctx == NULL)
	return;
    pkinit_fini_pkinit_oids(cryptoctx);
    pkinit_fini_dh_params(cryptoctx);
    free(cryptoctx);
}

krb5_error_code
pkinit_init_identity_crypto(pkinit_identity_crypto_context *idctx)
{
    krb5_error_code retval = ENOMEM;
    pkinit_identity_crypto_context ctx = NULL;

    ctx = (pkinit_identity_crypto_context)malloc(sizeof(*ctx));
    if (ctx == NULL)
	goto out;
    (void) memset(ctx, 0, sizeof(*ctx));

    retval = pkinit_init_certs(ctx);
    if (retval)
	goto out;

    retval = pkinit_init_pkcs11(ctx);
    if (retval)
	goto out;

    pkiDebug("%s: returning ctx at %p\n", __FUNCTION__, ctx);
    *idctx = ctx;

out:
    if (retval) {
	if (ctx)
	    pkinit_fini_identity_crypto(ctx);
    }

    return retval;
}

void
pkinit_fini_identity_crypto(pkinit_identity_crypto_context idctx)
{
    if (idctx == NULL)
	return;

    pkiDebug("%s: freeing   ctx at %p\n", __FUNCTION__, idctx);
    pkinit_fini_certs(idctx);
    pkinit_fini_pkcs11(idctx);
    free(idctx);
}

krb5_error_code
pkinit_init_req_crypto(pkinit_req_crypto_context *cryptoctx)
{

    pkinit_req_crypto_context ctx = NULL;

    /* Solaris Kerberos */
    if (cryptoctx == NULL)
	return EINVAL;

    ctx = (pkinit_req_crypto_context)malloc(sizeof(*ctx));
    if (ctx == NULL)
	return ENOMEM;
    (void) memset(ctx, 0, sizeof(*ctx));

    ctx->dh = NULL;
    ctx->received_cert = NULL;

    *cryptoctx = ctx;

    pkiDebug("%s: returning ctx at %p\n", __FUNCTION__, ctx);

    return 0;
}

void
pkinit_fini_req_crypto(pkinit_req_crypto_context req_cryptoctx)
{
    if (req_cryptoctx == NULL)
	return;

    pkiDebug("%s: freeing   ctx at %p\n", __FUNCTION__, req_cryptoctx);
    if (req_cryptoctx->dh != NULL)
      DH_free(req_cryptoctx->dh);
    if (req_cryptoctx->received_cert != NULL)
      X509_free(req_cryptoctx->received_cert);

    free(req_cryptoctx);
}

static krb5_error_code
pkinit_init_pkinit_oids(pkinit_plg_crypto_context ctx)
{
    ctx->id_pkinit_san = OBJ_txt2obj("1.3.6.1.5.2.2", 1);
    if (ctx->id_pkinit_san == NULL)
        return ENOMEM;

    ctx->id_pkinit_authData = OBJ_txt2obj("1.3.6.1.5.2.3.1", 1);
    if (ctx->id_pkinit_authData == NULL)
        return ENOMEM;

    ctx->id_pkinit_DHKeyData = OBJ_txt2obj("1.3.6.1.5.2.3.2", 1);
    if (ctx->id_pkinit_DHKeyData == NULL)
        return ENOMEM;

    ctx->id_pkinit_rkeyData = OBJ_txt2obj("1.3.6.1.5.2.3.3", 1);
    if (ctx->id_pkinit_rkeyData == NULL)
        return ENOMEM;

    ctx->id_pkinit_KPClientAuth = OBJ_txt2obj("1.3.6.1.5.2.3.4", 1);
    if (ctx->id_pkinit_KPClientAuth == NULL)
        return ENOMEM;

    ctx->id_pkinit_KPKdc = OBJ_txt2obj("1.3.6.1.5.2.3.5", 1);
    if (ctx->id_pkinit_KPKdc == NULL)
        return ENOMEM;

    ctx->id_ms_kp_sc_logon = OBJ_txt2obj("1.3.6.1.4.1.311.20.2.2", 1);
    if (ctx->id_ms_kp_sc_logon == NULL)
        return ENOMEM;

    ctx->id_ms_san_upn = OBJ_txt2obj("1.3.6.1.4.1.311.20.2.3", 1);
    if (ctx->id_ms_san_upn == NULL)
        return ENOMEM;

    ctx->id_kp_serverAuth = OBJ_txt2obj("1.3.6.1.5.5.7.3.1", 1);
    if (ctx->id_kp_serverAuth == NULL)
        return ENOMEM;

    return 0;
}

static krb5_error_code
get_cert(char *filename, X509 **retcert)
{
    X509 *cert = NULL;
    BIO *tmp = NULL;
    int code;
    krb5_error_code retval;

    if (filename == NULL || retcert == NULL)
	return EINVAL;

    *retcert = NULL;

    tmp = BIO_new(BIO_s_file());
    if (tmp == NULL)
	return ENOMEM;

    code = BIO_read_filename(tmp, filename);
    if (code == 0) {
	retval = errno;
	goto cleanup;
    }

    cert = (X509 *) PEM_read_bio_X509(tmp, NULL, NULL, NULL);
    if (cert == NULL) {
	retval = EIO;
	pkiDebug("failed to read certificate from %s\n", filename);
	goto cleanup;
    }
    *retcert = cert;
    retval = 0;
cleanup:
    if (tmp != NULL)
	BIO_free(tmp);
    return retval;
}

static krb5_error_code
get_key(char *filename, EVP_PKEY **retkey)
{
    EVP_PKEY *pkey = NULL;
    BIO *tmp = NULL;
    int code;
    krb5_error_code retval;

    if (filename == NULL || retkey == NULL)
	return EINVAL;

    tmp = BIO_new(BIO_s_file());
    if (tmp == NULL)
	return ENOMEM;

    code = BIO_read_filename(tmp, filename);
    if (code == 0) {
	retval = errno;
	goto cleanup;
    }
    pkey = (EVP_PKEY *) PEM_read_bio_PrivateKey(tmp, NULL, NULL, NULL);
    if (pkey == NULL) {
	retval = EIO;
	pkiDebug("failed to read private key from %s\n", filename);
	goto cleanup;
    }
    *retkey = pkey;
    retval = 0;
cleanup:
    if (tmp != NULL)
	BIO_free(tmp);
    return retval;
}

static void
pkinit_fini_pkinit_oids(pkinit_plg_crypto_context ctx)
{
    if (ctx == NULL)
	return;
    ASN1_OBJECT_free(ctx->id_pkinit_san);
    ASN1_OBJECT_free(ctx->id_pkinit_authData);
    ASN1_OBJECT_free(ctx->id_pkinit_DHKeyData);
    ASN1_OBJECT_free(ctx->id_pkinit_rkeyData);
    ASN1_OBJECT_free(ctx->id_pkinit_KPClientAuth);
    ASN1_OBJECT_free(ctx->id_pkinit_KPKdc);
    ASN1_OBJECT_free(ctx->id_ms_kp_sc_logon);
    ASN1_OBJECT_free(ctx->id_ms_san_upn);
    ASN1_OBJECT_free(ctx->id_kp_serverAuth);
}

static DH *
make_dhprime(uint8_t *prime, size_t len)
{
    DH *dh = NULL;
    BIGNUM *p = NULL, *q = NULL, *g = NULL;

    if ((p = BN_bin2bn(prime, len, NULL)) == NULL)
	goto cleanup;
    if ((q = BN_new()) == NULL)
	goto cleanup;
    if (!BN_rshift1(q, p))
	goto cleanup;
    if ((g = BN_new()) == NULL)
	goto cleanup;
    if (!BN_set_word(g, DH_GENERATOR_2))
	goto cleanup;

    dh = DH_new();
    if (dh == NULL)
	goto cleanup;
    DH_set0_pqg(dh, p, q, g);
    p = g = q = NULL;

cleanup:
    BN_free(p);
    BN_free(q);
    BN_free(g);
    return dh;
}

static krb5_error_code
pkinit_init_dh_params(pkinit_plg_crypto_context plgctx)
{
    krb5_error_code retval = ENOMEM;

    plgctx->dh_1024 = make_dhprime(pkinit_1024_dhprime,
        sizeof(pkinit_1024_dhprime));
    if (plgctx->dh_1024 == NULL)
	goto cleanup;

    plgctx->dh_2048 = make_dhprime(pkinit_2048_dhprime,
        sizeof(pkinit_2048_dhprime));
    if (plgctx->dh_2048 == NULL)
	goto cleanup;

    plgctx->dh_4096 = make_dhprime(pkinit_4096_dhprime,
        sizeof(pkinit_4096_dhprime));
    if (plgctx->dh_4096 == NULL)
	goto cleanup;

    retval = 0;

cleanup:
    if (retval)
	pkinit_fini_dh_params(plgctx);

    return retval;
}

static void
pkinit_fini_dh_params(pkinit_plg_crypto_context plgctx)
{
    if (plgctx->dh_1024 != NULL)
	DH_free(plgctx->dh_1024);
    if (plgctx->dh_2048 != NULL)
	DH_free(plgctx->dh_2048);
    if (plgctx->dh_4096 != NULL)
	DH_free(plgctx->dh_4096);

    plgctx->dh_1024 = plgctx->dh_2048 = plgctx->dh_4096 = NULL;
}

static krb5_error_code
pkinit_init_certs(pkinit_identity_crypto_context ctx)
{
    /* Solaris Kerberos */
    int i;

    for (i = 0; i < MAX_CREDS_ALLOWED; i++)
	ctx->creds[i] = NULL;
    ctx->my_certs = NULL;
    ctx->cert_index = 0;
    ctx->my_key = NULL;
    ctx->trustedCAs = NULL;
    ctx->intermediateCAs = NULL;
    ctx->revoked = NULL;

    return 0;
}

static void
pkinit_fini_certs(pkinit_identity_crypto_context ctx)
{
    if (ctx == NULL)
	return;

    if (ctx->my_certs != NULL)
	sk_X509_pop_free(ctx->my_certs, X509_free);

    if (ctx->my_key != NULL)
	EVP_PKEY_free(ctx->my_key);

    if (ctx->trustedCAs != NULL)
	sk_X509_pop_free(ctx->trustedCAs, X509_free);

    if (ctx->intermediateCAs != NULL)
	sk_X509_pop_free(ctx->intermediateCAs, X509_free);

    if (ctx->revoked != NULL)
	sk_X509_CRL_pop_free(ctx->revoked, X509_CRL_free);
}

static krb5_error_code
pkinit_init_pkcs11(pkinit_identity_crypto_context ctx)
{
    /* Solaris Kerberos */

#ifndef WITHOUT_PKCS11
    ctx->p11_module_name = strdup(PKCS11_MODNAME);
    if (ctx->p11_module_name == NULL)
	return ENOMEM;
    ctx->p11_module = NULL;
    ctx->slotid = PK_NOSLOT;
    ctx->token_label = NULL;
    ctx->cert_label = NULL;
    ctx->PIN = NULL;
    ctx->session = CK_INVALID_HANDLE;
    ctx->p11 = NULL;
    ctx->p11flags = 0; /* Solaris Kerberos */
#endif
    ctx->pkcs11_method = 0;
    (void) memset(ctx->creds, 0, sizeof(ctx->creds));

    return 0;
}

static void
pkinit_fini_pkcs11(pkinit_identity_crypto_context ctx)
{
#ifndef WITHOUT_PKCS11
    if (ctx == NULL)
	return;

    if (ctx->p11 != NULL) {
	if (ctx->session != CK_INVALID_HANDLE) {
	    ctx->p11->C_CloseSession(ctx->session);
	    ctx->session = CK_INVALID_HANDLE;
	}
	/*
	 * Solaris Kerberos:
	 * Only call C_Finalize if the process was not already using pkcs11.
	 */
	if (ctx->finalize_pkcs11 == TRUE)
	    ctx->p11->C_Finalize(NULL_PTR);

	ctx->p11 = NULL;
    }
    if (ctx->p11_module != NULL) {
	pkinit_C_UnloadModule(ctx->p11_module);
	ctx->p11_module = NULL;
    }
    if (ctx->p11_module_name != NULL)
	free(ctx->p11_module_name);
    if (ctx->token_label != NULL)
	free(ctx->token_label);
    if (ctx->cert_id != NULL)
	free(ctx->cert_id);
    if (ctx->cert_label != NULL)
	free(ctx->cert_label);
    if (ctx->PIN != NULL) {
	(void) memset(ctx->PIN, 0, strlen(ctx->PIN));
	free(ctx->PIN);
    }
#endif
}

krb5_error_code
pkinit_identity_set_prompter(pkinit_identity_crypto_context id_cryptoctx,
			     krb5_prompter_fct prompter,
			     void *prompter_data)
{
    id_cryptoctx->prompter = prompter;
    id_cryptoctx->prompter_data = prompter_data;

    return 0;
}

/* Create a CMS ContentInfo of type oid containing the octet string in data. */
static krb5_error_code
create_contentinfo(krb5_context context,
		   ASN1_OBJECT *oid,
		   unsigned char *data,
		   size_t data_len,
		   PKCS7 **p7_out)
{
    PKCS7 *p7 = NULL;
    ASN1_OCTET_STRING *ostr = NULL;

    *p7_out = NULL;

    ostr = ASN1_OCTET_STRING_new();
    if (ostr == NULL)
        goto oom;
    if (!ASN1_OCTET_STRING_set(ostr, (unsigned char *)data, data_len))
        goto oom;

    p7 = PKCS7_new();
    if (p7 == NULL)
        goto oom;
    p7->type = OBJ_dup(oid);
    if (p7->type == NULL)
        goto oom;

    if (OBJ_obj2nid(oid) == NID_pkcs7_data) {
        /* Draft 9 uses id-pkcs7-data for signed data.  For this type OpenSSL
         * expects an octet string in d.data. */
        p7->d.data = ostr;
    } else {
        p7->d.other = ASN1_TYPE_new();
        if (p7->d.other == NULL)
            goto oom;
        p7->d.other->type = V_ASN1_OCTET_STRING;
        p7->d.other->value.octet_string = ostr;
    }

    *p7_out = p7;
    return 0;

oom:
    if (ostr != NULL)
        ASN1_OCTET_STRING_free(ostr);
    if (p7 != NULL)
        PKCS7_free(p7);
    return ENOMEM;
}

/* ARGSUSED */
krb5_error_code
cms_signeddata_create(krb5_context context,
		      pkinit_plg_crypto_context plg_cryptoctx,
		      pkinit_req_crypto_context req_cryptoctx,
		      pkinit_identity_crypto_context id_cryptoctx,
		      int cms_msg_type,
		      int include_certchain,
		      unsigned char *data,
		      unsigned int data_len,
		      unsigned char **signed_data,
		      unsigned int *signed_data_len)
{
    /* Solaris Kerberos */
    krb5_error_code retval = KRB5KRB_ERR_GENERIC;
    PKCS7  *p7 = NULL, *inner_p7 = NULL;
    PKCS7_SIGNED *p7s = NULL;
    PKCS7_SIGNER_INFO *p7si = NULL;
    unsigned char *p;
    STACK_OF(X509) * cert_stack = NULL;
    ASN1_OCTET_STRING *digest_attr = NULL;
    EVP_MD_CTX *ctx = NULL, *ctx2 = NULL;
    const EVP_MD *md_tmp = NULL;
    unsigned char md_data[EVP_MAX_MD_SIZE], md_data2[EVP_MAX_MD_SIZE];
    unsigned char *digestInfo_buf = NULL, *abuf = NULL;
    unsigned int md_len, md_len2, alen, digestInfo_len;
    STACK_OF(X509_ATTRIBUTE) * sk;
    unsigned char *sig = NULL;
    unsigned int sig_len = 0;
    X509_ALGOR *alg = NULL;
    ASN1_OCTET_STRING *digest = NULL;
    unsigned int alg_len = 0, digest_len = 0;
    unsigned char *y = NULL, *alg_buf = NULL, *digest_buf = NULL;
    X509 *cert = NULL;
    ASN1_OBJECT *oid = NULL, *oid_copy;

    /* Solaris Kerberos */
    if (signed_data == NULL)
	return EINVAL;

    if (signed_data_len == NULL)
	return EINVAL;

    /* start creating PKCS7 data */
    if ((p7 = PKCS7_new()) == NULL)
	goto cleanup;
    p7->type = OBJ_nid2obj(NID_pkcs7_signed);

    if ((p7s = PKCS7_SIGNED_new()) == NULL)
	goto cleanup;
    p7->d.sign = p7s;
    if (!ASN1_INTEGER_set(p7s->version, 3))
	goto cleanup;

    /* create a cert chain that has at least the signer's certificate */
    if ((cert_stack = sk_X509_new_null()) == NULL)
	goto cleanup;

    cert = sk_X509_value(id_cryptoctx->my_certs, id_cryptoctx->cert_index);
    if (!include_certchain) {
	pkiDebug("only including signer's certificate\n");
	sk_X509_push(cert_stack, X509_dup(cert));
    } else {
	/* create a cert chain */
	X509_STORE *certstore = NULL;
	X509_STORE_CTX *certctx;
	STACK_OF(X509) *certstack = NULL;
	char buf[DN_BUF_LEN];
	int i = 0, size = 0;

	if ((certstore = X509_STORE_new()) == NULL)
	    goto cleanup;
	if ((certctx = X509_STORE_CTX_new()) == NULL)
	    goto cleanup;
	pkiDebug("building certificate chain\n");
	X509_STORE_set_verify_cb(certstore, openssl_callback);
	X509_STORE_CTX_init(certctx, certstore, cert,
			    id_cryptoctx->intermediateCAs);
	X509_STORE_CTX_set0_trusted_stack(certctx, id_cryptoctx->trustedCAs);
	/* Solaris Kerberos */
	if (X509_verify_cert(certctx) <= 0) {
	    pkiDebug("failed to create a certificate chain: %s\n",
	    X509_verify_cert_error_string(X509_STORE_CTX_get_error(certctx)));
	    if (!sk_X509_num(id_cryptoctx->trustedCAs))
		pkiDebug("No trusted CAs found. Check your X509_anchors\n");
	    goto cleanup;
	}
	certstack = X509_STORE_CTX_get1_chain(certctx);
	size = sk_X509_num(certstack);
	pkiDebug("size of certificate chain = %d\n", size);
	for(i = 0; i < size - 1; i++) {
	    X509 *x = sk_X509_value(certstack, i);
	    X509_NAME_oneline(X509_get_subject_name(x), buf, sizeof(buf));
	    pkiDebug("cert #%d: %s\n", i, buf);
	    sk_X509_push(cert_stack, X509_dup(x));
	}
	X509_STORE_CTX_free(certctx);
	X509_STORE_free(certstore);
	sk_X509_pop_free(certstack, X509_free);
    }
    p7s->cert = cert_stack;

    /* fill-in PKCS7_SIGNER_INFO */
    if ((p7si = PKCS7_SIGNER_INFO_new()) == NULL)
	goto cleanup;
    if (!ASN1_INTEGER_set(p7si->version, 1))
	goto cleanup;
    if (!X509_NAME_set(&p7si->issuer_and_serial->issuer,
		       X509_get_issuer_name(cert)))
	goto cleanup;
    /* because ASN1_INTEGER_set is used to set a 'long' we will do
     * things the ugly way. */
    ASN1_INTEGER_free(p7si->issuer_and_serial->serial);
    if (!(p7si->issuer_and_serial->serial =
	  ASN1_INTEGER_dup(X509_get_serialNumber(cert))))
	goto cleanup;

    /* will not fill-out EVP_PKEY because it's on the smartcard */

    /* Set digest algs */
    p7si->digest_alg->algorithm = OBJ_nid2obj(NID_sha1);

    if (p7si->digest_alg->parameter != NULL)
	ASN1_TYPE_free(p7si->digest_alg->parameter);
    if ((p7si->digest_alg->parameter = ASN1_TYPE_new()) == NULL)
	goto cleanup;
    p7si->digest_alg->parameter->type = V_ASN1_NULL;

    /* Set sig algs */
    if (p7si->digest_enc_alg->parameter != NULL)
	ASN1_TYPE_free(p7si->digest_enc_alg->parameter);
    p7si->digest_enc_alg->algorithm = OBJ_nid2obj(NID_sha1WithRSAEncryption);
    if (!(p7si->digest_enc_alg->parameter = ASN1_TYPE_new()))
	goto cleanup;
    p7si->digest_enc_alg->parameter->type = V_ASN1_NULL;

    /* pick the correct oid for the eContentInfo */
    oid = pkinit_pkcs7type2oid(plg_cryptoctx, cms_msg_type);
    if (oid == NULL)
	goto cleanup;

    if (cms_msg_type == CMS_SIGN_DRAFT9) {
	/* don't include signed attributes for pa-type 15 request */
	abuf = data;
	alen = data_len;
    } else {
	/* add signed attributes */
	/* compute sha1 digest over the EncapsulatedContentInfo */
	ctx = EVP_MD_CTX_new();
	if (ctx == NULL)
	    goto cleanup2;
	EVP_MD_CTX_init(ctx);
	EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
	EVP_DigestUpdate(ctx, data, data_len);
	md_tmp = EVP_MD_CTX_md(ctx);
	EVP_DigestFinal_ex(ctx, md_data, &md_len);
	EVP_MD_CTX_free(ctx);
	ctx = NULL;

	/* create a message digest attr */
	digest_attr = ASN1_OCTET_STRING_new();
	ASN1_OCTET_STRING_set(digest_attr, md_data, (int)md_len);
	PKCS7_add_signed_attribute(p7si, NID_pkcs9_messageDigest,
				   V_ASN1_OCTET_STRING, (char *) digest_attr);

	/* create a content-type attr */
	oid_copy = OBJ_dup(oid);
	if (oid_copy == NULL)
		goto cleanup2;
	PKCS7_add_signed_attribute(p7si, NID_pkcs9_contentType,
				   V_ASN1_OBJECT, oid_copy);

	/* create the signature over signed attributes. get DER encoded value */
	/* This is the place where smartcard signature needs to be calculated */
	sk = p7si->auth_attr;
	alen = ASN1_item_i2d((ASN1_VALUE *) sk, &abuf,
			     ASN1_ITEM_rptr(PKCS7_ATTR_SIGN));
	if (abuf == NULL)
	    goto cleanup2;
    }

#ifndef WITHOUT_PKCS11
    /* Some tokens can only do RSAEncryption without sha1 hash */
    /* to compute sha1WithRSAEncryption, encode the algorithm ID for the hash
     * function and the hash value into an ASN.1 value of type DigestInfo
     * DigestInfo::=SEQUENCE {
     *	digestAlgorithm  AlgorithmIdentifier,
     *	digest OCTET STRING }
     */
    if (id_cryptoctx->pkcs11_method == 1 &&
	    id_cryptoctx->mech == CKM_RSA_PKCS) {
	pkiDebug("mech = CKM_RSA_PKCS\n");
	ctx2 = EVP_MD_CTX_new();
	if (ctx2 == NULL)
	    goto cleanup2;
	EVP_MD_CTX_init(ctx2);
	/* if this is not draft9 request, include digest signed attribute */
	if (cms_msg_type != CMS_SIGN_DRAFT9)
	    EVP_DigestInit_ex(ctx2, md_tmp, NULL);
	else
	    EVP_DigestInit_ex(ctx2, EVP_sha1(), NULL);
	EVP_DigestUpdate(ctx2, abuf, alen);
	EVP_DigestFinal_ex(ctx2, md_data2, &md_len2);
	EVP_MD_CTX_free(ctx2);
	ctx2 = NULL;

	alg = X509_ALGOR_new();
	if (alg == NULL)
	    goto cleanup2;
	alg->algorithm = OBJ_nid2obj(NID_sha1);
	alg->parameter = NULL;
	alg_len = i2d_X509_ALGOR(alg, NULL);
	alg_buf = (unsigned char *)malloc(alg_len);
	if (alg_buf == NULL)
	    goto cleanup2;

	digest = ASN1_OCTET_STRING_new();
	if (digest == NULL)
	    goto cleanup2;
	ASN1_OCTET_STRING_set(digest, md_data2, (int)md_len2);
	digest_len = i2d_ASN1_OCTET_STRING(digest, NULL);
	digest_buf = (unsigned char *)malloc(digest_len);
	if (digest_buf == NULL)
	    goto cleanup2;

	digestInfo_len = ASN1_object_size(1, (int)(alg_len + digest_len),
					  V_ASN1_SEQUENCE);
	y = digestInfo_buf = (unsigned char *)malloc(digestInfo_len);
	if (digestInfo_buf == NULL)
	    goto cleanup2;
	ASN1_put_object(&y, 1, (int)(alg_len + digest_len), V_ASN1_SEQUENCE,
			V_ASN1_UNIVERSAL);
	i2d_X509_ALGOR(alg, &y);
	i2d_ASN1_OCTET_STRING(digest, &y);
#ifdef DEBUG_SIG
	pkiDebug("signing buffer\n");
	print_buffer(digestInfo_buf, digestInfo_len);
	print_buffer_bin(digestInfo_buf, digestInfo_len, "/tmp/pkcs7_tosign");
#endif
	retval = pkinit_sign_data(context, id_cryptoctx, digestInfo_buf,
				  digestInfo_len, &sig, &sig_len);
    } else
#endif
    {
	pkiDebug("mech = %s\n",
	    id_cryptoctx->pkcs11_method == 1 ? "CKM_SHA1_RSA_PKCS" : "FS");
	retval = pkinit_sign_data(context, id_cryptoctx, abuf, alen,
				  &sig, &sig_len);
    }
#ifdef DEBUG_SIG
    print_buffer(sig, sig_len);
#endif
    if (cms_msg_type != CMS_SIGN_DRAFT9)
	free(abuf);
    if (retval)
	goto cleanup2;

    /* Add signature */
    if (!ASN1_STRING_set(p7si->enc_digest, (unsigned char *) sig,
			 (int)sig_len)) {
	unsigned long err = ERR_peek_error();
	retval = KRB5KDC_ERR_PREAUTH_FAILED;
	krb5_set_error_message(context, retval, "%s\n",
			       ERR_error_string(err, NULL));
	pkiDebug("failed to add a signed digest attribute\n");
	goto cleanup2;
    }
    /* adder signer_info to pkcs7 signed */
    if (!PKCS7_add_signer(p7, p7si))
	goto cleanup2;

    /* start on adding data to the pkcs7 signed */
    retval = create_contentinfo(context, oid, data, data_len, &inner_p7);
    if (p7s->contents != NULL)
	PKCS7_free(p7s->contents);
    p7s->contents = inner_p7;

    *signed_data_len = i2d_PKCS7(p7, NULL);
    if (!(*signed_data_len)) {
	unsigned long err = ERR_peek_error();
	retval = KRB5KDC_ERR_PREAUTH_FAILED;
	krb5_set_error_message(context, retval, "%s\n",
			       ERR_error_string(err, NULL));
	pkiDebug("failed to der encode pkcs7\n");
	goto cleanup2;
    }
    if ((p = *signed_data =
	 (unsigned char *) malloc((size_t)*signed_data_len)) == NULL)
	goto cleanup2;

    /* DER encode PKCS7 data */
    retval = i2d_PKCS7(p7, &p);
    if (!retval) {
	unsigned long err = ERR_peek_error();
	retval = KRB5KDC_ERR_PREAUTH_FAILED;
	krb5_set_error_message(context, retval, "%s\n",
			       ERR_error_string(err, NULL));
	pkiDebug("failed to der encode pkcs7\n");
	goto cleanup2;
    }
    retval = 0;

#ifdef DEBUG_ASN1
    if (cms_msg_type == CMS_SIGN_CLIENT) {
	print_buffer_bin(*signed_data, *signed_data_len,
			 "/tmp/client_pkcs7_signeddata");
    } else {
	if (cms_msg_type == CMS_SIGN_SERVER) {
	    print_buffer_bin(*signed_data, *signed_data_len,
			     "/tmp/kdc_pkcs7_signeddata");
	} else {
	    print_buffer_bin(*signed_data, *signed_data_len,
			     "/tmp/draft9_pkcs7_signeddata");
	}
    }
#endif

  cleanup2:
    if (cms_msg_type != CMS_SIGN_DRAFT9)
	if (ctx != NULL)
		EVP_MD_CTX_free(ctx);
#ifndef WITHOUT_PKCS11
    if (id_cryptoctx->pkcs11_method == 1 &&
	    id_cryptoctx->mech == CKM_RSA_PKCS) {
	if (ctx2 != NULL)
		EVP_MD_CTX_free(ctx2);
	if (digest_buf != NULL)
	    free(digest_buf);
	if (digestInfo_buf != NULL)
	    free(digestInfo_buf);
	if (alg_buf != NULL)
	    free(alg_buf);
	if (digest != NULL)
	    ASN1_OCTET_STRING_free(digest);
    }
#endif
    if (alg != NULL)
	X509_ALGOR_free(alg);
  cleanup:
    if (p7 != NULL)
	PKCS7_free(p7);
    if (sig != NULL)
	free(sig);

    return retval;
}

krb5_error_code
cms_signeddata_verify(krb5_context context,
		      pkinit_plg_crypto_context plgctx,
		      pkinit_req_crypto_context reqctx,
		      pkinit_identity_crypto_context idctx,
		      int cms_msg_type,
		      int require_crl_checking,
		      unsigned char *signed_data,
		      unsigned int signed_data_len,
		      unsigned char **data,
		      unsigned int *data_len,
		      unsigned char **authz_data,
		      unsigned int *authz_data_len)
{
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;
    PKCS7 *p7 = NULL;
    BIO *out = NULL;
    int flags = PKCS7_NOVERIFY, i = 0;
    unsigned int vflags = 0, size = 0;
    const unsigned char *p = signed_data;
    STACK_OF(PKCS7_SIGNER_INFO) *si_sk = NULL;
    PKCS7_SIGNER_INFO *si = NULL;
    X509 *x = NULL;
    X509_STORE *store = NULL;
    X509_STORE_CTX *cert_ctx;
    STACK_OF(X509) *intermediateCAs = NULL;
    STACK_OF(X509_CRL) *revoked = NULL;
    STACK_OF(X509) *verified_chain = NULL;
    ASN1_OBJECT *oid = NULL;
    krb5_external_principal_identifier **krb5_verified_chain = NULL;
    krb5_data *authz = NULL;
    char buf[DN_BUF_LEN];

#ifdef DEBUG_ASN1
    print_buffer_bin(signed_data, signed_data_len,
		     "/tmp/client_received_pkcs7_signeddata");
#endif

    oid = pkinit_pkcs7type2oid(plgctx, cms_msg_type);
    if (oid == NULL)
	goto cleanup;

    /* decode received PKCS7 message */
    if ((p7 = d2i_PKCS7(NULL, &p, (int)signed_data_len)) == NULL) {
	unsigned long err = ERR_peek_error();
	krb5_set_error_message(context, retval, "%s\n",
			       ERR_error_string(err, NULL));
	pkiDebug("%s: failed to decode message: %s\n",
		 __FUNCTION__, ERR_error_string(err, NULL));
	goto cleanup;
    }

    /* verify that the received message is PKCS7 SignedData message */
    if (OBJ_obj2nid(p7->type) != NID_pkcs7_signed) {
	pkiDebug("Expected id-signedData PKCS7 msg (received type = %d)\n",
		 OBJ_obj2nid(p7->type));
	krb5_set_error_message(context, retval, "wrong oid\n");
	goto cleanup;
    }

    /* setup to verify X509 certificate used to sign PKCS7 message */
    if (!(store = X509_STORE_new()))
	goto cleanup;

    /* check if we are inforcing CRL checking */
    vflags = X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL;
    if (require_crl_checking)
	X509_STORE_set_verify_cb(store, openssl_callback);
    else
	X509_STORE_set_verify_cb(store, openssl_callback_ignore_crls);
    X509_STORE_set_flags(store, vflags);

    /* get the signer's information from the PKCS7 message */
    if ((si_sk = PKCS7_get_signer_info(p7)) == NULL)
	goto cleanup;
    if ((si = sk_PKCS7_SIGNER_INFO_value(si_sk, 0)) == NULL)
	goto cleanup;
    if ((x = PKCS7_cert_from_signer_info(p7, si)) == NULL)
	goto cleanup;

    /* create available CRL information (get local CRLs and include CRLs
     * received in the PKCS7 message
     */
    if (idctx->revoked == NULL)
	revoked = p7->d.sign->crl;
    else if (p7->d.sign->crl == NULL)
	revoked = idctx->revoked;
    else {
	size = sk_X509_CRL_num(idctx->revoked);
	revoked = sk_X509_CRL_new_null();
	for (i = 0; i < size; i++)
	    sk_X509_CRL_push(revoked, sk_X509_CRL_value(idctx->revoked, i));
	size = sk_X509_CRL_num(p7->d.sign->crl);
	for (i = 0; i < size; i++)
	    sk_X509_CRL_push(revoked, sk_X509_CRL_value(p7->d.sign->crl, i));
    }

    /* create available intermediate CAs chains (get local intermediateCAs and
     * include the CA chain received in the PKCS7 message
     */
    if (idctx->intermediateCAs == NULL)
	intermediateCAs = p7->d.sign->cert;
    else if (p7->d.sign->cert == NULL)
	intermediateCAs = idctx->intermediateCAs;
    else {
	size = sk_X509_num(idctx->intermediateCAs);
	intermediateCAs = sk_X509_new_null();
	for (i = 0; i < size; i++) {
	    sk_X509_push(intermediateCAs,
		sk_X509_value(idctx->intermediateCAs, i));
	}
	size = sk_X509_num(p7->d.sign->cert);
	for (i = 0; i < size; i++) {
	    sk_X509_push(intermediateCAs, sk_X509_value(p7->d.sign->cert, i));
	}
    }

    /* initialize x509 context with the received certificate and
     * trusted and intermediate CA chains and CRLs
     */
    if ((cert_ctx = X509_STORE_CTX_new()) == NULL)
	goto cleanup;
    if (!X509_STORE_CTX_init(cert_ctx, store, x, intermediateCAs))
	goto cleanup;

    X509_STORE_CTX_set0_crls(cert_ctx, revoked);

    /* add trusted CAs certificates for cert verification */
    if (idctx->trustedCAs != NULL)
	X509_STORE_CTX_set0_trusted_stack(cert_ctx, idctx->trustedCAs);
    else {
	pkiDebug("unable to find any trusted CAs\n");
	goto cleanup;
    }
#ifdef DEBUG_CERTCHAIN
    if (intermediateCAs != NULL) {
	size = sk_X509_num(intermediateCAs);
	pkiDebug("untrusted cert chain of size %d\n", size);
	for (i = 0; i < size; i++) {
	    X509_NAME_oneline(X509_get_subject_name(
		sk_X509_value(intermediateCAs, i)), buf, sizeof(buf));
	    pkiDebug("cert #%d: %s\n", i, buf);
	}
    }
    if (idctx->trustedCAs != NULL) {
	size = sk_X509_num(idctx->trustedCAs);
	pkiDebug("trusted cert chain of size %d\n", size);
	for (i = 0; i < size; i++) {
	    X509_NAME_oneline(X509_get_subject_name(
		sk_X509_value(idctx->trustedCAs, i)), buf, sizeof(buf));
	    pkiDebug("cert #%d: %s\n", i, buf);
	}
    }
    if (revoked != NULL) {
	size = sk_X509_CRL_num(revoked);
	pkiDebug("CRL chain of size %d\n", size);
	for (i = 0; i < size; i++) {
	    X509_CRL *crl = sk_X509_CRL_value(revoked, i);
	    X509_NAME_oneline(X509_CRL_get_issuer(crl), buf, sizeof(buf));
	    pkiDebug("crls by CA #%d: %s\n", i , buf);
	}
    }
#endif

    i = X509_verify_cert(cert_ctx);
    if (i <= 0) {
	int j = X509_STORE_CTX_get_error(cert_ctx);

	reqctx->received_cert = X509_dup(
	    X509_STORE_CTX_get_current_cert(cert_ctx));
	switch(j) {
	    case X509_V_ERR_CERT_REVOKED:
		retval = KRB5KDC_ERR_REVOKED_CERTIFICATE;
		break;
	    case X509_V_ERR_UNABLE_TO_GET_CRL:
		retval = KRB5KDC_ERR_REVOCATION_STATUS_UNKNOWN;
		break;
	    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
	    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
		retval = KRB5KDC_ERR_CANT_VERIFY_CERTIFICATE;
		break;
	    default:
		retval = KRB5KDC_ERR_INVALID_CERTIFICATE;
	}
	X509_NAME_oneline(X509_get_subject_name(
	    reqctx->received_cert), buf, sizeof(buf));
	pkiDebug("problem with cert DN = %s (error=%d) %s\n", buf, j,
		 X509_verify_cert_error_string(j));
	krb5_set_error_message(context, retval, "%s\n",
	    X509_verify_cert_error_string(j));
#ifdef DEBUG_CERTCHAIN
	size = sk_X509_num(p7->d.sign->cert);
	pkiDebug("received cert chain of size %d\n", size);
	for (j = 0; j < size; j++) {
	    X509 *tmp_cert = sk_X509_value(p7->d.sign->cert, j);
	    X509_NAME_oneline(X509_get_subject_name(tmp_cert), buf, sizeof(buf));
	    pkiDebug("cert #%d: %s\n", j, buf);
	}
#endif
    } else {
	/* retrieve verified certificate chain */
	if (cms_msg_type == CMS_SIGN_CLIENT || cms_msg_type == CMS_SIGN_DRAFT9)
	    verified_chain = X509_STORE_CTX_get1_chain(cert_ctx);
    }
    X509_STORE_CTX_free(cert_ctx);
    if (i <= 0)
	goto cleanup;

    out = BIO_new(BIO_s_mem());
    if (cms_msg_type == CMS_SIGN_DRAFT9)
	flags |= PKCS7_NOATTR;
    if (PKCS7_verify(p7, NULL, store, NULL, out, flags)) {
	int valid_oid = 0;

	if (!OBJ_cmp(p7->d.sign->contents->type, oid))
	    valid_oid = 1;
	else if (cms_msg_type == CMS_SIGN_DRAFT9) {
	    /*
	     * Various implementations of the pa-type 15 request use
	     * different OIDS.  We check that the returned object
	     * has any of the acceptable OIDs
	     */
	    ASN1_OBJECT *client_oid = NULL, *server_oid = NULL, *rsa_oid = NULL;
	    client_oid = pkinit_pkcs7type2oid(plgctx, CMS_SIGN_CLIENT);
	    server_oid = pkinit_pkcs7type2oid(plgctx, CMS_SIGN_SERVER);
	    rsa_oid = pkinit_pkcs7type2oid(plgctx, CMS_ENVEL_SERVER);
	    if (!OBJ_cmp(p7->d.sign->contents->type, client_oid) ||
		!OBJ_cmp(p7->d.sign->contents->type, server_oid) ||
		!OBJ_cmp(p7->d.sign->contents->type, rsa_oid))
		valid_oid = 1;
	}

	if (valid_oid)
	    pkiDebug("PKCS7 Verification successful\n");
	else {
	    const ASN1_OBJECT *etype = p7->d.sign->contents->type;
	    pkiDebug("wrong oid in eContentType\n");
	    print_buffer((unsigned char *)OBJ_get0_data(etype),
		OBJ_length(etype));
	    retval = KRB5KDC_ERR_PREAUTH_FAILED;
	    krb5_set_error_message(context, retval, "wrong oid\n");
	    goto cleanup;
	}
    }
    else {
	unsigned long err = ERR_peek_error();
	switch(ERR_GET_REASON(err)) {
	    case PKCS7_R_DIGEST_FAILURE:
		retval = KRB5KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED;
		break;
	    case PKCS7_R_SIGNATURE_FAILURE:
	    default:
		retval = KRB5KDC_ERR_INVALID_SIG;
	}
	pkiDebug("PKCS7 Verification failure\n");
	krb5_set_error_message(context, retval, "%s\n",
			       ERR_error_string(err, NULL));
	goto cleanup;
    }

    /* transfer the data from PKCS7 message into return buffer */
    for (size = 0;;) {
	if ((*data = realloc(*data, size + 1024 * 10)) == NULL)
	    goto cleanup;
	i = BIO_read(out, &((*data)[size]), 1024 * 10);
	if (i <= 0)
	    break;
	else
	    size += i;
    }
    *data_len = size;

    reqctx->received_cert = X509_dup(x);

    /* generate authorization data */
    if (cms_msg_type == CMS_SIGN_CLIENT || cms_msg_type == CMS_SIGN_DRAFT9) {

	if (authz_data == NULL || authz_data_len == NULL)
	    goto out;

	*authz_data = NULL;
	retval = create_identifiers_from_stack(verified_chain,
					       &krb5_verified_chain);
	if (retval) {
	    pkiDebug("create_identifiers_from_stack failed\n");
	    goto cleanup;
	}

	retval = k5int_encode_krb5_td_trusted_certifiers((const krb5_external_principal_identifier **)krb5_verified_chain, &authz);
	if (retval) {
	    pkiDebug("encode_krb5_td_trusted_certifiers failed\n");
	    goto cleanup;
	}
#ifdef DEBUG_ASN1
	print_buffer_bin((unsigned char *)authz->data, authz->length,
			 "/tmp/kdc_ad_initial_verified_cas");
#endif
	*authz_data = (unsigned char *)malloc(authz->length);
	if (*authz_data == NULL) {
	    retval = ENOMEM;
	    goto cleanup;
	}
	(void) memcpy(*authz_data, authz->data, authz->length);
	*authz_data_len = authz->length;
    }
  out:
    retval = 0;

  cleanup:
    if (out != NULL)
	BIO_free(out);
    if (store != NULL)
	X509_STORE_free(store);
    if (p7 != NULL) {
	if (idctx->intermediateCAs != NULL && p7->d.sign->cert)
	    sk_X509_free(intermediateCAs);
	if (idctx->revoked != NULL && p7->d.sign->crl)
	    sk_X509_CRL_free(revoked);
	PKCS7_free(p7);
    }
    if (verified_chain != NULL)
	sk_X509_pop_free(verified_chain, X509_free);
    if (krb5_verified_chain != NULL)
	free_krb5_external_principal_identifier(&krb5_verified_chain);
    if (authz != NULL)
	krb5_free_data(context, authz);

    return retval;
}

krb5_error_code
cms_envelopeddata_create(krb5_context context,
			 pkinit_plg_crypto_context plgctx,
			 pkinit_req_crypto_context reqctx,
			 pkinit_identity_crypto_context idctx,
			 krb5_preauthtype pa_type,
			 int include_certchain,
			 unsigned char *key_pack,
			 unsigned int key_pack_len,
			 unsigned char **out,
			 unsigned int *out_len)
{

    /* Solaris Kerberos */
    krb5_error_code retval = KRB5KRB_ERR_GENERIC;
    PKCS7 *p7 = NULL;
    BIO *in = NULL;
    unsigned char *p = NULL, *signed_data = NULL, *enc_data = NULL;
    int signed_data_len = 0, enc_data_len = 0, flags = PKCS7_BINARY;
    STACK_OF(X509) *encerts = NULL;
    const EVP_CIPHER *cipher = NULL;
    int cms_msg_type;

    /* create the PKCS7 SignedData portion of the PKCS7 EnvelopedData */
    switch ((int)pa_type) {
	case KRB5_PADATA_PK_AS_REQ_OLD:
	case KRB5_PADATA_PK_AS_REP_OLD:
	    cms_msg_type = CMS_SIGN_DRAFT9;
	    break;
	case KRB5_PADATA_PK_AS_REQ:
	    cms_msg_type = CMS_ENVEL_SERVER;
	    break;
	default:
	    /* Solaris Kerberos */
	    retval = EINVAL;
	    goto cleanup;
    }

    retval = cms_signeddata_create(context, plgctx, reqctx, idctx,
	cms_msg_type, include_certchain, key_pack, key_pack_len,
	&signed_data, (unsigned int *)&signed_data_len);
    if (retval) {
	pkiDebug("failed to create pkcs7 signed data\n");
	goto cleanup;
    }

    /* check we have client's certificate */
    if (reqctx->received_cert == NULL) {
	retval = KRB5KDC_ERR_PREAUTH_FAILED;
	goto cleanup;
    }
    encerts = sk_X509_new_null();
    sk_X509_push(encerts, reqctx->received_cert);

    cipher = EVP_des_ede3_cbc();
    in = BIO_new(BIO_s_mem());
    switch (pa_type) {
	case KRB5_PADATA_PK_AS_REQ:
	    prepare_enc_data(signed_data, signed_data_len, &enc_data,
			     &enc_data_len);
	    retval = BIO_write(in, enc_data, enc_data_len);
	    if (retval != enc_data_len) {
		pkiDebug("BIO_write only wrote %d\n", retval);
		goto cleanup;
	    }
	    break;
	case KRB5_PADATA_PK_AS_REP_OLD:
	case KRB5_PADATA_PK_AS_REQ_OLD:
	    retval = BIO_write(in, signed_data, signed_data_len);
		if (retval != signed_data_len) {
		    pkiDebug("BIO_write only wrote %d\n", retval);
		    /* Solaris Kerberos */
		    retval = KRB5KRB_ERR_GENERIC;
		    goto cleanup;
	    }
	    break;
	default:
	    retval = -1;
	    goto cleanup;
    }

    p7 = PKCS7_encrypt(encerts, in, cipher, flags);
    if (p7 == NULL) {
	pkiDebug("failed to encrypt PKCS7 object\n");
	retval = -1;
	goto cleanup;
    }
    switch (pa_type) {
	case KRB5_PADATA_PK_AS_REQ:
	    p7->d.enveloped->enc_data->content_type =
		OBJ_nid2obj(NID_pkcs7_signed);
	    break;
	case KRB5_PADATA_PK_AS_REP_OLD:
	case KRB5_PADATA_PK_AS_REQ_OLD:
	    p7->d.enveloped->enc_data->content_type =
		OBJ_nid2obj(NID_pkcs7_data);
	    break;
    }

    *out_len = i2d_PKCS7(p7, NULL);
    if (!*out_len || (p = *out = (unsigned char *)malloc(*out_len)) == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }
    retval = i2d_PKCS7(p7, &p);
    if (!retval) {
	pkiDebug("unable to write pkcs7 object\n");
	goto cleanup;
    }
    retval = 0;

#ifdef DEBUG_ASN1
    print_buffer_bin(*out, *out_len, "/tmp/kdc_enveloped_data");
#endif

cleanup:
    if (p7 != NULL)
	PKCS7_free(p7);
    if (in != NULL)
	BIO_free(in);
    if (signed_data != NULL)
	free(signed_data);
    if (enc_data != NULL)
	free(enc_data);
    if (encerts != NULL)
	sk_X509_free(encerts);
	
    return retval;
}

krb5_error_code
cms_envelopeddata_verify(krb5_context context,
			 pkinit_plg_crypto_context plg_cryptoctx,
			 pkinit_req_crypto_context req_cryptoctx,
			 pkinit_identity_crypto_context id_cryptoctx,
			 krb5_preauthtype pa_type,
			 int require_crl_checking,
			 unsigned char *enveloped_data,
			 unsigned int enveloped_data_len,
			 unsigned char **data,
			 unsigned int *data_len)
{
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;
    PKCS7 *p7 = NULL;
    BIO *out = NULL;
    int i = 0;
    unsigned int size = 0;
    const unsigned char *p = enveloped_data;
    unsigned int tmp_buf_len = 0, tmp_buf2_len = 0, vfy_buf_len = 0;
    unsigned char *tmp_buf = NULL, *tmp_buf2 = NULL, *vfy_buf = NULL;
    int msg_type = 0;

#ifdef DEBUG_ASN1
    print_buffer_bin(enveloped_data, enveloped_data_len,
		     "/tmp/client_envelopeddata");
#endif
    /* decode received PKCS7 message */
    if ((p7 = d2i_PKCS7(NULL, &p, (int)enveloped_data_len)) == NULL) {
	unsigned long err = ERR_peek_error();
	pkiDebug("failed to decode pkcs7\n");
	krb5_set_error_message(context, retval, "%s\n",
			       ERR_error_string(err, NULL));
	goto cleanup;
    }

    /* verify that the received message is PKCS7 EnvelopedData message */
    if (OBJ_obj2nid(p7->type) != NID_pkcs7_enveloped) {
	pkiDebug("Expected id-enveloped PKCS7 msg (received type = %d)\n",
		 OBJ_obj2nid(p7->type));
	krb5_set_error_message(context, retval, "wrong oid\n");
	goto cleanup;
    }

    /* decrypt received PKCS7 message */
    out = BIO_new(BIO_s_mem());
    if (pkcs7_decrypt(context, id_cryptoctx, p7, out)) {
	pkiDebug("PKCS7 decryption successful\n");
    } else {
	unsigned long err = ERR_peek_error();
	if (err != 0)
	    krb5_set_error_message(context, retval, "%s\n",
				   ERR_error_string(err, NULL));
	pkiDebug("PKCS7 decryption failed\n");
	goto cleanup;
    }

    /* transfer the decoded PKCS7 SignedData message into a separate buffer */
    for (;;) {
	if ((tmp_buf = realloc(tmp_buf, size + 1024 * 10)) == NULL)
	    goto cleanup;
	i = BIO_read(out, &(tmp_buf[size]), 1024 * 10);
	if (i <= 0)
	    break;
	else
	    size += i;
    }
    tmp_buf_len = size;

#ifdef DEBUG_ASN1
    print_buffer_bin(tmp_buf, tmp_buf_len, "/tmp/client_enc_keypack");
#endif
    /* verify PKCS7 SignedData message */
    switch (pa_type) {
	case KRB5_PADATA_PK_AS_REP:
	    msg_type = CMS_ENVEL_SERVER;

	    break;
	case KRB5_PADATA_PK_AS_REP_OLD:
	    msg_type = CMS_SIGN_DRAFT9;
	    break;
	default:
	    pkiDebug("%s: unrecognized pa_type = %d\n", __FUNCTION__, pa_type);
	    retval = KRB5KDC_ERR_PREAUTH_FAILED;
	    goto cleanup;
    }
    /*
     * If this is the RFC style, wrap the signed data to make
     * decoding easier in the verify routine.
     * For draft9-compatible, we don't do anything because it
     * is already wrapped.
     */
#ifdef LONGHORN_BETA_COMPAT
    /*
     * The Longhorn server returns the expected RFC-style data, but
     * it is missing the sequence tag and length, so it requires
     * special processing when wrapping.
     * This will hopefully be fixed before the final release and
     * this can all be removed.
     */
    if (msg_type == CMS_ENVEL_SERVER || longhorn == 1) {
	retval = wrap_signeddata(tmp_buf, tmp_buf_len,
				 &tmp_buf2, &tmp_buf2_len, longhorn);
	if (retval) {
	    pkiDebug("failed to encode signeddata\n");
	    goto cleanup;
	}
	vfy_buf = tmp_buf2;
	vfy_buf_len = tmp_buf2_len;

    } else {
	vfy_buf = tmp_buf;
	vfy_buf_len = tmp_buf_len;
    }
#else
    if (msg_type == CMS_ENVEL_SERVER) {
	retval = wrap_signeddata(tmp_buf, tmp_buf_len,
				 &tmp_buf2, &tmp_buf2_len);
	if (retval) {
	    pkiDebug("failed to encode signeddata\n");
	    goto cleanup;
	}
	vfy_buf = tmp_buf2;
	vfy_buf_len = tmp_buf2_len;

    } else {
	vfy_buf = tmp_buf;
	vfy_buf_len = tmp_buf_len;
    }
#endif

#ifdef DEBUG_ASN1
    print_buffer_bin(vfy_buf, vfy_buf_len, "/tmp/client_enc_keypack2");
#endif

    retval = cms_signeddata_verify(context, plg_cryptoctx, req_cryptoctx,
				   id_cryptoctx, msg_type,
				   require_crl_checking,
				   vfy_buf, vfy_buf_len,
				   data, data_len, NULL, NULL);

    if (!retval)
	pkiDebug("PKCS7 Verification Success\n");
    else { 	
	pkiDebug("PKCS7 Verification Failure\n");
	goto cleanup;
    }

    retval = 0;

  cleanup:

    if (p7 != NULL)
	PKCS7_free(p7);
    if (out != NULL)
	BIO_free(out);
    if (tmp_buf != NULL)
	free(tmp_buf);
    if (tmp_buf2 != NULL)
	free(tmp_buf2);

    return retval;
}

/* ARGSUSED */
static krb5_error_code
crypto_retrieve_X509_sans(krb5_context context,
			  pkinit_plg_crypto_context plgctx,
			  pkinit_req_crypto_context reqctx,
			  X509 *cert,
			  krb5_principal **princs_ret,
			  krb5_principal **upn_ret,
			  unsigned char ***dns_ret)
{
    krb5_error_code retval = EINVAL;
    char buf[DN_BUF_LEN];
    int p = 0, u = 0, d = 0;
    krb5_principal *princs = NULL;
    krb5_principal *upns = NULL;
    unsigned char **dnss = NULL;
    int i, num_found = 0;

    if (princs_ret == NULL && upn_ret == NULL && dns_ret == NULL) {
	pkiDebug("%s: nowhere to return any values!\n", __FUNCTION__);
	return retval;
    }

    if (cert == NULL) {
	pkiDebug("%s: no certificate!\n", __FUNCTION__);
	return retval;
    }

    X509_NAME_oneline(X509_get_subject_name(cert),
		      buf, sizeof(buf));
    pkiDebug("%s: looking for SANs in cert = %s\n", __FUNCTION__, buf);

    if ((i = X509_get_ext_by_NID(cert, NID_subject_alt_name, -1)) >= 0) {
	X509_EXTENSION *ext = NULL;
	GENERAL_NAMES *ialt = NULL;
	GENERAL_NAME *gen = NULL;
	int ret = 0;
	unsigned int num_sans = 0;

	if (!(ext = X509_get_ext(cert, i)) || !(ialt = X509V3_EXT_d2i(ext))) {
	    pkiDebug("%s: found no subject alt name extensions\n",
		     __FUNCTION__);
	    goto cleanup;
	}
	num_sans = sk_GENERAL_NAME_num(ialt);

	pkiDebug("%s: found %d subject alt name extension(s)\n",
		 __FUNCTION__, num_sans);

	/* OK, we're likely returning something. Allocate return values */
	if (princs_ret != NULL) {
	    princs = calloc(num_sans + 1, sizeof(krb5_principal));
	    if (princs == NULL) {
		retval = ENOMEM;
		goto cleanup;
	    }
	}
	if (upn_ret != NULL) {
	    upns = calloc(num_sans + 1, sizeof(krb5_principal));
	    if (upns == NULL) {
		retval = ENOMEM;
		goto cleanup;
	    }
	}
	if (dns_ret != NULL) {
	    dnss = calloc(num_sans + 1, sizeof(*dnss));
	    if (dnss == NULL) {
		retval = ENOMEM;
		goto cleanup;
	    }
	}

	for (i = 0; i < num_sans; i++) {
	    krb5_data name = { 0, 0, NULL };

	    gen = sk_GENERAL_NAME_value(ialt, i);
	    switch (gen->type) {
	    case GEN_OTHERNAME:
		name.length = gen->d.otherName->value->value.sequence->length;
		name.data = (char *)gen->d.otherName->value->value.sequence->data;
		if (princs != NULL
		    && OBJ_cmp(plgctx->id_pkinit_san,
			       gen->d.otherName->type_id) == 0) {
#ifdef DEBUG_ASN1
		    print_buffer_bin((unsigned char *)name.data, name.length,
				     "/tmp/pkinit_san");
#endif
		    ret = k5int_decode_krb5_principal_name(&name, &princs[p]);
		    if (ret) {
			pkiDebug("%s: failed decoding pkinit san value\n",
				 __FUNCTION__);
		    } else {
			p++;
			num_found++;
		    }
		} else if (upns != NULL
			   && OBJ_cmp(plgctx->id_ms_san_upn,
				      gen->d.otherName->type_id) == 0) {
		    ret = krb5_parse_name(context, name.data, &upns[u]);
		    if (ret) {
			pkiDebug("%s: failed parsing ms-upn san value\n",
				 __FUNCTION__);
		    } else {
			u++;
			num_found++;
		    }
		} else {
		    pkiDebug("%s: unrecognized othername oid in SAN\n",
			     __FUNCTION__);
		    continue;
		}

		break;
	    case GEN_DNS:
		if (dnss != NULL) {
		    pkiDebug("%s: found dns name = %s\n",
			     __FUNCTION__, gen->d.dNSName->data);
		    dnss[d] = (unsigned char *)
				    strdup((char *)gen->d.dNSName->data);
		    if (dnss[d] == NULL) {
			pkiDebug("%s: failed to duplicate dns name\n",
				 __FUNCTION__);
		    } else {
			d++;
			num_found++;
		    }
		}
		break;
	    default:
		pkiDebug("%s: SAN type = %d expecting %d\n",
			 __FUNCTION__, gen->type, GEN_OTHERNAME);
	    }
	}
	sk_GENERAL_NAME_pop_free(ialt, GENERAL_NAME_free);
    }

    retval = 0;
    if (princs)
	*princs_ret = princs;
    if (upns)
	*upn_ret = upns;
    if (dnss)
	*dns_ret = dnss;

  cleanup:
    if (retval) {
	if (princs != NULL) {
	    for (i = 0; princs[i] != NULL; i++)
		krb5_free_principal(context, princs[i]);
	    free(princs);
	}
	if (upns != NULL) {
	    for (i = 0; upns[i] != NULL; i++)
		krb5_free_principal(context, upns[i]);
	    free(upns);
	}
	if (dnss != NULL) {
	    for (i = 0; dnss[i] != NULL; i++)
		free(dnss[i]);
	    free(dnss);
	}
    }
    return retval;
}

/* ARGSUSED */
krb5_error_code
crypto_retrieve_cert_sans(krb5_context context,
			  pkinit_plg_crypto_context plgctx,
			  pkinit_req_crypto_context reqctx,
			  pkinit_identity_crypto_context idctx,
			  krb5_principal **princs_ret,
			  krb5_principal **upn_ret,
			  unsigned char ***dns_ret)
{
    krb5_error_code retval = EINVAL;

    if (reqctx->received_cert == NULL) {
	pkiDebug("%s: No certificate!\n", __FUNCTION__);
	return retval;
    }

    return crypto_retrieve_X509_sans(context, plgctx, reqctx,
				     reqctx->received_cert, princs_ret,
				     upn_ret, dns_ret);
}

/* ARGSUSED */
krb5_error_code
crypto_check_cert_eku(krb5_context context,
		      pkinit_plg_crypto_context plgctx,
		      pkinit_req_crypto_context reqctx,
		      pkinit_identity_crypto_context idctx,
		      int checking_kdc_cert,
		      int allow_secondary_usage,
		      int *valid_eku)
{
    char buf[DN_BUF_LEN];
    int found_eku = 0;
    krb5_error_code retval = EINVAL;
    int i;

    /* Solaris Kerberos */
    if (valid_eku == NULL)
	return retval;

    *valid_eku = 0;
    if (reqctx->received_cert == NULL)
	goto cleanup;

    X509_NAME_oneline(X509_get_subject_name(reqctx->received_cert),
		      buf, sizeof(buf));
    pkiDebug("%s: looking for EKUs in cert = %s\n", __FUNCTION__, buf);

    if ((i = X509_get_ext_by_NID(reqctx->received_cert,
				 NID_ext_key_usage, -1)) >= 0) {
	EXTENDED_KEY_USAGE *extusage;

	extusage = X509_get_ext_d2i(reqctx->received_cert, NID_ext_key_usage,
				    NULL, NULL);
	if (extusage) {
	    pkiDebug("%s: found eku info in the cert\n", __FUNCTION__);
	    for (i = 0; found_eku == 0 && i < sk_ASN1_OBJECT_num(extusage); i++) {
		ASN1_OBJECT *tmp_oid;

		tmp_oid = sk_ASN1_OBJECT_value(extusage, i);
		pkiDebug("%s: checking eku %d of %d, allow_secondary = %d\n",
			 __FUNCTION__, i+1, sk_ASN1_OBJECT_num(extusage),
			 allow_secondary_usage);
		if (checking_kdc_cert) {
		    if ((OBJ_cmp(tmp_oid, plgctx->id_pkinit_KPKdc) == 0)
			 || (allow_secondary_usage
			 && OBJ_cmp(tmp_oid, plgctx->id_kp_serverAuth) == 0))
			found_eku = 1;
		} else {
		    if ((OBJ_cmp(tmp_oid, plgctx->id_pkinit_KPClientAuth) == 0)
			 || (allow_secondary_usage
			 && OBJ_cmp(tmp_oid, plgctx->id_ms_kp_sc_logon) == 0))
			found_eku = 1;
		}
	    }
	}
	EXTENDED_KEY_USAGE_free(extusage);

	if (found_eku) {
	    ASN1_BIT_STRING *usage = NULL;
	    pkiDebug("%s: found acceptable EKU, checking for digitalSignature\n", __FUNCTION__);

	    /* check that digitalSignature KeyUsage is present */
	    if ((usage = X509_get_ext_d2i(reqctx->received_cert,
					  NID_key_usage, NULL, NULL))) {

		if (!ku_reject(reqctx->received_cert,
			       X509v3_KU_DIGITAL_SIGNATURE)) {
		    pkiDebug("%s: found digitalSignature KU\n",
			     __FUNCTION__);
		    *valid_eku = 1;
		} else
		    pkiDebug("%s: didn't find digitalSignature KU\n",
			     __FUNCTION__);
	    }
	    ASN1_BIT_STRING_free(usage);
	}
    }
    retval = 0;
cleanup:
    pkiDebug("%s: returning retval %d, valid_eku %d\n",
	     __FUNCTION__, retval, *valid_eku);
    return retval;
}

krb5_error_code
pkinit_octetstring2key(krb5_context context,
		       krb5_enctype etype,
		       unsigned char *key,
		       unsigned int dh_key_len,
		       krb5_keyblock * key_block)
{
    krb5_error_code retval;
    unsigned char *buf = NULL;
    unsigned char md[SHA_DIGEST_LENGTH];
    unsigned char counter;
    size_t keybytes, keylength, offset;
    krb5_data random_data;


    if ((buf = (unsigned char *) malloc(dh_key_len)) == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }
    (void) memset(buf, 0, dh_key_len);

    counter = 0;
    offset = 0;
    do {
	SHA_CTX c;

	SHA1_Init(&c);
	SHA1_Update(&c, &counter, 1);
	SHA1_Update(&c, key, dh_key_len);
	SHA1_Final(md, &c);

	if (dh_key_len - offset < sizeof(md))
	    (void) memcpy(buf + offset, md, dh_key_len - offset);
	else
	    (void) memcpy(buf + offset, md, sizeof(md));

	offset += sizeof(md);
	counter++;
    } while (offset < dh_key_len);

    /* Solaris Kerberos */
    key_block->magic = KV5M_KEYBLOCK;
    key_block->enctype = etype;

    retval = krb5_c_keylengths(context, etype, &keybytes, &keylength);
    if (retval)
	goto cleanup;

    key_block->length = keylength;
    key_block->contents = calloc(keylength, sizeof(unsigned char *));
    if (key_block->contents == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }

    random_data.length = keybytes;
    random_data.data = (char *)buf;

    retval = krb5_c_random_to_key(context, etype, &random_data, key_block);

  cleanup:
    if (buf != NULL)
	free(buf);
    if (retval && key_block->contents != NULL && key_block->length != 0) {
	(void) memset(key_block->contents, 0, key_block->length);
	key_block->length = 0;
    }

    return retval;
}

/* ARGSUSED */
krb5_error_code
client_create_dh(krb5_context context,
		 pkinit_plg_crypto_context plg_cryptoctx,
		 pkinit_req_crypto_context cryptoctx,
		 pkinit_identity_crypto_context id_cryptoctx,
		 int dh_size,
		 unsigned char **dh_params,
		 unsigned int *dh_params_len,
		 unsigned char **dh_pubkey,
		 unsigned int *dh_pubkey_len)
{
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;
    unsigned char *buf = NULL;
    int dh_err = 0;
    ASN1_INTEGER *asn_pub_key = NULL;
    BIGNUM *p, *g, *q;
    const BIGNUM *pub_key;

    if (cryptoctx->dh == NULL) {
	if ((cryptoctx->dh = DH_new()) == NULL)
	    goto cleanup;
	if ((g = BN_new()) == NULL || (q = BN_new()) == NULL)
	    goto cleanup;

	switch(dh_size) {
	    case 1024:
		pkiDebug("client uses 1024 DH keys\n");
		cryptoctx->dh = make_dhprime(pkinit_1024_dhprime,
		    sizeof(pkinit_1024_dhprime));
		break;
	    case 2048:
		pkiDebug("client uses 2048 DH keys\n");
		cryptoctx->dh = make_dhprime(pkinit_2048_dhprime,
		    sizeof(pkinit_2048_dhprime));
		break;
	    case 4096:
		pkiDebug("client uses 4096 DH keys\n");
		cryptoctx->dh = make_dhprime(pkinit_4096_dhprime,
		    sizeof(pkinit_4096_dhprime));
		break;
	}
	if (cryptoctx->dh == NULL)
		goto cleanup;
    }

    DH_generate_key(cryptoctx->dh);
    DH_get0_key(cryptoctx->dh, &pub_key, NULL);

/* Solaris Kerberos */
#ifdef DEBUG
    DH_check(cryptoctx->dh, &dh_err);
    if (dh_err != 0) {
	pkiDebug("Warning: dh_check failed with %d\n", dh_err);
	if (dh_err & DH_CHECK_P_NOT_PRIME)
	    pkiDebug("p value is not prime\n");
	if (dh_err & DH_CHECK_P_NOT_SAFE_PRIME)
	    pkiDebug("p value is not a safe prime\n");
	if (dh_err & DH_UNABLE_TO_CHECK_GENERATOR)
	    pkiDebug("unable to check the generator value\n");
	if (dh_err & DH_NOT_SUITABLE_GENERATOR)
	    pkiDebug("the g value is not a generator\n");
    }
#endif
#ifdef DEBUG_DH
    print_dh(cryptoctx->dh, "client's DH params\n");
    print_pubkey(pub_key, "client's pub_key=");
#endif

    DH_check_pub_key(cryptoctx->dh, pub_key, &dh_err);
    if (dh_err != 0) {
	pkiDebug("dh_check_pub_key failed with %d\n", dh_err);
	goto cleanup;
    }

    /* pack DHparams */
    /* aglo: usually we could just call i2d_DHparams to encode DH params
     * however, PKINIT requires RFC3279 encoding and openssl does pkcs#3.
     */
    DH_get0_pqg(cryptoctx->dh, (const BIGNUM **)&p, (const BIGNUM **)&q,
	(const BIGNUM **)&g);
    retval = pkinit_encode_dh_params(p, g, q, dh_params, dh_params_len);
    if (retval)
	goto cleanup;

    /* pack DH public key */
    /* Diffie-Hellman public key must be ASN1 encoded as an INTEGER; this
     * encoding shall be used as the contents (the value) of the
     * subjectPublicKey component (a BIT STRING) of the SubjectPublicKeyInfo
     * data element
     */
    if ((asn_pub_key = BN_to_ASN1_INTEGER(pub_key, NULL)) == NULL)
	goto cleanup;
    *dh_pubkey_len = i2d_ASN1_INTEGER(asn_pub_key, NULL);
    if ((buf = *dh_pubkey = (unsigned char *)
        malloc((size_t) *dh_pubkey_len)) == NULL) {
	    retval = ENOMEM;
	    goto cleanup;
    }
    i2d_ASN1_INTEGER(asn_pub_key, &buf);

    if (asn_pub_key != NULL)
	ASN1_INTEGER_free(asn_pub_key);

    retval = 0;
    return retval;

  cleanup:
    if (cryptoctx->dh != NULL)
	DH_free(cryptoctx->dh);
    cryptoctx->dh = NULL;
    if (*dh_params != NULL)
	free(*dh_params);
    *dh_params = NULL;
    if (*dh_pubkey != NULL)
	free(*dh_pubkey);
    *dh_pubkey = NULL;
    if (asn_pub_key != NULL)
	ASN1_INTEGER_free(asn_pub_key);

    return retval;
}

/* ARGSUSED */
krb5_error_code
client_process_dh(krb5_context context,
		  pkinit_plg_crypto_context plg_cryptoctx,
		  pkinit_req_crypto_context cryptoctx,
		  pkinit_identity_crypto_context id_cryptoctx,
		  unsigned char *subjectPublicKey_data,
		  unsigned int subjectPublicKey_length,
		  unsigned char **client_key,
		  unsigned int *client_key_len)
{
    /* Solaris Kerberos */
    krb5_error_code retval = KRB5_PREAUTH_FAILED;
    BIGNUM *server_pub_key = NULL;
    ASN1_INTEGER *pub_key = NULL;
    const unsigned char *p = NULL;
    unsigned char *data = NULL;
    long data_len;

    /* decode subjectPublicKey (retrieve INTEGER from OCTET_STRING) */

    if (der_decode_data(subjectPublicKey_data, (long)subjectPublicKey_length,
			&data, &data_len) != 0) {
	pkiDebug("failed to decode subjectPublicKey\n");
	/* Solaris Kerberos */
	retval = KRB5_PREAUTH_FAILED;
	goto cleanup;
    }

    *client_key_len = DH_size(cryptoctx->dh);
    if ((*client_key = (unsigned char *)
	    malloc((size_t) *client_key_len)) == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }
    p = data;
    if ((pub_key = d2i_ASN1_INTEGER(NULL, &p, data_len)) == NULL)
	goto cleanup;
    if ((server_pub_key = ASN1_INTEGER_to_BN(pub_key, NULL)) == NULL)
	goto cleanup;

    DH_compute_key(*client_key, server_pub_key, cryptoctx->dh);
#ifdef DEBUG_DH
    print_pubkey(server_pub_key, "server's pub_key=");
    pkiDebug("client secret key (%d)= ", *client_key_len);
    print_buffer(*client_key, *client_key_len);
#endif

    retval = 0;
    if (server_pub_key != NULL)
	BN_free(server_pub_key);
    if (pub_key != NULL)
	ASN1_INTEGER_free(pub_key);
    if (data != NULL)
	free (data);

    return retval;

  cleanup:
    if (*client_key != NULL)
	free(*client_key);
    *client_key = NULL;
    if (pub_key != NULL)
	ASN1_INTEGER_free(pub_key);
    if (data != NULL)
	free (data);

    return retval;
}

/* ARGSUSED */
krb5_error_code
server_check_dh(krb5_context context,
		pkinit_plg_crypto_context cryptoctx,
		pkinit_req_crypto_context req_cryptoctx,
		pkinit_identity_crypto_context id_cryptoctx,
		krb5_octet_data *dh_params,
		int minbits)
{
    DH *dh = NULL;
    unsigned char *tmp = NULL;
    int dh_prime_bits;
    krb5_error_code retval = KRB5KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED;
    const BIGNUM *p, *g, *q, *p2;

    tmp = dh_params->data;
    dh = DH_new();
    dh = pkinit_decode_dh_params(&dh, &tmp, dh_params->length);
    if (dh == NULL) {
	pkiDebug("failed to decode dhparams\n");
	goto cleanup;
    }

    DH_get0_pqg(dh, &p, &q, &g);

    /* KDC SHOULD check to see if the key parameters satisfy its policy */
    dh_prime_bits = BN_num_bits(p);
    if (minbits && dh_prime_bits < minbits) {
	pkiDebug("client sent dh params with %d bits, we require %d\n",
		 dh_prime_bits, minbits);
	goto cleanup;
    }

    /* check dhparams is group 2 */
    DH_get0_pqg(cryptoctx->dh_1024, &p2, NULL, NULL);
    if (pkinit_check_dh_params(p2, p, g, q) == 0) {
	retval = 0;
	goto cleanup;
    }

    /* check dhparams is group 14 */
    DH_get0_pqg(cryptoctx->dh_2048, &p2, NULL, NULL);
    if (pkinit_check_dh_params(p2, p, g, q) == 0) {
	retval = 0;
	goto cleanup;
    }

    /* check dhparams is group 16 */
    DH_get0_pqg(cryptoctx->dh_4096, &p2, NULL, NULL);
    if (pkinit_check_dh_params(p2, p, g, q) == 0) {
	retval = 0;
	goto cleanup;
    }

  cleanup:
    if (retval == 0)
	req_cryptoctx->dh = dh;
    else
	DH_free(dh);

    return retval;
}

/* kdc's dh function */
/* ARGSUSED */
krb5_error_code
server_process_dh(krb5_context context,
		  pkinit_plg_crypto_context plg_cryptoctx,
		  pkinit_req_crypto_context cryptoctx,
		  pkinit_identity_crypto_context id_cryptoctx,
		  unsigned char *data,
		  unsigned int data_len,
		  unsigned char **dh_pubkey,
		  unsigned int *dh_pubkey_len,
		  unsigned char **server_key,
		  unsigned int *server_key_len)
{
    /* Solaris Kerberos */
    krb5_error_code retval = KRB5KRB_ERR_GENERIC;
    DH *dh = NULL, *dh_server = NULL;
    const BIGNUM *p, *g, *q, *s_pub_key;
    BIGNUM *pub_key;
    unsigned char *s = NULL;
    ASN1_INTEGER *asn_pub_key = NULL;

    /* get client's received DH parameters that we saved in server_check_dh */
    dh = cryptoctx->dh;

    dh_server = DH_new();
    if (dh_server == NULL)
	goto cleanup;
    DH_get0_pqg(dh, &p, &g, &q);
    DH_set0_pqg(dh_server, BN_dup(p), BN_dup(g), BN_dup(q));

    /* decode client's public key */
    s = data;
    asn_pub_key = d2i_ASN1_INTEGER(NULL,
	(const unsigned char **)&s, (int)data_len);
    if (asn_pub_key == NULL)
	goto cleanup;
    pub_key = ASN1_INTEGER_to_BN(asn_pub_key, NULL);
    if (pub_key == NULL)
	goto cleanup;
    DH_set0_key(dh, pub_key, NULL);
    ASN1_INTEGER_free(asn_pub_key);

    if (!DH_generate_key(dh_server))
	goto cleanup;

    /* generate DH session key */
    *server_key_len = DH_size(dh_server);
    if ((*server_key = (unsigned char *) malloc((size_t)*server_key_len))
	== NULL)
	    goto cleanup;
    DH_compute_key(*server_key, pub_key, dh_server);
    DH_get0_key(dh_server, &s_pub_key, NULL);

#ifdef DEBUG_DH
    print_dh(dh_server, "client&server's DH params\n");
    print_pubkey(pub_key, "client's pub_key=");
    print_pubkey(s_pub_key, "server's pub_key=");
    pkiDebug("server secret key=");
    print_buffer(*server_key, *server_key_len);
#endif

    /* KDC reply */
    /* pack DH public key */
    /* Diffie-Hellman public key must be ASN1 encoded as an INTEGER; this
     * encoding shall be used as the contents (the value) of the
     * subjectPublicKey component (a BIT STRING) of the SubjectPublicKeyInfo
     * data element
     */
    if ((asn_pub_key = BN_to_ASN1_INTEGER(s_pub_key, NULL)) == NULL)
	goto cleanup;
    *dh_pubkey_len = i2d_ASN1_INTEGER(asn_pub_key, NULL);
    if ((s = *dh_pubkey = (unsigned char *) malloc((size_t)*dh_pubkey_len))
	== NULL)
	    goto cleanup;
    i2d_ASN1_INTEGER(asn_pub_key, &s);
    if (asn_pub_key != NULL)
	ASN1_INTEGER_free(asn_pub_key);

    retval = 0;

    if (dh_server != NULL)
	DH_free(dh_server);
    return retval;

  cleanup:
    if (dh_server != NULL)
	DH_free(dh_server);
    if (*dh_pubkey != NULL)
	free(*dh_pubkey);
    if (*server_key != NULL)
	free(*server_key);

    return retval;
}

/*
 * Solaris Kerberos:
 * Add locking around did_init to make it MT-safe.
 */
static krb5_error_code
openssl_init()
{
    krb5_error_code ret = 0;
    static int did_init = 0;
    static k5_mutex_t init_mutex = K5_MUTEX_PARTIAL_INITIALIZER;

    ret = k5_mutex_lock(&init_mutex);
    if (ret == 0) {
	if (!did_init) {
	    /* initialize openssl routines */
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
	    /*
	     * As of version 1.1.0, OpenSSL will automatically allocate
	     * resources as-needed.
	     */
	    CRYPTO_malloc_init();
	    ERR_load_crypto_strings();
	    OpenSSL_add_all_algorithms();
#endif
	    did_init++;
	}
	k5_mutex_unlock(&init_mutex);
    }
    return (ret);
}

static krb5_error_code
pkinit_encode_dh_params(const BIGNUM *p, const BIGNUM *g, const BIGNUM *q,
			unsigned char **buf, unsigned int *buf_len)
{
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;
    int bufsize = 0, r = 0;
    unsigned char *tmp = NULL;
    ASN1_INTEGER *ap = NULL, *ag = NULL, *aq = NULL;

    if ((ap = BN_to_ASN1_INTEGER(p, NULL)) == NULL)
	goto cleanup;
    if ((ag = BN_to_ASN1_INTEGER(g, NULL)) == NULL)
	goto cleanup;
    if ((aq = BN_to_ASN1_INTEGER(q, NULL)) == NULL)
	goto cleanup;
    bufsize = i2d_ASN1_INTEGER(ap, NULL);
    bufsize += i2d_ASN1_INTEGER(ag, NULL);
    bufsize += i2d_ASN1_INTEGER(aq, NULL);

    r = ASN1_object_size(1, bufsize, V_ASN1_SEQUENCE);

    tmp = *buf = (unsigned char *)malloc((size_t) r);
    if (tmp == NULL)
	goto cleanup;

    ASN1_put_object(&tmp, 1, bufsize, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);

    i2d_ASN1_INTEGER(ap, &tmp);
    i2d_ASN1_INTEGER(ag, &tmp);
    i2d_ASN1_INTEGER(aq, &tmp);

    *buf_len = r;

    retval = 0;

cleanup:
    if (ap != NULL)
	ASN1_INTEGER_free(ap);
    if (ag != NULL)
	ASN1_INTEGER_free(ag);
    if (aq != NULL)
	ASN1_INTEGER_free(aq);

    return retval;
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)

static DH *
pkinit_decode_dh_params(DH ** a, unsigned char **pp, unsigned int len)
{
    ASN1_INTEGER ai, *aip = NULL;
    long length = (long) len;

    M_ASN1_D2I_vars(a, DH *, DH_new);

    M_ASN1_D2I_Init();
    M_ASN1_D2I_start_sequence();
    aip = &ai;
    ai.data = NULL;
    ai.length = 0;
    M_ASN1_D2I_get_x(ASN1_INTEGER, aip, d2i_ASN1_INTEGER);
    if (aip == NULL)
	return NULL;
    else {
	(*a)->p = ASN1_INTEGER_to_BN(aip, NULL);
	if ((*a)->p == NULL)
	    return NULL;
	if (ai.data != NULL) {
	    OPENSSL_free(ai.data);
	    ai.data = NULL;
	    ai.length = 0;
	}
    }
    M_ASN1_D2I_get_x(ASN1_INTEGER, aip, d2i_ASN1_INTEGER);
    if (aip == NULL)
	return NULL;
    else {
	(*a)->g = ASN1_INTEGER_to_BN(aip, NULL);
	if ((*a)->g == NULL)
	    return NULL;
	if (ai.data != NULL) {
	    OPENSSL_free(ai.data);
	    ai.data = NULL;
	    ai.length = 0;
	}

    }
    M_ASN1_D2I_get_x(ASN1_INTEGER, aip, d2i_ASN1_INTEGER);
    if (aip == NULL)
	return NULL;
    else {
	(*a)->q = ASN1_INTEGER_to_BN(aip, NULL);
	if ((*a)->q == NULL)
	    return NULL;
	if (ai.data != NULL) {
	    OPENSSL_free(ai.data);
	    ai.data = NULL;
	    ai.length = 0;
	}

    }
    M_ASN1_D2I_end_sequence();
    M_ASN1_D2I_Finish(a, DH_free, 0);

}

#else

/*
 * This is taken from the internal dh_asn1.c file in OpenSSL 1.1, modified to
 * make q an optional field.
 */

typedef struct {
    ASN1_BIT_STRING *seed;
    BIGNUM *counter;
} int_dhvparams;

typedef struct {
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *g;
    BIGNUM *j;
    int_dhvparams *vparams;
} int_dhx942_dh;

ASN1_SEQUENCE(DHvparams) = {
    ASN1_SIMPLE(int_dhvparams, seed, ASN1_BIT_STRING),
    ASN1_SIMPLE(int_dhvparams, counter, BIGNUM)
} static_ASN1_SEQUENCE_END_name(int_dhvparams, DHvparams)

ASN1_SEQUENCE(DHxparams) = {
    ASN1_SIMPLE(int_dhx942_dh, p, BIGNUM),
    ASN1_SIMPLE(int_dhx942_dh, g, BIGNUM),
    ASN1_OPT(int_dhx942_dh, q, BIGNUM),
    ASN1_OPT(int_dhx942_dh, j, BIGNUM),
    ASN1_OPT(int_dhx942_dh, vparams, DHvparams),
} static_ASN1_SEQUENCE_END_name(int_dhx942_dh, DHxparams)

static DH *
pkinit_decode_dh_params(DH **a, unsigned char **pp, unsigned int len)
{
	int_dhx942_dh *params;
	DH *dh = *a;

	if (dh == NULL)
		return NULL;

	params = (int_dhx942_dh *)ASN1_item_d2i(NULL,
	    (const unsigned char **)pp, len, ASN1_ITEM_rptr(DHxparams));
	if (params == NULL) {
		DH_free(dh);
		return NULL;
	}

	DH_set0_pqg(dh, params->p, params->q, params->g);
	params->p = params->q = params->g = NULL;
	ASN1_item_free((ASN1_VALUE *)params, ASN1_ITEM_rptr(DHxparams));
	return dh;
}

#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L || LIBRESSL_VERSION_NUMBER */

static krb5_error_code
pkinit_create_sequence_of_principal_identifiers(
    krb5_context context,
    pkinit_plg_crypto_context plg_cryptoctx,
    pkinit_req_crypto_context req_cryptoctx,
    pkinit_identity_crypto_context id_cryptoctx,
    int type,
    krb5_data **out_data)
{
    krb5_error_code retval = KRB5KRB_ERR_GENERIC;
    krb5_external_principal_identifier **krb5_trusted_certifiers = NULL;
    krb5_data *td_certifiers = NULL, *data = NULL;
    krb5_typed_data **typed_data = NULL;

    switch(type) {
	case TD_TRUSTED_CERTIFIERS:
	    retval = create_krb5_trustedCertifiers(context, plg_cryptoctx,
		req_cryptoctx, id_cryptoctx, &krb5_trusted_certifiers);
	    if (retval) {
		pkiDebug("create_krb5_trustedCertifiers failed\n");
		goto cleanup;
    	    }
	    break;
	case TD_INVALID_CERTIFICATES:
	    retval = create_krb5_invalidCertificates(context, plg_cryptoctx,
		req_cryptoctx, id_cryptoctx, &krb5_trusted_certifiers);
	    if (retval) {
		pkiDebug("create_krb5_invalidCertificates failed\n");
		goto cleanup;
    	    }
	    break;
	default:
	    retval = -1;
	    goto cleanup;
    }

    retval = k5int_encode_krb5_td_trusted_certifiers((const krb5_external_principal_identifier **)krb5_trusted_certifiers, &td_certifiers);
    if (retval) {
	pkiDebug("encode_krb5_td_trusted_certifiers failed\n");
	goto cleanup;
    }
#ifdef DEBUG_ASN1
    print_buffer_bin((unsigned char *)td_certifiers->data,
		     td_certifiers->length, "/tmp/kdc_td_certifiers");
#endif
    typed_data = malloc (2 * sizeof(krb5_typed_data *));
    if (typed_data == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }
    typed_data[1] = NULL;
    init_krb5_typed_data(&typed_data[0]);
    if (typed_data[0] == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }
    typed_data[0]->type = type;
    typed_data[0]->length = td_certifiers->length;
    typed_data[0]->data = (unsigned char *)td_certifiers->data;
    retval = k5int_encode_krb5_typed_data((const krb5_typed_data **)typed_data,
					  &data);
    if (retval) {
	pkiDebug("encode_krb5_typed_data failed\n");
	goto cleanup;
    }
#ifdef DEBUG_ASN1
    print_buffer_bin((unsigned char *)data->data, data->length,
		     "/tmp/kdc_edata");
#endif
    *out_data = (krb5_data *)malloc(sizeof(krb5_data));
    (*out_data)->length = data->length;
    (*out_data)->data = (char *)malloc(data->length);
    (void) memcpy((*out_data)->data, data->data, data->length);

    retval = 0;

cleanup:
    if (krb5_trusted_certifiers != NULL)
	free_krb5_external_principal_identifier(&krb5_trusted_certifiers);

    if (data != NULL) {
	if (data->data != NULL)
	    free(data->data);
	free(data);
    }

    if (td_certifiers != NULL)
	free(td_certifiers);

    if (typed_data != NULL)
	free_krb5_typed_data(&typed_data);

    return retval;
}

krb5_error_code
pkinit_create_td_trusted_certifiers(krb5_context context,
				    pkinit_plg_crypto_context plg_cryptoctx,
				    pkinit_req_crypto_context req_cryptoctx,
				    pkinit_identity_crypto_context id_cryptoctx,
				    krb5_data **out_data)
{
    krb5_error_code retval = KRB5KRB_ERR_GENERIC;

    retval = pkinit_create_sequence_of_principal_identifiers(context,
	plg_cryptoctx, req_cryptoctx, id_cryptoctx,
	TD_TRUSTED_CERTIFIERS, out_data);

    return retval;
}

krb5_error_code
pkinit_create_td_invalid_certificate(
	krb5_context context,
	pkinit_plg_crypto_context plg_cryptoctx,
	pkinit_req_crypto_context req_cryptoctx,
	pkinit_identity_crypto_context id_cryptoctx,
	krb5_data **out_data)
{
    krb5_error_code retval = KRB5KRB_ERR_GENERIC;

    retval = pkinit_create_sequence_of_principal_identifiers(context,
	plg_cryptoctx, req_cryptoctx, id_cryptoctx,
	TD_INVALID_CERTIFICATES, out_data);

    return retval;
}

/* ARGSUSED */
krb5_error_code
pkinit_create_td_dh_parameters(krb5_context context,
			       pkinit_plg_crypto_context plg_cryptoctx,
			       pkinit_req_crypto_context req_cryptoctx,
			       pkinit_identity_crypto_context id_cryptoctx,
			       pkinit_plg_opts *opts,
			       krb5_data **out_data)
{
    /* Solaris Kerberos */
    krb5_error_code retval = KRB5KRB_ERR_GENERIC;
    unsigned int buf1_len = 0, buf2_len = 0, buf3_len = 0, i = 0;
    unsigned char *buf1 = NULL, *buf2 = NULL, *buf3 = NULL;
    krb5_typed_data **typed_data = NULL;
    krb5_data *data = NULL, *encoded_algId = NULL;
    krb5_algorithm_identifier **algId = NULL;
    const BIGNUM *p, *q, *g;

    /* Solaris Kerberos */
    if (opts->dh_min_bits > 4096) {
	retval = EINVAL;
	goto cleanup;
    }

    if (opts->dh_min_bits <= 1024) {
	DH_get0_pqg(plg_cryptoctx->dh_1024, &p, &q, &g);
	retval = pkinit_encode_dh_params(p, g, q, &buf1, &buf1_len);
	if (retval)
	    goto cleanup;
    }
    if (opts->dh_min_bits <= 2048) {
	DH_get0_pqg(plg_cryptoctx->dh_2048, &p, &q, &g);
	retval = pkinit_encode_dh_params(p, g, q, &buf2, &buf2_len);
	if (retval)
	    goto cleanup;
    }
    DH_get0_pqg(plg_cryptoctx->dh_4096, &p, &q, &g);
    retval = pkinit_encode_dh_params(p, g, q, &buf3, &buf3_len);
    if (retval)
	goto cleanup;

    if (opts->dh_min_bits <= 1024) {
	algId = malloc(4 * sizeof(krb5_algorithm_identifier *));
	if (algId == NULL)
	    goto cleanup;
	algId[3] = NULL;
	algId[0] = (krb5_algorithm_identifier *)malloc(sizeof(krb5_algorithm_identifier));
	if (algId[0] == NULL)
	    goto cleanup;
	algId[0]->parameters.data = (unsigned char *)malloc(buf2_len);
	if (algId[0]->parameters.data == NULL)
	    goto cleanup;
	(void) memcpy(algId[0]->parameters.data, buf2, buf2_len);
	algId[0]->parameters.length = buf2_len;
	algId[0]->algorithm = dh_oid;

	algId[1] = (krb5_algorithm_identifier *)malloc(sizeof(krb5_algorithm_identifier));
	if (algId[1] == NULL)
	    goto cleanup;
	algId[1]->parameters.data = (unsigned char *)malloc(buf3_len);
	if (algId[1]->parameters.data == NULL)
	    goto cleanup;
	(void) memcpy(algId[1]->parameters.data, buf3, buf3_len);
	algId[1]->parameters.length = buf3_len;
	algId[1]->algorithm = dh_oid;

	algId[2] = (krb5_algorithm_identifier *)malloc(sizeof(krb5_algorithm_identifier));
	if (algId[2] == NULL)
	    goto cleanup;
	algId[2]->parameters.data = (unsigned char *)malloc(buf1_len);
	if (algId[2]->parameters.data == NULL)
	    goto cleanup;
	(void) memcpy(algId[2]->parameters.data, buf1, buf1_len);
	algId[2]->parameters.length = buf1_len;
	algId[2]->algorithm = dh_oid;

    } else if (opts->dh_min_bits <= 2048) {
	algId = malloc(3 * sizeof(krb5_algorithm_identifier *));
	if (algId == NULL)
	    goto cleanup;
	algId[2] = NULL;
	algId[0] = (krb5_algorithm_identifier *)malloc(sizeof(krb5_algorithm_identifier));
	if (algId[0] == NULL)
	    goto cleanup;
	algId[0]->parameters.data = (unsigned char *)malloc(buf2_len);
	if (algId[0]->parameters.data == NULL)
	    goto cleanup;
	(void) memcpy(algId[0]->parameters.data, buf2, buf2_len);
	algId[0]->parameters.length = buf2_len;
	algId[0]->algorithm = dh_oid;

	algId[1] = (krb5_algorithm_identifier *)malloc(sizeof(krb5_algorithm_identifier));
	if (algId[1] == NULL)
	    goto cleanup;
	algId[1]->parameters.data = (unsigned char *)malloc(buf3_len);
	if (algId[1]->parameters.data == NULL)
	    goto cleanup;
	(void) memcpy(algId[1]->parameters.data, buf3, buf3_len);
	algId[1]->parameters.length = buf3_len;
	algId[1]->algorithm = dh_oid;

    } else if (opts->dh_min_bits <= 4096) {
	algId = malloc(2 * sizeof(krb5_algorithm_identifier *));
	if (algId == NULL)
	    goto cleanup;
	algId[1] = NULL;
	algId[0] = (krb5_algorithm_identifier *)malloc(sizeof(krb5_algorithm_identifier));
	if (algId[0] == NULL)
	    goto cleanup;
	algId[0]->parameters.data = (unsigned char *)malloc(buf3_len);
	if (algId[0]->parameters.data == NULL)
	    goto cleanup;
	(void) memcpy(algId[0]->parameters.data, buf3, buf3_len);
	algId[0]->parameters.length = buf3_len;
	algId[0]->algorithm = dh_oid;

    }
    retval = k5int_encode_krb5_td_dh_parameters((const krb5_algorithm_identifier **)algId, &encoded_algId);
    if (retval)
	goto cleanup;
#ifdef DEBUG_ASN1
    print_buffer_bin((unsigned char *)encoded_algId->data,
		     encoded_algId->length, "/tmp/kdc_td_dh_params");
#endif
    typed_data = malloc (2 * sizeof(krb5_typed_data *));
    if (typed_data == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }
    typed_data[1] = NULL;
    init_krb5_typed_data(&typed_data[0]);
    if (typed_data == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }
    typed_data[0]->type = TD_DH_PARAMETERS;
    typed_data[0]->length = encoded_algId->length;
    typed_data[0]->data = (unsigned char *)encoded_algId->data;
    retval = k5int_encode_krb5_typed_data((const krb5_typed_data**)typed_data,
					  &data);
    if (retval) {
	pkiDebug("encode_krb5_typed_data failed\n");
	goto cleanup;
    }
#ifdef DEBUG_ASN1
    print_buffer_bin((unsigned char *)data->data, data->length,
		     "/tmp/kdc_edata");
#endif
    *out_data = (krb5_data *)malloc(sizeof(krb5_data));
    if (*out_data == NULL)
	goto cleanup;
    (*out_data)->length = data->length;
    (*out_data)->data = (char *)malloc(data->length);
    if ((*out_data)->data == NULL) {
	free(*out_data);
	*out_data = NULL;
	goto cleanup;
    }
    (void) memcpy((*out_data)->data, data->data, data->length);

    retval = 0;
cleanup:

    if (buf1 != NULL)
	free(buf1);
    if (buf2 != NULL)
	free(buf2);
    if (buf3 != NULL)
	free(buf3);
    if (data != NULL) {
	if (data->data != NULL)
	    free(data->data);
	free(data);
    }
    if (typed_data != NULL)
	free_krb5_typed_data(&typed_data);
    if (encoded_algId != NULL)
	free(encoded_algId);

    if (algId != NULL) {
	while(algId[i] != NULL) {
	    if (algId[i]->parameters.data != NULL)
		free(algId[i]->parameters.data);
	    free(algId[i]);
	    i++;
	}
	free(algId);
    }

    return retval;
}

/* ARGSUSED */
krb5_error_code
pkinit_check_kdc_pkid(krb5_context context,
		      pkinit_plg_crypto_context plg_cryptoctx,
		      pkinit_req_crypto_context req_cryptoctx,
		      pkinit_identity_crypto_context id_cryptoctx,
		      unsigned char *pdid_buf,
		      unsigned int pkid_len,
		      int *valid_kdcPkId)
{
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;
    PKCS7_ISSUER_AND_SERIAL *is = NULL;
    const unsigned char *p = pdid_buf;
    int status = 1;
    X509 *kdc_cert = sk_X509_value(id_cryptoctx->my_certs, id_cryptoctx->cert_index);

    *valid_kdcPkId = 0;
    pkiDebug("found kdcPkId in AS REQ\n");
    is = d2i_PKCS7_ISSUER_AND_SERIAL(NULL, &p, (int)pkid_len);
    if (is == NULL)
	goto cleanup;

    status = X509_NAME_cmp(X509_get_issuer_name(kdc_cert), is->issuer);
    if (!status) {
	status = ASN1_INTEGER_cmp(X509_get_serialNumber(kdc_cert), is->serial);
	if (!status)
	    *valid_kdcPkId = 1;
    }

    retval = 0;
cleanup:
    X509_NAME_free(is->issuer);
    ASN1_INTEGER_free(is->serial);
    free(is);

    return retval;
}

static int
pkinit_check_dh_params(const BIGNUM *p1, const BIGNUM *p2, const BIGNUM *g1,
    const BIGNUM *q1)
{
    BIGNUM *g2 = NULL, *q2 = NULL;
    /* Solaris Kerberos */
    int retval = EINVAL;

    if (!BN_cmp(p1, p2)) {
	g2 = BN_new();
	BN_set_word(g2, DH_GENERATOR_2);
	if (!BN_cmp(g1, g2)) {
	    q2 = BN_new();
	    BN_rshift1(q2, p1);
	    if (!BN_cmp(q1, q2)) {
		pkiDebug("good %d dhparams\n", BN_num_bits(p1));
		retval = 0;
	    } else
		pkiDebug("bad group 2 q dhparameter\n");
	    BN_free(q2);
	} else
	    pkiDebug("bad g dhparameter\n");
	BN_free(g2);
    } else
	pkiDebug("p is not well-known group 2 dhparameter\n");

    return retval;
}

/* ARGSUSED */
krb5_error_code
pkinit_process_td_dh_params(krb5_context context,
			    pkinit_plg_crypto_context cryptoctx,
			    pkinit_req_crypto_context req_cryptoctx,
			    pkinit_identity_crypto_context id_cryptoctx,
			    krb5_algorithm_identifier **algId,
			    int *new_dh_size)
{
    krb5_error_code retval = KRB5KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED;
    int i = 0, use_sent_dh = 0, ok = 0;

    pkiDebug("dh parameters\n");

    while (algId[i] != NULL) {
	DH *dh = NULL;
	unsigned char *tmp = NULL;
	const BIGNUM *p, *g, *q, *p2;
	int dh_prime_bits = 0;

	if (algId[i]->algorithm.length != dh_oid.length ||
	    memcmp(algId[i]->algorithm.data, dh_oid.data, dh_oid.length))
	    goto cleanup;

	tmp = algId[i]->parameters.data;
	dh = DH_new();
	dh = pkinit_decode_dh_params(&dh, &tmp, algId[i]->parameters.length);
	dh_prime_bits = DH_bits(dh);
	pkiDebug("client sent %d DH bits server prefers %d DH bits\n",
		 *new_dh_size, dh_prime_bits);
	DH_get0_pqg(dh, &p, &q, &g);
	switch(dh_prime_bits) {
	    case 1024:
		DH_get0_pqg(cryptoctx->dh_1024, &p2, NULL, NULL);
		if (pkinit_check_dh_params(p2, p, g, q) == 0) {
		    *new_dh_size = 1024;
		    ok = 1;
		}
		break;
	    case 2048:
		DH_get0_pqg(cryptoctx->dh_2048, &p2, NULL, NULL);
		if (pkinit_check_dh_params(p2, p, g, q) == 0) {
		    *new_dh_size = 2048;
		    ok = 1;
		}
		break;
	    case 4096:
		DH_get0_pqg(cryptoctx->dh_4096, &p2, NULL, NULL);
		if (pkinit_check_dh_params(p2, p, g, q) == 0) {
		    *new_dh_size = 4096;
		    ok = 1;
		}
		break;
	    default:
		break;
	}
	if (!ok) {
	    DH_check(dh, &retval);
	    if (retval != 0) {
		pkiDebug("DH parameters provided by server are unacceptable\n");
		retval = KRB5KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED;
	    }
	    else {
		use_sent_dh = 1;
		ok = 1;
	    }
	}
	if (!use_sent_dh)
	    DH_free(dh);
	if (ok) {
	    if (req_cryptoctx->dh != NULL) {
		DH_free(req_cryptoctx->dh);
		req_cryptoctx->dh = NULL;
	    }
	    if (use_sent_dh)
		req_cryptoctx->dh = dh;
	    break;
	}
	i++;
    }

    if (ok)
	retval = 0;

cleanup:
    return retval;
}

/* ARGSUSED */
static int
openssl_callback(int ok, X509_STORE_CTX * ctx)
{
#ifdef DEBUG
    if (!ok) {
	char buf[DN_BUF_LEN];

	X509_NAME_oneline(X509_get_subject_name(ctx->current_cert), buf, sizeof(buf));
	pkiDebug("cert = %s\n", buf);
	pkiDebug("callback function: %d (%s)\n", ctx->error,
		X509_verify_cert_error_string(ctx->error));
    }
#endif
    return ok;
}

static int
openssl_callback_ignore_crls(int ok, X509_STORE_CTX * ctx)
{
    if (!ok)
	return (X509_STORE_CTX_get_error(ctx) == X509_V_ERR_UNABLE_TO_GET_CRL);
    return ok;
}

static ASN1_OBJECT *
pkinit_pkcs7type2oid(pkinit_plg_crypto_context cryptoctx, int pkcs7_type)
{
    switch (pkcs7_type) {
	case CMS_SIGN_CLIENT:
	    return cryptoctx->id_pkinit_authData;
	case CMS_SIGN_DRAFT9:
	    return OBJ_nid2obj(NID_pkcs7_data);
	case CMS_SIGN_SERVER:
	    return cryptoctx->id_pkinit_DHKeyData;
	case CMS_ENVEL_SERVER:
	    return cryptoctx->id_pkinit_rkeyData;
	default:
	    return NULL;
    }

}

#ifdef LONGHORN_BETA_COMPAT
#if 0
/*
 * This is a version that worked with Longhorn Beta 3.
 */
static int
wrap_signeddata(unsigned char *data, unsigned int data_len,
		unsigned char **out, unsigned int *out_len,
		int is_longhorn_server)
{

    unsigned int orig_len = 0, oid_len = 0, tot_len = 0;
    ASN1_OBJECT *oid = NULL;
    unsigned char *p = NULL;

    pkiDebug("%s: This is the Longhorn version and is_longhorn_server = %d\n",
	     __FUNCTION__, is_longhorn_server);

    /* Get length to wrap the original data with SEQUENCE tag */
    tot_len = orig_len = ASN1_object_size(1, (int)data_len, V_ASN1_SEQUENCE);

    if (is_longhorn_server == 0) {
	/* Add the signedData OID and adjust lengths */
	oid = OBJ_nid2obj(NID_pkcs7_signed);
	oid_len = i2d_ASN1_OBJECT(oid, NULL);

	tot_len = ASN1_object_size(1, (int)(orig_len+oid_len), V_ASN1_SEQUENCE);
    }

    p = *out = (unsigned char *)malloc(tot_len);
    if (p == NULL) return -1;

    if (is_longhorn_server == 0) {
	ASN1_put_object(&p, 1, (int)(orig_len+oid_len),
			V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);

	i2d_ASN1_OBJECT(oid, &p);

	ASN1_put_object(&p, 1, (int)data_len, 0, V_ASN1_CONTEXT_SPECIFIC);
    } else {
	ASN1_put_object(&p, 1, (int)data_len, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);
    }
    memcpy(p, data, data_len);

    *out_len = tot_len;

    return 0;
}
#else
/*
 * This is a version that works with a patched Longhorn KDC.
 * (Which should match SP1 ??).
 */
static int
wrap_signeddata(unsigned char *data, unsigned int data_len,
	       unsigned char **out, unsigned int *out_len,
	       int is_longhorn_server)
{

    unsigned int oid_len = 0, tot_len = 0, wrap_len = 0, tag_len = 0;
    ASN1_OBJECT *oid = NULL;
    unsigned char *p = NULL;

    pkiDebug("%s: This is the Longhorn version and is_longhorn_server = %d\n",
	     __FUNCTION__, is_longhorn_server);

    /* New longhorn is missing another sequence */
    if (is_longhorn_server == 1)
       wrap_len = ASN1_object_size(1, (int)(data_len), V_ASN1_SEQUENCE);
    else
       wrap_len = data_len;

    /* Get length to wrap the original data with SEQUENCE tag */
    tag_len = ASN1_object_size(1, (int)wrap_len, V_ASN1_SEQUENCE);

    /* Always add oid */
    oid = OBJ_nid2obj(NID_pkcs7_signed);
    oid_len = i2d_ASN1_OBJECT(oid, NULL);
    oid_len += tag_len;

    tot_len = ASN1_object_size(1, (int)(oid_len), V_ASN1_SEQUENCE);

    p = *out = (unsigned char *)malloc(tot_len);
    if (p == NULL)
       return -1;

    ASN1_put_object(&p, 1, (int)(oid_len),
		    V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);

    i2d_ASN1_OBJECT(oid, &p);

    ASN1_put_object(&p, 1, (int)wrap_len, 0, V_ASN1_CONTEXT_SPECIFIC);

    /* Wrap in extra seq tag */
    if (is_longhorn_server == 1) {
       ASN1_put_object(&p, 1, (int)data_len, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);
    }
    (void) memcpy(p, data, data_len);

    *out_len = tot_len;

    return 0;
}

#endif
#else
static int
wrap_signeddata(unsigned char *data, unsigned int data_len,
		unsigned char **out, unsigned int *out_len)
{

    unsigned int orig_len = 0, oid_len = 0, tot_len = 0;
    ASN1_OBJECT *oid = NULL;
    unsigned char *p = NULL;

    /* Get length to wrap the original data with SEQUENCE tag */
    tot_len = orig_len = ASN1_object_size(1, (int)data_len, V_ASN1_SEQUENCE);

    /* Add the signedData OID and adjust lengths */
    oid = OBJ_nid2obj(NID_pkcs7_signed);
    oid_len = i2d_ASN1_OBJECT(oid, NULL);

    tot_len = ASN1_object_size(1, (int)(orig_len+oid_len), V_ASN1_SEQUENCE);

    p = *out = (unsigned char *)malloc(tot_len);
    if (p == NULL) return -1;

    ASN1_put_object(&p, 1, (int)(orig_len+oid_len),
		    V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);

    i2d_ASN1_OBJECT(oid, &p);

    ASN1_put_object(&p, 1, (int)data_len, 0, V_ASN1_CONTEXT_SPECIFIC);
    (void) memcpy(p, data, data_len);

    *out_len = tot_len;

    return 0;
}
#endif

static int
prepare_enc_data(unsigned char *indata,
		 int indata_len,
		 unsigned char **outdata,
		 int *outdata_len)
{
    int tag, class;
    long tlen, slen;
    const uint8_t *p = indata, *oldp;

    /* Top-bit set means that the conversion failed. */
    if (ASN1_get_object(&p, &slen, &tag, &class, indata_len) & 0x80)
        return EINVAL;
    if (tag != V_ASN1_SEQUENCE)
        return EINVAL;

    oldp = p;
    if (ASN1_get_object(&p, &tlen, &tag, &class, slen) & 0x80)
        return EINVAL;
    p += tlen;
    slen -= (p - oldp);

    if (ASN1_get_object(&p, &tlen, &tag, &class, slen) & 0x80)
        return EINVAL;

    *outdata = malloc(tlen);
    if (*outdata == NULL)
        return ENOMEM;
    memcpy(*outdata, p, tlen);
    *outdata_len = tlen;

    return 0;
}

#ifndef WITHOUT_PKCS11
static void *
pkinit_C_LoadModule(const char *modname, CK_FUNCTION_LIST_PTR_PTR p11p)
{
    void *handle;
    CK_RV (*getflist)(CK_FUNCTION_LIST_PTR_PTR);

    pkiDebug("loading module \"%s\"... ", modname);
    /* Solaris Kerberos */
    handle = dlopen(modname, RTLD_NOW | RTLD_GROUP);
    if (handle == NULL) {
	pkiDebug("not found\n");
	return NULL;
    }
    getflist = (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR)) dlsym(handle, "C_GetFunctionList");
    if (getflist == NULL || (*getflist)(p11p) != CKR_OK) {
	(void) dlclose(handle);
	pkiDebug("failed\n");
	return NULL;
    }
    pkiDebug("ok\n");
    return handle;
}

static CK_RV
pkinit_C_UnloadModule(void *handle)
{
    /* Solaris Kerberos */
    if (dlclose(handle) != 0)
	return CKR_GENERAL_ERROR;

    return CKR_OK;
}

/*
 * Solaris Kerberos: this is a new function that does not exist yet in the MIT
 * code.
 *
 * labelstr will be C string containing token label with trailing white space
 * removed.
 */
static void
trim_token_label(CK_TOKEN_INFO *tinfo, char *labelstr, unsigned int labelstr_len)
{
    int i;

    assert(labelstr_len > sizeof (tinfo->label));
    /*
     * \0 terminate labelstr in case the last char in the token label is
     * non-whitespace
     */
    labelstr[sizeof (tinfo->label)] = '\0';
    (void) memcpy(labelstr, (char *) tinfo->label, sizeof (tinfo->label));

    /* init i so terminating \0 is skipped */
    for (i = sizeof (tinfo->label) - 1; i >= 0; i--) {
	if (labelstr[i] == ' ')
	    labelstr[i] = '\0';
	else
	    break;
    }
}

/*
 * Solaris Kerberos: this is a new function that does not exist yet in the MIT
 * code.
 */
static krb5_error_code
pkinit_prompt_user(krb5_context context,
		   pkinit_identity_crypto_context cctx,
		   krb5_data *reply,
		   char *prompt,
		   int hidden)
{
    krb5_error_code r;
    krb5_prompt kprompt;
    krb5_prompt_type prompt_type;

    if (cctx->prompter == NULL)
	return (EINVAL);

    kprompt.prompt = prompt;
    kprompt.hidden = hidden;
    kprompt.reply = reply;
    /*
     * Note, assuming this type for now, may need to be passed in in the future.
     */
    prompt_type = KRB5_PROMPT_TYPE_PREAUTH;

    /* PROMPTER_INVOCATION */
    k5int_set_prompt_types(context, &prompt_type);
    r = (*cctx->prompter)(context, cctx->prompter_data,
			  NULL, NULL, 1, &kprompt);
    k5int_set_prompt_types(context, NULL);
    return (r);
}

/*
 * Solaris Kerberos: this function was changed to support a PIN being passed
 * in.  If that is the case the user will not be prompted for their PIN.
 */
static krb5_error_code
pkinit_login(krb5_context context,
	     pkinit_identity_crypto_context id_cryptoctx,
	     CK_TOKEN_INFO *tip)
{
    krb5_data rdat;
    char *prompt;
    int prompt_len;
    int r = 0;

    if (tip->flags & CKF_PROTECTED_AUTHENTICATION_PATH) {
	rdat.data = NULL;
	rdat.length = 0;
    } else if (id_cryptoctx->PIN != NULL) {
	if ((rdat.data = strdup(id_cryptoctx->PIN)) == NULL)
	    return (ENOMEM);
	/*
	 * Don't include NULL string terminator in length calculation as this
	 * PIN is passed to the C_Login function and only the text chars should
	 * be considered to be the PIN.
	 */
	rdat.length = strlen(id_cryptoctx->PIN);
    } else {
        /* Solaris Kerberos - trim token label */
	char tmplabel[sizeof (tip->label) + 1];

	if (!id_cryptoctx->prompter) {
	    pkiDebug("pkinit_login: id_cryptoctx->prompter is NULL\n");
	    /* Solaris Kerberos: Improved error messages */
	    krb5_set_error_message(context, KRB5KDC_ERR_PREAUTH_FAILED,
		gettext("Failed to log into token: prompter function is NULL"));
	    return (KRB5KDC_ERR_PREAUTH_FAILED);
	}
	/* Solaris Kerberos - Changes for gettext() */
        prompt_len = sizeof (tip->label) + 256;
	if ((prompt = (char *) malloc(prompt_len)) == NULL)
	    return ENOMEM;

	/* Solaris Kerberos - trim token label which can be padded with space */
	trim_token_label(tip, tmplabel, sizeof (tmplabel));
	(void) snprintf(prompt, prompt_len, gettext("%s PIN"), tmplabel);

	/* Solaris Kerberos */
	if (tip->flags & CKF_USER_PIN_LOCKED)
	    (void) strlcat(prompt, gettext(" (Warning: PIN locked)"), prompt_len);
	else if (tip->flags & CKF_USER_PIN_FINAL_TRY)
	    (void) strlcat(prompt, gettext(" (Warning: PIN final try)"), prompt_len);
	else if (tip->flags & CKF_USER_PIN_COUNT_LOW)
	    (void) strlcat(prompt, gettext(" (Warning: PIN count low)"), prompt_len);
	rdat.data = malloc(tip->ulMaxPinLen + 2);
	rdat.length = tip->ulMaxPinLen + 1;
	/*
	 * Note that the prompter function will set rdat.length such that the
	 * NULL terminator is not included
	 */
	/* PROMPTER_INVOCATION */
	r = pkinit_prompt_user(context, id_cryptoctx, &rdat, prompt, 1);
	free(prompt);
    }

    if (r == 0) {
	r = id_cryptoctx->p11->C_Login(id_cryptoctx->session, CKU_USER,
		(u_char *) rdat.data, rdat.length);

	if (r != CKR_OK) {
	    pkiDebug("C_Login: %s\n", pkinit_pkcs11_code_to_text(r));
	    /* Solaris Kerberos: Improved error messages */
	    krb5_set_error_message(context, KRB5KDC_ERR_PREAUTH_FAILED,
		gettext("Failed to log into token: %s"),
		pkinit_pkcs11_code_to_text(r));
	    r = KRB5KDC_ERR_PREAUTH_FAILED;
	} else {
	    /* Solaris Kerberos: only need to login once */
            id_cryptoctx->p11flags |= C_LOGIN_DONE;
        }
    }
    if (rdat.data) {
	(void) memset(rdat.data, 0, rdat.length);
	free(rdat.data);
    }

    return (r);
}

/*
 * Solaris Kerberos: added these structs in support of prompting user for
 * missing token.
 */
struct _token_entry {
    CK_SLOT_ID slotID;
    CK_SESSION_HANDLE session;
    CK_TOKEN_INFO token_info;
};
struct _token_choices {
    unsigned int numtokens;
    struct _token_entry *token_array;
};


/*
 * Solaris Kerberos: this is a new function that does not exist yet in the MIT
 * code.
 */
static krb5_error_code
pkinit_prompt_token(krb5_context context,
		    pkinit_identity_crypto_context cctx)
{
    char tmpbuf[4];
    krb5_data reply;
    char *token_prompt = gettext("If you have a smartcard insert it now. "
				 "Press enter to continue");

    reply.data = tmpbuf;
    reply.length = sizeof(tmpbuf);

    /* note, don't care about the reply */
    return (pkinit_prompt_user(context, cctx, &reply, token_prompt, 0));
}

/*
 * Solaris Kerberos: new defines for prompting support.
 */
#define CHOOSE_THIS_TOKEN 0
#define CHOOSE_RESCAN 1
#define CHOOSE_SKIP 2
#define CHOOSE_SEE_NEXT 3

#define RESCAN_TOKENS -1
#define SKIP_TOKENS -2

/*
 * Solaris Kerberos: this is a new function that does not exist yet in the MIT
 * code.
 *
 * This prompts to user for various choices regarding a token to use.  Note
 * that if there is no error, choice will be set to one of:
 * - the token_choices->token_array entry
 * - RESCAN_TOKENS
 * - SKIP_TOKENS
 */
static int
pkinit_choose_tokens(krb5_context context,
		     pkinit_identity_crypto_context cctx,
		     struct _token_choices *token_choices,
		     int *choice)
{
    krb5_error_code r;
    /*
     * Assuming that PAM_MAX_MSG_SIZE is a reasonable restriction. Note that -
     * 2 is to account for the fact that a krb prompter to PAM conv bridge will
     * add ": ".
     */
    char prompt[PAM_MAX_MSG_SIZE - 2];
    char tmpbuf[4];
    char tmplabel[sizeof (token_choices->token_array->token_info.label) + 1];
    krb5_data reply;
    int i, num_used, tmpchoice;

    assert(token_choices != NULL);
    assert(choice != NULL);

    /* Create the menu prompt */

    /* only need to do this once before the for loop */
    reply.data = tmpbuf;

    for (i = 0; i < token_choices->numtokens; i++) {

	trim_token_label(&token_choices->token_array[i].token_info, tmplabel,
			 sizeof (tmplabel));

	if (i == (token_choices->numtokens - 1)) {
	    /* no more smartcards/tokens */
	    if ((num_used = snprintf(prompt, sizeof (prompt),
				     "%s\n%d: %s \"%s\" %s %d\n%d: %s\n%d: %s\n",
				     /*
				      * TRANSLATION_NOTE: Translations of the
				      * following 5 strings must not exceed 450
				      * bytes total.
				      */
				     gettext("Select one of the following and press enter:"),
				     CHOOSE_THIS_TOKEN, gettext("Use smartcard"), tmplabel,
                                     gettext("in slot"), token_choices->token_array[i].slotID,
				     CHOOSE_RESCAN, gettext("Rescan for newly inserted smartcard"),
				     CHOOSE_SKIP, gettext("Skip smartcard authentication")))
		>= sizeof (prompt)) {
		pkiDebug("pkinit_choose_tokens: buffer overflow num_used: %d,"
			 " sizeof prompt: %d\n", num_used, sizeof (prompt));
		krb5_set_error_message(context, EINVAL,
                               gettext("In pkinit_choose_tokens: prompt size"
				      " %d exceeds prompt buffer size %d"),
			       num_used, sizeof(prompt));
		(void) snprintf(prompt, sizeof (prompt), "%s",
			        gettext("Error: PKINIT prompt message is too large for buffer, "
					"please alert the system administrator. Press enter to "
					"continue"));
		reply.length = sizeof(tmpbuf);
		if ((r = pkinit_prompt_user(context, cctx, &reply, prompt, 0)) != 0 )
		    return (r);
		return (EINVAL);
	    }
	} else {
	    if ((num_used = snprintf(prompt, sizeof (prompt),
				     "%s\n%d: %s \"%s\" %s %d\n%d: %s\n%d: %s\n%d: %s\n",
				     /*
				      * TRANSLATION_NOTE: Translations of the
				      * following 6 strings must not exceed 445
				      * bytes total.
				      */
				     gettext("Select one of the following and press enter:"),
				     CHOOSE_THIS_TOKEN, gettext("Use smartcard"), tmplabel,
                                     gettext("in slot"), token_choices->token_array[i].slotID,
				     CHOOSE_RESCAN, gettext("Rescan for newly inserted smartcard"),
				     CHOOSE_SKIP, gettext("Skip smartcard authentication"),
				     CHOOSE_SEE_NEXT, gettext("See next smartcard")))
		>= sizeof (prompt)) {

		pkiDebug("pkinit_choose_tokens: buffer overflow num_used: %d,"
			 " sizeof prompt: %d\n", num_used, sizeof (prompt));
		krb5_set_error_message(context, EINVAL,
				       gettext("In pkinit_choose_tokens: prompt size"
					       " %d exceeds prompt buffer size %d"),
				       num_used, sizeof(prompt));
		(void) snprintf(prompt, sizeof (prompt), "%s",
				gettext("Error: PKINIT prompt message is too large for buffer, "
					"please alert the system administrator. Press enter to "
					"continue"));
		reply.length = sizeof(tmpbuf);
		if ((r = pkinit_prompt_user(context, cctx, &reply, prompt, 0)) != 0 )
		    return (r);
		return (EINVAL);
	    }
	}

        /*
	 * reply.length needs to be reset to length of tmpbuf before calling
	 * prompter
         */
        reply.length = sizeof(tmpbuf);
	if ((r = pkinit_prompt_user(context, cctx, &reply, prompt, 0)) != 0 )
	    return (r);

	if (reply.length == 0) {
	    return (EINVAL);
	} else {
            char *cp = reply.data;
            /* reply better be digits */
            while (*cp != NULL) {
                if (!isdigit(*cp++))
                    return (EINVAL);
            }
	    errno = 0;
	    tmpchoice = (int) strtol(reply.data, (char **)NULL, 10);
	    if (errno != 0)
		return (errno);
	}

	switch (tmpchoice) {
	case CHOOSE_THIS_TOKEN:
	    *choice = i; /* chosen entry of token_choices->token_array */
	    return (0);
	case CHOOSE_RESCAN:
	    *choice = RESCAN_TOKENS; /* rescan for new smartcard */
	    return (0);
	case CHOOSE_SKIP:
	    *choice = SKIP_TOKENS; /* skip smartcard auth */
	    return (0);
	case CHOOSE_SEE_NEXT: /* see next smartcard */
	    continue;
	default:
	    return (EINVAL);
	}
    }

    return (0);
}

/*
 * Solaris Kerberos: this is a new function that does not exist yet in the MIT
 * code.
 *
 * Note, this isn't the best solution to providing a function to check the
 * certs in a token however I wanted to avoid rewriting a bunch of code so I
 * settled for some duplication of processing.
 */
static krb5_error_code
check_load_certs(krb5_context context,
            CK_SESSION_HANDLE session,
	    pkinit_plg_crypto_context plg_cryptoctx,
	    pkinit_req_crypto_context req_cryptoctx,
            pkinit_identity_crypto_context id_cryptoctx,
            krb5_principal princ,
            int do_matching,
            int load_cert)
{
    CK_OBJECT_CLASS cls;
    CK_OBJECT_HANDLE obj;
    CK_ATTRIBUTE attrs[4];
    CK_ULONG count;
    CK_CERTIFICATE_TYPE certtype;
    CK_BYTE_PTR cert = NULL, cert_id = NULL;
    const unsigned char *cp;
    int i, r;
    unsigned int nattrs;
    X509 *x = NULL;

    cls = CKO_CERTIFICATE;
    attrs[0].type = CKA_CLASS;
    attrs[0].pValue = &cls;
    attrs[0].ulValueLen = sizeof cls;

    certtype = CKC_X_509;
    attrs[1].type = CKA_CERTIFICATE_TYPE;
    attrs[1].pValue = &certtype;
    attrs[1].ulValueLen = sizeof certtype;

    nattrs = 2;

    /* If a cert id and/or label were given, use them too */
    if (id_cryptoctx->cert_id_len > 0) {
	attrs[nattrs].type = CKA_ID;
	attrs[nattrs].pValue = id_cryptoctx->cert_id;
	attrs[nattrs].ulValueLen = id_cryptoctx->cert_id_len;
	nattrs++;
    }
    if (id_cryptoctx->cert_label != NULL) {
	attrs[nattrs].type = CKA_LABEL;
	attrs[nattrs].pValue = id_cryptoctx->cert_label;
	attrs[nattrs].ulValueLen = strlen(id_cryptoctx->cert_label);
	nattrs++;
    }

    r = id_cryptoctx->p11->C_FindObjectsInit(session, attrs, nattrs);
    if (r != CKR_OK) {
        pkiDebug("C_FindObjectsInit: %s\n", pkinit_pkcs11_code_to_text(r));
        krb5_set_error_message(context, EINVAL,
                               gettext("PKCS11 error from C_FindObjectsInit: %s"),
                               pkinit_pkcs11_code_to_text(r));
        r = EINVAL;
        goto out;
    }

    for (i = 0; ; i++) {
	if (i >= MAX_CREDS_ALLOWED) {
            r = EINVAL;
            goto out;
        }

	/* Look for x.509 cert */
	/* Solaris Kerberos */
	if ((r = id_cryptoctx->p11->C_FindObjects(session, &obj, 1, &count))
            != CKR_OK || count == 0) {
	    id_cryptoctx->creds[i] = NULL;
	    break;
	}

	/* Get cert and id len */
	attrs[0].type = CKA_VALUE;
	attrs[0].pValue = NULL;
	attrs[0].ulValueLen = 0;

	attrs[1].type = CKA_ID;
	attrs[1].pValue = NULL;
	attrs[1].ulValueLen = 0;

	if ((r = id_cryptoctx->p11->C_GetAttributeValue(session,
                                                        obj,
                                                        attrs,
                                                        2)) != CKR_OK &&
            r != CKR_BUFFER_TOO_SMALL) {
            pkiDebug("C_GetAttributeValue: %s\n", pkinit_pkcs11_code_to_text(r));
	    krb5_set_error_message(context, EINVAL,
				   gettext("Error from PKCS11 C_GetAttributeValue: %s"),
				   pkinit_pkcs11_code_to_text(r));
            r = EINVAL;
            goto out;
        }
	cert = malloc((size_t) attrs[0].ulValueLen + 1);
	if (cert == NULL) {
	    r = ENOMEM;
            goto out;
        }
	cert_id = malloc((size_t) attrs[1].ulValueLen + 1);
	if (cert_id == NULL) {
	    r = ENOMEM;
            goto out;
        }

	/* Read the cert and id off the card */

	attrs[0].type = CKA_VALUE;
	attrs[0].pValue = cert;

	attrs[1].type = CKA_ID;
	attrs[1].pValue = cert_id;

	if ((r = id_cryptoctx->p11->C_GetAttributeValue(session,
		obj, attrs, 2)) != CKR_OK) {
	    pkiDebug("C_GetAttributeValue: %s\n", pkinit_pkcs11_code_to_text(r));
	    krb5_set_error_message(context, EINVAL,
				   gettext("Error from PKCS11 C_GetAttributeValue: %s"),
				   pkinit_pkcs11_code_to_text(r));
	    r = EINVAL;
            goto out;
	}

	pkiDebug("cert %d size %d id %d idlen %d\n", i,
	    (int) attrs[0].ulValueLen, (int) cert_id[0],
	    (int) attrs[1].ulValueLen);

	cp = (unsigned char *) cert;
	x = d2i_X509(NULL, &cp, (int) attrs[0].ulValueLen);
	if (x == NULL) {
	    r = EINVAL;
            goto out;
        }

	id_cryptoctx->creds[i] = malloc(sizeof(struct _pkinit_cred_info));
	if (id_cryptoctx->creds[i] == NULL) {
	    r = ENOMEM;
            goto out;
        }
	id_cryptoctx->creds[i]->cert = x;
	id_cryptoctx->creds[i]->key = NULL;
	id_cryptoctx->creds[i]->cert_id = cert_id;
        cert_id = NULL;
	id_cryptoctx->creds[i]->cert_id_len = attrs[1].ulValueLen;
	free(cert);
        cert = NULL;
    }
    id_cryptoctx->p11->C_FindObjectsFinal(session);

    if (id_cryptoctx->creds[0] == NULL || id_cryptoctx->creds[0]->cert == NULL) {
	r = ENOENT;
    } else if (do_matching){
        /*
         * Do not let pkinit_cert_matching set the primary cert in id_cryptoctx
         * as this will be done later.
         */
        r = pkinit_cert_matching(context, plg_cryptoctx, req_cryptoctx,
                                 id_cryptoctx, princ, FALSE);
    }

out:
    if ((r != 0 || !load_cert) &&
        id_cryptoctx->creds[0] != NULL &&
        id_cryptoctx->creds[0]->cert != NULL) {
        /*
         * If there's an error or load_cert isn't 1 free all the certs loaded
         * onto id_cryptoctx.
         */
        (void) crypto_free_cert_info(context, plg_cryptoctx, req_cryptoctx,
                                     id_cryptoctx);
    }

    if (cert)
        free(cert);

    if (cert_id)
        free(cert_id);

    return (r);
}

/*
 * Solaris Kerberos: this function has been significantly modified to prompt
 * the user in certain cases so defer to this version when resyncing MIT code.
 *
 * pkinit_open_session now does several things including prompting the user if
 * do_matching is set which indicates the code is executing in a client
 * context.  This function fills out a pkinit_identity_crypto_context with a
 * set of certs and a open session if a token can be found that matches all
 * supplied criteria.  If no token is found then the user is prompted one time
 * to insert their token.  If there is more than one token that matches all
 * client criteria the user is prompted to make a choice if in client context.
 * If do_matching is false (KDC context) then the first token matching all
 * server criteria is chosen.
 */
static krb5_error_code
pkinit_open_session(krb5_context context,
                    pkinit_plg_crypto_context plg_cryptoctx,
                    pkinit_req_crypto_context req_cryptoctx,
                    pkinit_identity_crypto_context cctx,
                    krb5_principal princ,
                    int do_matching)
{
    int i, r;
    CK_ULONG count = 0;
    CK_SLOT_ID_PTR slotlist = NULL, tmpslotlist = NULL;
    CK_TOKEN_INFO tinfo;
    krb5_boolean tokenmatch = FALSE;
    CK_SESSION_HANDLE tmpsession = NULL;
    struct _token_choices token_choices;
    int choice = 0;

    if (cctx->session != CK_INVALID_HANDLE)
	return 0; /* session already open */

    /* Load module */
    if (cctx->p11_module == NULL) {
        cctx->p11_module =
            pkinit_C_LoadModule(cctx->p11_module_name, &cctx->p11);
        if (cctx->p11_module == NULL)
            return KRB5KDC_ERR_PREAUTH_FAILED;
    }

    /* Init */
    /* Solaris Kerberos: Don't fail if cryptoki is already initialized */
    r = cctx->p11->C_Initialize(NULL);
    if (r != CKR_OK && r != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
	pkiDebug("C_Initialize: %s\n", pkinit_pkcs11_code_to_text(r));
	krb5_set_error_message(context, KRB5KDC_ERR_PREAUTH_FAILED,
			       gettext("Error from PKCS11 C_Initialize: %s"),
			       pkinit_pkcs11_code_to_text(r));
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }

    (void) memset(&token_choices, 0, sizeof(token_choices));

    /*
     * Solaris Kerberos:
     * If C_Initialize was already called by the process before the pkinit
     * module was loaded then record that fact.
     * "finalize_pkcs11" is used by pkinit_fini_pkcs11 to determine whether
     * or not C_Finalize() should be called.
     */
     cctx->finalize_pkcs11 =
	(r == CKR_CRYPTOKI_ALREADY_INITIALIZED ? FALSE : TRUE);
    /*
     * First make sure that is an applicable slot otherwise fail.
     *
     * Start by getting a count of all slots with or without tokens.
     */

    if ((r = cctx->p11->C_GetSlotList(FALSE, NULL, &count)) != CKR_OK) {
	pkiDebug("C_GetSlotList: %s\n", pkinit_pkcs11_code_to_text(r));
	krb5_set_error_message(context, KRB5KDC_ERR_PREAUTH_FAILED,
	    gettext("Error trying to get PKCS11 slot list: %s"),
	    pkinit_pkcs11_code_to_text(r));
	r = KRB5KDC_ERR_PREAUTH_FAILED;
	goto out;
    }

    if (count == 0) {
	/* There are no slots so bail */
	r = KRB5KDC_ERR_PREAUTH_FAILED;
	krb5_set_error_message(context, r,
			       gettext("No PKCS11 slots found"));
	pkiDebug("pkinit_open_session: no slots, count: %d\n", count);
	goto out;
    } else if (cctx->slotid != PK_NOSLOT) {
	/* See if any of the slots match the specified slotID */
	tmpslotlist = malloc(count * sizeof (CK_SLOT_ID));
	if (tmpslotlist == NULL) {
	    krb5_set_error_message(context, ENOMEM,
				   gettext("Memory allocation error:"));
	    r = KRB5KDC_ERR_PREAUTH_FAILED;
	    goto out;
	}
	if ((r = cctx->p11->C_GetSlotList(FALSE, tmpslotlist, &count)) != CKR_OK) {
	    krb5_set_error_message(context, KRB5KDC_ERR_PREAUTH_FAILED,
				   gettext("Error trying to get PKCS11 slot list: %s"),
				   pkinit_pkcs11_code_to_text(r));
	    pkiDebug("C_GetSlotList: %s\n", pkinit_pkcs11_code_to_text(r));
	    r = KRB5KDC_ERR_PREAUTH_FAILED;
	    goto out;
	}

	for (i = 0; i < count && cctx->slotid != tmpslotlist[i]; i++)
	    continue;

	if (i >= count) {
	    /* no slots match */
	    r = KRB5KDC_ERR_PREAUTH_FAILED;
	    krb5_set_error_message(context, r,
				   gettext("Requested PKCS11 slot ID %d not found"),
				   cctx->slotid);
	    pkiDebug("open_session: no matching slot found for slotID %d\n",
		     cctx->slotid);
	    goto out;
	}
    }

tryagain:
    /* get count of slots that have tokens */
    if ((r = cctx->p11->C_GetSlotList(TRUE, NULL, &count)) != CKR_OK) {
	pkiDebug("C_GetSlotList: %s\n", pkinit_pkcs11_code_to_text(r));
	krb5_set_error_message(context, KRB5KDC_ERR_PREAUTH_FAILED,
			       gettext("Error trying to get PKCS11 slot list: %s"),
			       pkinit_pkcs11_code_to_text(r));
	r = KRB5KDC_ERR_PREAUTH_FAILED;
	goto out;
    }

    if (count == 0) {
	/*
	 * Note, never prompt if !do_matching as this implies KDC side
	 * processing
	 */
	if (!(cctx->p11flags & C_PROMPTED_USER) && do_matching) {
	    /* found slot(s) but no token so prompt and try again */
	    if ((r = pkinit_prompt_token(context, cctx)) == 0) {
		cctx->p11flags |= C_PROMPTED_USER;
		goto tryagain;
	    } else {
		pkiDebug("open_session: prompt for token/smart card failed\n");
		krb5_set_error_message(context, r,
				       gettext("Prompt for token/smart card failed"));
		r = KRB5KDC_ERR_PREAUTH_FAILED;
		goto out;
	    }

	} else {
	    /* already prompted once so bailing */
	    r = KRB5KDC_ERR_PREAUTH_FAILED;
	    krb5_set_error_message(context, r,
				   gettext("No smart card tokens found"));
	    pkiDebug("pkinit_open_session: no token, already prompted\n");
	    goto out;
	}
    }

    if (slotlist != NULL)
	free(slotlist);

    slotlist = malloc(count * sizeof (CK_SLOT_ID));
    if (slotlist == NULL) {
	krb5_set_error_message(context, KRB5KDC_ERR_PREAUTH_FAILED,
			       gettext("Memory allocation error"));
	r = KRB5KDC_ERR_PREAUTH_FAILED;
	goto out;
    }
    /*
     * Solaris Kerberos: get list of PKCS11 slotid's that have tokens.
     */
    if (cctx->p11->C_GetSlotList(TRUE, slotlist, &count) != CKR_OK) {
	krb5_set_error_message(context, KRB5KDC_ERR_PREAUTH_FAILED,
			       gettext("Error trying to get PKCS11 slot list: %s"),
			       pkinit_pkcs11_code_to_text(r));
	pkiDebug("C_GetSlotList: %s\n", pkinit_pkcs11_code_to_text(r));
	r = KRB5KDC_ERR_PREAUTH_FAILED;
	goto out;
    }

    token_choices.numtokens = 0;
    token_choices.token_array = malloc(count * sizeof (*token_choices.token_array));
    if (token_choices.token_array == NULL) {
	r = KRB5KDC_ERR_PREAUTH_FAILED;
	krb5_set_error_message(context, r,
			       gettext("Memory allocation error"));
	goto out;
    }

    /* examine all the tokens */
    for (i = 0; i < count; i++) {
	/*
	 * Solaris Kerberos: if a slotid was specified skip slots that don't
	 * match.
	 */
	if (cctx->slotid != PK_NOSLOT && cctx->slotid != slotlist[i])
	    continue;

	/* Open session */
	if ((r = cctx->p11->C_OpenSession(slotlist[i], CKF_SERIAL_SESSION,
					  NULL, NULL, &tmpsession)) != CKR_OK) {
	    pkiDebug("C_OpenSession: %s\n", pkinit_pkcs11_code_to_text(r));
	    krb5_set_error_message(context, KRB5KDC_ERR_PREAUTH_FAILED,
				   gettext("Error trying to open PKCS11 session: %s"),
				   pkinit_pkcs11_code_to_text(r));
	    r = KRB5KDC_ERR_PREAUTH_FAILED;
	    goto out;
	}

	/* Get token info */
	if ((r = cctx->p11->C_GetTokenInfo(slotlist[i], &tinfo)) != CKR_OK) {
	    pkiDebug("C_GetTokenInfo: %s\n", pkinit_pkcs11_code_to_text(r));
	    krb5_set_error_message(context, KRB5KDC_ERR_PREAUTH_FAILED,
				   gettext("Error trying to read PKCS11 token: %s"),
				   pkinit_pkcs11_code_to_text(r));
	    r = KRB5KDC_ERR_PREAUTH_FAILED;
	    cctx->p11->C_CloseSession(tmpsession);
	    goto out;
	}

	if (cctx->token_label == NULL) {
	    /*
             * If the token doesn't require login to examine the certs then
             * let's check the certs out to see if any match the criteria if
             * any.
             */
	    if (!(tinfo.flags & CKF_LOGIN_REQUIRED)) {
		/*
		 * It's okay to check the certs if we don't have to login but
		 * don't load the certs onto cctx at this point, this will be
		 * done later in this function for the chosen token.
		 */
		if ((r = check_load_certs(context, tmpsession, plg_cryptoctx,
					  req_cryptoctx, cctx, princ,
					  do_matching, 0)) == 0) {
		    tokenmatch = TRUE;
		} else if (r != ENOENT){
		    r = KRB5KDC_ERR_PREAUTH_FAILED;
		    cctx->p11->C_CloseSession(tmpsession);
		    goto out;
		} else {
		    /* ignore ENOENT here */
		    r = 0;
		}
	    } else {
                tokenmatch = TRUE;
            }
	} else {
	    /* + 1 so tokenlabelstr can be \0 terminated */
	    char tokenlabelstr[sizeof (tinfo.label) + 1];

	    /*
	     * Convert token label into C string with trailing white space
	     * trimmed.
	     */
	    trim_token_label(&tinfo, tokenlabelstr, sizeof (tokenlabelstr));

	    pkiDebug("open_session: slotid %d token found: \"%s\", "
		     "cctx->token_label: \"%s\"\n",
		     slotlist[i], tokenlabelstr, (char *) cctx->token_label);

	    if (!strcmp(cctx->token_label, tokenlabelstr)) {
		if (!(tinfo.flags & CKF_LOGIN_REQUIRED)) {
		    /*
		     * It's okay to check the certs if we don't have to login but
		     * don't load the certs onto cctx at this point, this will be
		     * done later in this function for the chosen token.
		     */
		    if ((r = check_load_certs(context, tmpsession, plg_cryptoctx,
					      req_cryptoctx, cctx, princ,
					      do_matching, 0)) == 0) {
			tokenmatch = TRUE;
		    } else if (r != ENOENT){
			r = KRB5KDC_ERR_PREAUTH_FAILED;
			cctx->p11->C_CloseSession(tmpsession);
			goto out;
		    } else {
			/* ignore ENOENT here */
			r = 0;
		    }
		} else {
		    tokenmatch = TRUE;
		}
	    }
	}

	if (tokenmatch == TRUE) {
	    /* add the token to token_choices.token_array */
	    token_choices.token_array[token_choices.numtokens].slotID = slotlist[i];
	    token_choices.token_array[token_choices.numtokens].session = tmpsession;
	    token_choices.token_array[token_choices.numtokens].token_info = tinfo;
	    token_choices.numtokens++;
            /* !do_matching implies we take the first matching token */
            if (!do_matching)
                break;
            else
                tokenmatch = FALSE;
	} else {
	    cctx->p11->C_CloseSession(tmpsession);
	}
    }

    if (token_choices.numtokens == 0) {
	/*
	 * Solaris Kerberos: prompt for token one time if there was no token
         * and do_matching is 1 (see earlier comment about do_matching).
	 */
	if (!(cctx->p11flags & C_PROMPTED_USER) && do_matching) {
	    if ((r = pkinit_prompt_token(context, cctx)) == 0) {
                cctx->p11flags |= C_PROMPTED_USER;
		goto tryagain;
	    } else {
		pkiDebug("open_session: prompt for token/smart card failed\n");
		krb5_set_error_message(context, r,
				       gettext("Prompt for token/smart card failed"));
		r = KRB5KDC_ERR_PREAUTH_FAILED;
		goto out;
	    }
	} else {
	    r = KRB5KDC_ERR_PREAUTH_FAILED;
	    krb5_set_error_message(context, r,
				   gettext("No smart card tokens found"));
	    pkiDebug("open_session: no matching token found\n");
	    goto out;
	}
    } else if (token_choices.numtokens == 1) {
        if ((token_choices.token_array[0].token_info.flags & CKF_LOGIN_REQUIRED) &&
            !(cctx->p11flags & C_PROMPTED_USER) &&
            do_matching) {
            if ((r = pkinit_choose_tokens(context, cctx, &token_choices, &choice)) != 0) {
                pkiDebug("pkinit_open_session: pkinit_choose_tokens failed: %d\n", r);
                r = KRB5KDC_ERR_PREAUTH_FAILED;
                krb5_set_error_message(context, r,
                                       gettext("Prompt for token/smart card failed"));
                goto out;
            }
            if (choice == RESCAN_TOKENS) {
                /* rescan for new smartcard/token */
                for (i = 0; i < token_choices.numtokens; i++) {
                    /* close all sessions */
                    cctx->p11->C_CloseSession(token_choices.token_array[i].session);
                }
                free(token_choices.token_array);
                token_choices.token_array = NULL;
                token_choices.numtokens = 0;
                goto tryagain;
            } else if (choice == SKIP_TOKENS) {
                /* do not use smartcard/token for auth */
                cctx->p11flags |= (C_PROMPTED_USER|C_SKIP_PKCS11_AUTH);
                r = KRB5KDC_ERR_PREAUTH_FAILED;
                goto out;
            } else {
                cctx->p11flags |= C_PROMPTED_USER;
            }
        } else {
            choice = 0; /* really the only choice is the first token_array entry */
        }
    } else if (!(cctx->p11flags & C_PROMPTED_USER) && do_matching) {
	/* > 1 token so present menu of token choices, let the user decide. */
	if ((r = pkinit_choose_tokens(context, cctx, &token_choices, &choice)) != 0) {
	    pkiDebug("pkinit_open_session: pkinit_choose_tokens failed: %d\n", r);
	    r = KRB5KDC_ERR_PREAUTH_FAILED;
	    krb5_set_error_message(context, r,
				   gettext("Prompt for token/smart card failed"));
	    goto out;
	}
	if (choice == RESCAN_TOKENS) {
	    /* rescan for new smartcard/token */
	    for (i = 0; i < token_choices.numtokens; i++) {
		/* close all sessions */
		cctx->p11->C_CloseSession(token_choices.token_array[i].session);
	    }
	    free(token_choices.token_array);
	    token_choices.token_array = NULL;
	    token_choices.numtokens = 0;
	    goto tryagain;
	} else if (choice == SKIP_TOKENS) {
	    /* do not use smartcard/token for auth */
            cctx->p11flags |= (C_PROMPTED_USER|C_SKIP_PKCS11_AUTH);
	    r = KRB5KDC_ERR_PREAUTH_FAILED;
	    goto out;
	} else {
            cctx->p11flags |= C_PROMPTED_USER;
        }
    } else {
        r = KRB5KDC_ERR_PREAUTH_FAILED;
        goto out;
    }

    cctx->slotid = token_choices.token_array[choice].slotID;
    cctx->session = token_choices.token_array[choice].session;

    pkiDebug("open_session: slotid %d (%d of %d)\n", (int) cctx->slotid,
	     i + 1, (int) count);

    /* Login if needed */
    /* Solaris Kerberos: added cctx->p11flags check */
    if ((token_choices.token_array[choice].token_info.flags & CKF_LOGIN_REQUIRED) &&
        !(cctx->p11flags & C_LOGIN_DONE)) {
        r = pkinit_login(context, cctx, &token_choices.token_array[choice].token_info);
    }

    if (r == 0) {
	/* Doing this again to load the certs into cctx. */
	r = check_load_certs(context, cctx->session, plg_cryptoctx,
			     req_cryptoctx, cctx, princ, do_matching, 1);
    }

out:
    if (slotlist != NULL)
	free(slotlist);

    if (tmpslotlist != NULL)
	free(tmpslotlist);

    if (token_choices.token_array != NULL) {
	if (r != 0) {
	    /* close all sessions if there's an error */
	    for (i = 0; i < token_choices.numtokens; i++) {
		cctx->p11->C_CloseSession(token_choices.token_array[i].session);
	    }
	    cctx->session = CK_INVALID_HANDLE;
	} else {
	    /* close sessions not chosen */
	    for (i = 0; i < token_choices.numtokens; i++) {
		if (i != choice) {
		    cctx->p11->C_CloseSession(token_choices.token_array[i].session);
		}
	    }
	}
	free(token_choices.token_array);
    }

    return (r);
}

/*
 * Look for a key that's:
 * 1. private
 * 2. capable of the specified operation (usually signing or decrypting)
 * 3. RSA (this may be wrong but it's all we can do for now)
 * 4. matches the id of the cert we chose
 *
 * You must call pkinit_get_certs before calling pkinit_find_private_key
 * (that's because we need the ID of the private key)
 *
 * pkcs11 says the id of the key doesn't have to match that of the cert, but
 * I can't figure out any other way to decide which key to use.
 *
 * We should only find one key that fits all the requirements.
 * If there are more than one, we just take the first one.
 */

/* ARGSUSED */
krb5_error_code
pkinit_find_private_key(pkinit_identity_crypto_context id_cryptoctx,
			CK_ATTRIBUTE_TYPE usage,
			CK_OBJECT_HANDLE *objp)
{
    CK_OBJECT_CLASS cls;
    CK_ATTRIBUTE attrs[4];
    CK_ULONG count;
    CK_KEY_TYPE keytype;
    RSA *rsa;
    unsigned int nattrs = 0;
    int r;
#ifdef PKINIT_USE_KEY_USAGE
    CK_BBOOL true_false;
#endif

    cls = CKO_PRIVATE_KEY;
    attrs[nattrs].type = CKA_CLASS;
    attrs[nattrs].pValue = &cls;
    attrs[nattrs].ulValueLen = sizeof cls;
    nattrs++;

#ifdef PKINIT_USE_KEY_USAGE
    /*
     * Some cards get confused if you try to specify a key usage,
     * so don't, and hope for the best. This will fail if you have
     * several keys with the same id and different usages but I have
     * not seen this on real cards.
     */
    true_false = TRUE;
    attrs[nattrs].type = usage;
    attrs[nattrs].pValue = &true_false;
    attrs[nattrs].ulValueLen = sizeof true_false;
    nattrs++;
#endif

    keytype = CKK_RSA;
    attrs[nattrs].type = CKA_KEY_TYPE;
    attrs[nattrs].pValue = &keytype;
    attrs[nattrs].ulValueLen = sizeof keytype;
    nattrs++;

    attrs[nattrs].type = CKA_ID;
    attrs[nattrs].pValue = id_cryptoctx->cert_id;
    attrs[nattrs].ulValueLen = id_cryptoctx->cert_id_len;
    nattrs++;

    r = id_cryptoctx->p11->C_FindObjectsInit(id_cryptoctx->session, attrs, nattrs);
    if (r != CKR_OK) {
	pkiDebug("krb5_pkinit_sign_data: C_FindObjectsInit: %s\n",
		 pkinit_pkcs11_code_to_text(r));
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }

    r = id_cryptoctx->p11->C_FindObjects(id_cryptoctx->session, objp, 1, &count);
    id_cryptoctx->p11->C_FindObjectsFinal(id_cryptoctx->session);
    pkiDebug("found %d private keys (%s)\n", (int) count, pkinit_pkcs11_code_to_text(r));

    /*
     * Solaris Kerberos:
     * The CKA_ID may not be correctly set for the private key. For e.g. when
     * storing a private key in softtoken pktool(1) doesn't generate or store
     * a CKA_ID for the private key. Another way to identify the private key is
     * to look for a private key with the same RSA modulus as the public key
     * in the certificate.
     */
    if (r == CKR_OK && count != 1) {

	EVP_PKEY *priv;
	X509 *cert;
	const BIGNUM *rsan;
	unsigned int n_len;
	unsigned char *n_bytes;

	cert = sk_X509_value(id_cryptoctx->my_certs, 0);
	priv = X509_get_pubkey(cert);
	if (priv == NULL) {
    		pkiDebug("Failed to extract pub key from cert\n");
		return KRB5KDC_ERR_PREAUTH_FAILED;
	}

	nattrs = 0;
	cls = CKO_PRIVATE_KEY;
	attrs[nattrs].type = CKA_CLASS;
	attrs[nattrs].pValue = &cls;
	attrs[nattrs].ulValueLen = sizeof cls;
	nattrs++;

#ifdef PKINIT_USE_KEY_USAGE
	true_false = TRUE;
	attrs[nattrs].type = usage;
	attrs[nattrs].pValue = &true_false;
	attrs[nattrs].ulValueLen = sizeof true_false;
	nattrs++;
#endif

	keytype = CKK_RSA;
	attrs[nattrs].type = CKA_KEY_TYPE;
	attrs[nattrs].pValue = &keytype;
	attrs[nattrs].ulValueLen = sizeof keytype;
	nattrs++;

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
	rsa = priv->pkey.rsa;
	rsan = rsa->n;
	n_len = BN_num_bytes(rsan);
#else
	rsa = EVP_PKEY_get0_RSA(priv);
	RSA_get0_key(rsa, &rsan, NULL, NULL);
	n_len = RSA_size(rsa);
#endif
	n_bytes = (unsigned char *) malloc((size_t) n_len);
	if (n_bytes == NULL) {
		return (ENOMEM);
	}

	if (BN_bn2bin(rsan, n_bytes) == 0) {
		free (n_bytes);
		pkiDebug("zero-byte key modulus\n");
		return KRB5KDC_ERR_PREAUTH_FAILED;
	}

	attrs[nattrs].type = CKA_MODULUS;
	attrs[nattrs].ulValueLen = n_len;
	attrs[nattrs].pValue = n_bytes;

	nattrs++;

	r = id_cryptoctx->p11->C_FindObjectsInit(id_cryptoctx->session, attrs, nattrs);
	free (n_bytes);
	if (r != CKR_OK) {
		pkiDebug("krb5_pkinit_sign_data: C_FindObjectsInit: %s\n",
			pkinit_pkcs11_code_to_text(r));
		return KRB5KDC_ERR_PREAUTH_FAILED;
	}

	r = id_cryptoctx->p11->C_FindObjects(id_cryptoctx->session, objp, 1, &count);
	id_cryptoctx->p11->C_FindObjectsFinal(id_cryptoctx->session);
	pkiDebug("found %d private keys (%s)\n", (int) count, pkinit_pkcs11_code_to_text(r));

    }

    if (r != CKR_OK || count < 1)
	return KRB5KDC_ERR_PREAUTH_FAILED;
    return 0;
}
#endif

/* ARGSUSED */
static krb5_error_code
pkinit_decode_data_fs(krb5_context context,
		      pkinit_identity_crypto_context id_cryptoctx,
		      unsigned char *data,
		      unsigned int data_len,
		      unsigned char **decoded_data,
		      unsigned int *decoded_data_len)
{
    if (decode_data(decoded_data, decoded_data_len, data, data_len,
		id_cryptoctx->my_key, sk_X509_value(id_cryptoctx->my_certs,
		id_cryptoctx->cert_index)) <= 0) {
	pkiDebug("failed to decode data\n");
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }
    return 0;
}

#ifndef WITHOUT_PKCS11
#ifdef SILLYDECRYPT
CK_RV
pkinit_C_Decrypt(pkinit_identity_crypto_context id_cryptoctx,
		 CK_BYTE_PTR pEncryptedData,
		 CK_ULONG  ulEncryptedDataLen,
		 CK_BYTE_PTR pData,
		 CK_ULONG_PTR pulDataLen)
{
    CK_RV rv = CKR_OK;

    rv = id_cryptoctx->p11->C_Decrypt(id_cryptoctx->session, pEncryptedData,
	ulEncryptedDataLen, pData, pulDataLen);
    if (rv == CKR_OK) {
	pkiDebug("pData %x *pulDataLen %d\n", (int) pData, (int) *pulDataLen);
    }
    return rv;
}
#endif

static krb5_error_code
pkinit_decode_data_pkcs11(krb5_context context,
			  pkinit_identity_crypto_context id_cryptoctx,
			  unsigned char *data,
			  unsigned int data_len,
			  unsigned char **decoded_data,
			  unsigned int *decoded_data_len)
{
    CK_OBJECT_HANDLE obj;
    CK_ULONG len;
    CK_MECHANISM mech;
    unsigned char *cp;
    int r;

    /*
     * Solaris Kerberos: assume session is open and libpkcs11 funcs have been
     * loaded.
     */
    assert(id_cryptoctx->p11 != NULL);

    /* Solaris Kerberos: Login, if needed, to access private object */
    if (!(id_cryptoctx->p11flags & C_LOGIN_DONE)) {
        CK_TOKEN_INFO tinfo;

        r = id_cryptoctx->p11->C_GetTokenInfo(id_cryptoctx->slotid, &tinfo);
        if (r != 0)
            return r;

        r = pkinit_login(context, id_cryptoctx, &tinfo);
        if (r != 0)
            return r;
    }

    r = pkinit_find_private_key(id_cryptoctx, CKA_DECRYPT, &obj);
    if (r != 0)
	return r;

    mech.mechanism = CKM_RSA_PKCS;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    if ((r = id_cryptoctx->p11->C_DecryptInit(id_cryptoctx->session, &mech,
	    obj)) != CKR_OK) {
	pkiDebug("C_DecryptInit: 0x%x\n", (int) r);
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }
    pkiDebug("data_len = %d\n", data_len);
    cp = (unsigned char *)malloc((size_t) data_len);
    if (cp == NULL)
	return ENOMEM;
    len = data_len;
#ifdef SILLYDECRYPT
    pkiDebug("session %x edata %x edata_len %d data %x datalen @%x %d\n",
	    (int) id_cryptoctx->session, (int) data, (int) data_len, (int) cp,
	    (int) &len, (int) len);
    if ((r = pkinit_C_Decrypt(id_cryptoctx, data, (CK_ULONG) data_len,
	    cp, &len)) != CKR_OK) {
#else
    if ((r = id_cryptoctx->p11->C_Decrypt(id_cryptoctx->session, data,
	    (CK_ULONG) data_len, cp, &len)) != CKR_OK) {
#endif
	pkiDebug("C_Decrypt: %s\n", pkinit_pkcs11_code_to_text(r));
	if (r == CKR_BUFFER_TOO_SMALL)
	    pkiDebug("decrypt %d needs %d\n", (int) data_len, (int) len);
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }
    pkiDebug("decrypt %d -> %d\n", (int) data_len, (int) len);
    *decoded_data_len = len;
    *decoded_data = cp;

    return 0;
}
#endif

krb5_error_code
pkinit_decode_data(krb5_context context,
		   pkinit_identity_crypto_context id_cryptoctx,
		   unsigned char *data,
		   unsigned int data_len,
		   unsigned char **decoded_data,
		   unsigned int *decoded_data_len)
{
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;

    if (id_cryptoctx->pkcs11_method != 1)
	retval = pkinit_decode_data_fs(context, id_cryptoctx, data, data_len,
	    decoded_data, decoded_data_len);
#ifndef WITHOUT_PKCS11
    else
	retval = pkinit_decode_data_pkcs11(context, id_cryptoctx, data,
	    data_len, decoded_data, decoded_data_len);
#endif

    return retval;
}

/* ARGSUSED */
static krb5_error_code
pkinit_sign_data_fs(krb5_context context,
		 pkinit_identity_crypto_context id_cryptoctx,
		 unsigned char *data,
		 unsigned int data_len,
		 unsigned char **sig,
		 unsigned int *sig_len)
{
    if (create_signature(sig, sig_len, data, data_len,
	    id_cryptoctx->my_key) != 0) {
	    pkiDebug("failed to create the signature\n");
	    return KRB5KDC_ERR_PREAUTH_FAILED;
    }
    return 0;
}

#ifndef WITHOUT_PKCS11
static krb5_error_code
pkinit_sign_data_pkcs11(krb5_context context,
			pkinit_identity_crypto_context id_cryptoctx,
			unsigned char *data,
			unsigned int data_len,
			unsigned char **sig,
			unsigned int *sig_len)
{
    CK_OBJECT_HANDLE obj;
    CK_ULONG len;
    CK_MECHANISM mech;
    unsigned char *cp;
    int r;

    /*
     * Solaris Kerberos: assume session is open and libpkcs11 funcs have been
     * loaded.
     */
    assert(id_cryptoctx->p11 != NULL);

    /* Solaris Kerberos: Login, if needed, to access private object */
    if (!(id_cryptoctx->p11flags & C_LOGIN_DONE)) {
        CK_TOKEN_INFO tinfo;

        r = id_cryptoctx->p11->C_GetTokenInfo(id_cryptoctx->slotid, &tinfo);
        if (r != 0)
            return r;

        r = pkinit_login(context, id_cryptoctx, &tinfo);
        if (r != 0)
            return r;
    }

    r = pkinit_find_private_key(id_cryptoctx, CKA_SIGN, &obj);
    if (r != 0 )
	return r;

    mech.mechanism = id_cryptoctx->mech;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    if ((r = id_cryptoctx->p11->C_SignInit(id_cryptoctx->session, &mech,
	    obj)) != CKR_OK) {
	pkiDebug("C_SignInit: %s\n", pkinit_pkcs11_code_to_text(r));
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }

    /*
     * Key len would give an upper bound on sig size, but there's no way to
     * get that. So guess, and if it's too small, re-malloc.
     */
    len = PK_SIGLEN_GUESS;
    cp = (unsigned char *)malloc((size_t) len);
    if (cp == NULL)
	return ENOMEM;

    r = id_cryptoctx->p11->C_Sign(id_cryptoctx->session, data,
				 (CK_ULONG) data_len, cp, &len);
    if (r == CKR_BUFFER_TOO_SMALL || (r == CKR_OK && len >= PK_SIGLEN_GUESS)) {
	free(cp);
	pkiDebug("C_Sign realloc %d\n", (int) len);
	cp = (unsigned char *)malloc((size_t) len);
	r = id_cryptoctx->p11->C_Sign(id_cryptoctx->session, data,
				     (CK_ULONG) data_len, cp, &len);
    }
    if (r != CKR_OK) {
	pkiDebug("C_Sign: %s\n", pkinit_pkcs11_code_to_text(r));
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }
    pkiDebug("sign %d -> %d\n", (int) data_len, (int) len);
    *sig_len = len;
    *sig = cp;

    return 0;
}
#endif

krb5_error_code
pkinit_sign_data(krb5_context context,
		 pkinit_identity_crypto_context id_cryptoctx,
		 unsigned char *data,
		 unsigned int data_len,
		 unsigned char **sig,
		 unsigned int *sig_len)
{
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;

    if (id_cryptoctx == NULL || id_cryptoctx->pkcs11_method != 1)
	retval = pkinit_sign_data_fs(context, id_cryptoctx, data, data_len,
				     sig, sig_len);
#ifndef WITHOUT_PKCS11
    else
	retval = pkinit_sign_data_pkcs11(context, id_cryptoctx, data, data_len,
					 sig, sig_len);
#endif

    return retval;
}


static krb5_error_code
decode_data(unsigned char **out_data, unsigned int *out_data_len,
	    unsigned char *data, unsigned int data_len,
	    EVP_PKEY *pkey, X509 *cert)
{
    /* Solaris Kerberos */
    int len;
    unsigned char *buf = NULL;
    int buf_len = 0;

    /* Solaris Kerberos */
    if (out_data == NULL || out_data_len == NULL)
	return EINVAL;

    if (cert && !X509_check_private_key(cert, pkey)) {
	pkiDebug("private key does not match certificate\n");
	/* Solaris Kerberos */
	return EINVAL;
    }

    buf_len = EVP_PKEY_size(pkey);
    buf = (unsigned char *)malloc((size_t) buf_len + 10);
    if (buf == NULL)
	return ENOMEM;

    len = EVP_PKEY_decrypt_old(buf, data, (int)data_len, pkey);
    if (len <= 0) {
	pkiDebug("unable to decrypt received data (len=%d)\n", data_len);
	/* Solaris Kerberos */
	free(buf);
	return KRB5KRB_ERR_GENERIC;
    }
    *out_data = buf;
    *out_data_len = len;

    return 0;
}

static krb5_error_code
create_signature(unsigned char **sig, unsigned int *sig_len,
		 unsigned char *data, unsigned int data_len, EVP_PKEY *pkey)
{
    krb5_error_code retval = ENOMEM;
    EVP_MD_CTX *md_ctx;

    if (pkey == NULL)
	/* Solaris Kerberos */
	return EINVAL;

    if ((md_ctx = EVP_MD_CTX_new()) == NULL)
	return EINVAL;

    EVP_VerifyInit(md_ctx, EVP_sha1());
    EVP_SignUpdate(md_ctx, data, data_len);
    *sig_len = EVP_PKEY_size(pkey);
    if ((*sig = (unsigned char *) malloc((size_t) *sig_len)) == NULL)
	goto cleanup;
    EVP_SignFinal(md_ctx, *sig, sig_len, pkey);

    retval = 0;

  cleanup:
    EVP_MD_CTX_free(md_ctx);

    return retval;
}

/*
 * Note:
 * This is not the routine the KDC uses to get its certificate.
 * This routine is intended to be called by the client
 * to obtain the KDC's certificate from some local storage
 * to be sent as a hint in its request to the KDC.
 */
/* ARGSUSED */
krb5_error_code
pkinit_get_kdc_cert(krb5_context context,
		    pkinit_plg_crypto_context plg_cryptoctx,
		    pkinit_req_crypto_context req_cryptoctx,
		    pkinit_identity_crypto_context id_cryptoctx,
		    krb5_principal princ)
{
   /* Solaris Kerberos */
    if (req_cryptoctx == NULL)
	return EINVAL;

    req_cryptoctx->received_cert = NULL;
    return 0;
}

/* ARGSUSED */
static krb5_error_code
pkinit_get_certs_pkcs12(krb5_context context,
			  pkinit_plg_crypto_context plg_cryptoctx,
			  pkinit_req_crypto_context req_cryptoctx,
			  pkinit_identity_opts *idopts,
			  pkinit_identity_crypto_context id_cryptoctx,
			  krb5_principal princ)
{
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;
    X509 *x = NULL;
    PKCS12 *p12 = NULL;
    int ret;
    FILE *fp;
    EVP_PKEY *y = NULL;

    if (idopts->cert_filename == NULL) {
	/* Solaris Kerberos: Improved error messages */
	krb5_set_error_message(context, retval,
	    gettext("Failed to get certificate location"));
	pkiDebug("%s: failed to get user's cert location\n", __FUNCTION__);
	goto cleanup;
    }

    if (idopts->key_filename == NULL) {
	/* Solaris Kerberos: Improved error messages */
	krb5_set_error_message(context, retval,
	    gettext("Failed to get private key location"));
	pkiDebug("%s: failed to get user's private key location\n", __FUNCTION__);
	goto cleanup;
    }

    fp = fopen(idopts->cert_filename, "rb");
    if (fp == NULL) {
	/* Solaris Kerberos: Improved error messages */
	krb5_set_error_message(context, retval,
	    gettext("Failed to open PKCS12 file '%s': %s"),
	    idopts->cert_filename, error_message(errno));
	pkiDebug("Failed to open PKCS12 file '%s', error %d\n",
		 idopts->cert_filename, errno);
	goto cleanup;
    }

    p12 = d2i_PKCS12_fp(fp, NULL);
    (void) fclose(fp);
    if (p12 == NULL) {
	krb5_set_error_message(context, retval,
	    gettext("Failed to decode PKCS12 file '%s' contents"),
	    idopts->cert_filename);
	pkiDebug("Failed to decode PKCS12 file '%s' contents\n",
		 idopts->cert_filename);
	goto cleanup;
    }
    /*
     * Try parsing with no pass phrase first.  If that fails,
     * prompt for the pass phrase and try again.
     */
    ret = PKCS12_parse(p12, NULL, &y, &x, NULL);
    if (ret == 0) {
	krb5_data rdat;
	krb5_prompt kprompt;
	krb5_prompt_type prompt_type;
	int r = 0;
	char prompt_string[128];
	char prompt_reply[128];
	/* Solaris Kerberos */
	char *prompt_prefix = gettext("Pass phrase for");

	pkiDebug("Initial PKCS12_parse with no password failed\n");

	if (id_cryptoctx->PIN != NULL) {
		/* Solaris Kerberos: use PIN if set */
		rdat.data = id_cryptoctx->PIN;
		/* note rdat.length isn't needed in this case */
	} else {
		(void) memset(prompt_reply, '\0', sizeof(prompt_reply));
		rdat.data = prompt_reply;
		rdat.length = sizeof(prompt_reply);

		r = snprintf(prompt_string, sizeof(prompt_string), "%s %s",
			     prompt_prefix, idopts->cert_filename);
		if (r >= sizeof(prompt_string)) {
		    pkiDebug("Prompt string, '%s %s', is too long!\n",
			     prompt_prefix, idopts->cert_filename);
		    goto cleanup;
		}
		kprompt.prompt = prompt_string;
		kprompt.hidden = 1;
		kprompt.reply = &rdat;
		prompt_type = KRB5_PROMPT_TYPE_PREAUTH;

		/* PROMPTER_INVOCATION */
		k5int_set_prompt_types(context, &prompt_type);
		r = (*id_cryptoctx->prompter)(context, id_cryptoctx->prompter_data,
					      NULL, NULL, 1, &kprompt);
		k5int_set_prompt_types(context, NULL);
	}

	ret = PKCS12_parse(p12, rdat.data, &y, &x, NULL);
	if (ret == 0) {
	    /* Solaris Kerberos: Improved error messages */
	    krb5_set_error_message(context, retval,
	        gettext("Failed to parse PKCS12 file '%s' with password"),
	        idopts->cert_filename);
	    pkiDebug("Seconde PKCS12_parse with password failed\n");
	    goto cleanup;
	}
    }
    id_cryptoctx->creds[0] = malloc(sizeof(struct _pkinit_cred_info));
    if (id_cryptoctx->creds[0] == NULL)
	goto cleanup;
    id_cryptoctx->creds[0]->cert = x;
#ifndef WITHOUT_PKCS11
    id_cryptoctx->creds[0]->cert_id = NULL;
    id_cryptoctx->creds[0]->cert_id_len = 0;
#endif
    id_cryptoctx->creds[0]->key = y;
    id_cryptoctx->creds[1] = NULL;

    retval = 0;

cleanup:
    if (p12)
	PKCS12_free(p12);
    if (retval) {
	if (x != NULL)
	    X509_free(x);
	if (y != NULL)
	    EVP_PKEY_free(y);
    }
    return retval;
}

static krb5_error_code
pkinit_load_fs_cert_and_key(krb5_context context,
			    pkinit_identity_crypto_context id_cryptoctx,
			    char *certname,
			    char *keyname,
			    int cindex)
{
    krb5_error_code retval;
    X509 *x = NULL;
    EVP_PKEY *y = NULL;

    /* load the certificate */
    retval = get_cert(certname, &x);
    if (retval != 0 || x == NULL) {
	/* Solaris Kerberos: Improved error messages */
	krb5_set_error_message(context, retval,
	    gettext("Failed to load user's certificate from %s: %s"),
	        certname, error_message(retval));
	pkiDebug("failed to load user's certificate from '%s'\n", certname);
	goto cleanup;
    }
    retval = get_key(keyname, &y);
    if (retval != 0 || y == NULL) {
	/* Solaris Kerberos: Improved error messages */
	krb5_set_error_message(context, retval,
	    gettext("Failed to load user's private key from %s: %s"),
	        keyname, error_message(retval));
	pkiDebug("failed to load user's private key from '%s'\n", keyname);
	goto cleanup;
    }

    id_cryptoctx->creds[cindex] = malloc(sizeof(struct _pkinit_cred_info));
    if (id_cryptoctx->creds[cindex] == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }
    id_cryptoctx->creds[cindex]->cert = x;
#ifndef WITHOUT_PKCS11
    id_cryptoctx->creds[cindex]->cert_id = NULL;
    id_cryptoctx->creds[cindex]->cert_id_len = 0;
#endif
    id_cryptoctx->creds[cindex]->key = y;
    id_cryptoctx->creds[cindex+1] = NULL;

    retval = 0;

cleanup:
    if (retval) {
	if (x != NULL)
	    X509_free(x);
	if (y != NULL)
	    EVP_PKEY_free(y);
    }
    return retval;
}

/* ARGSUSED */
static krb5_error_code
pkinit_get_certs_fs(krb5_context context,
			  pkinit_plg_crypto_context plg_cryptoctx,
			  pkinit_req_crypto_context req_cryptoctx,
			  pkinit_identity_opts *idopts,
			  pkinit_identity_crypto_context id_cryptoctx,
			  krb5_principal princ)
{
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;

    if (idopts->cert_filename == NULL) {
	pkiDebug("%s: failed to get user's cert location\n", __FUNCTION__);
	goto cleanup;
    }

    if (idopts->key_filename == NULL) {
	pkiDebug("%s: failed to get user's private key location\n",
		 __FUNCTION__);
	goto cleanup;
    }

    retval = pkinit_load_fs_cert_and_key(context, id_cryptoctx,
					 idopts->cert_filename,
					 idopts->key_filename, 0);
cleanup:
    return retval;
}

/* ARGSUSED */
static krb5_error_code
pkinit_get_certs_dir(krb5_context context,
		     pkinit_plg_crypto_context plg_cryptoctx,
		     pkinit_req_crypto_context req_cryptoctx,
		     pkinit_identity_opts *idopts,
		     pkinit_identity_crypto_context id_cryptoctx,
		     krb5_principal princ)
{
    /* Solaris Kerberos */
    krb5_error_code retval = KRB5KRB_ERR_GENERIC;
    DIR *d = NULL;
    struct dirent *dentry = NULL;
    char certname[1024];
    char keyname[1024];
    int i = 0, len;
    char *dirname, *suf;

    /* Solaris Kerberos */
    if (idopts == NULL)
	return EINVAL;

    if (idopts->cert_filename == NULL) {
	pkiDebug("%s: failed to get user's certificate directory location\n",
		 __FUNCTION__);
	return ENOENT;
    }

    dirname = idopts->cert_filename;
    d = opendir(dirname);
    if (d == NULL) {
	/* Solaris Kerberos: Improved error messages */
	krb5_set_error_message(context, errno,
	    gettext("Failed to open directory \"%s\": %s"),
	    dirname, error_message(errno));
	return errno;
    }

    /*
     * We'll assume that certs are named XXX.crt and the corresponding
     * key is named XXX.key
     */
    while ((i < MAX_CREDS_ALLOWED) &&  (dentry = readdir(d)) != NULL) {
	/* Ignore subdirectories and anything starting with a dot */
#ifdef DT_DIR
	if (dentry->d_type == DT_DIR)
	    continue;
#endif
	if (dentry->d_name[0] == '.')
	    continue;
	len = strlen(dentry->d_name);
	if (len < 5)
	    continue;
	suf = dentry->d_name + (len - 4);
	if (strncmp(suf, ".crt", 4) != 0)
	    continue;

	/* Checked length */
	if (strlen(dirname) + strlen(dentry->d_name) + 2 > sizeof(certname)) {
	    pkiDebug("%s: Path too long -- directory '%s' and file '%s'\n",
		     __FUNCTION__, dirname, dentry->d_name);
	    continue;
	}
	(void) snprintf(certname, sizeof(certname), "%s/%s", dirname, dentry->d_name);
	(void) snprintf(keyname, sizeof(keyname), "%s/%s", dirname, dentry->d_name);
	len = strlen(keyname);
	keyname[len - 3] = 'k';
	keyname[len - 2] = 'e';
	keyname[len - 1] = 'y';

	retval = pkinit_load_fs_cert_and_key(context, id_cryptoctx,
					     certname, keyname, i);
	if (retval == 0) {
	    pkiDebug("%s: Successfully loaded cert (and key) for %s\n",
		     __FUNCTION__, dentry->d_name);
	    i++;
	}
	else
	    continue;
    }

    if (i == 0) {
	/* Solaris Kerberos: Improved error messages */
	krb5_set_error_message(context, ENOENT,
	    gettext("No suitable cert/key pairs found in directory '%s'"),
	    idopts->cert_filename);
	pkiDebug("%s: No cert/key pairs found in directory '%s'\n",
		 __FUNCTION__, idopts->cert_filename);
	retval = ENOENT;
	goto cleanup;
    }

    retval = 0;

  cleanup:
    if (d)
	(void) closedir(d);

    return retval;
}

#ifndef WITHOUT_PKCS11
/* ARGSUSED */
static krb5_error_code
pkinit_get_certs_pkcs11(krb5_context context,
			pkinit_plg_crypto_context plg_cryptoctx,
			pkinit_req_crypto_context req_cryptoctx,
			pkinit_identity_opts *idopts,
			pkinit_identity_crypto_context id_cryptoctx,
			krb5_principal princ,
			int do_matching)
{
#ifdef PKINIT_USE_MECH_LIST
    CK_MECHANISM_TYPE_PTR mechp = NULL;
    CK_MECHANISM_INFO info;
#endif

    if (id_cryptoctx->p11flags & C_SKIP_PKCS11_AUTH)
	return KRB5KDC_ERR_PREAUTH_FAILED;

    /* Copy stuff from idopts -> id_cryptoctx */
    if (idopts->p11_module_name != NULL) {
	id_cryptoctx->p11_module_name = strdup(idopts->p11_module_name);
	if (id_cryptoctx->p11_module_name == NULL)
	    return ENOMEM;
    }
    if (idopts->token_label != NULL) {
	id_cryptoctx->token_label = strdup(idopts->token_label);
	if (id_cryptoctx->token_label == NULL)
	    return ENOMEM;
    }
    if (idopts->cert_label != NULL) {
	id_cryptoctx->cert_label = strdup(idopts->cert_label);
	if (id_cryptoctx->cert_label == NULL)
	    return ENOMEM;
    }
    if (idopts->PIN != NULL) {
	id_cryptoctx->PIN = strdup(idopts->PIN);
	if (id_cryptoctx->PIN == NULL)
	    return ENOMEM;
    }
    /* Convert the ascii cert_id string into a binary blob */
    /*
     * Solaris Kerberos:
     * If the cert_id_string is empty then behave in a similar way to how
     * an empty certlabel is treated - i.e. don't fail now but rather continue
     * as though the certid wasn't specified.
     */
    if (idopts->cert_id_string != NULL && strlen(idopts->cert_id_string) != 0) {
	BIGNUM *bn = NULL;
	BN_hex2bn(&bn, idopts->cert_id_string);
	if (bn == NULL)
	    return ENOMEM;
	id_cryptoctx->cert_id_len = BN_num_bytes(bn);
	id_cryptoctx->cert_id = malloc((size_t) id_cryptoctx->cert_id_len);
	if (id_cryptoctx->cert_id == NULL) {
	    BN_free(bn);
	    return ENOMEM;
	}
	BN_bn2bin(bn, id_cryptoctx->cert_id);
	BN_free(bn);
    }
    id_cryptoctx->slotid = idopts->slotid;
    id_cryptoctx->pkcs11_method = 1;

#ifndef PKINIT_USE_MECH_LIST
    /*
     * We'd like to use CKM_SHA1_RSA_PKCS for signing if it's available, but
     * many cards seems to be confused about whether they are capable of
     * this or not. The safe thing seems to be to ignore the mechanism list,
     * always use CKM_RSA_PKCS and calculate the sha1 digest ourselves.
     */

    id_cryptoctx->mech = CKM_RSA_PKCS;
#else
    if ((r = id_cryptoctx->p11->C_GetMechanismList(id_cryptoctx->slotid, NULL,
	    &count)) != CKR_OK || count <= 0) {
	pkiDebug("C_GetMechanismList: %s\n", pkinit_pkcs11_code_to_text(r));
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }
    mechp = (CK_MECHANISM_TYPE_PTR) malloc(count * sizeof (CK_MECHANISM_TYPE));
    if (mechp == NULL)
	return ENOMEM;
    if ((r = id_cryptoctx->p11->C_GetMechanismList(id_cryptoctx->slotid,
	    mechp, &count)) != CKR_OK) {
	free(mechp);
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }
    for (i = 0; i < count; i++) {
	if ((r = id_cryptoctx->p11->C_GetMechanismInfo(id_cryptoctx->slotid,
		mechp[i], &info)) != CKR_OK) {
	    free(mechp);
	    return KRB5KDC_ERR_PREAUTH_FAILED;
	}
#ifdef DEBUG_MECHINFO
	pkiDebug("mech %x flags %x\n", (int) mechp[i], (int) info.flags);
	if ((info.flags & (CKF_SIGN|CKF_DECRYPT)) == (CKF_SIGN|CKF_DECRYPT))
	    pkiDebug("  this mech is good for sign & decrypt\n");
#endif
	if (mechp[i] == CKM_RSA_PKCS) {
	    /* This seems backwards... */
	    id_cryptoctx->mech =
		(info.flags & CKF_SIGN) ? CKM_SHA1_RSA_PKCS : CKM_RSA_PKCS;
	}
    }
    free(mechp);

    pkiDebug("got %d mechs from card\n", (int) count);
#endif

    return (pkinit_open_session(context, plg_cryptoctx, req_cryptoctx,
                                id_cryptoctx, princ, do_matching));
}
#endif

/* ARGSUSED */
static void
free_cred_info(krb5_context context,
	       pkinit_identity_crypto_context id_cryptoctx,
	       struct _pkinit_cred_info *cred)
{
    if (cred != NULL) {
	if (cred->cert != NULL)
	    X509_free(cred->cert);
	if (cred->key != NULL)
	    EVP_PKEY_free(cred->key);
#ifndef WITHOUT_PKCS11
	if (cred->cert_id != NULL)
	    free(cred->cert_id);
#endif
	free(cred);
    }
}

/* ARGSUSED */
krb5_error_code
crypto_free_cert_info(krb5_context context,
		      pkinit_plg_crypto_context plg_cryptoctx,
		      pkinit_req_crypto_context req_cryptoctx,
		      pkinit_identity_crypto_context id_cryptoctx)
{
    int i;

    if (id_cryptoctx == NULL)
	return EINVAL;

    for (i = 0; i < MAX_CREDS_ALLOWED; i++) {
	if (id_cryptoctx->creds[i] != NULL) {
	    free_cred_info(context, id_cryptoctx, id_cryptoctx->creds[i]);
	    id_cryptoctx->creds[i] = NULL;
	}
    }
    return 0;
}

krb5_error_code
crypto_load_certs(krb5_context context,
		  pkinit_plg_crypto_context plg_cryptoctx,
		  pkinit_req_crypto_context req_cryptoctx,
		  pkinit_identity_opts *idopts,
		  pkinit_identity_crypto_context id_cryptoctx,
		  krb5_principal princ,
		  int do_matching)
{
    krb5_error_code retval;

    switch(idopts->idtype) {
	case IDTYPE_FILE:
	    retval = pkinit_get_certs_fs(context, plg_cryptoctx,
					 req_cryptoctx, idopts,
					 id_cryptoctx, princ);
	    break;
	case IDTYPE_DIR:
	    retval = pkinit_get_certs_dir(context, plg_cryptoctx,
					  req_cryptoctx, idopts,
					  id_cryptoctx, princ);
	    break;
#ifndef WITHOUT_PKCS11
	case IDTYPE_PKCS11:
	    retval = pkinit_get_certs_pkcs11(context, plg_cryptoctx,
					     req_cryptoctx, idopts,
					     id_cryptoctx, princ, do_matching);
	    break;
#endif
	case IDTYPE_PKCS12:
	    retval = pkinit_get_certs_pkcs12(context, plg_cryptoctx,
					     req_cryptoctx, idopts,
					     id_cryptoctx, princ);
		break;
	default:
	    retval = EINVAL;
    }
/* Solaris Kerberos */

    return retval;
}

/*
 * Get number of certificates available after crypto_load_certs()
 */
/* ARGSUSED */
krb5_error_code
crypto_cert_get_count(krb5_context context,
		      pkinit_plg_crypto_context plg_cryptoctx,
		      pkinit_req_crypto_context req_cryptoctx,
		      pkinit_identity_crypto_context id_cryptoctx,
		      int *cert_count)
{
    int count;

    if (id_cryptoctx == NULL || id_cryptoctx->creds[0] == NULL)
	return EINVAL;

    for (count = 0;
	 count <= MAX_CREDS_ALLOWED && id_cryptoctx->creds[count] != NULL;
	 count++);
    *cert_count = count;
    return 0;
}


/*
 * Begin iteration over the certs loaded in crypto_load_certs()
 */
/* ARGSUSED */
krb5_error_code
crypto_cert_iteration_begin(krb5_context context,
			    pkinit_plg_crypto_context plg_cryptoctx,
			    pkinit_req_crypto_context req_cryptoctx,
			    pkinit_identity_crypto_context id_cryptoctx,
			    pkinit_cert_iter_handle *ih_ret)
{
    struct _pkinit_cert_iter_data *id;

    if (id_cryptoctx == NULL || ih_ret == NULL)
	return EINVAL;
    if (id_cryptoctx->creds[0] == NULL)	/* No cred info available */
	return ENOENT;

    id = calloc(1, sizeof(*id));
    if (id == NULL)
	return ENOMEM;
    id->magic = ITER_MAGIC;
    id->plgctx = plg_cryptoctx,
    id->reqctx = req_cryptoctx,
    id->idctx = id_cryptoctx;
    id->index = 0;
    *ih_ret = (pkinit_cert_iter_handle) id;
    return 0;
}

/*
 * End iteration over the certs loaded in crypto_load_certs()
 */
/* ARGSUSED */
krb5_error_code
crypto_cert_iteration_end(krb5_context context,
			  pkinit_cert_iter_handle ih)
{
    struct _pkinit_cert_iter_data *id = (struct _pkinit_cert_iter_data *)ih;

    if (id == NULL || id->magic != ITER_MAGIC)
	return EINVAL;
    free(ih);
    return 0;
}

/*
 * Get next certificate handle
 */
/* ARGSUSED */
krb5_error_code
crypto_cert_iteration_next(krb5_context context,
			   pkinit_cert_iter_handle ih,
			   pkinit_cert_handle *ch_ret)
{
    struct _pkinit_cert_iter_data *id = (struct _pkinit_cert_iter_data *)ih;
    struct _pkinit_cert_data *cd;
    pkinit_identity_crypto_context id_cryptoctx;

    if (id == NULL || id->magic != ITER_MAGIC)
	return EINVAL;

    if (ch_ret == NULL)
	return EINVAL;

    id_cryptoctx = id->idctx;
    if (id_cryptoctx == NULL)
	return EINVAL;

    if (id_cryptoctx->creds[id->index] == NULL)
	return PKINIT_ITER_NO_MORE;

    cd = calloc(1, sizeof(*cd));
    if (cd == NULL)
	return ENOMEM;

    cd->magic = CERT_MAGIC;
    cd->plgctx = id->plgctx;
    cd->reqctx = id->reqctx;
    cd->idctx = id->idctx;
    cd->index = id->index;
    cd->cred = id_cryptoctx->creds[id->index++];
    *ch_ret = (pkinit_cert_handle)cd;
    return 0;
}

/*
 * Release cert handle
 */
/* ARGSUSED */
krb5_error_code
crypto_cert_release(krb5_context context,
		    pkinit_cert_handle ch)
{
    struct _pkinit_cert_data *cd = (struct _pkinit_cert_data *)ch;
    if (cd == NULL || cd->magic != CERT_MAGIC)
	return EINVAL;
    free(cd);
    return 0;
}

/*
 * Get certificate Key Usage and Extended Key Usage
 */
/* ARGSUSED */
static krb5_error_code
crypto_retieve_X509_key_usage(krb5_context context,
			      pkinit_plg_crypto_context plgcctx,
			      pkinit_req_crypto_context reqcctx,
			      X509 *x,
			      unsigned int *ret_ku_bits,
			      unsigned int *ret_eku_bits)
{
    /* Solaris Kerberos */
    int i;
    unsigned int eku_bits = 0, ku_bits = 0;
    ASN1_BIT_STRING *usage = NULL;

    if (ret_ku_bits == NULL && ret_eku_bits == NULL)
	return EINVAL;

    if (ret_eku_bits)
	*ret_eku_bits = 0;
    else {
	pkiDebug("%s: EKUs not requested, not checking\n", __FUNCTION__);
	goto check_kus;
    }

    /* Start with Extended Key usage */
    i = X509_get_ext_by_NID(x, NID_ext_key_usage, -1);
    if (i >= 0) {
	EXTENDED_KEY_USAGE *eku;

	eku = X509_get_ext_d2i(x, NID_ext_key_usage, NULL, NULL);
	if (eku) {
	    for (i = 0; i < sk_ASN1_OBJECT_num(eku); i++) {
		ASN1_OBJECT *certoid;
		certoid = sk_ASN1_OBJECT_value(eku, i);
		if ((OBJ_cmp(certoid, plgcctx->id_pkinit_KPClientAuth)) == 0)
		    eku_bits |= PKINIT_EKU_PKINIT;
		else if ((OBJ_cmp(certoid, OBJ_nid2obj(NID_ms_smartcard_login))) == 0)
		    eku_bits |= PKINIT_EKU_MSSCLOGIN;
		else if ((OBJ_cmp(certoid, OBJ_nid2obj(NID_client_auth))) == 0)
		    eku_bits |= PKINIT_EKU_CLIENTAUTH;
		else if ((OBJ_cmp(certoid, OBJ_nid2obj(NID_email_protect))) == 0)
		    eku_bits |= PKINIT_EKU_EMAILPROTECTION;
	    }
	    EXTENDED_KEY_USAGE_free(eku);
	}
    }
    pkiDebug("%s: returning eku 0x%08x\n", __FUNCTION__, eku_bits);
    *ret_eku_bits = eku_bits;

check_kus:
    /* Now the Key Usage bits */
    if (ret_ku_bits)
	*ret_ku_bits = 0;
    else {
	pkiDebug("%s: KUs not requested, not checking\n", __FUNCTION__);
	goto out;
    }

    /* Make sure usage exists before checking bits */
    usage = X509_get_ext_d2i(x, NID_key_usage, NULL, NULL);
    if (usage) {
	if (!ku_reject(x, X509v3_KU_DIGITAL_SIGNATURE))
	    ku_bits |= PKINIT_KU_DIGITALSIGNATURE;
	if (!ku_reject(x, X509v3_KU_KEY_ENCIPHERMENT))
	    ku_bits |= PKINIT_KU_KEYENCIPHERMENT;
	ASN1_BIT_STRING_free(usage);
    }

    pkiDebug("%s: returning ku 0x%08x\n", __FUNCTION__, ku_bits);
    *ret_ku_bits = ku_bits;

out:
    return 0;
}

/*
 * Return a string format of an X509_NAME in buf where
 * size is an in/out parameter.  On input it is the size
 * of the buffer, and on output it is the actual length
 * of the name.
 * If buf is NULL, returns the length req'd to hold name
 */
static char *
X509_NAME_oneline_ex(X509_NAME * a,
		     char *buf,
		     unsigned int *size,
		     unsigned long flag)
{
  BIO *out = NULL;

  out = BIO_new(BIO_s_mem ());
  if (X509_NAME_print_ex(out, a, 0, flag) > 0) {
    if (buf != NULL && *size > (int) BIO_number_written(out)) {
      (void) memset(buf, 0, *size);
      BIO_read(out, buf, (int) BIO_number_written(out));
    }
    else {
      *size = BIO_number_written(out);
    }
  }
  BIO_free(out);
  return (buf);
}

/*
 * Get certificate information
 */
krb5_error_code
crypto_cert_get_matching_data(krb5_context context,
			      pkinit_cert_handle ch,
			      pkinit_cert_matching_data **ret_md)
{
    krb5_error_code retval;
    pkinit_cert_matching_data *md;
    krb5_principal *pkinit_sans =NULL, *upn_sans = NULL;
    struct _pkinit_cert_data *cd = (struct _pkinit_cert_data *)ch;
    int i, j;
    char buf[DN_BUF_LEN];
    unsigned int bufsize = sizeof(buf);

    if (cd == NULL || cd->magic != CERT_MAGIC)
	return EINVAL;
    if (ret_md == NULL)
	return EINVAL;

    md = calloc(1, sizeof(*md));
    if (md == NULL)
	return ENOMEM;

    md->ch = ch;

    /* get the subject name (in rfc2253 format) */
    X509_NAME_oneline_ex(X509_get_subject_name(cd->cred->cert),
			 buf, &bufsize, XN_FLAG_SEP_COMMA_PLUS);
    md->subject_dn = strdup(buf);
    if (md->subject_dn == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }

    /* get the issuer name (in rfc2253 format) */
    X509_NAME_oneline_ex(X509_get_issuer_name(cd->cred->cert),
			 buf, &bufsize, XN_FLAG_SEP_COMMA_PLUS);
    md->issuer_dn = strdup(buf);
    if (md->issuer_dn == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }

    /* get the san data */
    retval = crypto_retrieve_X509_sans(context, cd->plgctx, cd->reqctx,
				       cd->cred->cert, &pkinit_sans,
				       &upn_sans, NULL);
    if (retval)
	goto cleanup;

    j = 0;
    if (pkinit_sans != NULL) {
	for (i = 0; pkinit_sans[i] != NULL; i++)
	    j++;
    }
    if (upn_sans != NULL) {
	for (i = 0; upn_sans[i] != NULL; i++)
	    j++;
    }
    if (j != 0) {
	md->sans = calloc((size_t)j+1, sizeof(*md->sans));
	if (md->sans == NULL) {
	    retval = ENOMEM;
	    goto cleanup;
	}
	j = 0;
	if (pkinit_sans != NULL) {
	    for (i = 0; pkinit_sans[i] != NULL; i++)
		md->sans[j++] = pkinit_sans[i];
	    free(pkinit_sans);
	}
	if (upn_sans != NULL) {
	    for (i = 0; upn_sans[i] != NULL; i++)
		md->sans[j++] = upn_sans[i];
	    free(upn_sans);
	}
	md->sans[j] = NULL;
    } else
	md->sans = NULL;

    /* get the KU and EKU data */

    retval = crypto_retieve_X509_key_usage(context, cd->plgctx, cd->reqctx,
					   cd->cred->cert,
					   &md->ku_bits, &md->eku_bits);
    if (retval)
	goto cleanup;

    *ret_md = md;
    retval = 0;
cleanup:
    if (retval) {
	if (md)
	    crypto_cert_free_matching_data(context, md);
    }
    return retval;
}

/*
 * Free certificate information
 */
krb5_error_code
crypto_cert_free_matching_data(krb5_context context,
		      pkinit_cert_matching_data *md)
{
    krb5_principal p;
    int i;

    if (md == NULL)
	return EINVAL;
    if (md->subject_dn)
	free(md->subject_dn);
    if (md->issuer_dn)
	free(md->issuer_dn);
    if (md->sans) {
	for (i = 0, p = md->sans[i]; p != NULL; p = md->sans[++i])
	    krb5_free_principal(context, p);
	free(md->sans);
    }
    free(md);
    return 0;
}

/*
 * Make this matching certificate "the chosen one"
 */
/* ARGSUSED */
krb5_error_code
crypto_cert_select(krb5_context context,
		   pkinit_cert_matching_data *md)
{
    struct _pkinit_cert_data *cd;
    if (md == NULL)
	return EINVAL;

    cd = (struct _pkinit_cert_data *)md->ch;
    if (cd == NULL || cd->magic != CERT_MAGIC)
	return EINVAL;

    /* copy the selected cert into our id_cryptoctx */
    if (cd->idctx->my_certs != NULL) {
	sk_X509_pop_free(cd->idctx->my_certs, X509_free);
    }
    cd->idctx->my_certs = sk_X509_new_null();	
    sk_X509_push(cd->idctx->my_certs, cd->cred->cert);
    cd->idctx->creds[cd->index]->cert = NULL;	    /* Don't free it twice */
    cd->idctx->cert_index = 0;

    if (cd->idctx->pkcs11_method != 1) {
	cd->idctx->my_key = cd->cred->key;
	cd->idctx->creds[cd->index]->key = NULL;    /* Don't free it twice */
    }
#ifndef WITHOUT_PKCS11
    else {
	cd->idctx->cert_id = cd->cred->cert_id;
	cd->idctx->creds[cd->index]->cert_id = NULL; /* Don't free it twice */
	cd->idctx->cert_id_len = cd->cred->cert_id_len;
    }
#endif
    return 0;
}

/*
 * Choose the default certificate as "the chosen one"
 */
krb5_error_code
crypto_cert_select_default(krb5_context context,
			   pkinit_plg_crypto_context plg_cryptoctx,
			   pkinit_req_crypto_context req_cryptoctx,
			   pkinit_identity_crypto_context id_cryptoctx)
{
    krb5_error_code retval;
    int cert_count = 0;

    retval = crypto_cert_get_count(context, plg_cryptoctx, req_cryptoctx,
				   id_cryptoctx, &cert_count);
    if (retval) {
	pkiDebug("%s: crypto_cert_get_count error %d, %s\n",
		 __FUNCTION__, retval, error_message(retval));
	goto errout;
    }
    if (cert_count != 1) {
	/* Solaris Kerberos: Improved error messages */
	retval = EINVAL;
	krb5_set_error_message(context, retval,
	    gettext("Failed to select default certificate: "
	        "found %d certs to choose from but there must be exactly one"),
	    cert_count);
	pkiDebug("%s: ERROR: There are %d certs to choose from, "
		 "but there must be exactly one.\n",
		 __FUNCTION__, cert_count);
	goto errout;
    }
    /* copy the selected cert into our id_cryptoctx */
    if (id_cryptoctx->my_certs != NULL) {
	sk_X509_pop_free(id_cryptoctx->my_certs, X509_free);
    }
    id_cryptoctx->my_certs = sk_X509_new_null();	
    sk_X509_push(id_cryptoctx->my_certs, id_cryptoctx->creds[0]->cert);
    id_cryptoctx->creds[0]->cert = NULL;	/* Don't free it twice */
    id_cryptoctx->cert_index = 0;

    if (id_cryptoctx->pkcs11_method != 1) {
	id_cryptoctx->my_key = id_cryptoctx->creds[0]->key;
	id_cryptoctx->creds[0]->key = NULL;	/* Don't free it twice */
    }
#ifndef WITHOUT_PKCS11
    else {
	id_cryptoctx->cert_id = id_cryptoctx->creds[0]->cert_id;
	id_cryptoctx->creds[0]->cert_id = NULL; /* Don't free it twice */
	id_cryptoctx->cert_id_len = id_cryptoctx->creds[0]->cert_id_len;
    }
#endif
    retval = 0;
errout:
    return retval;
}


/* ARGSUSED */
static krb5_error_code
load_cas_and_crls(krb5_context context,
		  pkinit_plg_crypto_context plg_cryptoctx,
		  pkinit_req_crypto_context req_cryptoctx,
		  pkinit_identity_crypto_context id_cryptoctx,
		  int catype,
		  char *filename)
{
    STACK_OF(X509_INFO) *sk = NULL;
    STACK_OF(X509) *ca_certs = NULL;
    STACK_OF(X509_CRL) *ca_crls = NULL;
    BIO *in = NULL;
    /* Solaris Kerberos */
    krb5_error_code retval = KRB5KRB_ERR_GENERIC;
    int i = 0;

    /* If there isn't already a stack in the context,
     * create a temporary one now */
    switch(catype) {
    case CATYPE_ANCHORS:
	if (id_cryptoctx->trustedCAs != NULL)
	    ca_certs = id_cryptoctx->trustedCAs;
	else {
	    ca_certs = sk_X509_new_null();
	    if (ca_certs == NULL)
		return ENOMEM;
	}
	break;
    case CATYPE_INTERMEDIATES:
	if (id_cryptoctx->intermediateCAs != NULL)
	    ca_certs = id_cryptoctx->intermediateCAs;
	else {
	    ca_certs = sk_X509_new_null();
	    if (ca_certs == NULL)
		return ENOMEM;
	}
	break;
    case CATYPE_CRLS:
	if (id_cryptoctx->revoked != NULL)
	    ca_crls = id_cryptoctx->revoked;
	else {
	    ca_crls = sk_X509_CRL_new_null();
	    if (ca_crls == NULL)
		return ENOMEM;
	}
	break;
    default:
	return ENOTSUP;
    }

    if (!(in = BIO_new_file(filename, "r"))) {
	retval = errno;
	pkiDebug("%s: error opening file '%s': %s\n", __FUNCTION__,
		 filename, error_message(errno));
	goto cleanup;
    }

    /* This loads from a file, a stack of x509/crl/pkey sets */
    if ((sk = PEM_X509_INFO_read_bio(in, NULL, NULL, NULL)) == NULL) {
	pkiDebug("%s: error reading file '%s'\n", __FUNCTION__, filename);
	retval = EIO;
	goto cleanup;
    }

    /* scan over the stack created from loading the file contents,
     * weed out duplicates, and push new ones onto the return stack
     */
    for (i = 0; i < sk_X509_INFO_num(sk); i++) {
	X509_INFO *xi = sk_X509_INFO_value(sk, i);
	if (xi != NULL && xi->x509 != NULL && catype != CATYPE_CRLS) {
	    int j = 0, size = sk_X509_num(ca_certs), flag = 0;

	    if (!size) {
		sk_X509_push(ca_certs, xi->x509);
		xi->x509 = NULL;
		continue;
	    }
	    for (j = 0; j < size; j++) {
		X509 *x = sk_X509_value(ca_certs, j);
		flag = X509_cmp(x, xi->x509);
		if (flag == 0)
		    break;
		else
		    continue;
	    }
	    if (flag != 0) {
		sk_X509_push(ca_certs, X509_dup(xi->x509));
	    }
	} else if (xi != NULL && xi->crl != NULL && catype == CATYPE_CRLS) {
	    int j = 0, size = sk_X509_CRL_num(ca_crls), flag = 0;
	    if (!size) {
		sk_X509_CRL_push(ca_crls, xi->crl);
		xi->crl = NULL;
		continue;
	    }
	    for (j = 0; j < size; j++) {
		X509_CRL *x = sk_X509_CRL_value(ca_crls, j);
		flag = X509_CRL_cmp(x, xi->crl);
		if (flag == 0)
		    break;
		else
		    continue;
	    }
	    if (flag != 0) {
		sk_X509_CRL_push(ca_crls, X509_CRL_dup(xi->crl));
	    }
	}
    }

    /* If we added something and there wasn't a stack in the
     * context before, add the temporary stack to the context.
     */
    switch(catype) {
    case CATYPE_ANCHORS:
	if (sk_X509_num(ca_certs) == 0) {
	    pkiDebug("no anchors in file, %s\n", filename);
	    if (id_cryptoctx->trustedCAs == NULL)
		sk_X509_free(ca_certs);
	} else {
	    if (id_cryptoctx->trustedCAs == NULL)
		id_cryptoctx->trustedCAs = ca_certs;
	}
	break;
    case CATYPE_INTERMEDIATES:
	if (sk_X509_num(ca_certs) == 0) {
	    pkiDebug("no intermediates in file, %s\n", filename);
	    if (id_cryptoctx->intermediateCAs == NULL)
		sk_X509_free(ca_certs);
	} else {
	    if (id_cryptoctx->intermediateCAs == NULL)
		id_cryptoctx->intermediateCAs = ca_certs;
	}
	break;
    case CATYPE_CRLS:
	if (sk_X509_CRL_num(ca_crls) == 0) {
	    pkiDebug("no crls in file, %s\n", filename);
	    if (id_cryptoctx->revoked == NULL)
		sk_X509_CRL_free(ca_crls);
	} else {
	    if (id_cryptoctx->revoked == NULL)
		id_cryptoctx->revoked = ca_crls;
	}
	break;
    default:
	/* Should have been caught above! */
	retval = EINVAL;
	goto cleanup;
	/* Solaris Kerberos: removed "break" as it's never reached */
    }

    retval = 0;

  cleanup:
    if (in != NULL)
	BIO_free(in);
    if (sk != NULL)
	sk_X509_INFO_pop_free(sk, X509_INFO_free);

    return retval;
}

static krb5_error_code
load_cas_and_crls_dir(krb5_context context,
		      pkinit_plg_crypto_context plg_cryptoctx,
		      pkinit_req_crypto_context req_cryptoctx,
		      pkinit_identity_crypto_context id_cryptoctx,
		      int catype,
		      char *dirname)
{
    krb5_error_code retval = EINVAL;
    DIR *d = NULL;
    struct dirent *dentry = NULL;
    char filename[1024];

    if (dirname == NULL)
	return EINVAL;

    d = opendir(dirname);
    if (d == NULL)
	return ENOENT;

    while ((dentry = readdir(d))) {
	if (strlen(dirname) + strlen(dentry->d_name) + 2 > sizeof(filename)) {
	    pkiDebug("%s: Path too long -- directory '%s' and file '%s'\n",
		     __FUNCTION__, dirname, dentry->d_name);
	    goto cleanup;
	}
	/* Ignore subdirectories and anything starting with a dot */
#ifdef DT_DIR
	if (dentry->d_type == DT_DIR)
	    continue;
#endif
	if (dentry->d_name[0] == '.')
	    continue;
	(void) snprintf(filename, sizeof(filename), "%s/%s", dirname, dentry->d_name);

	retval = load_cas_and_crls(context, plg_cryptoctx, req_cryptoctx,
				   id_cryptoctx, catype, filename);
	if (retval)
	    goto cleanup;
    }

    retval = 0;

  cleanup:
    if (d != NULL)
	(void) closedir(d);

    return retval;
}

/* ARGSUSED */
krb5_error_code
crypto_load_cas_and_crls(krb5_context context,
			 pkinit_plg_crypto_context plg_cryptoctx,
			 pkinit_req_crypto_context req_cryptoctx,
			 pkinit_identity_opts *idopts,
			 pkinit_identity_crypto_context id_cryptoctx,
			 int idtype,
			 int catype,
			 char *id)
{
    pkiDebug("%s: called with idtype %s and catype %s\n",
	     __FUNCTION__, idtype2string(idtype), catype2string(catype));
    /* Solaris Kerberos: Removed "break"'s as they are never reached */
    switch (idtype) {
    case IDTYPE_FILE:
	return load_cas_and_crls(context, plg_cryptoctx, req_cryptoctx,
				 id_cryptoctx, catype, id);
    case IDTYPE_DIR:
	return load_cas_and_crls_dir(context, plg_cryptoctx, req_cryptoctx,
				     id_cryptoctx, catype, id);
    default:
	return ENOTSUP;
    }
}

static krb5_error_code
create_identifiers_from_stack(STACK_OF(X509) *sk,
			      krb5_external_principal_identifier *** ids)
{
    krb5_error_code retval = ENOMEM;
    int i = 0, sk_size = sk_X509_num(sk);
    krb5_external_principal_identifier **krb5_cas = NULL;
    X509 *x = NULL;
    X509_NAME *xn = NULL;
    unsigned char *p = NULL;
    int len = 0;
    PKCS7_ISSUER_AND_SERIAL *is = NULL;
    char buf[DN_BUF_LEN];

    *ids = NULL;

    krb5_cas =
	malloc((sk_size + 1) * sizeof(krb5_external_principal_identifier *));
    if (krb5_cas == NULL)
	return ENOMEM;
    krb5_cas[sk_size] = NULL;

    for (i = 0; i < sk_size; i++) {
	krb5_cas[i] = (krb5_external_principal_identifier *)malloc(sizeof(krb5_external_principal_identifier));

	x = sk_X509_value(sk, i);

	X509_NAME_oneline(X509_get_subject_name(x), buf, sizeof(buf));
	pkiDebug("#%d cert= %s\n", i, buf);

	/* fill-in subjectName */
	krb5_cas[i]->subjectName.magic = 0;
	krb5_cas[i]->subjectName.length = 0;
	krb5_cas[i]->subjectName.data = NULL;

	xn = X509_get_subject_name(x);
	len = i2d_X509_NAME(xn, NULL);
	if ((p = krb5_cas[i]->subjectName.data = (unsigned char *)malloc((size_t) len)) == NULL)
	    goto cleanup;
	i2d_X509_NAME(xn, &p);
	krb5_cas[i]->subjectName.length = len;

	/* fill-in issuerAndSerialNumber */
	krb5_cas[i]->issuerAndSerialNumber.length = 0;
	krb5_cas[i]->issuerAndSerialNumber.magic = 0;
	krb5_cas[i]->issuerAndSerialNumber.data = NULL;

#ifdef LONGHORN_BETA_COMPAT
if (longhorn == 0) { /* XXX Longhorn doesn't like this */
#endif
	is = PKCS7_ISSUER_AND_SERIAL_new();
	X509_NAME_set(&is->issuer, X509_get_issuer_name(x));
	ASN1_INTEGER_free(is->serial);
	is->serial = ASN1_INTEGER_dup(X509_get_serialNumber(x));
	len = i2d_PKCS7_ISSUER_AND_SERIAL(is, NULL);
	if ((p = krb5_cas[i]->issuerAndSerialNumber.data =
	     (unsigned char *)malloc((size_t) len)) == NULL)
	    goto cleanup;
	i2d_PKCS7_ISSUER_AND_SERIAL(is, &p);
	krb5_cas[i]->issuerAndSerialNumber.length = len;
#ifdef LONGHORN_BETA_COMPAT
}
#endif

	/* fill-in subjectKeyIdentifier */
	krb5_cas[i]->subjectKeyIdentifier.length = 0;
	krb5_cas[i]->subjectKeyIdentifier.magic = 0;
	krb5_cas[i]->subjectKeyIdentifier.data = NULL;


#ifdef LONGHORN_BETA_COMPAT
if (longhorn == 0) {	/* XXX Longhorn doesn't like this */
#endif
	if (X509_get_ext_by_NID(x, NID_subject_key_identifier, -1) >= 0) {
	    ASN1_OCTET_STRING *ikeyid = NULL;

	    if ((ikeyid = X509_get_ext_d2i(x, NID_subject_key_identifier, NULL,
					   NULL))) {
		len = i2d_ASN1_OCTET_STRING(ikeyid, NULL);
		if ((p = krb5_cas[i]->subjectKeyIdentifier.data =
			(unsigned char *)malloc((size_t) len)) == NULL)
		    goto cleanup;
		i2d_ASN1_OCTET_STRING(ikeyid, &p);		
		krb5_cas[i]->subjectKeyIdentifier.length = len;
	    }
	    if (ikeyid != NULL)
		ASN1_OCTET_STRING_free(ikeyid);
	}
#ifdef LONGHORN_BETA_COMPAT
}
#endif
	if (is != NULL) {
	    if (is->issuer != NULL)
		X509_NAME_free(is->issuer);
	    if (is->serial != NULL)
		ASN1_INTEGER_free(is->serial);
	    free(is);
	}
    }

    *ids = krb5_cas;

    retval = 0;
  cleanup:
    if (retval)
	free_krb5_external_principal_identifier(&krb5_cas);

    return retval;
}

/* ARGSUSED */
static krb5_error_code
create_krb5_invalidCertificates(krb5_context context,
				pkinit_plg_crypto_context plg_cryptoctx,
				pkinit_req_crypto_context req_cryptoctx,
				pkinit_identity_crypto_context id_cryptoctx,
				krb5_external_principal_identifier *** ids)
{

    krb5_error_code retval = ENOMEM;
    STACK_OF(X509) *sk = NULL;

    *ids = NULL;
    if (req_cryptoctx->received_cert == NULL)
	return KRB5KDC_ERR_PREAUTH_FAILED;

    sk = sk_X509_new_null();
    if (sk == NULL)
	goto cleanup;
    sk_X509_push(sk, req_cryptoctx->received_cert);

    retval = create_identifiers_from_stack(sk, ids);

    sk_X509_free(sk);
cleanup:

    return retval;
}

/* ARGSUSED */
krb5_error_code
create_krb5_supportedCMSTypes(krb5_context context,
			      pkinit_plg_crypto_context plg_cryptoctx,
			      pkinit_req_crypto_context req_cryptoctx,
			      pkinit_identity_crypto_context id_cryptoctx,
			      krb5_algorithm_identifier ***oids)
{

    krb5_error_code retval = ENOMEM;
    krb5_algorithm_identifier **loids = NULL;
    krb5_octet_data des3oid = {0, 8, (unsigned char *)"\x2A\x86\x48\x86\xF7\x0D\x03\x07" };

    *oids = NULL;
    loids = malloc(2 * sizeof(krb5_algorithm_identifier *));
    if (loids == NULL)
	goto cleanup;
    loids[1] = NULL;
    loids[0] = (krb5_algorithm_identifier *)malloc(sizeof(krb5_algorithm_identifier));
    if (loids[0] == NULL) {
	free(loids);
	goto cleanup;
    }
    retval = pkinit_copy_krb5_octet_data(&loids[0]->algorithm, &des3oid);
    if (retval) {
	free(loids[0]);
	free(loids);
	goto cleanup;
    }
    loids[0]->parameters.length = 0;
    loids[0]->parameters.data = NULL;

    *oids = loids;
    retval = 0;
cleanup:

    return retval;
}

/* ARGSUSED */
krb5_error_code
create_krb5_trustedCertifiers(krb5_context context,
			      pkinit_plg_crypto_context plg_cryptoctx,
			      pkinit_req_crypto_context req_cryptoctx,
			      pkinit_identity_crypto_context id_cryptoctx,
			      krb5_external_principal_identifier *** ids)
{

    /* Solaris Kerberos */
    STACK_OF(X509) *sk = id_cryptoctx->trustedCAs;

    *ids = NULL;
    if (id_cryptoctx->trustedCAs == NULL)
	return KRB5KDC_ERR_PREAUTH_FAILED;

    return create_identifiers_from_stack(sk, ids);

}

/* ARGSUSED */
krb5_error_code
create_krb5_trustedCas(krb5_context context,
		       pkinit_plg_crypto_context plg_cryptoctx,
		       pkinit_req_crypto_context req_cryptoctx,
		       pkinit_identity_crypto_context id_cryptoctx,
		       int flag,
		       krb5_trusted_ca *** ids)
{
    krb5_error_code retval = ENOMEM;
    STACK_OF(X509) *sk = id_cryptoctx->trustedCAs;
    int i = 0, len = 0, sk_size = sk_X509_num(sk);
    krb5_trusted_ca **krb5_cas = NULL;
    X509 *x = NULL;
    char buf[DN_BUF_LEN];
    X509_NAME *xn = NULL;
    unsigned char *p = NULL;
    PKCS7_ISSUER_AND_SERIAL *is = NULL;

    *ids = NULL;
    if (id_cryptoctx->trustedCAs == NULL)
	return KRB5KDC_ERR_PREAUTH_FAILED;

    krb5_cas = malloc((sk_size + 1) * sizeof(krb5_trusted_ca *));
    if (krb5_cas == NULL)
	return ENOMEM;
    krb5_cas[sk_size] = NULL;

    for (i = 0; i < sk_size; i++) {
	krb5_cas[i] = (krb5_trusted_ca *)malloc(sizeof(krb5_trusted_ca));
	if (krb5_cas[i] == NULL)
	    goto cleanup;
	x = sk_X509_value(sk, i);

	X509_NAME_oneline(X509_get_subject_name(x), buf, sizeof(buf));
	pkiDebug("#%d cert= %s\n", i, buf);

	switch (flag) {
	    case choice_trusted_cas_principalName:
		krb5_cas[i]->choice = choice_trusted_cas_principalName;
		break;
	    case choice_trusted_cas_caName:
		krb5_cas[i]->choice = choice_trusted_cas_caName;
		krb5_cas[i]->u.caName.data = NULL;
		krb5_cas[i]->u.caName.length = 0;
		xn = X509_get_subject_name(x);
		len = i2d_X509_NAME(xn, NULL);
		if ((p = krb5_cas[i]->u.caName.data =
		    (unsigned char *)malloc((size_t) len)) == NULL)
		    goto cleanup;
		i2d_X509_NAME(xn, &p);
		krb5_cas[i]->u.caName.length = len;
		break;
	    case choice_trusted_cas_issuerAndSerial:
		krb5_cas[i]->choice = choice_trusted_cas_issuerAndSerial;
		krb5_cas[i]->u.issuerAndSerial.data = NULL;
		krb5_cas[i]->u.issuerAndSerial.length = 0;
		is = PKCS7_ISSUER_AND_SERIAL_new();
		X509_NAME_set(&is->issuer, X509_get_issuer_name(x));
		ASN1_INTEGER_free(is->serial);
		is->serial = ASN1_INTEGER_dup(X509_get_serialNumber(x));
		len = i2d_PKCS7_ISSUER_AND_SERIAL(is, NULL);
		if ((p = krb5_cas[i]->u.issuerAndSerial.data =
		    (unsigned char *)malloc((size_t) len)) == NULL)
		    goto cleanup;
		i2d_PKCS7_ISSUER_AND_SERIAL(is, &p);
		krb5_cas[i]->u.issuerAndSerial.length = len;
		if (is != NULL) {
		    if (is->issuer != NULL)
			X509_NAME_free(is->issuer);
		    if (is->serial != NULL)
			ASN1_INTEGER_free(is->serial);
		    free(is);
		}
		break;
	    default: break;
	}
    }
    retval = 0;
    *ids = krb5_cas;
cleanup:
    if (retval)
	free_krb5_trusted_ca(&krb5_cas);

    return retval;
}

/* ARGSUSED */
krb5_error_code
create_issuerAndSerial(krb5_context context,
		       pkinit_plg_crypto_context plg_cryptoctx,
		       pkinit_req_crypto_context req_cryptoctx,
		       pkinit_identity_crypto_context id_cryptoctx,
		       unsigned char **out,
		       unsigned int *out_len)
{
    unsigned char *p = NULL;
    PKCS7_ISSUER_AND_SERIAL *is = NULL;
    int len = 0;
    krb5_error_code retval = ENOMEM;
    X509 *cert = req_cryptoctx->received_cert;

    *out = NULL;
    *out_len = 0;
    if (req_cryptoctx->received_cert == NULL)
	return 0;

    is = PKCS7_ISSUER_AND_SERIAL_new();
    X509_NAME_set(&is->issuer, X509_get_issuer_name(cert));
    ASN1_INTEGER_free(is->serial);
    is->serial = ASN1_INTEGER_dup(X509_get_serialNumber(cert));
    len = i2d_PKCS7_ISSUER_AND_SERIAL(is, NULL);
    if ((p = *out = (unsigned char *)malloc((size_t) len)) == NULL)
	goto cleanup;
    i2d_PKCS7_ISSUER_AND_SERIAL(is, &p);
    *out_len = len;
    retval = 0;

cleanup:
    X509_NAME_free(is->issuer);
    ASN1_INTEGER_free(is->serial);
    free(is);

    return retval;
}

static int
pkcs7_decrypt(krb5_context context,
	      pkinit_identity_crypto_context id_cryptoctx,
	      PKCS7 *p7,
	      BIO *data)
{
    BIO *tmpmem = NULL;
    /* Solaris Kerberos */
    int i = 0;
    char buf[4096];

    if(p7 == NULL)
	return 0;

    if(!PKCS7_type_is_enveloped(p7)) {
	pkiDebug("wrong pkcs7 content type\n");
	return 0;
    }

    if(!(tmpmem = pkcs7_dataDecode(context, id_cryptoctx, p7))) {
	pkiDebug("unable to decrypt pkcs7 object\n");
	return 0;
    }
/* Solaris Kerberos: Suppress sun studio compiler warning */
#pragma error_messages (off, E_END_OF_LOOP_CODE_NOT_REACHED)
    for(;;) {
	i = BIO_read(tmpmem, buf, sizeof(buf));
	if (i <= 0) break;
	BIO_write(data, buf, i);
	BIO_free_all(tmpmem);
	return 1;
    }
#pragma error_messages (default, E_END_OF_LOOP_CODE_NOT_REACHED)

    return 0;
}

krb5_error_code
pkinit_process_td_trusted_certifiers(
    krb5_context context,
    pkinit_plg_crypto_context plg_cryptoctx,
    pkinit_req_crypto_context req_cryptoctx,
    pkinit_identity_crypto_context id_cryptoctx,
    krb5_external_principal_identifier **krb5_trusted_certifiers,
    int td_type)
{
    krb5_error_code retval = ENOMEM;
    STACK_OF(X509_NAME) *sk_xn = NULL;
    X509_NAME *xn = NULL;
    PKCS7_ISSUER_AND_SERIAL *is = NULL;
    ASN1_OCTET_STRING *id = NULL;
    const unsigned char *p = NULL;
    char buf[DN_BUF_LEN];
    int i = 0;

    if (td_type == TD_TRUSTED_CERTIFIERS)
	pkiDebug("received trusted certifiers\n");
    else
	pkiDebug("received invalid certificate\n");

    sk_xn = sk_X509_NAME_new_null();
    while(krb5_trusted_certifiers[i] != NULL) {
	if (krb5_trusted_certifiers[i]->subjectName.data != NULL) {
	    p = krb5_trusted_certifiers[i]->subjectName.data;
	    xn = d2i_X509_NAME(NULL, &p,
		(int)krb5_trusted_certifiers[i]->subjectName.length);
	    if (xn == NULL)
		goto cleanup;
	    X509_NAME_oneline(xn, buf, sizeof(buf));
	    if (td_type == TD_TRUSTED_CERTIFIERS)
		pkiDebug("#%d cert = %s is trusted by kdc\n", i, buf);
	    else
		pkiDebug("#%d cert = %s is invalid\n", i, buf);
		sk_X509_NAME_push(sk_xn, xn);
	}

	if (krb5_trusted_certifiers[i]->issuerAndSerialNumber.data != NULL) {
	    p = krb5_trusted_certifiers[i]->issuerAndSerialNumber.data;
	    is = d2i_PKCS7_ISSUER_AND_SERIAL(NULL, &p,
		(int)krb5_trusted_certifiers[i]->issuerAndSerialNumber.length);
	    if (is == NULL)
		goto cleanup;
	    X509_NAME_oneline(is->issuer, buf, sizeof(buf));
	    if (td_type == TD_TRUSTED_CERTIFIERS)
		pkiDebug("#%d issuer = %s serial = %ld is trusted bu kdc\n", i,
			 buf, ASN1_INTEGER_get(is->serial));
	    else
		pkiDebug("#%d issuer = %s serial = %ld is invalid\n", i, buf,
			 ASN1_INTEGER_get(is->serial));
	    PKCS7_ISSUER_AND_SERIAL_free(is);
	}

	if (krb5_trusted_certifiers[i]->subjectKeyIdentifier.data != NULL) {
	    p = krb5_trusted_certifiers[i]->subjectKeyIdentifier.data;
	    id = d2i_ASN1_OCTET_STRING(NULL, &p,
		(int)krb5_trusted_certifiers[i]->subjectKeyIdentifier.length);
	    if (id == NULL)
		goto cleanup;
	    /* XXX */
	    ASN1_OCTET_STRING_free(id);
	}
	i++;
    }
    /* XXX Since we not doing anything with received trusted certifiers
     * return an error. this is the place where we can pick a different
     * client certificate based on the information in td_trusted_certifiers
     */
    retval = KRB5KDC_ERR_PREAUTH_FAILED;
cleanup:
    if (sk_xn != NULL)
	sk_X509_NAME_pop_free(sk_xn, X509_NAME_free);

    return retval;
}

static BIO *
pkcs7_dataDecode(krb5_context context,
		 pkinit_identity_crypto_context id_cryptoctx,
		 PKCS7 *p7)
{
    int i = 0;
    unsigned int jj = 0, tmp_len = 0;
    BIO *out=NULL,*etmp=NULL,*bio=NULL;
    unsigned char *tmp=NULL;
    ASN1_OCTET_STRING *data_body=NULL;
    const EVP_CIPHER *evp_cipher=NULL;
    EVP_CIPHER_CTX *evp_ctx=NULL;
    X509_ALGOR *enc_alg=NULL;
    STACK_OF(PKCS7_RECIP_INFO) *rsk=NULL;
/* Solaris Kerberos: Not used */
#if 0
    X509_ALGOR *xalg=NULL;
#endif
    PKCS7_RECIP_INFO *ri=NULL;
    X509 *cert = sk_X509_value(id_cryptoctx->my_certs,
	id_cryptoctx->cert_index);

    p7->state=PKCS7_S_HEADER;

    rsk=p7->d.enveloped->recipientinfo;
    enc_alg=p7->d.enveloped->enc_data->algorithm;
    data_body=p7->d.enveloped->enc_data->enc_data;
    evp_cipher=EVP_get_cipherbyobj(enc_alg->algorithm);
    if (evp_cipher == NULL) {
	PKCS7err(PKCS7_F_PKCS7_DATADECODE,PKCS7_R_UNSUPPORTED_CIPHER_TYPE);
	goto cleanup;
    }
/* Solaris Kerberos: Not used */
#if 0
    xalg=p7->d.enveloped->enc_data->algorithm;
#endif

    if ((etmp=BIO_new(BIO_f_cipher())) == NULL) {
	PKCS7err(PKCS7_F_PKCS7_DATADECODE,ERR_R_BIO_LIB);
	goto cleanup;
    }

    /* It was encrypted, we need to decrypt the secret key
     * with the private key */

    /* Find the recipientInfo which matches the passed certificate
     * (if any)
     */

    if (cert) {
	for (i=0; i<sk_PKCS7_RECIP_INFO_num(rsk); i++) {
	    int tmp_ret = 0;
	    ri=sk_PKCS7_RECIP_INFO_value(rsk,i);
	    tmp_ret = X509_NAME_cmp(ri->issuer_and_serial->issuer,
		X509_get_issuer_name(cert));
	    if (!tmp_ret) {
		tmp_ret = ASN1_INTEGER_cmp(X509_get_serialNumber(cert),
					     ri->issuer_and_serial->serial);
		if (!tmp_ret)
		    break;
	    }
	    ri=NULL;
	}
	if (ri == NULL) {
	    PKCS7err(PKCS7_F_PKCS7_DATADECODE,
		     PKCS7_R_NO_RECIPIENT_MATCHES_CERTIFICATE);
	    goto cleanup;
	}
	
    }

    /* If we haven't got a certificate try each ri in turn */

    if (cert == NULL) {
	for (i=0; i<sk_PKCS7_RECIP_INFO_num(rsk); i++) {
	    ri=sk_PKCS7_RECIP_INFO_value(rsk,i);
	    jj = pkinit_decode_data(context, id_cryptoctx,
		(unsigned char *)ASN1_STRING_get0_data(ri->enc_key),
		ASN1_STRING_length(ri->enc_key),
		&tmp, &tmp_len);
	    if (jj) {
		PKCS7err(PKCS7_F_PKCS7_DATADECODE, ERR_R_EVP_LIB);
		goto cleanup;
	    }

	    if (!jj && tmp_len > 0) {
		jj = tmp_len;
		break;
	    }

	    ERR_clear_error();
	    ri = NULL;
	}

	if (ri == NULL) {
	    PKCS7err(PKCS7_F_PKCS7_DATADECODE,PKCS7_R_NO_RECIPIENT_MATCHES_CERTIFICATE);
	    goto cleanup;
	}
    }
    else {
	jj = pkinit_decode_data(context, id_cryptoctx,
	    (unsigned char *)ASN1_STRING_get0_data(ri->enc_key),
	    ASN1_STRING_length(ri->enc_key),
	    &tmp, &tmp_len);
	/* Solaris Kerberos: tmp_len is unsigned. Cannot be < 0 */
	if (jj || tmp_len == 0) {
	    PKCS7err(PKCS7_F_PKCS7_DATADECODE, ERR_R_EVP_LIB);
	    goto cleanup;
	}
	jj = tmp_len;
    }

    evp_ctx=NULL;
    BIO_get_cipher_ctx(etmp,&evp_ctx);
    if (EVP_CipherInit_ex(evp_ctx,evp_cipher,NULL,NULL,NULL,0) <= 0)
	goto cleanup;
    if (EVP_CIPHER_asn1_to_param(evp_ctx,enc_alg->parameter) < 0)
	goto cleanup;

    if (jj != EVP_CIPHER_CTX_key_length(evp_ctx)) {
	/* Some S/MIME clients don't use the same key
	 * and effective key length. The key length is
	 * determined by the size of the decrypted RSA key.
	 */
	if(!EVP_CIPHER_CTX_set_key_length(evp_ctx, (int)jj)) {
	    PKCS7err(PKCS7_F_PKCS7_DATADECODE,
		     PKCS7_R_DECRYPT_ERROR);
	    goto cleanup;
	}
    }
    if (EVP_CipherInit_ex(evp_ctx,NULL,NULL,tmp,NULL,0) <= 0)
	goto cleanup;

    OPENSSL_cleanse(tmp,jj);

    if (out == NULL)
	out=etmp;
    else
	BIO_push(out,etmp);
    etmp=NULL;

    if (data_body->length > 0)
	bio = BIO_new_mem_buf(data_body->data, data_body->length);
    else {
	bio=BIO_new(BIO_s_mem());
	BIO_set_mem_eof_return(bio,0);
    }
    BIO_push(out,bio);
    bio=NULL;

    /* Solaris Kerberos */
    goto out;

cleanup:
	if (out != NULL) BIO_free_all(out);
	if (etmp != NULL) BIO_free_all(etmp);
	if (bio != NULL) BIO_free_all(bio);
	out=NULL;

out:
    if (tmp != NULL)
	free(tmp);

    return(out);
}

static krb5_error_code
der_decode_data(unsigned char *data, long data_len,
		unsigned char **out, long *out_len)
{
    /* Solaris Kerberos */
    krb5_error_code retval = KRB5KRB_ERR_GENERIC;
    ASN1_OCTET_STRING *s = NULL;
    const unsigned char *p = data;

    if ((s = d2i_ASN1_BIT_STRING(NULL, &p, data_len)) == NULL)
	goto cleanup;
    *out_len = s->length;
    if ((*out = (unsigned char *) malloc((size_t) *out_len + 1)) == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }
    (void) memcpy(*out, s->data, (size_t) s->length);
    (*out)[s->length] = '\0';

    retval = 0;
  cleanup:
    if (s != NULL)
	ASN1_OCTET_STRING_free(s);

    return retval;
}


#ifdef DEBUG_DH
static void
print_dh(DH * dh, char *msg)
{
    BIO *bio_err = NULL;

    bio_err = BIO_new(BIO_s_file());
    BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    if (msg)
	BIO_puts(bio_err, (const char *)msg);
    if (dh)
	DHparams_print(bio_err, dh);

    BN_print(bio_err, dh->q);
    BIO_puts(bio_err, (const char *)"\n");
    BIO_free(bio_err);

}

static void
print_pubkey(BIGNUM * key, char *msg)
{
    BIO *bio_err = NULL;

    bio_err = BIO_new(BIO_s_file());
    BIO_set_fp(bio_err, stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    if (msg)
	BIO_puts(bio_err, (const char *)msg);
    if (key)
	BN_print(bio_err, key);
    BIO_puts(bio_err, "\n");

    BIO_free(bio_err);

}
#endif

/*
 * Solaris Kerberos:
 * Error message generation has changed so gettext() can be used
 */
#if 0
static char *
pkinit_pkcs11_code_to_text(int err)
{
    int i;
    static char uc[64];

    for (i = 0; pkcs11_errstrings[i].text != NULL; i++)
	if (pkcs11_errstrings[i].code == err)
	    break;
    if (pkcs11_errstrings[i].text != NULL)
	return (pkcs11_errstrings[i].text);
    snprintf(uc, 64, gettext("unknown code 0x%x"), err);
    return (uc);
}
#endif

static char *
pkinit_pkcs11_code_to_text(int err) {
	return pkcs11_error_table(err);
}
