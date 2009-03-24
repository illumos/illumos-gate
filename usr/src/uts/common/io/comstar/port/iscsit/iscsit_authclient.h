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
#ifndef _ISCSIT_AUTHCLIENT_H_
#define	_ISCSIT_AUTHCLIENT_H_

#define	ISCSI_AUTH_PASSED	0
#define	ISCSI_AUTH_FAILED	1

enum { iscsitAuthStringMaxLength = 256 };

enum { AuthStringMaxLength = 256 };
enum { AuthStringBlockMaxLength = 1024 };
enum { AuthLargeBinaryMaxLength = 1024 };

enum { iscsitAuthChapResponseLength = 16 };

enum { iscsitAuthMethodMaxCount = 2 };

enum { iscsitAuthChapAlgorithmMd5 = 5 };

enum {
	AKT_CHAP_A = 0,
	AKT_CHAP_I,
	AKT_CHAP_C,
	AKT_CHAP_N,
	AKT_CHAP_R,
	AUTH_KEY_TYPE_MAX
};

typedef union auth_value {
	uint32_t	numeric;
	char		*string;
	unsigned char	*binary;
} auth_value_t;

typedef struct auth_key {
	unsigned char	present;
	unsigned int	len;
	auth_value_t	value;
} auth_key_t;

typedef struct iscsit_auth_key_block {
	auth_key_t	key[AUTH_KEY_TYPE_MAX];
} auth_key_block_t;

typedef struct auth_large_binary {
	unsigned char largeBinary[AuthLargeBinaryMaxLength];
} auth_large_binary_t;

typedef enum {
	AM_CHAP = 1, /* keep 0 as invalid */
	AM_KRB5,
	AM_SPKM1,
	AM_SPKM2,
	AM_SRP,
	AM_NONE
} iscsit_auth_method_t;

typedef enum {
	/* authentication phase start status */
	AP_AM_UNDECIDED = 0,
	AP_AM_PROPOSED,
	AP_AM_DECIDED,

	/* authentication phase for chap */
	AP_CHAP_A_WAITING,
	AP_CHAP_A_RCVD,
	AP_CHAP_R_WAITING,
	AP_CHAP_R_RCVD,

	/* authentication phase for kerberos */
	AP_KRB_REQ_WAITING,
	AP_KRB_REQ_RCVD,

	/* authentication phase done */
	AP_DONE
} iscsit_auth_phase_t;

typedef struct iscsit_auth_client {
	iscsit_auth_phase_t	phase;
	iscsit_auth_method_t	negotiatedMethod;

	auth_large_binary_t	auth_send_binary_block;

	auth_key_block_t	recvKeyBlock;
	auth_key_block_t	sendKeyBlock;
} iscsit_auth_client_t;

void
client_set_numeric_data(auth_key_block_t *keyBlock,
    int key_type,
    uint32_t numeric);

void
client_set_string_data(auth_key_block_t *keyBlock,
    int key_type,
    char *string);

void
client_set_binary_data(auth_key_block_t *keyBlock,
    int key_type,
    unsigned char *binary, unsigned int len);

void
client_get_numeric_data(auth_key_block_t *keyBlock,
    int key_type,
    uint32_t *numeric);

void
client_get_string_data(auth_key_block_t *keyBlock,
    int key_type,
    char **string);

void
client_get_binary_data(auth_key_block_t *keyBlock,
    int key_type,
    unsigned char **binary, unsigned int *len);

int
client_auth_key_present(auth_key_block_t *keyBlock,
    int key_type);

void
client_compute_chap_resp(uchar_t *resp,
    unsigned int chap_i,
    uint8_t *password, int password_len,
    uchar_t *chap_c, unsigned int challenge_len);

int
client_verify_chap_resp(char *target_chap_name, char *initiator_chap_name,
    uint8_t *password, int password_len,
    unsigned int chap_i, uchar_t *chap_c, unsigned int challenge_len,
    uchar_t *chap_r, unsigned int resp_len);

void
auth_random_set_data(uchar_t *data, unsigned int length);

#endif /* _ISCSIT_AUTHCLIENT_H_ */
