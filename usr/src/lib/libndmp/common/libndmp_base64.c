/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * BSD 3 Clause License
 *
 * Copyright (c) 2007, The Storage Networking Industry Association.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 	- Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *
 * 	- Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in
 *	  the documentation and/or other materials provided with the
 *	  distribution.
 *
 *	- Neither the name of The Storage Networking Industry Association (SNIA)
 *	  nor the names of its contributors may be used to endorse or promote
 *	  products derived from this software without specific prior written
 *	  permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/* Copyright 2014 Nexenta Systems, Inc.  All rights reserved. */

#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <libndmp.h>

#define	NDMP_ENC_LEN	1024
#define	NDMP_DEC_LEN	256

static boolean_t ndmp_is_base64(unsigned char);

static char *b64_data =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static boolean_t
ndmp_is_base64(unsigned char c)
{
	return (isalnum(c) || (c == '+') || (c == '/'));
}

/* caller should use the encoded string and then free the string. */
char *
ndmp_base64_encode(const char *str_to_encode)
{
	int ret_cnt = 0;
	int i = 0, j = 0;
	char arr_3[3], arr_4[4];
	int len = strlen(str_to_encode);
	char *ret = malloc(NDMP_ENC_LEN);

	if (ret == NULL) {
		ndmp_errno = ENDMP_MEM_ALLOC;
		return (NULL);
	}

	while (len--) {
		arr_3[i++] = *(str_to_encode++);
		if (i == 3) {
			arr_4[0] = (arr_3[0] & 0xfc) >> 2;
			arr_4[1] = ((arr_3[0] & 0x03) << 4) +
			    ((arr_3[1] & 0xf0) >> 4);
			arr_4[2] = ((arr_3[1] & 0x0f) << 2) +
			    ((arr_3[2] & 0xc0) >> 6);
			arr_4[3] = arr_3[2] & 0x3f;

			for (i = 0; i < 4; i++)
				ret[ret_cnt++] = b64_data[arr_4[i]];
			i = 0;
		}
	}

	if (i) {
		for (j = i; j < 3; j++)
			arr_3[j] = '\0';

		arr_4[0] = (arr_3[0] & 0xfc) >> 2;
		arr_4[1] = ((arr_3[0] & 0x03) << 4) +
		    ((arr_3[1] & 0xf0) >> 4);
		arr_4[2] = ((arr_3[1] & 0x0f) << 2) +
		    ((arr_3[2] & 0xc0) >> 6);
		arr_4[3] = arr_3[2] & 0x3f;

		for (j = 0; j < (i + 1); j++)
			ret[ret_cnt++] = b64_data[arr_4[j]];

		while (i++ < 3)
			ret[ret_cnt++] = '=';
	}

	ret[ret_cnt++] = '\0';
	return (ret);
}

char *
ndmp_base64_decode(const char *encoded_str)
{
	int len = strlen(encoded_str);
	int i = 0, j = 0;
	int en_ind = 0;
	char arr_4[4], arr_3[3];
	int ret_cnt = 0;
	char *ret = malloc(NDMP_DEC_LEN);
	char *p;

	if (ret == NULL) {
		ndmp_errno = ENDMP_MEM_ALLOC;
		return (NULL);
	}

	while (len-- && (encoded_str[en_ind] != '=') &&
	    ndmp_is_base64(encoded_str[en_ind])) {
		arr_4[i++] = encoded_str[en_ind];
		en_ind++;
		if (i == 4) {
			for (i = 0; i < 4; i++) {
				if ((p = strchr(b64_data, arr_4[i])) == NULL) {
					free(ret);
					return (NULL);
				}

				arr_4[i] = (int)(p - b64_data);
			}

			arr_3[0] = (arr_4[0] << 2) +
			    ((arr_4[1] & 0x30) >> 4);
			arr_3[1] = ((arr_4[1] & 0xf) << 4) +
			    ((arr_4[2] & 0x3c) >> 2);
			arr_3[2] = ((arr_4[2] & 0x3) << 6) +
			    arr_4[3];

			for (i = 0; i < 3; i++)
				ret[ret_cnt++] = arr_3[i];

			i = 0;
		}
	}

	if (i) {
		for (j = i; j < 4; j++)
			arr_4[j] = 0;

		for (j = 0; j < 4; j++) {
			if ((p = strchr(b64_data, arr_4[j])) == NULL) {
				free(ret);
				return (NULL);
			}

			arr_4[j] = (int)(p - b64_data);
		}
		arr_3[0] = (arr_4[0] << 2) +
		    ((arr_4[1] & 0x30) >> 4);
		arr_3[1] = ((arr_4[1] & 0xf) << 4) +
		    ((arr_4[2] & 0x3c) >> 2);
		arr_3[2] = ((arr_4[2] & 0x3) << 6) +
		    arr_4[3];
		for (j = 0; j < (i - 1); j++)
			ret[ret_cnt++] = arr_3[j];
	}

	ret[ret_cnt++] = '\0';
	return (ret);
}
