/*
 *
 * Copyright 1999 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 *
 * Comments:   
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef _SEC_H_
#define _SEC_H_

#include <sys/types.h>
#include <md5.h>

void hmac_md5(unsigned char *text, int text_len, unsigned char *key,
	int key_len, unsigned char *digest);

char *hexa_print(unsigned char *aString, int aLen);
char *hexa2str(char *anHexaStr, int *aResLen);

#endif /* _SEC_H_ */
