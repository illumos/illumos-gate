/*
 *
 * Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 *
 * Comments:   
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static char	hexdig[] = "0123456789abcdef";

char* hexa_print(char *aString, int aLen)
{
	char *res;
	int i =0;
	
	if ((res = (char *)calloc (aLen*2 + 1, 1 )) == NULL){
		return (NULL);
	}
	for (;;){
		if (aLen < 1)
			break;
		res[i] = hexdig[ ( *aString & 0xf0 ) >> 4 ];
		res[i + 1] = hexdig[ *aString & 0x0f ];
		i+= 2;
		aLen--;
		aString++;
	}
	return (res);
}


static int
unhex( char c )
{
        return( c >= '0' && c <= '9' ? c - '0'
            : c >= 'A' && c <= 'F' ? c - 'A' + 10
            : c - 'a' + 10 );
}

char * hexa2str(char *anHexaStr, int *aResLen) {
	int theLen = 0;
	char *theRes = malloc(strlen(anHexaStr) /2 + 1);

	while (isxdigit(*anHexaStr)){
		theRes[theLen] = unhex(*anHexaStr) << 4;
		if (++anHexaStr != '\0'){
			theRes[theLen] += unhex(*anHexaStr);
			anHexaStr++;
		}
		theLen++;
	}
	theRes[theLen] = '\0';
	* aResLen = theLen;
	return (theRes);
}
