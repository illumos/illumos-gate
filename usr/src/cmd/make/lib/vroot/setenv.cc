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
 * Copyright 1994 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */


#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern	char	**environ;

static	short	setenv_made_new_vector= 0;

char *setenv(char *name, char *value)
{	char *p= NULL, **q;
	int length= 0, vl;

	if ((p= getenv(name)) == NULL) {	/* Allocate new vector */
		for (q= environ; *q != NULL; q++, length++);
		q= (char **)malloc((unsigned)(sizeof(char *)*(length+2)));
                memcpy(((char *)q)+sizeof(char *), (char *)environ, sizeof(char *)*(length+1));
		if (setenv_made_new_vector++)
			free((char *)environ);
		length= strlen(name);
		environ= q;}
	else { /* Find old slot */
		length= strlen(name);
		for (q= environ; *q != NULL; q++)
			if (!strncmp(*q, name, length))
				break;};
	vl= strlen(value);
	if (!p || (length+vl+1 > strlen(p)))
		*q= p= (char *) malloc((unsigned)(length+vl+2));
	else
		p= *q;
	(void)strcpy(p, name); p+= length;
	*p++= '=';
	(void)strcpy(p, value);
	return(value);
}
