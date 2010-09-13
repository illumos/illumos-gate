/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * valid_srecord.c: to get and check an S-record string from a file
 * (firmware image to be downloaded to the service processor)
 */

#include <stdio.h>
#include <string.h>

#include "adm.h"


static unsigned long
ADM_string_to_long(char *s, int chars)
{
	unsigned long val = 0;

	while (chars--) {
		val = val << 4;
		if ((*s >= '0') && (*s <= '9'))
			val += *s - '0';
		else if ((*s >= 'a') && (*s <= 'f'))
			val += *s - 'a' + 10;
		else if ((*s >= 'A') && (*s <= 'F'))
			val += *s - 'A' + 10;
		s++;
	}
	return (val);
}


int
ADM_Valid_srecord(FILE  *FilePtr)
{
	static char	Line[ADM_LINE_SIZE];
	char		*CurrentChar;
	int		SrecordLength;
	int		Sum;


	if (fgets(Line, ADM_LINE_SIZE, FilePtr) == NULL)
		return (SREC_ERR_LINE_TOO_BIG);

	rewind(FilePtr);

	if (strlen(Line) < 4)
		return (SREC_ERR_LINE_TOO_SMALL);

	/* Check first two characters for validity */
	if ((Line[0] != 'S') || (Line[1] < '0') || (Line[1] > '9'))
		return (SREC_ERR_BAD_HEADER);

	/* Next check the length for validity */
	SrecordLength = ADM_string_to_long(Line+2, 2);
	if (SrecordLength > ((strlen(Line) - 4) / 2))
		return (SREC_ERR_WRONG_LENGTH);

	/* Check the checksum. */
	CurrentChar	= &Line[2];	/* Skip s-record header */
	SrecordLength	+= 1;		/* Include checksum */
	Sum		= 0;
	while (SrecordLength--) {
		Sum		+= ADM_string_to_long(CurrentChar, 2);
		CurrentChar	+= 2;
	}

	if ((Sum & 0xFF) != 0xFF)
		return (SREC_ERR_BAD_CRC); /* checksum failed */
	else
		return (SREC_OK); /* checksum passed */
}
