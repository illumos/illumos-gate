/*
 * -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*-
 *
 * The contents of this file are subject to the Netscape Public License
 * Version 1.0 (the "NPL"); you may not use this file except in
 * compliance with the NPL.  You may obtain a copy of the NPL at
 * http://www.mozilla.org/NPL/
 *
 * Software distributed under the NPL is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the NPL
 * for the specific language governing rights and limitations under the
 * NPL.
 *
 * The Initial Developer of the Original Code is Netscape
 * Communications Corporation. Portions created by Netscape are
 * Copyright (C) 1998-1999 Netscape Communications Corporation. All
 * Rights Reserved.
 */

/*
 * Copyright (c) 1990 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */
/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"



#ifndef _KMFBER_INT_H
#define	_KMFBER_INT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>

#include <malloc.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>

#include <memory.h>
#include <string.h>

typedef struct seqorset {
	ber_len_t	sos_clen;
	ber_tag_t	sos_tag;
	char		*sos_first;
	char		*sos_ptr;
	struct seqorset	*sos_next;
} Seqorset;
#define	NULLSEQORSET	((Seqorset *) 0)

#define	SOS_STACK_SIZE 8 /* depth of the pre-allocated sos structure stack */

struct berelement {
	char		*ber_buf;
	char		*ber_ptr;
	char		*ber_end;
	struct seqorset	*ber_sos;
	ber_tag_t	ber_tag;
	ber_len_t	ber_len;
	int		ber_usertag;
	char		ber_options;
	char		*ber_rwptr;
	BERTranslateProc ber_encode_translate_proc;
	BERTranslateProc ber_decode_translate_proc;
	int		ber_flags;
#define	KMFBER_FLAG_NO_FREE_BUFFER	1	/* don't free ber_buf */
	int		ber_sos_stack_posn;
	Seqorset	ber_sos_stack[SOS_STACK_SIZE];
};

/* function prototypes */
void ber_err_print(char *data);

#define	THEMEMCPY(d, s, n)	memmove(d, s, n)

#ifdef SAFEMEMCPY
#undef SAFEMEMCPY
#define	SAFEMEMCPY(d, s, n) memmove(d, s, n);
#endif

/* allow the library to access the debug variable */

#ifdef KMFBER_DEBUG
extern int kmfber_debug;
#endif

#ifdef __cplusplus
}
#endif
#endif /* _KMFBER_INT_H */
