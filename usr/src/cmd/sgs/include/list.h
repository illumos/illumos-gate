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
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 *
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * This file maintains an old style of list processing that is required by
 * librtld_db to iterate over older core files/process images.
 */
#ifndef	_LIST_H
#define	_LIST_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/elftypes.h>

typedef	struct listnode	Listnode;
typedef	struct list	List;

struct	listnode {			/* a node on a linked list */
	void		*data;		/* the data item */
	Listnode	*next;		/* the next element */
};

struct	list {				/* a linked list */
	Listnode	*head;		/* the first element */
	Listnode	*tail;		/* the last element */
};


#ifdef _SYSCALL32
typedef	struct listnode32	Listnode32;
typedef	struct list32		List32;

struct	listnode32 {			/* a node on a linked list */
	Elf32_Addr	data;		/* the data item */
	Elf32_Addr	next;		/* the next element */
};

struct	list32 {			/* a linked list */
	Elf32_Addr	head;		/* the first element */
	Elf32_Addr	tail;		/* the last element */
};
#endif	/* _SYSCALL32 */

#ifdef	__cplusplus
}
#endif

#endif /* _LIST_H */
