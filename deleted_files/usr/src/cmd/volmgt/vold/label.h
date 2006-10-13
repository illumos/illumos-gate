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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef __LABEL_H
#define	__LABEL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <rpc/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Header file for label manipulation
 */

/*
 * This is the maximum block offset of a CD-ROM.  This is calculated
 * from 640 sectors/cylinder * 2048 cylinders.  It is used to cull out
 * bad (invalid) partitions in a Sun label.
 */

#define	PART_MAXCDROM	1310720
#define	PART_INF	0xffffffff

/*
 * This is a dummy label type that implements a temporary interface
 * between the medium and partition classes and the label objects
 * stored in the volume manager database and passed to the volume
 * manager daemon's event handler.
 */

typedef struct partition_label {
	ulong_t  crc;
	char	 *keyp;
	ulong_t  number_of_partitions;
	ulong_t  partition_mask;
	char	 *volume_namep;
} partition_label_t;

#define	PARTITION_LABEL 99

/*
 * structure for handling labels
 */
typedef struct label {
	int 	l_type;		/* label type index (into labsw[]) */
	void	*l_label;	/* pointer to it */
} label;

enum laread_res { L_UNRECOG, L_UNFORMATTED, L_NOTUNIQUE, L_ERROR, L_FOUND };

struct label_loc {
	off_t	ll_off;		/* offset (in bytes) */
	size_t	ll_len;		/* length (in bytes) */
};

/*
 * This is the internal interface between the label modules and the
 * generic labeling code
 */
struct labsw {
	char		*(*l_key)(label *);
	bool_t		(*l_compare)(label *, label *);
	enum laread_res	(*l_read)(int, label *, struct devs *);
	int		(*l_write)(char *, label *);
	void		(*l_setup)(struct vol *);
	void		(*l_xdr)(label *, enum xdr_op, void **);
	size_t		l_size;		/* bytes of just label */
	size_t		l_xdrsize;	/* bytes of xdr'd label */
	char		*l_ident;	/* name of label */
	uint_t		l_nll;		/* number of label locations */
	struct label_loc *l_ll;		/* array of label locations */
	char		**l_devlist;	/* devices this label live on */
	int		l_pad[10];	/* room to grow */
};

#define	MAX_LABELS	10

extern void	label_new(struct labsw *);	/* install a new label type */
extern bool_t	label_compare(label *, label *); /* TRUE if same */
extern char	*label_key(label *); 		/* return fairly unique key */
extern char	*label_ident(int);		/* string for label type */
extern int	label_type(char *);		/* label type from string */
extern enum laread_res	label_read(int, label *, struct devs *);
						/* read the label */
extern int	label_write(char *, label *); 	/* write the label to char * */
extern void	label_setup(label *, struct vol *, struct devs *);
extern void	label_xdr(label *, enum xdr_op, void **);
extern size_t	label_xdrsize(int);
extern struct labsw *label_getlast(void);
extern void	destroy_label(partition_label_t **);

/* the init routine to call in each "label_*.so" */
#define	LABEL_SYM	"label_init"

/* unnamed media names */
#define	UNNAMED_PREFIX	"unnamed_"

#ifdef	__cplusplus
}
#endif

#endif /* __LABEL_H */
