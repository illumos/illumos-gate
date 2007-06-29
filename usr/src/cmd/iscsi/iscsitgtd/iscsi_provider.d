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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

typedef struct uiscsiproto {
	int dummy;
} uiscsiproto_t;

typedef struct conninfo {
	int dummy;
} conninfo_t;

typedef struct iscsiinfo {
	int dummy;
} iscsiinfo_t;

translator conninfo_t < uiscsiproto_t *P > {
	dummy = P->dummy;
};

translator iscsiinfo_t < uiscsiproto_t *P > {
	dummy = P->dummy;
};

typedef struct uiscsicmd {
	int dummy;
} uiscsicmd_t;

typedef struct iscsicmd {
	int dummy;
} iscsicmd_t;

translator iscsicmd_t < uiscsicmd_t *P > {
	dummy = P->dummy;
};

provider iscsi {
	probe async__send(uiscsiproto_t *i) :
	    (conninfo_t *i, iscsiinfo_t *i);

	probe login__command(uiscsiproto_t *i) :
	    (conninfo_t *i, iscsiinfo_t *i);
	probe login__response(uiscsiproto_t *i) :
	    (conninfo_t *i, iscsiinfo_t *i);

	probe logout__command(uiscsiproto_t *i) :
	    (conninfo_t *i, iscsiinfo_t *i);
	probe logout__response(uiscsiproto_t *i) :
	    (conninfo_t *i, iscsiinfo_t *i);

	probe data__receive(uiscsiproto_t *i) :
	    (conninfo_t *i, iscsiinfo_t *i);
	probe data__request(uiscsiproto_t *i) :
	    (conninfo_t *i, iscsiinfo_t *i);
	probe data__send(uiscsiproto_t *i) :
	    (conninfo_t *i, iscsiinfo_t *i);

	probe nop__receive(uiscsiproto_t *i) :
	    (conninfo_t *i, iscsiinfo_t *i);
	probe nop__send(uiscsiproto_t *i) :
	    (conninfo_t *i, iscsiinfo_t *i);

	probe scsi__command(uiscsiproto_t *i, uiscsicmd_t *c) :
	    (conninfo_t *i, iscsiinfo_t *i, iscsicmd_t *c);
	probe scsi__response(uiscsiproto_t *i) :
	    (conninfo_t *i, iscsiinfo_t *i);

	probe task__command(uiscsiproto_t *i) :
	    (conninfo_t *i, iscsiinfo_t *i);
	probe task__response(uiscsiproto_t *i) :
	    (conninfo_t *i, iscsiinfo_t *i);

	probe text__command(uiscsiproto_t *i) :
	    (conninfo_t *i, iscsiinfo_t *i);
	probe text__response(uiscsiproto_t *i) :
	    (conninfo_t *i, iscsiinfo_t *i);
};

#pragma D attributes Evolving/Evolving/ISA provider iscsi provider
#pragma D attributes Private/Private/Unknown provider iscsi module
#pragma D attributes Private/Private/Unknown provider iscsi function
#pragma D attributes Private/Private/ISA provider iscsi name
#pragma D attributes Evolving/Evolving/ISA provider iscsi args
