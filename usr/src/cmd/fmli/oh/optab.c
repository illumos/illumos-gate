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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright  (c) 1985 AT&T
 *	All Rights Reserved
 */

#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.3 */

/* Note: this file created with tabstops set to 4.
 *
 * Definition of the internal Object Operations Table (OOT).
 */

#include <stdio.h>
#include <sys/types.h>		/* EFT abs k16 */
#include "wish.h"
#include "but.h"
#include "typetab.h"
#include "ifuncdefs.h"
#include "optabdefs.h"

/* The following static char's are used to both make this table more
 * readable, and also to save memory, since in many cases the same
 * labels will appear for different objects, and this way they will
 * be shared
 */

/* these are for most normal objects */

static char Op_null[]	=	"";
static char Op_view[]	=	"";		/* viewing init function */
static char Op_sh[]	=	"";		/* selection handler */
static char Op_cv[]	=	"";		/* veiwing/ascii conversions */
static char Op_ex[]	=	"";		/* exit function */
static char Op_open[]	=	"OPEN";
static char Op_cp[]	= 	"COPY";
static char Op_pr[]	=	"PRINT";
static char Op_rn[]	=	"RENAME";
static char Op_mv[]	=	"MOVE";
static char Op_unsc[] =	"UNSCRAMBLE";
static char Op_sc[]	=	"SCRAMBLE";
static char Op_unrm[] =	"UNDELETE";
static char Op_rm[]	=	"DELETE";


/* these define null and illegal operations */

struct operation No_op =
	{Op_null,NOBUT,F_NOP,0,NULL,0,FALSE,NOMASK,NOMASK};
struct operation Illeg_op =
	{Op_null,NOBUT,F_ILL,0,NULL,0,FALSE,NOMASK,NOMASK};

/* these are specific to directories */

/** To save space, common internal operations are assigned static vars to be
 ** used in the table, thus reducing table size by about a factor of 2.
 **/

/** general operations which can apply to most objects **/

struct operation Obj_view =	/* viewing init function */
	{	Op_view,	NOBUT,	F_INT,	IF_VI,	NULL,	OP_SNG, 
		FALSE, NOMASK, NOMASK
	};

struct operation Obj_sh =	/* selection handler */
	{	Op_sh,	NOBUT,	F_INT,	IF_SH,	NULL,	OP_BUT, 
		FALSE, NOMASK, NOMASK
	};

struct operation Obj_cp =
	{	Op_cp,	BUT2,	F_INT,	IF_CP,	NULL,	OP_NEW|OP_DIR, 
		FALSE, NOMASK, M_VF|M_RO|M_WB
	};

struct operation Obj_rn =
	{	Op_rn,	BUT4,	F_INT,	IF_RN,	NULL,	OP_NEW, 
		FALSE, NOMASK, M_VF|M_RO|M_WB
	};

struct operation Obj_mv =
	{	Op_mv,	BUT5,	F_INT,	IF_MV,	NULL,  	OP_DIR, 
		FALSE, NOMASK, M_VF|M_RO|M_WB
	};

struct operation Obj_sc =
	{	Op_sc,	BUT6,	F_INT,	IF_SC,NULL,	OP_SNG, 
		FALSE, NOMASK, M_RO|M_VF|M_EN|M_ZL|M_WB
	};

struct operation Obj_unsc =
	{	Op_unsc,	BUT6,	F_INT,	IF_UNSC,NULL,	OP_SNG, 
		FALSE, M_EN, M_RO|M_VF|M_ZL|M_WB
	};

struct operation Obj_rm =
	{	Op_rm,	BUT1R, F_INT,	IF_RM,	NULL,	OP_SNG, 
		FALSE, NOMASK, M_VF|M_RO|M_WB
	};

struct operation Obj_unrm =
	{	Op_unrm,	BUT1R, F_INT,	IF_UNRM,	NULL,	OP_SNG, 
		FALSE, NOMASK, M_VF|M_RO
	};

/** operations pertaining to directories **/

struct operation Dir_view = 
	{  Op_view,	NOBUT,	F_INT,	IF_DVI,	NULL,	OP_SNG, FALSE, NOMASK, NOMASK};
struct operation Dir_sh =
	{  Op_sh,	NOBUT,	F_INT,	IF_DSH,	NULL,	OP_BUT, FALSE, NOMASK, NOMASK};
struct operation Dir_ex =
	{  Op_ex,	NOBUT,	F_INT,	IF_DEX,	NULL,	OP_SNG,	FALSE, NOMASK, NOMASK};
static struct operation Dir_open =
	{  Op_open,	BUT1R,	F_INT,	IF_DED,NULL,	OP_SNG, FALSE, M_OB3, M_WB|M_BR|M_ZL|M_RO};

static struct operation Dir_mv =
	{  Op_mv,	BUT1R,	F_INT,	IF_DMV,NULL,	OP_CUR, FALSE, M_OB3, M_WB|M_BR|M_ZL|M_RO};

static struct operation Dir_rm =
	{  Op_rm,	BUT2R,	F_INT,	IF_DRM,NULL,	OP_CUR, FALSE, NOMASK, M_WB|M_BR|M_ZL|M_RO};

static struct operation Dir_rn =
	{  Op_rn,	BUT3R,	F_INT,	IF_DRN,	NULL,	OP_NEW, FALSE, NOMASK, M_OB3|M_WB|M_BR|M_ZL|M_RO};

static struct operation Dir_cp =
	{  Op_cp,	BUT3R,	F_INT,	IF_DCP,	NULL,	OP_NEW|OP_CUR, FALSE, NOMASK, M_OB3|M_WB|M_BR|M_ZL|M_RO};

/** operations pertaining to ascii files**/

struct operation Ascii_cv =
	{  Op_cv,	NOBUT,	F_INT,	IF_ACV, NULL,	OP_SNG,	FALSE, NOMASK, NOMASK};
struct operation Ascii_pr =
	{  Op_pr,	BUT3,	F_INT,	IF_APR,	NULL,	OP_SNG, FALSE, NOMASK, M_VF|M_EN|M_ZL|M_WB};
struct operation Ascii_open =
	{  Op_open,	BUT1,	F_INT,	IF_AED,	NULL,	OP_SNG, FALSE, NOMASK, M_VF|M_EN|M_RO|M_WB};

/** operations pertaining to menu objects */

static struct operation Menu_open =
	{  Op_open,	NOBUT,	F_INT,	IF_MENOPEN,NULL,OP_SNG, FALSE, M_OB3, M_WB|M_BR|M_ZL|M_RO};

/** operations pertaining to text objects */

static struct operation Text_open =
	{  Op_open,	NOBUT,	F_INT,	IF_HLPOPEN,NULL,OP_SNG, FALSE, M_OB3, M_WB|M_BR|M_ZL|M_RO};

/** operations pertaining to form objects */

static struct operation Form_open =
	{  Op_open,	NOBUT,	F_INT,	IF_FRMOPEN,NULL,OP_SNG, FALSE, M_OB3, M_WB|M_BR|M_ZL|M_RO};

/** operations pertaining to executable objects */

static struct operation Exec_open =
	{  Op_open,	BUT1R,	F_INT,	IF_EED,NULL,	OP_SNG, FALSE, M_OB3, M_WB|M_BR};


/*** IMPORTANT NOTE:  The entries in this table must be in the same
 *** order as the entries in the Object Parts Table (partab.c),
 *** because that is used as an indexing mechanism into this table!
 ***/

struct operation *Optab[MAX_TYPES][MAX_OPERS] = {

						/** DIRECTORY **/
{
&Dir_view, &Dir_sh, &Dir_ex, &Illeg_op, 
&Dir_open, &Dir_mv, &Dir_cp, &Dir_rn, &Obj_rm, &Obj_unrm,
NULL
},

						/**  ASCII  **/
{
&Obj_view, &Obj_sh, &Illeg_op, &Ascii_cv, 
&Ascii_open, &Obj_cp, &Obj_rn, &Obj_mv, &Obj_sc, &Obj_unsc, &Ascii_pr,
&Obj_rm, &Obj_unrm,
NULL
},

						/** MENU **/
{
&Obj_view, &Obj_sh, &Illeg_op, &Ascii_cv, 
&Menu_open, &Obj_cp, &Obj_rn, &Obj_mv, &Obj_sc, &Obj_unsc, &Ascii_pr, &Obj_rm,
&Obj_unrm,
NULL
},

						/** FORM **/
{
&Obj_view, &Obj_sh, &Illeg_op, &Ascii_cv, 
&Form_open, &Obj_cp, &Obj_rn, &Obj_mv, &Obj_sc, &Obj_unsc, &Ascii_pr, &Obj_rm,
&Obj_unrm,
NULL
},

						/** TEXT **/
{
&Obj_view, &Obj_sh, &Illeg_op, &Ascii_cv, 
&Text_open, &Obj_cp, &Obj_rn, &Obj_mv, &Obj_sc, &Obj_unsc, &Ascii_pr, 
&Obj_rm, &Obj_unrm,
NULL
},

						/** EXECUTABLE **/
{
&No_op, &Obj_sh, &Illeg_op, &No_op, 
&Exec_open, &Obj_cp, &Obj_rn, &Obj_mv, &Obj_sc, &Obj_unsc, &Obj_rm, &Obj_unrm,
NULL
},

						/** TRANSFER **/
{
&No_op, &Obj_sh, &Illeg_op, &No_op, 
&Obj_cp, &Obj_rn, &Obj_mv, &Obj_sc, &Obj_unsc, &Obj_rm, &Obj_unrm,
NULL
},

						/** UNKNOWN **/
{
&No_op, &Obj_sh, &Illeg_op, &No_op, 
&Obj_cp, &Obj_rn, &Obj_mv, &Obj_sc, &Obj_unsc, &Obj_rm, &Obj_unrm,
NULL
},

NULL
};
