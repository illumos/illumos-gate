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
 * Copyright  (c) 1986 AT&T
 *	All Rights Reserved
 */
#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.7 */

#include	<curses.h>
#include	"wish.h"
#include	"vt.h"
#include	"vtdefs.h"
#include	"color_pair.h"

/* vt which is in "front" of others (and head of linked list) */
vt_id	VT_front;
/* tail of linked list */
vt_id	VT_back;
/* vt which is "current" (ie operations default to this one) */
vt_id	VT_curid;
struct vt	*VT_array;

/*
 * makes the given vt current and in front of all others (also makes
 * old vt noncurrent if there is a current one
 */
vt_id
vt_current(vid)
vt_id	vid;
{
	register vt_id	n;
	register vt_id	oldvid;
	register struct vt	*v;
	struct	vt *curvt;

/* debug stuff

	fprintf( stderr, "\t\t\t\t\tInto vt_current( %d )\n", vid );

	fprintf( stderr, "VT_front = %d\n", VT_front );
	fprintf( stderr, "VT_back =  %d\n", VT_back );
	fprintf( stderr, "VT_curid = %d\n\n", VT_curid );

        for ( n = VT_front; n != VT_UNDEFINED; n = v->next )
	{
		v = &VT_array[ n ];

		fprintf( stderr, "prev = %d\n", v->prev );
		fprintf( stderr, "VT_array index = %d\n", n );
		fprintf( stderr, "next = %d\n\n", v->next );
	}
*/

	if ( VT_curid == vid && VT_front == vid )
		return VT_curid;

/*
 * makes current vt noncurrent
 */
	if (VT_curid >= 0) {
		curvt = &VT_array[VT_curid];
		curvt->flags |= VT_TDIRTY;
		/*
		 * Since active/inactive border colors can be specified
		 * for color terminals, border should also be marked dirty
		 * on NON-currency.
		 */
		if ((!(curvt->flags & VT_NOBORDER)) &&
		    Color_terminal == TRUE && Border_colors_differ)
			curvt->flags |= VT_BDIRTY;	
	}

/*
 * moves vt to front (without making it current)
 */

	if (VT_front != vid)
	{
		for (n = VT_front; n != VT_UNDEFINED; n = v->next)
		{
			v = &VT_array[n];
	
			if (v->next == vid)
			{
				v->next = VT_array[vid].next;
	
				if ( VT_back == vid )
					VT_back = VT_array[ VT_back ].prev;
				else
				{
					v = &VT_array[ vid ];
					VT_array[ v->next ].prev = n;
				}
	
				break;
			}
		}

		v = &VT_array[vid];
		v->flags |= VT_BDIRTY;
		VT_array[vid].next = VT_front;
		VT_array[ vid ].prev = VT_UNDEFINED;
	
		if ( VT_front != VT_UNDEFINED )
			VT_array[ VT_front ].prev = vid;
	
		VT_front = vid;
	}

/*
 * makes vt current without moving it to front
 */
	oldvid = VT_curid;
	v = &VT_array[VT_curid = vid];
	v->flags |= VT_TDIRTY;
	/*
	 * Since active/inactive border colors can be specified
	 * for color terminals, border should also be marked dirty
	 * on NON-currency.
	 */
	if ((!(v->flags & VT_NOBORDER)) &&
 	     Color_terminal == TRUE && Border_colors_differ)
		v->flags |= VT_BDIRTY;	

/* debug stuff

	fprintf( stderr, "\t\t\tAfter change\n" );
	fprintf( stderr, "VT_front = %d\n", VT_front );
	fprintf( stderr, "VT_back =  %d\n", VT_back );
	fprintf( stderr, "VT_curid = %d\n\n", VT_curid );

        for ( n = VT_front; n != VT_UNDEFINED; n = v->next )
	{
		v = &VT_array[ n ];

		fprintf( stderr, "prev = %d\n", v->prev );
		fprintf( stderr, "VT_array index = %d\n", n );
		fprintf( stderr, "next = %d\n\n", v->next );
	}
*/
	return oldvid;
}

/* used for debugging (LES)

pr_VT_array()
{
	FILE	*fp, *fopen();
	struct vt	*v;
	int	n;

        fp = fopen( "VT_ARRAY", "a" );

	fprintf( fp, "\nVT_front = %d\n", VT_front );
	fprintf( fp, "VT_back =  %d\n", VT_back );
	fprintf( fp, "VT_curid = %d\n\n", VT_curid );

        for ( n = VT_front; n != VT_UNDEFINED; n = v->next )
	{
		v = &VT_array[ n ];

		fprintf( fp, "VT_array index = %d\n", n );
		fprintf( fp, "next = %d\n", v->next );
		fprintf( fp, "prev = %d\n\n", v->prev );
	}

	fclose( fp );
}
*/
