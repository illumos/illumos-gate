/*
 * Copyright 1996, 1998, 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/vnode.h>
#include <locale.h>
#include <stdlib.h>
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_fsdir.h>
#include <sys/fs/ufs_acl.h>
#include <byteorder.h>

struct byteorder_ctx *
byteorder_create(void)
{
	struct byteorder_ctx *rc;

	/* LINTED: assignment value is used */
	if ((rc = (struct byteorder_ctx *)calloc(1, sizeof (*rc))) == NULL)
		return (NULL);
	return (rc);
}

void
byteorder_destroy(struct byteorder_ctx *ctx)
{
	if (ctx != NULL)
		(void) free((char *)ctx);
}

void
byteorder_banner(struct byteorder_ctx *ctx, FILE *filep)
{
	if ((! ctx->initialized) || (filep == NULL))
		return;

	if (ctx->Bcvt)
		(void) fprintf(filep, gettext("Note: doing byte swapping\n"));
}

/*
 * Control string (cp) is a sequence of optional numeric repeat counts
 * and format specifiers.  s/w/h indicate a 16-bit quantity is to be
 * byte-swapped, l indicates a 32-bit quantity.  A repeat count is
 * identical in effect to having the following format character appear
 * N times (e.g., "3h" is equivalent to "hhh").
 *
 * The byte-swapping is performed in-place, in the buffer sp.
 */
void
swabst(char *cp, uchar_t *sp)
{
	int n = 0;
	uchar_t c;

	while (*cp) {
		switch (*cp) {
		case '0': case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
			n = (n * 10) + (*cp++ - '0');
			continue;

		case 's': case 'w': case 'h':
			/* LINTED: type punning ok here */
			c = sp[0]; sp[0] = sp[1]; sp[1] = c;
			sp++;
			break;

		case 'l':
			c = sp[0]; sp[0] = sp[3]; sp[3] = c;
			c = sp[2]; sp[2] = sp[1]; sp[1] = c;
			sp += 3;
		}
		/* Any other character, like 'b' counts as byte. */
		sp++;
		if (n <= 1) {
			n = 0; cp++;
		} else
			n--;
	}
}

uint32_t
swabl(uint32_t x)
{
	uint32_t l = x;

	swabst("l", (uchar_t *)&l);
	/* LINTED: type punning ok here */
	return (l);
}

static int
checksum(struct byteorder_ctx *ctx, int *b, int size)
{
	uint_t i, j;

	if (! ctx->initialized)
		return (-1);

	/*
	 * We should only be called on to checksum u_spcl's, so make
	 * sure that's what we got.
	 */
	if ((unsigned)size < tp_bsize)
		return (-1);

	j = tp_bsize / sizeof (int);
	i = 0;
	if (!ctx->Bcvt) {
		do
			i += (uint_t)*b++;
		while (--j);
	} else {
		/*
		 * What happens if we want to read restore tapes
		 * for a 16bit int machine???
		 */
		do
			i += swabl(*b++);
		while (--j);
	}

	return (i != CHECKSUM);
}

/*
 * normspcl() checks that a spclrec is valid.  it does byte/quad
 * swapping if necessary, and checks the checksum.  it does NOT convert
 * from the old filesystem format; gethead() in tape.c does that.
 *
 * ctx is the context for this package
 * sp is a pointer to a current-format spclrec, that may need to be
 *	byteswapped.
 * cs is a pointer to the thing we want to checksum.  if we're
 *	converting from the old filesystem format, it might be different
 *	from sp.
 * css is the size of the thing we want to checksum.
 * magic is the magic number we compare against.
 */

int
normspcl(struct byteorder_ctx *ctx, struct s_spcl *sp, int *cs,
    int css, int magic)
{
	u_offset_t sv;

	if ((! ctx->initialized) && (sp->c_magic != magic)) {
		if (swabl(sp->c_magic) != (uint32_t)magic)
			return (-1);
		ctx->Bcvt = 1;
	}
	ctx->initialized = 1;

	if (checksum(ctx, cs, css))
		return (-1);

	/*
	 * Unless our caller is actively trying to break us, a
	 * successful checksum() means that *sp is at least as
	 * big as what we think it should be as far as byte
	 * swapping goes.  Therefore, we don't need to do any
	 * more size checks here.
	 */

	/* handle byte swapping */
	if (ctx->Bcvt) {
		/*
		 * byteswap
		 *	c_type, c_date, c_ddate, c_volume, c_tapea, c_inumber,
		 *	c_magic, c_checksum,
		 *	all of c_dinode, and c_count.
		 */

		swabst("8l4s31l", (uchar_t *)sp);

		/*
		 * byteswap
		 *	c_flags, c_firstrec, and c_spare.
		 */

		swabst("34l", (uchar_t *)&(sp->c_flags));

		/* byteswap the inodes if necessary. */

#ifndef	lint	/* lint won't shut up about sprintf below */
		if (sp->c_flags & DR_INODEINFO) {
			char buffy[BUFSIZ];
			/* Can't overflow, max len is %d format (20)+`l'+\0 */
			/* LINTED lint can't tell diff between %ld and %dl */
			(void) sprintf(buffy, "%dl", TP_NINOS);
			swabst(buffy, (uchar_t *)sp->c_data.s_inos);
		}
#endif	/* lint */

		/* if no metadata, byteswap the level */

		if (! (sp->c_flags & DR_HASMETA))
			swabst("1l", (uchar_t *)&(sp->c_level));
	}

	/* handle quad swapping (note -- we no longer perform this check */
	/*	we now do quad swapping iff we're doing byte swapping.)  */

	/*
	 * 	the following code is being changed during the large file
	 *	project. This code needed to be changed because ic_size
	 *	is no longer a quad, it has been changed to ic_lsize, which is
	 *	an offset_t, and the field "val" doesn't exist anymore.
	 */

/*
 * This is the old code. (before large file project.)
 *
 *	sv = sp->c_dinode.di_ic.ic_size.val;
 *
 *	if (ctx->Bcvt) {
 *		long foo;
 *
 *		foo = sv[1];
 *		sv[1] = sv[0];
 *		sv[0] = foo;
 *	}
 */

	/* swap the upper 32 bits of ic_lsize with the lower 32 bits */

	if (ctx->Bcvt) {
		sv = sp->c_dinode.di_ic.ic_lsize;
		sv = (sv << 32) | (sv >> 32);
		sp->c_dinode.di_ic.ic_lsize = sv;
	}

	if (sp->c_magic != magic)
		return (-1);
	return (0);
}

void
normdirect(ctx, d)
	struct byteorder_ctx *ctx;
	struct direct *d;
{
	assert(ctx->initialized);

	if (ctx->Bcvt)
		swabst("l2s", (uchar_t *)d);
}

void
normacls(struct byteorder_ctx *ctx, ufs_acl_t *acl, int n)
{
	static int complained = 0;
	int i;
	uid32_t uid;

	assert(ctx->initialized);

	if (! ctx->Bcvt)
		return;

	for (i = 0; i < n; i++) {
		swabst("1s", (uchar_t *)&(acl[i].acl_tag));  /* u_short */
		swabst("1s", (uchar_t *)&(acl[i].acl_perm)); /* o_mode_t */

		/* LINTED explicitly checking for truncation below */
		uid = (uid32_t)(acl[i].acl_who);
		if (!complained && ((uid_t)uid) != acl[i].acl_who) {
			/*
			 * The problem is that acl_who is a uid_t,
			 * and we know that the on-tape version is
			 * definitely 32 bits.  To avoid getting
			 * burned if/when uid_t becomes bigger
			 * than that, we need to do the explicit
			 * conversion and check.
			 */
			(void) fprintf(stderr,
			    "Some ACL uids have been truncated\n");
			complained = 1;
		}
		swabst("1l", (uchar_t *)&(uid));	/* uid32_t */
	}
}
