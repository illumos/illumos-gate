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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	bl.c - Binary label operations for kernel and user.
 *
 *		These routines initialize, compare, set and extract portions
 *	of binary labels.
 */

#include <sys/tsol/label.h>
#include <sys/tsol/label_macro.h>


/*
 *	bltype - Check the type of a label structure.
 *
 *	Entry	label = Address of the label to check.
 *		type = Label type to check:
 *			SUN_SL_ID = Sensitivity Label,
 *			SUN_SL_UN = Undefined Sensitivity Label structure,
 *			SUN_IL_ID = Information Label,
 *			SUN_IL_UN = Undefined Information Label structure,
 *			SUN_CLR_ID = Clearance, or
 *			SUN_CLR_UN = Undefined Clearance structure.
 *
 *	Exit	None.
 *
 *	Returns	True if the label is the type requested,
 *			otherwise false.
 *
 *	Calls	BLTYPE.
 */

int
bltype(const void *label, uint8_t type)
{

	return (BLTYPE(label, type));
}


/*
 *	blequal - Compare two labels for Classification and Compartments set
 *			equality.
 *
 *	Entry	label1, label2 = label levels to compare.
 *
 *	Exit	None.
 *
 *	Returns	True if labels equal,
 *			otherwise false.
 *
 *	Calls	BLEQUAL.
 */

int
blequal(const m_label_t *label1, const m_label_t *label2)
{

	return (BLEQUAL(label1, label2));
}


/*
 *	bldominates - Compare two labels for Classification and Compartments
 *			sets dominance.
 *
 *	Entry	label1, label2 = labels levels to compare.
 *
 *	Exit	None.
 *
 *	Returns	True if label1 dominates label2,
 *			otherwise false.
 *
 *	Calls	BLDOMINATES.
 */

int
bldominates(const m_label_t *label1, const m_label_t *label2)
{

	return (BLDOMINATES(label1, label2));
}


/*
 *	blstrictdom - Compare two labels for Classification and Compartments
 *			sets strict dominance.
 *
 *	Entry	label1, label2 = labels levels to compare.
 *
 *	Exit	None.
 *
 *	Returns	True if label1 dominates and is not equal to label2,
 *			otherwise false.
 *
 *	Calls	BLSTRICTDOM.
 */

int
blstrictdom(const m_label_t *label1, const m_label_t *label2)
{

	return (BLSTRICTDOM(label1, label2));
}


/*
 *	blinrange - Compare a label's classification and compartments set to
 *		    be within a lower and upper bound (range).
 *
 *	Entry	label = label level to compare.
 *		range = level range to compare against.
 *
 *	Exit	None.
 *
 *	Returns	True if label is within the range,
 *			otherwise false.
 *
 *	Calls BLINRANGE.
 */

int
blinrange(const m_label_t *label, const m_range_t *range)
{
	return (BLDOMINATES((label), ((range)->lower_bound)) &&
	    BLDOMINATES(((range)->upper_bound), (label)));
}

/*
 * This is the TS8 version which is used in the kernel
 */

int
_blinrange(const m_label_t *label, const brange_t *range)
{
	return (BLINRANGE(label, range));
}

#ifdef _KERNEL
/*
 *	blinlset - Check if the label belongs to the set
 *
 *	Entry	label = label level to compare.
 *		lset = label set to compare against.
 *
 *	Exit	None.
 *
 *	Returns	True if label is an element of the set,
 *			otherwise false.
 *
 */

int
blinlset(const m_label_t *label, const blset_t lset)
{
	int i;

	for (i = 0; i < NSLS_MAX; i++) {
		if (!BLTYPE(&lset[i], SUN_SL_ID))
			return (B_FALSE);
		if (BLEQUAL(label, &lset[i]))
			return (B_TRUE);
	}
	return (B_FALSE);
}
#endif /* _KERNEL */


/*
 *	blmaximum - Least Upper Bound of two levels.
 *
 *	Entry	label1, label2 = levels to bound.
 *
 *	Exit	label1 replaced by the LUB of label1 and label2.
 *
 *	Returns	None.
 *
 *	Calls	BLMAXIMUM.
 */

void
blmaximum(m_label_t *label1, const m_label_t *label2)
{

	BLMAXIMUM(label1, label2);
}


/*
 *	blminimum - Greatest Lower Bound of two levels.
 *
 *	Entry	label1, label2 = levels to bound.
 *
 *	Exit	label1 replaced by the GLB of label1 and label2.
 *
 *	Returns	None.
 *
 *	Calls	BLMINIMUM.
 */

void
blminimum(m_label_t *label1, const m_label_t *label2)
{

	BLMINIMUM(label1, label2);
}


/*
 *	bsllow - Initialize an admin_low Sensitivity Label.
 *
 *	Entry	label = Sensitivity Label structure to be initialized.
 *
 *	Exit	label = Initialized to the admin_low Sensitivity Label.
 *
 *	Returns	None.
 *
 *	Calls	BSLLOW.
 */

void
bsllow(bslabel_t *label)
{

	BSLLOW(label);
}


/*
 *	bslhigh - Initialize an admin_high Sensitivity Label.
 *
 *	Entry	label = Sensitivity Label structure to be initialized.
 *
 *	Exit	label = Initialized to the admin_high Sensitivity Label.
 *
 *	Returns	None.
 *
 *	Calls	BSLHIGH.
 */

void
bslhigh(bslabel_t *label)
{

	BSLHIGH(label);
}

/*
 *	bclearlow - Initialize an admin_low Clearance.
 *
 *	Entry	clearance = Clearnace structure to be initialized.
 *
 *	Exit	clearance = Initialized to the admin_low Clearance.
 *
 *	Returns	None.
 *
 *	Calls	BCLEARLOW.
 */

void
bclearlow(bclear_t *clearance)
{

	BCLEARLOW(clearance);
}


/*
 *	bclearhigh - Initialize an admin_high Clearance.
 *
 *	Entry	clearance = Clearance structure to be initialized.
 *
 *	Exit	clearance = Initialized to the admin_high Clearance.
 *
 *	Returns	None.
 *
 *	Calls	BCLEARHIGH.
 */

void
bclearhigh(bclear_t *clearance)
{

	BCLEARHIGH(clearance);
}

/*
 *	bslundef - Initialize an undefined Sensitivity Label.
 *
 *	Entry	label = Sensitivity Label structure to be initialized.
 *
 *	Exit	label = Initialized to undefined Sensitivity Label.
 *
 *	Returns	None.
 *
 *	Calls	BSLUNDEF.
 */

void
bslundef(bslabel_t *label)
{

	BSLUNDEF(label);
}


/*
 *	bclearundef - Initialize an undefined Clearance.
 *
 *	Entry	clearance = Clearance structure to be initialized.
 *
 *	Exit	clearance = Initialized to undefined Clearance.
 *
 *	Returns	None.
 *
 *	Calls	BCLEARUNDEF.
 */

void
bclearundef(bclear_t *clearance)
{

	BCLEARUNDEF(clearance);
}


/*
 *	setbltype - Set the type of a label structure.
 *
 *	Entry	label = Address of the label to set.
 *		type = Label type to set:
 *			SUN_SL_ID = Sensitivity Label,
 *			SUN_SL_UN = Undefined Sensitivity Label structure,
 *			SUN_IL_ID = Information Label,
 *			SUN_IL_UN = Undefined Information Label structure,
 *			SUN_CLR_ID = Clearance, or
 *			SUN_CLR_UN = Undefined Clearance structure.
 *
 *	Exit	label = Type set to specified type.
 *
 *	Returns	None.
 *
 *	Calls	SETBLTYPE.
 */

void
setbltype(void *label, uint8_t type)
{

	SETBLTYPE(label, type);
}

/*
 * Returns B_TRUE if the label is invalid (initialized to all zeros).
 */
boolean_t
bisinvalid(const void *label)
{
	return (GETBLTYPE(label) == SUN_INVALID_ID);
}
