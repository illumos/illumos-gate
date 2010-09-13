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
 *
 * ident	"%Z%%M%	%I%	%E% SMI"
 *
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * pmHelpItem
 * Abstraction of a help article
 */

package com.sun.admin.pm.client;

import java.awt.*;
import java.awt.event.*;
import java.util.*;

import com.sun.admin.pm.server.*;

class pmHelpItem extends Object {
    String title;
	String tag;
	Vector keywords;
	Vector seealso;
	pmHelpContent content;

    public pmHelpItem(String theTag) {
		tag = theTag;
		title = null;
		keywords = null;
		seealso = null;
		content = null;
	}

    public String toString() {
		/*
		 * String s = new String("Item: " + tag + "\n");
		 * s += ("\ttitle: "   + title + "\n");
		 * s += ("\tkeywords: " + keywords + "\n");
		 * s +=  ("\tseealso: " +  seealso + "\n");
		 * s += ("\tcontent: " +  content + "\n");
		 */
		return title;
	}


    public void setTag(String s) {
		if (tag != null)
			tag = new String(s);
	}

    public void setTitle(String s) {
		if (s != null)
			title = new String(s);
	}

    public void setKeywords(Vector v) {
		if (v != null)
			keywords = (Vector) v.clone();
	}

    public void setSeeAlso(Vector v) {
		if (v != null)
			seealso = (Vector) v.clone();
	}

    public void setContent(pmHelpContent c) {
		if (c != null)
			content = new pmHelpContent(c);
	}

}
