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
 * ident	"%Z%%M%	%I%	%E% SMI"
 *
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */
import java.awt.*;

/**
 * This class creates a line separator by drawing a 3D rectangle.
 */
public class LineSeparator extends Canvas {

	/**
         * Paints the 3D rectangle
         * @param g The graphics context to use for painting.
         */
	public void paint(Graphics g) {
		Dimension d = getSize();
		g.setColor(getBackground());
		g.fill3DRect(0, (int)(d.height/2), d.width, 2, true);
	}

	/**
         * Main method to test the class.
         */
	public static void main(String args[]) {
		Frame f = new Frame("Test LineSeparator");
		f.setBounds(10, 10, 50, 50);
		f.add(new LineSeparator());
		f.setVisible(true);
	}

}
