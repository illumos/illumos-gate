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
 * Copyright 2002 by Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
package com.sun.dhcpmgr.ui;

import javax.swing.JButton;
import javax.swing.ImageIcon;
import java.io.InputStream;
import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * A button with an image loaded from a gif file.  To use this class, extend it
 * and in your constructor call setImage().
 */
public abstract class ImageButton extends JButton {
    
    /**
     * Sets the button's icon to the image loaded from the file; falls back the 
     * specified text if for some reason the icon can't be loaded.  Base class
     * is used to find the gif image in the same directory as the class that's
     * using it, a convention we use.
     * @param baseClass the name of the class we're doing this on behalf of
     * @param file the name of the file the gif image is stored in
     * @param mnText is the mnemonic/text to be used for the button 
     */
    public void setImage(Class baseClass, String file, Mnemonic mnText) {
	try {
	    InputStream resource = baseClass.getResourceAsStream(file);
	    if (resource != null) {
		BufferedInputStream in = new BufferedInputStream(resource);
		ByteArrayOutputStream out = new ByteArrayOutputStream(1024);
		byte [] buffer = new byte[1024];
		int n;
		while ((n = in.read(buffer)) > 0) {
		    out.write(buffer, 0, n);
		}
		in.close();
		out.flush();
		buffer = out.toByteArray();
		setIcon(new ImageIcon(buffer));
	    }
	} catch (IOException ioe) {
	}
	// Added for accessibility
	setText(mnText.getString());
	setToolTipText(mnText.getString());
	setMnemonic(mnText.getMnemonic());
    }
}
