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
 * Copyright (c) 1998-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */
package com.sun.dhcpmgr.ui;

import javax.swing.JTable;
import javax.swing.table.TableCellRenderer;
import java.awt.Font;
import java.awt.Component;

/**
 * This class provides the functionality to indicate to the user which column
 * a table is currently being sorted on.  At present it merely uses a bold
 * font to display the column name, and does not indicate the collation order.
 */
public class SortedHeaderRenderer implements TableCellRenderer {
    TableCellRenderer renderer;
    
    public SortedHeaderRenderer(JTable table) {
	renderer = table.getTableHeader().getDefaultRenderer();
    }
    
    public Component getTableCellRendererComponent(JTable table, Object value,
	    boolean isSelected, boolean hasFocus, int row, int column) {
	Component c = renderer.getTableCellRendererComponent(table, value,
	    isSelected, hasFocus, row, column);
	Font f = c.getFont();
	c.setFont(new Font(f.getName(), Font.BOLD, f.getSize()));
	return c;
    }
}
