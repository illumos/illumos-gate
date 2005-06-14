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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */
package com.sun.dhcpmgr.client;

import javax.swing.table.AbstractTableModel;
import java.util.Vector;
import java.util.Date;

import com.sun.dhcpmgr.ui.AutosizingTable;
import com.sun.dhcpmgr.ui.ExtendedCellRenderer;
import com.sun.dhcpmgr.data.IPAddress;
import com.sun.dhcpmgr.data.ActionError;

/*
 * The model for the error table.
 */
class ErrorTableModel extends AbstractTableModel {
    private String column0Label;
    private Class column0Class;
    private Vector rows;

    public ErrorTableModel(String column0Label, Class column0Class) {
        this.column0Label = column0Label;
	this.column0Class = column0Class;
	rows = new Vector();
    }

    public int getRowCount() {
    	return rows.size();
    }

    public int getColumnCount() {
    	return 2;
    }

    public Object getValueAt(int row, int column) {
	Object [] ro = (Object [])rows.elementAt(row);
	return ro[column];
    }

    public Class getColumnClass(int column) {
        if (column == 0) {
	    return column0Class;
	} else {
	    return String.class;
	}
    }

    public String getColumnName(int column) {
        if (column == 0) {
	    return column0Label;
	} else {
	    return ResourceStrings.getString("error_message");
	}
    }

    public void addError(Object o, String msg) {
        Object [] row = new Object[] { o, msg };
    	rows.addElement(row);
    }
}

/**
 * A table for displaying errors which occurred while acting on multiple
 * objects.
 */
public class ErrorTable extends AutosizingTable {
    ErrorTableModel model;

    public ErrorTable(String column0Label, Class column0Class) {
    	super();
	model = new ErrorTableModel(column0Label, column0Class);
	setModel(model);
	ExtendedCellRenderer renderer = new ExtendedCellRenderer();
	setDefaultRenderer(Date.class, renderer);
	setDefaultRenderer(IPAddress.class, renderer);
    }

    public ErrorTable(String column0Label) {
	this(column0Label, String.class);
    }

    public void addError(Object o, String msg) {
        model.addError(o, msg);
    }

    public void setErrors(ActionError [] errs) {
	for (int i = 0; i < errs.length; ++i) {
	    model.addError(errs[i].getName(),
		errs[i].getException().getMessage());
	}
    }

    public boolean isEmpty() {
        return (model.getRowCount() == 0);
    }
}
