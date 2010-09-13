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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 *        Copyright (C) 1996  Active Software, Inc.
 *                  All rights reserved.
 *
 * @(#) ColumnListShadow.java 1.39 - last change made 08/12/97
 */

package sunsoft.jws.visual.rt.shadow;

import sunsoft.jws.visual.rt.awt.ColumnList;
import sunsoft.jws.visual.rt.awt.GBConstraints;
import sunsoft.jws.visual.rt.shadow.java.awt.CanvasShadow;
import sunsoft.jws.visual.rt.base.VJException;
import sunsoft.jws.visual.rt.base.Global;
import java.awt.Color;
import java.awt.Font;
import java.awt.SystemColor;

/**
 * Wraps an AWT widget.  The attributes available for this
 * class are listed below.  In the type column, type names beginning
 * with "sunsoft.jws.visual.rt" have been abbreviated to begin with
 * "rt".
 *
 * < pre>
name                type                    default value
-----------------------------------------------------------------------
autoWidth           java.lang.Boolean       true
visibleChars        java.lang.Integer       0
visibleRows         java.lang.Integer       5
headers             [Ljava.lang.String;     header1, header2, header3
formats             java.lang.String        lll
highlightItems      java.lang.Boolean       false
selectable          java.lang.Boolean       true
editable            java.lang.Boolean         true
showHeaders         java.lang.Boolean       true
showVerticalLines   java.lang.Boolean       false
showHorizontalLines java.lang.Boolean       false
sortColumns         [Ljava.lang.String;     null
*  < /pre>
*
* headers: An array of Strings. The size of this array determines the
* number of columns in the list. There will be one additional, hidden
* column that can be used for any Object. The length of the header
* string defines the initial width of the column. To make it wider,
* add spaces to the end of the string. If a header field is of the
* form "name=header", then only the "header" part will actually be
* used for the visible header. The "name" part is available through
* getNames() or getNameColumn() interfaces on the ColumnList widget.
* If the "name" part is started with a '*', then that column is
* considered a "key column."  When addItem() is used to add a new row
* of data to the column list, a check is made to see if the key
* columns of data in the new item exactly match all of the key
* columns in any of the current rows.  If there is a match, the new
* data replaces what was in the matched row, rather than the new data
* being added to the end in a new row.
*  < p>
* formats: A string with format characters for each column. The default
* is to left justify each column. 'l' left justifies, 'c' centers,
* and 'r' right justifies.
*  < p>
* selectable: If true, records(rows) can be selected with the
* mouse. A LIST_EVENT gets posted.
*  < p>
* editable: If true, records can be edited with the mouse.  Columns
* containing a checkbox are currently the only editable columns.
*  < p>
* highlight_items: If true, new entries will be highlighted in
* orange, slowly fading out.
*  < p>
* showHeaders: If set to false, the headers will not be shown.
*  < p>
* showVerticalLines: If set to true, columns will be separated by lines
*  < p>
* showHorizontalLines: If set to true, rows will be separated by lines
*  < p>
* sortColumns: an array of column names(see headers), optionally
*  preceded with a '+' f o r ascending(default) or '-' for descending
*  sort. Affects where new entries will be added.
*  < p>
* autoWidth: when set to true, a column will automatically become
* wider to accomodate a new piece of data in that column that doesn't
* fit within the current width of the column.
*  < p>
* Check the super class for additional attributes.
*
* @see ColumnList
* @version 1.39, 08/12/97
*/
public class ColumnListShadow extends CanvasShadow {
    public ColumnListShadow() {
        String sa[] = { /* NOI18N */"header1",
				    /* NOI18N */"header2",
				    /* NOI18N */"header3"};
        attributes.add(/* NOI18N */"headers",
		       /* NOI18N */"[Ljava.lang.String;", sa, 0);
        attributes.add(/* NOI18N */"formats",
		       /* NOI18N */"java.lang.String",
		       /* NOI18N */"lll", 0);
        attributes.add(/* NOI18N */"showHeaders",
		       /* NOI18N */"java.lang.Boolean", Boolean.TRUE, 0);
        attributes.add(/* NOI18N */"showHorizontalLines",
		       /* NOI18N */"java.lang.Boolean",
		       Boolean.FALSE, 0);
        attributes.add(/* NOI18N */"showVerticalLines",
		       /* NOI18N */"java.lang.Boolean", Boolean.FALSE, 0);
        attributes.add(/* NOI18N */"visibleRows",
		       /* NOI18N */"java.lang.Integer",
		       new Integer(5), 0);
        attributes.add(/* NOI18N */"visibleChars",
		       /* NOI18N */"java.lang.Integer",
		       new Integer(0), 0);
        attributes.add(/* NOI18N */"selectable",
		       /* NOI18N */"java.lang.Boolean", Boolean.TRUE, 0);
        attributes.add(/* NOI18N */"editable",
		       /* NOI18N */"java.lang.Boolean", Boolean.TRUE, 0);
        attributes.add(/* NOI18N */"highlightItems",
		       /* NOI18N */"java.lang.Boolean", Boolean.FALSE, 0);
        attributes.add(/* NOI18N */"autoWidth",
		       /* NOI18N */"java.lang.Boolean", Boolean.TRUE, 0);
        attributes.add(/* NOI18N */"sortColumns",
		       /* NOI18N */"[Ljava.lang.String;", null, 0);
        
        GBConstraints c =
	    (GBConstraints)get(/* NOI18N */"GBConstraints");
        c.fill = GBConstraints.BOTH;
        attributes.add(/* NOI18N */"GBConstraints",
	       /* NOI18N */"sunsoft.jws.visual.rt.awt.GBConstraints", c);
        // This is a work around for JDK color bug.
        // The defaults are not correctly set
        if (Global.isWindows())  {
            attributes.add(/* NOI18N */"background",
			   /* NOI18N */"java.awt.Color",
			   SystemColor.window, DONTFETCH);
        }
        if (Global.isMotif())  {
            attributes.add(/* NOI18N */"background",
			   /* NOI18N */"java.awt.Color",
			   SystemColor.text, DONTFETCH);
            attributes.add(/* NOI18N */"foreground",
			   /* NOI18N */"java.awt.Color",
			   SystemColor.textText, DONTFETCH);
        }
    }
    
    protected Object getOnBody(String key) {
        if (key.equals(/* NOI18N */"headers"))
            return (getFromTable(/* NOI18N */"headers"));
        else if (key.equals(/* NOI18N */"formats"))
            return (getFromTable(/* NOI18N */"formats"));
        else if (key.equals(/* NOI18N */"showHeaders"))
            return (getFromTable(/* NOI18N */"showHeaders"));
        else if (key.equals(/* NOI18N */"showHorizontalLines"))
            return (getFromTable(/* NOI18N */"showHorizontalLines"));
        else if (key.equals(/* NOI18N */"showVerticalLines"))
            return (getFromTable(/* NOI18N */"showVerticalLines"));
        else if (key.equals(/* NOI18N */"visibleRows"))
            return (getFromTable(/* NOI18N */"visibleRows"));
        else if (key.equals(/* NOI18N */"visibleChars"))
            return (getFromTable(/* NOI18N */"visibleChars"));
        else if (key.equals(/* NOI18N */"selectable"))
            return (getFromTable(/* NOI18N */"selectable"));
        else if (key.equals(/* NOI18N */"editable"))
            return (getFromTable(/* NOI18N */"editable"));
        else if (key.equals(/* NOI18N */"highlightItems"))
            return (getFromTable(/* NOI18N */"highlightItems"));
        else if (key.equals(/* NOI18N */"autoWidth"))
            return (getFromTable(/* NOI18N */"autoWidth"));
        else if (key.equals(/* NOI18N */"foreground"))
            return (((ColumnList)body).getCanvasForeground());
        else if (key.equals(/* NOI18N */"background"))
            return (((ColumnList)body).getCanvasBackground());
        else if (key.equals(/* NOI18N */"font"))
            return (((ColumnList)body).getCanvasFont());
        else if (key.equals(/* NOI18N */"sortColumns"))
            return (getFromTable(/* NOI18N */"sortColumns"));
        else
            return (super.getOnBody(key));
    }
    
    protected void setOnBody(String key, Object value) {
        if (key.equals(/* NOI18N */"headers"))
            ((ColumnList) body).setHeaders((String []) value);
        else if (key.equals(/* NOI18N */"sortColumns"))
            ((ColumnList) body).setSort((String []) value);
        else if (key.equals(/* NOI18N */"formats"))
        {
            // check if the string consists only of
            // l, c, r characters..
            String s = (String) value;
            for (int i = 0; i < s.length(); i++)
            {
                char c = s.charAt(i);
                if ((c == /* NOI18N */ 'c') ||
		    (c == /* NOI18N */ 'l') ||
		    (c == /* NOI18N */ 'r'))
		    continue;
                else
/* BEGIN JSTYLED */
		    throw new VJException(Global.getMsg("sunsoft.jws.visual.rt.shadow.ColumnListShadow.Column__Format"));
	    }
	    ((ColumnList) body).setFormats(s);
	}
	else if (key.equals(/* NOI18N */"showHeaders"))
	    ((ColumnList) body).setShowHeaders(((Boolean) value).booleanValue());
	else if (key.equals(/* NOI18N */"showHorizontalLines"))
	    ((ColumnList) body).setShowHorizontalLines(((Boolean) value).booleanValue());
	else if (key.equals(/* NOI18N */"showVerticalLines"))
	    ((ColumnList) body).setShowVerticalLines(((Boolean) value).booleanValue());
	else if (key.equals(/* NOI18N */"visibleRows"))
	    ((ColumnList) body).setVisibleRows(((Integer) value).intValue());
	else if (key.equals(/* NOI18N */"visibleChars"))
	{
	    if(((Integer) value).intValue () < 0)
		throw new VJException(/* NOI18N */"visibleChars value cannot be negative");
	    ((ColumnList) body).setVisibleChars(((Integer) value).intValue());
	}
	else if (key.equals(/* NOI18N */"selectable"))
	    ((ColumnList) body).setSelectable(((Boolean) value).booleanValue());
	else if (key.equals(/* NOI18N */"editable"))
	    ((ColumnList) body).setEditable(((Boolean) value).booleanValue());
	else if (key.equals(/* NOI18N */"highlightItems"))
	    ((ColumnList) body).setHighlightItems(((Boolean) value).booleanValue());
	else if (key.equals(/* NOI18N */"autoWidth"))
	    ((ColumnList) body).setAutoWidth(((Boolean) value).booleanValue());
/* END JSTYLED */
	else if (key.equals(/* NOI18N */"foreground"))
	    ((ColumnList)body).setCanvasForeground((Color)value);
	else if (key.equals(/* NOI18N */"background"))
	    ((ColumnList)body).setCanvasBackground((Color)value);
	else if (key.equals(/* NOI18N */"font"))
	    ((ColumnList)body).setCanvasFont((Font)value);
	else
	    super.setOnBody(key, value);
    }
            
    public void createBody() {
	body = new ColumnList(
	    (String[]) getFromTable(/* NOI18N */"headers"),
/* BEGIN JSTYLED */
	    ((Boolean) getFromTable(/* NOI18N */"selectable")).booleanValue(),
	    ((Boolean) getFromTable(/* NOI18N */"highlightItems")).booleanValue());
	((ColumnList) body).setFormats((String) getFromTable(/* NOI18N */"formats"));
	((ColumnList) body).setVisibleRows(((Integer) getFromTable(/* NOI18N */"visibleRows")).intValue());
	((ColumnList) body).setVisibleChars(((Integer) getFromTable(/* NOI18N */"visibleChars")).intValue());
	((ColumnList) body).setShowHeaders(((Boolean) getFromTable(/* NOI18N */"showHeaders")).booleanValue());
	((ColumnList) body).setShowHorizontalLines(((Boolean) getFromTable(/* NOI18N */"showHorizontalLines")).booleanValue());
	((ColumnList) body).setShowVerticalLines(((Boolean) getFromTable(/* NOI18N */"showVerticalLines")).booleanValue());
	((ColumnList) body).setAutoWidth(((Boolean) getFromTable(/* NOI18N */"autoWidth")).booleanValue());
	((ColumnList) body).setSort((String []) getFromTable(/* NOI18N */"sortColumns"));
/* END JSTYLED */
    }
}
