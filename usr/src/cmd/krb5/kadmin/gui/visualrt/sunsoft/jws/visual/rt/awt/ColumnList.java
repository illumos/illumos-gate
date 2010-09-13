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

/**
 * ColumnList.java
 *
 * Copyright 1995-1996 Active Software Inc.
 *
 * @version @(#)ColumnList.java 1.62 97/05/02
 * @author  Tilman Sporkert
 */

package sunsoft.jws.visual.rt.awt;

import sunsoft.jws.visual.rt.awt.GBLayout;
import sunsoft.jws.visual.rt.awt.GBConstraints;
import sunsoft.jws.visual.rt.awt.VJScrollbar;

import java.awt.*;
import java.util.Vector;

                /* BEGIN JSTYLED */
            /**
             * A Widget to display data in a row/column fashion, 
	     * with scrollbars etc.
             *
             * A ColumnList has the following features/attributes:
             * headers: An array of Strings. The size of 
	     * this array determines the number
             * of columns in the list. There will be one additional, hidden
             * column that can be used for any Object. 
             * The length of the header string defines the initial width of the
             * column. To make it wider, add spaces to the end of the string.
             * If a header field is of the form "name=header", then only the
             * "header" part will actually be used for the visible header.
             * The "name" part is available through 
	     * getNames() or getNameColumn()
             * selectable: If true, records can be selected 
	     * with the mouse. A LIST_EVENT gets posted.
             * editable: If true, records can be edited with the mouse.  
	     * Columns
             * containing a checkbox are currently the only editable columns.
             * highlight_items: If true, new entries will be 
	     * highlighted in orange, slowly
             * fading out.
             * showHeaders: If set to false, the headers will not be shown.
             *           
             *
             * @author  Tilman Sporkert
             */

                /* END JSTYLED */
public class ColumnList extends ScrollPanel {
    
    // Entry attributes
    static final int HIGHLIGHT = 1;
    
    ColumnListCanvas canvas;
    String[] names = null;
    boolean[] keys = null;
    int[] sortColumns = null; // references names
    int   validSortColumns = 0;
    // how many of them were actually recognized?
    boolean[] sortAscend = null;
    
    // event type for getting a chance to cancel the selection of a row
    public final static int CONFIRM_SELECT = 4863;
    
    // event type for applying an edit
    public final static int APPLY_EDIT = 4864;
    
    
    /**
     * create a new ColumnList with no information 
     * about the columns
    */
    public ColumnList() {
        add(canvas = new ColumnListCanvas(this));
        setCanvasBackground(Color.white);
    }
    
    
    /**
     * create a new ColumnList, with the given columns, and 
     * given visible
     * rows.
     *
     */
    public ColumnList(String[] headers,
		      boolean selectable,
		      boolean highlight_items) {
        this();
        setHeaders(headers);
        // setFormat(format);
        setSelectable(selectable);
        setHighlightItems(highlight_items);
    }
    
    
    /**
     * Sets the column to be editable or not.  
     * If a column is editable, then
     * all the strings that are in the column will
     * be able to be modified.
     *
     */
    public void setTextEditable(int column, boolean value) {
        canvas.setTextEditable(column, value);
    }
    
    /**
     * Sets all the columns to be editable or not.  If a column is
     * editable, then all the strings that are in the column will
     * be able to be modified.
     *
     */
    public void setTextEditable(boolean value) {
        canvas.setTextEditable(value);
    }
    
    /**
     * Gets the current value of the textEditable attribute.
     *
     */
    public boolean getTextEditable(int column) {
        return canvas.getTextEditable(column);
    }
    
    /**
     * Call this when a CONFIRM_SELECT event is received if you
     * don't want the selection to be changed.
     */
    public void cancelSelect() {
        canvas.cancelSelect();
    }
    
    /**
     * Call this to edit the given column of the 
     * currently selected row.
     *
     */
    public boolean startEdit(int column) {
        return canvas.startEdit(column);
    }
    
    /**
     * Call this to force edits to be applied.
     */
    public boolean applyChanges() {
        return canvas.applyChanges();
    }
    
    /**
     * Call this when a APPLY_EDIT event is received if you
     * don't want the change to be applied.
     */
    public void cancelApply() {
        canvas.cancelApply();
    }
    
    /**
     * Call this when you want to cancel any edit that might
     * currently be going on.
     */
    public void cancelEdit() {
        canvas.cancelEdit();
    }
    
    public int getEditRow() {
        return canvas.getEditRow();
    }
    
    public int getEditColumn() {
        return canvas.getEditColumn();
    }
    
    /**
     * Sets the foreground color.
     *
     */
    public void setCanvasForeground(Color fg) {
        canvas.setForeground(fg);
        canvas.repaint();
    }
    
    
    /**
     * Gets the current foreground color.
     *
     * @return Color
     */
    public Color getCanvasForeground() {
        return canvas.getForeground();
    }
    
    
    /**
     * Sets the background color.
     *
     */
    public void setCanvasBackground(Color fg) {
        canvas.setBackground(fg);
        canvas.repaint();
    }
    
    
    /**
     * Gets the current background color.
     *
     * @return Color
     */
    public Color getCanvasBackground() {
        return canvas.getBackground();
    }
    
    
    /**
     * Sets the font attribute.
     *
     */
    public void setCanvasFont(Font font) {
        canvas.setFont(font);
        canvas.repaint();
    }
    
    
    /**
     * Gets the font attribute.
     *
     */
    public Font getCanvasFont() {
        return canvas.getFont();
    }
    
    
    public Dimension preferredSize() {
        Dimension d = super.preferredSize();
        // Do NOT account for hbar height as
        // we want preferredSize height to accomodate
        // just the header and visibleRow data exactly
        d.height -= hbar.preferredSize().height;
        return d;
    }
    
    /**
     * Set the desired number of rows to be displayed. 
     * This affects the
     * minimumSize() and preferredSize() of the widget.
     * The actual rows
     * displayed by the widget depend on how the
     * LayoutManager interprets
     * those values.
     *
     */
    public void setVisibleRows(int rows) {
        setDisplayRows(rows);
    }
    
    
    // for backward compatibility
    public void setDisplayRows(int rows) {
        canvas.setDisplayRows(rows);
    }
    
    
    /**
     * Set the desired number of "visible" chars, i.e. 
     * the total width of
     * the column list. Defaults to "all".
     *
     */
    public void setVisibleChars(int chars) {
        canvas.setVisibleChars(chars);
    }
    
    
    /**
     * Sets the header strings.
     *
     */
    public void setHeaders(String[] headers) {
        String[] realHeaders = null;
        
        if (headers != null) {
            realHeaders = new String[headers.length];
            names = new String[headers.length];
            keys = new boolean[headers.length];
            boolean hasKeys = false;
            for (int h = 0; h < headers.length; h++) {
                keys[h] = false;
                int offset = headers[h].indexOf(/* NOI18N */ '=');
                if (offset > 0) {
                    names[h] = headers[h].substring(0, offset);
                    if (names[h].charAt(0) == /* NOI18N */ '*') {
                        keys[h] = true;
                        hasKeys = true;
                        names[h] = headers[h].substring(1, offset);
                    }
                    realHeaders[h] = headers[h].substring(
							  offset + 1);
                } else {
                    realHeaders[h] = headers[h];
                    names[h] = headers[h];
                }
            }
            if (!hasKeys)
                keys = null;
        } else {
            keys = null;
        }
        
        canvas.setHeaders(realHeaders);
    }
    
    /* BEGIN JSTYLED */
    /**
     * Set the sort order. Input is an array of 
     column names, optionally
     * preceded with a '+' for Ascend (default) 
     or '-' for descend.
     * This call should be made after setHeaders(), and 
     before adding items.
     * Items should only be added with addItem(Object[] entry).
     *
     *  If any of the names supplied do not match a 
     column name, then
     *  they will be silently ignored.
     *
     */
    /*
     * Fix for Sun Bug # 4069218: incorrect sortNames 
     * causes array out of bounds
     *                              error on addItem(...).
     *      -> If name is not recognized (i.e. getNameColumn() returns -1),
     *         Then that entry is *silently* ignored.
     *      -> Later we may want to throw some kind of exception.
     *
     */
    /* END JSTYLED */
    public void setSort(String[] sortNames) {
        if (sortNames != null && sortNames.length > 0) {
            sortColumns = new int[sortNames.length];
            sortAscend = new boolean[sortNames.length];
            int acceptedIndex = 0;
            int nameColumn;
            boolean ascend;
            for (int c = 0; c < sortNames.length; c++) {
                
                String colName = null;
                if (sortNames[c].startsWith(/* NOI18N */"+")) {
                    ascend = true;
                    colName = sortNames[c].substring(1);
                } else if (sortNames[c].startsWith(/* NOI18N */"-")) {
                    colName = sortNames[c].substring(1);
                    ascend = false;
                } else {
                    ascend = true;
                    colName = sortNames[c];
                }
                nameColumn = getNameColumn(colName);
                if (nameColumn != -1) {
                    // only process if recognized.
                    acceptedIndex ++;
                    sortColumns[acceptedIndex-1] = nameColumn;
                    sortAscend[acceptedIndex-1] =  ascend;
                }
            }
            // Need to remember the actual number of accepted sort columns.
            validSortColumns = acceptedIndex;
        } else {
            sortColumns = null;
            validSortColumns = 0;
            sortAscend = null;
        }
    }
    
    
    
    /**
     * set column formating. There is one letter for each column, with
     * l = left, c = center, r = right
     *
     */
    public void setFormats(String formatStr) {
        int[] format = new int[formatStr.length()];
        for (int c = 0; c < formatStr.length(); c++) {
            int f = formatStr.charAt(c);
            if (f == /* NOI18N */ 'c')
                format[c] = Label.CENTER;
            else if (f == /* NOI18N */ 'r')
                format[c] = Label.RIGHT;
            else
                format[c] = Label.LEFT; // default
        }
        canvas.setFormats(format);
    }
    
    
    /**
     * Sets the selectable attribute.
     *
     */
    public void setSelectable(boolean selectable) {
        canvas.setSelectable(selectable);
    }
    
    
    /**
     * Sets the editable attribute.
     *
     */
    public void setEditable(boolean editable) {
        canvas.setEditable(editable);
    }
    
    
    /**
     * Sets the hightLightItems attribute.
     *
     */
    public void setHighlightItems(boolean highlight_items) {
        canvas.setHighlightItems(highlight_items);
    }
    
    public void setHighlighted(int row, boolean highlight) {
        canvas.setHighlighted(row, highlight);
    }
    
    public boolean getHighlighted(int row) {
        return canvas.getHighlighted(row);
    }
    
    /**
     * Sets the showHeaders attribute.
     *
     */
    public void setShowHeaders(boolean showHeaders) {
        canvas.setShowHeaders(showHeaders);
    }
    
    
    /**
     * Sets the showVerticalLines attribute.
     *
     */
    public void setShowVerticalLines(boolean showVerticalLines) {
        canvas.setShowVerticalLines(showVerticalLines);
    }
    
    
    /**
     * Sets the showHorizontalLines attribute.
     *
     */
    public void setShowHorizontalLines(boolean showHorizontalLines) {
        canvas.setShowHorizontalLines(showHorizontalLines);
    }
    
    
    /**
     * Sets the autoWidth attribute.
     *
     */
    public void setAutoWidth(boolean autoWidth) {
        canvas.setAutoWidth(autoWidth);
    }
    
    
    /**
     * Adds an item to the list. If the list has no 
     * keys defined, the item
     * will be appended at the end of the list.
     * Otherwise, the existing entries
     * will be searched for an entry with the same key values.
     * If there is
     * such an entry, it will get replaced. Otherwise, the
     * record goes at the
     * end.
     *
     * @param values the record
     * @param updateView whether to update the view
     * @return index of new record
     */
    public int addItem(Object[] values, boolean updateView) {
        boolean setSelectedRow = false;
        if (keys != null) {
            for (int r = 0; r < entries(); r++)
                if (isEqualTo(values, r)) {
		    // found a matching entry
		    if (sortColumns != null && validSortColumns > 0) {
			// when sorting, take out the old one, and put the new
			// one in at its proper place
			if (getSelectedRow() == r)
			    setSelectedRow = true;
			canvas.delItems(r, r);
			break;
		    }
		    // no sorting -> just replace
		    canvas.addItem(values, r);
		    if (updateView)
			updateView();
		    return r;
		}
        }
        if (sortColumns != null && validSortColumns  > 0) {
            for (int r = 0; r < entries(); r++) {
                for (int c = 0; c < validSortColumns; c++) {
                    int colIndex = sortColumns[c];
                    int comp = values[colIndex].toString().compareTo(
				     getItem(r, colIndex).toString());
                    if (!sortAscend[c])
                        comp = -comp;
                    if (comp < 0) {
                        canvas.insertItem(values, r);
                        if (setSelectedRow)
                            selectRow(r);
                        if (updateView)
                            updateView();
                        return r;
                    } else if (comp > 0)
                        break;
                }
            }
        }
        canvas.addItem(values);
        if (setSelectedRow)
            selectRow(entries() - 1);
        if (updateView)
            updateView();
        return (entries() - 1);
    }
    
    
    /**
     * Adds an item to the list.
     *
     */
    public void addItem(Object[] values) {
        addItem(values, true);
    }
    
    
    /**
     * Compares a row to the specified values.
     *
     */
    private boolean isEqualTo(Object[] values, int r) {
        for (int c = 0; c < getColumns(); c++) {
            if (keys[c]) {
                if (!((String) getItem(r, c)).equals((String) values[c]))
                    return false;
            }
        }
        return true;
    }
    
    
    /**
     * Adds an item at a specific location. An existing record will be
     * replaced. You should not use this method if you have sorting
     * enabled!
     *
     */
    public void addItem(Object[] values, int row) {
        canvas.addItem(values, row);
        updateView();
    }
    
    
    /**
     * Insert a new item at a specific location. 
     * Existing records will be
     * moved back. You should not use this method if you have sorting
     * enabled!
     *
     */
    public void insertItem(Object[] values, int row) {
        canvas.insertItem(values, row);
        updateView();
    }
    
    
    /**
     * Deletes the items.
     */
    public void delItems() {
        delItems(true);
    }
    
    public void delItems(boolean updateView) {
        canvas.delItems();
        if (updateView)
            updateView();
    }
    
    
    /**
     * Delete the items.
     *
     */
    public void delItems(int start, int end) {
        canvas.delItems(start, end);
        updateView();
    }
    
    
    /**
     * Delete an item.
     *
     */
    public boolean delItem(Object[] values) {
        if (keys != null) {
            for (int r = 0; r < entries(); r++)
                if (isEqualTo(values, r)) {
		    canvas.delItems(r, r);
		    updateView();
		    return true;
		}
        }
        return false;
    }
    
    
    /**
     * Select a row.
     *
     */
    public int selectRow(int row) {
        return canvas.selectRow(row);
    }
    
    // for backwards compatibility
    public void highlight(int row) {
        canvas.selectRow(row);
    }
    
    /**
     * Gets the selectedRow attribute.
     */
    public int getSelectedRow() {
        return canvas.selectedRow;
    }
    
    public int getHighlightedRow() {
        return canvas.getSelectedRow();
    }
    
    /**
     * Gets the bounds.
     */
    public Rectangle getListBounds() {
        return canvas.bounds();
    }
    
    
    /**
     * Gets the entries.
     */
    public int entries() {
        return canvas.records;
    }
    
    
    /**
     * Gets the columns.
     */
    public int getColumns() {
        return canvas.columns;
    }
    
    
    /**
     * Gets the names of all the columns.
     */
    public String[] getNames() {
        return names;
    }
    
    
    /**
     * Gets the column with the specified name. 
     *
     */
    public int getNameColumn(String name) {
        for (int n = 0; n < names.length; n++)
            if (names[n].equals(name))
		return n;
        return -1;
    }
    
    
    /**
     * Gets an item in the specified row and column.
     *
     */
    public Object getItem(int row, int column) {
        return canvas.getItem(row, column);
    }
    
    
    /**
     * Gets the "Object" for a row. 
     *
     */
    public Object getObject(int row) {
        return canvas.getItem(row, canvas.columns);
    }
    
    /**
     * Puts an item at a specific row/column location.
     * Warning: If you are changing the value of a 
     * key column, another record
     *          that matches your keys will get deleted.
     * If you are changing
     *          the value of a sort column, your record
     * might get moved to a
     *          new position.
     *          The function returns the new row index.
     *
     */
    public int putItem(int row, int column, Object value) {
        Object oldValue = getItem(row, column);
        if (!canvas.putItem(row, column, value))
            return -1;
        
        // skip the checks if value didn't change (but not when value isn't
        // representable as a string, for example hwhen an icon has no label)
        if (value.toString() != null &&
	    value.toString().equals(oldValue.toString()))
	    return row;
        
        boolean setSelectedRow = false;
        if (getSelectedRow() == row)
            setSelectedRow = true;
        
        // did we update a key column?
        if (keys != null && keys.length > column && keys[column]) {
            Object[] values = (Object []) canvas.labels.elementAt(row);
            for (int r = 0; r < entries(); r++)
                if (r != row && isEqualTo(values, r)) {
		    // found a matching entry at a different location
		    canvas.delItems(r, r);
		    if (r < row)
			row--; // we just moved down one entry
		    break;
		}
        }
        if (isSortColumn(column)) {
            Object[] values = (Object []) canvas.labels.elementAt(row);
            for (int r = 0; r < entries(); r++) {
                for (int c = 0; c < sortColumns.length; c++) {
                    int colIndex = sortColumns[c];
                    int comp = values[colIndex].toString().compareTo(
				     getItem(r, colIndex).toString());
                    if (!sortAscend[c])
                        comp = -comp;
                    if (comp < 0) {
                        if (r != row && r != row + 1) {
                            swapItems(r, row);
                            row = r;
                        }
                        if (setSelectedRow)
                            selectRow(row);
                        return row;
                    } else if (comp > 0)
                        break;
                }
            }
        }
        if (setSelectedRow)
            selectRow(row);
        return row;
    }
    
    
    private boolean isSortColumn(int column) {
        if (sortColumns == null)
            return false;
        for (int c = 0; c < validSortColumns; c++)
            if (sortColumns[c] == column)
		return true;
        return false;
    }
    
    
    /**
     * Sets the object for a row
     *
     */
    public boolean putObject(int row, Object value) {
        return canvas.putItem(row, canvas.columns, value);
    }
    
    
    /**
     * Swaps the entries in two rows
     *
     */
    public boolean swapItems(int row1, int row2) {
        return canvas.swapItems(row1, row2);
    }
    
    
    /**
     * Gets the Y coordinate of the upper edge of a 
     * row in the column list.
     * Returns -1 if the row is not visible. Returns -2 is the list is
     * not layed out yet.
     *
     * @param row index of desired row
     * @return       Y coordinage of row
     */
    public int getRowY(int row) {
        return canvas.getRowY(row);
    }
    
    
    /**
     * Gets the row height of entries in the list
     *
     * @return       height of a row
     */
    public int getRowHeight() {
        return canvas.rowHeight;
    }
    
    
    /**
     * Calls repaint() on the ColumnListCanvas. Needed 
     * if an Object in the
     * column list has been changed directly(without going through
     * putItem).
     */
    public void needsRepaint() {
        canvas.repaint();
    }
    
    
    /**
     * Redraws everything, and re-evaluates the need for scroll bars
     */
    public void updateView() {
        canvas.repaint();
        updateWindow();
    }
    
    void setHBarValue(int value) {
        hbar.setValue(value);
    }
    
    void setVBarValue(int value) {
        vbar.setValue(value);
    }
    
    public void changeText(String text, int row, int column) {
        canvas.changeText(text, row, column);
    }
}
