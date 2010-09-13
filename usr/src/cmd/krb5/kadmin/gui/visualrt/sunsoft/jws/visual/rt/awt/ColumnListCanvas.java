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
 * ColumnListCanvas.java
 *
 * Copyright 1995-1996 Active Software Inc.
 *
 * @version @(#)ColumnListCanvas.java 1.93 97/07/25
 * @author  Tilman Sporkert
 */

package sunsoft.jws.visual.rt.awt;

import sunsoft.jws.visual.rt.base.DesignerAccess;
import sunsoft.jws.visual.rt.base.Global;

import java.awt.Graphics;
import java.util.Vector;
import java.awt.*;

/**
 * An internal widget for the ColumnList widget
 *
 * @author  Tilman Sporkert
 */
class ColumnListCanvas extends VJPanel implements Scrollable {
    // Padding
    final static int LEFT_PAD = 4;
    final static int RIGHT_PAD = 4;
    
    // Editing
    private EditLine editline;
    private CLChoice editchoice;
    private boolean justCancelled;
    Window choiceMenuWindow;
    TextList choiceMenu;
    private int editrow = -1;
    private int editcolumn = -1;
    private boolean[] textEditable;
    private boolean applying;
    private boolean cancelApply;
    
    // double-buffering
    private Image buffer;
    private Dimension bufferSize;
    private Image[] bufferCache = new Image[3];
    private Dimension[] bufferSizeCache = new Dimension[3];
    
    ColumnList parent;
    Frame      ourFrame = null;
    int        columns;         // # of data columns
    // there are actual columns + 1 columns managed
    // but only columns are visible. The last
    // column can be accessed only by addItem(),
    // getItem(), and putItem(), and can be used to
    // manage a random object together with the
    // data row
    int        charWidth;
    int        rowHeight;      // height of data row
    Component  hasComponents = null;
    int        componentHeight = 0;
    // height of largest component in list
    int        rowAscent;
    int        headerHeight;
    int        totalWidth;     // total width of all colums
    boolean    dragging = false; // for resizing columns
    int        dragStart;      // x position where drag started
    int        dragColumn;     // which column is getting resized?
    
    String[]   headers;
    boolean    showHeaders = true;
    boolean    showVerticalLines = false;
    boolean    showHorizontalLines = false;
    int[]      formats = null;   // Formatting mode for columns
    int[]      dimensions;      // the dimensions of the headers
    boolean    autoWidth = true; // automatically expand columns to fit?
    int        records;         // # of active records
    Vector     labels;          // the actual data, as Label[]
    Vector     rowColors;      // Attributes of a record
    
    int        requestedRows = 5;  // requested # of rows to show
    int        requestedChars = 0;
    // request # of chars to display horizontally
    int        dispRows;       // # of rows to show
    int        visibleRows = -1;
    // this can be one more than dispRows
    
    int        scrollx = 0;
    int        scrollrow = 0;
    int        scrolly = 0;
    
    // the selection
    boolean    highlightItems = false; // highlight new items?
    Thread     colorThread = null;
    boolean    selectable = false;
    int        selectedRow = -1;
    Color      selectColor;
    boolean    editable = true;
    
    // flag to track if the selection change has been canceled
    private boolean cancelSelect;
    
    private final static int COLOR_NONE = 0;
    private final static int COLOR_FIRST = 4;
    
    /**
     * create a new ColumnListCanvas. Before it can be used
     * in any reasonable fashion, setHeaders() should 
     * be called, followed
     * by an optional call to setFormat()!
     *
     * @param parent   The parent ColumnList
     */
    public ColumnListCanvas(ColumnList parent) {
        setLayout(null);
        this.parent = parent;
        
        headers = new String[0];
        columns = 0;
        
        labels = new Vector();
        rowColors = new Vector();
        
        dimensions = null;
        
        dispRows = 0;
        records = 0;
        
        selectColor = new Color(0, 0, 128);
    }
    
    public void setTextEditable(boolean value) {
        textEditable = ensureLength(textEditable, columns);
        for (int i = 0; i < textEditable.length; i++)
            textEditable[i] = value;
    }
    
    public void setTextEditable(int column, boolean value) {
        if (column < 0 || column >= columns)
            return;
        
        textEditable = ensureLength(textEditable, column+1);
        textEditable[column] = value;
    }
    
    public boolean getTextEditable(int column) {
        if (textEditable == null || column < 0 ||
	    column >= textEditable.length)
	    return false;
        
        return textEditable[column];
    }
    
    public boolean[] ensureLength(boolean[] arr, int length) {
        if (arr == null)
            return new boolean[length];
        
        if (arr.length < length) {
            boolean[] newarr = new boolean[length];
            System.arraycopy(arr, 0, newarr, 0, arr.length);
            arr = newarr;
        }
        
        return arr;
    }
    
    public void cancelApply() {
        cancelApply = true;
    }
    
    public synchronized void cancelEdit() {
        if (editline != null || editchoice != null) {
            selectRow(editrow);
            
            if (editline != null) {
                editline.destroy();
                editline = null;
                justCancelled = true;
            } else {
                editchoice.cancelEdit();
                editchoice = null;
                justCancelled = true;
            }
            
            editrow = -1;
            editcolumn = -1;
            repaint();
        }
    }
    
    public int getEditRow() {
        return editrow;
    }
    
    public int getEditColumn() {
        return editcolumn;
    }
    
    public boolean applyChanges() {
        if (editchoice != null) {
            cancelEdit();
            return true;
        } else if (editline != null) {
            editline.applyChanges();
            return !cancelApply;
        } else {
            return true;
        }
    }
    
    public boolean startEdit(int column) {
        return startEdit(column, -1);
    }
    
    private synchronized boolean startEdit(int column, int x) {
        if (editchoice != null)
            return false;
        
        if (editline != null)
            return false;
        
        if (column < 0 || column >= columns)
            return false;
        
        if (!getTextEditable(column))
            return false;
        
        int row = getSelectedRow();
        if (row == -1)
            return false;
        
        Object entry = ((Object[])labels.elementAt(row))[column];
        
        if (entry instanceof String) {
            String str = (String)entry;
            editline = new EditLine(this, str, textX(str, column),
				    textY(row));
            editrow = row;
            editcolumn = column;
            editline.paint(getBufferGraphics());
            copyBuffer();
        } else if (entry instanceof CLChoice) {
            CLChoice choice = (CLChoice)entry;
            if (!choice.getEditable())
                return false;
            editchoice = choice;
            editrow = row;
            editcolumn = column;
        } else if (entry instanceof CLComponent) {
            CLComponent comp = (CLComponent)entry;
            if (!comp.getEditable())
                return false;
            
            String text = comp.getText();
            
            if (text != null) {
                int textX = comp.textX() + columnX(column);
                int textY = comp.textY() + rowY(row);
                
                if (x != -1 && x < textX)
                    return false;
                
                editline = new EditLine(this, text, textX, textY);
                editrow = row;
                editcolumn = column;
                editline.paint(getBufferGraphics());
                copyBuffer();
            }
        }
        
        if (editline != null) {
            selectRow(-1);
            return true;
        } else if (editchoice != null) {
            return true;
        } else {
            return false;
        }
    }
    
    public int textX(String str, int column) {
        int x = -scrollx;
        for (int i = 0; i < column; i++)
            x += dimensions[i];
        x += LEFT_PAD;
        
        int format = getFormat(column);
        if (format != Label.LEFT) {
            int width = dimensions[column] - LEFT_PAD - RIGHT_PAD;
            FontMetrics fm = getFontMetrics(getFont());
            int w = fm.stringWidth(str);
            
            if (format == Label.RIGHT)
                x += width - w;
            else if (format == Label.CENTER)
                x += (width - w) / 2;
        }
        
        return x;
    }
    
    public int textY(int row) {
        return headerHeight + ((row - scrollrow) * rowHeight)
	    + rowAscent;
    }
    
    /**
     * ...
     *
     * @param ...    ...
     * @return       ...
     * @exception    ...
     */
    protected void finalize() {
        if (colorThread != null)
            colorThread.stop();
    }
    
    
    /**
     * set the headers for the columns. THis also defines the
     * # of columns. If the # of header columns 
     * changes, all current rows
     * will be deleted, and the formatting options get reset
     *
     * @param headersIn  array of column headers
     */
    public synchronized void setHeaders(String[] headersIn) {
        int newColumns;
        
        if (headersIn == null)
            newColumns = 0;
        else
            newColumns = headersIn.length;
        
        if (newColumns != columns) {
            // # of columns change -> get rid of everything
            delItems();
            labels = new Vector();
            rowColors = new Vector();
            formats = null;
            dimensions = null;
        }
        
        if (headersIn == null)
            columns = 0;
        else
            columns = headersIn.length;
        headers = headersIn;
        dimensions = null;
        cacheDimensions();
        repaint();
    }
    
    
    /**
     * ...
     *
     * @param ...    ...
     * @return       ...
     * @exception    ...
     */
    public void setFormats(int[] formatIn) {
        formats = formatIn;
    }
    
    
    /**
     * ...
     *
     * @param ...    ...
     * @return       ...
     * @exception    ...
     */
    public int getFormat(int column) {
        if ((formats == null) || (column < 0) || (
						  column >= formats.length))
	    return Label.LEFT;
        else
            return formats[column];
    }
    
    
    /**
     * ...
     *
     * @param ...    ...
     * @return       ...
     * @exception    ...
     */
    public void setSelectable(boolean selectable) {
        this.selectable = selectable;
    }
    
    
    public void setEditable(boolean editable_in) {
        editable = editable_in;
    }
    
    /**
     * ...
     *
     * @param ...    ...
     * @return       ...
     * @exception    ...
     */
    public void setHighlightItems(boolean highlightItems) {
        this.highlightItems = highlightItems;
    }
    
    public void setHighlighted(int row, boolean highlight) {
        if (row < 0 || row >= records)
            return;
        
        if (highlight) {
            rowColors.setElementAt(new Integer(COLOR_FIRST), row);
            
            if (highlightItems == true) {
                if (colorThread == null) {
                    colorThread = new ColumnListThread(this);
                    colorThread.start();
                } else {
                    colorThread.resume();
                }
            }
        } else {
            rowColors.setElementAt(new Integer(COLOR_NONE), row);
        }
    }
    
    public boolean getHighlighted(int row) {
        if (row < 0 || row >= records)
            return false;
        
        int rowColor = ((Integer) rowColors.elementAt(row)).intValue();
        return (rowColor != COLOR_NONE);
    }
    
    
    /**
     * ...
     *
     * @param ...    ...
     * @return       ...
     * @exception    ...
     */
    public void setShowHeaders(boolean showHeaders) {
        this.showHeaders = showHeaders;
        repaint();
    }
    
    
    /**
     * ...
     *
     * @param ...    ...
     * @return       ...
     * @exception    ...
     */
    public void setShowVerticalLines(boolean showVerticalLines) {
        this.showVerticalLines = showVerticalLines;
        repaint();
    }
    
    
    /**
     * ...
     *
     * @param ...    ...
     * @return       ...
     * @exception    ...
     */
    public void setShowHorizontalLines(boolean showHorizontalLines) {
        this.showHorizontalLines = showHorizontalLines;
        repaint();
    }
    
    
    /**
     * ...
     *
     * @param ...    ...
     * @return       ...
     * @exception    ...
     */
    public void setAutoWidth(boolean autoWidth) {
        this.autoWidth = autoWidth;
    }
    
    
    // Scrollable
    /**
     * ...
     *
     * @param ...    ...
     * @return       ...
     * @exception    ...
     */
    public void scrollX(int x) {
        if (scrollApply()) {
            scrollx = x;
            repaint();
        } else {
            parent.setHBarValue(scrollx);
        }
    }
    
    
    /**
     * Scroll vertically to y. Part of Scrollabel interface.
     *
     * @param y new vertical scroll position
     */
    public void scrollY(int y) {
        if (scrollApply()) {
            scrolly = y;
            if (rowHeight != 0)
                scrollrow = (y + rowHeight - 1) / rowHeight;
            else
                scrollrow = 0;
            repaint();
        } else {
            parent.setVBarValue(scrolly);
        }
    }
    
    
    private boolean scrollApply() {
        boolean status = true;
        if (!applying) {
            applying = true;
            status = applyChanges();
            
            // The Motif scrollbar gets locked down
            // when a modal dialog is
            // brought up while scrolling.  To prevent getting infinite
            // errors, we will cancel the edit here.
            if (!status && Global.isMotif())
                cancelEdit();
            
            applying = false;
        }
        return status;
    }
    
    public Dimension scrollSize() {
        cacheDimensions();
        if (dimensions == null)
            return new Dimension(100, 100);
        else
            return new Dimension(totalWidth, rowHeight * records);
    }
    
    public Dimension viewSize(Dimension size) {
        cacheDimensions();
        size.height -= headerHeight;
        return size;
    }
    
    /**
     * ...
     *
     * @param ...    ...
     * @return       ...
     * @exception    ...
     */
    public int lineHeight() {
        cacheDimensions();
        return rowHeight;
    }
    
    private synchronized void addMoreLabels() {
        int c;
        // have one extra for the "hidden" object
        Object[] newLabels = new Object[columns + 1];
        labels.addElement(newLabels);
        rowColors.addElement(new Integer(COLOR_NONE));
        for (c = 0; c < columns; c++)
            newLabels[c] = /* NOI18N */"";
        newLabels[columns] = null;
    }
    
    private void ensureCapacity(int row) {
        while (row >= labels.size())
            addMoreLabels();
    }
    
    private void growRecords(int row) {
        // initialize all intermediate records
        while (row > records) {
            Object[] labelRow = (Object[]) labels.elementAt(records);
            for (int c = 0; c < columns; c++)
                labelRow[c] = /* NOI18N */"";
            labelRow[columns] = null;
            rowColors.setElementAt(new Integer(COLOR_NONE), records);
            records++;
        }
    }
    
    
    /**
     * ...
     *
     * @param ...    ...
     * @return       ...
     * @exception    ...
     */
    public synchronized void insertItem(Object[] values, int row) {
        int c;
        boolean newWidth = false;
        
        // make sure we have enough labels...
        ensureCapacity(row);
        growRecords(row);
        
        // Make one extra entry
        ensureCapacity(records + 1);
        growRecords(records + 1);
        
        // Move other rows out of the way
        for (int pos = records-2; row <= pos; --pos) {
            labels.setElementAt(labels.elementAt(pos), pos+1);
            rowColors.setElementAt(rowColors.elementAt(pos), pos+1);
        }
        Object[] labelRow = new Object[columns+1];
        for (c = 0; c < columns; c++)
            labelRow[c] = /* NOI18N */"";
        labelRow[columns] = null;
        labels.setElementAt(labelRow, row);
        
        // Fix selected row
        if (selectedRow >= row)
            ++selectedRow;
        
        // Call addItem to replace things
        addItem(values, row);
    }
    
    
    /**
     * ...
     *
     * @param ...    ...
     * @return       ...
     * @exception    ...
     */
    public synchronized void addItem(Object[] values) {
        addItem(values, records);
    }
    
    
    /**
     * ...
     *
     * @param ...    ...
     * @return       ...
     * @exception    ...
     */
    public synchronized void addItem(Object[] values, int row) {
        // make sure we have enough labels...
        ensureCapacity(row);
        growRecords(row);
        
        if (autoWidth)
            cacheDimensions();
        
        Object[] labelRow = (Object[]) labels.elementAt(row);
        
        for (int c = 0; c < columns; c++) {
            labelRow[c] = values[c];
            if (values[c] instanceof CLComponent)
                ((CLComponent)values[c]).setCanvas(this, row, c);
            checkComponentCell(values[c]);
        }
        if (values.length > columns)
            labelRow[columns] = values[columns];
        else
            labelRow[columns] = null;
        
        adjustColumnWidths(row);
        
        if (highlightItems == true) {
            rowColors.setElementAt(new Integer(COLOR_FIRST), row);
            if (colorThread == null) {
                colorThread = new ColumnListThread(this);
                colorThread.start();
            } else
                colorThread.resume();
        } else
            rowColors.setElementAt(new Integer(COLOR_NONE), row);
        if (row >= records)
            records++;
    }
    
    
    /**
     * Adjust the widths of the columns for 'row' to make sure 
     * everything
     * fits properly. If autoWidth is false, then this
     * function has no effect
     *
     * @param row row number
     */
    private void adjustColumnWidths(int row) {
        if (!autoWidth || (dimensions == null))
            return;
        
        Object[] labelRow = (Object[]) labels.elementAt(row);
        for (int c = 0; c < columns; c++)
            adjustColumnWidths(labelRow[c], c);
    }
    
    
    /**
     * If autoWidth is enabled, make sure "value" fits 
     * into the given column.
     *
     * @param value the value to be checked
     * @param column column number
     */
    void adjustColumnWidths(Object value, int column) {
        if (!autoWidth || (value == null) || (dimensions == null))
            return;
        
        int w = labelWidth(value);
        int usableWidth = dimensions[column];
        if (w > usableWidth) {
            totalWidth += w - usableWidth;
            dimensions[column] += w - usableWidth;
        }
    }
    
    
    /**
     * If the object (to be put into a cell) is an AWT component, make
     * sure it gets properly managed in the layout, and 
     * that the rows are
     * high enough to hold it.
     *
     * @param ...    ...
     * @return       ...
     * @exception    ...
     */
    private void checkComponentCell(Object value) {
        if (value instanceof Component) {
            if (hasComponents == null)
                hasComponents = (Component) value;
            add((java.awt.Component) value);
            ((java.awt.Component) value).hide();
            Dimension size = ((java.awt.Component) value).
		preferredSize();
            if (size.height > componentHeight) {
                componentHeight = size.height;
                if (componentHeight > rowHeight) {
                    rowAscent += (componentHeight - rowHeight) / 2;
                    rowHeight = componentHeight + 2;
                }
                
            }
        }
    }
    
    /**
     * ...
     *
     * @param ...    ...
     * @return       ...
     * @exception    ...
     */
    public synchronized void delItems() {
        delItems(0, records - 1);
        selectedRow = -1;
    }
    
    
    /**
     * ...
     *
     * @param ...    ...
     * @return       ...
     * @exception    ...
     */
    public synchronized void delItems(int start, int end) {
        if ((start < 0) || (start >= records))
            return;
        if (end < start)
            return;
        if (end > records)
            end = records - 1;
        int r, c;
        int diff = end - start + 1;
        for (r = start; r <= end; r++) {
            Object[] labelRow = (Object[]) labels.elementAt(start);
            for (c = 0; c < columns; c++) {
                if (labelRow[c] instanceof Component)
                    remove((java.awt.Component) labelRow[c]);
                else if (labelRow[c] instanceof CLComponent)
                    ((CLComponent)labelRow[c]).setCanvas(null, -1, -1);
            }
            
            labels.removeElementAt(start);
            rowColors.removeElementAt(start);
        }
        records -= diff;
        
        if (selectedRow > end)
            selectedRow -= diff;
        else if (selectedRow > start)
            selectedRow = start - 1;
        
        // repaint all the time... could be optimized
        repaint();
    }
    
    
    /**
     * ...
     *
     * @param ...    ...
     * @return       ...
     * @exception    ...
     */
    protected Object getItem(int row, int column) {
        if ((row > records) || (row < 0) || (column > columns) ||
	    (column < 0))
	    return null;
        return ((Object []) labels.elementAt(row))[column];
    }
    
    
    /**
     * ...
     *
     * @param ...    ...
     * @return       ...
     * @exception    ...
     */
    protected synchronized boolean putItem(int row, int column,
					   Object value) {
        if ((row > records) || (row < 0) || (column > columns) ||
	    (column < 0))
	    return false;
        Object[] data = (Object []) labels.elementAt(row);
        data[column] = value;
        if (value instanceof CLComponent)
            ((CLComponent)value).setCanvas(this, row, column);
        
        if (column < columns) {
            // don't do this on objects in the hidden column
            checkComponentCell(value);
            adjustColumnWidths(value, column);
        }
        
        repaint();
        return true;
    }
    
    
    /**
     * ...
     *
     * @param ...    ...
     * @return       ...
     * @exception    ...
     */
    protected boolean swapItems(int row1, int row2) {
        if ((row1 > records) || (row1 < 0) || (row2 > records) ||
	    (row2 < 0))
	    return false;
        if (row1 == row2)
            return true;
        Object[] data1 = (Object []) labels.elementAt(row1);
        Object[] data2 = (Object []) labels.elementAt(row2);
        labels.setElementAt(data2, row1);
        labels.setElementAt(data1, row2);
        repaint();
        return true;
    }
    
    public String chopText(String text, int w) {
        if (w <= 0)
            return /* NOI18N */"";
        
        FontMetrics fm = getFontMetrics();
        int len = text.length();
        int index = getTextCutoff(fm, w, text, len, 0, len);
        if (index == len)
            return text;
        else
            return text.substring(0, index);
    }
    
    private int getTextCutoff(FontMetrics fm, int textW, String str,
			      int cur, int lower, int upper) {
        if (lower == upper) {
            return lower;
        } else if (lower == (upper-1)) {
            int width = fm.stringWidth(str.substring(0, upper));
            if (width < textW)
                return upper;
            else
                return lower;
        }
        
        int width = fm.stringWidth(str.substring(0, cur));
        if (width == textW)
            return cur;
        else if (width < textW)
            return getTextCutoff(fm, textW, str,
				 cur + (upper-cur)/2, cur, upper);
        else
            return getTextCutoff(fm, textW, str,
				 cur - (cur-lower)/2, lower, cur);
    }
    
    // drawString - calls g.drawString(str, x, y), but
    // makes sure that str
    //              will fit into width
    public void drawString(Graphics g, String str, int x, int y,
			   int width, int format) {
        str = chopText(str, width);
        
        g.setFont(getFont());
        FontMetrics fm = g.getFontMetrics();
        int w = fm.stringWidth(str);
        if (w <= 0)
            return;
        
        if (format == Label.RIGHT)
            x += width - w;
        else if (format == Label.CENTER)
            x += (width - w) / 2;
        g.drawString(str, x, y);
    }
    
    public FontMetrics getFontMetrics() {
        return getFontMetrics(getFont());
    }
    
    /**
     * ...
     *
     * @param ...    ...
     * @return       ...
     * @exception    ...
     */
    public void setFont(Font font) {
        super.setFont(font);
        dimensions = null;
        cacheDimensions();
    }
    
    
    /**
     * ...
     *
     * @param ...    ...
     * @return       ...
     * @exception    ...
     */
    public void update(Graphics g) {
        paint(g);
    }
    
    
    /**
     * Determines the width a label item needs.
     *
     * @param ...    ...
     * @return       ...
     * @exception    ...
     */
    private int labelWidth(Object item) {
        if (item == null)
            return (0);
        else if (item instanceof Component)
            return ((Component) item).preferredSize().width +
		LEFT_PAD + RIGHT_PAD;
        else if (item instanceof String) {
            String str = (String)item;
            Graphics g = getBufferGraphics();
            g.setFont(getFont());
            FontMetrics fm = g.getFontMetrics();
            return fm.stringWidth(str) + LEFT_PAD + RIGHT_PAD;
        } else if (item instanceof CLComponent) {
            Dimension s = ((CLComponent) item).size();
            if (s != null)
                return s.width;
            else
                return 0;
        } else {
            return 0;
        }
    }
    
    /**
     * ...
     *
     * @param ...    ...
     * @return       ...
     * @exception    ...
     */
    private void cacheDimensions() {
        if (dimensions != null)
            return;
        
        Graphics g = getBufferGraphics();
        if (g == null)
            return;
        
        g.setFont(getFont());
        FontMetrics fm = g.getFontMetrics();
        
        // figure out rowHeight (must be done before labelWidth is
        // ever called, because CLComponent width calculation depends
        // on rowHeight)
        rowHeight = fm.getHeight() + 3;
        rowAscent = fm.getAscent() + 2;
        
        if (Global.isWindows() && showHorizontalLines)
            rowHeight++;
        else if (Global.isMotif() && !showHorizontalLines)
            rowHeight--;
        
        charWidth = fm.charWidth(/* NOI18N */ 'X');
        
        if ((componentHeight == 0) && (hasComponents != null))
            componentHeight = hasComponents.preferredSize().height;
        
        if (rowHeight < componentHeight) {
            rowAscent += (componentHeight - rowHeight) / 2;
            rowHeight = componentHeight;
        }
        if (showHeaders)
            headerHeight = rowHeight + 6;
        else
            headerHeight = 0;
        
        // figure out column widths
        dimensions = new int[(columns == 0) ? 1 : columns];
        totalWidth = 0;
        for (int c = 0; c < columns; c++) {
            // base size of columns on header string
            int width = fm.stringWidth(headers[c]) + 10;
            
            if (autoWidth) {
                // column should be the width of the widest data item
                for (int r = 0; r < records; r++) {
                    Object[] labelRow = (Object[]) labels.elementAt(r);
                    int itemWidth = labelWidth(labelRow[c]);
                    if (itemWidth > width)
                        width += itemWidth - width;
                }
            }
            
            dimensions[c] = width;
            totalWidth += dimensions[c];
        }
        
    }
    
    public void paint(Graphics g) {
        if (Global.isWindows())
            g = getGraphics();
        paint(g, null);
    }
    
    private synchronized void paint(Graphics g, Rectangle cliprect) {
        Image buffer = getBuffer(size());
        g = buffer.getGraphics();
        g.setFont(getFont());
        
        // first time? get the dimensions of the header panel
        cacheDimensions();
        
        // how many rows fit?
        Dimension canvasSize = size();
        int usableHeight = canvasSize.height - headerHeight;
        int usableWidth = canvasSize.width;
        dispRows = usableHeight / rowHeight;
        
        // visibleRows can be one more than
        // dispRows (last row partially visible)
        visibleRows = (usableHeight + rowHeight - 1) / rowHeight;
        // make sure we have enough labels...
        int horOffset = scrollx;
        int vertOffset = scrollrow;
        while ((visibleRows + vertOffset) > labels.size())
            addMoreLabels();
        
        g.setColor(getForeground());
        Color origColor = g.getColor();
        Color dark = getBackground().darker();
        Color veryDark = dark.darker();
        
        
        // draw the column headers
        int x = 0;
        int colWidth;
        if (showHeaders) {
            for (int c = 0; c <= columns; c++) {
                
                if (c == columns)
                    // last column fills up the rest
		    colWidth = usableWidth - x + horOffset;
                else
                    colWidth = dimensions[c];
                
                int left = x - horOffset;
                int right = left + colWidth - 1;
                int bottom = headerHeight - 1;
                
                // is the column for real, and some of it visible?
                if ((colWidth > 0) && ((right > 0) ||
				       (left < usableWidth))) {
                    // now draw the thing...
                    g.setColor(getBackground());
                    g.drawLine(left, 0, right, 0); // top
                    g.drawLine(left, 0, left, bottom); // left
                    
                    g.setColor(veryDark);
                    g.drawLine(left, bottom, right, bottom); // bottom
                    g.drawLine(right, 0, right, bottom); // right
                    
                    g.setColor(dark);
                    g.fillRect(left + 1, 1, colWidth - 2,
			       headerHeight - 2);
                    
                    g.setColor(origColor);
                    
                    // last column has no strings
                    if (c != columns)
                        drawString(g, headers[c], left + LEFT_PAD,
				   headerHeight - 5,
				   colWidth - LEFT_PAD - RIGHT_PAD,
				   getFormat(c));
                }
                
                if (c != columns)
                    x += dimensions[c];
            }
        }
        
        // now paint the data
        int y = headerHeight;
        for (int r = 0; r < labels.size(); r++) {
            if ((r >= vertOffset) && (r <
				      (visibleRows + vertOffset))) {
                x = 0;
                Object[] row = (Object[]) labels.elementAt(r);
                int rowColor = ((Integer) rowColors.elementAt(r)).
		    intValue();
                
                Color stringForeground =
		    getStringForeground(origColor, r, rowColor);
                Color stringBackground =
		    getStringBackground(r, rowColor);
                
                g.setColor(stringBackground);
                g.fillRect(0, y, usableWidth, rowHeight);
                g.setColor(stringForeground);
                
                for (int c = 0; c < columns; c++) {
                    colWidth = dimensions[c];
                    int left = x - horOffset;
                    int right = left + colWidth - 1;
                    
                    // is the column for real, and some of it visible?
                    if ((colWidth > 0) &&
			((right > 0) || (left < usableWidth))) {
                        if (row[c] != null)
                            if (row[c] instanceof String)
				drawString(g, (String) row[c],
					   left + LEFT_PAD,
					   y + rowAscent,
					   colWidth - LEFT_PAD - RIGHT_PAD,
					   getFormat(c));
			    else if (row[c] instanceof CLComponent)
				((CLComponent)row[c]).paint(g, left, y,
							    colWidth, rowHeight,
							    rowAscent,
							    getFormat(c));
			    else if (row[c] instanceof Component) {
				Component cb = (Component) row[c];
				Dimension size = cb.preferredSize();
				size = new Dimension(size.width,
						     size.height);
				if (size.width > (colWidth - 2))
				    size.width = colWidth - 2;
				cb.reshape(left + 2, y,
					   size.width, rowHeight);
				cb.setBackground(stringBackground);
				cb.setForeground(stringForeground);
				cb.show();
				// cb.validate();
			    } else
				drawString(g, row[c].toString(),
					   left + LEFT_PAD, y + rowAscent,
					   colWidth - LEFT_PAD - RIGHT_PAD,
					   getFormat(c));
                    } else {
                        if (row[c] != null)
                            if (row[c] instanceof Component) {
				Component cb = (Component) row[c];
				cb.hide();
			    }
                    }
                    x += dimensions[c];
                }
                y += rowHeight;
                if (showHorizontalLines) {
                    g.setColor(dark);
                    g.drawLine(0, y - 1, usableWidth, y - 1);
                }
                g.setColor(origColor);
            } else {
                Object[] row = (Object[]) labels.elementAt(r);
                for (int c = 0; c < row.length; c++)
                    if (row[c] instanceof Component)
			((Component) row[c]).hide();
            }
        } // for each row
        
        
        if (showVerticalLines) {
            g.setColor(dark);
            x = 0;
            for (int c = 0; c < columns; c++) {
                colWidth = dimensions[c];
                int left = x - horOffset;
                int right = left + colWidth - 1;
                
                // only draw if the line would be visible
                if (right > usableWidth)
                    break;
                if ((colWidth > 0) && (right > 0))
                    g.drawLine(right, headerHeight, right,
			       canvasSize.height);
                
                x += dimensions[c];
            }
        }
        
        if (editline != null)
            editline.paint(g);
        
        copyBuffer();
    }
    
    private Image getBuffer(Dimension size) {
        // WORK-AROUND: sometimes size() calls return
        // dimensions of 0 for width
        // or height when they probably shouldn't
        // (this is on Win95), and it
        // causes an illegal argument exception in
        // the createImage call below
        if (size.width == 0 || size.height == 0) {
            if (buffer != null && bufferSize != null)
                size = new Dimension(bufferSize);
            else
                size = new Dimension(1, 1);
        }
        // end of WORK-AROUND
        
        if (buffer == null || bufferSize == null ||
	    (size.width != bufferSize.width) ||
	    (size.height != bufferSize.height)) {
            
            getCachedBuffer(size);
            
            if (buffer == null || bufferSize == null ||
		(size.width != bufferSize.width) ||
		(size.height != bufferSize.height)) {
                buffer = createImage(size.width, size.height);
                updateCache(buffer, size);
            }
            
            bufferSize = size;
        }
        
        return buffer;
    }
    
    private Graphics getBufferGraphics() {
        Image buffer = getBuffer(size());
        if (buffer == null)
            return null;
        else
            return buffer.getGraphics();
    }
    
    private void copyBuffer() {
        Graphics g = getGraphics();
        Image buffer = getBuffer(size());
        if (g != null && buffer != null)
            g.drawImage(buffer, 0, 0, this);
    }
    
    private void getCachedBuffer(Dimension size) {
        for (int i = 0; i < 3; i++) {
            if (bufferSizeCache[i] != null &&
		bufferSizeCache[i].width == size.width &&
		bufferSizeCache[i].height == size.height) {
                buffer = bufferCache[i];
                bufferSize = bufferSizeCache[i];
                break;
            }
        }
    }
    
    private void updateCache(Image buffer, Dimension size) {
        if (buffer == null)
            return;
        
        int i;
        for (i = 0; i < 3; i++) {
            if (bufferSizeCache[i] == null)
                break;
        }
        
        if (i < 3) {
            bufferCache[i] = buffer;
            bufferSizeCache[i] = new Dimension(size.width, size.height);
        } else {
            bufferCache[0] = bufferCache[1];
            bufferCache[1] = bufferCache[2];
            bufferCache[2] = buffer;
            
            bufferSizeCache[0] = bufferSizeCache[1];
            bufferSizeCache[1] = bufferSizeCache[2];
            bufferSizeCache[2] = new Dimension(size.width, size.height);
        }
    }
    
    /**
     * ...
     *
     * @param ...    ...
     * @return       ...
     * @exception    ...
     */
    private Color getStringForeground(Color origColor,
				      int row, int rowColor) {
        if (row == selectedRow)
            return getBackground();
        else
            return origColor;
    }
    
    private Color getStringBackground(int row, int rowColor) {
        Color bg = getBackground();
        if (row == selectedRow) {
            if (rowColor != COLOR_NONE)
                if (bg == Color.white)
		    return Color.magenta;
		else
		    return selectColor.darker();
            else
                return selectColor;
        } else {
            if (rowColor != COLOR_NONE)
                if (bg == Color.white)
		    return Color.orange;
		else
		    return bg.darker();
            else
                return getBackground();
        }
        
    }
    
    private boolean rowVisible(int row) {
        return ((row >= scrollrow) &&
		(row < (scrollrow + dispRows)));
    }
    
    
    public void updateView() {
        parent.updateView();
    }
    
    
    /**
     * @see sunsoft.jws.visual.designer.gui.ColumnList
     */
    public void setDisplayRows(int rows) {
        requestedRows = rows;
    }
    
    
    public void setVisibleChars(int chars) {
        requestedChars = chars;
    }
    
    
    /**
     * the minimum width is enough to fully display 
     * the first column, but not
     * more than 200 pixels. The minimum height is the
     * height to display the
     * number of rows requested with setDisplayRows() (default is 3)
     *
     * @return       Dimension
     */
    public Dimension minimumSize() {
        return preferredSize();
    }
    
    /**
     * Calculate the preferred size. Standard AWT function.
     *
     * @return       the preferred size of the ColumnListCanvas
     */
    public Dimension preferredSize() {
        cacheDimensions();
        if (dimensions == null)
            return new Dimension(100, 100);
        else
            if (requestedChars == 0)
		return new Dimension(totalWidth,
				     headerHeight + rowHeight * requestedRows);
	    else
		return new Dimension(requestedChars * charWidth,
				     headerHeight + rowHeight * requestedRows);
    }
    
    
    /**
     * select row, and make it visible
     * only one row can be selected at a time - previously selected
     * rows will be restored to normal
     * to remove the selection, set the selected row to -1
     *
     * @param row    index of row
     * @return       actual index of selected row, -1 if none
     */
    public int selectRow(int row) {
        if (selectedRow != row) {
            int oldSelectedRow = selectedRow;
            if (row < records)
                selectedRow = row;
            else
                selectedRow = -1;
            
            // make sure we can see the new selection
            // Tilman 05/21: Not tested if the makeVisible() call works
            if ((selectedRow != -1) && (!rowVisible(selectedRow)))
                parent.makeVisible(selectedRow);
            
            // repaint if anything is visible
            if (rowVisible(oldSelectedRow) || rowVisible(selectedRow))
                repaint();
        }
        return selectedRow;
    }
    
    
    /**
     * Get the index of the currently selected row
     *
     * @return       index of selected row, -1 if none is selected
     */
    public int getSelectedRow() {
        return selectedRow;
    }
    
    
    /**
     * ...
     *
     * @param ...    ...
     * @return       ...
     * @exception    ...
     */
    protected int getRowY(int row) {
        if ((dimensions == null) || (visibleRows == -1))
            return -2;
        if (rowVisible(row)) {
            return headerHeight + rowHeight * (row - scrollrow);
        } else
            return -1;
    }
    
    
    /**
     * ...
     *
     * @param ...    ...
     * @return       ...
     * @exception    ...
     */
    private synchronized void startDrag(int startX) {
        int x = -scrollx;
        for (int c = 0; c < columns; c++) {
            x += dimensions[c];
            if ((startX >= (x - 5)) && (startX <= (x + 5))) {
                dragColumn = c;
                dragging = true;
                dragStart = startX;
                break;
            }
        }
    }
    
    
    /**
     * ...
     *
     * @param ...    ...
     * @return       ...
     * @exception    ...
     */
    private synchronized int mouseColumn(int mouseX) {
        int x = -scrollx;
        if (mouseX < x)
            return -1;
        for (int c = 0; c < columns; c++) {
            x += dimensions[c];
            if (mouseX < x)
                return c;
        }
        return -1;
    }
    
    
    /**
     * ...
     *
     * @param ...    ...
     * @return       ...
     * @exception    ...
     */
    private synchronized void dragColumn(int dragX) {
        int diff = dragX - dragStart;
        if (dimensions[dragColumn] + diff >= 5) {
            dimensions[dragColumn] += diff;
            totalWidth += diff;
            dragStart = dragX;
            repaint();
        }
    }
    
    public boolean handleEvent(Event evt) {
        //
        // Workaround for an AWT bug on Windows95
        // where we get a spurious
        // mouse down event when the CLChoice menu is
        // unmapped as the result
        // of selection being made from a mouse down
        // event inside the menu.
        //
        if (editchoice == null && justCancelled &&
	    evt.id == Event.MOUSE_DOWN) {
            justCancelled = false;
            return true;
        }
        justCancelled = false;
        
        if (editline != null && editline.handleEvent(evt))
            return true;
        else if (editchoice != null && editchoice.handleEvent(evt))
            return true;
        
        if (evt.id == EditLine.REPAINT && evt.target == editline) {
            if (evt.arg != null) {
                paint(getGraphics(), (Rectangle)evt.arg);
            } else {
                editline.paint(getBufferGraphics());
                copyBuffer();
            }
        } else if (evt.id == EditLine.APPLY && evt.target == editline) {
            cancelApply = false;
            parent.postEvent(new Event(parent, ColumnList.APPLY_EDIT,
				       evt.arg));
            if (!cancelApply) {
                changeText((String)evt.arg, editrow, editcolumn);
                cancelEdit();
            } else if (editline != null) {
                editline.cancelApply();
            }
        } else if (evt.id == EditLine.CANCEL &&
		   evt.target == editline) {
            cancelEdit();
        } else if (evt.id == CLChoice.APPLY &&
		   evt.target == editchoice) {
            cancelApply = false;
            parent.postEvent(new Event(parent, ColumnList.APPLY_EDIT,
				       evt.arg));
            if (!cancelApply) {
                changeText((String)evt.arg, editrow, editcolumn);
                cancelEdit();
            }
        } else {
            return super.handleEvent(evt);
        }
        
        return true;
    }
    
    public synchronized void changeText(String text, int row,
					int column) {
        if (row < 0 || row >= records || column < 0 ||
	    column >= columns)
	    return;
        
        Object[] data = (Object []) labels.elementAt(row);
        Object item = data[column];
        
        if (item instanceof String) {
            data[column] = text;
            adjustColumnWidths(text, column);
            parent.updateView();
        } else if (item instanceof CLComponent) {
            ((CLComponent)item).setText(text, true);
        }
    }
    
    public int columnX(int column) {
        int x = -scrollx;
        for (int c = 0; c < column; c++)
            x += dimensions[c];
        return x;
    }
    
    public int columnWidth(int column) {
        return dimensions[column];
    }
    
    public int rowY(int row) {
        return headerHeight + ((row - scrollrow) * rowHeight);
    }
    
    public int rowHeight(int row) {
        return rowHeight;
    }
    
    public boolean mouseDown(Event e, int x, int y) {
        if (editline != null) {
            if (!applyChanges())
                return false;
            selectRow(-1);
        } else if (editchoice != null) {
            cancelEdit();
            selectRow(-1);
        }
        
        if (y > headerHeight) {
            int row = (y - headerHeight - 1) / rowHeight + scrollrow;
            if (row < records) {
                int column = mouseColumn(x);
                if (column != -1) {
                    Object entry = ((Object[])
				    labels.elementAt(row))[column];
                    if ((entry instanceof CLComponent) && editable) {
                        CLComponent comp = (CLComponent)entry;
                        Event evt = new Event(e.target, e.when, e.id,
					      x - columnX(column),
					      y - rowY(row), e.key,
					      e.modifiers, e.arg);
                        evt.clickCount = e.clickCount;
                        if (comp.mouseDown(evt))
                            return true;
                    }
                }
                if (selectable) {
                    cancelSelect = false;
                    if (e.clickCount == 1) {
                        if (row == getSelectedRow() &&
			    getTextEditable(column)) {
                            cancelEdit();
                            if (startEdit(column, x)) {
                                return true;
                            } else {
                                // Should make a beeping or
                                // clicking noise somehow.
                            }
                        }
                        
                        parent.postEvent(new Event(parent,
					   ColumnList.CONFIRM_SELECT,
						new Integer(row)));
                        if (!cancelSelect) {
                            row = selectRow(row);
                            parent.postEvent(new Event(parent,
						       Event.LIST_SELECT,
						       new Integer(row)));
                        }
                    } else if (e.clickCount == 2) {
                        row = selectRow(row);
                        parent.postEvent(new Event(parent,
						   Event.ACTION_EVENT,
						   new Integer(row)));
                    }
                }
            }
        } else if (y < headerHeight) {
            startDrag(x);
        }
        return true;
    }
    
    
    /**
     * ...
     *
     * @param ...    ...
     * @return       ...
     * @exception    ...
     */
    public boolean mouseDrag(Event e, int x, int y) {
        if (dragging) {
            dragColumn(x);
            return true;
        }
        return false;
    }
    
    
    /**
     * ...
     *
     * @param ...    ...
     * @return       ...
     * @exception    ...
     */
    public boolean mouseUp(Event e, int x, int y) {
        if (dragging) {
            dragging = false;
            parent.updateView();
            return true;
        }
        return false;
    }
    
    boolean resizeCursor = false;
    boolean checkedFrame = false;
    
    private Frame getFrame() {
        if (ourFrame == null) {
            if (!checkedFrame) {
                checkedFrame = true;
                Component c = parent;
                while (c != null) {
                    if (c instanceof Frame) {
                        ourFrame = (Frame) c;
                        break;
                    } else
                        c = c.getParent();
                }
            }
        }
        return ourFrame;
    }
    
    
    public boolean mouseMove(Event e, int x, int y) {
        if (getFrame() != null) {
            boolean resizable = false;
            
            if (y < headerHeight) {
                int x1 = -scrollx;
                for (int c = 0; c < columns; c++) {
                    x1 += dimensions[c];
                    if ((x >= (x1 - 5)) && (x <= (x1 + 5))) {
                        resizable = true;
                        break;
                    }
                }
            }
            
            if (resizable != resizeCursor) {
                if (resizable)
                    ourFrame.setCursor(Frame.E_RESIZE_CURSOR);
                else
                    ourFrame.setCursor(Frame.DEFAULT_CURSOR);
                
                resizeCursor = resizable;
            }
            return true;
        } else
            return false;
    }
    
    
    /**
     * restore the cursor when exiting 
     *
     * @param ...    ...
     * @return       ...
     */
    public boolean mouseExit(Event e, int x, int y) {
        if (resizeCursor) {
            ourFrame.setCursor(Frame.DEFAULT_CURSOR);
            resizeCursor = false;
        }
        return false;
    }
    
    
    /**
     * ...
     *
     * @return       ...
     */
    public synchronized boolean updateRowColors() {
        int r;
        boolean isChanging = false;
        boolean needsRepaint = false;
        for (r = 0; r < records; r++) {
            int rowColor = ((Integer)
			    rowColors.elementAt(r)).intValue();
            if (rowColor != COLOR_NONE) {
                if (rowColor == 1)
                    needsRepaint = true;
                isChanging = true;
                rowColors.setElementAt(new Integer(rowColor - 1), r);
            }
        }
        if (needsRepaint)
            repaint();
        return isChanging;
    }
    
    
    /**
     * ...
     */
    void cancelSelect() {
        cancelSelect = true;
    }
}
