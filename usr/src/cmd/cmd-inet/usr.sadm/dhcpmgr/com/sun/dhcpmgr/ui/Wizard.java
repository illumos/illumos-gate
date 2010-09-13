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
 * Copyright 1998-2002 by Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
package com.sun.dhcpmgr.ui;

import javax.swing.*;
import javax.swing.border.*;

import java.awt.event.*;
import java.awt.*;
import java.util.*;
import java.text.NumberFormat;

// Interface for notification of button events
interface WizButtonListener {
    public void buttonPressed(int buttonId);
    public static final int BACK = 0;
    public static final int FORWARD = 1;
    public static final int CANCEL = 2;
    public static final int HELP = 3;
    public static final int FINISH = 4;
}

/**
 * This is a widget for presenting a multi-step task, such as an installation
 * sequence or other task with many questions or multiple possible paths.  This
 * component displays as a dialog, with a contents outline on the left and a
 * panel for display of each step on the right, with a set of control buttons
 * at the bottom.  Typical usage is to subclass this class and implement a set
 * of WizardStep classes which provide the steps to be executed.
 *
 * @see WizardStep
 */
public class Wizard extends JDialog {

    // Panel to manage display and processing of buttons at base of window
    class WizButtonPanel extends JPanel {
    
	// Adaptor class to catch all button presses and pass along to listeners
	class ButtonAdaptor implements ActionListener {
	    public void actionPerformed(ActionEvent e) {
		int buttonId = -1;
		Object source = e.getSource();
		if (source == backButton || source == backButton2) {
		    buttonId = WizButtonListener.BACK;
		} else if (source == forwardButton) {
		    buttonId = WizButtonListener.FORWARD;
		} else if (source == cancelButton || source == cancelButton2) {
		    buttonId = WizButtonListener.CANCEL;
		} else if (source == helpButton || source == helpButton2) {
		    buttonId = WizButtonListener.HELP;
		} else if (source == finishButton) {
		    buttonId = WizButtonListener.FINISH;
		}
		Enumeration en = listeners.elements();
		while (en.hasMoreElements()) {
		    WizButtonListener l = (WizButtonListener)en.nextElement();
		    l.buttonPressed(buttonId);
		}
	    }
	}
	
	PreviousButton backButton, backButton2;
	NextButton forwardButton;
	JButton cancelButton, helpButton, finishButton;
	JButton cancelButton2, helpButton2;
	Vector listeners;
	ButtonAdaptor adaptor;
	JPanel innerPanel;
	
	public WizButtonPanel() {	    
	    super();

	    setBorder(new EtchedBorder());
	    // Right justify the buttons
	    setLayout(new FlowLayout(FlowLayout.RIGHT));
	    innerPanel = new JPanel(new CardLayout());
	    
	    // Create event handler
	    adaptor = new ButtonAdaptor();
	    listeners = new Vector();

	    /*
	     * Construct back buttons; need 2 for the separate cards used
	     * in the button panel
	     */
	    backButton = new PreviousButton();
	    backButton2 = new PreviousButton();
	    backButton.addActionListener(adaptor);
	    backButton2.addActionListener(adaptor);
	    backButton.setAlignmentY(Component.CENTER_ALIGNMENT);
	    backButton2.setAlignmentY(Component.CENTER_ALIGNMENT);

	    // Construct forward button
	    forwardButton = new NextButton();
	    forwardButton.addActionListener(adaptor);
	    forwardButton.setAlignmentY(Component.CENTER_ALIGNMENT);
	   
	    Mnemonic mnFinish = 
		new Mnemonic(ResourceStrings.getString("finish_button"));
	    finishButton = new JButton(mnFinish.getString());
	    finishButton.setToolTipText(mnFinish.getString());
            finishButton.setMnemonic(mnFinish.getMnemonic());
	    finishButton.addActionListener(adaptor);
	    finishButton.setAlignmentY(Component.CENTER_ALIGNMENT);
  	
	    Mnemonic mnCancel = 
		new Mnemonic(ResourceStrings.getString("cancel_button"));     
            cancelButton = new JButton(mnCancel.getString());    
            cancelButton.setToolTipText(mnCancel.getString());   
            cancelButton.setMnemonic(mnCancel.getMnemonic()); 

	    cancelButton.addActionListener(adaptor);
	    cancelButton.setAlignmentY(Component.CENTER_ALIGNMENT);

	    cancelButton2 = new JButton(mnCancel.getString());
	    cancelButton2.setToolTipText(mnCancel.getString());   
            cancelButton2.setMnemonic(mnCancel.getMnemonic()); 

	    cancelButton2.addActionListener(adaptor);
	    cancelButton2.setAlignmentY(Component.CENTER_ALIGNMENT);

            Mnemonic mnHelp = 
		new Mnemonic(ResourceStrings.getString("help_button"));
            helpButton = new JButton(mnHelp.getString());
            helpButton.setToolTipText(mnHelp.getString());
            helpButton.setMnemonic(mnHelp.getMnemonic());
 
	    helpButton.addActionListener(adaptor);
	    helpButton.setAlignmentY(Component.CENTER_ALIGNMENT);

	    helpButton2 = new JButton(mnHelp.getString());
            helpButton2.setToolTipText(mnHelp.getString());
            helpButton2.setMnemonic(mnHelp.getMnemonic());

	    helpButton2.addActionListener(adaptor);
	    helpButton2.setAlignmentY(Component.CENTER_ALIGNMENT);
	    
	    /*
	     * Now create cards; we created two copies of buttons that
	     * needed to be on both cards
	     */
	    Box box = Box.createHorizontalBox();
	    box.add(Box.createHorizontalGlue());
	    box.add(backButton);
	    box.add(Box.createHorizontalStrut(5));
	    box.add(forwardButton);
	    box.add(Box.createHorizontalStrut(5));
	    box.add(cancelButton);
	    box.add(Box.createHorizontalStrut(5));
	    box.add(helpButton);
	    innerPanel.add(box, "normal");
	    
	    // Finish panel replaces the forward button with the finish button
	    box = Box.createHorizontalBox();
	    box.add(Box.createHorizontalGlue());
	    box.add(backButton2);
	    box.add(Box.createHorizontalStrut(5));
	    box.add(finishButton);
	    box.add(Box.createHorizontalStrut(5));
	    box.add(cancelButton2);
	    box.add(Box.createHorizontalStrut(5));
	    box.add(helpButton2);
	    innerPanel.add(box, "finish");

	    add(innerPanel);
	}
	
	// Show the first step
	public void showFirst() {
	    backButton.setEnabled(false); // Can't go backwards
	    setForwardEnabled(false);
	    getRootPane().setDefaultButton(forwardButton);
	    forwardButton.requestFocus(true);
	    ((CardLayout)innerPanel.getLayout()).show(innerPanel, "normal");
	}
	
	// Show the last step
	public void showLast() {
	    backButton.setEnabled(true);
	    setFinishEnabled(false);
	    getRootPane().setDefaultButton(finishButton);
	    finishButton.requestFocus(true);
	    ((CardLayout)innerPanel.getLayout()).show(innerPanel, "finish");
	}
	
	// Show any other step
	public void showMiddle() {
	    backButton.setEnabled(true);
	    setForwardEnabled(false);
	    getRootPane().setDefaultButton(forwardButton);
	    cancelButton.requestFocus(true);
	    ((CardLayout)innerPanel.getLayout()).show(innerPanel, "normal");
	}
	
	// Allow steps to control when user may advance to next step
	public void setForwardEnabled(boolean state) {
	    forwardButton.setEnabled(state);
	}
	
	// Allow the final step to control when a user may complete the task
	public void setFinishEnabled(boolean state) {
	    finishButton.setEnabled(state);
	}
	
	public void addWizButtonListener(WizButtonListener l) {
	    listeners.addElement(l);
	}
	
	public void removeWizButtonListener(WizButtonListener l) {
	    listeners.removeElement(l);
	}
    }
    
    /*
     * Panel to display the list of steps; we use a very custom JList
     * for this as it does reasonable rendering with minimal effort on our part.
     */
    class WizContentsPanel extends JPanel {
	
	// Data model for holding the description text displayed
	class ContentsModel extends AbstractListModel {
	    Vector data;
	    
	    public ContentsModel() {
		data = new Vector();
	    }
	    
	    public Object getElementAt(int index) {
		return data.elementAt(index);
	    }
	    
	    public int getSize() {
		return data.size();
	    }
	    
	    public void addItem(String description) {
		data.addElement(description);
		fireIntervalAdded(this, data.size()-1, data.size()-1);
	    }
	}
	
	// Class to render the cells in the list
	class ContentsRenderer implements ListCellRenderer {
	    NumberFormat nf;
	    
	    public ContentsRenderer() {
		nf = NumberFormat.getInstance();
	    }
	    
	    public Component getListCellRendererComponent(JList list,
		    Object value, int index, boolean isSelected,
		    boolean cellHasFocus) {

		// Format label properly for i18n
		JTextArea text = new JTextArea((String)value, 2, 15);
		text.setWrapStyleWord(true);
		text.setLineWrap(true);
		text.setOpaque(false);
		text.setAlignmentY(Component.TOP_ALIGNMENT);
		JLabel l = new JLabel(nf.format(index + 1));
		l.setForeground(Color.black);
		l.setAlignmentY(Component.TOP_ALIGNMENT);
		
		JPanel stepBox = new JPanel();
		stepBox.setLayout(new BoxLayout(stepBox, BoxLayout.X_AXIS));
		stepBox.add(l);
		stepBox.add(Box.createHorizontalStrut(5));
		stepBox.add(text);
		stepBox.setBackground(list.getSelectionBackground());
		// Selected component is opaque, others transparent
		stepBox.setOpaque(isSelected);
		return stepBox;
	    }
	}
	
	/*
	 * This class is defined strictly so that we can prevent
	 * focus from ever reaching the steps list as it is a display-only
	 * use of JList, not intended for any sort of input by the user.
	 */
	class MyList extends JList {
	    public MyList(ListModel m) {
	        super(m);
		// Don't allow this list to be focused
		setFocusable(false);
	    }
	    // Ignore mouse clicks so highlighted step can't be changed
	    protected void processMouseEvent(MouseEvent e) {
		return;
	    }
	    // Ignore mouse drags, which can also change highlighting
	    protected void processMouseMotionEvent(MouseEvent e) {
		return;
	    }
	}

	MyList contentsList;
	ContentsModel model;
	
	public WizContentsPanel() {
	    setBorder(BorderFactory.createEmptyBorder(10, 5, 10, 10));
	    setBackground(Color.white);
	    setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));

	    Mnemonic mnSteps = 
		new Mnemonic(ResourceStrings.getString("steps_label"));
	    JLabel l = new JLabel(mnSteps.getString());
	    l.setLabelFor(this);
	    l.setToolTipText(mnSteps.getString());
	    l.setDisplayedMnemonic(mnSteps.getMnemonic());

	    l.setForeground(Color.black);
	    l.setAlignmentX(Component.LEFT_ALIGNMENT);
	    add(l);
    
	    model = new ContentsModel();
	    contentsList = new MyList(model);
	    contentsList.setCellRenderer(new ContentsRenderer());
	    /*
	     * Wrap the list with scroll bars, vertical as necessary but
	     * never a horizontal one.
	     */
	    JScrollPane scrollPane = new JScrollPane(contentsList,
		ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
		ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
	    scrollPane.setBorder(BorderFactory.createEmptyBorder(15, 10, 0, 0));
	    scrollPane.setAlignmentX(Component.LEFT_ALIGNMENT);
	    scrollPane.setBackground(Color.white);
	    add(scrollPane);
	    add(Box.createVerticalGlue());
	}
	
	public void addStep(WizardStep step) {
	    // Index the steps using the description string
	    model.addItem(step.getDescription());
	}
	
	public void showStep(WizardStep step) {
	    contentsList.setSelectedValue(step.getDescription(), true);
	}
    }

    /*
     * This class provides a simple card layout to display each step as needed.
     */	    
    class WizStepPanel extends JPanel {
	CardLayout layout;
	
	public WizStepPanel() {
	    setLayout(layout = new CardLayout());
	    // Make sure we have some space around the edges.
	    setBorder(BorderFactory.createEmptyBorder(15, 10, 10, 10));
	}
	
	public void addStep(WizardStep step) {
	    add(step.getComponent(), step.getDescription());
	}
	
	public void showStep(WizardStep step) {
	    layout.show(this, step.getDescription());
	}
    }
    
    WizButtonPanel buttonPanel;
    WizContentsPanel contentsPanel;
    WizStepPanel stepPanel;
    Vector steps;
    WizardStep activeStep = null;
    int stepNumber = 0;
    Vector listeners;

    /**
     * Constructs a wizard with the specified owning frame and title.
     *
     * @param	owner	the owning frame
     * @param	title	the wizard's title string
     */ 
    public Wizard(Frame owner, String title) {
	super(owner, title);
	
	setLocationRelativeTo(owner);

	getContentPane().setLayout(new BorderLayout());
	steps = new Vector();
	listeners = new Vector();
	
	// Put the buttons at the bottom.
	buttonPanel = new WizButtonPanel();
	getContentPane().add(buttonPanel, BorderLayout.SOUTH);
	
	/*
	 * The main display is designed to use a 7:11 ratio for the horizontal
	 * area consumed by the contents panel and the display panel,
	 * respectively.  There's nothing particularly magical about the
	 * ratio, that's just the way the designer drew it.
	 */	
	JPanel mainPanel = new JPanel(new ProportionalLayout());
	
	contentsPanel = new WizContentsPanel();
	mainPanel.add(contentsPanel, "7");
		
	stepPanel = new WizStepPanel();
	mainPanel.add(stepPanel, "11");
	
	// Consume all space not needed for buttons
	getContentPane().add(mainPanel, BorderLayout.CENTER);
	
	/*
	 * We manage the button interactions, but the steps get limited veto
	 * power
	 */
	buttonPanel.addWizButtonListener(new WizButtonListener() {
	    public void buttonPressed(int buttonId) {
		switch (buttonId) {
		case BACK:
		    showPreviousStep();
		    break;
		case FORWARD:
		    showNextStep();
		    break;
		case FINISH:
		    doFinish();
		    break;
		case CANCEL:
		    doCancel();
		    break;
		case HELP:
		    doHelp();
		    break;
		default:
		}
	    }
	});
    }
    
    /**
     * Override of setVisible to control size when displayed.  Perhaps this
     * should be relaxed, but subclasses can always do whatever they want.
     * @param state make visible or not?
     */
    public void setVisible(boolean state) {
	if (state) {
	    setSize(525, 425);
	}
	super.setVisible(state);
    }
    
    /**
     * Adds a step to the wizard.  Steps <bold>must</bold> be added in the
     * sequence they will be displayed when traversing forward.
     * @param step a <code>WizardStep</code>
     */
    public void addStep(WizardStep step) {
	steps.addElement(step);
	contentsPanel.addStep(step);
	stepPanel.addStep(step);
    }
    
    private boolean showStep(WizardStep step, int direction) {
	// Deactivate currently active step
	if (activeStep != null) {
	    if (!activeStep.setInactive(direction)) {
		// Step vetoed its deactivation.  We honor its wishes.
		return false;
	    }
	}
	/*
	 * Activate new step by updating contents, display area, and possibly
	 * buttons
	 */
	activeStep = step;
	contentsPanel.showStep(step);
	stepPanel.showStep(step);
	if (step == steps.firstElement()) {
	    buttonPanel.showFirst();
	} else if (step == steps.lastElement()) {
	    buttonPanel.showLast();
	} else {
	    buttonPanel.showMiddle();
	}
	activeStep.setActive(direction);
	return true;
    }
    
    // Show some arbitrary step indexed by number.
    private boolean showStep(int index, int direction)
	    throws ArrayIndexOutOfBoundsException {
	WizardStep ws = (WizardStep)steps.elementAt(index);
	return showStep(ws, direction);
    }
    
    /**
     * Show the very first step.
     */
    public void showFirstStep() {
	stepNumber = 0;
	showStep(stepNumber, WizardStep.FORWARD);
    }
    
    /**
     * Show the next step.
     */
    public void showNextStep() {
	++stepNumber;
	try {
	    // Handle step vetoing deactivation
	    if (!showStep(stepNumber, WizardStep.FORWARD)) {
		--stepNumber;
	    }
	} catch (ArrayIndexOutOfBoundsException e) {
	    --stepNumber;
	}
    }
    
    /**
     * Show the previous step.
     */
    public void showPreviousStep() {
	--stepNumber;
	try {
	    if (!showStep(stepNumber, WizardStep.BACKWARD)) {
		++stepNumber;
	    }
	} catch (ArrayIndexOutOfBoundsException e) {
	    ++stepNumber;
	}
    }
    
    /**
     * Show the last step.
     */
    public void showLastStep() {
	int saveStep = stepNumber;
	stepNumber = steps.size()-1;
	try {
	    if (!showStep(stepNumber, WizardStep.FORWARD)) {
		stepNumber = saveStep;
	    }    
	} catch (ArrayIndexOutOfBoundsException e) {
	    stepNumber = saveStep;
	}
    }
    
    /**
     * Control state of the forward button.
     * @param state <code>true</code> to enable the button
     */
    public void setForwardEnabled(boolean state) {
	buttonPanel.setForwardEnabled(state);
    }
    
    /**
     * Control state of the finish button.
     * @param state <code>true</code> to enable the button
     */
    public void setFinishEnabled(boolean state) {
	buttonPanel.setFinishEnabled(state);
    }
    
    /**
     * Handle user's press of the Cancel button.  Subclasses can override for
     * special cleanup needs.
     */
    public void doCancel() {
	fireActionPerformed("cancelled");
	dispose();
    }
    
    /**
     * Handle user's press of the Finish button.  Subclasses should override
     * to perform whatever processing needed to complete the wizard's task.
     */
    public void doFinish() {
	fireActionPerformed("finished");
	dispose();
    }
    
    /**
     * Handle user's press of the Help button.  Does nothing by default,
     * subclasses can override to provide help as desired.
     */
    public void doHelp() {
    }

    /**
     * Utility function to create a multi-line text display such as for the
     * explanatory text that most wizard steps use.
     * @param text the text to display
     * @param rows the number of rows to use for displaying the text
     * @param columns the number of columns to wrap text at.  45 is generally a
     *			good number for standard wizards with standard fonts
     * @return a <code>JComponent</code> displaying the supplied text
     */
    public static JComponent createTextArea(
	    String text, int rows, int columns) {

	// We extend JTextArea in order to make this behave more like a label
	class MyTextArea extends JTextArea {
	    public MyTextArea(String text, int rows, int columns) {
		/*
		 * Create a text area with word-wrapping, no editing, 
		 * and no background.
		 */
		super(text, rows, columns);
		setLineWrap(true);
		setWrapStyleWord(true);
		setEditable(false);
		setOpaque(false);
		setFocusable(false);
	    }
	}

	MyTextArea area = new MyTextArea(text, rows, columns);

	// Put it in a scrollpane to get sizing to happen
	JScrollPane scrollPane = new JScrollPane(area,
	    ScrollPaneConstants.VERTICAL_SCROLLBAR_NEVER,
	    ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);

	// Put empty borders on the subcomponents so that all we get is text
	Border b = BorderFactory.createEmptyBorder();
	area.setBorder(b);
	scrollPane.setBorder(b);
	return scrollPane;
    }
    
    /**
     * Add a listener for action events.  Wizard fires an
     * <code>ActionEvent</code> when user either cancels or finishes the wizard.
     */
    public void addActionListener(ActionListener l) {
	listeners.addElement(l);
    }
    
    /**
     * Remove an action listener.
     */
    public void removeActionListener(ActionListener l) {
	listeners.removeElement(l);
    }
    
    /**
     * Fire an action event.
     */
    protected void fireActionPerformed(String command) {
	ActionEvent e = new ActionEvent(this, ActionEvent.ACTION_PERFORMED,
	    command);
	for (Enumeration en = listeners.elements(); en.hasMoreElements(); ) {
	    ActionListener l = (ActionListener)en.nextElement();
	    l.actionPerformed(e);
	}
    }
}
