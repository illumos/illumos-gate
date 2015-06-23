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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

    import java.awt.*;
    import java.awt.event.*;

    /**
     * Creates a panel with two buttons (+ and - side by side on it). The
     * panel registers a DCListener with it that gets notified whenever
     * these butons are clicked. <bold>The buttons may also be kept continously
     * pressed for faster increments/decrements.</bold>
     * <para>
     * On a single click of the button, the listener is notified to
     * increment/decrement itself by a small amount. When the button is kept
     * pressed the following notifications are sent out for larger
     * increments/decrements. (It is up to the listener to decide the
     * increment/decrement corresponding to large/small.) Moreover, these
     * notifications will be sent out much faster if the button is kept
     * pressed.
     */

    // The panel waits for a period of BIG_SLEEP_TIME before the faster
    // increments are sent out. They, in turn, are sent out after
    // intervals of SMALL_SLEEP_TIME. Therfore, an instance of this class
    // is associated with 2 timers - a longer one that starts off and then
    // schedules the shorter one. The shorter one keeps scheduling itself
    // every time it wakes up.

    public class DCPanel extends Panel {

    private Button plusButton;
    private Button minusButton;

    private DCListener listener = null;

    private Timer bigTimer;
    private Timer smallTimer;

    private static int BIG_SLEEP_TIME	= 1000;
    private static int SMALL_SLEEP_TIME = 100;

    private boolean incrementFlag;

    public DCPanel() {

    setLayout(new GridLayout(1, 2));

    bigTimer	 = new BigTimer();
    smallTimer	 = new SmallTimer();

    bigTimer.start();
    smallTimer.start();

    plusButton = new DCButton("+");
    minusButton = new DCButton("-");

    add(plusButton);
    add(minusButton);

    }

    /**
     * Ensures that this component is not brought into focus by
     * tabbing. This prevents the tab focus from moving in here instead
     * of going to a text field.
     * @return false always.
     */
    public boolean isFocusable() {
    return false;
    }

    /**
     * Sets the listener for this tab.
     * @param listener the DCListener that needs to be notified when the
     * buttons on this panel are pressed.
     * @return the old listener
     */
    public DCListener setListener(DCListener listener) {
    DCListener oldListener = this.listener;
    this.listener = listener;
    return oldListener;
    }

    /**
     * Removes the listener when it no longer need to be notified.
     * @return the old listener
     */
    public DCListener removeListener() {
    return setListener(null);
    }

    /**
     * Kicks the times into action. Is called when a button is pressed.
     */
    private void startAction() {
    bigTimer.request();
    }

    /**
     * Stops the timers. Is called when a button is released.
     */
    private void stopAction() {
    smallTimer.cancel();
    bigTimer.cancel();
    }

    /**
     * Notifies the listener about whether to increment or decrement and
     * by how much.
     * @param bigFlag true if the listener needs to increment/decrement
     * by a large amount, false otherwise.
     */
    private void informListener(boolean bigFlag) {
    // System.out.println("DCPanel.informListener: " + bigFlag);

	if (listener != null) {

	    if (bigFlag) {
	    // request a big change
	    if (incrementFlag)
		listener.bigIncrement();
	    else
		listener.bigDecrement();
	    } else {
	    // request a small change
	    if (incrementFlag)
		listener.increment();
	    else
		listener.decrement();
	    }

	}

    } // informListener


    // ***********************************************
    //	 I N N E R    C L A S S E S   F O L L O W
    // ***********************************************

    /**
     * A timer class since java does not have one.
     */
    private abstract class Timer extends Thread {
    private boolean running = false;

    /**
     * Sleeps till the timer's services are requested using wait() and
     * notify(). Then it does its task and goes back to sleep. And
     * loops forever like this.
     */
    public void run() {
	while (true) {
	try {
	  synchronized (this) {
	    running = false;
	    // Wait till the timer is required
	    wait();
	    running = true;
	  }
	  doTask();
	} catch (InterruptedException e) {}
	} // while loop
    } // run method

    protected void doTask() {} // bug in java workshop

    /**
     * Wakes up the timer.
     */
    public synchronized void request() {
	notify();
    }

    /**
     * Cancels the timer if it is running.
     */
    public void cancel() {
	if (running) {
	interrupt();
	}
    }

    }// class Timer

    /**
     * The first stage of timer - is a longer timer. Wait to see if the
     * user really wants to amek the increments/decrements go by fast.
     */
    private class BigTimer extends Timer {

    /**
     * Sleep for the long amount of time. Then inform the listener
     * to have a bigIncrement/bigDecrement. After that, your job is
     * done, schedule the smaller (faster) timer from this point on.
     */
    protected void doTask() {
	try {
	sleep(BIG_SLEEP_TIME);
	informListener(true);
	smallTimer.request();
	} catch (InterruptedException e) {
	informListener(false);
	}
    }

    } // class BigTimer


    /**
     * The second stage of timers. This timer keeps rescheduling itself
     * everytime it wakes up. In between this, it sends a notification
     * to the listener to do a big Increment/Decrement.
     */
    private class SmallTimer extends Timer {

    protected void doTask() {
	try {
	// loop forever and keep rescheduling yourself
	while (true) {
	  sleep(SMALL_SLEEP_TIME);
	  informListener(true);
	    }
	} catch (InterruptedException e) {}
    } // doTask method

    } // class SmallTimer

    /**
     * A mouse listener to detect when a button has been
     * pressed/released. One instance of this is bound to the plus
     * button and the other instance to the minus button.
     */
    private class DCMouseListener extends MouseAdapter {
    private boolean plusOrMinus;

    /**
     * Constructor for DCMouseListener.
     * @param plusOrMinus true if this is a listener for the plus
     *	   button, false if it is for the minus button.
     */
    public DCMouseListener(boolean plusOrMinus) {
	this.plusOrMinus = plusOrMinus;
    }

    /**
     * Kicks in when the mouse is pressed.
     */
    public void mousePressed(MouseEvent e) {
	incrementFlag = plusOrMinus;
	DCPanel.this.startAction();
    }

    /**
     * Kicks in when the mouse is released.
     */
    public void mouseReleased(MouseEvent e) {
	incrementFlag = plusOrMinus;
	DCPanel.this.stopAction();
	}
    }

    /**
     * The button used by this DCPanel.
     */
    private class DCButton extends Button {
    public DCButton(String text) {
	super(text);
	if (text.equals("+"))
	   addMouseListener(new DCMouseListener(true));
	else
	addMouseListener(new DCMouseListener(false));
    }

    /**
     * Make the button non-focus traversable so that it cannot be
     * tabbed in to.
     */
    public boolean isFocusable() {
	return false;
    }

    } // DCButton


    /**
     * Test method for DCPanel class to see appearance.
     */
    public static void main(String args[]) {
    Frame f = new Frame("Testing DCPanel");
    f.add(new DCPanel());
    f.setBounds(new Rectangle(100, 100, 100, 100));
    f.setVisible(true);
    }

}
