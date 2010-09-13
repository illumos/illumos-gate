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
import java.awt.event.*;
import java.io.*;
import java.util.ResourceBundle;
import java.util.MissingResourceException;

public class PrintUtil {

    // For I18N
    private static ResourceBundle rb =
    ResourceBundle.getBundle("GuiResource" /* NOI18N */); 
    private static ResourceBundle hrb =
    ResourceBundle.getBundle("HelpData" /* NOI18N */); 
    /**
     * Prints an object to either file or printer. Uses the toString()
     * method of the object to obtain a string representation for it.
     * @param obj the Object that is to be printed
     */
    public static void dump(Frame parent, Object obj) {

        boolean usePrinter;
        String stringRep = obj.toString();

        Frame printFrame = new PrintFrame(parent, stringRep);
        printFrame.setVisible(true);
    }

    /**
     * Call rb.getString(), but catch exception and return English
     * key so that small spelling errors don't cripple the GUI
     *
     */
    private static final String getString(String key) {
        return (getString(rb, key));
    }

    private static final String getString(ResourceBundle rb, String key) {
        try {
    	    String res = rb.getString(key);
	    return res;
        } catch (MissingResourceException e) {
	    System.out.println("Missing resource "+key+", using English.");
	    return key;
        }
    }

    /**
     * Forgets the command and filename that was last entered.
     */
    public static final void reinitialize() {
        PrintFrame.command = PrintFrame.fileName = null;
    }

    /*
     ************************************************************
     *   I N N E R    C L A S S E S   F O L L O W
     ************************************************************
     */
  
    /**
     * This class will show a Frame to determine whether the user wants
     * to print to  a file and which file, if so, or to the printer
     * directly. Finally it will print to the appropriate destinaition.
     */
    private static class PrintFrame extends Frame {
    
        private String text;

        static TextField command = null;
        static TextField fileName = null;

        private CheckboxGroup options;
        private Checkbox printer;
        private Checkbox file;

        private Frame parent;

        private static String defaultFileName = 
            "/tmp/.SEAM_temp.txt" /* NO18N */;

        /**
         * Constructor for PrintFrame.
         */
        public PrintFrame(Frame parent, String text) {
            super(rb.getString("SEAM Print Helper"));
            this.text = text;
            this.parent = parent;
            setLayout(new GridBagLayout());

            addLabelsAndFields();
            addCheckboxGroup();
            addButtons();

            setBackground(parent.getBackground());
            setForeground(parent.getForeground());
            setSize(340, 160);
            setResizable(false);

            printer.setState(true);
            command.setEditable(true);
            fileName.setEditable(false);
        }

        private void addLabelsAndFields() {
            GridBagConstraints gbc = new GridBagConstraints();
            gbc.weightx = gbc.weighty = 1;
            gbc.gridwidth = 2;
            gbc.fill = GridBagConstraints.HORIZONTAL;

            gbc.gridx = 1;
            gbc.gridy = 0;
            add(new Label(getString("Print Command")), gbc);
            if (command == null) 
	        command = new TextField("lp" /* NO18N */, 10);
            gbc.gridx = 3;
            add(command, gbc);

            gbc.gridx = 1;
            gbc.gridy = 1;
            add(new Label(getString("File Name")), gbc);
            if (fileName == null) 
	        fileName = new TextField("" /* NO18N */, 10);
            gbc.gridx = 3;
            add(fileName, gbc);

            ActionListener al = new StartPrintingListener();
            command.addActionListener(al);
            fileName.addActionListener(al);
        }

        private void addCheckboxGroup() {

            GridBagConstraints gbc = new GridBagConstraints();
            gbc.weightx = gbc.weighty = 1;

            options = new CheckboxGroup();
              printer = new Checkbox();
            file = new Checkbox();
            printer.setCheckboxGroup(options);
            file.setCheckboxGroup(options);
            options.setSelectedCheckbox(printer);

            printer.addItemListener(new PrintSelectedListener());
            file.addItemListener(new FileSelectedListener());

            gbc.gridx = 0;

            gbc.gridy = 0;
            add(printer, gbc);
            gbc.gridy = 1;
            add(file, gbc);
        }

        private void addButtons() {

            Button fileMore = new Button("..." /* NO18N */);
            Button print = new Button(getString("Print"));
            Button cancel = new Button(getString("Cancel"));
            Button help = new Button(getString("Help"));

            GridBagConstraints gbc = new GridBagConstraints();
            gbc.weightx = gbc.weighty = 1;

            gbc.gridx = 5;
            gbc.gridy = 1;
            add(fileMore, gbc);


            gbc.gridx = 0;
      //      gbc.gridy = 2;
            gbc.gridwidth = GridBagConstraints.REMAINDER;
            gbc.fill = GridBagConstraints.BOTH;
      //      gbc.insets = new Insets(0, 10, 0, 10);
      //      gbc.weighty = .1;
      //   add(new LineSeparator(), gbc);
      //      gbc.weighty = 1;

            Panel p = new Panel();
            gbc.insets = new Insets(0, 10, 0, 10);
            gbc.gridy = 2;
            add(p, gbc);

            p.setLayout(new GridBagLayout());
            gbc = new GridBagConstraints();
            gbc.fill = GridBagConstraints.HORIZONTAL;
            gbc.weightx = gbc.weighty = 1;

            p.add(print, gbc);
            p.add(cancel, gbc);
            p.add(help, gbc);

            print.addActionListener(new StartPrintingListener());
            cancel.addActionListener(new CancelButtonListener());
            help.addActionListener(new HelpButtonListener());
            fileMore.addActionListener(new FileMoreButtonListener());
            addWindowListener(new WindowCloseListener());

        }

        /**
         * Called when the print frame has to be closed. IT may be closed
         * as a result of the user choosing any one of "print", "cancel" or
         * just the window close (which also cancels the printing). 
         * @param doIt true if the printing should be carried out, false
         * if it is to be cancelled.
         */
        private void close(boolean doIt) {
            if (doIt) {

	        Checkbox cb = options.getSelectedCheckbox();
	        String dest = null;

	        try {
	            if (cb == printer) {
	                dest = command.getText().trim();
	                if (dest.length() == 0)
	                    return;
	                else
	                    print(dest);
	            } else {
	                dest = fileName.getText().trim();
	                if (dest.length() == 0)
	                    return;
	                else
	                    saveToFile(dest);
	            }
	        } catch (IOException e) {
	            // System.out.println(e); XXX
	        }
            } // end of doIt
      
            dispose();
        }// end of close

        /**
         * Prints the string to a file and then send the file's contents
         * to the printer. It then deletes the file.
         * @param command the print comman to be used
         */
        private void print(String command) throws IOException {
            Thread printThread = new PrintThread(command);
            printThread.start();
            saveToFile(defaultFileName);
        }
    
        /**
         * Saves the string onto the file.
         * @param fileName the file to which the string must be written
         */    
        private void saveToFile(String fileName) throws IOException {
            PrintWriter outFile = null;
            outFile = new PrintWriter(new BufferedWriter(new 
                      FileWriter(fileName)));
            outFile.print(text);
            outFile.flush();
            outFile.close();
        }
    
        // Listeners for the gui components:
        // javac in current makefile will not compile if these are anonymous.

        private class PrintSelectedListener implements ItemListener {
            public void itemStateChanged(ItemEvent e) {
	        command.setEditable(true);
	        fileName.setEditable(false);
            }
        }

        private class FileSelectedListener implements ItemListener {
            public void itemStateChanged(ItemEvent e) {
	        command.setEditable(false);
	        fileName.setEditable(true);
            }
        }
    
        private class StartPrintingListener implements ActionListener {
            public void actionPerformed(ActionEvent e) {
	        close(true);
            }
        }
    
        private  class CancelButtonListener implements ActionListener {
            public void actionPerformed(ActionEvent e) {
	        close(false);
            }
        }
    
        private  class HelpButtonListener implements ActionListener {
            public void actionPerformed(ActionEvent e) {
	        HelpDialog hd = new HelpDialog(PrintFrame.this,
		getString("Help for Date/Time Helper"), false); 
	        hd.setVisible(true);
	        hd.setText(getString(hrb, "PrintUtilHelp"));
            }
        }
    
        private  class FileMoreButtonListener implements
        ActionListener {
      
            public void actionPerformed(ActionEvent e) {
	
	        // Turn off print "command" and enable output "file name"
	        options.setSelectedCheckbox(file);
	        command.setEditable(false);
	        fileName.setEditable(true);
	
	        FileDialog fd = new FileDialog(PrintFrame.this, 
				       getString("SEAM File Helper"),
				       FileDialog.SAVE);
	        fd.setDirectory(System.getProperty("user.dir" /* NO18N */));

	        // Use what's in the fileName field already to initialize the
	        // FileDialog
	        String fileNameText = fileName.getText();
	        if (fileNameText != null) {
	            File file = new File(fileNameText);
	            if (file.isDirectory())
	                fd.setDirectory(fileNameText);
	            else {
	                fd.setFile(fileNameText);
	                String parent = file.getParent();
	                if (parent != null)
	                    fd.setDirectory(parent);
	            }
	        }

	        fd.setVisible(true);
	        if (fd.getFile() != null && fd.getFile().length() > 0)
	            fileName.setText(fd.getDirectory() + fd.getFile());
            }
        }
    
        /**
         * This class prints out to a temporary file defaultFileName, send
         * that to the printer, and then deletes the file after TIME_OUT
         * milliseconds.
         */
        private class PrintThread extends Thread {
            private String command;
            private long TIME_OUT = 30000; // milliseconds

            public PrintThread(String command) {
	        this.command = command;
            }

            public void run() {
	        try {
	            Process printProcess = Runtime.getRuntime()
	            .exec(command + " " /* NO18N */ + defaultFileName);
	            try {
	                sleep(TIME_OUT);
	            } catch (InterruptedException e) {}
	            printProcess.destroy();
	            File tempFile = new File(PrintFrame.this.defaultFileName);
	            tempFile.delete();
	        } catch (IOException e) {
	            // System.err.println(e); XXX
	        }
            }
        }
    
        private  class WindowCloseListener extends  WindowAdapter {
            public void windowClosing(WindowEvent e) {
	        close(false);
            }
        }   
    }  // class PrintFrame
}
