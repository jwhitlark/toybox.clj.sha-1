 /*
 *
 * SHA1.java
 * The implementation of SHA-1 in Java
 * Copyright (C) 2005 Roy Abu Bakar
 *
 */

import java.util.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
// Added
import javax.xml.bind.DatatypeConverter;

@SuppressWarnings("serial")
public class SHA1 extends JFrame implements ActionListener {

    JFileChooser jfc = new JFileChooser("c:");
    File OpenFile = new File("");
    JButton jButtonHash = new JButton("Hash");
    JButton jButtonClear = new JButton("Clear");
    JButton jButtonBrowse = new JButton("Browse");
    JTextField jTextBrowse = new JTextField(70);
    JLabel jLabel1, jLabel2, jLabel3, jLabel4;
    JTextArea jTextMessage, jTextOutput;
    int j, temp;
    int A, B, C, D, E;
    int[] H = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    int F;

    public SHA1() {

        super("SHA-1");
        setSize(800, 600);
        Container cc = getContentPane();
        cc.setBackground(Color.black);

        jLabel1 = new JLabel("SHA-1", SwingConstants.CENTER);
        jLabel1.setForeground(Color.orange);
        jLabel1.setFont(new Font("Sans Serif", Font.PLAIN, 50));
        jLabel1.setBounds(100, 30, 600, 100);
        cc.add(jLabel1);

        jLabel2 = new JLabel("Message");
        jLabel2.setForeground(Color.white);
        jLabel2.setFont(new Font("Verdana", Font.PLAIN, 20));
        jLabel2.setBounds(30, 110, 600, 50);
        cc.add(jLabel2);

        jTextMessage = new JTextArea(10, 50);
        jTextMessage.setLineWrap(true);
        JScrollPane js = new JScrollPane(jTextMessage);
        js.setBounds(30, 160, 720, 150);
        cc.add(js);

        jLabel3 = new JLabel("Output");
        jLabel3.setForeground(Color.white);
        jLabel3.setFont(new Font("Verdana", Font.PLAIN, 20));
        jLabel3.setBounds(30, 320, 200, 30);
        cc.add(jLabel3);

        jTextOutput = new JTextArea(10, 50);
        jTextOutput.setBounds(30, 350, 720, 40);
        jTextOutput.setFont(new Font("Verdana", Font.PLAIN, 29));
        jTextOutput.setEditable(false);
        cc.add(jTextOutput);

        jButtonHash.setBounds(30, 400, 100, 30);
        cc.add(jButtonHash);

        jButtonClear.setBounds(30, 450, 100, 30);
        cc.add(jButtonClear);

        jButtonBrowse.setBounds(30, 500, 100, 30);
        cc.add(jButtonBrowse);

        jTextBrowse.setBounds(150, 500, 200, 30);
        jTextBrowse.setEditable(false);
        cc.add(jTextBrowse);

        jLabel4 = new JLabel("Copyright (c) Roy Abu Bakar 2005");
        jLabel4.setVerticalAlignment(JLabel.BOTTOM);
        jLabel4.setHorizontalAlignment(JLabel.CENTER);
        jLabel4.setForeground(Color.white);
        jLabel4.setFont(new Font("Verdana", Font.PLAIN, 12));
        jLabel4.setBounds(170, 500, 600, 100);
        cc.add(jLabel4);

        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        jButtonHash.addActionListener(this);
        jButtonClear.addActionListener(this);
        jButtonBrowse.addActionListener(this);

        setVisible(true);
    }

    public class Digest {

        String digestIt(byte[] dataIn) {
            byte[] paddedData = padTheMessage(dataIn);
            int[] H = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
            int[] K = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6};

            if (paddedData.length % 64 != 0) {
                System.out.println("Invalid padded data length.");
                System.exit(0);
            }

            int passesReq = paddedData.length / 64;
            byte[] work = new byte[64];

            for (int passCntr = 0; passCntr < passesReq; passCntr++) {
                System.arraycopy(paddedData, 64 * passCntr, work, 0, 64);
                processTheBlock(work, H, K);
            }

            return intArrayToHexStr(H);
        }
        //-------------------------------------------//

        public byte[] padTheMessage(byte[] data) {
            int origLength = data.length;
            int tailLength = origLength % 64;
            int padLength = 0;
            if ((64 - tailLength >= 9)) {
                padLength = 64 - tailLength;
            } else {
                padLength = 128 - tailLength;
            }

            byte[] thePad = new byte[padLength];
            thePad[0] = (byte) 0x80;
            long lengthInBits = origLength * 8;

            for (int cnt = 0; cnt < 8; cnt++) {
                thePad[thePad.length - 1 - cnt] = (byte) ((lengthInBits >> (8 * cnt)) & 0x00000000000000FF);
            }

            byte[] output = new byte[origLength + padLength];

            System.arraycopy(data, 0, output, 0, origLength);
            System.arraycopy(thePad, 0, output, origLength, thePad.length);

            // Added
            System.out.println(DatatypeConverter.printHexBinary(output));

            return output;

        }
        //-------------------------------------------//

        public void processTheBlock(byte[] work, int H[], int K[]) {

            int[] W = new int[80];
            for (int outer = 0; outer < 16; outer++) {
                int temp = 0;
                for (int inner = 0; inner < 4; inner++) {
                    temp = (work[outer * 4 + inner] & 0x000000FF) << (24 - inner * 8);
                    W[outer] = W[outer] | temp;
                }
            }

            for (int j = 16; j < 80; j++) {
                W[j] = rotateLeft(W[j - 3] ^ W[j - 8] ^ W[j - 14] ^ W[j - 16], 1);
            }

            A = H[0];
            B = H[1];
            C = H[2];
            D = H[3];
            E = H[4];

            for (int j = 0; j < 20; j++) {
                F = (B & C) | ((~B) & D);
                //	K = 0x5A827999;
                temp = rotateLeft(A, 5) + F + E + K[0] + W[j];
                System.out.println(Integer.toHexString(K[0]));
                E = D;
                D = C;
                C = rotateLeft(B, 30);
                B = A;
                A = temp;
            }

            for (int j = 20; j < 40; j++) {
                F = B ^ C ^ D;
                //   K = 0x6ED9EBA1;
                temp = rotateLeft(A, 5) + F + E + K[1] + W[j];
                System.out.println(Integer.toHexString(K[1]));
                E = D;
                D = C;
                C = rotateLeft(B, 30);
                B = A;
                A = temp;
            }

            for (int j = 40; j < 60; j++) {
                F = (B & C) | (B & D) | (C & D);
                //   K = 0x8F1BBCDC;
                temp = rotateLeft(A, 5) + F + E + K[2] + W[j];
                E = D;
                D = C;
                C = rotateLeft(B, 30);
                B = A;
                A = temp;
            }

            for (int j = 60; j < 80; j++) {
                F = B ^ C ^ D;
                //   K = 0xCA62C1D6;
                temp = rotateLeft(A, 5) + F + E + K[3] + W[j];
                E = D;
                D = C;
                C = rotateLeft(B, 30);
                B = A;
                A = temp;
            }

            H[0] += A;
            H[1] += B;
            H[2] += C;
            H[3] += D;
            H[4] += E;

            int n;
            for (n = 0; n < 16; n++) {
                System.out.println("W[" + n + "] = " + toHexString(W[n]));
            }

            System.out.println("H0:" + Integer.toHexString(H[0]));
            System.out.println("H0:" + Integer.toHexString(H[1]));
            System.out.println("H0:" + Integer.toHexString(H[2]));
            System.out.println("H0:" + Integer.toHexString(H[3]));
            System.out.println("H0:" + Integer.toHexString(H[4]));
        }

        final int rotateLeft(int value, int bits) {
            int q = (value << bits) | (value >>> (32 - bits));
            return q;
        }
    }

    public String intArrayToHexStr(int[] data) {
        String output = "";
        String tempStr = "";
        int tempInt = 0;
        for (int cnt = 0; cnt < data.length; cnt++) {

            tempInt = data[cnt];

            tempStr = Integer.toHexString(tempInt);

            if (tempStr.length() == 1) {
                tempStr = "0000000" + tempStr;
            } else if (tempStr.length() == 2) {
                tempStr = "000000" + tempStr;
            } else if (tempStr.length() == 3) {
                tempStr = "00000" + tempStr;
            } else if (tempStr.length() == 4) {
                tempStr = "0000" + tempStr;
            } else if (tempStr.length() == 5) {
                tempStr = "000" + tempStr;
            } else if (tempStr.length() == 6) {
                tempStr = "00" + tempStr;
            } else if (tempStr.length() == 7) {
                tempStr = "0" + tempStr;
            }
            output = output + tempStr;
        }//end for loop
        return output;
    }//end intArrayToHexStr
    //-------------------------------------------//

    static final String toHexString(final ByteBuffer bb) {
        final StringBuffer sb = new StringBuffer();
        for (int i = 0; i < bb.limit(); i += 4) {
            if (i % 4 == 0) {
                sb.append('\n');
            }
            sb.append(toHexString(bb.getInt(i))).append(' ');
        }
        sb.append('\n');
        return sb.toString();
    }

    static final String toHexString(int x) {
        return padStr(Integer.toHexString(x));
    }
    static final String ZEROS = "00000000";

    static final String padStr(String s) {
        if (s.length() > 8) {
            return s.substring(s.length() - 8);
        }
        return ZEROS.substring(s.length()) + s;
    }

    public void actionPerformed(ActionEvent e) {
        Digest digester = new Digest();
        if (e.getSource() == jButtonHash) {
            try {
                String z = jTextMessage.getText();
                System.out.println("Message: " + z);
                jTextBrowse.setText("");
                byte[] dataBuffer = (z).getBytes();
                String thedigest = digester.digestIt(dataBuffer);
                jTextOutput.setText(thedigest);
                System.out.println("Output: " + thedigest);
            } catch (Exception ex) {
            }
        }

        if (e.getSource() == jButtonBrowse) {
            try {
                int dlg = jfc.showOpenDialog(null);
                if (dlg == 0) {
                    File f = jfc.getSelectedFile();
                    OpenFile = f;
                    String path = f.getPath();
                    jTextBrowse.setText(path);
                    System.out.println("Browse: " + path);
                    jTextMessage.setText("");
                    FileReader berkasMasukan = new FileReader(OpenFile);
                    BufferedReader streamMasukan = new BufferedReader(berkasMasukan);

                    while (true) {
                        String barisData = streamMasukan.readLine();
                        if (barisData == null) {
                            break;
                        }
                        jTextMessage.setText(barisData);
                        System.out.println(barisData);
                    }
                    berkasMasukan.close();
                    jTextOutput.setText("");
                }

            } catch (Exception fnfe) {
            }
        }

        if (e.getSource() == jButtonClear) {
            try {
                jTextMessage.setText("");
                jTextOutput.setText("");
                jTextBrowse.setText("");
                System.out.println("Clear!");
            } catch (Exception fnfe) {
            }
        }
    }

    public static void main(String[] args) {
        SHA1 NgL = new SHA1();
    }
}
