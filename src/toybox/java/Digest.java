import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
// Added
import javax.xml.bind.DatatypeConverter;


public class Digest {
    int j, temp;
    int A, B, C, D, E;
    int[] H = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    int F;


    public int[] digestIt(byte[] dataIn) {
        byte[] paddedData = padTheMessage(dataIn);
        int[] H = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
        int[] K = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6};

        System.out.println("K:" + K[0] + ", " + K[1] + ", " + K[2] + ", " + K[3] + ", ");

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

        return H;
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
        // System.out.println(DatatypeConverter.printHexBinary(output));

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
            // System.out.println("W[" + j + "] =" +W[j]);
            temp = rotateLeft(A, 5) + F + E + K[0] + W[j];
            E = D;
            D = C;
            C = rotateLeft(B, 30);
            B = A;
            A = temp;
            System.out.println("i: " + j + ", w: " + W[j] + ", a: " + A + ", b: " + B + ", c: " + C + ", d: " + D + ", e: " +  E + ", f: " +  F + ", K: " +  K[0]);
        }

        for (int j = 20; j < 40; j++) {
            F = B ^ C ^ D;
            //   K = 0x6ED9EBA1;
            temp = rotateLeft(A, 5) + F + E + K[1] + W[j];
            E = D;
            D = C;
            C = rotateLeft(B, 30);
            B = A;
            A = temp;
            System.out.println("i: " + j + ", w: " + W[j] + ", a: " + A + ", b: " + B + ", c: " + C + ", d: " + D + ", e: " +  E + ", f: " +  F + ", K: " +  K[1]);
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
            System.out.println("i: " + j + ", w: " + W[j] + ", a: " + A + ", b: " + B + ", c: " + C + ", d: " + D + ", e: " +  E + ", f: " +  F + ", K: " +  K[2]);
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
            System.out.println("i: " + j + ", w: " + W[j] + ", a: " + A + ", b: " + B + ", c: " + C + ", d: " + D + ", e: " +  E + ", f: " +  F + ", K: " +  K[3]);
        }

        H[0] += A;
        H[1] += B;
        H[2] += C;
        H[3] += D;
        H[4] += E;

        int n;
        for (n = 0; n < 16; n++) {
            System.out.println("W[" + n + "] = " + W[n]);
        }

        System.out.println("H0:" + H[0]);
        System.out.println("H1:" + H[1]);
        System.out.println("H2:" + H[2]);
        System.out.println("H3:" + H[3]);
        System.out.println("H4:" + H[4]);
    }

    public int rotateLeft(int value, int bits) {
        int q = (value << bits) | (value >>> (32 - bits));
        return q;
    }
}
