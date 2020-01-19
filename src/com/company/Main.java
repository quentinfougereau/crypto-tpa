package com.company;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Main {


    public static void main(String[] args) {
        cert("./email1.txt");
        check("./email1-auth.txt");
        //testHmac("Jefe", "what do ya want for nothing?");
    }

    public static void cert(String filename) {
        try {
            Reader reader = new Reader(filename);
            String line;

            boolean isHeader = true;
            StringBuilder header = new StringBuilder();
            StringBuilder body = new StringBuilder();

            while ((line = reader.readLine()) != null) {
                if (line.equals("")) {
                    isHeader = false;
                    continue;
                }
                if (isHeader) {
                    header.append(line).append("\r\n");
                }
                if (!isHeader) {
                    body.append(line).append("\r\n");
                }
            }
            reader.close();

            /*
            String bodyWithSecret = body + "c5dcb78732e1f3966647655229729843";
            MessageDigest hash = MessageDigest.getInstance("MD5");
            hash.update(bodyWithSecret.getBytes());
            byte[] resumeMD5 = hash.digest();
            System.out.print("Le résumé MD5 du fichier \"" + filename + "\" vaut: 0x");
            StringBuilder stringBuffer = new StringBuilder();
            for (byte k : resumeMD5) {
                System.out.printf("%02x", k);
                stringBuffer.append(String.format("%02x", k));
            }
            */
            byte[] hmac = conformHmac("Alain Turin".getBytes(), body.toString());
            String stringHmac = hexToStringFormat(hmac);

            header.append("X-AUTH: ").append(stringHmac).append("\r\n");
            header.append("\r\n");

            FileWriter writer = new FileWriter("./email1-auth.txt");
            writer.write(header.toString());
            writer.write(body.toString());
            writer.flush();
            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    public static void check(String filename) {
        Reader reader = new Reader(filename);
        String certResumeMD5 = "";
        String line;
        boolean isBody = false;
        StringBuilder body = new StringBuilder();
        while ((line = reader.readLine()) != null) {
            if (line.contains("X-AUTH")) {
                certResumeMD5 = line.substring(line.indexOf(":") + 2);
            }
            if (line.equals("")) {
                isBody = true;
                continue;
            }
            if (isBody) {
                body.append(line).append("\r\n");
            }
        }
        reader.close();

        byte[] hmac = conformHmac("Alain Turin".getBytes(), body.toString());
        String stringHmac = hexToStringFormat(hmac);

        if (certResumeMD5.equals(stringHmac)) {
            System.out.println("Cet email est authentique");
        } else {
            System.out.println("[ALERTE] La signature de cet email ne correspond pas");
        }

    }

    public static byte[] conformHmac(byte[] value, String message) {
        byte[] secret = getResumeMD5(value);
        byte[] extension = new byte[secret.length + 48];
        byte[] ipad = new byte[secret.length + 48];
        byte[] opad = new byte[secret.length + 48];

        for (int i = 0; i < secret.length + 48; i++) {
            if (i < secret.length) {
                extension[i] = secret[i];
            } else {
                extension[i] = 0;
            }
            ipad[i] = 0x36; //0x36
            opad[i] = 0x5c; //0x5c
        }

        byte[] calculation1 = xor(extension, ipad);
        byte[] calculation15 = bytesConcat(calculation1, message.getBytes());
        byte[] calculation2 = getResumeMD5(calculation15);
        byte[] calculation3 = xor(extension, opad);
        byte[] calculation4 = bytesConcat(calculation3, calculation2);
        return getResumeMD5(calculation4);
    }

    public static byte[] getResumeMD5(byte[] value) {
        byte[] resumeMD5 = null;
        try {
            System.out.println("Sans MD5 : ");
            printBytes(value);
            System.out.println("Longueur de value = " + value.length);
            MessageDigest hash = MessageDigest.getInstance("MD5");
            hash.update(value);
            resumeMD5 = hash.digest();
            System.out.println("Avec MD5 = ");
            printBytes(resumeMD5);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return resumeMD5;
    }

    public static void printBytes(byte[] bytes) {
        for (byte b : bytes) {
            System.out.printf("%02x", b);
        }
        System.out.println();
    }

    public static byte[] xor(byte[] op1, byte[] op2) {
        byte[] res = new byte[op1.length];
        if (op1.length == op2.length) {
            for (int i = 0; i < op1.length; i++) {
                res[i] = (byte) (op1[i] ^ op2[i]);
            }
        }
        return res;
    }

    public static byte[] bytesConcat(byte[] first, byte[] second) {
        byte[] res = new byte[first.length + second.length];
        System.arraycopy(first, 0, res, 0, first.length);
        System.arraycopy(second, 0, res, first.length, second.length);
        return res;
    }

    public static String hexToStringFormat(byte[] bytes) {
        StringBuilder stringBuilder = new StringBuilder();
        for (byte b : bytes) {
            stringBuilder.append(String.format("%02x", b));
        }
        return stringBuilder.toString();
    }

    public static byte[] hexStringToByte(String s) {
        byte[] bytes = new byte[s.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            int index = i * 2;
            int j = Integer.parseInt(s.substring(index, index + 2), 16);
            bytes[i] = (byte) j;
        }
        return bytes;
    }

    public static void testHmac(String secret, String message) {
        //byte[] byteSecret = hexStringToByte(secret);
        byte[] byteSecret = secret.getBytes();
        byte[] h = conformHmac(byteSecret, message);
        printBytes(h);
    }

}
