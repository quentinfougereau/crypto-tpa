package com.company;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class Main {


    public static void main(String[] args) {
        cert("./email1.txt");
        check("./email1-auth.txt");
        tests();
    }

    /*
    Effectue le HMAC du corps de l'email passé en paramètre
    Ajoute le champs X-AUTH: ...  dans l'entête de l'email
    */
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

            byte[] secret = getResumeMD5("Alain Turin".getBytes());
            byte[] hmac = conformHmac(secret, body.toString());
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

    /*
    Effectue la vérification de l'intégrité de l'email passé en paramètre
    */
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

        byte[] secret = getResumeMD5("Alain Turin".getBytes());
        byte[] hmac = conformHmac(secret, body.toString());
        String stringHmac = hexToStringFormat(hmac);

        if (certResumeMD5.equals(stringHmac)) {
            System.out.println("Cet email est authentique");
        } else {
            System.out.println("[ALERTE] La signature de cet email ne correspond pas");
        }

    }

    /*
    Effectue le calcul du HMAC selon la RFC 2104 : H(K XOR opad || H(K XOR ipad || message))
        - Avec H la fonction de hachage MD5
    */
    public static byte[] conformHmac(byte[] value, String message) {
        byte[] secret = value;
        byte[] extendedKey = new byte[64];
        byte[] ipad = new byte[64];
        byte[] opad = new byte[64];

        for (int i = 0; i < 64; i++) {
            if (i < secret.length) {
                extendedKey[i] = secret[i];
            } else {
                extendedKey[i] = 0;
            }
            ipad[i] = 0x36; //0x36
            opad[i] = 0x5c; //0x5c
        }

        byte[] xorKeyIpad = xor(extendedKey, ipad);
        byte[] resumeMD5 = getResumeMD5(bytesConcat(xorKeyIpad, message.getBytes()));
        byte[] xorKeyOpad = xor(extendedKey, opad);
        return getResumeMD5(bytesConcat(xorKeyOpad, resumeMD5));
    }

    /*
    Calcule le résumé MD5 du tableau d'octets donné en paramètre
    */
    public static byte[] getResumeMD5(byte[] value) {
        byte[] resumeMD5 = null;
        try {
            MessageDigest hash = MessageDigest.getInstance("MD5");
            hash.update(value);
            resumeMD5 = hash.digest();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return resumeMD5;
    }

    /*
    Affiche un tableau d'octet sous forme hexadécimal
    */
    public static void printBytes(byte[] bytes) {
        for (byte b : bytes) {
            System.out.printf("%02x", b);
        }
        System.out.println();
    }

    /*
    Effectue l'opération xor entre deux tableaux d'octets de même taille
    */
    public static byte[] xor(byte[] op1, byte[] op2) {
        byte[] res = new byte[op1.length];
        if (op1.length == op2.length) {
            for (int i = 0; i < op1.length; i++) {
                res[i] = (byte) (op1[i] ^ op2[i]);
            }
        }
        return res;
    }

    /*
    Concatène deux tableaux d'octets
    */
    public static byte[] bytesConcat(byte[] first, byte[] second) {
        byte[] res = new byte[first.length + second.length];
        System.arraycopy(first, 0, res, 0, first.length);
        System.arraycopy(second, 0, res, first.length, second.length);
        return res;
    }

    /*
    Converti un tableau d'octets en chaine de caractères hexadécimaux
    Ex : f3c0 (byte) => "f3c0"
    */
    public static String hexToStringFormat(byte[] bytes) {
        StringBuilder stringBuilder = new StringBuilder();
        for (byte b : bytes) {
            stringBuilder.append(String.format("%02x", b));
        }
        return stringBuilder.toString();
    }

    /*
    Converti une chaine de caractères héxadécimaux en tableau d'octets
    Ex : "f3c0" => f3c0 (byte)
    */
    public static byte[] hexStringToByte(String s) {
        byte[] bytes = new byte[s.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            int index = i * 2;
            int j = Integer.parseInt(s.substring(index, index + 2), 16);
            bytes[i] = (byte) j;
        }
        return bytes;
    }

    /*
    Test la fonction conform HMAC.
    Affiche un résultat sous la forme suivante :
        - RESULTAT : 3b571940a6e7d6038c0a415dc0790e02 --- EXPECTED : 3b571940a6e7d6038c0a415dc0790e02
    */
    public static void testConformHmac(byte[] secret, String message, String expected) {
        byte[] byteExpected = hexStringToByte(expected);
        byte[] h = conformHmac(secret, message);

        System.out.println("RESULTAT : " + hexToStringFormat(h) + " --- EXPECTED : " + hexToStringFormat(byteExpected));
        if (Arrays.equals(h, byteExpected)) {
            System.out.println("Le calcul du HMAC est correct");
        } else {
            System.out.println("Erreur : Le calcul du HMAC est incorrect");
        }
    }

    public static void tests() {
        test_case_0();
        test_case_1();
        test_case_2();
    }

    /*
    test_case =     0
    key =           0xc5dcb78732e1f3966647655229729843
    key_len =       16
    data =          "Hi There"
    data_len =      8
    digest =        0x3b571940a6e7d6038c0a415dc0790e02
    */
    public static void test_case_0() {
        byte[] secret = getResumeMD5("Alain Turin".getBytes());
        testConformHmac(secret, "Hi There", "3b571940a6e7d6038c0a415dc0790e02");
    }

    /*
    test_case =     1
    key =           0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
    key_len =       16
    data =          "Hi There"
    data_len =      8
    digest =        0x9294727a3638bb1c13f48ef8158bfc9d
    */
    public static void test_case_1() {
        byte[] secret = hexStringToByte("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        testConformHmac(secret, "Hi There", "9294727a3638bb1c13f48ef8158bfc9d");
    }

    /*
    test_case =     2
    key =           "Jefe"
    key_len =       4
    data =          "what do ya want for nothing?"
    data_len =      28
    digest =        0x750c783e6ab0b503eaa86e310a5db738
    */
    public static void test_case_2() {
        testConformHmac("Jefe".getBytes(), "what do ya want for nothing?", "750c783e6ab0b503eaa86e310a5db738");
    }

}
