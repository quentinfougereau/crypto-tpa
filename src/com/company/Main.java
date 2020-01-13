package com.company;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) {
        cert("./email1.txt");
        check("./email1-auth.txt");
    }

    public static void cert(String filename) {
        try {
            File file = new File(filename);
            FileInputStream fis = new FileInputStream(file);
            Scanner scanner = new Scanner(fis);
            String line;
            boolean isHeader = true;
            boolean isBody = false;
            String header = "";
            String body = "";
            MessageDigest hash = MessageDigest.getInstance("MD5");
            while (scanner.hasNextLine()) {
                 line = scanner.nextLine();
                 if (line.equals("")) {
                     isHeader = false;
                     isBody = true;
                     continue;
                 }
                if (isHeader) {
                    header += line + "\r\n";
                }
                 if (isBody) {
                     body += line + "\r\n";
                 }
            }
            fis.close();
            scanner.close();

            System.out.println(header);
            System.out.println(body);
            String bodyWithSecret = body + "c5dcb78732e1f3966647655229729843";

            hash.update(bodyWithSecret.getBytes());
            byte[] resumeMD5 = hash.digest();
            System.out.print("Le résumé MD5 du fichier \"" + filename + "\" vaut: 0x");
            StringBuffer stringBuffer = new StringBuffer();
            for(byte k: resumeMD5) {
                System.out.printf("%02x", k);
                stringBuffer.append(String.format("%02x", k));
            }

            header += "X-AUTH: " + stringBuffer + "\r\n";
            header += "\r\n";

            FileWriter writer = new FileWriter("./email1-auth.txt");
            writer.write(header);
            writer.write(body);
            writer.flush();
            writer.close();
        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }

    }

    public static void check(String filename) {
        try {
            File file = new File(filename);
            FileInputStream fis = new FileInputStream(file);
            Scanner scanner = new Scanner(fis);
            String line;
            String certResumeMD5 = "";
            boolean isBody = false;
            String body = "";
            while (scanner.hasNextLine()) {
                line = scanner.nextLine();
                if (line.contains("X-AUTH")) {
                    certResumeMD5 = line.substring(line.indexOf(":") + 2);
                }
                if (line.equals("")) {
                    isBody = true;
                    continue;
                }
                if (isBody) {
                    body += line + "\r\n";
                }
            }

            System.out.println(certResumeMD5);
            System.out.println(body);

            String bodyWithSecret = body + "c5dcb78732e1f3966647655229729843";
            MessageDigest hash = MessageDigest.getInstance("MD5");
            hash.update(bodyWithSecret.getBytes());
            byte[] resumeMD5 = hash.digest();

            StringBuffer stringBuffer = new StringBuffer();
            for(byte k: resumeMD5) {
                stringBuffer.append(String.format("%02x", k));
            }

            if (certResumeMD5.contentEquals(stringBuffer)) {
                System.out.println("Cet email est authentique");
            } else {
                System.out.println("[ALERTE] La signature de cet email ne correspond pas");
            }

        } catch (FileNotFoundException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

    }

}
