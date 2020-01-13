package com.company;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Scanner;

public class Reader {

    private String filename;
    private File file;
    private Scanner scanner;
    private FileInputStream fis;

    public Reader(String filename) {
        this.filename = filename;
        init();
    }

    private void init() {
        try {
            this.file = new File(this.filename);
            this.fis = new FileInputStream(file);
            this.scanner = new Scanner(fis);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }

    public String readLine() {
        if (scanner.hasNextLine()) {
            return scanner.nextLine();
        } else {
            return null;
        }
    }

    public void close() {
        try {
            this.fis.close();
            this.scanner.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
