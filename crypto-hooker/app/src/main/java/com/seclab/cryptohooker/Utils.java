package com.seclab.cryptohooker;

import android.util.Base64;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.NoSuchElementException;
import java.util.Scanner;

import de.robv.android.xposed.XposedBridge;

public class Utils {
    private static String folderName = "CryptoHooker";
    private static String TAG_DATA = "[CRYPTOHOOKER-DATA]";
    private static String packageFile = "/data/cryptohooker/packagename.txt";
    private static String logFile = "/data/cryptohooker/log.txt";
    private static String randomNumFile = "/data/cryptohooker/random-num.txt";
    private static String randomNumFilesBase = "/data/cryptohooker/random-num";

    private static String recordTimestampsFile = "/mnt/obb/cryptohooker-ts/record-timestamps";
    private static String tsFilesBaseInitial = "/mnt/obb/cryptohooker-ts/initial-ts-";
    private static String tsFilesBase = "/mnt/obb/cryptohooker-ts/ts-";
    private static String indexFilesBase = "/mnt/obb/cryptohooker-ts/index-";

    public static int availableBlocks = 1244443;
    public static int availableBytes = 1244443 * 4096;
    public static int blockCount = 8192;
    public static int blockSize = 4096;
    public static int freeBlocks = 1024;
    public static int freeBytes= 512 * 4096;
    public static int totalBytes = 8192 * 4096;

    public static int availMem = 381681664;

    public static double nextNumber(String code){
        String fname = randomNumFilesBase + code;
        double result = 0.5;

        File f = new File(fname);

        if (!f.exists()) {
            try {
                copy(new File(randomNumFile), f);
            } catch (IOException ioe) {
                return result;
            }
        }

        ArrayList<String> coll = new ArrayList<>();

        try {
            Scanner fileScanner = new Scanner(f);
            String first = fileScanner.nextLine();
            result = Double.parseDouble(first);

            while(fileScanner.hasNextLine()) {
                String next = fileScanner.nextLine();
                coll.add(next);
            }

            fileScanner.close();

            FileWriter fileStream = new FileWriter(fname);
            BufferedWriter out = new BufferedWriter(fileStream);

            for (String line : coll) {
                out.write(line + '\n');
            }

            out.write(first);

            out.close();

        } catch (IOException ex) {
            return result;
        } catch (NoSuchElementException nex){
            return result;
        }

        return result;
    }

    public static void copy(File src, File dst) throws IOException {
        InputStream in = new FileInputStream(src);
        OutputStream out = new FileOutputStream(dst);

        // Transfer bytes from in to out
        byte[] buf = new byte[1024];
        int len;
        while ((len = in.read(buf)) > 0) {
            out.write(buf, 0, len);
        }
        in.close();
        out.close();
    }

    public static void logData(String tag, String data){
        BufferedWriter bw = null;

        try {
            bw = new BufferedWriter(new FileWriter(logFile, true));
            bw.newLine();
            bw.write(tag + data);
            bw.flush();
        } catch (IOException ioe) {
            ioe.printStackTrace();
        } finally {
            if (bw != null) try {
                bw.close();
            } catch (IOException ioe2) {
                // just ignore it
            }
        }
    }

    public static long getIndex(String fname){
        File f = new File(indexFilesBase + fname);
        long index = -1;

        try {
            Scanner fileScanner = new Scanner(f);
            String first = fileScanner.nextLine();
            index = Long.parseLong(first);
            fileScanner.close();
        } catch (IOException ioe) {
            XposedBridge.log("getIndex io ex");
            ioe.printStackTrace();
        } catch (NoSuchElementException nex){
            nex.printStackTrace();
        }

        return index;
    }

    public static void incIndex(String fname){
        File f = new File(indexFilesBase + fname);
        long index = 0;
        long new_index = index;

        try {
            Scanner fileScanner = new Scanner(f);
            String first = fileScanner.nextLine();
            index = Long.parseLong(first);
            fileScanner.close();

            FileWriter fileStream = new FileWriter(indexFilesBase + fname);
            BufferedWriter out = new BufferedWriter(fileStream);

            new_index = index + 1;
            out.write(Long.toString(new_index) + "\n");
            out.close();

        } catch (IOException ioe) {
            ioe.printStackTrace();
        } catch (NoSuchElementException nex){
            nex.printStackTrace();
        }
    }

    public static void recordTS(String fname, long ts){
        BufferedWriter bw = null;

        try {
            bw = new BufferedWriter(new FileWriter(tsFilesBase + fname, true));
            bw.write(Long.toString(ts));
            bw.newLine();
            bw.flush();
        } catch (IOException ioe) {
            ioe.printStackTrace();
        } finally {
            if (bw != null) try {
                bw.close();
            } catch (IOException ioe2) {
                // just ignore it
            }
        }
    }

    public static long nextTS(String fname){
        long result = -1;
        long index = getIndex(fname);
        File f = new File(tsFilesBase + fname);
        long i = 0;

        try {
            Scanner fileScanner = new Scanner(f);

            while(fileScanner.hasNextLine()) {
                if (i == index){
                    result = Long.parseLong(fileScanner.nextLine());
                    break;
                }
                fileScanner.nextLine();
                i = i + 1;
            }

            fileScanner.close();
            incIndex(fname);
        } catch (IOException ex) {
            XposedBridge.log("nextTS io ex");
            return result;
        }

        return result;
    }

    public static String getAPKPackage(){
        BufferedReader br;
        try {
            br = new BufferedReader(new FileReader(packageFile));
            String line = br.readLine();
            br.close();

            if (line != null)
                return line;
            else
                return "thisisnotarealpackage";
        } catch (IOException e) {
            return "thisisnotarealpackage";
        }
    }

    public  static boolean recordTimestamps(){
        File f = new File(recordTimestampsFile);
        return f.exists();
    }

    public static void logCipherInit(Object cipher, int opmode){
        JSONObject js = new JSONObject();
        try {
            js.put("Cipher", cipher.hashCode());
            js.put("opmode", opmode);
        } catch (JSONException e) {
            e.printStackTrace();
        }

        logData(TAG_DATA, "[CIPHER_INIT]" + js);
    }

    public static void logCipherEntry(Object cipher, byte [] in, byte [] out){
        JSONObject js = new JSONObject();
        try {
            js.put("Cipher", cipher.hashCode());
            js.put("in", Base64.encodeToString(in, Base64.DEFAULT));
            js.put("out", Base64.encodeToString(out, Base64.DEFAULT));
        } catch (JSONException e) {
            e.printStackTrace();
        }

        logData(TAG_DATA, "[CIPHER_ENTRY]" + js);
    }

    public static void logCipherFinal(Object cipher, byte [] in, byte [] out){
        JSONObject js = new JSONObject();
        try {
            js.put("Cipher", cipher.hashCode());
            js.put("in", Base64.encodeToString(in, Base64.DEFAULT));
            js.put("out", Base64.encodeToString(out, Base64.DEFAULT));
        } catch (JSONException e) {
            e.printStackTrace();
        }

        logData(TAG_DATA, "[CIPHER_FINAL]" + js);
    }

    public static void logHashInit(Object messageDigest){
        JSONObject js = new JSONObject();
        try {
            js.put("Digest", messageDigest.hashCode());
        } catch (JSONException e) {
            e.printStackTrace();
        }

        logData(TAG_DATA, "[HASH_INIT]" + js);
    }

    public static void logHashEntry(Object messageDigest, byte [] in, byte [] out){
        JSONObject js = new JSONObject();
        try {
            js.put("Digest", messageDigest.hashCode());
            js.put("in", Base64.encodeToString(in, Base64.DEFAULT));
            js.put("out", Base64.encodeToString(out, Base64.DEFAULT));
        } catch (JSONException e) {
            e.printStackTrace();
        }

        logData(TAG_DATA, "[HASH_ENTRY]" + js);
    }

    public static void logHashFinal(Object messageDigest, byte [] in, byte [] out){
        JSONObject js = new JSONObject();
        try {
            js.put("Digest", messageDigest.hashCode());
            js.put("in", Base64.encodeToString(in, Base64.DEFAULT));
            js.put("out", Base64.encodeToString(out, Base64.DEFAULT));
        } catch (JSONException e) {
            e.printStackTrace();
        }

        logData(TAG_DATA, "[HASH_FINAL]" + js);
    }

    public static void logHashReset(Object messageDigest){
        JSONObject js = new JSONObject();
        try {
            js.put("Digest", messageDigest.hashCode());
        } catch (JSONException e) {
            e.printStackTrace();
        }

        logData(TAG_DATA, "[HASH_RESET]" + js);
    }

    public static void logHashClone(Object messageDigest, Object clonedDigest){
        JSONObject js = new JSONObject();
        try {
            js.put("Digest", messageDigest.hashCode());
            js.put("Cloned", clonedDigest.hashCode());
        } catch (JSONException e) {
            e.printStackTrace();
        }

        logData(TAG_DATA, "[HASH_CLONE]" + js);
    }

    public static void  logMACInit(Object mac){
        JSONObject js = new JSONObject();
        try {
            js.put("Mac", mac.hashCode());
        } catch (JSONException e) {
            e.printStackTrace();
        }

        logData(TAG_DATA, "[MAC_INIT]" + js);
    }

    public static void logMACEntry(Object mac, byte [] in, byte [] out){
        JSONObject js = new JSONObject();
        try {
            js.put("Mac", mac.hashCode());
            js.put("in", Base64.encodeToString(in, Base64.DEFAULT));
            js.put("out", Base64.encodeToString(out, Base64.DEFAULT));
        } catch (JSONException e) {
            e.printStackTrace();
        }

        logData(TAG_DATA, "[MAC_ENTRY]" + js);
    }

    public static void logMACFinal(Object mac, byte [] in, byte [] out){
        JSONObject js = new JSONObject();
        try {
            js.put("Mac", mac.hashCode());
            js.put("in", Base64.encodeToString(in, Base64.DEFAULT));
            js.put("out", Base64.encodeToString(out, Base64.DEFAULT));
        } catch (JSONException e) {
            e.printStackTrace();
        }

        logData(TAG_DATA, "[MAC_FINAL]" + js);
    }

    public static void logMACReset(Object mac){
        JSONObject js = new JSONObject();
        try {
            js.put("Mac", mac.hashCode());
        } catch (JSONException e) {
            e.printStackTrace();
        }

        logData(TAG_DATA, "[MAC_RESET]" + js);
    }

    public static void logMACClone(Object mac, Object clonedMac){
        JSONObject js = new JSONObject();
        try {
            js.put("Mac", mac.hashCode());
            js.put("Cloned", clonedMac.hashCode());
        } catch (JSONException e) {
            e.printStackTrace();
        }

        logData(TAG_DATA, "[MAC_CLONE]" + js);
    }

    public static void logRandom(String randomID){
        JSONObject js = new JSONObject();
        try {
            js.put("ID", randomID);
        } catch (JSONException e) {
            e.printStackTrace();
        }

        logData(TAG_DATA, "[RANDOM_ID]" + js);
    }

    public static void logTs(long ts){
        JSONObject js = new JSONObject();
        try {
            js.put("TS", Long.toString(ts));
        } catch (JSONException e) {
            e.printStackTrace();
        }

        logData(TAG_DATA, "[TIMESTAMP]" + js);
    }
}
