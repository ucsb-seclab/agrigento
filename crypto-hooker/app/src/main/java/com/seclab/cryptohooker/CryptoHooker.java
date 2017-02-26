package com.seclab.cryptohooker;

import java.util.Arrays;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.SecureRandom;
import java.security.AlgorithmParameters;
import java.security.spec.AlgorithmParameterSpec;
import java.security.Provider;
import android.app.ActivityManager.MemoryInfo;

import static de.robv.android.xposed.XposedHelpers.findAndHookMethod;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

import android.util.Log;

public class CryptoHooker implements IXposedHookLoadPackage {
    private static String TAG_DEBUG = "[CRYPTOHOOKER-DEBUG]";

    public void handleLoadPackage(final LoadPackageParam lpparam) throws Throwable {
        Log.d(TAG_DEBUG, "Loaded app: " + lpparam.packageName);
        Utils.logData(TAG_DEBUG, "Loaded app: " + lpparam.packageName);

        String apkPackage = Utils.getAPKPackage();
        Log.d(TAG_DEBUG, "APKPackage:" + apkPackage);
        Utils.logData(TAG_DEBUG, "APKPackage:" + apkPackage);

        if (!lpparam.packageName.equals(apkPackage))
            return;

        Log.d(TAG_DEBUG, "We are in " + apkPackage);
        Utils.logData(TAG_DEBUG, "We are in " + apkPackage);

        boolean recordTS = Utils.recordTimestamps();
        Log.d(TAG_DEBUG, "Record TS: " + Boolean.toString(recordTS));
        Utils.logData(TAG_DEBUG, "Record TS: " + Boolean.toString(recordTS));

        // ******** Set hooks for crypto functions ********

        //Set hooks for init methods
        findAndHookMethod("javax.crypto.Cipher", lpparam.classLoader, "init", int.class, Key.class,
                new CryptoInitHook());
        findAndHookMethod("javax.crypto.Cipher", lpparam.classLoader, "init", int.class, Key.class,
                AlgorithmParameters.class, new CryptoInitHook());
        findAndHookMethod("javax.crypto.Cipher", lpparam.classLoader, "init", int.class, Key.class,
                AlgorithmParameterSpec.class, new CryptoInitHook());
        findAndHookMethod("javax.crypto.Cipher", lpparam.classLoader, "init", int.class, Key.class,
                AlgorithmParameterSpec.class, SecureRandom.class, new CryptoInitHook());
        findAndHookMethod("javax.crypto.Cipher", lpparam.classLoader, "init", int.class, Key.class,
                AlgorithmParameters.class, SecureRandom.class, new CryptoInitHook());
        findAndHookMethod("javax.crypto.Cipher", lpparam.classLoader, "init", int.class, Key.class,
                SecureRandom.class, new CryptoInitHook());


        //Set hooks for update methods

        findAndHookMethod("javax.crypto.Cipher", lpparam.classLoader, "update", byte[].class,
                new CryptoUpdateHook1());
        findAndHookMethod("javax.crypto.Cipher", lpparam.classLoader, "update", byte[].class,
                int.class, int.class, new CryptoUpdateHook3());
        findAndHookMethod("javax.crypto.Cipher", lpparam.classLoader, "update", byte[].class,
                int.class, int.class, byte[].class, new CryptoUpdateHook4());
        findAndHookMethod("javax.crypto.Cipher", lpparam.classLoader, "update", byte[].class,
                int.class, int.class, byte[].class, int.class, new CryptoUpdateHook5());
        findAndHookMethod("javax.crypto.Cipher", lpparam.classLoader, "update", ByteBuffer.class,
                ByteBuffer.class, new CryptoUpdateHook6());


        // Set hooks for doFinal methods

        findAndHookMethod("javax.crypto.Cipher", lpparam.classLoader, "doFinal",
                new CryptoHook0());
        findAndHookMethod("javax.crypto.Cipher", lpparam.classLoader, "doFinal", byte[].class,
                new CryptoHook1());
        findAndHookMethod("javax.crypto.Cipher", lpparam.classLoader, "doFinal", byte[].class,
                int.class, new CryptoHook2());
        findAndHookMethod("javax.crypto.Cipher", lpparam.classLoader, "doFinal", byte[].class,
                int.class, int.class, new CryptoHook3());
        findAndHookMethod("javax.crypto.Cipher", lpparam.classLoader, "doFinal", byte[].class,
                int.class, int.class, byte[].class, new CryptoHook4());
        findAndHookMethod("javax.crypto.Cipher", lpparam.classLoader, "doFinal", byte[].class,
                int.class, int.class, byte[].class, int.class, new CryptoHook5());
        findAndHookMethod("javax.crypto.Cipher", lpparam.classLoader, "doFinal", ByteBuffer.class,
                ByteBuffer.class, new CryptoHook6());


        // ******** Set hooks for hash functions ********

        //Set hooks for getInstance methods
        findAndHookMethod("java.security.MessageDigest", lpparam.classLoader, "getInstance",
                String.class, new HashInitHook());
        findAndHookMethod("java.security.MessageDigest", lpparam.classLoader, "getInstance",
                String.class, Provider.class, new HashInitHook());
        findAndHookMethod("java.security.MessageDigest", lpparam.classLoader, "getInstance",
                String.class, String.class, new HashInitHook());

        //Set hooks for update methods
        findAndHookMethod("java.security.MessageDigest", lpparam.classLoader, "update",
                byte.class, new HashUpdateHook0());
        findAndHookMethod("java.security.MessageDigest", lpparam.classLoader, "update",
                byte[].class, new HashUpdateHook1());
        findAndHookMethod("java.security.MessageDigest", lpparam.classLoader, "update",
                byte[].class, int.class, int.class, new HashUpdateHook3());
        findAndHookMethod("java.security.MessageDigest", lpparam.classLoader, "update",
                ByteBuffer.class, new HashUpdateHook4());

        //Set hooks for reset methods
        findAndHookMethod("java.security.MessageDigest", lpparam.classLoader, "reset",
                new HashResetHook());

        //Set hooks for clone methods
        findAndHookMethod("java.security.MessageDigest", lpparam.classLoader, "clone",
                new HashCloneHook());

        //Set hooks for digest methods
        findAndHookMethod("java.security.MessageDigest", lpparam.classLoader, "digest",
                new HashHook0());
        // findAndHookMethod("java.security.MessageDigest", lpparam.classLoader, "digest",
        //         byte[].class, new HashHook1());
        findAndHookMethod("java.security.MessageDigest", lpparam.classLoader, "digest",
                byte[].class, int.class, int.class, new HashHook3());


        // ******** Set hooks for random-ID-generation functions ********

        //Set hooks for randomUUID methods
        findAndHookMethod("java.util.UUID", lpparam.classLoader, "randomUUID",
                new RandomUUIDHook());


        // ******** Set hooks for MAC functions ********

        //Set hooks for init methods
        findAndHookMethod("javax.crypto.Mac", lpparam.classLoader, "init",
                Key.class, new MACInitHook());

        findAndHookMethod("javax.crypto.Mac", lpparam.classLoader, "init",
                Key.class, AlgorithmParameterSpec.class, new MACInitHook());

        //Set hooks for update methods
        findAndHookMethod("javax.crypto.Mac", lpparam.classLoader, "update",
                byte.class, new MACUpdateHook0());
        findAndHookMethod("javax.crypto.Mac", lpparam.classLoader, "update",
                byte[].class, new MACUpdateHook1());
        findAndHookMethod("javax.crypto.Mac", lpparam.classLoader, "update",
                byte[].class, int.class, int.class, new MACUpdateHook3());
        findAndHookMethod("javax.crypto.Mac", lpparam.classLoader, "update",
                ByteBuffer.class, new MACUpdateHook4());

        //Set hooks for doFinal methods
        findAndHookMethod("javax.crypto.Mac", lpparam.classLoader, "doFinal",
                new MACHook0());
        findAndHookMethod("javax.crypto.Mac", lpparam.classLoader, "doFinal",
                byte[].class, new MACHook1());
        findAndHookMethod("javax.crypto.Mac", lpparam.classLoader, "doFinal",
                byte[].class, int.class, new MACHook3());

        //Set hooks for clone methods
        findAndHookMethod("javax.crypto.Mac", lpparam.classLoader, "clone",
                new MACCloneHook());

        //Set hooks for reset methods
        findAndHookMethod("javax.crypto.Mac", lpparam.classLoader, "reset",
                new MACResetHook());


        // ******** Set hooks for random-numbers-generation functions ********

        //Set hooks for Math.random method
        findAndHookMethod("java.lang.Math", lpparam.classLoader, "random",
                new MathRandomHook());

        //Set hooks for Random.next methods
      findAndHookMethod("java.util.Random", lpparam.classLoader, "next",
                int.class, new SetRandomHookInt());
        findAndHookMethod("java.util.Random", lpparam.classLoader, "nextBoolean",
                new SetRandomHookBoolean());
        findAndHookMethod("java.util.Random", lpparam.classLoader, "nextDouble",
                new SetRandomHookDouble());
        findAndHookMethod("java.util.Random", lpparam.classLoader, "nextFloat",
                new SetRandomHookFloat());
        findAndHookMethod("java.util.Random", lpparam.classLoader, "nextGaussian",
                new SetRandomHookDouble());
        findAndHookMethod("java.util.Random", lpparam.classLoader, "nextInt",
                new SetRandomHookInt());
        findAndHookMethod("java.util.Random", lpparam.classLoader, "nextInt",
                int.class, new SetRandomHookIntMax());
        findAndHookMethod("java.util.Random", lpparam.classLoader, "nextLong",
                new SetRandomHookLong());
        findAndHookMethod("java.util.Random", lpparam.classLoader, "nextBytes",
                byte[].class, new SetRandomBytesHook());

        //Set hooks for ThreadLocalRandom.next methods
        findAndHookMethod("java.util.concurrent.ThreadLocalRandom", lpparam.classLoader, "next",
                int.class, new SetRandomHookInt());
        findAndHookMethod("java.util.concurrent.ThreadLocalRandom", lpparam.classLoader,
                "nextDouble", double.class, new SetRandomHookDoubleMax());
        findAndHookMethod("java.util.concurrent.ThreadLocalRandom", lpparam.classLoader,
                "nextDouble", double.class, double.class, new SetRandomHookDoubleMinMax());
        findAndHookMethod("java.util.concurrent.ThreadLocalRandom", lpparam.classLoader, "nextInt",
                int.class, int.class, new SetRandomHookIntMinMax());
        findAndHookMethod("java.util.concurrent.ThreadLocalRandom", lpparam.classLoader, "nextLong",
                long.class, new SetRandomHookLongMax());
        findAndHookMethod("java.util.concurrent.ThreadLocalRandom", lpparam.classLoader, "nextLong",
                long.class, long.class, new SetRandomHookLongMinMax());

        //Set hooks for SecureRandom.next methods
        findAndHookMethod("java.security.SecureRandom", lpparam.classLoader, "next",
                int.class, new SetRandomHookInt());
        findAndHookMethod("java.security.SecureRandom", lpparam.classLoader, "nextBytes",
                byte[].class, new SetRandomBytesHook());


        // ******** Set hooks for timestamp-related functions ********

        findAndHookMethod("android.os.SystemClock", lpparam.classLoader, "elapsedRealtime",
                new ElapsedRealtimeHook());
        findAndHookMethod("android.os.SystemClock", lpparam.classLoader, "elapsedRealtimeNanos",
                new ElapsedRealtimeNanosHook());
        findAndHookMethod("android.os.SystemClock", lpparam.classLoader, "currentThreadTimeMillis",
                new CurrentThreadTimeMillisHook());
        findAndHookMethod("java.lang.System", lpparam.classLoader, "currentTimeMillis",
                new CurrentTimeMillisHook());

        // ******** Set hooks for StatFs methods ********

        findAndHookMethod("android.os.StatFs", lpparam.classLoader, "getAvailableBlocks",
                new GetAvailableBlocksHook());
        findAndHookMethod("android.os.StatFs", lpparam.classLoader, "getAvailableBlocksLong",
                new GetAvailableBlocksHook());
        findAndHookMethod("android.os.StatFs", lpparam.classLoader, "getAvailableBytes",
                new GetAvailableBytesHook());
        findAndHookMethod("android.os.StatFs", lpparam.classLoader, "getBlockCount",
                new GetBlockCountHook());
        findAndHookMethod("android.os.StatFs", lpparam.classLoader, "getBlockCountLong",
                new GetBlockCountHook());
        findAndHookMethod("android.os.StatFs", lpparam.classLoader, "getBlockSize",
                new GetBlockSizeHook());
        findAndHookMethod("android.os.StatFs", lpparam.classLoader, "getBlockSizeLong",
                new GetBlockSizeHook());
        findAndHookMethod("android.os.StatFs", lpparam.classLoader, "getFreeBlocks",
                new GetFreeBlocksHook());
        findAndHookMethod("android.os.StatFs", lpparam.classLoader, "getFreeBlocksLong",
                new GetFreeBlocksHook());
        findAndHookMethod("android.os.StatFs", lpparam.classLoader, "getFreeBytes",
                new GetFreeBytesHook());
        findAndHookMethod("android.os.StatFs", lpparam.classLoader, "getTotalBytes",
                new GetTotalBytesHook());

        // ******** Set hooks for MemoryInfo functions ********

        findAndHookMethod("android.app.ActivityManager", lpparam.classLoader, "getMemoryInfo",
                MemoryInfo.class, new SetMemoryInfoHook());

    }

    // CryptoInit Hook

    public class CryptoInitHook extends XC_MethodHook{
        public CryptoInitHook(){
            Log.d(TAG_DEBUG, "Setting CryptoInitHook");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "CryptoInitHook before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "CryptoInitHook after");
            int opmode = (int)param.args[0];

            Utils.logCipherInit(param.thisObject, opmode);
        }
    }

    // CryptoUpdate Hooks

    public class CryptoUpdateHook1 extends XC_MethodHook{
        public CryptoUpdateHook1(){
            Log.d(TAG_DEBUG, "Setting CryptoUpdateHook1");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "CryptoUpdateHook1 before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "CryptoUpdateHook1 after");
            byte [] result = (byte [])param.getResult();
            byte[] input = (byte [])param.args[0];

            Utils.logCipherEntry(param.thisObject, input, result);
        }
    }

    public class CryptoUpdateHook3 extends XC_MethodHook{

        public CryptoUpdateHook3(){
            Log.d(TAG_DEBUG, "Setting CryptoUpdateHook3");
        }
        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "CryptoUpdateHook3 before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "CryptoUpdateHook3 after");
            byte[] input = (byte [])param.args[0];
            int offset = (int) param.args[1];
            int len = (int) param.args[2];

            if (offset + len <= input.length){

                byte [] realInput = Arrays.copyOfRange(input, offset, offset + len);
                byte [] result = (byte [])param.getResult();

                Utils.logCipherEntry(param.thisObject, realInput, result);
            }
            else
                Log.d(TAG_DEBUG, "CryptoUpdateHook3: Wrong offset/lenght");
        }

    }

    public class CryptoUpdateHook4 extends XC_MethodHook{
        public CryptoUpdateHook4(){
            Log.d(TAG_DEBUG, "Setting CryptoUpdateHook4");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "CryptoUpdateHook4 before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "CryptoUpdateHook4 after");
            byte[] input = (byte [])param.args[0];
            int offset = (int) param.args[1];
            int len = (int) param.args[2];
            byte [] output = (byte []) param.args[3];
            int outputLen = (int)param.getResult();

            if (offset + len <= input.length){

                byte [] realInput = Arrays.copyOfRange(input, offset, offset + len);
                byte [] realOutput = Arrays.copyOfRange(output, 0, outputLen);

                Utils.logCipherEntry(param.thisObject, realInput, realOutput);
            }
            else
                Log.d(TAG_DEBUG, "CryptoUpdateHook4: Wrong offset/lenght");
        }
    }

    public class CryptoUpdateHook5 extends XC_MethodHook{
        public CryptoUpdateHook5(){
            Log.d(TAG_DEBUG, "Setting CryptoUpdateHook5");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "CryptoUpdateHook5 before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "CryptoUpdateHook5 after");
            byte[] input = (byte [])param.args[0];
            int offset = (int) param.args[1];
            int len = (int) param.args[2];
            byte [] output = (byte []) param.args[3];
            int outputOffset = (int) param.args[4];
            int outputLen = (int) param.getResult();

            if (offset + len <= input.length){

                byte [] realInput = Arrays.copyOfRange(input, offset, offset + len);
                byte [] realOutput = Arrays.copyOfRange(output, outputOffset,
                        outputOffset + outputLen);

                Utils.logCipherEntry(param.thisObject, realInput, realOutput);
            }
            else
                Log.d(TAG_DEBUG, "CryptoUpdateHook5: Wrong offset/lenght");
        }
    }

    public class CryptoUpdateHook6 extends XC_MethodHook{
        int input_pos;
        int output_pos;

        public CryptoUpdateHook6(){
            Log.d(TAG_DEBUG, "Setting CryptoUpdateHook6");
            this.input_pos = 0;
            this.output_pos = 0;
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "CryptoUpdateHook6 before");
            ByteBuffer inputB = (ByteBuffer) param.args[0];
            ByteBuffer outputB = (ByteBuffer) param.args[1];

            this.input_pos = inputB.position();
            this.output_pos = outputB.position();
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "CryptoUpdateHook6 after");

            ByteBuffer inputB = (ByteBuffer) param.args[0];
            ByteBuffer outputB = (ByteBuffer) param.args[1];
            int len = (int) param.getResult();

            if (inputB.hasArray() && outputB.hasArray()) {
                byte[] input = inputB.array();
                byte[] output = outputB.array();
                byte[] realInput = Arrays.copyOfRange(input, this.input_pos,
                        this.input_pos + len);
                byte[] readOutput = Arrays.copyOfRange(output, this.output_pos,
                        this.output_pos + len);

                Utils.logCipherEntry(param.thisObject, realInput, readOutput);
            }
        }
    }


    // Crypto Hooks

    public class CryptoHook0 extends XC_MethodHook{
        public CryptoHook0(){
            Log.d(TAG_DEBUG, "Setting CryptoHook0");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "CryptoHook0 before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "CryptoHook0 after");
            byte [] result = (byte [])param.getResult();

            Utils.logCipherFinal(param.thisObject, new byte[0], result);
        }
    }

    public class CryptoHook1 extends XC_MethodHook{
        public CryptoHook1(){
            Log.d(TAG_DEBUG, "Setting CryptoHook1");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "CryptoHook1 before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "CryptoHook1 after");
            byte [] result = (byte [])param.getResult();
            byte[] input = (byte [])param.args[0];

            Utils.logCipherFinal(param.thisObject, input, result);
        }
    }

    public class CryptoHook2 extends XC_MethodHook{
        public CryptoHook2(){
            Log.d(TAG_DEBUG, "Setting CryptoHook2");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "CryptoHook2 before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "CryptoHook2 after");
            byte [] output = (byte [])param.args[0];
            int offset = (int) param.args[1];
            int len = (int)param.getResult();

            byte[] realOutput = Arrays.copyOfRange(output, offset, offset + len);

            Utils.logCipherFinal(param.thisObject, new byte[0], realOutput);
        }
    }

    public class CryptoHook3 extends XC_MethodHook{

        public CryptoHook3(){
            Log.d(TAG_DEBUG, "Setting CryptoHook3");
        }
        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "CryptoHook3 before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "CryptoHook3 after");
            byte[] input = (byte [])param.args[0];
            int offset = (int) param.args[1];
            int len = (int) param.args[2];

            if (offset + len <= input.length){

                byte [] realInput = Arrays.copyOfRange(input, offset, offset + len);
                byte [] result = (byte [])param.getResult();

                Utils.logCipherFinal(param.thisObject, realInput, result);
            }
            else
                Log.d(TAG_DEBUG, "CryptoHook3: Wrong offset/lenght");
        }

    }

    public class CryptoHook4 extends XC_MethodHook{
        public CryptoHook4(){
            Log.d(TAG_DEBUG, "Setting CryptoHook4");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "CryptoHook4 before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "CryptoHook4 after");
            byte[] input = (byte [])param.args[0];
            int offset = (int) param.args[1];
            int len = (int) param.args[2];
            byte [] output = (byte []) param.args[3];
            int outputLen = (int)param.getResult();

            if (offset + len <= input.length){

                byte [] realInput = Arrays.copyOfRange(input, offset, offset + len);
                byte [] realOutput = Arrays.copyOfRange(output, 0, outputLen);

                Utils.logCipherFinal(param.thisObject, realInput, realOutput);
            }
            else
                Log.d(TAG_DEBUG, "CryptoHook4: Wrong offset/lenght");
        }
    }

    public class CryptoHook5 extends XC_MethodHook{
        public CryptoHook5(){
            Log.d(TAG_DEBUG, "Setting CryptoHook5");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "CryptoHook5 before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "CryptoHook5 after");
            byte[] input = (byte [])param.args[0];
            int offset = (int) param.args[1];
            int len = (int) param.args[2];
            byte [] output = (byte []) param.args[3];
            int outputOffset = (int) param.args[4];
            int outputLen = (int) param.getResult();

            if (offset + len <= input.length){

                byte [] realInput = Arrays.copyOfRange(input, offset, offset + len);
                byte [] realOutput = Arrays.copyOfRange(output, outputOffset,
                        outputOffset + outputLen);

                Utils.logCipherFinal(param.thisObject, realInput, realOutput);
            }
            else
                Log.d(TAG_DEBUG, "CryptoHook5: Wrong offset/lenght");
        }
    }

    public class CryptoHook6 extends XC_MethodHook{
        int input_pos ;
        int output_pos;

        public CryptoHook6(){
            Log.d(TAG_DEBUG, "Setting CryptoHook6");
            this.input_pos = 0;
            this.output_pos = 0;
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "CryptoHook6 before");
            ByteBuffer inputB = (ByteBuffer) param.args[0];
            ByteBuffer outputB = (ByteBuffer) param.args[1];

            this.input_pos = inputB.position();
            this.output_pos = outputB.position();
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "CryptoHook6 after");

            ByteBuffer inputB = (ByteBuffer) param.args[0];
            ByteBuffer outputB = (ByteBuffer) param.args[1];
            int len = (int) param.getResult();

            if (inputB.hasArray() && outputB.hasArray()){
                byte [] input = inputB.array();
                byte [] output = outputB.array();
                byte [] realInput = Arrays.copyOfRange(input, this.input_pos,
                        this.input_pos + len);
                byte [] readOutput = Arrays.copyOfRange(output, this.output_pos,
                        this.output_pos + len);

                Utils.logCipherFinal(param.thisObject, realInput, readOutput);
            }
        }
    }

    // HashInit Hook

    public class HashInitHook extends XC_MethodHook{
        public HashInitHook(){
            Log.d(TAG_DEBUG, "Setting HashInitHook");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "HashInitHook before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "HashInitHook after");

            Utils.logHashInit(param.getResult());
        }
    }

    // HashUpdate Hooks

    public class HashUpdateHook0 extends XC_MethodHook{
        public HashUpdateHook0(){
            Log.d(TAG_DEBUG, "Setting HashUpdateHook0");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "HashUpdateHook0 before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "HashUpdateHook0 after");
            byte input = (byte) param.args[0];

            Utils.logHashEntry(param.thisObject, new byte[]{input}, new byte[0]);
        }
    }

    public class HashUpdateHook1 extends XC_MethodHook{
        public HashUpdateHook1(){
            Log.d(TAG_DEBUG, "Setting HashUpdateHook1");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "HashUpdateHook1 before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "HashUpdateHook1 after");
            byte [] input = (byte []) param.args[0];

            Utils.logHashEntry(param.thisObject, input, new byte[0]);
        }
    }

    public class HashUpdateHook3 extends XC_MethodHook{
        public HashUpdateHook3(){
            Log.d(TAG_DEBUG, "Setting HashUpdateHook3");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "HashUpdateHook3 before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "HashUpdateHook3 after");
            byte [] input = (byte []) param.args[0];
            int offset = (int) param.args[1];
            int len = (int) param.args[2];

            if (offset + len <= input.length) {
                byte[] realInput= Arrays.copyOfRange(input, offset, offset + len);
                Utils.logHashEntry(param.thisObject, realInput, new byte[0]);
            }
            else
                Log.d(TAG_DEBUG, "HashUpdateHook3: Wrong offset/lenght");
        }
    }

    public class HashUpdateHook4 extends XC_MethodHook{
        public HashUpdateHook4(){
            Log.d(TAG_DEBUG, "Setting HashUpdateHook4");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "HashUpdateHook4 before");
            ByteBuffer inputB = (ByteBuffer) param.args[0];
            int pos = inputB.position();

            if (inputB.hasArray()) {
                byte[] input = inputB.array();
                byte[] realInput = Arrays.copyOfRange(input, pos, input.length);

                Utils.logHashEntry(param.thisObject, realInput, new byte[0]);
            }
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "HashUpdateHook4 after");
        }
    }

    // HashReset Hook

    public class HashResetHook extends XC_MethodHook{
        public HashResetHook(){
            Log.d(TAG_DEBUG, "Setting HashResetHook");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "HashResetHook before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "HashResetHook after");

            Utils.logHashReset(param.thisObject);
        }
    }

    // HashClone Hook

    public class HashCloneHook extends XC_MethodHook{
        public HashCloneHook(){
            Log.d(TAG_DEBUG, "Setting HashCloneHook");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "HashCloneHook before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "HashCloneHook after");

            Utils.logHashClone(param.thisObject, param.getResult());
        }
    }

    // Hash Hooks

    public class HashHook0 extends XC_MethodHook{
        public HashHook0(){
            Log.d(TAG_DEBUG, "Setting HashHook0");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "HashHook0 before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "HashHook0 after");
            byte [] output = (byte []) param.getResult();

            Utils.logHashFinal(param.thisObject, new byte[0], output);
        }
    }

    public class HashHook1 extends XC_MethodHook{
        public HashHook1(){
            Log.d(TAG_DEBUG, "Setting HashHook1");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "HashHook1 before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "HashHook1 after");
            byte [] input = (byte []) param.args[0];
            byte [] output = (byte []) param.getResult();

            Utils.logHashFinal(param.thisObject, input, output);
        }
    }

    public class HashHook3 extends XC_MethodHook{
        public HashHook3(){
            Log.d(TAG_DEBUG, "Setting HashHook3");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "HashHook3 before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "HashHook3 after");
            byte [] output = (byte []) param.args[0];
            int offset = (int) param.args[1];
            int len = (int) param.getResult();

            if (offset + len <= output.length) {
                byte[] realOutput = Arrays.copyOfRange(output, offset, offset + len);
                Utils.logHashFinal(param.thisObject, new byte[0], realOutput);
            }
            else
                Log.d(TAG_DEBUG, "HashHook3: Wrong offset/lenght");
        }
    }

    // Random Hook

    public class RandomUUIDHook extends XC_MethodHook{
        public RandomUUIDHook(){
            Log.d(TAG_DEBUG, "Setting RandomUUIDHook");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "RandomUUIDHook before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "RandomUUIDHook after");

            Object uid = param.getResult();

            Utils.logRandom(uid.toString());
        }
    }

    // MAC Hooks

    public class MACInitHook extends XC_MethodHook{
        public MACInitHook(){
            Log.d(TAG_DEBUG, "Setting MACInitHook");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "MACInitHook before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "MACInitHook after");

            Utils.logMACInit(param.thisObject);
        }
    }

    public class MACCloneHook extends XC_MethodHook{
        public MACCloneHook(){
            Log.d(TAG_DEBUG, "Setting MACCloneHook");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "MACCloneHook before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "MACCloneHook after");

            Utils.logMACClone(param.thisObject, param.getResult());
        }
    }

    public class MACResetHook extends XC_MethodHook{
        public MACResetHook(){
            Log.d(TAG_DEBUG, "Setting MACResetHook");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "MACResetHook before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "MACResetHook after");

            Utils.logMACReset(param.thisObject);
        }
    }

    public class MACUpdateHook0 extends XC_MethodHook{
        public MACUpdateHook0(){
            Log.d(TAG_DEBUG, "Setting MACUpdateHook0");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "MACUpdateHook0 before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "MACUpdateHook0 after");
            byte input = (byte) param.args[0];

            Utils.logMACEntry(param.thisObject, new byte[]{input}, new byte[0]);
        }
    }

    public class MACUpdateHook1 extends XC_MethodHook{
        public MACUpdateHook1(){
            Log.d(TAG_DEBUG, "Setting MACUpdateHook1");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "MACUpdateHook1 before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "MACUpdateHook1 after");
            byte [] input = (byte []) param.args[0];

            Utils.logMACEntry(param.thisObject, input, new byte[0]);
        }
    }

    public class MACUpdateHook3 extends XC_MethodHook{
        public MACUpdateHook3(){
            Log.d(TAG_DEBUG, "Setting MACUpdateHook3");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "MACUpdateHook3 before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "MACUpdateHook3 after");
            byte [] input = (byte []) param.args[0];
            int offset = (int) param.args[1];
            int len = (int) param.args[2];

            if (offset + len <= input.length) {
                byte[] realInput= Arrays.copyOfRange(input, offset, offset + len);
                Utils.logMACEntry(param.thisObject, realInput, new byte[0]);
            }
            else
                Log.d(TAG_DEBUG, "MACUpdateHook3: Wrong offset/lenght");
        }
    }

    public class MACUpdateHook4 extends XC_MethodHook{
        public MACUpdateHook4(){
            Log.d(TAG_DEBUG, "Setting MACUpdateHook4");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "MACUpdateHook4 before");
            ByteBuffer inputB = (ByteBuffer) param.args[0];
            int pos = inputB.position();

            if (inputB.hasArray()) {
                byte[] input = inputB.array();
                byte[] realInput = Arrays.copyOfRange(input, pos, input.length);

                Utils.logMACEntry(param.thisObject, realInput, new byte[0]);
            }
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "MACUpdateHook4 after");
        }
    }

    public class MACHook0 extends XC_MethodHook{
        public MACHook0(){
            Log.d(TAG_DEBUG, "Setting MACHook0");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "MACHook0 before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "MACHook0 after");
            byte [] output = (byte []) param.getResult();

            Utils.logMACFinal(param.thisObject, new byte[0], output);
        }
    }

    public class MACHook1 extends XC_MethodHook{
        public MACHook1(){
            Log.d(TAG_DEBUG, "Setting MACHook1");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "MACHook1 before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "MACHook1 after");
            byte [] input = (byte []) param.args[0];
            byte [] output = (byte []) param.getResult();

            Utils.logMACFinal(param.thisObject, input, output);
        }
    }

    public class MACHook3 extends XC_MethodHook{
        public MACHook3(){
            Log.d(TAG_DEBUG, "Setting MACHook3");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "MACHook3 before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "MACHook3 after");
            byte [] output = (byte []) param.args[0];
            int offset = (int) param.args[1];

            if (offset <= output.length) {
                byte[] realOutput = Arrays.copyOfRange(output, offset, output.length);
                Utils.logMACFinal(param.thisObject, new byte[0], realOutput);
            }
            else
                Log.d(TAG_DEBUG, "MACHook3: Wrong offset/lenght");
        }
    }

    // Random Hook

    public class MathRandomHook extends XC_MethodHook{
        public MathRandomHook(){
            Log.d(TAG_DEBUG, "Setting MathRandomHook");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "MathRandomHook before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "MathRandomHook after");

            param.setResult(Utils.nextNumber("math"));
        }
    }

    public class SetRandomHookDouble extends XC_MethodHook{
        public SetRandomHookDouble(){
            Log.d(TAG_DEBUG, "Setting SetRandomHookDouble");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "SetRandomHookDouble before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "SetRandomHookDouble after");

            param.setResult(Utils.nextNumber(Integer.toString(param.thisObject.hashCode())));
        }
    }

    public class SetRandomHookDoubleMax extends XC_MethodHook{
        public SetRandomHookDoubleMax(){
            Log.d(TAG_DEBUG, "Setting SetRandomHookDoubleMax");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "SetRandomHookDoubleMax before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "SetRandomHookDoubleMax after");

            double max = (double) param.args[0];
            double output = Utils.nextNumber(Integer.toString(param.thisObject.hashCode()));

            while (output > max){
                output = output - max;
            }

            param.setResult(output);
        }
    }

    public class SetRandomHookDoubleMinMax extends XC_MethodHook{
        public SetRandomHookDoubleMinMax(){
            Log.d(TAG_DEBUG, "Setting SetRandomHookDoubleMinMax");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "SetRandomHookDoubleMinMax before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "SetRandomHookDoubleMinMax after");

            double min = (double) param.args[0];
            double max = (double) param.args[1];
            double output = Utils.nextNumber(Integer.toString(param.thisObject.hashCode()));

            while (output > max){
                output = output - max;
            }

            if (output < min){
                output = output + (min - output + (max - min) / 2);
            }
            param.setResult(output);
        }
    }

    public class SetRandomHookFloat extends XC_MethodHook{
        public SetRandomHookFloat(){
            Log.d(TAG_DEBUG, "Setting SetRandomHookFloat");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "SetRandomHookFloat before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "SetRandomHookFloat after");

            float output = (float) Utils.nextNumber(Integer.toString(param.thisObject.hashCode()));

            param.setResult(output);
        }
    }

    public class SetRandomHookInt extends XC_MethodHook{
        public SetRandomHookInt(){
            Log.d(TAG_DEBUG, "Setting SetRandomHookInt");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "SetRandomHookInt before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "SetRandomHookInt after");

            double number = Utils.nextNumber(Integer.toString(param.thisObject.hashCode()));
            int output = (int) (number * 100000) - 50000;
            param.setResult(output);
        }
    }


    public class SetRandomHookIntMinMax extends XC_MethodHook{
        public SetRandomHookIntMinMax(){
            Log.d(TAG_DEBUG, "Setting SetRandomHookIntMinMax");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "SetRandomHookIntMinMax before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "SetRandomHookIntMinMax after");

            int min = (int) param.args[0];
            int max = (int) param.args[1];
            double number = Utils.nextNumber(Integer.toString(param.thisObject.hashCode()));
            int output = (((int) (number * 100000)) % (max - min)) + min;

            param.setResult(output);
        }
    }

    public class SetRandomHookIntMax extends XC_MethodHook{
        public SetRandomHookIntMax(){
            Log.d(TAG_DEBUG, "Setting SetRandomHookIntMax");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "SetRandomHookIntMax before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "SetRandomHookIntMax after");

            int max = (int) param.args[0];
            double number = Utils.nextNumber(Integer.toString(param.thisObject.hashCode()));
            int output = ((int) (number * 100000)) % max;

            param.setResult(output);
        }
    }

    public class SetRandomHookLong extends XC_MethodHook{
        public SetRandomHookLong(){
            Log.d(TAG_DEBUG, "Setting SetRandomHookLong");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "SetRandomHookLong before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "SetRandomHookLong after");

            double number = Utils.nextNumber(Integer.toString(param.thisObject.hashCode()));
            long output = (long) (number * 100000000) - 50000000;
            param.setResult(output);
        }
    }


    public class SetRandomHookLongMinMax extends XC_MethodHook{
        public SetRandomHookLongMinMax(){
            Log.d(TAG_DEBUG, "Setting SetRandomHookLongMinMax");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "SetRandomHookLongMinMax before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "SetRandomHookLongMinMax after");

            long min = (long) param.args[0];
            long max = (long) param.args[1];
            double number = Utils.nextNumber(Integer.toString(param.thisObject.hashCode()));
            long output = (((long) (number * 100000000)) % (max - min)) + min;

            param.setResult(output);
        }
    }

    public class SetRandomHookLongMax extends XC_MethodHook{
        public SetRandomHookLongMax(){
            Log.d(TAG_DEBUG, "Setting SetRandomHookLongMax");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "SetRandomHookLongMax before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "SetRandomHookLongMax after");

            long max = (long) param.args[0];
            double number = Utils.nextNumber(Integer.toString(param.thisObject.hashCode()));
            long output = ((long) (number * 100000000)) % max;

            param.setResult(output);
        }
    }

    public class SetRandomHookBoolean extends XC_MethodHook{
        public SetRandomHookBoolean(){
            Log.d(TAG_DEBUG, "Setting SetRandomHookBoolean");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "SetRandomHookBoolean before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "SetRandomHookBoolean after");

            boolean output = Utils.nextNumber(Integer.toString(param.thisObject.hashCode())) > 0.5;
            param.setResult(output);
        }
    }

    public class SetRandomBytesHook extends XC_MethodHook{
        public SetRandomBytesHook(){
            Log.d(TAG_DEBUG, "Setting SetRandomBytesHook");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "SetRandomBytesHook before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "SetRandomBytesHook after");

            byte [] bytes = (byte []) param.args[0];

            for(int i = 0; i < bytes.length; i++) {
                double number = Utils.nextNumber(Integer.toString(param.thisObject.hashCode()));
                bytes[i] = (byte) (number * 256);
            }
        }
    }

    // Timestamp Hook

    public class ElapsedRealtimeHook extends XC_MethodHook{
        public ElapsedRealtimeHook(){
            Log.d(TAG_DEBUG, "Setting ElapsedRealtimeHook");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "ElapsedRealtimeHook before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "ElapsedRealtimeHook after");
            long ts = (long) param.getResult();

            if (Utils.recordTimestamps()){
                Utils.recordTS("elapsedRealtime", ts);
            }
            else{
                long new_ts = Utils.nextTS("elapsedRealtime");
                if (new_ts > 0){
                    param.setResult(new_ts);
                    ts = new_ts;
                }
            }

            Utils.logTs(ts);
        }
    }

    public class ElapsedRealtimeNanosHook extends XC_MethodHook{
        public ElapsedRealtimeNanosHook(){
            Log.d(TAG_DEBUG, "Setting ElapsedRealtimeNanosHook");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "ElapsedRealtimeNanosHook before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "ElapsedRealtimeNanosHook after");
            long ts = (long) param.getResult();

            if (Utils.recordTimestamps()){
                Utils.recordTS("elapsedRealtimeNanos", ts);
            }
            else{
                long new_ts = Utils.nextTS("elapsedRealtimeNanos");
                if (new_ts > 0) {
                    param.setResult(new_ts);
                    ts = new_ts;
                }
            }

            Utils.logTs(ts);
        }
    }

    public class CurrentThreadTimeMillisHook extends XC_MethodHook{
        public CurrentThreadTimeMillisHook(){
            Log.d(TAG_DEBUG, "Setting CurrentThreadTimeMillisHook");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "CurrentThreadTimeMillisHook before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "CurrentThreadTimeMillisHook after");
            long ts = (long) param.getResult();

            if (Utils.recordTimestamps()){
                Utils.recordTS("currentThreadTimeMillis", ts);
            }
            else{
                long new_ts = Utils.nextTS("currentThreadTimeMillis");
                if (new_ts > 0) {
                    param.setResult(new_ts);
                    ts = new_ts;
                }
            }

            Utils.logTs(ts);
        }
    }


    public class UptimeMillisHook extends XC_MethodHook{
        public UptimeMillisHook(){
            Log.d(TAG_DEBUG, "Setting UptimeMillisHook");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "UptimeMillisHook before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "UptimeMillisHook after");
            long ts = (long) param.getResult();

            if (Utils.recordTimestamps()){
                Utils.recordTS("uptimeMillis", ts);
            }
            else{
                long new_ts = Utils.nextTS("uptimeMillis");
                if (new_ts > 0) {
                    param.setResult(new_ts);
                    ts = new_ts;
                }
            }

            Utils.logTs(ts);
        }
    }

    public class CurrentTimeMillisHook extends XC_MethodHook{
        public CurrentTimeMillisHook(){
            Log.d(TAG_DEBUG, "Setting CurrentTimeMillisHook");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "CurrentTimeMillisHook before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "CurrentTimeMillisHook after");
            long ts = (long) param.getResult();

            if (Utils.recordTimestamps()){
                Utils.recordTS("currentTimeMillis", ts);
            }
            else{
                long new_ts = Utils.nextTS("currentTimeMillis");
                if (new_ts > 0) {
                    param.setResult(new_ts);
                    ts = new_ts;
                }
            }

            Utils.logTs(ts);
        }
    }

    public class NanoTimeHook extends XC_MethodHook{
        public NanoTimeHook(){
            Log.d(TAG_DEBUG, "Setting NanoTimeHook");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "NanoTimeHook before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "NanoTimeHook after");
            long ts = (long) param.getResult();

            if (Utils.recordTimestamps()){
                Utils.recordTS("nanoTime", ts);
            }
            else{
                long new_ts = Utils.nextTS("nanoTime");
                if (new_ts > 0) {
                    param.setResult(new_ts);
                    ts = new_ts;
                }
            }

            Utils.logTs(ts);
        }
    }


    // MemoryInfo Hook
    public class SetMemoryInfoHook extends XC_MethodHook{
        public SetMemoryInfoHook(){
            Log.d(TAG_DEBUG, "Setting SetMemoryInfoHook");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "SetMemoryInfoHook before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "SetMemoryInfoHook after");

            MemoryInfo mi = (MemoryInfo) param.args[0];
            mi.availMem = Utils.availMem;
        }
    }


    // StatFS Hooks
    public class GetAvailableBlocksHook extends XC_MethodHook{
        public GetAvailableBlocksHook(){
            Log.d(TAG_DEBUG, "Setting GetAvailableBlocksHook");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "GetAvailableBlocksHook before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "GetAvailableBlocksHook after");

            param.setResult(Utils.availableBlocks);
        }
    }

    public class GetAvailableBytesHook extends XC_MethodHook{
        public GetAvailableBytesHook(){
            Log.d(TAG_DEBUG, "Setting GetAvailableBytesHook");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "GetAvailableBytesHook before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "GetAvailableBytesHook after");

            param.setResult(Utils.availableBytes);
        }
    }

    public class GetBlockCountHook extends XC_MethodHook{
        public GetBlockCountHook(){
            Log.d(TAG_DEBUG, "Setting GetBlockCountHook");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "GetBlockCountHook before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "GetBlockCountHook after");

            param.setResult(Utils.blockCount);
        }
    }

    public class GetBlockSizeHook extends XC_MethodHook{
        public GetBlockSizeHook(){
            Log.d(TAG_DEBUG, "Setting GetBlockSizeHook");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "GetBlockSizeHook before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "GetBlockSizeHook after");

            param.setResult(Utils.blockSize);
        }
    }

    public class GetFreeBlocksHook extends XC_MethodHook{
        public GetFreeBlocksHook(){
            Log.d(TAG_DEBUG, "Setting GetFreeBlocksHook");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "GetFreeBlocksHook before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "GetFreeBlocksHook after");

            param.setResult(Utils.freeBlocks);
        }
    }

    public class GetFreeBytesHook extends XC_MethodHook{
        public GetFreeBytesHook(){
            Log.d(TAG_DEBUG, "Setting GetFreeBytesHook");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "GetFreeBytesHook before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "GetFreeBytesHook after");

            param.setResult(Utils.freeBytes);
        }
    }

    public class GetTotalBytesHook extends XC_MethodHook{
        public GetTotalBytesHook(){
            Log.d(TAG_DEBUG, "Setting GetTotalBytesHook");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "GetTotalBytesHook before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "GetTotalBytesHook after");

            param.setResult(Utils.totalBytes);
        }
    }
}

