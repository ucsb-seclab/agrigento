package edu.seclab.changer;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import android.util.Log;
import android.accounts.Account;

import static de.robv.android.xposed.XposedHelpers.findAndHookMethod;

public class Changer implements IXposedHookLoadPackage {
    private static String TAG_DEBUG = "[CHANGER-DEBUG]";

    public void handleLoadPackage(final XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        Log.d(TAG_DEBUG, "Loaded app: " + lpparam.packageName);

        String apkPackage = Utils.getAPKPackage();
        Log.d(TAG_DEBUG, "APKPackage:" + apkPackage);

        if (!lpparam.packageName.equals(apkPackage))
            return;

        Log.d(TAG_DEBUG, "We are in " + apkPackage);

        // ******** Set hooks ********

        findAndHookMethod("android.telephony.TelephonyManager", lpparam.classLoader, "getLine1Number",
                new GetPhoneNumHook());
        findAndHookMethod("android.telephony.TelephonyManager", lpparam.classLoader, "getSimSerialNumber",
                new GetSimSerialNumHook());
        findAndHookMethod("android.telephony.TelephonyManager", lpparam.classLoader, "getSubscriberId",
                new GetSubscriberIDHook());
        findAndHookMethod("android.telephony.TelephonyManager", lpparam.classLoader, "getDeviceId",
                new GetDeviceIDHook());
        findAndHookMethod("android.net.wifi.WifiInfo", lpparam.classLoader, "getMacAddress",
                new GetMACAddrHook());
    }


    public class GetPhoneNumHook extends XC_MethodHook {
        public GetPhoneNumHook(){
            Log.d(TAG_DEBUG, "Setting GetPhoneNumHook");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "GetPhoneNumHook before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "GetPhoneNumHook after");

            String result = Utils.getPhoneNumber();
            param.setResult(result);
        }
    }

    public class GetSimSerialNumHook extends XC_MethodHook {
        public GetSimSerialNumHook(){
            Log.d(TAG_DEBUG, "Setting GetSimSerialNumHook");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "GetSimSerialNumHook before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "GetSimSerialNumHook after");

            String result = Utils.getSimSerialNum();
            param.setResult(result);
        }
    }

    public class GetSubscriberIDHook extends XC_MethodHook {
        public GetSubscriberIDHook(){
            Log.d(TAG_DEBUG, "Setting GetSubscriberIDHook");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "GetSubscriberIDHook before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "GetSubscriberIDHook after");

            String result = Utils.getSubscriberID();
            param.setResult(result);
        }
    }

    public class GetDeviceIDHook extends XC_MethodHook {
        public GetDeviceIDHook(){
            Log.d(TAG_DEBUG, "Setting GetDeviceIDHook");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "GetDeviceIDHook before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "GetDeviceIDHook after");

            String result = Utils.getDeviceID();
            param.setResult(result);
        }
    }

    public class GetMACAddrHook extends XC_MethodHook {
        public GetMACAddrHook(){
            Log.d(TAG_DEBUG, "Setting GetMACAddrHook");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "GetMACAddrHook before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "GetMACAddrHook after");

            String result = Utils.getMACAddr();
            param.setResult(result);
        }
    }

    public class GetEMailHook extends XC_MethodHook {
        public GetEMailHook(){
            Log.d(TAG_DEBUG, "Setting GetEMailHook");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "GetEMailHook before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "GetEMailHook after");

            String result = Utils.getEMail();
            param.setResult(result);
        }
    }

    public class GetAccountsHook extends XC_MethodHook {
        public GetAccountsHook(){
            Log.d(TAG_DEBUG, "Setting GetAccountsHook");
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "GetAccountsHook before");
        }
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG_DEBUG, "GetAccountsHook after");

            Account [] result = new Account[1];
            result[0] = new Account(Utils.getEMail(), "com.google");
            param.setResult(result);
        }
    }
}