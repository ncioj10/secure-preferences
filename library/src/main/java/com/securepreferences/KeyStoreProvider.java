package com.securepreferences;

import android.annotation.TargetApi;
import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.util.Base64;
import android.util.Log;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.security.auth.x500.X500Principal;

/**
 * Created by Nicolas on 14.02.2017.
 */

public class KeyStoreProvider {

    private final static String TAG = "KeyStoreProvider";

    //Use RSA
    private static final String RSA = "RSA";

    private static final String CIPHER_INFO = "RSA/ECB/PKCS1Padding";

    //Key alias
    private static String KEY_ALIAS;

    //Android Keystore
    private static final String AndroidKeyStore = "AndroidKeyStore";

    //keystore Instance
    private KeyStore keyStore;

    private boolean sLoggingEnabled;


    private KeyPair keyPair;

    private Cipher cipher;


    public KeyStoreProvider(Context context, boolean sLoggingEnabled, String alias) throws GeneralSecurityException {
        this.sLoggingEnabled = sLoggingEnabled;
        if(alias == null){
            throw new GeneralSecurityException("Alias may not be null");
        }

        //get alias(= identifier) for KeyStore
        KEY_ALIAS = alias;

        //set Cipher
        cipher = Cipher.getInstance(CIPHER_INFO);



        this.keyStore = getKeystore();


        if (!keyStore.containsAlias(KEY_ALIAS)) {
            generateRSAKeys(context);
        }

        // Even if we just generated the key, always read it back to ensure we can read it successfully.
        final KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, null);
        keyPair = new KeyPair(entry.getCertificate().getPublicKey(), entry.getPrivateKey());
    }


    public static boolean isAliasInKeystore(String alias) throws GeneralSecurityException
    {
        final KeyStore keyStore = getKeystore();
        return keyStore.containsAlias(alias);
    }


    public static void deleteAlias(String alias) throws GeneralSecurityException
    {
        final KeyStore keyStore = getKeystore();
        boolean aliasExists = keyStore.containsAlias(alias);
        keyStore.deleteEntry(alias);
        boolean aliasExitsAfterDelete = keyStore.containsAlias(alias);
    }


    private static KeyStore getKeystore() throws GeneralSecurityException
    {
        try
        {
            final KeyStore keyStore = KeyStore.getInstance(AndroidKeyStore);
            keyStore.load(null);
            return keyStore;
        }
        catch (Exception e)
        {
            e.printStackTrace();
            throw new GeneralSecurityException(e);
        }

    }

    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
    private boolean generateRSAKeys(Context context){
        // Generate the RSA key pairs
        try {
            if (!keyStore.containsAlias(KEY_ALIAS)) {
                // Generate a key pair for encryption
                Calendar start = Calendar.getInstance();
                Calendar end = Calendar.getInstance();
                end.add(Calendar.YEAR, 30);
                KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(context)
                        .setAlias(KEY_ALIAS)
                        .setSubject(new X500Principal("CN=" + KEY_ALIAS))
                        .setSerialNumber(BigInteger.ONE)
                        .setStartDate(start.getTime())
                        .setEndDate(end.getTime())
                        .build();
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(RSA, AndroidKeyStore);
                kpg.initialize(spec);
                kpg.generateKeyPair();
                return true;
            }
        } catch (KeyStoreException e) {
            if (sLoggingEnabled) {
                Log.e(TAG, "KeyStoreException while generating RSA Keys: " + e.getMessage());
            }
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
            if (sLoggingEnabled) {
                Log.e(TAG, "Invalid Algorithm: " + e.getMessage());
            }
        } catch (NoSuchProviderException e) {
            if (sLoggingEnabled) {
                Log.e(TAG, "Invalid Provider: " + e.getMessage());
            }
        }
        return false;
    }

    public byte[] rsaEncrypt(byte[] secret) throws Exception{
        // Encrypt the text
        byte[] enc = null;
        try
        {
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            enc = cipher.doFinal(secret);
        }
        //no need to catch 4 different exceptions
        catch (Exception e)
        {
            if(sLoggingEnabled) {
                Log.e(TAG,"Encrypt error: " +e.getMessage(), e);
                throw new RuntimeException(e);
            }
        }

        return enc;
    }

    public  byte[]  rsaDecrypt(byte[] encrypted) throws Exception {
        //Decrypt the text
        byte[] plain = null;
        try
        {
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            plain = cipher.doFinal(encrypted);
        }
        //no need to catch 4 different exceptions
        catch (Exception e)
        {
            if(sLoggingEnabled) {
                Log.e(TAG,"Decrypt error: " +e.getMessage(), e);
                throw new RuntimeException(e);
            }
        }
        return plain;
    }

    public String rsaDecryptWithStrings(String encrypted){
        try {
            byte[] encryptedBytes = Base64.decode(encrypted, Base64.NO_WRAP);
            byte[] decryptedBytes = rsaDecrypt(encryptedBytes);
            String decryptedString = new String(decryptedBytes, "UTF-8");
            return decryptedString;
        } catch (UnsupportedEncodingException e) {
            if (sLoggingEnabled) {
                Log.e(TAG, "Unsupported encoding: " + e.getMessage());
            }
        } catch (Exception e) {
            if (sLoggingEnabled) {
                Log.e(TAG, "Error while Decrypting: " + e.getMessage());
            }
        }
        return null;
    }

    public String rsaEncryptWithStrings(String decrypted){
        try {
            byte[] decryptedBytes = decrypted.getBytes("UTF-8");
            String encryptedString = Base64.encodeToString(rsaEncrypt(decryptedBytes),Base64.NO_WRAP);
            return encryptedString;
        } catch (UnsupportedEncodingException e) {
            if (sLoggingEnabled) {
                Log.e(TAG, "Unsupported encoding: " + e.getMessage());
            }
        } catch (Exception e) {
            if (sLoggingEnabled) {
                Log.e(TAG, "Error while Decrypting: " + e.getMessage());
            }
        }
        return null;
    }
}
