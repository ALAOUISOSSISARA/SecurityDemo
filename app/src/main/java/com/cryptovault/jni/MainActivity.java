package com.cryptovault.jni;

import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import com.cryptovault.jni.databinding.ActivityMainBinding;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "SecurityDemo";

    static {
        System.loadLibrary("security-lib");
    }

    // ── Déclarations natives ──────────────────────────────────────
    public native String getNativeFingerprint();
    public native int    xorEncrypt(int value, int key);
    public native String caesarCipher(String text, int shift);
    public native int    sumArray(int[] array);

    private ActivityMainBinding binding;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        // ── 1) Native Fingerprint ─────────────────────────────────
        String fingerprint = getNativeFingerprint();
        binding.tvFingerprint.setText(fingerprint);
        Log.i(TAG, "Fingerprint: " + fingerprint);

        // ── 2) XOR Cipher ─────────────────────────────────────────
        int value    = 42;
        int key      = 15;
        int enc      = xorEncrypt(value, key);
        int dec      = xorEncrypt(enc, key);
        int badKey   = xorEncrypt(value, 0);

        binding.tvXor.setText(
                value + " ^ " + key + " = " + enc + "\n" +
                        enc   + " ^ " + key + " = " + dec + "  (decoded)\n" +
                        "key=0  →  error: " + badKey
        );
        Log.i(TAG, "XOR enc=" + enc + " dec=" + dec);

        // ── 3) Caesar Cipher ──────────────────────────────────────
        String original  = "HelloJNI";
        int    shift     = 3;
        String encrypted = caesarCipher(original, shift);
        String decrypted = caesarCipher(encrypted, -shift);

        binding.tvCaesar.setText(
                "Original  : " + original  + "\n" +
                        "Encrypted : " + encrypted + "\n" +
                        "Decrypted : " + decrypted
        );
        Log.i(TAG, "Caesar enc=" + encrypted + " dec=" + decrypted);

        // ── 4) Sum Array ──────────────────────────────────────────
        int[] data   = {10, 20, 30, 40, 50};
        int   sum    = sumArray(data);
        int   nullResult = sumArray(null);

        binding.tvArray.setText(
                "{10, 20, 30, 40, 50}  →  " + sum + "\n" +
                        "null array  →  error: " + nullResult
        );
        Log.i(TAG, "Sum=" + sum);
    }
}