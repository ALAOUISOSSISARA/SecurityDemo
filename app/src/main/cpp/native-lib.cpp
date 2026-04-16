#include <jni.h>
#include <string>
#include <algorithm>
#include <climits>
#include <android/log.h>

#define LOG_TAG "SECURITY_DEMO"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ─────────────────────────────────────────────────────────────────
// 1) Native Fingerprint (version avancée de helloFromJNI)
// ─────────────────────────────────────────────────────────────────
extern "C" JNIEXPORT jstring JNICALL
Java_com_cryptovault_jni_MainActivity_getNativeFingerprint(
        JNIEnv* env, jobject) {
    LOGI("getNativeFingerprint called");
    return env->NewStringUTF("SECURE::NATIVE::v1.0");
}

// ─────────────────────────────────────────────────────────────────
// 2) XOR Cipher (version avancée de factorial)
// ─────────────────────────────────────────────────────────────────
extern "C" JNIEXPORT jint JNICALL
Java_com_cryptovault_jni_MainActivity_xorEncrypt(
        JNIEnv* env, jobject, jint value, jint key) {
    if (key == 0) {
        LOGE("Invalid key: 0");
        return -1;
    }
    int result = value ^ key;
    LOGI("XOR: %d ^ %d = %d", value, key, result);
    return static_cast<jint>(result);
}

// ─────────────────────────────────────────────────────────────────
// 3) Caesar Cipher (version avancée de reverseString)
// ─────────────────────────────────────────────────────────────────
extern "C" JNIEXPORT jstring JNICALL
Java_com_cryptovault_jni_MainActivity_caesarCipher(
        JNIEnv* env, jobject, jstring javaString, jint shift) {
    if (javaString == nullptr) {
        LOGE("Null string received");
        return env->NewStringUTF("Error: null string");
    }

    const char* chars = env->GetStringUTFChars(javaString, nullptr);
    if (chars == nullptr) {
        LOGE("Cannot read Java string");
        return env->NewStringUTF("Error: JNI read failed");
    }

    std::string s(chars);
    env->ReleaseStringUTFChars(javaString, chars);

    // Normalise le shift (supporte valeurs négatives aussi)
    int normalizedShift = ((shift % 26) + 26) % 26;

    for (char& c : s) {
        if (c >= 'a' && c <= 'z')
            c = 'a' + (c - 'a' + normalizedShift) % 26;
        else if (c >= 'A' && c <= 'Z')
            c = 'A' + (c - 'A' + normalizedShift) % 26;
    }

    LOGI("Caesar cipher (shift=%d) result: %s", shift, s.c_str());
    return env->NewStringUTF(s.c_str());
}

// ─────────────────────────────────────────────────────────────────
// 4) Sum Array avec overflow check (identique au prof + amélioré)
// ─────────────────────────────────────────────────────────────────
extern "C" JNIEXPORT jint JNICALL
Java_com_cryptovault_jni_MainActivity_sumArray(
        JNIEnv* env, jobject, jintArray array) {
    if (array == nullptr) {
        LOGE("Null array received");
        return -1;
    }

    jsize len = env->GetArrayLength(array);
    jint* elements = env->GetIntArrayElements(array, nullptr);

    if (elements == nullptr) {
        LOGE("Cannot access array elements");
        return -2;
    }

    long long sum = 0;
    for (jsize i = 0; i < len; i++) {
        sum += elements[i];
    }

    env->ReleaseIntArrayElements(array, elements, 0);

    if (sum > INT_MAX) {
        LOGE("Overflow detected on sum");
        return -3;
    }

    LOGI("Array sum = %lld", sum);
    return static_cast<jint>(sum);
}