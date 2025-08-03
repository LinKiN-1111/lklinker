#include <jni.h>
#include <string>
#include <android/log.h>

#define  TAG    "linkin"

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,TAG,__VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,TAG,__VA_ARGS__)


extern "C" JNIEXPORT jstring JNICALL
Java_ng1ok_demo1_NativeLib_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}

__attribute__((constructor()))
void sayHello(){
    LOGD("[from libdemo1.so .init_array] Hello~~~");
}


extern "C" {
void _init(void){
    LOGD("[from libdemo1.so .init] _init~~~~");
}
}
