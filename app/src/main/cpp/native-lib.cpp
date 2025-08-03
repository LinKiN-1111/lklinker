#include <jni.h>
#include <string>
#include "log.h"
#include "lkLoader.h"


extern "C" JNIEXPORT jstring JNICALL
Java_com_linkin_lklinker_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}

void sayHello();
extern "C"
JNIEXPORT void JNICALL
Java_com_linkin_lklinker_MainActivity_lk_1load(JNIEnv *env, jobject thiz) {
    // TODO: implement lk_load()
    lkLoader lkLoader;
    LOGD("test start");
    lkLoader.lkload_library("/data/local/tmp/libdemo.so");
//    lkLoader.lkload_library();
    LOGD("test done....");
}