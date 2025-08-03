//
// Created by linkin on 2025/7/29.
//

#ifndef LKLINKER_LOG_H
#define LKLINKER_LOG_H

#include <android/log.h>

#define  TAG    "lklinker"

// 定義info信息

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,TAG,__VA_ARGS__)

// 定義debug信息

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)

// 定義error信息

#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,TAG,__VA_ARGS__)

#endif //LKLINKER_LOG_H
