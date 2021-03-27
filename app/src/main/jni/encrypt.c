// Created by jiangwei1-g on 2016/5/23.
#include "encrypt.h"
#include <jni.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <dlfcn.h>

const int handledSignals[] = {SIGSEGV, SIGABRT, SIGFPE, SIGILL, SIGBUS};
const int handledSignalsNum = sizeof(handledSignals) / sizeof(handledSignals[0]);
struct sigaction old_handlers[sizeof(handledSignals) / sizeof(handledSignals[0])];

int getTraceId();

JNIEXPORT jlong JNICALL ptrace_self(JNIEnv *env, jobject obj);

void my_sigaction(int signal, siginfo_t *info, void *reserved) {
    LOGD("signal:%d", signal);
}

char key_src[] = {'z', 'y', 't', 'y', 'r', 'T', 'R', 'A', '*', 'B', 'n', 'i', 'q', 'C', 'P', 'p',
                  'V', 's'};

static int is_trace_on = 0;

int is_number(const char *src) {
    if (src == NULL) {
        return 0;
    }
    while (*src != '\0') {
        if (*src < 48 || *src > 57) {
            return 0;
        }
        src++;
    }
    return 1;
}

char *get_encrypt_str(const char *src) {
    if (src == NULL) {
        return NULL;
    }
    int len = strlen(src);
    len++;
    char *dest = (char *) malloc(len * sizeof(char));
    char *head = dest;
    char *tmp = (char *) src;
    int i = 0;
    int key_len = 18;
    for (; i < len; i++) {
        int index = (*tmp) - 48;
        if (index == 0) {
            index = 1;
        }
        *dest = key_src[key_len - index];
        tmp++;
        dest++;
    }
    dest++;
    *dest = '\0';
    return head;
}

JNIEXPORT jint JNICALL getTraceId_(JNIEnv *env, jobject obj) {
    return getTraceId();
}

JNIEXPORT jboolean JNICALL jiangwei(JNIEnv *env, jobject obj, jstring str) {
    LOGD("JNIEnv1:%p", env);
    const char *strAry = (*env)->GetStringUTFChars(env, str, 0);
    int len = strlen(strAry);
    char *dest = (char *) malloc(len);
    strcpy(dest, strAry);

    int number = is_number(strAry);
    if (number == 0) {
        return 0;
    }

    char *encry_str = get_encrypt_str(strAry);
    const char *pas = "ssBCqpBssP";
    int result = strcmp(pas, encry_str);

    (*env)->ReleaseStringUTFChars(env, str, strAry);

    if (result == 0) {
        return 1;
    } else {
        return 0;
    }

}

pthread_t t_id;


int getTraceId() {
    int pid = getpid();
    char file_name[20] = {'\0'};
    sprintf(file_name, "/proc/%d/status", pid);
    char linestr[256];
    int traceid = -1;
    FILE *fp;
    fp = fopen(file_name, "r");
    if (fp == NULL) {
        return traceid;
    }
    while (!feof(fp)) {
        fgets(linestr, 256, fp);
        if (strstr(linestr, "TracerPid:")) {
            traceid = atoi(linestr + 10);
            return traceid;
        }
    }
    fclose(fp);
    return traceid;
}


void anti_debug() {
    pid_t child;
    child = fork();
    if (child)
        wait(NULL);
    else {
        pid_t parent = getppid();
        if (ptrace(PTRACE_ATTACH, parent, 0, 0) < 0)
            while (1);
        sleep(1);
        ptrace(PTRACE_DETACH, parent, 0, 0);
        exit(0);
    }
}


//开启循环轮训检查TracePid字段
void thread_fuction() {
    int traceid;
    is_trace_on = 1;
    while (1) {
        traceid = getTraceId();
        if (traceid > 0) {
            LOGD("I was be traced...trace pid:%d", traceid);
            exit(0);
        }
        sleep(5);
    }
}

//检测自己有没有被trace
JNIEXPORT void JNICALL create_thread_check_traceid(JNIEnv *env, jobject obj) {
    if (is_trace_on)
        return;
    int err = pthread_create(&t_id, NULL, thread_fuction, NULL);
    if (err != 0) {
        is_trace_on = 0;
        LOGD("create thread fail: %s\n", strerror(err));
    }
}

/**
 * 签名校验函数
 */
const char *app_signature = "3082030d308201f5a00302010202044054662e300d...";

int equal_sign(JNIEnv *env) {
    //调用Java层的Utils中的获取签名的方法
    char *className = "cn/wjdiankong/encryptdemo/Utils";
    jclass clazz = (*env)->FindClass(env, className);
    if (clazz == NULL) {
        LOGD("not find class '%s'", className);
        return 1;
    }

    LOGD("class name:%p", clazz);

    jmethodID method = (*env)->GetStaticMethodID(env, clazz, "getSignature",
                                                 "()Ljava/lang/String;");
    if (method == NULL) {
        LOGD("not find method '%s'", method);
        return 1;
    }

    jstring obj = (jstring) (*env)->CallStaticObjectMethod(env, clazz, method);
    if (obj == NULL) {
        LOGD("method invoke error:%p", obj);
        return 1;
    }

    const char *strAry = (*env)->GetStringUTFChars(env, obj, 0);
    int cmpval = strcmp(strAry, app_signature);
    if (cmpval == 0) {
        return 1;
    }
    (*env)->ReleaseStringUTFChars(env, obj, strAry);
    return 0;
}

//定义目标类名称
static const char *className = "qing/risk/detection/MainActivity";

//定义方法隐射关系
static JNINativeMethod methods[] = {
        {"isEquals",   "(Ljava/lang/String;)Z", (void *) jiangwei},
        {"traceCheck", "()V",                   (void *) create_thread_check_traceid},
        {"ptraceSelf", "()J",                   (void *) ptrace_self},
        {"getTraceId", "()I",                   (void *) getTraceId_},
};

JNIEXPORT jlong JNICALL ptrace_self(JNIEnv *env, jobject obj) {
    //自己附加
    long res = ptrace(PTRACE_TRACEME, 0, 0, 0);
    if (res >= 0) {
        LOGD("ptrace myself...%ld", res);
        return res;
    } else {
        anti_debug();
        return 1;
    }

}
 int (*libc_system_property_get)(const char*, char*);
jint JNI_OnLoad(JavaVM *vm, void *reserved) {

    char dst[]="/data/local/temp/dexinfo";
    FILE *fp = fopen(dst, "a+");
    if(fp!=NULL){
        fprintf(fp,"%s|%s\n","/data/data/qing.demo/1223.dump","base.apk");
        fclose(fp);
    }
    LOGD("JNI on load...");
    libc_system_property_get = dlsym(RTLD_DEFAULT, "__system_property_get");
    char temp[128];
    int res = libc_system_property_get("ro.debuggable",temp);
    //声明变量
    jint result = JNI_ERR;
    JNIEnv *env = NULL;
    jclass clazz;
    int methodsLenght;
    //获取JNI环境对象
    if ((*vm)->GetEnv(vm, (void **) &env, JNI_VERSION_1_4) != JNI_OK) {
        LOGD("ERROR: GetEnv failed\n");
        return JNI_ERR;
    }

    //签名校验
    /* LOGD("JNIEnv:%p", env);
     LOGD("start equal signature...");
     int check_sign = equal_sign(env);
     LOGD("check_sign:%d", check_sign);
     if(check_sign == 0){
         exit(0);
     }*/

    //注册本地方法.Load 目标类
    clazz = (*env)->FindClass(env, className);
    if (clazz == NULL) {
        LOGD("Native registration unable to find class '%s'", className);
        return JNI_ERR;
    }


    methodsLenght = sizeof(methods) / sizeof(methods[0]);
    if ((*env)->RegisterNatives(env, clazz, methods, methodsLenght) < 0) {
        LOGD("RegisterNatives failed for '%s'", className);
        return JNI_ERR;
    }

    result = JNI_VERSION_1_4;
    return result;
}

//onUnLoad方法，在JNI组件被释放时调用
void JNI_OnUnload(JavaVM *vm, void *reserved) {
    LOGD("JNI unload...");
}
