#pragma once
#include <cstdint>
#include <jni.h>

extern JavaVM* g_vm;

namespace Check {

    void InitLogging();
void StartWatcher(JavaVM* vm); 
    bool RunAll(JavaVM* vm); 
    

} 
