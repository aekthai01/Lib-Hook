LOCAL_PATH := $(call my-dir)

# ══════════════════════════════════════════════════════════════
# §1  PREBUILT STATIC LIBRARY (DOBBY)
# ══════════════════════════════════════════════════════════════
include $(CLEAR_VARS)
LOCAL_MODULE := dobby
LOCAL_SRC_FILES := Dobby/$(TARGET_ARCH_ABI)/libdobby.a
include $(PREBUILT_STATIC_LIBRARY)

# ══════════════════════════════════════════════════════════════
# §2  MAIN SHARED LIBRARY (URLHOOK)
# ══════════════════════════════════════════════════════════════
include $(CLEAR_VARS)
LOCAL_MODULE := urlhook
LOCAL_SRC_FILES := Main.cpp Check.cpp

LOCAL_C_INCLUDES := $(LOCAL_PATH)/Dobby $(LOCAL_PATH)
LOCAL_CPP_EXTENSION := .cpp .cc

LOCAL_CFLAGS := -std=c++11 -O2 -Wno-error=format-security -fvisibility=hidden -ffunction-sections -fdata-sections -w
LOCAL_CPPFLAGS := -std=c++11 -O2 -fvisibility=hidden -w
LOCAL_LDLIBS := -llog -ldl
LOCAL_LDFLAGS := -Wl,--gc-sections -Wl,--strip-all

LOCAL_ARM_MODE := arm
LOCAL_STATIC_LIBRARIES := dobby

include $(BUILD_SHARED_LIBRARY)
