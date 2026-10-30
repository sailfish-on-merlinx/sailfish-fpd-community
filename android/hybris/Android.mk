LOCAL_PATH := $(call my-dir)

ANDROID_VERSION_MAJOR := $(word 1, $(subst ., , $(PLATFORM_VERSION)))
ANDROID_VERSION_MINOR := $(word 2, $(subst ., , $(PLATFORM_VERSION)))
ANDROID_VERSION_PATCH := $(word 3, $(subst ., , $(PLATFORM_VERSION)))

ifeq ($(ANDROID_VERSION_MINOR),)
    ANDROID_VERSION_MINOR := 0
endif
ifeq ($(ANDROID_VERSION_PATCH),)
    ANDROID_VERSION_PATCH := 0
endif

IS_ANDROID_8 := $(shell test $(ANDROID_VERSION_MAJOR) -ge 8 && echo true)

ifneq ($(IS_ANDROID_8),true)
$(error "Android pre oreo not supported")
endif

# libbiometry_fp_api carries every backend the Android base can build; which
# one runs is decided on the device (biometry_fp_dispatch.cpp). The base only
# limits what can be compiled: a vendor on an Android 13+ base may still
# publish only the HIDL fingerprint HAL, and AIDL-only vendors exist from
# Android 12.
#
# HIDL backend: android.hardware.biometrics.fingerprint@2.1, Android 8+.
# AIDL backend: android.hardware.biometrics.fingerprint (NDK backend), Android
# 12+, built against the newest frozen version in the tree. AIDL is backward
# compatible and the backend uses only version 1 methods, so it talks to HALs
# of any version.

FP_AIDL_BP := hardware/interfaces/biometrics/fingerprint/aidl/Android.bp
FP_AIDL_API := hardware/interfaces/biometrics/fingerprint/aidl/aidl_api/android.hardware.biometrics.fingerprint
GK_AIDL_BP := hardware/interfaces/gatekeeper/aidl/Android.bp
GK_AIDL_API := hardware/interfaces/gatekeeper/aidl/aidl_api/android.hardware.gatekeeper

# NDK backend libraries were called -ndk_platform on Android 12.
ifeq ($(ANDROID_VERSION_MAJOR),12)
AIDL_NDK := ndk_platform
else
AIDL_NDK := ndk
endif

# Newest frozen version of an interface: the numbered directories in aidl_api.
aidl_latest = $(lastword $(sort $(filter-out current,$(notdir $(wildcard $(1)/*)))))

# Imports of a frozen version, from versions_with_info in its Android.bp
# (e.g. android.hardware.keymaster-V4), so the matching NDK libraries are
# linked: each version of an interface is built against specific versions of
# the ones it imports.
aidl_imports = $(shell awk '/version: "$(2)"/ {f=1} f {l=$$0; while (match(l, /android\.hardware\.[a-z.]+-V[0-9]+/)) {print substr(l, RSTART, RLENGTH); l=substr(l, RSTART+RLENGTH)}} f && /[]}]/ {exit}' $(1) 2>/dev/null)

FP_AIDL_VER := $(if $(shell test $(ANDROID_VERSION_MAJOR) -ge 12 && echo true),$(call aidl_latest,$(FP_AIDL_API)))
GK_AIDL_VER := $(if $(FP_AIDL_VER),$(call aidl_latest,$(GK_AIDL_API)))

include $(CLEAR_VARS)

LOCAL_MODULE := libbiometry_fp_api
LOCAL_MODULE_TAGS := optional

LOCAL_CFLAGS += \
	-DANDROID_VERSION_MAJOR=$(ANDROID_VERSION_MAJOR) \
	-DANDROID_VERSION_MINOR=$(ANDROID_VERSION_MINOR) \
	-DANDROID_VERSION_PATCH=$(ANDROID_VERSION_PATCH) \
	-DBIOMETRY_HAVE_HIDL \
	-Wno-unused-parameter

UPAPI_PATH := $(LOCAL_PATH)/../../

LOCAL_C_INCLUDES := \
	$(UPAPI_PATH)/src

LOCAL_SRC_FILES := \
	biometry_fp_dispatch.cpp \
	biometry_gatekeeper.cpp \
	biometry_fp_hidl_for_hybris.cpp

LOCAL_HEADER_LIBRARIES := libhardware_headers

LOCAL_SHARED_LIBRARIES := \
	libcutils \
	liblog \
	libutils \
	libhidlbase \
	android.hardware.biometrics.fingerprint@2.1 \
	android.hardware.gatekeeper@1.0

# libhidltransport was folded into libhidlbase; later trees keep only a stub.
ifneq ($(shell test $(ANDROID_VERSION_MAJOR) -ge 11 && echo true),true)
LOCAL_SHARED_LIBRARIES += libhidltransport
endif

ifneq ($(FP_AIDL_VER),)
FP_AIDL_IMPORTS := $(call aidl_imports,$(FP_AIDL_BP),$(FP_AIDL_VER))
# Trees without versions_with_info (Android 12): the imports of versions 1..4.
ifeq ($(FP_AIDL_IMPORTS),)
FP_AIDL_IMPORTS := \
	android.hardware.biometrics.common-V$(FP_AIDL_VER) \
	android.hardware.keymaster-V$(if $(filter 1 2,$(FP_AIDL_VER)),3,4)
endif
$(info libbiometry_fp_api: AIDL fingerprint V$(FP_AIDL_VER) ($(FP_AIDL_IMPORTS)))
LOCAL_CFLAGS += -DBIOMETRY_HAVE_AIDL
LOCAL_SRC_FILES += biometry_fp_aidl_for_hybris.cpp
LOCAL_SHARED_LIBRARIES += \
	libbinder_ndk \
	android.hardware.biometrics.fingerprint-V$(FP_AIDL_VER)-$(AIDL_NDK) \
	$(addsuffix -$(AIDL_NDK),$(FP_AIDL_IMPORTS))
endif

ifneq ($(GK_AIDL_VER),)
GK_AIDL_IMPORTS := $(call aidl_imports,$(GK_AIDL_BP),$(GK_AIDL_VER))
$(info libbiometry_fp_api: AIDL gatekeeper V$(GK_AIDL_VER) ($(GK_AIDL_IMPORTS)))
LOCAL_CFLAGS += -DBIOMETRY_HAVE_AIDL_GATEKEEPER
LOCAL_SHARED_LIBRARIES += \
	android.hardware.gatekeeper-V$(GK_AIDL_VER)-$(AIDL_NDK) \
	$(filter-out $(LOCAL_SHARED_LIBRARIES),$(addsuffix -$(AIDL_NDK),$(GK_AIDL_IMPORTS)))
endif

include $(BUILD_SHARED_LIBRARY)
