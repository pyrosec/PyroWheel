BUILD_PATH = ../build/src
ZYGISK_PATH = $(BUILD_PATH)/zygisk

CFILES_ZYGISK = src/hiding.c src/main.c src/utils.c

CFLAGS = -llog -fvisibility=hidden -fvisibility-inlines-hidden -Wpedantic     \
         -Wall -Wextra -Werror -Wformat -Wuninitialized -Wshadow -std=c99     \
         -Isrc/external/include -Wno-unused-function -D_GNU_SOURCE -fPIC      \
         -Wno-gnu-zero-variadic-macro-arguments -Ied25519 -Wno-c2x-extensions \
		 -Wno-gnu-statement-expression-from-macro-expansion

ifeq ($(IS_GITHUB_ACTION),true)
	CC := $(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin/clang
	STRIP := $(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip
	CLANG := $(CC)
	OBF_FLAGS :=
else
	CC := $(ANDROID_HOME)/ndk/27.0.12077973/toolchains/llvm/prebuilt/linux-x86_64/bin/clang
	STRIP := $(ANDROID_HOME)/ndk/27.0.12077973/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip
	CLANG := $(CC)
	OBF_FLAGS := 
endif

MKDIR_CMD = mkdir -p 
MKDIR_FINAL = > /dev/null

RM_TW = rm -rf ../build/TreatWheel.zip
ZIP_CMD = (cd ../build/src/ && zip -r ../TreatWheel.zip .) > /dev/null

all: CFLAGS += -DADDITIONAL_DESCRIPTION="$$ADDITIONAL_DESCRIPTION" -flto=full -s -Wl,--strip-all -Wl,--exclude-libs,ALL -Wl,--as-needed 
all: CFLAGS += $(OBF_FLAGS)
all: build

build:
	@echo Creating zygisk directories...
	@$(MKDIR_CMD)$(BUILD_PATH)$(MKDIR_FINAL)
	@$(MKDIR_CMD)$(ZYGISK_PATH)$(MKDIR_FINAL)
	@$(MKDIR_CMD)$(ZYGISK_PATH)/arm64-v8a$(MKDIR_FINAL)
	@$(MKDIR_CMD)$(ZYGISK_PATH)/armeabi-v7a$(MKDIR_FINAL)
	@$(MKDIR_CMD)$(ZYGISK_PATH)/x64$(MKDIR_FINAL)
	@$(MKDIR_CMD)$(ZYGISK_PATH)/x86$(MKDIR_FINAL)

	@echo Compiling zygisk module...
	@$(CLANG) --target=aarch64-linux-android34    -fPIC -DIS_ZYGISK_LIB $(CFILES_ZYGISK) $(CFLAGS) -nostartfiles -shared -o $(ZYGISK_PATH)/arm64-v8a/libexample.so
	@$(CLANG) --target=armv7a-linux-androideabi34 -fPIC -DIS_ZYGISK_LIB $(CFILES_ZYGISK) $(CFLAGS) -nostartfiles -shared -o $(ZYGISK_PATH)/armeabi-v7a/libexample.so
	@$(CLANG) --target=x86_64-linux-android34     -fPIC -DIS_ZYGISK_LIB $(CFILES_ZYGISK) $(CFLAGS) -nostartfiles -shared -o $(ZYGISK_PATH)/x64/libexample.so
	@$(CLANG) --target=i686-linux-android34       -fPIC -DIS_ZYGISK_LIB $(CFILES_ZYGISK) $(CFLAGS) -nostartfiles -shared -o $(ZYGISK_PATH)/x86/libexample.so

	@echo Stripping zygisk module...
	@$(STRIP) --strip-all $(ZYGISK_PATH)/arm64-v8a/libexample.so
	@$(STRIP) --strip-all $(ZYGISK_PATH)/armeabi-v7a/libexample.so
	@$(STRIP) --strip-all $(ZYGISK_PATH)/x64/libexample.so
	@$(STRIP) --strip-all $(ZYGISK_PATH)/x86/libexample.so
	@echo Copying module.prop file...
	@cp $(BUILD_PATH)/../module.prop $(BUILD_PATH)/module.prop

	@echo Creating zip...

	@rm -rf $(BUILD_PATH)/webroot
	@cp -r webroot $(BUILD_PATH)

	@$(RM_TW)
	@$(ZIP_CMD)
