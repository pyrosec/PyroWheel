# shellcheck disable=SC2034
SKIPUNZIP=1

VERSION=$(grep_prop version "${TMPDIR}/module.prop")
ui_print "- Installing Treat Wheel $VERSION"

if [ "$ARCH" != "arm" ] && [ "$ARCH" != "arm64" ] && [ "$ARCH" != "x86" ] && [ "$ARCH" != "x64" ]; then
  abort "! Unsupported platform: $ARCH"
else
  ui_print "- Device platform: $ARCH"
fi

if [ ! -f "/data/adb/modules/rezygisk/module.prop" ]; then
  abort "! ReZygisk is not installed. This module depends on it."
fi

REZYGISK_VERSION=$(grep_prop versionCode /data/adb/modules/rezygisk/module.prop)
if [ -z "$REZYGISK_VERSION" ]; then
  abort "! Could not determine ReZygisk version."
fi

if [ "$REZYGISK_VERSION" -lt 453 ]; then
  ui_print "! Your ReZygisk version ($REZYGISK_VERSION) is too old."
  abort    "! Please update to version 453 or higher."
fi

abort_verify() {
  ui_print "***********************************************************"
  ui_print "! $1"
  ui_print "! This zip is corrupted or incomplete"
  abort    "***********************************************************"
}

extract() {
  local zip="$1"
  local target="$2"
  local dir="$3"
  local junk_paths="${4:-false}"
  local opts="-o"
  local target_path

  [[ "$junk_paths" == true ]] && opts="-oj"

  if [[ "$target" == */ ]]; then
    target_path="$dir/$(basename "$target")"
    unzip $opts "$zip" "${target}*" -d "$dir" >&2
    [[ -d "$target_path" ]] || abort_verify "$target directory doesn't exist"
  else
    target_path="$dir/$(basename "$file")"
    unzip $opts "$zip" "$target" -d "$dir" >&2
    [[ -f "$target_path" || -d "$target_path" ]] || abort_verify "$target file doesn't exist"
  fi
}

ui_print "- Extracting module files"
extract "$ZIPFILE" 'module.prop'       "$MODPATH"
extract "$ZIPFILE" 'boot-completed.sh' "$MODPATH"
extract "$ZIPFILE" 'sepolicy.rule'     "$MODPATH"

mkdir "$MODPATH/zygisk"
mkdir "$MODPATH/cmd"

if [ "$ARCH" = "x86" ] || [ "$ARCH" = "x64" ]; then
  ui_print "- Extracting x86 libraries"

  extract "$ZIPFILE" 'zygisk/x86/libexample.so' "$MODPATH/zygisk" true
  mv "$MODPATH/zygisk/libexample.so" "$MODPATH/zygisk/x86.so"

  ui_print "- Extracting x64 libraries"

  extract "$ZIPFILE" 'zygisk/x64/libexample.so' "$MODPATH/zygisk" true
  mv "$MODPATH/zygisk/libexample.so" "$MODPATH/zygisk/x86_64.so"

  if [ "$ARCH" = "x86" ]; then
    extract "$ZIPFILE" 'cmd/x86/treat-wheel' "$MODPATH/cmd" true
  else
    extract "$ZIPFILE" 'cmd/x64/treat-wheel' "$MODPATH/cmd" true
  fi
else
  ui_print "- Extracting arm libraries"

  extract "$ZIPFILE" 'zygisk/armeabi-v7a/libexample.so' "$MODPATH/zygisk" true
  mv "$MODPATH/zygisk/libexample.so" "$MODPATH/zygisk/armeabi-v7a.so"

  ui_print "- Extracting arm64 libraries"

  extract "$ZIPFILE" 'zygisk/arm64-v8a/libexample.so' "$MODPATH/zygisk" true
  mv "$MODPATH/zygisk/libexample.so" "$MODPATH/zygisk/arm64-v8a.so"

  if [ "$ARCH" = "arm" ]; then
    extract "$ZIPFILE" 'cmd/armeabi-v7a/treat-wheel' "$MODPATH/cmd" true
  elif [ "$ARCH" = "arm64" ]; then
    extract "$ZIPFILE" 'cmd/arm64-v8a/treat-wheel' "$MODPATH/cmd" true
  fi
fi

ui_print "- Setting permissions"
set_perm_recursive "$MODPATH/zygisk" 0 0 0755 0755
set_perm_recursive "$MODPATH/cmd" 0 0 0755 0755

ui_print "- Extracting WebUI"
unzip -o "$ZIPFILE" "webroot/*" -d "$MODPATH"

if [ ! -d "/data/adb/treat_wheel" ]; then
  mkdir "/data/adb/treat_wheel"

  touch "/data/adb/treat_wheel/state"

  touch "/data/adb/treat_wheel/webui_config"
  echo "disable_fullscreen=false" >> "/data/adb/treat_wheel/webui_config"
fi

echo "disable_revanced_mounts_umount=true" >> "/data/adb/treat_wheel/state"
echo "disable_denylist_logic_inversion=true" >> "/data/adb/treat_wheel/state"

ui_print "- Welcome to Treat Wheel $VERSION"
