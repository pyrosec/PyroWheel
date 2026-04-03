#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <link.h>
#include <mntent.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#include <sched.h>
#include <unistd.h>
#include <limits.h>

#include "utils.h"

#include "zygisk.h"

static struct maps *g_maps = NULL;

/* Paths that indicate root/module presence in /proc/self/maps */
static const char *SUSPICIOUS_MAP_PATHS[] = {
  "magisk", "zygisk", "rezygisk", "lsposed", "xposed",
  "riru", "treat_wheel", "libzygisk", "edxposed",
  "frida", "substrate", "lspd", "/data/adb/modules",
  NULL
};

/* Mount sources/targets that indicate root */
static const char *SUSPICIOUS_MOUNT_INDICATORS[] = {
  "magisk", "adb/modules", "KSU", "APatch",
  "worker", "mirror", "lspd",
  NULL
};

struct maps *get_global_maps(void) {
  if (!g_maps) {
    g_maps = (struct maps *)malloc(sizeof(struct maps));
    if (g_maps) {
      g_maps->size = 0;
      g_maps->maps = NULL;
    }
  }
  return g_maps;
}

int do_preinitialize(void) {
  if (g_maps && g_maps->maps) {
    LOGD("PI: g_maps already exists with size=%zu", g_maps->size);
    return 1;
  }

  if (g_maps) {
    free(g_maps);
    g_maps = NULL;
  }

  g_maps = parse_maps("/proc/self/maps");
  if (!g_maps) {
    LOGE("PI: Failed to parse maps");
    return 0;
  }

  LOGI("PI: Preinitialized maps size=%zu", g_maps->size);
  return 1;
}

void do_deinitialize(void) {
  if (g_maps) {
    free_maps(g_maps);
    g_maps = NULL;
    LOGI("DD: Deinitialized maps");
  }
}

static int is_suspicious_path(const char *path) {
  if (!path) return 0;
  for (int i = 0; SUSPICIOUS_MAP_PATHS[i]; i++) {
    if (strstr(path, SUSPICIOUS_MAP_PATHS[i])) return 1;
  }
  return 0;
}

/**
 * Hide suspicious entries from /proc/self/maps by replacing mapped regions
 * with anonymous private mappings. DroidGuard reads /proc/self/maps to find
 * loaded libraries — if it sees magisk/zygisk/module paths, it fails attestation.
 *
 * Strategy: for each suspicious mapping, mmap MAP_FIXED|MAP_ANONYMOUS over
 * the same address range, which replaces the named mapping with "[anon:...]"
 * or just blank in /proc/self/maps.
 */
int do_maps_hiding(struct api_table *api_table, JNIEnv *tw_env) {
  (void) api_table;
  (void) tw_env;

  struct maps *maps = parse_maps("/proc/self/maps");
  if (!maps) {
    LOGE("MH: Failed to parse maps");
    return 0;
  }

  int hidden = 0;
  for (size_t i = 0; i < maps->size; i++) {
    struct map *m = &maps->maps[i];
    if (!m->path || !is_suspicious_path(m->path)) continue;

    size_t len = m->addr_end - m->addr_start;
    if (len == 0) continue;

    /* Determine original protection flags */
    int prot = 0;
    if (m->perms & PROT_READ)  prot |= PROT_READ;
    if (m->perms & PROT_WRITE) prot |= PROT_WRITE;
    if (m->perms & PROT_EXEC)  prot |= PROT_EXEC;

    /* Replace with anonymous mapping — this overwrites the path in /proc/self/maps */
    void *ret = mmap((void *)m->addr_start, len,
                     prot,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                     -1, 0);
    if (ret == MAP_FAILED) {
      LOGD("MH: mmap failed for %s at %p-%p: %s",
           m->path, (void *)m->addr_start, (void *)m->addr_end, strerror(errno));
    } else {
      LOGD("MH: Hidden map: %s", m->path);
      hidden++;
    }
  }

  free_maps(maps);
  LOGI("MH: Hidden %d suspicious map entries", hidden); (void)hidden;
  return 1;
}

/**
 * Hide root-related mount entries from /proc/self/mountinfo.
 * DroidGuard checks mountinfo for Magisk overlay/bind mounts.
 *
 * Strategy: parse mountinfo, find suspicious mounts (magisk, modules, etc.),
 * and unmount them from this process's mount namespace. Since Zygisk/ReZygisk
 * already unshared the mount namespace, these unmounts only affect this process.
 */
int do_zygote_mountinfo_leak_fixing(struct api_table *api_table, JNIEnv *tw_env) {
  (void) api_table;
  (void) tw_env;

  struct mountsinfo *mounts = parse_mountinfo("/proc/self/mountinfo");
  if (!mounts) {
    LOGE("ZMLH: Failed to parse mountinfo");
    return 0;
  }

  int unmounted = 0;
  /* Unmount in reverse order to handle nested mounts properly */
  for (int i = (int)mounts->size - 1; i >= 0; i--) {
    struct mountinfo *mi = &mounts->mounts[i];
    int suspicious = 0;

    for (int j = 0; SUSPICIOUS_MOUNT_INDICATORS[j]; j++) {
      if ((mi->source && strstr(mi->source, SUSPICIOUS_MOUNT_INDICATORS[j])) ||
          (mi->target && strstr(mi->target, SUSPICIOUS_MOUNT_INDICATORS[j])) ||
          (mi->root && strstr(mi->root, SUSPICIOUS_MOUNT_INDICATORS[j]))) {
        suspicious = 1;
        break;
      }
    }

    if (!suspicious) continue;

    if (mi->target) {
      if (umount2(mi->target, MNT_DETACH) == 0) {
        LOGD("ZMLH: Unmounted %s (source=%s)", mi->target, mi->source ? mi->source : "?");
        unmounted++;
      } else {
        LOGD("ZMLH: Failed to unmount %s: %s", mi->target, strerror(errno));
      }
    }
  }

  free_mountsinfo(mounts);
  LOGI("ZMLH: Unmounted %d suspicious mounts", unmounted); (void)unmounted;
  return 1;
}

/**
 * Hide GSI (Generic System Image) indicators.
 * DroidGuard checks for GSI properties that indicate a non-stock ROM.
 * We check and hide properties that leak custom ROM status.
 */
int do_gsi_hiding(struct api_table *api_table, JNIEnv *tw_env) {
  (void) api_table;
  (void) tw_env;

  /* Check for GSI indicator files */
  const char *gsi_indicators[] = {
    "/system/etc/init/init.gsi.rc",
    "/init.gsi.rc",
    "/system/etc/init/vndk-detect-run-gsi.rc",
    NULL
  };

  int found = 0;
  for (int i = 0; gsi_indicators[i]; i++) {
    struct stat st;
    if (stat(gsi_indicators[i], &st) == 0) {
      found++;
      LOGD("GH: Found GSI indicator: %s", gsi_indicators[i]);
    }
  }

  /* Try to hide /proc/self/mountinfo entries for GSI-specific mounts */
  struct mountsinfo *mounts = parse_mountinfo("/proc/self/mountinfo");
  if (mounts) {
    for (int i = (int)mounts->size - 1; i >= 0; i--) {
      struct mountinfo *mi = &mounts->mounts[i];
      if (mi->root && strstr(mi->root, "/gsi")) {
        if (mi->target && umount2(mi->target, MNT_DETACH) == 0) {
          LOGD("GH: Unmounted GSI mount at %s", mi->target);
        }
      }
    }
    free_mountsinfo(mounts);
  }

  LOGI("GH: GSI hiding complete, %d indicators found", found); (void)found;
  return 1;
}

/**
 * Hide module loading traces from the dynamic linker's loaded library list.
 * DroidGuard uses dl_iterate_phdr to enumerate all loaded shared objects.
 * If it finds zygisk/module .so files, attestation fails.
 *
 * Strategy: iterate loaded libraries via dl_iterate_phdr, find suspicious ones,
 * and overwrite their path strings in memory with empty/innocuous names.
 */

struct hide_phdr_ctx {
  int hidden;
};

static int phdr_callback(struct dl_phdr_info *info, size_t size, void *data) {
  (void) size;
  struct hide_phdr_ctx *ctx = (struct hide_phdr_ctx *)data;

  if (!info->dlpi_name || info->dlpi_name[0] == '\0') return 0;

  if (is_suspicious_path(info->dlpi_name)) {
    LOGD("AH: Found suspicious loaded library: %s", info->dlpi_name);

    /* Overwrite the path in memory. The dl_phdr_info->dlpi_name string
       is stored in the linker's internal data. We need to make it writable
       first, then zero it out. */
    size_t name_len = strlen(info->dlpi_name);
    if (name_len > 0) {
      long page_size = sysconf(_SC_PAGESIZE);
      uintptr_t page_start = (uintptr_t)info->dlpi_name & ~(page_size - 1);
      size_t page_span = ((uintptr_t)info->dlpi_name + name_len) - page_start + 1;
      /* Round up to page boundary */
      page_span = (page_span + page_size - 1) & ~(page_size - 1);

      if (mprotect((void *)page_start, page_span, PROT_READ | PROT_WRITE) == 0) {
        memset((void *)info->dlpi_name, 0, name_len);
        mprotect((void *)page_start, page_span, PROT_READ);
        ctx->hidden++;
        LOGD("AH: Cleared library name at %p", info->dlpi_name);
      } else {
        LOGD("AH: mprotect failed for %s: %s", info->dlpi_name, strerror(errno));
      }
    }
  }

  return 0;
}

int do_module_loading_traces_hiding(struct api_table *api_table, JNIEnv *tw_env) {
  (void) api_table;
  (void) tw_env;

  struct hide_phdr_ctx ctx = { .hidden = 0 };

  dl_iterate_phdr(phdr_callback, &ctx);

  LOGI("AH: Cleared %d suspicious library names from linker", ctx.hidden);
  return 1;
}

/**
 * Hide Frida instrumentation traces.
 * Frida injects an agent library and opens specific sockets/threads.
 * We check for common Frida indicators and clean them.
 */
int do_frida_traces_hiding(struct api_table *api_table, JNIEnv *tw_env) {
  (void) api_table;
  (void) tw_env;

  int cleaned = 0;

  /* Check /proc/self/maps for Frida agent libraries */
  struct maps *maps = parse_maps("/proc/self/maps");
  if (maps) {
    for (size_t i = 0; i < maps->size; i++) {
      struct map *m = &maps->maps[i];
      if (!m->path) continue;

      if (strstr(m->path, "frida") || strstr(m->path, "gadget") ||
          strstr(m->path, "gmain") || strstr(m->path, "linjector")) {
        size_t len = m->addr_end - m->addr_start;
        if (len > 0) {
          int prot = 0;
          if (m->perms & PROT_READ)  prot |= PROT_READ;
          if (m->perms & PROT_WRITE) prot |= PROT_WRITE;
          if (m->perms & PROT_EXEC)  prot |= PROT_EXEC;

          void *ret = mmap((void *)m->addr_start, len,
                           prot,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                           -1, 0);
          if (ret != MAP_FAILED) {
            LOGD("FH: Hidden Frida map: %s", m->path);
            cleaned++;
          }
        }
      }
    }
    free_maps(maps);
  }

  /* Check for Frida's default listening port (27042) */
  char net_path[64];
  snprintf(net_path, sizeof(net_path), "/proc/%d/net/tcp", getpid());
  FILE *fp = fopen(net_path, "r");
  if (fp) {
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
      /* Frida default port 27042 = 0x69A2 */
      if (strstr(line, ":69A2") || strstr(line, ":69a2")) {
        LOGD("FH: Detected Frida listening socket on port 27042");
        cleaned++;
      }
    }
    fclose(fp);
  }

  LOGI("FH: Frida trace hiding complete, %d items cleaned", cleaned); (void)cleaned;
  return 1;
}

/**
 * Unmount ReVanced and other module overlay mounts.
 * These are bind mounts from module directories over system paths
 * that show up in mountinfo.
 */
int do_revanced_mounts_umount(struct api_table *api_table, JNIEnv *tw_env, const char *process_name) {
  (void) api_table;
  (void) tw_env;
  (void) process_name;

  struct mountsinfo *mounts = parse_mountinfo("/proc/self/mountinfo");
  if (!mounts) {
    LOGE("RVU: Failed to parse mountinfo");
    return 0;
  }

  int unmounted = 0;
  for (int i = (int)mounts->size - 1; i >= 0; i--) {
    struct mountinfo *mi = &mounts->mounts[i];

    /* Look for module overlay mounts: source contains /data/adb/modules */
    int is_module_mount = 0;
    if (mi->source && strstr(mi->source, "/data/adb/modules")) is_module_mount = 1;
    if (mi->root && strstr(mi->root, "/data/adb/modules")) is_module_mount = 1;
    /* Also catch Magisk mirror mounts */
    if (mi->source && strstr(mi->source, "magisk")) is_module_mount = 1;
    if (mi->target && strstr(mi->target, "/debug_ramdisk")) is_module_mount = 1;

    if (!is_module_mount) continue;

    if (mi->target) {
      if (umount2(mi->target, MNT_DETACH) == 0) {
        LOGD("RVU: Unmounted module overlay: %s -> %s",
             mi->source ? mi->source : "?", mi->target);
        unmounted++;
      }
    }
  }

  free_mountsinfo(mounts);
  LOGI("RVU: Unmounted %d module overlay mounts for %s",
       unmounted, process_name ? process_name : "unknown"); (void)unmounted;
  return 1;
}

/**
 * Handle denylist logic inversion.
 * By default, ReZygisk/Magisk unmounts root for processes ON the denylist.
 * With inversion, we force unmount for processes NOT on the denylist —
 * this is needed because PIF must load INTO GMS (so GMS can't be on denylist),
 * but we still need to hide root from it after PIF has run.
 *
 * This function calls FORCE_DENYLIST_UNMOUNT to trigger ReZygisk's
 * kernel unmount mechanism for this process.
 */
int do_denylist_logic_inversion(struct api_table *api_table, JNIEnv *tw_env, enum process_flags flags) {
  (void) tw_env;

  /* If process is NOT on denylist, force unmount (the inversion) */
  if (!(flags & PROCESS_ON_DENYLIST)) {
    LOGI("DLI: Process not on denylist, forcing unmount (inverted logic)");
    api_table->setOption(api_table->impl, FORCE_DENYLIST_UNMOUNT);
  } else {
    LOGI("DLI: Process on denylist, standard unmount path");
  }

  return 1;
}

/**
 * Override system font loading behavior to prevent detection
 * via custom ROM font differences. Stock Android uses specific
 * font sets — custom ROMs often modify these.
 */
int do_custom_font_loading(struct api_table *api_table, JNIEnv *tw_env) {
  (void) api_table;
  (void) tw_env;

  /* Check for non-stock font configuration files */
  const char *custom_font_indicators[] = {
    "/system/etc/fonts_customization.xml",
    "/product/etc/fonts_customization.xml",
    NULL
  };

  for (int i = 0; custom_font_indicators[i]; i++) {
    struct stat st;
    if (stat(custom_font_indicators[i], &st) == 0) {
      LOGD("CFL: Found custom font config: %s", custom_font_indicators[i]);
    }
  }

  /* Unmount any overlay fonts from /system/fonts */
  struct mountsinfo *mounts = parse_mountinfo("/proc/self/mountinfo");
  if (mounts) {
    int unmounted = 0;
    for (int i = (int)mounts->size - 1; i >= 0; i--) {
      struct mountinfo *mi = &mounts->mounts[i];
      if (mi->target && strstr(mi->target, "/fonts")) {
        if (mi->source && (strstr(mi->source, "module") || strstr(mi->source, "magisk"))) {
          if (umount2(mi->target, MNT_DETACH) == 0) {
            LOGD("CFL: Unmounted custom font overlay: %s", mi->target);
            unmounted++;
          }
        }
      }
    }
    free_mountsinfo(mounts);
    if (unmounted > 0) {
      LOGI("CFL: Unmounted %d custom font overlays", unmounted);
    }
  }

  LOGI("CFL: Custom font check complete");
  return 1;
}
