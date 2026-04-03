#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <time.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/socket.h>

#include <sched.h>
#include <unistd.h>
#include <pthread.h>

#include <jni.h>

#include "utils.h"
#include "hiding.h"

#include "zygisk.h"

struct api_table *api_table;
JNIEnv *tw_env;

/* INFO: Global variables, the same for all processes */
void *rz_base = NULL;
dev_t rz_dev;
ino_t rz_ino;

struct tw_mem_info tw_info;

/* INFO: Process specific variables */
uint32_t flags = 0;

int cfd = -1;
struct module_state g_state = { 0 };

int my_munmap(void *addr, size_t length) {
  if (addr == rz_base) {
    LOGD("munmap: dladdr failed, found ReZygisk's library");

    /* INFO: Hiding code START - must run BEFORE unmapping libzygisk.so */
    if (g_state.is_ignoring) {
      LOGD("Module is set to be ignoring, nothing to do in deconstruction.");

      goto finish_hiding_post;
    }

    if (!(((flags & PROCESS_ON_DENYLIST) == PROCESS_ON_DENYLIST && g_state.disable_denylist_logic_inversion) || 
        ((flags & PROCESS_ON_DENYLIST) != PROCESS_ON_DENYLIST && !g_state.disable_denylist_logic_inversion))) {
      LOGD("Process not on denylist, nothing to do in deconstruction.");

      goto finish_hiding_post;
    }

    /* INFO: Utilizes dl_iterate_phdr, by CSOLoader, which resides in libzygisk.so */
    if (!g_state.disable_module_loading_traces_hiding) do_module_loading_traces_hiding(api_table, tw_env);

    finish_hiding_post:
      do_deinitialize();

      /* INFO: Part of module status system */
      enum daemon_operations op = DAEMON_CHECK_POINT;
      write_loop(cfd, &op, sizeof(op));

      enum module_status status = MODULE_STATUS_HIDING;
      write_loop(cfd, &status, sizeof(status));

      uint32_t pid = getpid();
      write_loop(cfd, &pid, sizeof(pid));

      op = DAEMON_GOODBYE;
      write_loop(cfd, &op, sizeof(op));

      close(cfd);
      /* INFO: Part of module status system */
    /* INFO: Hiding code END */

    /* INFO: Now safe to unmap libzygisk.so */
    munmap(addr, length);

    [[clang::musttail]] return munmap((void *)tw_info.start, tw_info.size);
  }

  return munmap(addr, length);
}

void preSpecialize(const char *process_name) {
  cfd = api_table->connectCompanion(api_table->impl);
  if (cfd == -1) return;

  api_table->exemptFd(cfd);

  enum daemon_operations op = DAEMON_CHECK_IGNORING;
  write_loop(cfd, &op, sizeof(op));

  LOGI("Checking if module is set to be ignoring.");

  uint8_t ret_state;
  if (read_loop(cfd, &ret_state, sizeof(ret_state)) == -1) {
    LOGI("Failed to read state, requested to dlclose Treat Wheel.");

    g_state.is_ignoring = true;

    return;
  }

  if (ret_state == 0) {
    LOGE("Execution was requested to be ignored, requested to dlclose Treat Wheel.");

    g_state.is_ignoring = true;

    return;
  }

  if (read_loop(cfd, &g_state, sizeof(g_state)) == -1) {
    LOGI("Failed to read state, requested to dlclose Treat Wheel.");

    g_state.is_ignoring = true;

    return;
  }

  /* INFO: Ignore everyone and everything will make Treat Wheel completely disappear and behave like
              it never existed.
  */
  if (g_state.is_ignoring) {
    LOGI("Module is set to be ignoring, requested to dlclose Treat Wheel.");

    return;
  }

  /* INFO: Part of module status system */
  op = DAEMON_CHECK_POINT;
  write_loop(cfd, &op, sizeof(op));

  enum module_status status = MODULE_STATUS_INJECTED;
  write_loop(cfd, &status, sizeof(status));

  uint32_t pid = getpid();
  write_loop(cfd, &pid, sizeof(pid));
  /* INFO: Part of module status system */

  flags = api_table->getFlags(api_table->impl);
  if (((flags & PROCESS_ON_DENYLIST) == PROCESS_ON_DENYLIST && g_state.disable_denylist_logic_inversion) || 
      ((flags & PROCESS_ON_DENYLIST) != PROCESS_ON_DENYLIST && !g_state.disable_denylist_logic_inversion)) {
    LOGI("Process is on denylist, cleaning extended traces.");

    if (!g_state.disable_gsi_hiding && !do_gsi_hiding(api_table, tw_env)) return;
    if (!g_state.disable_zygote_mountinfo_leak_fixing && !do_zygote_mountinfo_leak_fixing(api_table, tw_env)) return;
    if (!g_state.disable_maps_hiding && !do_maps_hiding(api_table, tw_env)) return;
    if (!g_state.disable_custom_font_loading && !do_custom_font_loading(api_table, tw_env)) return;
    if (!g_state.disable_frida_traces_hiding && !do_frida_traces_hiding(api_table, tw_env)) return;
  }

  if (!g_state.disable_denylist_logic_inversion) {
    if (!do_denylist_logic_inversion(api_table, tw_env, flags)) return;
  }

  if (((flags & PROCESS_ON_DENYLIST) == PROCESS_ON_DENYLIST && g_state.disable_denylist_logic_inversion) || 
      ((flags & PROCESS_ON_DENYLIST) != PROCESS_ON_DENYLIST && !g_state.disable_denylist_logic_inversion)) {
    if (!g_state.disable_revanced_mounts_umount && !do_revanced_mounts_umount(api_table, tw_env, process_name)) return;
  }
}

void preAppSpecialize(void *mod_data, struct AppSpecializeArgs *args) {
  (void) mod_data; (void) args;

  if (g_state.is_ignoring) {
    api_table->setOption(api_table->impl, DLCLOSE_MODULE_LIBRARY);

    return;
  }

  /* INFO: Deferencing nice_name is necessary. In C++, & does that job */
  const char *process = (*tw_env)->GetStringUTFChars(tw_env, *args->nice_name, NULL);
  if (str_equal(process, "webview_zygote")) {
    LOGD("Process is webview_zygote, skipping specialization.");

    (*tw_env)->ReleaseStringUTFChars(tw_env, *args->nice_name, process);

    api_table->setOption(api_table->impl, DLCLOSE_MODULE_LIBRARY);

    return;
  }

  preSpecialize(process);
  (*tw_env)->ReleaseStringUTFChars(tw_env, *args->nice_name, process);

  LOGD("Now setting custom unmap hook to hide Treat Wheel's library");
  api_table->pltHookRegister(rz_dev, rz_ino, "munmap", (void *)my_munmap, NULL);
  api_table->pltHookCommit();

  enum daemon_operations op = DAEMON_CHECK_POINT;
  write_loop(cfd, &op, sizeof(op));

  enum module_status status = MODULE_STATUS_MIDPERFORMING;
  write_loop(cfd, &status, sizeof(status));

  uint32_t pid = getpid();
  write_loop(cfd, &pid, sizeof(pid));
}

void preServerSpecialize(void *mod_data, struct ServerSpecializeArgs *args) {
  (void) mod_data; (void) args;

  if (g_state.is_ignoring) {
    api_table->setOption(api_table->impl, DLCLOSE_MODULE_LIBRARY);

    return;
  }

  cfd = api_table->connectCompanion(api_table->impl);
  if (cfd == -1) return;

  enum daemon_operations op = DAEMON_CHECK_IGNORING;
  write_loop(cfd, &op, sizeof(op));

  if (read_loop(cfd, &g_state, sizeof(g_state)) == -1) {
    LOGI("Failed to read state in system server.");

    close(cfd);

    return;
  }

  close(cfd);

  LOGD("Successfully initialized Treat Wheel daemon.");
}

void postAppSpecialize(void *mod_data, const struct AppSpecializeArgs *args) {
  (void) mod_data; (void) args;
}

void postServerSpecialize(void *mod_data, const struct ServerSpecializeArgs *args) {
  (void) mod_data; (void) args;

  api_table->setOption(api_table->impl, DLCLOSE_MODULE_LIBRARY);
}

__attribute__((constructor)) static void tw_initialization(void) {
  char process_name[128];
  if (!read_cmdline(process_name, sizeof(process_name))) {
    LOGE("Failed to read process name, requested to dlclose Treat Wheel.");

    g_state.is_ignoring = true;

    return;
  }

  if (!str_starts_with(process_name, "zygote")) {
    LOGI("Process is not zygote, it's ReZygiskd.");

    return;
  }

  /* INFO: Per-app initialization */
  do_preinitialize();

  struct maps *maps = get_global_maps();
  for (size_t i = 0; i < maps->size; i++) {
    struct map *map = &maps->maps[i];
    if (!map->path || !strstr(map->path, "rezygisk")) continue;

    if (!rz_base) rz_base = (void *)map->addr_start;
    rz_dev = map->dev;
    rz_ino = map->inode;

    LOGD("Found ReZygisk map at %s, dev=%d, ino=%d", map->path, (int)rz_dev, (int)rz_ino);
  }

  if (rz_dev == 0 || rz_ino == 0) {
    LOGE("Failed to find ReZygisk's library in maps, requested to dlclose Treat Wheel.");

    g_state.is_ignoring = true;

    do_deinitialize();

    return;
  }

  tw_info = tw_get_mem_info();

  LOGD("Treat Wheel memory region: start=%p, size=%zu", (void *)tw_info.start, tw_info.size);
}

void zygisk_module_entry(struct api_table *table, JNIEnv *env) {
  api_table = table;
  tw_env = env;

  static struct module_abi abi = {
    .api_version = 5,
    .preAppSpecialize = preAppSpecialize,
    .postAppSpecialize = postAppSpecialize,
    .preServerSpecialize = preServerSpecialize,
    .postServerSpecialize = postServerSpecialize
  };

  if (!table->registerModule(table, &abi)) return;
}

static bool has_crashed = false;

/* INFO: Checkpointing system */
struct tw_process_state {
  bool performed_hiding;
  uint32_t pid;
  time_t opened_at;
};

static struct tw_process_state *process_states = NULL;
static size_t process_states_size = 0;
static pthread_mutex_t process_states_lock = PTHREAD_MUTEX_INITIALIZER;

void zygisk_companion_entry(int module_fd) {
  while (1) {
    enum daemon_operations op;
    ssize_t ret = read(module_fd, &op, sizeof(op));
    if (ret == 0)
      goto cleanup;

    if (ret < 0) {
      PLOGE("Read operation");

      goto cleanup;
    }

    LOGI("Received operation: %d", op);

    if (op == DAEMON_CHECK_IGNORING) {
      FILE *fp = fopen("/data/adb/treat_wheel/state", "r");
      if (!fp) {
        PLOGE("Open state file");

        goto cleanup;
      }

      struct module_state state = { 0 };

      char line[128];
      while (fgets(line, sizeof(line), fp)) {
        if (str_starts_with(line, "ignoring=")) {
          state.is_ignoring = strncmp(line + strlen("ignoring="), "true", strlen("true")) == 0;

          LOGI("Found ignoring state: %d", state.is_ignoring);
        } else if (str_starts_with(line, "disable_prop_spoofing=")) {
          state.disable_prop_spoofing = strncmp(line + strlen("disable_prop_spoofing="), "true", strlen("true")) == 0;

          LOGI("Found disable_prop_spoofing state: %d", state.disable_prop_spoofing);
        } else if (str_starts_with(line, "disable_gsi_hiding=")) {
          state.disable_gsi_hiding = strncmp(line + strlen("disable_gsi_hiding="), "true", strlen("true")) == 0;

          LOGI("Found disable_gsi_hiding state: %d", state.disable_gsi_hiding);
        } else if (str_starts_with(line, "disable_zygote_mountinfo_leak_fixing=")) {
          state.disable_zygote_mountinfo_leak_fixing = strncmp(line + strlen("disable_zygote_mountinfo_leak_fixing="), "true", strlen("true")) == 0;

          LOGI("Found disable_zygote_mountinfo_leak_fixing state: %d", state.disable_zygote_mountinfo_leak_fixing);
        } else if (str_starts_with(line, "disable_maps_hiding=")) {
          state.disable_maps_hiding = strncmp(line + strlen("disable_maps_hiding="), "true", strlen("true")) == 0;

          LOGI("Found disable_maps_hiding state: %d", state.disable_maps_hiding);
        } else if (str_starts_with(line, "disable_revanced_mounts_umount=")) {
          state.disable_revanced_mounts_umount = strncmp(line + strlen("disable_revanced_mounts_umount="), "true", strlen("true")) == 0;

          LOGI("Found disable_revanced_mounts_umount state: %d", state.disable_revanced_mounts_umount);
        } else if (str_starts_with(line, "disable_custom_font_loading=")) {
          state.disable_custom_font_loading = strncmp(line + strlen("disable_custom_font_loading="), "true", strlen("true")) == 0;

          LOGI("Found disable_custom_font_loading state: %d", state.disable_custom_font_loading);
        } else if (str_starts_with(line, "disable_denylist_logic_inversion=")) {
          state.disable_denylist_logic_inversion = strncmp(line + strlen("disable_denylist_logic_inversion="), "true", strlen("true")) == 0;

          LOGI("Found disable_denylist_logic_inversion state: %d", state.disable_denylist_logic_inversion);
        } else if (str_starts_with(line, "disable_module_loading_traces_hiding=")) {
          state.disable_module_loading_traces_hiding = strncmp(line + strlen("disable_module_loading_traces_hiding="), "true", strlen("true")) == 0;

          LOGI("Found disable_module_loading_traces_hiding state: %d", state.disable_module_loading_traces_hiding);
        } else if (str_starts_with(line, "disable_frida_traces_hiding=")) {
          state.disable_frida_traces_hiding = strncmp(line + strlen("disable_frida_traces_hiding="), "true", strlen("true")) == 0;

          LOGI("Found disable_frida_traces_hiding state: %d", state.disable_frida_traces_hiding);
        }
      }

      fclose(fp);

      uint8_t ret_state = 1;
      write_loop(module_fd, &ret_state, sizeof(ret_state));

      write_loop(module_fd, &state, sizeof(state));
    } else if (op == DAEMON_CHECK_POINT) {
      enum module_status status;
      if (read_loop(module_fd, &status, sizeof(status)) == -1) {
        PLOGE("Read status");

        goto cleanup;
      }

      uint32_t ppid;
      if (read_loop(module_fd, &ppid, sizeof(ppid)) == -1) {
        PLOGE("Read ppid");

        goto cleanup;
      }

      if (has_crashed) {
        LOGW("Treat Wheel has crashed, refusing to set new state.");

        continue;
      }

      /* INFO: Check if timestamp was more than 3s for any existing ones */
      pthread_mutex_lock(&process_states_lock);
      for (size_t i = 0; i < process_states_size; i++) {
        time_t time_now = mono_sec_now();

        if (time_now - process_states[i].opened_at > 30 && !process_states[i].performed_hiding) {
          LOGE("Process %d has been opened for more than 30 seconds (%d seconds), assuming it has crashed.", process_states[i].pid, (int)(time_now - process_states[i].opened_at));

          free(process_states);
          process_states = NULL;
          process_states_size = 0;

          has_crashed = true;

          i--;
        }
      }

      pthread_mutex_unlock(&process_states_lock);

      if (has_crashed) {
        LOGE("Treat Wheel has crashed, setting proper state.");

        pthread_mutex_lock(&process_states_lock);

        if (process_states_size != 0) {
          LOGD("Clearing all existing process states.");

          free(process_states);
          process_states = NULL;
          process_states_size = 0;
        }

        pthread_mutex_unlock(&process_states_lock);

        int ffd = open("/data/adb/treat_wheel/status", O_WRONLY | O_CREAT, 0644);
        if (ffd == -1) {
          PLOGE("Open status file");

          goto cleanup;
        }

        write(ffd, "crashed\n", strlen("crashed\n"));

        close(ffd);

        continue;
      }

      if (status == MODULE_STATUS_HIDING) {
        pthread_mutex_lock(&process_states_lock);

        /* INFO: Process execution went well. Remove it. */
        struct tw_process_state *found = NULL;
        size_t i = 0;

        for (; i < process_states_size; i++) {
          if (process_states[i].pid != ppid) continue;

          LOGD("Found process now finalized in Treat Wheel execution with pid %d, removing. Now, %zu process being tracked.", ppid, process_states_size - 1);

          found = &process_states[i];

          break;
        }

        if (found) {
          memset(found, 0, sizeof(*found));

          for (size_t j = i; j < process_states_size - 1; j++) {
            process_states[j] = process_states[j + 1];
          }

          process_states_size--;
          if (process_states_size == 0) {
            if (process_states) {
              free(process_states);
              process_states = NULL;
            }
          } else {
            struct tw_process_state *tmp_states = realloc(process_states, sizeof(struct tw_process_state) * process_states_size);
            if (tmp_states) process_states = tmp_states;
          }
        }

        if (process_states_size == 0) {
          LOGD("No existing process states, resetting status to hiding.");

          int ffd = open("/data/adb/treat_wheel/status", O_RDWR | O_CREAT, 0644);
          if (ffd == -1) {
            PLOGE("Open status file");

            pthread_mutex_unlock(&process_states_lock);

            goto cleanup;
          }

          char current_status[32];
          ssize_t status_len = read(ffd, current_status, sizeof(current_status) - 1);
          if (status_len > 0) {
            current_status[status_len] = '\0';

            if (str_equal(current_status, "hiding\n")) {
              LOGD("Status is already hiding, nothing to do.");

              close(ffd);

              pthread_mutex_unlock(&process_states_lock);

              continue;
            }
          }

          /* INFO: Seek back to beginning before writing */
          lseek(ffd, 0, SEEK_SET);
          ftruncate(ffd, 0);
          write(ffd, "hiding\n", strlen("hiding\n"));

          close(ffd);
        }
        pthread_mutex_unlock(&process_states_lock);
      }

      if (status == MODULE_STATUS_MIDPERFORMING) {
        pthread_mutex_lock(&process_states_lock);

        /* INFO: Process is mid-performing, just update timestamp */
        for (size_t i = 0; i < process_states_size; i++) {
          if (process_states[i].pid != ppid) continue;

          process_states[i].performed_hiding = true;

          LOGD("Updated state for process with pid %d in Treat Wheel execution.", ppid);

          break;
        }

        pthread_mutex_unlock(&process_states_lock);

        continue;
      }

      if (status == MODULE_STATUS_INJECTED) {
        pthread_mutex_lock(&process_states_lock);

        struct tw_process_state *tmp_states = realloc(process_states, sizeof(struct tw_process_state) * (process_states_size + 1));
        if (!tmp_states) {
          PLOGE("Failed to allocate memory for process states");

          goto cleanup;
        }
        process_states = tmp_states;

        process_states[process_states_size].pid = ppid;
        process_states[process_states_size].opened_at = mono_sec_now();
        process_states[process_states_size].performed_hiding = false;
        process_states_size++;

        LOGD("Started now Treat Wheel execution for process with pid %d. Now, %zu processes are being tracked.", ppid, process_states_size);

        pthread_mutex_unlock(&process_states_lock);
      }
    } else if (op == DAEMON_GOODBYE) {
      LOGI("Received goodbye operation, exiting companion.");

      goto cleanup;
    }
  }

  cleanup:
    close(module_fd);
}
