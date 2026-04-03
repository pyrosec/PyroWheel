#ifndef HIDING_H
#define HIDING_H

#include "zygisk.h"

struct maps *get_global_maps(void);

int do_preinitialize(void);

void do_deinitialize(void);

int do_gsi_hiding(struct api_table *api_table, JNIEnv *tw_env);

int do_zygote_mountinfo_leak_fixing(struct api_table *api_table, JNIEnv *tw_env);

int do_maps_hiding(struct api_table *api_table, JNIEnv *tw_env);

int do_revanced_mounts_umount(struct api_table *api_table, JNIEnv *tw_env, const char *process_name);

int do_custom_font_loading(struct api_table *api_table, JNIEnv *tw_env);

int do_denylist_logic_inversion(struct api_table *api_table, JNIEnv *tw_env, enum process_flags flags);

int do_module_loading_traces_hiding(struct api_table *api_table, JNIEnv *tw_env);

int do_frida_traces_hiding(struct api_table *api_table, JNIEnv *tw_env);

#endif /* HIDING_H */
