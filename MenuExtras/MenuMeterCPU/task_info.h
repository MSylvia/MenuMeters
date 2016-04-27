//
//  task_info.h
//  MenuMeters
//
//  Created by X on 26/04/16.
//
//

#ifndef task_info_h
#define task_info_h

#include <stdio.h>

typedef struct { /* dynamic process information */
    size_t rss, vsize;
    double utime, stime;
} RunProcDyn;

void task_info_init();
int macosx_get_task_for_pid_rights (void);
int run_get_dynamic_proc_info(pid_t pid, RunProcDyn *rpd);

#endif /* task_info_h */
