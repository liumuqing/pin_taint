#include "common.h"
#ifdef TARGET_WINDOWS
extern void get_fullpath_from_fd_handle(void * handle, char * path);
#else
extern void get_fullpath_from_fd_handle(int fd, char * path);
#endif
