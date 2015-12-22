#include "common.h"

#ifdef TARGET_WINDOWS
#include <Windows.h>
/*
typedef struct _FILE_NAME_INFO {
  DWORD FileNameLength;
  WCHAR FileName[1];
} FILE_NAME_INFO, *PFILE_NAME_INFO;
*/
void get_fullpath_from_fd_handle(void * handle, char * path)
{
	char buf[0x10000];
	
	if (!GetFileInformationByHandleEx((HANDLE)handle, FileNameInfo, buf, 0x10000))
		ERROR("cant get filepath of handle:0x%p", handle);
	WideCharToMultiByte(0, // specify the code page used to perform the conversion
		0,         // no special flags to handle unmapped characters
		(WCHAR*)&buf[4],   // wide character string to convert
		*((int*)&buf[0]),   // the number of wide characters in that string
		path, // put the output ascii characters at the end of the buffer
		0x10000,                           // there is at least this much space there
		NULL,      // no replacement character given
		NULL);
}
#endif


#ifdef TARGET_MAC
#include <sys/syslimits.h>
#include <fcntl.h>
void get_fullpath_from_fd_handle(int fd, char * path)
{
	if (fcntl(fd, F_GETPATH, path) == -1)
		ERROR("cant get filepath of fd:%d", fd);
}
#endif
#ifdef TARGET_LINUX
#include <unistd.h>
#include "pin.H"
void get_fullpath_from_fd_handle(int fd, char * path)
{
	char temp[20480];
	sprintf(temp, "/proc/%d/fd/%d", PIN_GetPid(), fd);
	if (-1 == readlink(temp, path, 0x10000)
		ERROR("cant get filepath of fd:%d", fd);
}
#endif

#include <string.h>
bool isStrEndWith(const char * haystack, const char* needle)
{
	size_t len = strlen(haystack);
	size_t l = strlen(needle);
	if (l <= len && strcmp(&haystack[len-l], needle) == 0) return true;
	return false;
}

