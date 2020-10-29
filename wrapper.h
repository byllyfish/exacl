#include <sys/types.h>
#include <sys/errno.h>
#include <sys/acl.h>
#include <fcntl.h>
#if defined(__APPLE__)
// MacOS makes us translate between GUID and UID/GID.
# include <membership.h>
#else  // defined(__APPLE__)
// Linux supplies non-standard ACL extensions.
# include <acl/libacl.h>
#endif  // !defined(__APPLE__)
#include <unistd.h>
