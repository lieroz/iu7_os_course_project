#include "server.h"
#include "ftrace_hook.h"

static int __init kern_monitor_init(void)
{
        return 0;
}

static void __exit kern_monitor_exit(void)
{
}

module_init(kern_monitor_init)
module_exit(kern_monitor_exit)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kamakin Andrey");

