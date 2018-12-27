#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>


#define HOOK(_name, _function, _original)	\
	{					\
	        .name = (_name),		\
		.function = (_function),	\
		.original = (_original),	\
	}

struct ftrace_hook {
	const char *name;
	void *fake_func;
	void *orig_func;

	unsigned long address;
	struct ftrace_ops ops;
};

int fh_init(void);
void fh_exit(void);

