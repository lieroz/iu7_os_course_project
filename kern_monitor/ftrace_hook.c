#include "ftrace_hook.h"


#define USE_FENTRY_OFFSET 0
#define pr_fmt(fmt) "ftrace_hook: " fmt


static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
	if (!(hook->address = kallsyms_lookup_name(hook->name))) {
		pr_debug("unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

#if USE_FENTRY_OFFSET
	*((unsigned long*) hook->orig_func) = hook->address + MCOUNT_INSN_SIZE;
#else
	*((unsigned long*) hook->orig_func) = hook->address;
#endif

	return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *ops, struct pt_regs *regs)
{
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

#if USE_FENTRY_OFFSET
	regs->ip = (unsigned long) hook->fake_func;
#else
	if (!within_module(parent_ip, THIS_MODULE)) {
		regs->ip = (unsigned long) hook->fake_func;
        }
#endif
}

int fh_install_hook(struct ftrace_hook *hook)
{
	int err;

	if ((err = fh_resolve_hook_address(hook))) {
		return err;
        }

	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
	                | FTRACE_OPS_FL_RECURSION_SAFE
	                | FTRACE_OPS_FL_IPMODIFY;

	if ((err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0))) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}

	if ((err = register_ftrace_fake_func(&hook->ops))) {
		pr_debug("register_ftrace_fake_func() failed: %d\n", err);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return err;
	}

	return 0;
}

void fh_remove_hook(struct ftrace_hook *hook)
{
	int err;

	if ((err = unregister_ftrace_fake_func(&hook->ops))) {
		pr_debug("unregister_ftrace_fake_func() failed: %d\n", err);
	}

	if ((err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0))) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
	}
}

int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
	int err;
	size_t i;

	for (i = 0; i < count; i++) {
		err = fh_install_hook(&hooks[i]);

		if (err) {
                        while (i != 0) {
		                fh_remove_hook(&hooks[--i]);
	                }

			break;
                }
	}

	return err;
}

void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++) {
		fh_remove_hook(&hooks[i]);
        }
}

#ifndef CONFIG_X86_64
#error Currently only x86_64 architecture is supported
#endif

#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

static asmlinkage long (*real_sys_clone)(unsigned long clone_flags,
		unsigned long newsp, int __user *parent_tidptr,
		int __user *child_tidptr, unsigned long tls);

static asmlinkage long fh_sys_clone(unsigned long clone_flags,
		unsigned long newsp, int __user *parent_tidptr,
		int __user *child_tidptr, unsigned long tls)
{
	long ret;

	pr_info("clone() before\n");
	ret = real_sys_clone(clone_flags, newsp, parent_tidptr, child_tidptr, tls);
	pr_info("clone() after: %ld\n", ret);

	return ret;
}

static char *duplicate_filename(const char __user *filename)
{
	char *kernel_filename;

	if (!(kernel_filename = kmalloc(4096, GFP_KERNEL)))
		return NULL;

	if (strncpy_from_user(kernel_filename, filename, 4096) < 0) {
		kfree(kernel_filename);
		return NULL;
	}

	return kernel_filename;
}

static asmlinkage long (*real_sys_execve)(const char __user *filename,
		const char __user *const __user *argv,
		const char __user *const __user *envp);

static asmlinkage long fh_sys_execve(const char __user *filename,
		const char __user *const __user *argv,
		const char __user *const __user *envp)
{
	long ret;
	char *kernel_filename;

	kernel_filename = duplicate_filename(filename);
	pr_info("execve() before: %s\n", kernel_filename);

	kfree(kernel_filename);

	ret = real_sys_execve(filename, argv, envp);
	pr_info("execve() after: %ld\n", ret);

	return ret;
}

static struct ftrace_hook demo_hooks[] = {
	HOOK("__x64_sys_clone",  fh_sys_clone,  &real_sys_clone),
	HOOK("__x64_sys_execve", fh_sys_execve, &real_sys_execve),
};

static int fh_init(void)
{
        return fh_install_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
}

static void fh_exit(void)
{
	fh_remove_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
}

