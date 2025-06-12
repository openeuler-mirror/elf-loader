#include "z_asm.h"
#include "z_syscalls.h"
#include "z_utils.h"
#include "z_elf.h"
#include "z_epkg.h"

/* Auxiliary vector entry structure */
struct auxv_entry {
    unsigned long a_type;
    unsigned long a_val;
};

static unsigned long page_size = 0;

#define ALIGN		(page_size - 1)
#define ROUND_PG(x)	(((x) + (ALIGN)) & ~(ALIGN))
#define TRUNC_PG(x)	((x) & ~(ALIGN))
#define PFLAGS(x)	((((x) & PF_R) ? PROT_READ : 0) | \
			 (((x) & PF_W) ? PROT_WRITE : 0) | \
			 (((x) & PF_X) ? PROT_EXEC : 0))
#define LOAD_ERR	((unsigned long)-1)

char **z_environ;

// these will be replaced to real osroot and app path
static char epkg_env_osroot[] = "{{SOURCE_ENV_DIR LONG0 LONG1 LONG2 LONG3 LONG4 LONG5 LONG6 LONG7 LONG8 LONG9 LONG0 LONG1 LONG2 LONG3 LONG4 LONG5 LONG6 LONG7 LONG8 LONG9 LONG0 LONG1 LONG2 LONG3 LONG4 LONG5 LONG6 LONG7 LONG8 LONG9}}";
static char target_elf_path[] = "{{TARGET_ELF_PATH LONG0 LONG1 LONG2 LONG3 LONG4 LONG5 LONG6 LONG7 LONG8 LONG9 LONG0 LONG1 LONG2 LONG3 LONG4 LONG5 LONG6 LONG7 LONG8 LONG9 LONG0 LONG1 LONG2 LONG3 LONG4 LONG5 LONG6 LONG7 LONG8 LONG9}}";

// replaced for debug
/* static char epkg_env_osroot[] = "/mnt/debian\0DIR LONG0 LONG1 LONG2 LONG3 LONG4 LONG5 LONG6 LONG7 LONG8 LONG9 LONG0 LONG1 LONG2 LONG3 LONG4 LONG5 LONG6 LONG7 LONG8 LONG9 LONG0 LONG1 LONG2 LONG3 LONG4 LONG5 LONG6 LONG7 LONG8 LONG9}}"; */
/* static char target_elf_path[] = "/mnt/debian/bin/ls\0NG0 LONG1 LONG2 LONG3 LONG4 LONG5 LONG6 LONG7 LONG8 LONG9 LONG0 LONG1 LONG2 LONG3 LONG4 LONG5 LONG6 LONG7 LONG8 LONG9 LONG0 LONG1 LONG2 LONG3 LONG4 LONG5 LONG6 LONG7 LONG8 LONG9}}"; */

#define PATH_BUF_SIZE 1024
static char auto_detected_osroot[PATH_BUF_SIZE];
static char auto_detected_target[PATH_BUF_SIZE];

/* Get the path of the current executable */
static void get_executable_path(char *exec_path, size_t path_size)
{
    ssize_t len;
    size_t i;

    // Clear buffer
    for (i = 0; i < path_size; i++) {
        exec_path[i] = '\0';
    }

    // Get the path of the current executable from /proc/self/exe
    len = z_readlink("/proc/self/exe", exec_path, path_size - 1);
    if (len == -1) {
        // If readlink fails, we can't proceed
        z_errx(1, "failed to read /proc/self/exe");
    }
    exec_path[len] = '\0';
}

/**
 * Detect OS root directory from executable path
 *
 * Rules:
 * 1. Extract directory path from executable path (e.g., "$env_root/usr/ebin" from "$env_root/usr/ebin/jq")
 * 2. Remove "/ebin" suffix if present (e.g., "$env_root/usr/ebin" -> "$env_root/usr")
 * 3. Remove "/usr" suffix if present (e.g., "$env_root/usr" -> "$env_root")
 * 4. The result is the OS root directory
 *
 * Example:
 * - Executable: "$env_root/usr/ebin/jq"
 * - Directory path: "$env_root/usr/ebin"
 * - After removing "/ebin": "$env_root/usr"
 * - After removing "/usr": "$env_root"
 * - OS root: "$env_root"
 */
static void detect_osroot(const char *exec_path)
{
    char base_path[PATH_BUF_SIZE];
    char *base_path_end;
    ssize_t len;
    int i;

    debug("detect_osroot: exec_path = %s\n", exec_path);

    // Clear buffer
    for (i = 0; i < PATH_BUF_SIZE; i++) {
        // auto_detected_osroot[i] = '\0';
        base_path[i] = '\0';
    }

    // Copy exec_path to working buffer
    len = 0;
    while (exec_path[len] && len < (ssize_t)(sizeof(base_path) - 1)) {
        base_path[len] = exec_path[len];
        len++;
    }
    base_path[len] = '\0';

    // Find the last '/' to get the directory part
    base_path_end = base_path + len;
    while (base_path_end > base_path && *(base_path_end - 1) != '/') {
        base_path_end--;
    }
    if (base_path_end > base_path) {
        base_path_end--; // Remove the trailing '/'
    }
    *base_path_end = '\0';

    debug("detect_osroot: base_path (before ebin check) = %s\n", base_path);

    // Check if path ends with "/ebin" and remove it
    len = base_path_end - base_path;
    if (len >= 5 && z_memcmp(base_path + len - 5, "/ebin", 5) == 0) {
        base_path[len - 5] = '\0';
        base_path_end = base_path + len - 5;
        debug("detect_osroot: removed /ebin, new base_path = %s\n", base_path);
    }

    // For epkg_env_osroot: base_path.trim("/usr")
    len = base_path_end - base_path;
    if (len >= 4 && z_memcmp(base_path + len - 4, "/usr", 4) == 0) {
        // Copy everything except the last "/usr"
        for (i = 0; i < len - 4; i++) {
            auto_detected_osroot[i] = base_path[i];
        }
        auto_detected_osroot[len - 4] = '\0';
        debug("detect_osroot: removed /usr, osroot = %s\n", auto_detected_osroot);
    } else {
        // Copy the whole base_path if it doesn't end with "/usr"
        for (i = 0; i < len; i++) {
            auto_detected_osroot[i] = base_path[i];
        }
        auto_detected_osroot[len] = '\0';
        debug("detect_osroot: no /usr found, osroot = %s\n", auto_detected_osroot);
    }
}

/*
 * Detect target ELF path through symlinks
 *
 * Rules:
 * 1. Extract filename from executable path (e.g., "jq" from "$env_root/usr/ebin/jq")
 * 2. Get base directory by removing "/ebin" if present (e.g., "$env_root/usr/ebin" -> "$env_root/usr")
 * 3. Try symlink1: base_path + "/bin/" + filename (e.g., "$env_root/usr/bin/jq")
 * 4. If symlink1 fails, try symlink2: base_path + "/ebin/." + filename (e.g., "$env_root/usr/ebin/.jq")
 *
 * Example:
 * - Executable: "$env_root/usr/ebin/jq"
 * - Filename: "jq"
 * - Base path: "$env_root/usr" (after removing "/ebin")
 * - Try symlink1: "$env_root/usr/bin/jq" -> readlink to get target
 * - Try symlink2: "$env_root/usr/ebin/.jq" -> readlink to get target
 */
static void detect_target_path(const char *exec_path)
{
    char base_path[PATH_BUF_SIZE];
    char *base_path_end;
    char symlink1_path[PATH_BUF_SIZE];
    char symlink2_path[PATH_BUF_SIZE];
    char filename[64];
    const char *exec_filename;
    const char *last_slash;
    ssize_t len;
    size_t i;

    debug("detect_target_path: exec_path = %s\n", exec_path);

    // Clear buffer
    for (i = 0; i < PATH_BUF_SIZE; i++) {
        // auto_detected_target[i] = '\0';
        base_path[i] = '\0';
    }

    // Copy exec_path to working buffer and get base path
    len = 0;
    while (exec_path[len] && (size_t)len < (sizeof(base_path) - 1)) {
        base_path[len] = exec_path[len];
        len++;
    }
    base_path[len] = '\0';

    // Find the directory part of exec_path
    base_path_end = base_path + len;
    while (base_path_end > base_path && *(base_path_end - 1) != '/') {
        base_path_end--;
    }
    if (base_path_end > base_path) {
        base_path_end--; // Remove the trailing '/'
    }
    *base_path_end = '\0';

    debug("detect_target_path: base_path (before ebin check) = %s\n", base_path);

    // Check if path ends with "/ebin" and remove it
    len = base_path_end - base_path;
    if (len >= 5 && z_memcmp(base_path + len - 5, "/ebin", 5) == 0) {
        base_path[len - 5] = '\0';
        base_path_end = base_path + len - 5;
        debug("detect_target_path: removed /ebin, new base_path = %s\n", base_path);
    }

    // Extract filename from exec_path
    exec_filename = exec_path;
    last_slash = exec_path;
    while (*last_slash) {
        if (*last_slash == '/') {
            exec_filename = last_slash + 1;
        }
        last_slash++;
    }

    // Copy filename
    i = 0;
    while (exec_filename[i] && i < (sizeof(filename) - 1)) {
        filename[i] = exec_filename[i];
        i++;
    }
    filename[i] = '\0';

    debug("detect_target_path: extracted filename = %s\n", filename);

    // Construct symlink1 path: base_path + "/bin/" + filename
    len = base_path_end - base_path;
    for (i = 0; i < (size_t)len; i++) {
        symlink1_path[i] = base_path[i];
    }
    // Add "/bin/" to the path
    symlink1_path[len] = '/';
    len++;
    symlink1_path[len] = 'b';
    len++;
    symlink1_path[len] = 'i';
    len++;
    symlink1_path[len] = 'n';
    len++;
    symlink1_path[len] = '/';
    len++;
    i = 0;
    while (filename[i] && (size_t)len < (sizeof(symlink1_path) - 1)) {
        symlink1_path[len] = filename[i];
        len++;
        i++;
    }
    symlink1_path[len] = '\0';

    debug("detect_target_path: trying symlink1 = %s\n", symlink1_path);

    // Try to readlink symlink1
    len = z_readlink(symlink1_path, auto_detected_target, sizeof(auto_detected_target) - 1);
    if (len != -1) {
        auto_detected_target[len] = '\0';
        debug("detect_target_path: symlink1 SUCCESS, target = %s\n", auto_detected_target);
        return;
    }
    debug("detect_target_path: symlink1 failed\n");

    // Fall back to symlink2: base_path + "/ebin/." + filename
    len = base_path_end - base_path;
    for (i = 0; i < (size_t)len && i < (sizeof(symlink2_path) - 1); i++) {
        symlink2_path[i] = base_path[i];
    }

    // Add "/ebin/" to the path
    symlink2_path[len] = '/';
    len++;
    symlink2_path[len] = 'e';
    len++;
    symlink2_path[len] = 'b';
    len++;
    symlink2_path[len] = 'i';
    len++;
    symlink2_path[len] = 'n';
    len++;
    symlink2_path[len] = '/';
    len++;

    // Add "." prefix to filename
    if ((size_t)len < sizeof(symlink2_path) - 1) {
        symlink2_path[len] = '.';
        len++;
    }

    // Add filename
    i = 0;
    while (filename[i] && (size_t)len < (sizeof(symlink2_path) - 1)) {
        symlink2_path[len] = filename[i];
        len++;
        i++;
    }
    symlink2_path[len] = '\0';

    debug("detect_target_path: trying symlink2 = %s\n", symlink2_path);

    // Try to readlink symlink2
    len = z_readlink(symlink2_path, auto_detected_target, sizeof(auto_detected_target) - 1);
    if (len != -1) {
        auto_detected_target[len] = '\0';
        debug("detect_target_path: symlink2 SUCCESS, target = %s\n", auto_detected_target);
    } else {
        // Final fallback: empty target
        auto_detected_target[0] = '\0';
        debug("detect_target_path: symlink2 failed\n");
    }
}

/* Auto-detect paths when placeholders are not modified by binary edit tool */
static void auto_detect_paths(void)
{
    char exec_path[PATH_BUF_SIZE];

    get_executable_path(exec_path, sizeof(exec_path));
    detect_osroot(exec_path);
    detect_target_path(exec_path);
}

/* Initialize page_size by reading from auxv */
static void init_page_size(void)
{
    int fd;
    struct auxv_entry entry;

    fd = z_open("/proc/self/auxv", 0);  // O_RDONLY
    if (fd < 0) goto fallback;

    while (z_read(fd, &entry, sizeof(entry)) == sizeof(entry)) {
        if (entry.a_type == AT_PAGESZ) {
            page_size = entry.a_val;
            break;
        }
        if (entry.a_type == AT_NULL) break;
    }

    z_close(fd);

fallback:
    /* Default to 4096 if detection fails */
    if (page_size == 0) {
        page_size = 4096;
    }
}

static void z_fini(void)
{
	z_printf("Fini at work\n");
}

static int check_ehdr(Elf_Ehdr *ehdr)
{
	unsigned char *e_ident = ehdr->e_ident;
	return (e_ident[EI_MAG0] != ELFMAG0 || e_ident[EI_MAG1] != ELFMAG1 ||
		e_ident[EI_MAG2] != ELFMAG2 || e_ident[EI_MAG3] != ELFMAG3 ||
	    	e_ident[EI_CLASS] != ELFCLASS ||
		e_ident[EI_VERSION] != EV_CURRENT ||
		(ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN)) ? 0 : 1;
}

static unsigned long loadelf_anon(int fd, Elf_Ehdr *ehdr, Elf_Phdr *phdr)
{
	unsigned long minva, maxva;
	Elf_Phdr *iter;
	ssize_t sz;
	int flags, dyn = ehdr->e_type == ET_DYN;
	unsigned char *p, *base, *hint;

	minva = (unsigned long)-1;
	maxva = 0;

	for (iter = phdr; iter < &phdr[ehdr->e_phnum]; iter++) {
		if (iter->p_type != PT_LOAD)
			continue;
		if (iter->p_vaddr < minva)
			minva = iter->p_vaddr;
		if (iter->p_vaddr + iter->p_memsz > maxva)
			maxva = iter->p_vaddr + iter->p_memsz;
	}

	minva = TRUNC_PG(minva);
	maxva = ROUND_PG(maxva);

	/* For dynamic ELF let the kernel chose the address. */
	hint = dyn ? NULL : (void *)minva;
	flags = dyn ? 0 : MAP_FIXED_NOREPLACE;
	flags |= (MAP_PRIVATE | MAP_ANONYMOUS);

	/* Check that we can hold the whole image. */
	base = z_mmap(hint, maxva - minva, PROT_NONE, flags, -1, 0);
	if (base == (void *)-1)
		return -1;
	z_munmap(base, maxva - minva);

	flags = MAP_FIXED_NOREPLACE | MAP_ANONYMOUS | MAP_PRIVATE;
	/* Now map each segment separately in precalculated address. */
	for (iter = phdr; iter < &phdr[ehdr->e_phnum]; iter++) {
		unsigned long off, start;
		if (iter->p_type != PT_LOAD)
			continue;
		off = iter->p_vaddr & ALIGN;
		start = dyn ? (unsigned long)base : 0;
		start += TRUNC_PG(iter->p_vaddr);
		sz = ROUND_PG(iter->p_memsz + off);

		p = z_mmap((void *)start, sz, PROT_WRITE, flags, -1, 0);
		if (p == (void *)-1)
			goto err;
		if (z_lseek(fd, iter->p_offset, SEEK_SET) < 0)
			goto err;
		if (z_read(fd, p + off, iter->p_filesz) !=
				(ssize_t)iter->p_filesz)
			goto err;
		z_mprotect(p, sz, PFLAGS(iter->p_flags));
	}

	return (unsigned long)base;
err:
	z_munmap(base, maxva - minva);
	return LOAD_ERR;
}

#define Z_PROG		0
#define Z_INTERP	1

/* Initialize environment and parse arguments */
static void initialize_environment(unsigned long *sp, char ***argv, char ***env, Elf_auxv_t **av, int *argc)
{
    char **p;

    init_page_size();

    *argc = (int)*(sp);
    *argv = (char **)(sp + 1);
    *env = p = (char **)&(*argv)[*argc + 1];
    while (*p++ != NULL)
        ;
    *av = (void *)p;

    z_environ = *env;
}

/* Determine elf_file to execute and osroot to use */
static void determine_file_and_osroot(const char **elf_file, const char **osroot_to_use)
{
    // Check if placeholders are still untouched and auto-detect if needed
    if (epkg_env_osroot[0] == '{' && z_memcmp(epkg_env_osroot, "{{SOURCE_ENV_DIR LONG0 LONG1", 28) == 0) {
        // Placeholders are untouched, auto-detect paths
        auto_detect_paths();
        *osroot_to_use = auto_detected_osroot;
        *elf_file = auto_detected_target;
        debug("using auto-detected paths: osroot=%s, elf_file=%s\n", *osroot_to_use, *elf_file);
    } else {
        // Placeholders have been modified by binary edit tool
        *osroot_to_use = epkg_env_osroot;
        *elf_file = target_elf_path;
        debug("using placeholder paths: osroot=%s, elf_file=%s\n", *osroot_to_use, *elf_file);
    }

    if (**elf_file == '\0') {
        z_errx(1, "no target_elf_path");
    }
    if (**osroot_to_use == '\0') {
        z_errx(1, "no epkg_env_osroot");
    }
}

/* Setup auxiliary vector entries */
static void setup_auxv(Elf_auxv_t *av, unsigned long *base, Elf_Ehdr *ehdrs, unsigned long *entry, char *elf_interp, char **argv)
{
    /* Reassign some vectors that are important for
     * the dynamic linker and for lib C. */
#define AVSET(t, v, expr) case (t): (v)->a_un.a_val = (expr); break

    while (av && av->a_type != AT_NULL) {
        switch (av->a_type) {
        AVSET(AT_PHDR, av, base[Z_PROG] + ehdrs[Z_PROG].e_phoff);
        AVSET(AT_PHNUM, av, ehdrs[Z_PROG].e_phnum);
        AVSET(AT_PHENT, av, ehdrs[Z_PROG].e_phentsize);
        AVSET(AT_ENTRY, av, entry[Z_PROG]);
        AVSET(AT_EXECFN, av, (unsigned long)argv[0]); /* Use argv[0] instead of argv[1] */
        AVSET(AT_BASE, av, elf_interp ? base[Z_INTERP] : av->a_un.a_val);
        }
        ++av;
    }
#undef AVSET
}

/* Load and execute ELF files */
static void load_and_execute_elf(const char *file, char **argv, unsigned long *sp, Elf_auxv_t *av)
{
    Elf_Ehdr ehdrs[2], *ehdr = ehdrs;
    Elf_Phdr *phdr, *iter;
    char *elf_interp = NULL;
    unsigned long base[2], entry[2];
    ssize_t sz;
    int fd, i;

    for (i = 0;; i++, ehdr++) {
        /* Open file, read and than check ELF header.*/
        if ((fd = z_open(file, O_RDONLY)) < 0)
            z_errx(1, "can't open %s", file);
        if (z_read(fd, ehdr, sizeof(*ehdr)) != sizeof(*ehdr))
            z_errx(1, "can't read ELF header %s", file);
        if (!check_ehdr(ehdr))
            z_errx(1, "bogus ELF header %s", file);

        /* Read the program header. */
        sz = ehdr->e_phnum * sizeof(Elf_Phdr);
        phdr = z_alloca(sz);
        if (z_lseek(fd, ehdr->e_phoff, SEEK_SET) < 0)
            z_errx(1, "can't lseek to program header %s", file);
        if (z_read(fd, phdr, sz) != sz)
            z_errx(1, "can't read program header %s", file);
        /* Time to load ELF. */
        if ((base[i] = loadelf_anon(fd, ehdr, phdr)) == LOAD_ERR)
            z_errx(1, "can't load ELF %s", file);

        /* Set the entry point, if the file is dynamic than add bias. */
        entry[i] = ehdr->e_entry + (ehdr->e_type == ET_DYN ? base[i] : 0);
        /* The second round, we've loaded ELF interp. */
        if (file == elf_interp) {
            z_close(fd);
            break;
        }

        for (iter = phdr; iter < &phdr[ehdr->e_phnum]; iter++) {
            if (iter->p_type != PT_INTERP)
                continue;
            elf_interp = z_alloca(iter->p_filesz);
            if (z_lseek(fd, iter->p_offset, SEEK_SET) < 0)
                z_errx(1, "can't lseek interp segment");
            if (z_read(fd, elf_interp, iter->p_filesz) !=
                    (ssize_t)iter->p_filesz)
                z_errx(1, "can't read interp segment");
            if (elf_interp[iter->p_filesz - 1] != '\0')
                z_errx(1, "bogus interp path");
            file = elf_interp;
        }

        z_close(fd);
        /* Looks like the ELF is static -- leave the loop. */
        if (elf_interp == NULL)
            break;
    }

    setup_auxv(av, base, ehdrs, entry, elf_interp, argv);
    // Don't increment av here, it's already handled in setup_auxv

    debug("jumping to entry point %p\n", (void*)(elf_interp ? entry[Z_INTERP] : entry[Z_PROG]));
    z_trampo((void (*)(void))(elf_interp ?
            entry[Z_INTERP] : entry[Z_PROG]), sp, z_fini);
    /* Should not reach. */
    z_exit(0);
}

void z_entry(unsigned long *sp, void (*fini)(void))
{
    char **argv, **env;
    Elf_auxv_t *av;
    int argc;
    const char *elf_file;
    const char *osroot_to_use;

    (void)fini;

    // Initialize environment and parse arguments
    initialize_environment(sp, &argv, &env, &av, &argc);

    // Determine elf_file to execute and osroot to use
    determine_file_and_osroot(&elf_file, &osroot_to_use);

    // Mount the epkg root
    mount_os_root(osroot_to_use);

    // Load and execute ELF
    load_and_execute_elf(elf_file, argv, sp, av);
}

