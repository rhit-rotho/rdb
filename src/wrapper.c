#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <pthread.h>
#include <sys/auxv.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <string.h>
#include <capstone/capstone.h>

#define xperror(en, msg)    \
	do                      \
	{                       \
		errno = en;         \
		perror(msg);        \
		exit(EXIT_FAILURE); \
	} while (0)

static void *start_trace(void *args);

pthread_t p;

uint8_t x = __asm__("call rax");

__attribute__((constructor)) static void wrapper_init(void)
{
	void *entry = (void *)getauxval(AT_ENTRY);
	mprotect((uintptr_t)entry & ~(sysconf(_SC_PAGE_SIZE) - 1), sysconf(_SC_PAGE_SIZE), PROT_READ | PROT_WRITE);
	uint8_t patch[] = {0xc2};
	memcpy(entry, patch, sizeof(patch) / sizeof(uint8_t));
	mprotect((uintptr_t)entry & ~(sysconf(_SC_PAGE_SIZE) - 1), sysconf(_SC_PAGE_SIZE), PROT_READ | PROT_EXEC);

	int ret = pthread_create(&p, NULL, start_trace, NULL);
	if (ret)
		xperror(ret, "pthread_create");
}

__attribute__((destructor)) static void wrapper_fini(void)
{
}

static void *start_trace(void *args)
{
	time_t t;

	FILE *cstdout = fopen("stdout.txt", "w");
	FILE *cstderr = fopen("stderr.txt", "w");
	setbuf(cstdout, NULL);
	setbuf(cstderr, NULL);

	// let's have some fun
	void *entry = (void *)getauxval(AT_ENTRY);
	csh handle;
	cs_insn *insn;
	size_t count;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return -1;
	count = cs_disasm(handle, entry, 0x80, entry, 0, &insn);
	if (count > 0)
	{
		size_t j;
		for (j = 0; j < count; j++)
		{
			fprintf(cstdout, "0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
					insn[j].op_str);
		}

		cs_free(insn, count);
	}
	else
		fprintf(cstderr, "ERROR: Failed to disassemble given code!\n");

	cs_close(&handle);

	for (;;)
	{
		sleep(1);
		time(&t);
		fprintf(cstdout, "%ld\n", t);
	}

	return NULL;
}
