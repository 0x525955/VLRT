#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include <windef.h>
#include <intrin.h>
#include <ntstrsafe.h>

#include "imports.h"
#include "ia32.h"
#include "definitions.h"
#include "encrypt.h"
#include "crt.h"
#include "utils.h"
#include "interface.h"
#include "cache.h"
#include "cleaning.h"

void hook_clear()
{
	PVOID* function = reinterpret_cast<PVOID*>(utils::get_kernel_export("\\SystemRoot\\System32\\drivers\\dxgkrnl.sys",
		"NtQueryCompositionSurfaceStatistics"));

	utils::write_to_read_only_memory(function, &cache::original_byte, sizeof(cache::original_byte));
}

NTSTATUS communication_handler(void* a1)
{
	if (!a1 || ExGetPreviousMode() != UserMode || reinterpret_cast<request_data*>(a1)->unique != request_unique)
		return STATUS_UNSUCCESSFUL;
	
	const auto request = reinterpret_cast<request_data*>(a1);

	switch (request->code)
	{
	case request_base:
	{
		base_request data{ 0 };

		if (!utils::safe_copy(&data, request->data, sizeof(base_request)))
		{
			return 0;
		}

		if (!data.name || !data.pid)
		{
			return 0;
		}

		const auto base = utils::get_module_handle(data.pid, data.name);

		if (!base)
		{
			return 0;
		}

		reinterpret_cast<base_request*>(request->data)->handle = base;

		return request_success;
	}
	case request_write:
	{
		write_request data{ 0 };

		if (!utils::safe_copy(&data, request->data, sizeof(write_request)))
		{
			return 0;
		}

		if (!data.address || !data.pid || !data.buffer || !data.size)
		{
			return 0;
		}

		PEPROCESS process;
		if (PsLookupProcessByProcessId((HANDLE)data.pid, &process) == STATUS_SUCCESS)
		{
			//if (data.force_write)
			//	utils::expose_kernel_memory(data.pid, data.address, data.size);

			size_t bytes = 0;
			auto status = MmCopyVirtualMemory(PsGetCurrentProcess(), (void*)reinterpret_cast<write_request*>(request->data)->buffer, process, (void*)data.address, data.size, KernelMode, &bytes);

			ObDereferenceObject(process);
		}
		else
		{
			return 0;
		}

		return request_success;
	}
	case request_read:
	{
		read_request data{ 0 };

		if (!utils::safe_copy(&data, request->data, sizeof(read_request)))
		{
			return 0;
		}

		if (!data.address || !data.pid || !data.buffer || !data.size)
		{
			return 0;
		}

		PEPROCESS process;
		if (PsLookupProcessByProcessId((HANDLE)data.pid, &process) == STATUS_SUCCESS)
		{
			size_t bytes = 0;
			if (MmCopyVirtualMemory(process, (void*)data.address, IoGetCurrentProcess(), reinterpret_cast<write_request*> (request->data)->buffer, data.size, KernelMode, &bytes) != STATUS_SUCCESS || bytes != data.size)
			{
				ObDereferenceObject(process);
				return 0;
			}

			ObDereferenceObject(process);
		}
		else
		{
			return 0;
		}

		return request_success;
	}
	case request_pattern:
	{
		pattern_request data{ 0 };

		if (!utils::safe_copy(&data, request->data, sizeof(pattern_request)))
		{
			return 0;
		}

		PEPROCESS process;
		if (PsLookupProcessByProcessId((HANDLE)data.pid, &process) == STATUS_SUCCESS)
		{
			const auto o_process = utils::swap_process((uintptr_t)process);

			if (!o_process)
			{
				utils::swap_process((uintptr_t)o_process);

				ObDereferenceObject(process);

				return 0;
			}

			const auto address = utils::find_pattern(data.base, data.signature);

			utils::swap_process(o_process);

			ObDereferenceObject(process);

			if (!address)
			{
				return 0;
			}

			reinterpret_cast<pattern_request*>(request->data)->address = address;
		}
		else
		{
			return 0;
		}

		return request_success;
	}
	case request_swap:
	{
		swap_request data{ 0 };

		if (!utils::safe_copy(&data, request->data, sizeof(allocate_request)))
		{
			return 0;
		}

		if (!data.src || !data.dst || !data.pid)
		{
			return 0;
		}

		PEPROCESS process;
		if (PsLookupProcessByProcessId((HANDLE)data.pid, &process) == STATUS_SUCCESS)
		{
			const auto o_process = utils::swap_process((uintptr_t)process);

			if (!o_process)
			{
				utils::swap_process((uintptr_t)o_process);

				ObDereferenceObject(process);

				return 0;
			}

			uintptr_t old = 0;

			*(void**)&old = InterlockedExchangePointer((void**)data.src, (void*)data.dst);

			utils::swap_process((uintptr_t)o_process);

			ObDereferenceObject(process);

			if (!old)
			{
				return 0;
			}

			reinterpret_cast<swap_request*> (request->data)->old = old;

			return request_success;
		}

		return 0;
	}
	case request_allocate:
	{
		allocate_request data{ 0 };

		if (!utils::safe_copy(&data, request->data, sizeof(allocate_request)))
		{
			return 0;
		}

		if (!data.name || !data.pid)
		{
			return 0;
		}
		
		const auto module = utils::get_module(data.pid, data.name, data.size);

		if (!module)
		{
			return 0;
		}

		const auto new_base = utils::extend(data.pid, module, data.size);

		if (!new_base)
		{
			return 0;
		}

		reinterpret_cast<allocate_request*>(request->data)->handle = (uintptr_t)new_base;

		return request_success;
	}
	case request_protect:
	{
		protect_request data{ 0 };

		if (!utils::safe_copy(&data, request->data, sizeof(protect_request)))
		{
			return 0;
		}

		if (!data.pid || !data.address)
		{
			return 0;
		}

		PEPROCESS target_proc;
		if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)data.pid, &target_proc)))
			return 0;

		const auto o_process = utils::swap_process((uintptr_t)target_proc);

		ULONG old;
		ZwProtectVirtualMemory(ZwCurrentProcess(), &data.address, &data.size, data.protect, &old);


		utils::swap_process(o_process);

		ObDereferenceObject(target_proc);

		return request_success;
	}
	case request_unload:
	{
		hook_clear();
	}
	}

	return 0;
}

bool hook_initalize()
{
	PVOID* function = reinterpret_cast<PVOID*>(utils::get_kernel_export("\\SystemRoot\\System32\\drivers\\dxgkrnl.sys",
		"NtQueryCompositionSurfaceStatistics"));

	if (!function)
		return false;

	BYTE orig[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	BYTE shell_code[] = { 0x48, 0xB8 }; // mov rax, xxx
	BYTE shell_code_end[] = { 0xFF, 0xE0 }; //jmp rax

	memcpy(cache::original_byte, function, 12);
	memcpy((PVOID)((ULONG_PTR)orig), &shell_code, sizeof(shell_code));
	uintptr_t hook_address = reinterpret_cast<uintptr_t>(communication_handler);
	memcpy((PVOID)((ULONG_PTR)orig + sizeof(shell_code)), &hook_address, sizeof(void*));
	memcpy((PVOID)((ULONG_PTR)orig + sizeof(shell_code) + sizeof(void*)), &shell_code_end, sizeof(shell_code_end));

	utils::write_to_read_only_memory(function, &orig, sizeof(orig));

	return true;
}

NTSTATUS DriverEntry(UINT64 hash, UINT64)
{
	if (hash != 0x1A3A3A7)
	{
		*(int*)0x18181818 = 0x1337;
	}

	uintptr_t base = utils::get_kernel_module("ntoskrnl.exe");
	/*
	uintptr_t addr = utils::find_pattern(base, "\x41\xB8\x00\x00\x00\x00\x48\x8B\xD6\x49\x8B\xCE\xE8\x00\x00\x00\x00\x48\x8B\xD8", "xx????xxxxxxx????xxx");
	if (!addr) {
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	*(PVOID*)&utils::MiAllocateVad = RELATIVE_ADDR(addr + 12, 5);

	// MiInsertVadCharges
	addr = utils::find_pattern(base, "\xE8\x00\x00\x00\x00\x8B\xF8\x85\xC0\x78\x31", "x????xxxxxx");
	if (!addr) {
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	*(PVOID*)&utils::MiInsertVadCharges = RELATIVE_ADDR(addr, 5);

	// MiInsertVad
	addr = utils::find_pattern(base, "\x48\x2B\xD1\x48\xFF\xC0\x48\x03\xC2", "xxxxxxxxx");
	if (!addr) {
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	for (; *(BYTE*)addr != 0xE8 || *(BYTE*)(addr + 5) != 0x8B; ++addr);
	*(PVOID*)&utils::MiInsertVad = RELATIVE_ADDR(addr, 5);
	*/

	if (!base)
		return STATUS_UNSUCCESSFUL;

	*(uintptr_t*)&utils::MiAllocateVad = utils::find_pattern(base, "\x48\x89\x5C\x24\x00\x48\x89\x6C\x24\x00\x48\x89\x74\x24\x00\x57\x48\x83\xEC\x30\x48\x8B\xE9\x41\x8B\xF8\xB9\x00\x00\x00\x00\x48\x8B\xF2\x8B\xD1\x41\xB8\x00\x00\x00\x00", "xxxx?xxxx?xxxx?xxxxxxxxxxxx????xxxxxxx????");
	*(uintptr_t*)&utils::MiInsertVadCharges = utils::find_pattern(base, "\x48\x89\x5C\x24\x00\x48\x89\x6C\x24\x00\x48\x89\x74\x24\x00\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x83\xEC\x20\x8B\x41\x18\x48\x8B\xD9\x44\x0F\xB6\x71\x00\x45\x33\xE4", "xxxx?xxxx?xxxx?xxxxxxxxxxxxxxxxxxxxxxx?xxx");
	*(uintptr_t*)&utils::MiInsertVad = utils::find_pattern(base, "\x48\x89\x5C\x24\x00\x48\x89\x6C\x24\x00\x48\x89\x74\x24\x00\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x83\xEC\x20\x8B\x41\x1C\x33\xED\x0F\xB6\x59\x21", "xxxx?xxxx?xxxx?xxxxxxxxxxxxxxxxxxxxxx");

	hook_initalize();

	return STATUS_SUCCESS;
}