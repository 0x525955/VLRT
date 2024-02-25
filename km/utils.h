namespace utils
{
	PMMVAD(*MiAllocateVad)(UINT_PTR start, UINT_PTR end, LOGICAL deletable) = nullptr;
	NTSTATUS(*MiInsertVadCharges)(PMMVAD vad, PEPROCESS process) = nullptr;
	VOID(*MiInsertVad)(PMMVAD vad, PEPROCESS process) = nullptr;

	uintptr_t swap_process(uintptr_t new_process)
	{
		auto current_thread = (uintptr_t)KeGetCurrentThread();

		auto apc_state = *(uintptr_t*)(current_thread + 0x98);
		auto old_process = *(uintptr_t*)(apc_state + 0x20);
		*(uintptr_t*)(apc_state + 0x20) = new_process;

		auto dir_table_base = *(uintptr_t*)(new_process + 0x28);
		__writecr3(dir_table_base);

		return old_process;
	}

	uintptr_t resolve_relative_address(uintptr_t instruction, ULONG offset_offset, ULONG instruction_size)
	{
		auto instr = instruction;

		const auto rip_offset = *(PLONG)(instr + offset_offset);

		const auto resolved_addr = instr + instruction_size + rip_offset;

		return resolved_addr;
	}

	void* get_system_information(SYSTEM_INFORMATION_CLASS information_class)
	{
		unsigned long size = 32;
		char buffer[32];

		ZwQuerySystemInformation(information_class, buffer, size, &size);

		void* info = ExAllocatePoolZero(NonPagedPool, size, 7265746172);

		if (!info)
			return nullptr;

		if (!NT_SUCCESS(ZwQuerySystemInformation(information_class, info, size, &size)))
		{
			ExFreePool(info);
			return nullptr;
		}

		return info;
	}

	uintptr_t get_kernel_base()
	{
		uintptr_t addr = 0;

		ULONG size = 0;
		NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &size);
		if (STATUS_INFO_LENGTH_MISMATCH != status) {
			return addr;
		}

		PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPool, size);
		if (!modules) {
			return addr;
		}

		if (!NT_SUCCESS(status = ZwQuerySystemInformation(SystemModuleInformation, modules, size, 0))) {
			ExFreePool(modules);
			return addr;
		}

		if (modules->NumberOfModules > 0) {
			addr = (uintptr_t)modules->Modules[0].ImageBase;
		}

		ExFreePool(modules);
		return addr;
	}

	uintptr_t get_kernel_module(const char* name)
	{
		const auto to_lower = [](char* string) -> const char*
			{
				for (char* pointer = string; *pointer != '\0'; ++pointer)
				{
					*pointer = (char)(short)tolower(*pointer);
				}

				return string;
			};

		const PRTL_PROCESS_MODULES info = (PRTL_PROCESS_MODULES)get_system_information(SystemModuleInformation);

		if (!info)
			return NULL;

		for (size_t i = 0; i < info->NumberOfModules; ++i)
		{
			const auto& mod = info->Modules[i];

			if (crt::strcmp(to_lower_c((char*)mod.FullPathName + mod.OffsetToFileName), name) == 0 || crt::strcmp(to_lower_c((char*)mod.FullPathName), name) == 0)
			{
				const void* address = mod.ImageBase;
				ExFreePool(info);
				return (uintptr_t)address;
			}
		}

		ExFreePool(info);
		return NULL;
	}

	auto get_kernel_export(const char* module_name, LPCSTR export_name) -> uintptr_t
	{
		return reinterpret_cast<uintptr_t> (RtlFindExportedRoutineByName(reinterpret_cast<void*> (utils::get_kernel_module(module_name)), export_name));
	}

	void sleep(int ms)
	{
		LARGE_INTEGER time;
		time.QuadPart = -(ms) * 10 * 1000;
		KeDelayExecutionThread(KernelMode, TRUE, &time);
	}

	uintptr_t find_pattern(uintptr_t base, size_t range, const char* pattern, const char* mask)
	{
		const auto check_mask = [](const char* base, const char* pattern, const char* mask) -> bool
			{
				for (; *mask; ++base, ++pattern, ++mask)
				{
					if (*mask == 'x' && *base != *pattern)
					{
						return false;
					}
				}

				return true;
			};

		range = range - crt::strlen(mask);

		for (size_t i = 0; i < range; ++i)
		{
			if (check_mask((const char*)base + i, pattern, mask))
			{
				return base + i;
			}
		}

		return NULL;
	}

	uintptr_t find_pattern(uintptr_t base, const char* pattern, const char* mask)
	{
		const PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
		const PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);

		for (size_t i = 0; i < headers->FileHeader.NumberOfSections; i++)
		{
			const PIMAGE_SECTION_HEADER section = &sections[i];

			if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE)
			{
				const auto match = find_pattern(base + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);

				if (match)
				{
					return match;
				}
			}
		}

		return 0;
	}

	uintptr_t find_pattern(uintptr_t module_base, const char* pattern)
	{
		auto pattern_ = pattern;
		uintptr_t first_match = 0;

		if (!module_base)
		{
			return 0;
		}

		const auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(module_base + reinterpret_cast<IMAGE_DOS_HEADER*>(module_base)->e_lfanew);

		for (uintptr_t current = module_base; current < module_base + nt->OptionalHeader.SizeOfImage; current++)
		{
			if (!*pattern_)
			{
				return first_match;
			}

			if (*(BYTE*)pattern_ == '\?' || *(BYTE*)current == get_byte(pattern_))
			{
				if (!first_match)
					first_match = current;

				if (!pattern_[2])
					return first_match;

				if (*(WORD*)pattern_ == '\?\?' || *(BYTE*)pattern_ != '\?')
					pattern_ += 3;

				else
					pattern_ += 2;
			}
			else
			{
				pattern_ = pattern;
				first_match = 0;
			}
		}

		return 0;
	}

	uintptr_t find_pattern_executable(uintptr_t module_base, const char* pattern)
	{
		auto pattern_ = pattern;
		uintptr_t first_match = 0;

		if (!module_base)
		{
			return 0;
		}

		const auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(module_base + reinterpret_cast<IMAGE_DOS_HEADER*>(module_base)->e_lfanew);

		for (uintptr_t current = module_base; current < module_base + nt->OptionalHeader.SizeOfImage; current++)
		{
			if (!*pattern_)
			{
				return first_match;			
			}

			if (*(BYTE*)pattern_ == '\?' || *(BYTE*)current == get_byte(pattern_))
			{
				if (!first_match)
					first_match = current;

				if (!pattern_[2])
				{
					MEMORY_BASIC_INFORMATION info = { 0 };
					if (NT_SUCCESS(ZwQueryVirtualMemory(NtCurrentProcess(), (PVOID)first_match, MemoryBasicInformation, &info, sizeof(info), NULL)))
					{
						if (info.Protect & PAGE_EXECUTE)
							return first_match;
					}
				}

				if (*(WORD*)pattern_ == '\?\?' || *(BYTE*)pattern_ != '\?')
					pattern_ += 3;

				else
					pattern_ += 2;
			}
			else
			{
				pattern_ = pattern;
				first_match = 0;
			}
		}

		return 0;
	}

	uintptr_t get_module_handle(uintptr_t pid, LPCWSTR module_name)
	{
		PEPROCESS target_proc;
		uintptr_t base = 0;
		if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &target_proc)))
			return 0;

		const auto o_process = swap_process((uintptr_t)target_proc);

		PPEB peb = PsGetProcessPeb(target_proc);
		if (!peb)
			goto end;

		if (!peb->Ldr || !peb->Ldr->Initialized)
			goto end;


		UNICODE_STRING module_name_unicode;
		RtlInitUnicodeString(&module_name_unicode, module_name);
		for (PLIST_ENTRY list = peb->Ldr->InLoadOrderModuleList.Flink;
			list != &peb->Ldr->InLoadOrderModuleList;
			list = list->Flink) {
			PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			if (RtlCompareUnicodeString(&entry->BaseDllName, &module_name_unicode, TRUE) == 0) {
				base = (uintptr_t)entry->DllBase;
				goto end;
			}
		}

	end:

		swap_process((uintptr_t)o_process);

		ObDereferenceObject(target_proc);

		return base;
	}

	uintptr_t extend(uintptr_t pid, PLDR_DATA_TABLE_ENTRY _module, size_t size)
	{
		uintptr_t retn = 0;

		PEPROCESS target_proc;
		PLDR_DATA_TABLE_ENTRY base = 0;
		if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &target_proc)))
			return 0;

		const auto o_process = utils::swap_process((uintptr_t)target_proc);

		UINT_PTR start = (uintptr_t)_module->DllBase + _module->SizeOfImage;
		UINT_PTR end = start + size;

		//ULONG old;
		//ZwProtectVirtualMemory(ZwCurrentProcess(), (void**)&start, &size, PAGE_READWRITE, &old);

		PMMVAD vad = MiAllocateVad(start, end, TRUE);
		if (!vad) {
			goto cleanup;
		}

		PMMVAD_FLAGS flags = (PMMVAD_FLAGS)&vad->u.LongFlags;
		flags->Protection = 6;
		flags->NoChange = 0;

		if (!NT_SUCCESS(MiInsertVadCharges(vad, target_proc))) {
			ExFreePool(vad);
			goto cleanup;
		}

		MiInsertVad(vad, target_proc);

		retn = start;

		_module->SizeOfImage += size;

	cleanup:
		swap_process((uintptr_t)o_process);

		ObDereferenceObject(target_proc);

		return retn;
	}

	PLDR_DATA_TABLE_ENTRY get_module(uintptr_t pid, LPCWSTR module_name, size_t size)
	{
		PEPROCESS target_proc;
		PLDR_DATA_TABLE_ENTRY base = 0;
		if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &target_proc)))
			return 0;

		const auto o_process = swap_process((uintptr_t)target_proc);

		PPEB peb = PsGetProcessPeb(target_proc);
		if (!peb)
			goto end;

		if (!peb->Ldr || !peb->Ldr->Initialized)
			goto end;


		UNICODE_STRING module_name_unicode;
		RtlInitUnicodeString(&module_name_unicode, module_name);
		for (PLIST_ENTRY list = peb->Ldr->InLoadOrderModuleList.Flink;
			list != &peb->Ldr->InLoadOrderModuleList;
			list = list->Flink) {
			PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			//if (RtlCompareUnicodeString(&entry->BaseDllName, &module_name_unicode, TRUE) == 0)
			{
				UINT_PTR start = (UINT_PTR)entry->DllBase + entry->SizeOfImage;
				UINT_PTR end = start + size + 1;

				MEMORY_BASIC_INFORMATION info = { 0 };
				MEMORY_BASIC_INFORMATION next_info = { 0 };
				if (NT_SUCCESS(ZwQueryVirtualMemory(NtCurrentProcess(), (PVOID)start, MemoryBasicInformation, &info, sizeof(info), NULL)))
				{
					if (info.State == MEM_FREE && info.BaseAddress == (PVOID)start && info.RegionSize > size) {
						base = entry;
					}
				}
			}
		}

	end:

		swap_process((uintptr_t)o_process);

		ObDereferenceObject(target_proc);

		return base;
	}

	TABLE_SEARCH_RESULT
		MiFindNodeOrParent(
			IN PMM_AVL_TABLE Table,
			IN ULONG_PTR StartingVpn,
			OUT PMMADDRESS_NODE* NodeOrParent
		) {
		PMMADDRESS_NODE Child;
		PMMADDRESS_NODE NodeToExamine;
		PMMVAD    VpnCompare;
		ULONG_PTR       startVpn;
		ULONG_PTR       endVpn;

		if (Table->NumberGenericTableElements == 0) {
			return TableEmptyTree;
		}

		NodeToExamine = (PMMADDRESS_NODE)(Table->BalancedRoot);

		for (;;) {

			VpnCompare = (PMMVAD)NodeToExamine;
			startVpn = VpnCompare->StartingVpn;
			endVpn = VpnCompare->EndingVpn;

#if defined( _WIN81_ ) || defined( _WIN10_ )
			startVpn |= (ULONG_PTR)VpnCompare->StartingVpnHigh << 32;
			endVpn |= (ULONG_PTR)VpnCompare->EndingVpnHigh << 32;
#endif  

			//
			// Compare the buffer with the key in the tree element.
			//

			if (StartingVpn < startVpn) {

				Child = NodeToExamine->LeftChild;

				if (Child != NULL) {
					NodeToExamine = Child;
				}
				else {

					//
					// Node is not in the tree.  Set the output
					// parameter to point to what would be its
					// parent and return which child it would be.
					//

					*NodeOrParent = NodeToExamine;
					return TableInsertAsLeft;
				}
			}
			else if (StartingVpn <= endVpn) {

				//
				// This is the node.
				//

				*NodeOrParent = NodeToExamine;
				return TableFoundNode;
			}
			else {

				Child = NodeToExamine->RightChild;

				if (Child != NULL) {
					NodeToExamine = Child;
				}
				else {

					//
					// Node is not in the tree.  Set the output
					// parameter to point to what would be its
					// parent and return which child it would be.
					//

					*NodeOrParent = NodeToExamine;
					return TableInsertAsRight;
				}
			}

		};
	}

	NTSTATUS FindVAD(
		IN PEPROCESS pProcess,
		IN ULONG_PTR address,
		OUT PMMVAD* pResult
	) {
		NTSTATUS status = STATUS_SUCCESS;
		ULONG_PTR vpnStart = address >> PAGE_SHIFT;

		ASSERT(pProcess != NULL && pResult != NULL);
		if (pProcess == NULL || pResult == NULL)
			return STATUS_INVALID_PARAMETER;


		PMM_AVL_TABLE pTable = (PMM_AVL_TABLE)((PUCHAR)pProcess + 0x7d8);
		PMM_AVL_NODE pNode = (pTable->BalancedRoot);

		if (MiFindNodeOrParent(pTable, vpnStart, &pNode) == TableFoundNode) {
			*pResult = (PMMVAD)pNode;
		}
		else {
			status = STATUS_NOT_FOUND;
		}

		return status;
	}

	void set_vad(const int pid, void* address)
	{
		PEPROCESS process;
		if (PsLookupProcessByProcessId((HANDLE)pid, &process) == STATUS_SUCCESS)
		{
			PMMVAD out;
			if (NT_SUCCESS(FindVAD(process, (ULONG_PTR)address, &out)))
			{
				out->u.VadFlags.Protection = PAGE_READWRITE;

				DbgPrintEx(0, 0, "wriiten\n");
			}

			ObDereferenceObject(process);
		}
	}

	bool safe_copy(void* dst, void* src, size_t size)
	{
		SIZE_T bytes = 0;

		if (MmCopyVirtualMemory(IoGetCurrentProcess(), src, IoGetCurrentProcess(), dst, size, KernelMode, &bytes) == STATUS_SUCCESS && bytes == size)
		{
			return true;
		}

		return false;
	}

	MEMORY_BASIC_INFORMATION query_virtual_memory(void* address)
	{
		MEMORY_BASIC_INFORMATION mbi;
		ZwQueryVirtualMemory((HANDLE)-1, address, MemoryBasicInformation, &mbi, sizeof(MEMORY_BASIC_INFORMATION), 0);
		return mbi;
	}

	PAGE_INFORMATION get_page_information(void* va, CR3 cr3)
	{
		ADDRESS_TRANSLATION_HELPER helper;
		UINT32 level;
		PML4E_64* pml4, * pml4e;
		PDPTE_64* pdpt, * pdpte;
		PDE_64* pd, * pde;
		PTE_64* pt, * pte;

		PAGE_INFORMATION info;

		helper.AsUInt64 = (uintptr_t)va;

		PHYSICAL_ADDRESS pa;

		pa.QuadPart = cr3.AddressOfPageDirectory << PAGE_SHIFT;

		pml4 = (PML4E_64*)MmGetVirtualForPhysical(pa);

		pml4e = &pml4[helper.AsIndex.Pml4];

		info.PML4E = pml4e;

		if (pml4e->Present == FALSE)
		{
			info.PTE = nullptr;
			info.PDE = nullptr;
			info.PDPTE = nullptr;

			goto end;
		}

		pa.QuadPart = pml4e->PageFrameNumber << PAGE_SHIFT;

		pdpt = (PDPTE_64*)MmGetVirtualForPhysical(pa);

		pdpte = &pdpt[helper.AsIndex.Pdpt];

		info.PDPTE = pdpte;

		if ((pdpte->Present == FALSE) || (pdpte->LargePage != FALSE))
		{
			info.PTE = nullptr;
			info.PDE = nullptr;

			goto end;
		}

		pa.QuadPart = pdpte->PageFrameNumber << PAGE_SHIFT;

		pd = (PDE_64*)MmGetVirtualForPhysical(pa);

		pde = &pd[helper.AsIndex.Pd];

		info.PDE = pde;

		if ((pde->Present == FALSE) || (pde->LargePage != FALSE))
		{
			info.PTE = nullptr;

			goto end;
		}

		pa.QuadPart = pde->PageFrameNumber << PAGE_SHIFT;

		pt = (PTE_64*)MmGetVirtualForPhysical(pa);

		pte = &pt[helper.AsIndex.Pt];

		info.PTE = pte;

		return info;

	end:
		return info;
	}

	void free_mdl_memory(MDL_INFORMATION& memory)
	{
		MmUnmapLockedPages(reinterpret_cast<void*>(memory.va), memory.mdl);
		MmFreePagesFromMdl(memory.mdl);
		ExFreePool(memory.mdl);
	}

	bool expose_kernel_memory(const int pid, const uintptr_t kernel_address, size_t size)
	{
		PEPROCESS process;
		if (PsLookupProcessByProcessId((HANDLE)pid, &process) == STATUS_SUCCESS)
		{
			const auto o_process = utils::swap_process((uintptr_t)process);

			CR3 cr3{ };
			cr3.Flags = __readcr3();

			for (uintptr_t address = kernel_address; address <= kernel_address + size; address += 0x1000)
			{
				const auto page_information = utils::get_page_information((void*)address, cr3);
				auto pte = page_information.PTE;

			//	pte->ExecuteDisable = 0;
				pte->Write = 1;

				//DbgPrintEx(0, 0, "written\n");
			}

			utils::swap_process((uintptr_t)o_process);
		}
		else
		{
			return false;
		}

		return true;
	}

	bool write_to_read_only_memory(void* address, void* buffer, size_t size)
	{
		PMDL pMdl = IoAllocateMdl(address, sizeof(uintptr_t), FALSE, FALSE, NULL);

		if (!pMdl)
			return false;

		MmProbeAndLockPages(pMdl, KernelMode, IoReadAccess);

		void* target_remapped = MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmNonCached, NULL, FALSE, HighPagePriority);

		if (!target_remapped)
			return STATUS_BAD_DATA;

		RtlCopyMemory(target_remapped, buffer, size);

		MmUnmapLockedPages(target_remapped, pMdl);
		MmUnlockPages(pMdl);
		IoFreeMdl(pMdl);

		return true;
	}
}