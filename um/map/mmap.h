class mmap_t
{
private:
	unsigned char remote_call_dll_main[136] = {
		0x48, 0x83, 0xEC, 0x38,
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x48, 0x39, 0xFF, 
		0x90,
		0x39, 0xC0,
		0x90,
		0x48, 0x89, 0x44, 0x24, 0x20,
		0x90,
		0x48, 0x8B, 0x44, 0x24, 0x20, 
		0x90,
		0x83, 0x38, 0x00,
		0x90,
		0x75, 0x48, // or 0x55
		0x48, 0x8B, 0x44, 0x24, 0x20, 
		0x90, 0x90, 0x90,
		0xC7, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x90,
		0x48, 0x8B, 0x44, 0x24, 0x20,
		0x90, 
		0x48, 0x8B, 0x40, 0x08, 
		0x90, 
		0x48, 0x89, 0x44, 0x24, 0x28,
		0x90, 
		0x45, 0x33, 0xC0,
		0x90, 
		0xBA, 0x01, 0x00, 0x00, 0x00, 
		0x90, 0x90,
		0x48, 0x8B, 0x44, 0x24, 0x20,
		0x90,
		0x48, 0x8B, 0x48, 0x10, 
		0x90, 0x90,
		0xFF, 0x15, 0x02, 0x00, 0x00, 0x00, 0xEB, 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0x90,
		0x48, 0x8B, 0x44, 0x24, 0x20,
		0x90,
		0xC7, 0x00, 0xF1, 0x00, 0x00, 0x00, 
		0x90,
		0x48, 0x83, 0xC4, 0x38,
		0x90,
		0xC3, 
		0x90,
		0x48, 0x39, 0xC0, 
		0x90,
		0xCC
	};

	unsigned char remote_load_library[96] =
	{
		0x48, 0x83, 0xEC, 0x38, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x44, 0x24, 0x20,
		0x83, 0x38, 0x00, 0x75, 0x3D, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x40,
		0x08, 0x48, 0x89, 0x44, 0x24, 0x28, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x83, 0xC0, 0x18, 0x48, 0x8B, 0xC8, 0xFF, 0x54, 0x24, 0x28, 0x48, 0x8B,
		0x4C, 0x24, 0x20, 0x48, 0x89, 0x41, 0x10, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7, 0x00, 0x02, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x38, 0xC3, 0xCC
	}; 
	DWORD shell_data_offset = 0x6;

	typedef struct _load_library_struct
	{
		int status;
		uintptr_t fn_load_library_a;
		uintptr_t module_base;
		char module_name[80];
	}load_library_struct;

	typedef struct _remote_dll {
		INT status;
		uintptr_t dll_main_address;
		HINSTANCE dll_base;
	} remote_dll, * premote_dll;

	uintptr_t call_remote_load_library(const int pid, uintptr_t allocation, const char* dll_name)
	{
		static uintptr_t present_address = 0;

		if (!present_address)
		{
			const auto discord_base = kinterface->get_module_base(pid, "DiscordHook64.dll");

			if (!discord_base)
			{
				printf(xor_a("discord not found\n"));
				return false;
			}

			auto opcode = kinterface->find_signature(pid, discord_base, xor_a("48 8B 05 ?? ?? ?? ?? 48 89 D9 89 FA 41 89 F0 FF 15 ?? ?? ?? ?? 89 C6 48 89 E9"));

			if (!opcode)
			{
				printf(xor_a("opcode not found\n"));
				return false;
			}

			present_address = opcode + kinterface->read_virtual_memory<int32_t>(pid, opcode + 3) + 7;
		}

		if (present_address)
		{
			PVOID alloc_shell_code = (void*)allocation;
			DWORD shell_size = sizeof(remote_load_library) + sizeof(load_library_struct);
			PVOID alloc_local = VirtualAlloc(NULL, shell_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			/////////////////////////////////

			/////////////////////////////////
			RtlCopyMemory(alloc_local, &remote_load_library, sizeof(remote_load_library));
			uintptr_t shell_data = (uintptr_t)alloc_shell_code + sizeof(remote_load_library);
			*(uintptr_t*)((uintptr_t)alloc_local + shell_data_offset) = shell_data;
			load_library_struct* ll_data = (load_library_struct*)((uintptr_t)alloc_local + sizeof(remote_load_library));
			ll_data->fn_load_library_a = (uintptr_t)LoadLibraryA;
			strcpy_s(ll_data->module_name, 80, dll_name);
			/////////////////////////////////

			/////////////////////////////////
			if (!kinterface->write_virtual_memory(pid, (uintptr_t)allocation, alloc_local, shell_size))
			{
				printf(xor_a("write failed\n"));
				return false;
			}
			/////////////////////////////////

			const auto old_ptr = kinterface->swap_virtual_pointer(pid, present_address, (uintptr_t)allocation);

			if (!old_ptr)
			{
				return false;
			}

			/////////////////////////////////
			while (ll_data->status != 2)
			{
				kinterface->read_virtual_memory(pid, shell_data, (PVOID)ll_data, sizeof(load_library_struct));
				Sleep(1);
			} uintptr_t mod_base = ll_data->module_base;
			/////////////////////////////////

			if (!kinterface->swap_virtual_pointer(pid, present_address, old_ptr))
			{
				return false;
			}

			/////////////////////////////////
			VirtualFree(alloc_local, 0, MEM_RELEASE);
			/////////////////////////////////
			
			Sleep(50);

			return mod_base;
		}

		return 0;
	}

	auto get_nt_headers(const uintptr_t image_base) -> IMAGE_NT_HEADERS*
	{
		const auto dos_header = reinterpret_cast<IMAGE_DOS_HEADER*> (image_base);

		return reinterpret_cast<IMAGE_NT_HEADERS*> (image_base + dos_header->e_lfanew);
	}

	auto rva_va(const uintptr_t rva, IMAGE_NT_HEADERS* nt_header, void* local_image) -> void*
	{
		const auto first_section = IMAGE_FIRST_SECTION(nt_header);

		for (auto section = first_section; section < first_section + nt_header->FileHeader.NumberOfSections; section++)
		{
			if (rva >= section->VirtualAddress && rva < section->VirtualAddress + section->Misc.VirtualSize)
			{
				return (unsigned char*)local_image + section->PointerToRawData + (rva - section->VirtualAddress);
			}
		}

		return 0;
	}

	auto relocate_image(void* remote_image, void* local_image, IMAGE_NT_HEADERS* nt_header) -> bool
	{
		typedef struct _RELOC_ENTRY
		{
			ULONG ToRVA;
			ULONG Size;
			struct
			{
				WORD Offset : 12;
				WORD Type : 4;
			} Item[1];
		} RELOC_ENTRY, * PRELOC_ENTRY;

		const auto delta_offset = (uintptr_t)remote_image - nt_header->OptionalHeader.ImageBase;

		if (!delta_offset)
		{
			return true;
		}

		else if (!(nt_header->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE))
		{
			return false;
		}

		auto relocation_entry = (RELOC_ENTRY*)rva_va(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, nt_header, local_image);
		const auto relocation_end = (uintptr_t)relocation_entry + nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

		if (relocation_entry == nullptr)
		{
			return true;
		}

		while ((uintptr_t)relocation_entry < relocation_end && relocation_entry->Size)
		{
			auto records_count = (relocation_entry->Size - 8) >> 1;

			for (auto i = 0ul; i < records_count; i++)
			{
				WORD fixed_type = (relocation_entry->Item[i].Type);
				WORD shift_delta = (relocation_entry->Item[i].Offset) % 4096;

				if (fixed_type == IMAGE_REL_BASED_ABSOLUTE)
				{
					continue;
				}

				if (fixed_type == IMAGE_REL_BASED_HIGHLOW || fixed_type == IMAGE_REL_BASED_DIR64)
				{
					auto fixed_va = (uintptr_t)rva_va(relocation_entry->ToRVA, nt_header, local_image);

					if (!fixed_va)
					{
						fixed_va = (uintptr_t)local_image;
					}

					*(uintptr_t*)(fixed_va + shift_delta) += delta_offset;
				}
			}

			relocation_entry = (PRELOC_ENTRY)((LPBYTE)relocation_entry + relocation_entry->Size);
		}

		return true;
	}

	auto resolve_function_address(LPCSTR module_name, LPCSTR function_name) -> uintptr_t
	{
		const auto handle = LoadLibraryExA(module_name, nullptr, DONT_RESOLVE_DLL_REFERENCES);

		const auto offset = (uintptr_t)GetProcAddress(handle, function_name) - (uintptr_t)handle;

		FreeLibrary(handle);

		return offset;
	}

	auto write_sections(int pid, void* module_base, void* local_image, IMAGE_NT_HEADERS* nt_header) -> void
	{
		auto section = IMAGE_FIRST_SECTION(nt_header);

		for (WORD count = 0; count < nt_header->FileHeader.NumberOfSections; count++, section++)
		{
			if (!kinterface->write_virtual_memory(pid, (uintptr_t)((uintptr_t)module_base + section->VirtualAddress), (void*)((uintptr_t)local_image + section->PointerToRawData), section->SizeOfRawData))
				printf("write failed\n");
		}
	}

	auto resolve_import(void* local_image, IMAGE_NT_HEADERS* nt_header, uintptr_t allocation, int pid) -> bool
	{
		IMAGE_IMPORT_DESCRIPTOR* import_description = (IMAGE_IMPORT_DESCRIPTOR*)rva_va(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, nt_header, local_image);

		if (!nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress || !nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
		{
			return true;
		}

		LPSTR module_name = NULL;

		while ((module_name = (LPSTR)rva_va(import_description->Name, nt_header, local_image)))
		{
			const auto base_image = (ULONGLONG)LoadLibrary(module_name);// call_remote_load_library(pid, allocation, module_name);

			if (!base_image)
			{
				return false;
			}

			printf("%s : %p\n", module_name, base_image);

			auto import_header_data = (IMAGE_THUNK_DATA*)rva_va(import_description->FirstThunk, nt_header, local_image);

			while (import_header_data->u1.AddressOfData)
			{
				if (import_header_data->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				{
					import_header_data->u1.Function = base_image + resolve_function_address(module_name, (LPCSTR)(import_header_data->u1.Ordinal & 0xFFFF));
				}
				else
				{
					IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)rva_va(import_header_data->u1.AddressOfData, nt_header, local_image);
					import_header_data->u1.Function = base_image + resolve_function_address(module_name, (LPCSTR)ibn->Name);
				}
				import_header_data++;
			}
			import_description++;
		}

		return true;
	}

	auto erase_discardable_section(int pid, void* module_base, IMAGE_NT_HEADERS* nt_header) -> void
	{
		auto section = IMAGE_FIRST_SECTION(nt_header);

		for (WORD count = 0; count < nt_header->FileHeader.NumberOfSections; count++, section++)
		{
			if (section->SizeOfRawData == 0)
			{
				continue;
			}

			if (section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
			{
				auto zero_memory = VirtualAlloc(0, section->SizeOfRawData, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

				kinterface->write_virtual_memory(pid, (uintptr_t)((uintptr_t)module_base + section->VirtualAddress), zero_memory, section->SizeOfRawData);

				VirtualFree(zero_memory, 0, MEM_RELEASE);
			}


			if (!strcmp((char*)section->Name, ".text"))
			{
				//kinterface->protect_kernel_memory(pid, section->SizeOfRawData, (void*)((uintptr_t)module_base + section->VirtualAddress), PAGE_READWRITE);
				printf("text found\n");
			}
			else
				kinterface->protect_kernel_memory(pid, section->SizeOfRawData, (void*)((uintptr_t)module_base + section->VirtualAddress), PAGE_READWRITE);

		}
	}

	auto vmt_hook(const int pid, void* base, IMAGE_NT_HEADERS* nt_header, void* shellcode_allocation) -> bool
	{
		const auto shellcode_size = sizeof(remote_call_dll_main) + sizeof(remote_dll);

		const auto local_allocation = VirtualAlloc(0, shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		auto remote = (remote_dll*)((uintptr_t)local_allocation + sizeof(remote_call_dll_main));

		remote->dll_base = (HINSTANCE)base;

		remote->dll_main_address = ((uintptr_t)base + nt_header->OptionalHeader.AddressOfEntryPoint);

		memcpy(local_allocation, &remote_call_dll_main, sizeof(remote_call_dll_main));

		const auto shellcode_data = (uintptr_t)shellcode_allocation + sizeof(remote_call_dll_main);

		memcpy((void*)((uintptr_t)local_allocation + 0x6), &shellcode_data, sizeof(uintptr_t));

		memcpy((void*)((uintptr_t)local_allocation + 102), &remote->dll_main_address, sizeof(uintptr_t));

		if (!kinterface->write_virtual_memory(pid, (uintptr_t)shellcode_allocation, local_allocation, shellcode_size))
		{
			printf(xor_a("write failed\n"));
			return false;
		}

		printf("shellcode_allocation : %p\n", shellcode_allocation);

		printf("dll_main : %p\n", remote->dll_main_address);

		const auto discord_base = kinterface->get_module_base(pid, "DiscordHook64.dll");
		
		if (!discord_base)
		{
			printf(xor_a("discord not found\n"));
			return false;
		}

		auto opcode = kinterface->find_signature(pid, discord_base, xor_a("48 8B 05 ?? ?? ?? ?? 48 89 D9 89 FA 41 89 F0 FF 15 ?? ?? ?? ?? 89 C6 48 89 E9"));

		if (!opcode)
		{
			printf(xor_a("opcode not found\n"));
			return false;
		}

		const auto present_address = opcode + kinterface->read_virtual_memory<int32_t>(pid, opcode + 3) + 7;

		printf(xor_a("present_address: 0x%llx\n"), present_address);

		const auto old_ptr = kinterface->swap_virtual_pointer(pid, present_address, (uintptr_t)shellcode_allocation);

		if (!old_ptr)
		{
			return false;
		}

		printf(xor_a("waiting for execute\n"));

		while (remote->status != 0xF1)
		{
			kinterface->read_virtual_memory(pid, (uintptr_t)shellcode_data, remote, sizeof(remote_dll));
			Sleep(1);
		}

		if (!kinterface->swap_virtual_pointer(pid, present_address, old_ptr))
		{
			return false;
		}

		printf(xor_a("successfully executed\n"));

		VirtualFree(local_allocation, 0, MEM_RELEASE);

		return true;
	}

public:
	auto map(const int pid, void* buffer) -> bool
	{
		auto hook = utils::LoadSignedHostDLL(pid, xor_a("C:\\lm.x64.dll"));

		const auto nt_header = get_nt_headers(reinterpret_cast<uintptr_t>(buffer));
		printf(xor_a("nt_headers: 0x%llx\n"), nt_header);

		const auto base = kinterface->allocate_kernel_memory(pid, nt_header->OptionalHeader.SizeOfImage, "");
		const auto shellcode_base = (void*)(kinterface->get_module_base(pid, xor_a("lm.x64.dll")) + 0x5A000);

		if (!base)
		{
			printf(xor_a("invalid base\n"));
			return false;
		}

		if (shellcode_base == (void*)0x5A000)
		{
			printf(xor_a("invalid rwx\n"));
			return false;
		}

		if (!relocate_image(base, buffer, nt_header))
		{
			return false;
		}

		printf(xor_a("relocated image\n"));

		if (!resolve_import(buffer, nt_header, (uintptr_t)shellcode_base, pid))
		{
			return false;
		}

		printf(xor_a("resolved imports\n"));

		write_sections(pid, base, buffer, nt_header);
		printf(xor_a("wrote sections\n"));

		if (!vmt_hook(pid, base, nt_header, shellcode_base))
		{
			return false;
		}

		erase_discardable_section(pid, base, nt_header);
		printf(xor_a("erased discardable section\n"));

		//kinterface->protect_kernel_memory(pid, nt_header->OptionalHeader.SizeOfImage, base, PAGE_EXECUTE_READ);

		VirtualFree(buffer, 0, MEM_RELEASE);

		//UnhookWindowsHookEx(hook);

		return true;
	}
};

static mmap_t* mmap = new mmap_t();