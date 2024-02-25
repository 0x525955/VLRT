#define PE_HEADER(image) ((IMAGE_NT_HEADERS64*)((uint64_t)image + ((IMAGE_DOS_HEADER*)image)->e_lfanew))

namespace utils
{
	auto PID(std::string name) -> int
	{
		const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

		PROCESSENTRY32 entry{ };
		entry.dwSize = sizeof(PROCESSENTRY32);

		Process32First(snapshot, &entry);
		do
		{
			if (!name.compare(entry.szExeFile))
			{
				if (entry.cntThreads > 3)
					return entry.th32ProcessID;
			}

		} while (Process32Next(snapshot, &entry));

		return 0;
	}

	auto read_file(const std::string filename) -> std::vector<uint8_t>
	{
		std::ifstream stream(filename, std::ios::binary);

		std::vector<uint8_t> buffer{ };

		buffer.assign((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());

		stream.close();

		return buffer;
	}

	HHOOK InvokeSignedDllRemoteFunction(int32_t pid, uintptr_t host_dll_handle, uint8_t* entry_address)
	{
		/*	find the threads associated with this target process	*/
		HHOOK retn{};
		struct EnumWindowsParam
		{
			uint8_t* entry_address;
			uintptr_t host_dll_handle;
			uint32_t pid;
			HHOOK* retn;
		} parameter;

		parameter.pid = pid;
		parameter.entry_address = entry_address;
		parameter.host_dll_handle = host_dll_handle;
		parameter.retn = &retn;

		EnumWindows(
			(WNDENUMPROC)[](HWND hwnd, LPARAM lparam) -> BOOL CALLBACK {

				auto parameter = (EnumWindowsParam*)lparam;

				unsigned long process_id = 0;

				auto thread_id = GetWindowThreadProcessId(hwnd, &process_id);

				if (parameter->pid != process_id)
				{
					return TRUE;
				}
				else
				{
					auto hook = SetWindowsHookExA(WH_GETMESSAGE,
						(HOOKPROC)parameter->entry_address, (HINSTANCE)parameter->host_dll_handle, thread_id);

					if (GetLastError() == 0)
					{
						PostThreadMessageW(thread_id, 0x123, 0, 0);

						Sleep(150);

						*parameter->retn = hook;

						//auto status = UnhookWindowsHookEx(hook);

						//std::cout << "UnhookWindowsHookEx " << std::hex << status << " GetLastError() " << GetLastError() << std::endl;

						return FALSE;
					}

					std::cout << " GetLastError() 0x" << std::hex << GetLastError() << std::endl;

					return TRUE;
				}
			},
			(LPARAM)&parameter);

		static bool entrypoint_patched = false;

		return retn;
	}

	HHOOK LoadSignedHostDLL(int32_t pid, const char* signed_dll_name)
	{
		/*	First, Load the host DLL (OWClient.dll) in our process 	*/

		auto host_dll = (uintptr_t)LoadLibraryExA(
			signed_dll_name, nullptr, DONT_RESOLVE_DLL_REFERENCES);

		/*	Find ret (0xC3) instruction	*/

		uintptr_t ret_byte = 0;

		for (ret_byte = (uintptr_t)host_dll + 0x1000; *(uint8_t*)ret_byte != 0xC3; ++ret_byte)
		{
		}

		/*	Execute a ret using SetWindowsHookEx in target process to load the signed DLL in the target process	*/

		return InvokeSignedDllRemoteFunction(pid, host_dll, (uint8_t*)ret_byte);
	}
}