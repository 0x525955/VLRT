#include <windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>

#include "interface/kinterface.h"
#include "utils/utils.h"
#include "map/mmap.h"
#include "xor.h"

void main()
{
	//VALORANT-Win64-Shipping
	const auto pid = utils::PID(xor_a("VALORANT-Win64-Shipping.exe"));

	if (pid) {
		kinterface->initialize();
		mmap->map(pid, utils::read_file(xor_a("vlrt.dll")).data());
	}
	else {
		printf(xor_a("game not found \n"));
	}

	getchar();
}
