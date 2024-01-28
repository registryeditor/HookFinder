#include <Windows.h>
#include <iostream>
#include <string>
#include <tlhelp32.h>
#include <winnt.h>

void DumpListOfExport(void *lib, bool checkNt);
void CheckJmp(std::string name, DWORD* address, bool checkNt);
void ListLoadedDlls();

HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

void ListLoadedDlls() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    MODULEENTRY32 moduleEntry;
    moduleEntry.dwSize = sizeof(MODULEENTRY32);

    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    std::cout << "Listing loaded modules!\n";
    SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::cout << "------------------------------------------\n";
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    if (Module32First(hSnapshot, &moduleEntry)) {
        do {
            std::cout << moduleEntry.szExePath << " is loaded at ";
            SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            std::cout << static_cast<void*>(moduleEntry.modBaseAddr);
            SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            std::cout << ".\n";
        } while (Module32Next(hSnapshot, &moduleEntry));
    }

    CloseHandle(hSnapshot);
}

void DumpListOfExport(void *lib, bool checkNt) {
    IMAGE_DOS_HEADER* MZ = (IMAGE_DOS_HEADER*)lib;
    IMAGE_NT_HEADERS* PE = (IMAGE_NT_HEADERS*)((BYTE*)lib + MZ->e_lfanew);
    IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)lib + PE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    
    DWORD* names = (DWORD*)((BYTE*)lib + exportDir->AddressOfNames);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        CheckJmp((char*)lib + names[i], (DWORD*)GetProcAddress((HMODULE)lib, (char*)lib + names[i]), checkNt);
    }
}

void CheckJmp(std::string name, DWORD* address, bool checkNt) {
    BYTE* opcode = (BYTE*)address;

    if (checkNt && !(name[0] == 'N' && name[1] == 't')) {
        return;
    }

    if (*opcode == 0xe9) {
        std::cout << name << " is hooked\n";
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <dll>\n";
        return 1;
    }

    std::string dll = argv[1];
    HMODULE hDll = LoadLibrary(dll.c_str());
    bool checkNt = true;

    SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::cout << "\n__  __            __      _______           __         \n"
                 " / / / /___  ____  / /__   / ____(_)___  ____/ /__  _____\n"
                 "/ /_/ / __ \\/ __ \\/ //_/  / /_  / / __ \\/ __  / _ \\/ ___/\n"
                 "/ __  / /_/ / /_/ / ,<    / __/ / / / / / /_/ /  __/ /    \n"
                 "/_/ /_/\\____/\\____/_/|_|  /_/   /_/_/ /_/\\__,_/\\___/_/     \n\n";
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    std::cout << "Loading " << dll << "\n";
    if (hDll == NULL) {
        ExitProcess(0);
    }

    ListLoadedDlls();

    SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::cout << "------------------------------------------\n";
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    if (argc > 2) {
        checkNt = false;
    } else {
        std::cout << "Listing NT API only\nListing hooked functions!\n";
        SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << "------------------------------------------\n";
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }

    DumpListOfExport(hDll, checkNt);
    FreeLibrary(hDll);

    SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::cout << "------------------------------------------\nCompleted\n";
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    return 0;
}
