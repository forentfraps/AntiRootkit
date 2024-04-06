#include "includes.h"
#include <handleapi.h>
#include <heapapi.h>
#include <winnt.h>
#include <wow64apiset.h>
int parse_disk_ntdll64(void **ntdll_text_buffer, int *virt_size) {
  HANDLE hFile;
  HANDLE hFileMapping;
  LPVOID lpFileBase;
  PIMAGE_DOS_HEADER dosHeader;
  PIMAGE_NT_HEADERS ntHeaders;
  PIMAGE_SECTION_HEADER sectionHeader;
  hFile = CreateFile("C:\\Windows\\System32\\ntdll.dll", GENERIC_READ,
                     FILE_SHARE_READ, NULL, OPEN_EXISTING,
                     FILE_ATTRIBUTE_NORMAL, 0);
  if (hFile == INVALID_HANDLE_VALUE) {
    printf("Could not open file.\n");
    return 1;
  }

  hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
  if (hFileMapping == 0) {
    printf("Could not create file mapping.\n");
    goto disk64_parse_exit0;
  }

  lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
  if (lpFileBase == 0) {
    printf("Could not map view of file.\n");
    goto disk64_parse_exit1;
  }

  dosHeader = (PIMAGE_DOS_HEADER)lpFileBase;
  if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
    printf("Not a valid PE file.\n");
    goto disk64_parse_exit2;
  }

  ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpFileBase + dosHeader->e_lfanew);
  if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
    printf("Not a valid PE file.\n");
    goto disk64_parse_exit2;
  }

  sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
  for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections;
       i++, sectionHeader++) {
    if (strncmp((char *)sectionHeader->Name, ".text", 5) == 0) {
      *virt_size = sectionHeader->Misc.VirtualSize;
      *ntdll_text_buffer =
          HeapAlloc(GetProcessHeap(), 0, sectionHeader->SizeOfRawData);
      if (*ntdll_text_buffer) {
        memcpy(
            *ntdll_text_buffer,
            (LPVOID)((DWORD_PTR)lpFileBase + sectionHeader->PointerToRawData),
            sectionHeader->SizeOfRawData);
      }
    }
  }
  UnmapViewOfFile(lpFileBase);
  CloseHandle(hFileMapping);
  CloseHandle(hFile);
  return 0;
disk64_parse_exit2:
  UnmapViewOfFile(lpFileBase);
disk64_parse_exit1:
  CloseHandle(hFileMapping);
disk64_parse_exit0:
  CloseHandle(hFile);
  return 1;
}

int parse_disk_ntdll32(void **ntdll_text_buffer, int *virt_size,
                       DWORD *base_addr) {
  HANDLE hFile;
  HANDLE hFileMapping;
  LPVOID lpFileBase;
  PIMAGE_DOS_HEADER dosHeader;
  PIMAGE_NT_HEADERS32 ntHeaders;
  PIMAGE_SECTION_HEADER sectionHeader;
  hFile = CreateFile("C:\\Windows\\SysWOW64\\ntdll.dll", GENERIC_READ,
                     FILE_SHARE_READ, NULL, OPEN_EXISTING,
                     FILE_ATTRIBUTE_NORMAL, 0);
  if (hFile == INVALID_HANDLE_VALUE) {
    printf("Could not open file.\n");
    return 1;
  }

  hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
  if (hFileMapping == 0) {
    printf("Could not create file mapping.\n");
    goto disk32_parse_exit0;
  }

  lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
  if (lpFileBase == 0) {
    printf("Could not map view of file.\n");
    goto disk32_parse_exit1;
  }

  dosHeader = (PIMAGE_DOS_HEADER)lpFileBase;
  if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
    printf("Not a valid PE file.\n");
    goto disk32_parse_exit2;
  }

  ntHeaders =
      (PIMAGE_NT_HEADERS32)((DWORD_PTR)lpFileBase + dosHeader->e_lfanew);
  if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
    printf("Not a valid PE file.\n");
    goto disk32_parse_exit2;
  }
  *base_addr = ntHeaders->OptionalHeader.ImageBase;

  sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
  for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections;
       i++, sectionHeader++) {
    if (strncmp((char *)sectionHeader->Name, ".text", 5) == 0) {
      *virt_size = sectionHeader->Misc.VirtualSize;
      *base_addr += sectionHeader->VirtualAddress;
      *ntdll_text_buffer =
          HeapAlloc(GetProcessHeap(), 0, sectionHeader->SizeOfRawData);
      if (*ntdll_text_buffer) {
        memcpy(
            *ntdll_text_buffer,
            (LPVOID)((DWORD_PTR)lpFileBase + sectionHeader->PointerToRawData),
            sectionHeader->SizeOfRawData);
      }
    }
  }
  UnmapViewOfFile(lpFileBase);
  CloseHandle(hFileMapping);
  CloseHandle(hFile);
  return 0;
disk32_parse_exit2:
  UnmapViewOfFile(lpFileBase);
disk32_parse_exit1:
  CloseHandle(hFileMapping);
disk32_parse_exit0:
  CloseHandle(hFile);
  return 1;
}

int parse_process_ntdll64(HANDLE hProcess, void **virt_address_text,
                          int *virt_size) {
  HMODULE ntdllModuleHandle;
  PIMAGE_DOS_HEADER dosHeader;
  PIMAGE_NT_HEADERS ntHeaders;
  PIMAGE_SECTION_HEADER sectionHeader;
  unsigned char *dos_header_buffer;
  unsigned char *nt_header_buffer;
  SIZE_T bytes_read = 0;

  ntdllModuleHandle = GetModuleHandle("ntdll.dll");
  if (!ntdllModuleHandle) {
    printf("ntdll.dll is not loaded in the current process.\n");
    return 1;
  }
  nt_header_buffer = HeapAlloc(GetProcessHeap(), 0, sizeof(IMAGE_NT_HEADERS));
  dos_header_buffer = HeapAlloc(GetProcessHeap(), 0, sizeof(IMAGE_DOS_HEADER));
  if (!dos_header_buffer || !nt_header_buffer) {
    printf("Could not allocate memory\n");
    goto process64_parse_exit0;
  }

  if (!ReadProcessMemory(hProcess, (LPCVOID)ntdllModuleHandle,
                         (LPVOID)dos_header_buffer, sizeof(IMAGE_DOS_HEADER),
                         &bytes_read)) {
    //    printf("Could not read the process memory\n");
    return 1;
  }

  dosHeader = (PIMAGE_DOS_HEADER)dos_header_buffer;
  if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
    printf("Not a valid DOS Signature.\n");
    return 1;
  }

  bytes_read = 0;
  ntHeaders =
      (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllModuleHandle + dosHeader->e_lfanew);
  if (!ReadProcessMemory(hProcess, ntHeaders, nt_header_buffer,
                         sizeof(IMAGE_NT_HEADERS), &bytes_read))
    if (((PIMAGE_NT_HEADERS)nt_header_buffer)->Signature !=
        IMAGE_NT_SIGNATURE) {
      printf("Not a valid PE file.\n");
      goto process64_parse_exit0;
    }
  if (!ReadProcessMemory(
          hProcess,
          (LPCVOID)((DWORD_PTR)ntdllModuleHandle + dosHeader->e_lfanew),
          nt_header_buffer, sizeof(IMAGE_NT_HEADERS), &bytes_read)) {
    printf("Could not read NT headers from the remote process.\n");
    goto process64_parse_exit0;
  }

  ntHeaders = (PIMAGE_NT_HEADERS)nt_header_buffer;

  if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
    printf("Not a valid PE file.\n");
    goto process64_parse_exit0;
  }

  PIMAGE_SECTION_HEADER sectionHeadersBuffer = (PIMAGE_SECTION_HEADER)HeapAlloc(
      GetProcessHeap(), HEAP_ZERO_MEMORY,
      ntHeaders->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
  if (!sectionHeadersBuffer) {
    printf("Could not allocate memory for section headers\n");
    goto process64_parse_exit1;
  }

  DWORD_PTR sectionHeadersAddress =
      (DWORD_PTR)ntdllModuleHandle + dosHeader->e_lfanew + sizeof(DWORD) +
      sizeof(IMAGE_FILE_HEADER) + ntHeaders->FileHeader.SizeOfOptionalHeader;
  if (!ReadProcessMemory(
          hProcess, (LPCVOID)sectionHeadersAddress, sectionHeadersBuffer,
          ntHeaders->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER),
          &bytes_read)) {
    printf("Could not read section headers from the remote process.\n");
    goto process64_parse_exit1;
  }

  for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
    PIMAGE_SECTION_HEADER currentSection = &sectionHeadersBuffer[i];
    if (strncmp((char *)currentSection->Name, ".text",
                IMAGE_SIZEOF_SHORT_NAME) == 0) {
      void *virt_address = (void *)((DWORD_PTR)ntdllModuleHandle +
                                    currentSection->VirtualAddress);
      *virt_size = currentSection->Misc.VirtualSize;

      *virt_address_text = HeapAlloc(GetProcessHeap(), 0, *virt_size);
      if (!*virt_address_text) {
        printf("Failed to alloc buffer for end result\n");
        goto process64_parse_exit1;
      }
      bytes_read = 0;
      if (!ReadProcessMemory(hProcess, virt_address, *virt_address_text,
                             *virt_size, &bytes_read)) {
        printf("Failed to read .text section\n");
        goto process64_parse_exit2;
      }
    }
  }
  HeapFree(GetProcessHeap(), 0, sectionHeadersBuffer);
  HeapFree(GetProcessHeap(), 0, dos_header_buffer);
  HeapFree(GetProcessHeap(), 0, nt_header_buffer);

  return 0;

process64_parse_exit2:
  HeapFree(GetProcessHeap(), 0, *virt_address_text);
process64_parse_exit1:
  HeapFree(GetProcessHeap(), 0, sectionHeadersBuffer);
process64_parse_exit0:
  HeapFree(GetProcessHeap(), 0, dos_header_buffer);
  HeapFree(GetProcessHeap(), 0, nt_header_buffer);
  return 1;
}
BOOL Get32BitNtdllBaseAddress(HANDLE hProcess, LPVOID *baseAddress) {
  HMODULE hMods[1024];
  DWORD cbNeeded;
  if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded,
                           LIST_MODULES_32BIT)) {
    for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
      WCHAR szModName[MAX_PATH];
      if (GetModuleBaseNameW(hProcess, hMods[i], szModName,
                             sizeof(szModName) / sizeof(WCHAR))) {
        if (_wcsicmp(szModName, L"ntdll.dll") == 0) {
          MODULEINFO modInfo;
          if (GetModuleInformation(hProcess, hMods[i], &modInfo,
                                   sizeof(modInfo))) {
            *baseAddress = modInfo.lpBaseOfDll;
            CloseHandle(hProcess);
            return TRUE;
          }
        }
      }
    }
  }
  return FALSE;
}
int parse_process_ntdll32(HANDLE _hProcess, void **virt_address_text,
                          int *virt_size, DWORD pid, DWORD *base_virt_addr) {
  LPVOID ntdllModuleHandle;
  PIMAGE_DOS_HEADER dosHeader;
  PIMAGE_NT_HEADERS32 ntHeaders;
  SIZE_T bytes_read = 0;

  HANDLE hProcess = OpenProcess(PROCESS_VM_READ, 0, pid);
  if (hProcess == INVALID_HANDLE_VALUE) {
    printf("Invalid handle value: \n", GetLastError());
    goto process32_parse_exit;
  }
  dosHeader = HeapAlloc(GetProcessHeap(), 0, sizeof(IMAGE_DOS_HEADER));
  ntHeaders = HeapAlloc(GetProcessHeap(), 0, sizeof(IMAGE_NT_HEADERS32));
  if (!Get32BitNtdllBaseAddress(_hProcess, &ntdllModuleHandle)) {
    printf("Failed to get base address of the 32 bit ntdll.dll\n");
    goto process32_parse_exit;
  }

  if (!ntdllModuleHandle) {
    printf("ntdll.dll is not loaded in the current process.\n");
    goto process32_parse_exit;
  }

  if (!ReadProcessMemory(hProcess, ntdllModuleHandle, dosHeader,
                         sizeof(IMAGE_DOS_HEADER), &bytes_read)) {
    printf("Failed to read the DOS header or invalid DOS signature.\n");
    printf("Error: %lu\n", GetLastError());
    goto process32_parse_exit;
  }
  if (!ReadProcessMemory(hProcess, ntdllModuleHandle, dosHeader,
                         sizeof(IMAGE_DOS_HEADER), &bytes_read) ||
      dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
    printf("Failed to read the32  DOS header or not a valid DOS signature.\n");
    goto process32_parse_exit;
  }

  LPVOID ntHeadersAddress = (LPBYTE)ntdllModuleHandle + dosHeader->e_lfanew;
  if (!ReadProcessMemory(hProcess, ntHeadersAddress, ntHeaders,
                         sizeof(IMAGE_NT_HEADERS32), &bytes_read) ||
      ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
    printf("Failed to read NT headers or invalid PE signature.\n");

    goto process32_parse_exit;
  }

  IMAGE_SECTION_HEADER *sectionHeaders = (IMAGE_SECTION_HEADER *)HeapAlloc(
      GetProcessHeap(), HEAP_ZERO_MEMORY,
      ntHeaders->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
  if (!sectionHeaders) {
    printf("Could not allocate memory for section headers.\n");
    return 1;
  }

  LPVOID sectionHeadersAddress = (LPBYTE)ntHeadersAddress + sizeof(DWORD) +
                                 sizeof(IMAGE_FILE_HEADER) +
                                 ntHeaders->FileHeader.SizeOfOptionalHeader;
  if (!ReadProcessMemory(hProcess, sectionHeadersAddress, sectionHeaders,
                         ntHeaders->FileHeader.NumberOfSections *
                             sizeof(IMAGE_SECTION_HEADER),
                         &bytes_read)) {
    printf("Failed to read section headers.\n");
    goto process32_parse_exit;
  }

  for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
    if (strncmp((char *)sectionHeaders[i].Name, ".text",
                IMAGE_SIZEOF_SHORT_NAME) == 0) {
      LPVOID sectionAddress =
          (LPBYTE)ntdllModuleHandle + sectionHeaders[i].VirtualAddress;
      *base_virt_addr = (DWORD)sectionAddress;
      *virt_size = sectionHeaders[i].Misc.VirtualSize;
      *virt_address_text =
          HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *virt_size);

      if (!*virt_address_text) {
        printf("Failed to allocate buffer for the .text section.\n");
        goto process32_parse_exit;
      }

      if (!ReadProcessMemory(hProcess, sectionAddress, *virt_address_text,
                             *virt_size, &bytes_read)) {
        printf("Failed to read the .text section.\n");
        goto process32_parse_exit;
      }
      CloseHandle(hProcess);
      HeapFree(GetProcessHeap(), 0, sectionHeaders);
      return 0;
    }
  }

process32_parse_exit:
  if (sectionHeaders) {
    HeapFree(GetProcessHeap(), 0, sectionHeaders);
  }
  if (*virt_address_text) {
    HeapFree(GetProcessHeap(), 0, *virt_address_text);
    *virt_address_text = NULL;
  }
  if (dosHeader) {
    HeapFree(GetProcessHeap(), 0, dosHeader);
    HeapFree(GetProcessHeap(), 0, ntHeaders);
  }
  if (hProcess) {
    CloseHandle(hProcess);
  }
  return 1;
}

int compare_text_ntdll(unsigned char *stock_ntdll, int stock_size,
                       unsigned char *process_ntdll, int process_size) {
  if (process_size != stock_size) {
    // printf("Size differs: %d != %d\n", stock_size, process_size);
    return 1;
  }
  int bad_byte = 0;
  int last_patched_byte = 0;
  for (int i = 0; i < process_size; ++i) {
    if (stock_ntdll[i] != process_ntdll[i]) {
      bad_byte++;
    }
  }
  return bad_byte;
}

int compare_text_ntdll32(unsigned char *stock_ntdll, int stock_size,
                         unsigned char *process_ntdll, int process_size,
                         DWORD runtime_offset) {
  if (process_size != stock_size) {
    return 1;
  }
  DWORD constant = -1;
  int bad_byte = 0;
  int last_patched_byte = 0;
  for (int i = 0; i < process_size; ++i) {
    if (stock_ntdll[i] != process_ntdll[i]) {
      DWORD mod4_addr = i - 2;
      if (*((DWORD *)(process_ntdll + mod4_addr)) -
              *((DWORD *)(stock_ntdll + mod4_addr)) !=
          runtime_offset) {
        bad_byte++;
        continue;
      }
      i += 2;
    }
  }
  return bad_byte;
}

int iterate_processes(unsigned char *stock_text64, int stock_size64,
                      unsigned char *stock_text32, int stock_size32,
                      DWORD base_addr32) {
  void *process_text;
  int process_size;
  HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnapshot == INVALID_HANDLE_VALUE) {
    printf("CreateToolhelp32Snapshot failed. Error: %lu\n", GetLastError());
    return 1;
  }

  PROCESSENTRY32 pe32;
  pe32.dwSize = sizeof(PROCESSENTRY32);

  if (!Process32First(hSnapshot, &pe32)) {
    printf("Process32First failed. Error: %lu\n", GetLastError());
    CloseHandle(hSnapshot);
    return 1;
  }
  int patched_process_counter = 0;
  int usermod_process = 0;
  do {

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                                  FALSE, pe32.th32ProcessID);
    if (hProcess == NULL) {
      continue;
    }
    BOOL wow64;
    IsWow64Process(hProcess, &wow64);
    if (!wow64) {
      if (parse_process_ntdll64(hProcess, &process_text, &process_size)) {
        continue;
      }
      if (compare_text_ntdll(stock_text64, stock_size64, process_text,
                             process_size)) {

        // printf("Process %lu is patched\n", pe32.th32ProcessID);
        patched_process_counter++;
      } else {
        // printf("Process %lu is NOT patched\n", pe32.th32ProcessID);
      }

      usermod_process++;
    } else {
      DWORD base_virt_addr;
      if (parse_process_ntdll32(hProcess, &process_text, &process_size,
                                pe32.th32ProcessID, &base_virt_addr)) {
        continue;
      }
      if (compare_text_ntdll32(stock_text32, stock_size32, process_text,
                               process_size, base_virt_addr - base_addr32)) {
        patched_process_counter++;
      }

      usermod_process++;
    }

    HeapFree(GetProcessHeap(), 0, process_text);

  } while (Process32Next(hSnapshot, &pe32));
  printf("Total patched process: %d out of %d\n", patched_process_counter,
         usermod_process);
  CloseHandle(hSnapshot);
  if ((float)patched_process_counter / (float)usermod_process > 0.70) {
    printf("This system probably has a usermod rootkit!\n");
  } else {
    printf("This system probably does not have a usermod rootkit\n");
  }
  return 0;
}

BOOL ReadRemoteProcessMemory(DWORD processId, LPCVOID baseAddress,
                             LPVOID buffer, SIZE_T size) {
  HANDLE processHandle = OpenProcess(PROCESS_VM_READ, FALSE, processId);
  if (processHandle == NULL) {
    printf("Failed to open process. Error: %lu\n", GetLastError());
    return FALSE;
  }

  SIZE_T bytesRead;
  BOOL result =
      ReadProcessMemory(processHandle, baseAddress, buffer, size, &bytesRead);
  if (!result || bytesRead != size) {
    printf("Failed to read process memory. Error: %lu\n", GetLastError());
    CloseHandle(processHandle);
    return FALSE;
  }
  printf("Success!\n");

  CloseHandle(processHandle);
  return TRUE;
}
int main() {
  void *stock_text32;
  void *stock_text64;
  int stock_size32;
  int stock_size64;
  DWORD base_addr32;
  parse_disk_ntdll64(&stock_text64, &stock_size64);
  parse_disk_ntdll32(&stock_text32, &stock_size32, &base_addr32);

  iterate_processes(stock_text64, stock_size64, stock_text32, stock_size32,
                    base_addr32);
}
