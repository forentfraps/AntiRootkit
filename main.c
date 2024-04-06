#include "includes.h"
#include <heapapi.h>
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
      return 1;
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

int compare_text_ntdll64(unsigned char *stock_ntdll, int stock_size,
                         unsigned char *process_ntdll, int process_size) {
  if (process_size != stock_size) {
    printf("Size differs: %d != %d\n", stock_size, process_size);
    return 1;
  }
  int bad_byte = 0;
  for (int i = 0; i < process_size; ++i) {
    if (stock_ntdll[i] != process_ntdll[i]) {
      // printf("Byte %d\n", i);
      bad_byte++;
    }
  }
  // printf("The amount of funny bytes %d \n", bad_byte);
  return bad_byte;
}
int iterate_processes(unsigned char *stock_text, int stock_size) {
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
  int funny_process_counter = 0;
  int usermod_process = 0;
  do {
    // printf("Process ID: %lu\n", pe32.th32ProcessID);

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
    if (parse_process_ntdll64(hProcess, &process_text, &process_size)) {
      continue;
    }
    usermod_process++;
    if (compare_text_ntdll64(stock_text, stock_size, process_text,
                             process_size)) {

      printf("Process %lu is funny\n", pe32.th32ProcessID);
      funny_process_counter++;
    }
    HeapFree(GetProcessHeap(), 0, process_text);

  } while (Process32Next(hSnapshot, &pe32));

  CloseHandle(hSnapshot);
  printf("Total funny process: %d out of %d\n", funny_process_counter,
         usermod_process);
  return 0;
}
int main() {
  void *virt_text;
  void *stock_text;
  int virt_size;
  int stock_size;

  parse_disk_ntdll64(&stock_text, &stock_size);
  iterate_processes(stock_text, stock_size);
  printf("epic\n");
}
