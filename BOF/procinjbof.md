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

    # packs the userinput from C2 client
    packer.addstr(args[0])

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, f"Tasked the demon to execute process injection on the process ID: {args[0]}")
   
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

void go(char* args, int argc){
    
    datap parser;
    DWORD procid;

    //Beacon data parser
    BeaconDataParse(&parser, args, argc);
    procid = BeaconDataExtract(&parser, NULL);

    //prints hello world
    BeaconPrintf(CALLBACK_OUTPUT, "[!] Target PID: %s", procid);

    HANDLE pHandle;
	HANDLE rthreadHandle;
	PVOID buffer;

}
```


Reference
- https://www.ired.team/offensive-security/code-injection-process-injection/process-injection

[back to blog](../blog.md)