////#include <wdm.h> 
//#include <ntifs.h>
//#include <ntddk.h>
////#include <wdm.h>
#include <ntifs.h>
#include <tdi.h>
#include <tdikrnl.h>
////#include <windef.h>
#include <ntstrsafe.h>
#include <windef.h>
#include <wdm.h>

//#include <wdm.h>
#include <ntddk.h>
#include <ntifs.h>
#include <winerror.h>
#include <ntimage.h>
#include <windowsx.h>
#include <process.h>
#include <ntdef.h>
//#include <processthreadsapi.h>
#include <intrin.h>





#define DEVICE_NAME L"\\Device\\MyFirstDevice"
#define SYM_NAME L"\\??\\MyFirstDevice"
#define TEST_NAME "asd"
#define IOCTL_MY_DRIVER_FUNCTION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

//extern "C" NTSYSCALLAPI PCHAR PsGetProcessImageFileName( PEPROCESS pProcess);

KSPIN_LOCK my_spinlock;
BYTE PhyBuffer[] = "ooppqqcccWWoopp";
KSPIN_LOCK spinlock = { 0 };
KDPC kdpcobj = { 0 };
KEVENT kt = { 0 };
KEVENT KThreadEvent = { 0 };
KMUTEX g_Mutex;
BOOL threadFlase = false;
PKEVENT pkernelevent ;
HANDLE hthread = NULL;
HANDLE hthread2 = NULL;
BYTE mmcode[10] = { 0 };
KTIMER time = { 0 };
WORK_QUEUE_ITEM wkItem = { 0 };
LARGE_INTEGER cookie = { 0 };
PVOID _HANDLE = NULL;
PDEVICE_OBJECT pfileterdevobj = NULL;
PDEVICE_OBJECT pdodevobj = NULL;
KEVENT NetDispatchEvent = { 0 };
PVOID NtOpenProcessptraddr = NULL;
PVOID jmpBridgePtr = NULL;
typedef struct _NETWORK_ADDRESS
{
	CHAR address[4];
	CHAR port[2];
}NETWORK_ADDRESS,*PNETWORK_ADDRESS;


extern "C" NTSYSCALLAPI PCHAR PsGetProcessImageFileName(IN PEPROCESS pProcess);
VOID  YWORKER_THREAD_ROUTINE(PVOID Parameter)
{
	DbgPrint("Irql=%d\n", KeGetCurrentIrql());
	DbgPrint("Process Name = %s \n", PsGetProcessImageFileName(PsGetCurrentProcess()));
	LARGE_INTEGER sleepTime = { 0 };
	sleepTime.QuadPart = -10 * 1000 * 1000;
	while (1) // false
	{
		DbgPrint("Worked Item \n");
		KeDelayExecutionThread(KernelMode,FALSE,&sleepTime);
	}
}




//DISPACHER_HEADER
//{
//
//};
VOID KernelThread2(PVOID context)
{
	NTSTATUS status = STATUS_SUCCESS;
	//DbgPrint("Exe::KernelThread2\n");
	PKEVENT pevent = (PKEVENT)context;
	//DbgPrint("Create KernelThread2");
	DbgPrint("KernelThread2 \n");
	

	threadFlase = TRUE;
	int i = 3;

	LARGE_INTEGER sleeptime = { 0 };
	sleeptime.QuadPart = -100 * 10 * 1000 * 60;

	while (1)
	{
		status = KeWaitForSingleObject(pevent, Executive, KernelMode, FALSE, &sleeptime);
		if (STATUS_TIMEOUT == status)
		{
			DbgPrint("Time Out");
			break;
		}
		else
		{
			DbgPrint("WaitFor the Single object from exe\n");
		}

	}



	////while (NT_SUCCESS(KeWaitForSingleObject(&KThreadEvent, Executive, KernelMode, FALSE, NULL)))
	while(i)
	{
		//KeDelayExecutionThread(KernelMode, FALSE, &sleeptime);
		DbgPrint("Set Event stopping\n");
		//KeSetEvent(&kt, IO_NO_INCREMENT, FALSE);// 通过 有信号
		i--;
	}
	PsTerminateSystemThread(0);
}

VOID KernelThread1(PVOID context)
{
	KeInitializeEvent(&kt,NotificationEvent, TRUE);//  FALSE 不能通过

	HANDLE hthread = NULL;
	int i = 3;
	NTSTATUS status = PsCreateSystemThread(&hthread, 0, NULL, NULL, NULL, KernelThread2, PVOID(&kt));
	//ZwClose(hthread);
	//while (NT_SUCCESS(KeWaitForSingleObject(&KThreadEvent,Executive,KernelMode,FALSE,NULL)))
	while(i)
	{
		KeWaitForSingleObject(&kt, Executive, KernelMode, FALSE, NULL);
		DbgPrint("等到了");
		KeResetEvent(&kt);
		i--;
	}
	PsTerminateSystemThread(0);
}

VOID KernelThread3(PVOID context)
{
	//DbgPrint("KernelThread3\n");
	int i = 3;
	KeWaitForSingleObject(&g_Mutex, Executive, KernelMode, FALSE, NULL);
	//KeWaitForSingleObject(&KThreadEvent, Executive, KernelMode, FALSE, NULL);
	DbgPrint("Wait Over");
	LARGE_INTEGER duetime;
	duetime.QuadPart = -30*1000*1000;
	//int x = *(int*)context;
	//int i = 9000;
	while (i)
	{
		KeDelayExecutionThread(KernelMode,FALSE,&duetime);
		DbgPrint("KeDelayExecution Thread ending");
		if (threadFlase)
		{
			break;
		}
		//int j = 1000;
		//while (j)
		//{
		//	j--;
		//}

		//if (i == 0)
		//{
		//	PsCreateSystemThread(&hthread2, 0, NULL, NULL, NULL, KernelThread2, NULL);
		//}

		//
		//DbgPrint("Bool:%d",threadFlase);
		//DbgPrint("KernelThread %d",i);
		i--;
	}
	KeReleaseMutex(&g_Mutex, 0);

	DbgPrint("Break Thread");
	PsTerminateSystemThread(0);
	DbgPrint("Break Thread !!!!!!!!!");   //未被执行
}




// KernelMode =>  UserMode


UNICODE_STRING usFilePath = RTL_CONSTANT_STRING(L"C:\\Windows\\notepad.exe");
UNICODE_STRING usCommandLine = RTL_CONSTANT_STRING(L"notepad.exe");

//VOID UserThread(IN PVOID StartContext)
//{
//	// 在用户模式进程中创建窗口
//	// 启实notepad.exe进程
//	PROCESS_INFORMATION pi = { 0 };
//	STARTUPINFO si = { 0 };
//	si.cb = sizeof(si);
//	BOOL bCreateProcess = CreateProcess(NULL, usCommandLine.Buffer, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
//	if (!bCreateProcess)
//	{
//		DbgPrint("Failed to create process: %d\n", GetLastError());
//	}
//	else
//	{
//		DbgPrint("Process created successfully\n");
//	}
//
//	// 等待notepad.exe进程退出
//	WaitForSingleObject(pi.hProcess, INFINITE);
//
//	// 关闭句柄并退出线程
//	CloseHandle(pi.hProcess);
//	CloseHandle(pi.hThread);
//	PsTerminateSystemThread(STATUS_SUCCESS);
//}

// KernelMode =>  UserMode  end




	//void openWindow()
	//{
	//	NTSTATUS status;
	//	HANDLE hUserProcess;
	//	HANDLE hUserThread;
	//	OBJECT_ATTRIBUTES ObjectAttributes;
	//	CLIENT_ID ClientId;
	//	PEPROCESS UserProcess;
	//	PETHREAD UserThread;
	//	PVOID UserBaseAddress = NULL;
	//	SIZE_T UserStackSize = 0;
	//	SIZE_T UserMinimumStackSize = 0;
	//	PVOID UserEntryPoint = NULL;
	//	UNICODE_STRING usProcessName;
	//	UNICODE_STRING usThreadName;
	//	KAPC_STATE ApcState;

	//	// 创建设备对象和符号链接
	//	PDEVICE_OBJECT DeviceObject;
	//	UNICODE_STRING DeviceName;
	//	UNICODE_STRING SymLinkName;
	//	RtlInitUnicodeString(&DeviceName, DEVICE_NAME);
	//	RtlInitUnicodeString(&SymLinkName, DOS_DEVICE_NAME);
	//	status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);
	//	if (!NT_SUCCESS(status))
	//	{
	//		DbgPrint("Failed to create device object: %08X\n", status);
	//		return status;
	//	}
	//	status = IoCreateSymbolicLink(&SymLinkName, &DeviceName);
	//	if (!NT_SUCCESS(status))
	//	{
	//		DbgPrint("Failed to create symbolic link: %08X\n", status);
	//		IoDeleteDevice(DeviceObject);
	//		return status;
	//	}

	//	// 创建用户模式进程
	//	InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	//	status = ZwCreateUserProcess(&hUserProcess, &ClientId, &ObjectAttributes, NULL, NULL, NULL, NULL, FALSE, NULL);
	//	if (!NT_SUCCESS(status))
	//	{
	//		DbgPrint("Failed to create user process: %08X\n", status);
	//		IoDeleteSymbolicLink(&SymLinkName);
	//		IoDeleteDevice(DeviceObject);
	//		return status;
	//	}
	//	status = PsLookupProcessByProcessId(ClientId.UniqueProcess, &UserProcess);
	//	if (!NT_SUCCESS(status))
	//	{
	//		DbgPrint("Failed to lookup process: %08X\n", status);
	//		ZwClose(hUserProcess);
	//		IoDeleteSymbolicLink(&SymLinkName);
	//		IoDeleteDevice(DeviceObject);
	//		return status;
	//	}

	//	// 分配用户模式栈空间
	//	UserStackSize = 1024 * 1024;
	//	UserMinimumStackSize = 1024 * 1024;
	//	status = ZwAllocateVirtualMemory(hUserProcess, &UserBaseAddress, 0, &UserStackSize, MEM_COMMIT, PAGE_READWRITE);
	//	if (!NT_SUCCESS(status))
	//	{
	//		DbgPrint("Failed to allocate virtual memory: %08X\n", status);
	//		ObDereferenceObject(UserProcess);
	//		ZwClose(hUserProcess);
	//		IoDeleteSymbolicLink(&SymLinkName);
	//		IoDeleteDevice(DeviceObject);
	//		return status;
	//	}

	//	// 获取用户模式程序的入口点
	//	status = LdrGetDllHandle(NULL, NULL, &usFilePath, (PVOID*)&UserEntryPoint);
	//	if (!NT_SUCCESS(status))
	//	{
	//		DbgPrint("Failed to get DLL handle: %08X\n", status);
	//		ZwFreeVirtualMemory(hUserProcess, &UserBaseAddress, &UserMinimumStackSize, MEM_RELEASE);
	//		ObDereferenceObject(UserProcess);
	//		ZwClose(hUserProcess);
	//		IoDeleteSymbolicLink(&SymLinkName);
	//		IoDeleteDevice(DeviceObject);
	//		return status;
	//	}

	//	// 在用户模式进程中写入参数
	//	SIZE_T BytesWritten;
	//	status = ZwWriteVirtualMemory(hUserProcess, UserBaseAddress, usCommandLine.Buffer, usCommandLine.Length, &BytesWritten);
	//	if (!NT_SUCCESS(status))
	//	{
	//		DbgPrint("Failed to write virtual memory: %08X\n", status);
	//		LdrUnloadDll((PVOID)UserEntryPoint);
	//		ZwFreeVirtualMemory(hUserProcess, &UserBaseAddress, &UserMinimumStackSize, MEM_RELEASE);
	//		ObDereferenceObject(UserProcess);
	//		ZwClose(hUserProcess);
	//		IoDeleteSymbolicLink(&SymLinkName);
	//		IoDeleteDevice(DeviceObject);

	//		return status;
	//	}

	//	// 在用户模式进程中创建线程并启动用户模式程序
	//	RtlInitUnicodeString(&usProcessName, L"MyUserProcess");
	//	RtlInitUnicodeString(&usThreadName, L"MyUserThread");
	//	status = PsCreateSystemThread(&hUserThread, THREAD_ALL_ACCESS, &ObjectAttributes, NULL, &ClientId, UserThread, NULL);
	//	if (!NT_SUCCESS(status))
	//	{
	//		DbgPrint("Failed to create system thread: %08X\n", status);
	//		LdrUnloadDll((PVOID)UserEntryPoint);
	//		ZwFreeVirtualMemory(hUserProcess, &UserBaseAddress, &UserMinimumStackSize, MEM_RELEASE);
	//		ObDereferenceObject(UserProcess);
	//		ZwClose(hUserProcess);
	//		IoDeleteSymbolicLink(&SymLinkName);
	//		IoDeleteDevice(DeviceObject);
	//		return status;
	//	}

	//	// 等待用户模式进程启动完毕
	//	KeInitializeApc(&ApcState, PsGetThreadTcb(hUserThread), 0, NULL, NULL, NULL, KernelApcRoutine, NULL);
	//	KeInsertQueueApc(&ApcState, NULL, NULL, 0);

	//	// 关闭句柄并清理资源
	//	ZwClose(hUserThread);
	//	LdrUnloadDll((PVOID)UserEntryPoint);
	//	ZwFreeVirtualMemory(hUserProcess, &UserBaseAddress, &UserMinimumStackSize, MEM_RELEASE);
	//	ObDereferenceObject(UserProcess);
	//	ZwClose(hUserProcess);
	//	IoDeleteSymbolicLink(&SymLinkName);
	//	IoDeleteDevice(DeviceObject);

	//	return STATUS_SUCCESS;
	//}









bool staticBook = true;



typedef struct _MyStruct
{
	LIST_ENTRY list;
	HANDLE pid;
	PEPROCESS peprocessobj;
	BYTE processname[16];
};

LIST_ENTRY listHead = { 0 };


//EXTERN_C
//extern "C"

//DWORD GetProcessImageFileNameA(
//	[in]  HANDLE hProcess,
//	[out] LPSTR  lpImageFileName,
//	[in]  DWORD  nSize
//);

NTSTATUS KernelCopyFile(PWCHAR wDestPath, PWCHAR sourcePath);

void CloseAllProcessNotify(HANDLE ProcessId)
{	
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE pNotePad = NULL;
	CLIENT_ID clientId;
	OBJECT_ATTRIBUTES ob = { 0 };
	InitializeObjectAttributes(&ob, NULL, OBJ_KERNEL_HANDLE, NULL, NULL); 
	clientId.UniqueProcess = ProcessId;
	clientId.UniqueThread = NULL;


	//LARGE_INTEGER delayTime = { 0 };
	//delayTime.QuadPart = 500000000;
	//KeDelayExecutionThread(KernelMode, FALSE, &delayTime);

	status = ZwOpenProcess(&pNotePad, GENERIC_ALL,&ob,&clientId);
	if (NT_SUCCESS(status = ZwTerminateProcess(pNotePad, STATUS_SUCCESS)))
	{
		DbgPrint("ZwTerminateProcess successfully\n");
	}
	else
	{
		DbgPrint("ZwTerminateProcess UnSuccessfully\n %x", status);
	}


}

void PcreateProcessNotifyRoutine(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
{
	NTSTATUS status = STATUS_SUCCESS;
	DbgPrint("PcreateProcessNotifyRoutine");
	if (Create)
	{
		DbgPrint("Process : %d",ProcessId);
		
		PEPROCESS tempep = NULL;
		PsLookupProcessByProcessId(ProcessId,&tempep);
		//PEPROCESS tempep = PsGetCurrentProcess();
		PCHAR processName = PsGetProcessImageFileName(tempep);
	
//  Open Process

		CloseAllProcessNotify(ProcessId);
//  end open process
		DbgPrint("Process name is %s",processName);

		_MyStruct* pMyStruct = (_MyStruct* )ExAllocatePool(NonPagedPool,sizeof(_MyStruct));
		if (pMyStruct)
		{
			KIRQL oldirql = 0;
			//PLIST_ENTRY templist = ;
			RtlZeroMemory(pMyStruct,sizeof(_MyStruct));
			KeAcquireSpinLock(&spinlock,&oldirql);
			pMyStruct->peprocessobj = tempep;
			pMyStruct->pid = ProcessId;



			RtlCopyMemory(pMyStruct->processname, processName, 16);

			//templist = (PLIST_ENTRY)CONTAINING_RECORD(pMyStruct, _MyStruct, list);
			InsertTailList(&listHead, &(pMyStruct->list));
			KeReleaseSpinLock(&spinlock,oldirql);
		}
	}
	return;
	
}

VOID dpcRoutine(PVOID conetxt)
{

	// PASSIVE_LEVEL
	DbgPrint("Current irql %d",KeGetCurrentIrql());
	DbgPrint("ProcessName:%s \n ",PsGetProcessImageFileName(PsGetCurrentProcess()));
	//KernelCopyFile(L"\\??\\C:\\opq.txt",L"\\??\\C:\\Users\\opq\\Desktop\\123.txt");
	return;
}
__declspec(dllexport) NTSTATUS KernelQueryRegister( PUNICODE_STRING RegistryPath)
{
	NTSTATUS  status = STATUS_SUCCESS;
	HANDLE RegisterKeyHandle = NULL;
	ULONG keyop = 0;
	OBJECT_ATTRIBUTES oba = {0};
	InitializeObjectAttributes(&oba,RegistryPath,OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,NULL,NULL); 
	status = ZwCreateKey(&RegisterKeyHandle, KEY_ALL_ACCESS, &oba, 0, NULL, REG_OPTION_NON_VOLATILE, &keyop);
	if (NT_SUCCESS(status))
	{
		if (keyop == REG_CREATED_NEW_KEY)
		{
			DbgPrint("Key has be created \n");
		}
		else if(keyop == REG_OPENED_EXISTING_KEY)
		{
			DbgPrint("Key has be opened\n");
		}
		else
		{
			DbgPrint("Key else %d",keyop);
		}
	}
	//HANDLE zwOpenHandle = NULL;
	status = STATUS_SUCCESS;
	PVOID keyInfo = NULL;
	UNICODE_STRING unicodeStr = { 0 };
	status = ZwOpenKey(&RegisterKeyHandle,KEY_ALL_ACCESS,&oba);
	if (NT_SUCCESS(status))
	{
		keyInfo = ExAllocatePool(NonPagedPool,0x100);
		if (!keyInfo)
		{
			return 0;
		}
		RtlZeroMemory(keyInfo, 0x100);
		PWCHAR  wchar = L"ImagePath";
		RtlInitUnicodeString(&unicodeStr,wchar);
		status = ZwQueryValueKey(RegisterKeyHandle,&unicodeStr,KeyValuePartialInformation,keyInfo,0x100,&keyop);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("ZwQueryValueKey error %x",status);
			ZwClose(RegisterKeyHandle);
			ExFreePool(keyInfo);
			return status;
		}
		PKEY_VALUE_PARTIAL_INFORMATION tmpInfo = (PKEY_VALUE_PARTIAL_INFORMATION)keyInfo;
		DbgPrint("KEY_VALUE: %ws",tmpInfo->Data);
		KernelCopyFile(L"\\??\\C:\\Windows\\System32\\drivers\\asd.sys",(PWCHAR)tmpInfo->Data);
	}
	PWCHAR rootPath = L"\\SystemRoot\\system32\\drivers\\asd.sys";
	//UNICODE_STRING rootUnicode = { 0 };
	//RtlInitUnicodeString(&rootUnicode,rootPath);
	status = ZwSetValueKey(RegisterKeyHandle,&unicodeStr,0,REG_EXPAND_SZ,rootPath,wcslen(rootPath)*2+2);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("ZwSetValueKey error %x",status);
	}
	else
	{
		DbgPrint("ZwSetValueKey Successfully");
	}

	if (!keyInfo)
	{
		ExFreePool(keyInfo);
	}
	ZwClose(RegisterKeyHandle);
	ULONG tempStart = 1;
	RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, RegistryPath->Buffer,L"Start",REG_DWORD,&tempStart,4);


	return status;
}

NTSTATUS KernelDeleteFile(PWCHAR file_path)
{
	UNICODE_STRING filePath = {0};
	NTSTATUS status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES oba = { 0 };
	RtlInitUnicodeString(&filePath, file_path);
	InitializeObjectAttributes(&oba, &filePath, OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwDeleteFile(&oba);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("%wZ",filePath);
		DbgPrint("删除失败 %x",status);
	}
	else
	{
		DbgPrint("删除成功");
	}
	//STATUS_INVALID_PARAMETER

	return status;
}


NTSTATUS KernelCopyFile(PWCHAR wDestPath,PWCHAR sourcePath)
{
	NTSTATUS  status = STATUS_SUCCESS;
	HANDLE hFile = NULL;
	OBJECT_ATTRIBUTES oba = { 0 };
	UNICODE_STRING strUnicode = { 0 };
	IO_STATUS_BLOCK ioStack = { 0 };
	RtlInitUnicodeString(&strUnicode,sourcePath);
	InitializeObjectAttributes(&oba,&strUnicode,OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,NULL,NULL);
	DbgPrint("ObjectName: %wZ",oba.ObjectName);
	status = ZwOpenFile(&hFile,GENERIC_EXECUTE,&oba,&ioStack,FILE_SHARE_READ|FILE_SHARE_WRITE | FILE_SHARE_DELETE,FILE_SYNCHRONOUS_IO_NONALERT);
	DbgPrint("sourcePath: %wZ",strUnicode);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("Open 53 sourceFile failed %x \n",status);
		return status;
	}
	else
	{
		DbgPrint("Open sourceFile successfully \ n");

	}
	//ZwClose(hFile);
	//return status;
	FILE_STANDARD_INFORMATION fbi = { 0 };
	status = ZwQueryInformationFile(hFile,&ioStack,&fbi,sizeof(fbi),FileStandardInformation);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("ZwQueryInformation sourceFile failed %x \n",status);
		ZwClose(hFile);
		return status;
	}
	else
	{
		DbgPrint("ZwQueryInformation sourceFile success  \n");
	}
	PVOID fileBuffer = NULL;
	fileBuffer = ExAllocatePool(NonPagedPool,fbi.EndOfFile.QuadPart);
	if(!fileBuffer)
	{
		DbgPrint("Allocate Failed \n");
		ZwClose(hFile);
		return status;
	}
	RtlZeroMemory(fileBuffer,fbi.EndOfFile.QuadPart);
	LARGE_INTEGER readOffset = { 0 };
	readOffset.QuadPart = 0;
	status = ZwReadFile(hFile,NULL,NULL,NULL,&ioStack,fileBuffer,fbi.EndOfFile.QuadPart,&readOffset,NULL);
	if(!NT_SUCCESS(status))
	{
		DbgPrint("read Failed %x \n",status);
		ZwClose(hFile);
		ExFreePool(fileBuffer);
		return status;
	}
	
	else
	{
		DbgPrint("Read Successfully");
	}
	
	//DbgPrint("FileBuffer: %s",(char*)fileBuffer);
	//DbgPrint("---IoInfo--- %d\n",ioStack.Information);
	//DbgPrint("ooppqq");
	DbgPrint("fileBuffer:%wZ",(PWCHAR)fileBuffer);
	//
	//读取完文件
	HANDLE hFile2 = NULL;
	UNICODE_STRING destPath = { 0 };
	OBJECT_ATTRIBUTES oba2 = { 0 };
	IO_STATUS_BLOCK obj2 = { 0 };
	RtlInitUnicodeString(&destPath,wDestPath);
	InitializeObjectAttributes(&oba2, &destPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwCreateFile(&hFile2,GENERIC_ALL,&oba2,&obj2,NULL,FILE_ATTRIBUTE_NORMAL,FILE_SHARE_WRITE,FILE_SUPERSEDE,FILE_SYNCHRONOUS_IO_NONALERT,NULL,0);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("Create Fieled %x",status);
	}
	else
	{
		DbgPrint("Create successfully");
	}
	LARGE_INTEGER l_Int = { 0 };
	l_Int.QuadPart = 0;
	DbgPrint("FBI: %x",fbi.EndOfFile.QuadPart);
	status = ZwWriteFile(hFile2, NULL, NULL, NULL, &obj2, fileBuffer,fbi.EndOfFile.QuadPart, &l_Int, NULL);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("Write failed %x",status);
	}
	else
	{
		DbgPrint("Write successfully");
	}

	ExFreePool(fileBuffer);
	ZwClose(hFile2);
	ZwClose(hFile);
	return status;
}

VOID
TimeWork(
	_In_ struct _DEVICE_OBJECT *DeviceObject,
	_In_opt_ PVOID Context
)
{
	DbgPrint("Ener into the time work\n");
	DbgPrint("Irql = %d", KeGetCurrentIrql());
	DbgPrint("ProcessName:%s \n ",PsGetProcessImageFileName(PsGetCurrentProcess()));

}




VOID MyCreateProcessNotify(HANDLE parentId, HANDLE processId, BOOLEAN bCreate);
VOID MyCreateThreadNotify(HANDLE parentId, HANDLE threadId, BOOLEAN bCreate)
{

	if (bCreate)
	{
		PEPROCESS tempep = NULL;
		NTSTATUS status = STATUS_SUCCESS;
		status = PsLookupProcessByProcessId(threadId, &tempep);
		if (NT_SUCCESS(status))
		{
			//PEPROCESS tempep = NULL;
			//PsLookupProcessByProcessId(ProcessId, &tempep);
			ObReferenceObject(tempep);
			PEPROCESS tempep = PsGetCurrentProcess();
			PCHAR processName = PsGetProcessImageFileName(tempep);
			DbgPrint("%s",processName);
		}
	}
	return;
}
VOID MyLoadImageNotify(PUNICODE_STRING fullImageName, HANDLE processId, PIMAGE_INFO imageInfo)
{
//// 转换函数NTSTATUS flag = RtlUnicodeStringToAnsiString(&ansi_buffer_target,&uncode_buffer_source, TRUE);

	DbgPrint("MyLoadImageNotify\n");

	DbgPrint("Computer:%wZ",fullImageName);



	//ANSI_STRING ascII = {0};
	//char cAscIIi[100] = { 0 };
	//NTSTATUS ntStatus = RtlUnicodeStringToAnsiString(&ascII,fullImageName,TRUE);
	//if (NT_SUCCESS(ntStatus))
	//{
	//	//strcpy(cAscIIi,ascII.Buffer);
	//	//DbgPrint("Name: %s",cAscIIi);
	//}



	//DbgPrint(fullImageName->Buffer);


	return;

}
extern "C"
NTSTATUS unHook();

void SampleUnLoad(PDRIVER_OBJECT DriverObject)
{
	DbgPrint("SampleUnLoad");
	unHook();
	threadFlase = true;
	if (cookie.QuadPart != 0)
	{
		CmUnRegisterCallback(cookie);
	}
	if (NULL != _HANDLE)
	{
		ObUnRegisterCallbacks(_HANDLE);
	}



	//PsSetCreateProcessNotifyRoutine(MyCreateProcessNotify,TRUE);
	//PsSetLoadImageNotifyRoutine(MyLoadImageNotify);


	//PsRemoveLoadImageNotifyRoutine(MyLoadImageNotify);


	//PsRemoveCreateThreadNotifyRoutine(MyCreateThreadNotify);


	//IoStopTimer(DriverObject->DeviceObject);
	//KeSetEvent(&kt, IO_NO_INCREMENT, FALSE);




	//KeWaitForSingleObject(&g_Mutex, Executive, KernelMode, FALSE, NULL);
	//KeReleaseMutex(&g_Mutex, FALSE);



	//LARGE_INTEGER duetime;
	//duetime.QuadPart = -100 * 1000 * 1000;
	////int x = *(int*)context;
	//KeDelayExecutionThread(KernelMode, FALSE, &duetime);







	//ZwClose(NULL);

	DbgPrint("设置成功 threadFlase");
	UNREFERENCED_PARAMETER(DriverObject);
	KdPrint(("卸载程序 \n"));
	DbgPrint("开始关闭hFile == NULL");
	//HANDLE hFile = NULL;
	//ZwClose(hFile);
	//KdPrint(("abc %C",DriverObject->DriverName));
	UNICODE_STRING ustr = RTL_CONSTANT_STRING(SYM_NAME);
	ustr = RTL_CONSTANT_STRING(DEVICE_NAME);
	PWCHAR pWchar = (PWCHAR)ExAllocatePool(NonPagedPool, 0x1000);
	RtlZeroMemory(pWchar, 0x1000);
	RtlCopyMemory(pWchar, L"FFFFFFFFFFFF", sizeof(L"FFFFFFFFFFFF"));
	PCHAR pch = "thank";
	DbgPrint(pch);
	//---
	PCHAR tmpBuffer = "C:\\1a3\\3c1\\543.txt";
	STRING strBuffer = { 0 };
	RtlInitString(&strBuffer, tmpBuffer);
	UNICODE_STRING str = { 0 };
	RtlAnsiStringToUnicodeString(&str, &strBuffer, true);
	RtlUpcaseUnicodeString(&str, &str, false);
	DbgPrint("----wz---");
	DbgPrint("---%wZ---",str);
	DbgPrint("-----------------");
	DbgPrint("---------sourceStringUnicode------------");
	






	UNICODE_STRING sourceStringUnicode = {0};
	//sourceStringUnicode.Buffer = (PWCH)ExAllocatePool(NonPagedPool, 0x1000);
	//sourceStringUnicode.MaximumLength = 0x1000;
	RtlCopyUnicodeString(&sourceStringUnicode,&str);
	
	DbgPrint("---%wZ",sourceStringUnicode);


	RtlFreeUnicodeString(&str);
	RtlFreeUnicodeString(&sourceStringUnicode);
	
	PWCHAR tmpBufferW = (PWCHAR)ExAllocatePool(NonPagedPool, 0x1000);
	RtlZeroMemory(tmpBufferW, 0x1000);
	RtlStringCbCopyW(tmpBufferW, 0x1000, L"\\?\\");

	DbgPrint("----%ws", tmpBufferW);
	DbgPrint("--------------------------------");
	UNICODE_STRING tmpUnicode = { 0 }, DestionString = {0};
	RtlInitUnicodeString(&tmpUnicode,L"EX");
	RtlInitUnicodeString(&DestionString, L"Ex");
	if (FsRtlIsNameInExpression(&tmpUnicode, &DestionString, TRUE, NULL))
	{
		DbgPrint("---------------------成功-------------------");
	}
	else
	{ 
		DbgPrint("---------------------失败-------------------");
	}
	
	//DbgPrint("未卸载历程");
	// Delete routine


	//PsSetCreateProcessNotifyRoutine(PcreateProcessNotifyRoutine, TRUE);
	
	//LIST_ENTRY* plist = listHead.Blink;


/***	释放链表   ***/

	//LIST_ENTRY* plist = NULL;
	//_MyStruct *Myst = NULL;
	//while (listHead.Blink != &listHead)
	//{
	//	plist = RemoveTailList(&listHead);
	//	Myst = CONTAINING_RECORD(plist,_MyStruct,list);
	//	DbgPrint("释放进程中%s",Myst->processname);
	//	if (Myst != NULL)
	//	{
	//		ExFreePool(Myst);
	//	}
	//}

	if (pfileterdevobj != NULL)
	{
		IoDeleteDevice(pfileterdevobj);
	}

	while(DriverObject->DeviceObject)
	{
		//KdPrintEx(DriverObject->DeviceObject);
		//char x = 'a';
		//KdPrint(("asd"));
		//KdPrint(("abc %C",DriverObject->DriverName));
		if (DriverObject->DeviceObject == pfileterdevobj)
		{
			DbgPrint("pfileterdevobject is found\n");
		}
		IoDeleteDevice(DriverObject->DeviceObject);

	}
	UNICODE_STRING sysmname = { 0 };
	RtlInitUnicodeString(&sysmname, SYM_NAME);
	RtlInitUnicodeString(&ustr, DEVICE_NAME);
	IoDeleteSymbolicLink(&sysmname);



	if (pdodevobj != NULL)
	{
		IoDetachDevice(pdodevobj);
	}

	//KeSetEvent(&KThreadEvent, IO_NO_INCREMENT, FALSE);
	//  IO_NO_INCREMENT
}

extern "C"
NTSTATUS MyControl(PDEVICE_OBJECT pdevice,PIRP pirp )
{
	NTSTATUS status = STATUS_SUCCESS;
	DbgPrint("This my device control \n");
	PIO_STACK_LOCATION pstack = IoGetCurrentIrpStackLocation(pirp);
	ULONG iocode = pstack->Parameters.DeviceIoControl.IoControlCode;
	ULONG inlen = pstack->Parameters.DeviceIoControl.InputBufferLength;
	ULONG outlen = pstack->Parameters.DeviceIoControl.OutputBufferLength;
	ULONG ioinfo = 0;
	PCHAR data = "This String is from Device Driver !!!";
	int x = 10;
	DbgPrint("iocode对比%d::%d",iocode,IOCTL_MY_DRIVER_FUNCTION);
	switch (iocode)
	{
	case IOCTL_MY_DRIVER_FUNCTION:
	{
		DWORD indata = *(PDWORD)pirp->AssociatedIrp.SystemBuffer;
		DbgPrint("Kernel indata %x \n",indata);
		DbgPrint("Kernel outputBufferLength %d",outlen);
		HANDLE hevent = (HANDLE)indata;
		status = ObReferenceObjectByHandle(hevent,EVENT_MODIFY_STATE,*ExEventObjectType,KernelMode,(PVOID *)&pkernelevent,NULL);

		if (NT_SUCCESS(status))
		{
			ObReferenceObject(pkernelevent);
			if (NULL != pkernelevent)
			{
				DbgPrint("KEVENT:%x",&pkernelevent);
				status = PsCreateSystemThread(&hthread, 0, NULL, NULL, NULL, KernelThread2, PVOID(pkernelevent));
			}

		}

		//pirp->AssociatedIrp.SystemBuffer = &x;
		//RtlZeroMemory(pirp->AssociatedIrp.SystemBuffer,sizeof(int));



		RtlCopyBytes(pirp->AssociatedIrp.SystemBuffer,&x,sizeof(int));
		DbgPrint("Kernel outputValue: %d",pirp->AssociatedIrp.SystemBuffer);
		pirp->IoStatus.Information = sizeof(int);
		//ioinfo = 4;
		break;
	}
	default:
		break;
	}
	pirp->IoStatus.Status = status;
	pirp->IoStatus.Information = sizeof(int);
	IoCompleteRequest(pirp,IO_NO_INCREMENT);
	return status;
}
extern "C"
NTSTATUS MyCreate(PDEVICE_OBJECT pdevice,PIRP pirp )
{
	NTSTATUS status = STATUS_SUCCESS;
	DbgPrint("My device has been created \n");
	pirp->IoStatus.Status = status;
	pirp->IoStatus.Information = 0;
	IoCompleteRequest(pirp,IO_NO_INCREMENT);
	return status;
}
extern "C"
NTSTATUS MyRead(PDEVICE_OBJECT pdevice, PIRP pirp) 
{
	NTSTATUS status = STATUS_SUCCESS;
	DbgPrint("Read My device has be read \n");
	PIO_STACK_LOCATION pstack = IoGetCurrentIrpStackLocation(pirp);
	ULONG readSize = pstack->Parameters.Read.Length;
	PVOID readBuffer = pirp->AssociatedIrp.SystemBuffer;
	KIRQL oldirql = 0;
	// Wait for thirty seconds
	//-- Wait for thirty seconds
	KeAcquireSpinLock(&my_spinlock,&oldirql);
	//RtlCopyMemory(readBuffer, "ydmboy", strlen("ydmboy"));
	if (staticBook)
	{
		staticBook = false;
		LARGE_INTEGER DelayTime;
		DelayTime.QuadPart = -1000000LL * 60;
		KeDelayExecutionThread(KernelMode, FALSE, &DelayTime);
	}
	RtlCopyMemory(readBuffer, PhyBuffer, sizeof(PhyBuffer));
	DbgPrint("readBuffer:%s \n",readBuffer);
	strcpy((char*)PhyBuffer, "asd");
	DbgPrint("CURRENT KIRQL: %d",KeGetCurrentIrql());

	//PVOID  pv = ExAllocatePool(NonPagedPool,0x1000);


	//PVOID Allocation = ExAllocatePool3(POOL_FLAG_PAGED, 100, 'abcd');
	//ExAllocatePoolPriorityZero();

	//PWCHAR tmpBuffer = ExAllocatePool3();
	//ExAllocatePool2();
	// ExAllocatePool(NonPagedPool, 0x1000);

	pirp->IoStatus.Status = status;
	pirp->IoStatus.Information = sizeof(PhyBuffer);
	//pirp->IoStatus.Information = 10;

	//释放自旋锁
	KeReleaseSpinLock(&my_spinlock,oldirql);
	IoCompleteRequest(pirp,IO_NO_INCREMENT);
	return status;
}

extern "C"
NTSTATUS MyWrite(PDEVICE_OBJECT pdevice, PIRP pirp) 
{
	NTSTATUS status = STATUS_SUCCESS;
	DbgPrint("My device has be written\n");
	PIO_STACK_LOCATION pstack = IoGetCurrentIrpStackLocation(pirp);
	ULONG writeSize = pstack->Parameters.Write.Length;
	PVOID writeBuffer = pirp->AssociatedIrp.SystemBuffer;
	//RtlCopyMemory(readBuffer, "ydmboy", strlen("ydmboy"));

	DbgPrint((PCHAR)writeBuffer);
	pirp->IoStatus.Status = status;
	//pirp->IoStatus.Information = strlen("ydmboy");
	pirp->IoStatus.Information = 10;
	IoCompleteRequest(pirp,IO_NO_INCREMENT);
	return status;
}
extern "C"
NTSTATUS MyClose(PDEVICE_OBJECT pdevice,PIRP pirp )
{
	NTSTATUS status = STATUS_SUCCESS;
	DbgPrint("My device has be closed \n");
	pirp->IoStatus.Status = status;
	pirp->IoStatus.Information = 0;
	IoCompleteRequest(pirp,IO_NO_INCREMENT);
	return status;
}

extern "C"
NTSTATUS MyClean(PDEVICE_OBJECT pdevice,PIRP pirp )
{
	NTSTATUS status = STATUS_SUCCESS;
	DbgPrint("My device has be clean \n");
	pirp->IoStatus.Status = status;
	pirp->IoStatus.Information = 0;
	IoCompleteRequest(pirp,IO_NO_INCREMENT);
	return status;
}

typedef struct singleL
{
	int x;
	SINGLE_LIST_ENTRY  se;
	
}*pSingleL;

typedef struct List
{
	int x;
	LIST_ENTRY se;
};

VOID MyCreateProcessNotify(HANDLE parentId, HANDLE processId, BOOLEAN bCreate)
{
	DbgPrint("Debug into MyCreateProcessNotify");
	if (bCreate)
	{
		PEPROCESS tempep = NULL;
		NTSTATUS status = STATUS_SUCCESS;
		status = PsLookupProcessByProcessId(processId,&tempep);
		if (NT_SUCCESS(status))
		{
			ObDereferenceObject(tempep);
			PCHAR imageName = PsGetProcessImageFileName(tempep);
			DbgPrint("pid: <%d> name \n name: %s",processId,	
				imageName);
		}

	}
	return;
}



VOID FindProcessNotify()
{
	UNICODE_STRING apiName = { 0 };
	PCHAR apiAddr = NULL;
	ULONGLONG address64 = { 0 };
	RtlInitUnicodeString(&apiName,L"PsSetCreateProcessNotifyRoutine");
	PUCHAR addr = NULL;
	addr = (PUCHAR)MmGetSystemRoutineAddress(&apiName);
	//DbgPrint("%x",addr);
	for (int i = 0; i < 100; i++)
	{

		//DbgPrint("pssetcreateprocessnotifyroutineaddress: %p",addr++);

		//ULONGLONG add = address64 + 1;
		//// 判断地址

		////DbgPrint("address:%p\n", add);
		////DbgPrint("**:%x\n",*(char*)address64);

		//// 判断 address64里面的内容
		////PLONGLONG x = *address64;
		////DbgPrint("address's value :%llx",*(PLONGLONG*)address64);
		//PUCHAR x = *((PLONGLONG*)address64);


		//DbgPrint("%x",*addr++);
		

		if (*addr == 0xE9)
		{
			DbgPrint("%x",*addr);
			int d = 0;
			DbgPrint("%d",d);
			if (*(addr+(++d)) == 0xD6 && *(addr + (++d)) == 00 && *(addr + (++d)) == 00 && *(addr + (++d)) == 00)
			{
				DbgPrint("发现Address::%llx",addr);
				break;

			}
		}
		else
		{
			DbgPrint("Address未找到 \n");
		}
		addr++;
	}


	// 找到PsSetCreateProcessNotifyRoutineAddress的地址

	PUCHAR PspAddress = addr + *(addr + 1)+5;
	DbgPrint("PspSetCreateNotifyRoutineAddress: %p",PspAddress);



	for (int j = 0; j < 1000; j++)
	{
		if (*PspAddress == 0x4c )
		{
			int x = 0;
			if (*(PspAddress+(++x))==0x8d && *(PspAddress+(++x))==0x25 &&  *(PspAddress+(++x))==0x06 && *(PspAddress+(++x))==0x55  && *(PspAddress+(++x))==0xdd && *(PspAddress+(++x))==0xff)
			{
				DbgPrint("%x",PspAddress);
				break;
			}
			
		}
		PspAddress++;
	}
	// 计算数组的首地址
	//DbgPrint("arrAddress:%x",PspAddress);

	PUCHAR  routine = PspAddress + 3;
	routine += *(int*)routine + 4;
	DbgPrint("变量的地址:%p",routine);
	
	DWORD64 dwWord[64] = { 0 };
	DbgPrint("-----------------------------------");
	for (int w = 0; w < 64; w++)
	{
		dwWord[w] = *(DWORD64*)routine ;
		routine += 8;

		if (dwWord[w] == 0)
		{
			break;
		}
		dwWord[w] &= 0xFFFFFFFFFFFFFFF8;
		dwWord[w] = *(DWORD64*)dwWord[w];
		DbgPrint("%llx \n",dwWord[w]);
		
	}

	//关闭通知
	for(int x=0;dwWord[x]!=0;x++)
	{
		PsSetCreateProcessNotifyRoutine((PCREATE_PROCESS_NOTIFY_ROUTINE)dwWord[x],TRUE);
	}
	
	




	







	




	// 先找到 PspSetCreateProcessNotifyRoutine



	//int i = 0;
	//RtlInitUnicodeString(&apiName,L"PspSetCreateProcessNotifyRoutine");

	
	//ULONGLONG PspSetCreateProcessNotifyRoutineAddr = 0xfffff803de7b0d64;


	//PULONGLONG processNotifyArray = (PULONGLONG)0xfffff800f9d912d0;
	//ULONGLONG mask = 0xfffffffffffffff8;
	//ULONGLONG processNotifyActualAddress[100] = { 0 };
	//for (i = 0; i < 100; i++)
	//{
	//	if (processNotifyArray[i] != 0)
	//	{
	//		processNotifyActualAddress[i] = (processNotifyArray[i] & mask);
	//		DbgPrint("Address: %p",processNotifyActualAddress[i]);
	//	}
	//	else
	//	{
	//		i--;
	//		break;
	//	}

	//}



	
	//for (; i != 0; i--)
	//{
	//	DbgPrint("Address: %p",processNotifyActualAddress[i]);
	//}



	//apiAddr = (PCHAR)MmGetSystemRoutineAddress(&apiName);
	//if (!apiAddr)
	//{
	//	DbgPrint("Don't found the PspSetCreateProcessNotifyRoutine");
	//}
	//else
	//{
	//	DbgPrint("PspSetCreateProcessNotifyRoutine: %p", apiAddr);
	//}
	//if (!apiAddr)
	//{
	//	DbgPrint("FindProcessNotify Error\n");
	//	return;
	//}
	//for (int i = 0; i < 1000; i++)
	//{
	////	if(apiAddr)

	//}


}


NTSTATUS  RegistryCallback(PVOID callBackContext,PVOID arg1, PVOID arg2)
{
	NTSTATUS  status = STATUS_SUCCESS;
	REG_NOTIFY_CLASS tmpClass = (REG_NOTIFY_CLASS)(int)arg1;
	UNICODE_STRING tmpName = { 0 };
	RtlInitUnicodeString(&tmpName,L"*ASDIOPXXAADCGR");			
	PREG_CREATE_KEY_INFORMATION pkeinfo = (PREG_CREATE_KEY_INFORMATION)arg2;

	switch (tmpClass)
	{
		case RegNtPreOpenKey:
		{

			//DbgPrint("FsRtlIsNameExpressionName: %wZ",pkeinfo->CompleteName);
			break;
		}
		case RegNtPreOpenKeyEx:
		{

			__try
			{
				//DbgPrint("FsRtlIsNameExpressionName: %wZ",pkeinfo->CompleteName);
				if (FsRtlIsNameInExpression(&tmpName, pkeinfo->CompleteName, TRUE, NULL))
				{
					DbgPrint("ComleteName: %wZ", pkeinfo->CompleteName);
					DbgPrint("ASDIOPXXAADCGR Bad Create \n");
					status = STATUS_UNSUCCESSFUL;

				}
				//DbgPrint("Key info <%wZ> \n",pkeinfo->CompleteName);
			}
			__except (1)
			{
				DbgPrint("Bad memory \n");
			}
			break;
		}
		case RegNtPreCreateKey:
		{
			break;
		}
		case RegNtPreCreateKeyEx:
		{
			//DbgPrint("Create key or Open Key \n");
			
			__try
			{
				//DbgPrint("FsRtlIsNameExpressionName: %wZ",pkeinfo->CompleteName);
				if (FsRtlIsNameInExpression(&tmpName,pkeinfo->CompleteName,TRUE,NULL))
				{
					DbgPrint("ComleteName: %wZ",pkeinfo->CompleteName);
					DbgPrint("ASDIOPXXAADCGR Bad Create \n");
					status = STATUS_UNSUCCESSFUL;

				}
				//DbgPrint("Key info <%wZ> \n",pkeinfo->CompleteName);
			}
			__except(1)
			{
				DbgPrint("Bad memory \n");
			}
			break;
		}
		default:
			break;
	}
	return status;
}



typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union {
		struct {
			ULONG TimeDateStamp;
		};
		struct {
			PVOID LoadedImports;
		};
	};
	//struct _ACTIVATION_CONTEXT * EntryPointActivationContext;
	PVOID EntryPointActivationContext;
	PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

extern "C"
OB_PREOP_CALLBACK_STATUS  protectProcess(PVOID RegistrationContext,POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	PUCHAR imageFileName = (PUCHAR)PsGetProcessImageFileName((PEPROCESS)OperationInformation->Object);
	//if (strstr((const char*)imageFileName, "calc"))
	//{
		//DbgPrint("ProcessName:<%s>\n",imageFileName);
	//}

	if (strstr((const char*)imageFileName, "Calc"))
	{
		DbgPrint("calc stop\n");
		OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
		OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;
	}
	return OB_PREOP_SUCCESS;
}

typedef struct _CM_NOTIFY_ENTRY
{
	_CM_NOTIFY_ENTRY* ListFore;
	_CM_NOTIFY_ENTRY* ListNext;
	ULONG UnKnow2;
	LARGE_INTEGER Cookie;
	PVOID Context;
	PVOID Function;
}CM_NOTYFY_ENTRY,*PCM_NOTIFY_ENTRY;












extern "C" PVOID SearchMemory(PVOID pStartAddress, PVOID pEndAddress, PUCHAR pMemoryData, ULONG ulMemoryDataSize)
{

	return NULL;
}


extern "C" PVOID SearchCallbackListHead(PUCHAR pSpecialData, ULONG ulSpecialDataSize, LONG lSpecialOffset)
{
	UNICODE_STRING ustrFuncName;
	PVOID pCmUnRegisterCallback = NULL;
	PVOID pCallbackListHead = NULL;
	// 获取CmUnRegisterCallBack的函数地址
	RtlInitUnicodeString(&ustrFuncName, L"CmUnRegisterCallback");
	pCmUnRegisterCallback = MmGetSystemRoutineAddress(&ustrFuncName);
	if (NULL == pCmUnRegisterCallback)
	{
		return pCallbackListHead;
	}
	//pAddress = SearchMemory(pCmUnRegisterCallback, (PVOID)((PUCHAR)pCmUnRegisterCallback + 0xFF), pSpecialData, ulSpecialDataSize);

}

extern "C"
BOOL HandleError(NTSTATUS status)
{
	if(NT_SUCCESS(status))
	{
		DbgPrint("Handle SUCCESS \n");
		return TRUE;
	}
	else if(NT_INFORMATION(status))
	{
		DbgPrint("Handle INFORMATION \n");
	}
	else if (NT_WARNING(status))
	{
		DbgPrint("Handle WARNING\n");
	}
	else if(NT_ERROR(status))
	{
		DbgPrint("Handle ERROR\n");
	}
	return FALSE;

}


extern "C"
NTSTATUS CutRegisterCallback()
{
	UNICODE_STRING apiSearchName;
	RtlInitUnicodeString(&apiSearchName,L"CmUnRegisterCallback");
	LARGE_INTEGER int64_value = { 0 };
	int64_value.QuadPart = 0x10F;
	//pCmUnRegisterCallbackAddr = MmGetSystemRoutineAddress(&apiSearchName);
	PUCHAR pCmUnRegisterCallbackAddr = (PUCHAR)MmGetSystemRoutineAddress(&apiSearchName);

	DbgPrint("①pCmUnRegisterCallbackAddr:%I64X", pCmUnRegisterCallbackAddr);










	for (int i = 0; i < 100; i++)
	{
		//DbgPrint("①pCmUnRegisterCallbackAddr:");
		int d = 0;
		if (*pCmUnRegisterCallbackAddr == 0x48 && *(pCmUnRegisterCallbackAddr+(++d)) == 0x8d && *(pCmUnRegisterCallbackAddr + (++d)) == 0x0d && *(pCmUnRegisterCallbackAddr+(++d)) == 0x2b && *(pCmUnRegisterCallbackAddr+(++d)) == 0xa4 && *(pCmUnRegisterCallbackAddr+(++d)) == 0xd0 &&  *(pCmUnRegisterCallbackAddr+(++d)) == 0xff)
		{
			//DbgPrint("①pCmUnRegisterCallbackAddr:%I64X",pCmUnRegisterCallbackAddr);
			pCmUnRegisterCallbackAddr += 7 + (*((int*)(pCmUnRegisterCallbackAddr + 3)));
			break;
		}
		pCmUnRegisterCallbackAddr++;
	}
	PCM_NOTIFY_ENTRY pHeadList = (PCM_NOTIFY_ENTRY )(pCmUnRegisterCallbackAddr);
	PCM_NOTIFY_ENTRY pCur = pHeadList;
	int i = 0;
	LARGE_INTEGER cookieA = {0};
	while (pHeadList != pHeadList->ListNext)  // not null
	{
		pCur = pCur->ListNext;
		cookieA = pCur->Cookie;
		HandleError(CmUnRegisterCallback(cookieA));
	}





	



// test the address[
	//DbgPrint("1.RegisterCallback:%I64X\n",*(LARGE_INTEGER*)pCmUnRegisterCallbackAddr);
	////DbgPrint("1.RegisterCallback:0x%I64X",*(LARGE_INTEGER*)pCmUnRegisterCallbackAddr);
	////(("Hex value: 0x%I64X\n", value));
	//DbgPrint("2.RegisterCallback:%x\n",pCmUnRegisterCallbackAddr);
	////DbgPrint("3.RegisterCallback:%D\n",*(LARGE_INTEGER*)pCmUnRegisterCallbackAddr);
	//DbgPrint("3.RegisterCallback:%I64X\n",pCmUnRegisterCallbackAddr);
	//KdPrint(("4.RegisterCallback:%I64X\n",int64_value));
	//DbgPrint("5.PVOID:%D",sizeof(PVOID));
	//return STATUS_ALERTED;
	//if(NULL == )
	//PVODI = "CmUnRegisterCallback";
	return STATUS_SUCCESS;
}


extern "C"
NTSTATUS NotSupported(PDEVICE_OBJECT pdevice,PIRP irp)
{
	IoSkipCurrentIrpStackLocation(irp);
	return IoCallDriver(pdodevobj,irp);
}

extern "C"
NTSTATUS MyDispath(PDEVICE_OBJECT pdevice,PIRP irp)
{
	PIO_STACK_LOCATION pirpstack = NULL;
	//if (pdevice == pfileterdevobj)
	//{
		//DbgPrint("pdevice == pfileterdevobj \n");
	//	pirpstack = IoGetCurrentIrpStackLocation(irp);
	//	if (pirpstack == NULL)
	//	{
	//		return STATUS_UNSUCCESSFUL;
	//	}
	//	if (pirpstack->MinorFunction == TDI_CONNECT)
	//	{
	//		PTDI_REQUEST_KERNEL_CONNECT ptdiconnect = (PTDI_REQUEST_KERNEL_CONNECT)(&pirpstack->Parameters);
	//		PTA_ADDRESS ta_addr = ((PTRANSPORT_ADDRESS)(ptdiconnect->RequestConnectionInformation->RemoteAddress))->Address;
	//		PTDI_ADDRESS_IP tdi_addr = (PTDI_ADDRESS_IP)(ta_addr->Address);
	//		DWORD address = tdi_addr->in_addr;
	//		DbgPrint("Connect ip address <%d> \n",address);
	//		NETWORK_ADDRESS data = { 0 };
	//		USHORT port = tdi_addr->sin_port;
	//		data.address[0] = ((PCHAR)&address)[0];
	//		data.address[1] = ((PCHAR)&address)[1];
	//		data.address[2] = ((PCHAR)&address)[2];
	//		data.address[3] = ((PCHAR)&address)[3];
	//		data.port[0] = ((PCHAR)&port)[0];
	//		data.port[1] = ((PCHAR)&port)[1];
	//		port = data.port[0] + data.port[1];

	//		DbgPrint("Connect %d-%d-%d-%d port:%d\n",data.address[0],data.address[1],data.address[2],data.address[3],port);

	//	}
	//}

	//KeWaitForSingleObject(&NetDispatchEvent,Executive,KernelMode,FALSE,0);
	DbgPrint("MyDispatch/--//");
	//KeSetEvent(&NetDispatchEvent,IO_NO_INCREMENT, TRUE);
	IoSkipCurrentIrpStackLocation(irp);
	return IoCallDriver(pdodevobj,irp);

//处理情况
	//NTSTATUS status = STATUS_SUCCESS;
	//DbgPrint("My device has been created \n");
	//pirp->IoStatus.Status = status;
	//pirp->IoStatus.Information = 0;
	//IoCompleteRequest(pirp, IO_NO_INCREMENT);
	//return status;


}
extern "C"
NTSTATUS NetDriver(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING deviceName = { 0 };
	status = IoCreateDevice(DriverObject, 0, NULL, FILE_DEVICE_NETWORK, FILE_DEVICE_SECURE_OPEN, FALSE, &pfileterdevobj);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("Error create %x \n", status);
		return status;
	}
	DriverObject->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] = MyDispath;
	RtlInitUnicodeString(&deviceName, L"\\Device\\Tcp");
	status = IoAttachDevice(pfileterdevobj, &deviceName, &pdodevobj);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("error Attach %x\n", status);
		IoDeleteDevice(pfileterdevobj);
		return status;
	}
}
extern "C"
KIRQL WPOFFx64()
{
	KIRQL irql = KeRaiseIrqlToDpcLevel();
	DWORD64 cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;//将第16位置0
	__writecr0(cr0);
	_disable();
	return irql;
}

extern "C"
VOID WPONx64(KIRQL irql)
{
	DWORD64 cr0 = __readcr0();
	cr0 |= 0x10000;
	__writecr0(cr0);
	_enable();
	KeLowerIrql(irql);
	return;
}


extern "C"
NTSTATUS HookFunc();

typedef NTSTATUS(*PNtOpenProcess)(PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId);


extern "C"
NTSTATUS unHook()
{
	KIRQL tempIrql = WPOFFx64();
	if (NtOpenProcessptraddr)
	{
		RtlCopyMemory(NtOpenProcessptraddr, jmpBridgePtr, 13);
	}
	WPONx64(tempIrql);
	return 0;
}

extern "C"
NTSTATUS YOpenProcess(
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId
)
{
	//KIRQL tempIrql = WPOFFx64();
	//DbgPrint("YOpenProcess");
	//if (NtOpenProcessptraddr)
	//{
	//	RtlCopyMemory(NtOpenProcessptraddr, jmpBridgePtr, 13);
	//}
	//WPONx64(tempIrql);
	//NtOpenProcess(ProcessHandle,DesiredAccess,ObjectAttributes,ClientId);
	//HookFunc();
	//return 0;
	
	return ((PNtOpenProcess)jmpBridgePtr)(ProcessHandle,DesiredAccess,ObjectAttributes,ClientId);
}

extern "C"
NTSTATUS HookFunc()
{
	UNICODE_STRING apiName = { 0 };
	RtlInitUnicodeString(&apiName,L"NtOpenProcess");
	NtOpenProcessptraddr = MmGetSystemRoutineAddress(&apiName);
	if (!NtOpenProcessptraddr)
	{
		return STATUS_NOT_FOUND;

	}
	BYTE hookCode[] = {0x48,0xB8,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0xFF,0xE0};
	//BYTE hookCode[13];
	//for (int i = 0; i < 13; i++)
	//{
	//	hookCode[i] = 0x11;
	//}
	jmpBridgePtr = ExAllocatePool(NonPagedPool,0x1000);
	RtlZeroMemory(jmpBridgePtr,0x1000);


	*((PULONG_PTR*)(hookCode + 2)) = (PULONG_PTR)((PCHAR)NtOpenProcessptraddr +13);
	RtlCopyMemory((PUCHAR)jmpBridgePtr+13,hookCode,sizeof(hookCode));
	RtlCopyMemory(jmpBridgePtr, NtOpenProcessptraddr, 13);
	


	//int* a = NULL;
	//int b = *a;
	
	//*(int*)(hookCode) = 1;

	//int addr;
	//PULONG_PTR a = (PULONG_PTR)(&YOpenProcess);
	//PULONG_PTR b;
	//b = a;
	//*(PULONG_PTR*)(addr) = a;
	//b = a;
	//b = (PULONG_PTR)addr;
	////*(PULONG_PTR)(addr) = a;
	////((PULONG_PTR)addr) = a;
	KIRQL tempIrql = WPOFFx64();
	if (NtOpenProcessptraddr )
	{
		*((PULONG_PTR*)(hookCode + 2)) = (PULONG_PTR)(&YOpenProcess);
		RtlCopyMemory(NtOpenProcessptraddr, hookCode, 13);
	}	
	WPONx64(tempIrql);
	return STATUS_SUCCESS;
}



extern "C"
NTSTATUS DriverEntry( PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	DriverObject->DriverUnload = SampleUnLoad;
	HookFunc();
	//



	//*
	//	Initialize kevent;
	//*
	//KeInitializeEvent(&NetDispatchEvent, SynchronizationEvent, TRUE); // 有信号就是能通过
	

		
		//,KernelMode,0,0);


	//InitializeListHead(&listHead);
	//KeInitializeMutex(&g_Mutex,0);
	NTSTATUS status = STATUS_SUCCESS;
	
	
	
	//NO.14 网络连接请求的过滤



	//if (!HandleError(status))
	//{
	//	return status;
	//}

	//for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	//{
	//	DriverObject->MajorFunction[i] = NotSupported;
	//}

	
	
	//status = CmRegisterCallback(RegistryCallback,(PVOID)0x12345,&cookie);

	//delete cookie of cmpCallback
	//status = CutRegisterCallback();




	//DbgPrint("INT*: %d", );
	//DbgPrint("LONG* %d",);
	//DbgPrint("LONGLONG* %D",);

	//KeInitializeEvent(&KThreadEvent,NotificationEvent, FALSE);

	//while (1)
	//{
	//	DbgPrint("DriverEntry");
	//}
	int i = 100000;
	//while (i)
	//{

	//GENERIC_ALL
	//	DELETE
	//	GENERIC_ALL
	//	STANDARD_RIGHTS_ALL

	//	THREAD_ALL_ACCESS


	//DbgPrint("PsCreteSystemThread:%x",THREAD_ALL_ACCESS);
		
	
	
	//status = PsCreateSystemThread(&hthread, 0, NULL, NULL, NULL, KernelThread1, PVOID(&i));



		//i--;
	//}


	//LARGE_INTEGER delayTime = { 0 };
	//delayTime.QuadPart = -50000000;
	//KeDelayExecutionThread(KernelMode, FALSE, &delayTime);

// SINGLE_LIST_ENTRY'usage
	//SINGLE_LIST_ENTRY singleListEntry = {0};
	//int i = 0;
	//int j = 0;	
	//singleL* entry;
	//while (i < 10)
	//{
	//	entry = (singleL* )ExAllocatePool(NonPagedPool, sizeof(singleL));
	//	entry->x = i;
	//	PushEntryList(&singleListEntry,&(entry->se));
	//	i++;
	//}
	//SINGLE_LIST_ENTRY*  ptmp = singleListEntry.Next;
	//while (j < 10)
	//{
	//	//entry
	//	
	//	
	//	entry = (singleL*)CONTAINING_RECORD(ptmp, singleL, se);
	//	DbgPrint("%d \n",entry->x);
	//	//DbgPrint("%d \n",j);
	//	ptmp = ptmp->Next;
	//	j++;
	//}
	//SINGLE_LIST_ENTRY'usage

//	双链表
	//LIST_ENTRY ListEntry = { 0 };
	//InitializeListHead(&ListEntry);
	//int i = 0;
	//int j = 0;	
	//List* entry;
	//while (i < 10)
	//{
	//	entry = (List* )ExAllocatePool(NonPagedPool, sizeof(List));
	//	RtlZeroMemory(entry,sizeof(entry));
	//	entry->x = i;

	//	InsertTailList(&ListEntry, &(entry->se));
	//	//PushEntryList(&ListEntry,&(entry->se));
	//	i++;
	//}
	//LIST_ENTRY*  ptmp = ListEntry.Blink;
	//while (j < 10)
	//{
	//	//entry
	//	
	//	
	//	//entry = (singleL*)CONTAINING_RECORD(ptmp, singleL, se);
	//	//DbgPrint("%d \n",entry->x);
	//	////DbgPrint("%d \n",j);
	//	//ptmp = ptmp->Next;
	//	j++;
	//}




	


	//DbgPrint("SINGLE_LIST_ENTRY:%x---- STRUCT_SINGLE:%x",&singleListEntry,&entry);




		//ZwClose(hthread);
	PDEVICE_OBJECT  pdevice = NULL;
	//NTSTATUS status = STATUS_SUCCESS;
	//IO_STATUS_BLOCK io_stack = { 0 };
	//UNICODE_STRING sysmname = { 0 };
	//UNICODE_STRING deviceName;
	//RtlInitUnicodeString(&sysmname, SYM_NAME);
	////RtlInitUnicodeString(&deviceName, L"\\??\\C:\\Users\\opq\\Desktop\\MyDriver2.sys");
	//RtlInitUnicodeString(&deviceName, L"\\??\\C:\\Users\\opq\\Desktop\\WDMDriver.sys");
	//HANDLE hFile = NULL;
	//OBJECT_ATTRIBUTES oa = { 0 };

	//InitializeObjectAttributes(&oa,&deviceName,OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE,NULL,NULL);
	// status = ZwOpenFile(&hFile,FILE_EXECUTE ,&oa,&io_stack,FILE_SHARE_READ|FILE_SHARE_WRITE,FILE_NON_DIRECTORY_FILE);

	// //status = ZwOpenFile(&hFile,FILE_EXECUTE | SYNCHRONIZE,&oa,&io_stack,FILE_SHARE_READ|FILE_SHARE_WRITE,FILE_NON_DIRECTORY_FILE);
	//if (NT_SUCCESS(status))
	//{
	//	DbgPrint("ZwOpen successfully");
	//}
	//else
	//{
	//	DbgPrint("ZwOpen unsuccessfully %x",status);
	//}
	//ZwClose(hFile);

	//ZwOpenFile(&hFile,GENERIC_ALL,)
	////UNREFERENCED_PARAMETER(RegistryPath,0,&deviceName,FILE_DEVICE_UNKNOWN,0,TRUE,&);
	//NTSTATUS  ntStatus = IoCreateDevice( DriverObject,0,&deviceName,FILE_DEVICE_UNKNOWN,0,TRUE,&pdevice); 
	//if (!NT_SUCCESS(ntStatus))
	//{
	//	DbgPrint("Create Device Failed %x \n",ntStatus);
	//	return ntStatus;
	//}
	////PCSTR str = "";
	//pdevice->Flags |= DO_BUFFERED_IO;
	//ntStatus =IoCreateSymbolicLink(&sysmname,&deviceName);

	//if (!NT_SUCCESS(ntStatus))
	//{
	//	DbgPrint("Create SymbolicLink Failed %x \n",ntStatus);
	//	IoDeleteDevice(pdevice);
	//	return ntStatus;
	//}
	//KdPrint(("Hello World \n"));
	//DbgPrint("%ws",RegistryPath->Buffer);
	//HANDLE hd = NULL;
	//ZwClose(hd);
	//DbgPrint("DbgPrint \n");


	//DbgPrint("RegistryPath: %wZ",RegistryPath);
	//KernelQueryRegister(RegistryPath);



	//延迟调用的相关
	//DbgPrint("Current Irql=%d\n", KeGetCurrentIrql());
	//KIRQL rql = KeRaiseIrqlToDpcLevel();
	//DbgPrint("Current Irql=%d\n", KeGetCurrentIrql());
	//KeLowerIrql(rql);// oldirql == rql
	//DbgPrint("Current Irql=%d\n", KeGetCurrentIrql()); 
	//KeInitializeDpc(&kdpcobj,(PKDEFERRED_ROUTINE)dpcRoutine,NULL);
	//KeInsertQueueDpc(&kdpcobj,NULL,NULL);
	//NonPagedPool
	//ExAlocatePool();


	//PVOID tempbuffer = ExAllocatePoolWithTag(NonPagedPool,0x100,'abcd');
	//if (tempbuffer)
	//{
	//	RtlFillMemory(tempbuffer, 0x100, 1);
	//	ExFreePoolWithTag(tempbuffer, 'abcd');
	//}




	//DbgPrint("DriverName: %ws",DriverObject->DriverName.Buffer);

	//UNICODE_STRING DirDevice = {0};
	//RtlInitUnicodeString(&DirDevice,L"\\??\\C:\\Users\\opq\\Desktop\\123.txt");
	//KernelCopyFile("");
	//KernelQueryRegister(&DirDevice);  ==> bug 待解决
	//KernelQueryRegister(L"\\??\\C:\\Users\\opq\\Desktop\\123.txt");

	//KernelDeleteFile(L"\\??\\c:\\123.txt");
	//KernelCopyFile(L"\\??\\C:\\opq.txt",L"\\??\\C:\\Users\\opq\\Desktop\\123.txt");
	//DbgPrint("%ws",RegistryPath->Buffer);
	//KernelCopyFile(L"\\??\\c:\\opq.sy",L"\\??\\C:\\Users\\opq\\Desktop\\WDMDriver.sys");

	//UNICODE_STRING str = { 0 };
	//WCHAR wCh[128] = { 0 };
	//str.Buffer = wCh;
	//str.Length = wcslen(wCh)*2+2;
	//wcscpy(str.Buffer, L"ydmboy");

	//RtlInitUnicodeString(&str, L"ydmboy");
	//DbgPrint("UNICODE_STRING: %wZ",str);

	//NTSTATUS status = STATUS_SUCCESS;




	//UNICODE_STRING deviceName = { 0 };
	//RtlInitUnicodeString(&deviceName,DEVICE_NAME); 
	//KeInitializeSpinLock(&spinlock);
	//PDEVICE_OBJECT pdevice = NULL;
	
	//
	// CreateDevice 
	//
	//status = IoCreateDevice(DriverObject,0,&deviceName,FILE_DEVICE_UNKNOWN,0,FALSE,&pdevice);
	//pdevice->Flags |= DO_BUFFERED_IO;
	//if (!NT_SUCCESS(status))
	//{
	//	DbgPrint("The IoCreateDevice failed to run. %x \n",status);
	//}
	//UNICODE_STRING sysName = { 0 };
	//RtlInitUnicodeString(&sysName,SYM_NAME);
	//status = IoCreateSymbolicLink(&sysName,&deviceName);


	//if (!NT_SUCCESS(status))
	//{
	//	DbgPrint("The IoCreateSymblicLink failed to run. %x \n",status);
	//}
	//DriverObject->MajorFunction[IRP_MJ_CREATE] = MyCreate;
	//DriverObject->MajorFunction[IRP_MJ_READ] = MyRead;
	//DriverObject->MajorFunction[IRP_MJ_CLOSE] = MyClose;
	//DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MyControl;
	//


	// 
	//  进程劫持
	//


	//PLDR_DATA_TABLE_ENTRY ldr = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
	//ldr->Flags |= 0x20;

	//UNICODE_STRING attde = { 0 };
	//OB_CALLBACK_REGISTRATION ob = { 0 };
	//OB_OPERATION_REGISTRATION oor = { 0 };

	//ob.Version = ObGetFilterVersion();
	//ob.OperationRegistrationCount = 1;
	//ob.OperationRegistration = &oor;
	//RtlInitUnicodeString(&attde,L"321999");
	//ob.RegistrationContext = NULL;

	//// oor
	//oor.ObjectType = PsProcessType;
	//oor.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	//oor.PreOperation = protectProcess;
	//oor.PostOperation = NULL;
	//status = ObRegisterCallbacks(&ob,&_HANDLE);
	////////////////////////////








	// Test①
	//ULONGLONG x =  0x820a6191e1c;
	//DbgPrint("%p", ++x);
	
	
	// 找到进程通知并停用
	//FindProcessNotify();



	//**
	//	MyCreateProcessNotify thread  Notify
	//**
	



	//PsSetCreateProcessNotifyRoutine(MyCreateProcessNotify,FALSE);

	////**
	////	注册LoadImage通知  模块加载
	////**
	//DbgPrint("Begin the myloadImageNotify \n");
	//PsSetLoadImageNotifyRoutine(MyLoadImageNotify);



	//PsSetCreateThreadNotifyRoutine(MyCreateThreadNotify);

	//PsSetCreateProcessNotifyRoutine(PcreateProcessNotifyRoutine,FALSE);



	//**
	// Timer test
	//**


	//IoInitializeTimer(pdevice, TimeWork,NULL);


	//KeInitializeTimer(&time);
	//LARGE_INTEGER dpcTime = { 0 };
	//dpcTime.QuadPart = -10 * 1000 * 1000 * 4;
	//
	//LARGE_INTEGER dpcTimeOut = { 0 };
	//dpcTimeOut.QuadPart = -10 * 1000 * 1000 * 2;


	//KeInitializeDpc(&kdpcobj, (PKDEFERRED_ROUTINE)dpcRoutine, NULL);


	////KeSetTimer(&time, dpcTime,NULL);
	//KeSetTimer(&time, dpcTime,&kdpcobj);

	//DbgPrint("IoInitializeTimer");
	//NTSTATUS  ntStatus = KeWaitForSingleObject(&time,Executive,KernelMode,FALSE,&dpcTimeOut);
	//if (ntStatus == STATUS_TIMEOUT)
	//{
	//	KeCancelTimer(&time);
	//	DbgPrint("STATUS_TIMEOUT \n");
	//}


	//**
	//	Initialize Work Item
	//**

	//ExInitializeWorkItem(&wkItem,YWORKER_THREAD_ROUTINE,NULL);
	//ExQueueWorkItem(&wkItem,CriticalWorkQueue);


	// **
	// Start a time on devic;
	// **

	//IoInitializeTimer(pdevice, TimeWork,NULL);
	//IoStartTimer(pdevice);

	

	////U unicodeStr = { 0 };
	//DbgPrint("KIRQL = %d",KeGetCurrentIrql());
	//ZwClose(pdevice);



	//InitializeListHead(&listHead);
	//DbgPrint("%p:%p:%p",&listHead,listHead.Blink,listHead.Flink);

	//PsSetCreateProcessNotifyRoutine(PcreateProcessNotifyRoutine,false);
	DbgPrint("DbgPrint over!\n"); 
	return STATUS_SUCCESS;

} 