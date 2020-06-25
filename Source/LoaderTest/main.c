#include "global.h"

ULONG_PTR g_MaximumUserModeAddress = 0;

/*
* ShowVirtualBoxVesion
*
* Purpose:
*
* Read version from registry and output to console.
*
*/
VOID ShowVirtualBoxVersion()
{
    HKEY    hKey = NULL;
    LRESULT lRet;
    DWORD   dwSize;
    TCHAR   szBuffer[MAX_PATH + 1];

    //
    // Failures are non critical.
    //
    lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("Software\\Oracle\\VirtualBox"),
        0, KEY_READ, &hKey);

    if (lRet == ERROR_SUCCESS) {

        //
        // Read VBox version.
        //
        RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
        dwSize = MAX_PATH * sizeof(TCHAR);
        lRet = RegQueryValueEx(hKey, TEXT("Version"), NULL, NULL, (LPBYTE)&szBuffer, &dwSize);
        if (lRet == ERROR_SUCCESS) {
            printf_s("LDR: VirtualBox version %wS\r\n", szBuffer);
        }

        RegCloseKey(hKey);
    }
}

/*
* AssignPrivileges
*
* Purpose:
*
* Assign required privileges.
*
*/
BOOLEAN AssignPrivileges(
    _In_ BOOLEAN IsDebugRequired
)
{
    NTSTATUS ntStatus;

    if (IsDebugRequired) {
        ntStatus = supEnablePrivilege(SE_DEBUG_PRIVILEGE, TRUE);
        if (!NT_SUCCESS(ntStatus)) {
            printf_s("[!] Abort: SeDebugPrivilege is not assigned! NTSTATUS (0x%lX)\r\n", ntStatus);
            return FALSE;
        }
        else {
            printf_s("LDR: SeDebugPrivilege assigned\r\n");
        }
    }

    ntStatus = supEnablePrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE);
    if (!NT_SUCCESS(ntStatus)) {
        printf_s("[!] Abort: SeLoadDriverPrivilege is not assigned! NTSTATUS (0x%lX)\r\n", ntStatus);
        return FALSE;
    }
    else {
        printf_s("LDR: SeLoadDriverPrivilege assigned\r\n");
    }

    return TRUE;
}

int main()
{
    OSVERSIONINFO osv;

    HeapSetInformation(NULL, HeapEnableTerminationOnCorruption, NULL, 0);

    printf_s("LOADER TEST\r\n");

    RtlSecureZeroMemory(&osv, sizeof(osv));
    osv.dwOSVersionInfoSize = sizeof(osv);
    RtlGetVersion((PRTL_OSVERSIONINFOW)&osv);

    if (supUserIsFullAdmin()) {
        printf_s(T_PRNTDEFAULT, "LDR: User is admin");
    }

    ShowVirtualBoxVersion();

    CHAR szVersion[100];

    StringCchPrintfA(szVersion, 100,
        "LDR: Windows version: %u.%u build %u",
        osv.dwMajorVersion,
        osv.dwMinorVersion,
        osv.dwBuildNumber);

    printf_s(T_PRNTDEFAULT, szVersion);

    AssignPrivileges(TRUE);

    g_MaximumUserModeAddress = supQueryMaximumUserModeAddress();
    printf_s("LDR: Maximum User Mode address 0x%llX\r\n", g_MaximumUserModeAddress);

    TestRead();
    system("pause");
    ExitProcess(0);
}
