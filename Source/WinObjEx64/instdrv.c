/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2019, portions (C) Mark Russinovich, FileMon
*
*  TITLE:       INSTDRV.C
*
*  VERSION:     1.73
*
*  DATE:        07 Mar 2019
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

/*
* scmInstallDriver
*
* Purpose:
*
* Create SCM service entry describing kernel driver.
*
*/
BOOL scmInstallDriver(
    _In_ SC_HANDLE SchSCManager,
    _In_ LPCTSTR DriverName,
    _In_opt_ LPCTSTR ServiceExe,
    _Out_opt_ PDWORD lpStatus
)
{
    DWORD      resultStatus = ERROR_SUCCESS;
    SC_HANDLE  schService;

    schService = CreateService(SchSCManager, // SCManager database
        DriverName,            // name of service
        DriverName,            // name to display
        SERVICE_ALL_ACCESS,    // desired access
        SERVICE_KERNEL_DRIVER, // service type
        SERVICE_DEMAND_START,  // start type
        SERVICE_ERROR_NORMAL,  // error control type
        ServiceExe,            // service's binary
        NULL,                  // no load ordering group
        NULL,                  // no tag identifier
        NULL,                  // no dependencies
        NULL,                  // LocalSystem account
        NULL);                 // no password

    if (schService) {
        CloseServiceHandle(schService);
    }
    else {
        resultStatus = GetLastError();
    }

    if (lpStatus)
        *lpStatus = resultStatus;

    return TRUE;
}

/*
* scmStartDriver
*
* Purpose:
*
* Start service, resulting in SCM drvier load.
*
*/
BOOL scmStartDriver(
    _In_ SC_HANDLE SchSCManager,
    _In_ LPCTSTR DriverName,
    _Out_opt_ PDWORD lpStatus
)
{
    BOOL       ret = FALSE;
    DWORD      resultStatus = ERROR_SUCCESS;
    SC_HANDLE  schService;

    schService = OpenService(SchSCManager,
        DriverName,
        SERVICE_ALL_ACCESS);

    if (schService) {

        ret = StartService(schService, 0, NULL);

        resultStatus = GetLastError();

        if (resultStatus == ERROR_SERVICE_ALREADY_RUNNING) {
            ret = TRUE;
            resultStatus = ERROR_SUCCESS;
        }

        CloseServiceHandle(schService);
    }
    else {
        resultStatus = GetLastError();
    }

    if (lpStatus)
        *lpStatus = resultStatus;

    return ret;
}

/*
* scmOpenDevice
*
* Purpose:
*
* Open driver device by symbolic link.
*
*/
BOOL scmOpenDevice(
    _In_ LPCTSTR DriverName,
    _Out_opt_ PHANDLE lphDevice,
    _Out_opt_ PDWORD lpStatus
)
{
    BOOL bResult = FALSE;
    TCHAR completeDeviceName[MAX_PATH + 1];
    HANDLE hDevice;

    // assume failure
    if (lphDevice)
        *lphDevice = NULL;

    if (DriverName) {
        
        RtlSecureZeroMemory(completeDeviceName, sizeof(completeDeviceName));
        rtl_swprintf_s(completeDeviceName, MAX_PATH, TEXT("\\\\.\\%wS"), DriverName);

        hDevice = CreateFile(completeDeviceName,
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);

        if (lpStatus)
            *lpStatus = GetLastError();

        bResult = (hDevice != INVALID_HANDLE_VALUE);

        if (lphDevice) {
            if (bResult) {
                *lphDevice = hDevice;
            }
        }
        else {
            if (bResult)
                CloseHandle(hDevice);
        }

    }
    else {
        if (lpStatus)
            *lpStatus = ERROR_INVALID_PARAMETER;
    }

    return bResult;
}

/*
* scmStopDriver
*
* Purpose:
*
* Command SCM to stop service, resulting in driver unload.
*
*/
BOOL scmStopDriver(
    _In_ SC_HANDLE SchSCManager,
    _In_ LPCTSTR DriverName,
    _Out_opt_ PDWORD lpStatus
)
{
    BOOL            ret;
    INT             iRetryCount;
    DWORD           resultStatus = ERROR_SUCCESS;
    SC_HANDLE       schService;
    SERVICE_STATUS  serviceStatus;

    ret = FALSE;
    schService = OpenService(SchSCManager, DriverName, SERVICE_ALL_ACCESS);
    if (schService) {

        iRetryCount = 5;
        do {
            SetLastError(ERROR_SUCCESS);

            ret = ControlService(schService, SERVICE_CONTROL_STOP, &serviceStatus);
            if (ret != FALSE) {
                resultStatus = GetLastError();
                break;
            }

            resultStatus = GetLastError();
            if (resultStatus != ERROR_DEPENDENT_SERVICES_RUNNING)
                break;

            Sleep(1000);
            iRetryCount--;
        } while (iRetryCount);

        CloseServiceHandle(schService);
    }
    else {
        resultStatus = GetLastError();
    }

    if (lpStatus)
        *lpStatus = resultStatus;

    return ret;
}

/*
* scmRemoveDriver
*
* Purpose:
*
* Remove service entry from SCM database.
*
*/
BOOL scmRemoveDriver(
    _In_ SC_HANDLE SchSCManager,
    _In_ LPCTSTR DriverName,
    _Out_opt_ PDWORD lpStatus
)
{
    BOOL       bResult = FALSE;
    SC_HANDLE  schService;
    DWORD      resultStatus = ERROR_SUCCESS;

    schService = OpenService(SchSCManager, DriverName, SERVICE_ALL_ACCESS);
    if (schService) {
        bResult = DeleteService(schService);
        resultStatus = GetLastError();
        CloseServiceHandle(schService);
    }
    else {
        resultStatus = GetLastError();
    }

    if (lpStatus)
        *lpStatus = resultStatus;

    return bResult;
}

/*
* scmUnloadDeviceDriver
*
* Purpose:
*
* Combines scmStopDriver and scmRemoveDriver.
*
*/
BOOL scmUnloadDeviceDriver(
    _In_ LPCTSTR Name,
    _Out_opt_ PDWORD lpStatus
)
{
    BOOL      bResult = FALSE;
    SC_HANDLE schSCManager;

    DWORD resultStatus = ERROR_SUCCESS;

    if (Name) {
        schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        if (schSCManager) {
            scmStopDriver(schSCManager, Name, NULL);
            bResult = scmRemoveDriver(schSCManager, Name, &resultStatus);
            CloseServiceHandle(schSCManager);
        }
        else {
            resultStatus = GetLastError();
        }
    }
    else {
        resultStatus = ERROR_INVALID_PARAMETER;
    }

    if (lpStatus)
        *lpStatus = resultStatus;

    return bResult;
}

/*
* scmLoadDeviceDriver
*
* Purpose:
*
* Unload if already exists, Create, Load and Open driver instance.
*
*/
BOOL scmLoadDeviceDriver(
    _In_ LPCTSTR Name,
    _In_opt_ LPCTSTR Path,
    _Out_opt_ PHANDLE lphDevice,
    _Out_opt_ PDWORD lpStatus
)
{
    BOOL      bResult = FALSE;
    SC_HANDLE schSCManager;

    DWORD statusResult = ERROR_SUCCESS;

    //assume failure
    if (lphDevice) {
        *lphDevice = NULL;
    }

    if (Name) {
        schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        if (schSCManager) {

            scmRemoveDriver(schSCManager, Name, NULL);

            scmInstallDriver(schSCManager, Name, Path, NULL);

            if (scmStartDriver(schSCManager, Name, &statusResult)) {
                bResult = scmOpenDevice(Name, lphDevice, &statusResult);
            }
            CloseServiceHandle(schSCManager);
        }
        else {
            statusResult = GetLastError();
        }
    }
    else {
        statusResult = ERROR_INVALID_PARAMETER;
    }

    if (lpStatus)
        *lpStatus = statusResult;

    return bResult;
}
