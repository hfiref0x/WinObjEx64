/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022 - 2026
*
*  TITLE:       SYNC.C
*
*  VERSION:     2.11
*
*  DATE:        15 May 2026
*
*  Synchronization primitives.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

/*
* supInitFastEvent
*
* Purpose:
*
* Initialize fast event.
*
*/
VOID supInitFastEvent(
    _In_ PFAST_EVENT Event
)
{
    if (Event == NULL)
        return;

    Event->Value = FAST_EVENT_REFCOUNT_INC;
    Event->EventHandle = NULL;
}

/*
* supReferenceFastEvent
*
* Purpose:
*
* Make a reference for fast event.
*
*/
VOID supReferenceFastEvent(
    _In_ PFAST_EVENT Event
)
{
    if (Event == NULL)
        return;

    _InterlockedExchangeAddPointer((PLONG_PTR)&Event->Value, FAST_EVENT_REFCOUNT_INC);
}

/*
* supDereferenceFastEvent
*
* Purpose:
*
* Remove reference from fast event.
*
*/
VOID supDereferenceFastEvent(
    _In_ PFAST_EVENT Event,
    _In_opt_ HANDLE EventHandle
)
{
    ULONG_PTR value;

    if (Event == NULL)
        return;

    value = _InterlockedExchangeAddPointer((PLONG_PTR)&Event->Value, -FAST_EVENT_REFCOUNT_INC);
    if ((((value >> FAST_EVENT_REFCOUNT_SHIFT) & FAST_EVENT_REFCOUNT_MASK) - 1) == 0)
    {
        if (EventHandle)
        {
            NtClose(EventHandle);
            Event->EventHandle = NULL;
        }
    }
}

/*
* supSetFastEvent
*
* Purpose:
*
* Set event to signaled state.
*
*/
VOID supSetFastEvent(
    _In_ PFAST_EVENT Event
)
{
    HANDLE eventHandle;

    if (Event == NULL)
        return;

    if (!_InterlockedBitTestAndSetPointer((PLONG_PTR)&Event->Value, FAST_EVENT_SET_SHIFT)) {
        eventHandle = Event->EventHandle;
        if (eventHandle) {
            NtSetEvent(eventHandle, NULL);
        }
    }
}

/*
* supTestFastEvent
*
* Purpose:
*
* Returns fast event state.
*
*/
BOOLEAN supTestFastEvent(
    _In_ PFAST_EVENT Event
)
{
    ULONG_PTR value;

    if (Event == NULL)
        return FALSE;

    value = Event->Value;
    return (BOOLEAN)((value & FAST_EVENT_SET) != 0);
}

/*
* supResetFastEvent
*
* Purpose:
*
* Perform fast event manual reset.
*
*/
VOID supResetFastEvent(
    _In_ PFAST_EVENT Event
)
{
    HANDLE eventHandle;

    if (Event == NULL)
        return;

    eventHandle = Event->EventHandle;
    if (eventHandle != NULL) {
        NtResetEvent(eventHandle, NULL);
    }

    _InterlockedAndPointer((PLONG_PTR)&Event->Value, ~FAST_EVENT_SET);
}

/*
* supWaitForFastEvent
*
* Purpose:
*
* Do the wait for event, if event object not allocated - allocate it.
*
*/
BOOLEAN supWaitForFastEvent(
    _In_ PFAST_EVENT Event,
    _In_opt_ PLARGE_INTEGER Timeout
)
{
    BOOLEAN result;
    ULONG_PTR value;
    HANDLE eventHandle;
    HANDLE newHandle;
    NTSTATUS ntStatus;

    if (Event == NULL)
        return FALSE;

    value = Event->Value;
    if (value & FAST_EVENT_SET)
        return TRUE;

    if (Timeout && Timeout->QuadPart == 0)
        return FALSE;

    supReferenceFastEvent(Event);

    eventHandle = Event->EventHandle;
    if (eventHandle == NULL) {

        newHandle = NULL;
        ntStatus = NtCreateEvent(&newHandle,
            EVENT_MODIFY_STATE | SYNCHRONIZE,
            NULL,
            NotificationEvent,
            FALSE);

        if (!NT_SUCCESS(ntStatus) || (newHandle == NULL)) {
            supDereferenceFastEvent(Event, NULL);
            return FALSE;
        }

        eventHandle = _InterlockedCompareExchangePointer(
            &Event->EventHandle,
            newHandle,
            NULL);

        if (eventHandle != NULL) {
            NtClose(newHandle);
        }
        else {
            eventHandle = newHandle;

            if (Event->Value & FAST_EVENT_SET) {
                NtSetEvent(eventHandle, NULL);
            }
        }
    }

    if (!(Event->Value & FAST_EVENT_SET)) {
        result = (NtWaitForSingleObject(eventHandle, FALSE, Timeout) == STATUS_WAIT_0);
    }
    else {
        result = TRUE;
    }

    supDereferenceFastEvent(Event, eventHandle);

    return result;
}
