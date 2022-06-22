/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022
*
*  TITLE:       SYNC.C
*
*  VERSION:     2.00
*
*  DATE:        19 Jun 2022
*
*  Synchronization primitives.
* 
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

/*
*
* Fast events, taken from ph2
*
*/

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

    value = _InterlockedExchangeAddPointer((PLONG_PTR)&Event->Value, -FAST_EVENT_REFCOUNT_INC);
    if (((value >> FAST_EVENT_REFCOUNT_SHIFT) & FAST_EVENT_REFCOUNT_MASK) - 1 == 0)
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
    if (!_InterlockedBitTestAndSetPointer((PLONG_PTR)&Event->Value, FAST_EVENT_SET_SHIFT)) {
        eventHandle = Event->EventHandle;

        if (eventHandle)
        {
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
    return (BOOLEAN)Event->Set;
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
    if (Event == NULL)
        return;

    if (supTestFastEvent(Event))
        Event->Value = FAST_EVENT_REFCOUNT_INC;
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

    value = Event->Value;
    if (value & FAST_EVENT_SET)
        return TRUE;

    if (Timeout && Timeout->QuadPart == 0)
        return FALSE;

    supReferenceFastEvent(Event);
    eventHandle = Event->EventHandle;

    if (eventHandle == NULL) {

        NtCreateEvent(&eventHandle, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
        assert(eventHandle);

        if (NULL != _InterlockedCompareExchangePointer(
            &Event->EventHandle,
            eventHandle,
            NULL))
        {
            NtClose(eventHandle);
            eventHandle = Event->EventHandle;
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
