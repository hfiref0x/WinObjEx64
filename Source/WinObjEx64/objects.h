/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2018
*
*  TITLE:       OBJECTS.H
*
*  VERSION:     1.52
*
*  DATE:        08 Jan 2018
*
*  Header file for internal Windows objects handling.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

//
// Description Resource Id string table starting index
//
// Actual id = TYPE_DESCRIPTION_START_INDEX + TYPE_*
//
#define TYPE_DESCRIPTION_START_INDEX    100

//
// Object Type Indexes Used By Program Only 
// NOT RELATED TO REAL OBJECTS INDEXES
// TYPE_UNKNOWN and TYPE_MAX always end this list
// ImageList icon index used from range TYPE_DEVICE - TYPE_UNKNOWN
//
#define TYPE_DEVICE                     0
#define TYPE_DRIVER                     1
#define TYPE_SECTION                    2
#define TYPE_PORT                       3
#define TYPE_SYMLINK                    4
#define TYPE_KEY                        5
#define TYPE_EVENT                      6
#define TYPE_JOB                        7
#define TYPE_MUTANT                     8
#define TYPE_KEYEDEVENT                 9
#define TYPE_TYPE                       10
#define TYPE_DIRECTORY                  11
#define TYPE_WINSTATION                 12
#define TYPE_CALLBACK                   13
#define TYPE_SEMAPHORE                  14
#define TYPE_WAITABLEPORT               15
#define TYPE_TIMER                      16
#define TYPE_SESSION                    17
#define TYPE_CONTROLLER                 18
#define TYPE_PROFILE				    19
#define TYPE_EVENTPAIR                  20
#define TYPE_DESKTOP                    21
#define TYPE_FILE                       22
#define TYPE_WMIGUID                    23
#define TYPE_DEBUGOBJECT                24
#define TYPE_IOCOMPLETION               25
#define TYPE_PROCESS                    26
#define TYPE_ADAPTER                    27
#define TYPE_TOKEN                      28
#define TYPE_ETWREGISTRATION            29
#define TYPE_THREAD                     30
#define TYPE_TMTX                       31
#define TYPE_TMTM                       32
#define TYPE_TMRM                       33
#define TYPE_TMEN                       34
#define TYPE_PCWOBJECT                  35
#define TYPE_FLTCONN_PORT               36
#define TYPE_FLTCOMM_PORT               37
#define TYPE_POWER_REQUEST              38
#define TYPE_ETWCONSUMER                39
#define TYPE_TPWORKERFACTORY            40
#define TYPE_COMPOSITION                41
#define TYPE_IRTIMER                    42
#define TYPE_DXGKSHAREDRES              43
#define TYPE_DXGKSHAREDSWAPCHAIN        44
#define TYPE_DXGKSHAREDSYNC             45
#define TYPE_DXGKCURDXGPROCESSOBJECT    46
#define TYPE_MEMORYPARTITION            47
#define TYPE_UNKNOWN                    48
#define TYPE_MAX                        49

extern LPCWSTR g_lpObjectNames[TYPE_MAX];
