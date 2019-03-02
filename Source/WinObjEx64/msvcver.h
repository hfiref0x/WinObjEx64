/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2019
*
*  TITLE:       MSVCVER.H
*
*  VERSION:     1.72
*
*  DATE:        04 Feb 2019
*
*  Visual Studio compiler version determination.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#if defined _MSC_VER && _MSC_FULL_VER
    #if (_MSC_VER >= 1920) //2019 all variants (will be too many to list)
        #define VC_VER L"MSVC 2019"
    #elif (_MSC_VER >= 1910) //2017 all variants (too many to list)
        #define VC_VER L"MSVC 2017"
    #elif (_MSC_VER == 1900) //2015
        #if (_MSC_FULL_VER == 190023026) //2015 RTM
            #define VC_VER L"MSVC 2015"
        #elif (_MSC_FULL_VER == 190023506) // 2015 Update 1
            #define VC_VER L"MSVC 2015 Update 1"
        #elif (_MSC_FULL_VER == 190023918) // 2015 Update 2
            #define VC_VER L"MSVC 2015 Update 2"
        #elif (_MSC_FULL_VER == 190024210) // 2015 Update 3
            #define VC_VER L"MSVC 2015 Update 3"
        #elif (_MSC_FULL_VER == 190024215) // 2015 Update 3 with Cumulative Servicing Release
            #define VC_VER L"MSVC 2015 Update 3 CSR"
        #else
            #define VC_VER L"MSVC 2015" //exact variant unknown
        #endif
    #elif (_MSC_VER == 1810)
        #if (_MSC_FULL_VER == 180040629)
            #define VC_VER L"MSVC 2013 Update 5"
        #elif (_MSC_FULL_VER == 180031101)
            #define VC_VER L"MSVC 2013 Update 4"
        #elif (_MSC_FULL_VER == 180030723)
            #define VC_VER L"MSVC 2013 Update 3"
        #elif (_MSC_FULL_VER == 180030501)
            #define VC_VER L"MSVC 2013 Update 2"
        #elif (_MSC_FULL_VER < 180021005)
            #define VC_VER L"MSVC 2013 Preview/Beta/RC"
        #else
            #define VC_VER L"MSVC 2013"
        #endif
    #else
        #define VC_VER 0
    #endif
#else 
    #define VC_VER L"Unknown Compiler"
#endif