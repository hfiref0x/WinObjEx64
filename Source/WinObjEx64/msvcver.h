/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018 - 2025
*
*  TITLE:       MSVCVER.H
*
*  VERSION:     2.08
*
*  DATE:        13 Jun 2025
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

    // Visual Studio 2022 (17.x)
    #if (_MSC_VER >= 1930) 
        #if (_MSC_VER >= 1938)
            #define VC_VER L"MSVC 2022 (v17.8)"
        #elif (_MSC_VER >= 1937)
            #define VC_VER L"MSVC 2022 (v17.7)"
        #elif (_MSC_VER >= 1936)
            #define VC_VER L"MSVC 2022 (v17.6)"
        #elif (_MSC_VER >= 1935)
            #define VC_VER L"MSVC 2022 (v17.5)"
        #elif (_MSC_VER >= 1934)
            #define VC_VER L"MSVC 2022 (v17.4)"
        #elif (_MSC_VER >= 1932 && _MSC_VER < 1934)
            #define VC_VER L"MSVC 2022 (v17.2-v17.3)"
        #elif (_MSC_VER >= 1931)
            #define VC_VER L"MSVC 2022 (v17.1)"
        #elif (_MSC_VER == 1930)
            #define VC_VER L"MSVC 2022 (v17.0)"
        #else
            #define VC_VER L"MSVC 2022"
        #endif

    // Visual Studio 2019 (16.x)
    #elif (_MSC_VER >= 1920 && _MSC_VER < 1930)
        #if (_MSC_VER == 1929)
            #define VC_VER L"MSVC 2019 (v16.10-v16.11)"
        #elif (_MSC_VER == 1928)
            #define VC_VER L"MSVC 2019 (v16.8-v16.9)"
        #elif (_MSC_VER == 1927)
            #define VC_VER L"MSVC 2019 (v16.7)"
        #elif (_MSC_VER == 1926)
            #define VC_VER L"MSVC 2019 (v16.6)"
        #elif (_MSC_VER == 1925)
            #define VC_VER L"MSVC 2019 (v16.5)"
        #elif (_MSC_VER == 1924)
            #define VC_VER L"MSVC 2019 (v16.4)"
        #elif (_MSC_VER == 1923)
            #define VC_VER L"MSVC 2019 (v16.3)"
        #elif (_MSC_VER == 1922)
            #define VC_VER L"MSVC 2019 (v16.2)"
        #elif (_MSC_VER == 1921)
            #define VC_VER L"MSVC 2019 (v16.1)"
        #elif (_MSC_VER == 1920)
            #define VC_VER L"MSVC 2019 (v16.0)"
        #else
            #define VC_VER L"MSVC 2019"
    #endif

    // Visual Studio 2017 (15.x)
    #elif (_MSC_VER >= 1910 && _MSC_VER < 1920)
    #if (_MSC_VER == 1916)
        #define VC_VER L"MSVC 2017 (v15.9)"
    #elif (_MSC_VER == 1915)
        #define VC_VER L"MSVC 2017 (v15.8)"
    #elif (_MSC_VER == 1914)
        #define VC_VER L"MSVC 2017 (v15.7)"
    #elif (_MSC_VER == 1913)
        #define VC_VER L"MSVC 2017 (v15.6)"
    #elif (_MSC_VER == 1912)
        #define VC_VER L"MSVC 2017 (v15.5)"
    #elif (_MSC_VER == 1911)
        #define VC_VER L"MSVC 2017 (v15.3-v15.4)"
    #elif (_MSC_VER == 1910)
        #define VC_VER L"MSVC 2017 (v15.0-v15.2)"
    #else
        #define VC_VER L"MSVC 2017"
    #endif

    // Other versions
    #else
        #define VC_VER L"Unknown MSVC Version"
    #endif

#else 
    #define VC_VER L"Unknown Compiler"
#endif
