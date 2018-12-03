;*******************************************************************************
;
;  (C) COPYRIGHT AUTHORS, 2018
;
;  TITLE:       StubNtUserOpenWindowStation.asm
;
;  VERSION:     1.00
;
;  DATE:        30 Nov 2018
;
;  win32u NtUserOpenWindowStation implementation.
;
; THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
; ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
; TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
; PARTICULAR PURPOSE.
;
;*******************************************************************************/

public dwNtUserOpenWindowStation

_DATA$00 SEGMENT PARA 'DATA'

dwNtUserOpenWindowStation label dword
	dd	0

_DATA$00 ENDS

public StubNtUserOpenWindowStation

_TEXT$00 segment para 'CODE'

	ALIGN 16
	PUBLIC StubNtUserOpenWindowStation

StubNtUserOpenWindowStation PROC
	mov r10, rcx
	mov eax, dwNtUserOpenWindowStation
	syscall
	ret
StubNtUserOpenWindowStation ENDP

_TEXT$00 ENDS
	
END
