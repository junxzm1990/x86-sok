        .global _start

        .text
_start:
        # write(1, message, 13)
        mov     $1, %rax                # system call 1 is write
        mov     $1, %rdi                # file handle 1 is stdout
        mov     $message, %rsi          # address of string to output
        mov     $13, %rdx               # number of bytes
        syscall                         # invoke operating system to do the write
	jmp 	label2


message:
        .byte 0xed,0x00,0x00,0x00,0x00,0x1a,0x5a,0x0f,0x1f,0xff,0xc2,0x09,0x80,0x00,0x00,0x00,0x07,0xf7
	.byte 0xeb,0x2a,0xff,0xff,0x7f,0x57,0xe3,0x01,0xff,0xff,0x7f,0x57,0xeb,0x00,0xf0,0x00,0x00,0x24

label2:
        # exit(0)
        mov     $60, %rax               # system call 60 is exit
        xor     %rdi, %rdi              # we want return code 0
        syscall                         # invoke operating system to exit
