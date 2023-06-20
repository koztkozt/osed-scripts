#!/usr/bin/python3
import argparse

def to_hex(s):
    retval = list()
    for char in s:
        retval.append(hex(ord(char)).replace("0x", ""))
    return "".join(retval)


def push_string_1(input_string):
    rev_hex_payload = str(to_hex(input_string))
    rev_hex_payload_len = len(rev_hex_payload)

    instructions = []
    first_instructions = []
    null_terminated = False
    for i in range(rev_hex_payload_len, 0, -1):
        # add every 4 bytes (8 chars) to one push statement
        if i % 8 == 0:
            target_bytes = rev_hex_payload[i - 8:i]
            instructions.append(f"push dword 0x{target_bytes[6:8] + target_bytes[4:6] + target_bytes[2:4] + target_bytes[0:2]};")
        # handle the leftover instructions
        elif i == 1 and rev_hex_payload_len % 8 != 0:
            if rev_hex_payload_len % 8 == 2:
                first_instructions.append(f"mov al, 0x{rev_hex_payload[(rev_hex_payload_len - (rev_hex_payload_len%8)):]};")
                first_instructions.append("push eax;")
            elif rev_hex_payload_len % 8 == 4:
                target_bytes = rev_hex_payload[(rev_hex_payload_len - (rev_hex_payload_len%8)):]
                first_instructions.append(f"mov ax, 0x{target_bytes[2:4] + target_bytes[0:2]};")
                first_instructions.append("push eax;")
            else:
                target_bytes = rev_hex_payload[(rev_hex_payload_len - (rev_hex_payload_len%8)):]
                first_instructions.append(f"mov al, 0x{target_bytes[4:6]};")
                first_instructions.append("push eax;")
                first_instructions.append(f"mov ax, 0x{target_bytes[2:4] + target_bytes[0:2]};")
                first_instructions.append("push ax;")
            null_terminated = True

    instructions = first_instructions + instructions
    asm_instructions = "".join(instructions)
    return asm_instructions


def pad_to_multiple_of_4(string):
    remainder = len(string) % 4
    if remainder != 0:
        padding_length = 4 - remainder
        padding = ' ' * padding_length
        padded_string = string + padding
        return padded_string
    else:
        return string


def convert_neg(dword):
    return ((-int.from_bytes(dword, "little")) & 0xFFFFFFFF).to_bytes(4, "little")


def push_string_2(input_str, bad_chars, end=b"\x00"):
    def gen_push_code(dword):
        if not any(c in bad_chars for c in dword):
            return f'push  {hex(int.from_bytes(dword, "little"))};'

    def gen_neg_code(dword):
        neg_dword = convert_neg(dword)
        if not any(c in bad_chars for c in neg_dword):
            return (
                f'mov   eax, {hex(int.from_bytes(neg_dword, "little"))};'
                f"neg   eax;"
                f"push  eax;"
            )

    def gen_xor_code(dword):
        xor_dword_1 = xor_dword_2 = b""
        for i in range(4):
            for xor_byte_1 in range(256):
                xor_byte_2 = dword[i] ^ xor_byte_1
                if (xor_byte_1 not in bad_chars) and (xor_byte_2 not in bad_chars):
                    xor_dword_1 += bytes([xor_byte_1])
                    xor_dword_2 += bytes([xor_byte_2])
                    break
            else:
                return None

        return (
            f'mov   eax, {hex(int.from_bytes(xor_dword_1, "little"))};'
            f'xor   eax, {hex(int.from_bytes(xor_dword_2, "little"))};'
            f"push  eax;"
        )

    input_bytes = input_str.encode() if isinstance(input_str, str) else input_str
    input_bytes += end

    code = ""
    for i in range(0, len(input_bytes), 4)[::-1]:
        pad_byte = [c for c in range(256) if c not in bad_chars][0]
        dword = input_bytes[i: i + 4]
        dword += bytes([pad_byte]) * (4 - len(dword))

        new_code = gen_push_code(dword)
        if not new_code:
            new_code = gen_neg_code(dword)
        if not new_code:
            new_code = gen_xor_code(dword)
        if not new_code:
            raise Exception(f"cannot push dword: {dword}")
        code += new_code

    return code


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Push string generator")
    parser.add_argument("input_string", help="Input string to generate push instructions")
    args = parser.parse_args()

    input_string = args.input_string
    input_string_padded = pad_to_multiple_of_4(input_string)
    asm_instructions = push_string_1(input_string_padded)
    print("[", input_string_padded, "]:")
    print("\n".join(asm_instructions.split(";")).strip())  # Align output and print new lines

    badchars = b'\x00'
    asm_instructions = push_string_2(input_string, badchars)
    print("[", input_string, "]:")
    print("\n".join(asm_instructions.split(";")).strip())  # Align output and print new lines
