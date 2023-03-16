xx_consts = "+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
ord_0 = ord("0")


def xx_character(c):
    return xx_consts.index(c)


def uu_character(c):
    if c == "`":
        return 0
    else:
        return ord(c) - 32


# Modified from https://github.com/ezeeo/ctf-tools/blob/master/tools/coded/str/xx/xxdecode.py
def decode(s, parse_character):
    flag = ""
    ans = []
    k = -1
    for i in s:
        oldk = k
        k = parse_character(i)
        # That's basically what the old code would be doing, but somehow I doubt it's valid
        if k == -1:
            k = oldk
        if k == -1:
            raise Exception("Invalid first character")
        num = ""
        while k > 0:
            num += chr(k % 2 + ord_0)
            k = k // 2
        while len(num) < 6:
            num = num + "0"
        num = num[::-1]
        flag += num
    while len(flag) % 8 != 0:
        flag += "0"
    for i in range(0, len(flag), 8):
        x = 0
        for j in range(0, 8):
            x *= 2
            if flag[i + j] == "1":
                x += 1
        ans.append(x)
    return ans


def decode_from_file(file_path, parse_character):
    with open(file_path, "r") as f:
        lines = f.readlines()
    files = []
    ans = []
    for line in lines:
        line = line.strip()
        if line == "" or line.startswith("XXEncode  ") or line.startswith("UUEncode  ") or line.endswith(" bytes"):
            continue
        if line.startswith("begin "):
            output_file = line.split(" ", 2)[-1].strip()
            continue
        if line == "end":
            files.append((output_file, ans))
            ans = []
            del output_file
            continue
        length = parse_character(line[0])
        if length == 0:
            continue
        ans.extend(decode(line[1:], parse_character)[:length])
    return files


if __name__ == "__main__":
    import sys
    from pathlib import Path

    if len(sys.argv) != 3:
        print(f"Usage : {Path(__file__).name} [XXE, UUE] <filename>")
        exit(1)
    # Default to xxdecoding
    parse_character = xx_character
    if sys.argv[1] == "UUE":
        parse_character = uu_character
    file_path = sys.argv[2]
    files = decode_from_file(file_path, parse_character)
    for output_file, ans in files:
        with open(output_file, "wb") as f:
            f.write(bytes(ans))
