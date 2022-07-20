# -*- coding: utf-8 -*-
# @Time   : 2022/7/20 2:27 下午
# @Author : Amigo
def Sha256sum(message: bytes) -> bytes:
    # 初始化魔数
    # 前8个素数2..19的平方根的小数部分的前32位
    h0 = 0x6a09e667
    h1 = 0xbb67ae85
    h2 = 0x3c6ef372
    h3 = 0xa54ff53a
    h4 = 0x510e527f
    h5 = 0x9b05688c
    h6 = 0x1f83d9ab
    h7 = 0x5be0cd19

    # 定义常数K 64
    # 前64个素数2..311的立方根的小数部分的前32位
    K = (0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
         0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
         0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
         0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
         0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
         0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
         0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
         0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
         0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
         0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
         0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2)

    # R为循环右移，
    # 右移之后可能会超过32位，所以要和0xffffffff做与运算，确保结果为32位。
    R = lambda x, n: ((x >> n) | (x << (32 - n))) & 0xffffffff
    # 大端  0x12,0x34,0x56,0x78 -> 0x12345678
    W = lambda i1, i2, i3, i4: (i1 << 24) | (i2 << 16) | (i3 << 8) | i4

    # 对每一个输入先添加一个'0x80'，即'10000000', 即128
    ascii_list = list(map(lambda x: x, message))
    msg_length = len(ascii_list) * 8
    ascii_list.append(128)

    # 补充0
    while (len(ascii_list) * 8 + 64) % 512 != 0:
        ascii_list.append(0)

    # 最后64为存放消息长度，以大端数存放。
    # 例如，消息为'a'，则长度为'0x0000000000000008'
    for i in range(8):
        ascii_list.append(msg_length >> (8 * (7 - i)) & 0xff)

    for i in range(len(ascii_list) // 64):  # 64*8=512bits
        # print(ascii_list[i*64:(i+1)*64])
        # 每个512bits的块进行循环
        w = []
        # 将512bits扩展到64*32bits=2048bits存入32位无符号数数组
        for j in range(16):
            s = i * 64 + j * 4
            w.append(W(ascii_list[s], ascii_list[s + 1], ascii_list[s + 2], ascii_list[s + 3]))
        for j in range(16, 64):
            s0 = (R(w[j - 15], 7)) ^ (R(w[j - 15], 18)) ^ (w[j - 15] >> 3)
            s1 = (R(w[j - 2], 17)) ^ (R(w[j - 2], 19)) ^ (w[j - 2] >> 10)
            w.append((w[j - 16] + s0 + w[j - 7] + s1) & 0xffffffff)
        # 初始化
        a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
        for j in range(64):
            s0 = R(a, 2) ^ R(a, 13) ^ R(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = s0 + maj
            s1 = R(e, 6) ^ R(e, 11) ^ R(e, 25)
            ch = (e & f) ^ ((~e) & g)
            t1 = h + s1 + ch + K[j] + w[j]
            h = g & 0xffffffff
            g = f & 0xffffffff
            f = e & 0xffffffff
            e = (d + t1) & 0xffffffff
            d = c & 0xffffffff
            c = b & 0xffffffff
            b = a & 0xffffffff
            a = (t1 + t2) & 0xffffffff

        # 与第0轮运算中的魔数进行相加, 若有下一轮明文块的运算, 则做为下一轮运算的初始化魔数, 若没有则输出即可
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff
        h5 = (h5 + f) & 0xffffffff
        h6 = (h6 + g) & 0xffffffff
        h7 = (h7 + h) & 0xffffffff

    digest = (h0 << 224) | (h1 << 192) | (h2 << 160) | (h3 << 128)
    digest |= (h4 << 96) | (h5 << 64) | (h6 << 32) | h7
    return ((h0).to_bytes(4, 'big') + (h1).to_bytes(4, 'big') +
            (h2).to_bytes(4, 'big') + (h3).to_bytes(4, 'big') +
            (h4).to_bytes(4, 'big') + (h5).to_bytes(4, 'big') +
            (h6).to_bytes(4, 'big') + (h7).to_bytes(4, 'big')).hex()


if __name__ == '__main__':
    print(Sha256sum(b'123456'))
