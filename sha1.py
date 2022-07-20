# -*- coding: utf-8 -*-
# @Time   : 2022/7/20 1:58 下午
# @Author : Amigo
import struct
import io


def _left_rotate(n, b):
    """循环做移b位"""
    return ((n << b) | (n >> (32 - b))) & 0xffffffff


def _process_chunk(chunk, h0, h1, h2, h3, h4):
    """Process a chunk of data and return the new digest variables."""
    assert len(chunk) == 64

    w = [0] * 80

    # 将64字节的chunk, 分成16块数据, 每块4字节(32bit)
    for i in range(16):
        w[i] = struct.unpack(b'>I', chunk[i * 4:i * 4 + 4])[0]

    # 对每次传进来的chunk(64字节), 扩充成320字节
    for i in range(16, 80):
        w[i] = _left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)

    # 初始化魔数
    a = h0
    b = h1
    c = h2
    d = h3
    e = h4

    # 定义80轮运算中, 每轮用的f函数和k值
    for i in range(80):
        if 0 <= i <= 19:
            # Use alternative 1 for f from FIPS PB 180-1 to avoid bitwise not
            f = d ^ (b & (c ^ d))
            k = 0x5A827999
        elif 20 <= i <= 39:
            f = b ^ c ^ d
            k = 0x6ED9EBA1
        elif 40 <= i <= 59:
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        elif 60 <= i <= 79:
            f = b ^ c ^ d
            k = 0xCA62C1D6

        a, b, c, d, e = ((_left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff,
                         a, _left_rotate(b, 30), c, d)

    # 与第0轮的魔数相加, 并返回, 若还有未计算的chunk, 做为下一轮运算的初始化魔数
    h0 = (h0 + a) & 0xffffffff
    h1 = (h1 + b) & 0xffffffff
    h2 = (h2 + c) & 0xffffffff
    h3 = (h3 + d) & 0xffffffff
    h4 = (h4 + e) & 0xffffffff

    return h0, h1, h2, h3, h4


class Sha1Hash(object):
    """sha1 哈希算法"""

    name = 'python-sha1'
    digest_size = 20
    block_size = 64

    def __init__(self):
        # 初始化魔数
        self._h = (
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0,
        )

        # bytes object with 0 <= len < 64 used to store the end of the message
        # if the message length is not congruent to 64
        self._unprocessed = b''
        # Length in bytes of all data that has been processed so far
        self._message_byte_length = 0

    def update(self, arg):
        """Update the current digest.
        This may be called repeatedly, even after calling digest or hexdigest.
        Arguments:
            arg: bytes, bytearray, or BytesIO object to read from.
        """
        if isinstance(arg, (bytes, bytearray)):
            arg = io.BytesIO(arg)

        # 获取还未处理的明文块(64字节)
        chunk = self._unprocessed + arg.read(64 - len(self._unprocessed))

        # Read the rest of the data, 64 bytes at a time
        while len(chunk) == 64:
            # hash计算chunk(64字节), 若当前处理的chunk长度为64字节则一直循环处理, 直至chunk长度小于64字节,代表已经处理至明文末尾,
            # 需要对剩余的明文块进行填充, 做最终轮的运算
            self._h = _process_chunk(chunk, *self._h)
            self._message_byte_length += 64
            # 读取尚未处理的chunk
            chunk = arg.read(64)

        self._unprocessed = chunk
        return self

    def digest(self):
        """Produce the final hash value (big-endian) as a bytes object"""
        return b''.join(struct.pack(b'>I', h) for h in self._produce_digest())

    def hexdigest(self):
        """Produce the final hash value (big-endian) as a hex string"""
        return '%08x%08x%08x%08x%08x' % self._produce_digest()

    def _produce_digest(self):
        """对前面未处理的chunk(长度小于64字节)做最终的运算"""
        # Pre-processing:
        message = self._unprocessed
        message_byte_length = self._message_byte_length + len(message)

        # 先填充0x80, 即10000000(bit)
        message += b'\x80'

        # 填充0x00至填充明文的总长度对512(bit)取模余448
        message += b'\x00' * ((56 - (message_byte_length + 1) % 64) % 64)

        # 填充未填充明文的长度
        message_bit_length = message_byte_length * 8
        message += struct.pack(b'>Q', message_bit_length)

        # 处理填充好的最终明文块chunk
        h = _process_chunk(message[:64], *self._h)
        if len(message) == 64:
            return h
        return _process_chunk(message[64:], *h)


def sha1(data):
    """
    sha1 计算函数
    """
    return Sha1Hash().update(data).hexdigest()


if __name__ == '__main__':
    print(sha1(b"123456"))