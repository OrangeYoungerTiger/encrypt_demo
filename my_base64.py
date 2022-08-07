# -*- coding: utf-8 -*-
# @Time   : 2022/7/20 2:52 下午
# @Author : Amigo
class b64:

    def __init__(self, table=None):
        # base64 编码表
        self.table = table
        if not table:
            self.table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

    def __str__(self):
        return 'Base64 Encoder / Decoder'

    def encode(self, text):
        pad_count = 0
        bins = str()
        # 将明文转换为bit
        for c in text:
            bins += '{:0>8}'.format(str(bin(ord(c)))[2:])
        # 原文进行填充, 填充长度为3的整数倍
        while len(bins) % 3:
            bins += '00000000'
            # 记录填充的位数
            pad_count += 1
        # 填充好的明文进行分组, 每3个字节为一组
        # 再将3字节(24bits), 分为4组, 每组6bit
        for i in range(6, len(bins) + int(len(bins) / 6), 7):
            bins = bins[:i] + ' ' + bins[i:]
        bins = bins.split(' ')
        if '' in bins:
            bins.remove('')
        base64 = str()
        # 分组并处理好的数据, 每6bit高两位填充0, 转为10进制, 从table表中取出对应下标的数据, 若遇到000000则直接取值为=
        for b in bins[:len(bins) - pad_count]:
            cc = int(b, 2)
            print(f"操作{b} , 计算大小为 {cc}, 获取符号为{self.table[cc]}")
            base64 += self.table[cc]
        for i in range(pad_count):
            # 填充多少位就补多少个=号
            base64 += '='
        return base64

    def decode(self, text):
        bins = str()
        for c in text:
            if c == '=':
                bins += '000000'
            else:
                bins += '{:0>6}'.format(str(bin(self.table.index(c)))[2:])
        for i in range(8, len(bins) + int(len(bins) / 8), 9):
            bins = bins[:i] + ' ' + bins[i:]
        bins = bins.split(' ')
        if '' in bins:
            bins.remove('')
        text = str()
        for b in bins:
            if not b == '00000000':
                text += chr(int(b, 2))
        return text


if __name__ == '__main__':
    print(b64().decode(text="MQ=="))
