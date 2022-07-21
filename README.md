# func_self_enc_dec
函数运行时解密，运行后加密，基于ubuntu x86-64测试。

参考https://github.com/iqiyi/xHook和https://bbs.pediy.com/thread-191649.htm，
大部分函数都是从上述链接里直接拷贝而来，感谢大佬们的无私分享！

测试步骤：
1.编译libfuncselfdec.so：
gcc lib_func_self_enc_dec.c -g -O0 -fPIC -shared  -o libfuncselfdec.so
2.将当前目录加入库寻找路径：
echo $PWD >> /etc/ld.so.conf && /sbin/ldconfig
2.编译测试文件test:
gcc test.c  -g -O0 -L./  -lfuncselfdec  -o test
3.编译加密程序encrypt:
gcc encrypt_special_func.c -o encrypt
4.加密lib_func0函数：
./encrypt ./libfuncselfdec.so
5.运行测试：
./test

函数加密前：
![](https://github.com/tzs0/func_self_enc_dec/blob/main/before_enc.png)

函数加密后：
![](https://github.com/tzs0/func_self_enc_dec/blob/main/after_enc.png)

运行结果：
![](https://github.com/tzs0/func_self_enc_dec/blob/main/run_result.png)
