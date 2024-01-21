# MPC EdDSA FROST

本项目基于：

1. Chelsea Komlo, Ian Goldberg.["FROST: Flexible Round-Optimized Schnorr Threshold SIgnatures."](https://eprint.iacr.org/2020/852.pdf
) Conference on Selected Areas in Cryptography, 2020.
2. Komlo和Goldberg提供的FROST的PoC代码
   <https://git.uwaterloo.ca/ckomlo/frost>

## 编译

在项目根目录，执行`make`或`make release`。编译产物在`built`目录，有两个可执行文件：
1. `frost_test` -- MPC算法客户端
2. `luban_manager` -- MPC消息服务器

## 运行

不论是测试keygen还是sign，先进入built目录，启动`luban_manager`。

### Keygen

进入`built`目录, 开三个终端分别执行如下三条命令。

```sh
./frost_test sample.keygen1.json k1.json
./frost_test sample.keygen2.json k2.json
./frost_test sample.keygen3.json k3.json 
```

### Sign

进入`built`目录, 开两个终端，从如下三个命令任选两条执行。

```sh
./frost_test sample.sign23.json k1.json
./frost_test sample.sign23.json k2.json
./frost_test sample.sign23.json k3.json
```
