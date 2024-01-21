# MPC EdDSA FROST

本项目基于：

1. Chelsea Komlo, Ian Goldberg.["FROST: Flexible Round-Optimized Schnorr Threshold SIgnatures."](https://eprint.iacr.org/2020/852.pdf
) Conference on Selected Areas in Cryptography, 2020.
2. Komlo和Goldberg提供的FROST的PoC代码
   <https://git.uwaterloo.ca/ckomlo/frost>

默认情况下，本项目暂时支持：

1. $(t,n)$-门限Ed25519签名算法Frost（`keygen`、`sign`）；
2. 支持仿BIP32的HD Key衍生；
3. 支持BIP39助记词；

## Build

执行`make`或`make release`编译

## Manager

运行`built`->`luban_manager`，以管理各个参与方之间的通信。

## Keygen

$(t,n)$-门限签名下，支持$n$方（如$P_1, P_2, ..., P_n$）共同发起`keygen`命令。

进入`built`目录, 开三个终端分别执行

```sh
./frost_test sample.keygen1.json k1.json
./frost_test sample.keygen2.json k2.json
./frost_test sample.keygen3.json k3.json 
```
其中`keygen.json`是`keygen`的参数, `ki.json`是输出的`keystore`文件路径。

## Sign message

$(t,n)$-门限签名下，支持$t'$方（$t < t'\le n$，如$P_1, P_2, ..., P_{t'}$）共同发起`sign`命令、对一条信息进行标准EdDSA签名。

```sh
./frost_test sample.sign23.json k3.json
```

