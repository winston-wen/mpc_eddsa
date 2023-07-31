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

对输入参数的检错能力包括：
1. parties < threshold + 1
2. parties > share_count
3. <keysfile>重复

对输入参数的检错能力不包括：
1. <params>不一致
2. <message>不一致
```

## Note

由于目前`manager.rs`在分配参与方uuid方面的调试问题，`keygen`和`sign`在以下场景中会出现参与方之间存在两种${\rm uuid}$的bug。

也即，记第一轮`sign`有$t'_1$方，第二轮`sign`有$t'_2$方。当$t'_1<t'_2$时，第二轮分配${\rm uuid}$时会出现

$$
\begin{align*}
    P_1:~~&{\rm ID} = t'_1 + 1 &{\rm uuid} = {\rm uuid}_1 \\
    P_2:~~&{\rm ID} = t'_1 + 2 &{\rm uuid} = {\rm uuid}_1 \\
    ...... \\
    P_{t'_2-t'_1}:~~&{\rm ID} = t'_2 &{\rm uuid} = {\rm uuid}_1 \\
    P_{t'_2-t'_1+1}:~~&{\rm ID} = 1 &{\rm uuid} = {\rm uuid}_2 \\
    P_{t'_2-t'_1+2}:~~&{\rm ID} = 2 &{\rm uuid} = {\rm uuid}_2 \\
    ...... \\
    P_{t'_2}:~~&{\rm ID} = t'_1 &{\rm uuid} = {\rm uuid}_2
\end{align*}
$$

例如，`sign`第一轮的参数是`1/2/3`，第二轮的参数是`1/3/3`，则两轮${\rm uuid}$的具体分配情况分别是：

$$
\begin{align*}
    P_1:~~&{\rm ID} = 1 &{\rm uuid} = {\rm uuid}_1 \\
    P_2:~~&{\rm ID} = 2 &{\rm uuid} = {\rm uuid}_1
\end{align*}
$$

$$
\begin{align*}
    P_1:~~&{\rm ID} = 3 &{\rm uuid} = {\rm uuid}_1 \\
    P_2:~~&{\rm ID} = 1 &{\rm uuid} = {\rm uuid}_2 \\
    P_3:~~&{\rm ID} = 2 &{\rm uuid} = {\rm uuid}_2
\end{align*}
$$

虽然${\rm ID}$的分配是没有必要按照从$1$到$n$升序排列的，但每一轮只能有一种${\rm uuid}$。因此，在上述场景中，第二轮的所有参与方会一直处于等待$P_1$传输数据的状态。

目前可以通过以下两种方式解决：

1. 重新运行`manager`；
2. $P_1$重新调用`sign`命令。


# FROST

This implementation was part of the contribution for the following paper:

Chelsea Komlo, Ian Goldberg.
["FROST: Flexible Round-Optimized Schnorr Threshold SIgnatures."](https://eprint.iacr.org/2020/852.pdf
) Conference on Selected Areas in Cryptography, 2020.

This library provides the ability for participants to perform key generation
either via a trusted dealer or via a distributed key generation stage as
defined in the FROST KeyGen protocol. This library also provides the ability to
perform threshold signing operations and verification of signatures.

## Use

Note that this library does not provide support for serialization and
deserialization of data. Further, implementations should perform higher-level
authentication steps between participants.

## Development

Development on this project is frozen and will not implement any additional features.
Forking this project to extend features is welcome.

Running tests for this project is standard to any Cargo library. To run tests,
run:

```
cargo test
```

from the top-level directory of the repository.
