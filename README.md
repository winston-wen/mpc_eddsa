# MPC EdDSA FROST

本项目基于：

1. Chelsea Komlo, Ian Goldberg.["FROST: Flexible Round-Optimized Schnorr Threshold SIgnatures."](https://eprint.iacr.org/2020/852.pdf
) Conference on Selected Areas in Cryptography, 2020.
2. Komlo和Goldberg提供的FROST的PoC代码
   <https://git.uwaterloo.ca/ckomlo/frost>

默认情况下，本项目暂时支持：

1. $(t,n)$-门限Ed25519签名算法Frost（`keygen`、`sign`）

## Build

```sh
cargo build --release
```

## Manager

运行`manager`，以管理各个参与方之间的通信。

```sh
./target/release/mpc_eddsa-frost manager
```

可修改`Rocket.toml`或使用`[env vars]`覆盖，以使用不同的host/port，参见 <https://api.rocket.rs/v0.4/rocket/config/index.html#environment-variables> 。

```sh
ROCKET_ADDRESS=127.0.0.1 ROCKET_PORT=8008 ./target/release/mpc_eddsa-frost manager
```

## Keygen

$(t,n)$-门限签名下，支持$n$方（如$P_1, P_2, ..., P_n$）共同发起`keygen`命令。

***输入：函数体内、函数体外不需要读取 `keys.store`***

***输出：生成 `keys1.store`、`keys2.store`、……、`keysn.store`***

```sh
USAGE:
    mpc_eddsa-frost keygen [OPTIONS] <keysfile> <params>

OPTIONS:
    -a, --addr <manager_addr>    URL to manager. E.g. http://127.0.0.2:8002

ARGS:
    <keysfile>  Target keys file
    <params>    Threshold/parties
                例如1/3表示(1,3)-门限签名

t=1 && n=3; for i in $(seq 1 $n)
do
    echo "key gen for client $i out of $n"
    ./target/release/mpc_eddsa-frost keygen keys$i.store $t/$n &
    sleep 2
done

./target/release/mpc_eddsa-frost keygen -a http://127.0.0.1:8008 keys1.store 1/3
./target/release/mpc_eddsa-frost keygen -a http://127.0.0.1:8008 keys2.store 1/3
./target/release/mpc_eddsa-frost keygen -a http://127.0.0.1:8008 keys3.store 1/3    
```

## Sign message

$(t,n)$-门限签名下，支持$t'$方（$t < t'\le n$，如$P_1, P_2, ..., P_{t'}$）共同发起`sign`命令、对一条信息进行标准ECDSA签名。

***输入：函数体外需要读取 $t'$个 `keys.store`***

***输出：不生成 `keys.store`***

```sh
USAGE:
    mpc_eddsa-frost sign [OPTIONS] <keysfile> <params> <message>

OPTIONS:
    -a, --addr <manager_addr>    URL to manager

ARGS:
    <keysfile>  Keys file
    <params>    Threshold/parties/share_count
                例如1/2/3表示(1,3)-门限签名下由2方发起
    <message>   Message in hex format

./target/release/mpc_eddsa-frost sign -p m/0/1/2 -a http://127.0.0.1:8001 keys1.store 1/3/3 message
./target/release/mpc_eddsa-frost sign -p m/0/1/2 -a http://127.0.0.1:8001 keys2.store 1/3/3 message
./target/release/mpc_eddsa-frost sign -p m/0/1/2 -a http://127.0.0.1:8001 keys3.store 1/3/3 message

./target/release/mpc_eddsa-frost sign -p m/0/1/2 -a http://127.0.0.1:8001 keys1.store 1/2/3 message
./target/release/mpc_eddsa-frost sign -p m/0/1/2 -a http://127.0.0.1:8001 keys3.store 1/2/3 message

对输入参数的检错能力包括：
1. parties < threshold + 1
2. parties > share_count

对输入参数的检错能力不包括：
1. <keysfile>重复
2. <params>不一致
3. <message>不一致
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
