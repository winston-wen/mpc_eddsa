# MPC EdDSA

本项目基于：

1. Chelsea Komlo, Ian Goldberg. ["FROST: Flexible Round-Optimized Schnorr Threshold Signatures."](https://eprint.iacr.org/2020/852.pdf
) Conference on Selected Areas in Cryptography, 2020.
2. Komlo 和 Goldberg 提供的 [PoC 代码](https://git.uwaterloo.ca/ckomlo/frost)


# 1. 编译

编译此项目将得到 3 个可执行文件：
* `<proj>/out/mpc_sesman`，是一个消息服务器，main 函数定义在 [sesman_server.rs](mpc_sesman/src/sesman_server.rs)。
* `<proj>/out/demo_keygen`，是一个 keygen 客户端，main 函数定义在 [demo_keygen.rs](mpc_demo/src/demo_keygen.rs)。
* `<proj>/out/demo_sign`，是一个 sign 客户端，main 函数定义在 [demo_sign.rs](mpc_demo/src/demo_sign.rs)。

进入项目目录，根据自己的需要，选择如下两种模式之一，编译整个项目。

1. debug 模式（默认）。执行 `make` 就可以。
2. release 模式（需指定）。方法一：`PROFILE=release make`；方法二：设定 `PROFILE=release` 环境变量。

debug 模式的编译速度快，适合频繁改动、及时看到效果的开发阶段。release 模式生成更小、更快的程序。

# 2. 运行 demo

每次启动 keygen 或 sign 时，需 **（重新）** 启动 `./mpc_sesman`。`mpc_sesman` 监听 `localhost:14514`。

## 2.1. 运行 `demo_keygen`

运行 `demo_keygen` 的全部流程如这个代码片所示：

```
./mpc_sesman
./demo_keygen -m 1 -n N -t T
./demo_keygen -m 2 -n N -t T
./demo_keygen -m ... -n N -t T
./demo_keygen -m N -n N -t T
```

其中，
* 参数 `-m / --member_id` 是从 1 到 `n_members`的整数。
* 参数 `-n / --n_members` 是 keygen 参与方数量。
* 参数 `-t / --threshold` 再加1，就是 sign 时最少参与方数量；sign 的参与方数量如果小于 `threshold` ，会导致签名失败。

上述每一个命令都占用一个终端。也就是说，你需要启动 `n_members + 1` 个终端。

执行顺序方面，必须先执行 `./mpc_sesman`，其他的顺序可以打乱。

运行成功后，`demo_keygen` 所在目录将产生 `assets` 子目录，其下有 `n_members` 个名字如 `{member_id}@demo_keygen.keystore` 的文件。

## 2.2. 运行 `demo_sign`

运行 `demo_sign` 的全部流程如这个代码片所示：

```
./mpc_sesman
./demo_sign -m m1 -n N -s 1
./demo_sign -m m2 -n N -s 2
./demo_sign -m ... -n N -s ...
./demo_sign -m mN -n N -s N
```

其中，
* 参数 `-m / member_id` 是从 1 到 keygen 时 `n_members`的整数，不可重复，边界可取。每个具体值 `mi` 的含义为：「使用 keygen 时序号为 `mi` 的成员的分片」。
* 参数 `-n / n_signers` 是 sign 参与方数量；需大于 keygen 时的 `threshold`，否则将导致签名失败。
* 参数 `-s / signer_id` 是从 1 到 `n_signers` 的整数，不可重复，边界可取。

上述每一个命令都占用一个终端。也就是说，你需要启动 `n_signers + 1` 个终端。

执行顺序方面，必须先执行 `./mpc_sesman`，其他的顺序可以打乱。

运行成功后，所有运行 `./demo_sign` 的终端将打印相同的签名结构体。

## 2.3. 利用此项目提供的 Makefile 来运行 demo

Makefile 里写好了基于 tmux 的自动部署脚本，帮你在一个终端里、用一条命令做完 2.1 / 2.2 节描述的事情。
如果你了解 tmux 命令，至少知道如何进入会话、退出会话、切换窗口，那么可以依次运行以下命令：

```
make demo_keygen && tmux at -t eddsa:p1
make demo_sign && tmux at -t eddsa:p1
```
