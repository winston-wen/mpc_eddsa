# MPC EdDSA

本项目基于：

1. Chelsea Komlo, Ian Goldberg. ["FROST: Flexible Round-Optimized Schnorr Threshold Signatures."](https://eprint.iacr.org/2020/852.pdf
) Conference on Selected Areas in Cryptography, 2020.
2. Komlo 和 Goldberg 提供的 [PoC 代码](https://git.uwaterloo.ca/ckomlo/frost)


# 1. 编译

编译此项目将得到 3 个可执行文件:
* `<proj>/out/mpc_sesman`, 是一个消息服务器, main 函数定义在 [sesman_server.rs](mpc_sesman/src/sesman_server.rs)
* `<proj>/out/demo_keygen`, 是一个 keygen 客户端, main 函数定义在 [demo_keygen.rs](mpc_demo/src/demo_keygen.rs)
* `<proj>/out/demo_sign`, 是一个 sign 客户端, main 函数定义在 [demo_sign.rs](mpc_demo/src/demo_sign.rs)

进入项目目录, 根据自己的需要, 选择如下两种模式之一, 编译整个项目.

1. debug 模式 (默认). 执行 `make` 就可以.
2. release 模式 (需指定). 
    * 方法一: `PROFILE=release make`
    * 方法二: 设定环境变量 `PROFILE=release`

debug 模式的编译速度快, 适合频繁改动 & 及时看到效果的开发阶段. release 模式生成更小 & 更快的程序.

# 2. 运行 demo

每次启动 keygen 或 sign 时, 需 **(重新)** 启动 `./mpc_sesman` . 其监听 `localhost:14514` .

## 2.1. 运行 `demo_keygen`

运行 `demo_keygen` 的全部流程如这个代码片所示:

```
./mpc_sesman
./demo_keygen  -m 1 2 ... M  -t T  -i 1
./demo_keygen  -m 1 2 ... M  -t T  -i 2
./demo_keygen  -m 1 2 ... M  -t T  -i ...
./demo_keygen  -m 1 2 ... M  -t T  -i M
```

其中，
* 参数 `-m / --members` 是密钥生成参与方的 ID 的集合. 用空格分隔. 假设密钥生成参与方一共有 M 名, 那么 ID 一般从 1 分配到 M.
* 参数 `-t / --threshold` 再加1, 就是 sign 时最少参与方数量.

上述每一个命令都占用一个终端. 也就是说, 你需要启动 `M + 1` 个终端.

执行顺序方面, 必须先执行 `./mpc_sesman`; 其他的顺序可以打乱.

运行成功后, `demo_keygen` 所在目录将产生 `assets` 子目录, 其下有 `M` 个名字如 `{member_id}@demo_keygen.keystore` 的文件。

## 2.2. 运行 `demo_sign`

运行 `demo_sign` 的全部流程如这个代码片所示：

```
./mpc_sesman
./demo_sign  -s s1 s2 ... sN  -i s1
./demo_sign  -s s1 s2 ... sN  -i s2
./demo_sign  -s s1 s2 ... sN  -i ...
./demo_sign  -s s1 s2 ... sN  -i sN
```

其中，
* 参数 `-s / signers` 是签名参与方 ID 的集合. 用空格分隔. 是密钥生成阶段的参与方的子集.
* 参数 `-i / signer_id` 是 `signers` 的一个元素. 用于寻找 `{signer_id}@demo_keygen.keystore` .

上述每一个命令都占用一个终端. 也就是说, 你需要启动 `N + 1` 个终端. 

执行顺序方面, 必须先执行 `./mpc_sesman` , 其他的顺序可以打乱.

运行成功后, 所有运行 `./demo_sign` 的终端将打印相同的签名结构体.

## 2.3. 利用此项目提供的 Makefile 来运行 demo

Makefile 里写好了基于 tmux 的自动部署脚本, 帮你在一个终端里 & 用一条命令做完 2.1 / 2.2 节描述的事情.
如果你了解 tmux 命令, 至少知道如何进入会话 & 退出会话 & 切换窗口, 那么可以分别运行以下命令:

```
make demo_keygen && tmux at -t eddsa:p1
make demo_sign && tmux at -t eddsa:p1
```
