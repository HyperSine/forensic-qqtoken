# QQ安全中心 - 动态口令的生成算法

鉴于该App的服务群体是中文用户，故本篇文章不提供英文版。

I won't provide English version for this article. Because the app serves for QQ users which are Chinese mainly.

## 1. 动态口令的生成算法

动态口令的生成算法和RFC6238协议类似。

这里我们用 `secret` 代表动态口令的生成密钥，它一般是长度为32的octets，例如：

```python
b'\xa4\x22\x99\xe1\xce\xd4\xe7\x05\x48\x43\x92\x58\x3a\xd0\xb7\x6a\x8d\x6e\x89\x3c\x2d\xd1\x98\xbc\x39\x9b\x4c\x9a\x4e\x34\x21\xeb'
```

算法的大致过程如下：

1. 将当前北京时间向下对齐到30s，并按下面的格式格式化：

   ```
   yyyy-MM-dd HH:mm:ss
   ```

   得到一个长度为19的octets，记为 `timestamp`。
   
   例如，若当前北京时间为 `2020-02-12 13:02:46`，则向下对齐到30s，得到 `timestamp` 为：
   
   ```python
   b'2020-02-12 13:02:30'
   ```

2. 将 `timestamp` 添加到 `secret` 后面，并对新的octets做SHA256运算，得到长度为32的octets，记为 `digest`。

   例如：

   ```python
   # digest = hashlib.sha256(secret + timestamp).digest()
   digest = b'\x89\x60\xf9\xeb\x42\x67\x61\x0e\x74\xc0\x98\x59\x76\x88\xaf\x6e\x25\xfb\xf2\x6b\x6c\xe3\xbe\x95\x02\xcb\xed\xd8\x3e\x0b\xf9\x44'
   ```

3. 将 `digest` 的每个octet在原位分割成高四位和低四位，得到 `digest_exp`。

   例如：

   ```python
   digest_exp = [8, 9, 6, 0, 15, 9, 14, 11, 4, 2, 6, 7, 6, 1, 0, 14, 7, 4, 12, 0, 9, 8, 5, 9, 7, 6, 8, 8, 10, 15, 6, 14, 2, 5, 15, 11, 15, 2, 6, 11, 6, 12, 14, 3, 11, 14, 9, 5, 0, 2, 12, 11, 14, 13, 13, 8, 3, 14, 0, 11, 15, 9, 4, 4]
   ```

4. 按照如下公式得到6位动态口令的每一位：

   ![](https://latex.codecogs.com/gif.latex?%5Ctexttt%7Bcode%7D%5Bi%5D%3D%28%5Csum_%7Bj%3D0%7D%5E%7B8%7D%5Ctexttt%7Bdigest%5C_exp%7D%5Bi&plus;1&plus;7j%5D%29%5C%20Mod%5C%2010)

## 2. 如何获取secret

__要求条件：__

  1. __手机安装了“QQ安全中心”这个App，版本6.9.10或以上，并且在App里登录了QQ账号。__

  2. __手机已经root。__

`secret` 是存储在 

```
/data/data/com.tencent.token/databases/mobiletoken.db
```

数据库文件中，该数据库是经过加密的。

并且在数据库中，`secret` 被加密保存，加密的密钥存在

```
/data/data/com.tencent.token/shared_prefs/token_save_info.xml
```

下面将会介绍如何提取 `secret`：

1. 确保“QQ安全中心”已经退出。

2. 查看 `/data/data/com.tencent.token/shared_prefs/token_save_info.xml` 文件的内容。

   你可以用adb来查看：

   ```console
   $ adb shell
   gemini:/ $ su   
   gemini:/ # cat /data/data/com.tencent.token/shared_prefs/token_save_info.xml                                                                             
   <?xml version='1.0' encoding='utf-8' standalone='yes' ?>
   <map>
       <boolean name="token_status" value="true" />
       <string name="token_info">14C27B6EC74543302F02C01B50E16ED7</string>
       <int name="token_type" value="2" />
   </map>
   gemini:/ # 
   ```

   其中 `14C27B6EC74543302F02C01B50E16ED7` 就是加密 `secret` 的密钥。

   每次“QQ安全中心”退出，这个值都会变化。

3. 提取 `mobiletoken.db`：

   ```console
   $ adb root
   restarting adbd as root
   $ adb pull /data/data/com.tencent.token/databases/mobiletoken.db
   /data/data/com.tencent.token/databases/mobiletoken.db: 1 file pulled. 0.9 MB/s (13312 bytes in 0.013s)
   ```

4. 使用 `decrypt-database.py` 解密 `mobiletoken.db`：

   ```
   Usage:
       ./decrypt-database.py <mobiletoken.db的路径>
   ```

   例如：

   ```console
   $ ./decrypt-database.py ./mobiletoken.db
   ```

5. 查看加密的 `secret`：

   ```console
   $ sqlite3 ./mobiletoken.db 
   SQLite version 3.28.0 2019-04-15 14:49:49
   Enter ".help" for usage hints.
   sqlite> select hex(data) from main.token_conf;
   AE28874351F682CFDD5263E3D71D74E7D8847F00D157923539811AD0920499B9A88A5B8021C1ED2E7B20BD597ADA33AE
   sqlite>
   ```

   其中 `AE28874351F682CFDD5263E3D71D74E7D8847F00D157923539811AD0920499B9A88A5B8021C1ED2E7B20BD597ADA33AE` 就是加密的 `secret`。

6. 解密出 `secret`：

   ```
   Usage:
       ./decrypt-secret.py <加密的secret> <加密secret的密钥>
   ```

   例如：

   ```console
   $ ./decrypt-secret.py AE28874351F682CFDD5263E3D71D74E7D8847F00D157923539811AD0920499B9A88A5B8021C1ED2E7B20BD597ADA33AE 14C27B6EC74543302F02C01B50E16ED7
   a42299e1ced4e705484392583ad0b76a8d6e893c2dd198bc399b4c9a4e3421eb
   ```

   其中 `a42299e1ced4e705484392583ad0b76a8d6e893c2dd198bc399b4c9a4e3421eb` 就是我们要找的 `secret`。

## 3. 使用secret生成动态密码

```
Usage:
    ./generate-qqtoken.py <secret>
```

例如：

```console
$ ./generate-qqtoken.py a42299e1ced4e705484392583ad0b76a8d6e893c2dd198bc399b4c9a4e3421eb
530800
```
