# crypto

## 编译
``` go build crypto_tool.go ```
## 使用方法
```Usage：./cryptoautotime company md5info deskey```
## 加密方法
1、首先使用md5将随机字符串进行md5转换得到一个字符串
2、"截至时间"+“公司简称”+”md5转换后的字符串“组成一个“json字符串”
3、再将“json字符串”使用DES的ECB加密方法生成一个密钥
