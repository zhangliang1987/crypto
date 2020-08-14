package main

import (
  //"flag"
  "bytes"
  "crypto/cipher"
  "crypto/des"
  "fmt"
  "os"
  "time"
  "regexp"
  "crypto/md5"
  "encoding/hex"
  "encoding/json"
  
)

func md5V(str string) string  {
    h := md5.New()
    h.Write([]byte(str))
    return hex.EncodeToString(h.Sum(nil))
}

type AuthorizecodeJson struct {
    Company string `json:"company"`
    DuetoTime string `json:"duetotime"`
    Md5Info string `json:"md5info"`
}


func main() {
  //args
  if len(os.Args) < 5 {
    fmt.Println("Usage：" + os.Args[0] + "autotime company md5info deskey")
    return
  }

  var dutotime = os.Args[1] 
  _, err := time.Parse("2006-01-02",dutotime)
  if err != nil {
    fmt.Println("日期格式不正确，请正确填写日期：例如\"2020-03-21\"")
    return
  }
  
  var IsLetter = regexp.MustCompile(`^[a-zA-Z0-9]+$`).MatchString
  var company = os.Args[2]
  if !IsLetter(company) {
    fmt.Println("公司名称必须是字母或者数字")
    return
  }

  var info = os.Args[3]
  
  deskey := os.Args[4]
  if !IsLetter(deskey) {
    fmt.Println("DES的密钥必须是一个字母或者数字")
    return
  }
  
//将传入的info做一个md5转换   
  md5info := md5V(info)
  fmt.Println("md5:" + md5info)
  
//将截至时间、公司名称、info组成一个json字符串然后做一个des转换
  authorizecodeJsonObj := AuthorizecodeJson{ Company:company, DuetoTime: dutotime, Md5Info: md5info} 
  authorizecodeJson, err := json.Marshal(authorizecodeJsonObj)
  if err != nil {
    fmt.Println("JSON ERR:", err)
  }
  authorizecodeJsonStr := string(authorizecodeJson)
  fmt.Println(authorizecodeJsonStr)

//再对字符串做一个DES转换
  Enc_str := EncryptDES_ECB(authorizecodeJsonStr, deskey)
  fmt.Println("使用DSE的ECB加密后结果：" + Enc_str)

  
  
  
  
}


//CBC加密
func EncryptDES_CBC(src, key string) string {
   data := []byte(src)
   keyByte := []byte(key)
   block, err := des.NewCipher(keyByte)
   if err != nil {
      panic(err)
   }
   data = PKCS5Padding(data, block.BlockSize())
   //获取CBC加密模式
   iv := keyByte //用密钥作为向量(不建议这样使用)
   mode := cipher.NewCBCEncrypter(block, iv)
   out := make([]byte, len(data))
   mode.CryptBlocks(out, data)
   return fmt.Sprintf("%X", out)
}

//CBC解密
func DecryptDES_CBC(src, key string) string {
   keyByte := []byte(key)
   data, err := hex.DecodeString(src)
   if err != nil {
      panic(err)
   }
   block, err := des.NewCipher(keyByte)
   if err != nil {
      panic(err)
   }
   iv := keyByte //用密钥作为向量(不建议这样使用)
   mode := cipher.NewCBCDecrypter(block, iv)
   plaintext := make([]byte, len(data))
   mode.CryptBlocks(plaintext, data)
   plaintext = PKCS5UnPadding(plaintext)
   return string(plaintext)
}

//ECB加密
func EncryptDES_ECB(src, key string) string {
   data := []byte(src)
   keyByte := []byte(key)
   block, err := des.NewCipher(keyByte)
   if err != nil {
      panic(err)
   }
   bs := block.BlockSize()
   //对明文数据进行补码
   data = PKCS5Padding(data, bs)
   if len(data)%bs != 0 {
      panic("Need a multiple of the blocksize")
   }
   out := make([]byte, len(data))
   dst := out
   for len(data) > 0 {
      //对明文按照blocksize进行分块加密
      //必要时可以使用go关键字进行并行加密
      block.Encrypt(dst, data[:bs])
      data = data[bs:]
      dst = dst[bs:]
   }
   return fmt.Sprintf("%X", out)
}

//ECB解密
func DecryptDES_ECB(src, key string) string {
   data, err := hex.DecodeString(src)
   if err != nil {
      panic(err)
   }
   keyByte := []byte(key)
   block, err := des.NewCipher(keyByte)
   if err != nil {
      panic(err)
   }
   bs := block.BlockSize()
   if len(data)%bs != 0 {
      panic("crypto/cipher: input not full blocks")
   }
   out := make([]byte, len(data))
   dst := out
   for len(data) > 0 {
      block.Decrypt(dst, data[:bs])
      data = data[bs:]
      dst = dst[bs:]
   }
   out = PKCS5UnPadding(out)
   return string(out)
}

//明文补码算法
func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
   padding := blockSize - len(ciphertext)%blockSize
   padtext := bytes.Repeat([]byte{byte(padding)}, padding)
   return append(ciphertext, padtext...)
}

//明文减码算法
func PKCS5UnPadding(origData []byte) []byte {
   length := len(origData)
   unpadding := int(origData[length-1])
   return origData[:(length - unpadding)]
}



