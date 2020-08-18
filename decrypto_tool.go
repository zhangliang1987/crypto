package main

import (
  "fmt"
  "os"
  "bytes"
  "crypto/des"
  "encoding/hex"
  "encoding/json"
)

type AuthorizecodeJson struct {
    Company string `json:"company"`
    DuetoTime string `json:"duetotime"`
    Md5Info string `json:"md5info"`
}




func main(){
  if len(os.Args) < 3 {
    fmt.Println("Usage：" + os.Args[0] + "autotime company md5info deskey")
    return
  }
  
  Enc_str := os.Args[1]
  fmt.Println(Enc_str)
  
  deskey := os.Args[2]
  fmt.Println(deskey)
  
  
  authorizecodeJsonStr := DecryptDES_ECB(Enc_str, deskey)
  
  var authorizecodeJsonObj AuthorizecodeJson
  if err := json.Unmarshal([]byte(authorizecodeJsonStr), &authorizecodeJsonObj); err == nil {
    fmt.Println(authorizecodeJsonObj)
  } else {
    fmt.Println(err)
    return
  }
  
   fmt.Println(authorizecodeJsonObj.Md5Info)
   
  
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
