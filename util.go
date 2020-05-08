package gocore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	uuid "github.com/satori/go.uuid"
	"math"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

//存放全局使用函数

//创建主进程的pid文件
func InsertMainPid() (err error) {
	file, err := os.Create("aiotServer.pid")
	if err != nil {
		Logger.Error("creat aiot-lite pid file Error: ", err.Error())
		return err
	}
	defer file.Close()
	pid := []byte(strconv.Itoa(os.Getpid()))

	if _, err := file.Write(pid); err != nil {
		Logger.Error("write aiot-lite pid file Error: ", err.Error())
		return err
	}
	return nil
}

/**/

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

//加密
func AesEncrypt(origData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:16])
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData = PKCS5Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key[blockSize:])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

//解密
func AesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:16])
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[blockSize:])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	return origData, nil
}

//创建 UUID
func CreatUuid() string {
	// 创建可以进行错误处理的 UUID v4
	u2, err := uuid.NewV4()
	if err != nil {
		//6ba7b810-9dad-11d1-80b4-00c04fd430c8
		uuids := fmt.Sprintf("1a2b3c4d-%s-%s-%s-%s%v", RandStringRunes(4), RandStringRunes(4),
			RandStringRunes(4), RandStringRunes(2), time.Now().Unix())
		return uuids
	}
	return u2.String()
}

//产生一个随机字符串
func RandStringRunes(n int) string {
	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func GetIps() (map[string]string, error) {

	ips := make(map[string]string)

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, i := range interfaces {
		byName, err := net.InterfaceByName(i.Name)
		if err != nil {
			return nil, err
		}
		addresses, err := byName.Addrs()
		for _, v := range addresses {
			ips[byName.Name] = v.String()
		}
	}
	return ips, nil
}

//判断ip地址是内置还是外置，1--内置,2--外置，0-发生错误
func CheckIP(ip string) int64 {
	ips, _ := GetIps()
	/*获取en0*/
	en0, e0 := ips["en0"]
	if e0 {
		localIp := strings.Split(en0, "/")[0]
		if ip == localIp || ip == "127.0.0.1" {
			return 1
		} else {
			return 2
		}
	} else {
		Logger.Error("获取ip地址错误")
		return 0
	}
}

// 判断所给路径文件/文件夹是否存在
func IsExistsPath(path string) bool {
	_, err := os.Stat(path) //os.Stat获取文件信息
	if err != nil {
		if os.IsExist(err) {
			return true
		}
		return false
	}
	return true
}

func Byte2Int(data []byte) int {
	var ret int = 0
	var len int = len(data)
	var i uint = 0
	for i = 0; i < uint(len); i++ {
		ret = ret | (int(data[i]) << (i * 8))
	}
	return ret
}

// 拆分大文件
// @Pram fp 文件路径,默认切分成2M大小文件
func CarveBigFile(fp string) ([][]byte, error) {

	Logger.Debug("fp: %v", fp)
	file, err := os.Open(fp)
	if err != nil {
		Logger.Error("open file is Error: %v", err)
		return nil, err
	}
	defer file.Close()

	fileInfo, _ := file.Stat()

	var fileSize int64 = fileInfo.Size()
	Logger.Debug("fileSize: %v", fileSize)
	const fileChunk = 2 * (1 << 20) // 2 MB, change this to your requirement

	// 计算分成多少块
	totalPartsNum := uint64(math.Ceil(float64(fileSize) / float64(fileChunk)))

	Logger.Debug("文件将被分割成 %d 块.", totalPartsNum)

	var smallFileArr = make([][]byte, 0)

	for i := uint64(0); i < totalPartsNum; i++ {

		partSize := int(math.Min(fileChunk, float64(fileSize-int64(i*fileChunk))))
		partBuffer := make([]byte, partSize)
		_, err = file.Read(partBuffer)
		if err != nil {
			Logger.Error("读取文件异常：%v", err)
			return nil, err
		}
		smallFileArr = append(smallFileArr, partBuffer)
	}
	return smallFileArr, nil
}

// 拆分出ffmpag返回的错误字符串装中的错误代码
func SplitFfmpagErrorCode(str string) (code int, err error) {
	a := strings.Split(str, ",")
	if len(a) < 1 {
		err = fmt.Errorf("返回的错误信息不符合标准: %v", str)
		return
	}
	b := strings.Split(a[1], "=")
	switch b[1] {
	case "0":
		code = 10000
	case "-1":
		code = 12008
	case "-2":
		code = 12009
	case "-3":
		code = 12010
	case "-4":
		code = 12011
	case "-5":
		code = 12012
	case "-6":
		code = 12013
	case "-7":
		code = 12014
	case "-8":
		code = 12015
	case "-9":
		code = 12016
	case "-10":
		code = 12017
	case "-11":
		code = 12018
	case "-12":
		code = 12019
	}
	return
}

//执行系统命令
func RunCmd(name string, arg ...string) error {
	cmd := exec.Command(name, arg...)
	//cmd.Stderr = os.Stderr
	Logger.Info("run cmd begin, arg is: %v: %v", name, arg)
	if err := cmd.Start(); err != nil {
		return err
	}
	if err := cmd.Wait(); err != nil {
		return err
	}
	return nil
}

type TimeJson struct {
	Year   string `json:"year"`
	Month  string `json:"month"`
	Day    string `json:"day"`
	Hour   string `json:"hour"`
	Minute string `json:"minute"`
	Second string `json:"second"`
}

//构建当前时间
func GetTimeJson() string {
	t := time.Now()
	var to = TimeJson{
		Year:   t.Format("2006"),
		Month:  t.Format("01"),
		Day:    t.Format("02"),
		Hour:   t.Format("15"),
		Minute: t.Format("04"),
		Second: t.Format("05"),
	}

	j, _ := json.Marshal(&to)
	return string(j)
}
