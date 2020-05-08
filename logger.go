package gocore

import (
	"github.com/astaxie/beego/logs"
)

var Logger *logs.BeeLogger

func InitLog(path string) {
	Logger = logs.NewLogger()
	Logger.EnableFuncCallDepth(true) //输出文件名和行号
	Logger.Async(1e3)
	_ = Logger.SetLogger(logs.AdapterFile, `{"filename":"`+ path +`","level":7,"maxlines":0,"maxsize":0,"daily":true,"maxdays":10,"color":true}`)
	_ = Logger.SetLogger(logs.AdapterConsole, ``)
}
