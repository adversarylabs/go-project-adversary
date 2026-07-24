package utils

var Registry = map[string]func(){}

func init() { Registry["default"] = func() {} }
