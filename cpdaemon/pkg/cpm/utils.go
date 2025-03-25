package cpm

import (
	"fmt"
	"strings"
)

func splitArgs(input string) ([]string, error) {
	var args []string
	var currentArg []rune
	var inQuote rune = 0 // 0=未在引号中, '或"=在对应引号中

	for _, c := range input {
		switch {
		case c == '\\' && inQuote != 0:
			// 处理引号内的转义字符（简单实现）
			continue
		case inQuote != 0 && c == inQuote:
			inQuote = 0
		case (c == '\'' || c == '"') && inQuote == 0:
			inQuote = c
		case c == ' ' && inQuote == 0:
			if len(currentArg) > 0 {
				args = append(args, string(currentArg))
				currentArg = nil
			}
		default:
			currentArg = append(currentArg, c)
		}
	}

	if len(currentArg) > 0 {
		args = append(args, string(currentArg))
	}

	if inQuote != 0 {
		return nil, fmt.Errorf("unclosed quote")
	}

	return args, nil
}

func isUnknownFlagError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "unknown flag")
}
