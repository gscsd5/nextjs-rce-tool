package main

import (
	"fmt"
	"os"
	"time"
)

// VulnerableTarget 存储漏洞检测结果
type VulnerableTarget struct {
	URL        string
	Vulnerable bool
	Message    string
	POCIndex   int
	Timestamp  time.Time
}

// saveVulnerableTargets 保存存在漏洞的目标到文件
func saveVulnerableTargets(filename string, targets []VulnerableTarget) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("创建文件失败: %v", err)
	}
	defer file.Close()

	// 写入文件头
	header := fmt.Sprintf("# Next.js RCE 漏洞检测结果\n")
	header += fmt.Sprintf("# 检测时间: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	header += fmt.Sprintf("# 发现漏洞数量: %d\n", len(targets))
	header += fmt.Sprintf("# ========================================\n\n")

	if _, err := file.WriteString(header); err != nil {
		return fmt.Errorf("写入文件头失败: %v", err)
	}

	// 写入每个漏洞目标
	for i, target := range targets {
		entry := fmt.Sprintf("[%d] %s\n", i+1, target.URL)
		entry += fmt.Sprintf("    状态: 存在漏洞\n")
		entry += fmt.Sprintf("    检测POC: POC %d\n", target.POCIndex)
		entry += fmt.Sprintf("    详细信息: %s\n", target.Message)
		entry += fmt.Sprintf("    检测时间: %s\n", target.Timestamp.Format("2006-01-02 15:04:05"))
		entry += fmt.Sprintf("\n")

		if _, err := file.WriteString(entry); err != nil {
			return fmt.Errorf("写入目标信息失败: %v", err)
		}
	}

	// 写入纯URL列表（方便直接使用）
	urlListHeader := fmt.Sprintf("# ========================================\n")
	urlListHeader += fmt.Sprintf("# 纯URL列表（可直接用于批量注入）\n")
	urlListHeader += fmt.Sprintf("# ========================================\n\n")

	if _, err := file.WriteString(urlListHeader); err != nil {
		return err
	}

	for _, target := range targets {
		if _, err := file.WriteString(target.URL + "\n"); err != nil {
			return err
		}
	}

	return nil
}
