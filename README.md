
---

# Apache/Nginx/Tomcat Vulhub PoC

本项目是一个用于测试 Vulhub靶场 PoC（概念验证）。仅限安全研究和授权测试使用。

## 📌 安装依赖

请确保你的环境已经安装 Python 3，并执行以下命令安装必要的依赖库：

```bash
pip install -r requirements.txt
```



## 🚀 运行方式

使用以下命令运行 PoC 脚本：

```bash
python nginx_parsing_vulnerability-poc.py -t <TARGET_URL>
```

例如：

```bash
python nginx_parsing_vulnerability-poc.py -t http://192.168.128.145/
```

### 可选参数：
- `-c <command>`  指定执行的命令，默认是 `whoami`
- `-o <output_file>`  将结果保存到指定的文件
- `-v`  详细模式（使用 `-vv` 启用调试输出）

## ⚠️ 免责声明

本工具仅供安全研究和授权测试使用。请勿在未经授权的情况下对任何系统进行测试，否则可能会违反相关法律法规。

---

