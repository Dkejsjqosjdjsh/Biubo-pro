# Biubo WAF 安全修復與改進摘要

## 完成的改進項目

### 1. 安全漏洞修復

#### 路徑遍歷漏洞修復 (Path Traversal)
- **文件**: `src/api/routes/internal.py`
- **問題**: `/info/biubo/log` 和 `/info/biubo/rrweb` 端點使用不安全的日期參數驗證
- **修復**: 
  - 新增 `src/utils/validators.py` 提供安全的輸入驗證
  - 使用 `validate_date_string()` 嚴格驗證日期格式 (YYYY-MM-DD)
  - 使用 `sanitize_filename()` 清理文件名
  - 使用 `is_safe_path()` 確保路徑不會逃逸出基礎目錄

#### SSRF 防護加強
- **文件**: `src/utils/validators.py`
- **新增**: `is_safe_url()` 函數檢查 URL 是否指向內部/私有 IP
- **功能**: 檢測並阻止對以下地址的訪問：
  - 私有網絡 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
  - 本地回環 (127.0.0.0/8, ::1)
  - 鏈路本地地址 (169.254.0.0/16, fe80::/10)

### 2. 國際化 (i18n) 支持

#### 新增文件
- `src/utils/i18n.py` - 國際化工具模組
- `src/utils/chinese_converter.py` - 簡繁體中文轉換工具
- `i18n/zh-TW.json` - 繁體中文翻譯 (300+ 條目)
- `i18n/en.json` - 英文翻譯 (300+ 條目)

#### 功能特點
- 支持繁體中文 (zh-TW)、簡體中文 (zh)、英文 (en)
- 使用 `opencc-python-reimplemented` 庫進行離線簡繁轉換
- 無需外部 API 調用，保護隱私
- UI 語言可通過環境變量 `WAF_UI_LANGUAGE` 配置

#### 配置選項
```python
UI_LANGUAGE: str = os.getenv("WAF_UI_LANGUAGE", "zh-TW")
```

### 3. 配置更新

#### requirements.txt
新增依賴：
```
opencc-python-reimplemented
```

#### src/config/settings.py
- 新增 `UI_LANGUAGE` 配置項
- 更新 `save_config()` 保存語言設置

## 安全改進詳情

### 新增的安全工具函數

在 `src/utils/validators.py` 中：

```python
# IP 地址驗證
is_valid_ipv4(ip: str) -> bool
is_valid_ipv6(ip: str) -> bool
is_valid_ip(ip: str) -> bool
is_private_ip(ip: str) -> bool

# URL 安全檢查
is_safe_url(url: str, allow_private: bool = False) -> Tuple[bool, Optional[str]]

# 文件名清理
sanitize_filename(filename: str) -> str

# 路徑安全檢查
is_safe_path(path: str, base_path: str) -> bool

# 日期驗證
validate_date_string(date_str: str) -> bool

# 端口驗證
validate_port(port: int) -> bool
```

### 漏洞修復前後對比

**修復前 (存在漏洞)**:
```python
date = request.args.get("date")
if not date.replace("-", "").isdigit():  # 可被繞過
    return jsonify({})
new_path = os.path.join(host_dir, "logs", f"{date}.msgpack")  # 路徑遍歷風險
```

**修復後 (安全)**:
```python
date = request.args.get("date")
if not date or not validate_date_string(date):
    return jsonify({"status": "error", "msg": "Invalid date format"}), 400

safe_date = sanitize_filename(date)
new_path = os.path.join(host_dir, "logs", f"{safe_date}.msgpack")
if not is_safe_path(new_path, settings.DB_ROOT):
    return jsonify({"status": "error", "msg": "Invalid path"}), 403
```

## 翻譯功能使用示例

### Python 代碼中使用
```python
from src.utils.i18n import get_text
from src.utils.chinese_converter import s2t, t2s

# 獲取翻譯
title = get_text("dashboard_title")  # 根據當前語言返回對應文本

# 簡繁轉換
traditional = s2t("简体中文")  # 返回 "簡體中文"
simplified = t2s("繁體中文")  # 返回 "繁體中文"
```

## 部署說明

### 安裝新增依賴
```bash
pip install -r requirements.txt
```

### 環境變數配置
可選環境變數：
```bash
export WAF_UI_LANGUAGE="zh-TW"  # 設置 UI 語言 (zh-TW, zh, en)
```

### 啟動應用
```bash
python main.py
```

## 代碼審查結果

### 已檢查的潛在漏洞
- ✅ 無 `eval()` 使用
- ✅ 無 `exec()` 使用  
- ✅ 無 `pickle.loads()` 使用
- ✅ 無 `yaml.load()` 使用 (unsafe)
- ✅ 無 `subprocess` 用戶輸入執行
- ✅ 路徑遍歷漏洞已修復
- ✅ SSRF 防護已加強

### 現有防護機制
- CSP (Content Security Policy) 頭部
- X-Frame-Options 防止點擊劫持
- X-Content-Type-Options 防止 MIME 嗅探
- CSRF Token 驗證
- 密碼哈希存儲 (PBKDF2)
- 速率限制和登錄鎖定
- 文件上傳擴展名檢查
- 靜態資源過濾

## 注意事項

1. **JSON 翻譯文件中的重複鍵警告**: 某些鍵如 `connection` 和 `connection_caps` 同時存在是**有意設計**，用於不同 UI 上下文（普通標籤 vs 按鈕文本）。

2. **opencc-python-reimplemented**: 這是純 Python 實現，無需額外編譯，支持離線使用。

3. **向後兼容性**: 所有更改保持與現有配置的向後兼容，未設置 `WAF_UI_LANGUAGE` 時默認使用繁體中文 (zh-TW)。
