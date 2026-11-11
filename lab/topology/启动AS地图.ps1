param([int]$Port = 18765)
$ErrorActionPreference = 'Stop'
$pythonPath = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
$dataPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\data\topologies\processed\as-map-20261019-v1'))
if (-not (Test-Path -LiteralPath $pythonPath -PathType Leaf)) { throw '项目Python环境不存在，请按工程实现文档第7.2.1节安装依赖。' }
if (-not (Test-Path -LiteralPath (Join-Path $dataPath 'manifest.json') -PathType Leaf)) { throw '地图数据未完成构建。' }
if (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) { throw "端口$Port已占用。若地图已运行，请打开http://127.0.0.1:$Port；否则选择其他-Port，不会停止现有服务。" }
Write-Host "地图地址：http://127.0.0.1:$Port；在此窗口按Ctrl+C停止。仅本机可访问。"
& $pythonPath (Join-Path $PSScriptRoot 'serve_map.py') --data $dataPath --port $Port
