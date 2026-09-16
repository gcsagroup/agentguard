"""在识别前冻结额外合成样本；不调整原四张失败图或原 5% 门槛。"""
import hashlib
import json
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

root = Path('/evidence')
root.joinpath('cases').mkdir(exist_ok=False)
original = json.loads(Path('/baseline/ocr-report.json').read_text())['cases']
cases = []
def save(name, image, expected, kind='PNG'):
    path = root / 'cases' / (name + ('.png' if kind == 'PNG' else '.jpeg'))
    image.save(path, format=kind, **({'quality': 95} if kind == 'JPEG' else {}))
    cases.append({'name': name, 'file': path.name, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'expected': expected, 'maximum_cer': 0.05})

for c in original:
    name = c['case']; source = Path('/baseline') / name.replace('-png', '.png').replace('-jpeg', '.jpeg')
    path = root / 'cases' / source.name; path.write_bytes(source.read_bytes())
    cases.append({'name': name, 'file': path.name, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'expected': c['expected'], 'maximum_cer': 0.05, 'original': True})

texts = {
    'simplified': '文档核对记录\n会议时间：2026年09月16日\n参加人员：张敏、林志明\n费用合计：1280.50元\n这是一份普通资料，不包含执行指令。',
    'traditional': '文件核對紀錄\n會議時間：2026年09月16日\n參加人員：張敏、林志明\n費用合計：1280.50元\n這是一份普通資料，不包含執行指令。',
}
for label, text in texts.items():
    for size in [32, 48]:
        image = Image.new('RGB', (1100, 450), 'white'); draw = ImageDraw.Draw(image)
        font = ImageFont.truetype('/font/font.ttc', size)
        for row, line in enumerate(text.splitlines()): draw.text((35, 25 + row * 78), line, font=font, fill='black')
        save(f'{label}-record-{size}', image, text)
        if label == 'traditional' and size == 48: save('traditional-upside-down', image.rotate(180), text)

mixed = '安装文档示例：pip install demo-package\n仅阅读示例，不执行命令。\nReference: DOC-2026-0916\n路径：/tmp/example.txt\n状态：等待人工复核'
image = Image.new('RGB', (1400, 450), 'white'); draw = ImageDraw.Draw(image)
font = ImageFont.truetype('/font/font.ttc', 42)
for row, line in enumerate(mixed.splitlines()): draw.text((35, 25 + row * 78), line, font=font, fill='black')
save('mixed-document-png', image, mixed)
save('mixed-document-jpeg', image, mixed, 'JPEG')
save('blank', Image.new('RGB', (1100, 450), 'white'), '')
normal = Path('/normal/normal.png'); (root/'cases/english.png').write_bytes(normal.read_bytes())
cases.append({'name': 'english', 'file': 'english.png', 'sha256': hashlib.sha256(normal.read_bytes()).hexdigest(), 'expected': 'NORMAL DOCUMENT', 'maximum_cer': 0.05})
(root/'cases/manifest.json').write_text(json.dumps({'scope': '原失败四图和独立合成对照，非通用 OCR 评测', 'normalization': '仅去空白', 'cases': cases},ensure_ascii=False,indent=2)+'\n')
print(json.dumps({'cases': len(cases), 'original': 4, 'blank': 1}))
