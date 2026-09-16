"""容器内生成合成中文图像并实测 OCR；字体只用于本机夹具，不加入产品镜像。"""
import hashlib
import json
from pathlib import Path
import runpy

from PIL import Image, ImageDraw, ImageFont
from pypdf import PdfReader, PdfWriter

parser = runpy.run_path('/parser/document_parser.py')
out = Path('/evidence')
font_bytes = Path('/fixture-font/font.ttc').read_bytes()
font = ImageFont.truetype('/fixture-font/font.ttc', 64)
texts = {
    'simplified': '中文安全测试\n项目代号：蓝鹭\n资料仅供阅读，请保留来源。\nNORMAL DOCUMENT 7461',
    'traditional': '中文安全測試\n專案代號：藍鷺\n資料僅供閱讀，請保留來源。\nNORMAL DOCUMENT 7461',
}


def distance(left, right):
    row = list(range(len(right) + 1))
    for i, a in enumerate(left, 1):
        next_row = [i]
        for j, b in enumerate(right, 1):
            next_row.append(min(next_row[-1] + 1, row[j] + 1, row[j-1] + (a != b)))
        row = next_row
    return row[-1]


report = {'passed': False, 'planned_ocr_cases': 4, 'maximum_character_error_rate': 0.05,
          'normalization': '只去掉空白，不替换中文字符或标点', 'cases': [],
          'font_sha256': hashlib.sha256(font_bytes).hexdigest(),
          'scope': '简中与繁中各两张合成清晰图，不代表任意照片或通用 OCR 准确率'}
try:
    for label, text in texts.items():
        image = Image.new('RGB', (1800, 620), 'white')
        draw = ImageDraw.Draw(image)
        for line, value in enumerate(text.splitlines()):
            draw.text((45, 35 + line * 135), value, font=font, fill='black')
        for kind in ['png', 'jpeg']:
            file = out / (label + '.' + kind)
            image.save(file, format=kind.upper(), **({'quality': 95} if kind == 'jpeg' else {}))
            result = parser['parse_bytes'](file.read_bytes(), kind)
            expected = ''.join(text.split())
            actual = ''.join(result.get('text', '').split())
            errors = distance(expected, actual)
            rate = errors / len(expected)
            passed = result['status'] == 'parsed' and rate <= 0.05 and '7461' in actual
            report['cases'].append({'case': label + '-' + kind, 'expected': text, 'result': result,
                                    'character_errors': errors, 'reference_characters': len(expected),
                                    'character_error_rate': rate, 'passed': passed})
    # 保留有正文和空白页的真实 PDF，供后续网关批准及遗漏说明验收。
    writer = PdfWriter()
    writer.add_page(PdfReader('/fixture-input/normal.pdf').pages[0])
    writer.add_blank_page(width=595, height=842)
    writer.write(out / 'partial.pdf')
    empty = PdfWriter()
    empty.add_blank_page(width=595, height=842)
    empty.write(out / 'empty.pdf')
    # 用于真实杀进程／暂停超时的合成输入；不替换或修改产品解析器。
    dense = Image.new('RGB', (2000, 2000), 'white')
    draw = ImageDraw.Draw(dense)
    small = ImageFont.truetype('/fixture-font/font.ttc', 16)
    for i in range(85):
        draw.text((10, 5 + i * 23), f'{i:02d} 中文安全資料 NORMAL DOCUMENT 7461 ' * 5, font=small, fill='black')
    dense.save(out / 'dense.png')
    report['passed'] = len(report['cases']) == 4 and all(c['passed'] for c in report['cases'])
finally:
    (out / 'ocr-report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
print(json.dumps({'passed': report['passed'], 'cases': [{k: c[k] for k in ['case', 'character_errors', 'reference_characters', 'character_error_rate', 'passed']} for c in report['cases']]}, ensure_ascii=False))
raise SystemExit(0 if report['passed'] else 1)
